# Copyright (c) 2016 Thomas Nicholson <tnnich@googlemail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

from __future__ import annotations

from typing import Any, Union, List
from datetime import datetime
from time import sleep
from threading import Thread
import uuid

from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.ssh_proxy.protocols import (
    base_protocol,
    exec_term,
    port_forward,
    sftp,
    term,
)
from cowrie.ssh_proxy.util import int_to_hex, string_to_hex

import wazuh_interface
import response_generator

PACKETLAYOUT = {
    1: "SSH_MSG_DISCONNECT",  # ['uint32', 'reason_code'], ['string', 'reason'], ['string', 'language_tag']
    2: "SSH_MSG_IGNORE",  # ['string', 'data']
    3: "SSH_MSG_UNIMPLEMENTED",  # ['uint32', 'seq_no']
    4: "SSH_MSG_DEBUG",  # ['boolean', 'always_display']
    5: "SSH_MSG_SERVICE_REQUEST",  # ['string', 'service_name']
    6: "SSH_MSG_SERVICE_ACCEPT",  # ['string', 'service_name']
    20: "SSH_MSG_KEXINIT",  # ['string', 'service_name']
    21: "SSH_MSG_NEWKEYS",
    50: "SSH_MSG_USERAUTH_REQUEST",  # ['string', 'username'], ['string', 'service_name'], ['string', 'method_name']
    51: "SSH_MSG_USERAUTH_FAILURE",  # ['name-list', 'authentications'], ['boolean', 'partial_success']
    52: "SSH_MSG_USERAUTH_SUCCESS",  #
    53: "SSH_MSG_USERAUTH_BANNER",  # ['string', 'message'], ['string', 'language_tag']
    60: "SSH_MSG_USERAUTH_INFO_REQUEST",  # ['string', 'name'], ['string', 'instruction'],
    # ['string', 'language_tag'], ['uint32', 'num-prompts'],
    # ['string', 'prompt[x]'], ['boolean', 'echo[x]']
    61: "SSH_MSG_USERAUTH_INFO_RESPONSE",  # ['uint32', 'num-responses'], ['string', 'response[x]']
    80: "SSH_MSG_GLOBAL_REQUEST",  # ['string', 'request_name'], ['boolean', 'want_reply']  #tcpip-forward
    81: "SSH_MSG_REQUEST_SUCCESS",
    82: "SSH_MSG_REQUEST_FAILURE",
    90: "SSH_MSG_CHANNEL_OPEN",  # ['string', 'channel_type'], ['uint32', 'sender_channel'],
    # ['uint32', 'initial_window_size'], ['uint32', 'maximum_packet_size'],
    91: "SSH_MSG_CHANNEL_OPEN_CONFIRMATION",  # ['uint32', 'recipient_channel'], ['uint32', 'sender_channel'],
    # ['uint32', 'initial_window_size'], ['uint32', 'maximum_packet_size']
    92: "SSH_MSG_CHANNEL_OPEN_FAILURE",  # ['uint32', 'recipient_channel'], ['uint32', 'reason_code'],
    # ['string', 'reason'], ['string', 'language_tag']
    93: "SSH_MSG_CHANNEL_WINDOW_ADJUST",  # ['uint32', 'recipient_channel'], ['uint32', 'additional_bytes']
    94: "SSH_MSG_CHANNEL_DATA",  # ['uint32', 'recipient_channel'], ['string', 'data']
    95: "SSH_MSG_CHANNEL_EXTENDED_DATA",  # ['uint32', 'recipient_channel'],
    # ['uint32', 'data_type_code'], ['string', 'data']
    96: "SSH_MSG_CHANNEL_EOF",  # ['uint32', 'recipient_channel']
    97: "SSH_MSG_CHANNEL_CLOSE",  # ['uint32', 'recipient_channel']
    98: "SSH_MSG_CHANNEL_REQUEST",  # ['uint32', 'recipient_channel'], ['string', 'request_type'],
    # ['boolean', 'want_reply']
    99: "SSH_MSG_CHANNEL_SUCCESS",
    100: "SSH_MSG_CHANNEL_FAILURE",
}


class SSH(base_protocol.BaseProtocol):
    EXECUTION_TIMEOUT = 3

    def __init__(self, server, wi: wazuh_interface.WazuhInterface, rg: response_generator.ResponseGenerator):
        super().__init__()

        self.channels: list[dict[str, Any]] = []
        self.username = b""
        self.password = b""
        self.auth_type = b""
        self.service = b""

        self.sendOn = False
        self.expect_password = 0
        self.server = server
        # self.client

        self.wi = wi
        self.rg = rg

        self.timeout_killer: Union[Thread, None] = None
        self.last_prompt: Union[datetime, None] = None

    def set_client(self, client):
        self.client = client
        self.rg.init_attacker(self.server.attacker_id, self.server, self.client)

    def parse_num_packet(self, parent: str, message_num: int, payload: bytes) -> None:
        self.data = payload
        self.packetSize = len(payload)

        # PPS: Decide weather the packet will be sent to later process.
        self.sendOn = True

        if message_num in PACKETLAYOUT:
            packet = PACKETLAYOUT[message_num]
        else:
            packet = f"UNKNOWN_{message_num}"

        if parent == "[SERVER]":
            direction = "PROXY -> BACKEND"
        else:
            direction = "BACKEND -> PROXY"

        # log raw packets if user sets so
        if CowrieConfig.getboolean("proxy", "log_raw", fallback=False):
            log.msg(
                eventid="cowrie.proxy.ssh",
                format="%(direction)s - %(packet)s - %(payload)s",
                direction=direction,
                packet=packet.ljust(37),
                payload=repr(payload),
                protocol="ssh",
            )

        if packet == "SSH_MSG_SERVICE_REQUEST":
            service = self.extract_string()
            if service == b"ssh-userauth":
                self.sendOn = False

        # - UserAuth
        if packet == "SSH_MSG_USERAUTH_REQUEST":
            self.sendOn = False
            self.username = self.extract_string()
            self.extract_string()  # service
            self.auth_type = self.extract_string()

            if self.auth_type == b"password":
                self.extract_bool()
                self.password = self.extract_string()
                # self.server.sendPacket(52, b'')

            elif self.auth_type == b"publickey":
                self.sendOn = False
                self.server.sendPacket(51, string_to_hex("password") + chr(0).encode())

        elif packet == "SSH_MSG_USERAUTH_FAILURE":
            self.sendOn = False
            auth_list = self.extract_string()

            if b"publickey" in auth_list:
                log.msg("[SSH] Detected Public Key Auth - Disabling!")
                payload = string_to_hex("password") + chr(0).encode()

        elif packet == "SSH_MSG_USERAUTH_SUCCESS":
            self.sendOn = False

        elif packet == "SSH_MSG_USERAUTH_INFO_REQUEST":
            self.sendOn = False
            self.auth_type = b"keyboard-interactive"
            self.extract_string()
            self.extract_string()
            self.extract_string()
            num_prompts = self.extract_int(4)
            for i in range(0, num_prompts):
                request = self.extract_string()
                self.extract_bool()

                if b"password" in request.lower():
                    self.expect_password = i

        elif packet == "SSH_MSG_USERAUTH_INFO_RESPONSE":
            self.sendOn = False
            num_responses = self.extract_int(4)
            for i in range(0, num_responses):
                response = self.extract_string()
                if i == self.expect_password:
                    self.password = response

        # - End UserAuth
        # - Channels
        elif packet == "SSH_MSG_CHANNEL_OPEN":
            channel_type = self.extract_string()
            channel_id = self.extract_int(4)

            log.msg(f"got channel {channel_type!r} request")

            if channel_type == b"session":
                # if using an interactive session reset frontend timeout
                self.server.setTimeout(
                    CowrieConfig.getint("honeypot", "interactive_timeout", fallback=300)
                )

                self.create_channel(parent, channel_id, channel_type)

            elif channel_type == b"direct-tcpip" or channel_type == b"forwarded-tcpip":
                self.extract_int(4)
                self.extract_int(4)

                dst_ip = self.extract_string()
                dst_port = self.extract_int(4)

                src_ip = self.extract_string()
                src_port = self.extract_int(4)

                if CowrieConfig.getboolean("ssh", "forwarding"):
                    log.msg(
                        eventid="cowrie.direct-tcpip.request",
                        format="direct-tcp connection request to %(dst_ip)s:%(dst_port)s "
                        "from %(src_ip)s:%(src_port)s",
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        src_ip=src_ip,
                        src_port=src_port,
                    )

                    the_uuid = uuid.uuid4().hex
                    self.create_channel(parent, channel_id, channel_type)

                    if parent == "[SERVER]":
                        other_parent = "[CLIENT]"
                        the_name = "[LPRTF" + str(channel_id) + "]"
                    else:
                        other_parent = "[SERVER]"
                        the_name = "[RPRTF" + str(channel_id) + "]"

                    channel = self.get_channel(channel_id, other_parent)
                    channel["name"] = the_name
                    channel["session"] = port_forward.PortForward(
                        the_uuid, channel["name"], self
                    )

                else:
                    log.msg("[SSH] Detected Port Forwarding Channel - Disabling!")
                    log.msg(
                        eventid="cowrie.direct-tcpip.data",
                        format="discarded direct-tcp forward request %(id)s to %(dst_ip)s:%(dst_port)s ",
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                    )

                    self.sendOn = False
                    self.send_back(
                        parent,
                        92,
                        int_to_hex(channel_id)
                        + int_to_hex(1)
                        + string_to_hex("open failed")
                        + int_to_hex(0),
                    )
            else:
                # UNKNOWN CHANNEL TYPE
                if channel_type not in [b"exit-status"]:
                    log.msg(f"[SSH Unknown Channel Type Detected - {channel_type!r}")

        elif packet == "SSH_MSG_CHANNEL_OPEN_CONFIRMATION":
            channel = self.get_channel(self.extract_int(4), parent)
            # SENDER
            sender_id = self.extract_int(4)

            if parent == "[SERVER]":
                channel["serverID"] = sender_id
            elif parent == "[CLIENT]":
                channel["clientID"] = sender_id
                # CHANNEL OPENED

        elif packet == "SSH_MSG_CHANNEL_OPEN_FAILURE":
            channel = self.get_channel(self.extract_int(4), parent)
            self.channels.remove(channel)
            # CHANNEL FAILED TO OPEN

        elif packet == "SSH_MSG_CHANNEL_REQUEST":
            channel = self.get_channel(self.extract_int(4), parent)
            channel_type = self.extract_string()
            the_uuid = uuid.uuid4().hex

            # PPS: Request a shell session.
            if channel_type == b"shell":
                channel["name"] = "[TERM" + str(channel["serverID"]) + "]"
                channel["session"] = term.Term(the_uuid, channel["name"], self, channel["clientID"])

                # PPS: Attacker logged in at this moment, so set login credential.
                self.rg.login_collect[self.server.attacker_id] = self.rg.login_attempt_collect[self.server.attacker_id]

                # PPS: Start a thread for killing timeout execution for attacker command.
                self.timeout_killer = Thread(target=self.timeout_killer_handler)
                self.timeout_killer.start()

            elif channel_type == b"exec":
                channel["name"] = "[EXEC" + str(channel["serverID"]) + "]"
                self.extract_bool()
                command = self.extract_string()
                channel["session"] = exec_term.ExecTerm(
                    the_uuid, channel["name"], self, channel["serverID"], command
                )

            elif channel_type == b"subsystem":
                self.extract_bool()
                subsystem = self.extract_string()

                if subsystem == b"sftp":
                    if CowrieConfig.getboolean("ssh", "sftp_enabled"):
                        channel["name"] = "[SFTP" + str(channel["serverID"]) + "]"
                        # self.out.channel_opened(the_uuid, channel['name'])
                        channel["session"] = sftp.SFTP(the_uuid, channel["name"], self)
                    else:
                        # log.msg(log.LPURPLE, '[SSH]', 'Detected SFTP Channel Request - Disabling!')
                        self.sendOn = False
                        self.send_back(parent, 100, int_to_hex(channel["serverID"]))
                else:
                    # UNKNOWN SUBSYSTEM
                    log.msg(
                        "[SSH] Unknown Subsystem Type Detected - " + subsystem.decode()
                    )
            else:
                # UNKNOWN CHANNEL REQUEST TYPE
                if channel_type not in [
                    b"window-change",
                    b"env",
                    b"pty-req",
                    b"exit-status",
                    b"exit-signal",
                ]:
                    log.msg(
                        f"[SSH] Unknown Channel Request Type Detected - {channel_type.decode()}"
                    )

        elif packet == "SSH_MSG_CHANNEL_FAILURE":
            pass

        elif packet == "SSH_MSG_CHANNEL_CLOSE":
            channel = self.get_channel(self.extract_int(4), parent)
            # Is this needed?!
            channel[parent] = True

            if "[SERVER]" in channel and "[CLIENT]" in channel:
                # CHANNEL CLOSED
                if channel["session"] is not None:
                    log.msg("remote close")
                    channel["session"].channel_closed()

                self.channels.remove(channel)
        # - END Channels
        # - ChannelData
        elif packet == "SSH_MSG_CHANNEL_DATA":
            # PPS: This packet is for sending command in shell channel.
            channel = self.get_channel(self.extract_int(4), parent)

            # PPS: To prevent attacker from checking the history commands, simply replace up or down arrow with end.
            if payload.endswith(b'\x1b\x5b\x41') or payload.endswith(b'\x1b\x5b\x42'):
                self.data = self.data[:-3] + b'\x1b\x5b\x46'
                payload = payload[:-3] + b'\x1b\x5b\x46'
                log.msg('Attacker pressed up or down arrow to trace history command. Replaced with end.')

            # PPS: Disable tab, so simply replace it with bell.
            elif payload.endswith(b'\x09'):
                self.data = self.data[:-1] + b'\x07'
                payload = payload[:-1] + b'\x07'
                log.msg('Attacker pressed tab. Replaced with bell.')

            channel["session"].parse_packet(parent, self.extract_string())

        elif packet == "SSH_MSG_CHANNEL_EXTENDED_DATA":
            channel = self.get_channel(self.extract_int(4), parent)
            self.extract_int(4)
            channel["session"].parse_packet(parent, self.extract_string())
        # - END ChannelData

        elif packet == "SSH_MSG_GLOBAL_REQUEST":
            channel_type = self.extract_string()
            if channel_type == b"tcpip-forward":
                if not CowrieConfig.getboolean("ssh", "forwarding"):
                    self.sendOn = False
                    self.send_back(parent, 82, "")

        # PPS: self.sendOn decide weather the packet will be sent to later process.
        # If parent == "[SERVER]" represents the packet is from attacker to frontend, and then it will be sent to backend pool by client for command execution.
        # If parent == "[CLIENT]" represents the packet is from backend pool to backend, and then it will be sent to attacker by server for responding command execution result.
        if self.sendOn:
            if parent == "[SERVER]":
                if packet == 'SSH_MSG_CHANNEL_DATA':
                    # PPS: Deal with shell packet from attacker.
                    if type(channel["session"]) is term.Term:
                        # Get attacker info.
                        attacker_ip = self.server.attacker_id.split(':')[0]
                        attacker_port = int(self.server.attacker_id.split(':')[1])
                        attacker_id = attacker_ip + ':' + str(attacker_port)

                        # Response generator is taking over the control and try to generate response to attacker.
                        # Response attacker with some meaningless content.
                        if attacker_id in self.rg.attacker_collect:
                            #self.rg.send_packet_to(attacker_id, False, 'Please wait while command executing ...\r\n')
                            pass

                        # Cowrie should handle input from attacker.
                        else:
                            # PPS: A command is complete and parsed.
                            # Or, to be honest, attacker press Ctrl+C or Enter.
                            if len(channel["session"].commands) > 0:
                                # PPS: Attacker command is executing, so this is a part of attacker command.
                                if self.last_prompt is not None:
                                    log.msg(f'Command "{channel["session"].commands}" is part of attacker command.')
                                    channel["session"].commands.clear()
                                    self.client.sendPacket(message_num, payload)

                                # PPS: Attacker command is NOT executing, so this is a new command from attacker.
                                else:
                                    # Send a new line to attacker to pretend the command is executing.
                                    self.server.sendPacket(message_num, b'\x00\x00\x00\x00\x00\x00\x00\x02\r\n')

                                    # Send a clear line to backend pool to clear what attacker typed.
                                    self.client.sendPacket(message_num, b'\x00\x00\x00\x00\x00\x00\x00\x01\x15')

                                    # Get parsed commands from Term parser.
                                    commands = channel["session"].commands.copy()
                                    channel["session"].commands.clear()
                                    log.msg(f'Command from {attacker_ip}:{attacker_port} parsed:', [command.decode().strip() for command in commands])

                                    # Do many things in background by thread.
                                    # The thread will generate response to attacker.
                                    self.rg.add_task(f'{attacker_ip}:{attacker_port}', commands)

                            # PPS: A command is typing and parsing, so let it pass to backend pool.
                            else:
                                self.client.sendPacket(message_num, payload)

                    # PPS: Not shell packet, just let it go to backend pool.
                    else:
                        self.client.sendPacket(message_num, payload)

                else:
                    self.client.sendPacket(message_num, payload)

            else:
                if packet == 'SSH_MSG_CHANNEL_DATA':
                    # PPS: Deal with shell packet from backend pool.
                    # Send packet payload to the buffering list, and the thread will handle it.
                    if type(channel["session"]) is term.Term:
                        # Get attacker info.
                        attacker_id = self.server.attacker_id

                        # Attacker command has been executed, so stop the timer.
                        if self.last_prompt is not None and response_generator.ResponseGenerator.has_prompt(payload):
                            log.msg('Timer for attacker command execution stopped.')
                            self.last_prompt = None

                            # Clear filter about responses from backend pool to attacker.
                            log.msg('Backend pool response filter is cleared.')
                            self.rg.respFilter_collect[attacker_id] = None

                            # Apply terminal signal for response filter.
                            if attacker_id in self.rg.respFilterTermSignal_collect:
                                log.msg('Send disconnect signal to backend pool for response filter.')
                                self.client.sendPacket(message_num, b'\x00\x00\x00\x00\x00\x00\x00\x01\x04')

                        # Response generator is taking over the control and try to generate response to attacker.
                        # Pass response from backend pool to response generator.
                        if attacker_id in self.rg.attacker_collect:
                            self.rg.backendPacket_collect[attacker_id].append(payload[8:])

                        # Response generator turned the control back to cowrie.
                        # Cowrie should handle some clear job for response generator.
                        elif attacker_id in self.rg.clearer_collect and len(self.rg.clearer_collect[attacker_id]) > 0:
                            # Remove cleaned job from list.
                            for phrase in self.rg.clearer_collect[attacker_id].copy():
                                if phrase in payload:
                                    self.rg.clearer_collect[attacker_id].remove(phrase)
                                    log.msg(f'Clearer for response generator cleared "{phrase}".')

                            # All clean job are done.
                            # Record current time as the start of attacker command execution.
                            if len(self.rg.clearer_collect[attacker_id]) == 0:
                                log.msg('Timer for attacker command execution started.')
                                self.last_prompt = datetime.now()

                                # Clear history about responses from backend pool to attacker.
                                log.msg('Backend pool response history is cleared.')
                                self.rg.respHistory_collect[attacker_id].clear()

                        # Cowrie should handle response from backend pool.
                        else:
                            for payload in response_generator.ResponseGenerator.generate_packets(self.rg.backend_phrase_replace(attacker_id, self.rg.backend_hidden_phrase_remove(payload[8:]))):
                                login_info = self.rg.get_attacker_already_login(attacker_id)

                                if len(login_info) > 0:
                                    sudo_prompt = '[sudo] password for {}: '.format(login_info[0]).encode()

                                    # Fill real sudo password for attacker.
                                    if payload[8:].endswith(sudo_prompt):
                                        # Send real password to backend.
                                        for packet in response_generator.ResponseGenerator.generate_packets(self.rg.backend_login['password'] + '\r'):
                                            self.client.sendPacket(message_num, packet)

                                        # Remove sudo prompt string from the original packet.
                                        payload = response_generator.ResponseGenerator.generate_packets(payload[8:-len(sudo_prompt)])[0]

                                        log.msg('Auto fill sudo password complete.')

                                    # Do response filter.
                                    if self.rg.respFilter_collect[attacker_id] is not None:
                                        if attacker_id not in self.rg.respFilterTermSignal_collect:
                                            content = payload[8:]

                                            content = self.rg.respFilter_collect[attacker_id][0](*self.rg.respFilter_collect[attacker_id][1], content)
                                            payloads = response_generator.ResponseGenerator.generate_packets(content)

                                            self.rg.respHistory_collect[attacker_id] += [payload[8:] for payload in payloads]

                                            for payload in payloads:
                                                self.server.sendPacket(message_num, payload)

                                        # Response filter has set terminate signal, so ignore this packet.
                                        else:
                                            pass

                                    # No response filter.
                                    else:
                                        if attacker_id not in self.rg.respFilterTermSignal_collect:
                                            self.rg.respHistory_collect[attacker_id].append(payload[8:])
                                            self.server.sendPacket(message_num, payload)

                                        # Response filter has set terminate signal, so ignore this packet.
                                        else:
                                            pass

                                else:
                                    log.msg(f'Attacker leaves before cowrie handle response from backend.')

                    else:
                        self.server.sendPacket(message_num, payload)

                else:
                    self.server.sendPacket(message_num, payload)

    # PPS: Send back a response packet to respond original packet.
    # If parent == "[SERVER]" represents original packet is from attacker to frontend, so the response packet will be sent from frontend to attacker by server.
    # If parent == "[CLIENT]" represents original packet is from backend pool to backend, so the response packet will be sent from backend to backend pool by client.
    def send_back(self, parent, message_num, payload):
        packet = PACKETLAYOUT[message_num]

        if parent == "[SERVER]":
            direction = "PROXY -> FRONTEND"
        else:
            direction = "PROXY -> BACKEND"

            log.msg(
                eventid="cowrie.proxy.ssh",
                format="%(direction)s - %(packet)s - %(payload)s",
                direction=direction,
                packet=packet.ljust(37),
                payload=repr(payload),
                protocol="ssh",
            )

        if parent == "[SERVER]":
            self.server.sendPacket(message_num, payload)
        elif parent == "[CLIENT]":
            self.client.sendPacket(message_num, payload)

    def create_channel(self, parent, channel_id, channel_type, session=None):
        if parent == "[SERVER]":
            self.channels.append(
                {"serverID": channel_id, "type": channel_type, "session": session}
            )
        elif parent == "[CLIENT]":
            self.channels.append(
                {"clientID": channel_id, "type": channel_type, "session": session}
            )

    def get_channel(self, channel_num: int, parent: str) -> dict[str, Any]:
        the_channel = None
        for channel in self.channels:
            if parent == "[CLIENT]":
                search = "serverID"
            else:
                search = "clientID"

            if channel[search] == channel_num:
                the_channel = channel
                break
        if the_channel is None:
            raise KeyError
        else:
            return the_channel


    def timeout_killer_handler(self):

        # PPS: Restrict the execution time for attacker command.
        # This restriction is NOT applied to response generator.

        # When the connection lost, attacker_info will be cleared.
        while self.server.is_connected:
            # The timer for attacker command execution is started and timeout reached.
            if self.last_prompt is not None and (datetime.now() - self.last_prompt).total_seconds() >= SSH.EXECUTION_TIMEOUT:
                log.msg('Execution timeout is reached. Sending Ctrl+C to backend pool.')

                payloads = response_generator.ResponseGenerator.generate_packets(b'\x03')
                for payload in payloads:
                    self.client.sendPacket(response_generator.ResponseGenerator.MESSAGE_NUM, payload)

                payloads = response_generator.ResponseGenerator.generate_packets(b'[PAM] Execution timeout or you do NOT have enough privilege.\r\n')
                for payload in payloads:
                    self.server.sendPacket(response_generator.ResponseGenerator.MESSAGE_NUM, payload)

            sleep(1)
