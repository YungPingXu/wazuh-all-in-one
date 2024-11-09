#!/home/user/env/bin/python3

from __future__ import annotations
from typing import Union, List
from time import sleep
from datetime import datetime, timedelta
from threading import Thread
import socket
import subprocess

from tracer import Tracer, LoggingType

SERVER_ADDRESS = '127.0.0.1'
SERVER_PORT = 6417
DEFAULT_RULE_DELETE_TIMEOUT = 5 * 60  # 5 minutes


logger = None


def exec_command(args: list) -> str:

    result = subprocess.run(args, stdout=subprocess.PIPE)

    return result.stdout.decode()


class NetworkBlocker:

    @staticmethod
    def deserialize(nf: bytes) -> NetworkBlocker:
        tokens = nf.split(b';')

        if tokens[0] == b'NetworkBlocker' and len(tokens) == 6:
            args = tokens[1].decode(), tokens[2].decode(), int(tokens[3].decode()), [True if tokens[4].decode() == 'True' else False][0], datetime.strptime(tokens[5].decode(), '%Y%m%d%H%M%S')
            return NetworkBlocker(*args)

        assert ValueError

    def __init__(self, src_addr: str, dst_addr: str, dst_port: int = -1, is_create: bool = True, due: datetime = None):
        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.dst_port = dst_port
        self.is_create = is_create

        if due is None:
            self.due = datetime.now() + timedelta(seconds=DEFAULT_RULE_DELETE_TIMEOUT)
        else:
            self.due = due

    def __eq__(self, other):
        if type(self) == type(other):
            return self.src_addr == other.src_addr and self.dst_addr == other.dst_addr and self.dst_port == other.dst_port and self.is_create == other.is_create
        else:
            return False

    def __ne__(self, other):
        if type(self) == type(other):
            return self.src_addr != other.src_addr or self.dst_addr != other.dst_addr or self.dst_port != other.dst_port or self.is_create != other.is_create
        else:
            return False

    def __xor__(self, other):
        if type(self) == type(other):
            return self.src_addr == other.src_addr and self.dst_addr == other.dst_addr and self.dst_port == other.dst_port and self.is_create != other.is_create
        else:
            return False

    def serialize(self) -> bytes:
        return b';'.join([s.encode() for s in ['NetworkBlocker', self.src_addr, self.dst_addr, str(self.dst_port), str(self.is_create), self.due.strftime('%Y%m%d%H%M%S')]])

    def execute(self, reverse: bool = False) -> None:
        if reverse:
            is_create = not self.is_create
        else:
            is_create = self.is_create

        if is_create:
            if self.dst_port == -1:
                print(f'Block traffics from {self.src_addr} to {self.dst_addr}')
                logger.log(f'Block traffics from {self.src_addr} to {self.dst_addr}')
                exec_command(
                    ['iptables', '-I', 'FORWARD', '1', '-s', self.src_addr, '-d', self.dst_addr, '-j', 'DROP'])
            else:
                print(f'Block traffics from {self.src_addr} to {self.dst_addr}:{self.dst_port}')
                logger.log(f'Block traffics from {self.src_addr} to {self.dst_addr}:{self.dst_port}')
                exec_command(
                    ['iptables', '-I', 'FORWARD', '1', '-s', self.src_addr, '-d', self.dst_addr, '-p', 'tcp', '--dport',
                     str(self.dst_port), '-j', 'DROP'])
        else:
            if self.dst_port == -1:
                print(f'UnBlock traffics from {self.src_addr} to {self.dst_addr}')
                logger.log(f'UnBlock traffics from {self.src_addr} to {self.dst_addr}')
                exec_command(
                    ['iptables', '-D', 'FORWARD', '-s', self.src_addr, '-d', self.dst_addr, '-j', 'DROP'])
            else:
                print(f'UnBlock traffics from {self.src_addr} to {self.dst_addr}:{self.dst_port}')
                logger.log(f'UnBlock traffics from {self.src_addr} to {self.dst_addr}:{self.dst_port}')
                exec_command(
                    ['iptables', '-D', 'FORWARD', '-s', self.src_addr, '-d', self.dst_addr, '-p', 'tcp', '--dport',
                     str(self.dst_port), '-j', 'DROP'])


class NetworkForwarder:

    @staticmethod
    def deserialize(nf: bytes) -> NetworkForwarder:
        tokens = nf.split(b';')

        if tokens[0] == b'NetworkForwarder' and len(tokens) == 6:
            args = tokens[1].decode(), tokens[2].decode(), tokens[3].decode(), [True if tokens[4].decode() == 'True' else False][0], datetime.strptime(tokens[5].decode(), '%Y%m%d%H%M%S')
            return NetworkForwarder(*args)

        assert ValueError

    def __init__(self, src_addr: str, ori_dst_addr: str, new_dst_addr: str, is_create: bool = True, due: datetime = None):
        self.src_addr = src_addr
        self.ori_dst_addr = ori_dst_addr
        self.new_dst_addr = new_dst_addr
        self.is_create = is_create

        if due is None:
            self.due = datetime.now() + timedelta(seconds=DEFAULT_RULE_DELETE_TIMEOUT)
        else:
            self.due = due

    def __eq__(self, other):
        if type(self) == type(other):
            return self.src_addr == other.src_addr and self.ori_dst_addr == other.ori_dst_addr and self.new_dst_addr == other.new_dst_addr and self.is_create == other.is_create
        else:
            return False

    def __ne__(self, other):
        if type(self) == type(other):
            return self.src_addr != other.src_addr or self.ori_dst_addr != other.ori_dst_addr or self.new_dst_addr != other.new_dst_addr or self.is_create != other.is_create
        else:
            return False

    def __xor__(self, other):
        if type(self) == type(other):
            return self.src_addr == other.src_addr and self.ori_dst_addr == other.ori_dst_addr and self.new_dst_addr == other.new_dst_addr and self.is_create != other.is_create
        else:
            return False

    def serialize(self) -> bytes:
        return b';'.join([s.encode() for s in ['NetworkForwarder', self.src_addr, self.ori_dst_addr, self.new_dst_addr, str(self.is_create), self.due.strftime('%Y%m%d%H%M%S')]])

    def execute(self, reverse: bool = False) -> None:
        if reverse:
            is_create = not self.is_create
        else:
            is_create = self.is_create

        if is_create:
            print(f'Forward traffics from {self.ori_dst_addr} to {self.new_dst_addr} for traffic source {self.src_addr}')
            logger.log(f'Forward traffics from {self.ori_dst_addr} to {self.new_dst_addr} for traffic source {self.src_addr}')
            exec_command(['iptables', '-t', 'nat', '-I', 'PREROUTING', '1', '-s', self.src_addr, '-d', self.ori_dst_addr, '-j', 'DNAT', '--to-destination', self.new_dst_addr])
        else:
            print(f'UnForward traffics from {self.ori_dst_addr} to {self.new_dst_addr} for traffic source {self.src_addr}')
            logger.log(f'UnForward traffics from {self.ori_dst_addr} to {self.new_dst_addr} for traffic source {self.src_addr}')
            exec_command(['iptables', '-t', 'nat', '-D', 'PREROUTING', '-s', self.src_addr, '-d', self.ori_dst_addr, '-j', 'DNAT', '--to-destination', self.new_dst_addr])


def clear_network_rule(keep_running: List[bool], rules: List[Union[NetworkBlocker, NetworkForwarder]]) -> None:
    while len(keep_running) > 0:
        i = 0
        while i < len(rules):
            if rules[i].due <= datetime.now():
                rules.pop(i).execute(reverse=True)
            else:
                i += 1

        sleep(0.5)

    print('Cleaning created rules ...')
    logger.log('Cleaning created rules ...', LoggingType.DEBUG)
    while len(rules) > 0:
        rules.pop(0).execute(reverse=True)
    print('Cleaning created rules ... Done')
    logger.log('Cleaning created rules ... Done', LoggingType.DEBUG)


if __name__ == '__main__':
    logger = Tracer('iptables')
    server_keep_running = True
    rules = []

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((SERVER_ADDRESS, SERVER_PORT))
    s.listen(1)
    print(f'Server is listening on "{SERVER_ADDRESS}:{SERVER_PORT}".')
    logger.log(f'Server is listening on "{SERVER_ADDRESS}:{SERVER_PORT}".', LoggingType.DEBUG)

    while server_keep_running:
        while len(rules) > 0:
            print('Waiting for rules cleanup ...')
            logger.log('Waiting for rules cleanup ...', LoggingType.DEBUG)
            sleep(0.5)

        keep_running = [True, ]
        Thread(target=clear_network_rule, args=(keep_running, rules)).start()

        try:
            conn, client = s.accept()

            with conn:
                print(f'\nConnected from {client[0]}:{client[1]}.')
                logger.log(f'Connected from {client[0]}:{client[1]}.', LoggingType.DEBUG)

                while len(keep_running) > 0:
                    data = conn.recv(1024)

                    if not data or data == b'CLOSE':
                        break

                    if data.startswith(b'NetworkBlocker'):
                        obj = NetworkBlocker.deserialize(data)
                    elif data.startswith(b'NetworkForwarder'):
                        obj = NetworkForwarder.deserialize(data)
                    else:
                        raise ValueError

                    if obj:
                        is_create_reverse = False
                        for rule in rules:
                            if obj ^ rule:
                                is_create_reverse = True
                                break

                        if obj.is_create and obj not in rules:
                            obj.execute()
                            # Add to clearer monitoring.
                            rules.append(obj)
                        elif not obj.is_create and is_create_reverse:
                            obj.execute()
                            obj.is_create = True
                            rules.remove(obj)

                    # Maybe we need to send feedback in the future.
                    conn.sendall(b'Done')

        except ConnectionResetError:
            print('Connection reset by client.')
            logger.log('Connection reset by client.', LoggingType.DEBUG)
            keep_running.clear()

        except KeyboardInterrupt:
            print('User stop the server.')
            logger.log('User stop the server.', LoggingType.DEBUG)
            keep_running.clear()
            server_keep_running = False

        finally:
            keep_running.clear()

    s.close()
