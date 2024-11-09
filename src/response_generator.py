
# PPS-TODO: Run command in backend pool at any time. Not just in run_task().
# PPS-TODO: Too long command cause backend pool disconnect unexpectedly.

from typing import List, Tuple, Dict, Union, Callable
from math import floor
from time import sleep
from datetime import datetime, timedelta
from random import random, randint
import json
import re
from pathlib import Path
import socket
from threading import Thread

from twisted.python import log
from cowrie.ssh_proxy.server_transport import FrontendSSHTransport
from cowrie.ssh_proxy.client_transport import BackendSSHTransport
from shlex import quote
import validators

import training
from tracer import Tracer, LoggingType
from login_state import LoginState
import attack2engage
from wazuh_interface import WazuhInterface
from engage_interface import EngageInterface
from engage_action import ACTION_ID2NAME
from iptables_applyer import NetworkBlocker, NetworkForwarder


ATTRIBUTE_NAME = ('exec', 'mail_sender', 'mail_receiver', 'username', 'password', 'interface', 'domain', 'ip', 'port', 'path')
ATTRIBUTE_DEFAULT = ('', '', '', '', '', 'ens3', 'localhost', '127.0.0.1', '', '')

COMMON_EXEC = ()
COMMON_USERNAMES = ('ubuntu', 'admin')
COMMON_PASSWORDS = ()
COMMON_INTERFACES = ('lo', 'enp1s0', 'enp34s0', 'ens3', 'wlan0')
COMMON_PORTS = (20, 21, 22, 25, 53, 80, 123, 443, 465, 587, 2525, 3389, 8080, 8081, 8082, 8083, 8888)

SHARED_ENGAGE_INTERFACE_NAME = '0.0.0.0:0'


def char_remove(s: str, chars: List[str]) -> str:

    for char in chars:
        s = s.replace(char, '')

    return s


def str_extra_split(s: str, delim: str) -> List[str]:

    tokens = s.split()

    for d in delim:
        collect = []

        for token in tokens:
            collect += [t for t in token.split(d) if len(t) != 0]

        tokens = collect

    return tokens


def split_list(l: list, size: int) -> list:

    l = l.copy()
    splitted = []

    if size > 0:
        while len(l) > 0:
            if len(l) <= size:
                splitted.append(l)
                l = []
            else:
                splitted.append(l[:size])
                l = l[size:]

        return splitted

    else:
        return []


def most_frequent(l: list) -> list:

    return max(set(l), key=l.count)


class ResponseGenerator:

    MESSAGE_NUM = 94
    MAX_PAYLOAD_LEN = 127
    PASTING_ESCAPE_STARTER = b'[?2004h'
    PASTING_ESCAPE_TERMINATOR = b'[?2004l'
    PLAIN_PROMPT_PATTERN = rb'[a-zA-Z0-9_.-]+@[a-zA-Z0-9-]+:'
    COLORFUL_PROMPT_PATTERN = rb'\x1b\[01;32m[a-zA-Z0-9_.-]+@[a-zA-Z0-9-]+\x1b\[00m:'


    @staticmethod
    def generate_packets(content: Union[str, bytes]) -> List[bytes]:

        if type(content) is str:
            content = content.encode()

        payloads = []

        while len(content) != 0:
            if len(content) > ResponseGenerator.MAX_PAYLOAD_LEN:
                c = content[:ResponseGenerator.MAX_PAYLOAD_LEN]
                content = content[ResponseGenerator.MAX_PAYLOAD_LEN:]
            else:
                c = content
                content = b''

            payload = b'\x00\x00\x00\x00\x00\x00\x00' + chr(len(c)).encode() + c
            payloads.append(payload)

        return payloads


    @staticmethod
    def filter_prompt(content: Union[bytes, str]) -> List[bytes]:

        if type(content) is str:
            content = content.encode()

        colorful_prompt = re.findall(ResponseGenerator.COLORFUL_PROMPT_PATTERN, content)
        plain_prompt = re.findall(ResponseGenerator.PLAIN_PROMPT_PATTERN, content)

        prompts = colorful_prompt + plain_prompt

        return prompts


    @staticmethod
    def has_prompt(content: Union[bytes, str]) -> bool:

        return len(ResponseGenerator.filter_prompt(content)) > 0


    def __init__(self, wi: Union[WazuhInterface, None]):

        self.logger = Tracer('cowrie')
        self.is_training = training.IS_TRAINING
        self.phrase_replace = {}
        self.backend_login: Dict[str, str] = {}
        self.backend_hidden_phrase = ''
        self.read_config()

        if self.is_training:
            log.msg('Response Generator is run in TRAINING mode.')
            self.logger.log('Response Generator is run in TRAINING mode.', LoggingType.DEBUG)
        else:
            log.msg('Response Generator is run in RUNTIME mode.')
            self.logger.log('Response Generator is run in RUNTIME mode.', LoggingType.DEBUG)

        # wi only works for ssh.py but not for checkers.py .
        self.wi = wi

        # This is maintained by startFactory() and stopFactory() in PoolServerFactory.
        self.backendPool: List[dict] = []

        self.iptables_applyer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect_iptables_applyer()


        # Only backendIP_collect and login_cand_collect are indexed by attacker_ip.
        # Other dictionary type attributes are indexed by attacker_id.

        # These are initialized in init_attacker().
        # These are cleared in connectionLost() in server_transport.py .
        self.attackerCon_collect: Dict[str, Union[FrontendSSHTransport, None]] = {}
        self.backendCon_collect: Dict[str, Union[BackendSSHTransport, None]] = {}

        # Keep threads in this list even if the thread is done.
        self.tasks = []

        # These will be initialized in add_task() for access in run_task().
        # These will be cleared in complete_task().
        self.attacker_collect: List[str] = []
        self.backendPacket_collect: Dict[str, List[bytes]] = {}

        # After current task is done, complete_task() will add clearer in this list.
        # When the control sends back to cowrie, cowrie will clear phrase in clearer.
        self.clearer_collect: Dict[str, List[bytes]] = {}

        # This only for logged-in session to mark auto-sudo flag.
        # This is initialized in add_task(), and used in ssh.py .
        self.autoSudo_collect: Dict[str, bool] = {}

        # This only for logged-in session to record responses from backend pool to attacker.
        # This is created in init_attacker(), and managed in ssh.py .
        self.respHistory_collect: Dict[str, List[bytes]] = {}

        # This is filter for respHistory_collect.
        # The datum should be filtered before put into respHistory_collect and sent back to attacker.
        # This is created in init_attacker(), and managed in ssh.py .
        self.respFilter_collect: Dict[str, Union[None, Tuple[Callable, tuple]]] = {}
        self.respFilterTermSignal_collect: List[str] = []

        # Keep these in the list even if the current task is done.
        # By doing so, when the same attacker type new command, we can access old data.
        # These are created in init_attacker(), but ei_collect is created in need in add_task().
        # ei_collect and loginState_collect are cleared in connectionLost() in server_transport.py .
        self.cmdHistory_collect: Dict[str, List[bytes]] = {}
        self.login_cand_collect: Dict[str, Dict[str, List[str]]] = {}
        self.ei_collect: Dict[str, EngageInterface] = {}
        self.loginState_collect: Dict[str, LoginState] = {}

        # Store login credential for attackers.
        # This is created during shell open request in ssh.py .
        # This is destroyed in connectionLost() server_transport.py .
        self.login_collect: Dict[str, List[str]] = {}

        # Store last attempt login credential for attackers.
        # This is created in server_transport.py .
        self.login_attempt_collect: Dict[str, List[str]] = {}

        # Store phrase replacement for engage action.
        # This is created in init_attacker().
        self.phraseReplace_collect: Dict[str, List[Tuple[bytes, bytes, datetime]]] = {}

        # Store time of first command execution for each attacker.
        # This is initialized in init_attacker().
        self.firstExec_collect: Dict[str, datetime] = {}


    def phrase_replace_due(self) -> datetime:

        return datetime.now() + timedelta(seconds=self.phrase_replace['lifetime'])


    def connect_iptables_applyer(self) -> None:

        while True:
            try:
                self.iptables_applyer.connect(('127.0.0.1', 6417))
            except ConnectionRefusedError:
                log.msg('Connecting to iptables applyer ...')
            else:
                log.msg('Connecting to iptables applyer ... Done')
                break

            sleep(1)


    def read_config(self) -> None:

        with open(Path(__file__).parents[1] / 'etc/response_generator.json', 'r') as fin:
            config = json.load(fin)

        self.phrase_replace['lifetime'] = int(config['phrase_replace']['lifetime'])
        self.backend_login['username'] = config['backend']['username']
        self.backend_login['password'] = config['backend']['password']
        self.backend_login['root_password'] = config['backend']['root_password']
        self.backend_hidden_phrase = config['backend']['sudo_hidden_phrase']


    def extract_exec(self, attacker_id: str, attr_candidates: Dict[str, List[str]], tokens: List[str]) -> None:

        for token in tokens.copy():
            if token in COMMON_EXEC:
                tokens.remove(token)
                attr_candidates['exec'].append(token)

        tokens = [token for token in tokens if len(token) <= 20 and char_remove(token, ['_', '-', '.']).isalnum()]
        chunks = split_list(tokens, 3)

        for chunk in chunks:
            responses = self.run_command_in_backend(attacker_id, '; '.join([f'which {quote(token)}' for token in chunk]))

            for response in responses:
                exe = response.decode().split('/')[-1].strip()

                if len(exe) > 0 and exe in chunk:
                    attr_candidates['exec'].append(exe)


    def extract_mailer(self, attacker_id: str, attr_candidates: Dict[str, List[str]], tokens: List[str]) -> None:

        for i, token in enumerate(tokens):
            if token == 'ssmtp':
                for j in range(i+1, len(tokens)):
                    # Username.
                    if tokens[j].startswith('-au'):
                        index = tokens[j].find('=')

                        if index == -1:
                            # ['-au', 'username']
                            if len(tokens[j]) == 3:
                                if j + 1 < len(tokens):
                                    attr_candidates['username'].append(tokens[j+1])

                            # ['-auusername']
                            else:
                                attr_candidates['username'].append(tokens[j][3:])

                        # ['-au=username']
                        else:
                            if not tokens[j].endswith('='):
                                attr_candidates['username'].append(tokens[j][index+1:])

                    # Password.
                    elif tokens[j].startswith('-ap'):
                        index = tokens[j].find('=')

                        if index == -1:
                            # ['-ap', 'password']
                            if len(tokens[j]) == 3:
                                if j + 1 < len(tokens):
                                    attr_candidates['password'].append(tokens[j + 1])

                            # ['-appassword']
                            else:
                                attr_candidates['password'].append(tokens[j][3:])

                        # ['-ap=password']
                        else:
                            if not tokens[j].endswith('='):
                                attr_candidates['password'].append(tokens[j][index + 1:])

                    # Receivers.
                    elif validators.email(tokens[j]):
                        attr_candidates['mail_receiver'].append(tokens[j])

                break

            elif token == 'mail':
                for j in range(i + 1, len(tokens)):
                    # Username.
                    if tokens[j].startswith('-u') or tokens[j].startswith('--user'):
                        index = tokens[j].find('=')

                        # ['-u', 'username']
                        if index == -1:
                            if j + 1 < len(tokens):
                                attr_candidates['username'].append(tokens[j+1])

                        # ['-u=username']
                        else:
                            if not tokens[j].endswith('='):
                                attr_candidates['username'].append(tokens[j][index+1:])

                    # Receivers.
                    elif validators.email(tokens[j]):
                        attr_candidates['mail_receiver'].append(tokens[j])

                break

            elif token == 'sendemail':
                for j in range(i + 1, len(tokens)):
                    # Sender.
                    # ['-f', 'sender@example.com']
                    if tokens[j] == '-f':
                        if j + 1 < len(tokens):
                            attr_candidates['mail_sender'].append(tokens[j + 1])
                            j += 1

                    # Receivers.
                    # ['-t', 'receiver@example.com', ...]
                    elif tokens[j] == '-t':
                        k = j + 1
                        for k in range(j + 1, len(tokens)):
                            if validators.email(tokens[k]):
                                attr_candidates['mail_receiver'].append(tokens[k])
                            else:
                                break
                        j = k - 1

                    # Username.
                    # ['-xu', 'username']
                    if tokens[j] == '-xu':
                        if j + 1 < len(tokens):
                            attr_candidates['username'].append(tokens[j + 1])

                    # Password.
                    # ['-xp', 'password']
                    elif tokens[j].startswith('-xp'):
                        if j + 1 < len(tokens):
                            attr_candidates['password'].append(tokens[j + 1])

                    # Receivers.
                    elif validators.email(tokens[j]):
                        attr_candidates['mail_receiver'].append(tokens[j])

                break

            elif token == 'mailx':
                for j in range(i + 1, len(tokens)):
                    # Username.
                    if tokens[j].startswith('-u') or tokens[j].startswith('--user'):
                        index = tokens[j].find('=')

                        # ['-u', 'username']
                        if index == -1:
                            if j + 1 < len(tokens):
                                attr_candidates['username'].append(tokens[j+1])

                        # ['-u=username']
                        else:
                            if not tokens[j].endswith('='):
                                attr_candidates['username'].append(tokens[j][index+1:])

                    # Receivers.
                    elif validators.email(tokens[j]):
                        attr_candidates['mail_receiver'].append(tokens[j])

                break


    def extract_username(self, attacker_id: str, attr_candidates: Dict[str, List[str]], tokens: List[str]) -> None:

        for token in tokens.copy():
            if token in COMMON_USERNAMES:
                tokens.remove(token)
                attr_candidates['username'].append(token)

        tokens = [token for token in tokens if 1 <= len(token) <= 255 and not token.startswith('-') and not token.endswith('-') and char_remove(token, ['.', '-', '_']).isalpha()]
        chunks = split_list(tokens, 3)

        for chunk in chunks:
            responses = self.run_command_in_backend(attacker_id, '; '.join([f'cut -d : -f 1 /etc/passwd | grep -- {quote(token)}' for token in chunk]))

            for response in responses:
                username = response.decode().strip()

                if len(username) > 0 and username in chunk:
                    attr_candidates['username'].append(username)


    def extract_password(self, attacker_id: str, attr_candidates: Dict[str, List[str]], tokens: List[str]) -> None:

        for token in tokens:
            if token in COMMON_PASSWORDS:
                attr_candidates['password'].append(token)


    def extract_interface(self, attacker_id: str, attr_candidates: Dict[str, List[str]], tokens: List[str]) -> None:

        for token in tokens.copy():
            if token in COMMON_INTERFACES:
                tokens.remove(token)
                attr_candidates['interface'].append(token)

        tokens = [token for token in tokens if 1 <= len(token) <= 10 and token.isalnum()]
        chunks = split_list(tokens, 3)

        for chunk in chunks:
            responses = self.run_command_in_backend(attacker_id, '; '.join([f'ip -br a | cut -d\\  -f 1 | grep -- {quote(token)}' for token in chunk]))

            for response in responses:
                interface = response.decode().strip()

                if len(interface) > 0 and interface in chunk:
                    attr_candidates['interface'].append(interface)


    def extract_domain(self, attacker_id: str, attr_candidates: Dict[str, List[str]], tokens: List[str]) -> None:

        for token in tokens:
            start = token[:15].find('://')

            if start != -1 and start + 3 < len(token):
                start += 3
                ending = token.find('/', start)

                if ending != -1:
                    domain = token[start:ending]
                else:
                    domain = token[start:]

                index = domain.find(':')

                if index == -1:
                    if token.find('http://') != -1:
                        port = '80'
                    elif token.find('https://') != -1:
                        port = '443'
                    elif token.find('ftp://') != -1:
                        port = '21'
                    elif token.find('ssh://') != -1:
                        port = '22'
                    else:
                        port = ''
                else:
                    port = domain[index + 1:]
                    domain = domain[:index]

                    if not port.isdigit():
                        port = ''

                if validators.domain(domain):
                    attr_candidates['domain'].append(domain)

                    if len(port) != 0:
                        attr_candidates['port'].append(port)

            else:
                if validators.domain(token):
                    attr_candidates['domain'].append(token)


    def extract_ip(self, attacker_id: str, attr_candidates: Dict[str, List[str]], tokens: List[str]) -> None:

        for token in tokens:
            if validators.ipv4(token):
                attr_candidates['ip'].append(token)

            else:
                start = token[:15].find('://')

                if start != -1 and start + 3 < len(token):
                    start += 3
                    ending = token.find('/', start)

                    if ending != -1:
                        ip = token[start:ending]
                    else:
                        ip = token[start:]

                    index = ip.find(':')

                    if index == -1:
                        if token.find('http://') != -1:
                            port = '80'
                        elif token.find('https://') != -1:
                            port = '443'
                        elif token.find('ftp://') != -1:
                            port = '21'
                        elif token.find('ssh://') != -1:
                            port = '22'
                        else:
                            port = ''
                    else:
                        port = ip[index + 1:]
                        ip = ip[:index]

                        if not port.isdigit():
                            port = ''

                    if validators.ipv4(ip):
                        attr_candidates['ip'].append(ip)

                        if len(port) != 0:
                            attr_candidates['port'].append(port)


    def extract_port(self, attacker_id: str, attr_candidates: Dict[str, List[str]], tokens: List[str]) -> None:

        for token in tokens:
            if token.isdigit() and int(token) in COMMON_PORTS:
                attr_candidates['port'].append(token)


    def extract_path(self, attacker_id: str, attr_candidates: Dict[str, List[str]], tokens: List[str]) -> None:

        responses = self.run_command_in_backend(attacker_id, 'pwd')

        if len(responses) > 0:
            working_dir = responses[0].decode().strip()
            working_dir = self.backend_phrase_replace(attacker_id, working_dir.encode()).decode()
        else:
            working_dir = ''


        tokens = [token for token in tokens if all(c.isalnum() or c in ['_', '-', '.', '/'] for c in token)]
        chunks = split_list(tokens, 1)

        for chunk in chunks:
            responses = self.run_command_in_backend(attacker_id, '; '.join([f'if [[ -f {quote(token)} ]] || [[ -d {quote(token)} ]]; then echo True; else echo False; fi' for token in chunk]))

            for i, response in enumerate(responses):
                if response.decode() == 'True':
                    path = chunk[i].strip()

                    # Prepend current directory to relative path.
                    if not path.startswith('/') and not path.startswith('./'):
                        if len(working_dir) > 0:
                            path = str(Path(working_dir) / Path(path))

                    attr_candidates['path'].append(path)


    def extract_attr(self, attacker_id: str, commands: List[bytes], isLogin: bool = False) -> List[str]:

        attr = list(ATTRIBUTE_DEFAULT)

        # It's a login attempt, so no command.
        if isLogin:
            if len(commands) == 2:
                attr[3] = commands[0].decode()
                attr[4] = commands[1].decode()
            else:
                log.err(f'Invalid command format for login: {commands}')

        # It's a command, parse it.
        elif len(commands) > 0:
            # Set current login username and password as default attribute.
            attr[3], attr[4] = self.get_attacker_already_login(attacker_id)

            # PPS-TODO: For now, only deal with first command.
            command = commands[0].decode()

            tokens = command.split()
            tokens = [char_remove(token, ['(', ')', '[', ']', '{', '}', '$', "'", '"']) for token in tokens]

            attr_candidates = {}
            for i, attr_name in enumerate(ATTRIBUTE_NAME):
                attr_candidates[attr_name] = []

            self.extract_exec(attacker_id, attr_candidates, tokens)
            self.extract_mailer(attacker_id, attr_candidates, tokens)
            self.extract_username(attacker_id, attr_candidates, tokens)
            self.extract_password(attacker_id, attr_candidates, tokens)
            self.extract_interface(attacker_id, attr_candidates, tokens)
            self.extract_domain(attacker_id, attr_candidates, tokens)
            self.extract_ip(attacker_id, attr_candidates, tokens)
            self.extract_port(attacker_id, attr_candidates, tokens)
            self.extract_path(attacker_id, attr_candidates, tokens)

            log.msg('attr_candidates:', attr_candidates)

            for i, attr_name in enumerate(ATTRIBUTE_NAME):
                if len(attr_candidates[attr_name]) != 0:
                    attr[i] = most_frequent(attr_candidates[attr_name])

        else:
            log.msg(f'Invalid command format: {commands}')

        return attr


    def get_attacker_already_login(self, attacker_id: str) -> List[str]:

        if attacker_id in self.login_collect:
            return self.login_collect[attacker_id]
        else:
            return []


    def check_attacker_accepted_login(self, attacker: str, username: str, password: str) -> bool:

        if attacker.find(':') == -1:
            attacker_ip = attacker
        else:
            attacker_ip = attacker.split(':')[0]

        already_login_passwords = [self.login_collect[aid][1] for aid in self.login_collect if aid.split(':')[0] == attacker_ip and self.login_collect[aid][0] == username]

        # Same attacker with same username has already logged-in.
        # In this case, there is only one valid password for the username.
        if len(already_login_passwords) > 0:
            if password in already_login_passwords:
                log.msg(f'Attacker {attacker_ip} reuse login ({username},{password}).')
                return True
            else:
                return False

        # In this case, match candidate login to the credentials provided by attacker.
        else:
            is_logged_in = False
            #is_logged_in = True
            if attacker_ip in self.login_cand_collect:
                accept_login = self.login_cand_collect[attacker_ip]
            else:
                accept_login = {}

            # Match username in accepted login.
            if username in accept_login:
                # No restriction on password.
                if len(accept_login[username]) == 0:
                    log.msg(f'Attacker {attacker_ip} login with any password ({username},{password}).')
                    is_logged_in = True

                # Apply restriction on password.
                else:
                    for accept_password in accept_login[username]:
                        if password == accept_password:
                            log.msg(f'Attacker {attacker_ip} login with exactly match ({username},{password}).')
                            is_logged_in = True
                            break

            # Save login credential for successful login to match attacker session to its login credential later.
            # Only this info can be used to log in for same attacker and same username for now.
            if is_logged_in:
                #del self.login_cand_collect[attacker_ip][username]
                log.msg(f'Attacker {attacker_ip} logged in successfully with ({username},{password}).')
                log.msg(f'Login candidate for attacker {attacker_ip} with username {username} is cleared.')
            else:
                log.msg(f'Attacker {attacker_ip} logged in failed with ({username},{password}).')

            return is_logged_in


    def query_backend_ip(self, attacker_id: str) -> str:

        attacker_ip = attacker_id.split(':')[0]
        backend_ips = [backend['guest_ip'] for backend in self.backendPool if attacker_ip in backend['client_ips']]

        if len(backend_ips) > 0:
            return backend_ips[0]

        return ''


    def pick_from_backendPool(self, exclude_ip: str = None) -> Tuple[int, str]:

        candidates = [i for i, backend in enumerate(self.backendPool) if backend['guest_ip'] != exclude_ip]

        if len(candidates) > 0:
            selected = candidates[randint(0, len(candidates) - 1)]
            return self.backendPool[selected]['id'], self.backendPool[selected]['guest_ip']

        else:
            return -1, ''


    # Action ID 1
    def action_login_add(self, attacker_id: str, attr: List[str]) -> None:

        attacker_ip = attacker_id.split(':')[0]

        if attacker_ip not in self.login_cand_collect:
            self.login_cand_collect[attacker_ip] = {}

        if attr[3] not in self.login_cand_collect[attacker_ip]:
            self.login_cand_collect[attacker_ip][attr[3]] = []

        # Add accepted login for current username with any password.
        if random() >= 0.8:
            self.login_cand_collect[attacker_ip][attr[3]].clear()

        # Add accepted login for current username with selected password.
        else:
            if len(self.login_cand_collect[attacker_ip][attr[3]]) > 0:
                selected_password = COMMON_PASSWORDS[randint(0, len(COMMON_PASSWORDS) - 1)]
                self.login_cand_collect[attacker_ip][attr[3]].append(selected_password)

        log.msg(f'[Post-Process/action_login_add] Accepted login for {attacker_ip} is updated to {self.login_cand_collect[attacker_ip]}.')


    # Action ID 2
    def action_login_remove(self, attacker_id: str, attr: List[str]) -> None:

        attacker_ip = attacker_id.split(':')[0]

        if attacker_ip in self.login_cand_collect and attr[3] in self.login_cand_collect[attacker_ip]:
            if len(self.login_cand_collect[attacker_ip][attr[3]]) == 0:
                del self.login_cand_collect[attacker_ip][attr[3]]

            else:
                # Clear all accepted login for current username.
                if random() >= 0.8:
                    del self.login_cand_collect[attacker_ip][attr[3]]

                # Clear selected accepted login for current username.
                else:
                    self.login_cand_collect[attacker_ip][attr[3]].pop(randint(0, len(self.login_cand_collect[attacker_ip][attr[3]]) - 1))

        if attacker_ip in self.login_cand_collect:
            log.msg(f'[Post-Process/action_login_remove] Accepted login for {attacker_ip} is updated to {self.login_cand_collect[attacker_ip]}.')
        else:
            log.msg(f'[Post-Process/action_login_remove] Accepted login for {attacker_ip} is cleared.')


    # Action ID 3
    def action_login_remove_all(self, attacker_id: str) -> None:

        attacker_ip = attacker_id.split(':')[0]

        if attacker_ip in self.login_cand_collect:
            del self.login_cand_collect[attacker_ip]

        log.msg(f'[Post-Process/action_login_remove_all] Accepted login for {attacker_ip} is all cleared.')


    # Action ID 5
    def action_block_access(self, attr: List[str]) -> Union[str, bytes]:

        if len(attr[0]) == 0:
            response = 'Permission denied'
        else:
            response = f'{attr[0]}: Permission denied'

        log.msg('[Post-Process/action_block_access] Set response string to "Permission denied".')

        return response


    # Action ID 6
    def action_network_block(self, attacker_id: str, attacker_cmd: bytes, attr: List[str]) -> Union[str, bytes]:

        attacker_ip = attacker_id.split(':')[0]
        src_ip = self.query_backend_ip(attacker_id)
        due = self.phrase_replace_due()

        # For domain attr.
        if attr[6] == 'localhost':
            dst_ip = src_ip
        else:
            dst_ip = attr[6]

        if len(attr[8]) > 0:
            blocker = NetworkBlocker(src_ip, dst_ip, dst_port=int(attr[8]), due=due)
        else:
            blocker = NetworkBlocker(src_ip, dst_ip, due=due)

        self.phraseReplace_collect[attacker_id].append((dst_ip.encode(), src_ip.encode(), due))
        self.iptables_applyer.sendall(blocker.serialize())
        log.msg(f'[Post-Process/action_network_block/domain] Blocked traffics from {src_ip} to {dst_ip}:{attr[8]} .')

        # For ip attr.
        if attr[7] == '127.0.0.1':
            dst_ip = src_ip
        else:
            dst_ip = attr[7]

        if len(attr[8]) > 0:
            blocker = NetworkBlocker(src_ip, dst_ip, dst_port=int(attr[8]), due=due)
        else:
            blocker = NetworkBlocker(src_ip, dst_ip, due=due)

        self.phraseReplace_collect[attacker_id].append((dst_ip.encode(), src_ip.encode(), due))
        self.iptables_applyer.sendall(blocker.serialize())
        log.msg(f'[Post-Process/action_network_block/ip] Blocked traffics from {src_ip} to {dst_ip}:{attr[8]} .')

        return attacker_cmd


    # Action ID 7
    def action_network_forward(self, attacker_id: str, attacker_cmd: bytes, attr: List[str]) -> Union[str, bytes]:

        attacker_ip = attacker_id.split(':')[0]
        src_ip = self.query_backend_ip(attacker_id)
        new_dst_ip = self.pick_from_backendPool(src_ip)[1]
        due = self.phrase_replace_due()

        if len(new_dst_ip) > 0:
            # For ip attr.
            if attr[7] == '127.0.0.1':
                dst_ip = src_ip
            else:
                dst_ip = attr[7]

            blocker = NetworkForwarder(src_ip, dst_ip, new_dst_ip, due=due)

            self.phraseReplace_collect[attacker_id].append((new_dst_ip.encode(), dst_ip.encode(), due))
            self.iptables_applyer.sendall(blocker.serialize())
            log.msg(f'[Post-Process/action_network_forward/ip] Forwarded traffics from {dst_ip} to {new_dst_ip} for source {src_ip} .')

            # For domain attr.
            if attr[6] == 'localhost':
                dst_ip = src_ip
            else:
                dst_ip = attr[6]

            blocker = NetworkForwarder(src_ip, dst_ip, new_dst_ip, due=due)

            self.phraseReplace_collect[attacker_id].append((new_dst_ip.encode(), dst_ip.encode(), due))
            self.iptables_applyer.sendall(blocker.serialize())
            log.msg(f'[Post-Process/action_network_forward/domain] Forwarded traffics from {dst_ip} to {new_dst_ip} for source {src_ip} .')

        else:
            log.msg('[Post-Process/action_network_forward] No forward destination available.')

        return attacker_cmd


    # Action ID 8
    def action_replace_str(self, attacker_cmd: bytes, attr: List[str]) -> Union[str, bytes]:

        for att in attr[1:]:
            if len(att) > 0 and att.encode() in attacker_cmd and random() >= 0.7:
                attacker_cmd = attacker_cmd.replace(att.encode(), b'')
                log.msg(f'[Post-Process/action_replace_str] Replaced string from "{att}" to "".')

        return attacker_cmd


    # Action ID 9
    def action_replace_system_str_(self, content: bytes) -> bytes:

        # For interface.
        tokens = str_extra_split(content.decode(), '=:')
        tokens = list(set(tokens))

        for token in tokens:
            if token in COMMON_INTERFACES and token != 'lo':
                old_interface = token
                new_interface = token[:-1] + str(randint(1, 9))
                content = content.replace(old_interface.encode(), new_interface.encode())
                log.msg(f'[Post-Process/action_replace_system_str_] Replaced interface from {old_interface} to {new_interface} .')

        # For ip.
        old_ips = re.findall(rb'192\.168\.5\.\d{1,3}', content)

        for old_ip in old_ips:
            if not old_ip.endswith(b'.255'):
                new_ip = b'192.168.5.' + str(randint(2, 254)).encode()
                content = content.replace(old_ip, new_ip)
                log.msg(f'[Post-Process/action_replace_system_str_] Replaced ip from {old_ip.decode()} to {new_ip.decode()} .')

        return content


    # Action ID 10
    def action_version_variation_(self, content: bytes) -> bytes:

        versions = re.findall(rb'\b\d{1,2}\.\d{1,2}\.\d+\b', content)
        versions = list(set(versions))

        for old_version in versions:
            x, y, z = old_version.split(b'.')
            x = int(x.decode())
            y = int(y.decode())
            z = int(z.decode())

            y -= randint(0, y)
            z -= randint(0, z)
            new_version = f'{x}.{y}.{z}'.encode()

            log.msg(f'[Post-Process/action_version_variation_] Variant the version number from {old_version} to {new_version} .')
            content = content.replace(old_version, new_version)

        return content


    # Action ID 11
    def action_show_part_output_(self, attacker_id: str, attr: List[str], content: bytes) -> bytes:

        # For interface.
        tokens = str_extra_split(content.decode(), '=:')
        tokens = list(set(tokens))

        for token in tokens:
            if token in COMMON_INTERFACES and token != 'lo':
                log.msg(f'[Post-Process/action_show_part_output_] Stop the output due to interface "{token}".')
                return b'Permission denied.\r\n'

        # For consecutive two new lines.
        if len(self.respHistory_collect[attacker_id]) > 0 and self.respHistory_collect[attacker_id][-1] == b'\r\n' and content == b'\r\n':
            log.msg('[Post-Process/action_show_part_output_] Stop the output due to consecutive two new lines.')
            return b'Permission denied.\r\n'

        # For username.
        if attr[3].encode() in content:
            log.msg(f'[Post-Process/action_show_part_output_] Stop the output due to username "{attr[3]}".')
            return b'Permission denied.\r\n'

        return content


    # Action ID 12
    def action_stuff(self, attacker_cmd: bytes) -> Union[str, bytes]:

        response = b'for ((;;)); do bash -c ' + quote(attacker_cmd.decode()).encode() + b'; done'
        log.msg('[Post-Process/action_stuff] Stuff repeated and endless output back.')

        return response


    # Action ID 13
    def action_leak_info(self, attacker_id: str, attacker_cmd: bytes) -> Union[str, bytes]:

        # Fake login record.
        username = self.get_attacker_already_login(attacker_id)[0]
        ip = self.pick_from_backendPool(self.query_backend_ip(attacker_id))[1]
        port = randint(50000, 60000)
        records = self.run_command_in_backend(attacker_id, f"cat /var/log/auth.log | grep --color=never 'Accepted password'")

        if len(ip) > 0:
            if len(records) == 0:
                record = datetime.now().strftime('%b %d %H:%M:%S') + f' localhost sshd[{randint(1000, 100000)}]: Accepted password for username from 127.0.0.1 port 1234 ssh2'
            else:
                record = records[0].decode()

            record = re.sub(r'for [a-z0-9.-_]+', f'for {username}', record)
            record = re.sub(r'from [0-9.]+', f'from {ip}', record)
            record = re.sub(r'port [0-9]+', f'port {port}', record)

            log.msg(f'[Post-Process/action_leakInfo] Add a login record "{record}" in /var/log/auth.log file.')
            self.run_command_in_backend(attacker_id, f"echo {self.backend_login['root_password']} | sudo -S bash -c \"echo '{record}' >> /var/log/auth.log; #{self.backend_hidden_phrase}\"")

        else:
            log.msg('[Post-Process/action_leakInfo] No fake ip available.')

        return attacker_cmd


    # Action ID 14
    def action_send_phishing_email(self, attacker_id: str, attacker_cmd: bytes) -> Union[str, bytes]:

        backend_ip = self.query_backend_ip(attacker_id)
        email_domain = backend_ip.replace('.', '-') + '.local'
        sender = self.get_attacker_already_login(attacker_id)[0] + '@' + email_domain
        receiver = COMMON_USERNAMES[randint(0, len(COMMON_USERNAMES) - 1)] + '@' + email_domain
        subject = f'[Warn] Security event on vserver {backend_ip}'
        content = ''.join((f'Several security events occurred on vserver internal-ip={backend_ip} !\n'
                           f'Please login and check running process or system log.\n'
                           f'Check this: "http://{backend_ip}/security/admin".\n',
                           f' - From DEFENDER v2.1.0'))
        send_cmd = f"echo {quote(content)} | mail -s {quote(subject)} -a 'From: {sender}' '{receiver}'"

        log.msg(f'[Post-Process/action_send_phishing_email] Send phishing e-mail with command "{send_cmd}".')
        self.run_command_in_backend(attacker_id, send_cmd)

        return attacker_cmd


    # Action ID 15
    def action_reset(self, attacker_id: str) -> Union[str, bytes]:

        log.msg('[Post-Process/action_reset] Shutdown vm in backend pool to reset.')
        self.run_command_in_backend(attacker_id, f"echo {self.backend_login['root_password']} | sudo -S bash -c 'poweroff; #{self.backend_hidden_phrase}'")

        return ''


    # Action ID 16
    def action_kill_attacker_launched(self, attacker_id: str, attacker_cmd: bytes) -> Union[str, bytes]:

        usernames = [self.backend_login['username'], self.get_attacker_already_login(attacker_id)[0], 'root']

        for username in usernames:
            kill_after = self.firstExec_until_now(attacker_id)

            if kill_after >= 3:
                pids = self.run_command_in_backend(attacker_id, f"echo {self.backend_login['root_password']} | sudo -S bash -c 'ps -e -o pid,user:255,etimes,comm | awk -v me={username} '\\''$2 == me && $3 <= {kill_after} {{ print $1 }}'\\''; #{self.backend_hidden_phrase}'")
                pids = [int(pid.decode()) for pid in pids if pid.decode().isdigit()]

                for pid in pids:
                    self.run_command_in_backend(attacker_id, f"echo {self.backend_login['root_password']} | sudo -S bash -c 'kill -9 {pid}; #{self.backend_hidden_phrase}'")
                    log.msg(f'[Post-Process/action_kill_attacker_launched] Killed (user = {username}, pid = {pid}) launched by attacker.')

        return attacker_cmd


    def firstExec_until_now(self, attacker_id: str) -> int:

        if attacker_id in self.firstExec_collect:
            return int(floor((datetime.now() - self.firstExec_collect[attacker_id]).total_seconds()))
        else:
            return -1


    def init_attacker(self, attacker_id: str, attackerCon: Union[FrontendSSHTransport, None], backendCon: Union[BackendSSHTransport, None], isLogin: bool = False) -> None:

        # Create objects for new attacker.
        if attacker_id not in self.cmdHistory_collect:
            self.cmdHistory_collect[attacker_id] = []
        else:
            log.msg(f'Reuse existing cmd history len={len(self.cmdHistory_collect[attacker_id])}.')

        if attacker_id not in self.loginState_collect:
            if isLogin:
                self.loginState_collect[attacker_id] = LoginState.TRY_LOGIN
            else:
                self.loginState_collect[attacker_id] = LoginState.NORMAL_USER
        else:
            log.msg(f'Reuse existing login state {self.loginState_collect[attacker_id]}.')

        if attacker_id not in self.phraseReplace_collect:
            self.phraseReplace_collect[attacker_id] = []
        else:
            log.msg('Reuse existing phrase replacement.')

        if attacker_id not in self.firstExec_collect:
            self.firstExec_collect[attacker_id] = datetime.now()
        else:
            log.msg(f'Reuse existing first execution timestamp (firstExec={self.firstExec_collect[attacker_id]}, untilNow={self.firstExec_until_now(attacker_id)}sec).')

        # Got attacker connection and backend pool connection.
        if not isLogin:
            self.attackerCon_collect[attacker_id] = attackerCon
            self.backendCon_collect[attacker_id] = backendCon

        # Initialize response history for this attacker.
        # Initialize response history filter for this attacker.
        self.respHistory_collect[attacker_id] = []
        self.respFilter_collect[attacker_id] = None


    def add_task(self, attacker_id: str, commands: List[bytes], isLogin: bool = False) -> List[bool]:

        self.logger.log(f'Attacker {attacker_id} is using backend VM {self.query_backend_ip(attacker_id)} .', LoggingType.DEBUG)

        # For logged-in task, init_attacker() is already called in set_client() in ssh.py .
        # Only do this for try to log in session.
        if isLogin:
            self.init_attacker(attacker_id, None, None, True)

        # New attacker.
        if attacker_id not in self.ei_collect:
            # In training mode.
            # Use the same engage object for all login attempts and all commands.
            if self.is_training:
                # Create a shared engage object.
                if SHARED_ENGAGE_INTERFACE_NAME not in self.ei_collect:
                    self.ei_collect[SHARED_ENGAGE_INTERFACE_NAME] = EngageInterface()

                self.ei_collect[attacker_id] = self.ei_collect[SHARED_ENGAGE_INTERFACE_NAME]
                log.msg('Reuse shared engage handler connection.')

            # In runtime mode.
            # Just assign new engage object.
            else:
                self.ei_collect[attacker_id] = EngageInterface()
                log.msg('Create new engage handler connection.')

        # Already exists attacker.
        else:
            log.msg('Reuse existing engage handler connection.')

        # Add to dealing list.
        # Delete these entries after done.
        self.attacker_collect.append(attacker_id)
        self.backendPacket_collect[attacker_id] = []
        self.clearer_collect[attacker_id] = []

        self.autoSudo_collect[attacker_id] = False

        # Start a thread to handle this task.
        lazy_return = []
        t = Thread(target=self.run_task, args=(attacker_id, commands, lazy_return, isLogin))
        t.start()

        # PPS-TODO: This seems to be useless.
        #self.tasks.append(t)

        return lazy_return


    def run_task(self, attacker_id: str, commands: List[bytes], lazy_return: List[bool], isLogin: bool = False) -> None:

        # PPS:
        # (0) Add attacker commands to command history.
        # (1) Extract attr[] from commands.
        # (2) Execute commands in wazuh agent just like what attackers do to get techniques.
        # (3) Mapping techniques to suggested activities.
        # (4) Update login state for this attacker.
        # (5) Provide new state to engage handler and get selected action.
        # (6) Do post-process to execute commands in backend pool and generate response to attacker.
        # (7) Response to attacker with generated response.

        attacker_ip = attacker_id.split(':')[0]

        # (0)
        # PPS-TODO: This should be done in mysql.
        #self.cmdHistory_collect[attacker_id] += commands

        # (1)
        attr = self.extract_attr(attacker_id, commands, isLogin)
        log.msg(f'Attributes extracted: (exec={attr[0]}, mail_sender={attr[1]}, mail_receiver={attr[2]}, username={attr[3]}, password={attr[4]}, interface={attr[5]}, domain={attr[6]}, ip={attr[7]}, port={attr[8]}, path={attr[9]}) from command.')
        self.logger.log(f'Attributes extracted: (exec={attr[0]}, mail_sender={attr[1]}, mail_receiver={attr[2]}, username={attr[3]}, password={attr[4]}, interface={attr[5]}, domain={attr[6]}, ip={attr[7]}, port={attr[8]}, path={attr[9]}) from command.', LoggingType.DEBUG)

        # (2)
        if isLogin:
            techniques = ['T1110', 'T1021']
        else:
            techniques = self.wi.attacker_command_handler(attacker_ip, commands)

        self.logger.log('ATT&CK Techniques are [' + ', '.join(techniques) + ']', LoggingType.DEBUG)

        # (3)
        suggested_activities = attack2engage.technique2activities_union(techniques)
        self.logger.log('Suggested Engage Activities are [' + ', '.join(suggested_activities) + ']', LoggingType.DEBUG)

        # (4)
        if not isLogin:
            responses = self.run_command_in_backend(attacker_id, 'id -u')

            if len(responses) > 0 and responses[0].decode().isdigit():
                uid = int(responses[0].decode())

                if uid == 0:
                    self.loginState_collect[attacker_id] = LoginState.ROOT_USER
                    log.msg(f'Login state updated to "{self.loginState_collect[attacker_id]}".')
                    self.logger.log(f'Login state updated to "{self.loginState_collect[attacker_id]}".')
            else:
                log.err('Failed to update login state by command $(id -u).')
                self.logger.log('Failed to update login state by command $(id -u).', LoggingType.FAILED)

        # (5)
        selected_action = self.ei_collect[attacker_id].next_step(self.loginState_collect[attacker_id], attr, suggested_activities)
        self.logger.log(f'Selected action is {selected_action} "{ACTION_ID2NAME[selected_action]}".')

        # (6)
        response = ''

        self.logger.log('[Post-Process] Setting ...', LoggingType.DEBUG)

        # Only do this when (attacker try to log in) and (engage handler selects login related action).
        if self.loginState_collect[attacker_id] == LoginState.TRY_LOGIN and 1 <= selected_action <= 3:
            if selected_action == 1:
                self.action_login_add(attacker_id, attr)
            elif selected_action == 2:
                self.action_login_remove(attacker_id, attr)
            else:
                self.action_login_remove_all(attacker_id)

        # Only do this when (attacker is logged in).
        elif self.loginState_collect[attacker_id] != LoginState.TRY_LOGIN:
            if selected_action == 1:
                self.action_login_add(attacker_id, attr)
            elif selected_action == 2:
                self.action_login_remove(attacker_id, attr)
            elif selected_action == 3:
                self.action_login_remove_all(attacker_id)
            elif selected_action == 4:
                self.autoSudo_collect[attacker_id] = True
                response = commands[0]
            elif selected_action == 5:
                response = self.action_block_access(attr)
            elif selected_action == 6:
                response = self.action_network_block(attacker_id, commands[0], attr)
            elif selected_action == 7:
                response = self.action_network_forward(attacker_id, commands[0], attr)
            elif selected_action == 8:
                response = self.action_replace_str(commands[0], attr)
            elif selected_action == 9:
                self.respFilter_collect[attacker_id] = (self.action_replace_system_str_, ())
                response = commands[0]
            elif selected_action == 10:
                self.respFilter_collect[attacker_id] = (self.action_version_variation_, ())
                response = commands[0]
            elif selected_action == 11:
                self.respFilter_collect[attacker_id] = (self.action_show_part_output_, (attacker_id, attr))
                response = commands[0]
            elif selected_action == 12:
                response = self.action_stuff(commands[0])
            elif selected_action == 13:
                response = self.action_leak_info(attacker_id, commands[0])
            elif selected_action == 14:
                response = self.action_send_phishing_email(attacker_id, commands[0])
            elif selected_action == 15:
                response = self.action_reset(attacker_id)
            else:
                response = self.action_kill_attacker_launched(attacker_id, commands[0])

        self.logger.log('[Post-Process] Setting ... Done', LoggingType.DEBUG)

        # (7)
        # Response to attacker.
        # This function only call for logged in state.
        # For trying login state, no response should be generated to attacker.
        if isLogin:
            lazy_return.append(True)
        else:
            self.complete_task(attacker_id, response)


    def complete_task(self, attacker_id: str, response: Union[str, bytes]) -> None:

        log.msg('[Post-Process] Completing task ...')
        self.logger.log('[Post-Process] Completing task ...', LoggingType.DEBUG)

        # Run command (don't need to wait for complete) and return control to cowrie.
        if type(response) is bytes:
            log.msg(f'Run command "{response}" and response the result to attacker.')
            self.logger.log(f'Run command "{response}" and response the result to attacker.', LoggingType.DEBUG)

            # Add clearer to ask cowrie to ignore special phrase when sending packet back to attacker.
            self.clearer_collect[attacker_id].append(response)
            self.clearer_collect[attacker_id].append(ResponseGenerator.PASTING_ESCAPE_TERMINATOR)

            # Delete entries to return control to cowrie.
            self.attacker_collect.remove(attacker_id)

            # Do the command to generate response to attacker.
            self.send_packet_to(attacker_id, True, response + b'\r')

        # Return plain text with prompt to attacker and return control to cowrie.
        else:
            log.msg(f'Response plain text "{response}" to attacker directly.')
            self.logger.log(f'Response plain text "{response}" to attacker directly.', LoggingType.DEBUG)

            if len(response) > 0:
                if not response.endswith('\r\n'):
                    response += '\r\n'

                self.send_packet_to(attacker_id, False, response)

            # Get prompt from backend.
            backend_prompt = self.backend_prompt(attacker_id, True)

            log.msg(self.attacker_collect)
            log.msg(attacker_id)
            # Delete entries to return control to cowrie.
            self.attacker_collect.remove(attacker_id)

            # Send backend prompt back to attacker.
            self.send_packet_to(attacker_id, False, backend_prompt)
            print(f'Sent backend prompt "{backend_prompt}" back to attacker "{attacker_id}".')

        # Lazy delete entries to return control to cowrie.
        if attacker_id in self.backendPacket_collect:
            del self.backendPacket_collect[attacker_id]
        else:
            log.msg(f'Attacker leaves before response generator complete task.')

        log.msg('[Post-Process] Completing task ... Done')
        self.logger.log('[Post-Process] Completing task ... Done', LoggingType.DEBUG)


    def send_packet_to(self, attacker_id: str, is_toBackend: bool, content: Union[str, bytes]) -> bool:

        if is_toBackend:
            target = self.backendCon_collect
            target_phrase = 'backend pool'
        else:
            target = self.attackerCon_collect
            target_phrase = 'attacker'

        if type(content) is str:
            content = content.encode()

        payloads = ResponseGenerator.generate_packets(content)

        if len(payloads) > 0:
            if attacker_id in target:
                for payload in payloads:
                    target[attacker_id].sendPacket(ResponseGenerator.MESSAGE_NUM, payload)
                return True
            else:
                log.err(f'Invalid attacker id "{attacker_id}", so no packet sent to {target_phrase}.')
                log.err(f'Available attacker ids are {list(target.keys())}.')
                return False

        else:
            return False


    def run_command_in_backend(self, attacker_id: str, command: Union[str, bytes], pre_run: bool = False) -> List[bytes]:

        # This method runs command and prevent from being discovered by attacker.
        # To prevent from mixing our data with attacker data, this method should be called during run_task().

        if attacker_id in self.attacker_collect:
            if type(command) is str:
                command = command.encode()

            if len(command) == 0:
                return []

            if not pre_run:
                self.run_command_in_backend(attacker_id, b'\x03', True)
                log.msg(f'Run command in backend pool: {command}')
            else:
                log.msg(f'Pre-run command in backend pool: {command}')

            responses = []

            if self.send_packet_to(attacker_id, True, command + b'\r'):
                is_done = False
                is_output = False
                ignore_is_output = True

                # Wait until shell prompt back.
                while not is_done:
                    if attacker_id in self.backendPacket_collect:
                        if len(self.backendPacket_collect[attacker_id]) > 0:
                            packet = self.backendPacket_collect[attacker_id].pop(0)

                            if is_output and ignore_is_output:
                                ignore_is_output = False

                            # Ignore original command.
                            # it's just typing echo not command execution result.
                            if not is_output and command in packet:
                                is_output = True

                            if ResponseGenerator.has_prompt(packet):
                                is_done = True
                            else:
                                if not ignore_is_output and is_output:
                                    responses.append(packet)

                    else:
                        log.msg(f'Attacker leaves before response generator run_command_in_backend().')
                        return responses

                # Clean start of responses.
                while len(responses) != 0:
                    if (responses[0] == b'\r\n' or responses[0] == b'\r' or responses[0] == b'\n'
                            or ResponseGenerator.PASTING_ESCAPE_TERMINATOR in responses[0]):
                        responses.pop(0)
                    else:
                        break

                # Clean end of responses.
                while len(responses) != 0:
                    i = len(responses) - 1

                    if (responses[i] == b'\r\n' or responses[i] == b'\r' or responses[i] == b'\n'
                            or ResponseGenerator.PASTING_ESCAPE_STARTER in responses[i]):
                        responses.pop(i)
                    else:
                        break

            return responses

        else:
            log.err(f'run_command_in_backend() should be called only from run_task().')
            return []


    def backend_prompt(self, attacker_id: str, phrase_replace: bool = False) -> bytes:

        if attacker_id in self.attacker_collect:
            self.send_packet_to(attacker_id, True, '\x03')

            while True:
                if attacker_id in self.backendPacket_collect:
                    if len(self.backendPacket_collect[attacker_id]) > 0:
                        packet = self.backendPacket_collect[attacker_id].pop(0)

                        if ResponseGenerator.has_prompt(packet):
                            start = packet.find(ResponseGenerator.filter_prompt(packet)[0])
                            prompt = packet[start:]

                            if phrase_replace:
                                prompt = self.backend_phrase_replace(attacker_id, prompt)

                            return prompt

                else:
                    log.msg(f'Attacker leaves before response generator get backend_prompt().')
                    return b''

        else:
            log.err(f'backend_prompt() should be called only from run_task().')
            return b''


    def backend_hidden_phrase_remove(self, content: bytes) -> bytes:

        # Ignore our records by identify hidden phrase.

        if len(self.backend_hidden_phrase) > 0:
            lines = content.split(b'\r\n')

            for line in lines.copy():
                if self.backend_hidden_phrase.encode() in line:
                    lines.remove(line)

            content = b'\r\n'.join(lines)

        return content


    def backend_phrase_replace(self, attacker_id: str, content: bytes) -> bytes:

        # Replace real backend info with attacker info.

        # Replace real username with logged-in username.
        if len(self.get_attacker_already_login(attacker_id)) > 0:
            content = content.replace(self.backend_login['username'].encode(), self.get_attacker_already_login(attacker_id)[0].encode())

        # Replace real password with empty string.
        content = content.replace(self.backend_login['password'].encode(), b'')

        # Replace phrase and clear due for engage action.
        if attacker_id in self.phraseReplace_collect:
            i = 0
            while i < len(self.phraseReplace_collect[attacker_id]):
                if self.phraseReplace_collect[attacker_id][i][2] <= datetime.now():
                    self.phraseReplace_collect[attacker_id].pop(i)
                else:
                    rule = self.phraseReplace_collect[attacker_id][i]
                    content = content.replace(rule[0], rule[1])

                    i += 1

        return content


    def close(self, attacker_id: str) -> None:

        if attacker_id in self.attacker_collect:
            # Delete entries to return control to cowrie.
            self.attacker_collect.remove(attacker_id)

            # Clear unhandled packets and release entry.
            if attacker_id in self.backendPacket_collect:
                self.backendPacket_collect[attacker_id].clear()
                del self.backendPacket_collect[attacker_id]

        if attacker_id in self.loginState_collect:
            del self.loginState_collect[attacker_id]

        # Close the connection to engage handler and delete entry.
        if self.is_training:
            # Only delete the entry for this attacker.
            # Don't delete the engage object, because it is a shared object.
            del self.ei_collect[attacker_id]

        else:
            if attacker_id in self.ei_collect:
                self.ei_collect[attacker_id].close()
                del self.ei_collect[attacker_id]


    def close_all(self) -> None:

        self.iptables_applyer.sendall(b'CLOSE')
        self.iptables_applyer.close()

        # Clean objects.
        # However, shared engage handler object will be left.
        for attacker_id in self.ei_collect:
            self.close(attacker_id)

        # Clean shared engage handler object.
        if SHARED_ENGAGE_INTERFACE_NAME in self.ei_collect:
            self.ei_collect[SHARED_ENGAGE_INTERFACE_NAME].close()
            del self.ei_collect[SHARED_ENGAGE_INTERFACE_NAME]


def load_common_phrase() -> None:

    global COMMON_EXEC, COMMON_USERNAMES, COMMON_PASSWORDS

    # From Ubuntu 22.04 /usr/bin
    with open(Path(__file__).parents[1] / 'share/cowrie/response_generator/exec.txt', 'r') as fin:
        execs = fin.readlines()

    execs = [e.strip() for e in execs]

    log.msg(f'Loaded {len(execs)} execs from file.')

    COMMON_EXEC = tuple(list(COMMON_EXEC) + execs)


    # From https://github.com/jeanphorn/wordlist/blob/master/usernames.txt
    with open(Path(__file__).parents[1] / 'share/cowrie/response_generator/usernames.txt', 'r') as fin:
        usernames = fin.readlines()

    # Only preserve len(username) >= 3 .
    usernames = [username.strip() for username in usernames if len(username) >= 3]

    log.msg(f'Loaded {len(usernames)} usernames from file.')

    COMMON_USERNAMES = tuple(list(COMMON_USERNAMES) + usernames)


    with open(Path(__file__).parents[1] / 'share/cowrie/response_generator/rockyou.txt', 'r') as fin:
        passwords = fin.readlines()

    passwords = [password.strip() for password in passwords]

    log.msg(f'Loaded {len(passwords)} passwords from file.')

    COMMON_PASSWORDS = tuple(list(COMMON_PASSWORDS) + passwords)


# Load common phrases during module imported.
load_common_phrase()
