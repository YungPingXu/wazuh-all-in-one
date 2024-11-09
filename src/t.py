
# PPS-TODO: Auto reboot or reset dead vm.

from typing import Tuple, List, Dict, Union
from time import time, sleep
from datetime import datetime, timedelta
from random import randint
import json
from pathlib import Path
import urllib3
import requests
from requests.auth import HTTPBasicAuth
import paramiko
from paramiko.ssh_exception import AuthenticationException
from paramiko import SSHClient
from paramiko.channel import Channel
from twisted.python import log
import os

urllib3.disable_warnings()


class WazuhInterface:

    @staticmethod
    def events_fetch_techniques(events: dict) -> List[str]:

        techniques = []

        for event in events:
            if 'mitre' in event['_source']['rule']:
                for technique in event['_source']['rule']['mitre']['id']:
                    pos = technique.find('.')
                    technique = [technique[:pos] if pos >= 0 else technique][0]

                    techniques.append('T' + technique.replace('T', ''))

        techniques = list(set(techniques))
        techniques.sort()

        return techniques


    def __init__(self):

        self.target = {}
        self.provider = {}
        self.indexer = {}
        self.vm_info = {}

        self.target_con: Union[SSHClient, None] = None
        self.vm_size = 1
        self.all_vm: List[Dict[str, Union[str, int, List[str], List[Union[Channel, SSHClient]], datetime]]] = []

        # PPS-TODO: Wazuh event delay problem should be solved.
        self.pulled_wazuh_event_id: List[str] = []

        self.read_config()


    def read_config(self) -> None:

        with open(Path(__file__).parents[1] / 'etc/wazuh_interface.json', 'r') as fin:
            config = json.load(fin)

        self.target['ip'] = config['target']['ip']
        self.target['port'] = config['target']['port']
        self.target['username'] = config['target']['username']
        self.target['password'] = config['target']['password']
        self.provider['ip'] = config['provider']['ip']
        self.provider['port'] = config['provider']['port']
        self.provider['username'] = config['provider']['username']
        self.provider['password'] = config['provider']['password']
        self.indexer['ip'] = config['indexer']['ip']
        self.indexer['port'] = config['indexer']['port']
        self.indexer['username'] = config['indexer']['username']
        self.indexer['password'] = config['indexer']['password']
        self.vm_size = config['vm']['size']
        self.vm_info['destroy_before_start'] = config['vm']['destroy_before_start']
        self.vm_info['destroy_before_stop'] = config['vm']['destroy_before_stop']
        self.vm_info['username'] = config['vm']['username']
        self.vm_info['password'] = config['vm']['password']
        self.vm_info['network_interface'] = config['vm']['network_interface']
        self.vm_info['base_image'] = config['vm']['base_image']

        # VM id should be restricted to 0-255 (0x0-0xff)
        # because vm id will be used as last byte of mac address.
        assert self.vm_size <= 255


    def init_target_connection(self) -> None:

        self.target_con = SSHClient()
        self.target_con.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.target_con.load_system_host_keys()

        while True:
            try:
                self.target_con.connect(self.target['ip'], self.target['port'], self.target['username'], self.target['password'])
            except TimeoutError:
                log.msg(f'Wazuh interface failed to connect to {self.target["ip"]}:{self.target["port"]}.')
            except paramiko.ssh_exception.SSHException:
                log.msg(f'Wazuh interface failed to connect to {self.target["ip"]}:{self.target["port"]}.')
            else:
                break

            sleep(3)


    def init_vm_connection(self, vm: Union[int, str], bypass_vm_id: bool = False) -> Union[None, Tuple[Channel, SSHClient]]:

        vm_ip = ''

        if type(vm) is int:
            if 0 <= vm < self.vm_size:
                vm_ip = self.all_vm[vm]['ip']
        elif type(vm) is str:
            vm_ip = vm
        else:
            raise TypeError('Parameter vm should be an integer (represents VM id) or string (represents a IP).')

        assert len(vm_ip) > 0

        vm_id = self.query_vm_id(vm_ip)

        if not bypass_vm_id:
            assert 0 <= vm_id < self.vm_size

        proxy = self.target_con.get_transport().open_channel('direct-tcpip', (vm_ip, 22), ('127.0.0.1', 22))
        qvm = SSHClient()
        qvm.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        while True:
            try:
                qvm.connect(vm_ip, 22, self.vm_info['username'], self.vm_info['password'], sock=proxy)
            except AuthenticationException:
                log.msg(f'Failed to connect to {vm_ip} by ({self.vm_info["username"]}, {self.vm_info["password"]}) due to authentication error.')
            else:
                break

            sleep(1)

        if not bypass_vm_id:
            self.all_vm[vm_id]['con'].append(proxy)
            self.all_vm[vm_id]['con'].append(qvm)
        else:
            return proxy, qvm


    def vm_run_commands(self, commands: Union[List[str], List[bytes], str], vm: Union[int, str], bypass_vm_id: bool = False, set_timeout: bool = False) -> Tuple[List[str], List[str], List[str]]:

        vm_ip = ''

        if type(vm) is int:
            if 0 <= vm < self.vm_size:
                vm_ip = self.all_vm[vm]['ip']
        elif type(vm) is str:
            vm_ip = vm
        else:
            raise TypeError('Parameter vm should be an integer (represents VM id) or string (represents a IP).')

        if len(vm_ip) == 0:
            log.err('Unexpected error: vm ip should NOT be empty.')
            return [], [], []

        vm_id = self.query_vm_id(vm_ip)

        if not bypass_vm_id:
            if vm_id == -1 or vm_id >= self.vm_size:
                log.err(f'Unexpected error: vm id should NOT be {vm_id}.')
                return [], [], []

        if type(commands) is str:
            commands = [commands,]
        elif len(commands) > 0 and type(commands[0]) is bytes:
            command: bytes
            commands = [command.decode() for command in commands]

        stdin_collect = []
        stdout_collect = []
        stderr_collect = []

        if not bypass_vm_id:
            qvm: SSHClient = self.all_vm[vm_id]['con'][1]
        else:
            log.msg(vm_ip)
            proxy, qvm = self.init_vm_connection(vm_ip, bypass_vm_id)

        for i, command in enumerate(commands):
            command: str

            try:
                if set_timeout:
                    timeout = 3
                else:
                    timeout = None

                log.msg(f'Executing command "{command}" in vm {vm_ip} with timeout {timeout}.')
                stdin, stdout, stderr = qvm.exec_command(command)
                start_time = datetime.now()

                if timeout is not None:
                    while not stdout.channel.eof_received:
                        if (datetime.now() - start_time).total_seconds() >= timeout:
                            stdin.channel.close()
                            stdout.channel.close()
                            stderr.channel.close()
                            log.msg(f'Command execution timeout!')
                            break

                        sleep(0.5)

            except paramiko.ssh_exception.SSHException as e:
                log.err(e)
                self.handle_unexpected_vm(vm_ip)
                return [], [], []

            else:
                # stdin_collect.append()
                stdout_collect.append(stdout.read().decode().strip())
                stderr_collect.append(stderr.read().decode().strip())

        if bypass_vm_id:
            qvm.close()
            proxy.close()

        return stdin_collect, stdout_collect, stderr_collect


    def is_file_on_target(self, filename: str) -> bool:
        print(filename)
        stdin, stdout, stderr = self.target_con.exec_command(f'if [[ -f "{filename}" ]]; then echo True; else echo False; fi')
        print(stdin, stdout, stderr)
        is_file_exists = True if stdout.read().decode().strip() == 'True' else False

        return is_file_exists


    def copy_base_image(self) -> None:

        assert self.is_file_on_target(self.vm_info["base_image"])

        for i in range(self.vm_size):
            vm_disk = str(Path(self.vm_info["base_image"]).parents[0] / f'qvm{i}.qcow2')

            if self.is_file_on_target(vm_disk):
                log.msg(f'Disk file already exists "{vm_disk}".')
            else:
                log.msg(f'Copying disk file "{vm_disk}" ...')
                stdin, stdout, stderr = self.target_con.exec_command(f'cp "{self.vm_info["base_image"]}" "{vm_disk}"; echo True')
                stdout.read().decode()  # Wait for "True" string returned. Paramiko seems to have no blocking mechanism.
                log.msg(f'Copying disk file "{vm_disk}" ... Done')


    def scan_vm(self, vm_ip: str = '') -> List[str]:
        log.msg(vm_ip)
        if len(vm_ip) == 0:
            stdin, stdout, stderr = self.target_con.exec_command('nmap -sn 192.168.4.0/24')
        else:
            stdin, stdout, stderr = self.target_con.exec_command(f'nmap -sn {vm_ip}/32')
        log.msg(stdin, stdout, stderr)
        scanned = [line for line in stdout.read().decode().split('\n') if len(line) > 0]
        hosts = scanned[1:-1][::2]
        hosts = [host.replace('Nmap scan report for ', '') for host in hosts]
        up_hosts = [host for host in hosts if not host.endswith('.1')]

        return up_hosts


    def update_vm(self, vm_ip: str = '') -> int:
        log.msg(vm_ip)
        if len(vm_ip) == 0:
            log.msg('Scanning vm in the local network 192.168.4.0/24 .')
            vm_ips = self.scan_vm()
            log.msg(vm_ips)

            if len(vm_ips) > self.vm_size:
                log.msg(f'There are {len(vm_ips)} VMs up on the system. However, we need only {self.vm_size}.')

            available_vm_id = []
            orphan_attackers = []

            # Update vm with ip to all_vm variable.
            for vm_ip in vm_ips:
                vm_id = self.get_vm_id(vm_ip)
                vm_pid = self.get_vm_pid(vm_id)
                agent_id = self.get_vm_agentId(vm_ip)
                original_ip = self.all_vm[vm_id]['ip']

                if vm_id == -1 or vm_pid == -1:
                    continue

                self.all_vm[vm_id]['ip'] = vm_ip
                self.all_vm[vm_id]['pid'] = vm_pid
                self.all_vm[vm_id]['agent_id'] = agent_id

                # Original vm ip is empty, but it is assigned now.
                if len(original_ip) == 0 and self.all_vm[vm_id]['ip'] != original_ip:
                    # Create new connection.
                    self.init_vm_connection(vm_id)
                    self.all_vm[vm_id]['indexer_last_hit'] = datetime.now()

                # Original vm ip is NOT empty, but it is changed now.
                elif len(original_ip) > 0 and self.all_vm[vm_id]['ip'] != original_ip:
                    # Clear old connection.
                    self.all_vm[vm_id]['con'][1].close()
                    self.all_vm[vm_id]['con'][0].close()
                    self.all_vm[vm_id]['indexer_last_hit'] = datetime.now()

                    # Create new connection.
                    self.init_vm_connection(vm_id)

                available_vm_id.append(vm_id)

            available_vm_id = list(set(available_vm_id))

            # Check for unexpected stopped vm.
            for i, vm in enumerate(self.all_vm):
                if i not in available_vm_id and len(self.all_vm[i]['ip']) > 0:
                    if len(self.all_vm[i]['attacker_ip']) > 0:
                        for attacker_ip in self.all_vm[i]['attacker_ip']:
                            log.err(f'Vm{i} for attacker IP {attacker_ip} is no longer available.')
                            orphan_attackers.append(attacker_ip)

                    self.all_vm[i]['ip'] = ''
                    self.all_vm[i]['pid'] = -1
                    self.all_vm[i]['agent_id'] = -1
                    self.all_vm[i]['attacker_ip'].clear()
                    self.all_vm[i]['con'][1].close()
                    self.all_vm[i]['con'][0].close()
                    self.all_vm[i]['con'].clear()
                    self.all_vm[i]['indexer_last_hit'] = datetime.now()

            # Assign new vm for orphan attackers.
            for attacker_ip in orphan_attackers:
                vm_id = self.assign_vm(attacker_ip)
                log.msg(f'Assigned new vm {vm_id} for orphan attacker {attacker_ip} .')

            log.msg('Vm status is updated.')

            return len(available_vm_id)

        else:
            log.msg(f'Scanning target vm {vm_ip} in the local network.')
            vm_ips = self.scan_vm(vm_ip)

            if len(vm_ips) > 0:
                vm_id = self.get_vm_id(vm_ip)
                vm_pid = self.get_vm_pid(vm_id)
                agent_id = self.get_vm_agentId(vm_ip)

                if vm_id == -1 or vm_pid == -1:
                    for i, vm in enumerate(self.all_vm):
                        if vm['ip'] == vm_ip:
                            self.clear_vm(i)
                            return self.count_alive_vm()
                else:
                    self.all_vm[vm_id]['ip'] = vm_ip
                    self.all_vm[vm_id]['pid'] = vm_pid
                    self.all_vm[vm_id]['agent_id'] = agent_id
                    self.all_vm[vm_id]['attacker_ip'].clear()
                    self.all_vm[vm_id]['con'].clear()
                    self.all_vm[vm_id]['indexer_last_hit'] = datetime.now()
                    return self.count_alive_vm()
            else:
                for i, vm in enumerate(self.all_vm):
                    if vm['ip'] == vm_ip:
                        self.clear_vm(i)
                return self.count_alive_vm()


    def list_vm(self) -> List[int]:

        stdin, stdout, stderr = self.target_con.exec_command('pgrep -U 0 -f qvm')
        vm_pids_str = stdout.read().decode().split()
        vm_pids = list(map(int, vm_pids_str))

        return vm_pids


    def get_vm_id(self, vm_ip: str) -> int:

        vm_id = -1

        if len(vm_ip) > 0:
            stdin, stdout, stderr = self.vm_run_commands(f'ip addr show dev {self.vm_info["network_interface"]} | grep link/ether | sed "s/ //g" | sed "s/link\/ether//g" | cut -b 1-17', vm_ip, True)

            mac = stdout[0]

            if len(mac) == 17:
                vm_id = int(mac.split(':')[-1])

        return vm_id


    def get_vm_pid(self, vm_id: int) -> int:

        vm_pid = -1

        if 0 <= vm_id < self.vm_size:
            stdin, stdout, stderr = self.target_con.exec_command(f'pgrep -U 0 -f qvm{vm_id}')
            vm_pid_str = stdout.read().decode().strip()

            if len(vm_pid_str) > 0:
                #vm_pid = int(vm_pid_str)
                vm_pid = int(vm_pid_str.split('\n')[-1])

        return vm_pid


    def query_vm_id(self, vm_ip: str) -> int:

        for i, vm in enumerate(self.all_vm):
            if vm['ip'] == vm_ip:
                return i

        return -1


    # Accessor should NOT reuse the returned agent id for a long time.
    # It is because assigned vm may change unexpectedly.
    def query_vm_id_attacker(self, attacker_ip: str) -> int:

        for i, vm in enumerate(self.all_vm):
            if attacker_ip in vm['attacker_ip']:
                return i

        return -1


    # Accessor should NOT reuse the returned agent id for a long time.
    # It is because assigned vm may change unexpectedly.
    def query_wazuh_agentId(self, attacker_ip: str) -> int:

        for vm in self.all_vm:
            if attacker_ip in vm['attacker_ip']:
                return vm['agent_id']

        return -1


    def get_vm_agentId(self, vm_ip: str) -> int:

        agent_id = -1
        if len(vm_ip) != '':
            req = requests.get(f'https://{self.provider["ip"]}:{self.provider["port"]}/security/user/authenticate?raw=true', auth=HTTPBasicAuth(self.provider['username'], self.provider['password']), verify=False)

            if req.status_code == 200:
                token = req.text

                req = requests.get(f'https://{self.provider["ip"]}:{self.provider["port"]}/agents?select=id&ip={vm_ip}', headers={'Authorization': f'Bearer {token}'}, verify=False)

                if req.status_code == 200:
                    items = req.json()['data']['affected_items']
                    if len(items) > 0:
                        agent_id = int(items[0]['id'])

        return agent_id


    def create_vm(self, vm_id: int) -> None:
        #self.target_con.exec_command(f'screen -d -m sudo qemu-system-x86_64 -name qvm{vm_id} -smbios type=0,uefi=on -enable-kvm -smp 1 -m 1024 -hda /home/speedlab-ml-3/qvm{vm_id}.qcow2 -boot c -netdev bridge,br=br0,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:43:{vm_id:02x} -vnc 0.0.0.0:{vm_id}')
        
        #wazuh_interface_json = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'etc/wazuh_interface.json')
        #with open(wazuh_interface_json, encoding='utf-8') as f:
        #    sudo_password = json.load(f)['target']['password']
        #self.target_con.exec_command(f'echo "{sudo_password}" | sudo -S sudo qemu-system-x86_64 -name qvm{vm_id} -smbios type=0,uefi=on -smp 2 -m 4096 -hda /home/user/qvm{vm_id}.qcow2 -boot c -netdev bridge,br=br0,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:43:{vm_id:02x} -vnc 0.0.0.0:{vm_id}')
        pass

    def shutdown_vm(self, vm_id: int) -> None:

        if 0 <= vm_id < self.vm_size:
            if len(self.all_vm[vm_id]['ip']) > 0:
                log.msg(f'Try to shutdown VM {vm_id} gracefully. IP = {self.all_vm[vm_id]["ip"]}')
                self.vm_run_commands('sudo poweroff', vm_id)
                self.all_vm[vm_id]['con'][1].close()
                self.all_vm[vm_id]['con'][0].close()
                self.all_vm[vm_id]['con'].clear()
            else:
                log.err(f'Can NOT shutdown VM {vm_id} gracefully due to no ip information.')

        else:
            log.err(f'Invalid VM id {vm_id}.')


    def shutdown_all_vm(self, force: bool = False) -> None:

        log.msg(f'Try to shutdown all VM gracefully.')

        for i, vm in enumerate(self.all_vm):
            if len(vm['ip']) > 0:
                self.shutdown_vm(i)

        sleep(10)
        self.update_vm()

        if force:
            if len(self.list_vm()) > 0:
                self.destroy_all_vm()


    def destroy_vm(self, vm_id: int) -> None:

        if 0 <= vm_id < self.vm_size:
            if self.all_vm[vm_id]['pid'] != -1:
                log.msg(f'Try to kill VM {vm_id} brutally. PID = {self.all_vm[vm_id]["pid"]}')
                self.all_vm[vm_id]['con'][1].close()
                self.all_vm[vm_id]['con'][0].close()
                self.target_con.exec_command(f'sudo kill {self.all_vm[vm_id]["pid"]}')
            else:
                log.err(f'Can NOT destroy VM {vm_id} brutally due to no pid information.')

        else:
            log.err(f'Invalid VM id {vm_id}.')


    def destroy_all_vm(self) -> None:

        while len(self.list_vm()) > 0:
            log.msg(f'Try to kill all VM brutally.')
            self.target_con.exec_command(f'sudo pkill -U 0 -f qvm')
            sleep(1)


    def handle_unexpected_vm(self, vm_ip: str) -> None:

        log.err(f'The connection to vm {vm_ip} is down.')

        for vm in self.all_vm:
            if vm['ip'] == vm_ip:
                attackers = vm['attacker_ip'].copy()
                vm['attacker_ip'].clear()
                self.update_vm(vm_ip)

                for attacker in attackers:
                    log.msg(f'Try to assign new vm for attacker {attacker} .')
                    self.assign_vm(attacker)


    def vm_install_wazuhAgent(self, vm_id: int) -> None:

        if 0 <= vm_id < self.vm_size:
            with open(Path(__file__).parents[1] / 'etc/wazuh_interface.json', 'r') as fin:
                config = json.load(fin)

            # Make sure there is no double quote in the commands.
            for cmd in config['wazuh_agent_install']:
                assert cmd.find('"') == -1

            commands = [f'sudo bash -c "{cmd}"; echo True' for cmd in config['wazuh_agent_install']]

            self.vm_run_commands(commands, vm_id)


    def init_all_vm(self):
        # Make copies of base image for our vm.
        self.copy_base_image()

        # Create info struct and fill it with default value.
        for i in range(self.vm_size):
            self.all_vm.append({'pid': -1,
                                'ip': '',
                                'agent_id': -1,
                                'attacker_ip': [],
                                'con': [],
                                'indexer_last_hit': datetime.now()})

        # Destroy exists vm before start.
        if self.vm_info['destroy_before_start'] and len(self.list_vm()) > 0:
            self.destroy_all_vm()

        # Create and start vms.
        running_vms = len(self.list_vm())
        log.msg(f'Found {running_vms} running vm.')
        if running_vms < self.vm_size:
            create_vm_size = self.vm_size - running_vms
            log.msg(f'Created {create_vm_size} vm.')
            for i in range(create_vm_size):
                self.create_vm(running_vms + i)

        # Check vms are booting.
        while True:
            pids = self.list_vm()
            log.msg(f'Waiting for all vm power on {len(pids)}/{self.vm_size} ...')

            if len(pids) == self.vm_size:
                break
            # if len(pids) == 2 * self.vm_size:
            #     break

            sleep(0.5)

        # Check vms are booted.
        while True:
            if self.update_vm() == self.vm_size:
                for vm_id, vm in enumerate(self.all_vm):
                    if len(vm['ip']) > 0 and vm['agent_id'] == -1:
                        while True:
                            log.msg(f'Try to install Wazuh agent for vm{vm_id} ({vm["ip"]}) ...')
                            self.vm_install_wazuhAgent(vm_id)
                            log.msg(f'Try to install Wazuh agent for vm{vm_id} ({vm["ip"]}) ... done')

                            # It takes about 20 seconds to let new agent establish new connection with provider.
                            sleep(30)
                            log.msg("123", vm['ip'])
                            vm['agent_id'] = self.get_vm_agentId(vm['ip'])

                            if vm['agent_id'] == -1:
                                log.err(f'Failed to install Wazuh agent for vm{vm_id} with ip {vm["ip"]} .')
                                sleep(10)
                            else:
                                break

                break

            sleep(5)

        log.msg('All vm for wazuh agents are initialized.')
        self.log_all_vm()


    def log_all_vm(self) -> None:

        for i, vm in enumerate(self.all_vm):
            log.msg(f'[{i}] {vm["ip"]} wazuhAgent={vm["agent_id"]} | attacker={", ".join(vm["attacker_ip"])}')

        # Just do this for now.
        return

        for i, vm in enumerate(self.all_vm):
            # PPS-TODO: We can do more check on the connection.
            if len(vm['con']) > 0:
                proxy_con = True
                qvm_con = True
            else:
                proxy_con = False
                qvm_con = False

            log.msg(f'[{i}] pid={vm["pid"]} con=(proxy={proxy_con}, qvm={qvm_con}) indexerLastHit={vm["indexer_last_hit"]}')


    def assign_vm(self, attacker_ip: str) -> int:

        resp = -1

        if len(attacker_ip) > 0:
            # Find client ip in existing vm client.
            for i, vm in enumerate(self.all_vm):
                if attacker_ip in vm['attacker_ip']:
                    vm['attacker_ip'].append(attacker_ip)
                    log.msg(f'Assigned vm{i} with {vm["ip"]} to same attacker {attacker_ip}.')
                    resp = i
                    break

            if resp == -1:
                if self.count_alive_vm() > 0:
                    # Find an available vm.
                    for i, vm in enumerate(self.all_vm):
                        if len(vm['ip']) > 0 and len(vm['attacker_ip']) == 0:
                            vm['attacker_ip'].append(attacker_ip)
                            vm['indexer_last_hit'] = datetime.now()
                            log.msg(f'Assigned vm{i} with {vm["ip"]} to new attacker {attacker_ip}.')
                            resp = i
                            break

                    # Reuse vm.
                    if resp == -1:
                        while True:
                            vm_id = randint(0, self.vm_size - 1)

                            if len(self.all_vm[vm_id]['ip']) > 0:
                                break

                        self.all_vm[vm_id]['attacker_ip'].append(attacker_ip)
                        log.msg(f'Assigned used vm{vm_id} with {self.all_vm[vm_id]["ip"]} to new attacker {attacker_ip}.')
                        resp = vm_id

                else:
                    log.err(f'No vm alive to assign to attacker {attacker_ip}. qAq')

        else:
            log.err(f'Invalid attacker ip {attacker_ip} .')

        self.log_all_vm()

        return resp


    def release_vm(self, attacker_ip: str) -> None:

        if len(attacker_ip) > 0:
            for i, vm in enumerate(self.all_vm):
                if attacker_ip in vm['attacker_ip']:
                    vm['attacker_ip'].remove(attacker_ip)
                    log.msg(f'Released vm{i} with {vm["ip"]} for attacker {attacker_ip}.')
                    self.log_all_vm()
                    break

        else:
            log.err(f'Invalid attacker ip {attacker_ip} .')


    def clear_vm(self, vm_id: int) -> None:

        if 0 <= vm_id < self.vm_size:
            self.all_vm[vm_id]['pid'] = -1
            self.all_vm[vm_id]['ip'] = ''
            self.all_vm[vm_id]['agent_id'] = -1
            self.all_vm[vm_id]['attacker_ip'].clear()
            self.all_vm[vm_id]['con'].clear()
            self.all_vm[vm_id]['indexer_last_hit'] = datetime.now()


    def count_alive_vm(self) -> int:

        counter = 0

        for vm in self.all_vm:
            if len(vm['ip']) > 0:
                counter += 1

        return counter


    def get_indexer_events(self, agent_id: int, query: Union[float, int, dict] = None) -> dict:

        """
        :param query: search query options for request
            query can be either None, float, int, dict.
            None: from now to (now - 1 minutes).
            float: from now to (now - [query] minutes).
            int: from now to (now - [query] minutes).
            dict: pass [query] to request directly without pre-process.
        """

        records = {}

        auth = (self.indexer['username'], self.indexer['password'])

        if query is dict:
            search_options = query

        else:
            datetime_from = datetime.now()
            datetime_to = datetime_from

            if type(query) is float or type(query) is int:
                datetime_from = datetime_from - timedelta(minutes=query)
            else:
                vm_id = -1

                for i, vm in enumerate(self.all_vm):
                    if vm['agent_id'] == agent_id:
                        vm_id = i
                        break

                if vm_id == -1:
                    log.err('Unexpected status: vm id should NOT be -1.')
                    return {}

                datetime_from = self.all_vm[vm_id]['indexer_last_hit'] + timedelta(milliseconds=1)
                self.all_vm[vm_id]['indexer_last_hit'] = datetime_to

            search_options = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "term": {
                                    "agent.id": f"{agent_id:03d}"
                                }
                            }
                        ],
                        "filter": [
                            {
                                "range": {
                                    "timestamp": {
                                        "from": datetime_from.strftime("%Y-%m-%dT%H:%M:%S.%f+0800"),
                                        "to": datetime_to.strftime("%Y-%m-%dT%H:%M:%S.%f+0800")
                                    }
                                }
                            }
                        ]
                    }
                },
                "size": 10000,  # This is the maximum records at once.
                "sort": [
                    {
                        "timestamp": {
                            "order": "asc"
                        }
                    }
                ]
            }

        req = requests.get(f'https://{self.indexer["ip"]}:{self.indexer["port"]}/wazuh-alerts-4.x-*/_search', json=search_options, auth=auth, verify=False)

        if req.status_code == 200:
            data = req.json()
            server_records_len = data['hits']['total']['value']
            records = data['hits']['hits']

            if server_records_len > len(records):
                log.msg('There are more records on server than you get.')
                log.msg(f'Server has {server_records_len} records.  You only got {len(records)} records.')

        else:
            log.err('Indexer returns error.')
            log.err(f'ERROR: HTTP status code {req.status_code}')
            log.err(f'Server returned error messages: {req.json()}')

        return records


    def attacker_command_handler(self, attacker_ip: str, commands: List[bytes]) -> List[str]:

        # PPS-TODO: This whole process is slow.
        # send command to exec, command-exec-time, stay before access indexer, access indexer

        wazuh_agent_id = self.query_wazuh_agentId(attacker_ip)

        # PPS: Run commands in wazuh agent.
        # PPS-TODO: sudo -i will be killed due to timeout.
        log.msg(f'Running commands in wazuh_agent {wazuh_agent_id} to get techniques ...')
        self.vm_run_commands(commands, self.query_vm_id_attacker(attacker_ip), set_timeout=True)
        log.msg(f'Running commands in wazuh_agent {wazuh_agent_id} to get techniques ... Done')

        # PPS: Pull events from wazuh indexer API.
        log.msg('Pull events from wazuh indexer.')
        wazuh_events = self.get_indexer_events(wazuh_agent_id, 60)  # PPS-TODO: Set to 60 for now. Remove this argument after problem solved.

        # PPS-TODO: Do these for now. Remove these argument after problem solved.
        wazuh_events = [wazuh_event for wazuh_event in wazuh_events if wazuh_event['_source']['id'] not in self.pulled_wazuh_event_id]
        self.pulled_wazuh_event_id += [wazuh_event['_source']['id'] for wazuh_event in wazuh_events]

        # PPS: Extract techniques.
        techniques = WazuhInterface.events_fetch_techniques(wazuh_events)
        log.msg('Extracted techniques from events:', techniques)

        return techniques


if __name__ == '__main__':
    # Create interface to vm for running wazuh agent.
    wi = WazuhInterface()

    # Fetch events in 5 minutes from Wazuh indexer.
    for vm in wi.all_vm:
        events = wi.get_indexer_events(vm['agent_id'], 30)

        # Fetch MITRE Att&ck techniques from events.
        techniques = WazuhInterface.events_fetch_techniques(events)

        print()
        print('Agent id is', vm['agent_id'])
        print(f'Fetched {len(techniques)} techniques from Wazuh indexer events.')
        print(f'Here are the techniques: {techniques}.')
