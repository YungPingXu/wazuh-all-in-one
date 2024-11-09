
from __future__ import annotations
from typing import List, Union, Dict
import re
import os
from enum import Enum
from datetime import datetime, timedelta
from pathlib import Path
import html
import requests
import numpy as np
from matplotlib import pyplot as plt

from engage_action import ACTION_LEN


DATETIME_FORMAT = '%Y%m%d_%H%M%S.%f'
DEFAULT_BASE_DIR = '/home/user/Desktop/'
os.environ['COWRIE_BASE_PATH'] = os.path.dirname(__file__)

def is_valid_datetime(datetime_string: str) -> bool:
    try:
        datetime.strptime(datetime_string, DATETIME_FORMAT)

    except ValueError:
        return False

    else:
        return True


def check_default_base_dir() -> bool:
    return Path(DEFAULT_BASE_DIR).exists() and Path(DEFAULT_BASE_DIR).is_dir()


def search_log(logs: List[TracerLog], pattern: str, skip: int = 0) -> int:
    if 0 <= skip < len(logs):
        for i in range(skip, len(logs)):
            if logs[i].content.find(pattern) != -1:
                return i

    return -1


def common_exec() -> List[str]:
    with open(Path(__file__).parents[1] / 'share/cowrie/response_generator/exec.txt', 'r') as fin:
        execs = fin.readlines()

    execs = [e.strip() for e in execs]

    return execs


class LoggingComponent(Enum):
    # Max length = 10 characters.
    COWRIE = 0
    IPTABLES = 1
    ENGAGE = 2
    ATTACKER = 3


class LoggingType(Enum):
    # Max length = 10 characters.
    DEBUG = 0
    SUCCESS = 1
    FAILED = 2
    FATAL = 3


class TracerLog:
    @staticmethod
    def from_string(string: str, log_filename: str) -> TracerLog:
        tokens = string.split()

        # Validate the number of fields.
        assert (len(tokens) >= 4), f'Invalid log string in file "{log_filename}": {string}'

        # Convert logging component to upper case.
        tokens[1] = tokens[1].upper()

        # Validate each field.
        assert is_valid_datetime(tokens[0]), f'Invalid datetime format in file "{log_filename}": {tokens[0]}'
        assert (tokens[1] in [member.name for member in LoggingComponent]), f'Invalid log component in file "{log_filename}": {tokens[1]}'
        assert (tokens[2] in [member.name for member in LoggingType]), f'Invalid log level in file "{log_filename}": {tokens[2]}'

        return TracerLog(datetime.strptime(tokens[0], DATETIME_FORMAT), LoggingComponent[tokens[1]], LoggingType[tokens[2]], ' '.join(tokens[3:]))

    def __init__(self, timestamp: datetime, component: LoggingComponent, level: LoggingType, content: str):
        self.timestamp = timestamp
        self.component = component
        self.level = level
        self.content = content

    def __str__(self) -> str:
        return f'{self.timestamp.strftime(DATETIME_FORMAT)} {self.component.name:10s} {self.level.name:10s} {self.content}'


class PlotNodeColor(Enum):

    BLACK = '#4f4f4f'
    GREEN = '#006003'
    YELLOW = '#d77a03'
    RED = '#d40000'


class PlotNode:
    def __init__(self, text: str, color: PlotNodeColor, level: int):
        self.text = text
        self.color = color
        self.level = level

    def to_html(self) -> str:
        text = '&nbsp;&nbsp;&nbsp;&nbsp;' * self.level + html.escape(self.text)
        return f'<p style="color:{self.color.value}">{text}</p>'


class LoginLog:
    def __init__(self, usernames: List[str], passwords: List[str], isSuccesses: List[bool]):
        assert len(usernames) == len(passwords) == len(isSuccesses)

        self.usernames = usernames.copy()
        self.passwords = passwords.copy()
        self.isSuccesses = isSuccesses.copy()

    def to_plot(self, level: int = 0) -> List[PlotNode]:
        plots = []

        for i in range(len(self.passwords)):
            if self.isSuccesses[i]:
                plots.append(PlotNode(f'Login with ("{self.usernames[i]}", "{self.passwords[i]}")', PlotNodeColor.GREEN, level))
            else:
                plots.append(PlotNode(f'Login with ("{self.usernames[i]}", "{self.passwords[i]}")', PlotNodeColor.BLACK, level))

        return plots


class AttackLog:
    def __init__(self, commands: List[str], results: List[str], isTimeouts: List[bool], isErrors: List[bool]):
        assert len(commands) == len(results) == len(isTimeouts) == len(isErrors)

        self.commands = commands.copy()
        self.results = results.copy()
        self.isTimeouts = isTimeouts.copy()
        self.isErrors = isErrors.copy()

    def to_plot(self, level: int = 0) -> List[PlotNode]:
        plots = []

        for i in range(len(self.commands)):
            plots.append(PlotNode(f'Execute command "{self.commands[i]}"', PlotNodeColor.BLACK, level))

            if self.isTimeouts[i]:
                plots.append(PlotNode(f'Execute result timeout', PlotNodeColor.YELLOW, level))
            elif self.isErrors[i]:
                plots.append(PlotNode(f'Execute failed', PlotNodeColor.YELLOW, level))
            else:
                plots.append(PlotNode(f'Execute result "{self.results[i]}"', PlotNodeColor.GREEN, level))

        return plots


class GroupLog:
    def __init__(self, name: str, elements: List[Union[LoginLog, AttackLog, GroupLog]]):
        self.name = name
        self.elements = elements.copy()

    def to_plot(self, level: int = 0) -> List[PlotNode]:
        plots = []

        plots.append(PlotNode(f'{self.name} ...', PlotNodeColor.BLACK, level))

        for element in self.elements:
            plots += element.to_plot(level + 1)

        plots.append(PlotNode(f'{self.name} ... Done', PlotNodeColor.BLACK, level))

        return plots

    def flatten(self, name: str = '') -> GroupLog:
        flattened: List[Union[LoginLog, AttackLog]] = []

        for element in self.elements:
            if type(element) is GroupLog:
                flattened += element.flatten().elements
            else:
                flattened.append(element)

        return GroupLog(name, flattened)


class Tracer:
    LOGGING_PATH = Path(os.environ['COWRIE_BASE_PATH']).parent / Path('tracer_logs')

    @staticmethod
    def create_log_dir() -> None:

        Tracer.LOGGING_PATH.mkdir(exist_ok=True)


    @staticmethod
    def current_datetime() -> str:

        return datetime.now().strftime(DATETIME_FORMAT)


    @staticmethod
    def validate_datetime() -> bool:

        req = requests.get('http://just-the-time.appspot.com/')

        if req.status_code == 200:
            local_datetime = datetime.now()
            internet_datetime = datetime.strptime(req.text.strip(), '%Y-%m-%d %H:%M:%S') + timedelta(hours=8)
            diff = (internet_datetime - local_datetime).total_seconds()

            # The difference should be less than or equal to 5 seconds.
            return diff <= 5

        return False


    def __init__(self, app_name: str) -> None:

        assert Tracer.validate_datetime(), 'Please check your computer datetime/timezone setting.'

        self.app_name = app_name
        self.log_filename = str(Tracer.LOGGING_PATH / Path(f'{Tracer.current_datetime()}_{self.app_name}.log'))

        Tracer.create_log_dir()
        self.log_writer = open(self.log_filename, 'w')


    def __del__(self) -> None:

        self.log(f'Tracer object is going to be destroyed, and logs are saved to "{self.log_filename}".', LoggingType.DEBUG)
        self.log_writer.close()


    def log(self, msg: str, msg_type: LoggingType = LoggingType.SUCCESS) -> None:

        self.log_writer.write(f'{Tracer.current_datetime()} {self.app_name:10s} {msg_type.name:10s} {msg}\n')


class TracerGraph:
    @staticmethod
    def merge_logs(log_filenames: List[str], output_filename: str = '') -> None:
        logs = [log for filename in log_filenames for log in TracerGraph.read_log(filename)]
        logs_str = [str(log) for log in logs]

        # Sort logs by datetime (first field).
        logs_str.sort()

        if len(output_filename) == 0:
            output_filename = 'merge.log'

        with open(output_filename, 'w') as fout:
            fout.write('\n'.join(logs_str))

    @staticmethod
    def add_log_interval(log_filename: str, output_filename: str = '') -> None:
        with open(log_filename, 'r') as fin:
            lines = fin.readlines()

        # Remove trailing characters in each line.
        lines = [line.strip() for line in lines]

        logs = []
        for i, line in enumerate(lines):
            if i == 0:
                interval = 0
            else:
                time2 = datetime.strptime(line[:22], DATETIME_FORMAT)
                time1 = datetime.strptime(lines[i - 1][:22], DATETIME_FORMAT)
                interval = (time2 - time1).total_seconds()

            interval = '{:12.6f}'.format(interval)

            logs.append(interval + ' ' + line)

        if len(output_filename) == 0:
            output_filename = 'merge_interval.log'

        with open(output_filename, 'w') as fout:
            fout.write('\n'.join(logs))

    @staticmethod
    def read_log(log_filename: str) -> List[TracerLog]:
        logs: List[TracerLog] = []

        with open(log_filename, 'r') as fin:
            try:
                lines = fin.readlines()
            except UnicodeDecodeError:
                print(f'Encode error while reading file "{log_filename}".')
                return logs

        lines = [line.strip() for line in lines]
        logs += [TracerLog.from_string(line, log_filename) for line in lines]

        return logs

    def __init__(self, log_filename: str) -> None:
        self.logs: List[TracerLog] = TracerGraph.read_log(log_filename)

    def plot_all(self, output_dir: str) -> None:
        self.plot_total_rewards(output_dir)
        self.plot_losses(output_dir)
        self.plot_q_values(output_dir)
        self.plot_action_used(output_dir)
        self.plot_attack_used(output_dir)
        self.plot_engage_used(output_dir)

    def plot_total_rewards(self, output_dir: str) -> None:
        logs = [log.content for log in self.logs if log.content.find('reward=') != -1]

        rewards = []
        total_rewards = []

        for log in logs:
            match = re.search(r'reward=(-?\d+\.\d+), total=(-?\d+\.\d+)', log)

            if match:
                rewards.append(float(match.group(1)))
                total_rewards.append(float(match.group(2)))
            else:
                raise ValueError

        fig, ax = plt.subplots()
        ax.plot(np.arange(len(total_rewards)) + 1, total_rewards)
        ax.set_xlabel('Step')
        ax.set_ylabel('Total Rewards')
        ax.set_title('Step  x  Total Rewards')

        fig.tight_layout()
        fig.savefig(str(Path(output_dir) / Path('total_rewards.png')))

    def plot_losses(self, output_dir: str) -> None:
        logs = [log.content for log in self.logs if log.content.find('loss=') != -1]

        losses = []

        for log in logs:
            match = re.search(r'loss=(-?\d+\.\d+),', log)

            if match:
                losses.append(float(match.group(1)))
            else:
                raise ValueError

        fig, ax = plt.subplots()
        ax.plot(np.arange(len(losses)) + 1, losses)
        ax.set_xlabel('Step (offset batch_size)')
        ax.set_ylabel('Loss')
        ax.set_title('Step  x  Loss')

        fig.tight_layout()
        fig.savefig(str(Path(output_dir) / Path('losses.png')))

    def plot_q_values(self, output_dir: str) -> None:
        logs = [log.content for log in self.logs if log.content.find('q=') != -1]

        q_values = [[] for _ in range(ACTION_LEN)]

        for log in logs:
            if not log.startswith('Exec result:'):
                match = re.search(r'q=\(' + r', '.join([r'(-?\d+\.\d+)'] * ACTION_LEN) + r'\)', log)

                if match:
                    for i in range(ACTION_LEN):
                        q_values[i].append(float(match.group(i+1)))
                else:
                    raise ValueError

        fig, ax = plt.subplots(figsize=(20, 5))

        for i in range(ACTION_LEN):
            ax.plot(np.arange(0, len(q_values[i]), 3) + 1, np.array(q_values[i])[::3], label=f'Action {i+1}')

        ax.legend([f'Action {i+1}' for i in range(ACTION_LEN)], loc='upper left')
        ax.set_xlabel('Step (offset batch_size)')
        ax.set_ylabel('Q Value')
        ax.set_title('Step  x  Q Value')

        fig.tight_layout()
        fig.savefig(str(Path(output_dir) / Path('q_values.png')))

    def plot_action_used(self, output_dir: str) -> None:
        logs = [log.content for log in self.logs if log.component == LoggingComponent.ENGAGE and log.content.find('Selected action is') != -1]

        action_count = [0 for _ in range(ACTION_LEN)]

        for log in logs:
            match = re.search(r'Selected action is (\d+) ', log)

            if match:
                action_id = int(match.group(1))
                action_count[action_id - 1] += 1
            else:
                raise ValueError

        fig, ax = plt.subplots()
        ax.bar([str(i+1) for i in range(ACTION_LEN)], action_count)
        ax.set_xlabel('Action ID')
        ax.set_ylabel('Used Count')
        ax.set_title('Action ID  x  Used Count')

        fig.tight_layout()
        fig.savefig(str(Path(output_dir) / Path('action_used.png')))

    def plot_attack_used(self, output_dir: str) -> None:
        logs = [log.content for log in self.logs if log.content.find('ATT&CK Techniques are') != -1]

        attack_count = {}

        for log in logs:
            match = re.search(r'ATT&CK Techniques are \[(.*?)\]', log)

            if match:
                techniques = match.group(1).replace(' ', '')

                if len(techniques) > 0:
                    techniques = techniques.split(',')

                    for technique in techniques:
                        if technique not in attack_count:
                            attack_count[technique] = 0

                        attack_count[technique] += 1

            else:
                raise ValueError

        fig, ax = plt.subplots(figsize=(15, 5))
        ax.bar(list(attack_count.keys()), list(attack_count.values()))
        ax.set_xlabel('Technique ID')
        ax.set_ylabel('Used Count')
        ax.set_title('ATT&CK Technique ID  x  Used Count')

        # Add value text to each bar.
        for index, value in enumerate(attack_count.values()):
            ax.text(index, value, str(value))

        fig.tight_layout()
        fig.savefig(str(Path(output_dir) / Path('attack_used.png')))

    def plot_engage_used(self, output_dir: str) -> None:
        logs = [log.content for log in self.logs if log.content.find('Suggested Engage Activities are') != -1]

        engage_count = {}

        for log in logs:
            match = re.search(r'Suggested Engage Activities are \[(.*?)\]', log)

            if match:
                activities = match.group(1).replace(' ', '')

                if len(activities) > 0:
                    activities = activities.split(',')

                    for activity in activities:
                        if activity not in engage_count:
                            engage_count[activity] = 0

                        engage_count[activity] += 1

            else:
                raise ValueError

        fig, ax = plt.subplots(figsize=(15, 5))
        ax.bar(list(engage_count.keys()), list(engage_count.values()))
        ax.set_xlabel('Activity ID')
        ax.set_ylabel('Used Count')
        ax.set_title('Engage Activity ID  x  Used Count')

        # Add value text to each bar.
        for index, value in enumerate(engage_count.values()):
            ax.text(index, value, str(value))

        fig.tight_layout()
        fig.savefig(str(Path(output_dir) / Path('engage_used.png')))


class AttackGraph:
    @staticmethod
    def parse_log(logs: List[TracerLog]) -> List[GroupLog]:
        CVEs: List[GroupLog] = []

        while len(logs) > 0:
            if logs[0].content.startswith('Running CVE "'):
                pos = search_log(logs, logs[0].content, 1)
                assert (pos != -1 and logs[pos].content.endswith('Done')), f'Unable to parse end of "{logs[0].content}"'

                cve_id = re.search(r'CVE-\d{4}-\d{4,7}', logs[0].content).group()

                sub_logs = logs[1:pos]
                logs = logs[pos+1:]
                CVEs.append(AttackGraph.parse_log_(cve_id, sub_logs))

            else:
                logs = logs[1:]

        return CVEs

    @staticmethod
    def parse_log_(name: str, logs: List[TracerLog]) -> GroupLog:
        elements: List[Union[LoginLog, AttackLog, GroupLog]] = []

        while len(logs) > 0:
            if logs[0].content.startswith('Failed to login with '):
                match = re.search(r'Failed to login with \("([^"]*)", "([^"]*)"\)', logs[0].content)
                assert match is not None, f'Failed to extract login credential from: {logs[0]}'
                elements.append(LoginLog([match.group(1),], [match.group(2),], [False,]))
                logs = logs[1:]

            elif logs[0].content.startswith('Logged in with '):
                match = re.search(r'Logged in with \("([^"]*)", "([^"]*)"\)', logs[0].content)
                assert match is not None, f'Failed to extract login credential from: {logs[0]}'
                elements.append(LoginLog([match.group(1),], [match.group(2),], [True,]))
                logs = logs[1:]

            elif logs[0].content.startswith('Updating arguments ...'):
                pos = search_log(logs, logs[0].content, 1)
                assert (pos != -1 and logs[pos].content.endswith('Done')), f'Unable to parse end of "{logs[0].content}"'

                sub_logs = logs[1:pos]
                logs = logs[pos+1:]
                elements.append(AttackGraph.parse_log_('Updating arguments', sub_logs))

            elif logs[0].content.startswith('Execute command "'):
                command = logs[0].content[17:-2]

                pos = -1
                isResultTimeout = False
                isResultError = False

                for i in range(len(logs)):
                    if logs[i].content.find('Timeout for execution.') != -1:
                        isResultTimeout = True
                        pos = i
                        break
                    elif logs[i].content.find('Executed command failed.') != -1:
                        isResultError = True
                        pos = i
                        break
                    elif logs[i].content.find('Exec result: ') != -1:
                        pos = i
                        break

                assert pos != -1, f'Unable to parse command execution result.'

                if isResultTimeout or isResultError:
                    result = ''
                else:
                    result = logs[pos].content[13:]

                elements.append(AttackLog([command,], [result,], [isResultTimeout,], [isResultError,]))
                logs = logs[pos+1:]

            else:
                logs = logs[1:]

        return GroupLog(name, elements)

    @staticmethod
    def read_log(log_filename: str) -> List[GroupLog]:
        raw_logs = [raw for raw in TracerGraph.read_log(log_filename) if raw.component == LoggingComponent.ATTACKER]
        logs = AttackGraph.parse_log(raw_logs)

        return logs

    @staticmethod
    def count_login_len(logs: List[GroupLog]) -> int:
        session_lens = [sum(1 for element in cve.flatten().elements if isinstance(element, LoginLog)) for cve in logs]

        print('# of Login in Total: {}'.format(sum(session_lens)))

        return sum(session_lens)

    @staticmethod
    def count_command_session_len(logs: List[GroupLog]) -> Dict[str, int]:
        session_lens = [sum(1 for element in cve.flatten().elements if isinstance(element, AttackLog)) for cve in logs]
        unique, counts = np.unique(session_lens, return_counts=True)
        unique = unique.tolist()
        counts = counts.tolist()
        session_len_count = dict(zip(list(map(str, unique)), counts))

        print('# of Sessions: {}'.format(len(session_lens)))
        print('# of Commands in Total: {}'.format(sum(session_lens)))
        print('Count of Command Session Length: {}'.format(session_len_count))

        return session_len_count

    @staticmethod
    def count_command(logs: List[GroupLog]) -> Dict[str, int]:
        commands = [command for cve in logs for element in cve.flatten().elements if isinstance(element, AttackLog) for command in element.commands]
        words = [word for command in commands for word in re.findall(r'\w+', command)]
        executables = [word for word in words if word in common_exec()]

        unique, counts = np.unique(executables, return_counts=True)
        unique = unique.tolist()
        counts = counts.tolist()
        command_count = dict(zip(list(map(str, unique)), counts))

        print('Count of Command: {}'.format(command_count))

        return command_count

    def __init__(self, log_filename: str) -> None:
        self.logs: List[GroupLog] = AttackGraph.read_log(log_filename)
        self.login_len_count = AttackGraph.count_login_len(self.logs)
        self.command_session_len_count = AttackGraph.count_command_session_len(self.logs)
        self.command_count = AttackGraph.count_command(self.logs)

    def plot_attack_path(self, output_dir: str) -> None:
        for cve in self.logs:
            with open(str(output_dir / Path(f'{cve.name}.html')), 'w') as fout:
                fout.write('<style>p { margin:0px; font-size:20px; font-weight:bold; line-height:2; white-space:nowrap; }</style>\n')
                fout.write('\n'.join([p.to_html() for p in cve.to_plot()]))

    def plot_session_len(self, output_dir: str) -> None:
        fig, ax = plt.subplots(figsize=(30, 5))
        ax.bar(list(self.command_session_len_count.keys()), list(self.command_session_len_count.values()))
        ax.set_xlim([0, len(self.command_session_len_count.keys())])
        ax.set_xbound(lower=0, upper=len(self.command_session_len_count.keys()))
        ax.set_xticks(list(self.command_session_len_count.keys()))
        ax.set_xlabel('# of Commands in a Session')
        ax.set_ylabel('Count')
        ax.set_title('Session Length  x  Count')

        # Add value text to each bar.
        for index, value in enumerate(list(self.command_session_len_count.values())):
            ax.text(index, value, str(value))

        fig.tight_layout()
        fig.savefig(str(Path(output_dir) / Path('session_len_count.png')))

    def plot_session_len_range(self, output_dir: str) -> None:
        # Initialize list.
        # [0] -> 0-9 (0 is removed by the code above)
        # [1] -> 10-19
        # ...
        # [9] -> 90-99
        session_len_range_count = [0 for i in range(10)]

        x_labels = ['1-9', '10-19', '20-29', '30-39', '40-49', '50-59', '60-69', '70-79', '80-89', '90-']

        for slen in self.command_session_len_count:
            count = self.command_session_len_count[slen]
            slen = int(slen)
            group = slen // 10
            group = 9 if group > 9 else group
            session_len_range_count[group] += count

        fig, ax = plt.subplots()
        ax.bar(x_labels, session_len_range_count)
        ax.set_xlabel('# of Commands in a Session')
        ax.set_ylabel('Count')
        ax.set_title('Session Length  x  Count')

        # Add value text to each bar.
        for index, value in enumerate(session_len_range_count):
            ax.text(index, value, str(value))

        fig.tight_layout()
        fig.savefig(str(Path(output_dir) / Path('session_len_range_count.png')))

    def plot_command_used(self, output_dir: str) -> None:
        fig, ax = plt.subplots(figsize=(7 if len(self.command_count.keys()) < 7 else len(self.command_count.keys()), 5))
        ax.bar(list(self.command_count.keys()), list(self.command_count.values()))
        ax.set_xlim([0, len(self.command_count.keys())])
        ax.set_xbound(lower=0, upper=len(self.command_count.keys()))
        ax.set_xticks(list(self.command_count.keys()))
        ax.set_xlabel('Command')
        ax.set_ylabel('Used Count')
        ax.set_title('Command  x  Used Count')

        # Add value text to each bar.
        for index, value in enumerate(list(self.command_count.values())):
            ax.text(index, value, str(value))

        fig.tight_layout()
        fig.savefig(str(Path(output_dir) / Path('command_used.png')))


class CowrieGraph:
    @staticmethod
    def filter_session_len(dir_path: str) -> Dict[str, int]:
        lines_str = ''

        # Read all logs from files.
        filenames = list(map(str, Path(dir_path).glob('*cowrie.log*'))) + list(map(str, Path(dir_path).glob('*qrassh.log*')))
        filenames.sort()

        print('Load file:\n{}'.format('\n'.join(filenames)))

        for filename in filenames:
            with open(filename, 'r') as fin:
                lines = fin.readlines()

            lines = [line.strip() for line in lines]
            lines_str += '\n' + '\n'.join(lines)

        sessions = lines_str.split('.ssh.factory.CowrieSSHFactory] New connection: ')
        session_commands: List[List[str]] = []

        if not lines_str.startswith('.ssh.factory.CowrieSSHFactory] New connection: '):
            sessions = sessions[1:]

        for session in sessions:
            logs = session.split('\n')
            session_commands.append([''.join(log.split(' CMD: ')[1:]) for log in logs if log.find(' CMD: ') != -1])

        session_lengths = np.array([len(commands) for commands in session_commands])
        unique, counts = np.unique(session_lengths, return_counts=True)
        unique = unique.tolist()
        counts = counts.tolist()
        session_len_count = dict(zip(list(map(str, unique)), counts))

        print('# of Sessions: {}'.format(len(session_commands)))
        print('# of Commands in Total: {}'.format(sum([len(commands) for commands in session_commands])))
        print('Count of Session Length: {}'.format(session_len_count))

        return session_len_count

    @staticmethod
    def plot_all(cowrie_log_dir: str, output_dir: str) -> None:
        CowrieGraph.plot_session_len(cowrie_log_dir, output_dir)
        CowrieGraph.plot_session_len_range(cowrie_log_dir, output_dir)

    @staticmethod
    def plot_session_len(cowrie_log_dir: str, output_dir: str) -> None:
        session_len_count = CowrieGraph.filter_session_len(cowrie_log_dir)
        session_len_count_ = session_len_count.copy()

        # Remove length == 0 to make the plot more readable.
        if '0' in session_len_count_:
            del session_len_count_['0']

        fig, ax = plt.subplots(figsize=(30, 5))
        ax.bar(list(session_len_count_.keys()), list(session_len_count_.values()))
        ax.set_xlim([0, len(session_len_count_.keys())])
        ax.set_xbound(lower=0, upper=len(session_len_count_.keys()))
        ax.set_xticks(list(session_len_count_.keys()))
        ax.set_xlabel('# of Commands in a Session')
        ax.set_ylabel('Count')
        ax.set_title('Session Length  x  Count')

        # Add value text to each bar.
        for index, value in enumerate(list(session_len_count_.values())):
            ax.text(index, value, str(value))

        # Write count for length == 0 as text on plot.
        if 0 in session_len_count:
            ax.text(0.9, 0.9, f'Session Length is 0: {session_len_count["0"]}', transform=ax.transAxes)

        fig.tight_layout()
        fig.savefig(str(Path(output_dir) / Path('session_len_count.png')))

    @staticmethod
    def plot_session_len_range(cowrie_log_dir: str, output_dir: str) -> None:
        session_len_count = CowrieGraph.filter_session_len(cowrie_log_dir)
        session_len_range_count = []
        x_labels = ['1-9', '10-19', '20-29', '30-39', '40-49', '50-59', '60-69', '70-79', '80-89', '90-']

        # Remove length == 0 to make the plot more readable.
        if '0' in session_len_count:
            del session_len_count['0']

        # Initialize list.
        # [0] -> 0-9 (0 is removed by the code above)
        # [1] -> 10-19
        # ...
        # [9] -> 90-99
        for i in range(10):
            session_len_range_count.append(0)

        for slen in session_len_count:
            count = session_len_count[slen]
            slen = int(slen)
            group = slen // 10
            group = 9 if group > 9 else group
            session_len_range_count[group] += count

        fig, ax = plt.subplots()
        ax.bar(x_labels, session_len_range_count)
        ax.set_xlabel('# of Commands in a Session')
        ax.set_ylabel('Count')
        ax.set_title('Session Length  x  Count')

        # Add value text to each bar.
        for index, value in enumerate(session_len_range_count):
            ax.text(index, value, str(value))

        # Write count for length == 0 as text on plot.
        if 0 in session_len_count:
            ax.text(0.9, 0.9, f'Session Length is 0: {session_len_count["0"]}', transform=ax.transAxes)

        fig.tight_layout()
        fig.savefig(str(Path(output_dir) / Path('session_len_range_count.png')))

    def __init__(self):
        pass
