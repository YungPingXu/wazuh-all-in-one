# The model we use in cve2attack.py only category techniques without sub-techniques.
# In this module, the functions will treat sub-techniques as one parent technique.

from typing import Tuple, List, Dict
from pathlib import Path
import yaml
from random import randint
from shlex import quote
import cve2attack


ARGUMENT_NAME_ALIAS = {'interface': ['ifname',],
                       'password': ['enc_pass', 'encryption_password', 'admin_password'],
                       'dc_name': ['domain_controller',]}

ARGUMENT_VALUE_CANDIDATE = {'aws_region': ['us-east-2', 'us-east-1', 'us-west-1', 'us-west-2', 'af-south-1',
                                           'ap-east-1', 'ap-south-2', 'ap-southeast-3', 'ap-southeast-4',
                                           'ap-south-1', 'ap-northeast-3', 'ap-northeast-2', 'ap-southeast-1',
                                           'ap-southeast-2', 'ap-northeast-1', 'ca-central-1', 'ca-west-1',
                                           'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-south-1', 'eu-west-3',
                                           'eu-south-2', 'eu-north-1', 'eu-central-2', 'il-central-1', 'me-south-1',
                                           'me-central-1', 'sa-east-1', 'us-gov-east-1', 'us-gov-west-1'],
                            'file_to_overwrite': ['/var/log/syslog', '/var/log/kern.log',
                                                  '/var/log/auth.log', '/var/log/dmesg']}


def all_tests_by_technique() -> Dict[str, List[dict]]:

    tests_collect = {}

    for file in Path('ref/atomics').rglob('*.yaml'):
        if str(file).find('Indexes') == -1 and str(file).find('src') == -1:
            with open(str(file), 'r') as fin:
                content = yaml.safe_load(fin)

            technique = content['attack_technique']
            technique_merged = technique.split('.')[0]

            if technique_merged in cve2attack.MODEL_ID2TECHNIQUE_MAPPING:
                tests = content['atomic_tests']

                for test in tests:
                    if 'linux' in test['supported_platforms'] and test['executor']['name'] != 'manual' and test['executor']['name'] != 'command_prompt':
                        if technique_merged not in tests_collect:
                            tests_collect[technique_merged] = []

                        tests_collect[technique_merged].append(test)

    return tests_collect


def all_tests_by_guid() -> Dict[str, dict]:

    technique_tests = all_tests_by_technique()
    tests_collect = {}

    for technique in technique_tests:
        tests = technique_tests[technique]

        for test in tests:
            guid = test['auto_generated_guid']
            test['technique'] = technique
            tests_collect[guid] = test

    return tests_collect


TECHNIQUE_TESTS = all_tests_by_technique()
GUID_TESTS = all_tests_by_guid()


def query_available_tests(technique: str) -> List[str]:

    technique = technique.split('.')[0]
    guids = [test['auto_generated_guid'] for tech in TECHNIQUE_TESTS if tech == technique for test in TECHNIQUE_TESTS[tech]]

    return guids


def query_argType() -> List[str]:

    technique_tests = TECHNIQUE_TESTS
    arg_types = [test['input_arguments'][arg_name]['type'] for tech in technique_tests for test in technique_tests[tech] if 'input_arguments' in test for arg_name in test['input_arguments']]
    arg_types = list(set(arg_types))

    return arg_types


def query_argName() -> List[str]:

    arg_names = [arg_name for tech in TECHNIQUE_TESTS for test in TECHNIQUE_TESTS[tech] if 'input_arguments' in test for arg_name in test['input_arguments']]
    arg_names = list(set(arg_names))

    return arg_names


def count_available_tests_by_techniques() -> Dict[str, int]:

    count = {tech: len(TECHNIQUE_TESTS[tech]) for tech in TECHNIQUE_TESTS}

    return count


def count_available_tests_by_selected_techniques(techniques: List[str]) -> Dict[str, int]:

    available_tests = count_available_tests_by_techniques()
    count = {technique: available_tests[technique] if technique in available_tests else 0 for technique in techniques}

    return count


def source_download_scripts(source_path: str) -> Tuple[str, str, List[str]]:

    if source_path.startswith('PathToAtomicsFolder/'):
        source_path = source_path.replace('PathToAtomicsFolder/', '', 1)

        local_files: List[Path] = [(Path('ref/atomics/') / Path(source_path)),] + [file for file in (Path('ref/atomics/') / Path(source_path)).rglob('*') if file.is_file()]
        target_files: List[str] = [str(file).replace('ref/atomics/', '', 1) for file in local_files]
        github_files: List[str] = [f'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/{file}' for file in target_files]

        download_files = [f'wget {quote(github_files[i])} -O {quote(target_files[i])}' for i in range(len(github_files))]

        create_parents: List[str] = list(set([str(Path(file).parent) for file in target_files]))
        create_parents.sort()
        create_parents = [f'mkdir -p {quote(str(parent))}' for parent in create_parents]

        return source_path, '; '.join(create_parents), download_files

    else:
        return '', '', []


def argument_replace(arg_name: str, arg_value: str, commands: List[str]) -> List[str]:

    replaced_commands = []

    for cmd in commands:
        if cmd.find(f'#{{{arg_name}}}') != -1 and arg_value.startswith('PathToAtomicsFolder/'):
            arg_value, parents, downloads = source_download_scripts(arg_value)
            replaced_commands.append(parents)
            replaced_commands += downloads

        cmd = cmd.replace(f'#{{{arg_name}}}', arg_value)
        replaced_commands.append(cmd)

    return replaced_commands


def test_has_argument(guid: str, arg_name: str) -> bool:

    try:
        test = GUID_TESTS[guid]

    except KeyError:
        pass

    else:
        if 'input_arguments' in test:
            return arg_name in test['input_arguments']

    return False


def query_test_argument_default(guid: str, arg_name: str) -> str:

    try:
        test = GUID_TESTS[guid]

    except KeyError:
        pass

    else:
        if 'input_arguments' in test:
            if arg_name in test['input_arguments']:
                if 'default' in test['input_arguments'][arg_name]:
                    return test['input_arguments'][arg_name]['default']

    return ''


def print_test_help_by_guid(guid: str) -> None:

    try:
        test = GUID_TESTS[guid]

    except KeyError:
        print(f'GUID "{guid}" does NOT exist.')

    else:
        print('GUID:', guid)
        print('Name:', test['technique'], f'"{test["name"]}"')
        print('Description:', test['description'].strip().replace('\n', ' '))

        if 'input_arguments' in test:
            for i, arg_name in enumerate(test['input_arguments']):
                arg_descript = test['input_arguments'][arg_name]['description']
                arg_type = test['input_arguments'][arg_name]['type']
                arg_default = test['input_arguments'][arg_name]['default']

                print(f'- Argument[{i}]: {arg_name}: {arg_type} = "{arg_default}", descript = "{arg_descript}"')

        executor_name = test['executor']['name']
        executor_command = test['executor']['command'].strip().replace('\n', '; ')

        if 'cleanup_command' in test['executor'] and test['executor']['cleanup_command'] is not None:
            executor_cleanup = test['executor']['cleanup_command'].strip().replace('\n', '; ')
        else:
            executor_cleanup = ''

        print(f'Executor: {executor_name}, commands = "{executor_command}", cleanup = "{executor_cleanup}"')

        if 'dependencies' in test:
            for i, depend in enumerate(test['dependencies']):
                pre_check = depend['prereq_command'].strip().replace('\n', '; ')
                setup = depend['get_prereq_command'].strip().replace('\n', '; ')
                print(f'- Dependency[{i}]: pre-check = "{pre_check}", setup = "{setup}"')


def argument_creator(arguments: Dict[str, str]) -> Dict[str, str]:

    arguments = arguments.copy()

    # Compose argument: admin_user(admin@example.com), domain(example), top_level_domain(com).
    if len(arguments['username']) > 0 and len(arguments['full_domain']) > 0:
        arguments['admin_user'] = arguments['username'] + '@' + arguments['full_domain']

    if len(arguments['full_domain']) > 0:
        dc_parts = arguments['full_domain'].split('.')

        if len(dc_parts) >= 2:
            arguments['domain'] = dc_parts[-2]
            arguments['top_level_domain'] = dc_parts[-1]

    # Expand argument name alias.
    for arg_name in ARGUMENT_NAME_ALIAS:
        for arg_alias in ARGUMENT_NAME_ALIAS[arg_name]:
            arguments[arg_alias] = arguments[arg_name]

    # Pick randomized argument value.
    for arg_name in ARGUMENT_VALUE_CANDIDATE:
        candidates = ARGUMENT_VALUE_CANDIDATE[arg_name]
        selected_candidates = candidates[randint(0, len(candidates) - 1)]
        arguments[arg_name] = selected_candidates

    return arguments


def sample_test_by_guid(guid: str, arguments: Dict[str, str] = None) -> None | Tuple[List[List[List[str]]], str, List[str], List[str]]:

    if arguments is None:
        arguments = {}
    else:
        arguments = argument_creator(arguments)

    try:
        test = GUID_TESTS[guid]

    except KeyError:
        return None

    else:
        # Get executor name.
        executor_name = test['executor']['name']

        # Get commands.
        executor_commands = test['executor']['command'].strip().split('\n')

        # Get cleanup commands.
        if 'cleanup_command' in test['executor'] and test['executor']['cleanup_command'] is not None:
            executor_cleanups = test['executor']['cleanup_command'].strip().split('\n')
        else:
            executor_cleanups = []

        # Get dependencies.
        dependencies = []

        if 'dependencies' in test:
            for depend in test['dependencies']:
                pre_check = depend['prereq_command'].strip().split('\n')
                setup = depend['get_prereq_command'].strip().split('\n')
                dependencies.append([pre_check, setup])

        # Replace arguments in commands, cleanup commands, and dependency info.
        if 'input_arguments' in test:
            for i, arg_name in enumerate(test['input_arguments']):
                arg_default = test['input_arguments'][arg_name]['default']

                if arguments is not None and arg_name in arguments:
                    arg_value = str(arguments[arg_name])
                else:
                    arg_value = str(arg_default)

                executor_commands = argument_replace(arg_name, arg_value, executor_commands)
                executor_cleanups = argument_replace(arg_name, arg_value, executor_cleanups)

                for i, depend in enumerate(dependencies):
                    pre_check = [cmd.replace(f'#{{{arg_name}}}', arg_value) for cmd in depend[0]]
                    setup = [cmd.replace(f'#{{{arg_name}}}', arg_value) for cmd in depend[1]]
                    dependencies[i] = [pre_check, setup]

        return dependencies, executor_name, executor_commands, executor_cleanups
