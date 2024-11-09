
from typing import List, Dict
import json


NUMBER_CIRCLE = ['', '①', '②', '③', '④', '⑤', '⑥', '⑦', '⑧', '⑨', '⑩', '⑪', '⑫', '⑬', '⑭', '⑮', '⑯', '⑰', '⑱', '⑲', '⑳']

ACTION_ID2NAME = ['',
                  'Add a weak password for specific user.',
                  'Remove a password for specific user.',
                  'Remove all users.',
                  'Allow command execution and return output normally.',
                  'Block command execution and return permission issue string.',
                  'Block the access of the IP or port and allow command execution.',
                  'Redirect the access to another IP and allow command execution.',
                  'Replace specific string in the command and allow command execution.',
                  'Replace system-related string from the executed command.',
                  'Output the executed command normally with some version variation.',
                  'Show part of executed command only.',
                  'Stuff repeated and endless response to the attackers.',
                  'Intentionally leak some important information in the file and allow command execution.',
                  'Trigger the phishing email and stuff with fake data and allow command execution.',
                  'Reset system to the baseline.',
                  'Kill processes launched by the attacker and allow command execution.']

ACTIVITY_IDF2ID = ['', 'EAC0005', 'EAC0006', 'EAC0007', 'EAC0008', 'EAC0009', 'EAC0014', 'EAC0015',
                   'EAC0016', 'EAC0017', 'EAC0018', 'EAC0019', 'EAC0020', 'EAC0021', 'EAC0022']

ACTIVITY_IDF2NAME = ['', 'Lures', 'Application Diversity', 'Network Diversity', 'Burn-In', 'Email Manipulation',
                     'Software Manipulation', 'Information Manipulation', 'Network Manipulation',
                     'Hardware Manipulation', 'Security Controls', 'Baseline', 'Isolation', 'Attack Vector Migration',
                     'Artifact Diversity']

ACTION_LEN = len(ACTION_ID2NAME) - 1
ACTIVITY_LEN = len(ACTIVITY_IDF2ID) - 1

MAPPING_ACTIVITY2ACTION = {}

MAPPING_ACTION2ACTIVITY = {}


def load_mapping():

    load_mapping_activity2action()
    load_mapping_action2activity()

    self_test()


def load_mapping_activity2action():

    global MAPPING_ACTIVITY2ACTION

    with open('ref/activity2action.json', 'r') as fin:
        MAPPING_ACTIVITY2ACTION = json.load(fin)


def load_mapping_action2activity():

    global MAPPING_ACTION2ACTIVITY

    with open('ref/action2activity.json', 'r') as fin:
        MAPPING_ACTION2ACTIVITY = json.load(fin)


def self_test():

    assert MAPPING_ACTIVITY2ACTION == action2activity_reverser(MAPPING_ACTION2ACTIVITY)
    assert MAPPING_ACTION2ACTIVITY == activity2action_reverser(MAPPING_ACTIVITY2ACTION)


def activity2action_reverser(activity2action: Dict[str, List[List[int]]]) -> Dict[str, List[int]]:

    action2activity = {}

    for activity_idf in activity2action:
        for login_state, action_id in activity2action[activity_idf]:
            action_key = str(login_state * 100 + action_id)

            if action_key not in action2activity:
                action2activity[action_key] = []

            action2activity[action_key].append(int(activity_idf))

    return action2activity_sorter(action2activity)


def action2activity_reverser(action2activity: Dict[str, List[int]]) -> Dict[str, List[List[int]]]:

    activity2action = {}

    for action in action2activity:
        login_state = int(action) // 100
        action_id = int(action) % 100

        for activity_idf in action2activity[action]:
            activity_idf = str(activity_idf)

            if activity_idf not in activity2action:
                activity2action[activity_idf] = []

            activity2action[activity_idf].append([login_state, action_id])

    return activity2action_sorter(activity2action)


def activity2action_sorter(activity2action: Dict[str, List[List[int]]]) -> Dict[str, List[List[int]]]:

    activity_idf_sorted = list(map(int, list(activity2action.keys())))
    activity_idf_sorted.sort()
    activity_idf_sorted = list(map(str, activity_idf_sorted))

    activity2action_ = {}

    for activity_idf in activity_idf_sorted:
        tmp = []

        for login_state, action_id in activity2action[activity_idf]:
            tmp.append(login_state * 100 + action_id)

        tmp.sort()

        activity2action_[activity_idf] = []

        for action in tmp:
            login_state = action // 100
            action_id = action % 100

            activity2action_[activity_idf].append([login_state, action_id])

    return activity2action_


def action2activity_sorter(action2activity: Dict[str, List[int]]) -> Dict[str, List[int]]:

    action_sorted = list(map(int, list(action2activity.keys())))
    action_sorted.sort()
    action_sorted = list(map(str, action_sorted))

    action2activity_ = {}

    for action in action_sorted:
        action2activity_[action] = action2activity[action].copy()
        action2activity_[action].sort()

    return action2activity_


def action2activity_demo(action2activity: Dict[str, List[int]]) -> None:

    for action in action2activity:
        login_state = int(action) // 100
        action_id = int(action) % 100

        print(f'S{login_state} {NUMBER_CIRCLE[action_id]} {ACTION_ID2NAME[action_id]}')

        for activity_idf in action2activity[action]:
            print(f'{NUMBER_CIRCLE[activity_idf]} {ACTIVITY_IDF2NAME[activity_idf]}')

        print()


def activity2action_demo(activity2action: Dict[str, List[List[int]]]) -> None:

    for activity_idf in activity2action:
        print(f'{NUMBER_CIRCLE[int(activity_idf)]} {ACTIVITY_IDF2NAME[int(activity_idf)]}')

        for login_state, action_id in activity2action[activity_idf]:
            print(f'S{login_state} {NUMBER_CIRCLE[action_id]} {ACTION_ID2NAME[action_id]}')

        print()


# Mapping should be loaded first.
# It will do a self test to confirm data is mutual trivial.
load_mapping()
