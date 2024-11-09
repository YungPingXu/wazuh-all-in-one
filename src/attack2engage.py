
from typing import List, Callable
from pathlib import Path
import csv


ACTIVITY_ID2NAME_MAPPING = {}
TECHNIQUE2ACTIVITIES_MAPPING = {}


def load_mapping() -> None:

    with open(Path(__file__).parents[1] / 'share/cowrie/engage_interface/activity.csv', 'r') as fin:
        reader = csv.reader(fin)

        # Skip header.
        next(reader, None)

        for row in reader:
            ACTIVITY_ID2NAME_MAPPING[row[0]] = row[1]

    with open(Path(__file__).parents[1] / 'share/cowrie/engage_interface/attack2engage.csv', 'r') as fin:
        reader = csv.reader(fin)

        # Skip header.
        next(reader, None)

        for row in reader:
            if row[0] in TECHNIQUE2ACTIVITIES_MAPPING:
                if row[1] not in TECHNIQUE2ACTIVITIES_MAPPING[row[0]]:
                    TECHNIQUE2ACTIVITIES_MAPPING[row[0]].append(row[1])
            else:
                TECHNIQUE2ACTIVITIES_MAPPING[row[0]] = [row[1],]


def activity_id2name(activity_id: str) -> str:

    if activity_id in ACTIVITY_ID2NAME_MAPPING:
        return ACTIVITY_ID2NAME_MAPPING[activity_id]
    else:
        return ''


def available_activities() -> List[str]:

    activities = []

    for a in TECHNIQUE2ACTIVITIES_MAPPING.values():
        activities += a

    activities = list(set(activities))

    return activities


def technique2activities(technique_id: str) -> List[str]:

    if technique_id in TECHNIQUE2ACTIVITIES_MAPPING:
        return TECHNIQUE2ACTIVITIES_MAPPING[technique_id]
    else:
        return []


def technique2activities_union(technique_ids: List[str]) -> List[str]:

    activities = []

    for technique_id in technique_ids:
        activities += technique2activities(technique_id)

    activities = list(set(activities))

    return activities


def technique2activities_intersection(technique_ids: List[str]) -> List[str]:

    if len(technique_ids) == 0:
        activities = []

    else:
        activities = available_activities()

        for technique_id in technique_ids:
            activities = list(set(technique2activities(technique_id)) & set(activities))

    return activities


def demo_technique2activity() -> None:

    while True:
        technique_id = input('ATT&CK Technique ID: ')
        activities = [activity_id2name(activity_id) for activity_id in technique2activities(technique_id)]
        print(activities, end='\n\n')


def demo_technique2activities(handler: Callable[[List[str]], List[str]]) -> None:

    while True:
        technique_ids = input('ATT&CK Technique IDs: ').split()
        activities = [activity_id2name(activity_id) for activity_id in handler(technique_ids)]
        print(activities, end='\n\n')


# Must do this first!
load_mapping()

if __name__ == '__main__':
    try:
        # Choose one to demo.
        demo_technique2activity()
        #demo_technique2activities(technique2activities_union)
        #demo_technique2activities(technique2activities_intersection)

    except KeyboardInterrupt:
        print('Program exit.')
