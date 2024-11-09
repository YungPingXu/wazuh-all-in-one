
import json
import action_matrix


mapping_activity2action = {}

with open('Book1.csv', 'r') as fin:
    lines = fin.readlines()

for line in lines:
    line = line.strip()
    activity, actions = line.replace('"', '').replace(',', '#', 1).split('#')

    activity_id = action_matrix.NUMBER_CIRCLE.index(activity.split()[0][-1]) + 1

    login_state_id, action_id_circle, action_name = actions.replace(' ', '#', 2).split('#')

    login_state_id = int(login_state_id[1])
    action_id = action_matrix.NUMBER_CIRCLE.index(action_id_circle) + 1
    assert action_matrix.ACTION_ID2NAME[action_id - 1] == action_name

    if activity_id not in mapping_activity2action:
        mapping_activity2action[activity_id] = []

    mapping_activity2action[activity_id].append([login_state_id, action_id])

with open('activity2action.json', 'w') as fout:
    json.dump(mapping_activity2action, fout)

print(mapping_activity2action)
