
from datetime import datetime


with open('merge.log', 'r') as fin:
    lines = fin.readlines()


lines = [line.strip() for line in lines]

outputs = []
for i, line in enumerate(lines):
    if i == 0:
        interval = 0
    else:
        interval = (datetime.strptime(line[:22], '%Y%m%d_%H%M%S.%f') - datetime.strptime(lines[i-1][:22], '%Y%m%d_%H%M%S.%f')).total_seconds()

    interval = '{:12.6f}'.format(interval)

    outputs.append(interval + ' ' + line)

with open('merge_interval.log', 'w') as fout:
    fout.write('\n'.join(outputs))
