
from pathlib import Path
import json
import os

IS_TRAINING = False


def read_config() -> None:

    global IS_TRAINING
    with open(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/etc/training.json', 'r') as fin:
        config = json.load(fin)

    IS_TRAINING = config['is_training']


read_config()
