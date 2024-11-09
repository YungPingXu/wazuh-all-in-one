
from typing import List, Dict, Union
from time import sleep
from pathlib import Path
import json
import socket

from twisted.python import log

from login_state import LoginState
from engage_action import ACTION_ID2NAME, ACTION_LEN


class EngageInterface:

    def __init__(self):

        self.handler: Dict[str, Union[str, int]] = {}
        self.handler_con: Union[socket.socket, None] = None

        self.step_counter = 0

        self.read_config()
        self.init_con()


    def read_config(self) -> None:

        with open(Path(__file__).parents[1] / 'etc/engage_interface.json', 'r') as fin:
            config = json.load(fin)

        self.handler['ip'] = config['handler']['ip']
        self.handler['port'] = config['handler']['port']


    def init_con(self) -> None:

        self.handler_con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        while True:
            log.msg('Connecting to engage handler ...')

            try:
                log.msg(self.handler['ip'], self.handler['port'])
                self.handler_con.connect((self.handler['ip'], self.handler['port']))
            except ConnectionRefusedError:
                log.err('Connection to engage handler failed.')
            else:
                break

            sleep(5)

        log.msg('Connecting to engage handler ... Done')


    def close(self) -> None:

        if self.handler_con is not None:
            log.msg('Closing connection to engage handler ...')
            self.handler_con.close()
            log.msg('Closing connection to engage handler ... Done')


    def next_step(self, login_state: LoginState, attr: List[str], suggested_activities: List[str]) -> int:

        log.msg(f'Pre-process for engage handler: login_state={login_state}, attr={attr}, suggestedActivities={suggested_activities}')

        if self.step_counter != 0:
            # Provide next state to engage handler.
            encoded_data = json.dumps({'state': [str(login_state.value), ] + attr + suggested_activities}).encode()
            log.msg(f'Ask engage handler for an action with state')
            self.handler_con.sendall(encoded_data)

        self.step_counter += 1

        # Get selected action from engage handler.
        action = self.handler_con.recv(1024)

        if action:
            action = int(action.decode())

            # PPS-DEBUG: Set fixed action at this time.
            #action = 16

            log.msg(f'Got response from engage handler. Selected action is {action} "{ACTION_ID2NAME[action]}".')
            log.msg(f'From state ({login_state}, {attr}, {suggested_activities}), selected action {action} "{ACTION_ID2NAME[action]}".')

            return action

        else:
            log.err('Failed to get response from engage handler.')
            log.err('Try to reset environment. step = 0')
            self.step_counter = 0
            self.init_con()

            return -1
