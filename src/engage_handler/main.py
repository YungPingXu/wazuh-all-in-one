#!/usr/bin/env python

# Download pre-trained word2vec model.
# python -m gensim.downloader --download word2vec-google-news-300

from __future__ import annotations

from typing import Tuple, List, Union
from collections import deque, namedtuple
from datetime import datetime
from pathlib import Path
import socket
from threading import Thread
from math import log10
import json
import random
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from transformers import AutoTokenizer
import sys
sys.path.append('..')
import training
from tracer import Tracer, LoggingType
from action_matrix import ACTION_ID2NAME, ACTION_LEN, ACTIVITY_IDF2ID, ACTIVITY_IDF2NAME, ACTIVITY_LEN, MAPPING_ACTIVITY2ACTION


tokenizer = AutoTokenizer.from_pretrained("jackaduma/SecBERT")
cuda = torch.device('cuda')


SERVER_ADDRESS = '0.0.0.0'
SERVER_PORT = 6416
LOGIN_STATE_ID2NAME = ('Trying Login', 'Normal User', 'Root User')
ATTRIBUTE_NAME = ('exec', 'mail_sender', 'mail_receiver', 'username', 'password', 'interface', 'domain', 'ip', 'port', 'path')
ATTRIBUTE_DEFAULT = ('', '', '', '', '', 'enp1s0', 'localhost', '127.0.0.1', '', '')
IS_TRAINING = training.IS_TRAINING
TARGET_UPDATE_STEP = 10
MAX_VECTOR_LENGTH = 300


# Define the environment.
class CustomEnvironment:
    @staticmethod
    def reset() -> Tuple[int, List[str], List[int]]:
        
        return 1, list(ATTRIBUTE_DEFAULT), []
    
    
    @staticmethod
    def action_evaluation(suggested_activities: List[int], encoded_action: int) -> float:

        suggested_actions = []
        
        for activity_idf in suggested_activities:
            actions = MAPPING_ACTIVITY2ACTION[str(activity_idf)]

            for login_state, action_id in actions:
                encoded_action_ = login_state * 100 + action_id

                if encoded_action_ not in suggested_actions:
                    suggested_actions.append(encoded_action_)
              
        if encoded_action in suggested_actions:
            return 1.0
        else:
            return -1.0
    
    
    def __init__(self):
        
        self.previous_state = self.reset()
        self.current_state = self.reset()
        self.done = False
        self.step_counter = 0


    def step(self, action: int, state: Tuple[int, List[str], List[int]]) -> float:
        
        self.previous_state = self.current_state
        self.current_state = state
        self.step_counter += 1

        if self.previous_state[1][3] == 'root':
            username_is_root = 1
        else:
            username_is_root = 0

        if self.previous_state[1][6] == 'localhost':
            domain_is_localhost = 1
        else:
            domain_is_localhost = 0

        if self.previous_state[1][7] == '127.0.0.1':
            ip_is_localhost = 1
        else:
            ip_is_localhost = 0

        if len(self.previous_state[1][9]) == 0:
            path_level = 0
        else:
            path = Path(self.previous_state[1][9])
            tmp_path = Path('/tmp')
            home_path = Path('/home/' + self.previous_state[1][3])

            if (tmp_path == path or tmp_path in path.parents) or (home_path == path or home_path in path.parents):
                path_level = 0
            else:
                path_level = 1
        
        reward = (self.action_evaluation(self.previous_state[2], (self.previous_state[0] * 100 + action))
                  + username_is_root * 0.2
                  + (-domain_is_localhost + 1) * 0.2
                  + (-ip_is_localhost + 1) * 0.2
                  + path_level * 0.2
                  + (self.previous_state[0] - 1) * log10(self.step_counter))
        
        if state[0] == -1:
            self.done = True
        
        return reward


# Define the neural network architecture.
class DQN(nn.Module):
    def __init__(self, input_size, output_size):
        
        super(DQN, self).__init__()
        
        self.fc1 = nn.Linear(input_size, 128)
        self.fc2 = nn.Linear(128, 128)
        self.fc3 = nn.Linear(128, output_size)


    def forward(self, x):
        
        x = torch.relu(self.fc1(x))
        x = torch.relu(self.fc2(x))
        x = self.fc3(x)
        
        return x


# Define the double DQN with replay buffer.
class DoubleDQN:
    transition = namedtuple('transition', ('state', 'action', 'reward', 'next_state', 'done'))
    
    def __init__(self, lr=0.001, gamma=0.99, epsilon=1.0, epsilon_decay=0.999, epsilon_min=0.01, batch_size=32, buffer_size=100):
        
        self.input_size = 3017
        self.output_size = 16
        self.gamma = gamma
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.epsilon_min = epsilon_min
        self.batch_size = batch_size

        self.policy_net = DQN(self.input_size, self.output_size).cuda()
        self.target_net = DQN(self.input_size, self.output_size).cuda()
        self.target_net.load_state_dict(self.policy_net.state_dict())
        self.target_net.eval()

        self.optimizer = optim.Adam(self.policy_net.parameters(), lr=lr)
        self.criterion = nn.MSELoss()

        self.replay_buffer = deque(maxlen=buffer_size)


    def select_action(self, state: Tuple[int, List[str], List[int]]) -> int:
        
        if random.random() < self.epsilon:
            return random.randint(0, self.output_size - 1) + 1
        
        with torch.no_grad():
            q_values = self.policy_net(state_to_tensor(state))
            return q_values.argmax().item() + 1


    def store_transition(self, state: Tuple[int, List[str], List[int]], action: int, reward: float, next_state: Tuple[int, List[str], List[int]], done: bool) -> None:

        state = state_to_tensor(state)
        next_state = state_to_tensor(next_state)
        action -= 1
        
        self.replay_buffer.append(DoubleDQN.transition(state, action, reward, next_state, done))


    def sample_batch(self) -> List[DoubleDQN.transition]:
        
        transitions = random.sample(self.replay_buffer, self.batch_size)
        
        return transitions


    def train(self, state: Tuple[int, List[str], List[int]], action: int, reward: float, next_state: Tuple[int, List[str], List[int]], done: bool) -> Union[None, Tuple[List[float], float]]:
        
        self.store_transition(state, action, reward, next_state, done)

        if len(self.replay_buffer) >= self.batch_size:
            losses = []

            for state, action, reward, next_state, done in self.sample_batch():
                q_values = self.policy_net(state)
                next_q_value = self.target_net(next_state).detach()[self.policy_net(next_state).argmax()]

                q_value = q_values[action]
                expected_q_value = reward + (1 - done) * self.gamma * next_q_value

                loss = self.criterion(q_value, expected_q_value)
                losses.append(float(loss))

                self.optimizer.zero_grad()
                loss.backward()
                self.optimizer.step()

            if self.epsilon > self.epsilon_min:
                self.epsilon *= self.epsilon_decay

            if len(losses) > 0:
                return q_values.tolist(), sum(losses) / len(losses)
            else:
                return None

        return None


    def update_target_network(self) -> None:
        
        self.target_net.load_state_dict(self.policy_net.state_dict())
        
        
class EngageHandler:
    
    def __init__(self):

        self.logger = Tracer('engage')
        self.keep_running = True
        self.server: Union[socket.socket, None] = None
        self.clients: List[Thread] = []
        self.buffer: bytes = b''
        self.environments: Union[None, list] = None

        if IS_TRAINING:
            self.environments = [CustomEnvironment(), DoubleDQN(), 0]
        
        self.init_server()


    def decode_state(self, encoded_state: bytes) -> Tuple[int, List[str], List[int]]:

        self.buffer += encoded_state
        pos = self.buffer.find(b'}')

        if pos == -1:
            return CustomEnvironment.reset()

        else:
            pos += 1
            encoded_state = self.buffer[:pos].decode()
            self.buffer = self.buffer[pos:]

            state: List[str] = json.loads(encoded_state)['state']

            # int [1, 3]
            login_state = int(state[0])

            # List[str], len = 10
            attr = state[1:11]

            if len(state) > 11:
                # List[int], len = [0, 14], for each int [1, 14]
                suggested_activities_idf = [ACTIVITY_IDF2ID.index(act) for act in state[11:] if act in ACTIVITY_IDF2ID]
            else:
                suggested_activities_idf = []

            return login_state, attr, suggested_activities_idf
        
        
    def init_server(self):
        
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((SERVER_ADDRESS, SERVER_PORT))
        self.server.listen(5)
        
        print(f'Server is listening on "{SERVER_ADDRESS}:{SERVER_PORT}".')

        if IS_TRAINING:
            print('Server is run in TRAINING mode.')
            self.logger.log(f'Server is run in TRAINING mode.', LoggingType.DEBUG)
        else:
            print('Server is run in RUNTIME mode.')
            self.logger.log(f'Server is run in RUNTIME mode.', LoggingType.DEBUG)
        
        while self.keep_running:
            try:
                con, client = self.server.accept()
            except KeyboardInterrupt:
                self.close_server()
                break
            
            t = Thread(target=self.handle_con, args=(client, con))
            self.clients.append(t)

            t.start()
            
            
    def close_server(self):
        
        self.keep_running = False
        
        if self.server is not None:
            self.server.close()
            
        print('Server closed.')

        if IS_TRAINING:
            model_filename = str(Path(__file__).parents[0] / 'model' / datetime.now().strftime("%Y%m%d_%H%M%S"))
            torch.save(self.environments[1].policy_net.state_dict(), model_filename)
            print(f'Model file saved to "{model_filename}".')


    def handle_con(self, client: Tuple[str, int], con: socket.socket):

        client_id = len(self.clients)

        print(f'[{client_id}] Accepted connection from "{client[0]}:{client[1]}". Client id is {client_id}.')
        self.logger.log(f'[{client_id}] Accepted connection from "{client[0]}:{client[1]}". Client id is {client_id}.', LoggingType.DEBUG)

        # Use the same object.
        if IS_TRAINING:
            environments = self.environments

        # Properly use different objects.
        # Create new object for new client.
        else:
            model_filename = Path(__file__).parents[0] / 'model' / 'target_model'
            state_dict = torch.load(model_filename)

            environments = [CustomEnvironment(), DoubleDQN(), 0]

            environments[1].policy_net.load_state_dict(state_dict)
            environments[1].target_net.load_state_dict(state_dict)

        environments[0]: CustomEnvironment
        environments[1]: DoubleDQN
        environments[2]: int
            
        # DEBUG
        PREDEFINED_ACTIONS = [[1, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3], [4, 4, 14, 14, 5, 11], [11, 11],
                              [12, 13, 13, 9, 7, 8], [6, 10, 15, 15, 16, 16, 16, 16, 16, 16], []]

        with con:
            con.settimeout(1)

            while self.keep_running and not environments[0].done:
                action = environments[1].select_action(environments[0].current_state)

                # DEBUG
                # if len(PREDEFINED_ACTIONS[client_id]) > 0:
                #     action = PREDEFINED_ACTIONS[client_id].pop(0)

                con.sendall(str(action).encode())
                print(f'[{client_id}] Selected action is {action} "{ACTION_ID2NAME[action]}".')
                self.logger.log(f'[{client_id}] Selected action is {action} "{ACTION_ID2NAME[action]}".')

                while self.keep_running:
                    try:
                        encoded_state = con.recv(1024)
                    except ConnectionResetError:
                        encoded_state = ''
                        break
                    except TimeoutError:
                        pass
                    else:
                        break

                if len(encoded_state) == 0:
                    break

                if self.keep_running:
                    if encoded_state:
                        next_state = self.decode_state(encoded_state)
                    else:
                        next_state = (-1, list(ATTRIBUTE_DEFAULT), [])

                    print(f'[{client_id}] Next state is {next_state}.')
                    self.logger.log(f'[{client_id}] Next state is {next_state}.')

                    reward = environments[0].step(action, next_state)
                    environments[2] += reward

                    if IS_TRAINING:
                        print(f'[{client_id}] [{environments[0].step_counter}] From state {environments[0].previous_state}, do action {action}, to state {environments[0].current_state}. (reward={reward}, total={environments[2]})')
                        self.logger.log(f'[{client_id}] [{environments[0].step_counter}] reward={reward}, total={environments[2]}', LoggingType.DEBUG)

                        result = environments[1].train(environments[0].previous_state, action, reward, environments[0].current_state, environments[0].done)

                        if result is not None:
                            q_values, loss = result
                            print(f'[{client_id}] [{environments[0].step_counter}] loss={loss}, q=({", ".join([f"{q:.2f}" for q in q_values])})')
                            self.logger.log(f'[{client_id}] [{environments[0].step_counter}] loss={loss}, q=({", ".join([str(q) for q in q_values])})', LoggingType.DEBUG)

                        if environments[0].step_counter % TARGET_UPDATE_STEP == 0:
                            environments[1].update_target_network()

        print(f'[{client_id}] Disconnected from {client[0]}:{client[1]} .')
        self.logger.log(f'[{client_id}] Disconnected from {client[0]}:{client[1]} .', LoggingType.DEBUG)


def encode_login_state(state: int) -> np.ndarray:
    
    # Convert integer to one-hot encoding.
    return np.eye(3)[state - 1]


def embed_attributes(attributes: List[str]) -> np.ndarray:

    embedded_attributes = np.array([tokenizer.encode(attr, padding='max_length', max_length=MAX_VECTOR_LENGTH, truncation=True) for attr in attributes])
        
    return embedded_attributes.flatten()


def encode_suggested_activities(activities: List[int]) -> np.ndarray:
    
    # Convert activity IDFs to Multi-hot encoding.
    encoded_activities = np.zeros(ACTIVITY_LEN)
    
    for activity_idf in activities:
        if 1 <= activity_idf <= ACTIVITY_LEN:
            encoded_activities[activity_idf - 1] = 1
    
    return encoded_activities


def state_to_tensor(state: Tuple[int, List[str], List[int]]) -> torch.Tensor:
    
    # Return an one dimension tensor: 3 + 300 * 10 + 14 = 3017.
    
    login_state, attributes, suggested_activities = state
    login_state_tensor = torch.tensor(encode_login_state(login_state), dtype=torch.float32)
    attribute_tensor = torch.tensor(embed_attributes(attributes), dtype=torch.float32)
    suggested_activities_tensor = torch.tensor(encode_suggested_activities(suggested_activities), dtype=torch.float32)
    
    return torch.cat((login_state_tensor, attribute_tensor, suggested_activities_tensor)).cuda()
    

if __name__ == '__main__':
    eh = EngageHandler()
