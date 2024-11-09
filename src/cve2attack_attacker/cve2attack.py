
import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)

from typing import List, Tuple, Dict
import csv
import gc
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
import re
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoModel

from cve import cve_import_csv


TACTIC_ID2NAME_MAPPING = ['Reconnaissance',
                          'Resource Development',
                          'Initial Access',
                          'Execution',
                          'Persistence',
                          'Privilege Escalation',
                          'Defense Evasion',
                          'Credential Access',
                          'Discovery',
                          'Lateral Movement',
                          'Collection',
                          'Command and Control',
                          'Exfiltration',
                          'Impact']

# Load by load_technique2tactic() .
TECHNIQUE2TACTIC_MAPPING = {}

MODEL_ID2TEXT_MAPPING = ['Process Injection',
                         'Access Token Manipulation',
                         'Hijack Execution Flow',
                         'Data from Local System',
                         'External Remote Services',
                         'Data Manipulation',
                         'Network Sniffing',
                         'Exploitation for Privilege Escalation',
                         'Command and Scripting Interpreter',
                         'Phishing',
                         'Server Software Component',
                         'Archive Collected Data',
                         'Data Destruction',
                         'Browser Session Hijacking',
                         'Exploitation for Credential Access',
                         'Abuse Elevation Control Mechanism',
                         'Adversary-in-the-Middle',
                         'User Execution',
                         'Unsecured Credentials',
                         'Brute Force',
                         'File and Directory Discovery',
                         'Valid Accounts',
                         'Exploitation for Defense Evasion',
                         'Create Account',
                         'Endpoint Denial of Service',
                         'Drive-by Compromise',
                         'Exploitation for Client Execution',
                         'Exploitation of Remote Services',
                         'Stage Capabilities',
                         'Exploit Public-Facing Application',
                         'Forge Web Credentials']

# The model we use only category techniques without sub-techniques.
MODEL_ID2TECHNIQUE_MAPPING = ['T1055',
                              'T1134',
                              'T1574',
                              'T1005',
                              'T1133',
                              'T1565',
                              'T1040',
                              'T1068',
                              'T1059',
                              'T1566',
                              'T1505',
                              'T1560',
                              'T1485',
                              'T1185',
                              'T1212',
                              'T1548',
                              'T1557',
                              'T1204',
                              'T1552',
                              'T1110',
                              'T1083',
                              'T1078',
                              'T1211',
                              'T1136',
                              'T1499',
                              'T1189',
                              'T1203',
                              'T1210',
                              'T1608',
                              'T1190',
                              'T1606']


# Prevent from circular import issue.
import atomic


class Config:
    SEED = 42
    MODEL_PATH = 'allenai/scibert_scivocab_uncased'
    NUM_LABELS = 31

    # data
    TOKENIZER = AutoTokenizer.from_pretrained(MODEL_PATH)
    MAX_LENGTH = 512
    BATCH_SIZE = 16
    VALIDATION_SPLIT = 0.25

    # model
    DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    FULL_FINETUNING = True
    LR = 3e-5
    OPTIMIZER = 'AdamW'
    CRITERION = 'BCEWithLogitsLoss'
    N_VALIDATE_DUR_TRAIN = 3
    N_WARMUP = 0
    SAVE_BEST_ONLY = True
    EPOCHS = 50

    def __init__(self):
        super(Config, self).__init__()


def load_data_from_file(X_file, Y_file):

    X = pd.read_csv(X_file)
    Y = pd.read_csv(Y_file)

    Y = Y.astype(int)

    return (X, Y)


def clean_abstract(text):

    text = text.split()
    text = [x.strip() for x in text]
    text = [x.replace('\n', ' ').replace('\t', ' ') for x in text]
    text = ' '.join(text)
    text = re.sub('([.,!?()])', r' \1 ', text)

    return text


def get_texts(df):

    texts = df.apply(lambda x: clean_abstract(x))
    texts = texts.values.tolist()

    return texts


class TransformerDataset(Dataset):
    def __init__(self, df, labels=None, set_type=None):

        super(TransformerDataset, self).__init__()

        self.texts = get_texts(df)

        self.set_type = set_type
        if self.set_type != 'test':
            self.labels = labels

        self.tokenizer = Config.TOKENIZER
        self.max_length = Config.MAX_LENGTH

    def __len__(self):

        return len(self.texts)

    def __getitem__(self, index):

        tokenized = self.tokenizer.encode_plus(
            self.texts[index],
            max_length=self.max_length,
            pad_to_max_length=True,
            truncation=True,
            return_attention_mask=True,
            return_token_type_ids=False,
            return_tensors='pt'
        )
        input_ids = tokenized['input_ids'].squeeze()
        attention_mask = tokenized['attention_mask'].squeeze()

        if self.set_type != 'test':
            return {
                'input_ids': input_ids.long(),
                'attention_mask': attention_mask.long(),
                'labels': torch.Tensor(self.labels[index]).float(),
            }

        return {
            'input_ids': input_ids.long(),
            'attention_mask': attention_mask.long(),
        }


class Model(nn.Module):
    def __init__(self):

        super(Model, self).__init__()

        self.transformer_model = AutoModel.from_pretrained(Config.MODEL_PATH)
        self.dropout = nn.Dropout(0.5)
        self.output = nn.Linear(768, Config.NUM_LABELS)

    def forward(self, input_ids, attention_mask=None, token_type_ids=None):

        _, o2 = self.transformer_model(
            input_ids=input_ids,
            attention_mask=attention_mask,
            token_type_ids=token_type_ids,
            return_dict=False
        )

        x = self.dropout(o2)
        x = self.output(x)

        return x


def load_best_model() -> Model:

    best_model = Model()
    best_model.to(Config.DEVICE)
    best_model.load_state_dict(torch.load('extended_scibertfft_best_model.pt'))

    return best_model


def predict(model: Model, cve_descriptions: pd.DataFrame) -> pd.DataFrame:

    Y = pd.DataFrame(np.zeros((len(cve_descriptions), Config.NUM_LABELS)))
    y = []

    data = TransformerDataset(cve_descriptions, Y, set_type='test')
    dataloader = DataLoader(data, batch_size=Config.BATCH_SIZE)

    model.eval()

    for step, batch in enumerate(dataloader):
        b_input_ids = batch['input_ids'].to(Config.DEVICE)
        b_attention_mask = batch['attention_mask'].to(Config.DEVICE)

        with torch.no_grad():
            logits = model(input_ids=b_input_ids, attention_mask=b_attention_mask)
            logits = torch.sigmoid(logits)
            logits = np.round(logits.cpu().numpy())
            y.extend(logits)

        del b_input_ids, b_attention_mask
        gc.collect()
        torch.cuda.empty_cache()

    y = pd.DataFrame(np.array(y, dtype=np.uint8))

    return y


def label_id2text(id: int) -> str:

    if 0 <= id < len(MODEL_ID2TEXT_MAPPING):
        return MODEL_ID2TEXT_MAPPING[id]
    else:
        return ''


def label_id2technique(id: int) -> str:

    if 0 <= id < len(MODEL_ID2TECHNIQUE_MAPPING):
        return MODEL_ID2TECHNIQUE_MAPPING[id]
    else:
        return ''


def csv_readable_columns_creator(technique_name: bool = False) -> Dict[int, str]:

    atomic_available_count = atomic.count_available_tests_by_selected_techniques(MODEL_ID2TECHNIQUE_MAPPING)
    columns = {}

    for i in range(len(MODEL_ID2TEXT_MAPPING)):
        tech_name = MODEL_ID2TEXT_MAPPING[i]
        tech_id = MODEL_ID2TECHNIQUE_MAPPING[i]
        atomic_avail = atomic_available_count[tech_id]

        if technique_name:
            columns[i] = f'{tech_name}\n{tech_id} ({atomic_avail})'
        else:
            columns[i] = f'{tech_id}\n{atomic_avail}'

    return columns


def load_technique2tactic() -> None:

    global TECHNIQUE2TACTIC_MAPPING

    with open('ref/enterprise-attack-v14.1-techniques.csv', 'r') as fin:
        reader = csv.reader(fin)

        next(reader)

        for row in reader:
            tech_id = row[0]
            tactics = row[1].split(', ')

            if tech_id.find('.') == -1:
                tactics = [TACTIC_ID2NAME_MAPPING.index(tactic) for tactic in tactics]
                TECHNIQUE2TACTIC_MAPPING[tech_id] = tactics


def read_cve2attack(filename: str = None) -> List[Tuple[str, List[List[str]]]]:

    collect = []

    if filename is None:
        filename = 'output/ssh_cves_labeled_filtered.csv'

    with open(filename, 'r') as fin:
        reader = csv.reader(fin)

        # Skip header.
        next(reader)

        # Each row is a cve.
        for row in reader:
            if len(row) != 34:
                raise ValueError

            cve_id = row[0]
            techniques = [MODEL_ID2TECHNIQUE_MAPPING[i] for i, flag in enumerate(list(map(int, row[2:33]))) if flag == 1]
            tactic_technique = [[] for i in range(len(TACTIC_ID2NAME_MAPPING))]

            for technique in techniques:
                for tactic_id in TECHNIQUE2TACTIC_MAPPING[technique]:
                    if technique not in tactic_technique[tactic_id]:
                        tactic_technique[tactic_id].append(technique)

            collect.append((cve_id, tactic_technique))

    return collect


# Load necessary data before using this module.
load_technique2tactic()


if __name__ == '__main__':
    ssh_cves = cve_import_csv('output/ssh_cves.csv')
    model = load_best_model()
    ssh_cves_attack = predict(model, ssh_cves['description'])
    atomic_available_count = atomic.count_available_tests_by_selected_techniques(MODEL_ID2TECHNIQUE_MAPPING)

    atomic_available = np.array([atomic_available_count[tech_id] for tech_id in MODEL_ID2TECHNIQUE_MAPPING])
    atomic_available = atomic_available[:, None]
    ssh_cves_atomic = ssh_cves_attack.to_numpy() @ atomic_available
    ssh_cves_atomic = ssh_cves_atomic.flatten()
    ssh_cves_atomic = pd.DataFrame({'atomic_avail': ssh_cves_atomic})

    ssh_cves_attack.rename(columns=csv_readable_columns_creator(), inplace=True)
    ssh_cves_labeled = pd.concat([ssh_cves, ssh_cves_attack, ssh_cves_atomic], axis=1)
    ssh_cves_labeled.to_csv('output/ssh_cves_labeled.csv', index=False)

    ssh_cves_labeled_filtered = ssh_cves_labeled.loc[ssh_cves_labeled['atomic_avail'] != 0]
    ssh_cves_labeled_filtered.to_csv('output/ssh_cves_labeled_filtered.csv', index=False)

    print(ssh_cves_labeled.shape)
    print(ssh_cves_labeled_filtered.shape)


    train, test = train_test_split(ssh_cves_labeled_filtered, test_size=0.2)
    train.to_csv('output/ssh_cves_labeled_filtered_train.csv', index=False)
    test.to_csv('output/ssh_cves_labeled_filtered_test.csv', index=False)

    print(train.shape)
    print(test.shape)
