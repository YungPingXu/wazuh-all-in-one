
from typing import List
from pathlib import Path
import json
import base64
import requests
from zipfile import ZipFile
import numpy as np
import pandas as pd


def extract_cve_from_file(file_content: dict) -> List[str]:

    cve_id = file_content['cveMetadata']['cveId']
    cve_description = ''

    # Skip rejected cve.
    if 'rejectedReasons' not in file_content['containers']['cna']:
        for descriptions in file_content['containers']['cna']['descriptions']:
            if descriptions['lang'] == 'en' or descriptions['lang'].startswith('en-'):
                cve_description = descriptions['value']
                break

        if len(cve_description) == 0:
            print(f'There is NO description of CVE "{cve_id}" due to no english description, so this CVE is ignored.')
        else:
            return [cve_id, cve_description]

    return []


def get_github_latest_commit(owner: str, repo: str) -> str:

    req = requests.get(f'https://api.github.com/repos/{owner}/{repo}/commits/main')

    if req.status_code == 200:
        return req.json()['sha']
    else:
        print(f'HTTP status code {req.status_code}. {req.text}')

    return ''


def get_github_files(owner: str, repo: str, sha: str = None) -> dict:

    # Get sha from latest commit.
    if sha is None:
        sha = get_github_latest_commit(owner, repo)

        if len(sha) == 0:
            return {}

    req = requests.get(f'https://api.github.com/repos/{owner}/{repo}/git/trees/{sha}?recursive=1')

    if req.status_code == 200:
        return req.json()['tree']

    return {}


def get_github_cve_online() -> List[List[str]]:

    owner = 'CVEProject'
    repo = 'cvelistV5'
    cves = []

    files = get_github_files(owner, repo)

    for item in files:
        path = item['path']
        name = path.split('/')[-1]

        if name.startswith('CVE-') and name.endswith('.json'):
            req = requests.get(item['url'])

            if req.status_code == 200:
                resp = req.json()

                if resp['encoding'] == 'base64':
                    cve_json = json.loads(base64.b64decode(resp['content'].strip()).decode())
                    cve = extract_cve_from_file(cve_json)

                    if len(cve) > 0:
                        cves.append(cve)

                else:
                    print(f'Encoding of file "{path}" is NOT default encoding, base64, so the file is ignored.')

            else:
                print(f'Failed to get CVE file contents for file "{path}", so the file is ignored.')

    return cves


def get_github_archive(owner: str, repo: str, filename: str = 'cves.zip') -> bool:

    req = requests.get(f'https://api.github.com/repos/{owner}/{repo}/zipball')

    if req.status_code == 200:
        with open(filename, 'wb') as fout:
            fout.write(req.content)

        return Path(filename).exists()

    else:
        print(f'HTTP status code {req.status_code}. Failed to locate the archive file.')

    return False


def extract_archive(filename: str, target: str = None) -> None:

    with ZipFile(filename, 'r') as file:
        file.extractall(target)


def get_cve_folder_name() -> str:

    candidates = list(Path('.').glob('CVEProject-cvelistV5-*'))

    if len(candidates) >= 1:
        return str(candidates[0])

    return ''


def get_github_cve_local() -> List[List[str]]:

    owner = 'CVEProject'
    repo = 'cvelistV5'
    zip_filename = 'cves.zip'
    cves = []

    if len(get_cve_folder_name()) == 0:
        while not Path(zip_filename).exists():
            print('Download CVE archive from github.')
            get_github_archive(owner, repo, zip_filename)

        while len(get_cve_folder_name()) == 0:
            print('Extract CVE archive locally.')
            extract_archive(zip_filename)

        while Path(zip_filename).exists():
            print('Delete CVE local archive.')
            Path(zip_filename).unlink(missing_ok=True)

    cve_files = list(map(str, list((Path(get_cve_folder_name()) / 'cves').glob('**/CVE-*.json'))))

    for file in cve_files:
        with open(file, 'rb') as fin:
            cve_json = json.load(fin)
            cve = extract_cve_from_file(cve_json)

            if len(cve) > 0:
                cves.append(cve)

    return cves


def filter_cve(keyword: str, cves: List[List[str]]) -> List[List[str]]:

    extracted_cves = []

    for cve in cves:
        if cve[1].lower().find(keyword.lower()) != -1:
            extracted_cves.append(cve)

    return extracted_cves


def cve2dataframe(cves: List[List[str]]) -> pd.DataFrame:

    return pd.DataFrame({'id': np.array(cves)[:, 0], 'description': np.array(cves)[:, 1]})


def cve_export_csv(cves: List[List[str]], filename: str):

    cves = cve2dataframe(cves)
    cves.to_csv(filename, index=False)


def cve_import_csv(filename: str) -> pd.DataFrame:

    cves = pd.read_csv(filename)

    return cves


if __name__ == '__main__':
    cves = get_github_cve_local()
    ssh_cves = filter_cve('ssh', cves)
    cve_export_csv(ssh_cves, 'output/ssh_cves.csv')
    print('Exported ssh CVEs to "output/ssh_cves.csv".')
