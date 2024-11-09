import requests
from requests.auth import HTTPBasicAuth

provider_ip = '192.168.122.1'
provider_port = 55000
vm_ip = '192.168.4.59'

req = requests.get(f'https://{provider_ip}:{provider_port}/security/user/authenticate?raw=true', auth=HTTPBasicAuth('wazuh', '8rCB81l*MqLxwL7h+*rSwInr3JtdWBA1'), verify=False)
token = req.text
print(token)

req = requests.get(f'https://{provider_ip}:{provider_port}/agents?select=id&ip={vm_ip}', headers={'Authorization': f'Bearer {token}'}, verify=False)
print(req.text)
