import requests
from datetime import datetime
auth = ('admin', 'wCuIEvsl?DzCV7BeZV*9FKMW.89yitKq')
agent_id = 1
datetime_from = datetime.now()
datetime_to = datetime_from
search_options = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "term": {
                                    "agent.id": f"{agent_id:03d}"
                                }
                            }
                        ],
                        "filter": [
                            {
                                "range": {
                                    "timestamp": {
                                        "from": datetime_from.strftime("%Y-%m-%dT%H:%M:%S.%f+0800"),
                                        "to": datetime_to.strftime("%Y-%m-%dT%H:%M:%S.%f+0800")
                                    }
                                }
                            }
                        ]
                    }
                },
                "size": 10000,  # This is the maximum records at once.
                "sort": [
                    {
                        "timestamp": {
                            "order": "asc"
                        }
                    }
                ]
            }

req = requests.get(f'https://127.0.0.1:9200/wazuh-alerts-4.x-*/_search', json=search_options, auth=auth, verify=False)

if req.status_code == 200:
    data = req.json()
    server_records_len = data['hits']['total']['value']
    records = data['hits']['hits']
    print(data)
    print(records)
    if server_records_len > len(records):
        print('There are more records on server than you get.')
        print(f'Server has {server_records_len} records.  You only got {len(records)} records.')

else:
    print('Indexer returns error.')
    print(f'ERROR: HTTP status code {req.status_code}')
    print(f'Server returned error messages: {req.json()}')