import requests
import json, ast

sdn_con_ip = '172.18.0.2'
sdn_con_port = '8080'
sdn_con_url = 'http://'+sdn_con_ip+':'+sdn_con_port
switch_url = '/wm/core/controller/switches/json'

json_list = []

response = requests.get(sdn_con_url + switch_url,
                         auth=('user', 'password'))
switch_data = response.json()

for unique_json in switch_data:
    uid = (unique_json['switchDPID'])
    response = requests.get(sdn_con_url + '/wm/staticflowpusher/list/'+uid+'/json',
                         auth=('user', 'password'))
    data = response.json()
	if str(data) != '[None]':
	    draft_json = (ast.literal_eval(json.dumps(data)))
	    json_list.append(draft_json[0])

	for ready_json in json_list:
		print(ready_json)
