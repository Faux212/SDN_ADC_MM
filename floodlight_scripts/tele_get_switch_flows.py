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
	response = requests.get(sdn_con_url + '/wm/staticflowpusher/list/'+uid+'/json',auth=('user', 'password'))
	data = response.json()
	if str(data) != '[None]':
		draft_json = (ast.literal_eval(json.dumps(data)))
		if len(draft_json[uid]) > 0:
			for flow in draft_json[uid]:
				print(flow)
#
# {'Flow_0': {'outPort': 'any',
#  'outGroup': 'any',
#  'idleTimeoutSec': '0',
#   'command': 'ADD',
#    'priority': '32768',
#     'cookieMask': '0',
# 	 'version': 'OF_14',
# 	  'flags': '1',
# 	   'hardTimeoutSec': '0',
# 	    'cookie': '49539595420147166',
# 		 'tableId': '0x0',
# 		  'match': {'eth_dst': '52:a4:56:77:88:cb'},
#  'instructions': {'instruction_apply_actions': {'actions': 'output=1'}}}}
