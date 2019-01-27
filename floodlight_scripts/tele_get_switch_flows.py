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
	flow_table = {}
	uid = (unique_json['switchDPID'])
	response = requests.get(sdn_con_url + '/wm/staticflowpusher/list/'+uid+'/json',auth=('user', 'password'))
	data = response.json()
	if str(data) != '[None]':
		draft_json = (ast.literal_eval(json.dumps(data)))
		if len(draft_json[uid]) > 0:
			for flow in draft_json[uid]:
				for key in flow.keys():
					flow_name = key
				# print(flow[flow_name]['outPort'])
				flow_table['Switch'] = uid
				flow_table['Name'] = flow_name
				flow_table['outPort'] = flow[flow_name]['outPort']
				flow_table['outGroup'] = flow[flow_name]['outGroup']
				flow_table['idleTimeoutSec'] = flow[flow_name]['idleTimeoutSec']
				flow_table['command'] = flow[flow_name]['command']
				flow_table['priority'] = flow[flow_name]['priority']
				flow_table['cookieMask'] = flow[flow_name]['cookieMask']
				flow_table['version'] = flow[flow_name]['version']
				flow_table['flags'] = flow[flow_name]['flags']
				flow_table['hardTimeoutSec'] = flow[flow_name]['hardTimeoutSec']
				flow_table['cookie'] = flow[flow_name]['cookie']
				flow_table['tableId'] = flow[flow_name]['tableId']
				if "eth_dst" in str(flow[flow_name]):
					flow_table['eth_dst'] = flow[flow_name]['match']['eth_dst']
				if "actions" in str(flow[flow_name]):
					flow_table['actions'] = flow[flow_name]['instructions']['instruction_apply_actions']['actions']

				flow_json = (ast.literal_eval(json.dumps(flow_table)))
				print(flow_json)

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
