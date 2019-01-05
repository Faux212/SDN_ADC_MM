import requests
import json, ast

# Set up the JSON Dump
def json_dumps_default(obj):
	if isinstance(obj, Decimal):
		return str(obj)
	if isinstance(obj, datetime.datetime):
		return str(obj)
	raise TypeError

sdn_con_ip = '172.18.0.2'
sdn_con_port = '8080'
sdn_con_url = 'http://'+sdn_con_ip+':'+sdn_con_port
switch_url = '/wm/core/controller/switches/json'

json_list = []

response = requests.get(sdn_con_url + switch_url,
                         auth=('user', 'password'))
switch_data = response.json()
switch_data = (ast.literal_eval(json.dumps(switch_data)))
switch_data =  (str(switch_data).replace('/','')).replace("'",'"')
print(switch_data)
