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
switch_url = '/wm/device/'

json_list = []

response = requests.get(sdn_con_url + switch_url,
                         auth=('user', 'password'))
device_data = response.json()
device_data = (ast.literal_eval(json.dumps(device_data)))
device_data =  str(device_data).replace("'",'"')
device_data = device_data.replace('"port": "','"port": ')
device_data = device_data.replace('"}]','}]')
device_data = device_data.replace('{"devices": ','')
device_data = device_data.replace('}]}','}]')
device_data = device_data.replace(' "attachmentPoint": [{"switch":',' "attachedToSwitch":')
device_data = device_data.replace('"port"','"attachedtoSwitchPort"')
device_data = device_data.replace(']','')
device_data = device_data.replace('[','')
print(device_data)
