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
data = response.json()

for unique_json in data:
    uid = (unique_json['switchDPID'])
    # print("\n \n Pulling data from switch: " + uid + '\n \n')
    port_id = 0
    while (port_id <= 20):
        response = requests.get(sdn_con_url + '/wm/statistics/bandwidth/'+uid+'/'+str(port_id)+'/json',
                             auth=('user', 'password'))
        data = response.json()
        if str(data) != '[None]':
            # print("Statistics returned from port number: " + str(port_id))
            draft_json = (ast.literal_eval(json.dumps(data)))
            # print(draft_json[0]['bits-per-second-tx'])
            json_list.append(draft_json[0])
        port_id += 1

json_new = str(json_list).replace("bits-per-second-tx': '","bits-per-second-tx': ")
json_new  = json_new.replace("', 'link-speed-bits-per-second'",", 'link-speed-bits-per-second'")
json_new  = json_new.replace("'bits-per-second-rx': '","'bits-per-second-rx': ")
json_new  = json_new.replace("'link-speed-bits-per-second': '","'link-speed-bits-per-second': ")
json_new  = json_new.replace("', 'dpid':",", 'dpid':")
json_new  = json_new.replace("', 'port': '",", 'port': ")
json_new  = json_new.replace("'}","}")
json_new  = json_new.replace("'",'"')
# print(json_new)
as_json = json.dumps(json_new, default=json_dumps_default, sort_keys=False)
print(as_json)
