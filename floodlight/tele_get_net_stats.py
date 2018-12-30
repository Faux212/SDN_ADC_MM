import requests
import json

sdn_con_ip = '172.18.0.2'
sdn_con_port = '8080'
sdn_con_url = 'http://'+sdn_con_ip+':'+sdn_con_port
switch_url = '/wm/core/controller/switches/json'

json_list = []

response = requests.get(sdn_con_url + switch_url,
                         auth=('user', 'password'))
data = response.json()

for json in data:
    uid = (json['switchDPID'])
    # print("\n \n Pulling data from switch: " + uid + '\n \n')
    port_id = 0
    while (port_id <= 20):
        response = requests.get(sdn_con_url + '/wm/statistics/bandwidth/'+uid+'/'+str(port_id)+'/json',
                             auth=('user', 'password'))
        data = response.json()
        if str(data) != '[None]':
            # print("Statistics returned from port number: " + str(port_id))
            # print(data)
            json_list.append(data)
        port_id += 1

as_json = json.dumps(data, default=json_dumps_default, sort_keys=False)
print(as_json)
