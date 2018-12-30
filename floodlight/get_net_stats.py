import requests
import json

sdn_con_ip = '172.18.0.2'
sdn_con_port = '8080'
sdn_con_url = 'http://'+sdn_con_ip+':'+sdn_con_port
switch_url = '/wm/core/controller/switches/json'

response = requests.get(sdn_con_url + switch_url,
                         auth=('user', 'password'))
data = response.json()

for json in data:
    uid = (json['switchDPID'])
    print("Pulling data from switch: " + uid)
    port_id = 0
    while (port_id <= 20):
        print("Attempting port number: " + str(port_id))
        response = requests.get(sdn_con_url + '/wm/statistics/bandwidth/'+uid+'/json',
                             auth=('user', 'password'))
        data = response.json()
        print(data)
        port_id += 1
