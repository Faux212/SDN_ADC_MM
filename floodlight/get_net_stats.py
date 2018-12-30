import requests
import json

sdn_con_ip = '172.18.0.2'
sdn_con_port = '8080'
switch_url = '/wm/core/controller/switches/json'

response = requests.get('http://'+sdn_con_ip+':'+sdn_con_port+switch_url,
                         auth=('user', 'password'))
data = response.json()

for json in data:
    # print(json)
    dictdump = json.loads(json.read())
    print(dictdump)


# dictdump = json.loads(data.read())
#
# print(dictdump)
