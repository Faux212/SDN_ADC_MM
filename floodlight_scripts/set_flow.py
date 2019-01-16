import requests
import json, ast

sdn_con_ip = '172.18.0.2'
sdn_con_port = '8080'
sdn_con_url = 'http://'+sdn_con_ip+':'+sdn_con_port
switch_url = '/wm/core/controller/switches/json'
device_url = '/wm/device/'
end_url = '/wm/staticflowentrypusher/json'
api_url = sdn_con_url+end_url
print(api_url)

switch_list = []
device_list = []
port_json = []

def get_switch_data(sdn_con_url,switch_url):
    response = requests.get(sdn_con_url + switch_url,
                             auth=('user', 'password'))
    switch_data = response.json()
    for unique_json in switch_data:
        uid = (unique_json['switchDPID'])
        switch_list.append(uid)

def get_device_data(sdn_con_url,device_url):
    response = requests.get(sdn_con_url + device_url,
                             auth=('user', 'password'))
    device_data = response.json()
    device_data = device_data['devices']
    for unique_json in device_data:
        device_list.append(unique_json)
        port_json.append(unique_json['attachmentPoint'])


def send_request(url,payload):
        response = requests.post(url,data = payload)
        if '200' in str(response):
            print('Post Request OK.')
        else:
            print('ERROR: ' + str(response))

# def generate_and_send_payload(switch_id,flow_name,source_ip,destination_ip,ethernet_type,cookie,priority,ingress-port,active,actions):
    # json_template = '{"switch": "'+switch_id+'", "name":"'+flow_name+'", "src-ip":"'+source_ip+'", "dst-ip":"'+destination_ip+'", "ether-type":"'+destination_ip+'", "cookie":"'+cookie+'", "priority":"'+priority+'", "ingress-port":"'+ingress-port+'","active":"'+active+'", "actions":"'+actions+'"}'
    # send_request(api_url,json)

get_switch_data(sdn_con_url,switch_url)

print(switch_list)

get_device_data(sdn_con_url,device_url)

print(port_json)


port_amount = 0
for unique_json in port_json:
    if (unique_json[0]['switch'] == switch):
        if (int(unique_json[0]['port']) > port_amount):
            port_amount = int(unique_json[0]['port'])
print('Switch ' + switch + ' has ' + str(port_amount) + ' host devices currently connected.')

for device in device_list:
    print(device['mac'])
    print(device['vlan'])
    print(device['ipv4'])
    print(device['ipv6'])
    print(device['lastSeen'])
    print(device['attachmentPoint']['switch'])
    print(device['attachmentPoint']['port'])




# switch_id =
# flow_name =
# source_ip =
# destination_ip =
# ethernet_type =
# cookie =
# priority =
# ingress-port =
# active =
# actions =
#
# send_request(api_url,json)
