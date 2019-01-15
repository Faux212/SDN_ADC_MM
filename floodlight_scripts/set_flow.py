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
    device_data = str(device_data).replace()
    print(device_data)
    for unique_json in device_data:
        print(unique_json['switch'])

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
