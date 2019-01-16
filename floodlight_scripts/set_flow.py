import requests
import json, ast

sdn_con_ip = '172.18.0.2'
sdn_con_port = '8080'
sdn_con_url = 'http://'+sdn_con_ip+':'+sdn_con_port
switch_url = '/wm/core/controller/switches/json'
device_url = '/wm/device/'
link_url = '/wm/topology/links/json'
end_url = '/wm/staticflowentrypusher/json'
api_url = sdn_con_url+end_url

switch_list = []
switch_dict = {}
device_list = []
link_list = []
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

def get_link_data(sdn_con_url,link_url):
    response = requests.get(sdn_con_url + link_url,
                             auth=('user', 'password'))
    link_data = response.json()
    for unique_json in link_data:
        link_list.append(unique_json)

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

get_device_data(sdn_con_url,device_url)

get_link_data(sdn_con_url,link_url)


for link in link_list:
    latency = link['latency']
    direction = link['direction']
    source_sw = link['src-switch']
    source_port =  link['src-port']
    destination_sw = link['dst-switch']
    destination_port = link['dst-port']
    type = link['type']

    print("Link found between Switch "+source_sw+" Port "+str(source_port)+" and Switch "+destination_sw+" on Port "+str(destination_port)+". Direction is "+direction+", Type is "+type+" and Latency is "+str(latency)+".")

    for switch in switch_list:
        if switch == source_sw:
            switch_dict[switch]["Port "+str(src-source_port)]["Dest_SW"] = destination_sw
            switch_dict[switch]["Port "+str(src-source_port)]["Dest_Port"] = destination_port
            switch_dict[switch]["Port "+str(src-source_port)]["Latency"] = latency
            switch_dict[switch]["Port "+str(src-source_port)]["Type"] = type
            switch_dict[switch]["Port "+str(src-source_port)]["Direction"] = direction

    # switch_dict.fromkeys('switches', source_sw)
    # switch_dict['switches'][source_sw]['links']['source_port'] = source_port
    # switch_dict['switches'][source_sw]['links']['destination_sw'] = destination_sw
    # switch_dict['switches'][source_sw]['links']['destination_port'] = destination_port

## Switch information ##
print("\n ### GETTING SWITCH INFORMATION " + str(len(switch_list)) + " SWITCHES ### \n")
for switch in switch_list:
    port_amount = 0
    for unique_json in port_json:
        if (unique_json[0]['switch'] == switch):
            if (int(unique_json[0]['port']) > port_amount):
                port_amount = int(unique_json[0]['port'])
    print('Switch ' + switch + ' has ' + str(port_amount) + ' host devices currently connected.')

## Device information ##
print("\n ### GETTING DEVICE INFORMATION ON " + str(len(device_list)) + " HOSTS ### \n")
for device in device_list:
    mac = str(device['mac'][0])
    vlans = str(device['vlan'])
    if len(device['ipv4']) > 0:
        ipv4_addr = str(device['ipv4'][0])
    else:
        ipv4_addr = 'Unknown'
    ipv6_addr = str(device['ipv6'][0])
    last_seen = (device['lastSeen'])
    attached_switch = str(device['attachmentPoint'][0]['switch'])
    attached_switchport = (device['attachmentPoint'][0]['port'])

    print('Host: "' + mac + '"(IPv4:' + ipv4_addr + ', IPv6:' + ipv6_addr + ') is connected to Switch: (' + attached_switch + ') on Port ' + attached_switchport + '.')



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
