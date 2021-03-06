import requests
import httplib
import json, ast
import time

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
final_flow_list = []
found = 0

class StaticFlowPusher(object):

    def __init__(self, server):
        self.server = server

    def get(self, data):
        ret = self.rest_call({}, 'GET')
        return json.loads(ret[2])

    def set(self, data):
        ret = self.rest_call(data, 'POST')
        return ret[0] == 200

    def remove(self, objtype, data):
        ret = self.rest_call(data, 'DELETE')
        return ret[0] == 200

    def rest_call(self, data, action):
        path = '/wm/staticflowpusher/json'
        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
            }
        body = json.dumps(data)
        conn = httplib.HTTPConnection(self.server, 8080)
        conn.request(action, path, body, headers)
        response = conn.getresponse()
        ret = (response.status, response.reason, response.read())
        print ret
        conn.close()
        return ret

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
        print("Setting flow: " + str(payload))
        response = requests.post(url,data = payload)
        print("#####!!!!!       " + str(response))
        if '200' in str(response):
            print('Post Request OK.')
        else:
            print('ERROR: ' + str(response))

def generate_and_send_payload(switch_id,flow_name,eth_dst,cookie,priority,active,actions):
    json_template = '{"switch":"'+switch_id+'", "name":"'+flow_name+'", "eth_dst":"'+eth_dst+'", "cookie":"'+cookie+'", "priority":"'+priority+'", "active":"'+active+'", "actions":"'+actions+'"}'
    json_template = "'" + json_template + "'"
    send_request(api_url,json_template)

def print_all_connected_devices(switch):
    output_dict = {}
    output_dict[switch] = {}
    # print("Finding all connected switches on switch: " +switch)
    for port in switch_dict[switch]:
        output_dict[switch][port] = {}
        if "Dest_SW" in switch_dict[switch][port]:
            output_dict[switch][port]["Dest"] = switch_dict[switch][port]["Dest_SW"]
            output_dict[switch][port]["Type"] = "Switch"
        if "Destination_MAC" in switch_dict[switch][port]:
            output_dict[switch][port]["Dest"] = switch_dict[switch][port]["Destination_MAC"]
            output_dict[switch][port]["Type"] = "Host"
    return(output_dict)

get_switch_data(sdn_con_url,switch_url)

get_device_data(sdn_con_url,device_url)

get_link_data(sdn_con_url,link_url)

pusher = StaticFlowPusher(sdn_con_ip)

for switch in switch_list:
    switch = str(switch)
    switch_dict[switch] = {}

for link in link_list:
    latency = link['latency']
    direction = link['direction']
    source_sw = link['src-switch']
    source_port =  link['src-port']
    destination_sw = link['dst-switch']
    destination_port = link['dst-port']
    type = link['type']

    # print("Link found between Switch "+source_sw+" Port "+str(source_port)+" and Switch "+destination_sw+" on Port "+str(destination_port)+". Direction is "+direction+", Type is "+type+" and Latency is "+str(latency)+".")

    for switch in switch_list:
        if switch == source_sw:
            switch = str(switch)
            switch_dict[switch]["Port "+str(source_port)] = {}
            switch_dict[switch]["Port "+str(source_port)]["Dest_SW"] = str(destination_sw)
            switch_dict[switch]["Port "+str(source_port)]["Dest_Port"] = destination_port
            switch_dict[switch]["Port "+str(source_port)]["Latency"] = latency
            switch_dict[switch]["Port "+str(source_port)]["Type"] = str(type)
            switch_dict[switch]["Port "+str(source_port)]["Direction"] = str(direction)
            switch_dict[switch]["Port "+str(source_port)]["Link_Class"] = 'Switch-Switch'
        if switch == destination_sw:
            switch = str(switch)
            switch_dict[switch]["Port "+str(destination_port)] = {}
            switch_dict[switch]["Port "+str(destination_port)]["Dest_SW"] = str(source_sw)
            switch_dict[switch]["Port "+str(destination_port)]["Dest_Port"] = source_port
            switch_dict[switch]["Port "+str(destination_port)]["Latency"] = latency
            switch_dict[switch]["Port "+str(destination_port)]["Type"] = str(type)
            switch_dict[switch]["Port "+str(destination_port)]["Direction"] = str(direction)
            switch_dict[switch]["Port "+str(destination_port)]["Link_Class"] = 'Switch-Switch'

## Switch information ##
print("\n ### GETTING SWITCH INFORMATION " + str(len(switch_list)) + " SWITCHES ### \n")
for switch in switch_list:
    port_amount = 0
    for unique_json in port_json:
        if (unique_json[0]['switch'] == switch):
            if (int(unique_json[0]['port']) > port_amount):
                port_amount = int(unique_json[0]['port'])
    # print('Switch ' + switch + ' has ' + str(port_amount) + ' host devices currently connected.')

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

    # print('Host: "' + mac + '"(IPv4:' + ipv4_addr + ', IPv6:' + ipv6_addr + ') is connected to Switch: (' + attached_switch + ') on Port ' + attached_switchport + '.')

    for switch in switch_list:
        if switch == attached_switch:
            switch = str(switch)
            switch_dict[switch]["Port "+str(attached_switchport)] = {}
            switch_dict[switch]["Port "+str(attached_switchport)]["Destination_MAC"] = mac
            switch_dict[switch]["Port "+str(attached_switchport)]["Destination_IPv4"] = ipv4_addr
            switch_dict[switch]["Port "+str(attached_switchport)]["Destination_IPv6"] = ipv6_addr
            switch_dict[switch]["Port "+str(attached_switchport)]["Link_Class"] = 'Switch-Host'

# print(len(switch_dict))
print(switch_dict)
for switch in switch_list:
     switch = str(switch)
     print(" #### Switch " + switch + " #### ")
     if switch in switch_dict:
        flow_list = []
        count = 0
        while count < len(switch_dict[switch]):
            port_number = str(count+1)
            count_string = str(count)
            # print("  ---  Port " + port_number)
            output = switch_dict[switch]["Port " + port_number]
            print(output)
            if "Destination_MAC" in str(output):
                flow = {
                    'switch':switch,
                    "name":"Flow_"+switch+"_"+count_string,
                    "cookie":"0",
                    "priority":"32768",
                    "eth_dst":output["Destination_MAC"],
                    # "in_port":"1",
                    "active":"true",
                    "actions":"output="+port_number
                    }
                # pusher.set(flow)
                flow_list.append("Port "+port_number+" --> "+output["Destination_MAC"])
                # generate_and_send_payload(switch,"Flow_"+count_string,output["Destination_MAC"],"0","32768","true","output="+port_number)
            count += 1
            # print("Waiting for 5 seconds before setting next flow.")

### Setting switch to switch flows for end hosts ###
        for device in device_list:

            link_sw_list = []
            link_port_list = []
            end_point_mac = device['mac'][0]
            if end_point_mac in str(flow_list):
                print("Flow already exists for this host on this switch. " + end_point_mac)
                continue
            end_point_sw = device['attachmentPoint'][0]['switch']
            end_point_sw_prt = device['attachmentPoint'][0]['port']
            if end_point_sw == switch:
                print("Device is on this switch - Continuing 'for' loop")
                continue
            print("[NOTICE]:     Finding Path for end host: " + end_point_mac +". (On Switch: " + end_point_sw + " Port Number: " + end_point_sw_prt +")")

            for port in switch_dict[switch]:
                if end_point_sw in str(switch_dict[switch][port]):
                    print("[NOTICE]:    Setting flow for device ("+end_point_mac+") for this switch ("+switch+") on "+port)
                    flow_list.append(port + " --> " + end_point_mac)
                    found = 1
                    break
                else:
                    if 'Dest_SW' in switch_dict[switch][port]:
                        next_sw = switch_dict[switch][port]['Dest_SW']
                        if next_sw != switch:
                            link_sw_list.append(next_sw)
            for neighbour_sw in link_sw_list:
                for entry in switch_dict[switch]:
                    if switch_dict[switch][entry]["Link_Class"] == "Switch-Switch":
                        if switch_dict[switch][entry]["Dest_SW"] == neighbour_sw:
                            orig_port = entry
                output = print_all_connected_devices(neighbour_sw)

## Need to make the following into an iterative function to be called for each neighbour switch ##

                for port in output[neighbour_sw]:
                    if output[neighbour_sw][port]["Type"] == "Switch":
                        new_neighbour_sw = output[neighbour_sw][port]["Dest"]
                        if new_neighbour_sw != switch:
                            # print("("+switch+"-->"+neighbour_sw+"-->"+new_neighbour_sw+"'s Neigbours)")

                            new_output = print_all_connected_devices(new_neighbour_sw)
                            for new_port in new_output[new_neighbour_sw]:
                                if new_neighbour_sw in str(new_output):
                                    if new_output[new_neighbour_sw][new_port]["Type"] == "Host":
                                        if new_output[new_neighbour_sw][new_port]["Dest"] == end_point_mac:
                                            # print("New flow found and set ("+switch+ " " +orig_port+"-->"+neighbour_sw+"-->"+new_neighbour_sw+"("+new_port+"))")
                                            flow_list.append(orig_port + " --> " + end_point_mac)

                                    if new_output[new_neighbour_sw][new_port]["Type"] == "Switch":
                                        next_new_neighbour_sw = new_output[new_neighbour_sw][new_port]["Dest"]
                                        if next_new_neighbour_sw != switch and next_new_neighbour_sw != neighbour_sw and next_new_neighbour_sw != new_neighbour_sw:

                                            next_new_output = print_all_connected_devices(next_new_neighbour_sw)
                                            for next_new_port in next_new_output[next_new_neighbour_sw]:
                                                if next_new_output[next_new_neighbour_sw][next_new_port]["Type"] == "Host":
                                                    if next_new_output[next_new_neighbour_sw][next_new_port]["Dest"] == end_point_mac:
                                                        flow_list.append(orig_port + " --> " + end_point_mac)
                                                if next_new_output[next_new_neighbour_sw][next_new_port]["Type"] == "Switch":
                                                    next_next_new_neighbour_sw = next_new_output[next_new_neighbour_sw][next_new_port]["Dest"]
                                                    if next_next_new_neighbour_sw != switch and next_next_new_neighbour_sw != neighbour_sw and next_next_new_neighbour_sw != new_neighbour_sw and next_next_new_neighbour_sw != next_new_neighbour_sw:

                                                        next_next_new_output = print_all_connected_devices(next_next_new_neighbour_sw)
                                                        for next_next_new_port in next_next_new_output[next_next_new_neighbour_sw]:
                                                            if next_next_new_output[next_next_new_neighbour_sw][next_next_new_port]["Type"] == "Host":
                                                                if next_next_new_output[next_next_new_neighbour_sw][next_next_new_port]["Dest"] == end_point_mac:
                                                                    flow_list.append(orig_port + " --> " + end_point_mac)

        print("\n SETTING "+str(len(flow_list))+" FLOWS ON SWITCH "+switch+". THEY ARE:")
        flow_count = 0
        for flow in flow_list:
            print("Flow_" + str(flow_count) + ": " + flow)
            flow = flow.split(" --> ")
            PORT = flow[0][len(flow[0])-1]
            MAC = flow[1]
            api_flow = {
                'switch':switch,
                "name":"Flow_"+switch+"_"+str(flow_count),
                "cookie":"0",
                "priority":"32768",
                "eth_dst":MAC,
                # "in_port":"1",
                "active":"true",
                "actions":"output="+PORT
                }
            final_flow_list.append(api_flow)
            pusher.set(api_flow)
            flow_count += 1
        print("\n")
