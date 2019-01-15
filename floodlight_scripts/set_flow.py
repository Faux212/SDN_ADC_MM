import requests
import json, ast

sdn_con_ip = '172.18.0.2'
sdn_con_port = '8080'
sdn_con_url = 'http://'+sdn_con_ip+':'+sdn_con_port
end_url = '/wm/staticflowentrypusher/json'
api_url = sdn_con_url+end_url
print(api_url)

def send_request(url,payload):
        response = requests.post(url,data = payload)
        print(response)

json = '{"switch": "00:00:00:00:00:00:00:02", "name":"00:00:00:00:00:00:00:02.5Mbps02-04.f", "src-ip":"10.0.0.2", "dst-ip":"10.0.0.4", "ether-type":"0x800", "cookie":"0", "priority":"2", "ingress-port":"2","active":"true", "actions":"output=3"}'

send_request(api_url,json)
#
#
# switch
# flow_name
# source_ip
# destination_ip
# ethernet_type
# cookie
# priority
# ingress-port
# active
# actions
