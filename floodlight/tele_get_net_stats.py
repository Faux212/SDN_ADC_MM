import requests
import json, ast

sdn_con_ip = '172.18.0.2'
sdn_con_port = '8080'
sdn_con_url = 'http://'+sdn_con_ip+':'+sdn_con_port
switch_url = '/wm/core/controller/switches/json'

json_list = []

class Decoder(json.JSONDecoder):
    def decode(self, s):
        result = super(Decoder, self).decode(s)
        return self._decode(result)

    def _decode(self, o):
        if isinstance(o, str) or isinstance(o, unicode):
            try:
                return int(o)
            except ValueError:
                return o
        elif isinstance(o, dict):
            return {k: self._decode(v) for k, v in o.items()}
        elif isinstance(o, list):
            return [self._decode(v) for v in o]
        else:
            return o

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
            draft_json = json.loads(draft_json, cls=Decoder)
            # print(draft_json[0]['bits-per-second-tx'])
            json_list.append(draft_json[0])
        port_id += 1


print(json_list)
