import pexpect
import logging
import pprint
import csv
import subprocess
import os
import sys
import re
import socket
import struct
from threading import Thread
import subprocess
from Queue import Queue
from netaddr import IPNetwork
import datetime
import time
import glob
import pyCiscoSpark


# some global vars
num_threads = 200
queue = Queue()
fail_pings = []
pass_pings = []
fail_ssh = []
pass_ssh = []
logfile = ''
count = 0

list_of_files = glob.glob('strip_scans/strips_*.csv') # * means all if need specific format then *.csv
latest_file = max(list_of_files, key=os.path.getctime)
print('Latest scan .csv is: ' + latest_file)

##Threaded Ping Function##
def pinger(i, q):
	while True:
		ip = q.get()
		#print "Thread %s: Pinging %s" % (i, ip)
		ret = subprocess.call("ping -c 3 %s" % ip,
			shell=True,
			stdout=open('/dev/null', 'w'),
			stderr=subprocess.STDOUT)
            	if (ret == 0):
            		#print("%s: is alive" % ip)
                    pass_pings.append(ip)
            	else:
            		# ping_error(ip)
                    fail_pings.append(ip)
        	queue.task_done()
##To be notification function or prompt config ##
def ping_error():
    print("Ping Fail")
##Function called when SSH error is encountered ##
def die(child, errstr):
    #print errstr
    #print child.before, child.after
    # child.terminate()
    #print('PROCESS KILLED')
    queue.task_done()
    #print('PROCESS CLOSED')
    exit(1)
##Threaded SSH Debug analyser##
def check_ssh_debug(i, q):
    while True:
        ip = q.get()
        count = 0
        child = pexpect.spawn ('ssh -vvvvv '+ip)
        child.timeout=50
        #print(new)
        #print(child.logfile)
        i = child.expect (['Enabling compatibility mode for protocol 2.0','Connection refused', pexpect.exceptions.TIMEOUT, pexpect.EOF],1)
        #print(child.before)
        if i == 0:
            pass_ssh.append(ip)
            child.terminate()
        else:
            die(child, ip+': ssh Failed')
            fail_ssh.append(ip)
	    print(i)
        queue.task_done()
##Sends error notifications to Spark room##
def lost_strip(error_ipaddress):
    with open('at.txt', 'r') as myfile: ##at.txt = bot access token file ##
        at=myfile.read().replace('\n', '')

    def search (values, searchFor):
        for k in values["items"]:
            #print (k["title"])
            if (k["title"] == searchFor) : return k["id"]
        return None

    accesstoken="Bearer "+at

    rooms_dict=pyCiscoSpark.get_rooms(accesstoken)

    roomid = search (rooms_dict, "PDU Debug")
    if error_ipaddress in pass_pings:
    	pyCiscoSpark.post_message(accesstoken,roomid,error_ipaddress + ": **PDU Offline** - failed ssh test")
    else:
		pyCiscoSpark.post_message(accesstoken,roomid,error_ipaddress + ": **PDU Offline** ")

subnets = []
ips = []
with open('subnet_lib.txt', 'r') as myfile: ##at.txt = bot access token file ##
	subnets=myfile.read().split('\n')
subnet_amount = len(subnets)-1
output = [[]] * subnet_amount
sorted_subnets = [[]] * subnet_amount

print(subnets[:-1])

##Calculates possible IPs from subnets and appends them to output variable##
count = 0
while (count < subnet_amount):
    for ip in IPNetwork(subnets[count]).iter_hosts():
        ips.append('%s' % ip)
    count += 1

#Spawn Ping thread pool
for i in range(num_threads):
	worker = Thread(target=pinger, args=(i, queue))
	worker.setDaemon(True)
	worker.start()
print('Pinging ' + str(len(ips)) + ' possible IP addresses.')
for ip in ips:
    queue.put(ip)
queue.join()
print('Finished Pings.')
print("Hosts Reachable by ping: " + str(len(pass_pings)) + '/' + str(len(ips)))

#Spawn SSH thread pool
start_time = time.time()
queue = Queue()
for i in range(num_threads):
	worker = Thread(target=check_ssh_debug, args=(i, queue))
	worker.setDaemon(True)
	worker.start()
print('Starting SSH queue on ' + str(len(pass_pings)) + ' reachable IP addresses.' )
for ip in pass_pings:
    queue.put(ip)
queue.join()
passed = str(len(pass_ssh))
failed = str(len(fail_ssh))
print('The hosts that passed the ssh test include:'+ passed + '/' + str(len(pass_pings)))

no_host = []
from datetime import datetime
timestamp = datetime.now().strftime('%Y-%m-%d,%H:%M:%S')

##Write new CSV file##
new_csv = "strip_scans/strips_"+timestamp+".csv"
with open(new_csv, "wb") as csv_file:
    writer = csv.writer(csv_file, delimiter=',')
    writer.writerow(['ip_address'] + ['subnet'] + ['hostname'] + ['location'] + ['status'])

dic_old = []
dic_new = []
missing = []
found = []
print('Comparing old and new scans.')
print(latest_file)
reader = csv.DictReader(open(latest_file, 'rb')) ##specify csv to read
for line in reader:
	dic_old.append(line)

dic = []
a = 0
b = 0
c = 0
d = 0
count_2 = 0

while (count_2 < subnet_amount): ##count is less than amount of subnets##
    output[count_2] = []
    print('getting ips from ' + str(subnets[count_2]))
    for ip in IPNetwork(subnets[count_2]).iter_hosts(): ##for ip in generated ips from subnets ##
        output[count_2].append(str(ip)) ## add to output##
    print('Matching IPs on subnet: '+str(count_2+1)+'/'+str(subnet_amount))
    print('number of hosts in this subnet:'+str(len(output[count_2])))
##Matches IP addresses from SSH file to those calculated above##
    count_3 = 0
    while (count_3 < len(pass_ssh)): ##iterate through pass_ssh ips##

	#print(len(output[count_2]))
        if pass_ssh[count_3] in output[count_2]: ##if passed ip is in the subnet ##
            sorted_subnets[count_2].append(str(pass_ssh[count_3])) ## add ip to sorted subnet list ##
            try:
                host = socket.gethostbyaddr(str(pass_ssh[count_3])) ##DNS lookup##
            except socket.error:
                host = ''
            if 'str' in str(type(host)):
                # with open(new_csv, "a") as csv_file:
                    # writer = csv.writer(csv_file, delimiter=',')
                    # writer.writerow([str(pass_ssh[count_3])] + [subnets[count_2]] + ['UNKNOWN_HOSTNAME'] + ['UNKNOWN'] + [' ']) ## if DNS lookup fails ##
                no_host.append(str(pass_ssh[count_3]))
            elif 'hsrp' in host[0]:
                print('Found unwanted host.')
                # print(host[0])
                # print('1')
            elif '-gw'  in host[0]:
                print('Found unwanted host.')
                # print(host[0])
                # print('2')
            elif '-ipmi' in host[0]:
                print('Found unwanted host.')
                # print(host[0])
                # print('5')
            elif '-wsa' in host[0]:
                print('Found unwanted host.')
                # print(host[0])
                # print('4')
            elif '-sw' in host[0]:
                print('Found unwanted host.')
                # print(host[0])
                # print('5')
            elif '-ipc' in host[0]:
                print('Found unwanted host.')
                # print(host[0])
                # print('6')
            elif '-ps' in host[0]:
                print('Found unwanted host.')
                # print(host[0])
                # print('7')
            elif 'dmz' in host[0]:
                print('Found unwanted host.')
                # print(host[0])
	    elif '-fp' in host[0]:
                print('Found unwanted host.')
                # print(host[0])
	    elif '-spm' in host[0]:
		print('Found unwanted host.')
	 	# print(host[0])
	    else:
		value = '0'
		count = 0
		#print(len(dic_old))
		while count < len(dic_old): ##iterate through all lines of old csv##
			if (str(ip) in str(dic_old[count])): ## if ip from pass_ssh is found##
				if ('2' in dic_old[count]['status']):
					d = 1
				if ('1' in dic_old[count]['status']):
					d = 1
				if ('0' in dic_old[count]['status']):
					d = 1
			# else:
			#  	d = 0
			if (str(ip) in dic_old[count]) and ('3' in dic_old[count]['status']): ##if ip from old csv and was missing is now found##
				c = 2
				missing.append(str(ip))
				print('in old file and listed as missing')
			count += 1
		if c == 2:
			value = '2'
		if d == 1:
			value = '1'
		# if d == 0:
		# 	value = '0'
		#print(ip)

		#print(value)
		if len(host) < 1:
			count_3 += 1
			continue
		new_split = str(host[0]).split('.')
		location = new_split[0]
		with open(new_csv, "a") as csv_file:
			writer = csv.writer(csv_file, delimiter=',')
			writer.writerow([str(pass_ssh[count_3])] + [subnets[count_2]] + [host[0]] + [location.upper()] + [value])

	count_3 += 1
    count_2 += 1

for ip in dic_old:
		if (ip['ip_address'] not in pass_ssh):
			# print('missing strip - it is ' + str(ip))
			missing.append(ip)
			with open(new_csv, "a") as csv_file:
				writer = csv.writer(csv_file, delimiter=',')
				writer.writerow([ip['ip_address']] + [ip['subnet']] + [ip['hostname']] + [ip['location']] + ['3'])
##If IP was counted as missing twice in a row - send message##
			print(ip['ip_address'])
			##Debugging CSV to identify failing strips and patterns##
			with open("offline_strips.csv", "a") as csv_file:
				writer = csv.writer(csv_file, delimiter=',')
				writer.writerow([ip['ip_address']] + [ip['subnet']] + [ip['hostname']] + [ip['location']] + ['3'])


print('results are in: ' + new_csv)

print('The following IPs do not have Hostnames configured: \n'+str(no_host))
