import pexpect
import pprint
import subprocess
import os
import csv
import sys
from multiprocessing import Queue
import socket
import struct
from threading import Thread
from Queue import *
import getpass, os, traceback
import time

def snmp_auto_config(): ##SSH into target devices to configure SNMP ##
    count_1 = 0
    print("\n ---------- Starting Automatic Configuration ---------- ") ##Could be implemented earlier to avoid wait times - but that would require prompting Y/N per device
    while (count_1 < len(fails)):
        #print(count_1)
        #print(len(fails))
        ip_address = fails[count_1]
        if ip_address in fail_ssh:
            print(ip_address + ' failed the ssh check - no auto configuration attempted')
        else:
            count_2 = 0
            while (count_2 < len(dic)):
            	if "'"+ip_address+"'" in str(dic[count_2]):
            		subnet = dic[count_2]["subnet"]
            		#hostname = dic[count_2]["hostname"]
            		location = dic[count_2]["location"]
            		## variables pulled from config.ini file ##
            		ssh_user = ConfigSectionMap(subnet)['sshuser']
            		ssh_passw = ConfigSectionMap(subnet)['sshpass']
              		ldap_host = ConfigSectionMap("global")['ldap_host']
              		ldap_port = ConfigSectionMap("global")['ldap_port']
              		ldap_bind = ConfigSectionMap("global")['ldap_bind']
              		ldap_pass = ConfigSectionMap("global")['ldap_pass']
              		ldap_base = ConfigSectionMap("global")['ldap_base']
              		ldap_filter = ConfigSectionMap("global")['ldap_filter']
              		ldap_group_attr = ConfigSectionMap("global")['ldap_group_attr']
                   	ldap_admin_group = ConfigSectionMap("global")['ldap_admin_group']
                   	ldap_user_group = ConfigSectionMap("global")['ldap_user_group']

            		verifier = ConfigSectionMap(subnet)['verifier']
            	count_2 += 1

            print('# Starting SSH session with Host '+str(count_1+1)+': '+ip_address+' #')
            child = pexpect.spawn ('sshpass -p "'+ssh_passw+'" ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss -oStrictHostKeyChecking=no '+ssh_user+'@'+ip_address)
            child.timeout=300
            i = child.expect([pexpect.TIMEOUT, 'Permission denied', pexpect.EOF, 'Smart CDU: ', 'Smart PDU: '])
            print(i)
            if i == 0:
                die(child, 'ERROR!\nSSH timed out. Here is what SSH said:')
            elif i == 1:
                die(child, 'ERROR!\nIncorrect password Here is what SSH said:')
            elif i == 2:
                print child.before
            elif i == 3:
                print('####### SSH Connection Success #######')

                print('-------- Setting Email Disabled -------- ')
                child.sendline ('set email disabled\r')
                child.expect ('Smart CDU:')

                print('-------- Checking Firmware Version -------- ')
                child.sendline ('version\r')
                child.expect ('Smart CDU:')
                new = child.before
                #print(new)
                if (ver_1 in new):
                    print(ver_1+' detected.')
                if (ver_2 in new):
                    print(ver_2+' detected.')
                #print(new)
                if (ip_address in fail_ldap):
                    if ('7.0g' in new):
                        print('7.0g found - skipping')
                    if (ver_1 in new) and ('7.0g' not in new):
                        print('-------- Setting '+ver_1+' LDAP -------- ')
                        #Set LDAP
                        print('-------- Setting LDAP -------- ')
                        child.sendline ('set ldap enabled\r')
                        child.expect ('Command successful')
                        ##Set Primary Host
                        print('   -------- Setting LDAP Primary Host -------- ')
                        child.expect ('Smart CDU: ')
                        child.sendline ('set ldap host1 '+ldap_host+'\r')
                        # child.expect ('Host/IP')
                        # child.sendline (ldap_host+'\r')
                        child.expect ('Command successful')
                    ##Set Port
                        print('   -------- Setting LDAP Port -------- ')
                        child.expect ('Smart CDU: ')
                        child.sendline ('set ldap port\r')
                        child.expect ('LDAP Port')
                        child.sendline (ldap_port+'\r')
                        child.expect ('Command successful')

                        print('   -------- Setting LDAP Bind TLS -------- ')
                        child.expect ('Smart CDU: ')
                        child.sendline ('set ldap bind tls\r')
                        child.expect ('Command successful')

                        print('   -------- Setting LDAP Bind DN -------- ')
                        child.expect ('Smart CDU: ')
                        child.sendline ('set ldap binddn\r')
                        child.expect ('Enter Search Bind DN')
                        child.sendline (ldap_bind+'\r') ##Need Confirmation##
                        child.expect ('Command successful')

                        print('   -------- Setting LDAP BIND PW -------- ')
                        child.expect ('Smart CDU: ')
                        child.sendline ('set ldap bindpw\r')
                        child.expect ('Search Bind Password')
                        child.sendline (ldap_pass+'\r')
                        child.expect ('Command successful')

                        print('   -------- Setting LDAP Base DN -------- ')
                        child.expect ('Smart CDU: ')
                        child.sendline ('set ldap userbasedn\r')
                        child.expect ('Enter User Search Base')
                        child.sendline (ldap_base+'\r') ##Need Confirmation##
                        child.expect ('Command successful')

                        print('   -------- Setting LDAP User Filter -------- ')
                        child.expect ('Smart CDU: ')
                        child.sendline ('set ldap userfilter\r')
                        child.expect (' ')
                        child.sendline (ldap_filter+'\r')
                        child.expect ('Command successful')
                        #print(child.before)

                        print('   -------- Setting LDAP Group Attribute -------- ')
                        child.expect ('Smart CDU: ')
                        child.sendline ('set ldap groupattr\r')
                        child.expect (' ')
                        child.sendline (ldap_group_attr+'\r')
                        child.expect ('Command successful')

                        print('   -------- Disabling LDAP Group Search -------- ')
                        child.expect ('Smart CDU: ')
                        child.sendline ('set ldap groupsearch disabled\r')
                        child.expect ('Command successful')

                        print('   -------- Creating LDAP Admin Group -------- ')
                        child.expect ('Smart CDU: ')
                        child.sendline ('create ldapgroup '+ldap_admin_group+'\r')
                        m = child.expect (['Command successful', 'command failed'])
                        if m == 1:
                            print('Admin Group exists')

                        print('   -------- Creating LDAP User Group -------- ')
                        child.expect ('Smart CDU: ')
                        child.sendline ('create ldapgroup '+ldap_user_group+'\r')
                        m = child.expect (['Command successful', 'command failed'])
                        if m == 1:
                            print('User Group exists')

                        print('   -------- Setting LDAP Admin Group -------- ')
                        child.expect ('Smart CDU: ')
                        child.sendline ('set ldapgroup access admin\r')
                        child.expect ('Group Name: ')
                        child.sendline (ldap_admin_group+'\r')
                        child.expect ('Command successful')

                        print('   -------- Setting LDAP User Group -------- ')
                        child.expect ('Smart CDU: ')
                        child.sendline ('set ldapgroup access user\r')
                        child.expect ('Group Name: ')
                        child.sendline (ldap_user_group+'\r')
                        child.expect ('Command successful')

                        print('   -------- Disabling LDAP Group Search -------- ')
                        child.expect ('Smart CDU: ')
                        child.sendline ('set ldap groupsearch disabled\r')
                        child.expect ('Command successful')

                    if (ver_2 in new):
                        print('-------- Setting '+ver_2+' LDAP -------- ')
                        #Set LDAP
                        print('-------- Setting LDAP -------- ')
                        child.sendline ('set access method ldaplocal\r')
                        child.expect ('Command successful')
                        ##Set Primary Host
                        print('   -------- Setting LDAP Primary Host -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldap primary '+ldap_host+'\r')
                        # child.expect ('Host/IP')
                        # child.sendline (ldap_host+'\r')
                        child.expect ('Command successful')
                    ##Set Port
                        print('   -------- Setting LDAP Port -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldap port '+ldap_port+'\r')
                        # child.expect ('LDAP Port')
                        # child.sendline (ldap_port+'\r')
                        child.expect ('Command successful')

                        print('   -------- Setting LDAP Bind TLS -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldap bind tls\r')
                        child.expect ('Command successful')

                        print('   -------- Setting LDAP Bind DN -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldap binddn\r')
                        child.expect ('LDAP search bind DN')
                        child.sendline (ldap_bind+'\r') ##Need Confirmation##
                        child.expect ('Command successful')

                        print('   -------- Setting LDAP BIND PW -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldap bindpw\r')
                        child.expect ('search bind password')
                        child.sendline (ldap_pass+'\r')
                        child.expect ('Command successful')

                        print('   -------- Setting LDAP Base DN -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldap userbasedn\r')
                        child.expect ('user search base DN')
                        child.sendline (ldap_base+'\r') ##Need Confirmation##
                        child.expect ('Command successful')

                        print('   -------- Setting LDAP User Filter -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldap userfilter\r')
                        child.expect ('user search filter')
                        child.sendline (ldap_filter+'\r')
                        child.expect ('Command successful')
                        #print(child.before)

                        print('   -------- Setting LDAP Group Attribute -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldap groupattr\r')
                        child.expect ('membership attribute')
                        child.sendline (ldap_group_attr+'\r')
                        child.expect ('Command successful')

                        print('   -------- Creating LDAP Admin Group -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('create ldapgroup '+ldap_admin_group+'\r')
                        m = child.expect (['Command successful', 'command failed'])
                        if m == 1:
                            print('User Group exists')

                        print('   -------- Creating LDAP User Group -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('create ldapgroup '+ldap_user_group+'\r')
                        m = child.expect (['Command successful', 'command failed'])
                        if m == 1:
                            print('User Group exists')

                        print('   -------- Setting LDAP Admin Group -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldapgroup access admin\r')
                        child.expect ('LDAP group: ')
                        child.sendline (ldap_admin_group+'\r')
                        child.expect ('Command successful')

                        print('   -------- Setting LDAP User Group -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldapgroup access user\r')
                        child.expect ('LDAP group: ')
                        child.sendline (ldap_user_group+'\r')
                        child.expect ('Command successful')

                        print('   -------- Disabling LDAP Group Search -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldap groupsearch disabled\r')
                        child.expect ('Command successful')

            elif i == 4:
                print('####### SSH Connection Success #######')

                print('-------- Setting Email Disabled -------- ')
                child.sendline ('set email disabled\r')
                child.expect ('Smart PDU:')

                print('-------- Checking Firmware Version -------- ')
                child.sendline ('version\r')
                child.expect ('Smart PDU:')
                new = child.before
                #print(new)
                if (ver_2 in new):
                    print(ver_2+' detected.')
                else:
                    print('Unvalidated version detected: \n' + new)
                #print(new)


                if (ip_address in fail_ldap):
                    if (ver_2 in new):
                        print('-------- Setting '+ver_2+' LDAP -------- ')
                        #Set LDAP
                        print('-------- Setting LDAP -------- ')
                        child.sendline ('set access method ldaplocal\r')
                        child.expect ('Command successful')
                        ##Set Primary Host
                        print('   -------- Setting LDAP Primary Host -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldap primary '+ldap_host+'\r')
                        # child.expect ('Host/IP')
                        # child.sendline (ldap_host+'\r')
                        child.expect ('Command successful')
                    ##Set Port
                        print('   -------- Setting LDAP Port -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldap port '+ldap_port+'\r')
                        # child.expect ('LDAP Port')
                        # child.sendline (ldap_port+'\r')
                        child.expect ('Command successful')

                        print('   -------- Setting LDAP Bind TLS -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldap bind tls\r')
                        child.expect ('Command successful')

                        print('   -------- Setting LDAP Bind DN -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldap binddn\r')
                        child.expect ('LDAP search bind DN')
                        child.sendline (ldap_bind+'\r') ##Need Confirmation##
                        child.expect ('Command successful')

                        print('   -------- Setting LDAP BIND PW -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldap bindpw\r')
                        child.expect ('search bind password')
                        child.sendline (ldap_pass+'\r')
                        child.expect ('Command successful')

                        print('   -------- Setting LDAP Base DN -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldap userbasedn\r')
                        child.expect ('user search base DN')
                        child.sendline (ldap_base+'\r') ##Need Confirmation##
                        child.expect ('Command successful')

                        print('   -------- Setting LDAP User Filter -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldap userfilter\r')
                        child.expect ('user search filter')
                        child.sendline (ldap_filter+'\r')
                        child.expect ('Command successful')
                        #print(child.before)

                        print('   -------- Setting LDAP Group Attribute -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldap groupattr\r')
                        child.expect ('membership attribute')
                        child.sendline (ldap_group_attr+'\r')
                        child.expect ('Command successful')

                        print('   -------- Creating LDAP Admin Group -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('create ldapgroup '+ldap_admin_group+'\r')
                        m = child.expect (['Command successful', 'command failed', 'reserved name'])
                        if m == 1 or 2:
                            print('User Group exists')

                        print('   -------- Creating LDAP User Group -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('create ldapgroup '+ldap_user_group+'\r')
                        m = child.expect (['Command successful', 'command failed', 'reserved name'])
                        if m == 1 or 2:
                            print('User Group exists')

                        print('   -------- Setting LDAP Admin Group -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldapgroup access admin\r')
                        child.expect ('LDAP group: ')
                        child.sendline (ldap_admin_group+'\r')
                        child.expect ('Command successful')

                        print('   -------- Setting LDAP User Group -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldapgroup access user\r')
                        child.expect ('LDAP group: ')
                        child.sendline (ldap_user_group+'\r')
                        child.expect ('Command successful')

                        print('   -------- Disabling LDAP Group Search -------- ')
                        child.expect ('Smart PDU: ')
                        child.sendline ('set ldap groupsearch disabled\r')
                        child.expect ('Command successful')

            if ('Restart required' in child.before):
                print(' -------- RESTART REQUIRED ON STRIP '+ip_address+': Restarting PDU -------- ')
                child.sendline ('restart\r')
                child.expect (': ')
                child.sendline ('Yes\r')
                child.sendline ('Yes\r')

            #child.sendline ('exit\r')
            end_session(child)


                # else:
                #     print(" -------- Unknown Firmware Version - Not Configuring -------- ")
                #     child.sendline ('exit\r')
                #     end_session()

        count_1 = count_1 + 1
def ssh_test(i, q): ##Threaded test to determine if SSH connections are successful and identifies credential and timeout errors if not ##
    while True:
        ip = q.get()
        count = 0
        while (count < len(dic)):
            # if ip in dic[count]["ip_address"]:
            if "'"+ip+"'" in str(dic[count]):
                subnet = dic[count]["subnet"]
                #hostname = dic[count]["hostname"]
                location = dic[count]["location"]
    			## variables pulled from config.ini file ##
                ssh_user = ConfigSectionMap(subnet)['sshuser']
                ssh_passw = ConfigSectionMap(subnet)['sshpass']
                verifier = ConfigSectionMap(subnet)['verifier']
            count += 1
        print('Testing SSH on '+ip)
        newlocation = location.split('.')
        location = newlocation[0]
        # print('LOCATION IS :'+location)
        a = 0
        b = 0
        child = pexpect.spawn ('sshpass -p "'+ssh_passw+'" ssh -vvvv -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss -oStrictHostKeyChecking=no '+ssh_user+'@'+ip)
        child.timeout=50
        i = child.expect([pexpect.TIMEOUT, 'Connection refused', pexpect.EOF, 'Smart CDU: ', 'Smart PDU: '])
        print(i)
        if i == 0:
            fail_ssh.append(ip)
            die(child, ip+': ERROR!\nSSH timed out. Here is what SSH said:')
        elif i == 1:
            fail_ssh.append(ip)
            die(child, ip+': ERROR!\nIncorrect password Here is what SSH said:')
        elif i == 2:
            print child.before
        elif i == 3:
            pass_ssh.append(ip)
            print(ip+': SSH TRUE')
            child.sendline ('version\r')
            j = child.expect ('Smart CDU:')
            new = child.before

        elif i == 4:
            pass_ssh.append(ip)
            print(ip+': SSH TRUE')
            #print('-------- Checking Firmware Version -------- ')
            child.sendline ('version\r')
            j = child.expect ('Smart PDU:')
            new = child.before
            if ('Critical Alert' in new):
                crit_alerts.append(ip)

        queue.task_done()
    # die(child, 'SSH tests concluded.')
def ldap_test(i, q):
    while True:
        ip = q.get()
        count = 0
        while (count < len(dic)):
            # if ip in dic[count]["ip_address"]:
            if "'"+ip+"'" in str(dic[count]):
                subnet = dic[count]["subnet"]
                #hostname = dic[count]["hostname"]
                location = dic[count]["location"]
    			## variables pulled from config.ini file ##
                ssh_user = ConfigSectionMap(subnet)['sshuser']
                ssh_passw = ConfigSectionMap(subnet)['sshpass']
                cec_user = ConfigSectionMap("global")['cecuser']
                cec_passw = ConfigSectionMap("global")['cecpass']
                verifier = ConfigSectionMap(subnet)['verifier']
            count += 1
        print('Testing LDAP on '+ip)
        newlocation = location.split('.')
        location = newlocation[0]
        # print('LOCATION IS :'+location)
        a = 0
        b = 0
        child = pexpect.spawn ('sshpass -p "'+cec_passw+'" ssh -vvvv -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss -oStrictHostKeyChecking=no '+cec_user+'@'+ip)
        child.timeout=50
        i = child.expect([pexpect.TIMEOUT, 'Connection refused', pexpect.EOF, 'Smart CDU: ', 'Smart PDU: '])
        print(i)
        if i == 0:
            die(child, ip+': ERROR!\nSSH timed out. Here is what SSH said:')
        elif i == 1:
            die(child, ip+': LDAP Failed')
            fail_ldap.append(ip)
            fails.append(ip)
        elif i == 2:
            print(ip+': EOF - LDAP Failed')
            fail_ldap.append(ip)
            fails.append(ip)
        elif i == 3:
            print(ip+' ldap enabled and verified')
            pass_ldap.append(ip)
        elif i == 4:
            print(ip+' ldap enabled and verified')
            pass_ldap.append(ip)
        queue.task_done()
def pinger(i, q): ## Threaded ping test that runs through all ips given ##
	"""Pings subnet"""
	while True:
		ip = q.get()
		#print "Thread %s: Pinging %s" % (i, ip)
		ret = subprocess.call("ping -c 1 %s" % ip,
			shell=True,
			stdout=open('/dev/null', 'w'),
			stderr=subprocess.STDOUT)
                #print('ping occuring')
                #print("PASSED:"+str(pass_pings))
                #print("FAILED:"+str(fail_pings))
            	if (ret == 0):
            		#print("%s: is alive" % ip)
                    pass_pings.append(ip)

            	else:
            		fail_pings.append(ip)

        	queue.task_done()
def die(child, errstr): ##Function called when SSH error is encountered ##
    print errstr
    print child.before, child.after
    # child.terminate()
    print('PROCESS KILLED')
    queue.task_done()
    child.close()
    print('PROCESS CLOSED')
    exit(1)
def ConfigSectionMap(section): ##Function used for importing config.ini file variables ##
    dict1 = {}
    options = Config.options(section)
    for option in options:
        try:
            dict1[option] = Config.get(section, option)
            if dict1[option] == -1:
                DebugPrint("skip: %s" % option)
        except:
            print("exception on %s!" % option)
            dict1[option] = None
    return dict1
def end_session(child):
        print("Ending Session") ## ##Not attempting configs##
        child.sendline('exit')

first_start_time = time.time()

reader = csv.DictReader(open('RCDN.csv', 'rb')) ##specify csv to read
dic = []
for line in reader:
    dic.append(line)

results_dict = {}
length = len(dic) ##amount of devices to test/maintain (defualt is len(dic))
num_threads = 80 ##number of threads to run##
queue = Queue() ##maxsize = 0 ##
output = []
fails = [] ##ALL FAILS TO BE APPENDED TO THIS LIST IF NOT PRESENT ALREADY - EXCEPT SSH AND PING AS NO CONFIGURATION POSSIBLE##
pass_pings = []
fail_pings = []
pass_ssh = []
fail_ssh = []
pass_ldap = []
fail_ldap = []

ver_1 = '7.'
ver_2 = '8.0k'
ip_address = ""
hostname = ""
location = ""

from ConfigParser import SafeConfigParser
import ConfigParser
Config = ConfigParser.ConfigParser()
Config
Config.read('config.ini')
Config.sections() ##add subnet headers from config.ini ##
['default', 'global', 'richardson_new', '10.67.73.0/25']

print(' ################### STARTING PING THREAD  ################### ')
start_time = time.time()
count_2 = 0
while (count_2 < length):#len(dic)): ##While increment within length of imported IPs - PING ## ## This value changes the amount of strips to be attempted from the CSV ##  HERR
	results_dict["dic_"+str(count_2)]= {}
	output.append(dic[count_2]['ip_address'])
	results_dict["dic_"+str(count_2)]["ip_address"] = str(dic[count_2]['ip_address'])
        count_2 += 1
for i in range(num_threads): ## Specifies the maximum number of threads/workers to be called##
	worker = Thread(target=pinger, args=(i, queue))
	worker.setDaemon(True)
	worker.start()
for ip in output: ## Each IP in output list is added to the Pinger Queue ##
    queue.put(ip)
queue.join() ##Waits for all threads to finish before continuing ##

print(str(len(fail_pings))+'/'+str(len(dic))+' hosts failed PING test.')
print(fail_pings)
print('PAssed Pings: '+(str(len(pass_pings))))
print("--- PING took %s seconds ---" % (time.time() - start_time))

print(' ################### STARTING SSH THREAD ON (PINGABLE) '+str(len(pass_pings))+' HOSTS  ################### ')
start_time = time.time()
queue = Queue()
for i in range(num_threads):
	worker = Thread(target=ssh_test, args=(i, queue))
	worker.setDaemon(True)
	worker.start()
print('starting ssh queue')
for ip in pass_pings:
    queue.put(ip)
queue.join()

print(pass_ssh)
print(fail_ssh)
print(str(len(fail_ssh))+'/'+str(len(dic))+' hosts failed SSH test.')
print("--- SSH took %s seconds ---" % (time.time() - start_time))

print(' ################### STARTING LDAP THREAD ON (SSHABLE) '+str(len(pass_ssh))+' HOSTS  ################### ')
start_time = time.time()
queue = Queue()
for i in range(num_threads):
	worker = Thread(target=ldap_test, args=(i, queue))
	worker.setDaemon(True)
	worker.start()
print('starting ldap queue')
for ip in pass_ssh:
    queue.put(ip)
queue.join()

print(pass_ldap)
print(fail_ldap)
print(str(len(fail_ldap))+'/'+str(len(dic))+' hosts failed LDAP test.')
print("--- LDAP took %s seconds ---" % (time.time() - start_time))


print(' ################### GENERATING RESULTS  ################### ')
count_3 = 0

while (count_3 < len(results_dict)): ## Reads the pass/fail lists and adds a T/F statement to results_dict ##
	if results_dict["dic_"+str(count_3)]['ip_address'] in pass_pings:
		results_dict["dic_"+str(count_3)]["ping_status"] = 'TRUE'
	else: #results_dict["dic_"+str(count_3)]['ip_address'] in fail_pings:
		results_dict["dic_"+str(count_3)]["ping_status"] = 'FALSE'

    	location = dic[count_3]["location"]
    	results_dict["dic_"+str(count_3)]["location"] = location

	if results_dict["dic_"+str(count_3)]['ip_address'] in pass_ssh:
		results_dict["dic_"+str(count_3)]["ssh_status"] = 'TRUE'
	else: #results_dict["dic_"+str(count_3)]['ip_address'] in fail_ssh:
		results_dict["dic_"+str(count_3)]["ssh_status"] = 'FALSE'

    	if results_dict["dic_"+str(count_3)]['ip_address'] in pass_ldap:
		results_dict["dic_"+str(count_3)]["ldap_status"] = 'TRUE'
	else: #results_dict["dic_"+str(count_3)]['ip_address'] in fail_snmp:
		results_dict["dic_"+str(count_3)]["ldap_status"] = 'FALSE'
	count_3 += 1

total = str(len(dic))

print("--- ALL TESTS took %s seconds ---" % (time.time() - first_start_time))
print('--------- TOTALS --------- ')
ping_passed = str(len(pass_pings))
ping_failed = str(len(fail_pings))
print(ping_passed+'/'+total+' Hosts Reachable by PING ')
print('The hosts that failed PING Testing include:'+str(fail_pings))
ssh_passed = str(len(pass_ssh))
ssh_failed = str(len(fail_ssh))
print(ssh_passed+'/'+ping_passed+' hosts are reachable by SSH.')
print('The hosts that failed SSH Testing include:'+str(fail_ssh))
ldap_passed = str(len(pass_ldap))
ldap_failed = str(len(fail_ldap))
print(ldap_passed+'/'+ping_passed+' hosts have correct LDAP configurations.')
print('The hosts that failed LDAP testing include:'+str(fail_ldap))

if (long(len(fails)) > 0):
    snmp_auto_config()

print("Ping, SSH, LDAP checks have completed.")
