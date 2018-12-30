import pexpect
import logging
import pprint
import csv
import subprocess
import os
import sys
from pysnmp.hlapi import *
import pyCiscoSpark
import threading
from multiprocessing import Queue
import time
import re
import socket
import struct
from threading import Thread
from Queue import *
from netaddr import IPNetwork
import getpass, os, traceback
import glob
import optparse
from optparse import OptionParser

##Verbose disabled by default##
v = False
admin_change = False
ldap_change = False
##Command Line Options##
parser = OptionParser()
parser.add_option("-v", "--verbose", action="store_true", dest="verbose", help = "Display all possible debug output.")
parser.add_option("-a", "--admin", action="store_true", dest="admin_change", help = "Script will update admin credentials")
parser.add_option("-l", "--ldap", action="store_true", dest="ldap_change", help = "Script will update ldap credentials")

(options, args) = parser.parse_args()
v = options.verbose
if (options.admin_change is None) and (options.ldap_change is None):
    print("[ERROR]: Please select script mode. Use --help for command line arguments.")
    exit()
else:
    admin_change = options.admin_change
    ldap_change = options.ldap_change


def verbose_print(output):
    if (v is True):
        print(output)
def ConfigSectionMap(section): ##Function used for importing config.ini file variables ##
    dict1 = {}
    options = Config.options(section)
    for option in options:
        try:
            dict1[option] = Config.get(section, option)
            if dict1[option] == -1:
                Debugverbose_print("skip: %s" % option)
        except:
            verbose_print("exception on %s!" % option)
            dict1[option] = None
    return dict1
def ssh(i, q, user, password):
    while True:
        ip = q.get()
        verbose_print('Commencing SSH Session on '+ip)
        child = pexpect.spawn ('sshpass -p "'+password+'" ssh -vvvv -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss -oStrictHostKeyChecking=no '+user+'@'+ip)
        child.timeout=200
        i = child.expect([pexpect.TIMEOUT, 'Connection refused', pexpect.EOF, 'Smart CDU: ', 'Smart PDU: ', 'Switched CDU: '])
        #verbose_print(i)
        if i == 0:
            die(child, ip+': ERROR!\nSSH timed out. Here is what SSH said:')
        if i == 1:
            #die(child, ip+': ERROR!\nIncorrect password Here is what SSH said:')
            verbose_print("######## Incorrect Credentials - Attempting SSH using admin.cred passwords ########")
            child.close()
            count = 0
            while (count < len(old_admin_pass) and (i != 3 or 4)):
                verbose_print('SSH Attempt #'+str(count)+': "'+old_admin_pass[count]+'"')
                user = current_admin_user
                password = old_admin_pass[count]
                #print('starting new ssh')
                child = pexpect.spawn ('sshpass -p "'+password+'" ssh -vvvv -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss -oStrictHostKeyChecking=no '+user+'@'+ip)
                child.timeout=200
                i = child.expect([pexpect.TIMEOUT, 'Connection refused', pexpect.EOF, 'Smart CDU: ', 'Smart PDU: ', 'Switched CDU: '])
                #verbose_print(i)
                if i == 0:
                    die(child, ip+': ERROR!\nSSH timed out. Here is what SSH said:')
                elif i == 1:
                    verbose_print('EOF - Wrong Credentials')
                elif i == 2:
                    verbose_print('EOF - Wrong Credentials')
                elif i == 3:
                    verbose_print(ip+': SSH TRUE - Smart CDU')
                    prompt = "Smart CDU:"
                    child.sendline("version\r")
                    child.expect(prompt)
                    if ("7." in child.before):
                        version = 7
                    if ("8." in child.before):
                        version = 8
                    child.sendline("set email disabled\r")
                    child.expect(prompt)
                    if (ldap_change == True):
                        ldap_setup(child, prompt, version)
                    if (admin_change == True):
                        admin_update(child, prompt, version)
                        admin_change_ldap_failed.append(ip)
                    break
                elif i == 4:
                    verbose_print(ip+': SSH TRUE - Smart PDU')
                    child.sendline("version\r")
                    prompt = "Smart PDU: "
                    child.expect(prompt)
                    verbose_print("Disabling Email")
                    child.sendline("set email disabled\r")
                    if ("7." in child.before):
                        version = 7
                    if ("8." in child.before):
                        version = 8
                    child.expect(prompt)
                    if (ldap_change == True):
                        ldap_setup(child, prompt, version)
                    if (admin_change == True):
                        admin_update(child, prompt, version)
                        admin_change_ldap_failed.append(ip)
                    break
                elif i == 5:
                    verbose_print(ip+': SSH TRUE - Switched CDU')
                count += 1
            if (count >= len(old_admin_pass)):
                print('SUPERFAIL- ALL ATTEMPTS MADE TO LOGIN HAVE FAILED')
                super_fail.append(ip)
        elif i == 2:
            # die(child, ip+': ERROR!\nEOF - Here is what SSH said:')
            print("######## Incorrect Credentials - Attempting SSH using admin.cred passwords ########")
            child.close()
            count = 0
            while (count < len(old_admin_pass) and (i != 3 or 4)):
                verbose_print('SSH Attempt #'+str(count)+': "'+old_admin_pass[count]+'"')
                verbose_print('starting new ssh')
                child = pexpect.spawn ('sshpass -p "'+old_admin_pass[count]+'" ssh -vvvv -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss -oStrictHostKeyChecking=no '+current_admin_user+'@'+ip)
                child.timeout=200
                i = child.expect([pexpect.TIMEOUT, 'Connection refused', pexpect.EOF, 'Smart CDU: ', 'Smart PDU: ', 'Switched CDU: '])
                # verbose_print(i)
                if i == 0:
                    die(child, ip+': ERROR!\nSSH timed out. Here is what SSH said:')
                elif i == 1:
                    verbose_print('EOF - Wrong Credentials')
                elif i == 2:
                    verbose_print('EOF - Wrong Credentials')
                elif i == 3:
                    verbose_print(ip+': SSH TRUE - Smart CDU')
                    prompt = "Smart CDU:"
                    child.sendline("version\r")
                    child.expect(prompt)
                    if ("7." in child.before):
                        version = 7
                    if ("8." in child.before):
                        version = 8
                    child.sendline("set email disabled\r")
                    child.expect(prompt)
                    if (ldap_change == True):
                        ldap_setup(child, prompt, version)
                    if (admin_change == True):
                        print(ip + ": Failed LDAP login - Configuring LDAP - Admn Update will resume at end of script.")
                        ldap_setup(child, prompt, version)
                        admin_change_ldap_failed.append(ip)
                    break
                elif i == 4:
                    verbose_print(ip+': SSH TRUE - Smart PDU')
                    child.sendline("version\r")
                    prompt = "Smart PDU: "
                    child.expect(prompt)
                    verbose_print("Disabling Email")
                    child.sendline("set email disabled\r")
                    if ("7." in child.before):
                        version = 7
                    if ("8." in child.before):
                        version = 8
                    child.expect(prompt)
                    if (ldap_change == True):
                        ldap_setup(child, prompt, version)
                    if (admin_change == True):
                        print(ip + ": Failed LDAP login - Configuring LDAP - Admn Update will resume at end of script.")
                        ldap_setup(child, prompt, version)
                        admin_change_ldap_failed.append(ip)
                    break
                elif i == 5:
                    verbose_print(ip+': SSH TRUE - Switched CDU')
                count += 1
            if (count >= len(old_admin_pass)):
                print('SUPERFAIL - ALL ATTEMPTS MADE TO LOGIN HAVE FAILED')
                super_fail.append(ip)
        elif i == 3:
            verbose_print(ip+': SSH TRUE - Smart CDU')
            prompt = "Smart CDU:"
            child.sendline("version\r")
            child.expect(prompt)
            if ("7." in child.before):
                version = 7
            if ("8." in child.before):
                version = 8
            child.sendline("set email disabled\r")
            child.expect(prompt)
            if (ldap_change == True):
                ldap_setup(child, prompt, version)
            if (admin_change == True):
                admin_update(child, prompt, version)
        elif i == 4:
            verbose_print(ip+': SSH TRUE - Smart PDU')
            child.sendline("version\r")
            prompt = "Smart PDU: "
            child.expect(prompt)
            verbose_print("Disabling Email")
            child.sendline("set email disabled\r")
            if ("7." in child.before):
                version = 7
            if ("8." in child.before):
                version = 8
            child.expect(prompt)
            if (ldap_change == True):
                ldap_setup(child, prompt, version)
            if (admin_change == True):
                admin_update(child, prompt, version)
        elif i == 5:
            verbose_print(ip+': SSH TRUE - Switched CDU')
        verbose_print("Ending SSH Session")
        child.close()
        queue.task_done()
def admin_update(child, prompt, version):
    if (version == 7):
        verbose_print(" -------- Setting Admin Password -------- ")
        child.sendline('set user password\r')
        child.expect('Username:')
        child.sendline('admn\r')
        child.expect('Password:')
        child.sendline(current_admin_pass+'\r')
        child.expect('Verify Password:')
        child.sendline(current_admin_pass+'\r')
        child.expect(prompt)
        verbose_print(" -------- DONE -------- ")
        return
    if (version == 8):
        verbose_print(" -------- Setting Admin Password -------- ")
        child.sendline('set user password\r')
        child.expect('Local user:')
        child.sendline('admn\r')
        child.expect('Password:')
        child.sendline(current_admin_pass+'\r')
        child.expect('Verify password:')
        child.sendline(current_admin_pass+'\r')
        child.expect(prompt)
        verbose_print(" -------- DONE -------- ")
        return
def ldap_setup(child, prompt, version):
    if (version == 7):
        verbose_print('-------- Setting Version 7 LDAP -------- ')
        #Set LDAP
        verbose_print('-------- Setting LDAP -------- ')
        child.sendline ('set ldap enabled\r')
        child.expect ('Command successful')
        ##Set Primary Host
        verbose_print('   -------- Setting LDAP Primary Host -------- ')
        child.expect (prompt)
        child.sendline ('set ldap host1 '+ldap_host+'\r')
        # child.expect ('Host/IP')
        # child.sendline (ldap_host+'\r')
        child.expect ('Command successful')
    ##Set Port
        verbose_print('   -------- Setting LDAP Port -------- ')
        child.expect (prompt)
        child.sendline ('set ldap port\r')
        child.expect ('LDAP Port')
        child.sendline (ldap_port+'\r')
        child.expect ('Command successful')

        verbose_print('   -------- Setting LDAP Bind TLS -------- ')
        child.expect (prompt)
        child.sendline ('set ldap bind tls\r')
        child.expect ('Command successful')

        verbose_print('   -------- Setting LDAP Bind DN -------- ')
        child.expect (prompt)
        child.sendline ('set ldap binddn\r')
        child.expect ('Enter Search Bind DN')
        child.sendline (ldap_bind+'\r') ##Need Confirmation##
        child.expect ('Command successful')

        verbose_print('   -------- Setting LDAP BIND PW -------- ')
        child.expect (prompt)
        child.sendline ('set ldap bindpw\r')
        child.expect ('Search Bind Password')
        child.sendline (ldap_pass+'\r')
        child.expect ('Command successful')

        verbose_print('   -------- Setting LDAP Base DN -------- ')
        child.expect (prompt)
        child.sendline ('set ldap userbasedn\r')
        child.expect ('Enter User Search Base')
        child.sendline (ldap_base+'\r') ##Need Confirmation##
        child.expect ('Command successful')

        verbose_print('   -------- Setting LDAP User Filter -------- ')
        child.expect (prompt)
        child.sendline ('set ldap userfilter\r')
        child.expect (' ')
        child.sendline (ldap_filter+'\r')
        child.expect ('Command successful')
        #verbose_print(child.before)

        verbose_print('   -------- Setting LDAP Group Attribute -------- ')
        child.expect (prompt)
        child.sendline ('set ldap groupattr\r')
        child.expect (' ')
        child.sendline (ldap_group_attr+'\r')
        child.expect ('Command successful')

        verbose_print('   -------- Disabling LDAP Group Search -------- ')
        child.expect (prompt)
        child.sendline ('set ldap groupsearch disabled\r')
        child.expect ('Command successful')

        verbose_print('   -------- Creating LDAP Admin Group -------- ')
        child.expect (prompt)
        child.sendline ('create ldapgroup '+ldap_admin_group+'\r')
        m = child.expect (['Command successful', 'command failed'])
        if m == 1:
            verbose_print('Admin Group exists')

        verbose_print('   -------- Creating LDAP User Group -------- ')
        child.expect (prompt)
        child.sendline ('create ldapgroup '+ldap_user_group+'\r')
        m = child.expect (['Command successful', 'command failed'])
        if m == 1:
            verbose_print('User Group exists')

        verbose_print('   -------- Setting LDAP Admin Group -------- ')
        child.expect (prompt)
        child.sendline ('set ldapgroup access admin\r')
        child.expect ('Group Name: ')
        child.sendline (ldap_admin_group+'\r')
        child.expect ('Command successful')

        verbose_print('   -------- Setting LDAP User Group -------- ')
        child.expect (prompt)
        child.sendline ('set ldapgroup access user\r')
        child.expect ('Group Name: ')
        child.sendline (ldap_user_group+'\r')
        child.expect ('Command successful')

        verbose_print('   -------- Disabling LDAP Group Search -------- ')
        child.expect (prompt)
        child.sendline ('set ldap groupsearch disabled\r')
        child.expect ('Command successful')
    if (version == 8):
        verbose_print('-------- Setting Version 8 LDAP -------- ')
        #Set LDAP
        verbose_print('-------- Setting LDAP -------- ')
        child.sendline ('set access method ldaplocal\r')
        child.expect ('Command successful')
        ##Set Primary Host
        verbose_print('   -------- Setting LDAP Primary Host -------- ')
        child.expect (prompt)
        child.sendline ('set ldap primary '+ldap_host+'\r')
        # child.expect ('Host/IP')
        # child.sendline (ldap_host+'\r')
        child.expect ('Command successful')
    ##Set Port
        verbose_print('   -------- Setting LDAP Port -------- ')
        child.expect (prompt)
        child.sendline ('set ldap port '+ldap_port+'\r')
        # child.expect ('LDAP Port')
        # child.sendline (ldap_port+'\r')
        child.expect ('Command successful')

        verbose_print('   -------- Setting LDAP Bind TLS -------- ')
        child.expect (prompt)
        child.sendline ('set ldap bind tls\r')
        child.expect ('Command successful')

        verbose_print('   -------- Setting LDAP Bind DN -------- ')
        child.expect (prompt)
        child.sendline ('set ldap binddn\r')
        child.expect ('LDAP search bind DN')
        child.sendline (ldap_bind+'\r') ##Need Confirmation##
        child.expect ('Command successful')

        verbose_print('   -------- Setting LDAP BIND PW -------- ')
        child.expect (prompt)
        child.sendline ('set ldap bindpw\r')
        child.expect ('search bind password')
        child.sendline (ldap_pass+'\r')
        child.expect ('Command successful')

        verbose_print('   -------- Setting LDAP Base DN -------- ')
        child.expect (prompt)
        child.sendline ('set ldap userbasedn\r')
        child.expect ('user search base DN')
        child.sendline (ldap_base+'\r') ##Need Confirmation##
        child.expect ('Command successful')

        verbose_print('   -------- Setting LDAP User Filter -------- ')
        child.expect (prompt)
        child.sendline ('set ldap userfilter\r')
        child.expect ('user search filter')
        child.sendline (ldap_filter+'\r')
        child.expect ('Command successful')
        #verbose_print(child.before)

        verbose_print('   -------- Setting LDAP Group Attribute -------- ')
        child.expect (prompt)
        child.sendline ('set ldap groupattr\r')
        child.expect ('membership attribute')
        child.sendline (ldap_group_attr+'\r')
        child.expect ('Command successful')

        verbose_print('   -------- Creating LDAP Admin Group -------- ')
        child.expect (prompt)
        child.sendline ('create ldapgroup '+ldap_admin_group+'\r')
        m = child.expect (['Command successful', 'command failed', 'Invalid request'])
        if m == 1 or 2:
            verbose_print('User Group exists')

        verbose_print('   -------- Creating LDAP User Group -------- ')
        child.expect (prompt)
        child.sendline ('create ldapgroup '+ldap_user_group+'\r')
        m = child.expect (['Command successful', 'command failed', 'Invalid request'])
        if m == 1 or 2:
            verbose_print('User Group exists')

        verbose_print('   -------- Setting LDAP Admin Group -------- ')
        child.expect (prompt)
        child.sendline ('set ldapgroup access admin\r')
        child.expect ('LDAP group: ')
        child.sendline (ldap_admin_group+'\r')
        child.expect ('Command successful')

        verbose_print('   -------- Setting LDAP User Group -------- ')
        child.expect (prompt)
        child.sendline ('set ldapgroup access user\r')
        child.expect ('LDAP group: ')
        child.sendline (ldap_user_group+'\r')
        child.expect ('Command successful')

        verbose_print('   -------- Disabling LDAP Group Search -------- ')
        child.expect (prompt)
        child.sendline ('set ldap groupsearch disabled\r')
        child.expect ('Command successful')
    #child.expect (prompt)
    return
def spark_notification(message):
                with open('at.txt', 'r') as myfile: ##at.txt = bot access token file ##
                	at=myfile.read().replace('\n', '')

                def search (values, searchFor):
                    for k in values["items"]:
                        #verbose_print (k["title"])
                        if (k["title"] == searchFor) : return k["id"]
                    return None

                accesstoken="Bearer "+at

                rooms_dict=pyCiscoSpark.get_rooms(accesstoken)

                roomid = search (rooms_dict, "PDU Credential Updates")

                pyCiscoSpark.post_message(accesstoken,roomid,message)
def die(child, errstr): ##Function called when SSH error is encountered ##
    verbose_print(errstr)
    verbose_print(child.before)
    verbose_print(child.after)
    # child.terminate()
    verbose_print('PROCESS KILLED')
    queue.task_done()
    child.close()
    verbose_print('PROCESS CLOSED')
    exit(1)

##Reads latest scan file##
list_of_files = glob.glob('strip_scans/strips_*.csv') # * means all if need specific format then *.csv
latest_file = max(list_of_files, key=os.path.getctime)
verbose_print('Latest scan .csv is: ' + latest_file)
reader = csv.DictReader(open(latest_file, 'rb')) ##specify csv to read
dic = []
for line in reader:
    dic.append(line)
length = 1 #len(dic) ##amount of devices to run over##
num_threads = 1 ##number of threads to run##
queue = Queue() ##maxsize = 0 ##
version = 0
current_admin_user = "admn"
current_admin_pass = ""
current_admin_pass_valid = ""
admin_user = "admn"
ldap_user = ""
ldap_pass = ""
failed_list = []
output = []
old_admin_pass = []
super_fail = []
admin_change_ldap_failed = []
results_dict = {}

##Import Variables from Config.ini##
from ConfigParser import SafeConfigParser
import ConfigParser
Config = ConfigParser.ConfigParser()
Config
Config.read('config.ini')
Config.sections() ##adds specific subnet headers from config.ini ##
"global"
ldap_host = ConfigSectionMap('global')['ldap_host']
ldap_port = ConfigSectionMap('global')['ldap_port']
ldap_bind = ConfigSectionMap('global')['ldap_bind']
#ldap_pass = ConfigSectionMap('global')['ldap_pass']
ldap_base = ConfigSectionMap('global')['ldap_base']
ldap_filter = ConfigSectionMap('global')['ldap_filter']
ldap_group_attr = ConfigSectionMap('global')['ldap_group_attr']
ldap_admin_group = ConfigSectionMap('global')['ldap_admin_group']
ldap_user_group = ConfigSectionMap('global')['ldap_user_group']

##Read ldap.cred into variables##
f = open("ldap.cred", "r")
f = f.read().split('\n')
ldap_user = f[0]
ldap_pass = f[1]

##Reads IP addresses from results.csv into list for threaded functions to read##
count = 0
while (count < length): ##While less than ip amount, increment within length of imported IPs - PING ##
    results_dict["dic_"+str(count)]= {}
    output.append(dic[count]['ip_address'])
    results_dict["dic_"+str(count)]["ip_address"] = str(dic[count]['ip_address'])
    count += 1

##LDAP Credential Change##
if ldap_change == True:
    print("LDAP Update has been selected. \n Admin user will be used to update LDAP credentials. ")
    current_admin_pass = raw_input("Enter Current Admin Password:  ")
    current_admin_pass_valid = raw_input("Confirm Current Admin Password:  ")
    ldap_pass = raw_input("Enter New LDAP Password:  ")
    ldap_pass_valid = raw_input("Confirm LDAP Password Password:  ")

    if (current_admin_pass <> current_admin_pass_valid):
        print("[ERROR]: Admin Passwords do not match")
        exit()
    if (ldap_pass <> ldap_pass_valid):
        print("[ERROR]: LDAP Passwords do not match")
        exit()
    else:
        print("Starting LDAP Credential Update. Setting '"+ldap_pass+"' as new LDAP Password.")

        old_admin_pass.append(current_admin_pass)
        old_admin_pass.append("admn")
        ##Read admin.cred old passwords into list##
        f = open("admin.cred", "r")
        f = f.read().split('\n')
        count = 0
        while count < (len(f)-1):
            old_admin_pass.append(f[count])
            count += 1

        queue = Queue()
        for i in range(num_threads):
        	worker = Thread(target=ssh, args=(i, queue, current_admin_user, current_admin_pass))
        	worker.setDaemon(True)
        	worker.start()
        verbose_print('starting ssh queue')
        for ip in output:
            queue.put(ip)

        verbose_print('waiting for queue')
        queue.join()
##Admin Credential Change##
elif admin_change == True:
    print("Admin Update has been selected. \n LDAP user "+ldap_user+" will be used to update the Admin user password.")
    current_admin_pass = raw_input("Enter new Admin Password:  ")
    current_admin_pass_valid = raw_input("Confirm new Admin Password:  ")

    if (current_admin_pass <> current_admin_pass_valid):
        print("[ERROR]: Passwords do not match")
        exit()
    else:
        print("Starting Admin Credential Update. Setting '"+current_admin_pass+"' as Admin Password.")

        old_admin_pass.append(current_admin_pass)
        old_admin_pass.append("admn")
        ##Read admin.cred old passwords into list##
        f = open("admin.cred", "r")
        f = f.read().split('\n')
        count = 0
        while count < (len(f)-1):
            old_admin_pass.append(f[count])
            count += 1

        queue = Queue()
        for i in range(num_threads):
        	worker = Thread(target=ssh, args=(i, queue, ldap_user, ldap_pass))
        	worker.setDaemon(True)
        	worker.start()
        verbose_print('starting ssh queue')
        for ip in output:
            queue.put(ip)

        verbose_print('waiting for queue')
        queue.join()



## If there are hosts that attempted to ssh using LDAP credentials and failed - the LDAP function will be run over them ##
admin_change = False
ldap_change = False
if (len(admin_change_ldap_failed) > 0):
    spark_notification("LDAP LOGIN FAILED ON HOSTS DURING ADMIN PASSWORD UPDATE. LDAP AND ADMIN PASSWORDS HAVE BEEN UPDATED. \n" + str(admin_change_ldap_failed))
    admin_change = True
    print("Starting Admin Update SSH sessions with hosts that failed SSH with LDAP credentials.")
    print(admin_change_ldap_failed)
    print("Starting Admin Credential Update. Setting '"+current_admin_pass+"' as Admin Password.")

    queue = Queue()
    for i in range(num_threads):
        worker = Thread(target=ssh, args=(i, queue, ldap_user, ldap_pass))
        worker.setDaemon(True)
        worker.start()
    verbose_print('starting ssh queue')
    for ip in admin_change_ldap_failed:
        queue.put(ip)

    verbose_print('waiting for queue')
    queue.join()

if (len(super_fail) > 0):
    spark_notification("CRITICAL: ALL SSH ACCESS FAILED (ADMIN/LDAP) ON : \n"+str(super_fail))

print(" ########## Finished configurations. ##########")
