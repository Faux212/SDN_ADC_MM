import pexpect
import logging
import pprint
import csv
import xlsxwriter
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
single_instance = False
single_region = False
##Command Line Options##
parser = OptionParser()
parser.add_option("-v", "--verbose", action="store_true", dest="verbose", help = "Display all possible debug output.")
parser.add_option("-r", "--region", action="store_true", dest="single_region", help = "Runs script over single user-specified region (This depends on correct hostname-location configuration.)")
parser.add_option("-i", "--ip", dest="ip", help = "Runs script over single IP Address.")
parser.add_option("-s", "--subnet", dest="subnet", help = "Specifies IP subnet.")
parser.add_option("-t", "--test", action="store_false", dest="auto_config", help = "Only testing functions of script will run. ")

subnets = []
with open('subnet_lib.txt', 'r') as myfile: ##at.txt = bot access token file ##
    subnets=myfile.read().split('\n')

(options, args) = parser.parse_args()
auto_config = options.auto_config
print(auto_config)
v = options.verbose
single_region = options.single_region
if (options.ip is not None):
    if (options.subnet is not None):
        if (options.subnet in subnets):
            single_ip = options.ip
            single_subnet = options.subnet
            single_instance = True
            print('Running script over single host: ' + single_ip + ' Subnet: ' + single_subnet)
        else:
            print('ERROR: Chosen Subnet not found in subnet_lib.')
    else:
        print('ERROR: IP requires subnet (-s SUBNET) to be specified.')
        exit()

def ping_error(error_ipaddress): ##Sends error notifications to Spark room##
    with open('at.txt', 'r') as myfile: ##at.txt = bot access token file ##
        at=myfile.read().replace('\n', '')

    def search (values, searchFor):
        for k in values["items"]:
            #verbose_print (k["title"])
            if (k["title"] == searchFor) : return k["id"]
        return None

    accesstoken="Bearer "+at

    rooms_dict=pyCiscoSpark.get_rooms(accesstoken)

    roomid = search (rooms_dict, "PDU Spamalot")

    pyCiscoSpark.post_message(accesstoken,roomid,"PING FAILED ON "+error_ipaddress)
def ssh_error(error_ipaddress): ##Sends error notifications to Spark room##
    with open('at.txt', 'r') as myfile: ##at.txt = bot access token file ##
        at=myfile.read().replace('\n', '')

    def search (values, searchFor):
        for k in values["items"]:
            #verbose_print (k["title"])
            if (k["title"] == searchFor) : return k["id"]
        return None

    accesstoken="Bearer "+at

    rooms_dict=pyCiscoSpark.get_rooms(accesstoken)

    roomid = search (rooms_dict, "PDU Spamalot")

    pyCiscoSpark.post_message(accesstoken,roomid,"SSH FAILED ON "+error_ipaddress)
def snmp_error(error_ipaddress): ##Sends error notifications to Spark room##

        with open('at.txt', 'r') as myfile: ##at.txt = bot access token file ##
            at=myfile.read().replace('\n', '')

        def search (values, searchFor):
            for k in values["items"]:
                #verbose_print (k["title"])
                if (k["title"] == searchFor) : return k["id"]
            return None

        accesstoken="Bearer "+at

        rooms_dict=pyCiscoSpark.get_rooms(accesstoken)

        roomid = search (rooms_dict, "PDU Spamalot")

        pyCiscoSpark.post_message(accesstoken,roomid,"SNMP FAILED ON "+error_ipaddress)
def ldap_error(message):

            with open('at.txt', 'r') as myfile: ##at.txt = bot access token file ##
                at=myfile.read().replace('\n', '')

            def search (values, searchFor):
                for k in values["items"]:
                    #verbose_print (k["title"])
                    if (k["title"] == searchFor) : return k["id"]
                return None

            accesstoken="Bearer "+at

            rooms_dict=pyCiscoSpark.get_rooms(accesstoken)

            roomid = search (rooms_dict, "PDU Spamalot")

            pyCiscoSpark.post_message(accesstoken,roomid,"LDAP ACCESS FAILED ON "+message)
def default_password_detected(error_ipaddress):
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

            pyCiscoSpark.post_message(accesstoken,roomid,"DEFAULT PASSWORD DETECTED ON "+error_ipaddress+"\n PLEASE RUN 'update_credentials.py' TO UPDATE ADMIN PASSWORDS.")
def spark_post_results(results_xlsx):
    with open('at.txt', 'r') as myfile: ##at.txt = bot access token file ##
        at=myfile.read().replace('\n', '')

    def search (values, searchFor):
        for k in values["items"]:
            #verbose_print (k["title"])
            if (k["title"] == searchFor) : return k["id"]
        return None

    accesstoken="Bearer "+at

    rooms_dict=pyCiscoSpark.get_rooms(accesstoken)

    roomid = search (rooms_dict, "STLD Powerstrips")

    #verbose_print (roomid)

    if (len(fail_pings) > 0):
        pyCiscoSpark.post_message(accesstoken,roomid,"PING FAILED ON "+ping_failed+"/"+total+" HOSTS")
        a = 1
    else:
        pyCiscoSpark.post_message(accesstoken,roomid,"NO PING FAILURES DETECTED ON "+total+" HOSTS")
        a = 0
    if (len(fail_ssh) > 0):
        b = 1
        pyCiscoSpark.post_message(accesstoken,roomid,"SSH FAILED ON "+ssh_failed+"/"+ping_passed+" HOSTS")
    else:
        b = 0
        pyCiscoSpark.post_message(accesstoken,roomid,"NO SSH FAILURES DETECTED ON "+ping_passed+" HOSTS")
    if (len(fail_snmp) > 0):
        c = 1
        pyCiscoSpark.post_message(accesstoken,roomid,"SNMP FAILED ON "+snmp_failed+"/"+ping_passed+" HOSTS")
    else:
        c = 0
        pyCiscoSpark.post_message(accesstoken,roomid,"NO SNMP FAILURES DETECTED ON "+ping_passed+" HOSTS")

    if (len(fail_ldap) > 0):
        d = 1
        pyCiscoSpark.post_message(accesstoken,roomid,"LDAP FAILED ON "+ldap_failed+"/"+ping_passed+" HOSTS")
    else:
        d = 0
        pyCiscoSpark.post_message(accesstoken,roomid,"NO LDAP FAILURES DETECTED ON "+ping_passed+" HOSTS")

    if (len(fail_smtp) > 0):
        e = 1
        pyCiscoSpark.post_message(accesstoken,roomid,"SMTP FAILED ON "+smtp_failed+"/"+ssh_passed+" SSH-ABLE HOSTS \n They are: \n" + str(fail_smtp))
    else:
        e = 0
        pyCiscoSpark.post_message(accesstoken,roomid,"NO SMTP FAILURES DETECTED ON "+ssh_passed+" HOSTS")
    resp_dict = pyCiscoSpark.post_localfile(accesstoken,roomid,results_xlsx)#, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet') ##Post test results to Spark Room##
    # if (a + b + c == 0):
    #     pyCiscoSpark.post_localfile(accesstoken,roomid,"allgood.gif")
    # else:
    #     pyCiscoSpark.post_localfile(accesstoken,roomid,"warning.gif") ##Sends results to STLD Powerstrips Spark Room##

    if (len(fails) > 0):
        pyCiscoSpark.post_message(accesstoken,roomid,"Failures were detected - automatic configuration started.")
    else:
        pyCiscoSpark.post_message(accesstoken,roomid,"No Failures were detected.")
def spark_post_resultsii():
    with open('at.txt', 'r') as myfile: ##at.txt = bot access token file ##
        at=myfile.read().replace('\n', '')

    def search (values, searchFor):
        for k in values["items"]:
            #verbose_print (k["title"])
            if (k["title"] == searchFor) : return k["id"]
        return None

    accesstoken="Bearer "+at

    rooms_dict=pyCiscoSpark.get_rooms(accesstoken)

    roomid = search (rooms_dict, "STLD Powerstrips")

    #verbose_print (roomid)
    # if (len(fail_snmp) > 0):
    #     c = 1
    #     pyCiscoSpark.post_message(accesstoken,roomid,"SNMP FAILED AUTO-CONFIGURATION ON "+str(len(fail_snmp))+"/"+str(len(second_fail_snmp))+" HOSTS \n They are: "+str(fail_snmp))
def spark_config_success():
    with open('at.txt', 'r') as myfile: ##at.txt = bot access token file ##
        at=myfile.read().replace('\n', '')

    def search (values, searchFor):
        for k in values["items"]:
            #verbose_print (k["title"])
            if (k["title"] == searchFor) : return k["id"]
        return None

    accesstoken="Bearer "+at

    rooms_dict=pyCiscoSpark.get_rooms(accesstoken)

    roomid = search (rooms_dict, "STLD Powerstrips")

    pyCiscoSpark.post_message(accesstoken,roomid,"Automatic Configuration on "+str(len(fails))+" hosts has been completed without script-error")
def set_snmp_enabled(): ##SSH into target devices and enables SNMP before immediately rebooting the device##
    count_5 = 0
    print('################### ENABLING SNMPv3 ON '+ str(len(fail_snmp)) + ' HOSTS ######################')
    while (count_5 < len(fail_snmp)):
        verbose_print(count_5)
        snmp_ip_address = fail_snmp[count_5]
        if snmp_ip_address in fail_ssh or old_admin_ssh:
            verbose_print(snmp_ip_address + ': failed the ssh check - no auto configuration attempted')
        else:
            count_2 = 0
            while (count_2 < len(dic)):
                if "'"+snmp_ip_address+"'" in str(dic[count_2]):
                    subnet = dic[count_2]["subnet"]
                    #hostname = dic[count_2]["hostname"]
                    location = dic[count_2]["location"]
                    ## variables pulled from config.ini file ##
                    snmp_v3_rw_user = ConfigSectionMap(subnet)['snmpv3rwuser']
                    snmp_v3_rw_passw = ConfigSectionMap(subnet)['snmpv3rwauthpass']
                    snmp_v3_rw_privpassw = ConfigSectionMap(subnet)['snmpv3rwprivpass']
                    snmp_v3_ro_user = ConfigSectionMap(subnet)['snmpv3rouser']
                    snmp_v3_ro_passw = ConfigSectionMap(subnet)['snmpv3roauthpass']
                    snmp_v3_ro_privpassw = ConfigSectionMap(subnet)['snmpv3roprivpass']
                    dns_1 = ConfigSectionMap(subnet)['dns1']
                    dns_2 = ConfigSectionMap(subnet)['dns2']
                    verifier = ConfigSectionMap(subnet)['verifier']
                count_2 += 1
            verbose_print("---------- Setting SNMPv3 Enabled ---------- ") ##Could be implemented earlier to avoid wait times - but that would require prompting Y/N per device
            verbose_print('# Starting SSH session with Host '+snmp_ip_address+' #')
            child = pexpect.spawn ('sshpass -p "'+ldap_pass+'" ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss -oStrictHostKeyChecking=no '+ldap_user+'@'+snmp_ip_address)
            child.timeout=300

            verbose_print(snmp_ip_address+': Verifier = '+verifier)

            j = child.expect (['Smart CDU: ', 'Smart PDU: ', pexpect.TIMEOUT, 'Connection refused', pexpect.EOF])
            verbose_print(child.after)
            verbose_print("j = "+str(j))
            if j == 0:
                verbose_print('####### SSH Connection Success #######')

                verbose_print('-------- Setting Email Disabled -------- ')
                child.sendline ('set email disabled\r')
                child.expect ('Smart CDU:')

                #Set SNMPv2 Disabled
                verbose_print('-------- Setting SNMPv2 Disabled -------- ')
                child.sendline ('set snmp v2 disabled\r')
                child.expect ('Smart CDU:')

                #Set SNMPv3 Enabled
                verbose_print('-------- Setting SNMPv3 Enabled -------- ')
                child.sendline ('set snmp v3 enabled\r')
                child.expect ('Smart CDU:')

                verbose_print(' -------- Restarting PDU -------- ')
                child.sendline ('restart\r')
                child.expect (': ')
                child.sendline ('Yes\r')
                child.sendline ('Yes\r')

            if j == 1:
                verbose_print('####### SSH Connection Success #######')

                verbose_print('-------- Setting Email Disabled -------- ')
                child.sendline ('set email disabled\r')
                child.expect ('Smart PDU:')

                #Set SNMPv2 Disabled
                verbose_print('-------- Setting SNMPv2 Disabled -------- ')
                child.sendline ('set snmp v2 disabled\r')
                child.expect ('Smart PDU:')

                #Set SNMPv3 Enabled
                verbose_print('-------- Setting SNMPv3 Enabled -------- ')
                child.sendline ('set snmp v3 enabled\r')
                child.expect ('Smart PDU:')

                verbose_print(' -------- Restarting PDU -------- ')
                child.sendline ('restart\r')
                child.expect (': ')
                child.sendline ('Yes\r')
                child.sendline ('Yes\r')

 #            else:
 #               die(child, 'ERROR')
        count_5 += 1


    if len(fail_snmp) != len(fail_ssh):
        verbose_print('Waiting 200 seconds for reboot...') ##A sleep timer that waits long enough for any newly enabled strip to reboot ##
        for i in xrange(200,0,-1):
            time.sleep(1)
            # sys.stdout.write('\r')
            # # the exact output you're looking for:
            # sys.stdout.write("[%-20s] %d%%" % ('='*i, 5*i))
            # sys.stdout.flush()
            sys.stdout.write(str(i)+' ')
            sys.stdout.flush()
    else:
        verbose_print('All hosts with SNMP connectivity issues are also not able to communicate via SSH')
def auto_config_ssh(): ##SSH into target devices to configure SNMP ##
    count_1 = 0
    # for ip in fails:
    #     if (ip in fail_ssh):
    #         verbose_print(ip + "failed the ssh check - no auto configuration will be attempted")
    #     else:
    #         temp_fails.append(ip)
    # fails = temp_fails
    print('################### STARTING AUTO-CONFIGURATION ON '+ str(len(fails)) + ' HOSTS ######################')
    while (count_1 < len(fails)):
        #verbose_print(count_1)
        #verbose_print(len(fails))
        ip_address = fails[count_1]
        if ip_address in fail_ssh or old_admin_ssh:
            verbose_print(ip_address + ' failed the ssh check - no auto configuration attempted')
        else:
            verbose_print('# Starting SSH session with Host '+str(count_1+1)+': '+ip_address+' #')
            child = pexpect.spawn ('sshpass -p "'+ldap_pass+'" ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss -oStrictHostKeyChecking=no '+ldap_user+'@'+ip_address)
            child.timeout=500
            i = child.expect([pexpect.TIMEOUT, 'Permission denied', pexpect.EOF, 'Smart CDU: ', 'Smart PDU: '])
            if i == 0:
                die(child, 'ERROR!\nSSH timed out. Here is what SSH said:')
            elif i == 1:
                die(child, 'ERROR!\nIncorrect password Here is what SSH said:')
            elif i == 2:
                verbose_print(child.before)
            elif i == 3:
                verbose_print('####### SSH Connection Success #######')

                verbose_print('-------- Setting Email Disabled -------- ')
                child.sendline ('set email disabled\r')
                child.expect ('Smart CDU:')

                verbose_print('-------- Checking Firmware Version -------- ')
                child.sendline ('version\r')
                child.expect ('Smart CDU:')
                new = child.before
                #verbose_print(new)
                if ('Version 7.' in new):
                    verbose_print('v.7 detected.')
                if ('Version 8.' in new):
                    verbose_print('v.8 detected.')
                if ('Version 6.' in new):
                    verbose_print('v.6 detected')
                #verbose_print(new)

                config_script(child, new, i, ip_address)
            elif i == 4:
                verbose_print('####### SSH Connection Success #######')

                verbose_print('-------- Setting Email Disabled -------- ')
                child.sendline ('set email disabled\r')
                child.expect ('Smart PDU:')

                verbose_print('-------- Checking Firmware Version -------- ')
                child.sendline ('version\r')
                child.expect ('Smart PDU:')
                new = child.before
                #verbose_print(new)
                if ('Version 7.' in new):
                    verbose_print('v.7 detected.')
                if ('Version 8.' in new):
                    verbose_print('v.8 detected.')
                if ('Version 6.' in new):
                    verbose_print('v.6 detected')
                #verbose_print(new)
                config_script(child, new, i, ip_address)

            if ('Restart required' in child.before):
                verbose_print(' -------- RESTART REQUIRED ON STRIP '+ip_address+': Restarting PDU -------- ')
                child.sendline ('restart\r')
                child.expect (': ')
                child.sendline ('Yes\r')
                child.sendline ('Yes\r')

            #child.sendline ('exit\r')
            end_session(child)

        count_1 = count_1 + 1
    spark_config_success()
def config_script(child, new, i, ip_address):
    count_2 = 0
    while (count_2 < len(dic)):
        if "'"+ip_address+"'" in str(dic[count_2]):
            subnet = dic[count_2]["subnet"]
            #hostname = dic[count_2]["hostname"]
            location = dic[count_2]["location"]
            ## variables pulled from config.ini file ##
            snmp_v3_rw_user = ConfigSectionMap(subnet)['snmpv3rwuser']
            snmp_v3_rw_passw = ConfigSectionMap(subnet)['snmpv3rwauthpass']
            snmp_v3_rw_privpassw = ConfigSectionMap(subnet)['snmpv3rwprivpass']
            snmp_v3_ro_user = ConfigSectionMap(subnet)['snmpv3rouser']
            snmp_v3_ro_passw = ConfigSectionMap(subnet)['snmpv3roauthpass']
            snmp_v3_ro_privpassw = ConfigSectionMap(subnet)['snmpv3roprivpass']
            smtp_host = ConfigSectionMap(subnet)['smtphost']
            smtp_1 = ConfigSectionMap(subnet)['smtp1']
            smtp_2 = ConfigSectionMap(subnet)['smtp2']
            dns_1 = ConfigSectionMap(subnet)['dns1']
            dns_2 = ConfigSectionMap(subnet)['dns2']
            ver_1 = ConfigSectionMap(subnet)['ver_1']
            ver_2 = ConfigSectionMap(subnet)['ver_2']
            ldap_host = ConfigSectionMap('global')['ldap_host']
            ldap_port = ConfigSectionMap('global')['ldap_port']
            ldap_bind = ConfigSectionMap('global')['ldap_bind']
            #ldap_pass = ConfigSectionMap('global')['ldap_pass']
            ldap_base = ConfigSectionMap('global')['ldap_base']
            ldap_filter = ConfigSectionMap('global')['ldap_filter']
            ldap_group_attr = ConfigSectionMap('global')['ldap_group_attr']
            ldap_admin_group = ConfigSectionMap('global')['ldap_admin_group']
            ldap_user_group = ConfigSectionMap('global')['ldap_user_group']
            verifier = ConfigSectionMap(subnet)['verifier']
        count_2 += 1
    verbose_print('Verifier is ' + verifier)
    if (i == 3):
        if (ip_address in fail_snmp):
            if (ver_1 or 'Version 6.' in new):
                #Set SNMPv3
                verbose_print('-------- Setting '+ver_1+' SNMPv3 -------- ')
                ## SNMPv3 Read Write
                child.sendline ('set snmp v3 rwusername \r')
                child.expect ('Username: ')
                child.sendline (snmp_v3_rw_user+'\r')
                #verbose_print(child.before)
                child.expect ('Command successful')

                verbose_print('   -------- Setting SNMPv3 RW Authentication Type -------- ')
                child.sendline ('set snmp v3 rwauthtype\r') ##Not on new version - new version = rwauth ##
                child.expect ('NONE or MD5: ')
                child.sendline ('md5\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting SNMPv3 RW Authentication Password -------- ')
                child.expect ('Smart CDU:')
                child.sendline ('set snmp v3 rwauthpass \r')
                child.expect ('Password: ') ##not so sure about the following##
                child.sendline (snmp_v3_rw_passw+'\r')
                child.expect ('Verify Password: ') ##not so sure about the following##
                child.sendline (snmp_v3_rw_passw+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting SNMPv3 RW Privelige Type -------- ')
                child.expect ('Smart CDU:')
                child.sendline ('set snmp v3 rwprivtype\r') ## not on new verson ##
                child.expect ('NONE or DES: ')
                child.sendline ('des\r')
                #verbose_print(child.before)
                child.expect ('Command successful')

                verbose_print('   -------- Setting SNMPv3 RW Privelige Password -------- ')
                child.expect ('Smart CDU:')
                child.sendline ('set snmp v3 rwprivpass \r')
                child.expect ('Password: ') ##not so sure about the following##
                child.sendline (snmp_v3_rw_privpassw+'\r')
                child.expect ('Verify Password: ') ##not so sure about the following##
                child.sendline (snmp_v3_rw_privpassw+'\r')
                child.expect ('Command successful')

                ## SNMPv3 Read Only
                verbose_print(' -------- Setting SNMPv3 RO -------- ')
                child.expect ('Smart CDU:')
                child.sendline ('set snmp v3 rousername \r')
                child.expect ('Username: ')
                child.sendline (snmp_v3_ro_user+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting SNMPv3 RO Authentication Type -------- ')
                child.expect ('Smart CDU:')
                child.sendline ('set snmp v3 roauthtype\r') ##Not on new version - new version = roauth ##
                child.expect ('NONE or MD5: ')
                child.sendline ('md5\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting SNMPv3 RO Authentication Password -------- ')
                child.expect ('Smart CDU:')
                child.sendline ('set snmp v3 roauthpass \r')
                child.expect ('Password: ') ##not so sure about the following##
                child.sendline (snmp_v3_ro_passw+'\r')
                child.expect ('Verify Password: ') ##not so sure about the following##
                child.sendline (snmp_v3_ro_passw+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting SNMPv3 RO Privelige Type -------- ')
                child.expect ('Smart CDU:')
                child.sendline ('set snmp v3 roprivtype\r') ## not on new verson ##
                child.expect ('NONE or DES: ')
                child.sendline ('des\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting SNMPv3 RO Privelige Password -------- ')
                child.expect ('Smart CDU:')
                child.sendline ('set snmp v3 roprivpass \r')
                child.expect ('Password: ') ##not so sure about the following##
                child.sendline (snmp_v3_ro_privpassw+'\r')
                child.expect ('Verify Password: ') ##not so sure about the following##
                child.sendline (snmp_v3_ro_privpassw+'\r')
                child.expect ('Command successful')

            if (ver_2 in new):
                #Set SNMPv3
                verbose_print('-------- Setting '+ver_2+' SNMPv3 -------- ')

                ## SNMPv3 Read Write
                verbose_print(' -------- Setting SNMPv3 RW -------- ')
                child.sendline ('set snmp v3 rwusername \r')
                child.expect (':')
                child.sendline (snmp_v3_rw_user+'\r')
                #verbose_print(child.before)
                child.expect ('Command successful')

                verbose_print('   -------- Setting SNMPv3 RW Authentication Type -------- ')
                child.sendline ('set snmp v3 rwauth md5des\r') ##Not on new version - new version = rwauth ##
                child.expect ('Command successful')

                verbose_print('   -------- Setting SNMPv3 RW Authentication Password -------- ')
                child.expect ('Smart CDU:')
                child.sendline ('set snmp v3 rwauthpass \r')
                child.expect (']: ') ##not so sure about the following##
                child.sendline (snmp_v3_rw_passw+'\r')

                # verbose_print('4')
                # child.expect (': ') ##not so sure about the following##
                # verbose_print('5')
                # child.sendline (snmp_v3_rw_passw+'\r')
                # verbose_print('6')
                child.expect ('Command successful')

                verbose_print('   -------- Setting SNMPv3 RW Privelige Password -------- ')
                child.expect ('Smart CDU:')
                child.sendline ('set snmp v3 rwprivpass \r')
                child.expect (':')
                child.sendline (snmp_v3_rw_passw+'\r')
                child.expect ('Command successful')

                ## SNMPv3 Read Only
                verbose_print(' -------- Setting SNMPv3 RO -------- ')
                child.expect ('Smart CDU:')
                child.sendline ('set snmp v3 rousername \r')
                child.expect (': ')
                child.sendline (snmp_v3_ro_user+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting SNMPv3 RO Authentication Type -------- ')
                child.expect ('Smart CDU:')
                child.sendline ('set snmp v3 roauth md5des\r') ##Not on new version - new version = roauth ##

                child.expect ('Command successful')

                verbose_print('   -------- Setting SNMPv3 RO Authentication Password -------- ')
                child.expect ('Smart CDU:')
                child.sendline ('set snmp v3 roauthpass \r')
                child.expect (': ') ##not so sure about the following##
                child.sendline (snmp_v3_ro_passw+'\r')
                # child.expect (': ') ##not so sure about the following##
                # child.sendline (snmp_v3_ro_passw+'\r')
                child.expect ('Command successful')

                # verbose_print('   -------- Setting SNMPv3 RO Privelige Type -------- ')
                # child.expect ('Smart CDU:')
                # child.sendline ('set snmp v3 roprivtype\r') ## not on new verson ##
                # child.expect ('NONE or DES: ')
                # child.sendline ('des\r')
                # child.expect ('Command successful')

                verbose_print('   -------- Setting SNMPv3 RO Privelige Password -------- ')
                child.expect ('Smart CDU:')
                child.sendline ('set snmp v3 roprivpass \r')
                child.expect (': ') ##not so sure about the following##
                child.sendline (snmp_v3_ro_privpassw+'\r')
                # child.expect (': ') ##not so sure about the following##
                # child.sendline (snmp_v3_ro_privpassw+'\r')
                child.expect ('Command successful')

        if (ip_address in fail_dns):
            if ('6.0' or ver_1 in new):
                verbose_print('-------- Setting DNS '+ver_1+' -------- ')
                verbose_print('   -------- Setting DNS Primary -------- ')
                child.sendline ('set dns1 '+dns_1+'\r')
                child.expect ('Smart CDU:')
                verbose_print('   -------- Setting DNS Secondary -------- ')
                child.sendline ('set dns2 '+dns_2+'\r')
                child.expect ('Smart CDU:')

            if (ver_2 in new):
                verbose_print('-------- Setting DNS '+ver_2+' -------- ')
                verbose_print('   -------- Setting DNS Primary -------- ')
                child.sendline ('set dns primary '+dns_1+'\r')
                child.expect ('Smart CDU:')
                verbose_print('   -------- Setting DNS Secondary -------- ')
                child.sendline ('set dns secondary '+dns_2+'\r')
                child.expect ('Smart CDU:')

        if (ip_address in fail_smtp):
            if (ver_1 or 'Version 6.' in new):
                verbose_print('-------- Setting SMTP '+ver_1+' -------- ')
                verbose_print('   -------- Setting SMTP Host -------- ')
                child.sendline ('set email smtp host\r')
                child.expect ('Host/IP')
                child.sendline (smtp_host+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting SMTP Primary Address -------- ')
                child.expect ('Smart CDU:')
                child.sendline ('set email primaryto\r')
                child.expect ('email address:')
                child.sendline (smtp_1+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting SMTP Secondary Address -------- ')
                child.expect ('Smart CDU:')
                child.sendline ('set email secondaryto\r')
                child.expect ('email address:')
                child.sendline (smtp_2+'\r')
                child.expect ('Command successful')
                #
                # verbose_print('   -------- Setting SMTP "From" Address -------- ')
                # child.sendline ('set email from\r')
                # child.expect ('email address:')
                # child.sendline (tower_a+'@cisco.com\r')
                # child.expect ('Command successful')
                #
                # verbose_print('   -------- Setting SMTP Username -------- ')
                # # child.expect ('Smart CDU:')
                # # child.sendline ('set email smtp useusername\r')
                # # child.expect ('Command successful')
                #
                # verbose_print('   -------- Setting SMTP Password -------- ')
                verbose_print('   -------- Setting SMTP Events -------- ')
                child.expect ('Smart CDU:')
                child.sendline ('set email auth disabled\r')
                child.expect ('Command successful')
                child.expect ('Smart CDU:')
                child.sendline ('set email config disabled\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting SMTP Subject ID -------- ')
                child.sendline ('set email usesubjloc\r')
                child.expect ('Command successful')

            if (ver_2 in new):
                # verbose_print('Location is set as: '+location)
                verbose_print('-------- Setting SMTP '+ver_2+' -------- ')
                verbose_print('   -------- Setting SMTP Host -------- ')
                child.sendline ('set email smtp host\r')
                child.expect ('SMTP host')
                child.sendline (smtp_host+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting SMTP Primary Address -------- ')
                child.expect ('Smart CDU:')
                child.sendline ('set email toaddr1\r')
                child.expect ("Email 'To' address #1")
                child.sendline (smtp_1+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting SMTP Secondary Address -------- ')
                child.expect ('Smart CDU:')
                child.sendline ('set email toaddr2\r')
                child.expect ("Email 'To' address #2")
                child.sendline (smtp_2+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting SMTP Events -------- ')
                child.expect ('Smart CDU:')
                child.sendline ('set email auth disabled\r')
                child.expect ('Command successful')
                child.expect ('Smart CDU:')
                child.sendline ('set email config disabled\r')
                child.expect ('Command successful')

                # verbose_print('   -------- Setting SMTP "From" Address -------- ')
                # child.sendline ('set email fromaddr\r')
                # verbose_print('expecting')
                # child.expect ("Email 'From' address")
                # verbose_print('sending')
                # child.sendline (tower_a+'@cisco.com\r')
                # verbose_print('expecting')
                # child.expect ('Smart CDU:')
                # verbose_print(child.before)

                # verbose_print('   -------- Setting SMTP Username -------- ')
                # # child.expect ('Smart CDU:')
                # # child.sendline ('set email smtp useusername\r')
                # # child.expect ('Command successful')
                #
                # verbose_print('   -------- Setting SMTP Password -------- ')


                verbose_print('   -------- Setting SMTP Subject ID -------- ')
                child.sendline ('set email usesubjloc\r')
                child.expect ('Smart CDU:')

        if (ip_address in fail_ldap):
            if ('7.0g' in new):
                verbose_print('7.0g found - skipping')
            if (ver_1 or 'Version 6.' in new) and ('7.0g' not in new):
                verbose_print('-------- Setting '+ver_1+' LDAP -------- ')
                #Set LDAP
                verbose_print('-------- Setting LDAP -------- ')
                child.sendline ('set ldap enabled\r')
                child.expect ('Command successful')
                ##Set Primary Host
                verbose_print('   -------- Setting LDAP Primary Host -------- ')
                child.expect ('Smart CDU: ')
                child.sendline ('set ldap host1 '+ldap_host+'\r')
                # child.expect ('Host/IP')
                # child.sendline (ldap_host+'\r')
                child.expect ('Command successful')
            ##Set Port
                verbose_print('   -------- Setting LDAP Port -------- ')
                child.expect ('Smart CDU: ')
                child.sendline ('set ldap port\r')
                child.expect ('LDAP Port')
                child.sendline (ldap_port+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting LDAP Bind TLS -------- ')
                child.expect ('Smart CDU: ')
                child.sendline ('set ldap bind tls\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting LDAP Bind DN -------- ')
                child.expect ('Smart CDU: ')
                child.sendline ('set ldap binddn\r')
                child.expect ('Enter Search Bind DN')
                child.sendline (ldap_bind+'\r') ##Need Confirmation##
                child.expect ('Command successful')

                verbose_print('   -------- Setting LDAP BIND PW -------- ')
                child.expect ('Smart CDU: ')
                child.sendline ('set ldap bindpw\r')
                child.expect ('Search Bind Password')
                child.sendline (ldap_pass+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting LDAP Base DN -------- ')
                child.expect ('Smart CDU: ')
                child.sendline ('set ldap userbasedn\r')
                child.expect ('Enter User Search Base')
                child.sendline (ldap_base+'\r') ##Need Confirmation##
                child.expect ('Command successful')

                verbose_print('   -------- Setting LDAP User Filter -------- ')
                child.expect ('Smart CDU: ')
                child.sendline ('set ldap userfilter\r')
                child.expect (' ')
                child.sendline (ldap_filter+'\r')
                child.expect ('Command successful')
                #verbose_print(child.before)

                verbose_print('   -------- Setting LDAP Group Attribute -------- ')
                child.expect ('Smart CDU: ')
                child.sendline ('set ldap groupattr\r')
                child.expect (' ')
                child.sendline (ldap_group_attr+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Disabling LDAP Group Search -------- ')
                child.expect ('Smart CDU: ')
                child.sendline ('set ldap groupsearch disabled\r')
                child.expect ('Command successful')

                verbose_print('   -------- Creating LDAP Admin Group -------- ')
                child.expect ('Smart CDU: ')
                child.sendline ('create ldapgroup '+ldap_admin_group+'\r')
                m = child.expect (['Command successful', 'command failed'])
                if m == 1:
                    verbose_print('Admin Group exists')

                verbose_print('   -------- Creating LDAP User Group -------- ')
                child.expect ('Smart CDU: ')
                child.sendline ('create ldapgroup '+ldap_user_group+'\r')
                m = child.expect (['Command successful', 'command failed'])
                if m == 1:
                    verbose_print('User Group exists')

                verbose_print('   -------- Setting LDAP Admin Group -------- ')
                child.expect ('Smart CDU: ')
                child.sendline ('set ldapgroup access admin\r')
                child.expect ('Group Name: ')
                child.sendline (ldap_admin_group+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting LDAP User Group -------- ')
                child.expect ('Smart CDU: ')
                child.sendline ('set ldapgroup access user\r')
                child.expect ('Group Name: ')
                child.sendline (ldap_user_group+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Disabling LDAP Group Search -------- ')
                child.expect ('Smart CDU: ')
                child.sendline ('set ldap groupsearch disabled\r')
                child.expect ('Command successful')

            if (ver_2 in new):
                verbose_print('-------- Setting '+ver_2+' LDAP -------- ')
                #Set LDAP
                verbose_print('-------- Setting LDAP -------- ')
                child.sendline ('set access method ldaplocal\r')
                child.expect ('Command successful')
                ##Set Primary Host
                verbose_print('   -------- Setting LDAP Primary Host -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldap primary '+ldap_host+'\r')
                # child.expect ('Host/IP')
                # child.sendline (ldap_host+'\r')
                child.expect ('Command successful')
            ##Set Port
                verbose_print('   -------- Setting LDAP Port -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldap port '+ldap_port+'\r')
                # child.expect ('LDAP Port')
                # child.sendline (ldap_port+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting LDAP Bind TLS -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldap bind tls\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting LDAP Bind DN -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldap binddn\r')
                child.expect ('LDAP search bind DN')
                child.sendline (ldap_bind+'\r') ##Need Confirmation##
                child.expect ('Command successful')

                verbose_print('   -------- Setting LDAP BIND PW -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldap bindpw\r')
                child.expect ('search bind password')
                child.sendline (ldap_pass+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting LDAP Base DN -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldap userbasedn\r')
                child.expect ('user search base DN')
                child.sendline (ldap_base+'\r') ##Need Confirmation##
                child.expect ('Command successful')

                verbose_print('   -------- Setting LDAP User Filter -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldap userfilter\r')
                child.expect ('user search filter')
                child.sendline (ldap_filter+'\r')
                child.expect ('Command successful')
                #verbose_print(child.before)

                verbose_print('   -------- Setting LDAP Group Attribute -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldap groupattr\r')
                child.expect ('membership attribute')
                child.sendline (ldap_group_attr+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Creating LDAP Admin Group -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('create ldapgroup '+ldap_admin_group+'\r')
                m = child.expect (['Command successful', 'command failed'])
                if m == 1:
                    verbose_print('User Group exists')

                verbose_print('   -------- Creating LDAP User Group -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('create ldapgroup '+ldap_user_group+'\r')
                m = child.expect (['Command successful', 'command failed'])
                if m == 1:
                    verbose_print('User Group exists')

                verbose_print('   -------- Setting LDAP Admin Group -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldapgroup access admin\r')
                child.expect ('LDAP group: ')
                child.sendline (ldap_admin_group+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting LDAP User Group -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldapgroup access user\r')
                child.expect ('LDAP group: ')
                child.sendline (ldap_user_group+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Disabling LDAP Group Search -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldap groupsearch disabled\r')
                child.expect ('Command successful')

                return
    if (i == 4):
        if (ip_address in fail_snmp):
            if (ver_2 in new):
            #Set SNMPv3
                verbose_print('-------- Setting '+ver_2+' SNMPv3 -------- ')

            ## SNMPv3 Read Write
                verbose_print(' -------- Setting SNMPv3 RW -------- ')
                child.sendline ('set snmp v3 rwusername \r')
                child.expect (':')
                child.sendline (snmp_v3_rw_user+'\r')
                #verbose_print(child.before)
                child.expect ('Command successful')

                verbose_print('   -------- Setting SNMPv3 RW Authentication Type -------- ')
                child.sendline ('set snmp v3 rwauth md5des\r') ##Not on new version - new version = rwauth ##
                child.expect ('Command successful')

                verbose_print('   -------- Setting SNMPv3 RW Authentication Password -------- ')
                child.expect ('Smart PDU:')
                child.sendline ('set snmp v3 rwauthpass \r')
                child.expect (']: ') ##not so sure about the following##
                child.sendline (snmp_v3_rw_passw+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting SNMPv3 RW Privelige Password -------- ')
                child.expect ('Smart PDU:')
                child.sendline ('set snmp v3 rwprivpass \r')
                child.expect (':')
                child.sendline (snmp_v3_rw_passw+'\r')
                child.expect ('Command successful')

            ## SNMPv3 Read Only
                verbose_print(' -------- Setting SNMPv3 RO -------- ')
                child.expect ('Smart PDU:')
                child.sendline ('set snmp v3 rousername \r')
                child.expect (': ')
                child.sendline (snmp_v3_ro_user+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting SNMPv3 RO Authentication Type -------- ')
                child.expect ('Smart PDU:')
                child.sendline ('set snmp v3 roauth md5des\r') ##Not on new version - new version = roauth ##

                child.expect ('Command successful')

                verbose_print('   -------- Setting SNMPv3 RO Authentication Password -------- ')
                child.expect ('Smart PDU:')
                child.sendline ('set snmp v3 roauthpass \r')
                child.expect (': ') ##not so sure about the following##
                child.sendline (snmp_v3_ro_passw+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting SNMPv3 RO Privelige Password -------- ')
                child.expect ('Smart PDU:')
                child.sendline ('set snmp v3 roprivpass \r')
                child.expect (': ') ##not so sure about the following##
                child.sendline (snmp_v3_ro_privpassw+'\r')
                child.expect ('Command successful')

                # verbose_print('-------- Setting Email Enabled -------- ')
                # child.sendline ('set email enabled\r')
                # # child.expect ('Command successful')
                # child.expect ('Smart PDU:')


        if (ip_address in fail_dns):
            if (ver_2 in new):
                verbose_print('-------- Setting DNS '+ver_2+' -------- ')
                verbose_print('   -------- Setting DNS Primary -------- ')
                child.sendline ('set dns primary '+dns_1+'\r')
                child.expect ('Smart PDU:')
                verbose_print('   -------- Setting DNS Secondary -------- ')
                child.sendline ('set dns secondary '+dns_2+'\r')
                child.expect ('Smart PDU:')

        if (ip_address in fail_smtp):
            if (ver_2 in new):
                # verbose_print('Location is set as: '+location)
                verbose_print('-------- Setting SMTP '+ver_2+' -------- ')
                verbose_print('   -------- Setting SMTP Host -------- ')
                child.sendline ('set email smtp host\r')
                child.expect ('SMTP host')
                child.sendline (smtp_host+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting SMTP Primary Address -------- ')
                child.expect ('Smart PDU:')
                child.sendline ('set email toaddr1\r')
                child.expect ("Email 'To' address #1")
                child.sendline (smtp_1+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting SMTP Secondary Address -------- ')
                child.expect ('Smart PDU:')
                child.sendline ('set email toaddr2\r')
                child.expect ("Email 'To' address #2")
                child.sendline (smtp_2+'\r')
                child.expect ('Command successful')

                # verbose_print('   -------- Setting SMTP "From" Address -------- ')
                # child.sendline ('set email fromaddr\r')
                # verbose_print('expecting')
                # child.expect ("Email 'From' address")
                # verbose_print('sending')
                # child.sendline (location+'@cisco.com\r')
                # verbose_print('expecting')
                # child.expect ('Smart PDU:')
                # verbose_print(child.before)

                # verbose_print('   -------- Setting SMTP Username -------- ')
                # # child.expect ('Smart PDU:')
                # # child.sendline ('set email smtp useusername\r')
                # # child.expect ('Command successful')
                #
                # verbose_print('   -------- Setting SMTP Password -------- ')

                verbose_print('   -------- Setting SMTP Subject ID -------- ')
                child.sendline ('set email usesubjloc\r')
                child.expect ('Smart PDU:')

                verbose_print('   -------- Setting SMTP Events -------- ')
                child.expect ('Smart PDU:')
                child.sendline ('set email auth disabled\r')
                child.expect ('Command successful')
                child.expect ('Smart PDU:')
                child.sendline ('set email config disabled\r')
                child.expect ('Command successful')

        if (ip_address in fail_ldap):
            if (ver_2 in new):
                verbose_print('-------- Setting '+ver_2+' LDAP -------- ')
                #Set LDAP
                verbose_print('-------- Setting LDAP -------- ')
                child.sendline ('set access method ldaplocal\r')
                child.expect ('Command successful')
                ##Set Primary Host
                verbose_print('   -------- Setting LDAP Primary Host -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldap primary '+ldap_host+'\r')
                # child.expect ('Host/IP')
                # child.sendline (ldap_host+'\r')
                child.expect ('Command successful')
            ##Set Port
                verbose_print('   -------- Setting LDAP Port -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldap port '+ldap_port+'\r')
                # child.expect ('LDAP Port')
                # child.sendline (ldap_port+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting LDAP Bind TLS -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldap bind tls\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting LDAP Bind DN -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldap binddn\r')
                child.expect ('LDAP search bind DN')
                child.sendline (ldap_bind+'\r') ##Need Confirmation##
                child.expect ('Command successful')

                verbose_print('   -------- Setting LDAP BIND PW -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldap bindpw\r')
                child.expect ('search bind password')
                child.sendline (ldap_pass+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting LDAP Base DN -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldap userbasedn\r')
                child.expect ('user search base DN')
                child.sendline (ldap_base+'\r') ##Need Confirmation##
                child.expect ('Command successful')

                verbose_print('   -------- Setting LDAP User Filter -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldap userfilter\r')
                child.expect ('user search filter')
                child.sendline (ldap_filter+'\r')
                child.expect ('Command successful')
                #verbose_print(child.before)

                verbose_print('   -------- Setting LDAP Group Attribute -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldap groupattr\r')
                child.expect ('membership attribute')
                child.sendline (ldap_group_attr+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Creating LDAP Admin Group -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('create ldapgroup '+ldap_admin_group+'\r')
                m = child.expect (['Command successful', 'command failed', 'reserved name'])
                if m == 1 or 2:
                    verbose_print('User Group exists')

                verbose_print('   -------- Creating LDAP User Group -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('create ldapgroup '+ldap_user_group+'\r')
                m = child.expect (['Command successful', 'command failed', 'reserved name'])
                if m == 1 or 2:
                    verbose_print('User Group exists')

                verbose_print('   -------- Setting LDAP Admin Group -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldapgroup access admin\r')
                child.expect ('LDAP group: ')
                child.sendline (ldap_admin_group+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Setting LDAP User Group -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldapgroup access user\r')
                child.expect ('LDAP group: ')
                child.sendline (ldap_user_group+'\r')
                child.expect ('Command successful')

                verbose_print('   -------- Disabling LDAP Group Search -------- ')
                child.expect ('Smart PDU: ')
                child.sendline ('set ldap groupsearch disabled\r')
                child.expect ('Command successful')

                return
def end_session(child):
        verbose_print("Ending Session") ## ##Not attempting configs##
        child.sendline('exit')
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
def ssh_test(i, q, serial, serial_a, serial_b): ##Threaded test to determine if SSH connections are successful and identifies credential and timeout errors if not ##
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
                snmp_v3_rw_user = ConfigSectionMap(subnet)['snmpv3rwuser']
                snmp_v3_rw_passw = ConfigSectionMap(subnet)['snmpv3rwauthpass']
                snmp_v3_rw_privpassw = ConfigSectionMap(subnet)['snmpv3rwprivpass']
                snmp_v3_ro_user = ConfigSectionMap(subnet)['snmpv3rouser']
                snmp_v3_ro_passw = ConfigSectionMap(subnet)['snmpv3roauthpass']
                snmp_v3_ro_privpassw = ConfigSectionMap(subnet)['snmpv3roprivpass']
                smtp_host = ConfigSectionMap(subnet)['smtphost']
                smtp_1 = ConfigSectionMap(subnet)['smtp1']
                smtp_2 = ConfigSectionMap(subnet)['smtp2']
                dns_1 = ConfigSectionMap(subnet)['dns1']
                dns_2 = ConfigSectionMap(subnet)['dns2']
                ver_1 = ConfigSectionMap(subnet)['ver_1']
                ver_2 = ConfigSectionMap(subnet)['ver_2']
                verifier = ConfigSectionMap(subnet)['verifier']
            count += 1
        verbose_print('Testing SSH on '+ip)
        newlocation = location.split('.')
        location = newlocation[0]
        # verbose_print('LOCATION IS :'+location)
        a = 0
        b = 0
        child = pexpect.spawn ('sshpass -p "'+ldap_pass+'" ssh -vvvv -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss -oStrictHostKeyChecking=no '+ldap_user+'@'+ip)
        child.timeout=200
        i = child.expect([pexpect.TIMEOUT, 'Connection refused', pexpect.EOF, 'Smart CDU: ', 'Smart PDU: ', 'Switched CDU: '])
        if i == 0:
            fail_ssh.append(ip)
            die(child, ip+': ERROR!\nSSH timed out. Here is what SSH said:')
        elif i == 1:
            print(str(ip)+"######## Incorrect Credentials - Attempting SSH using admin.cred passwords ########")
            child.close()
            user = "admn"
            password = "admn"
            #print('starting new ssh')
            child = pexpect.spawn ('sshpass -p "'+password+'" ssh -vvvv -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss -oStrictHostKeyChecking=no '+user+'@'+ip)
            child.timeout=200
            i = child.expect([pexpect.TIMEOUT, 'Connection refused', pexpect.EOF, 'Smart CDU: ', 'Smart PDU: ', 'Switched CDU: '])
            if i == 0:
                die(child, ip+': ERROR!\nSSH timed out. Here is what SSH said:')
                fail_ssh.append(ip)
            elif i == 1:
                die(child, ip+': ERROR!\nIncorrect password Here is what SSH said:')
                fail_ssh.append(ip)
            elif i == 2:
                die(child, ip+': ERROR!\nIncorrect password Here is what SSH said:')
                fail_ssh.append(ip)
            elif i == 3:
                pass_ssh.append(ip)
                old_admin_ssh.append(ip)
                fail_ldap.append(ip)
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
            elif i == 4:
                pass_ssh.append(ip)
                old_admin_ssh.append(ip)
                fail_ldap.append(ip)
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
            elif i == 5:
                switched_cdu.append(ip)
                fail_ssh.append(ip)
                child.sendline('exit')
                child.close()
            # fail_ssh.append(ip)
            # die(child, ip+': ERROR!\nIncorrect password Here is what SSH said:')
        elif i == 2:
            print("######## Incorrect Credentials - Attempting SSH using admin.cred passwords ########")
            child.close()
            user = "admn"
            password = "admn"
            #print('starting new ssh')
            child = pexpect.spawn ('sshpass -p "'+password+'" ssh -vvvv -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss -oStrictHostKeyChecking=no '+user+'@'+ip)
            child.timeout=200
            i = child.expect([pexpect.TIMEOUT, 'Connection refused', pexpect.EOF, 'Smart CDU: ', 'Smart PDU: ', 'Switched CDU: '])
            if i == 0:
                fail_ssh.append(ip)
                die(child, ip+': ERROR!\nSSH timed out. Here is what SSH said:')
            elif i == 1:
                die(child, ip+': ERROR!\nIncorrect password Here is what SSH said:')
                fail_ssh.append(ip)
            elif i == 2:
                die(child, ip+': ERROR!\nIncorrect password Here is what SSH said:')
                fail_ssh.append(ip)
            elif i == 3:
                pass_ssh.append(ip)
                old_admin_ssh.append(ip)
                fail_ldap.append(ip)
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
            elif i == 4:
                pass_ssh.append(ip)
                fail_ldap.append(ip)
                old_admin_ssh.append(ip)
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
            elif i == 5:
                switched_cdu.append(ip)
                fail_ssh.append(ip)
                child.sendline('exit')
                child.close()
        elif i == 3:
            pass_ldap.append(ip)
            pass_ssh.append(ip)
            verbose_print(ip+': SSH TRUE')
            child.sendline ('version\r')
            j = child.expect ('Smart CDU:')
            new = child.before
            if ('Critical Alert' in new):
                crit_alerts.append(ip)
            verbose_print(new)

            ##Checking for FTP updates##
            verbose_print("Checking version against FTP Server.")
            if ('Version 8.0' in new):
                child.sendline('show system')
                child.expect ('Smart CDU:')
                hardware = child.before
                #verbose_print(hardware)
                if ('NIM2-3L' in hardware):
                    if ('Version 8.0k' not in new):
                        verbose_print('Unvalidated firmware found: Updating to firmware on FTP server.')
                        ftp_update.append(ip)
            if ('Version 7.' in new):
                child.sendline ('show system \r')
                child.expect ('Smart CDU:')
                if ('Version 7.1b' not in new):
                    verbose_print('Unvalidated firmware found: Updating to firmware on FTP server.')
                    ftp_update.append(ip)
            if ('Version 6.' in new):
                child.sendline ('show system \r')
                child.expect ('Smart CDU:')
                hardware = child.before
                if ('H/W Rev Code:      32' in hardware):
                    if ('Version 7.1b' not in new):
                        verbose_print('Unvalidated firmware found: Updating to firmware on FTP server.')
                        ftp_update.append(ip)
            if ('Version 8.0k' in new):
                updated_firmware_1.append(ip)
            if ('Version 7.1b' in new):
                updated_firmware_2.append(ip)
            if ('Version 7.0p' in new):
                old_firmware_1.append(ip)
            if ('Version 7.0t' in new):
                old_firmware_2.append(ip)
            if ('Version 7.0g' in new):
                old_firmware_3.append(ip)
            if ('Version 6.' in new):
                old_firmware_4.append(ip)
            verbose_print('continuing checks')


            if (ver_1 in new):
                #verbose_print(ver_1+' detected')
                child.sendline ('show network\r')
                i = child.expect (['More', 'Smart CDU:'])
                network = child.before
                if (i == 0):
                    child.sendline ('n\r')
                    child.expect ('Smart CDU:')
                    i = 1
                if (i == 1):
                    if (dns_1 in network):
                        a += 1
                    if (dns_2 in network):
                        a += 1
                    if (a == 2):
                        #verbose_print('DNS-Nameservers are correct.')
                        pass_dns.append(ip)
                    else:
                        verbose_print('DNS not configured correctly')
                        fail_dns.append(ip)
                        if (ip not in fails):
                            fails.append(ip)
                ##TEST DNS##
            if (ver_2 in new):
                #verbose_print(ver_2+' detected')
                child.sendline ('show network\r')
                child.expect ('Smart CDU:')
                network = child.before
                #verbose_print(network)
                if (dns_1 in network):
                    a += 1
                if (dns_2 in network):
                    a += 1
                if (a == 2):
                    #verbose_print('DNS-Nameservers are correct.')
                    pass_dns.append(ip)
                else:
                    verbose_print('DNS not configured correctly')
                    fail_dns.append(ip)
                    if (ip not in fails):
                        fails.append(ip)
            ## CHECKING S/N##
            if (ver_1 in new):
                child.sendline('show towers')
                d = child.expect(['Command successful', 'More'])
                verbose_print(d)
                serial = child.before
                if (d == 1):
                    serial_a = child.before
                    child.sendline('y')
                    child.expect('Command successful')
                    serial_b = child.before
                    serial = serial_a + serial_b
            if (ver_2 in new):
                child.sendline('show units\r')
                d = child.expect(['Smart CDU:', 'More'])
                serial_a = child.before
                if (d == 1):
                    child.sendline('y')
                    child.expect('Smart CDU:')
                    serial_b = child.before
                serial = serial_a + serial_b

            #verbose_print(serial)
            serial = str(serial).split('\n')
            count_7 = 0
            count_8 = 0
            serial_final = ''
            serial_dict = {'0': '', '1': '', '2': '', '3': ''}
            verbose_print(ip + str(serial))
            while (count_7 < len(serial)):
                if ('Product S/N:' in serial[count_7]):
                    serial_new = serial[count_7].split('    ')
                    verbose_print(ip + str(serial_new))
                    count_9 = 0
                    while (count_9 < len(serial_new)):
                        if ('\r' in serial_new[count_9]):
                            verbose_print(ip + ' found serial')
                            serial_final = serial_new[count_9].replace('\r', '')
                        count_9 += 1
                    serial_dict[str(count_8)] = serial_final.replace('  ', '')
                    if (serial_dict[str(count_8)].endswith('*')):
                        serial_dict[str(count_8)] = '*'
                    if ("Product S/N:" in serial_dict[str(count_8)]):
                        serial_dict[str(count_8)] = serial_dict[str(count_8)].replace('Product S/N:','')
                    count_8 += 1
                count_7 += 1
            verbose_print(ip+': S/N dict: '+ str(serial_dict))
            full_serial_dict[ip] = serial_dict



                ## CHECKING SMTP CONFIGURATION ##

            verbose_print('-------- Checking SMTP (Pager) Settings -------- ')
            if (ver_1 in new):
                verbose_print(ver_1+' detected')
                child.sendline ('show smtp\r')
                child.expect ('Command successful')
                smtp_output = child.before
                #verbose_print(smtp_output)
                # if (location + '@cisco.com' in smtp_output):
                #     verbose_print(ip+': from address correct')
                #     b += 1
                if (smtp_1 in smtp_output):
                    verbose_print(ip+': primary address correct')
                    b += 1
                if (smtp_2 in smtp_output):
                    verbose_print(ip+': secondary address correct')
                    b += 1
                # if ('['+location+']' in smtp_output):
                #     verbose_print(ip+': subject id correct')
                #     b += 1
                if ('AUTH Messages:            Disabled' in smtp_output):
                    verbose_print("auth messages are disabled")
                    b += 1
                if ('CONFIG Messages:          Disabled' in smtp_output):
                    verbose_print("config messages are disabled")
                    b += 1
                if ('Email Notifications:      Enabled' not in smtp_output):
                #     b += 1
                    email_disabled.append(ip)
                if (smtp_host in smtp_output):
                    verbose_print(ip+': smtp host address correct')
                    b += 1
                if (b == 5):#):
                    verbose_print('SMTP configuration is correct.')
                    pass_smtp.append(ip)
                else:
                    verbose_print(ip + smtp_output)
                    verbose_print(ip+': SMTP test failed. Value = '+str(b))
                    #verbose_print(ip+': expecting '+ location)
                    fail_smtp.append(ip)
                    if (ip not in fails):
                        fails.append(ip)
            if (ver_2 in new):
                verbose_print(ver_2+' detected')
                child.sendline ('show smtp\r')
                child.expect ('Smart CDU:')
                smtp_output = child.before
                # if (location[:-1] + '@cisco.com' in smtp_output):
                #     b += 1
                if (smtp_1 in smtp_output):
                    b += 1
                if (smtp_2 in smtp_output):
                    b += 1
                # verbose_print(ip+' expecting: ['+location[:-6]+']')
                # if ('['+location[:-6]+']' in smtp_output):
                #     b += 1
                if ('Email Notifications: enabled' not in smtp_output):
                    email_disabled.append(ip)
                if (smtp_host in smtp_output):
                    b += 1
                verbose_print(b)
                if (b == 3):#6):
                    pass_smtp.append(ip)
                else:
                    verbose_print(ip+': SMTP test failed. Value = '+str(b))
                    fail_smtp.append(ip)
                    if (ip not in fails):
                        fails.append(ip)
        elif i == 4:
            pass_ldap.append(ip)
            pass_ssh.append(ip)
            verbose_print(ip+': SSH TRUE')
            #verbose_print('-------- Checking Firmware Version -------- ')
            child.sendline ('version\r')
            j = child.expect ('Smart PDU:')
            new = child.before
            if ('Critical Alert' in new):
                crit_alerts.append(ip)
            #verbose_print(new)

            ##Checking for FTP updates##
            verbose_print("Checking version against FTP Server.")
            if ('Version 8.0' in new):
                child.sendline('show system')
                child.expect ('Smart PDU:')
                hardware = child.before
                if ('NIM2-3L' in hardware):
                    if ('Version 8.0k' not in new):
                        verbose_print('Unvalidated firmware found: Updating to firmware on FTP server.')
                        ftp_update.append(ip)
            if ('Version 8.0k' in new):
                updated_firmware_1.append(ip)
            if ('Version 7.1b' in new):
                updated_firmware_2.append(ip)
            if ('Version 7.0p' in new):
                old_firmware_1.append(ip)
            if ('Version 7.0t' in new):
                old_firmware_2.append(ip)
            if ('Version 6.' in new):
                old_firmware_4.append(ip)
            verbose_print('continuing checks')
            ## CHECKING DNS CONFIGURATION ##

            # child.expect ('Smart CDU:')
            #verbose_print('-------- Checking DNS Settings -------- ')

                       ##TEST DNS##
            if (ver_2 in new):
                verbose_print(ver_2+' detected')
                child.sendline ('show network\r')
                child.expect ('Smart PDU:')
                network = child.before
                #verbose_print(network)
                if (dns_1 in network):
                    a += 1
                if (dns_2 in network):
                    a += 1
                if (a == 2):
                    #verbose_print('DNS-Nameservers are correct.')
                    pass_dns.append(ip)
                else:
                    verbose_print('DNS not configured correctly')
                    fail_dns.append(ip)
                    if (ip not in fails):
                        fails.append(ip)
            ## CHECKING S/N##
            if (ver_2 in new):
                child.sendline('show units\r')
                d = child.expect(['Smart PDU:', 'More'])
                serial_a = child.before
                if (d == 1):
                    child.sendline('y')
                    child.expect('Smart PDU:')
                    serial_b = child.before
                serial = serial_a + serial_b

            serial = str(serial).split('\n')
            count_7 = 0
            count_8 = 0
            serial_final = ''
            serial_dict = {'0': '', '1': '', '2': '', '3': ''}
            while (count_7 < len(serial)):
                if ('Product S/N:' in serial[count_7]):
                    serial_new = serial[count_7].split('    ')
                    verbose_print(serial_new)
                    count_9 = 0
                    while (count_9 < len(serial_new)):
                        if ('\r' in serial_new[count_9]):
                            serial_final = serial_new[count_9].replace('\r', '')
                        count_9 += 1
                    serial_dict[str(count_8)] = serial_final.replace('  ', '')
                    count_8 += 1
                count_7 += 1
            verbose_print('S/N dict: '+ str(serial_dict))
            full_serial_dict[ip] = serial_dict
            verbose_print('-------- Checking SMTP (Pager) Settings -------- ')
            if (ver_1 in new):
                #verbose_print(ver_1+' detected')
                child.sendline ('show smtp\r')
                child.expect ('Command successful')
                smtp_output = child.before
                #verbose_print(smtp_output)
                # if (location + '@cisco.com' in smtp_output):
                #     b += 1
                if (smtp_1 in smtp_output):
                    b += 1
                if (smtp_2 in smtp_output):
                    b += 1
                # if ('['+location[:-5]+']' in smtp_output):
                #     b += 1
                if ('AUTH Messages:     disabled' in smtp_output):
                    verbose_print("auth messages are disabled")
                    b += 1
                if ('CONFIG Messages:   disabled' in smtp_output):
                    verbose_print("config messages are disabled")
                    b += 1
                if ('Email Notifications:      Enabled' not in smtp_output):
                    email_disabled.append(ip)
                if (smtp_host in smtp_output):
                    b += 1
                verbose_print(b)
                if (b == 5):#):
                    #verbose_print('SMTP configuration is correct.')
                    pass_smtp.append(ip)
                else:
                    verbose_print(ip + smtp_output)
                    verbose_print(ip+': SMTP test failed. Value = '+str(b))
                    #verbose_print(ip+': expecting '+ location[:-5])
                    fail_smtp.append(ip)
                    if (ip not in fails):
                        fails.append(ip)
            if (ver_2 in new):
                verbose_print(ver_2+' detected')
                child.sendline ('show smtp\r')
                child.expect ('Smart PDU:')
                smtp_output = child.before
                # if (location[:-1] + '@cisco.com' in smtp_output):
                #     b += 1
                if (smtp_1 in smtp_output):
                    b += 1
                if (smtp_2 in smtp_output):
                    b += 1
                # verbose_print(ip+' expecting: ['+location[:-6]+']')
                # if ('['+location[:-6]+']' in smtp_output):
                #     b += 1
                if ('AUTH Messages:     disabled' in smtp_output):
                    verbose_print("auth messages are disabled")
                    b += 1
                if ('CONFIG Messages:   disabled' in smtp_output):
                    verbose_print("config messages are disabled")
                    b += 1
                if ('Email Notifications: enabled' not in smtp_output):
                     email_disabled.append(ip)
                if (smtp_host in smtp_output):
                    b += 1
                verbose_print(b)
                if (b == 5):#6):
                    verbose_print('SMTP configuration is correct.')
                    pass_smtp.append(ip)
                else:
                    verbose_print(ip+': SMTP test failed. Value = '+str(b))
                    verbose_print(smtp_output)
                    fail_smtp.append(ip)
                    if (ip not in fails):
                        fails.append(ip)
        elif i == 5:
            switched_cdu.append(ip)
            fail_ssh.append(ip)
            child.sendline('exit')
            child.close()
        # verbose_print('task finished')


        queue.task_done()
    # die(child, 'SSH tests concluded.')
def default_password_test(i, q):
    while True:
        ip = q.get()
        verbose_print('Checking for Default Password on '+ip)
        # verbose_print('LOCATION IS :'+location)
        a = 0
        b = 0
        child = pexpect.spawn ('sshpass -p "admn" ssh -vvvv -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss -oStrictHostKeyChecking=no admn@'+ip)
        child.timeout=200
        i = child.expect([pexpect.TIMEOUT, 'Connection refused', pexpect.EOF, 'Smart CDU: ', 'Smart PDU: '])
        if i == 0:
            die(child, ip+': ERROR!\nSSH timed out. Here is what SSH said:')
        elif i == 1:
            child.close()
            count = 0
            while (count < len(old_admin_pass) and (i != 3 or 4)):
                verbose_print(ip+': Not Default')
                print(old_admin_pass[count])
                user = "admn"
                password = old_admin_pass[count]
                #print('starting new ssh')
                child = pexpect.spawn ('sshpass -p "'+password+'" ssh -vvvv -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss -oStrictHostKeyChecking=no '+user+'@'+ip)
                child.timeout=200
                i = child.expect([pexpect.TIMEOUT, 'Connection refused', pexpect.EOF, 'Smart CDU: ', 'Smart PDU: ', 'Switched CDU: '])
                if i == 0:
                    die(child, ip+': ERROR!\nSSH timed out. Here is what SSH said:')
                elif i == 1:
                    verbose_print(ip+' Not Old PW'+str(count))
                    fail_ssh.append(ip)
                elif i == 2:
                    verbose_print(ip+' Not Old PW'+str(count))
                    fail_ssh.append(ip)
                elif i == 3:
                    default_password.append(ip)
                    verbose_print(ip+' Old Password Found')
                    break
                elif i == 4:
                    default_password.append(ip)
                    verbose_print(ip+' Old Password Found')
                    break
                elif i == 5:
                    default_password.append(ip)
                    verbose_print(ip+' Old Password Found')
                    break
                count += 1
        elif i == 2:
            verbose_print(ip+': EOF - Not Default')
            child.close()
            count = 0
            while (count < len(old_admin_pass) and (i != 3 or 4)):
                print(old_admin_pass[count])
                user = "admn"
                password = old_admin_pass[count]
                #print('starting new ssh')
                child = pexpect.spawn ('sshpass -p "'+password+'" ssh -vvvv -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss -oStrictHostKeyChecking=no '+user+'@'+ip)
                child.timeout=200
                i = child.expect([pexpect.TIMEOUT, 'Connection refused', pexpect.EOF, 'Smart CDU: ', 'Smart PDU: ', 'Switched CDU: '])
                if i == 0:
                    die(child, ip+': ERROR!\nSSH timed out. Here is what SSH said:')
                elif i == 1:
                    verbose_print(ip+' Not Old PW'+str(count))
                    fail_ssh.append(ip)
                elif i == 2:
                    verbose_print(ip+' Not Old PW'+str(count))
                    fail_ssh.append(ip)
                elif i == 3:
                    default_password.append(ip)
                    verbose_print(ip+' Old Password Found')
                    break
                elif i == 4:
                    default_password.append(ip)
                    verbose_print(ip+' Old Password Found')
                    break
                elif i == 5:
                    default_password.append(ip)
                    verbose_print(ip+' Old Password Found')
                    break
                count += 1
            # ldap_error(ip)
        elif i == 3:
            verbose_print(ip+' Default Password Found')
            default_password.append(ip)
        elif i == 4:
            verbose_print(ip+' Default Password Found')
            default_password.append(ip)
        queue.task_done()
def pinger(i, q): ## Threaded ping test that runs through all ips given ##
    """Pings subnet"""
    while True:
        ip = q.get()
        #verbose_print "Thread %s: Pinging %s" % (i, ip)
        ret = subprocess.call("ping -c 1 %s" % ip,
        shell=True,
        stdout=open('/dev/null', 'w'),
        stderr=subprocess.STDOUT)
        #verbose_print('ping occuring')
        #verbose_print("PASSED:"+str(pass_pings))
        #verbose_print("FAILED:"+str(fail_pings))
        if (ret == 0):
            pass_pings.append(ip)
            with open("passed_ips.txt", "a") as myfile:
                myfile.write(ip+'\n')
        else:
            fail_pings.append(ip)
            ping_error(ip)
            with open("failed_ips.txt", "a") as myfile:
                myfile.write(ip+'\n')
        queue.task_done()
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
def snmp_test(i, q): ##Threaded SNMP walk test ##
    while True:
        ip = q.get()
        count_1 = 0
        while (count_1 < len(dic)):
            if ip in dic[count_1]["ip_address"]:
                subnet = dic[count_1]["subnet"]
                #hostname = dic[count_1]["hostname"]
                location = dic[count_1]["location"]
                ## variables pulled from config.ini file ##
                snmp_v3_rw_user = ConfigSectionMap(subnet)['snmpv3rwuser']
                snmp_v3_rw_passw = ConfigSectionMap(subnet)['snmpv3rwauthpass']
                snmp_v3_rw_privpassw = ConfigSectionMap(subnet)['snmpv3rwprivpass']
                snmp_v3_ro_user = ConfigSectionMap(subnet)['snmpv3rouser']
                snmp_v3_ro_passw = ConfigSectionMap(subnet)['snmpv3roauthpass']
                snmp_v3_ro_privpassw = ConfigSectionMap(subnet)['snmpv3roprivpass']
                dns_1 = ConfigSectionMap(subnet)['dns1']
                dns_2 = ConfigSectionMap(subnet)['dns2']
                verifier = ConfigSectionMap(subnet)['verifier']
            count_1 += 1
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(SnmpEngine(),
                   UsmUserData(snmp_v3_ro_user, snmp_v3_ro_passw, snmp_v3_ro_privpassw),
                   UdpTransportTarget((ip, 161)),
                   ContextData(),
                   ObjectType(ObjectIdentity('.1.3.6.1.2.1.1.1.0')))
        )
        if errorIndication:
            # snmp_error(ip)
            fail_snmp.append(ip)
            if (ip not in fails):
                fails.append(ip)
            verbose_print(ip+': SNMP FALSE')
        elif errorStatus:
            verbose_print('%s at %s' % (errorStatus.prettyverbose_print(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        else:
            #verbose_print('SNMP is Operational')
            verbose_print(ip+': SNMP TRUE')
            pass_snmp.append(ip)
        queue.task_done()
def auto_ftp_update():
    count_6 = 0
    while (count_6 < len(ftp_update)):
        verbose_print(count_6)
        ftp_ip_address = ftp_update[count_6]
        if ftp_ip_address in crit_alerts:
            z = 0
            count_6 += 1
            verbose_print(str(ftp_ip_address) + ': is reporting a critical alert')
            continue
        else:
            z = 1
            count_2 = 0
            while (count_2 < len(dic)):
                if "'"+ftp_ip_address+"'" in str(dic[count_2]):
                    subnet = dic[count_2]["subnet"]
                    #hostname = dic[count_2]["hostname"]
                    location = dic[count_2]["location"]
                    ## variables pulled from config.ini file ##
                    snmp_v3_rw_user = ConfigSectionMap(subnet)['snmpv3rwuser']
                    snmp_v3_rw_passw = ConfigSectionMap(subnet)['snmpv3rwauthpass']
                    snmp_v3_rw_privpassw = ConfigSectionMap(subnet)['snmpv3rwprivpass']
                    snmp_v3_ro_user = ConfigSectionMap(subnet)['snmpv3rouser']
                    snmp_v3_ro_passw = ConfigSectionMap(subnet)['snmpv3roauthpass']
                    snmp_v3_ro_privpassw = ConfigSectionMap(subnet)['snmpv3roprivpass']
                    dns_1 = ConfigSectionMap(subnet)['dns1']
                    dns_2 = ConfigSectionMap(subnet)['dns2']
                    ftp_host = ConfigSectionMap('global')['ftp_host']
                    ftp_user = ConfigSectionMap('global')['ftp_user']
                    ftp_directory = ConfigSectionMap('global')['ftp_directory']
                    ftp_pass = ConfigSectionMap('global')['ftp_pass']
                    ftp_filename = ConfigSectionMap('global')['ftp_filename'] ## Firmware 8.0k
                    ftp_filename2 = ConfigSectionMap('global')['ftp_filename2'] ## Firmware 7.1b
                    verifier = ConfigSectionMap(subnet)['verifier']
                count_2 += 1
            verbose_print("---------- Updating FTP Settings ---------- ") ##Could be implemented earlier to avoid wait times - but that would require prompting Y/N per device
            verbose_print('# Starting SSH session with Host '+ftp_ip_address+' #')
            child = pexpect.spawn ('sshpass -p "'+ldap_pass+'" ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss -oStrictHostKeyChecking=no '+ldap_user+'@'+ftp_ip_address)
            child.timeout=300

            k = child.expect (['Smart CDU:', 'Smart PDU: '])

            if k == 0:
                verbose_print('-------- Setting Email Disabled -------- ')
                child.sendline ('set email disabled\r')
                child.expect ('Smart CDU:')

                child.sendline ('version\r')
                child.expect ('Smart CDU:')
                version = child.before
                verbose_print(version)


                verbose_print('-------- Setting FTP Host -------- ')
                child.sendline('set ftp host '+ftp_host+'\r')

                child.expect ('Smart CDU:')
                verbose_print('-------- Setting FTP Username -------- ')
                child.sendline('set ftp username '+ftp_user+'\r')

                child.expect ('Smart CDU:')
                verbose_print('-------- Setting FTP Password -------- ')
                child.sendline('set ftp password '+ftp_pass+'\r')

                child.expect ('Smart CDU:')
                verbose_print('-------- Setting FTP Directory -------- ')
                child.sendline('set ftp directory '+ftp_directory+'\r')

                verbose_print('detecting ftp version to apply')
                child.expect ('Smart CDU:')
                if ('Version 6.' in version):
                    verbose_print('-------- Setting FTP Filename (for V6.0 ('+ftp_filename2+'))  -------- ')
                    child.sendline('set ftp filename '+ftp_filename2+'\r')
                if ('Version 7.' in version):
                    verbose_print('-------- Setting FTP Filename (for V7.0 ('+ftp_filename2+'))  -------- ')
                    child.sendline('set ftp filename '+ftp_filename2+'\r')
                if ('Version 8.' in version):
                    verbose_print('-------- Setting FTP Filename (for V8.0('+ftp_filename+')) -------- ')
                    child.sendline('set ftp filename '+ftp_filename+'\r')

                child.expect ('Smart CDU:')
                verbose_print('-------- Restarting with FTP Load -------- ')
                child.sendline('restart ftpload\r')
                child.expect (': ')
                child.sendline('Y\r')

            if k == 1:
                verbose_print('-------- Setting Email Disabled -------- ')
                child.sendline ('set email disabled\r')
                child.expect ('Smart PDU:')

                child.sendline ('version\r')
                child.expect ('Smart PDU:')
                version = child.before

                verbose_print('-------- Setting FTP Host -------- ')
                child.sendline('set ftp host '+ftp_host+'\r')

                child.expect ('Smart PDU:')
                verbose_print('-------- Setting FTP Username -------- ')
                child.sendline('set ftp username '+ftp_user+'\r')

                child.expect ('Smart PDU:')
                verbose_print('-------- Setting FTP Password -------- ')
                child.sendline('set ftp password '+ftp_pass+'\r')

                child.expect ('Smart PDU:')
                verbose_print('-------- Setting FTP Directory -------- ')
                child.sendline('set ftp directory '+ftp_directory+'\r')

                child.expect ('Smart PDU:')
                if ('Version 6.0' in version):
                    verbose_print('-------- Setting FTP Filename (for V6.0) -------- ')
                    child.sendline('set ftp filename '+ftp_filename2+'\r')
                if ('Version 8.0' in version):
                    verbose_print('-------- Setting FTP Filename (for V8.0) -------- ')
                    child.sendline('set ftp filename '+ftp_filename+'\r')

                child.expect ('Smart PDU:')
                verbose_print('-------- Restarting with FTP Load -------- ')
                child.sendline('restart ftpload\r')
                child.expect (': ')
                child.sendline('Y\r')
        count_6 += 1

    if z == 1:
        verbose_print('Waitng 300 seconds for reboot and FTP load...') ##A sleep timer that waits long enough for any newly enabled strip to reboot ##
        for i in xrange(300,0,-1):
            time.sleep(1)
            sys.stdout.write(str(i)+' ')
            sys.stdout.flush()
def snmp_restart():
    count_5 = 0
    while (count_5 < len(fail_snmp)):
        verbose_print(count_5)
        snmp_ip_address = fail_snmp[count_5]
        if snmp_ip_address in fail_ssh:
            continue
        else:
            count_2 = 0
            while (count_2 < len(dic)):
                if "'"+snmp_ip_address+"'" in str(dic[count_2]):
                    subnet = dic[count_2]["subnet"]
                    #hostname = dic[count_2]["hostname"]
                    location = dic[count_2]["location"]
                    ## variables pulled from config.ini file ##
                    snmp_v3_rw_user = ConfigSectionMap(subnet)['snmpv3rwuser']
                    snmp_v3_rw_passw = ConfigSectionMap(subnet)['snmpv3rwauthpass']
                    snmp_v3_rw_privpassw = ConfigSectionMap(subnet)['snmpv3rwprivpass']
                    snmp_v3_ro_user = ConfigSectionMap(subnet)['snmpv3rouser']
                    snmp_v3_ro_passw = ConfigSectionMap(subnet)['snmpv3roauthpass']
                    snmp_v3_ro_privpassw = ConfigSectionMap(subnet)['snmpv3roprivpass']
                    dns_1 = ConfigSectionMap(subnet)['dns1']
                    dns_2 = ConfigSectionMap(subnet)['dns2']
                    verifier = ConfigSectionMap(subnet)['verifier']
                count_2 += 1
            verbose_print("---------- Setting SNMPv3 Enabled ---------- ") ##Could be implemented earlier to avoid wait times - but that would require prompting Y/N per device
            verbose_print('# Starting SSH session with Host '+snmp_ip_address+' #')
            child = pexpect.spawn ('sshpass -p "'+ldap_pass+'" ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss -oStrictHostKeyChecking=no '+ldap_user+'@'+snmp_ip_address)
            child.timeout=300

            verbose_print(snmp_ip_address+': Verifier = '+verifier)

            j = child.expect (['Smart CDU: ', 'Smart PDU: '])
            verbose_print(child.after)
            verbose_print("j = "+str(j))
            if j == 0:
                verbose_print('-------- Setting Email Disabled -------- ')
                child.sendline ('set email disabled\r')
                child.expect ('Smart CDU:')

                verbose_print(' -------- Restarting PDU -------- ')
                child.sendline ('restart\r')
                child.expect (': ')
                child.sendline ('Yes\r')
                child.sendline ('Yes\r')
            if j == 1:
                verbose_print('-------- Setting Email Disabled -------- ')
                child.sendline ('set email disabled\r')
                child.expect ('Smart PDU:')
                verbose_print(' -------- Restarting PDU -------- ')
                child.sendline ('restart\r')
                child.expect (': ')
                child.sendline ('Yes\r')
                child.sendline ('Yes\r')
def email_enable(i, q, dic):
    while True:
        ip = q.get()
        count = 0
        if ip not in crit_alerts:
            while (count < len(dic)):
                # if ip in dic[count]["ip_address"]:
                if "'"+ip+"'" in str(dic[count]):
                    subnet = dic[count]["subnet"]
                    #hostname = dic[count]["hostname"]
                    location = dic[count]["location"]
                    ## variables pulled from config.ini file ##
                    snmp_v3_rw_user = ConfigSectionMap(subnet)['snmpv3rwuser']
                    snmp_v3_rw_passw = ConfigSectionMap(subnet)['snmpv3rwauthpass']
                    snmp_v3_rw_privpassw = ConfigSectionMap(subnet)['snmpv3rwprivpass']
                    snmp_v3_ro_user = ConfigSectionMap(subnet)['snmpv3rouser']
                    snmp_v3_ro_passw = ConfigSectionMap(subnet)['snmpv3roauthpass']
                    snmp_v3_ro_privpassw = ConfigSectionMap(subnet)['snmpv3roprivpass']
                    smtp_host = ConfigSectionMap(subnet)['smtphost']
                    smtp_1 = ConfigSectionMap(subnet)['smtp1']
                    smtp_2 = ConfigSectionMap(subnet)['smtp2']
                    dns_1 = ConfigSectionMap(subnet)['dns1']
                    dns_2 = ConfigSectionMap(subnet)['dns2']
                    verifier = ConfigSectionMap(subnet)['verifier']
                count += 1
            child = pexpect.spawn ('sshpass -p "'+ldap_pass+'" ssh -vvvv -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss -oStrictHostKeyChecking=no '+ldap_user+'@'+ip)
            child.timeout=300
            i = child.expect([pexpect.TIMEOUT, 'Connection refused', pexpect.EOF, 'Smart CDU: ', 'Smart PDU: '])
            if i == 0:
                fail_ssh.append(ip)
                die(child, ip+': ERROR!\nSSH timed out. Here is what SSH said:')
            elif i == 1:
                fail_ssh.append(ip)
                die(child, ip+': ERROR!\nIncorrect password Here is what SSH said:')
            elif i == 2:
                verbose_print(child.before)
                die(child, ip+': ERROR!\nEOF - Here is what SSH said:')
            elif i == 3:
                child.sendline ('set email enabled\r')
                # child.expect ('Command successful')
                child.expect ('Smart CDU:')
                child.sendline('exit')
            elif i == 4:
                child.sendline ('set email enabled\r')
                # child.expect ('Command successful')
                child.expect ('Smart PDU:')
                child.sendline('exit')
        queue.task_done()
def verbose_print(output):
    if (v is True):
        print(output)
def only_ldap_auto_config(): ##SSH into target devices to configure SNMP ##
    count_1 = 0
    print("\n ---------- Starting Automatic Configuration ---------- ") ##Could be implemented earlier to avoid wait times - but that would require prompting Y/N per device
    while (count_1 < len(old_admin_ssh)):
        #print(count_1)
        #print(len(fails))
        ip_address = old_admin_ssh[count_1]
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
                    ldap_host = ConfigSectionMap("global")['ldap_host']
                    ldap_port = ConfigSectionMap("global")['ldap_port']
                    ldap_bind = ConfigSectionMap("global")['ldap_bind']
                    #ldap_pass = ConfigSectionMap("global")['ldap_pass']
                    ldap_base = ConfigSectionMap("global")['ldap_base']
                    ldap_filter = ConfigSectionMap("global")['ldap_filter']
                    ldap_group_attr = ConfigSectionMap("global")['ldap_group_attr']
                    ldap_admin_group = ConfigSectionMap("global")['ldap_admin_group']
                    ldap_user_group = ConfigSectionMap("global")['ldap_user_group']
                    verifier = ConfigSectionMap(subnet)['verifier']
                    ver_1 = ConfigSectionMap(subnet)['ver_1']
                    ver_2 = ConfigSectionMap(subnet)['ver_2']
                count_2 += 1

            print('# Starting SSH session with Host '+str(count_1+1)+': '+ip_address+' #')
            child = pexpect.spawn ('sshpass -p "admn" ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss -oStrictHostKeyChecking=no admn@'+ip_address)
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
def xlsx_writer():
    alpha = [ "", "", "H", "I", "J", "K", "L", "M", "N", "O"]
    aer01_tally = 0
    alln01_tally = 0
    ast04_tally = 0
    bglnxtra1_tally = 0
    bxb200_tally = 0
    cardc01_tally = 0
    gpk03_tally = 0
    mtv5_tally = 0
    rcdn9_tally = 0
    rtp1_tally = 0
    rtp5_tally = 0
    sngdc01_tally = 0
    sngidc_tally = 0
    sjc05_tally = 0
    sjc12_tally = 0
    sjc20_tally = 0
    sjck_tally = 0
    stld1_tally = 0
    svl290_tally = 0

    results_xlsx = "results.xlsx"
    workbook = xlsxwriter.Workbook(results_xlsx)
    # cell_format.set_border(1)
    bold = workbook.add_format({'bold': True})
    bold.set_border(2)
    bold.set_border_color('black')
    value_format = workbook.add_format()
    value_format.set_border(1)
    bad = workbook.add_format({'bold': True})
    bad.set_font_color('red')
    bad.set_bg_color('#FEB4A4')
    bad.set_border(2)
    bad.set_border_color('red')
    good = workbook.add_format({'bold': True})
    good.set_font_color('green')
    good.set_bg_color('#66ff99')
    good.set_border(2)
    good.set_border_color('green')

    all_worksheet = workbook.add_worksheet('ALL')
    aer01sheet = workbook.add_worksheet('AER01')
    alln01sheet = workbook.add_worksheet('ALLN01')
    ast04sheet = workbook.add_worksheet('AST04')
    bglnxtra1sheet = workbook.add_worksheet('BGLNXTRA1')
    bxb200sheet = workbook.add_worksheet('BXB200')
    cardc01sheet = workbook.add_worksheet('CARDC01')
    gpk03sheet = workbook.add_worksheet('GPK03')
    mtv5sheet = workbook.add_worksheet('MTV5')
    rcdn9sheet = workbook.add_worksheet('RCDN9')
    rtp1sheet = workbook.add_worksheet('RTP1')
    rtp5sheet = workbook.add_worksheet('RTP5')
    sngdc01sheet = workbook.add_worksheet('SNGDC01')
    sngidcsheet = workbook.add_worksheet('SNGIDC')
    sjc05sheet = workbook.add_worksheet('SJC05')
    sjc12sheet = workbook.add_worksheet('SJC12')
    sjc20sheet = workbook.add_worksheet('SJC20')
    sjcksheet = workbook.add_worksheet('SJCK')
    stld1sheet = workbook.add_worksheet('STLD1')
    svl290sheet = workbook.add_worksheet('SVL290')

    for worksheet in workbook.worksheets():
        worksheet.set_column(0, 4, 14)
        worksheet.set_column(6, 6, 26)
        worksheet.set_column(13, 13, 13)
        worksheet.set_column(14, 14, 18)
        worksheet.set_column(15, 15, 1)
        worksheet.set_column(16, 18, 12)
        worksheet.write('A1', 'IP ADDRESS', bold)
        worksheet.write('B1', 'TOWER A S/N', bold)
        worksheet.write('C1', 'TOWER B S/N', bold)
        worksheet.write('D1', 'TOWER C S/N', bold)
        worksheet.write('E1', 'TOWER D S/N', bold)
        worksheet.write('F1', 'VERSION', bold)
        worksheet.write('G1', 'LOCATION', bold)
        worksheet.write('H1', 'PING', bold)
        worksheet.write('I1', 'SSH', bold)
        worksheet.write('J1', 'SNMP', bold)
        worksheet.write('K1', 'DNS', bold)
        worksheet.write('L1', 'SMTP', bold)
        worksheet.write('M1', 'LDAP', bold)
        worksheet.write('N1', 'CRIT ALERTS', bold)
        worksheet.write('O1', 'NON-DEFAULT PASS', bold)
    all_worksheet.write('Q1', 'TOTALS', bold)
    all_worksheet.write('R1', 'PASS', bold)
    all_worksheet.write('S1', 'FAIL', bold)
    all_worksheet.write('Q2', 'PING', bold)
    all_worksheet.write('Q3', 'SSH', bold)
    all_worksheet.write('Q4', 'SNMP', bold)
    all_worksheet.write('Q5', 'DNS', bold)
    all_worksheet.write('Q6', 'SMTP', bold)
    all_worksheet.write('Q7', 'LDAP', bold)
    all_worksheet.write('Q8', 'CRIT', bold)
    all_worksheet.write('Q9', 'PW', bold)
    all_worksheet.conditional_format('S2:S9', {'type': 'cell', 'criteria': '>', 'value': 0, 'format': bad})
    all_worksheet.conditional_format('R2:R2', {'type': 'cell', 'criteria': '==', 'value': length, 'format': good})
    all_worksheet.conditional_format('R3:R4', {'type': 'cell', 'criteria': '==', 'value': length - len(fail_pings), 'format': good})
    all_worksheet.conditional_format('R5:R8', {'type': 'cell', 'criteria': '==', 'value': length - (len(fail_ssh) + len(fail_pings)), 'format': good})
    all_worksheet.conditional_format('R9:R9', {'type': 'cell', 'criteria': '==', 'value': length - len(fail_pings), 'format': good})

    pass_totals_list = [ ping_passed, ssh_passed, snmp_passed, dns_passed, smtp_passed, ldap_passed, str(length - len(crit_alerts)), str(length - (len(default_password))) ]
    fail_totals_list = [ ping_failed, ssh_failed, snmp_failed, dns_failed, smtp_failed, ldap_failed, crit_alerts_num, str(len(default_password)) ]
    count = 0
    while (count < len(pass_totals_list)):
        all_worksheet.write('R'+str(count+2), int(pass_totals_list[count]), value_format)
        all_worksheet.write('S'+str(count+2), int(fail_totals_list[count]), value_format)
        count += 1

    count_1=count_2=count_3=count_4=count_5=count_6=count_7=count_8=count_9=count_10=count_11=count_12=count_13=count_14=count_15=count_16=count_17=count_18=count_19=count_20 = 0

    while (count_4 < len(results_dict)):
        ip_res = [results_dict["dic_"+str(count_4)]['ip_address']]
        ver_res = [results_dict["dic_"+str(count_4)]['version']]
        location = results_dict["dic_"+str(count_4)]['location']
        newlocation = location.split('.')
        location = newlocation[0]
        loc_res = [location.upper()]
        ping_res = [results_dict["dic_"+str(count_4)]['ping_status']]
        ssh_res = [results_dict["dic_"+str(count_4)]['ssh_status']]
        snmp_res = [results_dict["dic_"+str(count_4)]['snmp_status']]
        dns_res = [results_dict["dic_"+str(count_4)]['dns_status']]
        smtp_res = [results_dict["dic_"+str(count_4)]['smtp_status']]
        ldap_res = [results_dict["dic_"+str(count_4)]['ldap_status']]
        crit_res = [results_dict["dic_"+str(count_4)]['alerts']]
        tower_a = [results_dict["dic_"+str(count_4)]['tower_0']]
        tower_b = [results_dict["dic_"+str(count_4)]['tower_1']]
        tower_c = [results_dict["dic_"+str(count_4)]['tower_2']]
        tower_d = [results_dict["dic_"+str(count_4)]['tower_3']]
        d_password = [results_dict["dic_"+str(count_4)]['d_password']]

        from ConfigParser import SafeConfigParser
        with open("results.csv", "a") as csv_file: ## Pushes the results into the formatted .csv for each entry in results_dict ##
            writer = csv.writer(csv_file, delimiter=',')
            writer.writerow(ip_res + tower_a + tower_b + tower_c + tower_d + ver_res + loc_res + ping_res + ssh_res + snmp_res + dns_res + smtp_res + ldap_res + crit_res + d_password)
        # print(ip_res[0])

        all_worksheet.write('A'+str(count_4+2), ip_res[0])
        if (ip_res[0] in switched_cdu):
            all_worksheet.write('B'+str(count_4+2), "SWITCHED CDU")
        if ping_res[0] == "FALSE":
            all_worksheet.write('H'+str(count_4+2), ping_res[0], bad)
        else:
            all_worksheet.write('H'+str(count_4+2), ping_res[0])
            if snmp_res[0] == "TRUE":
                all_worksheet.write('J'+str(count_4+2), snmp_res[0])
            else:
                all_worksheet.write('J'+str(count_4+2), snmp_res[0], bad)
            if ssh_res[0] == "FALSE":
                all_worksheet.write('I'+str(count_4+2), ssh_res[0], bad)
            else:
                all_worksheet.write('I'+str(count_4+2), ssh_res[0])
                all_worksheet.write('B'+str(count_4+2), tower_a[0])
                all_worksheet.write('C'+str(count_4+2), tower_b[0])
                all_worksheet.write('D'+str(count_4+2), tower_c[0])
                all_worksheet.write('E'+str(count_4+2), tower_d[0])
                all_worksheet.write('F'+str(count_4+2), ver_res[0])
                all_worksheet.write('G'+str(count_4+2), loc_res[0])
                if ('STLD1' in loc_res[0]):
                    stld1_tally += 1
                    stld1sheet.write('H'+str(count_1+2), ping_res[0])
                    stld1sheet.write('A'+str(count_1+2), ip_res[0])
                    stld1sheet.write('J'+str(count_1+2), snmp_res[0])
                    stld1sheet.write('I'+str(count_1+2), ssh_res[0])
                    stld1sheet.write('B'+str(count_1+2), tower_a[0])
                    stld1sheet.write('C'+str(count_1+2), tower_b[0])
                    stld1sheet.write('D'+str(count_1+2), tower_c[0])
                    stld1sheet.write('E'+str(count_1+2), tower_d[0])
                    stld1sheet.write('F'+str(count_1+2), ver_res[0])
                    stld1sheet.write('G'+str(count_1+2), loc_res[0])
                    stld1sheet.write('K'+str(count_1+2), dns_res[0])
                    stld1sheet.write('L'+str(count_1+2), smtp_res[0])
                    stld1sheet.write('M'+str(count_1+2), ldap_res[0])
                    stld1sheet.write('N'+str(count_1+2), crit_res[0])
                    stld1sheet.write('O'+str(count_1+2), d_password[0])
                    count_1 += 1
                if ('RCDN9' in loc_res[0]):
                    rcdn9_tally += 1
                    rcdn9sheet.write('H'+str(count_2+2), ping_res[0])
                    rcdn9sheet.write('A'+str(count_2+2), ip_res[0])
                    rcdn9sheet.write('J'+str(count_2+2), snmp_res[0])
                    rcdn9sheet.write('I'+str(count_2+2), ssh_res[0])
                    rcdn9sheet.write('B'+str(count_2+2), tower_a[0])
                    rcdn9sheet.write('C'+str(count_2+2), tower_b[0])
                    rcdn9sheet.write('D'+str(count_2+2), tower_c[0])
                    rcdn9sheet.write('E'+str(count_2+2), tower_d[0])
                    rcdn9sheet.write('F'+str(count_2+2), ver_res[0])
                    rcdn9sheet.write('G'+str(count_2+2), loc_res[0])
                    rcdn9sheet.write('K'+str(count_2+2), dns_res[0])
                    rcdn9sheet.write('L'+str(count_2+2), smtp_res[0])
                    rcdn9sheet.write('M'+str(count_2+2), ldap_res[0])
                    rcdn9sheet.write('N'+str(count_2+2), crit_res[0])
                    rcdn9sheet.write('O'+str(count_2+2), d_password[0])
                    count_2 += 1
                if ('AER01' in loc_res[0]):
                    aer01_tally += 1
                    aer01sheet.write('H'+str(count_3+2), ping_res[0])
                    aer01sheet.write('A'+str(count_3+2), ip_res[0])
                    aer01sheet.write('J'+str(count_3+2), snmp_res[0])
                    aer01sheet.write('I'+str(count_3+2), ssh_res[0])
                    aer01sheet.write('B'+str(count_3+2), tower_a[0])
                    aer01sheet.write('C'+str(count_3+2), tower_b[0])
                    aer01sheet.write('D'+str(count_3+2), tower_c[0])
                    aer01sheet.write('E'+str(count_3+2), tower_d[0])
                    aer01sheet.write('F'+str(count_3+2), ver_res[0])
                    aer01sheet.write('G'+str(count_3+2), loc_res[0])
                    aer01sheet.write('K'+str(count_3+2), dns_res[0])
                    aer01sheet.write('L'+str(count_3+2), smtp_res[0])
                    aer01sheet.write('M'+str(count_3+2), ldap_res[0])
                    aer01sheet.write('N'+str(count_3+2), crit_res[0])
                    aer01sheet.write('O'+str(count_3+2), d_password[0])
                    count_3 += 1
                if ('ALLN01' in loc_res[0]):
                    alln01_tally += 1
                    alln01sheet.write('H'+str(count_5+2), ping_res[0])
                    alln01sheet.write('A'+str(count_5+2), ip_res[0])
                    alln01sheet.write('J'+str(count_5+2), snmp_res[0])
                    alln01sheet.write('I'+str(count_5+2), ssh_res[0])
                    alln01sheet.write('B'+str(count_5+2), tower_a[0])
                    alln01sheet.write('C'+str(count_5+2), tower_b[0])
                    alln01sheet.write('D'+str(count_5+2), tower_c[0])
                    alln01sheet.write('E'+str(count_5+2), tower_d[0])
                    alln01sheet.write('F'+str(count_5+2), ver_res[0])
                    alln01sheet.write('G'+str(count_5+2), loc_res[0])
                    alln01sheet.write('K'+str(count_5+2), dns_res[0])
                    alln01sheet.write('L'+str(count_5+2), smtp_res[0])
                    alln01sheet.write('M'+str(count_5+2), ldap_res[0])
                    alln01sheet.write('N'+str(count_5+2), crit_res[0])
                    alln01sheet.write('O'+str(count_5+2), d_password[0])
                    count_5 += 1
                if ('AST04' in loc_res[0]):
                    ast04_tally += 1
                    ast04sheet.write('H'+str(count_6+2), ping_res[0])
                    ast04sheet.write('H'+str(count_6+2), ping_res[0])
                    ast04sheet.write('A'+str(count_6+2), ip_res[0])
                    ast04sheet.write('J'+str(count_6+2), snmp_res[0])
                    ast04sheet.write('I'+str(count_6+2), ssh_res[0])
                    ast04sheet.write('B'+str(count_6+2), tower_a[0])
                    ast04sheet.write('C'+str(count_6+2), tower_b[0])
                    ast04sheet.write('D'+str(count_6+2), tower_c[0])
                    ast04sheet.write('E'+str(count_6+2), tower_d[0])
                    ast04sheet.write('F'+str(count_6+2), ver_res[0])
                    ast04sheet.write('G'+str(count_6+2), loc_res[0])
                    ast04sheet.write('K'+str(count_6+2), dns_res[0])
                    ast04sheet.write('L'+str(count_6+2), smtp_res[0])
                    ast04sheet.write('M'+str(count_6+2), ldap_res[0])
                    ast04sheet.write('N'+str(count_6+2), crit_res[0])
                    ast04sheet.write('O'+str(count_6+2), d_password[0])
                    count_6 += 1
                if ('BGLNXTRA1' in loc_res[0]):
                    bglnxtra1_tally += 1
                    bglnxtra1sheet.write('H'+str(count_7+2), ping_res[0])
                    bglnxtra1sheet.write('A'+str(count_7+2), ip_res[0])
                    bglnxtra1sheet.write('J'+str(count_7+2), snmp_res[0])
                    bglnxtra1sheet.write('I'+str(count_7+2), ssh_res[0])
                    bglnxtra1sheet.write('B'+str(count_7+2), tower_a[0])
                    bglnxtra1sheet.write('C'+str(count_7+2), tower_b[0])
                    bglnxtra1sheet.write('D'+str(count_7+2), tower_c[0])
                    bglnxtra1sheet.write('E'+str(count_7+2), tower_d[0])
                    bglnxtra1sheet.write('F'+str(count_7+2), ver_res[0])
                    bglnxtra1sheet.write('G'+str(count_7+2), loc_res[0])
                    bglnxtra1sheet.write('K'+str(count_7+2), dns_res[0])
                    bglnxtra1sheet.write('L'+str(count_7+2), smtp_res[0])
                    bglnxtra1sheet.write('M'+str(count_7+2), ldap_res[0])
                    bglnxtra1sheet.write('N'+str(count_7+2), crit_res[0])
                    bglnxtra1sheet.write('O'+str(count_7+2), d_password[0])
                    count_7 += 1
                if ('BXB200' in loc_res[0]):
                    bxb200_tally += 1
                    bxb200sheet.write('H'+str(count_8+2), ping_res[0])
                    bxb200sheet.write('A'+str(count_8+2), ip_res[0])
                    bxb200sheet.write('J'+str(count_8+2), snmp_res[0])
                    bxb200sheet.write('I'+str(count_8+2), ssh_res[0])
                    bxb200sheet.write('B'+str(count_8+2), tower_a[0])
                    bxb200sheet.write('C'+str(count_8+2), tower_b[0])
                    bxb200sheet.write('D'+str(count_8+2), tower_c[0])
                    bxb200sheet.write('E'+str(count_8+2), tower_d[0])
                    bxb200sheet.write('F'+str(count_8+2), ver_res[0])
                    bxb200sheet.write('G'+str(count_8+2), loc_res[0])
                    bxb200sheet.write('K'+str(count_8+2), dns_res[0])
                    bxb200sheet.write('L'+str(count_8+2), smtp_res[0])
                    bxb200sheet.write('M'+str(count_8+2), ldap_res[0])
                    bxb200sheet.write('N'+str(count_8+2), crit_res[0])
                    bxb200sheet.write('O'+str(count_8+2), d_password[0])
                    count_8 += 1
                if ('CARDC01' in loc_res[0]):
                    cardc01_tally += 1
                    cardc01sheet.write('H'+str(count_9+2), ping_res[0])
                    cardc01sheet.write('H'+str(count_9+2), ping_res[0])
                    cardc01sheet.write('A'+str(count_9+2), ip_res[0])
                    cardc01sheet.write('J'+str(count_9+2), snmp_res[0])
                    cardc01sheet.write('I'+str(count_9+2), ssh_res[0])
                    cardc01sheet.write('B'+str(count_9+2), tower_a[0])
                    cardc01sheet.write('C'+str(count_9+2), tower_b[0])
                    cardc01sheet.write('D'+str(count_9+2), tower_c[0])
                    cardc01sheet.write('E'+str(count_9+2), tower_d[0])
                    cardc01sheet.write('F'+str(count_9+2), ver_res[0])
                    cardc01sheet.write('G'+str(count_9+2), loc_res[0])
                    cardc01sheet.write('K'+str(count_9+2), dns_res[0])
                    cardc01sheet.write('L'+str(count_9+2), smtp_res[0])
                    cardc01sheet.write('M'+str(count_9+2), ldap_res[0])
                    cardc01sheet.write('N'+str(count_9+2), crit_res[0])
                    cardc01sheet.write('O'+str(count_9+2), d_password[0])
                    count_9 += 1
                if ('GPK03' in loc_res[0]):
                    gpk03_tally += 1
                    gpk03sheet.write('H'+str(count_10+2), ping_res[0])
                    gpk03sheet.write('A'+str(count_10+2), ip_res[0])
                    gpk03sheet.write('J'+str(count_10+2), snmp_res[0])
                    gpk03sheet.write('I'+str(count_10+2), ssh_res[0])
                    gpk03sheet.write('B'+str(count_10+2), tower_a[0])
                    gpk03sheet.write('C'+str(count_10+2), tower_b[0])
                    gpk03sheet.write('D'+str(count_10+2), tower_c[0])
                    gpk03sheet.write('E'+str(count_10+2), tower_d[0])
                    gpk03sheet.write('F'+str(count_10+2), ver_res[0])
                    gpk03sheet.write('G'+str(count_10+2), loc_res[0])
                    gpk03sheet.write('K'+str(count_10+2), dns_res[0])
                    gpk03sheet.write('L'+str(count_10+2), smtp_res[0])
                    gpk03sheet.write('M'+str(count_10+2), ldap_res[0])
                    gpk03sheet.write('N'+str(count_10+2), crit_res[0])
                    gpk03sheet.write('O'+str(count_10+2), d_password[0])
                    count_10 += 1
                if ('MTV5' in loc_res[0]):
                    mtv5_tally += 1
                    mtv5sheet.write('H'+str(count_11+2), ping_res[0])
                    mtv5sheet.write('A'+str(count_11+2), ip_res[0])
                    mtv5sheet.write('J'+str(count_11+2), snmp_res[0])
                    mtv5sheet.write('I'+str(count_11+2), ssh_res[0])
                    mtv5sheet.write('B'+str(count_11+2), tower_a[0])
                    mtv5sheet.write('C'+str(count_11+2), tower_b[0])
                    mtv5sheet.write('D'+str(count_11+2), tower_c[0])
                    mtv5sheet.write('E'+str(count_11+2), tower_d[0])
                    mtv5sheet.write('F'+str(count_11+2), ver_res[0])
                    mtv5sheet.write('G'+str(count_11+2), loc_res[0])
                    mtv5sheet.write('K'+str(count_11+2), dns_res[0])
                    mtv5sheet.write('L'+str(count_11+2), smtp_res[0])
                    mtv5sheet.write('M'+str(count_11+2), ldap_res[0])
                    mtv5sheet.write('N'+str(count_11+2), crit_res[0])
                    mtv5sheet.write('O'+str(count_11+2), d_password[0])
                    count_11 += 1
                if ('RTP1' in loc_res[0]):
                    rtp1_tally += 1
                    rtp1sheet.write('H'+str(count_12+2), ping_res[0])
                    rtp1sheet.write('A'+str(count_12+2), ip_res[0])
                    rtp1sheet.write('J'+str(count_12+2), snmp_res[0])
                    rtp1sheet.write('I'+str(count_12+2), ssh_res[0])
                    rtp1sheet.write('B'+str(count_12+2), tower_a[0])
                    rtp1sheet.write('C'+str(count_12+2), tower_b[0])
                    rtp1sheet.write('D'+str(count_12+2), tower_c[0])
                    rtp1sheet.write('E'+str(count_12+2), tower_d[0])
                    rtp1sheet.write('F'+str(count_12+2), ver_res[0])
                    rtp1sheet.write('G'+str(count_12+2), loc_res[0])
                    rtp1sheet.write('K'+str(count_12+2), dns_res[0])
                    rtp1sheet.write('L'+str(count_12+2), smtp_res[0])
                    rtp1sheet.write('M'+str(count_12+2), ldap_res[0])
                    rtp1sheet.write('N'+str(count_12+2), crit_res[0])
                    rtp1sheet.write('O'+str(count_12+2), d_password[0])
                    count_12 += 1
                if ('RTP5' in loc_res[0]):
                    rtp5_tally += 1
                    rtp5sheet.write('H'+str(count_13+2), ping_res[0])
                    rtp5sheet.write('A'+str(count_13+2), ip_res[0])
                    rtp5sheet.write('J'+str(count_13+2), snmp_res[0])
                    rtp5sheet.write('I'+str(count_13+2), ssh_res[0])
                    rtp5sheet.write('B'+str(count_13+2), tower_a[0])
                    rtp5sheet.write('C'+str(count_13+2), tower_b[0])
                    rtp5sheet.write('D'+str(count_13+2), tower_c[0])
                    rtp5sheet.write('E'+str(count_13+2), tower_d[0])
                    rtp5sheet.write('F'+str(count_13+2), ver_res[0])
                    rtp5sheet.write('G'+str(count_13+2), loc_res[0])
                    rtp5sheet.write('K'+str(count_13+2), dns_res[0])
                    rtp5sheet.write('L'+str(count_13+2), smtp_res[0])
                    rtp5sheet.write('M'+str(count_13+2), ldap_res[0])
                    rtp5sheet.write('N'+str(count_13+2), crit_res[0])
                    rtp5sheet.write('O'+str(count_13+2), d_password[0])
                    count_13 += 1
                if ('SNGDC01' in loc_res[0]):
                    sngdc01_tally += 1
                    sngdc01sheet.write('H'+str(count_14+2), ping_res[0])
                    sngdc01sheet.write('A'+str(count_14+2), ip_res[0])
                    sngdc01sheet.write('J'+str(count_14+2), snmp_res[0])
                    sngdc01sheet.write('I'+str(count_14+2), ssh_res[0])
                    sngdc01sheet.write('B'+str(count_14+2), tower_a[0])
                    sngdc01sheet.write('C'+str(count_14+2), tower_b[0])
                    sngdc01sheet.write('D'+str(count_14+2), tower_c[0])
                    sngdc01sheet.write('E'+str(count_14+2), tower_d[0])
                    sngdc01sheet.write('F'+str(count_14+2), ver_res[0])
                    sngdc01sheet.write('G'+str(count_14+2), loc_res[0])
                    sngdc01sheet.write('K'+str(count_14+2), dns_res[0])
                    sngdc01sheet.write('L'+str(count_14+2), smtp_res[0])
                    sngdc01sheet.write('M'+str(count_14+2), ldap_res[0])
                    sngdc01sheet.write('N'+str(count_14+2), crit_res[0])
                    sngdc01sheet.write('O'+str(count_14+2), d_password[0])
                    count_14 += 1
                if ('SNGIDC' in loc_res[0]):
                    sngidc_tally += 1
                    sngidcsheet.write('H'+str(count_15+2), ping_res[0])
                    sngidcsheet.write('A'+str(count_15+2), ip_res[0])
                    sngidcsheet.write('J'+str(count_15+2), snmp_res[0])
                    sngidcsheet.write('I'+str(count_15+2), ssh_res[0])
                    sngidcsheet.write('B'+str(count_15+2), tower_a[0])
                    sngidcsheet.write('C'+str(count_15+2), tower_b[0])
                    sngidcsheet.write('D'+str(count_15+2), tower_c[0])
                    sngidcsheet.write('E'+str(count_15+2), tower_d[0])
                    sngidcsheet.write('F'+str(count_15+2), ver_res[0])
                    sngidcsheet.write('G'+str(count_15+2), loc_res[0])
                    sngidcsheet.write('K'+str(count_15+2), dns_res[0])
                    sngidcsheet.write('L'+str(count_15+2), smtp_res[0])
                    sngidcsheet.write('M'+str(count_15+2), ldap_res[0])
                    sngidcsheet.write('N'+str(count_15+2), crit_res[0])
                    sngidcsheet.write('O'+str(count_15+2), d_password[0])
                    count_15 += 1
                if ('SJC05' in loc_res[0]):
                    sjc05_tally += 1
                    sjc05sheet.write('H'+str(count_16+2), ping_res[0])
                    sjc05sheet.write('A'+str(count_16+2), ip_res[0])
                    sjc05sheet.write('J'+str(count_16+2), snmp_res[0])
                    sjc05sheet.write('I'+str(count_16+2), ssh_res[0])
                    sjc05sheet.write('B'+str(count_16+2), tower_a[0])
                    sjc05sheet.write('C'+str(count_16+2), tower_b[0])
                    sjc05sheet.write('D'+str(count_16+2), tower_c[0])
                    sjc05sheet.write('E'+str(count_16+2), tower_d[0])
                    sjc05sheet.write('F'+str(count_16+2), ver_res[0])
                    sjc05sheet.write('G'+str(count_16+2), loc_res[0])
                    sjc05sheet.write('K'+str(count_16+2), dns_res[0])
                    sjc05sheet.write('L'+str(count_16+2), smtp_res[0])
                    sjc05sheet.write('M'+str(count_16+2), ldap_res[0])
                    sjc05sheet.write('N'+str(count_16+2), crit_res[0])
                    sjc05sheet.write('O'+str(count_16+2), d_password[0])
                    count_16 += 1
                if ('SJC12' in loc_res[0]):
                    sjc12_tally += 1
                    sjc12sheet.write('H'+str(count_17+2), ping_res[0])
                    sjc12sheet.write('A'+str(count_17+2), ip_res[0])
                    sjc12sheet.write('J'+str(count_17+2), snmp_res[0])
                    sjc12sheet.write('I'+str(count_17+2), ssh_res[0])
                    sjc12sheet.write('B'+str(count_17+2), tower_a[0])
                    sjc12sheet.write('C'+str(count_17+2), tower_b[0])
                    sjc12sheet.write('D'+str(count_17+2), tower_c[0])
                    sjc12sheet.write('E'+str(count_17+2), tower_d[0])
                    sjc12sheet.write('F'+str(count_17+2), ver_res[0])
                    sjc12sheet.write('G'+str(count_17+2), loc_res[0])
                    sjc12sheet.write('K'+str(count_17+2), dns_res[0])
                    sjc12sheet.write('L'+str(count_17+2), smtp_res[0])
                    sjc12sheet.write('M'+str(count_17+2), ldap_res[0])
                    sjc12sheet.write('N'+str(count_17+2), crit_res[0])
                    sjc12sheet.write('O'+str(count_17+2), d_password[0])
                    count_17 += 1
                if ('SJC20' in loc_res[0]):
                    sjc20_tally += 1
                    sjc12sheet.write('H'+str(count_18+2), ping_res[0])
                    sjc12sheet.write('A'+str(count_18+2), ip_res[0])
                    sjc12sheet.write('J'+str(count_18+2), snmp_res[0])
                    sjc12sheet.write('I'+str(count_18+2), ssh_res[0])
                    sjc12sheet.write('B'+str(count_18+2), tower_a[0])
                    sjc12sheet.write('C'+str(count_18+2), tower_b[0])
                    sjc12sheet.write('D'+str(count_18+2), tower_c[0])
                    sjc12sheet.write('E'+str(count_18+2), tower_d[0])
                    sjc12sheet.write('F'+str(count_18+2), ver_res[0])
                    sjc12sheet.write('G'+str(count_18+2), loc_res[0])
                    sjc12sheet.write('K'+str(count_18+2), dns_res[0])
                    sjc12sheet.write('L'+str(count_18+2), smtp_res[0])
                    sjc12sheet.write('M'+str(count_18+2), ldap_res[0])
                    sjc12sheet.write('N'+str(count_18+2), crit_res[0])
                    sjc12sheet.write('O'+str(count_18+2), d_password[0])
                    count_18 += 1
                if ('SJCK' in loc_res[0]):
                    sjck_tally += 1
                    sjcksheet.write('H'+str(count_19+2), ping_res[0])
                    sjcksheet.write('A'+str(count_19+2), ip_res[0])
                    sjcksheet.write('J'+str(count_19+2), snmp_res[0])
                    sjcksheet.write('I'+str(count_19+2), ssh_res[0])
                    sjcksheet.write('B'+str(count_19+2), tower_a[0])
                    sjcksheet.write('C'+str(count_19+2), tower_b[0])
                    sjcksheet.write('D'+str(count_19+2), tower_c[0])
                    sjcksheet.write('E'+str(count_19+2), tower_d[0])
                    sjcksheet.write('F'+str(count_19+2), ver_res[0])
                    sjcksheet.write('G'+str(count_19+2), loc_res[0])
                    sjcksheet.write('K'+str(count_19+2), dns_res[0])
                    sjcksheet.write('L'+str(count_19+2), smtp_res[0])
                    sjcksheet.write('M'+str(count_19+2), ldap_res[0])
                    sjcksheet.write('N'+str(count_19+2), crit_res[0])
                    sjcksheet.write('O'+str(count_19+2), d_password[0])
                    count_19 += 1
                if ('SVL290' in loc_res[0]):
                    svl290_tally += 1
                    svl290sheet.write('H'+str(count_20+2), ping_res[0])
                    svl290sheet.write('A'+str(count_20+2), ip_res[0])
                    svl290sheet.write('J'+str(count_20+2), snmp_res[0])
                    svl290sheet.write('I'+str(count_20+2), ssh_res[0])
                    svl290sheet.write('B'+str(count_20+2), tower_a[0])
                    svl290sheet.write('C'+str(count_20+2), tower_b[0])
                    svl290sheet.write('D'+str(count_20+2), tower_c[0])
                    svl290sheet.write('E'+str(count_20+2), tower_d[0])
                    svl290sheet.write('F'+str(count_20+2), ver_res[0])
                    svl290sheet.write('G'+str(count_20+2), loc_res[0])
                    svl290sheet.write('K'+str(count_20+2), dns_res[0])
                    svl290sheet.write('L'+str(count_20+2), smtp_res[0])
                    svl290sheet.write('M'+str(count_20+2), ldap_res[0])
                    svl290sheet.write('N'+str(count_20+2), crit_res[0])
                    svl290sheet.write('O'+str(count_20+2), d_password[0])
                    count_20 += 1
                all_worksheet.write('K'+str(count_4+2), dns_res[0])
                all_worksheet.write('L'+str(count_4+2), smtp_res[0])
                all_worksheet.write('L'+str(count_4+2), smtp_res[0])
                all_worksheet.write('M'+str(count_4+2), ldap_res[0])
                all_worksheet.write('N'+str(count_4+2), crit_res[0])
                all_worksheet.write('O'+str(count_4+2), d_password[0])
        count_4 += 1

    all_worksheet.write('Q11','REGION', bold)
    all_worksheet.write('R11','FOUND PDUs', bold)

    tally_names = ['ALL', 'AER01', 'ALLN01', 'AST04', 'BGLNXTRA1', 'BXB200', 'CARDC01', 'GPK03', 'MTV5', 'RCDN9', 'RTP1', 'RTP5', 'SNGDC01', 'SNGIDC', 'SJC05', 'SJC12', 'SJC20', 'SJCK', 'STLD1', 'SVL290' ]
    tallies = [len(pass_pings), aer01_tally, alln01_tally, ast04_tally, bglnxtra1_tally, bxb200_tally, cardc01_tally, gpk03_tally, mtv5_tally, rcdn9_tally, rtp1_tally, rtp5_tally, sngdc01_tally, sngidc_tally, sjc05_tally, sjc12_tally, sjc20_tally, sjck_tally, stld1_tally, svl290_tally ]
    count = 0
    while count < len(tallies):
        all_worksheet.write('Q'+str(count+12), tally_names[count], bold)
        all_worksheet.write('R'+str(count+12), tallies[count], value_format)
        count += 1


    serial_criteria = {'type': 'text', 'criteria': 'not containing', 'value': '0', 'format': bad}
    serial_criteria_2 = {'type': 'text', 'criteria': 'containing', 'value': '"*"', 'format': bad}
    true_conditional = {'type': 'text', 'criteria': 'containing', 'value': 'TRUE', 'format': bad}
    false_conditional = {'type': 'text', 'criteria': 'containing', 'value': 'FALSE', 'format': bad}
    ver_7_conditional = {'type': 'text', 'criteria': 'containing', 'value': '7.0', 'format': bad}
    ver_6_conditional = {'type': 'text', 'criteria': 'containing', 'value': '6', 'format': bad}

    all_worksheet.conditional_format(1, 1, length, 2, serial_criteria)
    all_worksheet.conditional_format(1, 3, length, 4, serial_criteria_2)
    all_worksheet.conditional_format(0, 0, length, 20, false_conditional)
    all_worksheet.conditional_format('F2:F'+str(length), ver_7_conditional)
    all_worksheet.conditional_format('F2:F'+str(length), ver_6_conditional)
    all_worksheet.conditional_format('N2:N'+str(length), true_conditional)

    stld1sheet.conditional_format(1, 1, stld1_tally, 2, serial_criteria)
    stld1sheet.conditional_format(1, 3, stld1_tally, 4, serial_criteria_2)
    stld1sheet.conditional_format(0, 0, stld1_tally, 20, false_conditional)
    stld1sheet.conditional_format('F2:F'+str(stld1_tally), ver_7_conditional)
    stld1sheet.conditional_format('F2:F'+str(stld1_tally), ver_6_conditional)
    stld1sheet.conditional_format('N2:N'+str(stld1_tally), true_conditional)

    rcdn9sheet.conditional_format(1, 1, rcdn9_tally, 2, serial_criteria)
    rcdn9sheet.conditional_format(1, 3, rcdn9_tally, 4, serial_criteria_2)
    rcdn9sheet.conditional_format(0, 0, rcdn9_tally, 20, false_conditional)
    rcdn9sheet.conditional_format('F2:F'+str(rcdn9_tally), ver_7_conditional)
    rcdn9sheet.conditional_format('F2:F'+str(rcdn9_tally), ver_6_conditional)
    rcdn9sheet.conditional_format('N2:N'+str(rcdn9_tally), true_conditional)

    aer01sheet.conditional_format(1, 1, aer01_tally, 2, serial_criteria)
    aer01sheet.conditional_format(1, 3, aer01_tally, 4, serial_criteria_2)
    aer01sheet.conditional_format(0, 0, aer01_tally, 20, false_conditional)
    aer01sheet.conditional_format('F2:F'+str(aer01_tally), ver_7_conditional)
    aer01sheet.conditional_format('F2:F'+str(aer01_tally), ver_6_conditional)
    aer01sheet.conditional_format('N2:N'+str(aer01_tally), true_conditional)

    alln01sheet.conditional_format(1, 1, alln01_tally, 2, serial_criteria)
    alln01sheet.conditional_format(1, 3, alln01_tally, 4, serial_criteria_2)
    alln01sheet.conditional_format(0, 0, alln01_tally, 20, false_conditional)
    alln01sheet.conditional_format('F2:F'+str(alln01_tally), ver_7_conditional)
    alln01sheet.conditional_format('F2:F'+str(alln01_tally), ver_6_conditional)
    alln01sheet.conditional_format('N2:N'+str(alln01_tally), true_conditional)

    ast04sheet.conditional_format(1, 1, ast04_tally, 2, serial_criteria)
    ast04sheet.conditional_format(1, 3, ast04_tally, 4, serial_criteria_2)
    ast04sheet.conditional_format(0, 0, ast04_tally, 20, false_conditional)
    ast04sheet.conditional_format('F2:F'+str(ast04_tally), ver_7_conditional)
    ast04sheet.conditional_format('F2:F'+str(ast04_tally), ver_6_conditional)
    ast04sheet.conditional_format('N2:N'+str(ast04_tally), true_conditional)

    bglnxtra1sheet.conditional_format(1, 1, bglnxtra1_tally, 2, serial_criteria)
    bglnxtra1sheet.conditional_format(1, 3, bglnxtra1_tally, 4, serial_criteria_2)
    bglnxtra1sheet.conditional_format(0, 0, bglnxtra1_tally, 20, false_conditional)
    bglnxtra1sheet.conditional_format('F2:F'+str(bglnxtra1_tally), ver_7_conditional)
    bglnxtra1sheet.conditional_format('F2:F'+str(bglnxtra1_tally), ver_6_conditional)
    bglnxtra1sheet.conditional_format('N2:N'+str(bglnxtra1_tally), true_conditional)

    bxb200sheet.conditional_format(1, 1, bxb200_tally, 2, serial_criteria)
    bxb200sheet.conditional_format(1, 3, bxb200_tally, 4, serial_criteria_2)
    bxb200sheet.conditional_format(0, 0, bxb200_tally, 20, false_conditional)
    bxb200sheet.conditional_format('F2:F'+str(bxb200_tally), ver_7_conditional)
    bxb200sheet.conditional_format('F2:F'+str(bxb200_tally), ver_6_conditional)
    bxb200sheet.conditional_format('N2:N'+str(bxb200_tally), true_conditional)

    cardc01sheet.conditional_format(1, 1, cardc01_tally, 2, serial_criteria)
    cardc01sheet.conditional_format(1, 3, cardc01_tally, 4, serial_criteria_2)
    cardc01sheet.conditional_format(0, 0, cardc01_tally, 20, false_conditional)
    cardc01sheet.conditional_format('F2:F'+str(cardc01_tally), ver_7_conditional)
    cardc01sheet.conditional_format('F2:F'+str(cardc01_tally), ver_6_conditional)
    cardc01sheet.conditional_format('N2:N'+str(cardc01_tally), true_conditional)

    gpk03sheet.conditional_format(1, 1, gpk03_tally, 2, serial_criteria)
    gpk03sheet.conditional_format(1, 3, gpk03_tally, 4, serial_criteria_2)
    gpk03sheet.conditional_format(0, 0, gpk03_tally, 20, false_conditional)
    gpk03sheet.conditional_format('F2:F'+str(gpk03_tally), ver_7_conditional)
    gpk03sheet.conditional_format('F2:F'+str(gpk03_tally), ver_6_conditional)
    gpk03sheet.conditional_format('N2:N'+str(gpk03_tally), true_conditional)

    mtv5sheet.conditional_format(1, 1, mtv5_tally, 2, serial_criteria)
    mtv5sheet.conditional_format(1, 3, mtv5_tally, 4, serial_criteria_2)
    mtv5sheet.conditional_format(0, 0, mtv5_tally, 20, false_conditional)
    mtv5sheet.conditional_format('F2:F'+str(mtv5_tally), ver_7_conditional)
    mtv5sheet.conditional_format('F2:F'+str(mtv5_tally), ver_6_conditional)
    mtv5sheet.conditional_format('N2:N'+str(mtv5_tally), true_conditional)

    rtp1sheet.conditional_format(1, 1, rtp1_tally, 2, serial_criteria)
    rtp1sheet.conditional_format(1, 3, rtp1_tally, 4, serial_criteria_2)
    rtp1sheet.conditional_format(0, 0, rtp1_tally, 20, false_conditional)
    rtp1sheet.conditional_format('F2:F'+str(rtp1_tally), ver_7_conditional)
    rtp1sheet.conditional_format('F2:F'+str(rtp1_tally), ver_6_conditional)
    rtp1sheet.conditional_format('N2:N'+str(rtp1_tally), true_conditional)

    rtp5sheet.conditional_format(1, 1, rtp5_tally, 2, serial_criteria)
    rtp5sheet.conditional_format(1, 3, rtp5_tally, 4, serial_criteria_2)
    rtp5sheet.conditional_format(0, 0, rtp5_tally, 20, false_conditional)
    rtp5sheet.conditional_format('F2:F'+str(rtp5_tally), ver_7_conditional)
    rtp5sheet.conditional_format('F2:F'+str(rtp5_tally), ver_6_conditional)
    rtp5sheet.conditional_format('N2:N'+str(rtp5_tally), true_conditional)

    sngdc01sheet.conditional_format(1, 1, sngdc01_tally, 2, serial_criteria)
    sngdc01sheet.conditional_format(1, 3, sngdc01_tally, 4, serial_criteria_2)
    sngdc01sheet.conditional_format(0, 0, sngdc01_tally, 20, false_conditional)
    sngdc01sheet.conditional_format('F2:F'+str(sngdc01_tally), ver_7_conditional)
    sngdc01sheet.conditional_format('F2:F'+str(sngdc01_tally), ver_6_conditional)
    sngdc01sheet.conditional_format('N2:N'+str(sngdc01_tally), true_conditional)

    sngidcsheet.conditional_format(1, 1, sngidc_tally, 2, serial_criteria)
    sngidcsheet.conditional_format(1, 3, sngidc_tally, 4, serial_criteria_2)
    sngidcsheet.conditional_format(0, 0, sngidc_tally, 20, false_conditional)
    sngidcsheet.conditional_format('F2:F'+str(sngidc_tally), ver_7_conditional)
    sngidcsheet.conditional_format('F2:F'+str(sngidc_tally), ver_6_conditional)
    sngidcsheet.conditional_format('N2:N'+str(sngidc_tally), true_conditional)

    sjc05sheet.conditional_format(1, 1, sjc05_tally, 2, serial_criteria)
    sjc05sheet.conditional_format(1, 3, sjc05_tally, 4, serial_criteria_2)
    sjc05sheet.conditional_format(0, 0, sjc05_tally, 20, false_conditional)
    sjc05sheet.conditional_format('F2:F'+str(sjc05_tally), ver_7_conditional)
    sjc05sheet.conditional_format('F2:F'+str(sjc05_tally), ver_6_conditional)
    sjc05sheet.conditional_format('N2:N'+str(sjc05_tally), true_conditional)

    sjc12sheet.conditional_format(1, 1, sjc12_tally, 2, serial_criteria)
    sjc12sheet.conditional_format(1, 3, sjc12_tally, 4, serial_criteria_2)
    sjc12sheet.conditional_format(0, 0, sjc12_tally, 20, false_conditional)
    sjc12sheet.conditional_format('F2:F'+str(sjc12_tally), ver_7_conditional)
    sjc12sheet.conditional_format('F2:F'+str(sjc12_tally), ver_6_conditional)
    sjc12sheet.conditional_format('N2:N'+str(sjc12_tally), true_conditional)

    sjc20sheet.conditional_format(1, 1, sjc20_tally, 2, serial_criteria)
    sjc20sheet.conditional_format(1, 3, sjc20_tally, 4, serial_criteria_2)
    sjc20sheet.conditional_format(0, 0, sjc20_tally, 20, false_conditional)
    sjc20sheet.conditional_format('F2:F'+str(sjc20_tally), ver_7_conditional)
    sjc20sheet.conditional_format('F2:F'+str(sjc20_tally), ver_6_conditional)
    sjc20sheet.conditional_format('N2:N'+str(sjc20_tally), true_conditional)

    sjcksheet.conditional_format(1, 1, sjck_tally, 2, serial_criteria)
    sjcksheet.conditional_format(1, 3, sjck_tally, 4, serial_criteria_2)
    sjcksheet.conditional_format(0, 0, sjck_tally, 20, false_conditional)
    sjcksheet.conditional_format('F2:F'+str(sjck_tally), ver_7_conditional)
    sjcksheet.conditional_format('F2:F'+str(sjck_tally), ver_6_conditional)
    sjcksheet.conditional_format('N2:N'+str(sjck_tally), true_conditional)

    svl290sheet.conditional_format(1, 1, svl290_tally, 2, serial_criteria)
    svl290sheet.conditional_format(1, 3, svl290_tally, 4, serial_criteria_2)
    svl290sheet.conditional_format(0, 0, svl290_tally, 20, false_conditional)
    svl290sheet.conditional_format('F2:F'+str(svl290_tally), ver_7_conditional)
    svl290sheet.conditional_format('F2:F'+str(svl290_tally), ver_6_conditional)
    svl290sheet.conditional_format('N2:N'+str(svl290_tally), true_conditional)

    workbook.close()
    spark_post_results(results_xlsx)
first_start_time = time.time()

##Reads latest scan file##
list_of_files = glob.glob('strip_scans/strips_*.csv') # * means all if need specific format then *.csv
latest_file = max(list_of_files, key=os.path.getctime)
verbose_print('Latest scan .csv is: ' + latest_file)
reader = csv.DictReader(open(latest_file, 'rb')) ##specify csv to read
dic = []
if (single_region is True):
    pdu_region = raw_input("Enter DC Region: (eg. 'STLD1')  ")
    pdu_region = (pdu_region.lower())
    print("Testing "+pdu_region+" PDUs")
    for line in reader:
        # print(line)
        if (pdu_region in str(line)):
            dic.append(line)
else:
    for line in reader:
        dic.append(line)

if (single_instance is True):
        dic = [{'ip_address': single_ip, 'subnet': single_subnet, 'location': 'single_test_ip'}]
        verbose_print(dic)

results_dict = {}
full_serial_dict = {}
length = len(dic) ##amount of devices to test/maintain (defualt is len(dic))
num_threads = 200 ##number of threads to run##
queue = Queue() ##maxsize = 0 ##
output = []
fails = [] ##ALL FAILS TO BE APPENDED TO THIS LIST IF NOT PRESENT ALREADY - EXCEPT SSH AND PING AS NO CONFIGURATION POSSIBLE##
temp_fails = []
pass_pings = []
fail_pings = []
pass_ssh = []
fail_ssh = []
pass_snmp = []
fail_snmp = []
pass_dns = []
fail_dns = []
pass_ldap = []
fail_ldap = []
pass_smtp = []
fail_smtp = []
email_disabled = []
ftp_update = []
updated_firmware_1 = []
updated_firmware_2 = []
old_firmware_1 = []
old_firmware_2 = []
old_firmware_3 = []
old_firmware_4 = []
crit_alerts = []
switched_cdu = []
old_admin_pass = []
old_admin_ssh = []
default_password = []
ip_address = ''
hostname = ''
location = ''
serial = ''
serial_a = ''
serial_b = ''
ldap_user = ""
ldap_pass = ""
z = 0
##Read subnets from subnet_lib##
subnets = []
with open('subnet_lib.txt', 'r') as myfile:
    subnets=myfile.read().split('\n')

##Import Variables from Config.ini##
from ConfigParser import SafeConfigParser
import ConfigParser
Config = ConfigParser.ConfigParser()
Config
Config.read('config.ini')
Config.sections() ##adds specific subnet headers from config.ini ##
subnets[:-1]

##Read ldap.cred into variables##
f = open("ldap.cred", "r")
f = f.read().split('\n')
ldap_user = f[0]
ldap_pass = f[1]

##Read admin.cred old passwords into list##
f = open("admin.cred", "r")
f = f.read().split('\n')
count = 0
while count < (len(f)-1):
    old_admin_pass.append(f[count])
    count += 1

print(' ################### STARTING PING THREAD  ################### ')
start_time = time.time()
count_2 = 0
while (count_2 < length): ##While less than ip amount, increment within length of imported IPs - PING ##
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

verbose_print(str(len(fail_pings))+'/'+str(len(dic))+' hosts failed PING test.')
verbose_print(fail_pings)
verbose_print('PAssed Pings: '+(str(len(pass_pings))))
verbose_print("--- PING took %s seconds ---" % (time.time() - start_time))

print(' ################### STARTING SSH THREAD ON (PINGABLE) '+str(len(pass_pings))+' HOSTS  ################### ')
start_time = time.time()
queue = Queue()
for i in range(num_threads):
    worker = Thread(target=ssh_test, args=(i, queue, serial, serial_a, serial_b))
    worker.setDaemon(True)
    worker.start()
verbose_print('starting ssh queue')
for ip in pass_pings:
    queue.put(ip)

verbose_print('waiting for queue')
queue.join()

verbose_print(pass_ssh)
verbose_print(fail_ssh)
verbose_print(str(len(fail_ssh))+'/'+str(len(dic))+' hosts failed SSH test.')
verbose_print("--- SSH took %s seconds ---" % (time.time() - start_time))
# verbose_print(full_serial_dict)

# print(' ################### STARTING LDAP THREAD ON (SSHABLE) '+str(len(pass_ssh))+' HOSTS  ################### ')
# start_time = time.time()
# queue = Queue()
# for i in range(num_threads):
#     worker = Thread(target=ldap_test, args=(i, queue))
#     worker.setDaemon(True)
#     worker.start()
# verbose_print('starting ldap queue')
# for ip in pass_ssh:
#     queue.put(ip)
# queue.join()
#
# verbose_print(pass_ldap)
# verbose_print(fail_ldap)
# verbose_print(str(len(fail_ldap))+'/'+str(len(dic))+' hosts failed LDAP test.')
# verbose_print("--- LDAP took %s seconds ---" % (time.time() - start_time))

print(' ################### STARTING Default Password THREAD ON (SSHABLE) '+str(len(pass_ssh))+' HOSTS  ################### ')
queue = Queue()
for i in range(num_threads):
    worker = Thread(target=default_password_test, args=(i, queue))
    worker.setDaemon(True)
    worker.start()
verbose_print('starting default password queue')
for ip in pass_pings:
    queue.put(ip)
queue.join()

verbose_print(default_password)
verbose_print(str(len(default_password))+'/'+str(len(dic))+' hosts have default admin passwords.')


# If any hosts are not the speicified firmware version, FPT settings will be applied and a restart requested##
if (len(ftp_update) > 0):
    print(' ################### STARTING FTP UPDATE ON '+str(len(ftp_update))+' HOSTS  ###################  ')
    verbose_print(ftp_update)
    auto_ftp_update()

##Threaded SNMP test that uses config.ini credentials to query system description MIB##
print(' ################### STARTING SNMP THREAD ON (PINGABLE) '+str(len(pass_pings))+' HOSTS  ################### ')
start_time = time.time()
queue = Queue()
verbose_print(pass_pings)
for i in range(num_threads):
    worker = Thread(target=snmp_test, args=(i, queue))
    worker.setDaemon(True)
    worker.start()
for ip in pass_pings:
    queue.put(ip)
queue.join()

verbose_print(str(len(fail_snmp))+'/'+str(len(dic))+' hosts failed SNMP test.')
verbose_print("---SNMP took %s seconds ---" % (time.time() - start_time))



print(' ################### GENERATING RESULTS  ################### ')
count_3 = 0
while (count_3 < len(results_dict)): ## Reads the pass/fail lists and adds a T/F statement to results_dict ##
    if results_dict["dic_"+str(count_3)]['ip_address'] in pass_pings:
        results_dict["dic_"+str(count_3)]["ping_status"] = 'TRUE'
    else:
        results_dict["dic_"+str(count_3)]["ping_status"] = 'FALSE'
    location = dic[count_3]["location"]
    results_dict["dic_"+str(count_3)]["location"] = location
    if results_dict["dic_"+str(count_3)]['ip_address'] in pass_ssh:
        results_dict["dic_"+str(count_3)]["ssh_status"] = 'TRUE'
    else:
        results_dict["dic_"+str(count_3)]["ssh_status"] = 'FALSE'
    if results_dict["dic_"+str(count_3)]['ip_address'] in pass_snmp:
        results_dict["dic_"+str(count_3)]["snmp_status"] = 'TRUE'
    else:
        results_dict["dic_"+str(count_3)]["snmp_status"] = 'FALSE'
    if results_dict["dic_"+str(count_3)]['ip_address'] in pass_dns:
        results_dict["dic_"+str(count_3)]["dns_status"] = 'TRUE'
    else:
        results_dict["dic_"+str(count_3)]["dns_status"] = 'FALSE'
    if results_dict["dic_"+str(count_3)]['ip_address'] in pass_smtp:
        results_dict["dic_"+str(count_3)]["smtp_status"] = 'TRUE'
    else:
        results_dict["dic_"+str(count_3)]["smtp_status"] = 'FALSE'
    if results_dict["dic_"+str(count_3)]['ip_address'] in pass_ldap:
        results_dict["dic_"+str(count_3)]["ldap_status"] = 'TRUE'
    else:
        results_dict["dic_"+str(count_3)]["ldap_status"] = 'FALSE'
    if results_dict["dic_"+str(count_3)]['ip_address'] in default_password:
        results_dict["dic_"+str(count_3)]["d_password"] = 'FALSE'
    else:
        results_dict["dic_"+str(count_3)]["d_password"] = 'TRUE'

    results_dict["dic_"+str(count_3)]["version"] = ' '
    if results_dict["dic_"+str(count_3)]['ip_address'] in updated_firmware_1:
        results_dict["dic_"+str(count_3)]["version"] = '8.0k'
    if results_dict["dic_"+str(count_3)]['ip_address'] in updated_firmware_2:
        results_dict["dic_"+str(count_3)]["version"] = '7.1b'
    if results_dict["dic_"+str(count_3)]['ip_address'] in old_firmware_1:
        results_dict["dic_"+str(count_3)]["version"] = '7.0p'
    if results_dict["dic_"+str(count_3)]['ip_address'] in old_firmware_2:
        results_dict["dic_"+str(count_3)]["version"] = '7.0t'
    if results_dict["dic_"+str(count_3)]['ip_address'] in old_firmware_3:
        results_dict["dic_"+str(count_3)]["version"] = '7.0g'
    if results_dict["dic_"+str(count_3)]['ip_address'] in old_firmware_4:
        results_dict["dic_"+str(count_3)]["version"] = '6.*'
   # if results_dict["dic_"+str(count_3)]['ip_address'] not in updated_firmware_1 or updated_firmware_2:
    # results_dict["dic_"+str(count_3)]["version"] = 'UNKNOWN'
    results_dict["dic_"+str(count_3)]["alerts"] = ' '
    results_dict["dic_"+str(count_3)]["tower_0"] = ''
    results_dict["dic_"+str(count_3)]["tower_1"] = ''
    results_dict["dic_"+str(count_3)]["tower_2"] = ''
    results_dict["dic_"+str(count_3)]["tower_3"] = ''
    if results_dict["dic_"+str(count_3)]['ip_address'] in crit_alerts:
        results_dict["dic_"+str(count_3)]["alerts"] = 'TRUE'
    uri = results_dict["dic_"+str(count_3)]['ip_address']
    if (uri in full_serial_dict):
        results_dict["dic_"+str(count_3)]["tower_0"] = full_serial_dict[uri]['0']
        results_dict["dic_"+str(count_3)]["tower_1"] = full_serial_dict[uri]['1']
        results_dict["dic_"+str(count_3)]["tower_2"] = full_serial_dict[uri]['2']
        results_dict["dic_"+str(count_3)]["tower_3"] = full_serial_dict[uri]['3']
    count_3 += 1
#
# with open("results.csv", "wb") as csv_file: ## correctly formats results.csv into columns ##
#     writer = csv.writer(csv_file, delimiter=',')
#     writer.writerow(['IP ADDRESS'] + ['TOWER A S/N'] + ['TOWER B S/N'] + ['TOWER C S/N'] + ['TOWER D S/N'] + ['VERSION'] + ['LOCATION'] + ['PING'] + ['SSH'] + ['SNMP'] + ['DNS'] + ['SMTP'] + ['LDAP'] + ['CRITICAL ALERTS'] + ['NON-DEFAULT PW'])

# worksheets = [ worksheet, stld1sheet, ast04sheet, rcdn9sheet, sngdc01sheet, gpk03sheet, sjc20sheet, cardc01sheet, bglnxtra1sheet, sjc05sheet, sjc12sheet, svl290sheet, mtv5sheet, bxb200sheet, rtp1sheet, aer01sheet, alln01sheet ]
# from datetime import datetime
# timestamp = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
# results_xlsx = "results_"+timestamp+".xlsx"

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
snmp_passed = str(len(pass_snmp))
snmp_failed = str(len(fail_snmp))
print(snmp_passed+'/'+ping_passed+' hosts are reachable by SNMP.')
print('The hosts that failed SNMP Testing include:'+str(fail_snmp))
dns_passed = str(len(pass_dns))
dns_failed = str(len(fail_dns))
print(dns_passed+'/'+ping_passed+' hosts have correct DNS configurations.')
print('The hosts that failed DNS testing include:'+str(fail_dns))
ldap_passed = str(len(pass_ldap))
ldap_failed = str(len(fail_ldap))
print(ldap_passed+'/'+ping_passed+' hosts have correct LDAP configurations.')
verbose_print('The hosts that failed LDAP testing include:'+str(fail_ldap))
smtp_passed = str(len(pass_smtp))
smtp_failed = str(len(fail_smtp))
print(smtp_passed+'/'+ping_passed+' hosts have correct SMTP configurations.')
print('The hosts that failed SMTP testing include:'+str(fail_smtp))
crit_alerts_num = str(len(crit_alerts))
print(crit_alerts_num+'/'+ping_passed+' hosts have critical alerts')
print('The hosts that have critical alerts include:'+str(crit_alerts))


print('Total Fails include:'+str(len(fails))+'\n'+(str(fails)))
print(str(len(updated_firmware_1)) + '/'+total+' hosts are on 8.0k firmware release. \n They are: '+str(updated_firmware_1))
print(str(len(updated_firmware_2)) + '/'+total+' hosts are on 7.1b firmware release. \n They are: '+str(updated_firmware_2))
print(str(len(old_firmware_1)) + '/'+total+' hosts are on 7.0p firmware release. \n They are: '+str(old_firmware_1))
print(str(len(old_firmware_2)) + '/'+total+' hosts are on 7.0t firmware release. \n They are: '+str(old_firmware_2))
if (len(default_password) > 0):
    print(str(len(default_password))+'/'+str(len(dic))+' hosts have default admin passwords.')
    default_password_detected(str(default_password))

xlsx_writer()
##If there are failures detectect -- Begin Automatic Configuration##
if (auto_config is not None or True):
    if (len(old_admin_ssh) > 0):
        only_ldap_auto_config()
        time.sleep(10)
    if (long(len(fails)) > 0):
        #answer = query_yes_no("Failures detected on on "+str(len(fails))+"/"+str(len(dic))+" - Try automatic configuration? (Default is no.)")
        #if (answer == False):
        #    end_session()
        #else:
        if (len(fail_snmp) > 0):
            set_snmp_enabled()

        auto_config_ssh()
    #
    #         # For V7.0s that don't SNMP walk after configuration - an additional restart may be necessary - snmp_restart()
    #     if (len(fail_snmp) > 0):
    #         verbose_print(' ################### STARTING SECOND SNMP THREAD ON '+str(len(fail_snmp))+' HOSTS  ################### ')
    #         second_fail_snmp = fail_snmp
    #         pass_snmp = []
    #         fail_snmp = []
    #         start_time = time.time()`<newline>': Block not closed..

    #         queue = Queue()
    #         for i in range(num_threads):
    #             worker = Thread(target=snmp_test, args=(i, queue))
    #             worker.setDaemon(True)
    #             worker.start()
    #         for ip in second_fail_snmp:
    #             queue.put(ip)
    #         queue.join()


    ## Re-enable Emails ##
print('########################## Re-enabling emails ###########################')
queue = Queue()
for i in range(num_threads):
    worker = Thread(target=email_enable, args=(i, queue, dic))
    worker.setDaemon(True)
    worker.start()
verbose_print('starting ssh queue')
fails = fails + email_disabled
for ip in fails:
    if ip not in fail_ssh:
        if ip not in fail_pings:
            if ip not in crit_alerts:
                if ip not in old_admin_ssh:
                    queue.put(ip)
            else:
                verbose_print(str(ip)+": PDU has a critical alert - not enabling email (excluding from list)")

verbose_print('waiting for task to complete.')
queue.join()

if ((len(default_password) > 0) or (len(old_admin_ssh) > 0)):
    print("Default Admin Passwords Found - If it failed, LDAP has now been configured - Please Run update_credentials.py. \n They include: \n "+str(old_admin_ssh) + "\n" + str(default_password))



    # verbose_print('waiting for task to complete.')
    # queue.join()

##If SNMP failures are detected again after Automatic Configuration##
print(email_disabled)


if len(switched_cdu) > 0:
    print("Switched CDUs detected! They are: " + str(switched_cdu))
#
# if (len(fail_snmp) > 0):
# #     print('SNMP fails still detected after auto-configuration, phyical inspection required. ')
# #     spark_post_resultsii()
#     # snmp_restart()
# else:
#     verbose_print("No hosts failed SNMPv3 connection.")

print("Ping, SSH, SNMPv3, LDAP, DNS and SMTP configuration checks have completed.")
