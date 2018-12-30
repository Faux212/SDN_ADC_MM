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

def ssh():
    while True:
        print('Commencing SSH Session on '+ip)
        child = pexpect.spawn ('sshpass -p "correct" ssh -vvvv -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss -oStrictHostKeyChecking=no admn@'+ip)
        child.timeout=200
        i = child.expect([pexpect.TIMEOUT, 'Connection refused', pexpect.EOF, 'Smart CDU: ', 'Smart PDU: ', 'Switched CDU: '])
        #print(i)
        if i == 0:
            die(child, ip+': ERROR!\nSSH timed out. Here is what SSH said:')
        if i == 1:
            die(child, ip+': ERROR!\nIncorrect password Here is what SSH said:')
        elif i == 2:
            die(child, ip+': ERROR!\nEOF - Here is what SSH said:')
        elif i == 3:
            print(ip+': SSH TRUE - Smart CDU')
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
            print(ip+': SSH TRUE - Smart PDU')
            child.sendline("version\r")
            prompt = "Smart PDU: "
            child.expect(prompt)
            print("Disabling Email")
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
            print(ip+': SSH TRUE - Switched CDU')
        print("Ending SSH Session")
        return
def admin_update(child, prompt, version):
    if (version == 7):
        print(" -------- Setting Admin Password -------- ")
        child.sendline('set user password\r')
        child.expect('Username:')
        child.sendline('admn\r')
        child.expect('Password:')
        child.sendline(test_admin_pass+'\r')
        child.expect('Verify Password:')
        child.sendline(test_admin_pass+'\r')
        child.expect(prompt)
        print(" -------- DONE -------- ")
        return
    if (version == 8):
        print(" -------- Setting Admin Password -------- ")
        child.sendline('set user password\r')
        child.expect('Local user:')
        child.sendline('admn\r')
        child.expect('Password:')
        child.sendline(test_admin_pass+'\r')
        child.expect('Verify password:')
        child.sendline(test_admin_pass+'\r')
        child.expect(prompt)
        print(" -------- DONE -------- ")
        return
def ldap_setup(child, prompt, version):
    if (version == 7):
        print('-------- Setting Version 7 LDAP -------- ')
        #Set LDAP
        print('-------- Setting LDAP -------- ')
        child.sendline ('set ldap '+ldap_status+'\r')
        child.expect ('Command successful')
        ##Set Primary Host
        print('   -------- Setting LDAP Primary Host -------- ')
        child.expect (prompt)
        child.sendline ('set ldap host1 '+ldap_host+'\r')
        # child.expect ('Host/IP')
        # child.sendline (ldap_host+'\r')
        child.expect ('Command successful')
    ##Set Port
        print('   -------- Setting LDAP Port -------- ')
        child.expect (prompt)
        child.sendline ('set ldap port\r')
        child.expect ('LDAP Port')
        child.sendline (ldap_port+'\r')
        child.expect ('Command successful')

        print('   -------- Setting LDAP Bind TLS -------- ')
        child.expect (prompt)
        child.sendline ('set ldap bind tls\r')
        child.expect ('Command successful')

        print('   -------- Setting LDAP Bind DN -------- ')
        child.expect (prompt)
        child.sendline ('set ldap binddn\r')
        child.expect ('Enter Search Bind DN')
        child.sendline (ldap_bind+'\r') ##Need Confirmation##
        child.expect ('Command successful')

        print('   -------- Setting LDAP BIND PW -------- ')
        child.expect (prompt)
        child.sendline ('set ldap bindpw\r')
        child.expect ('Search Bind Password')
        child.sendline (ldap_pass+'\r')
        child.expect ('Command successful')

        print('   -------- Setting LDAP Base DN -------- ')
        child.expect (prompt)
        child.sendline ('set ldap userbasedn\r')
        child.expect ('Enter User Search Base')
        child.sendline (ldap_base+'\r') ##Need Confirmation##
        child.expect ('Command successful')

        print('   -------- Setting LDAP User Filter -------- ')
        child.expect (prompt)
        child.sendline ('set ldap userfilter\r')
        child.expect (' ')
        child.sendline (ldap_filter+'\r')
        child.expect ('Command successful')
        #print(child.before)

        print('   -------- Setting LDAP Group Attribute -------- ')
        child.expect (prompt)
        child.sendline ('set ldap groupattr\r')
        child.expect (' ')
        child.sendline (ldap_group_attr+'\r')
        child.expect ('Command successful')

        print('   -------- Disabling LDAP Group Search -------- ')
        child.expect (prompt)
        child.sendline ('set ldap groupsearch disabled\r')
        child.expect ('Command successful')

        print('   -------- Creating LDAP Admin Group -------- ')
        child.expect (prompt)
        child.sendline ('create ldapgroup '+ldap_admin_group+'\r')
        m = child.expect (['Command successful', 'command failed'])
        if m == 1:
            print('Admin Group exists')

        print('   -------- Creating LDAP User Group -------- ')
        child.expect (prompt)
        child.sendline ('create ldapgroup '+ldap_user_group+'\r')
        m = child.expect (['Command successful', 'command failed'])
        if m == 1:
            print('User Group exists')

        print('   -------- Setting LDAP Admin Group -------- ')
        child.expect (prompt)
        child.sendline ('set ldapgroup access admin\r')
        child.expect ('Group Name: ')
        child.sendline (ldap_admin_group+'\r')
        child.expect ('Command successful')

        print('   -------- Setting LDAP User Group -------- ')
        child.expect (prompt)
        child.sendline ('set ldapgroup access user\r')
        child.expect ('Group Name: ')
        child.sendline (ldap_user_group+'\r')
        child.expect ('Command successful')

        print('   -------- Disabling LDAP Group Search -------- ')
        child.expect (prompt)
        child.sendline ('set ldap groupsearch disabled\r')
        child.expect ('Command successful')
    if (version == 8):
        print('-------- Setting Version 8 LDAP -------- ')
        #Set LDAP
        print('-------- Setting LDAP -------- ')
        child.sendline ('set access method ldaplocal\r')
        child.expect ('Command successful')
        ##Set Primary Host
        print('   -------- Setting LDAP Primary Host -------- ')
        child.expect (prompt)
        child.sendline ('set ldap primary '+ldap_host+'\r')
        # child.expect ('Host/IP')
        # child.sendline (ldap_host+'\r')
        child.expect ('Command successful')
    ##Set Port
        print('   -------- Setting LDAP Port -------- ')
        child.expect (prompt)
        child.sendline ('set ldap port '+ldap_port+'\r')
        # child.expect ('LDAP Port')
        # child.sendline (ldap_port+'\r')
        child.expect ('Command successful')

        print('   -------- Setting LDAP Bind TLS -------- ')
        child.expect (prompt)
        child.sendline ('set ldap bind tls\r')
        child.expect ('Command successful')

        print('   -------- Setting LDAP Bind DN -------- ')
        child.expect (prompt)
        child.sendline ('set ldap binddn\r')
        child.expect ('LDAP search bind DN')
        child.sendline (ldap_bind+'\r') ##Need Confirmation##
        child.expect ('Command successful')

        print('   -------- Setting LDAP BIND PW -------- ')
        child.expect (prompt)
        child.sendline ('set ldap bindpw\r')
        child.expect ('search bind password')
        child.sendline (ldap_pass+'\r')
        child.expect ('Command successful')

        print('   -------- Setting LDAP Base DN -------- ')
        child.expect (prompt)
        child.sendline ('set ldap userbasedn\r')
        child.expect ('user search base DN')
        child.sendline (ldap_base+'\r') ##Need Confirmation##
        child.expect ('Command successful')

        print('   -------- Setting LDAP User Filter -------- ')
        child.expect (prompt)
        child.sendline ('set ldap userfilter\r')
        child.expect ('user search filter')
        child.sendline (ldap_filter+'\r')
        child.expect ('Command successful')
        #print(child.before)

        print('   -------- Setting LDAP Group Attribute -------- ')
        child.expect (prompt)
        child.sendline ('set ldap groupattr\r')
        child.expect ('membership attribute')
        child.sendline (ldap_group_attr+'\r')
        child.expect ('Command successful')

        print('   -------- Creating LDAP Admin Group -------- ')
        child.expect (prompt)
        child.sendline ('create ldapgroup '+ldap_admin_group+'\r')
        m = child.expect (['Command successful', 'command failed', 'Invalid request'])
        if m == 1 or 2:
            print('User Group exists')

        print('   -------- Creating LDAP User Group -------- ')
        child.expect (prompt)
        child.sendline ('create ldapgroup '+ldap_user_group+'\r')
        m = child.expect (['Command successful', 'command failed', 'Invalid request'])
        if m == 1 or 2:
            print('User Group exists')

        print('   -------- Setting LDAP Admin Group -------- ')
        child.expect (prompt)
        child.sendline ('set ldapgroup access admin\r')
        child.expect ('LDAP group: ')
        child.sendline (ldap_admin_group+'\r')
        child.expect ('Command successful')

        print('   -------- Setting LDAP User Group -------- ')
        child.expect (prompt)
        child.sendline ('set ldapgroup access user\r')
        child.expect ('LDAP group: ')
        child.sendline (ldap_user_group+'\r')
        child.expect ('Command successful')

        print('   -------- Disabling LDAP Group Search -------- ')
        child.expect (prompt)
        child.sendline ('set ldap groupsearch disabled\r')
        child.expect ('Command successful')
    #child.expect (prompt)
    return
def die(child, errstr): ##Function called when SSH error is encountered ##
    print(errstr)
    print(child.before)
    print(child.after)
    # child.terminate()
    print('PROCESS KILLED')
    child.close()
    print('PROCESS CLOSED')
    exit(1)

test_case = raw_input("Enter Test Case Number: ")
test_case = int(test_case)
ip = '10.67.73.52'
default_ldap_settings = False
ldap_change = True
admin_change = True

f = open("ldap.cred", "r")
f = f.read().split('\n')
ldap_user = f[0]
current_ldap_pass = f[1]

test_set_1 = [1, 4, 7]
test_set_2 = [2, 5, 8]
test_set_3 = [3, 6, 9]

ldap_test_set_1 = [1,2,3]
ldap_test_set_2 = [4,5,6]
ldap_test_set_3 = [7,8,9]

print("Setting Test Case Variables for #"+str(test_case))

##sets variables according to test case
if test_case in test_set_1:
    test_admin_pass = 'admn' ##default
if test_case in test_set_2:
    test_admin_pass = 'test' ##old pw
if test_case in test_set_3:
    test_admin_pass = 'correct' ##correct

print(test_case)
print(test_admin_pass)

if test_case in ldap_test_set_1:
    ldap_pass = 'Padl-5udp-cd#ti' ##correct
    ldap_host = 'ds.cisco.com'
    ldap_port = '636'
    ldap_bind = 'cn=itdc-pdu-ldap.gen,OU=Generics,OU=Cisco Users,DC=cisco,DC=com'
    ldap_base = 'OU=Cisco Users,DC=cisco,DC=com'
    ldap_filter = '(cn=%s)'
    ldap_group_attr = 'memberOf'
    ldap_admin_group = 'ITDC_PDU_ADMIN'
    ldap_user_group = 'ITDC_PDU_USER'
    ldap_status = 'enabled'
if test_case in ldap_test_set_2:
    ldap_pass = 'Padl-5udp-cd#ti_old' ##old
    ldap_host = 'ds.cisco.com'
    ldap_port = '636'
    ldap_bind = 'cn=itdc-pdu-ldap.gen,OU=Generics,OU=Cisco Users,DC=cisco,DC=com'
    ldap_base = 'OU=Cisco Users,DC=cisco,DC=com'
    ldap_filter = '(cn=%s)'
    ldap_group_attr = 'memberOf'
    ldap_admin_group = 'ITDC_PDU_ADMIN'
    ldap_user_group = 'ITDC_PDU_USER'
    ldap_status = 'enabled'
if test_case in ldap_test_set_3:
    default_ldap_settings = True
    ldap_pass = 'default' ##default/not set
    ldap_host = 'default'
    ldap_port = '636'
    ldap_bind = 'default'
    ldap_base = 'default'
    ldap_filter = 'default'
    ldap_group_attr = 'default'
    ldap_admin_group = 'default'
    ldap_user_group = 'default'
    ldap_status = 'disabled'

print(ldap_pass)
ssh()
