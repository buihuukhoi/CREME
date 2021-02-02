import os
from interface import implements
from .interfaces import IConfiguration, IConfigurationAttack
from .helper import ScriptHelper


class Machine:
    show_cmd = True

    # Controller's information
    controller_hostname = None
    controller_ip = None
    controller_username = None
    controller_password = None
    controller_path = None

    def __init__(self, hostname, ip, username, password, path):
        self.hostname = hostname
        self.ip = ip
        self.username = username
        self.password = password
        self.path = path

    def __str__(self):
        attrs = vars(self)
        return ', '.join("%s: %s" % item for item in attrs.items())


class DataLoggerServer(Machine, implements(IConfiguration)):
    def __init__(self, hostname, ip, username, password, path, network_interface, tcp_file="traffic.pcap",
                 tcp_pids_file="tcp_pids.txt", atop_interval=1):
        super().__init__(hostname, ip, username, password, path)
        self.path = path
        self.network_interface = network_interface
        self.tcp_file = tcp_file
        self.tcp_pids_file = tcp_pids_file
        self.atop_interval = atop_interval

    def configure_base(self):
        cmd, del_known_hosts_path = ScriptHelper.get_script_cmd("configuration/./DataLoggerServer_base.sh")
        cmd += " {0} {1} {2} {3}".format(del_known_hosts_path, self.ip, self.username, self.password)
        print(cmd) if self.show_cmd else os.system(cmd)

    def configure_data_collection(self):
        cmd, del_known_hosts_path = ScriptHelper.get_script_cmd("configuration/./DataLoggerServer_data_collection.sh")
        cmd += " {0} {1} {2} {3} {4} {5} {6} {7}".format(del_known_hosts_path, self.ip, self.username, self.password,
                                                         self.controller_ip, self.controller_username,
                                                         self.controller_password, self.controller_path)
        print(cmd) if self.show_cmd else os.system(cmd)


class DataLoggerClient(Machine, implements(IConfiguration)):
    dls = None  # store information of data logger server

    def __init__(self, hostname, ip, username, password, path, atop_pids_file="atop_pids.txt"):
        super().__init__(hostname, ip, username, password, path)
        self.path = path
        self.atop_file = "{0}.raw".format(hostname)
        self.atop_pids_file = atop_pids_file
        self.atop_interval = str(self.dls.atop_interval)
        self.rsyslog_apache = False  # True will be overridden by Benign and Target Servers

    def configure_base(self):
        cmd, del_known_hosts_path = ScriptHelper.get_script_cmd("configuration/./DataLoggerClient_base.sh")
        cmd += " {0} {1} {2} {3}".format(del_known_hosts_path, self.ip, self.username, self.password)
        print(cmd) if self.show_cmd else os.system(cmd)

    def configure_data_collection(self):
        if self.rsyslog_apache:
            rsyslog_file = "rsyslog_apache.conf"
        else:
            rsyslog_file = "rsyslog_no_apache.conf"
        cmd, del_known_hosts_path = ScriptHelper.get_script_cmd("configuration/./DataLoggerClient_data_collection.sh")
        cmd += " {0} {1} {2} {3} {4} {5} {6} {7} {8} {9}".format(del_known_hosts_path, self.ip, self.username,
                                                                 self.password, self.controller_ip,
                                                                 self.controller_username, self.controller_password,
                                                                 self.controller_path, self.dls.ip, rsyslog_file)
        print(cmd) if self.show_cmd else os.system(cmd)


class VulnerableClient(DataLoggerClient, implements(IConfiguration), implements(IConfigurationAttack)):
    def __init__(self, hostname, ip, username, password, path, server=None, ftp_folder="ftp_folder", sleep_second='2',
                 benign_pids_file="benign_pids.txt"):
        super().__init__(hostname, ip, username, password, path)
        self.server = server  # target server
        self.ftp_folder = ftp_folder
        last_ip = int(ip.split('.')[-1])
        self.virtual_account = "client{0}".format(str(last_ip))
        self.target_virtual_account = "client{0}".format(str(last_ip + 1))
        self.sleep_second = sleep_second
        self.benign_pids_file = benign_pids_file

    def configure_base(self):
        super().configure_base()

    def configure_data_collection(self):
        super().configure_data_collection()

    def configure_mirai(self):
        cmd, del_known_hosts_path = ScriptHelper.get_script_cmd("configuration/./VulnerableClient_mirai.sh")
        cmd += " {0} {1} {2} {3} {4} {5} {6} {7}".format(del_known_hosts_path, self.ip, self.username, self.password,
                                                         self.controller_ip, self.controller_username,
                                                         self.controller_password, self.controller_path)
        print(cmd) if self.show_cmd else os.system(cmd)

    def configure_ransomware(self):
        pass

    def configure_resource_hijacking(self):
        pass

    def configure_disk_wipe(self):
        pass

    def configure_end_point_dos(self):
        pass


class NonVulnerableClient(DataLoggerClient, implements(IConfiguration)):
    def __init__(self, hostname, ip, username, password, path, server=None, ftp_folder="ftp_folder", sleep_second='2',
                 benign_pids_file="benign_pids.txt"):
        super().__init__(hostname, ip, username, password, path)
        self.server = server  # benign server
        self.ftp_folder = ftp_folder
        last_ip = int(ip.split('.')[-1])
        self.virtual_account = "client{0}".format(str(last_ip))
        self.target_virtual_account = "client{0}".format(str(last_ip + 1))
        self.sleep_second = sleep_second
        self.benign_pids_file = benign_pids_file
        # something else

    def configure_base(self):
        super().configure_base()

    def configure_data_collection(self):
        super().configure_data_collection()


class TargetServer(DataLoggerClient, implements(IConfiguration), implements(IConfigurationAttack)):
    def __init__(self, hostname, ip, username, password, path, domain_name="speedlab.net", attacker_server_ip=""):
        super().__init__(hostname, ip, username, password, path)
        self.rsyslog_apache = True
        self.domain_name = domain_name
        self.attacker_server_ip = attacker_server_ip
        # something else

    def configure_base(self):
        super().configure_base()

    def configure_data_collection(self):
        super().configure_data_collection()

    def configure_mirai(self):
        pass

    def configure_ransomware(self):
        # ?????
        pass

    def configure_resource_hijacking(self):
        # ?????
        pass

    def configure_disk_wipe(self):
        # ?????
        pass

    def configure_end_point_dos(self):
        # ?????
        pass


class BenignServer(DataLoggerClient, implements(IConfiguration)):
    def __init__(self, hostname, ip, username, password, path, domain_name="speedlab.net", attacker_server_ip=""):
        super().__init__(hostname, ip, username, password, path)
        self.rsyslog_apache = True
        self.domain_name = domain_name
        self.attacker_server_ip = attacker_server_ip
        # something else

    def configure_base(self):
        super().configure_base()

    def configure_data_collection(self):
        super().configure_data_collection()


class AttackerServer(Machine, implements(IConfiguration), implements(IConfigurationAttack)):
    data_logger_server_ip = None

    def __init__(self, hostname, ip, username, password, path="/home/client1/Desktop/reinstall",
                 cnc_pids_file="cnc_pids.txt", transfer_pids_file="transfer_pids.txt", number_of_new_bots="3",
                 targeted_DDoS="", DDoS_type="udp", DDoS_duration="30"):
        super().__init__(hostname, ip, username, password, path)
        self.cnc_pids_file = cnc_pids_file
        self.transfer_pids_file = transfer_pids_file
        self.bot_input_files = []
        self.num_of_new_bots = number_of_new_bots
        self.targeted_DDoS = targeted_DDoS
        self.DDoS_type = DDoS_type
        self.DDoS_duration = DDoS_duration

    def configure_base(self):
        cmd, del_known_hosts_path = ScriptHelper.get_script_cmd("configuration/./AttackerServer_base.sh")
        cmd += " {0} {1} {2} {3}".format(del_known_hosts_path, self.ip, self.username, self.password)
        print(cmd) if self.show_cmd else os.system(cmd)

    def configure_data_collection(self):
        cmd, del_known_hosts_path = ScriptHelper.get_script_cmd("configuration/./AttackerServer_data_collection.sh")
        cmd += " {0} {1} {2} {3} {4}".format(del_known_hosts_path, self.ip, self.username, self.password,
                                             self.data_logger_server_ip)
        print(cmd) if self.show_cmd else os.system(cmd)

    def configure_mirai(self):
        cmd, del_known_hosts_path = ScriptHelper.get_script_cmd("configuration/./AttackerServer_mirai.sh")
        cmd += " {0} {1} {2} {3} {4} {5} {6} {7} {8} {9}".format(del_known_hosts_path, self.ip, self.username,
                                                                 self.password, self.path, self.controller_ip,
                                                                 self.controller_username, self.controller_password,
                                                                 self.controller_path, self.transfer_pids_file)

    def configure_ransomware(self):
        # ?????
        pass

    def configure_resource_hijacking(self):
        # ?????
        pass

    def configure_disk_wipe(self):
        # ?????
        pass

    def configure_end_point_dos(self):
        # ?????
        pass


class MaliciousClient(Machine, implements(IConfiguration), implements(IConfigurationAttack)):
    data_logger_server_ip = None
    attacker_server = None

    def __init__(self, hostname, ip, username, password, path, mirai_pids_file="mirai_pids.txt"):
        super().__init__(hostname, ip, username, password, path)
        self.path = path
        self.mirai_pids_file = mirai_pids_file
        # do something else

    def configure_base(self):
        cmd, del_known_hosts_path = ScriptHelper.get_script_cmd("configuration/./MaliciousClient_base.sh")
        cmd += " {0} {1} {2} {3}".format(del_known_hosts_path, self.ip, self.username, self.password)
        print(cmd) if self.show_cmd else os.system(cmd)

    def configure_data_collection(self):
        cmd, del_known_hosts_path = ScriptHelper.get_script_cmd("configuration/./MaliciousClient_data_collection.sh")
        cmd += " {0} {1} {2} {3} {4}".format(del_known_hosts_path, self.ip, self.username, self.password,
                                             self.data_logger_server_ip)
        print(cmd) if self.show_cmd else os.system(cmd)

    def configure_mirai(self):
        cmd, del_known_hosts_path = ScriptHelper.get_script_cmd("configuration/./MaliciousClient_mirai.sh")
        cmd += " {0} {1} {2} {3} {4} {5} {6} {7} {8}".format(del_known_hosts_path, self.ip, self.username,
                                                             self.password, self.path, self.attacker_server.ip,
                                                             self.attacker_server.username,
                                                             self.attacker_server.password, self.attacker_server.path)

    def configure_ransomware(self):
        # ?????
        pass

    def configure_resource_hijacking(self):
        # ?????
        pass

    def configure_disk_wipe(self):
        # ?????
        pass

    def configure_end_point_dos(self):
        # ?????
        pass
