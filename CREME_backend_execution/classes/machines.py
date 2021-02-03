import os
from interface import implements
from .interfaces import IConfiguration, IConfigurationCommon, IConfigurationAttack, IDataCollection
from .helper import ScriptHelper
from .CREME import Creme


class Machine:
    show_cmd = True  # a flag use to show cmd or execute cmd

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


class DataLoggerServer(Machine, implements(IConfiguration), implements(IConfigurationCommon),
                       implements(IDataCollection)):
    def __init__(self, hostname, ip, username, password, path, network_interface, tcp_file="traffic.pcap",
                 tcp_pids_file="tcp_pids.txt", atop_interval=1):
        super().__init__(hostname, ip, username, password, path)
        self.path = path
        self.network_interface = network_interface
        self.tcp_file = tcp_file
        self.tcp_pids_file = tcp_pids_file
        self.atop_interval = atop_interval

    def configure(self):
        self.configure_base()
        self.configure_data_collection()

    def configure_base(self):
        filename_path = "configuration/./DataLoggerServer_base.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_data_collection(self):
        filename_path = "configuration/./DataLoggerServer_data_collection.sh"
        parameters = [self.ip, self.username, self.password, self.controller_ip, self.controller_username,
                      self.controller_password, self.controller_path]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def start_collect_data(self):
        filename_path = "data_collection/./start_packet.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.tcp_file, self.network_interface,
                      self.tcp_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_collect_data(self):
        filename_path = "./kill_pids.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.tcp_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)


class DataLoggerClient(Machine, implements(IConfigurationCommon), implements(IDataCollection)):
    dls = None  # store information of data logger server

    def __init__(self, hostname, ip, username, password, path, atop_pids_file="atop_pids.txt"):
        super().__init__(hostname, ip, username, password, path)
        self.path = path
        self.atop_file = "{0}.raw".format(hostname)
        self.atop_pids_file = atop_pids_file
        self.atop_interval = str(self.dls.atop_interval)
        self.rsyslog_apache = False  # True will be overridden by Benign and Target Servers

    def configure_base(self):
        filename_path = "configuration/./DataLoggerClient_base.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_data_collection(self):
        if self.rsyslog_apache:
            rsyslog_file = "rsyslog_apache.conf"
        else:
            rsyslog_file = "rsyslog_no_apache.conf"
        filename_path = "configuration/./DataLoggerClient_data_collection.sh"
        parameters = [self.ip, self.username, self.password, self.controller_ip, self.controller_username,
                      self.controller_password, self.controller_path, self.dls.ip, rsyslog_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def start_collect_data(self):
        filename_path = "data_collection/./start_atop.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.atop_file, self.interval,
                      self.atop_pids_file, self.controller_ip, self.controller_username, self.controller_password,
                      self.controller_path]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_collect_data(self):
        filename_path = "./kill_pids.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.atop_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)


class VulnerableClient(DataLoggerClient, implements(IConfiguration), implements(IConfigurationCommon),
                       implements(IConfigurationAttack), implements(IDataCollection)):
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

    def configure(self):
        self.configure_base()
        self.configure_data_collection()
        if Creme.mirai:
            self.configure_mirai()
        if Creme.ransomware:
            self.configure_ransomware()
        if Creme.resource_hijacking:
            self.configure_resource_hijacking()
        if Creme.disk_wipe:
            self.configure_disk_wipe()
        if Creme.end_point_dos:
            self.configure_end_point_dos()

    def configure_base(self):
        super().configure_base()

    def configure_data_collection(self):
        super().configure_data_collection()

    def start_collect_data(self):
        super().start_collect_data()

    def stop_collect_data(self):
        super().stop_collect_data()

    def configure_mirai(self):
        filename_path = "configuration/./VulnerableClient_mirai.sh"
        parameters = [self.ip, self.username, self.password, self.controller_ip, self.controller_username,
                      self.controller_password, self.controller_path]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_ransomware(self):
        pass

    def configure_resource_hijacking(self):
        pass

    def configure_disk_wipe(self):
        pass

    def configure_end_point_dos(self):
        pass


class NonVulnerableClient(DataLoggerClient, implements(IConfiguration), implements(IConfigurationCommon),
                          implements(IDataCollection)):
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

    def configure(self):
        self.configure_base()
        self.configure_data_collection()

    def configure_base(self):
        super().configure_base()

    def configure_data_collection(self):
        super().configure_data_collection()

    def start_collect_data(self):
        super().start_collect_data()

    def stop_collect_data(self):
        super().stop_collect_data()


class TargetServer(DataLoggerClient, implements(IConfiguration), implements(IConfigurationCommon),
                   implements(IConfigurationAttack), implements(IDataCollection)):
    def __init__(self, hostname, ip, username, password, path, domain_name="speedlab.net", attacker_server_ip=""):
        super().__init__(hostname, ip, username, password, path)
        self.rsyslog_apache = True
        self.domain_name = domain_name
        self.attacker_server_ip = attacker_server_ip
        # something else

    def configure(self):
        self.configure_base()
        self.configure_data_collection()
        if Creme.mirai:
            self.configure_mirai()
        if Creme.ransomware:
            self.configure_ransomware()
        if Creme.resource_hijacking:
            self.configure_resource_hijacking()
        if Creme.disk_wipe:
            self.configure_disk_wipe()
        if Creme.end_point_dos:
            self.configure_end_point_dos()

    def configure_base(self):
        super().configure_base()

    def configure_data_collection(self):
        super().configure_data_collection()

    def start_collect_data(self):
        super().start_collect_data()

    def stop_collect_data(self):
        super().stop_collect_data()

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


class BenignServer(DataLoggerClient, implements(IConfiguration), implements(IConfigurationCommon),
                   implements(IDataCollection)):
    def __init__(self, hostname, ip, username, password, path, domain_name="speedlab.net", attacker_server_ip=""):
        super().__init__(hostname, ip, username, password, path)
        self.rsyslog_apache = True
        self.domain_name = domain_name
        self.attacker_server_ip = attacker_server_ip
        # something else

    def configure(self):
        self.configure_base()
        self.configure_data_collection()

    def configure_base(self):
        super().configure_base()

    def configure_data_collection(self):
        super().configure_data_collection()

    def start_collect_data(self):
        super().start_collect_data()

    def stop_collect_data(self):
        super().stop_collect_data()


class AttackerServer(Machine, implements(IConfiguration), implements(IConfigurationCommon),
                     implements(IConfigurationAttack)):
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

    def configure(self):
        self.configure_base()
        self.configure_data_collection()
        if Creme.mirai:
            self.configure_mirai()
        if Creme.ransomware:
            self.configure_ransomware()
        if Creme.resource_hijacking:
            self.configure_resource_hijacking()
        if Creme.disk_wipe:
            self.configure_disk_wipe()
        if Creme.end_point_dos:
            self.configure_end_point_dos()

    def configure_base(self):
        filename_path = "configuration/./AttackerServer_base.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_data_collection(self):
        filename_path = "configuration/./AttackerServer_data_collection.sh"
        parameters = [self.ip, self.username, self.password, self.data_logger_server_ip]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_mirai(self):
        filename_path = "configuration/./AttackerServer_mirai.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.controller_ip, self.controller_username,
                      self.controller_password, self.controller_path, self.transfer_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

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


class MaliciousClient(Machine, implements(IConfiguration), implements(IConfigurationCommon),
                      implements(IConfigurationAttack)):
    data_logger_server_ip = None
    attacker_server = None

    def __init__(self, hostname, ip, username, password, path, mirai_pids_file="mirai_pids.txt"):
        super().__init__(hostname, ip, username, password, path)
        self.path = path
        self.mirai_pids_file = mirai_pids_file
        # do something else

    def configure(self):
        self.configure_base()
        self.configure_data_collection()
        if Creme.mirai:
            self.configure_mirai()
        if Creme.ransomware:
            self.configure_ransomware()
        if Creme.resource_hijacking:
            self.configure_resource_hijacking()
        if Creme.disk_wipe:
            self.configure_disk_wipe()
        if Creme.end_point_dos:
            self.configure_end_point_dos()

    def configure_base(self):
        filename_path = "configuration/./MaliciousClient_base.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_data_collection(self):
        filename_path = "configuration/./MaliciousClient_data_collection.sh"
        parameters = [self.ip, self.username, self.password, self.data_logger_server_ip]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_mirai(self):
        filename_path = "configuration/./MaliciousClient_mirai.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.attacker_server.ip,
                      self.attacker_server.username, self.attacker_server.password, self.attacker_server.path]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

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
