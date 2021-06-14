import os
from interface import implements
from .interfaces import IConfiguration, IConfigurationCommon, IConfigurationAttack, IConfigurationBenign,\
    IDataCollection, IDataCentralization, IBenignReproduction, IMiraiAttackerServer, IMiraiMaliciousClient,\
    ICleaningBenignReproduction, ICleaningAttackReproduction, IConfigurationAttackerSide, IDiskWipeAttackerServer,\
    IRansomwareAttackerServer, IResourceHijackingAttackerServer, IEndPointDosAttackerServer, IDataTheftAttackerServer,\
    IRootkitRansomwareAttackerServer
from .helper import ScriptHelper, OtherHelper
from .CREME import Creme
import time


class Machine:
    show_cmd = False  # a flag use to show cmd or execute cmd

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
                       implements(IDataCollection), implements(IDataCentralization)):
    """

    """
    def __init__(self, hostname, ip, username, password, path, network_interface, tcp_file="traffic.pcap",
                 tcp_pids_file="tcp_pids.txt", atop_interval=1, time_window_traffic=1):
        super().__init__(hostname, ip, username, password, path)
        self.path = path
        self.network_interface = network_interface
        self.tcp_file = tcp_file
        self.tcp_pids_file = tcp_pids_file
        self.atop_interval = atop_interval
        self.time_window_traffic = time_window_traffic

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

    def download_atop_data(self, data_logger_client):
        filename_path = "data_collection/./download_atop_data.sh"
        parameters = [self.ip, self.username, self.password, data_logger_client.ip, data_logger_client.username,
                      data_logger_client.password, data_logger_client.path, data_logger_client.atop_file, self.path]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def download_log_data(self, data_logger_client, remote_path, remote_log, new_log):
        filename_path = "data_collection/./download_log_data.sh"
        parameters = [self.ip, self.username, self.password, data_logger_client.ip, data_logger_client.username,
                      data_logger_client.password, remote_path, remote_log, self.path, new_log]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def download_time_file(self, data_logger_client, time_file):
        filename_path = "data_collection/./download_atop_data.sh"
        parameters = [self.ip, self.username, self.password, data_logger_client.ip, data_logger_client.username,
                      data_logger_client.password, data_logger_client.path, time_file, self.path]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def centralize_data(self, data_logger_client, contain_continuum_log=False):
        self.download_atop_data(data_logger_client)
        if contain_continuum_log:  # download apache continuum's log
            remote_path = '/opt/apache_continuum/apache-continuum-1.4.2/logs'
            remote_log = 'continuum.log'
            new_log = '{0}_continuum.log'.format(data_logger_client.hostname)
            self.download_log_data(data_logger_client, remote_path, remote_log, new_log)

    def centralize_time_files(self, data_logger_client, time_files):
        for time_file in time_files:
            self.download_time_file(data_logger_client, time_file)


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
        parameters = [self.ip, self.username, self.password, self.path, self.atop_file, self.atop_interval,
                      self.atop_pids_file, self.controller_ip, self.controller_username, self.controller_password,
                      self.controller_path]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_collect_data(self):
        filename_path = "data_collection/./stop_atop.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.atop_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)


class VulnerableClient(DataLoggerClient, implements(IConfiguration), implements(IConfigurationCommon),
                       implements(IConfigurationAttack), implements(IConfigurationBenign), implements(IDataCollection),
                       implements(IBenignReproduction), implements(ICleaningBenignReproduction)):
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
        self.configure_benign_services()
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
        if Creme.data_theft:
            self.configure_data_theft()
        if Creme.rootkit_ransomware:
            self.configure_rootkit_ransomware()

    def configure_base(self):
        super().configure_base()

    def configure_data_collection(self):
        super().configure_data_collection()

    def configure_benign_services(self):
        filename_path = "configuration/./Client_benign_services.sh"
        parameters = [self.hostname, self.ip, self.username, self.password, self.path, self.ftp_folder,
                      self.controller_ip, self.controller_username, self.controller_password, self.controller_path,
                      self.server.ip, self.virtual_account, self.server.domain_name]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

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

    def configure_data_theft(self):
        pass

    def configure_rootkit_ransomware(self):
        pass

    def start_benign_behaviors(self):
        filename_path = "configuration/./Client_start_benign_behaviors.sh"
        parameters = [self.hostname, self.ip, self.username, self.password, self.path, self.ftp_folder,
                      self.target_virtual_account, self.sleep_second, self.benign_pids_file, self.server.domain_name]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_benign_behaviors(self):
        filename_path = "./kill_pids.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.benign_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def clean_benign_reproduction(self):
        filename_path = "./kill_pids.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.benign_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def tmp_noexec(self):
        filename_path = "configuration/./VulnerableClient_tmp_noexec.sh"
        parameters = [self.ip, self.username, self.password, self.server.ip]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)


class NonVulnerableClient(DataLoggerClient, implements(IConfiguration), implements(IConfigurationCommon),
                          implements(IConfigurationBenign), implements(IDataCollection),
                          implements(IBenignReproduction), implements(ICleaningBenignReproduction)):
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
        self.configure_benign_services()

    def configure_base(self):
        super().configure_base()

    def configure_data_collection(self):
        super().configure_data_collection()

    def configure_benign_services(self):
        filename_path = "configuration/./Client_benign_services.sh"
        parameters = [self.hostname, self.ip, self.username, self.password, self.path, self.ftp_folder,
                      self.controller_ip, self.controller_username, self.controller_password, self.controller_path,
                      self.server.ip, self.virtual_account, self.server.domain_name]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def start_collect_data(self):
        super().start_collect_data()

    def stop_collect_data(self):
        super().stop_collect_data()

    def start_benign_behaviors(self):
        filename_path = "configuration/./Client_start_benign_behaviors.sh"
        parameters = [self.hostname, self.ip, self.username, self.password, self.path, self.ftp_folder,
                      self.target_virtual_account, self.sleep_second, self.benign_pids_file, self.server.domain_name]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_benign_behaviors(self):
        filename_path = "./kill_pids.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.benign_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def clean_benign_reproduction(self):
        filename_path = "./kill_pids.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.benign_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)


class TargetServer(DataLoggerClient, implements(IConfiguration), implements(IConfigurationCommon),
                   implements(IConfigurationAttack), implements(IConfigurationBenign), implements(IDataCollection),
                   implements(ICleaningAttackReproduction)):
    vulnerable_clients = None
    non_vulnerable_clients = None

    def __init__(self, hostname, ip, username, password, path, domain_name="speedlab.net", attacker_server_ip=""):
        super().__init__(hostname, ip, username, password, path)
        self.rsyslog_apache = True
        self.domain_name = domain_name
        self.attacker_server_ip = attacker_server_ip
        # something else

    def configure(self):
        self.configure_base()
        self.configure_data_collection()
        self.configure_benign_services()
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
        if Creme.data_theft:
            self.configure_data_theft()
        if Creme.rootkit_ransomware:
            self.configure_rootkit_ransomware()
        self.reboot()
        self.wait_machine_up()

    def configure_base(self):
        super().configure_base()

    def configure_data_collection(self):
        if self.rsyslog_apache:
            rsyslog_file = "rsyslog_apache.conf"
        else:
            rsyslog_file = "rsyslog_no_apache.conf"
        filename_path = "configuration/./TargetServer_data_collection.sh"
        parameters = [self.ip, self.username, self.password, self.controller_ip, self.controller_username,
                      self.controller_password, self.controller_path, self.dls.ip, rsyslog_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_benign_services(self):
        filename_path = "configuration/./Server_benign_services.sh"
        parameters = [self.hostname, self.ip, self.username, self.password, self.path, self.controller_ip,
                      self.controller_username, self.controller_password, self.controller_path, self.domain_name,
                      self.attacker_server_ip]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
        # add FTP users
        for client in self.vulnerable_clients:
            filename_path = "configuration/./Server_create_FTP_user.sh"
            parameters = [self.ip, self.username, self.password, client.hostname, client.password]
            ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
        for client in self.non_vulnerable_clients:
            filename_path = "configuration/./Server_create_FTP_user.sh"
            parameters = [self.ip, self.username, self.password, client.hostname, client.password]
            ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

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

    def configure_data_theft(self):
        pass

    def configure_rootkit_ransomware(self):
        pass

    def reboot(self):
        filename_path = "./reboot.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
        time.sleep(90)

    def wait_machine_up(self):
        OtherHelper.wait_machine_up(self.ip)

    def clean_mirai(self):
        pass

    def clean_disk_wipe(self):
        self.reboot()
        self.wait_machine_up()

    def clean_ransomware(self):
        self.reboot()
        self.wait_machine_up()

    def clean_resource_hijacking(self):
        self.reboot()
        self.wait_machine_up()

    def clean_end_point_dos(self):
        self.reboot()
        self.wait_machine_up()

    def clean_data_theft(self):
        self.reboot()
        self.wait_machine_up()

    def clean_rootkit_ransomware(self):
        self.reboot()
        self.wait_machine_up()


class BenignServer(DataLoggerClient, implements(IConfiguration), implements(IConfigurationCommon),
                   implements(IConfigurationBenign), implements(IDataCollection)):
    vulnerable_clients = None
    non_vulnerable_clients = None

    def __init__(self, hostname, ip, username, password, path, domain_name="speedlab.net", attacker_server_ip=""):
        super().__init__(hostname, ip, username, password, path)
        self.rsyslog_apache = True
        self.domain_name = domain_name
        self.attacker_server_ip = attacker_server_ip
        # something else

    def configure(self):
        self.configure_base()
        self.configure_data_collection()
        self.configure_benign_services()

    def configure_base(self):
        super().configure_base()

    def configure_data_collection(self):
        if self.rsyslog_apache:
            rsyslog_file = "rsyslog_apache.conf"
        else:
            rsyslog_file = "rsyslog_no_apache.conf"
        filename_path = "configuration/./TargetServer_data_collection.sh"  # similar to target_server
        parameters = [self.ip, self.username, self.password, self.controller_ip, self.controller_username,
                      self.controller_password, self.controller_path, self.dls.ip, rsyslog_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_benign_services(self):
        filename_path = "configuration/./Server_benign_services.sh"
        parameters = [self.hostname, self.ip, self.username, self.password, self.path, self.controller_ip,
                      self.controller_username, self.controller_password, self.controller_path, self.domain_name,
                      self.attacker_server_ip]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
        # add FTP users
        for client in self.vulnerable_clients:
            filename_path = "configuration/./Server_create_FTP_user.sh"
            parameters = [self.ip, self.username, self.password, client.hostname, client.password]
            ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
        for client in self.non_vulnerable_clients:
            filename_path = "configuration/./Server_create_FTP_user.sh"
            parameters = [self.ip, self.username, self.password, client.hostname, client.password]
            ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def start_collect_data(self):
        super().start_collect_data()

    def stop_collect_data(self):
        super().stop_collect_data()


class AttackerServer(Machine, implements(IConfiguration), implements(IConfigurationCommon),
                     implements(IConfigurationAttack), implements(IMiraiAttackerServer),
                     implements(ICleaningAttackReproduction), implements(IConfigurationAttackerSide),
                     implements(IDiskWipeAttackerServer), implements(IRansomwareAttackerServer),
                     implements(IResourceHijackingAttackerServer), implements(IEndPointDosAttackerServer),
                     implements(IDataTheftAttackerServer), implements(IRootkitRansomwareAttackerServer)):
    data_logger_server_ip = None
    DNS_server_ip = None
    mirai_o4_xxx_1 = None
    mirai_o4_xxx_2 = None

    def __init__(self, hostname, ip, username, password, path="/home/client1/Desktop/reinstall",
                 cnc_pids_file="cnc_pids.txt", transfer_pids_file="transfer_pids.txt", number_of_new_bots="3",
                 targeted_attack="", DDoS_type="udp", DDoS_duration="30"):
        super().__init__(hostname, ip, username, password, path)
        self.cnc_pids_file = cnc_pids_file
        self.transfer_pids_file = transfer_pids_file
        self.bot_input_files = []
        self.num_of_new_bots = number_of_new_bots
        self.targeted_attack = targeted_attack
        self.DDoS_type = DDoS_type
        self.DDoS_duration = DDoS_duration
        self.killed_pids_file = "killed_pids.txt"
        # self.flag_finish = "Creme_finish_attack_scenario"

    def configure(self):
        self.configure_base()
        self.configure_data_collection()
        if Creme.mirai:
            self.configure_mirai()
        if Creme.ransomware or Creme.resource_hijacking or Creme.disk_wipe or Creme.end_point_dos or \
                Creme.data_theft or Creme.rootkit_ransomware:
            self.configure_pymetasploit()
            self.configure_apache2()
        if Creme.ransomware:
            self.configure_ransomware()
        if Creme.resource_hijacking:
            self.configure_resource_hijacking()
        if Creme.disk_wipe:
            self.configure_disk_wipe()
        if Creme.end_point_dos:
            self.configure_end_point_dos()
        if Creme.data_theft:
            self.configure_data_theft()
        if Creme.rootkit_ransomware:
            self.configure_rootkit_ransomware()

    def configure_base(self):
        filename_path = "configuration/./AttackerServer_base.sh"
        parameters = [self.ip, self.username, self.password, self.controller_ip, self.controller_username,
                      self.controller_password, self.controller_path, self.DNS_server_ip]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_data_collection(self):
        filename_path = "configuration/./AttackerServer_data_collection.sh"
        parameters = [self.ip, self.username, self.password, self.data_logger_server_ip]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_mirai(self):
        ip_o = self.ip.split(".")
        mirai_dns_xxx = self.DNS_server_ip.replace(".", ",")

        filename_path = "configuration/./AttackerServer_mirai.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.controller_ip, self.controller_username,
                      self.controller_password, self.controller_path, self.transfer_pids_file, mirai_dns_xxx,
                      ip_o[0], ip_o[1], ip_o[2], '"' + self.mirai_o4_xxx_1 + '"', '"' + self.mirai_o4_xxx_2 + '"']
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_pymetasploit(self):
        filename_path = "configuration/./AttackerServer_pymetasploit.sh"
        parameters = [self.ip, self.username, self.password, self.path]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_apache2(self):
        filename_path = "configuration/./AttackerServer_apache2.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_ransomware(self):
        prepared_files = "CREME/CREME_backend_execution/scripts/configuration/prepared_files/ransomware/attacker_server"
        filename_path = "configuration/./AttackerServer_ransomware.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.controller_ip, self.controller_username,
                      self.controller_password, self.controller_path, prepared_files]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_resource_hijacking(self):
        prepared_files = "CREME/CREME_backend_execution/scripts/configuration/prepared_files/resource_hijacking/attacker_server"
        filename_path = "configuration/./AttackerServer_resource_hijacking.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.controller_ip, self.controller_username,
                      self.controller_password, self.controller_path, prepared_files]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_disk_wipe(self):
        prepared_files = "CREME/CREME_backend_execution/scripts/configuration/prepared_files/disk_wipe/attacker_server"
        filename_path = "configuration/./AttackerServer_disk_wipe.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.controller_ip, self.controller_username,
                      self.controller_password, self.controller_path, prepared_files]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_end_point_dos(self):
        prepared_files = "CREME/CREME_backend_execution/scripts/configuration/prepared_files/end_point_dos/attacker_server"
        filename_path = "configuration/./AttackerServer_end_point_dos.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.controller_ip, self.controller_username,
                      self.controller_password, self.controller_path, prepared_files]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_data_theft(self):
        prepared_files = "CREME/CREME_backend_execution/scripts/configuration/prepared_files/data_theft/attacker_server"
        filename_path = "configuration/./AttackerServer_data_theft.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.controller_ip, self.controller_username,
                      self.controller_password, self.controller_path, prepared_files]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_rootkit_ransomware(self):
        prepared_files = "CREME/CREME_backend_execution/scripts/configuration/prepared_files/rootkit_ransomware/attacker_server"
        filename_path = "configuration/./AttackerServer_rootkit_ransomware.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.controller_ip, self.controller_username,
                      self.controller_password, self.controller_path, prepared_files]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def mirai_start_cnc_and_login(self):
        filename_path = "attacks/mirai/./AttackerServer_start_cnc_and_login.sh"
        parameters = [self.hostname, self.ip, self.username, self.password, self.path, self.cnc_pids_file,
                      self.num_of_new_bots, self.targeted_attack, self.DDoS_type, self.DDoS_duration]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def mirai_wait_for_finished_scan(self):
        FinishedFile = "ScanFinishedFile.txt"

        filename_path = "attacks/mirai/./AttackerServer_wait_for_finished_phase.sh"
        parameters = [self.ip, self.username, self.password, self.path, FinishedFile]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def mirai_transfer_and_start_malicious(self):
        scan_flag = "0"
        input_bot = "input_bot"  # example: input_bot_192.168.1.112.txt
        logs_path = "CREME_backend_execution/logs/mirai/times"
        output_time = "time_2_start_transfer.txt"

        filename_path = "attacks/mirai/./AttackerServer_transfer_and_start_malicious.sh"
        parameters = [self.ip, self.username, self.password, self.path, input_bot, scan_flag, self.transfer_pids_file,
                      logs_path, output_time]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def mirai_wait_for_finished_transfer(self):
        FinishedFile = "TransferFinishedFile.txt"

        filename_path = "attacks/mirai/./AttackerServer_wait_for_finished_phase.sh"
        parameters = [self.ip, self.username, self.password, self.path, FinishedFile]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def mirai_wait_for_finished_ddos(self):
        FinishedFile = "ddosFinishedFile.txt"

        filename_path = "attacks/mirai/./AttackerServer_wait_for_finished_phase.sh"
        parameters = [self.ip, self.username, self.password, self.path, FinishedFile]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_malicious(self):
        filename_path = "attacks/mirai/./AttackerServer_cnc_stop_malicious.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.transfer_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_cnc_and_login(self):
        filename_path = "./kill_pids.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.cnc_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def clean_mirai(self):
        self.stop_malicious()
        self.stop_cnc_and_login()

    def disk_wipe_start_metasploit(self):
        filename_path = "attacks/disk_wipe/./AttackerServer_start_metasploit.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.killed_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def disk_wipe_first_stage(self):
        filename_path = "attacks/disk_wipe/./AttackerServer_first_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def disk_wipe_second_stage(self):
        filename_path = "attacks/disk_wipe/./AttackerServer_second_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def disk_wipe_third_stage(self):
        filename_path = "attacks/disk_wipe/./AttackerServer_third_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def ransomware_start_metasploit(self):
        filename_path = "attacks/ransomware/./AttackerServer_start_metasploit.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.killed_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def ransomware_first_stage(self):
        filename_path = "attacks/ransomware/./AttackerServer_first_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def ransomware_second_stage(self):
        filename_path = "attacks/ransomware/./AttackerServer_second_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def ransomware_third_stage(self):
        filename_path = "attacks/ransomware/./AttackerServer_third_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def resource_hijacking_start_metasploit(self):
        filename_path = "attacks/resource_hijacking/./AttackerServer_start_metasploit.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.killed_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def resource_hijacking_first_stage(self):
        filename_path = "attacks/resource_hijacking/./AttackerServer_first_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def resource_hijacking_second_stage(self):
        filename_path = "attacks/resource_hijacking/./AttackerServer_second_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def resource_hijacking_third_stage(self):
        filename_path = "attacks/resource_hijacking/./AttackerServer_third_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def end_point_dos_start_metasploit(self):
        filename_path = "attacks/end_point_dos/./AttackerServer_start_metasploit.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.killed_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def end_point_dos_first_stage(self):
        filename_path = "attacks/end_point_dos/./AttackerServer_first_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def end_point_dos_second_stage(self):
        filename_path = "attacks/end_point_dos/./AttackerServer_second_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def end_point_dos_third_stage(self):
        filename_path = "attacks/end_point_dos/./AttackerServer_third_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def data_theft_start_metasploit(self):
        filename_path = "attacks/data_theft/./AttackerServer_start_metasploit.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.killed_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def data_theft_first_stage(self):
        filename_path = "attacks/data_theft/./AttackerServer_first_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def data_theft_second_stage(self):
        filename_path = "attacks/data_theft/./AttackerServer_second_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def data_theft_third_stage(self):
        filename_path = "attacks/data_theft/./AttackerServer_third_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def rootkit_ransomware_start_metasploit(self):
        filename_path = "attacks/rootkit_ransomware/./AttackerServer_start_metasploit.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.killed_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def rootkit_ransomware_first_stage(self):
        filename_path = "attacks/rootkit_ransomware/./AttackerServer_first_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def rootkit_ransomware_second_stage(self):
        filename_path = "attacks/rootkit_ransomware/./AttackerServer_second_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def rootkit_ransomware_third_stage(self):
        filename_path = "attacks/rootkit_ransomware/./AttackerServer_third_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_metasploit(self):
        filename_path = "./kill_pids.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.killed_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def clean_disk_wipe(self):
        self.stop_metasploit()

    def clean_ransomware(self):
        self.stop_metasploit()

    def clean_resource_hijacking(self):
        self.stop_metasploit()

    def clean_end_point_dos(self):
        self.stop_metasploit()

    def clean_data_theft(self):
        self.stop_metasploit()

    def clean_rootkit_ransomware(self):
        self.stop_metasploit()


class MaliciousClient(Machine, implements(IConfiguration), implements(IConfigurationCommon),
                      implements(IConfigurationAttack), implements(IMiraiMaliciousClient),
                      implements(IConfigurationAttackerSide)):
    data_logger_server_ip = None
    attacker_server = None
    DNS_server_ip = None

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
        if Creme.ransomware or Creme.resource_hijacking or Creme.disk_wipe or Creme.end_point_dos or \
                Creme.data_theft or Creme.rootkit_ransomware:
            self.configure_pymetasploit()
            self.configure_apache2()
        if Creme.ransomware:
            self.configure_ransomware()
        if Creme.resource_hijacking:
            self.configure_resource_hijacking()
        if Creme.disk_wipe:
            self.configure_disk_wipe()
        if Creme.end_point_dos:
            self.configure_end_point_dos()
        if Creme.data_theft:
            self.configure_data_theft()
        if Creme.rootkit_ransomware:
            self.configure_rootkit_ransomware()

    def configure_base(self):
        filename_path = "configuration/./MaliciousClient_base.sh"
        parameters = [self.ip, self.username, self.password, self.controller_ip, self.controller_username,
                      self.controller_password, self.controller_path, self.DNS_server_ip]
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

    def configure_pymetasploit(self):
        pass

    def configure_apache2(self):
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

    def configure_data_theft(self):
        pass

    def configure_rootkit_ransomware(self):
        pass

    def mirai_start_malicious(self):
        logs_path = "CREME_backend_execution/logs/mirai/times"
        outputTime = "time_1_kali_start_scan.txt"

        filename_path = "attacks/mirai/./MaliciousClient_start_malicious.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.mirai_pids_file, logs_path, outputTime]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def mirai_stop_malicious(self):
        filename_path = "attacks/mirai/./MaliciousClient_stop_malicious.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.mirai_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
