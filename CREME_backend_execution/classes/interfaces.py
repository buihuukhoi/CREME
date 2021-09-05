from interface import Interface


# ---------- configuration ----------
class IConfiguration(Interface):
    def configure(self):
        """
        this function calls all of necessary configurations for each machine.
        """
        pass


class IConfigurationCommon(Interface):
    """
    defining common configurations that should be implemented by all cases of machines:
    including DataLoggerServer, DataLoggerClient, VulnerableClient, NonVulnerableClient, TargetServer, BenignServer,
    AttackerServer, MaliciousClient
    """
    def configure_base(self):
        pass

    def configure_data_collection(self):
        pass


class IConfigurationBenign(Interface):
    """
    defining configurations for benign services that should be implemented by clients and servers:
    including VulnerableClient, NonVulnerableClient, TargetServer, BenignServer
    """
    def configure_benign_services(self):
        pass


class IConfigurationAttack(Interface):
    """
    defining configurations for attack scenarios that should be implemented by clients and servers:
    including VulnerableClient, TargetServer, AttackerServer, MaliciousClient
    """
    def configure_mirai(self):
        pass

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


class IConfigurationAttackerSide(Interface):
    """
    defining additional configurations for attacker side that should be implemented by attacker machines:
    including AttackerServer, MaliciousClient
    """

    def configure_pymetasploit(self):
       pass

    def configure_apache2(self):
       pass


# ---------- data collection ----------
class IDataCollection(Interface):
    def start_collect_data(self):
        pass

    def stop_collect_data(self):
        pass


class IDataCentralization(Interface):
    """
    defining functions to centralize data that should be implemented by the data logger server:
    """
    def centralize_data(self, data_logger_client, other_data=False, remote_paths=[], remote_files=[]):
        """
        using to centralize data from the data logger client to the data logger server
        :param data_logger_client: the machine which we want to centralize data from
        :param other_data: except atop files, whether we needs to collect other data at the data logger client or not
        :param remote_paths: paths correspond to files
        :param remote_files: files correspond to paths
        """
        pass

    def centralize_time_files(self, data_logger_client, time_files):
        """
        using to centralize time files from the data logger client to the data logger server
        :param data_logger_client: the machine which you want to centralize time files from
        :param time_files: name of time files you want to get from the remote machine
        """
        pass

    # def centralize_time_files(self, data_logger_client):
    #     pass


# ---------- benign behavior reproduction ----------
class IBenignReproduction(Interface):
    """
    defining actions for clients to generate benign behaviors to servers
    """
    def start_benign_behaviors(self):
        pass

    def stop_benign_behaviors(self):
        pass


# ---------- attacks ----------
class IAttack(Interface):
    """
    defining attack scenarios that should be implemented by Creme
    """
    def attack_mirai(self):
        pass

    def attack_ransomware(self):
        pass

    def attack_resource_hijacking(self):
        pass

    def attack_disk_wipe(self):
        pass

    def attack_end_point_dos(self):
        pass


class IMiraiAttackerServer(Interface):
    """
    defining actions of Mirai attack for the attacker server
    """
    def mirai_start_cnc_and_login(self):
        """
        starting cnc program and telnet login to cnc program to control bots
        """
        pass

    def mirai_wait_for_finished_scan(self):
        """
        waiting the malicious client to finish scanning new bots
        """
        pass

    def mirai_transfer_and_start_malicious(self):
        """
        cnc transfers malicious software (mirai) to new bots and run it (mirai)
        """
        pass

    def mirai_wait_for_finished_transfer(self):
        """
        cnc waits to finish transferring malicious software (mirai) to new bots.
        Then, cnc sends ddos commands to bots.
        """
        pass

    def mirai_wait_for_finished_ddos(self):
        """
        waiting to finish ddos attack.
        """
        pass


class IMiraiMaliciousClient(Interface):
    """
    defining actions of Mirai attack for the malicious client
    """
    def mirai_start_malicious(self):
        """
        starting the malicious software (mirai) at malicious client and scanning to find new bots.
        """
        pass

    def mirai_stop_malicious(self):
        """
        should stop the malicious software (mirai) before cnc transfers mirai to new bots.
        Otherwise, cnc may fail to telnet login to new bots. Because the ip range is small, the malicious client will
        continue to scan the bot even it already found the username and password.
        Contracting a list of existing bots may help to deal this problem.
        """
        pass


class IDiskWipeAttackerServer(Interface):
    """
    defining actions of Disk Wipe attack for the attacker server
    """
    def disk_wipe_start_metasploit(self):
        pass

    def disk_wipe_first_stage(self):
        pass

    def disk_wipe_second_stage(self):
        pass

    def disk_wipe_third_stage(self):
        pass


class IRansomwareAttackerServer(Interface):
    """
    defining actions of Ransomware attack for the attacker server
    """
    def ransomware_start_metasploit(self):
        pass

    def ransomware_first_stage(self):
        pass

    def ransomware_second_stage(self):
        pass

    def ransomware_third_stage(self):
        pass


class IResourceHijackingAttackerServer(Interface):
    """
    defining actions of Resource Hijacking attack for the attacker server
    """
    def resource_hijacking_start_metasploit(self):
        pass

    def resource_hijacking_first_stage(self):
        pass

    def resource_hijacking_second_stage(self):
        pass

    def resource_hijacking_third_stage(self):
        pass


class IEndPointDosAttackerServer(Interface):
    """
    defining actions of End Point Dos attack for the attacker server
    """
    def end_point_dos_start_metasploit(self):
        pass

    def end_point_dos_first_stage(self):
        pass

    def end_point_dos_second_stage(self):
        pass

    def end_point_dos_third_stage(self):
        pass


class IDataTheftAttackerServer(Interface):
    """
    defining actions of Data Theft attack for the attacker server
    """
    def data_theft_start_metasploit(self):
        pass

    def data_theft_first_stage(self):
        pass

    def data_theft_second_stage(self):
        pass

    def data_theft_third_stage(self):
        pass


class IRootkitRansomwareAttackerServer(Interface):
    """
    defining actions of Rootkit Ransomware attack for the attacker server
    """
    def rootkit_ransomware_start_metasploit(self):
        pass

    def rootkit_ransomware_first_stage(self):
        pass

    def rootkit_ransomware_second_stage(self):
        pass

    def rootkit_ransomware_third_stage(self):
        pass


# ---------- process cleaning ----------
class ICleaningBenignReproduction(Interface):
    """
    defining actions for clients to clean benign reproduction.
    should be implemented by VulnerableClient and NonVulnerableClient.
    """
    def clean_benign_reproduction(self):
        pass


class ICleaningAttackReproduction(Interface):
    """
    defining actions for attacker server to clean attack reproduction.
    should be implemented by AttackerServer.
    """
    def clean_mirai(self):
        pass

    def clean_disk_wipe(self):
        pass

    def clean_data_theft(self):
        pass

    def clean_ransomware(self):
        pass

    def clean_resource_hijacking(self):
        pass

    def clean_end_point_dos(self):
        pass

    def clean_rootkit_ransomware(self):
        pass


class ICleaningDataCollection(Interface):
    """
    defining actions to clean data collection.
    should be implemented by DataLoggerServer, TargetServer, and BenignServer.
    """
    def clean_data_collection(self):
        pass
