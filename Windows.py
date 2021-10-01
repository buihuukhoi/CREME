import os
import time
import paramiko
from scp import SCPClient
import numpy as np
import pandas as pd
import json
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import ExtraTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from xgboost import XGBClassifier
from sklearn import preprocessing
from sklearn.model_selection import StratifiedKFold
from sklearn.model_selection import cross_validate
from sklearn.feature_selection import RFECV
import csv

class Creme:
    disk_wipe = True
    cred_steal = True

    models_name = ['decision_tree', 'random_forest', 'extra_tree', 'knn', 'naive_bayes']
    def __init__(self, dls, vulnerable_clients, non_vulnerable_clients, attacker_server, disk_wipe, cred_steal):
        # self.stage = 0
        # self.status = 1
        # self.finishedTasks = []
        # self.messages = []
        # self.sizes = []
        # self.finishedStageList = []
        # Helper.clearProgressData()

        # Machines
        self.dls = dls
        self.vulnerable_clients = vulnerable_clients
        self.non_vulnerable_clients = non_vulnerable_clients
        self.attacker_server = attacker_server


        # Attack scenarios. True/False

        Creme.disk_wipe = disk_wipe
        Creme.cred_steal = cred_steal



    def configure(self):

        # stage = 1
        # ProgressHelper.update_stage(stage, f"Controller is configuring {self.dls.hostname}", 5, new_stage=True)
        self.dls.configure()
        # ProgressHelper.update_stage(stage, f"Controller FINISHED configuring {self.dls.hostname}", 5,
        #                            finished_task=True, override_pre_message=True)

        for vulnerable_client in self.vulnerable_clients:
            # ProgressHelper.update_stage(stage, f"Controller is configuring {vulnerable_client.hostname}", 5)
            vulnerable_client.configure()
            # ProgressHelper.update_stage(stage, f"Controller FINISHED configuring {vulnerable_client.hostname}", 5,
            #                            finished_task=True, override_pre_message=True)

        for non_vulnerable_client in self.non_vulnerable_clients:
            # ProgressHelper.update_stage(stage, f"Controller is configuring {non_vulnerable_client.hostname}", 5)
            non_vulnerable_client.configure()
            # ProgressHelper.update_stage(stage, f"Controller FINISHED configuring {non_vulnerable_client.hostname}", 5,
            #                            finished_task=True, override_pre_message=True)
        # ProgressHelper.update_stage(stage, f"Controller is configuring {self.attacker_server.hostname}", 5)

        self.attacker_server.configure()
        # ProgressHelper.update_stage(stage, f"Controller FINISHED configuring {self.attacker_server.hostname}", 5,
        #                            finished_task=True, override_pre_message=True)

    # ---------- data collection ----------
    def start_collect_data(self):
        for vulnerable_client in self.vulnerable_clients:
            vulnerable_client.start_collect_data()
        for non_vulnerable_client in self.non_vulnerable_clients:
            non_vulnerable_client.start_collect_data()

    def stop_collect_data(self):
        for vulnerable_client in self.vulnerable_clients:
            vulnerable_client.stop_collect_data()
        for non_vulnerable_client in self.non_vulnerable_clients:
            non_vulnerable_client.stop_collect_data()

    def centralize_data(self):
        """
        using to centralize data from the data logger client to the data logger server
        :param contain_continuum_log: whether the attack scenario should collect log of apache continuum server or not
        """
        for vulnerable_client in self.vulnerable_clients:
            self.dls.centralize_data(vulnerable_client)
        for non_vulnerable_client in self.non_vulnerable_clients:
            self.dls.centralize_data(non_vulnerable_client)

    def collect_time_file(self):
        self.dls.download_time_files(self.attacker_server)

    def organize_dls_data(self):
        self.merge_pcap_files()
        self.uniform_log_file_name()
        self.uniform_accounting_file_name()

    def merge_pcap_files(self):
        '''
        dls.path = /home/dataloggerserver/All_data
        '''
        traffic_folder = "traffic"
        traffic_file = "traffic.pcap"
        merge_path = os.path.join(self.dls.path, traffic_folder)
        merge_path = os.path.join(merge_path, traffic_file)

        for vulnerable_client in self.vulnerable_clients:
            client_file_path = os.path.join(self.dls.path, vulnerable_client.username)
            client_file_path = os.path.join(client_file_path, "data")
            client_file_path = os.path.join(client_file_path, traffic_file)
            merge_path = merge_path + " " + client_file_path
        for non_vulnerable_client in self.non_vulnerable_clients:
            client_file_path = os.path.join(self.dls.path, non_vulnerable_client.username)
            client_file_path = os.path.join(client_file_path, "data")
            client_file_path = os.path.join(client_file_path, traffic_file)
            merge_path = merge_path + " " + client_file_path

        cmd = "mergecap -w " + merge_path

        SSHHelper.remote_execute(self.dls.ip, self.dls.username, self.dls.password, cmd)

    def uniform_log_file_name(self):
        '''
        dls.path = /home/dataloggerserver/All_data
        '''
        log_folder = "syslog"
        old_log_file = "log_out.csv"
        for vulnerable_client in self.vulnerable_clients:
            old_client_file_path = os.path.join(self.dls.path, vulnerable_client.username)
            old_client_file_path = os.path.join(old_client_file_path, "data")
            old_client_file_path = os.path.join(old_client_file_path, old_log_file)
            new_log_file = vulnerable_client.username + "_log.csv"
            new_client_file_path = os.path.join(self.dls.path, log_folder)
            new_client_file_path = os.path.join(new_client_file_path, new_log_file)
            cmd = "mv " + old_client_file_path + " " +new_client_file_path

            #print(cmd)

            SSHHelper.remote_execute(self.dls.ip, self.dls.username, self.dls.password, cmd)

        for non_vulnerable_client in self.non_vulnerable_clients:
            old_client_file_path = os.path.join(self.dls.path, non_vulnerable_client.username)
            old_client_file_path = os.path.join(old_client_file_path, "data")
            old_client_file_path = os.path.join(old_client_file_path, old_log_file)
            new_log_file = non_vulnerable_client.username + "_log.csv"
            new_client_file_path = os.path.join(self.dls.path, log_folder)
            new_client_file_path = os.path.join(new_client_file_path, new_log_file)
            cmd = "mv " + old_client_file_path + " " + new_client_file_path
            #print(cmd)

            SSHHelper.remote_execute(self.dls.ip, self.dls.username, self.dls.password, cmd)

    def uniform_accounting_file_name(self):
        '''
        dls.path = /home/dataloggerserver/All_data
        '''
        accounting_folder = "accounting"
        old_accounting_file = "stat_000001.csv"
        for vulnerable_client in self.vulnerable_clients:
            old_client_file_path = os.path.join(self.dls.path, vulnerable_client.username)
            old_client_file_path = os.path.join(old_client_file_path, "data")
            old_client_file_path = os.path.join(old_client_file_path, old_accounting_file)
            new_accounting_file = vulnerable_client.username + "_accounting.csv"
            new_client_file_path = os.path.join(self.dls.path, accounting_folder)
            new_client_file_path = os.path.join(new_client_file_path, new_accounting_file)
            cmd = "mv " + old_client_file_path + " " +new_client_file_path

            #print(cmd)

            SSHHelper.remote_execute(self.dls.ip, self.dls.username, self.dls.password, cmd)

        for non_vulnerable_client in self.non_vulnerable_clients:
            old_client_file_path = os.path.join(self.dls.path, non_vulnerable_client.username)
            old_client_file_path = os.path.join(old_client_file_path, "data")
            old_client_file_path = os.path.join(old_client_file_path, old_accounting_file)
            new_accounting_file = non_vulnerable_client.username + "_accounting.csv"
            new_client_file_path = os.path.join(self.dls.path, accounting_folder)
            new_client_file_path = os.path.join(new_client_file_path, new_accounting_file)
            cmd = "mv " + old_client_file_path + " " + new_client_file_path
            #print(cmd)

            SSHHelper.remote_execute(self.dls.ip, self.dls.username, self.dls.password, cmd)




    # --------- attacks ----------
    def attack_disk_wipe(self):
        #ProgressHelper.update_scenario("Disk_Wipe")
        self.attacker_server.disk_wipe_start_metasploit()
        time.sleep(20)
        self.attacker_server.disk_wipe()
        time.sleep(1)
        self.attacker_server.stop_metasploit()
        '''
        stage = 2
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is exploiting rails_secret_deserialization",
                                    5, new_stage=True)
        self.attacker_server.disk_wipe_first_stage()
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} finished exploiting rails_secret_deserialization",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

        stage += 1
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is executing service_persistence",
                                    5, new_stage=True)
        self.attacker_server.disk_wipe_second_stage()
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} finished executing service_persistence",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

        stage += 1
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is executing disk_wipe",
                                    5, new_stage=True)
        self.attacker_server.disk_wipe_third_stage()
        


        # wait and record timestamp
        
        timestamp_folder = os.path.join("CREME_backend_execution", "logs", "disk_wipe", "times")
        timestamp_file = "time_stage_3_end.txt"
        OtherHelper.wait_finishing(sleep_time=90, record_time=True, folder=timestamp_folder,
                                   timestamp_file=timestamp_file)
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} finished executing disk_wipe",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)
        '''

    def attack_cred_steal(self):
        #ProgressHelper.update_scenario("cred_steal")
        self.attacker_server.cred_steal_start_metasploit()
        time.sleep(20)
        self.attacker_server.cred_steal()
        time.sleep(1)
        self.attacker_server.stop_metasploit()
        #OtherHelper.wait_finishing(120)
        '''
        stage = 2
        ProgressHelper.update_stage(stage,
                                    f"{self.attacker_server.hostname} is exploiting unreal_ircd_3281_backdoor",
                                    5, new_stage=True)
        self.attacker_server.cred_steal_first_stage()
        ProgressHelper.update_stage(stage,
                                    f"{self.attacker_server.hostname} finished exploiting unreal_ircd_3281_backdoor",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

        stage += 1
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is executing docker_daemon_privilege_escalation",
                                    5, new_stage=True)
        self.attacker_server.cred_steal_second_stage()
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} finished executing docker_daemon_privilege_escalation",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)

        stage += 1
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} is executing cred_steal",
                                    5, new_stage=True)
        self.attacker_server.cred_steal_third_stage()
        # wait and record timestamp
        timestamp_folder = os.path.join("CREME_backend_execution", "logs", "cred_steal", "times")
        timestamp_file = "time_stage_3_end.txt"
        OtherHelper.wait_finishing(sleep_time=90, record_time=True, folder=timestamp_folder,
                                   timestamp_file=timestamp_file)
        ProgressHelper.update_stage(stage, f"{self.attacker_server.hostname} finished executing cred_steal",
                                    5, finished_task=True, override_pre_message=True, finished_stage=True)
        '''

    # ---------- cleaning ----------
    def clean_data_collection(self):
        for vulnerable_client in self.vulnerable_clients:
            vulnerable_client.clean_data_collection()
        for non_vulnerable_client in self.non_vulnerable_clients:
            non_vulnerable_client.clean_data_collection()

    def clean_attack_cred_steal(self):
        for vulnerable_client in self.vulnerable_clients:
            vulnerable_client.clean_windows()

    def clean_attack_disk_wipe(self):
        for vulnerable_client in self.vulnerable_clients:
            vulnerable_client.clean_windows()

    # ---------- download data to controller ----------
    def download_data_to_controller(self, scenario_log_folder, time_filenames=[], other_files_flag=False,
                                    local_folders=[], remote_files=[]):
        """
        using to download data from the data logger server to controller, and save it to scenario_log_folder.
        :param scenario_log_folder: a folder of specific scenario insides the logs folder.
        :param time_filenames: name of timestamp files
        :param other_files_flag: whether we needs to collect other data to controller or not
        :param local_folders: local folders at controller
        :param remote_files: other files at remote_machine (not pcap, accounting, syslog, timestamp)
        """
        log_folder = self.dls.controller_path
        tmp_folder_names = ["CREME_backend_execution", "logs", scenario_log_folder]
        for folder in tmp_folder_names:
            log_folder = os.path.join(log_folder, folder)

        # ----- download pcap file -----
        # dls path: /home/dataloggerserver/All_data
        traffic = "traffic"
        traffic_folder = os.path.join(log_folder, traffic)

        remote_folder = os.path.join(self.dls.path, traffic)
        file_names = [self.dls.tcp_file]
        DownloadDataHelper.get_data(self.dls.ip, self.dls.username, self.dls.password, remote_folder=remote_folder,
                                    file_names=file_names, local_folder=traffic_folder)

        # ----- download accounting files -----
        accounting = "accounting"
        accounting_folder = os.path.join(log_folder, accounting)

        file_names = []
        for vulnerable_client in self.vulnerable_clients:
            file_names.append(vulnerable_client.accounting_file)
        for non_vulnerable_client in self.non_vulnerable_clients:
            file_names.append(non_vulnerable_client.accounting_file)
        remote_folder = os.path.join(self.dls.path, accounting)

        DownloadDataHelper.get_data(self.dls.ip, self.dls.username, self.dls.password, remote_folder=remote_folder,
                                    file_names=file_names, local_folder=accounting_folder)

        # ----- download syslog files -----
        syslog = "syslog"
        syslog_folder = os.path.join(log_folder, syslog)

        file_names = []
        for vulnerable_client in self.vulnerable_clients:
            file_names.append(vulnerable_client.log_file)
        for non_vulnerable_client in self.non_vulnerable_clients:
            file_names.append(non_vulnerable_client.log_file)
        remote_folder = os.path.join(self.dls.path, syslog)

        DownloadDataHelper.get_data(self.dls.ip, self.dls.username, self.dls.password, remote_folder=remote_folder,
                                    file_names=file_names, local_folder=syslog_folder)

        if other_files_flag:  # download other logs/files
            for i, tmp_folder in enumerate(local_folders):
                # syslog = "syslog"
                local_folder = os.path.join(log_folder, tmp_folder)
                file_names = []
                file_names.append(remote_files[i])
                # file_names.append('{0}_continuum.log'.format(self.benign_server.hostname))
                # file_names.append('{0}_continuum.log'.format(self.target_server.hostname))

                DownloadDataHelper.get_data(self.dls.ip, self.dls.username, self.dls.password, remote_folder=self.dls.path,
                                            file_names=file_names, local_folder=local_folder)

        # ----- download timestamp files -----
        times = "times"
        times_folder = os.path.join(log_folder, times)

        file_names = time_filenames
        remote_folder = os.path.join(self.dls.path, times)

        DownloadDataHelper.get_data(self.dls.ip, self.dls.username, self.dls.password, remote_folder=remote_folder,
                                    file_names=file_names, local_folder=times_folder)

    # ---------- run scenario ----------
    def run_disk_wipe(self):
        scenario = "disk_wipe"
        #ProgressHelper.update_scenario(scenario)
        #self.start_reproduce_benign_behavior()
        self.start_collect_data()
        print("Finished start collect data")
        print("--------------------------------------------------------------")
        self.attack_disk_wipe()
        time.sleep(5)
        self.stop_collect_data()
        print("Finished stop collect data")
        print("--------------------------------------------------------------")
        #self.stop_reproduce_benign_behavior()
        self.centralize_data()
        self.collect_time_file()
        print("Finished centralize data")
        print("--------------------------------------------------------------")
        self.clean_attack_disk_wipe()
        self.clean_data_collection()
        self.organize_dls_data()
        file_names = ["time_start.txt", "time_end.txt"]
        self.download_data_to_controller(scenario, file_names)
        '''
        file_names = ["time_stage_1_start.txt", "time_stage_1_end.txt", "time_stage_2_start.txt",
                      "time_stage_2_end.txt", "time_stage_3_start.txt"]
        self.centralize_time_files(remote_machine=self.attacker_server, time_files=file_names)
        self.download_data_to_controller(scenario, time_filenames=file_names)
        '''

    def run_cred_steal(self):
        scenario = "cred_steal"
        #ProgressHelper.update_scenario(scenario)
        #self.start_reproduce_benign_behavior()
        self.start_collect_data()
        print("Finished start collect data")
        print("--------------------------------------------------------------")
        self.attack_cred_steal()
        time.sleep(5)
        self.stop_collect_data()
        print("Finished stop collect data")
        print("--------------------------------------------------------------")
        #self.stop_reproduce_benign_behavior()
        self.centralize_data()
        self.collect_time_file()
        print("Finished centralize data")
        print("--------------------------------------------------------------")
        self.clean_attack_cred_steal()
        self.clean_data_collection()
        self.organize_dls_data()
        file_names = ["time_start.txt", "time_end.txt"]
        self.download_data_to_controller(scenario, file_names)

    # ---------- process data ----------
    def process_data_mirai(self, log_folder):
        """
        this function use to create labeling_file that contain information to label accounting and traffic data,
        also return abnormal_hostnames, normal_hostnames, timestamps_syslog to process and label syslog
        """

        folder_times = os.path.join(log_folder, "times")
        t1, t2 = ProcessDataHelper.get_time_stamps_special(folder_times)  #still need to change


        t = [t1, t2, 0, 0, 0, 0]


        labels = [1, 1, 1]  # only for syslog
        tactic_names = ['Lateral Movement']
        technique_names = ['Exploitation of Remote Service']
        sub_technique_names = ['']

        src_ips_1 = []  # malicious server ip
        des_ips_1 = []  # vul client ip
        normal_ips_1 = []  # nonvul client ip
        abnormal_hostnames_1 = []  # vul client hostname
        normal_hostnames_1 = []  # nonvul client hostname

        src_ips_1.append(self.attacker_server.ip)
        for vulnerable_client in self.vulnerable_clients:
            des_ips_1.append(vulnerable_client.ip)
            abnormal_hostnames_1.append(vulnerable_client.hostname)
        for non_vulnerable_client in self.non_vulnerable_clients:
            normal_ips_1.append(non_vulnerable_client.ip)
            normal_hostnames_1.append(non_vulnerable_client.hostname)


        src_ips = [src_ips_1]
        des_ips = [des_ips_1]
        normal_ips = [normal_ips_1]
        normal_hostnames = [normal_hostnames_1]
        abnormal_hostnames = [abnormal_hostnames_1]
        drop_cmd_list = ['kworker']

        labeling_file_path = os.path.join(log_folder, "labeling_file_path.txt")

        ProcessDataHelper.make_labeling_file(labeling_file_path, tactic_names, technique_names,
                           sub_technique_names, t, src_ips, des_ips, normal_ips, normal_hostnames,
                           abnormal_hostnames, drop_cmd_list)

        timestamps_syslog = [[t1, t2]]

        return labeling_file_path, timestamps_syslog, abnormal_hostnames, normal_hostnames, labels, tactic_names, \
               technique_names, sub_technique_names

    def parse_data_general_scenerio(self, scenario_log_folder):
        # ----- get timestamps -----
        times = "times"
        data_folder = self.dls.controller_path
        times_folder_names = ["CREME_backend_execution", "logs", scenario_log_folder, times]
        for folder in times_folder_names:
            data_folder = os.path.join(data_folder, folder)
        t1, t2 = ProcessDataHelper.get_time_stamps_special(data_folder)
        time_list = [t1, t2]


        # ----- parse accoutning files -----
        accounting = "accounting"
        data_folder = self.dls.controller_path
        accounting_folder_names = ["CREME_backend_execution", "logs", scenario_log_folder, accounting]
        for folder in accounting_folder_names:
            data_folder = os.path.join(data_folder, folder)
        print(data_folder)
        for vulnerable_client in self.vulnerable_clients:
            output_file_name = "{0}_processed_accounting.csv".format(vulnerable_client.username)
            ProcessDataHelper.parse_accounting(data_folder, vulnerable_client.accounting_file,
                                               vulnerable_client.username, output_file_name)

        for non_vulnerable_client in self.non_vulnerable_clients:
            output_file_name = "{0}_processed_accounting.csv".format(non_vulnerable_client.username)
            ProcessDataHelper.parse_accounting(data_folder, non_vulnerable_client.accounting_file,
                                               non_vulnerable_client.username, output_file_name)


        # ----- parse system log files -----
        syslog = "syslog"
        data_folder = self.dls.controller_path
        accounting_folder_names = ["CREME_backend_execution", "logs", scenario_log_folder, syslog]
        for folder in accounting_folder_names:
            data_folder = os.path.join(data_folder, folder)

        for vulnerable_client in self.vulnerable_clients:
            output_file_name = "{0}_processed_syslog.csv".format(vulnerable_client.username)
            ProcessDataHelper.parse_syslog(data_folder, vulnerable_client.log_file,
                                                output_file_name, time_list)

        for non_vulnerable_client in self.non_vulnerable_clients:
            output_file_name = "{0}_processed_syslog.csv".format(non_vulnerable_client.username)
            ProcessDataHelper.parse_syslog(data_folder, non_vulnerable_client.log_file,
                                                output_file_name, time_list)

    def label_data_general_scenerio(self, scenario_log_folder):

        # ----- label accoutning files -----
        # get normal and abnormal cmd list

        normal_set = set()
        abnormal_set = set()

        accounting = "accounting"
        data_folder = self.dls.controller_path
        accounting_folder_names = ["CREME_backend_execution", "logs", scenario_log_folder, accounting]
        for folder in accounting_folder_names:
            data_folder = os.path.join(data_folder, folder)

        for vulnerable_client in self.vulnerable_clients:
            processed_file_name = "{0}_processed_accounting.csv".format(vulnerable_client.username)
            abnormal_cmd_list = ProcessDataHelper.get_cmd_accounting(data_folder, processed_file_name)
            abnormal_set = abnormal_set.union(abnormal_cmd_list)

        for non_vulnerable_client in self.non_vulnerable_clients:
            processed_file_name = "{0}_processed_accounting.csv".format(non_vulnerable_client.username)
            normal_cmd_list = ProcessDataHelper.get_cmd_accounting(data_folder, processed_file_name)
            normal_set = normal_set.union(normal_cmd_list)

        stage_abnormal_cmd_list = list(abnormal_set - normal_set)
        stage_normal_cmd_list = list(normal_set)

        for cmd in stage_abnormal_cmd_list:
            for normal_cmd in stage_normal_cmd_list:
                if normal_cmd in cmd:
                    stage_abnormal_cmd_list.remove(cmd)
                    break


        #add_cmd_list = ["lsass"]
        #stage_abnormal_cmd_list = add_cmd_list + stage_abnormal_cmd_list  # might need to change decided by the scenerio

        # start labeling
        label_data = []

        for vulnerable_client in self.vulnerable_clients:
            processed_file_name = "{0}_processed_accounting.csv".format(vulnerable_client.username)
            processed_input_file = os.path.join(data_folder, processed_file_name)
            df = pd.read_csv(processed_input_file)
            label = [0] * len(df)
            df['Label'] = label
            idx = df[df['cmd'].isin(stage_abnormal_cmd_list)].index
            df.loc[idx, 'Label'] = 1
            label_data.append(df)

        for non_vulnerable_client in self.non_vulnerable_clients:
            processed_file_name = "{0}_processed_accounting.csv".format(non_vulnerable_client.username)
            processed_input_file = os.path.join(data_folder, processed_file_name)
            df = pd.read_csv(processed_input_file)
            label = [0] * len(df)
            df['Label'] = label
            label_data.append(df)
        # finished labeling, concat all files to one file

        label_data = pd.concat(label_data)
        label_data = label_data.drop(['time', 'cmd', 'ID Process'], axis=1)
        label_data = label_data.replace(' ', 0)

        for k in list(label_data):
            label_data[k] = pd.to_numeric(label_data[k], errors='ignore')

        data_folder = self.dls.controller_path
        label_folder_names = ["CREME_backend_execution", "logs", "label_accounting"]
        for folder in label_folder_names:
            data_folder = os.path.join(data_folder, folder)
        label_out_file = os.path.join(data_folder, "label_accounting.csv")
        label_data.to_csv(label_out_file, index=False)

        # ----- label system log files -----
        # get normal and abnormal eventid list

        normal_set = set()
        abnormal_set = set()

        syslog = "syslog"
        data_folder = self.dls.controller_path
        syslog_folder_names = ["CREME_backend_execution", "logs", scenario_log_folder, syslog]
        for folder in syslog_folder_names:
            data_folder = os.path.join(data_folder, folder)

        for vulnerable_client in self.vulnerable_clients:
            processed_file_name = "{0}_processed_syslog.csv".format(vulnerable_client.username)
            abnormal_eventid_list = ProcessDataHelper.get_eventid_syslog(data_folder, processed_file_name)
            abnormal_set = abnormal_set.union(abnormal_eventid_list)

        for non_vulnerable_client in self.non_vulnerable_clients:
            processed_file_name = "{0}_processed_syslog.csv".format(non_vulnerable_client.username)
            normal_eventid_list = ProcessDataHelper.get_eventid_syslog(data_folder, processed_file_name)
            normal_set = normal_set.union(normal_eventid_list)
        eventid_plus_list = [7036]
        stage_abnormal_eventid_list = list(abnormal_set - normal_set)
        stage_abnormal_eventid_list = stage_abnormal_eventid_list + eventid_plus_list

        label_data = []

        for vulnerable_client in self.vulnerable_clients:
            processed_file_name = "{0}_processed_syslog.csv".format(vulnerable_client.username)
            processed_input_file = os.path.join(data_folder, processed_file_name)
            df = pd.read_csv(processed_input_file)
            label = [0] * len(df)
            df['Label'] = label
            idx = df[df['EventId'].isin(stage_abnormal_eventid_list)].index
            df.loc[idx, 'Label'] = 1
            label_data.append(df)

        for non_vulnerable_client in self.non_vulnerable_clients:
            processed_file_name = "{0}_processed_syslog.csv".format(non_vulnerable_client.username)
            processed_input_file = os.path.join(data_folder, processed_file_name)
            df = pd.read_csv(processed_input_file)
            label = [0] * len(df)
            df['Label'] = label
            label_data.append(df)
        # finished labeling, concat all files to one file

        label_data = pd.concat(label_data)
        label_data = label_data.drop(['TimeCreated', 'EventId'], axis=1)
        label_data = label_data.fillna(0)
        '''
        for k in list(label_data):
            label_data[k] = pd.to_numeric(label_data[k], errors='ignore')
        '''

        data_folder = self.dls.controller_path
        label_folder_names = ["CREME_backend_execution", "logs", "label_syslog"]
        for folder in label_folder_names:
            data_folder = os.path.join(data_folder, folder)
        label_out_file = os.path.join(data_folder, "label_syslog.csv")
        label_data.to_csv(label_out_file, index=False)

    def process_data_cred_steal(self):
        cred_steal = "cred_steal"
        self.parse_data_general_scenerio(cred_steal)
        self.label_data_general_scenerio(cred_steal)

    def process_data_disk_wipe(self):
        disk_wipe = "disk_wipe"
        self.parse_data_general_scenerio(disk_wipe)
        self.label_data_general_scenerio(disk_wipe)

    def process_data(self):
        # make_label_subflow.py might need to change
        # accounting
        big_list = []
        traffic_files = []
        scenarios_labels = []
        scenarios_tactics = []
        scenarios_techniques = []
        scenarios_sub_techniques = []

        log_folder = "../../CREME_backend_execution/logs"

        if Creme.disk_wipe:

            self.process_data_disk_wipe()

            scenario = "disk_wipe"
            log_folder_cred_steal = os.path.join(log_folder, scenario)
            labeling_file_path, timestamps_syslog, abnormal_hostnames, normal_hostnames, labels, tactics, \
            techniques, sub_techniques = self.process_data_mirai(log_folder_cred_steal)
            traffic_file = os.path.join("traffic", "traffic.pcap")
            information = [labeling_file_path, log_folder_cred_steal, traffic_file]

            big_list.append(information)
            traffic_files.append("label_traffic.csv")

            scenarios_labels.append(labels)
            scenarios_tactics.append(tactics)
            scenarios_techniques.append(techniques)
            scenarios_sub_techniques.append(sub_techniques)
        if Creme.cred_steal:


            self.process_data_cred_steal()

            scenario = "cred_steal"
            log_folder_cred_steal = os.path.join(log_folder, scenario)
            labeling_file_path, timestamps_syslog, abnormal_hostnames, normal_hostnames, labels, tactics, \
            techniques, sub_techniques = self.process_data_mirai(log_folder_cred_steal)
            traffic_file = os.path.join("traffic", "traffic.pcap")
            information = [labeling_file_path, log_folder_cred_steal, traffic_file]

            big_list.append(information)
            traffic_files.append("label_traffic.csv")

            scenarios_labels.append(labels)
            scenarios_tactics.append(tactics)
            scenarios_techniques.append(techniques)
            scenarios_sub_techniques.append(sub_techniques)

        folder_traffic = os.path.join(log_folder, "label_traffic")
        final_name_traffic = "label_traffic.csv"
        folder_accounting = os.path.join(log_folder, "label_accounting")
        final_name_accounting = "label_accounting.csv"
        folder_syslog = os.path.join(log_folder, "label_syslog")
        final_name_syslog = "label_syslog.csv"


        ProcessDataHelper.handle_accounting_packet_all_scenario(big_list, folder_traffic, traffic_files, final_name_traffic, 1)

        data_sources = []
        data_sources.append({"name": "accounting", "folder": folder_accounting, "file": final_name_accounting})
        data_sources.append({"name": "traffic", "folder": folder_traffic, "file": final_name_traffic})
        data_sources.append({"name": "syslog", "folder": folder_syslog, "file": final_name_syslog})

        return data_sources



    # ---------- train ML ----------

    def train_ML_accuracy(self, data_sources):
        output_folder = os.path.join("../../CREME_backend_execution", "evaluation_results") #need to be changed
        output_folder = os.path.join(output_folder, "accuracy")
        # models_name should update to let users select at the website *************
        models_name = Creme.models_name
        for data_source in data_sources:
            name = data_source["name"]
            folder = data_source["folder"]
            file = data_source["file"]
            output_folder, output_file = TrainMLHelper.accuracy(name, folder, file, output_folder, models_name)


    def train_ML(self, data_sources):
        # accuracy
        self.train_ML_accuracy(data_sources)


    def run(self):
        self.configure()

        if Creme.disk_wipe:
            self.run_disk_wipe()
        if Creme.cred_steal:
            self.run_cred_steal()

        data_sources = self.process_data()
        self.train_ML(data_sources)
        '''
        data_sources = self.process_data()
        self.train_ML(data_sources)
        '''


# Classes for machines

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



class DataLoggerServer(Machine):
    """

    """

    def __init__(self, hostname, ip, username, password, path, tcp_file="traffic.pcap"):
        super().__init__(hostname, ip, username, password, path)
        self.path = path
        self.tcp_file = tcp_file

    def configure(self):
        self.configure_base()

    def configure_base(self):
        filename_path = "configuration/./dataloggerserver_config.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
        # dataloggerserver ip: 192.168.1.99, username: root, password: qsefthuk

    def centralize_data(self, data_logger_client):
        filename_path = "data_collect/./collect_all.sh"
        parameters = [self.ip, self.username, self.password, data_logger_client.username, data_logger_client.ip, data_logger_client.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
        # ip: 192.168.1.99
        # username: dataloggerserver
        # password: qsefthuk
        # collectuser: testbed_2
        # collect_ip: 192.168.1.110
        # collectpass: qsefthuk

    def download_time_files(self, data_logger_client):
        filename_path = "data_collect/./download_data_Linux.sh"
        parameters = [self.ip, self.username, self.password, data_logger_client.ip, data_logger_client.username,
                      data_logger_client.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    '''
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
    '''


class VulnerableClient(Machine):
    def __init__(self, hostname, ip, username, password, path):
        super().__init__(hostname, ip, username, password, path)
        self.accounting_file = "{0}_accounting.csv".format(username)
        self.log_file = "{0}_log.csv".format(username)

    def configure(self):
        self.configure_base()
        self.configure_tools()
        if Creme.disk_wipe:
            self.configure_disk_wipe()
        if Creme.cred_steal:
            self.configure_cred_steal()

    '''
    def configure_base(self):
        filename_path = "configuration/./client_config_base.sh"
        parameters = [self.ip, self.username, self.password, self.controller_path]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
        # vul username: testbed_2, password: qsefthuk, ip: 192.168.1.110
    '''

    def configure_base(self):
        folder = self.controller_path
        local = os.path.join(folder, 'CREME_backend_execution/scripts/configuration/config_client')
        remote = '/home'
        remote = os.path.join(remote, self.username)
        remote = os.path.join(remote, 'Desktop/')
        SSHHelper.scp_file(self.ip, self.username, self.password, local, remote)

    def configure_tools(self):
        filename_path = "configuration/./client_config_tools.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
        # vul username: testbed_2, password: qsefthuk, ip: 192.168.1.110

    '''
    def configure_benign_services(self):
        filename_path = "configuration/./Client_benign_services.sh"
        parameters = [self.hostname, self.ip, self.username, self.password, self.path, self.ftp_folder,
                      self.controller_ip, self.controller_username, self.controller_password, self.controller_path,
                      self.server.ip, self.virtual_account, self.server.domain_name]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
    '''

    def start_collect_data(self):
        self.start_collect_data_stat()
        self.start_collect_data_traffic()
        self.start_collect_data_log()


    def start_collect_data_stat(self):
        filename_path = "data_collect/./stat_collect.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)


    def start_collect_data_traffic(self):
        filename_path = "data_collect/./traffic_collect.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def start_collect_data_log(self):
        filename_path = "data_collect/./log_collect.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_collect_data(self):
        self.stop_collect_data_stat()
        self.stop_collect_data_traffic()
        self.stop_collect_data_log()

    def stop_collect_data_stat(self):
        filename_path = "data_collect/./stat_stop.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_collect_data_traffic(self):
        filename_path = "data_collect/./traffic_stop.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_collect_data_log(self):
        filename_path = "data_collect/./log_stop.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_disk_wipe(self):
        filename_path = "configuration/./client_config_disk_wipe.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_cred_steal(self):
        pass

    def clean_data_collection(self):
        filename_path = "data_collect/./data_cleanup.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
        # ip: 192.168.1.110
        # username: testbed_2
        # password: qsefthuk

    def clean_windows(self):
        filename_path = "attacks/./cleanup_windows.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
        # ip: 192.168.1.110
        # username: testbed_2
        # password: qsefthuk


class NonVulnerableClient(Machine):
    def __init__(self, hostname, ip, username, password, path):
        super().__init__(hostname, ip, username, password, path)
        # something else
        self.accounting_file = "{0}_accounting.csv".format(username)
        self.log_file = "{0}_log.csv".format(username)

    def configure(self):
        self.configure_base()
        self.configure_tools()


    def configure_base(self):
        folder = self.controller_path
        local = os.path.join(folder, 'CREME_backend_execution/scripts/configuration/config_client')
        remote = '/home'
        remote = os.path.join(remote, self.username)
        remote = os.path.join(remote, 'Desktop/')
        SSHHelper.scp_file(self.ip, self.username, self.password, local, remote)

    def configure_tools(self):
        filename_path = "configuration/./client_config_tools.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    '''
    def configure_benign_services(self):
        filename_path = "configuration/./Client_benign_services.sh"
        parameters = [self.hostname, self.ip, self.username, self.password, self.path, self.ftp_folder,
                      self.controller_ip, self.controller_username, self.controller_password, self.controller_path,
                      self.server.ip, self.virtual_account, self.server.domain_name]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
    '''

    def start_collect_data(self):
        self.start_collect_data_stat()
        self.start_collect_data_traffic()
        self.start_collect_data_log()

    def start_collect_data_stat(self):
        filename_path = "data_collect/./stat_collect.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def start_collect_data_log(self):
        filename_path = "data_collect/./log_collect.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def start_collect_data_traffic(self):
        filename_path = "data_collect/./traffic_collect.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_collect_data(self):
        self.stop_collect_data_stat()
        self.stop_collect_data_traffic()
        self.stop_collect_data_log()

    def stop_collect_data_stat(self):
        filename_path = "data_collect/./stat_stop.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_collect_data_traffic(self):
        filename_path = "data_collect/./traffic_stop.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_collect_data_log(self):
        filename_path = "data_collect/./log_stop.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def clean_data_collection(self):
        filename_path = "data_collect/./data_cleanup.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
        # ip: 192.168.1.103
        # username: non_vul
        # password: qsefthuk

    '''
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
    '''


class AttackerServer(Machine):
    data_logger_server_ip = None

    def __init__(self, hostname, ip, username, password, path, target_ip = ""):
        super().__init__(hostname, ip, username, password, path)
        self.killed_pids_file = "killed_pids.txt"
        self.target_ip = target_ip
        # self.flag_finish = "Creme_finish_attack_scenario"

    def configure(self):
        self.configure_base()

        # if Creme.disk_wipe or Creme.cred_steal:
        #    self.configure_pymetasploit()
        if Creme.disk_wipe:
            self.configure_disk_wipe()
        if Creme.cred_steal:
            self.configure_cred_steal()

    def configure_base(self):
        filename_path = "configuration/./Kali_config_base.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
        '''
        set delKnownHosts "del_known_hosts.sh"
        set kali_ip "192.168.1.106"
        set username "root"
        set password "qsefthuk"
        set controller_user "controller"
        set controller_ip "192.168.1.4"
        set controller_path "/home/controller/Desktop/scripts/configuration/config_kali"
        set controller_pass "qsefthuk"
        '''

    '''
    def configure_pymetasploit(self):
        filename_path = "configuration/./AttackerServer_pymetasploit.sh"
        parameters = [self.ip, self.username, self.password, self.path]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
    '''

    def configure_disk_wipe(self):
        prepared_files = "CREME_backend_execution/scripts/configuration/config_kali/disk_wipe"
        filename_path = "configuration/./Kali_config_disk_wipe.sh"
        parameters = [self.ip, self.username, self.password, self.controller_ip, self.controller_username,
                      self.controller_password, self.controller_path, prepared_files]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_cred_steal(self):
        prepared_files = "CREME_backend_execution/scripts/configuration/config_kali/cred_steal"
        filename_path = "configuration/./Kali_config_cred_steal.sh"
        parameters = [self.ip, self.username, self.password, self.controller_ip, self.controller_username,
                      self.controller_password, self.controller_path, prepared_files]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def disk_wipe_start_metasploit(self):
        filename_path = "attacks/./start_metasploit.sh"
        parameters = [self.ip, self.username, self.password, self.killed_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def disk_wipe(self):
        filename_path = "attacks/disk_wipe/./start_attack_disk_wipe.sh"
        parameters = [self.ip, self.username, self.password, self.target_ip]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
        # ip: 192.168.1.106
        # username: root
        # password: qsefthuk
        # path: /root/Desktop

    '''
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
    '''

    def cred_steal_start_metasploit(self):
        filename_path = "attacks/./start_metasploit.sh"
        parameters = [self.ip, self.username, self.password, self.killed_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def cred_steal(self):
        filename_path = "attacks/cred_steal/./start_attack_cred_steal.sh"
        parameters = [self.ip, self.username, self.password, self.target_ip]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
        # ip: 192.168.1.106
        # username: root
        # password: qsefthuk
        # path: /root/Desktop
    '''
    def cred_steal_first_stage(self):
        filename_path = "attacks/cred_steal/./AttackerServer_first_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def cred_steal_second_stage(self):
        filename_path = "attacks/cred_steal/./AttackerServer_second_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def cred_steal_third_stage(self):
        filename_path = "attacks/cred_steal/./AttackerServer_third_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
    '''

    def stop_metasploit(self):
        filename_path = "attacks/./kill_pids.sh"
        parameters = [self.ip, self.username, self.password, self.killed_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    # Stop metasploit still need to be changed
    def clean_disk_wipe(self):
        #self.stop_metasploit()
        self.clean_windows()

    def clean_cred_steal(self):
        #self.stop_metasploit()
        self.clean_windows()



# Helper
class ScriptHelper:
    @staticmethod
    def get_del_known_hosts_path(scripts_path, del_script="./del_known_hosts.sh"):
        del_known_hosts_path = os.path.join(scripts_path, del_script)
        return del_known_hosts_path

    @staticmethod
    def get_script_cmd(file):
        scripts_path = os.path.join("../../CREME_backend_execution", "scripts")
        cmd = os.path.join(scripts_path, file)
        del_known_hosts_path = ScriptHelper.get_del_known_hosts_path(scripts_path, "./del_known_hosts.sh")
        return cmd, del_known_hosts_path

    @staticmethod
    def execute_script(filename_path, parameters, show_cmd=False):
        cmd, del_known_hosts_path = ScriptHelper.get_script_cmd(filename_path)
        cmd += " {0}".format(del_known_hosts_path)
        for parameter in parameters:
            cmd += " {0}".format(parameter)
        print(cmd) if show_cmd else os.system(cmd)

class OtherHelper:
    @staticmethod
    def wait_finishing(sleep_time, record_time=False, folder="", timestamp_file=""):
        time.sleep(sleep_time)
        if record_time:
            output_time_file = os.path.join(folder, timestamp_file)
            with open(output_time_file, "w+") as fw:
                fw.write('%f' % time.time())

class DownloadDataHelper:
    """
    this class supports to download data from machines to the Controller
    """
    @staticmethod
    def get_data(ip, username, password, remote_folder, file_names, local_folder):
        """
        using to get files that have a name existing in file_names at remote_folder from ip,
        and save them to local_folder.
        """
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=ip, username=username, password=password)

        ftp_client = ssh_client.open_sftp()

        for file_name in file_names:
            remote_file = os.path.join(remote_folder, file_name)
            local_file = os.path.join(local_folder, file_name)
            ftp_client.get(remote_file, local_file)

        ftp_client.close()

class SSHHelper:
    @staticmethod
    def remote_execute(ip, username, password, cmd):
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=ip, username=username, password=password)
        ssh_stdin, ssh_stdout, ssh_stderr = ssh_client.exec_command(cmd)
        ssh_client.close()

    def scp_file(ip, username, password, local, remote):
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=ip, username=username, password=password)
        scp = SCPClient(ssh_client.get_transport())
        scp.put(local, recursive=True, remote_path=remote)

class ProcessDataHelper:
    @staticmethod
    def parse_accounting(folder, input_file, username, out_file):
        raw_input_file = os.path.join(folder, input_file)

        replace_username = username.upper() + '-PC'

        df = pd.read_csv(raw_input_file)
        df_temp = df

        accounting_num = 28  # num of accounting data for each process
        row = df.shape[0]
        column = df.shape[1] - 1
        process_num = int(column / accounting_num)  # num of processes

        # df_time = df.iloc[:,0]

        # data_time = '05/03/2021 10:35:14.694'
        pattern = '%m/%d/%Y %H:%M:%S'
        # epoch = int(time.mktime(time.strptime(data_time, pattern)))
        # print (epoch)

        # Change time to epoch time
        for i in range(0, row):
            df_time_temp = df.iloc[i, 0]
            df_time_temp = df_time_temp[:-4]
            epoch = int(time.mktime(time.strptime(df_time_temp, pattern)))
            df.iloc[i, 0] = epoch

        # Adding time for every process
        for i in range(0, process_num - 3):
            df_time = df_temp.iloc[:, 0]
            df_time = df_time.to_frame()
            # df = df.append(df_time, ignore_index = True)
            df = pd.concat([df, df_time], ignore_index=True)

        # print(df)

        df_temp.drop(df_temp.columns[0], axis=1, inplace=True)

        # df_process = df.iloc[0:row, 1:29]
        # print(df_process)

        # Copying data from every 28 columns to the first 28 columns
        index = 29

        replace = "\\\\" + replace_username + "\Process("

        for i in range(0, process_num - 1):
            df_process = df.iloc[0:row, index:(index + accounting_num)]
            df_process_name = df.columns[index]
            df_process_name = df_process_name.replace(replace,'')
            df_process_name = df_process_name.replace(')\% Processor Time', '')
            if df_process_name != '_Total':
                df_process.columns = ['Processor Time', 'User Time', 'Privileged Time', 'Virtual Bytes Peak',
                                      'Virtual Bytes', 'Page Faults/sec', 'Working Set Peak', 'Working Set',
                                      'Page File Bytes Peak', 'Page File Bytes', 'Private Bytes', 'Thread Count',
                                      'Priority Base', 'Elapsed Time', 'ID Process', 'Creating Process ID',
                                      'Pool Paged Bytes', 'Pool Nonpaged Bytes', 'Handle Count',
                                      'IO Read Operations/sec', 'IO Write Operations/sec', 'IO Data Operations/sec',
                                      'IO Other Operations/sec', 'IO Read Bytes/sec', 'IO Write Bytes/sec',
                                      'IO Data Bytes/sec', 'IO Other Bytes/sec', 'Working Set - Private']
                cmd = [df_process_name] * len(df_process)
                df_process['cmd'] = cmd
                df_temp = pd.concat([df_temp, df_process], ignore_index=True, axis=0)
            index += 28

        df_temp.drop(df_temp.columns[0:(process_num * accounting_num)], axis=1, inplace=True)
        df_temp.drop(df_temp.index[0:row], axis=0, inplace=True)
        df_temp.index = np.arange(0, len(df_temp))

        df.drop(df.columns[1:(process_num * accounting_num + 1)], axis=1, inplace=True)
        df.columns = ['time']
        df = pd.concat([df, df_temp], axis=1)
        # df = df.sort_values(by=['time'], ignore_index = True)

        columns_titles = ['time', 'cmd', 'ID Process', 'Processor Time', 'User Time', 'Privileged Time',
                          'Virtual Bytes Peak', 'Virtual Bytes', 'Page Faults/sec', 'Working Set Peak', 'Working Set',
                          'Page File Bytes Peak', 'Page File Bytes', 'Private Bytes', 'Thread Count', 'Priority Base',
                          'Elapsed Time', 'Creating Process ID', 'Pool Paged Bytes', 'Pool Nonpaged Bytes',
                          'Handle Count', 'IO Read Operations/sec', 'IO Write Operations/sec', 'IO Data Operations/sec',
                          'IO Other Operations/sec', 'IO Read Bytes/sec', 'IO Write Bytes/sec', 'IO Data Bytes/sec',
                          'IO Other Bytes/sec', 'Working Set - Private']
        df = df.reindex(columns=columns_titles)

        # print(df)
        output_file = os.path.join(folder, out_file)
        df.to_csv(output_file, index=False)

    def parse_syslog(folder, input_file, out_file, time_files):
        raw_input_file = os.path.join(folder, input_file)

        df = pd.read_csv(raw_input_file)

        row = df.shape[0]

        # change time to epoch
        pattern = '%Y-%m-%d %H:%M:%S'

        for i in range(0, row):
            df_time_temp = df.iloc[i, 2]
            df_time_temp = df_time_temp[:-8]
            # since system log parser EvtxEcmd won't use local time we need to add 8 hours to epoch time
            epoch = int(time.mktime(time.strptime(df_time_temp, pattern))) + 28800
            df.iloc[i, 2] = epoch

        # since the attack windows is too short there won't be enough data if use timestamp as filter
        '''
        time_start = time_files[0]
        time_end = time_files[1]
        print(time_start, time_end)
        idx = df[(df['TimeCreated'] >= time_start) & (df['TimeCreated'] < time_end)]
        '''
        df = df.drop(['RecordNumber', 'EventRecordId', 'ProcessId', 'ThreadId', 'Computer', 'ChunkNumber',
                        'UserId', 'ExecutableInfo', 'ExtraDataOffset', 'HiddenRecord', 'RemoteHost',
                        'Payload', 'SourceFile', 'PayloadData1', 'PayloadData2', 'PayloadData3',
                        'PayloadData4', 'PayloadData5', 'PayloadData6', 'UserName'], axis=1)

        # change channel to number since there is only system and security
        for i in range(0, row):
            df_temp = df.loc[df.index[i], 'Channel']
            if df_temp == "System":
                df.loc[df.index[i], 'Channel'] = 0
            elif df_temp == "Security":
                df.loc[df.index[i], 'Channel'] = 1
            else:
                df.loc[df.index[i], 'Channel'] = 2

        # Create dummy variable for important info

        df = pd.get_dummies(data=df, columns=['MapDescription', 'Level', 'Provider', 'Keywords'])

        output_file = os.path.join(folder, out_file)
        df.to_csv(output_file, index=False)

    def get_cmd_accounting(folder, input_file):
        processed_input_file = os.path.join(folder, input_file)
        df = pd.read_csv(processed_input_file)
        cmd_list = df['cmd'].tolist()

        return cmd_list

    def get_eventid_syslog(folder, input_file):
        processed_input_file = os.path.join(folder, input_file)
        df = pd.read_csv(processed_input_file)
        eventid_list = df['EventId'].tolist()

        return eventid_list


    def make_labeling_file(labeling_file_path, tactic_names, technique_names, sub_technique_names, t, src_ips, des_ips,
                           normal_ips, normal_hostnames, abnormal_hostnames, drop_cmd_list):
        t1, t2, t3, t4, t5, t6 = map(float, t)

        # if attack_scenario == MIRAI:
        #     t1 = XXX + 1

        my_list = []
        my_list.append([tactic_names[0], technique_names[0], sub_technique_names[0], t1, t2 + 1, src_ips[0], des_ips[0],
                        normal_ips[0], normal_hostnames[0], abnormal_hostnames[0], drop_cmd_list])
        """
        my_list.append([tactic_names[1], technique_names[1], sub_technique_names[1], t3, t4 + 1, src_ips[1], des_ips[1],
                        normal_ips[1], normal_hostnames[1], abnormal_hostnames[1], drop_cmd_list])
        my_list.append([tactic_names[2], technique_names[2], sub_technique_names[2], t5, t6 + 1, src_ips[2], des_ips[2],
                        normal_ips[2], normal_hostnames[2], abnormal_hostnames[2], drop_cmd_list])
        """
        with open(labeling_file_path, "w+") as fw:
            json.dump(my_list, fw)

    def load_dataset_traffic(folder, filenames, finalname, one_hot_fields=[], removed_fields=[], replace_strings=dict(),
                             remove_rows_with_str=dict()):
        df = pd.DataFrame()
        for tmp_filename in filenames:
            filename = os.path.join(folder, tmp_filename)
            tmp_df = pd.read_csv(filename)
            tmp_df = tmp_df.drop(tmp_df[tmp_df['Label'] == -1].index)

            """
            # balance benign and malicious traffic in Mirai scenario
            if tmp_filename == 'label_traffic_mirai.csv':
                drop_indexes = tmp_df[tmp_df['SubTechnique'] == 'SubTechnique-Stage-3'].index
                # print(len(drop_indexes))
                num_of_keep = 150000
                number_drop = len(drop_indexes) - num_of_keep
                drop_indexes = random.sample(list(drop_indexes), number_drop)
                tmp_df = tmp_df.drop(drop_indexes)

            print('label uniques: {0}'.format(tmp_df['Label'].unique()))
            print('len of SubTechnique-Stage-1: {0}'.format(
                len(tmp_df[tmp_df['SubTechnique'] == 'SubTechnique-Stage-1'])))
            print('len of SubTechnique-Stage-2: {0}'.format(
                len(tmp_df[tmp_df['SubTechnique'] == 'SubTechnique-Stage-2'])))
            print('len of SubTechnique-Stage-3: {0}'.format(
                len(tmp_df[tmp_df['SubTechnique'] == 'SubTechnique-Stage-3'])))

            """
            df = df.append(tmp_df)

        # full_filename = os.path.join(folder, filename)
        # df = pd.read_csv(full_filename)

        for field in removed_fields:
            del df[field]
        # One hot, not hash
        one_hot_col_list = one_hot_fields
        df = pd.get_dummies(df, columns=one_hot_col_list)
        # for field in hash_fields:
        #    df[field] = df[field].apply(lambda x: abs(hash(x)) % (10 ** 8))
        for old_value, new_value in replace_strings.items():
            df = df.replace(to_replace=old_value, value=new_value, regex=True)
        for old_value, new_value in remove_rows_with_str.items():
            df = df.replace(to_replace=old_value, value=new_value)
        # for tmp_str in remove_rows_with_str:
        # df = df[(df.iloc[:, 0:] != tmp_str).all(axis=1)]
        # df = df[(df.iloc[:, 1:] != tmp_str).all(axis=1)]
        # print('*******************************************************')
        # print(df.dtypes)

        # print(len(df.columns.values))
        # print(df.dtypes)
        # print(df.isnull().any())

        # preprocess_hex_value
        fields_with_hex_value = ['Sport', 'Dport']

        # for field in fields_with_hex_value:
        #    df[field] = df[field].apply(lambda x: -1 if math.isnan(x) else x)

        for field in fields_with_hex_value:
            df[field] = df[field].fillna(-1)

        for field in fields_with_hex_value:
            df[field] = df[field].apply(lambda x: x if type(x) is str else int(x))

        for field in fields_with_hex_value:
            df[field] = df[field].apply(lambda x: int(str(x), 0))

        # print(len(df.columns.values))
        # print(df.dtypes)
        # print(df.isnull().any())

        column_names = df.columns.values
        for i in range(len(column_names)):
            column_names[i] = column_names[i].strip()
        df.columns = column_names

        # output_filename = os.path.join(folder, 'preprocess_label_traffic.csv')
        output_filename = os.path.join(folder, finalname)
        df.to_csv(output_filename, encoding='utf-8', index=False)

        return df

    def execute_traffic(folder, train_filename, finalname):
        # folder = r'Data\\Traffic'
        # train_filename = ['label_traffic_mirai.csv', 'label_traffic_second.csv', 'label_traffic_third.csv',
        #                 'label_traffic_fourth.csv', 'label_traffic_fifth.csv']

        one_hot_fields = ['Flgs', 'Proto', 'State']
        # fields_with_hex_value = ['Sport', 'Dport']
        removed_fields = ['Rank', 'StartTime', 'SrcAddr', 'DstAddr', 'LastTime', 'Tactic', 'Technique', 'SubTechnique']
        # removed_fields = ['Rank', 'StartTime', 'SrcAddr', 'DstAddr', 'LastTime']
        replace_strings = dict()
        remove_rows_with_str = dict()
        """
        label_field = 'Label'
        tactic_field = 'Tactic'
        technique_field = 'Technique'
        sub_technique_field = 'SubTechnique'
        threshold = 0.01
        """
        ProcessDataHelper.load_dataset_traffic(folder, train_filename, finalname, one_hot_fields=one_hot_fields,
                             removed_fields=removed_fields, replace_strings=replace_strings,
                             remove_rows_with_str=remove_rows_with_str)

        # Helper.rankFeatures(folder, train_filename, hash_fields=hash_fields, removed_fields=removed_fields,
        #                    replace_strings=replace_strings, remove_rows_with_str=remove_rows_with_str,
        #                    label_field=label_field, threshold=threshold)
        # Helper.MLModel(folder, train_filename, test_filename)

    def handle_accounting_and_packet_2(labeling_file_path, output_file_traffic, log_folder, traffic_file, traffic_result_path,
                                       time_window_traffic):
        """
        this function uses to process accounting and packet traffic for each scenario
        :param labeling_file_path: contains information to label data for each scenario
        :param output_file_atop: the output of atop after finishing process data
        :param output_file_traffic: the output of traffic after finishing process data
        :param log_folder: the log folder of the scenario
        :param accounting_folder: accounting_folder is inside log_folder
        :param traffic_file: traffic (pcap) file of the scenario
        :param accounting_result_path: folder uses to store output_file_atop
        :param traffic_result_path: folder uses to store output_file_traffic
        :param time_window_traffic: use to to split traffic flow to sub-flow
        :return:
        """
        # maybe you need to change that
        # accounting_folder = os.path.join(log_folder, accounting_folder)  # Logs/Mirai/Original/Accounting_1/
        traffic_file = os.path.join(log_folder, traffic_file)
        accounting_extraction_file = "../../CREME_backend_execution/scripts/preprocessing/NetworkPacket/./traffic_extraction.sh"
        cmd = '{0} {1} {2} {3} {4} {5}'.format(accounting_extraction_file, labeling_file_path, traffic_file,
                                               time_window_traffic, traffic_result_path, output_file_traffic)
        os.system(cmd)

    def handle_accounting_packet_all_scenario(biglist, folder_traffic, file_traffic, finalname_traffic, time_window_traffic):
        """
        this function uses to process accounting and packet data of all scenarios
        :param biglist: list of information of scenarios; list=[[labeling_file_path, log_folder_scenario,
        accounting_folder, traffic_file],...[labeling_file_path, log_folder_scenario,
        accounting_folder, traffic_file]]
        :param folder_traffic: folder for storing result of traffic
        :param file_traffic: list of label traffic files of scenarios
        :param finalname_traffic: the final output file of traffic
        :param folder_atop: folder for storing result of atop
        :param file_atop: list of label atop files of scenarios
        :param finalname_atop: the final output file of atop
        :param time_window_traffic: use to to split traffic flow to sub-flow
        :return:
        """
        for i, information in enumerate(biglist):
            labeling_file_path = information[0]
            output_file_traffic = file_traffic[i]
            log_folder = information[1]
            traffic_file = information[2]
            traffic_result_path = folder_traffic

            ProcessDataHelper.handle_accounting_and_packet_2(labeling_file_path, output_file_traffic,
                                           log_folder, traffic_file, traffic_result_path, time_window_traffic)

        ProcessDataHelper.execute_traffic(folder_traffic, file_traffic, finalname_traffic)
        # ProcessDataHelper.execute_accounting(folder_atop, file_atop, finalname_atop)

    def get_time_stamps(log_folder):
        time_stage_1_start = os.path.join(log_folder, "time_stage_1_start.txt")
        time_stage_1_end = os.path.join(log_folder, "time_stage_1_end.txt")
        time_stage_2_start = os.path.join(log_folder, "time_stage_2_start.txt")
        time_stage_2_end = os.path.join(log_folder, "time_stage_2_end.txt")
        time_stage_3_start = os.path.join(log_folder, "time_stage_3_start.txt")
        time_stage_3_end = os.path.join(log_folder, "time_stage_3_end.txt")

        with open(time_stage_1_start, 'rt') as f:
            t1 = float(f.readline())
        with open(time_stage_1_end, 'rt') as f:
            t2 = float(f.readline())
        with open(time_stage_2_start, 'rt') as f:
            t3 = float(f.readline())
        with open(time_stage_2_end, 'rt') as f:
            t4 = float(f.readline())
        with open(time_stage_3_start, 'rt') as f:
            t5 = float(f.readline())
        with open(time_stage_3_end, 'rt') as f:
            t6 = float(f.readline())
        return t1, t2, t3, t4, t5, t6

    def get_time_stamps_special(log_folder):
        time_stage_start = os.path.join(log_folder, "time_start.txt")
        time_stage_end = os.path.join(log_folder, "time_end.txt")


        with open(time_stage_start, 'rt') as f:
            t1 = float(f.readline())
        with open(time_stage_end, 'rt') as f:
            t2 = float(f.readline())

        return t1, t2



class TrainMLHelper:
    @staticmethod
    def accuracy(data_source, input_folder, input_file, output_folder, models_name=[], num_of_folds=5,
                 standard_scale=True):
        """
        use to train ML models and get accuracy score.
        return output_folder, output_file if successful
        otherwise return None None
        """

        def define_models(models_name):
            models = dict()
            if 'decision_tree' in models_name:
                models['decision_tree'] = DecisionTreeClassifier()
            if 'naive_bayes' in models_name:
                models['naive_bayes'] = GaussianNB()
            if 'extra_tree' in models_name:
                models['extra_tree'] = ExtraTreeClassifier()
            if 'knn' in models_name:
                models['knn'] = KNeighborsClassifier()
            if 'random_forest' in models_name:
                models['random_forest'] = RandomForestClassifier()
            if 'XGBoost' in models_name:
                models['XGBoost'] = XGBClassifier()
            # print('Defined %d models' % len(models))
            return models

        filename = os.path.join(input_folder, input_file)
        df = pd.read_csv(filename)

        csv_output_file = 'accuracy_for_{0}.csv'.format(data_source)
        label_field = 'Label'

        X = df.loc[:, df.columns != label_field]
        y = df.loc[:, df.columns == label_field]
        # features_train = X.columns.values

        if standard_scale:  # standard scale
            scaler = preprocessing.StandardScaler()
        else:  # Min Max scale
            scaler = preprocessing.MinMaxScaler()
        scaler = scaler.fit(X)
        tmp_df = scaler.transform(X)
        X = pd.DataFrame(tmp_df)

        if num_of_folds < 2:
            num_of_folds = 5
        cv = StratifiedKFold(n_splits=num_of_folds, shuffle=True, random_state=1)
        scoring = ['accuracy', 'f1', 'precision', 'recall']

        csv_columns = ['ML_algorithms', 'fit_time', 'score_time', 'test_accuracy', 'test_f1', 'test_precision', 'test_recall']
        csv_rows = []

        # get models and train
        models = define_models(models_name)
        for name, model in models.items():
            # print('training model {} ...........................'.format(name))
            # scores = cross_validate(model, X, y, scoring=scoring, cv=cv, return_train_score=True)
            scores = cross_validate(model, X, y, scoring=scoring, cv=cv)
            csv_row = dict()
            csv_row['ML_algorithms'] = name
            for key in scores.keys():
                csv_row[key] = round(sum(scores[key]) / len(scores[key]), 4)
                # print('{0}: {1}'.format(key, sum(scores[key]) / len(scores[key])))
            csv_rows.append(csv_row)

        # try to save results
        try:
            with open(os.path.join(output_folder, csv_output_file), 'w+', newline='') as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=csv_columns)
                writer.writeheader()
                for data in csv_rows:
                    writer.writerow(data)
        except IOError:
            print("I/O error")
            output_folder = None
            csv_output_file = None

        return output_folder, csv_output_file


print("Starting")

Machine.controller_ip = "192.168.1.87"
Machine.controller_username = "controller"
Machine.controller_password = "qsefthuk"
Machine.controller_path = "/home/"+Machine.controller_username+"/CREME_windows"

dls_test = DataLoggerServer(None, '192.168.1.99', 'dataloggerserver', 'qsefthuk', "/home/dataloggerserver/All_data")
Vul_client_1 = VulnerableClient(None, '192.168.1.110', 'testbed_2', 'qsefthuk', None)
Non_vul_client_1 = NonVulnerableClient(None, '192.168.1.103', 'client_2', 'qsefthuk', None)
Non_vul_client_2 = NonVulnerableClient(None, '192.168.1.117', 'benign_2', 'qsefthuk', None)
Kali_test = AttackerServer(None, '192.168.1.106', 'root', 'qsefthuk', None, Vul_client_1.ip)

Creme_test = Creme(dls_test, [Vul_client_1], [Non_vul_client_1, Non_vul_client_2], Kali_test, True, False)


#Creme_test.run()
#Creme_test.start_collect_data()
#time.sleep(20)
#Creme_test.stop_collect_data()
#Creme_test.centralize_data()
#Creme_test.configure()
#Creme_test.attack_cred_steal()
#time.sleep(5)
#Creme_test.clean_attack()
#Creme_test.merge_pcap_files()
#Creme_test.uniform_log_file_name()
#Creme_test.uniform_accounting_file_name()
#Creme_test.process_data_cred_steal()
#Creme_test.label_data_general_scenerio("cred_steal")
#Creme_test.label_data_general_scenerio("cred_steal")

#data_sources = Creme_test.process_data()
#Creme_test.train_ML(data_sources)
#Creme_test.process_data_cred_steal()
#Creme_test.process_data_disk_wipe()

