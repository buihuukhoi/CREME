import os
import paramiko
import pandas as pd
import json
from dateutil.parser import parse
from CREMEapplication.models import ProgressData
from . import Drain
import csv
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
import matplotlib.pyplot as plt
import time
import socket
import time
import numpy as np
import random

class ScriptHelper:
    @staticmethod
    def get_del_known_hosts_path(scripts_path, del_script="./del_known_hosts.sh"):
        del_known_hosts_path = os.path.join(scripts_path, del_script)
        return del_known_hosts_path

    @staticmethod
    def get_script_cmd(file):
        scripts_path = os.path.join("CREME_backend_execution", "scripts")
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


class ProgressHelper:
    """
    this class supports to update progress data that used to display progress on the dashboard
    """
    scenario = "scenario"
    status_fields = {1: "stage_1_status", 2: "stage_2_status", 3: "stage_3_status", 4: "stage_4_status",
                     5: "stage_5_status", 6: "stage_6_status", 7: "stage_7_status"}
    detail_fields = {1: "stage_1_detail", 2: "stage_2_detail", 3: "stage_3_detail", 4: "stage_4_detail",
                     5: "stage_5_detail", 6: "stage_6_detail", 7: "stage_7_detail"}
    attack_phase_fields = {0: "attack_phase_1_data", 1: "attack_phase_2_data", 2: "attack_phase_3_data"}
    messages = []

    @staticmethod
    def update_scenario(scenario):
        """
        use to update displayed scenario on the dashboard
        """
        progress_data_all = ProgressData.objects.all()
        progress_data = progress_data_all.first()
        setattr(progress_data, ProgressHelper.scenario, scenario)
        progress_data.save()

    @staticmethod
    def clean_stages(start_stage, end_stage):
        """
        use to clean next stages when moving to a new stage.
        it is called by update_stage() function
        """
        progress_data_all = ProgressData.objects.all()
        progress_data = progress_data_all.first()

        off_status = 1
        off_detail = "None"
        for i in range(start_stage, end_stage + 1):
            status_field = ProgressHelper.status_fields[i]
            detail_field = ProgressHelper.detail_fields[i]
            setattr(progress_data, status_field, off_status)
            setattr(progress_data, detail_field, off_detail)
        progress_data.save()

    @staticmethod
    def update_messages(message, size, finished_task, override_pre_message, finished_stage, new_stage):
        """
        use to update messages in the detail part of stage.
        it is called by update_stage() function
        """
        if new_stage:
            ProgressHelper.messages = []

        running_icon = '<i class="fa fa-refresh" aria-hidden="true"></i>'
        success_icon = '<i class="fa fa-check" aria-hidden="true"></i>'
        if finished_task:
            icon = success_icon
        else:
            icon = running_icon
        localtime = time.localtime()
        time_stamp =  time.strftime("%H:%M:%S", localtime)
        message = f'<h{size}>{icon} {message} {time_stamp}</h{size}>'
        # message += "<br>"

        if override_pre_message:
            ProgressHelper.messages[-1] = message
        else:
            ProgressHelper.messages.append(message)

        if finished_stage:
            finished_message = "Finished Stage"
            class_finish_stage = ' class="alert alert-success" role="alert"'
            finished_message = f'<h{size}{class_finish_stage}>{icon} {finished_message}</h{size}>'
            ProgressHelper.messages.append(finished_message)
    
    def update_stage(stage, message, size, finished_task=False, override_pre_message=False, finished_stage=False,
                     new_stage=False):
        """
        use to update status and detail of stages on the dashboard
        """
        if new_stage:
            ProgressHelper.clean_stages(stage, 7)

        ProgressHelper.update_messages(message, size, finished_task, override_pre_message, finished_stage, new_stage)
        detail = ""
        for message in ProgressHelper.messages:
            detail += message

        # update progress object
        progress_data_all = ProgressData.objects.all()
        progress_data = progress_data_all.first()

        status_field = ProgressHelper.status_fields[stage]
        if new_stage:
            setattr(progress_data, status_field, 2)
        if finished_stage:
            setattr(progress_data, status_field, 3)
        detail_field = ProgressHelper.detail_fields[stage]
        setattr(progress_data, detail_field, detail)
        progress_data.save()

    @staticmethod
    def update_attack_phase_data(attack_phases_data):
        """
        use to update the content(sub-technique) of attack phases
        """
        num_of_phases = len(attack_phases_data)
        if num_of_phases is not 3:
            while True:
                # should not come here, number of phases must be 3
                pass

        progress_data_all = ProgressData.objects.all()
        progress_data = progress_data_all.first()

        for i in range(3):
            attack_phase_field = ProgressHelper.attack_phase_fields[i]
            data = attack_phases_data[i]
            setattr(progress_data, attack_phase_field, data)
        progress_data.save()


class ProcessDataHelper:
    @staticmethod
    def make_labeling_file(labeling_file_path, tactic_names, technique_names, sub_technique_names, t, src_ips, des_ips,
                           normal_ips, normal_hostnames, abnormal_hostnames, pattern_normal_cmd_list=[[],[],[]],
                           force_abnormal_cmd_list=[[],[],[]]):
        """
        use to create a labeling file which is a parameter using to label data
        """
        t1, t2, t3, t4, t5, t6 = map(float, t)

        # if attack_scenario == MIRAI:
        #     t1 = XXX + 1

        # each element is one stage in an attack scenario
        my_list = []
        my_list.append([tactic_names[0], technique_names[0], sub_technique_names[0], t1, t2 + 1, src_ips[0], des_ips[0],
                        normal_ips[0], normal_hostnames[0], abnormal_hostnames[0], pattern_normal_cmd_list[0],
                        force_abnormal_cmd_list[0]])
        my_list.append([tactic_names[1], technique_names[1], sub_technique_names[1], t3, t4 + 1, src_ips[1], des_ips[1],
                        normal_ips[1], normal_hostnames[1], abnormal_hostnames[1], pattern_normal_cmd_list[1],
                        force_abnormal_cmd_list[1]])
        my_list.append([tactic_names[2], technique_names[2], sub_technique_names[2], t5, t6 + 1, src_ips[2], des_ips[2],
                        normal_ips[2], normal_hostnames[2], abnormal_hostnames[2], pattern_normal_cmd_list[2],
                        force_abnormal_cmd_list[2]])
        with open(labeling_file_path, "w+") as fw:
            json.dump(my_list, fw)

    @staticmethod
    def get_time_stamps_mirai(log_folder, dur):
        time_1_kali_start_scan = os.path.join(log_folder, "time_1_kali_start_scan.txt")
        time_2_start_transfer = os.path.join(log_folder, "time_2_start_transfer.txt")
        time_4_start_DDoS = os.path.join(log_folder, "time_4_start_DDoS.txt")

        with open(time_1_kali_start_scan, 'rt') as f1:
            t1 = int(f1.readline())
        with open(time_2_start_transfer, 'rt') as f2:
            t2 = int(f2.readline())
        with open(time_4_start_DDoS, 'rt') as f3:
            t3 = int(f3.readline())
            #t4 = t3
        t5 = t3 + int(dur) + 10  # 10 to avoid problems if there is some delay
        # return t1, t2, t3, t4, t5
        return t1, t2, t3, t5

    @staticmethod
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

    @staticmethod
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

    @staticmethod
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

    @staticmethod
    def load_dataset_accounting(folder, filenames, finalname, one_hot_fields=[], removed_fields=[],
                                replace_strings=dict(), remove_rows_with_str=dict()):
        df = pd.DataFrame()
        for tmp_filename in filenames:
            filename = os.path.join(folder, tmp_filename)
            tmp_df = pd.read_csv(filename)
            # print(len(tmp_df[tmp_df['Label'] == 0]))
            # print(len(tmp_df[tmp_df['Label'] == 1]))
            df = df.append(tmp_df)

        # print(len(df.columns.values))
        # print(df.columns.values)

        # print(len(df))
        # df.drop_duplicates(keep=False, inplace=True)
        # print(len(df))

        for field in removed_fields:
            del df[field]
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
        for k in list(df):
            df[k] = pd.to_numeric(df[k], errors='ignore')

        """
        print(len(df.columns.values))

        print(df.dtypes)

        print(df.isnull().any())

        print(df['RDDSK'].unique())
        """

        # output_filename = os.path.join(folder, 'preprocess_label_atop.csv')
        output_filename = os.path.join(folder, finalname)
        df.to_csv(output_filename, encoding='utf-8', index=False)

        return df

    @staticmethod
    def execute_accounting(folder, train_filenames, finalname):
        # folder = r'Data\\Accounting'
        # train_filenames = ['label_atop_mirai.csv', 'new_label_atop_second.csv', 'new_label_atop_third.csv',
        #                 'new_label_atop_fourth.csv', 'new_label_atop_fifth.csv']
        # test_filename='UNSW_NB15_testing-set.csv'

        one_hot_fields = ['POLI', 'ST', 'EXC', 'S']
        removed_fields = ['TIMESTAMP', 'PID', 'CMD', 'Hostname', 'Tactic', 'Technique', 'SubTechnique']
        # removed_fields = ['TIMESTAMP', 'PID', 'CMD', 'Hostname']
        replace_strings = {'%': '', 'K': '000', 'M': '000000', 'G': '000000000'}
        remove_rows_with_str = {'-': '0'}
        """
        label_field = 'Label'
        tactic_field = 'Tactic'
        technique_field = 'Technique'
        sub_technique_field = 'SubTechnique'
        threshold = 0.01
        """
        ProcessDataHelper.load_dataset_accounting(folder, train_filenames, finalname, one_hot_fields=one_hot_fields,
                                                  removed_fields=removed_fields, replace_strings=replace_strings,
                                                  remove_rows_with_str=remove_rows_with_str)

        # Helper.rankFeatures(folder, train_filename, hash_fields=hash_fields, removed_fields=removed_fields,
        #                    replace_strings=replace_strings, remove_rows_with_str=remove_rows_with_str,
        #                    label_field=label_field, threshold=threshold)
        # Helper.MLModel(folder, train_filename, test_filename)

    @staticmethod
    def handle_accounting_and_packet_2(labeling_file_path, output_file_atop, output_file_traffic, log_folder,
                                       accounting_folder, traffic_file, accounting_result_path, traffic_result_path,
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
        accounting_folder = os.path.join(log_folder, accounting_folder)  # Logs/Mirai/Original/Accounting_1/
        traffic_file = os.path.join(log_folder, traffic_file)

        # traffic_file = os.path.join(log_folder, traffic_folder)  # Logs/Mirai/Original/Traffic_1/traffic.pcap
        # traffic_file = os.path.join(traffic_file, "traffic.pcap")

        # output_file_atop = "label_atop.csv"
        # output_file_traffic = "label_traffic.csv"
        accounting_extraction_file = "CREME_backend_execution/scripts/Preprocessing/Accounting/./accounting_extraction.sh "
        cmd = '{0} {1} {2} {3} {4}'.format(accounting_extraction_file, labeling_file_path, accounting_folder,
                                           accounting_result_path, output_file_atop)
        os.system(cmd)
        accounting_extraction_file = "CREME_backend_execution/scripts/Preprocessing/NetworkPacket/./traffic_extraction.sh"
        cmd = '{0} {1} {2} {3} {4} {5}'.format(accounting_extraction_file, labeling_file_path, traffic_file,
                                               time_window_traffic, traffic_result_path, output_file_traffic)
        os.system(cmd)

    @staticmethod
    def handle_accounting_packet_all_scenario(biglist, folder_traffic, file_traffic, finalname_traffic, folder_atop,
                                              file_atop, finalname_atop, time_window_traffic):
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
            output_file_atop = file_atop[i]
            output_file_traffic = file_traffic[i]
            log_folder = information[1]
            accounting_folder = information[2]
            traffic_file = information[3]
            accounting_result_path = folder_atop
            traffic_result_path = folder_traffic

            ProcessDataHelper.handle_accounting_and_packet_2(labeling_file_path, output_file_atop, output_file_traffic,
                                                             log_folder, accounting_folder, traffic_file,
                                                             accounting_result_path, traffic_result_path,
                                                             time_window_traffic)

        ProcessDataHelper.execute_traffic(folder_traffic, file_traffic, finalname_traffic)
        ProcessDataHelper.execute_accounting(folder_atop, file_atop, finalname_atop)

    # ----- Handle Syslog -----
    @staticmethod
    def filter_syslog(input_file, t_start, t_end, dls_hostname):
        """
        this function filter syslog from input_file from t_start to t_end times, remove logs from dls_hostname, and
        separate the log into apache_log and normal syslog.
        """
        with open(input_file, 'rt') as f:
            lines = f.readlines()

        return_lines = []
        return_lines_apache = []

        apache_access = 'apache-access'

        for line in lines:
            fields = line.split(' ')
            if len(fields) < 2:
                continue
            time_string = fields[0]
            hostname = fields[1]

            if hostname != dls_hostname:
                dateTime = parse(time_string)
                # timestamp = (int)(dateTime.strftime("%s"))
                timestamp = (int)(dateTime.timestamp())

                if (int)(t_start) <= timestamp <= (int)(t_end):
                    component = fields[2]
                    if component == apache_access:
                        return_lines_apache.append(line)

                    else:
                        return_lines.append(line)

        return return_lines, return_lines_apache

    @staticmethod
    def parse_syslog(input_files, input_dir='Logs/Mirai/Original/Syslog_1', output_dir='Logs/Mirai/Result/'):
        # input_dir = 'Logs/Mirai/Original/Syslog_1'  # The input directory of log file
        # output_dir = 'Logs/Mirai/Result/'  # The output directory of parsing results

        benchmark_settings = {
            'Linux': {
                # 'log_file': '{0}.log'.format(host),
                'log_file': input_files[0],
                'log_format': '<Time> <HostName> <Component>(\[<PID_or_IP>\])?: <Content>',
                # 'log_format': '<Time> <HostName> <Component>(\[<PID>\])?: <Content>',
                #        'log_format': '<Month> <Date> <Time> <Level> <Component>(\[<PID>\])?: <Content>',
                # 'regex': [r'(\d+\.){3}\d+', r'\d{2}:\d{2}:\d{2}'],
                'regex': [r'(\d+\.){3}\d+', r'\d{2}:\d{2}:\d{2}', r'[A-Za-z0-9]+9E:', r'<[0-9]+\.[A-Z0-9]+\@.*>',
                          r'[A-Z0-9]{10,}', r'[0-9]+\.$'],
                'st': 0.2,
                # 'st': 0.39,
                'depth': 6
            },
            'Apache': {
                'log_file': input_files[1],
                # 'log_format': '<Time> <HostName> <Component> <SourceIP> - - \[<Time_Apache>\] <Content>',
                'log_format': '<Time> <HostName> <Component> <PID_or_IP> - - \[<Time_Apache>\] <Content>',
                #        'log_format': '<Month> <Date> <Time> <Level> <Component>(\[<PID>\])?: <Content>',
                'regex': [],
                'st': 0.2,
                'depth': 4
            },
        }

        lisf_of_output_files = []
        for dataset, setting in benchmark_settings.items():
            print('\n=== Evaluation on %s ===' % dataset)
            indir = os.path.join(input_dir, os.path.dirname(setting['log_file']))
            log_file = os.path.basename(setting['log_file'])

            parser = Drain.LogParser(log_format=setting['log_format'], indir=indir, outdir=output_dir,
                                     rex=setting['regex'],
                                     depth=setting['depth'], st=setting['st'])
            parser.parse(log_file)

            lisf_of_output_files.append([setting['log_file'] + "_structured.csv", setting['log_file'] + "_templates.csv"])
        return lisf_of_output_files

    @staticmethod
    def get_all_component_event_ids(abnormal_group, normal_group, t_start, t_end,):
        filtered_normal_group = normal_group[((t_start <= normal_group['Timestamp'].astype(int)) &
                                              (normal_group['Timestamp'].astype(int) < t_end))]
        normal_component_event_ids = filtered_normal_group['ComponentEventId']

        return list(set(normal_component_event_ids))

    @staticmethod
    def label_filtered_syslog(df, t, white_list_1, white_list_2, white_list_3, labels, tactics,
                              techniques, sub_techniques):
        # print('Begin label 0: {0}'.format(len(df[df['Label'] == 0])))
        # print('Begin label 1: {0}'.format(len(df[df['Label'] == 1])))
        t1, t2, t3, t4, t5, t6 = map(float, t)
        df.loc[(t1 <= df['Timestamp'].astype(int)) & (df['Timestamp'].astype(int) < t2) & (
            ~df['ComponentEventId'].isin(white_list_1)), ['Label', 'Tactic', 'Technique', 'SubTechnique']] = \
            labels[0], tactics[0], techniques[0], sub_techniques[0]
        df.loc[(t3 <= df['Timestamp'].astype(int)) & (df['Timestamp'].astype(int) < t4) & (
            ~df['ComponentEventId'].isin(white_list_2)), ['Label', 'Tactic', 'Technique', 'SubTechnique']] = \
            labels[1], tactics[1], techniques[1], sub_techniques[1]
        df.loc[(t5 <= df['Timestamp'].astype(int)) & (df['Timestamp'].astype(int) <= t6) & (
            ~df['ComponentEventId'].isin(white_list_3)), ['Label', 'Tactic', 'Technique', 'SubTechnique']] = \
            labels[2], tactics[2], techniques[2], sub_techniques[2]

    @staticmethod
    def counting_vector(folder, input_file, output_file):
        """
        use to convert input_file(label_syslog.csv) to counting vector and save to output_file.
        Return output_file if successful, otherwise --> return None
        :param folder:
        :param input_file:
        :param output_file:
        :return:
        """
        # all_df_count_vector = pd.DataFrame()
        # df = pd.DataFrame()

        filename = os.path.join(folder, input_file)

        col_list = ['HostName', 'EventTemplate', 'Timestamp', 'Label']
        one_hot_col_list = ['EventTemplate']
        df = pd.read_csv(filename, usecols=col_list)

        # print(len(df['Timestamp'].unique()))

        df = pd.get_dummies(df, columns=one_hot_col_list)

        hostnames = df['HostName'].unique()

        df_count_vector = pd.DataFrame()

        df_machines = []
        unique_timestamps_machines = []
        for hostname in hostnames:
            df_machines.append(df[df['HostName'] == hostname])

        for df_machine in df_machines:
            unique_timestamps = list(set(df_machine['Timestamp']))
            unique_timestamps_machines.append(unique_timestamps)

        del_col_list = ['HostName', 'Timestamp']
        for i in range(len(df_machines)):
            df_machine = df_machines[i]
            tmp_unique_timestamps = unique_timestamps_machines[i]
            for tmp_timestamp in tmp_unique_timestamps:
                tmp_df = df_machine[df_machine['Timestamp'] == tmp_timestamp]
                tmp_df = tmp_df.drop(columns=del_col_list)

                sum_one_hot = tmp_df.sum()
                df_count_vector = df_count_vector.append(sum_one_hot.transpose(), ignore_index=True)

        df_count_vector.loc[df_count_vector['Label'] > 0, 'Label'] = 1
        # all_df_count_vector = all_df_count_vector.append(df_count_vector)

        # try to save results
        try:
            full_output_file = os.path.join(folder, output_file)
            df_count_vector.to_csv(full_output_file, encoding='utf-8', index=False)
            return output_file
        except IOError:
            return None

    @staticmethod
    def handle_syslog(input_files, scenarios_timestamps, scenarios_abnormal_hostnames, scenarios_normal_hostnames,
                      scenarios_labels, scenarios_tactics, scenarios_techniques, scenarios_sub_techniques, dls_hostname,
                      result_path, output_file):
        filtered_lines = []
        filtered_lines_apache = []
        remove_files = []
        for i in range(len(input_files)):
            input_file = input_files[i]
            stage_timestamps = scenarios_timestamps[i]
            tmp_filtered_lines, tmp_filtered_lines_apache = \
                ProcessDataHelper.filter_syslog(input_file, stage_timestamps[0][0], stage_timestamps[-1][1],
                                                dls_hostname)
            filtered_lines.extend(tmp_filtered_lines)
            filtered_lines_apache.extend(tmp_filtered_lines_apache)

        filtered_syslog = "filtered_dataset_generation.log"
        filtered_syslog_apache = "filtered_dataset_generation_apache.log"
        # write to new files
        filtered_syslog_path = os.path.join(result_path, filtered_syslog)
        filtered_syslog_apache_path = os.path.join(result_path, filtered_syslog_apache)
        with open(filtered_syslog_path, 'w+') as fw:
            fw.write("".join(filtered_lines))
        with open(filtered_syslog_apache_path, 'w+') as fw:
            fw.write("".join(filtered_lines_apache))
        remove_files.append(filtered_syslog_path)
        remove_files.append(filtered_syslog_apache_path)

        # parse logs
        # tmp_output_files is a list 2d
        tmp_list_of_output_files = ProcessDataHelper.parse_syslog([filtered_syslog, filtered_syslog_apache],
                                                          input_dir=result_path, output_dir=result_path)
        for tmp_output_files in tmp_list_of_output_files:
            for tmp_file in tmp_output_files:
                remove_files.append(os.path.join(result_path, tmp_file))

        # merge syslog and apache log
        filtered_syslog_structured = os.path.join(result_path, tmp_list_of_output_files[0][0])
        filtered_syslog_structured_apache = os.path.join(result_path, tmp_list_of_output_files[1][0])

        df_syslog = pd.read_csv(filtered_syslog_structured)
        df_apache = pd.read_csv(filtered_syslog_structured_apache)
        del df_apache['Time_Apache']
        df = df_syslog.append(df_apache, ignore_index=True)

        # get diff services to label data
        # syslog_structured = os.path.join(result_path, "{0}_structured.csv".format(filtered_syslog))
        syslog_structured = "syslog_structured.csv"

        # load csv file to pandas
        # df = pd.read_csv(syslog_structured)
        # convert time to timestamp for filtering
        df['Timestamp'] = df['Time'].apply(lambda x: parse(x).timestamp())
        df = df.sort_values('Timestamp')
        del df['LineId']
        df = df.reset_index(drop=True)
        df.index = df.index.set_names(['Index'])
        tmp_output = os.path.join(result_path, syslog_structured)
        df.to_csv(tmp_output, encoding='utf-8', index=True)
        remove_files.append(tmp_output)

        # concatenate "Component" and "EventId" to new column and delete that column late
        df["ComponentEventId"] = df["Component"].astype(str) + "-" + df["EventId"].astype(str)
        # set default value for: label=0 Tactic=Normal Technique=Normal Sub-Technique=Normal
        df['Label'], df['Tactic'], df['Technique'], df['SubTechnique'] = [0, 'Normal', "Normal", "Normal"]

        # label
        for i in range(len(scenarios_timestamps)):  # each scenario
            white_list = []
            # stage
            for j in range(len(scenarios_timestamps[i])):  # each stage
                abnormal_hostnames = scenarios_abnormal_hostnames[i][j]
                normal_hostnames = scenarios_normal_hostnames[i][j]
                abnormal_df = df[(df['HostName'].isin(abnormal_hostnames))]
                normal_df = df[(df['HostName'].isin(normal_hostnames))]
                t_start = scenarios_timestamps[i][j][0]
                t_end = scenarios_timestamps[i][j][1]
                tmp_white_list = ProcessDataHelper.get_all_component_event_ids(abnormal_df, normal_df, t_start, t_end)
                white_list.extend(tmp_white_list)

            labels = scenarios_labels[i]
            tactics = scenarios_tactics[i]
            techniques = scenarios_techniques[i]
            sub_techniques = scenarios_sub_techniques[i]

            t = [scenarios_timestamps[i][0][0], scenarios_timestamps[i][0][1], scenarios_timestamps[i][1][0],
                 scenarios_timestamps[i][1][1], scenarios_timestamps[i][2][0], scenarios_timestamps[i][2][1]]
            # label
            ProcessDataHelper.label_filtered_syslog(df, t, white_list, white_list, white_list, labels, tactics,
                                                    techniques, sub_techniques)
            # print('label 0: {0}'.format(len(df[df['Label'] == 0])))
            # print('label 1: {0}'.format(len(df[df['Label'] == 1])))
            # print('\n')

        del df['ComponentEventId']
        tmp_output = "{0}_{1}".format("original", output_file)
        full_tmp_output = os.path.join(result_path, tmp_output)
        df.to_csv(full_tmp_output, encoding='utf-8', index=False)

        # remove temporary files
        for remove_file in remove_files:
            os.system("rm {0}".format(remove_file))

        output_file = ProcessDataHelper.counting_vector(result_path, tmp_output, output_file)
        return output_file

    # ----- Balance data and Filter features -----
    @staticmethod
    def balance_data(folder: str, input_file: str, balanced_label_zero=True):
        """
        use to balance the label 0 and label 1 data in folder/input_file,
        store the balanced data to a output file and return that file name
        """
        df = pd.read_csv(os.path.join(folder, input_file))

        # print(len(df.columns.values))

        df_0 = df[df['Label'] == 0]
        df_1 = df[df['Label'] == 1]
        # print('len(df): {0}'.format(len(df)))
        # print('label_0: {0}'.format(len(df_0)))
        # print('label_1: {0}'.format(len(df_1)))

        
        df_0.drop_duplicates(keep='last', inplace=True)
        df_1.drop_duplicates(keep='last', inplace=True)
        num_of_label_0 = len(df_0)
        num_of_label_1 = len(df_1)
        new_df_0 = pd.DataFrame()
        if balanced_label_zero:
            if(num_of_label_1 > num_of_label_0):
                if("traffic" in input_file):
                    df_1.drop( df_1[(df_1['Rate'] == 0.0) & (df_1['SrcRate'] == 0.0) & (df_1['DstRate'] == 0)].index 
                df = df_0.append(df_1)
            
            
        else:
            if(num_of_label_1 < num_of_label_0):
                
                
                if("traffic" in input_file):
                    ind = df_0[(df_0['Rate'] == 0.0) & (df_0['SrcRate'] == 0.0) & (df_0['DstRate'] == 0)].index
                    df_0.drop(ind)
                df = df_1.append(df_0)

        df.to_csv(os.path.join(folder, input_file), encoding='utf-8', index=False)

    @staticmethod
    def filter_features(folder: str, filename: str, corr_threshold=0.1, label_field="Label"):
        """
        use to filter/remove features have correlation with Label less then the corr_threshold
        in the folder/filename
        """
        tmp_filename = os.path.join(folder, filename)
        df = pd.read_csv(tmp_filename)

        # drop space character at the end of feature's name
        column_names = df.columns.values
        for i in range(len(column_names)):
            column_names[i] = column_names[i].strip()
        df.columns = column_names

        test = df.corr()
        removed_features = test.index[abs(test[label_field]) < corr_threshold].tolist()

        # update features and re-save the file
        df.drop(removed_features, axis=1, inplace=True)
        df.to_csv(tmp_filename, encoding='utf-8', index=False)


    @staticmethod
    def merge_other_logs_2_syslog(other_log_files, syslog_file, timestamps_syslog, hostnames, time_zone="+08:00",
                                  component="continuum[]"):
        t_start = timestamps_syslog[0][0]
        t_end = timestamps_syslog[-1][1]
        new_lines = []

        for i, log_file in enumerate(other_log_files):
            with open(log_file, 'rt') as fr:
                lines = fr.readlines()

            for line in lines:
                fields = line.split(maxsplit=4)
                tmp_date = fields[0]
                hour_min_second = (fields[1]).split(',')[0]
                log_message = fields[-1]
                if len(fields) < 5 or len(tmp_date.split('-')) is not 3:
                    continue  # something is wrong here

                time_string = "{0}T{1}{2}".format(tmp_date, hour_min_second, time_zone)
                dateTime = parse(time_string)
                timestamp = (int)(dateTime.timestamp())
                if (int)(t_start) <= timestamp <= (int)(t_end):
                    new_line = "{0} {1} {2}: {3}".format(time_string, hostnames[i], component, log_message)
                    new_lines.append(new_line)

        with open(syslog_file, 'a') as fa:
            for line in new_lines:
                fa.write("{}\n".format(line))


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
                models['decision_tree'] = DecisionTreeClassifier(random_state=1)
            if 'naive_bayes' in models_name:
                models['naive_bayes'] = GaussianNB()
            if 'extra_tree' in models_name:
                models['extra_tree'] = ExtraTreeClassifier(random_state=1)
            if 'knn' in models_name:
                models['knn'] = KNeighborsClassifier()
            if 'random_forest' in models_name:
                models['random_forest'] = RandomForestClassifier(n_jobs=-1,random_state=1)
            if 'XGBoost' in models_name:
                models['XGBoost'] = XGBClassifier(n_jobs=-1,random_state=1)
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
            # draw chart
            csv_file = os.path.join(output_folder, csv_output_file)
            df = pd.read_csv(csv_file)
            ax = df.plot.barh(x='ML_algorithms',y=['test_accuracy','test_f1','test_precision','test_recall'],width=0.8,figsize=(10,10))
            ax.legend(bbox_to_anchor=(1.1,1.1))
            for i in ax.patches:
                ax.text(i.get_width(), i.get_y()+0.1, 
                        str(round((i.get_width()), 2)), 
                        fontsize=10, fontweight='bold', 
                        color='grey') 
            ax.get_figure().savefig(os.path.join(output_folder,'accuracy_for_{0}.png'))
        except IOError:
            print("I/O error")
            output_folder = None
            csv_output_file = None

        return output_folder, csv_output_file

    @staticmethod
    def efficiency(input_folder, input_file, num_of_folds=5, standard_scale=True):
        # ----- train model -----
        filename = os.path.join(input_folder, input_file)
        df = pd.read_csv(filename)

        label_field = 'Label'

        X = df.loc[:, df.columns != label_field]
        y = df.loc[:, df.columns == label_field]
        # features_train = X.columns.values
        # print(len(list(features_train)))

        if standard_scale:  # standard scale
            scaler = preprocessing.StandardScaler()
        else:  # Min Max scale
            scaler = preprocessing.MinMaxScaler()
        scaler = scaler.fit(X)
        tmp_df = scaler.transform(X)
        X = pd.DataFrame(tmp_df)

        # if you want use other models, change at here
        model = XGBClassifier()

        if num_of_folds < 2:
            num_of_folds = 5
        # cv = KFold(n_splits=5, random_state=1, shuffle=True)
        cv = StratifiedKFold(n_splits=num_of_folds, shuffle=True, random_state=1)

        rfecv = RFECV(estimator=model, scoring='accuracy', cv=cv)
        rfecv.fit(X, y)

        # print('Optimal number of features: %d' % rfecv.n_features_)

        return rfecv


class EvaluationHelper:
    # ----- efficiency -----
    @staticmethod
    def generate_existing_efficiency(output_folder, output_file):
        """
        use to generate existing efficiency from pre-calculate existing datasets.
        Because calculating efficiency for existing datasets will take a lot of time
        """
        filename = os.path.join(output_folder, output_file)

        csv_columns = ["dataset", "total_features", "important_feature", "score"]

        csv_rows = []
        csv_rows.append(
            {"dataset": "Ton-IoT-Windows", "total_features": 124, "important_feature": 1, "score": round(1 / 124, 3)})
        csv_rows.append(
            {"dataset": "UNSW-NB15", "total_features": 202, "important_feature": 30, "score": round(30 / 202, 3)})
        csv_rows.append(
            {"dataset": "Ton-IoT-Network", "total_features": 227, "important_feature": 37, "score": round(37 / 227, 3)})
        csv_rows.append(
            {"dataset": "CICIDS", "total_features": 78, "important_feature": 18, "score": round(18 / 78, 3)})
        csv_rows.append({"dataset": "Bot-IoT", "total_features": 20, "important_feature": 5, "score": round(5 / 20, 3)})
        csv_rows.append(
            {"dataset": "Kyoto 2006 +", "total_features": 26, "important_feature": 17, "score": round(17 / 26, 3)})

        # try to save results
        try:
            with open(filename, 'w+', newline='') as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=csv_columns)
                writer.writeheader()
                for data in csv_rows:
                    writer.writerow(data)
        except IOError:
            print("I/O error")
            output_folder = None
            output_file = None

        return output_folder, output_file

    @staticmethod
    def find_important_features(rfecv, threshold) -> (int, int):
        grid_scores = rfecv.grid_scores_
        total_features = len(grid_scores)
        important_features = total_features
        maximum = max(grid_scores)
        acceptable_accuracy = maximum - threshold
        for index, accuracy in enumerate(grid_scores):
            if accuracy >= acceptable_accuracy:
                important_features = index + 1
                break
        return total_features, important_features

    @staticmethod
    def efficiency(data_source, rfecv, eff_folder, eff_file, threshold=0.0001):
        total_features, important_features = EvaluationHelper.find_important_features(rfecv, threshold)
        eff_file_path = os.path.join(eff_folder, eff_file)
        df_eff = pd.read_csv(eff_file_path)
        new_row = ["CREME-{0}".format(data_source), total_features, important_features,
                   round(important_features / total_features, 3)]
        df_eff.loc[len(df_eff)] = new_row
        df_eff.to_csv(eff_file_path, index=False)

        figure_output_file = "{0}_efficiency.png".format(data_source)
        figure_output_file = os.path.join(eff_folder, figure_output_file)
        plt.figure()
        plt.xlabel("number of features selected")
        plt.ylabel('cross validation score')
        plt.plot(range(1, len(rfecv.grid_scores_) + 1), rfecv.grid_scores_)
        plt.savefig(figure_output_file)

    # ----- coverage -----
    @staticmethod
    def generate_coverage(output_folder, output_file, weights, creme_attack_scenarios, creme_attack_types):
        """
        use to generate coverage for datasets with corresponding weights.
        """
        # weights = {"attack_types": 4 / 10 / 20, "attack_scenarios": 2 / 10 / 20, "data_sources": 1 / 10 / 6,
        #            "labeled_data": 1 / 10 / 6, "feature_set": 1 / 10 / 6, "metadata": 1 / 10}
        filename = os.path.join(output_folder, output_file)

        creme_num_of_scenarios = len(set(creme_attack_scenarios))
        creme_num_of_attack_types = len(set(creme_attack_types))

        csv_columns = ["dataset", "attack_types", "attack_scenarios", "data_sources", "labeled_data", "feature_set",
                       "metadata", "score"]

        csv_rows = []
        # existing datasets
        csv_rows.append({"dataset": "IoT-NID", "attack_types": 5, "attack_scenarios": 1, "data_sources": 1,
                         "labeled_data": 1, "feature_set": 0, "metadata": 1})
        csv_rows.append({"dataset": "NGIDS-DS", "attack_types": 7, "attack_scenarios": 0, "data_sources": 2,
                         "labeled_data": 1, "feature_set": 1, "metadata": 1})
        csv_rows.append({"dataset": "Kyoto 2006 +", "attack_types": 8, "attack_scenarios": 0, "data_sources": 1,
                         "labeled_data": 1, "feature_set": 1, "metadata": 1})
        csv_rows.append({"dataset": "CICIDS", "attack_types": 8, "attack_scenarios": 0, "data_sources": 1,
                         "labeled_data": 1, "feature_set": 1, "metadata": 1})
        csv_rows.append({"dataset": "BoT-IoT", "attack_types": 7, "attack_scenarios": 2, "data_sources": 1,
                         "labeled_data": 1, "feature_set": 1, "metadata": 1})
        csv_rows.append({"dataset": "UNSW-NB15", "attack_types": 10, "attack_scenarios": 0, "data_sources": 1,
                         "labeled_data": 1, "feature_set": 1, "metadata": 1})
        csv_rows.append({"dataset": "IoT-23", "attack_types": 7, "attack_scenarios": 10, "data_sources": 1,
                         "labeled_data": 1, "feature_set": 0, "metadata": 1})
        csv_rows.append({"dataset": "NDSec-1", "attack_types": 9, "attack_scenarios": 3, "data_sources": 2,
                         "labeled_data": 1, "feature_set": 1, "metadata": 1})
        csv_rows.append({"dataset": "Ton-IoT", "attack_types": 9, "attack_scenarios": 0, "data_sources": 3,
                         "labeled_data": 3, "feature_set": 3, "metadata": 1})
        # creme dataset
        csv_rows.append({"dataset": "CREME", "attack_types": creme_num_of_attack_types,
                         "attack_scenarios": creme_num_of_scenarios, "data_sources": 3,
                         "labeled_data": 3, "feature_set": 3, "metadata": 1})

        for row in csv_rows:  # dataset
            score = 0
            for key, value in row.items():
                if weights.__contains__(key):
                    score += value * weights[key]
            row["score"] = round(score, 3)

        # try to save results
        try:
            with open(filename, 'w+', newline='') as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=csv_columns)
                writer.writeheader()
                for data in csv_rows:
                    writer.writerow(data)
        except IOError:
            print("I/O error")
            output_folder = None
            output_file = None

        return output_folder, output_file


class OtherHelper:
    @staticmethod
    def wait_finishing(sleep_time, record_time=False, folder="", timestamp_file=""):
        time.sleep(sleep_time)
        if record_time:
            output_time_file = os.path.join(folder, timestamp_file)
            with open(output_time_file, "w+") as fw:
                fw.write('%f' % time.time())

    @staticmethod
    def wait_machine_up(ip):
        host_up = False
        while not host_up:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.settimeout(1)
                result = sock.connect_ex((ip, 22))
                if result == 0:
                    host_up = True
                else:
                    host_up = False
            except socket.error as exc:
                print("Caught exception socket.error : {0}".format(exc))
            finally:
                sock.close()
            time.sleep(1)
