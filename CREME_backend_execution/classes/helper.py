import os
import paramiko
import pandas as pd
import json
from dateutil.parser import parse
from CREMEapplication.models import ProgressData
from . import Drain


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
                     5: "stage_5_detail", 7: "stage_6_detail", 7: "stage_7_detail"}
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
    def clean_attack_stages():
        """
        use to clean attack stages when moving to other attack scenario.
        it is called by update_stage() function
        """
        progress_data_all = ProgressData.objects.all()
        progress_data = progress_data_all.first()

        off_status = 1
        off_detail = "None"
        for i in range(2, 5):
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
        message = f'<h{size}>{icon} {message}</h{size}>'
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

    @staticmethod
    def update_stage(stage, message, size, finished_task=False, override_pre_message=False, finished_stage=False,
                     new_stage=False):
        """
        use to update status and detail of stages on the dashboard
        """
        if new_stage and stage == 2:
            ProgressHelper.clean_attack_stages()

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


class ProcessDataHelper:
    @staticmethod
    def make_labeling_file(labeling_file_path, tactic_names, technique_names, sub_technique_names, t, src_ips, des_ips,
                           normal_ips, normal_hostnames, abnormal_hostnames, drop_cmd_list):
        t1, t2, t3, t4, t5, t6 = map(float, t)

        # if attack_scenario == MIRAI:
        #     t1 = XXX + 1

        my_list = []
        my_list.append([tactic_names[0], technique_names[0], sub_technique_names[0], t1, t2 + 1, src_ips[0], des_ips[0],
                        normal_ips[0], normal_hostnames[0], abnormal_hostnames[0], drop_cmd_list])
        my_list.append([tactic_names[1], technique_names[1], sub_technique_names[1], t3, t4 + 1, src_ips[1], des_ips[1],
                        normal_ips[1], normal_hostnames[1], abnormal_hostnames[1], drop_cmd_list])
        my_list.append([tactic_names[2], technique_names[2], sub_technique_names[2], t5, t6 + 1, src_ips[2], des_ips[2],
                        normal_ips[2], normal_hostnames[2], abnormal_hostnames[2], drop_cmd_list])
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

        print(len(df.columns.values))
        print(df.dtypes)
        print(df.isnull().any())

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

        print(len(df.columns.values))
        print(df.dtypes)
        print(df.isnull().any())

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

        output_files = []
        for dataset, setting in benchmark_settings.items():
            print('\n=== Evaluation on %s ===' % dataset)
            indir = os.path.join(input_dir, os.path.dirname(setting['log_file']))
            log_file = os.path.basename(setting['log_file'])

            parser = Drain.LogParser(log_format=setting['log_format'], indir=indir, outdir=output_dir,
                                     rex=setting['regex'],
                                     depth=setting['depth'], st=setting['st'])
            parser.parse(log_file)

            output_files.append([setting['log_file'] + "_structured.csv", setting['log_file'] + "_templates.csv"])
        return output_files

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
        tmp_output_files = ProcessDataHelper.parse_syslog([filtered_syslog, filtered_syslog_apache],
                                                          input_dir=result_path, output_dir=result_path)
        for tmp_file in tmp_output_files:
            remove_files.append(os.path.join(result_path, tmp_file))

        # merge syslog and apache log
        filtered_syslog_structured = os.path.join(result_path, tmp_output_files[0][0])
        filtered_syslog_structured_apache = os.path.join(result_path, tmp_output_files[1][0])

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
        tmp_output = os.path.join(result_path, output_file)
        df.to_csv(tmp_output, encoding='utf-8', index=False)
        remove_files.append(tmp_output)

        # remove temporary files
        for remove_file in remove_files:
            os.system("rm {0}".format(remove_file))
