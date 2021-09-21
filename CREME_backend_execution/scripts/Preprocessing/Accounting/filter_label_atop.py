import pandas as pd
import sys
import os
import json


def filter_timerange(start, end):
    for filename in os.listdir(os.getcwd()):
        if "_merge.csv" in filename:
            df = pd.read_csv(filename)
            df = df[(df['TIMESTAMP'] >= start) & (df['TIMESTAMP'] <= end)]
            df.to_csv(filename, index=False)


def merge(label_df_dict, result_abs_path, result_file_name):
    final_df = None
    for filename, df in label_df_dict.items():
        ip = filename.split("_")[0]
        temp = df
        temp["Hostname"] = ip

        if final_df is None:
            final_df = temp
        else:
            final_df = final_df.append(temp)

    final_df = final_df.sort_values('TIMESTAMP')
    final_df.to_csv(os.path.join(result_abs_path, result_file_name), index=False)


def label(labeling_list, all_stage_abnormal_cmd_list, result_abs_path, result_file_name):
    label_df_dict = {}
    for filename in os.listdir(os.getcwd()):
        if "_merge.csv" in filename:
            df = pd.read_csv(filename)

            # add label column
            label = [0] * len(df)
            df['Label'] = label
            tactic = ['Normal'] * len(df)
            df['Tactic'] = tactic
            technique = ['Normal'] * len(df)
            df['Technique'] = technique
            sub_technique = ['Normal'] * len(df)
            df['SubTechnique'] = sub_technique

            for idx, stage_list in enumerate(labeling_list):
                tactic_name = stage_list[0]
                technique_name = stage_list[1]
                sub_technique_name = stage_list[2]
                start_time = stage_list[3]
                end_time = stage_list[4]
                abnormal_cmd_list = all_stage_abnormal_cmd_list[idx]

                stage = df[(df['TIMESTAMP'] >= start_time) & (df['TIMESTAMP'] < end_time)]
                idx = stage[stage['CMD'].isin(abnormal_cmd_list)].index
                df.loc[idx, 'Label'] = 1
                df.loc[idx, 'Tactic'] = tactic_name
                df.loc[idx, 'Technique'] = technique_name
                df.loc[idx, 'SubTechnique'] = sub_technique_name

            label_df_dict[filename] = df
            os.remove(filename)

    merge(label_df_dict, result_abs_path, result_file_name)


def compareStage(labeling_list, result_abs_path, result_file_name):
    all_stage_abnormal_cmd_list = []
    for stage_list in labeling_list:
        # tactic_name = stage_list[0]
        # technique_name = stage_list[1]
        # sub_technique_name = stage_list[2]
        start_time = stage_list[3]
        end_time = stage_list[4]
        # srcip_list = stage_list[5]
        # dstip_list = stage_list[6]
        # normalip_list = stage_list[7]
        normal_atop_list = [s + "_merge.csv" for s in stage_list[8]]
        abnormal_atop_list = [s + "_merge.csv" for s in stage_list[9]]

        # cmd with these patterns are always the label 0,
        pattern_normal_cmd_list = stage_list[10]

        normal_set = set()
        for normal_filename in normal_atop_list:
            df = pd.read_csv(normal_filename)
            stage = df[(df['TIMESTAMP'] >= start_time) & (df['TIMESTAMP'] < end_time)]
            normal_cmd_list = stage['CMD'].tolist()
            normal_set = normal_set.union(normal_cmd_list)

        abnormal_set = set()
        for idx, abnormal_filename in enumerate(abnormal_atop_list):
            df = pd.read_csv(abnormal_filename)
            stage = df[(df['TIMESTAMP'] >= start_time) & (df['TIMESTAMP'] < end_time)]
            abnormal_cmd_list = stage['CMD'].tolist()
            if idx == 0:
                abnormal_set = abnormal_set.union(abnormal_cmd_list)
            else:
                abnormal_set = abnormal_set.intersection(abnormal_cmd_list)

        stage_abnormal_cmd_list = list(abnormal_set - normal_set)
        for pattern_normal_cmd in pattern_normal_cmd_list:
            # remove cmd contains this pattern in abnormal_cmd_list  --> always label 0
            stage_abnormal_cmd_list = [cmd for cmd in stage_abnormal_cmd_list if pattern_normal_cmd not in cmd]

        all_stage_abnormal_cmd_list.append(stage_abnormal_cmd_list)

    label(labeling_list, all_stage_abnormal_cmd_list, result_abs_path, result_file_name)


def main(argv):
    if len(argv) != 4:
        print("Usage: {} labeling_abs_file result_abs_path result_file_name".format(argv[0]))
        sys.exit()

    labeling_abs_file = argv[1]
    labeling_list = None
    with open(labeling_abs_file, "r") as fp:
        labeling_list = json.load(fp)

    result_abs_path = argv[2]
    result_file_name = argv[3]

    start = labeling_list[0][3]
    end = labeling_list[-1][4]

    filter_timerange(start, end)
    compareStage(labeling_list, result_abs_path, result_file_name)


if __name__ == '__main__':
    main(sys.argv)