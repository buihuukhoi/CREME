import pandas as pd
import sys
import os
import json

# Tactic
# Normal(0), Initial Access(1), Command and Control(2), Impact(3)
# Technique
# Normal(0), Valid Accounts(1), Non-Application Layer Protocol(2), Network Denial of Service(3)

def main(argv):
    if len(argv) != 5:
        print("Usage: {} filename labeling_abs_file result_abs_path result_file_name".format(argv[0]))
        sys.exit()

    filename = argv[1]
    
    labeling_abs_file = argv[2]
    labeling_list = None
    with open(labeling_abs_file, "r") as fp:
        labeling_list = json.load(fp)

    result_abs_path = argv[3]
    result_file_name = argv[4]

    # filter: start <-> end
    start = labeling_list[0][3]
    end = labeling_list[-1][4]
    df = pd.read_csv(filename, dtype={'Sport': object, 'Dport': object})
    df = df[(df['StartTime'] >= start) & (df['StartTime'] <= end)]
    
    # add label column
    label = [0]*len(df) # -1: delete, 0: normal, 1: abnormal
    df['Label'] = label
    tactic = ['Normal']*len(df)
    df['Tactic'] = tactic
    technique = ['Normal']*len(df)
    df['Technique'] = technique
    sub_technique = ['Normal']*len(df)
    df['SubTechnique'] = sub_technique
    
    for stage_list in labeling_list:
        tactic_name = stage_list[0]
        technique_name = stage_list[1]
        sub_technique_name = stage_list[2]
        start_time = stage_list[3]
        end_time = stage_list[4]
        srcip_list = stage_list[5]
        dstip_list = stage_list[6]
        normalip_list = stage_list[7]

        stage = df[(df['StartTime'] >= start_time) & (df['StartTime'] < end_time)]
        idx = stage[stage['SrcAddr'].isin(normalip_list) | stage['DstAddr'].isin(normalip_list)].index
        df.loc[idx, 'Label'] = 0
        # df.loc[idx, 'Tactic'] = 'Normal'
        # df.loc[idx, 'Technique'] = 'Normal'
        # df.loc[idx, 'SubTechnique'] = 'Normal'

        idx = stage[((stage['SrcAddr'].isin(srcip_list)) & (stage['DstAddr'].isin(dstip_list))) | ((stage['SrcAddr'].isin(dstip_list)) & (stage['DstAddr'].isin(srcip_list)))].index
        df.loc[idx, 'Label'] = 1
        df.loc[idx, 'Tactic'] = tactic_name
        df.loc[idx, 'Technique'] = technique_name
        df.loc[idx, 'SubTechnique'] = sub_technique_name

        stage = df[(df['StartTime'] >= start_time) & (df['StartTime'] < end_time)]
        del_idx = stage[stage['Label'] == -1].index
        df = df.drop(del_idx)

    df = df[df['Label'] != -1]

    df.reset_index(drop=True)

    if not os.path.exists(result_abs_path):
        os.makedirs(result_abs_path)
    df.to_csv(os.path.join(result_abs_path, result_file_name), index=False)


if __name__ == '__main__':
    main(sys.argv)
