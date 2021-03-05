from functools import reduce
import pandas as pd
import sys

def main(argv):
    if len(argv) != 5:
        print("Usage: {} disk.csv memory.csv process.csv merge.csv".format(argv[0]))

    disk_filename = argv[1]
    memory_filename = argv[2]
    process_filename = argv[3]
    merge_filename = argv[4]

    disk_df = pd.read_csv(disk_filename)
    memory_df = pd.read_csv(memory_filename)
    process_df = pd.read_csv(process_filename)

    data_frames = [disk_df, memory_df, process_df]
    # df_merged = reduce(lambda left, right: pd.merge(left, right, on=['TIMESTAMP', 'PID', 'CMD'], how='outer'), data_frames).fillna(0)
    df_merged = reduce(lambda left, right: pd.merge(left, right, on=['TIMESTAMP', 'PID', 'CMD'], how='outer'), data_frames)

    df_merged.to_csv(merge_filename, index=False)

if __name__ == '__main__':
    main(sys.argv)
