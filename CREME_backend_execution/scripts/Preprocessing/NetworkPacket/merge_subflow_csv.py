import os
import sys
import pandas as pd

def main(argv):
    if len(argv) != 2:
        print("Usage: {} filename_postfix".format(argv[0]))
        sys.exit()

    final = pd.DataFrame()
    for filename in os.listdir(os.getcwd()):
        if '.csv' in filename:
            # print(filename)
            temp = pd.read_csv(filename, dtype={'Sport': object, 'Dport': object})
            final = final.append(temp)
            final = final.reset_index(drop=True)
            os.remove(filename)

    final = final.sort_values(by=['StartTime'], ascending=True)
    final.to_csv('merge_' + sys.argv[1] + '.csv', index=False)

if __name__ == '__main__':
    main(sys.argv)
