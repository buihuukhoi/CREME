if [ $# != 5 ]; then
    echo "Usage: ./traffic_extraction.sh labeling_file pcap_file time_window(secs) result_file_path result_file_name"
    exit -1
fi

labeling_file=$1
labeling_abs_file=$(realpath "$labeling_file")
pcap_file=$2
# pcap_file_name=$(basename "$pcap_file")
pcap_file_path=$(dirname $(realpath "$pcap_file"))
time_window=$3
result_file_path=$4
result_file_name=$5
root_path=$(pwd)
code_path=$(dirname $(realpath "$0"))
result_file_abs_path="${root_path}/${result_file_path}"

cd $code_path
./make_subflow_dataset.sh $time_window $pcap_file_path $code_path

cd "${pcap_file_path}/pcap_${time_window}secs"
csvfile="merge_${time_window}secs.csv"
python3 "${code_path}/make_label_subflow.py" $csvfile $labeling_abs_file $result_file_abs_path $result_file_name

cd $root_path
rm -r "${pcap_file_path}/pcap_${time_window}secs"