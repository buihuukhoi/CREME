#!/bin/sh

if [ $# != 3 ]; then
    echo "Usage: ./clientWebGet.sh folder atop_file interval"
    exit -1
fi

folder=$1
atop_file=$2
interval=$3

sleep 3

atop -a -w $folder/$atop_file $interval


