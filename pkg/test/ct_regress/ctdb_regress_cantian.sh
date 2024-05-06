#!/bin/bash

install_dir=$1
sys_passwd=$2
ct_schedule_list=$3

ctsql=${install_dir}/bin/ctsql

rm -rf ./results/*
rm -rf ${install_dir}/cumu_*.bak*
rm -rf ${install_dir}/cantiandb_*.bak*
export CTSQL_SSL_QUIET=TRUE
./ct_regress --bindir=${ctsql} --user=sys/${sys_passwd} --host=127.0.0.1 --port=1611 --inputdir=./sql/ --outputdir=./results/ --expectdir=./expected/ --schedule=./${ct_schedule_list}
if [ $? -eq 0 ];then
   echo "    ct_regress        :  OK"
   echo "********************* END: ct_regress *********************"
else
   echo "    ct_regress        :  FAILED"
   echo "********************* END: ct_regress *********************"
fi
