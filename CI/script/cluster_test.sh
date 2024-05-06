#!/bin/sh
DIR_PATH=$(cd `dirname $0`;pwd)
code_path=$(cd ${DIR_PATH}/../../;pwd)
regress_path=${code_path}/pkg/test/ct_regress
script_path=${code_path}/CI/script
mkdir /home/cantiandba/tmp -p
tmp_file_path=/home/cantiandba/tmp
report_file=$tmp_file_path/regress.log
rm -rf $tmp_file_path/*
BASHRC_ORIGIN_NUM=$(sed -n '$=' /home/cantiandba/.bashrc)
echo export CTDB_HOME=/home/cantiandb/install >> /home/cantiandba/.bashrc
echo export CTDB_HOME_1=/home/cantiandb1/install >> /home/cantiandba/.bashrc
echo export sys_user_passwd='mHmNxBvw7Uu7LtSvrUIy8NY9womwIuJG9vAlMl0+zNifU7x5TnIz5UOqmkozbTyW' >> /home/cantiandba/.bashrc
echo export CTSQL_SSL_QUIET=TRUE >> /home/cantiandba/.bashrc
export CTDB_HOME=/home/cantiandb/install
export CTDB_HOME_1=/home/cantiandb1/install
PORT=`/sbin/ifconfig -a|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d "addr:" |head -n 1`
echo export PORT=${PORT} >> /home/cantiandba/.bashrc
collect_core()
{
    BASHRC_AFTER_NUM=$(sed -n '$=' /home/cantiandba/.bashrc)
    sed $(($BASHRC_ORIGIN_NUM+1)),${BASHRC_AFTER_NUM}d -i /home/cantiandba/.bashrc
	files=/home/core/CantianDB_`date +%Y-%m-%d-%H-%M-%S`
	mkdir -p ${files}
	# cp -r ${code_path}/pkg/bin ${files}/
	# cp -r ${code_path}/pkg/lib ${files}/
	mkdir -p ${files}/cantiandb0
	mkdir -p ${files}/cantiandb1
	cp -r ${CTDB_HOME}/add-ons ${files}/cantiandb0
	cp -r ${CTDB_HOME}/bin ${files}/cantiandb0
	cp -r ${CTDB_HOME}/cfg ${files}/cantiandb0
	cp -r ${CTDB_HOME}/lib ${files}/cantiandb0
	cp -r ${CTDB_HOME}/log ${files}/cantiandb0

	cp -r ${CTDB_HOME}/cfg ${files}/cantiandb1
	cp -r ${CTDB_HOME_1}/log ${files}/cantiandb1
    cp /home/ctsql.log ${files}/
    cp ${report_file} ${files}/

    tar -zcf ${files}.tar.gz  ${files}
    mv ${files}.tar.gz ${files}.tar.gz.log
    mkdir -p /home/regress/daac/build_test/logs/
    ls -l /home/core
    cp -r /home/core/* /home/regress/daac/build_test/logs/
    ls -l /home/regress/daac/build_test/logs/
}

log()
{
    echo
    echo
    echo $1
}

kill_cantiandb()
{
    ps -ef |grep cantiand |grep -v grep |awk '{print $2}' |xargs kill -9
    sleep 2
    ps -ef |grep cms |grep -v grep |awk '{print $2}' |xargs kill -9
    sleep 2

}

init_and_start_cms1()
{
    rm -rf /home/cms
	mkdir -p /home/cms
	dd if=/dev/zero of=/home/cms/gcc_file bs=100M count=1
    export CMS_HOME=${CTDB_HOME}
	echo export CMS_HOME=${CTDB_HOME} >> /home/cantiandba/.bashrc
	rm -rf ${CMS_HOME}/cfg/cms.ini
	echo NODE_ID = 0 >> ${CMS_HOME}/cfg/cms.ini
	echo GCC_HOME = /home/cms/gcc_file >> ${CMS_HOME}/cfg/cms.ini
    echo GCC_TYPE = FILE >> ${CMS_HOME}/cfg/cms.ini
    echo _IP = 127.0.0.1 >> ${CMS_HOME}/cfg/cms.ini
    echo _PORT = 1720 >> ${CMS_HOME}/cfg/cms.ini
    echo _DISK_DETECT_FILE = gcc_file >> ${CMS_HOME}/cfg/cms.ini
    chmod -R 777 /home/cms/
    chown -R cantiandba:cantiandba /home/cms/
    chmod -R 777 ${CMS_HOME}/
    chown -R cantiandba:cantiandba ${CMS_HOME}/
	su - cantiandba -c 'cms gcc -reset -f' >> $report_file
	su - cantiandba -c 'cms node -add 0 node0 127.0.0.1 1720' >> $report_file
	su - cantiandba -c 'cms node -add 1 node1 127.0.0.1 1721' >> $report_file
	su - cantiandba -c 'cms res -add db -type db -attr "check_timeout=10"'>> $report_file
    su - cantiandba -c 'cms node -list' >> $report_file
	su - cantiandba -c 'cms res -list' >> $report_file
    echo "start to start cms 1"   
    nohup su - cantiandba -c 'cms server -start' >> $report_file  2>&1 &
}

init_and_start_cms2()
{
    export CMS_HOME=${CTDB_HOME_1}
	rm -rf ${CMS_HOME}/cfg/cms.ini
	echo NODE_ID = 1 >> ${CMS_HOME}/cfg/cms.ini
	echo GCC_HOME = /home/cms/gcc_file >> ${CMS_HOME}/cfg/cms.ini
    echo GCC_TYPE = FILE >> ${CMS_HOME}/cfg/cms.ini
    echo _IP = 127.0.0.1 >> ${CMS_HOME}/cfg/cms.ini
    echo _PORT = 1721 >> ${CMS_HOME}/cfg/cms.ini
    echo _DISK_DETECT_FILE = gcc_file >> ${CMS_HOME}/cfg/cms.ini
    chmod -R 777 ${CMS_HOME}/
    chown -R cantiandba:cantiandba ${CMS_HOME}/
    echo "start to start cms 2"   
    nohup su - cantiandba -c 'cms server -start' >> $report_file  2>&1 &
}

init_ct_regress()
{
    log "=============== Initialize the Regression Program =============="
    kill_cantiandb
    rm -rf ${CTDB_HOME}
    mkdir -p ${CTDB_HOME}/data
    mkdir -p ${CTDB_HOME}/cfg
    mkdir -p ${CTDB_HOME}/log
    mkdir -p ${CTDB_HOME}/protect
    chmod 755 ${CTDB_HOME} -R

    echo COMPATIBLE_MYSQL = 0 >> ${CTDB_HOME}/cfg/cantiand.ini
    echo JOB_QUEUE_PROCESSES = 0 >> ${CTDB_HOME}/cfg/cantiand.ini
    echo STATS_LEVEL = BASIC >> ${CTDB_HOME}/cfg/cantiand.ini
    echo CLUSTER_DATABASE = TRUE >> ${CTDB_HOME}/cfg/cantiand.ini
    echo "INTERCONNECT_ADDR = 127.0.0.1;${PORT}" >> ${CTDB_HOME}/cfg/cantiand.ini
    echo INTERCONNECT_PORT = 1601,1602 >> ${CTDB_HOME}/cfg/cantiand.ini
    echo INTERCONNECT_TYPE = TCP >> ${CTDB_HOME}/cfg/cantiand.ini
    echo INSTANCE_ID = 0 >> ${CTDB_HOME}/cfg/cantiand.ini
    echo MES_POOL_SIZE = 16384 >> ${CTDB_HOME}/cfg/cantiand.ini
    echo LSNR_ADDR = 127.0.0.1   >> ${CTDB_HOME}/cfg/cantiand.ini
    echo LSNR_PORT = 1611 >> ${CTDB_HOME}/cfg/cantiand.ini
    echo _LOG_LEVEL = 16712567 >> ${CTDB_HOME}/cfg/cantiand.ini
    echo USE_NATIVE_DATATYPE = TRUE >> ${CTDB_HOME}/cfg/cantiand.ini
    echo _SYS_PASSWORD = pkAqfAUA0AdWc/O/W13ODhC9+5o+V1fWhXHm1kGv7z79S/GQyydsJFnLix8jBrY43bdNMsPJmYfwziCSpxgASC3Hi+3eq+C4lsCxy5dDimVWGWTGNfwpfA== >> ${CTDB_HOME}/cfg/cantiand.ini

    rm -rf ${CTDB_HOME_1}
    mkdir -p ${CTDB_HOME_1}/cfg
    mkdir -p ${CTDB_HOME_1}/log
    mkdir -p ${CTDB_HOME_1}/protect
    chmod 755 ${CTDB_HOME_1} -R

    echo COMPATIBLE_MYSQL = 0 >> ${CTDB_HOME_1}/cfg/cantiand.ini
    echo JOB_QUEUE_PROCESSES = 0 >> ${CTDB_HOME_1}/cfg/cantiand.ini
    echo STATS_LEVEL = BASIC >> ${CTDB_HOME_1}/cfg/cantiand.ini
    echo CLUSTER_DATABASE = TRUE >> ${CTDB_HOME_1}/cfg/cantiand.ini
    echo "INTERCONNECT_ADDR = 127.0.0.1;${PORT}" >> ${CTDB_HOME_1}/cfg/cantiand.ini
    echo INTERCONNECT_PORT = 1601,1602 >> ${CTDB_HOME_1}/cfg/cantiand.ini
    echo INTERCONNECT_TYPE = TCP >> ${CTDB_HOME_1}/cfg/cantiand.ini
    echo INSTANCE_ID = 1 >> ${CTDB_HOME_1}/cfg/cantiand.ini
    echo MES_POOL_SIZE = 16384 >> ${CTDB_HOME_1}/cfg/cantiand.ini
    echo LSNR_ADDR = ${PORT}   >> ${CTDB_HOME_1}/cfg/cantiand.ini
    echo LSNR_PORT = 1612 >> ${CTDB_HOME_1}/cfg/cantiand.ini
    echo _LOG_LEVEL = 16712567 >> ${CTDB_HOME_1}/cfg/cantiand.ini
    echo USE_NATIVE_DATATYPE = TRUE >> ${CTDB_HOME_1}/cfg/cantiand.ini
    echo _SYS_PASSWORD = pkAqfAUA0AdWc/O/W13ODhC9+5o+V1fWhXHm1kGv7z79S/GQyydsJFnLix8jBrY43bdNMsPJmYfwziCSpxgASC3Hi+3eq+C4lsCxy5dDimVWGWTGNfwpfA== >> ${CTDB_HOME_1}/cfg/cantiand.ini

    echo CONTROL_FILES = ${CTDB_HOME}/data/ctrl1, ${CTDB_HOME}/data/ctrl2, ${CTDB_HOME}/data/ctrl3 >> ${CTDB_HOME_1}/cfg/cantiand.ini
}

make_code()
{
    log "==================== Begin Rebuild CantianKernel ================="
    lcov_build_flag=""
    if [ "${LCOV_ENABLE}" = TRUE ]
    then
        lcov_build_flag="lcov=1"
    fi
    cd ${code_path}/build
    sh Makefile.sh clean
    sh Makefile.sh make_regress_test ${lcov_build_flag} DAAC_READ_WRITE=1
    if [ "$?" != "0" ]; then
        error "make package error!"
    fi
    cd ${code_path}/build
    source ./common.sh
    cd ${code_path}/build/pkg/test/cluster_test
    strip -N main ${CANTIANDB_LIB}/libzeserver.a
    make -sj 8
    if [ "$?" != "0" ]; then
        echo "make test error!"
        exit 1
    fi
    chown -R cantiandba:cantiandba ${code_path}/build/pkg/
}

cp_cantian_add_ons()
{
    mkdir -p $1/add-ons
    cp -d ${code_path}/library/pcre/lib/libpcre2-8.so*     $1/add-ons/
    cp -d ${code_path}/library/zlib/lib/libz.so*     $1/add-ons/
    cp -d ${code_path}/library/Zstandard/lib/libzstd.so*     $1/add-ons/
    cp -d ${code_path}/library/lz4/lib/liblz4.so*     $1/add-ons/
}

cp_cantian_bin()
{
    echo "################    cp_cantian_bin     #######################"
    mkdir -p $1/bin
    cp ${code_path}/output/bin/cantiand $1/bin/
    cp ${code_path}/output/bin/cms $1/bin/
    cp ${code_path}/output/bin/ctbackup $1/bin/
    cp ${code_path}/output/bin/ctsql $1/bin/
    cp ${code_path}/output/bin/ctbox $1/bin/
    cp ${code_path}/output/bin/ctencrypt $1/bin/
    cp ${code_path}/library/Zstandard/bin/zstd $1/bin/

    cp ${code_path}/pkg/install/installdb.sh  $1/bin/
    cp ${code_path}/pkg/install/shutdowndb.sh  $1/bin/
    cp ${code_path}/pkg/install/uninstall.py  $1/bin/
    cp ${code_path}/pkg/install/script/cluster/cluster.sh  $1/bin/
}

cp_cantian_lib()
{
    mkdir -p $1/lib
    cp ${code_path}/output/lib/libzeclient.so $1/lib/
    cp ${code_path}/output/lib/libzecommon.so $1/lib/
    cp ${code_path}/output/lib/libzeprotocol.so $1/lib/
}

install_cantiandb()
{
    log "========================= Install CantianDB ======================="
    echo "################    copy new lib     #######################"

    if [ ! -d ${CTDB_HOME} ];then
	    mkdir -p ${CTDB_HOME}
    fi

    rm -rf ${CTDB_HOME}/add-ons
    rm -rf ${CTDB_HOME}/bin
    rm -rf ${CTDB_HOME}/lib
	rm -rf ${CTDB_HOME}/admin
    # tar -zxvf ${code_path}/output/bin/Cantian-DATABASE-CENTOS-64bit/Cantian-RUN-CENTOS-64bit.tar.gz -C ${CTDB_HOME}
    # cp -rf ${CTDB_HOME}/Cantian-RUN-CENTOS-64bit/add-ons     ${CTDB_HOME}
    # cp -rf ${CTDB_HOME}/Cantian-RUN-CENTOS-64bit/bin         ${CTDB_HOME}
    # cp -rf ${CTDB_HOME}/Cantian-RUN-CENTOS-64bit/lib         ${CTDB_HOME}
    # cp -rf ${CTDB_HOME}/Cantian-RUN-CENTOS-64bit/admin       ${CTDB_HOME}
    # cp -rf ${CTDB_HOME}/Cantian-RUN-CENTOS-64bit/package.xml ${CTDB_HOME}
    # rm -rf ${CTDB_HOME}/Cantian-RUN-CENTOS-64bit

    cp_cantian_add_ons /home/cantiandb/install
    cp_cantian_bin /home/cantiandb/install
    cp_cantian_lib /home/cantiandb/install
    cp -R ${code_path}/pkg/admin  ${CTDB_HOME}/

    echo export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:${CTDB_HOME}/add-ons/nomlnx:${CTDB_HOME}/add-ons:${CTDB_HOME}/lib >> /home/cantiandba/.bashrc
    echo export PATH=${CTDB_HOME}/bin:$PATH >> /home/cantiandba/.bashrc

    if [ ! -d ${CTDB_HOME_1} ];then
        mkdir -p ${CTDB_HOME_1}
    fi

    rm -rf ${CTDB_HOME_1}/add-ons
    rm -rf ${CTDB_HOME_1}/bin
    rm -rf ${CTDB_HOME_1}/lib
    rm -rf ${CTDB_HOME_1}/admin

    # tar -zxvf ${code_path}/output/bin/Cantian-DATABASE-CENTOS-64bit/Cantian-RUN-CENTOS-64bit.tar.gz -C ${CTDB_HOME_1}
    # cp -rf ${CTDB_HOME_1}/Cantian-RUN-CENTOS-64bit/add-ons     ${CTDB_HOME_1}
    # cp -rf ${CTDB_HOME_1}/Cantian-RUN-CENTOS-64bit/bin         ${CTDB_HOME_1}
    # cp -rf ${CTDB_HOME_1}/Cantian-RUN-CENTOS-64bit/lib         ${CTDB_HOME_1}
    # cp -rf ${CTDB_HOME_1}/Cantian-RUN-CENTOS-64bit/admin       ${CTDB_HOME_1}
    # cp -rf ${CTDB_HOME_1}/Cantian-RUN-CENTOS-64bit/package.xml ${CTDB_HOME_1}
    # rm -rf ${CTDB_HOME_1}/Cantian-RUN-CENTOS-64bit

    cp_cantian_add_ons /home/cantiandb1/install
    cp_cantian_bin /home/cantiandb1/install
    cp_cantian_lib /home/cantiandb1/install
    cp -R ${code_path}/pkg/admin  ${CTDB_HOME_1}/

    chmod -R 777 ${CTDB_HOME}/
    chown -R cantiandba:cantiandba ${CTDB_HOME}/
    chmod -R 777 ${CTDB_HOME_1}/
    chown -R cantiandba:cantiandba ${CTDB_HOME_1}/

    echo "copy linux lib complate!!"   
    echo "start to init cms 1"   
    init_and_start_cms1

    echo "Start cantiand with nomount:"

	echo export CMS_HOME=${CTDB_HOME} >> /home/cantiandba/.bashrc
    nohup su - cantiandba -c 'cantiand nomount -D ${CTDB_HOME}' >> $report_file  2>&1 &
    pid=`ps ux | grep cantiand |grep -v grep |awk '{print $2}'`
    echo "cantiand pid=$pid"
    sleep 10
    rm -rf /home/ctsql.log
    echo "create database ..."
    chmod -R 777 ${code_path}/CI/build/script/init.sql
    chown -R cantiandba:cantiandba ${code_path}/CI/build/script/init.sql
    su - cantiandba -c "ctsql sys/sys@127.0.0.1:1611 -q -f ${code_path}/CI/build/script/init.sql" >> /home/ctsql.log

    echo "start cantiand node1"
    sleep 60

    echo export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:${CTDB_HOME_1}/add-ons/nomlnx:${CTDB_HOME_1}/add-ons:${CTDB_HOME_1}/lib >> /home/cantiandba/.bashrc
    echo export PATH=${CTDB_HOME_1}/bin:$PATH >> /home/cantiandba/.bashrc
    echo "start to init cms 2"   
    init_and_start_cms2
    export CMS_HOME=${CTDB_HOME_1}

    echo export CMS_HOME=${CTDB_HOME_1} >> /home/cantiandba/.bashrc
    su - cantiandba -c 'cantiand -h' 2>&1
    su - cantiandba -c 'cantiand -v' 2>&1
    nohup su - cantiandba -c 'cantiand -D ${CTDB_HOME_1}' >> $report_file  2>&1 &
    sleep 20  
    pid1=`ps ux | grep cantiand |grep -v grep |awk '{print $2}'`
    echo "cantiand pid1=$pid1"
	sleep 10

	echo "create new user"
   
    su - cantiandba -c 'ctsql sys/sys@127.0.0.1:1611 -c "create user cluster_tester identified by database_123;" ' >> /home/ctsql.log
   
    su - cantiandba -c 'ctsql sys/sys@127.0.0.1:1611 -c "grant dba to cluster_tester;" ' >> /home/ctsql.log

    su - cantiandba -c 'ctsql sys/sys@127.0.0.1:1611 -c "grant all privileges to cluster_tester;" ' >> /home/ctsql.log

    su - cantiandba -c 'ctsql sys/sys@127.0.0.1:1611 -c "grant unlimited tablespace to cluster_tester;" ' >> /home/ctsql.log

    error_num=`cat /home/ctsql.log |grep 'Succeed.'|wc -l`
    if [ $error_num -eq 0 ];then
       echo "Error: create database failed"
       collect_core
       exit 1
    fi
	sleep 2
    echo "copy linux lib complate!!"

}

run_ctbox_test()
{
    su - cantiandba -c "ctbox -T cminer -c ${code_path}/ctbox_test/ctrl_test -F -D -C"
    su - cantiandba -c "ctbox -T cminer -f ${code_path}/ctbox_test/page_test -F -D -C"
    su - cantiandba -c "ctbox -T cminer -l ${code_path}/ctbox_test/redo_test -F -D -C"
    su - cantiandba -c "echo -e 'y' | ctbox -T crepair -k ${code_path}/ctbox_test/dataObj -c storage.redo[1].logfiles[9].block_size=5120" || true
    echo
    su - cantiandba -c "echo -e 'y' | ctbox -T crepair -k ${code_path}/ctbox_test/dataObj -c storage.node[0].rcy_point=0-0-0-0-0" || true
    echo
    su - cantiandba -c "echo -e 'y' | ctbox -T crepair -k ${code_path}/ctbox_test/dataObj -c storage.node[1].lrp_point=0-0-0-0-0" || true
    echo
    su - cantiandba -c "echo -e 'y' | ctbox -T crepair -k ${code_path}/ctbox_test/dataObj -c storage.spaces[9].spaceid=1" || true
    echo
    su - cantiandba -c "echo -e 'y' | ctbox -T crepair -k ${code_path}/ctbox_test/dataObj -c storage.datafiles[9].dfileid=1" || true
    echo
    su - cantiandba -c "echo -e 'y' | ctbox -T crepair -k ${code_path}/ctbox_test/dataObj -c storage.redo[1].archive[9].first=1" || true
    echo
    su - cantiandba -c "echo -e 'y' | ctbox -T crepair -k ${code_path}/ctbox_test/dataObj -c storage.redo[1].logfiles[9].block_size=1" || true
    echo
    su - cantiandba -c "echo -e 'y' | ctbox -T crepair -k ${code_path}/ctbox_test/dataObj -c storage.node[0].raft_point=0" || true
    echo
    su - cantiandba -c "echo -e 'y' | ctbox -T crepair -k ${code_path}/ctbox_test/dataObj -c storage.redo[6].logfiles[9].block_size=1" || true
    echo
    su - cantiandba -c "echo -e 'y' | ctbox -T crepair -k ${code_path}/ctbox_test/dataObj -c storage.redo[1].archive[10250].first=1" || true
    echo
    su - cantiandba -c "echo -e 'y' | ctbox -T crepair -k ${code_path}/ctbox_test/dataObj -c storage.redo[1].logfiles[257].block_size=1" || true
    echo
    su - cantiandba -c "echo -e 'y' | ctbox -T crepair -k ${code_path}/ctbox_test/dataObj -c storage.redo[1].datefiles[257].block_size=1" || true
    echo
    su - cantiandba -c "echo -e 'y' | ctbox -T crepair -k ${code_path}/ctbox_test/dataObj -c storage.node[6].rcy_point=0-0-0-0-0" || true
    echo
    su - cantiandba -c "echo -e 'y' | ctbox -T crepair -k ${code_path}/ctbox_test/dataObj -c storage.spaces[1025].spaceid=1" || true
    echo
    su - cantiandba -c "echo -e 'y' | ctbox -T crepair -k ${code_path}/ctbox_test/dataObj -c storage.datafiles[1025].dfileid=1" || true
    echo
}

run_cluster_test()
{
	log "========================= Run Cluster Test ======================="
	echo `pwd`
    chown -R cantiandba:cantiandba ${code_path}/output/bin/cluster_test
    chmod -R 777 ${code_path}/output/bin/cluster_test
    # chown -R cantiandba:cantiandba ${code_path}/bazel-bin/pkg/test/cluster_test/cluster_test
    # chmod -R 777 ${code_path}bazel-bin/pkg/test/cluster_test/cluster_test
	# su - cantiandba -c "${code_path}/bazel-bin/pkg/test/cluster_test/cluster_test '127.0.0.1:1611' ${PORT}':1612' $1" 2>&1 | tee -a $report_file
    su - cantiandba -c "${code_path}/output/bin/cluster_test '127.0.0.1:1611' ${PORT}':1612' $1" 2>&1 | tee -a $report_file
    test_num=`cat $report_file | grep '\--------------------- TEST_CASE' | wc -l`
    succ_num=`cat $report_file | grep '\--------------------- FINISHED ---------------------' | wc -l`
    BASHRC_AFTER_NUM=$(sed -n '$=' /home/cantiandba/.bashrc)
	if [ $succ_num -ne $test_num ];then
	   echo "something wrong when cluster_test!"
	   echo "something wrong when cluster_test!" >> $report_file 2>&1
	   collect_core
	   exit 1
	fi
    sed $(($BASHRC_ORIGIN_NUM+1)),${BASHRC_AFTER_NUM}d -i /home/cantiandba/.bashrc
	echo "success finish cluster_test!"
}

gen_lcov_report()
{
    if [[ ! -d "${code_path}/lcov_output" ]]
    then 
	    mkdir -p ${code_path}/lcov_output
    fi
   
    coverage_info_name="${code_path}/lcov_output/cluster_test_coverage.info"
    coverage_report_name="${code_path}/lcov_output/cluster_test_coverage.report"
    find ${code_path}/ -name "*.gcno" | xargs touch
    lcov --capture --directory ${code_path}/ --rc lcov_branch_coverage=1 --output-file "${coverage_info_name}" 
    lcov -l --rc lcov_branch_coverage=1 "${coverage_info_name}" > "${coverage_report_name}" 
    # Reset all execution counts to zero
    lcov -d ./ -z
    log ">>>>>>>>>>>>>>>>>>>>> Lcov report successfully <<<<<<<<<<<<<<<<<<<<<<<<<<<"
}

main()
{
    LCOV_ENABLE=FALSE
    test_list=-1
    for arg in "$@"
    do 
        echo "arg is ${arg}"
        if [ ${arg} = "--coverage" ]
        then 
            echo "Enable coverage detection."
            LCOV_ENABLE=TRUE
        fi

        if [ ${arg} = "test_list_0" ]
        then 
            echo "Enable coverage detection."
            test_list=0
        fi

        if [ ${arg} = "test_list_1" ]
        then 
            echo "Enable coverage detection."
            test_list=1
        fi
    done

    echo "test_list is ${test_list}"

    init_ct_regress
    make_code
    install_cantiandb
    #run_ctbox_test
    run_cluster_test ${test_list}

    # collect_core

    if [ "${LCOV_ENABLE}" = TRUE ]
    then 
        gen_lcov_report
    fi
}

main "$@"                                    
