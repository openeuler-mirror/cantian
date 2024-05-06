#!/bin/bash
DIR_PATH=$(dirname $0)
code_path=$(cd ${DIR_PATH}/../../;pwd)
echo "code_path: ${code_path}"

BASHRC_ORIGIN_NUM=$(sed -n '$=' /home/cantiandba/.bashrc)
export CTDB_HOME=/home/cantiandb/install
echo export CTSQL_SSL_QUIET=TRUE >> /home/cantiandba/.bashrc
echo export CTDB_HOME=/home/cantiandb/install >> /home/cantiandba/.bashrc
echo export sys_user_passwd='mHmNxBvw7Uu7LtSvrUIy8NY9womwIuJG9vAlMl0+zNifU7x5TnIz5UOqmkozbTyW' >> /home/cantiandba/.bashrc
GRUN_LOG=${code_path}/mes_gtest_run.log
rm -rf ${GRUN_LOG}
echo "MES_GRUN_LOG: ${GRUN_LOG}"

kill_cantiandb()
{
    ps -ef |grep cantiand |grep -v grep |awk '{print $2}' |xargs kill -9
    sleep 2
    ps -ef |grep cms |grep -v grep |awk '{print $2}' |xargs kill -9
    sleep 2
}

init_ct_regress()
{
    echo "=============== Initialize the Regression Program =============="
    kill_cantiandb
    rm -rf ${CTDB_HOME}
    mkdir -p ${CTDB_HOME}/data
    mkdir -p ${CTDB_HOME}/cfg
    mkdir -p ${CTDB_HOME}/log
    mkdir -p ${CTDB_HOME}/protect
    chmod 755 ${CTDB_HOME} -R

    echo JOB_QUEUE_PROCESSES = 0 >> ${CTDB_HOME}/cfg/cantiand.ini
    echo STATS_LEVEL = BASIC >> ${CTDB_HOME}/cfg/cantiand.ini
    echo CLUSTER_DATABASE = TRUE >> ${CTDB_HOME}/cfg/cantiand.ini
    echo INTERCONNECT_ADDR = 127.0.0.1 >> ${CTDB_HOME}/cfg/cantiand.ini
    echo INTERCONNECT_PORT = 1601 >> ${CTDB_HOME}/cfg/cantiand.ini
    echo INTERCONNECT_TYPE = TCP >> ${CTDB_HOME}/cfg/cantiand.ini
    echo INSTANCE_ID = 0 >> ${CTDB_HOME}/cfg/cantiand.ini
    echo LOG_HOME = ${CTDB_HOME}/log >> ${CTDB_HOME}/cfg/cantiand.ini
    echo MES_POOL_SIZE = 16384 >> ${CTDB_HOME}/cfg/cantiand.ini
    echo LSNR_ADDR = 127.0.0.1   >> ${CTDB_HOME}/cfg/cantiand.ini
    echo LSNR_PORT = 1611 >> ${CTDB_HOME}/cfg/cantiand.ini
    echo _LOG_LEVEL = 16712567 >> ${CTDB_HOME}/cfg/cantiand.ini
    echo USE_NATIVE_DATATYPE = TRUE >> ${CTDB_HOME}/cfg/cantiand.ini
    echo _SYS_PASSWORD = pkAqfAUA0AdWc/O/W13ODhC9+5o+V1fWhXHm1kGv7z79S/GQyydsJFnLix8jBrY43bdNMsPJmYfwziCSpxgASC3Hi+3eq+C4lsCxy5dDimVWGWTGNfwpfA== >> ${CTDB_HOME}/cfg/cantiand.ini
    echo ENABLE_SYSDBA_LOGIN = TRUE >> ${CTDB_HOME}/cfg/cantiand.ini
    echo UPPER_CASE_TABLE_NAMES = FALSE >> ${CTDB_HOME}/cfg/cantiand.ini
    echo SHM_MQ_MSG_RECV_THD_NUM = 25 >> ${CTDB_HOME}/cfg/cantiand.ini
    echo SHM_CPU_GROUP_INFO = 0 >> ${CTDB_HOME}/cfg/cantiand.ini
    echo MAX_COLUMN_COUNT = 4096 >> ${CTDB_HOME}/cfg/cantiand.ini
    echo INTERCONNECT_BY_PROFILE = TRUE >> ${CTDB_HOME}/cfg/cantiand.ini
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
	su - cantiandba -c 'cms gcc -reset -f' >> ${GRUN_LOG}
	su - cantiandba -c 'cms node -add 0 node0 127.0.0.1 1720' >> ${GRUN_LOG}
	su - cantiandba -c 'cms res -add db -type db -attr "check_timeout=1000000000"' >> ${GRUN_LOG}
    su - cantiandba -c 'cms res -edit db -attr "HB_TIMEOUT=1000000000"' >> ${GRUN_LOG}
    su - cantiandba -c 'cms node -list' >> ${GRUN_LOG}
	su - cantiandba -c 'cms res -list' >> ${GRUN_LOG}
    echo "start to start cms 1"   
    nohup su - cantiandba -c 'cms server -start' >> ${GRUN_LOG} 2>&1 &
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
    cp ${code_path}/pkg/install/sql_process.py  $1/bin/
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
    echo "========================= Install CantianDB ======================="
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

    export CTDB_HOME=/home/cantiandb/install
    export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${code_path}/output/lib/:${code_path}/library/gtest/lib/:${CTDB_HOME}/add-ons:${CTDB_HOME}/lib:${CTDB_HOME}/add-ons/nomlnx
    echo export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${code_path}/output/lib/:${code_path}/library/gtest/lib/:${CTDB_HOME}/add-ons:${CTDB_HOME}/lib:${CTDB_HOME}/add-ons/nomlnx >> /home/cantiandba/.bashrc
    echo export PATH=${CTDB_HOME}/bin:$PATH >> /home/cantiandba/.bashrc

    echo "copy linux lib complate!!"   
    echo "start to init cms 1"   
    init_and_start_cms1

    echo "Start cantiand with nomount:"
    UNAME=$(uname -a)
    if [[ "${UNAME}" =~ .*aarch64.* ]];then
        echo export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${code_path}/library/xnet/lib_arm/ >> /home/cantiandba/.bashrc
    elif [[ "${UNAME}" =~ .*x86_64.* ]];then
        echo export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${code_path}/library/xnet/lib/ >> /home/cantiandba/.bashrc
    else
        error "error: unknown arch!"
    fi
}

function dots(){
    seconds=${1:-5}
    while true 
    do
        sleep $seconds
        echo -n '.'
    done
}

function error(){
    BASHRC_AFTER_NUM=$(sed -n '$=' /home/cantiandba/.bashrc)
    sed $(($BASHRC_ORIGIN_NUM+1)),${BASHRC_AFTER_NUM}d -i /home/cantiandba/.bashrc
    echo $1
    echo $1 >> ${GRUN_LOG} 2>&1
    kill -9 ${DOTS_BG_PID}
    exit 1
}

make_code()
{
    echo -n "make test ..."
    lcov_build_flag=""
    dots 5 &
    DOTS_BG_PID=$!
    trap "kill -9 $DOTS_BG_PID" INT

    chmod 777 ${code_path}/pkg/test/mes_test/config
    chmod 600 ${code_path}/pkg/test/mes_test/config/ca.crt

    cd ${code_path}/build/
    sh Makefile.sh clean >> ${GRUN_LOG} 2>&1

    if [ "${LCOV_ENABLE}" = TRUE ]
    then
        lcov_build_flag="lcov=1"
    fi

    sh Makefile.sh make_regress_test ${lcov_build_flag} DAAC_READ_WRITE=1 >> ${GRUN_LOG} 2>&1
    if [ "$?" != "0" ]; then
        error "make package error!"
    fi

    cd ${code_path}/build
    source ./common.sh
    cd ${code_path}/build/pkg/test/unit_test/ut/mes
    strip -N main ${CANTIANDB_LIB}/libzeserver.a >> ${GRUN_LOG} 2>&1
    make -sj 8 >> ${GRUN_LOG} 2>&1
    if [ "$?" != "0" ]; then
        error "make test error!"
    fi
    chown -R cantiandba:cantiandba ${code_path}/build/pkg/
}

run_mes_test()
{
    echo
    echo -n "run mes_test ..."
    if [[ ! -d "${code_path}/gtest_result" ]]
    then
        mkdir -p ${code_path}/gtest_result
    fi
    chown -R cantiandba:cantiandba ${code_path}/gtest_result
    su - cantiandba -c "${code_path}/output/bin/mes_test --gtest_output=xml:${code_path}/gtest_result/" >> ${GRUN_LOG} 2>&1
    if [ "$?" != "0" ]; then
        error "run mes_test error!"
    fi
    echo
    echo "run mes_test success!"
    BASHRC_AFTER_NUM=$(sed -n '$=' /home/cantiandba/.bashrc)
    sed $(($BASHRC_ORIGIN_NUM+1)),${BASHRC_AFTER_NUM}d -i /home/cantiandba/.bashrc
    kill -9 ${DOTS_BG_PID}
}

gen_lcov_report()
{
    if [[ ! -d "${code_path}/lcov_output" ]]
    then 
	    mkdir -p ${code_path}/lcov_output
    fi
    coverage_info_name="${code_path}/lcov_output/mes_test_coverage.info"
    coverage_report_name="${code_path}/lcov_output/mes_test_coverage.report"
    find ${code_path}/ -name "*.gcno" | xargs touch
    lcov --capture --directory ${code_path}/ --rc lcov_branch_coverage=1 --output-file "${coverage_info_name}" 
    lcov -l --rc lcov_branch_coverage=1 "${coverage_info_name}" > "${coverage_report_name}" 
    # Reset all execution counts to zero
    lcov -d ${code_path}/ -z
    echo ">>>>>>>>>>>>>>>>>>>>> mes utest lcov report successfully <<<<<<<<<<<<<<<<<<<<<<<<<<<"
}

main()
{
    LCOV_ENABLE=FALSE
    for arg in "$@"
    do 
        echo "arg is ${arg}"
        if [ ${arg} = "--coverage" ]
        then 
            echo "Enable coverage detection."
            LCOV_ENABLE=TRUE
        fi
    done

    init_ct_regress
    make_code
    install_cantiandb
    run_mes_test

    if [ "${LCOV_ENABLE}" = TRUE ]
    then 
        gen_lcov_report
    fi
}

main "$@"