#!/bin/bash

DIR_PATH=$(cd `dirname $0`;pwd)
ROOT_PATH=$(cd ${DIR_PATH}/../../;pwd)
REGRESS_PATH=${ROOT_PATH}/pkg/test/gs_regress

function help() {
    echo ""
    echo "$0"
    echo ""
    echo "Usage:    Dev_gs_cantian_regress.sh       {help} [--coverage --user]"
    echo "          --coverage         run test with test coverage report"
    echo "          --user             run test with user, if using docker/container.sh dev start container with different user,
                                       pass this user through --user, default is cantiandba"
    echo "          --core_dir        run test with user, if using docker/container.sh dev start container with different coredir,
                                       pass this core dir path through --core_dir, default is /home/core"
    echo "          --gs_schedule_list run test with specified test list, default is full test cases list gs_schedule"
}


function collect_core() {
	collect_script=${ROOT_PATH}/CI/script/collect_corefile_cantian.sh
	sh ${collect_script} ${CORE_DIR} ${TEMP_DIR} ${ROOT_PATH} ${TEST_DATA_DIR}/data  ${RUN_TEST_USER}
}

function run_gs_regress() {
	echo "========================= Run Regression ======================="
	cd ${ROOT_PATH}
	git clean -nf |grep "pkg/test/gs_regress/*.*"|xargs rm -f
	cp -f ${ROOT_PATH}/output/bin/gs_regress ${REGRESS_PATH}
	chmod u+x ${REGRESS_PATH}/gs_regress
	chown -R ${RUN_TEST_USER}:${RUN_TEST_USER} ${REGRESS_PATH}
    su - ${RUN_TEST_USER} -c "cd ${REGRESS_PATH} && sh gsdb_regress_cantian.sh ${TEST_DATA_DIR}/install ${SYS_PASSWD} ${GS_SCHEDULE_LIST} 2>&1 "| tee ${REGRESS_LOG}
    set +e
    fail_count=`grep -c ":  FAILED" ${REGRESS_LOG}`
	ok_count=`grep -c ":  OK" ${REGRESS_LOG}`
    set -e
	if [ $fail_count -ne 0 ] || [ $ok_count -eq 0 ]; then
		echo "Error: Some cases failed when gs_regress!!"
		echo "Error: Some cases failed when gs_regress!!" >> ${REGRESS_LOG} 2>&1
		cat $ROOT_PATH/pkg/test/gs_regress/results/*.diff >> ${REGRESS_LOG} 2>&1
		mkdir -p ${TEMP_DIR}/diff
		cp $ROOT_PATH/pkg/test/gs_regress/results/*.diff ${TEMP_DIR}/diff
		echo "Regress Failed! Regress Failed! Regress Failed! "
		collect_core # local debug, can annotate this step
		exit 1
	fi
	echo "Regress Success"
	echo "LCOV_ENABLE is ${LCOV_ENABLE}"
	if [ "${LCOV_ENABLE}" = TRUE ]; then
		echo "make lcov report"
		gen_lcov_report
	fi
}

function uninstall_cantiandb() {
    echo "========================= Uninstall CantianDB ======================="
    chown -R ${RUN_TEST_USER}:${RUN_TEST_USER} /home/regress/cantian_data
    rm -f ${UDF_CFG}
    su - ${RUN_TEST_USER} -c "python3 ${TEST_DATA_DIR}/install/bin/uninstall.py -U ${RUN_TEST_USER} -F -D ${TEST_DATA_DIR}/data -g withoutroot -d"
}

function install_cantiandb() {
    CREATEDB_SQL=${REGRESS_PATH}/sql/create_cluster_database.gsregress.sql
    DATA_PATH=${TEST_DATA_DIR}/data/data
    ESCAPE_DATA_PATH=${DATA_PATH//'/'/'\/'}
    sed -i 's/dbfiles1/'${ESCAPE_DATA_PATH}'/g' ${CREATEDB_SQL}

    echo "========================= Install CantianDB ======================="
    cd ${ROOT_PATH}/output/bin/Cantian-DATABASE-CENTOS-64bit
    python3 install.py -U ${RUN_TEST_USER}:${RUN_TEST_USER}  \
                       -R ${TEST_DATA_DIR}/install/  \
                       -D ${TEST_DATA_DIR}/data/  \
                       -l ${INSTALL_LOG_DIR}/install.log  \
                       -Z SESSIONS=200  \
                       -Z BUF_POOL_NUM=1  \
                       -Z VARIANT_MEMORY_AREA_SIZE=32M  \
                       -Z AUDIT_LEVEL=3  \
                       -Z USE_NATIVE_DATATYPE=TRUE  \
                       -Z _SYS_PASSWORD=${SYS_PASSWD}  \
                       -Z _LOG_LEVEL=255  \
                       -Z _LOG_MAX_FILE_SIZE=10M  \
                       -Z STATS_LEVEL=TYPICAL  \
                       -Z REACTOR_THREADS=1  \
                       -Z OPTIMIZED_WORKER_THREADS=100  \
                       -Z MAX_WORKER_THREADS=100  \
                       -Z UPPER_CASE_TABLE_NAMES=TRUE  \
                       -Z SHARED_POOL_SIZE=1G  \
                       -Z TEMP_BUFFER_SIZE=256M  \
                       -Z DATA_BUFFER_SIZE=2G  \
                       -Z _MAX_VM_FUNC_STACK_COUNT=10000  \
                       -Z MAX_COLUMN_COUNT=4096  \
                       -Z AUTO_INHERIT_USER=ON  \
                       -Z PAGE_CHECKSUM=TYPICAL  \
                       -Z JOB_QUEUE_PROCESSES=100  \
                       -Z CHECKPOINT_PERIOD=300  \
                       -Z LOG_BUFFER_SIZE=4M  \
                       -Z RECYCLEBIN=TRUE  \
                       -Z ENABLE_IDX_KEY_LEN_CHECK=TRUE  \
                       -Z EMPTY_STRING_AS_NULL=TRUE  \
                       -Z MYSQL_METADATA_IN_CANTIAN=TRUE  \
                       -Z SHARED_POOL_SIZE=2G  \
                       -Z COMPATIBLE_MYSQL=0  \
                       -f ${CREATEDB_SQL}  \
                       -g withoutroot -d -M cantiand -c
    result=`cat ${TEST_DATA_DIR}/data/log/cantianstatus.log |grep 'instance started'|wc -l`
    sed -i 's/'${ESCAPE_DATA_PATH}'/dbfiles1/g' ${CREATEDB_SQL}
    if [ $result -eq 0 ]; then
        echo "Error: install cantiandba failed"
        exit 1
    fi
    su - ${RUN_TEST_USER} -c "CTSQL_SSL_QUIET=TRUE ${TEST_DATA_DIR}/install/bin/ctsql sys/${SYS_PASSWD}@127.0.0.1:1611 -f ${ROOT_PATH}/pkg/test/ora-dialect.sql >> ${INSTALL_LOG_DIR}/install.log 2>&1"
    if [ $? -ne 0 ]; then
        echo "Error: create ora-dialect failed"
        exit 1
    fi
}

function compile_code() {
    echo "==================== Begin Rebuild CantianKernel ================="
    lcov_build_flag=""
    if [ "${LCOV_ENABLE}" = TRUE ]
    then 
        lcov_build_flag="lcov=1"
        cp -f ${ROOT_PATH}/pkg/src/server/srv_main.c ${ROOT_PATH}/pkg/src/server/srv_main.c.bak
        tmp_hllt_code1="#include <signal.h>"     
        tmp_hllt_code2="void save_llt_data(int signo){\nprintf(\"srv_main get signal=%d\",signo);\nexit(0);\n}"
        tmp_hllt_code3="    signal(35,save_llt_data);"
        sed -i "/cm_coredump.h/a$tmp_hllt_code1" ${ROOT_PATH}/pkg/src/server/srv_main.c
        sed -i "/$tmp_hllt_code1/a$tmp_hllt_code2" ${ROOT_PATH}/pkg/src/server/srv_main.c
        sed -i "/cantiand_lib_main(argc, argv);/i$tmp_hllt_code3" ${ROOT_PATH}/pkg/src/server/srv_main.c
        echo "finish modify main function"
    fi

    cd ${ROOT_PATH}/build
    sh Makefile.sh clean
    echo "### Compile & Make CantianKernel and CTSQL, no errors and warnings are allowed"
    sh Makefile.sh make_cantian_pkg_test ${lcov_build_flag} DAAC_READ_WRITE=1 | tee -a ${COMPILE_LOG}
#    error_num=`cat ${COMPILE_LOG} |grep 'error:'|wc -l`
#    ignore_error=`cat ${COMPILE_LOG} |grep 'error: unexpected end of file'|wc -l`
#    if [ $error_num -ne 0 ]; then
#        if [ ${ignore_error} != ${error_num} ]; then
#            echo "Error: make CantianKernel & CTSQL failed with errors"
#            exit 1
#        fi
#    fi
#    error_num=`cat ${COMPILE_LOG} |grep 'warning:'|wc -l`
#    if [ $error_num -ne 0 ]; then
#        echo "Error: make CantianKernel & CTSQL failed with warnings"
#        exit 1
#    fi
    echo "### Compile & Make CantianKernel and CTSQL success"
    echo "### Compile & Make test fold source file, no errors and warnings are allowed"
    cd ${ROOT_PATH}/build
    source ./common.sh
    cd ${ROOT_PATH}/build/pkg/test/gs_regress
    strip -N main ${CANTIANDB_LIB}/libzeserver.a
    make -sj 8 | tee -a ${COMPILE_LOG}
#    error_num=`cat ${COMPILE_LOG} |grep 'error:'|wc -l`
#    if [ $error_num -ne 0 ];then

#        if [ ${ignore_error} != ${error_num} ]; then
#            echo "Error: make test fold source file failed with errors"
#            exit 1
#        fi
#    fi
#    error_num=`cat ${COMPILE_LOG} |grep 'warning:'|wc -l`
#    if [ $error_num -ne 0 ];then
#        echo "Error: make test fold source file failed with warnings"
#        exit 1
#    fi
    if [ "${LCOV_ENABLE}" = TRUE ]
    then 
        # 恢复编译之前被修改的源码文件
        mv -f ${ROOT_PATH}/pkg/src/server/srv_main.c.bak ${ROOT_PATH}/pkg/src/server/srv_main.c
        echo "Restoring the srv_main.c file"
        # 修改编译后gcov生成的*.gcno和*.gcda文件属组，用户RUN_TEST_USER运行用例时生成覆盖率报告
        chown ${RUN_TEST_USER}:${RUN_TEST_USER} -R ${ROOT_PATH}/build
    fi
    echo "### Compile & Make test fold source file success"
}

gen_lcov_report()
{
    pid=`ps aux | grep cantiand |grep -v grep |awk '{print $2}'`
    sleep 5
    kill -35 $pid
    if [[ ! -d "${ROOT_PATH}/lcov_output" ]]
    then 
	    mkdir -p ${ROOT_PATH}/lcov_output
        echo "mkdir ${ROOT_PATH}/lcov_output"
    fi
    coverage_info_name="${ROOT_PATH}/lcov_output/Dev_gs_regress_test_coverage_${GS_SCHEDULE_LIST}.info"
    coverage_report_name="${ROOT_PATH}/lcov_output/Dev_gs_regress_test_coverage_${GS_SCHEDULE_LIST}.report"
    find ${ROOT_PATH}/ -name "*.gcno" | xargs touch
    lcov --capture --directory ${ROOT_PATH}/ --rc lcov_branch_coverage=1 --output-file "${coverage_info_name}" 
    lcov -l --rc lcov_branch_coverage=1 "${coverage_info_name}" > "${coverage_report_name}" 
    # Reset all execution counts to zero
    lcov -d ${ROOT_PATH}/ -z
    echo " Lcov report successfully "
}

function init_test_environment() {
    rm -rf ${TEST_DATA_DIR}
    rm -rf ${INSTALL_LOG_DIR}
    rm -rf ${TEMP_DIR}
    rm -rf ${CORE_DIR}/*
    mkdir -p ${TEST_DATA_DIR}
    mkdir -p ${INSTALL_LOG_DIR}
    mkdir -p ${TEMP_DIR}
    mkdir -p ${CORE_DIR}
    touch ${COMPILE_LOG}
    touch ${REGRESS_LOG}
    chown -R ${RUN_TEST_USER}:${RUN_TEST_USER} ${TEST_DATA_DIR}
    chown -R ${RUN_TEST_USER}:${RUN_TEST_USER} ${CORE_DIR}

    UDF_CFG=${ROOT_PATH}/pkg/cfg/udf.ini
    echo "self_func_tst.abs" > ${UDF_CFG}
    echo "self_func_tst.ABS" >> ${UDF_CFG}
    echo "self_func_tst.extract" >> ${UDF_CFG}
    echo "self_func_tst.EXTRACT" >> ${UDF_CFG}
    echo "self_func_tst.decode" >> ${UDF_CFG}
    echo "self_func_tst.DECODE" >> ${UDF_CFG}
    cat ${UDF_CFG}
}

function check_old_install() {
    old_install=`ps -aux|grep cantiand|grep "${TEST_DATA_DIR}/data"|wc -l`
    old_env_data=`cat /home/${RUN_TEST_USER}/.bashrc |grep "export CTDB_HOME="|wc -l`
    if [ $old_install -ne 0 ] || [ $old_env_data -ne 0 ]; then
        echo "existing install cantiandb, uninstall it first"
        uninstall_cantiandb
    fi
}

function parse_parameter() {
    ARGS=$(getopt -o c:u:d:g: --long coverage:,user:,core_dir:,gs_schedule_list: -n "$0" -- "$@")

    if [ $? != 0 ]; then
        echo "Terminating..."
        exit 1
    fi

    eval set -- "${ARGS}"
    declare -g LCOV_ENABLE=FALSE
    declare -g RUN_TEST_USER="cantiandba"
    declare -g CORE_DIR="/home/core"
    declare -g GS_SCHEDULE_LIST="gs_schedule"
    while true
    do
        case "$1" in
            -c | --coverage)
                LCOV_ENABLE=TRUE
                shift 2
                ;;
            -u | --user)
                RUN_TEST_USER="$2"
                shift 2
                ;;
            -d | --core_dir)
                CORE_DIR="$2"
                shift 2
                ;;
            -g | --gs_schedule_list)
                GS_SCHEDULE_LIST="$2"
                shift 2
                ;;
            --)
                shift
                break
                ;;
            *)
                help
                exit 0
                ;;
        esac
    done
    # using docker/container.sh dev start container will create user and config core pattern
    # pass this user to the script through --user, default is cantiandba
    declare -g TEST_DATA_DIR="/home/regress/gs_regress"
    declare -g INSTALL_LOG_DIR=${TEST_DATA_DIR}/logs
    declare -g TEMP_DIR=${TEST_DATA_DIR}/tmp
    declare -g COMPILE_LOG=${TEST_DATA_DIR}/logs/compile_log
    declare -g REGRESS_LOG=${TEST_DATA_DIR}/logs/regress_log
    declare -g SYS_PASSWD=Huawei@123
}

main() {
    parse_parameter "$@"
    check_old_install
    init_test_environment

    echo "Start compile, source code root path: ${ROOT_PATH}" > ${COMPILE_LOG}
    echo "ROOT_PATH: ${ROOT_PATH}"
    compile_code # local debug, if only change sql test file can annotate this step
    install_cantiandb

    run_gs_regress
    uninstall_cantiandb
}

main "$@"

