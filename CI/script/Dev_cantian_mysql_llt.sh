#!/bin/bash

# use: 1. compile and deploy cantian then run mysql llt test automaticlly 2. generate lcov report for cantian after running mysql llt
# usage: put this script in CI/script dir in cantian package, like /home/regress/CantianKernel/CI/script
# run with command -- sh Dev_cantian_mysql_llt.sh [--coverage] [--test_list=]
# log dir: /home/regress/mysql_llt
# lcov dir: /home/regress/CantianKernel/lcov_output/Dev_mtr_lcov*
# ref Dev_gs_cantian_regress.sh

DIR_PATH=$(cd `dirname $0`;pwd)
ROOT_PATH=$(cd ${DIR_PATH}/../../;pwd)
REGRESS_PATH=${ROOT_PATH}/pkg/test/gs_regress
MYSQL_PATH=/home/regress/mysql-server
MYSQL_USER_PATH=/usr/local/mysql
MYSQL_LCOV_PATH=${MYSQL_PATH}/bld_debug/storage/tianchi/CMakeFiles/ctc.dir

function help() {
    echo ""
    echo "$0"
    echo ""
    echo "Usage:    Dev_gs_cantian_regress.sh       {help} [--coverage --user --test_list]"
    echo "          --coverage         run test with test coverage report"
    echo "          --test_list        run test with specific test list file for mtr --do-test-list, use enableCases_gcov.list as default"
    echo "          --user             run test with user, if using docker/container.sh dev start container with different user,
                                       pass this user through --user, default is cantiandba"
}

function run_mysql_llt() {
    echo "========================= Run MySQL LLT ${TEST_LIST} ======================="
    cp -arfn ${MYSQL_PATH}/daac_lib/* /usr/lib64/
    cp -arfn ${MYSQL_USER_PATH}/lib/* /usr/lib64/
    cp -arfn ${MYSQL_USER_PATH}/lib/private/* /usr/lib64/
    ldconfig
    chmod +x ${MYSQL_USER_PATH}/bin/*

    cd ${MYSQL_USER_PATH}/mysql-test/
    ./mysql-test-run.pl --mysqld=--plugin_load="ctc_ddl_rewriter=ha_ctc.so;ctc=ha_ctc.so;" \
    --mysqld=--default-storage-engine=CTC --mysqld=--check_proxy_users=ON \
    --mysqld=--mysql_native_password_proxy_users=ON --do-test-list=${TEST_LIST} --noreorder
    echo "MySQL LLT ${TEST_LIST} End"
}

function uninstall_cantian() {
    echo "========================= Uninstall Cantian ======================="
    chown -R ${RUN_TEST_USER}:${RUN_TEST_USER} /home/regress/cantian_data /usr/local/mysql
    rm -f ${UDF_CFG}
    su - ${RUN_TEST_USER} -c "python3 ${TEST_DATA_DIR}/install/bin/uninstall.py -U ${RUN_TEST_USER} -F -D ${TEST_DATA_DIR}/data -g withoutroot -d"
}

function install_cantian() {
    echo "========================= Install Cantian ======================="
    cd ${ROOT_PATH}/output/bin/Cantian-DATABASE-CENTOS-64bit
    python3 install.py -U ${RUN_TEST_USER}:${RUN_TEST_USER}  \
                       -R ${TEST_DATA_DIR}/install/  \
                       -D ${TEST_DATA_DIR}/data/  \
                       -l ${INSTALL_LOG_DIR}/install.log  \
                       -Z _SYS_PASSWORD=${SYS_PASSWD}  \
                       -g withoutroot -d -M cantiand -c
    result=`cat ${TEST_DATA_DIR}/data/log/cantianstatus.log |grep 'instance started'|wc -l`
    if [ $result -eq 0 ]; then
        echo "Error: install cantian failed"
        exit 1
    fi
}

function compile_cantian() {
    echo "==================== Begin Comile Cantian ================="
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
    
    echo "### Compile & Make Cantian, no errors and warnings are allowed"
    export cmc_username=p_ciArtifact
    export cmc_password=encryption:ETMsDgAAAYWZguqfABFBRVMvR0NNL05vUGFkZGluZwCAABAAEBMG1JSYl+HNdWoh2xTsIOoAAAAqylgeKzik6xoE+eMga6I3TrTiY9lcodqK86EW4waRd53dbSqXZ5O2E/ruABTp7d8K52StBves9rACbK+2rWBlvA==
    sh Makefile.sh package ${lcov_build_flag} DAAC_READ_WRITE=1 | tee -a ${COMPILE_LOG}
    echo "### Compile & Make Cantian success"

    if [ "${LCOV_ENABLE}" = TRUE ]
    then 
        # 恢复编译之前被修改的源码文件
        mv -f ${ROOT_PATH}/pkg/src/server/srv_main.c.bak ${ROOT_PATH}/pkg/src/server/srv_main.c
        echo "Restoring the srv_main.c file"
        # 修改编译后gcov生成的*.gcno和*.gcda文件属组，用户RUN_TEST_USER运行用例时生成覆盖率报告
        chown ${RUN_TEST_USER}:${RUN_TEST_USER} -R ${ROOT_PATH}/build
    fi
}

function compile_mysql() {
    echo "==================== Begin Comile MySQL ================="
    lcov_build_flag=""
    if [ "${LCOV_ENABLE}" = TRUE ]
    then 
        lcov_build_flag="lcov=1"
    fi

    cd ${ROOT_PATH}/build
    echo "### Compile & Make MySQL, no errors and warnings are allowed"
    sh Makefile.sh mysql ${lcov_build_flag} | tee -a ${COMPILE_LOG}
    sh Makefile.sh mysql_package_node0 | tee -a ${COMPILE_LOG}
    echo "### Compile & Make MySQL success"
}

function gen_lcov_report() {
    echo "LCOV_ENABLE is ${LCOV_ENABLE}"
    if [ "${LCOV_ENABLE}" != TRUE ]; then
        return
    fi

    pid=`ps aux | grep cantiand |grep -v grep |awk '{print $2}'`
    sleep 5
    kill -35 $pid
    if [[ ! -d "${ROOT_PATH}/lcov_output" ]]
    then 
	mkdir -p ${ROOT_PATH}/lcov_output
        echo "mkdir ${ROOT_PATH}/lcov_output"
    fi
    
    # generate lcov for cantian
    cantian_coverage_info="${ROOT_PATH}/lcov_output/Dev_mtr_lcov_cantian.info"
    cantian_coverage_report="${ROOT_PATH}/lcov_output/Dev_mtr_lcov_cantian.report"
    cantian_coverage_package="${ROOT_PATH}/lcov_output/Dev_mtr_lcov_cantian"

    find ${ROOT_PATH}/ -name "*.gcno" | xargs touch
    lcov --capture --directory ${ROOT_PATH}/ --rc lcov_branch_coverage=1 --output-file "${cantian_coverage_info}"
    lcov -l --rc lcov_branch_coverage=1 "${cantian_coverage_info}" > "${cantian_coverage_report}"
    genhtml --branch-coverage "${cantian_coverage_info}" -o "${cantian_coverage_package}"

    # generate lcov for mysql
    mysql_coverage_info="${ROOT_PATH}/lcov_output/Dev_mtr_lcov_mysql.info"
    ctc_coverage_info="${ROOT_PATH}/lcov_output/Dev_mtr_lcov_mysql_ctc.info"
    ctc_coverage_report="${ROOT_PATH}/lcov_output/Dev_mtr_lcov_mysql_ctc.report"
    ctc_coverage_package="${ROOT_PATH}/lcov_output/Dev_mtr_lcov_mysql_ctc"

    find ${MYSQL_LCOV_PATH}/ -name "*.gcno" | xargs touch
    lcov --capture --directory ${MYSQL_LCOV_PATH}/ --rc lcov_branch_coverage=1 --output-file "${mysql_coverage_info}"
    lcov --extract "${mysql_coverage_info}" '*tianchi*' -o "${ctc_coverage_info}" --rc lcov_branch_coverage=1
    lcov --remove "${ctc_coverage_info}" '*tianchi/protobuf/*' -o "${ctc_coverage_info}" --rc lcov_branch_coverage=1
    lcov -l --rc lcov_branch_coverage=1 "${ctc_coverage_info}" > "${ctc_coverage_report}"
    genhtml --branch-coverage "${ctc_coverage_info}" -o "${ctc_coverage_package}"

    # Reset all execution counts to zero
    lcov -d ${ROOT_PATH}/ -z
    lcov -d ${MYSQL_LCOV_PATH}/ -z
    echo " Lcov report successfully "
}

function init_test_environment() {
    rm -rf ${TEST_DATA_DIR}
    rm -rf ${INSTALL_LOG_DIR}
    rm -rf ${TEMP_DIR}
    mkdir -p ${TEST_DATA_DIR}
    mkdir -p ${INSTALL_LOG_DIR}
    mkdir -p ${TEMP_DIR}
    touch ${COMPILE_LOG}
    touch ${REGRESS_LOG}
    chown -R ${RUN_TEST_USER}:${RUN_TEST_USER} ${TEST_DATA_DIR}

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
        echo "existing install cantian, uninstall it first"
        uninstall_cantian
    fi

    # cleanup for lcov
    find ${ROOT_PATH} -name "*.gcno" -delete
    find ${ROOT_PATH} -name "*.gcda" -delete
    find ${MYSQL_LCOV_PATH} -name "*.gcno" -delete
    find ${MYSQL_LCOV_PATH} -name "*.gcda" -delete
}

function parse_parameter() {
    ARGS=$(getopt -o c,u: --long coverage,user:,test_list: -- "$@")
    if [ $? != 0 ]; then
        echo "Terminating..."
        exit 1
    fi

    eval set -- "${ARGS}"
    declare -g LCOV_ENABLE=FALSE
    declare -g RUN_TEST_USER="cantiandba"
    declare -g TEST_LIST="enableCases_gcov.list"

    while true
    do
        case "$1" in
            -c|--coverage)
                LCOV_ENABLE=TRUE
                shift
                ;;
            -u|--user)
                RUN_TEST_USER="$2"
                shift 2
                ;;
            --test_list)
                TEST_LIST="$2"
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
    declare -g TEST_DATA_DIR="/home/regress/mysql_llt"
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
    compile_cantian
    compile_mysql
    
    install_cantian
    run_mysql_llt
    
    gen_lcov_report
    uninstall_cantian
}

main "$@"

