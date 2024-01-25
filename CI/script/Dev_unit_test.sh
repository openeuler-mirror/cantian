#!/bin/bash

CTDB_CODE_PATH=$(cd $(dirname $(dirname $(dirname $0))); pwd)

GTEST_RESULT_PATH=${CTDB_CODE_PATH}/gtest_result
echo "gtest_result_path: ${GTEST_RESULT_PATH}/"
if [[ ! -d "${GTEST_RESULT_PATH}" ]]; then
    mkdir -p ${GTEST_RESULT_PATH}
fi

GTEST_RUN_LOG=${CTDB_CODE_PATH}/gtest_run.log
rm -rf ${GTEST_RUN_LOG}
echo "gtest_run_log: ${GTEST_RUN_LOG}"

LCOV_OUTPUT_PATH=${CTDB_CODE_PATH}/lcov_output

function dots(){
    seconds=${1:-5}
    while true
    do
        sleep $seconds
        echo -n '.'
    done
}

function error(){
    echo $1
    echo $1 >> ${GTEST_RUN_LOG} 2>&1
    kill -9 ${DOTS_BG_PID}
    exit 1
}

echo -n "make test ..."
dots 5 &
DOTS_BG_PID=$!
trap "kill -9 $DOTS_BG_PID" INT

cd ${CTDB_CODE_PATH}/build/
sh Makefile.sh clean
sh Makefile.sh make_regress_test lcov=1 >> ${GTEST_RUN_LOG} 2>&1
cd ${CTDB_CODE_PATH}/build/pkg/test/unit_test/ut/
make -sj 8 2>&1 

if [ "$?" != "0" ]; then
    cat ${GTEST_RUN_LOG}
    error "make test error!"
fi

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${CTDB_CODE_PATH}/output/lib/
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${CTDB_CODE_PATH}/library/gtest/lib/
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${CTDB_CODE_PATH}/library/dbstor/lib/
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${CTDB_CODE_PATH}/library/dbstor/lib/nomlnx/

UNAME=$(uname -a)
if [[ "${UNAME}" =~ .*aarch64.* ]];then
    export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${CTDB_CODE_PATH}/library/xnet/lib_arm/
elif [[ "${UNAME}" =~ .*x86_64.* ]];then
    export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${CTDB_CODE_PATH}/library/xnet/lib/
else
    error "error: unknown arch!"
fi
mkdir -p ${CTDB_HOME}/cfg
chmod 777 ${CTDB_CODE_PATH}/pkg/test/unit_test/ut/cms_test/cfg
chmod 777 ${CTDB_CODE_PATH}/pkg/test/mes_test/config
chmod 600 ${CTDB_CODE_PATH}/pkg/test/mes_test/config/ca.crt
echo "DBWR_PROCESSES = 8" >> ${CTDB_HOME}/cfg/cantiand.ini

echo
echo -n "run message_queue_test ..."
${CTDB_CODE_PATH}/output/bin/message_queue_test --gtest_output=xml:${GTEST_RESULT_PATH}/ >> ${GTEST_RUN_LOG} 2>&1
if [ "$?" != "0" ]; then
    error "run message_queue_test error!"
fi
echo
echo "run message_queue_test success!"

echo
echo -n "run ctc_srv_test ..."
${CTDB_CODE_PATH}/output/bin/ctc_srv_test --gtest_output=xml:${GTEST_RESULT_PATH}/ >> ${GTEST_RUN_LOG} 2>&1
if [ "$?" != "0" ]; then
    error "run ctc_srv_test error!"
fi
echo
echo "run ctc_srv_test success!"

echo
echo -n "run ctbackup_test ..."
${CTDB_CODE_PATH}/output/bin/ctbackup_test --gtest_output=xml:${GTEST_RESULT_PATH}/ >> ${GTEST_RUN_LOG} 2>&1
if [ "$?" != "0" ]; then
    error "run ctbackup_test error!"
fi
echo
echo "run ctbackup_test success!"

echo -n "run knl_test ..."
${CTDB_CODE_PATH}/output/bin/knl_test --gtest_output=xml:${GTEST_RESULT_PATH}/ >> ${GTEST_RUN_LOG} 2>&1
if [ "$?" != "0" ]; then
    error "run knl_test error!"
fi
echo
echo "run knl_test success!"

echo -n "run server_test ..."
${CTDB_CODE_PATH}/output/bin/server_test --gtest_output=xml:${GTEST_RESULT_PATH}/ >> ${GTEST_RUN_LOG} 2>&1
if [ "$?" != "0" ]; then
    error "run server_test error!"
fi
echo
echo "run server_test success!"

echo -n "run common_test ..."
${CTDB_CODE_PATH}/output/bin/common_test --gtest_output=xml:${GTEST_RESULT_PATH}/ >> ${GTEST_RUN_LOG} 2>&1
if [ "$?" != "0" ]; then
    error "run common_test error!"
fi
echo
echo "run common_test success!"

echo -n "run tms_test ..."
${CTDB_CODE_PATH}/output/bin/tms_test --gtest_output=xml:${GTEST_RESULT_PATH}/ >> ${GTEST_RUN_LOG} 2>&1
if [ "$?" != "0" ]; then
    error "run tms_test error!"
fi
echo
echo "run tms_test success!"

echo
echo -n "run cms_test ..."
${CTDB_CODE_PATH}/output/bin/cms_test --gtest_output=xml:${GTEST_RESULT_PATH}/ >> ${GTEST_RUN_LOG} 2>&1
if [ "$?" != "0" ]; then
    error "run cms_test error!"
fi
echo
echo "run cms_test success!"

echo
echo -n "run mes_test ..."
${CTDB_CODE_PATH}/output/bin/mes_test --gtest_output=xml:${GTEST_RESULT_PATH}/ >> ${GTEST_RUN_LOG} 2>&1
if [ "$?" != "0" ]; then
    error "run mes_test error!"
fi
echo
echo "run mes_test success!"

echo -n "collect coverage data ..."
echo "lcov_output_path: ${LCOV_OUTPUT_PATH}/"
if [[ ! -d "${LCOV_OUTPUT_PATH}" ]]; then
    mkdir -p ${LCOV_OUTPUT_PATH}
fi
coverage_info_name="${LCOV_OUTPUT_PATH}/ut_test_coverage.info"
find ${CTDB_CODE_PATH}/ -name "*.gcno" | xargs touch
lcov --capture --directory ${CTDB_CODE_PATH}/ --rc lcov_branch_coverage=1 --output-file ${coverage_info_name} >> ${GTEST_RUN_LOG} 2>&1
lcov --directory ${CTDB_CODE_PATH}/ -z >> ${GTEST_RUN_LOG} 2>&1
echo
echo "ut_test lcov report successfully!"

kill -9 ${DOTS_BG_PID}
