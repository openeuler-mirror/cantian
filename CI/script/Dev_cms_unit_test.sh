#!/bin/bash

CTDB_CODE_PATH=$(cd $(dirname $(dirname $(dirname $0))); pwd)

GTEST_RESULT_PATH=${CTDB_CODE_PATH}/gtest_result
echo "gtest_result_path: ${GTEST_RESULT_PATH}/"
if [[ ! -d "${GTEST_RESULT_PATH}" ]]; then
    mkdir -p ${GTEST_RESULT_PATH}
fi

GTEST_RUN_LOG=${CTDB_CODE_PATH}/cms_gtest_run.log
rm -rf ${GTEST_RUN_LOG}
echo "cms_gtest_run_log: ${GTEST_RUN_LOG}"

LCOV_OUTPUT_PATH=${CTDB_CODE_PATH}/lcov_output
echo "lcov_output_path: ${LCOV_OUTPUT_PATH}/"
if [[ ! -d "${LCOV_OUTPUT_PATH}" ]]; then
    mkdir -p ${LCOV_OUTPUT_PATH}
fi

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

echo -n "make cms_test ..."
dots 5 &
DOTS_BG_PID=$!
trap "kill -9 $DOTS_BG_PID" INT

cd ${CTDB_CODE_PATH}/build/
sh Makefile.sh clean
sh Makefile.sh make_regress_test lcov=1
cd ${CTDB_CODE_PATH}/build/pkg/test/unit_test/ut
make -sj 8 2>&1 
if [ "$?" != "0" ]; then
    error "make cms test error!"
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

chmod 777 ${CTDB_CODE_PATH}/pkg/test/unit_test/ut/cms_test/cfg

echo
echo -n "run cms_test ..."
${CTDB_CODE_PATH}/output/bin/cms_test --gtest_output=xml:${GTEST_RESULT_PATH}/
if [ "$?" != "0" ]; then
    error "run cms_test error!"
fi
echo
echo "run cms_test success!"

echo -n "collect coverage data ..."
coverage_info_name="${LCOV_OUTPUT_PATH}/cms_ut_test_coverage.info"
coverage_report_name="${LCOV_OUTPUT_PATH}/cms_ut_test_coverage.report"
find ${CTDB_CODE_PATH}/ -name "*.gcno" | xargs touch
lcov --capture --directory ${CTDB_CODE_PATH}/ --rc lcov_branch_coverage=1 --output-file ${coverage_info_name} >> ${GTEST_RUN_LOG} 2>&1
lcov --directory ${CTDB_CODE_PATH}/ -z >> ${GTEST_RUN_LOG} 2>&1
lcov -l --rc lcov_branch_coverage=1 "${coverage_info_name}" > "${coverage_report_name}" 
echo
echo "cms_ut_test lcov report successfully!"

kill -9 ${DOTS_BG_PID}
