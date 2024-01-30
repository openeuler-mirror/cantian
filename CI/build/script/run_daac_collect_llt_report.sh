#!/bin/bash

DIR_PATH=$(dirname $0)
HOME_PATH=$(cd ${DIR_PATH}/../../../../;pwd)
CTDB_CODE_PATH=${HOME_PATH}/daac
LLT_REPORT_PATH=${CTDB_CODE_PATH}/lcov_output
GTEST_RESULT_PATH=${CTDB_CODE_PATH}/gtest_result
GTEST_REPORT_PATH=${CTDB_CODE_PATH}/gtest_output
G_TESTCASE_OUTPUT=${GTEST_REPORT_PATH}/test_detail.xml
echo "HOME_PATH: ${HOME_PATH}"

make_lcov_report()
{
    # 汇总LLT测试结果，合并info文件，并生成total.report
    LCOV_CMD="lcov --rc lcov_branch_coverage=1 "
    cd ${LLT_REPORT_PATH}
    echo "collector info start"
    for file in ./*
    do
	echo "file is ${file}"
        if [ "${file##*.}" = "info" ] && [ "${file}" != "./total.info" ]
	then
	    LCOV_CMD="${LCOV_CMD} -a ${file}"
            echo ${LCOV_CMD}
	fi
    done

    LCOV_CMD="${LCOV_CMD} -o total.info"
    echo ${LCOV_CMD}
    eval ${LCOV_CMD}
    lcov -l --rc lcov_branch_coverage=1 "total.info" > "total.report" 
    lcov --remove total.info '*/build_dependence/*' -o total.info --rc lcov_branch_coverage=1
    lcov --remove total.info '*/open_source/*' -o total.info --rc lcov_branch_coverage=1
    lcov --remove total.info '*/pkg/src/tse/protobuf/*' -o total.info --rc lcov_branch_coverage=1
    lcov --remove total.info '*/pkg/test/cantian_fuzz_test/*' -o total.info --rc lcov_branch_coverage=1
    genhtml --rc lcov_branch_coverage=1 total.info -o ${LLT_REPORT_PATH}
}

make_gtest_report()
{
    #汇总gTest测试结果，合并xml文件，并生成test_detail.xml
    if [ ! -d "${GTEST_REPORT_PATH}" ]
    then
        mkdir -p ${GTEST_REPORT_PATH}
    else 
        echo "${GTEST_REPORT_PATH} is exist"
    fi
	cd ${GTEST_REPORT_PATH}

	echo --------------GTEST_RESULT_PATH:${GTEST_RESULT_PATH}-------------
    echo --------------GTEST_REPORT_PATH:${GTEST_REPORT_PATH}-------------
	if [ -n "${GTEST_RESULT_PATH}" ] ; then
		xml_count=`find ${GTEST_RESULT_PATH} -type f -name "*.xml" | wc -l`
		echo --------------xml_count:${xml_count}-------------
		if [ $xml_count -gt 1 ]; then
			python ${CTDB_CODE_PATH}/CI/script/gtest_collect_output.py "${GTEST_RESULT_PATH}" "${G_TESTCASE_OUTPUT}"
			if [ ! -f "${G_TESTCASE_OUTPUT}" ]; then
				echo "ERRO:${G_TESTCASE_OUTPUT} not exist"
			else
				sed -i -r '/^[ ]*$/d' ${G_TESTCASE_OUTPUT}
			fi
		elif [ $xml_count -eq 1 ]; then
			cp -af ${GTEST_RESULT_PATH}/*.xml ${G_TESTCASE_OUTPUT}
		else
			echo "ERROR:Report is null"
		fi
    cp ${G_TESTCASE_OUTPUT} ${LLT_REPORT_PATH}
	fi
}
mkdir -p ${GTEST_RESULT_PATH}
mv ${LLT_REPORT_PATH}/*.xml ${GTEST_RESULT_PATH}
make_lcov_report $@
make_gtest_report $@
