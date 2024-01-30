#!/bin/bash

CTDB_CODE_PATH=$1
MYSQL_CODE_PATH=$2

TSE_SRV_FILE="tse_srv.h"
SRV_MQ_MSG_FILE="srv_mq_msg.h"
TSE_SRV_GCC_FILE="tse_srv.out"
SRV_MQ_MSG_GCC_FILE="srv_mq_msg.out"
FILE_DIFF_OUTPUT="interface_diff.out"

CANTIAN_TSE_PATH=${CTDB_CODE_PATH}/pkg/src/tse
MYSQL_TSE_PATH=${MYSQL_CODE_PATH}/storage/tianchi

function cleanUpDiffOutput()
{
  rm -f "cantian_${TSE_SRV_GCC_FILE}" "mysql_${TSE_SRV_GCC_FILE}" \
        "cantian_${SRV_MQ_MSG_GCC_FILE}" "mysql_${SRV_MQ_MSG_GCC_FILE}" ${FILE_DIFF_OUTPUT}
}

function checkInterfaceVersion()
{
  echo "start to check interface versions"

  if [[ ! -f ${CANTIAN_TSE_PATH}/${TSE_SRV_FILE} || ! -f ${MYSQL_TSE_PATH}/${TSE_SRV_FILE} ]]; then
    echo -e "\nFile ${TSE_SRV_FILE} does not exist!"
    exit 1
  fi

  if [[ ! -f ${CANTIAN_TSE_PATH}/${SRV_MQ_MSG_FILE} || ! -f ${MYSQL_TSE_PATH}/${SRV_MQ_MSG_FILE} ]]; then
    echo -e "\nFile ${SRV_MQ_MSG_FILE} dose not exist!"
    exit 1
  fi
  
  gcc -E -dD ${CANTIAN_TSE_PATH}/${TSE_SRV_FILE} -o "cantian_${TSE_SRV_GCC_FILE}"
  gcc -E -dD ${MYSQL_TSE_PATH}/${TSE_SRV_FILE} -o "mysql_${TSE_SRV_GCC_FILE}"
  
  diff -bpwB -I${TSE_SRV_FILE} "cantian_${TSE_SRV_GCC_FILE}" "mysql_${TSE_SRV_GCC_FILE}" > ${FILE_DIFF_OUTPUT}
  if [[ -s ${FILE_DIFF_OUTPUT} ]]; then
    echo -e "\n#################### ${TSE_SRV_FILE} is different ####################\n"
    cat ${FILE_DIFF_OUTPUT} | grep -v ${TSE_SRV_FILE}
    echo -e "\n#################### please review the differences in ${TSE_SRV_FILE} ####################\n"
    cleanUpDiffOutput
    exit 1
  fi

  gcc -E -dD ${CANTIAN_TSE_PATH}/${SRV_MQ_MSG_FILE} -o "cantian_${SRV_MQ_MSG_GCC_FILE}"
  gcc -E -dD ${MYSQL_TSE_PATH}/${SRV_MQ_MSG_FILE} -o "mysql_${SRV_MQ_MSG_GCC_FILE}"
  
  diff -bpwB -I${TSE_SRV_FILE} -I${SRV_MQ_MSG_FILE} "cantian_${SRV_MQ_MSG_GCC_FILE}" "mysql_${SRV_MQ_MSG_GCC_FILE}" > ${FILE_DIFF_OUTPUT}
  if [[ -s ${FILE_DIFF_OUTPUT} ]]; then
    echo -e "\n#################### ${SRV_MQ_MSG_FILE} is different ####################\n"
    cat ${FILE_DIFF_OUTPUT} | grep -v ${TSE_SRV_FILE} | grep -v ${SRV_MQ_MSG_FILE}
    echo -e "\n#################### please review the differences in ${SRV_MQ_MSG_FILE} ####################\n"
    cleanUpDiffOutput
    exit 1
  fi
  
  echo "interface versions are the same"
  cleanUpDiffOutput
}

checkInterfaceVersion

