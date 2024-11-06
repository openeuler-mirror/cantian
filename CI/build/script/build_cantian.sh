#!/bin/bash
set -e

BUILD_TYPE=${BUILD_TYPE:-"DEBUG"}
ENV_TYPE=${ENV_TYPE:-"x86_64"}
HOME_PATH="/home/regress"
CTDB_CODE_PATH=${HOME_PATH}/CantianKernel
if [ -n "${WORKSPACE}" ]; then
    HOME_PATH=${WORKSPACE}
    CTDB_CODE_PATH=${HOME_PATH}/cantian
fi

if [[ ${ENV_TYPE} == "aarch64" ]]; then 
    export C_INCLUDE_PATH=:/usr/include/python3.9/
fi

source /etc/profile

function linkCodeToHome() {
  # 如果代码路径不在HOME_PATH下，需要链接过去
  if [ -d ${CTDB_CODE_PATH} ]; then
      return 0
  fi
  
  if [ -L ${CTDB_CODE_PATH} ]; then
    rm -f ${CTDB_CODE_PATH}
  fi

  local code_home=$(dirname $(realpath ${BASH_SOURCE[0]}))/../../../..
  ln -s ${code_home}/cantian ${CTDB_CODE_PATH}
  ln -s ${code_home}/cantian_om ${HOME_PATH}/cantian_om
}

function buildCantianDebug() {
  echo "Start buildCantianDebug..."
  cd ${CTDB_CODE_PATH}/build
  sh Makefile.sh debug
}

function buildCantianRelease() {
  echo "Start buildCantianRelease..."
  cd ${CTDB_CODE_PATH}/build
  sh Makefile.sh release
}

echo "Start build cantian only"
echo "BUILD_TYPE: ${BUILD_TYPE}"
echo "ENV_TYPE: ${ENV_TYPE}"
echo "BUILD_MODE: ${BUILD_MODE}"
echo "HOME_PATH: ${HOME_PATH}"
echo "code_home: ${code_home}"

linkCodeToHome

if [ "${BUILD_TYPE}" == "DEBUG" ]; then
  buildCantianDebug
elif [ "${BUILD_TYPE}" == "RELEASE" ]; then
  buildCantianRelease
fi
