#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
# This script is used for compiling code via CMake and making packages
set -e

func_prepare_git_msg()
{
  echo "start func_prepare_git_msg"
  git_id=$(git rev-parse --short HEAD)
  WHOLE_COMMIT_ID=$(git rev-parse HEAD)
  merge_time=$(git log | grep Date | sed -n '1p' | sed 's/^Date:\s*//g')
  cantian_merge_time=$(git log | grep Date | sed -n '1p' | sed 's/^Date:\s*//g')
  driver_commit_id=$(git log --pretty=format:%h -n 1 ${CANTIANDB_SRC}/driver/)
  ctsql_commit_id=$(git log --pretty=format:%h -n 1 ${CANTIANDB_SRC}/utils/ctsql)
  cat /dev/null > ${CANTIANDB_BUILD}/conf/git_message.in
  echo "git_id=${git_id}" >> ${CANTIANDB_BUILD}/conf/git_message.in
  echo "gitVersion=${WHOLE_COMMIT_ID}" >> ${CANTIANDB_BUILD}/conf/git_message.in
  echo "merge_time=${merge_time}" >> ${CANTIANDB_BUILD}/conf/git_message.in
  echo "cantian_merge_time=${cantian_merge_time}" >> ${CANTIANDB_BUILD}/conf/git_message.in
  echo "driver_commit_id=${driver_commit_id}" >> ${CANTIANDB_BUILD}/conf/git_message.in
  echo "ctsql_commit_id=${ctsql_commit_id}" >> ${CANTIANDB_BUILD}/conf/git_message.in
  if [ -d ${MYSQL_CODE_PATH} ]; then
    cd ${MYSQL_CODE_PATH}
    MYSQL_COMMIT_ID=$(git rev-parse HEAD)
    mysql_merge_time=$(git log | grep Date | sed -n '1p' | sed 's/^Date:\s*//g')
    echo "mysqlGitVersion=${MYSQL_COMMIT_ID}" >> ${CANTIANDB_BUILD}/conf/git_message.in
    echo "mysql_merge_time=${mysql_merge_time}" >> ${CANTIANDB_BUILD}/conf/git_message.in
    cd -
  fi
}

function prepareGetMysqlClientStaticLibToDaaclib() {
  local MYSQL_CODE_PATH=$1
  local BUILD_TYPE=$2
  local LLT_TEST_TYPE=$3
  local BOOST_PATH=$4
  local CPU_CORES_NUM=$5
  local MYSQLD_CMAKE_DIR=$6
  local MYSQL_CLIENT_CMAKE_DIR=${MYSQL_CODE_PATH}/clientbuild
  local MYSQLCLIENTLIB_OUTPUT_PATH=${MYSQL_CLIENT_CMAKE_DIR}/archive_output_directory
  echo "[MysqlClient][INFO]Start buildMysqlClient Lib ${BUILD_TYPE} ${LLT_TEST_TYPE}..."
  if [ $# != 6 ]; then
    echo "[MysqlClient][ERROR]params mismatched!check ${MYSQL_CODE_PATH}|${BUILD_TYPE}|${LLT_TEST_TYPE}|${BOOST_PATH}|${CPU_CORES_NUM}|${MYSQLD_CMAKE_DIR}"
    exit 1
  fi
  mkdir -p ${MYSQLD_CMAKE_DIR}/include
  if [ -f ${MYSQLCLIENTLIB_OUTPUT_PATH}/libmysqlclient.a ]; then
    cp -arf ${MYSQLCLIENTLIB_OUTPUT_PATH}/libmysqlclient.a ${MYSQL_CODE_PATH}/daac_lib/
    cp -arf ${MYSQL_CLIENT_CMAKE_DIR}/include/mysqld_error.h ${MYSQLD_CMAKE_DIR}/include
    echo "[MysqlClient][INFO]use cache from last. buildMysqlClient succeed."
    return 0
  fi
  mkdir -p ${MYSQL_CLIENT_CMAKE_DIR}
  rm -rf ${MYSQL_CLIENT_CMAKE_DIR}/*
  cd ${MYSQL_CLIENT_CMAKE_DIR}/

  echo "[MysqlClient][INFO]gerenating Makefile..."
  # just build mysql client and client C API static lib
  if [ "${BUILD_TYPE}" == "DEBUG" ]; then
    if [ "${LLT_TEST_TYPE}" = "ASAN" ]; then
      cmake .. -DCMAKE_CXX_COMPILER=/usr/bin/g++ -DCMAKE_C_COMPILER=/usr/bin/gcc -DCMAKE_BUILD_TYPE=Debug \
          -DWITH_ASAN=ON -DWITH_ASAN_SCOPE=ON -DCMAKE_C_FLAGS=-w -DCMAKE_CXX_FLAGS=-w -DWITH_BOOST=${BOOST_PATH} \
          -DWITHOUT_SERVER=ON 1>/dev/null
    elif [ "${LLT_TEST_TYPE}" = "GCOV" ]; then
      cmake .. -DCMAKE_CXX_COMPILER=/usr/bin/g++ -DCMAKE_C_COMPILER=/usr/bin/gcc -DCMAKE_BUILD_TYPE=Debug \
          -DENABLE_GCOV=1 -DCMAKE_C_FLAGS=-w -DCMAKE_CXX_FLAGS=-w -DWITH_BOOST=${BOOST_PATH} \
          -DWITHOUT_SERVER=ON 1>/dev/null
    else
      cmake .. -DCMAKE_CXX_COMPILER=/usr/bin/g++ -DCMAKE_C_COMPILER=/usr/bin/gcc -DCMAKE_BUILD_TYPE=Debug \
          -DCMAKE_C_FLAGS=-w -DCMAKE_CXX_FLAGS=-w -DWITH_BOOST=${BOOST_PATH} -DWITHOUT_SERVER=ON 1>/dev/null
    fi
  elif [ "${BUILD_TYPE}" == "RELEASE" ]; then
    if [ "${LLT_TEST_TYPE}" = "ASAN" ]; then
      cmake .. -DCMAKE_CXX_COMPILER=/usr/bin/g++ -DCMAKE_C_COMPILER=/usr/bin/gcc -DCMAKE_BUILD_TYPE=Release \
          -DWITH_ASAN=ON -DWITH_ASAN_SCOPE=ON -DCMAKE_C_FLAGS=-w -DCMAKE_CXX_FLAGS=-w -DWITH_BOOST=${BOOST_PATH} \
          -DWITHOUT_SERVER=ON 1>/dev/null
    elif [ "${LLT_TEST_TYPE}" = "GCOV" ]; then
      cmake .. -DCMAKE_CXX_COMPILER=/usr/bin/g++ -DCMAKE_C_COMPILER=/usr/bin/gcc -DCMAKE_BUILD_TYPE=Release \
          -DENABLE_GCOV=1 -DCMAKE_C_FLAGS=-w -DCMAKE_CXX_FLAGS=-w -DWITH_BOOST=${BOOST_PATH} \
          -DWITHOUT_SERVER=ON 1>/dev/null
    else
      cmake .. -DCMAKE_CXX_COMPILER=/usr/bin/g++ -DCMAKE_C_COMPILER=/usr/bin/gcc -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_C_FLAGS=-g -DCMAKE_CXX_FLAGS=-g -DWITH_BOOST=${BOOST_PATH} -DWITHOUT_SERVER=ON 1>/dev/null
    fi
  fi
  echo "[MysqlClient][INFO]use Makefile, making..."
  make -j${CPU_CORES_NUM} 1>/dev/null
  if [ ! -f ${MYSQLCLIENTLIB_OUTPUT_PATH}/libmysqlclient.a ]; then
    echo "[MysqlClient][ERROR]buildMysqlClient failed."
    exit 1
  fi
  # ctc_proxy build before gerenating mysqld_error.h when build ctc SE, but ctc_proxy source depends on it.
  cp -arf ${MYSQL_CLIENT_CMAKE_DIR}/include/mysqld_error.h ${MYSQLD_CMAKE_DIR}/include
  export LIBRARY_PATH=${LIBRARY_PATH}:${MYSQLCLIENTLIB_OUTPUT_PATH}
  cp -arf ${MYSQLCLIENTLIB_OUTPUT_PATH}/libmysqlclient.a ${MYSQL_CODE_PATH}/daac_lib/
  echo "[MysqlClient][INFO]buildMysqlClient succeed."
  cd -
  return 0
}