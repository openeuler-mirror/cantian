#!/bin/bash

set -ex
source /etc/profile
BUILD_TYPE=${BUILD_TYPE:-"DEBUG"}
MYSQL_BUILD_TYPE=""
ENV_TYPE=${ENV_TYPE:-"x86_64"}
BUILD_MODE=${BUILD_MODE:-"multiple"}
BUILD_MYSQL_SO=${BUILD_MYSQL_SO:-"YES"}
if [ "${WORKSPACE}" != "" ]; then
    HOME_PATH=${WORKSPACE}
    CTDB_CODE_PATH=${HOME_PATH}/daac
    MYSQL_CODE_PATH=${HOME_PATH}/cantian-connector-mysql/mysql-source
    sed  -i 's/CantianKernel/daac/g' ${CTDB_CODE_PATH}/CI/CMC/mysql_server_tse_dependency.xml
    #cantian-connector-mysql门禁使用的py脚本写死路径，需要增加一个软链接
    ln -s ${CTDB_CODE_PATH} /home/regress/CantianKernel
 
else
    HOME_PATH="/home/regress"
    CTDB_CODE_PATH=${HOME_PATH}/CantianKernel
    MYSQL_CODE_PATH=${HOME_PATH}/cantian-connector-mysql
fi
CI_PACKAGE_PATH=${CTDB_CODE_PATH}/package_out
BUILD_TARGET_NAME="cantian_connector"
BUILD_PACK_NAME="Cantian_24.03"
SYMBOL_TARGET_NAME="Cantian_connector_symbol"
MYSQL_SOURCE_BIN_TARGET_NAME="Cantian_connector_mysql"
MYSQL_SOURCE_BIN_TARGET_PATH=${CI_PACKAGE_PATH}/${MYSQL_SOURCE_BIN_TARGET_NAME}
BUILD_TARGET_PATH=${CI_PACKAGE_PATH}/${BUILD_TARGET_NAME}
BUILD_SYMBOL_PATH=${CI_PACKAGE_PATH}/${SYMBOL_TARGET_NAME}
CTDB_TARGET_PATH=${BUILD_TARGET_PATH}/CantianKernel
MYSQL_TARGET_PATH=${BUILD_TARGET_PATH}/cantian-connector-mysql
MYSQL_BINARY_CODE_PATH=${CTDB_CODE_PATH}/library/mysql_pkg
XNET_LIB_PATH=${CTDB_CODE_PATH}/library/xnet/lib
BOOST_PATH=/tools/boost_1_73_0
DAAC_LIB_DIR=${CTDB_CODE_PATH}/daac_lib
DAAC_SECURITY_LIB_PATH=${CTDB_CODE_PATH}/library/huawei_security/lib
LOCAL_MYSQL_PATH=/usr/local/mysql
MYSQL_BIN_COMMIT_ID=""
LLT_TEST_TYPE=${1}
OS_ARCH=$(uname -i)
if [[ ${OS_ARCH} =~ "x86_64" ]]; then
    export CPU_CORES_NUM=`cat /proc/cpuinfo |grep "cores" |wc -l`
    LIB_OS_ARCH="lib_x86"
elif [[ ${OS_ARCH} =~ "aarch64" ]]; then 
    export C_INCLUDE_PATH=:/usr/include/python3.9/
    CPU_CORES_NUM=`cat /proc/cpuinfo |grep "architecture" |wc -l`
    LIB_OS_ARCH="lib_arm"
else 
    echo "OS_ARCH: ${OS_ARCH} is unknown, set CPU_CORES_NUM=16 "
    CPU_CORES_NUM=16
fi
WITH_TSE_STORAGE_ENGINE=1
if [ "${BUILD_MYSQL_SO}" == "YES" ]; then
  WITH_TSE_STORAGE_ENGINE=0
fi

CURRENT_PATH=$(dirname $(readlink -f $0))

SCRIPT_TOP_DIR=$(cd ${CURRENT_PATH}; pwd)
CI_TOP_DIR=$(cd ${SCRIPT_TOP_DIR}/..; pwd)
TMP_PKG_PATH=/tmp/cantian_new
TMP_COPY_PKG_NAME="${BUILD_TARGET_NAME}_for_asan"
TMP_COPY_PKG_TARGET="${BUILD_TARGET_NAME}_for_asan.tgz"

echo "Start build..."
echo "BUILD_TYPE: ${BUILD_TYPE}"
echo "ENV_TYPE: ${ENV_TYPE}"
echo "BUILD_MODE: ${BUILD_MODE}"
echo "HOME_PATH: ${HOME_PATH}"
echo "BUILD_TARGET_PATH: ${BUILD_TARGET_PATH}"
echo "BUILD_MYSQL_SO: ${BUILD_MYSQL_SO}"
echo "WITH_TSE_STORAGE_ENGINE: ${WITH_TSE_STORAGE_ENGINE}"
echo "LLT_TEST_TYPE: ${LLT_TEST_TYPE}"  # 当跑门禁测试用例的时候，传"ASAN"或者"GCOV"
echo "B_VERSION: ${B_VERSION}"   # 门禁通过传递参数修改versions.yaml的B版本

CURRENT_DIR=$(dirname $(readlink -f "$0"))
source ${CURRENT_DIR}/../../../build/function.sh

function pachingBazelCode() {
  cd ${MYSQL_CODE_PATH}
  git apply --check bazel_deleted.patch
  git apply --check bazel_created.patch
  
  patch --ignore-whitespace -p1 < bazel_deleted.patch
  patch --ignore-whitespace -p1 < bazel_created.patch
}

function pachingMysqlCode() {
  cd ${MYSQL_CODE_PATH}
  git apply --check mysql-scripts-meta.patch
  git apply --check mysql-test-meta.patch
  git apply --check mysql-source-code-meta.patch
  
  patch --ignore-whitespace -p1 < mysql-scripts-meta.patch
  patch --ignore-whitespace -p1 < mysql-test-meta.patch
  patch --ignore-whitespace -p1 < mysql-source-code-meta.patch
}

function collectMysqlTarget() {
  echo "Start collectMysqlTarget..."
  rm -rf ${MYSQL_TARGET_PATH}
  mkdir -p ${MYSQL_TARGET_PATH}
  mkdir -p ${MYSQL_TARGET_PATH}/mysql_bin/mysql

  mkdir -p ${MYSQL_TARGET_PATH}/mysql_bin/mysql/lib/plugin/nometa
  mkdir -p ${MYSQL_TARGET_PATH}/mysql_bin/mysql/lib/plugin/meta

  md5sum /usr/local/mysql/lib/plugin/ha_ctc.so.nometa
  md5sum /usr/local/mysql/lib/plugin/ha_ctc.so

  cp -arf /usr/local/mysql/lib/plugin/ha_ctc.so.nometa ${MYSQL_TARGET_PATH}/mysql_bin/mysql/lib/plugin/nometa/ha_ctc.so
  cp -arf /usr/local/mysql/lib/plugin/ha_ctc.so ${MYSQL_TARGET_PATH}/mysql_bin/mysql/lib/plugin/meta/ha_ctc.so

  if [ "${BUILD_TYPE}" == "RELEASE" ] && [ "${COMPILE_TYPE}" != "ASAN" ]; then
    rm -rf ${BUILD_SYMBOL_PATH}
    mkdir -p ${BUILD_SYMBOL_PATH}
    mkdir -p ${BUILD_SYMBOL_PATH}/cantian-connector-mysql-symbol
    mkdir -p ${BUILD_SYMBOL_PATH}/cantian-connector-mysql-symbol/meta
    mkdir -p ${BUILD_SYMBOL_PATH}/cantian-connector-mysql-symbol/nometa
    cp -arf ${MYSQL_CODE_PATH}/mysql_bin/symbol ${BUILD_SYMBOL_PATH}/cantian-connector-mysql-symbol 2>/dev/null || :
    sh ${CTDB_CODE_PATH}/build/seperate_dbg_symbol.sh ${MYSQL_TARGET_PATH}/mysql_bin/mysql/lib/plugin/meta/ha_ctc.so
    sh ${CTDB_CODE_PATH}/build/seperate_dbg_symbol.sh ${MYSQL_TARGET_PATH}/mysql_bin/mysql/lib/plugin/nometa/ha_ctc.so
    mv -f ${MYSQL_TARGET_PATH}/mysql_bin/mysql/lib/plugin/meta/ha_ctc.so.symbol ${BUILD_SYMBOL_PATH}/cantian-connector-mysql-symbol/meta
    mv -f ${MYSQL_TARGET_PATH}/mysql_bin/mysql/lib/plugin/nometa/ha_ctc.so.symbol ${BUILD_SYMBOL_PATH}/cantian-connector-mysql-symbol/nometa
    cd ${MYSQL_CODE_PATH}/daac_lib/
    sh ${CTDB_CODE_PATH}/build/seperate_dbg_symbol.sh libctc_proxy.so
    mv -f libctc_proxy.so.symbol ${BUILD_SYMBOL_PATH}/cantian-connector-mysql-symbol
  fi

  md5sum ${MYSQL_TARGET_PATH}/mysql_bin/mysql/lib/plugin/meta/ha_ctc.so
  md5sum ${MYSQL_TARGET_PATH}/mysql_bin/mysql/lib/plugin/nometa/ha_ctc.so

  rm -rf /usr/local/mysql/lib/plugin/ha_ctc.so.nometa
  rm -rf /usr/local/mysql/lib/plugin/ha_ctc.so

  nometa_so_md5sum=$(md5sum ${MYSQL_TARGET_PATH}/mysql_bin/mysql/lib/plugin/nometa/ha_ctc.so)
  meta_so_md5sum=$(md5sum ${MYSQL_TARGET_PATH}/mysql_bin/mysql/lib/plugin/meta/ha_ctc.so)

  echo -e >> ${BUILD_TARGET_PATH}/scm.property
  echo "nometa_so_md5sum: ${nometa_so_md5sum}" >> ${BUILD_TARGET_PATH}/scm.property
  echo "meta_so_md5sum: ${meta_so_md5sum}" >> ${BUILD_TARGET_PATH}/scm.property

  rm -rf ${MYSQL_SOURCE_BIN_TARGET_PATH}
  mkdir -p ${MYSQL_SOURCE_BIN_TARGET_PATH}
  cp -arf /usr/local/mysql ${MYSQL_SOURCE_BIN_TARGET_PATH}/

  mkdir -p ${MYSQL_TARGET_PATH}/daac_lib/
  if [ "${BUILD_MODE}" == "multiple" ]; then
    cp -arf ${MYSQL_CODE_PATH}/daac_lib/libsecurec.a ${MYSQL_TARGET_PATH}/daac_lib/libsecurec.a
    cp -arf ${MYSQL_CODE_PATH}/daac_lib/libctc_proxy.so ${MYSQL_TARGET_PATH}/daac_lib/libctc_proxy.so
  elif [ "${BUILD_MODE}" == "single" ]; then
    cp -arf ${MYSQL_CODE_PATH}/daac_lib ${MYSQL_TARGET_PATH}/
  fi

  mkdir -p ${MYSQL_TARGET_PATH}/scripts
  cp -arf ${MYSQL_CODE_PATH}/scripts/my.cnf ${MYSQL_TARGET_PATH}/scripts/
  if [ "${BUILD_MODE}" == "multiple" ] && [ "${COMPILE_TYPE}" == "ASAN" ]; then
    cp -arf ${MYSQL_CODE_PATH}/daac_lib/libasan.s* ${MYSQL_TARGET_PATH}/daac_lib/
    cp -arf ${MYSQL_CODE_PATH}/daac_lib/libubsan.s* ${MYSQL_TARGET_PATH}/daac_lib/
    sed -i "s/## BUILD_TYPE ENV_TYPE ##/ASAN ${ENV_TYPE}/g" ${CTDB_CODE_PATH}/CI/script/for_mysql_official/patch.sh
  else
    sed -i "s/## BUILD_TYPE ENV_TYPE ##/${BUILD_TYPE} ${ENV_TYPE}/g" ${CTDB_CODE_PATH}/CI/script/for_mysql_official/patch.sh
  fi
  mkdir -p ${MYSQL_TARGET_PATH}/scripts
  mkdir -p ${BUILD_TARGET_PATH}/for_mysql_official/docker
  cp -arf ${CTDB_CODE_PATH}/CI/script/for_mysql_official/docker/internals ${BUILD_TARGET_PATH}/for_mysql_official/docker/
  cp -arf ${CTDB_CODE_PATH}/CI/script/for_mysql_official/docker/mf_connector_init.sh ${BUILD_TARGET_PATH}/for_mysql_official/docker/
  cp -arf ${CTDB_CODE_PATH}/CI/script/for_mysql_official/patch.sh ${BUILD_TARGET_PATH}/for_mysql_official/
  chmod 755 ${BUILD_TARGET_PATH}/for_mysql_official/patch.sh
}

function collectDaacTarget() {
  echo "Start collectDaacTarget..."

  rm -rf ${CTDB_TARGET_PATH}
  mkdir -p ${CTDB_TARGET_PATH}
  cp -arf ${CTDB_CODE_PATH}/output/bin/Cantian-DATABASE-CENTOS-64bit ${CTDB_TARGET_PATH}
  cp -arf ${CTDB_CODE_PATH}/output/bin/Cantian-DATABASE-CENTOS-64bit.sha256 ${CTDB_TARGET_PATH}
  if [ "${BUILD_TYPE}" == "RELEASE" ] && [ "${COMPILE_TYPE}" != "ASAN" ]; then
    cp -arf ${CTDB_CODE_PATH}/output/bin/Cantian-DATABASE-CENTOS-64bit-SYMBOL ${BUILD_SYMBOL_PATH}
    cp -arf ${CTDB_CODE_PATH}/output/bin/Cantian-DATABASE-CENTOS-64bit-SYMBOL.sha256 ${BUILD_SYMBOL_PATH}
  fi
}

function collectTarget() {
  echo "Start collectTarget..."
  if [ "${static_type}" != "cooddy" ]; then
    collectMysqlTarget
  fi
  collectDaacTarget
}

function generateScmFile() {
  mysql_code_dir=$1
  echo "Start generateScmFile..."
  cd ${BUILD_TARGET_PATH}
  local scm_file_name="scm.property"
  rm -f ${scm_file_name}
  current_time=$(date "+%Y%m%d%H%M%S")
  # 获取当前时间戳
  echo "Package Time: ${current_time}" >>${scm_file_name}
  cd ${mysql_code_dir}
  local mysql_commit_id=$(git rev-parse HEAD)
  cd -
  cd ${CTDB_CODE_PATH}
  local daac_commit_id=$(git rev-parse HEAD)
  cd -
  echo "Commit Id:" >>${scm_file_name}
  echo "    cantian-connector-mysql: ${mysql_commit_id}" >>${scm_file_name}
  echo "    daac: ${daac_commit_id}" >>${scm_file_name}
  echo "scm info："
  cat ${scm_file_name}
}

function packageTarget() {
  echo "Start packageTarget..."
  cd ${CI_PACKAGE_PATH}
  tar -zcf cantian.tar.gz ${BUILD_TARGET_NAME}/
  if [ -d /opt/cantian/image ]; then
    rm -rf /opt/cantian/image
  fi
  mkdir -p /opt/cantian/image
  mv -f cantian.tar.gz /opt/cantian/image/
  sh ${CURRENT_PATH}/rpm_build_cantian.sh
  cd -
}

function newPackageTarget() {
  echo "Start newPackageTarget..."
  local current_time=$(date "+%Y%m%d%H%M%S")
  local pkg_dir_name="${BUILD_TARGET_NAME}"
  local pkg_name="${BUILD_PACK_NAME}_${ENV_TYPE}_${BUILD_TYPE}_${current_time}.tgz"
  local symbol_pkg_name="${SYMBOL_TARGET_NAME}_${ENV_TYPE}_${BUILD_TYPE}_${current_time}.tgz"
  local mysql_binary_pkg_prefix_name="${MYSQL_SOURCE_BIN_TARGET_NAME}_${ENV_TYPE}_${BUILD_TYPE}_${current_time}"
  local mysql_binary_pkg_name="${mysql_binary_pkg_prefix_name}"".tgz"
  if [ "${BUILD_MODE}" == "single" ]; then
    pkg_name="${BUILD_PACK_NAME}_${BUILD_MODE}_${ENV_TYPE}_${BUILD_TYPE}_${current_time}.tgz"
    symbol_pkg_name="${SYMBOL_TARGET_NAME}_${BUILD_MODE}_${ENV_TYPE}_${BUILD_TYPE}_${current_time}.tgz"
    mysql_binary_pkg_prefix_name="${MYSQL_SOURCE_BIN_TARGET_NAME}_${BUILD_MODE}_${ENV_TYPE}_${BUILD_TYPE}_${current_time}"
    mysql_binary_pkg_name="${mysql_binary_pkg_prefix_name}"".tgz"
  fi
  if [ "${BUILD_MODE}" == "multiple" ] && [ "${COMPILE_TYPE}" == "ASAN" ]; then
    mysql_binary_pkg_prefix_name="${MYSQL_SOURCE_BIN_TARGET_NAME}_${BUILD_MODE}_${ENV_TYPE}_${COMPILE_TYPE}_${current_time}"
    mysql_binary_pkg_name="${mysql_binary_pkg_prefix_name}"".tgz"
    pkg_name="${BUILD_PACK_NAME}_${ENV_TYPE}_${COMPILE_TYPE}_${current_time}.tgz"
  fi  
  if [ "${BUILD_TYPE}" == "RELEASE" ] && [ "${BUILD_MODE}" == "single" ]; then
    pkg_name="${BUILD_PACK_NAME}_${BUILD_MODE}_${ENV_TYPE}_${BUILD_TYPE}.tgz"
  fi
  if [ "${BUILD_TYPE}" == "RELEASE" ] && [ "${BUILD_MODE}" == "multiple" ] && [ "${COMPILE_TYPE}" != "ASAN" ]; then
    pkg_name="${BUILD_PACK_NAME}_${ENV_TYPE}_${BUILD_TYPE}.tgz"
  fi
  local pkg_real_path=${TMP_PKG_PATH}/${pkg_dir_name}
  if [ -d ${pkg_real_path} ]; then
    rm -rf ${pkg_real_path}
  fi
  mkdir -p ${pkg_real_path}/action
  mkdir -p ${pkg_real_path}/repo
  mkdir -p ${pkg_real_path}/config
  mkdir -p ${pkg_real_path}/common
  if [[ x"${B_VERSION}" != x"" ]];then
      sed -i "s/B[0-9]\+/${B_VERSION}/g" ${CTDB_CODE_PATH}/CI/build/conf/versions.yml
  fi
  cp -arf ${CTDB_CODE_PATH}/CI/build/conf/versions.yml ${pkg_real_path}/
  mkdir -p ${pkg_real_path}/for_mysql_official/docker

  sed -i "s/#MYSQL_PKG_PREFIX_NAME#/${mysql_binary_pkg_prefix_name}/g" ${CTDB_CODE_PATH}/CI/script/for_mysql_official/patch.sh
  cp -arf ${CTDB_CODE_PATH}/CI/script/for_mysql_official/docker/internals ${pkg_real_path}/for_mysql_official/docker/
  cp -arf ${CTDB_CODE_PATH}/CI/script/for_mysql_official/docker/mf_connector_init.sh ${pkg_real_path}/for_mysql_official/docker/
  cp -arf ${CTDB_CODE_PATH}/CI/script/for_mysql_official/patch.sh ${pkg_real_path}/for_mysql_official/

  cp -f ${CURRENT_PATH}/rpm/RPMS/${ENV_TYPE}/cantian*.rpm ${pkg_real_path}/repo/
  cp -f ${CI_TOP_DIR}/temp/ct_om/rpm/RPMS/${ENV_TYPE}/ct_om*.rpm ${pkg_real_path}/repo
  cp -rf ${CI_TOP_DIR}/../../pkg/deploy/action/* ${pkg_real_path}/action/
  cp -rf ${CI_TOP_DIR}/../../pkg/deploy/config/* ${pkg_real_path}/config/
  cp -rf ${CI_TOP_DIR}/../../common/* ${pkg_real_path}/common/
  if [ "${BUILD_MODE}" == "single" ]; then
      cp -rf ${CI_TOP_DIR}/../../pkg/deploy/single_options/* ${pkg_real_path}/action/cantian
  fi

  # 在脚本中调用 main 函数之前添加变量，区分 debug release asan版本
  if [ "${COMPILE_TYPE}" == "ASAN" ]; then
      sed -i "/main \$@/i CSTOOL_TYPE=${COMPILE_TYPE,,}" ${pkg_real_path}/action/dbstor/check_usr_pwd.sh
      sed -i "/main \$@/i CSTOOL_TYPE=${COMPILE_TYPE,,}" ${pkg_real_path}/action/inspection/inspection_scripts/kernal/check_link_cnt.sh
  else
      sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE,,}" ${pkg_real_path}/action/dbstor/check_usr_pwd.sh
      sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE,,}" ${pkg_real_path}/action/inspection/inspection_scripts/kernal/check_link_cnt.sh
  fi

  if [ "${static_type}" != "cooddy" ]; then
    echo "Start pkg ${pkg_dir_name}.tgz..."
    cd ${TMP_PKG_PATH}
    tar -zcf ${pkg_name} ${pkg_dir_name}
    cp ${pkg_name} ${CI_PACKAGE_PATH}/

    if [ "${BUILD_TYPE}" == "RELEASE" ] && [ "${COMPILE_TYPE}" != "ASAN" ]; then
      # 参天符号表单独编包
      cd ${CI_PACKAGE_PATH}
      tar -zcf ${symbol_pkg_name} ${SYMBOL_TARGET_NAME}/
      mkdir -p ${CI_PACKAGE_PATH}/${TMP_COPY_PKG_NAME}
      cp -f ${CI_PACKAGE_PATH}/${pkg_name} ${CI_PACKAGE_PATH}/${TMP_COPY_PKG_NAME}/${TMP_COPY_PKG_TARGET}
    fi

    cd ${CI_PACKAGE_PATH}
    tar -zcf ${mysql_binary_pkg_name} ${MYSQL_SOURCE_BIN_TARGET_NAME}/
  fi
}

function buildDaacDebug() {
  echo "Start buildDaacDebug..."
  cd ${CTDB_CODE_PATH}/build
  if [ "${BUILD_MODE}" == "multiple" ]; then
    sh Makefile.sh package
  elif [ "${BUILD_MODE}" == "single" ]; then
    sh Makefile.sh package no_shm=1
  fi
  cd -
}

function buildDaacAsan() {
  echo "Start buildDaacAsan..."
  cd ${CTDB_CODE_PATH}/build
  if [ "${BUILD_MODE}" == "multiple" ]; then
    sh Makefile.sh package-release asan=1
  elif [ "${BUILD_MODE}" == "single" ]; then
    sh Makefile.sh package-release no_shm=1 asan=1
  fi
  cd -
}

function buildDaacRelease() {
  echo "Start buildDaacRelease..."
  cd ${CTDB_CODE_PATH}/build
  if [ "${BUILD_MODE}" == "multiple" ]; then
    sh -x Makefile.sh package-release
  elif [ "${BUILD_MODE}" == "single" ]; then
    sh -x Makefile.sh package-release no_shm=1
  fi
  cd -
}

function separateMysqlSymbol() {
  local bin_dir=$1
  local symbol_dir=$2
  mkdir -p ${symbol_dir}
  rm -f ${symbol_dir}/*
  local file_list=("mysqld" "mysql")
  cd ${bin_dir}
  for file in ${file_list[@]}
  do
    cp ${file} ${file}.debug
    mv ${file}.debug ${symbol_dir}
    objcopy --strip-debug ${file}
  done
  cd -
}

function compileReleaseMysql() {
  echo "start compile release mysql"
  if [ "${LLT_TEST_TYPE}" == "" ]; then
    local LLT_TEST_TYPE="NORMAL"
  fi
  rm -f ${HACTC_LIBCTCPROXY_DIR}/bld_debug/CMakeCache.txt
  prepareGetMysqlClientStaticLibToDaaclib ${HACTC_LIBCTCPROXY_DIR} "RELEASE" ${LLT_TEST_TYPE} ${BOOST_PATH} ${CPU_CORES_NUM} ${HACTC_LIBCTCPROXY_DIR}/bld_debug
  cd ${HACTC_LIBCTCPROXY_DIR}/bld_debug

  if [ "${BUILD_MODE}" == "multiple" ]; then
    if [ "${LLT_TEST_TYPE}" = "ASAN" ] || [ "${LLT_TEST_TYPE}" = "GCOV" ]; then
      cmake .. -DCMAKE_CXX_COMPILER=/usr/bin/g++ -DCMAKE_C_COMPILER=/usr/bin/gcc -DWITH_ASAN=ON -DWITH_ASAN_SCOPE=ON -DENABLE_GCOV=1 -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Release -DWITH_BOOST=${BOOST_PATH} -DWITHOUT_SERVER=OFF -DCMAKE_INSTALL_PREFIX=${HACTC_LIBCTCPROXY_DIR}/tmp
    else
      if  [[ ${OS_ARCH} =~ "aarch64" ]]; then
        cmake .. -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Release -DWITH_BOOST=${BOOST_PATH} -DCMAKE_C_FLAGS="-g -march=armv8.2-a+crc+lse -mno-outline-atomics" -DCMAKE_CXX_FLAGS="-g -march=armv8.2-a+crc+lse -mno-outline-atomics" -DWITHOUT_SERVER=OFF -DCMAKE_INSTALL_PREFIX=${HACTC_LIBCTCPROXY_DIR}/tmp
      else
        cmake .. -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Release -DWITH_BOOST=${BOOST_PATH} -DCMAKE_C_FLAGS=-g -DCMAKE_CXX_FLAGS=-g -DWITHOUT_SERVER=OFF -DCMAKE_INSTALL_PREFIX=${HACTC_LIBCTCPROXY_DIR}/tmp
      fi
    fi
  elif [ "${BUILD_MODE}" == "single" ]; then
    if  [[ ${OS_ARCH} =~ "aarch64" ]]; then
      cmake .. -DWITH_DAAC=1 -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Release -DWITH_BOOST=${BOOST_PATH} -DCMAKE_C_FLAGS="-g -march=armv8.2-a+crc+lse -mno-outline-atomics" -DCMAKE_CXX_FLAGS="-g -march=armv8.2-a+crc+lse -mno-outline-atomics" -DWITHOUT_SERVER=OFF -DCMAKE_INSTALL_PREFIX=${HACTC_LIBCTCPROXY_DIR}/tmp
    else
      cmake .. -DWITH_DAAC=1 -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Release -DWITH_BOOST=${BOOST_PATH} -DCMAKE_C_FLAGS=-g -DCMAKE_CXX_FLAGS=-g -DWITHOUT_SERVER=OFF -DCMAKE_INSTALL_PREFIX=${HACTC_LIBCTCPROXY_DIR}/tmp
    fi
  fi
}

function compileDebugMysql() {
  echo "start compile debug mysql"
  if [ "${LLT_TEST_TYPE}" == "" ]; then
    local LLT_TEST_TYPE="NORMAL"
  fi
  rm -f ${HACTC_LIBCTCPROXY_DIR}/bld_debug/CMakeCache.txt
  prepareGetMysqlClientStaticLibToDaaclib ${HACTC_LIBCTCPROXY_DIR} "DEBUG" ${LLT_TEST_TYPE} ${BOOST_PATH} ${CPU_CORES_NUM} ${HACTC_LIBCTCPROXY_DIR}/bld_debug
  cd ${HACTC_LIBCTCPROXY_DIR}/bld_debug

  if [ "${BUILD_MODE}" == "multiple" ]; then
    if [ "${LLT_TEST_TYPE}" = "ASAN" ] || [ "${LLT_TEST_TYPE}" = "GCOV" ]; then
      cmake .. -DCMAKE_CXX_COMPILER=/usr/bin/g++ -DCMAKE_C_COMPILER=/usr/bin/gcc -DWITH_ASAN=ON -DWITH_ASAN_SCOPE=ON -DENABLE_GCOV=1 -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Debug -DWITH_BOOST=${BOOST_PATH} -DCMAKE_C_FLAGS=-w -DCMAKE_CXX_FLAGS=-w -DWITHOUT_SERVER=OFF -DCMAKE_INSTALL_PREFIX=${HACTC_LIBCTCPROXY_DIR}/tmp
    else
      cmake .. -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Debug -DWITH_BOOST=${BOOST_PATH} -DCMAKE_C_FLAGS=-w -DCMAKE_CXX_FLAGS=-w -DWITHOUT_SERVER=OFF -DCMAKE_INSTALL_PREFIX=${HACTC_LIBCTCPROXY_DIR}/tmp
    fi
  elif [ "${BUILD_MODE}" == "single" ]; then
    cmake .. -DWITH_DAAC=1 -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Debug -DWITH_BOOST=${BOOST_PATH} -DCMAKE_C_FLAGS=-w -DCMAKE_CXX_FLAGS=-w -DWITHOUT_SERVER=OFF -DCMAKE_INSTALL_PREFIX=${HACTC_LIBCTCPROXY_DIR}/tmp
  fi
}

function compileReleaseAsanMysql() {
  echo "start compile release asan mysql"
  rm -f ${HACTC_LIBCTCPROXY_DIR}/bld_debug/CMakeCache.txt
  prepareGetMysqlClientStaticLibToDaaclib ${HACTC_LIBCTCPROXY_DIR} "RELEASE" "ASAN" ${BOOST_PATH} ${CPU_CORES_NUM} ${HACTC_LIBCTCPROXY_DIR}/bld_debug

  cd ${HACTC_LIBCTCPROXY_DIR}/bld_debug
  export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${MYSQL_CODE_PATH}/daac_lib
  if [ "${BUILD_MODE}" == "multiple" ]; then
    cmake .. -DCMAKE_CXX_COMPILER=/usr/bin/g++ -DCMAKE_C_COMPILER=/usr/bin/gcc -DWITH_ASAN=ON -DWITH_ASAN_SCOPE=ON \
          -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Release -DWITH_BOOST=${BOOST_PATH} \
          -DWITH_UBSAN=ON -DWITHOUT_SERVER=OFF -DCMAKE_INSTALL_PREFIX=${HACTC_LIBCTCPROXY_DIR}/tmp
  elif [ "${BUILD_MODE}" == "single" ]; then
    cmake .. -DWITH_DAAC=1 -DWITH_TSE_STORAGE_ENGINE=${WITH_TSE_STORAGE_ENGINE} -DCMAKE_BUILD_TYPE=Release \
          -DWITH_BOOST=${BOOST_PATH} -DCMAKE_C_FLAGS=-g -DCMAKE_CXX_FLAGS=-g -DWITH_ASAN=ON -DWITH_ASAN_SCOPE=ON \
          -DWITH_UBSAN=ON -DWITHOUT_SERVER=OFF -DCMAKE_INSTALL_PREFIX=${HACTC_LIBCTCPROXY_DIR}/tmp
  fi
}

function buildMysqlnoMeta() {
  echo "nometa version: start build plugin so: ha_ctc and libctc_proxy"

  if [ "${mrId}" == "" ] && [ "${local_build}" != "true" ];then
    echo "[NO_META]: build MYSQL plugin WITHOUT metadata normalization"
    echo "declare directory and copy mysql code for ha_ctc.so and libctc_proxy.so -- making nometa version so file"
    rm -rf ${HACTC_LIBCTCPROXY_DIR}
    mkdir -p ${HACTC_LIBCTCPROXY_DIR}
    cp -arf ${MYSQL_CODE_PATH}/* ${HACTC_LIBCTCPROXY_DIR}

    mkdir -p ${HACTC_LIBCTCPROXY_DIR}/tmp
    mkdir -p ${HACTC_LIBCTCPROXY_DIR}/bld_debug
    if [ "${BUILD_MODE}" == "multiple" ] && [ "${COMPILE_TYPE}" == "ASAN" ]; then
      compileReleaseAsanMysql
    elif [ "${BUILD_TYPE}" == "DEBUG" ]; then
      compileDebugMysql
    elif [ "${BUILD_TYPE}" == "RELEASE" ]; then
      compileReleaseMysql
    fi
    cp ${HACTC_LIBCTCPROXY_DIR}/clientbuild/include/mysqld_error.h ${HACTC_LIBCTCPROXY_DIR}/bld_debug/include/
    cd -
    cd ${HACTC_LIBCTCPROXY_DIR}/bld_debug/storage/tianchi && make -j${CPU_CORES_NUM} && make install
    cp ${HACTC_LIBCTCPROXY_DIR}/tmp/lib/plugin/ha_ctc.so /usr/local/ha_ctc.so.nometa
    make clean
    md5sum /usr/local/ha_ctc.so.nometa
    echo "nometa version: build plugin so: ha_ctc and libctc_proxy finished"
  fi
}

function buildMysqlMeta() {
  echo "meta version: start build plugin so: ha_ctc and libctc_proxy"
  echo "BUILD_TYPE: ${BUILD_TYPE}"
  rm -rf ${HACTC_LIBCTCPROXY_DIR}
  mkdir -p ${HACTC_LIBCTCPROXY_DIR}
  cp -arf ${MYSQL_CODE_PATH}/* ${HACTC_LIBCTCPROXY_DIR}

  mkdir -p ${HACTC_LIBCTCPROXY_DIR}/tmp
  mkdir -p ${HACTC_LIBCTCPROXY_DIR}/bld_debug
  if [ "${BUILD_MODE}" == "multiple" ] && [ "${COMPILE_TYPE}" == "ASAN" ]; then
    compileReleaseAsanMysql
  elif [ "${BUILD_TYPE}" == "DEBUG" ]; then
    compileDebugMysql
  elif [ "${BUILD_TYPE}" == "RELEASE" ]; then
    compileReleaseMysql
  fi
  cp ${HACTC_LIBCTCPROXY_DIR}/clientbuild/include/mysqld_error.h ${HACTC_LIBCTCPROXY_DIR}/bld_debug/include/
  cd -
  cd ${HACTC_LIBCTCPROXY_DIR}/bld_debug/storage/tianchi && make -j${CPU_CORES_NUM} && make install
  cp ${HACTC_LIBCTCPROXY_DIR}/tmp/lib/plugin/ha_ctc.so /usr/local/ha_ctc.so
  cp -arf ${HACTC_LIBCTCPROXY_DIR}/daac_lib/libctc_proxy.so /usr/lib64
  cp -arf ${HACTC_LIBCTCPROXY_DIR}/daac_lib/libsecurec.a /usr/lib64
  cp -arf ${HACTC_LIBCTCPROXY_DIR}/daac_lib/libmessage_queue.a /usr/lib64
  make clean
  md5sum /usr/local/ha_ctc.so
  echo "meta version: build plugin so: ha_ctc and libctc_proxy finished"
}

function bazelBuildMysqlSource() {
  rm -rf ${LOCAL_MYSQL_PATH}
  mkdir -p ${LOCAL_MYSQL_PATH}

  if [[ ${OS_ARCH} =~ "x86_64" ]]; then
    cp ${MYSQL_CODE_PATH}/bazel-out/k8-fastbuild/bin/mysql.tar.gz /usr/local/mysql
  elif [[ ${OS_ARCH} =~ "aarch64" ]]; then
    cp ${MYSQL_CODE_PATH}/bazel-out/aarch64-fastbuild/bin/mysql.tar.gz /usr/local/mysql
  fi
  tar -xf ${LOCAL_MYSQL_PATH}/mysql.tar.gz -C ${LOCAL_MYSQL_PATH}
  md5sum /usr/lib64/libctc_proxy.so
  cp -arf /usr/lib64/libctc_proxy.so ${MYSQL_CODE_PATH}/daac_lib/
  cp -arf /usr/lib64/libsecurec.a ${MYSQL_CODE_PATH}/daac_lib/
  cp -arf /usr/lib64/libmessage_queue.a ${MYSQL_CODE_PATH}/daac_lib/
  if [ "${mrId}" == "" ] && [ "${local_build}" != "true" ];then
    cp -arf /usr/local/ha_ctc.so.nometa ${LOCAL_MYSQL_PATH}/lib/plugin/ha_ctc.so.nometa
    md5sum ${LOCAL_MYSQL_PATH}/lib/plugin/ha_ctc.so.nometa
  fi
  cp -arf /usr/local/ha_ctc.so ${LOCAL_MYSQL_PATH}/lib/plugin/ha_ctc.so
  md5sum ${LOCAL_MYSQL_PATH}/lib/plugin/ha_ctc.so
  cd -
}

function buildMysqlRelease() {
  LOCAL_REMOTE_FLAG=REMOTE_RELEASE
  rm -rf ${LOCAL_MYSQL_PATH}
  mkdir -p ${LOCAL_MYSQL_PATH}

  echo "Start buildMysqlRelease..."
  rm -rf ${MYSQL_CODE_PATH}/daac_lib
  mkdir -p ${MYSQL_CODE_PATH}/daac_lib
  cp -arf ${DAAC_LIB_DIR}/* ${MYSQL_CODE_PATH}/daac_lib/
  cp -arf ${DAAC_SECURITY_LIB_PATH}/* ${MYSQL_CODE_PATH}/daac_lib/
  rm -rf ${MYSQL_CODE_PATH}/bld_debug
  mkdir -p ${MYSQL_CODE_PATH}/bld_debug

  cp -arf ${MYSQL_CODE_PATH}/../bazel_code/. ${MYSQL_CODE_PATH}

  HACTC_LIBCTCPROXY_DIR=/hactc_libctcproxy_dir/mysql-source
  export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${HACTC_LIBCTCPROXY_DIR}/daac_lib

  buildMysqlnoMeta

  echo "meta version: declare directory and copy mysql code for ha_ctc.so and libctc_proxy.so"
  cd ${MYSQL_CODE_PATH}
  echo "pachingMysqlCode for mysql source"

  pachingBazelCode
  if [ $? -ne 0 ]; then
    echo "pachingBazelCode fail."
    exit 1
  fi
  pachingMysqlCode
  if [ $? -ne 0 ]; then
    echo "pachingMysqlCode fail."
    exit 1
  fi

  buildMysqlMeta

  cd ${MYSQL_CODE_PATH}
  if [ "${LLT_TEST_TYPE}" == "" ]; then
      local LLT_TEST_TYPE="NORMAL"
  fi
  prepareGetMysqlClientStaticLibToDaaclib ${MYSQL_CODE_PATH} "RELEASE" ${LLT_TEST_TYPE} ${BOOST_PATH} ${CPU_CORES_NUM} ${MYSQL_CODE_PATH}/bld_debug

  cd ${MYSQL_CODE_PATH}/bld_debug
  export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${MYSQL_CODE_PATH}/daac_lib

  bazelBuildMysqlSource
}

function buildMysqlDebug() {
  LOCAL_REMOTE_FLAG=REMOTE_DEBUG

  echo "Start buildMysqlDebug..."
  rm -rf ${LOCAL_MYSQL_PATH}
  mkdir -p ${LOCAL_MYSQL_PATH}

  rm -rf ${MYSQL_CODE_PATH}/daac_lib
  mkdir -p ${MYSQL_CODE_PATH}/daac_lib
  cp -arf ${DAAC_LIB_DIR}/* ${MYSQL_CODE_PATH}/daac_lib/
  cp -arf ${DAAC_SECURITY_LIB_PATH}/* ${MYSQL_CODE_PATH}/daac_lib/
  rm -rf ${MYSQL_CODE_PATH}/bld_debug
  mkdir -p ${MYSQL_CODE_PATH}/bld_debug

  cp -arf ${MYSQL_CODE_PATH}/../bazel_code/. ${MYSQL_CODE_PATH}
  HACTC_LIBCTCPROXY_DIR=/hactc_libctcproxy_dir/mysql-source
  export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${HACTC_LIBCTCPROXY_DIR}/daac_lib

  buildMysqlnoMeta

  echo "meta version: declare directory and copy mysql code for ha_ctc.so and libctc_proxy.so"
  cd ${MYSQL_CODE_PATH}
  echo "pachingMysqlCode for mysql source"
  pachingBazelCode
  if [ $? -ne 0 ]; then
    echo "pachingBazelCode fail."
    exit 1
  fi
  pachingMysqlCode
  if [ $? -ne 0 ]; then
    echo "pachingMysqlCode fail."
    exit 1
  fi
  buildMysqlMeta

  cd ${MYSQL_CODE_PATH}
  if [ "${LLT_TEST_TYPE}" == "" ]; then
    local LLT_TEST_TYPE="NORMAL"
  fi
  prepareGetMysqlClientStaticLibToDaaclib ${MYSQL_CODE_PATH} "DEBUG" ${LLT_TEST_TYPE} ${BOOST_PATH} ${CPU_CORES_NUM} ${MYSQL_CODE_PATH}/bld_debug

  cd ${MYSQL_CODE_PATH}/bld_debug
  export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${MYSQL_CODE_PATH}/daac_lib

  bazelBuildMysqlSource
}

function buildMysqlReleaseAsan() {
  LOCAL_REMOTE_FLAG=REMOTE_RELEASE_ASAN

  export ASAN_OPTIONS=verify_asan_link_order=0
  rm -rf ${LOCAL_MYSQL_PATH}
  mkdir -p ${LOCAL_MYSQL_PATH}

  echo "Start buildMysqlAsan..."
  rm -rf ${MYSQL_CODE_PATH}/daac_lib
  mkdir -p ${MYSQL_CODE_PATH}/daac_lib
  cp -arf ${DAAC_LIB_DIR}/* ${MYSQL_CODE_PATH}/daac_lib/
  cp -arf ${DAAC_SECURITY_LIB_PATH}/* ${MYSQL_CODE_PATH}/daac_lib/
  rm -rf ${MYSQL_CODE_PATH}/bld_debug
  mkdir -p ${MYSQL_CODE_PATH}/bld_debug

  cp -arf ${MYSQL_CODE_PATH}/../bazel_code/. ${MYSQL_CODE_PATH}

  HACTC_LIBCTCPROXY_DIR=/hactc_libctcproxy_dir/mysql-source
  export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${HACTC_LIBCTCPROXY_DIR}/daac_lib

  buildMysqlnoMeta

  echo "declare directory and copy mysql code for ha_ctc.so and libctc_proxy.so -- making meta version so file"
  cd ${MYSQL_CODE_PATH}
  echo "pachingMysqlCode for mysql source"
  pachingBazelCode
  if [ $? -ne 0 ]; then
    echo "pachingBazelCode fail."
    exit 1
  fi
  pachingMysqlCode
  if [ $? -ne 0 ]; then
    echo "pachingMysqlCode fail."
    exit 1
  fi
  buildMysqlMeta

  cd ${MYSQL_CODE_PATH}
  prepareGetMysqlClientStaticLibToDaaclib ${MYSQL_CODE_PATH} "RELEASE" "ASAN" ${BOOST_PATH} ${CPU_CORES_NUM} ${MYSQL_CODE_PATH}/bld_debug

  cd ${MYSQL_CODE_PATH}/bld_debug
  export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${MYSQL_CODE_PATH}/daac_lib

  bazelBuildMysqlSource
}

function sync_mysql_code()
{
    mysql_dir=$1
    mysql_source=$2
    echo "sync_mysql_code mysql_dir:${mysql_dir}"
    echo "sync_mysql_code mysql_source:${mysql_source}"
    cp -arf ${mysql_dir}/mysql-test ${mysql_source}
    cp -arf ${mysql_dir}/include ${mysql_source}
    cp -arf ${mysql_dir}/storage ${mysql_source}
    cp -arf ${mysql_dir}/docker ${mysql_source}
    cp -arf ${mysql_dir}/scripts ${mysql_source}
    cp -arf ${mysql_dir}/mysql_patch/* ${mysql_source}
    cp -arf ${mysql_dir}/bazel_patch/* ${mysql_source}
}

function checkInterfaceVersion()
{
  set +e
  # sh $(dirname $(realpath ${BASH_SOURCE[0]}))/check_interface.sh ${CTDB_CODE_PATH} ${MYSQL_CODE_PATH}
  sh ${CURRENT_PATH}/check_interface.sh ${CTDB_CODE_PATH} ${MYSQL_CODE_PATH}
  if [[ $? != 0 ]]; then
    exit 1
  fi
  set -e
}

function prepare() {
  # 合并不同代码仓代码至daac目录
  if [ -L ${MYSQL_CODE_PATH} ]; then
    rm -f ${MYSQL_CODE_PATH}
  fi

  if [ -L ${CTDB_CODE_PATH} ]; then
    rm -f ${CTDB_CODE_PATH}
  fi
  local code_home=$(dirname $(realpath ${BASH_SOURCE[0]}))/../../../..
  echo $(realpath ${BASH_SOURCE[0]})
  ln -s -f ${code_home}/daac ${CTDB_CODE_PATH}
  rm -rf ${BUILD_TARGET_PATH}
  mkdir -p ${BUILD_TARGET_PATH}
  generateScmFile ${code_home}/cantian-connector-mysql

  echo "[METADATA_TEST]: cd mysql-source"
  cd ${code_home}/cantian-connector-mysql/mysql-source
  pwd
  echo "[METADATA_TEST]: git branch"

  sync_mysql_code ${code_home}/cantian-connector-mysql/ ${code_home}/cantian-connector-mysql/mysql-source
  [[ "${WORKSPACE}" == "" ]] && ln -s -f ${code_home}/cantian-connector-mysql/mysql-source ${MYSQL_CODE_PATH}
  local xml_path=/etc/maven/settings.xml
  local GCC_VERSION=`gcc --version |head -1 |awk '{print $NF}'`
  if [[ ${OS_ARCH} =~ "aarch64" ]] && [[ ${GCC_VERSION} == "10.3.1" ]]; then
      xml_path=$MAVEN_HOME/conf/settings.xml
  fi
  rm -f ${xml_path}
  cp ${CTDB_CODE_PATH}/CI/maven/settings.xml ${xml_path}
  if [[ ${OS_ARCH} =~ "x86_64" ]]; then
      xml_path=$MAVEN_HOME/conf/settings.xml
  fi
  rm -f ${xml_path}
  cp ${CTDB_CODE_PATH}/CI/maven/settings.xml ${xml_path}
  cd ${code_home}/cantian-connector-mysql
  MYSQL_BIN_COMMIT_ID=($(git submodule status))
  echo " mysql binary commit id : ${MYSQL_BIN_COMMIT_ID}"
}


function buildCtOmPackage() {
  sh ${CURRENT_PATH}/build_ct_om.sh
  sh ${CURRENT_PATH}/rpm_build_ct_om.sh
  if [ $? -ne 0 ]; then
      echo "build ct_om fail"
      retrun 1
  fi

}

function installCert(){

    local cert_home=$JAVA_HOME/jre/lib/security
    local GCC_VERSION=`gcc --version |head -1 |awk '{print $NF}'`
    if [[ ${OS_ARCH} =~ "aarch64" ]] && [[ ${GCC_VERSION} == "10.3.1" ]]; then
        # v2R11 该路径与其他版本有区别，由于老镜像用的是混合镜像(v2r11内核)，这里用gcc -v区分
        cert_home=$JAVA_HOME/lib/security
    fi
    cd ${cert_home}
    keytool -keystore cacerts -importcert -alias HuaweiITRootCA -file HuaweiITRootCA.cer -storepass changeit -noprompt
    keytool -keystore cacerts -importcert -alias HWITEnterpriseCA1 -file HWITEnterpriseCA1.cer -storepass changeit -noprompt
    chmod 755 -R ${cert_home}/cacerts
    # cd -
}

# 数据入湖是否debug模式修改
function changeLogicrepDebugConf(){
    cd ${CTDB_CODE_PATH}/pkg/src/zlogicrep/conf/
    sed -i 's/isdebug=/isdebug=true/g' init.properties
}

# 数据入湖是否debug模式修改
function changeLogicrepRealeaseConf(){
    cd ${CTDB_CODE_PATH}/pkg/src/zlogicrep/conf/
    sed -i 's/isdebug=/isdebug=false/g' init.properties
    rm -f injection_switch.properties
}

set +e

set -e
prepare
checkInterfaceVersion
if [ "${BUILD_MODE}" == "multiple" ] && [ "${COMPILE_TYPE}" == "ASAN" ]; then
  buildDaacAsan
  buildMysqlReleaseAsan
  buildCtOmPackage
elif [ "${BUILD_TYPE}" == "DEBUG" ]; then
  changeLogicrepDebugConf
  buildDaacDebug
  if [ "${static_type}" != "cooddy" ]; then
    buildMysqlDebug
  fi
  buildCtOmPackage
elif [ "${BUILD_TYPE}" == "RELEASE" ]; then
  changeLogicrepRealeaseConf
  buildDaacRelease
  if [ "${static_type}" != "cooddy" ]; then
    buildMysqlRelease
  fi
  buildCtOmPackage
else
  echo "BUILD_TYPE: ${BUILD_TYPE} or ${COMPILE_TYPE}/${BUILD_MODE} is invalid!"
  exit 1
fi

# ASAN， GCOV 门禁使用参数，跑门禁不需要打包
if [ "${LLT_TEST_TYPE}" == "ASAN" ] || [ "${LLT_TEST_TYPE}" == "GCOV" ]; then
  echo "----------------- BUILD.SH FINISH -----------------"
  exit 0
else
  echo "----------------- COLLECTING AND PACKAGING -----------------"
  collectTarget
  packageTarget
  newPackageTarget
fi

if [ "${static_type}" != "cooddy" ]; then
    [[ ! -d ${CTDB_CODE_PATH}/package ]] && mkdir -p ${CTDB_CODE_PATH}/package
    cp ${CTDB_CODE_PATH}/package_out/*.tgz ${CTDB_CODE_PATH}/package/
fi