#!/bin/bash

set -e

CURRENT_PATH=$(dirname $(readlink -f $0))
source "${CURRENT_PATH}"/common.sh

CTDB_CODE_PATH="${CURRENT_PATH}"/..
MYSQL_SERVER_PATH="${CTDB_CODE_PATH}"/../cantian-connector-mysql
BUILD_TARGET_NAME="cantian_connector"
SYMBOL_TARGET_NAME="Cantian_connector_symbol"
BUILD_PACK_NAME="Cantian_24.12"
ENV_TYPE=$(uname -p)
TMP_PKG_PATH=${CTDB_CODE_PATH}/package
CTDB_TARGET_PATH=${CANTIANDB_BIN}/${BUILD_TARGET_NAME}/CantianKernel
MYSQL_CODE_PATH=${MYSQL_SERVER_PATH}/mysql-source
MYSQL_BIN_NAME="Mysql_server"
CONNECT_BIN_NAME="Cantian_connector"

export INTERNAL_BUILD="TRUE"

if [[ ! -d "${CTDB_CODE_PATH}"/../ProductComm_DoradoAA ]];then
    export INTERNAL_BUILD="FALSE"
fi

if [[ ${INTERNAL_BUILD} == "TRUE" ]];then
    TMP_PKG_PATH=${CTDB_CODE_PATH}/package
else
    TMP_PKG_PATH=/tmp/cantian_output
fi

mkdir -p ${TMP_PKG_PATH}

function packageTarget() {
  echo "Start packageTarget..."
  cd "${CANTIANDB_BIN}"
  tar -zcf cantian.tar.gz ${BUILD_TARGET_NAME}/
  if [ -d /opt/cantian/image ]; then
    rm -rf /opt/cantian/image
  fi
  mkdir -p /opt/cantian/image
  mv -f cantian.tar.gz /opt/cantian/image/
  cd ${CURRENT_PATH}
  bash "${CURRENT_PATH}"/rpm_build_cantian.sh
}

function buildCtOmPackage() {
  bash "${CURRENT_PATH}"/build_ct_om.sh
  bash "${CURRENT_PATH}"/rpm_build_ct_om.sh
  if [ $? -ne 0 ]; then
      echo "build ct_om fail"
      return 1
  fi
}

function packageSymbol() {
  if [[ ${BUILD_TYPE} != "release" ]]; then
    return
  fi

  echo "Start package symbol"
  local symbol_dir_name="${SYMBOL_TARGET_NAME}"
  local build_type_upper=$(echo "${BUILD_TYPE}" | tr [:lower:] [:upper:])
  local current_time=$(date "+%Y%m%d%H%M%S")
  local symbol_pkg_name="${symbol_dir_name}_${ENV_TYPE}_${build_type_upper}_${current_time}.tgz"
  if [[ ${BUILD_MODE} == "single" ]]; then
    symbol_pkg_name="${symbol_dir_name}_${BUILD_MODE}_${ENV_TYPE}_${build_type_upper}_${current_time}.tgz"
  fi
  local symbol_real_path=${TMP_PKG_PATH}/${symbol_dir_name}

  mkdir -p ${symbol_real_path}
  cp -arf "${CANTIANDB_BIN}"/mysql-server-symbol ${symbol_real_path}
  cp -arf "${CANTIANDB_BIN}"/Cantian-DATABASE-CENTOS-64bit-SYMBOL ${symbol_real_path}

  cd ${TMP_PKG_PATH}
  tar -zcf "${symbol_pkg_name}" ${symbol_dir_name}
  rm -rf ${TMP_PKG_PATH}/${symbol_dir_name}
  echo "Packing ${symbol_pkg_name} success"
}

function newPackageTarget() {
  echo "Start newPackageTarget..."
  local current_time=$(date "+%Y%m%d%H%M%S")
  local pkg_dir_name="${BUILD_TARGET_NAME}"
  local build_type_upper=$(echo "${BUILD_TYPE}" | tr [:lower:] [:upper:])
  local pkg_name="${BUILD_PACK_NAME}_${ENV_TYPE}_${build_type_upper}.tgz"
 
  local mysql_pkg_name="${MYSQL_BIN_NAME}_${ENV_TYPE}_${build_type_upper}.tgz"
  local connector_pkg_name="${CONNECT_BIN_NAME}_${ENV_TYPE}_${build_type_upper}.tgz"

  if [[ ${BUILD_MODE} == "single" ]]; then
    pkg_name="${BUILD_PACK_NAME}_${BUILD_MODE}_${ENV_TYPE}_${build_type_upper}.tgz"
    mysql_pkg_name="${MYSQL_BIN_NAME}_${BUILD_MODE}_${ENV_TYPE}_${build_type_upper}.tgz"
    connector_pkg_name="${CONNECT_BIN_NAME}_${BUILD_MODE}_${ENV_TYPE}_${build_type_upper}.tgz"
  fi
  local pkg_real_path=${TMP_PKG_PATH}/${pkg_dir_name}
  rm -rf ${TMP_PKG_PATH}/*

  mkdir -p ${pkg_real_path}/{action,repo,config,common,zlogicrep}
  mkdir -p ${pkg_real_path}/zlogicrep/build/Cantian_PKG/file

  if [[ ${INTERNAL_BUILD} == "TRUE" ]];then  
    B_VERSION=$(grep -oP '<Bversion>\K[^<]+' "${CTDB_CODE_PATH}"/../ProductComm_DoradoAA/CI/conf/cmc/dbstore/archive_cmc_versions.xml | sed 's/Cantian //g')
    # 提取B_VERSION最后一个点之后的部分
    B_VERSION_SUFFIX="${B_VERSION##*.}"
    echo "B_VERSION_SUFFIX: ${B_VERSION_SUFFIX}"
    if [[ x"${B_VERSION}" != x"" ]];then
        # 替换versions.yml 中的版本号的最后一个点后的部分
        sed -i "s/\(Version: .*\)\.[A-Z].*/\1.${B_VERSION_SUFFIX}/" "${CURRENT_PATH}"/versions.yml
    fi
    sed -i 's#ChangeVersionTime: .*#ChangeVersionTime: '"$(date +%Y/%m/%d\ %H:%M)"'#' "${CURRENT_PATH}"/versions.yml
  fi
  cp -arf "${CURRENT_PATH}"/versions.yml ${pkg_real_path}/
  cp -arf "${CANTIANDB_BIN}"/rpm/RPMS/"${ENV_TYPE}"/cantian*.rpm ${pkg_real_path}/repo/
  cp -arf "${CTDB_CODE_PATH}"/temp/ct_om/rpm/RPMS/"${ENV_TYPE}"/ct_om*.rpm ${pkg_real_path}/repo
  cp -arf "${CTDB_CODE_PATH}"/pkg/deploy/action/* ${pkg_real_path}/action/
  cp -arf "${CTDB_CODE_PATH}"/pkg/deploy/config/* ${pkg_real_path}/config/
  cp -arf "${CTDB_CODE_PATH}"/common/* ${pkg_real_path}/common/
  cp -arf  "${CANTIANDB_BIN}"/connector ${TMP_PKG_PATH}/
  rm -rf "${CANTIANDB_BIN}"/connector
  if [[ ${BUILD_MODE} == "single" ]]; then
    cp -rf  "${CTDB_CODE_PATH}"/pkg/deploy/single_options/* ${pkg_real_path}/action/cantian
  fi
  if [[ ${INTERNAL_BUILD} == "TRUE" ]];then
    cp -rf ${CTDB_CODE_PATH}/pkg/src/zlogicrep/build/Cantian_PKG/file/* ${pkg_real_path}/zlogicrep/build/Cantian_PKG/file/
  fi
  sed -i "s/#MYSQL_PKG_PREFIX_NAME#/${mysql_pkg_name}/g" ${CTDB_CODE_PATH}/CI/script/for_mysql_official/patch.sh
  sed -i "s/## BUILD_TYPE ENV_TYPE ##/${build_type_upper} ${ENV_TYPE}/g" ${CTDB_CODE_PATH}/CI/script/for_mysql_official/patch.sh
  sed -i "s/#CONNECTOR_PKG_PREFIX_NAME#/${connector_pkg_name}/g" ${CTDB_CODE_PATH}/CI/script/for_mysql_official/patch.sh
  cp -arf "${CTDB_CODE_PATH}"/CI/script/for_mysql_official ${pkg_real_path}

  sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE}" ${pkg_real_path}/action/dbstor/check_usr_pwd.sh
  sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE}" ${pkg_real_path}/action/dbstor/check_dbstor_compat.sh
  sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE}" ${pkg_real_path}/action/inspection/inspection_scripts/kernal/check_link_cnt.sh
  echo "Start pkg ${pkg_dir_name}.tgz..."
  cd ${TMP_PKG_PATH}
  tar -zcf "${pkg_name}" ${pkg_dir_name}
  rm -rf ${TMP_PKG_PATH}/${pkg_dir_name}
  echo "Packing ${pkg_name} success"
  mkdir -p ${MYSQL_BIN_NAME}
#  外部编译不生成mysql包，后续对外发布编包需要取消注释
#  cp -arf /usr/local/mysql ${MYSQL_BIN_NAME}
#  echo "Start pkg ${mysql_pkg_name}..."
#  tar -zcf "${mysql_pkg_name}" ${MYSQL_BIN_NAME}
  echo "Start pkg ${connector_pkg_name}..."
  tar -zcf "${connector_pkg_name}" connector
  rm -rf ${MYSQL_BIN_NAME}
  rm -rf ${pkg_dir_name}
  rm -rf ${TMP_PKG_PATH}/connector
   
  echo "Packing ${connector_pkg_name} success"
}

function patchingMysqlCode() {
  cd "${MYSQL_CODE_PATH}"
  # git apply --check mysql-scripts-meta.patch
  # git apply --check mysql-test-meta.patch
  # git apply --check mysql-source-code-meta.patch

  patch --ignore-whitespace -p1 < mysql-scripts-meta.patch
  patch --ignore-whitespace -p1 < mysql-test-meta.patch
  patch --ignore-whitespace -p1 < mysql-source-code-meta.patch
}

function revertPatching() {
  cd "${MYSQL_CODE_PATH}"
  patch -R -p1 < mysql-scripts-meta.patch
  patch -R -p1 < mysql-test-meta.patch
  patch -R -p1 < mysql-source-code-meta.patch
  cd "${CURRENT_PATH}"
}

function collectMysqlTarget() {
  cp "${MYSQL_CODE_PATH}"/cantian_lib/libctc_proxy.so  "${CANTIANDB_BIN}"/connector
  cp "${CANTIANDB_LIBRARY}"/huawei_security/lib/libsecurec.a "${CANTIANDB_BIN}"/cantian-connector-mysql/cantian_lib
  cp "${CANTIANDB_LIBRARY}"/huawei_security/lib/libsecurec.so "${CANTIANDB_BIN}"/cantian-connector-mysql/cantian_lib
  cp "${MYSQL_SERVER_PATH}"/scripts/my.cnf "${CANTIANDB_BIN}"/cantian-connector-mysql/scripts
}

function seperateSymbol() {
  so_path=$1
  sh "${CURRENT_PATH}"/seperate_dbg_symbol.sh ${so_path}
}

function buildMysql() {
  echo "meta version: declare directory and copy mysql code for ha_ctc.so and libctc_proxy.so"
  mkdir -p "${CANTIANDB_BIN}"/cantian-connector-mysql/{cantian_lib,mysql_bin,scripts}
  mkdir -p "${CANTIANDB_BIN}"/cantian-connector-mysql/mysql_bin/mysql/lib/plugin/{meta,nometa}
  mkdir -p "${CANTIANDB_BIN}"/connector
  if [[ ${BUILD_MODE} == "multiple" ]] || [[ -z ${BUILD_MODE} ]]; then
    echo "compile multiple mysql process"
    sh "${CURRENT_PATH}"/Makefile.sh "${MYSQL_BUILD_TYPE}"
  elif [[ ${BUILD_MODE} == "single" ]]; then
    echo "compile single mysql process"
    sh "${CURRENT_PATH}"/Makefile.sh "${MYSQL_BUILD_TYPE} no_shm=1"
  else
    echo "unsupported build mode"
    exit 1
  fi

  cp "${MYSQL_CODE_PATH}"/bld_debug/plugin_output_directory/ha_ctc.so ${CANTIANDB_BIN}/connector/ha_ctc_noshare.so
  echo "patching MysqlCode for mysql source"
  patchingMysqlCode
  if [ $? -ne 0 ]; then
    echo "patching MysqlCode fail."
    exit 1
  fi

  cd "${CURRENT_PATH}"
  if [[ ${BUILD_MODE} == "multiple" ]] || [[ -z ${BUILD_MODE} ]]; then
    echo "compile multiple mysql process"
    sh "${CURRENT_PATH}"/Makefile.sh "${MYSQL_BUILD_TYPE}"
  elif [[ ${BUILD_MODE} == "single" ]]; then
    echo "compile single mysql process"
    sh "${CURRENT_PATH}"/Makefile.sh "${MYSQL_BUILD_TYPE} no_shm=1"
  fi

  revertPatching
  cp "${MYSQL_CODE_PATH}"/bld_debug/plugin_output_directory/ha_ctc.so "${CANTIANDB_BIN}"/connector/ha_ctc_share.so
  collectMysqlTarget
}

function prepare_path() {
  if [[ ${INTERNAL_BUILD} == "TRUE" ]];then
    cd ${WORKSPACE}
    mkdir -p cantian/build_dependence/libaio/include/
    cp libaio.h cantian/build_dependence/libaio/include/
    tar -zxf mysql-server-mysql-8.0.26.tar.gz && mv mysql-server-mysql-8.0.26 ${mysql_dir}/mysql-source
    cp -arf ${mysql_dir}/storage ${mysql_dir}/mysql-source
    cp -arf ${mysql_dir}/mysql-test ${mysql_dir}/mysql-source
    cp -arf ${mysql_dir}/mysql-test/*.patch ${mysql_dir}/mysql-source
    mkdir -p ${WORKSPACE}/3rdPartyPkg
    touch ${WORKSPACE}/3rdPartyPkg/cantian3.0.0.zip
    unzip ${WORKSPACE}/cantian-test-cantian3.0.0.zip -d ${WORKSPACE}/3rdPartyPkg/
    cp ${WORKSPACE}/3rdPartyPkg/cantian-test-cantian3.0.0/* ${WORKSPACE}/3rdPartyPkg/
    cd -
  else
    cp -arf ${MYSQL_SERVER_PATH}/storage ${MYSQL_CODE_PATH}/mysql-source
    cp -arf ${MYSQL_SERVER_PATH}/mysql-test ${MYSQL_CODE_PATH}/mysql-source
    cp -arf ${MYSQL_SERVER_PATH}/mysql-test/*.patch ${MYSQL_CODE_PATH}/mysql-source
    mkdir -p ${MYSQL_CODE_PATH}/3rdPartyPkg
    cd ${MYSQL_CODE_PATH}/3rdPartyPkg
    wget --no-check-certificate https://gitee.com/solid-yang/cantian-test/repository/archive/cantian3.0.0.zip   
    unzip cantian3.0.0.zip
    mv cantian-test-cantian3.0.0/* ./
    rm -rf cantian-test-cantian3.0.0
    tar -zxvf protobuf-c-1.4.1.tar.gz
    mkdir -p ${MYSQL_CODE_PATH}/include/protobuf-c
    cp ${MYSQL_CODE_PATH}/3rdPartyPkg/protobuf-c-1.4.1/protobuf-c/protobuf-c.h ${MYSQL_CODE_PATH}/include/protobuf-c/
    cd -
    rm -rf ${MYSQL_CODE_PATH}/3rdPartyPkg
  fi  
}

function prepare() {
  prepare_path

  if [[ ${BUILD_MODE} == "multiple" ]] || [[ -z ${BUILD_MODE} ]]; then
    echo "compiling multiple process"
    if [[ ${BUILD_TYPE} == "debug" ]]; then
      echo "compiling multiple process debug"
      sh "${CURRENT_PATH}"/Makefile.sh "${CT_BUILD_TYPE} CANTIAN_READ_WRITE=1"
    else
      echo "compiling multiple process release"
      sh "${CURRENT_PATH}"/Makefile.sh "${CT_BUILD_TYPE}"
    fi
  elif [[ ${BUILD_MODE} == "single" ]]; then
    echo "compiling single process"
    if [[ ${BUILD_TYPE} == "debug" ]]; then
      echo "compiling single process debug"
      sh "${CURRENT_PATH}"/Makefile.sh "${CT_BUILD_TYPE} no_shm=1 CANTIAN_READ_WRITE=1"
    else
      echo "compiling single process release"
      sh "${CURRENT_PATH}"/Makefile.sh "${CT_BUILD_TYPE} no_shm=1"
    fi
  else
    echo "unsupported build mode"
    exit 1
  fi
  
  buildMysql
  if [ ! -d "${CTDB_TARGET_PATH}" ];then
    mkdir -p "${CTDB_TARGET_PATH}"
    chmod 700  "${CTDB_TARGET_PATH}"
  fi
  cp -arf "${CTDB_CODE_PATH}"/Cantian-DATABASE* "${CTDB_TARGET_PATH}"/
  cp -arf "${CTDB_CODE_PATH}"/CI/script/for_mysql_official "${CANTIANDB_BIN}"/"${BUILD_TARGET_NAME}"
  cp -arf "${CANTIANDB_BIN}"/cantian-connector-mysql "${CANTIANDB_BIN}"/"${BUILD_TARGET_NAME}"
}

BUILD_TYPE=${1,,}
if [[ ${BUILD_TYPE} != "debug" ]] && [[ ${BUILD_TYPE} != "release" ]]; then
  echo "Usage: ${0##*/} {debug|release}."
  exit 0
fi

CT_BUILD_TYPE="package-${BUILD_TYPE}"
MYSQL_BUILD_TYPE="mysql_${BUILD_TYPE}"

prepare
buildCtOmPackage
packageTarget
newPackageTarget
