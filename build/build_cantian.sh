#!/bin/bash

set -e

CURRENT_PATH=$(dirname $(readlink -f $0))
CTDB_CODE_PATH="${CURRENT_PATH}"/..
MYSQL_SERVER_PATH="${CTDB_CODE_PATH}"/../mysql-server
BUILD_TARGET_NAME="cantian_connector"
BUILD_PACK_NAME="Cantian_Database_Storage_Engine_3.0.0"
ENV_TYPE=$(uname -p)
TMP_PKG_PATH=/tmp/cantian_output
CTDB_TARGET_PATH=${CURRENT_PATH}/${BUILD_TARGET_NAME}/CantianKernel
MYSQL_CODE_PATH=${MYSQL_SERVER_PATH}/mysql-source

source "${CURRENT_PATH}"/common.sh

function packageTarget() {
  echo "Start packageTarget..."
  tar -zcf cantian.tar.gz ${BUILD_TARGET_NAME}/
  if [ -d /opt/cantian/image ]; then
    rm -rf /opt/cantian/image
  fi
  mkdir -p /opt/cantian/image
  mv -f cantian.tar.gz /opt/cantian/image/
  bash "${CURRENT_PATH}"/rpm_build_cantian.sh
  cd -
}

function buildCtOmPackage() {
  bash "${CURRENT_PATH}"/build_ct_om.sh
  bash "${CURRENT_PATH}"/rpm_build_ct_om.sh
  if [ $? -ne 0 ]; then
      echo "build ct_om fail"
      retrun 1
  fi
}

function newPackageTarget() {
  echo "Start newPackageTarget..."
  local current_time=$(date "+%Y%m%d%H%M%S")
  local pkg_dir_name="${BUILD_TARGET_NAME}"
  local build_type_upper=$(echo "${BUILD_TYPE}" | tr [:lower:] [:upper:])
  local pkg_name="${BUILD_PACK_NAME}_${ENV_TYPE}_${build_type_upper}.tgz"
  local pkg_real_path=${TMP_PKG_PATH}/${pkg_dir_name}
  rm -rf ${TMP_PKG_PATH}/*

  mkdir -p ${pkg_real_path}/{action,repo,config,common,zlogicrep}

  cp -arf "${CURRENT_PATH}"/versions.yml ${pkg_real_path}/
  cp -arf "${CURRENT_PATH}"/rpm/RPMS/"${ENV_TYPE}"/cantian*.rpm ${pkg_real_path}/repo/
  cp -arf "${CTDB_CODE_PATH}"/temp/ct_om/rpm/RPMS/"${ENV_TYPE}"/ct_om*.rpm ${pkg_real_path}/repo
  cp -arf "${CTDB_CODE_PATH}"/pkg/deploy/action/* ${pkg_real_path}/action/
  cp -arf "${CTDB_CODE_PATH}"/pkg/deploy/config/* ${pkg_real_path}/config/
  cp -arf "${CTDB_CODE_PATH}"/common/* ${pkg_real_path}/common/
  cp -arf "${CTDB_CODE_PATH}"/CI/script/for_mysql_official ${pkg_real_path}

  sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE}" ${pkg_real_path}/action/dbstor/check_usr_pwd.sh
  sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE}" ${pkg_real_path}/action/inspection/inspection_scripts/kernal/check_link_cnt.sh

  echo "Start pkg ${pkg_dir_name}.tgz..."
  cd ${TMP_PKG_PATH}
  tar -zcf "${pkg_name}" ${pkg_dir_name}
  echo "Packing ${pkg_name} success"
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
  cp "${MYSQL_CODE_PATH}"/daac_lib/libctc_proxy.so  "${CURRENT_PATH}"/mysql-server/daac_lib
  cp "${CANTIANDB_LIBRARY}"/huawei_security/lib/libsecurec.a "${CURRENT_PATH}"/mysql-server/daac_lib
  cp "${CANTIANDB_LIBRARY}"/huawei_security/lib/libsecurec.so "${CURRENT_PATH}"/mysql-server/daac_lib
}

function buildMysql() {
  echo "meta version: declare directory and copy mysql code for ha_ctc.so and libctc_proxy.so"
  mkdir -p "${CURRENT_PATH}"/mysql-server/{daac_lib,mysql_bin,scripts}
  mkdir -p "${CURRENT_PATH}"/mysql-server/mysql_bin/mysql/lib/plugin/{meta,nometa}

  sh "${CURRENT_PATH}"/Makefile.sh "${MYSQL_BUILD_TYPE}"
  cp "${MYSQL_CODE_PATH}"/bld_debug/plugin_output_directory/ha_ctc.so "${CURRENT_PATH}"/mysql-server/mysql_bin/mysql/lib/plugin/nometa

  echo "patching MysqlCode for mysql source"
  patchingMysqlCode
  if [ $? -ne 0 ]; then
    echo "patching MysqlCode fail."
    exit 1
  fi

  cd "${CURRENT_PATH}"
  sh "${CURRENT_PATH}"/Makefile.sh "${MYSQL_BUILD_TYPE}"
  revertPatching
  cp "${MYSQL_CODE_PATH}"/bld_debug/plugin_output_directory/ha_ctc.so "${CURRENT_PATH}"/mysql-server/mysql_bin/mysql/lib/plugin/meta
  collectMysqlTarget
}

function prepare() {
  sh "${CURRENT_PATH}"/Makefile.sh "${CT_BUILD_TYPE}"
  buildMysql
  if [ ! -d "${CTDB_TARGET_PATH}" ];then
    mkdir -p "${CTDB_TARGET_PATH}"
    chmod 700  "${CTDB_TARGET_PATH}"
  fi
  cp -arf "${CTDB_CODE_PATH}"/Cantian-DATABASE* "${CTDB_TARGET_PATH}"/
  cp -arf "${CTDB_CODE_PATH}"/CI/script/for_mysql_official "${CURRENT_PATH}"/"${BUILD_TARGET_NAME}"
  cp -arf "${CURRENT_PATH}"/mysql-server "${CURRENT_PATH}"/"${BUILD_TARGET_NAME}"
}

BUILD_TYPE=$1
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