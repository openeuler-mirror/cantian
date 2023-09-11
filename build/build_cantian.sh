#!/bin/bash

set -e

CURRENT_PATH=$(dirname $(readlink -f $0))
CI_TOP_DIR="${CURRENT_PATH}"/../
BUILD_TARGET_NAME="cantian_connector"
BUILD_PACK_NAME="Cantian_Database_Storage_Engine_2.0.0"
ENV_TYPE=$(uname -p)
TMP_PKG_PATH=/tmp/cantian_new
CTDB_TARGET_PATH=${CURRENT_PATH}/${BUILD_TARGET_NAME}/CantianKernel

source ${CURRENT_PATH}/common.sh

bash Makefile.sh package

if [ ! -d "${CTDB_TARGET_PATH}" ];then
    mkdir -p "${CTDB_TARGET_PATH}"
    chmod 700  "${CTDB_TARGET_PATH}"
fi
cp -arf "${CURRENT_PATH}"/../Cantian-DATABASE* "${CTDB_TARGET_PATH}"/Cantian-DATABASE-${OS_SUFFIX}-64bit

function packageTarget() {
  echo "Start packageTarget..."
  tar -zcf cantian.tar.gz ${BUILD_TARGET_NAME}/
  if [ -d /opt/cantian/image ]; then
    rm -rf /opt/cantian/image
  fi
  mkdir -p /opt/cantian/image
  mv -f cantian.tar.gz /opt/cantian/image/
  bash ${CURRENT_PATH}/rpm_build_cantian.sh
  cd -
}

function buildCtOmPackage() {
  bash ${CURRENT_PATH}/build_ct_om.sh
  bash ${CURRENT_PATH}/rpm_build_ct_om.sh
  if [ $? -ne 0 ]; then
      echo "build ct_om fail"
      retrun 1
  fi
}

function newPackageTarget() {
  echo "Start newPackageTarget..."
  local current_time=$(date "+%Y%m%d%H%M%S")
  local pkg_dir_name="${BUILD_TARGET_NAME}"
  local pkg_name="${BUILD_PACK_NAME}_${ENV_TYPE}.tgz"
 local pkg_real_path=${TMP_PKG_PATH}/${pkg_dir_name}
  if [ -d ${pkg_real_path} ]; then
    rm -rf ${pkg_real_path}
  fi
  mkdir -p ${pkg_real_path}/action
  mkdir -p ${pkg_real_path}/repo
  mkdir -p ${pkg_real_path}/config
  mkdir -p ${pkg_real_path}/common
  cp -arf "${CURRENT_PATH}"/versions.yml ${pkg_real_path}/
  cp -f ${CURRENT_PATH}/rpm/RPMS/${ENV_TYPE}/cantian*.rpm ${pkg_real_path}/repo/
  cp -f ${CURRENT_PATH}/../temp/ct_om/rpm/RPMS/${ENV_TYPE}/ct_om*.rpm ${pkg_real_path}/repo
  cp -rf ${CURRENT_PATH}/../pkg/deploy/action/* ${pkg_real_path}/action/
  cp -rf ${CURRENT_PATH}/../pkg/deploy/config/* ${pkg_real_path}/config/
  cp -rf ${CURRENT_PATH}/../common/* ${pkg_real_path}/common/
  echo "Start pkg ${pkg_dir_name}.tgz..."
  cd ${TMP_PKG_PATH}
  tar -zcf ${pkg_name} ${pkg_dir_name}
  echo "Packing ${pkg_name} success"
}

buildCtOmPackage
packageTarget
newPackageTarget