#!/bin/bash
set -eo pipefail
shopt -s nullglob

MYSQL_OFFICIAL_DIR=$(dirname "$(realpath "${BASH_SOURCE[0]}")")
echo "MYSQL_OFFICIAL_DIR: ${MYSQL_OFFICIAL_DIR}"

MF_CONNECTOR_ROOT=$(realpath "${MYSQL_OFFICIAL_DIR}/../")
echo "MF_CONNECTOR_ROOT: ${MF_CONNECTOR_ROOT}"

MF_CONNECTOR_MOUNT_DIR=${MYSQL_OFFICIAL_DIR}/mf_connector_mount_dir
echo "MF_CONNECTOR_MOUNT_DIR: ${MF_CONNECTOR_MOUNT_DIR}"

MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR=${MF_CONNECTOR_ROOT}/../../mysql/install
echo "MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR" ${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}

PROJECT_TYPE="## BUILD_TYPE ENV_TYPE ##" # this text will be replaced by build.sh pipeline
MYSQL_PKG_PREFIX_NAME="#MYSQL_PKG_PREFIX_NAME#" # this text will be replaced by build.sh pipeline
CONNECTOR_PKG_PREFIX_NAME="#CONNECTOR_PKG_PREFIX_NAME#"

if [ -d "${MF_CONNECTOR_MOUNT_DIR}" ]; then
  rm -rf "${MF_CONNECTOR_MOUNT_DIR}"
fi
mkdir -p "${MF_CONNECTOR_MOUNT_DIR}"

rm -rf "${MF_CONNECTOR_MOUNT_DIR}"/mf_connector_init.sh
cp -arf "${MYSQL_OFFICIAL_DIR}"/docker/mf_connector_init.sh "${MF_CONNECTOR_MOUNT_DIR}"/

rm -rf "${MF_CONNECTOR_MOUNT_DIR}"/cantian_lib
mkdir "${MF_CONNECTOR_MOUNT_DIR}"/cantian_lib
cp -arf "${MF_CONNECTOR_ROOT}"/cantian-connector-mysql/cantian_lib/* "${MF_CONNECTOR_MOUNT_DIR}"/cantian_lib
cp -arf "${MYSQL_OFFICIAL_DIR}"/docker/internals/install_cantian_lib.sh "${MF_CONNECTOR_MOUNT_DIR}"/cantian_lib

# install_mysql.sh still used this dir
rm -rf "${MF_CONNECTOR_MOUNT_DIR}"/mysql_lib
mkdir "${MF_CONNECTOR_MOUNT_DIR}"/mysql_lib

rm -rf "${MF_CONNECTOR_MOUNT_DIR}"/plugin
mkdir "${MF_CONNECTOR_MOUNT_DIR}"/plugin

cp -arf "${MYSQL_OFFICIAL_DIR}"/docker/internals/install_mf_connector_plugin.sh "${MF_CONNECTOR_MOUNT_DIR}"/plugin

mkdir -p "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/mysql/lib/plugin

chmod a+rx -R "${MF_CONNECTOR_MOUNT_DIR}"
chmod a+rx -R "${MYSQL_OFFICIAL_DIR}"/docker/*.sh
echo "patch mf_connector_pkg has done"