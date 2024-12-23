#!/bin/bash
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))
MYSQL_LOG_PATH=/opt/cantian/log/mysql
CANTIAN_HACTC_DIR=/opt/cantian/cantian

MYSQL_INSTALL_SH_DIR=$(dirname "$(realpath "${BASH_SOURCE[0]}")")
echo "MYSQL_INSTALL_SH_DIR: ${MYSQL_INSTALL_SH_DIR}"

MYSQL_PKG_DIR=$(realpath "${MYSQL_INSTALL_SH_DIR}/../../../")
echo "MYSQL_PKG_DIR: ${MYSQL_PKG_DIR}"

source "${CURRENT_PATH}"/../env.sh

deploy_user=`python3 ${CURRENT_PATH}/../get_config_info.py "deploy_user"`
deploy_group=`python3 ${CURRENT_PATH}/../get_config_info.py "deploy_group"`
MF_CONNECTOR_ROOT=/opt/cantian/image/cantian_connector
MF_CONNECTOR_MOUNT_DIR=${MF_CONNECTOR_ROOT}/for_mysql_official/mf_connector_mount_dir
MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR=/opt/cantian/mysql/install
backup_dir=$1

function install_ctc() {
    # 回归场景不需要拷贝ctc
    if [[ -d "${backup_dir}" ]];then
        back_version=`cat ${backup_dir}/versions.yml | grep 'Version:' | awk -F ":" '{print $2}' | sed -r 's/[a-z]*[A-Z]*0*([0-9])/\1/' | sed 's/ //g'`
        if [[ "${back_version}" < "24.12.B032" ]];then
            if [[ -L ${CANTIAN_HACTC_DIR}/server/lib/ha_ctc.so ]];then
                rm -rf ${CANTIAN_HACTC_DIR}/server/lib/ha_ctc.so
            fi
            if [[ -f ${CANTIAN_HACTC_DIR}/server/lib/libctc_proxy.so ]];then
                rm -rf ${CANTIAN_HACTC_DIR}/server/lib/libctc_proxy.so
            fi
            if [[ -f "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/mysql/lib/libctc_proxy.so ]];then
                rm -rf "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/mysql/lib/libctc_proxy.so
            fi
            if [[ -f "${MF_CONNECTOR_MOUNT_DIR}"/plugin/ha_ctc.so ]];then
                rm -rf "${MF_CONNECTOR_MOUNT_DIR}"/plugin/ha_ctc.so
            fi
            if [[ -f "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/mysql/lib/plugin/ha_ctc.so ]];then
                rm -rf "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/mysql/lib/plugin/ha_ctc.so
            fi
        fi
        return
    fi
    set +e
    META_DATA_SWITCH_OFF=`cat /opt/cantian/config/deploy_param.json | grep mysql_metadata_in_cantian | grep false`
    set -e
    if [ "${META_DATA_SWITCH_OFF}" == "" ]; then
      echo "/opt/cantian/config/deploy_param.json mysql_metadata_in_cantian: TRUE"
      MYSQL_METADATA_IN_CANTIAN="TRUE"
    else
      echo "/opt/cantian/config/deploy_param.json mysql_metadata_in_cantian: FALSE"
      MYSQL_METADATA_IN_CANTIAN="FALSE"
    fi

    CONNECTOR_PKG_PREFIX_NAME=`cat ${MYSQL_PKG_DIR}/cantian_connector/for_mysql_official/patch.sh | grep CONNECTOR_PKG_PREFIX_NAME= | grep -oP "\".*\"" | tr -d '"' `
    CONNECTOR_DATA_PKG="${MYSQL_PKG_DIR}/${CONNECTOR_PKG_PREFIX_NAME}"
    tar -zxf ${CONNECTOR_DATA_PKG} -C ${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}/

    LINK_MOUNT_HACTC_NAME="${MF_CONNECTOR_MOUNT_DIR}"/plugin/ha_ctc.so
    LINK_PHYSIC_HACTC_NAME="${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/mysql/lib/plugin/ha_ctc.so
    if [ -f "${LINK_MOUNT_HACTC_NAME}" ]; then
        # 如果存在MOUNT ha_ctc.so，删除 ha_ctc.so
        rm -rf "${LINK_MOUNT_HACTC_NAME}"
        echo "Deleted existing ${LINK_MOUNT_HACTC_NAME}"
    fi
    if [ -f "${LINK_PHYSIC_HACTC_NAME}" ]; then
        # 如果存在PHYSIC ha_ctc.so，删除 ha_ctc.so
        rm -rf "${LINK_PHYSIC_HACTC_NAME}"
        echo "Deleted existing ${LINK_PHYSIC_HACTC_NAME}"
    fi

    if [ -f ${CANTIAN_HACTC_DIR}/server/lib/ha_ctc.so ]; then
        # 如果存在PHYSIC ha_ctc.so，删除 ha_ctc.so
        rm -rf ${CANTIAN_HACTC_DIR}/server/lib/ha_ctc.so
        echo "Deleted existing ${CANTIAN_HACTC_DIR}/server/lib/ha_ctc.so"
    fi
    cp -arf "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/connector/libctc_proxy.so "${CANTIAN_HACTC_DIR}"/server/lib/
    cp -arf "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/connector/libctc_proxy.so "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/mysql/lib

    if [ "$MYSQL_METADATA_IN_CANTIAN" = "TRUE" ]; then
      echo "copy meta ha_ctc_share.so to ${MF_CONNECTOR_MOUNT_DIR}/plugin"
      cp -arf "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/connector/ha_ctc_share.so "${MF_CONNECTOR_MOUNT_DIR}"/plugin/ha_ctc.so
      mkdir -p "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/mysql/lib/plugin
      cp -arf "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/connector/ha_ctc_share.so "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/mysql/lib/plugin
      ln -s "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/mysql/lib/plugin/ha_ctc_share.so "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/mysql/lib/plugin/ha_ctc.so
      cp -arf "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/connector/ha_ctc_share.so ${CANTIAN_HACTC_DIR}/server/lib
      ln -s ${CANTIAN_HACTC_DIR}/server/lib/ha_ctc_share.so ${CANTIAN_HACTC_DIR}/server/lib/ha_ctc.so
    else
      echo "copy nometa ha_ctc_noshare.so to ${MF_CONNECTOR_MOUNT_DIR}/plugin"
      cp -arf "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/connector/ha_ctc_noshare.so "${MF_CONNECTOR_MOUNT_DIR}"/plugin/ha_ctc.so
      mkdir -p "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/mysql/lib/plugin
      cp -arf "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/connector/ha_ctc_noshare.so "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/mysql/lib/plugin
      ln -s "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/mysql/lib/plugin/ha_ctc_noshare.so "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/mysql/lib/plugin/ha_ctc.so
      cp -arf "${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}"/connector/ha_ctc_noshare.so ${CANTIAN_HACTC_DIR}/server/lib
      ln -s ${CANTIAN_HACTC_DIR}/server/lib/ha_ctc_noshare.so ${CANTIAN_HACTC_DIR}/server/lib/ha_ctc.so
    fi
    rm -rf  ${MF_CONNECTOR_PHYSIC_INSTALL_MYSQL_DIR}/connector
}
su -s /bin/bash - "${deploy_user}" -c "sh -x ${MF_CONNECTOR_ROOT}/for_mysql_official/patch.sh > ${MYSQL_LOG_PATH}/install.log 2>&1"

if [ $? -ne 0 ]; then
    echo "Failed to execute /opt/cantian/image/cantian_connector/for_mysql_official/patch.sh."
    exit 1
fi

install_ctc

cp -arf /opt/cantian/image/cantian_connector/for_mysql_official/mf_connector_mount_dir/ /opt/cantian/mysql/server/
if [ $? -ne 0 ]; then
    echo "Failed to copy file from /opt/cantian/image/cantian_connector/for_mysql_official/mf_connector_mount_dir/ to /opt/cantian/mysql/server/"
    exit 1
fi
chown ${cantian_user}:${cantian_group} -hR ${CANTIAN_HACTC_DIR}/