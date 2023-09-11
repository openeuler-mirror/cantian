#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
uninstall_type=$1
force_type=$2
source ${CURRENT_PATH}/env.sh
source ${CURRENT_PATH}/log4sh.sh

deploy_user=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_user"`

# 获取已创建路径的路径名
storage_share_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_share_fs"`
storage_archive_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_archive_fs"`
storage_metadata_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_metadata_fs"`
storage_dbstore_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_dbstore_fs"`
node_id=$(python3 ${CURRENT_PATH}/get_config_info.py "node_id")
deploy_mode=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode"`

# 根据性能要求配置/etc/security/limits.conf，进程内线程优先级提升开关
function clear_security_limits() {
  local security_limits=/etc/security/limits.conf
  grep "${deploy_user} hard nice -20" "${security_limits}"
  if [ $? -eq 0 ];then
    sed -i "/${deploy_user} hard nice -20/ d"  "${security_limits}"
  fi
  grep "${deploy_user} soft nice -20" "${security_limits}"
  if [ $? -eq 0 ];then
    sed -i "/${deploy_user} soft nice -20/ d" "${security_limits}"
  fi
  grep "${deploy_user} hard nice -20" "${security_limits}" || grep "${deploy_user} soft nice -20" "${security_limits}"
  if [ $? -eq 0 ];then
    logAndEchoInfo "clear security limits failed"
    exit 1
  fi
  logAndEchoInfo "clear security limits success"
}

function uninstall_rpm()
{
    RPM_PACK_ORG_PATH="/opt/cantian/image/Cantian-RUN-CENTOS-64bit"
    result=`rpm -qa cantian | wc -l`
    if [ ${result} -ne 0 ]; then
        rpm -ev cantian --nodeps
    fi

    if [ -d ${RPM_PACK_ORG_PATH} ]; then
        rm -rf ${RPM_PACK_ORG_PATH}
    fi
}

# 检查输入项是否为override或者reserve
if [[ ${uninstall_type} != 'override' && ${uninstall_type} != 'reserve' ]]; then
    logAndEchoInfo "uninstall_type must be override or reserve"
    exit 1
fi

if [ ! -f ${CURRENT_PATH}/../config/deploy_param.json ]; then
    logAndEchoInfo "Cantian id not install, uninstall success."
    exit 0
fi

python3 ${CURRENT_PATH}/write_config.py "uninstall_type" ${uninstall_type}

logAndEchoInfo "uninstall begin"

clear_security_limits

logAndEchoInfo "Begin to uninstall. [Line:${LINENO}, File:${SCRIPT_NAME}]"
for lib_name in "${UNINSTALL_ORDER[@]}"
do
    logAndEchoInfo "uninstall ${lib_name} . [Line:${LINENO}, File:${SCRIPT_NAME}]"
    if [[ ${uninstall_type} == 'override' && ${force_type} == 'force' ]]; then
        sh ${CURRENT_PATH}/${lib_name}/appctl.sh uninstall ${uninstall_type} ${force_type} >> ${OM_DEPLOY_LOG_FILE} 2>&1
        if [ $? -eq 0 ]; then
            logAndEchoInfo "force uninstall ${lib_name} result is success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        else
            logAndEchoError "force uninstall ${lib_name} result is failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            logAndEchoError "For details, see the /opt/cantian/${lib_name}/log. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi
    else
        sh ${CURRENT_PATH}/${lib_name}/appctl.sh uninstall ${uninstall_type} >> ${OM_DEPLOY_LOG_FILE} 2>&1
        if [ $? -eq 0 ]; then
            logAndEchoInfo "uninstall ${lib_name} result is success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        else
            logAndEchoError "uninstall ${lib_name} result is failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            logAndEchoError "For details, see the /opt/cantian/${lib_name}/log. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi
    fi
done

uninstall_rpm

# 如果uninstall_type为override 执行以下操作
echo "uninstall_type is: ${uninstall_type}"
if [[ ${uninstall_type} = 'override' ]]; then
  sysctl fs.nfs.nfs_callback_tcpport=0
  # 取消nfs挂载
  umount -f -l /mnt/dbdata/remote/share_${storage_share_fs}
  if [[ ${storage_archive_fs} != '' ]]; then
      umount -f -l /mnt/dbdata/remote/archive_${storage_archive_fs}
  fi
  umount -f -l /mnt/dbdata/remote/metadata_${storage_metadata_fs}
  # 取消nfs挂载
  if [[ -d /mnt/dbdata/remote/storage_"${storage_dbstore_fs}" ]] && [[ ${node_id} == "0" ]];then
      rm -rf /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"/* > /dev/null 2>&1
  fi
  if [[ x"${deploy_mode}" == x"--nas" ]];then
      umount -f -l /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"
  fi
  # 删除创建的公共目录（挂载目录）
  rm -rf /opt/cantian/common/data
  rm -rf /opt/cantian/common/socket
  rm -rf /opt/cantian/common/config
  rm -rf /mnt/dbdata/remote/share_${storage_share_fs}
  if [[ ${storage_archive_fs} != '' ]]; then
      rm -rf /mnt/dbdata/remote/archive_${storage_archive_fs}
  fi
  rm -rf /mnt/dbdata/remote/metadata_${storage_metadata_fs}
  rm -rf /mnt/dbdata/remote/storage_${storage_dbstore_fs}

  # 删除已创建用户
  if id -u cantian > /dev/null 2>&1; then
      userdel -rf cantian
      if [ $? -eq 0 ]; then
          logAndEchoInfo "remove user cantian success"
      else
          logAndEchoError "remove user cantian failed"
          exit 1
      fi
  fi

  if id -u cantainduser > /dev/null 2>&1; then
      userdel -rf cantainduser
      if [ $? -eq 0 ]; then
          logAndEchoInfo "remove user cantainduser success"
      else
          logAndEchoError "remove user cantainduser failed"
          exit 1
      fi
  fi

  if id -u cmsuser > /dev/null 2>&1; then
      userdel -rf cmsuser
      if [ $? -eq 0 ]; then
          logAndEchoInfo "remove user cmsuser success"
      else
          logAndEchoError "remove user cmsuser failed"
          exit 1
      fi
  fi

  if id -u ctmgruser > /dev/null 2>&1; then
      userdel -rf ctmgruser
      if [ $? -eq 0 ]; then
          logAndEchoInfo "remove user ctmgruser success"
      else
          logAndEchoError "remove user ctmgruser failed"
          exit 1
      fi
  fi

  if id -u ctcliuser > /dev/null 2>&1; then
      userdel -rf ctcliuser
      if [ $? -eq 0 ]; then
          logAndEchoInfo "remove user ctcliuser success"
      else
          logAndEchoError "remove user ctcliuser failed"
          exit 1
      fi
  fi

  # 从用户组移除用户
  groups ${deploy_user} | grep "^cantiangroup$"
  if [ $? -eq 0 ]; then
      gpasswd -d ${deploy_user} cantiangroup > /dev/null 2>&1
      if [ $? -eq 0 ]; then
          logAndEchoInfo "remove user ${deploy_user} from cantiangroup success"
      else
          logAndEchoError "remove user ${deploy_user} from cantiangroup failed"
          exit 1
      fi
  fi

  # 删除用户组
  less /etc/group | grep "^cantiangroup:" > /dev/null 2>&1
  if [ $? -eq 0 ]; then
      groupdel -f cantiangroup
      if [ $? -eq 0 ]; then
          logAndEchoInfo "remove group cantiangroup success"
      else
          logAndEchoError "remove group cantiangroup failed"
          exit 1
      fi
  fi

  less /etc/group | grep "^cantianmgrgroup:" > /dev/null 2>&1
  if [ $? -eq 0 ]; then
      groupdel -f cantianmgrgroup
      if [ $? -eq 0 ]; then
          logAndEchoInfo "remove group cantianmgrgroup success"
      else
          logAndEchoError "remove group cantianmgrgroup failed"
          exit 1
      fi
  fi

  less /etc/group | grep "^cantianctdgroup:" > /dev/null 2>&1
  if [ $? -eq 0 ]; then
      groupdel -f cantianctdgroup
      if [ $? -eq 0 ]; then
          logAndEchoInfo "remove group cantianctdgroup success"
      else
          logAndEchoError "remove group cantianctdgroup failed"
          exit 1
      fi
  fi

  less /etc/group | grep "^cantiancmsgroup:" > /dev/null 2>&1
  if [ $? -eq 0 ]; then
      groupdel -f cantiancmsgroup
      if [ $? -eq 0 ]; then
          logAndEchoInfo "remove group cantiancmsgroup success"
      else
          logAndEchoError "remove group cantiancmsgroup failed"
          exit 1
      fi
  fi

  rm -f /etc/systemd/system/cantian.timer /etc/systemd/system/cantian.service
  rm -f /etc/systemd/system/cantian_logs_handler.timer /etc/systemd/system/cantian_logs_handler.service
  rm -rf /opt/cantian/image /opt/cantian/action /opt/cantian/config

fi

logAndEchoInfo "uninstall finished"
exit 0
