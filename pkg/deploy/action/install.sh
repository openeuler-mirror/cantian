#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
INSTALL_TYPE=$1
PRE_INSTALL_PY_PATH=${CURRENT_PATH}/pre_install.py
FILE_MOD_FILE=${CURRENT_PATH}/file_mod.sh
CONFIG_PATH=${CURRENT_PATH}/../config
ENV_FILE=${CURRENT_PATH}/env.sh
MYSQL_MOUNT_PATH=/opt/cantian/image/cantian_connector/for_mysql_official/mf_connector_mount_dir
config_install_type="override"
pass_check='true'
add_group_user_ceck='true'
mount_nfs_check='true'
dbstor_user=''
dbstor_pwd_first=''
unix_sys_pwd_first=''
unix_sys_pwd_second=''
cert_encrypt_pwd=''
storage_share_fs=''
storage_archive_fs=''
storage_metadata_fs=''
deploy_mode=''
deploy_user=''
deploy_group=''
NFS_TIMEO=50

source ${CURRENT_PATH}/log4sh.sh
source ${FILE_MOD_FILE}

# 适配欧拉系统，nologin用户没有执行ping命令的权限
chmod u+s /bin/ping

if [ -f ${INSTALL_TYPE} ]; then  # 默认override，接收第一个参数文件为配置文件路径
    CONFIG_FILE=${INSTALL_TYPE}
    INSTALL_TYPE='override'
elif [[ ${INSTALL_TYPE} == "override" ]]; then  # 指定override，接收第二个参数为配置文件路径
    CONFIG_FILE=$2
    if [ ! -f ${CONFIG_FILE} ]; then
        logAndEchoError "file: ${CONFIG_FILE} not exist"
        exit 1
    fi
elif [[ ${INSTALL_TYPE} == "reserve" ]]; then  # 指定reserve，无配置文件路径接收
    CONFIG_FILE=""
    cp /opt/cantian/config/deploy_param.json ${CURRENT_PATH}
else  # 参数输入格式有误
    logAndEchoError "input params error"
    exit 1
fi

function correct_files_mod() {
    for file_path in ${!FILE_R_MODE_MAP[@]}; do
        if [ ! -e ${file_path} ]; then
            continue
        fi

        chmod -R ${FILE_R_MODE_MAP[$file_path]} $file_path
        if [ $? -ne 0 ]; then
            logAndEchoError "chmod -R ${FILE_R_MODE_MAP[$file_path]} ${file_path} failed"
            exit 1
        fi
    done

    for file_path in ${!FILE_MODE_MAP[@]}; do
        if [ ! -e ${file_path} ]; then
            continue
        fi

        chmod ${FILE_MODE_MAP[$file_path]} $file_path
        if [ $? -ne 0 ]; then
            logAndEchoError "chmod ${FILE_MODE_MAP[$file_path]} ${file_path} failed"
            exit 1
        fi
    done
}

# 获取用户输入用户名密码
function enter_pwd()
{
    if [[ x"${deploy_mode}" == x"--dbstore" ]];then
        read -p "please enter dbstor_user: " dbstor_user
        echo "dbstor_user is: ${dbstor_user}"

        read -s -p "please enter dbstor_pwd: " dbstor_pwd_first
        echo ''
        echo "${dbstor_pwd_first}" | python3 ${CURRENT_PATH}/check_pwd.py
        if [ $? -ne 0 ]; then
            logAndEchoError 'dbstor_pwd not available'
            exit 1
        fi
    fi

    read -s -p "please enter cantian_sys_pwd: " unix_sys_pwd_first
    echo ''
    echo "${unix_sys_pwd_first}" | python3 ${CURRENT_PATH}/check_pwd.py
    if [ $? -ne 0 ]; then
        logAndEchoError 'cantian_sys_pwd not available'
        exit 1
    fi

    read -s -p "please enter cantian_sys_pwd again: " unix_sys_pwd_second
    echo ''
    if [[ ${unix_sys_pwd_first} != ${unix_sys_pwd_second} ]]; then
        logAndEchoError "two cantian_sys_pwd are different"
        exit 1
    fi

    read -s -p "please enter private key encryption password:" cert_encrypt_pwd
    echo ''
}

# 检查用户用户组是否创建成功
function checkGroupUserAdd() {
    check_item=$1
    if [[ ${check_item} != '0' ]]; then
        add_group_user_ceck='fales'
    fi
}

# 检查NFS是否挂载成功
function checkMountNFS() {
    check_item=$1
    if [[ ${check_item} != '0' ]]; then
        mount_nfs_check='fales'
    fi
}

# 配置ctmgruser sudo权限
function config_sudo() {
    local chmod_script="/opt/cantian/action/change_log_priority.sh"
    ctmgruser_sudo="ctmgruser ALL=(root) NOPASSWD:${chmod_script}"
    cat /etc/sudoers | grep ctmgruser
    if [[ -n $? ]];then
        sed -i '/ctmgruser*/d' /etc/sudoers
    fi
    echo "${ctmgruser_sudo}" >> /etc/sudoers
}

# 创建用户用户组
function initUserAndGroup()
{
    # 创建用户组
    groupadd cantiangroup -g 1100
    checkGroupUserAdd $?
    groupadd cantianmgrgroup -g 1101
    checkGroupUserAdd $?
    useradd ctmgruser -s /sbin/nologin -G cantiangroup,cantianmgrgroup,${deploy_group} -u 6004
    checkGroupUserAdd $?
    # 增加用户到用户组
    usermod -a -G cantiangroup ${deploy_user}
    config_sudo
}

# 检查ntp服务示范开启
function check_ntp_active() {
    ntp_status=`systemctl is-active chronyd`
    logAndEchoInfo "ntp status is: ${ntp_status}"
    if [[ ${ntp_status} != "active" ]]; then
        echo "ntp service is inactive, please active it before install"
        logAndEchoError "ntp service is inactive"
        exit 1
    fi
}

# 根据性能要求配置/etc/security/limits.conf，进程内线程优先级提升开关
function config_security_limits() {
  local security_limits=/etc/security/limits.conf
  grep "\* soft memlock unlimited" "${security_limits}"
  if [ $? -ne 0 ];then
    echo "* soft memlock unlimited" >> "${security_limits}"
  fi
  grep "\* hard memlock unlimited" "${security_limits}"
  if [ $? -ne 0 ];then
    echo "* hard memlock unlimited" >> "${security_limits}"
  fi
  grep "${deploy_user} hard nice -20" "${security_limits}"
  if [ $? -ne 0 ];then
    echo "${deploy_user} hard nice -20" >> "${security_limits}"
  fi
  grep "${deploy_user} soft nice -20" "${security_limits}"
  if [ $? -ne 0 ];then
    echo "${deploy_user} soft nice -20" >> "${security_limits}"
  fi
  grep "${deploy_user} soft nice -20" "${security_limits}" && grep "${deploy_user} hard nice -20" "${security_limits}" && grep "\* hard memlock unlimited" "${security_limits}" && grep "\* soft memlock unlimited" "${security_limits}"
  if [ $? -ne 0 ];then
    logAndEchoInfo "config security limits failed"
    exit 1
  fi
  logAndEchoInfo "config security limits success"
}


function check_port() {
  # nfs4.0协议挂载固定监听端口，不指定端口该监听会随机指定端口不符合安全要求。指定前检查若该端口被非nfs进程占用则报错
  # 端口范围36729~36738: 起始端口36729， 通过循环每次递增1，检查端口是否被暂用，如果10个端口都被暂用，报错退出；
  #                     检测到有未被占用端口，退出循环，使用当前未被占用端口进行文件系统挂载
  for ((i=0; i<10; i++))
  do
    local port=$(("${NFS_PORT}" + "${i}"))
    listen_port=$(netstat -tunpl 2>/dev/null | grep "${port}" | awk '{print $4}' | awk -F':' '{print $NF}')
    occupied_proc_name=$(netstat -tunpl 2>/dev/null | grep "${port}" | awk '{print $7}' | awk 'NR==1 { print }')
    if [[ -n "${listen_port}" && ${occupied_proc_name} != "-" ]];then
      logAndEchoError "Port ${port} has been temporarily used by a non-nfs process"
      continue
    else
      logAndEchoInfo "Port[${port}] is available"
      NFS_PORT=${port}
      return
    fi
  done
  logAndEchoError "Port 36729~36738 has been temporarily used by a non-nfs process, please modify env.sh file in the current path, Change the value of NFS_PORT to an unused port"
  sh "${CURRENT_PATH}"/uninstall.sh ${config_install_type}
  exit 1
}

function install_rpm()
{
    RPM_PATH=${CURRENT_PATH}/../repo/cantian-*.rpm
    RPM_UNPACK_PATH_FILE="/opt/cantian/image/cantian_connector/CantianKernel/Cantian-DATABASE-CENTOS-64bit/Cantian-DATABASE-CENTOS-64bit"
    RPM_PACK_ORG_PATH="/opt/cantian/image"

    if [ ! -f  "${CURRENT_PATH}"/../repo/cantian-*.rpm ]; then
        echo " cantian.rpm is not exist."
        exit 1
    fi

    rpm -ivh --replacepkgs ${RPM_PATH} --nodeps --force

    tar -zxf ${RPM_UNPACK_PATH_FILE}/Cantian-RUN-CENTOS-64bit.tar.gz -C ${RPM_PACK_ORG_PATH}
    if [ x"${deploy_mode}" == x"--dbstore" ];then
        install_dbstore
        if [ $? -ne 0 ];then
            sh ${CURRENT_PATH}/uninstall.sh ${config_install_type}
            exit 1
        fi
    fi
    chown ${deploy_user} -hR ${RPM_PACK_ORG_PATH}
    chown root:root ${RPM_PACK_ORG_PATH}
}

function install_dbstore(){
    local arrch=$(uname -p)
    local dbstore_path="${CURRENT_PATH}"/../repo
    local dbtore_test_file=$(ls "${dbstore_path}"/Dbstore_Client_Test*-"${arrch}"-product-dbstore.tgz)
    local dbtore_client_file=$(ls "${dbstore_path}"/dbstore_client-*-"${arrch}"-product-dbstore.tgz)
    if [ ! -f ${dbtore_test_file} ];then
        logAndEchoError "${dbtore_test_file} is not exist."
        return 1
    fi
    if [ ! -f ${dbtore_client_file} ];then
        logAndEchoError "${dbtore_client_file} is not exist."
        return 1
    fi
    dbstore_file_path=${CURRENT_PATH}/dbstore_file_path
    if [ -d "${dbstore_file_path}" ];then
        rm -rf "${dbstore_file_path}"
    fi
    mkdir -p "${dbstore_file_path}"
    mkdir -p "${dbstore_file_path}"/client
    mkdir -p "${dbstore_file_path}"/client_test
    tar -zxf "${dbtore_test_file}" -C "${dbstore_file_path}"/client_test
    tar -zxf "${dbtore_client_file}" -C "${dbstore_file_path}"/client
    cp -arf "${dbstore_file_path}"/client/lib/* "${RPM_PACK_ORG_PATH}"/Cantian-RUN-CENTOS-64bit/add-ons/
    cp -arf "${dbstore_file_path}"/client_test "${RPM_PACK_ORG_PATH}"/Cantian-RUN-CENTOS-64bit
    rm -rf "${dbstore_file_path}"
    return 0
}

function copy_cert_files() {
    local target_path=/opt/cantian/certificate
    local ca_path
    ca_path=$(python3 "${CURRENT_PATH}"/get_config_info.py "ca_path")
    local crt_path
    crt_path=$(python3 "${CURRENT_PATH}"/get_config_info.py "crt_path")
    local key_path
    key_path=$(python3 "${CURRENT_PATH}"/get_config_info.py "key_path")
    mkdir -m 750 -p "${target_path}"
    cp -arf "${ca_path}" "${target_path}"/ca.crt
    cp -arf "${crt_path}" "${target_path}"/mes.crt
    cp -arf "${key_path}" "${target_path}"/mes.key
    chmod 600 "${target_path}"/*
    chown -hR "${deploy_user}":"${deploy_group}" "${target_path}"
    echo -e "${cert_encrypt_pwd}" | python3 -B "${CURRENT_PATH}"/check_pwd.py "check_cert_pwd"
    if [ $? -ne 0 ];then
        logAndEchoError "Cert file or passwd check failed."
        exit 1
    fi
    cert_encrypt_pwd=$(echo -n "${cert_encrypt_pwd}" | openssl base64)
}

check_ntp_active

# 公共预安装检查
python3 ${PRE_INSTALL_PY_PATH} ${INSTALL_TYPE} ${CONFIG_FILE}
if [ $? -ne 0 ]; then
  logAndEchoError "over all pre_install failed. For details, see the /opt/cantian/deploy/om_deploy/om_deploy.log"
  exit 1
fi

# 把生成的deploy_param.json移到config路径下
mv -f ${CURRENT_PATH}/deploy_param.json ${CONFIG_PATH}
python3 ${CURRENT_PATH}/write_config.py "install_type" ${INSTALL_TYPE}

# 获取deploy_user和deploy_group，输入文档中的deploy_user关键字
deploy_user=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_user"`
exit_deploy_user_name=`ls /home | grep "^${deploy_user}$"`
if [[ ${exit_deploy_user_name} = '' ]]; then
    logAndEchoError "deploy_user ${deploy_user} not exist"
    exit 1
fi

deploy_group=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_group"`
less /etc/group | grep "^${deploy_group}:"
if [ $? -ne 0 ]; then
    logAndEchoError "deploy_group ${deploy_group} not exist"
    exit 1
fi

if [ -d /opt/cantian/backup ]; then
    chown -hR ${deploy_user}:${deploy_group} /opt/cantian/backup
    if [ $? -eq 0 ]; then
        logAndEchoInfo "changed /opt/cantian/backup owner success"
    else
        logAndEchoInfo "changed /opt/cantian/backup owner failed"
        exit 1
    fi
fi

# 提前创建/opt/cantian/action路径，方便各模块pre_install的时候移动模块代码到该路径下
config_install_type=`python3 ${CURRENT_PATH}/get_config_info.py "install_type"`
if [[ ${config_install_type} = 'override' ]]; then
    mkdir -p /opt/cantian/action
fi

deploy_mode=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode"`
if [[ x"${deploy_mode}" == x"--nas" ]];then
    python3 "${CURRENT_PATH}"/modify_env.py
    if [  $? -ne 0 ];then
        echo "Current deploy mode is ${deploy_mode}, modify env.sh failed."
    fi
fi

source ${CURRENT_PATH}/env.sh

chmod 755 /opt/cantian/action
chmod 755 /opt/cantian/
if [ $? -eq 0 ]; then
    logAndEchoInfo "changed /opt/cantian/action mod success"
else
    logAndEchoInfo "changed /opt/cantian/action mod failed"
    exit 1
fi

# 替mysql创建此目录，以避免/opt/cantian、/opt/cantian/action目录权限设置为777触及安全问题
mkdir -p /opt/cantian/mysql/server/
chmod 750 /opt/cantian/mysql/server/
chown -hR "${deploy_user}":"${deploy_group}" /opt/cantian/mysql/server/
logAndEchoInfo "create '/opt/cantian/mysql/server/' for mysql success"

# 去root后安装卸载，如果卸载前未去root权限需要修改各模块残留配置权限
for dir_name in "${DIR_LIST[@]}"
do
    if [ -d "${dir_name}" ];then
        chown -hR "${deploy_user}":"${deploy_group}" "${dir_name}"
    fi
done

# 修改公共模块文件权限
correct_files_mod
chmod 400 "${CURRENT_PATH}"/../repo/*
chown "${deploy_user}":"${deploy_group}" "${CURRENT_PATH}"/obtains_lsid.py
# 预安装各模块，有一个模块失败pass_check设为false
for lib_name in "${PRE_INSTALL_ORDER[@]}"
do
    logAndEchoInfo "pre_install ${lib_name}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    sh ${CURRENT_PATH}/${lib_name}/appctl.sh pre_install >> ${OM_DEPLOY_LOG_FILE} 2>&1
    single_result=$?
    if [ ${single_result} -ne 0 ]; then
        logAndEchoError "[error] pre_install ${lib_name} failed"
        logAndEchoError "For details, see the /opt/cantian/${lib_name}/log. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        pass_check='false'
    fi
    logAndEchoInfo "pre_install ${lib_name} result is ${single_result}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
done

# 存在预校验模块失败，退出
if [[ ${pass_check} = 'false' ]]; then
    logAndEchoError "pre_install failed."
    exit 1
fi

# 获取install_type 如果install_type为override 执行以下操作
config_install_type=`python3 ${CURRENT_PATH}/get_config_info.py "install_type"`
echo "install_type in deploy_param.json is: ${config_install_type}"
if [[ ${config_install_type} = 'override' ]]; then
  # 用户输入密码
  enter_pwd

  # 拷贝证书
  copy_cert_files

  # 创建用户用户组
  initUserAndGroup

  # 检查用户用户组是否都创建成功
  if [[ ${add_group_user_ceck} != 'true' ]]; then
      logAndEchoError "add user or group failed"
      sh ${CURRENT_PATH}/uninstall.sh ${config_install_type}
      exit 1
  fi

  # 获取要创建路径的路径名
  storage_share_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_share_fs"`
  storage_archive_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_archive_fs"`
  storage_metadata_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_metadata_fs"`

  # 创建公共路径
  mkdir -m 755 -p /opt/cantian/logs
  mkdir -m 755 -p /opt/cantian/image
  mkdir -m 750 -p /opt/cantian/common/data
  mkdir -m 755 -p /opt/cantian/common/socket
  mkdir -m 755 -p /opt/cantian/common/config # 秘钥配置文件
  mkdir -m 750 -p /mnt/dbdata/remote/share_${storage_share_fs}
  mkdir -m 755 -p /mnt/dbdata/local
  chmod 755 /mnt/dbdata /mnt/dbdata/remote /mnt/dbdata/local
  if [[ ${storage_archive_fs} != '' ]]; then
      mkdir -m 750 -p /mnt/dbdata/remote/archive_${storage_archive_fs}
      chown ${deploy_user}:${deploy_group} /mnt/dbdata/remote/archive_${storage_archive_fs}
  fi
  chown ${deploy_user}:${deploy_group} /mnt/dbdata/remote/share_${storage_share_fs}
  mkdir -m 755 -p /mnt/dbdata/remote/metadata_${storage_metadata_fs}

  chown ${deploy_user}:${deploy_group} /opt/cantian/common/data
  if [ $? -ne 0 ]; then
      logAndEchoError "change /opt/cantian/common/data to ${deploy_user}:${deploy_group} failed"
      sh ${CURRENT_PATH}/uninstall.sh ${config_install_type}
      exit 1
  else
      logAndEchoInfo "change /opt/cantian/common/data to ${deploy_user}:${deploy_group} success"
  fi

  # 创建dbstor需要的key
  if [ ! -f /opt/cantian/common/config/primary_keystore.ks ]; then
      touch /opt/cantian/common/config/primary_keystore.ks
      chmod 600 /opt/cantian/common/config/primary_keystore.ks
  fi

  if [ ! -f /opt/cantian/common/config/standby_keystore.ks ]; then
      touch /opt/cantian/common/config/standby_keystore.ks
      chmod 600 /opt/cantian/common/config/standby_keystore.ks
  fi

  # 获取nfs挂载的ip
  share_logic_ip=`python3 ${CURRENT_PATH}/get_config_info.py "share_logic_ip"`

  if [[ ${storage_archive_fs} != '' ]]; then
      archive_logic_ip=`python3 ${CURRENT_PATH}/get_config_info.py "archive_logic_ip"`
      if [[ ${archive_logic_ip} = '' ]]; then
          logAndEchoInfo "please check archive_logic_ip"
      fi
  fi
  metadata_logic_ip=`python3 ${CURRENT_PATH}/get_config_info.py "metadata_logic_ip"`

  kerberos_type=`python3 ${CURRENT_PATH}/get_config_info.py "kerberos_key"`
  mount -t nfs -o sec="${kerberos_type}",timeo=${NFS_TIMEO},nosuid,nodev ${metadata_logic_ip}:/${storage_metadata_fs} /mnt/dbdata/remote/metadata_${storage_metadata_fs}
  metadata_result=$?
  if [ ${metadata_result} -ne 0 ]; then
      logAndEchoError "mount matedata nfs failed"
  fi
  # 检查36729~36728是否有可用端口
  check_port
  sysctl fs.nfs.nfs_callback_tcpport="${NFS_PORT}" > /dev/null 2>&1
  # 挂载nfs
  mount -t nfs -o sec="${kerberos_type}",vers=4.0,timeo=${NFS_TIMEO},nosuid,nodev ${share_logic_ip}:/${storage_share_fs} /mnt/dbdata/remote/share_${storage_share_fs}
  share_result=$?
  if [ ${share_result} -ne 0 ]; then
      logAndEchoError "mount share nfs failed"
  fi
  checkMountNFS ${share_result}
  if [[ ${storage_archive_fs} != '' ]]; then
      mount -t nfs -o sec="${kerberos_type}",timeo=${NFS_TIMEO},nosuid,nodev ${archive_logic_ip}:/${storage_archive_fs} /mnt/dbdata/remote/archive_${storage_archive_fs}
      archive_result=$?
      if [ ${archive_result} -ne 0 ]; then
          logAndEchoError "mount archive nfs failed"
      fi
      checkMountNFS ${archive_result}
      chmod 750 /mnt/dbdata/remote/archive_${storage_archive_fs}
      # 修改备份nfs路径属主属组
      chown ${deploy_user}:${deploy_group} /mnt/dbdata/remote/archive_${storage_archive_fs} > /dev/null 2>&1
  fi
  checkMountNFS ${metadata_result}

  if [[ x"${deploy_mode}" == x"--nas" ]];then
      storage_dbstore_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_dbstore_fs"`
      storage_logic_ip=`python3 ${CURRENT_PATH}/get_config_info.py "storage_logic_ip"`
      mkdir -m 750 -p /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"
      chown "${deploy_user}":"${deploy_group}" /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"
      mount -t nfs -o sec="${kerberos_type}",timeo=${NFS_TIMEO},nosuid,nodev "${storage_logic_ip}":/"${storage_dbstore_fs}" /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"
      checkMountNFS $?
      chown "${deploy_user}":"${deploy_group}" /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"
      mkdir -m 750 -p /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"/data
      mkdir -m 750 -p /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"/share_data
      chown ${deploy_user}:${deploy_group} /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"/data
      chown ${deploy_user}:${deploy_group} /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"/share_data
  fi
  # 检查nfs是否都挂载成功
  if [[ ${mount_nfs_check} != 'true' ]]; then
      logAndEchoInfo "mount nfs failed"
      sh ${CURRENT_PATH}/uninstall.sh ${config_install_type}
      exit 1
  fi
  remoteInfo=`ls -l /mnt/dbdata/remote`
  logAndEchoInfo "/mnt/dbdata/remote detial is: ${remoteInfo}"
  # 目录权限最小化
  chmod 750 /mnt/dbdata/remote/share_${storage_share_fs}
  chmod 755 /mnt/dbdata/remote/metadata_${storage_metadata_fs}
  node_id=$(python3 ${CURRENT_PATH}/get_config_info.py "node_id")
  if [ -d /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node${node_id} ];then
      rm -rf /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node${node_id}
  fi
  mkdir -m 750 -p /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node${node_id}
  chown ${deploy_user}:${deploy_group} /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node${node_id}
fi

# 修改ks权限和存放ks的目录的权限
chown -hR "${deploy_user}":"${deploy_group}" /opt/cantian/common/config
chmod 700 /opt/cantian/common/config
# 修改日志定期清理执行脚本权限
chown -h "${deploy_user}":"${deploy_group}" ${CURRENT_PATH}/../common/script/logs_handler/do_compress_and_archive.py

cp -fp ${CURRENT_PATH}/../config/cantian.service /etc/systemd/system/
cp -fp ${CURRENT_PATH}/../config/cantian.timer /etc/systemd/system/
cp -fp ${CURRENT_PATH}/../config/cantian_logs_handler.service /etc/systemd/system/
cp -fp ${CURRENT_PATH}/../config/cantian_logs_handler.timer /etc/systemd/system/

cp -fp ${CURRENT_PATH}/* /opt/cantian/action > /dev/null 2>&1
cp -rfp ${CURRENT_PATH}/inspection /opt/cantian/action
cp -rfp ${CURRENT_PATH}/dbstor /opt/cantian/action
cp -rfp ${CURRENT_PATH}/../config /opt/cantian/
cp -rfp ${CURRENT_PATH}/../common /opt/cantian/


# 调用各模块安装脚本，如果有模块安装失败直接退出，不继续安装接下来的模块
logAndEchoInfo "Begin to install. [Line:${LINENO}, File:${SCRIPT_NAME}]"
# 适配开源场景，使用nas，不使用dbstore，提前安装参天rpm包

install_rpm

for lib_name in "${INSTALL_ORDER[@]}"
do
    logAndEchoInfo "install ${lib_name}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    if [[ ${lib_name} = 'cantian' ]]; then
        echo -e "${unix_sys_pwd_first}\n${cert_encrypt_pwd}" | sh ${CURRENT_PATH}/${lib_name}/appctl.sh install >> ${OM_DEPLOY_LOG_FILE} 2>&1
        install_result=$?
        logAndEchoInfo "install ${lib_name} result is ${install_result}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        if [ ${install_result} -ne 0 ]; then
            logAndEchoError "cantian install failed."
            logAndEchoError "For details, see the /opt/cantian/${lib_name}/log. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            sh ${CURRENT_PATH}/uninstall.sh ${config_install_type}
            exit 1
        fi
    elif [[ ${lib_name} = 'dbstor' ]]; then
        echo -e "${dbstor_user}\n${dbstor_pwd_first}" | sh ${CURRENT_PATH}/${lib_name}/appctl.sh install >> ${OM_DEPLOY_LOG_FILE} 2>&1
        install_result=$?
        logAndEchoInfo "install ${lib_name} result is ${install_result}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        if [ ${install_result} -ne 0 ]; then
            if [ ${install_result} -eq 2 ]; then
                logAndEchoWarn "Failed to ping some remote ip, for details, see the /opt/cantian/${lib_name}/log."
            else
                logAndEchoError "dbstor install failed"
                logAndEchoError "For details, see the /opt/cantian/${lib_name}/log. [Line:${LINENO}, File:${SCRIPT_NAME}]"
                sh ${CURRENT_PATH}/uninstall.sh ${config_install_type}
                exit 1
            fi
        fi
    else
         echo -e "${cert_encrypt_pwd}" |sh ${CURRENT_PATH}/${lib_name}/appctl.sh install >> ${OM_DEPLOY_LOG_FILE} 2>&1
        install_result=$?
        logAndEchoInfo "install ${lib_name} result is ${install_result}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        if [ ${install_result} -ne 0 ]; then
            logAndEchoError "${lib_name} install failed"
            logAndEchoError "For details, see the /opt/cantian/${lib_name}/log. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            sh ${CURRENT_PATH}/uninstall.sh ${config_install_type}
            exit 1
        fi
    fi
done

# 把升级备份相关路径拷贝到/opt/cantian
cp -rfp ${CURRENT_PATH}/../repo /opt/cantian/
cp -fp ${CURRENT_PATH}/../versions.yml /opt/cantian/

config_security_limits

# 等各模块安装好后检查dbstor的user与pwd是否正确
if [[ x"${deploy_mode}" != x"--nas" ]];then
    logAndEchoInfo "check username and password of dbstor. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    su -s /bin/bash "${deploy_user}" -c "sh ${CURRENT_PATH}/dbstor/check_usr_pwd.sh"
    install_result=$?
    if [ ${install_result} -ne 0 ]; then
        logAndEchoError "check failed, possible reasons:
            1 username or password of dbstor storage service is incorrect.
            2 cgw create link failed.
            3 ip address of dbstor storage service is incorrect.
            please contact the engineer to solve. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        sh ${CURRENT_PATH}/uninstall.sh ${config_install_type}
        exit 1
    else
        logAndEchoInfo "user and password of dbstor check pass. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    fi
fi

# 修改/home/regress/action目录下cantian, cantian_exporter, cms, dbstor, mysql权限，防止复写造成提权
for module in "${INSTALL_ORDER[@]}"
do
    chown -h root:root ${CURRENT_PATH}/${module}
    chmod 755 ${CURRENT_PATH}/${module}
    chown -h root:root /opt/cantian/action/${module}
    chmod 755 /opt/cantian/action/${module}
done


# 修改巡检相关脚本为deploy_user
chown -hR ${deploy_user}:${deploy_group} /opt/cantian/action/inspection


logAndEchoInfo "install success"
exit 0