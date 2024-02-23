#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
INSTALL_TYPE=$1
CONFIG_FILE=""
FS_CONFIG_FILE=""
PRE_INSTALL_PY_PATH=${CURRENT_PATH}/pre_install.py
FILE_MOD_FILE=${CURRENT_PATH}/file_mod.sh
CONFIG_PATH=${CURRENT_PATH}/../config
ENV_FILE=${CURRENT_PATH}/env.sh
MYSQL_MOUNT_PATH=/opt/cantian/image/cantian_connector/for_mysql_official/mf_connector_mount_dir
UPDATE_CONFIG_FILE_PATH="${CURRENT_PATH}"/update_config.py
DBSTORE_CHECK_FILE=/opt/cantian/dbstor/tools/cs_check_version.sh
config_install_type="override"
pass_check='true'
add_group_user_ceck='true'
mount_nfs_check='true'
auto_create_fs='false'
dbstor_user=''
dbstor_pwd_first=''
unix_sys_pwd_first=''
unix_sys_pwd_second=''
dm_login_pwd=''
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
    FS_CONFIG_FILE=$2
    INSTALL_TYPE='override'
elif [[ ${INSTALL_TYPE} == "override" ]]; then  # 指定override，接收第二个参数为配置文件路径
    CONFIG_FILE=$2
    FS_CONFIG_FILE=$3
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

# 接收第三个参数为文件系统配置文件路径
if [ -f "${FS_CONFIG_FILE}" ];then
    auto_create_fs="true"
fi

function correct_files_mod() {
    for file_path in "${!FILE_MODE_MAP[@]}"; do
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
    if [[ x"${deploy_mode}" != x"nas" ]];then
        read -p "please enter dbstor_user: " dbstor_user
        echo "dbstor_user is: ${dbstor_user}"

        read -s -p "please enter dbstor_pwd: " dbstor_pwd_first
        echo ''
        echo "${dbstor_pwd_first}" | python3 ${CURRENT_PATH}/implement/check_pwd.py
        if [ $? -ne 0 ]; then
            logAndEchoError 'dbstor_pwd not available'
            exit 1
        fi
    fi

    read -s -p "please enter cantian_sys_pwd: " unix_sys_pwd_first
    echo ''
    echo "${unix_sys_pwd_first}" | python3 ${CURRENT_PATH}/implement/check_pwd.py
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
    if [ x"${mes_type}" == x"TCP" ];then
        read -s -p "please enter private key encryption password:" cert_encrypt_pwd
        echo ''
    fi

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
    cantian_sudo="cantian ALL=(root) NOPASSWD:/usr/bin/chrt"
    cat /etc/sudoers | grep ^cantian
    if [[ -n $? ]];then
        sed -i '/^cantian*/d' /etc/sudoers
    fi
    echo "${cantian_sudo}" >> /etc/sudoers
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
    useradd cantian -s /sbin/nologin -G cantiangroup -u 6000
    useradd ctmgruser -s /sbin/nologin -G cantiangroup -u 6004
    # 增加用户到用户组
    usermod -a -G cantiangroup ${deploy_user}
    usermod -a -G ${deploy_group} cantian
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
  grep "${cantian_user} hard nice -20" "${security_limits}"
  if [ $? -ne 0 ];then
    echo "${cantian_user} hard nice -20" >> "${security_limits}"
  fi
  grep "${cantian_user} soft nice -20" "${security_limits}"
  if [ $? -ne 0 ];then
    echo "${cantian_user} soft nice -20" >> "${security_limits}"
  fi
  grep "${cantian_user} soft nice -20" "${security_limits}" && grep "${cantian_user} hard nice -20" "${security_limits}"
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

function rpm_check(){
    local count=2
    if [ x"${deploy_mode}" != x"nas" ];then
      count=3
    fi
    rpm_pkg_count=$(ls "${CURRENT_PATH}"/../repo | wc -l)
    rpm_pkg_info=$(ls -l "${CURRENT_PATH}"/../repo)
    logAndEchoInfo "There are ${rpm_pkg_count} packages in repo dir, which detail is: ${rpm_pkg_info}"
    if [ ${rpm_pkg_count} -ne ${count} ]; then
        logAndEchoError "We have to have only ${count} rpm package,please check"
        exit 1
    fi
}

function copy_certificate() {
    local certificate_dir="/mnt/dbdata/remote/share_${storage_share_fs}/certificates"
    local certificate_dir_node="${certificate_dir}/node${node_id}"
    if [ -d "${certificate_dir_node}" ];then
        rm -rf "${certificate_dir_node}"
    fi
    mkdir -m 700 -p  "${certificate_dir_node}"
    local ca_path
    ca_path=$(python3 "${CURRENT_PATH}"/get_config_info.py "ca_path")
    local crt_path
    crt_path=$(python3 "${CURRENT_PATH}"/get_config_info.py "crt_path")
    local key_path
    key_path=$(python3 "${CURRENT_PATH}"/get_config_info.py "key_path")
    cp -arf "${ca_path}" "${certificate_dir_node}"/ca.crt
    cp -arf "${crt_path}" "${certificate_dir_node}"/mes.crt
    cp -arf "${key_path}" "${certificate_dir_node}"/mes.key
    chmod 600 "${certificate_dir_node}"/*
    chown -hR "${deploy_user}":"${deploy_group}" "${certificate_dir}"
    echo -e "${cert_encrypt_pwd}" | python3 -B "${CURRENT_PATH}"/implement/check_pwd.py "check_cert_pwd"
    if [ $? -ne 0 ];then
        logAndEchoError "Cert file or passwd check failed."
        uninstall
        exit 1
    fi
}

function uninstall() {
    if [[ ${auto_create_fs} == "true" && ${node_id} == "0" ]];then
        echo -e "${dm_login_ip}\n${dm_login_user}\n${dm_login_pwd}" | sh "${CURRENT_PATH}"/uninstall.sh "${config_install_type}" delete_fs
    else
        sh ${CURRENT_PATH}/uninstall.sh ${config_install_type}
    fi
}

function check_deploy_param() {
    if [[ x"${node_id}" == x"0" ]];then
        cp -rf "${CONFIG_PATH}"/deploy_param.json /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/
        chmod 600 /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/deploy_param.json
        chown "${cantian_user}":"${cantian_group}" /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/deploy_param.json
    else
        su -s /bin/bash - "${cantian_user}" -c "python3 -B ${CURRENT_PATH}/implement/check_deploy_param.py"
        if [ $? -ne 0 ];then
            logAndEchoError "Check params failed."
            uninstall
            exit 1
        fi
    fi
}

function install_dbstor(){
    local arrch=$(uname -p)
    local dbstor_path="${CURRENT_PATH}"/../repo
    local dbstor_package_file=$(ls "${dbstor_path}"/DBStor_Client*_"${arrch}"*.tgz)
    if [ ! -f "${dbstor_package_file}" ];then
        logAndEchoError "${dbstor_package_file} is not exist."
        return 1
    fi

    dbstor_file_path=${CURRENT_PATH}/dbstor_file_path
    if [ -d "${dbstor_file_path}" ];then
        rm -rf "${dbstor_file_path}"
    fi
    mkdir -p "${dbstor_file_path}"
    tar -zxf "${dbstor_package_file}" -C "${dbstor_file_path}"

    local dbstor_test_file=$(ls "${dbstor_file_path}"/Dbstor_Client_Test*-"${arrch}"*-dbstor*.tgz)
    local dbstor_client_file=$(ls "${dbstor_file_path}"/dbstor_client*-"${arrch}"*-dbstor*.tgz)
    if [ ! -f "${dbstor_test_file}" ];then
        logAndEchoError "${dbstor_test_file} is not exist."
        return 1
    fi
    if [ ! -f "${dbstor_client_file}" ];then
        logAndEchoError "${dbstor_client_file} is not exist."
        return 1
    fi

    mkdir -p "${dbstor_file_path}"/client
    mkdir -p "${dbstor_file_path}"/client_test
    tar -zxf "${dbstor_test_file}" -C "${dbstor_file_path}"/client_test
    tar -zxf "${dbstor_client_file}" -C "${dbstor_file_path}"/client
    cp -arf "${dbstor_file_path}"/client/lib/* "${RPM_PACK_ORG_PATH}"/Cantian-RUN-CENTOS-64bit/add-ons/
    cp -arf "${dbstor_file_path}"/client_test "${RPM_PACK_ORG_PATH}"/Cantian-RUN-CENTOS-64bit
    rm -rf "${dbstor_file_path}"
    return 0
}

function install_rpm()
{
    RPM_PATH=${CURRENT_PATH}/../repo/cantian-*.rpm
    RPM_UNPACK_PATH_FILE="/opt/cantian/image/cantian_connector/CantianKernel/Cantian-DATABASE-CENTOS-64bit"
    RPM_PACK_ORG_PATH="/opt/cantian/image"

    if [ ! -f  "${CURRENT_PATH}"/../repo/cantian-*.rpm ]; then
        echo "cantian.rpm is not exist."
        exit 1
    fi

    rpm -ivh --replacepkgs ${RPM_PATH} --nodeps --force

    tar -zxf ${RPM_UNPACK_PATH_FILE}/Cantian-RUN-CENTOS-64bit.tar.gz -C ${RPM_PACK_ORG_PATH}
    if [ x"${deploy_mode}" != x"nas" ];then
        install_dbstor
        if [ $? -ne 0 ];then
            sh ${CURRENT_PATH}/uninstall.sh ${config_install_type}
            exit 1
        fi
    fi
    chmod -R 750 ${RPM_PACK_ORG_PATH}/Cantian-RUN-CENTOS-64bit
    chown ${deploy_user}:${deploy_group} -hR ${RPM_PACK_ORG_PATH}/
    chown root:root ${RPM_PACK_ORG_PATH}
}

function show_cantian_version() {
    echo '#!/bin/bash
    set +x
    sn=$(dmidecode -s system-uuid)
    name=$(cat /etc/hostname)
    version=$(cat /opt/cantian/versions.yml | grep -oE "([0-9]+\.[0-9]+\.[0-9]+)" | sed "s/\.$//")
    echo SN                          : ${sn}
    echo System Name                 : ${name}
    echo Product Model               : Cantian
    echo Product Version             : ${version}' > /usr/local/bin/show
    chmod 550 /usr/local/bin/show
}

function check_dbstore_client_compatibility() {
    deploy_mode=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode")
    if [[ x"${deploy_mode}" == x"nas" ]]; then
        return 0
    fi
    logAndEchoInfo "begin to check dbstore client compatibility."
    if [ ! -f "${DBSTORE_CHECK_FILE}" ];then
        logAndEchoError "${DBSTORE_CHECK_FILE} file is not exists."
        uninstall
        exit 1
    fi
    su -s /bin/bash - "${cantian_user}" -c "sh ${DBSTORE_CHECK_FILE}"
    if [[ $? -ne 0 ]];then
        logAndEchoError "dbstore client compatibility check failed."
        uninstall
        exit 1
    fi
    logAndEchoInfo "dbstore client compatibility check success."
}

function update_random_seed() {
    if [[ x"${node_id}" == x"0" ]];then
        random_seed=$(python3 -c 'import secrets; secrets_generator = secrets.SystemRandom(); print(secrets_generator.randint(0, 255))')
    else
        random_seed=$(python3 ${CURRENT_PATH}/get_config_info.py "share_random_seed")
    fi
    python3 ${CURRENT_PATH}/write_config.py "random_seed" "${random_seed}"
}

# 容器内无需检查ntp服务
if [ ! -f /.dockerenv ]; then
    check_ntp_active
fi

python3 ${PRE_INSTALL_PY_PATH} ${INSTALL_TYPE} ${CONFIG_FILE}
if [ $? -ne 0 ]; then
  logAndEchoError "over all pre_install failed. For details, see the /opt/cantian/deploy/om_deploy/om_deploy.log"
  exit 1
fi

# 把生成的deploy_param.json移到config路径下
mv -f ${CURRENT_PATH}/deploy_param.json ${CONFIG_PATH}
python3 ${CURRENT_PATH}/write_config.py "install_type" ${INSTALL_TYPE}

deploy_mode=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode"`
# 公共预安装检查
rpm_check

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
# 单进程场景使用deploy_user
is_single=$(cat "${CURRENT_PATH}"/cantian/options.py | grep -oP 'self\.running_mode = "\K[^"]+')
if [[ x"${is_single}" == x"cantiand_with_mysql_in_cluster" ]];then
    sed -i "s/cantian_user=\"cantian\"/cantian_user=\"${deploy_user}\"/g" "${CURRENT_PATH}"/env.sh
    sed -i "s/cantian_group=\"cantian\"/cantian_group=\"${deploy_group}\"/g" "${CURRENT_PATH}"/env.sh
fi

if [[ x"${deploy_mode}" == x"nas" ]];then
    python3 "${CURRENT_PATH}"/modify_env.py
    if [  $? -ne 0 ];then
        echo "Current deploy mode is ${deploy_mode}, modify env.sh failed."
    fi
fi

source ${CURRENT_PATH}/env.sh

correct_files_mod

# 创建用户用户组
initUserAndGroup


if [ -d /opt/cantian/backup ]; then
    chown -hR ${cantian_user}:${cantian_group} /opt/cantian/backup
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
        chown -hR "${cantian_user}":"${cantian_group}" "${dir_name}"
    fi
done
if [ -d /opt/cantian/mysql ];then
    chown -hR "${deploy_user}":"${deploy_group}" /opt/cantian/mysql
fi


# 修改公共模块文件权限
correct_files_mod
chmod 400 "${CURRENT_PATH}"/../repo/*
chown "${cantian_user}":"${cantian_group}" "${CURRENT_PATH}"/obtains_lsid.py
chown "${cantian_user}":"${cantian_group}" "${CURRENT_PATH}"/implement/update_cantian_passwd.py
chown "${cantian_user}":"${cantian_group}" "${CURRENT_PATH}"/implement/check_deploy_param.py
chown "${cantian_user}":"${cantian_group}" "${CURRENT_PATH}"/update_config.py
chown -hR "${cantian_user}":"${cantian_group}" "${CURRENT_PATH}"/cantian_common


# 预安装各模块，有一个模块失败pass_check设为false
for lib_name in "${PRE_INSTALL_ORDER[@]}"
do
    logAndEchoInfo "pre_install ${lib_name}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    sh ${CURRENT_PATH}/${lib_name}/appctl.sh pre_install ${config_install_type} >> ${OM_DEPLOY_LOG_FILE} 2>&1
    single_result=$?
    if [ ${single_result} -ne 0 ]; then
        logAndEchoError "[error] pre_install ${lib_name} failed"
        logAndEchoError "For details, see the /opt/cantian/${lib_name}/log. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        pass_check='false'
    fi
    logAndEchoInfo "pre_install ${lib_name} result is ${single_result}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
done
chmod 755 /mnt/dbdata/local

# 存在预校验模块失败，卸载
if [[ ${pass_check} = 'false' ]]; then
    logAndEchoError "pre_install failed."
    exit 1
fi

# 获取install_type 如果install_type为override 执行以下操作
mes_type=$(python3 ${CURRENT_PATH}/get_config_info.py "mes_type")
config_install_type=$(python3 ${CURRENT_PATH}/get_config_info.py "install_type")
node_id=$(python3 ${CURRENT_PATH}/get_config_info.py "node_id")
echo "install_type in deploy_param.json is: ${config_install_type}"
if [[ ${config_install_type} = 'override' ]]; then
  # 用户输入密码
  enter_pwd
  if [[ ${auto_create_fs} == "true" && ${node_id} == "0" ]];then
      if [ ! -f "${FS_CONFIG_FILE}" ];then
          logAndEchoError "Auto create fs config file is not exist, please check"
          exit 1
      fi
      read -p "please input DM login ip:" dm_login_ip
      if [[ x"${dm_login_ip}" == x"" ]];then
          logAndEchoError "Enter a correct IP address, not None"
          exit 1
      fi
      echo "please input DM login ip:${dm_login_ip}"

      read -s -p "please input DM login user:" dm_login_user
      if [[ x"${dm_login_user}" == x"" ]];then
          logAndEchoError "Enter a correct user, not None."
          exit 1
      fi
      echo "please input DM login user:${dm_login_user}"

      read -s -p "please input DM login passwd:" dm_login_pwd
      if [[ x"${dm_login_pwd}" == x"" ]];then
          logAndEchoError "Enter a correct passwd, not None."
          exit 1
      fi
      echo ""

      cp ${FS_CONFIG_FILE} ${CONFIG_PATH}/file_system_info.json
      logAndEchoInfo "Auto create fs start"
      echo -e "${dm_login_user}\n${dm_login_pwd}" | python3 -B "${CURRENT_PATH}"/storage_operate/create_file_system.py --action="pre_check" --ip="${dm_login_ip}" >> ${OM_DEPLOY_LOG_FILE} 2>&1
      if [ $? -ne 0 ];then
          logAndEchoError "Auto create fs pre check failed, for details see the /opt/cantian/deploy/om_deploy/rest_request.log"
          exit 1
      fi
      echo -e "${dm_login_user}\n${dm_login_pwd}" | python3 -B "${CURRENT_PATH}"/storage_operate/create_file_system.py --action="create" --ip="${dm_login_ip}" >> ${OM_DEPLOY_LOG_FILE} 2>&1
      if [ $? -ne 0 ];then
          logAndEchoError "Auto create fs failed, for details see the /opt/cantian/deploy/om_deploy/rest_request.log"
          uninstall
          exit 1
      fi
      logAndEchoInfo "Auto create fs success"
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
      chown ${cantian_user}:${cantian_group} /mnt/dbdata/remote/archive_${storage_archive_fs}
  fi
  chown ${cantian_user}:${cantian_group} /mnt/dbdata/remote/share_${storage_share_fs}
  mkdir -m 755 -p /mnt/dbdata/remote/metadata_${storage_metadata_fs}

  chown ${cantian_user}:${cantian_group} /opt/cantian/common/data
  if [ $? -ne 0 ]; then
      logAndEchoError "change /opt/cantian/common/data to ${cantian_user}:${cantian_group} failed"
      uninstall
      exit 1
  else
      logAndEchoInfo "change /opt/cantian/common/data to ${cantian_user}:${cantian_group} sucess"
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

  if [[ x"${deploy_mode}" != x"nas" ]]; then
      kerberos_type=`python3 ${CURRENT_PATH}/get_config_info.py "kerberos_key"`
      mount -t nfs -o sec="${kerberos_type}",timeo=${NFS_TIMEO},nosuid,nodev ${metadata_logic_ip}:/${storage_metadata_fs} /mnt/dbdata/remote/metadata_${storage_metadata_fs}
  else
      mount -t nfs -o timeo=${NFS_TIMEO},nosuid,nodev ${metadata_logic_ip}:/${storage_metadata_fs} /mnt/dbdata/remote/metadata_${storage_metadata_fs}
  fi

  metadata_result=$?
  if [ ${metadata_result} -ne 0 ]; then
      logAndEchoError "mount metadata nfs failed"
  fi
  # 检查36729~36728是否有可用端口
  check_port
  sysctl fs.nfs.nfs_callback_tcpport="${NFS_PORT}" > /dev/null 2>&1
  # 挂载nfs
  if [[ x"${deploy_mode}" == x"dbstore" ]]; then
      mount -t nfs -o sec="${kerberos_type}",vers=4.0,timeo=${NFS_TIMEO},nosuid,nodev ${share_logic_ip}:/${storage_share_fs} /mnt/dbdata/remote/share_${storage_share_fs}
  else
      mount -t nfs -o vers=4.0,timeo=${NFS_TIMEO},nosuid,nodev ${share_logic_ip}:/${storage_share_fs} /mnt/dbdata/remote/share_${storage_share_fs}
  fi
  share_result=$?
  if [ ${share_result} -ne 0 ]; then
      logAndEchoError "mount share nfs failed"
  fi
  chown -hR "${cantian_user}":"${cantian_group}" /mnt/dbdata/remote/share_${storage_share_fs} > /dev/null 2>&1
  checkMountNFS ${share_result}
  if [[ ${storage_archive_fs} != '' ]]; then
      if [[ x"${deploy_mode}" != x"nas" ]]; then
          mount -t nfs -o sec="${kerberos_type}",timeo=${NFS_TIMEO},nosuid,nodev ${archive_logic_ip}:/${storage_archive_fs} /mnt/dbdata/remote/archive_${storage_archive_fs}
      else
          mount -t nfs -o timeo=${NFS_TIMEO},nosuid,nodev ${archive_logic_ip}:/${storage_archive_fs} /mnt/dbdata/remote/archive_${storage_archive_fs}
      fi

      archive_result=$?
      if [ ${archive_result} -ne 0 ]; then
          logAndEchoError "mount archive nfs failed"
      fi
      checkMountNFS ${archive_result}
      chmod 750 /mnt/dbdata/remote/archive_${storage_archive_fs}
      chown -hR "${cantian_user}":"${deploy_group}" /mnt/dbdata/remote/archive_${storage_archive_fs} > /dev/null 2>&1
      # 修改备份nfs路径属主属组
  fi
  checkMountNFS ${metadata_result}

  if [[ x"${deploy_mode}" == x"nas" ]]; then
      storage_dbstore_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_dbstore_fs"`
      storage_logic_ip=`python3 ${CURRENT_PATH}/get_config_info.py "storage_logic_ip"`
      mkdir -m 750 -p /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"
      chown "${cantian_user}":"${cantian_user}" /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"
      mount -t nfs -o timeo=${NFS_TIMEO},nosuid,nodev "${storage_logic_ip}":/"${storage_dbstore_fs}" /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"
      checkMountNFS $?
      chown "${cantian_user}":"${cantian_user}" /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"
      mkdir -m 750 -p /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"/data
      mkdir -m 750 -p /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"/share_data
      chown ${cantian_user}:${cantian_user} /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"/data
      chown ${cantian_user}:${cantian_user} /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"/share_data
  fi

  # 检查nfs是否都挂载成功
  if [[ ${mount_nfs_check} != 'true' ]]; then
      logAndEchoInfo "mount nfs failed"
      uninstall
      exit 1
  fi
  remoteInfo=`ls -l /mnt/dbdata/remote`
  logAndEchoInfo "/mnt/dbdata/remote detail is: ${remoteInfo}"
  # 目录权限最小化
  chmod 750 /mnt/dbdata/remote/share_${storage_share_fs}
  chmod 755 /mnt/dbdata/remote/metadata_${storage_metadata_fs}
  node_id=$(python3 ${CURRENT_PATH}/get_config_info.py "node_id")
  if [ -d /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node${node_id} ];then
      rm -rf /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node${node_id}
  fi
  mkdir -m 770 -p /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node${node_id}
  chown ${deploy_user}:${cantian_common_group} /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node${node_id}
  update_random_seed
  # 挂载后，0节点拷贝配置文件至文件系统下，1节点检查对应配置文件参数
  check_deploy_param
  if [[ x"${mes_type}" == x"TCP" ]];then
      copy_certificate
  fi
fi

# 修改ks权限和存放ks的目录的权限
chmod 700 /opt/cantian/common/config
chown -hR "${cantian_user}":"${cantian_group}" /opt/cantian/common/config
chown -hR "${cantian_user}":"${cantian_group}" /mnt/dbdata/remote/share_${storage_share_fs} > /dev/null 2>&1
chown -hR "${cantian_user}":"${deploy_group}" /mnt/dbdata/remote/archive_${storage_archive_fs} > /dev/null 2>&1
# 修改日志定期清理执行脚本权限
chown -h "${cantian_user}":"${cantian_group}" ${CURRENT_PATH}/../common/script/logs_handler/do_compress_and_archive.py

cp -fp ${CURRENT_PATH}/../config/cantian.service /etc/systemd/system/
cp -fp ${CURRENT_PATH}/../config/cantian.timer /etc/systemd/system/
cp -fp ${CURRENT_PATH}/../config/cantian_logs_handler.service /etc/systemd/system/
cp -fp ${CURRENT_PATH}/../config/cantian_logs_handler.timer /etc/systemd/system/

cp -fp ${CURRENT_PATH}/* /opt/cantian/action > /dev/null 2>&1
cp -rfp ${CURRENT_PATH}/inspection /opt/cantian/action
cp -rfp ${CURRENT_PATH}/implement /opt/cantian/action
cp -rfp ${CURRENT_PATH}/cantian_common /opt/cantian/action
cp -rfp ${CURRENT_PATH}/logic /opt/cantian/action
cp -rfp ${CURRENT_PATH}/storage_operate /opt/cantian/action
cp -rfp ${CURRENT_PATH}/utils /opt/cantian/action
cp -rfp ${CURRENT_PATH}/../config /opt/cantian/
cp -rfp ${CURRENT_PATH}/../common /opt/cantian/
cp -rfp ${CURRENT_PATH}/wsr_report /opt/cantian/action
cp -rfp ${CURRENT_PATH}/dbstor /opt/cantian/action

# 适配开源场景，使用file，不使用dbstore，提前安装参天rpm包
install_rpm

# 调用各模块安装脚本，如果有模块安装失败直接退出，不继续安装接下来的模块
logAndEchoInfo "Begin to install. [Line:${LINENO}, File:${SCRIPT_NAME}]"
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
            uninstall
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
                uninstall
                exit 1
            fi
        fi
    else
        sh ${CURRENT_PATH}/${lib_name}/appctl.sh install >> ${OM_DEPLOY_LOG_FILE} 2>&1
        install_result=$?
        logAndEchoInfo "install ${lib_name} result is ${install_result}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        if [ ${install_result} -ne 0 ]; then
            logAndEchoError "${lib_name} install failed"
            logAndEchoError "For details, see the /opt/cantian/${lib_name}/log. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            uninstall
            exit 1
        fi
    fi
done

# 把升级备份相关路径拷贝到/opt/cantian
cp -rfp ${CURRENT_PATH}/../repo /opt/cantian/
cp -rfp ${CURRENT_PATH}/../versions.yml /opt/cantian/

config_security_limits > /dev/null 2>&1

# 增UUID至参天、cms、dostore配置文件
system_uuid=$(dmidecode -s system-uuid)
su -s /bin/bash - "${cantian_user}" -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=dbstore --action=add --key=SYSTEM_UUID --value=${system_uuid}"

# 等各模块安装好后检查dbstor的user与pwd是否正确
if [[ x"${deploy_mode}" != x"nas" ]];then
    logAndEchoInfo "check username and password of dbstor. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    su -s /bin/bash - "${cantian_user}" -c "sh ${CURRENT_PATH}/dbstor/check_usr_pwd.sh"
    install_result=$?
    if [ ${install_result} -ne 0 ]; then
        logAndEchoError "check dbstor passwd failed, possible reasons:
            1 username or password of dbstor storage service is incorrect.
            2 cgw create link failed.
            3 ip address of dbstor storage service is incorrect.
            please contact the engineer to solve. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        uninstall
        exit 1
    else
        logAndEchoInfo "user and password of dbstor check pass. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    fi
fi
# 检查dbstore client 与server端是否兼容
check_dbstore_client_compatibility

# 修改/home/regress/action目录下cantian, cantian_exporter, cms, dbstor, mysql权限，防止复写造成提权
for module in "${INSTALL_ORDER[@]}"
do
    chown -h root:root ${CURRENT_PATH}/${module}
    chmod 755 ${CURRENT_PATH}/${module}
    chown -h root:root /opt/cantian/action/${module}
    chmod 755 /opt/cantian/action/${module}
done

# 解决mysql容器巡检，把巡检相关移动到挂载路径
cp -rfp ${CURRENT_PATH}/inspection ${MYSQL_MOUNT_PATH}

# 修改巡检相关脚本为deploy_user
chown -hR ${cantian_user}:${cantian_group} /opt/cantian/action/inspection
show_cantian_version
logAndEchoInfo "install success"
exit 0