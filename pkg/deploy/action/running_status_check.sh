#!/bin/bash

online_list=()


logAndEchoInfo "check cantian status."
cms_info=$(ps -ef | grep cms | grep server | grep start | grep -v grep)
if [[ -n ${cms_info} ]]; then
    logAndEchoInfo "cms process info:\n ${cms_info}"
    online_list[${#online_list[*]}]="cms"
fi

# 单进程场景使用deploy_user
is_single=$(cat "${CURRENT_PATH}"/cantian/options.py | grep -oP 'self\.running_mode = "\K[^"]+')
if [[ x"${is_single}" == x"cantiand_with_mysql_in_cluster" ]];then
    mysqld_info=$(ps -ef | grep /opt/cantian/mysql/install/mysql/bin/mysqld | grep -v grep)
    if [[ -n ${mysqld_info} ]];then
        logAndEchoInfo "mysqld process info:\n ${mysqld_info}"
        online_list[${#online_list[*]}]="mysqld"
    fi
else
    pidof cantiand > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        cantiand_info=$(ps -ef | grep cantiand | grep /mnt/dbdata/local/cantian/tmp/data | grep -v grep)
        logAndEchoInfo "cantiand process info:\n ${cantiand_info}"
        online_list[${#online_list[*]}]="cantiand"
    fi
fi

ctmgr_info=$(ps -ef | grep "python3 /opt/cantian/ct_om/service/ctmgr/uds_server.py" | grep -v grep)
if [[ -n ${ctmgr_info} ]]; then
    logAndEchoInfo "ctmgr process info:\n ${ctmgr_info}"
    online_list[${#online_list[*]}]="ctmgr"
fi

cantian_exporter_info=$(ps -ef | grep "python3 /opt/cantian/ct_om/service/cantian_exporter/exporter/execute.py" | grep -v grep)
if [[ -n ${cantian_exporter_info} ]]; then
    logAndEchoInfo "cantian_exporter process info:\n ${cantian_exporter_info}"
    online_list[${#online_list[*]}]="cantian_exporter"
fi

daemon_info=$(ps -ef | grep -v grep | grep "sh /opt/cantian/common/script/cantian_daemon.sh")
if [ -n "${daemon_info}" ]; then
    logAndEchoInfo "daemon process info:\n ${daemon_info}"
    online_list[${#online_list[*]}]="cantian_daemon"
fi

systemctl is-active cantian.timer > /dev/null 2>&1
if [ $? -eq 0 ]; then
    online_list[${#online_list[*]}]="cantian_timer_active"
fi

systemctl is-enabled cantian.timer > /dev/null 2>&1
if [ $? -eq 0 ]; then
    online_list[${#online_list[*]}]="cantian_timer_enabled"
fi

systemctl is-active cantian_logs_handler.timer > /dev/null 2>&1
if [ $? -eq 0 ]; then
    online_list[${#online_list[*]}]="cantian_logs_handler_timer_active"
fi

systemctl is-enabled cantian_logs_handler.timer > /dev/null 2>&1
if [ $? -eq 0 ]; then
    online_list[${#online_list[*]}]="cantian_logs_handler_timer_enabled"
fi

logAndEchoInfo "check cantian complete."
