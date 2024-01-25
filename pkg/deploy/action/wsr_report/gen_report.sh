#!/bin/bash
set +x

# 使用该脚本前，需要先开启performance_schema引擎
# 拉起mysql前,在mysql配置文件中加入performance_schema=ON字段
CURRENT_PATH=$(dirname $(readlink -f $0))
MYSQL_BIN_PATH="/opt/cantian/mysql/install/mysql/bin"
date_time=`date +"%Y%m%d%H%M%S"`
source ${CURRENT_PATH}/../env.sh

function gen_dignostics_report() {
    ${MYSQL_BIN_PATH}/mysql -u ${mysql_user_name} --password=${mysql_user_password} --host=${mysql_server_ip} \
    --port=${mysql_server_port} -e "set @ctc_ddl_enabled=true;set global ctc_concurrent_ddl=ON;"
    ${MYSQL_BIN_PATH}/mysql -u ${mysql_user_name} --password=${mysql_user_password} --host=${mysql_server_ip} \
    --port=${mysql_server_port} sys < ${CURRENT_PATH}/diagnostics/diagnostics_ctc_init.sql
    ${MYSQL_BIN_PATH}/mysql -u ${mysql_user_name} --password=${mysql_user_password} --host=${mysql_server_ip} \
    --port=${mysql_server_port} sys < ${CURRENT_PATH}/diagnostics/diagnostics_ctc_detail.sql
    ${MYSQL_BIN_PATH}/mysql -u ${mysql_user_name} --password=${mysql_user_password} --host=${mysql_server_ip} \
    --port=${mysql_server_port} -H -e "set autocommit=on;CALL sys.diagnostics_ctc_init(${mysql_diag_total_time}, ${mysql_diag_period_time}, '${mysql_diag_mode}');" > ${report_output_dir}/mysql_diag_${mysql_server_ip}_${date_time}.html
    ${MYSQL_BIN_PATH}/mysql -u ${mysql_user_name} --password=${mysql_user_password} --host=${mysql_server_ip} \
    --port=${mysql_server_port} -e "set global ctc_concurrent_ddl=OFF;"
}

function gen_wsr_report() {
    host_name=`hostname`
    kmc_log=`su -s /bin/bash - ${cantian_user} -c "ctsql ${ctsql_user_name}/${ctsql_user_passwd}@${ctsql_server_ip}:${ctsql_server_port} -q -c 'wsr list'" | grep KmcCheckKmcCtx`
    su -s /bin/bash - ${cantian_user} -c "ctsql ${ctsql_user_name}/${ctsql_user_passwd}@${ctsql_server_ip}:${ctsql_server_port} -q -c 'CALL WSR\$CREATE_SNAPSHOT'"
    sleep ${ctsql_snapshot_time}
    su -s /bin/bash - ${cantian_user} -c "ctsql ${ctsql_user_name}/${ctsql_user_passwd}@${ctsql_server_ip}:${ctsql_server_port} -q -c 'CALL WSR\$CREATE_SNAPSHOT'"
    if [ -z ${kmc_log} ]; then
        snap_id_1=`su -s /bin/bash - ${cantian_user} -c "ctsql ${ctsql_user_name}/${ctsql_user_passwd}@${ctsql_server_ip}:${ctsql_server_port} -q -c 'wsr list'" | sed -n '11p' | awk '{print $1}'`
        snap_id_2=`su -s /bin/bash - ${cantian_user} -c "ctsql ${ctsql_user_name}/${ctsql_user_passwd}@${ctsql_server_ip}:${ctsql_server_port} -q -c 'wsr list'" | sed -n '10p' | awk '{print $1}'`
    else
        snap_id_1=`su -s /bin/bash - ${cantian_user} -c "ctsql ${ctsql_user_name}/${ctsql_user_passwd}@${ctsql_server_ip}:${ctsql_server_port} -q -c 'wsr list'" | sed -n '12p' | awk '{print $1}'`
        snap_id_2=`su -s /bin/bash - ${cantian_user} -c "ctsql ${ctsql_user_name}/${ctsql_user_passwd}@${ctsql_server_ip}:${ctsql_server_port} -q -c 'wsr list'" | sed -n '11p' | awk '{print $1}'`
    fi
    su -s /bin/bash - ${cantian_user} -c "ctsql ${ctsql_user_name}/${ctsql_user_passwd}@${ctsql_server_ip}:${ctsql_server_port} -q -c 'wsr ${snap_id_1} ${snap_id_2} \"${report_output_dir}/cantian_wsr_${host_name}_${date_time}.html\"'"
}

function main() {
    source ${CURRENT_PATH}/report.cnf
    if [ ! -d ${report_output_dir} ]; then
        mkdir -m 750 -p ${report_output_dir}
    fi
    chmod 770 ${report_output_dir}
    chown -h ${system_user_name}:${cantian_common_group} ${report_output_dir}
    if [ $? -ne 0 ]; then
        echo "creat dir failed, please check the config and permission of the dir."
        exit 1
    fi

    gen_dignostics_report
    if [ $? -ne 0 ]; then
        echo "generate mysql diagnotics report failed, please check the config and permission of the dir."
        rm -rf ${report_output_dir}/mysql_diag_${mysql_server_ip}_${date_time}.html
    fi

    gen_wsr_report
    if [ $? -ne 0 ]; then
        echo "generate wsr report failed, please check the config and permission of the dir."
        rm -rf ${report_output_dir}/cantian_wsr_${ctsql_server_ip}_${date_time}.html
        exit 1
    fi
}

main