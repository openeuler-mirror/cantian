#!/bin/bash
declare -A MYSQL_FILE_MODE_MAP
MYSQL_FILE_MODE_MAP[0]=/opt/cantian/image/cantian_connector/
MYSQL_FILE_MODE_MAP[1]=/opt/cantian/mysql
MYSQL_FILE_MODE_MAP[2]=/opt/cantian/image/Cantian-RUN-CENTOS-64bit
MYSQL_FILE_MODE_MAP[3]=/opt/cantian/mysql/install/mysql/
CURRENT_PATH=$(dirname $(readlink -f $0))

deploy_user=`python3 ${CURRENT_PATH}/../get_config_info.py "deploy_user"`
deploy_group=`python3 ${CURRENT_PATH}/../get_config_info.py "deploy_group"`
#定义遍历目录函数
function getdir(){
            dir_mode=$2

            #循环控制
            chmod -R 500 $1
            chmod 750 $1
            for j in `ls $1`
                do
                    all_dir=$1"/"$j

                    if [ -d $all_dir ]
                    then
                        chmod 750 $all_dir
                        #再次调用函数对子目录的文件进行遍历
                        getdir $all_dir
                    fi
                done
            chmod 400 "$1"/*.py > /dev/null 2>&1
}
chmod -R 500 /opt/cantian/action/mysql
chmod 755 /opt/cantian/action/mysql
getdir ${MYSQL_FILE_MODE_MAP[0]} 750
getdir ${MYSQL_FILE_MODE_MAP[1]} 750
getdir ${MYSQL_FILE_MODE_MAP[2]} 750
if [ -d ${MYSQL_FILE_MODE_MAP[3]} ]
then
    getdir ${MYSQL_FILE_MODE_MAP[3]} 770
fi
chown -hR "${deploy_user}":"${deploy_group}" ${MYSQL_FILE_MODE_MAP[0]} ${MYSQL_FILE_MODE_MAP[1]} ${MYSQL_FILE_MODE_MAP[2]}
chmod 600 /opt/cantian/image/cantian_connector/cantian-connector-mysql/scripts/my.cnf
chown root:root -h /opt/cantian/image/cantian_connector /opt/cantian/image/cantian_connector/for_mysql_official /opt/cantian/image/cantian_connector/for_mysql_official/mf_connector_mount_dir
chmod 755 /opt/cantian/image/cantian_connector /opt/cantian/image/cantian_connector/for_mysql_official /opt/cantian/image/cantian_connector/for_mysql_official/mf_connector_mount_dir
if [ -f /opt/cantian/mysql/install/mysql/bin/mysql ]
then
    chmod 550 /opt/cantian/mysql/install/mysql/bin/mysql
fi