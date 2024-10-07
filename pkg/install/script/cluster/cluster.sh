#!/bin/bash
source ~/.bashrc

dbuser=`whoami`
loguser=`whoami`
if [ "${dbuser}" = "root" ]
then
	dbuser=$(grep '"U_USERNAME_AND_GROUP"' /opt/cantian/action/cantian/install_config.json | cut -d '"' -f 4 | sed 's/:.*//')
fi
running_mode=$(grep '"M_RUNING_MODE"' /opt/cantian/action/cantian/install_config.json | cut -d '"' -f 4)
exit_num_file="/opt/cantian/cms/cfg/exit_num.txt"
exit_num_dir="/opt/cantian/cms/cfg"
single_mode="multiple"
process_to_check="cantiand"
process_path=$CTDB_DATA
if [ "$running_mode" = "cantiand_with_mysql" ] || 
   [ "$running_mode" = "cantiand_with_mysql_in_cluster" ] || 
   [ "$running_mode" = "cantiand_with_mysql_in_cluster_st" ]; then
	single_mode="single"
	process_to_check="mysqld"
	process_path=$MYSQL_BIN_DIR
fi
MYSQL_INSTALL_LOG_FILE="/opt/cantian/mysql/log/install.log"

function usage()
{
	echo "Usage:"
	echo "	    $0 -start node_id"
	echo "	    startup CTDB..."
	echo "	    $0 -stop node_id"
	echo "	    kill CTDB..."
	echo "      $0 -stop_force node_id"
	echo "      kill CTDB by force..."
	echo "	    $0 -check node_id"
	echo "	    check CTDB status..."
	echo "      $0 -init_exit_file node_id"
	echo "      $0 -inc_exit_num node_id"
}

function check_process()
{
	res_count=`ps -u ${dbuser} | grep ${process_to_check} |grep -vE '(grep|defunct)' |wc -l`
	if [ "$res_count" -eq "0" ]; then
		return 1
	elif [ "$res_count" -eq "1" ]; then
		return 0
	else 
		res_count=`ps -fu ${dbuser} | grep ${process_to_check} | grep ${process_path} | grep -vE '(grep|defunct)' | wc -l`
		if [ "$res_count" -eq "0" ]; then
			return 1
		elif [ "$res_count" -eq "1" ]; then
			return 0
		else
			echo "res_count= ${res_count}"
			return 1
		fi
	fi
	return 0
}

function start_cantian() {
	numactl_str=" "
	set +e
	numactl --hardware > /dev/null 2>&1
	if [ $? -eq 0 ]; then
		OS_ARCH=$(uname -i)
		if [[ ${OS_ARCH} =~ "aarch64" ]]; then
		CPU_CORES_NUM=`cat /proc/cpuinfo |grep "architecture" |wc -l`
		CPU_CORES_NUM=$((CPU_CORES_NUM - 1))
		numactl_str="numactl -C 0-1,6-11,16-"${CPU_CORES_NUM}" "
		fi
	fi
	set -e
	if [ "${loguser}" = "root" ]; then
		if [ ${single_mode} = "single" ];then
			sudo -E -i -u ${dbuser} sh -c "export CANTIAND_MODE=open && export CANTIAND_HOME_DIR=${CTDB_DATA} && export LD_LIBRARY_PATH=${MYSQL_BIN_DIR}/lib:${MYSQL_CODE_DIR}/daac_lib:${LD_LIBRARY_PATH} \
											&& export RUN_MODE=$running_mode && nohup ${MYSQL_BIN_DIR}/bin/mysqld \
											--defaults-file=${MYSQL_CODE_DIR}/scripts/my.cnf --datadir=${MYSQL_DATA_DIR} --plugin-dir=${MYSQL_BIN_DIR}/lib/plugin \
											--early-plugin-load="ha_ctc.so" --default-storage-engine=CTC --core-file >> ${MYSQL_LOG_FILE} 2>&1 &"
			if [ $? -ne 0 ]; then 
				echo "RES_FAILED"
				exit 1
			fi
		else
			sudo  -E -i -u ${dbuser} sh -c "nohup cantiand -D \${CTDB_DATA}  1>/dev/null 2>&1 &"
			if [ $? -ne 0 ]; then 
				echo "RES_FAILED"
				exit 1
			fi
		fi
	else
		if [ ${single_mode} = "single" ];then
			export CANTIAND_MODE=open
			export CANTIAND_HOME_DIR=${CTDB_DATA}
			export RUN_MODE=$running_mode
			export LD_LIBRARY_PATH=${MYSQL_BIN_DIR}/lib:${MYSQL_CODE_DIR}/daac_lib:${LD_LIBRARY_PATH}
			nohup ${numactl_str} ${MYSQL_BIN_DIR}/bin/mysqld \
				--defaults-file=${MYSQL_CODE_DIR}/scripts/my.cnf --datadir=${MYSQL_DATA_DIR} --plugin-dir=${MYSQL_BIN_DIR}/lib/plugin \
				--early-plugin-load="ha_ctc.so" --default-storage-engine=CTC --core-file >> ${MYSQL_INSTALL_LOG_FILE} 2>&1 &
			if [ $? -ne 0 ]; then 
				echo "RES_FAILED"
				exit 1
			fi
		else
			nohup cantiand -D ${CTDB_DATA}  1>/dev/null 2>&1 &
			if [ $? -ne 0 ]; then 
				echo "RES_FAILED"
				exit 1
			fi
		fi
	fi
}

function stop_cantian() {
	res_count=`ps -u ${dbuser} | grep ${process_to_check} |grep -v grep |wc -l`
	echo "res_count = ${res_count}"
	if [ "$res_count" -eq "0" ]; then
		echo "RES_FAILED"
		exit 1
	elif [ "$res_count" -eq "1" ]; then
		ps -u ${dbuser} | grep ${process_to_check}|grep -v grep | awk '{print "kill -9 " $1}' |sh
		echo "RES_SUCCESS"
		exit 0
	else 
		res_count=`ps -fu ${dbuser} | grep ${process_to_check} | grep ${process_path} | grep -v grep | wc -l`
		echo "res_count is ${res_count}"
		if [ "$res_count" -eq "0" ]; then
			echo "RES_FAILED"
			exit 1
		elif [ "$res_count" -eq "1" ]; then
			ps -fu ${dbuser} | grep ${process_to_check} | grep ${process_path} | grep -v grep | awk '{print "kill -9 " $2}' |sh
			echo "RES_SUCCESS"
			exit 0
		else
			echo "RES_MULTI"
			exit 1
		fi
	fi
}

function stop_cantian_by_force() {
	res_count=`ps -u ${dbuser} | grep ${process_to_check}|grep -v grep |wc -l`
	echo "res_count = ${res_count}"
	if [ "$res_count" -eq "0" ]; then
		echo "RES_SUCCESS"
		exit 0
	elif [ "$res_count" -eq "1" ]; then
		ps -u ${dbuser} | grep ${process_to_check}|grep -v grep | awk '{print "kill -9 " $1}' |sh
		echo "RES_SUCCESS"
		exit 0
	else
		res_count=`ps -fu ${dbuser} | grep ${process_to_check} | grep ${process_path} | grep -v grep | wc -l`
		echo "res_count is ${res_count}"
		if [ "$res_count" -eq "0" ]; then
			echo "RES_SUCCESS"
			exit 0
		elif [ "$res_count" -eq "1" ]; then
			ps -fu ${dbuser} | grep ${process_to_check} | grep ${process_path} | grep -v grep | awk '{print "kill -9 " $2}' |sh
			echo "RES_SUCCESS"
			exit 0
		else
			echo "RES_FAILED"
			exit 1
		fi
	fi
}

function inc_exit_num() {
	if [ -d ${exit_num_dir} ]; then
		if [ ! -f ${exit_num_file} ]; then
	  		touch ${exit_num_file}
	  		if [ $? -eq 0 ]; then
	  		  	chmod 755 ${exit_num_file}
	  		  	echo 1 > ${exit_num_file}
	  		  	echo "create exit_num_file success"
				echo "RES_SUCCESS"
	  		  	exit 0
	  		else
	  		  	echo "create exit_num_file failed"
				echo "RES_FAILED"
	  		  	exit 1
	  		fi
		else
		  	for num in `cat ${exit_num_file}`
		  	do
		  	  	num_new=$((${num}+1))
		  	  	echo ${num_new} > ${exit_num_file}
		  	done
		fi
	else
		echo "do not have exit_num dir"
		exit 1
	fi
}

function init_exit_file() {
	if [ -d ${exit_num_dir} ]; then
		if [ ! -f ${exit_num_file} ]; then
			touch ${exit_num_file}
			  	if [ $? -eq 0 ]; then
			  		chmod 755 ${exit_num_file}
			  		echo 0 > ${exit_num_file}
					echo "RES_SUCCESS"
			  		exit 0
			  	else
			  	  	echo "create exit_num_file failed"
					echo "RES_FAILED"
			  	  	exit 1
			  	fi
		else
		  	echo 0 > ${exit_num_file}
		fi
	else
		echo "do not have exit_num dir"
		exit 1
	fi
}

############################### main ###############################

if [ $#	-ne 2 ]; then
	usage
	exit 1
fi

parm=$1
node_id=$2
case "${parm}" in
	-start)
		start_cantian
		;;
	-stop)
		stop_cantian
		;;
	-stop_force)
		stop_cantian_by_force
		;;
	-check)
		check_process
		if [ $? -ne 0 ]; then
			echo "RES_FAILED"
			exit 1
		fi
		;;
	-inc_exit_num)
		inc_exit_num
		;;
	-init_exit_file)
		init_exit_file
		;;
	*)
		echo "RES_FAILED"
		usage
		exit 1
		;;
esac

echo "RES_SUCCESS"
exit 0