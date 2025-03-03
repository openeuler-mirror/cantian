#!/bin/bash
source ~/.bashrc

USER=`whoami`
if [ "${USER}" = "root" ]
then
	USER=$(grep '"U_USERNAME_AND_GROUP"' /opt/cantian/action/cantian/install_config.json | cut -d '"' -f 4 | sed 's/:.*//')
fi

DSS_BIN=dssserver
BIN_PATH=${DSS_HOME}/bin
SCRIPT_NAME=`basename $(readlink -f $0)`
CONN_PATH=UDS:${DSS_HOME}/.dss_unix_d_socket
PARM=$1
NODE_ID=$2

usage()
{
    echo "Usage:"
    echo "cmd:"
    echo "    $0 -start node_id: start dssserver"
    echo "    $0 -stop node_id: kill dssserver"
    echo "    $0 -stop_force node_id: kill dssserver by force"
    echo "    $0 -check node_id: check dssserver"
    echo "    $0 -reg node_id: register dssserver"
    echo "    $0 -kick node_id: unregister dssserver"
    echo "    $0 -isreg node_id: check whether dssserver is registered"
}

program_pid()
{
    pid=`ps -f f -u ${USER} | grep -w ${DSS_BIN} | grep ${DSS_HOME} | grep -v grep | grep -v ${SCRIPT_NAME} | awk '{print $2}' | tail -1`
    echo ${pid}
}

program_status()
{
    pid=`program_pid`
    if [[ -z ${pid} ]]; then
        echo ""
        return
    fi

    pstatus_file="/proc/"${pid}"/status"
    cat ${pstatus_file} | while read line
    do
        if [[ "${line}" =~ ^State.* ]]; then
            echo ${line} | awk -F ":" '{print $2}' | awk -F " " '{print $1}'
            return
        fi
    done

    echo ""
}

function check_dss()
{
    dss_status=$(program_status)
    if [[ -z ${dss_status} ]]
    then
        echo "RES_FAILED"
        return 1
    fi
    if [[ "${dss_status}" == "D" || "${dss_status}" == "T" || "${dss_status}" == "Z" ]]
    then
        echo "RES_EAGAIN"
        return 3
    fi
    return 0
}

function check_dss_config()
{
    if [[ ! -e ${DSS_HOME}/cfg/dss_inst.ini ]]
    then
        echo "${DSS_HOME}/cfg/dss_inst.ini NOT exist"
        echo "RES_FAILED"
        exit 1
    fi

    if [[ ! -e ${DSS_HOME}/cfg/dss_vg_conf.ini ]]
    then
        echo "${DSS_HOME}/cfg/dss_vg_conf.ini NOT exist"
        echo "RES_FAILED"
        exit 1
    fi

    LSNR_PATH=`cat ${DSS_HOME}/cfg/dss_inst.ini | sed s/[[:space:]]//g |grep -Eo "^LSNR_PATH=.*" | awk -F '=' '{print $2}'`
    if [[ -z ${LSNR_PATH} ]]
    then
        echo "CANNOT find lsnr path."
        echo "RES_FAILED"
        exit 1
    fi
    CONN_PATH=UDS:${LSNR_PATH}/.dss_unix_d_socket
}

function scand_check()
{
    groups=`groups`
    echo $groups
    array=(${groups// / })
    for var in ${array[@]}
    do
        echo $var
        nohup dsscmd scandisk -t block -p /dev/sd -u $USER -g $var >> /dev/null 2>&1 &
        if [[ $? != 0 ]]
        then
            exit 1
        fi
    done
}

function reg()
{
    scand_check
    LOCAL_INSTANCE_ID=`awk '/INST_ID/{print}' ${DSS_HOME}/cfg/dss_inst.ini | awk -F= '{print $2}' | xargs`
    if [[ -z ${LOCAL_INSTANCE_ID} ]]
    then
        echo "RES_FAILED"
        return 1
    fi
    dsscmd reghl -D ${DSS_HOME} >> /dev/null 2>&1
    if [[ $? != 0 ]]
    then
        echo "RES_EAGAIN"
        return 3
    fi
    return 0
}

function kick()
{
    LOCAL_INSTANCE_ID=`awk '/INST_ID/{print}' ${DSS_HOME}/cfg/dss_inst.ini | awk -F= '{print $2}' | xargs`
    if [[ -z ${LOCAL_INSTANCE_ID} ]]
    then
        echo "RES_FAILED"
        exit 1
    fi
    if [[ ${LOCAL_INSTANCE_ID} == ${NODE_ID} ]]
    then
        dsscmd unreghl -D ${DSS_HOME} >> /dev/null 2>&1
    else
        dsscmd kickh -i ${NODE_ID} -D ${DSS_HOME} >> /dev/null 2>&1
    fi

    if [[ $? != 0 ]]
    then
        echo "RES_FAILED"
        exit 1
    fi
    echo "RES_SUCCESS"
    exit 0
}

function is_reg()
{
    dsscmd inq_reg -i ${NODE_ID} -D ${DSS_HOME} >> /dev/null 2>&1
    result=$?
    if [[ ${result} == 255 ]]
    then
        echo "RES_EAGAIN"
		exit 3
    fi
    if [[ ${result} != 2 ]]
    then
        echo "RES_FAILED"
        exit 1
    fi 
    echo "RES_SUCCESS"
    exit 0
}

function start_dss()
{
    check_dss_config
    reg
	if [ $? -ne 0 ]; then
			echo "RES_FAILED"
			exit 1
	fi
    nohup ${BIN_PATH}/${DSS_BIN} -D ${DSS_HOME} >> /dev/null 2>&1 &
}

function stop_dss() {
	res_count=`ps -u ${USER} | grep ${DSS_BIN} |grep -v grep |wc -l`
	echo "res_count = ${res_count}"
	if [ "$res_count" -eq "0" ]; then
		echo "RES_FAILED"
		exit 1
	elif [ "$res_count" -eq "1" ]; then
		ps -u ${USER} | grep ${DSS_BIN}|grep -v grep | awk '{print "kill -9 " $1}' |sh
		echo "RES_SUCCESS"
		exit 0
	else 
		res_count=`ps -fu ${USER} | grep ${DSS_BIN} | grep ${process_path} | grep -v grep | wc -l`
		echo "res_count is ${res_count}"
		if [ "$res_count" -eq "0" ]; then
			echo "RES_FAILED"
			exit 1
		elif [ "$res_count" -eq "1" ]; then
			ps -fu ${USER} | grep ${DSS_BIN} | grep ${process_path} | grep -v grep | awk '{print "kill -9 " $2}' |sh
			echo "RES_SUCCESS"
			exit 0
		else
			echo "RES_EAGAIN"
			exit 3
		fi
	fi
}

function stop_dss_by_force() {
	res_count=`ps -u ${USER} | grep ${DSS_BIN}|grep -v grep |wc -l`
	echo "res_count = ${res_count}"
	if [ "$res_count" -eq "0" ]; then
		echo "RES_SUCCESS"
		exit 0
	elif [ "$res_count" -eq "1" ]; then
		ps -u ${USER} | grep ${DSS_BIN}|grep -v grep | awk '{print "kill -9 " $1}' |sh
		echo "RES_SUCCESS"
		exit 0
	else
		res_count=`ps -fu ${USER} | grep ${DSS_BIN} | grep ${process_path} | grep -v grep | wc -l`
		echo "res_count is ${res_count}"
		if [ "$res_count" -eq "0" ]; then
			echo "RES_SUCCESS"
			exit 0
		elif [ "$res_count" -eq "1" ]; then
			ps -fu ${USER} | grep ${DSS_BIN} | grep ${process_path} | grep -v grep | awk '{print "kill -9 " $2}' |sh
			echo "RES_SUCCESS"
			exit 0
		else
			echo "RES_FAILED"
			exit 1
		fi
	fi
}

############################### main ###############################

if [ $#	-ne 2 ]; then
	usage
	exit 1
fi

case "${PARM}" in
	-start)
		start_dss
		;;
	-stop)
		stop_dss
		;;
	-stop_force)
		stop_dss_by_force
		;;
	-check)
		check_dss
        if [ $? -ne 0 ]; then
			echo "RES_FAILED"
			exit 1
		fi
		;;
	-reg)
		reg
		if [ $? -ne 0 ]; then
			echo "RES_FAILED"
			exit 1
		fi
		;;
	-kick)
		kick
		;;
    -isreg)
		is_reg
		;;
	*)
		echo "RES_FAILED"
		usage
		exit 1
		;;
esac

echo "RES_SUCCESS"
exit 0
