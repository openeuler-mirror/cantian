#!/bin/bash

usage()
{
	echo "Usage:"
	echo "	    $0 -start"
	echo "	    startup CMS..."
	echo "	    $0 -stop"
	echo "	    kill CMS..."
	echo "	    $0 -check"
	echo "	    check CMS status..."
}

dbuser=`whoami`
loguser=`whoami`


check_process()
{
	cms_count=`ps -fu ${dbuser} | grep "cms server -start" | grep -vE '(grep|defunct)' | wc -l`
	return ${cms_count}
}

wait_for_success() {
	local attempts=$1
	local success_cmd=${@:2}

	xtrace=$(set -o | awk '/xtrace/ {print($2)}')
	set -x
	i=0
	while ! ${success_cmd}; do
	echo -n "."
	sleep 1
	i=$((i + 1))
	if [ $i -eq ${attempts} ]; then
		break
	fi
	done
	echo
	if [ "$xtrace" eq "on" ]; then set -x; fi
	${success_cmd}
}

wait_for_node_in_cluster() {
	is_node_joined_cluster() {
	if [ "${NODE_ID}" -eq "0" ]; then
		cms node -list | grep -q node0
	elif [ "${NODE_ID}" -eq "1" ]; then
		cms node -list | grep -q node1
	fi
	}
	wait_for_success 60 is_node_joined_cluster
}

wait_for_cms_start() {
	wait_for_cms_srv_ready() {
		cms stat -server ${NODE_ID}| grep -q "TRUE"
	}
	wait_for_success 120 wait_for_cms_srv_ready
}

start_cms() {
	echo "=========== start cms ${NODE_ID} ================"
	wait_for_node_in_cluster

	cms node -list
	cms res -list

  nohup cms server -start >> ${STATUS_LOG} 2>&1 &
  if [ $? -ne 0 ]
  then
    echo "CMS_FAILED"
    exit 1
  fi

	echo "=========== wait for cms server start ================"
	wait_for_cms_start
	echo "=========== start cantian ${NODE_ID} ================"
	cms res -start db -node ${NODE_ID}
}

check_env() {
    if [ -z ${CMS_HOME} ]; then
        echo "Environment Variable CMS_HOME NOT EXISTS!"
        exit 1
    fi
}

if [ $#	-ne 1 ]
then
	usage
	exit 1
fi

parm=$1


if [ "${parm}" = "-start" ]
then
	check_env
	CLUSTER_CONFIG="${CMS_HOME}/cfg/cluster.ini"
	CMS_INSTALL_PATH="${CMS_HOME}/service"
	set -e -u -x
	TMPCFG=$(mktemp /tmp/tmpcfg2.XXXXXXX) || exit 1
	echo "create temp cfg file ${TMPCFG}"
	(cat ${CLUSTER_CONFIG} | sed 's/ *= */=/g') > $TMPCFG
	source $TMPCFG
	start_cms
	
elif [ "${parm}" = "-stop" ]
then
	cms_count=`ps -u ${dbuser} | grep cms|grep -v grep |wc -l`
	if [ "$cms_count" -eq "0" ]
	then
		echo "cms_count = 0"
		echo "CMS_FAILED"
		exit 1
	elif [ "$cms_count" -eq "1" ] 
	then
		ps -u ${dbuser} | grep cms|grep -v grep | awk '{print "kill -9 " $1}' |sh
		echo "CMS_SUCCESS"
		exit 0
	else 
		cms_count=`ps -fu ${dbuser} | grep cms | grep ${CTDB_HOME} | grep -v grep | wc -l`
		if [ "$cms_count" -eq "0" ]
		then
			echo "cms_count  is 0"
			echo "CMS_FAILED"
			exit 1
		elif [ "$cms_count" -eq "1" ] 
		then
			ps -fu ${dbuser} | grep cms | grep ${CTDB_HOME} | grep -v grep | awk '{print "kill -9 " $2}' |sh
			echo "CMS_SUCCESS"
			exit 0
		else
			echo "cms_count   =  ${cms_count}"
			echo "CMS_FAILED"
			exit 1
		fi
	fi	
elif [ "${parm}" = "-check" ]
then
	check_process
	exit $?
		
else
	echo "CMS_FAILED"
	usage
	exit 1
fi

echo "CMS_SUCCESS"
exit 0