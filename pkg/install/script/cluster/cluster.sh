#!/bin/bash

usage()
{
	echo "Usage:"
	echo "	    $0 -start node_id"
	echo "	    startup CTDB..."
	echo "	    $0 -stop node_id"
	echo "	    kill CTDB..."
	echo "	    $0 -check node_id"
	echo "	    check CTDB status..."
  echo "	    reset CTDB..."
  echo "	    $0 -reset node_id"
	echo "      $0 -init_exit_file node_id"
	echo "      $0 -inc_exit_num node_id"
}

source ~/.bashrc

dbuser=`whoami`
loguser=`whoami`
if [ "${dbuser}" = "root" ]
then
	dbuser="cantiandba"
fi
exit_num_file="/opt/cantian/cms/cfg/exit_num.txt"
exit_num_dir="/opt/cantian/cms/cfg"

check_process()
{
	res_count=`ps -u ${dbuser} | grep cantiand|grep -vE '(grep|defunct)' |wc -l`
	if [ "$res_count" -eq "0" ]
	then
		return 1
	elif [ "$res_count" -eq "1" ] 
	then
		return 0
	else 
		res_count=`ps -fu ${dbuser} | grep cantiand | grep ${CTDB_DATA} | grep -vE '(grep|defunct)' | wc -l`
		if [ "$res_count" -eq "0" ]
		then
			return 1
		elif [ "$res_count" -eq "1" ] 
		then
			return 0
		else
			echo "res_count= ${res_count}"
			return 1
		fi
	fi
	return 0
}

if [ $#	-ne 2 ]
then
	usage
	exit 1
fi

parm=$1
node_id=$2


if [ "${parm}" = "-start" ]
then
	if [ "${loguser}" = "root" ]
	then
		sudo  -E -i -u ${dbuser} sh -c "nohup cantiand -D \${CTDB_DATA}  1>/dev/null 2>&1 &"
		if [ $? -ne 0 ]
		then 
			echo "RES_FAILED"
			exit 1
		fi
	else
		nohup cantiand -D ${CTDB_DATA}  1>/dev/null 2>&1 &
		if [ $? -ne 0 ]
		then 
			echo "RES_FAILED"
			exit 1
		fi
	fi
elif [ "${parm}" = "-stop" ]
then
	res_count=`ps -u ${dbuser} | grep cantiand|grep -v grep |wc -l`
	echo "res_count = $res_count"
	if [ "$res_count" -eq "0" ]
	then
		echo "RES_FAILED"
		exit 1
	elif [ "$res_count" -eq "1" ] 
	then
		ps -u ${dbuser} | grep cantiand|grep -v grep | awk '{print "kill -9 " $1}' |sh
		echo "RES_SUCCESS"
		exit 0
	else 
		res_count=`ps -fu ${dbuser} | grep cantiand | grep ${CTDB_DATA} | grep -v grep | wc -l`
		echo "res_count is $res_count"
		if [ "$res_count" -eq "0" ]
		then
			echo "RES_FAILED"
			exit 1
		elif [ "$res_count" -eq "1" ] 
		then
			ps -fu ${dbuser} | grep cantiand | grep ${CTDB_DATA} | grep -v grep | awk '{print "kill -9 " $2}' |sh
			echo "RES_SUCCESS"
			exit 0
		else
			echo "RES_FAILED"
			exit 1
		fi
	fi
elif [ "${parm}" = "-stop_force" ]
then
	res_count=`ps -u ${dbuser} | grep cantiand|grep -v grep |wc -l`
	echo "res_count = $res_count"
	if [ "$res_count" -eq "0" ]
	then
		echo "RES_SUCCESS"
		exit 0
	elif [ "$res_count" -eq "1" ] 
	then
		ps -u ${dbuser} | grep cantiand|grep -v grep | awk '{print "kill -9 " $1}' |sh
		echo "RES_SUCCESS"
		exit 0
	else
		res_count=`ps -fu ${dbuser} | grep cantiand | grep ${CTDB_DATA} | grep -v grep | wc -l`
		echo "res_count is $res_count"
		if [ "$res_count" -eq "0" ]
		then
			echo "RES_SUCCESS"
			exit 0
		elif [ "$res_count" -eq "1" ] 
		then
			ps -fu ${dbuser} | grep cantiand | grep ${CTDB_DATA} | grep -v grep | awk '{print "kill -9 " $2}' |sh
			echo "RES_SUCCESS"
			exit 0
		else
			echo "RES_FAILED"
			exit 1
		fi
	fi
elif [ "${parm}" = "-check" ]
then
	check_process
	if [ $? -ne 0 ]
	then
		#process dosen't exist
		echo "RES_FAILED"
		exit 1
	fi
elif [ "${parm}" = "-reset" ]
then
	res_count=`ps -u ${dbuser} | grep cantiand|grep -v grep |wc -l`
	if [ "$res_count" -eq "0" ]
	then
		echo "res_count = 0"
		echo "RES_FAILED"
		exit 1
	elif [ "$res_count" -eq "1" ] 
	then
		ps -u ${dbuser} | grep cantiand|grep -v grep | awk '{print "kill -9 " $1}' |sh
		echo "RES_SUCCESS"
		exit 0
	else 
		res_count=`ps -fu ${dbuser} | grep cantiand | grep ${CTDB_DATA} | grep -v grep | wc -l`
		if [ "$res_count" -eq "0" ]
		then
			echo "res_count  is 0"
			echo "RES_FAILED"
			exit 1
		elif [ "$res_count" -eq "1" ] 
		then
			ps -fu ${dbuser} | grep cantiand | grep ${CTDB_DATA} | grep -v grep | awk '{print "kill -9 " $2}' |sh
			echo "RES_SUCCESS"
			exit 0
		else
			echo "res_count   =  ${res_count}"
			echo "RES_FAILED"
			exit 1
		fi
	fi

elif [ "${parm}" = "-inc_exit_num" ]
then
	if [ -d ${exit_num_dir} ]
	then
		if [ ! -f ${exit_num_file} ]
		then
	  		touch ${exit_num_file}
	  		if [ $? -eq 0 ]
			then
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

elif [ "${parm}" = "-init_exit_file" ]
then
	if [ -d ${exit_num_dir} ]
	then
		if [ ! -f ${exit_num_file} ]
		then
			touch ${exit_num_file}
			  	if [ $? -eq 0 ]
				then
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

else
	echo "RES_FAILED"
	usage
	exit 1
fi

echo "RES_SUCCESS"
exit 0