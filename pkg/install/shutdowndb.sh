#!/bin/bash
# Perform hot backups of CantianDB100 databases.
# Copyright © Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.


function help
{
    echo ""
    echo "$1"
    echo ""
    echo "Usage: shutdowndb.sh -h HOSTIP -p PORT -U sys -w|-W -m IMMEDIATE|NORMAL|ABORT [-D CTDB_DATADIR]"
    echo "          -h, --host=HOSTIP        database server host or socket directory (default: \"local socket\")"
    echo "          -p, --port=PORT          database server port (default: \"1611\")"
    echo "          -U, --username=sys       database sys user name"
    echo "          -w, --no-password        never prompt for password"
    echo "          -W, --password           force password prompt (should happen automatically)"   
    echo "          -m, --mode               shutdown mode: IMMEDIATE, NORMAL, ABORT"
    echo "          -D, --data-directory     database data directory"
    echo "          -T, --timeout            shutdown database timeout"
}

ARGS=$(getopt -o wWh:p:U:m:D:T: --long no-password,password,host:,port:,username:,mode:,data-directory:,timeout: -n 'shutdowndb.sh' -- "$@")

curr_path=$(dirname $(readlink -f $0))
os_user=$(whoami)
proc_name="cantiand"
file_user=`ls -l ${curr_path}"/shutdowndb.sh" | awk '{print $3}'`

if [ ${file_user} != ${os_user} ]; then
    echo "Can't run shutdowndb.sh, because it does not belong to the current user!"
    exit 1
fi

if [ $? != 0 ]; then
    help "Terminating..."
    exit 1
fi
eval set -- "${ARGS}"
declare HOST=
declare PORT=
declare DB_USER=
declare LOGIN_TYPE=
declare MODE=
declare DB_DATA=
declare DB_PVALUE=
declare TMOUT=

while true
do
    case "$1" in
        -w|--no-password)
            if ([ "X$LOGIN_TYPE" != "X" ]); then
                help "Login parameter input error!"           
                exit 1
            fi
            LOGIN_TYPE="NoAuth"            
            shift
            ;;
        -W|--password)
            if ([ "X$LOGIN_TYPE" != "X" ]); then
                help "Login parameter input error!"           
                exit 1
            fi
            LOGIN_TYPE="Auth"
            shift
            while true
            do
                echo -n "please input your password : "
                read -s DB_PVALUE
                [ -z "${DB_PVALUE}" ] && continue || break
            done
            ;;
        -h|--host) 
            HOST="$2";
            shift 2
            ;;
        -p|--port)
            PORT="$2";
            shift 2
            ;;
        -U|--username)
            DB_USER="$2";
            shift 2
            ;;
        -m|--mode)
            MODE="$2";
            shift 2
            ;;

        -D|--data-directory)
            DB_DATA="$2"
            if [ ! -d "${DB_DATA}" ]; then
                help "Error : data directory is not exist!"
                exit 1
            fi
            shift 2
        ;;

        -T|--timeout)
            TMOUT="$2"
            shift 2
        ;;

        --)
            shift
            break
            ;;
        *)
            help "Internal error!"
            exit 1
            ;;
    esac
done

if ([ "X$TMOUT" = "X" ]); then
    TMOUT="1800"
fi

if ([ "X$HOST" = "X" ] || [ "X$PORT" = "X" ] || [ "X$MODE" = "X" ]); then
    help "Parameter input error!"           
    exit 1
fi

# $HOST must be a valid IP address
if [[ $(echo "${HOST}" |grep -E "^.*[;|\`$&<>\"! '].*$") == "${HOST}" ]]; then
    help "Parameter input error!"
    exit 1
fi

# $PORT must be a digit
if [[ ! $(echo "${PORT}" |grep -E "^[0-9]{1,9}$") == "${PORT}" ]]; then
    help "Parameter input error!"
    exit 1
fi

# $MODE must in ("IMMEDIATE", "NORMAL", "ABORT")
if [[ "${MODE}" != "IMMEDIATE" ]] && [[ "${MODE}" != "NORMAL" ]] && [[ "${MODE}" != "ABORT" ]] && [[ "${MODE}" != "immediate" ]] && [[ "${MODE}" != "normal" ]] && [[ "${MODE}" != "abort" ]]; then
    help "Parameter input error!"
    exit 1
fi

if [ "X$LOGIN_TYPE" = "X" ]; then
    help "Parameter input error!"
    exit 1
fi

if [ "$LOGIN_TYPE" = "Auth" ]; then
    if [ "X$DB_USER" = "X" -o "X$DB_PVALUE" = "X" ]; then
        help "Parameter input error!"
        exit 1
    fi
    # $DB_USER must be a valid username
    if [[ $(echo "${DB_USER}" |grep -E "^.*[;|\`$&<>\"! '].*$") == "${DB_USER}" ]]; then
        help "Parameter input error!"
        exit 1
    fi
fi

if [ "$LOGIN_TYPE" = "NoAuth" ]; then
    if [ "X$DB_DATA" = "X" ]; then
        DB_DATA="$CTDB_DATA"
    fi
    # $DB_DATA must be a valid path
    if [[ ! -d "$DB_DATA" ]]; then
        help "Parameter input error!"
        exit 1
    fi
fi

proc_name="cantiand"

# check process by cantiand and datadir
if [ "X$DB_DATA" = "X" ]; then
    DB_DATA="$CTDB_DATA"
fi
# $DB_DATA must be a valid path
if [[ ! -d "$DB_DATA" ]]; then
    echo ""
    echo "Can not get database directory."
    help "Please check CTDB_DATA environment variable or -D data_dir"
    exit 1
fi
# get cantiand datadir process
proc_id=$(ps aux | grep -v grep | grep "cantiand " | grep -w "\-D ${DB_DATA}" | awk '{print $2}')

if [[ -z "$proc_id" ]];then
    echo "The $proc_name is not running ! "
else
    # pid exists, get detail info
    pid_info_a=$(ps -eo pid,lstart,cmd | grep -w ${proc_id} |grep cantiand | grep -v grep)
    echo "------shutdown "${proc_name}"!------"
    echo "cantiand process info: ${pid_info_a}"
    
    if [ "$LOGIN_TYPE" = "Auth" ]; then
        ctsql "${DB_USER}"@"${HOST}":"${PORT}" -q -c "exit;" << EOF
$DB_PVALUE
EOF
    else
        ctsql / as sysdba "${HOST}":"${PORT}" -q -D "${DB_DATA}" -c "exit;"
    fi
    
    if [[ $? -ne 0 ]]; then
        echo "test login failed, please check cantian_shutdown.log to find fail reason "
        unset DB_PVALUE
        exit 1
    fi
    
    if [ "$LOGIN_TYPE" = "Auth" ]; then
        ctsql "${DB_USER}"/"${DB_PVALUE}"@"${HOST}":"${PORT}" -q -c "shutdown $MODE" > ~/cantian_shutdown.log
    else
        ctsql / as sysdba "${HOST}":"${PORT}" -q -D "${DB_DATA}" -c "shutdown $MODE" > ~/cantian_shutdown.log
    fi

    unset DB_PVALUE

    pid_info_b=$(ps -eo pid,lstart,cmd | grep -w ${proc_id} |grep cantiand | grep -v grep)
    count=0
    while ([ "${pid_info_a}" == "${pid_info_b}" -a "${count}" -le ${TMOUT} ]); do
    sleep 1
        count=$((count + 1))
        pid_info_b=$(ps -eo pid,lstart,cmd | grep -w ${proc_id} |grep cantiand | grep -v grep)
    done

    if [ "${pid_info_a}" != "${pid_info_b}" ];then
        echo "$proc_name shutdown sucessfully"
    else
        # stop failed, record pid info
        echo "cantiand process info: ${pid_info_b}"
        echo "$proc_name shutdown timeout, if the process persists, check kernel log for the reason"
        exit 1
    fi
fi

sleep 2
exit 0
