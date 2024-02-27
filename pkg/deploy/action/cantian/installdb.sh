#!/bin/bash
#
# This library is using the variables listed in cfg/cluster.ini, and value come from install.py#set_cluster_conf
#

CURRENT_PATH=$(dirname $(readlink -f $0))

function help() {
    echo ""
    echo "$1"
    echo ""
    echo "Usage: installdb.sh -P CMS|GSS|CANTIAND -M NOMOUNT|OPEN|MOUNT -T ... [-C MYSQL_CONFIG_FILE] [-R]"
    echo "          -P    start process: CMS, GSS, CANTIAND"
    echo "          -M    start mode: NOMOUNT, OPEN, MOUNT"
    echo "          -R    if it's restart"
    echo "          -T    run type:cantiand, cantiand_with_mysql, cantiand_with_mysql_st, cantiand_in_cluster, cantiand_with_mysql_in_cluster"
    echo "          -C    mysql config file in single process mode"
}

function clean() {
  if [[ -e ${TMPCFG} ]]; then
    rm -f ${TMPCFG}
    log "remove temp config file ${TMPCFG}"
  fi
}

trap clean EXIT

function wait_for_success() {
  local attempts=$1
  local success_cmd=${@:2}

  i=0
  while ! ${success_cmd}; do
    echo -n "."
    sleep 1
    i=$((i + 1))
    if [ $i -eq ${attempts} ]; then
      break
    fi
  done
}

function log() {
  printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S\"`" "$1"
}

function err() {
  log "$@"
  exit 2
}

function wait_node1_online() {

  function is_db1_online_by_cms() {
    ${CTDB_HOME}/bin/cms stat -res db | grep -E "^1[[:blank:]]+db[[:blank:]]+ONLINE"
  }

  function is_db1_online_by_query() {
    echo -e "${DB_PASSWD}" | ${CTDB_HOME}/bin/ctsql SYS@127.0.0.1:1611 -q -c "SELECT NAME, STATUS, OPEN_STATUS FROM DV_DATABASE"
  }
  log "query db1 by cms, please wait..."
  wait_for_success 1800 is_db1_online_by_cms
  log "query db1 by ctsql, please wait..."
  wait_for_success 1800 is_db1_online_by_query
}

function wait_node0_online() {
  function is_db0_online_by_cms() {
    ${CTDB_HOME}/bin/cms stat -res db | awk '{print $1, $3, $6}' | grep "0 ONLINE 1"
  }
  wait_for_success 5400 is_db0_online_by_cms
}

function start_cantiand() {
  log "================ start cantiand ${NODE_ID} ================"

  ever_started=`python3 ${CURRENT_PATH}/get_config_info.py "CANTIAN_EVER_START"`
  if [ "${NODE_ID}" != 0 ] && [ "${ever_started}" != "True" ]; then
    wait_node0_online || err "timeout waiting for node0"
    sleep 60
  fi

  log "Start cantiand with mode=${START_MODE}, CTDB_HOME=${CTDB_HOME}, RUN_MODE=${RUN_MODE}"

  if [ "${RUN_MODE}" == "cantiand_with_mysql" ] || [ "${RUN_MODE}" == "cantiand_with_mysql_st" ] || [ "${RUN_MODE}" == "cantiand_with_mysql_in_cluster" ]; then
    
    if [ ! -f "${MYSQL_CONFIG_FILE}" ]; then
      err "Invalid mysql config file: ${MYSQL_CONFIG_FILE}"
    fi

    export CANTIAND_MODE=${START_MODE}
    export CANTIAND_HOME_DIR=${CTDB_DATA}
    if [ -z "${LD_LIBRARY_PATH}" ];then
        export LD_LIBRARY_PATH=${MYSQL_BIN_DIR}/lib:${MYSQL_CODE_DIR}/daac_lib
    else
        export LD_LIBRARY_PATH=${MYSQL_BIN_DIR}/lib:${MYSQL_CODE_DIR}/daac_lib:${LD_LIBRARY_PATH}
    fi

    if [ "${IS_RERUN}" == 0 ]; then
        log "Init mysqld data dir ${MYSQL_DATA_DIR}"
        ${MYSQL_BIN_DIR}/bin/mysqld --defaults-file=${MYSQL_CONFIG_FILE} --initialize-insecure --datadir=${MYSQL_DATA_DIR}
    fi

    if [ "${RUN_MODE}" != "cantiand_with_mysql_st" ]; then
        log "Start mysqld with conf ${MYSQL_CONFIG_FILE}"
        nohup ${MYSQL_BIN_DIR}/bin/mysqld --defaults-file=${MYSQL_CONFIG_FILE} --datadir=${MYSQL_DATA_DIR} --plugin-dir=${MYSQL_BIN_DIR}/lib/plugin \
                                      --plugin_load="ctc_ddl_rewriter=ha_ctc.so;ctc=ha_ctc.so;" \
                                      --default-storage-engine=CTC --core-file >> ${MYSQL_LOG_FILE} 2>&1 &
    fi
    sleep 10
  else
    # 如果参天被cms抢占拉起，等待此参天拉起完成，并跳过安装部署的启动参天进程命令
    cantiand_pid=$(ps -ef | grep -v grep | grep cantiand | grep -w 'cantiand -D /mnt/dbdata/local/cantian/tmp/data' | awk '{print $2}')
    if [ ! -z "${cantiand_pid}" ]; then
      log "cms has start cantiand already"
      if [ "${NODE_ID}" == 0 ]; then
        wait_node0_online || err "timeout waiting for node0"
      else
        wait_node1_online || err "timeout waiting for node1"
      fi
      echo "instance started" >> /mnt/dbdata/local/cantian/tmp/data/log/cantianstatus.log
      return 0
    fi
    numactl_str=" "
    set +e
    numactl --hardware
    if [ $? -eq 0 ]; then
      OS_ARCH=$(uname -i)
      if [[ ${OS_ARCH} =~ "aarch64" ]]; then
        CPU_CORES_NUM=`cat /proc/cpuinfo |grep "architecture" |wc -l`
        CPU_CORES_NUM=$((CPU_CORES_NUM - 1))
        numactl_str="numactl -C 0-1,6-11,16-"${CPU_CORES_NUM}" "
      fi
    fi
    set -e
    if [ "${ever_started}" == "True" ]; then
      cms res -start db -node "${NODE_ID}"
      if [ $? -eq 0 ]; then
        echo "instance started" >> /mnt/dbdata/local/cantian/tmp/data/log/cantianstatus.log
      else
        echo "instance startup failed" >> /mnt/dbdata/local/cantian/tmp/data/log/cantianstatus.log
      fi
    else
      nohup ${numactl_str} ${CTDB_HOME}/bin/cantiand ${START_MODE} -D ${CTDB_DATA} >> ${STATUS_LOG} 2>&1 &
    fi
  fi
  
  if [ $? != 0 ]; then err "failed to start cantiand"; fi

  if [ "${NODE_ID}" == 1 ]; then
    wait_node1_online || err "timeout waiting for node1"
  fi
}

function wait_for_node1_in_cluster() {
  function is_node1_joined_cluster() {
    ${CTDB_HOME}/bin/cms node -list | grep -q node1
  }
  wait_for_success 60 is_node1_joined_cluster
}

function start_cms() {
  log "=========== start cms ${NODE_ID} ================"
  if [ ${NODE_ID} == 0 ]; then
    if [ ${CLUSTER_SIZE} == 1 ]; then
      ${CTDB_HOME}/bin/cms node -add 0 node0 127.0.0.1 ${CMS_PORT[0]}
    else
      for ((i = 0; i < ${CLUSTER_SIZE}; i++)); do
        ${CTDB_HOME}/bin/cms node -add ${i} node${i} ${NODE_IP[$i]} ${CMS_PORT[$i]}
      done
    fi

    ${CTDB_HOME}/bin/cms res -add db -type db -attr "script=${CTDB_HOME}/bin/cluster.sh"
  elif [ ${NODE_ID} == 1 ]; then
    wait_for_node1_in_cluster
  fi

  ${CTDB_HOME}/bin/cms node -list
  ${CTDB_HOME}/bin/cms res -list
  ${CTDB_HOME}/bin/cms server -start >> ${STATUS_LOG} 2>&1 &
}

function prepare_cms_gcc() {
  if [ "${IS_RERUN}" == 1 ]; then
    return 0
  fi

  if [ "${NODE_ID}" == 0 ]; then
    log "zeroing ${GCC_HOME} on node ${NODE_ID}"
    dd if=/dev/zero of=${GCC_HOME} bs=1M count=1024
    ${CTDB_HOME}/bin/cms gcc -reset -f
  fi
}

function install_cantiand() {
  start_cantiand
}

function install_cms() {
  prepare_cms_gcc
  start_cms
}

function parse_parameter() {
  ARGS=$(getopt -o RSP:M:T:C: -n 'installdb.sh' -- "$@")
  
  if [ $? != 0 ]; then
    log "Terminating..."
    exit 1
  fi

  eval set -- "${ARGS}"
  
  declare -g PROCESS=
  declare -g START_MODE=
  declare -g IS_RERUN=0
  declare -g RUN_MODE=
  declare -g MYSQL_CONFIG_FILE=
  declare -g CLUSTER_CONFIG="${CTDB_DATA}/cfg/cluster.ini"
  
  while true
  do
    case "$1" in
      -P)
        PROCESS="$2"
        shift 2
        ;;
      -M)
        START_MODE="$2"
        shift 2
        ;;
      -T)
        RUN_MODE="$2"
        shift 2
        ;;
      -C)
        MYSQL_CONFIG_FILE="$2"
        shift 2
        ;;
      -R)
        IS_RERUN=1
        shift
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

  if [[ "${PROCESS^^}" == "CANTIAND" && "${START_MODE^^}" != "NOMOUNT" && "${START_MODE^^}" != "OPEN" && "${START_MODE^^}" != "MOUNT" ]]; then
    help "Wrong start mode ${START_MODE} for cantiand passed by -M!"
    exit 1
  fi
  
  if [[ "${PROCESS^^}" == "CANTIAND" && "${RUN_MODE}" != "cantiand" && "${RUN_MODE}" != "cantiand_with_mysql" && "${RUN_MODE}" != "cantiand_with_mysql_st" && "${RUN_MODE}" != "cantiand_in_cluster" && "${RUN_MODE}" != "cantiand_with_mysql_in_cluster" ]]; then
    help "Wrong run mode ${RUN_MODE} for cantiand passed by -T!"
    exit 1
  fi
  
  if [ ! -f "${CLUSTER_CONFIG}" ]; then
    help "Cluster config file ${CLUSTER_CONFIG} passed by -F not exists!"
    exit 1
  fi
}

function check_env() {
    if [ -z $CTDB_HOME ]; then
        err "Environment Variable CTDB_HOME NOT EXISTS!"
        exit 1
    fi

    if [ -z $CTDB_DATA ]; then
        err "Environment Variable CTDB_DATA NOT EXISTS!"
        exit 1
    fi
}

function main() {
  source ~/.bashrc
  read -s DB_PASSWD
  check_env
  parse_parameter "$@"
  
  set -e -u
  TMPCFG=$(mktemp /tmp/tmpcfg.XXXXXXX) || exit 1
  log "create temp cfg file ${TMPCFG}"
  (cat ${CLUSTER_CONFIG} | sed 's/ *= */=/g') > $TMPCFG
  source $TMPCFG

  case ${PROCESS} in
  cantiand | CANTIAND)
    log "================ Install cantiand process ================"
    install_cantiand
    ;;
  *)
    help "Wrong start process passed by -P!"
    exit 1
    ;;
  esac
  
  log "${PROCESS} processed ok !!"
  exit 0
}

main "$@"
