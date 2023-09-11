#!/bin/bash
#
# This library is using the variables listed in cfg/cluster.ini, and value come from install.py#set_cluster_conf
#

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

  xtrace=$(set -o | awk '/xtrace/ {print($2)}')
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
  xtrace=$(set -o | awk '/xtrace/ {print($2)}')
  set +x
  printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S\"`" "$1"
  if [ "$xtrace" == "on" ]; then set -x; fi
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
    echo -e "${DB_PASSWD}" | ${CTDB_HOME}/bin/ctclient SYS@127.0.0.1:1611 -q -c "SELECT NAME, STATUS, OPEN_STATUS FROM DV_DATABASE"
  }
  log "query db1 by cms, please wait..."
  wait_for_success 1800 is_db1_online_by_cms
  log "query db1 by ctclient, please wait..."
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

  if [ "${NODE_ID}" != 0 ]; then
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
    nohup ${CTDB_HOME}/bin/cantiand ${START_MODE} -D ${CTDB_DATA} >> ${STATUS_LOG} 2>&1 &
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

    if [ "${USE_GSS}" == "True" ]; then
      ${CTDB_HOME}/bin/cms res -add gss -type gss -attr "script=${CTDB_HOME}/bin/gssctrl.sh"
    fi

    ${CTDB_HOME}/bin/cms res -add db -type db -attr "script=${CTDB_HOME}/bin/cluster.sh"
  elif [ ${NODE_ID} == 1 ]; then
    wait_for_node1_in_cluster
  fi

  ${CTDB_HOME}/bin/cms node -list
  ${CTDB_HOME}/bin/cms res -list
  ${CTDB_HOME}/bin/cms server -start >> ${STATUS_LOG} 2>&1 &
}

function wait_for_gss() {
  function check_gss_resources() {
    local target_lines=$(($CLUSTER_SIZE + 1))
    lines=$(${CTDB_HOME}/bin/cms stat -res gss | wc -l)
    /usr/bin/test "${lines}" = "${target_lines}"
  }

  function check_local_gssd_ready() {
    ${CTDB_HOME}/bin/gssadmin show vg1 vg_header | grep -o gss-disk1
  }

  wait_for_success 120 check_gss_resources
  wait_for_success 180 check_local_gssd_ready
}

function start_gss() {
  log "============ starting gss ${NODE_ID} ================"
  log "starting gssd daemon with CTDB_HOME=${CTDB_HOME}"
  CTDB_HOME=${CTDB_HOME} ${CTDB_HOME}/bin/gssd -D ${CTDB_DATA} >> ${STATUS_LOG} 2>&1 &
  sleep 3
  gssdid=$(pgrep gssd)
  log "gssdid = $gssdid"
  wait_for_gss
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

function reghl_gss_disk() {
  local CURR_NODE_ID=$1
  log "============ register gss-disk ================"
  set +e
  if [ "${CURR_NODE_ID}" == 0 ]; then
      CTDB_HOME=${CTDB_HOME} ${CTDB_HOME}/bin/gssadmin kickhl 0 1 -D ${CTDB_DATA}
  fi
  CTDB_HOME=${CTDB_HOME} ${CTDB_HOME}/bin/gssadmin reghl $CURR_NODE_ID -D ${CTDB_DATA}
  set -e
}

function format_gss_disk() {
  log "============ initializing gss-disk ================"
  NUM_GSS_DISKS=3
  for i in $(seq 1 ${NUM_GSS_DISKS}); do
    log "clearing /dev/gss-disk$i"
    dd if=/dev/zero of=/dev/gss-disk$i bs=8k count=1 >/dev/null 2>&1
    log "create vg$i in /dev/gss-disk$i"
    CTDB_HOME=${CTDB_HOME} ${CTDB_HOME}/bin/gssadmin cv vg$i /dev/gss-disk$i -D ${CTDB_DATA}
  done
  log "============ initializing gss-disk ========== done"
}

function prepare_gss_disk() {
  if [ "${IS_RERUN}" == 1 ]; then
    return 0
  fi
  
  reghl_gss_disk ${NODE_ID}
  if [ "${NODE_ID}" == 0 ]; then
    format_gss_disk
  fi
}

function install_cantiand() {
  start_cantiand
}

function install_cms() {
  prepare_cms_gcc
  start_cms
}

function install_gss() {
  prepare_gss_disk
  start_gss
}

function setcap() {
  su -c "setcap CAP_SYS_RAWIO+ep ${CTDB_HOME}/bin/cms CAP_SYS_RAWIO+ep ${CTDB_HOME}/bin/gssd CAP_SYS_RAWIO+ep ${CTDB_HOME}/bin/gssadmin"
  echo "/usr/lib64" > /etc/ld.so.conf.d/cantian.conf
  echo "${CTDB_HOME}/lib" >> /etc/ld.so.conf.d/cantian.conf
  echo "${CTDB_HOME}/add-ons" >> /etc/ld.so.conf.d/cantian.conf
  ldconfig
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
  read DB_PASSWD
  check_env
  parse_parameter "$@"
  
  set -u
  TMPCFG=$(mktemp /tmp/tmpcfg.XXXXXXX) || exit 1
  log "create temp cfg file ${TMPCFG}"
  (cat ${CLUSTER_CONFIG} | sed 's/ *= */=/g') > $TMPCFG
  source $TMPCFG

  case ${PROCESS} in
  cantiand | CANTIAND)
    log "================ Install cantiand process ================"
    install_cantiand
    ;;
  setcap | SETCAP)
    log "================ Setcap for binary files ================"
    setcap
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
