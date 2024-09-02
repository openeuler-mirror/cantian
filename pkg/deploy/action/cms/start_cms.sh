#!/bin/bash
set +x

CURRENT_PATH=$(dirname $(readlink -f $0))

function log() {
  printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S\"`" "$1"
}

function err() {
  log "$@"
  exit 1
}

function parse_parameter() {
  ARGS=$(getopt -o RSP:M:T:C: -n 'start_cms.sh' -- "$@")

  if [ $? != 0 ]; then
    err "Terminating..."
  fi

  eval set -- "${ARGS}"

  declare -g PROCESS=
  declare -g IS_RERUN=0
  declare -g CLUSTER_CONFIG="${CMS_HOME}/cfg/cluster.ini"

  while true
  do
    case "$1" in
      -P)
        PROCESS="$2"
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

  if [ ! -f "${CLUSTER_CONFIG}" ]; then
    help "Cluster config file ${CLUSTER_CONFIG} passed by -F not exists!"
    exit 1
  fi
}

function check_env() {
  if [ -z ${CMS_HOME} ]; then
    err "Environment Variable CMS_HOME NOT EXISTS!"
    exit 1
  fi
}

function prepare_cms_gcc() {
  if [ "${IS_RERUN}" == 1 ]; then
    return 0
  fi

  if [ "${NODE_ID}" == 0 ]; then
    if [[ ${DEPLOY_MODE} != "dbstor" && ${DEPLOY_MODE} != "combined" ]]; then
      rm -rf ${GCC_HOME}*
      log "zeroing ${GCC_HOME} on node ${NODE_ID}"
      dd if=/dev/zero of=${GCC_HOME} bs=1M count=1024
      chmod 600 ${GCC_HOME}
    else
      cms gcc -create
      if [ $? -ne 0 ]; then
        err "GCC CREATE FAILED"
      fi
    fi
    set +e
    ${CMS_INSTALL_PATH}/bin/cms gcc -reset -f
    if [ $? -ne 0 ]; then
      err "GCC RESET FAILED"
    fi
    set -e
    log "finished prepare_cms_gcc"
  fi
}

function wait_for_success() {
  local attempts=$1
  local success_cmd=${@:2}

  i=0
  while ! ${success_cmd}; do
    echo -n "."
    sleep 1
    i=$((i + 1))
    if [ $i -eq ${attempts} ]; then
      log "WAIT FOR SUCCESS TIMEOUT"
      break
    fi
  done
  ${success_cmd}
}

function check_node_in_cluster() {
  set +e
  if [ "${NODE_ID}" -eq "0" ]; then
    ${CMS_INSTALL_PATH}/bin/cms node -list | grep -q node0
  elif [ "${NODE_ID}" -eq "1" ]; then
    ${CMS_INSTALL_PATH}/bin/cms node -list | grep -q node1
  fi
  if [ $? -ne 0 ]; then
    err "CHECK NODE LIST FAILED"
  fi
  set -e
}

function check_res_in_cluster() {
  set +e
	${CMS_INSTALL_PATH}/bin/cms res -list | grep -q cluster
  if [ $? -ne 0 ]; then
    err "CHECK RES LIST FAILED"
  fi
  set -e
}

function wait_for_node1_in_cluster() {
  log "wait for node1 in cluster"
  function is_node1_joined_cluster() {
    ${CMS_INSTALL_PATH}/bin/cms node -list | grep -q node1
  }
  function is_gcc_file_initialized() {
    ${CMS_INSTALL_PATH}/bin/cms gccmark -check | grep -q success
  }

  if [[ ${DEPLOY_MODE} != "dbstor" && ${DEPLOY_MODE} != "combined" ]]; then
    wait_for_success 180 is_node1_joined_cluster
  else
    wait_for_success 180 is_gcc_file_initialized
    ${CMS_INSTALL_PATH}/bin/cms gccmark -check
    wait_for_success 180 is_node1_joined_cluster
  fi
}

function set_cms() {
  log "=========== set cms ${NODE_ID} ================"
  if [ ${NODE_ID} == 0 ]; then
    if [ ${CLUSTER_SIZE} == 1 ]; then
      ${CMS_INSTALL_PATH}/bin/cms node -add 0 node0 127.0.0.1 ${CMS_PORT[0]}
    else
      for ((i = 0; i < ${CLUSTER_SIZE}; i++)); do
        ${CMS_INSTALL_PATH}/bin/cms node -add ${i} node${i} ${NODE_IP[$i]} ${CMS_PORT[$i]}
      done
    fi

    ${CMS_INSTALL_PATH}/bin/cms res -add db -type db -attr "script=${CMS_INSTALL_PATH}/bin/cluster.sh"
    if [[ ${DEPLOY_MODE} == "dbstor" || ${DEPLOY_MODE} == "combined" ]]; then
      ${CMS_INSTALL_PATH}/bin/cms gccmark -create
    fi
  elif [ ${NODE_ID} == 1 ]; then
    wait_for_node1_in_cluster
  fi

  check_node_in_cluster
  ${CMS_INSTALL_PATH}/bin/cms node -list
  check_res_in_cluster
  ${CMS_INSTALL_PATH}/bin/cms res -list
  
  log "=========== finished set cms ${NODE_ID} ================"
}

function install_cms() {
  if [[ ${cantian_in_container} == "0" ]]; then
    prepare_cms_gcc
    set_cms
  fi
}

function start_cms() {
  log "=========== start cms ${NODE_ID} ================"
  check_node_in_cluster
  ${CMS_INSTALL_PATH}/bin/cms node -list
  check_res_in_cluster
  ${CMS_INSTALL_PATH}/bin/cms res -list

  if [ ! -f ${STATUS_LOG} ];then
      touch ${STATUS_LOG}
      chmod 640 ${STATUS_LOG}
  fi
  set +e
  ${CMS_INSTALL_PATH}/bin/cms server -start >> ${STATUS_LOG} 2>&1 &
  if [ $? -ne 0 ]; then
    err "START CMS FAILED"
  fi
  set -e

  ${CMS_INSTALL_PATH}/bin/cms stat -server
  log "=========== finished start cms ${NODE_ID} ================"
}

function init_container() {
  prepare_cms_gcc
  set_cms
  touch ${CMS_HOME}/cfg/container_flag
}

function main() {

  source ~/.bashrc
  check_env
  parse_parameter "$@"
  set -e -u
  TMPCFG=$(mktemp /tmp/tmpcfg.XXXXXXX) || exit 1
  echo "create temp cfg file ${TMPCFG}"
  (cat ${CLUSTER_CONFIG} | sed 's/ *= */=/g') > $TMPCFG
  source $TMPCFG
  CMS_INSTALL_PATH="${CMS_HOME}/service"
  DEPLOY_MODE=$(python3 "${CURRENT_PATH}"/get_config_info.py "deploy_mode")
  cantian_in_container=$(python3 "${CURRENT_PATH}"/get_config_info.py "cantian_in_container")
  METADATA_FS=$(python3 "${CURRENT_PATH}"/get_config_info.py "storage_metadata_fs")
  VERSION_PATH="/mnt/dbdata/remote/metadata_${METADATA_FS}"
  VERSION_FILE="versions.yml"

  if [ ${PROCESS} == install_cms ]; then
    install_cms
  elif [ ${PROCESS} == start_cms ]; then
    start_cms
  elif [ ${PROCESS} == init_container ] && [ ! -f ${VERSION_PATH}/${VERSION_FILE} ]; then
    init_container
  fi

  exit 0
}

main "$@"
