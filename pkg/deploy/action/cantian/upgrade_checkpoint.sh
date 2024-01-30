#!/bin/bash
export CANTIAND_PORT0=1611

function log() {
  printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S\"`" "$1"
}

log "make full checkpoint..."
node_ip=$1
read -s -p "Please Input SYS_PassWord: " user_pwd
echo -e ${user_pwd} | ctsql sys@${node_ip}:${CANTIAND_PORT0} -q -c "alter system checkpoint global;"


if [[ $? = 0 ]]
then
        log "make full checkpoint success"
else
        log "make full checkpoint failed"
        exit 1
fi