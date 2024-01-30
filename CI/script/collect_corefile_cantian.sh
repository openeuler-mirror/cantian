#!/bin/bash

if [ $# -ne 5 ]
then	
	echo "Help:"	
	echo "usage: collect_corefile_cantian.sh CORE_DIR BACKUP_DIR ROOT_PATH CTDB_DATA USER"
	exit 1	
fi

CORE_DIR=$1
BACKUP_DIR=$2
ROOT_PATH=$3
CTDB_DATA=$4
TEST_USER=$5

OUTPUT_DIR=${ROOT_PATH}/output

if [ ! -d ${CORE_DIR} ]; then
	echo "directory ${CORE_DIR} is not exists, please check"
	exit 1
fi

if [ ! -d ${BACKUP_DIR} ]; then
	echo "directory ${BACKUP_DIR} is not exists, please check"
	exit 1
fi

if [ ! -d ${OUTPUT_DIR} ]; then
	echo "directory ${OUTPUT_DIR} is not exists, please check"
	exit 1
fi

if [ ! -d ${OUTPUT_DIR}/bin ]; then
	echo "directory ${OUTPUT_DIR}/bin is not exists, please check"
	exit 1
fi

if [ ! -d ${OUTPUT_DIR}/lib ]; then
	echo "directory ${OUTPUT_DIR}/lib is not exists, please check"
	exit 1
fi

vDate=`date +%Y%m%d%H%M%S`
cd ${BACKUP_DIR}
collect_core=core_${vDate}
mkdir -p ${collect_core}

collect_run_log()
{
	if [ -d ${CTDB_DATA}/cfg ]; then
		cp -rf ${CTDB_DATA}/cfg/ ${BACKUP_DIR}/${collect_core}/
	fi
	
	if [ -d ${CTDB_DATA}/log ]; then
		cp -rf ${CTDB_DATA}/log/ ${BACKUP_DIR}/${collect_core}/
	fi
	
}

cd ${CORE_DIR}
count=`ls -l | grep ${TEST_USER} | grep core | wc -l`
if [ ${count} -gt 0 ]; then
	echo "collect core"
	echo ""
	cp -rf ${OUTPUT_DIR}/bin/ ${BACKUP_DIR}/${collect_core}/
	cp -rf ${OUTPUT_DIR}/lib/ ${BACKUP_DIR}/${collect_core}/
	corefile=`ls -l | grep ${TEST_USER} | grep core | awk '{print $9}'`
	cp -rf ${CORE_DIR}/${corefile} ${BACKUP_DIR}/${collect_core}/
fi

echo "collect run log"
echo ""
collect_run_log

cd ${BACKUP_DIR}
tar -czf ${collect_core}.tar.gz ${collect_core}
rm -rf ${BACKUP_DIR}/${collect_core}

echo "delete the corefiles 2days ago"
find ${BACKUP_DIR} -mtime 2 -name "core_*" | xargs rm -rf
echo ""

cd ${CORE_DIR}
echo "delete core* file in ${CORE_DIR}"
ls -l | grep ${TEST_USER} | grep core | awk '{print $9}'
ls -l | grep ${TEST_USER} | grep core | awk '{print $9}' | xargs rm -rf
echo ""
echo "the name of corefile is" ${collect_core} "which in" ${BACKUP_DIR}