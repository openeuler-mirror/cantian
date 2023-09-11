#!/bin/bash
set +x
CURRENT_FILE_PATH=$(dirname $(readlink -f $0))
INSTALL_PATH=/opt/cantian
BACKUP_PATH=/opt/cantian/backup
NFS_PORT=36729

PRE_INSTALL_ORDER=("cantian" "cms" "dbstor")
INSTALL_ORDER=("dbstor" "cms" "cantian" "ct_om" "cantian_exporter")
START_ORDER=("cms" "cantian" "ct_om" "cantian_exporter")
STOP_ORDER=("cms" "cantian" "ct_om" "cantian_exporter")
UNINSTALL_ORDER=("ct_om" "cantian" "cms" "dbstor")
BACKUP_ORDER=("cantian" "cms" "ct_om" "dbstor" )
CHECK_STATUS=("cantian" "cms" "ct_om" "cantian_exporter")
PRE_UPGRADE_ORDER=("ct_om" "cantian_exporter" "dbstor" "cms" "cantian")
UPGRADE_ORDER=("ct_om" "cantian_exporter" "dbstor" "cms" "cantian")
POST_UPGRADE_ORDER=("ct_om" "cantian_exporter" "dbstor" "cms" "cantian")
ROLLBACK_ORDER=("dbstor" "cms" "cantian" "ct_om" "cantian_exporter")
DIR_LIST=(/opt/cantian/cms  /opt/cantian/cantian /opt/cantian/dbstor /opt/cantian/ct_om ${CURRENT_FILE_PATH}/inspection/inspection_scripts/kernal ${CURRENT_FILE_PATH}/inspection/inspection_scripts/cms)