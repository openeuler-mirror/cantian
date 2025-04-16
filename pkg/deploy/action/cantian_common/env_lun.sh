#!/bin/bash
set +x
CURRENT_FILE_PATH=$(dirname $(readlink -f $0))
INSTALL_PATH=/opt/cantian
BACKUP_PATH=/opt/cantian/backup
NFS_PORT=36729

cantian_user="cantian"
cantian_group="cantian"
cantian_common_group="cantiangroup"

PRE_INSTALL_ORDER=("cantian" "cms" "dss")
INSTALL_ORDER=( "cms" "dss" "cantian" "ct_om" "cantian_exporter" "mysql")
START_ORDER=("cms" "dss" "cantian" "ct_om" "cantian_exporter")
STOP_ORDER=("cms" "dss" "cantian" "ct_om" "cantian_exporter")
UNINSTALL_ORDER=("ct_om" "cantian" "dss" "cms")
BACKUP_ORDER=("cantian" "dss" "cms" "ct_om")
CHECK_STATUS=("cantian" "cms" "dss" "ct_om" "cantian_exporter")
PRE_UPGRADE_ORDER=("ct_om" "cantian_exporter" "cms" "cantian" "mysql")
UPGRADE_ORDER=("ct_om" "cantian_exporter" "cms" "cantian" "mysql")
POST_UPGRADE_ORDER=("ct_om" "cantian_exporter" "cms" "cantian" "mysql")
ROLLBACK_ORDER=("cms" "cantian" "mysql" "ct_om" "cantian_exporter")
INIT_CONTAINER_ORDER=("cms" "cantian" "logicrep")
DIR_LIST=(/opt/cantian/cms  /opt/cantian/cantian /opt/cantian/dbstor /opt/cantian/mysql ${CURRENT_FILE_PATH}/inspection/inspection_scripts/kernal ${CURRENT_FILE_PATH}/inspection/inspection_scripts/cms ${CURRENT_FILE_PATH}/inspection/inspection_scripts/ct_om)