#!/bin/bash
set +x
CURRENT_FILE_PATH=$(dirname $(readlink -f $0))
INSTALL_PATH=/opt/cantian
BACKUP_PATH=/opt/cantian/backup
NFS_PORT=36729

cantian_user="cantian"
cantian_group="cantian"
cantian_common_group="cantiangroup"

PRE_INSTALL_ORDER=("cantian" "cms" "dbstor" "dss")
INSTALL_ORDER=("dbstor" "cms" "dss" "cantian" "ct_om" "cantian_exporter" "mysql" "logicrep")
START_ORDER=("cms" "dss" "cantian" "ct_om" "cantian_exporter" "logicrep")
STOP_ORDER=("logicrep" "cms" "dss" "cantian" "ct_om" "cantian_exporter")
UNINSTALL_ORDER=("ct_om" "cantian" "dss" "cms" "dbstor" "logicrep")
BACKUP_ORDER=("cantian" "dss" "cms" "ct_om" "dbstor" )
CHECK_STATUS=("cantian" "cms" "dss" "ct_om" "cantian_exporter")
PRE_UPGRADE_ORDER=("ct_om" "cantian_exporter" "dbstor" "cms" "dss" "cantian" "mysql" "logicrep")
UPGRADE_ORDER=("ct_om" "cantian_exporter" "dbstor" "cms" "dss" "cantian" "mysql" "logicrep")
POST_UPGRADE_ORDER=("ct_om" "cantian_exporter" "dbstor" "cms" "dss" "cantian" "mysql")
ROLLBACK_ORDER=("dbstor" "cms" "cantian" "mysql" "ct_om" "cantian_exporter" "logicrep")
INIT_CONTAINER_ORDER=("dbstor" "cms" "cantian" "logicrep")
DIR_LIST=(/opt/cantian/cms  /opt/cantian/cantian /opt/cantian/dbstor /opt/cantian/mysql ${CURRENT_FILE_PATH}/inspection/inspection_scripts/kernal ${CURRENT_FILE_PATH}/inspection/inspection_scripts/cms ${CURRENT_FILE_PATH}/inspection/inspection_scripts/ct_om)