#!/bin/bash

CURRENT_PATH=$(dirname $(readlink -f $0))

declare -A FILE_R_MODE_MAP
declare -A FILE_MODE_MAP

find "${CURRENT_PATH}"/ -maxdepth 1 -type f -print0 | xargs -0 chmod 400
find "${CURRENT_PATH}"/../config/ -maxdepth 1 -type f -print0 | xargs -0 chmod 400
find "${CURRENT_PATH}"/../common/ -type f -print0 | xargs -0 chmod 400
find "${CURRENT_PATH}"/implement/ -type f -print0 | xargs -0 chmod 400
find "${CURRENT_PATH}"/utils/ -type f -print0 | xargs -0 chmod 400
find "${CURRENT_PATH}"/logic/ -type f -print0 | xargs -0 chmod 400
find "${CURRENT_PATH}"/storage_operate/ -type f -print0 | xargs -0 chmod 400
find "${CURRENT_PATH}"/inspection/ -type f -print0 | xargs -0 chmod 400
find "${CURRENT_PATH}"/wsr_report/ -type f -print0 | xargs -0 chmod 400
find "${CURRENT_PATH}"/logic/ -type d -print0 | xargs -0 chmod 755
find "${CURRENT_PATH}"/ -maxdepth 1 -type d -print0 | xargs -0 chmod 755

FILE_MODE_MAP["${CURRENT_PATH}/../common"]="755"
FILE_MODE_MAP["${CURRENT_PATH}/../common/script"]="755"
FILE_MODE_MAP["${CURRENT_PATH}/../common/script/logs_handler"]="755"
FILE_MODE_MAP["${CURRENT_PATH}/../common/script/logs_handler/logs_tool"]="700"
FILE_MODE_MAP["${CURRENT_PATH}/../common/script/logs_handler/do_compress_and_archive.py"]="440"
FILE_MODE_MAP["${CURRENT_PATH}/../common/script/log4sh.sh"]="440"
FILE_MODE_MAP["${CURRENT_PATH}"]="755"
FILE_MODE_MAP["${CURRENT_PATH}/change_log_priority.sh"]="500"
FILE_MODE_MAP["${CURRENT_PATH}/../deploy"]="755"
FILE_MODE_MAP["${CURRENT_PATH}/../deploy/deploy.log"]="640"
FILE_MODE_MAP["${CURRENT_PATH}/../config"]="755"
FILE_MODE_MAP["${CURRENT_PATH}/../config/deploy_param.json"]="644"
FILE_MODE_MAP["${CURRENT_PATH}/../config/dr_deploy_param.json"]="644"
FILE_MODE_MAP["${CURRENT_PATH}/../versions.yml"]="644"
FILE_MODE_MAP["${CURRENT_PATH}/inspection"]="750"
FILE_MODE_MAP["${CURRENT_PATH}/config_params.json"]="640"
FILE_MODE_MAP["${CURRENT_PATH}/log4sh.sh"]="440"
FILE_MODE_MAP["${CURRENT_PATH}/om_log_config.py"]="440"
FILE_MODE_MAP["${CURRENT_PATH}/om_log.py"]="440"
FILE_MODE_MAP["${CURRENT_PATH}/env.sh"]="444"
FILE_MODE_MAP["${CURRENT_PATH}/../common/script/log4sh.sh"]="440"
FILE_MODE_MAP["${CURRENT_PATH}/inspection/inspection_scripts"]="750"
FILE_MODE_MAP["${CURRENT_PATH}/inspection/inspection_scripts/cms"]="750"
FILE_MODE_MAP["${CURRENT_PATH}/inspection/inspection_scripts/kernal"]="750"
FILE_MODE_MAP["${CURRENT_PATH}/inspection/inspection_scripts/mysql"]="750"
FILE_MODE_MAP["${CURRENT_PATH}/inspection/inspection_scripts/ct_om"]="750"
FILE_MODE_MAP["${CURRENT_PATH}/storage_operate/file_system_info.json"]="600"
FILE_MODE_MAP["${CURRENT_PATH}/inspection/log_tool.py"]="400"
FILE_MODE_MAP["${CURRENT_PATH}/wsr_report/report.cnf"]="600"

function correct_files_mod() {
    for file_path in "${!FILE_MODE_MAP[@]}"; do
        if [ ! -e ${file_path} ]; then
            continue
        fi

        chmod ${FILE_MODE_MAP[$file_path]} $file_path
        if [ $? -ne 0 ]; then
            logAndEchoError "chmod ${FILE_MODE_MAP[$file_path]} ${file_path} failed"
            exit 1
        fi
    done
}

correct_files_mod