#!/bin/bash
set +x

CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_PATH=${CURRENT_PATH}/..
CONFIG_PATH=${CURRENT_PATH}/../../config
DORADO_CONF_PATH="${CURRENT_PATH}/../../config/container_conf/dorado_conf"
DM_USER="DMUser"
DM_PWD="DMPwd"

role=$(python3 ${CURRENT_PATH}/get_config_info.py "dr_deploy.role")

source ${CURRENT_PATH}/../log4sh.sh

function check_dr_deploy_process_completed() {
    max_iterations=300
    count=1
    last_status=""

    while [ $count -le $max_iterations ]; do
        sleep 2
        result=$(jq -r '.data.dr_deploy' ${CONFIG_PATH}/dr_process_record.json)
        all_status=$(jq -r '.data | to_entries[] | select(.value != "success" and .value != "default") | .key + ": " + .value' ${CONFIG_PATH}/dr_process_record.json)

        case "${result}" in
            *"success"*)
                logAndEchoInfo "executing dr_deploy success."
                return 0
                ;;
            *"failed"*)
                logAndEchoError "executing dr_deploy failed."
                exit 0
                ;;
            *"running"*)
                if [ -n "$all_status" ]; then
                    first_status=$(echo "$all_status" | head -n 1)

                    if [[ "$first_status" == *"failed"* ]]; then
                        logAndEchoError "dr_deploy ${first_status}"
                        exit 0
                    fi

                    if [ "${first_status}" != "${last_status}" ]; then
                        logAndEchoInfo "dr_deploy ${first_status}"
                        last_status="${first_status}"
                    fi
                fi
                ;;
            *)
                logAndEchoError "Unexpected status for dr_deploy."
                exit 0
                ;;
        esac
        ((count=count+1))
    done

    logAndEchoInfo "Timeout reached without success."
    return 1
}

function dr_deploy() {
    password=$1

    echo -e "${password}" | sh ${SCRIPT_PATH}/appctl.sh dr_operate pre_check ${role} --conf=/opt/cantian/config/deploy_param.json
    if [ $? -ne 0 ]; then
        logAndEchoError "dr_operate pre_check failed."
        exit 0
    fi

    logAndEchoInfo "dr_operate pre_check succeeded."

    echo -e "${password}\n" | sh ${SCRIPT_PATH}/appctl.sh dr_operate deploy ${role} --mysql_cmd='mysql' --mysql_user=root
    if [ $? -ne 0 ]; then
        logAndEchoError "dr_deploy failed."
        exit 0
    fi
    check_dr_deploy_process_completed

    logAndEchoInfo "dr_deploy succeeded."
}

function get_dm_password() {
    dm_user_file="${DORADO_CONF_PATH}/${DM_USER}"
    dm_password_file="${DORADO_CONF_PATH}/${DM_PWD}"

    if [ ! -f "${dm_user_file}" ] || [ ! -f "${dm_password_file}" ]; then
        logAndEchoError "DM User or password file not found."
        exit 0
    fi

    dm_user=$(cat "${dm_user_file}")
    dm_password=$(cat "${dm_password_file}")

    if [ "${role}" == "active" ]; then
        expected_dm_user=$(python3 ${CURRENT_PATH}/get_config_info.py "dr_deploy.active.dm_user")
    elif [ "${role}" == "standby" ]; then
        expected_dm_user=$(python3 ${CURRENT_PATH}/get_config_info.py "dr_deploy.standby.dm_user")
    else
        logAndEchoError "Unknown DM role value: ${role}"
        exit 0
    fi

    if [ "${dm_user}" != "${expected_dm_user}" ]; then
        logAndEchoError "DM Username does not match. Expected ${expected_dm_user}, but found ${dm_user}."
        exit 0
    fi

    ld_path_src=${LD_LIBRARY_PATH}
    export LD_LIBRARY_PATH=/opt/cantian/dbstor/lib:${LD_LIBRARY_PATH}
    password_tmp=$(python3 -B "${CURRENT_PATH}/resolve_pwd.py" "resolve_kmc_pwd" "${dm_password}")
    if [ $? -ne 0 ]; then
        logAndEchoError "Failed to decrypt the DM password."
        exit 0
    fi

    password=$(eval echo ${password_tmp})
    if [ -z "${password}" ]; then
        logAndEchoError "Failed to get dm password"
        exit 0
    fi

    export LD_LIBRARY_PATH=${ld_path_src}
    echo "${password}"
}

function main() {
    if [ "$1" == "get_dm_password" ]; then
        passwd=$(get_dm_password)
        echo "${passwd}"
    else
        passwd=$(get_dm_password)
        dr_deploy ${passwd}
    fi
}

main "$@"