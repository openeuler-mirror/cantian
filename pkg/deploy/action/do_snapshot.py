import os
import sys
import stat
import json
import time
import traceback

from rest_client import RestClient
from om_log import SNAPSHOT_LOGS as LOG

CUR_PATH, _ = os.path.split(os.path.abspath(__file__))
DEPLOY_PARAM_PATH = '/opt/cantian/config/deploy_param.json'

NORMAL_STATE, ABNORMAL_STATE = 0, 1


def read_helper(file_path):
    with open(file_path, 'r', encoding='utf-8') as f_handler:
        deploy_data = f_handler.read()
        return deploy_data


def write_helper(file_path, data):
    modes = stat.S_IWRITE | stat.S_IRUSR
    flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT
    if data:
        with os.fdopen(os.open(file_path, flags, modes), 'w', encoding='utf-8') as file:
            file.write(json.dumps(data))
    else:
        with os.fdopen(os.open(file_path, flags, modes), 'w', encoding='utf-8') as file:
            file.truncate()


def get_fs_processed_info(info_path, fs_names):
    json_file_path = os.path.join(info_path, 'processed_snapshots.json')
    init_fs_info = {name: '' for name in fs_names}
    if not os.path.exists(info_path):
        os.makedirs(info_path)
        return init_fs_info

    if not os.path.exists(json_file_path):
        return init_fs_info

    json_file_data = read_helper(json_file_path)
    if not json_file_data:
        return init_fs_info

    return json.loads(json_file_data)


def main(mode, ip_address, main_path):
    """
    mode: create or rollback
    ip_address：dorado ip address
    main_path: main backup file path
    """
    user_name = input()
    passwd = input()

    config_params = json.loads(read_helper(DEPLOY_PARAM_PATH))
    fs_names = [fs_val
                for fs_name, fs_val in config_params.items()
                if fs_name.endswith('_fs')]

    process_fs_path = '{}/cantian_upgrade_snapshots'.format(main_path)
    fs_processed_data = get_fs_processed_info(process_fs_path, fs_names)

    login_data = (ip_address, user_name, passwd)
    rest_client_obj = RestClient(login_data, fs_processed_data)
    for fs_name in fs_names:
        LOG.info("do %s for fs[%s] start", mode, fs_name)
        try:
            _ = rest_client_obj.execute(fs_name, mode)
        except Exception as error:
            LOG.error('error happened when try to {} snapshot of {}, err_info: {}, '
                      'err_traceback: {}'.format(mode, fs_name, str(error), traceback.format_exc(limit=-1)))
            return ABNORMAL_STATE

    if mode == 'rollback':
        query_rollback_process(fs_names, rest_client_obj)

    recoder_path = os.path.join(process_fs_path, 'processed_snapshots.json')
    if mode == 'create':
        new_processed_info = rest_client_obj.processed_fs
        write_helper(recoder_path, new_processed_info)
    elif mode == 'rollback':
        write_helper(recoder_path, '')

    return NORMAL_STATE


def query_rollback_process(fs_names, rest_client_obj):
    """
    查询文件系统回滚状态
    :param fs_names:
    :param rest_client_obj:
    :return:
    """
    query_list = fs_names
    success_list = []
    while query_list:
        for fs_name in query_list:
            rollback_rate, rollbacks_status = rest_client_obj.query_rollback_snapshots_process(fs_name)
            if int(rollbacks_status) == 0:
                success_list.append(fs_name)
        query_list = list(set(query_list) - set(success_list))
        time.sleep(10)


if __name__ == "__main__":
    snapshot_mode, ip, main_backup_file_path = sys.argv[1:]
    RET_VAL = NORMAL_STATE
    try:
        RET_VAL = main(snapshot_mode, ip, main_backup_file_path)
    except Exception as err:
        LOG.error('{} snapshots failed, err_details: {}, '
                  'err_traceback: {}'.format(snapshot_mode, str(err), traceback.format_exc(limit=-1)))
        exit(ABNORMAL_STATE)

    exit(RET_VAL)
