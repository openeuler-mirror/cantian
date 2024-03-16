import os
import sys
import json
import time
import traceback
import pathlib

CUR_PATH, _ = os.path.split(os.path.abspath(__file__))

sys.path.append(str(pathlib.Path(CUR_PATH).parent))

from logic.storage_operate import StorageInf
from storage_operate.dr_deploy_operate.dr_deploy_common import DRDeployCommon
from utils.client.rest_client import get_cur_timestamp, read_helper, write_helper
from om_log import REST_LOG as LOG

DEPLOY_PARAM_PATH = '/opt/cantian/config/deploy_param.json'

NORMAL_STATE, ABNORMAL_STATE = 0, 1


class SnapShotRestClient(object):
    def __init__(self, login_tuple, processed_fs):
        self.storage_operate = StorageInf(login_tuple=login_tuple)
        self.upgrade_version = get_cur_timestamp()
        self.processed_fs = processed_fs
        self.handler = {
            'create': self.create_snapshots,
            'rollback': self.rollback_snapshots,
            "delete": self.delete_snapshots
        }

    @staticmethod
    def exception_handler(err_msg=None, cur_mode=None):
        err_info = '[current_mode] {}, [err_info] {}'.format(cur_mode, err_msg)
        LOG.error(err_info)
        raise Exception(err_info)

    def check_dr_site(self):
        """
        判断当前是否为备端，不执行打快照和回滚快照
        :return:
        """
        if not self.storage_operate.rest_client.token:
            self.storage_operate.login()
        config_params = json.loads(read_helper(DEPLOY_PARAM_PATH))
        storage_dbstore_page_fs = config_params.get("storage_dbstore_page_fs")
        page_fs_info = self.storage_operate.query_filesystem_info(storage_dbstore_page_fs)
        page_fs_id = page_fs_info.get("ID")
        ulog_fs_info = self.storage_operate.query_filesystem_info(storage_dbstore_page_fs)
        ulog_fs_id = ulog_fs_info.get("ID")
        dr_deploy_opt = DRDeployCommon(self.storage_operate)
        page_pair_info = dr_deploy_opt.query_remote_replication_pair_info(page_fs_id)
        ulog_pair_info = dr_deploy_opt.query_hyper_metro_filesystem_pair_info(ulog_fs_id)
        if page_pair_info:
            secondary = page_pair_info[0].get("ISPRIMARY")
            return secondary == "false"
        if ulog_pair_info:
            secondary = ulog_pair_info[0].get("ISPRIMARY")
            return secondary == "false"
        LOG.info("Current node is not dr or is primary")
        return False

    def create_snapshots(self, fs_name, vstore_id=0):
        if self.processed_fs.get(fs_name):
            return NORMAL_STATE
        fs_info = self.storage_operate.query_filesystem_info(fs_name, vstore_id=vstore_id)
        if not fs_info:
            err_msg = "file system [%s] is not exist, please check." % fs_name
            self.exception_handler(err_msg=err_msg, cur_mode='create')
        fs_id = fs_info.get("ID")
        reg_version = '{}_{}'.format(fs_name, self.upgrade_version).replace('.', '_')
        snapshot_name = '{}_{}'.format(reg_version, str(get_cur_timestamp()))
        snapshot_info = self.storage_operate.create_file_system_snapshot(snapshot_name, fs_id, vstore_id=vstore_id)
        snapshot_id = snapshot_info.get('ID')
        self.processed_fs[fs_name] = snapshot_id
        return NORMAL_STATE

    def rollback_snapshots(self, fs_name, vstore_id=0):
        # 若该fs_name的快照未成功创建则无需回退
        if not self.processed_fs.get(fs_name):
            return NORMAL_STATE
        snapshot_id = self.processed_fs.get(fs_name)
        try:
            snapshot_info = self.storage_operate.query_file_system_snapshot_info(snapshot_id)
        except Exception as e:
            if str(e).find("1077937875") != -1 or str(e).find("snapshot does not exist") != -1:
                err_msg = "The snapshot is already not exist, details:%s" % str(e)
                LOG.info(err_msg)
                return NORMAL_STATE
            else:
                raise e
        rollback_status = snapshot_info.get("rollbackStatus")
        # rollback_status == "1"表示当前正在进行回退
        if rollback_status == "1":
            return NORMAL_STATE
        self.storage_operate.rollback_file_system_snapshot(snapshot_id, vstore_id)
        return NORMAL_STATE

    def delete_snapshots(self, fs_name, vstore_id=0):
        # 若该fs_name的快照未成功创建则无需回退
        if not self.processed_fs.get(fs_name):
            return NORMAL_STATE
        snapshot_id = self.processed_fs.get(fs_name)
        try:
            snapshot_info = self.storage_operate.query_file_system_snapshot_info(snapshot_id)
        except Exception as e:
            if str(e).find("1077937875") != -1 or str(e).find("snapshot does not exist") != -1:
                err_msg = "The snapshot is already not exist, details:%s" % str(e)
                LOG.info(err_msg)
                return NORMAL_STATE
            else:
                raise e
        if not snapshot_info:
            return NORMAL_STATE
        else:
            self.storage_operate.delete_file_system_snapshot(snapshot_id)
            return NORMAL_STATE

    def execute(self, fs_name, mode, vstore_id=0):
        if isinstance(self.processed_fs, str):
            self.processed_fs = json.loads(self.processed_fs)

        if not self.storage_operate.rest_client.token:
            self.storage_operate.login()

        return self.handler.get(mode)(fs_name, vstore_id)


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
    vstore_id = config_params.get("vstore_id", 0)
    dbstore_fs_vstore_id = config_params.get("dbstore_fs_vstore_id", 0)
    fs_names_type = []
    for fs_type, fs_name in config_params.items():
        if fs_type.endswith('_fs') and fs_type.startswith("storage") and fs_type == "storage_share_fs":
            fs_names_type.append((fs_name, fs_type, vstore_id))
        elif fs_type.endswith('_fs') and fs_type.startswith("storage") and fs_type == "storage_dbstore_fs":
            fs_names_type.append((fs_name, fs_type, dbstore_fs_vstore_id))
        elif fs_type.endswith('_fs') and fs_type.startswith("storage"):
            fs_names_type.append((fs_name, fs_type, 0))
    fs_names = [
        fs_val
        for fs_name, fs_val in config_params.items()
        if fs_name.endswith('_fs') and fs_name.startswith("storage")
    ]
    process_fs_path = '{}/cantian_upgrade_snapshots'.format(main_path)
    fs_processed_data = get_fs_processed_info(process_fs_path, fs_names)

    login_data = (ip_address, user_name, passwd)
    rest_client_obj = SnapShotRestClient(login_data, fs_processed_data)
    # 检查当前是否为备端，是不打快照
    if rest_client_obj.check_dr_site():
        return NORMAL_STATE
    for fs_name, _, _vstore_id in fs_names_type:
        LOG.info("do %s for fs[%s] start", mode, fs_name)
        try:
            _ = rest_client_obj.execute(fs_name, mode, _vstore_id)
        except Exception as error:
            LOG.error('error happened when try to {} snapshot of {}, err_info: {}, '
                      'err_traceback: {}'.format(mode, fs_name, str(error), traceback.format_exc(limit=-1)))
            return ABNORMAL_STATE

    if mode == 'rollback':
        query_rollback_process(fs_names_type, rest_client_obj.storage_operate)

    recoder_path = os.path.join(process_fs_path, 'processed_snapshots.json')
    if mode == 'create':
        new_processed_info = rest_client_obj.processed_fs
        write_helper(recoder_path, new_processed_info)
    elif mode == 'delete':
        write_helper(recoder_path, '')

    return NORMAL_STATE


def query_rollback_process(fs_names_type, rest_client_obj):
    """
    查询文件系统回滚状态
    :param fs_names_type:
    :param rest_client_obj:
    :return:
    """
    query_list = fs_names_type
    success_list = []
    while query_list:
        for item in query_list:
            fs_name, fs_type, _vstore_id = item
            data = rest_client_obj.query_rollback_snapshots_process(fs_name, vstore_id=_vstore_id)
            rollback_rate, rollback_status = data.get("rollbackRate"), data.get("rollbackStatus")
            if int(rollback_status) == 0:
                success_list.append(item)
            LOG.info("Filesystem[%s] rollback status[%s], process[%s]", fs_name, rollback_status, rollback_rate)
        query_list = list(set(query_list) - set(success_list))
        time.sleep(30)


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
