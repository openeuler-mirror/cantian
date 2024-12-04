import os.path
import shutil

from storage_operate.dr_deploy_operate.dr_deploy_common import KmcResolve
from logic.common_func import read_json_config, exec_popen, write_json_config
from storage_operate.dr_deploy_operate.dr_deploy_common import DRDeployCommon
from logic.storage_operate import StorageInf
from om_log import LOGGER as LOG
from get_config_info import get_env_info


CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
DEPLOY_PARAM_FILE = "/opt/cantian/config/deploy_param.json"
DR_DEPLOY_CONFIG = os.path.join(CURRENT_PATH, "../../../config/dr_deploy_param.json")
RUN_USER = get_env_info("cantian_user")
USER_GROUP = get_env_info("cantian_group")


class UpdateDRParams(object):

    def __init__(self):
        self.deploy_params = read_json_config(DEPLOY_PARAM_FILE)
        self.storage_dbstore_page_fs = self.deploy_params.get("storage_dbstore_page_fs")
        self.storage_dbstore_fs = self.deploy_params.get("storage_dbstore_fs")
        self.storage_metadata_fs = self.deploy_params.get("storage_metadata_fs")
        self.storage_share_fs = self.deploy_params.get("storage_share_fs")
        self.cluster_name = self.deploy_params.get("cluster_name")
        self.mysql_metadata_in_cantian = self.deploy_params.get("mysql_metadata_in_cantian")
        self.dbstore_fs_vstore_id = self.deploy_params.get("dbstore_fs_vstore_id")
        self.deploy_mode = self.deploy_params.get("deploy_mode")

    @staticmethod
    def restart_cantian_exporter():
        """
        容灾告警需要重启cantian_exporter
        :return:
        """
        cmd = "ps -ef | grep \"python3 /opt/cantian/ct_om/service/cantian_exporter/exporter/execute.py\"" \
              " | grep -v grep | awk '{print $2}' | xargs kill -9"
        exec_popen(cmd)

    def copy_dr_deploy_param_file(self):
        """
        处理 dbstore_unify 模式下的 dr_deploy_param.json 文件读取逻辑，
        如果不是 dbstore_unify 模式，则从共享路径中读取文件。
        :return: dr_deploy_param_file 的路径
        """
        if self.deploy_mode == "dbstor":
            remote_dir = "/opt/cantian/config/remote/"
            dr_deploy_param_file = os.path.join(remote_dir, "dr_deploy_param.json")

            # 创建 remote 目录并设置权限
            if not os.path.exists(remote_dir):
                os.makedirs(remote_dir)
                chown_command = f'chown "{RUN_USER}":"{USER_GROUP}" "{remote_dir}"'
                LOG.info(f"Executing command: {chown_command}")
                return_code, output, stderr = exec_popen(chown_command, timeout=30)

                if return_code:
                    err_msg = f"Execution of chown command failed, output: {output}, stderr: {stderr}"
                    LOG.error(err_msg)
                    raise Exception(err_msg)
            else:
                if os.path.exists(dr_deploy_param_file):
                    os.remove(dr_deploy_param_file)
                    LOG.info(f"Removing {dr_deploy_param_file}")

            dbstor_command = (
                f'su -s /bin/bash - "{RUN_USER}" -c \''
                f'dbstor --copy-file --fs-name="{self.storage_share_fs}" '
                f'--source-dir="/" '
                f'--target-dir="{remote_dir}" '
                f'--file-name="/dr_deploy_param.json"\''
            )
            LOG.info(f"Executing command: {dbstor_command}")
            return_code, output, stderr = exec_popen(dbstor_command, timeout=100)

            if return_code:
                err_msg = f"Execution of dbstor command failed, output: {output}, stderr: {stderr}"
                LOG.error(err_msg)
                raise Exception(err_msg)
        else:
            # 处理非 dbstore_unify 模式的逻辑
            share_path = f"/mnt/dbdata/remote/metadata_{self.storage_metadata_fs}"
            dr_deploy_param_file = os.path.join(share_path, "dr_deploy_param.json")

        # 检查文件是否存在
        if not os.path.exists(dr_deploy_param_file):
            err_msg = "Dr deploy param file does not exist, please check whether dr deploy is successful."
            LOG.error(err_msg)
            raise Exception(err_msg)

        return dr_deploy_param_file

    def execute(self):
        dr_deploy_param_file = self.copy_dr_deploy_param_file()
        dr_deploy_params = read_json_config(dr_deploy_param_file)
        dm_ip = dr_deploy_params.get("dm_ip")
        dm_user = dr_deploy_params.get("dm_user")
        dr_deploy_params["node_id"] = self.deploy_params.get("node_id")
        dr_deploy_params["cantian_vlan_ip"] = self.deploy_params.get("cantian_vlan_ip")
        dm_passwd = input()
        storage_operate = StorageInf((dm_ip, dm_user, dm_passwd))
        try:
            storage_operate.login()
        except Exception as er:
            err_msg = f"Login DM failed, please check.details:ip[{dm_ip}], user[{dm_user}], errors:{str(er)}"
            LOG.error(err_msg)
            raise Exception(err_msg) from er

        try:
            self.check_dr_infos(dr_deploy_params, storage_operate)
        finally:
            storage_operate.logout()

        target_path = "/opt/cantian"
        current_real_path = os.path.realpath(CURRENT_PATH)

        if not current_real_path.startswith(target_path):
            try:
                shutil.copy(DEPLOY_PARAM_FILE, os.path.join(CURRENT_PATH, "../../../config"))
            except Exception as _err:
                LOG.info(f"copy DEPLOY_PARAM_FILE failed")
        encrypted_pwd = KmcResolve.kmc_resolve_password("encrypted", dm_passwd)
        dr_deploy_params["dm_pwd"] = encrypted_pwd
        write_json_config(DR_DEPLOY_CONFIG, dr_deploy_params)
        os.chmod(os.path.join(CURRENT_PATH, "../../../config/dr_deploy_param.json"), mode=0o644)
        if not current_real_path.startswith(target_path):
            try:
                shutil.copy(DR_DEPLOY_CONFIG, "/opt/cantian/config")
            except Exception as _err:
                LOG.info(f"copy DR_DEPLOY_CONFIG failed")
        LOG.info("Restart cantian_exporter process")
        self.restart_cantian_exporter()
        LOG.info("Update dr params success.")

    def check_dr_infos(self, dr_deploy_params, storage_operate):
        """
        检查容灾pair对信息是否存在
        :param dr_deploy_params:
        :param storage_operate:
        :return:
        """
        page_fs_pair_id = dr_deploy_params.get("page_fs_pair_id")
        meta_fs_pair_id = dr_deploy_params.get("meta_fs_pair_id")
        hyper_domain_id = dr_deploy_params.get("hyper_domain_id")
        hyper_metro_vstore_pair_id = dr_deploy_params.get("vstore_pair_id")
        ulog_fs_pair_id = dr_deploy_params.get("ulog_fs_pair_id")
        dr_deploy_opt = DRDeployCommon(storage_operate)
        LOG.info(f"begin to check hyper metro domain[{hyper_domain_id}]")
        dr_deploy_opt.query_hyper_metro_domain_info(hyper_domain_id)
        LOG.info(f"begin to check hyper metro vstore pair[{hyper_metro_vstore_pair_id}]")
        dr_deploy_opt.query_hyper_metro_vstore_pair_info(hyper_metro_vstore_pair_id)
        LOG.info(f"begin to check hyper metro filesystem pair[{ulog_fs_pair_id}]")
        dr_deploy_opt.query_hyper_metro_filesystem_pair_info_by_pair_id(ulog_fs_pair_id)
        LOG.info(f"begin to check remote replication pair[{page_fs_pair_id}]")
        dr_deploy_opt.query_remote_replication_pair_info_by_pair_id(page_fs_pair_id)
        if not self.mysql_metadata_in_cantian:
            LOG.info(f"begin to check remote replication pair[{meta_fs_pair_id}]")
            dr_deploy_opt.query_remote_replication_pair_info_by_pair_id(meta_fs_pair_id)

