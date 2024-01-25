import json
import sys
import pathlib
import time
import traceback
import os

CUR_PATH, _ = os.path.split(os.path.abspath(__file__))
sys.path.append(str(pathlib.Path(CUR_PATH).parent))


from logic.storage_operate import StorageInf
from utils.client.rest_client import read_helper
from utils.client.ssh_client import SshClient
from om_log import LOGGER


class MigrateFileSystem(StorageInf):
    def __init__(self, ip, user_name, passwd, new_config, old_config=""):
        super(MigrateFileSystem, self).__init__((ip, user_name, passwd))
        self.ssh_client = SshClient(ip, user_name, passwd)
        self.new_config_info = json.loads(read_helper(new_config))
        if old_config:
            self.old_config_info = json.loads(read_helper(old_config))

    def umount_share_file_system(self, share_file_system_name):
        """
        取消挂载
        :param share_file_system_name: 文件系统名称
        :return:
        """
        mount_dir = f"share_{share_file_system_name}"
        self.umount_file_system(mount_dir)

    def mount_share_file_system(self, file_system_name, logic_ip):
        """
        挂载
        :param file_system_name: 文件系统名称
        :param logic_ip: 挂载ip
        :return:
        """
        kerberos_type = self.new_config_info.get("kerberos_key")
        params = f" -o sec={kerberos_type},timeo=50,nosuid,nodev "
        self.mount_file_system(file_system_name, logic_ip, prefix="share", params=params)

    def create_share_file_system_nfs_share(self, share_fs_id, share_path, vstore_id):
        """
        创建共享
        :param share_fs_id: 文件系统id
        :param share_path: 共享路径
        :param vstore_id: 租户id
        :return: 共享id
        """
        data = {
            "SHAREPATH": f"/{share_path}/",
            "vstoreId": vstore_id,
            "FSID": share_fs_id
        }
        return self.create_nfs_share(data)

    def add_share_file_system_nfs_client(self, parent_id, vstore_id, client_name):
        data = {
            "ACCESSVAL": 1,
            "ALLSQUASH": 1,
            "ROOTSQUASH": 1,
            "PARENTID": parent_id,
            "vstoreId": vstore_id,
            "NAME": client_name
        }
        self.add_nfs_client(data)

    def config_mandatory_lock_switch(self, vstore_id):
        """
        配置租户强制锁

        :param vstore_id: 租户ID
        :return:
        """
        def _exec_cmd():
            _cmd = f"change vstore view id={vstore_id}"
            res = self.ssh_client.execute_cmd(_cmd, expect=":/>", timeout=10)
            if "Command executed successfully." in res:
                LOGGER.info("Execute cmd[%s] success", _cmd)
            else:
                err_msg = "Execute cmd[%s], details:%s" % (_cmd, res)
                LOGGER.error(err_msg)
                raise Exception(err_msg)
            _cmd = "change service nfs_config nfsv4_mandatory_lock_switch=enable"
            self.ssh_client.execute_cmd(_cmd, expect="(y/n)", timeout=10)
            _cmd = "y"
            self.ssh_client.execute_cmd(_cmd, expect=":/>", timeout=10)
            if "Command executed successfully." in res:
                LOGGER.info("Execute cmd[%s] success", _cmd)
            else:
                err_msg = "Execute cmd[%s], details:%s" % (_cmd, res)
                LOGGER.error(err_msg)
                raise Exception(err_msg)
        self.ssh_client.create_client()
        try:
            _exec_cmd()
        finally:
            self.ssh_client.close_client()

    def pre_upgrade(self):
        """
        升级前检查
            1、检查当前租户下是否存在对应逻辑端口，不存在报错
            2、检查当前克隆文件系统是否存在，存在报错
        :return:
        """
        LOGGER.info("begin to check migrate share fs info")
        clone_file_system_name = self.new_config_info.get("storage_share_fs")
        clone_file_system_share_logic_ip = self.new_config_info.get("share_logic_ip")
        clone_share_file_system_vstore_id = self.new_config_info.get("vstore_id")
        logic_port_info = self.query_logical_port_info(clone_file_system_share_logic_ip,
                                                       vstore_id=clone_share_file_system_vstore_id)
        if logic_port_info is None:
            err_msg = "Logic port info[%s] is not exist" % clone_file_system_share_logic_ip
            LOGGER.error(err_msg)
            raise Exception(err_msg)
        clone_file_system_info = self.query_file_system_info(clone_file_system_name,
                                                             vstore_id=clone_share_file_system_vstore_id)
        if clone_file_system_info:
            err_msg = "Clone share file system[%s] is exist, details: %s " % (clone_file_system_name,
                                                                              clone_file_system_info)
            LOGGER.error(err_msg)
            raise Exception(err_msg)
        LOGGER.info("Success to check migrate share fs info")

    def upgrade(self):
        """
        step:
            1、克隆share文件系统
            2、分裂share文件系统
            3、创建共享
            4、查询原共享客户端
            5、添加客户端
            6、取消挂载
            7、挂载
            8、打开前置锁开关
        :return:
        """
        file_system_conf_key = [("storage_share_fs", "share_logic_ip")]
        clone_file_system_vstore_id = self.new_config_info.get("vstore_id")
        for fs_type_key, logic_ip_key in file_system_conf_key:
            file_system_name = self.old_config_info.get(fs_type_key)
            clone_file_system_name = self.new_config_info.get(fs_type_key)
            file_system_info = self.query_file_system_info(file_system_name, vstore_id=0)
            file_system_id = file_system_info.get("ID")

            clone_file_system_info = self.query_file_system_info(file_system_name,
                                                                 vstore_id=clone_file_system_vstore_id)
            if not clone_file_system_info:
                clone_file_system_info = self.create_clone_file_system(file_system_id,
                                                                       file_system_name,
                                                                       clone_file_system_vstore_id)
            clone_file_system_id = clone_file_system_info.get("ID")
            split_status = clone_file_system_info.get("SPLITSTATUS")
            split_enable = clone_file_system_info.get("SPLITENABLE")
            if int(split_status) == 1 and split_enable == "false":
                self.split_clone_file_system(clone_file_system_id, action=1, vstore_id=clone_file_system_vstore_id)
            self.query_split_clone_file_system_process(clone_file_system_name, vstore_id=clone_file_system_vstore_id)
            clone_file_system_nfs_info = self.query_nfs_info(clone_file_system_id,
                                                             vstore_id=clone_file_system_vstore_id)
            if clone_file_system_nfs_info:
                clone_share_file_system_nfs_id = clone_file_system_nfs_info[0].get("ID")
                self.delete_nfs_share(clone_share_file_system_nfs_id, vstore_id=clone_file_system_vstore_id)
            clone_file_system_nfs_share_id = self.create_share_file_system_nfs_share(
                clone_file_system_id, file_system_name, clone_file_system_vstore_id)
            share_nfs_info = self.query_nfs_info(file_system_id, vstore_id=0)
            if not share_nfs_info:
                err_msg = "Failed to query fs[%s] nfs share info." % file_system_name
                LOGGER.error(err_msg)
                raise Exception(err_msg)
            share_nfs_id = share_nfs_info[0].get("ID")
            share_nfs_client_config = self.query_nfs_share_auth_client(share_nfs_id, vstore_id=0)
            share_nfs_client_name = share_nfs_client_config[0].get("NAME")
            self.add_share_file_system_nfs_client(clone_file_system_nfs_share_id,
                                                  clone_file_system_vstore_id,
                                                  share_nfs_client_name)
            time.sleep(2)
            self.umount_share_file_system(file_system_name)
            clone_file_system_logic_ip = self.new_config_info.get(logic_ip_key)
            time.sleep(2)
            self.mount_share_file_system(clone_file_system_name, clone_file_system_logic_ip)
            self.config_mandatory_lock_switch(clone_file_system_vstore_id)

    def rollback(self):
        """
        step:
           1、取消挂载
           2、挂载
           3、查询原share文件系统，确认当前clone文件系统是否为原share文件系统克隆文件系统，是执行后续删除操作，否则报错
           3、删除克隆文件系统共享
           4、删除克隆文件系统
        :return:
        """
        file_system_conf_key = [("storage_share_fs", "share_logic_ip")]
        clone_share_file_system_vstore_id = self.new_config_info.get("vstore_id")
        for fs_type_key, logic_key in file_system_conf_key:
            file_system_name = self.old_config_info.get(fs_type_key)
            clone_file_system_name = self.new_config_info.get(fs_type_key)
            file_system_logic_ip = self.old_config_info.get(logic_key)
            time.sleep(2)
            self.umount_share_file_system(clone_file_system_name)
            time.sleep(2)
            self.mount_share_file_system(file_system_name, file_system_logic_ip)
            clone_file_system_info = self.query_file_system_info(clone_file_system_name,
                                                                 vstore_id=clone_share_file_system_vstore_id)
            if not clone_file_system_info:
                return
            clone_file_system_id = clone_file_system_info.get("ID")
            clone_file_system_nfs_share_info = self.query_nfs_info(clone_file_system_id,
                                                                   clone_share_file_system_vstore_id)
            if clone_file_system_nfs_share_info:
                clone_file_system_nfs_share_id = clone_file_system_nfs_share_info[0].get("ID")
                self.delete_nfs_share(clone_file_system_nfs_share_id, clone_share_file_system_vstore_id)
            self.delete_file_system(clone_file_system_id)


def check_version(old_config):
    if not os.path.exists(old_config):
        return True
    config_dir = os.path.dirname(old_config)
    versions_path = os.path.join(config_dir, "..", "versions.yml")
    with open(versions_path, 'r', encoding='utf-8') as file:
        source_version_info = file.readlines()
    version = ''
    for line in source_version_info:
        if 'Version:' in line:
            version = line.split()[-1]
    return version.startswith("2.0.0")


def main():
    action = sys.argv[1]
    new_config = sys.argv[2]
    old_config = ""
    if len(sys.argv) > 3:
        old_config = sys.argv[3]
    if not check_version(old_config):
        LOGGER.info("Current version is not 2.0.0, no need split file system")
        return
    ip_addr = input()
    user_name = input()
    passwd = input()
    migrate_file_system = MigrateFileSystem(ip_addr, user_name, passwd, new_config, old_config)
    migrate_file_system.login()
    try:
        getattr(migrate_file_system, action)()
    finally:
        migrate_file_system.logout()


if __name__ == "__main__":
    try:
        main()
    except Exception as _err:
        LOGGER.error("details:%s, traceback:%s", str(_err), traceback.format_exc())
        exit(1)
