import json
import sys
import os
import pathlib
import traceback
import time
import shutil

CUR_PATH, _ = os.path.split(os.path.abspath(__file__))
sys.path.append(str(pathlib.Path(CUR_PATH).parent))

from logic.storage_operate import StorageInf
from logic.common_func import exec_popen
from utils.client.rest_client import read_helper
from implement.upgrade_version_check import UpgradeVersionCheck
from om_log import LOGGER


class StorageFileSystemSplit(StorageInf):
    def __init__(self, ip, user_name, passwd, config):
        super(StorageFileSystemSplit, self).__init__((ip, user_name, passwd))
        self.config_info = json.loads(read_helper(config))
        self.storage_dbstore_fs = self.config_info.get("storage_dbstore_fs")
        self.storage_dbstore_page_fs = self.config_info.get("storage_dbstore_page_fs")
        self.metadata_logic_ip = self.config_info.get("metadata_logic_ip")
        self.namespace = self.config_info.get("cluster_name")
        self.vstore_id = 0

    @staticmethod
    def _move_files(src_path, dst_path):
        """
        循环遍历文件夹，移动所有文件
        :param src_path: 源目录
        :param dst_path: 目标目录
        :return:
        """
        files = os.listdir(src_path)
        for file_name in files:
            temp_src = os.path.join(src_path, file_name)
            shutil.move(temp_src, dst_path)

    @staticmethod
    def _remove_mount_file_path(fs_name):
        """
        删除dbstore文件系统挂载目录
        :param fs_name: 文件系统名称
        :return:
        """
        mount_dir = f"/mnt/dbdata/remote/{fs_name}"
        rmdir_cmd = f"if [ -d {mount_dir} ];then rm -rf {mount_dir};fi"
        return_code, _, stderr = exec_popen(rmdir_cmd)
        if return_code:
            err_msg = f"Failed remove {mount_dir}, details:{stderr}"
            raise Exception(err_msg)

    def tailor_file_system(self):
        """
        裁剪文件系统目录
        steps:
             1、挂载文件系统
             2、裁剪log所在文件系统
             3、裁剪page所在文件系统
             4、取消挂载
        :return:
        """
        LOGGER.info("Start to tailor dbstore fs.")
        # sleep 避免nfs server 繁忙报错
        time.sleep(2)
        self.mount_file_system(self.storage_dbstore_fs, self.metadata_logic_ip)
        # sleep 避免nfs server 繁忙报错
        time.sleep(2)
        self.mount_file_system(self.storage_dbstore_page_fs, self.metadata_logic_ip)
        self.tailor_log_file_system()
        self.tailor_page_file_system()
        time.sleep(2)
        self._change_group_recursive()
        self.umount_file_system(self.storage_dbstore_fs)
        time.sleep(2)
        self.umount_file_system(self.storage_dbstore_page_fs)
        self._remove_mount_file_path(self.storage_dbstore_fs)
        self._remove_mount_file_path(self.storage_dbstore_page_fs)
        LOGGER.info("Success to tailor dbstore fs.")

    def tailor_log_file_system(self):
        """
        裁剪log所在文件系统
        steps:
            1、删除page_pool_root_dir目录
            2、将ulog_root_dir内部目录上移一层，然后删除ulog_root_di
        :return:
        """
        log_namespace_path = f"/mnt/dbdata/remote/{self.storage_dbstore_fs}/{self.namespace}"
        page_pool_root_dir = os.path.join(log_namespace_path, "page_pool_root_dir")
        ulog_root_dir = os.path.join(log_namespace_path, "ulog_root_dir")
        if os.path.exists(page_pool_root_dir):
            shutil.rmtree(page_pool_root_dir, ignore_errors=True)
        if os.path.exists(ulog_root_dir):
            self._move_files(ulog_root_dir, log_namespace_path)
            shutil.rmtree(ulog_root_dir)

    def tailor_page_file_system(self):
        """
        裁剪page所在文件系统
        steps:
            1、将namespace同名文件删除
            2、删除ulog_root_dir目录
            3、将page_pool_root_dir内的目录上移后，删除page_pool_root_dir
        :return:
        """
        page_namespace_path = f"/mnt/dbdata/remote/{self.storage_dbstore_page_fs}/{self.namespace}"
        namespace_file = os.path.join(page_namespace_path, self.namespace)
        page_pool_root_dir = os.path.join(page_namespace_path, "page_pool_root_dir")
        ulog_root_dir = os.path.join(page_namespace_path, "ulog_root_dir")
        if os.path.isfile(namespace_file):
            os.remove(namespace_file)
        if os.path.exists(ulog_root_dir):
            shutil.rmtree(ulog_root_dir)
        if os.path.exists(page_pool_root_dir):
            self._move_files(page_pool_root_dir, page_namespace_path)
            shutil.rmtree(page_pool_root_dir)

    def add_clone_share_client(self, share_id):
        data = {
            "ACCESSVAL": 1,
            "ALLSQUASH": 1,
            "ROOTSQUASH": 1,
            "PARENTID": share_id,
            "vstoreId": self.vstore_id,
            "NAME": "*"
        }
        self.add_nfs_client(data)

    def create_clone_share(self, clone_fs_id, share_path):
        """
        创建克隆文件系统共享路径
        :param clone_fs_id: 克隆文件系统id
        :param share_path: 共享路劲
        :return:
        """
        clone_share_info = self.query_nfs_info(clone_fs_id, vstore_id=self.vstore_id)
        if clone_share_info:
            _share_id = clone_share_info[0].get("ID")
            self.delete_nfs_share(_share_id, vstore_id=self.vstore_id)
        data = {
            "SHAREPATH": f"/{share_path}/",
            "vstoreId": self.vstore_id,
            "FSID": clone_fs_id
        }
        share_id = self.create_nfs_share(data)
        return share_id

    def clear_dbstore_nfs_share(self, fs_id, clone_fs_id):
        """
        删除文件系统共享
        :param fs_id:文件系统id
        :param clone_fs_id:克隆文件系统ID
        :return:
        """
        LOGGER.info("Begin to clear dbstore nfs share.fs_name:[%s], clone_fs_name:[%s]", self.storage_dbstore_fs,
                    self.storage_dbstore_page_fs)
        for _id in [fs_id, clone_fs_id]:
            share_info = self.query_nfs_info(_id, vstore_id=self.vstore_id)
            if share_info:
                _share_id = share_info[0].get("ID")
                self.delete_nfs_share(_share_id, vstore_id=self.vstore_id)
        LOGGER.info("Success to clear dbstore nfs share.")

    def pre_upgrade(self):
        LOGGER.info("Begin to check dbstore page fs info")
        page_file_system_info = self.query_filesystem_info(self.storage_dbstore_page_fs, vstore_id=self.vstore_id)
        if page_file_system_info:
            err_msg = "File system [%s] is exist." % self.storage_dbstore_page_fs
            LOGGER.error(err_msg)
            raise Exception(err_msg)
        LOGGER.info("Success to check dbstore page fs info")

    def upgrade(self):
        """
        分裂dbstore文件系统
        steps:
           1、登录DM
           2、查询storage_dbstore_fs信息
           3、查询storage_dbstore_page_fs信息，不存在执行步骤4，存在判断：正在分裂执行步骤6，没有分裂执行步骤5
           4、克隆文件系统
           5、分裂文件系统
           6、查询分裂进度
           7、创建共享
           8、添加客户端
           9、裁剪文件目录
           10、删除共享
        :return:
        """
        fs_info = self.query_filesystem_info(self.storage_dbstore_fs, vstore_id=self.vstore_id)
        fs_id = fs_info.get("ID")

        clone_fs_info = self.query_filesystem_info(self.storage_dbstore_page_fs, vstore_id=self.vstore_id)
        if not clone_fs_info:
            clone_fs_info = self.create_clone_file_system(fs_id, self.storage_dbstore_page_fs, vstore_id=self.vstore_id)

        clone_fs_id = clone_fs_info.get("ID")
        split_status = clone_fs_info.get("SPLITSTATUS")
        split_enable = clone_fs_info.get("SPLITENABLE")

        if int(split_status) == 1 and split_enable == "false":
            self.split_clone_file_system(clone_fs_id)

        self.query_split_clone_file_system_process(self.storage_dbstore_page_fs, vstore_id=self.vstore_id)

        for _fs_id, _fs_name in [(fs_id, self.storage_dbstore_fs),
                                 (clone_fs_id, self.storage_dbstore_page_fs)]:
            _share_id = self.create_clone_share(_fs_id, _fs_name)
            self.add_clone_share_client(_share_id)

        self.tailor_file_system()

        self.clear_dbstore_nfs_share(_fs_id, clone_fs_id)

    def rollback(self):
        page_fs_info = self.query_filesystem_info(self.storage_dbstore_page_fs, vstore_id=self.vstore_id)
        if not page_fs_info:
            return
        file_system_id = page_fs_info.get("ID")
        self.delete_file_system(file_system_id)

    def _change_group_recursive(self):
        file_path = os.path.join(CUR_PATH, "..", "env.sh")
        env_conf = read_helper(file_path).split("\n")
        cantian_user = ""
        cantian_group = ""
        for i in env_conf:
            cantian_user = i.split("=")[1] if "cantian_user" in i else cantian_user
            cantian_group = i.split("=")[1] if "cantian_group" in i else cantian_group
        dbstore_fs_path = f"/mnt/dbdata/remote/{self.storage_dbstore_fs}/{self.namespace}"
        dbstore_page_fs_path = f"/mnt/dbdata/remote/{self.storage_dbstore_page_fs}/{self.namespace}"
        LOGGER.info("Start change owner of %s and %s", dbstore_fs_path, dbstore_page_fs_path)
        cmd = f"chown -hR {cantian_user}:{cantian_group} {dbstore_fs_path} &&" \
              f" chown -hR {cantian_user}:{cantian_group} {dbstore_page_fs_path}"
        return_code, _, stderr = exec_popen(cmd)
        if return_code:
            err_msg = f"Failed chown {dbstore_fs_path}  {dbstore_page_fs_path}, details:{stderr}"
            LOGGER.info(err_msg)


def check_version():
    version_check = UpgradeVersionCheck()
    try:
        version_check.read_source_version_info()
    except Exception as _err:
        err_msg = 'obtain source version failed with error: %s', str(_err)
        raise Exception(err_msg) from _err
    return version_check.source_version.startswith("2.0.0")


def main():
    if not check_version():
        LOGGER.info("Current version is not 2.0.0, no need split file system")
        return
    action = sys.argv[1]
    config_file = sys.argv[2]
    if not os.path.exists(config_file):
        err_mgs = "Please input correct config file path."
        raise Exception(err_mgs)
    ip_addr = input()
    user_name = input()
    passwd = input()
    db_store_opt = StorageFileSystemSplit(ip_addr, user_name, passwd, config_file)
    db_store_opt.login()
    try:
        getattr(db_store_opt, action)()
    finally:
        db_store_opt.logout()


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        LOGGER.error("details:%s, traceback:%s", str(err), traceback.format_exc())
        exit(1)
