# coding=utf-8
import os
import time

from logic.storage_operate import StorageInf
from utils.config.rest_constant import Constant, RepFileSystemNameRule
from logic.common_func import exec_popen
from logic.common_func import retry
from om_log import LOGGER as LOG


CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))


class RemoteStorageOPT(object):
    def __init__(self, storage_operate: StorageInf, remote_device_id: str):
        self.storage_opt = storage_operate
        self.rest_client = self.storage_opt.rest_client
        self.remote_device_id = remote_device_id

    def query_remote_storage_vstore_info(self, vstore_id: str) -> list:
        LOG.info("Start to query remote storage vstore info, vstoreId[%s]", vstore_id)
        url = Constant.REMOTE_EXECUTE
        data = {
            "device_id": self.remote_device_id,
            "url": Constant.CREATE_VSTORE.replace("{deviceId}", "xxx"),
            "method": "GET",
            "body": {
                "ID": f"{vstore_id}"
            }
        }
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to query remote storage vstore info,vstoreId[%s]" % vstore_id
        rsp_data = StorageInf.omstask_result_parse(err_msg, res)
        LOG.info("Success to query remote storage vstore info, vstoreId[%s]", vstore_id)
        return rsp_data

    def query_remote_storage_system_info(self) -> dict:
        LOG.info("Start to query remote storage system info.")
        url = Constant.REMOTE_EXECUTE
        data = {
            "device_id": self.remote_device_id,
            "url": Constant.QUERY_SYSTEM_INFO.replace("{deviceId}", "xxx"),
            "method": "GET",
            "body": {}
        }
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to query remote storage system info"
        rsp_data = StorageInf.omstask_result_parse(err_msg, res)
        LOG.info("Success to query remote storage system info.")
        return rsp_data

    def query_remote_storage_vstore_filesystem_num(self, vstore_id):
        url = Constant.REMOTE_EXECUTE
        remote_url = Constant.QUERY_FILE_SYSTEM_NUM
        data = {
            "device_id": self.remote_device_id,
            "url": remote_url.replace("{deviceId}", "xxx"),
            "method": "GET",
            "body": {
                "vstoreId": vstore_id
            }
        }
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to query remote storage filesystem num,vstoreId[%s]" % vstore_id
        rsp_data = StorageInf.omstask_result_parse(err_msg, res)
        LOG.info("Success to query remote storage filesystem num, vstoreId[%s]", vstore_id)
        return rsp_data

    def query_remote_filesystem_info(self, fs_name: str, vstore_id: str):
        url = Constant.REMOTE_EXECUTE
        data = {
            "device_id": self.remote_device_id,
            "url": Constant.CREATE_FS.replace("{deviceId}", "xxx") + "?filter=NAME::%s" % fs_name,
            "method": "GET",
            "body": {
                "vstoreId": vstore_id
            }
        }
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to query remote filesystem[%s] info, vstore_id[%s]" % (fs_name, vstore_id)
        rsp_data = StorageInf.omstask_result_parse(err_msg, res)
        fs_info = dict()
        for filesystem_info in rsp_data:
            if filesystem_info.get("NAME") == fs_name:
                fs_info = filesystem_info
                break
        LOG.info("Success to query remote filesystem[%s] info, vstore_id[%s]", fs_name, vstore_id)
        return fs_info

    def query_remote_storage_pool_info(self, pool_id: str) -> dict:
        """
        查询远端存储池信息
        """
        url = Constant.REMOTE_EXECUTE
        remote_url = Constant.QUERY_POOL
        data = {
            "device_id": self.remote_device_id,
            "url": remote_url.replace("{deviceId}", "xxx"),
            "method": "GET",
            "body": {
                "ID": pool_id
            }
        }
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to query remote storage pool info,poolId[%s]" % pool_id
        rsp_data = StorageInf.omstask_result_parse(err_msg, res)
        LOG.info("Success to query remote storage pool info, poolId[%s]", pool_id)
        return rsp_data


class KmcResolve(object):
    @staticmethod
    def kmc_resolve_password(mode, plain_text):
        """
        密码解密
        :param mode:  encrypted/decrypted
        :param plain_text: 加解密内容
        :return:
        """
        resolve_file_path = os.path.join(CURRENT_PATH, "../../cantian_common/crypte_adapter.py")
        cmd = "su -s /bin/bash - cantian -c \"export LD_LIBRARY_PATH=/opt/cantian/dbstor/lib:${LD_LIBRARY_PATH} " \
              "&& echo -e %s | python3 -B %s %s\"" % (plain_text, resolve_file_path, mode)
        return_code, output, stderr = exec_popen(cmd)
        if return_code == 1:
            raise Exception("resolve password failed.")
        return output


class DRDeployCommon(object):
    def __init__(self, storage_operate: StorageInf):
        self.storage_opt = storage_operate
        self.device_id = self.storage_opt.rest_client.device_id
        self.rest_client = self.storage_opt.rest_client

    def query_storage_system_info(self) -> dict:
        """
        查询存储系统状态
        :return:
        """
        LOG.info("Start to query storage system info.")
        url = Constant.QUERY_SYSTEM_INFO.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query storage system info"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to query storage system info.")
        return rsp_data

    def query_remote_device_info(self, remote_device_id=None) -> list:
        """
        查询远端设备信息
        :param remote_device_id: 远端设备id
        :return:list
        """
        LOG.info("Start to query remote device info.")
        url = Constant.QUERY_REMOTE_DEVICE_INFO.format(deviceId=self.device_id)
        if remote_device_id:
            url = url + f"/{remote_device_id}"
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query remote device info"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to query remote device info")
        return rsp_data

    def query_vstore_filesystem_num(self, vstore_id: str):
        """
        查询租户下文件系统数目
        :param vstore_id: 租户id
        :return:
        """
        LOG.info("Start to query vstore file system num.")
        url = Constant.QUERY_FILE_SYSTEM_NUM.format(deviceId=self.device_id)
        data = {
            "vstoreId": vstore_id
        }
        res = self.rest_client.normal_request(url, data=data, method="get")
        err_msg = "Failed to query vstore file system num"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to query vstore file system num.")
        return rsp_data

    def query_license_info(self):
        """
        查询license信息
        :return:
        """
        LOG.info("Start to query license info.")
        url = Constant.QUERY_LICENSE_FEATURE.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query license info"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to query license info.")
        return rsp_data

    @retry(retry_times=3, wait_times=20, log=LOG, task="query_hyper_metro_domain_info")
    def query_hyper_metro_domain_info(self, domain_id=None):
        """
        查询文件系统双活域信息
        :param domain_id: 文件系统双活域id
        :return:
        """
        LOG.info("Start to query hyper metro domain info.")
        url = Constant.HYPER_METRO_DOMAIN.format(deviceId=self.device_id)
        if domain_id:
            url = url + "/" + domain_id
        res = self.rest_client.normal_request(url, method="get")
        err_msg = "Failed to query hyper metro domain info"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to query hyper metro domain info.")
        return rsp_data

    def query_hyper_metro_vstore_pair_info(self, vstore_pair_id=None) -> dict:
        LOG.info("Start to query hyper metro vstore pair info.")
        url = Constant.HYPER_METRO_VSTORE_PAIR.format(deviceId=self.device_id)
        if vstore_pair_id:
            url = url + "/" + vstore_pair_id
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query hyper metro vstore pair info"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to query hyper metro vstore pair info.")
        return rsp_data

    def query_hyper_metro_filesystem_pair_info(self, filesystem_id: str) -> list:
        url = (Constant.QUERY_HYPER_METRO_FILE_SYSTEM_PAIR + "?ASSOCIATEOBJTYPE=40&ASSOCIATEOBJID={fs_id}"). \
            format(deviceId=self.device_id, fs_id=filesystem_id)
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query hyper metro file system pair info"
        rsp_data = StorageInf.result_parse(err_msg, res)
        return rsp_data

    def query_hyper_metro_filesystem_pair_info_by_pair_id(self, pair_id: str) -> dict:
        """
        根据文件系统双活pair id查询双活pair信息
        :param pair_id:
        :return:
        """
        url = Constant.DELETE_HYPER_METRO_PAIR.format(deviceId=self.device_id, id=pair_id)
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query hyper metro filesystem pair info by pair id[%s]" % pair_id
        rsp_data = StorageInf.result_parse(err_msg, res)
        return rsp_data

    def query_remote_replication_pair_info(self, filesystem_id: str) -> list:
        """
        查询文件系统远程复制pair对信息
        :param filesystem_id: 文件系统id
        :return: list
        """
        url = (Constant.QUERY_REPLICATION_FILE_SYSTEM_PAIR + "?ASSOCIATEOBJTYPE=40&ASSOCIATEOBJID={fs_id}") \
            .format(deviceId=self.device_id, fs_id=filesystem_id)
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query remote replication filesystem[%s] info" % filesystem_id
        rsp_data = StorageInf.result_parse(err_msg, res)
        return rsp_data

    def query_remote_replication_pair_info_by_pair_id(self, pair_id: str) -> dict:
        """
        通过远程复制pair id查询pair信息
        :param pair_id: 远程复制pair id
        :return:
        """
        url = Constant.REMOTE_REPLICATION_FILESYSTEM_PAIR_OPT.format(deviceId=self.device_id, id=pair_id)
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query remote replication file system info by pair id[%s]" % pair_id
        rsp_data = StorageInf.result_parse(err_msg, res)
        return rsp_data

    def query_filesystem_for_replication(self, remote_device_id: str) -> list:
        """
        查询远端设备可用用作为远程复制或者双活的远端fs
        :param remote_device_id:
        :return:
        """
        LOG.info("Start to query filesystem for replication info.")
        url = (Constant.QUERY_FILESYSTEM_FOR_REPLICATION + "?rmtDeviceId={remote_device_id}&RSSType=24"). \
            format(deviceId=self.device_id, remote_device_id=remote_device_id)
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query filesystem for replication info"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to query filesystem for replication info.")
        return rsp_data

    def query_omtask_process(self, task_id: str, timeout: int) -> None:
        LOG.info("Start to query task[%s] process", task_id)
        url = Constant.QUERY_TASK_PROCESS.format(id=task_id)
        while timeout:
            res = self.rest_client.normal_request(url, "get")
            err_msg = "Failed to query task[%s] process" % task_id
            rsp_data = StorageInf.omstask_result_parse(err_msg, res)
            task_status = rsp_data.get("taskStatus")
            name = rsp_data.get("name")
            description = rsp_data.get("description")
            current_step_index = description.get("currentStepIndex")
            step_count = description.get("stepCount")
            LOG.info("Task[%s] status [%s], running process[%s/%s]",
                     name, task_status, current_step_index, step_count)
            if task_status == "success":
                break
            if task_status in ["executing", "wait"]:
                time.sleep(10)
                timeout -= 10
                continue
            else:
                err_msg = "Failed to create replication filesystem pair"
                LOG.error(err_msg)
                raise Exception(err_msg)

    @retry(retry_times=3, wait_times=20, log=LOG, task="create_filesystem_hyper_metro_domain")
    def create_filesystem_hyper_metro_domain(self, dev_name: str, dev_esn: str, dev_id: str, domain_name: str) -> dict:
        """
        创建文件系统双活域
        :param dev_name: 远端设备名称
        :param dev_esn: 远端设备esn号
        :param dev_id: 远端设备ID
        :param domain_name: 双活域名称
        :return: dict
        """
        LOG.info("Start to create filesystem hyper metro domain.")
        data = {
            "NAME": domain_name,
            "workMode": "1",
            "isShareAuthenticationSync": False,
            "DESCRIPTION": "",
            "REMOTEDEVICES": [
                {
                    "devId": dev_id,
                    "devESN": dev_esn,
                    "devName": dev_name
                }
            ]
        }
        url = Constant.HYPER_METRO_DOMAIN.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to create filesystem hyper metro domain"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to create filesystem hyper metro domain.")
        return rsp_data

    @retry(retry_times=3, wait_times=20, log=LOG, task="create_hyper_metro_vstore_pair")
    def create_hyper_metro_vstore_pair(self, domain_id: str, local_vstore_id: str, remote_vstore_id: str) -> dict:
        """
        创建双活租户pair
        :param domain_id: 文件系统双活域id
        :param local_vstore_id: 本端租户id
        :param remote_vstore_id: 远端租户id
        :return: dict
        """
        LOG.info("Start to create hyper metro vstore pair.")
        data = {
            "DOMAINID": domain_id,
            "LOCALVSTOREID": local_vstore_id,
            "REMOTEVSTOREID": remote_vstore_id,
            "REPTYPE": "1",
            "PREFERREDMODE": "0",
            "isNetworkSync": False
        }
        url = Constant.HYPER_METRO_VSTORE_PAIR.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to create hyper metro vstore pair"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to create hyper metro vstore pair.")
        return rsp_data

    @retry(retry_times=3, wait_times=20, log=LOG, task="create_hyper_metro_filesystem_pair")
    def create_hyper_metro_filesystem_pair(self, filesystem_id: str, pool_id: str, vstore_pair_id: str) -> dict:
        """
        调用omtask接口创建双活文件系统
        :param filesystem_id: 本端文件系统id
        :param pool_id: 远端存储池id
        :param vstore_pair_id: 双活租户id
        :return:
        """
        LOG.info("Start to create hyper metro filesystem pair.")
        data = {
            "vstorePairID": vstore_pair_id,
            "remoteStoragePoolId": pool_id,
            "objs": [filesystem_id]
        }
        url = Constant.CREATE_HYPER_METRO_FILESYSTEM_PAIR
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to create hyper metro filesystem pair"
        rsp_data = StorageInf.omstask_result_parse(err_msg, res)
        LOG.info("Success to create hyper metro filesystem pair.")
        return rsp_data

    @retry(retry_times=3, wait_times=20, log=LOG, task="create_remote_replication_filesystem_pair")
    def create_remote_replication_filesystem_pair(self, remote_device_id: str,
                                                  remote_pool_id: str,
                                                  local_fs_id: str,
                                                  remote_name_rule=1,
                                                  name_suffix=None):
        """

        :param remote_device_id: 远端设备id
        :param remote_pool_id: 远端存储池id
        :param local_fs_id:  组复制pair的文件系统id
        :param remote_name_rule: 远端文件系统命名规则，0，表示系统自动化创建，1，表示与与主端保持一直，2表示自定义前后缀
        :param name_suffix: 当remote_name_rule为2时，该字段不能为None
        :return:
        """
        LOG.info("Start to create remote replication filesystem[%s] pair.", local_fs_id)
        data = {
            "type": "filesystem",
            "replication": {
                "replicationModel": 2,
                "remoteStorageId": remote_device_id,
                "speed": 2,
                "recoveryPolicy": 2,
                "remoteStoragePoolId": remote_pool_id,
                "remoteVstoreId": 0,
                "remoteNameRule": remote_name_rule,
                "enableCompress": False,
                "syncPair": True,
                "syncSnapPolicy": 0,
                "createType": 0,
                "reservedConsistencySnapSwitch": 0
            },
            "objs": [
                {
                    "id": local_fs_id,
                    "vstoreId": 0
                }
            ]
        }
        if remote_name_rule == 2:
            data["replication"]["namePrefix"] = RepFileSystemNameRule.NamePrefix
            data["replication"]["nameSuffix"] = name_suffix
        url = Constant.CREATE_REMOTE_REPLICATION_FILESYSTEM_PAIR
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to create remote replication filesystem pair"
        rsp_data = StorageInf.omstask_result_parse(err_msg, res)
        LOG.info("Success to create remote replication filesystem[%s] pair.", local_fs_id)
        return rsp_data

    @retry(retry_times=3, wait_times=20, log=LOG, task="split_remote_replication_filesystem_pair")
    def split_remote_replication_filesystem_pair(self, pair_id: str) -> dict:
        """
        分裂远程复制pair
        :param pair_id: 远程复制pair id
        :return: {}
        """
        LOG.info("Start to split remote replication filesystem pair[%s].", pair_id)
        data = {
            "ID": pair_id
        }
        url = Constant.SPLIT_REMOTE_REPLICATION_FILESYSTEM_PAIR.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="put")
        err_msg = "Failed to split remote replication filesystem pair"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to split remote replication filesystem pair")
        return rsp_data

    @retry(retry_times=3, wait_times=20, log=LOG, task="remote_replication_filesystem_pair_cancel_secondary_write_lock")
    def remote_replication_filesystem_pair_cancel_secondary_write_lock(self, pair_id: str) -> dict:
        """
        取消远程复制从资源写保护
        :param pair_id: 远程复制id
        :return:
        """
        LOG.info("Start to cancel secondary write lock.")
        data = {
            "ID": pair_id
        }
        url = Constant.CANCEL_SECONDARY_WRITE_LOCK.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="put")
        err_msg = "Failed to to cancel secondary write lock"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to cancel secondary write lock.")
        return rsp_data

    @retry(retry_times=3, wait_times=20, log=LOG, task="remote_replication_filesystem_pair_set_secondary_write_lock")
    def remote_replication_filesystem_pair_set_secondary_write_lock(self, pair_id: str) -> dict:
        """
        设置远程复制从资源写保护
        :param pair_id: 远程复制iD
        :return:
        """
        LOG.info("Start to set secondary write lock.")
        data = {
            "ID": pair_id
        }
        url = Constant.SET_SECONDARY_WRITE_LOCK.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="put")
        err_msg = "Failed to set secondary write lock."
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to set secondary write lock.")
        return rsp_data

    @retry(retry_times=3, wait_times=20, log=LOG, task="sync_remote_replication_filesystem_pair")
    def sync_remote_replication_filesystem_pair(self, pair_id: str, vstore_id: str, is_full_copy: bool) -> None:
        """
        触发远程复制
        :param pair_id: 远程复制pair id
        :param vstore_id: 租户id
        :param is_full_copy: bool, 是否触发全量同步
        :return:
        """
        LOG.info("Start to sync remote replication filesystem pair.")
        data = {
            "ID": pair_id,
            "vstoreId": vstore_id,
            "isFullCopy": is_full_copy
        }
        url = Constant.SYNC_REMOTE_REPLICATION_FILESYSTEM_PAIR.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="put")
        err_msg = "Failed to sync remote replication filesystem pair"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to sync remote replication filesystem pair.")
        return rsp_data

    def delete_remote_replication_filesystem_pair(self, pair_id, is_local_del=False) -> dict:
        LOG.info("Start to delete remote replication filesystem pair[%s].", pair_id)
        data = {
            "ISLOCALDELETE": is_local_del,
            "TOSYNCSRWHENDELETE": False
        }
        url = Constant.REMOTE_REPLICATION_FILESYSTEM_PAIR_OPT.format(deviceId=self.device_id, id=pair_id)
        res = self.rest_client.normal_request(url, data=data, method="delete")
        err_msg = "Start to delete remote replication filesystem pair[%s]" % pair_id
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to delete remote replication filesystem pair[%s].", pair_id)
        return rsp_data

    def delete_hyper_metro_filesystem_pair(self, pair_id: str, vstore_id: str, is_local_del=False) -> dict:
        """
        删除双活pair
        :param pair_id: 双活pair id
        :param vstore_id: 双活pair所在租户id
        :param is_local_del:  是否本地删除，默认是False，当链路状态不正常是使用True， 即首次删除返回错误码为1077674261执行
        :return:
        """
        LOG.info("Start to delete hyper metro filesystem pair")
        url = Constant.DELETE_HYPER_METRO_PAIR.format(deviceId=self.device_id, id=pair_id)
        data = {
            "ISLOCALDELETE": is_local_del,
            "vstoreId": vstore_id
        }
        res = self.rest_client.normal_request(url, data=data, method="delete")
        err_mgs = "Failed to to delete hyper metro filesystem pair"
        rsp_data = StorageInf.result_parse(err_mgs, res)
        LOG.info("Success to delete hyper metro filesystem pair")
        return rsp_data

    @retry(retry_times=3, wait_times=20, log=LOG, task="delete_hyper_metro_vstore_pair")
    def delete_hyper_metro_vstore_pair(self, pair_id: str, is_local_del=False) -> dict:
        """
        删除双活租户pair
        :param pair_id: 双活pair id
        :param is_local_del: 是否本地删除，默认是False，当链路状态不正常是使用True， 即首次删除返回错误码为1077674261执行
        :return:
        """
        LOG.info("Start to delete hyper metro vstore pair")
        url = Constant.DELETE_HYPER_METRO_VSTORE_PAIR.format(deviceId=self.device_id, id=pair_id)
        data = {
            "isLocalDelete": is_local_del
        }
        res = self.rest_client.normal_request(url, data=data, method="delete")
        err_msg = "Failed to delete hyper metro vstore pair"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to delete hyper metro vstore pair.")
        return rsp_data

    def split_filesystem_hyper_metro_domain(self, domain_id: str) -> dict:
        """
        分裂文件系统双活域
        :param domain_id: 文件系统双活域id
        :return:
        """
        LOG.info("Start to split filesystem hyper metro domain, domain_id[%s]", domain_id)
        data = {
            "ID": domain_id
        }
        url = Constant.SPLIT_FILESYSTEM_HYPER_METRO_DOMAIN.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to split filesystem hyper metro domain, domain_id[%s]" % domain_id
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to split filesystem hyper metro domain, domain_id[%s]", domain_id)
        return rsp_data

    def delete_filesystem_hyper_metro_domain(self, domain_id: str, is_local_del=False) -> dict:
        """
        删除文件系统双活域
        :param domain_id: 文件系统双活域id
        :param is_local_del: 是否执行本端删除，默认False，不执行。当删除失败错误码为1077674506时，使用本地删除
        :return:
        """
        LOG.info("Start to delete filesystem hyper metro domain, "
                 "domain_id[%s], is_local_del[%s].", domain_id, is_local_del)
        data = {
            "ISLOCALDELETE": is_local_del
        }
        url = Constant.DELETE_FILESYSTEM_HYPER_METRO_DOMAIN.format(deviceId=self.device_id, id=domain_id)
        res = self.rest_client.normal_request(url, data=data, method="delete")
        err_msg = "Failed to delete filesystem hyper metro domain, " \
                  "domain_id[%s], is_local_del[%s]." % (domain_id, is_local_del)
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to delete filesystem hyper metro domain, "
                 "domain_id[%s], is_local_del[%s].", domain_id, is_local_del)
        return rsp_data

    def swap_role_replication_pair(self, pair_id: str, vstore_id=0) -> None:
        """
        远程复制主备切换
        :param vstore_id:
        :param pair_id:
        :return:
        """
        LOG.info("Swap replication pair[%s] role start", pair_id)
        data = {
            "ID": pair_id,
            "vstoreId": vstore_id
        }
        url = Constant.SWAP_ROLE_REPLICATION_PAIR.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="put")
        err_msg = "Swap replication pair[%s] role failed" % pair_id
        StorageInf.result_parse(err_msg, res)
        LOG.info("Swap replication pair[%s] role success", pair_id)

    def swap_role_fs_hyper_metro_domain(self, domain_id: str) -> None:
        """
        双活域主备切换
        :param domain_id:
        :return:
        """
        LOG.info("Swap role fs hyper metro domain[%s] start.", domain_id)
        data = {
            "ID": domain_id
        }
        url = Constant.SWAP_ROLE_FS_HYPER_METRO_DOMAIN.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Swap role fs hyper metro domain[%s] failed" % domain_id
        StorageInf.result_parse(err_msg, res)
        LOG.info("Swap role fs hyper metro domain[%s] success.", domain_id)

    def change_fs_hyper_metro_domain_second_access(self, domain_id: str, access: str) -> None:
        """
        双活域主备切换
        :param access: 1: 禁止访问 2: 读写
        :param domain_id:
        :return:
        """
        LOG.info("Change fs hyper metro domain[%s] second access[%s] start.", domain_id, access)
        data = {
            "ID": domain_id,
            "access": access
        }
        url = Constant.CHANGE_FS_HYPER_METRO_DOMAIN_SECOND_ACCESS.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Change fs hyper metro domain[%s] second access[%s] failed." % (domain_id, access)
        StorageInf.result_parse(err_msg, res)
        LOG.info("Change fs hyper metro domain[%s] second access[%s] success.", domain_id, access)

    def join_fs_hyper_metro_domain(self, domain_id: str) -> None:
        """
        恢复文件系统双活域
        :param domain_id:
        :return:
        """
        LOG.info("Join fs hyper metro domain[%s] start", domain_id)
        data = {
            "ID": domain_id
        }
        url = Constant.JOIN_FS_HYPER_METRO_DOMAIN.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to join fs hyper metro domain[%s]" % domain_id
        StorageInf.result_parse(err_msg, res)
        LOG.info("Join fs hyper metro domain[%s] success", domain_id)
