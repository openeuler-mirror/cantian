# -*- coding: UTF-8 -*-
import json
import os
import sys
from query_storage_info.rest_client import RestClient, read_helper
from query_storage_info.response_parse import ResponseParse
from query_storage_info.rest_constant import Constant, \
    MetroDomainRunningStatus, VstorePairRunningStatus, HealthStatus
from exporter.log import EXPORTER_LOG as LOG

sys.path.append('/opt/cantian/action/dbstor')
from kmc_adapter import CApiWrapper


DR_DEPLOY_PARAM = "/opt/cantian/config/dr_deploy_param.json"
PRIMARY_KEYSTORE = "/opt/cantian/common/config/primary_keystore_bak.ks"
STANDBY_KEYSTORE = "/opt/cantian/common/config/standby_keystore_bak.ks"


def get_status(status: str, status_class: object) -> str:
    for key, value in status_class.__dict__.items():
        if value == status:
            return key
    return status


class DRStatusCheck(object):
    def __init__(self):
        self.kmc_decrypt = None
        self.rest_client = None
        self.device_id = None
        self.decrypt_pwd = None
        self.dm_pwd = None
        self.dm_ip = ""
        self.dm_user = ""
        self.dr_deploy_params = dict()
        self.remote_device_id = None

    @classmethod
    def result_parse(cls, err_msg, res):
        err_msg = err_msg + ", Detail:[%s]%s.Suggestion:%s"
        result = ResponseParse(res)
        status_code, error_code, error_des = result.get_res_code()
        if status_code != 200 or error_code != 0:
            err_msg = err_msg % (status_code, error_code, error_des)
            raise Exception(err_msg)
        rsp_code, rsp_result, rsp_data = result.get_rsp_data()
        error_code = rsp_result.get('code')
        if rsp_code != 0 or error_code != 0:
            error_des = rsp_result.get('description')
            error_sgt = rsp_result.get('suggestion')
            err_msg = err_msg % (error_code, error_des, error_sgt)
            raise Exception(err_msg)
        return rsp_data

    @classmethod
    def omstask_result_parse(cls, err_msg, res):
        err_msg = err_msg + ", Detail:[%s]%s.Suggestion:%s"
        result = ResponseParse(res)
        rsp_code, rsp_result, rsp_data = result.get_omtask_rsp_data()
        if rsp_code != 0 or (rsp_result.get('code') and rsp_result.get('code') != 0):
            error_des = rsp_result.get('description')
            error_sgt = rsp_result.get('suggestion')
            err_msg = err_msg % (rsp_result.get('code'), error_des, error_sgt)
            raise Exception(err_msg)
        return rsp_data

    def opt_init(self):
        if not os.path.exists(DR_DEPLOY_PARAM):
            return
        self.dr_deploy_params = json.loads(read_helper(DR_DEPLOY_PARAM))
        self.dm_ip = self.dr_deploy_params.get("dm_ip")
        self.dm_user = self.dr_deploy_params.get("dm_user")
        dm_pwd = self.dr_deploy_params.get("dm_pwd")
        if os.path.exists(DR_DEPLOY_PARAM):
            self.kmc_decrypt = CApiWrapper(primary_keystore=PRIMARY_KEYSTORE, standby_keystore=STANDBY_KEYSTORE)
            self.kmc_decrypt.initialize()
            try:
                self.dm_pwd = self.kmc_decrypt.decrypt(dm_pwd)
            except Exception as err:
                LOG.error("Failed to decrypt dm passwd")
                return
        self.kmc_decrypt.finalize()
        # 恢复环境变量，避免cms命令执行失败
        split_env = os.environ['LD_LIBRARY_PATH'].split(":")
        filtered_env = [single_env for single_env in split_env if "/opt/cantian/dbstor/lib" not in single_env]
        os.environ['LD_LIBRARY_PATH'] = ":".join(filtered_env)

        self.rest_client = RestClient((self.dm_ip, self.dm_user, self.decrypt_pwd))
        self.rest_client.login()
        self.device_id = self.rest_client.device_id

    def query_remote_storage_system_info(self) -> str:
        url = Constant.REMOTE_EXECUTE
        data = {
            "device_id": self.remote_device_id,
            "url": Constant.QUERY_SYSTEM_INFO.replace("{deviceId}", "xxx"),
            "method": "GET",
            "body": {}
        }
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to query remote storage system info"
        remote_device_info = self.omstask_result_parse(err_msg, res)
        health_status = remote_device_info.get("HEALTHSTATUS")
        return get_status(health_status, HealthStatus)

    def query_storage_system_info(self) -> str:
        """
        查询存储系统状态
        :return:
        """
        url = Constant.QUERY_SYSTEM_INFO.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query storage system info"
        system_info = self.result_parse(err_msg, res)
        health_status = system_info.get("HEALTHSTATUS")
        return get_status(health_status, HealthStatus)

    def query_remote_device_info(self, remote_device_id: str) -> str:
        """
        查询远端设备信息
        :param remote_device_id: 远端设备id
        :return:list
        """
        url = Constant.QUERY_REMOTE_DEVICE_INFO.format(deviceId=self.device_id) + f"/{remote_device_id}"
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query remote device info"
        remote_device_info = self.result_parse(err_msg, res)
        health_status = remote_device_info.get("HEALTHSTATUS")
        self.remote_device_id = remote_device_info.get("ID")
        return get_status(health_status, HealthStatus)

    def query_hyper_metro_domain_info(self, domain_id: str) -> str:
        """
        查询文件系统双活域信息
        :param domain_id: 文件系统双活域id
        :return:
        """
        url = Constant.HYPER_METRO_DOMAIN.format(deviceId=self.device_id)
        if domain_id:
            url = url + "/" + domain_id
        res = self.rest_client.normal_request(url, method="get")
        err_msg = "Failed to query hyper metro domain info"
        domain_info = self.result_parse(err_msg, res)
        running_status = domain_info.get("RUNNINGSTATUS")
        return get_status(running_status, MetroDomainRunningStatus)

    def query_hyper_metro_vstore_pair_info(self, vstore_pair_id: str) -> str:
        url = Constant.HYPER_METRO_VSTORE_PAIR.format(deviceId=self.device_id)
        if vstore_pair_id:
            url = url + "/" + vstore_pair_id
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query hyper metro vstore pair info"
        vstore_pair_info = self.result_parse(err_msg, res)
        running_status = vstore_pair_info.get("RUNNINGSTATUS")
        return get_status(running_status, VstorePairRunningStatus)

    def query_rep_link_status(self):
        url = Constant.IP_LINK.format(deviceId=self.device_id) + \
              "?DEVICEID=%s&LINKUSAGE=true&range=[0-10]" % self.remote_device_id
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to rep link info"
        ip_links = self.result_parse(err_msg, res)
        url = Constant.FC_LINK.format(deviceId=self.device_id) + \
              "?DEVICEID=%s&LINKUSAGE=true&range=[0-10]" % self.remote_device_id
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to rep link info"
        fc_links = self.result_parse(err_msg, res)
        abnormal = 0
        if ip_links:
            ip_link_status = {"total": len(ip_links)}
            for ip_link in ip_links:
                health_status = ip_link.get("HEALTHSTATUS")
                if health_status != HealthStatus.Normal:
                    abnormal += 1
            ip_link_status["abnormal"] = abnormal
        else:
            ip_link_status = {"total": 0, "abnormal": 0}
        abnormal = 0
        if fc_links:
            fc_link_status = {"total": len(fc_links)}
            for fc_link in fc_links:
                health_status = fc_link.get("HEALTHSTATUS")
                if health_status != HealthStatus.Normal:
                    abnormal += 1
            fc_link_status["abnormal"] = abnormal
        else:
            fc_link_status = {"total": 0, "abnormal": 0}
        result = {
            "ip_link": ip_link_status,
            "fc_link": fc_link_status,
        }
        return result

    def execute(self):
        result = dict()
        if not os.path.exists(DR_DEPLOY_PARAM):
            return result
        if self.rest_client.token is None:
            res = {"local_con": "Abnormal"}
            result["dr_status"] = res
            return result
        data = self.query_dr_status()
        result["dr_status"] = data
        self.rest_client.logout()
        return result

    def query_dr_status(self):
        self.remote_device_id = self.dr_deploy_params.get("remote_device_id")
        hyper_domain_id = self.dr_deploy_params.get("hyper_domain_id")
        vstore_pair_id = self.dr_deploy_params.get("vstore_pair_id")
        try:
            local_system_status = self.query_storage_system_info()
        except Exception as err:
            local_system_status = "Abnormal"
        try:
            remote_system_status = self.query_remote_storage_system_info()
        except Exception as err:
            remote_system_status = "Abnormal"
        try:
            remote_device_status = self.query_remote_device_info(self.remote_device_id)
        except Exception as err:
            remote_device_status = "Abnormal"
        try:
            metro_domain_status = self.query_hyper_metro_domain_info(hyper_domain_id)
        except Exception as err:
            metro_domain_status = "Abnormal"
        try:
            metro_vstore_status = self.query_hyper_metro_vstore_pair_info(vstore_pair_id)
        except Exception as err:
            metro_vstore_status = "Abnormal"
        try:
            rep_link_status = self.query_rep_link_status()
        except Exception as err:
            rep_link_status = {
                "ip_link": "Abnormal",
                "fc_link": "Abnormal",
            }
        data = {
            "local_con": "Normal",
            "local_system_status": local_system_status,
            "remote_system_status": remote_system_status,
            "remote_device_status": remote_device_status,
            "rep_link_status": rep_link_status,
            "metro_domain_status": metro_domain_status,
            "metro_vstore_status": metro_vstore_status
        }
        return data
