#!/usr/bin/python3
# coding=utf-8
import os
import time

from logic.common_func import read_json_config, get_status, exec_popen, retry
from logic.storage_operate import StorageInf
from storage_operate.dr_deploy_operate.dr_deploy_common import DRDeployCommon
from om_log import LOGGER as LOG
from utils.config.rest_constant import DomainAccess, MetroDomainRunningStatus, VstorePairRunningStatus, HealthStatus, \
    ConfigRole

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
DR_DEPLOY_CONFIG = os.path.join(CURRENT_PATH, "../../../config/dr_deploy_param.json")


class SwitchOver(object):
    def __init__(self):
        self.dr_deploy_opt = None
        self.dr_deploy_info = read_json_config(DR_DEPLOY_CONFIG)
        self.hyper_domain_id = self.dr_deploy_info.get("hyper_domain_id")
        self.page_fs_pair_id = self.dr_deploy_info.get("page_fs_pair_id")
        self.meta_fs_pair_id = self.dr_deploy_info.get("meta_fs_pair_id")
        self.metadata_in_cantian = self.dr_deploy_info.get("mysql_metadata_in_cantian")

    @staticmethod
    def check_cluster_status(target_node=None):
        """
        cms 命令拉起参天后检查集群状态
        :return:
        """
        check_time = 100
        LOG.info("Check cantian status.")
        cmd = "su -s /bin/bash - cantian -c \"cms stat | " \
              "grep -v STAT | awk '{print \$1, \$3, \$6}'\""
        while check_time:
            time.sleep(10)
            check_time -= 10
            return_code, output, stderr = exec_popen(cmd, timeout=100)
            if return_code:
                err_msg = "Execute cmd[%s] failed, details:%s" % (cmd, stderr)
                LOG.error(err_msg)
                raise Exception(err_msg)
            cms_stat = output.split("\n")
            if len(cms_stat) < 2:
                err_msg = "Current cluster status is abnormal, output:%s, stderr:%s" % (output, stderr)
                LOG.error(err_msg)
                raise Exception(err_msg)
            online = True
            for node_stat in cms_stat:
                node_id, online, work_stat = node_stat.split(" ")
                if (online != "ONLINE" or work_stat != "1") and node_id is None:
                    online = False
                # 只检查当前节点，不影响容灾切换
                if (online != "ONLINE" or work_stat != "1") and node_id == target_node:
                    online = False
            if not online:
                LOG.info("Current cluster status is abnormal, output:%s, stderr:%s", output, stderr)
                continue
            else:
                break
        else:
            err_msg = "Check cluster status timeout."
            LOG.error(err_msg)
            raise Exception(err_msg)

    def standby_cms_res_opt(self):
        LOG.info("Standby stop by cms command.")
        cmd = "source ~/.bashrc && su -s /bin/bash - cantian -c " \
              "\"cms res -stop db\""
        return_code, output, stderr = exec_popen(cmd, timeout=600)
        if return_code:
            err_msg = "Cantian stop failed, error:%s." % output + stderr
            LOG.info(err_msg)
        LOG.info("Stop cantian by cms command success.")
        time.sleep(10)
        LOG.info("Standby start by cms command.")
        cmd = "source ~/.bashrc && su -s /bin/bash - cantian -c " \
              "\"cms res -start db\""
        return_code, output, stderr = exec_popen(cmd, timeout=600)
        if return_code:
            err_msg = "Cantian start failed, error:%s." % output + stderr
            LOG.error(err_msg)
            raise Exception(err_msg)
        LOG.info("Standby start by cms command success.")
        self.check_cluster_status()

    def init_storage_opt(self):
        """
        从配置文件中读取参数，初始化操作，登录DM
        :return:
        """
        dm_ip = self.dr_deploy_info.get("dm_ip")
        dm_user = self.dr_deploy_info.get("dm_user")
        dm_passwd = input()
        storage_opt = StorageInf((dm_ip, dm_user, dm_passwd))
        storage_opt.login()
        self.dr_deploy_opt = DRDeployCommon(storage_opt)

    def execute(self):
        """
        step:
            查询当前是否为主站点，否：
                        1、分裂双活域
                        2、取消从资源保护
                        3、主从切换
            查询当前是否为主，否：
                        4、远程复制主从切换
        :return:
        """
        LOG.info("Active/standby switchover start.")
        node_id = self.dr_deploy_info.get("node_id")
        self.check_cluster_status(node_id)
        self.init_storage_opt()
        domain_info = self.dr_deploy_opt.query_hyper_metro_domain_info(self.hyper_domain_id)
        config_role = domain_info.get("CONFIGROLE")
        if config_role != ConfigRole.Primary:
            self.dr_deploy_opt.split_filesystem_hyper_metro_domain(self.hyper_domain_id)
            self.dr_deploy_opt.change_fs_hyper_metro_domain_second_access(
                self.hyper_domain_id, DomainAccess.ReadAndWrite)
            self.dr_deploy_opt.swap_role_fs_hyper_metro_domain(self.hyper_domain_id)
        else:
            LOG.info("FS hyper metro domain is already active site.")
        pair_info = self.dr_deploy_opt.query_remote_replication_pair_info_by_pair_id(
            self.page_fs_pair_id)
        page_role = pair_info.get("ISPRIMARY")
        if page_role != "true":
            self.dr_deploy_opt.swap_role_replication_pair(self.page_fs_pair_id)
        else:
            LOG.info("Page fs rep pair is already active site.")
        if not self.metadata_in_cantian:
            meta_info = self.dr_deploy_opt.query_remote_replication_pair_info_by_pair_id(
                self.meta_fs_pair_id)
            meta_role = meta_info.get("ISPRIMARY")
            if meta_role != "true":
                self.dr_deploy_opt.swap_role_replication_pair(self.meta_fs_pair_id)
            else:
                LOG.info("Meta fs rep pair is already active site.")
        LOG.info("Active/standby switchover success.")


class DRRecover(SwitchOver):
    def __init__(self):
        super(DRRecover, self).__init__()
        self.vstore_pair_id = self.dr_deploy_info.get("vstore_pair_id")

    def execute(self):
        """
        step:
            1、检查当前双活域状态，
            2、
        :return:
        """
        LOG.info("DR recover start.")
        self.init_storage_opt()
        domain_info = self.dr_deploy_opt.query_hyper_metro_domain_info(self.hyper_domain_id)
        running_status = domain_info.get("RUNNINGSTATUS")
        if running_status != MetroDomainRunningStatus.Normal:
            self.dr_deploy_opt.change_fs_hyper_metro_domain_second_access(
                self.hyper_domain_id, DomainAccess.ReadOnly)
            self.dr_deploy_opt.join_fs_hyper_metro_domain(self.hyper_domain_id)
        while True:
            vstore_pair_info = self.dr_deploy_opt.query_hyper_metro_vstore_pair_info(self.vstore_pair_id)
            health_status = vstore_pair_info.get("HEALTHSTATUS")
            running_status = vstore_pair_info.get("RUNNINGSTATUS")
            LOG.info("Vstore pair sync running, running status[%s]",
                     get_status(running_status, VstorePairRunningStatus))
            if running_status == VstorePairRunningStatus.Invalid or health_status == HealthStatus.Faulty:
                err_msg = "Hyper metro vstore pair status is not normal, " \
                          "health_status[%s], running_status[%s], details: %s" % \
                          (get_status(health_status, HealthStatus),
                           get_status(running_status, VstorePairRunningStatus),
                           vstore_pair_info)
                LOG.error(err_msg)
            if running_status == VstorePairRunningStatus.Normal and health_status == HealthStatus.Normal:
                LOG.info("Vstore pair sync complete.")
                break
            time.sleep(60)

        domain_info = self.dr_deploy_opt.query_hyper_metro_domain_info(self.hyper_domain_id)
        config_role = domain_info.get("CONFIGROLE")
        if config_role != ConfigRole.Primary:
            self.standby_cms_res_opt()
        LOG.info("Active/standby switchover success.")


class CancelStandbyResPro(SwitchOver):
    def __init__(self):
        super(CancelStandbyResPro, self).__init__()

    def execute(self):
        LOG.info("Cancel secondary resource protection start.")
        self.init_storage_opt()
        domain_info = self.dr_deploy_opt.query_hyper_metro_domain_info(self.hyper_domain_id)
        config_role = domain_info.get("CONFIGROLE")
        if config_role != ConfigRole.Primary:
            self.dr_deploy_opt.change_fs_hyper_metro_domain_second_access(
                self.hyper_domain_id, DomainAccess.ReadAndWrite)
        LOG.info("Cancel secondary resource protection success.")
