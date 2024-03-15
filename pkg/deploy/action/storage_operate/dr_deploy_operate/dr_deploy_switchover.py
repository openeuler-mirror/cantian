#!/usr/bin/python3
# coding=utf-8
import os
import time

from logic.common_func import read_json_config, get_status, exec_popen, retry
from logic.storage_operate import StorageInf
from storage_operate.dr_deploy_operate.dr_deploy_common import DRDeployCommon
from om_log import LOGGER as LOG
from utils.config.rest_constant import DomainAccess, MetroDomainRunningStatus, VstorePairRunningStatus, HealthStatus, \
    ConfigRole, DataIntegrityStatus, ReplicationRunningStatus

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
DR_DEPLOY_CONFIG = os.path.join(CURRENT_PATH, "../../../config/dr_deploy_param.json")
LOGICREP_APPCTL_FILE = os.path.join(CURRENT_PATH, "../../logicrep/appctl.sh")


class SwitchOver(object):
    def __init__(self):
        self.dr_deploy_opt = None
        self.dr_deploy_info = read_json_config(DR_DEPLOY_CONFIG)
        self.hyper_domain_id = self.dr_deploy_info.get("hyper_domain_id")
        self.page_fs_pair_id = self.dr_deploy_info.get("page_fs_pair_id")
        self.meta_fs_pair_id = self.dr_deploy_info.get("meta_fs_pair_id")
        self.ulog_fs_pair_id = self.dr_deploy_info.get("ulog_fs_pair_id")
        self.vstore_pair_id = self.dr_deploy_info.get("vstore_pair_id")
        self.node_id = self.dr_deploy_info.get("node_id")
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
            time.sleep(20)
            check_time -= 20
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
            online_flag = True
            for node_stat in cms_stat:
                node_id, online, work_stat = node_stat.split(" ")
                if (online != "ONLINE" or work_stat != "1") and target_node is None:
                    online_flag = False
                # 只检查当前节点，不影响容灾切换
                if (online != "ONLINE" or work_stat != "1") and node_id == target_node:
                    online_flag = False
            if not online_flag:
                LOG.info("Current cluster status is abnormal, output:%s, stderr:%s", output, stderr)
                continue
            else:
                break
        else:
            err_msg = "Check cluster status timeout."
            LOG.error(err_msg)
            raise Exception(err_msg)

    def query_sync_status(self):
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

    def standby_logicrep_stop(self):
        LOG.info("logcirep stop by appctl.")
        cmd = "sh %s shutdown" % LOGICREP_APPCTL_FILE
        return_code, output, stderr = exec_popen(cmd, timeout=600)
        if return_code:
            err_msg = "logicrep stop failed, error:%s." % output + stderr
            LOG.info(err_msg)
        LOG.info("Stop logicrep by appctl success.")

    def standby_cms_res_stop(self):
        LOG.info("Standby stop by cms command.")
        cmd = "source ~/.bashrc && su -s /bin/bash - cantian -c " \
              "\"cms res -stop db\""
        return_code, output, stderr = exec_popen(cmd, timeout=600)
        if return_code:
            err_msg = "Cantian stop failed, error:%s." % output + stderr
            LOG.info(err_msg)
        LOG.info("Stop cantian by cms command success.")

    def standby_cms_res_start(self):
        LOG.info("Standby start by cms command.")
        cmd = "source ~/.bashrc && su -s /bin/bash - cantian -c " \
              "\"cms res -start db\""
        return_code, output, stderr = exec_popen(cmd, timeout=600)
        if return_code:
            err_msg = "Cantian start failed, error:%s." % output + stderr
            LOG.error(err_msg)
            raise Exception(err_msg)
        LOG.info("Standby start by cms command success.")

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
            1、检查双活，复制数据是否完整
            2、检查当前双活域状态：
                1）、正常
                    ①、停止参天
                    ②、分裂文件系统双活域
                    ③、取消远程复制从资源写保护
                    ④、主从切换
                        Ⅰ）、双活域主备切换
                        Ⅱ）、远程复制主备切换
                    ⑤、恢复远程复制从资源写保护
                    ⑥、page远程复制主备切换（元数据非归一，metadata_fs）
                    ⑦、启动参天
                2）、分裂
                2）、故障退出
        :return:
        """
        LOG.info("Active/standby switchover start.")
        node_id = self.dr_deploy_info.get("node_id")
        self.check_cluster_status(node_id)
        self.init_storage_opt()
        pair_info = self.dr_deploy_opt.query_hyper_metro_filesystem_pair_info_by_pair_id(self.ulog_fs_pair_id)
        local_data_status = pair_info.get("LOCALDATASTATE")
        remote_data_status = pair_info.get("REMOTEDATASTATE")
        if local_data_status == DataIntegrityStatus.inconsistent or remote_data_status == DataIntegrityStatus.inconsistent:
            err_msg = "Data is inconsistent, please check."
            LOG.error(err_msg)
            raise Exception(err_msg)
        domain_info = self.dr_deploy_opt.query_hyper_metro_domain_info(self.hyper_domain_id)
        running_status = domain_info.get("RUNNINGSTATUS")
        config_role = domain_info.get("CONFIGROLE")
        if running_status != MetroDomainRunningStatus.Normal and running_status != MetroDomainRunningStatus.Split:
            err_msg = "DR recover operation is not allowed in %s status." % \
                      get_status(running_status, MetroDomainRunningStatus)
            LOG.error(err_msg)
            raise Exception(err_msg)
        if config_role == ConfigRole.Primary and running_status == MetroDomainRunningStatus.Normal:
            self.standby_logicrep_stop()
            self.standby_cms_res_stop()
            self.dr_deploy_opt.split_filesystem_hyper_metro_domain(self.hyper_domain_id)
            self.dr_deploy_opt.change_fs_hyper_metro_domain_second_access(
                self.hyper_domain_id, DomainAccess.ReadAndWrite)
            self.dr_deploy_opt.swap_role_fs_hyper_metro_domain(self.hyper_domain_id)
            self.dr_deploy_opt.change_fs_hyper_metro_domain_second_access(self.hyper_domain_id, DomainAccess.ReadOnly)
            self.dr_deploy_opt.join_fs_hyper_metro_domain(self.hyper_domain_id)
            self.query_sync_status()
            pair_info = self.dr_deploy_opt.query_remote_replication_pair_info_by_pair_id(
                self.page_fs_pair_id)
            page_role = pair_info.get("ISPRIMARY")
            if page_role == "true":
                self.dr_deploy_opt.swap_role_replication_pair(self.page_fs_pair_id)
            else:
                LOG.info("Page fs rep pair is already standby site.")
            if not self.metadata_in_cantian:
                meta_info = self.dr_deploy_opt.query_remote_replication_pair_info_by_pair_id(
                    self.meta_fs_pair_id)
                meta_role = meta_info.get("ISPRIMARY")
                if meta_role == "true":
                    self.dr_deploy_opt.swap_role_replication_pair(self.meta_fs_pair_id)
                else:
                    LOG.info("Meta fs rep pair is already standby site.")
            self.standby_cms_res_start()
            self.check_cluster_status()
            LOG.info("Active/standby switchover success.")
        else:
            LOG.info("FS hyper metro domain is already standby site.")


class DRRecover(SwitchOver):
    def __init__(self):
        super(DRRecover, self).__init__()

    def execute_replication_steps(self, running_status, pair_id):
        if running_status != ReplicationRunningStatus.Synchronizing:
            self.dr_deploy_opt.sync_remote_replication_filesystem_pair(pair_id=pair_id,
                                                                       vstore_id="0",
                                                                       is_full_copy=False)
            time.sleep(10)
        pair_info = self.dr_deploy_opt.query_remote_replication_pair_info_by_pair_id(
            pair_id)
        running_status = pair_info.get("RUNNINGSTATUS")
        while running_status == ReplicationRunningStatus.Synchronizing:
            pair_info = self.dr_deploy_opt.query_remote_replication_pair_info_by_pair_id(
               pair_id)
            running_status = pair_info.get("RUNNINGSTATUS")
            replication_progress = pair_info.get("REPLICATIONPROGRESS")
            LOG.info(f"Page fs rep pair is synchronizing, current progress: {replication_progress}%, please wait...")
            time.sleep(10)
        self.dr_deploy_opt.split_remote_replication_filesystem_pair(pair_id)
        self.dr_deploy_opt.remote_replication_filesystem_pair_cancel_secondary_write_lock(pair_id)

    def rep_pair_recover(self, pair_id: str) -> None:
        pair_info = self.dr_deploy_opt.query_remote_replication_pair_info_by_pair_id(
            pair_id)
        page_role = pair_info.get("ISPRIMARY")
        running_status = pair_info.get("RUNNINGSTATUS")
        if page_role == "true":
            self.dr_deploy_opt.swap_role_replication_pair(pair_id)
            self.dr_deploy_opt.remote_replication_filesystem_pair_set_secondary_write_lock(pair_id)
            self.execute_replication_steps(running_status, pair_id)
        else:
            LOG.info("Page fs rep pair is already standby site.")
            if running_status == ReplicationRunningStatus.Split:
                try:
                    self.check_cluster_status()
                except Exception as _er:
                    self.dr_deploy_opt.remote_replication_filesystem_pair_set_secondary_write_lock(pair_id)
                    self.execute_replication_steps(running_status, pair_id)
                else:
                    return
            elif running_status == ReplicationRunningStatus.Normal or \
                    running_status == ReplicationRunningStatus.Synchronizing:
                self.execute_replication_steps(running_status, pair_id)
            else:
                err_msg = "Remote replication filesystem pair is not in normal status."
                LOG.error(err_msg)
                raise Exception(err_msg)

    def hyper_metro_status_check(self, running_status, config_role):
        if running_status != MetroDomainRunningStatus.Normal and running_status != MetroDomainRunningStatus.Split:
            err_msg = "DR recover operation is not allowed in %s status." % \
                      get_status(running_status, MetroDomainRunningStatus)
            LOG.error(err_msg)
            raise Exception(err_msg)
        if running_status == MetroDomainRunningStatus.Normal and config_role == ConfigRole.Primary:
            err_msg = "DR recover operation is not allowed in %s status." % \
                      get_status(running_status, MetroDomainRunningStatus)
            LOG.error(err_msg)
            raise Exception(err_msg)

    def execute(self):
        """
        step:
            1、检查当前双活域状态：
                1）故障报错退出
                2）分裂：
                    ① 判断主备、主节点进行主备切换
                    ② 设置从资源保护
                    ③ 回复双活域，如果报错pass
                    ④ 查询双活文件系统同步状态，如果暂停状态超过五分钟，报错退出
                3）正常：
                    ① 查询双活文件系统同步状态，如果暂停状态超过五分钟，报错退出
                4） 其他
            2、检查远程复制pair状态
                1) 主：
                    ① 主从切换
                    ② 设置从资源保护
                    ③ 回复，同步数据（增量）
                    ④ 分裂
                    ⑤ 取消从资源保护
                2) 备：
                    ① pair状态分裂
                        Ⅰ） 参天状态异常 -> 1）② -> ⑤
                        Ⅱ）参天状态正常 -> end
                    ②pair状态正常 -> 1）③ -> ⑤
        :return:
        """
        LOG.info("DR recover start.")
        self.init_storage_opt()
        domain_info = self.dr_deploy_opt.query_hyper_metro_domain_info(self.hyper_domain_id)
        running_status = domain_info.get("RUNNINGSTATUS")
        config_role = domain_info.get("CONFIGROLE")
        self.hyper_metro_status_check(running_status, config_role)
        if running_status == MetroDomainRunningStatus.Split:
            if config_role == ConfigRole.Primary:
                self.dr_deploy_opt.change_fs_hyper_metro_domain_second_access(
                    self.hyper_domain_id, DomainAccess.ReadAndWrite)
                self.dr_deploy_opt.swap_role_fs_hyper_metro_domain(self.hyper_domain_id)
            self.dr_deploy_opt.change_fs_hyper_metro_domain_second_access(
                self.hyper_domain_id, DomainAccess.ReadOnly)
            try:
                self.dr_deploy_opt.join_fs_hyper_metro_domain(self.hyper_domain_id)
            except Exception as _er:
                LOG.info("Fail to recover hyper metro domain, details: %s", str(_er))
        self.query_sync_status()
        self.rep_pair_recover(self.page_fs_pair_id)
        if not self.metadata_in_cantian:
            self.rep_pair_recover(self.meta_fs_pair_id)
        try:
            self.check_cluster_status()
        except Exception as _err:
            self.standby_logicrep_stop()
            self.standby_cms_res_stop()
            time.sleep(10)
            self.standby_cms_res_start()
            self.check_cluster_status()
        LOG.info("DR recovery complete")


class FailOver(SwitchOver):
    def __init__(self):
        super(FailOver, self).__init__()

    def execute(self):
        """
        step:
            1、检查双活域角色
            2、检查当前双活域状态
            3、检查参天状态
            4、取消从资源保护
        """
        LOG.info("Cancel secondary resource protection start.")
        self.init_storage_opt()
        domain_info = self.dr_deploy_opt.query_hyper_metro_domain_info(self.hyper_domain_id)
        config_role = domain_info.get("CONFIGROLE")
        if config_role == ConfigRole.Primary:
            err_msg = "Fail over operation is not allowed in primary node."
            LOG.error(err_msg)
            raise Exception(err_msg)
        running_status = domain_info.get("RUNNINGSTATUS")
        try:
            self.check_cluster_status(self.node_id)
        except Exception as _er:
            err_msg = "Check cantian status failed, error: {}".format(_er)
            LOG.error(err_msg)
            raise Exception(err_msg) from _er
        if running_status == MetroDomainRunningStatus.Normal:
            self.dr_deploy_opt.split_filesystem_hyper_metro_domain(self.hyper_domain_id)
        self.dr_deploy_opt.change_fs_hyper_metro_domain_second_access(
            self.hyper_domain_id, DomainAccess.ReadAndWrite)
        LOG.info("Cancel secondary resource protection success.")