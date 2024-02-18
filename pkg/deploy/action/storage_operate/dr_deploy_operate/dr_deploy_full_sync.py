#!/usr/bin/python3
# coding=utf-8
import argparse
import datetime
import json
import os
import stat
import time

from utils.config.rest_constant import SecresAccess, HealthStatus, ReplicationRunningStatus
from storage_operate.dr_deploy_operate.dr_deploy import DRDeploy
from logic.common_func import get_status
from logic.common_func import exec_popen
from om_log import DR_DEPLOY_LOG as LOG

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
FULL_SYNC_PROGRESS = os.path.join(CURRENT_PATH, "../../../config/full_sync_progress.json")
ZSQL_INI_PATH = '/mnt/dbdata/local/cantian/tmp/data/cfg/ctsql.ini'
LOCK_INSTANCE = "lock instance for backup;"
UNLOCK_INSTANCE = "unlock instance;"
FLUSH_TABLE = "flush table with read lock;"
UNLOCK_TABLE = "unlock tables;"
FULL_CHECK_POINT_CMD = 'echo -e %s | su -s /bin/bash - cantian -c \'source ~/.bashrc && ' \
                       'ctsql sys@127.0.0.1:1611 -q -c "alter system checkpoint global;"\''


class FullSyncRepPair(DRDeploy):
    def __init__(self):
        super(FullSyncRepPair, self).__init__()
        self.site = None
        self.dm_passwd = None
        self.mysql_pwd = None
        self.mysql_user = None
        self.mysql_cmd = None
        self.dr_deploy_opt = None
        self.record_progress_file = FULL_SYNC_PROGRESS
        self.page_fs_pair_id = self.dr_deploy_info.get("page_fs_pair_id")
        self.meta_fs_pair_id = self.dr_deploy_info.get("page_fs_pair_id")
        self.dm_ip = self.dr_deploy_info.get("dm_ip")
        self.dm_user = self.dr_deploy_info.get("dm_user")
        self.metadata_in_cantian = self.dr_deploy_info.get("mysql_metadata_in_cantian")

    @staticmethod
    def check_cluster_status():
        """
        cms 命令拉起参天后检查集群状态
        :return:
        """
        check_time = 100
        LOG.info("Check cantian status.")
        cmd = "su -s /bin/bash - cantian -c \"cms stat | " \
              "grep -v STAT | awk '{print \$3, \$6}'\""
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
                online, work_stat = node_stat.split(" ")
                if online != "ONLINE" or work_stat != "1":
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

    def record_deploy_process_init(self):
        """
        当前部署状态记录文件初始化
        状态文件.json:
            {
                data:
                {
                    sync_metro_fs_pair: default/start/running/success/failed,
                    sync_rep_meta_fs_pair: default/start/running/success/failed,
                    sync_rep_page_fs_pair: default/start/running/success/failed,
                    standby_install: default/start/running/success/failed,
                    standby_start: default/start/running/success/failed,
                    ...
                    dr_deploy: default/start/running/success/failed
                }
                error:
                {
                    "code": 0,  错误码：0 正常，其他不正常
                    "description": "xxx" 异常情况描述，code=0时表示无异常
                }
            }
        :return:
        """
        active_record_dict = {
            "do_lock_instance_for_backup": "default",
            "do_full_check_point": "default",
            "do_flush_table_with_read_lock": "default",
            "sync_rep_page_fs_pair": "default",
            "cancel_rep_page_fs_secondary_write_lock": "default",
            "do_unlock_instance_for_backup": "default"
        }
        standby_record_dict = {
            "sync_rep_page_fs_pair": "default",
            "standby_start": "default",
            "cantian_disaster_recovery_status": "default",
        }
        self.metadata_in_cantian = self.dr_deploy_info.get("mysql_metadata_in_cantian")
        dr_record_dict = active_record_dict if self.site == "active" else standby_record_dict

        if not self.metadata_in_cantian:
            dr_record_dict.update({
                "create_rep_meta_fs_pair": "default",
                "sync_rep_meta_fs_pair": "default",
                "cancel_rep_meta_fs_secondary_write_lock": "default"
            })
        dr_record_dict.update({"full_sync": "default"})
        result = {
            "data": dr_record_dict,
            "error":
                {
                    "code": 0,
                    "description": ""
                }
        }
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        modes = stat.S_IWUSR | stat.S_IRUSR
        with os.fdopen(os.open(self.record_progress_file, flags, modes), 'w') as fp:
            json.dump(result, fp, indent=4)

    def do_full_sync(self, pair_id: str) -> None:
        """
        step:
            1、根据pair_id查询当前pair状态
            2、pair为从端可读写状态，启用从端写资源保护，触发全量同步
            3、记录full_sync_process.json文件
            {

            }
        :param pair_id:
        :return:
        """
        remote_replication_pair_info = self.dr_deploy_opt.query_remote_replication_pair_info_by_pair_id(
            pair_id=pair_id)
        secres_access = remote_replication_pair_info.get("SECRESACCESS")
        if secres_access == SecresAccess.ReadAndWrite:
            self.dr_deploy_opt.remote_replication_filesystem_pair_set_secondary_write_lock(pair_id=pair_id)
            self.dr_deploy_opt.sync_remote_replication_filesystem_pair(pair_id=self.page_fs_pair_id,
                                                                       vstore_id="0",
                                                                       is_full_copy=True)

    def query_full_sync_status(self, pair_id: str) -> tuple:
        """
        查询当前同步状态
        :param pair_id:
        :return:
        """
        remote_replication_pair_info = self.dr_deploy_opt.query_remote_replication_pair_info_by_pair_id(
            pair_id=pair_id)
        replication_progress = remote_replication_pair_info.get("REPLICATIONPROGRESS")
        start_time = remote_replication_pair_info.get("STARTTIME")
        end_time = remote_replication_pair_info.get("ENDTIME")
        replication_pair_health_status = remote_replication_pair_info.get("HEALTHSTATUS")
        replication_pair_running_status = remote_replication_pair_info.get("RUNNINGSTATUS")
        secres_access = remote_replication_pair_info.get("SECRESACCESS")
        LOG.info("Sync remote replication filesystem pair[%s], health status:[%s], "
                 "running status[%s], progress[%s%%], start time[%s]",
                 pair_id,
                 get_status(replication_pair_health_status, HealthStatus),
                 get_status(replication_pair_running_status, ReplicationRunningStatus),
                 replication_progress,
                 datetime.datetime.fromtimestamp(int(start_time)))
        if replication_progress == "100" and \
                replication_pair_running_status == ReplicationRunningStatus.Normal and \
                replication_pair_health_status == HealthStatus.Normal:
            LOG.info("Success to sync remote replication filesystem pair[%s], end time[%s]",
                     pair_id,
                     datetime.datetime.fromtimestamp(int(end_time)))
            return True, replication_progress, secres_access
        return False, replication_progress, secres_access

    def standby_check_status(self):
        LOG.info("Check standby cluster status.")
        cmd = "source ~/.bashrc && su -s /bin/bash - cantian -c " \
              "\"cms stat | awk '{print \$3, \$(NF-1), \$NF}'\""
        return_code, output, stderr = exec_popen(cmd)
        if return_code:
            err_msg = "Cms stat command execute failed, details:%s" % output + stderr
            LOG.error(err_msg)
            self.record_deploy_process("full_sync", "failed", code=-1, description=err_msg)
            raise Exception(err_msg)
        cms_stat = output.split("\n")
        if len(cms_stat) < 3:
            err_msg = "Cluster stat is abnormal, details:%s" % output
            LOG.error(err_msg)
            self.record_deploy_process("full_sync", "failed", code=-1, description=err_msg)
            raise Exception(err_msg)
        online_flag = True
        stat_change_time = 0
        for status in cms_stat[1:]:
            node_stat, _date, _time = status.split(" ")
            datetime_obj = datetime.datetime.strptime(_date + " " + _time, "%Y-%m-%d %H:%M:%S.%f")
            timestamp = int(datetime_obj.timestamp())
            stat_change_time = timestamp if timestamp > stat_change_time else stat_change_time
            if node_stat == "UNKNOWN":
                online_flag = False
        LOG.info("Standby cluster status, online[%s], change time[%s]", online_flag, stat_change_time)
        return online_flag, stat_change_time

    def standby_cms_res_opt(self, action="start"):
        self.record_deploy_process("standby_start", "running")
        LOG.info("Standby stop by cms command.")
        cmd = "su -s /bin/bash - cantian -c " \
              "\"source ~/.bashrc && cms res -stop db\""
        return_code, output, stderr = exec_popen(cmd, timeout=600)
        if return_code:
            err_msg = "Cantian stop failed, error:%s." % output + stderr
            LOG.error(err_msg)
        LOG.info("Stop cantian by cms command success.")
        time.sleep(60)
        LOG.info("Standby start by cms command.")
        cmd = "su -s /bin/bash - cantian -c " \
              "\"source ~/.bashrc && cms res -%s db\"" % action
        return_code, output, stderr = exec_popen(cmd)
        if return_code:
            err_msg = "Cantian %s failed, error:%s." % (action, output + stderr)
            LOG.error(err_msg)
            self.record_deploy_process("standby_start", "failed", code=-1, description=err_msg)
            raise Exception(err_msg)
        self.check_cluster_status()
        LOG.info("Standby start by cms command success.")
        self.record_deploy_process("standby_start", "success")

    def full_sync_active(self):
        """
        触发全量同步
        主端：
            1、加备份锁
            2、flush table
            3、full check point
            4、全量同步
            5、全量同步时间过长，触发增量同步
            6、解备份锁
        :return:
        """
        self.do_lock_instance_for_backup()
        self.do_full_check_point()
        self.do_flush_table_with_read_lock()
        self.do_full_sync(self.page_fs_pair_id)
        LOG.info("Full sync replication pair of page fs")
        if not self.metadata_in_cantian:
            self.do_full_sync(self.meta_fs_pair_id)
            LOG.info("Full sync replication pair of meta fs")
        meta_pair_ready = True if self.metadata_in_cantian else False
        while True:
            page_pair_ready, page_pair_progress, secres_access = self.query_full_sync_status(self.page_fs_pair_id)
            self.record_deploy_process("sync_rep_page_fs_pair", page_pair_progress)
            if not self.metadata_in_cantian:
                meta_pair_ready, meta_pair_progress, secres_access = self.query_full_sync_status(self.meta_fs_pair_id)
                self.record_deploy_process("sync_rep_meta_fs_pair", meta_pair_progress)
            if page_pair_ready and meta_pair_ready:
                break
            time.sleep(60)
        self.dr_deploy_opt.split_remote_replication_filesystem_pair(self.page_fs_pair_id)
        self.record_deploy_process("sync_rep_page_fs_pair", "success")
        self.dr_deploy_opt.remote_replication_filesystem_pair_cancel_secondary_write_lock(self.page_fs_pair_id)
        self.record_deploy_process("cancel_rep_page_fs_secondary_write_lock", "success")
        if not self.metadata_in_cantian:
            self.dr_deploy_opt.split_remote_replication_filesystem_pair(self.meta_fs_pair_id)
            self.record_deploy_process("sync_rep_page_fs_pair", "success")
            self.dr_deploy_opt.remote_replication_filesystem_pair_cancel_secondary_write_lock(self.meta_fs_pair_id)
            self.record_deploy_process("cancel_rep_meta_fs_secondary_write_lock", "success")
        self.do_unlock_instance_for_backup()

    def full_sync_standby(self):
        """
        备端：
            1、查看cms状态，最后状态变化时间
            2、查询恢复状态，如果是在线并且最后状态变化时间大于同步完成的时间，直接返回
            3、启动参天
        :return:
        """
        ready_flag = False
        cantian_online, stat_change_time = self.standby_check_status()
        meta_access = SecresAccess.ReadAndWrite if self.metadata_in_cantian else SecresAccess.ReadOnly
        page_pair_info = self.dr_deploy_opt.query_remote_replication_pair_info_by_pair_id(
            pair_id=self.page_fs_pair_id)
        page_end_time = page_pair_info.get("ENDTIME")
        page_access = page_pair_info.get("SECRESACCESS")
        if page_access == SecresAccess.ReadAndWrite and \
                page_end_time is not None and int(page_end_time) < stat_change_time:
            ready_flag = True
        if not self.metadata_in_cantian:
            ready_flag = False
            meta_pair_info = self.dr_deploy_opt.query_remote_replication_pair_info_by_pair_id(
                self.meta_fs_pair_id)
            meta_end_time = meta_pair_info.get("ENDTIME")
            meta_access = meta_pair_info.get("SECRESACCESS")
            if meta_access == SecresAccess.ReadAndWrite \
                    and meta_end_time is not None and int(page_end_time) < stat_change_time:
                ready_flag = True
        if not ready_flag:
            self.wait_rep_pair_sync_end(meta_access)
        self.standby_cms_res_opt(action="start")
        self.query_cantian_disaster_recovery_status()

    def wait_rep_pair_sync_end(self, meta_access):
        """
        循环检查rep pair状态
        :param meta_access:
        :return:
        """
        while True:
            _, page_pair_progress, page_access = self.query_full_sync_status(self.page_fs_pair_id)
            self.record_deploy_process("sync_rep_page_fs_pair", page_pair_progress)
            if not self.metadata_in_cantian:
                _, meta_pair_progress, meta_access = self.query_full_sync_status(self.meta_fs_pair_id)
                self.record_deploy_process("sync_rep_meta_fs_pair", meta_pair_progress)
            if page_access == SecresAccess.ReadAndWrite and \
                    meta_access == SecresAccess.ReadAndWrite:
                self.record_deploy_process("sync_rep_page_fs_pair", "success")
                if not self.metadata_in_cantian:
                    self.record_deploy_process("sync_rep_meta_fs_pair", "success")
                break
            time.sleep(60)

    def execute(self):
        action_parse = argparse.ArgumentParser()
        action_parse.add_argument("--site", dest="site", choices=["standby", "active"], required=True)
        action_parse.add_argument("--mysql_cmd", dest="mysql_cmd", required=False)
        action_parse.add_argument("--mysql_user", dest="mysql_user", required=False)
        args = action_parse.parse_args()
        self.site = args.site
        self.init_storage_opt()
        self.record_deploy_process_init()
        self.record_deploy_process("full_sync", "running")
        if self.site == "active":
            self.mysql_cmd = args.mysql_cmd
            self.mysql_user = args.mysql_user
            mysql_pwd = input()
            self.mysql_pwd = mysql_pwd
            self.full_sync_active()
        else:
            self.full_sync_standby()
        self.record_deploy_process("full_sync", "success")
