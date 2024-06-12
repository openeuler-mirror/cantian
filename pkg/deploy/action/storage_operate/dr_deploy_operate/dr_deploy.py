#!/usr/bin/python3
# coding=utf-8
import datetime
import json
import os
import argparse
import re
import shutil
import stat
import time
import traceback
import signal

from storage_operate.dr_deploy_operate.dr_deploy_common import DRDeployCommon
from storage_operate.dr_deploy_operate.dr_deploy_common import KmcResolve
from utils.config.rest_constant import HealthStatus, MetroDomainRunningStatus, SecresAccess, VstorePairRunningStatus, \
    FilesystemPairRunningStatus, ReplicationRunningStatus, CANTIAN_DOMAIN_PREFIX, Constant
from logic.storage_operate import StorageInf
from logic.common_func import read_json_config
from logic.common_func import write_json_config
from logic.common_func import exec_popen
from logic.common_func import exec_popen_long
from logic.common_func import retry
from logic.common_func import get_status
from om_log import DR_DEPLOY_LOG as LOG

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
DR_DEPLOY_CONFIG = os.path.join(CURRENT_PATH, "../../../config/dr_deploy_param.json")
DEPLOY_PARAM_FILE = "/opt/cantian/config/deploy_param.json"
EXEC_SQL = os.path.join(CURRENT_PATH, "../../cantian_common/exec_sql.py")
LOCAL_PROCESS_RECORD_FILE = os.path.join(CURRENT_PATH, "../../../config/dr_process_record.json")
FULL_CHECK_POINT_CMD = 'echo -e "alter system checkpoint global;" | '\
                       'su -s /bin/bash - cantian -c \'source ~/.bashrc && '\
                       'export LD_LIBRARY_PATH=/opt/cantian/dbstor/lib:${LD_LIBRARY_PATH} && '\
                       'python3 -B %s\'' % EXEC_SQL
CANTIAN_DISASTER_RECOVERY_STATUS_CHECK = 'echo -e "select * from DV_LRPL_DETAIL;" | '\
                                         'su -s /bin/bash - cantian -c \'source ~/.bashrc && '\
                                         'export LD_LIBRARY_PATH=/opt/cantian/dbstor/lib:${LD_LIBRARY_PATH} && '\
                                         'python3 -B %s\'' % EXEC_SQL
ZSQL_INI_PATH = '/mnt/dbdata/local/cantian/tmp/data/cfg/ctsql.ini'
LOCK_INSTANCE = "set @ctc_ddl_enabled=true;lock instance for backup;"
LOCK_INSTANCE_LONG_LIVED = "lock instance for backup;do sleep(100000);"
FLUSH_TABLE = "flush table with read lock;unlock tables;"
INSTALL_TIMEOUT = 900
START_TIMEOUT = 3600
FS_CREAT_TIMEOUT = 300


ACTIVE_RECORD_DICT = {
    "do_lock_instance_for_backup": "default",
    "do_full_check_point": "default",
    "do_flush_table_with_read_lock": "default",
    "create_metro_domain": "default",
    "create_metro_vstore_pair": "default",
    "create_metro_fs_pair": "default",
    "create_rep_page_fs_pair": "default",
    "sync_metro_fs_pair": "default",
    "sync_rep_page_fs_pair": "default"
}
STANDBY_RECORD_DICT = {
    "create_metro_domain": "default",
    "create_metro_vstore_pair": "default",
    "create_metro_fs_pair": "default",
    "create_rep_page_fs_pair": "default",
    "standby_install": "default",
    "sync_metro_fs_pair": "default",
    "sync_rep_page_fs_pair": "default",
    "standby_start": "default"
}


class DRDeploy(object):
    def __init__(self):
        self.dr_deploy_opt = None
        self.ctsql_passwd = None
        self.ulog_fs_pair_id = None
        self.standby_conf = None
        self.active_conf = None
        self.dm_passwd = None
        self.page_fs_pair_id = None
        self.meta_fs_pair_id = None
        self.dr_deploy_info = read_json_config(DR_DEPLOY_CONFIG)
        self.record_progress_file = LOCAL_PROCESS_RECORD_FILE
        self.mysql_user = None
        self.mysql_cmd = None
        self.mysql_pwd = None
        self.site = None
        self.metadata_in_cantian = False
        self.backup_lock_pid = None

    @staticmethod
    def restart_cantian_exporter():
        """
        容灾告警需要重启cantian_exporter
        :return:
        """
        cmd = "ps -ef | grep \"python3 /opt/cantian/ct_om/service/cantian_exporter/exporter/execute.py\"" \
              " | grep -v grep | awk '{print $2}' | xargs kill -9"
        exec_popen(cmd)

    def record_deploy_process(self, exec_step: str, exec_status: str, code=0, description="") -> None:
        """
        :param exec_step: 执行步骤
        :param exec_status: 执行状态
        :param code:  错误码
        :param description: 描述
        :return:
        """
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        modes = stat.S_IWUSR | stat.S_IRUSR
        with open(self.record_progress_file, "r") as fp:
            result = json.loads(fp.read())
        data = result.get("data")
        error = result.get("error")
        data.update({exec_step: exec_status})
        error["code"] = code
        error["description"] = description
        with os.fdopen(os.open(self.record_progress_file, flags, modes), 'w') as fp:
            json.dump(result, fp, indent=4)

    def record_deploy_process_init(self):
        """
        当前部署状态记录文件初始化
        状态文件.json:
            {
                data:
                {
                    create_metro_domain: default/start/running/success/failed,
                    create_metro_vstore_pair: default/start/running/success/failed,
                    create_metro_fs_pair: default/start/running/success/failed,
                    create_rep_meta_fs_pair: default/start/running/success/failed,
                    create_rep_page_fs_pair: default/start/running/success/failed,
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
        self.metadata_in_cantian = self.dr_deploy_info.get("mysql_metadata_in_cantian")
        dr_record_dict = ACTIVE_RECORD_DICT if self.site == "active" else STANDBY_RECORD_DICT

        if not self.metadata_in_cantian:
            dr_record_dict.update({
                "create_rep_meta_fs_pair": "default",
                "sync_rep_meta_fs_pair": "default"
            })
        if self.site == "standby":
            dr_record_dict.update({
                "cantian_disaster_recovery_status": "default"
            })
        else:
            if not self.metadata_in_cantian:
                dr_record_dict.update({
                    "cancel_rep_meta_fs_secondary_write_lock": "default"
                })
            dr_record_dict.update({
                "cancel_rep_page_fs_secondary_write_lock": "default",
                "do_unlock_instance_for_backup": "default"
            })
        dr_record_dict.update({"dr_deploy": "default"})
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

    def record_disaster_recovery_info(self, key, value):
        """
        读取容灾配置信息，支持重试功能
        :return:
        """
        self.dr_deploy_info[key] = value
        write_json_config(DR_DEPLOY_CONFIG, self.dr_deploy_info)

    def do_lock_instance_for_backup(self):
        """
        mysql 执行备份锁
        mysql_cmd:
             物理mysql:/usr/local/mysql/bin/mysql
             k8s: kubectl exec -n namespace pod_name -c mysql -- mysql
        :return:
        """
        LOG.info("Start to do lock instance for backup.")
        cmd = "%s -u'%s' -p'%s' -e \"%s;\"" % (self.mysql_cmd,
                                           self.mysql_user,
                                           self.mysql_pwd,
                                           LOCK_INSTANCE)
        cmd += ";echo last_cmd=$?"
        self.record_deploy_process("do_lock_instance_for_backup", "start")
        _, output, stderr = exec_popen(cmd)
        if "last_cmd=0" not in output:
            err_msg = "Failed to do lock instance for backup,output:%s, " \
                      "stderr:%s" % (output, stderr)
            err_msg.replace(self.mysql_pwd, "***")
            LOG.error(err_msg)
            self.record_deploy_process("do_lock_instance_for_backup", "failed", code=-1, description=err_msg)
            raise Exception(err_msg)
        cmd = "%s -u'%s' -p'%s' -e \"%s;\"" % (self.mysql_cmd,
                                            self.mysql_user,
                                            self.mysql_pwd,
                                            LOCK_INSTANCE_LONG_LIVED)
        self.backup_lock_pid = exec_popen_long(cmd)
        LOG.info("Success to do lock instance for backup.")
        self.record_deploy_process("do_lock_instance_for_backup", "success")

    def do_unlock_instance_for_backup(self):
        """
        关闭长连接
        :return:
        """
        LOG.info("Start to do unlock instance for backup.")
        self.record_deploy_process("do_unlock_instance_for_backup", "start")
        try:
            os.killpg(self.backup_lock_pid, signal.SIGKILL)
        except ProcessLookupError as err:
            err_msg = "Failed to do unlock instance for backup, the child process was accidentally killed prematurely"
            LOG.error(err_msg)
            self.record_deploy_process("do_unlock_instance_for_backup", "failed", code=-1, description=err_msg)
            raise Exception(err_msg)
        except Exception as err:
            err_msg = "Failed to do unlock instance for backup, stderr:%s" % (str(err))
            err_msg.replace(self.mysql_pwd, "***")
            LOG.error(err_msg)
            self.record_deploy_process("do_unlock_instance_for_backup", "failed", code=-1, description=err_msg)
            raise Exception(err_msg)
        LOG.info("Success to do unlock instance for backup.")
        self.record_deploy_process("do_unlock_instance_for_backup", "success")

    def do_flush_table_with_read_lock(self):
        """
        mysql数据库flush table
        :return:
        """
        LOG.info("Start to do flush table with read lock.")
        cmd = "%s -u'%s' -p'%s' -e \"%s;\"" % (self.mysql_cmd,
                                           self.mysql_user,
                                           self.mysql_pwd,
                                           FLUSH_TABLE)
        cmd += ";echo last_cmd=$?"
        self.record_deploy_process("do_flush_table_with_read_lock", "start")
        attempts = 15
        stderr = ""
        output = ""
        while attempts > 0:
            _, output, stderr = exec_popen(cmd, 20)
            if "last_cmd=0" in output:
                LOG.info("Success to do flush table with read lock.")
                self.record_deploy_process("do_flush_table_with_read_lock", "success")
                return
            elif "last_cmd=1" in output:
                err_msg = "Failed to do flush table with read lock, try again."
                LOG.error(err_msg)
                time.sleep(20)
                attempts -= 1
                continue
                
            else:
                break

        err_msg = "Failed to do unlock table with read lock, " \
                    "output:%s, stderr:%s" % (output, stderr)
        err_msg.replace(self.mysql_pwd, "***")
        LOG.error(err_msg)
        self.record_deploy_process("do_flush_table_with_read_lock", "failed", code=-1, description=err_msg)
        raise Exception(err_msg)

    def do_full_check_point(self):
        """
        cantian数据库full check point
        :return:
        """
        LOG.info("Start do full checkpoint.")
        self.record_deploy_process("do_full_check_point", "start")
        return_code, output, stderr = exec_popen(FULL_CHECK_POINT_CMD, timeout=100)
        if return_code:
            err_msg = "Do full checkpoint failed, output: %s, stderr:%s" % (output, stderr)
            LOG.error(err_msg)
            self.record_deploy_process("do_full_check_point", "failed", code=-1, description=err_msg)
            raise Exception(err_msg)
        self.record_deploy_process("do_full_check_point", "success")
        LOG.info("Success to do full checkpoint.")

    def init_storage_opt(self):
        """
        从配置文件中读取参数，初始化操作，登录DM
        :return:
        """
        dm_ip = self.dr_deploy_info.get("dm_ip")
        dm_user = self.dr_deploy_info.get("dm_user")
        self.dm_passwd = input()
        storage_opt = StorageInf((dm_ip, dm_user, self.dm_passwd))
        storage_opt.login()
        self.dr_deploy_opt = DRDeployCommon(storage_opt)

    def do_create_filesystem_hyper_metro_domain(self) -> dict:
        """
        读取配置文件，获取双活域id，查询当前双活域：
            1）未获取到ID表示当前全新创建，执行创建双活域操作
                 a. 查询远端设备信息，获取远端设备名称、esn、远端设备id
                 b. 生成双活域名称，命名规则CantianDomain_cluster_id_random_seed
            2）获取到ID，查询当前双活域状态，状态不正常报错
        :return:
        """
        self.record_deploy_process("create_metro_domain", "start")
        hyper_domain_id = self.dr_deploy_info.get("hyper_domain_id")
        cluster_id = self.dr_deploy_info.get("cluster_id")
        remote_dev_name = self.dr_deploy_info.get("remote_dev_name")
        remote_dev_esn = self.dr_deploy_info.get("remote_dev_esn")
        remote_device_id = self.dr_deploy_info.get("remote_device_id")
        deploy_params = read_json_config(DEPLOY_PARAM_FILE)
        random_seed = deploy_params.get("random_seed", 1)
        domain_name = CANTIAN_DOMAIN_PREFIX % (cluster_id, random_seed)
        if hyper_domain_id is None:
            domain_info = self.dr_deploy_opt.create_filesystem_hyper_metro_domain(
                remote_dev_name, remote_dev_esn, remote_device_id, domain_name)
        else:
            domain_info = self.dr_deploy_opt.query_hyper_metro_domain_info(hyper_domain_id)
        if not domain_info:
            domain_info = self.dr_deploy_opt.create_filesystem_hyper_metro_domain(
                remote_dev_name, remote_dev_esn, remote_device_id, domain_name)
        running_status = domain_info.get("RUNNINGSTATUS")
        domain_name = domain_info.get("NAME")
        if running_status == MetroDomainRunningStatus.Invalid:
            err_msg = "Hyper metro domain[%s] status is invalid" % domain_name
            LOG.error(err_msg)
            self.record_deploy_process("create_metro_domain", "failed", code=-1, description=err_msg)
            raise Exception(err_msg)
        self.record_deploy_process("create_metro_domain", "success")
        return domain_info

    def do_create_hyper_metro_vstore_pair(self, domain_info: dict) -> dict:
        """
        查询所有双活域信息，
        :param domain_info: 双活域信息
        :return:
        """
        self.record_deploy_process("create_metro_vstore_pair", "start")
        vstore_pair_id = None
        remote_vstore_id = self.dr_deploy_info.get("remote_dbstore_fs_vstore_id")
        local_vstore_id = self.dr_deploy_info.get("dbstore_fs_vstore_id")
        domain_id = domain_info.get("ID")
        vstore_pair_infos = self.dr_deploy_opt.query_hyper_metro_vstore_pair_info()
        for exist_vstore_pair_info in vstore_pair_infos:
            exist_remote_vstoreid = exist_vstore_pair_info.get("REMOTEVSTOREID")
            exist_local_vstoreid = exist_vstore_pair_info.get("LOCALVSTOREID")
            if exist_local_vstoreid == local_vstore_id and remote_vstore_id == exist_remote_vstoreid:
                vstore_pair_id = exist_vstore_pair_info.get("ID")
        if vstore_pair_id is None:
            vstore_pair_info = self.dr_deploy_opt.create_hyper_metro_vstore_pair(
                domain_id, local_vstore_id, remote_vstore_id)
        else:
            vstore_pair_info = self.dr_deploy_opt.query_hyper_metro_vstore_pair_info(vstore_pair_id)
        health_status = vstore_pair_info.get("HEALTHSTATUS")
        running_status = vstore_pair_info.get("RUNNINGSTATUS")
        if running_status != VstorePairRunningStatus.Normal and health_status != HealthStatus.Normal:
            err_msg = "Hyper metro vstore pair status is not normal, " \
                      "health_status[%s], running_status[%s], details: %s" % \
                      (get_status(health_status, HealthStatus),
                       get_status(running_status, VstorePairRunningStatus),
                       vstore_pair_info)
            LOG.error(err_msg)
            self.record_deploy_process("create_metro_vstore_pair", "failed", code=-1, description=err_msg)
            raise Exception(err_msg)
        self.record_deploy_process("create_metro_vstore_pair", "success")
        return vstore_pair_info

    def do_create_hyper_metro_filesystem_pair(self, vstore_pair_info: dict) -> dict:
        """
        创建文件系统双活
        :param vstore_pair_info: 双活租户pair信息
        :return:
        """
        self.record_deploy_process("create_metro_fs_pair", "start")
        vstore_pair_id = vstore_pair_info.get("ID")
        remote_pool_id = self.dr_deploy_info.get("remote_pool_id")
        dbstore_fs_vstore_id = self.dr_deploy_info.get("dbstore_fs_vstore_id")
        storage_dbstore_fs = self.dr_deploy_info.get("storage_dbstore_fs")
        dbstore_fs_info = self.dr_deploy_opt.storage_opt.query_filesystem_info(storage_dbstore_fs,
                                                                               dbstore_fs_vstore_id)
        self.record_deploy_process("create_metro_fs_pair", "running")
        dbstore_fs_id = dbstore_fs_info.get("ID")
        filesystem_pair_info = self.dr_deploy_opt.query_hyper_metro_filesystem_pair_info(dbstore_fs_id)
        if filesystem_pair_info is None:
            filesystem_pair_task_info = self.dr_deploy_opt.create_hyper_metro_filesystem_pair(
                filesystem_id=dbstore_fs_id, pool_id=remote_pool_id, vstore_pair_id=vstore_pair_id)
            task_id = filesystem_pair_task_info.get("taskId")
            self.record_deploy_process("create_metro_fs_pair", "running")
            self.dr_deploy_opt.query_omtask_process(task_id, timeout=120)
        self.record_deploy_process("create_metro_fs_pair", "success")
        filesystem_pair_info = self.dr_deploy_opt.query_hyper_metro_filesystem_pair_info(dbstore_fs_id)
        return filesystem_pair_info[0]

    def do_sync_hyper_metro_filesystem_pair(self, pair_id: str) -> bool:
        """
        同步双活pair
        :param pair_id: ulog文件系统pair id
        :return:
        """
        filesystem_pair_info = self.dr_deploy_opt.query_hyper_metro_filesystem_pair_info_by_pair_id(pair_id)
        running_status = filesystem_pair_info.get("RUNNINGSTATUS")
        sync_progress = filesystem_pair_info.get("SYNCPROGRESS")
        health_status = filesystem_pair_info.get("HEALTHSTATUS")
        if running_status == FilesystemPairRunningStatus.Normal \
                and health_status == HealthStatus.Normal \
                and sync_progress == "100":
            LOG.info("Sync hyper metro filesystem pair success")
            self.record_deploy_process("sync_metro_fs_pair", "success")
            return True
        if running_status == FilesystemPairRunningStatus.Invalid or health_status != HealthStatus.Normal:
            err_msg = "Failed to create hyper metro filesystem pair, " \
                      "health status[%s], running status[%s] details:%s" % \
                      (get_status(health_status, HealthStatus),
                       get_status(running_status, FilesystemPairRunningStatus),
                       filesystem_pair_info)
            self.record_deploy_process("sync_metro_fs_pair", "failed", code=-1, description=err_msg)
            raise Exception(err_msg)
        time.sleep(2)
        LOG.info("Create hyper metro filesystem pair process[%s%%], "
                 "running_status[%s], health_status[%s]",
                 sync_progress,
                 get_status(running_status, FilesystemPairRunningStatus),
                 get_status(health_status, HealthStatus))
        if running_status == FilesystemPairRunningStatus.Paused:
            self.record_deploy_process("sync_metro_fs_pair", get_status(running_status, FilesystemPairRunningStatus))
        else:
            self.record_deploy_process("sync_metro_fs_pair", sync_progress + "%")
        return False

    def do_create_remote_replication_filesystem_pair(self, page_fs_id):
        """
        创建远程复制pair对
        :param page_fs_id:
        :return:
        """
        remote_device_id = self.dr_deploy_info.get("remote_device_id")
        remote_pool_id = self.dr_deploy_info.get("remote_pool_id")
        name_suffix = self.dr_deploy_info.get("name_suffix", "")
        remote_name_rule = 2 if name_suffix else 1
        remote_replication_pair_info = self.dr_deploy_opt.query_remote_replication_pair_info(
            filesystem_id=page_fs_id)
        if remote_replication_pair_info is None:
            rep_filesystem_pair_task_info = self.dr_deploy_opt.create_remote_replication_filesystem_pair(
                remote_device_id=remote_device_id,
                remote_pool_id=remote_pool_id,
                local_fs_id=page_fs_id,
                remote_name_rule=remote_name_rule,
                name_suffix=name_suffix
            )
            rep_filesystem_pair_task_id = rep_filesystem_pair_task_info.get("taskId")
            self.dr_deploy_opt.query_omtask_process(rep_filesystem_pair_task_id, timeout=120)
            remote_replication_pair_info = self.dr_deploy_opt.query_remote_replication_pair_info(
                filesystem_id=page_fs_id)
        return remote_replication_pair_info

    @retry(retry_times=3, wait_times=20, log=LOG, task="do_sync_remote_replication_filesystem_pair")
    def do_sync_remote_replication_filesystem_pair(self, pair_id: str, is_page: bool) -> bool:
        """
        同步远程复制pair
        :param is_page: page文件系统或者是meta文件系统
        :param pair_id: 远程复制ID
        :return:
        """
        exec_step = "sync_rep_meta_fs_pair" if not is_page else "sync_rep_page_fs_pair"
        remote_replication_pair_info = self.dr_deploy_opt.query_remote_replication_pair_info_by_pair_id(
            pair_id=pair_id)
        replication_pair_id = remote_replication_pair_info.get("ID")
        replication_progress = remote_replication_pair_info.get("REPLICATIONPROGRESS")
        start_time = remote_replication_pair_info.get("STARTTIME")
        end_time = remote_replication_pair_info.get("ENDTIME")
        replication_pair_health_status = remote_replication_pair_info.get("HEALTHSTATUS")
        replication_pair_running_status = remote_replication_pair_info.get("RUNNINGSTATUS")
        # 当已经设置从端可读写状态，且为分裂状态时，直接返回
        secres_access = remote_replication_pair_info.get("SECRESACCESS")
        if not is_page:
            self.meta_fs_pair_id = replication_pair_id
        else:
            self.page_fs_pair_id = replication_pair_id
        if secres_access == SecresAccess.ReadAndWrite and \
                replication_pair_running_status == ReplicationRunningStatus.Split:
            LOG.info("Create remote replication pair success.")
            self.record_deploy_process(exec_step, "success")
            return True
        self.replication_status_check_and_sync(exec_step, remote_replication_pair_info)
        time.sleep(20)
        LOG.info("Sync remote replication filesystem pair[%s], health status:[%s], "
                 "running status[%s], progress[%s%%], start time[%s]",
                 replication_pair_id,
                 get_status(replication_pair_health_status, HealthStatus),
                 get_status(replication_pair_running_status, ReplicationRunningStatus),
                 replication_progress,
                 datetime.datetime.fromtimestamp(int(start_time)))
        if replication_progress == "100" and \
                replication_pair_running_status == ReplicationRunningStatus.Normal and \
                replication_pair_health_status == HealthStatus.Normal:
            LOG.info("Success to sync remote replication filesystem pair[%s], end time[%s]",
                     replication_pair_id,
                     datetime.datetime.fromtimestamp(int(end_time)))
            if int(start_time) - int(end_time) > Constant.FULL_SYNC_MAX_TIME:
                LOG.info("Do sync remote replication filesystem[%s] pair of full copy." % replication_pair_id)
                self.dr_deploy_opt.sync_remote_replication_filesystem_pair(pair_id=replication_pair_id, vstore_id=0,
                                                                           is_full_copy=False)
                return False
            self.record_deploy_process(exec_step, "success")
            return True
        if replication_pair_health_status != ReplicationRunningStatus.Normal or \
                replication_pair_running_status not in \
                [ReplicationRunningStatus.Normal, ReplicationRunningStatus.Synchronizing]:
            err_msg = "Failed to sync remote replication filesystem[%s] pair." % replication_pair_id
            self.record_deploy_process(exec_step, "failed", code=-1, description=err_msg)
            raise Exception(err_msg)
        self.record_deploy_process(exec_step, replication_progress + "%")
        return False

    def replication_status_check_and_sync(self, exec_step, remote_replication_pair_info):
        """
        检查复制pair对状态，并进行同步
        :param exec_step:
        :param remote_replication_pair_info:
        :return:
        """
        replication_pair_id = remote_replication_pair_info.get("ID")
        start_time = remote_replication_pair_info.get("STARTTIME")
        replication_pair_health_status = remote_replication_pair_info.get("HEALTHSTATUS")
        replication_pair_running_status = remote_replication_pair_info.get("RUNNINGSTATUS")
        # 当复制pair对健康状态为非正常状态，并且running状态不为正常、正在同步、待恢复状态，异常退出
        if replication_pair_health_status != HealthStatus.Normal and \
                replication_pair_running_status not in [ReplicationRunningStatus.Normal,
                                                        ReplicationRunningStatus.Synchronizing,
                                                        ReplicationRunningStatus.TobeRecovered]:
            err_msg = "Current replication pair health is not normal, " \
                      "current status: %s, running status:%s, filesystem: %s" % \
                      (get_status(replication_pair_health_status, HealthStatus),
                       get_status(replication_pair_running_status, ReplicationRunningStatus),
                       replication_pair_id)
            self.record_deploy_process(exec_step, "failed", code=-1, description=err_msg)
            LOG.error(err_msg)
            raise Exception(err_msg)
        # 当前远程复制pair对状态为分裂且没有同步开始时间时，表示当前为首次创建还未同步，执行全量同步
        if replication_pair_running_status == ReplicationRunningStatus.Split and start_time is None:
            LOG.info("Do sync remote replication filesystem[%s] pair of full copy." % replication_pair_id)
            self.dr_deploy_opt.sync_remote_replication_filesystem_pair(pair_id=replication_pair_id,
                                                                       vstore_id="0",
                                                                       is_full_copy=True)
        # 当前远程复制pair对状态为分裂且有同步开始时间时，表示当前为首次创建还未同步，执行增量同步
        if replication_pair_running_status in \
                [ReplicationRunningStatus.Split, ReplicationRunningStatus.TobeRecovered] \
                and start_time is not None:
            LOG.info("Do sync remote replication filesystem[%s] pair of incremental." % replication_pair_id)
            self.dr_deploy_opt.sync_remote_replication_filesystem_pair(pair_id=replication_pair_id,
                                                                       vstore_id="0",
                                                                       is_full_copy=False)

    def do_remote_replication_filesystem_pair_cancel_secondary_write_lock(self, pair_id: str, is_page: bool) -> None:
        """
        远程复制pair对分裂后取消从端写锁
              1、 查询pair对状态
              2、分裂状态并且为有读写权限时，返回
              3、取消从端写保护
        :param is_page: 是否是page文件系统，否则为meta文件系统
        :param pair_id: 远程复制pair对id
        """
        exec_step = "cancel_rep_meta_fs_secondary_write_lock" if not is_page \
            else "cancel_rep_page_fs_secondary_write_lock"
        self.record_deploy_process(exec_step, "start")
        rep_pair_info = self.dr_deploy_opt.query_remote_replication_pair_info_by_pair_id(pair_id)
        self.record_deploy_process(exec_step, "running")
        secres_access = rep_pair_info.get("SECRESACCESS")
        running_status = rep_pair_info.get("RUNNINGSTATUS")
        if secres_access == SecresAccess.ReadAndWrite and running_status == ReplicationRunningStatus.Split:
            LOG.info("Current replicantion pair status already is[%s].", get_status(secres_access, SecresAccess))
            self.record_deploy_process(exec_step, "success")
            return
        self.dr_deploy_opt.remote_replication_filesystem_pair_cancel_secondary_write_lock(pair_id)
        self.record_deploy_process(exec_step, "success")

    def deploy_remote_replication_pair(self, fs_name: str, is_page: bool) -> str:
        """
        1、查询文件系统是否配置远程复制：已经配置场景查询，再次触发同步操作
        2、创建远程复制
        3、同步数据：
           1）记录同步开始时间与结束时间
           2）同步时间超过1h，再次出发同步
           3）查询同步状态
        4、分裂文件系统
        5、取消从站点写保护
        :param is_page: 是否为page文件系统，否则为meta文件系统
        :param fs_name: 文件系统名
        :return:
        """
        exec_step = "create_rep_meta_fs_pair" if not is_page else "create_rep_page_fs_pair"
        self.record_deploy_process(exec_step, "start")
        LOG.info("Start to create [%s]remote replication pair success.", fs_name)
        LOG.info("Create remote replication pair step 1: query filesystem[%s] info.", fs_name)
        fs_info = self.dr_deploy_opt.storage_opt.query_filesystem_info(fs_name)
        fs_id = fs_info.get("ID")
        LOG.info("Create remote replication pair step 2: create filesystem[%s] pair.", fs_name)
        self.record_deploy_process(exec_step, "running")
        remote_replication_pair_info = self.do_create_remote_replication_filesystem_pair(fs_id)
        replication_pair_id = remote_replication_pair_info[0].get("ID")
        key = "page_fs_pair_id" if is_page else "meta_fs_pair_id"
        self.record_disaster_recovery_info(key, replication_pair_id)
        self.record_deploy_process(exec_step, "success")
        return replication_pair_id

    def deploy_hyper_metro_pair(self):
        """
        1、查询双活域
        2、创建双活域
        3、查询双活租户pair
        4、创建双活租户pair
        5、查询双活pair
        6、创建说活pair
        7、查询同步状态
        :return:
        """
        try:
            domain_info = self.do_create_filesystem_hyper_metro_domain()
        except Exception as err:
            self.record_deploy_process("create_metro_domain", "failed", code=-1, description=str(err))
            raise err
        self.record_disaster_recovery_info("hyper_domain_id", domain_info.get("ID"))
        try:
            vstore_pair_info = self.do_create_hyper_metro_vstore_pair(domain_info)
        except Exception as err:
            self.record_deploy_process("create_metro_vstore_pair", "failed", code=-1, description=str(err))
            raise err
        self.record_disaster_recovery_info("vstore_pair_id", vstore_pair_info.get("ID"))
        try:
            filesystem_pair_info = self.do_create_hyper_metro_filesystem_pair(vstore_pair_info)
        except Exception as err:
            self.record_deploy_process("create_metro_fs_pair", "failed", code=-1, description=str(err))
            raise err
        self.ulog_fs_pair_id = filesystem_pair_info.get("ID")
        self.record_disaster_recovery_info("ulog_fs_pair_id", filesystem_pair_info.get("ID"))

    def query_cantian_disaster_recovery_status(self):
        """
        查询当前参天回放状态
        1、查询当前节点是否为reformer节点
        :return:
        """
        self.record_deploy_process("cantian_disaster_recovery_status", "start")
        node_id = self.dr_deploy_info.get("node_id")
        cms_cmd = "su -s /bin/bash - cantian -c 'source ~/.bashrc " \
                  "&& cms stat | awk \"{print \$1, \$9}\"'"
        return_code, output, stderr = exec_popen(cms_cmd)
        LOG.info("Check cms reformer node.")
        if return_code:
            err_msg = "Execute cms command[%s] query reform node failed, output:%s, " \
                      "stderr:%s" % (cms_cmd, output, stderr)
            self.record_deploy_process("cantian_disaster_recovery_status", "failed",
                                       code=-1, description=err_msg)
            raise Exception(err_msg)
        cms_stat = output.split("\n")
        LOG.info("Cms stat is:\n %s", cms_stat)
        LOG.info("Check cantian replay status.")
        self.record_deploy_process("cantian_disaster_recovery_status", "running")
        for node_stat in cms_stat:
            if "REFORMER" in node_stat and node_id == node_stat.split(" ")[0].strip(" "):
                return_code, output, stderr = exec_popen(CANTIAN_DISASTER_RECOVERY_STATUS_CHECK, timeout=20)
                if return_code:
                    err_msg = "Execute check cantian disaster recovery command failed, " \
                              "oupout:%s, stderr:%s" % (output, stderr)
                    self.record_deploy_process("cantian_disaster_recovery_status", "failed",
                                               code=-1, description=err_msg)

                    LOG.info("Check cantian replay failed.")
                    raise Exception(err_msg)
                if "START_REPLAY" not in output:
                    err_msg = "Cantian lrpl status is abnormal, details: %s" % output.split("SQL>")[1:]
                    self.record_deploy_process("cantian_disaster_recovery_status", "failed", code=-1,
                                               description=err_msg)
                    LOG.info("Check cantian replay failed.")
                    raise Exception(err_msg)

        LOG.info("Check cantian replay success.")
        self.record_deploy_process("cantian_disaster_recovery_status", "success")

    def do_start(self, node_id):
        """
        本端节点启动
        :param node_id: 节点id
        :return:
        """
        if self.check_install_status(node_id, "start"):
            return True
        self.update_install_status(node_id, "start", "default")
        LOG.info("Start node[%s] cantian.", node_id)
        ctl_file_path = os.path.join(CURRENT_PATH, "../../")
        cmd = "sh %s/start.sh standby" % ctl_file_path
        _, output, stderr = exec_popen(cmd, timeout=3600)
        if "start success" not in output:
            self.update_install_status(node_id, "start", "failed")
            err_pattern = re.compile(".*ERROR.*")
            _err = err_pattern.findall(output + stderr)
            err_msg = "Failed to execute start, details:\n%s  for details see " \
                      "/opt/cantian/deploy/deploy.log" % "\n".join(_err)
            self.record_deploy_process("standby_start", "failed", code=-1, description=err_msg)
            raise Exception(err_msg)
        self.update_install_status(node_id, "start", "success")
        LOG.info("Start node[%s] cantian success.", node_id)
        return True

    def update_install_status(self, node_id, exec_step, exec_status):
        """
        更新配置文件中安装部署状态
        1、 检查当前是否有挂载点，没有直接返回
        :param node_id: 节点id
        :param exec_step: 执行步骤（install/stop/start/uninstall）
        :param exec_status: 步骤执行状态（success/failed）
        :return:
        """
        LOG.info("Start to update %s status[%s] start", exec_step, exec_status)
        share_fs_name = self.dr_deploy_info.get("storage_share_fs")
        share_path = f"/mnt/dbdata/remote/share_{share_fs_name}"
        check_mount_cmd = f"mountpoint {share_path} > /dev/null 2>&1"
        return_code, _, _ = exec_popen(check_mount_cmd)
        if return_code:
            LOG.info("Cantian hasn't been installed.")
            return
        install_record_file = f"/mnt/dbdata/remote/share_{share_fs_name}/node{node_id}_install_record.json"
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        modes = stat.S_IWUSR | stat.S_IRUSR
        if os.path.exists(install_record_file):
            with open(install_record_file, "r") as fp:
                install_status = json.loads(fp.read())
            with os.fdopen(os.open(install_record_file, flags, modes), 'w') as fp:
                install_status.update({exec_step: exec_status})
                json.dump(install_status, fp, indent=4)
        else:
            data = {"install": "default", "start": "default", "stop": "default"}
            data.update({exec_step: exec_status})
            with os.fdopen(os.open(install_record_file, flags, modes), 'w') as fp:
                json.dump(data, fp, indent=4)
        LOG.info("Update %s status[%s] success", exec_step, exec_status)

    def check_install_status(self, node_id, exec_step):
        """
        检查当前执行步骤执行状态,重入时先检查当前执行状态，如果执行结果为成功直接返回
        :param node_id: 节点id
        :param exec_step: 执行步骤（install/start/stop/uninstall）
        :return:
        """
        share_fs_name = self.dr_deploy_info.get("storage_share_fs")
        install_record_file = f"/mnt/dbdata/remote/share_{share_fs_name}/node{node_id}_install_record.json"
        if not os.path.exists(install_record_file):
            return False
        with open(install_record_file, "r") as fp:
            status_info = json.loads(fp.read())
            status = status_info.get(exec_step)
        if status == "success":
            return True
        return False

    def standby_check_ulog_fs_pair_ready(self, ulog_fs_pair_ready_flag):
        """
        备端检查ulog文件系统pair对创建进度
        :param ulog_fs_pair_ready_flag:
        :return:
        """
        dbstore_fs_name = self.dr_deploy_info.get("storage_dbstore_fs")
        dbstore_fs_vstore_id = self.dr_deploy_info.get("dbstore_fs_vstore_id")
        dbstore_fs_info = self.dr_deploy_opt.storage_opt.query_filesystem_info(
            dbstore_fs_name, vstore_id=dbstore_fs_vstore_id)
        ulog_fs_pair_info = None
        if dbstore_fs_info and not ulog_fs_pair_ready_flag:
            dbstore_fs_id = dbstore_fs_info.get("ID")
            try:
                ulog_fs_pair_info = self.dr_deploy_opt.query_hyper_metro_filesystem_pair_info(dbstore_fs_id)
            except Exception as err:
                self.record_deploy_process("create_metro_fs_pair", "failed",
                                           code=-1, description=str(err))
                raise err
            self.record_deploy_process("create_metro_domain", "success")
            self.record_deploy_process("create_metro_vstore_pair", "success")
            self.record_deploy_process("create_metro_fs_pair", "success")
            if ulog_fs_pair_info:
                ulog_fs_pair_id = ulog_fs_pair_info[0].get("ID")
                running_status = ulog_fs_pair_info[0].get("RUNNINGSTATUS")
                sync_progress = ulog_fs_pair_info[0].get("SYNCPROGRESS")
                health_status = ulog_fs_pair_info[0].get("HEALTHSTATUS")
                hyper_domain_id = ulog_fs_pair_info[0].get("DOMAINID")
                vstore_pair_id = ulog_fs_pair_info[0].get("VSTOREPAIRID")
                if running_status == FilesystemPairRunningStatus.Paused:
                    self.record_deploy_process("sync_metro_fs_pair",
                                               get_status(running_status, FilesystemPairRunningStatus))
                else:
                    self.record_deploy_process("sync_metro_fs_pair", sync_progress + "%")
                if running_status == FilesystemPairRunningStatus.Normal \
                        and health_status == HealthStatus.Normal \
                        and sync_progress == "100":
                    LOG.info("Hyper metro filesystem[%s] pair ready", dbstore_fs_name)
                    self.record_deploy_process("sync_metro_fs_pair", "success")
                    ulog_fs_pair_ready_flag = True
                    self.record_disaster_recovery_info("ulog_fs_pair_id", ulog_fs_pair_id)
                    self.record_disaster_recovery_info("hyper_domain_id", hyper_domain_id)
                    self.record_disaster_recovery_info("vstore_pair_id", vstore_pair_id)
        return ulog_fs_pair_info, ulog_fs_pair_ready_flag

    def standby_check_page_fs_pair_ready(self, page_fs_pair_ready_flag):
        """
        备端检查page文件系统pair对创建进度
        :param page_fs_pair_ready_flag:
        :return:
        """
        dbstore_page_fs_name = self.dr_deploy_info.get("storage_dbstore_page_fs")
        dbstore_page_fs_info = self.dr_deploy_opt.storage_opt.query_filesystem_info(
            dbstore_page_fs_name)
        page_fs_pair_info = None
        if dbstore_page_fs_info and not page_fs_pair_ready_flag:
            self.record_deploy_process("create_rep_page_fs_pair", "success")
            dbstore_page_fs_id = dbstore_page_fs_info.get("ID")
            page_fs_pair_info = self.dr_deploy_opt.query_remote_replication_pair_info(dbstore_page_fs_id)
            if page_fs_pair_info:
                # 当已经设置从端可读写状态，且为分裂状态时，表示当前同步完成
                page_fs_pair_id = page_fs_pair_info[0].get("ID")
                secres_access = page_fs_pair_info[0].get("SECRESACCESS")
                running_status = page_fs_pair_info[0].get("RUNNINGSTATUS")
                remote_replication_pair_info = self.dr_deploy_opt.query_remote_replication_pair_info_by_pair_id(
                    page_fs_pair_id)
                replication_progress = remote_replication_pair_info.get("REPLICATIONPROGRESS")
                self.record_deploy_process("sync_rep_page_fs_pair", str(replication_progress) + "%")
                if secres_access == SecresAccess.ReadAndWrite and running_status == ReplicationRunningStatus.Split:
                    LOG.info("Remote replication pair[%s] ready.", dbstore_page_fs_name)
                    self.record_deploy_process("sync_rep_page_fs_pair", "success")
                    page_fs_pair_ready_flag = True
                    self.record_disaster_recovery_info("page_fs_pair_id", page_fs_pair_id)
        return page_fs_pair_info, page_fs_pair_ready_flag

    def standby_check_metadata_fs_pair_ready(self, metadata_fs_ready_flag):
        """
        备端检查metadata文件系统pair创建进度
        :param metadata_fs_ready_flag:
        :return:
        """
        mysql_metadata_in_cantian = self.dr_deploy_info.get("mysql_metadata_in_cantian")
        metadata_fs_name = self.dr_deploy_info.get("storage_metadata_fs")
        metadata_fs_info = self.dr_deploy_opt.storage_opt.query_filesystem_info(
            metadata_fs_name)
        metadata_fs_pair_info = None if not mysql_metadata_in_cantian else metadata_fs_info
        if metadata_fs_info and not mysql_metadata_in_cantian and not metadata_fs_ready_flag:
            metadata_fs_id = metadata_fs_info.get("ID")
            metadata_fs_pair_info = self.dr_deploy_opt.query_remote_replication_pair_info(metadata_fs_id)
            self.record_deploy_process("create_rep_meta_fs_pair", "success")
            if metadata_fs_pair_info:
                # 当已经设置从端可读写状态，且为分裂状态时，表示当前同步完成
                meta_fs_pair_id = metadata_fs_pair_info[0].get("ID")
                secres_access = metadata_fs_pair_info[0].get("SECRESACCESS")
                running_status = metadata_fs_pair_info[0].get("RUNNINGSTATUS")
                remote_replication_pair_info = self.dr_deploy_opt. \
                    query_remote_replication_pair_info_by_pair_id(meta_fs_pair_id)
                replication_progress = remote_replication_pair_info.get("REPLICATIONPROGRESS")
                self.record_deploy_process("sync_rep_meta_fs_pair", str(replication_progress) + "%")
                if secres_access == SecresAccess.ReadAndWrite and running_status == ReplicationRunningStatus.Split:
                    LOG.info("Remote replication pair[%s] ready.", metadata_fs_name)
                    self.record_deploy_process("sync_rep_meta_fs_pair", "success")
                    metadata_fs_ready_flag = True
                    self.record_disaster_recovery_info("meta_fs_pair_id", meta_fs_pair_id)
        return metadata_fs_pair_info, metadata_fs_ready_flag, metadata_fs_info

    def create_nfs_share_and_client(self, fs_info: dict) -> None:
        """
        元数据非归一场景，metadata文件系统需要创建共享
        1、查询文件系统共享，不存在创建，存在返回
        2、查询文件系统客户端，不存在创建，存在返回
        :param fs_info: 文件系统信息
        :return:
        """
        if self.metadata_in_cantian:
            return
        fs_id = fs_info.get("ID")
        fs_name = fs_info.get("NAME")
        share_data = {
            "SHAREPATH": f"/{fs_name}/",
            "vstoreId": "0",
            "FSID": fs_id
        }
        share_info = self.dr_deploy_opt.storage_opt.query_nfs_info(fs_id)
        if not share_info:
            parent_id = self.dr_deploy_opt.storage_opt.create_nfs_share(share_data)
        else:
            parent_id = share_info[0].get("ID")
        client_data = {
            "ACCESSVAL": 1,
            "ALLSQUASH": 1,
            "ROOTSQUASH": 1,
            "PARENTID": parent_id,
            "vstoreId": "0",
            "NAME": "*"
        }
        client_info = self.dr_deploy_opt.storage_opt.query_nfs_share_auth_client(parent_id)
        if not client_info:
            self.dr_deploy_opt.storage_opt.add_nfs_client(client_data)

    def standby_do_install(self):
        """
        主备节点同时下发安装部署命令，0 节点安装完成后，1 节点启动安装，1 节点安装部署完成后，0 节点与1 节点同时返回成功
        dr_deploy_install_record.json:
             {
                 install_status: success/failed,
                 start_status: success/failed
             }
        :return:
        """
        LOG.info("Start to install cantian engine.")
        node_id = self.dr_deploy_info.get("node_id")
        if self.check_install_status(node_id, "start"):
            return True
        node_id = self.dr_deploy_info.get("node_id")
        if not self.check_install_status(node_id, "install"):
            ctl_file_path = os.path.join(CURRENT_PATH, "../../")
            dbstor_user = input()
            dbstor_pwd = input()
            cantian_pwd = input()
            comfirm_cantian_pwd = input()
            cert_encrypt_pwd = ""
            if self.dr_deploy_info.get("mes_ssl_switch"):
                cert_encrypt_pwd = input()
            cmd = "echo -e \"%s\\n%s\\n%s\\n%s\\n%s\"|sh %s/install.sh %s" \
                  % (dbstor_user, dbstor_pwd,
                     cantian_pwd, comfirm_cantian_pwd, cert_encrypt_pwd,
                     ctl_file_path, DR_DEPLOY_CONFIG)
            _, output, stderr = exec_popen(cmd, timeout=600)
            if "install success" not in output:
                err_pattern = re.compile(".*ERROR.*")
                _err = err_pattern.findall(output + stderr)
                err_msg = "Failed to execute install, details:\n%s, for details see " \
                          "/opt/cantian/deploy/deploy.log" % "\n".join(_err)
                self.record_deploy_process("standby_install", "failed", code=-1, description=err_msg)
                self.update_install_status(node_id, "install", "failed")
                raise Exception(err_msg)
            self.update_install_status(node_id, "install", "success")
        LOG.info("Install cantian engine success.")
        return True

    def standby_do_start(self):
        LOG.info("Start to start cantian engine.")
        node_id = self.dr_deploy_info.get("node_id")
        self.do_start(node_id)
        LOG.info("Start cantian engine success.")

    def active_dr_deploy_and_sync(self):
        """
        容灾同步与复制对分裂、取消从资源保护
        :return:
        """
        ulog_ready, page_ready, meta_ready = True, True, True
        while True:
            try:
                ulog_ready = self.do_sync_hyper_metro_filesystem_pair(self.ulog_fs_pair_id)
            except Exception as err:
                self.record_deploy_process("sync_metro_fs_pair", "failed", code=-1, description=str(err))
                raise err
            try:
                page_ready = self.do_sync_remote_replication_filesystem_pair(self.page_fs_pair_id, True)
            except Exception as err:
                self.record_deploy_process("sync_rep_page_fs_pair", "failed", code=-1, description=str(err))
                raise err
            if not self.metadata_in_cantian:
                try:
                    meta_ready = self.do_sync_remote_replication_filesystem_pair(self.meta_fs_pair_id, False)
                except Exception as err:
                    self.record_deploy_process("sync_rep_meta_fs_pair", "failed", code=-1, description=str(err))
                    raise err
            if ulog_ready and page_ready and meta_ready:
                break
            time.sleep(60)
        try:
            self.dr_deploy_opt.split_remote_replication_filesystem_pair(self.page_fs_pair_id)
            self.do_remote_replication_filesystem_pair_cancel_secondary_write_lock(
                self.page_fs_pair_id, True)
        except Exception as err:
            self.record_deploy_process("cancel_rep_page_fs_secondary_write_lock",
                                       "failed", code=-1, description=str(err))
            raise err
        if not self.metadata_in_cantian:
            try:
                self.dr_deploy_opt.split_remote_replication_filesystem_pair(self.meta_fs_pair_id)
                self.do_remote_replication_filesystem_pair_cancel_secondary_write_lock(
                    self.meta_fs_pair_id, False)
            except Exception as err:
                self.record_deploy_process("cancel_rep_meta_fs_secondary_write_lock",
                                           "failed", code=-1, description=str(err))
                raise err

    def active_execute(self):
        """
        主端灾备搭建
        1、加备份锁
        2、full check point
        3、flush table
        4、创建文件系统双活域
        5、创建双活租户pair
        6、创建双活pair
        7、创建远程复制pair
        8、同步数据
        9、分裂文件系统
        10、解备份锁
        11、返回
        :return:
        """
        if not self.mysql_cmd or not self.mysql_user:
            err_msg = "Mysql_pwd or mysql_user is None, please check."
            LOG.error(err_msg)
            raise Exception(err_msg)
        self.mysql_pwd = input()
        self.record_deploy_process("dr_deploy", "start")
        self.record_deploy_process("dr_deploy", "running")
        self.do_lock_instance_for_backup()
        self.do_full_check_point()
        self.do_flush_table_with_read_lock()
        dbstore_page_fs_name = self.dr_deploy_info.get("storage_dbstore_page_fs")
        metadata_fs_name = self.dr_deploy_info.get("storage_metadata_fs")
        self.deploy_hyper_metro_pair()
        try:
            self.page_fs_pair_id = self.deploy_remote_replication_pair(dbstore_page_fs_name, True)
        except Exception as err:
            self.record_deploy_process("create_rep_page_fs_pair", "failed", code=-1, description=str(err))
            raise err
        if not self.metadata_in_cantian:
            try:
                self.meta_fs_pair_id = self.deploy_remote_replication_pair(metadata_fs_name, False)
            except Exception as err:
                self.record_deploy_process("create_rep_meta_fs_pair", "failed", code=-1, description=str(err))
                raise err
        self.active_dr_deploy_and_sync()
        self.do_unlock_instance_for_backup()
        self.record_deploy_process("dr_deploy", "success")

    def standby_execute(self):
        """
        备端灾备搭建
        1、备端查询容灾状态
        2、安装部署参天
        3、备站方式启动
        4、检查参天容灾状态
        5、返回
        :return:
        """
        self.record_deploy_process("dr_deploy", "running")
        mysql_metadata_in_cantian = self.dr_deploy_info.get("mysql_metadata_in_cantian")
        ulog_fs_pair_ready_flag = False
        page_fs_pair_ready_flag = False
        metadata_fs_ready_flag = False if not mysql_metadata_in_cantian else True
        is_installed_flag = False
        wait_time = 0
        while True:
            ulog_fs_pair_info, ulog_fs_pair_ready_flag = \
                self.standby_check_ulog_fs_pair_ready(ulog_fs_pair_ready_flag)
            page_fs_pair_info, page_fs_pair_ready_flag = \
                self.standby_check_page_fs_pair_ready(page_fs_pair_ready_flag)
            metadata_fs_pair_info, metadata_fs_ready_flag, metadata_fs_info = \
                self.standby_check_metadata_fs_pair_ready(metadata_fs_ready_flag)
            fs_ready = ulog_fs_pair_info and page_fs_pair_info and metadata_fs_pair_info
            if fs_ready and not is_installed_flag:
                LOG.info("Filesystem creat success, start to isntall cantian engine.")
                self.record_deploy_process("standby_install", "running")
                self.create_nfs_share_and_client(metadata_fs_info)
                self.standby_do_install()
                self.record_deploy_process("standby_install", "success")
                is_installed_flag = True
            else:
                if wait_time > FS_CREAT_TIMEOUT and not is_installed_flag:
                    err_msg = "Wait for the filesystem creat timeout, please check."
                    self.record_deploy_process("standby_install", "failed", code=-1, description=err_msg)
                    LOG.error(err_msg)
                    raise Exception(err_msg)
                LOG.info("Wait until the DR is successfully set up, waited[%s]s", wait_time)
            pair_ready = metadata_fs_ready_flag and ulog_fs_pair_ready_flag and page_fs_pair_ready_flag
            if is_installed_flag and pair_ready:
                self.record_deploy_process("standby_start", "running")
                try:
                    self.standby_do_start()
                except Exception as err:
                    self.record_deploy_process("standby_start", "failed", code=-1, description=str(err))
                    raise err
                self.record_deploy_process("standby_start", "success")
                break
            time.sleep(60)
            wait_time += 60
        self.query_cantian_disaster_recovery_status()
        self.record_deploy_process("dr_deploy", "success")

    def execute(self):
        """
        deploy --site=[standby/active] --mysql_cmd='/usr/local/mysql/bin/mysql' --mysql_user=root
        :return:
        """
        def _execute():
            action_parse = argparse.ArgumentParser()
            action_parse.add_argument("--site", dest="site", choices=["standby", "active"], required=True)
            action_parse.add_argument("--mysql_cmd", dest="mysql_cmd", required=False)
            action_parse.add_argument("--mysql_user", dest="mysql_user", required=False)
            args = action_parse.parse_args()
            self.mysql_cmd = args.mysql_cmd
            self.mysql_user = args.mysql_user
            self.site = args.site
            self.record_deploy_process_init()
            self.init_storage_opt()
            try:
                if args.site == "active":
                    self.active_execute()
                else:
                    self.standby_execute()
            finally:
                self.dr_deploy_opt.storage_opt.logout()
            # 安装部署完成后记录加密密码到配置文件
            encrypted_pwd = KmcResolve.kmc_resolve_password("encrypted", self.dm_passwd)
            self.record_disaster_recovery_info("dm_pwd", encrypted_pwd)
            os.chmod(os.path.join(CURRENT_PATH, "../../../config/dr_deploy_param.json"), mode=0o644)
            try:
                shutil.copy(os.path.join(CURRENT_PATH, "../../../config/dr_deploy_param.json"), "/opt/cantian/config/")
            except Exception as _err:
                LOG.info(f"copy dr_deploy_param failed")
            share_path = f"/mnt/dbdata/remote/metadata_{self.dr_deploy_info.get('storage_metadata_fs')}"
            try:
                shutil.copy(os.path.join(CURRENT_PATH, "../../../config/dr_deploy_param.json"), share_path)
            except Exception as _err:
                LOG.info(f"copy dr_deploy_param failed")
            self.restart_cantian_exporter()
        try:
            _execute()
        except Exception as err:
            LOG.error("Dr deploy execute failed, traceback:%s", traceback.format_exc())
            raise err
