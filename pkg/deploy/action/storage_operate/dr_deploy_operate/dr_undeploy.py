#!/usr/bin/python3
# coding=utf-8
import argparse
import os
import json
import time
import shutil

from storage_operate.dr_deploy_operate.dr_deploy_common import DRDeployCommon
from storage_operate.dr_deploy_operate.dr_deploy import DRDeploy
from logic.storage_operate import StorageInf
from logic.common_func import read_json_config
from logic.common_func import exec_popen
from om_log import LOGGER as LOG

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
CANTIAN_DEPLOY_CONFIG = os.path.join(CURRENT_PATH, "../../../config/deploy_param.json")
DR_DEPLOY_CONFIG = os.path.join(CURRENT_PATH, "../../../config/dr_deploy_param.json")
UNINSTALL_TIMEOUT = 900


class UNDeploy(object):
    def __init__(self):
        self.dr_deploy = None
        self.dr_deploy_opt = None
        self.storage_opt = None
        self.site = None
        self.dr_deploy_info = read_json_config(DR_DEPLOY_CONFIG)
        
    def init_storage_opt(self):
        dm_ip = self.dr_deploy_info.get("dm_ip")
        dm_user = self.dr_deploy_info.get("dm_user")
        dm_passwd = input()
        self.storage_opt = StorageInf((dm_ip, dm_user, dm_passwd))
        self.storage_opt.login()
        self.dr_deploy_opt = DRDeployCommon(self.storage_opt)
        self.dr_deploy = DRDeploy()

    def delete_replication_filesystem_pair(self, page_id):
        try:
            self.dr_deploy_opt.query_remote_replication_pair_info_by_pair_id(page_id)
        except Exception as err:
            if "The specified remote replication is unavailable" in str(err):
                LOG.info("Replication pair id[%s] is not exist.", page_id)
                return
            else:
                raise err
        self.dr_deploy_opt.split_remote_replication_filesystem_pair(page_id)
        try:
            self.dr_deploy_opt.delete_remote_replication_filesystem_pair(page_id)
        except Exception as err:
            self.dr_deploy_opt.delete_remote_replication_filesystem_pair(page_id, is_local_del=True)
        LOG.info("Delete Replication pair[id:%s] success", page_id)

    def delete_filesystem(self, vstore_id, fs_name):
        if self.site == "active":
            return
        else:
            fs_info = self.dr_deploy_opt.storage_opt.query_filesystem_info(fs_name,
                                                                                   vstore_id)
            if not fs_info:
                LOG.info("Filesystem[%s] is not exist.", fs_name)
                return
            if fs_info.get("scheduleName") != "--":
                # schedule cdp 存在，先删除
                LOG.info("Delete schedule[%s]", fs_info.get("scheduleName"))
                self.dr_deploy_opt.storage_opt.delete_fs_cdp_schedule(fs_info.get("ID"),
                                                                      fs_info.get("TIMINGSNAPSHOTSCHEDULEID"),
                                                                      fs_info.get("scheduleName"),
                                                                      fs_info.get("vstoreId"))
                LOG.info("Delete schedule[%s] success!", fs_info.get("scheduleName"))
            fs_id = fs_info.get("ID")
            nfs_share_info = self.storage_opt.query_nfs_info(fs_id=fs_id, vstore_id=vstore_id)
            if nfs_share_info:
                nfs_share_id = nfs_share_info[0].get("ID")
                self.storage_opt.delete_nfs_share(nfs_share_id=nfs_share_id, vstore_id=vstore_id)
                LOG.info("Delete file system %s nfs share success!", fs_name)
            self.storage_opt.delete_file_system(fs_id)
            LOG.info("Delete file system %s success!", fs_name)

    def delete_hyper_metro_filesystem(self):
        """
        删除双活pair 文件系统的pair id
        """
        # 双活文件系统租户id
        dbstore_fs_vstore_id = self.dr_deploy_info.get("dbstore_fs_vstore_id")
        if not dbstore_fs_vstore_id:
            return
        # 双活文件系统名字
        storage_dbstore_fs = self.dr_deploy_info.get("storage_dbstore_fs")
        if not storage_dbstore_fs:
            return
        dbstore_fs_info = self.dr_deploy_opt.storage_opt.query_filesystem_info(storage_dbstore_fs,
                                                                               dbstore_fs_vstore_id)
        if not dbstore_fs_info:
            LOG.info("Filesystem[%s] is not exist.", storage_dbstore_fs)
            return
        # 双活文件系统id
        dbstore_fs_id = dbstore_fs_info.get("ID")
        # 通过双活文件系统id查询双活文件系统pair id
        hyper_filesystem_pair_info = self.dr_deploy_opt.query_hyper_metro_filesystem_pair_info(dbstore_fs_id)
        if hyper_filesystem_pair_info:
            hyper_filesystem_pair_id = hyper_filesystem_pair_info[0].get("ID")
            try:
                self.dr_deploy_opt.delete_hyper_metro_filesystem_pair(hyper_filesystem_pair_id, dbstore_fs_vstore_id)
            except Exception as err:
                self.dr_deploy_opt.delete_hyper_metro_filesystem_pair(hyper_filesystem_pair_id, dbstore_fs_vstore_id,
                                                                      is_local_del=True)
            LOG.info("Delete Hyper Metro filesystem pair id[%s] success", hyper_filesystem_pair_id)
        LOG.info("Delete Hyper Metro filesystem pair id success")

    def delete_hyper_metro_filesystem_vstore_id(self):
        """
        删除双活租户pair id
        """
        hyper_metro_vstore_pair_id = self.dr_deploy_info.get("vstore_pair_id")
        if not hyper_metro_vstore_pair_id:
            return
        try:
            self.dr_deploy_opt.query_hyper_metro_vstore_pair_info(hyper_metro_vstore_pair_id)
        except Exception as err:
            if "1073781761" in str(err):
                LOG.info("Hyper Metro pair id[%s] is not exist.", hyper_metro_vstore_pair_id)
                return
            else:
                raise err
        try:
            self.dr_deploy_opt.delete_hyper_metro_vstore_pair(hyper_metro_vstore_pair_id)
        except Exception as err:
            self.dr_deploy_opt.delete_hyper_metro_vstore_pair(hyper_metro_vstore_pair_id, is_local_del=True)
        LOG.info("Delete Hyper Metro pair id[id:%s] success", hyper_metro_vstore_pair_id)

    def delete_hyper_metro_domain(self):
        """
        分裂双活域，删除双活域
        """
        hyper_domain_id = self.dr_deploy_info.get("hyper_domain_id")
        if not hyper_domain_id:
            return
        try:
            self.dr_deploy_opt.query_hyper_metro_domain_info(hyper_domain_id)
        except Exception as err:
            if "1077674284" in str(err):
                LOG.info("Hyper filesystem pair id[%s] is not exist.", hyper_domain_id)
                return
            else:
                raise err
        self.dr_deploy_opt.split_filesystem_hyper_metro_domain(hyper_domain_id)
        try:
            self.dr_deploy_opt.delete_filesystem_hyper_metro_domain(hyper_domain_id)
        except Exception as err:
            self.dr_deploy_opt.delete_filesystem_hyper_metro_domain(hyper_domain_id, is_local_del=True)
        LOG.info("Delete hyper metro domain[id:%s] success", hyper_domain_id)

    def delete_replication(self):
        action_parse = argparse.ArgumentParser()
        action_parse.add_argument("--site", dest="site", choices=["standby", "active"], required=True)
        args = action_parse.parse_args()
        self.site = args.site
        page_fs_pair_id = self.dr_deploy_info.get("page_fs_pair_id")
        if page_fs_pair_id:
            self.delete_replication_filesystem_pair(page_fs_pair_id)
            LOG.info("Successfully delete metadata pair id %s.", page_fs_pair_id)
        meta_fs_pair_id = self.dr_deploy_info.get("meta_fs_pair_id")
        metadata_in_cantian = self.dr_deploy_info.get("metadata_in_cantian")
        if meta_fs_pair_id and not metadata_in_cantian:
            self.delete_replication_filesystem_pair(meta_fs_pair_id)
            LOG.info("Successfully delete metadata pair id %s.", meta_fs_pair_id)

    def delete_hyper(self):
        action_parse = argparse.ArgumentParser()
        action_parse.add_argument("--site", dest="site", choices=["standby", "active"], required=True)
        args = action_parse.parse_args()
        self.site = args.site
        # 删除双活文件系统pair id
        self.delete_hyper_metro_filesystem()
        # 删除双活文件系统租户pair id
        time.sleep(60)
        self.delete_hyper_metro_filesystem_vstore_id()
        self.delete_hyper_metro_domain()

    def do_stop(self):
        stop_flag_file = f"/opt/cantian/.stop_success"
        if not os.path.exists(stop_flag_file):
            node_id = self.dr_deploy_info.get("node_id")
            share_fs_name = self.dr_deploy_info.get("storage_share_fs")
            install_record_file = f"/mnt/dbdata/remote/share_{share_fs_name}/node{node_id}_install_record.json"
            ctl_file_path = os.path.join(CURRENT_PATH, "../../")
            cmd = "sh %s/stop.sh;last_cmd=$?" % ctl_file_path
            _, output, stderr = exec_popen(cmd, timeout=3600)
            if "Stop Cantian Engine success." not in output:
                err_msg = "Failed to execute stop, stderr:%s, output:%s" % (stderr, output)
                raise Exception(err_msg)
            if not os.path.exists(install_record_file):
                return
            self.dr_deploy.update_install_status(node_id, "stop", "success")
            with open(stop_flag_file, "w") as f:
                f.write("")

    def do_uninstall(self):
        ctl_file_path = os.path.join(CURRENT_PATH, "../../")
        cmd = "sh %s/uninstall.sh override" % ctl_file_path
        _, output, stderr = exec_popen(cmd, timeout=180)
        if "uninstall finished" not in output:
            err_msg = "Failed to execute uninstall, stderr:%s, output:%s" % (stderr, output)
            raise Exception(err_msg)
        if os.path.exists("/opt/cantian"):
            shutil.rmtree("/opt/cantian")

    def site_uninstall(self):
        node_id = self.dr_deploy_info.get("node_id")
        if node_id == "1":
            self.do_uninstall()
        else:
            self.wait_remote_node_exec("1", "stop", UNINSTALL_TIMEOUT)
            self.do_uninstall()
        return True

    def wait_remote_node_exec(self, node_id, exec_step, timeout):
        share_fs_name = self.dr_deploy_info.get("storage_share_fs")
        install_record_file = f"/mnt/dbdata/remote/share_{share_fs_name}/node{node_id}_install_record.json"
        wait_time = 0
        while timeout:
            time.sleep(10)
            wait_time += 10
            timeout -= 10
            LOG.info("wait node%s %s success, waited[%s]s", node_id, exec_step, wait_time)
            if not os.path.exists(install_record_file):
                return
            with open(install_record_file, "r") as fp:
                status_info = json.loads(fp.read())
            status = status_info.get(exec_step)
            if status == "success":
                break
            else:
                continue

    def check_process(self):
        process_name = "/storage_operate/dr_operate_interface.py deploy"
        cmd = "ps -ef | grep -v grep | grep '%s'" % process_name
        return_code, output, stderr = exec_popen(cmd)
        if return_code or not output:
            return False
        return True

    def standby_uninstall(self, node_id, uninstall_cantian_flag):
        if self.site == "standby" and os.path.exists(CANTIAN_DEPLOY_CONFIG) and uninstall_cantian_flag:
            self.do_stop()
            LOG.info("Stop Cantian engine success.")
        if node_id == "0":
            LOG.info("Start to delete dr deploy!")
            rep_fs_name = self.dr_deploy_info.get("storage_dbstore_page_fs")
            mysql_metadata_in_cantian = self.dr_deploy_info.get("mysql_metadata_in_cantian")
            metadata_fs = self.dr_deploy_info.get("storage_metadata_fs")
            self.delete_replication()
            self.delete_filesystem(vstore_id="0", fs_name=rep_fs_name)
            if not mysql_metadata_in_cantian:
                self.delete_filesystem(vstore_id="0", fs_name=metadata_fs)
            fs_name = self.dr_deploy_info.get("storage_dbstore_fs")
            dbstor_fs_vstore_id = self.dr_deploy_info.get("dbstore_fs_vstore_id")
            self.delete_hyper()
            try:
                self.delete_filesystem(dbstor_fs_vstore_id, fs_name)
            except Exception as err:
                LOG.info("Standby site delete hyper system failed: %s", str(err))
        if self.site == "standby" and os.path.exists(CANTIAN_DEPLOY_CONFIG) and uninstall_cantian_flag:
            self.site_uninstall()
            # stop cantian, uninstall cantian 备集群需要卸载cantian， 主集群不需要卸载，不需要停
            LOG.info("Uninstall Cantian engine success.")
        LOG.info("Successfully uninstalled!")

    def execute(self):
        if not os.path.exists(DR_DEPLOY_CONFIG):
            LOG.info("No dr deploy set up.")
            return
        if self.check_process():
            LOG.info("Deploy process exist.")
            return
        self.init_storage_opt()
        node_id = self.dr_deploy_info.get("node_id")
        action_parse = argparse.ArgumentParser()
        action_parse.add_argument("--site", dest="site", choices=["standby", "active"], required=True)
        args = action_parse.parse_args()
        self.site = args.site
        # 告警提示，是否确认卸载；是否卸载Cantian
        uninstall_cantian_flag = False
        confirmation = input()
        if self.site == "standby":
            cantian_confirmation = input()
            if cantian_confirmation == "yes":
                uninstall_cantian_flag = True
        if confirmation == "yes":
            try:
                self.standby_uninstall(node_id, uninstall_cantian_flag)
            finally:
                self.dr_deploy_opt.storage_opt.logout()
