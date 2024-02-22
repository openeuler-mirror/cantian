#!/usr/bin/python
# coding=utf-8
import copy
import os
import argparse
import re
import shutil

from pre_install import PreInstall
from logic.storage_operate import StorageInf
from storage_operate.dr_deploy_operate.dr_deploy_common import DRDeployCommon
from storage_operate.dr_deploy_operate.dr_deploy_common import RemoteStorageOPT
from utils.config.rest_constant import SUPPORT_VERSION, SystemRunningStatus, \
    HealthStatus, RemoteDeviceStatus, FilesystemRunningStatus, PoolStatus, PoolHealth, CANTIAN_DOMAIN_PREFIX
from om_log import LOGGER as LOG
from logic.common_func import exec_popen, read_json_config, write_json_config, get_status

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
DR_DEPLOY_PARAM_FILE = os.path.join(CURRENT_PATH, "../../../config/dr_deploy_param.json")
DR_PROCESS_RECORD_FILE = os.path.join(CURRENT_PATH, "../../../config/dr_process_record.json")
DEPLOY_PARAM_FILE = "/opt/cantian/config/deploy_param.json"
DOMAIN_LIMITS = 4


class DRDeployPreCheck(object):
    def __init__(self):
        self.deploy_operate = None
        self.storage_opt = None
        self.deploy_params = None
        self.remote_vstore_id = None
        self.conf = None
        self.local_conf_params = dict()
        self.remote_conf_params = dict()
        self.remote_device_id = None
        self.site = None
        self.dm_login_passwd = None
        self.remote_operate = None

    @staticmethod
    def check_master_cantian_status() -> list:
        """
        主端检查参天集群状态
        :return:
        """
        err_msg = []
        cmd = "su -s /bin/bash - cantian -c \"cms stat | " \
              "grep -v NODE_ID | awk '{print \$3,\$6,\$9}'\""
        return_code, output, stderr = exec_popen(cmd)
        if return_code == 1:
            err_msg = ["Execute command[cms stat] failed, details:%s" % stderr]
        else:
            cms_stat = [re.split(r"\s+", item.strip()) for item in output.strip().split("\n")]
            reformer_status = False
            for index, item in enumerate(cms_stat):
                if item[0].strip(" ") != "ONLINE":
                    err_msg.append("Node[%s] status is not ONLINE." % index)
                if item[1] != "1":
                    err_msg.append("Node[%s] status is not normal." % index)
                if item[2] == "REFORMER":
                    reformer_status = True
            if not reformer_status:
                err_msg.append("Current cluster reformer status is not normal.")
        return err_msg

    @staticmethod
    def clean_env():
        """
        部署前清理环境
        :return:
        """
        file_list = [DR_PROCESS_RECORD_FILE, DR_DEPLOY_PARAM_FILE]
        for file in file_list:
            if os.path.exists(file):
                os.remove(file)

    @staticmethod
    def check_dr_process():
        """
        检查当前环境是否在进行容灾搭建、全量同步、容灾拆除操作。存在报错退出
        :return:
        """
        deploy_proc_name = "/storage_operate/dr_operate_interface.py deploy"
        check_deploy_cmd = "ps -ef | grep -v grep | grep '%s'" % deploy_proc_name
        undeploy_proc_name = "/storage_operate/dr_operate_interface.py undeploy"
        check_undeploy_cmd = "ps -ef | grep -v grep | grep '%s'" % undeploy_proc_name
        sync_proc_name = "/storage_operate/dr_operate_interface.py full_sync"
        check_sync_cmd = "ps -ef | grep -v grep | grep '%s'" % sync_proc_name
        _, deploy_proc, _ = exec_popen(check_deploy_cmd)
        _, undeploy_proc, _ = exec_popen(check_undeploy_cmd)
        _, sync_proc, _ = exec_popen(check_sync_cmd)
        err_msg = ""
        if deploy_proc:
            err_msg += "Dr deploy is executing, please check, details:\n%s" % deploy_proc
        if undeploy_proc:
            err_msg += "Dr undeploy is executing, please check, details:\n%s" % undeploy_proc
        if sync_proc:
            err_msg += "Dr full sync is executing, please check, details:\n%s" % sync_proc
        if err_msg:
            raise Exception(err_msg)

    def check_storage_system_info(self) -> list:
        """
        检查存储系统状态:
        HEALTHSTATUS：系统健康状态。参数取值：1：正常；2：故障。
        RUNNINGSTATUS：系统运行状态。参数取值：1：正常；3：未运行；12：正在上电；47：正在下电；51：正在升级
        PRODUCTVERSION：产品版本。
        PRODUCTMODE：产品型号。
        pointRelease: 当前版本版本号
        productModeString: 产品型号字符串
        :return: bool
        """
        LOG.info("Check storage system info start.")
        err_msg = []
        system_info = self.deploy_operate.query_storage_system_info()
        health_status = system_info.get("HEALTHSTATUS")
        running_status = system_info.get("RUNNINGSTATUS")
        point_release = system_info.get("pointRelease")
        product_mode_string = system_info.get("productModeString")
        if self.remote_device_id:
            remote_opt = RemoteStorageOPT(self.storage_opt, self.remote_device_id)
            remote_system_info = remote_opt.query_remote_storage_system_info()
            remote_mode_string = remote_system_info.get("productModeString")
            if remote_mode_string != product_mode_string:
                err_msg.append("System mode is non-consistent, local mode[%s], remote mode[%s]" %
                               (product_mode_string, remote_mode_string))
        if health_status != HealthStatus.Normal:
            err_msg.append("System health status is not normal: health status[%s]." %
                           get_status(health_status, HealthStatus))
        if running_status != SystemRunningStatus.Normal:
            err_msg.append("System running status is not normal: running status[%s]." %
                           get_status(running_status, SystemRunningStatus))
        if point_release not in SUPPORT_VERSION:
            err_msg.append("System product release version not supported: current version[%s], support version%s"
                           % (point_release, SUPPORT_VERSION))
        LOG.info("Check storage system info success.")
        return err_msg

    def check_remote_device_info(self) -> list:
        """
        检查远端设备状态：
        HEALTHSTATUS: 健康状态。参数取值：1：正常；2：故障；14 ：失效。
        RUNNINGSTATUS: 运行状态。参数取值：10：已连接；11：未连接；31：已禁用；101：正在连接。
        DEVICEMODEL：远端设备型号。
        :return: bool
        """
        LOG.info("Check remote device info start.")
        err_msg = []
        remote_esn = self.remote_conf_params.get("esn")
        remote_device_infos = self.deploy_operate.query_remote_device_info()
        remote_device_info = dict()
        for item in remote_device_infos:
            if item.get("SN") == remote_esn:
                remote_device_info = item
        if not remote_device_info:
            err_msg.append("Remote device esn[%s] is not correct, please check" % remote_esn)
            return err_msg
        self.remote_device_id = remote_device_info.get("ID")
        health_status = remote_device_info.get("HEALTHSTATUS")
        running_status = remote_device_info.get("RUNNINGSTATUS")
        if health_status != HealthStatus.Normal:
            err_msg.append("Remote device health status is not normal: health status[%s]." %
                           get_status(health_status, HealthStatus))
        if running_status != RemoteDeviceStatus.LinkUp:
            err_msg.append("Remote device running status is not normal: running status[%s]." %
                           get_status(running_status, RemoteDeviceStatus))
        LOG.info("Check remote device info success.")
        return err_msg

    def check_file_system_status(self, fs_name: str, vstore_id: str) -> list:
        """
        检查主端文件系统健康状态，当前如果是备端直接返回
        HEALTHSTATUS：健康状态。参数取值：1： 正常
        RUNNINGSTATUS：运行状态。参数取值：27：在线；28：不在线；35：失效；53：初始化中
        :return: bool
        """
        LOG.info("Check master filesystem[%s] status start.", fs_name)
        file_system_info = self.storage_opt.query_filesystem_info(fs_name, vstore_id)
        err_msg = []
        if not file_system_info:
            err_msg.append("Failed to query filesystem[%s] info." % fs_name)
            return err_msg
        health_status = file_system_info.get("HEALTHSTATUS")
        running_status = file_system_info.get("RUNNINGSTATUS")
        if health_status != HealthStatus.Normal:
            err_msg.append("Filesystem[%s] health is not normal, status[%s]." %
                           (fs_name, get_status(health_status, HealthStatus)))
        if running_status != FilesystemRunningStatus.Online:
            err_msg.append("Filesystem[%s] running status is not normal, status[%s]." %
                           (fs_name, get_status(running_status, FilesystemRunningStatus)))

        LOG.info("Check master filesystem[%s] status success.", fs_name)
        return err_msg

    def check_standby_pool_info(self):
        """
        检查远端存储池信息
        :return:
        """
        err_msg = []
        if self.site == "standby":
            return err_msg
        remote_pool_info = {}
        remote_pool_id = self.local_conf_params.get("remote_pool_id")
        try:
            remote_pool_info = self.remote_operate.query_remote_storage_pool_info(pool_id=remote_pool_id)
        except Exception as _err:
            if str(_err).find("1077949965") != -1:
                err_msg.append("Standby pool[%s] is not exist." % remote_pool_id)
            else:
                err_msg.append("Failed to query remote pool[%s] info, details:%s" % (remote_pool_id, _err))
        if remote_pool_info:
            running_status = remote_pool_info.get("RUNNINGSTATUS")
            health_status = remote_pool_info.get("HEALTHSTATUS")
            if running_status != PoolStatus.Online:
                err_msg.append("Pool running status is not online, current status:[%s]" %
                               get_status(running_status, PoolStatus))
            if health_status != PoolHealth.Normal:
                err_msg.append("Pool health status is not normal, current status:[%s]" %
                               get_status(health_status, PoolHealth))
        return err_msg

    def check_standby_filesystem(self) -> list:
        """
        检查备端ulog文件系统所在租户下文件系统个数，要求为空。当前如果是主端直接返回
        检查备站点dbstore page文件系统是否存在
        元数据非归一场景检查元数据文件系统是否存在
        :return:
        """
        err_msg = []
        if self.site == "standby":
            return err_msg
        remote_vstore_id = self.local_conf_params.get("remote_dbstore_fs_vstore_id")
        LOG.info("Check standby filesystem nums start.")
        metadata_fs_name = self.remote_conf_params.get("storage_metadata_fs") if self.site == "active" else \
            self.local_conf_params.get("storage_metadata_fs")
        dbstore_page_fs = self.remote_conf_params.get("storage_dbstore_page_fs") if self.site == "active" else \
            self.local_conf_params.get("storage_dbstore_page_fs")

        metadata_in_cantian = self.local_conf_params.get("mysql_metadata_in_cantian")
        self.remote_operate = RemoteStorageOPT(self.storage_opt, self.remote_device_id)
        file_system_count = self.remote_operate.query_remote_storage_vstore_filesystem_num(remote_vstore_id)
        remote_metadata_fs_info = self.remote_operate.\
            query_remote_filesystem_info(fs_name=metadata_fs_name, vstore_id="0")
        remote_dbstore_page_fs_info = self.remote_operate.\
            query_remote_filesystem_info(fs_name=dbstore_page_fs, vstore_id="0")
        if file_system_count and file_system_count.get("COUNT") != "0":
            err_msg.append("Standby vstore[%s] exist filesystems, count[%s]"
                           % (remote_vstore_id, file_system_count.get("COUNT")))
        if remote_dbstore_page_fs_info:
            err_msg.append("Standby dbstore page filesystem[%s] exist, filesystem id[%s]." %
                           (dbstore_page_fs, remote_dbstore_page_fs_info.get("ID")))
        if remote_metadata_fs_info and not metadata_in_cantian:
            err_msg.append("Standby metadata filesystem[%s] exist, filesystem id[%s]." %
                           (metadata_fs_name, remote_metadata_fs_info.get("ID")))
        LOG.info("Check standby filesystem nums success.")
        return err_msg

    def check_license_effectivity(self) -> list:
        """
        检查license有效性：远程复制（HyperReplication）和NAS基础特性（NAS Foundation）有效
        data 返回jsonarray 特性的license状态信息。参数取值：各个json对象由特性名称、特性状态键值对组成。
        License的状态枚举：1：有效；2：过期；3：无效。备注：license过期后，有60天试用期。
        :return: bool
        """
        LOG.info("Check license effectivity start.")
        license_info = self.deploy_operate.query_license_info()
        nas_foundation = False
        hyper_replication = False
        for info in license_info:
            if info.get("HyperReplication") and info.get("HyperReplication") != "3":
                hyper_replication = True
            if info.get("NAS Foundation") and info.get("NAS Foundation") != "3":
                nas_foundation = True
        err_msg = []
        if not nas_foundation:
            err_msg.append("NAS Foundation license is not Found or expired, license status: %s" % license_info)
        if not hyper_replication:
            err_msg.append("HyperReplication license is not Found or expired, license status: %s" % license_info)
        LOG.info("Check license effectivity success.")
        return err_msg

    def check_disaster_exist(self) -> list:
        """
        检查当前文件系统，租户。双活域是否存在，存在就报错
        :return: bool
        """
        err_msg = []
        if self.site == "standby":
            return err_msg
        LOG.info("Check license effectivity start.")
        dbstore_fs = self.local_conf_params.get("storage_dbstore_fs")
        dbstore_fs_vstore_id = self.local_conf_params.get("dbstore_fs_vstore_id")
        remote_dbstore_fs_vstore_id = self.local_conf_params.get("remote_dbstore_fs_vstore_id")
        dbstore_page_fs = self.local_conf_params.get("storage_dbstore_page_fs")
        metadata_fs = self.local_conf_params.get("storage_metadata_fs")
        metadata_in_cantian = self.local_conf_params.get("mysql_metadata_in_cantian")
        cluster_id = self.local_conf_params.get("cluster_id")
        dbstore_fs_info = self.storage_opt.query_filesystem_info(dbstore_fs, dbstore_fs_vstore_id)
        dbstore_fs_id = dbstore_fs_info.get("ID")
        dbstore_fs_info = self.storage_opt.query_filesystem_info(dbstore_page_fs)
        page_fs_id = dbstore_fs_info.get("ID")
        dbstore_fs_info = self.storage_opt.query_filesystem_info(metadata_fs)
        metadata_fs_id = dbstore_fs_info.get("ID")
        # 检查双活域是否已经存在
        random_seed = self.deploy_params.get("random_seed", 1)
        domain_infos = self.deploy_operate.query_hyper_metro_domain_info()
        domain_name = CANTIAN_DOMAIN_PREFIX % (cluster_id, random_seed)
        for domain_info in domain_infos:
            if domain_info.get("NAME") == domain_name:
                err_msg.append("Domain name[%s] is exist." % domain_name)
                break
        if len(domain_infos) >= DOMAIN_LIMITS:
            err_msg.append("The number of HyperMetro domains has reached the upper limit %s." % DOMAIN_LIMITS)
        page_pair_info = self.deploy_operate.query_remote_replication_pair_info(page_fs_id)
        if page_pair_info:
            err_msg.append("Filesystem[%s] replication pair is exist." % dbstore_page_fs)
        vstore_pair_infos = self.deploy_operate.query_hyper_metro_vstore_pair_info()
        for vstore_pair_info in vstore_pair_infos:
            exist_remote_vstoreid = vstore_pair_info.get("REMOTEVSTOREID")
            exist_local_vstoreid = vstore_pair_info.get("LOCALVSTOREID")
            if exist_local_vstoreid == dbstore_fs_vstore_id and remote_dbstore_fs_vstore_id == exist_remote_vstoreid:
                err_msg.append("Vstore[%s] metro pair is exist." % dbstore_fs_vstore_id)
                break
        ulog_pair_info = self.deploy_operate.query_hyper_metro_filesystem_pair_info(dbstore_fs_id)
        if ulog_pair_info:
            err_msg.append("Filesystem[%s] metro pair is exist." % dbstore_fs)
        if metadata_in_cantian:
            meta_pair_info = self.deploy_operate.query_remote_replication_pair_info(metadata_fs_id)
            if meta_pair_info:
                err_msg.append("Filesystem[%s] replication pair is exist." % metadata_fs)

        LOG.info("Check license effectivity success.")
        return err_msg

    def check_active_exist_params(self):
        """
        主端检查配置文件与安装部署文件信息是否一致
        :return:
        """
        err_msg = []
        check_list = [
            "cluster_id",
            "cluster_name",
            "storage_dbstore_fs",
            "storage_dbstore_page_fs",
            "storage_metadata_fs",
            "mysql_metadata_in_cantian",
            "dbstore_fs_vstore_id"
        ]
        if not os.path.exists(DEPLOY_PARAM_FILE):
            _err_msg = "Deploy param file[%s] is not exists, " \
                      "please check cantian is deployed." % DEPLOY_PARAM_FILE
            LOG.error(_err_msg)
            raise Exception(_err_msg)
        self.deploy_params = read_json_config(DEPLOY_PARAM_FILE)
        diff_list = []
        for check_item in check_list:
            if self.deploy_params.get(check_item) != self.local_conf_params.get(check_item):
                diff_list.append(check_item)
        if diff_list:
            err_msg.append("Param check failed, different items[%s]" % diff_list)
        return err_msg

    def params_parse(self):
        """
        检查参数：
           1、检查本端阵列登录ip、用户、阵列是否正确
           2、检查配置文件中cluster name是否一致
        :return:
        """
        LOG.info("Parse config params start.")
        if not os.path.isfile(self.conf):
            err_msg = "Config file[%s] is not exist." % self.conf
            LOG.error(err_msg)
            raise Exception(err_msg)
        conf_params = read_json_config(self.conf)
        local_site = self.site
        remote_site = ({"standby", "active"} - {self.site}).pop()
        local_dr_deploy_param = conf_params.get("dr_deploy").get(local_site)
        remote_dr_deploy_param = conf_params.get("dr_deploy").get(remote_site)
        remote_pool_id = conf_params.get("dr_deploy").get("standby").get("pool_id")
        remote_dbstore_fs_vstore_id = conf_params.get("dr_deploy").get("standby").get("dbstore_fs_vstore_id")
        del conf_params["dr_deploy"]
        self.local_conf_params = copy.deepcopy(conf_params)
        self.local_conf_params.update(local_dr_deploy_param)
        if self.site == "active":
            self.local_conf_params.update({
                "remote_pool_id": remote_pool_id,
                "remote_dbstore_fs_vstore_id": remote_dbstore_fs_vstore_id
            })
        self.remote_conf_params = copy.deepcopy(conf_params)
        self.remote_conf_params.update(remote_dr_deploy_param)
        LOG.info("Parse config params end.")

    def record_config(self):
        """
        记录配置信息到配置文件
        :return:
        """
        dr_params = {
            "dm_ip": self.local_conf_params.get("dm_ip"),
            "dm_user": self.local_conf_params.get("dm_user"),
            "remote_pool_id": self.local_conf_params.get("remote_pool_id"),
            "remote_cluster_name": self.local_conf_params.get("remote_cluster_name"),
            "remote_device_id": self.remote_device_id,
            "remote_dbstore_fs_vstore_id": self.local_conf_params.get("remote_dbstore_fs_vstore_id")
        }
        self.local_conf_params.update(dr_params)
        write_json_config(DR_DEPLOY_PARAM_FILE, self.local_conf_params)

    def init_opt(self):
        local_login_ip = self.local_conf_params.get("dm_ip")
        local_login_user = self.local_conf_params.get("dm_user")
        storage_operate = StorageInf((local_login_ip, local_login_user, self.dm_login_passwd))
        storage_operate.login()
        self.storage_opt = storage_operate
        self.deploy_operate = DRDeployCommon(storage_operate)

    def parse_input_params(self):
        parse_params = argparse.ArgumentParser()
        parse_params.add_argument("-s", "--site", dest="site", choices=['active', "standby"], required=True)
        parse_params.add_argument("-l", "--conf", dest="conf", required=True)
        args = parse_params.parse_args()
        self.site = args.site
        self.conf = args.conf
        self.dm_login_passwd = input()

    def check_active_params(self):
        check_result = []
        if self.site == "standby":
            return check_result
        if not os.path.exists(os.path.join(CURRENT_PATH, "../../../config/deploy_param.json")):
            shutil.copy("/opt/cantian/config/deploy_param.json", os.path.join(CURRENT_PATH, "../../../config"))
            return check_result
        check_result.extend(self.check_master_cantian_status())
        check_result.extend(self.check_file_system_status(
            fs_name=self.local_conf_params.get("storage_dbstore_page_fs"),
            vstore_id="0"))
        check_result.extend(self.check_file_system_status(
            fs_name=self.local_conf_params.get("storage_dbstore_fs"),
            vstore_id=self.local_conf_params.get("dbstore_fs_vstore_id")))
        check_result.extend(self.check_active_exist_params())
        if not self.local_conf_params.get("mysql_metadata_in_cantian"):
            check_result.extend(self.check_file_system_status(
                fs_name=self.local_conf_params.get("storage_metadata_fs"), vstore_id="0"))
        return check_result

    def check_nfs_lif_info(self):
        """检查share、archive、meta文件系统是否存在，逻辑端口是否存在, 检查nfs协议是否开启"""
        check_result = []
        share_vstore_id = None
        err_msg = "Param [%s: %s] is incorrect."
        db_type = self.local_conf_params.get("db_type")
        storage_share_fs = self.local_conf_params.get("storage_share_fs")
        storage_archive_fs = self.local_conf_params.get("storage_archive_fs")
        storage_metadata_fs = self.local_conf_params.get("storage_metadata_fs")
        share_logic_ip = self.local_conf_params.get("share_logic_ip")
        archive_logic_ip = self.local_conf_params.get("archive_logic_ip")
        metadata_logic_ip = self.local_conf_params.get("metadata_logic_ip")
        mysql_metadata_in_cantian = self.local_conf_params.get("mysql_metadata_in_cantian")
        share_lif_info = self.storage_opt.query_logical_port_info(share_logic_ip)
        if not share_lif_info:
            check_result.append(err_msg % ("share_logic_ip", share_logic_ip))
        else:
            share_vstore_id = share_lif_info[0].get("vstoreId")
            share_fs_info = self.storage_opt.query_filesystem_info(storage_share_fs, vstore_id=share_vstore_id)
            if not share_fs_info:
                check_result.append(err_msg % ("storage_share_fs", storage_share_fs) +
                                    "Please confirm share_logic_ip and storage_share_fs is in the same vstore")
        meta_lif_info = self.storage_opt.query_logical_port_info(metadata_logic_ip, vstore_id="0")
        if not meta_lif_info:
            check_result.append(err_msg % ("metadata_logic_ip", metadata_logic_ip))
        meta_fs_info = self.storage_opt.query_filesystem_info(storage_metadata_fs, vstore_id="0")
        if mysql_metadata_in_cantian and not meta_fs_info:
            check_result.append(err_msg % ("storage_metadata_fs", storage_metadata_fs))
        if db_type == "1":
            archive_lif_info = self.storage_opt.query_logical_port_info(archive_logic_ip, vstore_id="0")
            if not archive_lif_info:
                check_result.append(err_msg % ("archive_logic_ip", archive_logic_ip))
            archive_fs_info = self.storage_opt.query_filesystem_info(storage_archive_fs, vstore_id="0")
            if not archive_fs_info:
                check_result.append(err_msg % ("storage_archive_fs", storage_archive_fs))
        if share_vstore_id:
            share_vstore_nfs_service = self.storage_opt.query_nfs_service(vstore_id=share_vstore_id)
            support_v4 = share_vstore_nfs_service.get("SUPPORTV4")
            if support_v4 == "false":
                check_result.append("Share vstore[%s] nfs service[v4.0] is not support." % share_vstore_id)
        system_nfs_service = self.storage_opt.query_nfs_service(vstore_id="0")
        support_v41 = system_nfs_service.get("SUPPORTV41")
        if support_v41 == "false":
            check_result.append("System vstore nfs service[v4.1] is not support.")
        return check_result

    def check_standby_params(self):
        """
        备端搭建前检查参数：
            1、检查dbstor ulog文件系统所在租户id是否一致。租户是否存在
            2、检查share、archive、meta文件系统是否存在
            3、检查逻辑端口是否存在
            4、检查文件系统与逻辑端口是否在同一租户
            5、检查share租户是否开启nfs服务
            6、storage_vlan_ip连通性检查
        :return:
        """
        check_result = []
        if self.site == "active":
            return check_result
        pre_install = PreInstall(install_model="override", config_path=self.conf)
        if pre_install.check_main() == 1:
            check_result.append("Params check failed")
        conf_params = read_json_config(self.conf)
        dbstore_fs_vstore_id = conf_params.get("dbstore_fs_vstore_id")
        remote_dbstore_fs_vstore_id = conf_params.get("dr_deploy").get("standby").get("dbstore_fs_vstore_id")
        if dbstore_fs_vstore_id != remote_dbstore_fs_vstore_id:
            check_result.append("Inconsistent dbstor fs vstore id, %s and %s" % (dbstore_fs_vstore_id,
                                                                                 remote_dbstore_fs_vstore_id))
            return check_result
        try:
            self.deploy_operate.storage_opt.query_vstore_info(dbstore_fs_vstore_id)
        except Exception as err:
            check_result.append("Vstore[%s] is not exist, details: %s" % (dbstore_fs_vstore_id, str(err)))
            return check_result
        check_result.extend(self.check_nfs_lif_info())
        LOG.info("Param check success")
        return check_result

    def check_common_params(self):
        check_result = []
        remote_cluster_name = self.local_conf_params.get("remote_cluster_name")
        cluster_name = self.local_conf_params.get("cluster_name")
        if cluster_name != remote_cluster_name:
            check_result.append("Inconsistent cluster names, remote[%s], local[%s]."
                                % (remote_cluster_name, cluster_name))
        return check_result

    def execute(self):
        LOG.info("Start to dr pre check.")
        self.check_dr_process()
        self.parse_input_params()
        check_result = []
        self.params_parse()
        self.init_opt()
        try:
            check_result.extend(self.check_common_params())
            check_result.extend(self.check_active_params())
            check_result.extend(self.check_standby_params())
            check_result.extend(self.check_storage_system_info())
            check_result.extend(self.check_remote_device_info())
            check_result.extend(self.check_license_effectivity())
            check_result.extend(self.check_standby_filesystem())
            check_result.extend(self.check_standby_pool_info())
            check_result.extend(self.check_disaster_exist())
            if check_result:
                _err = "\n".join([" " * 8 + str(index + 1) + "." + err for index, err in enumerate(check_result)])
                _err = "DR deploy pre_check failed, details:\n" + _err
                raise Exception(str(_err))
        finally:
            self.storage_opt.logout()
        self.clean_env()
        self.record_config()
        LOG.info("DR deploy pre check success.")


class ParamCheck(object):
    def __init__(self):
        self.mysql_user = None
        self.mysql_cmd = None
        self.action = None
        self.site = None
        self.dr_deploy_params = read_json_config(DR_DEPLOY_PARAM_FILE)

    def check_dm_pwd(self, dm_pwd: str) -> None:
        """
        检查DM密码是否正确，登录成功后退出
        """
        local_login_ip = self.dr_deploy_params.get("dm_ip")
        local_login_user = self.dr_deploy_params.get("dm_user")
        storage_operate = StorageInf((local_login_ip, local_login_user, dm_pwd))
        try:
            storage_operate.login()
        except Exception as _err:
            LOG.error("Log in device manager failed, details:%s", str(_err))
            raise _err
        storage_operate.logout()

    def check_mysql_pwd(self, mysql_pwd: str) -> None:
        """
        执行查询命令检查mysql密码是否正确
        """
        mysql_check_cmd = "%s -u'%s' -p'%s' -e \"show engines;\"" % (self.mysql_cmd, self.mysql_user, mysql_pwd)
        return_code, output, stderr = exec_popen(mysql_check_cmd)
        if return_code:
            stderr = str(stderr).replace(mysql_pwd, "***")
            err_msg = "Check mysql login failed, details:%s" % stderr
            LOG.error(err_msg)
            raise Exception(err_msg)

    def execute(self):
        parse_params = argparse.ArgumentParser()
        parse_params.add_argument("--action", dest="action", required=True)
        parse_params.add_argument("--site", dest="site", required=False, default="")
        parse_params.add_argument("--mysql_cmd", dest="mysql_cmd", required=False, default="")
        parse_params.add_argument("--mysql_user", dest="mysql_user", required=False, default="")
        parse_params.add_argument("--display", dest="display", required=False, default="")
        args = parse_params.parse_args()
        self.action = args.action
        self.site = args.site
        self.mysql_cmd = args.mysql_cmd
        self.mysql_user = args.mysql_user
        dm_pwd = input()
        self.check_dm_pwd(dm_pwd)
        if self.site == "active" and (self.action == "deploy" or self.action == "full_sync"):
            my_pwd = input()
            self.check_mysql_pwd(my_pwd)
