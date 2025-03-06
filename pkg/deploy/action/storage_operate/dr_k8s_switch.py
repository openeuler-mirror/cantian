import copy
import getpass
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import logging
import traceback
import collections
from datetime import datetime

import yaml


CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(CURRENT_PATH, ".."))
from utils.client.ssh_client import SshClient
from logic.common_func import get_status
from logic.storage_operate import StorageInf
from dr_deploy_operate.dr_deploy_common import DRDeployCommon
from utils.config.rest_constant import (DataIntegrityStatus, MetroDomainRunningStatus, ConfigRole, HealthStatus,
                                        DomainAccess, ReplicationRunningStatus, VstorePairRunningStatus,
                                        FilesystemPairRunningStatus)


EXEC_SQL = "/ctdb/cantian_install/cantian_connector/action/cantian_common/exec_sql.py"
CANTIAN_DATABASE_ROLE_CHECK = ("echo -e 'select DATABASE_ROLE from DV_LRPL_DETAIL;' | "
                               "su -s /bin/bash - %s -c 'source ~/.bashrc && "
                               "export LD_LIBRARY_PATH=/opt/cantian/dbstor/lib:${LD_LIBRARY_PATH} && "
                               "python3 -B %s'")

DBSTOR_CHECK_VERSION_FILE = "/opt/cantian/dbstor/tools/cs_baseline.sh"
DEPLOY_LOG_FILE = "/opt/cantian/log/deploy/deploy.log"

KUBECTL_TRY_COUNT = 5
CHECK_DEL_TRY_COUNT = 30


class LogGer:
    def __init__(self, name, file_name):
        self.name = name
        self.file_name = file_name

    def get_logger(self):
        ERROR_TO_FILE = 15
        logging.addLevelName(ERROR_TO_FILE, "ERR")

        logger = logging.getLogger(self.name)

        def error_to_file(logger, msg, *args, **kwargs):
            if logger.isEnabledFor(ERROR_TO_FILE):
                logger._log(ERROR_TO_FILE, msg, args, kwargs)

        logging.Logger.error_to_file = error_to_file

        logger.setLevel(logging.DEBUG)

        file_handler = logging.FileHandler(self.file_name)
        file_handler.setLevel(logging.DEBUG)

        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.INFO)

        formatter = logging.Formatter('[%(asctime)s] [%(name)s] [%(levelname)s]: %(message)s')

        file_handler.setFormatter(formatter)
        stream_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)

        return logger


LOG = LogGer("DR_SWITCH", "dr_k8s_switch.log").get_logger()


def close_child_process(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError as err:
        _ = err
        return 'success'
    except Exception as err:
        return str(err)

    return 'success'


def exec_popen(cmd, timeout=5):
    """
    subprocess.Popen in python3.
    param cmd: commands need to execute
    return: status code, standard output, error output
    """
    bash_cmd = ["bash"]
    pobj = subprocess.Popen(bash_cmd, shell=False, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
    pobj.stdin.write(cmd.encode())
    pobj.stdin.write(os.linesep.encode())
    try:
        stdout, stderr = pobj.communicate(timeout=timeout)
    except Exception as err:
        return pobj.returncode, "", str(err)
    finally:
        return_code = pobj.returncode
        close_child_process(pobj)

    stdout, stderr = stdout.decode(), stderr.decode()
    if stdout[-1:] == os.linesep:
        stdout = stdout[:-1]
    if stderr[-1:] == os.linesep:
        stderr = stderr[:-1]

    return return_code, stdout, stderr


def get_now_timestamp():
    now = datetime.now()
    timestamp = now.timestamp()
    return int(timestamp)


def get_json_config(file_path):
    with open(file_path, 'r') as f:
        configs = json.load(f)
    return configs


def copy_file(source, dest):
    if os.path.exists(dest):
        os.remove(dest)
    shutil.copy(source, dest)


def remove_dir(path):
    if not os.path.isdir(path):
        return False
    for filename in os.listdir(path):
        file_path = os.path.join(path, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
            return True
        except Exception as e:
            print(f'delete {file_path} err: {e}')
            return False
    return True


def split_pod_name(pod_name):
    parts = pod_name.split('-')
    if len(parts) > 3:
        first_part = '-'.join(parts[:len(parts) - 2])
        return first_part
    else:
        return pod_name


def warning(warn_msg):
    print(f"\033[91m{warn_msg}\033[0m")


def confirm():
    warning_confirm = input("Do you want to continue? (yes/no): ").strip()
    if warning_confirm != "yes" and warning_confirm != "no":
        warning_confirm = input("Invalid input. Please enter 'yes' or 'no': ").strip()
    if warning_confirm == "no":
        LOG.info("Operation cancelled.")
        return False
    second_warning_confirm = input("To confirm operation, enter yes. Otherwise, exit: ").strip()
    if second_warning_confirm != "yes":
        LOG.info("Operation cancelled.")
        return False
    return True


def get_node_id(config_map, pod_name):
    for config in config_map:
        if config.get("pod_name") == split_pod_name(pod_name):
            return config.get("node_id")
    return ""


def check_cantian_yaml_config(value, cantian_path):
    cantian_flag = False
    with open(cantian_path, 'r') as f:
        configs = yaml.safe_load_all(f)
        for config in configs:
            if config.get("kind") != "Deployment":
                continue
            cantian_flag = True
            if "namespace" not in value:
                value["namespace"] = config.get("metadata").get("namespace")
            value["pod_name"].append(config.get("metadata").get("name").strip())
            volumes = config.get("spec").get("template").get("spec").get("volumes")
            for volume in volumes:
                if volume.get("name") == "config-volume":
                    data = {
                        "name": volume.get("configMap").get("name").strip(),
                        "pod_name": config.get("metadata").get("name").strip()
                    }
                    value["config_map"].append(data)
                    break
    return cantian_flag


class K8sDRContainer:
    def __init__(self):
        self.k8s_config_path = os.path.join(CURRENT_PATH, "k8s_dr_config.json")
        self.single_file_path = os.path.join(CURRENT_PATH, "single_file.json")
        self.action = ""
        self.domain_name = ""
        self.domain_id = ""
        self.dm_ip = ""
        self.dm_user = ""
        self.server_info = {}
        self.server_user = "root"
        self.server_key_file = "/root/.ssh/id_rsa"
        self.dr_option = None
        self.storage_opt = None
        self.ulog_pair_list = []
        self.ssh_cmd_end = " ; echo last_cmd=$?"
        self.vstore_pair_list = []
        self.single_pod = collections.defaultdict(list)
        self.abnormal_pod = {}
        self.check_flag = True
        self.action_list = ["delete", "switch_over", "fail_over", "recover", "unconnected_switch_delete",
                            "unconnected_fail_over", "unconnected_switch", "unconnected_recover",
                            "unconnected_check","unconnected_delete"]
        self.ip_info = ""
        self.config_count = 0
        self.ssh_expect = "]# "
        self.change_apply = False
        self.dm_logic_ip = []
        self.skip_login = False
        self.unconnected_ip = []
        self.is_unconnected_flag = False

    def warning_tip(self):
        warning_msgs = {
            "switch_over": "\tSwitchover operation will be performed.\n"
                           "\tThe current operation will cause the active-standby switch,\n"
                           "\tplease make sure the standby data is consistent with the main data,\n"
                           "\tif the data is not consistent, "
                           "the execution of the switch operation may cause data loss,\n"
                           "\tplease make sure the standby and DeviceManager are in good condition, "
                           "if not, the new active will hang after switch over.\n"
                           "\tAfter the command is executed, check the replay status on the standby "
                           "side to determine if the active-standby switch was successful.\n",
            "recover": "\tRecover operation will downgrade current station to standby,\n"
                       "\tsynchronize data from remote to local, and cover local data.\n"
                       "\tEnsure remote data consistency to avoid data loss.\n",
            "fail_over": "\tFailover operation will start the standby cluster.\n"
                         "\tPlease ensure that the main end executes command[python3 dr_k8s_switch.py delete] "
                           "to stop the active Cantian cluster\n"
                         "\tPlease confirm that the active device or cantian has failed,\n"
                         "\tPlease ensure that all primary sites have been stopped.\n"
                         "\tAfter this operation,\n"
                         "\tplease ensure that the original active cluster is not accessed for write operations,\n"
                         "\totherwise it will cause data inconsistency.\n",
            "delete": "\tDeletion operation will delete the all Cantian nodes under hyper metro domain.\n",
            "unconnected_switch_delete": "\tDeletion operation will delete the all Cantian nodes under hyper "
                                         "metro domain.\n",
            "unconnected_delete": "\tDeletion operation will delete the all Cantian nodes under hyper metro domain.\n",
            "unconnected_switch": "\tSwitchover operation will be performed.\n"
                                  "\tThe current operation will cause the active-standby switch,\n"
                                  "\tplease make sure the standby data is consistent with the main data,\n"
                                  "\tif the data is not consistent, "
                                  "the execution of the switch operation may cause data loss,\n"
                                  "\tplease make sure the standby and DeviceManager are in good condition, "
                                  "if not, the new active will hang after switch over.\n"
                                  "\tAfter the command is executed, check the replay status on the standby "
                                  "side to determine if the active-standby switch was successful.\n",
            "unconnected_recover": "\tRecover operation will downgrade current station to standby,\n"
                                   "\tsynchronize data from remote to local, and cover local data.\n"
                                   "\tEnsure remote data consistency to avoid data loss.\n",
            "unconnected_check": "\tThis operation will check query single_even write tags.\n",
            "unconnected_fail_over": "\tThis operation will check pods' stat\n"
        }
        if self.action in warning_msgs:
            warning("Warning:")
            warning(warning_msgs[self.action])
            return confirm()
        return True

    def init_k8s_config(self):
        """
        Initialize the switching configuration file and provide error prompts for empty field data
        """
        if not os.path.exists(self.k8s_config_path):
            err_msg = f"k8s_config_path does not exist, path: {self.k8s_config_path}"
            LOG.error(err_msg)
            self.check_flag = False
            return
        try:
            config = get_json_config(self.k8s_config_path)
        except Exception as e:
            LOG.error("Failed to load k8s config file, please check the k8s config file")
            raise e
        self.domain_name = config.get("domain_name").strip()
        if not self.domain_name:
            err_msg = f"Domain name is empty, config path: {self.k8s_config_path}"
            LOG.error(err_msg)
            self.check_flag = False
        self.dm_ip = config.get("dm_ip").strip()
        if not self.dm_ip:
            err_msg = f"Domain ip is empty, config path: {self.k8s_config_path}"
            LOG.error(err_msg)
            self.check_flag = False
        self.dm_user = config.get("dm_user").strip()
        if not self.dm_user:
            err_msg = f"Domain user is empty, config path: {self.k8s_config_path}"
            LOG.error(err_msg)
            self.check_flag = False
        self.server_info = config.get("server")
        if not self.server_info:
            err_msg = f"Server info is empty, config path: {self.k8s_config_path}"
            LOG.error(err_msg)
            self.check_flag = False
        LOG.info("init k8s config finish")

    def get_self_ip_info(self):
        cmd = "hostname -I"
        ret_code, ret, _ = exec_popen(cmd, 20)
        if ret_code:
            err_msg = f"Failed to get ip info for {cmd}"
            LOG.error(err_msg)
            self.check_flag = False
            return
        self.ip_info = ret.strip()
        LOG.info("get self ip info finish")

    def check_configmap_yaml_config(self, ip, value, config_path):
        config_flag = False
        config_yaml = value.get("config_yaml")
        with open(config_path, 'r') as f:
            configs = yaml.safe_load_all(f)
            for config in configs:
                if config.get("kind") != "ConfigMap":
                    continue
                config_flag = True
                deploy_param = json.loads(config.get("data").get("deploy_param.json"))
                domain_name = deploy_param.get("dr_deploy").get("domain_name")
                if domain_name != self.domain_name:
                    LOG.error(f"Domain name is not match, server ip[{ip}], config path[{config_yaml}]")
                    return False
                if not self.check_info_contain_logic_ip(deploy_param.get("storage_vlan_ip")):
                    LOG.error(f"This configuration file[{config_yaml}] "
                              f"does not belong to the current DM IP address")
                    return False
                configMaps = value.get("config_map", [])
                for configMap in configMaps:
                    if configMap.get("name") == config.get("metadata").get("name").strip():
                        configMap["node_id"] = deploy_param.get("node_id")
                        break
                if "run_user" in value:
                    continue
                value["storage_dbstor_fs"] = deploy_param.get("storage_dbstor_fs")
                value["run_user"] = deploy_param.get("deploy_user").strip().split(":")[0]
                value["cluster_name"] = deploy_param.get("cluster_name").strip()
                value["storage_dbstor_page_fs"] = deploy_param.get("storage_dbstor_page_fs")
                value["dbstor_fs_vstore_id"] = deploy_param.get("dbstor_fs_vstore_id")
                value["storage_metadata_fs"] = deploy_param.get("storage_metadata_fs", "")
                value["cluster_id"] = deploy_param.get("cluster_id")
        return config_flag

    def check_k8s_config(self, ip, index, dir_path):
        value = self.server_info[ip][index]
        config_yaml = value.get("config_yaml")
        cantian_yaml = value.get("cantian_yaml")
        cantian_path = os.path.join(dir_path, "cantian.yaml")
        config_path = os.path.join(dir_path, "configMap.yaml")
        if (not os.path.exists(cantian_path) or
                not os.path.exists(config_path)):
            self.check_flag = False
            return False
        value["server_path"] = dir_path
        value["pod_name"] = []
        value["config_map"] = []
        cantian_flag = check_cantian_yaml_config(value, cantian_path)
        config_flag = self.check_configmap_yaml_config(ip, value, config_path)

        if not cantian_flag or not config_flag:
            LOG.error(f"check ip[{ip}] k8s config [cantian.yaml:{cantian_yaml} configMap.yaml:{config_yaml}] failed, "
                      f"maybe error in filling in configuration file information.")
            return False
        LOG.info(f"check ip[{ip}] k8s config [cantian.yaml:{cantian_yaml} configMap.yaml:{config_yaml}] finish")
        return True

    def change_config(self, dir_path):
        if self.action != "recover":
            return True
        try:
            config_yaml_path = os.path.join(dir_path, "configMap.yaml")
            config_list = []
            with open(config_yaml_path, 'r') as f:
                configs = yaml.safe_load_all(f)
                for config in configs:
                    if config.get("kind") == "ConfigMap":
                        deploy_param = json.loads(config.get("data").get("deploy_param.json"))
                        deploy_param["dr_action"] = self.action
                        new_deploy_param_str = json.dumps(deploy_param)
                        config.get("data")["deploy_param.json"] = new_deploy_param_str
                        config_list.append(config)
            with open(config_yaml_path, 'w') as file:
                file.truncate()
                yaml.safe_dump_all(config_list, file)
            LOG.info("change_config finish")
            return True
        except Exception as e:
            LOG.error(f"change_config failed, err[{e}]")
            LOG.error_to_file(f"traceback: {traceback.format_exc(limit=-1)}")
            return False

    def download_config_file(self, ssh_client, ip, index, dir_path):
        value = self.server_info[ip][index]
        cantian_yaml = value.get("cantian_yaml")
        config_yaml = value.get("config_yaml")
        try:
            if ip in self.ip_info:
                copy_file(cantian_yaml, f"{dir_path}/cantian.yaml")
                copy_file(config_yaml, f"{dir_path}/configMap.yaml")
            else:
                ssh_client.down_file(cantian_yaml, dir_path, "cantian.yaml")
                ssh_client.down_file(config_yaml, dir_path, "configMap.yaml")
        except Exception as e:
            LOG.error(f"Download config file failed, err[{e}]")
            LOG.error_to_file(f"traceback: {traceback.format_exc(limit=-1)}")
            return False
        return True

    def pre_check_dir(self):
        if not os.path.exists(self.server_key_file):
            err_msg = f"Server key file {self.server_key_file} does not exist"
            LOG.error(err_msg)
            self.check_flag = False
            return

        server_path = os.path.join(CURRENT_PATH, "server")
        if not os.path.exists(server_path):
            os.makedirs(server_path)        
        if not remove_dir(server_path):
            err_msg = f"Failed to remove {server_path}."
            LOG.error(err_msg)
            raise Exception(err_msg)
        
    def pre_check_link(self):
        config_index = 0
        server_path = os.path.join(CURRENT_PATH, "server")
        for ip in self.server_info:
            if ip in self.ip_info:
                ssh_client = None
                islocal = True
            else:
                ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)                
                islocal = False
                try:
                    ssh_client.create_client()
                except:
                    LOG.error(f"Failed to create ssh client for {ip}")
                    self.unconnected_ip.append(ip)
                    continue
            self.config_count += len(self.server_info[ip])
            for index, value in enumerate(self.server_info[ip]):
                dir_path = os.path.join(server_path, str(config_index))
                config_index += 1
                if not os.path.exists(dir_path):
                    os.makedirs(dir_path)
                cantian_yaml = value.get("cantian_yaml", "")
                config_yaml = value.get("config_yaml", "")
                if not cantian_yaml or not config_yaml:
                    LOG.error(f"IP[{ip}] Cantian or config yaml path is empty, please check.")
                    self.check_flag = False
                    continue
                cmd = f"ls {cantian_yaml}"
                res, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
                if not flag:
                    LOG.error(f"Failed to ls {cantian_yaml}, maybe not exist")
                    self.check_flag = False
                    continue
                cmd = f"ls {config_yaml}"
                res, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
                if not flag:
                    LOG.error(f"Failed to ls {config_yaml}, maybe not exist")
                    self.check_flag = False
                    continue
                LOG.info(f"Ip[{ip}] check path exist finish")
                if not self.download_config_file(ssh_client, ip, index, dir_path):
                    self.check_flag = False
                    LOG.error(f"Ip[{ip}] download_config_file config index[{index}] failed.")
                    continue
                LOG.info(f"Ip[{ip}] download_config_file config index[{index}] finish")
                if not self.check_k8s_config(ip, index, dir_path):
                    self.check_flag = False
                    LOG.error(f"Ip[{ip}] check_k8s_config config index[{index}] failed.")
                    continue
                LOG.info(f"Ip[{ip}] check_k8s_config config index[{index}] finish")
                if not self.change_config(dir_path):
                    LOG.error(f"Ip[{ip}] change_config[{dir_path}] index[{index}] failed.")
            if ssh_client is not None:
                ssh_client.close_client()
        LOG.info("pre_check_link finish")

    def user_confirm_twice(self, warning_info):
        if self.unconnected_ip:
            warning(f"Existing unconnected ip: {self.unconnected_ip}, are you sure continue manually?")
            if confirm():                    
                warning(f"Please upload the same package to the node {self.unconnected_ip} and decompress it.\n"
                        "Then modify the configuration file k8s_dr_config.json.\n"
                        "Input {warning_info}.")
                self.is_unconnected_flag = False
                if not confirm(): 
                    raise Exception("User abort the program.")
            else:
                raise Exception("User abort the program.")

    def pre_check_unconnected_confirm(self):
        if self.unconnected_ip:
            self.is_unconnected_flag = True
            for ip in self.unconnected_ip:
                del self.server_info[ip]
            if self.action in ["delete", "switch_over", "unconnected_switch_delete","unconnected_delete"
                               "fail_over", "unconnected_fail_over"]:
                warning(f"Existing unconnected ip: {self.unconnected_ip}, are you sure continue manually?")
                if confirm():
                    warning(f"Please upload the same package to the node {self.unconnected_ip} and decompress it.\n"
                            "Then modify the configuration file k8s_dr_config.json.\n")                   
                    if self.action in ["switch_over", "unconnected_switch_delete"]:
                        warning("Input 'python3 dr_k8s_switch.py unconnected_switch_delete'.")
                    if self.action in ["delete", "unconnected_delete"]:
                        warning("Input 'python3 dr_k8s_switch.py unconnected_delete'.")
                    if self.action in ["fail_over", "unconnected_fail_over"]:
                        warning("Input 'python3 dr_k8s_switch.py unconnected_fail_over'.")
                    if not confirm():
                        self.check_flag = False
                else:
                    self.check_flag = False

    def init_dr_option(self):
        ping_cmd = f"ping -c 1 -i 1 {self.dm_ip}"
        code, _, _ = exec_popen(ping_cmd, timeout=20)
        if code:
            err_msg = f"Fail to ping DM ip[{self.dm_ip}], maybe DM is fault."
            warning(err_msg)
            if self.action not in ["delete", "unconnected_delete"]:
                raise Exception(err_msg)
            if confirm():
                self.skip_login = True
                return
            raise Exception(f"DM ip[{self.dm_ip}] can't be login.")
        dm_passwd = getpass.getpass("Please input device manager login passwd: ")
        self.storage_opt = StorageInf((self.dm_ip, self.dm_user, dm_passwd))
        try:
            self.storage_opt.login()
        except Exception as e:
            if self.action not in ["delete", "unconnected_delete"]:
                raise e
            if "user name or password is incorrect" in str(e) or "verification code is not entered" in str(e):
                raise e
            if confirm():
                self.skip_login = True
                return

        self.dr_option = DRDeployCommon(self.storage_opt)

    def get_dm_logic_ip(self):
        if self.skip_login:
            return
        logic_infos = self.storage_opt.query_logical_port_info_by_vstore_id()
        for info in logic_infos:
            if info["SUPPORTPROTOCOL"] == "0" or info["SUPPORTPROTOCOL"] == "1":
                continue
            self.dm_logic_ip.append(info["IPV4ADDR"])

    def check_info_contain_logic_ip(self, info):
        if self.skip_login:
            return True
        for ip in self.dm_logic_ip:
            if ip in info:
                return True
        return False

    def check_hyper_metro_domain_role(self, role):
        primary_action = ["switch_over", "delete", "unconnected_delete", "unconnected_switch",
                          "unconnected_switch_delete"]
        if self.action in primary_action and role != ConfigRole.Primary:
            LOG.error(f"Current action[{self.action}] not supporting operations on the standby side")
            self.check_flag = False

    def get_ulog_pair_info_list(self):
        domain_infos = self.dr_option.query_hyper_metro_domain_info()
        self.vstore_pair_list = []
        for domain_info in domain_infos:
            if domain_info.get("NAME") == self.domain_name:
                self.domain_id = domain_info.get("ID")
                self.check_hyper_metro_domain_role(domain_info.get("CONFIGROLE"))
                LOG.info("Domain name[%s] is exist." % self.domain_name)
                break
        else:
            err_msg = f"No information was found for Domain name[{self.domain_name}]."
            LOG.error(err_msg)
            self.check_flag = False
            raise Exception("Program pre check failed")
        vstore_pair_list = self.dr_option.query_hyper_metro_vstore_pair_info()
        for vstore_pair_info in vstore_pair_list:
            if vstore_pair_info.get("DOMAINID") == self.domain_id:
                self.vstore_pair_list.append(vstore_pair_info)
                pair_list = self.dr_option.query_ulog_filesystem_info_list(
                    vstore_pair_info.get("LOCALVSTOREID"))
                for pair in pair_list:
                    if pair.get("DOMAINID") == self.domain_id:
                        self.ulog_pair_list.append(pair)
        LOG.info("get_ulog_pair_info_list finish")

    def match_config_and_pair_with_fs_name(self, value, ulog_pair_info):
        log_fs_name = ulog_pair_info.get("LOCALOBJNAME").strip()
        vstore_id = ulog_pair_info.get("vstoreId").strip()
        if value.get("storage_dbstor_fs") == log_fs_name and value.get("dbstor_fs_vstore_id") == vstore_id:
            value["log_fs_id"] = ulog_pair_info.get("LOCALOBJID")
            value["log_pair_id"] = ulog_pair_info.get("ID")
            return True
        return False

    def check_and_match_ulog_page_info(self):
        LOG.info("begin to check_and_match_ulog_page_info")
        filter_server_info = collections.defaultdict(list)
        ulog_pair_list = []
        for ulog_pair_info in self.ulog_pair_list:
            for ip in self.server_info:
                for index, value in enumerate(self.server_info[ip]):
                    if ip in filter_server_info and index in filter_server_info[ip]:
                        continue
                    if self.match_config_and_pair_with_fs_name(value, ulog_pair_info):
                        filter_server_info[ip].append(index)
                        ulog_pair_list.append(ulog_pair_info)
                        break
        if self.is_unconnected_flag == True:
            self.ulog_pair_list = ulog_pair_list
        LOG.info("check_and_match_ulog_page_info finish")

    def check_hyper_metro_stat(self):
        domain_info = self.dr_option.query_hyper_metro_domain_info(self.domain_id)
        running_status = domain_info.get("RUNNINGSTATUS")
        if running_status != MetroDomainRunningStatus.Normal and running_status != MetroDomainRunningStatus.Split:
            err_msg = "DR recover operation is not allowed in %s status." % \
                      get_status(running_status, MetroDomainRunningStatus)
            LOG.error(err_msg)
            self.check_flag = False
        self.check_hyper_metro_filesystem_pair_stat()
        self.check_replication_filesystem_pair_stat()

    def pre_check(self):
        self.get_self_ip_info()
        self.init_dr_option()
        self.get_dm_logic_ip()
        self.pre_check_dir()
        self.pre_check_link()
        self.pre_check_unconnected_confirm()
        self.check_flag_stat()
        if self.skip_login:
            return
        self.get_ulog_pair_info_list()
        self.check_and_match_ulog_page_info()
        if self.action == "switch_over":
            self.exe_func(self.check_pod_stat)
            self.check_hyper_metro_stat()
        if self.config_count != len(self.ulog_pair_list):
            LOG.error(f"config count[{self.config_count}] not match ulog pair list[{len(self.ulog_pair_list)}].")
            self.check_flag = False
        self.check_flag_stat()
        LOG.info("success to pre check.")

    def ssh_exec_cmd(self, ssh_client, cmd, timeout=10, islocal=False, err_log=True):
        try:
            cmd = f"{cmd}{self.ssh_cmd_end}"
            err_msg = ""
            if islocal:
                _, res, err_msg = exec_popen(cmd, timeout)
            else:
                res = ssh_client.execute_cmd(cmd, expect=self.ssh_expect, timeout=timeout)
            ret = res.strip().split("\n")
            if "last_cmd=0" not in res:
                if not err_log:
                    return ret[:-1], False
                if islocal:
                    LOG.error_to_file(f"execute cmd[{cmd}] failed err[{err_msg}]")
                else:
                    LOG.error_to_file(f"execute cmd[{cmd}] failed err[{res}]")
                return ret[:-1], False
            return ret[:-1], True
        except Exception as e:
            err_msg = f"Failed to execute ssh command {cmd}. err[{e}]"
            LOG.error_to_file(f"traceback: {traceback.format_exc(limit=-1)}")
            if ssh_client:
                ssh_client.close_client()
            raise Exception(err_msg)

    def get_pod_list(self, ssh_client, namespace, islocal=False):
        count = 0
        while count <= KUBECTL_TRY_COUNT:
            cmd = f"kubectl get pod -n {namespace}"
            res, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
            if not flag: 
                time.sleep(5)
                count += 1
                continue
            get_flag = False
            for i in res:
                if "NAME" in i:
                    get_flag = True
            return res if get_flag else []
        if count == KUBECTL_TRY_COUNT:
            err_msg = f"Failed to get the pod list more than 3 times."
            if not islocal:
                err_msg = f"Failed to get the pod list more than 3 times, server ip[{ssh_client.ip}]."
            LOG.error(err_msg)
            return []

    def get_pod_name_list_by_stat(self, ssh_client, namespace, pod_list, stat="default", islocal=False):
        pod_name_list = []
        data_list = self.get_pod_list(ssh_client, namespace, islocal=islocal)
        if not data_list:
            if stat == "abnormal":
                return pod_list
            return []
        for data in data_list:
            info = data.split()
            if not info:
                continue
            pod_name = info[0].strip()
            if split_pod_name(pod_name) not in pod_list:
                continue
            if stat == "default":
                pod_name_list.append(pod_name)
                continue
            elif stat == "running":
                if info[2] == "Running":
                    pod_name_list.append(pod_name)
                    continue
            elif stat == "ready":
                if info[1] == "1/1" and info[2] == "Running":
                    pod_name_list.append(pod_name)
                    continue
            elif stat == "abnormal":
                if info[1] != "1/1" or info[2] != "Running":
                    pod_name_list.append(pod_name)
                    continue
        return pod_name_list

    def del_all_pod(self, ip, ssh_client, value, islocal=False):
        cantian_yaml = value.get("cantian_yaml")
        config_yaml = value.get("config_yaml")
        cmd = f"kubectl delete -f {cantian_yaml} -f {config_yaml}"
        _, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
        if not flag:
            err_msg = f"Failed to delete pod, IP[{ip}] cantian path[{cantian_yaml}] config path[{config_yaml}]."
            LOG.error(err_msg)

    def del_pod(self, ip, cantian_yaml):
        if ip in self.ip_info:
            ssh_client = None
            islocal = True
        else:
            ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
            ssh_client.create_client()
            islocal = False
        cmd = f"kubectl delete -f {cantian_yaml}"
        res, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
        if not flag:
            err_msg = f"Failed to delete pod ,path[{cantian_yaml}]"
            LOG.error(err_msg)
        if ssh_client is not None:
            ssh_client.close_client()

    def apply_pods(self, ip, ssh_client, value, islocal=False):

        cantian_yaml = value.get("cantian_yaml", "")
        config_yaml = value.get("config_yaml", "")
        cmd = f"kubectl apply -f {config_yaml} -f {cantian_yaml}"
        _, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
        if not flag:
            err_msg = f"Failed to apply pod, IP[{ip}] config path[{config_yaml}] cantian path[{cantian_yaml}]"
            LOG.error(err_msg)

    def apply_pod(self, ip, cantian_yaml, config_yaml):
        if ip in self.ip_info:
            ssh_client = None
            islocal = True
        else:
            ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
            ssh_client.create_client()
            islocal = False
        cmd = f"kubectl apply -f {config_yaml}"
        _, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
        if not flag:
            err_msg = f"Failed to apply pod ,path[{config_yaml}]"
            LOG.error(err_msg)
        cmd = f"kubectl apply -f {cantian_yaml}"
        _, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
        if not flag:
            err_msg = f"Failed to apply pod ,path[{cantian_yaml}]"
            LOG.error(err_msg)
        if ssh_client is not None:
            ssh_client.close_client()

    def del_pods_with_change_file(self, ip, ssh_client, value, islocal=False):
        cantian_yaml = value.get("dst_cantian_yaml")
        config_yaml = value.get("dst_config_yaml")
        cantian_del = False
        config_del = False
        count = 0
        while True:
            if not config_del:
                cmd = f"kubectl delete -f {config_yaml}"
                _, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
                if not flag:
                    err_msg = f"Failed to delete pod, path[{config_yaml}]"
                    LOG.error(err_msg)
                else:
                    config_del = True
            if not cantian_del:
                cmd = f"kubectl delete -f {cantian_yaml}"
                _, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
                if not flag:
                    err_msg = f"Failed to delete pod, path[{cantian_yaml}]"
                    LOG.error(err_msg)
                else:
                    cantian_del = True
            if config_del and cantian_del:
                break
            if count == KUBECTL_TRY_COUNT:
                LOG.error(f"ip[{ip}] delete pod err, please check.")
            count += 1

    def change_config_and_apply_pod(self, ip, ssh_client, value, islocal=False):
        timestamp = get_now_timestamp()
        server_dir = value.get("server_path")
        source_cantian_yaml = os.path.join(server_dir, "cantian.yaml")
        source_config_yml = os.path.join(server_dir, "configMap.yaml")
        dst_cantian_yaml = os.path.join("/home", f"cantian-{timestamp}.yaml")
        dst_config_yaml = os.path.join("/home", f"configMap-{timestamp}.yaml")
        cantian_flag = False
        cantian_apply = False
        config_apply = False
        config_flag = False
        count = 0
        while True:
            if islocal:
                value["dst_cantian_yaml"] = source_cantian_yaml
                value["dst_config_yaml"] = source_config_yml
                if not config_apply:
                    cmd = f"kubectl apply -f {source_config_yml}"
                    _, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
                    if not flag:
                        err_msg = f"Failed to apply pod, path[{source_config_yml}]"
                        LOG.error(err_msg)
                    else:
                        config_apply = True
                if not cantian_apply:
                    cmd = f"kubectl apply -f {source_cantian_yaml}"
                    _, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
                    if not flag:
                        err_msg = f"Failed to apply pod, path[{source_cantian_yaml}]"
                        LOG.error(err_msg)
                    else:
                        cantian_apply = True
            else:
                if not config_flag:
                    ssh_client.upload_file(source_config_yml, dst_config_yaml)
                    value["dst_config_yaml"] = dst_config_yaml
                    config_flag = True
                if not config_apply:
                    cmd = f"kubectl apply -f {dst_config_yaml}"
                    _, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
                    if not flag:
                        err_msg = f"Failed to apply pod, path[{dst_config_yaml}]"
                        LOG.error(err_msg)
                    else:
                        config_apply = True
                if not cantian_flag:
                    ssh_client.upload_file(source_cantian_yaml, dst_cantian_yaml)
                    value["dst_cantian_yaml"] = dst_cantian_yaml
                    config_flag = True
                if not cantian_apply:
                    cmd = f"kubectl apply -f {dst_cantian_yaml}"
                    _, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
                    if not flag:
                        err_msg = f"Failed to apply pod, path[{dst_cantian_yaml}]"
                        LOG.error(err_msg)
                    else:
                        cantian_apply = True
            if config_apply and cantian_apply:
                break
            if count == KUBECTL_TRY_COUNT:
                LOG.error(f"ip[{ip}] copy file and apply err, please check.")
                raise Exception("copy_file or apply error")
            count += 1

    def check_pod_del(self, timeout=300):
        exist_pod = False
        ssh_client = None
        time.sleep(10)
        run_time = 10
        try:
            for ip in self.server_info:
                islocal = True
                if ip not in self.ip_info:
                    ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
                    ssh_client.create_client()
                    islocal = False
                for value in self.server_info[ip]:
                    LOG.info(f"check IP[{ip}]pods delete stat, please waiting ...")
                    namespace = value.get("namespace")
                    pod_name_list = value.get("pod_name")
                    count = 0
                    while True:
                        if run_time > timeout:
                            err_msg = f" check pod del timeout"
                            LOG.error(err_msg)
                            return False
                        pod_list = self.get_pod_name_list_by_stat(ssh_client, namespace,
                                                                  pod_name_list, islocal=islocal)
                        if len(pod_list) == 0:
                            break
                        if count == CHECK_DEL_TRY_COUNT:
                            exist_pod = True
                            break
                        count += 1
                        time.sleep(3)
                        run_time += 3
                if ssh_client is not None:
                    ssh_client.close_client()
                    ssh_client = None
            LOG.info("check pod delete finish")
            if exist_pod:
                return False
            else:
                return True
        except Exception as e:
            raise e
        finally:
            if ssh_client is not None:
                ssh_client.close_client()

    def do_check_pod_start(self, ip, ssh_client, value, islocal=False, time_over=False, run_time=0, timeout=1200):
        namespace = value.get("namespace")
        pod_name_list = value.get("pod_name")
        LOG.info(f"check IP[{ip}]pods apply stat, please waiting ...")
        while True:
            if run_time > timeout:
                err_msg = f"IP[{ip}], namespace[{namespace}], pod name[{pod_name_list}], Abnormal status"
                LOG.error(err_msg)
                break
            start_pod_list = []
            value["abnormal_pods"] = []
            data_list = self.get_pod_list(ssh_client, namespace, islocal=islocal)
            if not data_list:
                LOG.error("Failed to get the pod list more than 3 times.")
                return run_time
            for data in data_list:
                info = data.split()
                if not info:
                    continue
                if split_pod_name(info[0]) in pod_name_list:
                    if info[1] == "1/1" and info[2] == "Running":
                        start_pod_list.append(info[0])
                        continue
                    value["abnormal_pods"].append(info[0])
            if len(start_pod_list) == len(pod_name_list):
                break
            if time_over:
                err_msg = (f"IP[{ip}], namespace[{namespace}], "
                           f"pod name[{pod_name_list}], Abnormal status")
                LOG.error(err_msg)
                break
            run_time += 30
            time.sleep(30)
        return run_time

    def check_pod_start(self):
        time_over = False
        ssh_client = None
        time.sleep(180)
        run_time = 180
        timeout = 1200
        try:
            for ip in self.server_info:
                islocal = True
                if ip not in self.ip_info:
                    ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
                    ssh_client.create_client()
                    islocal = False
                for value in self.server_info[ip]:
                    run_time = self.do_check_pod_start(ip, ssh_client, value, islocal=islocal,
                                                       time_over=time_over, run_time=run_time)
                    if run_time > timeout:
                        time_over = True
                if ssh_client is not None:
                    ssh_client.close_client()
                    ssh_client = None
            LOG.info("check pod stat finish")
        except Exception as e:
            raise e
        finally:
            if ssh_client is not None:
                ssh_client.close_client()

    def check_pod_stat(self, ip, ssh_client, value, islocal=False):
        namespace = value.get("namespace")
        pod_name_list = value.get("pod_name")
        value["abnormal_pods"] = []
        pod_list = self.get_pod_name_list_by_stat(ssh_client, namespace, pod_name_list, stat="abnormal",
                                                  islocal=islocal)
        value["abnormal_pods"] += pod_list

    def check_abnormal_pod_stat(self):
        abnormal_flag = False
        warning_flag = False
        for ip in self.server_info:
            for value in self.server_info[ip]:
                pod_name_list = value.get("pod_name", [])
                namespace = value.get("namespace")
                abnormal_pod_list = value.get("abnormal_pods", [])
                if len(abnormal_pod_list) == len(pod_name_list):
                    err_msg = (f"IP[{ip}], namespace[{namespace}], "
                               f"pod name[{pod_name_list}], all pods Abnormal status")
                    LOG.error(err_msg)
                    abnormal_flag = True
                else:
                    for pod in abnormal_pod_list:
                        err_msg = (f"IP[{ip}], namespace[{namespace}], "
                                   f"pod name[{pod}], Abnormal status")
                        LOG.error(err_msg)
                        warning_flag = True
        if abnormal_flag:
            LOG.error("pods stat abnormal, please check pod stat.")
            if self.action == "switch_over":
                LOG.warning("Please execute command [python3 dr_k8s_switch.py delete] on the active site first, "
                            "and then execute command [python3 dr_k8s_switch.py fail_over] on the standby site.")
        else:
            if not warning_flag:
                return True
            return confirm()
        return False

    def check_hyper_metro_filesystem_pair_info(self):
        err_flag = False
        for ulog_pair_info in self.ulog_pair_list:
            local_data_status = ulog_pair_info.get("LOCALDATASTATE")
            remote_data_status = ulog_pair_info.get("REMOTEDATASTATE")
            if local_data_status == DataIntegrityStatus.inconsistent or \
                remote_data_status == DataIntegrityStatus.inconsistent:
                err_msg = "Data is inconsistent, please check, pair_id[%s]." % ulog_pair_info.get("ID")
                LOG.error(err_msg)
                err_flag = True
        if err_flag:
            raise Exception("Data is inconsistent, please check.")
        LOG.info("check hyper metro filesystem pair finish")

    def check_hyper_metro_filesystem_pair_stat(self):
        for ulog_pair_info in self.ulog_pair_list:
            run_stat = ulog_pair_info.get("RUNNINGSTATUS")
            if run_stat != FilesystemPairRunningStatus.Normal:
                err_msg = "ulog pair is not Abnormal, please check, pair_id[%s]." % ulog_pair_info.get("ID")
                LOG.error(err_msg)
                self.check_flag = False
        LOG.info("check hyper metro filesystem pair stat finish")

    def check_replication_filesystem_pair_stat(self):
        for ip in self.server_info:
            for value in self.server_info[ip]:
                page_fs_info = self.storage_opt.query_filesystem_info(value.get("storage_dbstor_page_fs"))
                page_pair_info = self.dr_option.query_remote_replication_pair_info(page_fs_info.get("ID"))[0]
                page_pair_id = page_pair_info.get("ID")
                value["page_pair_id"] = page_pair_id
                run_stat = page_pair_info.get("RUNNINGSTATUS")
                if run_stat != ReplicationRunningStatus.Split:
                    err_msg = "page pair is not Split, please check, pair_id[%s]." % page_pair_id
                    LOG.error(err_msg)
                    self.check_flag = False
        LOG.info("check replication filesystem pair stat finish")

    def query_sync_status(self, timeout=600):
        flag = False
        run_time = 0
        while True:
            for index, vstore_pair in enumerate(self.vstore_pair_list):
                vstore_id = vstore_pair.get("ID")
                vstore_pair_info = self.dr_option.query_hyper_metro_vstore_pair_info(vstore_id)
                health_status = vstore_pair_info.get("HEALTHSTATUS")
                running_status = vstore_pair_info.get("RUNNINGSTATUS")
                LOG.info(f"Vstore pair[{vstore_id}] sync running, "
                         f"running status[{get_status(running_status, VstorePairRunningStatus)}]")

                if running_status == VstorePairRunningStatus.Invalid or health_status == HealthStatus.Faulty:
                    err_msg = "Hyper metro vstore pair[%s] status is not normal, " \
                              "health_status[%s], running_status[%s], details: %s" % \
                              (vstore_id,
                               get_status(health_status, HealthStatus),
                               get_status(running_status, VstorePairRunningStatus),
                               vstore_pair_info)
                    LOG.error(err_msg)
                if running_status == VstorePairRunningStatus.Normal and health_status == HealthStatus.Normal:
                    LOG.info("Vstore pair sync complete.")
                    if index == len(self.vstore_pair_list) - 1:
                        flag = True
                        break
                    continue
                run_time += 60
                if run_time >= timeout:
                    return flag
                time.sleep(60)
            if flag:
                return flag

    def switch_hyper_metro_domain_role(self):
        self.check_hyper_metro_filesystem_pair_info()
        domain_info = self.dr_option.query_hyper_metro_domain_info(self.domain_id)
        running_status = domain_info.get("RUNNINGSTATUS")
        config_role = domain_info.get("CONFIGROLE")
        if running_status != MetroDomainRunningStatus.Normal and running_status != MetroDomainRunningStatus.Split:
            err_msg = "DR recover operation is not allowed in %s status." % \
                      get_status(running_status, MetroDomainRunningStatus)
            LOG.error(err_msg)
            raise Exception(err_msg)
        if config_role == ConfigRole.Primary and running_status == MetroDomainRunningStatus.Normal:
            self.dr_option.split_filesystem_hyper_metro_domain(self.domain_id)
            self.dr_option.change_fs_hyper_metro_domain_second_access(
                self.domain_id, DomainAccess.ReadAndWrite)
            self.dr_option.swap_role_fs_hyper_metro_domain(self.domain_id)
            self.dr_option.change_fs_hyper_metro_domain_second_access(self.domain_id, DomainAccess.ReadOnly)
            self.dr_option.join_fs_hyper_metro_domain(self.domain_id)
            self.query_sync_status()
        LOG.info("Success to recover hyper metro domain.")

    def switch_replication_pair_role(self):
        for ip in self.server_info:
            for value in self.server_info[ip]:
                page_fs_info = self.storage_opt.query_filesystem_info(value.get("storage_dbstor_page_fs"))
                page_pair_info = self.dr_option.query_remote_replication_pair_info(page_fs_info.get("ID"))[0]
                page_role = page_pair_info.get("ISPRIMARY")
                pair_id = page_pair_info.get("ID")
                if page_role == "true":
                    self.dr_option.swap_role_replication_pair(pair_id)
                else:
                    LOG.info("Page fs rep pair is already standby site, pair_id[%s].", pair_id)
        LOG.info("switch replication pair finish.")

    def do_fail_over(self):
        domain_info = self.dr_option.query_hyper_metro_domain_info(self.domain_id)
        config_role = domain_info.get("CONFIGROLE")
        if config_role == ConfigRole.Primary:
            err_msg = "Fail over operation is not allowed in primary node."
            LOG.error(err_msg)
            raise Exception(err_msg)
        running_status = domain_info.get("RUNNINGSTATUS")
        if running_status == MetroDomainRunningStatus.Normal:
            self.dr_option.split_filesystem_hyper_metro_domain(self.domain_id)
        self.dr_option.change_fs_hyper_metro_domain_second_access(self.domain_id, DomainAccess.ReadAndWrite)
        LOG.info("fail over finish.")

    def pod_exe_cmd(self, pod_name, namespace, cmd, ssh_client, timeout=30, islocal=False):
        exe_cmd = f"kubectl exec -it {pod_name} -n {namespace} -- {cmd}"
        return self.ssh_exec_cmd(ssh_client, exe_cmd, timeout=timeout, islocal=islocal)

    def query_database_role(self, pod_name, namespace, cmd, ssh_client, timeout=180, islocal=False):
        run_time = 0
        while True:
            exe_cmd = f"kubectl exec -it {pod_name} -n {namespace} -- sh -c \"{cmd}{self.ssh_cmd_end}\""
            try:
                if islocal:
                    _, res, _ = exec_popen(exe_cmd, timeout)
                else:
                    res = ssh_client.execute_cmd(exe_cmd, expect=self.ssh_expect, timeout=timeout)
                ret = res.strip()
                if "last_cmd=0" not in res:
                    flag = False
                else:
                    flag = True
            except Exception as e:
                err_msg = f"Failed to execute ssh command {cmd}. err[{e}]"
                if ssh_client:
                    ssh_client.close_client()
                raise Exception(err_msg)
            if not flag:
                err_msg = "Query database role failed, error:%s." % ret
                LOG.error(err_msg)
                raise Exception(err_msg)
            if "PRIMARY" in ret:
                LOG.info(f"The pod name[{pod_name}] current site database role is primary.")
                return True
            LOG.info(f"The pod name[{pod_name}] current site database role is standby, please wait...")
            if run_time >= timeout:
                LOG.error(f"The current site database role is {ret} but timed out,"
                          f" pod_name[{pod_name}], namespace[{namespace}].")
                return False
            run_time += 20
            time.sleep(20)

    def check_database_role(self, ip, ssh_client, value, islocal=False):
        run_user = value.get("run_user")
        check_cmd = CANTIAN_DATABASE_ROLE_CHECK % (run_user, EXEC_SQL)
        namespace = value.get("namespace")
        pod_name_list = value.get("pod_name")
        total_pod_list = copy.deepcopy(pod_name_list)
        pod_list = self.get_pod_name_list_by_stat(ssh_client, namespace, pod_name_list,
                                                  stat="ready", islocal=islocal)
        if not pod_list:
            err_msg = f"Failed to check database role, server_ip[{ip}] pod_name[{pod_name_list}]"
            LOG.error(err_msg)
            return
        for pod_name in pod_list:
            total_pod_list.remove(split_pod_name(pod_name))
            if self.query_database_role(pod_name, namespace, check_cmd,
                                        ssh_client, islocal=islocal):
                continue
            else:
                err_msg = f"Failed to check database role, server_ip[{ip}] pod_name[{pod_name}]"
                LOG.error(err_msg)
        for pod_name in total_pod_list:
            LOG.error(f"Not checking database role, server_ip[{ip}] pod_name[{pod_name}], "
                      f"because pod stat is abnormal.")

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

    def get_single_write_flag(self, ssh_client, pod_name, namespace, cluster_name, islocal=False, timeout=60):
        get_cmd = "sh %s getbase %s" % (DBSTOR_CHECK_VERSION_FILE, cluster_name)
        cmd = f"single=$(kubectl exec -it {pod_name} -n {namespace} -- {get_cmd}); echo single=$single"
        try:
            ret_err = ""
            if islocal:
                _, res, ret_err = exec_popen(cmd, timeout)
            else:
                res = ssh_client.execute_cmd(cmd, expect=self.ssh_expect, timeout=timeout)
            if "single=0" in res:
                return 0
            elif "single=1" in res:
                return 1
            else:
                if ssh_client:
                    err_msg = (f"server ip[{ssh_client.ip}], pod_name[{pod_name}] "
                               f"Execute command[{cmd}], err[{res}] failed.")
                else:
                    err_msg = (f"server ip[{self.ip_info}], pod_name[{pod_name}] "
                               f"Execute command[{cmd}], err[{ret_err}] failed.")
                LOG.error(err_msg)
                raise Exception(err_msg)
        except Exception as e:
            err_msg = f"Failed to execute ssh command {cmd}. err[{e}]"
            if ssh_client:
                ssh_client.close_client()
            raise Exception(err_msg)

    def write_single_flag(self, ip, single, index):
        value = self.server_info[ip][index]
        value["single"] = str(single)
        with open(self.single_file_path, "w") as f:
            f.truncate()
            json.dump(self.server_info, f, indent=4)

    def do_check_pod_dbstor_init(self, ip, ssh_client, index, islocal=False, timeout=600):
        check_cmd = f"cat {DEPLOY_LOG_FILE} | grep 'init dbstor success.'"
        value = self.server_info[ip][index]
        namespace = value.get("namespace")
        pod_name_list = value.get("pod_name")
        run_time = 0
        while True:
            if run_time > timeout:
                err_msg = f"IP[{ip}] pod name[{pod_name_list}] Failed to check_dbstor_init, execute timeout"
                LOG.error(err_msg)
                raise Exception(err_msg)
            run_time += 5
            time.sleep(5)
            for pod_name in self.get_pod_name_list_by_stat(ssh_client, namespace, pod_name_list,
                                                           stat="running", islocal=islocal):
                _, check_flag = self.pod_exe_cmd(pod_name, namespace, check_cmd, ssh_client, islocal=islocal)
                if not check_flag:
                    continue
                else:
                    single = self.get_single_write_flag(ssh_client, pod_name, namespace,
                                                        value.get("cluster_name"), islocal=islocal)
                    self.write_single_flag(ip, single, index)
                    return

    def check_dbstor_init(self):
        ssh_client = None
        try:
            for ip in self.server_info:
                islocal = True
                if ip not in self.ip_info:
                    ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
                    ssh_client.create_client()
                    islocal = False
                for index, _ in enumerate(self.server_info[ip]):
                    self.do_check_pod_dbstor_init(ip, ssh_client, index, islocal=islocal)
                if ssh_client is not None:
                    ssh_client.close_client()
                    ssh_client = None
            LOG.info("check pod init finish.")
        except Exception as e:
            raise e
        finally:
            if ssh_client is not None:
                ssh_client.close_client()

    def switch_hyper_metro_domain_role_recover(self):
        domain_info = self.dr_option.query_hyper_metro_domain_info(self.domain_id)
        running_status = domain_info.get("RUNNINGSTATUS")
        config_role = domain_info.get("CONFIGROLE")
        self.hyper_metro_status_check(running_status, config_role)
        if running_status == MetroDomainRunningStatus.Split:
            if config_role == ConfigRole.Primary:
                self.dr_option.change_fs_hyper_metro_domain_second_access(
                    self.domain_id, DomainAccess.ReadAndWrite)
                self.dr_option.swap_role_fs_hyper_metro_domain(self.domain_id)
            self.exe_func(self.change_config_and_apply_pod)
            LOG.info("apply pods with change config finish")
            self.change_apply = True
            try:
                self.check_dbstor_init()
            except Exception as e:
                raise e
            finally:
                self.exe_func(self.del_pods_with_change_file)
            LOG.info("delete pods with change config finish")
            self.user_confirm_twice("'python3 dr_k8s_switch.py unconnected_check' and wait for the indication")            
            self.dr_option.change_fs_hyper_metro_domain_second_access(self.domain_id, DomainAccess.ReadOnly)
            try:
                self.dr_option.join_fs_hyper_metro_domain(self.domain_id)
            except Exception as _er:
                LOG.error("Fail to recover hyper metro domain, details: %s", str(_er))
        else:
            self.exe_func(self.apply_pods)
            LOG.info("apply pods finish")
            LOG.info("The current hyper_metro_status running_status is not Split.")
            return
        self.query_sync_status()
        self.user_confirm_twice("'python3 dr_k8s_switch.py unconnected_recover'")
        LOG.info("switch hyper metro domain with recover finish.")

    def wait_remote_replication_pair_sync(self, pair_id):
        pair_info = self.dr_option.query_remote_replication_pair_info_by_pair_id(pair_id)
        running_status = pair_info.get("RUNNINGSTATUS")
        while running_status == ReplicationRunningStatus.Synchronizing:
            pair_info = self.dr_option.query_remote_replication_pair_info_by_pair_id(pair_id)
            running_status = pair_info.get("RUNNINGSTATUS")
            replication_progress = pair_info.get("REPLICATIONPROGRESS")
            LOG.info(f"Page fs rep pair[{pair_id}] is synchronizing, "
                     f"current progress: {replication_progress}%, please wait...")
            time.sleep(10)

    def execute_replication_steps(self, running_status, server_info, pair_id):
        LOG.info(f"Execute replication steps. pair id[{pair_id}] Singel_write: {server_info.get('single')}")
        if server_info.get("single") == "1":
            if running_status != ReplicationRunningStatus.Synchronizing:
                self.dr_option.sync_remote_replication_filesystem_pair(pair_id=pair_id,
                                                                       vstore_id="0", is_full_copy=False)
                time.sleep(10)
            self.wait_remote_replication_pair_sync(pair_id)
        else:
            LOG.info("Single write is disabled, no need to execute replication steps.")
        self.dr_option.split_remote_replication_filesystem_pair(pair_id)
        self.dr_option.remote_replication_filesystem_pair_cancel_secondary_write_lock(pair_id)

    def switch_replication_pair_role_recover(self):
        err_flag = False
        single_config = get_json_config(self.single_file_path)
        for ip in single_config:
            for value in single_config[ip]:
                page_fs_info = self.storage_opt.query_filesystem_info(value.get("storage_dbstor_page_fs"))
                page_pair_info = self.dr_option.query_remote_replication_pair_info(page_fs_info.get("ID"))[0]
                page_role = page_pair_info.get("ISPRIMARY")
                running_status = page_pair_info.get("RUNNINGSTATUS")
                pair_id = page_pair_info.get("ID")
                if page_role == "true":
                    if value["single"] == "1":
                        self.single_pod[ip].append(value)
                        self.del_pod(ip, value["cantian_yaml"], )
                    self.dr_option.swap_role_replication_pair(pair_id)
                    self.dr_option.remote_replication_filesystem_pair_set_secondary_write_lock(pair_id)
                    self.execute_replication_steps(running_status, value, pair_id=pair_id)
                else:
                    LOG.info(f"Page fs rep pair[{pair_id}] is already standby site.")
                    if running_status == ReplicationRunningStatus.Split:
                        continue
                    elif running_status == ReplicationRunningStatus.Normal or \
                            running_status == ReplicationRunningStatus.Synchronizing:
                        self.wait_remote_replication_pair_sync(pair_id)
                        self.dr_option.split_remote_replication_filesystem_pair(pair_id)
                    else:
                        err_msg = f"Remote replication filesystem pair is not in normal status, pair_id[{pair_id}]."
                        LOG.error(err_msg)
                        err_flag = True
        if err_flag:
            raise Exception("Remote replication filesystem pair is not in normal status.")
        LOG.info("switch replication pair with recover finish.")

    def delete_config_file(self, ip, ssh_client, value, islocal=False):
        cantian_yaml = value.get("dst_cantian_yaml")
        config_yaml = value.get("dst_config_yaml")
        if islocal:
            if os.path.exists(cantian_yaml):
                os.remove(cantian_yaml)
            if os.path.exists(config_yaml):
                os.remove(config_yaml)
        else:
            cmd = f"rm -rf {cantian_yaml} {config_yaml}"
            _, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
            if not flag:
                err_msg = (f"Failed to delete config file, IP[{ip}] cantian path[{cantian_yaml}] "
                           f"config path[{config_yaml}].]")
                LOG.error(err_msg)

    def ctbackup_purge_log(self, ip, ssh_client, value, islocal=False):
        namespace = value.get("namespace")
        pod_name_list = value.get("pod_name")
        flag = False
        exe_flag = False
        for pod_name in self.get_pod_name_list_by_stat(ssh_client, namespace, pod_name_list,
                                                       stat="ready", islocal=islocal):
            exe_flag = True
            cmd = ("su -s /bin/bash - %s -c "
                   "'source ~/.bashrc && ctbackup --purge-logs'") % value.get("run_user")
            ret, flag = self.pod_exe_cmd(pod_name, namespace, cmd,
                                         ssh_client, timeout=600, islocal=islocal)
            if not flag:
                continue
            break
        if not flag:
            if not exe_flag:
                err_msg = "Failed to execute[ctbackup --purge-logs], because pod stat is abnormal."
            else:
                err_msg = (f"server ip[{ip}], pod_name[{pod_name_list}], "
                           f"Execute command[ctbackup --purge-logs] failed.")
            LOG.error(err_msg)

    def backup_pod_log(self, ip, ssh_client, value, islocal=False):
        namespace = value.get("namespace")
        pod_name_list = value.get("pod_name")
        cluster_name = value.get("cluster_name")
        cluster_id = value.get("cluster_id")
        config_map = value.get("config_map")
        run_user = value.get("run_user")
        storage_metadata_fs = value.get("storage_metadata_fs")
        for pod_name in self.get_pod_name_list_by_stat(ssh_client, namespace, pod_name_list,
                                                       stat="running", islocal=islocal):
            node_id = get_node_id(config_map, pod_name)
            LOG.info(f"Ip[{ip}] namespace[{namespace}] pod[{pod_name}] begin to backup pod logs.")
            cmd = (f"sh /ctdb/cantian_install/cantian_connector/action/docker/log_backup.sh "
                   f"{cluster_name} {cluster_id} {node_id} {run_user} {storage_metadata_fs}")
            _, flag = self.pod_exe_cmd(pod_name, namespace, cmd, ssh_client, islocal=islocal)
            if not flag:
                LOG.error(f"IP[{ip}] namespace[{namespace}] "
                          f"pod_name[{pod_name}] back pod logs failed.")
        LOG.info(f"Ip[{ip}] namespace[{namespace}] backup_pod_log finish.")

    def delete_pods(self):
        self.exe_func(self.backup_pod_log)
        self.exe_func(self.del_all_pod)
        LOG.info("active pods delete finish.")
        if not self.check_pod_del():
            LOG.error("active pods delete failed.")
            return False
        return True

    def exe_func(self, func):
        ssh_client = None
        try:
            for ip in self.server_info:
                islocal = True
                if ip not in self.ip_info:
                    ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
                    ssh_client.create_client()
                    islocal = False
                for value in self.server_info[ip]:
                    func(ip, ssh_client, value, islocal=islocal)
                if ssh_client is not None:
                    ssh_client.close_client()
                    ssh_client = None
        except Exception as e:
            LOG.error(f"execute fun[{str(func)}] failed, err[{e}]")
            raise e
        finally:
            if ssh_client is not None:
                ssh_client.close_client()

    def switch_over(self):
        if not self.check_abnormal_pod_stat():
            LOG.info("active pods stat abnormal, exit.")
            return
        self.delete_pods()
        self.switch_hyper_metro_domain_role()
        self.switch_replication_pair_role()
        self.exe_func(self.apply_pods)
        LOG.info("apply pods finish")
        if self.unconnected_ip:
            warning(f"Go to the node {self.unconnected_ip} and input 'python3 dr_k8s_switch.py unconnected_switch'.")
        self.check_pod_start()

    def fail_over(self):
        self.exe_func(self.check_pod_stat)
        if not self.check_abnormal_pod_stat():
            LOG.info("standby pods stat abnormal, exit.")
            return
        self.do_fail_over()
        self.exe_func(self.check_database_role)
        LOG.info("check database role finish.")

    def unconnected_fail_over(self):
        self.exe_func(self.check_pod_stat)
        if not self.check_abnormal_pod_stat():
            warning("pod stat is abnormal, back to the orginal node and input 'no'.")

    def recover(self):
        try:
            self.switch_hyper_metro_domain_role_recover()
            self.switch_replication_pair_role_recover()
            self.exe_func(self.apply_pods)
            LOG.info("apply pods finish")
            self.check_pod_start()
            self.exe_func(self.ctbackup_purge_log)
            LOG.info("ctbackup_purge_log finish.")
        except Exception as e:
            raise e
        finally:
            if self.change_apply:
                self.exe_func(self.delete_config_file)

    def delete(self):
        if self.delete_pods():
            LOG.info("active pods delete success.")

    def unconnected_delete(self):
        if self.delete_pods():
            LOG.info("active pods delete success.")

    def unconnected_switch_delete(self):
        if not self.check_abnormal_pod_stat():
            LOG.info("active pods stat abnormal, exit.")
            return
        self.delete_pods()
        warning("Script complete, back to the original node and wait for the next indication.")

    def unconnected_switch(self):
        self.switch_replication_pair_role()
        self.exe_func(self.apply_pods)
        LOG.info("apply pods finish")
        if self.unconnected_ip:
            warning(f"Go to the node {self.unconnected_ip} and input 'python3 dr_k8s_switch.py unconnected_switch'.")
        self.check_pod_start()
        warning("Script complete, succeed to switch_over in this unconnected node.")
    
    def unconnected_check(self):
        self.exe_func(self.change_config_and_apply_pod)
        LOG.info("apply pods with change config finish")
        self.change_apply = True
        try:
            self.check_dbstor_init()
        except Exception as e:
            LOG.error(f"Check dbstor init fialed, detail: {e}")
            raise e
        finally:
            self.exe_func(self.del_pods_with_change_file)
        LOG.info("delete pods with change config finish")
        self.user_confirm_twice("'python3 dr_k8s_switch.py unconnected_check' and wait for the indication")
        warning("Script complete, back to the original node and wait for the next indication.") 

    def unconnected_recover(self):
        self.user_confirm_twice("'python3 dr_k8s_switch.py unconnected_recover'")
        try:
            self.switch_replication_pair_role_recover()
            self.exe_func(self.apply_pods)
            LOG.info("apply pods finish")
            self.check_pod_start()
            self.exe_func(self.ctbackup_purge_log)
            LOG.info("ctbackup_purge_log finish.")
        except Exception as e:
            LOG.error(f"Cannot apply pods and ctbackup purge log, detail: {e}")
            raise e
        finally:
            if self.change_apply:
                self.exe_func(self.delete_config_file)
        warning("Script complete, succeed to recover in the unconnected node.")

    def check_flag_stat(self):
        if not self.check_flag:
            raise Exception("Program pre check failed")

    def run(self):
        if len(sys.argv) < 2:
            err_msg = "The number of parameters must not be less than 2"
            LOG.error(err_msg)
            raise Exception(err_msg)
        self.action = sys.argv[1]
        if self.action not in self.action_list:
            LOG.error(f"Action {self.action} not supported, supported actions are: {self.action_list}")
            return
        if not self.warning_tip():
            return
        if "unconnected" in self.action:
            self.is_unconnected_flag = True
        self.init_k8s_config()
        self.check_flag_stat()
        try:
            self.pre_check()
            try:  
                getattr(self, self.action)
            except AttributeError as _err:
                err_msg = "The supported types of operations include [delete, switch_over, fail_over, recover,\n"
                          "unconnected_switch_delete, unconnected_fail_over, unconnected_switch, unconnected_recover,
                          "unconnected_check, unconnected_delete]\n"
                raise Exception(err_msg) from _err
            getattr(self, self.action)()
        except Exception as e:
            raise e
        finally:
            if self.storage_opt is not None:
                self.storage_opt.logout()


if __name__ == '__main__':
    try:
        K8sDRContainer().run()
    except Exception as err:
        LOG.error(f"err[{err}], [{traceback.format_exc(limit=-1)}]")
        raise err

