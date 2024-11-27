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

DBSTORE_CHECK_VERSION_FILE = "/opt/cantian/dbstor/tools/cs_baseline.sh"


class LogGer:
    def __init__(self, name, file_name):
        self.name = name
        self.file_name = file_name

    def get_logger(self):
        logger = logging.getLogger(self.name)
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
    warning_confirm = input("Do you want to continue? (yes/no): ", )
    if warning_confirm != "yes" and warning_confirm != "no":
        warning_confirm = input("Invalid input. Please enter 'yes' or 'no': ", )
    if warning_confirm == "no":
        LOG.info("Operation cancelled.")
        return False
    second_warning_confirm = input("To confirm operation, enter yes. Otherwise, exit: ")
    if second_warning_confirm != "yes":
        LOG.info("Operation cancelled.")
        return False
    return True


class K8sDRContainer:
    def __init__(self):
        self.k8s_config_path = os.path.join(CURRENT_PATH, "k8s_dr_config.json")
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
        self.dr_info_map = {}
        self.ssh_cmd_end = " ; echo last_cmd=$?"
        self.vstore_pair_list = []
        self.single_file_path = os.path.join(CURRENT_PATH, "single_file.json")
        self.single_pod = {}
        self.abnormal_pod = {}
        self.check_flag = True
        self.action_list = ["delete", "switch_over", "fail_over", "recover"]
        self.ip_info = ""
        self.config_count = 0
        self.ssh_expect = "]# "

    def warning_tip(self):
        warning_msgs = {
            "switch_over": "\tSwitchover operation will be performed.\n"
                           "\tThe current operation will cause the active-standby switch,\n"
                           "\tplease make sure the standby data is consistent with the main data,\n"
                           "\tif the data is not consistent, the execution of the switch operation may cause data loss,\n"
                           "\tplease make sure the standby and DeviceManager are in good condition, "
                           "if not, the new active will hang after switch over.\n"
                           "\tAfter the command is executed, check the replay status on the standby "
                           "side to determine if the active-standby switch was successful.\n",
            "recover": "\tRecover operation will downgrade current station to standby,\n"
                       "\tsynchronize data from remote to local, and cover local data.\n"
                       "\tEnsure remote data consistency to avoid data loss.\n",
            "fail_over": "\tFailover operation will start the standby cluster.\n"
                         "\tPlease confirm that the active device or cantian has failed,\n"
                         "\tPlease ensure that all primary sites have been stopped.\n"
                         "\tAfter this operation,\n"
                         "\tplease ensure that the original active cluster is not accessed for write operations,\n"
                         "\totherwise it will cause data inconsistency.\n",
            "delete": "\tDeletion operation will delete the all Cantian nodes under hyper metro domain.\n"
        }
        if self.action in warning_msgs:
            warning("Warning:")
            warning(warning_msgs[self.action])
            return confirm()
        return True

    def init_k8s_config(self):
        if not os.path.exists(self.k8s_config_path):
            err_msg = f"k8s_config_path does not exist, path: {self.k8s_config_path}"
            LOG.error(err_msg)
            self.check_flag = False
            return
        config = get_json_config(self.k8s_config_path)
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
        ret_code, ret, stderr = exec_popen(cmd, 20)
        if ret_code:
            err_msg = f"Failed to get ip info for {cmd}"
            LOG.error(err_msg)
            self.check_flag = False
            return
        self.ip_info = ret.strip()
        LOG.info("get self ip info finish")

    def check_k8s_config(self, ip, index, dir_path):
        value = self.server_info[ip][index]
        config_yaml = value.get("config_yaml")
        if (not os.path.exists(os.path.join(dir_path, "cantian.yaml")) or 
                not os.path.exists(os.path.join(dir_path, "configMap.yaml"))):
            self.check_flag = False
            return False
        value["server_path"] = dir_path
        with open(os.path.join(dir_path, "configMap.yaml"), 'r') as f:
            configs = yaml.safe_load_all(f)
            for config in configs:
                if config.get("kind") == "ConfigMap":
                    deploy_param = json.loads(config.get("data").get("deploy_param.json"))
                    domain_name = deploy_param.get("dr_deploy").get("domain_name")
                    if domain_name != self.domain_name:
                        err_msg = f"Domain name is not match, server ip[{ip}], config path[{config_yaml}]"
                        LOG.error(err_msg)
                        return False
                    value["storage_dbstore_fs"] = deploy_param.get("storage_dbstore_fs")
                    value["run_user"] = deploy_param.get("deploy_user").strip().split(":")[0]
                    value["cluster_name"] = deploy_param.get("cluster_name").strip()
                    value["storage_dbstore_page_fs"] = deploy_param.get("storage_dbstore_page_fs")
                    value["dbstore_fs_vstore_id"] = deploy_param.get("dbstore_fs_vstore_id")
                    break
                
        with open(os.path.join(dir_path, "cantian.yaml"), 'r') as f:
            configs = yaml.safe_load_all(f)
            for config in configs:
                if config.get("kind") == "Deployment":
                    if "pod_name" in value:
                        value["pod_name"].append(config.get("metadata").get("name"))
                        continue
                    value["pod_name"] = [config.get("metadata").get("name")]
                    value["namespace"] = config.get("metadata").get("namespace")
                    continue
        LOG.info(f"check ip[{ip}] k8s config index[{index}] finish")
        return True

    def change_config(self, dir_path):
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
                    yaml.dump(config, file)

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
            self.change_config(dir_path)
        except Exception as e:
            LOG.error(f"Download config file failed, err[{e}]")
            return False
        return True

    def pre_check_link(self):
        if not os.path.exists(self.server_key_file):
            err_msg = f"Server key file {self.server_key_file} does not exist"
            LOG.error(err_msg)
            self.check_flag = False
            return

        server_path = os.path.join(CURRENT_PATH, "server")
        if not os.path.exists(server_path):
            os.makedirs(server_path)
        config_index = 0
        remove_dir(server_path)
        if not remove_dir(server_path):
            err_msg = f"Failed to remove {server_path}."
            LOG.error(err_msg)
            raise Exception(err_msg)
        for ip in self.server_info:
            if ip in self.ip_info:
                ssh_client = None
                islocal = True
            else:
                ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
                ssh_client.create_client()
                islocal = False
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
                LOG.info(f"ip[{ip}] check path exist finish")
                if not self.download_config_file(ssh_client, ip, index, dir_path):
                    self.check_flag = False
                    LOG.error(f"ip[{ip}] download_config_file config index[{index}] failed.")
                    continue
                LOG.info(f"ip[{ip}] download_config_file config index[{index}] finish")
                if not self.check_k8s_config(ip, index, dir_path):
                    self.check_flag = False
                    LOG.error(f"ip[{ip}] check_k8s_config config index[{index}] failed.")
                    continue
                LOG.info(f"ip[{ip}] check_k8s_config config index[{index}] finish")
            if ssh_client is not None:
                ssh_client.close_client()
        LOG.info("pre_check_link finish")

    def init_dr_option(self):
        dm_passwd = getpass.getpass("Please input device manager login passwd: ")
        storage_opt = StorageInf((self.dm_ip, self.dm_user, dm_passwd))
        storage_opt.login()
        self.storage_opt = storage_opt
        self.dr_option = DRDeployCommon(storage_opt)

    def get_ulog_pair_info_list(self):
        domain_infos = self.dr_option.query_hyper_metro_domain_info()
        self.vstore_pair_list = []
        for domain_info in domain_infos:
            if domain_info.get("NAME") == self.domain_name:
                self.domain_id = domain_info.get("ID")
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

    def match_config_and_pair_with_fs_name(self, ip, index, ulog_pair_info):
        log_fs_name = ulog_pair_info.get("LOCALOBJNAME").strip()
        vstore_id = ulog_pair_info.get("vstoreId").strip()
        value = self.server_info[ip][index]
        if value.get("storage_dbstore_fs") == log_fs_name and value.get("dbstore_fs_vstore_id") == vstore_id:
            value["log_fs_id"] = ulog_pair_info.get("LOCALOBJID")
            value["log_pair_id"] = ulog_pair_info.get("ID")
            return True
        return False

    def check_and_match_ulog_page_info(self):
        LOG.info("begin to check_and_match_ulog_page_info")
        filter_server_info = {}
        for ulog_pair_info in self.ulog_pair_list:
            for ip in self.server_info:
                for index, value in enumerate(self.server_info[ip]):
                    if ip in filter_server_info and index in filter_server_info[ip]:
                        continue
                    if self.match_config_and_pair_with_fs_name(ip, index, ulog_pair_info):
                        if ip in filter_server_info:
                            filter_server_info[ip].append(index)
                        else:
                            filter_server_info[ip] = [index]
                        break
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
        self.pre_check_link()
        self.check_flag_stat()
        self.init_dr_option()
        self.get_ulog_pair_info_list()
        self.check_and_match_ulog_page_info()
        if self.action == "switch_over":
            self.check_pod_stat()
            self.check_hyper_metro_stat()
        if self.config_count != len(self.ulog_pair_list):
            LOG.error("config count not match ulog pair list.")
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
                    LOG.debug(f"execute cmd[{cmd}] failed err[{err_msg}]")
                else:
                    LOG.debug(f"execute cmd[{cmd}] failed err[{res}]")
                return ret[:-1], False
            return ret[:-1], True
        except Exception as e:
            err_msg = f"Failed to execute ssh command {cmd}. err[{e}]"
            if ssh_client:
                ssh_client.close_client()
            raise Exception(err_msg)

    def get_pod_list(self, ssh_client, namespace, islocal=False):
        cmd = f"kubectl get pod -n {namespace} | grep -v NAME"
        res, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
        if not flag:
            err_msg = f"Failed to check pod stat, server ip[{ssh_client.ip}]."
            LOG.error(err_msg)
            return None
        return res

    def del_pods(self):
        for ip in self.server_info:
            if ip in self.ip_info:
                ssh_client = None
                islocal = True
            else:
                ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
                ssh_client.create_client()
                islocal = False
            for value in self.server_info[ip]:
                cantian_yaml = value.get("cantian_yaml")
                config_yaml = value.get("config_yaml")
                cmd = f"kubectl delete -f {cantian_yaml} -f {config_yaml}"
                res, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
                if not flag:
                    err_msg = f"Failed to delete pod, cantian path[{cantian_yaml}] config path[{config_yaml}]."
                    LOG.error(err_msg)
            if ssh_client is not None:
                ssh_client.close_client()
        LOG.info("delete pods finish")

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

    def apply_pods(self):
        for ip in self.server_info:
            if ip in self.ip_info:
                ssh_client = None
                islocal = True
            else:
                ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
                ssh_client.create_client()
                islocal = False
            for value in self.server_info[ip]:
                cantian_yaml = value.get("cantian_yaml", "")
                config_yaml = value.get("config_yaml", "")
                cmd = f"kubectl apply -f {config_yaml}"
                res, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
                if not flag:
                    err_msg = f"Failed to apply pod ,path[{config_yaml}]"
                    LOG.error(err_msg)
                cmd = f"kubectl apply -f {cantian_yaml}"
                res, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
                if not flag:
                    err_msg = f"Failed to apply pod ,path[{cantian_yaml}]"
                    LOG.error(err_msg)
            if ssh_client is not None:
                ssh_client.close_client()
        LOG.info("apply pods finish")

    def apply_pod(self, ip, cantian_yaml, config_yaml):
        if ip in self.ip_info:
            ssh_client = None
            islocal = True
        else:
            ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
            ssh_client.create_client()
            islocal = False
        cmd = f"kubectl apply -f {config_yaml}"
        res, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
        if not flag:
            err_msg = f"Failed to apply pod ,path[{config_yaml}]"
            LOG.error(err_msg)
        cmd = f"kubectl apply -f {cantian_yaml}"
        res, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
        if not flag:
            err_msg = f"Failed to apply pod ,path[{cantian_yaml}]"
            LOG.error(err_msg)
        if ssh_client is not None:
            ssh_client.close_client()

    def del_pods_with_change_file(self):
        for ip in self.server_info:
            if ip in self.ip_info:
                ssh_client = None
                islocal = True
            else:
                ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
                ssh_client.create_client()
                islocal = False
            for value in self.server_info[ip]:
                cantian_yaml = value.get("dst_cantian_yaml")
                config_yaml = value.get("dst_config_yaml")
                cantian_del = False
                config_del = False
                count = 0
                while True:
                    if not config_del:
                        cmd = f"kubectl delete -f {config_yaml}"
                        res, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
                        if not flag:
                            err_msg = f"Failed to delete pod, path[{config_yaml}]"
                            LOG.error(err_msg)
                        else:
                            config_del = True
                    if not cantian_del:
                        cmd = f"kubectl delete -f {cantian_yaml}"
                        res, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
                        if not flag:
                            err_msg = f"Failed to delete pod, path[{cantian_yaml}]"
                            LOG.error(err_msg)
                        else:
                            cantian_del = True
                    if config_del and cantian_del:
                        break
                    if count == 5:
                        LOG.error(f"ip[{ip}] delete pod err, please check.")
                    count += 1
            if ssh_client is not None:
                ssh_client.close_client()
        LOG.info("delete pods with change config finish")

    def change_config_and_apply_pod(self):
        for ip in self.server_info:
            if ip in self.ip_info:
                ssh_client = None
                islocal = True
            else:
                ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
                ssh_client.create_client()
                islocal = False
            for value in self.server_info[ip]:
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
                            res, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
                            if not flag:
                                err_msg = f"Failed to apply pod ,path[{source_config_yml}]"
                                LOG.error(err_msg)
                            else:
                                config_apply = True
                        if not cantian_apply:
                            cmd = f"kubectl apply -f {source_cantian_yaml}"
                            res, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
                            if not flag:
                                err_msg = f"Failed to apply pod ,path[{source_cantian_yaml}]"
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
                            res, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
                            if not flag:
                                err_msg = f"Failed to apply pod ,path[{dst_config_yaml}]"
                                LOG.error(err_msg)
                            else:
                                config_apply = True
                        if not cantian_flag:
                            ssh_client.upload_file(source_cantian_yaml, dst_cantian_yaml)
                            value["dst_cantian_yaml"] = dst_cantian_yaml
                            config_flag = True
                        if not cantian_apply:
                            cmd = f"kubectl apply -f {dst_cantian_yaml}"
                            res, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal)
                            if not flag:
                                err_msg = f"Failed to apply pod ,path[{dst_cantian_yaml}]"
                                LOG.error(err_msg)
                            else:
                                cantian_apply = True
                    if config_apply and cantian_apply:
                        break
                    if count == 5:
                        LOG.error(f"ip[{ip}] copy file and apply err, please check.")
                        raise Exception("copy_file or apply error")
                    count += 1
            if ssh_client is not None:
                ssh_client.close_client()
        LOG.info("apply pods with change config finish")

    def check_pod_del(self, timeout=300):
        exist_pod = []
        for ip in self.server_info:
            if ip in self.ip_info:
                ssh_client = None
                islocal = True
            else:
                ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
                ssh_client.create_client()
                islocal = False
            for value in self.server_info[ip]:
                LOG.info(f"check IP[{ip}]pods delete stat, please waiting ...")
                namespace = value.get("namespace")
                pod_name_list = value.get("pod_name")
                run_time = 0
                while True:
                    check_pod_list = []
                    if run_time > timeout:
                        err_msg = f" check pod del timeout"
                        LOG.error(err_msg)
                        return False
                    for pod_name in pod_name_list:
                        cmd = f"kubectl get pod -n {namespace} | grep -v NAME | grep {pod_name}"
                        res, flag = self.ssh_exec_cmd(ssh_client, cmd, timeout=10, islocal=islocal, err_log=False)
                        if not flag:
                            check_pod_list.append(pod_name)
                            continue
                        if not res:
                            for data in res:
                                info = data.split()
                                if not info:
                                    continue
                                if (split_pod_name(info[0]) in pod_name_list and
                                        info[1] == "1/1" and info[2] == "Running"):
                                    exist_pod.append(pod_name)
                    if len(check_pod_list) == len(pod_name_list):
                        break
                    time.sleep(10)
                    run_time += 10
            if ssh_client is not None:
                ssh_client.close_client()
        LOG.info("check pod delete finish")
        if exist_pod:
            return False
        else:
            return True

    def check_pod_stat(self, timeout=1200):
        time_over = False
        for ip in self.server_info:
            if ip in self.ip_info:
                ssh_client = None
                islocal = True
            else:
                ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
                ssh_client.create_client()
                islocal = False
            for value in self.server_info[ip]:
                LOG.info(f"check IP[{ip}]pods apply stat, please waiting ...")
                namespace = value.get("namespace")
                pod_name_list = value.get("pod_name")
                run_time = 0
                while True:
                    check_pod_list = []
                    if run_time > timeout:
                        err_msg = f"IP[{ip}], namespace[{namespace}], pod name[{pod_name_list}], Abnormal status"
                        LOG.error(err_msg)
                        time_over = True
                        break
                    data_list = self.get_pod_list(ssh_client, namespace, islocal=islocal)
                    if not data_list:
                        if time_over:
                            LOG.error(f"IP[{ip}], namespace[{namespace}], "
                                      f"pod name[{pod_name_list}], get pod list failed")
                            break
                        time.sleep(5)
                        continue
                    for data in data_list:
                        info = data.split()
                        if not info:
                            continue
                        if split_pod_name(info[0]) in pod_name_list:
                            if info[1] == "1/1" and info[2] == "Running":
                                check_pod_list.append(info[0])
                                continue
                    if len(check_pod_list) == len(pod_name_list):
                        break
                    if time_over:
                        break
                    run_time += 30
                    time.sleep(30)
                if time_over:
                    err_msg = (f"IP[{ip}], namespace[{namespace}], "
                               f"pod name[{pod_name_list}], Abnormal status")
                    LOG.error(err_msg)
                    if ip not in self.abnormal_pod:
                        self.abnormal_pod[ip] = [err_msg]
                    else:
                        self.abnormal_pod[ip].append(err_msg)

            if ssh_client is not None:
                ssh_client.close_client()
        LOG.info("check pod stat finish")

    def check_standby_pod_stat(self):
        if not self.abnormal_pod:
            return True
        warning("Warning:")
        war_msg = ("\tThere are currently multiple nodes with abnormal status.\n"
                   "\tIf you want to continue executing 'fail over', "
                   "it may cause business interruption, data loss, and other phenomena\n"
                   "\tThe following nodes currently have abnormal states:\n")
        warning(war_msg)
        for ip in self.abnormal_pod:
            for msg in self.abnormal_pod[ip]:
                LOG.info(msg)
        return confirm()

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
                page_fs_info = self.storage_opt.query_filesystem_info(value.get("storage_dbstore_page_fs"))
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
                page_fs_info = self.storage_opt.query_filesystem_info(value.get("storage_dbstore_page_fs"))
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

    def query_database_role(self, pod_name, namespace, cmd, ssh_client, timeout=600, islocal=False):
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
            run_time += 20
            if run_time >= timeout:
                LOG.error(f"The current site database role is {ret} but timed out,"
                          f" pod_name[{pod_name}], namespace[{namespace}].")
                return False
            time.sleep(20)

    def check_database_role(self, timeout=1200):
        for ip in self.server_info:
            if ip in self.ip_info:
                ssh_client = None
                islocal = True
            else:
                ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
                ssh_client.create_client()
                islocal = False
            for value in self.server_info[ip]:
                run_user = value.get("run_user")
                check_cmd = CANTIAN_DATABASE_ROLE_CHECK % (run_user, EXEC_SQL)
                namespace = value.get("namespace")
                pod_name_list = value.get("pod_name")
                run_time = 0
                while True:
                    check_pod_list = []
                    data_list = self.get_pod_list(ssh_client, namespace, islocal=islocal)
                    if not data_list:
                        time.sleep(10)
                        continue
                    for data in data_list:
                        info = data.split()
                        if not info:
                            continue
                        if split_pod_name(info[0]) in pod_name_list:
                            if info[2] != "Running":
                                continue
                            if self.query_database_role(info[0].strip(), namespace, check_cmd,
                                                        ssh_client, islocal=islocal):
                                check_pod_list.append(info[0])
                                continue
                            else:
                                err_msg = f"Failed to check database role, server_ip[{ip}] pod_name[{info[0].strip()}]"
                                LOG.error(err_msg)
                    if len(check_pod_list) == len(pod_name_list):
                        break
                    if run_time > timeout:
                        break
                    run_time += 20
                    time.sleep(20)
            if ssh_client is not None:
                ssh_client.close_client()
        LOG.info("check database role finish.")

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
        get_cmd = "sh %s getbase %s" % (DBSTORE_CHECK_VERSION_FILE, cluster_name)
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

    def check_dbstor_init(self, timeout=600):
        check_cmd = "cat /opt/cantian/deploy/deploy.log | grep 'init dbstor success.'"
        for ip in self.server_info:
            if ip in self.ip_info:
                ssh_client = None
                islocal = True
            else:
                ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
                ssh_client.create_client()
                islocal = False
            for index, value in enumerate(self.server_info[ip]):
                namespace = value.get("namespace")
                pod_name_list = value.get("pod_name")
                run_time = 0
                check_flag = False
                while True:
                    data_list = self.get_pod_list(ssh_client, namespace, islocal=islocal)
                    if not data_list:
                        time.sleep(5)
                        continue
                    if run_time > timeout:
                        err_msg = f"IP[{ip}] pod name[{pod_name_list}] Failed to check_dbstor_init, execute timeout"
                        LOG.error(err_msg)
                        break
                    run_time += 5
                    time.sleep(5)
                    pod_name = ""
                    for data in data_list:
                        info = data.split()
                        if not info:
                            continue
                        if split_pod_name(info[0]) in pod_name_list:
                            pod_name = info[0].strip()
                            ret, check_flag = self.pod_exe_cmd(pod_name, namespace, check_cmd, ssh_client, islocal=islocal)
                            if not check_flag:
                                continue
                            break
                    if check_flag:
                        single = self.get_single_write_flag(ssh_client, pod_name, namespace,
                                                            value.get("cluster_name"), islocal=islocal)
                        self.write_single_flag(ip, single, index)
                        break
            if ssh_client is not None:
                ssh_client.close_client()
        LOG.info("check pod init finish.")

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
            self.change_config_and_apply_pod()
            self.check_dbstor_init()
            self.del_pods_with_change_file()
            self.dr_option.change_fs_hyper_metro_domain_second_access(self.domain_id, DomainAccess.ReadOnly)
            try:
                self.dr_option.join_fs_hyper_metro_domain(self.domain_id)
            except Exception as _er:
                LOG.error("Fail to recover hyper metro domain, details: %s", str(_er))
        else:
            self.apply_pods()
            LOG.info("The current hyper_metro_status running_status is not Split.")
            return
        self.query_sync_status()
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
                page_fs_info = self.storage_opt.query_filesystem_info(value.get("storage_dbstore_page_fs"))
                page_pair_info = self.dr_option.query_remote_replication_pair_info(page_fs_info.get("ID"))[0]
                page_role = page_pair_info.get("ISPRIMARY")
                running_status = page_pair_info.get("RUNNINGSTATUS")
                pair_id = page_pair_info.get("ID")
                if page_role == "true":
                    if ip not in self.single_pod:
                        if value["single"] == "1":
                            self.single_pod[ip] = [value]
                            self.del_pod(ip, value["cantian_yaml"])
                    else:
                        if value["single"] == "1":
                            self.single_pod[ip].append(value)
                            self.del_pod(ip, value["cantian_yaml"])
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

    def delete_config_file(self):
        pass

    def ctbackup_purge_log(self):
        for ip in self.server_info:
            if ip in self.ip_info:
                ssh_client = None
                islocal = True
            else:
                ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
                ssh_client.create_client()
                islocal = False
            for value in self.server_info[ip]:
                namespace = value.get("namespace")
                pod_name_list = value.get("pod_name")
                while True:
                    data_list = self.get_pod_list(ssh_client, namespace, islocal=islocal)
                    if not data_list:
                        time.sleep(5)
                        continue
                    flag = False
                    exe_flag = False
                    pod_name = ""
                    for data in data_list:
                        info = data.split()
                        if not info:
                            continue
                        if split_pod_name(info[0]) in pod_name_list:
                            pod_name = info[0].strip()
                            if info[1] == "1/1" and info[2] == "Running":
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
                            err_msg = (f"server ip[{ip}], pod_name[{pod_name}], "
                                       f"Execute command[ctbackup --purge-logs] failed.")
                        LOG.error(err_msg)
                    break
            if ssh_client is not None:
                ssh_client.close_client()
        LOG.info("ctbackup_purge_log finish.")

    def switch_over(self):
        self.del_pods()
        self.check_pod_del()
        self.switch_hyper_metro_domain_role()
        self.switch_replication_pair_role()
        self.apply_pods()
        self.check_pod_stat()

    def fail_over(self):
        self.check_pod_stat()
        if not self.check_standby_pod_stat():
            LOG.info("standby pods stat abnormal, exit.")
            return
        self.do_fail_over()
        self.check_database_role()

    def recover(self):
        self.switch_hyper_metro_domain_role_recover()
        self.switch_replication_pair_role_recover()
        self.apply_pods()
        self.check_pod_stat()
        self.ctbackup_purge_log()

    def delete(self):
        self.del_pods()
        self.check_pod_del()
        LOG.info("delete pods finish")

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
        self.init_k8s_config()
        self.check_flag_stat()
        self.pre_check()
        try:
            getattr(self, self.action)
        except AttributeError as _err:
            err_msg = "The supported types of operations include[fail_over, recover, switch_over, delete]"
            raise Exception(err_msg) from _err
        getattr(self, self.action)()


if __name__ == '__main__':
    try:
        K8sDRContainer().run()
    except Exception as err:
        LOG.error(f"err[{err}], [{traceback.format_exc(limit=-1)}]")
        raise err

