import copy
import getpass
import json
import os
import signal
import subprocess
import sys
import time
import logging

import yaml


CURRENT_PATH = os.path.dirname(os.path.abspath(__file__)) # cantian/action/storage_operate
sys.path.append(os.path.join(CURRENT_PATH, "..", "utils", "client"))
sys.path.append(os.path.join(CURRENT_PATH, "..", "utils", "config"))
sys.path.append(os.path.join(CURRENT_PATH, ".."))
sys.path.append(os.path.join(CURRENT_PATH, "..", "logic"))
sys.path.append(os.path.join(CURRENT_PATH, "dr_deploy_operate"))
from ssh_client import SshClient
from common_func import get_status
from storage_operate import StorageInf
from dr_deploy_common import DRDeployCommon
from rest_constant import (DataIntegrityStatus, MetroDomainRunningStatus, ConfigRole, HealthStatus,
                           DomainAccess, ReplicationRunningStatus, VstorePairRunningStatus,
                           FilesystemPairRunningStatus)


EXEC_SQL = os.path.join(CURRENT_PATH, "../cantian_common/exec_sql.py")
CANTIAN_DATABASE_ROLE_CHECK = ('echo -e "select DATABASE_ROLE from DV_LRPL_DETAIL;" | '
                               'su -s /bin/bash - {run_user} -c \'source ~/.bashrc && '
                               'export LD_LIBRARY_PATH=/opt/cantian/dbstor/lib:${LD_LIBRARY_PATH} && '
                               'python3 -B {exe_sql}\'')

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


def get_all_yaml_config(file_path):
    with open(file_path, 'r') as f:
        return yaml.safe_load_all(f)


def get_json_config(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)


def split_pod_name(pod_name):
    parts = pod_name.split('-')
    if len(parts) > 3:
        first_part = '-'.join(parts[:len(parts) - 2])
        return first_part
    else:
        msg = f"split pod name failed: pod_name[{pod_name}]"
        print(msg)
        raise Exception(msg)


def warning(warn_msg):
    print(f"\033[91m{warn_msg}\033[0m")


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
        self.server_key_file = "/root/.ssh/id_rsa.pub"
        self.dr_option = None
        self.ulog_pair_list = None
        self.dr_info_map = None
        self.ssh_cmd_end = " ; echo last_cmd=$?"
        self.vstore_pair_list = None
        self.server_value_map = None
        self.single_file_path = os.path.join(CURRENT_PATH, "single_file.json")
        self.single_pod = None
        self.check_flag = True

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
                         "\tAfter this operation,\n"
                         "\tplease ensure that the original active cluster is not accessed for write operations,\n"
                         "\totherwise it will cause data inconsistency.\n",
            "delete": "\tDeletion operation will delete the all Cantian nodes under hyper metro domain.\n"
        }
        if self.action in warning_msgs:
            warning("Warning:")
            warning(warning_msgs[self.action])
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

    def init_k8s_config(self):
        if not os.path.exists(self.k8s_config_path):
            err_msg = f"k8s_config_path does not exist, path: {self.k8s_config_path}"
            LOG.error(err_msg)
            self.check_flag = False
            return
        config = get_json_config(self.k8s_config_path)
        err_msg = None
        if "domain_name" in config:
            self.domain_name = config["domain_name"]
            if not self.domain_name:
                err_msg = f"Domain name is empty, config path: {self.k8s_config_path}"
                LOG.error(err_msg)
                self.check_flag = False
        if "dm_ip" in config:
            self.dm_ip = config["dm_ip"]
            if not self.dm_ip:
                err_msg = f"Domain ip is empty, config path: {self.k8s_config_path}"
                LOG.error(err_msg)
                self.check_flag = False
        if "dm_user" in config:
            self.dm_user = config["dm_user"]
            if not self.dm_user:
                err_msg = f"Domain user is empty, config path: {self.k8s_config_path}"
                LOG.error(err_msg)
                self.check_flag = False
        if "server" in config:
            self.server_info = config["server"]
            if not self.server_info:
                err_msg = f"server info is empty, config path: {self.k8s_config_path}"
                LOG.error(err_msg)
                self.check_flag = False

    def check_k8s_config(self, ip, path, server_path):
        cmd = f"ls {path}"
        ret_code, ret, stderr = exec_popen(cmd, 20)
        if ret_code:
            err_msg = f"Failed to ls {path}"
            LOG.error(err_msg)
            return False
        if ip not in self.server_value_map:
            self.server_value_map[ip] = []
        file_list = ret.strip()
        file_count = 0
        data = {
            "server_path": server_path,
            "file_path": path
        }
        for name in file_list:
            if name.endswith(".yaml") and "configMap" in name:
                data["configMap"] = name.strip()
                configs = get_all_yaml_config(os.path.join(path, name.strip()))
                for config in configs:
                    if config.get("kind") == "ConfigMap":
                        deploy_param = json.loads(config.get("data").get("deploy_param.json"))
                        domain_name = deploy_param.get("dr_deploy").get("domain_name")
                        if domain_name != self.domain_name:
                            err_msg = f"Domain name is not match, server ip[{ip}], config path[{path}]"
                            LOG.error(err_msg)
                            return False
                        data["storage_dbstore_fs"] = deploy_param.get("storage_dbstore_fs")
                        data["run_user"] = deploy_param.get("deploy_user").strip().split(":")[0]
                        data["cluster_name"] = deploy_param.get("cluster_name").strip()
                        data["storage_dbstore_page_fs"] = deploy_param.get("storage_dbstore_page_fs")
                        data["dbstore_fs_vstore_id"] = deploy_param.get("dbstore_fs_vstore_id")
                        file_count += 1
                        break
            if name.endswith(".yaml") and "cantian" in name:
                data["cantian"] = name.strip()
                configs = get_all_yaml_config(os.path.join(path, name.strip()))
                for config in configs:
                    if config.get("kind") == "Deployment":
                        if "pod_name" in data:
                            data["pod_name"].append(config.get("metadata").get("name"))
                            continue
                        data["pod_name"] = [config.get("metadata").get("name")]
                        data["namespace"] = config.get("metadata").get("namespace")
                        continue
                file_count += 1
        if file_count != 2:
            err_msg = (f"Failed to analysis server ip[{ip}], path[{path}],Expected to be two configuration files, "
                       f"but actually file_count[{file_count}]")
            LOG.error(err_msg)
            return False
        self.server_value_map[ip].append(data)
        return True

    def pre_check_link(self):
        server_path = os.path.join(CURRENT_PATH, "server")
        if not os.path.exists(server_path):
            os.makedirs(server_path)
        del_cmd = f"rm -rf {server_path}/*"
        ret_code, _, stderr = exec_popen(del_cmd, 20)
        if ret_code:
            err_msg = f"Failed to remove {server_path}/*, err[{stderr}]"
            LOG.error(err_msg)
            raise Exception(err_msg)
        for ip in self.server_info:
            ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
            ssh_client.create_client()
            for index, path in enumerate(self.server_info[ip]):
                dir_path = os.path.join(server_path, str(index))
                if not os.path.exists(dir_path):
                    os.makedirs(dir_path)
                cmd = f"ls {path}"
                res, flag = self.ssh_exec_cmd(ssh_client, cmd, "]#", timeout=20)
                if not flag:
                    LOG.error(f"Failed to ls {path}, maybe not exist")
                    self.check_flag = False
                    continue
                cmd = f"scp {self.server_user}@{ip}:{path}/* {dir_path}"
                res, flag = self.ssh_exec_cmd(ssh_client, cmd, "]#", timeout=60)
                if not flag:
                    LOG.error(f"Failed to copy {path} to {dir_path}")
                    self.check_flag = False
                    continue
                if not self.check_k8s_config(ip, dir_path, path):
                    self.check_flag = False
            ssh_client.close_client()
        LOG.info("pre_check_link successful")

    def init_dr_option(self):
        dm_passwd = getpass.getpass("Please input device manager login passwd: ")
        storage_opt = StorageInf((self.dm_ip, self.dm_user, dm_passwd))
        storage_opt.login()
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
            self.check_flag_stat()
            return
        ulog_pair_info_list = []
        vstore_pair_list = self.dr_option.query_hyper_metro_vstore_pair_info()
        for vstore_pair_info in vstore_pair_list:
            if vstore_pair_info.get("DOMAINID") == self.domain_id:
                self.vstore_pair_list.append(vstore_pair_info)
                ulog_pair_info_list += self.dr_option.query_ulog_filesystem_info_list(
                    vstore_pair_info.get("LOCALVSTOREID"))
        self.ulog_pair_list = ulog_pair_info_list

    def match_config_and_pair_with_fs_name(self, ip, ulog_pair_info):
        log_fs_name = ulog_pair_info.get("LOCALOBJNAME").strip()
        vstore_id = ulog_pair_info.get("vstoreId").strip()
        for value in self.server_value_map[ip]:
            if value.get("storage_dbstore_fs") == log_fs_name and value.get("dbstore_fs_vstore_id") == vstore_id:
                value["log_fs_id"] = ulog_pair_info.get("LOCALOBJID")
                value["log_pair_id"] = ulog_pair_info.get("ID")
                value["vstore_pair_id"] = ulog_pair_info.get("vstorePairId")
                return value.get("server_path")
        return ""

    def check_and_match_ulog_page_info(self):
        filter_server_info = {}
        for ulog_pair_info in self.ulog_pair_list:
            for ip in self.server_info:
                for path in self.server_info[ip]:
                    if ip in filter_server_info and path in filter_server_info[ip]:
                        continue
                    file_path = self.match_config_and_pair_with_fs_name(ip, ulog_pair_info)
                    if file_path:
                        if ip in filter_server_info:
                            filter_server_info[ip].append(file_path)
                        else:
                            filter_server_info[ip] = [file_path]
                    break

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
        self.pre_check_link()
        self.init_dr_option()
        self.get_ulog_pair_info_list()
        self.check_and_match_ulog_page_info()
        if self.action == "switch_over":
            self.check_pod_stat()
            self.check_hyper_metro_stat()
        self.check_flag_stat()
        LOG.info("success to pre check.")

    def ssh_exec_cmd(self, ssh_client, cmd, expect, timeout=5):
        try:
            cmd = f"{cmd}{self.ssh_cmd_end}"
            res = ssh_client.execute_cmd(cmd, expect=expect, timeout=timeout)
            res = res.split("\n")
            if res[-1].strip().split("=")[-1] == 0:
                return res[:-1], True
            return res[:-1], False
        except Exception as e:
            err_msg = f"Failed to execute ssh command {cmd}. err[{e}]"
            ssh_client.close_client()
            raise Exception(err_msg)

    def get_pod_list(self, ssh_client, namespace):
        cmd = f"kubectl get pod -n {namespace} | grep -v NAME"
        res, flag = self.ssh_exec_cmd(ssh_client, cmd, "]#", timeout=10)
        if not flag:
            err_msg = f"Failed to check pod stat, server ip[{ssh_client.ip}]."
            LOG.error(err_msg)
            return None
        return res.split("\n")

    def del_pods(self):
        for ip in self.server_info:
            ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
            ssh_client.create_client()
            for path in self.server_info[ip]:
                cmd = f"kubectl delete -f {path}"
                res, flag = self.ssh_exec_cmd(ssh_client, cmd, "]#", timeout=10)
                if not flag:
                    err_msg = f"Failed to delete pod ,path[{path}]"
                    LOG.error(err_msg)
            ssh_client.close_client()

    def del_pod(self, ip, server_path):
        ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
        ssh_client.create_client()
        cmd = f"kubectl delete -f {server_path}"
        res, flag = self.ssh_exec_cmd(ssh_client, cmd, "]#", timeout=10)
        if not flag:
            err_msg = f"Failed to delete pod ,path[{server_path}]"
            LOG.error(err_msg)
        ssh_client.close_client()

    def apply_pods(self):
        for ip in self.server_info:
            ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
            ssh_client.create_client()
            for path in self.server_info[ip]:
                cmd = f"kubectl apply -f {path}"
                res, flag = self.ssh_exec_cmd(ssh_client, cmd, "]#", timeout=10)
                if not flag:
                    err_msg = f"Failed to apply pod ,path[{path}]"
                    LOG.error(err_msg)
            ssh_client.close_client()

    def apply_pod(self, ip, server_path):
        ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
        ssh_client.create_client()
        cmd = f"kubectl apply -f {server_path}"
        res, flag = self.ssh_exec_cmd(ssh_client, cmd, "]#", timeout=10)
        if not flag:
            err_msg = f"Failed to apply pod ,path[{server_path}]"
            LOG.error(err_msg)
        ssh_client.close_client()

    def check_pod_stat(self, timeout=1200):
        for ip in self.server_value_map:
            ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
            ssh_client.create_client()
            for value in self.server_value_map[ip]:
                namespace = value.get("namespace")
                pod_name_list = value.get("pod_name")
                run_time = 0
                while True:
                    check_pod_list = []
                    data_list = self.get_pod_list(ssh_client, namespace)
                    if not data_list:
                        time.sleep(60)
                        continue
                    for data in data_list:
                        info = data.strip()
                        if split_pod_name(info[0]) in pod_name_list:
                            if info[1] == "1/1" and info[2] == "Running":
                                check_pod_list.append(info[0])
                                continue
                    if len(check_pod_list) == len(pod_name_list):
                        break
                    if run_time > timeout:
                        break
                    run_time += 60
                    time.sleep(60)
            ssh_client.close_client()

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

    def check_hyper_metro_filesystem_pair_stat(self):
        for ulog_pair_info in self.ulog_pair_list:
            run_stat = ulog_pair_info.get("RUNNINGSTATUS")
            if run_stat == FilesystemPairRunningStatus.Normal:
                err_msg = "ulog pair is not Abnormal, please check, pair_id[%s]." % ulog_pair_info.get("ID")
                LOG.error(err_msg)
                self.check_flag = False

    def check_replication_filesystem_pair_stat(self):
        for ip in self.server_value_map:
            for value in self.server_value_map[ip]:
                page_fs_info = self.dr_option.query_filesystem_info(value.get("storage_dbstore_page_fs"))
                page_pair_info = self.dr_option.query_remote_replication_pair_info(page_fs_info.get("ID"))
                page_pair_id = page_pair_info.get("ID")
                value["page_pair_id"] = page_pair_id
                run_stat = page_pair_info.get("RUNNINGSTATUS")
                if run_stat == ReplicationRunningStatus.Normal:
                    err_msg = "page pair is not Abnormal, please check, pair_id[%s]." % page_pair_id
                    LOG.error(err_msg)
                    self.check_flag = False

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
            return True
        LOG.info("Success to recover hyper metro domain.")
        return False

    def switch_replication_pair_role(self):
        for ip in self.server_value_map:
            for value in self.server_value_map[ip]:
                page_fs_info = self.dr_option.query_filesystem_info(value.get("storage_dbstore_page_fs"))
                page_pair_info = self.dr_option.query_remote_replication_pair_info(page_fs_info.get("ID"))
                page_role = page_pair_info.get("ISPRIMARY")
                pair_id = page_pair_info.get("ID")
                if page_role == "true":
                    self.dr_option.swap_role_replication_pair(pair_id)
                else:
                    LOG.info("Page fs rep pair is already standby site, pair_id[%s].", pair_id)

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

    def pod_exe_cmd(self, pod_name, namespace, cmd, ssh_client, timeout=30):
        exe_cmd = f"kubectl exec -it {pod_name} -n {namespace} -- {cmd}"
        return self.ssh_exec_cmd(ssh_client, exe_cmd, "]#", timeout=timeout)

    def query_database_role(self, pod_name, namespace, cmd, ssh_client, timeout=600):
        run_time = 0
        while True:
            stdout, flag = self.pod_exe_cmd(pod_name, namespace, cmd, ssh_client)
            if not flag:
                err_msg = "Query database role failed, error:%s." % stdout
                LOG.error(err_msg)
                raise Exception(err_msg)
            if "PRIMARY" in stdout:
                LOG.info("The current site database role is primary.")
                return True
            LOG.info("The current site database role is {}".format(stdout))
            run_time += 20
            if run_time >= timeout:
                LOG.error(f"The current site database role is {stdout} but timed out, pod_name[{pod_name}], namespace[{namespace}].")
                return False
            time.sleep(20)

    def check_database_role(self, timeout=1200):
        for ip in self.server_value_map:
            ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
            ssh_client.create_client()
            for value in self.server_value_map[ip]:
                run_user = value.get("run_user")
                check_cmd = CANTIAN_DATABASE_ROLE_CHECK.format(run_user=run_user, exe_sql=EXEC_SQL)
                namespace = value.get("namespace")
                pod_name_list = value.get("pod_name")
                run_time = 0
                while True:
                    check_pod_list = []
                    data_list = self.get_pod_list(ssh_client, namespace)
                    if not data_list:
                        time.sleep(10)
                        continue
                    for data in data_list:
                        info = data.strip()
                        if split_pod_name(info[0]) in pod_name_list:
                            check_pod_list.append(info[0])
                            if self.query_database_role(info[0].strip(), namespace, check_cmd, ssh_client):
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
            ssh_client.close_client()

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

    def get_single_write_flag(self, ssh_client, pod_name, namespace, cluster_name):
        cmd = "sh %s getbase %s" % (DBSTORE_CHECK_VERSION_FILE, cluster_name)
        ret, flag = self.ssh_exec_cmd(ssh_client, cmd, "]#", timeout=30)
        if not flag:
            err_msg = f"server ip[{ssh_client.ip}], pod_name[{pod_name}] Execute command[{cmd}] failed."
            LOG.error(err_msg)
        else:
            msg = f"server ip[{ssh_client.ip}], pod_name[{pod_name}] Execute command[{cmd}] success."
            LOG.info(msg)
        return ret

    def write_single_flag(self, ip, single, server_path):
        if os.path.exists(self.single_file_path):
            config = get_json_config(self.single_file_path)
        else:
            config = copy.deepcopy(self.server_value_map)
        for value in config[ip]:
            if value.get("server_path") == server_path:
                value["single"] = str(single)
                break
        with open(self.single_file_path, "w") as f:
            f.truncate()
            f.write(json.dumps(config))

    def check_dbstor_init(self, timeout=600):
        check_cmd = "cat /opt/cantian/deploy/deploy.log | grep 'init dbstor success.' | wc -l"
        for ip in self.server_value_map:
            ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
            ssh_client.create_client()
            for value in self.server_value_map[ip]:
                namespace = value.get("namespace")
                pod_name_list = value.get("pod_name")
                run_time = 0
                while True:
                    data_list = self.get_pod_list(ssh_client, namespace)
                    if not data_list:
                        time.sleep(5)
                        continue
                    ret = 0
                    pod_name = ""
                    for data in data_list:
                        info = data.strip()
                        if split_pod_name(info[0]) in pod_name_list:
                            pod_name = info[0].strip()
                            ret, flag = self.pod_exe_cmd(pod_name, namespace, check_cmd, ssh_client)
                            if not flag:
                                continue
                            break
                    if int(ret) >= 1:
                        single = self.get_single_write_flag(ssh_client, pod_name, namespace, value.get("cluster_name"))
                        self.write_single_flag(ip, single, value.get("server_path"))
                        break
                    if run_time > timeout:
                        err_msg = "Failed to check_dbstor_init, execute timeout"
                        LOG.error(err_msg)
                        return
                    run_time += 5
                    time.sleep(5)
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
            self.apply_pods()
            self.check_dbstor_init()
            self.dr_option.change_fs_hyper_metro_domain_second_access(self.domain_id, DomainAccess.ReadOnly)
            try:
                self.dr_option.join_fs_hyper_metro_domain(self.domain_id)
            except Exception as _er:
                LOG.error("Fail to recover hyper metro domain, details: %s", str(_er))
        else:
            self.apply_pods()
            LOG.info("The current hyper_metro_status running_status not is Split.")
            return
        self.query_sync_status()

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
        LOG.info(f"Execute replication steps. pair id[{pair_id}] Singel_write: {server_info.get("single")}")
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
                page_fs_info = self.dr_option.query_filesystem_info(value.get("storage_dbstore_page_fs"))
                page_pair_info = self.dr_option.query_remote_replication_pair_info(page_fs_info.get("ID"))
                page_role = page_pair_info.get("ISPRIMARY")
                running_status = page_pair_info.get("RUNNINGSTATUS")
                pair_id = page_pair_info.get("ID")
                if ip not in self.single_pod:
                    if value["single"] == "1":
                        self.single_pod[ip] = [value]
                        self.del_pod(ip, value["server_path"])
                else:
                    if value["single"] == "1":
                        self.single_pod[ip].append(value)
                        self.del_pod(ip, value["server_path"])
                if page_role == "true":
                    self.dr_option.swap_role_replication_pair(pair_id)
                    self.dr_option.remote_replication_filesystem_pair_set_secondary_write_lock(pair_id)
                    self.execute_replication_steps(running_status, value, pair_id=pair_id)
                else:
                    LOG.info("Page fs rep pair is already standby site.")
                    if running_status == ReplicationRunningStatus.Split:
                        self.apply_pod(ip, value["server_path"])
                        continue
                    elif running_status == ReplicationRunningStatus.Normal or \
                            running_status == ReplicationRunningStatus.Synchronizing:
                        self.wait_remote_replication_pair_sync(pair_id)
                        self.dr_option.split_remote_replication_filesystem_pair(pair_id)
                        self.apply_pod(ip, value["server_path"])
                    else:
                        err_msg = f"Remote replication filesystem pair is not in normal status, pair_id[{pair_id}]."
                        LOG.error(err_msg)
                        err_flag = True
        if err_flag:
            raise Exception("Remote replication filesystem pair is not in normal status.")

    def ctbackup_purge_log(self):
        cmd = "source ~/.bashrc && su -s /bin/bash - %s -c \"ctbackup --purge-logs\""
        for ip in self.server_value_map:
            ssh_client = SshClient(ip, self.server_user, private_key_file=self.server_key_file)
            ssh_client.create_client()
            for value in self.server_value_map[ip]:
                namespace = value.get("namespace")
                pod_name_list = value.get("pod_name")
                while True:
                    data_list = self.get_pod_list(ssh_client, namespace)
                    if not data_list:
                        time.sleep(5)
                        continue
                    flag = False
                    exe_flag = False
                    pod_name = ""
                    for data in data_list:
                        info = data.strip()
                        if split_pod_name(info[0]) in pod_name_list:
                            pod_name = info[0].strip()
                            if info[1] == "1/1" and info[2] == "Running":
                                exe_flag = True
                                ret, flag = self.pod_exe_cmd(pod_name, namespace, cmd, ssh_client, timeout=600)
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

    def switch_over(self):
        self.del_pods()
        self.switch_hyper_metro_domain_role()
        self.switch_replication_pair_role()
        self.apply_pods()
        self.check_pod_stat()

    def fail_over(self):
        self.check_pod_stat()
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

    def check_flag_stat(self):
        if not self.check_flag:
            raise Exception("Program pre check failed")

    def run(self):
        if len(sys.argv) < 2:
            err_msg = "The number of parameters must not be less than 2"
            LOG.error(err_msg)
            raise Exception(err_msg)
        self.action = sys.argv[1]
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
        LOG.error(str(err))

