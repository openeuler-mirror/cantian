#!/usr/bin/env python3

import os
import json
import stat
import subprocess
from datetime import datetime

# 导入 KubernetesService 类
from docker_common.kubernetes_service import KubernetesService
from get_config_info import get_value

UNREADY_THRESHOLD_SECONDS = 600
CUR_PATH = os.path.dirname(os.path.realpath(__file__))

def _exec_popen(cmd, values=None):
    """
    subprocess.Popen in python2 and 3.
    :param cmd: commands need to execute
    :return: status code, standard output, error output
    """
    if not values:
        values = []
    bash_cmd = ["bash"]
    pobj = subprocess.Popen(bash_cmd, shell=False, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pobj.stdin.write(cmd.encode())
    pobj.stdin.write(os.linesep.encode())
    for value in values:
        pobj.stdin.write(value.encode())
        pobj.stdin.write(os.linesep.encode())
    try:
        stdout, stderr = pobj.communicate(timeout=1800)
    except subprocess.TimeoutExpired as err_cmd:
        pobj.kill()
        return -1, "Time Out.", str(err_cmd)
    stdout = stdout.decode()
    stderr = stderr.decode()
    if stdout[-1:] == os.linesep:
        stdout = stdout[:-1]
    if stderr[-1:] == os.linesep:
        stderr = stderr[:-1]

    return pobj.returncode, stdout, stderr


def get_pod_name_from_info(pod_info, pod_name):
    if not pod_info:
        return None

    for entry in pod_info:
        pod_name_full = entry.get("pod_name")
        if pod_name_full:
            if pod_name in pod_name_full:
                return pod_name_full

    return None

def backup_log():
    """备份日志函数，unready的pod会被重复检测，只有首次打印备份日志，后续直接返回"""
    healthy_file = '/opt/cantian/healthy'
    if os.path.exists(healthy_file):
        # 读文件内参数
        with open(healthy_file, 'r') as fread:
            data = fread.read()
        try:
            healthy_dict = json.loads(data)
        except json.decoder.JSONDecodeError as e:
            healthy_dict = {'delete_unready_pod': 0}
        if not healthy_dict['delete_unready_pod']:
            healthy_dict['delete_unready_pod'] = 1
            flags = os.O_CREAT | os.O_RDWR
            modes = stat.S_IWUSR | stat.S_IRUSR
            with os.fdopen(os.open(healthy_file, flags, modes), 'w') as fwrite:
                json.dump(healthy_dict, fwrite)
        else:
            return
    else:
        # healthy文件不存在说明pod状态异常，会有其他处理，直接返回
        return

    cluster_name = get_value('cluster_name')
    cluster_id = get_value('cluster_id')
    node_id = get_value('node_id')
    deploy_user = get_value('deploy_user')
    storage_metadata_fs = get_value('storage_metadata_fs')
    cmd = "sh %s/log_backup.sh %s %s %s %s %s" % (CUR_PATH, cluster_name, cluster_id, node_id, deploy_user, storage_metadata_fs)
    ret_code, _, stderr = _exec_popen(cmd)
    if ret_code:
        raise Exception("failed to backup log. output:%s" % str(stderr))

def monitor_pods(k8s_service, pod_name):
    pod = k8s_service.get_pod_by_name(pod_name)
    if not pod:
        print(f"Pod {pod_name} not found.")
        return

    pod_conditions = pod.get("status", {}).get("conditions", [])
    current_time = datetime.utcnow()

    for condition in pod_conditions:
        if condition["type"] == "Ready" and condition["status"] != "True":
            last_transition_time = condition.get("lastTransitionTime")
            if last_transition_time:
                last_transition_time = datetime.strptime(last_transition_time, "%Y-%m-%dT%H:%M:%SZ")
                unready_duration = current_time - last_transition_time
                print(f"Pod {pod_name} has been unready for more than {unready_duration.total_seconds()} seconds.")
                if unready_duration.total_seconds() > UNREADY_THRESHOLD_SECONDS:
                    print(f"Pod {pod_name} has been unready for more than {UNREADY_THRESHOLD_SECONDS} seconds. Deleting...")
                    backup_log()
                    k8s_service.delete_pod(name=pod_name, namespace=pod["metadata"]["namespace"])
                    return

if __name__ == "__main__":
    pod_name = os.getenv("HOSTNAME")
    if not pod_name:
        exit(1)

    kube_config_path = os.path.expanduser("~/.kube/config")
    k8s_service = KubernetesService(kube_config_path)
    service_name = k8s_service.get_service_by_pod_name(pod_name)

    if service_name:
        pod_info = k8s_service.get_pod_info_by_service(service_name)
        pod_name_full = get_pod_name_from_info(pod_info, pod_name)
        monitor_pods(k8s_service, pod_name_full)
    else:
        print(f"Service not found for pod: {pod_name}")
        exit(1)