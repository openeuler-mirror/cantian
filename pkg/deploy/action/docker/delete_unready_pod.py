#!/usr/bin/env python3

import os
import sys
import requests
import base64
import re
import urllib3
import json
import stat
import subprocess
from get_config_info import get_value
from datetime import datetime

UNREADY_THRESHOLD_SECONDS = 600
CUR_PATH = os.path.dirname(os.path.realpath(__file__))

# 禁用 InsecureRequestWarning 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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


class KubernetesService:
    def __init__(self, kube_config_path):
        self.kube_config_path = kube_config_path
        self.api_server = "https://kubernetes.default.svc"
        self.cert = None
        self.headers = {"Accept": "application/json"}
        self._load_kube_config()

    def _load_kube_config(self):
        with open(self.kube_config_path, "r") as kube_config_file:
            kube_config_content = kube_config_file.read()
        client_cert_data = re.search(r'client-certificate-data: (.+)', kube_config_content).group(1)
        client_key_data = re.search(r'client-key-data: (.+)', kube_config_content).group(1)
        client_cert_data = base64.b64decode(client_cert_data)
        client_key_data = base64.b64decode(client_key_data)
        with open("/tmp/client-cert.pem", "wb") as cert_file:
            cert_file.write(client_cert_data)
        with open("/tmp/client-key.pem", "wb") as key_file:
            key_file.write(client_key_data)
        self.cert = ("/tmp/client-cert.pem", "/tmp/client-key.pem")

    def _get(self, path):
        url = f"{self.api_server}{path}"
        response = requests.get(url, headers=self.headers, cert=self.cert, verify=False)
        response.raise_for_status()
        return response.json()

    def get_service_by_pod_name(self, pod_name):
        services_data = self._get("/api/v1/services")
        pods_data = self._get("/api/v1/pods")

        for service in services_data.get("items", []):
            service_selector = service["spec"].get("selector", {})
            if not service_selector:
                continue

            matching_pods = []
            for pod in pods_data.get("items", []):
                pod_labels = pod["metadata"].get("labels", {})
                if all(item in pod_labels.items() for item in service_selector.items()):
                    matching_pods.append(pod)

            for pod in matching_pods:
                if pod_name in pod.get("metadata", {}).get("name", ""):
                    return service["metadata"]["name"]

        return None

    def get_pod_info_by_service(self, service_name):
        services_data = self._get("/api/v1/services")
        pods_data = self._get("/api/v1/pods")
        target_service = None

        for service in services_data.get("items", []):
            if service["metadata"]["name"] == service_name:
                target_service = service
                break

        if not target_service:
            return []

        service_selector = target_service["spec"].get("selector", {})
        matching_pods = []
        for pod in pods_data.get("items", []):
            pod_labels = pod["metadata"].get("labels", {})
            if all(item in pod_labels.items() for item in service_selector.items()):
                matching_pods.append(pod)

        pod_info = []
        for pod in matching_pods:
            pod_name = pod.get("metadata", {}).get("name")
            pod_ip = pod.get("status", {}).get("podIP")
            containers = pod.get("spec", {}).get("containers", [])
            for container in containers:
                ports = container.get("ports", [])
                for port in ports:
                    container_port = port.get("containerPort")
                    if pod_name and pod_ip and container_port:
                        pod_info.append({
                            "pod_name": pod_name,
                            "pod_ip": pod_ip,
                            "container_port": container_port
                        })

        return pod_info

    def get_pods(self):
        return self._get("/api/v1/pods")

    def delete_pod(self, name, namespace):
        url = f"{self.api_server}/api/v1/namespaces/{namespace}/pods/{name}"
        response = requests.delete(url, headers=self.headers, cert=self.cert, verify=False)
        response.raise_for_status()
        return response.json()

    def get_pod_by_name(self, pod_name):
        pods_data = self.get_pods()
        for pod in pods_data.get("items", []):
            if pod_name == pod["metadata"]["name"]:
                return pod
        return None


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
            with os.fdopen(os.open(healthy_file,flags, modes), 'w') as fwrite:
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