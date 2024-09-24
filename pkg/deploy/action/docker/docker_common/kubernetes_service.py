#!/usr/bin/env python3

import os
import re
import stat
import base64

import requests
import urllib3

# 禁用 InsecureRequestWarning 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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

        cert_file_path = "/tmp/client-cert.pem"
        key_file_path = "/tmp/client-key.pem"

        cert_fd = os.open(cert_file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(cert_fd, "wb") as cert_file:
            cert_file.write(client_cert_data)

        key_fd = os.open(key_file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(key_fd, "wb") as key_file:
            key_file.write(client_key_data)

        os.chmod(cert_file_path, 0o666)
        os.chmod(key_file_path, 0o666)

        self.cert = (cert_file_path, key_file_path)

    def _get(self, path, timeout=5):
        url = f"{self.api_server}{path}"
        response = requests.get(url, headers=self.headers, cert=self.cert, verify=False, timeout=timeout)
        response.raise_for_status()
        return response.json()

    def get_service_by_pod_name(self, pod_name, timeout=5):
        services_data = self._get("/api/v1/services", timeout=timeout)
        pods_data = self._get("/api/v1/pods", timeout=timeout)

        try:
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
        except Exception as e:
            print(f"Error getting service by pod name: {e}")
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

    def get_all_pod_info(self, timeout=5):
        services_data = self._get("/api/v1/services", timeout=timeout)
        pods_data = self._get("/api/v1/pods", timeout=timeout)

        all_pod_info = []

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
                pod_name_all = pod.get("metadata", {}).get("name")
                pod_ip = pod.get("status", {}).get("podIP")
                containers = pod.get("spec", {}).get("containers", [])
                for container in containers:
                    ports = container.get("ports", [])
                    for port in ports:
                        container_port = port.get("containerPort")
                        if pod_name_all and pod_ip and container_port:
                            all_pod_info.append({
                                "service_name": service["metadata"]["name"],
                                "pod_name": pod_name_all,
                                "pod_ip": pod_ip,
                                "container_port": container_port
                            })

        return all_pod_info

    def get_pods(self):
        return self._get("/api/v1/pods")

    def delete_pod(self, name, namespace, timeout=5):
        url = f"{self.api_server}/api/v1/namespaces/{namespace}/pods/{name}"
        response = requests.delete(url, headers=self.headers, cert=self.cert, verify=False, timeout=timeout)
        response.raise_for_status()
        return response.json()

    def get_pod_by_name(self, pod_name):
        pods_data = self.get_pods()

        try:
            for pod in pods_data.get("items", []):
                if pod_name == pod["metadata"]["name"]:
                    return pod
        except Exception as e:
            print(f"Error getting pod by name: {e}")
            return None
