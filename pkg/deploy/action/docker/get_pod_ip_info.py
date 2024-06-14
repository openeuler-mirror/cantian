#!/usr/bin/env python3
import os
import sys
import requests
import base64
import re
import urllib3

# 禁用InsecureRequestWarning警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class KubernetesService:
    def __init__(self, kube_config_path):
        self.kube_config_path = kube_config_path
        self.api_server = "https://kubernetes.default.svc"
        self.cert = None
        self.headers = {
            "Accept": "application/json"
        }
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
            pod_labels = pod["metadata"]["labels"]
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

    def print_pod_info(self, pod_info, node_number=None):
        for i, info in enumerate(pod_info):
            if node_number is None:
                print(f"{info['pod_name']}: {info['pod_ip']}:{info['container_port']}")
            elif node_number == i:
                print(f"{info['pod_ip']}:{info['container_port']}")
                break


if __name__ == "__main__":
    service_name = os.getenv("SERVICE_NAME")
    if not service_name:
        exit(1)
    node_number = None
    if len(sys.argv) > 1:
        try:
            node_number = int(sys.argv[1])
        except ValueError:
            exit(1)

    kube_config_path = os.path.expanduser("~/.kube/config")
    k8s_service = KubernetesService(kube_config_path)
    pod_info = k8s_service.get_pod_info_by_service(service_name)
    k8s_service.print_pod_info(pod_info, node_number)