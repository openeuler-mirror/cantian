import subprocess
import time
import requests
import sys
import os
import pwd
import grp

sys.path.append("/ctdb/cantian_install/cantian_connector/action")

from om_log import LOGGER as LOG
from docker_common.kubernetes_service import KubernetesService
from get_config_info import get_value


K8S_STATE_FILE="/opt/cantian/cms/cfg/k8s_hb"
# cms节点间心跳超时时间为5s，投票持续4s,总共等待9s
# 希望9s内有两次查询机会，设置间隔时间为3s
INTERVAL_SECONDS = 3


def get_u_g_id():
    deploy_user = get_value("deploy_user")
    deploy_group = get_value("deploy_group")
    deploy_user_info = pwd.getpwnam(deploy_user)
    deploy_group_info = grp.getgrnam(deploy_group)
    u_id = deploy_user_info.pw_uid
    g_id = deploy_group_info.gr_gid
    return u_id, g_id

def ping_kubernetes_service():
    try:
        subprocess.check_output(["timeout", "1", "ping", "-c", "1", "kubernetes.default.svc"], stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        LOG.error("Ping kubernetes service failed")
        return False

def kubernetes_service():
    kube_config_path = os.path.expanduser("~/.kube/config")
    k8s_service = KubernetesService(kube_config_path)
    try:
        if not ping_kubernetes_service():
            return False
        url = f"{k8s_service.api_server}/api/v1/services"
        requests.get(url, headers=k8s_service.headers, cert=k8s_service.cert, verify=False, timeout=2)
        return True
    except Exception as e:
        LOG.error(e)
        return False

def main():
    u_id, g_id = get_u_g_id()
    while True:
        start_time = time.time()
        is_connected = kubernetes_service()
        if is_connected:
            try:
                with open(K8S_STATE_FILE, "w"):
                    pass
                os.chown(K8S_STATE_FILE, u_id, g_id)
            except Exception as e:
                LOG.error(f"Failed to create file: {e}")
        elapsed_time = time.time() - start_time
        if elapsed_time < INTERVAL_SECONDS:
            time.sleep(INTERVAL_SECONDS - elapsed_time)

if __name__ == "__main__":
    main()