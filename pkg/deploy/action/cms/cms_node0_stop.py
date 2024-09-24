#!/usr/bin/env python3

import os
import sys
import subprocess
import platform
from get_config_info import get_value
from log import LOGGER


def _exec_popen(cmd, values=None):
    if not values:
        values = []
    bash_cmd = ["bash"]
    pobj = subprocess.Popen(bash_cmd, shell=False, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    py_version = platform.python_version()
    if py_version[0] == "3":
        pobj.stdin.write(cmd.encode())
        pobj.stdin.write(os.linesep.encode())
        for value in values:
            pobj.stdin.write(value.encode())
            pobj.stdin.write(os.linesep.encode())
        stdout, stderr = pobj.communicate(timeout=100)
        stdout = stdout.decode()
        stderr = stderr.decode()
    else:
        pobj.stdin.write(cmd)
        pobj.stdin.write(os.linesep)
        for value in values:
            pobj.stdin.write(value)
            pobj.stdin.write(os.linesep)
        stdout, stderr = pobj.communicate(timeout=100)

    if stdout[-1:] == os.linesep:
        stdout = stdout[:-1]
    if stderr[-1:] == os.linesep:
        stderr = stderr[:-1]

    return pobj.returncode, stdout, stderr


def stop_services():
    LOGGER.info("Stopping node0 cms services...")
    returncode, stdout, stderr = _exec_popen("rm -rf /opt/cantian/cms/cfg/cms_enable")
    if returncode != 0:
        LOGGER.error(f"Error removing cms_enablep: {stderr}")

    returncode, stdout, stderr = _exec_popen("kill -9 $(pidof cms)")
    if returncode != 0:
        LOGGER.error(f"Error stopping CMS process: {stderr}")


def main():
    node_id = get_value('node_id')
    cantian_in_container = get_value('cantian_in_container')

    if node_id == "0" and cantian_in_container in ["1", "2"]:
        sys.path.append('/ctdb/cantian_install/cantian_connector/action')
        from docker.docker_common.kubernetes_service import KubernetesService

        pod_name = os.getenv("HOSTNAME")
        if not pod_name:
            exit(1)

        kube_config_path = os.path.expanduser("~/.kube/config")
        k8s_service = KubernetesService(kube_config_path)
        try:
            service_name = k8s_service.get_service_by_pod_name(pod_name)
        except Exception:
            LOGGER.info(f"Error getting service name.")
            service_name = None

        if not service_name:
            stop_services()


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        LOGGER.error(f"Error stopping CMS process: {err}")