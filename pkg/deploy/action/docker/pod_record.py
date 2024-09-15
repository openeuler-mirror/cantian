#!/usr/bin/env python3

import os
import sys
from datetime import datetime
from docker_common.file_utils import load_or_initialize_json, write_json

sys.path.append('/ctdb/cantian_install/cantian_connector/action')

from delete_unready_pod import KubernetesService, get_pod_name_from_info
from om_log import LOGGER as LOG

POD_RECORD_FILE_PATH = "/home/mfdb_core/POD-RECORD/cantian-pod-record.json"
# 重启次数阈值，超过该次数则触发漂移
RESTART_THRESHOLD = 6


def update_pod_restart_record(k8s_service, pod_name_full, pod_namespace):
    pod_record = load_or_initialize_json(POD_RECORD_FILE_PATH)

    if pod_name_full not in pod_record:
        pod_record[pod_name_full] = {
            "restart_count": 1,
            "last_restart_time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        }
    else:
        pod_record[pod_name_full]["restart_count"] += 1
        pod_record[pod_name_full]["last_restart_time"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    restart_count = pod_record[pod_name_full]["restart_count"]

    if restart_count > RESTART_THRESHOLD:
        LOG.info(f"Pod {pod_name_full} has restarted {restart_count} times, Deleting...")
        k8s_service.delete_pod(pod_name_full, pod_namespace)
    else:
        LOG.info("Cantian pod start record updated successfully.")

    write_json(POD_RECORD_FILE_PATH, pod_record)


def main():
    short_hostname = os.getenv("HOSTNAME")
    kube_config_path = os.path.expanduser("~/.kube/config")

    k8s_service = KubernetesService(kube_config_path)

    if not short_hostname:
        LOG.error("Pod short hostname not found.")
        return

    try:
        all_pod_info = k8s_service.get_all_pod_info()
        if not all_pod_info:
            LOG.error("No Pods found in the cluster.")
            return
    except Exception as e:
        LOG.error(f"Error fetching pod information: {e}")
        return

    pod_name_full = get_pod_name_from_info(all_pod_info, short_hostname)

    if pod_name_full:
        pod_info = k8s_service.get_pod_by_name(pod_name_full)
        pod_namespace = pod_info["metadata"]["namespace"]

        if pod_namespace:
            update_pod_restart_record(k8s_service, pod_name_full, pod_namespace)
        else:
            LOG.error(f"Namespace not found for pod: {pod_name_full}")


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        LOG.error(f"Error in pod_record.py: {err}")