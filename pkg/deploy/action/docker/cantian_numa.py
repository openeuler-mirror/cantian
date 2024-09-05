#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import re
import sys
import fcntl
import json

sys.path.append('/ctdb/cantian_install/cantian_connector/action')

from logic.common_func import exec_popen
from delete_unready_pod import KubernetesService, get_pod_name_from_info
from om_log import LOGGER as LOG

NUMA_INFO_PATH = "/home/mfdb_core/NUMA-INFO/numa-pod.json"
TIME_OUT = 100


class LockFile:
    """持锁状态下对文件标识符进行修改，使用阻塞模式等待锁释放"""
    @staticmethod
    def lock(handle):
        fcntl.flock(handle, fcntl.LOCK_EX)

    @staticmethod
    def unlock(handle):
        fcntl.flock(handle, fcntl.LOCK_UN)


class CPUAllocator:
    def __init__(self):
        self.numa_info_key = "numa_info"

    @staticmethod
    def get_cpu_num():
        return int(os.getenv("MY_CPU_NUM", "0"))

    @staticmethod
    def get_hostname():
        return os.getenv("HOSTNAME", "")

    @staticmethod
    def execute_cmd(cmd):
        return_code, output, stderr = exec_popen(cmd, timeout=TIME_OUT)
        if return_code:
            err_msg = f"Execute cmd[{cmd}] failed, details:{stderr}"
            raise Exception(err_msg)
        return output

    @staticmethod
    def _parse_cpu_list(cpu_list_str):
        """
        解析CPU列表字符串，处理范围和单个数字的组合
        例如输入 '0-25'，输出 [0, 1, 2, ..., 25]
        """
        cpu_list = []
        for part in cpu_list_str.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                cpu_list.extend(range(start, end + 1))
            else:
                cpu_list.append(int(part))
        return cpu_list

    @staticmethod
    def get_numa_info():
        cmd = "lscpu | grep -i 'NUMA node(s)'"
        return_code, stdout, stderr = exec_popen(cmd, timeout=TIME_OUT)
        if return_code:
            err_msg = f"Execute cmd[{cmd}] failed, details:{stderr}"
            raise Exception(err_msg)

        numa_nodes = int(re.search(r'\d+', stdout).group())

        cmd = "lscpu | grep -i 'NUMA node[0-9] CPU(s)'"
        return_code, stdout, stderr = exec_popen(cmd, timeout=TIME_OUT)
        if return_code:
            err_msg = f"Execute cmd[{cmd}] failed, details:{stderr}"
            raise Exception(err_msg)

        cpu_info = {}
        total_cpus = 0
        for line in stdout.splitlines():
            match = re.search(r'NUMA node(\d+) CPU\(s\):\s+([\d\-]+)', line)
            if match:
                node = str(match.group(1))
                cpu_range = list(map(int, match.group(2).split('-')))
                node_cpus = cpu_range[1] - cpu_range[0] + 1
                total_cpus = max(total_cpus, node_cpus)
                cpu_info[node] = {
                    "available_cpus": list(range(cpu_range[0], cpu_range[1] + 1)),
                    "available_cpu_count": node_cpus,
                    "max_cpu": cpu_range[1],
                    "min_cpu": cpu_range[0]
                }
        return total_cpus, numa_nodes, cpu_info

    def bind_cpu(self, cpus, pid=1):
        cmd = f"taskset -cp {','.join(map(str, cpus))} {pid}"
        return self.execute_cmd(cmd)

    def verify_binding(self, expected_cpu_num, pid=1):
        cmd = f"taskset -cp {pid}"
        stdout = self.execute_cmd(cmd)

        # 解析 taskset 输出的 CPU 列表
        match = re.search(r'list:\s+([\d,-]+)', stdout)
        if match:
            cpu_list_str = match.group(1)
            actual_cpus = self._parse_cpu_list(cpu_list_str)

            if len(actual_cpus) == expected_cpu_num:
                return True, stdout
        return False, stdout

    def determine_binding_strategy(self, cpu_num, numa_info):
        if cpu_num == 0:
            return 1, []

        # 如果 numa_info 是空的，未拉起过 cantian 容器，需要初始化 numa 信息
        if not numa_info:
            total_cpus, numa_nodes, cpu_info = self.get_numa_info()
            numa_info.update(cpu_info)

        max_single_numa = max(info['available_cpu_count'] for info in numa_info.values() if isinstance(info, dict))
        total_available_cpus = sum(info['available_cpu_count'] for info in numa_info.values() if isinstance(info, dict))

        if cpu_num > total_available_cpus:
            return 0, []

        if cpu_num > max_single_numa:
            needed_cpus = cpu_num
            binding_cpus = []
            for node, info in sorted(numa_info.items(), key=lambda x: x[1]['available_cpu_count'], reverse=True):
                if isinstance(info, dict):
                    if info['available_cpu_count'] >= needed_cpus:
                        binding_cpus.extend(info['available_cpus'][:needed_cpus])
                        return 2, binding_cpus
                    else:
                        binding_cpus.extend(info['available_cpus'])
                        needed_cpus -= info['available_cpu_count']
            return 2, binding_cpus

        for node, info in numa_info.items():
            if isinstance(info, dict) and info['available_cpu_count'] >= cpu_num:
                return 1, info['available_cpus'][:cpu_num]

        needed_cpus = cpu_num
        binding_cpus = []
        for node, info in sorted(numa_info.items(), key=lambda x: x[1]['available_cpu_count'], reverse=True):
            if isinstance(info, dict):
                if needed_cpus > 0:
                    take_cpus = min(needed_cpus, info['available_cpu_count'])
                    binding_cpus.extend(info['available_cpus'][:take_cpus])
                    needed_cpus -= take_cpus
                if needed_cpus == 0:
                    return 2, binding_cpus

        return 0, []

    def update_available_cpus(self, numa_data, cpu_info, bound_cpus):
        """
        更新 numa_data 中可用 CPU 的信息
        """
        for node, info in cpu_info.items():
            node_str = str(node)

            existing_available_cpus = set(numa_data[self.numa_info_key][node_str].get("available_cpus", []))

            available_cpus = existing_available_cpus - set(bound_cpus)
            numa_data[self.numa_info_key][node_str]["available_cpus"] = sorted(list(available_cpus))

            numa_data[self.numa_info_key][node_str]["available_cpu_count"] = len(
                numa_data[self.numa_info_key][node_str]["available_cpus"])

    def clean_up_json(self, numa_data, pod_info, hostname_pattern):
        """
        清理不存在的 Pod 绑定信息，并将绑定的 CPU 恢复到 numa_info 中。
        """
        matching_pods = [pod['pod_name'] for pod in pod_info if re.match(hostname_pattern, pod['pod_name'])]

        keys_to_delete = [key for key in numa_data.keys() if key not in matching_pods and key != self.numa_info_key]

        for key in keys_to_delete:
            bind_cpus = numa_data[key].get("bind_cpus", "")

            if bind_cpus and bind_cpus != "None":
                self.restore_cpus_to_numa_info(numa_data, bind_cpus)

            LOG.info(f"Removing outdated entry from JSON: {key}")
            del numa_data[key]

    @staticmethod
    def restore_cpus_to_numa_info(numa_data, bind_cpus):
        """
        将已绑定的 CPU 恢复到 numa_info 中。
        """
        cpu_list = CPUAllocator._parse_cpu_list(bind_cpus)

        for cpu in cpu_list:
            for node, info in numa_data["numa_info"].items():
                if info["min_cpu"] <= cpu <= info["max_cpu"]:
                    if cpu not in info["available_cpus"]:
                        info["available_cpus"].append(cpu)
                        info["available_cpus"].sort()
                    info["available_cpu_count"] = len(info["available_cpus"])
                    break

    def execute_binding(self, cpu_num, hostname, numa_data, cpu_info):
        """
        执行绑核操作，检查是否已经绑核成功，已绑核则跳过。
        """
        if self.numa_info_key not in numa_data:
            numa_data[self.numa_info_key] = {}

        if hostname in numa_data:
            if numa_data[hostname].get("bind_flag", False):
                LOG.info(f"Host {hostname} is already bound successfully. Skipping binding.")
                return

        # 检查 numa_info 是否为空，如果为空则初始化
        if not numa_data[self.numa_info_key]:
            total_cpus, numa_nodes, cpu_info = self.get_numa_info()
            numa_data[self.numa_info_key].update(cpu_info)

        binding_status, binding_cpus = self.determine_binding_strategy(cpu_num, numa_data[self.numa_info_key])

        # 0-绑定失败，没有足够的 CPU
        if binding_status == 0:
            LOG.error("Binding failed: Insufficient CPUs.")
            numa_data[hostname] = {
                "bind_cpus": "",
                "bind_flag": False,
                "taskset_output": "Binding failed due to insufficient CPUs"
            }
        elif binding_status in (1, 2):
            if binding_status == 2:
                LOG.warning(f"Cross NUMA binding detected for host {hostname}. This may affect performance.")

            # 执行绑核,1-单个numa，2-跨numa绑核
            self.bind_cpu(binding_cpus)
            bind_successful, taskset_output = self.verify_binding(len(binding_cpus))

            if bind_successful:
                numa_data[hostname] = {
                    "bind_cpus": ",".join(map(str, binding_cpus)),
                    "bind_flag": True,
                    "taskset_output": taskset_output
                }
                self.update_available_cpus(numa_data, cpu_info, binding_cpus)
            else:
                numa_data[hostname] = {
                    "bind_cpus": "",
                    "bind_flag": False,
                    "taskset_output": "Binding failed during verification"
                }

    def delete_binding_info(self, short_hostname):
        """
        删除包含 short_hostname 的绑核信息，并恢复对应的 CPU 到 numa_info
        """
        numa_data = load_or_initialize_json(NUMA_INFO_PATH)

        keys_to_delete = [key for key in numa_data.keys() if short_hostname in key]

        if keys_to_delete:
            for key in keys_to_delete:
                LOG.info(f"Deleting binding info for: {key}")

                bind_cpus = numa_data[key].get("bind_cpus")
                if bind_cpus and bind_cpus != "None":
                    self.restore_cpus_to_numa_info(numa_data, bind_cpus)

                # 删除绑核信息
                del numa_data[key]

            # 更新 JSON 文件
            write_json_to_file(NUMA_INFO_PATH, numa_data)
            LOG.info(f"NUMA information updated after deletion in {NUMA_INFO_PATH}")
        else:
            LOG.info(f"No matching entry found for hostname: {short_hostname}")


def load_or_initialize_json(filepath):
    """
    加载或初始化 JSON 文件，并使用文件锁保护文件操作
    """
    fd = os.open(filepath, os.O_RDWR | os.O_CREAT, 0o644)
    with os.fdopen(fd, 'r+') as file:
        LockFile.lock(file)
        try:
            file.seek(0)
            if os.path.getsize(filepath) > 0:
                return json.load(file)
            else:
                return {}
        finally:
            LockFile.unlock(file)

def write_json_to_file(filepath, data):
    """
    写入 JSON 文件并使用文件锁保护文件操作
    """
    fd = os.open(filepath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, 'w') as file:
        LockFile.lock(file)
        try:
            json.dump(data, file, indent=4)
        finally:
            LockFile.unlock(file)


def format_cpu_ranges(cpu_list):
    """
    将 CPU 列表格式化为范围形式（例如：0-31,64-95）
    """
    if not cpu_list:
        return ""

    cpu_list = sorted(set(map(int, cpu_list)))
    ranges = []
    range_start = cpu_list[0]
    range_end = cpu_list[0]

    for i in range(1, len(cpu_list)):
        if cpu_list[i] == range_end + 1:
            range_end = cpu_list[i]
        else:
            if range_start == range_end:
                ranges.append(str(range_start))
            else:
                ranges.append(f"{range_start}-{range_end}")
            range_start = cpu_list[i]
            range_end = cpu_list[i]

    if range_start == range_end:
        ranges.append(str(range_start))
    else:
        ranges.append(f"{range_start}-{range_end}")

    return ",".join(ranges)


def show_numa_binding_info(numa_info_path):
    """
    查询 numa-pod.json 文件中每个 Pod 的绑核信息，并以表格形式显示。
    """
    try:
        numa_data = load_or_initialize_json(numa_info_path)
    except Exception as err:
        LOG.error(f"Error loading NUMA info from {numa_info_path}: {err}")
        return

    col1_width = 40
    col2_width = 20

    print(f"{'Pod Name'.ljust(col1_width)} {'Bind CPUs'.ljust(col2_width)}")

    for pod_name, pod_info in numa_data.items():
        if pod_name == "numa_info":
            continue

        bind_cpus = pod_info.get("bind_cpus", "")

        if bind_cpus:
            try:
                cpu_list = list(map(int, bind_cpus.split(','))) if bind_cpus else []
                formatted_cpus = format_cpu_ranges(cpu_list)
            except ValueError:
                formatted_cpus = bind_cpus
        else:
            formatted_cpus = ""

        print(f"{pod_name.ljust(col1_width)} {formatted_cpus.ljust(col2_width)}")

    try:
        cmd = "lscpu | grep -i 'NUMA node[0-9] CPU(s)'"
        return_code, stdout, stderr = exec_popen(cmd, timeout=TIME_OUT)
        if return_code:
            LOG.error(f"Error retrieving NUMA info: {stderr}")
            return

        print("\nNUMA:")
        for line in stdout.splitlines():
            print(line)

    except Exception as e:
        LOG.error(f"Error fetching NUMA CPU distribution: {e}")


def main():
    cpu_allocator = CPUAllocator()
    cpu_num = cpu_allocator.get_cpu_num()
    short_hostname = cpu_allocator.get_hostname()

    kube_config_path = os.path.expanduser("~/.kube/config")
    k8s_service = KubernetesService(kube_config_path)

    try:
        all_pod_info = k8s_service.get_all_pod_info()
        if not all_pod_info:
            LOG.error("No Pods found in the cluster.")
            return
    except Exception as e:
        LOG.error(f"Error fetching pod information: {e}")
        return

    # 获取 NUMA 信息和初始化 JSON 数据
    try:
        total_cpus, numa_nodes, cpu_info = cpu_allocator.get_numa_info()
    except Exception as e:
        LOG.error(f"Error fetching NUMA info: {e}")
        return

    # 初始化或加载 NUMA JSON 数据
    numa_data = load_or_initialize_json(NUMA_INFO_PATH)

    # 清理 JSON 中不再存在的 POD 信息
    hostname_pattern = r'cantian.*-node.*'
    cpu_allocator.clean_up_json(numa_data, all_pod_info, hostname_pattern)

    # 找到与当前 short_hostname 匹配的 Pod 全名，并执行绑定操作
    pod_name_full = get_pod_name_from_info(all_pod_info, short_hostname)
    if pod_name_full:
        cpu_allocator.execute_binding(cpu_num, pod_name_full, numa_data, cpu_info)
    else:
        LOG.info(f"Pod with hostname {short_hostname} not found in the cluster.")

    # 更新 JSON 文件
    write_json_to_file(NUMA_INFO_PATH, numa_data)
    LOG.info("NUMA information updated successfully.")


if __name__ == "__main__":
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "show":
            show_numa_binding_info(NUMA_INFO_PATH)
        else:
            main()
    except Exception as _err:
        LOG.error(f"An error occurred: {_err}")