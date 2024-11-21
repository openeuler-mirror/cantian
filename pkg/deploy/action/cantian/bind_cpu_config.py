import json
import os
import platform
import subprocess
import stat
import sys
import re
import pwd
import grp

from log import LOGGER
from get_config_info import get_value
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from update_config import update_dbstore_conf

# 需要的路径和配置
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cpu_bind_config.json")
CPU_CONFIG_INFO = "/opt/cantian/cantian/cfg/cpu_config.json"
CONFIG_DIR = "/mnt/dbdata/local/cantian/tmp/data"
XNET_MODULE = "NETWORK_BIND_CPU"
CANTIAN_NUMA_INFO = "CANTIAN_NUMA_CPU_INFO"
MYSQL_NUMA_INFO = "MYSQL_NUMA_CPU_INFO"
MODULE_LIST = [XNET_MODULE] # 目前只支持xnet绑核，后续扩展秩序添加在这里即可
dbstor_file_module_dict = {
    "XNET_CPU": XNET_MODULE,
    "IOD_CPU": "",
    "ULOG_CPU": ""
}  # 用于更新dbstor.ini文件，后续扩展加上
BIND_NUMA_NODE_NUM = 2  # 物理机时绑定的 NUMA 前n个节点数，只支持绑前2个

gPyVersion = platform.python_version()


def cpu_info_to_cpu_list(cpu_list_str):
    """
    Converts CPU info string (e.g., '1-3,5-6') into a list of individual CPU IDs.
    If the input string is empty, returns an empty list.
    """
    if not cpu_list_str:
        return []

    cpu_list = []

    for part in cpu_list_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            cpu_list.extend(range(start, end + 1))
        else:
            cpu_list.append(int(part))

    return cpu_list


def cpu_list_to_cpu_info(cpu_list):
    """
    Converts a list of CPU IDs (either as integers or a comma-separated string) into a string in the format '1-3,5-6'.
    """
    if isinstance(cpu_list, str):
        cpu_list = cpu_list.split(',')

    if not all(isinstance(cpu, (int, str)) for cpu in cpu_list):
        raise ValueError("cpu_list should contain integers or strings that can be converted to integers")

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

def get_json_config(path):
    """
    Retrieves the NUMA configuration from the specified JSON file.
    """
    with open(path, 'r', encoding='utf-8') as file:
        config_json = json.load(file)
    return config_json


def write_json_config_file(path, config):
    """
    Updates the NUMA configuration JSON file at the given path and changes ownership.
    """
    flags = os.O_WRONLY | os.O_CREAT
    mode = stat.S_IWUSR | stat.S_IRUSR

    with os.fdopen(os.open(path, flags, mode), "w") as file:
        file.truncate()
        json.dump(config, file, indent=4)

    os.chmod(path, stat.S_IWUSR | stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

    user_name = get_value("deploy_user")
    group_name = get_value("deploy_group")

    try:
        if user_name and group_name:
            uid = pwd.getpwnam(user_name).pw_uid
            gid = grp.getgrnam(group_name).gr_gid
            os.chown(path, uid, gid)
        else:
            LOGGER.error("Deploy user or group not found.")
    except KeyError:
        LOGGER.error(f"User '{user_name}' or group '{group_name}' not found.")
    except PermissionError:
        LOGGER.error("Permission denied: cannot change file ownership. Run as root or with sufficient privileges.")


class NumaConfigBase:
    def _exec_popen(self, cmd, values=None):
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

        if gPyVersion[0] == "3":
            pobj.stdin.write(cmd.encode())
            pobj.stdin.write(os.linesep.encode())
            for value in values:
                pobj.stdin.write(value.encode())
                pobj.stdin.write(os.linesep.encode())
            try:
                stdout, stderr = pobj.communicate(timeout=3600)
            except subprocess.TimeoutExpired as err_cmd:
                pobj.kill()
                return -1, "Time Out.", str(err_cmd)
            stdout = stdout.decode()
            stderr = stderr.decode()
        else:
            pobj.stdin.write(cmd)
            pobj.stdin.write(os.linesep)
            for value in values:
                pobj.stdin.write(value)
                pobj.stdin.write(os.linesep)
            try:
                stdout, stderr = pobj.communicate(timeout=1800)
            except subprocess.TimeoutExpired as err_cmd:
                pobj.kill()
                return -1, "Time Out.", str(err_cmd)
        if stdout[-1:] == os.linesep:
            stdout = stdout[:-1]
        if stderr[-1:] == os.linesep:
            stderr = stderr[:-1]

        return pobj.returncode, stdout, stderr

    def get_default_bind_num(self, cpu_len):
        """
        Returns the default number of CPUs to bind based on the total CPU count.
        """
        if cpu_len <= 16:
            return 1
        elif cpu_len <= 32:
            return 2
        else:
            return 4

    def pre_check(self):
        """
        Performs pre-checks before proceeding with NUMA configuration.
        """
        if platform.machine() != 'aarch64':
            LOGGER.info("System is not aarch64")
            return

        if not os.path.exists(CONFIG_PATH):
            err_msg = "ERROR: cpu_bind_config.json does not exist"
            raise Exception(err_msg)

    def update_dbstor_config_file(self, cpu_config_info):
        """
        Modifies the dbstor configuration file based on the provided CPU configuration.
        If the CPU configuration for a module ID is missing or empty, it removes the corresponding entries.
        """
        for dbstor_file_key, cpu_config_module_key in dbstor_file_module_dict.items():
            if cpu_config_module_key != "":
                module_id_key = f"{cpu_config_module_key}_ID"

                if module_id_key in cpu_config_info and cpu_config_info[module_id_key]:
                    cpu_info = cpu_list_to_cpu_info(cpu_config_info[module_id_key])
                    update_dbstore_conf("add", dbstor_file_key, cpu_info)
                else:
                    update_dbstore_conf("remove", dbstor_file_key, None)

    def update_cantian_config_file(self, mysql_cpu_info):
        """
        Updates the cantian configuration file with the provided MySQL CPU info.
        """
        cantian_conf_file = os.path.join(CONFIG_DIR, "cfg", "cantiand.ini")

        if not os.path.exists(cantian_conf_file):
            LOGGER.warning(f"Configuration file {cantian_conf_file} does not exist.")
            return

        shm_mysql_info = ";".join([mysql_cpu_info] * 6)
        count = 0

        try:
            with open(cantian_conf_file, "r+", encoding="utf-8") as file:
                config = file.readlines()

                for index, item in enumerate(config):
                    if count >= 2:
                        break
                    if "=" not in item:
                        continue

                    key, _ = item.split("=", maxsplit=1)
                    key = key.strip()

                    if key == "SHM_MYSQL_CPU_GROUP_INFO":
                        config[index] = f"{key} = {shm_mysql_info}\n"
                        count += 1
                    elif key == "SHM_CPU_GROUP_INFO":
                        config[index] = f"{key} = {mysql_cpu_info}\n"
                        count += 1

                file.seek(0)
                file.writelines(config)
                file.truncate()

        except Exception as e:
            LOGGER.error(f"Failed to update {cantian_conf_file}: {e}")


class PhysicalCpuConfig(NumaConfigBase):
    def __init__(self):
        super().__init__()
        self.all_cpu_list = []
        self.available_cpu_for_binding_dict = {}
        self.numa_info_dict = {}
        self.bind_cpu_list = []

    def check_cpu_list_invalid(self, bind_cpu_list):
        """
        Checks if the provided list of CPUs is valid for binding.
        """
        invalid_list = [0, 1, 2, 3, 4, 5]
        for i in bind_cpu_list:
            if i in invalid_list and get_value("cantian_in_container") == "0":
                LOGGER.error(f"invalid cpu id, id is {i}")
                return True
            if i not in self.all_cpu_list:
                LOGGER.error(f"invalid cpu id, id is {i}")
                return True

        return False

    def init_cpu_info(self):
        """ 获取物理机上的所有 CPU 相关信息 """
        # 获取物理机上所有 CPU 的列表
        ret_code, result, stderr = self._exec_popen('/usr/bin/lscpu | grep -i "On-line CPU(s) list"')
        if ret_code:
            raise Exception(f"Failed to get CPU list, err: {stderr}")

        _result = result.strip().split(':')
        if len(_result) != 2:
            raise Exception(f"NUMA info parsing failed, result: {result}")
        self.all_cpu_list = cpu_info_to_cpu_list(_result[1].strip())

        ret_code, result, stderr = self._exec_popen('/usr/bin/lscpu | grep -i "NUMA node[0-9] CPU(s)"')
        if ret_code:
            raise Exception(f"Failed to get NUMA node info, err: {stderr}")

        self.numa_info_dict = {}

        # 解析 lscpu 输出中的 NUMA node 信息
        lines = result.strip().splitlines()
        for line in lines:
            match = re.search(r'NUMA node(\d+) CPU\(s\):\s+([\d,\-]+)', line)
            if match:
                numa_id = int(match.group(1))
                cpu_range_str = match.group(2)

                cpu_list = cpu_info_to_cpu_list(cpu_range_str)

                self.numa_info_dict[numa_id] = cpu_list

        # 更新 available_cpu_for_binding_dict，移除 CPU IDs from 0 to 11
        self.available_cpu_for_binding_dict = {}
        for numa_id, cpu_list in list(self.numa_info_dict.items())[:BIND_NUMA_NODE_NUM]:
            valid_cpu_list = [cpu for cpu in cpu_list if cpu >= 12]  # 只保留 ID >= 12 的 CPU
            self.available_cpu_for_binding_dict[numa_id] = valid_cpu_list

    def update_bind_cpu_info(self):
        """ 获取绑定的 CPU 列表，支持手动配置 """
        numa_config = get_json_config(CONFIG_PATH)
        bind_cpu_list = []

        for module_name in MODULE_LIST:
            module_info = numa_config.get(module_name, "")
            module_id_key = f"{module_name}_ID"

            if module_info == "off":
                numa_config[module_id_key] = ""
                continue

            if module_id_key in numa_config and numa_config[module_id_key]:
                manually_configured_cpus = cpu_info_to_cpu_list(numa_config[module_id_key])
                if self.check_cpu_list_invalid(manually_configured_cpus):
                    err_msg = (f"Invalid CPU binding in {module_id_key}. "
                               f"Cannot use CPUs outside the available range or in 0-5.")
                    LOGGER.error(err_msg)
                    raise Exception(err_msg)
                LOGGER.info(f"{module_id_key} is manually configured, skipping CPU binding generation.")
                bind_cpu_list.extend(manually_configured_cpus)
                continue

            if not module_info:
                module_info = self.get_default_bind_num(len(self.all_cpu_list))

            try:
                module_info = int(module_info)
                if not (1 <= module_info <= 10):
                    LOGGER.warning(f"Module {module_name} thread number out of range (1-10).")
                    numa_config[module_id_key] = ""
                    continue
            except ValueError:
                LOGGER.warning(f"Module {module_name} thread number invalid.")
                numa_config[module_id_key] = ""
                continue

            module_cpu_list = self.get_module_bind_cpu_list(module_info)
            bind_cpu_list.extend(module_cpu_list)
            numa_config[module_id_key] = ",".join(map(str, module_cpu_list))

        self.bind_cpu_list = bind_cpu_list
        write_json_config_file(CONFIG_PATH, numa_config)

    def get_module_bind_cpu_list(self, module_thread_num):
        """ 获取模块绑核的 CPU 列表 """
        result_ranges = []
        count = module_thread_num

        numa_pointer = {numa_id: 0 for numa_id in self.available_cpu_for_binding_dict}

        while count > 0:
            for numa_id, available_cpu_list in self.available_cpu_for_binding_dict.items():
                if numa_pointer[numa_id] < len(available_cpu_list):
                    result_ranges.append(available_cpu_list[numa_pointer[numa_id]])
                    numa_pointer[numa_id] += 1
                    count -= 1
                    if count == 0:
                        break

        for numa_id, available_cpu_list in self.available_cpu_for_binding_dict.items():
            self.available_cpu_for_binding_dict[numa_id] = available_cpu_list[numa_pointer[numa_id]:]

        return result_ranges

    def get_mysql_cpu_info(self):
        """
        获取 MYSQL_CPU_INFO：将 NUMA 节点内移除绑定的 CPU 后，剩余 CPU 转换为 NUMA 节点范围字符串形式
        """
        # 深拷贝 NUMA 节点信息
        remaining_numa_info = {numa_id: list(cpu_list) for numa_id, cpu_list in self.numa_info_dict.items()}

        # 从 NUMA 节点中移除已绑定的 CPU
        for cpu in self.bind_cpu_list:
            for numa_id, cpu_list in remaining_numa_info.items():
                if cpu in cpu_list:
                    cpu_list.remove(cpu)

        # 将每个 NUMA 节点的剩余 CPU 列表转换为 NUMA 范围字符串
        mysql_cpu_info = []
        for numa_id, cpu_list in remaining_numa_info.items():
            if cpu_list:
                mysql_cpu_info.append(cpu_list_to_cpu_info(cpu_list))

        return " ".join(mysql_cpu_info)

    def update_cantian_mysql_info(self):
        """
        更新 CANTIAN_CPU_INFO 和 MYSQL_CPU_INFO，并更新 CPU_CONFIG_INFO 文件
        """
        # 获取 module_id_key 和对应的绑定 CPU 列表
        numa_config = get_json_config(CONFIG_PATH)
        cpu_config_info = {}

        for module_name in MODULE_LIST:
            module_id_key = f"{module_name}_ID"
            bind_cpu = cpu_info_to_cpu_list(numa_config.get(module_id_key, ""))

            if bind_cpu:
                cpu_config_info[module_id_key] = ",".join(map(str, bind_cpu))

        # 更新CPU_CONFIG_INFO
        remaining_cpus = list(set(self.all_cpu_list) - set(self.bind_cpu_list))
        cantian_cpu_info = cpu_list_to_cpu_info(remaining_cpus)

        cpu_config_info[CANTIAN_NUMA_INFO] = cantian_cpu_info
        self.update_dbstor_config_file(cpu_config_info)

        # 更新 MYSQL_CPU_INFO
        mysql_cpu_info = self.get_mysql_cpu_info()
        self.update_cantian_config_file(mysql_cpu_info)
        cpu_config_info[MYSQL_NUMA_INFO] = mysql_cpu_info

        write_json_config_file(CPU_CONFIG_INFO, cpu_config_info)

    def update_numa_config_file(self):
        self.init_cpu_info()
        self.update_bind_cpu_info()
        self.update_cantian_mysql_info()



class ContainerCpuConfig(NumaConfigBase):
    def __init__(self):
        super().__init__()
        self.all_cpu_list = []
        self.available_cpu_for_binding_dict = {}
        self.bind_cpu_list = []

    def update_cpu_info(self):
        """ 获取容器中的所有 CPU 列表 """
        if not os.path.exists('/sys/fs/cgroup/cpuset/cpuset.cpus'):
            raise Exception("cpuset.cpus path does not exist in container.")

        ret_code, result, stderr = self._exec_popen('cat /sys/fs/cgroup/cpuset/cpuset.cpus')
        if ret_code:
            raise Exception(f"Failed to get CPU list in container, err: {stderr}")

        self.all_cpu_list = cpu_info_to_cpu_list(result.strip())

        # 容器环境，只需要简单分成两份
        num_cpus = len(self.all_cpu_list)
        mid = num_cpus // 2
        self.available_cpu_for_binding_dict[0] = self.all_cpu_list[:mid]
        self.available_cpu_for_binding_dict[1] = self.all_cpu_list[mid:]

    def get_bind_cpu_list(self):
        """
        获取容器中绑定的 CPU 列表
        绑定的 CPU 列表是由模块信息决定的，不能手动配置
        """
        numa_config = get_json_config(CONFIG_PATH)
        bind_cpu_list = []

        for module_name in MODULE_LIST:
            module_info = numa_config.get(module_name, "")
            module_id_key = f"{module_name}_ID"

            if module_info == "off":
                numa_config[module_id_key] = ""
                continue

            if not module_info:
                module_info = self.get_default_bind_num(len(self.all_cpu_list))

            try:
                module_info = int(module_info)
                if not (1 <= module_info <= 10):
                    numa_config[module_id_key] = ""
                    LOGGER.warning(f"Module {module_name} thread number out of range (1-10).")
                    continue
            except ValueError:
                numa_config[module_id_key] = ""
                LOGGER.warning(f"Module {module_name} thread number invalid.")
                continue

            module_cpu_list = self.get_module_bind_cpu_list(module_info)
            bind_cpu_list.extend(module_cpu_list)
            numa_config[module_id_key] = ",".join(map(str, module_cpu_list))

        self.bind_cpu_list = bind_cpu_list
        write_json_config_file(CONFIG_PATH, numa_config)

        return bind_cpu_list

    def get_module_bind_cpu_list(self, module_thread_num):
        """ 轮流选 CPU 进行绑核 """
        result_ranges = []
        count = module_thread_num

        numa_pointer = {numa_id: 0 for numa_id in self.available_cpu_for_binding_dict}

        while count > 0:
            for numa_id, available_cpu_list in self.available_cpu_for_binding_dict.items():
                if numa_pointer[numa_id] < len(available_cpu_list):
                    result_ranges.append(available_cpu_list[numa_pointer[numa_id]])
                    numa_pointer[numa_id] += 1
                    count -= 1
                    if count == 0:
                        break

        for numa_id, available_cpu_list in self.available_cpu_for_binding_dict.items():
            self.available_cpu_for_binding_dict[numa_id] = available_cpu_list[numa_pointer[numa_id]:]

        return result_ranges

    def get_mysql_cpu_info(self):
        """
        获取 MYSQL_CPU_INFO：容器中的 NUMA 节点信息
        """
        # 容器场景下，简单将cpu分成两份
        remaining_cpus = list(set(self.all_cpu_list) - set(self.bind_cpu_list))

        container_cpu_info = []
        mid = len(remaining_cpus) // 2
        container_cpu_info.append(cpu_list_to_cpu_info(remaining_cpus[:mid]))
        container_cpu_info.append(cpu_list_to_cpu_info(remaining_cpus[mid:]))

        return " ".join(container_cpu_info)

    def update_cantian_mysql_info(self):
        """
        更新 CANTIAN_CPU_INFO 和 MYSQL_CPU_INFO，并更新 CPU_CONFIG_INFO 文件
        """
        # 获取 module_id_key 和对应的绑定 CPU 列表
        numa_config = get_json_config(CONFIG_PATH)
        cpu_config_info = {}

        for module_name in MODULE_LIST:
            module_id_key = f"{module_name}_ID"
            bind_cpu = cpu_info_to_cpu_list(numa_config.get(module_id_key, ""))

            if bind_cpu:
                cpu_config_info[module_id_key] = ",".join(map(str, bind_cpu))

        # 更新 CPU_CONFIG_INFO
        remaining_cpus = list(set(self.all_cpu_list) - set(self.bind_cpu_list))
        cantian_cpu_info = cpu_list_to_cpu_info(remaining_cpus)

        cpu_config_info[CANTIAN_NUMA_INFO] = cantian_cpu_info
        self.update_dbstor_config_file(cpu_config_info)

        # 更新 MYSQL_CPU_INFO
        mysql_cpu_info = self.get_mysql_cpu_info()
        self.update_cantian_config_file(mysql_cpu_info)
        cpu_config_info[MYSQL_NUMA_INFO] = mysql_cpu_info

        write_json_config_file(CPU_CONFIG_INFO, cpu_config_info)

    def update_numa_config_file(self):
        self.update_cpu_info()
        self.get_bind_cpu_list()
        self.update_cantian_mysql_info()


class ConfigManager:
    def init_numa_config(self):
        # 根据MODULE_LIST动态生成 numa_config
        numa_config = {}
        for module in MODULE_LIST:
            numa_config[module] = ""

        write_json_config_file(CONFIG_PATH, numa_config)

    def update_cpu_config(self):
        """ 更新 CPU 配置 """
        if get_value("cantian_in_container") == "0":
            manager = PhysicalCpuConfig()
        else:
            manager = ContainerCpuConfig()

        manager.pre_check()
        manager.update_numa_config_file()

if __name__ == "__main__":
    try:
        config_manager = ConfigManager()
        if len(sys.argv) > 1:
            param = sys.argv[1]
            if param == "init_config":
                config_manager.init_numa_config()
        else:
            if get_value("deploy_mode") != "dbstor":
                sys.exit(0)
            config_manager.update_cpu_config()
    except Exception as e:
        LOGGER.error(f"An unexpected error occurred: {str(e)}")