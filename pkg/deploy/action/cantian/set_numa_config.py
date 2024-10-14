import json
import os
import platform
import stat
import subprocess
import sys
from configparser import ConfigParser, NoSectionError, NoOptionError

from log import LOGGER
from get_config_info import get_value
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from update_config import update_dbstore_conf


CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "numa_config.json")
NUMA_CONFIG_PATH = "/opt/cantian/cantian/cfg/numa_config.json"
CONFIG_DIR = "/mnt/dbdata/local/cantian/tmp/data"
XNET_MODULE = "XNET_NUMA_ID" 
ULOG_MODULE = "ULOG_NUMA_ID"
IOD_MODULE = "IOD_NUMA_ID"
CANTIAN_NUMA_INFO = "CANTIAN_NUMA_CPU_INFO"
MYSQL_NUMA_INFO = "MYSQL_NUMA_CPU_INFO"
THREAD_BATCH = 2
gPyVersion = platform.python_version()


def get_numa_config(path) -> json:
    with open(path, 'r', encoding='utf-8') as file:
        info = file.read()
    config_json = json.loads(info)
    return config_json


def update_numa_config_file(path, config):
    flags = os.O_WRONLY | os.O_CREAT
    mode = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(path, flags, mode), "w") as file:
        file.truncate()
        json.dump(config, file, indent=4)


def execute_fun_with_param(param):
    function_dict = {
        "update_numa": update_numa_config, 
        "update_dbstor": update_dbstor_config_file,
        "update_cantian": update_cantian_config_file,
        "init_config": init_numa_config
    }
    if param in function_dict.keys():
        function_dict[param]()


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


def cpu_list_to_cpu_info(target_list, filter_list=None):
    """
    Convert the CPU list to a CPU string, for example
    [1,2,3,5,6] => 1-3,5-6
    """

    target_list.sort()
    start_id = None
    end_id = None
    result_ranges = []

    for i in target_list:
        if filter_list is not None and i in filter_list:
            continue
        if start_id is None:
            start_id = i
            end_id = i
        elif i == end_id + 1:
            end_id = i
        else:
            result_ranges.append(f"{start_id}-{end_id}" if start_id != end_id else f"{start_id}")
            start_id = i
            end_id = i
    if start_id is not None:
        result_ranges.append(f"{start_id}-{end_id}" if start_id != end_id else f"{start_id}")

    return ','.join(result_ranges)


def cpu_info_to_cpu_list(cpu_list_info):
    """
    Convert the CPU string to a CPU list, for example
    1-3,5-6 => [1,2,3,5,6]
    """
    
    cpu_list = cpu_list_info.strip().split(',')
    result = []
    for i in cpu_list:
        list_i = i.strip().split('-')
        if len(list_i) == 1:
            if not list_i[0].strip().isdigit():
                msg = "get cpu list failed, numa(s) cpu get error, result:%s" % list_i[0]
                LOGGER.error(msg)
                continue
            result.append(int(list_i[0].strip()))
            continue
        result += list(range(int(list_i[0].strip()), int(list_i[1].strip()) + 1))
    return result


def get_all_cpu_list():
    if get_value("cantian_in_container") != "0":
        if not os.path.exists('/sys/fs/cgroup/cpuset/cpuset.cpus'):
            err_msg = "error: cpuset.cpus path get error"
            LOGGER.error(err_msg)
            raise Exception(err_msg)
        ret_code, result, stderr = _exec_popen('cat /sys/fs/cgroup/cpuset/cpuset.cpus')
        if ret_code:
            err_msg = "can not get cpu list in container, err: %s" % stderr
            LOGGER.error(err_msg)
            raise Exception(err_msg)
        cpu_list = cpu_info_to_cpu_list(result)
    else:
        if not os.path.exists('/usr/bin/lscpu'):
            LOGGER.error("Warning: lscpu path get error")
            return ""
        ret_code, result, stderr = _exec_popen('/usr/bin/lscpu | grep -i "On-line CPU(s) list"')
        if ret_code:
            err_msg = "can not get cpu list, err: %s" % stderr
            LOGGER.error(err_msg)
            raise Exception(err_msg)
        _result = result.strip().split(':')

        if len(_result) != 2:
            LOGGER.error("Warning: numa get error, result:%s" % result)
            return ""
        cpu_list = cpu_info_to_cpu_list(_result[1])

    return cpu_list


def get_module_cpu_list(module_name):
    """
    get module CPU list from numa_config
    """
    
    numa_config = get_numa_config(CONFIG_PATH)
    module_info = numa_config.get(module_name, "")
    if module_info == "" or module_info == "off":
        return []
    
    return cpu_info_to_cpu_list(module_info)


def generate_cpu_list_based_filter_list(target_list, filter_list, thread_num):
    if thread_num >= 2:
        count = thread_num / THREAD_BATCH
    else:
        count = 1
    target_list.sort()
    cpu_id = None
    result_ranges = []

    for i in target_list:
        if i in filter_list or i < 12:
            continue
        if count == 0:
            break
        if cpu_id is None:
            cpu_id = i
        else:
            result_ranges.append(cpu_id)
            cpu_id = i
            count -= 1

    return result_ranges


def get_module_defult_cpu_list_in_container(filter_cpu_list, module_thread_num):
    cpu_list = get_all_cpu_list()
    cpu_list.sort()
    cpu_id = None
    count = module_thread_num
    result_ranges = []
    for i in cpu_list:
        if i in filter_cpu_list or i < 2:
            continue
        if count == 0:
            break
        if cpu_id is None:
            cpu_id = i
        else:
            result_ranges.append(cpu_id)
            cpu_id = i
            count -= 1

    return result_ranges
    

def get_module_defult_cpu_list(filter_cpu_list, module_thread_num):
    if get_value("cantian_in_container") != "0":
        return get_module_defult_cpu_list_in_container(filter_cpu_list, module_thread_num)
    ret_code, result, stderr = _exec_popen('/usr/bin/lscpu | grep -i "NUMA node(s)"')
    if ret_code:
        err_msg = "can not get numa node parameters, err: %s" % stderr
        LOGGER.error(err_msg)
        raise Exception(err_msg)
    _result = result.strip().split(':')

    if len(_result) != 2:
        LOGGER.error("Warning: numa get error, result:%s" % result)
        return []
    if not _result[1].strip().isdigit():
        LOGGER.error("Warning: numa(s) size get error, result:%s" % result)
        return []
    
    max_numa_num = int(_result[1].strip())
    numa_num = 0
    result_ranges = []
    while numa_num < max_numa_num:
        if numa_num >= THREAD_BATCH:
            break
        err_code, ans, stderr = _exec_popen('/usr/bin/lscpu | grep -i "NUMA node%s"' % numa_num)
        if err_code:
            err_msg = "can not get numa node parameters, err: %s" % stderr
            LOGGER.error(err_msg)
            raise Exception(err_msg)
        _ans = ans.strip().split(':')
        if len(_ans) != 2:
            LOGGER.info("Warning: numa node get error, ans:%s" % ans)
            return []
        
        numa_id_list = cpu_info_to_cpu_list(_ans[1])
        numa_id_cpu_list = generate_cpu_list_based_filter_list(numa_id_list, filter_cpu_list, module_thread_num)
        result_ranges += numa_id_cpu_list
        numa_num += 1
    return result_ranges


def get_defult_thread_num():
    cpu_list = get_all_cpu_list()

    if not cpu_list:
        LOGGER.error("get cpu list failed")
        return 4
    cpu_len = len(cpu_list)
    if cpu_len <= 16:
        return 1
    elif cpu_len <= 32:
        return 2
    elif cpu_len < 96:
        return 4
    else:
        return 4
    

def get_module_thread_num(module_name):
    thread_option = None
    if module_name == XNET_MODULE:
        thread_option = "XNET_THREAD"
    elif module_name == ULOG_MODULE:
        thread_option = "ULOG_THREAD"
    else:
        return 0
    try:
        config_dir = "/opt/cantian/dbstor/tools"  # 文件不存在的风险
        file_name = "dbstor_config.ini"
        config = ConfigParser()
        config.optionxform = str
        dbstor_conf_file = os.path.join(config_dir, file_name)
        if not os.path.exists(dbstor_conf_file):
            return get_defult_thread_num()
        config.read(dbstor_conf_file)
        if config.has_section('CLIENT') and config.has_option('CLIENT', thread_option):
            thread_num = config.get('CLIENT', thread_option)
            if thread_num.strip().isdigit():
                num = int(thread_num.strip())
                if num <= 8:
                    return num
            return get_defult_thread_num()
        else:
            LOGGER.info("The configuration file does not have option %s" % thread_option)
            return get_defult_thread_num()
    except NoSectionError:
        LOGGER.error("The configuration file does not exists")
        return get_defult_thread_num()
    except NoOptionError:
        LOGGER.error("The configuration file does not have option %s" % thread_option)
        return get_defult_thread_num()
    except Exception as e:
        LOGGER.error(f"failed to get module thread num, {e}")
        return get_defult_thread_num()


def check_cpu_list_invalid(cpu_list):
    # 0,1 id 不绑死轮， 2，3，4，5当前ulog写死需要绑核
    invalid_list = [0, 1, 2, 3, 4, 5]
    all_cpu_list = get_all_cpu_list()
    for i in cpu_list:
        if i in invalid_list and get_value("cantian_in_container") == "0":
            LOGGER.error(f"invalid cpu id, id is {i}")
            return True
        if i not in all_cpu_list:
            LOGGER.error(f"invalid cpu id, id is {i}")
            return True
    
    return False


def get_filter_cpu_list():
    module_list = [IOD_MODULE, XNET_MODULE, ULOG_MODULE]
    numa_config = get_numa_config(CONFIG_PATH)
    filter_cpu_list = []

    for module_name in module_list:
        module_info = numa_config.get(module_name, "")
        if module_info == "off":
            continue
        if module_name == IOD_MODULE:
            numa_config[module_name] = "off"
        if module_info == "":
            if module_name == ULOG_MODULE and get_value("cantian_in_container") == "0":
                module_cpu_list = [2, 3, 4, 5]
            else:
                module_thread_num = get_module_thread_num(module_name)
                module_cpu_list = get_module_defult_cpu_list(filter_cpu_list, module_thread_num)
            filter_cpu_list += module_cpu_list
            numa_config[module_name] = ",".join(map(str, module_cpu_list))
            continue
        module_cpu_list = cpu_info_to_cpu_list(module_info)
        if check_cpu_list_invalid(module_cpu_list):
            if get_value("cantian_in_container") != "0":
                module_thread_num = get_module_thread_num(module_name)
                module_cpu_list = get_module_defult_cpu_list(filter_cpu_list, module_thread_num)
                filter_cpu_list += module_cpu_list
                numa_config[module_name] = ",".join(map(str, module_cpu_list))
                continue
            if module_name == ULOG_MODULE:
                module_cpu_list = [2, 3, 4, 5]
                filter_cpu_list += module_cpu_list
                numa_config[module_name] = ",".join(map(str, module_cpu_list))
                continue
            msg = "failed to get module cpu list, The list contains invalid values 0-5"
            LOGGER.error(msg)
            raise Exception(msg)
        filter_cpu_list += module_cpu_list
        
    update_numa_config_file(CONFIG_PATH, numa_config)
    return filter_cpu_list


def get_cantian_numa_info():
    """
    Get the cantian CPU string 
    """
    # x86 不配绑核
    if platform.machine() != 'aarch64':
        LOGGER.info("system is not aarch64")
        return ""
    
    cpu_list = get_all_cpu_list()
    filter_list = get_filter_cpu_list()

    return cpu_list_to_cpu_info(cpu_list, filter_list)


def get_mysql_numa_info_in_container():
    cpu_list = get_all_cpu_list()
    index = int(len(cpu_list) / 2)
    cpu_group_list = [cpu_list[:index], cpu_list[index:]]
    filter_list = get_filter_cpu_list()
    result_ranges = []
    for cpu_l in cpu_group_list:
        result_ranges.append(cpu_list_to_cpu_info(cpu_l, filter_list))
    return " ".join(result_ranges)


def get_mysql_numa_info():
    """
    Get the mysql CPU string 
    """
    # x86 不配绑核
    if platform.machine() != 'aarch64':
        LOGGER.info("system is not aarch64")
        return ""
    if get_value("cantian_in_container") != "0":
        return get_mysql_numa_info_in_container()
    
    if not os.path.exists('/usr/bin/lscpu'):
        LOGGER.error("Warning: lscpu path get error")
        return ""
    
    filter_list = get_filter_cpu_list()
    ret_code, result, stderr = _exec_popen('/usr/bin/lscpu | grep -i "NUMA node(s)"')
    if ret_code:
        err_msg = "can not get numa node parameters, err: %s" % stderr
        LOGGER.error(err_msg)
        raise Exception(err_msg)
    _result = result.strip().split(':')

    if len(_result) != 2:
        LOGGER.error("Warning: numa get error, result:%s" % result)
        return ""
    if not _result[1].strip().isdigit():
        LOGGER.error("Warning: numa(s) size get error, result:%s" % result)
        return ""
    
    max_numa_num = int(_result[1].strip())
    numa_num = 0
    result_ranges = []
    while numa_num < max_numa_num:
        err_code, ans, stderr = _exec_popen('/usr/bin/lscpu | grep -i "NUMA node%s"' % numa_num)
        if err_code:
            err_msg = "can not get numa node parameters, err: %s" % stderr
            LOGGER.error(err_msg)
            raise Exception(err_msg)
        _ans = ans.strip().split(':')
        if len(_ans) != 2:
            LOGGER.info("Warning: numa node get error, ans:%s" % ans)
            return ""
        
        numa_id_list = cpu_info_to_cpu_list(_ans[1])
        if numa_id_list is None:
            msg = "get cpu list failed"
            LOGGER.error(msg)
            raise Exception(msg)
        result_ranges.append(cpu_list_to_cpu_info(numa_id_list, filter_list))
        numa_num += 1
    return " ".join(result_ranges)


def update_numa_config():
    """
    Update the file with two parameters, CANTIAN_NUMA_CPU_INFO and MYSQL_NUMA_CPU_INFO
    """

    if platform.machine() != 'aarch64':
        LOGGER.info("system is not aarch64")
        return

    if not os.path.exists(CONFIG_PATH):
        LOGGER.error("ERROR: numa_config.json does not exists")
        return

    cantian_numa_info = get_cantian_numa_info()
    mysql_numa_info = get_mysql_numa_info()
    config_json = get_numa_config(CONFIG_PATH)
    config_json[CANTIAN_NUMA_INFO] = cantian_numa_info
    config_json[MYSQL_NUMA_INFO] = mysql_numa_info
    update_numa_config_file(NUMA_CONFIG_PATH, config_json)
    LOGGER.info("Success to create new numa json config")


def update_dbstor_config_file():
    """
    Modify the dbstor config file and add three new parameters
    XNET_CPU, ULOG_CPU and IOD_CPU
    """

    if platform.machine() != 'aarch64':
        LOGGER.info("system is not aarch64")
        return

    config_json = get_numa_config(NUMA_CONFIG_PATH)
    module_list = [IOD_MODULE, XNET_MODULE, ULOG_MODULE]
    module_key_list = ["IOD_CPU", "XNET_CPU", "ULOG_CPU"]
    for index, value in enumerate(module_list):
        if config_json[value] != "" and config_json[value] != "off":
            cpu_list = get_module_cpu_list(value)
            cpu_info = cpu_list_to_cpu_info(cpu_list)
            update_dbstore_conf("add", module_key_list[index], cpu_info)
    
    LOGGER.info("Success to update dbstor ini config")


def update_cantian_config_file():
    if platform.machine() != 'aarch64':
        LOGGER.info("system is not aarch64")
        return
    cantian_conf_file = os.path.join(CONFIG_DIR, "cfg", "cantiand.ini")
    if not os.path.exists(cantian_conf_file):
        return
    mysql_numa_info = get_mysql_numa_info()
    shm_mysql_info = ";".join([mysql_numa_info] * 6)
    count = 0
    with open(cantian_conf_file, "r", encoding="utf-8") as file:
        config = file.readlines()
    for index, item in enumerate(config):
        if count == 2:
            break
        if "=" not in item:
            continue
        key, _ = item.split("=", maxsplit=1)
        key = key.strip()
        if key == "SHM_MYSQL_CPU_GROUP_INFO":
            config[index] = f"{key} = {shm_mysql_info}\n"
            count += 1
        elif key == "SHM_CPU_GROUP_INFO":
            config[index] = f"{key} = {mysql_numa_info}\n"
            count += 1
        continue    
    
    flags = os.O_RDWR
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(cantian_conf_file, flags, modes), "w") as file_obj:
        file_obj.writelines(config)
    LOGGER.info("Success to update cantian ini config")


def init_numa_config():
    numa_config = {
        "XNET_NUMA_ID": "",
        "ULOG_NUMA_ID": "off",
        "IOD_NUMA_ID": "off"
    }
    update_numa_config_file(CONFIG_PATH, numa_config)


if __name__ == "__main__":
    _param = sys.argv[1]
    try:
        res = execute_fun_with_param(_param)
    except Exception as e:
        LOGGER.error(f"Failed to execute execute_fun_with_param, param is {_param}")
        raise e
