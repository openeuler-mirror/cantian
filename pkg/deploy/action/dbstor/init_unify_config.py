import os
import platform
import json
import sys
import stat
import logging
import subprocess
from configparser import ConfigParser

DBSTORE_LOG_PATH = "/opt/cantian/dbstor"
LOG_PATH = "/opt/cantian/log/dbstor"
LOG_FILE = "/opt/cantian/log/dbstor/install.log"
JS_CONF_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../config/deploy_param.json")
DBSTOR_CONF_FILE = "/mnt/dbdata/remote/share_"
CONTAINER_DBSTOR_CONF_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../config/container")
DOCKER_DBSTOR_CONF_FILE = "/home/regress/cantian_data"
SECTION = 'CLIENT'
MAX_DIRECTORY_MODE = 0o755
PYTHON242 = "2.4.2"
PYTHON25 = "2.5"
TIMEOUT_COUNT = 1800

gPyVersion = platform.python_version()

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger_handle = logging.FileHandler(LOG_FILE, 'a', "utf-8")

logger_handle.setLevel(logging.DEBUG)
logger_formatter = logging.Formatter('[%(asctime)s]-[%(filename)s]-[line:%(lineno)d]-[%(levelname)s]-'
                            '%(message)s-[%(process)s]')
logger_handle.setFormatter(logger_formatter)
logger.addHandler(logger_handle)

def _exec_popen(cmd, values=None):
    """
    subprocess.Popen in python2 and 3.
    :param cmd: commands need to execute
    :return: status code, standard output, error output
    """
    if not values:
        values = []
    bash_cmd = ["bash"]
    p_obj = subprocess.Popen(bash_cmd, shell=False, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if gPyVersion[0] == "3":
        p_obj.stdin.write(cmd.encode())
        p_obj.stdin.write(os.linesep.encode())
        for value in values:
            p_obj.stdin.write(value.encode())
            p_obj.stdin.write(os.linesep.encode())
        stdout, stderr = p_obj.communicate(timeout=TIMEOUT_COUNT)
        stdout = stdout.decode()
        stderr = stderr.decode()
    else:
        p_obj.stdin.write(cmd)
        p_obj.stdin.write(os.linesep)
        for value in values:
            p_obj.stdin.write(value)
            p_obj.stdin.write(os.linesep)
        stdout, stderr = p_obj.communicate(timeout=TIMEOUT_COUNT)

    if stdout[-1:] == os.linesep:
        stdout = stdout[:-1]
    if stderr[-1:] == os.linesep:
        stderr = stderr[:-1]
    return p_obj.returncode, stdout, stderr

class ConfigTool:
    def __init__(self) -> None:
        self.conf_file_path = ""
        self.dbstor_conf_file = ""
        self.dbstor_config = {}
        self.node_id = ""
        self.cluster_name = ""
        self.cluster_id = ""
        self.cantian_in_container = ""
        self.dbstore_fs_vstore_id = "0"
        self.dbstor_page_fs_vstore_id = "0"
        self.dbstor_home="/opt/cantian/dbstor"
        self.dbstor_log_path="/opt/cantian/log/dbstor"
        self.dbstor_config_tmp = {  # dbstor_config.ini default parameters
            "NAMESPACE_FSNAME": "",
            "NAMESPACE_PAGE_FSNAME": "",
            "DPU_UUID": "",
            "LINK_TYPE": "",
            "LOCAL_IP": "",
            "REMOTE_IP": "",
            "NODE_ID": "",
            "USER_NAME": "",
            "PASSWORD": "",
            "CLUSTER_ID": "",
        }
        self.dbstor_config = self.dbstor_config_tmp
        with os.fdopen(os.open(JS_CONF_FILE, os.O_RDONLY | os.O_EXCL, stat.S_IWUSR | stat.S_IRUSR), "r")\
                as file_handle:
            json_data = json.load(file_handle)
            self.node_id = json_data.get('node_id', "").strip()
            self.cluster_id = json_data.get('cluster_id', "").strip()
            self.cantian_in_container = json_data.get('cantian_in_container', "0").strip()
            self.dbstore_fs_vstore_id = json_data.get('dbstore_fs_vstore_id', "0").strip()
            self.cluster_name = json_data.get("cluster_name", '')
            
    def create_unify_dbstor_config(self):
        logger.info('Deploy_mode = dbstor, begin to set config.')
        config = ConfigParser()
        config.optionxform = str
        conf_file_path = "/opt/cantian/dbstor/tools"
        dbstor_conf_file = os.path.join(conf_file_path, "dbstor_config.ini")
        config.read(dbstor_conf_file)
        split_env = os.environ['LD_LIBRARY_PATH'].split(":")
        filtered_env = [single_env for single_env in split_env if "/opt/cantian/dbstor/lib" not in single_env]
        os.environ['LD_LIBRARY_PATH'] = ":".join(filtered_env)
        for i in range(7,11):
            file_num = i - 6
            cmd = "python3 %s/../obtains_lsid.py %s %s %s %s"
            ret_code, stdout, stderr = _exec_popen(cmd % ("/opt/cantian/action/dbstor", 2, self.cluster_id, i, self.node_id))
            if ret_code:
                raise OSError("Failed to execute LSIDGenerate."
                    " Error: %s" % (stderr + os.linesep + stderr))
            data = stdout.split("\n")
            if len(data) == 2:
                inst_id, dbs_tool_uuid = data[0], data[1]
            else:
                raise ValueError("Data parse error: length of parsed data is not 2.")
            logger.info('Generate inst_id, dbs_tool_uuid success.')
            ret_code, stdout, stderr = _exec_popen(cmd % ("/opt/cantian/action/dbstor", 0, self.cluster_id, 0, 0))
            if ret_code:
                raise OSError("Failed to execute LSIDGenerate."
                    " Error: %s" % (stderr + os.linesep + stderr))
            data = stdout.split("\n")
            if len(data) == 2:
                self.cluster_uuid = data[1]
            else:
                raise ValueError("Data parse error: length of parsed data is not 2.")
            logger.info('Generate cluster_uuid success.')
            folder_path = "%s/conf/dbs/" % (self.dbstor_home)
            if not os.path.exists(folder_path):
                os.makedirs(folder_path)
            config.set('CLIENT', 'DBSTOR_OWNER_NAME', 'dbstor')    
            config.set('CLIENT', 'CLUSTER_NAME', str(self.cluster_name))
            config.set('CLIENT', 'CLUSTER_UUID', str(self.cluster_uuid))
            config.set('CLIENT', 'INST_ID', inst_id)      
            config.set('CLIENT', 'DBS_TOOL_UUID', dbs_tool_uuid)
            config.set('CLIENT', 'DBS_LOG_PATH', self.dbstor_log_path)
            flags = os.O_CREAT | os.O_RDWR
            modes = stat.S_IWUSR | stat.S_IRUSR
            file_path = "%s/conf/dbs/dbstor_config_tool_%s.ini" % (self.dbstor_home, str(file_num))
            with os.fdopen(os.open(file_path, flags, modes), "w") as file_obj:
                config.write(file_obj)
        logger.info('Set config success.')

if __name__ == '__main__':
    configTool = ConfigTool()
    configTool.create_unify_dbstor_config()