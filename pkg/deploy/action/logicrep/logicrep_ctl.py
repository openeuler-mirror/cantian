import os
import sys
import re
import json
import stat
import argparse
import logging
import time
import glob
from get_config_info import get_value
from logging import handlers

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                             "inspection", "inspection_scripts", "ct_om"))

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dbstor"))
from kmc_adapter import CApiWrapper

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cantian"))
from Common import DefaultValue

CMD_CREATE_LREP = f"CREATE USER LREP IDENTIFIED BY '%s'; \
CREATE TABLE LREP.LOGICREP_PROGRESS( \
ID VARCHAR(128), \
COMMITTED_TX_SCN BIGINT, \
COMMITTED_TX_TIME TIMESTAMP, \
LOGPOINT VARCHAR(128), \
UPDATE_TIME TIMESTAMP, \
INSERT_NUM BIGINT, \
UPDATE_NUM BIGINT, \
DELETE_NUM BIGINT, \
LAST_SEQ BIGINT, \
START_LOGPOINT VARCHAR(128), \
SPEED_UPDATE_TIME TIMESTAMP, \
PROCESS_SPEED DOUBLE, \
REDO_GEN_SPEED DOUBLE); \
CREATE UNIQUE INDEX IX_LREP_PROGRESS ON LREP.LOGICREP_PROGRESS(ID); \
"
CMD_GRANT = f"GRANT CONNECT, RESOURCE TO LREP; \
GRANT SELECT ON SYS.SYS_TABLES TO LREP; \
GRANT SELECT ON SYS.SYS_COLUMNS TO LREP; \
GRANT SELECT ON SYS.SYS_USERS TO LREP; \
GRANT SELECT ON SYS.SYS_CONSTRAINT_DEFS TO LREP; \
GRANT SELECT ON SYS.SYS_LOGIC_REPL TO LREP; \
GRANT SELECT ON SYS.DV_DATABASE TO LREP; \
GRANT SELECT ON SYS.DV_LOG_FILES TO LREP; \
GRANT SELECT ON SYS.DV_ARCHIVED_LOGS TO LREP; \
GRANT SELECT ON SYS.SYS_INDEXES TO LREP; \
GRANT SELECT ON SYS.SYS_SEQUENCES TO LREP; \
GRANT SELECT ON SYS.ADM_FREE_SPACE TO LREP; \
GRANT SELECT ON SYS.DV_TEMP_ARCHIVED_LOGS TO LREP; \
GRANT SELECT ON SYS.DV_LFNS TO LREP; \
GRANT SELECT ON SYS.SYS_TABLEMETA_DIFF TO LREP; \
GRANT SELECT ON SYS.SYS_COLUMNMETA_HIS TO LREP; \
GRANT SELECT ON SYS.DV_SYS_STATS TO LREP; \
"
CMD_CREATE_PROFILE = f"CREATE PROFILE LREP_PROFILE LIMIT SESSIONS_PER_USER 100; \
ALTER USER LREP PROFILE LREP_PROFILE;"
CMD_RESOURCE_LIMIT = f"ALTER SYSTEM SET RESOURCE_LIMIT=TRUE;"
CMD_OPEN = "ALTER DATABASE ENABLE_LOGIC_REPLICATION ON;"
CMD_CLOSE = "ALTER DATABASE ENABLE_LOGIC_REPLICATION OFF;"
CMD_CHECK_OPEN = "SELECT LREP_MODE FROM SYS.DV_DATABASE;"
CMD_CHECK_ACTIVE = "SELECT * FROM DV_LRPL_DETAIL;"
DV_LRPL_DETAIL = "select * from DV_LRPL_DETAIL;"
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
CTSQL_INI_PATH = r'/mnt/dbdata/local/cantian/tmp/data/cfg/*sql.ini'
PRIMARY_KEYSTORE = r"/opt/cantian/common/config/primary_keystore_bak.ks"
STANDBY_KEYSTORE = r"/opt/cantian/common/config/standby_keystore_bak.ks"
CANTIAN_CONFIG = os.path.join(CURRENT_PATH, "..", "..", "config", "deploy_param.json")

LOG_FILE = r"/opt/cantian/logicrep/log/logicrep_deploy.log"
RETRY_TIMES = 20


# 日志组件
def setup():
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)

    log = logging.getLogger("logicrep")
    for handler in list(log.handlers):
        log.removeHandler(handler)

    file_log = handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=6291456,
        backupCount=5)
    log.addHandler(file_log)
    log.addHandler(console)

    for handler in log.handlers:
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s %(levelname)s [pid:%(process)d] [%(threadName)s]"
                    " [tid:%(thread)d] [%(filename)s:%(lineno)d %(funcName)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"))
    log.setLevel(logging.INFO)
    return log


LOG = setup()


def file_reader(file_path):
    with open(file_path, 'r', encoding="utf-8") as file:
        return file.read()


def file_lines_reader(file_path):
    with open(file_path, 'r', encoding="utf-8") as file:
        return file.readlines()


# 标记LREP用户已创建
class USEREXIST(Exception):
    def __init__(self, errorinfo):
        super().__init__(self)
        self.errorinfo = errorinfo

    def __str__(self):
        return self.errorinfo


class Logicrep:
    def __init__(self, mode="active"):
        self.logicrep_user = ""
        self.storage_archive_fs = ""
        self.deploy_mode = "nas"
        self.cantian_in_container = get_value("cantian_in_container")
        self.home = r"/opt/software/tools/logicrep"
        self.init_conf_file = os.path.join(self.home, "conf", "init.properties")
        self.conf_file = os.path.join(self.home, "conf", "datasource.properties")
        self.key1_file = os.path.join(self.home, "conf", "sec", "primary_keystore.ks")
        self.key2_file = os.path.join(self.home, "conf", "sec", "standby_keystore.ks")
        self.node_id = ""
        self.cmsip = []
        self.lsnr_port = "1611"
        self.passwd = ""
        self.mode = mode

    @staticmethod
    def kmc_resovle_password(mode, plain_text, key1=PRIMARY_KEYSTORE, key2=STANDBY_KEYSTORE):
        kmc_adapter = CApiWrapper(primary_keystore=key1, standby_keystore=key2)
        kmc_adapter.initialize()
        try:
            if mode == "encrypted":
                ret_pwd = kmc_adapter.encrypt(plain_text)
            if mode == "decrypted":
                ret_pwd = kmc_adapter.decrypt(plain_text)
        except Exception as error:
            raise Exception("Failed to %s password. output: %s" % (mode, error)) from error

        split_env = os.environ['LD_LIBRARY_PATH'].split(":")
        filtered_env = [single_env for single_env in split_env if "/opt/software/tools/logicrep/lib" not in single_env]
        os.environ['LD_LIBRARY_PATH'] = ":".join(filtered_env)
        kmc_adapter.finalize()

        return ret_pwd

    @staticmethod
    def run_cmd(cmd):
        code, stdout, stderr = DefaultValue.exec_popen(cmd)
        if code or stderr or code is None:
            output = "%s%s" % (str(stdout), str(stderr))
            raise Exception("Execute %s failed. output:%s" % (cmd, output))
        return stdout

    @staticmethod
    def pre_upgrade():
        LOG.info("begin logicrep check")
        try:
            import cantian_om_logicrep_check
        except Exception as error:
            raise Exception(f"import inspection failed. Error info : {str(error)}") from error

        far = cantian_om_logicrep_check.LogicrepChecker()
        result = far.get_format_output()
        if result['error']['code'] == -1:
            raise Exception(f"check failed.Error info : {result['error']['description']}")
        LOG.info("logicrep check success")

    # 获取用户信息
    def set_cantian_conf(self, mode=None):
        LOG.info("begin get cantian config")
        info = json.loads(file_reader(CANTIAN_CONFIG))
        self.cmsip = info.get("cms_ip").split(";")
        self.node_id = info.get("node_id")
        if mode == "install" or mode == "init_container":
            self.storage_archive_fs = info.get("storage_archive_fs")
            self.deploy_mode = info.get("deploy_mode")
            ctsql_file = glob.glob(CTSQL_INI_PATH)[0]
            ctsql_ini_data = file_reader(ctsql_file)
            encrypt_pwd = ctsql_ini_data[ctsql_ini_data.find('=') + 1:].strip()
            self.passwd = self.kmc_resovle_password("decrypted", encrypt_pwd)
        else:
            info_list = file_lines_reader(self.conf_file)
            for line in info_list:
                if "ds.username=" in line:
                    self.logicrep_user = line[12:].strip()
                if "ds.passwd=" in line:
                    self.passwd = self.kmc_resovle_password("decrypted",
                                                            line[10:].strip(),
                                                            key1=self.key1_file,
                                                            key2=self.key2_file)
                    break
        if not self.passwd:
            raise Exception("get password failed")

    def execute_sql(self, sql, message):
        if self.pre_execute_sql():
            return self.execute(sql, message)
        else:
            return "LREP_MODE--------------------ON "

    def pre_execute_sql(self):
        """
        容灾场景检查当前版本是否为主站点
        :return:
        """
        try:
            stdout_data = self.execute(DV_LRPL_DETAIL, "Check lrpl role")
        except Exception as _err:
            if "The table or view SYS.DV_LRPL_DETAIL does not exist." in str(_err):
                return True
            else:
                raise _err
        if "PRIMARY" in stdout_data:
            LOG.info("Current mode is primary")
            return True
        LOG.info("Current mode is standby, not allowed to log in to zsql to perform operations.")
        return False

    def execute(self, sql, message):
        for i in range(RETRY_TIMES):
            cmd = "source ~/.bashrc && echo -e '%s' | ctsql sys@%s:%s -q -c \"%s\"" % (
                self.passwd,
                self.cmsip[int(self.node_id)].split(",")[0],
                self.lsnr_port,
                sql)

            return_code, stdout_data, stderr_data = DefaultValue.exec_popen(cmd)
            output = "%s%s" % (str(stdout_data), str(stderr_data))
            result = output.replace("\n", "")

            # 数据库尚未启动完全
            if re.match(".*CT-00827.*", result) or re.match(".*CT-00601.*", result):
                time.sleep(30)
                LOG.info("Try to reconnect to the database, attempt:%s/%s", i + 1, RETRY_TIMES)
                continue

            # 创建失败：改用户已经存在
            if re.match(".*CT-00753.*", result):
                raise USEREXIST("%s already exist,please choose another name" % self.logicrep_user)
            if self.passwd in output:
                output = "execute ctsql failed"
            if return_code:
                raise Exception("Failed to %s by sql, output:%s"
                                % (message, output))

            # return code is 0, but output has error info, CT-xxx, ZS-xxx
            if re.match(".*ZS-00001.*", result):
                return stdout_data
            if re.match(".*CT-\d{5}.*", result) or re.match(".*ZS-\d{5}.*", result):
                raise Exception("Failed to execute sql, output:%s" % output)

            return stdout_data
        else:
            raise Exception("Execute sql timeout.")

    def create_db_user(self):
        self.execute_sql(CMD_CREATE_LREP.replace("LREP", self.logicrep_user)
                         % self.passwd, f"create {self.logicrep_user}")
        self.execute_sql(CMD_GRANT.replace("LREP", self.logicrep_user), f"create {self.logicrep_user}")
        self.execute_sql(CMD_CREATE_PROFILE.replace("LREP", self.logicrep_user), f"create {self.logicrep_user}")

    def set_resource_limit_true(self):
        self.execute_sql(CMD_RESOURCE_LIMIT.replace("LREP", self.logicrep_user), "set resource limit >>>")

    def update_init_properties(self):
        if self.node_id == "1":
            return
        flags = os.O_WRONLY | os.O_CREAT
        modes = stat.S_IWUSR | stat.S_IRUSR
        info_list = file_lines_reader(self.init_conf_file)
        for i, line in enumerate(info_list):
            if "binlog.path=" in line:
                info_list[i] = f"binlog.path=/mnt/dbdata/remote/archive_{self.storage_archive_fs}/\n"
            if "archive.path=" in line:
                info_list[i] = f"archive.path=/mnt/dbdata/remote/archive_{self.storage_archive_fs}/\n"
            if "deploy.mode" in line:
                info_list[i] = f"deploy.mode={self.deploy_mode}\n"
        with os.fdopen(os.open(self.init_conf_file, flags, modes), 'w') as fs:
            fs.writelines(info_list)

    # 秘钥等信息写入
    def write_key(self):
        LOG.info("begin to write key")
        split_env = os.environ['LD_LIBRARY_PATH'].split(":")
        split_env.append("/opt/software/tools/logicrep/lib")
        os.environ['LD_LIBRARY_PATH'] = ":".join(split_env)
        new_encrypt_pwd = self.kmc_resovle_password("encrypted",
                                                    self.passwd,
                                                    key1=self.key1_file,
                                                    key2=self.key2_file)
        url = ""
        for ip in self.cmsip:
            url += f"@{ip}:{self.lsnr_port}"
        info_list = file_lines_reader(self.conf_file)
        for i, line in enumerate(info_list):
            if "ds.url" in line:
                info_list[i] = f"ds.url=newdriver:cantian:{url}?useSSL=false\n"
            elif "ds.username" in line:
                info_list[i] = f"ds.username=LREP\n"
            elif "ds.passwd" in line:
                info_list[i] = f"ds.passwd={new_encrypt_pwd}\n"
                break
        flags = os.O_WRONLY | os.O_CREAT
        modes = stat.S_IWUSR | stat.S_IRUSR
        with os.fdopen(os.open(self.conf_file, flags, modes), 'w') as fs:
            fs.writelines(info_list)

        self.update_init_properties()

    def status_check(self):
        cmd = "ps -ef | grep cantiand | grep /mnt/dbdata/local/cantian/tmp/data | grep -v grep"
        try:
            self.run_cmd(cmd)
        except Exception as _:
            return False
        return True

    def install(self):
        LOG.info("begin install logicrep")
        if self.cantian_in_container == "0":
            self.set_cantian_conf(mode="install")
            self.write_key()
        LOG.info("install logicrep success")

    def init_container(self):
        LOG.info("begin init container logicrep")
        self.set_cantian_conf(mode="init_container")
        self.write_key()
        LOG.info("container init logicrep success")

    def start(self):
        LOG.info("begin create logicrep user")
        self.set_cantian_conf()
        if self.mode == "standby":
            return
        self.create_db_user()
        LOG.info("create logicrep user success")

    def set_resource_limit(self):
        LOG.info("try set resource limit")
        self.set_cantian_conf()
        self.set_resource_limit_true()
        LOG.info("resource limit set success")

    def startup(self):
        LOG.info("begin start logicrep")
        self.set_cantian_conf()
        res = self.execute(CMD_CHECK_ACTIVE, "check active")
        res = res.replace("\n", "")
        if "PHYSICAL_STANDBY" in res:
            raise Exception("standby node can not startup logicrep")
        res = self.execute_sql(CMD_CHECK_OPEN, "check switch")
        res = res.replace("\n", "")
        if re.match(".*LREP_MODE.*OFF.*", res):
            self.execute_sql(CMD_OPEN, "open logicrep switch")
            LOG.info("turn logicrep switch on")
        elif re.match(".*LREP_MODE.*ON.*", res):
            LOG.info("logicrep switch already turn on")

    def stop(self):
        try:
            self.run_cmd(f"cd {self.home} && sh shutdown.sh -n logicrep")
        except Exception as error:
            if "kill: not enough arguments" in str(error):
                pass
            else:
                raise error
        LOG.info("stop logicrep success")

    def shutdown(self):
        LOG.info("begin turn logicrep switch off")
        self.set_cantian_conf()
        if self.status_check():
            self.execute_sql(CMD_CLOSE, "stop logicrep")
        else:
            LOG.error("turn logicrep switch off failed, because cantiand does not exist.")
        self.stop()


# 参数解析
def main():
    ctl_parse = argparse.ArgumentParser()
    ctl_parse.add_argument("--act", type=str,
                           choices=["install", "init_container", "start", "startup", "stop", "shutdown", "pre_upgrade",
                                    "set_resource_limit"])
    ctl_parse.add_argument("--mode", required=False, dest="mode")
    arg = ctl_parse.parse_args()
    act = arg.act
    mode = arg.mode
    logicrep = Logicrep(mode)
    func_dict = {
        "install": logicrep.install,
        "init_container": logicrep.init_container,
        "start": logicrep.start,
        "startup": logicrep.startup,
        "stop": logicrep.stop,
        "shutdown": logicrep.shutdown,
        "pre_upgrade": logicrep.pre_upgrade,
        "set_resource_limit": logicrep.set_resource_limit
    }
    func_dict.get(act)()


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        LOG.error(str(err))
        exit(str(err))
    exit(0)
