import argparse
import datetime
import logging
import os.path
import re
import subprocess
import shutil
import stat
import time
import json
from logging import handlers
import sys
from config import INST_CONFIG, VG_CONFIG
from pathlib import Path

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from cantian_common.exec_sql import exec_popen
from cantian_common.get_config_info import get_value


CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCE_DIR = os.path.join(Path(CURRENT_DIR).parent.parent, "dss")
LOG_FILE = r"/opt/cantian/log/dss/dss_deploy.log"
DSS_HOME = "/opt/cantian/dss"
DSS_LOG = "/opt/cantian/log/dss"
CMS_HOME = "/opt/cantian/cms/service"
DSS_CFG = "/opt/cantian/dss/cfg"
BACKUP_NAME = "/opt/cantian/backup/files/dss"
SCRIPTS_DIR = "/opt/cantian/action/dss"
DSS_CTRL_SCRIPTS = "%s/dss_contrl.sh" % SCRIPTS_DIR
INSTALL_FILE = "/opt/cantian/config/deploy_param.json"
RETRY_TIMES = 20
TIMEOUT = 60

CAP_WIO = "CAP_SYS_RAWIO"
CAP_ADM = "CAP_SYS_ADMIN"


# 日志组件
def setup():
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)

    log = logging.getLogger("dss")
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


class ComOpt:
    @staticmethod
    def write_ini(file_path: str, contents: dict, split="=") -> None:
        content = []
        for key in contents.keys():
            content.append("{}{}{}".format(key, split, contents[key]))
        modes = stat.S_IWRITE | stat.S_IRUSR
        flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT
        with os.fdopen(os.open(file_path, flags, modes), 'w', encoding='utf-8') as file:
            file.write("\n".join(content))
        os.chmod(file_path, 0o640)

    @staticmethod
    def read_ini(file_path: str) -> str:
        with open(file_path, 'r', encoding="utf-8") as file:
            return file.read()


class DssCtl(object):
    def __init__(self):
        self.dss_inst_cfg = os.path.join(DSS_CFG, "dss_inst.ini")
        self.dss_vg_cfg = os.path.join(DSS_CFG, "dss_vg_conf.ini")
        self.node_id = get_value("node_id")
        self.cms_ip = get_value("cms_ip")
        self.mes_ssl_switch = get_value("mes_ssl_switch")
        self.ca_path = get_value("ca_path")
        self.crt_path = get_value("crt_path")
        self.key_path = get_value("key_path")
        self.log_file = os.path.join(DSS_LOG, "run/dssinstance.rlog")
        self.begin_time = None

    @staticmethod
    def modify_env(action="add") -> None:
        """
        modify user environment variables
           exp: DSS_HOME
                LD_LIBRARY_PATH
                PATH
        :param action: add/delete
        :return:
        """
        home_directory = os.path.expanduser('~')
        bashrc_path = os.path.join(home_directory, '.bashrc')
        with open(bashrc_path, 'r') as bashrc_file:
            bashrc_content = bashrc_file.readlines()
        env = [
            "export DSS_HOME=%s\n" % DSS_HOME,
            "export LD_LIBRARY_PATH=%s:$LD_LIBRARY_PATH\n" % os.path.join(DSS_HOME, "lib"),
            "export PATH=%s:$PATH\n" % os.path.join(DSS_HOME, "bin")
        ]
        for line in env:
            if action == "add":
                if line not in bashrc_content:
                    bashrc_content.append(line)
            if action == "delete":
                if line in bashrc_content:
                    bashrc_content.remove(line)

        modes = stat.S_IWRITE | stat.S_IRUSR
        flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT
        with os.fdopen(os.open(bashrc_path, flags, modes), 'w', encoding='utf-8') as bashrc_file:
            bashrc_file.writelines(bashrc_content)

    @staticmethod
    def kill_cmd(cmd: str) -> None:
        return_code, stdout, stderr = exec_popen(cmd, timeout=TIMEOUT)
        if return_code:
            output = stdout + stderr
            err_msg = "Dssserver is offline: %s" % str(output)
            LOG.info(err_msg)
        if stdout:
            LOG.info("dss server pid is[%s].", stdout)
            for line in re.split(r'\n\s', stdout):
                kill_cmd = "kill -9 %s" % line.strip()
                return_code, stdout, stderr = exec_popen(kill_cmd, timeout=TIMEOUT)
                if return_code:
                    output = stdout + stderr
                    err_msg = "Exec kill cmd[%s] failed, details: %s" % (cmd, str(output))
                    LOG.error(err_msg)

    def wait_dss_instance_started(self):
        LOG.info("Waiting for dss_instance to start...")
        timeout = 60
        while timeout:
            time.sleep(5)
            timeout = timeout - 5
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r', errors='ignore') as f:
                    all_the_text = f.read()
                succ_pattern = re.compile(r'.*(\d{4}\-\d{2}\-\d{2} \d{2}\:\d{2}\:\d{2}).*?DSS SERVER STARTED.*?',
                                          re.IGNORECASE)
                fail_pattern = re.compile(r'.*(\d{4}\-\d{2}\-\d{2} \d{2}\:\d{2}\:\d{2}).*?dss failed to startup.*?',
                                          re.IGNORECASE)
                succ_timestamps = re.findall(succ_pattern, all_the_text)
                fail_timestamps = re.findall(fail_pattern, all_the_text)
                is_instance_started = len(succ_timestamps) != 0 and max(succ_timestamps) >= self.begin_time
                is_instance_failed = len(fail_timestamps) != 0 and max(fail_timestamps) >= self.begin_time
                if is_instance_started:
                    LOG.info("DSS server started successfully.")
                    return
                if is_instance_failed:
                    err_msg = "DSS server start failed."
                    LOG.error(err_msg)
                    raise Exception(err_msg)
        else:
            err_msg = "Start dss server timeout"
            LOG.error(err_msg)
            raise Exception(err_msg)

    def dss_cmd_add_vg(self) -> None:
        """
        create volume by dsscmd.
        :return:
        """
        if self.node_id == "0":
            LOG.info("Start to exec dsscmd cv.")
            dsscmd = "source ~/.bashrc && dsscmd cv -g %s -v %s"
            for key, value in VG_CONFIG.items():
                return_code, stdout, stderr = exec_popen(dsscmd % (key, value), timeout=TIMEOUT)
                if return_code:
                    output = stdout + stderr
                    err_msg = "Dsscmd cv cmd[%s] exec failed, details: %s" % (dsscmd % (key, value), str(output))
                    raise Exception(err_msg)
            LOG.info("Success to exec dsscmd cv.")
        else:
            LOG.info("No need to exec dsscmd cv for node[%s].", self.node_id)

    def prepare_dss_dick(self) -> None:
        """
        Initialization disk
        :return:
        """
        if self.node_id == "0":
            LOG.info("start to init lun.")
            init_cmd = "dd if=/dev/zero of=%s bs=1M count=1 conv=notrunc"
            for key, value in VG_CONFIG.items():
                return_code, stdout, stderr = exec_popen(init_cmd % value, timeout=120)
                if return_code:
                    output = stdout + stderr
                    err_msg = "Init lun cmd[%s] exec failed, details: %s" % (init_cmd % value, str(output))
                    raise Exception(err_msg)
                LOG.info("Init lun cmd[] exec success.", init_cmd)
            LOG.info("Success to init lun.")
        else:
            LOG.info("No need to init lun for node[%s].", self.node_id)

    def prepare_cfg(self) -> None:
        """
        prepare dss config: dss_vg.ini/dss_inst.ini
        :return:
        """
        if not os.path.exists(DSS_HOME):
            os.makedirs(DSS_HOME, exist_ok=True)
        if not os.path.exists(DSS_CFG):
            os.makedirs(DSS_CFG, exist_ok=True)
        ComOpt.write_ini(self.dss_vg_cfg, VG_CONFIG, split=":")
        INST_CONFIG["INST_ID"] = self.node_id
        INST_CONFIG["DSS_NODES_LIST"] = "0:{}:1811,1:{}:1811".format(self.cms_ip.split(";")[0], self.cms_ip.split(";")[1])
        INST_CONFIG["LSNR_PATH"] = DSS_HOME
        INST_CONFIG["LOG_HOME"] = DSS_LOG
        ComOpt.write_ini(self.dss_inst_cfg, INST_CONFIG)

    def prepare_source(self) -> None:
        """
        prepare dsscmd/dssserver lib and bin
        :return:
        """
        LOG.info("Copy bin and lib source start.")
        if os.path.exists(os.path.join(DSS_HOME, "bin")):
            shutil.rmtree(os.path.join(DSS_HOME, "bin"))
        if os.path.exists(os.path.join(DSS_HOME, "lib")):
            shutil.rmtree(os.path.join(DSS_HOME, "lib"))
        shutil.copytree(os.path.join(SOURCE_DIR, "bin"), os.path.join(DSS_HOME, "bin"))
        shutil.copytree(os.path.join(SOURCE_DIR, "lib"), os.path.join(DSS_HOME, "lib"))
        LOG.info("Copy bin and lib source success.")

    def cms_add_dss_res(self) -> None:
        """
        add dss res for cms
        :return:
        """
        os.chmod(DSS_CTRL_SCRIPTS, 0o700)
        dss_contrl_path = os.path.join(DSS_HOME, "dss_contrl.sh")
        shutil.copyfile(DSS_CTRL_SCRIPTS, dss_contrl_path)
        os.chmod(dss_contrl_path, 0o700)
        if self.node_id == "0":
            LOG.info("Start to add dss res.")
            cmd = ("source ~/.bashrc && %s/bin/cms res -add dss -type dss -attr \"script=%s\""
                   % (CMS_HOME, DSS_CTRL_SCRIPTS))
            return_code, stdout, stderr = exec_popen(cmd, timeout=TIMEOUT)
            if return_code:
                output = stdout + stderr
                err_msg = "Failed to add dss res, details: %s" % (str(output))
                raise Exception(err_msg)
            LOG.info("Success to add dss res.")
        LOG.info("Success to copy dss control script.")

    def config_perctrl_permission(self) -> None:
        """
        config perctl permission for caw write.
        :return:
        """
        LOG.info("Start to config perctrl permission.")
        cap_mode = f"{CAP_ADM},{CAP_WIO}"
        path = f"{DSS_HOME}/bin/perctrl"
        cmd = f'sudo setcap {cap_mode}+ep {path}'
        return_code, stdout, stderr = exec_popen(cmd, timeout=TIMEOUT)
        if return_code:
            output = stdout + stderr
            err_msg = "Failed to config perctl permission, details: %s" % (str(output))
            raise Exception(err_msg)
        LOG.info("Success to config perctrl permission.")

    def check_is_reg(self) -> bool:
        """
        check current node is reg.
        :return:
        """
        kick_cmd = "source ~/.bashrc && %s/bin/dsscmd inq_reg -i %s -D %s" % (DSS_HOME, self.node_id, DSS_HOME)
        return_code, stdout, stderr = exec_popen(kick_cmd, timeout=TIMEOUT)
        if return_code:
            output = stdout + stderr
            err_msg = "Failed to inq_reg disk, details: %s" % (str(output))
            LOG.error(err_msg)
        return "is registered" in str(stdout)

    def kick_node(self):
        """
        kick node before reg.
        :return:
        """
        LOG.info("Start to kick node.")
        kick_cmd = "source ~/.bashrc && %s/bin/dsscmd unreghl -D %s" % (DSS_HOME, DSS_HOME)
        return_code, stdout, stderr = exec_popen(kick_cmd, timeout=TIMEOUT)
        if return_code:
            output = stdout + stderr
            err_msg = "Kick node cmd[%s] exec failed, details:%s" % (kick_cmd, output)
            raise Exception(err_msg)
        LOG.info("Success to kick node.")

    def reghl_dss_disk(self) -> None:
        """
        reg current by dsscmd, dssserver is offline
        :return:
        """
        LOG.info("Start to reghl disk.")
        if self.check_is_reg():
            self.kick_node()
        reg_cmd = "source ~/.bashrc && %s/bin/dsscmd reghl -D %s" % (DSS_HOME, DSS_HOME)
        return_code, stdout, stderr = exec_popen(reg_cmd, timeout=TIMEOUT)
        if return_code:
            output = stdout + stderr
            err_msg = "Reghl node cmd[%s] exec failed, details:%s" % (reg_cmd, output)
            raise Exception(err_msg)
        LOG.info("Success to reghl disk.")

    def clean_soft(self):
        """
        clean soft, bin/lib/cfg, keep logs
        :return:
        """
        LOG.info("Start to clean soft.")
        if os.path.exists(os.path.join(DSS_HOME, "lib")):
            shutil.rmtree(os.path.join(DSS_HOME, "lib"))
        if os.path.exists(os.path.join(DSS_HOME, "bin")):
            shutil.rmtree(os.path.join(DSS_HOME, "bin"))
        if os.path.exists(DSS_CFG):
            shutil.rmtree(DSS_CFG)
        LOG.info("Success to clean soft.")

    def pre_install(self, *args) -> None:
        """
        pre-check before install
        :param args:
        :return:
        """
        LOG.info("Start to pre install.")
        LOG.info("Success to pre install.")

    def install(self, *args) -> None:
        """
        install dss:
           add user environment variables;
           prepare dss lib and bin source;
           add res;
           reg current node to dssserver ;
           init disk;
           create vg by dsscmd;
        :param args:
        :return:
        """
        self.modify_env(action="add")
        self.prepare_cfg()
        self.prepare_source()
        self.cms_add_dss_res()
        self.config_perctrl_permission()
        
        with open(INSTALL_FILE, encoding="utf-8") as f:
            _tmp = f.read()
            info = json.loads(_tmp)
            dss_install_type = info.get("install_type", "")
        
        LOG.info("dss_install_type is %s", dss_install_type)
        
        if dss_install_type != "reserve":
            self.prepare_dss_dick()
            self.reghl_dss_disk()
            self.dss_cmd_add_vg()

    def backup(self, *args) -> None:
        LOG.info("Start backup.")
        if not os.path.exists(BACKUP_NAME):
            os.makedirs(BACKUP_NAME, exist_ok=True)
        shutil.copytree(DSS_CFG, BACKUP_NAME,
                        symlinks=False, ignore=None,
                        copy_function=shutil.copy2,
                        ignore_dangling_symlinks=False)
        if not os.path.exists(os.path.join(BACKUP_NAME, "scripts")):
            os.makedirs(os.path.join(BACKUP_NAME, "scripts"))
        shutil.copytree(SCRIPTS_DIR, os.path.join(BACKUP_NAME, "scripts"))
        LOG.info("Success to backup.")

    def uninstall(self, *args) -> None:
        """
        uninstall dss:
           - clean user environment variables;
           - clean soft.
        :param args:
        :return:
        """
        self.modify_env(action="delete")
        self.clean_soft()

    def start(self, *args) -> None:
        """
        start dss server:
             - check dss server status
             - register dss disk
             - start dss server
        :param args:
        :return:
        """
        LOG.info("Start dss server.")
        if self.check_status():
            return
        self.reghl_dss_disk()
        self.begin_time = str(datetime.datetime.now()).split(".")[0]
        dssserver_cmd = "source ~/.bashrc && nohup dssserver -D %s &" % DSS_HOME
        subprocess.Popen(dssserver_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.wait_dss_instance_started()
        if self.check_status():
            LOG.info("Success to start dss server.")
        else:
            err_msg = "Failed to start dss server."
            LOG.error(err_msg)
            raise Exception(err_msg)

    def stop(self, *args) -> None:
        """
        1、stop dssserver
        2、stop perctrl
        :param args:
        :return:
        """
        LOG.info("Start to stop dss server.")
        dss_server_pid = "pidof dssserver"
        self.kill_cmd(dss_server_pid)
        LOG.info("Success to stop dss server.")
        LOG.info("Start to stop perctrl.")
        perctrl_pid = "ps -ef | grep perctrl | grep -v grep | awk '{print $2}'"
        self.kill_cmd(perctrl_pid)
        LOG.info("Success to stop perctrl.")

    def check_status(self, *args) -> bool:
        LOG.info("Start check status start")
        check_cmd = "ps -ef | grep dssserver | grep -v grep | grep %s" % DSS_HOME
        _, stdout, stderr = exec_popen(check_cmd, timeout=TIMEOUT)
        if stdout:
            LOG.info("dssserver is online, status: %s" % stdout)
            return True
        else:
            LOG.info("dssserver is offline.")
            return False
    
    def upgrade_backup(self, *args) -> None:
        LOG.info("Start to upgrade_backup dss.")
        LOG.info("Success to upgrade_backup dss.")


def main():
    parse = argparse.ArgumentParser()
    parse.add_argument("--action", type=str,
                       choices=["install", "uninstall", "start", "stop", "pre_install",
                                "upgrade", "rollback", "pre_upgrade", "check_status", "upgrade_backup"])
    parse.add_argument("--mode", required=False, dest="mode", default="")
    arg = parse.parse_args()
    act = arg.action
    dss_opt = DssCtl()
    getattr(dss_opt, act)(arg.mode)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        LOG.error(str(err))
        exit(str(err))
    exit(0)