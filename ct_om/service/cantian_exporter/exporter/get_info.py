# -*- coding: UTF-8 -*-
import os
import re
import sys
import json
import time
import stat
import signal
import traceback
import subprocess
import glob
from datetime import datetime
from pathlib import Path
from datetime import datetime
from exporter.log import EXPORTER_LOG as LOG
from exporter.tool import SimpleSql
from exporter.tool import _exec_popen
sys.path.append('/opt/cantian/action/dbstor')
from kmc_adapter import CApiWrapper

cur_abs_path, _ = os.path.split(os.path.abspath(__file__))
OLD_CANTIAND_DATA_SAVE_PATH = Path(cur_abs_path, 'cantiand_report_data_saves.json')
DEPLOY_PARAM_PATH = '/opt/cantian/config/deploy_param.json'
CANTIAND_INI_PATH = '/mnt/dbdata/local/cantian/tmp/data/cfg/cantiand.ini'
CANTIAND_LOG_PATH = '/mnt/dbdata/local/cantian/tmp/data/log/run/cantiand.rlog'
CTSQL_INI_PATH = '/mnt/dbdata/local/cantian/tmp/data/cfg/*sql.ini'
PRIMARY_KEYSTORE = "/opt/cantian/common/config/primary_keystore_bak.ks"
STANDBY_KEYSTORE = "/opt/cantian/common/config/standby_keystore_bak.ks"
LOGICREP_START_TIME_PATH = "/opt/software/tools/logicrep/log/start_time"
TIME_OUT = 5
ABNORMAL_STATE, NORMAL_STATE = 1, 0
CONVERT_DICT = {
    "M": 1024 * 1024,
    "G": 1024 * 1024 * 1024,
    "T": 1000 * 1024 * 1024 * 1024,
    "P": 1000 * 1000 * 1024 * 1024 * 1024
}


def file_reader(file_path):
    with open(file_path, 'r') as file:
        return file.read()


def file_writer(file_path, data):
    modes = stat.S_IWRITE | stat.S_IRUSR
    flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT
    if data:
        with os.fdopen(os.open(file_path, flags, modes), 'w', encoding='utf-8') as file:
            file.write(json.dumps(data))
    else:
        with os.fdopen(os.open(file_path, flags, modes), 'w', encoding='utf-8') as file:
            file.truncate()


class GetNodesInfo:
    def __init__(self):
        self.std_output = {'node_id': '', 'stat': '', 'work_stat': 0, 'cluster_name': '', 'cms_ip': '',
                           'cantian_vlan_ip': '', 'storage_vlan_ip': '', 'share_logic_ip': '',
                           'storage_share_fs': '', 'storage_archive_fs': '', 'storage_metadata_fs': '',
                           'data_buffer_size': '', 'log_buffer_size': '', 'log_buffer_count': '',
                           'cluster_stat': '', 'cms_port': '', 'cms_connected_domain': '', 'disk_iostat': '',
                           'mem_total': '', 'mem_free': '', 'mem_used': '', 'cpu_us': '', 'cpu_sy': '', 'cpu_id': '',
                           'sys_backup_sets': {}, 'checkpoint_pages': {}, 'checkpoint_period': {}, 'global_lock': {},
                           'local_lock': {}, 'local_txn': {}, 'global_txn': {}, "dv_lrpl_detail": {},
                           'pitr_warning': '', 'logicrep': ''
                           }

        self.sql = SimpleSql()
        self.kmc_decrypt = CApiWrapper(primary_keystore=PRIMARY_KEYSTORE, standby_keystore=STANDBY_KEYSTORE)
        self.kmc_decrypt.initialize()
        self.deploy_param = None
        self.mes_type = "UC"
        self.node_id = None
        self.decrypt_pwd = None
        self.ctsql_decrypt_error_flag = False
        self.storage_archive_fs = None
        self.dm_pwd = None

        self.sh_cmd = {'top -bn 1 -i': self.update_cpu_mem_info,
                       'source ~/.bashrc&&cms stat': self.update_cms_status_info,
                       'source ~/.bashrc&&cms node -list': self.update_cms_port_info,
                       'source ~/.bashrc&&cms node -connected': self.update_cms_node_connected,
                       'source ~/.bashrc&&cms diskiostat': self.update_cms_diskiostat
                       }
        self.sql_file = os.path.join(cur_abs_path, "../config/get_ctsql_info.sql")
        self.logicrep_sql_file = os.path.join(cur_abs_path, "../config/get_logicrep_info.sql")
        self.reg_string = r'invalid argument'

    @staticmethod
    def ctsql_result_parse(result: str) -> zip:
        """
        解析如下格式的ctsql返回值，exp：
        DRC_RESOURCE         USED         TOTAL        RATIO
        -------------------- ------------ ------------ --------------------
        LOCAL_TXN            0            0            0.00000
        1 rows fetched.

        备份恢复返回示例，取最近一次备份时间
        START_TIME                       COMPLETION_TIME                  MAX_BUFFER_SIZE
        -------------------------------- -------------------------------- ---------------
        2023-10-17 20:00:51.624220       2023-10-17 20:01:32.582088       134217728
        2023-10-17 20:29:06.516188       2023-10-17 20:31:46.508040       134217728
        2023-10-18 10:47:02.172953       2023-10-18 10:50:22.724287       134217728
        2023-10-18 14:27:50.749253       2023-10-18 14:30:18.068850       134217728
        2023-10-18 14:35:46.053201       2023-10-18 14:37:33.633707       134217728

        5 rows fetched.

        """
        res = re.findall(r"(\d+) rows fetched.", result)
        if not res:
            res_count = 1
        else:
            res_count = int(res[0])
        if res_count == 0:
            return zip([], [])
        keys = result.strip().split("\n")[0].strip().split()
        values = re.split(r"\s{2,}", result.strip().split("\n")[res_count + 1].strip())
        return zip(keys, values)

    @staticmethod
    def cantiand_report_handler(dict_data):
        """单独处理data_buffer_size, log_buffer_size, log_buffer_count这三个指标，返回合理的生效的指标值

        data_buffer_size, log_buffer_size, log_buffer_count这三个指标若发生变动，需要重启参天进程才能生效。
        cantian_exporter进程预期应上报生效的指标，为解决此问题，在当前路径创建一个json文件用于记录上一次的上报值
        和参天进程id，每次获取新的指标和当前参天进程id后，与旧数据对比，合理上报数据

        Args:
            dict_data: 字典，键为data_buffer_size等上报指标，值为从cantiand.ini文件实时读取的值
        Return：
            返回一个字典，键同dict_data，值为cantian进程当前生效的值
        """
        cmd = "ps -ef | grep -v grep | grep cantiand | grep -w '\-D " \
              "/mnt/dbdata/local/cantian/tmp/data' | awk '{print $2}'"
        err_code, pidof_cantiand, _ = _exec_popen(cmd)

        if err_code or not pidof_cantiand:
            return {}

        if not os.path.exists(OLD_CANTIAND_DATA_SAVE_PATH):
            record_data = {'report_data': dict_data, 'cantian_pid': pidof_cantiand}
            file_writer(OLD_CANTIAND_DATA_SAVE_PATH, record_data)
            return dict_data

        old_report_data = json.loads(file_reader(OLD_CANTIAND_DATA_SAVE_PATH))
        old_data, old_pidof_cantiand = old_report_data.get('report_data'), old_report_data.get('cantian_pid')
        init_record_data = {'report_data': old_data, 'cantian_pid': pidof_cantiand}
        if old_pidof_cantiand != pidof_cantiand:
            if old_data != dict_data:
                init_record_data['report_data'] = dict_data
            file_writer(OLD_CANTIAND_DATA_SAVE_PATH, init_record_data)
            return dict_data

        return old_data

    @staticmethod
    def get_pitr_data_from_external_exec_cmd(res):
        """通过执行外部可执行命令获取pitr指标

        Args:
            res: 上层函数传递进来的字典类型数据，用于记录当前函数获取的上报指标
        """
        # 找到最后一次出现ntp时间误差的行数
        exist_cmd = f"grep -onE '\[NTP_TIME_WARN\] .* us.*' {CANTIAND_LOG_PATH} " \
                    "| grep -v ignored" \
                    f"| tail -n 1 | awk -F: '{{print $1}}'"
        ignored_exist_cmd = f"grep -onE '\[NTP_TIME_WARN\] .+ ignored.' {CANTIAND_LOG_PATH}" \
                            f" | tail -n 1 | awk -F: '{{print $1}}'"

        _, exist_res, _ = _exec_popen(exist_cmd)
        # 不存在ntp时间误差
        if not exist_res:
            res.update({'pitr_warning': 'False'})
            return

        _, ignored_res, _ = _exec_popen(ignored_exist_cmd)
        # 存在ntp时间误差
        if not ignored_res:
            res.update({'pitr_warning': 'True'})
            return

        ignored_res, exist_res = int(ignored_res), int(exist_res)
        pitr_flag = 'False' if ignored_res > exist_res else 'True'
        res.update({'pitr_warning': pitr_flag})

    @staticmethod
    def get_cms_lock_failed_info(res):
        """
        通过查看cms日志获取当前cms进程是否有读写锁失败问题。
        获取最近一次失败日志的时间戳，与当前时间进行对比如果小于10秒，表示cms锁有异常
        否则为正常
        exp:
            "cms_disk_lock timeout."
            "read failed"
            "write failed"
        """
        check_cmd = "zgrep -E \"(cms_disk_lock timeout.|read failed|write failed)\" " \
                    "/opt/cantian/cms/log/run/* | grep -oE \"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]+\" | sort"
        _, output, _ = _exec_popen(check_cmd)
        # 存在加解锁失败问题
        if output:
            lock_failed_happen_time = output.split("\n")[-1]
            datetime_object = datetime.strptime(lock_failed_happen_time, '%Y-%m-%d %H:%M:%S')
            happen_times = datetime_object.timestamp()
            current_time = time.time()
            if int(current_time) - int(happen_times) < 10:
                res.update({'cms_lock_status': 'abnormal'})
                return
        res.update({'cms_lock_status': 'normal'})


    @staticmethod
    def close_child_process(proc):
        """kill掉执行外部可执行命令时fork出的子孙进程

        Args:
            proc: 首领进程对象
        """
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError as err:
            return str(err), NORMAL_STATE
        except Exception as err:
            return str(err), ABNORMAL_STATE

        return 'success', NORMAL_STATE

    @staticmethod
    def get_logicrep_running_info(max_archive_size, sql_info):
        """
        解析sql返回，获取入湖日志处理速度、日志堆积速度，计算距离堆满空间剩余时间
        return: 归档清理上限、
        """
        process_speed = sql_info.get("logicrep_progress", {}).get("PROCESS_SPEED", "0")
        process_speed = float(process_speed) * CONVERT_DICT.get("M")
        redo_gen_speed = sql_info.get("logicrep_progress", {}).get("REDO_GEN_SPEED", "0")
        redo_gen_speed = float(redo_gen_speed) * CONVERT_DICT.get("M")
        speed_update_time = sql_info.get("logicrep_progress", {}).get("SPEED_UPDATE_TIME",
                                                                      "1970-01-01 00:00:00").split(".")[0]
        speed_update_time = int(datetime.strptime(speed_update_time, '%Y-%m-%d %H:%M:%S').timestamp())
        current_time = int(time.time())
        # 如果入湖进程刷新时间（speed_update_time）与当前时间（current_time）间隔不大于30s，
        # 当前入湖实际速度为日志刷盘速度（redo_gen_speed） - 工具处理速度（process_speed）
        # 否则入湖实际速度为（redo_gen_speed）
        real_process_speed = redo_gen_speed - process_speed if \
            current_time - speed_update_time < 30 else redo_gen_speed
        arch_clean_upper_limit = sql_info.get("arch_clean_upper_limit", {}).get("RUNTIME_VALUE", 85)
        # 归档清理上限（arch_clean_upper_size）
        arch_clean_upper_size = max_archive_size * int(arch_clean_upper_limit) / 100
        return arch_clean_upper_size, real_process_speed

    def get_logicrep_info(self, res):
        """
        查看当前节点是否为logicrep主节点，是则查看进程是否存在
        """
        logicrep_cmd = "ps -ef | grep ZLogCatcherMain | grep -v grep"

        if os.path.exists(LOGICREP_START_TIME_PATH):
            with open(LOGICREP_START_TIME_PATH, 'r') as f:
                start_time = f.readline().strip()
            if not start_time:
                start_time = "null"
        else:
            start_time = "null"

        _, process_info, _ = _exec_popen(logicrep_cmd)
        if process_info:
            res.update({'logicrep': 'Online', 'logicrep_start_time': start_time})
            res.update(self.get_logicrep_info_from_sql(res))
            return
        logicrep_path = "/opt/software/tools/logicrep/"
        if os.path.exists(logicrep_path):
            res.update({'logicrep': 'Offline', 'logicrep_start_time': start_time})
            res.update(self.get_logicrep_info_from_sql(res))
            return
        res.update({'logicrep': 'None'})

    def get_certificate_status(self, res):
        """
        检查证书是否过期
        检查证书吊销列表是否过期
        检查证书是否已经被吊销
        """
        cmd = f"source ~/.bashrc && python3 -B {cur_abs_path}/get_certificate_status.py"
        output, err_state = self.shell_task(cmd)
        if not err_state and output:
            crl_status, crt_status = re.findall(r"'([^']*)'", output)
            res.update({
                "crl_status": crl_status,
                "crt_status": crt_status
            })
        else:
            res.update({
                "crl_status": None,
                "crt_status": None
            })

    def shell_task(self, exec_cmd):
        """公共方法，用于执行shell命令

        Args：
            exec_cmd: 具体的某个shell命令
        """
        try:
            proc = subprocess.Popen(exec_cmd, stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)
        except Exception as err:
            LOG.error("[shell task] node {} execute '{}' failed, err: {}".format(self.node_id, exec_cmd, str(err)))
            _, close_state = self.close_child_process(proc)
            if close_state:
                LOG.error("[shell task] after node {} executes cmd '{}', "
                          "it fails to kill the forked process ".format(self.node_id, exec_cmd))
            return str(err), ABNORMAL_STATE

        try:
            output, err_state = proc.communicate(timeout=TIME_OUT)
        except Exception as err:
            LOG.error("[shell task] node {} execute cmd '{}' failed, err: {}".format(self.node_id, exec_cmd, str(err)))
            return str(err), ABNORMAL_STATE
        finally:
            close_res, close_state = self.close_child_process(proc)

        if close_state:
            LOG.error("[shell task] after node {} executes cmd '{}', "
                      "it fails to kill the forked process ".format(self.node_id, exec_cmd))
            return close_res, close_state

        if err_state or not output:
            LOG.error("[shell task] node {} execute cmd '{}' failed, output: {}, "
                      "err_state: {}".format(self.node_id, exec_cmd, str(output), err_state))
            return output, ABNORMAL_STATE

        output = output.decode('utf-8')
        if re.findall(self.reg_string, output):
            LOG.error("the execution result of command '{}' matched the regular pattern '{}', "
                      "and the execution failed".format(exec_cmd, self.reg_string))
            return output, ABNORMAL_STATE

        return output, err_state

    def get_info_from_file(self, res):
        """公共方法，用于处理从文件读取的上报质保

        Args:
            res: 上层函数传递进来的字典类型数据，用于记录当前函数获取的上报指标
        """
        deploy_key_list = ['cluster_name', 'cantian_vlan_ip', 'storage_vlan_ip', 'cms_ip', 'share_logic_ip',
                           'storage_archive_fs', 'storage_share_fs', 'storage_metadata_fs']
        res.update({name: self.deploy_param.get(name, '') for name in deploy_key_list})

        cantiand_key_list = ['data_buffer_size', 'log_buffer_size', 'log_buffer_count']
        try:
            cantiand_data = file_reader(CANTIAND_INI_PATH)
        except Exception as err:
            LOG.error("[file read task] node {} read '{}' from {} failed, "
                      "err_details: {}".format(self.node_id, cantiand_key_list, CANTIAND_INI_PATH, str(err)))
        else:
            processed_data = [data for data in cantiand_data.split('\n') if data]
            reg_string = r'DATA_BUFFER_SIZE|LOG_BUFFER_SIZE|LOG_BUFFER_COUNT'
            report_data = [item for item in processed_data if re.findall(reg_string, item)]
            cantian_report_data = {item.split(' ')[0].lower(): item.split(' ')[-1] for item in report_data}
            res.update(self.cantiand_report_handler(cantian_report_data))

    def get_info_from_sql(self, res):
        """公共方法，用于处理从ctsql读取的上报质保

        Args:
            res: 上层函数传递进来的字典类型数据，用于记录当前函数获取的上报指标
        """
        # 参天进程异常，性能上报不采集ctsql数据库中的指标，防止和参天进程竞争ctsql
        if res.get('stat') != 'ONLINE' or str(res.get('work_stat')) != '1':
            return
        res.update(self.sql_info_query())

    def get_tmp_archive_count(self, res):
        archive_log_path = f"/mnt/dbdata/remote/archive_{self.storage_archive_fs}"
        count = 0
        for filename in os.listdir(archive_log_path):
            if f"{self.node_id}arch_file.tmp" in filename:
                count += 1
        return count

    def get_tmp_archive_size(self, res):
        tmp_archive_path = f"/mnt/dbdata/remote/archive_{self.storage_archive_fs}/{self.node_id}arch_file.tmp"
        if os.path.exists(tmp_archive_path):
            return os.path.getsize(tmp_archive_path)
        else:
            return 0

    def modify_logicrep_sql_file(self):
        logicrep_sql = file_reader(self.logicrep_sql_file)
        logicrep_sql = logicrep_sql.replace('LOGICREP0', 'LOGICREP1')
        modes = stat.S_IWRITE | stat.S_IRUSR
        flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT
        with os.fdopen(os.open(self.logicrep_sql_file, flags, modes), 'w', encoding='utf-8') as file:
            file.write(logicrep_sql)

    def get_logicrep_info_from_sql(self, res):
        logicrep_process_info = {
            "unrep_archive_count": "null",
            "unrep_archive_percent": "null",
            "estimate_full_time": "null"
        }

        if res.get('stat') != 'ONLINE' or str(res.get('work_stat')) != '1' or not self.decrypt_pwd \
                or not self.storage_archive_fs:
            return logicrep_process_info
        if self.node_id == 1:
            self.modify_logicrep_sql_file()
        sql_info = self.sql_logicrep_info_query()
        if sql_info.get("lrep_mode", {}).get("LREP_MODE") == "OFF":
            return logicrep_process_info
        tmp_archive_count = self.get_tmp_archive_count(res)
        max_sequence = sql_info.get("max(sequence)", {}).get("MAX(SEQUENCE#)")

        max_archive_count = tmp_archive_count if not max_sequence else tmp_archive_count + int(max_sequence)
        if not max_archive_count:
            return logicrep_process_info

        undo_archive_size, max_archive_size, sub_logicrep_process_info = self.get_logicrep_undo_count_and_percent(
            sql_info, res, max_archive_count)
        arch_clean_upper_size, real_process_speed = self.get_logicrep_running_info(
            max_archive_size, sql_info)
        # 日志预计堆满时间 = (归档上限空间（arch_clean_upper_size） - 未梳理日志空间（undo_archive_size）) / 日志刷盘速度（real_process_speed）
        full_remaining_time = (arch_clean_upper_size - undo_archive_size) / real_process_speed \
            if real_process_speed != 0 else "null"
        logicrep_process_info.update({"estimate_full_time": "{:.2f}s".format(full_remaining_time)})
        logicrep_process_info.update(sub_logicrep_process_info)
        return logicrep_process_info

    def get_logicrep_undo_count_and_percent(self, sql_info, res, max_archive_count):
        """
        获取入湖未归档文件数量（unrep_archive_count）和未归档百分比（unrep_archive_percent）
        """
        max_arch_files_size = sql_info.get("max_arch_files_size", {}).get("RUNTIME_VALUE")
        units = max_arch_files_size[-1]
        max_archive_size = int(max_arch_files_size[:-1]) * CONVERT_DICT.get(units)
        arch_file_size = sql_info.get("arch_file_size", {}).get("RUNTIME_VALUE")
        arch_clean_upper_limit = int(sql_info.get("arch_clean_upper_limit", {}).get("RUNTIME_VALUE", "85"))
        units = arch_file_size[-1]
        single_archive_size = int(arch_file_size[:-1]) * CONVERT_DICT.get(units)
        logic_point = sql_info.get("logicrep_progress", {}).get("LOGPOINT")
        temp_archive_size = self.get_tmp_archive_size(res)
        if not logic_point:
            undo_archive_count = max_archive_count
            undo_archive_size = undo_archive_count * single_archive_size if temp_archive_size == 0 else (
                    (undo_archive_count - 1) * single_archive_size + temp_archive_size)
            undo_archive_percent = 0 if max_archive_size == 0 else \
                (undo_archive_size / (max_archive_size * arch_clean_upper_limit / 100) * 100)
        else:
            point_info = logic_point.split("-")
            asn = int(point_info[1], 16)
            offset = int(point_info[2], 16)
            undo_archive_count = max_archive_count - asn + 1
            undo_archive_size = temp_archive_size - offset if undo_archive_count == 0 \
                else (undo_archive_count - 1) * single_archive_size + temp_archive_size - offset
            undo_archive_percent = 0 if max_archive_size == 0 else \
                (undo_archive_size / (max_archive_size * arch_clean_upper_limit / 100) * 100)
        undo_archive_percent = "{:.2f}%".format(undo_archive_percent)
        logicrep_process_info = {"unrep_archive_count": str(undo_archive_count),
                                 "unrep_archive_percent": str(undo_archive_percent)}
        return undo_archive_size, max_archive_size, logicrep_process_info

    def sql_logicrep_info_query(self):
        """
        从ctsql查询logicrep指标的方法，用于执行某一条sql语句，获取对应的指标
        新增指标，确保report_key与get_logicrep_info_.sql顺序一致
        """
        res = {}
        report_key = [
            "MAX(SEQUENCE)", "LOGICREP_PROGRESS", "LREP_MODE", "MAX_ARCH_FILES_SIZE",
            "ARCH_FILE_SIZE", "ARCH_CLEAN_UPPER_LIMIT"
        ]
        return_code, sql_res = self.sql.query(self.logicrep_sql_file)
        if not return_code and sql_res:
            res = self.parase_sql_file_res(report_key, sql_res)
        return res

    def sql_info_query(self):
        """
        从ctsql查询指标的公共方法，用于执行某一条sql语句，获取对应的指标
        新增ctsql指标，确保report_key与get_ctsql_info.sql顺序一致
        """
        res = {}
        report_key = [
            "SYS_BACKUP_SETS", "CHECKPOINT_PAGE",
            "CHECKPOINT_PERIOD", "GLOBAL_LOCK",
            "LOCAL_LOCK", "LOCAL_TXN", "GLOBAL_TXN",
            "DV_LRPL_DETAIL"
        ]
        return_code, sql_res = self.sql.query(self.sql_file)
        if not return_code and sql_res:
            res = self.parase_sql_file_res(report_key, sql_res)
        return res

    def parase_sql_file_res(self, report_key, sql_res) -> dict:
        """
        解析sql语句返回值，返回字典：
        exp:
            DRC_RESOURCE         USED         TOTAL        RATIO
            -------------------- ------------ ------------ --------------------
            LOCAL_TXN            0            0            0.00000
        返回：
            {
                "local_txn":
                    {
                        "USED": "0",
                        "TOTAL": "0",
                        "RATIO": "0.00000",
                    }
                ...
            }

        """
        res = {}
        sql_res_list = sql_res.split("SQL>")
        for index, sql_res in enumerate(sql_res_list[1:len(report_key) + 1]):
            res.update(
                {
                    report_key[index].lower(): dict(self.ctsql_result_parse(sql_res))
                }
            )
        return res

    def get_cms_info(self, res):
        """公共方法，用于处理执行cms相关命令读取的上报质保

        Args:
            res: 上层函数传递进来的字典类型数据，用于记录当前函数获取的上报指标
        """
        for exec_cmd, exec_func in self.sh_cmd.items():
            res.update(exec_func(exec_cmd))

    def update_cms_port_info(self, cms_port_cmd):
        """处理执行cms node -list命令后获取的数据

        Args:
            cms_port_cmd: cms node -list
        """
        cms_port_info, cms_port_err = self.shell_task(cms_port_cmd)
        if not cms_port_err and cms_port_info:
            tmp_port_info = [re.split(r'\s+', val.strip(' '))
                             for _, val in enumerate(cms_port_info.split('\n'))
                             if val][1:]
            return {'cms_port': str(tmp_port_info[self.node_id][-1])}

        return {}

    def update_cms_node_connected(self, cms_node_connected_cmd):
        """处理执行cms node -connected命令后获取的数据

        Args:
            cms_node_connected_cmd: cms node -connected
        """
        node_info, err_code = self.shell_task(cms_node_connected_cmd)
        if not err_code and node_info:
            processed_info = [re.split(r'\s+', item.strip(' ')) for item in node_info.split('\n') if item]
            remain_nums = len(processed_info[1:])
            node_id_idx, ip_idx, voting_idx = 0, 2, 4
            node_data = [{'NODE_ID': item[node_id_idx], 'IP': item[ip_idx], 'VOTING': item[voting_idx]}
                         for item in processed_info[1:]]

            res = {'cms_connected_domain': {'remaining_nodes_nums': remain_nums, 'remaining_nodes': node_data}}
            return res

        return {}

    def update_cms_status_info(self, cms_stats_cmd):
        """处理执行cms stat命令后获取的数据

        Args:
            cms_stats_cmd: cms stat
        """
        res = {}

        id_to_key = {'0': 'node_id', '2': 'stat', '5': 'work_stat'}
        cms_output, cms_err = self.shell_task(cms_stats_cmd)
        if not cms_err and cms_output:
            tmp_info = [re.split(r'\s+', val.strip(' '))
                        for _, val in enumerate(cms_output.split('\n'))
                        if val]
            cms_stat = [{val: item[int(key)] for key, val in id_to_key.items()} for item in tmp_info[1:]]
            cluster_stat = 0 if {'ONLINE'} == set([item.get('stat') for item in cms_stat]) else 1

            stat_data = cms_stat[self.node_id]
            work_stat = stat_data.get('work_stat')
            stat_data['work_stat'] = int(work_stat)

            res.update(stat_data)
            res.update({'cluster_stat': cluster_stat})

        return res

    def update_cms_diskiostat(self, cms_disk_iostat_cmd):
        """处理执行cms diskiostat命令后获取的数据

        Args:
            cms_disk_iostat_cmd: cms stat
        return:
            获取到的结果
        """
        cms_output, cms_err = self.shell_task(cms_disk_iostat_cmd)
        if not cms_err and cms_output:
            return {'disk_iostat': cms_output.split('\n')[0]}

        return {}

    def update_cpu_mem_info(self, exec_cmd):
        """执行top -bn 1 -i命令后获取cpu占用，内存占用等数据

        Args:
            exec_cmd: top -bn 1 -i
        """
        output, err = self.shell_task(exec_cmd)

        if not err and output:
            output = output.split('\n')
            cpu_info, physical_mem = [item.strip() for item in re.split(r'[,:]', output[2].strip())], \
                [item.strip() for item in re.split(r'[,:]', output[3].strip())]
            mem_unit = physical_mem[0].split(' ')[0]
            cpu_res, mem_res = {('cpu_' + item.split(' ')[1]): item.split(' ')[0] + '%'
                                for item in cpu_info[1:5]}, \
                {('mem_' + item.split(' ')[1]): item.split(' ')[0] + mem_unit
                 for item in physical_mem[1:4]}
            cpu_res.pop('cpu_ni')
            mem_res.update(cpu_res)

            return mem_res

        return {}

    def get_export_data(self, res):
        """公共方法，从获取途径上统一管理各指标获取方法

        Args:
            res: 上层函数传递进来的字典类型数据，用于记录当前函数获取的上报指标
        """
        self.get_info_from_file(res)
        self.get_cms_info(res)
        if self.decrypt_pwd:
            self.get_info_from_sql(res)
            self.get_logicrep_info(res)
        self.get_pitr_data_from_external_exec_cmd(res)
        self.get_cms_lock_failed_info(res)
        if self.mes_type == "TCP":
            self.get_certificate_status(res)

    def execute(self):
        """总入口，调用此函数获取上报指标"""
        res = {key: val for key, val in self.std_output.items()}

        if not self.deploy_param:
            try:
                self.deploy_param = json.loads(file_reader(DEPLOY_PARAM_PATH))
            except Exception as err:
                LOG.error('[result] execution failed when read deploy_param.json, [err_msg] {}'.format(str(err)))
                return res

            self.node_id = int(self.deploy_param.get('node_id'))
            self.mes_type = self.deploy_param.get("mes_type")
            self.storage_archive_fs = self.deploy_param.get("storage_archive_fs")

        if not self.decrypt_pwd:
            # ctsql数据库密码解密失败，不会影响其它性能指标的读取和上报
            self._init_ctsql_vars()

        # 恢复环境变量，避免cms命令执行失败
        split_env = os.environ['LD_LIBRARY_PATH'].split(":")
        filtered_env = [single_env for single_env in split_env if "/opt/cantian/dbstor/lib" not in single_env]
        os.environ['LD_LIBRARY_PATH'] = ":".join(filtered_env)

        try:
            self.get_export_data(res)
        except Exception as err:
            LOG.error('[result] execution failed when get specific export data. '
                      '[err_msg] {}, [err_traceback] {}'.format(str(err), traceback.format_exc(limit=-1)))
            return res

        return res

    def _init_ctsql_vars(self):
        ctsql_ini_path = glob.glob(CTSQL_INI_PATH)[0]
        ctsql_ini_data = file_reader(ctsql_ini_path)
        encrypt_pwd = ctsql_ini_data[ctsql_ini_data.find('=') + 1:].strip()
        try:
            self.decrypt_pwd = self.kmc_decrypt.decrypt(encrypt_pwd)
        except Exception as err:
            # 日志限频
            if not self.ctsql_decrypt_error_flag:
                LOG.error('[result] decrypt ctsql passwd failed, [err_msg] {}'.format(str(err)))
                self.ctsql_decrypt_error_flag = True
        self.ctsql_decrypt_error_flag = False
        self.sql.update_sys_data(self.node_id, self.decrypt_pwd)


class GetDbstorInfo:
    def __init__(self):
        self.deploy_config = self.get_deploy_info()
        self.std_output = {
            self.deploy_config.get("storage_dbstore_fs"):
                {
                    'limit': 0, 'used': 0, 'free': 0,
                    'snapshotLimit': 0, 'snapshotUsed': 0,
                    'fsId': '', 'linkState': ''
                },
            self.deploy_config.get("storage_dbstore_page_fs"):
                {
                    'limit': 0, 'used': 0, 'free': 0,
                    'snapshotLimit': 0, 'snapshotUsed': 0,
                    'fsId': '', 'linkState': ''
                }
        }
        self.info_file_path = '/opt/cantian/common/data/dbstore_info.json'
        self.index = 0
        self.max_index = 10
        self.last_time_stamp = None

    @staticmethod
    def get_deploy_info():
        return json.loads(file_reader(DEPLOY_PARAM_PATH))

    def dbstor_info_handler(self):
        try_times = 3
        dbstor_info = None

        while try_times > 0:
            try:
                dbstor_info = json.loads(file_reader(self.info_file_path))
                break
            except Exception as err:
                try_times -= 1
                LOG.error("[dbstor info reader] fail to read dbstor info from '{}', "
                          "err_msg: {}, remaining attempts: {}".format(self.info_file_path, str(err), try_times))
                time.sleep(1)
                continue

        if not dbstor_info:
            raise Exception('dbstor_info is empty.')

        dbstor_log_fs, dbstor_page_fs = dbstor_info
        time_stamp, _ = dbstor_log_fs.pop('timestamp'), dbstor_page_fs.pop('timestamp')
        if time_stamp != self.last_time_stamp:
            self.index, self.last_time_stamp = 0, time_stamp
        else:
            self.index = min(self.max_index, self.index + 1)

        return dbstor_info

    def get_dbstor_info(self):
        res = {key: val for key, val in self.std_output.items()}
        try:
            dbstor_info = self.dbstor_info_handler()
        except Exception as err:
            LOG.error("Get dbstor info failed, err_msg: {}".format(str(err)))
            return res

        if dbstor_info:
            dbstor_log_fs, dbstor_page_fs = dbstor_info
            log_fs_name, page_fs_name = dbstor_log_fs.pop('fsName'), dbstor_page_fs.pop('fsName')
            cur_res = {log_fs_name: dbstor_log_fs, page_fs_name: dbstor_page_fs}
            if self.index >= self.max_index:
                cur_res.update({'work_stat': 6})
            res.update(cur_res)

        return res
