# -*- coding: UTF-8 -*-
import os
import re
import json
import time
import stat
import signal
import traceback
import subprocess
from pathlib import Path
from exporter.log import EXPORTER_LOG as LOG
from exporter.tool import SimpleSql
from exporter.tool import _exec_popen


cur_abs_path, _ = os.path.split(os.path.abspath(__file__))
OLD_CANTIAND_DATA_SAVE_PATH = Path(cur_abs_path, 'cantiand_report_data_saves.json')
DEPLOY_PARAM_PATH = '/opt/cantian/config/deploy_param.json'
CANTIAND_INI_PATH = '/mnt/dbdata/local/cantian/tmp/data/cfg/cantiand.ini'
CANTIAND_LOG_PATH = '/mnt/dbdata/local/cantian/tmp/data/log/run/cantiand.rlog'
TIME_OUT = 5
ABNORMAL_STATE, NORMAL_STATE = 1, 0


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
                           'cluster_stat': '', 'cms_port': '', 'cms_connected_domain': '', 'disk_iostat': '',
                           'mem_total': '', 'mem_free': '', 'mem_used': '', 'cpu_us': '', 'cpu_sy': '', 'cpu_id': '',
                           'pitr_warning': ''
                           }
        self.zsql_output = {
            'data_buffer_size': '', 'log_buffer_size': '', 'log_buffer_count': '',
            'sys_backup_sets': {}, 'checkpoint_pages': {}, 'checkpoint_period': {}, 'global_lock': {},
            'local_lock': {}, 'local_txn': {}, 'global_txn': {},
        }
        self.sql = SimpleSql()
        self.deploy_param = json.loads(file_reader(DEPLOY_PARAM_PATH))
        self.node_id = int(self.deploy_param.get('node_id'))
        self.deploy_mode = self.deploy_param.get("deploy_mode")

        self.sh_cmd = {'top -bn 1 -i': self.update_cpu_mem_info,
                       'source ~/.bashrc&&cms stat': self.update_cms_status_info,
                       'source ~/.bashrc&&cms node -list': self.update_cms_port_info,
                       'source ~/.bashrc&&cms node -connected': self.update_cms_node_connected,
                       'source ~/.bashrc&&cms diskiostat': self.update_cms_diskiostat
                       }
        self.sql_cmd = [
            {'select': ['START_TIME', 'COMPLETION_TIME', 'MAX_BUFFER_SIZE'], 'source_from': 'SYS_BACKUP_SETS'},
            {'select': ['NAME', 'VALUE'], 'source_from': 'DV_PARAMETERS', 'where': ['NAME', 'CHECKPOINT_PAGES']},
            {'select': ['NAME', 'VALUE'], 'source_from': 'DV_PARAMETERS', 'where': ['NAME', 'CHECKPOINT_PERIOD']},
            {'select': ['*'], 'source_from': 'DV_DRC_RES_RATIO', 'where': ['DRC_RESOURCE', 'GLOBAL_LOCK']},
            {'select': ['*'], 'source_from': 'DV_DRC_RES_RATIO', 'where': ['DRC_RESOURCE', 'LOCAL_LOCK']},
            {'select': ['*'], 'source_from': 'DV_DRC_RES_RATIO', 'where': ['DRC_RESOURCE', 'LOCAL_TXN']},
            {'select': ['*'], 'source_from': 'DV_DRC_RES_RATIO', 'where': ['DRC_RESOURCE', 'GLOBAL_TXN']}
        ] if self.deploy_mode != "--nas" else []
        if self.deploy_mode != "--nas":
            self.std_output.update(self.zsql_output)
        self.sql_res_handler = {'sys_backup_sets': self.sys_backup_sets_handler}
        self.reg_string = r'invalid argument'

    @staticmethod
    def sql_res_key_extract(sql_cmd):
        """从sql语句中提取出上报指标名

        Args:
            sql_cmd: 字典格式的sql语句，示例可见self.sql_cmd列表
        Return:
            sql语句对应的指标名
        """
        last_key = list(sql_cmd.keys())[-1]
        last_val = sql_cmd.get(last_key)
        if isinstance(last_val, list):
            return last_val[-1]
        return last_val

    @staticmethod
    def sys_backup_sets_handler(list_res):
        """单独设立此函数，用于处理上报指标sys_backup_sets

        Args:
            list_res: 多维列表，第一行是系统备份参数名，第二行起是系统备份参数值
        Return:
            字典，键是系统备份参数名，值是系统备份参数值
        """
        if list_res[0][0] != 'START_TIME':
            return {}

        keys, *backup_vals = list_res
        str_backup_val = ' '.join(backup_vals[-1])
        vals = re.findall(r'\d+-\d+-\d+\s+\d+:\d+:\d+.\d+', str_backup_val)
        max_buffer_size = backup_vals[-1][-1]
        vals.append(max_buffer_size)
        return {key: val for key, val in zip(keys, vals)}

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
        """公共方法，用于处理从zsql读取的上报质保

        Args:
            res: 上层函数传递进来的字典类型数据，用于记录当前函数获取的上报指标
        """
        # 参天进程异常，性能上报不采集zsql数据库中的指标，防止和参天进程竞争zsql
        if res.get('stat') != 'ONLINE' or str(res.get('work_stat')) != '1':
            return

        for item in self.sql_cmd:
            res.update(self.sql_info_query(item))

    def sql_info_query(self, single_sql_cmd):
        """从zsql查询指标的公共方法，用于执行某一条sql语句，获取对应的指标

        Args:
            single_sql_cmd: 某一条具体的sql语句，示例可见self.sql_cmd列表
        """
        return_code, sh_res = self.sql.query(**single_sql_cmd)
        if not return_code and sh_res:
            res_key = self.sql_res_key_extract(single_sql_cmd).lower()
            str_res = [item for item in sh_res.split('\n') if item][4:-1]
            list_res = [re.split(r'\s+', item.strip(' ')) for item in str_res if '---' not in item]

            if len(list_res) <= 1:
                return {}
            if res_key in self.sql_res_handler:
                return {res_key: self.sql_res_handler.get(res_key)(list_res)}

            res = {res_key: {list_res[0][idx]: list_res[1][idx] for idx, _ in enumerate(list_res[0])}}
            return res

        return {}

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
        self.get_pitr_data_from_external_exec_cmd(res)

    def execute(self):
        """总入口，调用此函数获取上报指标"""
        res = {key: val for key, val in self.std_output.items()}

        self._init_zsql_vars()

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

    def _init_zsql_vars(self):
        self.sql.update_sys_data(self.node_id)


class GetDbstorInfo:
    def __init__(self):
        self.std_output = {'limit': 0, 'used': 0, 'free': 0,
                           'snapshotLimit': 0, 'snapshotUsed': 0, 'fsId': '', 'fsName': '', 'linkState': ''}
        self.info_file_path = '/opt/cantian/common/data/dbstore_info.json'
        self.index = 0
        self.max_index = 10
        self.last_time_stamp = None

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

        if dbstor_info:
            time_stamp = dbstor_info.pop("timestamp")
            if time_stamp != self.last_time_stamp:
                self.index, self.last_time_stamp = 0, time_stamp
            else:
                self.index = min(self.max_index, self.index + 1)

        return dbstor_info

    def get_dbstor_info(self):
        deploy_param = json.loads(file_reader(DEPLOY_PARAM_PATH))
        deploy_mode = deploy_param.get("deploy_mode")
        if deploy_mode == "--nas":
            return {}
        res = {key: val for key, val in self.std_output.items()}
        dbstor_info = self.dbstor_info_handler()
        if dbstor_info:
            if self.index >= self.max_index:
                dbstor_info.update({'work_stat': 6})
            res.update(dbstor_info)

        return res
