import glob
import os
import json
import shlex
import tarfile
import subprocess
from pathlib import Path
from datetime import datetime
from datetime import timezone
from collections import Counter
from ctmgr.log_tool.om_log import LOGS_COLLECTION as LOG
from ctmgr.logs_collection.tools import timeout
from ctmgr.logs_collection.tools import RecordLogPackingProgress

cur_abs_path, _ = os.path.split(os.path.abspath(__file__))


def json_data_reader(data_path):
    with open(data_path, 'r', encoding='utf-8') as file:
        info = file.read()
    return json.loads(info)


def get_file_creation_time(file_path):
    ori_create_time = os.path.getmtime(file_path)
    return int(round(ori_create_time * 1000))


class LogsCollection:
    def __init__(self):
        self.packing_ratio = 50
        self.max_gather_vol = 0
        self.sh_task_time_out = 600
        self.record_progress = RecordLogPackingProgress(cur_abs_path)
        self.config_info = json_data_reader(str(Path(cur_abs_path, 'config.json')))

    @staticmethod
    def get_cur_timestamp(flag=None):
        utc_now = datetime.utcnow()

        if flag == 'name':
            return utc_now.replace(tzinfo=timezone.utc).astimezone(tz=None).strftime('%Y%m%d%H%M%S')

        return utc_now.replace(tzinfo=timezone.utc).astimezone(tz=None).strftime('%Y-%m-%d %H:%M:%S')

    @staticmethod
    def path_authority_judgment(file_path):
        # 目录需要可读可执行权限
        if os.path.isdir(file_path):
            return os.access(file_path, os.R_OK | os.X_OK)
        if os.path.isfile(file_path):
            return os.access(file_path, os.R_OK)

        return False

    @staticmethod
    def reg_handler(log_name_prefix, match_string):
        """匹配出待采集的文件"""
        if match_string.startswith(log_name_prefix) and match_string.endswith('tar.gz'):
            return True
        return False

    def pre_execute(self):
        """
        日志收集前，修改日志权限，确保ctmgruser用户有权限
        :return:
        """
        LOG.info("Modify file mode before collection.")
        cmd = "sudo /opt/cantian/action/change_log_priority.sh"
        res = self.shell_task(cmd, "modify file mode")
        if res != 'success':
            err_msg = "Modify files mode failed."
            LOG.error(err_msg)
        LOG.info("Modify file success.")

    def packing_files(self, log_file_list, tar_name, mode):
        """ 将当前模块日志归档为一个压缩文件

        :param log_file_list: 当前模块日志列表
        :param tar_name: 压缩文件名
        :param mode: recent or all，表示日志采集场景
        """
        log_names = []
        for log_file in log_file_list:
            log_names.append(log_file)
            log_directory, log_name = os.path.split(log_file)
            log_name_prefix = log_name.split('.')[0]
            archive_logs = [(item, get_file_creation_time(str(Path(log_directory, item))))
                            for item in os.listdir(log_directory)
                            if self.reg_handler(log_name_prefix, item)]
            # 近期日志采集场景，仅采集实时日志和归档日志
            if mode == 'recent':
                archive_logs.sort(key=lambda x: (x[1], x[0]), reverse=True)
                cur_size = int(os.path.getsize(str(Path(log_directory, log_name))))
                for archive_log_name, _ in archive_logs:
                    if cur_size >= self.max_gather_vol:
                        break
                    cur_size += int(os.path.getsize(str(Path(log_directory, archive_log_name))))
                    log_names.append(os.path.join(log_directory, archive_log_name))
            else:
                log_names.extend([os.path.join(log_directory, name) for name, _ in archive_logs])

        with tarfile.open(f'{tar_name}', 'w:gz') as tar:
            for pack_name in log_names:
                tar.add(pack_name)

    def shell_task(self, spec_cmd, task_type):
        """公共方法，支持调用外部可执行程序

        :param spec_cmd: shell/python等可执行命令
        :param task_type: 用于区分当前方法的用途
        :return: 字符串，'success' or 'fail'
        """
        res_state = 'success'

        try:
            proc = subprocess.Popen(shlex.split(spec_cmd), stdout=subprocess.PIPE, shell=False)
        except Exception as err:
            LOG.error('[{}] execute cmd: {} failed, err_msg: {}'.format(task_type, spec_cmd, err))
            return 'fail'

        try:
            res, state = proc.communicate(timeout=self.sh_task_time_out)
        except Exception as err:
            LOG.error('[{}] execute cmd: {} failed, err_msg: {}'.format(task_type, spec_cmd, err))
            return 'fail'

        if state:
            LOG.error('[{}] execute cmd: {} failed, res_err: {}'.format(task_type, spec_cmd, res.decode('utf-8')))
            res_state = 'fail'
        else:
            LOG.info('[{}] execute cmd: {} succeed, res_msg: {}'.format(task_type, spec_cmd, res.decode('utf-8')))

        return res_state

    def generate_logs(self):
        pre_generate_info = [item for item in self.config_info if item.get('generate_type') == 'script generated']
        res = []
        prefix_to_type = {'py': 'python3', 'sh': 'sh'}

        for log_item in pre_generate_info:
            script_type, script_path = log_item.get('script_type'), log_item.get('script_path')
            cmd = prefix_to_type.get(script_type) + ' ' + script_path
            state = self.shell_task(cmd, 'generate logs')
            res.append(state)

        return res

    def exception_handler(self, target_path):
        cur_time = self.get_cur_timestamp()
        if os.path.exists(target_path):
            self.removing_dirs(target_path)

        self.record_progress.record_cur_progress((cur_time, cur_time), 'for details see logs',
                                                 'for details see logs', ('fail', 'time_out', 'None'))

    def removing_dirs(self, dir_to_remove):
        """递归删除包含输入目录在内的所有文件

        :param dir_to_remove: 输入目录
        """
        if os.path.isdir(dir_to_remove):
            for file_name in os.listdir(dir_to_remove):
                file_to_remove = os.path.join(dir_to_remove, file_name)
                self.removing_dirs(file_to_remove)
            if os.path.exists(dir_to_remove):
                os.rmdir(dir_to_remove)
        else:
            if os.path.exists(dir_to_remove):
                os.remove(dir_to_remove)

    def sub_module_packing(self, item, main_path, idx, mode):
        start_time, collect_state = self.get_cur_timestamp(), 'done'

        self.max_gather_vol = int(item.get('size')) * self.packing_ratio * pow(1024, 2)
        tar_name, generate_type = item.get('tar_name'), item.get('generate_type')
        is_repeat_generate = item.get("is_repeat_generate", False)
        log_file_list = [item.get('dir')] if not is_repeat_generate \
            else glob.glob(item.get('dir'), recursive=True)
        log_name = None
        for log_file_dir in log_file_list:
            # 分离日志目录和日志名
            log_directory, log_name = os.path.split(log_file_dir)

            LOG.info('[submodule log collection starts] child_module: {}, '
                     'generate_type: {}'.format(log_name, generate_type))

            if not os.path.exists(log_file_dir):
                LOG.error('log_source_path: {} does not exist log collection failed and exited'.format(log_file_dir))
                self.record_cur_progress(("fail", 'invalid path'), (idx, generate_type, log_name), start_time)
                return False

            if not self.path_authority_judgment(log_file_dir) or not self.path_authority_judgment(log_directory):
                LOG.error(
                    "log_file_dir: '{}' or log_content: '{}' permission denied".format(log_file_dir, log_directory))
                self.record_cur_progress(("fail", 'permission denied'), (idx, generate_type, log_name), start_time)
                return False

        sub_module_tar_path = os.path.join(main_path, tar_name)
        self.packing_files(log_file_list, sub_module_tar_path, mode)
        self.record_cur_progress((collect_state, 'None'), (idx, generate_type, log_name), start_time)
        return True

    def record_cur_progress(self, collect_state, submodule_info, start_time):
        state, err_type = collect_state
        idx, generate_type, name_pre = submodule_info
        end_time = self.get_cur_timestamp()
        try:
            cur_percent = str('%.2f' % ((idx + 1) * 100 / len(self.config_info))) + '%'
        except ZeroDivisionError:
            cur_percent = 'error'
        self.record_progress.record_cur_progress((start_time, end_time),
                                                 name_pre, generate_type, (state, err_type, cur_percent))

        LOG.info('[submodule log collection ends] child_module: {}, pack_status: {}, '
                 'cur_progress: {}'.format(name_pre, state, cur_percent))

    @timeout(1800)
    def execute(self, target_path, mode):
        """
        target: 由用户指定的压缩包存放路径
        mode: all:打包近期日志， recent：全量打包
        """
        LOG.info('[logs collection] starts')
        self.pre_execute()
        LOG.info(f'[generate logs starts], start_time:{self.get_cur_timestamp()}, mode: {mode}')
        gen_res = self.generate_logs()
        statistics_res = Counter(gen_res)
        LOG.info(f"[generate logs ends], end_time:{self.get_cur_timestamp()}, all:{len(gen_res)}, "
                 f"success: {statistics_res.get('success', 0)}, fail: {statistics_res.get('fail', 0)}")

        if not os.path.exists(target_path):
            try:
                os.makedirs(target_path)
            except Exception as err:
                err_msg = f"directory '{target_path}' creation failed, err_details: {str(err)}"
                LOG.error(err_msg)
                raise IOError(err_msg) from err
            finally:
                os.chmod(target_path, 0o750)

        time_stamp = self.get_cur_timestamp(flag='name')
        final_tar_file_name = 'cantian_log_{}.tar.gz'.format(time_stamp)
        main_path = os.path.join(target_path, time_stamp)
        try:
            os.mkdir(main_path)
        except Exception as err:
            err_msg = f"directory {main_path} creation failed, err_details: {str(err)}"
            LOG.error(err_msg)
            raise IOError(err_msg) from err

        res = Counter([str(self.sub_module_packing(item, main_path, idx, mode))
                       for idx, item in enumerate(self.config_info)])

        # 将各模块日志压缩为一个归档日志
        final_tar_file_path = str(Path(target_path, final_tar_file_name))
        os.chdir(main_path)
        with tarfile.open(f'{final_tar_file_path}', 'w:gz') as tar:
            for file_name in os.listdir(main_path):
                tar.add(file_name)
        os.chdir(cur_abs_path)
        # 修改归档日志权限
        os.chmod(final_tar_file_path, 0o440)
        self.removing_dirs(main_path)
        LOG.info('[logs collection ends], success: {}, fail: {}'.format(res.get('True', 0), res.get('False', 0)))
