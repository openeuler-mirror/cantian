import json
import os
import sys

sys.path.append('/opt/cantian/action/inspection')

from om_common_function import exec_popen

CHECK_PATTERN = "thread aborted\|Logic Replication"
LOG_FILE_PATH = "/opt/software/tools/logicrep/logicrep/logicrep/alarm/alarm.log"
FLAG_FILE = "/opt/software/tools/logicrep/enable.success"


class LogicrepChecker:
    def __init__(self):
        self.check_process_cmd = 'ps -ef | grep ZLogCatcherMain | grep -v grep'
        self.collect_cmd = f'grep -E "{CHECK_PATTERN}" {LOG_FILE_PATH}'
        self.flag = 0
        self.check_note = {
            'Logicrep master node': 'unknown',
            'Logicrep process': 'unknown',
            'Warning log': "unknown",
        }
        self.format_output = {
            'data': dict(),
            'error': {
                'code': 0,
                'description': ''
            }
        }

    @staticmethod
    def select_error_info(info_list):
        res_list = list()
        select_dict = dict()
        info_list = info_list[::-1]

        for info in info_list:
            info = info.split("|")
            err_id, err_stat = info[1], info[6]
            if err_id in select_dict.keys():
                continue
            if err_stat == "1":
                res_list.append(str(info))
            select_dict[err_id] = err_stat
            if len(select_dict) == 11:
                break

        return res_list[::-1]

    @staticmethod
    def _run_cmd(cmd):
        code, stdout, stderr = exec_popen(cmd)
        if code or stderr or code is None:
            raise Exception("Execute %s failed" % cmd)
        return stdout

    def check_node(self):
        if os.path.exists(FLAG_FILE):
            self.check_note['Logicrep master node'] = 'true'
        else:
            self.check_note['Logicrep master node'] = 'false'
            self.flag += 1

    def check_process(self):
        self.check_note['Logicrep process'] = 'online'
        try:
            _ = self._run_cmd(self.check_process_cmd)
        except Exception as err:
            if self.check_process_cmd in str(err):
                self.check_note['Logicrep process'] = 'offline'
                self.flag += 1
            else:
                raise

    def collect_log(self):
        stdout = ""
        try:
            stdout = self._run_cmd(self.collect_cmd)
        except Exception as err:
            if self.collect_cmd in str(err):
                pass
        if not stdout:
            self.check_note['Warning log'] = 'none'
            return

        stdout_list = self.select_error_info(stdout.split("\n"))
        if not stdout_list:
            self.check_note['Warning log'] = 'none'
            return

        self.check_note['Warning log'] = "\n".join(stdout_list)
        raise Exception(str(self.check_note))

    def get_format_output(self):
        try:
            self.check_node()
        except Exception as err:
            self.format_output['error']['code'] = -1
            self.format_output['error']['description'] = "check logicrep master node failed with err: {}".format(
                str(err))
            self.format_output['data'] = self.check_note
            return self.format_output
        try:
            self.check_process()
        except Exception as err:
            self.format_output['error']['code'] = -1
            self.format_output['error']['description'] = "check logicrep process failed with err: {}".format(str(err))
            self.format_output['data'] = self.check_note
            return self.format_output
        if self.flag == 2:
            self.check_note['Warning log'] = 'none'
            self.format_output['data'] = self.check_note
            return self.format_output
        elif self.flag:
            self.format_output['error']['code'] = -1
            self.format_output['error']['description'] = f"directory or process not found\n{str(self.check_note)}"
            self.format_output['data'] = self.check_note
            return self.format_output
        try:
            self.collect_log()
        except Exception as err:
            self.format_output['error']['code'] = -1
            self.format_output['error']['description'] = "collect warning info failed with err: {}".format(str(err))
            self.format_output['data'] = self.check_note
            return self.format_output
        self.format_output['data'] = self.check_note
        return self.format_output


if __name__ == '__main__':
    far = LogicrepChecker()
    print(json.dumps(far.get_format_output()))
