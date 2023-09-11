import json
import re
import sys
from datetime import datetime

sys.path.append('/opt/cantian/action/inspection')

from log_tool import setup
from om_common_function import exec_popen


LOG = setup("ct_om")
# 检查ntp服务器有没有开启
# 检查某个路径的flag有没有 告警提示 打印多节点时间不相同的时间差时间点。也就是打印跳变。
CHECK_PATTERN = "(\[NTP_TIME_WARN\])(.*)(us)"
LOG_FILE_PATH = "/mnt/dbdata/local/cantian/tmp/data/log/run/*log"
LOG_ZIP_FILE_PATH = "/mnt/dbdata/local/cantian/tmp/data/log/run/*tar.gz"


class NtpChecker:

    def __init__(self):
        self.check_ntp_cmd = 'timedatectl'
        self.check_cmd = f'grep -E "%s" {LOG_FILE_PATH}'
        self.check_zip_cmd = f'tar -Oxzf {LOG_ZIP_FILE_PATH} | grep -E "%s"'
        self.check_note = {
            'System clock synchronized': 'unknown',
            'pitr warning': "unknown",
        }
        self.format_output = {
            'data': dict(),
            'error': {
                'code': 0,
                'description': ''
            }
        }

    @staticmethod
    def get_ntp_result(output):
        return isinstance(output, str) and "yes" in output[:-7]

    @staticmethod
    def _run_cmd(cmd):
        code, stdout, stderr = exec_popen(cmd)
        if code or stderr or code is None:
            raise Exception("Execute %s failed" % cmd)
        return stdout

    @staticmethod
    def _get_log_time(stdout):
        pattern = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+")
        datetime_str = re.findall(pattern, stdout)[0]
        datetime_obj = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S.%f")
        timestamp = datetime_obj.timestamp()
        return timestamp

    def check_ntp(self):
        stdout = self._run_cmd(self.check_ntp_cmd)
        flag = self.get_ntp_result(stdout)
        if flag:
            self.check_note['System clock synchronized'] = 'yes'
        else:
            self.check_note['System clock synchronized'] = 'no'

    def check_time_interval(self):
        check_list = [self.check_cmd, self.check_zip_cmd]
        check_result = []
        check_mid = []
        for cmd in check_list:
            _cmd = cmd % CHECK_PATTERN
            try:
                stdout = self._run_cmd(_cmd)
            except Exception as err:
                continue
            stdout_list = stdout.split("\n")
            check_mid.extend(stdout_list)
        for item in check_mid:
            timestamp = self._get_log_time(item)
            check_result.append((timestamp, item))
        if check_result:
            self.check_note["pitr warning"] = "\n".join([item[1] for item in sorted(check_result)])
            raise Exception(str(self.check_note))
        else:
            self.check_note["pitr warning"] = "success"

    def get_format_output(self):
        try:
            self.check_ntp()
        except Exception as err:
            self.format_output['error']['code'] = -1
            self.format_output['error']['description'] = "check ntp server failed with err: {}".format(str(err))
            self.format_output['data'] = self.check_note
            return self.format_output
        try:
            self.check_time_interval()
        except Exception as err:
            self.format_output['error']['code'] = -1
            self.format_output['error']['description'] = "check time interval failed with err: {}".format(str(err))
            self.format_output['data'] = self.check_note
            return self.format_output
        self.format_output['data'] = self.check_note
        return self.format_output


if __name__ == '__main__':
    far = NtpChecker()
    print(json.dumps(far.get_format_output()))

