import json
import os
import sys
import stat
import re
from pathlib import Path
from gs_check import CheckContext, BaseItem, ResultStatus

sys.path.append('/opt/cantian/action/inspection')
from log_tool import setup

DEPLOY_CONFIG_FILE = str(Path('/opt/cantian/config/deploy_param.json'))
UNIT_CONVERSION_MAP = {
    "P": 1024 * 1024 * 1024 * 1024,
    "T": 1024 * 1024 * 1024,
    "G": 1024 * 1024,
    "M": 1024,
    "K": 1
}


class CheckArchiveStatus(BaseItem):
    '''
    check version of database
    '''

    def __init__(self):
        super(CheckArchiveStatus, self).__init__(self.__class__.__name__)
        self.title = "Check the archive status"
        self.max_archive_size = 0
        self.max_archive_size_str = ""
        self.db_type = 0
        self.archive_ip = ""
        self.archive_fs = ""

    def check_config(self):
        values = {}
        if self.db_type == 0 or self.db_type == "0":
            self.result.rst = ResultStatus.WARNING
            self.result.sug = "The backup function is invalid. You are advised to enable it"
            values["result"] = "db_type is %s" % self.db_type
            self.result.val = json.dumps(values)
            return False
        return True

    def do_check(self):
        values = {}
        self.result.rst = ResultStatus.OK
        self.result.val = json.dumps(values)
        if not self.check_config():
            return

        cmd = "ping %s -i 1 -c 3 |grep ttl |wc -l" % self.archive_ip
        ret_code, str_out = self.get_cmd_result(cmd)
        if ret_code:
            self.result.rst = ResultStatus.ERROR
            self.result.sug = "1) Check whether the network link is normal\n " \
                              "2) If the link is normal, contact technical support engineers"
            values["except"] = "can not connect to %s" % self.archive_ip
            self.result.val = json.dumps(values)
            return

        cmd = "timeout 10 df -h | grep %s:/%s" % (self.archive_ip, self.archive_fs)
        ret_code, str_out = self.get_cmd_result(cmd)
        if ret_code:
            self.result.rst = ResultStatus.NG
            values["result"] = "can not find mount node info"
            self.result.val = json.dumps(values)
            return
        ret_info = str_out.split()

        max_capacity = ""
        max_capacity_unit_str = ""
        used_capacity = ""
        used_capacity_unit_str = ""
        if len(ret_info) > 2:
            used_capacity = ret_info[2]
            max_capacity = ret_info[1]
        if len(re.compile("[A-z]").findall(used_capacity)):
            used_capacity_unit_str = re.compile("[A-z]").findall(used_capacity)[0]
            max_capacity_unit_str = re.compile("[A-z]").findall(max_capacity)[0]
        used_capacity_number_str = re.sub("[A-z]", "", used_capacity)
        max_capacity_number_str = re.sub("[A-z]", "", max_capacity)

        used_capacity_num = float(used_capacity_number_str) * UNIT_CONVERSION_MAP.get(used_capacity_unit_str, 0)
        max_capacity_num = float(max_capacity_number_str) * UNIT_CONVERSION_MAP.get(max_capacity_unit_str, 0)

        if self.max_archive_size > max_capacity_num * 0.9:
            self.result.rst = ResultStatus.WARNING
            values["result"] = "The archive configuration capacity must be less than or " \
                               "equal to 90% of the maximum archive file system capacity"
            self.result.sug = "Please modify the archive file"
            self.result.val = json.dumps(values)
            return

        if used_capacity_num > self.max_archive_size * 0.95:
            self.result.rst = ResultStatus.WARNING
            values["result"] = "The used archive file capacity exceeds the threshold, causing archive failure"
            self.result.sug = "Contact technical support engineers"
            self.result.val = json.dumps(values)


if __name__ == '__main__':
    '''
    main
    '''
    # check if user is root
    cantian_log = setup('cantian')
    if os.getuid() == 0:
        cantian_log.error("Cannot use root user for this operation!")
        sys.exit(1)

    archive_object = CheckArchiveStatus()
    with os.fdopen(os.open(DEPLOY_CONFIG_FILE, os.O_RDONLY | os.O_EXCL, stat.S_IWUSR | stat.S_IRUSR), "r") \
            as file_handle:
        json_data = json.load(file_handle)
        archive_object.max_archive_size_str = json_data.get("MAX_ARCH_FILES_SIZE", "")
        archive_object.db_type = json_data.get("db_type", 0)
        archive_object.archive_ip = json_data.get("archive_logic_ip", "")
        archive_object.archive_fs = json_data.get("storage_archive_fs", "")
        unit_str = re.compile("[A-z]").findall(archive_object.max_archive_size_str)[0]
        number_str = re.sub("[A-z]", "", archive_object.max_archive_size_str)
        if UNIT_CONVERSION_MAP.get(unit_str, 0) != 0:
            archive_object.max_archive_size = int(number_str) * UNIT_CONVERSION_MAP.get(unit_str)

    checker_context = CheckContext()
    archive_object.run_check(checker_context, cantian_log)
