#!/usr/bin/env python
# coding: UTF-8
import json
import os
import sys
from ct_check import CheckContext
from ct_check import BaseItem
from ct_check import ResultStatus
sys.path.append('/opt/cantian/action/inspection')
from log_tool import setup


class CheckDBVersion(BaseItem):
    '''
    check version of database
    '''
    def __init__(self):
        super(CheckDBVersion, self).__init__(self.__class__.__name__)
        self.title = "Check the database version"

    def do_check(self):
        '''
        function : Check version of database
        input : NA
        output : NA
        '''

        vals = {}
        self.result.rst = ResultStatus.OK

        cmd = "source ~/.bashrc && %s/cantiand -v | grep -oP \"\K\d+\.\d+\.\d+\"" % \
              os.path.join(self.context.app_path, "bin")
        self.result.raw = cmd
        status, output = self.get_cmd_result(cmd, self.user)
        if (status == 0):
            vals["db_version"] = output
            cmd = "cat /opt/cantian/versions.yml | grep -oP 'Version: \K\d+\.\d+\.\d+'"
            status, output = self.get_cmd_result(cmd, self.user)
            version_info = vals.get("db_version").strip()
            if version_info and version_info != output.strip(" "):
                self.result.rst = ResultStatus.ERROR
                vals["except"] = "Cantiand version is different from the version.yaml"
            if not version_info:
                raise Exception("Failed to find Cantian database version info.")
        else:
            self.result.rst = ResultStatus.ERROR
            vals["except"] = output
        # add resault to json
        self.result.val = json.dumps(vals)


if __name__ == '__main__':
    '''
    main
    '''
    # check if user is root
    cantian_log = setup('cantian')
    if os.getuid() == 0:
        cantian_log.error("Cannot use root user for this operation!")
        sys.exit(1)

    # main function
    checker = CheckDBVersion()
    checker_context = CheckContext()
    db_user = input()
    db_pass = input()
    checker_context.db_user = db_user
    checker_context.db_passwd = db_pass
    context_attr = ["db_addr", "port"]
    item_index = 0
    for argv in sys.argv[1:]:
        setattr(checker_context, context_attr[item_index], argv)
        item_index += 1
    checker.run_check(checker_context, cantian_log)
