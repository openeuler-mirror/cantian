#!/usr/bin/env python
# coding: UTF-8
import json
import os
import sys
from gs_check import CheckContext
from gs_check import BaseItem
from gs_check import ResultStatus
sys.path.append('/opt/cantian/action/inspection')
from log_tool import setup

class CheckDRCResRatio(BaseItem):
    '''
    check DRC res ratio
    '''
    def __init__(self):
        super(CheckDRCResRatio, self).__init__(self.__class__.__name__)
        self.suggestion = "If DRC resource ratio is too high, try checkpoint"
        self.standard = "Check DRC res ratio, check if ratio is too high."
        self.title = "Check for DRC res ratio"
        self.epv = 0.9375

    def do_check(self):
        '''
        function : Check for DRC res ratio
        input : NA
        output : NA
        '''
        self.result.epv = self.epv
        self.result.rst = ResultStatus.OK

        sql = "SELECT RATIO FROM DV_DRC_RES_RATIO;"
        self.result.raw = sql.replace("\$", "$")

        res_ratio_dict = {}
        # Execute sql command
        status, records = self.get_sql_result(sql)

        if (status == 0):
            res_ratio_dict['PAGE_BUF'] = records["records"][0][0]
            res_ratio_dict['GLOBAL_LOCK'] = records["records"][1][0]
            res_ratio_dict['LOCAL_LOCK'] = records["records"][2][0]
            res_ratio_dict['LOCAL_TXN'] = records["records"][3][0]
            res_ratio_dict['GLOBAL_TXN'] = records["records"][4][0]
            res_ratio_dict['LOCK_ITEM'] = records["records"][5][0]
            self.result.rst = ResultStatus.OK
            for value in res_ratio_dict.values():
                if (float(value) >= self.result.epv) :
                    self.result.rst = ResultStatus.NG
        else:
            self.result.rst = ResultStatus.ERROR
            vals["except"] = records

        # add result to json
        self.result.val = json.dumps(res_ratio_dict)

if __name__ == '__main__':
    '''
    main
    '''
    # check if user is root
    cantian_log = setup('cantian')
    if(os.getuid() == 0):
        cantian_log.error("Cannot use root user for this operation!")
        sys.exit(1)

    # main function
    checker = CheckDRCResRatio()
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
