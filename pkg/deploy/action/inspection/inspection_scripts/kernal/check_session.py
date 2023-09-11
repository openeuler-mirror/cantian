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


class CheckSession(BaseItem):
    '''
    check resource of host
    '''
    def __init__(self):
        super(CheckSession, self).__init__(self.__class__.__name__)
        self.suggestion = \
            "The SQL client connection is less than or equal to 80% of the configured value."
        self.standard = "The SQL client connection is less than or equal to 80% of the configured value."
        self.title = "Check the number of database connections"
        self.epv = "[0, 80]"

    def execute_sql(self, sql, vals):
        '''
        function : excute sql
        input : NA
        output : NA
        '''
        if not (self.context.db_user and self.context.db_passwd and
                self.context.port):
            vals["except"] = "Database connection failed"
            self.result.rst = ResultStatus.ERROR
            self.result.val = json.dumps(vals)
            return -1, 0

        status, records = self.get_sql_result(sql)
        if status :
            self.result.rst = ResultStatus.ERROR
            vals["except"] = records
        return status, records

    def get_db_session(self, vals):
        '''
        function : get session count of database
        input : NA
        output : int
        '''
        if self.copyright:
            sql = "SELECT COUNT(1) FROM DV_SESSIONS;"
        else:
            sql = "SELECT COUNT(1) FROM V\$SESSION;"
        self.result.raw += "SESSION: " + sql.replace("\$", "$") + "\n"
        status, records = self.execute_sql(sql, vals)
        if (status == 0):
            session_count = int(records["records"][0][0])
        else:
            session_count = 0
        return status, session_count

    def get_conf_session(self, vals):
        '''
        function : get session value of confFile
        input : dict
        output : int
        '''
        session_value = 1500
        status = 0
        conf_file = "%s/cfg/cantiand.ini" % self.data_path
        if not os.path.exists(conf_file):
            vals["except"] = "config file not exist"
            status = -1
            return status, 0

        content = ""
        with open(conf_file, 'r') as fp:
            content = fp.readlines()

        for line in content:
            if line.strip().startswith("SESSIONS"):

                try:
                    session_value = int(line.split("=")[1].strip())
                except (ValueError, IndexError):
                    session_value = 1500

        return status, session_value - 5

    def check_session(self, vals):
        '''
        function : check session
        input : dict
        output : NA
        '''
        status, db_session = self.get_db_session(vals)
        if status:
            return
        status, conf_session = self.get_conf_session(vals)
        if status:
            return
        usage = float(db_session) * 100 / float(conf_session)
        if usage > 80.0:
            self.result.rst = ResultStatus.NG

        vals['db_session'] = db_session
        vals['conf_session'] = conf_session
        vals['usage'] = "%.2f%%" % usage

    def do_check(self):
        '''
        function : Check for status
        input : NA
        output : NA
        '''

        vals = {}
        self.result.rst = ResultStatus.OK

        self.check_session(vals)
        # add resault to json
        self.result.val = json.dumps(vals)


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
    checker = CheckSession()
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
