import sys
import os
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(CURRENT_PATH, "../"))
from logic.common_func import exec_popen, file_reader
from cantian_common.crypte_adapter import KmcResolve


ZSQL_INI_PATH = '/mnt/dbdata/local/cantian/tmp/data/cfg/ctsql.ini'


class ExecSQL(object):
    def __init__(self, sql):
        self.sql = sql

    def decrypted(self):
        ctsql_ini_data = file_reader(ZSQL_INI_PATH)
        encrypt_pwd = ctsql_ini_data[ctsql_ini_data.find('=') + 1:].strip()
        ctsql_passwd = KmcResolve.kmc_resolve_password("decrypted", encrypt_pwd)
        return ctsql_passwd

    def execute(self):
        ctsql_passwd = self.decrypted()
        sql = ("source ~/.bashrc && echo -e \"%s\" | "
               "ctsql sys@127.0.0.1:1611 -q -c \"%s\"") % (ctsql_passwd, self.sql)
        return_code, stdout, stderr = exec_popen(sql)
        if return_code:
            output = stdout + stderr
            err_msg = "Exec [%s] failed, details: %s" % (self.sql, output.replace(ctsql_passwd, "***"))
            raise Exception(err_msg)
        return stdout


if __name__ == '__main__':
    _sql_cmd = input()
    exec_sql = ExecSQL(_sql_cmd)
    try:
        print(exec_sql.execute())
    except Exception as e:
        exit(str(e))

