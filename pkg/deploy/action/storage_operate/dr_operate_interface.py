#!/usr/bin/python
# coding=utf-8
import traceback
import sys
from om_log import LOGGER as LOG
from storage_operate.dr_deploy_operate.dr_deploy_pre_check import DRDeployPreCheck, ParamCheck
from storage_operate.dr_deploy_operate.dr_deploy import DRDeploy
from storage_operate.dr_deploy_operate.dr_undeploy import UNDeploy
from storage_operate.dr_deploy_operate.dr_deploy_progress_query import ProgressQuery
from storage_operate.dr_deploy_operate.dr_deploy_full_sync import FullSyncRepPair
from storage_operate.dr_deploy_operate.dr_deploy_switchover import SwitchOver, DRRecover, FailOver
from storage_operate.dr_deploy_operate.update_dr_params import UpdateDRParams

HELP_MSG = "example:\n" \
           "        sh appctl.sh dr_operate pre_check active/standby --conf=config_file_path\n" \
           "        sh appctl.sh dr_operate deploy standby/active -" \
           "-mysql_cmd='/usr/local/mysql/bin/mysql' --mysql_user=myuser\n" \
           "        sh appctl.sh dr_operate progress_query --action=deploy/full_sync --display=table/json\n" \
           "        sh appctl.sh dr_operate undeploy active/standby\n" \
           "        sh appctl.sh dr_operate switch_over\n" \
           "        sh appctl.sh dr_operate recover\n" \
           "        sh appctl.sh dr_operate fail_over\n" \
           "        sh appctl.sh dr_operate update_conf\n"


class DRDeployOperate(object):
    @staticmethod
    def pre_check():
        del sys.argv[1]
        dr_pre_check = DRDeployPreCheck()
        dr_pre_check.execute()

    @staticmethod
    def deploy():
        del sys.argv[1]
        dr_pre_check = DRDeploy()
        dr_pre_check.execute()

    @staticmethod
    def param_check():
        del sys.argv[1]
        dr_pre_check = ParamCheck()
        dr_pre_check.execute()

    @staticmethod
    def progress_query():
        del sys.argv[1]
        dr_process_query = ProgressQuery()
        dr_process_query.execute()

    @staticmethod
    def undeploy():
        del sys.argv[1]
        dr_pre_check = UNDeploy()
        dr_pre_check.execute()

    @staticmethod
    def full_sync():
        del sys.argv[1]
        full_sync_rep_pair = FullSyncRepPair()
        full_sync_rep_pair.execute()

    @staticmethod
    def switch_over():
        del sys.argv[1]
        switch_over = SwitchOver()
        switch_over.execute()

    @staticmethod
    def recover():
        del sys.argv[1]
        dr_recover = DRRecover()
        dr_recover.execute()

    @staticmethod
    def fail_over():
        del sys.argv[1]
        fail_over = FailOver()
        fail_over.execute()

    @staticmethod
    def update_conf():
        del sys.argv[1]
        update_dr_params = UpdateDRParams()
        update_dr_params.execute()

    @staticmethod
    def help():
        print(HELP_MSG)


def main():
    err_msg = "Failed to parse the DR setup command, deploy operate commands " \
              + HELP_MSG
    dr_deploy_operate = DRDeployOperate()
    if len(sys.argv) <= 1:
        raise Exception(err_msg)
    action = sys.argv[1]
    try:
        getattr(dr_deploy_operate, action)
    except AttributeError as _err:
        raise Exception(err_msg) from _err
    getattr(dr_deploy_operate, action)()


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        exit(str(err))
