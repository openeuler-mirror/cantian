import sys
import mock
import unittest
import collections
sys.modules["requests"] = mock.MagicMock()
sys.modules["termios"] = mock.MagicMock()
sys.modules["pty"] = mock.MagicMock()
sys.modules["tty"] = mock.MagicMock()
import storage_operate.dr_deploy_operate.dr_deploy_pre_check as pre_check


args = collections.namedtuple("args", ["action", "site", "mysql_cmd", "mysql_user", "display", "conf"])


class getConfigTestCase(unittest.TestCase):
    @mock.patch("storage_operate.dr_deploy_operate.dr_deploy_pre_check.read_json_config")
    def test_get_config_values_normal(self, mock_json_config):
        mock_json_config.return_value = {"deploy_policy": "ModeA", "ModeA": {"config": {"test": "test keys"}}}
        result =  pre_check.get_config_values("test")
        self.assertEqual("test keys", result)

    def test_get_config_values_abnormal(self):
        pre_check.read_json_config = mock.Mock(return_value={"deploy_policy": "default",
                                                             "ModeA": {"config": {"test": "test keys"}}})
        result =  pre_check.get_config_values("test")
        self.assertEqual('', result)


class FakeDRDeployPreCheck(pre_check.DRDeployPreCheck):
    def __init__(self, password=None, conf=None):
        self.deploy_operate = None
        self.storage_opt = None
        self.deploy_params = None
        self.remote_vstore_id = None
        self.conf = conf
        self.local_conf_params = dict()
        self.remote_conf_params = dict()
        self.remote_device_id = None
        self.site = None
        self.dm_login_passwd = password
        self.remote_operate = None
        self.run_user = "cantian_user"
        self.domain_name = None
        self.hyper_domain_id = None
        self.vstore_pair_id = None
        self.ulog_fs_pair_id = None
        self.page_fs_pair_id = None
        self.meta_fs_pair_id = None


class DRDeployPreCheckTestCase(unittest.TestCase):
    def setUp(self):
        super(DRDeployPreCheckTestCase, self).setUp()
        self.dr_deploy_pre_check_none = FakeDRDeployPreCheck()
        self.dr_deploy_pre_check_not_none = FakeDRDeployPreCheck("password", "conf")

    @mock.patch("storage_operate.dr_deploy_operate.dr_deploy_pre_check.exec_popen")
    def test_execute_check_dr_error(self, mock_exec_popen):
        mock_exec_popen.return_value = (2, 1, 2)
        target_error = ("Dr deploy is executing, please check, details:\n1Dr undeploy is executing, please " + \
                        "check, details:\n1Dr full sync is executing, please check, details:\n1")
        with self.assertRaisesRegex(Exception, target_error):
            self.dr_deploy_pre_check_none.execute()

    @mock.patch("builtins.input", return_value="password")
    @mock.patch("os.path.isfile", return_value=False)
    @mock.patch("argparse.ArgumentParser.parse_args", return_value=args)
    @mock.patch("storage_operate.dr_deploy_operate.dr_deploy_pre_check.exec_popen")
    def test_execute_no_parse_input_parse_error(self, mock_exec_popen, mock_parser, mock_file, mock_input):
        args.site = "active"
        mock_exec_popen.return_value = (2, 0, 2)
        target_error = "Config file\[conf\] is not exist."
        with self.assertRaisesRegex(Exception, target_error):
            self.dr_deploy_pre_check_not_none.execute()
        self.assertEqual(mock_input.call_count, 0)



class FakeParamCheck(pre_check.ParamCheck):
    def __init__(self):
        self.mysql_user = None
        self.mysql_cmd = None
        self.action = None
        self.site = None
        self.dr_deploy_params = {"dm_ip": "127.0.0.1", "dm_user": "admin"}


class ParamCheckTestCase(unittest.TestCase):
    def setUp(self):
        super(ParamCheckTestCase, self).setUp()
        self.param_check = FakeParamCheck()

    @mock.patch("time.sleep")
    @mock.patch("builtins.input", side_effect=["password1", "password2"])
    @mock.patch("cantian_common.mysql_shell.MysqlShell.close_session")
    @mock.patch("cantian_common.mysql_shell.MysqlShell.start_session")
    @mock.patch("logic.storage_operate.StorageInf.login")
    @mock.patch("logic.storage_operate.StorageInf.logout")
    @mock.patch("argparse.ArgumentParser.parse_args", return_value=args)
    def test_execute_normal(self, mock_parser, mock_logout, mock_login, mock_start_session,
                            mock_close_session, mock_input, mock_sleep):
        args.action = "deploy"
        args.site = "active"
        self.param_check.execute()
        self.assertEqual(mock_input.call_count, 2)

    @mock.patch("builtins.input", side_effect=["password1", "password2"])
    @mock.patch("cantian_common.mysql_shell.MysqlShell.close_session")
    @mock.patch("cantian_common.mysql_shell.MysqlShell.start_session")
    @mock.patch("logic.storage_operate.StorageInf.login", side_effect=Exception("test"))
    @mock.patch("argparse.ArgumentParser.parse_args", return_value=args)
    def test_execute_dm_pwd_error(self, mock_parser, mock_login, mock_start_session,
                                  mock_close_session, mock_input):
        args.action = "deploy"
        args.site = "active"
        with self.assertRaisesRegex(Exception, "test"):
            self.param_check.execute()

    @mock.patch("time.sleep")
    @mock.patch("builtins.input", side_effect=["password1", "password2"])
    @mock.patch("cantian_common.mysql_shell.MysqlShell.close_session", side_effect=Exception("password2 test"))
    @mock.patch("cantian_common.mysql_shell.MysqlShell.start_session")
    @mock.patch("logic.storage_operate.StorageInf.login")
    @mock.patch("logic.storage_operate.StorageInf.logout")
    @mock.patch("argparse.ArgumentParser.parse_args", return_value=args)
    def test_execute_sql_pwd_error(self, mock_parser, mock_logout, mock_login, mock_start_session,
                                   mock_close_session, mock_input, mock_sleep):
        args.action = "deploy"
        args.site = "active"
        with self.assertRaisesRegex(Exception, "\*\*\* test"):
            self.param_check.execute()
        self.assertEqual(mock_sleep.call_count, 3)
