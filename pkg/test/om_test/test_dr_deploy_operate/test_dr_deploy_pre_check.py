import sys
import mock
import unittest
import collections
sys.modules["requests"] = mock.MagicMock()
sys.modules["termios"] = mock.MagicMock()
sys.modules["pty"] = mock.MagicMock()
sys.modules["tty"] = mock.MagicMock()
import storage_operate.dr_deploy_operate.dr_deploy_pre_check as pre_check


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

    def tearDown(self):
        super(DRDeployPreCheckTestCase, self).tearDown()

    @mock.patch("storage_operate.dr_deploy_operate.dr_deploy_pre_check.exec_popen")
    def test_check_dr_process_no_error(self, mock_exec_popen):
        mock_exec_popen.return_value = (2, 0, 2)
        result = pre_check.DRDeployPreCheck.check_dr_process()
        self.assertEqual(None, result)

    @mock.patch("storage_operate.dr_deploy_operate.dr_deploy_pre_check.exec_popen")
    def test_check_dr_process_all_error(self, mock_exec_popen):
        mock_exec_popen.return_value = (2, 1, 2)
        target_error = ("Dr deploy is executing, please check, details:\n1Dr undeploy is executing, please " +\
                        "check, details:\n1Dr full sync is executing, please check, details:\n1")
        with self.assertRaisesRegex(Exception, target_error):
            pre_check.DRDeployPreCheck.check_dr_process()


class FakeParamCheck(pre_check.ParamCheck):
    def __init__(self):
        self.mysql_user = None
        self.mysql_cmd = None
        self.action = None
        self.site = None
        self.dr_deploy_params = {"dm_ip": "127.0.0.1", "dm_user": "admin"}


args = collections.namedtuple("args", ["action", "site", "mysql_cmd", "mysql_user", "display"])


class ParamCheckTestCase(unittest.TestCase):
    def setUp(self):
        super(ParamCheckTestCase, self).setUp()
        self.param_check = FakeParamCheck()

    @mock.patch("builtins.input", side_effect=["password1", "password2"])
    @mock.patch("cantian_common.mysql_shell.MysqlShell.close_session", return_value="")
    @mock.patch("cantian_common.mysql_shell.MysqlShell.start_session", return_value="")
    @mock.patch("logic.storage_operate.StorageInf.login", return_value="")
    @mock.patch("argparse.ArgumentParser")
    def test_execute_normal(self, mock_parser, mock_login, mock_start_session, mocke_close_session, mock_input):
        args.action = "deploy"
        args.site = "active"
        mock_parser.parse_args.return_value = args
        self.param_check.execute()

    @mock.patch("builtins.input", side_effect=["password1", "password2"])
    @mock.patch("cantian_common.mysql_shell.MysqlShell.close_session", return_value="")
    @mock.patch("cantian_common.mysql_shell.MysqlShell.start_session", return_value="")
    @mock.patch("logic.storage_operate.StorageInf.login", side_effect=Exception("test"))
    @mock.patch("argparse.ArgumentParser")
    def test_execute_abnormal(self, mock_parser, mock_login, mock_start_session, mocke_close_session, mock_input):
        args.action = "deploy"
        args.site = "active"
        mock_parser.parse_args.return_value = args
        with self.assertRaisesRegex(Exception, "test"):
            self.param_check.execute()

