import logging
import os
from logging import handlers
from log_tool.om_log_config import CONSOLE_CONF

log_config = CONSOLE_CONF.get("log")
LOG_DIR_MODE = 700
LOG_DIR_MODE_OCT = 0o700
LOG_FILE_MODE = 640
LOG_FILE_MODE_OCT = 0o640


def _get_log_file_path(project):
    logger_dir = log_config.get("log_dir")

    if logger_dir:
        if not os.path.exists(logger_dir):
            os.makedirs(logger_dir, mode=LOG_DIR_MODE_OCT)
        else:
            if oct(os.stat(logger_dir).st_mode)[-3:] != str(LOG_DIR_MODE):
                os.chmod(logger_dir, LOG_DIR_MODE_OCT)

        return os.path.join(logger_dir, "{}.log".format(project))

    return ''


def setup(project_name):
    """
    init log config
    :param project_name:
    """
    log_root = logging.getLogger(project_name)
    for handler in list(log_root.handlers):
        log_root.removeHandler(handler)

    log_path = _get_log_file_path(project_name)
    if log_path:
        file_log = handlers.RotatingFileHandler(
            log_path, maxBytes=log_config.get("log_file_max_size"),
            backupCount=log_config.get("log_file_backup_count"))
        log_root.addHandler(file_log)

    if oct(os.stat(log_path).st_mode)[-3:] != str(LOG_FILE_MODE):
        os.chmod(log_path, LOG_FILE_MODE_OCT)

    for handler in log_root.handlers:
        handler.setFormatter(
            logging.Formatter(
                fmt=log_config.get("logging_context_format_string"),
                datefmt=log_config.get("log_date_format")))

    if log_config.get("debug"):
        log_root.setLevel(logging.DEBUG)
    else:
        log_root.setLevel(logging.INFO)
    return log_root


LOG = setup("ctmgr_audit")
TASK_LOG = setup("ctmgr_task")
DEPLOY_LOG = setup("ctmgr_deploy")
LOGS_COLLECTION = setup("ctmgr_logs_collection")


class LOGGER:
    """
    审计日志需要参数： client_pid, client_uid, cmd, result, begin_time, finish_time
    """
    def __init__(self, client_pid, client_uid, begin_time, finish_time='', request_time=''):
        self.begin_time = begin_time
        self.request_time = request_time
        self.finish_time = finish_time
        self.client_pid = client_pid
        self.client_uid = client_uid

    def set_request_time(self, request_time):
        self.request_time = request_time

    def set_finish_time(self, finish_time):
        self.finish_time = finish_time

    def format_log_message(self, cmd, result):
        return 'client_pid=[{}],client_uid=[{}],command=[{}],running_status=[{}],begin_time=[{}],request_time=[{}],' \
               'finish_time=[{}]'.format(
                self.client_pid, self.client_uid, cmd, result, self.begin_time, self.request_time, self.finish_time)

    def info(self, cmd, result):
        LOG.info(self.format_log_message(cmd, result))

    def debug(self, cmd, result):
        LOG.debug(self.format_log_message(cmd, result))

    def warning(self, cmd, result):
        LOG.warning(self.format_log_message(cmd, result))

    def error(self, cmd, result):
        LOG.error(self.format_log_message(cmd, result))
