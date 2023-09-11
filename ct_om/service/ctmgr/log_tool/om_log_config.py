import os
from pathlib import Path

dir_name, file_name = os.path.split(os.path.abspath(__file__))


CONSOLE_CONF = {
    "log": {
        "use_syslog": False,
        "debug": False,
        "log_dir": str(Path('{}/../ctmgr_log'.format(str(dir_name)))),
        "log_file_max_size": 1048576,
        "log_file_backup_count": 5,
        "log_date_format": "%Y-%m-%d %H:%M:%S",
        "logging_default_format_string": "time=[%(asctime)s],level=[%(levelname)s],pid=[%(process)d],"
                                         "thread=[%(threadName)s],tid=[%(thread)d],"
                                         "file=[%(filename)s:%(lineno)d %(funcName)s],%(message)s",
        "logging_context_format_string": "time=[%(asctime)s],level=[%(levelname)s],pid=[%(process)d],"
                                         "thread=[%(threadName)s],tid=[%(thread)d],"
                                         "file=[%(filename)s:%(lineno)d %(funcName)s],%(message)s"
    }
}
