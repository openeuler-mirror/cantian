import os
import stat
from pathlib import Path
from datetime import datetime
from datetime import timezone

from task_obj import PyTask
from log_tool.om_log import TASK_LOG

MAX_AUDIT_NUM = 10
DIR_NAME, _ = os.path.split(os.path.abspath(__file__))
INSPECTION_PATH = str(Path('{}/../inspections'.format(DIR_NAME)))


class AuditTask(PyTask):

    def __init__(self, task_name, handler, file_path, py_input, params_check_dict):
        super().__init__(task_name, handler, file_path, py_input, params_check_dict)
        self.output_data = ''
        self.audit_path = INSPECTION_PATH

    def task_execute(self, input_params, task_logger):
        res = super(AuditTask, self).task_execute(input_params=input_params, task_logger=task_logger)

        audit_info = eval(eval(res.__str__()).get('data', {}).get('ctmgr_common_output', ''))

        audit_result = audit_info.get('RESULT')
        if str(audit_result) == '0':
            self.output_data = str(audit_info).replace('\n', '')
            self.write_audit()
            TASK_LOG.info('show cantian status success')
            res.set_output_data(str(audit_info.get('CMS_STAT')))
            return res
        else:
            TASK_LOG.error('show cantian status fail')
            res.set_output_data('')
            res.set_error_code(1)
            return res

    def write_audit(self):
        if not os.path.exists(self.audit_path):
            os.mkdir(self.audit_path)

        audit_list = sorted(os.listdir(self.audit_path))
        while len(audit_list) >= MAX_AUDIT_NUM:
            os.remove(str(Path(self.audit_path + "/" + str(audit_list[0]))))
            audit_list.pop(0)

        modes = stat.S_IWRITE | stat.S_IRUSR
        flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT
        utc_now = datetime.utcnow()
        cur_time = utc_now.replace(tzinfo=timezone.utc).astimezone(tz=None)
        audit_file = 'inspection_{}'.format(str(cur_time.strftime("%Y%m%d%H%M%S")))
        audit_file_path = str(Path(self.audit_path + '/' + audit_file))
        with os.fdopen(os.open(audit_file_path, flags, modes), 'w', encoding='utf-8') as file:
            file.write(self.output_data)


