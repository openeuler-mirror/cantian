import os
from pathlib import Path

from task_obj import TASK
from log_tool.om_log import LOGGER, TASK_LOG
from common.output_tool import CommonResult
from common.common_tool import TimeTool

cur_abs_path, _ = os.path.split(os.path.abspath(__file__))
upper_path = os.path.abspath(os.path.join(cur_abs_path, ".."))
LOG_FILE_PATH = str(Path('{}/logs_collection'.format(upper_path), 'log_packing_progress.json'))
SUCCESS = 'success'


class QueryLogProgressTask(TASK):

    def __init__(self, task_name, handler, params_check_dict):
        super().__init__(task_name, handler, params_check_dict)

    def task_execute(self, input_params, task_logger: LOGGER):
        task_logger.set_finish_time(TimeTool.get_current_time())
        task_logger.info(self.task_name, SUCCESS)
        TASK_LOG.info('doing logs collection progress query, path is: {}'.format(LOG_FILE_PATH))
        return CommonResult(output_data=LOG_FILE_PATH)


if __name__ == '__main__':
    lt = QueryLogProgressTask(None, None)
    lg = LOGGER(None, None, None)
    lt.task_execute({}, lg)
