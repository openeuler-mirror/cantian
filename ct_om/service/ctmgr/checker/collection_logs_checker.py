from log_tool.om_log import TASK_LOG


class LogEnumCheck:

    @staticmethod
    def check(input_params_dict):
        _type = input_params_dict.get('type')
        if _type not in ('recent', 'all'):
            TASK_LOG.error('collection logs fail, type must be recent or all, type is {}'.format(_type))
            return False

        return True
