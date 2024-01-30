# coding=utf-8

class ResponseParse(object):
    def __init__(self, res):
        """

        :rtype: object
        """
        self.res = res

    def get_res_code(self):
        status_code = self.res.status_code
        error_code = -1
        error_des = "failed"
        if status_code == 200:
            res = self.res.json()
            error_code = res['error']['code']
            error_des = res['error']['description']
            if error_des is None or error_code == 0:
                error_des = "success"
        return status_code, int(error_code), error_des

    def get_rsp_data(self):
        status_code = self.res.status_code
        rsp_code = -1
        ret_result = None
        ret_data = None
        if status_code == 200:
            rsp_code = 0
            ret_result = self.res.json().get('error')
            ret_data = self.res.json().get('data')
        return rsp_code, ret_result, ret_data
