import json


class HttpResult:

    def __init__(self, res_data):
        self.res_data = res_data

    def __str__(self):
        if isinstance(self.res_data, str):
            return self.res_data

        return json.dumps(self.res_data)


class CommonResult:

    def __init__(self, output_data="", error_code=0, description=""):
        self.output_data = output_data
        self.error_code = error_code
        self.description = description

    def __str__(self):
        result = {
            "data": {
                "ctmgr_common_output": self.output_data
            },
            "error": {
                "code": int(self.error_code),
                "description": self.description
            }
        }

        return json.dumps(result)

    def set_error_code(self, error_code):
        self.error_code = int(error_code)

    def set_output_data(self, output_data):
        self.output_data = output_data

    def set_description(self, description):
        self.description = str(description)


if __name__ == '__main__':
    res = CommonResult()
    res.set_output_data("task_obj.task_execute(input_params_dict)")
    res.set_output_data("doing XXX success")
