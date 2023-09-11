import json
import os
import stat
from pathlib import Path

TEMPLETE_BODY_EN = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>inspection</title>
</head>
<body>
    <h1 style="text-align: center">inspection result</h1>
    {}
</body>
</html>
'''

TEMPLETE_BODY_ZH = '''
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>巡检</title>
</head>
<body>
    <h1 style="text-align: center">巡检结果</h1>
    {}
</body>
</html>
'''
TEMPLETE_DEV = '''
    <div style="font-size:12px;width: 80%;position: center; margin-left:10%;margin-right: 10%;margin-top: 20px;max-height: 700px">
        <h2 style="text-align: left;font-size: 20px">{inspection_name}</h2>
        <table border=1 style="width:100%">
            <tr>
                <td style="width: 10%;background-color: darkgray;text-align: center">
                    {information}
                </td>
                <td style="width: 90%">
                    <div style="max-height: 200px;overflow-y:auto;margin-left: 20px;margin-bottom: 5px;margin-top:5px">
                        {information_detail}
                    </div>
                </td>
            </tr>
            <tr>
                <td style="width: 10%;background-color: darkgray;text-align: center">
                    {method}
                </td>
                <td style="width: 90%">
                    <div style="margin-left: 20px;margin-top: 5px;margin-bottom: 5px">
                        {method_detail}
                    </div>
                </td>
            </tr>
            <tr>
                <td style="width: 10%;background-color: darkgray;text-align: center">
                    {criteria}
                </td>
                <td style="width: 90%">
                    <div style="margin-left: 20px;margin-top: 5px;margin-bottom: 5px">
                        {criteria_detail}
                    </div>
                </td>
            </tr>
            <tr style="display: {display}">
                <td style="width: 10%;background-color: darkgray;text-align: center">
                    {suggestion}
                </td>
                <td style="width: 90%">
                    <div style="margin-left: 20px;margin-top: 5px;margin-bottom: 5px">
                        {suggestion_detail}
                    </div>
                </td>
            </tr>
            <tr>
                <td style="width: 10%;background-color: darkgray;text-align: center">
                    {result}
                </td>
                <td width="90%">
                    <div style="margin-left: 20px;margin-top: 5px;margin-bottom: 5px">
                        {result_detail}
                    </div>
                </td>
            </tr>
        </table>
    </div>
'''


class GenHtmlRes(object):
    def __init__(self, inspect_res, file_path, node_info):
        self.inspect_res = inspect_res
        self.file_path = file_path
        self.node_info = node_info

    def write_file(self, content, lang="zh"):
        file_name = "{}_inspection_result_{}.html".format(self.node_info, lang)
        file_path = str(Path(self.file_path + '/' + file_name))
        modes = stat.S_IWRITE | stat.S_IRUSR
        flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT
        with os.fdopen(os.open(file_path, flags, modes), 'w', encoding='utf-8') as file:
            file.write(content)

    def generate_html_zh(self):
        dev_list = ""
        for item in self.inspect_res:
            resource_zh = item.get("resource_zh")
            result = "成功" if item.get("inspection_result") == "success" else "失败"
            display = "none" if item.get("inspection_result") == "success" else 'contents'
            inspection_detail = json.dumps(item.get("inspection_detail"), indent=4, ensure_ascii=False).strip("\"")
            method_detail = json.dumps(resource_zh.get("检查步骤"), indent=4, ensure_ascii=False).strip("\"")
            criteria = json.dumps(resource_zh.get("检查方法"), indent=4, ensure_ascii=False).strip("\"")
            suggestion = json.dumps(resource_zh.get("修复建议"), indent=4, ensure_ascii=False).strip("\"")
            dev_one = TEMPLETE_DEV.format(inspection_name=item.get("description_zn"),
                                          information="原始信息",
                                          information_detail=inspection_detail.replace('\\n', "<br>"),
                                          method="检查步骤",
                                          method_detail=method_detail.replace('\\n', "<br>"),
                                          criteria="检查方法",
                                          criteria_detail=criteria.replace('\\n', "<br>"),
                                          suggestion="修复建议",
                                          suggestion_detail=suggestion.replace('\\n', "<br>"),
                                          result="检查结果",
                                          result_detail=result,
                                          display=display
                                          )
            dev_list += dev_one
        zh_html_res = TEMPLETE_BODY_ZH.format(dev_list)
        self.write_file(zh_html_res, 'zh')

    def generate_html_en(self):
        dev_list = ""
        for item in self.inspect_res:
            resource_en = item.get("resource_en")
            display = "none" if item.get("inspection_result") == "success" else 'contents'
            inspection_detail = json.dumps(item.get("inspection_detail"), indent=4, ensure_ascii=False).strip("\"")
            method_detail = json.dumps(resource_en.get("method"), indent=4, ensure_ascii=False).strip("\"")
            criteria = json.dumps(resource_en.get("description"), indent=4, ensure_ascii=False).strip("\"")
            suggestion = json.dumps(resource_en.get("suggestion"), indent=4, ensure_ascii=False).strip("\"")
            dev_one = TEMPLETE_DEV.format(inspection_name=item.get("description_en"),
                                          information="information",
                                          information_detail=inspection_detail.replace('\\n', "<br>"),
                                          method="method",
                                          method_detail=method_detail.replace('\\n', "<br>"),
                                          criteria="description",
                                          criteria_detail=criteria.replace('\\n', "<br>"),
                                          suggestion="suggestion",
                                          suggestion_detail=suggestion.replace('\\n', "<br>"),
                                          result="result",
                                          result_detail=item.get("inspection_result"),
                                          display=display
                                          )
            dev_list += dev_one
        en_html_res = TEMPLETE_BODY_EN.format(dev_list)
        self.write_file(en_html_res, 'en')
