import os
import pwd
from pathlib import Path


class DeclearEnv:
    def __init__(self):
        self.version_file = str(Path("/opt/cantian/versions.yml"))
        self.root_id = 0
        self.deploy_id = 6000

    def get_env_type(self):
        """
        get current environment is cantian or mysql
        :return:
            string: cantian or mysql
        """
        if os.path.exists(self.version_file):
            return 'cantian'

        return 'mysql'

    def get_executor(self):
        """
        get name of the user, who is executing this processing
        :return:
            string: name of the user, such as root.
        """
        user_id = os.getuid()
        if user_id == self.root_id:
            return "root"

        if user_id == self.deploy_id:
            return pwd.getpwuid(self.deploy_id)[0]  # 列表下标0为uid对应的用户名

        raise ValueError("[error] executor must be root or deploy_user")
