import os
import pwd
from pathlib import Path


class DeclearEnv:
    def __init__(self):
        self.version_file = str(Path("/opt/cantian/versions.yml"))
        self.root_id = 0

    @staticmethod
    def get_run_user():
        with open("/opt/cantian/action/env.sh", "r", encoding="utf-8") as f:
            env_config = f.readlines()
        run_user = "cantian"
        for line in env_config:
            if line.startswith("cantian_user"):
                run_user = line.split("=")[1].strip("\n").strip('"')
                break
        return run_user

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

        run_user = self.get_run_user()
        user_info = pwd.getpwnam(run_user)
        if user_id == user_info.pw_uid:
            return run_user

        raise ValueError("[error] executor must be root or deploy_user")
