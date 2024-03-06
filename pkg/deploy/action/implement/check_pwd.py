import json
import sys
import os
CUR_PATH = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CUR_PATH, "../"))
from logic.common_func import exec_popen
from om_log import LOGGER as LOG

PWD_LEN = 8


class PassWordChecker:
    def __init__(self, pwd):
        self.pwd = pwd
        self.user = 'ctcliuser'

    @staticmethod
    def check_key_passwd(key_file_path, passwd):
        """
        校验私钥key和密码
        """
        cmd = f"openssl rsa -in '{key_file_path}' -check -noout -passin pass:'{passwd}'"
        ret_code, _, stderr = exec_popen(cmd)
        stderr = str(stderr)
        stderr.replace(passwd, "****")
        if ret_code:
            raise Exception("The password is incorrect.")
    
    @staticmethod
    def get_crt_modulus(cert_file_path):
        """
        获取crt证书的模数
        """
        cmd = f"openssl x509 -noout -modulus -in '{cert_file_path}' | openssl md5"
        ret_code, stdout, stderr = exec_popen(cmd)
        if ret_code:
            raise Exception("Failed to get crt modulus, output:%s" % str(stderr))
        return str(stdout)
    
    @staticmethod
    def get_key_modulus(key_file_path, passwd):
        """
        获取私钥key的模数
        """
        cmd = f"echo -e '{passwd}' | openssl rsa -noout -modulus -in '{key_file_path}' | openssl md5"
        ret_code, stdout, stderr = exec_popen(cmd)
        stderr = str(stderr)
        stderr.replace(passwd, "****")
        if ret_code:
            raise Exception("Failed to get key modulus, output:%s" % str(stderr))
        return str(stdout)

    def verify_new_passwd(self, shortest_len=PWD_LEN):
        """
        Verify new password.
        :return: NA
        """
        # eg 'length in [8-64]'
        if len(self.pwd) < shortest_len or len(self.pwd) > 64:
            LOG.error("The length of password must be %s to 64.", shortest_len)
            return 1

        upper_cases = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        lower_cases = set("abcdefghijklmnopqrstuvwxyz")
        digits = set("1234567890")
        special_cases = set(r"""`~!@#$%^&*()-_=+\|[{}]:'",<.>/? """)

        # Contains at least three different types of characters
        types = 0
        passwd_set = set(self.pwd)
        for cases in [upper_cases, lower_cases, digits, special_cases]:
            if passwd_set & cases:
                types += 1
        if types < 3:
            LOG.error("Error: Password must contains at least three different types of characters.")
            return 1

        # Only can contains enumerated cases
        all_cases = upper_cases | lower_cases | digits | special_cases
        un_cases = passwd_set - all_cases
        if un_cases:
            LOG.error("Error: There are characters that are not allowed in the password: '%s'", "".join(un_cases))
            return 1

        return 0

    def check_cert_passwd(self):
        if len(self.pwd) > 32:
            raise Exception("cert pwd is too long. The length should not exceed 32.")
        certificate_dir = "/opt/cantian/common/config/certificates"
        cert_file = os.path.join(certificate_dir, "mes.crt")
        key_file = os.path.join(certificate_dir, "mes.key")

        self.check_key_passwd(key_file, self.pwd)
        # 提取证书和私钥的模数
        certificate_modulus = self.get_crt_modulus(cert_file)
        private_key_modulus = self.get_key_modulus(key_file, self.pwd)

        # 检查模数是否匹配
        if certificate_modulus == private_key_modulus:
            LOG.info("The certificate matches the private key.")
        else:
            raise Exception("The certificate and private key do not match.")


if __name__ == '__main__':
    pwd_checker = PassWordChecker(input())
    action = "check_pwd"
    if len(sys.argv) > 1:
        action = sys.argv[1]
    operator = {
        "check_pwd": pwd_checker.verify_new_passwd,
        "check_cert_pwd": pwd_checker.check_cert_passwd
    }
    exit(operator.get(action)())
