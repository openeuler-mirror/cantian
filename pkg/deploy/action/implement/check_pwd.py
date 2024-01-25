import json
import sys
import os
CUR_PATH = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CUR_PATH, "../"))
from om_log import LOGGER as LOG

PWD_LEN = 8


class PassWordChecker:
    def __init__(self, pwd):
        self.pwd = pwd
        self.user = 'ctcliuser'

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
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        from OpenSSL import crypto
        deploy_config = os.path.join(CUR_PATH, "../../config/deploy_param.json")
        with open(deploy_config, "r") as f:
            config_json = json.loads(f.read())
        storage_share_fs = config_json.get("storage_share_fs")
        node_id = config_json.get("node_id")
        certificate_dir = f"/mnt/dbdata/remote/share_{storage_share_fs}/certificates/node{node_id}"
        cert_file = os.path.join(certificate_dir, "mes.crt")
        key_file = os.path.join(certificate_dir, "mes.key")
         # 加载证书
        with open(cert_file, 'rb') as f:
            cert_data = f.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

        # 加载私钥
        with open(key_file, 'rb') as f:
            key_data = f.read()
        private_key = serialization.load_pem_private_key(key_data, self.pwd.encode("utf-8"), default_backend())

        # 获取证书的公钥
        cert_public_key = cert.get_pubkey().to_cryptography_key()
        # 校验证书和私钥是否匹配
        # 比较证书的公钥和私钥的公钥是否匹配
        if cert_public_key.public_numbers() == private_key.public_key().public_numbers():
            LOG.info("Certificate and private key are valid.")
            return 0
        else:
            LOG.error("Certificate or private key is invalid.")
            return 1


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
