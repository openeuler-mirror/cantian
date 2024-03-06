import json
import os
import stat
import sys
import shutil
import getpass
from datetime import datetime, timedelta, timezone

from dateutil import parser

CUR_PATH = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CUR_PATH, "../"))
from logic.common_func import exec_popen
from om_log import LOGGER as LOG


class CertificateUpdateAndRevocation(object):
    def __init__(self):
        certificate_path = "/opt/cantian/common/config/certificates"
        self.ca_file_path = f"{certificate_path}/ca.crt"
        self.cert_file_path = f"{certificate_path}/mes.crt"
        self.key_file_path = f"{certificate_path}/mes.key"
        self.crl_file_path = f"{certificate_path}/mes.crl"

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

    @staticmethod
    def verify_ca_cert_chain(ca_file_path, cert_file_path):
        """
        检验crt是否被ca信任
        """
        cmd = f"openssl verify -CAfile '{ca_file_path}' '{cert_file_path}'"
        ret_code, _, stderr = exec_popen(cmd)
        if ret_code:
            raise Exception("The root certificate does not match the certificate chain")

    @staticmethod
    def get_crt_serial_num(cert_file_path):
        """
        获取crt证书的序列号
        """
        cmd = f"openssl x509 -in '{cert_file_path}' -noout -serial"
        ret_code, stdout, stderr = exec_popen(cmd)
        if ret_code:
            raise Exception("Failed to get crt serial number, output:%s" % str(stderr))
        return str(stdout)

    @staticmethod
    def get_revoked_cert_by_serial_num(crl_file_path, crt_serial_num):
        """
        校验证书crt是否在吊销列表crl
        """
        cmd = f"openssl crl -in '{crl_file_path}' -noout -text | grep -A 1 'Revoked Certificates' | grep 'Serial Number: {crt_serial_num}'"
        ret_code, stdout, stderr = exec_popen(cmd)
        if ret_code:
            return 0
        return 1

    @staticmethod
    def update_certificate_passwd(passwd):
        """
        更新证书密码
        """
        cmd = "su -s /bin/bash - cantian -c \""
        cmd += "tmp_path=${LD_LIBRARY_PATH};export LD_LIBRARY_PATH=/opt/cantian/dbstor/lib:${LD_LIBRARY_PATH};"
        cmd += f"echo -e '{passwd}' | python3 -B /opt/cantian/action/implement" \
               f"/update_cantian_passwd.py update_mes_key_pwd;"
        cmd += "export LD_LIBRARY_PATH=${tmp_path}\""
        ret_code, _, stderr = exec_popen(cmd)
        stderr = str(stderr)
        stderr.replace(passwd, "****")
        if ret_code:
            raise Exception("update certificate passwd failed, output:%s" % str(stderr))

    def update_crt_key(self, cert_file_path, key_file_path):
        """
        检查新key密码是否正确
        检查新crt与新key是否匹配
        检查新crt、新key与原ca是否匹配
        如果存在吊销列表检查证书是否被吊销
        :param cert_file_path: 新证书crt
        :param key_file_path: 新私钥key
        :return bool
        """
        passwd = getpass.getpass("Enter the certificate and password:")
        if len(passwd) > 32:
            raise Exception("cert pwd is too long. The length should not exceed 32.")
        self.check_key_passwd(key_file_path, passwd)
        # 提取证书和私钥的模数
        certificate_modulus = self.get_crt_modulus(cert_file_path)
        private_key_modulus = self.get_key_modulus(key_file_path, passwd)

        # 检查模数是否匹配
        if certificate_modulus == private_key_modulus:
            LOG.info("The certificate matches the private key.")
        else:
            raise Exception("The certificate and private key do not match.")
        # 确保根证书是证书链的一部分
        self.verify_ca_cert_chain(self.ca_file_path, cert_file_path)

        if os.path.exists(self.crl_file_path):
            crt_serial_num = self.get_crt_serial_num(cert_file_path)
            # 验证证书是否在CRL中
            if self.get_revoked_cert_by_serial_num(crl_file_path, crt_serial_num):
                raise Exception("The certificate has been revoked.")
            else:
                LOG.info("The certificate is valid.")
        shutil.copy(cert_file_path, self.cert_file_path)
        shutil.copy(key_file_path, self.key_file_path)
        self.update_certificate_passwd(passwd)
        print("update crt and key succeed.")

    def update_ca_crt_key(self, ca_file_path, cert_file_path, key_file_path):
        passwd = getpass.getpass("Enter the certificate and password:")
        if len(passwd) > 32:
            raise Exception("cert pwd is too long. The length should not exceed 32.")
        self.check_key_passwd(key_file_path, passwd)
        # 提取证书和私钥的模数
        certificate_modulus = self.get_crt_modulus(cert_file_path)
        private_key_modulus = self.get_key_modulus(key_file_path, passwd)

        # 检查模数是否匹配
        if certificate_modulus == private_key_modulus:
            LOG.info("The certificate matches the private key.")
        else:
            raise Exception("The certificate and private key do not match.")
        # 确保根证书是证书链的一部分
        self.verify_ca_cert_chain(ca_file_path, cert_file_path)

        shutil.copy(ca_file_path, self.ca_file_path)
        shutil.copy(cert_file_path, self.cert_file_path)
        shutil.copy(key_file_path, self.key_file_path)
        self.update_certificate_passwd(passwd)
        print("update ca, crt and key succeed.")

    def query_crt_info(self):
        """
        查询crt信息
        """
        cmd = f"openssl x509 -in '{self.cert_file_path}' -text -noout"
        ret_code, stdout, stderr = exec_popen(cmd)
        stderr = str(stderr)
        if ret_code:
            raise Exception("query certifcate info failed, output:%s" % str(stderr))
        print(str(stdout))

if __name__ == "__main__":
    cert_update_and_revocation = CertificateUpdateAndRevocation()
    _args = []
    action = sys.argv[1]
    if len(sys.argv) > 2:
        _args = sys.argv[2:]
    try:
        getattr(cert_update_and_revocation, action)
    except AttributeError as err:
        err_msg = "Currently, you can modify the certificate revocation list,"\
                  " update certificates, and query certificate information.\n"\
                  "example:\n"\
                  "query_crt_info\n"\
                  "update_crt_key cert_file_path, key_file_path\n"\
                  "update_ca_crt_key ca_file_path, cert_file_path, key_file_path\n"\
                  "update_certificate_crl crl_file_path"
        exit(err_msg)
    try:
        getattr(cert_update_and_revocation, action)(*_args)
    except Exception as err:
        exit(str(err))
