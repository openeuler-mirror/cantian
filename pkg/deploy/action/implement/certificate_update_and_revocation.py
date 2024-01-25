import json
import os
import stat
import sys
import shutil
import getpass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from OpenSSL import crypto
from dateutil import parser

CUR_PATH = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CUR_PATH, "../"))
from logic.common_func import exec_popen
from om_log import LOGGER as LOG

DEPLOY_CONFIG_FILE = "/opt/cantian/config/deploy_param.json"


def get_config(file=DEPLOY_CONFIG_FILE):
    with open(file, "r") as f:
        return json.loads(f.read())


class CertificateUpdateAndRevocation(object):
    def __init__(self):
        deploy_config = get_config()
        storage_share_fs = deploy_config.get("storage_share_fs")
        node_id = deploy_config.get("node_id")
        certificate_path = f"/mnt/dbdata/remote/share_{storage_share_fs}/certificates/node{node_id}"
        self.ca_file_path = f"{certificate_path}/ca.crt"
        self.cert_file_path = f"{certificate_path}/mes.crt"
        self.key_file_path = f"{certificate_path}/mes.key"
        self.crl_file_path = f"{certificate_path}/mes.crl"

    @staticmethod
    def load_certificate_crl(crl_file_path):
        # 加载crl列表
        with open(crl_file_path, "rb") as crl_file:
            crl = x509.load_pem_x509_crl(crl_file.read(), default_backend())
        return crl

    @staticmethod
    def load_certificate_key(key_file_path, encryption_password):
        """
        加载证书key
        """
        encryption_password = encryption_password.encode("utf-8")
        # 加载私钥
        with open(key_file_path, "rb") as private_key_file:
            private_key = serialization.load_pem_private_key(
                private_key_file.read(),
                password=encryption_password,
                backend=default_backend())
        return private_key

    @staticmethod
    def load_certificate(cert_file_path):
        """
        加载证书
        """
        with open(cert_file_path, "rb") as cert_file:
            certificate = x509.load_pem_x509_certificate(
                cert_file.read(), default_backend())
        return certificate

    @staticmethod
    def load_ca_certificate(ca_file_path):
        """
        加载根证书
        """
        with open(ca_file_path, "rb") as root_cert_file:
            ca_certificate = x509.load_pem_x509_certificate(
                root_cert_file.read(), default_backend())
        return ca_certificate

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

    def update_certificate(self, cert_file_path, key_file_path):
        """
        检查证书有效性
        检查证书密码是否正确
        如果存在吊销列表检查证书是否被吊销
        :param cert_file_path: 新证书路径
        :param key_file_path: 新证书对应key
        :return bool
        """
        passwd = getpass.getpass("Enter the certificate and password:")
        ca_certificate = self.load_ca_certificate(self.ca_file_path)
        certificate = self.load_certificate(cert_file_path)
        try:
            private_key = self.load_certificate_key(key_file_path, passwd)
        except ValueError as _err:
            err_msg = "The password is incorrect."
            raise Exception(err_msg) from _err
        # 提取证书和私钥的模数
        certificate_modulus = certificate.public_key().public_numbers().n
        private_key_modulus = private_key.private_numbers().public_numbers.n

        # 检查模数是否匹配
        if certificate_modulus == private_key_modulus:
            LOG.info("The certificate matches the private key.")
        else:
            err_msg = "The certificate and private key do not match."
            raise Exception(err_msg)
        # 确保根证书是证书链的一部分
        try:
            ca_certificate.public_key().verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
            LOG.info("The root certificate matches the certificate chain.")
        except Exception as e:
            err_msg = "The root certificate does not match the certificate chain:"
            raise Exception(err_msg) from e

        if os.path.exists(self.crl_file_path):
            crl = self.load_certificate_crl(self.crl_file_path)
            # 验证证书是否在CRL中
            if crl.get_revoked_certificate_by_serial_number(certificate.serial_number):
                err_msg = "The certificate has been revoked."
                raise Exception(err_msg)
            else:
                LOG.info("The certificate is valid.")
        shutil.copy(cert_file_path, self.cert_file_path)
        self.update_certificate_passwd(passwd)

    def update_certificate_crl(self, crl_file_path):
        """
        更新吊销列表
        :param crl_file_path: 吊销列表路径
        """
        certificate = self.load_certificate(self.cert_file_path)
        crl = self.load_certificate_crl(crl_file_path)
        # 验证证书是否在CRL中
        if crl.get_revoked_certificate_by_serial_number(certificate.serial_number):
            err_msg = "The certificate has been revoked."
            raise Exception(err_msg)
        else:
            LOG.info("The certificate is valid.")
        shutil.copy(crl_file_path, self.cert_file_path)

    def query_certificate_info(self, *args):
        """
        查询证书信息
        :param args: 预留参数，确保函数调用接口一致
        """
        _ = args
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(self.cert_file_path, 'r').read().encode("utf-8"))
        res = "\n"
        res += "version：" + str(cert.get_version()) + "\n"
        res += "SN：" + str(hex(cert.get_serial_number())) + "\n"
        res += "Issuer：" + cert.get_issuer().commonName + "\n"
        res += "Validity：" + parser.parse(cert.get_notBefore().decode("utf-8")).strftime("%Y-%m-%d %H:%M:%S") + "\n"
        res += "Expiration time：" + parser.parse(cert.get_notAfter().decode("utf-8")).\
            strftime("%Y-%m-%d %H:%M:%S") + "\n"
        res += "Expired or Not：" + str(cert.has_expired()) + "\n"
        res += "Subject Information：" + "\n"
        for item in cert.get_issuer().get_components():
            res += item[0].decode("utf-8") + ": " + item[1].decode("utf-8") + "\n"
        LOG.info(res)

    def revoke_certificate(self, under_revoke_crt_file):
        """
        创建吊销证书列表文件
        :param under_revoke_crt_file: 待吊销客户端证书文件路径
        """
        ca_key_file = self.key_file_path
        crl_file = "/opt/certificate/mes.crl"
        if not os.path.exists("/opt/certificate"):
            os.mkdir("/opt/certificate")
        revocation_date_timestamp = 2684329385  # 2055-01-23 23:03:05
        now = datetime.now(tz=timezone.utc)
        next_update_duration = dict(hours=4)

        ca_crt = self.load_ca_certificate(self.ca_file_path)
        passwd = getpass.getpass("")
        ca_key = self.load_certificate_key(ca_key_file, passwd)

        with open(under_revoke_crt_file, 'rb') as f:
            under_revoke_crt_bytes = f.read()

        under_revoke_crt = x509.load_pem_x509_certificate(under_revoke_crt_bytes)

        revoked_cert = x509.RevokedCertificateBuilder(
            under_revoke_crt.serial_number,
            datetime.fromtimestamp(revocation_date_timestamp),
        ).build()

        builder = x509.CertificateRevocationListBuilder(
            issuer_name=ca_crt.issuer,
            last_update=now,
            next_update=now + timedelta(**next_update_duration),
            revoked_certificates=[revoked_cert],
        )

        ski_ext = ca_crt.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        identifier = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski_ext.value)
        builder = builder.add_extension(identifier, critical=False)

        crl = builder.sign(private_key=ca_key, algorithm=under_revoke_crt.signature_hash_algorithm)
        flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
        modes = stat.S_IRWXU | stat.S_IROTH | stat.S_IRGRP
        with os.fdopen(os.open(crl_file, flags, modes), "wb") as file_obj:
            file_obj.write(crl.public_bytes(encoding=serialization.Encoding.PEM))


if __name__ == "__main__":
    cert_update_and_revocation = CertificateUpdateAndRevocation()
    _args = []
    action = sys.argv[1]
    if len(sys.argv) > 2:
        file_path = sys.argv[2]
        _args.append(file_path)
    if len(sys.argv) > 3:
        key_path = sys.argv[3]
        _args.append(key_path)
    try:
        getattr(cert_update_and_revocation, action)
    except AttributeError as err:
        LOG.error("Currently, you can modify the certificate revocation list,"
                  " update certificates, and query certificate information.\n"
                  "example:\n"
                  "query_certificate_info\n"
                  "update_certificate cert_file_path, key_file_path\n"
                  "update_certificate_crl crl_file_path")
        exit(1)
    try:
        getattr(cert_update_and_revocation, action)(*_args)
    except Exception as err:
        LOG.error(str(err))
        exit(1)
