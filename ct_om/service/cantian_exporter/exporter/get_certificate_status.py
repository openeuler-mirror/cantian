import os
import json
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend


DEPLOY_PARAM_PATH = '/opt/cantian/config/deploy_param.json'


def file_reader(file_path):
    with open(file_path, 'r') as file:
        return file.read()


def get_certificate_status():
    deploy_param = json.loads(file_reader(DEPLOY_PARAM_PATH))

    storage_share_fs = deploy_param.get("storage_share_fs")
    node_id = deploy_param.get("node_id")
    cert_file_path = f"/mnt/dbdata/remote/share_{storage_share_fs}/certificates/node{node_id}/mes.crt"
    crl_file_path = f"/mnt/dbdata/remote/share_{storage_share_fs}/certificates/node{node_id}/mes.crl"
    with open(cert_file_path, "rb") as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
    current_time = datetime.now(tz=timezone.utc)
    cert_status = "active"
    crl_status = "unexpired"
    if os.path.exists(crl_file_path):
        with open(crl_file_path, "rb") as crl_file:
            crl = x509.load_pem_x509_crl(crl_file.read(), default_backend())
        next_update = crl.next_update
        if next_update <= current_time:
            crl_status = "expired"
        if crl.get_revoked_certificate_by_serial_number(cert.serial_number):
            cert_status = "revoked"
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after
    if not_before <= current_time <= not_after:
        cert_status = "expired"
    return crl_status, cert_status


if __name__ == "__main__":
    print(get_certificate_status())
