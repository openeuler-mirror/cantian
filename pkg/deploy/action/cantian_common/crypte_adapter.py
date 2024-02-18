import os
import ctypes
import sys


CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(CURRENT_PATH, "../"))

from dbstor.kmc_adapter import CApiWrapper


PRIMARY_KEYSTORE = "/opt/cantian/common/config/primary_keystore_bak.ks"
STANDBY_KEYSTORE = "/opt/cantian/common/config/standby_keystore_bak.ks"


class KmcResolve(object):
    def __init__(self, pwd):
        self.pwd = pwd

    @staticmethod
    def kmc_resolve_password(mode, plain_text):
        """
        密码解密
        :param mode:  encrypted/decrypted
        :param plain_text: 加解密内容
        :return:
        """
        ret_pwd = ""
        kmc_adapter = CApiWrapper(PRIMARY_KEYSTORE, STANDBY_KEYSTORE)
        kmc_adapter.initialize()
        try:
            if mode == "encrypted":
                ret_pwd = kmc_adapter.encrypt(plain_text)
            if mode == "decrypted":
                ret_pwd = kmc_adapter.decrypt(plain_text)
        except Exception as error:
            raise Exception("Failed to %s password of user [sys]. Error: %s" % (mode, str(error))) from error
        finally:
            kmc_adapter.finalize()
        split_env = os.environ['LD_LIBRARY_PATH'].split(":")
        filtered_env = [single_env for single_env in split_env if "/opt/cantian/dbstor/lib" not in single_env]
        os.environ['LD_LIBRARY_PATH'] = ":".join(filtered_env)
        return ret_pwd

    def encrypted(self):
        ret_pwd = self.kmc_resolve_password("encrypted", self.pwd)
        return ret_pwd

    def decrypted(self):
        ret_pwd = self.kmc_resolve_password("decrypted", self.pwd)
        return ret_pwd


if __name__ == "__main__":
    kmc_resolve = KmcResolve(input().strip())
    action = sys.argv[1]
    print(getattr(kmc_resolve, action)())

