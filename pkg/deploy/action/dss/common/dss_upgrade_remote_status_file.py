import os
import sys
from get_config_info import get_value
from file_utils import pad_file_to_512
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(CURRENT_PATH, "..", ".."))
from update_config import _exec_popen
from dss.dssctl import LOG


class DssRemoteStatusfile(object):
    def __init__(self):
        self.node_remote_status_file_name = None
        self.node_remote_status_file_path = None
        self.vg_remote_file_path = None   
        
    def file_exits(self, vg_path):
        cmd = f'dsscmd ls -p {vg_path}'
        code, _, _ = _exec_popen(cmd)

        if code == 0:
            return True
        return False
    
    def detele_file(self, vg_path):
        cmd = f'dsscmd rm -p {vg_path}'
        code, _, stderr = _exec_popen(cmd)

        if code != 0:
            raise Exception(f"`dsscmd rm remote` failed: {stderr}")
                
    def cp_remote_status_file_to_path(self):
        
        if self.file_exits(self.vg_remote_file_path):
            self.detele_file(self.vg_remote_file_path)
        cmd = f'dsscmd cp -s {self.node_remote_status_file_path} -d {self.vg_remote_file_path}'
        code, _, stderr = _exec_popen(cmd)
        
        if code != 0:
            raise Exception(f"`dsscmd cp remote` failed: {stderr}")

    def mkdir_vg_path(self):
        if self.file_exits("+vg1/upgrade/cluster_and_node_status"):
            return
        cmd = f'dsscmd mkdir -p +vg1/upgrade -d cluster_and_node_status'
        code, _, stderr = _exec_popen(cmd)
        
        if code != 0:
            raise Exception(f"`dsscmd mkdir remote` failed: {stderr}")
    
    def upgrade_remote_status_file_by_dss(self, remote_status_file):
        if "cluster_and_node_status" in remote_status_file:
            self.node_remote_status_file_name = os.path.basename(remote_status_file)
            self.node_remote_status_file_path = remote_status_file
            self.vg_remote_file_path = os.path.join("+vg1/upgrade/cluster_and_node_status", 
                                                    self.node_remote_status_file_name)
            self.mkdir_vg_path()
            pad_file_to_512(self.node_remote_status_file_path)
            self.cp_remote_status_file_to_path()
        else:
            self.node_remote_status_file_name = os.path.basename(remote_status_file)
            self.node_remote_status_file_path = remote_status_file
            self.vg_remote_file_path = os.path.join("+vg1/upgrade", self.node_remote_status_file_name)

            pad_file_to_512(self.node_remote_status_file_path)
            self.cp_remote_status_file_to_path()
        return


def main():
    dss_remote_status = DssRemoteStatusfile()
    if len(sys.argv) < 1:
        raise Exception("remote not input")
    input_file = sys.argv[1]
    try:
        dss_remote_status.upgrade_remote_status_file_by_dss(input_file)
    except Exception as e:
        LOG.error(f"Failed to input file when upgrade")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        exit(str(err))