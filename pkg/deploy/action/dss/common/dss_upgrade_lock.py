import os
import sys
from file_utils import pad_file_to_512
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(CURRENT_PATH, "..", ".."))
from update_config import _exec_popen
from dss.dssctl import LOG


class DssLock(object):
    def __init__(self):
        self.node_lock_file_name = None
        self.node_lock_file_path = None
        self.vg_lock_file_path = None
        self.lock_res = None
                      
    def create_vg_upgrade_path(self):
        
        cmd = f'dsscmd mkdir -p +vg1 -d upgrade'
        code, _, stderr = _exec_popen(cmd)
        
        if code != 0:
            raise RuntimeError(f"dsscmd mkdir lock failed: {stderr}")
    
    def cp_node_lock_file_to_path(self):
        
        cmd = f'dsscmd cp -s {self.node_lock_file_path} -d {self.vg_lock_file_path}'
        code, _, stderr = _exec_popen(cmd)
        
        if code != 0:
            raise RuntimeError(f"dsscmd cp lock failed: {stderr}")

    def is_locked_new(self):
        cmd = f'dsscmd ls -p +vg1/upgrade'
        code, stdout, _ = _exec_popen(cmd)

        if code != 0:
            self.lock_res = "upgrade no exists"
            return
        
        lines = stdout.strip().splitlines()
        if len(lines) < 2:
            self.lock_res = "upgrade is empty"
            return
    
        for line in lines:
            if self.node_lock_file_name in line:
                self.lock_res = "node lock is existing"
                return
            if "upgrade_lock_" in line[5]:
                raise RuntimeError(f"other lock is using, {line[5]}") 
        self.lock_res = "upgrade not lock"       
    
    def upgrade_lock_by_dss(self, input_file=None):
        self.node_lock_file_name = os.path.basename(input_file)
        self.node_lock_file_path = os.path.join("/mnt/dbdata/remote/metadata_/upgrade", self.node_lock_file_name)
        self.vg_lock_file_path = os.path.join("+vg1/upgrade", self.node_lock_file_name)

        self.is_locked_new()
        if self.lock_res == "upgrade no exists":
            self.create_vg_upgrade_path()
        elif self.lock_res == "node lock is existing":
            return
        pad_file_to_512(self.node_lock_file_path)
        self.cp_node_lock_file_to_path()
        LOG.info(f"{self.node_lock_file_name} success")


def main():
    dss_lock = DssLock()
    if len(sys.argv) < 1:
        raise Exception("upgrade lock no input")
    input_file = sys.argv[1]
    try:
        dss_lock.upgrade_lock_by_dss(input_file)
    except Exception as e:
        LOG.error(f"Failed to lock dss when upgrade")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        exit(str(err))