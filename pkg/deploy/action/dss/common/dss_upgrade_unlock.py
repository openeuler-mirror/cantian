import os
import sys
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(CURRENT_PATH, "..", ".."))
from update_config import _exec_popen
from dss.dssctl import LOG

class DssUnLock(object):
    def __init__(self):
        self.node_lock_file_name = None
        self.vg_lock_file_path = None

    def is_locked(self):
        cmd = f'dsscmd ls -p +vg1/upgrade'
        code, stdout, stderr = _exec_popen(cmd)

        if code != 0:
            raise RuntimeError(f"`dsscmd ls unlock` failed: {stderr}")
        
        lines = stdout.strip().splitlines()
        if len(lines) < 2:
            raise RuntimeError(f"no file with lock")
    
        for line in lines:
            if self.node_lock_file_name in line:
                return True
        return False

    def unlock_node(self):
        cmd = f'dsscmd rm -p {self.vg_lock_file_path}'
        code, _, stderr = _exec_popen(cmd)

        if code != 0:
            raise RuntimeError(f"`dsscmd rm unlock` failed: {stderr}")
                
    def upgrade_unlock_by_dss(self, input_file=None):
        self.node_lock_file_name = os.path.basename(input_file)
        self.vg_lock_file_path = os.path.join("+vg1/upgrade", self.node_lock_file_name)
        if self.is_locked():  
            self.unlock_node()
        return


def main():
    dss_unlock = DssUnLock()
    if len(sys.argv) < 1:
        raise Exception("Failed to unlock dss when upgrade input")
    input_file = sys.argv[1]
    try:
        dss_unlock.upgrade_unlock_by_dss(input_file)
    except Exception as e:
        LOG.error(f"Failed to unlock dss when upgrade")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        exit(str(err))