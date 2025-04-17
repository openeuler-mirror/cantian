import os
import sys
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(CURRENT_PATH, "..", ".."))
from update_config import _exec_popen
from dss.dssctl import LOG


class DssLocalStatusfile(object):            
    def dir_exists(self, exists_path, exists_dir):
        cmd = f"dsscmd ls -p {exists_path}"
        code, stdout, stderr = _exec_popen(cmd)

        if code != 0:
            raise Exception(f"dsscmd ls local failed: {stderr}")
        
        lines = stdout.strip().splitlines()
        if len(lines) < 2:
            return False
    
        for line in lines:
            if exists_dir in line:
                return True
    
    def mkdir_local_status_file_to_path(self, mkdir_path, mkdir_dir):
        if self.dir_exists(mkdir_path, mkdir_dir):
            return 
        cmd = f"dsscmd mkdir -p {mkdir_path} -d {mkdir_dir}"
        code, _, stderr = _exec_popen(cmd)
        
        if code != 0:
            raise Exception(f"dsscmd mkdir local failed: {stderr}")
        
    def upgrade_local_status_file_by_dss(self):
        self.mkdir_local_status_file_to_path("+vg1", "upgrade")
        self.mkdir_local_status_file_to_path("+vg1/upgrade", "cluster_and_node_status")

 
def main():
    dss_local_status = DssLocalStatusfile()
    try:
        dss_local_status.upgrade_local_status_file_by_dss()
    except Exception as e:
        LOG.error(f"Failed with local file when upgrade")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        exit(str(err))