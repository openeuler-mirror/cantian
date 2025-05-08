import os
import sys
import traceback
from file_utils import read_dss_file
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(CURRENT_PATH, "..", ".."))
from update_config import _exec_popen
from dss.dssctl import LOG


class DssLocalStatusfile(object):            
    def rollback_check_files(self, file):
        vg_file_path = os.path.join("+vg1/upgrade/cluster_and_node_status", file)
        context = read_dss_file(vg_file_path)
        if context != "commit":
            raise Exception(f"Rolling upgrade is currently in progress, Offline rollback cannot be performed by {file}.") 

    def check_vg_to_path(self, path):
        cmd = f"dsscmd ls -p {path}"
        code, stdout, stderr = _exec_popen(cmd)

        if code != 0:
            return
        
        lines = stdout.strip().splitlines()
        if len(lines) < 2:
            raise Exception(f"file is not complete")
    
        for line in lines:
            if "written_size" not in line:
                if "updatesys.success" in line or "updatesys.failed" in line:
                    values = line.strip().split()
                    raise Exception(f"Rolling upgrade is currently in progress, Offline rollback cannot be performed by {values[5]}.")
                if "cluster_status.txt" in line:
                    values = line.strip().split()
                    self.rollback_check_files(values[5])
        
    def upgrade_local_status_file_by_dss(self):
        self.check_vg_to_path("+vg1/upgrade")
        self.check_vg_to_path("+vg1/upgrade/cluster_and_node_status")
        
 
def main():
    dss_local_status = DssLocalStatusfile()
    try:
        dss_local_status.upgrade_local_status_file_by_dss()
    except Exception as e:
        LOG.error(f"Failed with local file when upgrade {traceback.format_exc(limit=-1)}")
        raise e


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        exit(str(err))