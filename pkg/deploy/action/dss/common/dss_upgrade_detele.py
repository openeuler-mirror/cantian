import os
import sys
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(CURRENT_PATH, "..", ".."))
from update_config import _exec_popen
from dss.dssctl import LOG


class DssDetele(object):
    def __init__(self):
        self.node_id = None
        self.node_lock_file_name = None
        self.node_lock_file_path = None
        self.cantian_user = None
        self.vg_lock_file_path = None

    def file_exits(self, input_file=None):
        cmd = f'dsscmd ls -p +vg1/upgrade'
        code, stdout, _ = _exec_popen(cmd)

        if code != 0:
            return True
        
        lines = stdout.strip().splitlines()
    
        for line in lines:
            if input_file in line:
                return True
        return False

    def delete_file(self, input_file=None):
        cmd = f'dsscmd rm -p +vg1/{input_file}'
        code, _, stderr = _exec_popen(cmd)

        if code != 0:
            raise RuntimeError(f"`dsscmd rm delete` failed: {stderr}")
        
    def delete_special_file(self, file_name, vg_path_name):
        cmd = f'dsscmd ls -p {vg_path_name}'
        code, stdout, _ = _exec_popen(cmd)

        if code != 0:
            return
        
        lines = stdout.strip().splitlines()
    
        for line in lines:
            if file_name in line[5]:
                self.delete_file(line[5])

    def delete_dir(self, input_file=None):
        cmd = f'dsscmd rmdir -p +vg1/upgrade/{input_file} -r'
        code, _, stderr = _exec_popen(cmd)

        if code != 0:
            raise RuntimeError(f"`dsscmd rmdir delete` failed: {stderr}")    
                
    def upgrade_detele_by_dss(self, input_file=None):        
        if "updatesys" in input_file:
            self.delete_special_file("updatesys", "+vg1/upgrade")
        elif input_file == "cluster_and_node_status":
            self.delete_dir("cluster_and_node_status")
        elif "cluster_and_node_status/node" in input_file:
            self.delete_special_file("node", "+vg1/upgrade/cluster_and_node_status")
        elif "upgrade_node" in input_file:
            self.delete_special_file("upgrade_node", "+vg1/upgrade")
        else:
            if not self.file_exits(input_file):
                return
            self.delete_file(input_file)
        

def main():
    dss_delete = DssDetele()
    if len(sys.argv) < 1:
        raise Exception("Failed to delete dss when upgrade input")
    input_file = sys.argv[1]
    try:
        dss_delete.upgrade_detele_by_dss(input_file)
    except Exception as e:
        LOG.error(f"Failed to delete dss file when upgrade")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        exit(str(err))