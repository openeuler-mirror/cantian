import os
import sys
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(CURRENT_PATH, "..", ".."))
from update_config import _exec_popen
from dss.dssctl import LOG


class DssYaml(object):
    def __init__(self):
        self.node_yaml_file_name = None
        self.node_yaml_file_path = None
        self.vg_yaml_file_path = None

    def detele_file(self, vg_path):
        cmd = f'dsscmd rm -p {vg_path}'
        code, _, stderr = _exec_popen(cmd)

        if code != 0:
            raise RuntimeError(f"`dsscmd rm yaml` failed: {stderr}")

    def file_exits(self):
        cmd = f'dsscmd ls -p +vg1'
        code, stdout, _ = _exec_popen(cmd)

        if code != 0:
            return
        
        lines = stdout.strip().splitlines()
    
        for line in lines:
            if self.node_yaml_file_name in line:
                self.detele_file(self.vg_yaml_file_path)
                break

    def cp_yaml_file_to_path(self):
        
        cmd = f'dsscmd cp -s {self.node_yaml_file_path} -d {self.vg_yaml_file_path}'
        code, _, stderr = _exec_popen(cmd)
        
        if code != 0:
            raise RuntimeError(f"`dsscmd cp yaml` failed: {stderr}")
    
    def upgrade_yaml_by_dss(self, input_file=None):
        self.node_yaml_file_name = os.path.basename(input_file)
        self.node_yaml_file_path = input_file
        self.vg_yaml_file_path = os.path.join("+vg1", self.node_yaml_file_name)
        self.cp_yaml_file_to_path()
        return


def main():
    dss_yaml = DssYaml()
    if len(sys.argv) < 1:
        raise Exception("Failed to cp yaml when upgrade input")
    input_file = sys.argv[1]
    try:
        dss_yaml.upgrade_yaml_by_dss(input_file)
    except Exception as e:
        LOG.error(f"Failed to cp yaml when upgrade")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        exit(str(err))