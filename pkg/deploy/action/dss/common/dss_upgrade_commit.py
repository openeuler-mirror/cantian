import os
import sys
import traceback
from file_utils import read_dss_file
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(CURRENT_PATH, "..", ".."))
from update_config import _exec_popen
from dss.dssctl import LOG


class DssUpgradeCommit(object):
    def __init__(self):
        self.node_status_num = 0    
    
    def file_exits(self):
        '''
        检查cluster_and_node_status下是否有文件存在
        '''
        cmd = "dsscmd ls -p +vg1/upgrade/cluster_and_node_status"
        code, stdout, stderr = _exec_popen(cmd)

        if code != 0:
            raise Exception(f"dsscmd ls commit failed: {stderr}")
        
        lines = stdout.strip().splitlines()
        if len(lines) < 2:
            raise Exception(f"cluster_and_node_status file is not complete")
    
        for line in lines:
            if "status.txt" in line and "cluster" not in line:
                self.node_status_num += 1
    
    def check_nodes(self, cms_status=1):
        '''
        检查节点状态文件和cms的ip数量是否相同
        '''
        if cms_status != self.node_status_num:
            LOG.error(f"txt num is {self.node_status_num}, ip num is {cms_status}")  
            if cms_status > self.node_status_num:
                raise Exception(f"the txt in cluster_and_node_status is not enough")
            raise Exception(f"the txt in cluster_and_node_status is error")
    
    def check_status_file(self, cms_status=1):
        '''
        检查节点状态文件内容
        '''
        context = []
        for i in range(cms_status):
            node_status_file = os.path.join("+vg1/upgrade/cluster_and_node_status", f"node{i}_status.txt")
            context.append(read_dss_file(node_status_file))
        for rollup_result in context:
            if rollup_result != "rollup_success":
                raise Exception(f"rollup result is error {rollup_result}")
    
    def upgrade_commit(self, input_status=None):
        self.file_exits()
        self.check_nodes(input_status)
        self.check_status_file(input_status)


def main():
    dss_commit = DssUpgradeCommit()
    if len(sys.argv) < 1:
        raise Exception("remote not input")
    input_status = sys.argv[1]
    try:
        dss_commit.upgrade_commit(int(input_status))
    except Exception as e:
        LOG.error(f"cluster file check error {traceback.format_exc(limit=-1)}")
        raise e

if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        exit(str(err))