import json
import os
import stat
import sys
import uuid
import fcntl
from pathlib import Path


class LSIDGenerate(object):
    def __init__(self, n_type, c_id, p_id, n_id):
        self.n_type = int(n_type)
        self.process_id = int(p_id)
        self.cluster_id = int(c_id)
        self.node_id = int(n_id)
        self.info = {}

    @staticmethod
    def generate_uuid(n_type, c_id, p_id, n_id):
        _id = str(n_type) + str(c_id) + str(n_id) + str(p_id)
        return str(uuid.uuid3(uuid.NAMESPACE_DNS, _id))

    def generate_lsid(self):
        # 返回lsid十六进制
        return int(str(bin(self.n_type))[2:].rjust(2, "0") + str(bin(self.cluster_id))[2:].rjust(16, "0")
                   + str(bin(self.process_id))[2:].rjust(4, "0") + "00"
                   + str(bin(self.node_id))[2:].rjust(8, "0"), 2)

    def execute(self):
        process_uuid = self.generate_uuid(self.n_type, self.cluster_id, self.process_id, self.node_id)
        ls_id = self.generate_lsid()
        return ls_id, process_uuid


if __name__ == "__main__":
    node_type = sys.argv[1]
    cluster_id = sys.argv[2]
    process_id = sys.argv[3]
    node_id = sys.argv[4]
    id_generate = LSIDGenerate(node_type, cluster_id, process_id, node_id)
    print("%s\n%s" % id_generate.execute())
