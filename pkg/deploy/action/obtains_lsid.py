import json
import os
import hashlib
import sys
import uuid
import random
from pathlib import Path

CUR_PATH = os.path.dirname(os.path.realpath(__file__))
INSTALL_FILE = str(Path(os.path.join(CUR_PATH, "../config/deploy_param.json")))
DBSTORE_UNIFY_FLAG = os.path.exists("/opt/cantian/deploy/.dbstor_unify_flag")

# 适配LLT
if os.path.exists(INSTALL_FILE):
    with open(INSTALL_FILE, encoding="utf-8") as f:
        _tmp = f.read()
        info = json.loads(_tmp)
else:
    info = {
        "cluster_id": "1",
        "random_seed": "1"
    }


class LSIDGenerate(object):
    def __init__(self, n_type, c_id, p_id, n_id):
        self.n_type = int(n_type)
        self.process_id = int(p_id)
        self.cluster_id = int(c_id)
        self.node_id = int(n_id)
        self.random_seed = -1
        self.info = {}

    @staticmethod
    def generate_uuid(n_type, c_id, c_random, p_id, n_id):
        _id = str(n_type) + str(c_id) + str(c_random) + str(n_id) + str(p_id)
        return str(uuid.uuid3(uuid.NAMESPACE_DNS, _id))

    @staticmethod
    def generate_random_seed():
        cluster_name = info.get("cluster_name", "")
        hash_object = int(hashlib.sha256(cluster_name.encode('utf-8')).hexdigest(), 16)
        random.seed(hash_object)
        return random.randint(0, 255)

    def generate_lsid(self):
        # 返回lsid十六进制
        return int(str(bin(self.n_type))[2:].rjust(2, "0")
                   + str(bin(self.cluster_id))[2:].rjust(8, "0")
                   + str(bin(self.random_seed))[2:].rjust(8, "0")
                   + str(bin(self.process_id))[2:].rjust(4, "0") + "00"
                   + str(bin(self.node_id))[2:].rjust(8, "0"), 2)

    def execute(self):
        self.random_seed = self.generate_random_seed()
        process_uuid = self.generate_uuid(self.n_type, self.cluster_id, self.random_seed, self.process_id, self.node_id)
        ls_id = self.generate_lsid()
        return ls_id, process_uuid


if __name__ == "__main__":
    node_type = sys.argv[1]
    cluster_id = info.get("cluster_id")
    process_id = sys.argv[3]
    node_id = sys.argv[4]
    id_generate = LSIDGenerate(node_type, cluster_id, process_id, node_id)
    print("%s\n%s" % id_generate.execute())
