import json
import os
import secrets
import sys
import uuid
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

    def generate_lsid(self):
        # 返回lsid十六进制
        return int(str(bin(self.n_type))[2:].rjust(2, "0")
                   + str(bin(self.cluster_id))[2:].rjust(8, "0")
                   + str(bin(self.random_seed))[2:].rjust(8, "0")
                   + str(bin(self.process_id))[2:].rjust(4, "0") + "00"
                   + str(bin(self.node_id))[2:].rjust(8, "0"), 2)

    def generate_random_seed(self):
        secrets_generator = secrets.SystemRandom()
        return secrets_generator.randint(0, 2 ** 8 - 1)

    def random_seed_set(self):
        if DBSTORE_UNIFY_FLAG:
            if self.process_id == 1 or self.process_id == 0:
                self.random_seed = 0
            else:
                self.random_seed = self.generate_random_seed()
        else:
            # 多租场景容器构建没有随机数生成，先默认取值0
            tmp_seed = info.get("random_seed", '1')
            if not tmp_seed:
                raise Exception("invalid random seed!")
            else:
                self.random_seed = int(tmp_seed)

    def execute(self):
        self.random_seed_set()
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
