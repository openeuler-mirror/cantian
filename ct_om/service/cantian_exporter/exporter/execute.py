# -*- coding: UTF-8 -*-
import time
from exporter.log import EXPORTER_LOG as LOG
from exporter.get_info import GetNodesInfo
from exporter.get_info import GetDbstorInfo
from exporter.save_file import SaveFile


def main():
    get_node_info, get_dbstor_info = GetNodesInfo(), GetDbstorInfo()
    save_file = SaveFile()

    while True:
        cms_nodes_info, dbstor_info = get_node_info.execute(), get_dbstor_info.get_dbstor_info()
        cms_nodes_info.update(dbstor_info)
        try:
            save_file.create_files(cms_nodes_info)
        except Exception as err:
            LOG.error("[result] Fail to record report data in json file, [err_msg] {}".format(str(err)))
        time.sleep(5)


if __name__ == "__main__":
    main()
