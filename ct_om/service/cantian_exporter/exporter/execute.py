# -*- coding: UTF-8 -*-
import time
import os
from exporter.log import EXPORTER_LOG as LOG
from exporter.get_info import GetNodesInfo
from exporter.get_info import GetDbstorInfo
from exporter.save_file import SaveFile
from query_storage_info.get_dr_info import DRStatusCheck


def main():
    get_node_info, get_dbstor_info = GetNodesInfo(), GetDbstorInfo()
    get_dr_info = DRStatusCheck()
    try:
        get_dr_info.opt_init()
    except Exception as err:
        LOG.error("Failed to login DM, details:%s", str(err))
    save_file = SaveFile()

    while True:
        cms_nodes_info, dbstor_info = get_node_info.execute(), get_dbstor_info.get_dbstor_info()
        cms_nodes_info.update(dbstor_info)
        try:
            dr_status_info = get_dr_info.execute()
        except Exception as err:
            LOG.error("Failed to get dr status,details:%s", str(err))
            dr_status_info = {}
        cms_nodes_info.update(dr_status_info)
        try:
            save_file.create_files(cms_nodes_info)
        except Exception as err:
            LOG.error("[result] Fail to record report data in json file, [err_msg] {}".format(str(err)))
        time.sleep(20)


if __name__ == "__main__":
    main()
