/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
 *
 * Cantian is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * cm_dbs_ctrl.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_dbs_ctrl.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_dbs_ctrl.h"
#include "cm_log.h"
#include "cm_error.h"
#include "cm_dbs_intf.h"
#include "cm_dbs_map.h"
#include "cm_text.h"
#include "cm_dbs_iofence.h"
#include "cm_dbstore.h"

typedef struct {
    NameSpaceId pgNsId;
    NameSpaceId ulogNsId;
} cm_dbs_ns_mgr;

cm_dbs_ns_mgr g_dbs_ns_mgr;
static cm_dbs_cfg_s g_dbs_cfg = { GS_FALSE };

static void cm_dbs_set_ns_id(device_type_t type, NameSpaceId *nsId)
{
    if (type == DEV_TYPE_PGPOOL) {
        g_dbs_ns_mgr.pgNsId = *nsId;
    } else if (type == DEV_TYPE_ULOG) {
        g_dbs_ns_mgr.ulogNsId = *nsId;
    }
    return;
}

status_t cm_dbs_get_ns_id(device_type_t type, NameSpaceId *nsId)
{
    if (type == DEV_TYPE_PGPOOL) {
        *nsId = g_dbs_ns_mgr.pgNsId;
        return GS_SUCCESS;
    } else if (type == DEV_TYPE_ULOG) {
        *nsId = g_dbs_ns_mgr.ulogNsId;
        return GS_SUCCESS;
    }
    return GS_ERROR;
}

static status_t cm_dbs_create_ns(const char *name, NameSpaceId *nsId)
{
    NameSpaceAttr nsAttr;
    nsAttr.userId = 0;
    nsAttr.poolId = 0;
    nsAttr.app = 0;
    nsAttr.mod = 0;
    nsAttr.termId = 0;
    nsAttr.dbVersion = CANTIAN_VERSION;
    return dbs_global_handle()->create_namespace((char *)name, &nsAttr, nsId) == 0 ? GS_SUCCESS : GS_ERROR;
}

status_t cm_dbs_create_all_ns(void)
{
    int32 ret;
    NameSpaceId nsId = {0};
    cm_dbs_cfg_s *cfg = cm_dbs_get_cfg();

    if (!cfg->enable) {
        return GS_SUCCESS;
    }

    ret = cm_dbs_create_ns(cfg->ns, &nsId);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("Failed to create namespace %s, ret %d", cfg->ns, ret);
        return GS_ERROR;
    }

    cm_dbs_set_ns_id(DEV_TYPE_PGPOOL, &nsId);
    cm_dbs_set_ns_id(DEV_TYPE_ULOG, &nsId);
    return GS_SUCCESS;
}

status_t cm_dbs_open_ns(const char *name, NameSpaceId *nsId)
{
    int32 ret;
    NameSpaceAttr attr;

    ret = dbs_global_handle()->open_namespace((char *)name, &attr, nsId);
    if (ret != 0) {
        GS_LOG_RUN_ERR("Failed to open namespace %s, ret %d", name, ret);
        return GS_ERROR;
    }
    GS_LOG_DEBUG_INF("current cantian version is %u, original version is %u", CANTIAN_VERSION, attr.dbVersion);
    if (attr.dbVersion > CANTIAN_VERSION) {
        GS_LOG_RUN_ERR("Failed to open namespace, current cantian version less than original version");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cm_dbs_open_all_ns(void)
{
    int32 ret;
    NameSpaceId nsId;
    cm_dbs_cfg_s *cfg = cm_dbs_get_cfg();

    if (!cfg->enable) {
        return GS_SUCCESS;
    }

    ret = cm_dbs_open_ns(cfg->ns, &nsId);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("Failed to open namespace %s, ret %d", cfg->ns, ret);
        return GS_ERROR;
    }

    cm_dbs_set_ns_id(DEV_TYPE_PGPOOL, &nsId);
    cm_dbs_set_ns_id(DEV_TYPE_ULOG, &nsId);
    return GS_SUCCESS;
}

static status_t cm_dbs_set_ns_name(cm_dbs_cfg_s *cfg, const char *value)
{
    char str_tmp[DBS_NS_MAX_NAME_LEN] = { 0 };
    errno_t err = strcpy_s(str_tmp, sizeof(str_tmp), value);
    if (err != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, (err));
        return GS_ERROR;
    }
    text_t txt;
    txt.str = str_tmp;
    txt.len = (uint32)strlen(str_tmp);
    cm_trim_text(&txt);
    if (txt.len == 0) {
        return GS_ERROR;
    }
    err = strncpy_s(cfg->ns, sizeof(cfg->ns), txt.str, txt.len);
    if (err != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, (err));
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

cm_dbs_cfg_s *cm_dbs_get_cfg(void)
{
    return &g_dbs_cfg;
}

status_t cm_dbs_set_cfg(bool32 enable, uint32 dataPgSize, uint32 ctrlPgSize, const char *ns_name, uint32 partition_num,
    bool32 enable_batch_flush)
{
    status_t ret;

    g_dbs_cfg.enable = enable;
    if (enable) {
        g_dbs_cfg.dataFilePgSize = dataPgSize;
        g_dbs_cfg.ctrlFilePgSize = ctrlPgSize;
        g_dbs_cfg.partition_num = partition_num;
        g_dbs_cfg.enable_batch_flush = enable_batch_flush;
        GS_LOG_RUN_INF("date page size is %d, ctrl page size is %d, partition num %d, enable_batch_flush %d",
            dataPgSize, ctrlPgSize, partition_num, enable_batch_flush);
        if (ns_name == NULL || strlen(ns_name) == 0) {
            GS_LOG_RUN_ERR("DBStor namespace param error");
            return GS_ERROR;
        }
        ret = cm_dbs_set_ns_name(&g_dbs_cfg, ns_name);
        if (ret != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

bool32 cm_dbs_is_enable_dbs(void)
{
    cm_dbs_cfg_s *cfg = cm_dbs_get_cfg();
    return cfg->enable;
}

void exit_panic(void)
{
    GS_LOG_RUN_ERR("CANTIAND EXIT!");
    cm_panic(0);
}

void cm_set_dbs_uuid_lsid(const char* uuid, uint32 lsid)
{
    dbs_global_handle()->dbs_client_set_uuid_lsid(uuid, lsid);
    GS_LOG_RUN_INF("set dbstore uuid %s and lsid %u", uuid, lsid);
    return;
}

status_t cm_dbs_init(const char* home_path)
{
#ifndef DB_DEBUG_VERSION
    atexit(exit_panic);
#endif
    int32 ret;
    cm_dbs_cfg_s *cfg = cm_dbs_get_cfg();

    if (!cfg->enable) {
        GS_LOG_RUN_INF("DBStor is not enabled");
        return GS_SUCCESS;
    }
    char dbstor_work_path[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
    int32 cnt = sprintf_s(dbstor_work_path, sizeof(dbstor_work_path), "%s/dbstor/", home_path);
    if (cnt == -1) {
        GS_LOG_RUN_ERR("Failed to assemble the dbstor work path by instance home(%s).", home_path);
        return GS_ERROR;
    }

    ret = dbs_global_handle()->dbs_client_lib_init(dbstor_work_path);
    if (ret != 0) {
        GS_LOG_RUN_ERR("Failed(%d) to init dbstor client at %s.", ret, dbstor_work_path);
        return GS_ERROR;
    }
    GS_LOG_RUN_INF("START WAIT DBSTORE INIT");
    cm_dbs_map_init();
    GS_LOG_RUN_INF("END WAIT DBSTORE INIT");
    return GS_SUCCESS;
}

status_t cm_dbs_iof_reg_all_ns(uint32 inst_id)
{
    int32 ret;
    NameSpaceId nsId;
    cm_dbs_cfg_s *cfg = cm_dbs_get_cfg();
    iof_info_t iof = {0};

    if (!cfg->enable) {
        GS_LOG_RUN_INF("dbstore is not enabled");
        return GS_SUCCESS;
    }

    cm_dbs_get_ns_id(DEV_TYPE_PGPOOL, &nsId);
    iof.nodeid = inst_id;
    iof.nsid = nsId;
    iof.sn = 0;
    iof.termid = 0;
    ret = cm_dbs_iof_register(&iof);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("Failed to iof reg, ret %d, node id %u, sn %llu, termid %u, namespace %s", ret,
            iof.nodeid, iof.sn, iof.termid, cfg->ns);
        return GS_ERROR;
    }

    cm_dbs_get_ns_id(DEV_TYPE_ULOG, &nsId);
    iof.nsid = nsId;
    ret = cm_dbs_iof_register(&iof);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("Failed to iof reg, ret %d, node id %u, sn %llu, termid %u, namespace %s", ret,
            iof.nodeid, iof.sn, iof.termid, cfg->ns);
        return GS_ERROR;
    }

    GS_LOG_DEBUG_INF("iof reg ns succ, node id %u, sn %llu, termid %u, namespace %s, memory usage=%lu",
        iof.nodeid, iof.sn, iof.termid, cfg->ns, cm_print_memory_usage());
    return GS_SUCCESS;
}

uint32 cm_dbs_get_part_num(void)
{
    return g_dbs_cfg.partition_num;
}


bool32 cm_dbs_is_enable_batch_flush(void)
{
    cm_dbs_cfg_s *cfg = cm_dbs_get_cfg();
    return cfg->enable_batch_flush;
}