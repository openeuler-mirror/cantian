/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * cm_dbs_iofence.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_dbs_iofence.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_dbs_module.h"
#include "cm_log.h"
#include "cm_dbs_iofence.h"
#include "cm_dbs_intf.h"
#include "cm_dbstore.h"

int32 cm_dbs_iof_register(iof_info_t* iof_info)
{
    TermAccessAttr attr;
    int32 ret = CT_SUCCESS;

    attr.sn = iof_info->sn;
    attr.nodeId = iof_info->nodeid;
    attr.termId = iof_info->termid;
    attr.accessMode = CS_TERM_ACCESS_RDWR;
    ret = dbs_global_handle()->set_term_access_mode_for_ns(iof_info->nsName, &attr);
    if (ret != CT_SUCCESS) {
        CT_LOG_DEBUG_ERR("DBStor iof register failed, ret %d, sn %llu, nodeid %d, termid %d.", ret,
            (uint64)attr.sn, attr.nodeId, attr.termId);
        return ret;
    }

    CT_LOG_DEBUG_INF("DBStor iof register succ, sn %llu, nodeid %d, termid %d.", (uint64)attr.sn,
        attr.nodeId, attr.termId);
    return CT_SUCCESS;
}

int32 cm_dbs_iof_kick(iof_info_t* iof_info)
{
    TermAccessAttr attr;
    int32 ret = CT_SUCCESS;

    attr.sn = iof_info->sn;
    attr.nodeId = iof_info->nodeid;
    attr.termId = iof_info->termid;
    attr.accessMode = CS_TERM_ACCESS_FORBID_RDWR;
    ret = dbs_global_handle()->set_term_access_mode_for_ns(iof_info->nsName, &attr);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("DBStor iof kick failed, ret %d, sn %llu, nodeid %d, termid %d.", ret,
            (uint64)attr.sn, attr.nodeId, attr.termId);
        return ret;
    }

    CT_LOG_DEBUG_INF("DBStor iof kick succ, sn %llu, nodeid %d, termid %d.", (uint64)attr.sn,
        attr.nodeId, attr.termId);

    return CT_SUCCESS;
}

int32 cm_dbs_iof_kick_by_ns(iof_info_t* iof_info)
{
    TermAccessAttr attr;
    int32 ret = CT_SUCCESS;

    attr.sn = iof_info->sn;
    attr.nodeId = iof_info->nodeid;
    attr.termId = iof_info->termid;
    attr.accessMode = CS_TERM_ACCESS_FORBID_RDWR;
    cm_dbs_cfg_s *cfg = cm_dbs_get_cfg();
    ret = dbs_global_handle()->set_term_access_mode_for_ns((char *)cfg->ns, &attr);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("DBStor iof kick failed, ret %d, sn %llu, nodeid %d, termid %d.", ret,
            (uint64)attr.sn, attr.nodeId, attr.termId);
        return ret;
    }

    CT_LOG_DEBUG_INF("DBStor iof kick succ, sn %llu, nodeid %d, termid %d.", (uint64)attr.sn,
        attr.nodeId, attr.termId);

    return CT_SUCCESS;
}
