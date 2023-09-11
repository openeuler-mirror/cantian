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
 * srv_view.h
 *
 *
 * IDENTIFICATION
 * src/server/srv_view.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_VIEW_H__
#define __SRV_VIEW_H__

#include "knl_interface.h"
#include "knl_dc.h"

#define LOG_LEVEL_MODE_VIEW 1
#define LONGSQL_LOG_MODE_VIEW 2
#define LOG_MODE_PARAMETER_COUNT 2
typedef enum en_dynview_id {
    DYN_VIEW_LOGFILE,
    DYN_VIEW_SESSION,
    DYN_VIEW_BUFFER_POOL,
    DYN_VIEW_BUFFER_POOL_STAT,
    DYN_VIEW_BUFFER_PAGE_STAT,
    DYN_VIEW_BUFFER_INDEX_STAT,
    DYN_VIEW_PARAMETER,
    DYN_VIEW_TEMP_POOL,
    DYN_VIEW_LOCK,
    DYN_VIEW_ARCHIVE_LOG,
    DYN_VIEW_ARCHIVE_GAP,
    DYN_VIEW_ARCHIVE_PROCESS,
    DYN_VIEW_ARCHIVE_DEST_STATUS,
    DYN_VIEW_DATABASE,
    DYN_VIEW_SGA,
    DYN_VIEW_LOCKED_OBJECT,
    DYN_VIEW_TABLESPACE,
    DYN_VIEW_SPINLOCK,
    DYN_VIEW_DLSLOCK,
    DYN_VIEW_SESSION_WAIT,
    DYN_VIEW_SESSION_EVENT,
    DYN_VIEW_SYSTEM_EVENT,
    DYN_VIEW_ME,
    DYN_VIEW_DATAFILE,
    DYN_VIEW_MEMSTAT,
    DYN_VIEW_SYSTEM,
    DYN_VIEW_VERSION,
    DYN_VIEW_TRANSACTION,
    DYN_VIEW_ALL_TRANSACTION,
    DYN_VIEW_RESOURCE_MAP,
    DYN_VIEW_USER_ASTATUS_MAP,
    DYN_VIEW_UNDO_SEGMENT,
    DYN_VIEW_TEMP_UNDO_SEGMENT,
    DYN_VIEW_BACKUP_PROCESS,
    DYN_VIEW_INSTANCE,
    DYN_VIEW_NLS_SESSION_PARAMETERS,
    DYN_VIEW_PL_MNGR,
    DYN_VIEW_COLUMN,
    DYN_VIEW_USER_PARAMETER,
    DYN_VIEW_FREE_SPACE,
    DYN_VIEW_CONTROLFILE,
    DYN_VIEW_SGASTAT,
    DYN_VIEW_HBA,
    DYN_VIEW_VM_FUNC_STACK,
    DYN_VIEW_PL_REFSQLS,
    DYN_VIEW_SEGMENT_STATISTICS,
    DYN_VIEW_WAITSTAT,
    DYN_VIEW_LATCH,
    DYN_VIEW_DC_POOL,
    DYN_VIEW_REACTOR_POOL,
    DYN_VIEW_SESS_ALOCK,
    DYN_VIEW_SESS_SHARED_ALOCK,
    DYN_VIEW_XACT_ALOCK,
    DYN_VIEW_XACT_SHARED_ALOCK,
    DYN_VIEW_GLOBAL_TRANSACTION,
    DYN_VIEW_DC_RANKINGS,
    DYN_VIEW_WHITELIST,
    DYN_VIEW_RCY_WAIT,
    DYN_VIEW_TEMPTABLES,
    DYN_VIEW_BUFFER_ACCESS_STATS,
    DYN_VIEW_BUFFER_RECYCLE_STATS,
    DYN_BACKUP_PROCESS_STATS,
    DYN_VIEW_TEMP_TABLE_STATS,
    DYN_VIEW_TEMP_COLUMN_STATS,
    DYN_VIEW_TEMP_INDEX_STATS,
    DYN_VIEW_SESSION_EX,
    DYN_VIEW_DATAFILE_LAST_TABLE,
    DYN_VIEW_PBL,
    DYN_VIEW_USER_ALOCK,
    DYN_VIEW_ALL_ALOCK,
    DYN_VIEW_ASYN_SHRINK_TABLES,
    DYN_VIEW_UNDO_STAT,
    DYN_VIEW_CKPT_STATS,
    DYN_VIEW_INDEX_COALESCE,
    DYN_VIEW_INDEX_RECYCLE,
    DYN_VIEW_INDEX_REBUILD,
    DYN_VIEW_USERS,
    // dynamic view ID for DTC begin
    DYN_VIEW_DRC_INFO,
    DYN_VIEW_DRC_BUF_INFO,   // display master info for pages.
    DYN_VIEW_DRC_RES_RATIO,  // ratios that have been used for drc resource
    DYN_VIEW_DRC_GLOBAL_RES, // display global_buf_res and global_lock_res
    DYN_VIEW_DRC_RES_MAP,    // dispaly txn_res_map/local_txn_map/local_lock_map
    DYN_VIEW_BUF_CTRL_INFO,  // display pages buf ctrl.
    DYN_VIEW_DRC_LOCAL_LOCK_INFO,
    DYN_VIEW_DTC_CONVERTING_PAGE_CNT,
    DYN_VIEW_DTC_BUFFER_CTRL, // VS X$BH
    DYN_VIEW_DTC_MES_STAT,
    DYN_VIEW_DTC_MES_ELAPSED,
    DYN_VIEW_DTC_MES_QUEUE,
    DYN_VIEW_DTC_NODE_INFO,
    DYN_VIEW_DTC_MES_TASK_QUEUE,
    DYN_VIEW_GDV_LOGFILES,
    DYN_VIEW_GDV_SGA,
    DYN_VIEW_GDV_LOCKS,
    DYN_VIEW_GDV_DLSLOCKS,
    DYN_VIEW_GDV_DRC_RES_RATIO,
    DYN_VIEW_GDV_DRC_BUF_INFO, // display master info for pages.
    DYN_VIEW_GDV_DRC_GLOBAL_RES,
    DYN_VIEW_GDV_DRC_RES_MAP,
    // Global view dynamic ID for DTC end
    DYN_VIEW_IO_STAT_RECORD,
    DYN_VIEW_TSE_IO_STAT_RECORD,
    DYN_VIEW_REFORM_STAT,
    DYN_VIEW_REFORM_DETAIL,
    DYN_VIEW_PARAL_REPLAY_STAT,
    DYN_VIEW_SYNCPOINT_STAT,
    DYN_VIEW_REDO_STAT,
    DYN_VIEW_CKPT_PART_STAT,
    /* ADD NEW VIEW HERE... */
    /* ATENTION PLEASE: DYN_VIEW_SELF MUST BE THE LAST. */
    DYN_VIEW_SELF,
} dynview_id_t;

#define VW_DECL static dynview_desc_t

#define VW_LONGSQL_ELAPSED_MS_SCALE 2 /* VW_LONGSQL_ELAPSED_MS_SCALE used for dv_longsql */

extern knl_dynview_t g_dynamic_views[];

void server_regist_dynamic_views(void);
status_t vw_common_open(knl_handle_t session, knl_cursor_t *cursor);

typedef enum en_vw_version_content {
    VW_VERSION_GIT = 0,
    VW_VERSION_CANTIAND,
    VW_VERSION_PKG,
    VW_VERSION_COMMIT,
    VW_VERSION_BOTTOM
} vw_version_content_t;

typedef enum en_global_dynview_id {
    /* GLOBAL DYNAMIC VIEWS */
    GLOBAL_DYN_VIEW_SESSION,
    /* ADD NEW VIEW HERE... */
} global_dynview_id_t;

extern knl_dynview_t g_global_dynamic_views[];
typedef status_t (*vw_fetch_func)(knl_handle_t session, knl_cursor_t *cursor);
status_t vw_fetch_for_tenant(vw_fetch_func func, knl_handle_t session, knl_cursor_t *cursor);

#define CURSOR_SET_TENANT_ID_BY_USER(func, cursor, user)  \
    do {                                                  \
        if ((func) == GS_SUCCESS) {                       \
            (cursor)->tenant_id = (user)->desc.tenant_id; \
        } else {                                          \
            (cursor)->tenant_id = SYS_TENANTROOT_ID;      \
            cm_reset_error();                             \
        }                                                 \
    } while (0)

extern char *cantiand_get_dbversion(void);
#endif
