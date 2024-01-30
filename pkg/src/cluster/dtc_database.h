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
 * dtc_database.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_database.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef DTC_DATABASE_H
#define DTC_DATABASE_H

#include "cm_types.h"
#include "dtc_context.h"
#include "knl_session.h"
#include "knl_context.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DTC_BAK_SUCCESS (uint32)1
#define DTC_BAK_ERROR   (uint32)0

typedef struct st_dtc_node_ctrl {
    atomic_t    scn;
    log_point_t rcy_point;
    log_point_t lrp_point;
    uint64      ckpt_id;
    atomic_t    lsn;
    atomic_t    lfn;
    uint32      log_count;
    uint32      log_hwm;  // include holes (logfile has been dropped)
    uint32      log_first;
    uint32      log_last;
    bool32      shutdown_consistency;
    bool32      open_inconsistency;
    uint64      consistent_lfn;
    uint32      undo_space;
    uint32      swap_space;
    uint32      archived_start;
    uint32      archived_end;
    uint32      dw_start;
    uint32      dw_end;
    uint32      last_asn;
    uint32      last_lfn;
    uint32      temp_undo_space;
    log_point_t lrep_point;  // log point when logic replication is turned on.
} dtc_node_ctrl_t;

typedef struct st_dtc_node_def {
    uint32 id;
    knl_space_def_t undo_space;
    knl_space_def_t swap_space;
    knl_space_def_t temp_undo_space;
    galist_t logfiles;
} dtc_node_def_t;

status_t dtc_build_node_spaces(knl_session_t *session, knl_database_def_t *def);
status_t dtc_build_logfiles(knl_session_t *session, knl_database_def_t *def);
status_t dtc_init_undo_spaces(knl_session_t *session, knl_database_def_t *def);
status_t dtc_save_all_ctrls(knl_session_t *session, uint32 count);

status_t dtc_save_ctrl(knl_session_t *session, uint32 id);
status_t dtc_build_completed(knl_session_t *session);
status_t dtc_read_node_ctrl(knl_session_t *session, uint8 node_id);

EXTER_ATTACK void dtc_update_scn(knl_session_t *session, knl_scn_t lamport_scn);
EXTER_ATTACK void dtc_update_lsn(knl_session_t *session, atomic_t lamport_lsn);
void dtc_wait_reform_util(knl_session_t *session, bool8 is_master, reform_status_t stat);
void dtc_wait_reform(void);
void dtc_wait_reform_open(void);

status_t dtc_ddl_enabled(knl_handle_t knl_session, bool32 forbid_in_rollback);
status_t dtc_reset_log(knl_session_t *session, bool32 reset_recover, bool32 reset_archive);

static inline dtc_node_ctrl_t *dtc_get_ctrl(knl_session_t *session, uint32 id)
{
    knl_instance_t *kernel = session->kernel;
    ctrl_page_t *page = &kernel->db.ctrl.pages[CTRL_LOG_SEGMENT + id];
    return (dtc_node_ctrl_t *)page->buf;
}

static inline dtc_node_ctrl_t *dtc_my_kernel_ctrl(knl_instance_t *kernel)
{
    ctrl_page_t *page = &kernel->db.ctrl.pages[CTRL_LOG_SEGMENT + kernel->id];
    return (dtc_node_ctrl_t *)page->buf;
}

static inline dtc_node_ctrl_t *dtc_my_ctrl(knl_session_t *session)
{
    return dtc_my_kernel_ctrl(session->kernel);
}

#ifdef __cplusplus
}
#endif


#endif
