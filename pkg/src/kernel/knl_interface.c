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
 * knl_interface.c
 *
 *
 * IDENTIFICATION
 * src/kernel/knl_interface.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "knl_interface.h"
#include "cm_hash.h"
#include "cm_file.h"
#include "cm_kmc.h"
#include "cm_device.h"
#include "cm_io_record.h"
#include "cm_file_iofence.h"
#include "knl_lob.h"
#include "rcr_btree.h"
#include "rcr_btree_scan.h"
#include "pcr_btree.h"
#include "pcr_btree_scan.h"
#include "index_common.h"
#include "pcr_heap.h"
#include "pcr_heap_scan.h"
#include "knl_context.h"
#include "knl_sequence.h"
#include "knl_table.h"
#include "knl_user.h"
#include "knl_tenant.h"
#include "knl_log_file.h"
#include "temp_btree.h"
#include "ostat_load.h"
#ifdef DB_DEBUG_VERSION
#include "knl_syncpoint.h"
#endif /* DB_DEBUG_VERSION */
#include "knl_comment.h"
#include "knl_map.h"
#include "knl_tran.h"
#include "knl_database.h"
#include "knl_datafile.h"
#include "knl_space_manage.h"
#include "knl_temp_space.h"
#include "knl_alter_space.h"
#include "knl_create_space.h"
#include "knl_drop_space.h"
#include "knl_shrink_space.h"
#include "knl_punch_space.h"
#include "knl_external.h"
#include "knl_flashback.h"
#include "knl_db_alter.h"
#include "knl_ctrl_restore.h"
#include "knl_lrepl_meta.h"
#include "dc_part.h"
#include "dc_dump.h"
#include "dc_util.h"
#include "bak_restore.h"
#include "bak_common.h"
#include "knl_part_output.h"
#include "knl_abr.h"
#include "dc_seq.h"
#include "dtc_dls.h"
#include "dtc_dc.h"
#include "dtc_ckpt.h"
#include "dtc_context.h"
#include "dtc_database.h"
#include "dtc_backup.h"
#include "dtc_dcs.h"
#ifdef __cplusplus
extern "C" {
#endif

const text_t g_system = { (char *)"SYSTEM", 6 };
const text_t g_temp = { (char *)"TEMP2", 5 };  // temp changes for new space type
const text_t g_swap = { (char *)"TEMP", 4 };
const text_t g_undo = { (char *)"UNDO", 4 };
const text_t g_users = { (char *)"USERS", 5 };
const text_t g_temp2 = { (char *)"TEMP2", 5 };
const text_t g_temp_undo = { (char *)"TEMP2_UNDO", 10 }; // temp changes for new space type
const text_t g_temp2_undo = { (char *)"TEMP2_UNDO", 10 };
const text_t g_sysaux = { (char *)"SYSAUX", 6 };
const text_t g_tenantroot = { (char *)"TENANT$ROOT", 11 };

const page_id_t g_invalid_pagid = { .page = 0, .file = INVALID_FILE_ID, .aligned = 0 };
const rowid_t g_invalid_rowid = { .file = INVALID_FILE_ID, .page = 0, .slot = 0, .unused2 = 0 };
const rowid_t g_invalid_temp_rowid = { .vmid = CT_INVALID_ID32, .vm_slot = 0, .vm_tag = 0 };
const undo_page_id_t g_invalid_undo_pagid = { .page = 0, .file = INVALID_FILE_ID };
const undo_rowid_t g_invalid_undo_rowid = { .page_id.file = INVALID_FILE_ID, .page_id.page = 0,
                                            .slot = CT_INVALID_ID16, .aligned = 0 };

knl_callback_t g_knl_callback = { NULL, NULL, NULL, NULL, NULL };
#define HIGH_PRIO_ACT(act) ((act) == MAXIMIZE_STANDBY_DB || (act) == SWITCHOVER_STANDBY || (act) == FAILOVER_STANDBY)
#define COLUMN_DATATYPE_LEN_0 0
#define COLUMN_DATATYPE_LEN_4 4
#define COLUMN_DATATYPE_LEN_8 8

init_cursor_t g_init_cursor = {
    .stmt = NULL,
    .temp_cache = NULL,
    .vm_page = NULL,
    .file = -1,
    .part_loc.part_no = 0,
    .part_loc.subpart_no = 0,
    .rowid_count = 0,
    .decode_count = CT_INVALID_ID16,
    .chain_count = 0,
    .index_slot = INVALID_INDEX_SLOT,
    .index_dsc = CT_FALSE,
    .index_only = CT_FALSE,
    .index_ffs = CT_FALSE,
    .index_prefetch_row = CT_FALSE,
    .index_ss = CT_FALSE,
    .index_paral = CT_FALSE,
    .skip_index_match = CT_FALSE,
    .asc_relocate_next_key = CT_FALSE,
    .set_default = CT_FALSE,
    .restrict_part = CT_FALSE,
    .restrict_subpart = CT_FALSE,
    .is_valid = CT_TRUE,
    .eof = CT_FALSE,
    .logging = CT_TRUE,
    .page_soft_damaged = CT_FALSE,
    .global_cached = CT_FALSE,
    .rowmark.value = 0,
    .is_splitting = CT_FALSE,
    .for_update_fetch = CT_FALSE,
    .nologging_type = 0,
};

knl_savepoint_t g_init_savepoint = {
    .urid = { .page_id.file = INVALID_FILE_ID, .page_id.page = 0, .slot = CT_INVALID_ID16, .aligned = 0 },
    .noredo_urid = { .page_id.file = INVALID_FILE_ID, .page_id.page = 0, .slot = CT_INVALID_ID16, .aligned = 0 },
    .lsn = CT_INVALID_ID64,
    .xid = CT_INVALID_ID64,

    .lob_items = { .count = 0, .first = NULL, .last = NULL },

    .key_lock.plocks = { .count = 0, .first = CT_INVALID_ID32, .last = CT_INVALID_ID32 },
    .key_lock.glocks = { .count = 0, .first = CT_INVALID_ID32, .last = CT_INVALID_ID32 },
    .key_lock.plock_id = CT_INVALID_ID32,

    .row_lock.plocks = { .count = 0, .first = CT_INVALID_ID32, .last = CT_INVALID_ID32 },
    .row_lock.glocks = { .count = 0, .first = CT_INVALID_ID32, .last = CT_INVALID_ID32 },
    .row_lock.plock_id = CT_INVALID_ID32,

    .sch_lock.plocks = { .count = 0, .first = CT_INVALID_ID32, .last = CT_INVALID_ID32 },
    .sch_lock.glocks = { .count = 0, .first = CT_INVALID_ID32, .last = CT_INVALID_ID32 },
    .sch_lock.plock_id = CT_INVALID_ID32,

    .alck_lock.plocks = { .count = 0, .first = CT_INVALID_ID32, .last = CT_INVALID_ID32 },
    .alck_lock.glocks = { .count = 0, .first = CT_INVALID_ID32, .last = CT_INVALID_ID32 },
    .alck_lock.plock_id = CT_INVALID_ID32
};

const wait_event_desc_t g_wait_event_desc[] = {
    { "idle wait", "", "Idle" },
    { "message from client", "", "Idle" },
    { "message to client", "", "Idle" },
    { "latch: large pool", "", "Concurrency" },
    { "latch: data buffer pool", "", "Concurrency" },
    { "latch: cache buffers chains", "", "Concurrency" },
    { "cursor: mutex", "", "Other" },
    { "library : mutex", "", "Other" },
    { "log file sync", "", "Commit" },
    { "buffer busy waits", "", "Concurrency" },
    { "enq: TX row lock contention", "", "Application" },
    { "enq: TX alloc itl entry", "", "Concurrency" },
    { "enq: TX index contention", "", "Application" },
    { "enq: TX table lock S", "", "Application" },
    { "enq: TX table lock X", "", "Application" },
    { "enq: TX read  wait", "", "Application" },
    { "db file scattered read", "", "User/IO" },
    { "db file sequential read", "", "User/IO" },
    { "db file gbp read", "", "User/IO" },
    { "mtrl segment sort", "", "User/IO" },
    { "log file switch(checkpoint incomplete)", "", "Configuration" },
    { "log file switch(archiving needed)", "", "Configuration" },
    { "read by other session", "", "Concurrency" },
    { "attached to agent", "", "Idle" },
    { "heap find map", "", "Concurrency" },
    { "heap extend segment", "", "Concurrency" },
    { "resmgr: io quantum", "", "User/IO" },
    { "direct path read temp", "", "User/IO" },
    { "direct path write temp", "", "User/IO" },
    { "advisory lock wait time", "", "Concurrency" },
    { "cn commit", "", "Commit" },
    { "cn execute request", "", "CN Execute" },
    { "cn execute ack", "", "CN Execute" },
    { "buf enter temp page with nolock", "", "Concurrency" },
    { "online redo log recycle", "", "Concurrency" },
    { "undo alloc page from space", "", "Concurrency" },
    { "plsql object lock wait", "", "Concurrency" },
    { "latch: temp pool", "", "Concurrency" },
    { "parallel finish", "", "User/IO" },
    { "gc buffer busy", "", "Cluster" },
    { "dcs: request master4page 1-way", "", "Cluster" },
    { "dcs: request master4page 2-way", "", "Cluster" },
    { "dcs: request master4page 3-way", "", "Cluster" },
    { "dcs: request master4page try", "", "Cluster" },
    { "dcs: request owner4page", "", "Cluster" },
    { "dcs: claim owner", "", "Cluster" },
    { "dcs: recycle owner", "", "Cluster" },
    { "dcs: invalidate readonly copy", "", "Cluster" },
    { "dcs: invalidate readonly copy process", "", "Cluster" },
    { "dcs: transfer page latch", "", "Cluster" },
    { "dcs: transfer page readonly2x", "", "Cluster" },
    { "dcs: transfer page flush log", "", "Cluster" },
    { "dcs: transfer page", "", "Cluster" },
    { "dcs: transfer last edp page", "", "Cluster" },
    { "dcs: transfer last edp page latch", "", "Cluster" },
    { "pcr: request btree page", "", "Cluster" },
    { "pcr: request heap page", "", "Cluster" },
    { "pcr: request master", "", "Cluster" },
    { "pcr: request owner", "", "Cluster" },
    { "pcr: check current visible", "", "Cluster" },
    { "txn: request txn info", "", "Cluster" },
    { "txn: request txn snapshot", "", "Cluster" },
    { "dls: request spinlock/latch", "", "Cluster" },
    { "dls: request table lock", "", "Cluster" },
    { "txn: wait remote", "", "Cluster" },
    { "smon: dead lock check txn remote", "", "Cluster" },
    { "smon: dead lock check table remote", "", "Cluster" },
    { "smon: dead lock check itl remote", "", "Cluster" },
    { "broadcast btree split", "", "Cluster" },
    { "broadcast btree root page", "", "Cluster" },
    { "ckpt disable wait", "", "Commit" },
};

#ifdef WIN32
__declspec(thread) void *tls_curr_sess = 0;
#else
__thread void *tls_curr_sess = 0;
#endif

void knl_set_curr_sess2tls(void *sess)
{
    tls_curr_sess = sess;
}

void *knl_get_curr_sess(void)
{
    return tls_curr_sess;
}

const wait_event_desc_t *knl_get_event_desc(const uint16 id)
{
    return &g_wait_event_desc[id];
}

status_t knl_ddl_latch_s(drlatch_t *latch, knl_handle_t session, latch_statis_t *stat)
{
    knl_session_t *se = (knl_session_t *)session;

    do {
        if (!dls_latch_timed_s(session, latch, 1, CT_FALSE, stat, CT_INVALID_ID32)) {
            if (se->canceled) {
                CT_THROW_ERROR(ERR_OPERATION_CANCELED);
                return CT_ERROR;
            }

            if (se->killed) {
                CT_THROW_ERROR(ERR_OPERATION_KILLED);
                return CT_ERROR;
            }
        } else {
            latch->latch.sid = se->id;
            return CT_SUCCESS;
        }
    } while (1);
}

status_t knl_ddl_latch_x_inner(drlatch_t *latch, knl_handle_t session, latch_statis_t *stat)
{
    knl_session_t *se = (knl_session_t *)session;

    do {
        if (se->user_locked_ddl) {
            CT_THROW_ERROR(ERR_USER_DDL_LOCKED);
            return CT_ERROR;
        }
        if (!dls_latch_timed_x(session, latch, se->id, 1, stat, CT_INVALID_ID32)) {
            if (se->canceled) {
                CT_THROW_ERROR(ERR_OPERATION_CANCELED);
                return CT_ERROR;
            }

            if (se->killed) {
                CT_THROW_ERROR(ERR_OPERATION_KILLED);
                return CT_ERROR;
            }
        } else {
            if (DB_IS_CLUSTER((knl_session_t*)session) && RC_REFORM_IN_PROGRESS) {
                dls_unlatch(session, latch, NULL);
                CT_THROW_ERROR(ERR_CLUSTER_DDL_DISABLED);
                return CT_ERROR;
            }
            return CT_SUCCESS;
        }
    } while (1);
}

status_t knl_ddl_latch_sx(knl_handle_t session, latch_statis_t *stat)
{
    knl_session_t *se = (knl_session_t *)session;
    drlatch_t *ddl_latch = &se->kernel->db.ddl_latch;
    drlatch_t *ctrl_latch = &se->kernel->db.ctrl_latch;
    if (knl_ddl_latch_x_inner(ctrl_latch, session, stat) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (knl_ddl_latch_s(ddl_latch, session, stat) != CT_SUCCESS) {
        dls_unlatch(session, ctrl_latch, NULL);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t knl_ddl_latch_x(knl_handle_t session, latch_statis_t *stat)
{
    knl_session_t *se = (knl_session_t *)session;
    drlatch_t *ddl_latch = &se->kernel->db.ddl_latch;
    drlatch_t *ctrl_latch = &se->kernel->db.ctrl_latch;
    if (knl_ddl_latch_x_inner(ctrl_latch, session, stat) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (knl_ddl_latch_x_inner(ddl_latch, session, stat) != CT_SUCCESS) {
        dls_unlatch(session, ctrl_latch, NULL);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void knl_ddl_unlatch_x(knl_handle_t session)
{
    knl_session_t *se = (knl_session_t *)session;
    drlatch_t *ddl_latch = &se->kernel->db.ddl_latch;
    drlatch_t *ctrl_latch = &se->kernel->db.ctrl_latch;
    dls_unlatch(session, ddl_latch, NULL);
    dls_unlatch(session, ctrl_latch, NULL);
}

status_t knl_match_cond(knl_handle_t session, knl_cursor_t *cursor, bool32 *matched)
{
    knl_match_cond_t match_cond = NULL;
    knl_session_t *se = (knl_session_t *)session;

    if (IS_INDEX_ONLY_SCAN(cursor)) {
        idx_decode_row(se, cursor, cursor->offsets, cursor->lens, &cursor->data_size);
        cursor->decode_cln_total = ((index_t *)cursor->index)->desc.column_count;
    } else {
        cm_decode_row_ex((char *)cursor->row, cursor->offsets, cursor->lens, cursor->decode_count, &cursor->data_size,
                         &cursor->decode_cln_total);
    }

    match_cond = se->match_cond;

    if (cursor->stmt == NULL || match_cond == NULL) {
        *matched = CT_TRUE;
        return CT_SUCCESS;
    }

    return match_cond(cursor->stmt, matched);
}

/*
 * kernel interface for begin autonomous rm
 * @param handle pointer for kernel session
 * @note handle would be switch to autonomous rm after called.
 */
status_t knl_begin_auton_rm(knl_handle_t session)
{
    if (g_knl_callback.alloc_auton_rm(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_set_session_scn(session, CT_INVALID_ID64);
    return CT_SUCCESS;
}

/*
 * kernel interface for end autonomous rm
 * @note end current transaction due to execution status
 * @note handle would be switch to parent rm after called.
 */
void knl_end_auton_rm(knl_handle_t handle, status_t status)
{
    knl_session_t *session = (knl_session_t *)(handle);

    if (status == CT_SUCCESS) {
        knl_commit(session);
    } else {
        knl_rollback(session, NULL);
    }

    (void)g_knl_callback.release_auton_rm(handle);
}

status_t knl_timestamp_to_scn(knl_handle_t session, timestamp_t tstamp, uint64 *scn)
{
    knl_session_t *se = (knl_session_t *)session;
    struct timeval time;
    time_t init_time;

    init_time = DB_INIT_TIME(se);
    cm_date2timeval(tstamp, &time);

    if (time.tv_sec < init_time) {
        CT_THROW_ERROR(ERR_TOO_OLD_SCN, "no snapshot found based on specified time");
        return CT_ERROR;
    }

    *scn = KNL_TIME_TO_SCN(&time, init_time);

    return CT_SUCCESS;
}

void knl_scn_to_timeval(knl_handle_t session, knl_scn_t scn, timeval_t *time_val)
{
    knl_session_t *se = (knl_session_t *)session;
    time_t init_time;

    init_time = DB_INIT_TIME(se);
    KNL_SCN_TO_TIME(scn, time_val, init_time);
}

void knl_set_replica(knl_handle_t session, uint16 replica_port, bool32 is_start)
{
    knl_session_t *se = (knl_session_t *)session;
    arch_context_t *arch_ctx = &se->kernel->arch_ctx;
    lrcv_context_t *lrcv = &se->kernel->lrcv_ctx;
    se->kernel->attr.repl_port = replica_port;

    if (is_start) {
        cm_spin_lock(&arch_ctx->dest_lock, NULL);
        // set arch_dest_state_changed = CT_TRUE to trigger log sender init in srv loop
        arch_ctx->arch_dest_state_changed = CT_TRUE;
        while (arch_ctx->arch_dest_state_changed) {
            if (se->killed) {
                cm_spin_unlock(&arch_ctx->dest_lock);
                return;
            }
            cm_sleep(1);
        }
        cm_spin_unlock(&arch_ctx->dest_lock);
    }

    if (DB_IS_PRIMARY(&se->kernel->db)) {
        return;
    }

    if (lrcv->session == NULL) {
        return;
    }

    lrcv_close(se);
}

void knl_qos_begin(knl_handle_t session)
{
    knl_session_t *se = (knl_session_t *)session;
    uint32 threshold = se->kernel->attr.qos_threshold;
    uint32 sleep_time = se->kernel->attr.qos_sleep_time;
    uint32 random_range = se->kernel->attr.qos_random_range;
    uint32 total_wait_time = 0;
    uint32 sleep_in_us = 0;

    if (!se->kernel->attr.enable_qos) {
        return;
    }

    while (se->qos_mode != QOS_NOWAIT) {
        // running_sessions is smaller than uint32
        if ((uint32)se->kernel->running_sessions < threshold) {
            break;
        }

        if (total_wait_time > CT_MAX_QOS_WAITTIME_US) {
            break;
        }

        // wait time at once should be in ms level, and increase by exponential
        sleep_in_us = sleep_time * (MICROSECS_PER_MILLISEC + se->itl_id % random_range);
        cm_spin_sleep_ex(MICROSECS_PER_MILLISEC * sleep_in_us);
        total_wait_time = total_wait_time + sleep_in_us;
    }

    (void)cm_atomic32_inc(&se->kernel->running_sessions);
}

void knl_qos_end(knl_handle_t session)
{
    knl_session_t *se = (knl_session_t *)session;

    if (!se->kernel->attr.enable_qos) {
        return;
    }

    if (se->kernel->running_sessions > 0) {
        (void)cm_atomic32_dec(&se->kernel->running_sessions);
        if (se->kernel->running_sessions < 0) {
            se->kernel->running_sessions = 0;
        }
    }
    se->qos_mode = QOS_NORMAL;
    se->status = SESSION_ACTIVE;
}

void knl_set_repl_timeout(knl_handle_t handle, uint32 val)
{
    knl_session_t *session = (knl_session_t *)handle;

    session->kernel->attr.repl_wait_timeout = val;
    session->kernel->lrcv_ctx.timeout = val;

    for (uint32 i = 0; i < CT_MAX_PHYSICAL_STANDBY; i++) {
        if (session->kernel->lsnd_ctx.lsnd[i] != NULL) {
            session->kernel->lsnd_ctx.lsnd[i]->timeout = val;
        }
    }
}

status_t knl_set_session_trans(knl_handle_t session, isolation_level_t level, bool32 is_select)
{
    knl_session_t *se = (knl_session_t *)session;

    if (DB_IS_READONLY(se) && (is_select == CT_FALSE)) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
        return CT_ERROR;
    }

    if (level < ISOLATION_READ_COMMITTED || level > ISOLATION_SERIALIZABLE) {
        CT_THROW_ERROR(ERR_INVALID_ISOLATION_LEVEL, level);
        return CT_ERROR;
    }

    if (se->rm->query_scn != CT_INVALID_ID64 || se->rm->txn != NULL) {
        CT_THROW_ERROR(ERR_TXN_IN_PROGRESS, "set transaction must be first statement of transaction");
        return CT_ERROR;
    }

    se->rm->isolevel = (uint8)level;
    se->rm->query_scn = DB_CURR_SCN(se);

    return CT_SUCCESS;
}

/*
 * set session query scn
 * Set the current session query scn as expected, if invalid
 * scn input, we set the query scn during to current isolation level.
 *
 * We use the query scn to judge the visibility of different transaction.
 * @param kernel session handle, expected query scn
 */
void knl_set_session_scn(knl_handle_t handle, uint64 scn)
{
    knl_session_t *session = (knl_session_t *)handle;
    knl_rm_t *rm = session->rm;

    if (SECUREC_UNLIKELY(scn != CT_INVALID_ID64)) {
        session->query_scn = scn;
    } else if (rm->isolevel != (uint8)ISOLATION_SERIALIZABLE) {
        session->query_scn = DB_CURR_SCN(session);
    } else {
        knl_panic(rm->query_scn != CT_INVALID_ID64);
        session->query_scn = rm->query_scn;
    }
}

/*
 * increase session SSN(sql sequence number)
 *
 * Increase current session SSN to separate different sql statement, so following
 * statement can see the results of previous statement in same transaction.
 *
 * @note Cursor would set its SSN to row/key to declare that it has changed it.
 * Different statement(include forked statement) has different SSN.

 * The statement can only modify the same row/key once during its lifetime, so
 * be careful if you got an error "row has been changed by current statement".
 * Cursor see the before version of row/key if it has changed it rather than
 * the after version. If you want to read the result just changed in transaction,
 * increase the SSN to indicate that it's a different statement.
 *
 * The SSN value of same row/key is strictly increasing.
 * @param kernel session handle
 */
void knl_inc_session_ssn(knl_handle_t handle)
{
    knl_session_t *session = (knl_session_t *)handle;

    session->ssn++;

    if (knl_xact_status(session) != XACT_END) {
        session->rm->ssn++;
    }
}

void knl_logic_log_put(knl_handle_t session, uint32 type, const void *data, uint32 size)
{
    knl_session_t *se = (knl_session_t *)session;
    logic_op_t logic_type = type + RD_SQL_LOG_BEGIN;

    log_put(se, RD_LOGIC_OPERATION, &logic_type, sizeof(logic_op_t), LOG_ENTRY_FLAG_NONE);
    log_append_data(se, data, size);
}

static inline void knl_init_session_stat(knl_session_t *session)
{
    session->stat->cr_gets = 0;
    session->stat->dcs_buffer_gets = 0;
    session->stat->dcs_buffer_sends = 0;
    session->stat->dcs_cr_gets = 0;
    session->stat->dcs_cr_sends = 0;
    session->stat->cr_reads = 0;
    session->stat->dcs_cr_reads = 0;
    session->stat->dcs_net_time = 0;
    session->stat->buffer_gets = 0;
    session->stat->disk_reads = 0;
    session->stat->disk_read_time = 0;
    session->stat->db_block_changes = 0;
    session->stat->con_wait_time = 0;
    session->stat->table_creates = 0;
    session->stat->table_drops = 0;
    session->stat->table_alters = 0;
    session->stat->hists_inserts = 0;
    session->stat->hists_updates = 0;
    session->stat->hists_deletes = 0;
    session->stat->table_part_drops = 0;
    session->stat->table_subpart_drops = 0;
    session->stat->spc_free_exts = 0;
    session->stat->spc_shrink_times = 0;
    session->stat->undo_free_pages = 0;
    session->stat->undo_shrink_times = 0;
    session->stat->auto_txn_alloc_times = 0;
    session->stat->auto_txn_page_waits = 0;
    session->stat->auto_txn_page_end_waits = 0;
    session->stat->txn_alloc_times = 0;
    session->stat->txn_page_waits = 0;
    session->stat->txn_page_end_waits = 0;
    session->stat->cr_pool_used = 0;
    session->stat->undo_disk_reads = 0;
    session->stat->undo_buf_reads = 0;
    session->stat->btree_leaf_recycled = 0;

    if (session->kernel->attr.enable_table_stat) {
        session->stat_heap.enable = CT_TRUE;
        session->stat_btree.enable = CT_TRUE;
        session->stat_page.enable = CT_TRUE;
        session->stat_lob.enable = CT_TRUE;
        session->stat_interval.enable = CT_TRUE;
    } else {
        session->stat_heap.enable = CT_FALSE;
        session->stat_btree.enable = CT_FALSE;
        session->stat_page.enable = CT_FALSE;
        session->stat_lob.enable = CT_FALSE;
        session->stat_interval.enable = CT_FALSE;
    }
}

uint16 knl_get_rm_sid(knl_handle_t session, uint16 rmid)
{
    knl_session_t *knl_session = (knl_session_t *)session;
    knl_rm_t *rm = NULL;

    if (rmid >= CT_MAX_RMS) {
        CT_LOG_RUN_ERR("knl_get_rm_sid failed, invalid rmid %u", rmid);
        return CT_INVALID_ID16;
    }

    rm = knl_session->kernel->rms[rmid];

    return (rm != NULL) ? rm->sid : CT_INVALID_ID16;
}

void knl_init_rm(knl_handle_t handle, uint16 rmid)
{
    knl_rm_t *rm = (knl_rm_t *)handle;

    rm->id = rmid;
    rm->uid = CT_INVALID_ID32;
    rm->txn = NULL;
    rm->svpt_count = 0;
    rm->logging = CT_TRUE;
    rm->tx_id.value = CT_INVALID_ID64;
    rm->large_page_id = CT_INVALID_ID32;
    rm->query_scn = CT_INVALID_ID64;
    rm->xid.value = CT_INVALID_ID64;
    rm->ssn = 0;
    rm->begin_lsn = CT_INVALID_ID64;
    cm_init_cond(&rm->cond);
    lock_init(rm);
    lob_items_reset(rm);
    rm->temp_has_undo = CT_FALSE;
    rm->temp_has_redo = CT_FALSE;
    rm->noredo_undo_pages.count = 0;
    rm->noredo_undo_pages.first = INVALID_UNDO_PAGID;
    rm->noredo_undo_pages.last = INVALID_UNDO_PAGID;

    rm->xa_flags = CT_INVALID_ID64;
    rm->xa_status = XA_INVALID;
    rm->xa_xid.fmt_id = CT_INVALID_ID64;
    rm->xa_xid.bqual_len = 0;
    rm->xa_xid.gtrid_len = 0;
    rm->xa_prev = CT_INVALID_ID16;
    rm->xa_next = CT_INVALID_ID16;
    rm->xa_rowid = INVALID_ROWID;
    rm->is_ddl_op = CT_FALSE;
    rm->logging = CT_TRUE;
    rm->logic_log_size = 0;
    rm->nolog_type = LOGGING_LEVEL;
    rm->nolog_insert = CT_FALSE;
}

void knl_set_session_rm(knl_handle_t handle, uint16 rmid)
{
    knl_session_t *session = (knl_session_t *)handle;
    knl_rm_t *rm = session->kernel->rms[rmid];

    rm->sid = session->id;
    rm->isolevel = session->kernel->attr.db_isolevel;
    rm->suspend_timeout = session->kernel->attr.xa_suspend_timeout;
    rm->txn_alarm_enable = CT_TRUE;

    session->rmid = rmid;
    session->rm = rm;
    rm->logging = CT_TRUE;
    rm->nolog_type = LOGGING_LEVEL;
    rm->nolog_insert = CT_FALSE;
}

/* knl_session initialize with session->id during lock */
void knl_init_sess_ex(knl_handle_t kernel, knl_handle_t sess)
{
    knl_instance_t *ctx = (knl_instance_t *)kernel;
    knl_session_t *session = (knl_session_t *)sess;

    session->temp_pool = &ctx->temp_pool[session->id % ctx->temp_ctx_count];
    session->temp_mtrl->pool = session->temp_pool;
    knl_set_session_rm(session, session->rmid);
}

/* knl_session initialize without session->id, no need lock */
void knl_init_session(knl_handle_t kernel, knl_handle_t knl_session, uint32 uid, char *plog_buf, cm_stack_t *stack)
{
    knl_instance_t *ctx = (knl_instance_t *)kernel;
    knl_session_t *session = (knl_session_t *)knl_session;
    errno_t ret;

    session->serial_id = 1; /* ID 0 reserved for invalid ID */
    session->uid = uid;
    session->drop_uid = CT_INVALID_ID32;
    session->kernel = ctx;
    session->stack = stack;
    session->log_buf = plog_buf;
    session->wrmid = CT_INVALID_ID16;
    session->wpid = INVALID_PAGID;
    session->wtid.is_locking = CT_FALSE;
    session->wrid = g_invalid_rowid;
    session->wxid.value = CT_INVALID_ID64;
    session->curr_lfn = 0;
    session->ssn = 0;
    session->curr_lsn = DB_CURR_LSN(session);
    session->ddl_lsn_pitr = session->curr_lsn;
    session->commit_batch = (bool8)ctx->attr.commit_batch;
    session->commit_nowait = (bool8)ctx->attr.commit_nowait;
    session->lock_wait_timeout = ctx->attr.lock_wait_timeout;
    session->autotrace = CT_FALSE;
    session->interactive_altpwd = CT_FALSE;
    knl_init_session_stat(session);
    ret = memset_sp(&session->datafiles, CT_MAX_DATA_FILES * sizeof(int32), 0xFF, CT_MAX_DATA_FILES * sizeof(int32));
    knl_securec_check(ret);
    ret = memset_sp(&session->wait_pool, WAIT_EVENT_COUNT * sizeof(knl_session_wait_t), 0,
        WAIT_EVENT_COUNT * sizeof(knl_session_wait_t));
    knl_securec_check(ret);    
    temp_mtrl_init_context(session);
    session->temp_version = 0;
    session->index_root = NULL;
    KNL_SESSION_CLEAR_THREADID(session);
    cm_init_cond(&session->commit_cond);
    session->dist_ddl_id = NULL;
    session->has_migr = CT_FALSE;
    lock_init_group(&session->alck_lock_group);

    session->log_encrypt = CT_FALSE;
    session->atomic_op = CT_FALSE;
    session->logic_log_size = 0;
    session->logic_log_num = 0;
    session->dtc_session_type = DTC_TYPE_NONE;
    session->log_diag = CT_FALSE;
    session->user_locked_ddl = CT_FALSE;
    session->user_locked_lst = NULL;
#ifdef LOG_DIAG
    for (uint32 i = 0; i < KNL_MAX_ATOMIC_PAGES; i++) {
        session->log_diag_page[i] = (char *)malloc(ctx->attr.page_size);
        if (session->log_diag_page[i] == NULL) {
            CT_LOG_RUN_ERR("failed to malloc log_diag_page with size %u", ctx->attr.page_size);
            CM_ABORT(0, "ABORT INFO: failed to malloc log_diag_page");
        }
    }
#endif
}

void knl_reset_index_conflicts(knl_handle_t session)
{
    ((knl_session_t *)session)->rm->idx_conflicts = 0;
}

void knl_init_index_conflicts(knl_handle_t session, uint64 *conflicts)
{
    knl_session_t *se = (knl_session_t *)session;

    *conflicts = se->rm->idx_conflicts;
    se->rm->idx_conflicts = 0;
}

status_t knl_check_index_conflicts(knl_handle_t session, uint64 conflicts)
{
    knl_session_t *se = (knl_session_t *)session;

    if (se->rm->idx_conflicts == 0) {
        se->rm->idx_conflicts = conflicts;
        return CT_SUCCESS;
    }

    ((knl_session_t *)session)->rm->idx_conflicts = 0;
    CT_THROW_ERROR(ERR_DUPLICATE_KEY, "");
    return CT_ERROR;
}

void knl_destroy_session(knl_handle_t kernel, uint32 sid)
{
    knl_instance_t *ctx = (knl_instance_t *)kernel;
    knl_session_t *session = ctx->sessions[sid];

    if (session == NULL) {
        return;
    }

#ifdef LOG_DIAG
    for (uint32 i = 0; i < KNL_MAX_ATOMIC_PAGES; i++) {
        free(session->log_diag_page[i]);
        session->log_diag_page[i] = NULL;
    }
#endif
}

status_t knl_open_dc(knl_handle_t session, text_t *user, text_t *name, knl_dictionary_t *dc)
{
    status_t ret = dc_open((knl_session_t *)session, user, name, dc);
    while (ret != CT_SUCCESS) {
        if (cm_get_error_code() != ERR_DC_LOAD_CONFLICT) {
            return CT_ERROR;
        }
        cm_reset_error();
        ret = dc_open((knl_session_t *)session, user, name, dc);
    }
    return CT_SUCCESS;
}

/* this function won't open dc,it only get dc entry */
dc_entry_t *knl_get_dc_entry(knl_handle_t session, text_t *user, text_t *name, knl_dictionary_t *dc)
{
    return dc_get_entry_private((knl_session_t *)session, user, name, dc);
}

status_t knl_open_dc_with_public(knl_handle_t session, text_t *user, bool32 implicit_user, text_t *name,
                                 knl_dictionary_t *dc)
{
    knl_session_t *se = (knl_session_t *)session;
    bool32 is_found = CT_FALSE;
    text_t public_user = { PUBLIC_USER, (uint32)strlen(PUBLIC_USER) };

    if (CT_SUCCESS != knl_open_dc_if_exists(se, user, name, dc, &is_found)) {
        return CT_ERROR;
    }

    dc->syn_orig_uid = CT_INVALID_ID32;

    (void)knl_get_user_id(session, user, &dc->syn_orig_uid);
    /* find object in current user just return */
    if (is_found) {
        return CT_SUCCESS;
    }

    /* hit specify user or synonym exist but link object not exist scenario, return error */
    if (!implicit_user || se->kernel->db.status < DB_STATUS_OPEN) {
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(user), T2S_EX(name));
        return CT_ERROR;
    }

    if (SYNONYM_EXIST(dc)) {
        CT_THROW_ERROR(ERR_OBJECT_INVALID, "SYNONYM", T2S(user), T2S_EX(name));
        return CT_ERROR;
    }

    if (CT_SUCCESS != knl_open_dc_if_exists(se, &public_user, name, dc, &is_found)) {
        return CT_ERROR;
    }

    if (!is_found) {
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(user), T2S_EX(name));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

// there is not error information in this function
status_t knl_open_dc_with_public_ex(knl_handle_t session, text_t *user, bool32 implicit_user, text_t *name,
    knl_dictionary_t *dc)
{
    knl_session_t *se = (knl_session_t *)session;
    bool32 is_found = CT_FALSE;
    text_t public_user = { PUBLIC_USER, (uint32)strlen(PUBLIC_USER) };

    if (CT_SUCCESS != knl_open_dc_if_exists(se, user, name, dc, &is_found)) {
        cm_reset_error();
        return CT_ERROR;
    }

    dc->syn_orig_uid = CT_INVALID_ID32;

    (void)knl_get_user_id(session, user, &dc->syn_orig_uid);
    /* find object in current user just return */
    if (is_found) {
        return CT_SUCCESS;
    }

    cm_reset_error();
    /* hit specify user or synonym exist but link object not exist scenario, return error */
    if (!implicit_user || se->kernel->db.status < DB_STATUS_OPEN) {
        return CT_ERROR;
    }

    if (SYNONYM_EXIST(dc)) {
        return CT_ERROR;
    }

    if (CT_SUCCESS != knl_open_dc_if_exists(se, &public_user, name, dc, &is_found)) {
        cm_reset_error();
        return CT_ERROR;
    }

    if (!is_found) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t knl_open_seq_dc(knl_handle_t session, text_t *username, text_t *seqname, knl_dictionary_t *dc)
{
    return dc_seq_open((knl_session_t *)session, username, seqname, dc);
}

void knl_close_dc(knl_handle_t dc)
{
    knl_dictionary_t *pdc = (knl_dictionary_t *)dc;

    dc_close(pdc);
}

bool32 knl_is_table_csf(knl_handle_t dc_entity, knl_part_locate_t part_loc)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;

    if (entity->type != DICT_TYPE_TABLE && entity->type != DICT_TYPE_TABLE_NOLOGGING) {
        return CT_FALSE;
    }

    /* normal table */
    table_t *table = &entity->table;
    if (!IS_PART_TABLE(table)) {
        return table->desc.is_csf;
    }

    /* part table */
    if (knl_verify_interval_part(entity, part_loc.part_no)) {
        return table->desc.is_csf;
    }

    table_part_t *table_part = TABLE_GET_PART(table, part_loc.part_no);
    if (!IS_COMPART_TABLE(table->part_table)) {
        return table_part->desc.is_csf;
    }

    /* composite part table */
    table_part_t *table_subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[part_loc.subpart_no]);
    return table_subpart->desc.is_csf;
}

uint32 knl_table_max_row_len(knl_handle_t dc_entity, uint32 max_col_size, knl_part_locate_t part_loc)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    return heap_table_max_row_len(&entity->table, max_col_size, part_loc);
}

bool32 knl_is_part_table(knl_handle_t dc_entity)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;

    if (entity->type != DICT_TYPE_TABLE && entity->type != DICT_TYPE_TABLE_NOLOGGING) {
        return CT_FALSE;
    } else {
        return entity->table.desc.parted;
    }
}

bool32 knl_is_compart_table(knl_handle_t dc_entity)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;

    if (knl_is_part_table(dc_entity)) {
        return IS_COMPART_TABLE(&entity->table.part_table->desc);
    }

    return CT_FALSE;
}

part_type_t knl_part_table_type(knl_handle_t dc_entity)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    table_t *table = &entity->table;

    if (!knl_is_part_table(dc_entity)) {
        return PART_TYPE_INVALID;
    }

    knl_panic_log(table->part_table != NULL, "the part_table is NULL, panic info: table %s", entity->table.desc.name);
    return table->part_table->desc.parttype;
}

part_type_t knl_subpart_table_type(knl_handle_t dc_entity)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    table_t *table = &entity->table;

    if (!knl_is_part_table(dc_entity)) {
        return PART_TYPE_INVALID;
    }

    knl_panic_log(table->part_table != NULL, "the part_table is NULL, panic info: table %s", entity->table.desc.name);
    if (!knl_is_compart_table(dc_entity)) {
        return PART_TYPE_INVALID;
    }

    return table->part_table->desc.subparttype;
}

bool32 knl_table_nologging_enabled(knl_handle_t dc_entity)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    table_t *table = &entity->table;

    if (table->desc.type != TABLE_TYPE_HEAP) {
        return CT_FALSE;
    }

    if (IS_PART_TABLE(table)) {
        return CT_FALSE;
    }

    return table->desc.is_nologging;
}

bool32 knl_part_nologging_enabled(knl_handle_t dc_entity, knl_part_locate_t part_loc)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    table_t *table = &entity->table;

    if (table->desc.type != TABLE_TYPE_HEAP) {
        return CT_FALSE;
    }

    table_part_t *compart = TABLE_GET_PART(table, part_loc.part_no);
    if (!IS_PARENT_TABPART(&compart->desc)) {
        return compart->desc.is_nologging;
    }

    knl_panic(part_loc.subpart_no != CT_INVALID_ID32);
    table_part_t *subpart = PART_GET_SUBENTITY(table->part_table, compart->subparts[part_loc.subpart_no]);

    return subpart->desc.is_nologging;
}

uint32 knl_part_count(knl_handle_t dc_entity)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    part_table_t *part_table = entity->table.part_table;
    return part_table->desc.partcnt;
}

uint32 knl_subpart_count(knl_handle_t dc_entity, uint32 part_no)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    part_table_t *part_table = entity->table.part_table;
    table_part_t *table_part = PART_GET_ENTITY(part_table, part_no);
    knl_panic_log(IS_PARENT_TABPART(&table_part->desc),
                  "the table_part is not parent tabpart, panic info: "
                  "table %s table_part %s",
                  entity->table.desc.name, table_part->desc.name);
    return table_part->desc.subpart_cnt;
}

uint32 knl_total_subpart_count(knl_handle_t dc_entity)
{
    table_part_t *compart = NULL;
    table_part_t *subpart = NULL;
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    part_table_t *part_table = entity->table.part_table;

    knl_panic_log(IS_COMPART_TABLE(part_table), "the part_table is not compart table, panic info: table %s",
                  entity->table.desc.name);
    uint32 total_subparts = 0;
    for (uint32 i = 0; i < part_table->desc.partcnt; i++) {
        compart = TABLE_GET_PART(&entity->table, i);
        if (!IS_READY_PART(compart)) {
            continue;
        }

        knl_panic_log(IS_PARENT_TABPART(&compart->desc),
                      "the compart is not parent tabpart, panic info: "
                      "table %s compart %s",
                      entity->table.desc.name, compart->desc.name);
        for (uint32 j = 0; j < compart->desc.subpart_cnt; j++) {
            subpart = PART_GET_SUBENTITY(part_table, compart->subparts[j]);
            if (subpart == NULL) {
                continue;
            }

            total_subparts++;
        }
    }

    return total_subparts;
}

uint32 knl_real_part_count(knl_handle_t dc_entity)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    part_table_t *part_table = entity->table.part_table;
    return PART_CONTAIN_INTERVAL(part_table) ? part_table->desc.real_partcnt : part_table->desc.partcnt;
}

uint16 knl_part_key_count(knl_handle_t dc_entity)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    part_table_t *part_table = entity->table.part_table;
    return (uint16)part_table->desc.partkeys;
}

uint16 knl_part_key_column_id(knl_handle_t dc_entity, uint16 id)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    part_table_t *part_table = entity->table.part_table;
    return part_table->keycols[id].column_id;
}

void knl_set_table_part(knl_cursor_t *cursor, knl_part_locate_t part_loc)
{
    cursor->part_loc = part_loc;
    cursor->table_part = TABLE_GET_PART(cursor->table, part_loc.part_no);
    if (IS_PARENT_TABPART(&((table_part_t *)(cursor->table_part))->desc)) {
        table_t *table = (table_t *)cursor->table;
        table_part_t *table_part = (table_part_t *)cursor->table_part;
        cursor->table_part = PART_GET_SUBENTITY(table->part_table, table_part->subparts[part_loc.subpart_no]);
    }
}

status_t knl_find_table_part_by_name(knl_handle_t dc_entity, text_t *name, uint32 *part_no)
{
    dc_entity_t *entity;
    part_table_t *part_table;
    table_part_t *table_part = NULL;

    entity = (dc_entity_t *)dc_entity;
    part_table = entity->table.part_table;

    if (!part_table_find_by_name(part_table, name, &table_part)) {
        CT_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(name));
        return CT_ERROR;
    }

    *part_no = table_part->part_no;
    return CT_SUCCESS;
}

/*
 * fetch dynamic view interface
 * use the dynamic view registered fetch function to get a virtual cursor row.
 * @param kernel session, kernel cursor
 */
static status_t knl_fetch_dynamic_view(knl_handle_t session, knl_cursor_t *cursor)
{
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;

    for (;;) {
        if (entity->dview->fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cursor->eof) {
            return CT_SUCCESS;
        }

        if (knl_match_cond(session, cursor, &cursor->is_found) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cursor->is_found) {
            return CT_SUCCESS;
        }
    }
}

status_t knl_get_index_par_schedule(knl_handle_t handle, knl_dictionary_t *dc, knl_idx_paral_info_t paral_info,
                                    knl_index_paral_range_t *sub_ranges)
{
    knl_session_t *session = (knl_session_t *)handle;
    dc_entity_t *entity = DC_ENTITY(dc);
    index_t *index = NULL;
    index_part_t *index_part = NULL;
    btree_t *btree = NULL;
    knl_scn_t org_scn;
    errno_t err;

    if (knl_check_dc(session, dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc->type != DICT_TYPE_TABLE && dc->type != DICT_TYPE_TABLE_NOLOGGING) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "parallel scan", "temp table");
        return CT_ERROR;
    }

    knl_panic_log(paral_info.index_slot < entity->table.index_set.total_count,
                  "the index_slot is not smaller than "
                  "index_set's total count, panic info: table %s index_slot %u index_set's total_count %u",
                  entity->table.desc.name, paral_info.index_slot, entity->table.index_set.total_count);
    index = entity->table.index_set.items[paral_info.index_slot];

    if (IS_PART_INDEX(index)) {
        knl_panic_log(
            paral_info.part_loc.part_no < index->part_index->desc.partcnt,
            "the part_no is not smaller than part count, panic info: table %s index %s part_no %u part count %u",
            entity->table.desc.name, index->desc.name, paral_info.part_loc.part_no, index->part_index->desc.partcnt);
        index_part = INDEX_GET_PART(index, paral_info.part_loc.part_no);
        if (index_part == NULL) {
            sub_ranges->workers = 0;
            return CT_SUCCESS;
        }

        if (IS_PARENT_IDXPART(&index_part->desc)) {
            uint32 subpart_no = paral_info.part_loc.subpart_no;
            index_part_t *subpart = PART_GET_SUBENTITY(index->part_index, index_part->subparts[subpart_no]);
            btree = &subpart->btree;
            org_scn = subpart->desc.org_scn;
        } else {
            btree = &index_part->btree;
            org_scn = index_part->desc.org_scn;
        }

        if (btree->segment == NULL && !IS_INVALID_PAGID(btree->entry)) {
            if (dc_load_index_part_segment(session, entity, index_part) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    } else {
        btree = &index->btree;
        org_scn = index->desc.org_scn;
    }

    if (btree->segment == NULL) {
        sub_ranges->workers = 0;
        return CT_SUCCESS;
    }

    if (paral_info.is_index_full) {
        for (uint32 i = 0; i < index->desc.column_count; i++) {
            knl_set_key_flag(&paral_info.org_range->l_key, SCAN_KEY_LEFT_INFINITE, i);
            knl_set_key_flag(&paral_info.org_range->r_key, SCAN_KEY_RIGHT_INFINITE, i);
        }
    }

    if (idx_get_paral_schedule(session, btree, org_scn, paral_info, sub_ranges) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sub_ranges->workers == 1) {
        err = memcpy_sp(sub_ranges->index_range[0], sizeof(knl_scan_range_t), paral_info.org_range,
                        sizeof(knl_scan_range_t));
        knl_securec_check(err);
    }
    return CT_SUCCESS;
}

void knl_set_index_scan_range(knl_cursor_t *cursor, knl_scan_range_t *sub_range)
{
    errno_t err;

    err = memcpy_sp(cursor->scan_range.l_buf, CT_KEY_BUF_SIZE, sub_range->l_buf, CT_KEY_BUF_SIZE);
    knl_securec_check(err);
    cursor->scan_range.l_key = sub_range->l_key;
    cursor->scan_range.l_key.buf = cursor->scan_range.l_buf;
    err = memcpy_sp(cursor->scan_range.r_buf, CT_KEY_BUF_SIZE, sub_range->r_buf, CT_KEY_BUF_SIZE);
    knl_securec_check(err);

    cursor->scan_range.r_key = sub_range->r_key;
    cursor->scan_range.r_key.buf = cursor->scan_range.r_buf;
    cursor->scan_range.is_equal = sub_range->is_equal;
}

void knl_set_table_scan_range(knl_handle_t handle, knl_cursor_t *cursor, page_id_t left, page_id_t right)
{
    knl_session_t *session = (knl_session_t *)handle;

    if (!spc_validate_page_id(session, left)) {
        cursor->scan_range.l_page = INVALID_PAGID;
    } else {
        cursor->scan_range.l_page = left;
    }

    if (!spc_validate_page_id(session, right)) {
        cursor->scan_range.r_page = INVALID_PAGID;
    } else {
        cursor->scan_range.r_page = right;
    }

    SET_ROWID_PAGE(&cursor->rowid, cursor->scan_range.l_page);
    cursor->rowid.slot = INVALID_SLOT;
}

void knl_init_table_scan(knl_handle_t handle, knl_cursor_t *cursor)
{
    heap_segment_t *segment;
    knl_session_t *session = (knl_session_t *)handle;

    segment = (heap_segment_t *)(CURSOR_HEAP(cursor)->segment);
    if (segment == NULL) {
        cursor->scan_range.l_page = INVALID_PAGID;
        cursor->scan_range.r_page = INVALID_PAGID;
    } else {
        heap_t *heap = CURSOR_HEAP(cursor);
        segment = HEAP_SEGMENT(session, heap->entry, heap->segment);
        cursor->scan_range.l_page = segment->data_first;
        if (!spc_validate_page_id(session, cursor->scan_range.l_page)) {
            cursor->scan_range.l_page = INVALID_PAGID;
        }

        cursor->scan_range.r_page = segment->data_last;
        if (!spc_validate_page_id(session, cursor->scan_range.r_page)) {
            cursor->scan_range.r_page = INVALID_PAGID;
        }
    }

    SET_ROWID_PAGE(&cursor->rowid, cursor->scan_range.l_page);
    cursor->rowid.slot = INVALID_SLOT;
}

static status_t dc_load_part_segments(knl_session_t *session, knl_cursor_t *cursor, knl_dictionary_t *dc)
{
    table_part_t *table_part = NULL;
    table_t *table = (table_t *)cursor->table;
    table_part = (table_part_t *)TABLE_GET_PART(table, cursor->part_loc.part_no);
    if (!IS_READY_PART(table_part)) {
        return CT_SUCCESS;
    }

    if (IS_PARENT_TABPART(&table_part->desc)) {
        knl_panic_log(cursor->part_loc.subpart_no != CT_INVALID_ID32,
                      "the subpart_no record on cursor is invalid, "
                      "panic info: table %s table_part %s",
                      table->desc.name, table_part->desc.name);
        table_part = PART_GET_SUBENTITY(table->part_table, table_part->subparts[cursor->part_loc.subpart_no]);
        if (table_part == NULL) {
            return CT_SUCCESS;
        }
    }

    if (table_part->heap.loaded) {
        return CT_SUCCESS;
    }

    if (dc_load_table_part_segment(session, cursor->dc_entity, table_part) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * open table cursor interface
 * Open a normal table cursor in request scan mode, register the fetch method
 * @param kernel session, kernel cursor, kernel dictionary
 */
static status_t knl_open_table_cursor(knl_session_t *session, knl_cursor_t *cursor, knl_dictionary_t *dc)
{
    cursor->table_part = NULL;
    cursor->index_part = NULL;
    cursor->chain_count = 0;
    cursor->cleanout = CT_FALSE;
    cursor->is_locked = CT_FALSE;
    cursor->ssi_conflict = CT_FALSE;
    cursor->ssn = session->rm->ssn;

    table_t *table = (table_t *)(cursor->table);
    if (IS_PART_TABLE(table)) {
        if (dc_load_part_segments(session, cursor, dc) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (cursor->action == CURSOR_ACTION_INSERT) {
        cursor->rowid_count = 0;
        cursor->rowid_no = 0;
        cursor->row_offset = 0;
        cursor->index = NULL;
        return CT_SUCCESS;
    }

    if (cursor->scan_mode == SCAN_MODE_INDEX) {
        index_t *index = DC_INDEX(dc, cursor->index_slot);

        cursor->index = index;
        cursor->fetch = index->acsor->do_fetch;
        cursor->key_loc.is_initialized = CT_FALSE;
        if (index->desc.is_dsc && DB_ATTR_COMPATIBLE_MYSQL(session)) {
            cursor->index_dsc = index->desc.is_dsc;
        }

        if (IS_PART_INDEX(cursor->index)) {
            knl_panic_log(cursor->part_loc.part_no != CT_INVALID_ID32,
                          "the part_no record on cursor is invalid, "
                          "panic info: table %s index %s",
                          table->desc.name, index->desc.name);
            cursor->table_part = TABLE_GET_PART(cursor->table, cursor->part_loc.part_no);
            cursor->index_part = INDEX_GET_PART(cursor->index, cursor->part_loc.part_no);
            if (!IS_READY_PART(cursor->table_part)) {
                cursor->eof = CT_TRUE;
                return CT_SUCCESS;
            }

            if (IS_PARENT_IDXPART(&((index_part_t *)(cursor->index_part))->desc)) {
                knl_panic_log(cursor->part_loc.subpart_no != CT_INVALID_ID32,
                              "the subpart_no record on cursor is "
                              "invalid, panic info: table %s index %s",
                              table->desc.name, index->desc.name);
                index_part_t *index_part = (index_part_t *)cursor->index_part;
                table_part_t *table_part = (table_part_t *)cursor->table_part;
                uint32 subpart_no = cursor->part_loc.subpart_no;
                cursor->index_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[subpart_no]);
                cursor->table_part = PART_GET_SUBENTITY(table->part_table, table_part->subparts[subpart_no]);
                if (cursor->index_part == NULL) {
                    cursor->eof = CT_TRUE;
                    return CT_SUCCESS;
                }
            }
        }
    } else if (cursor->scan_mode == SCAN_MODE_TABLE_FULL) {
        cursor->fetch = TABLE_ACCESSOR(cursor)->do_fetch;

        if (IS_PART_TABLE(table)) {
            knl_panic_log(cursor->part_loc.part_no != CT_INVALID_ID32,
                          "the part_no record on cursor is invalid, panic info: table %s", table->desc.name);
            cursor->table_part = TABLE_GET_PART(table, cursor->part_loc.part_no);
            if (!IS_READY_PART(cursor->table_part)) {
                cursor->eof = CT_TRUE;
                return CT_SUCCESS;
            }

            if (IS_PARENT_TABPART(&((table_part_t *)(cursor->table_part))->desc)) {
                uint32 subpart_no = cursor->part_loc.subpart_no;
                knl_panic_log(subpart_no != CT_INVALID_ID32,
                              "the subpart_no record on cursor is invalid, panic info: table %s", table->desc.name);
                table_part_t *table_part = (table_part_t *)cursor->table_part;
                cursor->table_part = PART_GET_SUBENTITY(table->part_table, table_part->subparts[subpart_no]);
                if (cursor->table_part == NULL) {
                    cursor->eof = CT_TRUE;
                    return CT_SUCCESS;
                }
            }
        }

        knl_init_table_scan(session, cursor);

        cursor->index = NULL;
    } else if (cursor->scan_mode == SCAN_MODE_ROWID) {
        cursor->fetch = TABLE_ACCESSOR(cursor)->do_rowid_fetch;
        cursor->index = NULL;
        cursor->rowid_no = 0;
    }

    return CT_SUCCESS;
}

void knl_init_cursor_buf(knl_handle_t handle, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)handle;
    char *ext_buf;
    uint32 ext_size;

    /* 2 pages, one is for cursor->row, one is for cursor->page_buf */
    ext_buf = cursor->buf + 2 * DEFAULT_PAGE_SIZE(session);
    ext_size = session->kernel->attr.max_column_count * sizeof(uint16);

    cursor->offsets = (uint16 *)ext_buf;
    cursor->lens = (uint16 *)(ext_buf + ext_size);
    cursor->update_info = session->trig_ui == NULL ? session->update_info : *session->trig_ui;
    cursor->update_info.count = 0;
    cursor->update_info.data = NULL;

    cursor->insert_info.data = NULL;
    cursor->insert_info.lens = NULL;
    cursor->insert_info.offsets = NULL;
}

/*
 * create kernel cursor and initialize it
 * when call this interface, need to add CM_SAVE_STACK and CM_RESTORE_STACK around it
 */
knl_cursor_t *knl_push_cursor(knl_handle_t handle)
{
    knl_session_t *session = (knl_session_t *)handle;
    char *ext_buf = NULL;
    uint32 ext_size;

    knl_cursor_t *cursor = (knl_cursor_t *)cm_push(session->stack, session->kernel->attr.cursor_size);

    knl_panic_log(cursor != NULL, "cursor is NULL.");

    /* 2 pages, one is for cursor->row, one is for cursor->page_buf */
    ext_buf = cursor->buf + 2 * DEFAULT_PAGE_SIZE(session);
    ext_size = session->kernel->attr.max_column_count * sizeof(uint16);
    cursor->offsets = (uint16 *)ext_buf;
    cursor->lens = (uint16 *)(ext_buf + ext_size);

    cursor->update_info.columns = (uint16 *)cm_push(session->stack, ext_size);
    knl_panic_log(cursor->update_info.columns != NULL,
                  "update_info's columns record on cursor is NULL, panic info: "
                  "stack's size %u heap_offset %u push_offset %u table %s",
                  session->stack->size, session->stack->heap_offset, session->stack->push_offset,
                  ((table_t *)cursor->table)->desc.name);

    cursor->update_info.offsets = (uint16 *)cm_push(session->stack, ext_size);
    knl_panic_log(cursor->update_info.offsets != NULL,
                  "update_info's offsets record on cursor is NULL, panic info: "
                  "stack's size %u heap_offset %u push_offset %u table %s",
                  session->stack->size, session->stack->heap_offset, session->stack->push_offset,
                  ((table_t *)cursor->table)->desc.name);

    cursor->update_info.lens = (uint16 *)cm_push(session->stack, ext_size);
    knl_panic_log(cursor->update_info.lens != NULL,
                  "update_info's lens record on cursor is NULL, panic info: "
                  "stack's size %u heap_offset %u push_offset %u table %s",
                  session->stack->size, session->stack->heap_offset, session->stack->push_offset,
                  ((table_t *)cursor->table)->desc.name);

    KNL_INIT_CURSOR(cursor);

    return cursor;
}

/*
 * pop the stack when used by kernel cursor
 * only used by sql_update_depender_status interface
 */
void knl_pop_cursor(knl_handle_t handle)
{
    knl_session_t *session = (knl_session_t *)handle;

    cm_pop(session->stack);  // pop cursor->update_info.lens
    cm_pop(session->stack);  // pop cursor->update_info.offsets
    cm_pop(session->stack);  // cursor->update_info.columns
    cm_pop(session->stack);  // pop cursor
}

/*
 * create kernel cursor and initialize it., only used by sharing layer and sql layer
 * when call this interface, need to add CTSQL_SAVE_STACK and CTSQL_RESTORE_STACK around it
 * @param kernel handle, knl_cursor_t ** cursor
 */
status_t sql_push_knl_cursor(knl_handle_t handle, knl_cursor_t **cursor)
{
    knl_session_t *session = (knl_session_t *)handle;
    char *ext_buf = NULL;
    uint32 ext_size;

    *cursor = (knl_cursor_t *)cm_push(session->stack, session->kernel->attr.cursor_size);

    if (*cursor == NULL) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        return CT_ERROR;
    }

    /* 2 pages, one is for cursor->row, one is for cursor->page_buf */
    ext_buf = (*cursor)->buf + 2 * session->kernel->attr.page_size;
    ext_size = session->kernel->attr.max_column_count * sizeof(uint16);
    (*cursor)->offsets = (uint16 *)ext_buf;
    (*cursor)->lens = (uint16 *)(ext_buf + ext_size);

    (*cursor)->update_info.columns = (uint16 *)cm_push(session->stack, ext_size);
    if ((*cursor)->update_info.columns == NULL) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        return CT_ERROR;
    }

    (*cursor)->update_info.offsets = (uint16 *)cm_push(session->stack, ext_size);
    if ((*cursor)->update_info.offsets == NULL) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        return CT_ERROR;
    }

    (*cursor)->update_info.lens = (uint16 *)cm_push(session->stack, ext_size);
    if ((*cursor)->update_info.lens == NULL) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        return CT_ERROR;
    }

    KNL_INIT_CURSOR((*cursor));

    return CT_SUCCESS;
}

void knl_open_sys_cursor(knl_session_t *session, knl_cursor_t *cursor, knl_cursor_action_t action, uint32 table_id,
                         uint32 index_slot)
{
    knl_rm_t *rm = session->rm;
    heap_t *heap = NULL;
    heap_segment_t *segment = NULL;
    index_t *index = NULL;
    knl_dictionary_t dc;

    knl_inc_session_ssn(session);

    db_get_sys_dc(session, table_id, &dc);
    if (DB_IS_UPGRADE(session) && dc.handle == NULL) {
        CM_ABORT(0, "[UPGRADE] ABORT INFO: System table %u is not available during upgrade processs", table_id);
    }

    cursor->table = DC_TABLE(&dc);
    cursor->dc_entity = dc.handle;
    cursor->dc_type = dc.type;
    cursor->action = action;
    cursor->row = (row_head_t *)cursor->buf;
    cursor->page_buf = cursor->buf + DEFAULT_PAGE_SIZE(session);
    cursor->update_info.data = session->update_info.data;
    cursor->isolevel = ISOLATION_READ_COMMITTED;
    if (DB_IS_PRIMARY(&session->kernel->db)) {
        cursor->query_scn = DB_CURR_SCN(session);
    } else {
        cursor->query_scn = session->query_scn;
    }
    cursor->query_lsn = DB_CURR_LSN(session);
    cursor->xid = rm->xid.value;
    cursor->ssn = rm->ssn;
    cursor->is_locked = CT_FALSE;
    cursor->cleanout = CT_FALSE;
    cursor->eof = CT_FALSE;
    cursor->is_valid = CT_TRUE;
    cursor->stmt = NULL;
    cursor->restrict_part = CT_FALSE;
    cursor->restrict_subpart = CT_FALSE;
    cursor->decode_count = CT_INVALID_ID16;
    cursor->is_xfirst = CT_FALSE;
    cursor->disable_pk_update = CT_TRUE;

    if (index_slot != CT_INVALID_ID32) {
        index = DC_INDEX(&dc, index_slot);
        cursor->index = index;

        cursor->index_slot = index_slot;
        cursor->fetch = index->acsor->do_fetch;
        cursor->scan_mode = SCAN_MODE_INDEX;
        cursor->index_dsc = CT_FALSE;
        cursor->index_only = CT_FALSE;
        cursor->key_loc.is_initialized = CT_FALSE;
    } else {
        cursor->fetch = TABLE_ACCESSOR(cursor)->do_fetch;
        cursor->scan_mode = SCAN_MODE_TABLE_FULL;
        cursor->index = NULL;

        heap = CURSOR_HEAP(cursor);
        segment = (heap_segment_t *)(heap->segment);
        if (segment == NULL) {
            cursor->scan_range.l_page = INVALID_PAGID;
        } else {
            buf_enter_page(session, heap->entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
            segment = (heap_segment_t *)(heap->segment);
            buf_leave_page(session, CT_FALSE);

            cursor->scan_range.l_page = segment->data_first;
            if (!spc_validate_page_id(session, cursor->scan_range.l_page)) {
                cursor->scan_range.l_page = INVALID_PAGID;
            }
        }
        cursor->scan_range.r_page = INVALID_PAGID;
        SET_ROWID_PAGE(&cursor->rowid, cursor->scan_range.l_page);
        cursor->rowid.slot = INVALID_SLOT;
    }
}

static inline void knl_update_cursor_isolevel(knl_session_t *session, knl_cursor_t *cursor)
{
    table_t *table = (table_t *)cursor->table;
    if (table->ashrink_stat == ASHRINK_COMPACT && cursor->isolevel == ISOLATION_CURR_COMMITTED &&
        !session->compacting) {
        cursor->isolevel = ISOLATION_READ_COMMITTED;
    }
}

/*
 * open kernel cursor interface
 * @note if query wants to set query scn and ssn, please set after open cursor
 * @param kernel session handle, kernel cursor, kernel dictionary
 */
status_t knl_open_cursor(knl_handle_t handle, knl_cursor_t *cursor, knl_dictionary_t *dc)
{
    knl_session_t *session = (knl_session_t *)handle;
    knl_rm_t *rm = session->rm;
    dc_entity_t *entity = DC_ENTITY(dc);

    if (DB_IS_READONLY(session) && cursor->action > CURSOR_ACTION_SELECT) {
        if (DB_IS_PRIMARY(&session->kernel->db) ||
            (dc->type != DICT_TYPE_TEMP_TABLE_SESSION && dc->type != DICT_TYPE_TEMP_TABLE_TRANS)) {
            CT_THROW_ERROR(ERR_DATABASE_ROLE, "operation", "in readonly mode");
            return CT_ERROR;
        }
    }

    if (cursor->action != CURSOR_ACTION_SELECT && !cursor->skip_lock) {
        /* in case of select for update, wait time depend on input */
        if (cursor->action == CURSOR_ACTION_UPDATE && cursor->rowmark.type != ROWMARK_WAIT_BLOCK) {
            if (lock_table_shared(session, entity, cursor->rowmark.wait_seconds) != CT_SUCCESS) {
                return CT_ERROR;
            }
        } else {
            if (lock_table_shared(session, entity, LOCK_INF_WAIT) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    cursor->dc_type = dc->type;
    cursor->dc_entity = entity;
    cursor->table = &entity->table;
    cursor->page_buf = cursor->buf + DEFAULT_PAGE_SIZE(session);
    cursor->xid = rm->xid.value;
    cursor->isolevel = rm->isolevel;
    cursor->query_scn = session->query_scn;
    cursor->query_lsn = session->curr_lsn;
    cursor->cc_cache_time = KNL_NOW(session);
    cursor->eof = CT_FALSE;
    cursor->is_valid = CT_TRUE;
    cursor->row = (row_head_t *)cursor->buf;
    cursor->chain_info = cursor->buf;
    cursor->update_info.data = cursor->page_buf;
    cursor->disable_pk_update = CT_FALSE;

    cursor->null_first = DB_ATTR_COMPATIBLE_MYSQL(session) == 1 ? CT_TRUE : CT_FALSE;
    
    knl_update_cursor_isolevel(session, cursor);

    switch (dc->type) {
        case DICT_TYPE_DYNAMIC_VIEW:
        case DICT_TYPE_GLOBAL_DYNAMIC_VIEW:
            cursor->fetch = knl_fetch_dynamic_view;
            return entity->dview->dopen(session, cursor);

        case DICT_TYPE_TEMP_TABLE_SESSION:
        case DICT_TYPE_TEMP_TABLE_TRANS:
            return knl_open_temp_cursor(session, cursor, dc);

        case DICT_TYPE_TABLE_EXTERNAL:
            return knl_open_external_cursor(session, cursor, dc);
        default:
            return knl_open_table_cursor(session, cursor, dc);
    }
}

/*
 * in the case of rescan, it means a re-open of a existing cursor.
 * this may happen in the operation like JOIN and the re-opened cursor already
 * got an query_scn and ssn, it should not be update.
 */
status_t knl_reopen_cursor(knl_handle_t session, knl_cursor_t *cursor, knl_dictionary_t *dc)
{
    knl_scn_t query_scn;
    uint64 query_lsn;
    uint64 ssn;
    uint8 isolevel;
    row_head_t *row_buf;
    char *upd_buf;
    uint64 xid;

    query_scn = cursor->query_scn;
    query_lsn = cursor->query_lsn;
    ssn = cursor->ssn;
    isolevel = cursor->isolevel;
    row_buf = cursor->row;
    upd_buf = cursor->update_info.data;
    xid = cursor->xid;

    if (knl_open_cursor(session, cursor, dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cursor->query_scn = query_scn;
    cursor->query_lsn = query_lsn;
    cursor->ssn = ssn;
    cursor->isolevel = isolevel;
    cursor->row = row_buf;
    cursor->update_info.data = upd_buf;
    cursor->xid = xid;

    return CT_SUCCESS;
}

void knl_close_cursor(knl_handle_t session, knl_cursor_t *cursor)
{
    knl_session_t *se = (knl_session_t *)session;
    if (cursor->vm_page == NULL) {
        return;
    }

    vm_close_and_free(se, se->temp_pool, cursor->vm_page->vmid);
    cursor->vm_page = NULL;
}

status_t knl_cursor_use_vm(knl_handle_t handle, knl_cursor_t *cursor, bool32 replace_row)
{
    knl_session_t *session = (knl_session_t *)handle;
    uint32 vmid;

    if (cursor->vm_page == NULL) {
        if (vm_alloc(session, session->temp_pool, &vmid) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (vm_open(session, session->temp_pool, vmid, &cursor->vm_page) != CT_SUCCESS) {
            vm_free(session, session->temp_pool, vmid);
            return CT_ERROR;
        }
    }

    if (replace_row) {
        cursor->row = (row_head_t *)cursor->vm_page->data;
    }

    return CT_SUCCESS;
}

static inline void knl_init_pcr_index_scan(knl_cursor_t *cursor, index_t *index, bool32 is_equal)
{
    pcrb_key_t *l_key = NULL;
    pcrb_key_t *r_key = NULL;
    errno_t ret;

    cursor->scan_range.is_equal = is_equal;
    cursor->scan_range.l_key.buf = cursor->scan_range.l_buf;
    l_key = (pcrb_key_t *)cursor->scan_range.l_key.buf;
    ret = memset_sp(l_key, sizeof(pcrb_key_t), 0, sizeof(pcrb_key_t));
    knl_securec_check(ret);
    l_key->size = sizeof(pcrb_key_t);
    cursor->key_loc.is_initialized = CT_FALSE;

    if (!is_equal) {
        cursor->scan_range.r_key.buf = cursor->scan_range.r_buf;
        r_key = (pcrb_key_t *)cursor->scan_range.r_key.buf;
        ret = memset_sp(r_key, sizeof(pcrb_key_t), 0, sizeof(pcrb_key_t));
        knl_securec_check(ret);

        /* PCR does not support index for temp table */
        r_key->rowid = INVALID_ROWID;
        r_key->size = sizeof(pcrb_key_t);
    }
}

static inline void knl_init_rcr_index_scan(knl_cursor_t *cursor, index_t *index, bool32 is_equal)
{
    btree_key_t *l_key = NULL;
    btree_key_t *r_key = NULL;
    errno_t ret;

    cursor->scan_range.is_equal = is_equal;
    cursor->scan_range.l_key.buf = cursor->scan_range.l_buf;
    l_key = (btree_key_t *)cursor->scan_range.l_key.buf;
    ret = memset_sp(l_key, sizeof(btree_key_t), 0, sizeof(btree_key_t));
    knl_securec_check(ret);
    l_key->size = sizeof(btree_key_t);
    cursor->key_loc.is_initialized = CT_FALSE;

    if (!is_equal) {
        cursor->scan_range.r_key.buf = cursor->scan_range.r_buf;
        r_key = (btree_key_t *)cursor->scan_range.r_key.buf;
        ret = memset_sp(r_key, sizeof(btree_key_t), 0, sizeof(btree_key_t));
        knl_securec_check(ret);

        if (cursor->dc_type == DICT_TYPE_TEMP_TABLE_SESSION || cursor->dc_type == DICT_TYPE_TEMP_TABLE_TRANS) {
            r_key->rowid = INVALID_TEMP_ROWID;
        } else {
            r_key->rowid = INVALID_ROWID;
        }
        r_key->size = sizeof(btree_key_t);
    }
}

void knl_init_index_scan(knl_cursor_t *cursor, bool32 is_equal)
{
    index_t *index = (index_t *)cursor->index;

    if (index->desc.cr_mode == CR_PAGE) {
        knl_init_pcr_index_scan(cursor, index, is_equal);
    } else {
        knl_init_rcr_index_scan(cursor, index, is_equal);
    }
}

uint32 knl_get_key_size(knl_index_desc_t *desc, const char *buf)
{
    if (desc->cr_mode == CR_PAGE) {
        // size is 12 bit and is smammler than uint32
        return (uint32)((pcrb_key_t *)buf)->size;
    } else {
        // size is 12 bit and is smammler than uint32
        return (uint32)((btree_key_t *)buf)->size;
    }
}

void knl_set_key_size(knl_index_desc_t *desc, knl_scan_key_t *key, uint32 size)
{
    if (desc->cr_mode == CR_PAGE) {
        ((pcrb_key_t *)key->buf)->size = size;
    } else {
        ((btree_key_t *)key->buf)->size = size;
    }
}

uint32 knl_scan_key_size(knl_index_desc_t *desc, knl_scan_key_t *key)
{
    if (desc->cr_mode == CR_PAGE) {
        // size is 12 bit, and add sizeof(knl_scan_key_t) is smammler than uint32
        return (uint32)(sizeof(knl_scan_key_t) + ((pcrb_key_t *)key->buf)->size);
    } else {
        // size is 12 bit, and add sizeof(knl_scan_key_t) is smammler than uint32
        return (uint32)(sizeof(knl_scan_key_t) + ((btree_key_t *)key->buf)->size);
    }
}

void knl_init_key(knl_index_desc_t *desc, char *buf, rowid_t *rid)
{
    if (desc->cr_mode == CR_PAGE) {
        pcrb_init_key((pcrb_key_t *)buf, rid);
    } else {
        btree_init_key((btree_key_t *)buf, rid);
    }
}

void knl_set_key_rowid(knl_index_desc_t *desc, char *buf, rowid_t *rid)
{
    if (desc->cr_mode == CR_PAGE) {
        pcrb_set_key_rowid((pcrb_key_t *)buf, rid);
    } else {
        btree_set_key_rowid((btree_key_t *)buf, rid);
    }
}

void knl_put_key_data(knl_index_desc_t *desc, char *buf, ct_type_t type, const void *data, uint16 len, uint16 id)
{
    bool32 is_pcr = desc->cr_mode == CR_PAGE;

    if (is_pcr) {
        pcrb_put_key_data(buf, type, (const char *)data, len, id);
    } else {
        btree_put_key_data(buf, type, (const char *)data, len, id);
    }

    if (SECUREC_UNLIKELY(IS_REVERSE_INDEX(desc))) {
        uint16 size = idx_get_col_size(type, len, is_pcr);
        uint16 offset = is_pcr ? ((pcrb_key_t*)buf)->size - size : ((btree_key_t*)buf)->size - size;
        idx_reverse_key_data(buf + offset, type, len);
    }
}

void knl_set_scan_key(knl_index_desc_t *desc, knl_scan_key_t *scan_key, ct_type_t type, const void *data, uint16 len,
                      uint16 id)
{
    pcrb_key_t *pcr_key = NULL;
    btree_key_t *rcr_key = NULL;
    bool32 is_pcr = desc->cr_mode == CR_PAGE;

    scan_key->flags[id] = SCAN_KEY_NORMAL;

    if (is_pcr) {
        pcr_key = (pcrb_key_t *)scan_key->buf;
        scan_key->offsets[id] = (uint16)pcr_key->size;
        pcrb_put_key_data(scan_key->buf, type, (const char *)data, len, id);
    } else {
        rcr_key = (btree_key_t *)scan_key->buf;
        scan_key->offsets[id] = (uint16)rcr_key->size;
        btree_put_key_data(scan_key->buf, type, (const char *)data, len, id);
    }

    if (SECUREC_UNLIKELY(IS_REVERSE_INDEX(desc))) {
        uint16 size = idx_get_col_size(type, len, is_pcr);
        uint16 offset = is_pcr ? ((pcrb_key_t*)scan_key->buf)->size - size : ((btree_key_t*)scan_key->buf)->size - size;
        idx_reverse_key_data(scan_key->buf + offset, type, len);
    }
}

void knl_set_key_flag(knl_scan_key_t *border, uint8 flag, uint16 id)
{
    border->flags[id] = flag;
}

/*
 * if index is invalid and it is primary/unique index, then report error
 */
static status_t knl_check_index_operate_state(index_t *index, knl_cursor_t *cursor, bool32 *need_operate)
{
    if (index->desc.is_invalid) {
        // if spliting partition is ongoing, don't report error
        if (INDEX_IS_UNSTABLE(index, cursor->is_splitting)) {
            CT_THROW_ERROR(ERR_INDEX_NOT_STABLE, index->desc.name);
            return CT_ERROR;
        } else {
            *need_operate = CT_FALSE;
        }

        return CT_SUCCESS;
    }

    if (!IS_PART_INDEX(index)) {
        return CT_SUCCESS;
    }

    index_part_t *index_part = (index_part_t *)cursor->index_part;

    if (index_part->desc.is_invalid) {
        if (INDEX_IS_UNSTABLE(index, cursor->is_splitting)) {
            CT_THROW_ERROR(ERR_INDEX_PART_UNUSABLE, index_part->desc.name, index->desc.name);
            return CT_ERROR;
        } else {
            *need_operate = CT_FALSE;
        }
    }

    return CT_SUCCESS;
}

static status_t knl_insert_index_key(knl_handle_t session, knl_cursor_t *cursor)
{
    index_t *index = (index_t *)cursor->index;
    bool32 need_insert = CT_TRUE;

    if (knl_check_index_operate_state(index, cursor, &need_insert) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(!need_insert)) {
        return CT_SUCCESS;
    }

    if (knl_make_key(session, cursor, index, cursor->key) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return index->acsor->do_insert((knl_session_t *)session, cursor);
}

static status_t knl_batch_insert_index_keys(knl_handle_t session, knl_cursor_t *cursor)
{
    index_t *index = (index_t *)cursor->index;
    bool32 need_insert = CT_TRUE;

    if (knl_check_index_operate_state(index, cursor, &need_insert) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(!need_insert)) {
        return CT_SUCCESS;
    }

    if (cursor->dc_type == DICT_TYPE_TEMP_TABLE_SESSION ||
        cursor->dc_type == DICT_TYPE_TEMP_TABLE_TRANS) {
        return temp_btree_batch_insert(session, cursor);
    }

    return pcrb_batch_insert(session, cursor);
}
/*
 * if index is invalid and it is primary/unique index, then report error
 */
static status_t knl_delete_index_key(knl_handle_t session, knl_cursor_t *cursor)
{
    index_t *index = (index_t *)cursor->index;
    bool32 need_delete = CT_TRUE;

    if (knl_check_index_operate_state(index, cursor, &need_delete) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(!need_delete)) {
        return CT_SUCCESS;
    }

    if (knl_make_key(session, cursor, index, cursor->key) != CT_SUCCESS) {
        knl_panic_log(0, "knl_make_key is failed, panic info: page %u-%u type %u table %s index %s", cursor->rowid.file,
                      cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                      ((dc_entity_t *)cursor->dc_entity)->table.desc.name, index->desc.name);
    }

    return index->acsor->do_delete(session, cursor);
}

static inline void knl_check_icol_changed(knl_cursor_t *cursor, index_t *index, uint16 *map, uint32 i,
                                          bool32 *is_changed)
{
    knl_icol_info_t *icol;
    uint32 j, k, col_id;

    icol = &index->desc.columns_info[i];
    for (k = 0; k < icol->arg_count; k++) {
        col_id = icol->arg_cols[k];

        for (j = 0; j < cursor->update_info.count; j++) {
            if (col_id == cursor->update_info.columns[j]) {
                map[i] = j;
                *is_changed = CT_TRUE;
            }
        }
    }
}

static bool32 knl_check_index_changed(knl_session_t *session, knl_cursor_t *cursor, index_t *index, uint16 *map)
{
    uint32 i, j, col_id;
    dc_entity_t *entity = (dc_entity_t *)(cursor->dc_entity);
    bool32 is_changed = CT_FALSE;
    knl_column_t *index_col = NULL;

    for (i = 0; i < index->desc.column_count; i++) {
        map[i] = CT_INVALID_ID16;
        col_id = index->desc.columns[i];
        index_col = dc_get_column(entity, col_id);
        if (KNL_COLUMN_IS_VIRTUAL(index_col)) {
            knl_check_icol_changed(cursor, index, map, i, &is_changed);
        }

        for (j = 0; j < cursor->update_info.count; j++) {
            if (col_id == cursor->update_info.columns[j]) {
                map[i] = j;
                is_changed = CT_TRUE;
            }
        }
    }

    return is_changed;
}

static void knl_restore_cursor_index(knl_cursor_t *cursor, knl_handle_t org_index, uint8 index_slot)
{
    cursor->index_slot = index_slot;
    cursor->index = org_index;
    if (cursor->index != NULL && IS_PART_INDEX(cursor->index)) {
        knl_panic_log(cursor->part_loc.part_no != CT_INVALID_ID32,
                      "the part_no record on cursor is invalid, panic info: table %s index %s",
                      ((dc_entity_t *)cursor->dc_entity)->table.desc.name, ((index_t *)cursor->index)->desc.name);
        index_part_t *index_part = INDEX_GET_PART(cursor->index, cursor->part_loc.part_no);
        if (IS_PARENT_IDXPART(&index_part->desc)) {
            knl_panic_log(cursor->part_loc.subpart_no != CT_INVALID_ID32,
                          "the subpart_no record on cursor is invalid,"
                          " panic info: table %s index %s",
                          ((dc_entity_t *)cursor->dc_entity)->table.desc.name, ((index_t *)cursor->index)->desc.name);
            index_t *index = (index_t *)cursor->index;
            uint32 subpart_no = cursor->part_loc.subpart_no;
            cursor->index_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[subpart_no]);
        } else {
            cursor->index_part = index_part;
        }
    }
}

status_t knl_insert_indexes(knl_handle_t handle, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)handle;
    table_t *table = (table_t *)cursor->table;
    index_t *index = NULL;
    seg_stat_t temp_stat;
    btree_t *btree = NULL;

    table = (table_t *)cursor->table;

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        cursor->index_slot = i;
        index = table->index_set.items[i];
        cursor->index = index;

        if (IS_PART_INDEX(cursor->index)) {
            knl_panic_log(cursor->part_loc.part_no != CT_INVALID_ID32,
                          "the part_no record on cursor is invalid, "
                          "panic info: table %s index %s",
                          table->desc.name, ((index_t *)cursor->index)->desc.name);
            cursor->index_part = INDEX_GET_PART(index, cursor->part_loc.part_no);
            if (IS_PARENT_IDXPART(&((index_part_t *)cursor->index_part)->desc)) {
                knl_panic_log(cursor->part_loc.subpart_no != CT_INVALID_ID32,
                              "the subpart_no record on cursor is "
                              "invalid, panic info: table %s index %s",
                              table->desc.name, ((index_t *)cursor->index)->desc.name);
                index_part_t *index_part = (index_part_t *)cursor->index_part;
                uint32 subpart_no = cursor->part_loc.subpart_no;
                cursor->index_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[subpart_no]);
            }
        }

        btree = CURSOR_BTREE(cursor);
        SEG_STATS_INIT(session, &temp_stat);
        if (knl_insert_index_key(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }
        SEG_STATS_RECORD(session, temp_stat, &btree->stat);
    }

    return CT_SUCCESS;
}

static inline bool32 knl_check_ref_changed(knl_cursor_t *cursor, ref_cons_t *ref, uint16 *map)
{
    uint32 i, j;
    bool32 is_changed = CT_FALSE;

    for (i = 0; i < ref->col_count; i++) {
        map[i] = CT_INVALID_ID16;
        for (j = 0; j < cursor->update_info.count; j++) {
            if (ref->cols[i] == cursor->update_info.columns[j]) {
                map[i] = j;
                is_changed = CT_TRUE;
                break;
            }
        }
    }

    return is_changed;
}

static void knl_check_precision_and_scale_match(knl_column_t *child_column, knl_column_t *ref_column,
                                                bool32 *is_precision_scale_match)
{
    if (!(*is_precision_scale_match)) {
        return;
    }

    if (child_column->datatype == CT_TYPE_REAL ||
        child_column->mysql_ori_datatype == MYSQL_TYPE_ENUM || child_column->mysql_ori_datatype == MYSQL_TYPE_SET) {
        return;
    }

    if (child_column->mysql_ori_datatype == MYSQL_TYPE_BIT) {
        *is_precision_scale_match =
            (CM_ALIGN8((uint32)ref_column->precision) == CM_ALIGN8((uint32)child_column->precision));
        return;
    }

    if (child_column->datatype == CT_TYPE_DATETIME_MYSQL || child_column->datatype == CT_TYPE_TIMESTAMP ||
        child_column->datatype == CT_TYPE_TIME_MYSQL) {
        *is_precision_scale_match =
            (CM_ALIGN2((uint32)ref_column->precision) == CM_ALIGN2((uint32)child_column->precision));
        return;
    }

    *is_precision_scale_match = ref_column->precision == child_column->precision &&
                                ref_column->scale == child_column->scale;
    return;
}

static status_t knl_verify_ref_cons(knl_session_t *session, knl_cursor_t *cursor, ref_cons_t *cons)
{
    knl_dictionary_t dc;
    uint32 i, col_id, uid;
    index_t *index = NULL;
    table_t *table = NULL;
    dc_entity_t *ref_entity = NULL;
    knl_column_t *ref_column = NULL;
    knl_column_t *child_column = NULL;
    char *key = NULL;
    char *data = NULL;
    uint32 len;
    uint32 part_no, subpart_no;
    bool32 parent_exist = CT_FALSE;
    knl_update_info_t *ui = &cursor->update_info;
    index_part_t *index_part = NULL;
    btree_t *btree = NULL;
    uint16 *map;
    bool32 is_precision_scale_match = CT_TRUE;

    map = (uint16 *)cm_push(session->stack, CT_MAX_INDEX_COLUMNS * sizeof(uint16));
    if ((cursor->action == CURSOR_ACTION_UPDATE && !knl_check_ref_changed(cursor, cons, map)) ||
        !cons->cons_state.is_enable) {
        cm_pop(session->stack);
        return CT_SUCCESS;
    }

    if (cons->ref_entity == NULL) {
        cm_spin_lock(&cons->lock, NULL);
        if (cons->ref_entity == NULL) {
            if (knl_open_dc_by_id(session, cons->ref_uid, cons->ref_oid, &dc, CT_TRUE) != CT_SUCCESS) {
                cm_spin_unlock(&cons->lock);
                cm_pop(session->stack);
                return CT_ERROR;
            }

            cons->ref_entity = dc.handle;
        }
        cm_spin_unlock(&cons->lock);
    }

    ref_entity = (dc_entity_t *)cons->ref_entity;
    table = &ref_entity->table;

    for (i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (index->desc.id == cons->ref_ix) {
            break;
        }
    }

    if (index->desc.is_invalid) {
        cm_pop(session->stack);
        CT_THROW_ERROR(ERR_INDEX_NOT_STABLE, index->desc.name);
        return CT_ERROR;
    }

    knl_panic_log(i < table->index_set.count,
                  "table's index count is incorrect, panic info: page %u-%u type %u "
                  "table %s index %s current index_count %u record index_count %u",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name,
                  index->desc.name, i, table->index_set.count);
    if (IS_PART_INDEX(index)) {
        if (db_get_fk_part_no(session, cursor, index, cons->ref_entity, cons, &part_no) != CT_SUCCESS) {
            cm_pop(session->stack);
            return CT_ERROR;
        }

        if (part_no == CT_INVALID_ID32) {
            cm_pop(session->stack);
            CT_THROW_ERROR(ERR_CONSTRAINT_VIOLATED_NO_FOUND, "parent key not found");
            return CT_ERROR;
        }

        index_part = PART_GET_ENTITY(index->part_index, part_no);
        if (IS_PARENT_IDXPART(&index_part->desc)) {
            if (db_get_fk_subpart_no(session, cursor, index, cons->ref_entity, cons, part_no, &subpart_no) !=
                CT_SUCCESS) {
                cm_pop(session->stack);
                return CT_ERROR;
            }

            if (subpart_no == CT_INVALID_ID32 || index->part_index->sub_groups[subpart_no / PART_GROUP_SIZE] == NULL) {
                cm_pop(session->stack);
                CT_THROW_ERROR(ERR_CONSTRAINT_VIOLATED_NO_FOUND, "parent key not found");
                return CT_ERROR;
            }
            index_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[subpart_no]);
        }

        if (index_part == NULL) {
            cm_pop(session->stack);
            CT_THROW_ERROR(ERR_CONSTRAINT_VIOLATED_NO_FOUND, "parent key not found");
            return CT_ERROR;
        }

        if (index_part->desc.is_invalid) {
            cm_pop(session->stack);
            CT_THROW_ERROR(ERR_INDEX_PART_UNUSABLE, index_part->desc.name, index->desc.name);
            return CT_ERROR;
        }
    }

    key = (char *)cm_push(session->stack, CT_KEY_BUF_SIZE);
    knl_init_key(INDEX_DESC(index), key, NULL);

    if (cursor->action == CURSOR_ACTION_INSERT) {
        for (i = 0; i < index->desc.column_count; i++) {
            col_id = cons->cols[i];
            ref_column = dc_get_column(ref_entity, index->desc.columns[i]);
            child_column = dc_get_column((dc_entity_t *)(cursor->dc_entity), col_id);
            knl_check_precision_and_scale_match(child_column, ref_column, &is_precision_scale_match);
            data = CURSOR_COLUMN_DATA(cursor, col_id);
            len = CURSOR_COLUMN_SIZE(cursor, col_id);
            if (len == CT_NULL_VALUE_LEN) {
                cm_pop(session->stack);
                cm_pop(session->stack);
                return CT_SUCCESS;
            }
            knl_put_key_data(INDEX_DESC(index), key, ref_column->datatype, data, len, i);
        }
    } else {
        knl_panic_log(cursor->action == CURSOR_ACTION_UPDATE,
                      "current cursor's action is invalid, panic info: "
                      "page %u-%u type %u table %s index %s",
                      cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name,
                      index->desc.name);
        for (i = 0; i < index->desc.column_count; i++) {
            ref_column = dc_get_column(ref_entity, index->desc.columns[i]);
            col_id = cons->cols[i];
            if (map[i] == CT_INVALID_ID16) {
                data = CURSOR_COLUMN_DATA(cursor, col_id);
                len = CURSOR_COLUMN_SIZE(cursor, col_id);
            } else {
                uid = map[i];
                data = ui->data + ui->offsets[uid];
                len = ui->lens[uid];
            }

            if (len == CT_NULL_VALUE_LEN) {
                cm_pop(session->stack);
                cm_pop(session->stack);
                return CT_SUCCESS;
            }
            knl_put_key_data(INDEX_DESC(index), key, ref_column->datatype, data, len, i);
        }
    }

    if (!is_precision_scale_match) {
        cm_pop(session->stack);
        cm_pop(session->stack);
        CT_THROW_ERROR(ERR_CONSTRAINT_VIOLATED_NO_FOUND, "parent key not found");
        return CT_ERROR;
    }

    if (IS_PART_INDEX(index)) {
        btree = &index_part->btree;
    } else {
        btree = &index->btree;
    }

    if (btree->segment != NULL && index->desc.cr_mode == CR_PAGE) {
        if (pcrb_check_key_exist(session, btree, key, &parent_exist) != CT_SUCCESS) {
            cm_pop(session->stack);
            cm_pop(session->stack);
            return CT_ERROR;
        }
    } else if (btree->segment != NULL) {
        if (btree_check_key_exist(session, btree, key, &parent_exist) != CT_SUCCESS) {
            cm_pop(session->stack);
            cm_pop(session->stack);
            return CT_ERROR;
        }
    } else {
        parent_exist = CT_FALSE;
    }
    cm_pop(session->stack);
    cm_pop(session->stack);
    if (!parent_exist) {
        CT_THROW_ERROR(ERR_CONSTRAINT_VIOLATED_NO_FOUND, "parent key not found");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t knl_verify_check_cons(knl_session_t *session, knl_cursor_t *cursor, check_cons_t *check)
{
    status_t ret;
    cond_result_t cond_result;

    if (!check->cons_state.is_enable) {
        return CT_SUCCESS;
    }

    if (cursor->stmt == NULL || check->condition == NULL) {
        CT_LOG_RUN_WAR("[DC] could not decode check cond %s or stmt is null", T2S(&check->check_text));
        return CT_SUCCESS;
    }

    g_knl_callback.set_stmt_check(cursor->stmt, cursor, CT_TRUE);
    ret = g_knl_callback.match_cond_tree((void *)cursor->stmt, check->condition, &cond_result);
    g_knl_callback.set_stmt_check(cursor->stmt, NULL, CT_FALSE);
    if (ret != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cond_result == COND_FALSE) {
        CT_THROW_ERROR(ERR_CONSTRAINT_VIOLATED_CHECK_FAILED);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t knl_delete_or_update_set_null(knl_session_t *session, knl_cursor_t *cursor, cons_dep_t *dep)
{
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    knl_column_t *dc_column = NULL;
    row_assist_t ra;
    int32 i, j;
    uint16 temp;
    uint16 col_id;
    bool32 is_csf = knl_is_table_csf(entity, cursor->part_loc);

    cursor->update_info.count = dep->col_count;
    cm_row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), dep->col_count, is_csf);
    for (i = 0; i < dep->col_count; i++) {
        col_id = dep->cols[i];
        dc_column = dc_get_column(entity, col_id);
        if (dc_column->nullable != CT_TRUE) {
            CT_THROW_ERROR(ERR_COLUMN_NOT_NULL, dc_column->name);
            return CT_ERROR;
        }
        cursor->update_info.columns[i] = col_id;
        row_put_null(&ra);
    }
    row_end(&ra);
    // sort update_info from small to large
    for (i = 0; i < dep->col_count - 1; i++) {
        for (j = 0; j < dep->col_count - 1 - i; j++) {
            if (cursor->update_info.columns[j] > cursor->update_info.columns[j + 1]) {
                temp = cursor->update_info.columns[j];
                cursor->update_info.columns[j] = cursor->update_info.columns[j + 1];
                cursor->update_info.columns[j + 1] = temp;
            }
        }
    }

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void knl_get_bits_by_len(uint8 *bits, uint16 len)
{
    switch (len) {
        case COLUMN_DATATYPE_LEN_0:
            *bits = COL_BITS_NULL;
            break;
        case COLUMN_DATATYPE_LEN_4:
            *bits = COL_BITS_4;
            break;
        case COLUMN_DATATYPE_LEN_8:
            *bits = COL_BITS_8;
            break;
        default:
            *bits = COL_BITS_VAR;
            break;
    }
}

status_t knl_update_cascade_process(knl_cursor_t *parent_cursor, uint8 count, char **loc,
                                    uint8 *bits, dc_entity_t *entity, uint16 col_id, row_head_t *row_head)
{
    knl_column_t *child_column = NULL;
    uint16 update_len = parent_cursor->update_info.lens[count];
    uint64 original_size;
    uint64 actual_size;
    uint64 zero_count = 0;

    if (update_len == CT_INVALID_ID16) {
        child_column = dc_get_column(entity, col_id);
        if (child_column->nullable != CT_TRUE) {
            CT_THROW_ERROR(ERR_ROW_IS_REFERENCED);
            return CT_ERROR;
        }
        knl_get_bits_by_len(bits, 0);
        return CT_SUCCESS;
    }

    if (*bits == COL_BITS_VAR) {
        row_head->size += sizeof(uint16);
        *(uint16 *)(*loc) = update_len;
        (*loc) += sizeof(uint16);
        original_size = (uint64)update_len + sizeof(uint16);
        actual_size = CM_ALIGN4(original_size);
        zero_count = actual_size - original_size;
    }

    if (update_len > 0) {
        knl_securec_check(memcpy_s((*loc), update_len,
                                   parent_cursor->update_info.data + parent_cursor->update_info.offsets[count],
                                   update_len));
        (*loc) += update_len;
    }

    if (zero_count > 0) {
        knl_securec_check(memset_s((*loc), (size_t)zero_count, 0, (size_t)zero_count));
        (*loc) += zero_count;
    }
    return CT_SUCCESS;
}

// child row err should be sent back at that scenes when update cascade:
// 1. type char: the maximum length of ref column is greater than that of child column
// 2. type varchar: the update char size is greater than the maximum length of child column
// 3. update cascade fk columns are affected by other foreign keys
status_t knl_update_cascade_precheck(uint16 col_id, dc_entity_t *entity, knl_column_t *ref_column,
                                     knl_cursor_t *parent_cursor, int32 data_offset)
{
    ref_cons_t *ref_cons = NULL;
    uint16 loop_fk_column_id;
    uint32 col_count;
    uint32 ref_count = entity->table.cons_set.ref_count;
    knl_column_t *child_column = dc_get_column(entity, col_id);
    CHARSET_COLLATION *cs = NULL;
    char *data;
    uint16 offset, len;
    uint16 count = 0;

    if (child_column->datatype == CT_TYPE_STRING && ref_column->size > child_column->size) {
        CT_THROW_ERROR(ERR_ROW_IS_REFERENCED);
        return CT_ERROR;
    }

    if (child_column->datatype == CT_TYPE_VARCHAR) {
        cs = cm_get_charset_coll(child_column->collate_id);
        data = parent_cursor->update_info.data;
        offset = parent_cursor->update_info.offsets[data_offset];
        len = parent_cursor->update_info.lens[data_offset];
        if (len != CT_INVALID_ID16 &&
            cs->numchars(cs, data + offset, data + offset + len) > child_column->size / cs->mbmaxlen) {
            CT_THROW_ERROR(ERR_ROW_IS_REFERENCED);
            return CT_ERROR;
        }
    }

    for (uint32 i = 0; i < ref_count; i++) {
        ref_cons = entity->table.cons_set.ref_cons[i];
        col_count = ref_cons->col_count;
        for (uint32 j = 0; j < col_count; j++) {
            loop_fk_column_id = ref_cons->cols[j];
            if (loop_fk_column_id == col_id) {
                count++;
                break;
            }
        }
        if (count > 1) {
            CT_THROW_ERROR(ERR_CHILD_ROW_CANNOT_ADD_OR_UPDATE);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t knl_update_cascade(knl_session_t *session, knl_cursor_t *cursor, knl_cursor_t *parent_cursor,
                            cons_dep_t *dep, index_t *parent_index)
{
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    dc_entity_t *parent_entity = (dc_entity_t *)parent_cursor->dc_entity;
    knl_column_t *ref_fk_column = NULL;
    char *loc = NULL;
    uint16 col_id;
    uint16 len;
    uint8 bits;
    uint64 pre_conflicts = session->rm->idx_conflicts;
    
    row_head_t *row_head = (row_head_t *)cursor->update_info.data;
    uint16 ex_maps = col_bitmap_ex_size(entity->column_count);
    row_head->size = sizeof(row_head_t) + ex_maps;
    row_head->flags = 0;
    row_head->column_count = 0;
    cursor->update_info.count = 0;
    loc = cursor->update_info.data + sizeof(row_head_t);
    for (int32 i = 0; i < dep->col_count; i++) {
        col_id = dep->cols[i];
        ref_fk_column = dc_get_column(parent_entity, parent_index->desc.columns[i]);
        for (int32 j = 0; j < parent_cursor->update_info.count; j++) {
            if (parent_cursor->update_info.columns[j] == ref_fk_column->id) {
                CT_RETURN_IFERR(knl_update_cascade_precheck(col_id, entity, ref_fk_column, parent_cursor, j));
                len = idx_get_col_size(ref_fk_column->datatype, parent_cursor->update_info.lens[j], CT_TRUE);
                row_head->size += len;
                row_head->column_count++;
                cursor->update_info.columns[cursor->update_info.count] = col_id;
                knl_get_bits_by_len(&bits, len);
                CT_RETURN_IFERR(knl_update_cascade_process(parent_cursor, j, &loc, &bits, entity, col_id, row_head));
                row_set_column_bits2(row_head, bits, cursor->update_info.count);
                cursor->update_info.count++;
                break;
            }
        }
    }
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);
    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (pre_conflicts != session->rm->idx_conflicts) {
        CT_THROW_ERROR(ERR_CHILD_DUPLICATE_KEY);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t knl_fk_match_parent(void *handle, bool32 *matched)
{
    char *data = NULL;
    uint16 len;
    dep_condition_t *dep_cond = (dep_condition_t *)handle;
    cons_dep_t *dep = dep_cond->dep;
    int16 i;
    uint16 col_id;

    for (i = 0; i < dep->col_count - dep->ix_match_cols; i++) {
        col_id = dep->cols[dep->col_map[i + dep->ix_match_cols]];
        data = CURSOR_COLUMN_DATA(dep_cond->child_cursor, col_id);
        len = CURSOR_COLUMN_SIZE(dep_cond->child_cursor, col_id);
        if (len != dep_cond->lens[i] || memcmp(data, dep_cond->data[i], len) != 0) {
            *matched = CT_FALSE;
            return CT_SUCCESS;
        }
    }

    *matched = CT_TRUE;
    return CT_SUCCESS;
}

void knl_set_cursor_action_when_delete(cons_dep_t *dep, knl_cursor_t *cursor)
{
    if (dep->refactor == REF_DEL_NOT_ALLOWED) {
        cursor->action = CURSOR_ACTION_SELECT;
    } else if (dep->refactor & REF_DEL_CASCADE) {
        cursor->action = CURSOR_ACTION_DELETE;
    } else {
        cursor->action = CURSOR_ACTION_UPDATE;
    }
}

void knl_set_cursor_action_when_update(cons_dep_t *dep, knl_cursor_t *cursor)
{
    if (dep->refactor == REF_DEL_NOT_ALLOWED) {
        cursor->action = CURSOR_ACTION_SELECT;
    } else {
        cursor->action = CURSOR_ACTION_UPDATE;
    }
}

void knl_init_child_cursor(knl_dictionary_t *dc, cons_dep_t *dep, knl_cursor_t *parent_cursor,
                           index_t *parent_index, knl_cursor_t *cursor)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    char *data = NULL;
    uint16_t len;
    uint16_t i;
    uint16_t col_id;
    knl_column_t *column = NULL;
    dep_condition_t *dep_cond = (dep_condition_t *)cursor->stmt;
    cursor->vm_page = NULL;

    if (dep->scan_mode == DEP_SCAN_TABLE_FULL) {
        cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    } else {
        cursor->scan_mode = SCAN_MODE_INDEX;
        cursor->index_slot = dep->idx_slot;
        cursor->index = DC_INDEX(dc, dep->idx_slot);
        knl_init_index_scan(cursor, CT_FALSE);

        for (i = 0; i < dep->ix_match_cols; i++) {
            col_id = parent_index->desc.columns[dep->col_map[i]];
            column = dc_get_column(entity, dep->cols[dep->col_map[i]]);
            data = CURSOR_COLUMN_DATA(parent_cursor, col_id);
            len = CURSOR_COLUMN_SIZE(parent_cursor, col_id);

            knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, column->datatype, data, len, i);
            knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, column->datatype, data, len, i);
        }

        for (i = dep->ix_match_cols; i < INDEX_DESC(cursor->index)->column_count; i++) {
            knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, i);
            knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, i);
        }
    }

    dep_cond->dep = dep;
    dep_cond->child_cursor = cursor;

    for (i = 0; i < dep->col_count - dep->ix_match_cols; i++) {
        col_id = parent_index->desc.columns[dep->col_map[i + dep->ix_match_cols]];
        data = CURSOR_COLUMN_DATA(parent_cursor, col_id);
        len = CURSOR_COLUMN_SIZE(parent_cursor, col_id);
        dep_cond->data[i] = data;
        dep_cond->lens[i] = len;
    }
}

void knl_init_child_cursor_delete(knl_dictionary_t *dc, cons_dep_t *dep, knl_cursor_t *parent_cursor,
                                  index_t *parent_index, knl_cursor_t *cursor)
{
    knl_set_cursor_action_when_delete(dep, cursor);
    knl_init_child_cursor(dc, dep, parent_cursor, parent_index, cursor);
}

void knl_init_child_cursor_update(knl_dictionary_t *dc, cons_dep_t *dep, knl_cursor_t *parent_cursor,
                                  index_t *parent_index, knl_cursor_t *cursor)
{
    knl_set_cursor_action_when_update(dep, cursor);
    knl_init_child_cursor(dc, dep, parent_cursor, parent_index, cursor);
}

status_t knl_update_or_set_null_cascade(knl_session_t *session, cons_dep_t *cons_dep,
                                        knl_cursor_t *child_cursor, knl_cursor_t *parent_cursor, index_t *parent_index)
{
    child_cursor->is_cascade = CT_TRUE;
    if (cons_dep->refactor & REF_UPDATE_SET_NULL) {
        if (knl_delete_or_update_set_null(session, child_cursor, cons_dep) != CT_SUCCESS) {
            child_cursor->is_cascade = CT_FALSE;
            return CT_ERROR;
        }
    } else {
        if (knl_update_cascade(session, child_cursor, parent_cursor, cons_dep, parent_index) != CT_SUCCESS) {
            child_cursor->is_cascade = CT_FALSE;
            return CT_ERROR;
        }
    }
    child_cursor->is_cascade = CT_FALSE;
    return CT_SUCCESS;
}

status_t knl_delete_or_set_null_cascade(knl_session_t *session, cons_dep_t *cons_dep, knl_cursor_t *child_cursor)
{
    child_cursor->is_cascade = CT_TRUE;
    if (cons_dep->refactor & REF_DEL_SET_NULL) {
        if (knl_delete_or_update_set_null(session, child_cursor, cons_dep) != CT_SUCCESS) {
            child_cursor->is_cascade = CT_FALSE;
            return CT_ERROR;
        }
    } else {
        if (knl_internal_delete(session, child_cursor) != CT_SUCCESS) {
            child_cursor->is_cascade = CT_FALSE;
            return CT_ERROR;
        }
    }
    child_cursor->is_cascade = CT_FALSE;
    return CT_SUCCESS;
}

status_t knl_verify_dep_by_row_update(knl_session_t *session, dep_condition_t *dep_cond, knl_cursor_t *parent_cursor,
                                      knl_dictionary_t *child_dc, bool32 *depended, uint8 depth, index_t *parent_index)
{
    status_t ret = CT_ERROR;
    knl_cursor_t *child_cursor = dep_cond->child_cursor;
    cons_dep_t *cons_dep = dep_cond->dep;
    knl_handle_t child_cursor_stmt = child_cursor->stmt;

    dc_entity_t *child_entity = (dc_entity_t *)child_dc->handle;
    session->wtid.is_locking = CT_TRUE;
    session->wtid.oid = child_entity->entry->id;
    session->wtid.uid = child_entity->entry->uid;

    if (dc_locked_by_self(session, child_entity->entry)) {
        if (lock_table_in_exclusive_mode(session, child_entity, child_entity->entry, LOCK_INF_WAIT) != CT_SUCCESS) {
            return ret;
        }
    } else {
        if (lock_table_exclusive(session, child_entity, LOCK_INF_WAIT) != CT_SUCCESS) {
            return ret;
        }
    }

    session->wtid.is_locking = CT_FALSE;
    *depended = CT_FALSE;
    for (;;) {
        child_cursor->stmt = dep_cond;
        if (knl_fetch(session, child_cursor) != CT_SUCCESS) {
            break;
        }

        if (child_cursor->eof) {
            ret = CT_SUCCESS;
            break;
        }

        if (!(cons_dep->refactor & REF_UPDATE_CASCADE || cons_dep->refactor & REF_UPDATE_SET_NULL)) {
            *depended = CT_TRUE;
            ret = CT_SUCCESS;
            break;
        }

        child_cursor->stmt = child_cursor_stmt;

        if (knl_update_or_set_null_cascade(session, cons_dep, child_cursor,
                                           parent_cursor, parent_index) != CT_SUCCESS) {
            ret = CT_ERROR;
            break;
        }

        if (child_cursor->is_found) {
            if (knl_verify_children_dependency(session, child_cursor, CT_TRUE, depth + 1, CT_FALSE) != CT_SUCCESS) {
                ret = CT_ERROR;
                break;
            }
        }
    }

    if (SCH_LOCKED_EXCLUSIVE(child_entity)) {
        lock_degrade_table_lock(session, child_entity);
    }
    child_cursor->stmt = child_cursor_stmt;
    return ret;
}

status_t knl_verify_dep_by_row_delete(knl_session_t *session, dep_condition_t *dep_cond, knl_cursor_t *parent_cursor,
                                      knl_dictionary_t *child_dc, bool32 *depended, uint8 depth)
{
    status_t ret = CT_ERROR;
    knl_cursor_t *child_cursor = dep_cond->child_cursor;
    cons_dep_t *cons_dep = dep_cond->dep;
    knl_handle_t child_cursor_stmt = child_cursor->stmt;

    dc_entity_t *child_entity = (dc_entity_t *)child_dc->handle;
    table_t *child_table = &child_entity->table;
    table_t *parent_table = (table_t *)parent_cursor->table;
    session->wtid.is_locking = CT_TRUE;
    session->wtid.oid = child_entity->entry->id;
    session->wtid.uid = child_entity->entry->uid;

    if (dc_locked_by_self(session, child_entity->entry)) {
        if (lock_table_in_exclusive_mode(session, child_entity, child_entity->entry, LOCK_INF_WAIT) != CT_SUCCESS) {
            return ret;
        }
    } else {
        if (lock_table_exclusive(session, child_entity, LOCK_INF_WAIT) != CT_SUCCESS) {
            return ret;
        }
    }

    session->wtid.is_locking = CT_FALSE;
    *depended = CT_FALSE;
    for (;;) {
        child_cursor->stmt = dep_cond;
        if (knl_fetch(session, child_cursor) != CT_SUCCESS) {
            break;
        }

        if (child_cursor->eof) {
            // self-referenced delete
            if (child_table->desc.id == parent_table->desc.id && child_table->desc.uid == parent_table->desc.uid &&
                !(cons_dep->refactor & REF_DEL_CASCADE || cons_dep->refactor & REF_DEL_SET_NULL)) {
                *depended = CT_TRUE;
            }
            ret = CT_SUCCESS;
            break;
        }

        if (parent_cursor->action == CURSOR_ACTION_UPDATE ||
            !(cons_dep->refactor & REF_DEL_CASCADE || cons_dep->refactor & REF_DEL_SET_NULL)) {
            *depended = CT_TRUE;
            ret = CT_SUCCESS;
            break;
        }

        child_cursor->stmt = child_cursor_stmt;

        if (knl_delete_or_set_null_cascade(session, cons_dep, child_cursor) != CT_SUCCESS) {
            break;
        }

        if (child_cursor->is_found) {
            if (knl_verify_children_dependency(session, child_cursor, false, depth + 1, CT_FALSE) != CT_SUCCESS) {
                break;
            }
        }
    }

    if (SCH_LOCKED_EXCLUSIVE(child_entity)) {
        lock_degrade_table_lock(session, child_entity);
    }
    child_cursor->stmt = child_cursor_stmt;
    return ret;
}

status_t knl_fetch_depended(knl_session_t *session, knl_cursor_t *child_cursor,
                            index_t *index, dep_condition_t *dep_cond)
{
    child_cursor->stmt = dep_cond;
    if (index->desc.cr_mode == CR_PAGE) {
        if (pcrb_fetch_depended(session, child_cursor) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[knl_fetch_depended]: pcrb_fetch_depended failed");
            return CT_ERROR;
        }
    } else {
        if (btree_fetch_depended(session, child_cursor) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[knl_fetch_depended]: pcrb_fetch_depended failed");
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t knl_verify_dep_by_key_update(knl_session_t *session, dep_condition_t *dep_cond, knl_cursor_t *parent_cursor,
                                      knl_dictionary_t *child_dc, bool32 *depended, uint8 depth, index_t *parent_index)
{
    index_t *index = NULL;
    status_t ret = CT_ERROR;
    knl_cursor_t *child_cursor = dep_cond->child_cursor;
    cons_dep_t *cons_dep = dep_cond->dep;
    knl_handle_t child_cursor_stmt = child_cursor->stmt;

    dc_entity_t *child_entity = (dc_entity_t *)child_dc->handle;
    table_t *child_table = &child_entity->table;

    for (uint32 i = 0; i < child_table->index_set.count; i++) {
        index = child_table->index_set.items[i];
        if (index->desc.id == cons_dep->idx_slot) {
            break;
        }
    }
    *depended = CT_FALSE;
    for (;;) {
        if (knl_fetch_depended(session, child_cursor, index, dep_cond) != CT_SUCCESS) {
            break;
        }

        if (child_cursor->eof) {
            ret = CT_SUCCESS;
            break;
        }

        if (!(cons_dep->refactor & REF_UPDATE_CASCADE || cons_dep->refactor & REF_UPDATE_SET_NULL)) {
            *depended = CT_TRUE;
            ret = CT_SUCCESS;
            break;
        }

        child_cursor->stmt = child_cursor_stmt;

        if (knl_update_or_set_null_cascade(session, cons_dep, child_cursor,
                                           parent_cursor, parent_index) != CT_SUCCESS) {
            ret = CT_ERROR;
            break;
        }

        if (child_cursor->is_found) {
            if (knl_verify_children_dependency(session, child_cursor, true, depth + 1, CT_FALSE) != CT_SUCCESS) {
                ret = CT_ERROR;
                break;
            }
        }
    }
    child_cursor->stmt = child_cursor_stmt;
    return ret;
}

status_t knl_verify_dep_by_key_delete(knl_session_t *session, dep_condition_t *dep_cond, knl_cursor_t *parent_cursor,
                                      knl_dictionary_t *child_dc, bool32 *depended, uint8 depth)
{
    index_t *index = NULL;
    status_t ret = CT_ERROR;
    knl_cursor_t *child_cursor = dep_cond->child_cursor;
    cons_dep_t *cons_dep = dep_cond->dep;
    knl_handle_t child_cursor_stmt = child_cursor->stmt;

    dc_entity_t *child_entity = (dc_entity_t *)child_dc->handle;
    table_t *child_table = &child_entity->table;
    table_t *parent_table = (table_t *)parent_cursor->table;

    for (uint32 i = 0; i < child_table->index_set.count; i++) {
        index = child_table->index_set.items[i];
        if (index->desc.id == cons_dep->idx_slot) {
            break;
        }
    }
    *depended = CT_FALSE;
    for (;;) {
        if (knl_fetch_depended(session, child_cursor, index, dep_cond) != CT_SUCCESS) {
            break;
        }

        if (child_cursor->eof) {
            // self-referenced delete
            if (child_table->desc.id == parent_table->desc.id && child_table->desc.uid == parent_table->desc.uid &&
                !(cons_dep->refactor & REF_DEL_CASCADE || cons_dep->refactor & REF_DEL_SET_NULL)) {
                *depended = CT_TRUE;
            }
            ret = CT_SUCCESS;
            break;
        }

        if (parent_cursor->action == CURSOR_ACTION_UPDATE ||
            !(cons_dep->refactor & REF_DEL_CASCADE || cons_dep->refactor & REF_DEL_SET_NULL)) {
            *depended = CT_TRUE;
            ret = CT_SUCCESS;
            break;
        }

        child_cursor->stmt = child_cursor_stmt;

        if (knl_delete_or_set_null_cascade(session, cons_dep, child_cursor) != CT_SUCCESS) {
            break;
        }

        if (child_cursor->is_found) {
            if (knl_verify_children_dependency(session, child_cursor, false, depth + 1, CT_FALSE) != CT_SUCCESS) {
                break;
            }
        }
    }
    child_cursor->stmt = child_cursor_stmt;
    return ret;
}

status_t knl_verify_ref_entity_update(knl_session_t *session, dep_condition_t *dep_cond, knl_dictionary_t *child_dc,
                                      knl_cursor_t *parent_cursor, bool32 *depended, uint8 depth, index_t *parent_index)
{
    if (dep_cond->dep->scan_mode != DEP_SCAN_TABLE_FULL) {
        if (knl_verify_dep_by_key_update(session, dep_cond, parent_cursor, child_dc,
                                         depended, depth, parent_index) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (knl_verify_dep_by_row_update(session, dep_cond, parent_cursor, child_dc,
                                         depended, depth, parent_index) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t knl_verify_ref_entity_delete(knl_session_t *session, dep_condition_t *dep_cond, knl_dictionary_t *child_dc,
                                      knl_cursor_t *parent_cursor, bool32 *depended, uint8 depth)
{
    if (dep_cond->dep->scan_mode != DEP_SCAN_TABLE_FULL) {
        if (knl_verify_dep_by_key_delete(session, dep_cond, parent_cursor, child_dc, depended, depth) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (knl_verify_dep_by_row_delete(session, dep_cond, parent_cursor, child_dc, depended, depth) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t knl_verify_dep_part_table_update(knl_session_t *session, dep_condition_t *dep_cond, bool32 *depended,
                                          knl_cursor_t *parent_cursor, knl_dictionary_t *child_dc,
                                          uint8 depth, index_t *parent_index)
{
    uint32 lpart_no, rpart_no;
    uint32 lsubpart_no, rsubpart_no;
    table_part_t *compart = NULL;
    knl_cursor_t *child_cursor = dep_cond->child_cursor;

    if (dc_get_part_fk_range(session, parent_cursor, child_cursor, dep_cond->dep, &lpart_no, &rpart_no) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* no parititon match, the depended will be set CT_FALSE */
    if (lpart_no == CT_INVALID_ID32) {
        *depended = CT_FALSE;
        return CT_SUCCESS;
    }

    for (uint32 i = lpart_no; i <= rpart_no; i++) {
        child_cursor->part_loc.part_no = i;
        compart = TABLE_GET_PART(child_cursor->table, i);
        if (!IS_READY_PART(compart)) {
            continue;
        }

        if (!IS_PARENT_TABPART(&compart->desc)) {
            child_cursor->part_loc.subpart_no = CT_INVALID_ID32;
            if (knl_reopen_cursor(session, child_cursor, child_dc) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (knl_verify_ref_entity_update(session, dep_cond, child_dc, parent_cursor,
                                             depended, depth, parent_index) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (*depended) {
                return CT_SUCCESS;
            }

            continue;
        }

        if (dc_get_subpart_fk_range(session, parent_cursor, child_cursor,
                                    dep_cond->dep, i, &lsubpart_no, &rsubpart_no) != CT_SUCCESS) {
            return CT_ERROR;
        }

        for (uint32 j = lsubpart_no; j <= rsubpart_no; j++) {
            child_cursor->part_loc.subpart_no = j;
            if (knl_reopen_cursor(session, child_cursor, child_dc) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (knl_verify_ref_entity_update(session, dep_cond, child_dc, parent_cursor,
                                             depended, depth, parent_index) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (*depended) {
                return CT_SUCCESS;
            }
        }
    }

    return CT_SUCCESS;
}

status_t knl_verify_dep_part_table_delete(knl_session_t *session, dep_condition_t *dep_cond, bool32 *depended,
                                          knl_cursor_t *parent_cursor, knl_dictionary_t *child_dc, uint8 depth)
{
    uint32 lpart_no, rpart_no;
    uint32 lsubpart_no, rsubpart_no;
    table_part_t *compart = NULL;
    knl_cursor_t *child_cursor = dep_cond->child_cursor;

    if (dc_get_part_fk_range(session, parent_cursor, child_cursor, dep_cond->dep, &lpart_no, &rpart_no) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* no parititon match, the depended will be set CT_FALSE */
    if (lpart_no == CT_INVALID_ID32) {
        *depended = CT_FALSE;
        return CT_SUCCESS;
    }

    for (uint32 i = lpart_no; i <= rpart_no; i++) {
        child_cursor->part_loc.part_no = i;
        compart = TABLE_GET_PART(child_cursor->table, i);
        if (!IS_READY_PART(compart)) {
            continue;
        }

        if (!IS_PARENT_TABPART(&compart->desc)) {
            child_cursor->part_loc.subpart_no = CT_INVALID_ID32;
            if (knl_reopen_cursor(session, child_cursor, child_dc) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (knl_verify_ref_entity_delete(session, dep_cond, child_dc, parent_cursor,
                                             depended, depth) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (*depended) {
                return CT_SUCCESS;
            }

            continue;
        }

        if (dc_get_subpart_fk_range(session, parent_cursor, child_cursor,
                                    dep_cond->dep, i, &lsubpart_no, &rsubpart_no) != CT_SUCCESS) {
            return CT_ERROR;
        }

        for (uint32 j = lsubpart_no; j <= rsubpart_no; j++) {
            child_cursor->part_loc.subpart_no = j;
            if (knl_reopen_cursor(session, child_cursor, child_dc) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (knl_verify_ref_entity_delete(session, dep_cond, child_dc, parent_cursor,
                                             depended, depth) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (*depended) {
                return CT_SUCCESS;
            }
        }
    }

    return CT_SUCCESS;
}

status_t knl_verify_dep_update(knl_session_t *session, dep_condition_t *dep_cond, knl_dictionary_t *child_dc,
                               knl_cursor_t *parent_cursor, bool32 *depended, uint8 depth, index_t *parent_index)
{
    knl_cursor_t *cursor = dep_cond->child_cursor;

    if (!IS_PART_TABLE(cursor->table)) {
        if (knl_verify_ref_entity_update(session, dep_cond, child_dc, parent_cursor,
                                         depended, depth, parent_index) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        /* global index scan in part table is equal to normal table using index scan */
        if (dep_cond->dep->scan_mode != DEP_SCAN_TABLE_FULL && !IS_PART_INDEX(cursor->index)) {
            return knl_verify_ref_entity_update(session, dep_cond, child_dc, parent_cursor,
                                                depended, depth, parent_index);
        }

        if (knl_verify_dep_part_table_update(session, dep_cond, depended, parent_cursor,
                                             child_dc, depth, parent_index) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t knl_verify_dep_delete(knl_session_t *session, dep_condition_t *dep_cond, knl_dictionary_t *child_dc,
                               knl_cursor_t *parent_cursor, bool32 *depended, uint8 depth)
{
    knl_cursor_t *cursor = dep_cond->child_cursor;

    if (!IS_PART_TABLE(cursor->table)) {
        if (knl_verify_ref_entity_delete(session, dep_cond, child_dc, parent_cursor, depended, depth) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        /* global index scan in part table is equal to normal table using index scan */
        if (dep_cond->dep->scan_mode != DEP_SCAN_TABLE_FULL && !IS_PART_INDEX(cursor->index)) {
            return knl_verify_ref_entity_delete(session, dep_cond, child_dc, parent_cursor, depended, depth);
        }

        if (knl_verify_dep_part_table_delete(session, dep_cond, depended, parent_cursor,
                                             child_dc, depth) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

void knl_set_cursor_when_verify_ref_dep(knl_session_t *session, knl_cursor_t *child_cursor)
{
    if (child_cursor->action == CURSOR_ACTION_SELECT) {
        child_cursor->ssn = session->ssn + 1;
    }

    child_cursor->update_info.data = (char *)cm_push(session->stack, CT_MAX_ROW_SIZE);
    session->match_cond = knl_fk_match_parent;
    child_cursor->isolevel = (uint8)ISOLATION_CURR_COMMITTED;
    child_cursor->query_scn = DB_CURR_SCN(session);
    child_cursor->cc_cache_time = KNL_NOW(session);
}

// if the precision or the scale of parent column and child column do not match, do not cascade child
status_t knl_check_precision_and_scale(cons_dep_t *dep, dc_entity_t *parent_entity, index_t *ref_dc_index,
                                       dc_entity_t *child_entity, bool32 *is_precision_scale_match)
{
    knl_column_t *ref_fk_column = NULL;
    knl_column_t *child_column = NULL;
    for (uint32 i = 0; i < dep->col_count; i++) {
        ref_fk_column = dc_get_column(parent_entity, ref_dc_index->desc.columns[i]);
        child_column = dc_get_column(child_entity, dep->cols[i]);
        knl_check_precision_and_scale_match(child_column, ref_fk_column, is_precision_scale_match);
    }

    return CT_SUCCESS;
}

status_t knl_verify_ref_dep_update(knl_session_t *session, knl_cursor_t *parent_cursor, index_t *parent_index,
                                   cons_dep_t *cons_dep, bool32 *depended, uint8 depth)
{
    dep_condition_t *dep_cond = NULL;
    knl_cursor_t *child_cursor = NULL;
    knl_dictionary_t child_dc;
    knl_match_cond_t org_match_cond = session->match_cond;
    bool32 is_precision_scale_match = CT_TRUE;
    status_t ret;

    if (knl_open_dc_by_id(session, cons_dep->uid, cons_dep->oid, &child_dc, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!cons_dep->loaded || cons_dep->chg_scn != child_dc.chg_scn) {
        dc_load_child_entity(session, cons_dep, &child_dc);
    }

    if (knl_check_precision_and_scale(cons_dep, (dc_entity_t *)(parent_cursor->dc_entity), parent_index,
                                      (dc_entity_t *)(child_dc.handle), &is_precision_scale_match) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!is_precision_scale_match) {
        return CT_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);
    child_cursor = knl_push_cursor(session);

    child_cursor->stmt = cm_push(session->stack, sizeof(dep_condition_t));

    knl_init_child_cursor_update(&child_dc, cons_dep, parent_cursor, parent_index, child_cursor);
    dep_cond = (dep_condition_t *)child_cursor->stmt;

    child_cursor->stmt = parent_cursor->stmt;
    if (knl_open_cursor(session, child_cursor, &child_dc) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        dc_close(&child_dc);
        return CT_ERROR;
    }
    child_cursor->no_logic_logging = parent_cursor->no_logic_logging;
    knl_set_cursor_when_verify_ref_dep(session, child_cursor);

    ret = knl_verify_dep_update(session, dep_cond, &child_dc, parent_cursor, depended, depth, parent_index);

    knl_close_cursor(session, child_cursor);
    session->match_cond = org_match_cond;
    CM_RESTORE_STACK(session->stack);
    dc_close(&child_dc);
    return ret;
}

status_t knl_verify_ref_dep_delete(knl_session_t *session, knl_cursor_t *parent_cursor, index_t *parent_index,
                                   cons_dep_t *cons_dep, bool32 *depended, uint8 depth)
{
    dep_condition_t *dep_cond = NULL;
    knl_cursor_t *child_cursor = NULL;
    knl_dictionary_t child_dc;
    knl_match_cond_t org_match_cond = session->match_cond;
    bool32 is_precision_scale_match = CT_TRUE;
    status_t ret;

    if (knl_open_dc_by_id(session, cons_dep->uid, cons_dep->oid, &child_dc, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!cons_dep->loaded || cons_dep->chg_scn != child_dc.chg_scn) {
        dc_load_child_entity(session, cons_dep, &child_dc);
    }

    if (knl_check_precision_and_scale(cons_dep, (dc_entity_t *)(parent_cursor->dc_entity), parent_index,
                                      (dc_entity_t *)(child_dc.handle), &is_precision_scale_match) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!is_precision_scale_match) {
        return CT_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);
    child_cursor = knl_push_cursor(session);

    child_cursor->stmt = cm_push(session->stack, sizeof(dep_condition_t));

    knl_init_child_cursor_delete(&child_dc, cons_dep, parent_cursor, parent_index, child_cursor);
    dep_cond = (dep_condition_t *)child_cursor->stmt;

    child_cursor->stmt = parent_cursor->stmt;
    if (knl_open_cursor(session, child_cursor, &child_dc) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        dc_close(&child_dc);
        return CT_ERROR;
    }
    child_cursor->no_logic_logging = parent_cursor->no_logic_logging;
    knl_set_cursor_when_verify_ref_dep(session, child_cursor);

    ret = knl_verify_dep_delete(session, dep_cond, &child_dc, parent_cursor, depended, depth);

    knl_close_cursor(session, child_cursor);
    session->match_cond = org_match_cond;
    CM_RESTORE_STACK(session->stack);
    dc_close(&child_dc);
    return ret;
}

bool32 knl_check_index_key_changed(knl_cursor_t *cursor, index_t *index, uint16 *map)
{
    uint32 i, col_id, uid;
    knl_update_info_t *ui = &cursor->update_info;

    for (i = 0; i < index->desc.column_count; i++) {
        col_id = index->desc.columns[i];

        if (map[i] == CT_INVALID_ID16) {
            continue;
        }

        uid = map[i];
        if (ui->lens[uid] != cursor->lens[col_id]) {
            return CT_TRUE;
        }

        if (ui->lens[uid] == CT_NULL_VALUE_LEN) {
            continue;
        }

        if (memcmp(ui->data + ui->offsets[uid], CURSOR_COLUMN_DATA(cursor, col_id), ui->lens[uid])) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

status_t knl_verify_ref_depend(knl_session_t *session, knl_cursor_t *cursor, index_t *index,
                               bool32 *depended, bool32 is_update, uint8 depth)
{
    cons_dep_t *dep = NULL;
    bool32 has_null = CT_FALSE;
    uint16 col_id;
    uint32 i;
    status_t ret = CT_SUCCESS;

    *depended = CT_FALSE;
    for (i = 0; i < index->desc.column_count; i++) {
        col_id = index->desc.columns[i];
        if (CURSOR_COLUMN_SIZE(cursor, col_id) == CT_NULL_VALUE_LEN) {
            has_null = CT_TRUE;
            break;
        }
    }

    if (has_null) {
        *depended = CT_FALSE;
        return CT_SUCCESS;
    }

    dep = index->dep_set.first;
    while (dep != NULL) {
        if (!dep->cons_state.is_enable || !dep->cons_state.is_cascade) {
            dep = dep->next;
            continue;
        }

        if (is_update) {
            ret = knl_verify_ref_dep_update(session, cursor, index, dep, depended, depth);
        } else {
            ret = knl_verify_ref_dep_delete(session, cursor, index, dep, depended, depth);
        }

        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[knl_verify_ref_depend]: verify ref dep fail, is_update: %d", is_update);
            return CT_ERROR;
        }

        if (*depended) {
            return CT_SUCCESS;
        }

        dep = dep->next;
    }

    return CT_SUCCESS;
}

/*
 * kernel interface for ensure row is not referenced by child table row
 * @param handle pointer for kernel session
 * @note called when delete or update
 */
status_t knl_verify_children_dependency(knl_handle_t session, knl_cursor_t *cursor, bool32 is_update,
                                        uint8 depth, bool32 is_dd_table)
{
    table_t *table = &((dc_entity_t *)cursor->dc_entity)->table;
    index_t *index = NULL;
    bool32 depended = CT_FALSE;
    uint32 i;
    uint16 *map = NULL;
    knl_session_t *se = (knl_session_t *)session;

    if (depth >= CT_MAX_CASCADE_DEPTH) {
        CT_THROW_ERROR(ERR_EXCEED_MAX_CASCADE_DEPTH);
        return CT_ERROR;
    }

    if (!table->cons_set.referenced) {
        return CT_SUCCESS;
    }
    map = (uint16 *)cm_push(se->stack, CT_MAX_INDEX_COLUMNS * sizeof(uint16));

    for (i = 0; i < table->index_set.count; i++) {
        index = table->index_set.items[i];
        if (!index->desc.is_enforced || index->dep_set.count == 0) {
            continue;
        }

        if (cursor->action == CURSOR_ACTION_UPDATE && !knl_check_index_changed(se, cursor, index, map)) {
            continue;
        }

        if (knl_verify_ref_depend(se, cursor, index, &depended, is_update, depth) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_ROW_IS_REFERENCED);
            cm_pop(se->stack);
            return CT_ERROR;
        }

        if (depended && !is_dd_table) {
            if (cursor->action == CURSOR_ACTION_DELETE || knl_check_index_key_changed(cursor, index, map)) {
                CT_THROW_ERROR(ERR_ROW_IS_REFERENCED);
                cm_pop(se->stack);
                return CT_ERROR;
            }
        }
    }
    cm_pop(se->stack);
    return CT_SUCCESS;
}
/*
 * kernel interface for ensure constraint of check and foreign key(for child table)
 * @param handle pointer for kernel session
 * @note called when insert or update
 */
status_t knl_verify_ref_integrities(knl_handle_t session, knl_cursor_t *cursor)
{
    table_t *table = &((dc_entity_t *)cursor->dc_entity)->table;
    ref_cons_t *cons = NULL;

    if (table->cons_set.ref_count == 0) {
        return CT_SUCCESS;
    }

    if (table->index_set.count == 0) {
        /* if table has no index, row has not be decoded */
        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);
    }

    for (uint32 i = 0; i < table->cons_set.ref_count; i++) {
        cons = table->cons_set.ref_cons[i];
        if (knl_verify_ref_cons((knl_session_t *)session, cursor, cons) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t knl_update_index_key(knl_handle_t session, knl_cursor_t *cursor)
{
    index_t *index = (index_t *)cursor->index;
    uint16 *map = NULL;
    knl_session_t *se = (knl_session_t *)session;
    bool32 need_update = CT_TRUE;

    map = (uint16 *)cm_push(se->stack, CT_MAX_INDEX_COLUMNS * sizeof(uint16));
    if (!knl_check_index_changed(se, cursor, index, map)) {
        cm_pop(se->stack);
        return CT_SUCCESS;
    }

    if (knl_check_index_operate_state(index, cursor, &need_update) != CT_SUCCESS) {
        cm_pop(se->stack);
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(!need_update)) {
        cm_pop(se->stack);
        return CT_SUCCESS;
    }

    /* delete old value */
    if (knl_make_key(session, cursor, index, cursor->key) != CT_SUCCESS) {
        cm_pop(se->stack);
        return CT_ERROR;
    }

    if (index->acsor->do_delete(session, cursor) != CT_SUCCESS) {
        cm_pop(se->stack);
        return CT_ERROR;
    }

    /* insert new value */
    if (knl_make_update_key(session, cursor, index, cursor->key, &cursor->update_info, map) != CT_SUCCESS) {
        cm_pop(se->stack);
        return CT_ERROR;
    }

    if (index->acsor->do_insert(session, cursor) != CT_SUCCESS) {
        cm_pop(se->stack);
        return CT_ERROR;
    }

    cm_pop(se->stack);
    return CT_SUCCESS;
}

status_t knl_insert(knl_handle_t session, knl_cursor_t *cursor)
{
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_KNL_INSERT, &tv_begin);
    if (cursor->vnc_column != NULL) {
        CT_THROW_ERROR(ERR_COLUMN_NOT_NULL, cursor->vnc_column);
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INSERT, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    if (knl_internal_insert(session, cursor) == CT_SUCCESS) {
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INSERT, &tv_begin, IO_STAT_SUCCESS);
        return CT_SUCCESS;
    }

    if (cursor->rowid_count == 0) {
        CT_THROW_ERROR(ERR_INVALID_NUMBER, "");
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INSERT, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    cm_reset_error();
    /* if batch insert failed, retry to insert as much as possible with single row insert */
    uint32 row_count = cursor->rowid_count;
    row_head_t *row_addr = cursor->row;
    for (uint32 i = 0; i < row_count; i++) {
        cursor->rowid_count = 1;
        if (knl_internal_insert(session, cursor) != CT_SUCCESS) {
            cursor->rowid_count = i;
            cursor->row = row_addr;
            cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INSERT, &tv_begin, IO_STAT_FAILED);
            return CT_ERROR;
        }
        cursor->row = (row_head_t *)((char *)cursor->row + cursor->row->size);
    }

    cursor->row = row_addr;
    cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INSERT, &tv_begin, IO_STAT_SUCCESS);
    return CT_SUCCESS;
}

static status_t knl_update_shadow_index(knl_session_t *session, knl_cursor_t *cursor, shadow_index_t *shadow_index,
                                        knl_cursor_action_t action)
{
    if (!shadow_index->is_valid) {
        return CT_SUCCESS;
    }

    if (shadow_index->part_loc.part_no != CT_INVALID_ID32) {
        if (shadow_index->part_loc.part_no != cursor->part_loc.part_no ||
            shadow_index->part_loc.subpart_no != cursor->part_loc.subpart_no) {
            return CT_SUCCESS;
        }

        cursor->index = SHADOW_INDEX_ENTITY(shadow_index);
        cursor->index_part = &shadow_index->index_part;
    } else {
        cursor->index = &shadow_index->index;
        if (IS_PART_INDEX(cursor->index)) {
            index_part_t *index_part = INDEX_GET_PART(cursor->index, cursor->part_loc.part_no);
            if (IS_PARENT_IDXPART(&index_part->desc)) {
                index_t *index = &shadow_index->index;
                index_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[cursor->part_loc.subpart_no]);
            }
            cursor->index_part = index_part;
        }
    }

    switch (action) {
        case CURSOR_ACTION_INSERT:
            return knl_insert_index_key(session, cursor);

        case CURSOR_ACTION_DELETE:
            return knl_delete_index_key(session, cursor);

        case CURSOR_ACTION_UPDATE:
            return knl_update_index_key(session, cursor);

        default:
            return CT_SUCCESS;
    }
}

static status_t knl_insert_single_appendix(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity)
{
    table_t *table = (table_t *)cursor->table;

    if (table->cons_set.check_count > 0) {
        for (uint32 i = 0; i < table->cons_set.check_count; i++) {
            if (knl_verify_check_cons(session, cursor, table->cons_set.check_cons[i]) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    if (table->shadow_index != NULL) {
        if (knl_update_shadow_index(session, cursor, table->shadow_index, CURSOR_ACTION_INSERT) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static inline bool32 knl_insert_index_batchable(knl_session_t *session, knl_cursor_t *cursor, index_t *index)
{
    return (index->desc.cr_mode == CR_PAGE ||
            cursor->dc_type == DICT_TYPE_TEMP_TABLE_SESSION ||
            cursor->dc_type == DICT_TYPE_TEMP_TABLE_TRANS);
}

static status_t knl_batch_insert_indexes(knl_session_t *session, knl_cursor_t *cursor, bool32 expect_batch_insert)
{
    index_t *index = NULL;
    seg_stat_t temp_stat;
    btree_t *btree = NULL;
    idx_batch_insert insert_method = expect_batch_insert ? knl_batch_insert_index_keys : knl_insert_index_key;
    table_t *table = (table_t *)cursor->table;
    uint8 index_slot = cursor->index_slot;
    knl_handle_t org_index = cursor->index;

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (knl_insert_index_batchable(session, cursor, index) != expect_batch_insert) {
            continue;
        }

        cursor->index_slot = i;
        cursor->index = index;

        if (IS_PART_INDEX(cursor->index)) {
            knl_panic_log(cursor->part_loc.part_no != CT_INVALID_ID32,
                          "the part_no record on cursor is invalid, "
                          "panic info: table %s index %s",
                          table->desc.name, ((index_t *)cursor->index)->desc.name);
            index_part_t *index_part = INDEX_GET_PART(cursor->index, cursor->part_loc.part_no);
            if (IS_PARENT_IDXPART(&index_part->desc)) {
                knl_panic_log(cursor->part_loc.subpart_no != CT_INVALID_ID32,
                              "the subpart_no record on cursor is "
                              "invalid, panic info: table %s index %s",
                              table->desc.name, ((index_t *)cursor->index)->desc.name);
                index_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[cursor->part_loc.subpart_no]);
            }
            cursor->index_part = index_part;
        }

        btree = CURSOR_BTREE(cursor);
        SEG_STATS_INIT(session, &temp_stat);
        if (insert_method(session, cursor) != CT_SUCCESS) {
            knl_restore_cursor_index(cursor, org_index, index_slot);
            return CT_ERROR;
        }

        SEG_STATS_RECORD(session, temp_stat, &btree->stat);
    }

    knl_restore_cursor_index(cursor, org_index, index_slot);
    return CT_SUCCESS;
}

static inline bool32 knl_need_insert_appendix(knl_cursor_t *cursor)
{
    table_t *table = (table_t *)cursor->table;

    if (table->desc.index_count > 0 || table->cons_set.check_count > 0 || table->shadow_index != NULL) {
        return CT_TRUE;
    }

    if (cursor->rowid_count > 0 && table->cons_set.ref_count > 0) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

static status_t knl_insert_appendix(knl_session_t *session, knl_cursor_t *cursor)
{
    table_t *table = (table_t *)cursor->table;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;

    if (SECUREC_LIKELY(cursor->rowid_count == 0)) {
        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);
        if (table->desc.index_count > 0) {
            if (knl_insert_indexes(session, cursor) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }

        if (knl_insert_single_appendix(session, cursor, entity) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (knl_batch_insert_indexes(session, cursor, CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        row_head_t *row_addr = cursor->row;
        for (uint32 i = 0; i < cursor->rowid_count; i++) {
            cursor->rowid = cursor->rowid_array[i];
            cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);
            if (knl_batch_insert_indexes(session, cursor, CT_FALSE) != CT_SUCCESS) {
                cursor->row = row_addr;
                return CT_ERROR;
            }

            if (knl_insert_single_appendix(session, cursor, entity) != CT_SUCCESS) {
                cursor->row = row_addr;
                return CT_ERROR;
            }

            if (knl_verify_ref_integrities(session, cursor) != CT_SUCCESS) {
                cursor->row = row_addr;
                return CT_ERROR;
            }
            cursor->row = (row_head_t *)((char *)cursor->row + cursor->row->size);
        }

        cursor->row = row_addr;
    }

    return CT_SUCCESS;
}

status_t knl_internal_insert(knl_handle_t session, knl_cursor_t *cursor)
{
    if (!cursor->is_valid) {
        CT_THROW_ERROR(ERR_INVALID_CURSOR);
        return CT_ERROR;
    }

    knl_session_t *se = (knl_session_t *)session;

    if (SECUREC_UNLIKELY(!cursor->logging)) {
        if (se->kernel->lsnd_ctx.standby_num > 0) {
            CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "insert data in nologging mode when standby server is available");
            return CT_ERROR;
        }

        if (!se->rm->nolog_insert) {
            se->rm->nolog_insert = CT_TRUE;
            CT_LOG_RUN_WAR("The transcation(seg_id: %d, slot: %d, xnum: %d) is inserting data without logs.",
                se->rm->xid.xmap.seg_id, se->rm->xid.xmap.slot, se->rm->xid.xnum);
        }

        se->rm->logging = CT_FALSE;
        se->rm->nolog_type = cursor->nologging_type;
    }

    seg_stat_t seg_stat;
    knl_savepoint_t save_point;
    SEG_STATS_INIT(se, &seg_stat);
    knl_savepoint(session, &save_point);

    if (TABLE_ACCESSOR(cursor)->do_insert(session, cursor) != CT_SUCCESS) {
        int32 code = cm_get_error_code();
        if (code != ERR_SHRINK_EXTEND) {
            knl_rollback(session, &save_point);
        }

        return CT_ERROR;
    }

    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    if (entity != NULL && entity->forbid_dml) {
        CT_THROW_ERROR(ERR_CONSTRAINT_VIOLATED);
        return CT_ERROR;
    }

    heap_t *heap = CURSOR_HEAP(cursor);
    SEG_STATS_RECORD(se, seg_stat, &heap->stat);
    if (knl_need_insert_appendix(cursor)) {
        knl_handle_t org_index = cursor->index;
        uint8 org_index_slot = cursor->index_slot;
        if (knl_insert_appendix(session, cursor) != CT_SUCCESS) {
            knl_rollback(session, &save_point);
            knl_restore_cursor_index(cursor, org_index, org_index_slot);
            return CT_ERROR;
        }

        knl_restore_cursor_index(cursor, org_index, org_index_slot);
    }

    if (entity != NULL && STATS_ENABLE_MONITOR_TABLE((knl_session_t *)session)) {
        stats_monitor_table_change(cursor);
    }

    if (SECUREC_UNLIKELY(cursor->rowid_count > 0)) {
        cursor->rowid_count = 0;
    }

    return CT_SUCCESS;
}

status_t knl_delete(knl_handle_t session, knl_cursor_t *cursor)
{
    return knl_internal_delete(session, cursor);
}

status_t knl_internal_delete(knl_handle_t handle, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)handle;
    uint32 i;
    table_t *table;
    index_t *index = NULL;
    knl_savepoint_t savepoint;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    index_set_t *index_set = NULL;
    seg_stat_t temp_stat;
    heap_t *heap = CURSOR_HEAP(cursor);
    btree_t *btree = NULL;

    table = (table_t *)cursor->table;
    index_set = &table->index_set;

    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_KNL_INTERNAL_DELETE, &tv_begin);

    if (!cursor->is_valid) {
        CT_THROW_ERROR(ERR_INVALID_CURSOR);
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INTERNAL_DELETE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    SEG_STATS_INIT(session, &temp_stat);
    knl_savepoint(session, &savepoint);

    if (TABLE_ACCESSOR(cursor)->do_delete(session, cursor) != CT_SUCCESS) {
        knl_rollback(session, &savepoint);
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INTERNAL_DELETE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    SEG_STATS_RECORD(session, temp_stat, &heap->stat);
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);

    if (SECUREC_UNLIKELY(!cursor->is_found)) {
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INTERNAL_DELETE, &tv_begin, IO_STAT_SUCCESS);
        return CT_SUCCESS;
    }

    uint8 org_index_slot = cursor->index_slot;
    knl_handle_t org_index = cursor->index;

    for (i = 0; i < index_set->total_count; i++) {
        cursor->index_slot = i;
        index = index_set->items[i];
        cursor->index = index;

        if (IS_PART_INDEX(cursor->index)) {
            knl_panic_log(cursor->part_loc.part_no != CT_INVALID_ID32,
                          "the part_no record on cursor is invalid, "
                          "panic info: table %s index %s",
                          table->desc.name, ((index_t *)cursor->index)->desc.name);
            index_part_t *index_part = INDEX_GET_PART(cursor->index, cursor->part_loc.part_no);
            if (IS_PARENT_IDXPART(&index_part->desc)) {
                knl_panic_log(cursor->part_loc.subpart_no != CT_INVALID_ID32,
                              "the subpart_no record on cursor is "
                              "invalid, panic info: table %s index %s",
                              table->desc.name, ((index_t *)cursor->index)->desc.name);
                index_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[cursor->part_loc.subpart_no]);
            }
            cursor->index_part = index_part;
        }
        btree = CURSOR_BTREE(cursor);
        SEG_STATS_INIT(session, &temp_stat);

        if (knl_delete_index_key(session, cursor) != CT_SUCCESS) {
            knl_rollback(session, &savepoint);
            knl_restore_cursor_index(cursor, org_index, org_index_slot);
            cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INTERNAL_DELETE, &tv_begin, IO_STAT_FAILED);
            return CT_ERROR;
        }
        SEG_STATS_RECORD(session, temp_stat, &btree->stat);
    }

    if (entity != NULL && entity->forbid_dml) {
        knl_rollback(session, &savepoint);
        CT_THROW_ERROR(ERR_CONSTRAINT_VIOLATED);
        knl_restore_cursor_index(cursor, org_index, org_index_slot);
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INTERNAL_DELETE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(table->shadow_index != NULL)) {
        if (knl_update_shadow_index(session, cursor, table->shadow_index, CURSOR_ACTION_DELETE) != CT_SUCCESS) {
            knl_rollback(session, &savepoint);
            knl_restore_cursor_index(cursor, org_index, org_index_slot);
            cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INTERNAL_DELETE, &tv_begin, IO_STAT_FAILED);
            return CT_ERROR;
        }
    }

    knl_restore_cursor_index(cursor, org_index, org_index_slot);

    if (entity != NULL && STATS_ENABLE_MONITOR_TABLE(session)) {
        stats_monitor_table_change(cursor);
    }

    cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INTERNAL_DELETE, &tv_begin, IO_STAT_SUCCESS);
    return CT_SUCCESS;
}

status_t knl_update(knl_handle_t session, knl_cursor_t *cursor)
{
    if (cursor->vnc_column != NULL) {
        CT_THROW_ERROR(ERR_COLUMN_NOT_NULL, cursor->vnc_column);
        return CT_ERROR;
    }

    return knl_internal_update(session, cursor);
}

status_t knl_internal_update(knl_handle_t session, knl_cursor_t *cursor)
{
    uint32 i;
    table_t *table;
    index_t *index = NULL;
    knl_savepoint_t savepoint;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    index_set_t *index_set = NULL;
    seg_stat_t temp_stat;
    heap_t *heap = CURSOR_HEAP(cursor);
    btree_t *btree = NULL;
    knl_session_t *se = (knl_session_t *)session;
    knl_part_locate_t new_part_loc;
    table = (table_t *)cursor->table;
    index_set = &table->index_set;
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_KNL_INTERNAL_UPDATE, &tv_begin);

    if (!cursor->is_valid) {
        CT_THROW_ERROR(ERR_INVALID_CURSOR);
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INTERNAL_UPDATE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    knl_savepoint(session, &savepoint);
    SEG_STATS_INIT(se, &temp_stat);

    /* check if it's need to do update overpart, if need, the new part no is stored in variable new_part_no */
    new_part_loc.part_no = CT_INVALID_ID32;
    new_part_loc.subpart_no = CT_INVALID_ID32;

    if (!IS_COMPATIBLE_MYSQL_INST) {
        if (IS_PART_TABLE(table) && part_prepare_crosspart_update(se, cursor, &new_part_loc) != CT_SUCCESS) {
            cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INTERNAL_UPDATE, &tv_begin, IO_STAT_FAILED);
            return CT_ERROR;
        }

        if (part_check_update_crosspart(&new_part_loc, &cursor->part_loc)) {
            bool32 is_new_part_csf = knl_is_table_csf(entity, new_part_loc);
            bool32 is_old_part_csf = knl_is_table_csf(entity, cursor->part_loc);
            if (is_new_part_csf != is_old_part_csf) {
                knl_rollback(session, &savepoint);
                CT_THROW_ERROR(ERR_INVALID_OPERATION,
                               ", cross partition update between different partition row types are forbidden");
                cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INTERNAL_UPDATE, &tv_begin, IO_STAT_FAILED);
                return CT_ERROR;
            }
            if (knl_crosspart_update(se, cursor, new_part_loc) != CT_SUCCESS) {
                knl_rollback(session, &savepoint);
                cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INTERNAL_UPDATE, &tv_begin, IO_STAT_FAILED);
                return CT_ERROR;
            }
            cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INTERNAL_UPDATE, &tv_begin, IO_STAT_SUCCESS);
            return CT_SUCCESS;
        }
    }

    if (TABLE_ACCESSOR(cursor)->do_update(session, cursor) != CT_SUCCESS) {
        knl_rollback(session, &savepoint);
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INTERNAL_UPDATE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    SEG_STATS_RECORD(se, temp_stat, &heap->stat);

    uint8 org_index_slot = cursor->index_slot;
    knl_handle_t org_index = cursor->index;

    for (i = 0; i < index_set->total_count; i++) {
        index = index_set->items[i];
        cursor->index_slot = i;
        cursor->index = index;

        if (IS_PART_INDEX(cursor->index)) {
            knl_panic_log(cursor->part_loc.part_no != CT_INVALID_ID32,
                          "the part_no record on cursor is invalid, "
                          "panic info: table %s index %s",
                          table->desc.name, ((index_t *)cursor->index)->desc.name);
            index_part_t *index_part = INDEX_GET_PART(cursor->index, cursor->part_loc.part_no);
            if (IS_PARENT_IDXPART(&index_part->desc)) {
                knl_panic_log(cursor->part_loc.subpart_no != CT_INVALID_ID32,
                              "the subpart_no record on cursor is "
                              "invalid, panic info: table %s index %s",
                              table->desc.name, ((index_t *)cursor->index)->desc.name);
                index_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[cursor->part_loc.subpart_no]);
            }
            cursor->index_part = index_part;
        }

        btree = CURSOR_BTREE(cursor);
        SEG_STATS_INIT(se, &temp_stat);

        if (knl_update_index_key(session, cursor) != CT_SUCCESS) {
            knl_rollback(session, &savepoint);
            knl_restore_cursor_index(cursor, org_index, org_index_slot);
            cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INTERNAL_UPDATE, &tv_begin, IO_STAT_FAILED);
            return CT_ERROR;
        }
        SEG_STATS_RECORD(se, temp_stat, &btree->stat);
    }

    if (entity != NULL && entity->forbid_dml) {
        knl_rollback(session, &savepoint);
        CT_THROW_ERROR(ERR_CONSTRAINT_VIOLATED);
        knl_restore_cursor_index(cursor, org_index, org_index_slot);
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INTERNAL_UPDATE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    if (table->cons_set.check_count > 0) {
        for (i = 0; i < table->cons_set.check_count; i++) {
            if (knl_verify_check_cons(se, cursor, table->cons_set.check_cons[i]) != CT_SUCCESS) {
                knl_rollback(session, &savepoint);
                knl_restore_cursor_index(cursor, org_index, org_index_slot);
                cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INTERNAL_UPDATE, &tv_begin, IO_STAT_FAILED);
                return CT_ERROR;
            }
        }
    }

    if (table->shadow_index != NULL) {
        if (knl_update_shadow_index(se, cursor, table->shadow_index, CURSOR_ACTION_UPDATE) != CT_SUCCESS) {
            knl_rollback(session, &savepoint);
            knl_restore_cursor_index(cursor, org_index, org_index_slot);
            cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INTERNAL_UPDATE, &tv_begin, IO_STAT_FAILED);
            return CT_ERROR;
        }
    }

    knl_restore_cursor_index(cursor, org_index, org_index_slot);

    if (entity != NULL && STATS_ENABLE_MONITOR_TABLE(se)) {
        stats_monitor_table_change(cursor);
    }

    cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_INTERNAL_UPDATE, &tv_begin, IO_STAT_SUCCESS);
    return CT_SUCCESS;
}

status_t knl_crosspart_update(knl_handle_t se, knl_cursor_t *cursor, knl_part_locate_t new_part_loc)
{
    row_head_t *old_row = NULL;
    row_head_t *new_row = NULL;
    knl_handle_t old_index_part = NULL;
    rowid_t old_rowid;
    knl_session_t *session = (knl_session_t *)se;

    knl_part_locate_t old_part_loc = cursor->part_loc;
    old_row = cursor->row;
    old_index_part = cursor->index_part;
    ROWID_COPY(old_rowid, cursor->rowid);
    CM_SAVE_STACK(session->stack);
    new_row = (row_head_t *)cm_push(session->stack, CT_MAX_ROW_SIZE);

    /* delete old row from the old part */
    if (knl_internal_delete(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    /* if row has been deleted by current stmt, we should return error, because we are updating row */
    if (SECUREC_UNLIKELY(!cursor->is_found)) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_ROW_SELF_UPDATED);
        return CT_ERROR;
    }

    /* reorganize new row and copy lob data into new part */
    if (heap_prepare_update_overpart(session, cursor, new_row, new_part_loc) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    /* insert the new row into the new part */
    cursor->row = new_row;
    if (knl_internal_insert(session, cursor) != CT_SUCCESS) {
        ROWID_COPY(cursor->rowid, old_rowid);
        cursor->row = old_row;
        knl_set_table_part(cursor, old_part_loc);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    ROWID_COPY(cursor->rowid, old_rowid);
    cursor->row = old_row;
    knl_set_table_part(cursor, old_part_loc);
    cursor->index_part = old_index_part;
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t knl_fetch_by_rowid(knl_handle_t session, knl_cursor_t *cursor, bool32 *is_found)
{
    if (cursor->isolevel == ISOLATION_CURR_COMMITTED) {
        cursor->query_scn = DB_CURR_SCN((knl_session_t *)session);
        cursor->cc_cache_time = KNL_NOW((knl_session_t *)session);
    }

    if (TABLE_ACCESSOR(cursor)->do_fetch_by_rowid(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *is_found = cursor->is_found;

    return CT_SUCCESS;
}

status_t knl_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    if (cursor->eof) {
        return CT_SUCCESS;
    }

    if (!cursor->is_valid) {
        CT_THROW_ERROR(ERR_INVALID_CURSOR);
        return CT_ERROR;
    }

    return cursor->fetch(session, cursor);
}

/*
 * kernel copy row
 * copy cursor row to dest cursor row
 * @note lob locator data would be re-generated and lob chunk data would be copied to
 * @param kernel session, src cursor, dest cursor
 */
status_t knl_copy_row(knl_handle_t handle, knl_cursor_t *src, knl_cursor_t *dest)
{
    knl_session_t *session = (knl_session_t *)handle;
    dc_entity_t *entity = (dc_entity_t *)src->dc_entity;
    dc_entity_t *mentity = (dc_entity_t *)dest->dc_entity;
    row_head_t *row = src->row;
    knl_column_t *column = NULL;
    row_assist_t ra;
    uint16 i;
    knl_put_row_column_t put_col_func = row->is_csf ? heap_put_csf_row_column : heap_put_bmp_row_column;

    lob_locator_t *locator = NULL;

    cm_row_init(&ra, (char *)dest->row, KNL_MAX_ROW_SIZE(session), ROW_COLUMN_COUNT(row), row->is_csf);

    for (i = 0; i < ROW_COLUMN_COUNT(row); i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column) || CURSOR_COLUMN_SIZE(src, i) == CT_NULL_VALUE_LEN) {
            put_col_func(row, src->offsets, src->lens, i, &ra);
            continue;
        }

        locator = (lob_locator_t *)CURSOR_COLUMN_DATA(src, i);
        if (knl_row_move_lob(session, dest, dc_get_column(mentity, i), locator, &ra) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    row_end(&ra);

    return CT_SUCCESS;
}

/*
 * kernel lock row interface
 * lock the cursor row just fetched by cursor rowid
 * @note transaction wait maybe heap during locking, caller must set the correct
 * cursor action 'cause the lock behavior is different depending on cursor action.
 * @param session handle, kernel cursor, is_found(result)
 */
status_t knl_lock_row(knl_handle_t session, knl_cursor_t *cursor, bool32 *is_found)
{
    *is_found = CT_FALSE;

    if (cursor->eof) {
        return CT_SUCCESS;
    }

    if (!cursor->is_valid) {
        CT_THROW_ERROR(ERR_INVALID_CURSOR);
        return CT_ERROR;
    }

    if (cursor->action <= CURSOR_ACTION_SELECT) {
        CT_THROW_ERROR(ERR_INVALID_CURSOR);
        return CT_ERROR;
    }

    /* can't lock non-existent row */
    if (!cursor->is_found) {
        return CT_SUCCESS;
    }

    if (TABLE_ACCESSOR(cursor)->do_lock_row(session, cursor, &cursor->is_found) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *is_found = cursor->is_found;
    return CT_SUCCESS;
}

knl_column_t *knl_get_column(knl_handle_t dc_entity, uint32 id)
{
    return dc_get_column((dc_entity_t *)dc_entity, id);
}

knl_table_desc_t *knl_get_table(knl_dictionary_t *dc)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    return &entity->table.desc;
}

status_t knl_get_view_sub_sql(knl_handle_t session, knl_dictionary_t *dc, text_t *sql, uint32 *page_id)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    knl_session_t *knl_session = (knl_session_t *)session;

    *page_id = CT_INVALID_ID32;

    if (entity->view.sub_sql.str != NULL) {
        *sql = entity->view.sub_sql;
        return CT_SUCCESS;
    }

    if (entity->view.sub_sql.len + 1 >= CT_LARGE_PAGE_SIZE) {
        return CT_ERROR;
    }

    knl_begin_session_wait(knl_session, LARGE_POOL_ALLOC, CT_FALSE);
    if (mpool_alloc_page_wait(knl_session->kernel->attr.large_pool, page_id, CM_MPOOL_ALLOC_WAIT_TIME) != CT_SUCCESS) {
        knl_end_session_wait(knl_session, LARGE_POOL_ALLOC);
        return CT_ERROR;
    }
    knl_end_session_wait(knl_session, LARGE_POOL_ALLOC);

    sql->len = entity->view.sub_sql.len;
    sql->str = mpool_page_addr(knl_session->kernel->attr.large_pool, *page_id);

    if (knl_read_lob(session, entity->view.lob, 0, sql->str, sql->len + 1, NULL, NULL) != CT_SUCCESS) {
        mpool_free_page(knl_session->kernel->attr.large_pool, *page_id);
        *page_id = CT_INVALID_ID32;
        return CT_ERROR;
    }

    sql->str[sql->len] = '\0';
    return CT_SUCCESS;
}

dynview_desc_t *knl_get_dynview(knl_dictionary_t *dc)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    return entity->dview;
}

/*
 * Get the serial cached value from a table's dc_entity
 */
status_t knl_get_serial_cached_value(knl_handle_t session, knl_handle_t dc_entity, int64 *value)
{
    dc_entry_t *entry = NULL;
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    if (entity->has_serial_col != CT_TRUE) {
        CT_THROW_ERROR(ERR_NO_AUTO_INCREMENT_COLUMN);
        return CT_ERROR;
    }

    if (entity->type == DICT_TYPE_TEMP_TABLE_SESSION || entity->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        knl_temp_cache_t *temp_table = NULL;

        if (knl_ensure_temp_cache(session, entity, &temp_table) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (temp_table->serial == 0) {
            temp_table->serial = entity->table.desc.serial_start;
        }
        *value = temp_table->serial;
        return CT_SUCCESS;
    }

    if (entity->table.heap.segment == NULL) {
        *value = entity->table.desc.serial_start;
        return CT_SUCCESS;
    }

    entry = entity->entry;
    dls_spin_lock(session, &entry->serial_lock, NULL);
    *value = HEAP_SEGMENT(session, entity->table.heap.entry, entity->table.heap.segment)->serial;
    dls_spin_unlock(session, &entry->serial_lock);

    return CT_SUCCESS;
}

status_t knl_get_serial_value(knl_handle_t handle, knl_handle_t dc_entity, uint64 *value)
{
    uint32 residue = 1;
    knl_session_t *session = (knl_session_t *)handle;
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    dc_entry_t *entry = entity->entry;

    if (lock_table_shared(session, dc_entity, LOCK_INF_WAIT) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (entity->type == DICT_TYPE_TEMP_TABLE_SESSION || entity->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        knl_temp_cache_t *temp_table = NULL;

        if (knl_ensure_temp_cache(session, entity, &temp_table) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (temp_table->serial == 0) {
            temp_table->serial = entity->table.desc.serial_start;
            if (temp_table->serial == 0) {
                temp_table->serial++;
            }
        }
        *value = temp_table->serial++;
        return CT_SUCCESS;
    }

    if (entity->table.heap.segment == NULL) {
        if (heap_create_entry(session, &entity->table.heap) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    dls_spin_lock(session, &entry->serial_lock, NULL);

    if (entry->version != session->kernel->dc_ctx.version) {
        entry->serial_value = 0;
        entry->version = session->kernel->dc_ctx.version;
    }

    // int64 segment_serial = HEAP_SEGMENT(session, entity->table.heap.entry, entity->table.heap.segment)->serial;

    if (entry->serial_value == 0) {
        entry->serial_value = HEAP_SEGMENT(session, entity->table.heap.entry, entity->table.heap.segment)->serial;

        if (entry->serial_value == 0) {
            entry->serial_value = 1;
        }
    }

    if (entity->table.desc.serial_start == 0) {
        residue = 1;
    } else {
        residue = 0;
    }

    *value = entry->serial_value;
    if (*value == CT_INVALID_ID64) {
        dls_spin_unlock(session, &entry->serial_lock);
        return CT_SUCCESS;
    }

    if (*value >= CT_INVALID_ID64 - CT_SERIAL_CACHE_COUNT) {
        if (CT_INVALID_ID64 != HEAP_SEGMENT(session, entity->table.heap.entry, entity->table.heap.segment)->serial) {
            heap_update_serial(session, &entity->table.heap, CT_INVALID_ID64);
        }
    } else if ((entry->serial_value - entity->table.desc.serial_start) % CT_SERIAL_CACHE_COUNT == residue) {
        heap_increase_serial(session, &entity->table.heap);
        entry->serial_value = HEAP_SEGMENT(session, entity->table.heap.entry, entity->table.heap.segment)->serial - CT_SERIAL_CACHE_COUNT;
        *value = entry->serial_value;
    }

    entry->serial_value++;

    dls_spin_unlock(session, &entry->serial_lock);

    return CT_SUCCESS;
}

status_t knl_get_serial_value_tmp_table(knl_handle_t se, knl_handle_t dc_entity, uint64 *value,
    uint16 auto_inc_step, uint16 auto_inc_offset, bool32 is_change)
{
    knl_session_t *session = (knl_session_t *)se;
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    knl_temp_cache_t *temp_table = NULL;

    if (knl_ensure_temp_cache(session, entity, &temp_table) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("get temp cache failed!");
        return CT_ERROR;
    }
    if (temp_table->serial >= CT_INVALID_ID64 - auto_inc_step ||
        entity->table.desc.serial_start >= CT_INVALID_ID64 - auto_inc_step) {
        CT_LOG_RUN_ERR("serial value exceeded the maximum!");
        return CT_ERROR;
    }
    knl_cal_serial_value_4mysql(temp_table->serial, value, entity->table.desc.serial_start, auto_inc_step,
        auto_inc_offset);
    if (is_change) {
        temp_table->serial = *value;
    }
    return CT_SUCCESS;
}

void knl_cal_serial_value_4mysql(uint64 prev_id, uint64 *curr_id, uint64 start_val, uint16 step, uint16 offset)
{
    if (step == 1) { // auto_increment_increment, step = 1
        *curr_id = prev_id + 1;
        if (*curr_id < start_val) {
            *curr_id = start_val;
        }
    } else {
        *curr_id = prev_id + step;
        if (*curr_id <= offset) {
            *curr_id = offset;
        } else if (*curr_id <= start_val) {
            *curr_id = AUTO_INCREMENT_VALUE(start_val, offset, step);
        } else {
            *curr_id = AUTO_INCREMENT_VALUE(*curr_id, offset, step);
        }
    }
    return ;
}

void knl_first_serial_value_4mysql(uint64 *curr_id, uint64 start_val, uint16 step, uint16 offset)
{
    if (offset < start_val) {
        *curr_id = AUTO_INCREMENT_VALUE(start_val, offset, step);
    } else {
        *curr_id = offset;
    }
}

void knl_heap_update_serial_value(knl_session_t *session, dc_entity_t *entity, uint64 *value, uint16 step,
                                  uint16 offset)
{
    uint64 segment_serial = HEAP_SEGMENT(session, entity->table.heap.entry, entity->table.heap.segment)->serial;
    uint64 update_serial_value = *value > segment_serial ? *value : segment_serial;
    *value = AUTO_INCREMENT_VALUE(update_serial_value, offset, step);
    uint64 residue = (update_serial_value == 0) ? 0 : 1;
    heap_update_serial(session, &entity->table.heap, DC_CACHED_SERIAL_VALUE(*value, residue));
}

void knl_init_serial_value(knl_session_t *session, dc_entity_t *entity, uint64 *value, uint16 auto_inc_step,
                           uint16 auto_inc_offset)
{
    dc_entry_t *entry = entity->entry;
    knl_first_serial_value_4mysql(value, entity->table.desc.serial_start, auto_inc_step, auto_inc_offset);
    knl_heap_update_serial_value(session, entity, value, auto_inc_step, auto_inc_offset);
    entry->serial_value = *value;
}

// If the current entry->serial_value is larger than the pre-allocated segment_serial
// we need to update the pre-allocated segment_serial
status_t knl_get_serial_value_4mysql(knl_handle_t handle, knl_handle_t dc_entity, uint64 *value, uint16 auto_inc_step,
                                       uint16 auto_inc_offset)
{
    knl_session_t *session = (knl_session_t *)handle;
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    dc_entry_t *entry = entity->entry;
    uint64 start_val = entity->table.desc.serial_start;
    if (lock_table_shared(session, dc_entity, LOCK_INF_WAIT) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (entity->type == DICT_TYPE_TEMP_TABLE_SESSION || entity->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        return knl_get_serial_value_tmp_table(session, entity, value, auto_inc_step, auto_inc_offset, CT_TRUE);
    }

    if (entity->table.heap.segment == NULL) {
        if (heap_create_entry(session, &entity->table.heap) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    dls_spin_lock(session, &entry->serial_lock, NULL);
    if (entry->version != session->kernel->dc_ctx.version) {
        entry->serial_value = 0;
        entry->version = session->kernel->dc_ctx.version;
    }
    if (entry->serial_value == 0) {
        knl_init_serial_value(session, entity, value, auto_inc_step, auto_inc_offset);
        dls_spin_unlock(session, &entry->serial_lock);
        return CT_SUCCESS;
    }

    if (entry->serial_value >= CT_INVALID_ID64 - auto_inc_step) {
        *value = CT_INVALID_ID64;
        dls_spin_unlock(session, &entry->serial_lock);
        return CT_SUCCESS;
    }

    knl_cal_serial_value_4mysql(entry->serial_value, value, start_val, auto_inc_step, auto_inc_offset);
    if (*value >= CT_INVALID_ID64 - CT_SERIAL_CACHE_COUNT) {
        if (CT_INVALID_ID64 != HEAP_SEGMENT(session, entity->table.heap.entry, entity->table.heap.segment)->serial) {
            heap_update_serial(session, &entity->table.heap, CT_INVALID_ID64);
        }
    } else if ((*value - 1) / CT_SERIAL_CACHE_COUNT >
               (entry->serial_value - 1) / CT_SERIAL_CACHE_COUNT) {
        knl_heap_update_serial_value(session, entity, value, auto_inc_step, auto_inc_offset);
    }
    entry->serial_value = *value;
    dls_spin_unlock(session, &entry->serial_lock);
    return CT_SUCCESS;
}

status_t knl_reset_serial_value(knl_handle_t handle, knl_handle_t dc_entity)
{
    knl_session_t *session = (knl_session_t *)handle;
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    dc_entry_t *entry = entity->entry;

    if (lock_table_shared(session, dc_entity, LOCK_INF_WAIT) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (entity->type == DICT_TYPE_TEMP_TABLE_SESSION || entity->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        knl_temp_cache_t *temp_table = NULL;

        if (knl_ensure_temp_cache(session, entity, &temp_table) != CT_SUCCESS) {
            return CT_ERROR;
        }

        temp_table->serial = entity->table.desc.serial_start;
        return CT_SUCCESS;
    }

    dls_spin_lock(session, &entry->serial_lock, NULL);
    
    if (IS_COMPATIBLE_MYSQL_INST) {
        if (db_update_table_increment_start(session, &entity->table.desc, 0) != CT_SUCCESS) {
            dls_spin_unlock(session, &entry->serial_lock);
            return CT_ERROR;
        }
        entity->table.desc.serial_start = 0;
    }

    entry->serial_value = entity->table.desc.serial_start;
    if (entity->table.heap.segment != NULL) {
        heap_update_serial(session, &entity->table.heap, entity->table.desc.serial_start);
    }
    dls_spin_unlock(session, &entry->serial_lock);

    return CT_SUCCESS;
}

uint32 knl_get_column_count(knl_handle_t dc_entity)
{
    return ((dc_entity_t *)dc_entity)->column_count;
}

uint16 knl_get_column_id(knl_dictionary_t *dc, text_t *name)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    knl_column_t *column = NULL;
    uint32 hash;
    uint16 index;
    char column_name[CT_NAME_BUFFER_SIZE];

    (void)cm_text2str(name, column_name, CT_NAME_BUFFER_SIZE);
    hash = cm_hash_column_name(column_name, strlen(column_name), entity->column_count, IS_COMPATIBLE_MYSQL_INST);
    index = DC_GET_COLUMN_INDEX(entity, hash);

    while (index != CT_INVALID_ID16) {
        column = dc_get_column(entity, index);
        if (IS_COMPATIBLE_MYSQL_INST) {
            if (cm_strcmpi(column->name, column_name) == 0) {
                return index;
            }
        } else {
            if (strcmp(column->name, column_name) == 0) {
                return index;
            }
        }

        index = column->next;
    }

    return CT_INVALID_ID16;
}

uint32 knl_get_index_count(knl_handle_t dc_entity)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;

    if (!(entity->type == DICT_TYPE_TABLE || entity->type == DICT_TYPE_TEMP_TABLE_SESSION ||
          entity->type == DICT_TYPE_TEMP_TABLE_TRANS || entity->type == DICT_TYPE_TABLE_NOLOGGING)) {
        return 0;
    }

    return entity->table.index_set.count;
}

knl_index_desc_t *knl_get_index(knl_handle_t dc_entity, uint32 index_id)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    index_set_t *index_set;

    index_set = &entity->table.index_set;
    return &(index_set->items[index_id]->desc);
}

static status_t knl_create_table_handle_ref_cons(knl_session_t *session, knl_table_def_t *def, table_t *table,
                                                 bool32 is_referenced)
{
    knl_constraint_def_t *cons = NULL;
    knl_reference_def_t *ref = NULL;

    if (db_invalidate_children_for_update_ref_cons(session, is_referenced, table) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DB]create table %s fail when handle ref cons", def->name.str);
        return CT_ERROR;
    }

    /* unlock parent tables of references constraints */
    for (uint32 i = 0; i < def->constraints.count; i++) {
        cons = (knl_constraint_def_t *)cm_galist_get(&def->constraints, i);
        if (cons->type != CONS_TYPE_REFERENCE) {
            continue;
        }

        ref = &cons->ref;

        if (ref->ref_dc.handle != NULL) {
            dc_invalidate(session, (dc_entity_t *)ref->ref_dc.handle);
            dc_invalidate_remote(session, (dc_entity_t *)ref->ref_dc.handle);
            dc_close(&ref->ref_dc);
        }
    }
    return CT_SUCCESS;
}

static status_t knl_lock_table_when_create(knl_session_t *session, knl_table_def_t *def, table_t *table)
{
    if (def->create_as_select) {
        dc_user_t *user = NULL;
        dc_entry_t *entry = NULL;
        if (dc_open_user(session, &def->schema, &user) != CT_SUCCESS) {
            return CT_ERROR;
        }

        entry = DC_GET_ENTRY(user, table->desc.id);
        if (dc_try_lock_table_ux(session, entry) != CT_SUCCESS) {
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }
    if (def->is_mysql_copy) {
        knl_dictionary_t dc;
        if (dc_open_table_private(session, table->desc.uid, table->desc.id, &dc) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (lock_table_directly(session, &dc, session->kernel->attr.ddl_lock_timeout) != CT_SUCCESS) {
            dc_close_table_private(&dc);
            return CT_ERROR;
        }
        dc_close_table_private(&dc);
        return CT_SUCCESS;
    }
    return CT_SUCCESS;
}

static status_t knl_create_table_log_put(knl_session_t *se, knl_handle_t stmt, knl_table_def_t *def, table_t *table)
{
    rd_create_table_t redo;

    redo.op_type = RD_CREATE_TABLE;
    redo.uid = table->desc.uid;
    redo.oid = table->desc.id;
    redo.org_scn = table->desc.org_scn;
    redo.chg_scn = table->desc.chg_scn;
    redo.type = table->desc.type;
    errno_t ret = strcpy_sp(redo.obj_name, CT_NAME_BUFFER_SIZE, table->desc.name);
    knl_securec_check(ret);
    log_put(se, RD_LOGIC_OPERATION, &redo, sizeof(rd_create_table_t), LOG_ENTRY_FLAG_NONE);
    if (db_write_ddl_op_for_constraints(se, table->desc.uid, table->desc.id, &def->constraints) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DB]create table %s fail when log_put", def->name.str);
        return CT_ERROR;
    }
    // for mysql copy, do not add_lrep_ddl_info here to avoid duplicate sql,
    // we only add one sql text in the step of drop table during mysql copy
    if (!def->is_mysql_copy) {
        log_add_lrep_ddl_info(se, stmt, LOGIC_OP_TABLE, RD_CREATE_TABLE, table);
    }
    return CT_SUCCESS;
}

status_t knl_create_table_log_put4mysql(knl_handle_t session, knl_handle_t stmt, knl_table_def_t *def,
    knl_dictionary_t *dc)
{
    knl_session_t *se = (knl_session_t *)session;
    table_t *table = DC_TABLE(dc);
    return knl_create_table_log_put(se, stmt, def, table);
}

static status_t knl_record_temp_table4mysql(knl_session_t *session, knl_table_def_t *def, table_t *table)
{
    knl_cursor_t* cursor = NULL;
    row_assist_t ra;
    uint32 max_size = session->kernel->attr.max_row_size;

    if (!DB_ATTR_COMPATIBLE_MYSQL(session) || !(def->is_mysql_copy || def->create_as_select)) {
        return CT_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_GARBAGE_TABLE_ID, IX_SYS_GARBAGE_TABLE001_ID);
    row_init(&ra, (char *)cursor->row, max_size, SYS_GARBAGE_TABLE_COLS);
    (void)row_put_int32(&ra, table->desc.uid);
    (void)row_put_text(&ra, &def->name);

    if (knl_internal_insert(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        CT_LOG_RUN_ERR("[for mysql]record temp table %s fail when alter table for mysql copy", def->name.str);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

void knl_drop_garbage_table4mysql_copy(knl_handle_t session, knl_drop_def_t *drop_def){
    knl_session_t *se = (knl_session_t *)session;
    dc_user_t *user = NULL;
    if (!DB_ATTR_COMPATIBLE_MYSQL(se)) {
        return;
    }
    if (dc_open_user(se, &drop_def->owner, &user) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("[DB] Open user %s failed when drop grabage table %s for mysql, may leave garbage table",
                       T2S_EX(&drop_def->owner), T2S_EX(&drop_def->name));
        return;
    }
    status_t status = CT_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_ROLLBACK_DROP_GARBAGE_TABLE_FAIL, &status, CT_ERROR);
    status = knl_internal_drop_table(se, NULL, drop_def, CT_TRUE);
    SYNC_POINT_GLOBAL_END;
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_WAR("[DB] Drop garbage table %s failed when rollback for mysql, may leave garbage table",
                       T2S_EX(&drop_def->name));
    }
}

status_t knl_delete_temp_table_record4mysql(knl_handle_t session, knl_table_def_t *def) {
    knl_session_t *se = (knl_session_t *)session;
    dc_user_t *user = NULL;
    if (!DB_ATTR_COMPATIBLE_MYSQL(se) || !(def->is_mysql_copy || def->create_as_select)) {
        return CT_SUCCESS;
    }
    CT_LOG_RUN_WAR("[DB] Delete garbage table %s record when commit for mysql", T2S_EX(&def->name));
    if (dc_open_user(se, &def->schema, &user) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("[DB]Open user %s failed when drop grabage table for mysql, may leave garbage table",
                       T2S_EX(&def->schema));
        return CT_ERROR;
    }
    status_t status = CT_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_DELETE_GARBAGE_TABLE_4COMMIT_FAIL, &status, CT_ERROR);
    status = db_delete_garbage_table_record4mysql(se, &def->name, user->desc.id);
    SYNC_POINT_GLOBAL_END;

    return status;
}

static status_t knl_clean_garbage_table(knl_session_t *session, knl_table_def_t *def, bool32 has_auton_rm)
{
    CT_LOG_RUN_INF("[DB] Clean garbage table %s left by mysql copy or create as select", T2S_EX(&def->name));
    knl_cursor_t* cursor = NULL;
    bool32 is_garbage_table = CT_FALSE;
    dc_user_t *user = NULL;
    if (dc_open_user(session, &def->schema, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }
    uint32 uid = user->desc.id;
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_GARBAGE_TABLE_ID, IX_SYS_GARBAGE_TABLE001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &uid, sizeof(uint32),
        IX_COL_SYS_GARBAGE_TABLE001_UID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, def->name.str,
        (uint16)def->name.len, IX_COL_SYS_GARBAGE_TABLE001_TABLE);
    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    if (!cursor->eof) {
        is_garbage_table = CT_TRUE;
    }
    CM_RESTORE_STACK(session->stack);
    if (is_garbage_table) {
        knl_drop_def_t drop_def = { { 0 } };
        drop_def.purge = CT_TRUE;
        drop_def.name = def->name;
        drop_def.owner = def->schema;
        def->options = DROP_NO_CHECK_FK;
        if (!has_auton_rm && knl_begin_auton_rm(session) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (knl_internal_drop_table(session, NULL, &drop_def, CT_TRUE) != CT_SUCCESS) {
            knl_end_auton_rm(session, CT_ERROR);
            return CT_ERROR;
        }
        if (!has_auton_rm) {
            knl_end_auton_rm(session, CT_SUCCESS);
        }
    }
    return CT_SUCCESS;
}

static void knl_end_create_table_rm(knl_session_t *session, bool32 need_commit, status_t status)
{
    if (!need_commit) {
        return;
    }
    unlock_tables_directly(session);
    return knl_end_auton_rm(session, status);
}

bool32 knl_create_table_check_exist(knl_handle_t session, knl_table_def_t *def, bool32 has_auton_rm)
{
    knl_session_t *se = (knl_session_t *)session;
    bool32 is_existed = CT_FALSE;
    knl_dict_type_t obj_type;
    // failed mysql copy or create_as_select may leave garbage table, clean it first;
    if (dc_object_exists(se, &def->schema, &def->name, &obj_type) &&
        knl_clean_garbage_table(se, def, has_auton_rm) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("[DB]clean garbage table with same name failed when db_create_table %s", def->name.str);
    }
    if ((def->options & CREATE_IF_NOT_EXISTS) && dc_object_exists(se, &def->schema, &def->name, &obj_type)) {
        if (IS_TABLE_BY_TYPE(obj_type)) {
            is_existed = CT_TRUE;
        }
    }
    return is_existed;
}

static status_t knl_create_table_commit(knl_session_t *session, knl_handle_t stmt, knl_table_def_t *def, table_t *table,
    bool32 is_auton_rm)
{
    status_t status = CT_SUCCESS;
    // for mysql copy, add this temp table to systable: garbage table, do that we can drop it when copy fail
    status = knl_record_temp_table4mysql(session, def, table);
    if (status == CT_SUCCESS) {
        status = knl_create_table_log_put(session, stmt, def, table);
    }

    log_add_lrep_ddl_end(session);
    if (status != CT_SUCCESS) {
        if (is_auton_rm) {
            knl_end_create_table_rm (session, is_auton_rm, status);
        } else {
            knl_rollback(session, NULL);
        }
        dc_free_broken_entry(session, table->desc.uid, table->desc.id);
        return CT_ERROR;
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_CREATE_TABLE_BEFORE_SYNC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    knl_commit(session);
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_CREATE_TABLE_AFTER_SYNC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return status;
}

static status_t knl_internal_create_table(knl_session_t *session, knl_handle_t stmt, knl_table_def_t *def,
    bool32 *is_existed)
{
    table_t table;

    *is_existed = knl_create_table_check_exist(session, def, CT_FALSE);
    if (*is_existed) {
        return CT_SUCCESS;
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_MEMORY_LEAK, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    log_add_lrep_ddl_begin(session);
    bool32 is_referenced = CT_FALSE;
    status_t status = CT_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_CREATE_TABLE_FAIL, &status, CT_ERROR);
    status = db_create_table(session, def, &table, &is_referenced);
    SYNC_POINT_GLOBAL_END;
    if (status != CT_SUCCESS) {
        log_add_lrep_ddl_end(session);
        knl_rollback(session, NULL);
        if (def->options & CREATE_IF_NOT_EXISTS && cm_get_error_code() == ERR_DUPLICATE_TABLE) {
            *is_existed = CT_TRUE;
            cm_reset_error();
            return CT_SUCCESS;
        }
        CT_LOG_RUN_ERR("[DB]create table %s fail when db_create_table", def->name.str);
        return CT_ERROR;
    }

    // create table as select and mysql copy ddl need lock table before dc is ready
    status = knl_lock_table_when_create(session, def, &table);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DB]create table %s fail when lock new table", def->name.str);
        knl_rollback(session, NULL);
        dc_free_broken_entry(session, table.desc.uid, table.desc.id);
        return CT_ERROR;
    }
    if (knl_create_table_commit(session, stmt, def, &table, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_CREATE_TABLE_HANDLE_REFS_FAIL, &status, CT_ERROR);
    status = knl_create_table_handle_ref_cons(session, def, &table, is_referenced);
    SYNC_POINT_GLOBAL_END;

    dc_ready(session, table.desc.uid, table.desc.id);

    CT_LOG_RUN_INF("[DB] Finish to create table %s, uid %u, oid %u, type %d, ret:%d",
                   T2S_EX(&def->name), table.desc.uid, table.desc.id, table.desc.type, status);
    return status;
}

static status_t knl_internal_create_table_no_commit(knl_session_t *session, knl_handle_t stmt, knl_table_def_t *def)
{
    table_t table;
    bool32 need_commit = DB_ATTR_COMPATIBLE_MYSQL(session) && (def->is_mysql_copy || def->create_as_select);
    if (need_commit && knl_begin_auton_rm(session) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DB]begin auton rm fail when db_create_table %s", def->name.str);
        return CT_ERROR;
    }

    if (knl_create_table_check_exist(session, def, need_commit)) {
        knl_end_create_table_rm (session, need_commit, CT_SUCCESS);
        return CT_SUCCESS;
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_MEMORY_LEAK, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    log_add_lrep_ddl_begin(session);
    bool32 is_referenced = CT_FALSE;
    status_t status = CT_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_CREATE_TABLE_FAIL, &status, CT_ERROR);
    status = db_create_table(session, def, &table, &is_referenced);
    SYNC_POINT_GLOBAL_END;
    if (status != CT_SUCCESS) {
        if (need_commit) {
            log_add_lrep_ddl_end(session);
            knl_end_create_table_rm (session, need_commit, status);
        }
        if (def->options & CREATE_IF_NOT_EXISTS && cm_get_error_code() == ERR_DUPLICATE_TABLE) {
            cm_reset_error();
            return CT_SUCCESS;
        }
        CT_LOG_RUN_ERR("[DB]create table %s fail when db_create_table", def->name.str);
        return CT_ERROR;
    }

    if (need_commit && knl_create_table_commit(session, stmt, def, &table, need_commit) != CT_SUCCESS) {
        return CT_ERROR;
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_CREATE_TABLE_HANDLE_REFS_FAIL, &status, CT_ERROR);
    status = knl_create_table_handle_ref_cons(session, def, &table, is_referenced);
    SYNC_POINT_GLOBAL_END;

    knl_end_create_table_rm(session, need_commit, status);

    // create table as select and mysql copy ddl need lock table before dc is ready
    if (status == CT_SUCCESS && knl_lock_table_when_create(session, def, &table) != CT_SUCCESS) {
        status = CT_ERROR;
        CT_LOG_RUN_ERR("[DB]create table %s fail when lock new table", def->name.str);
    }
    dc_ready(session, table.desc.uid, table.desc.id);

    CT_LOG_RUN_INF("[DB] Finish to create table %s, uid %u, oid %u, type %d, ret:%d",
                   T2S_EX(&def->name), table.desc.uid, table.desc.id, table.desc.type, status);
    return status;
}

status_t knl_create_table_as_select(knl_handle_t session, knl_handle_t stmt, knl_table_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;
    drlatch_t *ddl_latch = &se->kernel->db.ddl_latch;
    dc_user_t *user = NULL;
    status_t status;
    bool32 is_exist = CT_FALSE;

    if (knl_ddl_enabled(se, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_open_user(se, &def->schema, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dls_latch_x(session, &user->user_latch, se->id, NULL);
    if (knl_ddl_latch_s(ddl_latch, session, NULL) != CT_SUCCESS) {
        dls_unlatch(session, &user->user_latch, NULL);
        return CT_ERROR;
    }

    if (knl_internal_create_table(se, stmt, def, &is_exist) != CT_SUCCESS) {
        unlock_tables_directly(se);
        dls_unlatch(session, ddl_latch, NULL);
        dls_unlatch(session, &user->user_latch, NULL);
        return CT_ERROR;
    }

    // is_exist is true, hasn't locked the table
    if (is_exist) {
        dls_unlatch(session, ddl_latch, NULL);
        dls_unlatch(session, &user->user_latch, NULL);
        return CT_SUCCESS;
    }

    status = g_knl_callback.import_rows(stmt, BATCH_COMMIT_COUNT);
    if (status != CT_SUCCESS) {
        knl_rollback(se, NULL);
        knl_drop_def_t drop_def = { { 0 } };
        drop_def.purge = CT_TRUE;
        drop_def.name = def->name;
        drop_def.owner = def->schema;
        if (knl_internal_drop_table(se, NULL, &drop_def, CT_TRUE) != CT_SUCCESS) {
            unlock_tables_directly(se);
            dls_unlatch(session, ddl_latch, NULL);
            dls_unlatch(session, &user->user_latch, NULL);
            return CT_ERROR;
        }
    }
    unlock_tables_directly(se);
    dls_unlatch(session, ddl_latch, NULL);
    dls_unlatch(session, &user->user_latch, NULL);
    return status;
}

status_t knl_create_table(knl_handle_t session, knl_handle_t stmt, knl_table_def_t *def)
{
    CT_LOG_RUN_INF("[DB] Start to create table %s", T2S_EX(&def->name));
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_KNL_CREATE_TABLE, &tv_begin);
    knl_session_t *se = (knl_session_t *)session;
    drlatch_t *ddl_latch = &se->kernel->db.ddl_latch;
    dc_user_t *user = NULL;
    status_t status;
    bool32 is_existed = CT_FALSE;

    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_CREATE_TABLE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    if (dc_open_user(se, &def->schema, &user) != CT_SUCCESS) {
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_CREATE_TABLE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    dls_latch_x(session, &user->user_latch, se->id, NULL);
    if (knl_ddl_latch_s(ddl_latch, session, NULL) != CT_SUCCESS) {
        dls_unlatch(session, &user->user_latch, NULL);
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_CREATE_TABLE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    CT_LOG_DEBUG_INF("[DB] Create table %s, get ddl lock", T2S_EX(&def->name));
    status = knl_internal_create_table(session, stmt, def, &is_existed);
    unlock_tables_directly(session);
    dls_unlatch(session, ddl_latch, NULL);
    dls_unlatch(session, &user->user_latch, NULL);

    cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_CREATE_TABLE, &tv_begin, status == CT_SUCCESS ?
                       IO_STAT_SUCCESS : IO_STAT_FAILED);
    CT_LOG_DEBUG_INF("[DB] Finish to create table %s, ret: %d", T2S_EX(&def->name), status);
    return status;
}

status_t knl_create_table4mysql(knl_handle_t session, knl_handle_t stmt, knl_table_def_t *def)
{
    // interface for mysql, create table without commit or rollback,
    // user latch and ddl latch are not locked inside, must lock user and ddl before this interface
    // note the lock sequence: add user lock first and then the ddl lock
    CT_LOG_RUN_INF("[For MYSQL] Start to create table %s without commit", T2S_EX(&def->name));
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_KNL_CREATE_TABLE, &tv_begin);
    knl_session_t *se = (knl_session_t *)session;
    status_t status;

    status = knl_internal_create_table_no_commit(se, stmt, def);

    cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_CREATE_TABLE, &tv_begin, status == CT_SUCCESS ?
                       IO_STAT_SUCCESS : IO_STAT_FAILED);
    CT_LOG_RUN_INF("[For MYSQL] Finish to create table %s without commit, ret: %d", T2S_EX(&def->name), status);
    return status;
}

status_t knl_unlock_users4mysql(knl_handle_t session)
{
    knl_session_t *se = (knl_session_t *)session;
    uint32 *unlock_user_lst = se->user_locked_lst;
    dc_user_t *user = NULL;
    uint32 uid;
    uint32 *unlock_user_lst_size = unlock_user_lst;
    if (unlock_user_lst == NULL || *unlock_user_lst_size == 0) {
        return CT_SUCCESS;
    }

    for (uint32 i = *unlock_user_lst_size; i > 0; i--) {
        uid = unlock_user_lst[i];
        if (dc_open_user_by_id(se, uid, &user) != CT_SUCCESS) {
            knl_panic_log(0, "open user %u failed when unlock users for mysql", uid);
        }

        dls_unlatch(se, &user->user_latch, NULL);
        *unlock_user_lst_size -= 1;
        CT_LOG_RUN_INF("[For MySQL]: unlock user %s success", user->desc.name);
    }

    knl_panic_log(*(se->user_locked_lst) == 0, "user locked lst size is %u", *(se->user_locked_lst));
    se->user_locked_lst = NULL;
    return CT_SUCCESS;
}

status_t knl_create_view(knl_handle_t session, knl_handle_t stmt, knl_view_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;
    dc_user_t *user = NULL;

    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_open_user(se, &def->user, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dls_latch_x(session, &user->user_latch, se->id, NULL);
    if (db_create_view((knl_session_t *)session, stmt, def) != CT_SUCCESS) {
        dls_unlatch(session, &user->user_latch, NULL);
        return CT_ERROR;
    }

    dls_unlatch(session, &user->user_latch, NULL);
    return CT_SUCCESS;
}

status_t knl_create_or_replace_view(knl_handle_t session, knl_handle_t stmt, knl_view_def_t *def)
{
    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return db_create_or_replace_view((knl_session_t *)session, stmt, def);
}

static inline void knl_set_new_space_type(knl_handle_t se, knl_space_def_t *def)
{
    knl_session_t *session = (knl_session_t *)se;
    if (cm_text_equal_ins(&def->name, &g_temp2_undo) && (DB_CORE_CTRL(session)->temp_undo_space == 0)) {
        def->extent_size = UNDO_EXTENT_SIZE;
        def->type = SPACE_TYPE_UNDO | SPACE_TYPE_TEMP | SPACE_TYPE_DEFAULT;
    } else if (cm_text_equal_ins(&def->name, &g_temp2) && (DB_CORE_CTRL(session)->temp_space == 0)) {
        def->type = SPACE_TYPE_TEMP | SPACE_TYPE_USERS | SPACE_TYPE_DEFAULT;
    } else if (cm_text_equal_ins(&def->name, &g_sysaux) && (DB_CORE_CTRL(session)->sysaux_space == 0)) {
        def->type = SPACE_TYPE_SYSAUX | SPACE_TYPE_DEFAULT;
    }
    return;
}

static void knl_save_core_space_type(knl_handle_t se, knl_space_def_t *def, uint32 space_id)
{
    knl_session_t *session = (knl_session_t *)se;
    if (def->type == (SPACE_TYPE_UNDO | SPACE_TYPE_TEMP | SPACE_TYPE_DEFAULT)) {
        undo_context_t *ctx = &session->kernel->undo_ctx;
        ctx->temp_space = spc_get_temp_undo(session);
        DB_CORE_CTRL(session)->temp_undo_space = space_id;
    } else if (def->type == (SPACE_TYPE_TEMP | SPACE_TYPE_USERS | SPACE_TYPE_DEFAULT)) {
        DB_CORE_CTRL(session)->temp_space = space_id;
    } else if (def->type == (SPACE_TYPE_SYSAUX | SPACE_TYPE_DEFAULT)) {
        DB_CORE_CTRL(session)->sysaux_space = space_id;
    } else {
        return;
    }

    if (db_save_core_ctrl(session) != CT_SUCCESS) {
        knl_ddl_unlatch_x(session);
        CM_ABORT(0, "[SPACE] ABORT INFO: save core control space file failed when create space %s", T2S(&(def->name)));
    }

    return;
}

status_t knl_create_space_internal(knl_handle_t session, knl_handle_t stmt, knl_space_def_t *def)
{
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_KNL_CREATE_SPACE, &tv_begin);
    knl_session_t *se = (knl_session_t *)session;
    uint32 space_id;

    if (DB_IS_READONLY(se)) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_CREATE_SPACE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    if (def->in_memory == CT_TRUE) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "create space all in memory");
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_CREATE_SPACE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    knl_set_new_space_type(session, def);

    if (spc_create_space_precheck(se, def) != CT_SUCCESS) {
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_CREATE_SPACE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    log_add_lrep_ddl_begin_4database(se, (!def->is_for_create_db));
    if (spc_create_space(se, def, &space_id) != CT_SUCCESS) {
        log_add_lrep_ddl_end_4database(se, (!def->is_for_create_db));
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_CREATE_SPACE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    log_add_lrep_ddl_info_4database(se, stmt, LOGIC_OP_TABLESPACE, RD_CREATE_TABLE, NULL, (!def->is_for_create_db));
    log_add_lrep_ddl_end_4database(se, (!def->is_for_create_db));

    if (def->type & SPACE_TYPE_DEFAULT) {
        knl_save_core_space_type(session, def, space_id);
    }

    cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_CREATE_SPACE, &tv_begin, IO_STAT_SUCCESS);
    CT_LOG_RUN_INF("[DB] Success to create space, space_id %u", space_id);
    return CT_SUCCESS;
}

status_t knl_create_space(knl_handle_t session, knl_handle_t stmt, knl_space_def_t *def)
{
    status_t status;

    if (knl_ddl_latch_sx(session, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }
    status = knl_create_space_internal(session, stmt, def);
    knl_ddl_unlatch_x(session);
    return status;
}

status_t knl_create_space4mysql(knl_handle_t session, knl_handle_t stmt, knl_space_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;
    // check if tablespace exists
    if (spc_check_space_exists(se, &def->name, CT_TRUE)) {
        return CT_SUCCESS;
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_CREATE_DB_4MYSQL_BEFORE_CREATE_SPC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    CT_LOG_RUN_INF("[DB] Start to create space for mysql");

    sql_stmt_t *sql_stmt = (sql_stmt_t *)stmt;
    sql_stmt->context->type = CTSQL_TYPE_CREATE_TABLESPACE;
    sql_stmt->context->entry = def;

    if (knl_create_space_internal(session, stmt, def) != CT_SUCCESS) {
        CT_LOG_RUN_INF("[DB] Failed to create space for mysql");
        return CT_ERROR;
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_CREATE_DB_4MYSQL_AFTER_CREATE_SPC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return CT_SUCCESS;
}

status_t knl_alter_space(knl_handle_t session, knl_handle_t stmt, knl_altspace_def_t *def)
{
    CT_LOG_RUN_INF("[DB] Start to alter space %s, action %u", def->name.str, (uint32)def->action);
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_KNL_ALTER_SPACE, &tv_begin);
    knl_session_t *se = (knl_session_t *)session;
    status_t status = CT_ERROR;
    uint32 space_id;

    if (DB_IS_READONLY(se)) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_ALTER_SPACE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    if (knl_ddl_latch_x(session, NULL) != CT_SUCCESS) {
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_ALTER_SPACE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    if (CT_SUCCESS != spc_get_space_id(se, &def->name, def->is_for_create_db, &space_id)) {
        knl_ddl_unlatch_x(session);
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_ALTER_SPACE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    log_add_lrep_ddl_begin(se);
    space_t *space = KNL_GET_SPACE(se, space_id);

    switch (def->action) {
        case ALTSPACE_ADD_DATAFILE:
            status = spc_create_datafiles(se, space, def);
            break;
        case ALTSPACE_SET_AUTOEXTEND:
            status = spc_set_autoextend(se, space, &def->autoextend);
            break;
        case ALTSPACE_SET_AUTOOFFLINE:
            status = spc_set_autooffline(se, space, def->auto_offline);
            break;
        case ALTSPACE_DROP_DATAFILE:
            status = spc_drop_datafiles(se, space, &def->datafiles);
            break;
        case ALTSPACE_RENAME_SPACE:
            status = spc_rename_space(se, space, &def->rename_space);
            break;
        case ALTSPACE_OFFLINE_DATAFILE:
            status = spc_offline_datafiles(se, space, &def->datafiles);
            break;
        case ALTSPACE_RENAME_DATAFILE:
            status = spc_rename_datafiles(se, space, &def->datafiles, &def->rename_datafiles);
            break;
        case ALTSPACE_SET_AUTOPURGE:
            status = spc_set_autopurge(se, space, def->auto_purge);
            break;
        case ALTSPACE_SHRINK_SPACE:
            status = spc_shrink_space(se, space, &def->shrink);
            break;
        case ALTSPACE_PUNCH:
            status = spc_punch_hole(se, space, def->punch_size);
            break;
        default:
            status = CT_ERROR;
            break;
    };

    if (IS_SWAP_SPACE(space)) {
        se->temp_pool->get_swap_extents = 0;
    }

    if (status != CT_ERROR) {
        log_add_lrep_ddl_info(se, stmt, LOGIC_OP_TABLESPACE, RD_ALTER_TABLE, NULL);
    }
    log_add_lrep_ddl_end(se);
    space->allow_extend = CT_TRUE;
    knl_ddl_unlatch_x(session);

    cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_ALTER_SPACE, &tv_begin, status == CT_SUCCESS ?
                       IO_STAT_SUCCESS : IO_STAT_FAILED);
    CT_LOG_RUN_INF("[DB] Finish to alter space %s, ret:%d", def->name.str, status);
    return status;
}

status_t knl_set_commit(knl_handle_t session, knl_commit_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;
    status_t status = CT_SUCCESS;

    switch (def->action) {
        case COMMIT_LOGGING:
            se->commit_batch = (bool8)def->batch;
            break;
        case COMMIT_WAIT:
            se->commit_nowait = (bool8)def->nowait;
            break;
        default:
            status = CT_ERROR;
            break;
    }

    return status;
}

void knl_set_lockwait_timeout(knl_handle_t session, knl_lockwait_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;
    se->lock_wait_timeout = def->lock_wait_timeout;
}
static status_t db_check_ddm_rule_by_obj(knl_session_t *session, uint32 uid, uint32 oid)
{
    knl_cursor_t *cursor = NULL;
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_scan_key_t *l_key = NULL;
    knl_scan_key_t *r_key = NULL;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_DDM_ID, IX_SYS_DDM_001_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    l_key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, CT_TYPE_INTEGER, &uid, sizeof(uint32), IX_COL_SYS_DDM_001_UID);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, CT_TYPE_INTEGER, &oid, sizeof(uint32), IX_COL_SYS_DDM_001_OID);
    knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_DDM_001_COLID);
    r_key = &cursor->scan_range.r_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), r_key, CT_TYPE_INTEGER, &uid, sizeof(uint32), IX_COL_SYS_DDM_001_UID);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_key, CT_TYPE_INTEGER, &oid, sizeof(uint32), IX_COL_SYS_DDM_001_OID);
    knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_DDM_001_COLID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    if (cursor->eof == CT_FALSE) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR_EX(ERR_INVALID_OPERATION, ", the table has rule, please drop rule firstly.");
        return CT_ERROR;
    }
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t knl_drop_space_internal(knl_handle_t session, knl_handle_t stmt, knl_drop_space_def_t *def)
{
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_KNL_DROP_SPACE, &tv_begin);
    knl_session_t *se = (knl_session_t *)session;
    space_t *space = NULL;
    uint32 space_id;
    status_t status;

    if (DB_IS_READONLY(se)) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_DROP_SPACE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    if (se->kernel->db.status != DB_STATUS_OPEN) {
        CT_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "drop tablespace");
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_DROP_SPACE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    if (spc_get_space_id(se, &def->obj_name, def->is_for_create_db, &space_id) != CT_SUCCESS) {
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_DROP_SPACE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    space = KNL_GET_SPACE(se, space_id);
    if (SPACE_IS_DEFAULT(space)) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ",forbid to drop database system space");
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_DROP_SPACE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    log_add_lrep_ddl_begin(se);
    if (!SPACE_IS_ONLINE(space)) {
        status = spc_drop_offlined_space(se, stmt, space, def->options);
    } else {
        status = spc_drop_online_space(se, stmt, space, def->options);
    }

    if (status == CT_SUCCESS) {
        status = spc_try_inactive_swap_encrypt(se);
    }
    log_add_lrep_ddl_end(se);

    cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_DROP_SPACE, &tv_begin, status == CT_SUCCESS ?
                       IO_STAT_SUCCESS : IO_STAT_FAILED);
    return status;
}

status_t knl_drop_space(knl_handle_t session, knl_handle_t stmt, knl_drop_space_def_t *def)
{
    status_t status;

    if (knl_ddl_latch_sx(session, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }
    status = knl_drop_space_internal(session, stmt, def);
    knl_ddl_unlatch_x(session);

    return status;
}

status_t knl_drop_space4mysql(knl_handle_t session, knl_handle_t stmt, knl_drop_space_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;
    // check if tablespace exists
    if (!spc_check_space_exists(se, &def->obj_name, CT_TRUE)) {
        // space does not exist
        CT_LOG_RUN_INF("[DB] no need to drop space when dropping db for mysql");
        return CT_SUCCESS;
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_DROP_DB_4MYSQL_BEFORE_DROP_SPC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    CT_LOG_RUN_INF("[DB] Start to drop space for mysql");
    status_t status;

    sql_stmt_t *sql_stmt = (sql_stmt_t *)stmt;
    sql_stmt->context->type = CTSQL_TYPE_DROP_TABLESPACE;
    sql_stmt->context->entry = def;

    SYNC_POINT_GLOBAL_START(CANTIAN_DROP_DB_4MYSQL_DROP_SPC_FAIL, &status, CT_ERROR);
    status = knl_drop_space_internal(session, stmt, def);
    SYNC_POINT_GLOBAL_END;

    CT_LOG_RUN_INF("[DB] Finish to drop space for mysql");

    SYNC_POINT_GLOBAL_START(CANTIAN_DROP_DB_4MYSQL_AFTER_DROP_SPC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    return status;
}

status_t knl_create_user_internal(knl_handle_t session, knl_handle_t stmt, knl_user_def_t *def)
{
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_KNL_CREATE_USER, &tv_begin);
    knl_session_t *se = (knl_session_t *)session;
    status_t status;

    status = user_create(se, stmt, def);

    cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_CREATE_USER, &tv_begin, status == CT_SUCCESS ?
                       IO_STAT_SUCCESS : IO_STAT_FAILED);
    return status;
}

status_t knl_create_user(knl_handle_t session, knl_user_def_t *def)
{
    status_t status;

    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_ddl_latch_x(session, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }
    status = knl_create_user_internal(session, NULL, def);
    knl_ddl_unlatch_x(session);

    return status;
}

status_t knl_create_user4mysql(knl_handle_t session, knl_handle_t stmt, knl_user_def_t *def)
{
    CT_LOG_RUN_INF("[DB] Start to create user for mysql");
    status_t status = knl_create_user_internal(session, stmt, def);
    return status;
}

status_t knl_drop_user_internal(knl_handle_t session, knl_drop_user_t *def)
{
    timeval_t tv_begin;
    knl_session_t *se = (knl_session_t *)session;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_KNL_DROP_USER, &tv_begin);
    status_t status = user_drop(se, def);
    cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_DROP_USER, &tv_begin, status == CT_SUCCESS ?
                       IO_STAT_SUCCESS : IO_STAT_FAILED);
    return status;
}

status_t knl_drop_user(knl_handle_t session, knl_drop_user_t *def)
{
    knl_session_t *se = (knl_session_t *)session;
    dc_user_t *user = NULL;
    status_t status;
    CT_LOG_RUN_INF("[DB] Start to drop user %s for ctsql", def->owner.str);

    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_open_user(se, &def->owner, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }
    dls_latch_x(session, &user->user_latch, se->id, NULL);
    if (knl_ddl_latch_x(session, NULL) != CT_SUCCESS) {
        dls_unlatch(session, &user->user_latch, NULL);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DB] Drop user %s for ctsql get ddl latch", def->owner.str);
    status = knl_drop_user_internal(session, def);
    knl_ddl_unlatch_x(session);
    dls_unlatch(session, &user->user_latch, NULL);

    CT_LOG_RUN_INF("[DB] Finish to drop user %s for ctsql", def->owner.str);

    return status;
}

status_t knl_drop_user4mysql(knl_handle_t session, knl_handle_t stmt, knl_drop_user_t *def)
{
    SYNC_POINT_GLOBAL_START(CANTIAN_DROP_DB_4MYSQL_BEFORE_DROP_USER_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    CT_LOG_RUN_INF("[DB] Start to drop user for mysql");
    status_t status = CT_SUCCESS;

    sql_stmt_t *sql_stmt = (sql_stmt_t *)stmt;
    sql_stmt->context->type = CTSQL_TYPE_DROP_USER;
    sql_stmt->context->entry = def;

    SYNC_POINT_GLOBAL_START(CANTIAN_DROP_DB_4MYSQL_DROP_USER_FAIL, &status, CT_ERROR);
    status = knl_drop_user_internal(session, def);
    SYNC_POINT_GLOBAL_END;

    CT_LOG_RUN_INF("[DB] Finish to drop user for mysql");

    SYNC_POINT_GLOBAL_START(CANTIAN_DROP_DB_4MYSQL_AFTER_DROP_USER_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    return status;
}
static status_t knl_refresh_sys_pwd(knl_session_t *session, knl_user_def_t *def)
{
    text_t owner;
    dc_user_t *user = NULL;
    cm_str2text(def->name, &owner);
    if (dc_open_user_direct(session, &owner, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cm_alter_config(session->kernel->attr.config, "_SYS_PASSWORD", user->desc.password, CONFIG_SCOPE_DISK,
                        CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}
status_t knl_alter_user(knl_handle_t session, knl_user_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;
    status_t status = CT_SUCCESS;
    drlatch_t *ddl_latch = &se->kernel->db.ddl_latch;

    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_ddl_latch_s(ddl_latch, session, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (user_alter(se, def) != CT_SUCCESS) {
        dls_unlatch(session, ddl_latch, NULL);
        return CT_ERROR;
    }
    if (CT_BIT_TEST(def->mask, CT_GET_MASK(ALTER_USER_FIELD_PASSWORD))) {
        CT_LOG_RUN_WAR("user password of %s has been changed successfully", def->name);
        CT_LOG_ALARM(WARN_PASSWDCHANGE, "user : %s", def->name);
        if (cm_str_equal_ins(def->name, SYS_USER_NAME)) {
            status = knl_refresh_sys_pwd(session, def);
        }
    }
    dls_unlatch(session, ddl_latch, NULL);

    return status;
}

status_t knl_check_user_4mysql(knl_handle_t session, knl_user_def_t *user_def, bool32 *exist)
{
    knl_session_t *se = (knl_session_t *)session;
    uint32 uid;
    text_t user_name;
    cm_str2text(user_def->name, &user_name);
    if (cm_text_str_equal(&user_name, "tmp") || cm_text_str_equal(&user_name, "SYS") ||
        cm_text_str_equal(&user_name, "PUBLIC") || cm_text_str_equal(&user_name, "LREP")) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create database", "sys users");
        CT_LOG_RUN_ERR("[DB] user %s is sys users, not allowed to create db for mysql", user_def->name);
        return CT_ERROR;
    }
    if (dc_get_user_id(se, &user_name, &uid)) {
        // user already exist, check if this user has table
        *exist = CT_TRUE;
        bool32 isfound = CT_FALSE;
        if (knl_check_user_tables(session, uid, &isfound) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] faild to check user %s when creating db for mysql", user_def->name);
            return CT_ERROR;
        }
        if (isfound) {
            CT_THROW_ERROR(ERR_USER_NOT_EMPTY_4MYSQL);
            CT_LOG_RUN_ERR("[DB] user %s already exists and has tables when creating db for mysql", user_def->name);
            return CT_ERROR;
        }
        CT_LOG_RUN_INF("[DB] no need to create db for mysql, user %s exists", user_def->name);
        return CT_SUCCESS;
    }
    *exist = CT_FALSE;
    return CT_SUCCESS;
}

status_t knl_create_database4mysql(knl_handle_t session, knl_handle_t stmt, knl_space_def_t *space_def,
                                   knl_user_def_t *user_def, bool32 is_mysql_sys_db)
{
    CT_LOG_RUN_INF("[for mysql] Start to create db for mysql, space %s, user %s", space_def->name.str, user_def->name);
    knl_session_t *se = (knl_session_t *)session;
    sql_stmt_t *sql_stmt = (sql_stmt_t *)stmt;
    status_t ret = CT_SUCCESS;

    SYNC_POINT_GLOBAL_START(CANTIAN_CREATE_DB_4MYSQL_LOCK_FAIL, &ret, CT_ERROR);
    ret = knl_ddl_latch_sx(se, NULL);
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        return CT_ERROR;
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_CREATE_DB_4MYSQL_AFTER_LOCK_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    // check if user exists
    bool32 exist = CT_FALSE;
    if (knl_check_user_4mysql(session, user_def, &exist) != CT_SUCCESS) {
        knl_ddl_unlatch_x(session);
        return CT_ERROR;
    }
    if (exist) {
        knl_ddl_unlatch_x(session);
        if (is_mysql_sys_db) {
            CT_LOG_RUN_INF("[DB] mysql system database 'mysql' already exists");
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_CREATE_DB_4MYSQL_CREATE_SPC_FAIL, &ret, CT_ERROR);
    ret = knl_create_space4mysql(session, stmt, space_def);
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        knl_ddl_unlatch_x(session);
        CT_LOG_RUN_ERR("[DB] failed to create tablespace for mysql");
        return CT_ERROR;
    }

    // create user
    sql_stmt->context->type = CTSQL_TYPE_CREATE_USER;
    sql_stmt->context->entry = user_def;
    SYNC_POINT_GLOBAL_START(CANTIAN_CREATE_DB_4MYSQL_BEFORE_CREATE_USER_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    SYNC_POINT_GLOBAL_START(CANTIAN_CREATE_DB_4MYSQL_BEFORE_CREATE_USER_DELAY, NULL, 50000); // delay 50s
    SYNC_POINT_GLOBAL_END;

    SYNC_POINT_GLOBAL_START(CANTIAN_CREATE_DB_4MYSQL_CREATE_USER_FAIL, &ret, CT_ERROR);
    ret = knl_create_user4mysql(session, stmt, user_def);
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        knl_ddl_unlatch_x(session);
        CT_LOG_RUN_ERR("[DB] failed to create user %s for mysql", user_def->name);
        return CT_ERROR;
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_CREATE_DB_4MYSQL_AFTER_CREATE_USER_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    knl_ddl_unlatch_x(session);
    CT_LOG_RUN_INF("[DB] Success to create db for mysql, user %s", user_def->name);
    return CT_SUCCESS;
}

status_t knl_drop_database4mysql(knl_handle_t session, knl_handle_t stmt, knl_drop_space_def_t *space_def,
                                 knl_drop_user_t *user_def)
{
    CT_LOG_RUN_INF("[for mysql] Start to drop db for mysql, space %s, user %s",
                   space_def->obj_name.str, user_def->owner.str);
    knl_session_t *se = (knl_session_t *)session;
    dc_user_t *user = NULL;
    uint32 uid;
    status_t ret = CT_SUCCESS;

    bool32 user_exist = dc_get_user_id(se, &user_def->owner, &uid);
    if (user_exist) {
        if (dc_open_user(se, &user_def->owner, &user) != CT_SUCCESS) {
            return CT_ERROR;
        }
        dls_latch_x(session, &user->user_latch, se->id, NULL);
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_DROP_DB_4MYSQL_LOCK_FAIL, &ret, CT_ERROR);
    ret = knl_ddl_latch_sx(se, NULL);
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        if (user_exist) {
            dls_unlatch(session, &user->user_latch, NULL);
        }
        return CT_ERROR;
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_DROP_DB_4MYSQL_AFTER_LOCK_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    if (user_exist && knl_drop_user4mysql(session, stmt, user_def) != CT_SUCCESS) {
        knl_ddl_unlatch_x(session);
        dls_unlatch(session, &user->user_latch, NULL);
        CT_LOG_RUN_ERR("[for mysql] faild to drop user %s when dropping db for mysql", user_def->owner.str);
        return CT_ERROR;
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_DROP_DB_4MYSQL_AFTER_DROP_USER_DELAY, NULL, 50000); // delay 50s
    SYNC_POINT_GLOBAL_END;

    ret = knl_drop_space4mysql(session, stmt, space_def);

    knl_ddl_unlatch_x(session);
    if (user_exist) {
        dls_unlatch(session, &user->user_latch, NULL);
    }

    CT_LOG_RUN_INF("[for mysql] Finish to drop db for mysql, space %s, user %s, ret:%d",
                   space_def->obj_name.str, user_def->owner.str, ret);
    return ret;
}

status_t knl_create_role(knl_handle_t session, knl_role_def_t *def)
{
    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return user_create_role((knl_session_t *)session, def);
}

status_t knl_drop_role(knl_handle_t session, knl_drop_def_t *def)
{
    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return user_drop_role((knl_session_t *)session, def);
}

status_t knl_create_tenant(knl_handle_t session, knl_tenant_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;
    drlatch_t *ddl_latch = &se->kernel->db.ddl_latch;
    uint32 id = se->id;
    status_t status;

    CM_MAGIC_CHECK(def, knl_tenant_def_t);

    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dls_latch_x(session, ddl_latch, id, NULL);
    status = tenant_create(se, def);
    dls_unlatch(session, ddl_latch, NULL);

    return status;
}

status_t knl_drop_tenant(knl_handle_t session, knl_drop_tenant_t *def)
{
    knl_session_t *se = (knl_session_t *)session;
    drlatch_t *ddl_latch = &se->kernel->db.ddl_latch;
    uint32 id = se->id;
    status_t status;

    CM_MAGIC_CHECK(def, knl_drop_tenant_t);

    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dls_latch_x(session, ddl_latch, id, NULL);
    status = tenant_drop(se, def);
    dls_unlatch(session, ddl_latch, NULL);

    return status;
}

status_t knl_create_sequence(knl_handle_t session, knl_handle_t stmt, knl_sequence_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;
    dc_user_t *user = NULL;

    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_open_user(se, &def->user, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dls_latch_x(session, &user->user_latch, se->id, NULL);
    if (db_create_sequence((knl_session_t *)session, stmt, def) != CT_SUCCESS) {
        dls_unlatch(session, &user->user_latch, NULL);
        return CT_ERROR;
    }

    dls_unlatch(session, &user->user_latch, NULL);
    return CT_SUCCESS;
}

status_t knl_alter_sequence(knl_handle_t session, knl_handle_t stmt, knl_sequence_def_t *def)
{
    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return db_alter_sequence((knl_session_t *)session, stmt, def);
}

status_t knl_alter_seq_nextval(knl_handle_t session, knl_sequence_def_t *def, int64 value)
{
    return db_alter_seq_nextval((knl_session_t *)session, def, value);
}

status_t knl_get_seq_def(knl_handle_t session, text_t *user, text_t *name, knl_sequence_def_t *def)
{
    return db_get_seq_def((knl_session_t *)session, user, name, def);
}

status_t knl_seq_nextval(knl_handle_t session, text_t *user, text_t *name, int64 *nextval)
{
    return db_next_seq_value((knl_session_t *)session, user, name, nextval);
}

status_t knl_get_nextval_for_cn(knl_handle_t session, text_t *user, text_t *name, int64 *value)
{
    return db_get_nextval_for_cn((knl_session_t *)session, user, name, value);
}

status_t knl_seq_multi_val(knl_handle_t session, knl_sequence_def_t *def, uint32 group_order, uint32 group_cnt,
                           uint32 count)
{
    return db_multi_seq_value((knl_session_t *)session, def, group_order, group_cnt, count);
}

status_t knl_seq_currval(knl_handle_t session, text_t *user, text_t *name, int64 *nextval)
{
    return db_current_seq_value((knl_session_t *)session, user, name, nextval);
}

status_t knl_get_seq_dist_data(knl_handle_t session, text_t *user, text_t *name, binary_t **dist_data)
{
    return db_get_seq_dist_data((knl_session_t *)session, user, name, dist_data);
}

status_t knl_get_sequence_id(knl_handle_t session, text_t *user, text_t *name, uint32 *id)
{
    return db_get_sequence_id((knl_session_t *)session, user, name, id);
}

status_t knl_set_cn_seq_currval(knl_handle_t session, text_t *user, text_t *name, int64 nextval)
{
    return db_set_cn_seq_currval((knl_session_t *)session, user, name, nextval);
}

status_t knl_drop_sequence(knl_handle_t session, knl_handle_t stmt, knl_drop_def_t *def)
{
    knl_dictionary_t dc;
    bool32 seq_exists = CT_FALSE;
    bool32 drop_if_exists = (def->options & DROP_IF_EXISTS);
    knl_session_t *se = (knl_session_t *)session;

    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dc_user_t *user = NULL;
    if (dc_open_user(session, &def->owner, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dls_latch_x(session, &user->user_latch, se->id, NULL);
    if (CT_SUCCESS != dc_seq_open(se, &def->owner, &def->name, &dc)) {
        dls_unlatch(session, &user->user_latch, NULL);
        cm_reset_error_user(ERR_SEQ_NOT_EXIST, T2S(&def->owner), T2S_EX(&def->name), ERR_TYPE_SEQUENCE);
        if (drop_if_exists) {
            int32 code = cm_get_error_code();
            if (code == ERR_SEQ_NOT_EXIST) {
                cm_reset_error();
                return CT_SUCCESS;
            }
        }
        return CT_ERROR;
    }

    if (db_drop_sequence(se, stmt, &dc, &seq_exists) != CT_SUCCESS) {
        dc_seq_close(&dc);
        dls_unlatch(session, &user->user_latch, NULL);
        return CT_ERROR;
    }

    dc_seq_close(&dc);
    dls_unlatch(session, &user->user_latch, NULL);

    if (!seq_exists && !drop_if_exists) {
        CT_THROW_ERROR(ERR_SEQ_NOT_EXIST, T2S(&def->owner), T2S_EX(&def->name));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static bool32 knl_judge_index_exist(knl_handle_t session, knl_index_def_t *def, dc_entity_t *entity)
{
    table_t *table = &entity->table;
    index_t *index = NULL;

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];

        if (cm_text_str_equal(&def->name, index->desc.name)) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

static bool32 knl_is_online_upgrading(knl_session_t *session)
{
    // if the database is online upgrading, return true
    ctrl_version_t cantaind_version = {0};
    db_get_cantiand_version(&cantaind_version);
    cantaind_version.inner = CORE_VERSION_INNER;
    // if current ctrl version < cantiand_version
    if (!db_cur_ctrl_version_is_higher(session, cantaind_version) &&
        !db_equal_to_cur_ctrl_version(session, cantaind_version)) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

static bool32 knl_create_index_precheck(knl_session_t *session, knl_dictionary_t *dc, knl_index_def_t *def)
{
    if (SYNONYM_EXIST(dc)) {
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&def->user), T2S_EX(&def->table));
        return CT_FALSE;
    }

    if (!DB_IS_MAINTENANCE(session) && dc->type == DICT_TYPE_TABLE_EXTERNAL) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create index", "external organized table");
        return CT_FALSE;
    }

    if (dc->type != DICT_TYPE_TABLE && dc->type != DICT_TYPE_TEMP_TABLE_SESSION &&
        dc->type != DICT_TYPE_TEMP_TABLE_TRANS && dc->type != DICT_TYPE_TABLE_NOLOGGING) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create index", "view");
        return CT_FALSE;
    }

    if (!DB_IS_MAINTENANCE(session) && !session->bootstrap && IS_SYS_DC(dc)) {
        if (IS_CORE_SYS_TABLE(dc->uid, dc->oid) || !knl_is_online_upgrading(session)) {
            CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create index", "system table");
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

status_t knl_create_index(knl_handle_t handle, knl_handle_t stmt, knl_index_def_t *def)
{
    knl_dictionary_t dc;
    rd_table_t redo;
    knl_session_t *session = (knl_session_t *)handle;
    drlatch_t *ddl_latch = &session->kernel->db.ddl_latch;

    if (knl_ddl_enabled(handle, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_open(session, &def->user, &def->table, &dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!knl_create_index_precheck(session, &dc, def)) {
        dc_close(&dc);
        return CT_ERROR;
    }

    if (knl_ddl_latch_s(ddl_latch, handle, NULL) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }

    // create index online is TRUE, should wait for DDL lock, i.e., nowait is FALSE
    uint32 timeout = def->online ? LOCK_INF_WAIT : session->kernel->attr.ddl_lock_timeout;
    if (lock_table_directly(session, &dc, timeout) != CT_SUCCESS) {
        dls_unlatch(session, ddl_latch, NULL);
        dc_close(&dc);
        return CT_ERROR;
    }

    if (lock_child_table_directly(session, dc.handle, !def->online) != CT_SUCCESS) {
        unlock_tables_directly(session);
        dls_unlatch(session, ddl_latch, NULL);
        dc_close(&dc);
        return CT_ERROR;
    }

    if (knl_judge_index_exist(handle, def, DC_ENTITY(&dc)) && (def->options & CREATE_IF_NOT_EXISTS)) {
        unlock_tables_directly(session);
        dls_unlatch(session, ddl_latch, NULL);
        dc_close(&dc);
        return CT_SUCCESS;
    }

    log_add_lrep_ddl_begin(session);
    if (def->online) {
        if (db_create_index_online(session, def, &dc) != CT_SUCCESS) {
            log_add_lrep_ddl_end(session);
            unlock_tables_directly(session);
            dls_unlatch(session, ddl_latch, NULL);
            dc_close(&dc);
            return CT_ERROR;
        }
    } else {
        if (db_create_index(session, def, &dc, CT_FALSE, NULL) != CT_SUCCESS) {
            log_add_lrep_ddl_end(session);
            unlock_tables_directly(session);
            dls_unlatch(session, ddl_latch, NULL);
            dc_close(&dc);
            return CT_ERROR;
        }
    }

    status_t status = db_write_ddl_op_for_children(session, &((dc_entity_t*)dc.handle)->table);
    if (status != CT_SUCCESS) {
        unlock_tables_directly(session);
        dls_unlatch(session, ddl_latch, NULL);
        dc_close(&dc);
        return CT_ERROR;
    }

    redo.op_type = RD_CREATE_INDEX;
    redo.uid = dc.uid;
    redo.oid = dc.oid;
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_table_t), LOG_ENTRY_FLAG_NONE);
    log_add_lrep_ddl_info(session, stmt, LOGIC_OP_INDEX, RD_CREATE_INDEX, NULL);
    log_add_lrep_ddl_end(session);

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_CREATE_INDEX_BEFORE_SYNC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    knl_commit(handle);
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_CREATE_INDEX_AFTER_SYNC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    dc_invalidate_children(session, (dc_entity_t *)dc.handle);
    dc_invalidate(session, (dc_entity_t *)dc.handle);
    unlock_tables_directly(session);
    dls_unlatch(session, ddl_latch, NULL);
    dc_close(&dc);

    if ((DB_IS_MAINTENANCE(session)) && IS_SYS_DC(&dc)) {
        if (knl_open_dc_by_id(handle, dc.uid, dc.oid, &dc, CT_TRUE) != CT_SUCCESS) {
            CM_ABORT(0, "[DB] ABORT INFO: failed to update dictionary cache, "
                        "please check environment and restart instance");
        }
        dc_close(&dc);
    }

    return CT_SUCCESS;
}

static void knl_ddm_write_rd(knl_handle_t session, knl_dictionary_t *dc)
{
    rd_table_t rd_altable;
    rd_altable.op_type = RD_ALTER_TABLE;
    rd_altable.uid = dc->uid;
    rd_altable.oid = dc->oid;
    log_put(session, RD_LOGIC_OPERATION, &rd_altable, sizeof(rd_table_t), LOG_ENTRY_FLAG_NONE);
}

static status_t db_verify_write_sys_policy(knl_session_t *session, knl_dictionary_t *dc, policy_def_t *policy)
{
    table_t *table = DC_TABLE(dc);
    if (table->policy_set.plcy_count + 1 > CT_MAX_POLICIES) {
        CT_THROW_ERROR(ERR_TOO_MANY_OBJECTS, CT_MAX_POLICIES, "table's policies");
        return CT_ERROR;
    }

    if (dc->type != DICT_TYPE_TABLE || dc->is_sysnonym) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", please set rule on common table");
        return CT_ERROR;
    }
    dc_entity_t *entity = DC_ENTITY(dc);
    if (IS_SYS_TABLE(&entity->table) || IS_PART_TABLE(&entity->table)) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", please set rule on common table");
        return CT_ERROR;
    }

    /* get policy owner id */
    if (!knl_get_user_id(session, &policy->object_owner, &policy->object_owner_id)) {
        CT_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&policy->object_owner));
        return CT_ERROR;
    }

    if (policy->object_owner_id == DB_SYS_USER_ID) {
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }

    /* check if the policy name already exists */
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_POLICY_ID, IX_SYS_POLICY_001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER,
                     (void *)&policy->object_owner_id, sizeof(uint32), IX_COL_SYS_POLICY_001_OBJ_SCHEMA_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING,
                     (void *)policy->object_name.str, (uint16)policy->object_name.len, IX_COL_SYS_POLICY_001_OBJ_NAME);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING,
                     (void *)policy->policy_name.str, (uint16)policy->policy_name.len, IX_COL_SYS_POLICY_001_PNAME);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (!cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_DUPLICATE_NAME, "policy", T2S(&policy->policy_name));
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static status_t db_write_sys_policy(knl_session_t *session, policy_def_t *policy)
{
    row_assist_t row;
    table_t *table = NULL;
    status_t status;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    uint32 max_size = session->kernel->attr.max_row_size;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_POLICY_ID, CT_INVALID_ID32);
    table = (table_t *)cursor->table;

    row_init(&row, (char *)cursor->row, max_size, table->desc.column_count);
    (void)row_put_uint32(&row, policy->object_owner_id);
    (void)row_put_text(&row, &policy->object_name);
    (void)row_put_text(&row, &policy->policy_name);
    (void)row_put_text(&row, &policy->function_owner);
    (void)row_put_text(&row, &policy->function);
    (void)row_put_uint32(&row, policy->stmt_types);
    (void)row_put_uint32(&row, policy->ptype);
    (void)row_put_uint32(&row, policy->check_option);
    (void)row_put_uint32(&row, policy->enable);
    (void)row_put_uint32(&row, policy->long_predicate);

    status = knl_internal_insert(session, cursor);
    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t knl_write_sys_policy(knl_handle_t session, policy_def_t *plcy_def)
{
    knl_dictionary_t dc;
    knl_session_t *se = (knl_session_t *)session;
    drlatch_t *ddl_latch = &se->kernel->db.ddl_latch;
    uint32 id = se->id;

    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_open_dc_with_public(session, &plcy_def->object_owner, CT_TRUE, &plcy_def->object_name, &dc) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&plcy_def->object_owner), T2S_EX(&plcy_def->object_name));
        return CT_ERROR;
    }

    dls_latch_s(session, ddl_latch, id, CT_FALSE, NULL);
    uint32 timeout = se->kernel->attr.ddl_lock_timeout;
    if (lock_table_directly(se, &dc, timeout) != CT_SUCCESS) {
        dls_unlatch(session, ddl_latch, NULL);
        knl_close_dc(&dc);
        return CT_ERROR;
    }

    if (db_verify_write_sys_policy(se, &dc, plcy_def) != CT_SUCCESS) {
        unlock_tables_directly(se);
        dls_unlatch(session, ddl_latch, NULL);
        knl_close_dc(&dc);
        return CT_ERROR;
    }

    if (db_write_sys_policy(se, plcy_def) != CT_SUCCESS) {
        unlock_tables_directly(se);
        dls_unlatch(session, ddl_latch, NULL);
        knl_close_dc(&dc);
        return CT_ERROR;
    }
    knl_ddm_write_rd(session, &dc);
    knl_commit(session);

    dc_invalidate(se, DC_ENTITY(&dc));
    unlock_tables_directly(se);
    dls_unlatch(session, ddl_latch, NULL);
    knl_close_dc(&dc);
    return CT_SUCCESS;
}

static status_t db_modify_sys_policy(knl_session_t *session, policy_def_t *policy, knl_cursor_action_t action)
{
    row_assist_t row;
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, action, SYS_POLICY_ID, IX_SYS_POLICY_001_ID);

    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER,
                     (void *)&policy->object_owner_id, sizeof(uint32), IX_COL_SYS_POLICY_001_OBJ_SCHEMA_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING,
                     (void *)policy->object_name.str, (uint16)policy->object_name.len, IX_COL_SYS_POLICY_001_OBJ_NAME);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING,
                     (void *)policy->policy_name.str, (uint16)policy->policy_name.len, IX_COL_SYS_POLICY_001_PNAME);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "policy", T2S(&policy->policy_name));
        return CT_ERROR;
    }

    if (action == CURSOR_ACTION_DELETE) {
        if (knl_internal_delete(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    } else if (action == CURSOR_ACTION_UPDATE) {
        row_init(&row, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
        (void)row_put_int32(&row, (int32)policy->enable);
        cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
        cursor->update_info.columns[0] = SYS_POLICIES_COL_ENABLE;
        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);
        if (knl_internal_update(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t knl_modify_sys_policy(knl_handle_t session, policy_def_t *plcy_def, knl_cursor_action_t action)
{
    knl_dictionary_t dc;
    knl_session_t *se = (knl_session_t *)session;
    drlatch_t *ddl_latch = &se->kernel->db.ddl_latch;
    uint32 id = se->id;

    /* get policy owner id */
    if (!knl_get_user_id(session, &plcy_def->object_owner, &plcy_def->object_owner_id)) {
        CT_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&plcy_def->object_owner));
        return CT_ERROR;
    }
    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (knl_open_dc_with_public(session, &plcy_def->object_owner, CT_TRUE, &plcy_def->object_name, &dc) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&plcy_def->object_owner), T2S_EX(&plcy_def->object_name));
        return CT_ERROR;
    }

    dls_latch_s(session, ddl_latch, id, CT_FALSE, NULL);
    uint32 timeout = se->kernel->attr.ddl_lock_timeout;
    if (lock_table_directly(se, &dc, timeout) != CT_SUCCESS) {
        dls_unlatch(session, ddl_latch, NULL);
        knl_close_dc(&dc);
        return CT_ERROR;
    }

    if (db_modify_sys_policy(se, plcy_def, action) != CT_SUCCESS) {
        unlock_tables_directly(se);
        dls_unlatch(session, ddl_latch, NULL);
        knl_close_dc(&dc);
        return CT_ERROR;
    }
    knl_ddm_write_rd(session, &dc);
    knl_commit(session);

    dc_invalidate(se, DC_ENTITY(&dc));
    unlock_tables_directly(se);
    dls_unlatch(session, ddl_latch, NULL);
    knl_close_dc(&dc);
    return CT_SUCCESS;
}

static void knl_alter_table_after_commit(knl_handle_t session, knl_dictionary_t *dc, knl_altable_def_t *def,
                                         trig_name_list_t *trig)
{
    knl_dictionary_t *ref_dc = NULL;
    dc_entity_t *entity = (dc_entity_t *)dc->handle;
    trig_set_t trig_set = entity->trig_set;

    switch (def->action) {
        case ALTABLE_ADD_CONSTRAINT:
            if (def->cons_def.new_cons.type == CONS_TYPE_REFERENCE) {
                ref_dc = &def->cons_def.new_cons.ref.ref_dc;
                if (ref_dc->handle != NULL) {
                    dc_invalidate((knl_session_t *)session, (dc_entity_t *)ref_dc->handle);
                    dc_close(ref_dc);
                }
            }
            break;
        case ALTABLE_ADD_COLUMN:
        case ALTABLE_RENAME_TABLE:
        case ALTABLE_RENAME_COLUMN:
        case ALTABLE_DROP_COLUMN:
            if (trig_set.trig_count > 0) {
                g_knl_callback.pl_free_trig_entity_by_tab(session, dc);
            }
            break;
        default:
            break;
    }
}

/*
 * kernel shrink space compact
 * Shrink compact the given table with table shared lock.
 * @note only support shrink compact heap segment
 * @param kernel session, dictionary
 */
static status_t knl_shrink_compact(knl_session_t *session, knl_dictionary_t *dc, heap_cmp_def_t def)
{
    table_part_t *table_part = NULL;
    knl_part_locate_t part_loc;

    if (def.timeout != 0) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ",timeout only supported in shrink space");
        return CT_ERROR;
    }

    if (lock_table_shared_directly(session, dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dc_entity_t *entity = DC_ENTITY(dc);
    if (entity->corrupted) {
        unlock_tables_directly(session);
        CT_THROW_ERROR(ERR_DC_CORRUPTED);
        return CT_ERROR;
    }

    table_t *table = DC_TABLE(dc);
    if (table->ashrink_stat != ASHRINK_END) {
        unlock_tables_directly(session);
        CT_THROW_ERROR(ERR_SHRINK_IN_PROGRESS_FMT, DC_ENTRY_USER_NAME(dc), DC_ENTRY_NAME(dc));
        return CT_ERROR;
    }

    if (IS_PART_TABLE(table)) {
        for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
            table_part = TABLE_GET_PART(table, i);
            if (!IS_READY_PART(table_part)) {
                continue;
            }

            part_loc.part_no = i;
            if (heap_shrink_compart_compact(session, dc, part_loc, CT_FALSE, def) != CT_SUCCESS) {
                unlock_tables_directly(session);
                return CT_ERROR;
            }
        }
    } else {
        part_loc.part_no = 0;
        part_loc.subpart_no = CT_INVALID_ID32;
        if (heap_shrink_compact(session, dc, part_loc, CT_FALSE, def) != CT_SUCCESS) {
            unlock_tables_directly(session);
            return CT_ERROR;
        }
    }

    unlock_tables_directly(session);

    return CT_SUCCESS;
}

static void knl_ashrink_update_hwms(knl_session_t *session, knl_dictionary_t *dc, bool32 *valid_hwm)
{
    table_t *table = DC_TABLE(dc);
    knl_part_locate_t part_loc;

    part_loc.subpart_no = CT_INVALID_ID32;
    if (!IS_PART_TABLE(table)) {
        part_loc.part_no = 0;
        heap_ashrink_update_hwms(session, dc, part_loc, valid_hwm);
        return;
    }

    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        table_part_t *table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        part_loc.part_no = i;
        bool32 valid = CT_FALSE;
        heap_ashrink_update_hwms(session, dc, part_loc, &valid);
        if (!(*valid_hwm)) {
            *valid_hwm = valid;
        }
    }

    return;
}

static status_t knl_internel_shrink_compact(knl_session_t *session, knl_dictionary_t *dc,
    heap_cmp_def_t def, bool32 *is_canceled)
{
    bool32 async_shrink = (bool32)(def.timeout != 0);
    bool32 shrink_hwm = !async_shrink;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = DC_TABLE(dc);
    table_part_t *table_part = NULL;
    knl_part_locate_t part_loc;
    status_t status = CT_SUCCESS;

    lock_degrade_table_lock(session, entity);

    if (!IS_PART_TABLE(table)) {
        part_loc.part_no = 0;
        part_loc.subpart_no = CT_INVALID_ID32;
        status = heap_shrink_compact(session, dc, part_loc, shrink_hwm, def);
    } else {
        for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
            if (async_shrink && (KNL_NOW(session) - def.end_time) / MICROSECS_PER_SECOND > 0) {
                CT_LOG_RUN_INF("async shrink timeout. uid %u oid %u name %s part_no %d.",
                    dc->uid, dc->oid, table->desc.name, i);
                break;
            }

            table_part = TABLE_GET_PART(table, i);
            if (!IS_READY_PART(table_part)) {
                continue;
            }

            part_loc.part_no = i;
            if (heap_shrink_compart_compact(session, dc, part_loc, shrink_hwm, def) != CT_SUCCESS) {
                status = CT_ERROR;
                break;
            }
        }
    }

    if (status != CT_SUCCESS) {
        if (cm_get_error_code() != ERR_OPERATION_CANCELED) {
            return CT_ERROR;
        }
        cm_reset_error();
        session->canceled = CT_FALSE;
        *is_canceled = CT_TRUE;
    }

    return lock_upgrade_table_lock(session, entity, LOCK_INF_WAIT);
}

/*
 * kernel shrink space
 * Same like the shrink space compact, but we shrink the
 * hwm of all the heap segments
 * @note only support shrink heap segment
 * @param kernel session, dictionary
 */
static status_t knl_shrink_space(knl_session_t *session, knl_dictionary_t *dc, heap_cmp_def_t def, bool32 *retry,
                                 bool32 *is_canceled)
{
    bool32 async_shrink = (bool32)(def.timeout != 0);
    uint32 tlock_time = session->kernel->attr.ddl_lock_timeout;

    def.end_time = KNL_NOW(session) + (date_t)def.timeout * MICROSECS_PER_SECOND;
    tlock_time = async_shrink ? MAX(tlock_time, def.timeout) : tlock_time;
    if (lock_table_directly(session, dc, tlock_time) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dc_entity_t *entity = DC_ENTITY(dc);
    if (entity->corrupted) {
        unlock_tables_directly(session);
        CT_THROW_ERROR(ERR_DC_CORRUPTED);
        return CT_ERROR;
    }

    table_t *table = &entity->table;
    if (table->ashrink_stat != ASHRINK_END) {
        CT_LOG_RUN_INF("last shrink not finish,reset table async shrink status.uid %u oid %u name %s", dc->uid, dc->oid,
                       table->desc.name);
        *retry = CT_TRUE;
        dc_invalidate(session, entity);
        unlock_tables_directly(session);
        return CT_SUCCESS;
    }

    table->ashrink_stat = async_shrink ? ASHRINK_COMPACT : ASHRINK_END;

    if (knl_internel_shrink_compact(session, dc, def, is_canceled) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("table async shrink compact failed.uid %u oid %u name %s", dc->uid, dc->oid, table->desc.name);
        table->ashrink_stat = ASHRINK_END;
        unlock_tables_directly(session);
        return CT_ERROR;
    }

    if (!async_shrink) {
        status_t status = heap_shrink_spaces(session, dc, CT_FALSE);
        dc_invalidate(session, entity);
        unlock_tables_directly(session);
        return status;
    }

    bool32 valid_hwm = CT_FALSE;
    knl_ashrink_update_hwms(session, dc, &valid_hwm);

    if (!valid_hwm) {
        CT_LOG_RUN_INF("table async shrink compact zero rows.uid %u oid %u name %s", dc->uid, dc->oid,
                       table->desc.name);
        dc_invalidate(session, entity);
        unlock_tables_directly(session);
        return CT_SUCCESS;
    }

    table->ashrink_stat = ASHRINK_WAIT_SHRINK;
    if (ashrink_add(session, dc, DB_CURR_SCN(session)) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("push table to async shrink list failed.uid %u oid %u name %s", dc->uid, dc->oid,
                       table->desc.name);
        dc_invalidate(session, entity);
        unlock_tables_directly(session);
        return CT_ERROR;
    }

    unlock_tables_directly(session);
    return CT_SUCCESS;
}

static status_t knl_check_shrinkable(knl_handle_t session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    if (IS_SYS_DC(dc)) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "shrink table", "view or system table");
        return CT_ERROR;
    }

    if (SYNONYM_EXIST(dc)) {
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&def->user), T2S_EX(&def->name));
        return CT_ERROR;
    }

    if (dc->type == DICT_TYPE_TABLE_EXTERNAL) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "shrink table", "external organized table");
        return CT_ERROR;
    }

    if (dc->type < DICT_TYPE_TABLE || dc->type > DICT_TYPE_TABLE_NOLOGGING) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "shrink table", "view or system table");
        return CT_ERROR;
    }

    if (dc->type == DICT_TYPE_TEMP_TABLE_SESSION || dc->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "shrink table", "temp table");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * shrink table space online
 * @param kernel session, alter table definition
 */
status_t knl_alter_table_shrink(knl_handle_t session, knl_handle_t stmt, knl_altable_def_t *def)
{
    knl_dictionary_t dc;
    status_t status = CT_SUCCESS;
    knl_session_t *se = (knl_session_t *)session;
    bool32 is_canceled = CT_FALSE;

    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    heap_cmp_def_t shrink_def;
    uint32 shrink_opt = def->table_def.shrink_opt;
    shrink_def.percent = def->table_def.shrink_percent;
    shrink_def.timeout = def->table_def.shrink_timeout;

    if (shrink_opt & SHRINK_CASCADE) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "shrink cascade");
        return CT_ERROR;
    }

    for (;;) {
        if (dc_open(se, &def->user, &def->name, &dc) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (knl_check_shrinkable(session, &dc, def) != CT_SUCCESS) {
            dc_close(&dc);
            return CT_ERROR;
        }

        if (knl_ddl_latch_s(&se->kernel->db.ddl_latch, session, NULL) != CT_SUCCESS) {
            dc_close(&dc);
            return CT_ERROR;
        }

        log_add_lrep_ddl_begin(se);
        bool32 retry = CT_FALSE;
        if (shrink_opt & SHRINK_COMPACT) {
            status = knl_shrink_compact(se, &dc, shrink_def);
        } else {
            status = knl_shrink_space(se, &dc, shrink_def, &retry, &is_canceled);
        }

        table_t *table = DC_TABLE(&dc);
        log_lrep_shrink_table(se, stmt, table, status);
        log_add_lrep_ddl_end(se);

        dls_unlatch(session, &se->kernel->db.ddl_latch, NULL);
        dc_close(&dc);

        if (!retry) {
            break;
        }
    }

    if (is_canceled) {
        se->canceled = CT_TRUE;
    }

    if (status == CT_SUCCESS) {
        se->stat->table_alters++;
    }

    return status;
}

static status_t knl_altable_check_table_type(knl_session_t *session, knl_altable_def_t *def, knl_dictionary_t *dc)
{
    if (SYNONYM_EXIST(dc)) {
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&def->user), T2S_EX(&def->name));
        return CT_ERROR;
    }

    if (dc->type == DICT_TYPE_TABLE_EXTERNAL) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "alter table", "external organized table");
        return CT_ERROR;
    }

    if (dc->type < DICT_TYPE_TABLE || dc->type > DICT_TYPE_TABLE_NOLOGGING) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "alter table", "view or system table");
        return CT_ERROR;
    }

    if (!DB_IS_MAINTENANCE(session) && IS_SYS_DC(dc)) {
        // allow to add nullable column for upgrade online, the nullable check is in 
        if (!IS_CORE_SYS_TABLE(dc->uid, dc->oid) &&
            (def->action == ALTABLE_ADD_COLUMN || def->action == ALTABLE_ADD_CONSTRAINT) &&
            knl_is_online_upgrading(session)) {
            return CT_SUCCESS;
        }
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "alter table", "system table");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static bool32 knl_altable_logicrep_enabled(knl_session_t *session, knl_altable_def_t *def, knl_dictionary_t *dc)
{
    if (def->action == ALTABLE_ADD_COLUMN || def->action == ALTABLE_MODIFY_COLUMN ||
        def->action == ALTABLE_RENAME_COLUMN || def->action == ALTABLE_DROP_COLUMN) {
        return LOGIC_REP_DB_ENABLED(session) && LOGIC_REP_TABLE_ENABLED(session, DC_ENTITY(dc));
    }
    return CT_FALSE;
}

void knl_rename_table_write_logical(knl_handle_t se, knl_altable_def_t *def, knl_dictionary_t *dc)
{
    rd_rename_table_t rd_rename;
    rd_rename.op_type = RD_RENAME_TABLE;
    rd_rename.uid = dc->uid;
    rd_rename.oid = dc->oid;
    (void)cm_text2str(&def->table_def.new_name, rd_rename.new_name, CT_NAME_BUFFER_SIZE);
    log_put((knl_session_t *)se, RD_LOGIC_OPERATION, &rd_rename, sizeof(rd_rename_table_t), LOG_ENTRY_FLAG_NONE);
}

static void knl_altable_write_logical(knl_session_t *session, knl_altable_def_t *def, knl_dictionary_t *dc)
{
    rd_table_t rd_altable;

    bool32 has_logic = knl_altable_logicrep_enabled(session, def, dc);

    if (def->action == ALTABLE_RENAME_TABLE) {
        knl_rename_table_write_logical(session, def, dc);
    } else {
        rd_altable.op_type = RD_ALTER_TABLE;
        rd_altable.uid = dc->uid;
        rd_altable.oid = dc->oid;
        log_put(session, RD_LOGIC_OPERATION, &rd_altable, sizeof(rd_table_t), LOG_ENTRY_FLAG_NONE);
        if (has_logic) {
            log_append_data(session, (void *)(&def->action), sizeof(uint32));
        }
    }
}

static status_t knl_altable_with_action(knl_handle_t se, knl_handle_t stmt, knl_altable_def_t *def,
                                        knl_dictionary_t *dc, trig_name_list_t *trig)
{
    status_t status;

    switch (def->action) {
        case ALTABLE_ADD_COLUMN:
            status = db_altable_add_column(se, dc, stmt, def);
            break;

        case ALTABLE_MODIFY_COLUMN:
            status = db_altable_modify_column(se, dc, stmt, def);
            break;

        case ALTABLE_RENAME_COLUMN:
            status = db_altable_rename_column(se, dc, def);
            break;

        case ALTABLE_DROP_COLUMN:
            status = db_altable_drop_column(se, dc, def);
            break;

        case ALTABLE_ADD_CONSTRAINT:
            status = db_altable_add_cons(se, dc, def);
            break;

        case ALTABLE_DROP_CONSTRAINT:
            status = db_altable_drop_cons(se, dc, def);
            break;

        case ALTABLE_MODIFY_CONSTRAINT:
            status = CT_ERROR;
            CT_THROW_ERROR(ERR_INVALID_OPERATION, ",unsupported alter table operation");
            break;

        case ALTABLE_RENAME_CONSTRAINT:
            status = db_altable_rename_constraint(se, dc, def);
            break;

        case ALTABLE_TABLE_PCTFREE:
            status = db_altable_pctfree(se, dc, def);
            break;

        case ALTABLE_TABLE_INITRANS:
            status = db_altable_initrans(se, dc, def);
            break;

        case ALTABLE_MODIFY_STORAGE:
            status = db_altable_storage(se, dc, def);
            break;

        case ALTABLE_MODIFY_PART_INITRANS:
            status = db_altable_part_initrans(se, dc, &def->part_def);
            break;

        case ALTABLE_MODIFY_PART_STORAGE:
            status = db_altable_part_storage(se, dc, def);
            break;

        case ALTABLE_RENAME_TABLE:
            status = db_altable_rename_table(se, dc, def, trig);
            break;

        case ALTABLE_APPENDONLY:
            status = db_altable_appendonly(se, dc, def);
            break;

        case ALTABLE_DROP_PARTITION:
            status = db_altable_drop_part(se, dc, def, CT_FALSE);
            break;

        case ALTABLE_DROP_SUBPARTITION:
            status = db_altable_drop_subpartition(se, dc, def, CT_FALSE);
            break;

        case ALTABLE_TRUNCATE_PARTITION:
            status = db_altable_truncate_part(se, dc, &def->part_def);
            break;

        case ALTABLE_TRUNCATE_SUBPARTITION:
            status = db_altable_truncate_subpart(se, dc, &def->part_def);
            break;

        case ALTABLE_ADD_PARTITION:
            status = db_altable_add_part(se, dc, def);
            break;

        case ALTABLE_ADD_SUBPARTITION:
            status = db_altable_add_subpartition(se, dc, def);
            break;

        case ALTABLE_SPLIT_PARTITION:
            status = db_altable_split_part(se, dc, def);
            break;

        case ALTABLE_SPLIT_SUBPARTITION:
            status = db_altable_split_subpart(se, dc, def);
            break;

        case ALTABLE_AUTO_INCREMENT:
            status = db_altable_auto_increment(se, dc, def->table_def.serial_start);
            break;

        case ALTABLE_ENABLE_ALL_TRIG:
            status = db_altable_set_all_trig_status(se, dc, CT_TRUE);
            break;

        case ALTABLE_DISABLE_ALL_TRIG:
            status = db_altable_set_all_trig_status(se, dc, CT_FALSE);
            break;

        case ALTABLE_ENABLE_NOLOGGING:
            status = db_altable_enable_nologging(se, dc);
            break;

        case ALTABLE_DISABLE_NOLOGGING:
            status = db_altable_disable_nologging(se, dc);
            break;

        case ALTABLE_ENABLE_PART_NOLOGGING:
            status = db_altable_enable_part_nologging(se, dc, def);
            break;

        case ALTABLE_DISABLE_PART_NOLOGGING:
            status = db_altable_disable_part_nologging(se, dc, def);
            break;

        case ALTABLE_ENABLE_SUBPART_NOLOGGING:
            status = db_altable_enable_subpart_nologging(se, dc, def);
            break;

        case ALTABLE_DISABLE_SUBPART_NOLOGGING:
            status = db_altable_disable_subpart_nologging(se, dc, def);
            break;

        case ALTABLE_COALESCE_PARTITION:
            status = db_altable_coalesce_partition(se, dc, def);
            break;

        case ALTABLE_COALESCE_SUBPARTITION:
            status = db_altable_coalesce_subpartition(se, dc, def);
            break;

        case ALTABLE_APPLY_CONSTRAINT:
            status = db_altable_apply_constraint(se, dc, def);
            break;

        case ALTABLE_SET_INTERVAL_PART:
            status = db_altable_set_interval_part(se, dc, &def->part_def);
            break;

        case ALTABLE_ADD_LOGICAL_LOG:
            status = db_altable_add_logical_log(se, dc, def);
            break;

        case ALTABLE_DROP_LOGICAL_LOG:
            status = db_altable_drop_logical_log(se, dc, def);
            break;

        case ALTABLE_ENABLE_ROW_MOVE:
        case ALTABLE_DISABLE_ROW_MOVE:
        default:
            status = CT_ERROR;
            CT_THROW_ERROR(ERR_INVALID_OPERATION, ",unsupported alter table operation");
            break;
    }

    return status;
}

/*
 * perform alter table, move the knl_ddl_enabled to the outside,
 * @attention: SQL layer should not call this interface.
 * @param kernel session, knl_handle_t stmt, knl_altable_def_t * def
 */
status_t knl_perform_alter_table(knl_handle_t session, knl_handle_t stmt, knl_altable_def_t *def, bool32 is_lrep_log)
{
    knl_dictionary_t dc;
    status_t status;
    trig_name_list_t trig;
    errno_t ret;
    knl_session_t *se = (knl_session_t *)session;

    ret = memset_sp(&dc, sizeof(knl_dictionary_t), 0, sizeof(knl_dictionary_t));
    knl_securec_check(ret);
    if (dc_open(se, &def->user, &def->name, &dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc.type == DICT_TYPE_TABLE_EXTERNAL) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "alter table", "external organzied table");
        dc_close(&dc);
        return CT_ERROR;
    }

    if (knl_altable_check_table_type(se, def, &dc) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }

    if (knl_lock_table_self_parent_child_directly(session, &dc) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }

    log_add_lrep_ddl_begin(se);
    uint16 op_type = (def->action == ALTABLE_RENAME_TABLE) ? RD_RENAME_TABLE : RD_ALTER_TABLE;
    status = knl_altable_with_action(se, stmt, def, &dc, &trig);
    if (status == CT_SUCCESS) {
        status = db_write_ddl_op_for_parents(session, &((dc_entity_t*)dc.handle)->table);
    }
    if (status == CT_SUCCESS) {
        status = db_write_ddl_op_for_children(session, &((dc_entity_t*)dc.handle)->table);
    }

    if (status == CT_SUCCESS) {
        knl_altable_write_logical(se, def, &dc);
        if (is_lrep_log) {
            table_t *table = DC_TABLE(&dc);
            log_add_lrep_ddl_info(se, stmt, LOGIC_OP_TABLE, op_type, table);
        }
        log_add_lrep_ddl_end(se);

        SYNC_POINT(session, "SP_B1_ALTER_TABLE");
        SYNC_POINT_GLOBAL_START(CANTIAN_DDL_ALTER_TABLE_BEFORE_SYNC_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;
        knl_commit(session);
        SYNC_POINT_GLOBAL_START(CANTIAN_DDL_ALTER_TABLE_AFTER_SYNC_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;
        if (db_garbage_segment_handle(se, dc.uid, dc.oid, CT_FALSE) != CT_SUCCESS) {
            cm_spin_lock(&se->kernel->rmon_ctx.mark_mutex, NULL);
            se->kernel->rmon_ctx.delay_clean_segments = CT_TRUE;
            cm_spin_unlock(&se->kernel->rmon_ctx.mark_mutex);
            CT_LOG_RUN_ERR("failed to handle garbage segment");
        }

        if (!DB_IS_MAINTENANCE(se)) {
            knl_alter_table_after_commit(session, &dc, def, &trig);
        }

        se->stat->table_alters++;
    } else {
        log_add_lrep_ddl_end(se);
        knl_rollback(session, NULL);
    }

    dc_invalidate_children(se, (dc_entity_t *)dc.handle);
    dc_invalidate_parents(se, (dc_entity_t *)dc.handle);
    dc_invalidate(se, (dc_entity_t *)dc.handle);
    unlock_tables_directly(se);
    dc_close(&dc);

    if ((DB_IS_MAINTENANCE(se)) && IS_SYS_DC(&dc)) {
        if (knl_open_dc_by_id(session, dc.uid, dc.oid, &dc, CT_TRUE) != CT_SUCCESS) {
            CM_ABORT(0, "[DB] ABORT INFO: failed to update dictionary cache,"
                        "please check environment and restart instance");
        }
        dc_close(&dc);
    }

    return status;
}

static status_t knl_is_alter_systable_online(knl_session_t *session, knl_altable_def_t *def, bool32 *need_ddl_latch_x)
{
    knl_dictionary_t dc;
    errno_t ret = memset_sp(&dc, sizeof(knl_dictionary_t), 0, sizeof(knl_dictionary_t));
    knl_securec_check(ret);
    if (dc_open(session, &def->user, &def->name, &dc) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (!DB_IS_MAINTENANCE(session) && knl_is_online_upgrading(session) && IS_SYS_DC(&dc)) {
        *need_ddl_latch_x = CT_TRUE;
    }
    dc_close(&dc);
    return CT_SUCCESS;
}

status_t knl_alter_table(knl_handle_t session, knl_handle_t stmt, knl_altable_def_t *def, bool32 is_lrep_log)
{
    CT_LOG_RUN_INF("[DB] Start to alter table %s", T2S_EX(&def->name));
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_KNL_ALTER_TABLE, &tv_begin);
    knl_session_t *se = (knl_session_t *)session;
    status_t status;
    drlatch_t *ddl_latch = &se->kernel->db.ddl_latch;
    bool32 need_ddl_latch_x = CT_FALSE;

    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_ALTER_TABLE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    // for rolling upgrade, we allow to alter system table, and users can start other transactions at the same time.
    // to avoid other ddl write the system table which is being alter by rolling upgrade, we have to use ddl x latch
    // when alter system table during rolling upgrade
    if (knl_is_alter_systable_online(se, def, &need_ddl_latch_x) != CT_SUCCESS) {
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_ALTER_TABLE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }
    if(!need_ddl_latch_x) {
        status = knl_ddl_latch_s(ddl_latch, session, NULL);
    } else {
        status = knl_ddl_latch_x(session, NULL);
    }

    if (status != CT_SUCCESS) {
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_ALTER_TABLE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    if (def->action == ALTABLE_MODIFY_LOB) {
        status = db_altable_modify_lob((knl_session_t *)session, def);
    } else {
        status = knl_perform_alter_table(session, stmt, def, is_lrep_log);
    }
    if(!need_ddl_latch_x) {
        dls_unlatch(session, ddl_latch, NULL);
    } else {
        knl_ddl_unlatch_x(session);
    }

    cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_ALTER_TABLE, &tv_begin, status == CT_SUCCESS ?
                       IO_STAT_SUCCESS : IO_STAT_FAILED);
    CT_LOG_RUN_INF("[DB] Finish to alter table %s, ret:%d, action:%d", T2S_EX(&def->name), status, def->action);
    return status;
}

status_t knl_open_dc_by_index(knl_handle_t se, text_t *owner, text_t *table, text_t *idx_name, knl_dictionary_t *dc)
{
    knl_session_t *session = (knl_session_t *)se;
    uint32 uid;
    knl_index_desc_t desc;
    index_t *index = NULL;

    if (table == NULL) {
        if (!dc_get_user_id(session, owner, &uid)) {
            CT_THROW_ERROR(ERR_INDEX_NOT_EXIST, T2S(owner), T2S_EX(idx_name));
            return CT_ERROR;
        }

        if (db_fetch_index_desc(session, uid, CT_INVALID_ID32, idx_name, &desc) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (knl_open_dc_by_id(session, desc.uid, desc.table_id, dc, CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (knl_open_dc(session, owner, table, dc) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    index = dc_find_index_by_name(DC_ENTITY(dc), idx_name);
    if (index == NULL) {
        dc_close(dc);
        CT_THROW_ERROR(ERR_INDEX_NOT_EXIST, T2S(owner), T2S_EX(idx_name));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

bool32 knl_find_dc_by_tmpidx(knl_handle_t se, text_t *owner, text_t *idx_name)
{
    knl_session_t *session = (knl_session_t *)se;
    knl_temp_dc_t *temp_dc = session->temp_dc;
    dc_entry_t *entry = NULL;
    index_t *index = NULL;

    if (temp_dc == NULL) {
        return CT_FALSE;
    }

    for (uint32 i = 0; i < session->temp_table_capacity; i++) {
        entry = (dc_entry_t *)temp_dc->entries[i];
        if (entry == NULL) {
            continue;
        }

        index = dc_find_index_by_name(entry->entity, idx_name);
        if (index != NULL) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

status_t knl_alter_index_coalesce(knl_handle_t session, knl_alindex_def_t *def)
{
    knl_dictionary_t dc;
    status_t status = CT_SUCCESS;
    bool32 lock_inuse = CT_FALSE;
    index_t *index = NULL;
    knl_session_t *se = (knl_session_t *)session;
    drlatch_t *ddl_latch = &se->kernel->db.ddl_latch;
    text_t *table_name;

    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_ddl_latch_s(ddl_latch, session, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    table_name = &def->table;

    if (knl_open_dc_by_index(se, &def->user, table_name, &def->name, &dc) != CT_SUCCESS) {
        dls_unlatch(session, ddl_latch, NULL);
        return CT_ERROR;
    }

    if (!lock_table_without_xact(se, dc.handle, &lock_inuse)) {
        dc_close(&dc);
        dls_unlatch(session, ddl_latch, NULL);
        return CT_ERROR;
    }

    index = dc_find_index_by_name(DC_ENTITY(&dc), &def->name);
    if (index == NULL) {
        unlock_table_without_xact(se, dc.handle, lock_inuse);
        dc_close(&dc);
        CT_THROW_ERROR(ERR_INDEX_NOT_EXIST, T2S(&def->user), T2S_EX(&def->name));
        dls_unlatch(session, ddl_latch, NULL);
        return CT_ERROR;
    }

    if (def->type == ALINDEX_TYPE_MODIFY_PART) {
        status = db_alter_part_index_coalesce(se, &dc, def, index);
    } else if (def->type == ALINDEX_TYPE_MODIFY_SUBPART) {
        status = db_alter_subpart_index_coalesce(se, &dc, def, index);
    } else if (def->type == ALINDEX_TYPE_COALESCE) {
        status = db_alter_index_coalesce(se, &dc, index);
    }

    unlock_table_without_xact(se, dc.handle, lock_inuse);
    dc_close(&dc);
    dls_unlatch(session, ddl_latch, NULL);

    return status;
}

uint32 knl_get_index_vcol_count(knl_index_desc_t *desc)
{
    uint32 vcol_count = 0;

    if (!desc->is_func) {
        return 0;
    }

    for (uint32 i = 0; i < desc->column_count; i++) {
        if (desc->columns[i] >= DC_VIRTUAL_COL_START) {
            vcol_count++;
        }
    }

    return vcol_count;
}

void knl_get_index_name(knl_index_desc_t *desc, char *name, uint32 max_len)
{
    errno_t ret = strncpy_s(name, max_len, desc->name, strlen(desc->name));
    knl_securec_check(ret);
}

status_t knl_alter_index_rename(knl_handle_t session, knl_alt_index_prop_t *def, knl_dictionary_t *dc,
                                index_t *old_index)
{
    knl_session_t *se = (knl_session_t *)session;
    knl_cursor_t *cursor = NULL;
    char old_name[CT_NAME_BUFFER_SIZE];
    char new_name[CT_NAME_BUFFER_SIZE];
    bool32 is_found = CT_FALSE;
    errno_t ret;

    CM_SAVE_STACK(se->stack);
    cursor = knl_push_cursor(se);
    if (db_fetch_sysindex_row(se, cursor, dc->uid, dc->oid, &def->new_name,
                              CURSOR_ACTION_SELECT, &is_found) != CT_SUCCESS) {
        CM_RESTORE_STACK(se->stack);
        return CT_ERROR;
    }
    CM_RESTORE_STACK(se->stack);

    if (is_found) {
        CT_THROW_ERROR(ERR_OBJECT_EXISTS, "index", T2S(&def->new_name));
        return CT_ERROR;
    }

    knl_get_index_name(&old_index->desc, old_name, CT_NAME_BUFFER_SIZE);

    ret = strncpy_s(new_name, CT_NAME_BUFFER_SIZE, def->new_name.str, def->new_name.len);
    knl_securec_check(ret);

    cm_str2text_safe(new_name, (uint32)strlen(new_name), &def->new_name);
    if (db_update_index_name(se, old_index->desc.uid, old_index->desc.table_id,
                             old_name, &def->new_name) != CT_SUCCESS) {
        int32 err_code = cm_get_error_code();
        if (err_code == ERR_DUPLICATE_KEY) {
            cm_reset_error();
            CT_THROW_ERROR(ERR_OBJECT_EXISTS, "index", T2S(&def->new_name));
        }

        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t knl_alter_index_with_action(knl_session_t *session,
                                            knl_alindex_def_t *def,
                                            knl_dictionary_t *dc,
                                            index_t *index)
{
    status_t status = CT_SUCCESS;
    switch (def->type) {
        case ALINDEX_TYPE_REBUILD:
            status = db_alter_index_rebuild(session, def, dc, index);
            break;

        case ALINDEX_TYPE_REBUILD_PART:
        case ALINDEX_TYPE_REBUILD_SUBPART:
            if (def->rebuild.specified_parts > 1 || def->rebuild.parallelism) {
                status = db_alter_index_rebuild(session, def, dc, index);
            } else {
                status = db_alter_index_rebuild_part(session, def, dc, index);
            }
            break;

        case ALINDEX_TYPE_RENAME:
            status = knl_alter_index_rename(session, &def->idx_def, dc, index);
            break;

        case ALINDEX_TYPE_UNUSABLE:
            status = db_alter_index_unusable(session, index);
            break;

        case ALINDEX_TYPE_INITRANS:
            status = db_alter_index_initrans(session, def, index);
            break;

        case ALINDEX_TYPE_MODIFY_PART:
            status = db_alter_index_partition(session, def, dc, index);
            break;
        case ALINDEX_TYPE_MODIFY_SUBPART:
            status = db_alter_index_subpartition(session, def, dc, index);
            break;
        default:
            CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "alter index not in type rebuild or rebuild_part");
            status = CT_ERROR;
    }
    return status;
}

status_t knl_alter_index(knl_handle_t session, knl_handle_t stmt, knl_alindex_def_t *def)
{
    knl_dictionary_t dc;
    status_t status;
    rd_table_t redo;
    index_t *index = NULL;
    knl_session_t *se = (knl_session_t *)session;
    drlatch_t *ddl_latch = &se->kernel->db.ddl_latch;
    text_t *table_name;
    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_ddl_latch_s(ddl_latch, session, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }
    table_name = &def->table;
    if (knl_open_dc_by_index(se, &def->user, table_name, &def->name, &dc) != CT_SUCCESS) {
        dls_unlatch(session, ddl_latch, NULL);
        return CT_ERROR;
    }

    if (!DB_IS_MAINTENANCE(se) && IS_SYS_DC(&dc)) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "alter index", "system table");
        dc_close(&dc);
        dls_unlatch(session, ddl_latch, NULL);
        return CT_ERROR;
    }

    bool32 timeout_default = CT_TRUE;
    if (def->type == ALINDEX_TYPE_REBUILD || def->type == ALINDEX_TYPE_REBUILD_PART) {
        timeout_default = !def->rebuild.is_online;
    }

    uint32 timeout = timeout_default ? se->kernel->attr.ddl_lock_timeout : LOCK_INF_WAIT;
    if (IS_AUTO_REBUILD(def->rebuild.lock_timeout)) {
        timeout = def->rebuild.lock_timeout;
        dc_entry_t *entry = DC_ENTRY(&dc);

        if (entry != NULL && entry->sch_lock && entry->sch_lock->mode == LOCK_MODE_IX) {
            dc_close(&dc);
            dls_unlatch(session, ddl_latch, NULL);
            CT_THROW_ERROR(ERR_RESOURCE_BUSY);
            return CT_ERROR;
        }
    }
    if (lock_table_directly(se, &dc, timeout) != CT_SUCCESS) {
        dc_close(&dc);
        dls_unlatch(session, ddl_latch, NULL);
        return CT_ERROR;
    }

    if (lock_parent_table_directly(se, dc.handle, timeout_default) != CT_SUCCESS) {
        unlock_tables_directly(se);
        dc_close(&dc);
        dls_unlatch(session, ddl_latch, NULL);
        return CT_ERROR;
    }

    if (lock_child_table_directly(se, dc.handle, timeout_default) != CT_SUCCESS) {
        unlock_tables_directly(se);
        dc_close(&dc);
        dls_unlatch(session, ddl_latch, NULL);
        return CT_ERROR;
    }

    index = dc_find_index_by_name(DC_ENTITY(&dc), &def->name);
    if (index == NULL) {
        unlock_tables_directly(se);
        dc_close(&dc);
        dls_unlatch(session, ddl_latch, NULL);
        CT_THROW_ERROR(ERR_INDEX_NOT_EXIST, T2S(&def->user), T2S_EX(&def->name));
        return CT_ERROR;
    }

    log_add_lrep_ddl_begin(se);
    status = knl_alter_index_with_action(session, def, &dc, index);
    if (status == CT_SUCCESS) {
        status = db_write_ddl_op_for_children(session, &((dc_entity_t*)dc.handle)->table);
    }

    /* alter index will reload dc entity, so memory of index may be reused by other table, we
     * should use uid, oid of dc instead of index->desc.uid while writing logic log.
     */
    if (status == CT_SUCCESS) {
        redo.op_type = RD_ALTER_INDEX;
        redo.uid = dc.uid;
        redo.oid = dc.oid;
        log_put(se, RD_LOGIC_OPERATION, &redo, sizeof(rd_table_t), LOG_ENTRY_FLAG_NONE);

        log_add_lrep_ddl_info(se, stmt, LOGIC_OP_INDEX, RD_ALTER_INDEX, NULL);
        log_add_lrep_ddl_end(se);
        if (DB_IS_MAINTENANCE(se) && IS_CORE_SYS_TABLE(dc.uid, dc.oid)) {
            if (db_save_core_ctrl(se) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[DB] failed to save core control file");
                dc_close(&dc);
                dls_unlatch(session, ddl_latch, NULL);
                return CT_ERROR;
            }
        }
        SYNC_POINT_GLOBAL_START(CANTIAN_DDL_ALTER_INDEX_BEFORE_SYNC_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;
        knl_commit(session);
        SYNC_POINT_GLOBAL_START(CANTIAN_DDL_ALTER_INDEX_AFTER_SYNC_ABORT, NULL, 0);
        SYNC_POINT_GLOBAL_END;
    } else {
        log_add_lrep_ddl_end(se);
        knl_rollback(session, NULL);
    }

    dc_invalidate_children(se, (dc_entity_t *)dc.handle);
    dc_invalidate_parents(se, (dc_entity_t *)dc.handle);
    if (SCH_LOCKED_EXCLUSIVE(dc.handle)) {
        dc_invalidate(se, (dc_entity_t *)dc.handle);
    }

    if (status == CT_SUCCESS) {
        db_update_index_clean_option(session, def, index->desc);
    }

    if (db_garbage_segment_handle(se, dc.uid, dc.oid, CT_FALSE) != CT_SUCCESS) {
        cm_spin_lock(&se->kernel->rmon_ctx.mark_mutex, NULL);
        se->kernel->rmon_ctx.delay_clean_segments = CT_TRUE;
        cm_spin_unlock(&se->kernel->rmon_ctx.mark_mutex);
        CT_LOG_RUN_ERR("[DB] failed to handle garbage segment");
    }
    dc_close(&dc);
    unlock_tables_directly(se);
    if (DB_IS_MAINTENANCE(se) && IS_CORE_SYS_TABLE(dc.uid, dc.oid)) {
        if (dc_load_core_table(se, dc.oid) != CT_SUCCESS) {
            CM_ABORT(0, "[DB] ABORT INFO: failed to update core system dictionary cache,\
            please check environment and restart instance");
        }
    } else if (DB_IS_MAINTENANCE(se) && IS_SYS_DC(&dc)) {
        if (knl_open_dc_by_id(session, dc.uid, dc.oid, &dc, CT_TRUE) != CT_SUCCESS) {
            CM_ABORT(0, "[DB] ABORT INFO: failed to update dictionary cache,\
            please check environment and restart instance");
        }
        dc_close(&dc);
    }
    dls_unlatch(session, ddl_latch, NULL);

    return status;
}

status_t knl_purge(knl_handle_t session, knl_purge_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;
    status_t status;
    drlatch_t *ddl_latch = &se->kernel->db.ddl_latch;

    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_ddl_latch_s(ddl_latch, session, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }
    status = db_purge(se, def);
    dls_unlatch(session, ddl_latch, NULL);

    return status;
}

static inline bool8 knl_check_systables_executable(knl_session_t *session, knl_dictionary_t dc)
{
    if (IS_CORE_SYS_TABLE(dc.uid, dc.oid)) {
        return CT_FALSE;
    }

    if (!DB_IS_MAINTENANCE(session) && IS_SYS_DC(&dc)) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

static status_t knl_internal_drop_table_precheck(knl_session_t *se, knl_drop_def_t *def, knl_dictionary_t *dc,
                                                 bool32 lock)
{
    // precheck for drop table, and lock table if needed
    if (SYNONYM_EXIST(dc)) {
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&def->owner), T2S_EX(&def->name));
        return CT_ERROR;
    }
    if (def->temp) {
        if (!(dc->type == DICT_TYPE_TEMP_TABLE_TRANS || dc->type == DICT_TYPE_TEMP_TABLE_SESSION)) {
            CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "drop temporary table",
                           "common table or system table only for temp");
            return CT_ERROR;
        }
    }
    if (dc->type < DICT_TYPE_TABLE || dc->type > DICT_TYPE_TABLE_EXTERNAL) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "drop table", "temp table or system table");
        return CT_ERROR;
    }

    if (!knl_check_systables_executable(se, *dc)) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "drop table", "system table");
        return CT_ERROR;
    }

    if (lock && knl_lock_table_self_parent_child_directly(se, dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // if table has ddm policy, please drop policy first
    if (db_check_ddm_rule_by_obj(se, dc->uid, dc->oid) != CT_SUCCESS) {
        if (lock) {
            unlock_tables_directly(se);
        }
        return CT_ERROR;
    }
    return CT_SUCCESS;
}
status_t knl_internal_drop_table_handle_ref(knl_handle_t session, knl_drop_def_t *def, knl_dictionary_t dc)
{
    knl_session_t *se = (knl_session_t *)session;
    if (def->options & DROP_CASCADE_CONS) {
        if (db_drop_cascade_cons(se, dc.uid, dc.oid) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to cascade cons when drop parent table");
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }
    if (DB_ATTR_COMPATIBLE_MYSQL(se) && (def->options & DROP_FOR_MYSQL_COPY)) {
        // for mysql copy, update the ref table id in dropping table for mysql copy
        knl_dictionary_t new_dc;
        if (knl_open_dc_by_id(session, def->new_user_id, def->new_parent_id, &new_dc, CT_TRUE) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[for mysql] open new parent table id %u fail when update ref cons in mysql copy",
                           def->new_parent_id);
            return CT_ERROR;
        }
        if (knl_update_ref_syscons4mysql(se, &dc, &new_dc) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to update ref cons for drop table in mysql copy");
            dc_close(&new_dc);
            return CT_ERROR;
        }
        dc_close(&new_dc);
        return CT_SUCCESS;
    }
    if (DB_ATTR_COMPATIBLE_MYSQL(se) && (def->options & DROP_NO_CHECK_FK)) {
        if (db_invalid_fk_cons(se, &dc) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DB] failed to invalide foreign key when drop parent table");
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }
    CT_THROW_ERROR(ERR_TABLE_IS_REFERENCED);
    return CT_ERROR;
}

void knl_drop_table_after_commit4mysql(knl_handle_t session, knl_dictionary_t *dc, knl_drop_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;
    core_ctrl_t *core = &se->kernel->db.ctrl.core;
    table_t *table = DC_TABLE(dc);
    db_drop_table_drop_dc(se, dc, table);
    if (db_table_is_referenced(se, table, CT_FALSE)) {
        dc_invalidate_children(se, DC_ENTITY(dc));
    }
    bool32 is_drop = (dc->type != DICT_TYPE_TABLE || table->desc.space_id == SYS_SPACE_ID ||
               table->desc.space_id == core->sysaux_space || def->purge || !se->kernel->attr.recyclebin);
    unlock_tables_directly(session);
    if (is_drop) {
        dc_free_entry(se, DC_ENTRY(dc));
    }
}

status_t knl_internal_drop_table(knl_handle_t session, knl_handle_t stmt, knl_drop_def_t *def, bool32 commit)
{
    knl_dictionary_t dc;
    status_t status = CT_SUCCESS;
    bool32 is_referenced = CT_FALSE;
    bool32 is_drop = CT_FALSE;
    knl_session_t *se = (knl_session_t *)session;
    core_ctrl_t *core = &se->kernel->db.ctrl.core;

    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (dc_open(se, &def->owner, &def->name, &dc) != CT_SUCCESS) {
        return CT_ERROR;
    }
    // precheck and lock table for drop
    if (knl_internal_drop_table_precheck(se, def, &dc, commit) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }

    table_t *table = DC_TABLE(&dc);
    is_referenced = db_table_is_referenced(se, table, CT_FALSE);
    if (is_referenced && knl_internal_drop_table_handle_ref(se, def, dc) != CT_SUCCESS) {
        unlock_tables_directly(se);
        dc_close(&dc);
        return CT_ERROR;
    }
    if (db_altable_drop_logical_log(se, &dc, NULL) != CT_SUCCESS) {
        unlock_tables_directly(se);
        dc_close(&dc);
        CT_THROW_ERROR(ERR_DROP_LOGICAL_LOG);
        return CT_ERROR;
    }

    is_drop = (dc.type != DICT_TYPE_TABLE || table->desc.space_id == SYS_SPACE_ID ||
        table->desc.space_id == core->sysaux_space || def->purge || !se->kernel->attr.recyclebin);
    log_add_lrep_ddl_begin(se);
    status = is_drop ? db_drop_table(se, stmt, &dc, commit) : rb_drop_table(se, stmt, &dc, commit);

    if (!commit) {
        dc_close(&dc);
        return status;
    }

    if (status == CT_SUCCESS && is_referenced) {
        status = db_write_ddl_op_for_children(session, table);
    }
    log_add_lrep_ddl_end(se);

    if (status != CT_SUCCESS) {
        knl_rollback(session, NULL);
        unlock_tables_directly(se);
        dc_close(&dc);
        return CT_ERROR;
    }

    if (is_referenced) {
        dc_invalidate_children(se, (dc_entity_t *)dc.handle);
    }
    unlock_tables_directly(se);
    if (is_drop) {
        dc_free_entry(se, DC_ENTRY(&dc));
    }
    dc_close(&dc);
    return status;
}

void knl_drop_table_log_put(knl_handle_t session, knl_handle_t stmt, knl_drop_def_t *def,
                            knl_dictionary_t *dc)
{
    rd_drop_table_t redo;
    table_t *table = DC_TABLE(dc);
    knl_session_t *se = (knl_session_t *)session;
    core_ctrl_t *core = &se->kernel->db.ctrl.core;
    bool32 is_drop = (dc->type != DICT_TYPE_TABLE || table->desc.space_id == SYS_SPACE_ID ||
               table->desc.space_id == core->sysaux_space || def->purge || !se->kernel->attr.recyclebin);

    redo.op_type = RD_DROP_TABLE;
    redo.purge = is_drop;
    redo.uid = table->desc.uid;
    redo.oid = table->desc.id;
    redo.org_scn = table->desc.org_scn;
    errno_t err = strcpy_sp(redo.name, CT_NAME_BUFFER_SIZE, table->desc.name);
    knl_securec_check(err);
    log_put(se, RD_LOGIC_OPERATION, &redo, sizeof(rd_drop_table_t), LOG_ENTRY_FLAG_NONE);
    log_add_lrep_ddl_info(se, stmt, LOGIC_OP_TABLE, RD_DROP_TABLE, table);
}

status_t knl_drop_table(knl_handle_t session, knl_handle_t stmt, knl_drop_def_t *def)
{
    CT_LOG_RUN_INF("[DB] Start to drop table %s", T2S_EX(&def->name));
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_KNL_DROP_TABLE, &tv_begin);
    knl_session_t *se = (knl_session_t *)session;
    status_t status;
    drlatch_t *ddl_latch = &se->kernel->db.ddl_latch;
    dc_user_t *user = NULL;

    if (dc_open_user(se, &def->owner, &user) != CT_SUCCESS) {
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_DROP_TABLE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    dls_latch_x(session, &user->user_latch, se->id, NULL);
    if (knl_ddl_latch_s(ddl_latch, session, NULL) != CT_SUCCESS) {
        dls_unlatch(session, &user->user_latch, NULL);
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_DROP_TABLE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    status = knl_internal_drop_table(session, stmt, def, CT_TRUE);
    dls_unlatch(session, ddl_latch, NULL);
    dls_unlatch(session, &user->user_latch, NULL);
    cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_DROP_TABLE, &tv_begin, status == CT_SUCCESS ?
                       IO_STAT_SUCCESS : IO_STAT_FAILED);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_WAR("[DB] Finish to drop table %s, ret:%d", T2S_EX(&def->name), status);
    } else {
        CT_LOG_RUN_INF("[DB] Finish to drop table %s, ret:%d", T2S_EX(&def->name), status);
    }
    return status;
}

status_t knl_drop_table_no_commit4mysql(knl_handle_t session, knl_handle_t stmt, knl_drop_def_t *def)
{
    // interface for mysql, drop table without commit or rollback,
    // user latch, ddl latch, and table lock are not locked inside, must lock user, ddl, and table before this interface
    // note the lock sequence: add user lock first and then the ddl lock, and then table lock
    CT_LOG_RUN_INF("[For MYSQL] Start to drop table %s without commit", T2S_EX(&def->name));
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_KNL_DROP_TABLE, &tv_begin);
    status_t status = CT_SUCCESS;
    knl_session_t *se = (knl_session_t *)session;
    if (DB_ATTR_COMPATIBLE_MYSQL(se) && (def->options & DROP_FOR_MYSQL_COPY)) {
        // for copy in mysql, the table has already been renamed, we have to update this dc
        knl_dictionary_t dc;
        if (dc_open(se, &def->owner, &def->name, &dc) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[For MYSQL]: update dc for drop table in copy algorithm, dc_open failed");
            return CT_ERROR;
        }
        dc_invalidate(session, (dc_entity_t *)dc.handle);
        dc_close(&dc);
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_DROP_TABLE_FAIL, &status, CT_ERROR);
    status = knl_internal_drop_table(session, stmt, def, CT_FALSE);
    SYNC_POINT_GLOBAL_END;

    cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_DROP_TABLE, &tv_begin, status == CT_SUCCESS ?
                       IO_STAT_SUCCESS : IO_STAT_FAILED);
    CT_LOG_RUN_INF("[For MYSQL] Finish to drop table %s without commit, ret:%d", T2S_EX(&def->name), status);
    return status;
}

status_t knl_drop_index(knl_handle_t session, knl_handle_t stmt, knl_drop_def_t *def)
{
    knl_dictionary_t dc;
    rd_table_t redo;
    index_t *index = NULL;
    knl_session_t *se = (knl_session_t *)session;
    text_t *table_name = NULL;
    drlatch_t *ddl_latch = &se->kernel->db.ddl_latch;

    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    table_name = def->ex_name.len > 0 ? &def->ex_name : NULL;

    if (knl_open_dc_by_index(se, &def->owner, table_name, &def->name, &dc) != CT_SUCCESS) {
        if (!(def->options & DROP_IF_EXISTS)) {
            return CT_ERROR;
        }
        int32 err_code = cm_get_error_code();
        if (err_code == ERR_OBJECT_NOT_EXISTS || err_code == ERR_INDEX_NOT_EXIST) {
            cm_reset_error();
            return CT_SUCCESS;
        }
        return CT_ERROR;
    }

    if (!knl_check_systables_executable(se, dc)) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "drop index", "system table");
        dc_close(&dc);
        return CT_ERROR;
    }

    if (knl_ddl_latch_s(ddl_latch, session, NULL) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }

    uint32 timeout = se->kernel->attr.ddl_lock_timeout;
    if (lock_table_directly(se, &dc, timeout) != CT_SUCCESS) {
        dc_close(&dc);
        dls_unlatch(session, ddl_latch, NULL);
        return CT_ERROR;
    }

    if (lock_child_table_directly(se, dc.handle, CT_TRUE) != CT_SUCCESS) {
        unlock_tables_directly(se);
        dc_close(&dc);
        dls_unlatch(session, ddl_latch, NULL);
        return CT_ERROR;
    }

    index = dc_find_index_by_name(DC_ENTITY(&dc), &def->name);
    if (index == NULL) {
        unlock_tables_directly(se);
        dc_close(&dc);
        dls_unlatch(session, ddl_latch, NULL);
        if (def->options & DROP_IF_EXISTS) {
            return CT_SUCCESS;
        }
        CT_THROW_ERROR(ERR_INDEX_NOT_EXIST, T2S(&def->owner), T2S_EX(&def->name));
        return CT_ERROR;
    }

    if (index->desc.is_enforced) {
        unlock_tables_directly(se);
        dc_close(&dc);
        dls_unlatch(session, ddl_latch, NULL);
        CT_THROW_ERROR(ERR_INDEX_ENFORCEMENT);
        return CT_ERROR;
    }

    log_add_lrep_ddl_begin(se);
    if (db_drop_index(se, index, &dc) != CT_SUCCESS) {
        log_add_lrep_ddl_end(se);
        knl_rollback(se, NULL);
        unlock_tables_directly(se);
        dc_close(&dc);
        dls_unlatch(session, ddl_latch, NULL);
        return CT_ERROR;
    }

    redo.op_type = RD_DROP_INDEX;
    redo.uid = dc.uid;
    redo.oid = dc.oid;
    log_put(se, RD_LOGIC_OPERATION, &redo, sizeof(rd_table_t), LOG_ENTRY_FLAG_NONE);
    log_add_lrep_ddl_info(se, stmt, LOGIC_OP_INDEX, RD_DROP_INDEX, NULL);
    log_add_lrep_ddl_end(se);

    status_t status = db_write_ddl_op_for_children(se, &((dc_entity_t*)dc.handle)->table);
    if (status != CT_SUCCESS) {
        knl_rollback(se, NULL);
        unlock_tables_directly(se);
        dc_close(&dc);
        dls_unlatch(session, ddl_latch, NULL);
        return CT_ERROR;
    }

    SYNC_POINT(session, "SP_B1_DROP_INDEX");
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_DROP_INDEX_BEFORE_SYNC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    knl_commit(session);
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_DROP_INDEX_AFTER_SYNC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    if (db_garbage_segment_handle(se, dc.uid, dc.oid, CT_FALSE) != CT_SUCCESS) {
        cm_spin_lock(&se->kernel->rmon_ctx.mark_mutex, NULL);
        se->kernel->rmon_ctx.delay_clean_segments = CT_TRUE;
        cm_spin_unlock(&se->kernel->rmon_ctx.mark_mutex);
        CT_LOG_RUN_ERR("failed to handle garbage segment");
    }

    dc_invalidate_children(se, DC_ENTITY(&dc));
    dc_invalidate(se, DC_ENTITY(&dc));
    dc_close(&dc);
    unlock_tables_directly(se);

    if ((DB_IS_MAINTENANCE(se)) && IS_SYS_DC(&dc)) {
        if (knl_open_dc_by_id(session, dc.uid, dc.oid, &dc, CT_TRUE) != CT_SUCCESS) {
            CM_ABORT(0, "[DB] ABORT INFO: failed to update dictionary cache,"
                        "please check environment and restart instance");
        }
        dc_close(&dc);
    }
    dls_unlatch(session, ddl_latch, NULL);

    return CT_SUCCESS;
}

status_t knl_drop_view(knl_handle_t session, knl_handle_t stmt, knl_drop_def_t *def)
{
    knl_dictionary_t dc;
    status_t status;
    knl_dict_type_t obj_type;
    knl_session_t *se = (knl_session_t *)session;
    dc_user_t *user = NULL;
    bool32 need_latch = (stmt != NULL) && (DB_IS_CLUSTER(se));  /* latch is not needed when doing drop user. */

    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if ((def->options & DROP_IF_EXISTS) && !dc_object_exists(se, &def->owner, &def->name, &obj_type)) {
        return CT_SUCCESS;
    }

    if (dc_open_user(se, &def->owner, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (need_latch) {
        dls_latch_x(session, &user->user_latch, se->id, NULL);
    }

    if (dc_open(se, &def->owner, &def->name, &dc) != CT_SUCCESS) {
        if (need_latch) {
            dls_unlatch(session, &user->user_latch, NULL);
        }
        return CT_ERROR;
    }

    if (dc.type == DICT_TYPE_DYNAMIC_VIEW || dc.type == DICT_TYPE_GLOBAL_DYNAMIC_VIEW) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "drop view", "dynamic view");
        dc_close(&dc);
        if (need_latch) {
            dls_unlatch(session, &user->user_latch, NULL);
        }
        return CT_ERROR;
    }

    if (SYNONYM_EXIST(&dc) || dc.type != DICT_TYPE_VIEW) {
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&def->owner), T2S_EX(&def->name));
        dc_close(&dc);
        if (need_latch) {
            dls_unlatch(session, &user->user_latch, NULL);
        }
        return CT_ERROR;
    }

    status = db_drop_view(se, stmt, &dc);
    dc_close(&dc);

    if (need_latch) {
        dls_unlatch(session, &user->user_latch, NULL);
    }

    return status;
}

status_t knl_truncate_table_lock_table(knl_handle_t session, knl_dictionary_t *dc)
{
    knl_session_t *se = (knl_session_t *)session;

    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    uint32 timeout = se->kernel->attr.ddl_lock_timeout;
    if (CT_SUCCESS != lock_table_directly(se, dc, timeout)) {
        CT_LOG_RUN_ERR("truncate table lock table fail");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t knl_check_truncate_table(knl_session_t *session, knl_trunc_def_t *def, knl_dictionary_t dc)
{
    if (SYNONYM_EXIST(&dc)) {
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&def->owner), T2S_EX(&def->name));
        return CT_ERROR;
    }

    if (dc.type == DICT_TYPE_TABLE_EXTERNAL) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "truncate table", "external organized table");
        return CT_ERROR;
    }

    if (dc.type < DICT_TYPE_TABLE || dc.type > DICT_TYPE_TABLE_NOLOGGING) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "truncate table", "view or system table");
        return CT_ERROR;
    }

    if (IS_SYS_DC(&dc)) {
        if (dc.oid == SYS_AUDIT_ID || SYS_STATS_TABLE_ENABLE_TRUNCATE(dc, session)) {
            return CT_SUCCESS;
        }

        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "truncate table", "system table");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t knl_truncate_table_precheck(knl_handle_t session, knl_trunc_def_t *def, knl_dictionary_t *dc,
                                            bool32 *no_segment)
{
    knl_session_t *se = (knl_session_t *)session;
    if (knl_check_truncate_table(se, def, *dc) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TRUNCATE TABLE] Failed to check table %s", T2S_EX(&def->name));
        return CT_ERROR;
    }
    table_t *table = DC_TABLE(dc);
    if (db_table_is_referenced(se, table, CT_TRUE)) {
        if (!(DB_ATTR_COMPATIBLE_MYSQL(se) && def->no_need_check_fk)) {
            CT_THROW_ERROR(ERR_TABLE_IS_REFERENCED);
            return CT_ERROR;
        }
    }
    /* reset serial value */
    if (knl_reset_serial_value(session, dc->handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TRUNCATE TABLE] Failed to check table %s", T2S_EX(&def->name));
        return CT_ERROR;
    }
    if (dc->type == DICT_TYPE_TABLE || dc->type == DICT_TYPE_TABLE_NOLOGGING) {
        if (!db_table_has_segment(se, dc)) {
            *no_segment = CT_TRUE;
            CT_LOG_RUN_INF("[DB] Sucess to truncate table %s", T2S_EX(&def->name));
        }
    }
    return CT_SUCCESS;
}

void knl_truncate_table_log_put(knl_handle_t session, knl_handle_t stmt, knl_dictionary_t *dc)
{
    knl_session_t *se = (knl_session_t *)session;
    rd_table_t redo;
    table_t *table = DC_TABLE(dc);

    redo.op_type = RD_TRUNCATE_TABLE;
    redo.uid = dc->uid;
    redo.oid = dc->oid;
    if (IS_LOGGING_TABLE_BY_TYPE(dc->type)) {
        log_put(se, RD_LOGIC_OPERATION, &redo, sizeof(rd_table_t), LOG_ENTRY_FLAG_NONE);
    }
    log_add_lrep_ddl_info(se, stmt, LOGIC_OP_TABLE, RD_TRUNCATE_TABLE, table);
}

void knl_truncate_table_invalidate_dc(knl_handle_t session, knl_dictionary_t *dc,
                                      bool32 is_changed, bool32 is_not_rcyclebin)
{
    knl_session_t *se = (knl_session_t *)session;
    table_t *table = DC_TABLE(dc);
    // it means that the state(is_invalid) of global index is changed when is_changed is true,
    // then we need invalidate dc
    if (is_not_rcyclebin && !is_changed && table->ashrink_stat == ASHRINK_END) {
        db_update_seg_scn(se, dc);
    } else {
        dc_invalidate(se, DC_ENTITY(dc));
    }
}

static status_t knl_truncate_table_internal(knl_session_t *se, knl_trunc_def_t *def, knl_dictionary_t *dc)
{
    status_t status = CT_ERROR;
    table_t *table = DC_TABLE(dc);
    def->is_not_rcyclebin = dc->type != DICT_TYPE_TABLE || table->desc.space_id == SYS_SPACE_ID ||
                       def->option != TRUNC_RECYCLE_STORAGE || !se->kernel->attr.recyclebin ||
                       IS_SYS_STATS_TABLE(dc->uid, dc->oid);
    log_add_lrep_ddl_begin(se);
    if (def->is_not_rcyclebin) {
        // when the state(is_invalid) of global index is changed, the flag is_changed will be set to CT_TRUE
        status = db_truncate_table_prepare(se, dc, def->option & TRUNC_REUSE_STORAGE, &(def->is_changed));
    } else {
        status = rb_truncate_table(se, dc);
    }
    return status;
}

void knl_truncate_table_after_commit(knl_handle_t session, knl_trunc_def_t *def, knl_dictionary_t *dc)
{
    knl_session_t *se = (knl_session_t *)session;

    if (db_garbage_segment_handle(se, dc->uid, dc->oid, CT_FALSE) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("failed to handle garbage segment");
        def->is_changed = CT_TRUE;  // if garbage segment has not been cleaned, must load latest dc;
        db_force_truncate_table(se, dc, def->option & TRUNC_REUSE_STORAGE, def->is_not_rcyclebin);
        cm_spin_lock(&se->kernel->rmon_ctx.mark_mutex, NULL);
        se->kernel->rmon_ctx.delay_clean_segments = CT_TRUE;
        cm_spin_unlock(&se->kernel->rmon_ctx.mark_mutex);
    }

    knl_truncate_table_invalidate_dc(session, dc, def->is_changed, def->is_not_rcyclebin);
}

void knl_truncate_table_after_rollback(knl_handle_t session, knl_trunc_def_t *def,
                                     knl_dictionary_t *dc)
{
    knl_session_t *se = (knl_session_t *)session;
    if (dc_locked_by_self(se, ((dc_entity_t *)dc->handle)->entry)) {
        knl_truncate_table_invalidate_dc(session, dc, def->is_changed, def->is_not_rcyclebin);
    }
}

status_t knl_truncate_table(knl_handle_t session, knl_handle_t stmt, knl_trunc_def_t *def)
{
    CT_LOG_RUN_INF("[DB] Start to truncate table %s", T2S_EX(&def->name));
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_KNL_TRUNCATE_TABLE, &tv_begin);
    knl_dictionary_t dc;
    status_t status = CT_ERROR;
    knl_session_t *se = (knl_session_t *)session;
    bool32 no_segment = CT_FALSE;

    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_TRUNCATE_TABLE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    if (CT_SUCCESS != dc_open(se, &def->owner, &def->name, &dc)) {
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_TRUNCATE_TABLE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    uint32 timeout = se->kernel->attr.ddl_lock_timeout;
    if (CT_SUCCESS != lock_table_directly(se, &dc, timeout)) {
        dc_close(&dc);
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_TRUNCATE_TABLE, &tv_begin, IO_STAT_FAILED);
        return CT_ERROR;
    }

    status = knl_truncate_table_precheck(session, def, &dc, &no_segment);
    if (status != CT_SUCCESS || no_segment) {
        unlock_tables_directly(se);
        dc_close(&dc);
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_TRUNCATE_TABLE, &tv_begin, IO_STAT_FAILED);
        return status;
    }

    status = knl_truncate_table_internal(se, def, &dc);

    if (status == CT_SUCCESS) {
        knl_truncate_table_log_put(se, stmt, &dc);

        SYNC_POINT(session, "SP_B1_TRUNCATE_TABLE");
        knl_commit(session);
        knl_truncate_table_after_commit(session, def, &dc); // handle garbage segment and invalidate dc
        SYNC_POINT(session, "SP_B2_TRUNCATE_TABLE");
    } else {
        log_add_lrep_ddl_end(se);
        knl_rollback(session, NULL);
        knl_truncate_table_invalidate_dc(session, &dc, def->is_changed, def->is_not_rcyclebin);
    }

    dc_close(&dc);
    unlock_tables_directly(se);

    cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_TRUNCATE_TABLE, &tv_begin, status == CT_SUCCESS ?
                       IO_STAT_SUCCESS : IO_STAT_FAILED);
    CT_LOG_RUN_INF("[DB] Finish to truncate table %s, ret:%d", T2S_EX(&def->name), status);
    return status;
}

status_t knl_truncate_table4mysql(knl_handle_t session, knl_handle_t stmt, knl_trunc_def_t *def, knl_dictionary_t *dc)
{
    CT_LOG_RUN_INF("[for mysql] Start to truncate table %s", T2S_EX(&def->name));
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_KNL_TRUNCATE_TABLE, &tv_begin);

    status_t status = CT_ERROR;
    knl_session_t *se = (knl_session_t *)session;
    bool32 no_segment = CT_FALSE;

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_TRUNCATE_TABLE_PRECHECK_FAIL, &status, CT_ERROR);
    status = knl_truncate_table_precheck(session, def, dc, &no_segment);
    SYNC_POINT_GLOBAL_END;
    if (status != CT_SUCCESS || no_segment) {
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_TRUNCATE_TABLE, &tv_begin, IO_STAT_FAILED);
        return status;
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_TRUNCATE_TABLE_FAIL, &status, CT_ERROR);
    status = knl_truncate_table_internal(se, def, dc);
    SYNC_POINT_GLOBAL_END;

    cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_TRUNCATE_TABLE, &tv_begin, status == CT_SUCCESS ?
                       IO_STAT_SUCCESS : IO_STAT_FAILED);
    CT_LOG_RUN_INF("[for mysql] Finish to truncate table %s, ret:%d", T2S_EX(&def->name), status);
    return status;
}

status_t knl_put_ddl_sql(knl_handle_t session, knl_handle_t stmt)
{
    log_add_lrep_ddl_begin(session);
    log_add_lrep_ddl_info(session, stmt, LOGIC_OP_OTHER, RD_SQL_DDL, NULL);
    log_add_lrep_ddl_end(session);

    log_commit(session);
    
    knl_session_t *se = (knl_session_t *)session;
	// if sesssion not start transaction, do commit
    if (se->rm->txn == NULL) {
        knl_commit(session);
    }
    return CT_SUCCESS;
}

status_t knl_flashback_table(knl_handle_t session, knl_flashback_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;
    status_t status;
    drlatch_t *ddl_latch = &se->kernel->db.ddl_latch;

    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_ddl_latch_s(ddl_latch, session, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }

    status = fb_flashback(se, def);
    dls_unlatch(session, ddl_latch, NULL);

    return status;
}

void knl_savepoint(knl_handle_t handle, knl_savepoint_t *savepoint)
{
    knl_session_t *session = (knl_session_t *)handle;
    knl_rm_t *rm = session->rm;

    if (rm->txn == NULL) {
        *savepoint = g_init_savepoint;
    } else {
        savepoint->urid = rm->undo_page_info.undo_rid;
        savepoint->noredo_urid = rm->noredo_undo_page_info.undo_rid;
        savepoint->xid = rm->xid.value;
        savepoint->key_lock = rm->key_lock_group;
        savepoint->row_lock = rm->row_lock_group;
        savepoint->sch_lock = rm->sch_lock_group;
        savepoint->alck_lock = rm->alck_lock_group;
        savepoint->lob_items = rm->lob_items;
    }
    savepoint->lsn = session->curr_lsn;
    savepoint->name[0] = '\0';
}

status_t knl_set_savepoint(knl_handle_t handle, text_t *name)
{
    knl_session_t *session = (knl_session_t *)handle;
    knl_rm_t *rm = session->rm;
    knl_savepoint_t *savepoint = NULL;
    uint8 i, j;

    if (DB_IS_READONLY(session)) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
        return CT_ERROR;
    }

    if (name->len >= CT_MAX_NAME_LEN) {
        CT_THROW_ERROR(ERR_NAME_TOO_LONG, "savepoint", name->len, CT_MAX_NAME_LEN - 1);
        return CT_ERROR;
    }

    for (i = 0; i < rm->svpt_count; i++) {
        if (cm_text_str_equal_ins(name, rm->save_points[i].name)) {
            break;
        }
    }

    // remove the savepoint with same name.
    if (i < rm->svpt_count) {
        for (j = i; j < rm->svpt_count - 1; j++) {
            rm->save_points[j] = rm->save_points[j + 1];
        }
        rm->svpt_count--;
    } else {
        if (rm->svpt_count == CT_MAX_SAVEPOINTS) {
            CT_THROW_ERROR(ERR_TOO_MANY_SAVEPOINTS);
            return CT_ERROR;
        }
    }

    savepoint = &rm->save_points[rm->svpt_count];
    knl_savepoint(session, savepoint);
    (void)cm_text2str(name, savepoint->name, CT_MAX_NAME_LEN);
    rm->svpt_count++;

    return CT_SUCCESS;
}

status_t knl_release_savepoint(knl_handle_t handle, text_t *name)
{
    knl_session_t *session = (knl_session_t *)handle;
    knl_rm_t *rm = session->rm;
    uint8 i;

    for (i = 0; i < rm->svpt_count; i++) {
        if (cm_text_str_equal_ins(name, rm->save_points[i].name)) {
            break;
        }
    }

    if (i == rm->svpt_count) {
        CT_THROW_ERROR(ERR_SAVEPOINT_NOT_EXIST, T2S(name));
        return CT_ERROR;
    }

    rm->svpt_count = i;

    return CT_SUCCESS;
}

status_t knl_rollback_savepoint(knl_handle_t handle, text_t *name)
{
    knl_session_t *session = (knl_session_t *)handle;
    knl_rm_t *rm = session->rm;
    knl_savepoint_t *savepoint = NULL;
    uint8 i;

    for (i = 0; i < rm->svpt_count; i++) {
        if (cm_text_str_equal_ins(name, rm->save_points[i].name)) {
            savepoint = &rm->save_points[i];
            break;
        }
    }

    if (i == rm->svpt_count) {
        CT_THROW_ERROR(ERR_SAVEPOINT_NOT_EXIST, T2S(name));
        return CT_ERROR;
    }

    knl_rollback(session, savepoint);

    return CT_SUCCESS;
}

status_t knl_alloc_swap_extent(knl_handle_t se, page_id_t *extent)
{
    knl_session_t *session = (knl_session_t *)se;
    space_t *swap_space = SPACE_GET(session, dtc_my_ctrl(session)->swap_space);
    knl_panic_log(IS_SWAP_SPACE(swap_space), "[SPACE] space %u is not swap space, type is %u.", swap_space->ctrl->id,
                  swap_space->ctrl->type);

    if (CT_SUCCESS != spc_alloc_swap_extent(session, swap_space, extent)) {
        CT_THROW_ERROR(ERR_ALLOC_TEMP_EXTENT);
        return CT_ERROR;
    }

    knl_panic_log(!IS_INVALID_PAGID(*extent), "alloc swap extent from swap space error, page id %u-%u.", extent->file,
                  extent->page);
    knl_panic_log(IS_SWAP_SPACE(SPACE_GET(session, DATAFILE_GET(session, extent->file)->space_id)),
                  "alloc swap extent from swap space error, page id %u-%u.", extent->file, extent->page);

    session->stat->temp_allocs++;
    return CT_SUCCESS;
}

void knl_release_swap_extent(knl_handle_t se, page_id_t extent)
{
    knl_session_t *session = (knl_session_t *)se;
    space_t *swap_space = SPACE_GET(session, dtc_my_ctrl(session)->swap_space);
    knl_panic_log(IS_SWAP_SPACE(swap_space), "[SPACE] space %u is not swap space, type is %u.", swap_space->ctrl->id,
                  swap_space->ctrl->type);

    knl_panic_log(!IS_INVALID_PAGID(extent), "alloc swap extent from swap space error, page id %u-%u.", extent.file,
                  extent.page);
    // verify swap space by space_id. because space->ctrl maybe freed in knl_close_temp_tables
    knl_panic_log((DATAFILE_GET(session, extent.file)->space_id) == dtc_my_ctrl(session)->swap_space,
                  "release swap extent error, page id %u-%u is below to space %u.", extent.file, extent.page,
                  DATAFILE_GET(session, extent.file)->space_id);

    spc_free_temp_extent(session, swap_space, extent);
    return;
}

static inline void swap_free_cipher_buf(knl_session_t *session, char *data_buf)
{
    if (!session->thread_shared) {
        cm_pop(session->stack);
    } else {
        free(data_buf);
    }
}

status_t knl_read_swap_data(knl_handle_t se, page_id_t extent, uint32 cipher_len, char *data, uint32 size)
{
    knl_session_t *session = (knl_session_t *)se;
    datafile_t *df = &session->kernel->db.datafiles[extent.file];
    int32 *handle = &session->datafiles[extent.file];
    int64 offset = (int64)extent.page * DEFAULT_PAGE_SIZE(session);
    space_t *swap_space = SPACE_GET(session, dtc_my_ctrl(session)->swap_space);
    char *data_buf = data;
    uint32 data_size = size;
    bool8 is_encrypt = cipher_len > 0 ? CT_TRUE : CT_FALSE;

    if (is_encrypt) {
        uint32 extent_size = swap_space->ctrl->extent_size * DEFAULT_PAGE_SIZE(session);
        if (!session->thread_shared) {
            data_buf = (char *)cm_push(session->stack, extent_size);
        } else {
            data_buf = (char *)malloc(extent_size);
        }
        if (data_buf == NULL) {
            CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)(extent_size), "read swap data");
            return CT_ERROR;
        }
        data_size = extent_size;
    }

    if (spc_read_datafile(session, df, handle, offset, data_buf, data_size) != CT_SUCCESS) {
        spc_close_datafile(df, handle);
        CT_THROW_ERROR(ERR_READ_FILE, errno);
        CT_LOG_RUN_ERR("[SPACE] failed to open datafile %s", df->ctrl->name);
        if (is_encrypt) {
            swap_free_cipher_buf(session, data_buf);
        }
        return CT_ERROR;
    }

    if (is_encrypt) {
        if (cm_kmc_decrypt(CT_KMC_KERNEL_DOMAIN, data_buf, cipher_len, data, &data_size) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("swap data decrypt failed");
            swap_free_cipher_buf(session, data_buf);
            return CT_ERROR;
        }
        knl_panic_log(data_size == size,
                      "the data_size is incorrect, panic info: "
                      "page %u-%u data_size %u swap_data size %u",
                      extent.file, extent.page, data_size, size);
        swap_free_cipher_buf(session, data_buf);
    }

    return CT_SUCCESS;
}

status_t knl_write_swap_data(knl_handle_t se, page_id_t extent, const char *data, uint32 p_size, uint32 *cipher_len)
{
    uint32 size = p_size;
    knl_session_t *session = (knl_session_t *)se;
    datafile_t *df = &session->kernel->db.datafiles[extent.file];
    int32 *handle = &session->datafiles[extent.file];
    int64 offset = (int64)extent.page * DEFAULT_PAGE_SIZE(session);
    space_t *swap_space = SPACE_GET(session, dtc_my_ctrl(session)->swap_space);
    encrypt_context_t *encrypt_ctx = &session->kernel->encrypt_ctx;
    bool8 is_encrypt = encrypt_ctx->swap_encrypt_flg;
    char *cipher_buf = NULL;

    *cipher_len = 0;
    if (is_encrypt) {
        uint32 extent_size = swap_space->ctrl->extent_size * DEFAULT_PAGE_SIZE(session);
        *cipher_len = extent_size;
        if (!session->thread_shared) {
            cipher_buf = (char *)cm_push(session->stack, extent_size);
        } else {
            cipher_buf = (char *)malloc(extent_size);
        }
        if (cipher_buf == NULL) {
            CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)(extent_size), "write swap data");
            return CT_ERROR;
        }
        if (cm_kmc_encrypt(CT_KMC_KERNEL_DOMAIN, encrypt_ctx->swap_encrypt_version, data, size, cipher_buf,
                           cipher_len) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("swap data encrypt failed");
            swap_free_cipher_buf(session, cipher_buf);
            return CT_ERROR;
        }
        knl_panic_log(*cipher_len - size <= encrypt_ctx->swap_cipher_reserve_size,
                      "Encrypted length of data is "
                      "invalid, panic info: page %u-%u cipher_len %u size %u swap_cipher_reserve_size %u",
                      extent.file, extent.page, *cipher_len, size, encrypt_ctx->swap_cipher_reserve_size);
        knl_panic_log(*cipher_len <= extent_size,
                      "Encrypted length of data is more than extent_size, panic info: "
                      "page %u-%u cipher_len %u extent_size %u",
                      extent.file, extent.page, *cipher_len, extent_size);
        data = cipher_buf;
        size = extent_size;
    }

    if (spc_write_datafile(session, df, handle, offset, data, size) != CT_SUCCESS) {
        spc_close_datafile(df, handle);
        if (is_encrypt) {
            swap_free_cipher_buf(session, cipher_buf);
        }
        CT_THROW_ERROR(ERR_WRITE_FILE, errno);
        CT_LOG_RUN_ERR("[SPACE] failed to write datafile %s", df->ctrl->name);
        return CT_ERROR;
    }

    if (is_encrypt) {
        swap_free_cipher_buf(session, cipher_buf);
    }
    return CT_SUCCESS;
}

uint32 knl_get_swap_extents(knl_handle_t se)
{
    datafile_t *df = NULL;
    knl_session_t *session = (knl_session_t *)se;
    space_t *swap_space = SPACE_GET(session, dtc_my_ctrl(session)->swap_space);
    uint32 total_extents = 0;
    int64 df_size = 0;
    uint32 id;

    CM_POINTER2(session, swap_space);

    cm_spin_lock(&swap_space->lock.lock, NULL);

    for (id = 0; id < swap_space->ctrl->file_hwm; id++) {
        if (CT_INVALID_ID32 == swap_space->ctrl->files[id]) {
            continue;
        }

        df = DATAFILE_GET(session, swap_space->ctrl->files[id]);
        if (DATAFILE_IS_AUTO_EXTEND(df)) {
            df_size = df->ctrl->auto_extend_maxsize;
        } else {
            df_size = df->ctrl->size;
        }
        // size is less than 2^14, file_hwm <= 8, so total_extents is less than uint32
        total_extents += (uint32)(df_size / DEFAULT_PAGE_SIZE(session) / swap_space->ctrl->extent_size);
    }

    cm_spin_unlock(&swap_space->lock.lock);
    return total_extents;
}

status_t knl_alter_database(knl_handle_t session, knl_alterdb_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;
    status_t status = CT_SUCCESS;
    bak_context_t *ctx = &se->kernel->backup_ctx;
    drlatch_t *ddl_latch = &se->kernel->db.ddl_latch;

    if (!BAK_NOT_WORK(ctx) && !HIGH_PRIO_ACT(def->action)) {
        CT_THROW_ERROR(ERR_FORBID_ALTER_DATABASE);
        return CT_ERROR;
    }

    switch (def->action) {
        case STARTUP_DATABASE_MOUNT:
            if (se->kernel->db.status >= DB_STATUS_MOUNT) {
                CT_THROW_ERROR(ERR_DATABASE_ALREADY_MOUNT);
                return CT_ERROR;
            }
            status = db_mount(se);
            if (status != CT_SUCCESS) {
                CT_LOG_RUN_ERR("failed to alter database MOUNT");
            }
            break;

        case STARTUP_DATABASE_OPEN:
            if (se->kernel->db.status > DB_STATUS_MOUNT) {
                CT_THROW_ERROR(ERR_DATABASE_ALREADY_OPEN);
                return CT_ERROR;
            }
            
            if (se->kernel->db.status < DB_STATUS_MOUNT) {
                status = db_mount(se);
            }

            if (status != CT_SUCCESS) {
                CT_LOG_RUN_ERR("failed to alter database MOUNT");
            } else {
                status = db_open(se, &def->open_options);
                if (status != CT_SUCCESS) {
                    CT_LOG_RUN_ERR("failed to alter database OPEN");
                }
            }
            break;

        case DATABASE_ARCHIVELOG:
            if (se->kernel->db.status != DB_STATUS_MOUNT) {
                CT_THROW_ERROR(ERR_DATABASE_NOT_MOUNT, "set archivelog");
                return CT_ERROR;
            }
            status = db_alter_archivelog(se, ARCHIVE_LOG_ON);
            break;

        case DATABASE_NOARCHIVELOG:
            if (se->kernel->db.status != DB_STATUS_MOUNT) {
                CT_THROW_ERROR(ERR_DATABASE_NOT_MOUNT, "set noarchivelog");
                return CT_ERROR;
            }
            status = db_alter_archivelog(se, ARCHIVE_LOG_OFF);
            break;

        case ADD_LOGFILE:
            if (DB_IS_READONLY(se)) {
                CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
                return CT_ERROR;
            }

            if (se->kernel->db.status != DB_STATUS_OPEN) {
                CT_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "add logfile");
                return CT_ERROR;
            }

            if (knl_ddl_latch_x(session, NULL) != CT_SUCCESS) {
                return CT_ERROR;
            }
            status = db_alter_add_logfile(se, def);
            knl_ddl_unlatch_x(session);
            break;

        case DROP_LOGFILE:
            if (DB_IS_READONLY(se)) {
                CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
                return CT_ERROR;
            }

            if (se->kernel->db.status != DB_STATUS_OPEN) {
                CT_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "drop logfile");
                return CT_ERROR;
            }

            if (knl_ddl_latch_x(session, NULL) != CT_SUCCESS) {
                return CT_ERROR;
            }
            status = db_alter_drop_logfile(se, def);
            knl_ddl_unlatch_x(session);
            break;
        case ARCHIVE_LOGFILE:
            status = db_alter_archive_logfile(se, def);
            break;

        case MAXIMIZE_STANDBY_DB:
            status = db_alter_protection_mode(se, def);
            break;

        case SWITCHOVER_STANDBY:
            status = db_alter_switchover(se, def);
            break;

        case FAILOVER_STANDBY:
            status = db_alter_failover(se, def);
            break;

        case CONVERT_TO_STANDBY:
            status = db_alter_convert_to_standby(se, def);
            break;

        case CONVERT_TO_READ_ONLY:
            if (knl_ddl_latch_x(session, NULL) != CT_SUCCESS) {
                return CT_ERROR;
            }

            status = db_alter_convert_to_readonly(se);
            knl_ddl_unlatch_x(session);
            break;

        case CONVERT_TO_READ_WRITE:
            if (knl_ddl_latch_x(session, NULL) != CT_SUCCESS) {
                return CT_ERROR;
            }

            status = db_alter_convert_to_readwrite(se);
            knl_ddl_unlatch_x(session);
            break;

        case START_STANDBY:
            status = CT_ERROR;
            break;

        case ALTER_DATAFILE:
            if (knl_ddl_latch_s(ddl_latch, session, NULL) != CT_SUCCESS) {
                return CT_ERROR;
            }
            status = db_alter_datafile(se, &def->datafile);
            dls_unlatch(session, ddl_latch, NULL);
            break;

        case DELETE_ARCHIVELOG:
            // to delete archivelog
            if (se->kernel->db.status < DB_STATUS_OPEN) {
                CT_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "delete archivelog");
                return CT_ERROR;
            }

            if (!se->kernel->arch_ctx.is_archive) {
                CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "delete archivelog on noarchivelog mode");
                return CT_ERROR;
            }

            status = db_alter_delete_archivelog(se, def);
            break;

        case DELETE_BACKUPSET:
            status = db_alter_delete_backupset(se, def);
            break;

        case ENABLE_LOGIC_REPLICATION:
            status = db_alter_logicrep(se, LOG_REPLICATION_ON);
            break;

        case DISABLE_LOGIC_REPLICATION:
            status = db_alter_logicrep(se, LOG_REPLICATION_OFF);
            break;

        case DATABASE_CLEAR_LOGFILE:
            status = db_alter_clear_logfile(se, def->clear_logfile_id);
            break;

        case ALTER_CHARSET:
            status = db_alter_charset(se, def->charset_id);
            break;

        case REBUILD_TABLESPACE:
            status = db_alter_rebuild_space(se, &def->rebuild_spc.space_name);
            break;

        case CANCEL_UPGRADE:
            status = db_alter_cancel_upgrade(se);
            break;

        case UPDATE_MASTER_SERVER_KEY:
            cm_spin_lock(&se->kernel->encrypt_ctx.lock, NULL);
            status = db_alter_update_server_masterkey(se);
            cm_spin_unlock(&se->kernel->encrypt_ctx.lock);
            break;
        case UPDATE_MASTER_KERNEL_KEY:
            cm_spin_lock(&se->kernel->encrypt_ctx.lock, NULL);
            status = db_alter_update_kernel_masterkey(se);
            cm_spin_unlock(&se->kernel->encrypt_ctx.lock);
            break;
        case UPDATE_MASTER_ALL_KEY:
            cm_spin_lock(&se->kernel->encrypt_ctx.lock, NULL);
            status = db_alter_update_masterkey(se);
            cm_spin_unlock(&se->kernel->encrypt_ctx.lock);
            break;

        default:
            CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "the input is not support");
            return CT_ERROR;
    }
    return status;
}

void knl_get_system_name(knl_handle_t session, constraint_type_t type, char *name, uint32 name_len)
{
    static const char *cons_name_prefix[MAX_CONS_TYPE_COUNT] = { "PK", "UQ", "REF", "CHK" };
    const char *prefix = cons_name_prefix[type];
    knl_instance_t *kernel = ((knl_session_t *)session)->kernel;

    uint32 id = cm_atomic32_inc(&kernel->seq_name);
    int32 ret = sprintf_s(name, name_len, "_%s_SYS_%u_%u", prefix, kernel->db.ctrl.core.open_count, id);
    knl_securec_check_ss(ret);
}

status_t knl_do_force_archive(knl_handle_t session)
{
    CM_POINTER(session);
    knl_session_t *se = (knl_session_t *)session;
    database_t *db = &se->kernel->db;

    if (knl_db_open_dbstor_ns(session) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (db_mount_ctrl(se) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (log_load(se) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dtc_rst_db_init_logfile_ctrl_by_dbstor(se, &se->kernel->db.ctrl.log_segment);
    for (uint32 i = 0; i < se->kernel->db.ctrl.core.node_count; i++) {
        knl_instance_t *kernel = se->kernel;
        log_context_t *ctx = &kernel->redo_ctx;
        log_file_t *file = &ctx->files[0];
        int32 fd = CT_INVALID_HANDLE;
        file->ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(db->ctrl.pages, 0, sizeof(log_file_ctrl_t),
                                                             db->ctrl.log_segment, i);
        if (cm_open_device(file->ctrl->name, file->ctrl->type, knl_io_flag(se), &fd) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[ARCH] failed to open redo log file=%s ", file->ctrl->name);
            return CT_ERROR;
        }
        if (arch_force_archive_file(se, i, file->ctrl->block_size, file->ctrl->type, fd) != CT_SUCCESS) {
            cm_close_device(file->ctrl->type, &fd);
            CT_LOG_RUN_ERR("[ARCH] failed to force archive file, node_id[%u]", i);
            return CT_ERROR;
        }
        cm_close_device(file->ctrl->type, &fd);
    }
    return CT_SUCCESS;
}

status_t knl_switch_log(knl_handle_t session)
{
    CM_POINTER(session);
    knl_session_t *se = (knl_session_t *)session;
    database_t *db = &se->kernel->db;

    if (DB_IS_READONLY(se)) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
        return CT_ERROR;
    }

    if (db->status == DB_STATUS_NOMOUNT && cm_dbs_is_enable_dbs()) {
        return knl_do_force_archive(session);
    }

    if (db->status != DB_STATUS_OPEN) {
        CT_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "set param");
        return CT_ERROR;
    }

    CT_LOG_RUN_INF("knl switch log file");
    if (dtc_bak_handle_log_switch(se) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t knl_checkpoint(knl_handle_t handle, ckpt_type_t type)
{
    knl_session_t *session = (knl_session_t *)handle;
    database_t *db = &session->kernel->db;

    if (db->status != DB_STATUS_OPEN) {
        CT_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "operation");
        return CT_ERROR;
    }

    if (type == CKPT_TYPE_GLOBAL) {
        dcs_ckpt_trigger(session, CT_TRUE, CKPT_TRIGGER_FULL);
        return CT_SUCCESS;
    } else {
        ckpt_trigger(session, CT_TRUE, CKPT_TRIGGER_FULL);
        return CT_SUCCESS;
    }
}

status_t knl_set_arch_param(knl_handle_t handle, knl_alter_sys_def_t *def)
{
    knl_session_t *session = (knl_session_t *)handle;
    database_t *db = &session->kernel->db;
    config_item_t *item = NULL;
    bool32 force = CT_TRUE;

    if (db->status != DB_STATUS_MOUNT && db->status != DB_STATUS_OPEN) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "set param only work in mount or open state");
        return CT_ERROR;
    }

    item = &session->kernel->attr.config->items[def->param_id];
    if (def->param_id != item->id) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "def->param_id(%u) == item->id(%u)", def->param_id, item->id);
        return CT_ERROR;
    }

    if (def->scope != CONFIG_SCOPE_DISK) {
        if (item->notify && item->notify((knl_handle_t)session, (void *)item, def->value)) {
            return CT_ERROR;
        }
    } else {
        if (item->notify_pfile && item->notify_pfile((knl_handle_t)session, (void *)item, def->value)) {
            return CT_ERROR;
        }
    }

    if (item->attr & ATTR_READONLY) {
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
        force = CT_TRUE;
#else
        force = CT_FALSE; // can not alter parameter whose attr is readonly for release
#endif
    }
    if (cm_alter_config(session->kernel->attr.config, def->param, def->value, def->scope, force) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (def->arch_set_type == ARCH_SET_TYPE_GLOBAL && DB_IS_CLUSTER(session)) {
        if(dcs_alter_set_param(session, def->value, def->scope) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

typedef status_t (*knl_dump_page_func)(knl_session_t *session, page_head_t *head, cm_dump_t *dump);
typedef struct st_knl_dump_page_obj {
    page_type_t type;              // page type
    knl_dump_page_func dump_func;  // page dump function
} knl_dump_page_obj_t;

static knl_dump_page_obj_t g_knl_dump_page_func_list[] = { { PAGE_TYPE_FREE_PAGE, NULL },
                                                           { PAGE_TYPE_SPACE_HEAD, space_head_dump },
                                                           { PAGE_TYPE_HEAP_HEAD, map_segment_dump },
                                                           { PAGE_TYPE_HEAP_MAP, map_dump_page },
                                                           { PAGE_TYPE_HEAP_DATA, heap_dump_page },
                                                           { PAGE_TYPE_UNDO_HEAD, undo_segment_dump },
                                                           { PAGE_TYPE_TXN, txn_dump_page },
                                                           { PAGE_TYPE_UNDO, undo_dump_page },
                                                           { PAGE_TYPE_BTREE_HEAD, btree_segment_dump },
                                                           { PAGE_TYPE_BTREE_NODE, btree_dump_page },
                                                           { PAGE_TYPE_LOB_HEAD, lob_segment_dump },
                                                           { PAGE_TYPE_LOB_DATA, lob_dump_page },
                                                           { PAGE_TYPE_TEMP_HEAP, NULL },
                                                           { PAGE_TYPE_TEMP_INDEX, NULL },
                                                           { PAGE_TYPE_FILE_HEAD, NULL },
                                                           { PAGE_TYPE_CTRL, NULL },
                                                           { PAGE_TYPE_PCRH_DATA, pcrh_dump_page },
                                                           { PAGE_TYPE_PCRB_NODE, pcrb_dump_page },
                                                           { PAGE_TYPE_DF_MAP_HEAD, df_dump_map_head_page },
                                                           { PAGE_TYPE_DF_MAP_DATA, df_dump_map_data_page } };

#define KNL_PAGE_DUMP_COUNT (uint32)(sizeof(g_knl_dump_page_func_list) / sizeof(knl_dump_page_obj_t))

static inline knl_dump_page_func knl_get_page_dump_func(page_type_t type)
{
    for (uint32 i = 0; i < KNL_PAGE_DUMP_COUNT; i++) {
        if (g_knl_dump_page_func_list[i].type == type) {
            return g_knl_dump_page_func_list[i].dump_func;
        }
    }
    return NULL;
}

static status_t knl_dump_page_head(knl_session_t *session, page_head_t *head, cm_dump_t *dump)
{
    dump->offset = 0;

    // the max number of data files is smaller than 1023, file is uint16, page is uint32, is not larger than uint32
    cm_dump(dump, "\ninformation of page %u-%u\n", (uint32)AS_PAGID_PTR(head->id)->file,
            (uint32)AS_PAGID_PTR(head->id)->page);
    cm_dump(dump, "\tlsn: %llu", head->lsn);
    cm_dump(dump, "\tpcn: %u", head->pcn);
    cm_dump(dump, "\tsize: %u", PAGE_SIZE(*head));
    cm_dump(dump, "\ttype: %s", page_type(head->type));
    cm_dump(dump, "\tsoft_damage: %u", head->soft_damage);
    cm_dump(dump, "\thard_damage: %u", head->hard_damage);
    cm_dump(dump, "\tnext_ext: %u-%u\n", (uint32)AS_PAGID_PTR(head->next_ext)->file,
            (uint32)AS_PAGID_PTR(head->next_ext)->page);
    CM_DUMP_WRITE_FILE(dump);
    return CT_SUCCESS;
}

static status_t knl_internal_dump_page(knl_session_t *session, const char *file_name, page_head_t *page_head,
                                       cm_dump_t *dump)
{
    knl_dump_page_func dump_func = knl_get_page_dump_func(page_head->type);
    if (dump_func == NULL) {
        CT_THROW_ERROR(ERR_INVALID_PAGE_TYPE);
        return CT_ERROR;
    }

    if (cm_file_exist(file_name)) {
        CT_THROW_ERROR(ERR_FILE_ALREADY_EXIST, file_name, "failed to dump page");
        return CT_ERROR;
    }

    if (cm_create_file(file_name, O_RDWR | O_BINARY | O_SYNC, &dump->handle) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_CREATE_FILE, file_name, errno);
        return CT_ERROR;
    }

    if (knl_dump_page_head(session, page_head, dump) != CT_SUCCESS) {
        cm_close_file(dump->handle);
        return CT_ERROR;
    }

    status_t status = dump_func(session, page_head, dump);
    cm_close_file(dump->handle);

    return status;
}

status_t knl_dump_ctrl_page(knl_handle_t handle, knl_alter_sys_def_t *def)
{
    knl_session_t *session = (knl_session_t *)handle;
    char file_name[CT_MAX_FILE_NAME_LEN];
    database_ctrl_t *page = NULL;

    // default size 1024
    cm_dump_t dump = { .handle = CT_INVALID_HANDLE, .buf_size = PAGE_DUMP_SIZE };

    if (DB_IS_READONLY(session)) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
        return CT_ERROR;
    }

    uint32 ret = memset_sp(file_name, CT_MAX_FILE_NAME_LEN, 0, CT_MAX_FILE_NAME_LEN);
    knl_securec_check(ret);

    if (CM_IS_EMPTY(&def->out_file)) {
        ret = snprintf_s(file_name, CT_MAX_FILE_NAME_LEN, CT_MAX_FILE_NAME_LEN - 1, "%s/trc/ctrl_page.trc",
                         session->kernel->home);
        knl_securec_check_ss(ret);
    } else {
        if (def->out_file.len >= CT_MAX_FILE_NAME_LEN) {
            CT_THROW_ERROR(ERR_INVALID_FILE_NAME, T2S(&def->out_file), (uint32)CT_MAX_FILE_NAME_LEN);
            return CT_ERROR;
        }

        ret = memcpy_sp(file_name, CT_MAX_FILE_NAME_LEN, def->out_file.str, def->out_file.len);
        knl_securec_check(ret);
    }

    page = (database_ctrl_t *)&session->kernel->db.ctrl;
    if (page == NULL) {
        return CT_SUCCESS;
    }

    if (cm_file_exist(file_name)) {
        CT_THROW_ERROR(ERR_FILE_ALREADY_EXIST, file_name, "failed to dump ctrlfile");
        return CT_ERROR;
    } else {
        if (cm_create_file(file_name, O_RDWR | O_BINARY | O_SYNC | O_TRUNC, &dump.handle) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    dump.buf = (char *)cm_push(session->stack, dump.buf_size);
    if (knl_dump_page_head(session, (page_head_t *)page->pages, &dump) != CT_SUCCESS) {
        cm_close_file(dump.handle);
        cm_pop(session->stack);
        return CT_ERROR;
    }

    if (dump_ctrl_page(page, &dump) != CT_SUCCESS) {
        cm_close_file(dump.handle);
        cm_pop(session->stack);
        return CT_ERROR;
    }

    if (dump_rebuild_ctrl_statement(page, &dump) != CT_SUCCESS) {
        cm_close_file(dump.handle);
        cm_pop(session->stack);
        return CT_ERROR;
    }

    cm_close_file(dump.handle);
    cm_pop(session->stack);
    return CT_SUCCESS;
}

status_t knl_dump_page(knl_handle_t handle, knl_alter_sys_def_t *def)
{
    knl_session_t *session = (knl_session_t *)handle;
    char file_name[CT_MAX_FILE_NAME_LEN];
    page_head_t *page = NULL;
    bool32 has_err = CT_FALSE;

    if (DB_IS_READONLY(session)) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
        return CT_ERROR;
    }

    if (session->kernel->db.status != DB_STATUS_OPEN) {
        CT_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "operation dump page");
        return CT_ERROR;
    }

    uint32 ret = memset_sp(file_name, CT_MAX_FILE_NAME_LEN, 0, CT_MAX_FILE_NAME_LEN);
    knl_securec_check(ret);

    if (CM_IS_EMPTY(&def->out_file)) {
        ret = snprintf_s(file_name, CT_MAX_FILE_NAME_LEN, CT_MAX_FILE_NAME_LEN - 1, "%s/trc/%u_%u.trc",
                         session->kernel->home, def->page_id.file, def->page_id.page);
        knl_securec_check_ss(ret);
    } else {
        if (def->out_file.len >= CT_MAX_FILE_NAME_LEN) {
            CT_THROW_ERROR(ERR_INVALID_FILE_NAME, T2S(&def->out_file), (uint32)CT_MAX_FILE_NAME_LEN);
            return CT_ERROR;
        }

        ret = memcpy_sp(file_name, CT_MAX_FILE_NAME_LEN, def->out_file.str, def->out_file.len);
        knl_securec_check(ret);
    }

    if (!spc_validate_page_id(session, def->page_id)) {
        CT_THROW_ERROR(ERR_INVALID_PAGE_ID, "");
        return CT_ERROR;
    }

    if (buf_read_page(session, def->page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // default size 1024
    cm_dump_t dump = { .handle = CT_INVALID_HANDLE, .buf_size = PAGE_DUMP_SIZE };
    dump.buf = (char *)cm_push(session->stack, dump.buf_size);

    if (session->curr_page != NULL) {
        page = (page_head_t *)CURR_PAGE(session);
        if (knl_internal_dump_page(session, file_name, page, &dump) != CT_SUCCESS) {
            has_err = CT_TRUE;
        }
        buf_leave_page(session, CT_FALSE);
    }

    cm_pop(session->stack);

    return (has_err ? CT_ERROR : CT_SUCCESS);
}

status_t knl_dump_dc(knl_handle_t handle, knl_alter_sys_def_t *def)
{
    knl_session_t *session = (knl_session_t *)handle;
    dc_dump_info_t info;
    status_t status = CT_SUCCESS;

    if (DB_IS_READONLY(session)) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
        return CT_ERROR;
    }

    if (session->kernel->db.status != DB_STATUS_OPEN) {
        CT_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "operation dump catalog");
        return CT_ERROR;
    }

    cm_dump_t dump;
    dump.handle = CT_INVALID_HANDLE;
    dump.buf_size = PAGE_DUMP_SIZE;
    dump.buf = (char *)cm_push(session->stack, dump.buf_size);
    info = def->dump_info;

    switch (info.dump_type) {
        case DC_DUMP_TABLE:
            status = dc_dump_table(session, &dump, info);
            break;
        case DC_DUMP_USER:
            status = dc_dump_user(session, &dump, info);
            break;
        default:
            break;
    }
    cm_pop(session->stack);
    return status;
}

static status_t knl_get_table_by_pageid(knl_session_t *session, page_head_t *page, uint32 *uid, uint32 *tabid)
{
    bool32 belong = CT_FALSE;
    heap_page_t *heap_page = NULL;
    lob_segment_t *lob_segment = NULL;
    heap_segment_t *heap_segment = NULL;
    btree_segment_t *btree_segment = NULL;

    switch (page->type) {
        case PAGE_TYPE_HEAP_HEAD:
            heap_segment = (heap_segment_t *)((char *)page + sizeof(page_head_t));
            *uid = heap_segment->uid;
            *tabid = heap_segment->oid;
            return CT_SUCCESS;

        case PAGE_TYPE_HEAP_MAP:
            CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "get table info from map page");
            return CT_ERROR;

        case PAGE_TYPE_HEAP_DATA:
        case PAGE_TYPE_PCRH_DATA:
            heap_page = (heap_page_t *)page;
            *uid = heap_page->uid;
            *tabid = heap_page->oid;

            if (heap_check_page_belong_table(session, heap_page, *uid, *tabid, &belong) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (!belong) {
                CT_THROW_ERROR(ERR_PAGE_NOT_BELONG_TABLE, page_type(heap_page->head.type));
                return CT_ERROR;
            }

            return CT_SUCCESS;

        case PAGE_TYPE_BTREE_HEAD:
            btree_segment = (btree_segment_t *)((char *)page + CM_ALIGN8(sizeof(btree_page_t)));
            *uid = btree_segment->uid;
            *tabid = btree_segment->table_id;
            return CT_SUCCESS;

        case PAGE_TYPE_BTREE_NODE:
            return btree_get_table_by_page(session, page, uid, tabid);

        case PAGE_TYPE_PCRB_NODE:
            return pcrb_get_table_by_page(session, page, uid, tabid);

        case PAGE_TYPE_LOB_HEAD:
            lob_segment = (lob_segment_t *)((char *)page + sizeof(page_head_t));
            *uid = lob_segment->uid;
            *tabid = lob_segment->table_id;
            return CT_SUCCESS;

        case PAGE_TYPE_LOB_DATA:
            return lob_get_table_by_page(session, page, uid, tabid);

        default:
            CT_THROW_ERROR(ERR_PAGE_NOT_BELONG_TABLE, page_type(page->type));
            return CT_ERROR;
    }
}

static status_t knl_fetch_table_name(knl_session_t *session, uint32 uid, uint32 table_id, text_t *table_name)
{
    knl_table_desc_t desc;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLE_ID, IX_SYS_TABLE_002_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_TABLE_002_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &table_id, sizeof(uint32),
                     IX_COL_SYS_TABLE_002_ID);

    if (knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CT_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "table", "");
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    dc_convert_table_desc(cursor, &desc);
    dc_user_t *user = NULL;
    if (dc_open_user_by_id(session, desc.uid, &user) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    errno_t ret = sprintf_s(table_name->str, table_name->len, "%s.%s", user->desc.name, desc.name);
    knl_securec_check_ss(ret);
    table_name->len = ret;
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t knl_get_table_name(knl_handle_t se, uint32 fileid, uint32 pageid, text_t *table_name)
{
    uint32 uid, tabid;
    page_id_t page_id;
    knl_session_t *session = (knl_session_t *)se;

    page_id.file = fileid;
    page_id.page = pageid;
    if (session->kernel->db.status != DB_STATUS_OPEN) {
        CT_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "operation dump table");
        return CT_ERROR;
    }

    if (!spc_validate_page_id(session, page_id)) {
        CT_THROW_ERROR(ERR_INVALID_PAGE_ID, "");
        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    page_head_t *page = (page_head_t *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session));
    buf_enter_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    errno_t ret = memcpy_sp(page, DEFAULT_PAGE_SIZE(session), CURR_PAGE(session), DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);
    buf_leave_page(session, CT_FALSE);

    if (knl_get_table_by_pageid(session, page, &uid, &tabid) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    if (knl_fetch_table_name(session, uid, tabid, table_name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

bool8 knl_backup_database_can_retry(knl_session_t *session, knl_backup_t *param)
{
    if (!session->kernel->attr.backup_retry) {
        return CT_FALSE;
    }
    if (bak_backup_database_need_retry(session) && (bak_delete_backupset_for_retry(param) == CT_SUCCESS)) {
        cm_reset_error();
        if (bak_wait_reform_finish() == CT_SUCCESS) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

status_t knl_check_db_status(knl_session_t *se, knl_backup_t *param)
{
    if (!cm_spin_try_lock(&se->kernel->lock)) {
        CT_THROW_ERROR(ERR_BACKUP_RESTORE, "backup", "because database is starting");
        return CT_ERROR;
    }
 
    if (se->kernel->db.status != DB_STATUS_OPEN && se->kernel->db.status != DB_STATUS_MOUNT) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ",not mount/open mode, can not backup");
        cm_spin_unlock(&se->kernel->lock);
        return CT_ERROR;
    }
 
    if (se->kernel->db.status == DB_STATUS_MOUNT && param->type == BACKUP_MODE_INCREMENTAL) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ",can not make incremental backup in mount mode");
        cm_spin_unlock(&se->kernel->lock);
        return CT_ERROR;
    }
 
    if ((!DB_IS_PRIMARY(&se->kernel->db)) ||
        (DB_IS_RAFT_ENABLED(se->kernel) && !DB_IS_PRIMARY(&se->kernel->db) && param->type != BACKUP_MODE_FULL)) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", can not do backup on current database role");
        cm_spin_unlock(&se->kernel->lock);
        return CT_ERROR;
    }
    cm_spin_unlock(&se->kernel->lock);
    return CT_SUCCESS;
}

status_t knl_backup(knl_handle_t session, knl_backup_t *param)
{
    CM_POINTER(session);
    knl_session_t *se = (knl_session_t *)session;
    uint32 retry_times = 0;
    status_t status = CT_SUCCESS;
    CT_LOG_RUN_INF("[BACKUP] backup task start!");
    if (bak_set_process_running(se) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[BACKUP] set backup process running failed");
        CT_THROW_ERROR(ERR_BACKUP_IN_PROGRESS, "backup or delete backupset process");
        return CT_ERROR;
    }

    do {
        if (knl_check_db_status(se, param) != CT_SUCCESS) {
            bak_unset_process_running(se);
            return CT_ERROR;
        }

        status = bak_backup_database(se, param);
        if (status == CT_SUCCESS) {
            break;
        }

        if (knl_backup_database_can_retry(se, param)) {
            cm_sleep(MILLISECS_PER_SECOND);
            retry_times++;
            CT_LOG_RUN_WAR("start retry backup, status %d, retry_times %u", status, retry_times);
        } else {
            CT_LOG_RUN_ERR("backup failed, status %d, retry_times %u", status, retry_times);
            break;
        }
    } while (retry_times <= BAK_MAX_RETRY_TIMES_FOR_REFORM);
    bak_unset_process_running(se);
    return status;
}

status_t knl_restore(knl_handle_t session, knl_restore_t *param)
{
    knl_session_t *se = (knl_session_t *)session;
    bak_context_t *ctx = &se->kernel->backup_ctx;
    status_t status;

    CM_POINTER(session);
    if (param->type == RESTORE_BLOCK_RECOVER || param->file_type == RESTORE_DATAFILE) {
        if (se->kernel->db.status != DB_STATUS_MOUNT) {
            CT_THROW_ERROR(ERR_INVALID_OPERATION, ",not mount mode, can not recover block or recover file from backup");
            return CT_ERROR;
        }
    } else {
        if (se->kernel->db.status != DB_STATUS_NOMOUNT) {
            CT_THROW_ERROR(ERR_INVALID_OPERATION, ",not nomount mode, can not restore");
            return CT_ERROR;
        }
    }

    if (param->file_type == RESTORE_ALL && ctx->bak.restored) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", restore database has been performed, "
                                              "please restart and restore again");
        return CT_ERROR;
    }

    if (rst_check_backupset_path(param) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (param->file_type == RESTORE_DATAFILE) {
        return abr_restore_file_recover((knl_session_t *)session, param);
    }

    if (knl_db_open_dbstor_ns(session) != CT_SUCCESS) {
        CT_LOG_RUN_INF("failed to open dbstore namespace");
        return CT_ERROR;
    }

    status = rst_restore_database((knl_session_t *)session, param);
    if (param->file_type == RESTORE_ALL) {
        ctx->bak.restored = CT_TRUE;
        se->kernel->db.ctrl.core.dbid = dbc_generate_dbid(se);
        db_set_ctrl_restored(se, CT_TRUE);
    }

    return status;
}

void knl_recover_get_max_lrp(knl_session_t *se, uint64 *max_recover_lrp_lsn)
{
    if (!se->kernel->db.recover_for_restore) {
        return;
    }
    uint64 max_lsn = 0;
    dtc_node_ctrl_t *ctrl;
    for (uint32 i = 0; i < se->kernel->db.ctrl.core.node_count; i++) {
        ctrl = dtc_get_ctrl(se, i);
        max_lsn = MAX(max_lsn, ctrl->lrp_point.lsn);
        CT_LOG_RUN_INF("[RECOVER] get lrp_lsn when full_recovery, the node is %u, lrp_lsn is %llu ",
                       i, ctrl->lrp_point.lsn);
    }
    *max_recover_lrp_lsn = max_lsn;
    CT_LOG_RUN_INF("[RECOVER] get the max_lrp_lsn [%llu]", *max_recover_lrp_lsn);
}

status_t knl_recover_set_end_point(knl_session_t *se, knl_recover_t *param, knl_scn_t *max_recover_scn,
                                   uint64 *max_recover_lrp_lsn)
{
    if (param->action == RECOVER_UNTIL_TIME) {
        if (param->time.tv_sec < se->kernel->db.ctrl.core.init_time) {
            CT_THROW_ERROR(ERR_RECOVER_TIME_INVALID);
            return CT_ERROR;
        }
        *max_recover_scn = KNL_TIME_TO_SCN(&param->time, DB_INIT_TIME(se));
    } else if (param->action == RECOVER_UNTIL_SCN) {
        *max_recover_scn = param->scn;
    } else {
        knl_recover_get_max_lrp(se, max_recover_lrp_lsn);
    }
    return CT_SUCCESS;
}

status_t knl_register_iof(knl_session_t *se)
{
    if (knl_dbs_is_enable_dbs()) {
        if (knl_db_open_dbstor_ns((knl_handle_t)se) != CT_SUCCESS) {
            CT_LOG_RUN_INF("failed to open dbstore namespace");
            return CT_ERROR;
        }
    } else {
        knl_instance_t *kernel = (knl_instance_t *)se->kernel;
        if (kernel->file_iof_thd.id == 0) {
            if (cm_file_iof_register(kernel->id, &kernel->file_iof_thd) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("failed to iof reg file, inst id %u", kernel->id);
                return CT_ERROR;
            }
        }
    }
    return CT_SUCCESS;
}

status_t knl_recover_precheck(knl_session_t *se, knl_recover_t *param, knl_scn_t *max_recover_scn,
                              uint64 *max_recover_lrp_lsn)
{
    if (knl_register_iof(se) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("register iof failed.");
        return CT_ERROR;
    }

    if (param->action == RECOVER_UNTIL_CANCEL) {
        if (se->kernel->db.status != DB_STATUS_MOUNT) {
            CT_THROW_ERROR(ERR_DATABASE_NOT_MOUNT, " recover database until cancle ");
            return CT_ERROR;
        }

        if (DB_IS_RAFT_ENABLED(se->kernel)) {
            CT_THROW_ERROR(ERR_INVALID_OPERATION, ", can not recover database until cancle when database in raft mode");
            return CT_ERROR;
        }
    } else {
        if (se->kernel->db.status != DB_STATUS_NOMOUNT) {
            CT_THROW_ERROR(ERR_DATABASE_ALREADY_MOUNT);
            return CT_ERROR;
        }

        if (db_mount_ctrl(se) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (knl_recover_set_end_point(se, param, max_recover_scn, max_recover_lrp_lsn) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if ((*max_recover_scn) < (uint64)dtc_my_ctrl(se)->scn) {
            CT_THROW_ERROR(ERR_RECOVER_TIME_INVALID);
            return CT_ERROR;
        }

        if (db_mount(se) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (DB_IS_PRIMARY(&se->kernel->db) &&
            (param->action == RECOVER_UNTIL_SCN || param->action == RECOVER_UNTIL_TIME)) {
            if (dtc_log_prepare_pitr(se) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

status_t knl_recover(knl_handle_t session, knl_recover_t *param)
{
    knl_session_t *se = (knl_session_t *)session;
    knl_scn_t max_recover_scn = CT_INVALID_ID64;
    uint64 max_recover_lrp_lsn = CT_INVALID_ID64;

    CM_POINTER(session);

    se->kernel->db.recover_for_restore = CT_TRUE;
    if (knl_recover_precheck(se, param, &max_recover_scn, &max_recover_lrp_lsn) != CT_SUCCESS) {
        se->kernel->db.recover_for_restore = CT_FALSE;
        return CT_ERROR;
    }

    if (log_ddl_init_file_mgr(session) != CT_SUCCESS) {
        se->kernel->db.recover_for_restore = CT_FALSE;
        return CT_ERROR;
    }

    se->kernel->rcy_ctx.action = param->action;
    if (db_recover(se, max_recover_scn, max_recover_lrp_lsn) != CT_SUCCESS) {
        se->kernel->rcy_ctx.action = RECOVER_NORMAL;
        se->kernel->db.recover_for_restore = CT_FALSE;
        log_ddl_file_end(se);
        return CT_ERROR;
    }
    se->kernel->db.recover_for_restore = CT_FALSE;
    log_ddl_file_end(se);
    return CT_SUCCESS;
}

status_t knl_daac_recover(knl_handle_t session, knl_daac_recover_t *param)
{
    knl_session_t *se = (knl_session_t *)session;

    if (!se->kernel->attr.clustered) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "cluster recover", "non-clusterd database");
        return CT_ERROR;
    }

    instance_list_t *rcy_list = (instance_list_t *)cm_push(se->stack, sizeof(instance_list_t));
    rcy_list->inst_id_count = param->count;
    for (uint32 i = 0; i < param->count; i++) {
        rcy_list->inst_id_list[i] = (uint8)(param->start + i);
    }

    status_t status = dtc_recover_crashed_nodes(se, rcy_list, (param->full == 1));
    cm_pop(se->stack);
    return status;
}

status_t knl_build(knl_handle_t session, knl_build_def_t *param)
{
    knl_session_t *se = (knl_session_t *)session;

    CM_POINTER(session);

    if (db_build_baseline(se, param) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t knl_stop_build(knl_handle_t session)
{
    knl_session_t *se = (knl_session_t *)session;
    bak_context_t *backup_ctx = &se->kernel->backup_ctx;
    bak_t *bak = &backup_ctx->bak;

    if (DB_IS_CASCADED_PHYSICAL_STANDBY(&se->kernel->db)) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", can not stop build on cascaded standby");
        return CT_ERROR;
    }

    if (!PRIMARY_IS_BUILDING(backup_ctx)) {
        return CT_SUCCESS;
    }

    bak->build_stopped = CT_TRUE;
    bak->failed = CT_TRUE;
    do {
        if (se->killed) {
            bak->build_stopped = CT_FALSE;
            bak->failed = CT_FALSE;
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            return CT_ERROR;
        }
        cm_sleep(200);
    } while (PRIMARY_IS_BUILDING(backup_ctx));

    bak->build_stopped = CT_FALSE;
    bak->failed = CT_FALSE;
    return CT_SUCCESS;
}

status_t knl_validate(knl_handle_t session, knl_validate_t *param)
{
    knl_session_t *se = (knl_session_t *)session;

    if (param->validate_type == VALIDATE_DATAFILE_PAGE) {
        return buf_validate_corrupted_page(se, param);
    } else {
        return bak_validate_backupset(se, param);
    }
}

status_t knl_lock_tables(knl_handle_t session, lock_tables_def_t *def)
{
    knl_dictionary_t dc;
    lock_table_t *table = NULL;
    galist_t *tables = &def->tables;
    knl_session_t *se = (knl_session_t *)session;
    status_t status = CT_ERROR;
    uint32 wait_time = def->wait_time;
    schema_lock_t *lock = NULL;
    dc_entity_t *entity = NULL;

    if (DB_IS_READONLY(se)) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
        return CT_ERROR;
    }

    for (uint32 i = 0; i < tables->count; i++) {
        table = (lock_table_t *)cm_galist_get(tables, i);
        if (dc_open(se, &table->schema, &table->name, &dc) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (SYNONYM_EXIST(&dc)) {
            dc_close(&dc);
            CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&table->schema), T2S_EX(&table->name));
            return CT_ERROR;
        }

        if (dc.type == DICT_TYPE_DYNAMIC_VIEW || dc.type == DICT_TYPE_VIEW ||
            dc.type == DICT_TYPE_GLOBAL_DYNAMIC_VIEW) {
            dc_close(&dc);
            CT_THROW_ERROR(ERR_INVALID_OPERATION, ",not support lock view");
            return CT_ERROR;
        }

        if (dc.type == DICT_TYPE_TEMP_TABLE_TRANS || dc.type == DICT_TYPE_TEMP_TABLE_SESSION) {
            dc_close(&dc);
            return CT_SUCCESS;
        }

        entity = (dc_entity_t *)dc.handle;
        lock = entity->entry->sch_lock;

        switch (def->lock_mode) {
            case LOCK_MODE_SHARE:
                se->wtid.is_locking = CT_TRUE;
                se->wtid.oid = entity->entry->id;
                se->wtid.uid = entity->entry->uid;
                status = lock_table_shared(se, dc.handle, wait_time);
                break;

            case LOCK_MODE_EXCLUSIVE:
                se->wtid.is_locking = CT_TRUE;
                se->wtid.oid = entity->entry->id;
                se->wtid.uid = entity->entry->uid;
                status = lock_table_exclusive(se, dc.handle, wait_time);
                break;
        }

        if (status != CT_SUCCESS) {
            break;
        }

        cm_spin_lock(&entity->entry->sch_lock_mutex, &se->stat->spin_stat.stat_sch_lock);
        SCH_LOCK_EXPLICIT(se, lock);
        cm_spin_unlock(&entity->entry->sch_lock_mutex);
    }
    se->wtid.is_locking = CT_FALSE;
    dc_close(&dc);
    return status;
}

status_t knl_load_sys_dc(knl_handle_t session, knl_alter_sys_def_t *def)
{
    text_t user;
    text_t name;
    knl_dictionary_t dc;

    cm_str2text(def->param, &user);
    cm_str2text(def->value, &name);

    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!cm_text_str_equal(&user, "SYS")) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "load sys dictionary", "non-sys user");
        return CT_ERROR;
    }

    if (dc_open((knl_session_t *)session, &user, &name, &dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t knl_init_entry(knl_handle_t session, knl_alter_sys_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;

    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (se->kernel->db.open_status != DB_OPEN_STATUS_UPGRADE) {
        if (knl_is_online_upgrading(session)) {
            return CT_SUCCESS;
        }
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "of initializing entry for upgrade mode", "non-upgrade mode");
        return CT_ERROR;
    }

    if (knl_internal_repair_catalog(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_init_all_entry_for_upgrade(se) != CT_SUCCESS) {
        return CT_ERROR;
    }

    db_update_sysdata_version(session);

    if (db_callback_function(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    se->kernel->db.open_status = DB_OPEN_STATUS_UPGRADE_PHASE_2;
    CT_LOG_RUN_INF("[UPGRADE] all entry have been initialized successfully");

    return CT_SUCCESS;
}

xact_status_t knl_xact_status(knl_handle_t session)
{
    knl_session_t *se = (knl_session_t *)session;
    txn_t *txn = NULL;

    if (se->rm == NULL) {
        return XACT_END;
    }

    txn = se->rm->txn;
    if (txn == NULL) {
        return XACT_END;
    }

    return (xact_status_t)txn->status;
}

status_t knl_flush_buffer(knl_handle_t session, knl_alter_sys_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;
    buf_context_t *ctx = &se->kernel->buf_ctx;
    buf_set_t *set = NULL;
    uint32 total = 0;

    CM_POINTER(session);

    for (uint32 i = 0; i < ctx->buf_set_count; i++) {
        set = &ctx->buf_set[i];
        total += buf_expire_cache(se, set);
    }

    CT_LOG_RUN_INF("recycled (%d) buffer ctrls.", total);
    return CT_SUCCESS;
}

void knl_free_temp_cache_memory(knl_temp_cache_t *temp_table)
{
    if (temp_table->memory != NULL) {
        mctx_destroy(temp_table->memory);
        temp_table->memory = NULL;
    }
    temp_table->stat_exists = CT_FALSE;
    temp_table->stats_version = CT_INVALID_ID32;
    temp_table->cbo_stats = NULL;
}

knl_handle_t knl_get_temp_cache(knl_handle_t session, uint32 uid, uint32 oid)
{
    knl_temp_cache_t *temp_table_ptr = NULL;
    knl_session_t *se = (knl_session_t *)session;
    uint32 i;
    for (i = 0; i < se->temp_table_count; i++) {
        temp_table_ptr = &se->temp_table_cache[i];
        if (temp_table_ptr->user_id == uid && temp_table_ptr->table_id == oid) {
            break;
        }
    }
    if (i >= se->temp_table_count) {
        return NULL;
    }
    return temp_table_ptr;
}

status_t knl_put_temp_cache(knl_handle_t session, knl_handle_t dc_entity)
{
    knl_session_t *se = (knl_session_t *)session;
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    table_t *table = &entity->table;
    knl_temp_cache_t *temp_table_ptr = NULL;
    uint32 i;
    errno_t errcode;
    index_t *index = NULL;

    for (i = 0; i < se->temp_table_count; i++) {
        if ((se->temp_table_cache[i].user_id == table->desc.uid) &&
            (se->temp_table_cache[i].table_id == table->desc.id)) {
            CT_THROW_ERROR(ERR_OBJECT_ID_EXISTS, "table id in temp table cache", table->desc.id);
            return CT_ERROR;
        }
    }

    for (i = 0; i < se->temp_table_count; i++) {
        temp_table_ptr = &se->temp_table_cache[i];
        if (temp_table_ptr->table_id == CT_INVALID_ID32) {
            break;
        }

        if (!knl_temp_object_isvalid_by_id(se, temp_table_ptr->user_id, temp_table_ptr->table_id,
                                           temp_table_ptr->org_scn)) {
            CT_LOG_RUN_WAR("free and reuse outdated temp cache for table (%d:%d), cached scn (%lld)",
                           temp_table_ptr->user_id, temp_table_ptr->table_id, temp_table_ptr->org_scn);
            knl_free_temp_vm(session, temp_table_ptr);
            break;
        }
    }

    if (i >= se->temp_table_capacity) {
        CT_THROW_ERROR(ERR_TOO_MANY_OBJECTS, se->temp_table_capacity, "items in temp table cache");
        return CT_ERROR;
    }

    if (i >= se->temp_table_count) {
        se->temp_table_count++;
    }

    temp_table_ptr = &se->temp_table_cache[i];
    temp_table_ptr->table_type = entity->type;
    temp_table_ptr->org_scn = table->desc.org_scn;
    temp_table_ptr->seg_scn = se->temp_version++;
    temp_table_ptr->chg_scn = table->desc.chg_scn;
    temp_table_ptr->user_id = table->desc.uid;
    temp_table_ptr->table_id = table->desc.id;
    temp_table_ptr->table_segid = CT_INVALID_ID32;
    temp_table_ptr->index_segid = CT_INVALID_ID32;
    temp_table_ptr->rows = 0;
    temp_table_ptr->serial = 0;
    temp_table_ptr->cbo_stats = NULL;
    temp_table_ptr->rmid = se->rmid;
    temp_table_ptr->hold_rmid = CT_INVALID_ID32;

    if (temp_table_ptr->memory != NULL) {
        knl_free_temp_cache_memory(temp_table_ptr);
    }

    errcode = memset_sp(&temp_table_ptr->index_root, sizeof(temp_table_ptr->index_root), 0xFF,
                        sizeof(temp_table_ptr->index_root));
    knl_securec_check(errcode);

    for (i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        temp_table_ptr->index_root[index->desc.id].org_scn = index->desc.org_scn;
    }

    return CT_SUCCESS;
}

void knl_free_temp_vm(knl_handle_t session, knl_handle_t temp_table)
{
    knl_session_t *se = (knl_session_t *)session;
    knl_temp_cache_t *cache = (knl_temp_cache_t *)temp_table;

    if (cache->table_segid != CT_INVALID_ID32) {
        temp_drop_segment(se->temp_mtrl, cache->table_segid);
        cache->table_segid = CT_INVALID_ID32;
    }

    if (cache->index_segid != CT_INVALID_ID32) {
        temp_drop_segment(se->temp_mtrl, cache->index_segid);
        cache->index_segid = CT_INVALID_ID32;
    }

    cache->table_id = CT_INVALID_ID32;

    knl_free_temp_cache_memory(cache);

    (void)g_knl_callback.invalidate_temp_cursor(session, cache);
}

bool32 knl_is_temp_table_empty(knl_handle_t session, uint32 uid, uint32 oid)
{
    temp_heap_page_t *page = NULL;
    vm_page_t *vm_page = NULL;
    mtrl_segment_t *segment = NULL;
    knl_temp_cache_t *temp_table = NULL;
    knl_session_t *se = (knl_session_t *)session;
    uint32 vmid;

    temp_table = knl_get_temp_cache(session, uid, oid);
    if (temp_table == NULL || temp_table->table_segid == CT_INVALID_ID32) {
        return CT_TRUE;
    }

    segment = se->temp_mtrl->segments[temp_table->table_segid];
    if (segment->vm_list.count > 1) {
        return CT_FALSE;
    }

    vmid = segment->vm_list.last;
    if (buf_enter_temp_page_nolock(se, vmid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to open vm (%d) when check temp table.", vmid);
        return CT_FALSE;
    }

    vm_page = buf_curr_temp_page(se);
    page = (temp_heap_page_t *)vm_page->data;
    if (page->dirs == 0) {
        buf_leave_temp_page_nolock(se, CT_FALSE);
        return CT_TRUE;
    }

    buf_leave_temp_page_nolock(se, CT_FALSE);
    return CT_FALSE;
}

status_t knl_ensure_temp_cache(knl_handle_t session, knl_handle_t dc_entity, knl_temp_cache_t **temp_table_ret)
{
    knl_session_t *se = (knl_session_t *)session;
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    table_t *table = &entity->table;
    knl_temp_cache_t *temp_table;

    temp_table = knl_get_temp_cache(session, table->desc.uid, table->desc.id);
    if (temp_table != NULL) {
        if (temp_table->org_scn != table->desc.org_scn) {
            CT_LOG_RUN_WAR("Found invalid temp cache for table (%d:%d), dc scn(%lld), cached scn (%lld)",
                           table->desc.uid, table->desc.id, table->desc.org_scn, temp_table->org_scn);

            knl_free_temp_vm(session, temp_table);
            temp_table = NULL;
        } else {
            if (temp_table->mem_chg_scn != table->desc.chg_scn) {
                knl_free_temp_cache_memory(temp_table);
            }
        }
    }
    if (temp_table == NULL) {
        if (knl_put_temp_cache(session, dc_entity) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_TOO_MANY_OBJECTS, se->temp_table_capacity, "temp tables opened");
            *temp_table_ret = NULL;
            return CT_ERROR;
        }

        temp_table = knl_get_temp_cache(session, table->desc.uid, table->desc.id);
        knl_panic_log(
            temp_table->org_scn == table->desc.org_scn && temp_table != NULL,
            "temp_table's org_scn is not equal to table, panic info: temp_table org_scn %llu table %s org_scn %llu",
            temp_table->org_scn, entity->table.desc.name, table->desc.org_scn);

        if (temp_heap_create_segment(se, temp_table) != CT_SUCCESS) {
            knl_free_temp_vm(session, temp_table);
            *temp_table_ret = NULL;
            return CT_ERROR;
        }

        if (entity->contain_lob) {
            if (lob_temp_create_segment(se, temp_table) != CT_SUCCESS) {
                knl_free_temp_vm(session, temp_table);
                *temp_table_ret = NULL;
                return CT_ERROR;
            }
        }

    }
    /* one for temp heap, one for temp index */
    knl_panic_log(temp_table->table_segid < se->temp_table_capacity * 2,
                  "temp_table's table_segid is invalid, panic info: table %s table_segid %u temp_table_capacity %u",
                  entity->table.desc.name, temp_table->table_segid, se->temp_table_capacity);

    *temp_table_ret = temp_table;
    if (temp_table->stat_exists) {
        temp_table->stats_version++;
    }
    return CT_SUCCESS;
}

status_t knl_ensure_temp_index(knl_handle_t session, knl_cursor_t *cursor, knl_dictionary_t *dc,
                               knl_temp_cache_t *temp_table)
{
    table_t *table = DC_TABLE(dc);
    index_t *index = NULL;
    temp_btree_segment_t *root_seg = NULL;
    knl_session_t *se = (knl_session_t *)session;

    if (temp_table->chg_scn == table->desc.chg_scn) {
        return CT_SUCCESS;
    }

    for (uint32 i = 0; i < table->index_set.count; i++) {
        index = table->index_set.items[i];
        root_seg = &temp_table->index_root[index->desc.id];

        if (root_seg->org_scn == index->desc.org_scn) {
            continue;
        }

        // index has been dropped and recreated
        if (cursor->action != CURSOR_ACTION_INSERT && cursor->scan_mode == SCAN_MODE_INDEX &&
            cursor->index_slot == index->desc.slot) {
            dc_user_t *user = NULL;

            if (dc_open_user_by_id(se, index->desc.uid, &user) != CT_SUCCESS) {
                return CT_ERROR;
            }

            CT_THROW_ERROR(ERR_INDEX_NOT_EXIST, user->desc.name, index->desc.name);
            return CT_ERROR;
        }

        root_seg->root_vmid = CT_INVALID_ID32;
    }

    return CT_SUCCESS;
}

/* get the temp table cache and attach it with one rm */
static status_t knl_attach_temp_cache(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
                                      knl_temp_cache_t **temp_table_ret)
{
    knl_temp_cache_t *temp_table = NULL;

    if (knl_ensure_temp_cache(session, entity, &temp_table) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cursor->action > CURSOR_ACTION_SELECT) {
        if (temp_table->hold_rmid != CT_INVALID_ID32 && temp_table->hold_rmid != session->rmid) {
            CT_THROW_ERROR(ERR_TEMP_TABLE_HOLD, entity->entry->user->desc.name, entity->table.desc.name);
            return CT_ERROR;
        }

        if (temp_table->hold_rmid == CT_INVALID_ID32) {
            temp_table->hold_rmid = session->rmid;
        }
    }

    *temp_table_ret = temp_table;
    return CT_SUCCESS;
}

status_t knl_open_temp_cursor(knl_handle_t session, knl_cursor_t *cursor, knl_dictionary_t *dc)
{
    knl_session_t *se = (knl_session_t *)session;
    knl_temp_cache_t *temp_table = NULL;
    dc_entity_t *entity = DC_ENTITY(dc);

    if (knl_attach_temp_cache(session, cursor, entity, &temp_table) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* 2 means one for temp heap, one for temp index */
    knl_panic_log(temp_table->table_segid < se->temp_table_capacity * 2,
                  "temp_table's table_segid is invalid, "
                  "panic info: page %u-%u type %u table %s index %s table_segid %u",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  entity->table.desc.name, ((index_t *)cursor->index)->desc.name, temp_table->table_segid);
    mtrl_segment_t *segment = se->temp_mtrl->segments[temp_table->table_segid];
    cursor->rowid.vmid = segment->vm_list.first;
    cursor->rowid.vm_slot = CT_INVALID_ID16;
    cursor->rowid.vm_tag = CT_INVALID_ID16;
    cursor->temp_cache = temp_table;
    cursor->ssn = se->ssn;
    cursor->index = NULL;
    cursor->rowid_no = 0;
    cursor->key_loc.is_initialized = CT_FALSE;

    knl_panic_log(segment->vm_list.count > 0,
                  "the count of vm page list is incorrect, panic info: "
                  "page %u-%u type %u table %s index %s vm_list count %u",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  entity->table.desc.name, ((index_t *)cursor->index)->desc.name, segment->vm_list.count);

    if (knl_ensure_temp_index((knl_session_t *)session, cursor, dc, temp_table) != CT_SUCCESS) {
        knl_free_temp_vm(session, temp_table);
        temp_table = NULL;
        return CT_ERROR;
    }

    if (cursor->action == CURSOR_ACTION_INSERT) {
        cursor->rowid_count = 0;
        cursor->row_offset = 0;
        return CT_SUCCESS;
    }

    if (cursor->scan_mode == SCAN_MODE_INDEX) {
        index_t *index = DC_INDEX(dc, cursor->index_slot);
        cursor->index = index;
        cursor->fetch = index->acsor->do_fetch;

        temp_btree_segment_t *root_seg = &temp_table->index_root[((index_t *)cursor->index)->desc.id];
        if (root_seg->root_vmid == CT_INVALID_ID32) {
            if (CT_SUCCESS != temp_btree_create_segment(se, (index_t *)cursor->index, temp_table)) {
                CT_THROW_ERROR(ERR_VM, "fail to create temp_btree_create_segment in knl_open_temp_cursor");
                return CT_ERROR;
            }
        }

        ((index_t *)cursor->index)->desc.entry.vmid = 0;
        ((index_t *)cursor->index)->temp_btree = NULL;
        /* one for heap, one for index */
        knl_panic_log(
            temp_table->index_segid < se->temp_table_capacity * 2,
            "temp_table's index_segid is invalid, panic info: page %u-%u type %u table %s index %s index_segid %u",
            cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, entity->table.desc.name,
            ((index_t *)cursor->index)->desc.name, temp_table->index_segid);
    } else if (cursor->scan_mode == SCAN_MODE_TABLE_FULL) {
        cursor->fetch = TABLE_ACCESSOR(cursor)->do_fetch;
        return CT_SUCCESS;
    } else if (cursor->scan_mode == SCAN_MODE_ROWID) {
        cursor->fetch = TABLE_ACCESSOR(cursor)->do_rowid_fetch;
        return CT_SUCCESS;
    }

    return CT_SUCCESS;
}

status_t knl_exec_grant_privs(knl_handle_t session, knl_grant_def_t *def)
{
    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return db_exec_grant_privs((knl_session_t *)session, def);
}

status_t knl_exec_revoke_privs(knl_handle_t session, knl_revoke_def_t *def)
{
    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return db_exec_revoke_privs((knl_session_t *)session, def);
}
void knl_close_temp_tables(knl_handle_t session, knl_dict_type_t type)
{
    uint32 i;
    knl_temp_cache_t *temp_table_ptr = NULL;
    knl_session_t *se = (knl_session_t *)session;

    for (i = 0; i < se->temp_table_count; i++) {
        temp_table_ptr = &se->temp_table_cache[i];
        if (temp_table_ptr->table_id != CT_INVALID_ID32) {
            if (temp_table_ptr->table_segid != CT_INVALID_ID32 && type >= temp_table_ptr->table_type &&
                (temp_table_ptr->hold_rmid == CT_INVALID_ID32 ||
                 (temp_table_ptr->hold_rmid != CT_INVALID_ID32 && temp_table_ptr->hold_rmid == se->rmid))) {
                knl_free_temp_vm(session, temp_table_ptr);
            }
        }
    }
    if (type == DICT_TYPE_TEMP_TABLE_SESSION) {
        temp_mtrl_release_context(se);
        se->temp_table_count = 0;
    }
}

status_t knl_init_temp_dc(knl_handle_t session)
{
    knl_session_t *sess = (knl_session_t *)session;
    dc_context_t *dc_ctx = &sess->kernel->dc_ctx;
    memory_context_t *context = NULL;
    errno_t ret;

    if (dc_create_memory_context(dc_ctx, &context) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_temp_dc_t *temp_dc = NULL;
    if (dc_alloc_mem(dc_ctx, context, sizeof(knl_temp_dc_t), (void **)&temp_dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ret = memset_sp(temp_dc, sizeof(knl_temp_dc_t), 0, sizeof(knl_temp_dc_t));
    knl_securec_check(ret);

    temp_dc->entries = sess->temp_dc_entries;
    ret = memset_sp(temp_dc->entries, sizeof(void *) * sess->temp_table_capacity, 0,
                    sizeof(void *) * sess->temp_table_capacity);
    knl_securec_check(ret);

    temp_dc->ctx = (void *)context;
    sess->temp_dc = temp_dc;

    return CT_SUCCESS;
}
void knl_release_temp_dc(knl_handle_t session)
{
    knl_session_t *sess = (knl_session_t *)session;
    knl_temp_dc_t *temp_dc = sess->temp_dc;
    if (temp_dc != NULL) {
        for (uint32 i = 0; i < sess->temp_table_capacity; i++) {
            dc_entry_t *entry = (dc_entry_t *)temp_dc->entries[i];
            if (entry != NULL) {
                mctx_destroy(entry->entity->memory);
            }
        }

        memory_context_t *ctx = (memory_context_t *)(temp_dc->ctx);
        mctx_destroy(ctx);
        sess->temp_dc = NULL;
    }
}

status_t knl_get_lob_recycle_pages(knl_handle_t se, page_id_t entry, uint32 *extents, uint32 *pages, uint32 *page_size)
{
    knl_session_t *session = (knl_session_t *)se;
    page_head_t *head = NULL;
    lob_segment_t *lob_segment = NULL;
    datafile_t *datafile = NULL;
    space_t *space = NULL;

    if (!spc_validate_page_id(session, entry)) {
        /* treat it as empty table */
        *extents = 0;
        *pages = 0;
        *page_size = DEFAULT_PAGE_SIZE(session);
        return CT_SUCCESS;
    }

    if (buf_read_page(session, entry, LATCH_MODE_S, ENTER_PAGE_NORMAL) != CT_SUCCESS) {
        return CT_ERROR;
    }

    head = (page_head_t *)session->curr_page;

    if (head->type != PAGE_TYPE_LOB_HEAD) {
        buf_leave_page(session, CT_FALSE);
        CT_THROW_ERROR(ERR_INVALID_SEGMENT_ENTRY);
        return CT_ERROR;
    }

    lob_segment = (lob_segment_t *)(session->curr_page + sizeof(page_head_t));
    *pages = lob_segment->free_list.count;
    buf_leave_page(session, CT_FALSE);

    datafile = DATAFILE_GET(session, entry.file);
    space = SPACE_GET(session, datafile->space_id);
    *page_size = DEFAULT_PAGE_SIZE(session);
    *extents = (*pages + space->ctrl->extent_size - 1) / space->ctrl->extent_size;

    return CT_SUCCESS;
}

static status_t knl_find_ltt_slot(knl_session_t *session, uint32 *tmp_id)
{
    uint32 id = 0;
    for (id = 0; id < session->temp_table_capacity; id++) {
        dc_entry_t *entry = (dc_entry_t *)session->temp_dc->entries[id];
        if (entry == NULL) {
            break;
        }
    }

    if (id >= session->temp_table_capacity) {
        CT_THROW_ERROR(ERR_TOO_MANY_OBJECTS, session->temp_table_capacity, "local temporary tables");
        return CT_ERROR;
    }

    *tmp_id = id;
    return CT_SUCCESS;
}

status_t knl_create_ltt(knl_handle_t session, knl_table_def_t *def, bool32 *is_existed)
{
    CT_LOG_RUN_INF("[DB] Start to create tmp table %s", T2S_EX(&def->name));
    memory_context_t *ctx = NULL;
    dc_entry_t *entry = NULL;
    dc_entity_t *entity = NULL;
    knl_session_t *sess = (knl_session_t *)session;
    dc_context_t *dc_ctx = &sess->kernel->dc_ctx;
    errno_t ret;
    dc_user_t *user = NULL;
    *is_existed = CT_FALSE;

    if (knl_ddl_enabled4ltt(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_open_user(sess, &def->schema, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_dictionary_t dc;

    if (dc_find_ltt(sess, user, &def->name, &dc, is_existed) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (*is_existed) {
        if (def->options & CREATE_IF_NOT_EXISTS) {
            CT_LOG_DEBUG_INF("[DB] tmp table %s has already exists, end create", T2S_EX(&def->name));
            return CT_SUCCESS;
        }
        CT_THROW_ERROR(ERR_OBJECT_EXISTS, user->desc.name, T2S(&def->name));
        return CT_ERROR;
    }

    uint32 tmp_id = 0;
    if (knl_find_ltt_slot(sess, &tmp_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_create_memory_context(dc_ctx, &ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_alloc_mem(dc_ctx, ctx, sizeof(dc_entity_t), (void **)&entity) != CT_SUCCESS) {
        mctx_destroy(ctx);
        return CT_ERROR;
    }

    ret = memset_sp(entity, sizeof(dc_entity_t), 0, sizeof(dc_entity_t));
    knl_securec_check(ret);
    entity->memory = ctx;
    knl_table_desc_t *desc = &entity->table.desc;
    if (db_init_table_desc(sess, desc, def) != CT_SUCCESS) {
        mctx_destroy(ctx);
        return CT_ERROR;
    }

    if (dc_create_ltt_entry(sess, ctx, user, desc, tmp_id, &entry) != CT_SUCCESS) {
        mctx_destroy(ctx);
        return CT_ERROR;
    }

    entity->type = entry->type;
    entity->entry = entry;
    entry->entity = entity;
    entity->valid = CT_TRUE;

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_CREATE_TMP_TABLE_BEFORE_CREATE_LTT_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    status_t status = db_create_ltt(sess, def, entity);
    if (status != CT_SUCCESS) {
        mctx_destroy(ctx);
        return CT_ERROR;
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_CREATE_TMP_TABLE_AFTER_CREATE_LTT_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    entry->ready = CT_TRUE;
    sess->temp_dc->entries[tmp_id] = entity->entry;

    CT_LOG_RUN_INF("[DB] Finish to create tmp table %s, ret: %d", T2S_EX(&def->name), status);
    return CT_SUCCESS;
}

status_t knl_drop_ltt(knl_handle_t session, knl_drop_def_t *def)
{
    CT_LOG_RUN_INF("[DB] Start to drop tmp table %s", T2S_EX(&def->name));
    knl_dictionary_t dc;
    dc_user_t *user = NULL;
    bool32 found = CT_FALSE;
    knl_session_t *se = (knl_session_t *)session;

    if (knl_ddl_enabled4ltt(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_open_user(se, &def->owner, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_find_ltt(se, user, &def->name, &dc, &found) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!found) {
        if (def->options & DROP_IF_EXISTS) {
            return CT_SUCCESS;
        }
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&def->owner), T2S_EX(&def->name));
        return CT_ERROR;
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_DROP_TMP_TABLE_BEFORE_RELEASE_LTT_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    cm_latch_x(&se->ltt_latch, se->id, NULL);
    status_t status = db_drop_ltt(se, &dc);
    cm_unlatch(&se->ltt_latch, NULL);
    CT_LOG_RUN_INF("[DB] Finish to drop tmp table %s, ret:%d", T2S_EX(&def->name), status);

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_DROP_TMP_TABLE_AFTER_RELEASE_LTT_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return status;
}

status_t knl_create_ltt_index(knl_handle_t session, knl_index_def_t *def)
{
    knl_dictionary_t dc;
    knl_session_t *se = (knl_session_t *)session;

    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_open(se, &def->user, &def->table, &dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_judge_index_exist(session, def, DC_ENTITY(&dc))) {
        dc_close(&dc);

        if (def->options & CREATE_IF_NOT_EXISTS) {
            return CT_SUCCESS;
        }
        CT_THROW_ERROR(ERR_OBJECT_EXISTS, "index", T2S(&def->name));
        return CT_ERROR;
    }

    if (db_create_ltt_index(se, def, &dc, CT_TRUE) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }

    dc_close(&dc);
    return CT_SUCCESS;
}

status_t knl_drop_ltt_index(knl_handle_t session, knl_drop_def_t *def)
{
    knl_dictionary_t dc;

    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (def->ex_owner.str == NULL || def->ex_name.str == NULL) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "drop index needs on clause for local temporary table");
        return CT_ERROR;
    }

    if (!cm_text_equal(&def->owner, &def->ex_owner)) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "the owner of index and table need to be the same");
        return CT_ERROR;
    }

    if (dc_open((knl_session_t *)session, &def->ex_owner, &def->ex_name, &dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    table_t *table = DC_TABLE(&dc);
    index_t *index = NULL;
    for (uint32 i = 0; i < table->index_set.count; i++) {
        index_t *ptr = table->index_set.items[i];
        if (cm_text_str_equal(&def->name, ptr->desc.name)) {
            index = ptr;
            break;
        }
    }

    if (index == NULL) {
        dc_close(&dc);
        CT_THROW_ERROR(ERR_INDEX_NOT_EXIST, T2S(&def->owner), T2S_EX(&def->name));
        return CT_ERROR;
    }

    knl_temp_cache_t *temp_cache = knl_get_temp_cache(session, dc.uid, dc.oid);
    if (temp_cache != NULL) {
        dc_entity_t *entity = DC_ENTITY(&dc);
        knl_table_desc_t *desc = &entity->table.desc;

        knl_panic_log(temp_cache->org_scn == desc->org_scn,
                      "the temp_cache's org_scn is not equal to table, "
                      "panic info: table %s index %s temp_cache org_scn %llu table org_scn %llu",
                      desc->name, index->desc.name, temp_cache->org_scn, desc->org_scn);

        if (temp_cache->index_segid != CT_INVALID_ID32) {
            temp_cache->index_root[index->desc.id].root_vmid = CT_INVALID_ID32;
        }

        temp_cache->index_root[index->desc.id].org_scn = CT_INVALID_ID64;
    }

    uint32 slot = index->desc.slot;
    index_t *end_index = table->index_set.items[table->index_set.count - 1];
    table->index_set.items[slot] = end_index;
    end_index->desc.slot = slot;
    table->index_set.items[table->index_set.count - 1] = NULL;
    table->index_set.count--;
    table->index_set.total_count--;

    dc_close(&dc);
    return CT_SUCCESS;
}

void knl_set_logbuf_stack(knl_handle_t kernel, uint32 sid, char *plog_buf, cm_stack_t *stack)
{
    knl_instance_t *ctx = (knl_instance_t *)kernel;
    knl_session_t *session = ctx->sessions[sid];
    session->stack = stack;
    session->log_buf = plog_buf;
}

bool32 knl_exist_session_wait(knl_handle_t se)
{
    knl_session_t *session = (knl_session_t *)se;
    for (uint16 event = 0; event < WAIT_EVENT_COUNT; event++) {
        if (session->wait_pool[event].event != IDLE_WAIT) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

bool32 knl_hang_session_wait(knl_handle_t se)
{
    knl_session_t *session = (knl_session_t *)se;
    for (uint16 event = 0; event < WAIT_EVENT_COUNT; event++) {
        if (session->wait_pool[event].is_waiting) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

void knl_begin_session_wait(knl_handle_t se, wait_event_t event, bool32 immediate)
{
    knl_session_t *session = (knl_session_t *)se;
    knl_session_wait_t *wait = &session->wait_pool[event];
    if (wait->is_waiting) {
        return;
    }
    wait->event = event;
    wait->usecs = 0;
    wait->pre_spin_usecs = cm_total_spin_usecs();
    wait->is_waiting = CT_TRUE;
    wait->begin_time = session->kernel->attr.timer->now;
    wait->immediate = immediate;
    if (!immediate || !session->kernel->attr.enable_timed_stat) {
        return;
    }
    (void)cm_gettimeofday(&wait->begin_tv);

}

void knl_end_session_wait(knl_handle_t se, wait_event_t event)
{
    knl_session_t *session = (knl_session_t *)se;
    knl_session_wait_t *wait = &session->wait_pool[event];
    timeval_t tv_end;
    if (!wait->is_waiting) {
        return;
    }
    if (wait->immediate && session->kernel->attr.enable_timed_stat) {
        (void)cm_gettimeofday(&tv_end);
        wait->usecs = TIMEVAL_DIFF_US(&wait->begin_tv, &tv_end);
    } else {
        wait->usecs = cm_total_spin_usecs() - wait->pre_spin_usecs;
    }
    session->stat->wait_time[event] += wait->usecs;
    session->stat->wait_count[event]++;
    wait->is_waiting = CT_FALSE;
}

void knl_end_session_waits(knl_handle_t se)
{
    for (uint16 event = 0; event < WAIT_EVENT_COUNT; event++) {
        knl_end_session_wait(se, event);
    }
}

status_t knl_begin_itl_waits(knl_handle_t se, uint32 *itl_waits)
{
    knl_session_t *session = (knl_session_t *)se;

    if (session->itl_dead_locked) {
        CT_THROW_ERROR(ERR_DEAD_LOCK, "itl", session->id);
        return CT_ERROR;
    }

    if (session->lock_dead_locked) {
        CT_THROW_ERROR(ERR_DEAD_LOCK, "lock", session->id);
        return CT_ERROR;
    }

    if (session->dead_locked) {
        CT_THROW_ERROR(ERR_DEAD_LOCK, "transaction", session->id);
        return CT_ERROR;
    }

    if (session->canceled) {
        CT_THROW_ERROR(ERR_OPERATION_CANCELED);
        return CT_ERROR;
    }

    if (session->killed) {
        CT_THROW_ERROR(ERR_OPERATION_KILLED);
        return CT_ERROR;
    }

    if (!session->wait_pool[ENQ_TX_ITL].is_waiting) {
        *itl_waits = *itl_waits + 1;
    }

    knl_begin_session_wait(session, ENQ_TX_ITL, CT_TRUE);
    cm_spin_sleep_and_stat2(1);
    return CT_SUCCESS;
}

void knl_end_itl_waits(knl_handle_t se)
{
    knl_session_t *session = (knl_session_t *)se;

    knl_end_session_wait(session, ENQ_TX_ITL);
    session->wpid = INVALID_PAGID;
    session->itl_dead_locked = CT_FALSE;
    session->dead_locked = CT_FALSE;
    session->lock_dead_locked = CT_FALSE;
}

bool32 knl_db_is_primary(knl_handle_t session)
{
    CM_POINTER(session);
    knl_session_t *se = (knl_session_t *)session;
    database_t *db = &se->kernel->db;

    return DB_IS_PRIMARY(db);
}

bool32 knl_db_is_physical_standby(knl_handle_t session)
{
    CM_POINTER(session);
    knl_session_t *se = (knl_session_t *)session;
    database_t *db = &se->kernel->db;

    return DB_IS_PHYSICAL_STANDBY(db);
}

bool32 knl_db_is_cascaded_standby(knl_handle_t session)
{
    CM_POINTER(session);
    knl_session_t *se = (knl_session_t *)session;
    database_t *db = &se->kernel->db;

    return DB_IS_CASCADED_PHYSICAL_STANDBY(db);
}

#ifdef DB_DEBUG_VERSION
status_t knl_add_syncpoint(knl_handle_t session, syncpoint_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;

    CM_POINTER2(session, def);

    if (DB_IS_READONLY(se)) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
        return CT_ERROR;
    }

    return sp_add_syncpoint(se, def);
}

status_t knl_reset_syncpoint(knl_handle_t session)
{
    knl_session_t *se = (knl_session_t *)session;

    CM_POINTER(session);

    if (DB_IS_READONLY(se)) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
        return CT_ERROR;
    }

    return sp_reset_syncpoint(se);
}

status_t knl_exec_syncpoint(knl_handle_t session, const char *syncpoint_name)
{
    CM_POINTER2(session, syncpoint_name);

    return sp_exec_syncpoint(session, syncpoint_name);
}

void knl_clear_syncpoint_action(knl_handle_t session)
{
    CM_POINTER(session);

    sp_clear_syncpoint_action(session);
}

status_t knl_exec_global_syncpoint(uint32 sp_id, int32* user_param, int32 ret)
{
    return sp_exec_global_syncpoint(sp_id, user_param, ret);
}

status_t knl_set_global_syncpoint(syncpoint_def_t *def)
{
    return sp_set_global_syncpoint(def);
}

bool32 knl_get_global_syncpoint_flag(uint32 sp_id)
{
    return sp_get_global_syncpoint_flag(sp_id);
}

uint32 knl_get_global_syncpoint_count(uint32 sp_id)
{
    return sp_get_global_syncpoint_count(sp_id);
}

const char* knl_get_global_syncpoint_name(uint32 sp_id)
{
    return sp_get_global_syncpoint_name(sp_id);
}

uint32 knl_get_global_syncpoint_total_count(void)
{
    return sp_get_global_syncpoint_total_count();
}

#endif /* DB_DEBUG_VERSION */

status_t knl_analyze_table_dynamic(knl_handle_t session, knl_analyze_tab_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;

    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (def->part_no != CT_INVALID_ID32) {
        return db_analyze_table_part(se, def, CT_TRUE);
    } else {
        return db_analyze_table(se, def, CT_TRUE);
    }
}

status_t knl_analyze_table(knl_handle_t session, knl_analyze_tab_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;

    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (def->part_name.len > 0 ||
       (((session_t *)session)->is_tse && (def->part_no != CT_INVALID_ID32))) {
        return db_analyze_table_part(se, def, CT_FALSE);
    } else {
        return db_analyze_table(se, def, CT_FALSE);
    }
}

status_t knl_analyze_index_dynamic(knl_handle_t session, knl_analyze_index_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;

    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return db_analyze_index(se, def, CT_TRUE);
}

status_t knl_write_sysddm(knl_handle_t *session, knl_ddm_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;
    knl_dictionary_t dc;

    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (knl_open_dc_by_id(session, def->uid, def->oid, &dc, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    uint32 timeout = se->kernel->attr.ddl_lock_timeout;
    if (lock_table_directly(se, &dc, timeout) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }
    if (db_write_sysddm(se, def) != CT_SUCCESS) {
        unlock_tables_directly(se);
        dc_close(&dc);
        return CT_ERROR;
    }
    knl_ddm_write_rd(session, &dc);
    knl_commit(session);
    dc_invalidate(se, (dc_entity_t *)dc.handle);
    unlock_tables_directly(se);
    dc_close(&dc);
    return CT_SUCCESS;
}
status_t knl_check_ddm_rule(knl_handle_t *session, text_t ownname, text_t tabname, text_t rulename)
{
    knl_dictionary_t dc;
    knl_session_t *se = (knl_session_t *)session;
    knl_ddm_def_t def;
    errno_t ret = memset_sp(&def, sizeof(knl_ddm_def_t), 0, sizeof(knl_ddm_def_t));
    knl_securec_check(ret);
    if (dc_open(se, &ownname, &tabname, &dc) != CT_SUCCESS) {
        return CT_ERROR;
    }
    def.uid = dc.uid;
    def.oid = dc.oid;
    dc_close(&dc);
    if (cm_text2str(&rulename, def.rulename, CT_NAME_BUFFER_SIZE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return db_check_rule_exists_by_name(se, &def);
}

status_t knl_drop_ddm_rule_by_name(knl_handle_t *session, text_t ownname, text_t tabname, text_t rulename)
{
    knl_session_t *se = (knl_session_t *)session;
    knl_dictionary_t dc;
    knl_ddm_def_t def;
    errno_t ret = memset_sp(&def, sizeof(knl_ddm_def_t), 0, sizeof(knl_ddm_def_t));
    knl_securec_check(ret);

    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_open(se, &ownname, &tabname, &dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    uint32 timeout = se->kernel->attr.ddl_lock_timeout;
    if (lock_table_directly(se, &dc, timeout) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }
    def.uid = dc.uid;
    def.oid = dc.oid;
    (void)cm_text2str(&rulename, def.rulename, CT_NAME_BUFFER_SIZE);
    if (db_check_rule_exists_by_name(se, &def) == CT_ERROR) {
        unlock_tables_directly(se);
        dc_close(&dc);
        return CT_ERROR;
    }
    if (db_drop_ddm_rule_by_name(se, &def) != CT_SUCCESS) {
        unlock_tables_directly(se);
        dc_close(&dc);
        return CT_ERROR;
    }
    knl_ddm_write_rd(session, &dc);
    knl_commit(session);
    dc_invalidate(se, (dc_entity_t *)dc.handle);
    unlock_tables_directly(se);
    dc_close(&dc);
    return CT_SUCCESS;
}

status_t knl_analyze_index(knl_handle_t session, knl_analyze_index_def_t *def)
{
    knl_session_t *se = (knl_session_t *)session;

    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return db_analyze_index(se, def, CT_FALSE);
}

/*
 * knl_analyze_schema
 *
 * This procedure gathers statistics for all objects in a schema.
 */
status_t knl_analyze_schema(knl_handle_t session, knl_analyze_schema_def_t *def)
{
    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return db_analyze_schema((knl_session_t *)session, def);
}

/*
 * knl_delete_table_stats
 *
 * This function is used to delete stat info of table.
 */
status_t knl_delete_table_stats(knl_handle_t session, text_t *own_name, text_t *tab_name, text_t *part_name)
{
    knl_session_t *se = (knl_session_t *)session;

    if (DB_IS_READONLY(se)) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
        return CT_ERROR;
    }

    return db_delete_table_stats(se, own_name, tab_name, part_name);
}

/*
 * knl_delete_schema_stats
 *
 * This function is used to delete stat info of a schema.
 */
status_t knl_delete_schema_stats(knl_handle_t session, text_t *schema_name)
{
    return db_delete_schema_stats((knl_session_t *)session, schema_name);
}

char *knl_get_db_name(knl_handle_t session)
{
    CM_POINTER(session);
    knl_session_t *se = (knl_session_t *)session;
    database_t *db = &se->kernel->db;

    return db->ctrl.core.name;
}

db_status_t knl_get_db_status(knl_handle_t session)
{
    CM_POINTER(session);
    knl_session_t *se = (knl_session_t *)session;
    database_t *db = &se->kernel->db;

    return db->status;
}
db_open_status_t knl_get_db_open_status(knl_handle_t session)
{
    CM_POINTER(session);
    knl_session_t *se = (knl_session_t *)session;
    database_t *db = &se->kernel->db;

    return db->open_status;
}

uint64 knl_txn_buffer_size(uint32 page_size, uint32 segment_count)
{
    uint32 txn_per_page = (page_size - PAGE_HEAD_SIZE - PAGE_TAIL_SIZE) / sizeof(txn_t);

    /* txn undo page of one undo segment is UNDO_MAX_TXN_PAGE * SIZE_K(8) / page_size */
    uint64 capacity = (uint64)segment_count * (UNDO_MAX_TXN_PAGE * SIZE_K(8) / page_size) * txn_per_page;

    return capacity * sizeof(tx_item_t);
}

status_t knl_get_segment_size_by_cursor(knl_handle_t se, knl_cursor_t *knl_cur, uint32 *extents, uint32 *pages,
                                        uint32 *page_size)
{
    page_id_t entry;
    knl_session_t *session = (knl_session_t *)se;
    heap_t *heap = CURSOR_HEAP(knl_cur);
    heap_segment_t *segment = (heap_segment_t *)heap->segment;
    if (segment != NULL) {
        buf_enter_page(session, heap->entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
        segment = (heap_segment_t *)heap->segment;
        buf_leave_page(session, CT_FALSE);

        entry = segment->extents.first;
        if (knl_get_segment_size(session, entry, extents, pages, page_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        *extents = 0;
        *pages = 0;
        *page_size = 0;
    }
    return CT_SUCCESS;
}

status_t knl_get_segment_size(knl_handle_t se, page_id_t entry, uint32 *extents, uint32 *pages, uint32 *page_size)
{
    knl_session_t *session = (knl_session_t *)se;
    btree_segment_t *btree_segment = NULL;
    heap_segment_t *heap_segment = NULL;
    lob_segment_t *lob_segment = NULL;

    if (!spc_validate_page_id(session, entry)) {
        /* treat it as empty table */
        *extents = 0;
        *pages = 0;
        *page_size = DEFAULT_PAGE_SIZE(session);

        return CT_SUCCESS;
    }

    if (buf_read_page(session, entry, LATCH_MODE_S, ENTER_PAGE_NORMAL) != CT_SUCCESS) {
        return CT_ERROR;
    }

    page_head_t *head = (page_head_t *)session->curr_page;
    datafile_t *datafile = DATAFILE_GET(session, entry.file);
    space_t *space = SPACE_GET(session, datafile->space_id);
    switch (head->type) {
        case PAGE_TYPE_HEAP_HEAD:
            heap_segment = (heap_segment_t *)(session->curr_page + sizeof(page_head_t));
            *extents = heap_segment->extents.count + heap_segment->free_extents.count;
            *pages = heap_get_all_page_count(space, heap_segment);
            break;

        case PAGE_TYPE_BTREE_HEAD:
            btree_segment = (btree_segment_t *)(session->curr_page + sizeof(btree_page_t));
            *extents = btree_segment->extents.count;
            *pages = btree_get_segment_page_count(space, btree_segment);
            break;

        case PAGE_TYPE_LOB_HEAD:
            lob_segment = (lob_segment_t *)(session->curr_page + sizeof(page_head_t));
            *extents = lob_segment->extents.count;
            *pages = spc_pages_by_ext_cnt(space, *extents, head->type);
            break;

        default:
            buf_leave_page(session, CT_FALSE);
            CT_THROW_ERROR(ERR_INVALID_SEGMENT_ENTRY);
            return CT_ERROR;
    }

    buf_leave_page(session, CT_FALSE);
    *page_size = DEFAULT_PAGE_SIZE(session);
    return CT_SUCCESS;
}

/*
 * get first free extent from given page id.
 * this is the last extent in current datafile when is_last equals true.
 */
status_t knl_get_free_extent(knl_handle_t se, uint32 file_id, page_id_t start, uint32 *extent, uint64 *page_count,
                             bool32 *is_last)
{
    knl_session_t *session = (knl_session_t *)se;
    datafile_t *df = DATAFILE_GET(session, file_id);

    space_t *space = KNL_GET_SPACE(session, df->space_id);
    if (spc_is_remote_swap_space(session, space)) {
        // skip the remote swap space, as it is invisible
        extent = 0;
        page_count = 0;
        *is_last = CT_TRUE;
        return CT_SUCCESS;
    }

    return df_get_free_extent(session, df, start, extent, page_count, is_last);
}

void knl_calc_seg_size(seg_size_type_t type, uint32 pages, uint32 page_size, uint32 extents, int64 *result)
{
    switch (type) {
        case SEG_BYTES:
            *result = (int64)pages * (int64)page_size;
            break;
        case SEG_PAGES:
            *result = (int64)pages;
            break;
        default:
            *result = (int64)extents;
            break;
    }
}

status_t knl_get_partitioned_lobsize(knl_handle_t session, knl_dictionary_t *dc, seg_size_type_t type, int32 col_id,
                                     int64 *result)
{
    lob_t *lob = NULL;
    knl_column_t *column = NULL;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;

    if (col_id >= (int32)table->desc.column_count) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "column id");
        return CT_ERROR;
    }

    if (table->part_table == NULL) {
        // not partition, return error
        CT_THROW_ERROR(ERR_INVALID_PART_TYPE, "table", ",can not calc table-size.");
        return CT_ERROR;
    }

    *result = 0;
    for (uint32 i = 0; i < table->desc.column_count; i++) {
        column = dc_get_column(entity, i);
        CT_CONTINUE_IFTRUE(!COLUMN_IS_LOB(column));

        lob = (lob_t *)column->lob;
        CT_CONTINUE_IFTRUE((col_id != -1) && (col_id != lob->desc.column_id));

        if (part_get_lob_segment_size((knl_session_t *)session, dc, lob, type, result) != CT_SUCCESS) {
            return CT_ERROR;
        }

        CT_BREAK_IF_TRUE(col_id != -1);
    }
    return CT_SUCCESS;
}

status_t knl_get_partitioned_tabsize(knl_handle_t session, knl_dictionary_t *dc, seg_size_type_t type, int64 *result)
{
    table_t *table = DC_TABLE(dc);
    part_table_t *part_table = table->part_table;
    knl_session_t *se = (knl_session_t *)session;

    if (table->part_table == NULL) {
        // not partition, return error
        CT_THROW_ERROR(ERR_INVALID_PART_TYPE, "table", ",can not calc table-size.");
        return CT_ERROR;
    }

    *result = 0;
    int64 part_size = 0;
    table_part_t *table_part = NULL;
    for (uint32 i = 0; i < part_table->desc.partcnt; ++i) {
        table_part = PART_GET_ENTITY(part_table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        part_size = 0;
        if (part_get_heap_segment_size(se, dc, table_part, type, &part_size) != CT_SUCCESS) {
            return CT_ERROR;
        }

        *result += part_size;
    }

    return CT_SUCCESS;
}

status_t knl_get_table_size(knl_handle_t session, knl_dictionary_t *dc, seg_size_type_t type, int64 *result)
{
    table_t *table = DC_TABLE(dc);
    page_id_t entry;
    uint32 pages, page_size, extents;
    if (table->part_table != NULL) {
        return knl_get_partitioned_tabsize(session, dc, type, result);
    }

    *result = 0;
    if (table->heap.segment == NULL) {
        return CT_SUCCESS;
    }
    entry = HEAP_SEGMENT(session, table->heap.entry, table->heap.segment)->extents.first;
    if (knl_get_segment_size(session, entry, &extents, &pages, &page_size) != CT_SUCCESS) {
        return CT_ERROR;
    }
    (void)knl_calc_seg_size(type, pages, page_size, extents, result);
    return CT_SUCCESS;
}

status_t knl_get_table_partsize(knl_handle_t session, knl_dictionary_t *dc, seg_size_type_t type, text_t *part_name,
                                int64 *result)
{
    table_t *table = DC_TABLE(dc);
    part_table_t *part_table = table->part_table;
    knl_session_t *se = (knl_session_t *)session;
    table_part_t *compart = NULL;
    *result = 0;

    if (table->part_table == NULL) {
        CT_THROW_ERROR(ERR_INVALID_PART_TYPE, "table", ",can not calc table-part size.");
        return CT_ERROR;
    }

    if (!part_table_find_by_name(part_table, part_name, &compart)) {
        CT_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(part_name));
        return CT_ERROR;
    }

    return part_get_heap_segment_size(se, dc, compart, type, result);
}

status_t knl_get_partitioned_indsize(knl_handle_t session, knl_dictionary_t *dc, seg_size_type_t type,
                                     text_t *index_name, int64 *result)
{
    index_t *index = NULL;
    uint32 start_slot, end_slot;
    table_t *table = DC_TABLE(dc);
    knl_session_t *se = (knl_session_t *)session;

    if (table->part_table == NULL) {
        // not partition, return error
        CT_THROW_ERROR(ERR_INVALID_PART_TYPE, "table", ",can not calc index-size.");
        return CT_ERROR;
    }

    if (index_name == NULL) {
        start_slot = 0;
        end_slot = table->index_set.count;
    } else {
        index = dc_find_index_by_name(DC_ENTITY(dc), index_name);
        if (index == NULL) {
            text_t user_name;

            if (knl_get_user_name(session, dc->uid, &user_name) != CT_SUCCESS) {
                return CT_ERROR;
            }

            CT_THROW_ERROR(ERR_INDEX_NOT_EXIST, T2S(&user_name), T2S_EX(index_name));
            return CT_ERROR;
        }

        start_slot = index->desc.slot;
        end_slot = start_slot + 1;
    }

    *result = 0;
    index_part_t *index_part = NULL;
    table_part_t *table_part = NULL;
    for (uint32 i = start_slot; i < end_slot; i++) {
        index = table->index_set.items[i];
        if (!IS_PART_INDEX(index)) {
            continue;
        }

        for (uint32 j = 0; j < index->part_index->desc.partcnt; j++) {
            int64 part_size = 0;
            index_part = INDEX_GET_PART(index, j);
            table_part = TABLE_GET_PART(table, j);
            if (!IS_READY_PART(table_part) || index_part == NULL) {
                continue;
            }

            if (part_get_btree_seg_size(se, index, index_part, type, &part_size) != CT_SUCCESS) {
                return CT_ERROR;
            }

            *result += part_size;
        }

        CT_BREAK_IF_TRUE(index_name != NULL);
    }

    return CT_SUCCESS;
}

status_t knl_get_idx_size(knl_handle_t se, knl_dictionary_t *dc, index_t *index, seg_size_type_t type, int64 *result_size)
{
    int64 indsize = 0;
    table_t *table = DC_TABLE(dc);
    knl_session_t *session = (knl_session_t *)se;
    uint32 pages, page_size, extents;
    int64 part_size;
    if (IS_PART_INDEX(index)) {
        for (uint32 j = 0; j < index->part_index->desc.partcnt; j++) {
            index_part_t *index_part = INDEX_GET_PART(index, j);
            table_part_t *table_part = TABLE_GET_PART(table, j);
            if (!IS_READY_PART(table_part) || index_part == NULL) {
                continue;
            }

            if (part_get_btree_seg_size(se, index, index_part, type, &part_size) != CT_SUCCESS) {
                return CT_ERROR;
            }
            indsize += part_size;
        }
    } else {
        if (index->btree.segment == NULL) {
            *result_size = 0;
            return CT_SUCCESS;
        }
        page_id_t entry = BTREE_SEGMENT(session, index->btree.entry, index->btree.segment)->extents.first;
        if (knl_get_segment_size(session, entry, &extents, &pages, &page_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
        knl_calc_seg_size(type, pages, page_size, extents, &indsize);
    }
    *result_size = indsize;
    return CT_SUCCESS;
}

status_t knl_get_table_idx_size(knl_handle_t se, knl_dictionary_t *dc, seg_size_type_t type,
                               text_t *idx_name, int64 *result_size)
{
    index_t *index = NULL;
    table_t *table = DC_TABLE(dc);
    int64 part_size;
    int64 ind_size = 0;

    if (idx_name == NULL) {
        for (uint32 i = 0; i < table->index_set.total_count; i++) {
            index = table->index_set.items[i];
            if (knl_get_idx_size(se, dc, index, type, &part_size) != CT_SUCCESS) {
                return CT_ERROR;
            }
            ind_size += part_size;
        }
    } else {
        index = dc_find_index_by_name(DC_ENTITY(dc), idx_name);
        if (index == NULL) {
            dc_entry_t *entry = DC_ENTITY(dc)->entry;
            CT_THROW_ERROR(ERR_INDEX_NOT_EXIST, entry->user->desc.name, T2S(idx_name));
            return CT_ERROR;
        }
        if (knl_get_idx_size(se, dc, index, type, &ind_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    *result_size = ind_size;
    return CT_SUCCESS;
}

status_t knl_create_synonym(knl_handle_t session, knl_handle_t stmt, knl_synonym_def_t *def)
{
    knl_dictionary_t dc;
    bool32 is_found = CT_FALSE;
    knl_session_t *knl_session = (knl_session_t *)session;
    dc_user_t *user = NULL;
    errno_t ret;

    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_open_user(knl_session, &def->owner, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dls_latch_x(session, &user->user_latch, knl_session->id, NULL);

    if (DB_NOT_READY(knl_session)) {
        CT_THROW_ERROR(ERR_NO_DB_ACTIVE);
        dls_unlatch(session, &user->user_latch, NULL);
        return CT_ERROR;
    }

    /* direct to open dc, no need to open "public" use again */
    ret = memset_sp(&dc, sizeof(knl_dictionary_t), 0, sizeof(knl_dictionary_t));
    knl_securec_check(ret);
    if (knl_open_dc_if_exists(knl_session, &def->owner, &def->name, &dc, &is_found) != CT_SUCCESS) {
        dls_unlatch(session, &user->user_latch, NULL);
        return CT_ERROR;
    }

    if (SYNONYM_OBJECT_EXIST(&dc)) {
        /* first close the link table */
        dc_close(&dc);
    }

    if (SYNONYM_EXIST(&dc)) {
        if (SYNONYM_IS_REPLACE & def->flags) {
            /* second close the synonym entry, synonym entry do not have the entity */
            if (db_drop_synonym(knl_session, NULL, &dc) != CT_SUCCESS) {
                dls_unlatch(session, &user->user_latch, NULL);
                return CT_ERROR;
            }
        } else {
            CT_THROW_ERROR(ERR_OBJECT_EXISTS, T2S(&def->owner), T2S_EX(&def->name));
            dls_unlatch(session, &user->user_latch, NULL);
            return CT_ERROR;
        }
    }

    if (db_create_synonym(knl_session, stmt, def) != CT_SUCCESS) {
        dls_unlatch(session, &user->user_latch, NULL);
        return CT_ERROR;
    }

    dls_unlatch(session, &user->user_latch, NULL);
    return CT_SUCCESS;
}

status_t knl_drop_synonym_internal(knl_handle_t session, knl_handle_t stmt, knl_drop_def_t *def)
{
    bool32 is_found = CT_FALSE;
    knl_dictionary_t dc;
    knl_session_t *knl_session = (knl_session_t *)session;
    errno_t ret;

    CM_POINTER2(session, def);

    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ret = memset_sp(&dc, sizeof(knl_dictionary_t), 0, sizeof(knl_dictionary_t));
    knl_securec_check(ret);

    if (knl_open_dc_if_exists(session, &def->owner, &def->name, &dc, &is_found) != CT_SUCCESS) {
        if (!dc.is_sysnonym) {
            return CT_ERROR;
        }
    }

    if (SYNONYM_OBJECT_EXIST(&dc)) {
        dc_close(&dc);
    }

    if (SYNONYM_NOT_EXIST(&dc)) {
        if (def->options & DROP_IF_EXISTS) {
            return CT_SUCCESS;
        }
        CT_THROW_ERROR(ERR_SYNONYM_NOT_EXIST, T2S(&def->owner), T2S_EX(&def->name));
        return CT_ERROR;
    }

    return db_drop_synonym(knl_session, stmt, &dc);
}

status_t knl_drop_synonym(knl_handle_t session, knl_handle_t stmt, knl_drop_def_t *def)
{
    knl_session_t *knl_session = (knl_session_t *)session;
    dc_user_t *user = NULL;
    status_t status;

    CM_POINTER2(session, def);

    if (dc_open_user(knl_session, &def->owner, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dls_latch_x(knl_session, &user->user_latch, knl_session->id, NULL);
    status = knl_drop_synonym_internal(session, stmt, def);
    dls_unlatch(session, &user->user_latch, NULL);

    return status;
}

status_t knl_delete_dependency(knl_handle_t session, uint32 uid, int64 oid, uint32 tid)
{
    knl_session_t *knl_session = (knl_session_t *)session;

    return db_delete_dependency(knl_session, uid, oid, tid);
}

status_t knl_update_trig_table_flag(knl_handle_t session, knl_table_desc_t *desc, bool32 has_trig)
{
    knl_session_t *knl_session = (knl_session_t *)session;
    return db_update_table_trig_flag(knl_session, desc, has_trig);
}

status_t knl_insert_dependency(knl_handle_t *session, object_address_t *depender, object_address_t *ref_obj,
                               uint32 order)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(knl_session);
    if (CT_SUCCESS != db_write_sysdep(knl_session, cursor, depender, ref_obj, order)) {
        CM_RESTORE_STACK(knl_session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(knl_session->stack);
    return CT_SUCCESS;
}

void knl_get_link_name(knl_dictionary_t *dc, text_t *user, text_t *objname)
{
    dc_entry_t *entry = NULL;
    synonym_link_t *synonym_link = NULL;

    user->str = NULL;
    user->len = 0;
    objname->str = NULL;
    objname->len = 0;

    if (dc->is_sysnonym && dc->syn_handle) {
        entry = (dc_entry_t *)dc->syn_handle;
        if (entry->appendix && entry->appendix->synonym_link) {
            synonym_link = entry->appendix->synonym_link;
            cm_str2text(synonym_link->user, user);
            cm_str2text(synonym_link->name, objname);
        }
    }
}

status_t knl_get_space_size(knl_handle_t se, uint32 space_id, int32 *page_size, knl_handle_t info)
{
    knl_session_t *session = (knl_session_t *)se;
    knl_space_info_t *spc_info = (knl_space_info_t *)info;
    datafile_t *df = NULL;
    int64 normal_pages, normal_size, compress_pages, compress_size;
    uint32 id;

    normal_pages = 0;
    normal_size = 0;
    compress_pages = 0;
    compress_size = 0;

    if (space_id >= CT_MAX_SPACES) {
        CT_THROW_ERROR(ERR_TOO_MANY_OBJECTS, CT_MAX_SPACES, "tablespace");
        return CT_ERROR;
    }

    space_t *space = SPACE_GET(session, space_id);
    if (!space->ctrl->used) {
        CT_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "tablespace", space_id);
        return CT_ERROR;
    }

    if (!SPACE_IS_ONLINE(space) || space->head == NULL ||
        (IS_SWAP_SPACE(space) && space->ctrl->id != dtc_my_ctrl(session)->swap_space)) {
        *page_size = DEFAULT_PAGE_SIZE(session);
        spc_info->total = 0;
        spc_info->used = 0;
        spc_info->normal_total = 0;
        spc_info->normal_used = 0;
        spc_info->compress_total = 0;
        spc_info->compress_used = 0;
        return CT_SUCCESS;
    }

    if (!spc_view_try_lock_space(session, space, "get space size failed")) {
        return CT_ERROR;
    }

    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        id = space->ctrl->files[i];
        if (CT_INVALID_ID32 == id) {
            continue;
        }
        df = DATAFILE_GET(session, space->ctrl->files[i]);
        if (!DATAFILE_IS_COMPRESS(df)) {
            normal_pages += spc_get_df_used_pages(session, space, i);
            normal_size += DATAFILE_GET(session, id)->ctrl->size;
        } else {
            compress_pages += spc_get_df_used_pages(session, space, i);
            compress_size += DATAFILE_GET(session, id)->ctrl->size;
        }
    }

    if (!SPACE_IS_BITMAPMANAGED(space)) {
        normal_pages -= SPACE_HEAD_RESIDENT(session, space)->free_extents.count * space->ctrl->extent_size;
        normal_pages -= spc_get_punch_extents(session, space) * space->ctrl->extent_size;
    }

    spc_unlock_space(session, space);

    *page_size = DEFAULT_PAGE_SIZE(session);
    spc_info->normal_total = normal_size;
    spc_info->normal_used = normal_pages * DEFAULT_PAGE_SIZE(session);
    spc_info->compress_total = compress_size;
    spc_info->compress_used = compress_pages * DEFAULT_PAGE_SIZE(session);
    spc_info->used = spc_info->normal_used + spc_info->compress_used;
    spc_info->total = spc_info->normal_total + spc_info->compress_total;
    return CT_SUCCESS;
}

status_t knl_get_space_name(knl_handle_t session, uint32 space_id, text_t *space_name)
{
    return spc_get_space_name((knl_session_t *)session, space_id, space_name);
}

status_t knl_comment_on(knl_handle_t session, knl_handle_t stmt, knl_comment_def_t *def)
{
    knl_session_t *knl_session = (knl_session_t *)session;
    CM_POINTER2(session, def);

    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (CT_SUCCESS != db_comment_on(knl_session, def)) {
        return CT_ERROR;
    }

    log_add_lrep_ddl_info(session, stmt, LOGIC_OP_COMMENT, RD_CREATE_TABLE, NULL);
    knl_commit(session);
    return CT_SUCCESS;
}

/*
 * privilege kernel API
 */
bool32 knl_check_sys_priv_by_name(knl_handle_t session, text_t *user, uint32 priv_id)
{
    return dc_check_sys_priv_by_name((knl_session_t *)session, user, priv_id);
}

bool32 knl_check_sys_priv_by_uid(knl_handle_t session, uint32 uid, uint32 priv_id)
{
    return dc_check_sys_priv_by_uid((knl_session_t *)session, uid, priv_id);
}

bool32 knl_check_dir_priv_by_uid(knl_handle_t session, uint32 uid, uint32 priv_id)
{
    return dc_check_dir_priv_by_uid((knl_session_t *)session, uid, priv_id);
}

bool32 knl_check_obj_priv_by_name(knl_handle_t session, text_t *curr_user, text_t *obj_user, text_t *obj_name,
                                  object_type_t objtype, uint32 priv_id)
{
    return dc_check_obj_priv_by_name((knl_session_t *)session, curr_user, obj_user, obj_name, objtype, priv_id);
}

bool32 knl_check_user_priv_by_name(knl_handle_t session, text_t *curr_user, text_t *obj_user, uint32 priv_id)
{
    return dc_check_user_priv_by_name((knl_session_t *)session, curr_user, obj_user, priv_id);
}

bool32 knl_check_obj_priv_with_option(knl_handle_t session, text_t *curr_user, text_t *obj_user, text_t *obj_name,
                                      object_type_t objtype, uint32 priv_id)
{
    return dc_check_obj_priv_with_option((knl_session_t *)session, curr_user, obj_user, obj_name, objtype, priv_id);
}

bool32 knl_check_allobjprivs_with_option(knl_handle_t session, text_t *curr_user, text_t *obj_user, text_t *obj_name,
                                         object_type_t objtype)
{
    return dc_check_allobjprivs_with_option((knl_session_t *)session, curr_user, obj_user, obj_name, objtype);
}

bool32 knl_sys_priv_with_option(knl_handle_t session, text_t *user, uint32 priv_id)
{
    return dc_sys_priv_with_option((knl_session_t *)session, user, priv_id);
}

bool32 knl_grant_role_with_option(knl_handle_t session, text_t *user, text_t *role, bool32 with_option)
{
    return dc_grant_role_with_option((knl_session_t *)session, user, role, with_option);
}

status_t knl_create_profile(knl_handle_t session, knl_profile_def_t *def)
{
    status_t status = CT_SUCCESS;
    knl_session_t *ptr_session = (knl_session_t *)session;
    profile_t *profile = NULL;
    bucket_t *bucket = NULL;

    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    bucket = profile_get_bucket(ptr_session, &def->name);
    cm_latch_x(&bucket->latch, ptr_session->id, NULL);
    bool32 is_exists = profile_find_by_name(ptr_session, &def->name, bucket, &profile);
    if (is_exists == CT_TRUE) {
        if (def->is_replace) {
            status = profile_drop(ptr_session, (knl_drop_def_t *)def, profile);
        } else {
            CT_THROW_ERROR(ERR_OBJECT_EXISTS, "profile", T2S(&def->name));
            status = CT_ERROR;
        }
    }

    if (status != CT_SUCCESS) {
        cm_unlatch(&bucket->latch, NULL);
        return status;
    }

    if (profile_alloc_and_insert_bucket(ptr_session, def, bucket, &profile) != CT_SUCCESS) {
        cm_unlatch(&bucket->latch, NULL);
        return CT_ERROR;
    }

    status = profile_create(ptr_session, profile);
    cm_unlatch(&bucket->latch, NULL);

    return status;
}

status_t knl_drop_profile(knl_handle_t session, knl_drop_def_t *def)
{
    status_t status = CT_SUCCESS;
    knl_session_t *ptr_session = (knl_session_t *)session;
    profile_t *profile = NULL;
    bucket_t *bucket = NULL;

    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    bucket = profile_get_bucket(ptr_session, &def->name);
    cm_latch_x(&bucket->latch, ptr_session->id, NULL);
    bool32 is_exists = profile_find_by_name(ptr_session, &def->name, bucket, &profile);
    if (is_exists == CT_FALSE) {
        cm_unlatch(&bucket->latch, NULL);
        CT_THROW_ERROR(ERR_PROFILE_NOT_EXIST, T2S(&def->name));
        return CT_ERROR;
    }

    status = profile_drop(ptr_session, def, profile);
    cm_unlatch(&bucket->latch, NULL);

    return status;
}

status_t knl_alter_profile(knl_handle_t session, knl_profile_def_t *def)
{
    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return profile_alter((knl_session_t *)session, def);
}

status_t knl_create_directory(knl_handle_t session, knl_directory_def_t *def)
{
    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return db_create_directory((knl_session_t *)session, def);
}

status_t knl_rebuild_ctrlfile(knl_handle_t session, knl_rebuild_ctrlfile_def_t *def)
{
    return ctrl_rebuild_ctrl_files((knl_session_t *)session, def);
}

status_t knl_drop_directory(knl_handle_t session, knl_drop_def_t *def)
{
    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return db_drop_directory((knl_session_t *)session, def);
}

status_t knl_check_user_lock(knl_handle_t session, text_t *user)
{
    if (!KNL_IS_DB_OPEN_NORMAL(session)) {
        return CT_SUCCESS;
    }

    return dc_check_user_lock((knl_session_t *)session, user);
}

status_t knl_check_user_lock_timed(knl_handle_t session, text_t *user, bool32 *p_lock_unlock)
{
    if (!KNL_IS_DB_OPEN_NORMAL(session)) {
        return CT_SUCCESS;
    }

    return dc_check_user_lock_timed((knl_session_t *)session, user, p_lock_unlock);
}

status_t knl_check_user_expire(knl_handle_t session, text_t *user, char *message, uint32 message_len)
{
    if (!KNL_IS_DB_OPEN_NORMAL(session)) {
        return CT_SUCCESS;
    }

    return dc_check_user_expire((knl_session_t *)session, user, message, message_len);
}

status_t knl_process_failed_login(knl_handle_t session, text_t *user, uint32 *p_lock_unlock)
{
    if (!KNL_IS_DB_OPEN_NORMAL(session)) {
        return CT_SUCCESS;
    }

    return dc_process_failed_login((knl_session_t *)session, user, p_lock_unlock);
}

/* the following 3 functions were intended to replaced knl_get_page_size() */
status_t knl_update_serial_value(knl_handle_t session, knl_handle_t dc_entity, int64 value, bool32 is_uint64)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    dc_entry_t *entry = entity->entry;
    knl_session_t *se = (knl_session_t *)session;

    if (entity->type == DICT_TYPE_TEMP_TABLE_SESSION || entity->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        knl_temp_cache_t *temp_table = NULL;

        if (knl_ensure_temp_cache(session, entity, &temp_table) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (temp_table->serial == 0) {
            temp_table->serial = entity->table.desc.serial_start;
            if (temp_table->serial == 0) {
                temp_table->serial++;
            }
        }

        if ((!is_uint64 && value < 0) || (uint64)value < temp_table->serial) {
            return CT_SUCCESS;
        }
 
        if (is_uint64) {
            temp_table->serial = (value == CT_INVALID_ID64) ? value : (value + 1);
        } else {
            temp_table->serial = (value == CT_INVALID_INT64) ? value : (value + 1);
        }

        return CT_SUCCESS;
    }

    if (entity->table.heap.segment == NULL) {
        if (heap_create_entry(se, &entity->table.heap) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    dls_spin_lock(session, &entry->serial_lock, NULL);

    // int64 segment_serial = HEAP_SEGMENT(session, entity->table.heap.entry, entity->table.heap.segment)->serial;

    if (entry->serial_value == 0) {
        entry->serial_value = HEAP_SEGMENT(session, entity->table.heap.entry, entity->table.heap.segment)->serial;

        if (entry->serial_value == 0) {
            entry->serial_value = 1;
        }
    }

    if ((!is_uint64 && value < 0) || (uint64)value < entry->serial_value) {
        dls_spin_unlock(session, &entry->serial_lock);
        return CT_SUCCESS;
    }
 
    if (is_uint64) {
        if ((uint64)value >= CT_INVALID_ID64 - CT_SERIAL_CACHE_COUNT) {
            if (CT_INVALID_ID64 != HEAP_SEGMENT(session, entity->table.heap.entry,
                                                entity->table.heap.segment)->serial) {
                heap_update_serial(se, &entity->table.heap, CT_INVALID_ID64);
            }
        } else if ((uint64)value >= HEAP_SEGMENT(session, entity->table.heap.entry,
            entity->table.heap.segment)->serial) {
            heap_update_serial(se, &entity->table.heap,
                               DC_CACHED_SERIAL_VALUE(value, entity->table.desc.serial_start));
        }
    } else {
        if (value >= CT_INVALID_INT64 - CT_SERIAL_CACHE_COUNT) {
            if (CT_INVALID_INT64 != HEAP_SEGMENT(session, entity->table.heap.entry,
                entity->table.heap.segment)->serial) {
                heap_update_serial(se, &entity->table.heap, CT_INVALID_INT64);
            }
        } else if (value >= HEAP_SEGMENT(session, entity->table.heap.entry,
            entity->table.heap.segment)->serial) {
            heap_update_serial(se, &entity->table.heap,
                               DC_CACHED_SERIAL_VALUE(value, entity->table.desc.serial_start));
        }
    }

    if (is_uint64) {
        entry->serial_value = (value == CT_INVALID_ID64) ? value : (value + 1);
    } else {
        entry->serial_value = (value == CT_INVALID_INT64) ? value : (value + 1);
    }

    dls_spin_unlock(session, &entry->serial_lock);

    return CT_SUCCESS;
}

status_t knl_update_serial_value_tmp_table(knl_handle_t session, dc_entity_t *entity, int64 value, bool32 is_uint64)
{
    knl_temp_cache_t *temp_table = NULL;

    if (knl_ensure_temp_cache(session, entity, &temp_table) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (temp_table->serial == 0) {
        temp_table->serial = entity->table.desc.serial_start;
        if (temp_table->serial == 0) {
            temp_table->serial++;
        }
    }

    if ((!is_uint64 && value < 0) || (uint64)value < temp_table->serial) {
        return CT_SUCCESS;
    }

    if (is_uint64) {
        temp_table->serial = (value == CT_INVALID_ID64) ? value : (value + 1);
    } else {
        temp_table->serial = (value == CT_INVALID_INT64) ? value : (value + 1);
    }

    return CT_SUCCESS;
}

void knl_update_heap_4mysql(knl_handle_t session, dc_entity_t *entity, int64 *value, bool32 is_uint64)
{
    knl_session_t *se = (knl_session_t *)session;
    uint64 residue = (*value == 0) ? 0 : 1;
    if (is_uint64) {
        if ((uint64)*value >= CT_INVALID_ID64 - CT_SERIAL_CACHE_COUNT) {
            if (CT_INVALID_ID64 != HEAP_SEGMENT(session, entity->table.heap.entry,
                                                entity->table.heap.segment)->serial) {
                heap_update_serial(se, &entity->table.heap, CT_INVALID_ID64);
            }
        } else if ((uint64)*value >= HEAP_SEGMENT(session, entity->table.heap.entry,
                                                  entity->table.heap.segment)->serial) {
            heap_update_serial(se, &entity->table.heap,
                               DC_CACHED_SERIAL_VALUE(*value, residue));
        }
    } else {
        if (*value >= CT_INVALID_INT64 - CT_SERIAL_CACHE_COUNT) {
            if (CT_INVALID_INT64 != HEAP_SEGMENT(session, entity->table.heap.entry,
                                                 entity->table.heap.segment)->serial) {
                heap_update_serial(se, &entity->table.heap, CT_INVALID_INT64);
            }
        } else if (*value >= HEAP_SEGMENT(session, entity->table.heap.entry,
                                          entity->table.heap.segment)->serial) {
            heap_update_serial(se, &entity->table.heap,
                               DC_CACHED_SERIAL_VALUE(*value, residue));
        }
    }
}

/* the following 3 functions were intended to replaced knl_get_page_size() */
status_t knl_update_serial_value_4mysql(knl_handle_t session, knl_handle_t dc_entity, int64 value, bool32 is_uint64)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    dc_entry_t *entry = entity->entry;
    knl_session_t *se = (knl_session_t *)session;

    if (entity->type == DICT_TYPE_TEMP_TABLE_SESSION || entity->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        return knl_update_serial_value_tmp_table(session, entity, value, is_uint64);
    }
    if (entity->table.heap.segment == NULL) {
        if (heap_create_entry(se, &entity->table.heap) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    dls_spin_lock(session, &entry->serial_lock, NULL);
    uint64 seg_val = HEAP_SEGMENT(session, entity->table.heap.entry, entity->table.heap.segment)->serial;
    uint64 serial_value = entry->serial_value;
    if (serial_value == 0) {
        serial_value = seg_val;
        if (serial_value == 0) {
            serial_value = 1;
        }
    }

    if ((!is_uint64 && value < 0) || (uint64)value < serial_value) {
        dls_spin_unlock(session, &entry->serial_lock);
        return CT_SUCCESS;
    }

    if ((value >= DC_CACHED_SERIAL_VALUE(entry->serial_value, 0)) && (value < seg_val)) {
        entry->serial_value = seg_val - 1;
        dls_spin_unlock(session, &entry->serial_lock);
        return CT_SUCCESS;
    }
    knl_update_heap_4mysql(session, entity, &value, is_uint64);
    entry->serial_value = value;
    dls_spin_unlock(session, &entry->serial_lock);

    return CT_SUCCESS;
}

uint32 knl_get_update_info_size(knl_handle_t handle)
{
    uint32 ui_size;
    knl_attr_t *attr = (knl_attr_t *)handle;

    uint32 column_size = attr->max_column_count * sizeof(uint16);
    uint32 offsets_size = attr->max_column_count * sizeof(uint16);
    uint32 lens_size = attr->max_column_count * sizeof(uint16);
    uint32 data_size = attr->page_size;

    ui_size = column_size + offsets_size + lens_size + data_size;

    return ui_size;
}

void knl_bind_update_info(knl_handle_t handle, char *buf)
{
    knl_session_t *session = (knl_session_t *)handle;

    uint32 buf_size = session->kernel->attr.max_column_count;

    session->update_info.columns = (uint16 *)buf;
    session->update_info.offsets = session->update_info.columns + buf_size;
    session->update_info.lens = session->update_info.offsets + buf_size;
    session->update_info.data = (char *)(session->update_info.lens + buf_size);
}

status_t knl_get_page_size(knl_handle_t session, uint32 *page_size)
{
    *page_size = (((knl_session_t *)session)->kernel->attr.page_size);
    return CT_SUCCESS;
}

knl_column_t *knl_find_column(text_t *col_name, knl_dictionary_t *dc)
{
    uint16 col_id;
    knl_column_t *column = NULL;

    col_id = knl_get_column_id(dc, col_name);
    if (col_id == CT_INVALID_ID16) {
        return NULL;
    }

    column = knl_get_column(dc->handle, col_id);
    if (KNL_COLUMN_IS_DELETED(column)) {
        return NULL;
    }

    return column;
}

void knl_get_sync_info(knl_handle_t session, knl_handle_t sync_info)
{
    knl_session_t *se = (knl_session_t *)session;
    ha_sync_info_t *ha_sync_info = (ha_sync_info_t *)sync_info;

    lsnd_get_sync_info(se, ha_sync_info);
}

uint32 knl_get_dbwrite_file_id(knl_handle_t session)
{
    knl_instance_t *kernel = (knl_instance_t *)((knl_session_t *)session)->kernel;

    database_t *db = &kernel->db;

    return db->ctrl.core.dw_file_id;
}

uint32 knl_get_dbwrite_end(knl_handle_t session)
{
    knl_instance_t *kernel = (knl_instance_t *)((knl_session_t *)session)->kernel;

    database_t *db = &kernel->db;

    return dtc_get_ctrl(session, 0)->dw_start + db->ctrl.core.dw_area_pages;
}

bool32 knl_batch_insert_enabled(knl_handle_t session, knl_dictionary_t *dc, uint8 trig_disable)
{
    dc_entity_t *entity = (dc_entity_t *)dc->handle;
    knl_session_t *se = (knl_session_t *)session;

    if (!trig_disable && entity->trig_set.trig_count > 0) {
        return CT_FALSE;
    }

    if (LOGIC_REP_TABLE_ENABLED((knl_session_t *)session, entity)) {
        return CT_FALSE;
    }

    if (entity->table.desc.cr_mode == CR_PAGE) {
        return CT_TRUE;
    }

    if (!se->kernel->attr.temptable_support_batch) {
        return CT_FALSE;
    }

    return (dc->type == DICT_TYPE_TEMP_TABLE_SESSION ||
        dc->type == DICT_TYPE_TEMP_TABLE_TRANS);
}

static bool32 knl_check_idxes_columns_duplicate(knl_index_def_t *idx1, knl_index_def_t *idx2)
{
    if (idx1->columns.count != idx2->columns.count) {
        return CT_FALSE;
    }

    knl_index_col_def_t *index_col1 = NULL;
    knl_index_col_def_t *index_col2 = NULL;
    for (uint32 i = 0; i < idx1->columns.count; i++) {
        index_col1 = (knl_index_col_def_t *)cm_galist_get(&idx1->columns, i);
        index_col2 = (knl_index_col_def_t *)cm_galist_get(&idx2->columns, i);
        if (!cm_text_equal(&index_col1->name, &index_col2->name)) {
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

static status_t knl_create_indexes_check_def(knl_session_t *session, knl_indexes_def_t *def)
{
    if (def->index_count > CT_MAX_INDEX_COUNT_PERSQL) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "create more than eight indexes in one SQL statement");
        return CT_ERROR;
    }

    text_t *table_name = &def->indexes_def[0].table;
    text_t *user_name = &def->indexes_def[0].user;
    uint32 parallelism = def->indexes_def[0].parallelism;
    bool32 nologging = def->indexes_def[0].nologging;
    if (!DB_IS_SINGLE(session) && nologging) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "creating an index with nologging in HA mode");
        return CT_ERROR;
    }

    for (uint32 i = def->index_count - 1; i > 0; i--) {
        if (!cm_text_equal_ins(table_name, &def->indexes_def[i].table) ||
            !cm_text_equal_ins(user_name, &def->indexes_def[i].user)) {
            CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "create indexcluster for different tables in one SQL statement");
            return CT_ERROR;
        }

        if (parallelism != def->indexes_def[i].parallelism) {
            CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "create indexes with different parallelism in one SQL statement");
            return CT_ERROR;
        }

        if (nologging != def->indexes_def[i].nologging) {
            CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "create indexes with different logging mode in one SQL statement");
            return CT_ERROR;
        }
    }

    bool32 is_parted = def->indexes_def[0].parted;
    for (uint32 i = 0; i < def->index_count; i++) {
        if (def->indexes_def[i].parted != is_parted) {
            CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "create different type indexes in create indexcluster statement");
            return CT_ERROR;
        }

        if (def->indexes_def[i].is_func) {
            CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "create function indexes in create indexcluster SQL statement");
            return CT_ERROR;
        }

        if (def->indexes_def[i].parallelism == 0) {
            CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "create indexes without specify parallelism value");
            return CT_ERROR;
        }

        for (uint32 j = 0; j < def->index_count; j++) {
            if (i == j) {
                continue;
            }

            if (cm_text_equal_ins(&def->indexes_def[i].name, &def->indexes_def[j].name) &&
                cm_text_equal_ins(&def->indexes_def[i].user, &def->indexes_def[j].user)) {
                CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "create duplicate indexes for the same table");
                return CT_ERROR;
            }

            if (knl_check_idxes_columns_duplicate(&def->indexes_def[i], &def->indexes_def[j])) {
                CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "create different indexes with the same index columns");
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

static status_t knl_create_indexes_check_dc(knl_session_t *session, knl_indexes_def_t *def, knl_dictionary_t *dc)
{
    text_t *table_name = &def->indexes_def[0].table;
    text_t *user_name = &def->indexes_def[0].user;

    if (SYNONYM_EXIST(dc)) {
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(user_name), T2S_EX(table_name));
        return CT_ERROR;
    }

    if (IS_SYS_DC(dc)) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create indexes", "system table");
        return CT_ERROR;
    }

    if (dc->type == DICT_TYPE_TABLE_EXTERNAL) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create indexes", "external organized table");
        return CT_ERROR;
    }

    if (dc->type == DICT_TYPE_TEMP_TABLE_SESSION || dc->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create indexes", "temporary table");
        return CT_ERROR;
    }

    if (dc->type != DICT_TYPE_TABLE && dc->type != DICT_TYPE_TEMP_TABLE_SESSION &&
        dc->type != DICT_TYPE_TEMP_TABLE_TRANS && dc->type != DICT_TYPE_TABLE_NOLOGGING) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create indexes", "view");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static void knl_create_indexes_release_lock(knl_session_t *session)
{
    drlatch_t *ddl_latch = &session->kernel->db.ddl_latch;
    unlock_tables_directly(session);
    dls_unlatch(session, ddl_latch, NULL);
}

static status_t knl_create_indexes_lock_resource(knl_session_t *session, knl_indexes_def_t *def, knl_dictionary_t *dc)
{
    if (knl_create_indexes_check_dc(session, def, dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    drlatch_t *ddl_latch = &session->kernel->db.ddl_latch;
    if (knl_ddl_latch_s(ddl_latch, session, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }

    uint32 timeout = session->kernel->attr.ddl_lock_timeout;
    if (lock_table_directly(session, dc, timeout) != CT_SUCCESS) {
        dls_unlatch(session, ddl_latch, NULL);
        return CT_ERROR;
    }

    if (lock_child_table_directly(session, dc->handle, CT_TRUE) != CT_SUCCESS) {
        knl_create_indexes_release_lock(session);
        return CT_ERROR;
    }

    for (uint32 i = 0; i < def->index_count; i++) {
        if (knl_judge_index_exist(session, &def->indexes_def[i], DC_ENTITY(dc))) {
            knl_create_indexes_release_lock(session);
            CT_THROW_ERROR(ERR_OBJECT_EXISTS, "index", T2S(&def->indexes_def[i].name));
            return CT_ERROR;
        }
    }

    table_t *table = DC_TABLE(dc);
    if (table->index_set.total_count + def->index_count > CT_MAX_TABLE_INDEXES) {
        knl_create_indexes_release_lock(session);
        CT_THROW_ERROR(ERR_TOO_MANY_INDEXES, T2S(&def->indexes_def[0].user), T2S_EX(&def->indexes_def[0].table));
        return CT_ERROR;
    }

    if (!IS_PART_TABLE(table)) {
        knl_create_indexes_release_lock(session);
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "create indexes on non-partitioned table");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t knl_create_indexes(knl_handle_t se, knl_handle_t stmt, knl_indexes_def_t *def)
{
    knl_session_t *session = (knl_session_t *)se;

    if (!KNL_IS_DB_OPEN_NORMAL(session)) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "create indexes in abnormally open mode");
        return CT_ERROR;
    }

    if (knl_create_indexes_check_def(session, def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_dictionary_t dc;
    text_t *table_name = &def->indexes_def[0].table;
    text_t *user_name = &def->indexes_def[0].user;
    if (dc_open(session, user_name, table_name, &dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_create_indexes_lock_resource(session, def, &dc) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }

    log_add_lrep_ddl_begin(session);
    if (db_create_indexes(session, def, &dc) != CT_SUCCESS) {
        log_add_lrep_ddl_end(session);
        knl_create_indexes_release_lock(session);
        dc_close(&dc);
        return CT_ERROR;
    }

    rd_table_t redo;
    redo.op_type = RD_CREATE_INDEXES;
    redo.uid = dc.uid;
    redo.oid = dc.oid;
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_table_t), LOG_ENTRY_FLAG_NONE);
    log_add_lrep_ddl_info(session, stmt, LOGIC_OP_INDEX, RD_CREATE_INDEXES, NULL);
    log_add_lrep_ddl_end(session);

    knl_commit(session);
    dc_invalidate_children(session, (dc_entity_t *)dc.handle);
    dc_invalidate(session, (dc_entity_t *)dc.handle);
    knl_create_indexes_release_lock(session);
    dc_close(&dc);

    return CT_SUCCESS;
}

status_t knl_get_space_type(knl_handle_t se, text_t *spc_name, device_type_t *type)
{
    knl_session_t *session = (knl_session_t *)se;

    if (DB_IS_READONLY(session)) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
        return CT_ERROR;
    }

    return spc_get_device_type(session, spc_name, type);
}

#ifdef Z_SHARDING

routing_info_t *knl_get_table_routing_info(knl_handle_t dc_entity)
{
    return &((dc_entity_t *)dc_entity)->table.routing_info;
}

#endif

memory_context_t *knl_get_dc_memory_context(knl_handle_t dc_entity)
{
    return ((dc_entity_t *)dc_entity)->memory;
}

void knl_get_low_arch(knl_handle_t session, uint32 *rst_id, uint32 *asn)
{
    knl_session_t *se = (knl_session_t *)session;
    CM_POINTER(se);

    log_get_curr_rstid_asn(se, rst_id, asn);
}

void knl_get_high_arch(knl_handle_t session, uint32 *rst_id, uint32 *asn)
{
    knl_session_t *se = (knl_session_t *)session;
    CM_POINTER(se);

    arch_get_last_rstid_asn(se, rst_id, asn);
}

char *knl_get_arch_dest_type(knl_handle_t session, uint32 id, knl_handle_t attr, bool32 *is_primary)
{
    knl_session_t *se = (knl_session_t *)session;
    arch_attr_t *arch_attr = (arch_attr_t *)attr;
    CM_POINTER3(se, arch_attr, is_primary);

    return arch_get_dest_type(se, id, arch_attr, is_primary);
}

void knl_get_arch_dest_path(knl_handle_t session, uint32 id, knl_handle_t attr, char *path, uint32 path_size)
{
    knl_session_t *se = (knl_session_t *)session;
    arch_attr_t *arch_attr = (arch_attr_t *)attr;
    CM_POINTER3(se, arch_attr, path);

    arch_get_dest_path(se, id, arch_attr, path, path_size);
}

char *knl_get_arch_sync_status(knl_handle_t session, uint32 id, knl_handle_t attr, knl_handle_t dest_sync)
{
    knl_session_t *se = (knl_session_t *)session;
    arch_attr_t *arch_attr = (arch_attr_t *)attr;
    arch_dest_sync_t *sync = (arch_dest_sync_t *)dest_sync;
    CM_POINTER3(se, arch_attr, sync);

    return arch_get_sync_status(se, id, arch_attr, sync);
}

char *knl_get_arch_sync(knl_handle_t dest_sync)
{
    arch_dest_sync_t *sync = (arch_dest_sync_t *)dest_sync;
    CM_POINTER(sync);

    return arch_get_dest_sync(sync);
}

/*
 * get the name of datafile according to the file number specified by user.
 *
 * @Note
 * the output argument will return the name to the datafile_t directly,
 * if the caller(SQL engine) wants to store the name, it should allocate memory by itself
 */
status_t knl_get_dfname_by_number(knl_handle_t session, int32 filenumber, char **filename)
{
    return spc_get_datafile_name_bynumber((knl_session_t *)session, filenumber, filename);
}

bool32 knl_has_update_default_col(knl_handle_t handle)
{
    dc_entity_t *dc_entity = (dc_entity_t *)handle;
    return dc_entity->has_udef_col;
}

bool32 knl_failover_triggered_pending(knl_handle_t knl_handle)
{
    knl_instance_t *kernel = (knl_instance_t *)knl_handle;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;

    if (!DB_IS_RAFT_ENABLED(kernel)) {
        return (ctrl->request == SWITCH_REQ_FAILOVER_PROMOTE || ctrl->request == SWITCH_REQ_FORCE_FAILOVER_PROMOTE);
    } else {
        return (ctrl->request == SWITCH_REQ_RAFT_PROMOTE || ctrl->request == SWITCH_REQ_RAFT_PROMOTE_PENDING);
    }
}

bool32 knl_failover_triggered(knl_handle_t knl_handle)
{
    knl_instance_t *kernel = (knl_instance_t *)knl_handle;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;

    if (!DB_IS_RAFT_ENABLED(kernel)) {
        return (ctrl->request == SWITCH_REQ_FAILOVER_PROMOTE ||
                (ctrl->request == SWITCH_REQ_FORCE_FAILOVER_PROMOTE && kernel->lrcv_ctx.session == NULL));
    } else {
        return (ctrl->request == SWITCH_REQ_RAFT_PROMOTE);
    }
}

bool32 knl_switchover_triggered(knl_handle_t knl_handle)
{
    knl_instance_t *kernel = (knl_instance_t *)knl_handle;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;

    if (!DB_IS_RAFT_ENABLED(kernel)) {
        return (ctrl->request == SWITCH_REQ_DEMOTE || ctrl->request == SWITCH_REQ_PROMOTE);
    } else {
        return CT_FALSE;
    }
}

bool32 knl_open_mode_triggered(knl_handle_t knl_handle)
{
    knl_instance_t *kernel = (knl_instance_t *)knl_handle;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;

    if (!DB_IS_RAFT_ENABLED(kernel)) {
        return (ctrl->request == SWITCH_REQ_READONLY || ctrl->request == SWITCH_REQ_CANCEL_UPGRADE);
    } else {
        return CT_FALSE;
    }
}

status_t knl_tx_enabled(knl_handle_t session)
{
    knl_session_t *se = (knl_session_t *)session;

    if (DB_NOT_READY(se)) {
        CT_THROW_ERROR(ERR_NO_DB_ACTIVE);
        return CT_ERROR;
    }

    if (DB_IS_READONLY(se)) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t chk_ddl_enable_rd_only(knl_session_t *session, ddl_exec_status_t *exec_stat)
{
    if (!DB_IS_PRIMARY(&session->kernel->db)) {
        *exec_stat = DDL_DISABLE_STANDBY;
        CT_THROW_ERROR(ERR_DATABASE_ROLE, "operation", "not in primary mode");
        return CT_ERROR;
    }

    if (DB_IS_READONLY(session)) {
        *exec_stat = DDL_DISABLE_READ_ONLY;
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t knl_ddl_enabled(knl_handle_t session, bool32 forbid_in_rollback)
{
    ddl_exec_status_t ddl_exec_stat;
    if (DB_IS_CLUSTER((knl_session_t*)session)) {
        if (dtc_ddl_enabled(session, forbid_in_rollback) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_CLUSTER_DDL_DISABLED);
            return CT_ERROR;
        }
    }
    return knl_ddl_execute_status(session, forbid_in_rollback, &ddl_exec_stat);
}

status_t knl_ddl_execute_status_internal(knl_handle_t sess, bool32 forbid_in_rollback, ddl_exec_status_t *ddl_exec_stat)
{
    knl_session_t *se = (knl_session_t *)sess;

    if (DB_IS_UPGRADE(se) || se->bootstrap) {
        *ddl_exec_stat = DDL_ENABLE;
        return CT_SUCCESS;
    }

    if (DB_STATUS(se) != DB_STATUS_OPEN) {
        *ddl_exec_stat = DDL_DISABLE_DB_NOT_OPEN;
        CT_THROW_ERROR(ERR_DATABASE_NOT_AVAILABLE);
        return CT_ERROR;
    }

    if (!forbid_in_rollback) {
        *ddl_exec_stat = DDL_ENABLE;
        return CT_SUCCESS;
    }

    if (se->kernel->dc_ctx.completed) {
        *ddl_exec_stat = DDL_ENABLE;
        return CT_SUCCESS;
    }
    if (DB_IN_BG_ROLLBACK(se)) {
        *ddl_exec_stat = DDL_DISABLE_DB_IS_ROLLING_BACK;
        CT_THROW_ERROR(ERR_DATABASE_IS_ROLLING_BACK);
        return CT_ERROR;
    }

    *ddl_exec_stat = se->kernel->set_dc_complete_status;
    if (*ddl_exec_stat == DDL_ENABLE) {
        *ddl_exec_stat = DDL_PART_DISABLE_SET_DC_COMPLETING;
    }
    CT_THROW_ERROR(ERR_DATABASE_NOT_AVAILABLE);
    return CT_ERROR;
}

status_t knl_ddl_execute_status(knl_handle_t sess, bool32 forbid_in_rollback, ddl_exec_status_t *ddl_exec_stat)
{
    if (chk_ddl_enable_rd_only(sess, ddl_exec_stat) == CT_ERROR) {
        return CT_ERROR;
    }
    return knl_ddl_execute_status_internal(sess, forbid_in_rollback, ddl_exec_stat);
}

status_t knl_ddl_enabled4ltt(knl_handle_t session, bool32 forbid_in_rollback)
{
    ddl_exec_status_t ddl_exec_stat;
    if (DB_IS_CLUSTER((knl_session_t*)session) && RC_REFORM_IN_PROGRESS) {
        CT_LOG_RUN_WAR("reform is preparing, refuse to ddl operation");
        CT_THROW_ERROR(ERR_CLUSTER_DDL_DISABLED, "reform is preparing");
        return CT_ERROR;
    }
    // do not check read only for ltt ddls
    return knl_ddl_execute_status_internal(session, forbid_in_rollback, &ddl_exec_stat);
}

status_t knl_convert_path_format(text_t *src, char *dst, uint32 dst_size, const char *home)
{
    uint32 len;
    uint32 home_len = (uint32)strlen(home);
    bool32 in_home = CT_FALSE;
    errno_t ret;
    cm_trim_text(src);

    if (CM_TEXT_FIRST(src) == '?') {
        CM_REMOVE_FIRST(src);
        len = home_len + src->len;
        in_home = CT_TRUE;
    } else {
        len = src->len;
    }

    if (len > CT_MAX_FILE_NAME_LEN) {
        CT_THROW_ERROR(ERR_NAME_TOO_LONG, "datafile or logfile", len, CT_MAX_FILE_NAME_LEN);
        return CT_ERROR;
    }

    if (in_home) {
        ret = memcpy_s(dst, dst_size, home, home_len);
        knl_securec_check(ret);
        if (src->len > 0) {
            ret = memcpy_s(dst + home_len, dst_size - home_len, src->str, src->len);
            knl_securec_check(ret);
        }
    } else {
        if (src->len > 0) {
            ret = memcpy_s(dst, dst_size, src->str, src->len);
            knl_securec_check(ret);
        }
    }

    dst[len] = '\0';
    return CT_SUCCESS;
}

status_t knl_get_convert_params(const char *item_name, char *value, file_convert_t *file_convert, const char *home)
{
    text_t text;
    text_t left;
    text_t right;
    uint32 i;
    char comma = ',';

    if (strlen(value) == 0) {
        file_convert->is_convert = CT_FALSE;
        return CT_SUCCESS;
    }

    file_convert->is_convert = CT_TRUE;
    cm_str2text(value, &text);

    /* two max_file_convert_num, one is for primary, one is for standby
     * other number like 2 or 1 is for calculate odd-even
     * The primary path of the mapping relationship is odd,
     * and the standby path of the mapping relationship is even
     */
    for (i = 0; i < CT_MAX_FILE_CONVERT_NUM * 2; i++) {
        cm_split_text(&text, comma, '\0', &left, &right);
        if (i % 2 == 0) {
            if (CM_TEXT_FIRST(&left) == '?') {
                CT_LOG_RUN_ERR("? can only be used for the local path, not for the peer path in %s", item_name);
                CT_THROW_ERROR(ERR_INVALID_PARAMETER, item_name);
                return CT_ERROR;
            }
            if (left.len > CT_MAX_FILE_NAME_LEN) {
                CT_THROW_ERROR(ERR_NAME_TOO_LONG, "datafile or logfile", left.len, CT_MAX_FILE_NAME_LEN);
                return CT_ERROR;
            }
            (void)cm_text2str(&left, file_convert->convert_list[i / 2].primry_path, CT_FILE_NAME_BUFFER_SIZE);
        } else {
            if (knl_convert_path_format(&left, file_convert->convert_list[i / 2].standby_path, CT_FILE_NAME_BUFFER_SIZE,
                                        home) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
        text = right;
        if (text.len == 0) {
            if (i % 2 == 1) {
                file_convert->count = (i + 1) / 2;
                return CT_SUCCESS;
            } else {
                CT_THROW_ERROR(ERR_INVALID_PARAMETER, item_name);
                return CT_ERROR;
            }
        }
    }
    CT_THROW_ERROR(ERR_TOO_MANY_OBJECTS, CT_MAX_FILE_CONVERT_NUM, "path number in %s", item_name);
    return CT_ERROR;
}

status_t knl_create_interval_part(knl_handle_t session, knl_dictionary_t *dc, uint32 part_no, part_key_t *part_key)
{
    knl_session_t *se = (knl_session_t *)session;
    dc_entity_t *dc_entity = DC_ENTITY(dc);
    table_t *table = DC_TABLE(dc);

    // check whether dc is corrupted or not, if corrupted, could not create interval partition
    if (dc_entity->corrupted) {
        CT_THROW_ERROR(ERR_DC_CORRUPTED);
        CT_LOG_RUN_ERR("dc for table %s is corrupted ", table->desc.name);
        return CT_ERROR;
    }

    if (part_no == CT_INVALID_ID32) {
        CT_THROW_ERROR(ERR_INVALID_PART_KEY, "inserted partition key does not map to any partition");
        return CT_ERROR;
    }

    /* check physical part is created or not */
    if (is_interval_part_created(se, dc, part_no)) {
        return CT_SUCCESS;
    }

    if (db_create_interval_part(se, dc, part_no, part_key) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * kernel get parallel schedule interface
 * We divide the heap segment during the given worker number(which maybe adjust inner).
 * @note in this interface, we hold no table lock
 * @param kernel session, dictionary, partition no, worker number, parallel range(output)
 */
status_t knl_get_paral_schedule(knl_handle_t handle, knl_dictionary_t *dc, knl_part_locate_t part_loc, uint32 workers,
                                knl_paral_range_t *range)
{
    knl_session_t *session = (knl_session_t *)handle;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = NULL;
    table_part_t *table_part = NULL;
    heap_t *heap = NULL;
    knl_scn_t org_scn;

    if (knl_check_dc(handle, dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc->type != DICT_TYPE_TABLE && dc->type != DICT_TYPE_TABLE_NOLOGGING) {
        range->workers = 0;
        return CT_SUCCESS;
    }

    table = &entity->table;

    if (IS_PART_TABLE(table)) {
        knl_panic_log(part_loc.part_no < table->part_table->desc.partcnt,
                      "the part_no is not smaller than part count, panic info: part_no %u part count %u table %s",
                      part_loc.part_no, table->part_table->desc.partcnt, table->desc.name);
        table_part = TABLE_GET_PART(table, part_loc.part_no);
        if (!IS_READY_PART(table_part)) {
            range->workers = 0;
            return CT_SUCCESS;
        }

        if (knl_is_parent_part((knl_handle_t)entity, part_loc.part_no)) {
            knl_panic_log(part_loc.subpart_no != CT_INVALID_ID32, "the subpart_no is invalid, panic info: table %s",
                          table->desc.name);
            table_part_t *subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[part_loc.subpart_no]);
            if (subpart == NULL) {
                range->workers = 0;
                return CT_SUCCESS;
            }

            heap = &subpart->heap;
            org_scn = subpart->desc.org_scn;
        } else {
            heap = &table_part->heap;
            org_scn = table_part->desc.org_scn;
        }
    } else {
        heap = &table->heap;
        org_scn = table->desc.org_scn;
    }

    heap_get_paral_schedule(session, heap, org_scn, workers, range);

    return CT_SUCCESS;
}

status_t knl_check_sessions_per_user(knl_handle_t session, text_t *username, uint32 count)
{
    knl_session_t *sess = session;
    dc_user_t *user = NULL;
    uint64 limit;

    if (!sess->kernel->attr.enable_resource_limit) {
        return CT_SUCCESS;
    }

    if (dc_open_user_direct(sess, username, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (CT_SUCCESS != profile_get_param_limit(sess, user->desc.profile_id, SESSIONS_PER_USER, &limit)) {
        return CT_ERROR;
    }

    if (PARAM_UNLIMITED == limit) {
        return CT_SUCCESS;
    }

    if (count >= limit) {
        CT_THROW_ERROR(ERR_EXCEED_SESSIONS_PER_USER, limit);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * knl_insert_dependency_list
 * This function is used to insert dependency list to dependency$.
 */
status_t knl_insert_dependency_list(knl_handle_t session, object_address_t *depender, galist_t *referenced_list)
{
    knl_session_t *knl_session = (knl_session_t *)session;

    return db_write_sysdep_list(knl_session, depender, referenced_list);
}

/*
 * knl_purge_stats
 * This function is used to purge the stats before given time.
 */
status_t knl_purge_stats(knl_handle_t session, int64 max_analyze_time)
{
    knl_session_t *knl_session = (knl_session_t *)session;

    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return stats_purge_stats_by_time(knl_session, max_analyze_time);
}

bool32 knl_is_lob_table(knl_dictionary_t *dc)
{
    return ((dc_entity_t *)dc->handle)->contain_lob;
}

status_t knl_reconstruct_lob_row(knl_handle_t session, knl_handle_t entity, knl_cursor_t *cursor, uint32 *scan_id,
                                 uint32 col_id)
{
    knl_column_t *column = NULL;
    errno_t ret;
    char *copy_row_start = NULL;
    char *copy_row_dest = NULL;
    char *copy_row_src = NULL;
    uint32 len;
    lob_locator_t *locator = NULL;
    text_t lob;
    uint32 id = *scan_id;
    bool32 is_csf = cursor->row->is_csf;

    CM_SAVE_STACK(((knl_session_t *)session)->stack);
    lob.str = cm_push(((knl_session_t *)session)->stack, CT_LOB_LOCATOR_BUF_SIZE);
    ret = memset_sp(lob.str, CT_LOB_LOCATOR_BUF_SIZE, 0, CT_LOB_LOCATOR_BUF_SIZE);
    knl_securec_check(ret);

    while (id < col_id) {
        column = knl_get_column(entity, id);
        if (!COLUMN_IS_LOB(column)) {
            id++;
            continue;
        }

        if (CURSOR_COLUMN_SIZE(cursor, id) == CT_NULL_VALUE_LEN) {
            id++;
            continue;
        }

        copy_row_start = heap_get_col_start(cursor->row, cursor->offsets, cursor->lens, id);
        locator = (lob_locator_t *)CURSOR_COLUMN_DATA(cursor, id);
        if (!locator->head.is_outline) {
            if (CURSOR_COLUMN_SIZE(cursor, id) <= KNL_LOB_LOCATOR_SIZE) {
                cursor->lob_inline_num--;
                id++;
                continue;
            }

            ret = memcpy_sp(lob.str, locator->head.size, (char *)locator->data, locator->head.size);
            knl_securec_check(ret);

            lob.len = locator->head.size;
            locator = knl_lob_col_new_start(is_csf, locator, lob.len);
            locator->head.size = 0;
            locator->first = INVALID_PAGID;
            locator->last = INVALID_PAGID;

            if (knl_write_lob(session, cursor, (char *)locator, column, CT_TRUE, &lob) != CT_SUCCESS) {
                CM_RESTORE_STACK(((knl_session_t *)session)->stack);
                return CT_ERROR;
            }

            copy_row_dest = copy_row_start + knl_lob_outline_size(is_csf);
            copy_row_src = copy_row_start + knl_lob_inline_size(is_csf, lob.len, CT_TRUE);
            len = cursor->row->size - cursor->offsets[id] - knl_lob_inline_size(is_csf, lob.len, CT_FALSE);
            if (len > 0) {
                ret = memmove_s(copy_row_dest, len, copy_row_src, len);
                knl_securec_check(ret);
            }

            cursor->row->size -= (uint16)(knl_lob_inline_size(is_csf, lob.len, CT_TRUE) - knl_lob_outline_size(is_csf));
            heap_write_col_size(is_csf, copy_row_start, KNL_LOB_LOCATOR_SIZE);
            cursor->lob_inline_num--;
            id++;
            break;
        }

        id++;
    }

    *scan_id = id;
    CM_RESTORE_STACK(((knl_session_t *)session)->stack);
    return CT_SUCCESS;
}

status_t knl_reconstruct_lob_update_info(knl_handle_t session, knl_dictionary_t *dc, knl_cursor_t *cursor,
                                         uint32 col_id)
{
    char *copy_row_start = NULL;
    char *copy_row_dest = NULL;
    char *copy_row_src = NULL;
    text_t lob;
    knl_update_info_t *ui = &cursor->update_info;
    bool32 is_csf = ((row_head_t *)ui->data)->is_csf;

    CM_SAVE_STACK(((knl_session_t *)session)->stack);
    lob.str = cm_push(((knl_session_t *)session)->stack, CT_LOB_LOCATOR_BUF_SIZE);
    errno_t ret = memset_sp(lob.str, CT_LOB_LOCATOR_BUF_SIZE, 0, CT_LOB_LOCATOR_BUF_SIZE);
    knl_securec_check(ret);

    for (uint32 i = 0; i < ui->count; i++) {
        if (i > col_id) {
            break;
        }

        uint32 col = ui->columns[i];
        knl_column_t *column = knl_get_column(dc->handle, col);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        if (CURSOR_UPDATE_COLUMN_SIZE(cursor, i) == CT_NULL_VALUE_LEN) {
            continue;
        }

        row_head_t *row = (row_head_t *)ui->data;
        copy_row_start = heap_get_col_start((row_head_t *)ui->data, ui->offsets, ui->lens, i);
        lob_locator_t *locator = (lob_locator_t *)((char *)ui->data + ui->offsets[i]);

        if (!locator->head.is_outline) {
            if (CURSOR_UPDATE_COLUMN_SIZE(cursor, i) <= KNL_LOB_LOCATOR_SIZE) {
                cursor->lob_inline_num--;
                continue;
            }

            ret = memcpy_sp(lob.str, locator->head.size, (char *)locator->data, locator->head.size);
            knl_securec_check(ret);
            lob.len = locator->head.size;
            locator = knl_lob_col_new_start(is_csf, locator, lob.len);
            locator->head.size = 0;
            locator->first = INVALID_PAGID;
            locator->last = INVALID_PAGID;

            if (knl_write_lob(session, cursor, (char *)locator, column, CT_TRUE, &lob) != CT_SUCCESS) {
                CM_RESTORE_STACK(((knl_session_t *)session)->stack);
                return CT_ERROR;
            }

            copy_row_dest = copy_row_start + knl_lob_outline_size(is_csf);
            copy_row_src = copy_row_start + knl_lob_inline_size(is_csf, lob.len, CT_TRUE);
            uint32 len = row->size - ui->offsets[i] - knl_lob_inline_size(is_csf, lob.len, CT_FALSE);
            if (len > 0) {
                ret = memmove_s(copy_row_dest, len, copy_row_src, len);
                knl_securec_check(ret);
            }

            row->size -= (uint16)(knl_lob_inline_size(is_csf, lob.len, CT_TRUE) - knl_lob_outline_size(is_csf));
            heap_write_col_size(is_csf, copy_row_start, KNL_LOB_LOCATOR_SIZE);
            cursor->lob_inline_num--;
            break;
        }
    }

    CM_RESTORE_STACK(((knl_session_t *)session)->stack);
    return CT_SUCCESS;
}

/*
 * knl_submit_job
 * This procedure submits a new job.
 */
status_t knl_submit_job(knl_handle_t session, knl_job_def_t *def)
{
    return db_write_sysjob((knl_session_t *)session, def);
}

/*
 * knl_update_job
 * This procedure update a job.
 */
status_t knl_update_job(knl_handle_t session, text_t *user, knl_job_node_t *job, bool32 should_exist)
{
    return db_update_sysjob((knl_session_t *)session, user, job, should_exist);
}

/*
 * knl_delete_job
 * This procedure delete a job.
 */
status_t knl_delete_job(knl_handle_t session, text_t *user, const int64 jobno, bool32 should_exist)
{
    return db_delete_sysjob((knl_session_t *)session, user, jobno, should_exist);
}

/* implementation for resource manager */
status_t knl_create_control_group(knl_handle_t session, knl_rsrc_group_t *group)
{
    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return db_create_control_group((knl_session_t *)session, group);
}

status_t knl_delete_control_group(knl_handle_t session, text_t *group_name)
{
    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return db_delete_control_group((knl_session_t *)session, group_name);
}

status_t knl_update_control_group(knl_handle_t session, knl_rsrc_group_t *group)
{
    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return db_update_control_group((knl_session_t *)session, group);
}

status_t knl_create_rsrc_plan(knl_handle_t session, knl_rsrc_plan_t *plan)
{
    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return db_create_rsrc_plan((knl_session_t *)session, plan);
}

status_t knl_delete_rsrc_plan(knl_handle_t session, text_t *plan_name)
{
    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return db_delete_rsrc_plan((knl_session_t *)session, plan_name);
}

status_t knl_update_rsrc_plan(knl_handle_t session, knl_rsrc_plan_t *plan)
{
    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return db_update_rsrc_plan((knl_session_t *)session, plan);
}

status_t knl_create_rsrc_plan_rule(knl_handle_t session, knl_rsrc_plan_rule_def_t *def)
{
    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return db_create_rsrc_plan_rule((knl_session_t *)session, def);
}

status_t knl_delete_rsrc_plan_rule(knl_handle_t session, text_t *plan_name, text_t *group_name)
{
    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return db_delete_rsrc_plan_rule((knl_session_t *)session, plan_name, group_name);
}

status_t knl_update_rsrc_plan_rule(knl_handle_t session, knl_rsrc_plan_rule_def_t *def)
{
    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return db_update_rsrc_plan_rule((knl_session_t *)session, def);
}

status_t knl_set_cgroup_mapping(knl_handle_t session, knl_rsrc_group_mapping_t *mapping)
{
    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return db_set_cgroup_mapping((knl_session_t *)session, mapping);
}

status_t knl_alter_sql_map(knl_handle_t session, knl_sql_map_t *sql_map)
{
    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return db_alter_sql_sysmap((knl_session_t *)session, sql_map);
}

status_t knl_drop_sql_map(knl_handle_t session, knl_sql_map_t *sql_map)
{
    bool8 is_exist = CT_FALSE;

    if (knl_ddl_enabled(session, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (db_delete_sql_sysmap((knl_session_t *)session, sql_map, &is_exist) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!is_exist && (sql_map->options & DROP_IF_EXISTS) == 0) {
        CT_THROW_ERROR(ERR_SQL_MAP_NOT_EXIST);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t knl_refresh_sql_map_hash(knl_handle_t session, knl_cursor_t *cursor, uint32 hash_value)
{
    uint32 old_hash_value = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SQL_MAP_COL_SRC_HASHCODE);
    if (old_hash_value != hash_value) {
        if (db_update_sql_map_hash((knl_session_t *)session, cursor, hash_value) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static void estimate_segment_rows(uint32 *pages, uint32 *rows, knl_session_t *session, table_t *table,
                                  table_part_t *part)
{
    if (pages != NULL) {
        *pages = 0;
    }
    if (rows != NULL) {
        *rows = 0;
    }

    uint32 tmp_pages;
    uint32 pctfree;
    knl_scn_t org_scn;
    space_t *space = NULL;
    heap_t *heap = NULL;
    heap_segment_t *seg = NULL;
    page_head_t *head = NULL;

    if (part == NULL) {
        space = SPACE_GET(session, table->desc.space_id);
        pctfree = table->desc.pctfree;
        heap = &table->heap;
        org_scn = table->desc.org_scn;
    } else {
        space = SPACE_GET(session, part->desc.space_id);
        pctfree = part->desc.pctfree;
        heap = &part->heap;
        org_scn = part->desc.org_scn;
    }

    if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
        return;
    }
    if (IS_INVALID_PAGID(heap->entry)) {
        return;
    }

    buf_enter_page(session, heap->entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
    head = (page_head_t *)CURR_PAGE(session);
    seg = HEAP_SEG_HEAD(session);
    if (head->type != PAGE_TYPE_HEAP_HEAD || seg->org_scn != org_scn) {
        buf_leave_page(session, CT_FALSE);
        return;
    }

    if (IS_INVALID_PAGID(seg->data_last)) {
        tmp_pages = 0;
    } else {
        if (seg->extents.count == 1) {
            tmp_pages = seg->data_last.page - seg->data_first.page + 1;
        } else {
            tmp_pages = seg->extents.count * space->ctrl->extent_size;
            tmp_pages = tmp_pages - seg->map_count[0] - seg->map_count[1] - seg->map_count[2];  // map pages 0 - 2
            tmp_pages--;                                                                        // segment page
        }
    }
    buf_leave_page(session, CT_FALSE);

    if (pages != NULL) {
        *pages = tmp_pages;
    }

    if (rows != NULL) {
        // pctfree is a ratio num
        *rows = ((uint64)tmp_pages *
                 (space->ctrl->block_size - sizeof(heap_page_t) - heap->cipher_reserve_size - PAGE_TAIL_SIZE) *
                 (100 - pctfree)) /
                (table->desc.estimate_len * 100);
    }
}

static void estimate_all_subpart_rows(uint32 *pages, uint32 *rows, knl_handle_t sess, table_t *table,
                                      table_part_t *part)
{
    if (pages != NULL) {
        *pages = 0;
    }
    if (rows != NULL) {
        *rows = 0;
    }

    knl_session_t *session = (knl_session_t *)sess;
    table_part_t *subpart = NULL;
    for (uint32 i = 0; i < part->desc.subpart_cnt; i++) {
        subpart = PART_GET_SUBENTITY(table->part_table, part->subparts[i]);
        if (subpart == NULL) {
            continue;
        }
        uint32 tmp_pages, tmp_rows;
        estimate_segment_rows(&tmp_pages, &tmp_rows, session, table, (table_part_t *)subpart);
        if (pages != NULL) {
            *pages += tmp_pages;
        }
        if (rows != NULL) {
            *rows += tmp_rows;
        }
    }
}

static void estimate_all_part_rows(uint32 *pages, uint32 *rows, knl_handle_t sess, table_t *table)
{
    if (pages != NULL) {
        *pages = 0;
    }
    if (rows != NULL) {
        *rows = 0;
    }

    knl_session_t *session = (knl_session_t *)sess;
    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        table_part_t *part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(part)) {
            continue;
        }
        uint32 tmp_pages, tmp_rows;
        if (IS_PARENT_TABPART(&part->desc)) {
            estimate_all_subpart_rows(&tmp_pages, &tmp_rows, sess, table, part);
        } else {
            estimate_segment_rows(&tmp_pages, &tmp_rows, session, table, part);
        }

        if (pages != NULL) {
            *pages += tmp_pages;
        }
        if (rows != NULL) {
            *rows += tmp_rows;
        }
    }
}

static void estimate_temp_table_rows(knl_session_t *session, table_t *table, uint32 *pages, uint32 *rows)
{
    space_t *space = SPACE_GET(session, table->desc.space_id);

    if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
        return;
    }

    knl_temp_cache_t *temp_cache = knl_get_temp_cache(session, table->desc.uid, table->desc.id);

    if (temp_cache == NULL) {
        return;
    }

    mtrl_segment_t *segment = session->temp_mtrl->segments[temp_cache->table_segid];
    if (segment->vm_list.count == 0) {
        return;
    }

    uint64 total_size = TEMP_ESTIMATE_TOTAL_ROW_SIZE(segment, table);
    if (rows != NULL) {
        *rows = (uint32)(total_size * TEMP_ESTIMATE_ROW_SIZE_RATIO / table->desc.estimate_len);
    }
    if (pages != NULL) {
        *pages = segment->vm_list.count;
    }
}

void knl_estimate_table_rows(uint32 *pages, uint32 *rows, knl_handle_t sess, knl_handle_t entity, uint32 part_no)
{
    table_t *table = &((dc_entity_t *)entity)->table;
    table_part_t *part = NULL;

    if (knl_get_db_status(sess) != DB_STATUS_OPEN) {
        if (pages != NULL) {
            *pages = 0;
        }
        if (rows != NULL) {
            *rows = 0;
        }
        return;
    }

    if (IS_PART_TABLE(table)) {
        if (part_no == CT_INVALID_ID32) {
            estimate_all_part_rows(pages, rows, sess, table);
            return;
        }
        part = TABLE_GET_PART(table, part_no);
        if (IS_READY_PART(part) && IS_PARENT_TABPART(&part->desc)) {
            estimate_all_subpart_rows(pages, rows, sess, table, part);
            return;
        }
    }

    if (TABLE_IS_TEMP(table->desc.type)) {
        estimate_temp_table_rows((knl_session_t *)sess, table, pages, rows);
    } else {
        estimate_segment_rows(pages, rows, (knl_session_t *)sess, table, part);
    }
}

void knl_estimate_subtable_rows(uint32 *pages, uint32 *rows, knl_handle_t sess, knl_handle_t entity, uint32 part_no,
                                uint32 subpart_no)
{
    table_t *table = &((dc_entity_t *)entity)->table;
    table_part_t *part = NULL;

    if (knl_get_db_status(sess) != DB_STATUS_OPEN) {
        if (pages != NULL) {
            *pages = 0;
        }
        if (rows != NULL) {
            *rows = 0;
        }
        return;
    }

    if (!IS_PART_TABLE(table)) {
        estimate_segment_rows(pages, rows, (knl_session_t *)sess, table, NULL);
        return;
    }

    if (part_no == CT_INVALID_ID32) {
        estimate_all_part_rows(pages, rows, sess, table);
        return;
    }

    part = TABLE_GET_PART(table, part_no);
    if (part == NULL || !IS_PARENT_TABPART(&part->desc)) {
        estimate_segment_rows(pages, rows, (knl_session_t *)sess, table, part);
        return;
    }

    if (subpart_no == CT_INVALID_ID32) {
        estimate_all_subpart_rows(pages, rows, sess, table, part);
        return;
    }

    table_part_t *subpart = PART_GET_SUBENTITY(table->part_table, part->subparts[subpart_no]);
    if (subpart == NULL) {
        estimate_all_subpart_rows(pages, rows, sess, table, part);
        return;
    }

    estimate_segment_rows(pages, rows, (knl_session_t *)sess, table, (table_part_t *)subpart);
    return;
}

void knl_inc_dc_ver(knl_handle_t kernel)
{
    ((knl_instance_t *)kernel)->dc_ctx.version++;
}

/**
 * recycle lob pages for sql engine
 * @note getting locator from cursor->row
 * @param kernel session, kernel cursor
 */
status_t knl_recycle_lob_insert_pages(knl_handle_t session, knl_cursor_t *cursor)
{
    knl_session_t *se = (knl_session_t *)session;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    knl_column_t *column = NULL;
    lob_locator_t *locator = NULL;

    for (uint32 i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        if (KNL_COLUMN_IS_DELETED(column)) {
            continue;
        }

        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        if (CURSOR_COLUMN_SIZE(cursor, i) == CT_NULL_VALUE_LEN) {
            continue;
        }

        locator = (lob_locator_t *)CURSOR_COLUMN_DATA(cursor, i);
        if (!locator->head.is_outline) {
            continue;
        }

        if (lob_recycle_pages(se, cursor, (lob_t *)column->lob, locator) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

/**
 * recycle lob pages for sql engine
 * @note getting locator from  cursor->update_info
 * @param kernel session, kernel cursor
 */
status_t knl_recycle_lob_update_pages(knl_handle_t session, knl_cursor_t *cursor)
{
    knl_session_t *se = (knl_session_t *)session;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    knl_column_t *column = NULL;
    lob_locator_t *locator = NULL;
    knl_update_info_t *ui = &cursor->update_info;
    uint16 col_id;

    for (uint32 i = 0; i < ui->count; i++) {
        col_id = cursor->update_info.columns[i];
        column = dc_get_column(entity, col_id);
        if (KNL_COLUMN_IS_DELETED(column)) {
            continue;
        }

        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        if (ui->lens[i] == CT_NULL_VALUE_LEN) {
            continue;
        }

        locator = (lob_locator_t *)((char *)ui->data + ui->offsets[i]);

        if (!locator->head.is_outline) {
            continue;
        }

        if (lob_recycle_pages(se, cursor, (lob_t *)column->lob, locator) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t knl_recycle_lob_column_pages(knl_handle_t session, knl_cursor_t *cursor, knl_column_t *column, char *lob)
{
    knl_session_t *se = (knl_session_t *)session;
    lob_locator_t *locator = (lob_locator_t *)lob;
    if (KNL_COLUMN_IS_DELETED(column) || !locator->head.is_outline) {
        return CT_SUCCESS;
    }
    return lob_recycle_pages(se, cursor, (lob_t *)column->lob, (lob_locator_t *)locator);
}

status_t knl_delete_syssyn_by_name(knl_handle_t knl_session, uint32 uid, const char *syn_name)
{
    knl_session_t *session = (knl_session_t *)knl_session;
    knl_cursor_t *cursor = NULL;
    dc_user_t *user = NULL;

    if (dc_open_user_by_id(session, uid, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SYN_ID, IX_SYS_SYNONYM001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&uid,
                     sizeof(uint32), IX_COL_SYS_SYNONYM001_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)syn_name,
                     (uint16)strlen(syn_name), IX_COL_SYS_SYNONYM001_SYNONYM_NAME);

    if (CT_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_SYNONYM_NOT_EXIST, user->desc.name, syn_name);
        return CT_ERROR;
    }

    if (CT_SUCCESS != knl_internal_delete(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

status_t knl_check_and_load_synonym(knl_handle_t knl_session, text_t *user, text_t *name, knl_synonym_t *result,
                                    bool32 *exists)
{
    knl_session_t *session = (knl_session_t *)knl_session;
    uint32 uid, syn_uid;
    text_t syn_name, table_owner, table_name;
    *exists = CT_FALSE;

    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!knl_get_user_id(session, user, &uid)) {
        CT_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(user));
        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SYN_ID, IX_SYS_SYNONYM001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&uid,
                     sizeof(uint32), IX_COL_SYS_SYNONYM001_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, name->str, name->len,
                     IX_COL_SYS_SYNONYM001_SYNONYM_NAME);

    for (;;) {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }
        // get synonym uid and name
        syn_uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_USER);
        syn_name.len = (uint32)CURSOR_COLUMN_SIZE(cursor, SYS_SYN_SYNONYM_NAME);
        syn_name.str = (char *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_SYNONYM_NAME);

        if (uid == syn_uid && cm_text_equal(&syn_name, name)) {
            // get synonym info
            result->uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_USER);
            result->id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_OBJID);
            result->chg_scn = *(int64 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_CHG_SCN);
            result->org_scn = *(int64 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_ORG_SCN);
            result->type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_TYPE);

            table_owner.len = (uint32)CURSOR_COLUMN_SIZE(cursor, SYS_SYN_TABLE_OWNER);
            table_owner.str = (char *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_TABLE_OWNER);
            table_name.len = (uint32)CURSOR_COLUMN_SIZE(cursor, SYS_SYN_TABLE_NAME);
            table_name.str = (char *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_TABLE_NAME);

            cm_text2str(&syn_name, result->name, CT_NAME_BUFFER_SIZE);
            cm_text2str(&table_owner, result->table_owner, CT_NAME_BUFFER_SIZE);
            cm_text2str(&table_name, result->table_name, CT_NAME_BUFFER_SIZE);
            *exists = CT_TRUE;
            break;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t knl_pl_create_synonym(knl_handle_t knl_session, knl_synonym_def_t *def, const int64 syn_id)
{
    knl_session_t *session = (knl_session_t *)knl_session;
    knl_synonym_t synonym;
    knl_cursor_t *cursor = NULL;
    object_address_t depender, referer;
    dc_user_t *user = NULL;
    errno_t err;

    if (knl_ddl_enabled(session, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (DB_NOT_READY(session)) {
        CT_THROW_ERROR(ERR_NO_DB_ACTIVE);
        return CT_ERROR;
    }

    if (db_init_synonmy_desc(session, &synonym, def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_open_user_by_id(session, synonym.uid, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // for creating table bug fix: cursor->row is null
    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    cursor->row = (row_head_t *)cursor->buf;

    // init the function synonym id as ref->oid
    synonym.id = (uint32)syn_id;

    if (db_write_syssyn(session, cursor, &synonym) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    // insert into sys.dependency$
    depender.uid = synonym.uid;
    depender.oid = synonym.id;
    depender.tid = OBJ_TYPE_PL_SYNONYM;
    depender.scn = synonym.chg_scn;
    err = strncpy_s(depender.name, CT_NAME_BUFFER_SIZE, def->name.str, def->name.len);
    knl_securec_check(err);
    referer.uid = def->ref_uid;
    referer.oid = def->ref_oid;
    referer.tid = knl_get_object_type(def->ref_dc_type);
    referer.scn = def->ref_chg_scn;
    err = strncpy_s(referer.name, CT_NAME_BUFFER_SIZE, def->table_name.str, def->table_name.len);
    knl_securec_check(err);
    if (db_write_sysdep(session, cursor, &depender, &referer, 0) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

#ifdef Z_SHARDING
status_t knl_insert_ddl_loginfo(knl_handle_t knl_session, knl_dist_ddl_loginfo_t *info)
{
    row_assist_t ra;
    table_t *table = NULL;
    knl_cursor_t *cursor = NULL;
    knl_session_t *session = (knl_session_t *)knl_session;
    knl_column_t *lob_column = NULL;

    CM_SAVE_STACK(session->stack);

    if (sql_push_knl_cursor(session, &cursor) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_DIST_DDL_LOGINFO, CT_INVALID_ID32);
    table = (table_t *)cursor->table;
    lob_column = knl_get_column(cursor->dc_entity, DIST_DDL_LOGINFO_COL_DDL);
    row_init(&ra, (char *)cursor->row, HEAP_MAX_ROW_SIZE(session), table->desc.column_count);
    (void)row_put_text(&ra, &info->dist_ddl_id);
    (void)row_put_int32(&ra, (int32)info->rec.group_id);
    (void)row_put_int32(&ra, (int32)info->rec.datanode_id);
    if (knl_row_put_lob(session, cursor, lob_column, &info->rec.ddl_info, &ra) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    (void)row_put_timestamp(&ra, info->rec.create_time);
    (void)row_put_timestamp(&ra, info->rec.expired_time);
    (void)row_put_int32(&ra, (int32)info->rec.retry_times);
    (void)row_put_int32(&ra, (int32)info->rec.status);

    if (CT_SUCCESS != knl_internal_insert(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}
#endif

bool32 knl_is_dist_ddl(knl_handle_t knl_session)
{
    return (((knl_session_t *)knl_session)->dist_ddl_id != NULL);
}

void knl_set_ddl_id(knl_handle_t knl_session, text_t *id)
{
    ((knl_session_t *)knl_session)->dist_ddl_id = id;
}

void knl_clean_before_commit(knl_handle_t knl_session)
{
#ifdef Z_SHARDING
    knl_session_t *session = (knl_session_t *)knl_session;
    if (session->dist_ddl_id != NULL) {
        (void)knl_delete_ddl_loginfo(knl_session, session->dist_ddl_id);
    }

    session->dist_ddl_id = NULL;
#endif
}

#ifdef Z_SHARDING
status_t knl_clean_ddl_loginfo(knl_handle_t knl_session, text_t *ddl_id, uint32 *rows)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *session = (knl_session_t *)knl_session;

    *rows = 0;
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_DIST_DDL_LOGINFO, IX_DIST_DDL_LOGINFO_001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, ddl_id->str, ddl_id->len, 0);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CT_LOG_DEBUG_ERR("delete ddl loginfo :%s fetch failed", T2S(ddl_id));
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (!cursor->eof) {
        if (CT_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
        *rows = 1;
    }

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

status_t knl_delete_ddl_loginfo(knl_handle_t knl_session, text_t *ddl_id)
{
    uint32 rows = 0;

    return knl_clean_ddl_loginfo(knl_session, ddl_id, &rows);
}

status_t knl_query_ddl_loginfo(knl_handle_t knl_session, text_t *ddl_id, text_t *ddl_info, uint32 *used_encrypt)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *session = (knl_session_t *)knl_session;
    lob_locator_t *src_lob = NULL;

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_DIST_DDL_LOGINFO, IX_DIST_DDL_LOGINFO_001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, ddl_id->str, ddl_id->len, 0);
    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!cursor->eof) {
        src_lob = (lob_locator_t *)CURSOR_COLUMN_DATA(cursor, DIST_DDL_LOGINFO_COL_DDL);
        ddl_info->len = knl_lob_size(src_lob);
        ddl_info->str = (char *)cm_push(session->stack, (ddl_info->len + 1));
        if (ddl_info->str == NULL) {
            CT_THROW_ERROR(ERR_STACK_OVERFLOW);
            return CT_ERROR;
        }

        *used_encrypt = *(uint32 *)CURSOR_COLUMN_DATA(cursor, DIST_DDL_LOGINFO_COL_RETRY_TIMES);
        if (knl_read_lob(session, src_lob, 0, ddl_info->str, ddl_info->len, NULL, NULL) != CT_SUCCESS) {
            return CT_ERROR;
        }

        ddl_info->str[ddl_info->len] = '\0';
        return CT_SUCCESS;
    }

    CT_THROW_ERROR(ERR_TF_QUERY_DDL_INFO_FAILED);
    return CT_ERROR;
}
#endif

status_t knl_convert_xa_xid(xa_xid_t *src, knl_xa_xid_t *dst)
{
    errno_t ret;

    if (src->gtrid_len == 0) {
        CT_THROW_ERROR_EX(ERR_XA_INVALID_XID, "gtrid len: 0");
        return CT_ERROR;
    }

    dst->gtrid_len = src->gtrid_len;
    ret = memcpy_sp(dst->gtrid, CT_MAX_XA_BASE16_GTRID_LEN, src->data, (uint32)src->gtrid_len);
    knl_securec_check(ret);

    dst->bqual_len = src->bqual_len;
    ret = memcpy_sp(dst->bqual, CT_MAX_XA_BASE16_BQUAL_LEN, src->data + src->gtrid_len, (uint32)src->bqual_len);
    knl_securec_check(ret);

    dst->fmt_id = src->fmt_id;
    return CT_SUCCESS;
}

bool32 knl_xa_xid_equal(knl_xa_xid_t *xid1, knl_xa_xid_t *xid2)
{
    text_t xid_text1;
    text_t xid_text2;

    if (xid1->fmt_id != xid2->fmt_id) {
        return CT_FALSE;
    }

    cm_str2text_safe(xid1->gtrid, xid1->gtrid_len, &xid_text1);
    cm_str2text_safe(xid2->gtrid, xid2->gtrid_len, &xid_text2);

    if (!cm_text_equal(&xid_text1, &xid_text2)) {
        return CT_FALSE;
    }

    cm_str2text_safe(xid1->bqual, xid1->bqual_len, &xid_text1);
    cm_str2text_safe(xid2->bqual, xid2->bqual_len, &xid_text2);

    if (!cm_text_equal(&xid_text1, &xid_text2)) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

uint32 knl_get_bucket_by_variant(variant_t *data, uint32 part_cnt)
{
    if (CT_IS_NUMBER_TYPE(data->type)) {
        dec4_t d4;
        (void)cm_dec_8_to_4(&d4, &data->v_dec);
        data->v_bin.bytes = (uint8 *)&d4;
        data->v_bin.size = cm_dec4_stor_sz(&d4);

        return part_get_bucket_by_variant(data, part_cnt);
    } else {
        return part_get_bucket_by_variant(data, part_cnt);
    }
}

status_t knl_open_external_cursor(knl_handle_t session, knl_cursor_t *cursor, knl_dictionary_t *dc)
{
    int32 ret;
    uint32 mode;
    bool32 is_found = CT_FALSE;
    uint32 uid = ((knl_session_t *)session)->uid;
    char dest_name[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    char path_name[CT_MAX_PATH_BUFFER_SIZE] = { 0 };
    table_t *table = (table_t *)cursor->table;
    knl_ext_desc_t *external_desc = table->desc.external_desc;

    cursor->fetch = TABLE_ACCESSOR(cursor)->do_fetch;
    if (db_fetch_directory_path(session, external_desc->directory, path_name, CT_MAX_PATH_BUFFER_SIZE, &is_found) !=
        CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!is_found) {
        CT_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "directory", external_desc->directory);
        return CT_ERROR;
    }

    /* check if has read priv on the directory */
    if (!db_check_dirpriv_by_uid(session, external_desc->directory, uid, CT_PRIV_DIRE_READ)) {
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }

    ret = snprintf_s(dest_name, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s/%s", path_name,
                     external_desc->location);
    knl_securec_check_ss(ret);

    if (!cm_file_exist(dest_name)) {
        CT_THROW_ERROR(ERR_FILE_NOT_EXIST, "external", external_desc->location);
        return CT_ERROR;
    }

    knl_panic_log(external_desc->external_type == LOADER,
                  "external type is abnormal, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name);
    mode = O_BINARY | O_SYNC | O_RDONLY;
    /* file cursor->fd is closed in external_heap_fetch_by_page */
    if (cm_open_file(dest_name, mode, &cursor->fd) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_seek_file(cursor->fd, 0, SEEK_SET) != 0) {
        cm_close_file(cursor->fd);
        cursor->fd = -1;
        CT_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_SET, errno);
        return CT_ERROR;
    }

    cursor->text.len = 0;
    MAXIMIZE_ROWID(cursor->rowid);

    return CT_SUCCESS;
}

void knl_destroy_se_alcks(knl_handle_t session)
{
    lock_destroy_se_alcks((knl_session_t *)session);
}

static status_t knl_prepare_check_dc(knl_session_t *session, knl_dictionary_t *dc)
{
    dc_entity_t *entity = DC_ENTITY(dc);

    if (entity == NULL) {
        CT_THROW_ERROR(ERR_DC_INVALIDATED);
        return CT_ERROR;
    }
    dc_entry_t *entry = entity->entry;

    if (entity->corrupted) {
        CT_THROW_ERROR(ERR_DC_CORRUPTED);
        return CT_ERROR;
    }

    if (!IS_LOGGING_TABLE_BY_TYPE(dc->type)) {
        if (entry && entry->need_empty_entry && KNL_IS_DATABASE_OPEN(session)) {
            CT_THROW_ERROR(ERR_DC_INVALIDATED);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t knl_check_dc_sync(knl_session_t *session, knl_dictionary_t *dc)
{
    text_t orig_user;
    text_t name;
    knl_dictionary_t new_dc;
    bool32 is_found = CT_FALSE;
    dc_entity_t *entity = DC_ENTITY(dc);
    dc_entry_t *sync_entry = (dc_entry_t *)dc->syn_handle;

    if (dc->syn_orig_uid != sync_entry->uid) {
        if (knl_get_user_name(session, dc->syn_orig_uid, &orig_user) != CT_SUCCESS) {
            cm_reset_error();
            CT_THROW_ERROR(ERR_INVALID_OPERATION, ", please check user or schema");
            return CT_ERROR;
        }

        cm_str2text(sync_entry->name, &name);
        if (knl_open_dc_if_exists(session, &orig_user, &name, &new_dc, &is_found) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (is_found) {
            knl_close_dc(&new_dc);
            CT_THROW_ERROR(ERR_DC_INVALIDATED);
            return CT_ERROR;
        }
    }

    if ((dc->syn_chg_scn == sync_entry->chg_scn) && (dc->chg_scn == entity->entry->chg_scn) && entity->valid &&
        !entity->entry->recycled) {
        return dc_check_stats_version(session, dc, entity);
    }

    CT_THROW_ERROR(ERR_DC_INVALIDATED);
    return CT_ERROR;
}

status_t knl_check_dc(knl_handle_t handle, knl_dictionary_t *dc)
{
    knl_session_t *session = (knl_session_t *)handle;
    dc_entity_t *entity = DC_ENTITY(dc);

    if (knl_prepare_check_dc(session, dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (SYNONYM_EXIST(dc)) {
        return knl_check_dc_sync(session, dc);
    } else {
        if (dc->type == DICT_TYPE_TEMP_TABLE_SESSION && IS_LTT_BY_NAME(entity->table.desc.name)) {
            knl_session_t *curr = (knl_session_t *)knl_get_curr_sess();
            uint32 tab_id = entity->table.desc.id;

            dc_entry_t *entry = entity->entry;
            if (entry == NULL || tab_id < CT_LTT_ID_OFFSET ||
                tab_id >= (CT_LTT_ID_OFFSET + curr->temp_table_capacity)) {
                CT_THROW_ERROR(ERR_DC_INVALIDATED);
                return CT_ERROR;
            }

            dc_entry_t *sess_entry = (dc_entry_t *)curr->temp_dc->entries[tab_id - CT_LTT_ID_OFFSET];
            if (entry == sess_entry && dc->org_scn == sess_entry->org_scn) {
                return CT_SUCCESS;
            }
        } else if ((dc->chg_scn == entity->entry->chg_scn) && entity->valid && !entity->entry->recycled) {
            return dc_check_stats_version(session, dc, entity);
        }
    }

    CT_THROW_ERROR(ERR_DC_INVALIDATED);
    return CT_ERROR;
}

status_t knl_set_table_stats(knl_handle_t session, knl_table_set_stats_t *tab_stats)
{
    knl_session_t *se = (knl_session_t *)session;
    knl_dictionary_t dc;
    part_table_t *part_table = NULL;
    table_t *table = NULL;
    table_part_t *table_part = NULL;
    status_t status;

    if (knl_open_dc(session, &tab_stats->owner, &tab_stats->name, &dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (IS_TEMP_TABLE_BY_DC(&dc)) {
        dc_close(&dc);
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "set statistics", "temp table");
        return CT_ERROR;
    }

    if (lock_table_shared_directly(se, &dc) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }

    table = DC_TABLE(&dc);

    if (tab_stats->is_single_part) {
        if (!IS_PART_TABLE(table)) {
            unlock_tables_directly(se);
            dc_close(&dc);
            CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "set partition statistics", table->desc.name);
            return CT_ERROR;
        }

        part_table = table->part_table;

        if (!part_table_find_by_name(part_table, &tab_stats->part_name, &table_part)) {
            unlock_tables_directly(se);
            dc_close(&dc);
            CT_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&tab_stats->part_name));
            return CT_ERROR;
        }
    }

    status = stats_set_tables(se, &dc, tab_stats, table_part);
    if (status == CT_SUCCESS) {
        knl_commit(session);
    } else {
        knl_rollback(session, NULL);
    }

    unlock_tables_directly(se);
    dc_close(&dc);
    return status;
}

status_t knl_set_columns_stats(knl_handle_t session, knl_column_set_stats_t *col_stats)
{
    knl_session_t *se = (knl_session_t *)session;
    knl_dictionary_t dc;
    part_table_t *part_table = NULL;
    table_t *table = NULL;
    table_part_t *table_part = NULL;
    knl_column_t *column = NULL;
    status_t status;

    if (knl_open_dc(session, &col_stats->owner, &col_stats->tabname, &dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (IS_TEMP_TABLE_BY_DC(&dc)) {
        dc_close(&dc);
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "set statistics", "temp table");
        return CT_ERROR;
    }

    if (lock_table_shared_directly(se, &dc) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }

    table = DC_TABLE(&dc);
    column = knl_find_column(&col_stats->colname, &dc);
    if (column == NULL) {
        unlock_tables_directly(se);
        dc_close(&dc);
        CT_THROW_ERROR(ERR_COLUMN_NOT_EXIST, T2S(&col_stats->tabname), T2S_EX(&col_stats->colname));
        return CT_ERROR;
    }

    if (col_stats->is_single_part) {
        if (!IS_PART_TABLE(table)) {
            unlock_tables_directly(se);
            dc_close(&dc);
            CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "set partition statistics", table->desc.name);
            return CT_ERROR;
        }

        part_table = table->part_table;

        if (!part_table_find_by_name(part_table, &col_stats->part_name, &table_part)) {
            unlock_tables_directly(se);
            dc_close(&dc);
            CT_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&col_stats->part_name));
            return CT_ERROR;
        }
    }

    status = stats_set_column(se, &dc, col_stats, table_part, column);
    if (status == CT_SUCCESS) {
        knl_commit(session);
    } else {
        knl_rollback(session, NULL);
    }

    unlock_tables_directly(se);
    dc_close(&dc);
    return status;
}

static status_t knl_ckeck_index_status(knl_dictionary_t *dc, knl_index_set_stats_t *ind_stats, index_t *index,
                                       index_part_t **idx_part)
{
    if (index == NULL) {
        CT_THROW_ERROR(ERR_INDEX_NOT_EXIST, T2S(&ind_stats->owner), T2S_EX(&ind_stats->name));
        return CT_ERROR;
    }

    if (index->desc.is_invalid) {
        CT_THROW_ERROR(ERR_INDEX_NOT_STABLE, T2S_EX(&ind_stats->name));
        return CT_ERROR;
    }

    if (ind_stats->is_single_part) {
        table_t *table = DC_TABLE(dc);
        if (!IS_PART_INDEX(index)) {
            CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "set partition statistics", table->desc.name);
            return CT_ERROR;
        }

        part_index_t *part_idx = index->part_index;
        if (!part_idx_find_by_name(part_idx, &ind_stats->part_name, idx_part)) {
            CT_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&ind_stats->part_name));
            return CT_ERROR;
        }

        if ((*idx_part)->desc.is_invalid) {
            CT_THROW_ERROR(ERR_INDEX_PART_UNUSABLE, T2S(&ind_stats->part_name), T2S_EX(&ind_stats->name));
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t knl_set_index_stats(knl_handle_t session, knl_index_set_stats_t *ind_stats)
{
    knl_session_t *se = (knl_session_t *)session;
    knl_dictionary_t dc;
    index_part_t *idx_part = NULL;

    if (knl_open_dc_by_index(se, &ind_stats->owner, NULL, &ind_stats->name, &dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (IS_TEMP_TABLE_BY_DC(&dc)) {
        dc_close(&dc);
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "set statistics", "temp table");
        return CT_ERROR;
    }

    if (lock_table_shared_directly(se, &dc) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }

    index_t *idx = dc_find_index_by_name(DC_ENTITY(&dc), &ind_stats->name);
    if (knl_ckeck_index_status(&dc, ind_stats, idx, &idx_part) != CT_SUCCESS) {
        unlock_tables_directly(se);
        dc_close(&dc);
        return CT_ERROR;
    }

    status_t status = stats_set_index(se, &dc, ind_stats, idx_part, idx);
    if (status == CT_SUCCESS) {
        knl_commit(session);
    } else {
        knl_rollback(session, NULL);
    }

    unlock_tables_directly(se);
    dc_close(&dc);
    return status;
}

status_t knl_lock_table_stats(knl_handle_t session, knl_dictionary_t *dc)
{
    knl_session_t *se = (knl_session_t *)session;
    dc_entity_t *entity = DC_ENTITY(dc);

    cm_latch_x(&entity->cbo_latch, se->id, NULL);

    if (entity->stats_locked) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "lock table statistics", "locked table");
        cm_unlatch(&entity->cbo_latch, NULL);
        return CT_ERROR;
    }

    status_t status = stats_set_analyze_time(session, dc, CT_TRUE);
    if (status == CT_SUCCESS) {
        knl_commit(session);
        entity->stats_locked = CT_TRUE;
    } else {
        knl_rollback(session, NULL);
    }

    cm_unlatch(&entity->cbo_latch, NULL);
    return status;
}

status_t knl_unlock_table_stats(knl_handle_t session, knl_dictionary_t *dc)
{
    knl_session_t *se = (knl_session_t *)session;
    dc_entity_t *entity = DC_ENTITY(dc);

    cm_latch_x(&entity->cbo_latch, se->id, NULL);

    if (!entity->stats_locked) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "unlock table statistics", "non-locked table");
        cm_unlatch(&entity->cbo_latch, NULL);
        return CT_SUCCESS;
    }

    status_t status = stats_set_analyze_time(session, dc, CT_FALSE);
    if (status == CT_SUCCESS) {
        knl_commit(session);
        entity->stats_locked = CT_FALSE;
    } else {
        knl_rollback(session, NULL);
    }

    cm_unlatch(&entity->cbo_latch, NULL);
    return status;
}

status_t knl_check_undo_space(knl_session_t *session, uint32 space_id)
{
    space_t *undo_space = SPACE_GET(session, space_id);
    undo_context_t *ctx = &session->kernel->undo_ctx;
    space_t *old_undo_space = SPACE_GET(session, ctx->space->ctrl->id);
    datafile_t *df = NULL;
    uint32 id;
    uint64 total_size = 0;

    if (undo_space->ctrl->type != SPACE_TYPE_UNDO) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "switch UNDO tablespace using non-undo tablespace");
        return CT_ERROR;
    }

    if (space_id == old_undo_space->ctrl->id) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ",switch the same undo tablespace");
        return CT_ERROR;
    }

    if (!SPACE_IS_ONLINE(undo_space)) {
        CT_THROW_ERROR(ERR_SPACE_OFFLINE, undo_space->ctrl->name, "can not be switched");
        return CT_ERROR;
    }

    for (uint32 i = 0; i < undo_space->ctrl->file_hwm; i++) {
        id = undo_space->ctrl->files[i];
        if (CT_INVALID_ID32 == id) {
            continue;
        }
        df = DATAFILE_GET(session, id);
        /* calculate space max size by maxsize with autoextend on or size with autoextend off of each datafile */
        if (DATAFILE_IS_AUTO_EXTEND(df)) {
            total_size += (uint64)df->ctrl->auto_extend_maxsize;
        } else {
            total_size += (uint64)df->ctrl->size;
        }
    }

    if (total_size <= UNDO_SEGMENT_COUNT(session) * UNDO_DEF_TXN_PAGE(session) * DEFAULT_PAGE_SIZE(session)) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", new undo tablespace size too small");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t knl_alter_switch_undo_space(knl_handle_t se, text_t *spc_name)
{
    knl_session_t *session = (knl_session_t *)se;
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);

    if (!DB_IS_PRIMARY(&session->kernel->db)) {
        CT_THROW_ERROR(ERR_DATABASE_ROLE, "operation", "not in primary mode");
        return CT_ERROR;
    }

    if (!DB_IS_RESTRICT(session)) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in restrict mode");
        return CT_ERROR;
    }

    if (core_ctrl->undo_segments_extended) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ",operation not supported after undo segments extend");
        return CT_ERROR;
    }

    if (undo_check_active_transaction(session)) {
        CT_THROW_ERROR(ERR_TXN_IN_PROGRESS, "end all transaction before action");
        return CT_ERROR;
    }

    uint32 space_id;
    if (spc_get_space_id(session, spc_name, CT_FALSE, &space_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_check_undo_space(session, space_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (undo_switch_space(session, space_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

#ifdef Z_SHARDING
status_t knl_get_consis_hash_buckets(knl_handle_t handle, knl_consis_hash_strategy_t *strategy, bool32 *is_found)
{
    lob_locator_t *lob = NULL;
    status_t status;
    knl_session_t *session = (knl_session_t *)handle;

    CM_SAVE_STACK(session->stack);
    do {
        knl_cursor_t *cursor = knl_push_cursor(session);
        status = db_query_consis_hash_strategy(session, &strategy->slice_cnt, &strategy->group_cnt, cursor, is_found);
        CT_BREAK_IF_ERROR(status);
        if (*is_found) {
            lob = (lob_locator_t *)CURSOR_COLUMN_DATA(cursor, SYS_CONSIS_HASH_STRATEGY_COL_BUCKETS);
            status = knl_read_lob(session, lob, 0, strategy->buckets.bytes, BUCKETDATALEN, NULL, NULL);
            CT_BREAK_IF_ERROR(status);
        }
    } while (0);

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}
#endif

static status_t knl_btree_corruption_scan(knl_session_t *session, btree_t *btree, knl_corrupt_info_t *info)
{
    btree_page_t *page = NULL;
    page_head_t *head = NULL;
    space_t *space = NULL;
    page_id_t next_ext;
    uint32 extent_size = 0;
    uint32 extents = 1;

    if (!IS_INVALID_PAGID(btree->entry)) {
        space = SPACE_GET(session, btree->segment->space_id);
        // No.0 extents can not degrade, here should calc, because the page have not been read
        extent_size = spc_get_ext_size(space, 0);
        buf_enter_page(session, btree->entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        head = (page_head_t *)CURR_PAGE(session);
        next_ext = AS_PAGID(head->next_ext);
        uint32 extent_count = btree->segment->extents.count;
        page_id_t last_pagid = (btree->segment->ufp_count > 0) ? btree->segment->ufp_first : btree->segment->ufp_extent;
        page_id_t curr_pagid = btree->segment->extents.first;
        buf_leave_page(session, CT_FALSE);

        for (;;) {
            if (IS_INVALID_PAGID(curr_pagid) || IS_SAME_PAGID(last_pagid, curr_pagid)) {
                break;
            }

            if (knl_check_session_status(session) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (buf_read_page(session, curr_pagid, LATCH_MODE_S, ENTER_PAGE_NORMAL | ENTER_PAGE_SEQUENTIAL) !=
                CT_SUCCESS) {
                errno_t err_code = cm_get_error_code();
                if (err_code == ERR_PAGE_CORRUPTED) {
                    db_save_corrupt_info(session, curr_pagid, info);
                }
                return CT_ERROR;
            }
            page = BTREE_CURR_PAGE(session);

            if (extent_size == 0) {
                extent_size = spc_get_page_ext_size(space, page->head.ext_size);
                next_ext = (extent_count == extents) ? INVALID_PAGID : AS_PAGID(page->head.next_ext);
                extents++;
            }

            extent_size--;

            buf_leave_page(session, CT_FALSE);

            if (extent_size == 0) {
                curr_pagid = next_ext;
            } else {
                curr_pagid.page++;
            }
        }
    }

    return CT_SUCCESS;
}

static status_t knl_index_verify(knl_session_t *session, knl_dictionary_t *dc, index_t *index, knl_corrupt_info_t *info)
{
    table_t *table = &DC_ENTITY(dc)->table;
    part_table_t *part_table = table->part_table;
    btree_t *btree = NULL;

    if (!IS_PART_INDEX(index)) {
        btree = &index->btree;
        return knl_btree_corruption_scan(session, btree, info);
    }

    for (uint32 i = 0; i < part_table->desc.partcnt; i++) {
        part_index_t *part_index = index->part_index;
        index_part_t *index_part = PART_GET_ENTITY(part_index, i);
        table_part_t *table_part = PART_GET_ENTITY(part_table, i);
        if (!IS_READY_PART(table_part) || index_part == NULL) {
            continue;
        }
        btree = &index_part->btree;
        if ((btree->segment == NULL) && !IS_INVALID_PAGID(btree->entry)) {
            if (dc_load_index_part_segment(session, dc->handle, index_part) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }

        if (knl_btree_corruption_scan(session, btree, info) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t knl_verify_index_by_name(knl_handle_t session, knl_dictionary_t *dc, text_t *index_name,
                                  knl_corrupt_info_t *info)
{
    knl_session_t *se = (knl_session_t *)session;
    index_t *index = NULL;
    bool32 lock_inuse = CT_FALSE;

    if (!lock_table_without_xact(se, dc->handle, &lock_inuse)) {
        return CT_ERROR;
    }

    if (DC_ENTITY(dc)->corrupted) {
        unlock_table_without_xact(se, dc->handle, lock_inuse);
        CT_THROW_ERROR(ERR_DC_CORRUPTED);
        return CT_ERROR;
    }

    index = dc_find_index_by_name(DC_ENTITY(dc), index_name);
    if (index == NULL) {
        unlock_table_without_xact(se, dc->handle, lock_inuse);
        CT_THROW_ERROR(ERR_INDEX_NOT_EXIST, DC_ENTITY(dc)->entry->user_name, T2S_EX(index_name));
        return CT_ERROR;
    }

    if (knl_index_verify(se, dc, index, info) != CT_SUCCESS) {
        unlock_table_without_xact(se, dc->handle, lock_inuse);
        return CT_ERROR;
    }

    unlock_table_without_xact(se, dc->handle, lock_inuse);

    return CT_SUCCESS;
}

status_t knl_verify_table(knl_handle_t session, knl_dictionary_t *dc, knl_corrupt_info_t *corrupt_info)
{
    bool32 lock_inuse = CT_FALSE;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = (table_t *)&entity->table;
    if (!lock_table_without_xact(session, entity, &lock_inuse)) {
        return CT_ERROR;
    }

    if (entity->corrupted) {
        unlock_table_without_xact(session, dc->handle, lock_inuse);
        CT_THROW_ERROR(ERR_DC_CORRUPTED);
        return CT_ERROR;
    }

    if (IS_PART_TABLE(table)) {
        if (part_table_corruption_verify((knl_session_t *)session, dc, corrupt_info)) {
            unlock_table_without_xact(session, dc->handle, lock_inuse);
            return CT_ERROR;
        }
    } else {
        if (heap_table_corruption_verify((knl_session_t *)session, dc, corrupt_info)) {
            unlock_table_without_xact(session, dc->handle, lock_inuse);
            return CT_ERROR;
        }
    }
    unlock_table_without_xact(session, dc->handle, lock_inuse);
    return CT_SUCCESS;
}

void dc_recycle_all(knl_handle_t session)
{
    knl_session_t *sess = (knl_session_t *)session;
    dc_context_t *ctx = &sess->kernel->dc_ctx;
    dc_lru_queue_t *queue = ctx->lru_queue;
    dc_entity_t *curr = NULL;
    dc_entity_t *head = NULL;
    dc_entity_t *prev = NULL;

    if (queue->count == 0) {
        return;
    }
    queue = ctx->lru_queue;
    cm_spin_lock(&queue->lock, NULL);

    if (queue->count == 0) {
        cm_spin_unlock(&queue->lock);
        return;
    }

    head = queue->head;
    curr = queue->tail;

    while (curr != NULL && curr != head) {
        prev = curr->lru_prev;
        if (!dc_try_recycle(ctx, queue, curr)) {
            dc_lru_shift(queue, curr);
        }
        curr = prev;
    }
    cm_spin_unlock(&queue->lock);
    return;
}

status_t knl_repair_catalog(knl_handle_t session)
{
    knl_session_t *se = (knl_session_t *)session;

    if (!DB_IS_MAINTENANCE(se)) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "repairing catalog with non-restrict or non-upgrade mode");
        return CT_ERROR;
    }

    if (knl_internal_repair_catalog(se) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t knl_database_has_nolog_object(knl_handle_t se, bool32 *has_nolog)
{
    *has_nolog = CT_FALSE;
    knl_session_t *session = (knl_session_t *)se;
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_INSTANCE_INFO_ID, IX_SYS_INSTANCE_INFO_001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    char name[] = "NOLOGOBJECT_CNT";
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, name, (uint16)strlen(name),
                     IX_COL_SYS_INSTANCE_INFO_001_NAME);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (!cursor->eof) {
        uint64 nolog_cnt = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_INSTANCE_INFO_COL_VALUE);
        if (nolog_cnt > 0) {
            *has_nolog = CT_TRUE;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

bool32 knl_chk_seq_entry(knl_handle_t session, knl_scn_t scn, uint32 uid, uint32 oid)
{
    dc_user_t *user = NULL;

    if (dc_open_user_by_id((knl_session_t*)session, uid, &user) != CT_SUCCESS) {
        cm_reset_error();
        return CT_FALSE;
    }

    if (!user->sequence_set.is_loaded) {
        return CT_FALSE;
    }

    sequence_entry_t *entry = DC_GET_SEQ_ENTRY(user, oid);
    if (entry == NULL || entry->is_free || !entry->used || entry->entity == NULL || entry->chg_scn != scn) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

bool32 knl_dbs_is_enable_dbs(void)
{
    return cm_dbs_is_enable_dbs();
}

status_t knl_db_open_dbstor_ns(knl_handle_t session)
{
    status_t status;
    SYNC_POINT_GLOBAL_START(CANTIAN_RST_OPEN_NAMESPACE_FAIL, &status, CT_ERROR);
    status = cm_dbs_open_all_ns();
    SYNC_POINT_GLOBAL_END;
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("failed to open dbstore namespace.");
        return CT_ERROR;
    }
    knl_session_t *se = (knl_session_t *)session;
    knl_instance_t *kernel = (knl_instance_t *)se->kernel;
    if (cm_dbs_iof_reg_all_ns(kernel->id) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("failed to iof reg dbstore namespace, inst id %u", kernel->id);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t knl_get_tableid(knl_handle_t handle, text_t *user_name, text_t *table_name, uint32 *tableid)
{
    knl_dictionary_t dc;
    knl_session_t *session = (knl_session_t *)handle;
    if (dc_open(session, user_name, table_name, &dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *tableid = dc.oid;
    dc_close(&dc);
    return CT_SUCCESS;
}

bool8 knl_is_llt_by_name(char first_char)
{
    if (temp_is_compative_mysql()) {
        return CT_FALSE;
    }

    return knl_is_llt_by_name2(first_char);
}

bool8 knl_is_llt_by_name2(char first_char)
{
    if (first_char == '#') {
        return CT_TRUE;
    }

    return CT_FALSE;
}

status_t knl_lock_table_self_parent_child_directly(knl_handle_t session, knl_dictionary_t *dc)
{
    knl_session_t *se = (knl_session_t *)session;

    uint32 timeout = se->kernel->attr.ddl_lock_timeout;
    if (lock_table_directly(se, dc, timeout) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("lock table fail");
        return CT_ERROR;
    }

    if (lock_parent_table_directly(se, dc->handle, CT_TRUE) != CT_SUCCESS) {
        unlock_tables_directly(se);
        CT_LOG_RUN_ERR("lock parent table fail");
        return CT_ERROR;
    }

    if (lock_child_table_directly(se, dc->handle, CT_TRUE) != CT_SUCCESS) {
        unlock_tables_directly(se);
        CT_LOG_RUN_ERR("lock child table fail");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void knl_alter_table_unlock_table(knl_handle_t session)
{
    knl_session_t *se = (knl_session_t *)session;
    unlock_tables_directly(se);
}

static status_t knl_check_table_is_dropped(knl_session_t *session, knl_dictionary_t *dc, bool32 *is_dropped)
{
    knl_cursor_t *cursor = NULL;
    *is_dropped = CT_FALSE;
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLE_ID, IX_SYS_TABLE_002_ID);

    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&dc->uid,
        sizeof(uint32), IX_COL_SYS_TABLE_002_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&dc->oid,
        sizeof(uint32), IX_COL_SYS_TABLE_002_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        CT_LOG_RUN_WAR("[For mysql] knl_fetch SYS_TABLE_ID failed when alter table %s commit",
            DC_TABLE(dc)->desc.name);
        *is_dropped = CT_TRUE;
        return CT_ERROR;
    }

    if (cursor->eof) {
        CT_LOG_RUN_INF("[For mysql copy] table %s is already been dropped, no need to invalidate dc when commit alter",
                       DC_TABLE(dc)->desc.name);
        *is_dropped = CT_TRUE;
    }
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

void knl_alter_table_invalidate_dc(knl_handle_t session, knl_dictionary_t *dc)
{
    knl_session_t *se = (knl_session_t *)session;
    if (dc_locked_by_self(se, ((dc_entity_t *)dc->handle)->entry)) {
        dc_invalidate_children(se, (dc_entity_t *)dc->handle);
        dc_invalidate_parents(se, (dc_entity_t *)dc->handle);
        bool32 is_dropped = CT_TRUE;
        if (knl_check_table_is_dropped (se, dc, &is_dropped) != CT_SUCCESS) {
            is_dropped = CT_TRUE;
            CT_LOG_RUN_WAR("[For mysql] skip segment statistic and flush %s.%s monitor statistic force,"
                "there might be some statitics loss",
                ((dc_entity_t *)dc->handle)->entry->user->desc.name, DC_TABLE(dc)->desc.name);
        }
        // if the table has already be dropped by mysql copy, do not update the SYS_MONITOR sys table
        dc_invalidate4mysql(se, (dc_entity_t *)dc->handle, !is_dropped);
    }
}

status_t knl_perform_create_index4mysql(knl_session_t *se,
                                        knl_handle_t stmt,
                                        knl_index_def_t *def,
                                        knl_dictionary_t *dc,
                                        bool32 is_lrep_log)
{
    knl_session_t *session = (knl_session_t *)se;

    if (knl_judge_index_exist(se, def, DC_ENTITY(dc)) && (def->options & CREATE_IF_NOT_EXISTS)) {
        return CT_SUCCESS;
    }
    if (def->online) {
        if (db_create_index_online(session, def, dc) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("create online index fail");
            return CT_ERROR;
        }
    } else {
        if (db_create_index(session, def, dc, CT_FALSE, NULL) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("create index fail");
            return CT_ERROR;
        }
    }
    status_t status = db_write_ddl_op_for_children(session, &((dc_entity_t*)dc->handle)->table);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("create index write ddl op fail");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t knl_perform_alter_index4mysql(knl_session_t *session,
                                       knl_handle_t stmt,
                                       knl_alindex_def_t *def,
                                       knl_dictionary_t *dc,
                                       bool32 is_lrep_log)
{
    status_t status;
    index_t *index = NULL;

    if (IS_AUTO_REBUILD(def->rebuild.lock_timeout)) {
        dc_entry_t *entry = DC_ENTRY(dc);
        if (entry != NULL && entry->sch_lock && entry->sch_lock->mode == LOCK_MODE_IX) {
            CT_THROW_ERROR(ERR_RESOURCE_BUSY);
            return CT_ERROR;
        }
    }
    index = dc_find_index_by_name(DC_ENTITY(dc), &def->name);
    if (index == NULL) {
        CT_THROW_ERROR(ERR_INDEX_NOT_EXIST, T2S(&def->user), T2S_EX(&def->name));
        CT_LOG_RUN_ERR("alter index not found");
        return CT_ERROR;
    }
    status = knl_alter_index_with_action(session, def, dc, index);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("alter index with action fail, action:%d", def->type);
        return status;
    }
    status = db_write_ddl_op_for_children(session, &((dc_entity_t*)dc->handle)->table);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("alter index write ddl op fail, action:%d", def->type);
        return status;
    }
    return status;
}

status_t knl_perform_drop_index4mysql(knl_session_t *session,
                                      knl_handle_t stmt,
                                      knl_drop_def_t *def,
                                      knl_dictionary_t *dc,
                                      bool32 is_lrep_log)

{
    index_t *index = NULL;
    knl_session_t *se = (knl_session_t *)session;

    index = dc_find_index_by_name(DC_ENTITY(dc), &def->name);
    if (index == NULL) {
        if (def->options & DROP_IF_EXISTS) {
            return CT_SUCCESS;
        }
        CT_THROW_ERROR(ERR_INDEX_NOT_EXIST, T2S(&def->owner), T2S_EX(&def->name));
        return CT_ERROR;
    }
    if (index->desc.is_enforced) {
        CT_THROW_ERROR(ERR_INDEX_ENFORCEMENT);
        return CT_ERROR;
    }
    if (db_drop_index(se, index, dc) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("drop index fail");
        return CT_ERROR;
    }
    status_t status = db_write_ddl_op_for_children(se, &((dc_entity_t*)dc->handle)->table);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("drop index write ddl op fail");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t knl_perform_alter_table4mysql_impl(knl_session_t *se,
                                            knl_handle_t stmt,
                                            knl_altable_def_t *def,
                                            knl_dictionary_t *dc,
                                            bool32 is_lrep_log)
{
    status_t status;
    trig_name_list_t trig;
    knl_session_t *session = (knl_session_t *)se;
    status = knl_altable_with_action(se, stmt, def, dc, &trig);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("alter table fail, action:%d", def->action);
        return status;
    }
    
    status = db_write_ddl_op_for_parents(session, &((dc_entity_t*)dc->handle)->table);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("alter table write ddl op parent fail, action:%d", def->action);
        return status;
    }
    
    status = db_write_ddl_op_for_children(session, &((dc_entity_t*)dc->handle)->table);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("alter table write ddl op children fail, action:%d", def->action);
        return status;
    }

    return status;
}

void knl_alter_table_log_put(knl_handle_t session, knl_handle_t stmt, knl_dictionary_t *dc, bool32 is_lrep_log)
{
    rd_table_t rd_altable;
    knl_session_t *se = (knl_session_t *)session;

    rd_altable.op_type = RD_ALTER_TABLE;
    rd_altable.uid = dc->uid;
    rd_altable.oid = dc->oid;
    log_put(se, RD_LOGIC_OPERATION, &rd_altable, sizeof(rd_table_t), LOG_ENTRY_FLAG_NONE);

    if (is_lrep_log) {
        table_t *table = DC_TABLE(dc);
        log_add_lrep_ddl_info(se, stmt, LOGIC_OP_TABLE, RD_ALTER_TABLE, table);
    }
}

void knl_rename_table_log_put(knl_handle_t session, knl_handle_t stmt, knl_dictionary_t *dc, knl_altable_def_t *def,
                              bool32 is_lrep_log)
{
    rd_rename_table_t rd_rename;
    knl_session_t *se = (knl_session_t *)session;

    rd_rename.op_type = RD_RENAME_TABLE;
    rd_rename.uid = dc->uid;
    rd_rename.oid = dc->oid;
    (void)cm_text2str(&def->table_def.new_name, rd_rename.new_name, CT_NAME_BUFFER_SIZE);
    log_put((knl_session_t *)se, RD_LOGIC_OPERATION, &rd_rename, sizeof(rd_rename_table_t), LOG_ENTRY_FLAG_NONE);

    if (is_lrep_log && !def->is_mysql_copy) {
        // for mysql copy, do not add_lrep_ddl_info here to avoid duplicate sql,
        // we only add one sql text in the step of drop table during mysql copy
        table_t *table = DC_TABLE(dc);
        log_add_lrep_ddl_info(se, stmt, LOGIC_OP_TABLE, RD_RENAME_TABLE, table);
    }
}

void knl_alter_table_after_commit4mysql(knl_handle_t session, knl_dictionary_t *dc)
{
    knl_session_t *se = (knl_session_t *)session;
    if (db_garbage_segment_handle(se, dc->uid, dc->oid, CT_FALSE) != CT_SUCCESS) {
        cm_spin_lock(&se->kernel->rmon_ctx.mark_mutex, NULL);
        se->kernel->rmon_ctx.delay_clean_segments = CT_TRUE;
        cm_spin_unlock(&se->kernel->rmon_ctx.mark_mutex);
        CT_LOG_RUN_ERR("failed to handle garbage segment");
    }
    se->stat->table_alters++;
    knl_alter_table_invalidate_dc(session, dc);
}

void knl_alter_table_commit(knl_handle_t session,
                            knl_handle_t stmt,
                            knl_dictionary_t *dc,
                            bool32 is_lrep_log)
{
    knl_alter_table_log_put(session, stmt, dc, is_lrep_log);
    knl_commit4mysql(session);
    knl_alter_table_after_commit4mysql(session, dc);
}

void knl_commit4mysql(knl_handle_t session)
{
    log_add_lrep_ddl_end(session);
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_TABLE_BEFORE_COMMIT_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    knl_commit(session);
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_TABLE_AFTER_COMMIT_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
}

void knl_rollback4mysql(knl_handle_t session)
{
    log_add_lrep_ddl_end(session);
    knl_rollback(session, NULL);
}

void knl_alter_table_rollback(knl_handle_t session, knl_dictionary_t *dc, bool32 is_lrep_log)
{
    log_add_lrep_ddl_end(session);
    knl_rollback(session, NULL);
    knl_alter_table_invalidate_dc(session, dc);
}

status_t knl_alter_table4mysql_alter_index(knl_session_t *session,
                                           knl_handle_t stmt,
                                           knl_altable_def_t *def,
                                           knl_dictionary_t *dc,
                                           bool32 is_lrep_log)
{
    status_t ret = CT_SUCCESS;

    if (def->index_def != NULL) {
        knl_index_def_t *index_def = (knl_index_def_t *)def->index_def;
        ret = knl_perform_create_index4mysql(session, stmt, index_def, dc, is_lrep_log);
    }
    if (def->alindex_def != NULL) {
        ret = knl_perform_alter_index4mysql(session, stmt, (knl_alindex_def_t *)def->alindex_def, dc, is_lrep_log);
    }

    if (def->drop_index_def != NULL) {
        ret = knl_perform_drop_index4mysql(session, stmt, (knl_drop_def_t *)def->drop_index_def, dc, is_lrep_log);
    }
    return ret;
}

bool32 knl_alter_table_is_add_hashpart(knl_dictionary_t *dc, knl_altable_def_t *def)
{
    table_t *table = DC_TABLE(dc);
    return def->action == ALTABLE_ADD_PARTITION && table->part_table->desc.parttype == PART_TYPE_HASH;
}

status_t knl_alter_table_update_dc(knl_handle_t se, knl_dictionary_t *dc)
{
    knl_session_t *session = (knl_session_t *)se;
    knl_dictionary_t new_dc;
    dc_invalidate(session, (dc_entity_t *)dc->handle);
    if (knl_open_dc_by_id(session, dc->uid, dc->oid, &new_dc, CT_TRUE) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[for mysql]alter table open dc fail, uid %u, oid %u", dc->uid, dc->oid);
        return CT_ERROR;
    }
    dc_close(dc);
    errno_t ret = memcpy_sp(dc, sizeof(knl_dictionary_t), &new_dc, sizeof(knl_dictionary_t));
    knl_securec_check(ret);
    return CT_SUCCESS;
}
status_t knl_perform_alter_table4mysql(knl_handle_t se, knl_handle_t stmt,
                                       knl_altable_def_t *def, knl_dictionary_t *dc, bool32 is_lrep_log)
{
    status_t ret = CT_SUCCESS;
    knl_session_t *session = (knl_session_t *)se;
    if (def->index_def != NULL || def->alindex_def != NULL || def->drop_index_def != NULL) {
        ret = knl_alter_table4mysql_alter_index(session, stmt, def, dc, is_lrep_log);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[For MySQL] alter table %s alter index fail", def->name.str);
        }
        return ret;
    }

    ret = knl_perform_alter_table4mysql_impl(session, stmt, def, dc, is_lrep_log);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[For MySQL] alter table %s fail", def->name.str);
    }
    if (ret == CT_SUCCESS && knl_meta_record(session, def, dc, DB_CURR_SCN(session)) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[For MySQL]: failed to maintain the meta data of table.");
        ret = CT_ERROR;
    }
    return ret;
}

bool32 knl_alter_table_is_coalesce_partition(knl_dictionary_t *dc, knl_altable_def_t *def)
{
    table_t *table = DC_TABLE(dc);
    return def->action == ALTABLE_COALESCE_PARTITION && table->part_table->desc.parttype == PART_TYPE_HASH;
}

void knl_alter_table_update_part_entry(knl_dictionary_t *old_dc, knl_dictionary_t *new_dc)
{
    table_t *table = DC_TABLE(old_dc);
    uint32 pcnt = table->part_table->desc.partcnt;
    table_t *new_table = DC_TABLE(new_dc);
    uint32 new_pcnt = new_table->part_table->desc.partcnt;
    uint32 min_pcnt = pcnt > new_pcnt ? new_pcnt : pcnt;
    uint32 i = 0;
    table_part_t *part = NULL;
    table_part_t *new_part = NULL;
    for (; i < min_pcnt; i++) {
        part = TABLE_GET_PART(table, i);
        new_part = TABLE_GET_PART(new_table, i);
        if ((IS_INVALID_PAGID(part->desc.entry)) && !IS_INVALID_PAGID(new_part->desc.entry)) {
            part->desc.entry = new_part->desc.entry;
            part->heap.entry = new_part->desc.entry;
            part->heap.loaded = CT_FALSE;
        }
    }
}

status_t knl_reopen_dc_in_alter_constraints(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *cur_def)
{
    text_t user_text = {0};
    text_t name_text = {0};
    dc_user_t *user = NULL;
    dc_entity_t *entity = (dc_entity_t *)dc->handle;
    if (cur_def->action == ALTABLE_ADD_CONSTRAINT) {
        if (dc_open_user_by_id(session, entity->table.desc.uid, &user)) {
            CT_LOG_RUN_ERR("[knl_reopen_dc_in_alter_constraints]:dc_open_user_by_id failed");
            return CT_ERROR;
        }
        cm_str2text(entity->table.desc.name, &name_text);
        cm_str2text(user->desc.name, &user_text);
        dc_invalidate(session, entity);
        knl_close_dc(dc);
        if (knl_open_dc(session, &user_text, &name_text, dc)) {
            CT_LOG_RUN_ERR("[knl_reopen_dc_in_alter_constraints]:knl_open_dc failed");
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t knl_alter_single_action(knl_session_t *session, knl_handle_t stmt, knl_altable_def_t *cur_def,
                                 knl_dictionary_t *dc, bool32 is_lrep_log, bool32 *contain_hash_part)
{
    knl_dictionary_t new_dc;
    status_t ret = CT_SUCCESS;
    do {
        ret = dc_open_table_private(session, dc->uid, dc->oid, &new_dc);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[knl_alter_single_action]: dc_open_table_private failed");
            break;
        }
        if (cur_def->action == ALTABLE_TRUNCATE_PARTITION || cur_def->action == ALTABLE_TRUNCATE_SUBPARTITION) {
            dc_load_all_part_segments(session, new_dc.handle);
        }
        ret = knl_perform_alter_table4mysql(session, stmt, cur_def, &new_dc, is_lrep_log);
        *contain_hash_part = *contain_hash_part ? *contain_hash_part : knl_alter_table_is_add_hashpart(dc, cur_def);
        if (knl_alter_table_is_coalesce_partition(dc, cur_def)) {
            knl_alter_table_update_part_entry(dc, &new_dc);
        }
        dc_close_table_private(&new_dc);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[knl_alter_single_action]: dc_close_table_private failed");
            break;
        }
    } while (0);
    if (knl_reopen_dc_in_alter_constraints(session, dc, cur_def) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[knl_alter_single_action]: knl_reopen_dc_in_alter_constraints failed");
        log_add_lrep_ddl_end(session);
        return CT_ERROR;
    }
    if (ret != CT_SUCCESS) {
        log_add_lrep_ddl_end(session);
    }
    return ret;
}

status_t knl_alter_table4mysql(knl_handle_t se, knl_handle_t stmt,
                               knl_altable_def_t *def, uint32 def_count, knl_dictionary_t *dc, bool32 is_lrep_log)
{
    CT_LOG_RUN_INF("[for mysql] Start to alter table %s for mysql", def->name.str);
    knl_session_t *session = (knl_session_t *)se;
    uint32 count = 0;
    knl_altable_def_t *cur_def = NULL;
    status_t ret = CT_SUCCESS;
    bool32 contain_hash_part = CT_FALSE;
    
    if (knl_altable_check_table_type(session, def, dc) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[for mysql]alter table %s type %d", def->name.str, dc->type);
        return CT_ERROR;
    }
    log_add_lrep_ddl_begin(session);
    if (def->action == ALTABLE_ADD_COLUMN && def->contains_vircol) {
        CT_RETURN_IFERR(db_altable_drop_logical_log(session, dc, def));
    }
    for (; count < def_count; count++) {
        cur_def = &def[count];
        ret = knl_alter_single_action(session, stmt, cur_def, dc, is_lrep_log, &contain_hash_part);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[for mysql]alter table %s fail, count:%u", def->name.str, count);
            break;
        }
    }
    if (contain_hash_part && knl_alter_table_update_dc(session, dc) != CT_SUCCESS) {
        if (ret == CT_SUCCESS) {
            log_add_lrep_ddl_end(session);
        }
        return CT_ERROR;
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_ALTER_TABLE_RETURN_ERROR, &ret, CT_ERROR);
    SYNC_POINT_GLOBAL_END;
    CT_LOG_RUN_INF("[for mysql]alter table %s, ret:%d", def->name.str, ret);
    return ret;
}

bool32 is_sys_col_ref(knl_cursor_t *cursor)
{
    return *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_CONSDEF_COL_CONS_TYPE) == CONS_TYPE_REFERENCE;
}

bool32 is_sys_fk(knl_cursor_t *cursor, uint32_t ref_uid, uint32_t ref_oid)
{
    return *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_CONSDEF_COL_CONS_TYPE) == CONS_TYPE_REFERENCE &&
           *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_CONSDEF_COL_REF_USER_ID) == ref_uid &&
           *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_CONSDEF_COL_REF_TABLE_ID) == ref_oid;
}

bool32 is_fetch_success(knl_handle_t se, knl_cursor_t *cursor)
{
    knl_session_t *knl_session = (knl_session_t *)se;
    return knl_fetch(knl_session, cursor) == CT_SUCCESS;
}

status_t knl_fill_fk_name_from_sys4mysql(knl_handle_t se, char *fk_name, uint32_t ref_uid,
                                         uint32_t ref_oid, knl_dictionary_t *dc)
{
    knl_session_t *knl_session = (knl_session_t *)se;
    knl_cursor_t *cursor = NULL;
    CM_SAVE_STACK(knl_session->stack);
    cursor = knl_push_cursor(knl_session);

    dc_entity_t *entity = (dc_entity_t *)dc->handle;

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_SELECT, SYS_CONSDEF_ID, IX_SYS_CONSDEF001_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &(entity->table.desc.uid),
                     sizeof(uint32), IX_COL_SYS_CONSDEF001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &(entity->table.desc.id),
                     sizeof(uint32), IX_COL_SYS_CONSDEF001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &(entity->table.desc.uid),
                     sizeof(uint32), IX_COL_SYS_CONSDEF001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &(entity->table.desc.id),
                     sizeof(uint32), IX_COL_SYS_CONSDEF001_TABLE_ID);

    if (knl_fetch(knl_session, cursor) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[tse_fill_fk_name_from_sys]: knl_fetch failed.");
        CM_RESTORE_STACK(knl_session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        if (is_sys_fk(cursor, ref_uid, ref_oid)) {
            knl_securec_check(memcpy_s(fk_name, CT_NAME_BUFFER_SIZE,
                                       CURSOR_COLUMN_DATA(cursor, SYS_CONSDEF_COL_CONS_NAME), CT_NAME_BUFFER_SIZE));
        }

        if (!is_fetch_success(knl_session, cursor)) {
            break;
        }
    }

    CM_RESTORE_STACK(knl_session->stack);
    return CT_SUCCESS;
}

static void fill_update_ref_info4mysql(knl_cursor_t *cursor, knl_dictionary_t *new_dc)
{
    row_assist_t ra;
    uint32_t new_uid = new_dc->uid;
    uint32_t new_oid = new_dc->oid;
    row_init(&ra, cursor->update_info.data, CT_MAX_ROW_SIZE, UPDATE_COLUMN_COUNT_TWO);
    (void)row_put_int32(&ra, new_uid);
    (void)row_put_int32(&ra, new_oid);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_TWO;
    cursor->update_info.columns[0] = SYS_CONSDEF_COL_REF_USER_ID;
    cursor->update_info.columns[1] = SYS_CONSDEF_COL_REF_TABLE_ID;
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);
}

status_t knl_update_ref_syscons4mysql(knl_handle_t se, knl_dictionary_t *old_dc, knl_dictionary_t *new_dc)
{
    knl_session_t *session = (knl_session_t *)se;
    uint32_t old_uid = old_dc->uid;
    uint32_t old_oid = old_dc->oid;
    CT_LOG_RUN_INF("[for mysql] Start to update ref_syscons for mysql, from uid:%u oid:%u to uid:%u oid:%u",
                   old_uid, old_oid, new_dc->uid, new_dc->oid);
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_CONSDEF_ID, IX_SYS_CONSDEF002_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &old_uid, sizeof(uint32),
                     IX_COL_SYS_CONSDEF002_REF_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &old_oid, sizeof(uint32),
                     IX_COL_SYS_CONSDEF002_REF_TABLE_ID);
    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    while (!cursor->eof) {
        if (is_sys_col_ref(cursor)) {
            fill_update_ref_info4mysql(cursor, new_dc);
            if (knl_internal_update(session, cursor) != CT_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return CT_ERROR;
            }
        } else {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
        if (!is_fetch_success(session, cursor)) {
            CT_LOG_RUN_ERR("[for mysql]Failed to fetch cursor in update sys table.");
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }
    CM_RESTORE_STACK(session->stack);
    CT_LOG_RUN_INF("[for mysql] Success to update ref_syscons for mysql");
    return CT_SUCCESS;
}

static void fill_update_comment_info4mysql(knl_handle_t session, knl_cursor_t *cursor, knl_dictionary_t *new_dc)
{
    row_assist_t ra;
    uint32_t new_uid = new_dc->uid;
    uint32_t new_oid = new_dc->oid;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_TWO);
    (void)row_put_int32(&ra, new_uid);
    (void)row_put_int32(&ra, new_oid);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_TWO;
    cursor->update_info.columns[0] = COMMENT_USER_COLUMN_ID;
    cursor->update_info.columns[1] = COMMENT_TABLE_COLUMN_ID;
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);
}

status_t knl_update_comment4mysql(knl_handle_t se, knl_dictionary_t *old_dc, knl_dictionary_t *new_dc)
{
    knl_session_t *session = (knl_session_t *)se;
    uint32_t old_uid = old_dc->uid;
    uint32_t old_oid = old_dc->oid;
    dc_entity_t *entity = (dc_entity_t *)old_dc->handle;
    CT_LOG_RUN_INF("[for mysql] Start to update sys_comment for mysql, from uid:%u oid:%u to uid:%u oid:%u",
                   old_uid, old_oid, new_dc->uid, new_dc->oid);

    for (int i = 0; i < entity->column_count; i++) {
        CM_SAVE_STACK(session->stack);
        knl_cursor_t *cursor = knl_push_cursor(session);
        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_COMMENT_ID, IX_SYS_COMMENT001_ID);
        knl_init_index_scan(cursor, CT_TRUE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &old_uid, sizeof(uint32),
                     COMMENT_USER_COLUMN_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &old_oid, sizeof(uint32),
                     COMMENT_TABLE_COLUMN_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &i,
                             sizeof(uint32), COMMENT_COLUMN_COLUMN_ID);
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
                    CM_RESTORE_STACK(session->stack);
                    CT_LOG_RUN_ERR("[for mysql]fail to fetch data when updating syscomment.");
                    return CT_ERROR;
        }

        if (!cursor->eof) {
            fill_update_comment_info4mysql(session, cursor, new_dc);
            if (knl_internal_update(session, cursor) != CT_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                CT_LOG_RUN_ERR("[for mysql]knl_internal_update failed when updating syscomment.");
                return CT_ERROR;
            }
        }
        CM_RESTORE_STACK(session->stack);
    
    }

    CT_LOG_RUN_INF("[for mysql] Success to update sys_comments for mysql");
    return CT_SUCCESS;
}

static bool32 knl_upgrade_ctrl_core_version_precheck(knl_session_t *session,  ctrl_version_t version)
{
    if (db_cur_ctrl_version_is_higher(session, version)) {
        CT_LOG_RUN_ERR("[UPGARDE] current version is higher than %hu-%hu-%hu-%hu",
                       version.main, version.major, version.revision, version.inner);
        return CT_FALSE;
    }
    if (db_equal_to_cur_ctrl_version(session, version)) {
        CT_LOG_RUN_WAR("[UPGARDE] current version is equal to %hu-%hu-%hu-%hu, retry to upgrade",
                       version.main, version.major, version.revision, version.inner);
    }
    return CT_TRUE;
}

status_t knl_set_ctrl_core_version(void *item_ptr)
{
    ctrl_version_t *version = (ctrl_version_t *)item_ptr;
    knl_session_t *session = NULL;

    if (g_knl_callback.alloc_knl_session(CT_TRUE, (knl_handle_t *)&session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CT_LOG_RUN_INF("[UPGARDE] Start to update cantian version to %hu-%hu-%hu-%hu",
                   version->main, version->major, version->revision, version->inner);
    status_t status = CT_SUCCESS;
    // add ddl latch, because ddl operations may change and save core ctrl
    SYNC_POINT_GLOBAL_START(CANTIAN_UPGRADE_CTRL_VERSION_LOCK_DDL_FAIL, &status, CT_ERROR);
    status = knl_ddl_latch_x(session, NULL);
    SYNC_POINT_GLOBAL_END;
    CT_LOG_RUN_INF("[UPGARDE] Finish ddl latch x in knl_set_ctrl_core_version");
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[UPGARDE] Update cantian version lock ddl fail");
        g_knl_callback.release_knl_session(session);
        return CT_ERROR;
    }
    // step 1: upgrade version in memory
    if (!knl_upgrade_ctrl_core_version_precheck(session, *version)) {
        knl_ddl_unlatch_x(session);
        g_knl_callback.release_knl_session(session);
        return CT_ERROR;
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_UPGRADE_CTRL_VERSION_BEFORE_WRITE_DISK_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    DB_CORE_CTRL(session)->version = *version;
    // step 2: upgrade version in ctrlfile
    SYNC_POINT_GLOBAL_START(CANTIAN_UPGRADE_CTRL_VERSION_WRITE_DISK_FAIL, &status, CT_ERROR);
    status = db_save_core_ctrl(session);
    SYNC_POINT_GLOBAL_END;
    SYNC_POINT_GLOBAL_START(CANTIAN_UPGRADE_CTRL_VERSION_AFTER_WRITE_DISK_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    if (status != CT_SUCCESS) {
        knl_ddl_unlatch_x(session);
        g_knl_callback.release_knl_session(session);
        CM_ABORT(0, "[UPGARDE] ABORT INFO: save core control version failed when upgrade version to %hu-%hu-%hu-%hu",
                 version->main, version->major, version->revision, version->inner);
    }
    // step 3: sync to other nodes, like dtc_sync_ddl, upgrade their version in memory
    if (DB_IS_CLUSTER(session)) {
        status = dtc_sync_upgrade_ctrl_version(session);
    }
    knl_ddl_unlatch_x(session);
    CT_LOG_RUN_INF("[UPGARDE] Finish to update cantian version to %hu-%hu-%hu-%hu, ret: %d",
                   version->main, version->major, version->revision, version->inner, status);

    g_knl_callback.release_knl_session(session);
    return status;
}

status_t knl_schema_exists4mysql(knl_handle_t session, text_t *schema_name, bool32 *exist)
{
    CT_LOG_RUN_INF("[DB] Start to check schema %s exist", T2S_EX(schema_name));
    knl_session_t *se = (knl_session_t *)session;
    drlatch_t *ddl_latch = &se->kernel->db.ddl_latch;
    uint32 uid;
    *exist = CT_FALSE;

    if (knl_ddl_latch_s(ddl_latch, session, NULL) != CT_SUCCESS) {
        *exist = CT_FALSE;
        return CT_ERROR;
    }

    if (dc_get_user_id(se, schema_name, &uid)) {
        *exist = CT_TRUE;
    } else {
        *exist = CT_FALSE;
    }

    dls_unlatch(session, ddl_latch, NULL);

    CT_LOG_RUN_INF("[DB] Finish to check schema %s exist, existence %d", T2S_EX(schema_name), *exist);
    return CT_SUCCESS;
}

status_t knl_object_exists4mysql(knl_handle_t session, text_t *schema_name, text_t *object_name, bool32 *exist)
{
    knl_session_t *se = (knl_session_t *)session;
    dc_user_t *user = NULL;
    knl_dict_type_t obj_type;
 
    if (dc_open_user(se, schema_name, &user) != CT_SUCCESS) {
        *exist = CT_FALSE;
        return CT_SUCCESS;
    }
    dls_latch_s(se, &user->user_latch, se->id, CT_FALSE, NULL);
    if (dc_object_exists(se, schema_name, object_name, &obj_type)) {
        *exist = CT_TRUE;
    } else {
        *exist = CT_FALSE;
    }

    dls_unlatch(se, &user->user_latch, NULL);
    return CT_SUCCESS;
}

status_t knl_is_daac_cluster_ready(bool32 *is_ready)
{
    cms_res_status_list_t res_stat;
    if (cms_get_res_stat_list(&res_stat) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("knl_is_daac_cluster_ready get res stat list failed");
        return CT_ERROR;
    }
    uint16_t i = g_instance->id;
    if (res_stat.inst_list[i].stat != CMS_RES_ONLINE ||
            res_stat.inst_list[i].work_stat != RC_JOINED) {
        *is_ready = CT_FALSE;
        return CT_SUCCESS;
    }
    *is_ready = CT_TRUE;
    return CT_SUCCESS;
}

void knl_set_db_status_4mysql_init(bool32 open)
{
    //Do not set readonly = false here in standby, it may cause to write ckpt unexpectedlly.
    if (g_instance->kernel.db.open_status != DB_OPEN_STATUS_MAX_FIX) {
        return;
    }
    g_instance->kernel.db.is_readonly = open;
}

uint8 knl_get_initrans(void)
{
    return g_instance->kernel.attr.initrans;
}

// set initialization status
void knl_set_sql_server_initializing_status(knl_handle_t session, bool32 status)
{
    ((knl_session_t *)session)->kernel->is_sql_server_initializing = status;
}

void knl_lock_info_log_put4mysql(knl_handle_t session, void *lock_info)
{
    knl_session_t *se = (knl_session_t *)session;
    rd_lock_info_4mysql_ddl *info = (rd_lock_info_4mysql_ddl *)lock_info;
    uint32 total_buf_len = info->db_name_len + info->table_name_len;
    log_put(se, RD_LOGIC_OPERATION, lock_info, sizeof(rd_lock_info_4mysql_ddl), LOG_ENTRY_FLAG_NONE);
    log_append_data(se, info->buff, total_buf_len);
    if (info->op_type == RD_UNLOCK_TABLE_FOR_MYSQL_DDL) {
        tx_copy_logic_log(se);
        se->logic_log_size = 0;
    }
}

void knl_invalid_dd_log_put4mysql(knl_handle_t session, void *invalid_info)
{
    knl_session_t *se = (knl_session_t *)session;
    rd_invalid_dd_4mysql_ddl *info = (rd_invalid_dd_4mysql_ddl*)invalid_info;
    log_put(se, RD_LOGIC_OPERATION, invalid_info, sizeof(rd_invalid_dd_4mysql_ddl), LOG_ENTRY_FLAG_NONE);
    log_append_data(se, info->buff, info->buff_len);
}

#ifdef __cplusplus
}
#endif
