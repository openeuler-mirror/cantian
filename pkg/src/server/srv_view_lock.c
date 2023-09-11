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
 * srv_view_lock.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_view_lock.c
 *
 * -------------------------------------------------------------------------
 */

#include "srv_view_lock.h"
#include "srv_instance.h"
#include "knl_alck.h"
#include "dtc_database.h"
#include "dtc_dls.h"
#include "dtc_drc.h"

static knl_column_t g_lock_columns[] = {
    { 0, "SID",   0, 0, GS_TYPE_INTEGER, sizeof(uint32),        0, 0, GS_FALSE, 0, { 0 } },
    { 1, "TYPE",  0, 0, GS_TYPE_VARCHAR, GS_DYNVIEW_NORMAL_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 2, "ID1",   0, 0, GS_TYPE_BIGINT,  sizeof(uint64),        0, 0, GS_FALSE, 0, { 0 } },
    { 3, "ID2",   0, 0, GS_TYPE_BIGINT,  sizeof(uint64),        0, 0, GS_FALSE, 0, { 0 } },
    { 4, "LMODE", 0, 0, GS_TYPE_VARCHAR, GS_DYNVIEW_NORMAL_LEN, 0, 0, GS_TRUE,  0, { 0 } },
    { 5, "BLOCK", 0, 0, GS_TYPE_INTEGER, sizeof(uint32),        0, 0, GS_FALSE, 0, { 0 } },
    { 6, "RMID",  0, 0, GS_TYPE_INTEGER, sizeof(uint32),        0, 0, GS_FALSE, 0, { 0 } },
};

static knl_column_t g_spin_lock_columns[] = {
    { 0, "SID",    0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 1, "TYPE",   0, 0, GS_TYPE_VARCHAR, 128,            0, 0, GS_FALSE, 0, { 0 } },
    { 2, "SPINS",  0, 0, GS_TYPE_BIGINT,  sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 } },
    { 3, "SLEEPS", 0, 0, GS_TYPE_BIGINT,  sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 } },
    { 4, "FAILS",  0, 0, GS_TYPE_BIGINT,  sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 } },
};

#define LOCK_VALUE_LMODE_NAME 10

static knl_column_t g_locked_object_columns[] = {
    { 0, "SESSION_ID",     0, 0, GS_TYPE_INTEGER, sizeof(uint32),           0, 0, GS_FALSE, 0, { 0 } },
    { 1, "XIDUSN",         0, 0, GS_TYPE_INTEGER, sizeof(uint32),           0, 0, GS_FALSE, 0, { 0 } },
    { 2, "XIDSLOT",        0, 0, GS_TYPE_INTEGER, sizeof(uint32),           0, 0, GS_FALSE, 0, { 0 } },
    { 3, "XIDSQN",         0, 0, GS_TYPE_INTEGER, sizeof(uint32),           0, 0, GS_FALSE, 0, { 0 } },
    { 4, "USER_NAME",      0, 0, GS_TYPE_CHAR,    GS_NAME_BUFFER_SIZE,      0, 0, GS_TRUE,  0, { 0 } },
    { 5, "OBJECT_ID",      0, 0, GS_TYPE_INTEGER, sizeof(uint32),           0, 0, GS_FALSE, 0, { 0 } },
    { 6, "OBJECT_NAME",    0, 0, GS_TYPE_CHAR,    GS_NAME_BUFFER_SIZE,      0, 0, GS_TRUE,  0, { 0 } },
    { 7, "CLIENT_OS_NAME", 0, 0, GS_TYPE_CHAR,    GS_HOST_NAME_BUFFER_SIZE, 0, 0, GS_FALSE, 0, { 0 } },
    { 8, "CLIENT_PROGREM", 0, 0, GS_TYPE_CHAR,    GS_FILE_NAME_BUFFER_SIZE, 0, 0, GS_FALSE, 0, { 0 } },
    { 9, "LMODE",          0, 0, GS_TYPE_CHAR,    LOCK_VALUE_LMODE_NAME,    0, 0, GS_TRUE,  0, { 0 } },
};

static knl_column_t g_sess_alocks[] = {
    { 0, "SID",        0, 0, GS_TYPE_INTEGER, sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
    { 1, "LOCK_NAME",  0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 2, "LOCK_TIMES", 0, 0, GS_TYPE_UINT32,  sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
    { 3, "LOCK_SCN",   0, 0, GS_TYPE_INTEGER, sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
};

static knl_column_t g_sess_shared_alocks[] = {
    { 0, "LOCK_NAME",          0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 1, "SID",                0, 0, GS_TYPE_INTEGER, sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
    { 2, "TOTAL_LOCKED_TIMES", 0, 0, GS_TYPE_UINT32,  sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
};

static knl_column_t g_xact_alocks[] = {
    { 0, "SID",        0, 0, GS_TYPE_INTEGER, sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
    { 1, "SERIAL#",    0, 0, GS_TYPE_INTEGER, sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
    { 2, "LOCK_NAME",  0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 3, "LOCK_TIMES", 0, 0, GS_TYPE_UINT32,  sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
};

static knl_column_t g_xact_shared_alocks[] = {
    { 0, "LOCK_NAME",          0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 1, "SID",                0, 0, GS_TYPE_INTEGER, sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
    { 2, "TOTAL_LOCKED_TIMES", 0, 0, GS_TYPE_UINT32,  sizeof(uint32),  0, 0, GS_FALSE, 0, { 0 } },
};

static knl_column_t g_user_alocks[] = {
    { 0, "NAME",        0, 0, GS_TYPE_VARCHAR, GS_MAX_ALCK_USER_NAME_LEN,   0, 0, GS_FALSE, 0, { 0 } },
    { 1, "TYPE",        0, 0, GS_TYPE_VARCHAR, 2,                           0, 0, GS_FALSE, 0, { 0 } },
    { 2, "X_LOCKS",     0, 0, GS_TYPE_UINT32,  sizeof(uint32),              0, 0, GS_FALSE, 0, { 0 } },
    { 3, "MY_LOCKS",    0, 0, GS_TYPE_UINT32,  sizeof(uint32),              0, 0, GS_FALSE, 0, { 0 } },
    { 4, "TOTAL_LOCKS", 0, 0, GS_TYPE_UINT32,  sizeof(uint32),              0, 0, GS_FALSE, 0, { 0 } },
    { 5, "IX_SETTED",   0, 0, GS_TYPE_UINT32,  sizeof(uint32),              0, 0, GS_FALSE, 0, { 0 } },
    { 6, "LOCK_MODE",   0, 0, GS_TYPE_VARCHAR, GS_MAX_ALCK_MODE_STATUS_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 7, "IX_MAP",      0, 0, GS_TYPE_VARCHAR, GS_MAX_ALCK_IX_MAP_LEN,      0, 0, GS_TRUE,  0, { 0 } },
};

static knl_column_t g_all_alocks[] = {
    { 0, "NAME",        0, 0, GS_TYPE_VARCHAR, GS_MAX_ALCK_USER_NAME_LEN,   0, 0, GS_FALSE, 0, { 0 } },
    { 1, "TYPE",        0, 0, GS_TYPE_VARCHAR, 2,                           0, 0, GS_FALSE, 0, { 0 } },
    { 2, "X_LOCKS",     0, 0, GS_TYPE_UINT32,  sizeof(uint32),              0, 0, GS_FALSE, 0, { 0 } },
    { 3, "TOTAL_LOCKS", 0, 0, GS_TYPE_UINT32,  sizeof(uint32),              0, 0, GS_FALSE, 0, { 0 } },
    { 4, "IX_SETTED",   0, 0, GS_TYPE_UINT32,  sizeof(uint32),              0, 0, GS_FALSE, 0, { 0 } },
    { 5, "LOCK_DETAIL", 0, 0, GS_TYPE_VARCHAR, GS_MAX_COLUMN_SIZE,          0, 0, GS_FALSE, 0, { 0 } },
    { 6, "LOCK_MODE",   0, 0, GS_TYPE_VARCHAR, GS_MAX_ALCK_MODE_STATUS_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 7, "IX_MAP",      0, 0, GS_TYPE_VARCHAR, GS_MAX_ALCK_IX_MAP_LEN,      0, 0, GS_TRUE,  0, { 0 } },
};

static knl_column_t g_dls_lock_columns[] = {
    { 0, "IDX", 0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 1, "DRID_TYPE", 0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 2, "DRID_UID", 0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 3, "DRID_ID", 0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 4, "DRID_IDX", 0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 5, "DRID_PART", 0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 6, "DRID_SUBPART", 0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 7, "MODE", 0, 0, GS_TYPE_VARCHAR, GS_DYNVIEW_NORMAL_LEN, 0, 0, GS_FALSE, 0, { 0 } },
    { 8, "PART_ID", 0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 9, "GRANTED_MAP", 0, 0, GS_TYPE_BIGINT, sizeof(uint64), 0, 0, GS_FALSE, 0, { 0 } },
    { 10, "CONVERTQ_LEN", 0, 0, GS_TYPE_UINT32, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 11, "CONVERTING", 0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
};

#define LOCK_COLS (ELEMENT_COUNT(g_lock_columns))
#define SPINLOCK_COLS (ELEMENT_COUNT(g_spin_lock_columns))
#define LOCKED_OBJECT_COLS (ELEMENT_COUNT(g_locked_object_columns))
#define SESS_ALOCKS (ELEMENT_COUNT(g_sess_alocks))
#define SESS_SHARED_ALOCKS (ELEMENT_COUNT(g_sess_shared_alocks))
#define XACT_ALOCKS (ELEMENT_COUNT(g_xact_alocks))
#define XACT_SHARED_ALOCKS (ELEMENT_COUNT(g_xact_shared_alocks))
#define ALL_ALOCKS (ELEMENT_COUNT(g_all_alocks))
#define USER_ALOCKS (ELEMENT_COUNT(g_user_alocks))
#define DLSLOCK_COLS (ELEMENT_COUNT(g_dls_lock_columns))

static void vw_lock_put_row(knl_handle_t session, lock_item_t *item, row_assist_t *ra, dc_entry_t *entry, uint16 sid)
{
    page_id_t page_id;
    uint16 rmid = item->rmid;
    (void)row_put_int32(ra, (int32)sid);
    (void)row_put_str(ra, lock_type_string(item->type));
    knl_session_t *ss = (knl_session_t *)session;
    if (item->type == LOCK_TYPE_TS || item->type == LOCK_TYPE_TX) {
        entry = item->dc_entry;
        if (entry != NULL) {
            (void)row_put_int64(ra, (int64)entry->uid);
            (void)row_put_int64(ra, (int64)entry->id);
            (void)row_put_str(ra, lock_mode_string(entry));
        } else {
            (void)row_put_int64(ra, GS_INVALID_INT64);
            (void)row_put_int64(ra, GS_INVALID_INT64);
            (void)row_put_null(ra);
        }
        if (entry == NULL || sid == GS_INVALID_ID16) {
            (void)row_put_int32(ra, GS_INVALID_INT32);
        } else {
            (void)row_put_int32(ra,
                (int32)(dc_locked_by_self(ss->kernel->sessions[sid], entry) ? 1 : 0));
        }
    } else {
        page_id = MAKE_PAGID(item->file, item->page);
        (void)row_put_int64(ra, *(int64 *)&page_id);
        (void)row_put_int64(ra, (int64)item->itl);
        (void)row_put_null(ra);
        (void)row_put_int32(ra, (int32)(1));
    }
    (void)row_put_int32(ra, (int32)rmid);
}

static status_t vw_lock_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    row_assist_t ra;
    uint16 sid;
    dc_entry_t *entry = NULL;
    knl_rm_t *rm = NULL;
    uint16 rmid;
    knl_session_t *ss = (knl_session_t *)session;
    if (cur->rowid.vmid >= ss->kernel->lock_ctx.hwm) {
        cur->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    lock_item_t *item = lock_addr(&ss->kernel->lock_ctx, (uint32)cur->rowid.vmid);
    rmid = item->rmid;
    sid = knl_get_rm_sid(session, rmid);

    while (item->type == LOCK_TYPE_FREE || item->type >= LOCK_TYPE_ALCK_TS || sid == GS_INVALID_ID16 ||
        item->dc_entry == NULL) {
        if (rmid != GS_INVALID_ID16) {
            rm = ss->kernel->rms[rmid];
        }

        if (rm != NULL && item->type != LOCK_TYPE_FREE && item->dc_entry != NULL && knl_xa_xid_valid(&rm->xa_xid)) {
            break;
        }

        cur->rowid.vmid++;
        if (cur->rowid.vmid >= ss->kernel->lock_ctx.hwm) {
            cur->eof = GS_TRUE;
            return GS_SUCCESS;
        }

        item = lock_addr(&ss->kernel->lock_ctx, (uint32)cur->rowid.vmid);
        rmid = item->rmid;
        rm = NULL;
        sid = knl_get_rm_sid(session, rmid);
    }

    row_init(&ra, (char *)cur->row, ss->kernel->attr.max_row_size, LOCK_COLS);
    vw_lock_put_row(session, item, &ra, entry, sid);
    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);

    cur->rowid.vmid++;
    return GS_SUCCESS;
}

typedef enum en_spin_type {
    SPIN_TXN = 0,
    SPIN_TXN_LIST,
    SPIN_INC_SCN,
    SPIN_SERI_COMMIT,
    SPIN_REDO_BUF,
    SPIN_COMMIT_QUEUE,
    SPIN_CKPT_QUEUE,
    SPIN_BUFFER,
    SPIN_BUCKET,
    SPIN_SPACE,
    SPIN_DC_ENTRY,
    SPIN_LOG_FLUSH,
    SPIN_SCH_LOCK,
    SPIN_CKPT,
    SPIN_PCR_POOL,
    SPIN_PCR_BUCKET,

    /* * must be the last one */
    SPIN_TYPE_COUNT
} spin_type_t;

typedef struct spin_mgr {
    spin_type_t type;
    const char *name;
} spin_mgr_t;

static spin_mgr_t g_spin_mgrs[] = {
    { SPIN_TXN,          "TXN" },
    { SPIN_TXN_LIST,     "TXN_LIST" },
    { SPIN_INC_SCN,      "INC_SCN" },
    { SPIN_SERI_COMMIT,  "SERIALIZED_COMMIT" },
    { SPIN_REDO_BUF,     "REDO_BUFFER" },
    { SPIN_COMMIT_QUEUE, "COMMIT_QUEUE" },
    { SPIN_CKPT_QUEUE,   "CKPT_QUEUE" },
    { SPIN_BUFFER,       "BUFFER" },
    { SPIN_BUCKET,       "BUCKET" },
    { SPIN_SPACE,        "SPACE" },
    { SPIN_DC_ENTRY,     "DC_ENTRY" },
    { SPIN_LOG_FLUSH,    "LOG_FLUSH" },
    { SPIN_SCH_LOCK,     "SCH_LOCK" },
    { SPIN_CKPT,         "CKPT" },
    { SPIN_PCR_POOL,    "PCR_POOL"},
    { SPIN_PCR_BUCKET,  "PCR_BUCKET"},
};

static spin_statis_t *vw_get_spin_info(knl_session_t *session, spin_type_t type)
{
    switch (type) {
        case SPIN_TXN:
            return &session->stat->spin_stat.stat_txn;
        case SPIN_TXN_LIST:
            return &session->stat->spin_stat.stat_txn_list;
        case SPIN_INC_SCN:
            return &session->stat->spin_stat.stat_inc_scn;
        case SPIN_SERI_COMMIT:
            return &session->stat->spin_stat.stat_seri_commit;
        case SPIN_REDO_BUF:
            return &session->stat->spin_stat.stat_redo_buf;
        case SPIN_COMMIT_QUEUE:
            return &session->stat->spin_stat.stat_commit_queue;
        case SPIN_CKPT_QUEUE:
            return &session->stat->spin_stat.stat_ckpt_queue;
        case SPIN_BUFFER:
            return &session->stat->spin_stat.stat_buffer;
        case SPIN_BUCKET:
            return &session->stat->spin_stat.stat_bucket;
        case SPIN_SPACE:
            return &session->stat->spin_stat.stat_space;
        case SPIN_DC_ENTRY:
            return &session->stat->spin_stat.stat_dc_entry;
        case SPIN_LOG_FLUSH:
            return &session->stat->spin_stat.stat_log_flush;
        case SPIN_SCH_LOCK:
            return &session->stat->spin_stat.stat_sch_lock;
        case SPIN_CKPT:
            return &session->stat->spin_stat.stat_ckpt;
        case SPIN_PCR_POOL:
            return &session->stat->spin_stat.stat_pcr_pool;
        case SPIN_PCR_BUCKET:
            return &session->stat->spin_stat.stat_pcr_bucket;
        case SPIN_TYPE_COUNT:
        default:
            return NULL;
    }
}

static status_t vw_spin_lock_fetch_core(knl_handle_t handle, knl_cursor_t *cur)
{
    session_t *item = NULL;
    knl_session_t *session = NULL;
    spin_statis_t *stat = NULL;
    row_assist_t ra;

    while (1) {
        if (cur->rowid.vmid >= g_instance->session_pool.hwm) {
            cur->eof = GS_TRUE;
            return GS_SUCCESS;
        }

        item = g_instance->session_pool.sessions[cur->rowid.vmid];
        if (!item->is_free) {
            break;
        }

        cur->rowid.vmid++;
    }

    session = &item->knl_session;
    stat = vw_get_spin_info(session, g_spin_mgrs[cur->rowid.vm_slot].type);
    GS_RETURN_IFERR(stat == NULL);

    cur->tenant_id = item->curr_tenant_id;
    row_init(&ra, (char *)cur->row, GS_MAX_ROW_SIZE, SPINLOCK_COLS);
    GS_RETURN_IFERR(row_put_int32(&ra, (int32)session->id));
    GS_RETURN_IFERR(row_put_str(&ra, g_spin_mgrs[cur->rowid.vm_slot].name));
    GS_RETURN_IFERR(row_put_int64(&ra, (int64)stat->spins));
    GS_RETURN_IFERR(row_put_int64(&ra, (int64)stat->wait_usecs));
    GS_RETURN_IFERR(row_put_int64(&ra, (int64)stat->fails));

    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);
    cur->rowid.vm_slot++;

    if (cur->rowid.vm_slot == SPIN_TYPE_COUNT) {
        cur->rowid.vmid++;
        cur->rowid.vm_slot = 0;
    }

    return GS_SUCCESS;
}

static status_t vw_spin_lock_fetch(knl_handle_t handle, knl_cursor_t *cur)
{
    return vw_fetch_for_tenant(vw_spin_lock_fetch_core, handle, cur);
}

static status_t vw_locked_object_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    knl_session_t *sess = (knl_session_t *)session;
    lock_area_t *area = &sess->kernel->lock_ctx;
    lock_item_t item;
    row_assist_t ra;
    uint16 sid;

    if (cur->rowid.vmid >= area->hwm) {
        cur->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    item = *lock_addr(area, (uint32)cur->rowid.vmid);
    sid = knl_get_rm_sid(session, item.rmid);

    while ((item.type != LOCK_TYPE_TS && item.type != LOCK_TYPE_TX) || sid == GS_INVALID_ID16 ||
        item.dc_entry == NULL) {
        cur->rowid.vmid++;
        if (cur->rowid.vmid >= area->hwm) {
            cur->eof = GS_TRUE;
            return GS_SUCCESS;
        }

        item = *lock_addr(area, (uint32)cur->rowid.vmid);
        sid = knl_get_rm_sid(session, item.rmid);
    }

    session_t *se = g_instance->session_pool.sessions[sid];
    row_init(&ra, (char *)cur->row,
             sess->kernel->attr.max_row_size, LOCKED_OBJECT_COLS);
    (void)row_put_int32(&ra, (int32)sid);
    (void)row_put_int32(&ra, (int32)se->knl_session.rm->xid.xmap.seg_id);
    (void)row_put_int32(&ra, (int32)se->knl_session.rm->xid.xmap.slot);
    (void)row_put_int32(&ra, (int32)se->knl_session.rm->xid.xnum);

    if (item.dc_entry == NULL) {
        (void)row_put_null(&ra);
        (void)row_put_int32(&ra, GS_INVALID_INT32);
        (void)row_put_null(&ra);
        (void)row_put_str(&ra, se->os_host); // CLIENT_OS_NAME
        (void)row_put_str(&ra, se->os_prog); // ClIENT_PROCESS
        (void)row_put_null(&ra);
    } else {
        (void)row_put_str(&ra, item.dc_entry->user->desc.name);
        (void)row_put_int32(&ra, (int32)item.dc_entry->id);
        (void)row_put_str(&ra, item.dc_entry->name);
        (void)row_put_str(&ra, se->os_host); // CLIENT_OS_NAME
        (void)row_put_str(&ra, se->os_prog); // ClIENT_PROCESS
        (void)row_put_str(&ra, lock_mode_string(item.dc_entry));
    }

    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);

    cur->rowid.vmid++;
    return GS_SUCCESS;
}

static status_t vw_sess_alocks_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    row_assist_t ra;
    alck_item_pool_t *pool = &((knl_session_t *)session)->kernel->alck_ctx.se_ctx.item_pool;
    alck_map_pool_t *map_pool = &((knl_session_t *)session)->kernel->alck_ctx.se_ctx.map_pool;
    alck_item_t *alck_item;
    while (1) {
        if (cur->rowid.vmid >= pool->count) {
            cur->eof = GS_TRUE;
            return GS_SUCCESS;
        }

        alck_item = ALCK_ITEM_PTR(pool, (uint32)cur->rowid.vmid);
        while (alck_item->lock_mode != ALCK_MODE_X || alck_item->x_times == 0) {
            cur->rowid.vmid++;
            if (cur->rowid.vmid >= pool->count) {
                cur->eof = GS_TRUE;
                return GS_SUCCESS;
            }

            alck_item = ALCK_ITEM_PTR(pool, (uint32)cur->rowid.vmid);
        }
        cm_spin_lock(&alck_item->lock, NULL);
        if (alck_item->lock_mode != ALCK_MODE_X || alck_item->x_times == 0) {
            cm_spin_unlock(&alck_item->lock);
            cur->rowid.vmid++;
        } else {
            break;
        }
    }

    row_init(&ra, (char *)cur->row, ((knl_session_t *)session)->kernel->attr.max_row_size, SESS_ALOCKS);
    (void)row_put_int32(&ra, (int32)alck_item->x_map_id);
    (void)row_put_str(&ra, alck_item->name);
    (void)row_put_int32(&ra, alck_get_locks(map_pool, alck_item, alck_item->x_map_id));
    (void)row_put_int32(&ra, alck_item->sn);
    cm_spin_unlock(&alck_item->lock);

    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);

    cur->rowid.vmid++;
    return GS_SUCCESS;
}

static bool8 vw_shared_lock_loop(knl_cursor_t *cur, alck_item_pool_t *pool)
{
    while (1) {
        if (cur->rowid.vmid >= pool->count) {
            cur->eof = GS_TRUE;
            return GS_FALSE;
        }
        
        alck_item_t *alck_item = ALCK_ITEM_PTR(pool, (uint32)cur->rowid.vmid);
        while (alck_item->lock_mode != ALCK_MODE_S || alck_item->lock_times == 0) {
            cur->rowid.vmid++;
            if (cur->rowid.vmid >= pool->count) {
                cur->eof = GS_TRUE;
                return GS_FALSE;
            }

            alck_item = ALCK_ITEM_PTR(pool, (uint32)cur->rowid.vmid);
        }

        cm_spin_lock(&alck_item->lock, NULL);
        if (alck_item->lock_mode != ALCK_MODE_S || alck_item->lock_times == 0) {
            cm_spin_unlock(&alck_item->lock);
            cur->rowid.vmid++;
            continue;
        }
        return GS_TRUE;
    }
}

static status_t vw_sess_shared_alocks_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    row_assist_t ra;
    alck_item_pool_t *pool = &((knl_session_t *)session)->kernel->alck_ctx.se_ctx.item_pool;

    bool8 is_continue = vw_shared_lock_loop(cur, pool);
    if (is_continue == GS_FALSE) {
        return GS_SUCCESS;
    }

    alck_item_t *alck_item = ALCK_ITEM_PTR(pool, (uint32)cur->rowid.vmid);
    row_init(&ra, (char *)cur->row, ((knl_session_t *)session)->kernel->attr.max_row_size, SESS_SHARED_ALOCKS);
    (void)row_put_str(&ra, alck_item->name);
    (void)row_put_int32(&ra, 0);
    (void)row_put_int32(&ra, alck_item->lock_times);
    cm_spin_unlock(&alck_item->lock);

    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);

    cur->rowid.vmid++;
    return GS_SUCCESS;
}

static status_t vw_xact_locks_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    row_assist_t ra;
    alck_item_pool_t *pool = &((knl_session_t *)session)->kernel->alck_ctx.tx_ctx.item_pool;
    alck_item_t *alck_item;
    uint16 sid;
    while (1) {
        if (cur->rowid.vmid >= pool->count) {
            cur->eof = GS_TRUE;
            return GS_SUCCESS;
        }

        alck_item = ALCK_ITEM_PTR(pool, (uint32)cur->rowid.vmid);
        while (alck_item->lock_mode != ALCK_MODE_X || alck_item->x_times == 0) {
            cur->rowid.vmid++;
            if (cur->rowid.vmid >= pool->count) {
                cur->eof = GS_TRUE;
                return GS_SUCCESS;
            }

            alck_item = ALCK_ITEM_PTR(pool, (uint32)cur->rowid.vmid);
        }
        cm_spin_lock(&alck_item->lock, NULL);
        sid = knl_get_rm_sid(session, alck_item->x_map_id);
        if (alck_item->lock_mode != ALCK_MODE_X || alck_item->x_times == 0 || sid == GS_INVALID_ID16) {
            cm_spin_unlock(&alck_item->lock);
            cur->rowid.vmid++;
        } else {
            break;
        }
    }

    row_init(&ra, (char *)cur->row, ((knl_session_t *)session)->kernel->attr.max_row_size, XACT_ALOCKS);
    (void)row_put_int32(&ra, (int32)sid);
    (void)row_put_int32(&ra, alck_item->sn);
    (void)row_put_str(&ra, alck_item->name);
    (void)row_put_int32(&ra, alck_item->lock_times);

    cm_spin_unlock(&alck_item->lock);

    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);

    cur->rowid.vmid++;
    return GS_SUCCESS;
}

static status_t vw_xact_shared_locks_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    row_assist_t ra;
    alck_item_pool_t *pool = &((knl_session_t *)session)->kernel->alck_ctx.tx_ctx.item_pool;
    bool8 is_continue = vw_shared_lock_loop(cur, pool);
    if (is_continue == GS_FALSE) {
        return GS_SUCCESS;
    }

    alck_item_t *alck_item = ALCK_ITEM_PTR(pool, (uint32)cur->rowid.vmid);

    row_init(&ra, (char *)cur->row,
             ((knl_session_t *)session)->kernel->attr.max_row_size, XACT_SHARED_ALOCKS);

    (void)row_put_str(&ra, alck_item->name);
    (void)row_put_int32(&ra, 0);
    (void)row_put_int32(&ra, alck_item->lock_times);

    cm_spin_unlock(&alck_item->lock);

    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);

    cur->rowid.vmid++;
    return GS_SUCCESS;
}

static status_t vw_alocks_open(knl_handle_t session, knl_cursor_t *cur)
{
    cur->rowid.vmid = 0;
    cur->rowid.vm_slot = 0;
    cur->rowid.vm_tag = 0;
    vw_alocks_assist_t *assist = (vw_alocks_assist_t *)cur->page_buf;
    assist->se_pool_itemcnts = ((knl_session_t *)session)->kernel->alck_ctx.se_ctx.item_pool.count;
    assist->tx_pool_itemcnts = ((knl_session_t *)session)->kernel->alck_ctx.tx_ctx.item_pool.count;
    return GS_SUCCESS;
}

static status_t vm_format_alck_se_detail(knl_handle_t session, alck_map_pool_t *map_pool, alck_item_t *alck_item,
    text_buf_t *txt_buf)
{
    uint32 map_id = alck_item->first_map;
    alck_map_t *alck_map = NULL;
    while (map_id != GS_INVALID_ID32) {
        alck_map = ALCK_MAP_PTR(map_pool, map_id);
        if (!cm_buf_append_fmt(txt_buf, "%u:%u ", alck_map->idx, alck_map->count)) {
            GS_RETURN_IFERR(cm_concat_string((text_t *)txt_buf, txt_buf->max_size, "..."));
            return GS_SUCCESS;
        }
        map_id = alck_map->next;
    }
    return GS_SUCCESS;
}

static status_t vm_format_alck_tx_detail(knl_handle_t session, alck_map_pool_t *map_pool, alck_item_t *alck_item,
    text_buf_t *txt_buf)
{
    uint32 map_id = alck_item->first_map;
    alck_map_t *alck_map = NULL;
    while (map_id != GS_INVALID_ID32) {
        alck_map = ALCK_MAP_PTR(map_pool, map_id);
        if (!cm_buf_append_fmt(txt_buf, "%u(%u):%u ", alck_map->idx, knl_get_rm_sid(session, alck_map->idx),
            alck_map->count)) {
            GS_RETURN_IFERR(cm_concat_string((text_t *)txt_buf, txt_buf->max_size, "..."));
            return GS_SUCCESS;
        }
        map_id = alck_map->next;
    }
    return GS_SUCCESS;
}

static status_t vm_format_alck_detail(knl_handle_t session, alck_map_pool_t *map_pool, alck_item_t *alck_item,
    text_buf_t *txt_buf, alck_lock_set_t lock_set)
{
    if (lock_set == SE_LOCK) {
        return vm_format_alck_se_detail(session, map_pool, alck_item, txt_buf);
    } else if (lock_set == TX_LOCK) {
        return vm_format_alck_tx_detail(session, map_pool, alck_item, txt_buf);
    }
    return GS_SUCCESS;
}

static char *vw_get_alck_mode(uint32 lock_mode)
{
    switch (lock_mode) {
        case ALCK_MODE_IDLE:
            return "IDLE";
        case ALCK_MODE_IX:
            return "IX";
        case ALCK_MODE_S:
            return "S";
        case ALCK_MODE_X:
            return "X";
        default:
            return "";
    }
}

static status_t vw_alocks_rowput_ix_map(row_assist_t *ra, knl_handle_t session, alck_item_t *alck_item,
    alck_lock_set_t lock_set)
{
    char buffer[GS_MAX_ALCK_IX_MAP_LEN + 1];
    buffer[0] = '\0';
    if (alck_item->lock_mode != ALCK_MODE_IX) {
        return row_put_str(ra, "");
    }
    if (lock_set == SE_LOCK) {
        PRTS_RETURN_IFERR(sprintf_s(buffer, GS_MAX_ALCK_IX_MAP_LEN + 1, "%u", alck_item->ix_map_id));
    } else if (lock_set == TX_LOCK) {
        PRTS_RETURN_IFERR(sprintf_s(buffer, GS_MAX_ALCK_IX_MAP_LEN + 1, "%u(%u)", alck_item->ix_map_id,
            knl_get_rm_sid(session, alck_item->ix_map_id)));
    }
    return row_put_str(ra, buffer);
}

static status_t vw_all_alocks_rowput(knl_handle_t session, knl_cursor_t *cur, alck_ctx_spec_t *ctx,
    alck_item_t *alck_item)
{
    row_assist_t ra;
    sql_stmt_t *stmt = ((session_t *)session)->current_stmt;
    text_buf_t lock_detail;

    SQL_SAVE_STACK(stmt);
    GS_RETURN_IFERR(sql_push_textbuf(stmt, GS_MAX_COLUMN_SIZE, &lock_detail));
    lock_detail.max_size -= ALCK_TEXTBUF_APPEND_RESERVE;
    if (vm_format_alck_detail(session, &ctx->map_pool, alck_item, &lock_detail, ctx->lock_set) != GS_SUCCESS) {
        SQL_RESTORE_STACK(stmt);
        return GS_ERROR;
    }
    row_init(&ra, (char *)cur->row, ((knl_session_t *)session)->kernel->attr.max_row_size, ALL_ALOCKS);
    (void)row_put_str(&ra, alck_item->name);
    if (ctx->lock_set == SE_LOCK) {
        (void)row_put_str(&ra, "SE");
    } else {
        (void)row_put_str(&ra, "TX");
    }
    uint32 ix_setted = (alck_item->lock_mode == ALCK_MODE_IX) ? 1 : 0;
    (void)row_put_uint32(&ra, alck_item->x_times);
    (void)row_put_uint32(&ra, alck_item->lock_times);
    (void)row_put_uint32(&ra, ix_setted);
    (void)row_put_text(&ra, &lock_detail.value);
    (void)row_put_str(&ra, vw_get_alck_mode(alck_item->lock_mode));
    (void)vw_alocks_rowput_ix_map(&ra, session, alck_item, ctx->lock_set);
    SQL_RESTORE_STACK(stmt);
    return GS_SUCCESS;
}

static status_t vw_all_alocks_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    alck_ctx_spec_t *ctx = NULL;
    alck_item_pool_t *pool = NULL;
    alck_item_t *alck_item = NULL;
    vw_alocks_assist_t *assist = (vw_alocks_assist_t *)cur->page_buf;
    status_t status;
    uint32 se_pool_count = assist->se_pool_itemcnts;
    uint32 tx_pool_count = assist->tx_pool_itemcnts;

    do {
        if (cur->rowid.vmid >= se_pool_count + tx_pool_count) {
            cur->eof = GS_TRUE;
            return GS_SUCCESS;
        } else if (cur->rowid.vmid >= tx_pool_count) {
            ctx = &((knl_session_t *)session)->kernel->alck_ctx.se_ctx;
            pool = &ctx->item_pool;
            alck_item = ALCK_ITEM_PTR(pool, (uint32)cur->rowid.vmid - tx_pool_count);
        } else {
            ctx = &((knl_session_t *)session)->kernel->alck_ctx.tx_ctx;
            pool = &ctx->item_pool;
            alck_item = ALCK_ITEM_PTR(pool, (uint32)cur->rowid.vmid);
        }
        if (alck_item->lock_times == 0 || alck_item->lock_mode == ALCK_MODE_IDLE) {
            cur->rowid.vmid++;
            continue;
        }

        cm_spin_lock(&alck_item->lock, NULL);
        if (alck_item->lock_times == 0 || alck_item->lock_mode == ALCK_MODE_IDLE) {
            cm_spin_unlock(&alck_item->lock);
            cur->rowid.vmid++;
            continue;
        }
        break;
    } while (GS_TRUE);

    status = vw_all_alocks_rowput(session, cur, ctx, alck_item);
    cm_spin_unlock(&alck_item->lock);
    GS_RETURN_IFERR(status);
    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);
    cur->rowid.vmid++;
    return GS_SUCCESS;
}

static void vw_user_alck_row_put(knl_handle_t session, knl_cursor_t *cur, alck_ctx_spec_t *ctx,
    alck_item_t *alck_item, alck_map_t *map)
{
    row_assist_t ra;
    row_init(&ra, (char *)cur->row, ((knl_session_t *)session)->kernel->attr.max_row_size, USER_ALOCKS);
    (void)row_put_str(&ra, alck_item->name);
    if (ctx->lock_set == SE_LOCK) {
        (void)row_put_str(&ra, "SE");
    } else {
        (void)row_put_str(&ra, "TX");
    }
    uint32 ix_setted = (alck_item->lock_mode == ALCK_MODE_IX) ? 1 : 0;
    (void)row_put_uint32(&ra, alck_item->x_times);
    (void)row_put_uint32(&ra, map->count);
    (void)row_put_uint32(&ra, alck_item->lock_times);
    (void)row_put_uint32(&ra, ix_setted);
    (void)row_put_str(&ra, vw_get_alck_mode(alck_item->lock_mode));
    (void)vw_alocks_rowput_ix_map(&ra, session, alck_item, ctx->lock_set);
    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);
}

static status_t vw_user_alocks_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    alck_ctx_spec_t *ctx = NULL;
    alck_item_pool_t *pool = NULL;
    alck_map_pool_t *map_pool = NULL;
    alck_item_t *alck_item = NULL;
    vw_alocks_assist_t *assist = (vw_alocks_assist_t *)cur->page_buf;
    uint32 se_pool_count = assist->se_pool_itemcnts;
    uint32 tx_pool_count = assist->tx_pool_itemcnts;
    knl_session_t *knl_sess = (knl_session_t *)session;
    uint32 match_idx;
    alck_map_t *map = NULL;

    do {
        if (cur->rowid.vmid >= se_pool_count + tx_pool_count) {
            cur->eof = GS_TRUE;
            return GS_SUCCESS;
        } else if (cur->rowid.vmid >= tx_pool_count) {
            ctx = &knl_sess->kernel->alck_ctx.se_ctx;
            pool = &ctx->item_pool;
            alck_item = ALCK_ITEM_PTR(pool, (uint32)cur->rowid.vmid - tx_pool_count);
            match_idx = knl_sess->id;
        } else {
            ctx = &knl_sess->kernel->alck_ctx.tx_ctx;
            pool = &ctx->item_pool;
            alck_item = ALCK_ITEM_PTR(pool, (uint32)cur->rowid.vmid);
            match_idx = knl_sess->rmid;
        }
        map_pool = &ctx->map_pool;
        if (alck_item->lock_times == 0 || alck_item->lock_mode == ALCK_MODE_IDLE) {
            cur->rowid.vmid++;
            continue;
        }

        cm_spin_lock(&alck_item->lock, NULL);
        if (alck_item->lock_times == 0 || alck_item->lock_mode == ALCK_MODE_IDLE ||
            (alck_item->lock_mode == ALCK_MODE_X && alck_item->x_map_id != match_idx)) {
            cm_spin_unlock(&alck_item->lock);
            cur->rowid.vmid++;
            continue;
        }

        map = alck_get_map(map_pool, alck_item, match_idx);
        if (map == NULL) {
            cm_spin_unlock(&alck_item->lock);
            cur->rowid.vmid++;
            continue;
        }
        break;
    } while (GS_TRUE);

    vw_user_alck_row_put(session, cur, ctx, alck_item, map);
    cm_spin_unlock(&alck_item->lock);
    cur->rowid.vmid++;
    return GS_SUCCESS;
}

static status_t get_lock_resource_view(row_assist_t *ra, drc_master_res_t *lock_res)
{
    GS_RETURN_IFERR(row_put_uint32(ra, (uint32)lock_res->idx));
    GS_RETURN_IFERR(row_put_uint32(ra, (uint32)lock_res->res_id.type));
    GS_RETURN_IFERR(row_put_uint32(ra, (uint32)lock_res->res_id.uid));
    GS_RETURN_IFERR(row_put_uint32(ra, (uint32)lock_res->res_id.id));
    GS_RETURN_IFERR(row_put_uint32(ra, (uint32)lock_res->res_id.idx));
    GS_RETURN_IFERR(row_put_uint32(ra, (uint32)lock_res->res_id.part));
    GS_RETURN_IFERR(row_put_uint32(ra, (uint32)lock_res->res_id.subpart));
    GS_RETURN_IFERR(row_put_str(ra, drc_get_lock_mode_str(lock_res)));
    GS_RETURN_IFERR(row_put_int32(ra, (int32)lock_res->part_id));
    GS_RETURN_IFERR(row_put_int64(ra, (int64)lock_res->granted_map));
    GS_RETURN_IFERR(row_put_uint32(ra, (uint32)lock_res->convert_q.count));
    GS_RETURN_IFERR(row_put_int32(ra, (int32)lock_res->converting.req_info.inst_id));
    return GS_SUCCESS;
}

static status_t vw_dls_lock_fetch(knl_handle_t handle, knl_cursor_t *cur)
{
    row_assist_t ra;
    drc_list_t *part_list = NULL;
    drc_master_res_t *lock_res = NULL;
    uint64 index;
    uint32 i, lock_idx;

    if (cur->rowid.vm_slot >= DRC_MAX_PART_NUM) {
        cur->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    drc_get_global_lock_res_parts(cur->rowid.vm_slot, &part_list);
    while (part_list->count == 0 && cur->rowid.vm_slot < DRC_MAX_PART_NUM) {
        cur->rowid.vm_slot++;
        cur->rowid.vmid = 0;
        drc_get_global_lock_res_parts(cur->rowid.vm_slot, &part_list);
    }

    if (cur->rowid.vm_slot >= DRC_MAX_PART_NUM) {
        cur->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    drc_lock_remaster_mngr();
    index = cur->rowid.vmid;
    lock_idx = part_list->first;
    for (i = 0; i < part_list->count; i++) {
        lock_res = drc_get_global_lock_resx_by_id(lock_idx);
        if (index == 0) {
            break;
        } else {
            index--;
            lock_idx = lock_res->node.next;
        }
    }
    drc_unlock_remaster_mngr();

    row_init(&ra, (char *)cur->row, GS_MAX_ROW_SIZE, DLSLOCK_COLS);
    status_t ret = get_lock_resource_view(&ra, lock_res);
    if (ret != GS_SUCCESS) {
        return ret;
    }
    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);
    cur->rowid.vmid++;

    if (i == part_list->count - 1) {
        cur->rowid.vm_slot++;
        cur->rowid.vmid = 0;
    }

    return GS_SUCCESS;
}

VW_DECL dv_lock = { "SYS", "DV_LOCKS", LOCK_COLS, g_lock_columns, vw_common_open, vw_lock_fetch };
VW_DECL dv_spinlock = { "SYS", "DV_SPINLOCKS", SPINLOCK_COLS, g_spin_lock_columns, vw_common_open, vw_spin_lock_fetch };
VW_DECL dv_locked_object = { "SYS",          "DV_LOCKED_OBJECTS",   LOCKED_OBJECT_COLS, g_locked_object_columns,
                             vw_common_open, vw_locked_object_fetch };
VW_DECL dv_sess_alocks = { "SYS",         "DV_USER_ADVISORY_LOCKS", SESS_ALOCKS,
                           g_sess_alocks, vw_common_open,           vw_sess_alocks_fetch };
VW_DECL dv_sess_shared_alocks = { "SYS",          "DV_SESSION_SHARED_LOCKS",  SESS_SHARED_ALOCKS, g_sess_shared_alocks,
                                  vw_common_open, vw_sess_shared_alocks_fetch };
VW_DECL dv_xact_alocks = { "SYS", "DV_XACT_LOCKS", XACT_ALOCKS, g_xact_alocks, vw_common_open, vw_xact_locks_fetch };
VW_DECL dv_xact_shared_alocks = { "SYS",          "DV_XACT_SHARED_LOCKS",    XACT_SHARED_ALOCKS, g_xact_shared_alocks,
                                  vw_common_open, vw_xact_shared_locks_fetch };
VW_DECL dv_user_alocks = { "SYS", "DV_USER_ALOCKS", USER_ALOCKS, g_user_alocks, vw_alocks_open, vw_user_alocks_fetch };
VW_DECL dv_all_alocks = { "SYS", "DV_ALL_ALOCKS", ALL_ALOCKS, g_all_alocks, vw_alocks_open, vw_all_alocks_fetch };
VW_DECL dv_dlslock = { "SYS", "DV_DLSLOCKS", DLSLOCK_COLS, g_dls_lock_columns, vw_common_open, vw_dls_lock_fetch };

dynview_desc_t *vw_describe_lock(uint32 id)
{
    switch ((dynview_id_t)id) {
        case DYN_VIEW_LOCK:
            return &dv_lock;

        case DYN_VIEW_LOCKED_OBJECT:
            return &dv_locked_object;

        case DYN_VIEW_SPINLOCK:
            return &dv_spinlock;

        case DYN_VIEW_SESS_ALOCK:
            return &dv_sess_alocks;

        case DYN_VIEW_SESS_SHARED_ALOCK:
            return &dv_sess_shared_alocks;

        case DYN_VIEW_XACT_ALOCK:
            return &dv_xact_alocks;

        case DYN_VIEW_XACT_SHARED_ALOCK:
            return &dv_xact_shared_alocks;

        case DYN_VIEW_ALL_ALOCK:
            return &dv_all_alocks;

        case DYN_VIEW_USER_ALOCK:
            return &dv_user_alocks;

        case DYN_VIEW_DLSLOCK:
            return &dv_dlslock;

        default:
            return NULL;
    }
}
