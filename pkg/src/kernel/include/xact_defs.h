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
 * xact_defs.h
 *
 *
 * IDENTIFICATION
 * src/kernel/include/xact_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_XACT_DEFS_H__
#define __KNL_XACT_DEFS_H__

#include "knl_defs.h"

#ifdef __cplusplus
extern "C" {
#endif
    
#define KNL_XA_DEFAULT       0x0000
#define KNL_XA_NEW           0x0001
#define KNL_XA_NOMIGRATE     0x0002
#define KNL_XA_SUSPEND       0x0004
#define KNL_XA_RESUME        0x0010
#define KNL_XA_ONEPHASE      0x0020
#define KNL_XA_LGWR_BATCH    0x0040
#define KNL_XA_LGWR_IMMED    0x0080
#define KNL_XA_LGWR_WAIT     0x0100
#define KNL_XA_LGWR_NOWAIT   0x0200

#define KNL_XA_XID_DATA_OFFSET ((uint64)((xa_xid_t *)0)->data)
#define KNL_XA_XID_LEN(xid) ((uint64)(((xa_xid_t *)0)->data) + (xid)->gtrid_len + (xid)->bqual_len)
#define KNL_MAX_XA_XID_LEN (10 + CT_MAX_XA_BASE16_GTRID_LEN + CT_MAX_XA_BASE16_BQUAL_LEN)
#define KNL_IS_INVALID_ROWID(rowid) ((rowid).file == INVALID_FILE_ID && (rowid).page == 0 && (rowid).slot == 0)
#define KNL_IS_INVALID_SCN(scn)  ((scn) == 0)
    
typedef enum en_isolation_level {
    ISOLATION_READ_COMMITTED = 1,  // read committed isolation level(default)
    ISOLATION_CURR_COMMITTED = 2,  // current committed isolation level(internal)
    ISOLATION_SERIALIZABLE = 3,    // serializable isolation level
} isolation_level_t;

typedef enum en_xact_status {
    XACT_END = 0,
    XACT_BEGIN = 1,
    XACT_PHASE1 = 2, /* xa prepare */
    XACT_PHASE2 = 3, /* xa rollback */
} xact_status_t;

typedef struct st_xa_xid {
    uint64  fmt_id;
    uint8   gtrid_len;
    uint8   bqual_len;
    char    data[1];
} xa_xid_t;

#pragma pack(4)
typedef struct st_knl_xa_xid {
    uint64  fmt_id;
    char    gtrid[CT_MAX_XA_BASE16_GTRID_LEN];
    char    bqual[CT_MAX_XA_BASE16_BQUAL_LEN];
    uint8   gtrid_len;
    uint8   bqual_len;
} knl_xa_xid_t;
#pragma pack()

typedef struct st_lob_item_list {
    uint32 count;
    struct st_lob_item *first;
    struct st_lob_item *last;
} lob_item_list_t;

typedef struct st_lock_group {
    // lock
    id_list_t plocks;
    id_list_t glocks;
    uint32 plock_id;  // current private lock id
} lock_group_t;

typedef struct st_knl_savepoint {
    char name[CT_MAX_NAME_LEN];  // save point name
    undo_rowid_t urid;           // save point undo row_id;
    undo_rowid_t noredo_urid;    // save point noredo undo row_id;
    uint64 lsn;                  // lsn when the savepoint was created
    uint64 xid;
    lob_item_list_t lob_items;
    lock_group_t key_lock;
    lock_group_t row_lock;
    lock_group_t sch_lock;
    lock_group_t alck_lock;
} knl_savepoint_t;

typedef struct st_knl_xid {
    uint16 seg_id;
    uint16 slot;
    uint32 xnum;
} knl_xid_t;

status_t knl_xa_start(knl_handle_t session, xa_xid_t *xa_xid, uint64 timeout, uint64 flags);
status_t knl_xa_end(knl_handle_t handle);
status_t knl_xa_prepare(knl_handle_t handle, xa_xid_t *xa_xid, uint64 flags, knl_scn_t scn, bool32 *readonly);
status_t knl_xa_commit(knl_handle_t session, xa_xid_t *xa_xid, uint64 flags, knl_scn_t scn);
status_t knl_xa_rollback(knl_handle_t session, xa_xid_t *xa_xid, uint64 flags);
status_t knl_xa_status(knl_handle_t session, xa_xid_t *xa_xid, xact_status_t *status);
void knl_xa_reset_rm(void *rm);
void knl_tx_reset_rm(void *rm);
status_t knl_convert_xa_xid(xa_xid_t *src, knl_xa_xid_t *dst);
bool32 knl_xa_xid_equal(knl_xa_xid_t *xid1, knl_xa_xid_t *xid2);
status_t knl_set_session_trans(knl_handle_t session, isolation_level_t level, bool32 is_select);
xact_status_t knl_xact_status(knl_handle_t session);
status_t knl_commit_force(knl_handle_t handle, knl_xid_t *xid);
void knl_commit(knl_handle_t handle);
void knl_savepoint(knl_handle_t handle, knl_savepoint_t *savepoint);
status_t knl_release_savepoint(knl_handle_t handle, text_t *name);
void knl_rollback(knl_handle_t handle, knl_savepoint_t *savepoint);
status_t knl_set_savepoint(knl_handle_t handle, text_t *name);
status_t knl_rollback_savepoint(knl_handle_t handle, text_t *name);
status_t knl_get_space_type(knl_handle_t se, text_t *spc_name, device_type_t *type);

/* set commit type enumeration */
typedef enum en_commit_action {
    COMMIT_LOGGING = 0,
    COMMIT_WAIT = 1,
} commit_action_t;

/* Kernel set commit definition */
typedef struct st_knl_commit_def {
    commit_action_t action;
    bool32 nowait; /* < commit wait or nowait or force wait .force wait equal with wait */
    bool32 batch;  /* < commit_logging batch or immediate */
} knl_commit_def_t;
status_t knl_set_commit(knl_handle_t session, knl_commit_def_t *def);

static inline bool32 knl_xa_xid_valid(knl_xa_xid_t *xa_xid)
{
    return (xa_xid->gtrid_len != 0);
}

static inline uint32 knl_xa_xid_hash(knl_xa_xid_t *xid)
{
    text_t values[CT_MAX_XA_XID_TEXT_CNT];
    uint16 i = 0;
    uint32 value;

    cm_str2text_safe(xid->gtrid, xid->gtrid_len, &values[i]);
    i++;
    cm_str2text_safe(xid->bqual, xid->bqual_len, &values[i]);

    value = cm_hash_multi_text(values, CT_MAX_XA_XID_TEXT_CNT, CT_MAX_RM_BUCKETS);
    value = (value << 1) | ((value & 0x80000000) ? 1 : 0);
    value ^= cm_hash_int64((int64)xid->fmt_id);
    return value % CT_MAX_RM_BUCKETS;
}

uint64 knl_txn_buffer_size(uint32 page_size, uint32 segment_count);

#ifdef __cplusplus
}
#endif

#endif