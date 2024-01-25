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
 * knl_xa.c
 *
 *
 * IDENTIFICATION
 * src/kernel/xact/knl_xa.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_xact_module.h"
#include "knl_xa.h"
#include "knl_tran.h"
#include "knl_lob.h"
#include "rcr_btree.h"
#include "pcr_btree.h"
#include "knl_context.h"
#include "knl_temp.h"
#include "knl_table.h"

/*
* we use uint64 to store the user id(uid),table id(oid) and table lock type(type),
* uint64 = |---uid---|---oid---|--type--|
* uint64 = |--30bit--|--32bit--|--2bit--|
*/
#define TLOCKS_TO_UINT64(uid, oid, type)              (((uint64)(uid) << 34) | ((uint64)(oid) << 2) | ((uint8)(type)))
#define UINT64_TO_TLOCKS(ids_p, uid_p, oid_p, type_p) \
    do {                                                   \
        *(uid_p) = *(ids_p) >> 34;                         \
        *(oid_p) = (*(ids_p) >> 2) & 0x00000000ffffffffULL;  \
        *(type_p) = *(ids_p) & 0x0000000000000003ULL;        \
    } while (0)

/*
* buf = |---plocks_num---|---glocks_num---|--lob_num--|
* buf = |--uint32--|--uint32--|--uint32--|
*/
#define TX_ENCOD_TLOCKLOB(tlocklob, plocks_num, glocks_num, lob_num)      \
    do {                                                                  \
        *(uint32 *)((tlocklob)->bytes + (tlocklob)->size) = (plocks_num); \
        (tlocklob)->size += sizeof(uint32);                               \
        *(uint32 *)((tlocklob)->bytes + (tlocklob)->size) = (glocks_num); \
        (tlocklob)->size += sizeof(uint32);                               \
        *(uint32 *)((tlocklob)->bytes + (tlocklob)->size) = (lob_num);    \
        (tlocklob)->size += sizeof(uint32);                               \
    } while (0)

static void xa_decode_tlocklob(binary_t *tlocklob, uint32 *plocks_num, uint32 *glocks_num, uint32 *lob_num)
{
    *plocks_num = *(uint32 *)(tlocklob->bytes);
    tlocklob->size -= sizeof(uint32);
    tlocklob->bytes += sizeof(uint32);
    *glocks_num = *(uint32 *)(tlocklob->bytes);
    tlocklob->size -= sizeof(uint32);
    tlocklob->bytes += sizeof(uint32);
    if (lob_num != NULL) {
        *lob_num = *(uint32 *)(tlocklob->bytes);
    }
    tlocklob->size -= sizeof(uint32);
    tlocklob->bytes += sizeof(uint32);
}

static inline void xa_reset_rm(knl_rm_t *rm)
{
    rm->xa_prev = CT_INVALID_ID16;
    rm->xa_next = CT_INVALID_ID16;

    rm->xa_flags = CT_INVALID_ID64;
    rm->xa_status = XA_INVALID;
    rm->xa_xid.fmt_id = CT_INVALID_ID64;
    rm->xa_xid.bqual_len = 0;
    rm->xa_xid.gtrid_len = 0;
    rm->xa_rowid = INVALID_ROWID;
}

void knl_xa_reset_rm(void *rm)
{
    xa_reset_rm((knl_rm_t *)rm);
}

static void xa_print_err(knl_session_t *session, char *message, xa_xid_t *xid, knl_xa_xid_t *xa_xid)
{
    text_t gtrid;
    text_t bqual;

    if (xid != NULL) {
        cm_str2text_safe(xid->data, (uint32)xid->gtrid_len, &gtrid);
        cm_str2text_safe(xid->data + xid->gtrid_len, (uint32)xid->bqual_len, &bqual);
        CT_LOG_RUN_INF("%s.xa_xid[%llu-%s-%s] sid[%u] rmid[%u]", message, xid->fmt_id,
            T2S(&gtrid), T2S_EX(&bqual), session->id, session->rmid);
        return;
    }

    if (xa_xid != NULL) {
        cm_str2text_safe(xa_xid->gtrid, xa_xid->gtrid_len, &gtrid);
        cm_str2text_safe(xa_xid->bqual, xa_xid->bqual_len, &bqual);
        CT_LOG_RUN_INF("%s.xa_xid[%llu-%s-%s] sid[%u] rmid[%u]", message, xa_xid->fmt_id,
            T2S(&gtrid), T2S_EX(&bqual), session->id, session->rmid);
    }
}

static status_t xa_get_tlockids(knl_session_t *session, id_list_t *list, uint32 end_id,
    binary_t *tlock_ids, uint32 *count, uint32 max_size)
{
    lock_area_t *area = &session->kernel->lock_ctx;
    lock_item_t *item = NULL;
    knl_dictionary_t dc;
    uint32 cur_id;
    uint64 cur_tids;

    *count = 0;
    if (list->count == 0) {
        return CT_SUCCESS;
    }

    cur_id = list->first;

    while (cur_id != end_id) {
        item = lock_addr(area, cur_id);
        if (item->type == LOCK_TYPE_FREE) {
            break;
        }

        if (item->dc_entry == NULL) {
            cur_id = item->next;
            continue;
        }

        if (tlock_ids->size >= max_size) {
            CT_THROW_ERROR(ERR_XA_EXTEND_BUFFER_EXCEEDED);
            return CT_ERROR;
        }

        if (knl_open_dc_by_id(session, item->dc_entry->uid, item->dc_entry->id, &dc, CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (dc.type == DICT_TYPE_TABLE_NOLOGGING) {
            CT_THROW_ERROR(ERR_XATXN_CHANGED_NOLOGGING_TABLE);
            dc_close(&dc);
            return CT_ERROR;
        }

        // distributed transactions are not supported for temporary tables.
        if (dc.type == DICT_TYPE_TEMP_TABLE_TRANS || dc.type == DICT_TYPE_TEMP_TABLE_SESSION) {
            CT_THROW_ERROR(ERR_XATXN_CHANGED_TEMP_TABLE);
            dc_close(&dc);
            return CT_ERROR;
        }

        cur_tids = TLOCKS_TO_UINT64(item->dc_entry->uid, item->dc_entry->id, DC_GET_SCH_LOCK(item->dc_entry)->mode);
        *(uint64 *)(tlock_ids->bytes + tlock_ids->size) = cur_tids;
        tlock_ids->size += sizeof(uint64);
        cur_id = item->next;
        (*count)++;

        dc_close(&dc);
    }
    return CT_SUCCESS;
}

static status_t xa_get_tlocklob_info(knl_session_t *session, lock_group_t *group, binary_t *bin, uint32 max_size)
{
    uint32 real_size;
    uint32 plocks_count;
    uint32 glocks_count;

    bin->size = CT_LOCK_GROUP_COUNT * sizeof(uint32);
    if (CT_SUCCESS != xa_get_tlockids(session, &group->plocks, group->plock_id, bin, &plocks_count, max_size)) {
        return CT_ERROR;
    }

    if (CT_SUCCESS != xa_get_tlockids(session, &group->glocks, CT_INVALID_ID32, bin, &glocks_count, max_size)) {
        return CT_ERROR;
    }

    if (CT_SUCCESS != lob_write_2pc_buff(session, bin, max_size)) {
        return CT_ERROR;
    }

    real_size = bin->size;
    bin->size = 0;
    TX_ENCOD_TLOCKLOB(bin, plocks_count, glocks_count, session->rm->lob_items.count);
    bin->size = real_size;

    return CT_SUCCESS;
}

static inline bool32 xa_ptrans_accessible(knl_session_t *session)
{
    if (DB_STATUS(session) != DB_STATUS_OPEN || DB_IS_UPGRADE(session)) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

static inline bool32 xa_ptrans_modifiable(knl_session_t *session)
{
    if (!xa_ptrans_accessible(session)) {
        return CT_FALSE;
    }

    if (DB_IS_READONLY(session) || !DB_IS_PRIMARY(&session->kernel->db)) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

static status_t xa_insert_ptransinfo(knl_session_t *session, rowid_t *rowid)
{
    lock_group_t *group = &session->rm->sch_lock_group;
    bool8 org_nowait = session->commit_nowait;
    knl_rm_t *rm = session->rm;
    uint32 max_size;
    knl_xa_xid_t *xa_xid = NULL;
    xid_t ltid;
    binary_t tlocklob;

    max_size = CT_LOCK_GROUP_COUNT * sizeof(uint32);
    max_size += (group->plocks.count + group->glocks.count) * sizeof(uint64);
    max_size += rm->lob_items.count * sizeof(lob_pages_info_t);

    if (max_size > CT_XA_EXTEND_BUFFER_SIZE) {
        CT_THROW_ERROR(ERR_XA_EXTEND_BUFFER_EXCEEDED);
        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);

    tlocklob.bytes = (uint8 *)cm_push(session->stack, max_size);
    if (xa_get_tlocklob_info(session, group, &tlocklob, max_size) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    xa_xid = &rm->xa_xid;
    ltid = rm->xid;

    if (knl_begin_auton_rm(session) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    session->commit_nowait = CT_TRUE;
    if (db_insert_ptrans(session, xa_xid, ltid.value, &tlocklob, rowid) != CT_SUCCESS) {
        session->commit_nowait = org_nowait;
        knl_end_auton_rm(session, CT_ERROR);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_end_auton_rm(session, CT_SUCCESS);
    CM_RESTORE_STACK(session->stack);
    session->commit_nowait = org_nowait;
    return CT_SUCCESS;
}

static status_t xa_decode_tlocks(binary_t *tlocklob_ids, uint32 *plock_num, uint32 *glock_num)
{
    uint32 lob_num = 0;
    if (tlocklob_ids->size > 0) {
        if (tlocklob_ids->size < CT_LOCK_GROUP_COUNT * sizeof(uint32)) {
            CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "tlock_ids size is invalid");
            return CT_ERROR;
        }

        xa_decode_tlocklob(tlocklob_ids, plock_num, glock_num, &lob_num);
        if (tlocklob_ids->size < lob_num * sizeof(lob_pages_info_t)) {
            CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "tlock_ids size is invalid");
            return CT_ERROR;
        }
        tlocklob_ids->size -= lob_num * sizeof(lob_pages_info_t);
    }

    if (tlocklob_ids->size % sizeof(uint64) != 0) {
        CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "tlock_ids is invalid");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t xa_lock_table(knl_session_t *session, knl_dictionary_t *dc, lock_mode_t type)
{
    dc_entity_t *entity;

    entity = (dc_entity_t *)dc->handle;
    if (type == LOCK_MODE_X) {
        if (lock_table_exclusive(session, entity, LOCK_INF_WAIT) != CT_SUCCESS) {
            lock_free_sch_group(session);
            return CT_ERROR;
        }

        return CT_SUCCESS;
    }

    if (lock_table_shared(session, entity, LOCK_INF_WAIT) != CT_SUCCESS) {
        lock_free_sch_group(session);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t xa_recover_tlocks(knl_session_t *session, binary_t *tlocklob)
{
    knl_dictionary_t dc;
    uint32 uid = 0;
    uint32 oid = 0;
    uint32 type = 0;
    uint32 pos = 0;
    uint32 plock_num = 0;
    uint32 glock_num = 0;
    binary_t tlock;

    tlock.bytes = tlocklob->bytes;
    tlock.size = tlocklob->size;

    if (xa_decode_tlocks(&tlock, &plock_num, &glock_num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    while (pos < tlock.size) {
        UINT64_TO_TLOCKS((uint64 *)(tlock.bytes + pos), &uid, &oid, &type);

        if (knl_open_dc_by_id((knl_handle_t)session, uid, oid, &dc, CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (xa_lock_table(session, &dc, (lock_mode_t)type) != CT_SUCCESS) {
            dc_close(&dc);
            return CT_ERROR;
        }

        pos += sizeof(uint64);
        dc_close(&dc);
    }

    return CT_SUCCESS;
}

static status_t xa_recover_lobs(knl_session_t *session, binary_t *tlocklob)
{
    knl_rm_t *rm = session->rm;
    uint32 plock_num = 0;
    uint32 glock_num = 0;
    binary_t lob_ids;

    lob_ids.bytes = tlocklob->bytes;
    lob_ids.size = tlocklob->size;

    // only keep lob info
    if (lob_ids.size > 0) {
        if (lob_ids.size < CT_LOCK_GROUP_COUNT * sizeof(uint32)) {
            CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "tlock_ids size is invalid");
            return CT_ERROR;
        }
        xa_decode_tlocklob(&lob_ids, &plock_num, &glock_num, NULL);
        if (lob_ids.size < (plock_num + glock_num) * sizeof(uint64)) {
            CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "tlock_ids size is invalid");
            return CT_ERROR;
        }
        lob_ids.size -= (plock_num + glock_num) * sizeof(uint64);
        lob_ids.bytes += (plock_num + glock_num) * sizeof(uint64);
    }

    if (lob_ids.size % sizeof(lob_pages_info_t) != 0) {
        CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "tlock_ids is invalid size");
        return CT_ERROR;
    }

    return lob_create_2pc_items(session, lob_ids.bytes, lob_ids.size, &rm->lob_items);
}

static status_t xa_finish_recover(knl_session_t *session, knl_rm_t *rm, binary_t *tlocklob,
                                  uint16 old_rmid, knl_xa_xid_t *xa_xid)
{
    if (xa_recover_tlocks(session, tlocklob) != CT_SUCCESS) {
        xa_print_err(session, "XA recover tlocks failed", NULL, xa_xid);
        return CT_ERROR;
    }

    if (xa_recover_lobs(session, tlocklob) != CT_SUCCESS) {
        xa_print_err(session, "XA recover lobs failed", NULL, xa_xid);
        return CT_ERROR;
    }

    rm->xa_xid = *xa_xid;

    if (!g_knl_callback.add_xa_xid(xa_xid, rm->id, XA_PHASE1)) {
        CT_THROW_ERROR(ERR_XA_DUPLICATE_XID);
        xa_print_err(session, "XA recover add xa_xid failed", NULL, xa_xid);
        return CT_ERROR;
    }

    rm->xa_flags = KNL_XA_DEFAULT;
    g_knl_callback.detach_pending_rm(session, old_rmid);
    return CT_SUCCESS;
}

static inline void xa_recover_reset(knl_session_t *session, knl_rm_t *rm, uint16 old_rmid, uint16 rmid)
{
    xa_reset_rm(rm);
    knl_set_session_rm(session, old_rmid);
    g_knl_callback.release_rm(rmid);
}

status_t xa_recover(knl_session_t *session, tx_item_t *item, txn_t *txn, uint32 item_id)
{
    uint16 rmid;
    uint16 old_rmid = session->rmid;
    knl_rm_t *rm = NULL;
    bool32 is_found = CT_FALSE;
    xid_t ltid;
    knl_xa_xid_t xa_xid;
    binary_t tlocklob;

    if (g_knl_callback.alloc_rm(&rmid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("XA recover to alloc rm failed.ltid[%u-%u-%u]", item->xmap.seg_id, item->xmap.slot, txn->xnum);
        return CT_ERROR;
    }
    knl_set_session_rm(session, rmid);
    rm = session->rm;

    tx_rm_attach_trans(rm, item, txn, item_id);
    CM_SAVE_STACK(session->stack);

    ltid = rm->xid;
    tlocklob.bytes = (uint8 *)cm_push(session->stack, CT_XA_EXTEND_BUFFER_SIZE);
    tlocklob.size = 0;
    xa_xid.gtrid_len = 0;
    xa_xid.bqual_len = 0;
    xa_xid.fmt_id = CT_INVALID_ID64;

    if (db_fetch_ptrans_by_ltid(session, ltid.value, &xa_xid, &tlocklob, &is_found, rm) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        CT_LOG_RUN_ERR("XA recover to fetch pending_trans$ by local transaction id failed.ltid[%u-%u-%u val %llu]",
            ltid.xmap.seg_id, ltid.xmap.slot, ltid.xnum, ltid.value);
        xa_recover_reset(session, rm, old_rmid, rmid);
        return CT_ERROR;
    }

    if (!is_found) {
        CM_RESTORE_STACK(session->stack);
        xa_print_err(session, "XA recover not found ltid in pending_trans.", NULL, &xa_xid);
        CT_LOG_RUN_ERR("XA recover fetch from pending_trans$ by local transaction id not found.ltid[%u-%u-%u val %llu]",
            ltid.xmap.seg_id, ltid.xmap.slot, ltid.xnum, ltid.value);
        xa_recover_reset(session, rm, old_rmid, rmid);
        return CT_ERROR;
    }

    if (xa_finish_recover(session, rm, &tlocklob, old_rmid, &xa_xid) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        xa_recover_reset(session, rm, old_rmid, rmid);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static status_t xa_resume(knl_session_t *session, xa_xid_t *xa_xid, uint64 timeout_input)
{
    uint64 timeout = timeout_input;
    date_t begin = KNL_NOW(session);
    knl_xa_xid_t xid;

    if (knl_convert_xa_xid(xa_xid, &xid) != CT_SUCCESS) {
        xa_print_err(session, "XA resume convert XA xid failed", xa_xid, NULL);
        return CT_ERROR;
    }

    if (timeout == 0 || timeout == CT_INVALID_ID64) {
        timeout = session->kernel->attr.xa_suspend_timeout;
    }

    for (;;) {
        if (g_knl_callback.attach_suspend_rm(session, &xid, XA_START, CT_TRUE)) {
            break;
        }

        if (session->canceled) {
            CT_THROW_ERROR(ERR_OPERATION_CANCELED);
            xa_print_err(session, "XA resume cancled", xa_xid, NULL);
            return CT_ERROR;
        }

        if (session->killed) {
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            xa_print_err(session, "XA resume killed", xa_xid, NULL);
            return CT_ERROR;
        }

        if (((uint64)(KNL_NOW(session) - begin) / MICROSECS_PER_SECOND) > timeout) {
            CT_THROW_ERROR(ERR_XA_RESUME_TIMEOUT);
            xa_print_err(session, "XA resume timeout", xa_xid, NULL);
            return CT_ERROR;
        }

        cm_sleep(TX_WAIT_INTERVEL);
        continue;
    }

    return CT_SUCCESS;
}

static inline status_t xa_check(knl_session_t *session, knl_rm_t *rm)
{
    if (rm->temp_has_undo) {
        CT_THROW_ERROR(ERR_XATXN_CHANGED_TEMP_TABLE);
        CT_LOG_RUN_ERR("XA can not change temp table");
        return CT_ERROR;
    }

    if (rm->noredo_undo_pages.count > 0) {
        CT_THROW_ERROR(ERR_XATXN_CHANGED_NOLOGGING_TABLE);
        CT_LOG_RUN_ERR("XA can not change nologging table");
        return CT_ERROR;
    }

    if (KNL_IS_AUTON_SE(session)) {
        CT_THROW_ERROR(ERR_XA_IN_AUTON_TRANS);
        CT_LOG_RUN_ERR("cannot prepare XA in autonomous transaction");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline status_t check_unique_by_ptrans(knl_session_t *session, knl_xa_xid_t *xa_xid)
{
    bool32 is_found = CT_FALSE;
    xid_t ltid;
    rowid_t rid;

    if (!xa_ptrans_accessible(session)) {
        CT_THROW_ERROR(ERR_DATABASE_ROLE, "xa fetch pending_trans", "in wrong mode");
        return CT_ERROR;
    }

    if (db_fetch_ptrans_by_gtid(session, xa_xid, &ltid.value, &is_found, &rid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // find dumplicate xa xid
    if (is_found) {
        CT_THROW_ERROR(ERR_XA_DUPLICATE_XID);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t xa_check_start(knl_session_t *session, xa_xid_t *xa_xid)
{
    knl_rm_t *rm = session->rm;

    if (knl_xa_xid_valid(&rm->xa_xid)) {
        CT_THROW_ERROR(ERR_XA_TIMING);
        xa_print_err(session, "XA start duplicate", xa_xid, NULL);
        return CT_ERROR;
    }

    if (rm->txn != NULL && rm->txn->status != (uint8)XACT_END) {
        CT_THROW_ERROR(ERR_XA_ALREADY_IN_LOCAL_TRANS);
        xa_print_err(session, "XA start alread in local trans", xa_xid, NULL);
        return CT_ERROR;
    }

    if (rm->svpt_count > 0 || rm->query_scn != CT_INVALID_ID64) {
        CT_THROW_ERROR(ERR_XA_OUTSIDE);
        xa_print_err(session, "can't set savepoint or transaction isolation level before XA start", xa_xid, NULL);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t knl_xa_start(knl_handle_t session, xa_xid_t *xa_xid, uint64 timeout, uint64 flags)
{
    knl_session_t *se = (knl_session_t *)session;
    knl_rm_t *rm = se->rm;

    if (xa_check_start(se, xa_xid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (xa_check(se, rm) != CT_SUCCESS) {
        xa_print_err(se, "XA start check failed", xa_xid, NULL);
        return CT_ERROR;
    }

    if (flags & KNL_XA_RESUME) {
        return xa_resume(se, xa_xid, timeout);
    }

    if (!(flags & KNL_XA_NEW)) {
        CT_THROW_ERROR(ERR_NOT_SUPPORT_TYPE, (int32)flags);
        xa_print_err(se, "XA start invalid XA flags", xa_xid, NULL);
        return CT_ERROR;
    }

    if (knl_convert_xa_xid(xa_xid, &rm->xa_xid) != CT_SUCCESS) {
        xa_reset_rm(rm);
        xa_print_err(se, "XA start covert XA xid failed", xa_xid, NULL);
        return CT_ERROR;
    }

    if (DB_IN_BG_ROLLBACK(se)) {
        if (check_unique_by_ptrans(se, &rm->xa_xid) != CT_SUCCESS) {
            xa_reset_rm(rm);
            xa_print_err(se, "XA start find duplicate XA xid in pending_trans$", xa_xid, NULL);
            return CT_ERROR;
        }
    }
    rm->uid = se->uid;
    rm->xa_flags = flags;
    if (timeout != 0 && timeout != CT_INVALID_ID64) {
        rm->suspend_timeout = timeout;
    } else {
        rm->suspend_timeout = se->kernel->attr.xa_suspend_timeout;
    }

    if (!g_knl_callback.add_xa_xid(&rm->xa_xid, rm->id, XA_START)) {
        xa_reset_rm(rm);
        CT_THROW_ERROR(ERR_XA_DUPLICATE_XID);
        xa_print_err(se, "XA start duplicate XA xid", xa_xid, NULL);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t knl_xa_end(knl_handle_t handle)
{
    knl_session_t *session = (knl_session_t *)handle;
    knl_rm_t *rm = session->rm;
    uint16 rmid;

    if (!knl_xa_xid_valid(&rm->xa_xid)) {
        CT_THROW_ERROR(ERR_XA_BRANCH_NOT_EXISTS);
        xa_print_err(session, "no XA transaction can be ended", NULL, &rm->xa_xid);
        return CT_ERROR;
    }

    if (xa_check(session, rm) != CT_SUCCESS) {
        xa_print_err(session, "XA resume check failed", NULL, &rm->xa_xid);
        return CT_ERROR;
    }

    if (g_knl_callback.alloc_rm(&rmid) != CT_SUCCESS) {
        xa_print_err(session, "XA end alloc rm failed", NULL, &rm->xa_xid);
        return CT_ERROR;
    }

    g_knl_callback.detach_suspend_rm(session, rmid);
    return CT_SUCCESS;
}

static status_t convert_to_xa(knl_session_t *session, xa_xid_t *xa_xid)
{
    knl_rm_t *rm = session->rm;
    if (xa_check(session, rm) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_convert_xa_xid(xa_xid, &rm->xa_xid) != CT_SUCCESS) {
        xa_reset_rm(rm);
        return CT_ERROR;
    }

    if (DB_IN_BG_ROLLBACK(session)) {
        if (check_unique_by_ptrans(session, &rm->xa_xid) != CT_SUCCESS) {
            xa_reset_rm(rm);
            return CT_ERROR;
        }
    }

    rm->uid = session->uid;
    if (!g_knl_callback.add_xa_xid(&rm->xa_xid, rm->id, XA_PHASE1)) {
        xa_reset_rm(rm);
        CT_THROW_ERROR(ERR_XA_DUPLICATE_XID);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static void xa_commit_phase1(knl_session_t *session, knl_scn_t phase1_scn)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    tx_area_t *area = &session->kernel->tran_ctx;
    knl_rm_t *rm = session->rm;
    undo_t *undo = NULL;
    txn_t *txn = NULL;
    tx_item_t *tx_item = NULL;
    rd_xa_phase1_t redo;
    undo_page_id_t page_id;

    knl_panic(XID_INST_ID(rm->xid) == session->kernel->id);
    txn = rm->txn;
    undo = &ctx->undos[rm->tx_id.seg_id];
    tx_item = &undo->items[rm->tx_id.item_id];
    page_id = undo->segment->txn_page[tx_item->xmap.slot / TXN_PER_PAGE(session)];

    redo.xmap = rm->xid.xmap;
    knl_panic(XID_INST_ID(rm->xid) == session->kernel->id);

    if (session->kernel->attr.serialized_commit) {
        cm_spin_lock(&area->seri_lock, &session->stat->spin_stat.stat_seri_commit);
    }

    log_atomic_op_begin(session);

    buf_enter_page(session, PAGID_U2N(page_id), LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    cm_spin_lock(&tx_item->lock, &session->stat->spin_stat.stat_txn);
    txn->scn = tx_inc_scn(session, rm->tx_id.seg_id, txn, phase1_scn);
    txn->status = (uint8)XACT_PHASE1;
    cm_spin_unlock(&tx_item->lock);
    cm_atomic_set(&session->kernel->commit_scn, (int64)txn->scn);

    redo.scn = txn->scn;
    log_put(session, RD_XA_PHASE1, &redo, sizeof(rd_xa_phase1_t), LOG_ENTRY_FLAG_NONE);
    buf_leave_page(session, CT_TRUE);

    log_atomic_op_end(session);

    if (session->kernel->attr.serialized_commit) {
        cm_spin_unlock(&area->seri_lock);
    }
}

status_t knl_xa_prepare(knl_handle_t handle, xa_xid_t *xa_xid, uint64 flags, knl_scn_t scn, bool32 *readonly)
{
    knl_session_t *session = (knl_session_t *)handle;
    knl_rm_t *rm = session->rm;
    uint16 rmid = session->rmid;
    knl_xa_xid_t curr_xa_xid;

    if (knl_xa_xid_valid(&rm->xa_xid)) {
        knl_rollback(session, NULL);
        CT_THROW_ERROR(ERR_XA_TIMING);
        xa_print_err(session, "need XA end before XA prepare", xa_xid, NULL);
        return CT_ERROR;
    }

    if (rm->txn != NULL && rm->txn->status != (uint8)XACT_END) {
        /* convert current rm to XA rm */
        if (convert_to_xa(session, xa_xid) != CT_SUCCESS) {
            knl_rollback(session, NULL);
            xa_print_err(session, "local transaction convert to XA failed", xa_xid, NULL);
            return CT_ERROR;
        }

        if (g_knl_callback.alloc_rm(&rmid) != CT_SUCCESS) {
            knl_rollback(session, NULL);
            xa_print_err(session, "XA prepare alloc rm failed", NULL, &rm->xa_xid);
            return CT_ERROR;
        }
    } else {
        if (knl_convert_xa_xid(xa_xid, &curr_xa_xid) != CT_SUCCESS) {
            knl_rollback(session, NULL);
            xa_print_err(session, "invalid XA xid", xa_xid, NULL);
            return CT_ERROR;
        }

        rmid = session->rmid;

        if (!g_knl_callback.attach_suspend_rm(session, &curr_xa_xid, XA_PHASE1, CT_FALSE)) {
            knl_rollback(session, NULL);
            CT_THROW_ERROR(ERR_XA_BRANCH_NOT_EXISTS);
            xa_print_err(session, "XA prepare attach suspend rm failed", xa_xid, NULL);
            return CT_ERROR;
        }
        rm = session->rm;

        if (rm->txn == NULL || rm->txn->status == (uint8)XACT_END) {
            *readonly = CT_TRUE;
            knl_rollback(session, NULL);
            g_knl_callback.release_rm(rmid);
            return CT_SUCCESS;
        }
    }

    if (xa_insert_ptransinfo(session, &rm->xa_rowid) != CT_SUCCESS) {
        knl_rollback(session, NULL);
        g_knl_callback.release_rm(rmid);
        xa_print_err(session, "insert into pending_trans$ failed", xa_xid, NULL);
        return CT_ERROR;
    }

    *readonly = CT_FALSE;
    rm->xa_flags = flags;

    // insert pending_trans$ is succeeded,but the server may down before finish prepared,
    // remain records will be deleted by XA commit or XA rollback
    xa_commit_phase1(session, scn);
    log_commit(session);

    g_knl_callback.detach_pending_rm(session, rmid);
    return CT_SUCCESS;
}

/*
* need modify txn status before rollback xa transaction,
* so that when rollback fail because of database shutdown,
* this xa transaction won't be committed after restart
*/
static void xa_rollback_phase2(knl_session_t *session)
{
    undo_t *undo = NULL;
    txn_t *txn = NULL;
    tx_item_t *tx_item = NULL;
    undo_page_id_t page_id;

    knl_panic(XID_INST_ID(session->rm->xid) == session->kernel->id);

    txn = session->rm->txn;
    if (txn != NULL && txn->status != (uint8)XACT_END) {
        undo = &session->kernel->undo_ctx.undos[session->rm->tx_id.seg_id];
        tx_item = &undo->items[session->rm->tx_id.item_id];
        page_id = undo->segment->txn_page[tx_item->xmap.slot / TXN_PER_PAGE(session)];

        log_atomic_op_begin(session);
        buf_enter_page(session, PAGID_U2N(page_id), LATCH_MODE_X, ENTER_PAGE_RESIDENT);

        cm_spin_lock(&tx_item->lock, &session->stat->spin_stat.stat_txn);
        txn->status = (uint8)XACT_PHASE2;
        cm_spin_unlock(&tx_item->lock);

        log_put(session, RD_XA_ROLLBACK_PHASE2, &session->rm->xid.xmap, sizeof(xmap_t), LOG_ENTRY_FLAG_NONE);
        buf_leave_page(session, CT_TRUE);

        log_atomic_op_end(session);
        log_commit(session);
    }

    tx_rollback(session, NULL);
}

static status_t xa_phase2_attach_rm(knl_session_t *session, knl_xa_xid_t *xa_xid, uint64 flags, bool32 commit,
                                    bool32 *from_suspend)
{
    bool32 bg_rollback = DB_IN_BG_ROLLBACK(session);
    bool32 is_found = CT_FALSE;
   
    *from_suspend = CT_FALSE;

    if (flags & KNL_XA_ONEPHASE) {
        if (g_knl_callback.attach_suspend_rm(session, xa_xid, XA_PHASE2, CT_FALSE)) {
            *from_suspend = CT_TRUE;
            return CT_SUCCESS;
        }

        CT_THROW_ERROR(ERR_XA_BRANCH_NOT_EXISTS);
        return CT_ERROR;
    }

    if (g_knl_callback.attach_pending_rm(session, xa_xid)) {
        return CT_SUCCESS;
    }

    /* support xa_end --> xa_rollback to rollback transaction */
    if (!commit) {
        if (g_knl_callback.attach_suspend_rm(session, xa_xid, XA_PHASE2, CT_FALSE)) {
            *from_suspend = CT_TRUE;
            return CT_SUCCESS;
        }
    }

    if (bg_rollback || !xa_ptrans_modifiable(session)) {
        CT_THROW_ERROR(ERR_XA_IN_ABNORMAL_MODE);
        return CT_ERROR;
    }

    if (db_delete_ptrans_remained(session, xa_xid, NULL, &is_found) != CT_SUCCESS) {
        xa_print_err(session, "XA fail to delete remain XA xid in ptrans", NULL, xa_xid);
        return CT_ERROR;
    }

    if (is_found) {
        xa_print_err(session, "XA phase2 delete all remain xa xid in ptrans", NULL, xa_xid);
    }

    CT_THROW_ERROR(ERR_XA_BRANCH_NOT_EXISTS);
    return CT_ERROR;
}

static status_t xa_try_rollback_start(knl_session_t *session, bool32 commit, knl_xa_xid_t *xa_xid)
{
    knl_rm_t *rm = session->rm;

    if (!commit) {
        if (knl_xa_xid_equal(xa_xid, &rm->xa_xid)) {
            knl_rollback(session, NULL);
            return CT_SUCCESS;
        }
    }

    CT_THROW_ERROR(ERR_XA_TIMING);
    xa_print_err(session, "XA phase2 can't end active XA transaction", NULL, xa_xid);
    return CT_ERROR;
}

static inline void xa_delete_xa_xid(knl_xa_xid_t *xa_xid)
{
    if (knl_xa_xid_valid(xa_xid)) {
        g_knl_callback.delete_xa_xid(xa_xid);
    }
}

static inline void xa_phase2_end_trans(knl_session_t *session, bool32 commit, uint64 flags, knl_scn_t scn)
{
    bool8 org_nowait = session->commit_nowait;

    if (commit) {
        session->stat->xa_commits++;
        if (flags & KNL_XA_LGWR_NOWAIT) {
            session->commit_nowait = CT_TRUE;
        }
        tx_commit(session, scn);
        session->commit_nowait = org_nowait;
    } else {
        session->stat->xa_rollbacks++;
        xa_rollback_phase2(session);
    }
}

static inline status_t xa_phase2_delete_ptrans(knl_session_t *session, knl_xa_xid_t *xa_xid, xid_t *ltid, rowid_t rid)
{
    bool8 org_nowait = session->commit_nowait;

    session->commit_nowait = CT_TRUE;
    if (db_delete_ptrans_by_rowid(session, xa_xid, ltid->value, rid) != CT_SUCCESS) {
        session->commit_nowait = org_nowait;
        knl_rollback(session, NULL);
        return CT_ERROR;
    }

    knl_commit(session);
    session->commit_nowait = org_nowait;
    return CT_SUCCESS;
}

static status_t xa_phase2(knl_session_t *session, xa_xid_t *xa_xid, bool32 commit, uint64 flags, knl_scn_t scn)
{
    knl_rm_t *rm = session->rm;
    uint16 org_rmid = session->rmid;
    knl_xa_xid_t curr_xa_xid;
    xid_t ltid;
    uint16 xa_rmid;
    bool32 from_suspend = CT_FALSE;

    if (knl_convert_xa_xid(xa_xid, &curr_xa_xid) != CT_SUCCESS) {
        xa_print_err(session, "XA phase2 invalid XA xid", xa_xid, NULL);
        return CT_ERROR;
    }

    if (knl_xa_xid_valid(&rm->xa_xid)) {
        return xa_try_rollback_start(session, commit, &curr_xa_xid);
    }

    if (rm->txn != NULL && rm->txn->status != (uint8)XACT_END) {
        CT_THROW_ERROR(ERR_XA_ALREADY_IN_LOCAL_TRANS);
        xa_print_err(session, "XA phase2 can't end local transaction", xa_xid, NULL);
        return CT_ERROR;
    }

    /* try attach suspend or pending rm to do XA phase2 */
    if (xa_phase2_attach_rm(session, &curr_xa_xid, flags, commit, &from_suspend) != CT_SUCCESS) {
        xa_print_err(session, "XA phase2 attach rm failed", xa_xid, NULL);
        return CT_ERROR;
    }
    rm = session->rm;
    ltid = rm->xid;
    xa_rmid = session->rmid;

    xa_phase2_end_trans(session, commit, flags, scn);
    if (from_suspend) {
        xa_delete_xa_xid(&rm->xa_xid);
        g_knl_callback.release_rm(org_rmid);
        return CT_SUCCESS;
    }

    /* first delete ptrans,use org rm to delete for safety */
    knl_set_session_rm(session, org_rmid);
    if (!commit) {
        session->xa_scn = 0;
    }
    session->delete_ptrans = CT_TRUE;
    if (xa_phase2_delete_ptrans(session, &curr_xa_xid, &ltid, rm->xa_rowid) != CT_SUCCESS) {
        xa_print_err(session, "XA phase2 delete pending_trans$ failed", xa_xid, NULL);
        xa_delete_xa_xid(&rm->xa_xid);
        g_knl_callback.release_rm(xa_rmid);
        session->delete_ptrans = CT_FALSE;
        return CT_ERROR;
    }
    session->delete_ptrans = CT_FALSE;

    /* then release xa_xid in hash */
    xa_delete_xa_xid(&rm->xa_xid);
    g_knl_callback.release_rm(xa_rmid);

    return CT_SUCCESS;
}

status_t knl_xa_commit(knl_handle_t session, xa_xid_t *xa_xid, uint64 flags, knl_scn_t scn)
{
    return xa_phase2((knl_session_t *)session, xa_xid, CT_TRUE, flags, scn);
}

status_t knl_xa_rollback(knl_handle_t session, xa_xid_t *xa_xid, uint64 flags)
{
    return xa_phase2((knl_session_t *)session, xa_xid, CT_FALSE, flags, CT_INVALID_ID64);
}

status_t knl_xa_status(knl_handle_t session, xa_xid_t *xa_xid, xact_status_t *status)
{
    knl_session_t *se = (knl_session_t *)session;
    knl_xa_xid_t knl_xa_xid;
    txn_t *txn = NULL;
    uint16 rmid;

    if (knl_convert_xa_xid(xa_xid, &knl_xa_xid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    rmid = g_knl_callback.get_xa_xid(&knl_xa_xid);
    if (rmid == CT_INVALID_ID16) {
        *status = XACT_END;
        return CT_SUCCESS;
    }

    txn = se->kernel->rms[rmid]->txn;

    if (txn == NULL) {
        *status = XACT_END;
        return CT_SUCCESS;
    }

    *status = (xact_status_t)txn->status;
    return CT_SUCCESS;
}
