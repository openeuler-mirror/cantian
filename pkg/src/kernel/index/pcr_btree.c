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
 * pcr_btree.c
 *
 *
 * IDENTIFICATION
 * src/kernel/index/pcr_btree.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_index_module.h"
#include "pcr_btree.h"
#include "cm_utils.h"
#include "cm_log.h"
#include "knl_table.h"
#include "knl_context.h"
#include "pcr_btree_scan.h"
#include "index_common.h"
#include "knl_space_manage.h"
#include "dtc_dls.h"
#include "dtc_btree.h"
#include "dtc_dc.h"
#include "rc_reform.h"
#include "srv_instance.h"
#include "cm_io_record.h"

#define PCRB_MIN_PAGE_USED_RATIO 0.4
#define PCRB_MAX_BATCH_INSERT_SIZE 128
#define PCRB_INSERT_UNDO_COUNT 2
#define ROOT_PAGE_WAIT_ACK_TIMEOUT  (10000)  // ms
#define ROOT_PAGE_WAIT_ACK_RETRY_THRESHOLD  (0xFFFFFFFF)

static status_t pcrb_try_split_page(knl_session_t *session, knl_cursor_t *cursor, btree_path_info_t *path_info,
                                    int64 version, bool32 use_pct, uint64 trigger_version);
static status_t pcrb_construct_ancestors(knl_session_t *session, btree_t *btree, btree_page_t **parent_page,
                                         char **key_buf, pcrb_key_t *key, uint32 level, bool32 nologging);

void pcrb_init_key(pcrb_key_t *key, rowid_t *rid)
{
    int32 ret;

    ret = memset_sp(key, sizeof(pcrb_key_t), 0, sizeof(pcrb_key_t));
    knl_securec_check(ret);

    if (rid != NULL) {
        ROWID_COPY(key->rowid, *rid);
    } else {
        MINIMIZE_ROWID(key->rowid);
    }

    key->size = sizeof(pcrb_key_t);
}

void pcrb_insert_minimum_key(knl_session_t *session)
{
    btree_page_t *page;
    pcrb_key_t *key = NULL;
    pcrb_dir_t *dir = NULL;
    rd_pcrb_insert_t redo;
    page_id_t page_id;

    page = BTREE_CURR_PAGE(session);
    page_id = AS_PAGID(page->head.id);
    knl_panic_log(page->itls > 0, "page's itls is abnormal, panic info: page %u-%u type %u itls %u", page_id.file,
                  page_id.page, page->head.type, page->itls);
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, page_id.file)->space_id);
    bool32 need_encrypt = SPACE_IS_ENCRYPT(space);
    key = (pcrb_key_t *)((char *)page + page->free_begin);
    dir = pcrb_get_dir(page, 0);
    *dir = page->free_begin;

    pcrb_init_key(key, NULL);
    key->is_infinite = CT_TRUE;
    key->itl_id = CT_INVALID_ID8;

    page->free_begin += (uint16)key->size;
    page->free_end -= sizeof(pcrb_dir_t);
    page->free_size -= ((uint16)key->size + sizeof(pcrb_dir_t));
    page->keys++;

    redo.slot = 0;
    redo.is_reuse = 0;
    redo.ssn = 0;
    redo.undo_page = INVALID_UNDO_PAGID;
    redo.undo_slot = INVALID_SLOT;
    if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
        log_encrypt_prepare(session, page->head.type, need_encrypt);
        log_put(session, RD_PCRB_INSERT, &redo, (uint32)OFFSET_OF(rd_pcrb_insert_t, key), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, key, (uint32)key->size);
    }
}

void pcrb_decode_key(index_profile_t *profile, pcrb_key_t *key, knl_scan_key_t *scan_key)
{
    uint32 id;
    uint16 offset;

    scan_key->buf = (char *)key;
    offset = sizeof(pcrb_key_t);

    for (id = 0; id < profile->column_count; id++) {
        btree_decode_key_column(scan_key, &key->bitmap, &offset, profile->types[id], id, CT_TRUE);
    }
}

void pcrb_put_key_data(char *key_buf, ct_type_t type, const char *data, uint16 len, uint16 id)
{
    pcrb_key_t *key = NULL;
    uint32 align_size;
    uint32 buf_size;
    errno_t err;

    if ((len != 0) && (data == NULL || len == CT_NULL_VALUE_LEN)) {
        return;
    }

    key = (pcrb_key_t *)key_buf;
    btree_set_bitmap(&key->bitmap, id);

    switch (type) {
        case CT_TYPE_UINT64:
            *(uint64 *)CURR_KEY_PTR(key) = *(uint64 *)data;
            key->size += sizeof(uint64);
            break;
        case CT_TYPE_BIGINT:
            if (len == sizeof(int32)) {
                *(int64 *)CURR_KEY_PTR(key) = (int64)(*(int32 *)data);
                key->size += sizeof(int64);
                break;
            }
            // fall - through
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_REAL:
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_BOOLEAN:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_TZ:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_INTERVAL_DS:
        case CT_TYPE_INTERVAL_YM:
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
        case CT_TYPE_DATE_MYSQL:
            buf_size = CT_KEY_BUF_SIZE - (uint32)key->size;
            err = memcpy_sp(CURR_KEY_PTR(key), buf_size, data, len);
            knl_securec_check(err);
            key->size += len;  // for now, maximum key size is 3900, won't overflow
            break;
        case CT_TYPE_NUMBER2:
            buf_size = CT_KEY_BUF_SIZE - (uint32)key->size - sizeof(uint8);
            if (SECUREC_UNLIKELY(len == 0)) {
                *(uint8 *)CURR_KEY_PTR(key) = 1;
                *(uint8 *)(CURR_KEY_PTR(key) + sizeof(uint8)) = ZERO_EXPN;
                key->size += 1 + sizeof(uint8);
                break;
            }
            *(uint8 *)CURR_KEY_PTR(key) = (uint8)len;
            err = memcpy_sp(CURR_KEY_PTR(key) + sizeof(uint8), buf_size, data, len);
            knl_securec_check(err);
            key->size += (len + sizeof(uint8));
            break;
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER3:
        case CT_TYPE_NUMBER:
            buf_size = CT_KEY_BUF_SIZE - (uint32)key->size;
            if (SECUREC_UNLIKELY(len == 0)) {
                err = memcpy_sp(CURR_KEY_PTR(key), buf_size, "\0\0\0\0", CSF_NUMBER_INDEX_LEN);
                knl_securec_check(err);
                key->size += CSF_NUMBER_INDEX_LEN;
                break;
            }
            // pcr optimization, only put data
            err = memcpy_sp(CURR_KEY_PTR(key), buf_size, data, len);
            knl_securec_check(err);

            align_size = CM_ALIGN4(len) - len;
            if (align_size != 0) {
                buf_size -= len;
                err = memset_sp(CURR_KEY_PTR(key) + len, buf_size, 0, align_size);
                knl_securec_check(err);
            }
            key->size += (len + align_size);
            break;
        
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            *(uint16 *)CURR_KEY_PTR(key) = len;
            buf_size = CT_KEY_BUF_SIZE - (uint32)key->size - sizeof(uint16);

            if (len != 0) {
                err = memcpy_sp(CURR_KEY_PTR(key) + sizeof(uint16), buf_size, data, len);
                knl_securec_check(err);
            }

            align_size = CM_ALIGN4(len + sizeof(uint16)) - (len + sizeof(uint16));
            if (align_size != 0) {
                buf_size -= len;
                err = memset_sp(CURR_KEY_PTR(key) + (len + sizeof(uint16)), buf_size, 0, align_size);
                knl_securec_check(err);
            }
            key->size += CM_ALIGN4(len + sizeof(uint16));
            break;
        default:
            CT_LOG_RUN_WAR("[PCRB] unknown datatype %u when generate key data", type);
            knl_panic(0);
    }
}

static page_id_t pcrb_clean_copied_itl(knl_session_t *session, uint64 xid, page_id_t page_id_input)
{
    page_id_t page_id = page_id_input;
    txn_info_t txn_info;
    bool32 is_changed = CT_FALSE;
    rd_pcrb_clean_itl_t redo;
    bool32 need_redo = SPC_IS_LOGGING_BY_PAGEID(session, page_id);

    log_atomic_op_begin(session);
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    btree_page_t *page = BTREE_CURR_PAGE(session);

    for (uint8 i = 0; i < page->itls; i++) {
        pcr_itl_t *itl = pcrb_get_itl(page, i);
        if (!itl->is_active) {
            continue;
        }

        if (itl->xid.value != xid) {
            continue;
        }

        if (itl->xid.value == session->rm->xid.value) {
            itl->is_active = CT_FALSE;
            itl->scn = session->rm->txn->scn;
            itl->is_owscn = 0;
        } else {
            tx_get_pcr_itl_info(session, CT_FALSE, itl, &txn_info);
            knl_panic_log(txn_info.status == (uint8)XACT_END, "txn's status is abnormal, panic info: page %u-%u type "
                          "%u txn status %u", page_id.file, page_id.page,
                          ((page_head_t *)CURR_PAGE(session))->type, txn_info.status);
            itl->is_active = CT_FALSE;
            itl->scn = txn_info.scn;
            itl->is_owscn = (uint16)txn_info.is_owscn;
        }

        if (page->scn < itl->scn) {
            page->scn = itl->scn;
        }

        redo.itl_id = i;
        redo.scn = itl->scn;
        redo.is_owscn = (uint8)itl->is_owscn;
        redo.is_copied = (uint8)itl->is_copied;
        redo.aligned = (uint8)0;
        if (need_redo) {
            log_put(session, RD_PCRB_CLEAN_ITL, &redo, sizeof(rd_pcrb_clean_itl_t), LOG_ENTRY_FLAG_NONE);
        }
        is_changed = CT_TRUE;
        break;
    }

    page_id = AS_PAGID(page->next);
    buf_leave_page(session, is_changed);
    log_atomic_op_end(session);

    return page_id;
}

static status_t pcrb_check_unique(knl_session_t *session, knl_cursor_t *cursor, rowid_t *path, bool32 is_same,
    idx_conflict_info_t *conflict_info)
{
    index_t *index = (index_t *)cursor->index;
    txn_info_t txn_info;

    if (!IS_UNIQUE_PRIMARY_INDEX(index) || !is_same) {
        return CT_SUCCESS;
    }

    cursor->snapshot.is_valid = 0;

    btree_page_t *page = BTREE_CURR_PAGE(session);
    pcrb_dir_t *dir = pcrb_get_dir(page, (uint32)path[0].slot);
    pcrb_key_t *key = PCRB_GET_KEY(page, dir);
    if (key->itl_id == CT_INVALID_ID8) {
        if (cursor->isolevel == (uint8)ISOLATION_SERIALIZABLE && cursor->query_scn < page->scn) {
            CT_THROW_ERROR(ERR_SERIALIZE_ACCESS);
            return CT_ERROR;
        }
    } else {
        pcr_itl_t *itl = pcrb_get_itl(page, key->itl_id);
        if (itl->xid.value == session->rm->xid.value) {
            if (itl->ssn == cursor->ssn) {
                cursor->snapshot.undo_page = itl->undo_page;
                cursor->snapshot.undo_slot = itl->undo_slot;
                cursor->snapshot.is_valid = 1;
            }
        } else {
            tx_get_pcr_itl_info(session, CT_FALSE, itl, &txn_info);
            if (txn_info.status != (uint8)XACT_END) {
                ROWID_COPY(session->wrid, key->rowid);
                session->wxid = itl->xid;
                return CT_SUCCESS;
            }

            if (cursor->isolevel == (uint8)ISOLATION_SERIALIZABLE && cursor->query_scn < txn_info.scn) {
                CT_THROW_ERROR(ERR_SERIALIZE_ACCESS);
                return CT_ERROR;
            }
        }
    }

    if (!key->is_deleted) {
        cursor->conflict_rid = key->rowid;
        conflict_info->is_duplicate = CT_TRUE;
        cursor->conflict_idx_slot = cursor->index_slot;
        if (cursor->action != CURSOR_ACTION_UPDATE || cursor->disable_pk_update) {
            conflict_info->conflict = CT_TRUE;
            return idx_generate_dupkey_error(session, index, (char *)key);
        }
        
        CT_THROW_ERROR(ERR_DUPLICATE_KEY, "");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * generate undo for PCR btree itl
 * @param kernel session, kernel cursor, btree page, itl, undo
 */
static void pcrb_generate_itl_undo(knl_session_t *session, knl_cursor_t *cursor, btree_page_t *page, pcr_itl_t *itl,
                                   undo_data_t *undo)
{
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);

    undo->snapshot.scn = itl->scn;
    undo->snapshot.is_owscn = itl->is_owscn;
    undo->snapshot.undo_page = itl->undo_page;
    undo->snapshot.undo_slot = itl->undo_slot;
    undo->snapshot.is_xfirst = CT_TRUE;

    undo->size = sizeof(xid_t);
    undo->data = (char *)&itl->xid;

    undo->type = UNDO_PCRB_ITL;
    undo->rowid.file = AS_PAGID_PTR(page->head.id)->file;
    undo->rowid.page = AS_PAGID_PTR(page->head.id)->page;
    undo->rowid.slot = session->itl_id;
    undo->ssn = (uint32)cursor->ssn;

    undo_write(session, undo, need_redo, !cursor->logging);
}

uint8 pcrb_new_itl(knl_session_t *session, btree_page_t *page)
{
    char *dst = NULL;
    char *src = NULL;
    uint8 itl_id;
    errno_t ret;

    if (page->itls == CT_MAX_TRANS || page->free_size < sizeof(pcr_itl_t) ||
        (page->free_end - page->free_begin) < sizeof(pcr_itl_t)) {
        return CT_INVALID_ID8;
    }

    src = (char *)page + page->free_end;
    dst = src - sizeof(pcr_itl_t);

    if (page->keys > 0) {
        ret = memmove_s(dst, page->keys * sizeof(pcrb_dir_t), src, page->keys * sizeof(pcrb_dir_t));
        knl_securec_check(ret);
    }

    *(pcr_itl_t *)(dst + page->keys * sizeof(pcrb_dir_t)) = g_init_pcr_itl;

    itl_id = page->itls;
    page->itls++;
    page->free_end -= sizeof(pcr_itl_t);
    page->free_size -= sizeof(pcr_itl_t);

    return itl_id;
}

void pcrb_reuse_itl(knl_session_t *session, btree_page_t *page, pcr_itl_t *itl, uint8 itl_id, knl_scn_t min_scn)
{
    pcrb_key_t *key = NULL;
    pcrb_dir_t *dir = NULL;
    uint16 i;

    if (page->level != 0) {
        return;
    }

    for (i = 0; i < page->keys; i++) {
        dir = pcrb_get_dir(page, i);
        key = PCRB_GET_KEY(page, dir);
        if (key->itl_id != itl_id) {
            continue;
        }

        if (key->is_cleaned) {
            continue;
        }

        key->itl_id = CT_INVALID_ID8;

        /*
         * keys which are deleted and commit scn > min_scn would be
         * cleaned later using page ow_scn.
         */
        if (key->is_deleted && itl->scn <= min_scn) {
            key->is_cleaned = 1;
            page->free_size += ((uint16)key->size + sizeof(pcrb_dir_t));
        }
    }
}

static void pcrb_init_itl(knl_session_t *session, knl_cursor_t *cursor, btree_page_t *page, pcr_itl_t **itl)
{
    undo_data_t undo;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    rd_pcrb_reuse_itl_t rd_reuse;
    rd_pcrb_new_itl_t rd_new;
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);

    if (*itl == NULL) {
        *itl = pcrb_get_itl(page, session->itl_id);

        rd_new.ssn = (uint32)cursor->ssn;
        rd_new.xid = session->rm->xid;
        rd_new.undo_rid = undo_page_info->undo_rid;

        if (cursor->nologging_type != SESSION_LEVEL) {
            pcrb_generate_itl_undo(session, cursor, page, *itl, &undo);
            tx_init_pcr_itl(session, *itl, &rd_new.undo_rid, rd_new.xid, rd_new.ssn);
        } else {
            undo_rowid_t undo_rid = g_invalid_undo_rowid;
            tx_init_pcr_itl(session, *itl, &undo_rid, rd_new.xid, rd_new.ssn);
        }
        
        if (need_redo && cursor->logging) {
            log_put(session, RD_PCRB_NEW_ITL, &rd_new, sizeof(rd_pcrb_new_itl_t), LOG_ENTRY_FLAG_NONE);
        }
    } else {
        if ((*itl)->is_copied) {
            cursor->reused_xid = (*itl)->xid.value;
        }

        rd_reuse.min_scn = btree_get_recycle_min_scn(session);
        rd_reuse.ssn = (uint32)cursor->ssn;
        rd_reuse.xid = session->rm->xid;
        rd_reuse.undo_rid = undo_page_info->undo_rid;
        rd_reuse.itl_id = session->itl_id;

        pcrb_reuse_itl(session, page, *itl, session->itl_id, rd_reuse.min_scn);

        if (cursor->nologging_type != SESSION_LEVEL) {
            pcrb_generate_itl_undo(session, cursor, page, *itl, &undo);
            tx_init_pcr_itl(session, *itl, &rd_reuse.undo_rid, rd_reuse.xid, rd_reuse.ssn);
        } else {
            undo_rowid_t undo_rid = g_invalid_undo_rowid;
            tx_init_pcr_itl(session, *itl, &undo_rid, rd_reuse.xid, rd_reuse.ssn);
        }
        if (need_redo && cursor->logging) {
            log_put(session, RD_PCRB_REUSE_ITL, &rd_reuse, sizeof(rd_pcrb_reuse_itl_t), LOG_ENTRY_FLAG_NONE);
        }
    }
}

static status_t pcrb_find_available_itl(knl_session_t *session, knl_cursor_t *cursor, uint8 i, pcr_itl_t **itl,
                                        bool32 *check_next)
{
    txn_info_t txn_info;
    rd_pcrb_clean_itl_t rd_clean;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    btree_page_t *page = BTREE_CURR_PAGE(session);
    pcr_itl_t *item = pcrb_get_itl(page, i);

    *check_next = CT_FALSE;
    if (!item->is_active) {
        /* find the oldest itl to reuse */
        if (*itl == NULL || item->scn < (*itl)->scn) {
            session->itl_id = i;
            *itl = item;
        }
        *check_next = CT_TRUE;
        return CT_SUCCESS;
    }

    tx_get_pcr_itl_info(session, CT_FALSE, item, &txn_info);
    if (txn_info.status != (uint8)XACT_END) {
        *check_next = CT_TRUE;
        return CT_SUCCESS;
    }

    if (cursor->isolevel == (uint8)ISOLATION_SERIALIZABLE && cursor->query_scn < txn_info.scn) {
        CT_THROW_ERROR(ERR_SERIALIZE_ACCESS);
        return CT_ERROR;
    }

    if (page->scn < txn_info.scn) {
        page->scn = txn_info.scn;
    }

    item->is_active = 0;
    item->scn = txn_info.scn;
    item->is_owscn = (uint16)txn_info.is_owscn;

    if (*itl == NULL || item->scn < (*itl)->scn) {
        session->itl_id = i;
        *itl = item;
    }

    rd_clean.scn = item->scn;
    rd_clean.itl_id = i;
    rd_clean.is_owscn = (uint8)item->is_owscn;
    rd_clean.is_copied = (uint8)item->is_copied;
    rd_clean.aligned = (uint8)0;

    if (need_redo && cursor->logging) {
        log_put(session, RD_PCRB_CLEAN_ITL, &rd_clean, sizeof(rd_pcrb_clean_itl_t), LOG_ENTRY_FLAG_NONE);
    }
    return CT_SUCCESS;
}

static void pcrb_alloc_itl_set_part(knl_cursor_t *cursor, knl_part_locate_t *part_loc)
{
    if (IS_PART_INDEX(cursor->index)) {
        part_loc->part_no = cursor->part_loc.part_no;
        part_loc->subpart_no = cursor->part_loc.subpart_no;
    } else {
        part_loc->part_no = CT_INVALID_ID24;
        part_loc->subpart_no = CT_INVALID_ID32;
    }
}

static status_t pcrb_alloc_itl(knl_session_t *session, knl_cursor_t *cursor, btree_page_t *page, pcr_itl_t **itl,
                               bool32 *changed)
{
    btree_t *btree = CURSOR_BTREE(cursor);
    bool32 check_next;

    cursor->reused_xid = CT_INVALID_ID64;
    session->itl_id = CT_INVALID_ID8;

    *itl = NULL;

    for (uint8 i = 0; i < page->itls; i++) {
        pcr_itl_t *item = pcrb_get_itl(page, i);
        if (item->xid.value == session->rm->xid.value) {
            session->itl_id = i;  // itl already exists
            *itl = item;
            return CT_SUCCESS;
        }

        if (pcrb_find_available_itl(session, cursor, i, itl, &check_next) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (check_next) {
            continue;
        }
        *changed = CT_TRUE;
    }

    if (*itl == NULL) {
        if (page->itls >= btree->index->desc.maxtrans - 1) {
            session->itl_id = CT_INVALID_ID8;
            return CT_SUCCESS;
        }
        session->itl_id = pcrb_new_itl(session, page);
        if (session->itl_id == CT_INVALID_ID8) {
            return CT_SUCCESS;
        }
    }

    pcrb_init_itl(session, cursor, page, itl);
    *changed = CT_TRUE;

    if (SECUREC_UNLIKELY(DB_NOT_READY(session))) {
        (*itl)->is_active = 0;
        return CT_SUCCESS;
    }

    knl_panic_log(!DB_IS_READONLY(session), "current DB is readonly, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)btree->index)->desc.name);

    knl_part_locate_t part_loc;
    pcrb_alloc_itl_set_part(cursor, &part_loc);
    
    if (lock_itl(session, AS_PAGID(page->head.id), session->itl_id, part_loc, AS_PAGID(page->next),
        LOCK_TYPE_PCR_KX) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static inline void pcrb_clean_dir(knl_session_t *session, btree_page_t *page, uint16 slot)
{
    uint16 j;

    for (j = slot; j < page->keys - 1; j++) {
        *pcrb_get_dir(page, j) = *pcrb_get_dir(page, j + 1);
    }
    page->keys--;
}

void pcrb_compact_page(knl_session_t *session, btree_page_t *page, knl_scn_t min_scn)
{
    pcrb_dir_t *dir = NULL;
    pcrb_key_t *key = NULL;
    pcrb_key_t *free_addr = NULL;
    pcr_itl_t *itl = NULL;
    uint16 key_size;
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, AS_PAGID_PTR(page->head.id)->file)->space_id);

    for (int16 i = 0; i < page->keys; i++) {
        /* keep a non-deleted min key in page to prevent parent delete */
        if (SECUREC_UNLIKELY(page->keys == 1)) {
            dir = pcrb_get_dir(page, 0);
            key = PCRB_GET_KEY(page, dir);

            *dir = key->bitmap;
            if (key->is_cleaned) {
                key->is_cleaned = 0;
            }
            key->bitmap = 0;
            break;
        }

        dir = pcrb_get_dir(page, (uint16)i);
        key = PCRB_GET_KEY(page, dir);
        if (key->is_cleaned) {
            pcrb_clean_dir(session, page, (uint16)i);
            i--;
            continue;
        }

        if (key->is_deleted && page->level == 0) {
            if (key->itl_id == CT_INVALID_ID8) {
                if (page->scn <= min_scn) {
                    key->is_cleaned = 1;
                    pcrb_clean_dir(session, page, (uint16)i);
                    i--;
                    continue;
                }
            } else {
                itl = pcrb_get_itl(page, key->itl_id);
                if (!itl->is_active && itl->scn <= min_scn) {
                    key->is_cleaned = 1;
                    pcrb_clean_dir(session, page, (uint16)i);
                    i--;
                    continue;
                }
            }
        }

        *dir = key->bitmap;
        key->bitmap = (uint16)i;
    }

    key = (pcrb_key_t *)((char *)page + sizeof(btree_page_t) + space->ctrl->cipher_reserve_size);
    free_addr = key;

    while ((char *)key < (char *)page + page->free_begin) {
        knl_panic_log(key->size > 0, "size in key is invalid, panic info: page %u-%u type %u key size %u",
                      AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, key->size);
        if (key->is_cleaned) {
            key = (pcrb_key_t *)((char *)key + key->size);
            continue;
        }

        knl_panic_log(key->bitmap < page->keys,
            "key's bitmap is more than page's keys, panic info: page %u-%u type %u key bitmap %u page keys %u",
            AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, key->bitmap, page->keys);

        key_size = (uint16)key->size;

        if (key != free_addr) {
            errno_t ret = memmove_s(free_addr, key_size, key, key_size);
            knl_securec_check(ret);
        }

        dir = pcrb_get_dir(page, free_addr->bitmap);
        free_addr->bitmap = *dir;
        *dir = (uint16)((char *)free_addr - (char *)page);

        free_addr = (pcrb_key_t *)((char *)free_addr + free_addr->size);
        key = (pcrb_key_t *)((char *)key + key_size);
    }

    page->free_begin = (uint16)((char *)free_addr - (char *)page);
    page->free_end = (uint16)((char *)pcrb_get_dir(page, page->keys - 1) - (char *)page);
    page->free_size = page->free_end - page->free_begin;
}

static void pcrb_get_sibling_key(knl_session_t *session, btree_path_info_t *path_info)
{
    btree_page_t *page = BTREE_CURR_PAGE(session);
    CM_ASSERT(page->level == 1);
    uint32 slot = (uint32)path_info->path[1].slot + 1;
    if (slot == page->keys) {
        page_id_t next_pid = AS_PAGID(page->next);
        if (IS_INVALID_PAGID(next_pid)) {
            return;
        }
        buf_leave_page(session, CT_FALSE);
        buf_enter_page(session, next_pid, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page = BTREE_CURR_PAGE(session);
        slot = 0;
    }

    pcrb_dir_t *dir = pcrb_get_dir(page, slot);
    pcrb_key_t *key = PCRB_GET_KEY(page, dir);
    errno_t ret = memcpy_sp(path_info->sibling_key, CT_KEY_BUF_SIZE, key, (size_t)key->size);
    knl_securec_check(ret);
}

static bool32 pcrb_find_update_pos(knl_session_t *session, btree_find_assist_t *find_assist, bool32 *is_same,
    bool32 *compact_leaf, bool32 logging)
{
    btree_t *btree = find_assist->btree;
    btree_segment_t *seg = BTREE_SEGMENT(session, btree->entry, btree->segment);
    index_t *index = btree->index;
    knl_tree_info_t tree_info;
    knl_scn_t scn;
    btree_page_t *page = NULL;
    pcrb_dir_t *dir = NULL;
    pcrb_key_t *curr_key = NULL;
    bool32 need_redo = SPACE_IS_LOGGING(SPACE_GET(session, seg->space_id)) && logging;
    knl_scn_t snap_scn = DB_CURR_SCN(session);
    btree_find_type org_type = find_assist->find_type;
    bool32 org_compact_leaf = *compact_leaf;

    tree_info.value = cm_atomic_get(&seg->tree_info.value);
    uint32 level = (uint32)tree_info.level - 1;
    page_id_t page_id = AS_PAGID(tree_info.root);

    bool32 cmp_rowid = (index->desc.primary || index->desc.unique) ? CT_FALSE : CT_TRUE;
    uint16 cost_size = sizeof(pcr_itl_t);
    if (find_assist->find_type != BTREE_FIND_DELETE) {
        cost_size = PCRB_COST_SIZE((pcrb_key_t *)find_assist->scan_key->buf) + sizeof(pcr_itl_t);
    }

    for (;;) {
        buf_enter_page(session, page_id, (level == 0) ? LATCH_MODE_X : LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page = BTREE_CURR_PAGE(session);
        if (page_soft_damaged(&page->head)) {
            buf_leave_page(session, CT_FALSE);
            find_assist->page_damage = CT_TRUE;
            find_assist->page_id = page_id;
            return CT_FALSE;
        }

        if (SECUREC_UNLIKELY(page->is_recycled)) {
            buf_leave_page(session, CT_FALSE);
            return CT_FALSE;
        }

        knl_panic_log(level == page->level, "the page's level is abnormal, panic info: page %u-%u type %u index %s "
                      "level %u page_level %u", AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page,
                      page->head.type, index->desc.name, level, page->level);
        if (page->level > 0) {
            snap_scn = KNL_GET_SCN(&seg->recycle_ver_scn);
        }

        if (bt_chk_leaf_recycled(session, btree, page, snap_scn)) {
            buf_leave_page(session, CT_FALSE);
            level = (uint32)tree_info.level - 1;
            page_id = AS_PAGID(tree_info.root);
            find_assist->find_type = org_type;
            *compact_leaf = org_compact_leaf;
            continue;
        }

        SET_ROWID_PAGE(&find_assist->path_info->path[page->level], page_id);
        if (page->level == 0 && find_assist->find_type != BTREE_FIND_DELETE_NEXT &&
            BTREE_NEED_COMPACT(page, cost_size)) {
            if (compact_leaf != NULL) {
                *compact_leaf = CT_TRUE;
            }
            scn = btree_get_recycle_min_scn(session);
            btree->min_scn = scn;
            pcrb_compact_page(session, page, scn);
            if (need_redo) {
                rd_btree_info_t btree_info;
                btree_info.min_scn = scn;
                btree_info.uid = index->desc.uid;
                btree_info.oid = index->desc.table_id;
                btree_info.idx_id = index->desc.id;
                btree_info.part_loc = find_assist->path_info->part_loc;
                log_put(session, RD_PCRB_COMPACT_PAGE, &btree_info, sizeof(rd_btree_info_t), LOG_ENTRY_FLAG_NONE);
            }
        }

        knl_panic_log(page->head.type == PAGE_TYPE_PCRB_NODE,
                      "page type is abnormal, panic info: page %u-%u type %u index %s",
                      AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, index->desc.name);
        knl_panic_log(page->seg_scn == seg->seg_scn, "the seg_scn of page and segment are not same, panic info: "
                      "page %u-%u type %u index %s page seg_scn %llu seg seg_scn %llu", AS_PAGID(page->head.id).file,
                      AS_PAGID(page->head.id).page, page->head.type, index->desc.name, page->seg_scn, seg->seg_scn);

        pcrb_binary_search(INDEX_PROFILE(index), page, find_assist->scan_key, find_assist->path_info, cmp_rowid,
                           is_same);

        if (find_assist->path_info->path[page->level].slot >= page->keys) {
            if (find_assist->find_type == BTREE_FIND_DELETE || find_assist->find_type == BTREE_FIND_DELETE_NEXT) {
                page_id = AS_PAGID(page->next);
                snap_scn = KNL_GET_SCN(&seg->recycle_ver_scn);
                if (IS_INVALID_PAGID(page_id)) {
                    return CT_FALSE;
                }

                buf_leave_page(session, page->level == 0 ? (*compact_leaf) : CT_FALSE);
                *compact_leaf = CT_FALSE;
                find_assist->find_type = BTREE_FIND_DELETE_NEXT;
                continue;
            } else if (find_assist->find_type == BTREE_FIND_INSERT) {
                /*
                 * for insert, if located at the last slot, insert key could be the largest key of this page,
                 * or it could located on next page.
                 */
                buf_leave_page(session, page->level == 0 ? (*compact_leaf) : CT_FALSE);
                *compact_leaf = CT_FALSE;
                return CT_FALSE;
            }
        }

        if (page->level == 0) {
            break;
        }

        dir = pcrb_get_dir(page, (uint32)find_assist->path_info->path[page->level].slot);
        curr_key = PCRB_GET_KEY(page, dir);
        page_id = pcrb_get_child(curr_key);
        level = page->level - 1;
        if (SECUREC_UNLIKELY(find_assist->path_info->get_sibling) && level == 0) {
            pcrb_get_sibling_key(session, find_assist->path_info);
        }
        buf_leave_page(session, CT_FALSE);
    }

    return CT_TRUE;
}

static status_t pcrb_check_level(knl_session_t *session, btree_t *btree, rowid_t *path, uint32 level)
{
    btree_page_t *page = NULL;
    uint16 max_key_size;

    if (level < (uint16)CT_MAX_ROOT_LEVEL) {
        return CT_SUCCESS;
    }

    max_key_size = btree_max_key_size(btree->index) + sizeof(knl_part_locate_t) + sizeof(page_id_t);

    /* check child of root */
    if (buf_read_page(session, GET_ROWID_PAGE(path[CT_MAX_ROOT_LEVEL - 1]), LATCH_MODE_S, ENTER_PAGE_NORMAL) !=
        CT_SUCCESS) {
        return CT_ERROR;
    }
    page = BTREE_CURR_PAGE(session);
    if (max_key_size > page->free_size) {
        buf_leave_page(session, CT_FALSE);
        CT_THROW_ERROR(ERR_BTREE_LEVEL_EXCEEDED, CT_MAX_ROOT_LEVEL);
        return CT_ERROR;
    }
    buf_leave_page(session, CT_FALSE);

    return CT_SUCCESS;
}

static bool32 pcrb_is_equal_key(pcrb_key_t *key1, pcrb_key_t *key2)
{
    char *data1 = NULL;
    char *data2 = NULL;

    if (key1 == NULL || key2 == NULL) {
        return CT_FALSE;
    }

    if (key1->size != key2->size) {
        return CT_FALSE;
    }

    data1 = (char *)key1 + sizeof(pcrb_key_t);
    data2 = (char *)key2 + sizeof(pcrb_key_t);
    if (memcmp(data1, data2, (size_t)key1->size - sizeof(pcrb_key_t)) != 0) {
        return CT_FALSE;
    }
    return CT_TRUE;
}

static bool32 pcrb_is_same_key(index_t *index, pcrb_key_t *key1, pcrb_key_t *key2)
{
    bool32 is_same = CT_FALSE;

    if (!pcrb_is_equal_key(key1, key2)) {
        return CT_FALSE;
    }

    if (index->desc.unique || index->desc.primary) {
        return CT_TRUE;
    } else {
        is_same = IS_SAME_ROWID(key1->rowid, key2->rowid);
        return is_same;
    }
}

static bool32 pcrb_check_self_conflict(knl_session_t *session, knl_cursor_t *cursor, btree_t *btree, pcrb_key_t *key)
{
    undo_snapshot_t *snapshot;
    undo_page_t *ud_page = NULL;
    undo_row_t *ud_row = NULL;

    snapshot = &cursor->snapshot;

    for (;;) {
        buf_enter_page(session, PAGID_U2N(snapshot->undo_page), LATCH_MODE_S, ENTER_PAGE_NORMAL);
        ud_page = (undo_page_t *)CURR_PAGE(session);
        ud_row = UNDO_ROW(session, ud_page, snapshot->undo_slot);
        if (ud_row->ssn < cursor->ssn || ud_row->xid.value != cursor->xid) {
            buf_leave_page(session, CT_FALSE);
            return CT_FALSE;
        }

        if (pcrb_is_same_key(btree->index, key, (pcrb_key_t *)ud_row->data)) {
            buf_leave_page(session, CT_FALSE);
            return CT_TRUE;
        }

        snapshot->undo_page = ud_row->prev_page;
        snapshot->undo_slot = ud_row->prev_slot;
        buf_leave_page(session, CT_FALSE);
    }
}

static status_t pcrb_enter_insert(knl_session_t *session, knl_cursor_t *cursor, btree_path_info_t *path_info,
    bool32 is_rebuild, bool32 *is_same, bool32 *changed, idx_conflict_info_t *conflict_info)
{
    pcr_itl_t *itl = NULL;
    knl_scan_key_t scan_key;
    int64 version;
    btree_find_assist_t find_assist;
    bool32 lock_tree = path_info->get_sibling;
    btree_t *btree = CURSOR_BTREE(cursor);
    pcrb_key_t *key = (pcrb_key_t *)cursor->key;
    uint32 level;

    pcrb_decode_key(INDEX_PROFILE(btree->index), key, &scan_key);
    path_info->part_loc = cursor->part_loc;
    for (;;) {
        *changed = CT_FALSE;
        log_atomic_op_begin(session);
        log_set_group_nolog_insert(session, cursor->logging);
        if (lock_tree) {
            dls_latch_s(session, &btree->struct_latch, session->id, CT_FALSE, &session->stat_btree);
            version = cm_atomic_get(&btree->struct_ver);
            level = BTREE_SEGMENT(session, btree->entry, btree->segment)->tree_info.level;
            btree_init_find_assist(btree, path_info, &scan_key, BTREE_FIND_INSERT_LOCKED, &find_assist);
            (void)pcrb_find_update_pos(session, &find_assist, is_same, changed, cursor->logging);
            dls_unlatch(session, &btree->struct_latch, &session->stat_btree);
            lock_tree = path_info->get_sibling;
        } else {
            version = cm_atomic_get(&btree->struct_ver);
            level = BTREE_SEGMENT(session, btree->entry, btree->segment)->tree_info.level;
            btree_init_find_assist(btree, path_info, &scan_key, BTREE_FIND_INSERT, &find_assist);
            bool32 find_result = pcrb_find_update_pos(session, &find_assist, is_same, changed, cursor->logging);
            if (find_assist.page_damage) {
                log_atomic_op_end(session);
                CT_THROW_ERROR(ERR_PAGE_SOFT_DAMAGED, find_assist.page_id.file, find_assist.page_id.page);
                return CT_ERROR;
            }

            if (!find_result) {
                log_atomic_op_end(session);
                lock_tree = CT_TRUE;
                continue;
            }
        }

        if (find_assist.page_damage) {
            log_atomic_op_end(session);
            CT_THROW_ERROR(ERR_PAGE_SOFT_DAMAGED, find_assist.page_id.file, find_assist.page_id.page);
            return CT_ERROR;
        }

        btree_page_t *page = BTREE_CURR_PAGE(session);
        uint16 pct_size = ((is_rebuild || btree->is_shadow) &&
                           PCRB_MAX_COST_SIZE(key) <= DEFAULT_PAGE_SIZE(session) - BTREE_PCT_SIZE(btree))
                            ? BTREE_PCT_SIZE(btree) : (uint16)0;
        if (!*is_same && page->free_size < PCRB_MAX_COST_SIZE(key) + pct_size) {
            path_info->leaf_lsn = page->head.lsn;
            uint64 trigger_version = DRC_GET_CURR_REFORM_VERSION;
            buf_leave_page(session, *changed);

            if (pcrb_check_level(session, btree, path_info->path, level) != CT_SUCCESS) {
                log_atomic_op_end(session);
                knl_end_itl_waits(session);
                return CT_ERROR;
            }

            log_atomic_op_end(session);

            if (*changed) {
                path_info->leaf_lsn = session->curr_lsn;
            }

            path_info->is_rebuild = is_rebuild;
            if (pcrb_try_split_page(session, cursor, path_info, version, (pct_size != 0), trigger_version) != CT_SUCCESS) {
                knl_end_itl_waits(session);
                return CT_ERROR;
            }
            continue;
        }

        if (pcrb_check_unique(session, cursor, path_info->path, *is_same, conflict_info) != CT_SUCCESS) {
            buf_leave_page(session, *changed);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            if (!conflict_info->conflict && cursor->snapshot.is_valid) {
                conflict_info->conflict = pcrb_check_self_conflict(session, cursor, btree, key);
            }

            return CT_ERROR;
        }

        if (session->wxid.value != CT_INVALID_ID64) {
            buf_leave_page(session, *changed);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            btree->stat.row_lock_waits++;
            if (tx_wait(session, session->lock_wait_timeout, ENQ_TX_KEY) != CT_SUCCESS) {
                tx_record_rowid(session->wrid);
                return CT_ERROR;
            }
            continue;
        }

        /* shadow index rebuilding no need to alloc itl here */
        if (SECUREC_UNLIKELY(is_rebuild)) {
            knl_end_itl_waits(session);
            return CT_SUCCESS;
        }

        if (pcrb_alloc_itl(session, cursor, page, &itl, changed) != CT_SUCCESS) {
            buf_leave_page(session, *changed);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            return CT_ERROR;
        }

        if (SECUREC_UNLIKELY(itl == NULL)) {
            session->wpid = AS_PAGID(page->head.id);
            buf_leave_page(session, *changed);
            log_atomic_op_end(session);
            if (knl_begin_itl_waits(session, &btree->stat.itl_waits) != CT_SUCCESS) {
                knl_end_itl_waits(session);
                return CT_ERROR;
            }
            continue;
        }
        knl_end_itl_waits(session);
        break;
    }

    return CT_SUCCESS;
}

void pcrb_insert_into_page(knl_session_t *session, btree_page_t *page, pcrb_key_t *key, rd_pcrb_insert_t *redo)
{
    pcrb_dir_t *dir = NULL;
    pcrb_key_t *curr_key = NULL;
    uint32 i;
    errno_t ret;

    if (redo->is_reuse) {
        dir = pcrb_get_dir(page, redo->slot);
        curr_key = PCRB_GET_KEY(page, dir);
        if (curr_key->is_cleaned) {
            page->free_size -= (uint16)curr_key->size + sizeof(pcrb_dir_t);
        }

        ret = memcpy_sp(curr_key, CT_KEY_BUF_SIZE, key, (size_t)key->size);
        knl_securec_check(ret);
    } else {
        if (redo->slot < page->keys) {
            for (i = page->keys; i > redo->slot; i--) {
                *pcrb_get_dir(page, i) = *pcrb_get_dir(page, i - 1);
            }
        }

        curr_key = (pcrb_key_t *)((char *)page + page->free_begin);
        dir = pcrb_get_dir(page, redo->slot);
        *dir = page->free_begin;

        ret = memcpy_sp(curr_key, CT_KEY_BUF_SIZE, key, (size_t)key->size);
        knl_securec_check(ret);

        page->free_begin += (uint16)key->size;
        page->free_end -= sizeof(pcrb_dir_t);
        page->free_size -= ((uint16)key->size + sizeof(pcrb_dir_t));
        page->keys++;
    }
}

static void pcrb_generate_insert_undo(knl_session_t *session, knl_cursor_t *cursor, rowid_t *path, bool32 is_same,
                                      undo_data_t *undo)
{
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);
    btree_t *btree = CURSOR_BTREE(cursor);
    btree_page_t *page = BTREE_CURR_PAGE(session);
    pcrb_key_t *key = (pcrb_key_t *)cursor->key;
    knl_part_locate_t part_loc = { .part_no = CT_INVALID_ID32,
        .subpart_no = CT_INVALID_ID32 };

    if (IS_PART_INDEX(cursor->index)) {
        part_loc = cursor->part_loc;
    }

    undo->data = (char *)cm_push(session->stack, undo->size);

    if (is_same) {
        pcrb_dir_t *dir = pcrb_get_dir(page, (uint32)path[0].slot);
        pcrb_key_t *old_key = PCRB_GET_KEY(page, dir);
        if (btree->is_shadow && !old_key->is_deleted) {
            undo->snapshot.is_xfirst = CT_TRUE;
            errno_t ret = memcpy_sp(undo->data, undo->size, key, (size_t)key->size);
            knl_securec_check(ret);
        } else {
            undo->snapshot.is_xfirst = (old_key->itl_id != session->itl_id);
            errno_t ret = memcpy_sp(undo->data, undo->size, old_key, (size_t)old_key->size);
            knl_securec_check(ret);
        }
    } else {
        undo->snapshot.is_xfirst = CT_TRUE;
        errno_t ret = memcpy_sp(undo->data, undo->size, key, (size_t)key->size);
        knl_securec_check(ret);
    }

    table_t *table = (table_t *)cursor->table;
    uint32 partloc_size = undo_part_locate_size(table);
    errno_t ret = memcpy_sp(undo->data + key->size, partloc_size, &part_loc, partloc_size);
    knl_securec_check(ret);

    pcr_itl_t *itl = pcrb_get_itl(page, session->itl_id);

    undo->snapshot.scn = DB_CURR_SCN(session);
    undo->snapshot.is_owscn = itl->is_owscn;
    undo->snapshot.undo_page = itl->undo_page;
    undo->snapshot.undo_slot = itl->undo_slot;
    undo->snapshot.contain_subpartno = (IS_PART_TABLE(table) && IS_COMPART_TABLE(table->part_table));
    undo->ssn = (uint32)cursor->ssn;

    undo->type = UNDO_PCRB_INSERT;
    undo->seg_page = btree->entry.page;
    undo->seg_file = btree->entry.file;
    undo->index_id = (btree->is_shadow) ? CT_SHADOW_INDEX_ID : btree->index->desc.id;

    itl->undo_page = undo_page_info->undo_rid.page_id;
    itl->undo_slot = undo_page_info->undo_rid.slot;
    itl->ssn = (uint32)cursor->ssn;

    if (cursor->nologging_type != SESSION_LEVEL) {
        undo_write(session, undo, need_redo, !cursor->logging);
    }

    cm_pop(session->stack);
}

static inline void pcrb_leave_insert(knl_session_t *session)
{
    buf_leave_page(session, CT_TRUE);
    log_atomic_op_end(session);
}

static status_t pcrb_do_insert(knl_session_t *session, knl_cursor_t *cursor, idx_conflict_info_t *conflict_info)
{
    btree_t *btree = CURSOR_BTREE(cursor);
    btree_path_info_t path_info;
    bool32 page_changed = CT_FALSE;
    bool32 is_same = CT_FALSE;
    undo_data_t undo;
    rd_pcrb_insert_t redo;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(btree->cipher_reserve_size);

    pcrb_key_t *key = (pcrb_key_t *)cursor->key;
    table_t *table = (table_t *)cursor->table;
    undo.size = (uint32)key->size + undo_part_locate_size(table);

    /* We prepare two undo rows (itl undo and insert undo) */
    if (cursor->nologging_type != SESSION_LEVEL) {
        if (undo_multi_prepare(session, PCRB_INSERT_UNDO_COUNT, sizeof(xid_t) + undo.size, need_redo,
            need_encrypt) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    path_info.get_sibling = CT_FALSE;
    if (pcrb_enter_insert(session, cursor, &path_info, CT_FALSE, &is_same,
        &page_changed, conflict_info) != CT_SUCCESS) {
        return CT_ERROR;
    }

    btree_page_t *page = BTREE_CURR_PAGE(session);
    page_id_t next_pid = AS_PAGID(page->next);

    key->is_deleted = CT_FALSE;
    key->itl_id = session->itl_id;

    redo.is_reuse = (uint16)is_same;
    redo.slot = (uint16)path_info.path[0].slot;
    redo.ssn = (uint32)cursor->ssn;
    redo.undo_page = undo_page_info->undo_rid.page_id;
    redo.undo_slot = undo_page_info->undo_rid.slot;

    pcrb_generate_insert_undo(session, cursor, path_info.path, is_same, &undo);
    pcrb_insert_into_page(session, page, key, &redo);
    if (need_redo && cursor->logging) {
        log_encrypt_prepare(session, page->head.type, need_encrypt);
        log_put(session, RD_PCRB_INSERT, &redo, (uint32)OFFSET_OF(rd_pcrb_insert_t, key), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, key, (uint32)key->size);
    }

    pcrb_validate_page(session, &page->head, btree->index);
    pcrb_leave_insert(session);

    if (cursor->reused_xid != CT_INVALID_ID64 && !IS_INVALID_PAGID(next_pid)) {
        (void)pcrb_clean_copied_itl(session, cursor->reused_xid, next_pid);
    }

    if (KNL_IDX_RECYCLE_ENABLED(session->kernel)) {
        btree->chg_stats.insert_size += PCRB_COST_SIZE((pcrb_key_t *)cursor->key);
    }

    return CT_SUCCESS;
}

static void pcrb_generate_batch_insert_undo(knl_session_t *session, knl_cursor_t *cursor, const char *insert_keys,
    uint32 key_count, uint32 key_size)
{
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);
    btree_t *btree = CURSOR_BTREE(cursor);
    btree_page_t *page = BTREE_CURR_PAGE(session);
    pcr_itl_t *itl = pcrb_get_itl(page, session->itl_id);
    undo_data_t undo;
    undo.size = CM_ALIGN4(OFFSET_OF(pcrb_undo_batch_insert_t, keys) + key_size);
    pcrb_undo_batch_insert_t *undo_insert = (pcrb_undo_batch_insert_t *)cm_push(session->stack, undo.size);

    if (IS_PART_INDEX(cursor->index)) {
        undo_insert->part_loc = cursor->part_loc;
    } else {
        undo_insert->part_loc.part_no = CT_INVALID_ID32;
        undo_insert->part_loc.subpart_no = CT_INVALID_ID32;
    }
    undo_insert->count = key_count;
    undo_insert->aligned = 0;

    undo.snapshot.is_xfirst = CT_FALSE;
    undo.snapshot.scn = DB_CURR_SCN(session);
    undo.snapshot.is_owscn = itl->is_owscn;
    undo.snapshot.undo_page = itl->undo_page;
    undo.snapshot.undo_slot = itl->undo_slot;
    undo.ssn = (uint32)cursor->ssn;

    undo.type = UNDO_PCRB_BATCH_INSERT;
    undo.seg_page = btree->entry.page;
    undo.seg_file = btree->entry.file;
    undo.index_id = btree->index->desc.id;

    if (cursor->nologging_type != SESSION_LEVEL) {
        itl->undo_page = undo_page_info->undo_rid.page_id;
        itl->undo_slot = undo_page_info->undo_rid.slot;
    } else {
        itl->undo_page = INVALID_UNDO_PAGID;
        itl->undo_slot = CT_INVALID_ID16;
    }

    itl->ssn = (uint32)cursor->ssn;
    errno_t ret = memcpy_sp(undo_insert->keys, key_size, (const void *)insert_keys, key_size);
    knl_securec_check(ret);
    undo.data = (char *)undo_insert;
    if (cursor->nologging_type != SESSION_LEVEL) {
        undo_write(session, &undo, need_redo, !cursor->logging);
    }
    cm_pop(session->stack);
}

static bool32 pcrb_is_batch_insert_enable(knl_session_t *session, knl_cursor_t *cursor, pcrb_key_t *sibling_key,
                                          pcrb_key_t *src_key, rd_pcrb_insert_t *rd_insert)
{
    btree_t *btree = CURSOR_BTREE(cursor);
    btree_page_t *page = BTREE_CURR_PAGE(session);
    knl_scan_key_t scan_key;
    idx_conflict_info_t conflict_info = { CT_FALSE, CT_FALSE };
    bool32 cmp_rowid = !IS_UNIQUE_PRIMARY_INDEX(btree->index);
    btree_path_info_t path_info;
    bool32 is_same = CT_FALSE;
    index_profile_t *profile = INDEX_PROFILE(btree->index);

    rd_insert->slot = INVALID_SLOT;

    pcrb_decode_key(profile, src_key, &scan_key);
    if (sibling_key != NULL) {
        if (pcrb_compare_key(profile, &scan_key, sibling_key, cmp_rowid, NULL) >= 0) {
            return CT_FALSE;
        }
    }

    pcrb_binary_search(profile, page, &scan_key, &path_info, cmp_rowid, &is_same);

    if (!is_same && page->free_end - page->free_begin < src_key->size + sizeof(pcrb_dir_t)) {
        return CT_FALSE;
    }

    if (pcrb_check_unique(session, cursor, path_info.path, is_same, &conflict_info) != CT_SUCCESS) {
        cm_reset_error();
        return CT_FALSE;
    }

    rd_insert->is_reuse = (uint16)is_same;
    rd_insert->slot = (uint16)path_info.path[0].slot;

    if (session->wxid.value != CT_INVALID_ID64) {
        session->wxid.value = CT_INVALID_ID64;
        return CT_FALSE;
    }
    return CT_TRUE;
}

static void pcrb_batch_insert_key(knl_session_t *session, uint16 undo_size, rd_pcrb_insert_t *rd_insert,
                                  pcrb_key_t *src_key, pcrb_key_t *ud_key)
{
    btree_page_t *page = BTREE_CURR_PAGE(session);
    errno_t ret;

    if (rd_insert->is_reuse) {
        pcrb_dir_t *old_dir = pcrb_get_dir(page, rd_insert->slot);
        pcrb_key_t *old_key = PCRB_GET_KEY(page, old_dir);
        ret = memcpy_sp((void *)ud_key, undo_size, old_key, (size_t)old_key->size);
        knl_securec_check(ret);
        ud_key->itl_id = (old_key->itl_id == session->itl_id) ? old_key->itl_id : CT_INVALID_ID8;
    } else {
        ret = memcpy_sp((void *)ud_key, undo_size, src_key, (size_t)src_key->size);
        knl_securec_check(ret);
        ud_key->itl_id = CT_INVALID_ID8;
    }

    pcrb_insert_into_page(session, page, src_key, rd_insert);
}

static uint64 pcrb_batch_insert_keys(knl_session_t *session, knl_cursor_t *cursor, uint16 *batch_size,
                                     pcrb_key_t *sibling_key, bool32 *need_wait)
{
    btree_page_t *src_page = (btree_page_t *)cursor->buf;
    char *undo_data = (char *)cm_push(session->stack, UNDO_MAX_ROW_SIZE(session));
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);
    pcrb_dir_t *src_dir = NULL;
    pcrb_key_t *src_key = NULL;
    pcrb_key_t *ud_key = NULL;
    uint16 key_size = 0;
    uint32 keys = 0;
    uint64 keys_size = 0;
    rd_pcrb_insert_t redo;

    redo.ssn = (uint32)cursor->ssn;
    redo.undo_page = undo_page_info->undo_rid.page_id;
    redo.undo_slot = undo_page_info->undo_rid.slot;
    *need_wait = CT_FALSE;

    for (uint32 i = 1; i < src_page->keys; i++) {
        src_dir = pcrb_get_dir(src_page, i);
        src_key = PCRB_GET_KEY(src_page, src_dir);
        if (src_key->is_cleaned) {
            continue;
        }

        if (!pcrb_is_batch_insert_enable(session, cursor, sibling_key, src_key, &redo)) {
            *need_wait = (redo.slot != INVALID_SLOT);
            break;
        }

        src_key->itl_id = session->itl_id;
        src_key->is_deleted = CT_FALSE;
        ud_key = (pcrb_key_t *)(undo_data + key_size);
        pcrb_batch_insert_key(session, *batch_size - key_size, &redo, src_key, ud_key);

        if (need_redo && cursor->logging) {
            log_put(session, RD_PCRB_INSERT, &redo, (uint32)OFFSET_OF(rd_pcrb_insert_t, key), LOG_ENTRY_FLAG_NONE);
            log_append_data(session, src_key, (uint32)src_key->size);
        }

        key_size += (uint16)src_key->size;
        src_key->is_cleaned = CT_TRUE;
        keys++;
        keys_size += PCRB_COST_SIZE(src_key);
    }

    if (keys > 0) {
        pcrb_generate_batch_insert_undo(session, cursor, undo_data, keys, key_size);
        *batch_size -= key_size;
    }

    cm_pop(session->stack);

    return keys_size;
}

static status_t pcrb_enter_batch_insert(knl_session_t *session, knl_cursor_t *cursor, bool32 need_redo,
    bool32 *page_changed, pcrb_key_t *sibling_key)
{
    bool32 is_same = CT_FALSE;
    idx_conflict_info_t conflict_info = { CT_FALSE, CT_FALSE };
    btree_path_info_t path_info;

    path_info.get_sibling = CT_TRUE;
    path_info.sibling_key = (char *)sibling_key;
    if (pcrb_enter_insert(session, cursor, &path_info, CT_FALSE, &is_same,
        page_changed, &conflict_info) != CT_SUCCESS) {
        return CT_ERROR;
    }

    btree_page_t *page = BTREE_CURR_PAGE(session);
    if (page->free_size > page->free_end - page->free_begin) {
        btree_t *btree = CURSOR_BTREE(cursor);
        index_t *index = btree->index;
        knl_scn_t scn = btree_get_recycle_min_scn(session);
        btree->min_scn = scn;
        pcrb_compact_page(session, page, scn);
        if (need_redo) {
            rd_btree_info_t btree_info;
            btree_info.min_scn = scn;
            btree_info.uid = index->desc.uid;
            btree_info.oid = index->desc.table_id;
            btree_info.idx_id = index->desc.id;
            btree_info.part_loc = path_info.part_loc;
            log_put(session, RD_PCRB_COMPACT_PAGE, &btree_info, sizeof(rd_btree_info_t), LOG_ENTRY_FLAG_NONE);
        }
    }

    return CT_SUCCESS;
}

static status_t pcrb_do_batch_insert(knl_session_t *session, knl_cursor_t *cursor, btree_page_t *src_page,
                                     bool32 *need_wait, uint16 *batch_size)
{
    btree_t *btree = CURSOR_BTREE(cursor);
    bool32 page_changed = CT_FALSE;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(btree->cipher_reserve_size);
    uint32 undo_size = CM_ALIGN4(OFFSET_OF(pcrb_undo_batch_insert_t, keys) + *batch_size);
    /* We prepare two undo rows (itl undo and insert undo) */
    if (cursor->nologging_type != SESSION_LEVEL) {
        if (undo_multi_prepare(session, PCRB_INSERT_UNDO_COUNT, sizeof(xid_t) + undo_size, need_redo, need_encrypt) !=
            CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    CM_SAVE_STACK(session->stack);
    pcrb_key_t *sibling_key = cm_push(session->stack, CT_KEY_BUF_SIZE);
    if (pcrb_enter_batch_insert(session, cursor, need_redo, &page_changed, sibling_key) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    btree_page_t *page = BTREE_CURR_PAGE(session);
    page_id_t next_pid = AS_PAGID(page->next);
    uint64 keys_size = pcrb_batch_insert_keys(session, cursor, batch_size,
        IS_INVALID_PAGID(next_pid) ? NULL : sibling_key, need_wait);
    if (keys_size > 0) {
        page_changed = CT_TRUE;
    }

    buf_leave_page(session, page_changed);
    log_atomic_op_end(session);

    if (cursor->reused_xid != CT_INVALID_ID64 && !IS_INVALID_PAGID(next_pid)) {
        (void)pcrb_clean_copied_itl(session, cursor->reused_xid, next_pid);
    }

    if (KNL_IDX_RECYCLE_ENABLED(session->kernel)) {
        btree->chg_stats.insert_size += (int64)keys_size;
    }

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

static status_t pcrb_try_batch_insert(knl_session_t *session, knl_cursor_t *cursor, btree_page_t *src_page,
                                      uint16 *batch_size)
{
    bool32 need_retry = CT_FALSE;
    uint16 rest_size;
    idx_conflict_info_t conflict_info = { CT_FALSE, CT_FALSE };

    if (*batch_size == 0) {
        return CT_SUCCESS;
    }

    while (*batch_size > 0) {
        rest_size = *batch_size;
        pcrb_dir_t *dir = pcrb_get_dir(src_page, 1);
        pcrb_key_t *key = PCRB_GET_KEY(src_page, dir);
        errno_t ret = memcpy_sp(cursor->key, CT_KEY_BUF_SIZE, key, (size_t)key->size);
        knl_securec_check(ret);

        if (pcrb_do_batch_insert(session, cursor, src_page, &need_retry, &rest_size) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (*batch_size > rest_size) {
            *batch_size = rest_size;
            /* compact sort page, no need to write redo log */
            pcrb_compact_page(session, src_page, 0);
            if (rest_size == 0) {
                break;
            }
        }

        if (need_retry) {
            pcrb_dir_t *dir1 = pcrb_get_dir(src_page, 1);
            pcrb_key_t *key1 = PCRB_GET_KEY(src_page, dir1);
            ret = memcpy_sp(cursor->key, CT_KEY_BUF_SIZE, key1, (size_t)key1->size);
            knl_securec_check(ret);

            if (pcrb_do_insert(session, cursor, &conflict_info) != CT_SUCCESS) {
                return CT_ERROR;
            }

            key1->is_cleaned = 1;
            /* compact sort page, no need to write redo log */
            (*batch_size) -= (uint16)key1->size;
            pcrb_compact_page(session, src_page, 0);
        }
    }

    CM_ASSERT(src_page->free_size == src_page->free_end - src_page->free_begin);
    return CT_SUCCESS;
}

static status_t pcrb_prepare_batch_insert(knl_session_t *session, knl_cursor_t *cursor)
{
    btree_t *btree = CURSOR_BTREE(cursor);
    btree_page_t *page = (btree_page_t *)cursor->buf;

    if (SECUREC_UNLIKELY(btree->segment == NULL)) {
        if (IS_PART_INDEX(btree->index)) {
            knl_panic_log(cursor->index_part != NULL,
                          "the index_part is NULL, panic info: page %u-%u type %u table %s index %s",
                          cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                          ((table_t *)cursor->table)->desc.name, ((index_t *)btree->index)->desc.name);
            if (btree_create_part_entry(session, btree, cursor->index_part, cursor->part_loc) != CT_SUCCESS) {
                return CT_ERROR;
            }
        } else {
            if (btree_create_entry(session, btree) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    rd_btree_page_init_t redo;
    redo.cr_mode = btree->segment->cr_mode;
    redo.seg_scn = btree->segment->seg_scn;
    redo.level = 0;
    redo.page_id = btree->entry;
    redo.itls = 0;
    redo.extent_size = 0;
    redo.reserve_ext = 0;
    redo.aligned = 0;
    redo.unused = 0;
    btree_init_page(session, page, &redo);
    pcrb_key_t min_key;
    pcrb_init_key(&min_key, NULL);
    min_key.is_infinite = CT_TRUE;
    errno_t ret = memcpy_sp((char *)page + page->free_begin, DEFAULT_PAGE_SIZE(session) - page->free_begin, &min_key,
                            sizeof(pcrb_key_t));
    knl_securec_check(ret);

    pcrb_dir_t *dir = pcrb_get_dir(page, 0);
    *dir = page->free_begin;
    page->free_begin += sizeof(pcrb_key_t);
    page->free_end -= sizeof(pcrb_dir_t);
    page->free_size -= sizeof(pcrb_key_t) + sizeof(pcrb_dir_t);
    page->keys = 1;
    return CT_SUCCESS;
}

static status_t pcrb_insert_into_sort_page(knl_session_t *session, btree_t *btree,
    btree_page_t *page, pcrb_key_t *key)
{
    rd_pcrb_insert_t rd_insert = { .ssn = 0, .is_reuse = CT_FALSE, .undo_page = INVALID_UNDO_PAGID };
    btree_path_info_t path_info;
    knl_scan_key_t scan_key;
    bool32 cmp_rid = !IS_UNIQUE_PRIMARY_INDEX(btree->index);
    bool32 is_same = CT_FALSE;

    pcrb_decode_key(INDEX_PROFILE(btree->index), key, &scan_key);
    pcrb_binary_search(INDEX_PROFILE(btree->index), page, &scan_key, &path_info, cmp_rid, &is_same);
    if (is_same) {
        return idx_generate_dupkey_error(session, btree->index, (char *)key);
    }

    rd_insert.slot = (uint16)path_info.path[0].slot;
    pcrb_insert_into_page(session, page, key, &rd_insert);

    return CT_SUCCESS;
}

status_t pcrb_batch_insert(knl_handle_t handle, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)handle;
    btree_t *btree = CURSOR_BTREE(cursor);
    btree_page_t *page = (btree_page_t *)cursor->buf;

    if (pcrb_prepare_batch_insert(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    row_head_t *org_row = cursor->row;
    uint16 batch_size = 0;
    uint32 max_batch_size = undo_max_prepare_size(session, PCRB_INSERT_UNDO_COUNT) - sizeof(xid_t) -
                            OFFSET_OF(pcrb_undo_batch_insert_t, keys);
    pcrb_key_t *key = (pcrb_key_t *)cm_push(session->stack, CT_KEY_BUF_SIZE);
    status_t status = CT_SUCCESS;

    for (uint32 i = 0; i < cursor->rowid_count; i++) {
        cursor->rowid = cursor->rowid_array[i];
        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);
        if (knl_make_key(session, cursor, btree->index, (char *)key) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (batch_size + key->size > max_batch_size || page->keys > PCRB_MAX_BATCH_INSERT_SIZE ||
            page->free_size < PCRB_COST_SIZE(key)) {
            if (pcrb_try_batch_insert(session, cursor, page, &batch_size) != CT_SUCCESS) {
                status = CT_ERROR;
                break;
            }

            CM_ASSERT(page->free_size >= PCRB_COST_SIZE(key));
        }

        status = pcrb_insert_into_sort_page(session, btree, page, key);
        if (status != CT_SUCCESS) {
            break;
        }

        cursor->row = (row_head_t *)((char *)cursor->row + cursor->row->size);
        batch_size += (uint16)key->size;
    }

    if (status == CT_SUCCESS) {
        status = pcrb_try_batch_insert(session, cursor, page, &batch_size);
    }

    cm_pop(session->stack);
    cursor->row = org_row;
    knl_panic_log(status != CT_SUCCESS || batch_size == 0, "batch insert SUCCESS but batch_size is not zero, "
                  "panic info: page %u-%u type %u, table %s index %s batch_size %u",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)btree->index)->desc.name, batch_size);
    return status;
}

static status_t pcrb_force_update_dupkey(knl_session_t *session, knl_cursor_t *cursor)
{
    pcrb_key_t *key = (pcrb_key_t *)cursor->key;
    rowid_t curr_rid;
    knl_handle_t index = (index_t *)cursor->index;
    knl_handle_t part = cursor->index_part;
    shadow_index_t *shadow_entity = ((table_t *)cursor->table)->shadow_index;
    idx_conflict_info_t conflict_info = { CT_FALSE, CT_FALSE };
    status_t status = CT_SUCCESS;

    session->rm->idx_conflicts++; /* could not overflow, we won't have a table with 2^64 rows */
    ROWID_COPY(curr_rid, key->rowid);
    ROWID_COPY(key->rowid, cursor->conflict_rid); /* Note : cursor->conflict_rid is rowid which duplicated with current
                                                     row */
    ROWID_COPY(cursor->rowid, cursor->conflict_rid); /* to keep cursor->rowid == key->rowid while deleting keys */

    do {
        if (pcrb_delete(session, cursor) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (shadow_entity != NULL) {
            /*
             * this only happened while rebuild index online,
             * if there is a conflict on original index, there must be a same conflict on shadow index
             * pcrb_delete will try to insert and delete a key which conflicts with exist keys, so
             * session->idx_conflicts should +1 and do same operations on shadow index,
             */
            if (!btree_get_index_shadow(session, cursor, shadow_entity)) {
                status = CT_SUCCESS;
                break;
            }

            session->rm->idx_conflicts++;
            if (pcrb_delete(session, cursor) != CT_SUCCESS) {
                status = CT_ERROR;
                break;
            }
        }
    } while (0);

    // revert cursor variable
    cursor->index = index;
    cursor->index_part = part;
    ROWID_COPY(cursor->rowid, curr_rid);
    ROWID_COPY(key->rowid, curr_rid);

    if (status != CT_SUCCESS) {
        return status;
    }

    return pcrb_do_insert(session, cursor, &conflict_info);
}

status_t pcrb_insert(knl_session_t *session, knl_cursor_t *cursor)
{
    btree_t *btree;
    idx_conflict_info_t conflict_info = { CT_FALSE, CT_FALSE };
    io_record_stat_t io_stat = IO_STAT_SUCCESS;
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_KNL_PCRB_INSERT, &tv_begin);

    btree = CURSOR_BTREE(cursor);
    if (SECUREC_UNLIKELY(btree->segment == NULL)) {
        if (IS_PART_INDEX(btree->index)) {
            knl_panic_log(cursor->index_part != NULL, "current index_part is NULL, panic info: page %u-%u type %u, "
                "table %s, index %s", cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                ((table_t *)cursor->table)->desc.name, ((index_t *)btree->index)->desc.name);
            if (btree_create_part_entry(session, btree, cursor->index_part, cursor->part_loc) != CT_SUCCESS) {
                cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_PCRB_INSERT, &tv_begin, IO_STAT_FAILED);
                return CT_ERROR;
            }
        } else {
            if (btree_create_entry(session, btree) != CT_SUCCESS) {
                cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_PCRB_INSERT, &tv_begin, IO_STAT_FAILED);
                return CT_ERROR;
            }
        }
    }

    if (pcrb_do_insert(session, cursor, &conflict_info) != CT_SUCCESS) {
        if (!conflict_info.is_duplicate || conflict_info.conflict) {
            cursor->query_scn = DB_CURR_SCN(session);
            cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_PCRB_INSERT, &tv_begin, IO_STAT_FAILED);
            return CT_ERROR;
        }
        status_t status;
        cm_reset_error();
        status = pcrb_force_update_dupkey(session, cursor);
        io_stat = (status == CT_SUCCESS ? IO_STAT_SUCCESS : IO_STAT_FAILED);
        cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_PCRB_INSERT, &tv_begin, io_stat);
        return status;
    }
    cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_PCRB_INSERT, &tv_begin, IO_STAT_SUCCESS);
    return CT_SUCCESS;
}

status_t pcrb_insert_into_shadow(knl_session_t *session, knl_cursor_t *cursor)
{
    btree_path_info_t path_info;
    bool32 is_same = CT_FALSE;
    bool32 page_changed = CT_FALSE;
    btree_page_t *page = NULL;
    pcrb_key_t *key;
    idx_conflict_info_t conflict_info = { CT_FALSE, CT_FALSE };
    rd_pcrb_insert_t redo;
    btree_t *btree = CURSOR_BTREE(cursor);
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(btree->cipher_reserve_size);

    key = (pcrb_key_t *)cursor->key;

    path_info.get_sibling = CT_FALSE;
    if (pcrb_enter_insert(session, cursor, &path_info, CT_TRUE,
        &is_same, &page_changed, &conflict_info) != CT_SUCCESS) {
        return CT_ERROR;
    }

    page = BTREE_CURR_PAGE(session);
    if (is_same) {
        pcrb_dir_t *dir = pcrb_get_dir(page, (uint32)path_info.path[0].slot);
        pcrb_key_t *same_key = PCRB_GET_KEY(page, dir);

        if (IS_SAME_ROWID(same_key->rowid, key->rowid)) {
            buf_leave_page(session, page_changed);
            log_atomic_op_end(session);
            return CT_SUCCESS;
        }
    }

    redo.slot = (uint16)path_info.path[0].slot;
    redo.is_reuse = is_same;
    redo.ssn = 0;
    redo.undo_page = INVALID_UNDO_PAGID;
    redo.undo_slot = INVALID_SLOT;

    key->is_deleted = CT_FALSE;
    key->itl_id = CT_INVALID_ID8;
    pcrb_insert_into_page(session, page, key, &redo);

    if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type) && cursor->logging) {
        log_encrypt_prepare(session, page->head.type, need_encrypt);
        log_put(session, RD_PCRB_INSERT, &redo, (uint32)OFFSET_OF(rd_pcrb_insert_t, key), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, key, (uint32)key->size);
    }

    pcrb_validate_page(session, &page->head, btree->index);
    buf_leave_page(session, CT_TRUE);

    log_atomic_op_end(session);

    return CT_SUCCESS;
}

static status_t pcrb_need_wait(knl_session_t *session, knl_cursor_t *cursor, btree_page_t *page, pcrb_key_t *key,
                               bool32 *need_wait)
{
    pcr_itl_t *itl = NULL;
    txn_info_t txn_info;

    if (key->itl_id == CT_INVALID_ID8) {
        return CT_SUCCESS;
    }

    itl = pcrb_get_itl(page, key->itl_id);
    if (itl->xid.value == session->rm->xid.value) {
        return CT_SUCCESS;
    }

    tx_get_pcr_itl_info(session, CT_FALSE, itl, &txn_info);
    if (txn_info.status != (uint8)XACT_END) {
        ROWID_COPY(session->wrid, key->rowid);
        session->wxid = itl->xid;
        *need_wait = CT_TRUE;
        return CT_SUCCESS;
    }

    /* transaction has committed, we need to check if it is visible for serializible isolation */
    if (cursor->isolevel == (uint8)ISOLATION_SERIALIZABLE && cursor->query_scn < txn_info.scn) {
        CT_THROW_ERROR(ERR_SERIALIZE_ACCESS);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t pcrb_enter_delete(knl_session_t *session, knl_cursor_t *cursor, btree_path_info_t *path_info,
                                  bool32 *is_found)
{
    btree_t *btree = NULL;
    btree_page_t *page = NULL;
    pcr_itl_t *itl = NULL;
    pcrb_key_t *key = NULL;
    pcrb_key_t *curr_key = NULL;
    pcrb_dir_t *dir = NULL;
    knl_scan_key_t scan_key;
    bool32 changed = CT_FALSE;
    bool32 need_wait = CT_FALSE;
    btree_find_assist_t find_assist;

    btree = CURSOR_BTREE(cursor);
    key = (pcrb_key_t *)cursor->key;
    pcrb_decode_key(INDEX_PROFILE(btree->index), key, &scan_key);
    path_info->part_loc = cursor->part_loc;
    path_info->get_sibling = CT_FALSE;

    for (;;) {
        changed = CT_FALSE;
        log_atomic_op_begin(session);
        btree_init_find_assist(btree, path_info, &scan_key, BTREE_FIND_DELETE, &find_assist);
        (void)pcrb_find_update_pos(session, &find_assist, is_found, &changed, cursor->logging);
        if (find_assist.page_damage) {
            log_atomic_op_end(session);
            CT_THROW_ERROR(ERR_PAGE_SOFT_DAMAGED, find_assist.page_id.file, find_assist.page_id.page);
            return CT_ERROR;
        }

        page = BTREE_CURR_PAGE(session);
        dir = pcrb_get_dir(page, (uint32)path_info->path[0].slot);
        curr_key = PCRB_GET_KEY(page, dir);

        if (SECUREC_UNLIKELY(!(*is_found))) {
            if (btree->is_shadow) {
                buf_leave_page(session, changed);
                log_atomic_op_end(session);
                knl_end_itl_waits(session);
                return CT_ERROR;
            }
            /* this will not happen */
            knl_panic_log(0, "[PCRB] index %s cannot find the key %u-%u-%u to be deleted in page %u-%u",
                          btree->index->desc.name, (uint32)key->rowid.file, (uint32)key->rowid.page,
                          (uint32)key->rowid.slot, (uint32)AS_PAGID(page->head.id).file,
                          (uint32)AS_PAGID(page->head.id).page);
        }

        /*
         * in case of update primary key, we need force delete old key,
         * which has on lock on heap row, so we need to check itl status here
         */
        if (pcrb_need_wait(session, cursor, page, curr_key, &need_wait) != CT_SUCCESS) {
            buf_leave_page(session, changed);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            return CT_ERROR;
        }

        if (need_wait) {
            buf_leave_page(session, changed);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            btree->stat.row_lock_waits++;
            need_wait = CT_FALSE;

            if (tx_wait(session, session->lock_wait_timeout, ENQ_TX_KEY) != CT_SUCCESS) {
                tx_record_rowid(session->wrid);
                return CT_ERROR;
            }
            continue;
        }

        if (session->rm->idx_conflicts > 0) {
            if (!IS_SAME_ROWID(curr_key->rowid, cursor->rowid) || curr_key->is_deleted) {
                buf_leave_page(session, changed);
                log_atomic_op_end(session);
                knl_end_itl_waits(session);
                session->rm->idx_conflicts--;
                *is_found = CT_FALSE;
                return CT_SUCCESS;
            }
        }

        if (btree->is_shadow) {
            if (!IS_SAME_ROWID(curr_key->rowid, cursor->rowid)) {
                *is_found = CT_FALSE;
                buf_leave_page(session, changed);
                log_atomic_op_end(session);
                knl_end_itl_waits(session);
                return CT_SUCCESS;
            }
        }

        if (pcrb_alloc_itl(session, cursor, page, &itl, &changed) != CT_SUCCESS) {
            buf_leave_page(session, changed);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            return CT_ERROR;
        }

        if (itl == NULL) {
            session->wpid = AS_PAGID(page->head.id);
            buf_leave_page(session, changed);
            log_atomic_op_end(session);
            if (knl_begin_itl_waits(session, &btree->stat.itl_waits) != CT_SUCCESS) {
                knl_end_itl_waits(session);
                return CT_ERROR;
            }
            continue;
        }
        knl_end_itl_waits(session);
        break;
    }

    return CT_SUCCESS;
}

static void pcrb_generate_delete_undo(knl_session_t *session, knl_cursor_t *cursor, pcrb_key_t *old_key,
                                      undo_data_t *undo)
{
    errno_t ret;
    knl_part_locate_t part_loc;
    table_t *table = (table_t *)cursor->table;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);

    btree_t *btree = CURSOR_BTREE(cursor);
    btree_page_t *page = BTREE_CURR_PAGE(session);
    if (IS_PART_INDEX(cursor->index)) {
        part_loc = cursor->part_loc;
    } else {
        part_loc.part_no = CT_INVALID_ID32;
        part_loc.subpart_no = CT_INVALID_ID32;
    }

    undo->data = (char *)cm_push(session->stack, undo->size);

    undo->snapshot.is_xfirst = (old_key->itl_id != session->itl_id);
    ret = memcpy_sp(undo->data, undo->size, old_key, (size_t)old_key->size);
    knl_securec_check(ret);
    uint32 partloc_size = undo_part_locate_size(table);
    ret = memcpy_sp(undo->data + old_key->size, partloc_size, &part_loc, partloc_size);
    knl_securec_check(ret);

    pcr_itl_t *itl = pcrb_get_itl(page, session->itl_id);

    undo->snapshot.scn = DB_CURR_SCN(session);
    undo->snapshot.is_owscn = itl->is_owscn;
    undo->snapshot.undo_page = itl->undo_page;
    undo->snapshot.undo_slot = itl->undo_slot;
    undo->snapshot.contain_subpartno = (IS_PART_TABLE(table) && IS_COMPART_TABLE(table->part_table));
    undo->ssn = (uint32)cursor->ssn;

    undo->type = UNDO_PCRB_DELETE;
    undo->seg_page = btree->entry.page;
    undo->seg_file = btree->entry.file;
    undo->index_id = (btree->is_shadow) ? CT_SHADOW_INDEX_ID : btree->index->desc.id;

    itl->undo_page = undo_page_info->undo_rid.page_id;
    itl->undo_slot = undo_page_info->undo_rid.slot;
    itl->ssn = (uint32)cursor->ssn;

    undo_write(session, undo, need_redo, CT_FALSE);

    cm_pop(session->stack);
}

static inline void pcrb_leave_delete(knl_session_t *session)
{
    buf_leave_page(session, CT_TRUE);
    log_atomic_op_end(session);
}

status_t pcrb_do_delete(knl_session_t *session, knl_cursor_t *cursor, bool32 *is_found)
{
    btree_path_info_t path_info;
    page_id_t next_pid;
    undo_data_t undo;
    rd_pcrb_delete_t redo;
    table_t *table = (table_t *)cursor->table;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);

    btree_t *btree = CURSOR_BTREE(cursor);
    pcrb_key_t *key = (pcrb_key_t *)cursor->key;
    undo.size = (uint32)key->size + undo_part_locate_size(table);
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(btree->cipher_reserve_size);
    /* We prepare two undo rows (itl undo and insert undo) */
    if (undo_multi_prepare(session, 2, sizeof(xid_t) + undo.size, IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type),
                           need_encrypt) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (pcrb_enter_delete(session, cursor, &path_info, is_found) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!(*is_found)) {
        return CT_SUCCESS;
    }

    btree_page_t *page = BTREE_CURR_PAGE(session);
    next_pid = AS_PAGID(page->next);

    redo.slot = (uint16)path_info.path[0].slot;
    redo.ssn = (uint32)cursor->ssn;
    redo.undo_page = undo_page_info->undo_rid.page_id;
    redo.undo_slot = undo_page_info->undo_rid.slot;
    redo.itl_id = session->itl_id;
    redo.unused1 = (uint8)0;
    redo.unused2 = (uint16)0;

    pcrb_dir_t *dir = pcrb_get_dir(page, (uint32)path_info.path[0].slot);
    pcrb_key_t *old_key = PCRB_GET_KEY(page, dir);

    knl_panic_log(IS_SAME_ROWID(old_key->rowid, cursor->rowid),
                  "[PCRB] index %s try to delete a wrong key %u-%u-%u, cursor rid %u-%u-%u", btree->index->desc.name,
                  (uint32)old_key->rowid.file, (uint32)old_key->rowid.page, (uint32)old_key->rowid.slot,
                  (uint32)cursor->rowid.file, (uint32)cursor->rowid.page, (uint32)cursor->rowid.slot);
    knl_panic_log(!old_key->is_deleted, "old_key is deleted, panic info: page %u-%u type %u, table %s, index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name,
                  ((index_t *)btree->index)->desc.name);

    pcrb_generate_delete_undo(session, cursor, old_key, &undo);

    old_key->itl_id = session->itl_id;
    old_key->is_deleted = CT_TRUE;

    if (need_redo) {
        log_put(session, RD_PCRB_DELETE, &redo, sizeof(rd_pcrb_delete_t), LOG_ENTRY_FLAG_NONE);
    }
    pcrb_leave_delete(session);

    if (cursor->reused_xid != CT_INVALID_ID64 && !IS_INVALID_PAGID(next_pid)) {
        (void)pcrb_clean_copied_itl(session, cursor->reused_xid, next_pid);
    }

    if (KNL_IDX_RECYCLE_ENABLED(session->kernel)) {
        btree->chg_stats.delete_size += PCRB_COST_SIZE((pcrb_key_t *)cursor->key);
        btree_try_notify_recycle(session, btree, cursor->part_loc);
    }

    return CT_SUCCESS;
}

status_t pcrb_delete(knl_session_t *session, knl_cursor_t *cursor)
{
    btree_t *btree = NULL;
    bool32 is_found = CT_FALSE;
    
    timeval_t tv_begin;
    cantian_record_io_stat_begin(IO_RECORD_EVENT_KNL_PCRB_DELETE, &tv_begin);

    if (pcrb_do_delete(session, cursor, &is_found) != CT_SUCCESS) {
        btree = CURSOR_BTREE(cursor);
        if (!btree->is_shadow || is_found) {
            cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_PCRB_DELETE, &tv_begin, IO_STAT_FAILED);
            return CT_ERROR;
        }

        if (pcrb_insert_into_shadow(session, cursor) != CT_SUCCESS) {
            int32 code = cm_get_error_code();
            if (code != ERR_DUPLICATE_KEY) {
                cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_PCRB_DELETE, &tv_begin, IO_STAT_FAILED);
                return CT_ERROR;
            }

            cm_reset_error();
        }

        if (pcrb_do_delete(session, cursor, &is_found) != CT_SUCCESS) {
            cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_PCRB_DELETE, &tv_begin, IO_STAT_FAILED);
            return CT_ERROR;
        }
    }
    cantian_record_io_stat_end(IO_RECORD_EVENT_KNL_PCRB_DELETE, &tv_begin, IO_STAT_SUCCESS);
    return CT_SUCCESS;
}

/*
 * copy itl from src page
 */
uint8 pcrb_copy_itl(knl_session_t *session, pcr_itl_t *src_itl, btree_page_t *dst_page)
{
    pcr_itl_t *dst_itl = NULL;
    uint8 slot;

    for (slot = 0; slot < dst_page->itls; slot++) {
        dst_itl = pcrb_get_itl(dst_page, slot);
        if (!dst_itl->is_active && dst_itl->scn == 0) {
            *dst_itl = *src_itl;
            dst_itl->is_copied = 0;
            return slot;
        }
    }

    slot = pcrb_new_itl(session, dst_page);
    knl_panic_log(slot != CT_INVALID_ID8, "the slot is invalid, panic info: page %u-%u type %u",
                  AS_PAGID(dst_page->head.id).file, AS_PAGID(dst_page->head.id).page, dst_page->head.type);
    dst_itl = pcrb_get_itl(dst_page, slot);

    *dst_itl = *src_itl;
    dst_itl->is_copied = 0;

    return slot;
}

/*
 * PCR btree move keys and itls to new page
 * @param kernel session, btree segment, src page, dst page, split position, level, it_map
 */
static void pcrb_move_keys(knl_session_t *session, btree_page_t *src_page, btree_page_t *dst_page, uint32 pos,
                           uint32 level, uint8 *itl_map)
{
    txn_info_t txn_info;
    uint8 i;
    uint16 slot;
    pcrb_dir_t *src_dir = NULL;
    page_id_t page_id = AS_PAGID(src_page->head.id);
    bool32 need_redo = SPC_IS_LOGGING_BY_PAGEID(session, page_id);
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, page_id.file)->space_id);
    bool32 need_encrypt = SPACE_IS_ENCRYPT(space);

    /* copy valid itls only on leaf node */
    if (pos < src_page->keys) {
        for (i = 0; i < src_page->itls; i++) {
            pcr_itl_t *itl = pcrb_get_itl(src_page, i);
            tx_get_pcr_itl_info(session, CT_FALSE, itl, &txn_info);

            itl_map[i] = pcrb_copy_itl(session, itl, dst_page);
            if (need_redo) {
                log_put(session, RD_PCRB_COPY_ITL, itl, sizeof(pcr_itl_t), LOG_ENTRY_FLAG_NONE);
            }
        }
    }

    for (slot = pos; slot < src_page->keys; slot++) {
        src_dir = pcrb_get_dir(src_page, slot);
        pcrb_key_t *src_key = PCRB_GET_KEY(src_page, src_dir);

        pcrb_key_t *new_key = (pcrb_key_t *)((char *)dst_page + dst_page->free_begin);
        errno_t ret = memcpy_sp(new_key, CT_KEY_BUF_SIZE, src_key, (size_t)src_key->size);
        knl_securec_check(ret);

        /* link copy key to copied itl_id */
        if (src_key->itl_id != CT_INVALID_ID8) {
            new_key->itl_id = itl_map[src_key->itl_id];
        }

        pcrb_dir_t *new_dir = pcrb_get_dir(dst_page, dst_page->keys);
        *new_dir = dst_page->free_begin;

        dst_page->free_begin += (uint16)src_key->size;
        dst_page->free_end -= sizeof(pcrb_dir_t);
        dst_page->free_size -= ((uint16)src_key->size + sizeof(pcrb_dir_t));
        dst_page->keys++;

        if (need_redo) {
            log_encrypt_prepare(session, ((page_head_t *)session->curr_page)->type, need_encrypt);
            log_put(session, RD_PCRB_COPY_KEY, new_key, (uint32)new_key->size, LOG_ENTRY_FLAG_NONE);
        }

        if (!src_key->is_cleaned) {
            src_page->free_size += ((uint16)src_key->size + sizeof(pcrb_dir_t));
            src_key->is_cleaned = (uint16)CT_TRUE;
        }
    }

    dst_page->scn = src_page->scn;
    if (need_redo) {
        log_put(session, RD_PCRB_SET_SCN, &(dst_page->scn), sizeof(knl_scn_t), LOG_ENTRY_FLAG_NONE);
    }

    /* calculate the new free end of src page */
    src_dir = pcrb_get_dir(src_page, pos - 1);
    src_page->keys = pos;
    src_page->free_end = (uint16)((char *)src_dir - (char *)src_page);
}

static void pcrb_insert_new_node(knl_session_t *session, btree_path_info_t *path_info, pcrb_key_t *insert_key,
    pcrb_key_t *new_key)
{
    rd_pcrb_insert_t redo;
    errno_t ret;
    btree_page_t *dst_page = BTREE_CURR_PAGE(session);
    bool32 need_redo = SPC_IS_LOGGING_BY_PAGEID(session, AS_PAGID(dst_page->head.id));
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, AS_PAGID_PTR(dst_page->head.id)->file)->space_id);
    bool32 need_encrypt = SPACE_IS_ENCRYPT(space);
    uint8 old_itl_id = insert_key->itl_id;
    int level = dst_page->level;
    rowid_t *path = &path_info->path[level];

    path->slot = 0;
    SET_ROWID_PAGE(path, AS_PAGID(dst_page->head.id));
    /* get dst_page's first key to insert into high level branch */
    ret = memcpy_sp(new_key, CT_KEY_BUF_SIZE, insert_key, (size_t)insert_key->size);
    knl_securec_check(ret);

    if (level == 0) {
        if (!path_info->is_empty_newnode || path_info->is_rebuild) {
            return;
        }

        insert_key->is_deleted = CT_TRUE;
        insert_key->itl_id = CT_INVALID_ID8;
    }

    redo.slot = (uint16)path->slot;
    redo.is_reuse = 0;
    redo.ssn = 0;
    redo.undo_page = INVALID_UNDO_PAGID;
    redo.undo_slot = INVALID_SLOT;

    pcrb_insert_into_page(session, dst_page, insert_key, &redo);
    if (need_redo) {
        log_encrypt_prepare(session, ((page_head_t *)session->curr_page)->type, need_encrypt);
        log_put(session, RD_PCRB_INSERT, &redo, (uint32)OFFSET_OF(rd_pcrb_insert_t, key), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, insert_key, (uint32)insert_key->size);
    }

    insert_key->itl_id = old_itl_id;
    insert_key->is_deleted = CT_FALSE;
}

static uint16 pcrb_calc_split_pos(knl_session_t *session, btree_t *btree, btree_page_t *src_page, btree_path_info_t *path_info,
                                  pcrb_key_t *insert_key, bool32 use_pct, bool32 *new_node)
{
    pcrb_dir_t *dir = NULL;
    pcrb_key_t *key = NULL;
    uint16 cost_size, src_size, dst_size;
    uint16 dst_capacity;
    uint32 i;
    uint16 pos = 0;
    uint16 level = src_page->level;
    uint8 cipher_reserve_size = btree->cipher_reserve_size;
    rowid_t *path = path_info->path;
    path_info->is_empty_newnode = CT_FALSE;

    dst_capacity = BTREE_SPLIT_PAGE_SIZE - sizeof(btree_page_t) - sizeof(page_tail_t) - cipher_reserve_size -
                   sizeof(pcr_itl_t) * src_page->itls;
    if (SECUREC_UNLIKELY(use_pct)) {
        /* transform pctfree to ratio and calculate page capacity */
        dst_capacity -= BTREE_SPLIT_PAGE_SIZE * BTREE_SEGMENT(session, btree->entry, btree->segment)->pctfree / 100;
    }

    src_size = PAGE_SIZE(src_page->head) - src_page->free_size - sizeof(btree_page_t) - sizeof(page_tail_t) -
        cipher_reserve_size - sizeof(pcr_itl_t) * src_page->itls + PCRB_MAX_COST_SIZE(insert_key);
    dst_size = 0;

    /* if insert key is max of btree, just split one key to new page */
    if (path[level].slot == src_page->keys && IS_INVALID_PAGID(AS_PAGID(src_page->next))) {
        pos = src_page->keys - 1;
        dir = pcrb_get_dir(src_page, src_page->keys - 1);
        key = PCRB_GET_KEY(src_page, dir);
        pos = (((PCRB_COST_SIZE(key) + PCRB_MAX_COST_SIZE(insert_key)) > dst_capacity) ||
               (key->size > BTREE_RESERVE_SIZE))
                  ? src_page->keys
                  : (src_page->keys - 1);
        *new_node = (pos == src_page->keys);
        path_info->is_empty_newnode = (pos == src_page->keys);
    } else {
        for (i = src_page->keys; i >= 0; i--) {
            if (i > path[level].slot) {
                dir = pcrb_get_dir(src_page, i - 1);
                key = PCRB_GET_KEY(src_page, dir);
                cost_size = PCRB_COST_SIZE(key);
            } else if (i == path[level].slot) {
                cost_size = PCRB_MAX_COST_SIZE(insert_key);
            } else {
                dir = pcrb_get_dir(src_page, i);
                key = PCRB_GET_KEY(src_page, dir);
                cost_size = PCRB_COST_SIZE(key);
            }

            src_size -= cost_size;
            dst_size += cost_size;
            /*
             *  if dst page exceeds its capacity, move 1 key less to dst page
             */
            if (dst_size > dst_capacity) {
                pos = i + 1;
                break;
            }

            /* make sure src page does not exceed its capacity */
            if (src_size > dst_capacity) {
                continue;
            }

            /*
             * here dst_size <= dst_capacity && src_size <= dst_capacity, we can split here. However
             * we need to seed for a better split position.
             */
            if (dst_size > src_size) {
                pos = (src_size + cost_size) > dst_capacity ? i : (i + 1);
                break;
            }
            knl_panic_log(i != 0, "page[%u-%u] has been damaged.", AS_PAGID(src_page->head.id).file,
                AS_PAGID(src_page->head.id).page);
        }

        if (pos == path[level].slot) {
            *new_node = CT_TRUE;
        } else {
            pos = ((path[level].slot > pos) ? pos : (pos - 1));
        }
    }

    return pos;
}

static void pcrb_split_normal(knl_session_t *session, btree_page_t *src_page, btree_path_info_t *path_info,
    uint16 split_pos, bool32 new_node, pcrb_key_t *insert_key, pcrb_key_t *new_key)
{
    btree_page_t *dst_page = BTREE_CURR_PAGE(session);
    errno_t ret;
    uint8 i;
    page_id_t page_id = AS_PAGID(src_page->head.id);
    bool32 need_redo = SPC_IS_LOGGING_BY_PAGEID(session, page_id);
    uint16 level = src_page->level;
    rd_btree_clean_keys_t redo;
    rowid_t *path = path_info->path;

    uint8 *itl_map = (uint8 *)cm_push(session->stack, CT_MAX_TRANS * sizeof(uint8));
    if (level == 0) {
        ret = memset_sp(itl_map, CT_MAX_TRANS, CT_INVALID_ID8, CT_MAX_TRANS);
        knl_securec_check(ret);
    }

    pcrb_move_keys(session, src_page, dst_page, split_pos, level, itl_map);
    if (new_node) {
        pcrb_insert_new_node(session, path_info, insert_key, new_key);
    } else {
        if (path[level].slot > split_pos) {
            path[level].slot -= split_pos;
            SET_ROWID_PAGE(&path[level], AS_PAGID(dst_page->head.id));
        }

        /* get dst_page's first key to insert into high level branch */
        pcrb_dir_t *dir = pcrb_get_dir(dst_page, 0);
        pcrb_key_t *key = PCRB_GET_KEY(dst_page, dir);
        ret = memcpy_sp(new_key, CT_KEY_BUF_SIZE, key, (size_t)key->size);
        knl_securec_check(ret);
    }

    buf_leave_page(session, CT_TRUE); /* leave dst page */

    redo.keys = src_page->keys;
    redo.free_size = src_page->free_size;
    if (need_redo) {
        log_put(session, RD_PCRB_CLEAN_KEYS, &redo, sizeof(rd_btree_clean_keys_t), LOG_ENTRY_FLAG_NONE);
    }

    if (level == 0) {
        for (i = 0; i < src_page->itls; i++) {
            if (itl_map[i] != CT_INVALID_ID8) {
                pcr_itl_t *itl = pcrb_get_itl(src_page, i);
                itl->is_copied = 1;
            }
        }
        if (need_redo) {
            log_put(session, RD_PCRB_SET_COPY_ITL, itl_map, src_page->itls, LOG_ENTRY_FLAG_NONE);
        }
    }
    cm_pop(session->stack);
}

static inline void pcrb_copy_root_page(knl_session_t *session, knl_cursor_t *cursor, btree_t *btree, btree_page_t *page)
{
    btree_copy_root_page(session, btree, page);

    if (DB_IS_CLUSTER(session) && !btree->is_shadow) {
        knl_begin_session_wait(session, BROADCAST_ROOT_PAGE, CT_TRUE);
        dtc_btree_broadcast_root_page(session, btree, page, cursor->part_loc);
    }
}

static void pcrb_resend_copy_root_page(knl_session_t *session, uint64 resend_bitmap, btree_t *btree,
    knl_part_locate_t part_loc)
{
    msg_btree_broadcast_t bcast;
    index_page_item_t *item = (index_page_item_t *)(btree->root_copy);

    btree_page_t *page = (btree_page_t *)(item->page);
    page_id_t page_id = AS_PAGID(page->head.id);
    mes_init_send_head(&bcast.head, MES_CMD_BTREE_ROOT_PAGE, sizeof(msg_btree_broadcast_t) + DEFAULT_PAGE_SIZE(session),
        CT_INVALID_ID32, session->kernel->id, CT_INVALID_ID8, session->id, CT_INVALID_ID16);
    bcast.table_id = btree->index->desc.table_id;
    bcast.uid = btree->index->desc.uid;
    bcast.index_id = btree->index->desc.id;
    bcast.part_loc = part_loc;
    bcast.is_shadow = btree->is_shadow;

    CT_LOG_RUN_INF("[DTC] session %u resend root page[%u-%u] bitmap %llu, rsn %u, pcn %u, table-uid-index[%u-%u-%u]",
        session->id, page_id.file, page_id.page, resend_bitmap, bcast.head.rsn, page->head.pcn,
        btree->index->desc.table_id, btree->index->desc.uid, btree->index->desc.id);

    (void)mes_broadcast_bufflist_and_wait_with_retry(session->id, resend_bitmap, &bcast.head,
        sizeof(msg_btree_broadcast_t), (char *)(page), ROOT_PAGE_WAIT_ACK_TIMEOUT, ROOT_PAGE_WAIT_ACK_RETRY_THRESHOLD);
}

static inline void pcrb_wait_copy_root_page(knl_session_t *session, btree_t *btree, knl_part_locate_t part_loc)
{
    if (DB_IS_CLUSTER(session)) {
        uint64 resend_bitmap = 0;
        status_t ret = mes_wait_acks_new(session->id, ROOT_PAGE_WAIT_ACK_TIMEOUT, &resend_bitmap);
        if (ret == CT_SUCCESS) {
            knl_end_session_wait(session, BROADCAST_ROOT_PAGE);
            return;
        }

        pcrb_resend_copy_root_page(session, resend_bitmap, btree, part_loc);
        knl_end_session_wait(session, BROADCAST_ROOT_PAGE);
    }
}

static void pcrb_increase_level(knl_session_t *session, knl_cursor_t *cursor, btree_t *btree, pcrb_key_t *key1,
                                pcrb_key_t *key2)
{
    btree_segment_t *segment = BTREE_SEGMENT(session, btree->entry, btree->segment);
    bool32 need_redo = SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id));
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(btree->cipher_reserve_size);
    btree_alloc_assist_t alloc_assist;
    knl_tree_info_t tree_info = segment->tree_info;

    bt_all_pageid(session, btree, &alloc_assist);
    bt_all_page(session, btree, &alloc_assist);
    uint8 options = (alloc_assist.type == BTREE_ALLOC_NEW_PAGE) ? ENTER_PAGE_NO_READ : ENTER_PAGE_NORMAL;
    buf_enter_page(session, alloc_assist.new_pageid, LATCH_MODE_X, options);
    btree_page_t *page = BTREE_CURR_PAGE(session);
    btree_format_page(session, segment, alloc_assist.new_pageid, (uint32)tree_info.level, (uint8)page->head.ext_size,
        alloc_assist.type == BTREE_ALLOC_NEW_PAGE ? CT_FALSE : CT_TRUE);

    /* insert left key */
    pcrb_key_t *key = (pcrb_key_t *)((char *)page + page->free_begin);
    errno_t ret = memcpy_sp(key, CT_KEY_BUF_SIZE, key1, (size_t)key1->size);
    knl_securec_check(ret);

    pcrb_dir_t *dir = pcrb_get_dir(page, page->keys);
    *dir = page->free_begin;

    page->free_begin += (uint16)key->size;
    page->free_end -= sizeof(pcrb_dir_t);
    page->free_size -= ((uint16)key->size + sizeof(pcrb_dir_t));
    page->keys++;

    if (need_redo) {
        log_encrypt_prepare(session, page->head.type, need_encrypt);
        log_put(session, RD_PCRB_COPY_KEY, key1, (uint32)key1->size, LOG_ENTRY_FLAG_NONE);
    }

    /* insert right key */
    key = (pcrb_key_t *)((char *)page + page->free_begin);
    ret = memcpy_sp(key, CT_KEY_BUF_SIZE, key2, (size_t)key2->size);
    knl_securec_check(ret);

    dir = pcrb_get_dir(page, page->keys);
    *dir = page->free_begin;

    page->free_begin += (uint16)key->size;
    page->free_end -= sizeof(pcrb_dir_t);
    page->free_size -= ((uint16)key->size + sizeof(pcrb_dir_t));
    page->keys++;
    if (need_redo) {
        log_encrypt_prepare(session, page->head.type, need_encrypt);
        log_put(session, RD_PCRB_COPY_KEY, key2, (uint32)key2->size, LOG_ENTRY_FLAG_NONE);
    }

    pcrb_copy_root_page(session, cursor, btree, page);
    pcrb_validate_page(session, &page->head, btree->index);
    buf_leave_page(session, CT_TRUE);

    buf_enter_page(session, btree->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    TO_PAGID_DATA(alloc_assist.new_pageid, tree_info.root);
    tree_info.level++;

    (void)cm_atomic_set(&segment->tree_info.value, tree_info.value);

    if (need_redo) {
        log_put(session, RD_BTREE_CHANGE_SEG, segment, sizeof(btree_segment_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, CT_TRUE);
}

static void pcrb_split_page(knl_session_t *session, knl_cursor_t *cursor, pcrb_key_t *insert_key,
                            btree_path_info_t *path_info, uint32 level, bool32 use_pct);

static void pcrb_insert_into_parent(knl_session_t *session, knl_cursor_t *cursor, pcrb_key_t *key,
                                    btree_path_info_t *path_info, uint32 level)
{
    btree_t *btree = CURSOR_BTREE(cursor);
    knl_scn_t scn;
    btree_page_t *page = NULL;
    rd_pcrb_insert_t redo;
    page_id_t root;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    rowid_t *path = path_info->path;
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(btree->cipher_reserve_size);

    buf_enter_page(session, GET_ROWID_PAGE(path[level]), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = BTREE_CURR_PAGE(session);

    path[level].slot++;

    /* current level page is not enough, need to split again */
    if (page->free_size < PCRB_COST_SIZE(key)) {
        buf_leave_page(session, CT_FALSE);
        pcrb_split_page(session, cursor, key, path_info, level, CT_FALSE);
        // insert the key in pcrb move new node
        if (path[level].slot == 0) {
            return;
        }
        buf_enter_page(session, GET_ROWID_PAGE(path[level]), LATCH_MODE_X, ENTER_PAGE_NORMAL);
        page = BTREE_CURR_PAGE(session);
    }

    redo.slot = (uint16)path[level].slot;
    redo.is_reuse = 0;
    redo.ssn = 0;
    redo.undo_page = INVALID_UNDO_PAGID;
    redo.undo_slot = INVALID_SLOT;

    if ((uint16)(page->free_end - page->free_begin) < PCRB_COST_SIZE(key)) {
        scn = btree_get_recycle_min_scn(session);
        btree->min_scn = scn;
        pcrb_compact_page(session, page, scn);
        if (need_redo) {
            rd_btree_info_t btree_info;
            btree_info.min_scn = scn;
            btree_info.uid = btree->index->desc.uid;
            btree_info.oid = btree->index->desc.table_id;
            btree_info.idx_id = btree->index->desc.id;
            btree_info.part_loc = cursor->part_loc;
            log_put(session, RD_PCRB_COMPACT_PAGE, &btree_info, sizeof(rd_btree_info_t), LOG_ENTRY_FLAG_NONE);
        }
    }

    knl_panic_log((uint16)(page->free_end - page->free_begin) >= PCRB_COST_SIZE(key), "page's free size is abnormal, "
        "panic info: page %u-%u type %u free_end %u free_begin %u key size %lu, table %s, index %s",
        AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, page->free_end, page->free_begin,
        PCRB_COST_SIZE(key), ((table_t *)cursor->table)->desc.name, ((index_t *)btree->index)->desc.name);

    pcrb_insert_into_page(session, page, key, &redo);

    if (need_redo) {
        log_encrypt_prepare(session, page->head.type, need_encrypt);
        log_put(session, RD_PCRB_INSERT, &redo, (uint32)OFFSET_OF(rd_pcrb_insert_t, key), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, key, (uint32)key->size);
    }

    root = AS_PAGID(BTREE_SEGMENT(session, btree->entry, btree->segment)->tree_info.root);
    if (IS_SAME_PAGID(AS_PAGID(page->head.id), root)) {
        pcrb_copy_root_page(session, cursor, btree, page);
    }

    pcrb_validate_page(session, &page->head, btree->index);
    buf_leave_page(session, CT_TRUE);
}

static void pcrb_split_remove_partid(knl_cursor_t *cursor, pcrb_key_t *src_key, pcrb_key_t *new_key)
{
    if (IS_PART_TABLE(cursor->table) && !IS_PART_INDEX(cursor->index)) {
        if (IS_COMPART_TABLE(((table_t *)cursor->table)->part_table)) {
            pcrb_remove_part_id(src_key);
            pcrb_remove_part_id(src_key);
            pcrb_remove_part_id(new_key);
            pcrb_remove_part_id(new_key);
        } else {
            pcrb_remove_part_id(src_key);
            pcrb_remove_part_id(new_key);
        }
    }
}

static bool32 is_include_null_in_unique_key(index_t *index, pcrb_key_t * key)
{
    knl_index_desc_t *index_desc = &(index->desc);
    if (!IS_COMPATIBLE_MYSQL_INST || index->desc.primary ||
        dc_is_reserved_entry(index_desc->uid, index_desc->table_id)) {
        return CT_FALSE;
    }
    return ((uint16)(~key->bitmap) & (uint16)(0xFFFF << (16 - index_desc->column_count)));
}

static void pcrb_split_page(knl_session_t *session, knl_cursor_t *cursor, pcrb_key_t *insert_key,
                            btree_path_info_t *path_info, uint32 level, bool32 use_pct)
{
    rowid_t *path = path_info->path;
    btree_t *btree;
    btree_segment_t *segment;
    btree_page_t *src_page = NULL;
    btree_page_t *dst_page = NULL;
    btree_page_t *next_page = NULL;
    page_id_t src_page_id, next_page_id;
    pcrb_key_t *key = NULL;
    pcrb_dir_t *dir = NULL;
    pcrb_key_t *src_key = NULL;
    pcrb_key_t *new_key = NULL;
    uint16 split_pos;
    errno_t err;
    btree_alloc_assist_t alloc_assist;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    bool32 new_node = CT_FALSE;
    uint8 options;

    btree = CURSOR_BTREE(cursor);
    segment = BTREE_SEGMENT(session, btree->entry, btree->segment);

    CM_SAVE_STACK(session->stack);

    src_key = (pcrb_key_t *)cm_push(session->stack, CT_KEY_BUF_SIZE);
    new_key = (pcrb_key_t *)cm_push(session->stack, CT_KEY_BUF_SIZE);

    src_page_id = GET_ROWID_PAGE(path[level]);
    bt_all_pageid(session, btree, &alloc_assist);
    page_id_t alloced_id = alloc_assist.new_pageid;
    bt_upd_ow_recycle_scn(session, btree, &alloc_assist);

    buf_enter_page(session, src_page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    src_page = BTREE_CURR_PAGE(session);
    if (level == 0 && src_page->head.lsn != path_info->leaf_lsn) {
        buf_leave_page(session, CT_FALSE);
        CM_RESTORE_STACK(session->stack);
        return;
    }

    next_page_id = AS_PAGID(src_page->next);
    if (!IS_INVALID_PAGID(next_page_id)) {
        buf_enter_page(session, next_page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
        next_page = BTREE_CURR_PAGE(session);
        TO_PAGID_DATA(alloc_assist.new_pageid, next_page->prev);
        if (need_redo) {
            /* log the prev and next page meanwhile */
            log_put(session, RD_BTREE_CHANGE_CHAIN, &next_page->prev, sizeof(page_id_t) * 2, LOG_ENTRY_FLAG_NONE);
        }
        buf_leave_page(session, CT_TRUE);
    }

    /* if new page is a recycled page enter_page_no_read will erase page->head.next_ext */
    options = (alloc_assist.type == BTREE_ALLOC_NEW_PAGE) ? ENTER_PAGE_NO_READ : ENTER_PAGE_NORMAL;
    buf_enter_page(session, alloc_assist.new_pageid, LATCH_MODE_X, options);
    dst_page = BTREE_CURR_PAGE(session);
    btree_format_page(session, segment, alloc_assist.new_pageid, level, (uint8)dst_page->head.ext_size,
                      (alloc_assist.type == BTREE_ALLOC_NEW_PAGE) ? CT_FALSE : CT_TRUE);
    TO_PAGID_DATA(src_page_id, dst_page->prev);
    TO_PAGID_DATA(next_page_id, dst_page->next);
    if (need_redo) {
        /* log the prev and next page meanwhile */
        log_put(session, RD_BTREE_CHANGE_CHAIN, &dst_page->prev, sizeof(page_id_t) * 2, LOG_ENTRY_FLAG_NONE);
    }

    split_pos = pcrb_calc_split_pos(session, btree, src_page, path_info, insert_key, use_pct, &new_node);
    pcrb_split_normal(session, src_page, path_info, split_pos, new_node, insert_key, new_key);

    TO_PAGID_DATA(alloc_assist.new_pageid, src_page->next);
    if (need_redo) {
        /* log the prev and next page meanwhile */
        log_put(session, RD_BTREE_CHANGE_CHAIN, &src_page->prev, sizeof(page_id_t) * 2, LOG_ENTRY_FLAG_NONE);
    }

    dir = pcrb_get_dir(src_page, 0);
    key = PCRB_GET_KEY(src_page, dir);
    err = memcpy_sp(src_key, CT_KEY_BUF_SIZE, key, (size_t)key->size);
    knl_securec_check(err);
    pcrb_validate_page(session, &src_page->head, btree->index);
    buf_leave_page(session, CT_TRUE);  // src_page

    bt_all_page(session, btree, &alloc_assist);
    page_id_t alloced_page = alloc_assist.new_pageid;
    CM_ABORT(IS_SAME_PAGID(alloced_id, alloced_page),
        "alloc page and id mismatch, alloced id %u-%u, real id %u-%u", alloced_id.page, alloced_id.file,
        alloced_page.page, alloced_page.file);
    if (KNL_IDX_RECYCLE_ENABLED(session->kernel)) {
        btree->chg_stats.alloc_pages++;
    }

    new_key->is_cleaned = CT_FALSE;
    new_key->is_deleted = CT_FALSE;

    if (level == 0) {
        /*
         * if index is unique and not null, parent node does not need to hold heap rowid,
         * null keys have compared rowid.
         */
        if (IS_UNIQUE_PRIMARY_INDEX(btree->index) && !BTREE_KEY_IS_NULL(new_key)) {
            bool32 include_null = is_include_null_in_unique_key(btree->index, new_key);
            if (!include_null) {
                MINIMIZE_ROWID(new_key->rowid);
                if ((level == segment->tree_info.level - 1) && !BTREE_KEY_IS_NULL(src_key)) {
                    MINIMIZE_ROWID(src_key->rowid);
                }
            }
        }

        /* remove part_id for global index of partitioned table when split from level 0 to 1 */
        pcrb_split_remove_partid(cursor, src_key, new_key);

        pcrb_put_child(src_key, src_page_id);
        pcrb_put_child(new_key, alloc_assist.new_pageid);
    } else {
        pcrb_set_child(src_key, src_page_id);
        pcrb_set_child(new_key, alloc_assist.new_pageid);
    }

    new_key->itl_id = CT_INVALID_ID8;

    if (SECUREC_UNLIKELY(level == segment->tree_info.level - 1)) {
        src_key->is_cleaned = CT_FALSE;
        src_key->is_deleted = CT_FALSE;
        src_key->itl_id = CT_INVALID_ID8;
        pcrb_increase_level(session, cursor, btree, src_key, new_key);
    } else {
        pcrb_insert_into_parent(session, cursor, new_key, path_info, level + 1);
    }

    CM_RESTORE_STACK(session->stack);
}

static status_t pcrb_try_split_page(knl_session_t *session, knl_cursor_t *cursor, btree_path_info_t *path_info,
                                    int64 version, bool32 use_pct, uint64 trigger_version)
{
    btree_t *btree;
    btree_segment_t *segment = NULL;
    page_id_t extent;
    int64 struct_ver;
    volatile char *old_root_copy = NULL;
    status_t ret = CT_SUCCESS;

    btree = CURSOR_BTREE(cursor);

    dls_latch_x(session, &btree->struct_latch, session->id, &session->stat_btree);

    /*
     * In case of struct version is the same but btree is splitting,
     * which means the version might be changed soon btree->is_splitting
     * makes sure there is only one thread doing split.
     *
     * when occur reform, remaster will clean dls owner, request could get dls without release owner,
     * because btree version++ in the process of release owner, so in this case, it uses old btree version,
     * need rescan.
     */
    struct_ver = cm_atomic_get(&btree->struct_ver);
    if (struct_ver != version || btree->is_splitting || trigger_version != DRC_GET_CURR_REFORM_VERSION) {
        dls_unlatch(session, &btree->struct_latch, &session->stat_btree);
        return CT_SUCCESS;
    }

    btree->is_splitting = CT_TRUE;
    segment = BTREE_SEGMENT(session, btree->entry, btree->segment);
    /* make sure segment free pages enough, avoid no free page error occurred during splitting */
    if (btree_need_extend(session, segment)) {
        dls_unlatch(session, &btree->struct_latch, &session->stat_btree);
        log_atomic_op_begin(session);

        space_t *space = SPACE_GET(session, segment->space_id);
        uint32 extent_size = spc_get_ext_size(space, segment->extents.count);
        bool32 is_degrade = CT_FALSE;
        ret = CT_SUCCESS;
        SYNC_POINT_GLOBAL_START(CANTIAN_BTREE_SPLIT_ALLOC_EXTENT_FAIL, &ret, CT_ERROR);
        ret = spc_try_alloc_extent(session, space, &extent, &extent_size, &is_degrade, CT_FALSE);
        SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
            log_atomic_op_end(session);
            dls_latch_x(session, &btree->struct_latch, session->id, &session->stat_btree);
            btree->is_splitting = CT_FALSE;
            btree->wait_ticks = 0;
            dls_unlatch(session, &btree->struct_latch, &session->stat_btree);
            return CT_ERROR;
        }

        btree_concat_extent(session, btree, extent, extent_size, is_degrade);
        log_atomic_op_end(session);
        dls_latch_x(session, &btree->struct_latch, session->id, &session->stat_btree);
    }

    old_root_copy = btree->root_copy;
    log_atomic_op_begin(session);
    pcrb_split_page(session, cursor, (pcrb_key_t *)cursor->key, path_info, 0, use_pct);
    struct_ver = btree->struct_ver + 1;
    btree->pre_struct_ver = btree->struct_ver;
    (void)cm_atomic_set(&btree->struct_ver, struct_ver);
    btree->is_splitting = CT_FALSE;
    btree->wait_ticks = 0;
    log_atomic_op_end(session);

    if (DB_IS_CLUSTER(session)) {
        if (old_root_copy != btree->root_copy && !btree->is_shadow) {
            pcrb_wait_copy_root_page(session, btree, cursor->part_loc);
        }
    }

    dls_unlatch(session, &btree->struct_latch, &session->stat_btree);

    return CT_SUCCESS;
}

void pcrb_clean_lock(knl_session_t *session, lock_item_t *lock)
{
    rd_pcrb_clean_itl_t redo;
    uint64 itl_xid = CT_INVALID_ID64;
    uint8 option = !session->kernel->attr.delay_cleanout ? ENTER_PAGE_NORMAL : (ENTER_PAGE_NORMAL | ENTER_PAGE_TRY);

    log_atomic_op_begin(session);
    buf_enter_page(session, MAKE_PAGID(lock->file, lock->page), LATCH_MODE_X, option);

    if (SECUREC_UNLIKELY(session->curr_page == NULL)) {
        log_atomic_op_end(session);
        return;
    }

    btree_page_t *page = BTREE_CURR_PAGE(session);
    page_id_t page_id = AS_PAGID(page->head.id);
    page_id_t next_pagid = AS_PAGID(page->next);

    if (lock->itl >= page->itls) {
        buf_leave_page(session, CT_FALSE);
        log_atomic_op_end(session);
        return;
    }

    pcr_itl_t *itl = pcrb_get_itl(page, lock->itl);
    if (!itl->is_active || itl->xid.value != session->rm->xid.value) {
        buf_leave_page(session, CT_FALSE);
        log_atomic_op_end(session);
        return;
    }

    if (itl->is_copied) {
        itl->is_copied = CT_FALSE;
        itl_xid = itl->xid.value;
    }

    itl->is_active = CT_FALSE;
    itl->scn = session->rm->txn->scn;
    itl->is_owscn = CT_FALSE;

    if (page->scn < itl->scn) {
        page->scn = itl->scn;
    }

    redo.itl_id = lock->itl;
    redo.scn = itl->scn;
    redo.is_owscn = CT_FALSE;
    redo.is_copied = CT_FALSE;
    redo.aligned = (uint8)0;
    if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
        log_put(session, RD_PCRB_CLEAN_ITL, &redo, sizeof(rd_pcrb_clean_itl_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, CT_TRUE);
    log_atomic_op_end(session);

    if (itl_xid == CT_INVALID_ID64) {
        return;
    }

    while (!IS_INVALID_PAGID(next_pagid) && !IS_SAME_PAGID(next_pagid, AS_PAGID(lock->next_pagid))) {
        next_pagid = pcrb_clean_copied_itl(session, itl_xid, next_pagid);
    }
}

void pcrb_undo_itl(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    btree_page_t *page = NULL;
    pcr_itl_t *itl = NULL;
    rowid_t rid;
    uint8 itl_id;
    page_id_t page_id;

    rid = ud_row->rowid;
    itl_id = (uint8)rid.slot;
    page_id = GET_ROWID_PAGE(rid);
    if (!spc_validate_page_id(session, page_id)) {
        return;
    }

    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = BTREE_CURR_PAGE(session);
    if (page_is_damaged(&page->head)) {
        buf_leave_page(session, CT_FALSE);
        return;
    }

    itl = pcrb_get_itl(page, itl_id);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "xid of itl and rm are not same, panic info: "
                  "page %u-%u type %u itl xid %llu rm xid %llu", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, itl->xid.value, session->rm->xid.value);

    itl->xid = *(xid_t *)ud_row->data;
    itl->scn = ud_row->scn;
    itl->is_owscn = ud_row->is_owscn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;
    itl->is_active = CT_FALSE;

    if (SPC_IS_LOGGING_BY_PAGEID(session, page_id)) {
        log_put(session, RD_PCRB_UNDO_ITL, itl, sizeof(pcr_itl_t), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, &itl_id, sizeof(uint8));
    }
    buf_leave_page(session, CT_TRUE);
}

static void pcrb_undo_insert_key(knl_session_t *session, btree_t *btree, pcrb_key_t *ud_key,
                                 rd_pcrb_undo_t *redo)
{
    btree_page_t *page = BTREE_CURR_PAGE(session);
    pcrb_dir_t *dir = pcrb_get_dir(page, (uint32)redo->slot);
    pcrb_key_t *key = PCRB_GET_KEY(page, dir);
    knl_panic_log(key->itl_id != CT_INVALID_ID8, "key's itl_id is invalid, panic info: page %u-%u type %u, index %s",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type,
                  ((index_t *)btree->index)->desc.name);
    knl_panic_log(!key->is_deleted, "key is deleted, panic info: page %u-%u type %u index %s",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type,
                  ((index_t *)btree->index)->desc.name);
    pcrb_copy_data(key, ud_key);
    key->is_deleted = 1;
    pcr_itl_t *itl = pcrb_get_itl(page, key->itl_id);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "xid of itl and rm are not same, panic info: page %u-%u "
        "type %u, index %s itl xid %llu rm xid %llu", AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page,
        page->head.type, ((index_t *)btree->index)->desc.name, itl->xid.value, session->rm->xid.value);
    itl->ssn = redo->ssn;
    itl->undo_page = redo->undo_page;
    itl->undo_slot = redo->undo_slot;

    if (redo->is_xfirst) {
        key->itl_id = CT_INVALID_ID8;
    }

    if (SPC_IS_LOGGING_BY_PAGEID(session, btree->entry)) {
        log_put(session, RD_PCRB_UNDO_INSERT, redo, sizeof(rd_pcrb_undo_t), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, ud_key, (uint32)ud_key->size);
    }
}

void pcrb_undo_insert(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                      knl_dictionary_t *dc)
{
    knl_scan_key_t scan_key;
    bool32 is_same = CT_FALSE;
    bool32 compact_leaf = CT_FALSE;
    btree_path_info_t path_info;
    rd_pcrb_undo_t redo;
    knl_part_locate_t part_loc;
    btree_find_assist_t find_assist;

    pcrb_key_t *ud_key = (pcrb_key_t *)ud_row->data;
    if (ud_row->contain_subpartno) {
        part_loc = *(knl_part_locate_t *)(ud_row->data + ud_key->size);
    } else {
        part_loc.part_no = *(uint32 *)(ud_row->data + ud_key->size);
        part_loc.subpart_no = CT_INVALID_ID32;
    }
    
    btree_t *btree = btree_get_handle_by_undo(session, dc, part_loc, (char *)ud_row);
    if (btree == NULL) {
        return;
    }

    pcrb_decode_key(INDEX_PROFILE(btree->index), ud_key, &scan_key);
    path_info.part_loc = part_loc;
    path_info.get_sibling = CT_FALSE;
    btree_init_find_assist(btree, &path_info, &scan_key, BTREE_FIND_DELETE, &find_assist);
    (void)pcrb_find_update_pos(session, &find_assist, &is_same, &compact_leaf, CT_TRUE);
    if (find_assist.page_damage) {
        return;
    }
    
    btree_page_t *page = BTREE_CURR_PAGE(session);
    knl_panic_log(is_same, "[PCRB] index %s cannot find the key %u-%u-%u for undo insert in page %u-%u",
                  btree->index->desc.name, (uint32)ud_key->rowid.file, (uint32)ud_key->rowid.page,
                  (uint32)ud_key->rowid.slot, (uint32)AS_PAGID(page->head.id).file,
                  (uint32)AS_PAGID(page->head.id).page);
    redo.is_xfirst = ud_row->is_xfirst;
    redo.slot = (uint16)path_info.path[0].slot;
    redo.ssn = ud_row->ssn;
    redo.undo_page = ud_row->prev_page;
    redo.undo_slot = ud_row->prev_slot;
    pcrb_undo_insert_key(session, btree, ud_key, &redo);
    buf_leave_page(session, CT_TRUE);
}

void pcrb_undo_batch_insert(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                            knl_dictionary_t *dc)
{
    bool32 is_same = CT_FALSE;
    bool32 compact_leaf = CT_FALSE;
    knl_scan_key_t scan_key;
    btree_path_info_t path_info;
    rd_pcrb_undo_t redo;
    pcrb_undo_batch_insert_t *ud_batch = (pcrb_undo_batch_insert_t *)ud_row->data;
    path_info.part_loc = ud_batch->part_loc;
    path_info.get_sibling = CT_FALSE;

    btree_t *btree = btree_get_handle_by_undo(session, dc, path_info.part_loc, (char *)ud_row);
    if (btree == NULL) {
        return;
    }

    btree_find_assist_t find_assist;
    uint16 offset = 0;
    bool32 find_page = CT_FALSE;
    bool32 cmp_rowid = !IS_UNIQUE_PRIMARY_INDEX(btree->index);
    btree_page_t *page = NULL;
    uint16 keys = 0;
    pcrb_key_t *ud_key = (pcrb_key_t *)((char *)ud_batch->keys);
    pcrb_decode_key(INDEX_PROFILE(btree->index), ud_key, &scan_key);
    redo.ssn = ud_row->ssn;
    redo.undo_page = ud_row->prev_page;
    redo.undo_slot = ud_row->prev_slot;

    while (keys < ud_batch->count) {
        if (find_page) {
            ud_key = (pcrb_key_t *)((char *)ud_batch->keys + offset);
            pcrb_decode_key(INDEX_PROFILE(btree->index), ud_key, &scan_key);
            pcrb_binary_search(INDEX_PROFILE(btree->index), page, &scan_key, &path_info, cmp_rowid, &is_same);
            if (path_info.path[0].slot >= page->keys) {
                buf_leave_page(session, CT_TRUE);
                find_page = CT_FALSE;
                continue;
            }
        } else {
            btree_init_find_assist(btree, &path_info, &scan_key, BTREE_FIND_DELETE, &find_assist);
            (void)pcrb_find_update_pos(session, &find_assist, &is_same, &compact_leaf, CT_TRUE);
            if (find_assist.page_damage) {
                return;
            }
            
            page = BTREE_CURR_PAGE(session);
            find_page = CT_TRUE;
        }

        knl_panic_log(is_same, "[PCRB]index %s cannot find the %u key %u-%u-%u for undo batch insert page %u-%u",
            btree->index->desc.name, (uint32)keys, (uint32)ud_key->rowid.file, (uint32)ud_key->rowid.page,
            (uint32)ud_key->rowid.slot, (uint32)AS_PAGID(page->head.id).file, (uint32)AS_PAGID(page->head.id).page);

        redo.is_xfirst = (ud_key->itl_id == CT_INVALID_ID8);
        redo.slot = (uint16)path_info.path[0].slot;
        pcrb_undo_insert_key(session, btree, ud_key, &redo);
        offset += (uint16)ud_key->size;
        keys++;
    }
    buf_leave_page(session, CT_TRUE);
}

void pcrb_undo_delete(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                      knl_dictionary_t *dc)
{
    btree_find_assist_t find_assist;
    knl_scan_key_t scan_key;
    btree_path_info_t path_info;
    bool32 is_same = CT_FALSE;
    bool32 compact_leaf = CT_FALSE;
    rd_pcrb_undo_t redo;
    knl_part_locate_t part_loc;

    pcrb_key_t *ud_key = (pcrb_key_t *)ud_row->data;
    if (ud_row->contain_subpartno) {
        part_loc = *(knl_part_locate_t *)(ud_row->data + ud_key->size);
    } else {
        part_loc.part_no = *(uint32 *)(ud_row->data + ud_key->size);
        part_loc.subpart_no = CT_INVALID_ID32;
    }
    
    btree_t *btree = btree_get_handle_by_undo(session, dc, part_loc, (char *)ud_row);
    if (btree == NULL) {
        return;
    }

    pcrb_decode_key(INDEX_PROFILE(btree->index), ud_key, &scan_key);
    path_info.part_loc = part_loc;
    path_info.get_sibling = CT_FALSE;
    btree_init_find_assist(btree, &path_info, &scan_key, BTREE_FIND_DELETE, &find_assist);
    (void)pcrb_find_update_pos(session, &find_assist, &is_same, &compact_leaf, CT_TRUE);
    if (find_assist.page_damage) {
        return;
    }

    btree_page_t *page = BTREE_CURR_PAGE(session);

    knl_panic_log(is_same, "scan_key is not found, panic info: page %u-%u type %u, index %s",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type,
                  ((index_t *)btree->index)->desc.name);

    pcrb_dir_t *dir = pcrb_get_dir(page, (uint32)path_info.path[0].slot);
    pcrb_key_t *key = PCRB_GET_KEY(page, dir);
    knl_panic_log(key->itl_id != CT_INVALID_ID8, "key's itl_id is invalid, panic info: page %u-%u type %u, index %s",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type,
                  ((index_t *)btree->index)->desc.name);
    knl_panic_log(key->is_deleted, "key is not deleted, panic info: page %u-%u type %u, index %s",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type,
                  ((index_t *)btree->index)->desc.name);

    pcr_itl_t *itl = pcrb_get_itl(page, key->itl_id);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not same, panic info: "
                  "page %u-%u type %u, index %s itl xid %llu rm xid %llu", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, ((index_t *)btree->index)->desc.name, itl->xid.value,
                  session->rm->xid.value);

    key->is_deleted = 0;

    if (ud_row->is_xfirst) {
        key->itl_id = CT_INVALID_ID8;
    }

    itl->ssn = ud_row->ssn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;

    if (SPC_IS_LOGGING_BY_PAGEID(session, btree->entry)) {
        redo.slot = (uint16)path_info.path[0].slot;
        redo.ssn = ud_row->ssn;
        redo.is_xfirst = ud_row->is_xfirst;
        redo.undo_page = ud_row->prev_page;
        redo.undo_slot = ud_row->prev_slot;
        log_put(session, RD_PCRB_UNDO_DELETE, &redo, sizeof(rd_pcrb_undo_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, CT_TRUE);

    if (KNL_IDX_RECYCLE_ENABLED(session->kernel)) {
        btree->chg_stats.delete_size -= PCRB_COST_SIZE(ud_key);
    }
}

static inline void pcrb_append_to_page(btree_page_t *page, pcrb_key_t *key, uint8 itl_id)
{
    pcrb_dir_t *dir = NULL;
    errno_t err;

    knl_panic(page->free_end - page->free_begin >= (uint16)(key->size + sizeof(pcrb_dir_t)));
    dir = pcrb_get_dir(page, page->keys);
    *dir = page->free_begin;

    key->itl_id = CT_INVALID_ID8;
    err = memcpy_sp((char *)page + page->free_begin, BTREE_PAGE_FREE_SIZE(page) - sizeof(pcrb_dir_t), key,
                    (size_t)key->size);
    knl_securec_check(err);

    page->free_begin += (uint16)key->size;
    page->free_end -= sizeof(pcrb_dir_t);
    page->free_size -= (uint16)key->size + sizeof(pcrb_dir_t);
    page->keys++;
}

static status_t pcrb_construct_ancestors(knl_session_t *session, btree_t *btree, btree_page_t **parent_page,
    char **key_buf, pcrb_key_t *key, uint32 level, bool32 nologging)
{
    page_id_t page_id, prev_page_id;
    btree_page_t *page = NULL;
    bool32 is_ext_first = CT_FALSE;
    uint8 options;

    if (level >= CT_MAX_ROOT_LEVEL - 1) {
        CT_THROW_ERROR(ERR_BTREE_LEVEL_EXCEEDED, CT_MAX_ROOT_LEVEL);
        return CT_ERROR;
    }

    // due to recursive function, we save/restore stack outside this function, in pcrb_construct
    if (key_buf[level] == NULL) {
        key_buf[level] = (char *)cm_push(session->stack, CT_KEY_BUF_SIZE);
    }

    char *min_key = key_buf[level];
    if (parent_page[level] == NULL) {
        parent_page[level] = (btree_page_t *)cm_push(session->stack, session->kernel->attr.page_size);
        if (btree_prepare_pages(session, btree) != CT_SUCCESS) {
            return CT_ERROR;
        }

        log_atomic_op_begin(session);
        btree_alloc_from_ufp(session, btree, &page_id, &is_ext_first);
        options = is_ext_first ? ENTER_PAGE_NORMAL : ENTER_PAGE_NO_READ;
        buf_enter_page(session, page_id, LATCH_MODE_X, options);
        page = BTREE_CURR_PAGE(session);
        btree_format_page(session, BTREE_SEGMENT(session, btree->entry, btree->segment), page_id, level + 1,
            (uint8)page->head.ext_size, is_ext_first ? CT_TRUE : CT_FALSE);
        buf_leave_page(session, CT_TRUE);
        log_atomic_op_end(session);

        btree_format_vm_page(session, BTREE_SEGMENT(session, btree->entry, btree->segment), parent_page[level], page_id,
            level + 1);
        TO_PAGID_DATA(INVALID_PAGID, parent_page[level]->prev);
        TO_PAGID_DATA(INVALID_PAGID, parent_page[level]->next);
    }

    btree_page_t *vm_page = parent_page[level];
    uint16 pct_size = (PCRB_COST_SIZE(key) > DEFAULT_PAGE_SIZE(session) - BTREE_PCT_SIZE(btree) || vm_page->level > 0)
                   ? (uint16)0 : BTREE_PCT_SIZE(btree);
    if (vm_page->free_begin + PCRB_COST_SIZE(key) + pct_size > vm_page->free_end) {
        if (btree_prepare_pages(session, btree) != CT_SUCCESS) {
            return CT_ERROR;
        }

        log_atomic_op_begin(session);
        btree_alloc_from_ufp(session, btree, &page_id, &is_ext_first);
        options = is_ext_first ? ENTER_PAGE_NORMAL : ENTER_PAGE_NO_READ;
        buf_enter_page(session, page_id, LATCH_MODE_X, options);
        page = BTREE_CURR_PAGE(session);
        btree_format_page(session, BTREE_SEGMENT(session, btree->entry, btree->segment), page_id, level + 1,
                          (uint8)page->head.ext_size, is_ext_first ? CT_TRUE : CT_FALSE);
        buf_leave_page(session, CT_TRUE);
        log_atomic_op_end(session);

        TO_PAGID_DATA(page_id, vm_page->next);
        log_atomic_op_begin(session);
        log_set_group_nolog_insert(session, !nologging);
        buf_enter_page(session, AS_PAGID(vm_page->head.id), LATCH_MODE_X, ENTER_PAGE_NORMAL);
        page = BTREE_CURR_PAGE(session);
        errno_t err = memcpy_sp(BTREE_PAGE_BODY(page), BTREE_PAGE_BODY_SIZE(page), BTREE_PAGE_BODY(vm_page),
            BTREE_PAGE_BODY_SIZE(page));
        knl_securec_check(err);
        if (SPC_IS_LOGGING_BY_PAGEID(session, btree->entry) && !nologging) {
            log_put(session, RD_BTREE_CONSTRUCT_PAGE, BTREE_PAGE_BODY(page), BTREE_PAGE_BODY_SIZE(page),
                    LOG_ENTRY_FLAG_NONE);
        }

        if (parent_page[level + 1] != NULL) {
            buf_leave_page(session, CT_TRUE);
            log_atomic_op_end(session);
        } else {
            pcrb_key_t *mkey = PCRB_GET_KEY(page, pcrb_get_dir(page, 0));
            err = memcpy_sp(min_key, CT_KEY_BUF_SIZE, mkey, (size_t)mkey->size);
            knl_securec_check(err);
            pcrb_set_child((pcrb_key_t *)min_key, AS_PAGID(parent_page[level]->head.id));
            buf_leave_page(session, CT_TRUE);
            log_atomic_op_end(session);
            if (pcrb_construct_ancestors(session, btree, parent_page, key_buf, (pcrb_key_t *)min_key, level + 1,
                nologging) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
        prev_page_id = AS_PAGID(vm_page->head.id);
        btree_format_vm_page(session, BTREE_SEGMENT(session, btree->entry, btree->segment),
                             vm_page, page_id, level + 1);
        TO_PAGID_DATA(prev_page_id, vm_page->prev);
        err = memcpy_sp(min_key, CT_KEY_BUF_SIZE, key, (size_t)key->size);
        knl_securec_check(err);
        pcrb_set_child((pcrb_key_t *)min_key, page_id);
        if (pcrb_construct_ancestors(session, btree, parent_page, key_buf, (pcrb_key_t *)min_key, level + 1,
            nologging) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    pcrb_append_to_page(vm_page, key, CT_INVALID_ID8);
    return CT_SUCCESS;
}

status_t pcrb_construct(btree_mt_context_t *ctx)
{
    mtrl_cursor_t cursor;
    mtrl_sort_cursor_t cur1, cur2;
    btree_page_t *parent_page[CT_MAX_BTREE_LEVEL];
    pcrb_key_t *key = NULL;
    pcrb_key_t *mkey = NULL;
    page_id_t prev_page_id;
    char *key_buf[CT_MAX_BTREE_LEVEL];
    status_t status = CT_SUCCESS;
    uint16 pct_size;
    bool32 is_ext_first = CT_FALSE;
    knl_session_t *session = (knl_session_t *)ctx->mtrl_ctx.session;
    btree_t *btree = (btree_t *)ctx->mtrl_ctx.segments[ctx->seg_id]->cmp_items;
    btree_segment_t *segment = BTREE_SEGMENT(session, btree->entry, btree->segment);
    page_id_t page_id = AS_PAGID(segment->tree_info.root);
    bool32 need_redo = SPACE_IS_LOGGING(SPACE_GET(session, segment->space_id));
    uint8 cipher_reserve_size = btree->cipher_reserve_size;
    uint8 options;

    CM_SAVE_STACK(session->stack);

    log_atomic_op_begin(session);
    log_set_group_nolog_insert(session, !ctx->nologging);
    session->rm->logging = !ctx->nologging;
    session->rm->nolog_type = TABLE_LEVEL;
    if (btree_open_mtrl_cursor(ctx, &cur1, &cur2, &cursor) != CT_SUCCESS) {
        log_atomic_op_end(session);
        return CT_ERROR;
    }

    if (btree_fetch_mtrl_sort_key(ctx, &cur1, &cur2, &cursor) != CT_SUCCESS) {
        log_atomic_op_end(session);
        return CT_ERROR;
    }

    char *src_mkey = (char *)cm_push(session->stack, CT_KEY_BUF_SIZE);
    char *dst_mkey = (char *)cm_push(session->stack, CT_KEY_BUF_SIZE);

    uint32 mem_size = sizeof(char *) * CT_MAX_BTREE_LEVEL;
    errno_t err = memset_sp(parent_page, mem_size, 0, mem_size);
    knl_securec_check(err);
    err = memset_sp(key_buf, mem_size, 0, mem_size);
    knl_securec_check(err);

    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    btree_page_t *page = BTREE_CURR_PAGE(session);
    int16 free_size = (int16)(DEFAULT_PAGE_SIZE(session) - sizeof(btree_page_t) - sizeof(page_tail_t) -
                              cipher_reserve_size - page->itls * sizeof(pcr_itl_t) - BTREE_RESERVE_SIZE);

    while (!cursor.eof) {
        key = (pcrb_key_t *)cursor.sort.row;
        pct_size = (PCRB_COST_SIZE(key) > DEFAULT_PAGE_SIZE(session) - BTREE_PCT_SIZE(btree)) ? (uint16)0
                                                                                     : BTREE_PCT_SIZE(btree);
        if (free_size - (int16)pct_size - (int16)PCRB_COST_SIZE(key) < 0) {
            if (need_redo && !ctx->nologging) {
                log_put(session, RD_BTREE_CONSTRUCT_PAGE, BTREE_PAGE_BODY(page), BTREE_PAGE_BODY_SIZE(page),
                        LOG_ENTRY_FLAG_NONE);
            }
            prev_page_id = AS_PAGID(page->head.id);
            buf_leave_page(session, CT_TRUE);
            log_atomic_op_end(session);

            // page is full, we need move on to next page
            if (btree_prepare_pages(session, btree) != CT_SUCCESS) {
                status = CT_ERROR;
                break;
            }

            log_atomic_op_begin(session);
            is_ext_first = CT_FALSE;
            btree_alloc_from_ufp(session, btree, &page_id, &is_ext_first);

            options = is_ext_first ? ENTER_PAGE_NORMAL : ENTER_PAGE_NO_READ;
            buf_enter_page(session, page_id, LATCH_MODE_X, options);
            page = BTREE_CURR_PAGE(session);
            btree_format_page(session, segment, page_id, 0, (uint8)page->head.ext_size,
                              is_ext_first ? CT_TRUE : CT_FALSE);
            buf_leave_page(session, CT_TRUE);

            buf_enter_page(session, prev_page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
            page = BTREE_CURR_PAGE(session);
            TO_PAGID_DATA(page_id, page->next);
            if (need_redo) {
                /* log the prev and next page meanwhile */
                log_put(session, RD_BTREE_CHANGE_CHAIN, &page->prev, sizeof(page_id_t) * 2, LOG_ENTRY_FLAG_NONE);
            }

            if (parent_page[0] == NULL) {
                mkey = PCRB_GET_KEY(page, pcrb_get_dir(page, 0));
                err = memcpy_sp(src_mkey, CT_KEY_BUF_SIZE, (void *)mkey, (size_t)mkey->size);
                knl_securec_check(err);
                pcrb_minimize_unique_parent(btree->index, (pcrb_key_t *)src_mkey);
                pcrb_put_child((pcrb_key_t *)src_mkey, AS_PAGID(page->head.id));
            }

            buf_leave_page(session, CT_TRUE);
            log_atomic_op_end(session);

            if (parent_page[0] == NULL && pcrb_construct_ancestors(session, btree, parent_page, key_buf,
                (pcrb_key_t *)src_mkey, 0, ctx->nologging) != CT_SUCCESS) {
                status = CT_ERROR;
                break;
            }

            err = memcpy_sp(dst_mkey, CT_KEY_BUF_SIZE, (void *)key, (size_t)key->size);
            knl_securec_check(err);
            pcrb_minimize_unique_parent(btree->index, (pcrb_key_t *)dst_mkey);
            pcrb_put_child((pcrb_key_t *)dst_mkey, page_id);

            if (pcrb_construct_ancestors(session, btree, parent_page, key_buf, (pcrb_key_t *)dst_mkey, 0,
                ctx->nologging) != CT_SUCCESS) {
                status = CT_ERROR;
                break;
            }

            log_atomic_op_begin(session);
            log_set_group_nolog_insert(session, !ctx->nologging);
            buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
            page = BTREE_CURR_PAGE(session);
            TO_PAGID_DATA(prev_page_id, page->prev);
            free_size = (int16)(DEFAULT_PAGE_SIZE(session) - sizeof(btree_page_t) - sizeof(page_tail_t) -
                                cipher_reserve_size - page->itls * sizeof(pcr_itl_t) - BTREE_RESERVE_SIZE);
        }

        pcrb_append_to_page(page, key, CT_INVALID_ID8);
        free_size -= (int16)key->size + sizeof(pcrb_dir_t);

        if (btree_fetch_mtrl_sort_key(ctx, &cur1, &cur2, &cursor) != CT_SUCCESS) {
            if (need_redo && !ctx->nologging) {
                log_put(session, RD_BTREE_CONSTRUCT_PAGE, BTREE_PAGE_BODY(page), BTREE_PAGE_BODY_SIZE(page),
                    LOG_ENTRY_FLAG_NONE);
            }
            buf_leave_page(session, CT_TRUE);
            log_atomic_op_end(session);
            status = CT_ERROR;
            break;
        }
    }

    if (status == CT_SUCCESS) {
        if (need_redo && !ctx->nologging) {
            log_put(session, RD_BTREE_CONSTRUCT_PAGE, BTREE_PAGE_BODY(page), BTREE_PAGE_BODY_SIZE(page),
                    LOG_ENTRY_FLAG_NONE);
        }
        buf_leave_page(session, CT_TRUE);
        log_atomic_op_end(session);
        btree_construct_ancestors_finish(session, btree, parent_page, ctx->nologging);
    }

    btree_close_mtrl_cursor(ctx, &cur1, &cur2, &cursor);
    CM_RESTORE_STACK(session->stack);
    return status;
}

static void pcrb_get_parent_page(knl_session_t *session, btree_t *btree, knl_scan_key_t *scan_key, uint32 child_level,
                                 btree_path_info_t *path_info)
{
    btree_segment_t *seg = BTREE_SEGMENT(session, btree->entry, btree->segment);
    knl_tree_info_t tree_info;
    index_t *index = btree->index;
    pcrb_dir_t *dir = NULL;
    pcrb_key_t *curr_key = NULL;
    btree_page_t *page = NULL;
    page_id_t page_id;
    bool32 cmp_rowid;
    bool32 is_same = CT_FALSE;
    uint32 level;

    tree_info.value = cm_atomic_get(&seg->tree_info.value);
    level = (uint32)tree_info.level - 1;
    page_id = AS_PAGID(tree_info.root);
    cmp_rowid = (index->desc.primary || index->desc.unique) ? CT_FALSE : CT_TRUE;
    for (;;) {
        buf_enter_page(session, page_id, (child_level + 1 == level) ? LATCH_MODE_X : LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page = BTREE_CURR_PAGE(session);
        SET_ROWID_PAGE(&path_info->path[page->level], page_id);
        pcrb_binary_search(INDEX_PROFILE(index), page, scan_key, path_info, cmp_rowid, &is_same);

        if (child_level + 1 == page->level) {
            break;
        }

        dir = pcrb_get_dir(page, (uint32)path_info->path[page->level].slot);
        curr_key = PCRB_GET_KEY(page, dir);
        page_id = pcrb_get_child(curr_key);
        level = page->level - 1;
        buf_leave_page(session, CT_FALSE);
    }
}

void pcrb_clean_key(knl_session_t *session, btree_page_t *page, uint16 slot)
{
    pcrb_dir_t *dir = pcrb_get_dir(page, slot);
    pcrb_key_t *key = PCRB_GET_KEY(page, dir);

    for (uint16 j = slot; j < page->keys - 1; j++) {
        dir = pcrb_get_dir(page, j);
        *dir = *pcrb_get_dir(page, j + 1);
    }

    page->free_size += ((uint16)key->size + sizeof(pcrb_dir_t));
    key->is_cleaned = (uint16)CT_TRUE;
    page->keys--;
}

static bool32 pcrb_recycle_delete_leaf(knl_session_t *session, btree_t *btree, btree_recycle_desc_t *recycle_desc,
    knl_scan_key_t *key, knl_part_locate_t part_locate)
{
    btree_path_info_t path_info;
    // remove parent key
    pcrb_get_parent_page(session, btree, key, 0, &path_info);
    btree_page_t *parent_page = BTREE_CURR_PAGE(session);
    if (path_info.path[1].slot == 0) {
        buf_leave_page(session, CT_FALSE);  // parent page
        recycle_desc->is_first_child = CT_TRUE;
        return CT_FALSE;
    }

    if (!bt_recycle_page(session, btree, recycle_desc, part_locate)) {
        buf_leave_page(session, CT_FALSE);  // parent page
        recycle_desc->is_sparse = CT_TRUE;
        return CT_FALSE;
    }

    recycle_desc->is_recycled = CT_TRUE;
    pcrb_clean_key(session, parent_page, (uint16)path_info.path[1].slot);
    uint16 key_slot = (uint16)path_info.path[1].slot;
    if (SPC_IS_LOGGING_BY_PAGEID(session, btree->entry)) {
        log_put(session, RD_PCRB_CLEAN_KEY, &key_slot, sizeof(uint16), LOG_ENTRY_FLAG_NONE);
    }
    page_id_t root = AS_PAGID(BTREE_SEGMENT(session, btree->entry, btree->segment)->tree_info.root);
    if (IS_SAME_PAGID(AS_PAGID(parent_page->head.id), root)) {
        btree_copy_root_page(session, btree, parent_page);
    }
    buf_leave_page(session, CT_TRUE);
    return CT_TRUE;
}

/*
 * Description     : recycle leaf page to deleted pages list
 * Input           : leaf_id: the page id can be recycled
 * Input           : lsn & pcn: to make sure leaf_page never be changed
 * Output          : NA
 * ReturnValue     : void
 */
void pcrb_recycle_leaf(knl_session_t *session, btree_t *btree, knl_part_locate_t part_loc,
    btree_recycle_desc_t *desc)
{
    knl_scan_key_t scan_key;
    int64 version;

    CM_SAVE_STACK(session->stack);
    char *key_buf = (char *)cm_push(session->stack, CT_KEY_BUF_SIZE);
    log_atomic_op_begin(session);
    for (;;) {
        dls_latch_x(session, &btree->struct_latch, session->id, &session->stat_btree);
        if (!btree->is_splitting) {
            break;
        }
        dls_unlatch(session, &btree->struct_latch, &session->stat_btree);
        cm_spin_sleep();
        CT_LOG_DEBUG_INF("index %s recycle page %u-%u try latch btree struct latch.",
            btree->index->desc.name, (uint32)desc->leaf_id.file, (uint32)desc->leaf_id.page);
        continue;
    }

    buf_enter_page(session, desc->leaf_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    btree_page_t *page = BTREE_CURR_PAGE(session);
    if (page->head.lsn != desc->snapshot_lsn || page->is_recycled) {
        buf_leave_page(session, CT_FALSE);
        dls_unlatch(session, &btree->struct_latch, &session->stat_btree);
        log_atomic_op_end(session);
        CM_RESTORE_STACK(session->stack);
        desc->is_sparse = CT_TRUE;
        return;
    }
    page_id_t prev_page_id = AS_PAGID(page->prev);
    page_id_t next_page_id = AS_PAGID(page->next);
    pcrb_dir_t *dir = pcrb_get_dir(page, 0);
    pcrb_key_t *key = PCRB_GET_KEY(page, dir);
    errno_t err = memcpy_sp(key_buf, CT_KEY_BUF_SIZE, key, (size_t)key->size);
    knl_securec_check(err);
    pcrb_decode_key(INDEX_PROFILE(btree->index), (pcrb_key_t *)key_buf, &scan_key);
    buf_leave_page(session, CT_FALSE);

    if (!pcrb_recycle_delete_leaf(session, btree, desc, &scan_key, part_loc)) {
        dls_unlatch(session, &btree->struct_latch, &session->stat_btree);
        log_atomic_op_end(session);
        CM_RESTORE_STACK(session->stack);
        return;
    }

    btree_concat_next_to_prev(session, next_page_id, prev_page_id);
    btree_concat_del_pages(session, btree, desc);

    version = btree->struct_ver + 1;
    (void)cm_atomic_set(&btree->struct_ver, version);

    log_atomic_op_end(session);
    CM_RESTORE_STACK(session->stack);

    if (DB_IS_CLUSTER(session)) {
        status_t ret = dtc_broadcast_btree_split(session, btree, part_loc, CT_TRUE);
        if (ret != CT_SUCCESS) {
            knl_panic_log(
                0,
                "[DTC] pcrb_recycle_leaf failed to broadcast btree split info, abort, uid/table_id/index_id/part:[%d-%d-%d-%u-%u], struct version:%llu",
                btree->index->desc.uid, btree->index->desc.table_id, btree->index->desc.id, part_loc.part_no,
                part_loc.subpart_no, btree->struct_ver);
        }
    }
    dls_unlatch(session, &btree->struct_latch, &session->stat_btree);
}

void pcrb_get_txn_info(knl_session_t *session, btree_page_t *page, pcrb_key_t *key, txn_info_t *txn_info)
{
    if (key->itl_id == CT_INVALID_ID8) {
        txn_info->status = (uint8)XACT_END;
        txn_info->scn = page->scn;
        txn_info->is_owscn = 1;
    } else {
        knl_panic_log(key->itl_id < page->itls, "the key's itl_id is nore than page's itls, panic info: page %u-%u "
                      "type %u itl_id %u itls %u", AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page,
                      page->head.type, key->itl_id, page->itls);
        pcr_itl_t *itl = pcrb_get_itl(page, key->itl_id);

        tx_get_pcr_itl_info(session, CT_FALSE, itl, txn_info);
    }
}

static inline uint16 pcrb_total_size(knl_session_t *session, space_t *space, btree_page_t *btree_page)
{
    return (uint16)(DEFAULT_PAGE_SIZE(session) - sizeof(pcr_itl_t) * btree_page->itls - sizeof(page_tail_t) -
        sizeof(btree_page_t) - space->ctrl->cipher_reserve_size);
}

bool32 pcrb_is_recycled_page(knl_session_t *session, btree_page_t *page,
    knl_scn_t interval_scn, btree_recycle_desc_t *desc)
{
    txn_info_t txn_info;
    bool32 is_recyclable = CT_TRUE;
    uint16 used_size = 0;
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, AS_PAGID_PTR(page->head.id)->file)->space_id);
    knl_scn_t min_scn = btree_get_recycle_min_scn(session);

    desc->is_empty = CT_TRUE;
    desc->max_del_scn = 0;
    for (uint32 i = 0; i < page->keys; i++) {
        pcrb_dir_t *dir = pcrb_get_dir(page, i);
        pcrb_key_t *key = PCRB_GET_KEY(page, dir);
        if (!key->is_deleted) {
            desc->is_empty = CT_FALSE;
            is_recyclable = CT_FALSE;
            used_size += PCRB_COST_SIZE(key);
            continue;
        }

        txn_info.xid.value = CT_INVALID_ID64;
        pcrb_get_txn_info(session, page, key, &txn_info);
        if (txn_info.status != (uint8)XACT_END) {
            is_recyclable = CT_FALSE;
            desc->active_txn = CT_TRUE;
            desc->xid = (txn_info.xid.value == CT_INVALID_ID64) ? desc->xid : txn_info.xid;
            continue;
        }

        if (!bt_recycle_time_expire(session, interval_scn, min_scn, txn_info.scn)) {
            is_recyclable = CT_FALSE;
            desc->unexpire = CT_TRUE;
            continue;
        }
        desc->force_recycle = (min_scn >= txn_info.scn) ? desc->force_recycle : CT_TRUE;
        desc->max_del_scn = MAX(txn_info.scn, desc->max_del_scn);
    }

    for (uint8 j = 0; j < page->itls; j++) {
        if (!is_recyclable) {
            break;
        }
        pcr_itl_t *itl = pcrb_get_itl(page, j);
        tx_get_pcr_itl_info(session, CT_FALSE, itl, &txn_info);
        if (txn_info.status != (uint8)XACT_END) {
            is_recyclable = CT_FALSE;
            desc->active_txn = CT_TRUE;
            continue;
        }
        desc->max_del_scn = MAX(txn_info.scn, desc->max_del_scn);
    }

    if (is_recyclable) {
        return CT_TRUE;
    }

    uint16 total_size = pcrb_total_size(session, space, page);
    desc->is_sparse = (bool8)(!(desc->is_empty) && used_size < total_size * PCRB_MIN_PAGE_USED_RATIO);
    return CT_FALSE;
}

status_t pcrb_dump_page(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump)
{
    btree_page_t *page = (btree_page_t *)page_head;

    cm_dump(dump, "btree page information\n");
    cm_dump(dump, "\tseg_scn: %llu", page->seg_scn);
    cm_dump(dump, "\tprev: %u-%u", AS_PAGID_PTR(page->prev)->file, AS_PAGID_PTR(page->prev)->page);
    cm_dump(dump, "\tnext: %u-%u\n", AS_PAGID_PTR(page->next)->file, AS_PAGID_PTR(page->next)->page);
    cm_dump(dump, "\tlevel: %u", page->level);
    cm_dump(dump, "\tkeys: %u", page->keys);
    cm_dump(dump, "\titls: %u", page->itls);
    cm_dump(dump, "\tfree_begin: %u", page->free_begin);
    cm_dump(dump, "\tfree_end: %u", page->free_end);
    cm_dump(dump, "\tfree_size: %u\n", page->free_size);

    cm_dump(dump, "itl information on this page\n");

    CM_DUMP_WRITE_FILE(dump);
    pcr_itl_t *itl = NULL;
    for (uint32 slot = 0; slot < page->itls; slot++) {
        itl = pcrb_get_itl(page, (uint8)slot);

        cm_dump(dump, "\tslot: #%-3u", slot);
        cm_dump(dump, "\tscn: %llu", itl->scn);
        cm_dump(dump, "\txmap: %u-%u", itl->xid.xmap.seg_id, itl->xid.xmap.slot);
        cm_dump(dump, "\txnum: %u", itl->xid.xnum);
        cm_dump(dump, "\tfsc: %u", itl->fsc);
        cm_dump(dump, "\tis_active: %u", itl->is_active);
        cm_dump(dump, "\tis_owscn: %u", itl->is_owscn);
        cm_dump(dump, "\tis_hist: %u", itl->is_hist);
        cm_dump(dump, "\tis_fast: %u\n", itl->is_fast);

        CM_DUMP_WRITE_FILE(dump);
    }

    cm_dump(dump, "key information on this page\n");
    pcrb_dir_t *dir = NULL;
    pcrb_key_t *key = NULL;
    for (uint32 slot = 0; slot < page->keys; slot++) {
        dir = pcrb_get_dir(page, slot);
        key = PCRB_GET_KEY(page, dir);

        cm_dump(dump, "\tslot: #%-3u", slot);
        cm_dump(dump, "\toffset: %-5u", *dir);
        cm_dump(dump, "\titl_id: %u", key->itl_id);
        cm_dump(dump, "\tinfinite/deleted/cleaned: %u/%u/%u", key->is_infinite, key->is_deleted, key->is_cleaned);
        cm_dump(dump, "\theap_page: %u-%u", key->rowid.file, key->rowid.page);
        cm_dump(dump, "\theap_slot: %u", key->rowid.slot);
        cm_dump(dump, "\tsize: %u\n", key->size);

        CM_DUMP_WRITE_FILE(dump);
    }
    return CT_SUCCESS;
}

void pcrb_validate_page(knl_session_t *session, page_head_t *page, index_t *index)
{
#ifdef LOG_DIAG
    pcr_itl_t *itl = NULL;
    pcrb_dir_t *dir = NULL;
    pcrb_key_t *key = NULL;
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, AS_PAGID_PTR(page->id)->file)->space_id);

    CM_SAVE_STACK(session->stack);
    btree_page_t *copy_page = (btree_page_t *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session));
    errno_t ret = memcpy_sp(copy_page, DEFAULT_PAGE_SIZE(session), page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);

    // if btree page recycled, no need to check
    if (copy_page->is_recycled) {
        CM_RESTORE_STACK(session->stack);
        return;
    }

    // check page itl
    for (uint8 j = 0; j < copy_page->itls; j++) {
        itl = pcrb_get_itl(copy_page, j);
        if (itl->is_active) {
            knl_panic_log(itl->xid.value != CT_INVALID_ID64,
                          "itl xid is invalid, panic info: copy_page %u-%u type %u, page %u-%u type %u",
                          AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type,
                          AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type);
        }
    }

    // check dir and itl
    for (uint16 i = 0; i < copy_page->keys; i++) {
        dir = pcrb_get_dir(copy_page, i);
        knl_panic_log(*dir < copy_page->free_begin, "dir's offset is more than copy_page's free_begin, panic info: "
                      "copy_page %u-%u type %u free_begin %u dir's offset %u, page %u-%u type %u",
                      AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type,
                      copy_page->free_begin, *dir, AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type);
        knl_panic_log(*dir >= sizeof(btree_page_t) + space->ctrl->cipher_reserve_size,
                      "dir is invalid, panic info: copy_page %u-%u type %u, page %u-%u type %u cipher_reserve_size %u",
                      AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type,
                      AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type, space->ctrl->cipher_reserve_size);
        key = PCRB_GET_KEY(copy_page, dir);
        uint8 itl_id = key->itl_id;
        knl_panic_log(itl_id == CT_INVALID_ID8 || itl_id <= copy_page->itls, "itl_id is abnormal, panic info: "
                      "copy_page %u-%u type %u, page %u-%u type %u itl_id %u copy_page itls %u",
                      AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type,
                      AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type, itl_id, copy_page->itls);
    }

    // check key size
    uint64 total_size = sizeof(btree_page_t) + space->ctrl->cipher_reserve_size;
    uint32 max_key_size = CT_MAX_KEY_SIZE - space->ctrl->cipher_reserve_size;
    max_key_size = copy_page->level > 0 ? max_key_size + sizeof(page_id_t) : max_key_size;
    for (uint16 i = 0; i < copy_page->keys; i++) {
        key = (pcrb_key_t *)((char *)copy_page + total_size);
        knl_panic_log(key->size <= max_key_size, "the size in key is abnormal, level %u, "
            "panic info: copy_page %u-%u type %u, page %u-%u type %u key size %u cipher_reserve_size %u",
            copy_page->level, AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type,
            AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type, key->size, space->ctrl->cipher_reserve_size);
        total_size += key->size;
        knl_panic_log(total_size <= copy_page->free_begin, "total_size is more than copy_page's free_begin, "
                      "panic info: copy_page %u-%u type %u, page %u-%u type %u free_begin %u total_size %llu",
                      AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type,
                      AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type, copy_page->free_begin, total_size);
    };

    // check page size
    knl_scn_t scn = btree_get_recycle_min_scn(session);
    pcrb_compact_page(session, copy_page, scn);
    knl_panic_log(copy_page->free_begin + copy_page->free_size == copy_page->free_end, "copy_page's free size is "
                  "abnormal, panic info: copy_page %u-%u type %u, page %u-%u type %u free_begin %u free_size %u "
                  "free_end %u", AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page,
                  copy_page->head.type, AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type,
                  copy_page->free_begin, copy_page->free_size, copy_page->free_end);

    // check key order
    if (index != NULL) {
        knl_scan_key_t scan_key;
        bool32 is_same = CT_FALSE;
        bool32 cmp_rowid = !IS_UNIQUE_PRIMARY_INDEX(index);
        dir = NULL;
        pcrb_key_t *key1 = NULL;
        pcrb_key_t *key2 = NULL;
        index_profile_t *profile = INDEX_PROFILE(index);

        for (uint32 i = 0; i < copy_page->keys - 1; i++) {
            dir = pcrb_get_dir(copy_page, i);
            key1 = PCRB_GET_KEY(copy_page, dir);

            dir = pcrb_get_dir(copy_page, i + 1);
            key2 = PCRB_GET_KEY(copy_page, dir);

            pcrb_decode_key(profile, key2, &scan_key);
            if (pcrb_compare_key(profile, &scan_key, key1, cmp_rowid, &is_same) <= 0) {
                knl_panic_log(0, "keys are out of order: page %u-%u type %u, (%d)th key is larger than its next key",
                              AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type, i);
            }
        }
    }
    CM_RESTORE_STACK(session->stack);
#endif
}

#ifndef WIN32
int32 pcrb_cmp_mtrl_column_data(knl_handle_t col1, knl_handle_t col2, ct_type_t type, uint16 *offset1,
                                uint16 *offset2, uint16 collate_id)
{
    text_t text1, text2;
    static void *labels[] = {
        [CT_TYPE_I(CT_TYPE_INTEGER)] = &&LABEL_INTEGER,
        [CT_TYPE_I(CT_TYPE_BIGINT)] = &&LABEL_BIGINT,
        [CT_TYPE_I(CT_TYPE_REAL)] = &&LABEL_REAL,
        [CT_TYPE_I(CT_TYPE_NUMBER)] = &&LABEL_NUMBER,
        [CT_TYPE_I(CT_TYPE_NUMBER2)] = &&LABEL_NUMBER2,
        [CT_TYPE_I(CT_TYPE_DECIMAL)] = &&LABEL_NUMBER,
        [CT_TYPE_I(CT_TYPE_DATE)] = &&LABEL_BIGINT,
        [CT_TYPE_I(CT_TYPE_TIMESTAMP)] = &&LABEL_BIGINT,
        [CT_TYPE_I(CT_TYPE_CHAR)] = &&LABEL_STRING,
        [CT_TYPE_I(CT_TYPE_VARCHAR)] = &&LABEL_STRING,
        [CT_TYPE_I(CT_TYPE_STRING)] = &&LABEL_STRING,
        [CT_TYPE_I(CT_TYPE_BINARY)] = &&LABEL_STRING,
        [CT_TYPE_I(CT_TYPE_VARBINARY)] = &&LABEL_STRING,
        [CT_TYPE_I(CT_TYPE_CLOB)] = &&LABEL_ERROR,
        [CT_TYPE_I(CT_TYPE_BLOB)] = &&LABEL_ERROR,
        [CT_TYPE_I(CT_TYPE_CURSOR)] = &&LABEL_ERROR,
        [CT_TYPE_I(CT_TYPE_COLUMN)] = &&LABEL_ERROR,
        [CT_TYPE_I(CT_TYPE_BOOLEAN)] = &&LABEL_BOOLEAN,
        [CT_TYPE_I(CT_TYPE_TIMESTAMP_TZ_FAKE)] = &&LABEL_BIGINT,
        [CT_TYPE_I(CT_TYPE_TIMESTAMP_LTZ)] = &&LABEL_BIGINT,
        [CT_TYPE_I(CT_TYPE_INTERVAL)] = &&LABEL_ERROR,
        [CT_TYPE_I(CT_TYPE_INTERVAL_YM)] = &&LABEL_INTERVAL_YM,
        [CT_TYPE_I(CT_TYPE_INTERVAL_DS)] = &&LABEL_INTERVAL_DS,
        [CT_TYPE_I(CT_TYPE_RAW)] = &&LABEL_STRING,
        [CT_TYPE_I(CT_TYPE_IMAGE)] = &&LABEL_ERROR,
        [CT_TYPE_I(CT_TYPE_UINT32)] = &&LABEL_UINT32,
        [CT_TYPE_I(CT_TYPE_UINT64)] = &&LABEL_UINT64,
        [CT_TYPE_I(CT_TYPE_SMALLINT)] = &&LABEL_ERROR,
        [CT_TYPE_I(CT_TYPE_USMALLINT)] = &&LABEL_ERROR,
        [CT_TYPE_I(CT_TYPE_TINYINT)] = &&LABEL_ERROR,
        [CT_TYPE_I(CT_TYPE_UTINYINT)] = &&LABEL_ERROR,
        [CT_TYPE_I(CT_TYPE_FLOAT)] = &&LABEL_ERROR,
        [CT_TYPE_I(CT_TYPE_TIMESTAMP_TZ)] = &&LABEL_TSTZ,
        [CT_TYPE_I(CT_TYPE_DATETIME_MYSQL)] = &&LABEL_DATETIME_MYSQL,
        [CT_TYPE_I(CT_TYPE_TIME_MYSQL)] = &&LABEL_TIME_MYSQL,
        [CT_TYPE_I(CT_TYPE_DATE_MYSQL)] = &&LABEL_DATE_MYSQL,
        [CT_TYPE_I(CT_TYPE_NUMBER3)] = &&LABEL_NUMBER,
    };

    goto *labels[CT_TYPE_I(type)];
LABEL_UINT32:
    *offset1 += sizeof(uint32);
    *offset2 += sizeof(uint32);
    return NUM_DATA_CMP(uint32, col1, col2);

LABEL_INTEGER:
    *offset1 += sizeof(int32);
    *offset2 += sizeof(int32);
    return NUM_DATA_CMP(int32, col1, col2);

LABEL_BOOLEAN:
    *offset1 += sizeof(bool32);
    *offset2 += sizeof(bool32);
    return NUM_DATA_CMP(bool32, col1, col2);

LABEL_INTERVAL_YM:
    *offset1 += sizeof(interval_ym_t);
    *offset2 += sizeof(interval_ym_t);
    return NUM_DATA_CMP(interval_ym_t, col1, col2);

LABEL_INTERVAL_DS:
    *offset1 += sizeof(interval_ds_t);
    *offset2 += sizeof(interval_ds_t);
    return NUM_DATA_CMP(interval_ds_t, col1, col2);

LABEL_UINT64:
    *offset1 += sizeof(uint64);
    *offset2 += sizeof(uint64);
    return NUM_DATA_CMP(uint64, col1, col2);

LABEL_BIGINT:
    *offset1 += sizeof(int64);
    *offset2 += sizeof(int64);
    return NUM_DATA_CMP(int64, col1, col2);

LABEL_DATETIME_MYSQL:
    *offset1 += sizeof(int64);
    *offset2 += sizeof(int64);
    return cm_datetime_cmp_mysql(col1, col2);

LABEL_TIME_MYSQL:
    *offset1 += sizeof(int64);
    *offset2 += sizeof(int64);
    return cm_time_cmp_mysql(col1, col2);

LABEL_DATE_MYSQL:
    *offset1 += sizeof(int64);
    *offset2 += sizeof(int64);
    return cm_date_cmp_mysql(col1, col2);

LABEL_TSTZ:
    *offset1 += sizeof(timestamp_tz_t);
    *offset2 += sizeof(timestamp_tz_t);
    return cm_tstz_cmp((timestamp_tz_t*)col1, (timestamp_tz_t*)col2);

LABEL_REAL:
    *offset1 += sizeof(double);
    *offset2 += sizeof(double);
    return NUM_DATA_CMP(double, col1, col2);

LABEL_NUMBER:
    *offset1 += DECIMAL_FORMAT_LEN((char *)col1);
    *offset2 += DECIMAL_FORMAT_LEN((char *)col2);
    return cm_dec4_cmp((dec4_t *)((char *)col1), (dec4_t *)((char *)col2));

LABEL_NUMBER2:
    *offset1 += *(uint8 *)col1 + sizeof(uint8);
    *offset2 += *(uint8 *)col2 + sizeof(uint8);
    return cm_dec_cmp_payload((char *)col1 + sizeof(uint8), *(uint8 *)col1,
                              (char *)col2 + sizeof(uint8), *(uint8 *)col2);

LABEL_STRING:
    text1.len = *(uint16 *)col1;
    text1.str = (char *)col1 + sizeof(uint16);
    text2.len = *(uint16 *)col2;
    text2.str = (char *)col2 + sizeof(uint16);
    *offset1 += CM_ALIGN4(text1.len + sizeof(uint16));
    *offset2 += CM_ALIGN4(text2.len + sizeof(uint16));
    if (collate_id != CT_INVALID_ID16) {
        CHARSET_COLLATION *charset = cm_get_charset_coll(collate_id);
        return cm_mysql_compare(charset, &text1, &text2);
    } else {
        return cm_compare_text(&text1, &text2);
    }
LABEL_ERROR:
    knl_panic(0);
    return 0;
}
#else
int32 pcrb_cmp_mtrl_column_data(knl_handle_t col1, knl_handle_t col2, ct_type_t type, uint16 *offset1, uint16 *offset2)
{
    text_t text1, text2;
    switch (type) {
        case CT_TYPE_UINT32:
            *offset1 += sizeof(uint32);
            *offset2 += sizeof(uint32);
            return NUM_DATA_CMP(uint32, col1, col2);

        case CT_TYPE_INTEGER:
            *offset1 += sizeof(int32);
            *offset2 += sizeof(int32);
            return NUM_DATA_CMP(int32, col1, col2);

        case CT_TYPE_BOOLEAN:
            *offset1 += sizeof(bool32);
            *offset2 += sizeof(bool32);
            return NUM_DATA_CMP(bool32, col1, col2);

        case CT_TYPE_INTERVAL_YM:
            *offset1 += sizeof(interval_ym_t);
            *offset2 += sizeof(interval_ym_t);
            return NUM_DATA_CMP(interval_ym_t, col1, col2);

        case CT_TYPE_INTERVAL_DS:
            *offset1 += sizeof(interval_ds_t);
            *offset2 += sizeof(interval_ds_t);
            return NUM_DATA_CMP(interval_ds_t, col1, col2);

        case CT_TYPE_UINT64:
            *offset1 += sizeof(uint64);
            *offset2 += sizeof(uint64);
            return NUM_DATA_CMP(uint64, col1, col2);

        case CT_TYPE_BIGINT:
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
            *offset1 += sizeof(int64);
            *offset2 += sizeof(int64);
            return NUM_DATA_CMP(int64, col1, col2);
        
        case CT_TYPE_DATETIME_MYSQL:
            *offset1 += sizeof(int64);
            *offset2 += sizeof(int64);
            return cm_datetime_cmp_mysql(col1, col2);

        case CT_TYPE_TIME_MYSQL:
            *offset1 += sizeof(int64);
            *offset2 += sizeof(int64);
            return cm_time_cmp_mysql(col1, col2);

        case CT_TYPE_DATE_MYSQL:
            *offset1 += sizeof(int64);
            *offset2 += sizeof(int64);
            return cm_date_cmp_mysql(col1, col2);

        case CT_TYPE_TIMESTAMP_TZ:
            *offset1 += sizeof(timestamp_tz_t);
            *offset2 += sizeof(timestamp_tz_t);
            return cm_tstz_cmp((timestamp_tz_t*)col1, (timestamp_tz_t*)col2);

        case CT_TYPE_REAL:
            *offset1 += sizeof(double);
            *offset2 += sizeof(double);
            return NUM_DATA_CMP(double, col1, col2);

        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER3:
        case CT_TYPE_DECIMAL:
            *offset1 += DECIMAL_FORMAT_LEN((char *)col1);
            *offset2 += DECIMAL_FORMAT_LEN((char *)col2);
            return cm_dec4_cmp((dec4_t *)((char *)col1), (dec4_t *)((char *)col2));
        case CT_TYPE_NUMBER2:
            *offset1 += *(uint8 *)col1 + sizeof(uint8);
            *offset2 += *(uint8 *)col2 + sizeof(uint8);

            return cm_dec_cmp_payload((char *)col1 + sizeof(uint8), *(uint8 *)col1,
                                      (char *)col2 + sizeof(uint8), *(uint8 *)col2);

        default:
            text1.len = *(uint16 *)col1;  // we store len in the first 2 bytes
            text1.str = (char *)col1 + sizeof(uint16);
            text2.len = *(uint16 *)col2;  // we store len in the first 2 bytes
            text2.str = (char *)col2 + sizeof(uint16);
            *offset1 += (uint16)CM_ALIGN4(text1.len + sizeof(uint16));
            *offset2 += (uint16)CM_ALIGN4(text2.len + sizeof(uint16));

            return cm_compare_text(&text1, &text2);
    }
}
#endif

int32 pcrb_cmp_mtrl_column(index_profile_t *profile, pcrb_key_t *key1, pcrb_key_t *key2, uint32 idx_col_id,
                           uint16 *offset1, uint16 *offset2, uint16 collate_id, bool32 *cmp_rowid)
{
    ct_type_t datatype = profile->types[idx_col_id];
    bool8 null_first = profile->null_first;
    bool32 key2_is_null = !btree_get_bitmap(&key2->bitmap, idx_col_id);
    uint8 key1_is_null = !btree_get_bitmap(&key1->bitmap, idx_col_id);
    int32 result;

    if (SECUREC_LIKELY(!key1_is_null)) {
        if (SECUREC_UNLIKELY(key2_is_null)) {
            return null_first ? 1 : -1;
        }
        char *data1 = (char*)key1 + *offset1;
        char *data2 = (char *)key2 + *offset2;
        result = pcrb_cmp_mtrl_column_data(data1, data2, datatype, offset1, offset2, collate_id);
    } else if (key1_is_null) {
        result = (key2_is_null) ? 0 : (null_first ? -1 : 1);
        if (IS_COMPATIBLE_MYSQL_INST && profile->unique && !dc_is_reserved_entry(profile->uid, profile->table_id) &&
            key2_is_null) {
            *cmp_rowid = CT_TRUE;
        }
    }

    return result;
}

int32 pcrb_get_cmp_result(dc_entity_t *entity, index_t *index, pcrb_key_t *key1, pcrb_key_t *key2, bool32 cmp_rowid)
{
    int32 result;
    index_profile_t *profile = INDEX_PROFILE(index);
    knl_index_desc_t *desc = &index->desc;
    knl_column_t *column;
    uint16 collate_id;

    if (SECUREC_UNLIKELY(key2->is_infinite)) {
        return 1;
    }

    uint16 offset1 = sizeof(pcrb_key_t);
    uint16 offset2 = sizeof(pcrb_key_t);
    for (uint32 i = 0; i < profile->column_count; i++) {
        column = dc_get_column(entity, desc->columns[i]);
        if (column->is_collate) {
            collate_id = column->collate_id;
        } else {
            collate_id = CT_INVALID_ID16;
        }
        result = pcrb_cmp_mtrl_column(profile, key1, key2, i, &offset1, &offset2, collate_id, &cmp_rowid);
        if (result != 0) {
            return result;
        }
    }

    if (cmp_rowid || BTREE_KEY_IS_NULL(key2)) {
        result = pcrb_cmp_rowid(key1, key2);
    } else {
        result = 0;
    }

    return result;
}

status_t pcrb_compare_mtrl_key(mtrl_segment_t *segment, char *data1, char *data2, int32 *result)
{
    index_t *index = ((btree_t *)segment->cmp_items)->index;
    bool32 cmp_rowid = IS_UNIQUE_PRIMARY_INDEX(index) ? CT_FALSE : CT_TRUE;

    *result = pcrb_get_cmp_result(index->entity, index, (pcrb_key_t *)data1, (pcrb_key_t *)data2, cmp_rowid);
    if (*result != 0) {
        return CT_SUCCESS;
    }

    if (!cmp_rowid) {
        if (IS_COMPATIBLE_MYSQL_INST) {
            CT_THROW_ERROR(ERR_DUPLICATE_ENTRY, index->entity->table.desc.name,
                           index->desc.primary ? "PRIMARY" : index->desc.name);
        } else {
            CT_THROW_ERROR(ERR_DUPLICATE_KEY, "");
        }
        return CT_ERROR;
    }

    return CT_SUCCESS;
}
