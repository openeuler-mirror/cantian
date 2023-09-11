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
 * rcr_btree_scan.c
 *
 *
 * IDENTIFICATION
 * src/kernel/index/rcr_btree_scan.c
 *
 * -------------------------------------------------------------------------
 */
#include "rcr_btree_scan.h"
#include "knl_table.h"
#include "temp_btree.h"

/*
* Description     : compare two key
* Input           : index : index handle
* Output          : is_same : return GS_TRUE if one key is exactly equal to the other.
* For non-unique index, is_same means each index column
* and heap row id of these two key equals;
* For unique index, only index columns are compared.
* Return Value    : int32: result of comparison
* History         : 1. 2017/4/26, wangjincheng 343637, create
*/
#ifndef WIN32
int32 btree_cmp_column_data(void *col1, void *col2, gs_type_t type, uint16 *offset, bool32 is_pcr)
{
    text_t text1, text2;
    static void *labels[] = {
        [GS_TYPE_I(GS_TYPE_INTEGER)] = &&LABEL_INTEGER,
        [GS_TYPE_I(GS_TYPE_BIGINT)] = &&LABEL_BIGINT,
        [GS_TYPE_I(GS_TYPE_REAL)] = &&LABEL_REAL,
        [GS_TYPE_I(GS_TYPE_NUMBER)] = &&LABEL_NUMBER,
        [GS_TYPE_I(GS_TYPE_NUMBER2)] = &&LABEL_NUMBER2,
        [GS_TYPE_I(GS_TYPE_DECIMAL)] = &&LABEL_NUMBER,
        [GS_TYPE_I(GS_TYPE_DATE)] = &&LABEL_BIGINT,
        [GS_TYPE_I(GS_TYPE_TIMESTAMP)] = &&LABEL_BIGINT,
        [GS_TYPE_I(GS_TYPE_CHAR)] = &&LABEL_STRING,
        [GS_TYPE_I(GS_TYPE_VARCHAR)] = &&LABEL_STRING,
        [GS_TYPE_I(GS_TYPE_STRING)] = &&LABEL_STRING,
        [GS_TYPE_I(GS_TYPE_BINARY)] = &&LABEL_STRING,
        [GS_TYPE_I(GS_TYPE_VARBINARY)] = &&LABEL_STRING,
        [GS_TYPE_I(GS_TYPE_CLOB)] = &&LABEL_ERROR,
        [GS_TYPE_I(GS_TYPE_BLOB)] = &&LABEL_ERROR,
        [GS_TYPE_I(GS_TYPE_CURSOR)] = &&LABEL_ERROR,
        [GS_TYPE_I(GS_TYPE_COLUMN)] = &&LABEL_ERROR,
        [GS_TYPE_I(GS_TYPE_BOOLEAN)] = &&LABEL_BOOLEAN,
        [GS_TYPE_I(GS_TYPE_TIMESTAMP_TZ_FAKE)] = &&LABEL_BIGINT,
        [GS_TYPE_I(GS_TYPE_TIMESTAMP_LTZ)] = &&LABEL_BIGINT,
        [GS_TYPE_I(GS_TYPE_INTERVAL)] = &&LABEL_ERROR,
        [GS_TYPE_I(GS_TYPE_INTERVAL_YM)] = &&LABEL_INTERVAL_YM,
        [GS_TYPE_I(GS_TYPE_INTERVAL_DS)] = &&LABEL_INTERVAL_DS,
        [GS_TYPE_I(GS_TYPE_RAW)] = &&LABEL_STRING,
        [GS_TYPE_I(GS_TYPE_IMAGE)] = &&LABEL_ERROR,
        [GS_TYPE_I(GS_TYPE_UINT32)] = &&LABEL_UINT32,
        [GS_TYPE_I(GS_TYPE_UINT64)] = &&LABEL_UINT64,
        [GS_TYPE_I(GS_TYPE_SMALLINT)] = &&LABEL_ERROR,
        [GS_TYPE_I(GS_TYPE_USMALLINT)] = &&LABEL_ERROR,
        [GS_TYPE_I(GS_TYPE_TINYINT)] = &&LABEL_ERROR,
        [GS_TYPE_I(GS_TYPE_UTINYINT)] = &&LABEL_ERROR,
        [GS_TYPE_I(GS_TYPE_FLOAT)] = &&LABEL_ERROR,
        [GS_TYPE_I(GS_TYPE_TIMESTAMP_TZ)] = &&LABEL_TSTZ,
        [GS_TYPE_I(GS_TYPE_NUMBER3)] = &&LABEL_NUMBER,
    };

    goto *labels[GS_TYPE_I(type)];
LABEL_UINT32:
    *offset += sizeof(uint32);
    return NUM_DATA_CMP(uint32, col1, col2);

LABEL_INTEGER:
    *offset += sizeof(int32);
    return NUM_DATA_CMP(int32, col1, col2);

LABEL_BOOLEAN:
    *offset += sizeof(bool32);
    return NUM_DATA_CMP(bool32, col1, col2);

LABEL_INTERVAL_YM:
    *offset += sizeof(interval_ym_t);
    return NUM_DATA_CMP(interval_ym_t, col1, col2);

LABEL_INTERVAL_DS:
    *offset += sizeof(interval_ds_t);
    return NUM_DATA_CMP(interval_ds_t, col1, col2);

LABEL_UINT64:
    *offset += sizeof(uint64);
    return NUM_DATA_CMP(uint64, col1, col2);

LABEL_BIGINT:
    *offset += sizeof(int64);
    return NUM_DATA_CMP(int64, col1, col2);

LABEL_TSTZ:
    *offset += sizeof(timestamp_tz_t);
    return cm_tstz_cmp((timestamp_tz_t*)col1, (timestamp_tz_t*)col2);

LABEL_REAL:
    *offset += sizeof(double);
    return cm_compare_double_prec16(*(double*)col1, *(double*)col2);

LABEL_NUMBER:
    if (is_pcr) {
        *offset += DECIMAL_FORMAT_LEN((char *)col2);
        return cm_dec4_cmp((dec4_t *)((char *)col1), (dec4_t *)((char *)col2));
    } else {
        *offset += CM_ALIGN4(*(uint16 *)col2 + sizeof(uint16));
        return cm_dec4_cmp((dec4_t *)((char *)col1 + sizeof(uint16)),
            (dec4_t *)((char *)col2 + sizeof(uint16)));
    }

LABEL_NUMBER2:
    *offset += *(uint8 *)col2 + sizeof(uint8);
    return cm_dec_cmp_payload((char *)col1 + sizeof(uint8), *(uint8 *)col1,
                              (char *)col2 + sizeof(uint8), *(uint8 *)col2);

LABEL_STRING:
    text1.len = *(uint16 *)col1;
    text1.str = (char *)col1 + sizeof(uint16);
    text2.len = *(uint16 *)col2;
    text2.str = (char *)col2 + sizeof(uint16);
    *offset += CM_ALIGN4(text2.len + sizeof(uint16));

    return cm_compare_text(&text1, &text2);

LABEL_ERROR:
    knl_panic(0);
    return 0;
}
#else
int32 btree_cmp_column_data(void *col1, void *col2, gs_type_t type, uint16 *offset, bool32 is_pcr)
{
    text_t text1, text2;

    switch (type) {
        case GS_TYPE_UINT32:
            *offset += sizeof(uint32);
            return NUM_DATA_CMP(uint32, col1, col2);

        case GS_TYPE_INTEGER:
            *offset += sizeof(int32);
            return NUM_DATA_CMP(int32, col1, col2);

        case GS_TYPE_BOOLEAN:
            *offset += sizeof(bool32);
            return NUM_DATA_CMP(bool32, col1, col2);

        case GS_TYPE_INTERVAL_YM:
            *offset += sizeof(interval_ym_t);
            return NUM_DATA_CMP(interval_ym_t, col1, col2);

        case GS_TYPE_INTERVAL_DS:
            *offset += sizeof(interval_ds_t);
            return NUM_DATA_CMP(interval_ds_t, col1, col2);

        case GS_TYPE_UINT64:
            *offset += sizeof(uint64);
            return NUM_DATA_CMP(uint64, col1, col2);

        case GS_TYPE_BIGINT:
        case GS_TYPE_DATE:
        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_TIMESTAMP_LTZ:
            *offset += sizeof(int64);
            return NUM_DATA_CMP(int64, col1, col2);

        case GS_TYPE_TIMESTAMP_TZ:
            *offset += sizeof(timestamp_tz_t);
            return cm_tstz_cmp((timestamp_tz_t*)col1, (timestamp_tz_t*)col2);

        case GS_TYPE_REAL:
            *offset += sizeof(double);
            return cm_compare_double_prec16(*(double*)col1, *(double*)col2);

        case GS_TYPE_NUMBER:
        case GS_TYPE_NUMBER3:
        case GS_TYPE_DECIMAL:
            if (is_pcr) {
                *offset += DECIMAL_FORMAT_LEN((char *)col2);
                return cm_dec4_cmp((dec4_t *)((char *)col1), (dec4_t *)((char *)col2));
            }
            *offset += CM_ALIGN4(*(uint16 *)col2 + sizeof(uint16));
            return cm_dec4_cmp((dec4_t *)((char *)col1 + sizeof(uint16)), (dec4_t *)((char *)col2 + sizeof(uint16)));

        case GS_TYPE_NUMBER2:
            *offset += *(uint8 *)col2 + sizeof(uint8);
            return cm_dec_cmp_payload((char *)col1 + sizeof(uint8), *(uint8 *)col1,
                                      (char *)col2 + sizeof(uint8), *(uint8 *)col2);
    
        // if not, go to default branch
        default:
            text1.len = *(uint16 *)col1;  // we store len in the first 2 bytes
            text1.str = (char *)col1 + sizeof(uint16);
            text2.len = *(uint16 *)col2;  // we store len in the first 2 bytes
            text2.str = (char *)col2 + sizeof(uint16);
            *offset += (uint16)CM_ALIGN4(text2.len + sizeof(uint16));

            return cm_compare_text(&text1, &text2);
    }
}
#endif

int32 btree_cmp_column(knl_column_t *column, knl_scan_key_t *scan_key, uint32 idx_col_id, btree_key_t *key,
    uint16 *offset)
{
    bool32 key_is_null = !btree_get_bitmap(&key->bitmap, idx_col_id);
    uint8 flag = scan_key->flags[idx_col_id];
    int32 result;

    if (flag == SCAN_KEY_NORMAL) {
        if (SECUREC_UNLIKELY(key_is_null)) {
            return -1;
        }
        char *data1 = scan_key->buf + scan_key->offsets[idx_col_id];
        char *data2 = (char *)key + *offset;
        result = btree_cmp_column_data((void *)data1, data2, column->datatype, offset, GS_FALSE);
    } else if (flag == SCAN_KEY_IS_NULL) {
        result = (key_is_null) ? 0 : (1);
    } else if (flag == SCAN_KEY_LEFT_INFINITE || flag == SCAN_KEY_MINIMAL) {
        result = -1;
    } else {
        result = (flag == SCAN_KEY_MAXIMAL && key_is_null) ? (-1) : 1;
    }

    return result;
}

static inline int32 btree_cmp_rowid(btree_key_t *key1, btree_key_t *key2)
{
    int32 result;

    result = key1->rowid.file > key2->rowid.file ? 1 : (key1->rowid.file < key2->rowid.file ? (-1) : 0);
    if (result != 0) {
        return result;
    }

    result = key1->rowid.page > key2->rowid.page ? 1 : (key1->rowid.page < key2->rowid.page ? (-1) : 0);
    if (result != 0) {
        return result;
    }

    result = key1->rowid.slot > key2->rowid.slot ? 1 : (key1->rowid.slot < key2->rowid.slot ? (-1) : 0);
    return result;
}

int32 btree_compare_key(index_t *index, knl_scan_key_t *scan_key, btree_key_t *key, bool32 cmp_rowid,
    bool32 *is_same)
{
    dc_entity_t *entity = index->entity;
    table_t *table = &entity->table;
    knl_column_t *column = NULL;
    int32 result;
    uint32 i;
    uint16 offset;

    if (SECUREC_LIKELY(is_same != NULL)) {
        *is_same = GS_FALSE;
    }

    if (SECUREC_UNLIKELY(key->is_infinite)) {
        return 1;
    }

    offset = sizeof(btree_key_t);

    for (i = 0; i < index->desc.column_count; i++) {
        column = dc_get_column(entity, index->desc.columns[i]);
        result = btree_cmp_column(column, scan_key, i, key, &offset);
        if (result != 0) {
            return result;
        }
    }

    if (cmp_rowid || BTREE_KEY_IS_NULL(key)) {
        if (table->desc.type == TABLE_TYPE_SESSION_TEMP || table->desc.type == TABLE_TYPE_TRANS_TEMP) {
            result = temp_btree_cmp_rowid((btree_key_t *)scan_key->buf, key);
        } else {
            result = btree_cmp_rowid((btree_key_t *)scan_key->buf, key);
        }
    } else {
        result = 0;
    }

    if (is_same != NULL) {
        *is_same = (result == 0);
    }

    return result;
}

static bool8 btree_need_match_cond(knl_cursor_t *cursor, index_t *index, knl_scan_key_t *key)
{
    for (uint32 i = 1; i < index->desc.column_count; i++) {
        if (key->flags[i] != SCAN_KEY_LEFT_INFINITE && key->flags[i] != SCAN_KEY_RIGHT_INFINITE) {
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

void btree_set_match_cond(knl_cursor_t *cursor)
{
    index_t *index = (index_t *)cursor->index;

    cursor->key_loc.match_left = btree_need_match_cond(cursor, index, &cursor->scan_range.l_key);
    cursor->key_loc.match_right = btree_need_match_cond(cursor, index, &cursor->scan_range.r_key);
}

void btree_binary_search(index_t *index, btree_page_t *page, knl_scan_key_t *scan_key,
    btree_path_info_t *path_info, bool32 cmp_rowid, bool32 *is_same)
{
    int32 result;
    uint16 begin, end, curr;
    btree_dir_t *dir = NULL;
    btree_key_t *cmp_key = NULL;

    curr = 0;
    begin = 0;
    result = 0;
    end = page->keys;
    /* branch node should have at least one key */
    knl_panic_log(page->level == 0 || page->keys > 0, "page level is not equal to zero and the keys is not more than "
        "zero, panic info: page %u-%u type %u index %s page_level %u page_keys %u", AS_PAGID(page->head.id).file,
        AS_PAGID(page->head.id).page, page->head.type, index->desc.name, page->level, page->keys);
    if (page->keys == 0) {
        *is_same = GS_FALSE;
    }

    while (begin < end) {
        curr = (end + begin) >> 1;
        dir = BTREE_GET_DIR(page, curr);
        cmp_key = BTREE_GET_KEY(page, dir);

        result = btree_compare_key(index, scan_key, cmp_key, cmp_rowid, is_same);
        if (result < 0) {
            end = curr;
        } else if (result > 0) {
            begin = curr + 1;
        } else {
            break;
        }
    }

    if (result > 0) {
        path_info->path[page->level].slot = curr + ((0 == page->level) ? 1 : 0);
    } else {
        path_info->path[page->level].slot = curr - ((0 == page->level) ? 0 : ((0 == result) ? 0 : 1));
    }
}

static bool32 btree_is_same_key(index_t *index, btree_key_t *key1, btree_key_t *key2)
{
    char *data1 = NULL;
    char *data2 = NULL;
    bool32 is_same = GS_FALSE;

    if (key1->size != key2->size) {
        return GS_FALSE;
    }

    data1 = (char *)key1 + sizeof(btree_key_t);
    data2 = (char *)key2 + sizeof(btree_key_t);
    if (memcmp(data1, data2, (size_t)key1->size - sizeof(btree_key_t)) != 0) {
        return GS_FALSE;
    }

    if (index->desc.unique || index->desc.primary) {
        return GS_TRUE;
    } else {
        is_same = IS_SAME_ROWID(key1->rowid, key2->rowid);
        return is_same;
    }
}

static status_t btree_enter_locate_page(knl_session_t *session, btree_search_t *search_info,
    uint8 level, page_id_t page_id, btree_page_t **page)
{
    btree_segment_t *seg = BTREE_SEGMENT(session, search_info->btree->entry, search_info->btree->segment);

    if (search_info->read_root_copy && BTREE_ROOT_COPY_VALID(session->index_root)) {
        search_info->read_root_copy = GS_FALSE;
        *page = (btree_page_t *)BTREE_GET_ROOT_COPY(session->index_root);
        session->curr_page = (char *)(*page);
        search_info->parent_snap_scn = ((index_page_item_t *)(session->index_root))->cache_scn;
        buf_push_page(session, NULL, LATCH_MODE_S);
    } else {
        if (level > 0) {
            if (buf_read_page(session, page_id, LATCH_MODE_S,
                ENTER_PAGE_NORMAL | ENTER_PAGE_HIGH_AGE) != GS_SUCCESS) {
                session->index_root = NULL;
                return GS_ERROR;
            }
            search_info->parent_snap_scn = KNL_GET_SCN(&seg->recycle_ver_scn);
        } else if (search_info->is_full_scan) {
            if (buf_read_prefetch_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
                session->index_root = NULL;
                return GS_ERROR;
            }
            search_info->child_snap_scn = KNL_GET_SCN(&seg->recycle_ver_scn);
        } else {
            if (buf_read_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
                session->index_root = NULL;
                return GS_ERROR;
            }
            search_info->child_snap_scn = KNL_GET_SCN(&seg->recycle_ver_scn);
        }

        *page = BTREE_CURR_PAGE(session);
        if (page_soft_damaged(&(*page)->head)) {
            buf_leave_page(session, GS_FALSE);
            GS_THROW_ERROR(ERR_PAGE_SOFT_DAMAGED, page_id.file, page_id.page);
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

bool32 bt_chk_leaf_recycled(knl_session_t *session, btree_t *btree, btree_page_t *btree_page, knl_scn_t snap_scn)
{
    if (btree_page->level > 0) {
        return GS_FALSE;
    }

    if (!btree_page->is_recycled) {
        if (GS_INVALID_SCN(snap_scn)) {
            return GS_FALSE;
        }

        knl_scn_t ow_recycle_scn = KNL_GET_SCN(&btree->segment->ow_recycle_scn);
        if (GS_INVALID_SCN(ow_recycle_scn)) {
            return GS_FALSE;
        }

        if (snap_scn > ow_recycle_scn) {
            return GS_FALSE;
        }

        GS_LOG_RUN_WAR("index %s leaf is recycled.page id %u-%u, seg_scn %llu, is recycled %u,"
            "snap_scn %llu, ow_recycle_scn %llu",
            btree->index->desc.name, (uint32)AS_PAGID(btree_page->head.id).file, (uint32)AS_PAGID(btree_page->head.id).page,
            btree_page->seg_scn, btree_page->is_recycled, snap_scn, ow_recycle_scn);
    }

    GS_LOG_DEBUG_INF("index %s leaf is recycled.page id %u-%u, seg_scn %llu, is recycled %u,"
        "snap_scn %llu, ow_recycle_scn %llu",
        btree->index->desc.name, (uint32)AS_PAGID(btree_page->head.id).file, (uint32)AS_PAGID(btree_page->head.id).page,
        btree_page->seg_scn, btree_page->is_recycled, snap_scn, KNL_GET_SCN(&btree->segment->ow_recycle_scn));
    session->stat->btree_leaf_recycled++;
    return GS_TRUE;
}

status_t bt_chk_keys_recycled(knl_session_t *session, btree_t *btree, btree_page_t *btree_page,
    uint8 isolevel, knl_scn_t query_scn)
{
    if (btree_page->level > 0 || isolevel == ISOLATION_CURR_COMMITTED ||
        GS_INVALID_SCN(btree->chg_stats.ow_del_scn)) {
        return GS_SUCCESS;
    }

    if (query_scn < KNL_GET_SCN(&btree->chg_stats.ow_del_scn)) {
        GS_THROW_ERROR(ERR_KEYS_RECYCLED);
        GS_LOG_RUN_ERR("index %s keys may recycled, details: query_scn %llu,"
            "ow_del_scn %llu, btree min scn %llu",
            btree->index->desc.name, query_scn,
            KNL_GET_SCN(&btree->chg_stats.ow_del_scn), btree->min_scn);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t bt_chk_page(knl_session_t *session, btree_search_t *search_info, btree_page_t *btree_page)
{
    index_t *index = search_info->btree->index;

    if (btree_check_segment_scn(btree_page, PAGE_TYPE_BTREE_NODE, search_info->seg_scn) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_INDEX_ALREADY_DROPPED, index->desc.name);
        return GS_ERROR;
    }
    
    if (SECUREC_UNLIKELY(!DB_IS_PRIMARY(&session->kernel->db))) {
        if (btree_check_min_scn(search_info->query_scn, search_info->btree->min_scn, btree_page->level) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (bt_chk_keys_recycled(session, search_info->btree, btree_page,
        search_info->isolevel, search_info->query_scn) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t btree_find_leaf(knl_session_t *session, btree_search_t *search_info, knl_scan_key_t *scan_key,
    btree_path_info_t *path_info, bool32 cmp_rowid, bool32 *is_found)
{
    index_t *index = search_info->btree->index;
    page_id_t page_id = AS_PAGID(search_info->tree_info.root);
    btree_dir_t *dir = NULL;
    btree_key_t *curr_key = NULL;
    btree_page_t *page = NULL;
    uint32 level = (uint32)search_info->tree_info.level - 1;
    bool32 is_same = GS_FALSE;

    /*
    * desc scan always compare rowid, so if this is the first time doing find leaf, slot of level 0 is the key
    * which is the smallest key that larger than scan key(no matter index is unique or not); if this is a retry
    * find leaf process, slot of level 0 is the slot we have scanned last time. Both in these case we do a slot--
    */
    session->index_root = search_info->read_root_copy ? search_info->btree->root_copy : NULL;

    for (;;) {
        if (btree_enter_locate_page(session, search_info, level, page_id, &page) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (bt_chk_page(session, search_info, page) != GS_SUCCESS) {
            buf_leave_page(session, GS_FALSE);
            session->index_root = NULL;
            return GS_ERROR;
        }

        if (bt_chk_leaf_recycled(session, search_info->btree, page, search_info->parent_snap_scn)) {
            buf_leave_page(session, GS_FALSE);
            page_id = AS_PAGID(search_info->tree_info.root);
            level = (uint32)search_info->tree_info.level - 1;
            search_info->read_root_copy = GS_FALSE;
            continue;
        }

        SET_ROWID_PAGE(&path_info->path[page->level], page_id);
        btree_binary_search(index, page, scan_key, path_info, cmp_rowid, &is_same);

        if (path_info->path[page->level].slot >= page->keys) {
            if (search_info->is_dsc_scan) {
                knl_panic_log(page->level == 0, "page level is not equal to zero, panic info: page %u-%u type %u "
                              "page level %u, index %s", AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page,
                              page->head.type, page->level, index->desc.name);
                break;
            }

            page_id = AS_PAGID(page->next);
            if (IS_INVALID_PAGID(page_id)) {
                buf_leave_page(session, GS_FALSE);
                session->index_root = NULL;
                *is_found = GS_FALSE;
                return GS_SUCCESS;
            }

            if (page->level == 0) {
                search_info->parent_snap_scn = search_info->child_snap_scn;
            }
            buf_leave_page(session, GS_FALSE);
            continue;
        }

        if (page->level == 0) {
            if (search_info->is_equal && !is_same) {
                buf_leave_page(session, GS_FALSE);
                session->index_root = NULL;
                *is_found = GS_FALSE;
                return GS_SUCCESS;
            }
            break;
        }

        dir = BTREE_GET_DIR(page, path_info->path[page->level].slot);
        curr_key = BTREE_GET_KEY(page, dir);
        page_id = curr_key->child;
        level = page->level - 1;
        buf_leave_page(session, GS_FALSE);
    }

    session->index_root = NULL;

    *is_found = GS_TRUE;
    return GS_SUCCESS;
}

static void btree_check_part_id(knl_cursor_t *cursor, btree_t *btree, uint32 parent_partid, uint32 part_id,
    bool32 *is_found)
{
    table_part_t *table_part = NULL;
    if (!(IS_PART_TABLE(cursor->table) && !IS_PART_INDEX(btree->index))) {
        return;
    }
    
    table_t *table = (table_t *)cursor->table;
    part_table_t *part_table = table->part_table;
    if (cursor->restrict_part) {
        table_part = TABLE_GET_PART(table, cursor->part_loc.part_no);
        knl_panic_log(table_part != NULL, "table_part is NULL, panic info: page %u-%u type %u table %s index %s",
                      cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                      table->desc.name, ((index_t *)btree->index)->desc.name);
        if (IS_COMPART_TABLE(part_table)) {
            if (table_part->desc.part_id != parent_partid) {
                *is_found = GS_FALSE;
            }
        } else {
            if (table_part->desc.part_id != part_id) {
                *is_found = GS_FALSE;
            }
        }

        return;
    }

    if (cursor->restrict_subpart) {
        knl_panic_log(IS_COMPART_TABLE(part_table), "part_table is not compart table, panic info: index %s table %s "
            "table_part %s page %u-%u type %u", ((index_t *)btree->index)->desc.name, table->desc.name,
            table_part->desc.name, cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type);
        table_part = TABLE_GET_PART(table, cursor->part_loc.part_no);
        knl_panic_log(table_part != NULL, "table_part is NULL, panic info: page %u-%u type %u table %s index %s",
                      cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                      table->desc.name, ((index_t *)btree->index)->desc.name);
        table_part_t *subpart = PART_GET_SUBENTITY(part_table, table_part->subparts[cursor->part_loc.subpart_no]);
        knl_panic_log(subpart != NULL, "the subpart is NULL, panic info: page %u-%u type %u table %s table_part %s "
                      "index %s", cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                      table->desc.name, table_part->desc.name, ((index_t *)btree->index)->desc.name);
        if (subpart->desc.parent_partid != parent_partid || subpart->desc.part_id != part_id) {
            *is_found = GS_FALSE;
        }
    }
}

static status_t btree_check_visible_with_udss(knl_session_t *session, knl_cursor_t *cursor, btree_t *btree,
    btree_key_t *key, uint32 *part_id, uint32 *parent_partid, bool32 *is_found)
{
    if (buf_read_page(session, PAGID_U2N(cursor->snapshot.undo_page), LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
        return GS_ERROR;
    }

    undo_page_t *ud_page = (undo_page_t *)CURR_PAGE(session);
    if (cursor->snapshot.undo_slot >= ud_page->rows) {
        buf_leave_page(session, GS_FALSE);
        tx_record_sql(session);
        GS_LOG_RUN_ERR("snapshot too old, detail: snapshot slot %u, undo rows %u, query scn %llu",
            cursor->snapshot.undo_slot, ud_page->rows, cursor->query_scn);
        GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
        return GS_ERROR;
    }

    undo_row_t *ud_row = UNDO_ROW(session, ud_page, cursor->snapshot.undo_slot);
    if (!cursor->snapshot.is_xfirst) {
        if (cursor->snapshot.xid != ud_row->xid.value) {
            buf_leave_page(session, GS_FALSE);
            GS_LOG_RUN_ERR("snapshot too old, detail: snapshot xid %llu, undo row xid %llu, query scn %llu",
                           cursor->snapshot.xid, ud_row->xid.value, cursor->query_scn);
            GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return GS_ERROR;
        }
    } else {
        btree_key_t *mkey = (btree_key_t *)ud_row->data;
        if (cursor->snapshot.scn <= ud_row->scn || !btree_is_same_key(btree->index, key, mkey)) {
            buf_leave_page(session, GS_FALSE);
            GS_LOG_RUN_ERR("snapshot too old, detail: snapshot scn %llu, undo row scn %llu, query scn %llu",
                           cursor->snapshot.scn, ud_row->scn, cursor->query_scn);
            GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return GS_ERROR;
        }
    }

    if (ud_row->xid.value == cursor->xid) {
        if (ud_row->ssn < cursor->ssn) {
            // The last undo generated before open cursor.
            // Use undo scn to overwrite snapshot scn to replace
            // ud_row->ssn < cursor->ssn judgement.
            knl_panic_log(ud_row->scn <= cursor->query_scn, "ud_row's scn is more than query_scn, panic info: "
                "ud_page %u-%u type %u page %u-%u type %u ud_row's scn %llu query_scn %llu table %s index %s",
                AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type,
                cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ud_row->scn,
                cursor->query_scn, ((table_t *)cursor->table)->desc.name, ((index_t *)btree->index)->desc.name);
            *is_found = (ud_row->type == UNDO_BTREE_INSERT);
            cursor->snapshot.scn = ud_row->scn;
            cursor->snapshot.is_owscn = GS_FALSE;
            cursor->snapshot.is_xfirst = GS_TRUE;
            cursor->snapshot.xid = ud_row->xid.value;
            buf_leave_page(session, GS_FALSE);
            return GS_SUCCESS;
        }
    }

    *is_found = (ud_row->type == UNDO_BTREE_DELETE);

    BTREE_COPY_ROWID((btree_key_t *)ud_row->data, cursor);
    if (cursor->restrict_part || cursor->restrict_subpart) {
        if (IS_COMPART_TABLE(((table_t *)cursor->table)->part_table)) {
            *part_id = btree_get_subpart_id((btree_key_t *)ud_row->data);
            *parent_partid = btree_get_part_id((btree_key_t *)ud_row->data);
        } else {
            *part_id = btree_get_part_id((btree_key_t *)ud_row->data);
            *parent_partid = GS_INVALID_ID32;
        }
    }

    cursor->snapshot.undo_page = ud_row->prev_page;
    cursor->snapshot.undo_slot = ud_row->prev_slot;
    cursor->snapshot.scn = ud_row->scn;
    cursor->snapshot.is_owscn = ud_row->is_owscn;
    cursor->snapshot.is_xfirst = ud_row->is_xfirst;
    cursor->snapshot.xid = ud_row->xid.value;
    buf_leave_page(session, GS_FALSE);

    return GS_SUCCESS;
}

static status_t btree_check_visible_with_undo(knl_session_t *session, knl_cursor_t *cursor, btree_t *btree,
    btree_key_t *key, uint32 *part_id, uint32 *parent_partid, bool32 *is_found)
{
    for (;;) {
        if (IS_INVALID_PAGID(cursor->snapshot.undo_page)) {
            *is_found = GS_FALSE;
            return GS_SUCCESS;
        }

        if (btree_check_visible_with_udss(session, cursor, btree, key, part_id, parent_partid,
            is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!cursor->snapshot.is_xfirst) {
            continue;
        }

        if (cursor->snapshot.scn <= cursor->query_scn) {
            cursor->scn = cursor->snapshot.scn;
            return GS_SUCCESS;
        }

        if (cursor->snapshot.is_owscn) {
            tx_record_sql(session);
            GS_LOG_RUN_ERR("snapshot too old, detail: snapshot owscn %llu, query scn %llu",
                cursor->snapshot.scn, cursor->query_scn);
            GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return GS_ERROR;
        }

        if (cursor->isolevel == (uint8)ISOLATION_SERIALIZABLE) {
            cursor->ssi_conflict = GS_TRUE;
        }
    }
}

static void btree_check_restrict_part(knl_cursor_t *cursor, btree_t *btree, btree_key_t *key, bool32 *is_found)
{
    uint32 part_id, parent_partid;
    if (*is_found && (cursor->restrict_part || cursor->restrict_subpart)) {
        if (IS_COMPART_TABLE(((table_t *)cursor->table)->part_table)) {
            part_id = btree_get_subpart_id(key);
            parent_partid = btree_get_part_id(key);
        } else {
            part_id = btree_get_part_id(key);
            parent_partid = GS_INVALID_ID32;
        }
        btree_check_part_id(cursor, btree, parent_partid, part_id, is_found);
    }
}

static status_t btree_check_visible(knl_session_t *session, knl_cursor_t *cursor, btree_dir_t *dir,
    btree_key_t *key, bool32 *is_found)
{
    btree_t *btree;
    btree_page_t *page;
    itl_t *itl = NULL;
    txn_info_t txn_info;
    uint32 part_id, parent_partid;

    btree = CURSOR_BTREE(cursor);
    part_id = GS_INVALID_ID32;
    parent_partid = GS_INVALID_ID32;
    page = (cursor->key_loc.page_cache == LOCAL_PAGE_CACHE) ?
               (btree_page_t *)cursor->page_buf :
               BTREE_CURR_PAGE(session);
    btree_get_txn_info(session, GS_TRUE, page, dir, key, &txn_info);

    if (txn_info.status == (uint8)XACT_END) {
        if (dir->itl_id != GS_INVALID_ID8) {
            itl = BTREE_GET_ITL(page, dir->itl_id);
            if (itl->is_active) {
                cursor->cleanout = GS_TRUE;
            }
        }

        if (txn_info.scn <= cursor->query_scn) {
            *is_found = (bool32)!key->is_deleted;
            btree_check_restrict_part(cursor, btree, key, is_found);
            if (*is_found) {
                BTREE_COPY_ROWID(key, cursor);
            }
            return GS_SUCCESS;
        }

        if (txn_info.is_owscn) {
            tx_record_sql(session);
            GS_LOG_RUN_ERR("snapshot too old, detail: key owscn %llu, query scn %llu",
                txn_info.scn, cursor->query_scn);
            GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return GS_ERROR;
        }

        if (cursor->isolevel == (uint8)ISOLATION_SERIALIZABLE) {
            cursor->ssi_conflict = GS_TRUE;
        }

        cursor->snapshot.scn = txn_info.scn;
        cursor->snapshot.is_xfirst = GS_TRUE;
        cursor->snapshot.xid = GS_INVALID_ID64;
    } else {
        itl = BTREE_GET_ITL(page, dir->itl_id);
        if (itl->xid.value == cursor->xid) {
            if (key->scn < cursor->ssn) {
                *is_found = (bool32)!key->is_deleted;
                btree_check_restrict_part(cursor, btree, key, is_found);

                if (*is_found) {
                    BTREE_COPY_ROWID(key, cursor);
                }
                return GS_SUCCESS;
            }
        } else {
            if (TX_XA_CONSISTENCY(session) &&
                (txn_info.status == (uint8)XACT_PHASE1 || txn_info.status == (uint8)XACT_PHASE2) &&
                txn_info.scn < cursor->query_scn) {
                GS_LOG_DEBUG_INF("need read wait.prepare_scn[%llu] < query_scn[%llu]", txn_info.scn, cursor->query_scn);
                session->wxid = itl->xid;
                ROWID_COPY(session->wrid, key->rowid);
                *is_found = GS_FALSE;
                return GS_SUCCESS;
            }
        }

        cursor->snapshot.scn = DB_CURR_SCN(session);
        cursor->snapshot.is_xfirst = GS_FALSE;
        cursor->snapshot.xid = itl->xid.value;
    }

    BTREE_COPY_ROWID(key, cursor);
    if (cursor->restrict_part || cursor->restrict_subpart) {
        if (IS_COMPART_TABLE(((table_t *)cursor->table)->part_table)) {
            part_id = btree_get_subpart_id(key);
            parent_partid = btree_get_part_id(key);
        } else {
            part_id = btree_get_part_id(key);
            parent_partid = GS_INVALID_ID32;
        }
    }

    cursor->snapshot.undo_page = key->undo_page;
    cursor->snapshot.undo_slot = key->undo_slot;

    if (btree_check_visible_with_undo(session, cursor, btree, key, &part_id, &parent_partid, is_found) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (*is_found && (cursor->restrict_part || cursor->restrict_subpart)) {
        btree_check_part_id(cursor, btree, parent_partid, part_id, is_found);
    }

    return GS_SUCCESS;
}

static bool32 btree_check_scan_range(knl_cursor_t *cursor, index_t *index, knl_scan_key_t *filter_key, btree_key_t *key)
{
    knl_scan_range_t *scan_range = &cursor->scan_range;
    int32 result;

    if (!cursor->index_ss) {
        if (!cursor->key_loc.cmp_end) {
            return GS_TRUE;
        }

        if (cursor->index_dsc) {
            bool32 cmp_rowid = BTREE_NEED_CMP_ROWID(cursor, index);
            if (btree_compare_key(index, filter_key, key, cmp_rowid, NULL) <= 0) {
                return GS_TRUE;
            }
        } else {
            bool32 cmp_rowid = (!scan_range->is_equal && BTREE_NEED_CMP_ROWID(cursor, index));
            if (btree_compare_key(index, filter_key, key, cmp_rowid, NULL) >= 0) {
                return GS_TRUE;
            }
        }

        return GS_FALSE;
    }

    knl_column_t *column = dc_get_column(index->entity, index->desc.columns[0]);
    uint16 offset = sizeof(btree_key_t);

    if (cursor->index_dsc) {
        if (SECUREC_UNLIKELY(key->is_infinite)) {
            return GS_FALSE;
        }

        if (btree_cmp_column(column, &scan_range->r_key, 0, key, &offset) > 0) {
            return GS_FALSE;
        }

        for (uint32 i = 1; i < index->desc.column_count; i++) {
            column = dc_get_column(index->entity, index->desc.columns[i]);
            result = btree_cmp_column(column, &scan_range->l_key, i, key, &offset);
            if (result > 0) {
                return GS_FALSE;
            } else if (result < 0) {
                return GS_TRUE;
            }
        }
    } else {
        if (btree_cmp_column(column, &scan_range->l_key, 0, key, &offset) < 0) {
            return GS_FALSE;
        }

        for (uint32 i = 1; i < index->desc.column_count; i++) {
            column = dc_get_column(index->entity, index->desc.columns[i]);
            result = btree_cmp_column(column, &scan_range->r_key, i, key, &offset);
            if (result < 0) {
                return GS_FALSE;
            } else if (result > 0) {
                return GS_TRUE;
            }
        }
    }

    return GS_TRUE;
}

static bool32 btree_do_match_cond(knl_cursor_t *cursor, btree_key_t *key)
{
    index_t *index = (index_t *)cursor->index;
    key_locator_t *locator = &cursor->key_loc;
    knl_column_t *column = NULL;
    knl_scan_key_t curr_key;
    knl_scan_key_t *l_key = cursor->index_dsc ? &cursor->scan_range.l_key : &cursor->scan_range.org_key;
    knl_scan_key_t *r_key = cursor->index_dsc ? &cursor->scan_range.org_key : &cursor->scan_range.r_key;
    uint8 i;
    uint16 offset;

    curr_key.buf = (char *)key;
    btree_decode_key(index, key, &curr_key);

    offset = curr_key.offsets[locator->equal_cols];

    if (locator->match_left) {
        offset = curr_key.offsets[locator->equal_cols];
        for (i = locator->equal_cols; i < index->desc.column_count; i++) {
            column = dc_get_column(index->entity, index->desc.columns[i]);
            offset = curr_key.offsets[i];
            if (btree_cmp_column(column, l_key, i, key, &offset) > 0) {
                return GS_FALSE;
            }
        }
    }

    if (locator->match_right) {
        offset = curr_key.offsets[locator->equal_cols];
        for (uint32 j = locator->equal_cols; j < index->desc.column_count; j++) {
            column = dc_get_column(index->entity, index->desc.columns[j]);
            offset = curr_key.offsets[j];
            if (btree_cmp_column(column, r_key, j, key, &offset) < 0) {
                return GS_FALSE;
            }
        }
    }

    return GS_TRUE;
}

static inline bool32 btree_match_cond(knl_cursor_t *cursor, btree_page_t *page)
{
    if (!cursor->key_loc.match_left && !cursor->key_loc.match_right) {
        return GS_TRUE;
    }

    btree_dir_t *dir = BTREE_GET_DIR(page, cursor->key_loc.slot);
    btree_key_t *key = BTREE_GET_KEY(page, dir);

    return btree_do_match_cond(cursor, key);
}

static status_t btree_fetch_key_asc(knl_session_t *session, knl_cursor_t *cursor, bool32 *is_found)
{
    btree_dir_t *dir = NULL;
    btree_key_t *key = NULL;
    knl_scan_key_t *filter_key = cursor->scan_range.is_equal ? &cursor->scan_range.l_key : &cursor->scan_range.r_key;
    btree_page_t *page = (cursor->key_loc.page_cache == LOCAL_PAGE_CACHE) ?
        (btree_page_t *)cursor->page_buf : BTREE_CURR_PAGE(session);
    index_t *index = (index_t *)cursor->index;
    bool32 is_equal = cursor->scan_range.is_equal && IS_UNIQUE_PRIMARY_INDEX(index);

    *is_found = GS_FALSE;

    while (cursor->key_loc.slot < page->keys) {
        cursor->ssi_conflict = GS_FALSE;
        dir = BTREE_GET_DIR(page, cursor->key_loc.slot);
        key = BTREE_GET_KEY(page, dir);
        if (!is_equal && (cursor->key_loc.slot_end == INVALID_SLOT ||
            cursor->key_loc.slot_end < cursor->key_loc.slot)) {
            /* for point scan, do not need to compare rowid */
            if (!btree_check_scan_range(cursor, index, filter_key, key)) {
                cursor->key_loc.is_last_key = GS_TRUE;
                cursor->eof = GS_TRUE;
                return GS_SUCCESS;
            }
        } else {
            /* do nothing */
        }

        *is_found = btree_match_cond(cursor, page);
        if (*is_found) {
            if (btree_check_visible(session, cursor, dir, key, is_found) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (*is_found) {
            int32 ret = memcpy_sp(cursor->scan_range.l_buf, GS_KEY_BUF_SIZE, key, (size_t)key->size);
            knl_securec_check(ret);
            key = (btree_key_t *)cursor->scan_range.l_buf;
            cursor->key_loc.is_last_key = (cursor->key_loc.slot == page->keys - 1);
            btree_decode_key(index, key, &cursor->scan_range.l_key);
            return GS_SUCCESS;
        }

        if (TX_NEED_READ_WAIT(session)) {
            cursor->key_loc.is_last_key = GS_FALSE;
            return GS_SUCCESS;
        }

        if (is_equal) {
            cursor->eof = GS_TRUE;
            return GS_SUCCESS;
        }

        cursor->key_loc.slot++;
    }

    cursor->key_loc.is_last_key = GS_TRUE;
    return GS_SUCCESS;
}

static status_t btree_fetch_key_dsc(knl_session_t *session, knl_cursor_t *cursor, bool32 *is_found)
{
    btree_dir_t *dir = NULL;
    btree_key_t *key = NULL;
    btree_page_t *page = (cursor->key_loc.page_cache == LOCAL_PAGE_CACHE) ?
        (btree_page_t *)cursor->page_buf : BTREE_CURR_PAGE(session);
    index_t *index = (index_t *)cursor->index;
    knl_scan_key_t *filter_key = &cursor->scan_range.l_key;
    int32 ret;

    *is_found = GS_FALSE;

    for (;;) {
        cursor->ssi_conflict = GS_FALSE;
        dir = BTREE_GET_DIR(page, cursor->key_loc.slot);
        key = BTREE_GET_KEY(page, dir);

        if (cursor->key_loc.slot_end == INVALID_SLOT || cursor->key_loc.slot_end > cursor->key_loc.slot) {
            if (!btree_check_scan_range(cursor, index, filter_key, key)) {
                cursor->key_loc.is_last_key = GS_TRUE;
                cursor->eof = GS_TRUE;
                return GS_SUCCESS;
            }
        }

        *is_found = btree_match_cond(cursor, page);
        if (*is_found) {
            if (btree_check_visible(session, cursor, dir, key, is_found) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (*is_found) {
            ret = memcpy_sp(cursor->scan_range.r_buf, GS_KEY_BUF_SIZE, key, (size_t)key->size);
            knl_securec_check(ret);
            key = (btree_key_t *)cursor->scan_range.r_buf;
            cursor->key_loc.is_last_key = (cursor->key_loc.slot == 0);
            btree_decode_key(index, key, &cursor->scan_range.r_key);
            return GS_SUCCESS;
        }

        if (TX_NEED_READ_WAIT(session)) {
            cursor->key_loc.is_last_key = GS_FALSE;
            return GS_SUCCESS;
        }

        if (cursor->key_loc.slot > 0) {
            cursor->key_loc.slot--;
        } else {
            break;
        }
    }

    cursor->key_loc.is_last_key = GS_TRUE;

    return GS_SUCCESS;
}

void btree_get_end_slot(knl_session_t *session, knl_cursor_t *cursor)
{
    btree_page_t *page = (btree_page_t *)cursor->page_buf;
    knl_scan_range_t *range = &cursor->scan_range;
    index_t *index = (index_t *)cursor->index;
    knl_scan_key_t *end_key = cursor->index_dsc ? &range->l_key :
        (range->is_equal ? &range->l_key : &range->r_key);
    btree_dir_t *dir = NULL;
    btree_key_t *key = NULL;
    uint16 slot;

    if (cursor->index_dsc) {
        end_key = &range->l_key;
        cursor->key_loc.slot_end = INVALID_SLOT;
        slot = 0;

        for (;;) {
            if (cursor->key_loc.slot - slot < BTREE_COMPARE_SLOT_GAP) {
                return;
            }

            dir = BTREE_GET_DIR(page, slot);
            key = BTREE_GET_KEY(page, dir);
            if (btree_check_scan_range(cursor, index, end_key, key)) {
                cursor->key_loc.slot_end = slot;
                return;
            }

            slot = (cursor->key_loc.slot + slot) >> 1;
        }
    } else {
        end_key = range->is_equal ? &range->l_key : &range->r_key;
        cursor->key_loc.slot_end = INVALID_SLOT;
        slot = page->keys - 1;

        for (;;) {
            if (slot - cursor->key_loc.slot < BTREE_COMPARE_SLOT_GAP) {
                return;
            }
            dir = BTREE_GET_DIR(page, slot);
            key = BTREE_GET_KEY(page, dir);
            if (btree_check_scan_range(cursor, index, end_key, key)) {
                cursor->key_loc.slot_end = slot;
                return;
            }

            slot = (cursor->key_loc.slot + slot) >> 1;
        }
    }
}

static status_t bt_loc_leaf(knl_session_t *session, btree_search_t *search_info, knl_cursor_t *cursor,
    knl_scan_key_t *scan_key, btree_path_info_t *path_info)
{
    btree_t *btree = search_info->btree;
    bool32 is_found = GS_FALSE;

    search_info->tree_info.value = cm_atomic_get(&BTREE_SEGMENT(session, btree->entry,
                                                                btree->segment)->tree_info.value);
    search_info->read_root_copy = (search_info->tree_info.level > 1 && !cursor->key_loc.skip_cache);

    if (!spc_validate_page_id(session, AS_PAGID(&search_info->tree_info.root))) {
        GS_THROW_ERROR(ERR_INDEX_ALREADY_DROPPED, btree->index->desc.name);
        return GS_ERROR;
    }

    if (cursor->isolevel == (uint8)ISOLATION_CURR_COMMITTED) {
        cursor->query_scn = DB_CURR_SCN(session);
        cursor->cc_cache_time = KNL_NOW(session);
        search_info->query_scn = cursor->query_scn;
    }

    bool32 asc_cmp_rowid = (!IS_UNIQUE_PRIMARY_INDEX(btree->index) || cursor->asc_relocate_next_key);
    bool32 cmp_rowid = search_info->is_dsc_scan ? GS_TRUE : asc_cmp_rowid;
    if (btree_find_leaf(session, search_info, scan_key, path_info, cmp_rowid, &is_found) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!is_found) {
        cursor->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    return GS_SUCCESS;
}

static status_t bt_loc_next_key(knl_session_t *session, btree_search_t *search_info, knl_cursor_t *cursor,
    btree_path_info_t *path_info)
{
    btree_page_t *page = BTREE_CURR_PAGE(session);

    if (search_info->is_dsc_scan) {
        if (path_info->path[0].slot == 0) {
            page_id_t prev_id = AS_PAGID(page->prev);
            buf_leave_page(session, GS_FALSE);

            path_info->path[0].page = prev_id.page;
            path_info->path[0].file = prev_id.file;

            if (buf_read_page(session, prev_id, LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
                return GS_ERROR;
            }
            page = BTREE_CURR_PAGE(session);
            path_info->path[0].slot = page->keys - 1;
        } else {
            path_info->path[0].slot--;
        }

        return GS_SUCCESS;
    }

    if (path_info->path[0].slot + 1 >= page->keys) {
        page_id_t next_id = AS_PAGID(page->next);
        if (IS_INVALID_PAGID(next_id)) {
            cursor->eof = GS_TRUE;
            buf_leave_page(session, GS_FALSE);
            return GS_SUCCESS;
        }
        buf_leave_page(session, GS_FALSE);

        if (buf_read_page(session, next_id, LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
            return GS_ERROR;
        }
        path_info->path[0].slot = 0;
        path_info->path[0].page = next_id.page;
        path_info->path[0].file = next_id.file;
    } else {
        path_info->path[0].slot++;
    }

    GS_LOG_RUN_INF("index %s relocate next key rowid %u-%u-%u", search_info->btree->index->desc.name,
        (uint32)path_info->path[0].file, (uint32)path_info->path[0].page, (uint32)path_info->path[0].slot);
    return GS_SUCCESS;
}

static status_t btree_locate_key(knl_session_t *session, btree_search_t *search_info, knl_cursor_t *cursor,
    knl_scan_key_t *scan_key, btree_path_info_t *path_info)
{
    btree_t *btree = search_info->btree;

    if (BTREE_LOCATE_NEXT_KEY(search_info, cursor)) {
        cm_latch_s(&btree->struct_latch.latch, session->id, GS_FALSE, &session->stat_btree);
    }

    status_t status = bt_loc_leaf(session, search_info, cursor, scan_key, path_info);
    if (status != GS_SUCCESS || cursor->eof) {
        if (BTREE_LOCATE_NEXT_KEY(search_info, cursor)) {
            cm_unlatch(&btree->struct_latch.latch, &session->stat_btree);
        }
        return status;
    }

    if (BTREE_LOCATE_NEXT_KEY(search_info, cursor)) {
        status = bt_loc_next_key(session, search_info, cursor, path_info);
        cm_unlatch(&btree->struct_latch.latch, &session->stat_btree);
    }
    return status;
}

static status_t btree_locate_with_find(knl_session_t *session, knl_cursor_t *cursor, knl_scan_key_t *scan_key)
{
    btree_page_t *page = NULL;
    btree_t *btree;
    btree_search_t search_info;
    btree_path_info_t path_info;
    int32 ret;

    btree = CURSOR_BTREE(cursor);
    search_info.btree = btree;
    search_info.seg_scn = (IS_PART_INDEX((cursor)->index) ?
        ((index_part_t *)(cursor)->index_part)->desc.seg_scn : ((index_t *)(cursor)->index)->desc.seg_scn);
    search_info.is_dsc_scan = (bool32)cursor->index_dsc;
    search_info.is_equal = cursor->scan_range.is_equal && IS_UNIQUE_PRIMARY_INDEX(btree->index) && (!cursor->index_dsc);
    search_info.is_full_scan = cursor->index_ffs;
    search_info.query_scn = cursor->query_scn;
    search_info.isolevel = cursor->isolevel;

    if (btree_locate_key(session, &search_info, cursor, scan_key, &path_info) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cursor->eof) {
        return GS_SUCCESS;
    }

    page = BTREE_CURR_PAGE(session);
    cursor->key_loc.seg_scn = search_info.seg_scn;
    cursor->key_loc.lsn = page->head.lsn;
    cursor->key_loc.slot = (uint16)path_info.path[0].slot;
    cursor->key_loc.page_id = GET_ROWID_PAGE(path_info.path[0]);
    cursor->key_loc.pid_snap_scn = search_info.parent_snap_scn;
    cursor->key_loc.next_page_id = AS_PAGID(page->next);
    cursor->key_loc.prev_page_id = AS_PAGID(page->prev);
    cursor->key_loc.next_pid_snap_scn = search_info.child_snap_scn;
    cursor->key_loc.is_located = GS_TRUE;
    cursor->key_loc.pcn = page->head.pcn;
    cursor->key_loc.index_ver = (uint64)cm_atomic_get(&btree->struct_ver);

    if (search_info.is_equal || cursor->action != CURSOR_ACTION_SELECT) {
        cursor->key_loc.page_cache = NO_PAGE_CACHE;
        cursor->key_loc.slot_end = INVALID_SLOT;
    } else {
        cursor->key_loc.page_cache = LOCAL_PAGE_CACHE;
        ret = memcpy_sp(cursor->page_buf, DEFAULT_PAGE_SIZE(session), page, PAGE_SIZE(page->head));
        knl_securec_check(ret);
        buf_leave_page(session, GS_FALSE);
        btree_get_end_slot(session, cursor);
    }

    return GS_SUCCESS;
}

static status_t btree_enter_next_page(knl_session_t *session, knl_cursor_t *cursor,
    page_id_t *next_page, knl_scn_t *next_snap_scn, bool32 *check_next)
{
    btree_search_t search_info;

    *check_next = GS_FALSE;
    if (cursor->isolevel == (uint8)ISOLATION_CURR_COMMITTED) {
        cursor->query_scn = DB_CURR_SCN(session);
        cursor->cc_cache_time = KNL_NOW(session);
    }

    if (cursor->index_ffs) {
        if (buf_read_prefetch_page(session, *next_page, LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        if (buf_read_page(session, *next_page, LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    btree_page_t *page = BTREE_CURR_PAGE(session);

    search_info.btree = CURSOR_BTREE(cursor);
    search_info.seg_scn = cursor->key_loc.seg_scn;
    search_info.is_equal = GS_FALSE;
    search_info.query_scn = cursor->query_scn;
    search_info.isolevel = cursor->isolevel;
    search_info.ssn = (uint32)cursor->ssn;
    search_info.is_full_scan = cursor->index_ffs;
    btree_segment_t *seg = BTREE_SEGMENT(session, search_info.btree->entry, search_info.btree->segment);

    if (bt_chk_page(session, &search_info, page) != GS_SUCCESS) {
        buf_leave_page(session, GS_FALSE);
        return GS_ERROR;
    }

    if (page->is_recycled) {
        *next_page = cursor->index_dsc ? AS_PAGID(page->prev) : AS_PAGID(page->next);
        *next_snap_scn = KNL_GET_SCN(&seg->recycle_ver_scn);
        buf_leave_page(session, GS_FALSE);
        *check_next = GS_TRUE;
    }
    return GS_SUCCESS;
}

static void bt_loc_next_locator(knl_session_t *session, knl_cursor_t *cursor, btree_page_t *page,
    knl_scn_t next_pid_snap_scn)
{
    btree_t *btree = CURSOR_BTREE(cursor);
    btree_segment_t *seg = BTREE_SEGMENT(session, btree->entry, btree->segment);

    cursor->key_loc.page_id = AS_PAGID(page->head.id);
    cursor->key_loc.lsn = page->head.lsn;
    cursor->key_loc.pid_snap_scn = next_pid_snap_scn;
    cursor->key_loc.pcn = page->head.pcn;
    cursor->key_loc.next_page_id = AS_PAGID(page->next);
    cursor->key_loc.prev_page_id = AS_PAGID(page->prev);
    cursor->key_loc.next_pid_snap_scn = KNL_GET_SCN(&seg->recycle_ver_scn);
    if (cursor->key_loc.page_cache == LOCAL_PAGE_CACHE) {
        errno_t err = memcpy_sp(cursor->page_buf, DEFAULT_PAGE_SIZE(session), page, PAGE_SIZE(page->head));
        knl_securec_check(err);
        buf_leave_page(session, GS_FALSE);
        btree_get_end_slot(session, cursor);
    }
}

static status_t bt_reloc_next_key(knl_session_t *session, knl_cursor_t *cursor, knl_scan_key_t *scan_key)
{
    cursor->key_loc.is_located = GS_FALSE;
    cursor->key_loc.skip_cache = GS_TRUE;
    if (!cursor->index_dsc) {
        cursor->asc_relocate_next_key = GS_TRUE;
    }

    status_t status = btree_locate_with_find(session, cursor, scan_key);
    cursor->asc_relocate_next_key = GS_FALSE;
    return status;
}

static status_t btree_locate_next_page(knl_session_t *session, knl_cursor_t *cursor, knl_scan_key_t *scan_key)
{
    btree_page_t *page = NULL;
    btree_t *btree = CURSOR_BTREE(cursor);
    bool32 check_next = GS_FALSE;

    if (session->canceled) {
        GS_THROW_ERROR(ERR_OPERATION_CANCELED);
        return GS_ERROR;
    }

    if (session->killed) {
        GS_THROW_ERROR(ERR_OPERATION_KILLED);
        return GS_ERROR;
    }

    page_id_t next_page = cursor->index_dsc ? cursor->key_loc.prev_page_id : cursor->key_loc.next_page_id;
    knl_scn_t next_snap_scn = cursor->key_loc.next_pid_snap_scn;

    for (;;) {
        if (IS_INVALID_PAGID(next_page)) {
            cursor->eof = GS_TRUE;
            return GS_SUCCESS;
        }

        if (btree_enter_next_page(session, cursor, &next_page, &next_snap_scn, &check_next) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (check_next) {
            continue;
        }
        break;
    }

    page = BTREE_CURR_PAGE(session);
    if (bt_chk_leaf_recycled(session, btree, page, next_snap_scn)) {
        buf_leave_page(session, GS_FALSE);
        return bt_reloc_next_key(session, cursor, scan_key);
    }

    if (cursor->index_dsc) {
        if (!IS_SAME_PAGID(AS_PAGID(page->next), cursor->key_loc.page_id)) {
            buf_leave_page(session, GS_FALSE);
            cursor->key_loc.is_located = GS_FALSE;
            return btree_locate_with_find(session, cursor, scan_key);
        }

        cursor->key_loc.slot = page->keys - 1;
    } else {
        cursor->key_loc.slot = 0;
    }

    bt_loc_next_locator(session, cursor, page, next_snap_scn);
    return GS_SUCCESS;
}

static status_t btree_relocate_curr_page(knl_session_t *session, knl_cursor_t *cursor, knl_scan_key_t *scan_key)
{
    bool32 is_same = GS_FALSE;
    btree_path_info_t path_info;
    btree_t *btree = CURSOR_BTREE(cursor);
    btree_segment_t *seg = BTREE_SEGMENT(session, btree->entry, btree->segment);
    bool32 cmp_rowid = BTREE_NEED_CMP_ROWID(cursor, btree->index);
    btree_page_t *page = BTREE_CURR_PAGE(session);
    btree_search_t search_info;
    int64 struct_ver;
    errno_t err;

    /* if split happened on this page, re-search from root */
    struct_ver = cm_atomic_get(&btree->struct_ver);
    if (cursor->index_dsc && cursor->key_loc.index_ver != (uint64)struct_ver) {
        buf_leave_page(session, GS_FALSE);
        cursor->key_loc.is_located = GS_FALSE;
        return btree_locate_with_find(session, cursor, scan_key);
    }

    search_info.btree = CURSOR_BTREE(cursor);
    search_info.seg_scn = cursor->key_loc.seg_scn;
    search_info.is_equal = GS_FALSE;
    search_info.query_scn = cursor->query_scn;
    search_info.isolevel = cursor->isolevel;
    search_info.ssn = (uint32)cursor->ssn;
    search_info.is_full_scan = cursor->index_ffs;

    if (bt_chk_page(session, &search_info, page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (bt_chk_leaf_recycled(session, btree, page, cursor->key_loc.pid_snap_scn)) {
        buf_leave_page(session, GS_FALSE);
        return bt_reloc_next_key(session, cursor, scan_key);
    }

    for (;;) {
        btree_binary_search(btree->index, page, scan_key, &path_info, cmp_rowid, &is_same);
        if (cursor->index_dsc) {
            if (path_info.path[0].slot == 0) {
                buf_leave_page(session, GS_FALSE);
                cursor->key_loc.is_located = GS_FALSE;
                return btree_locate_with_find(session, cursor, scan_key);
            }

            cursor->key_loc.slot = (uint16)path_info.path[0].slot - 1;
            break;
        }

        if (path_info.path[0].slot < page->keys - (uint16)1) {
            /* if key is still on current page, then move on to next slot */
            cursor->key_loc.slot = (uint16)path_info.path[0].slot + 1;
            break;
        }

        cursor->key_loc.page_id = AS_PAGID(page->next);
        cursor->key_loc.pid_snap_scn = KNL_GET_SCN(&seg->recycle_ver_scn);
        buf_leave_page(session, GS_FALSE);

        if (IS_INVALID_PAGID(cursor->key_loc.page_id)) {
            cursor->eof = GS_TRUE;
            return GS_SUCCESS;
        }

        if (buf_read_page(session, cursor->key_loc.page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
            return GS_ERROR;
        }
        page = BTREE_CURR_PAGE(session);
        if (page_soft_damaged(&page->head)) {
            GS_THROW_ERROR(ERR_PAGE_SOFT_DAMAGED, AS_PAGID(&page->head.id).file, AS_PAGID(&page->head.id).page);
            return GS_ERROR;
        }

        if (bt_chk_page(session, &search_info, page) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (bt_chk_leaf_recycled(session, btree, page, cursor->key_loc.pid_snap_scn)) {
            buf_leave_page(session, GS_FALSE);
            return bt_reloc_next_key(session, cursor, scan_key);
        }

        /* if scan key is last key of prev page, no need to binary search on curr page */
        if (is_same) {
            cursor->key_loc.slot = 0;
            break;
        }
    }

    cursor->key_loc.lsn = page->head.lsn;
    cursor->key_loc.pcn = page->head.pcn;
    cursor->key_loc.next_page_id = AS_PAGID(page->next);
    cursor->key_loc.prev_page_id = AS_PAGID(page->prev);
    cursor->key_loc.next_pid_snap_scn = KNL_GET_SCN(&seg->recycle_ver_scn);
    if (cursor->key_loc.page_cache == LOCAL_PAGE_CACHE) {
        err = memcpy_sp(cursor->page_buf, DEFAULT_PAGE_SIZE(session), page, PAGE_SIZE(page->head));
        knl_securec_check(err);
        buf_leave_page(session, GS_FALSE);
        btree_get_end_slot(session, cursor);
    }

    return GS_SUCCESS;
}

static inline bool32 btree_cached_valid(knl_session_t *session, knl_cursor_t *cursor)
{
    date_t timeout;

    if (cursor->key_loc.page_cache == LOCAL_PAGE_CACHE) {
        if (cursor->isolevel != (uint8)ISOLATION_CURR_COMMITTED) {
            return GS_TRUE;
        }

        timeout = (date_t)session->kernel->undo_ctx.retention * MICROSECS_PER_SECOND / RETENTION_TIME_PERCENT;

        return (bool32)((KNL_NOW(session) - cursor->cc_cache_time) < timeout);
    }

    return GS_FALSE;
}

static status_t btree_locate_curr_page(knl_session_t *session, knl_cursor_t *cursor, knl_scan_key_t *scan_key)
{
    btree_page_t *page = NULL;
    bool32 use_curr_slot = TX_NEED_READ_WAIT(session);

    if (TX_NEED_READ_WAIT(session)) {
        GS_LOG_DEBUG_INF("locate key on curr btree page need begin read wait.");
        if (tx_wait(session, 0, ENQ_TX_READ_WAIT) != GS_SUCCESS) {
            tx_record_rowid(session->wrid);
            return GS_ERROR;
        }
    }

    if (btree_cached_valid(session, cursor)) {
        if (use_curr_slot) {
            return GS_SUCCESS;
        }
        if (cursor->index_dsc) {
            cursor->key_loc.slot--;
        } else {
            cursor->key_loc.slot++;
        }
        return GS_SUCCESS;
    }

    if (cursor->isolevel == (uint8)ISOLATION_CURR_COMMITTED) {
        cursor->query_scn = DB_CURR_SCN(session);
        cursor->cc_cache_time = KNL_NOW(session);
    }

    if (buf_read_page(session, cursor->key_loc.page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
        return GS_ERROR;
    }
    page = BTREE_CURR_PAGE(session);
    if (page->head.lsn == cursor->key_loc.lsn &&
        page->head.pcn == cursor->key_loc.pcn) { // page never changed after the last fetch
        if (use_curr_slot) {
            return GS_SUCCESS;
        }

        if (cursor->index_dsc) {
            cursor->key_loc.slot--;
        } else {
            cursor->key_loc.slot++;
        }

        if (cursor->key_loc.slot >= page->keys) {
            knl_panic_log(0, "key's slot is bigger than page keys, panic info: slot %u page %u-%u type %u keys %u "
                          "table %s", cursor->key_loc.slot, cursor->rowid.file, cursor->rowid.page, page->head.type,
                          page->keys, ((table_t *)cursor->table)->desc.name);
            buf_leave_page(session, GS_FALSE);
        }

        if (cursor->key_loc.page_cache == LOCAL_PAGE_CACHE) {
            buf_leave_page(session, GS_FALSE);
        }
        return GS_SUCCESS;
    }

    if (btree_relocate_curr_page(session, cursor, scan_key) != GS_SUCCESS) {
        buf_leave_page(session, GS_FALSE);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static inline status_t btree_find_key(knl_session_t *session, knl_cursor_t *cursor, knl_scan_key_t *scan_key)
{
    if (!cursor->key_loc.is_located) {
        return btree_locate_with_find(session, cursor, scan_key);
    } else if (cursor->key_loc.is_last_key) {
        return btree_locate_next_page(session, cursor, scan_key);
    } else {
        return btree_locate_curr_page(session, cursor, scan_key);
    }
}

page_id_t btree_clean_copied_itl(knl_session_t *session, uint64 itl_xid, page_id_t p_page_id, bool32 need_redo)
{
    page_id_t page_id = p_page_id;
    txn_info_t txn_info;
    bool32 is_changed = GS_FALSE;
    rd_btree_clean_itl_t redo;
    itl_t *itl = NULL;
    btree_page_t *page = NULL;
    uint8 i;

    log_atomic_op_begin(session);
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = BTREE_CURR_PAGE(session);

    for (i = 0; i < page->itls; i++) {
        itl = BTREE_GET_ITL(page, i);
        if (!itl->is_active) {
            continue;
        }

        if (itl->xid.value != itl_xid) {
            continue;
        }

        if (itl->xid.value == session->rm->xid.value) {
            itl->is_active = GS_FALSE;
            itl->scn = session->rm->txn->scn;
            itl->is_owscn = 0;
            itl->xid.value = GS_INVALID_ID64;
        } else {
            tx_get_itl_info(session, GS_FALSE, itl, &txn_info);
            knl_panic_log(txn_info.status == (uint8)XACT_END, "current txn status is abnormal, panic info: page %u-%u "
                          "type %u status %u", page_id.file, page_id.page, page->head.type, txn_info.status);
            itl->is_active = GS_FALSE;
            itl->scn = txn_info.scn;
            itl->is_owscn = (uint16)txn_info.is_owscn;
            itl->xid.value = GS_INVALID_ID64;
        }

        if (need_redo) {
            redo.itl_id = i;
            redo.scn = itl->scn;
            redo.is_owscn = (uint8)itl->is_owscn;
            redo.is_copied = (uint8)itl->is_copied;
            redo.aligned = (uint8)0;
            log_put(session, RD_BTREE_CLEAN_ITL, &redo, sizeof(rd_btree_clean_itl_t), LOG_ENTRY_FLAG_NONE);
        }
        is_changed = GS_TRUE;
        break;
    }
    page_id = AS_PAGID(page->next);
    buf_leave_page(session, is_changed);
    log_atomic_op_end(session);

    return page_id;
}

static void btree_cleanout_itls(knl_session_t *session, knl_cursor_t *cursor, btree_page_t *page,
    bool32 *changed)
{
    itl_t *itl = NULL;
    txn_info_t txn_info;
    rd_btree_clean_itl_t redo;
    uint8 i;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);

    // clean current page
    for (i = 0; i < page->itls; i++) {
        itl = BTREE_GET_ITL(page, i);
        if (!itl->is_active) {
            continue;
        }

        tx_get_itl_info(session, GS_FALSE, itl, &txn_info);
        if (txn_info.status != (uint8)XACT_END) {
            continue;
        }

        itl->is_active = 0;
        itl->scn = txn_info.scn;
        itl->is_owscn = (uint16)txn_info.is_owscn;
        itl->xid.value = GS_INVALID_ID64;

        if (itl->is_copied) {
            itl->is_copied = GS_FALSE;
        }

        if (need_redo && cursor->logging) {
            redo.itl_id = i;
            redo.scn = itl->scn;
            redo.is_owscn = (uint8)itl->is_owscn;
            redo.is_copied = GS_FALSE;
            redo.aligned = (uint8)0;
            log_put(session, RD_BTREE_CLEAN_ITL, &redo, sizeof(rd_btree_clean_itl_t), LOG_ENTRY_FLAG_NONE);
        }

        *changed = GS_TRUE;
    }
}

static void btree_cleanout_page(knl_session_t *session, knl_cursor_t *cursor, page_id_t page_id)
{
    btree_page_t *page = NULL;
    bool32 lock_inuse = GS_FALSE;
    bool32 is_changed = GS_FALSE;

    if (DB_IS_READONLY(session)) {
        return;
    }

    // may be called during rollback, already in atmatic operation
    if (session->atomic_op) {
        return;
    }

    if (!lock_table_without_xact(session, cursor->dc_entity, &lock_inuse)) {
        cm_reset_error();
        return;
    }

    log_atomic_op_begin(session);
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = BTREE_CURR_PAGE(session);
    if (page_soft_damaged(&page->head)) {
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        unlock_table_without_xact(session, cursor->dc_entity, lock_inuse);
        return;
    }

    if (btree_check_segment_scn(page, PAGE_TYPE_BTREE_NODE, cursor->key_loc.seg_scn) != GS_SUCCESS ||
        page->is_recycled) {
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        unlock_table_without_xact(session, cursor->dc_entity, lock_inuse);
        return;
    }

    btree_cleanout_itls(session, cursor, page, &is_changed);

    cursor->cleanout = GS_FALSE;
    buf_leave_page(session, is_changed);
    log_atomic_op_end(session);
    unlock_table_without_xact(session, cursor->dc_entity, lock_inuse);
}

static status_t btree_locate_next_scan_key(knl_session_t *session, knl_cursor_t *cursor)
{
    knl_scan_key_t *scan_key = cursor->index_dsc ? &cursor->scan_range.r_key : &cursor->scan_range.l_key;
    knl_scan_key_t next_scan_key;
    btree_t *btree = CURSOR_BTREE(cursor);
    index_t *index = btree->index;
    uint16 len;
    uint16 offset = sizeof(btree_key_t);
    btree_page_t *page = NULL;

    if (cursor->key_loc.page_cache == NO_PAGE_CACHE) {
        buf_enter_page(session, cursor->key_loc.page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page = BTREE_CURR_PAGE(session);
        if (bt_chk_leaf_recycled(session, btree, page, cursor->key_loc.pid_snap_scn)) {
            buf_leave_page(session, GS_FALSE);
            cursor->eof = GS_FALSE;
            return GS_SUCCESS;
        }
        errno_t ret = memcpy_sp(cursor->page_buf, DEFAULT_PAGE_SIZE(session), page, PAGE_SIZE(page->head));
        knl_securec_check(ret);
        buf_leave_page(session, GS_FALSE);
        cursor->key_loc.page_cache = LOCAL_PAGE_CACHE;
    }

    page = (btree_page_t *)cursor->page_buf;
    btree_dir_t *dir = BTREE_GET_DIR(page, (uint32)cursor->key_loc.slot);
    btree_key_t *key = BTREE_GET_KEY(page, dir);
    knl_column_t *column = dc_get_column(index->entity, index->desc.columns[0]);

    if (btree_cmp_column(column, scan_key, 0, key, &offset) != 0) {
        cursor->eof = GS_FALSE;
        return GS_SUCCESS;
    }

    next_scan_key.buf = (char *)cm_push(session->stack, GS_KEY_BUF_SIZE);
    next_scan_key.flags[0] = scan_key->flags[0];
    btree_init_key((btree_key_t *)next_scan_key.buf, NULL);

    if (scan_key->flags[0] == SCAN_KEY_NORMAL) {
        char *data = btree_get_column(scan_key, column->datatype, 0, &len, GS_FALSE);
        knl_set_scan_key(&index->desc, &next_scan_key, column->datatype, (const char *)data, len, 0);
    } else {
        knl_set_key_flag(&next_scan_key, scan_key->flags[0], 0);
    }

    uint8 flag = cursor->index_dsc ? SCAN_KEY_LEFT_INFINITE : SCAN_KEY_RIGHT_INFINITE;

    for (uint32 i = 1; i < index->desc.column_count; i++) {
        knl_set_key_flag(&next_scan_key, flag, i);
    }

    btree_search_t search_info;
    btree_path_info_t path_info;

    search_info.btree = btree;
    search_info.seg_scn = cursor->key_loc.seg_scn;
    search_info.tree_info.value = cm_atomic_get(&btree->segment->tree_info.value);
    search_info.is_dsc_scan = cursor->index_dsc;
    search_info.is_equal = GS_FALSE;
    search_info.is_full_scan = GS_FALSE;
    search_info.query_scn = cursor->query_scn;
    search_info.isolevel = cursor->isolevel;
    search_info.ssn = (uint32)cursor->ssn;
    cursor->eof = GS_FALSE;

    if (btree_locate_key(session, &search_info, cursor, &next_scan_key, &path_info) != GS_SUCCESS) {
        cm_pop(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        cm_pop(session->stack);
        return GS_SUCCESS;
    }

    page = BTREE_CURR_PAGE(session);
    errno_t ret = memcpy_sp(cursor->page_buf, DEFAULT_PAGE_SIZE(session), page, PAGE_SIZE(page->head));
    knl_securec_check(ret);
    buf_leave_page(session, GS_FALSE);

    cursor->key_loc.page_cache = LOCAL_PAGE_CACHE;
    cursor->key_loc.slot = (uint16)path_info.path[0].slot;
    cm_pop(session->stack);
    return GS_SUCCESS;
}

static void btree_set_next_scan_key(knl_session_t *session, knl_cursor_t *cursor, index_t *index, btree_key_t *key,
    knl_scan_key_t *scan_key)
{
    knl_scan_key_t next_scan_key;
    knl_column_t *column = NULL;
    char *data = NULL;
    uint16 len;

    next_scan_key.buf = (char *)cm_push(session->stack, GS_KEY_BUF_SIZE);
    btree_decode_key(index, key, &next_scan_key);
    errno_t ret = memset_sp(scan_key->buf, sizeof(btree_key_t), 0, sizeof(btree_key_t));
    knl_securec_check(ret);
    if (SECUREC_UNLIKELY(cursor->index_dsc)) {
        rowid_t max_rid;
        MAXIMIZE_ROWID(max_rid);
        btree_init_key((btree_key_t *)scan_key->buf, &max_rid);
    } else {
        btree_init_key((btree_key_t *)scan_key->buf, NULL);
    }

    if (!btree_get_bitmap(&key->bitmap, 0)) {
        knl_set_key_flag(scan_key, SCAN_KEY_IS_NULL, 0);
    } else {
        column = dc_get_column(index->entity, index->desc.columns[0]);
        data = btree_get_column(&next_scan_key, column->datatype, 0, &len, GS_FALSE);
        knl_set_scan_key(&index->desc, scan_key, column->datatype, data, len, 0);
    }

    for (uint32 i = 1; i < index->desc.column_count; i++) {
        scan_key->flags[i] = cursor->scan_range.org_key.flags[i];
        if (scan_key->flags[i] == SCAN_KEY_NORMAL) {
            column = dc_get_column(index->entity, index->desc.columns[i]);
            data = btree_get_column(&cursor->scan_range.org_key, column->datatype, i, &len, GS_FALSE);
            knl_set_scan_key(&index->desc, scan_key, column->datatype, data, len, i);
        }
    }
    cm_pop(session->stack);
}

static status_t btree_set_next_range(knl_session_t *session, knl_cursor_t *cursor, btree_t *btree)
{
    knl_scan_key_t *scan_key = cursor->index_dsc ? &cursor->scan_range.r_key : &cursor->scan_range.l_key;
    knl_scan_key_t *end_key = cursor->index_dsc ? &cursor->scan_range.l_key : &cursor->scan_range.r_key;
    index_t *index = btree->index;

    if (btree_locate_next_scan_key(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cursor->eof) {
        return GS_SUCCESS;
    }

    btree_page_t *page = (btree_page_t *)cursor->page_buf;
    btree_dir_t *dir = BTREE_GET_DIR(page, (uint32)cursor->key_loc.slot);
    btree_key_t *key = BTREE_GET_KEY(page, dir);

    int32 result = btree_compare_key(index, end_key, key, GS_TRUE, NULL);
    cursor->eof = cursor->index_dsc ? (result > 0) : (result < 0);

    if (cursor->eof) {
        return GS_SUCCESS;
    }

    btree_set_next_scan_key(session, cursor, index, key, scan_key);

    cursor->key_loc.is_located = GS_FALSE;
    cursor->key_loc.is_last_key = GS_FALSE;

    return GS_SUCCESS;
}

static inline status_t btree_check_eof(knl_session_t *session, knl_cursor_t *cursor)
{
    if (!cursor->eof || !cursor->index_ss) {
        return GS_SUCCESS;
    }

    return btree_set_next_range(session, cursor, CURSOR_BTREE(cursor));
}

void btree_init_match_cond(knl_cursor_t *cursor, bool32 is_pcr)
{
    index_t *index = (index_t *)cursor->index;
    uint8 i;

    if (cursor->scan_range.is_equal || cursor->skip_index_match ||
        index->desc.column_count == 1 || cursor->index_paral || index->desc.is_reverse) {
        cursor->key_loc.match_left = GS_FALSE;
        cursor->key_loc.match_right = GS_FALSE;
        return;
    }

    btree_set_match_cond(cursor);

    if (!cursor->key_loc.match_right && !cursor->key_loc.match_left) {
        return;
    }

    knl_scan_key_t *l_key = &cursor->scan_range.l_key;
    knl_scan_key_t *r_key = &cursor->scan_range.r_key;
    knl_column_t *column = NULL;
    uint16 offset = is_pcr ? sizeof(pcrb_key_t) : sizeof(btree_key_t);

    for (i = 0; i < index->desc.column_count - 1; i++) {
        if (l_key->flags[i] != SCAN_KEY_NORMAL ||
            r_key->flags[i] != SCAN_KEY_NORMAL) {
            break;
        }

        column = dc_get_column(index->entity, index->desc.columns[i]);
        if (btree_cmp_column_data((void *)(l_key->buf + l_key->offsets[i]),
            (void *)(r_key->buf + r_key->offsets[i]), column->datatype,
            &offset, is_pcr) != 0) {
            break;
        }
    }

    if (i == index->desc.column_count - 1) {
        cursor->key_loc.match_left = GS_FALSE;
        cursor->key_loc.match_right = GS_FALSE;
        return;
    }

    cursor->key_loc.equal_cols = i;
}

static inline void btree_save_org_key(knl_cursor_t *cursor)
{
    cursor->scan_range.org_key = cursor->index_dsc ? cursor->scan_range.r_key : cursor->scan_range.l_key;
    btree_key_t *key = (btree_key_t *)(cursor->index_dsc ? cursor->scan_range.r_buf : cursor->scan_range.l_buf);

    cursor->scan_range.org_key.buf = cursor->scan_range.org_buf;
    errno_t ret = memcpy_sp(cursor->scan_range.org_buf, GS_KEY_BUF_SIZE, key, (size_t)key->size);
    knl_securec_check(ret);
}

static void btree_init_fetch(knl_session_t *session, knl_cursor_t *cursor)
{
    /*
    * for PAGE LEVEL SNAPSHOT, index fast full scan use the same scan mode with index full scan
    * later, we will implement specified scan mode for index ffs, which scan leaf pages by extent.
    */
    cursor->index_ffs = cursor->index_ffs ? GS_TRUE : btree_is_full_scan(&cursor->scan_range);
    btree_init_key_loc(&cursor->key_loc);

    if (SECUREC_UNLIKELY(cursor->index_ss)) {
        if (cursor->scan_range.is_equal) {
            cursor->index_ss = GS_FALSE;
            btree_set_cmp_endpoint(cursor);
            return;
        }

        knl_panic_log(((index_t *)cursor->index)->desc.column_count > BTREE_MIN_SKIP_COLUMNS, "the column count is "
            "abnormal, panic info: page %u-%u type %u table %s index %s column count %u", cursor->rowid.file,
            cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name,
            ((index_t *)cursor->index)->desc.name, ((index_t *)cursor->index)->desc.column_count);
        btree_save_org_key(cursor);
        return;
    }

    btree_init_match_cond(cursor, GS_FALSE);
    if (cursor->index_dsc) {
        if (cursor->key_loc.match_right) {
            btree_save_org_key(cursor);
        }
    } else {
        if (cursor->key_loc.match_left) {
            btree_save_org_key(cursor);
        }
    }

    btree_set_cmp_endpoint(cursor);
}
/*
* Description     : Entry of btree fetch
* Input           : session
* Input           : cursor : search key is set in cursor->scan_range
* Output          : cursor : heap row fetched is set in cursor->row, and
* cursor->scan_range.l_key is set to current key for next search.
* Return Value    : status_t
* History         : 1.2017/4/26,  add description
*/
status_t btree_fetch(knl_handle_t handle, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)handle;
    btree_t *btree = NULL;
    status_t status;
    seg_stat_t temp_stat;

    CM_ASSERT(!DB_IS_CLUSTER(session));

    SEG_STATS_INIT(session, &temp_stat);

    btree = CURSOR_BTREE(cursor);
    if (SECUREC_UNLIKELY(btree->segment == NULL)) {
        cursor->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    bool32 unique_equal_fetch = IS_UNIQUE_PRIMARY_INDEX(btree->index) && cursor->scan_range.is_equal;
    knl_scan_key_t *scan_key = cursor->index_dsc ? &cursor->scan_range.r_key : &cursor->scan_range.l_key;

    if (!cursor->key_loc.is_initialized) {
        btree_init_fetch(session, cursor);
    }

    for (;;) {
        if (unique_equal_fetch && cursor->key_loc.is_located && !TX_NEED_READ_WAIT(session)) {
            cursor->eof = GS_TRUE;
            return GS_SUCCESS;
        }

        if (btree_find_key(session, cursor, scan_key) != GS_SUCCESS) {
            SEG_STATS_RECORD(session, temp_stat, &btree->stat);
            return GS_ERROR;
        }

        if (cursor->eof) {
            SEG_STATS_RECORD(session, temp_stat, &btree->stat);
            return GS_SUCCESS;
        }

        if (cursor->index_dsc) {
            status = btree_fetch_key_dsc(session, cursor, &cursor->is_found);
        } else {
            status = btree_fetch_key_asc(session, cursor, &cursor->is_found);
        }

        if (cursor->key_loc.page_cache == NO_PAGE_CACHE) {
            buf_leave_page(session, GS_FALSE);
        }

        if (status != GS_SUCCESS) {
            return GS_ERROR;
        }
        
        if (cursor->is_found) {
            if (knl_cursor_ssi_conflict(cursor, GS_FALSE) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (cursor->cleanout && !unique_equal_fetch && cursor->key_loc.is_last_key) {
            btree_cleanout_page(session, cursor, cursor->key_loc.page_id);
        }

        if (btree_check_eof(session, cursor) != GS_SUCCESS) {
            SEG_STATS_RECORD(session, temp_stat, &btree->stat);
            return GS_ERROR;
        }

        if (cursor->eof) {
            SEG_STATS_RECORD(session, temp_stat, &btree->stat);
            return GS_SUCCESS;
        }

        if (TX_NEED_READ_WAIT(session)) {
            GS_LOG_DEBUG_INF("fetch btree need read wait.");
            continue;
        }

        if (!cursor->is_found) {
            continue;
        }
        
        if (IS_INDEX_ONLY_SCAN(cursor)) {
            if (cursor->index_prefetch_row) {
                if (buf_read_page_asynch(session, GET_ROWID_PAGE(cursor->rowid)) != GS_SUCCESS) {
                    GS_LOG_DEBUG_WAR("failed to prefetch page file : %u , page: %llu",
                        (uint32)cursor->rowid.file, (uint64)cursor->rowid.page);
                }
            }

            if (knl_match_cond(session, cursor, &cursor->is_found) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            if (TABLE_ACCESSOR(cursor)->do_fetch_by_rowid(session, cursor) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (cursor->is_found) {
            SEG_STATS_RECORD(session, temp_stat, &btree->stat);
            return GS_SUCCESS;
        }
    }
}

status_t bt_chk_exist_pre(knl_session_t *session, btree_t *btree, btree_search_t *search_info)
{
    knl_tree_info_t tree_info;

    search_info->btree = btree;
    search_info->is_dsc_scan = GS_FALSE;
    search_info->is_equal = GS_TRUE;
    search_info->seg_scn = BTREE_SEGMENT(session, btree->entry, btree->segment)->seg_scn;
    tree_info.value = cm_atomic_get(&BTREE_SEGMENT(session, btree->entry, btree->segment)->tree_info.value);
    search_info->tree_info = tree_info;
    search_info->is_full_scan = GS_FALSE;
    search_info->query_scn = DB_CURR_SCN(session);
    search_info->isolevel = (uint8)ISOLATION_CURR_COMMITTED;
    search_info->read_root_copy = (search_info->tree_info.level > 1);
    search_info->use_cr_pool = GS_TRUE;
    if (!spc_validate_page_id(session, AS_PAGID(&tree_info.root))) {
        GS_THROW_ERROR(ERR_INDEX_ALREADY_DROPPED, btree->index->desc.name);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t btree_check_key_exist(knl_session_t *session, btree_t *btree, char *data, bool32 *exists)
{
    btree_path_info_t path_info;
    bool32 found = GS_FALSE;
    txn_info_t txn_info;
    knl_scan_key_t scan_key;
    btree_search_t search_info;

    if (btree->segment == NULL) {
        return GS_SUCCESS;
    }

    btree_key_t *key = (btree_key_t *)data;
    btree_decode_key(btree->index, key, &scan_key);
    if (bt_chk_exist_pre(session, btree, &search_info) != GS_SUCCESS) {
        return GS_ERROR;
    }

    bool32 cmp_rowid = search_info.is_dsc_scan ? GS_TRUE : !IS_UNIQUE_PRIMARY_INDEX(btree->index);

    for (;;) {
        if (btree_find_leaf(session, &search_info, &scan_key, &path_info, cmp_rowid, &found) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (!found) {
            *exists = GS_FALSE;
            return GS_SUCCESS;
        }

        btree_page_t *page = BTREE_CURR_PAGE(session);
        btree_dir_t *dir = BTREE_GET_DIR(page, path_info.path[0].slot);
        key = BTREE_GET_KEY(page, dir);

        if (GS_INVALID_ID8 == dir->itl_id) {
            break;
        }

        itl_t *itl = BTREE_GET_ITL(page, dir->itl_id);
        if (itl->xid.value == session->rm->xid.value) {
            break;
        }

        tx_get_itl_info(session, GS_FALSE, itl, &txn_info);
        if (txn_info.status == (uint8)XACT_END) {
            break;
        }
        ROWID_COPY(session->wrid, key->rowid);
        session->wxid = itl->xid;
        buf_leave_page(session, GS_FALSE);

        btree->stat.row_lock_waits++;
        if (tx_wait(session, session->lock_wait_timeout, ENQ_TX_KEY) != GS_SUCCESS) {
            tx_record_rowid(session->wrid);
            return GS_ERROR;
        }
    }

    *exists = (!key->is_deleted);
    buf_leave_page(session, GS_FALSE);

    return GS_SUCCESS;
}

static status_t btree_check_exist(knl_session_t *session, btree_dir_t *dir, btree_key_t *key, bool32 *is_found,
    bool32 *is_wait)
{
    btree_page_t *page = NULL;
    itl_t *itl = NULL;
    txn_info_t txn_info;

    *is_found = GS_FALSE;
    *is_wait = GS_FALSE;
    page = BTREE_CURR_PAGE(session);

    if (GS_INVALID_ID8 == dir->itl_id) {
        *is_found = (!key->is_deleted);
        return GS_SUCCESS;
    }

    itl = BTREE_GET_ITL(page, dir->itl_id);
    if (itl->xid.value == session->rm->xid.value) {
        *is_found = (!key->is_deleted);
        return GS_SUCCESS;
    }

    tx_get_itl_info(session, GS_FALSE, itl, &txn_info);
    if (txn_info.status == (uint8)XACT_END) {
        *is_found = (!key->is_deleted);
        return GS_SUCCESS;
    }

    *is_wait = GS_TRUE;
    ROWID_COPY(session->wrid, key->rowid);
    session->wxid = itl->xid;
    return GS_SUCCESS;
}

static status_t btree_fetch_depended_asc(knl_session_t *session, knl_cursor_t *cursor)
{
    btree_page_t *page;
    btree_key_t *key = NULL;
    btree_dir_t *dir = NULL;
    knl_scan_key_t *filter_key;
    btree_t *btree;
    int32 result;
    bool32 is_wait;
    errno_t ret;

    btree = CURSOR_BTREE(cursor);
    filter_key = &cursor->scan_range.r_key;
    page = (cursor->key_loc.page_cache == LOCAL_PAGE_CACHE) ?
               (btree_page_t *)cursor->page_buf :
               BTREE_CURR_PAGE(session);
    is_wait = GS_FALSE;

    while (cursor->key_loc.slot < page->keys) {
        dir = BTREE_GET_DIR(page, cursor->key_loc.slot);
        key = BTREE_GET_KEY(page, dir);

        if (cursor->key_loc.slot_end == INVALID_SLOT || cursor->key_loc.slot_end < cursor->key_loc.slot) {
            result = btree_compare_key(btree->index, filter_key, key, GS_FALSE, NULL);
            if (result < 0) {
                if (cursor->key_loc.page_cache == NO_PAGE_CACHE) {
                    buf_leave_page(session, GS_FALSE);
                }
                cursor->eof = GS_TRUE;
                return GS_SUCCESS;
            }
        }

        if (btree_check_exist(session, dir, key, &cursor->is_found, &is_wait) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (is_wait) {
            if (cursor->key_loc.page_cache == NO_PAGE_CACHE) {
                buf_leave_page(session, GS_FALSE);
            }

            btree->stat.row_lock_waits++;
            if (tx_wait(session, session->lock_wait_timeout, ENQ_TX_KEY) != GS_SUCCESS) {
                tx_record_rowid(session->wrid);
                return GS_ERROR;
            }
            cursor->key_loc.slot--;  // relocate this slot
            cursor->key_loc.is_last_key = GS_FALSE;
            return GS_SUCCESS;
        }

        if (cursor->is_found) {
            ret = memcpy_sp(cursor->scan_range.l_buf, GS_KEY_BUF_SIZE, key, (size_t)key->size);
            knl_securec_check(ret);
            key = (btree_key_t *)cursor->scan_range.l_buf;
            cursor->key_loc.is_last_key = (cursor->key_loc.slot == page->keys - 1);
            btree_decode_key(btree->index, key, &cursor->scan_range.l_key);
            if (cursor->key_loc.page_cache == NO_PAGE_CACHE) {
                buf_leave_page(session, GS_FALSE);
            }

            BTREE_COPY_ROWID(key, cursor);
            if (TABLE_ACCESSOR(cursor)->do_fetch_by_rowid(session, cursor) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (cursor->is_found) {
                return GS_SUCCESS;
            }
        }
        cursor->key_loc.slot++;
    }

    cursor->key_loc.is_last_key = GS_TRUE;
    if (cursor->key_loc.page_cache == NO_PAGE_CACHE) {
        buf_leave_page(session, GS_FALSE);
    }
    return GS_SUCCESS;
}

status_t btree_fetch_depended(knl_session_t *session, knl_cursor_t *cursor)
{
    if (cursor->eof) {
        return GS_SUCCESS;
    }

    btree_t *btree = CURSOR_BTREE(cursor);
    if (btree->segment == NULL) {
        cursor->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    knl_scan_key_t *scan_key = &cursor->scan_range.l_key;
    cursor->index_dsc = GS_FALSE;

    if (!cursor->key_loc.is_initialized) {
        btree_init_fetch(session, cursor);
    }

    for (;;) {
        if (btree_find_key(session, cursor, scan_key) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (cursor->eof) {
            return GS_SUCCESS;
        }

        if (btree_fetch_depended_asc(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (cursor->is_found || cursor->eof) {
            return GS_SUCCESS;
        }
    }
}


static void btree_get_sub_r_key(knl_session_t *session, index_t *index, btree_key_t *key,
    knl_scan_range_t *range, bool8 is_dsc)
{
    page_id_t page_id;
    btree_page_t *page = NULL;
    btree_dir_t *dir = NULL;
    btree_key_t *r_key = NULL;
    errno_t err;

    r_key = (btree_key_t *)range->r_buf;

    if (index->desc.primary || index->desc.unique) {
        for (;;) {
            page_id = key->child;
            buf_enter_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
            page = (btree_page_t *)session->curr_page;
            dir = BTREE_GET_DIR(page, 0);
            key = BTREE_GET_KEY(page, dir);

            if (page->level != 0) {
                buf_leave_page(session, GS_FALSE);
                continue;
            }

            err = memcpy_sp(r_key, GS_KEY_BUF_SIZE, key, (size_t)key->size);
            knl_securec_check(err);
            buf_leave_page(session, GS_FALSE);
            break;
        }
    } else {
        err = memcpy_sp(r_key, GS_KEY_BUF_SIZE, key, (size_t)key->size);
        knl_securec_check(err);
    }

    if (!is_dsc) {
        if (r_key->rowid.slot != 0) {
            r_key->rowid.slot--;
        } else {
            knl_panic_log(r_key->rowid.page > 0, "the rowid's page is abnormal, panic info: index %s page no %u",
                          index->desc.name, r_key->rowid.page);
            r_key->rowid.slot = INVALID_SLOT;
            r_key->rowid.page--;
        }
    }

    btree_decode_key(index, r_key, &range->r_key);
}

void btree_get_parl_schedule(knl_session_t *session, index_t *index, knl_idx_paral_info_t paral_info,
    idx_range_info_t org_info, uint32 root_level, knl_index_paral_range_t *sub_range)
{
    uint32 i = 0;
    uint32 r_border;
    knl_scan_range_t *org_range = paral_info.org_range;
    knl_scan_range_t *range = sub_range->index_range[0];
    page_id_t page_id;
    errno_t ret;

    uint32 step = org_info.keys / sub_range->workers;

    // set first left range
    buf_enter_page(session, org_info.l_page[org_info.level], LATCH_MODE_S, ENTER_PAGE_NORMAL);
    btree_page_t *page = BTREE_CURR_PAGE(session);
    uint32 slot = org_info.l_slot[org_info.level];
    btree_dir_t *dir = BTREE_GET_DIR(page, slot);
    btree_key_t *key = BTREE_GET_KEY(page, dir);

    if (key->is_infinite) {
        ret = memcpy_sp(range->l_buf, GS_KEY_BUF_SIZE, org_range->l_buf, GS_KEY_BUF_SIZE);
        knl_securec_check(ret);
        range->l_key = org_range->l_key;
        range->l_key.buf = range->l_buf;
    } else {
        ret = memcpy_sp(range->l_buf, GS_KEY_BUF_SIZE, key, (size_t)key->size);
        knl_securec_check(ret);
        btree_decode_key(index, key, &range->l_key);
    }

    do {
        if (org_info.level == root_level) {
            r_border = slot + step;
        } else {
            page_id = AS_PAGID(page->head.id);
            buf_leave_page(session, GS_FALSE);

            idx_enter_next_range(session, page_id, slot, step, &r_border);
            page = BTREE_CURR_PAGE(session);
        }

        slot = r_border;
        dir = BTREE_GET_DIR(page, r_border);
        key = BTREE_GET_KEY(page, dir);
        btree_get_sub_r_key(session, index, key, range, paral_info.is_dsc);

        i++; // set next range
        range = sub_range->index_range[i];

        ret = memcpy_sp(range->l_buf, GS_KEY_BUF_SIZE, key, (size_t)key->size);
        knl_securec_check(ret);
        btree_decode_key(index, key, &range->l_key);
    } while (i < sub_range->workers - 1);

    // set last right range
    buf_leave_page(session, GS_FALSE);
    ret = memcpy_sp(range->r_buf, GS_KEY_BUF_SIZE, org_range->r_buf, GS_KEY_BUF_SIZE);
    knl_securec_check(ret);
    range->r_key = org_range->r_key;
    range->r_key.buf = range->r_buf;
}
