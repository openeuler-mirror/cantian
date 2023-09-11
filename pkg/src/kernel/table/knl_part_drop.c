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
 * knl_part_drop.c
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_part_drop.c
 *
 * -------------------------------------------------------------------------
 */
 
#include "knl_part_output.h"
#include "cm_hash.h"
#include "cm_log.h"
#include "index_common.h"
#include "knl_table.h"
#include "ostat_load.h"
#include "dc_part.h"
#include "knl_lob.h"
#include "knl_heap.h"
#include "knl_sys_part_defs.h"
#include "knl_part_inner.h"

status_t db_delete_from_syspartobject(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id,
                                      uint32 index_id)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_PARTOBJECT_ID, IX_SYS_PARTOBJECT001_ID);

    if (index_id == GS_INVALID_ID32) {
        // drop part table
        knl_init_index_scan(cursor, GS_FALSE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                         &uid, sizeof(uint32), IX_COL_SYS_PARTOBJECT001_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                         &table_id, sizeof(uint32), IX_COL_SYS_PARTOBJECT001_TABLE_ID);
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_PARTOBJECT001_INDEX_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                         &uid, sizeof(uint32), IX_COL_SYS_PARTOBJECT001_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                         &table_id, sizeof(uint32), IX_COL_SYS_PARTOBJECT001_TABLE_ID);
        knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_PARTOBJECT001_INDEX_ID);
    } else {
        // drop part index
        knl_init_index_scan(cursor, GS_TRUE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                         &uid, sizeof(uint32), IX_COL_SYS_PARTOBJECT001_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                         &table_id, sizeof(uint32), IX_COL_SYS_PARTOBJECT001_TABLE_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                         &index_id, sizeof(uint32), IX_COL_SYS_PARTOBJECT001_INDEX_ID);
    }

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_delete_from_sys_partcolumn(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_PARTCOLUMN_ID, IX_SYS_PARTCOLUMN001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &uid, sizeof(uint32), IX_COL_SYS_PARTCOLUMN001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &table_id, sizeof(uint32), IX_COL_SYS_PARTCOLUMN001_TABLE_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_delete_from_systablepart(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id,
                                     uint32 part_id)
{
    knl_table_part_desc_t desc = { 0 };
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_TABLEPART_ID, IX_SYS_TABLEPART001_ID);

    if (part_id == GS_INVALID_ID32) {
        knl_init_index_scan(cursor, GS_FALSE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                         &uid, sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                         &table_id, sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_TABLEPART001_PART_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                         &uid, sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                         &table_id, sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
        knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_TABLEPART001_PART_ID);
    } else {
        knl_init_index_scan(cursor, GS_TRUE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                         &uid, sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                         &table_id, sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                         &part_id, sizeof(uint32), IX_COL_SYS_TABLEPART001_PART_ID);
    }

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        dc_convert_table_part_desc(cursor, &desc);
        if (desc.is_nologging) {
            if (db_update_nologobj_cnt(session, GS_FALSE) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
        
        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_delete_from_shadow_sysindexpart(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id,
                                            uint32 index_id)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SHADOW_INDEXPART_ID, IX_SYS_SHW_INDEXPART001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &uid, sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &table_id, sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &index_id, sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PART_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PARENTPART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &uid, sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &table_id, sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &index_id, sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PARENTPART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_delete_from_sysindexpart(knl_session_t *session, knl_cursor_t *cursor,
                                     uint32 uid, uint32 table_id, uint32 index_id, uint32 part_id)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_INDEXPART_ID, IX_SYS_INDEXPART001_ID);
    if (index_id == GS_INVALID_ID32) {
        // drop part table
        knl_init_index_scan(cursor, GS_FALSE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid,
            sizeof(uint32), IX_COL_SYS_INDEXPART001_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table_id,
            sizeof(uint32), IX_COL_SYS_INDEXPART001_TABLE_ID);
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_INDEXPART001_INDEX_ID);
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_INDEXPART001_PART_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &uid,
            sizeof(uint32), IX_COL_SYS_INDEXPART001_PART_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &table_id,
            sizeof(uint32), IX_COL_SYS_INDEXPART001_TABLE_ID);
        knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEXPART001_INDEX_ID);
        knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEXPART001_PART_ID);
    } else if (part_id == GS_INVALID_ID32) {
        // drop part index
        knl_init_index_scan(cursor, GS_FALSE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid,
            sizeof(uint32), IX_COL_SYS_INDEXPART001_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table_id,
            sizeof(uint32), IX_COL_SYS_INDEXPART001_TABLE_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &index_id,
            sizeof(uint32), IX_COL_SYS_INDEXPART001_INDEX_ID);
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_INDEXPART001_PART_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &uid,
            sizeof(uint32), IX_COL_SYS_INDEXPART001_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &table_id,
            sizeof(uint32), IX_COL_SYS_INDEXPART001_TABLE_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &index_id,
            sizeof(uint32), IX_COL_SYS_INDEXPART001_INDEX_ID);
        knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEXPART001_PART_ID);
    } else {
        // drop index part during drop table part
        knl_init_index_scan(cursor, GS_TRUE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid,
            sizeof(uint32), IX_COL_SYS_INDEXPART001_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table_id,
            sizeof(uint32), IX_COL_SYS_INDEXPART001_TABLE_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &index_id,
            sizeof(uint32), IX_COL_SYS_INDEXPART001_INDEX_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &part_id,
            sizeof(uint32), IX_COL_SYS_INDEXPART001_PART_ID);
    }

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static void part_convert_shwidx_part_desc(const knl_cursor_t *cursor, knl_index_part_desc_t *desc)
{
    text_t text;
    
    desc->uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_USER_ID);
    desc->table_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_TABLE_ID);
    desc->index_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_INDEX_ID);
    desc->part_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_PART_ID);

    text.str = CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_NAME);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_SHADOW_INDEXPART_COL_NAME);
    (void)cm_text2str(&text, desc->name, GS_NAME_BUFFER_SIZE);

    desc->space_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_SPACE_ID);
    desc->org_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_ORG_SCN);
    desc->entry = *(page_id_t *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_ENTRY);
    desc->initrans = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_INITRANS);
    desc->seg_scn = desc->org_scn;
}

status_t db_drop_shadow_indexpart(knl_session_t *session, uint32 uid, uint32 table_id, bool32 clean_segment)
{
    errno_t ret;
    index_part_t part;
    knl_index_part_desc_t *desc = NULL;
    
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SHADOW_INDEXPART_ID, IX_SYS_SHW_INDEXPART001_ID);

    // drop part index
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &uid, sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &table_id, sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PART_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PARENTPART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &uid, sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &table_id, sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PARENTPART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        ret = memset_sp(&part, sizeof(index_part_t), 0, sizeof(index_part_t));
        knl_securec_check(ret);
        desc = &part.desc;
        part_convert_shwidx_part_desc(cursor, desc);
        if (clean_segment && spc_valid_space_object(session, desc->space_id) && !IS_INVALID_PAGID(desc->entry)) {
            btree_drop_part_segment(session, &part);
        }

        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_clean_all_shadow_indexparts(knl_session_t *session, knl_cursor_t *cursor)
{
    uint32 uid;
    uint32 tid;
    uint32 sid;
    dc_user_t *user = NULL;
    dc_entry_t *entry = NULL;
    space_t *space = NULL;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SHADOW_INDEXPART_ID, GS_INVALID_ID32);
    cursor->isolevel = (uint8)ISOLATION_CURR_COMMITTED;

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);
        uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_USER_ID);
        tid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_TABLE_ID);
        sid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_SPACE_ID);

        if (dc_open_user_by_id(session, uid, &user) != GS_SUCCESS) {
            return GS_ERROR;
        }
        entry = DC_GET_ENTRY(user, tid);
        if (!dc_locked_by_xa(session, entry)) {
            space = SPACE_GET(session, sid);
            if (SPACE_IS_NOLOGGING(space)) {
                GS_LOG_RUN_WAR("dc clean shadow indexes parts found nologging table ID(%u)", tid);
            }
            if (db_drop_shadow_indexpart(session, uid, tid, !SPACE_IS_NOLOGGING(space)) != GS_SUCCESS) {
                return GS_ERROR;
            }

            knl_commit(session);
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_delete_from_syslobpart(knl_session_t *session, knl_cursor_t *cursor,
    uint32 uid, uint32 table_id, uint32 column_id, uint32 part_id)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_LOBPART_ID, IX_SYS_LOBPART001_ID);

    if (column_id == GS_INVALID_ID32) {
        // drop part table
        knl_init_index_scan(cursor, GS_FALSE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid,
            sizeof(uint32), IX_COL_SYS_LOBPART001_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table_id,
            sizeof(uint32), IX_COL_SYS_LOBPART001_TABLE_ID);
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_LOBPART001_COLUMN_ID);
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_LOBPART001_PART_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &uid,
            sizeof(uint32), IX_COL_SYS_LOBPART001_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &table_id,
            sizeof(uint32), IX_COL_SYS_LOBPART001_TABLE_ID);
        knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_LOBPART001_COLUMN_ID);
        knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_LOBPART001_PART_ID);
    } else if (part_id == GS_INVALID_ID32) {
        // drop part column
        knl_init_index_scan(cursor, GS_FALSE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid,
            sizeof(uint32), IX_COL_SYS_LOBPART001_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table_id,
            sizeof(uint32), IX_COL_SYS_LOBPART001_TABLE_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &column_id,
            sizeof(uint32), IX_COL_SYS_LOBPART001_COLUMN_ID);
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_LOBPART001_PART_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &uid,
            sizeof(uint32), IX_COL_SYS_LOBPART001_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &table_id,
            sizeof(uint32), IX_COL_SYS_LOBPART001_TABLE_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &column_id,
            sizeof(uint32), IX_COL_SYS_LOBPART001_COLUMN_ID);
        knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_LOBPART001_PART_ID);
    } else {
        // drop lob part during drop table part
        knl_init_index_scan(cursor, GS_TRUE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid,
            sizeof(uint32), IX_COL_SYS_LOBPART001_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table_id,
            sizeof(uint32), IX_COL_SYS_LOBPART001_TABLE_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &column_id,
            sizeof(uint32), IX_COL_SYS_LOBPART001_COLUMN_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &part_id,
            sizeof(uint32), IX_COL_SYS_LOBPART001_PART_ID);
    }

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
        GS_LOG_DEBUG_INF("delete from lobpart: delete one row from LOBPART$, uid: %d,tid: %d, colid: %d, part_id: %d",
                         uid, table_id, column_id, part_id);
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_delete_from_sys_partstore(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_PARTSTORE_ID, IX_SYS_PARTSTORE001_ID);

    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_PARTSTORE001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table_id, sizeof(uint32),
                     IX_COL_SYS_PARTSTORE001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_PARTSTORE001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_PARTSTORE001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &table_id, sizeof(uint32),
                     IX_COL_SYS_PARTSTORE001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_PARTSTORE001_INDEX_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_delete_from_parts_sysstorage(knl_session_t *session, knl_cursor_t *cursor, part_table_t *part_table)
{
    table_part_t *table_part = NULL;
    
    for (uint32 i = 0; i < part_table->desc.partcnt; i++) {
        table_part = PART_GET_ENTITY(part_table, i);
        if (!IS_READY_PART(table_part) || !table_part->desc.storaged) {
            continue;
        }

        if (db_delete_from_sysstorage(session, cursor, table_part->desc.org_scn) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    
    return GS_SUCCESS;
}

static status_t db_delete_from_sys_subpartcolumn(knl_session_t *session, knl_cursor_t *cursor, uint32 uid,
    uint32 table_id)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SUB_PARTCOLUMN_ID, IX_SYS_SUBPARTCOLUMN001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
        IX_COL_SYS_SUBPARTCOLUMN001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table_id, sizeof(uint32),
        IX_COL_SYS_SUBPARTCOLUMN001_TABLE_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t db_delete_all_sub_tabparts(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id)
{
    knl_table_part_desc_t desc = { 0 };
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SUB_TABLE_PARTS_ID, IX_SYS_TABLESUBPART001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
        IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
        IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &table_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    while (!cursor->eof) {
        dc_convert_table_part_desc(cursor, &desc);
        if (desc.is_nologging) {
            if (db_update_nologobj_cnt(session, GS_FALSE) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t db_delete_all_sub_idxparts(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SUB_INDEX_PARTS_ID, IX_SYS_INDEXSUBPART001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &uid, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &table_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_INDEXSUBPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_INDEXSUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_INDEXSUBPART001_SUB_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &uid, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &table_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEXSUBPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEXSUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEXSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    while (!cursor->eof) {
        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t db_delete_all_sub_lobparts(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SUB_LOB_PARTS_ID, IX_SYS_LOBSUBPART001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &uid, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &table_id, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_LOBSUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_LOBSUBPART001_COLUMN_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_LOBSUBPART001_SUB_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &uid, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &table_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_LOBSUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_LOBSUBPART001_COLUMN_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_LOBSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    while (!cursor->eof) {
        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t db_delete_all_subparts(knl_session_t *session, knl_cursor_t *cursor, part_table_t *part_table)
{
    knl_part_desc_t *desc = &part_table->desc;

    GS_LOG_DEBUG_INF("drop all sub table parts: begin to delete from system sub table parts");
    if (db_delete_all_sub_tabparts(session, cursor, desc->uid, desc->table_id) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    GS_LOG_DEBUG_INF("drop all sub index parts: begin to delete from system sub index parts");
    if (db_delete_all_sub_idxparts(session, cursor, desc->uid, desc->table_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    GS_LOG_DEBUG_INF("drop all sub lob parts: begin to delete from system sub lob parts");
    if (db_delete_all_sub_lobparts(session, cursor, desc->uid, desc->table_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_delete_parts_from_syscompress(knl_session_t *session, knl_cursor_t *cursor,
    part_table_t *part_table)
{
    space_t *space = NULL;

    for (uint32 i = 0; i < TOTAL_PARTCNT(&part_table->desc); i++) {
        table_part_t *table_part_entity = PART_GET_ENTITY(part_table, i);
        if (!IS_READY_PART(table_part_entity)) {
            continue;
        }
        space = SPACE_GET(session, table_part_entity->desc.space_id);
        if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
            continue;
        }
        if (!table_part_entity->desc.compress) {
            continue;
        }
        if (db_delete_from_syscompress(session, cursor, table_part_entity->desc.org_scn) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}
/*
 * drop partitioned table
 * @param kernel session, kernel cursor, partition table
 * @note support first level partition, support range and list partition table
 */
status_t db_drop_part_table(knl_session_t *session, knl_cursor_t *cursor, part_table_t *part_table)
{
    knl_part_desc_t desc = part_table->desc;

    GS_LOG_DEBUG_INF("drop  part  table: begin to  delete from partobject$");

    if (db_delete_from_syspartobject(session, cursor, desc.uid, desc.table_id, desc.index_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    GS_LOG_DEBUG_INF("drop part table: begin to  delete from partcolumn$");

    if (db_delete_from_sys_partcolumn(session, cursor, desc.uid, desc.table_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    GS_LOG_DEBUG_INF("drop part table: begin to  delete from tablepart$");

    if (db_delete_from_systablepart(session, cursor, desc.uid, desc.table_id, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    GS_LOG_DEBUG_INF(" drop part table: begin to  delete from indexpart$");

    if (db_delete_from_sysindexpart(session, cursor, desc.uid, desc.table_id, GS_INVALID_ID32,
        GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    GS_LOG_DEBUG_INF(" drop part table: begin to  delete from lobpart$");

    if (db_delete_from_syslobpart(session, cursor, desc.uid, desc.table_id, GS_INVALID_ID32,
        GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    GS_LOG_DEBUG_INF("drop part table: begin to  delete from partstore$");

    if (db_delete_from_sys_partstore(session, cursor, desc.uid, desc.table_id) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    GS_LOG_DEBUG_INF("drop part table: begin to  delete from storage$");

    if (db_delete_from_parts_sysstorage(session, cursor, part_table) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (IS_COMPART_TABLE(part_table)) {
        if (db_delete_from_sys_subpartcolumn(session, cursor, desc.uid, desc.table_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (db_delete_all_subparts(session, cursor, part_table) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (db_delete_parts_from_syscompress(session, cursor, part_table) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t part_drop_heap_segment(knl_session_t *session, knl_dictionary_t *dc, uint32 part_no)
{
    table_t *table = DC_TABLE(dc);
    table_part_t *table_part = TABLE_GET_PART(table, part_no);

    if (!IS_PARENT_TABPART(&table_part->desc)) {
        if (heap_part_segment_prepare(session, table_part, GS_FALSE, HEAP_DROP_PART_SEGMENT) != GS_SUCCESS) {
            return GS_ERROR;
        }

        return GS_SUCCESS;
    }

    table_part_t *table_subpart = NULL;
    for (uint32 i = 0; i < table_part->desc.subpart_cnt; i++) {
        table_subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[i]);
        if (table_subpart == NULL) {
            continue;
        }
        
        if (heap_part_segment_prepare(session, table_subpart, GS_FALSE, HEAP_DROP_PART_SEGMENT) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t part_drop_btree_segment(knl_session_t *session, knl_dictionary_t *dc, uint32 part_no)
{
    index_t *index = NULL;
    index_part_t *index_part = NULL;
    index_part_t *index_subpart = NULL;
    table_t *table = DC_TABLE(dc);

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (!IS_PART_INDEX(index)) {
            continue;
        }

        index_part = INDEX_GET_PART(index, part_no);
        if (index_part == NULL) {
            continue;
        }
        
        if (!IS_PARENT_IDXPART(&index_part->desc)) {
            if (btree_part_segment_prepare(session, index_part, GS_FALSE, BTREE_DROP_PART_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }

            continue;
        }

        for (uint32 j = 0; j < index_part->desc.subpart_cnt; j++) {
            index_subpart = PART_GET_SUBENTITY(index->part_index, index_part->subparts[j]);
            if (index_subpart == NULL) {
                continue;
            }

            if (btree_part_segment_prepare(session, index_subpart, GS_FALSE, BTREE_DROP_PART_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t part_drop_lob_segment(knl_session_t *session, knl_dictionary_t *dc, uint32 part_no)
{
    lob_t *lob = NULL;
    lob_part_t *lob_part = NULL;
    lob_part_t *lob_subpart = NULL;
    knl_column_t  *knl_column = NULL;
    dc_entity_t *entity = DC_ENTITY(dc);

    if (!entity->contain_lob) {
        return GS_SUCCESS;
    }

    for (uint32 i = 0; i < entity->column_count; i++) {
        knl_column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(knl_column)) {
            continue;
        }

        lob = knl_column->lob;
        lob_part = LOB_GET_PART(lob, part_no);
        if (lob_part == NULL) {
            continue;
        }
        
        if (!IS_PARENT_LOBPART(&lob_part->desc)) {
            if (lob_part_segment_prepare(session, lob_part, GS_FALSE, LOB_DROP_PART_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }

            continue;
        }

        for (uint32 j = 0; j < lob_part->desc.subpart_cnt; j++) {
            lob_subpart = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[j]);
            if (lob_subpart == NULL) {
                continue;
            }

            if (lob_part_segment_prepare(session, lob_subpart, GS_FALSE, LOB_DROP_PART_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

status_t db_drop_part_btree_segments(knl_session_t *session, index_t *index, knl_parts_locate_t parts_loc)
{
    index_part_t *index_part = NULL;
    index_part_t *index_subpart = NULL;
    table_part_t *table_part = NULL;
    table_t *table = &index->entity->table;
    knl_part_locate_t part_loc;
    bool32 remain = GS_FALSE;

    for (uint32 i = 0; i < TOTAL_PARTCNT(&index->part_index->desc); i++) {
        index_part = INDEX_GET_PART(index, i);
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part) || index_part == NULL) {
            continue;
        }

        part_loc.part_no = i;
        part_loc.subpart_no = GS_INVALID_ID32;
        remain = is_idx_part_existed(&part_loc, parts_loc, GS_FALSE);

        if (!IS_PARENT_IDXPART(&index_part->desc)) {
            if (!remain) {
                continue;
            }

            if (btree_part_segment_prepare(session, index_part, GS_FALSE, BTREE_DROP_PART_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }

            continue;
        }
        
        for (uint32 j = 0; j < index_part->desc.subpart_cnt; j++) {
            index_subpart = PART_GET_SUBENTITY(index->part_index, index_part->subparts[j]);
            if (index_subpart == NULL) {
                continue;
            }

            part_loc.part_no = i;
            part_loc.subpart_no = j;
            remain = is_idx_part_existed(&part_loc, parts_loc, GS_TRUE);
            if (!remain) {
                continue;
            }

            if (btree_part_segment_prepare(session, index_subpart, GS_FALSE, BTREE_DROP_PART_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

status_t db_drop_part_segments(knl_session_t *session, knl_dictionary_t *dc, uint32 part_no)
{
    if (part_drop_heap_segment(session, dc, part_no) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (part_drop_btree_segment(session, dc, part_no) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    if (part_drop_lob_segment(session, dc, part_no) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    return GS_SUCCESS;
}

static status_t db_coalesce_part_precheck(knl_session_t *session, table_t *table)
{
    if (!table->desc.parted) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "alter table coalesce partition", table->desc.name);
        return GS_ERROR;
    }

    part_table_t *part_table = table->part_table;
    if (part_table->desc.parttype != PART_TYPE_HASH) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "COALESCE PARTITION on other partitioned objects except hash");
        return GS_ERROR;
    }

    if (table->part_table->desc.partcnt < COALESCE_MIN_PART_COUNT) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "coalesce a table with only one partition");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/*
 * set the partition name according to the pno specified, used by coalesce partition
 * @param part_table, pno, part_def
 */
static void part_table_set_part_name_by_pno(part_table_t *part_table, uint32 pno, knl_alt_part_t *part_def)
{
    table_part_t *entity = NULL;
    entity = PART_GET_ENTITY(part_table, pno);

    knl_panic(entity != NULL);

    cm_str2text(entity->desc.name, &part_def->name);
}

status_t db_altable_coalesce_partition(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    status_t status;
    table_t *table = DC_TABLE(dc);

    if (db_coalesce_part_precheck(session, table) != GS_SUCCESS) {
        return GS_ERROR;
    }

    uint32 pcnt = table->part_table->desc.partcnt;
    uint32 bucketcnt = dc_get_hash_bucket_count(pcnt);

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor_select = knl_push_cursor(session);
    cursor_select->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor_select->action = CURSOR_ACTION_DELETE;
    cursor_select->part_loc.part_no = pcnt - 1;

    if (knl_open_cursor(session, cursor_select, dc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_cursor_t *cursor_insert = knl_push_cursor(session);
    cursor_insert->stmt = NULL;
    cursor_insert->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor_insert->action = CURSOR_ACTION_INSERT;
    /* the orgorithms to get the bucket by partcnt, the count of buckets is an integer power of 2 */
    cursor_insert->part_loc.part_no = pcnt - 1 - bucketcnt / HASH_PART_BUCKET_BASE;

    table_part_t *select_part = TABLE_GET_PART(table, cursor_select->part_loc.part_no);
    table_part_t *insert_part = TABLE_GET_PART(table, cursor_insert->part_loc.part_no);

    if (select_part->desc.is_csf != insert_part->desc.is_csf) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION,
            ", coalesce partition between different partition row types are forbidden");
        return GS_ERROR;
    }

    if (knl_open_cursor(session, cursor_insert, dc) != GS_SUCCESS) {
        knl_close_cursor(session, cursor_select);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    cursor_insert->row = (row_head_t *)cm_push(session->stack, GS_MAX_ROW_SIZE);

    if (IS_PARENT_TABPART(&select_part->desc)) {
        status = part_redis_move_part(session, cursor_select, dc, cursor_insert, GS_TRUE);
    } else {
        status = part_redis_move_part(session, cursor_select, dc, cursor_insert, GS_FALSE);
    }

    if (status != GS_SUCCESS) {
        knl_close_cursor(session, cursor_select);
        knl_close_cursor(session, cursor_insert);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_close_cursor(session, cursor_select);
    knl_close_cursor(session, cursor_insert);
    CM_RESTORE_STACK(session->stack);

    /* drop the last partition */
    part_table_t *part_table = table->part_table;
    part_table_set_part_name_by_pno(part_table, pcnt - 1, &def->part_def);
    if (db_altable_drop_part(session, dc, def, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_delete_subtabparts_of_compart(knl_session_t *session, knl_cursor_t *cursor, uint32 uid,
    uint32 table_id, uint32 compart_id)
{
    knl_table_part_desc_t desc = { 0 };
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SUB_TABLE_PARTS_ID, IX_SYS_TABLESUBPART001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
        IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &compart_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
        IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &table_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &compart_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    while (!cursor->eof) {
        dc_convert_table_part_desc(cursor, &desc);
        if (desc.is_nologging) {
            if (db_update_nologobj_cnt(session, GS_FALSE) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }

        session->stat->table_subpart_drops++;

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_delete_one_sub_tabpart(knl_session_t *session, knl_cursor_t *cursor, knl_table_part_desc_t *sub_desc)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SUB_TABLE_PARTS_ID, IX_SYS_TABLESUBPART001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &sub_desc->uid,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &sub_desc->table_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &sub_desc->parent_partid,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &sub_desc->part_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s table_part %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, sub_desc->name, ((index_t *)cursor->index)->desc.name);
    if (sub_desc->is_nologging) {
        if (db_update_nologobj_cnt(session, GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_delete_subidxparts_with_index(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id,
    uint32 index_id)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SUB_INDEX_PARTS_ID, IX_SYS_INDEXSUBPART001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &uid, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &table_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &index_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_INDEXSUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_INDEXSUBPART001_SUB_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &uid, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &table_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &index_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEXSUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEXSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    while (!cursor->eof) {
        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_delete_subidxparts_with_compart(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id,
    uint32 index_id, uint32 compart_id)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SUB_INDEX_PARTS_ID, IX_SYS_INDEXSUBPART001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &uid, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &table_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &index_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &compart_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_INDEXSUBPART001_SUB_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &uid, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &table_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &index_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &compart_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEXSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    while (!cursor->eof) {
        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_delete_one_sub_idxpart(knl_session_t *session, knl_cursor_t *cursor, knl_table_part_desc_t *desc,
    uint32 index_id)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SUB_INDEX_PARTS_ID, IX_SYS_INDEXSUBPART001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &desc->uid, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &desc->table_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &index_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &desc->parent_partid, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &desc->part_id, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s table_part %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, desc->name, ((index_t *)cursor->index)->desc.name);
    if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_delete_sublobparts_with_lob(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id,
    uint32 column_id)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SUB_LOB_PARTS_ID, IX_SYS_LOBSUBPART001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &uid, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &table_id, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &column_id, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_COLUMN_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_LOBSUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_LOBSUBPART001_SUB_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &uid, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &table_id, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &column_id, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_COLUMN_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_LOBSUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_LOBSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    while (!cursor->eof) {
        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_delete_sublobparts_with_compart(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id,
    uint32 column_id, uint32 compart_id)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SUB_LOB_PARTS_ID, IX_SYS_LOBSUBPART001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &uid, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &table_id, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &column_id, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_COLUMN_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &compart_id, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_LOBSUBPART001_SUB_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &uid, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &table_id, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &column_id, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_COLUMN_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
                     &compart_id, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_PARENT_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_LOBSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    while (!cursor->eof) {
        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_delete_one_sub_lobpart(knl_session_t *session, knl_cursor_t *cursor, knl_table_part_desc_t *desc,
    uint32 column_id)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SUB_LOB_PARTS_ID, IX_SYS_LOBSUBPART001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &desc->uid, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &desc->table_id, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &column_id, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_COLUMN_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &desc->parent_partid, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &desc->part_id, sizeof(uint32), IX_COL_SYS_LOBSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s table_part %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, desc->name, ((index_t *)cursor->index)->desc.name);
    if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t subpart_drop_precheck(knl_session_t *session, knl_handle_t knl_table, knl_altable_def_t *def,
    bool32 is_part_add_or_coalesce)
{
    table_t *table = (table_t *)knl_table;
    
    if (!table->desc.parted) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "drop partition", table->desc.name);
        return GS_ERROR;
    }

    if (!is_part_add_or_coalesce && !def->part_def.is_garbage_clean) {
        if (table->part_table == NULL) {
            GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&def->part_def.name));
            return GS_ERROR;
        }
        if (table->part_table->desc.subparttype == PART_TYPE_HASH) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "alter table drop subpartition", "hash partition");
            return GS_ERROR;
        }
    }
    
    if (db_table_is_referenced(session, table, GS_TRUE)) {
        GS_THROW_ERROR(ERR_TABLE_IS_REFERENCED);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_drop_subpart_segments(knl_session_t *session, knl_dictionary_t *dc, table_part_t *subpart)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;

    knl_panic_log(IS_SUB_TABPART(&subpart->desc), "current subpart is not sub_tabpart, panic info: "
                  "table %s table_subpart %s", table->desc.name, subpart->desc.name);
    table_part_t *compart = PART_GET_ENTITY(table->part_table, subpart->parent_partno);
    knl_panic_log(compart != NULL, "compart is NULL, panic info: table %s table_subpart %s", table->desc.name,
                  subpart->desc.name);
    if (heap_part_segment_prepare(session, subpart, GS_INVALID_ID32, HEAP_DROP_PART_SEGMENT) != GS_SUCCESS) {
        return GS_ERROR;
    }

    lob_t *lob = NULL;
    knl_column_t *column = NULL;
    lob_part_t *lob_compart = NULL;
    lob_part_t *lob_subpart = NULL;
    if (entity->contain_lob) {
        for (uint32 i = 0; i < entity->column_count; i++) {
            column = dc_get_column(entity, i);
            if (!COLUMN_IS_LOB(column)) {
                continue;
            }

            lob = column->lob;
            lob_compart = LOB_GET_PART(lob, compart->part_no);
            lob_subpart = PART_GET_SUBENTITY(lob->part_lob, lob_compart->subparts[subpart->part_no]);
            if (lob_part_segment_prepare(session, (lob_part_t *)lob_subpart, GS_INVALID_ID32,
                LOB_DROP_PART_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    index_t *index = NULL;
    index_part_t *index_compart = NULL;
    index_part_t *index_subpart = NULL;
    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (!IS_PART_INDEX(index)) {
            continue;
        }

        index_compart = INDEX_GET_PART(index, compart->part_no);
        index_subpart = PART_GET_SUBENTITY(index->part_index, index_compart->subparts[subpart->part_no]);
        if (btree_part_segment_prepare(session, (index_part_t *)index_subpart, GS_INVALID_ID32,
            BTREE_DROP_PART_SEGMENT) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t subpart_drop_lobparts(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *cursor,
    knl_table_part_desc_t *desc)
{
    knl_column_t *column = NULL;
    dc_entity_t *entity = DC_ENTITY(dc);

    for (uint32 i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        if (db_delete_one_sub_lobpart(session, cursor, desc, column->id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        GS_LOG_DEBUG_INF("drop lob subpart, uid: %d, tid: %d, column id: %d, ppart_id: %d, subpart_id %d",
            desc->uid, desc->table_id, column->id, desc->parent_partid, desc->part_id);
    }

    return GS_SUCCESS;
}

static status_t subpart_drop_idxparts(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *cursor,
    table_part_t *subpart)
{
    bool32 is_changed = GS_FALSE;
    table_t *table = DC_TABLE(dc);
    bool32 need_invalid_index = GS_FALSE;
    knl_table_part_desc_t *desc = &subpart->desc;

    if (db_need_invalidate_index(session, dc, table, subpart, &need_invalid_index) != GS_SUCCESS) {
        return GS_ERROR;
    }

    index_t *index = NULL;
    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (!IS_PART_INDEX(index) && need_invalid_index) {  // for global index, it's need to invalid it when drop part
            if (db_update_index_status(session, index, GS_TRUE, &is_changed) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (btree_segment_prepare(session, index, GS_INVALID_ID32, BTREE_DROP_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }

            continue;
        }

        if (IS_PART_INDEX(index) && IS_COMPART_INDEX(index->part_index)) {
            if (db_delete_one_sub_idxpart(session, cursor, desc, index->desc.id) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (db_update_subidxpart_count(session, &index->desc, desc->parent_partid, GS_FALSE) != GS_SUCCESS) {
                return GS_ERROR;
            }

            GS_LOG_DEBUG_INF("drop idx subpart, uid: %d, tid: %d, idx id: %d, ppart_id: %d, subpart_id %d",
                desc->uid, desc->table_id, index->desc.id, desc->parent_partid, desc->part_id);
        }
    }

    return GS_SUCCESS;
}

static status_t subpart_drop_compare_logical(knl_session_t *session, dc_entity_t *entity,
    table_part_t *table_subpart, text_t *text)
{
    errno_t err;
    table_part_t *compart = NULL;
    table_part_t *subpart = NULL;
    part_table_t *part_table = entity->table.part_table;
    text->len = 0;

    table_part_t *table_compart = PART_GET_ENTITY(part_table, table_subpart->parent_partno);
    knl_panic_log(table_compart != NULL, "table_compart is NULL, panic info: table %s table_subpart %s",
                  entity->table.desc.name, table_subpart->desc.name);
    for (uint32 i = 0; i < entity->table.part_table->desc.partcnt; i++) {
        compart = TABLE_GET_PART(&entity->table, i);
        if (!IS_READY_PART(compart)) {
            continue;
        }

        for (uint32 j = 0; j < compart->desc.subpart_cnt; j++) {
            subpart = PART_GET_SUBENTITY(part_table, compart->subparts[j]);
            if (subpart == NULL) {
                continue;
            }

            if (subpart->desc.lrep_status == PART_LOGICREP_STATUS_ON && (table_compart->part_no != compart->part_no ||
                subpart->part_no != table_subpart->part_no)) {
                if (text->len > 0) {
                    err = snprintf_s(text->str + text->len, GS_NAME_BUFFER_SIZE + 1, GS_NAME_BUFFER_SIZE, ",");
                    knl_securec_check_ss(err);
                    text->len += err;
                }
                    
                err = snprintf_s(text->str + text->len, GS_NAME_BUFFER_SIZE + 1, GS_NAME_BUFFER_SIZE, "%s",
                    subpart->desc.name);
                knl_securec_check_ss(err);
                text->len += err;
            }
        }
    }

    return GS_SUCCESS;
}

status_t subpart_drop_logical(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
    table_part_t *table_subpart)
{
    text_t text;
    table_t *table = &entity->table;
    uint32 uid = table->desc.uid;
    uint32 tableid = table->desc.id;
    status_t status = GS_SUCCESS;

    if (entity->lrep_info.status == LOGICREP_STATUS_ON || entity->lrep_info.parts_count == 0 ||
        table_subpart->desc.lrep_status != PART_LOGICREP_STATUS_ON) {
        return GS_SUCCESS;
    }

    if (entity->lrep_info.parts_count == 1) {
        status = db_altable_drop_logical_log_inner(session, cursor, uid, tableid);
        if (status == GS_SUCCESS) {
            table_subpart->desc.lrep_status = PART_LOGICREP_STATUS_OFF;
            entity->lrep_info.parts_count = 0;
        }
        return status;
    }
    
    text.str = (char *)cm_push(session->stack, entity->lrep_info.parts_count * (GS_NAME_BUFFER_SIZE + 1));
    if (text.str == NULL) {
        GS_THROW_ERROR(ERR_STACK_OVERFLOW);
        return GS_ERROR;
    }
    status = subpart_drop_compare_logical(session, entity, table_subpart, &text);
    if (status != GS_SUCCESS) {
        cm_pop(session->stack);
        return status;
    }

    status = db_altable_update_logical_log(session, cursor, uid, tableid, &text);
    if (status == GS_SUCCESS) {
        table_subpart->desc.lrep_status = PART_LOGICREP_STATUS_OFF;
        entity->lrep_info.parts_count--;
    }
    cm_pop(session->stack);
    return status;
}

static status_t db_delete_subpart_stats(knl_session_t *session, knl_dictionary_t *dc, table_part_t *sub_part)
{
    table_t *tabele = DC_TABLE(dc);
    bool32 is_nologging = IS_NOLOGGING_BY_TABLE_TYPE(tabele->desc.type);
    if (stats_delete_histhead_by_subpart(session, sub_part, is_nologging) != GS_SUCCESS) {
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    if (stats_delete_histgram_by_subpart(session, cursor, sub_part, is_nologging) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

status_t db_drop_subpartition(knl_session_t *session, knl_dictionary_t *dc, table_part_t *subpart)
{
    table_t *table = DC_TABLE(dc);
    knl_table_part_desc_t *desc = &subpart->desc;

    if (stats_update_global_partstats(session, dc, desc->parent_partid, subpart->part_no) != GS_SUCCESS) {
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = (knl_cursor_t *)knl_push_cursor(session);
   
    if (db_delete_one_sub_tabpart(session, cursor, desc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_update_subtabpart_count(session, desc->uid, desc->table_id, desc->parent_partid, GS_FALSE) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (DC_ENTITY(dc)->contain_lob) {
        if (subpart_drop_lobparts(session, dc, cursor, desc) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    if (subpart_drop_idxparts(session, dc, cursor, subpart) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_update_table_chgscn(session, &table->desc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_drop_subpart_segments(session, dc, subpart) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    dc_entity_t *entity = DC_ENTITY(dc);
    if (subpart_drop_logical(session, cursor, entity, subpart) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    
    CM_RESTORE_STACK(session->stack);

    if (db_delete_subpart_stats(session, dc, subpart) != GS_SUCCESS) {
        return GS_ERROR;
    }

    session->stat->table_subpart_drops++;
    return GS_SUCCESS;
}

status_t db_altable_drop_subpartition(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def,
    bool32 is_coalesce)
{
    table_t *table = DC_TABLE(dc);
    table_part_t *compart = NULL;
    table_part_t *subpart = NULL;

    if (subpart_drop_precheck(session, table, def, is_coalesce) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!subpart_table_find_by_name(table->part_table, &def->part_def.name, &compart, &subpart)) {
        if (def->options & DROP_IF_EXISTS) {
            return GS_SUCCESS;
        } else {
            GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&def->part_def.name));
            return GS_ERROR;
        }
    }

    /* if subpartcnt < 2 , drop table partition is not allowed */
    if (compart->desc.subpart_cnt < 2) {
        GS_THROW_ERROR(ERR_DROP_ONLY_PART);
        return GS_ERROR;
    }
    
    if (db_drop_subpartition(session, dc, subpart) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_coalesce_subpart_precheck(knl_session_t *session, table_t *table, knl_altable_def_t *def)
{
    if (!IS_PART_TABLE(table) || !IS_COMPART_TABLE(table->part_table)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "alter table coalesce subpartition", table->desc.name);
        return GS_ERROR;
    }

    part_table_t *part_table = table->part_table;
    if (part_table->desc.subparttype != PART_TYPE_HASH) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "COALESCE SUBPARTITION on other partitioned objects except hash");
        return GS_ERROR;
    }

    table_part_t *compart = NULL;
    if (!part_table_find_by_name(table->part_table, &def->part_def.name, &compart)) {
        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&def->part_def.name));
        return GS_ERROR;
    }

    if (compart->desc.subpart_cnt < COALESCE_MIN_PART_COUNT) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "coalesce a parent part with only one subpartition");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static void subpart_coalesce_close_cursor(knl_session_t *session, knl_cursor_t *cursor_delete,
    knl_cursor_t *cursor_insert)
{
    knl_close_cursor(session, cursor_delete);
    knl_close_cursor(session, cursor_insert);
}

status_t db_altable_coalesce_subpartition(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    table_t *table = DC_TABLE(dc);
    if (db_coalesce_subpart_precheck(session, table, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    table_part_t *compart = NULL;
    if (!part_table_find_by_name(table->part_table, &def->part_def.name, &compart)) {
        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&def->part_def.name));
        return GS_ERROR;
    }

    uint32 subpart_cnt = compart->desc.subpart_cnt;
    uint32 bucket_cnt = dc_get_hash_bucket_count(subpart_cnt);
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor_delete = knl_push_cursor(session);
    cursor_delete->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor_delete->action = CURSOR_ACTION_DELETE;
    cursor_delete->part_loc.part_no = compart->part_no;
    cursor_delete->part_loc.subpart_no = subpart_cnt - 1;
    if (knl_open_cursor(session, cursor_delete, dc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_cursor_t *cursor_insert = knl_push_cursor(session);
    cursor_insert->action = CURSOR_ACTION_INSERT;
    cursor_insert->part_loc.part_no = compart->part_no;
    cursor_insert->part_loc.subpart_no = subpart_cnt - 1 - bucket_cnt / HASH_PART_BUCKET_BASE;
    if (knl_open_cursor(session, cursor_insert, dc) != GS_SUCCESS) {
        knl_close_cursor(session, cursor_delete);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    cursor_insert->row = (row_head_t *)cm_push(session->stack, GS_MAX_ROW_SIZE);
    if (part_redis_move_part(session, cursor_delete, dc, cursor_insert, GS_FALSE) != GS_SUCCESS) {
        subpart_coalesce_close_cursor(session, cursor_delete, cursor_insert);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    subpart_coalesce_close_cursor(session, cursor_delete, cursor_insert);
    CM_RESTORE_STACK(session->stack);

    /* drop last subpartition */
    table_part_t *subpart = PART_GET_SUBENTITY(table->part_table, compart->subparts[subpart_cnt - 1]);
    if (db_drop_subpartition(session, dc, subpart) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

