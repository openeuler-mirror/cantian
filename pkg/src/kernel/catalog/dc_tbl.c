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
 * dc_tbl.c
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/dc_tbl.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_dc_module.h"
#include "dc_tbl.h"
#include "cm_log.h"
#include "knl_table.h"
#include "knl_context.h"
#include "ostat_load.h"
#include "dc_util.h"
#include "index_common.h"
#include "knl_sys_part_defs.h"
#include "dtc_dls.h"
#include "dtc_drc.h"

void dc_set_table_accessor(table_t *table)
{
    switch (table->desc.type) {
        case TABLE_TYPE_TRANS_TEMP:
        case TABLE_TYPE_SESSION_TEMP:
            table->acsor = &g_temp_heap_acsor;
            break;

        case TABLE_TYPE_HEAP:
        case TABLE_TYPE_NOLOGGING:
            if (table->desc.cr_mode == CR_ROW) {
                table->acsor = &g_heap_acsor;
            } else {
                table->acsor = &g_pcr_heap_acsor;
            }
            break;
        case TABLE_TYPE_EXTERNAL:
            table->acsor = &g_external_table_acsor;
            break;

        case TABLE_TYPE_IOT:
            table->acsor = &g_invalid_table_acsor;
            break;

        default:
            table->acsor = &g_invalid_table_acsor;
            break;
    }
}

void dc_set_index_accessor(table_t *table, index_t *index)
{
    bool32 is_temp = (table->desc.type == TABLE_TYPE_TRANS_TEMP || table->desc.type == TABLE_TYPE_SESSION_TEMP);
    switch (index->desc.type) {
        case INDEX_TYPE_BTREE:
            if (index->desc.cr_mode == CR_ROW) {
                if (is_temp) {
                    index->acsor = &g_temp_btree_acsor;
                } else {
                    index->acsor = &g_btree_acsor;
                }
            } else {
                index->acsor = &g_pcr_btree_acsor;
            }
            break;
        case INDEX_TYPE_HASH:
        case INDEX_TYPE_BITMAP:
        default:
            index->acsor = &g_invalid_index_acsor;
            break;
    }
}

static inline void dc_entry_inc_ref(dc_entry_t *entry)
{
    cm_spin_lock(&entry->ref_lock, NULL);
    if (entry->type == DICT_TYPE_TABLE) {
        entry->ref_count++;
    }
    cm_spin_unlock(&entry->ref_lock);
}

static void dc_entry_dec_ref(dc_entity_t *entity)
{
    if (entity == NULL) {
        return;
    }

    dc_entry_t *entry = entity->entry;
    table_t *table = &entity->table;

    cm_spin_lock(&entry->ref_lock, NULL);
    if (entry->type == DICT_TYPE_TABLE && table->desc.org_scn == entry->org_scn) {
        entry->ref_count--;
        knl_panic_log(entry->ref_count >= 0, "ref_count is incorrect, panic info: table %s ref_count %u",
                      table->desc.name, entry->ref_count);
    }
    cm_spin_unlock(&entry->ref_lock);
}

void dc_convert_table_desc(knl_cursor_t *cursor, knl_table_desc_t *desc)
{
    text_t text;

    desc->uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_USER_ID);
    desc->id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_ID);

    text.str = CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_NAME);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_TABLE_COL_NAME);
    (void)cm_text2str(&text, desc->name, CT_NAME_BUFFER_SIZE);

    desc->space_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_SPACE_ID);
    desc->org_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_ORG_SCN);
    desc->chg_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_CHG_SCN);
    desc->type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_TYPE);
    desc->column_count = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_COLS);
    desc->index_count = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_INDEXES);
    desc->parted = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_PARTITIONED);
    desc->entry = *(page_id_t *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_ENTRY);
    desc->initrans = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_INITRANS);
    desc->pctfree = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_PCTFREE);
    desc->cr_mode = (uint8)(*(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_CR_MODE));
    desc->recycled = (uint8)(*(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_RECYCLED));
    desc->appendonly = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_APPENDONLY);
    desc->serial_start = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_SERIAL_START);
    desc->oid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_OBJID);
    if (CURSOR_COLUMN_SIZE(cursor, SYS_TABLE_COL_VERSION) == CT_NULL_VALUE_LEN) {
        desc->version = 0;
    } else {
        desc->version = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_VERSION);
    }
    if (CURSOR_COLUMN_SIZE(cursor, SYS_TABLE_COL_FLAG) == CT_NULL_VALUE_LEN) {
        desc->flags = 0;
    } else {
        desc->flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_FLAG);
    }

    desc->seg_scn = desc->org_scn;
    desc->compress_algo = COMPRESS_NONE;
}

status_t dc_convert_view_desc(knl_session_t *session, knl_cursor_t *cursor, knl_view_t *view, dc_entity_t *entity)
{
    text_t text;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    errno_t err;
    lob_locator_t *lob = NULL;
    uint32 lob_size;

    view->uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_VIEW_USER);
    view->id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_VIEW_OBJID);

    text.str = CURSOR_COLUMN_DATA(cursor, SYS_VIEW_NAME);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_VIEW_NAME);
    (void)cm_text2str(&text, view->name, CT_NAME_BUFFER_SIZE);

    view->column_count = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_VIEW_COLS);
    view->flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_VIEW_FLAG);
    view->org_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_VIEW_ORG_SCN);
    view->chg_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_VIEW_CHG_SCN);
    view->sql_type = *(sql_style_t *)CURSOR_COLUMN_DATA(cursor, SYS_VIEW_SQL_TYPE);
    if (entity != NULL) {
        lob = (lob_locator_t *)CURSOR_COLUMN_DATA(cursor, SYS_VIEW_TEXT);
        lob_size = knl_lob_locator_size(lob);
        if (dc_alloc_mem(ctx, entity->memory, lob_size + 1, &view->lob) != CT_SUCCESS) {
            return CT_ERROR;
        }

        err = memcpy_sp(view->lob, lob_size, lob, lob_size);
        knl_securec_check(err);

        view->sub_sql.len = knl_lob_size(view->lob);

        if (LOB_IS_INLINE(lob)) {
            view->sub_sql.str = LOB_INLINE_DATA((lob_locator_t *)view->lob);
            return CT_SUCCESS;
        }

        if (view->sub_sql.len + 1 < CT_SHARED_PAGE_SIZE) {
            if (dc_alloc_mem(ctx, entity->memory, view->sub_sql.len + 1, (void **)&view->sub_sql.str) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (knl_read_lob(session, view->lob, 0, view->sub_sql.str, view->sub_sql.len + 1, NULL, NULL) !=
                CT_SUCCESS) {
                return CT_ERROR;
            }
            view->sub_sql.str[view->sub_sql.len] = '\0';
        }
    }
    return CT_SUCCESS;
}

status_t dc_copy_column_data(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity, uint32 id,
    void *dest, bool32 is_reserved)
{
    text_t *text = (text_t *)dest;
    errno_t ret;

    if (CURSOR_COLUMN_SIZE(cursor, id) != CT_NULL_VALUE_LEN) {
        text->len = CURSOR_COLUMN_SIZE(cursor, id);

        if (!is_reserved && dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, text->len, (void **)&text->str) !=
            CT_SUCCESS) {
            return CT_ERROR;
        }

        if (text->len == 0) {
            return CT_SUCCESS;
        }
        ret = memcpy_sp(text->str, text->len, CURSOR_COLUMN_DATA(cursor, id), text->len);
        knl_securec_check(ret);
    } else {
        text->len = 0;
        text->str = NULL;
    }

    return CT_SUCCESS;
}

/* Fetch the precision and scale from sys.column$. Its dual function is
* *row_put_prec_and_scale* and *db_write_syscolumn*,
* The 6th column is precision and the 7-th column represents scale.
*/
static void dc_fetch_prec_and_scale(knl_cursor_t *cursor, knl_column_t *column)
{
    bool32 prec_is_null = (bool32)(cursor->lens[SYS_COLUMN_COL_PRECISION] == CT_NULL_VALUE_LEN);

    switch ((ct_type_t)column->datatype) {
        case CT_TYPE_REAL:
        case CT_TYPE_FLOAT:
            if (prec_is_null) {
                column->precision = CT_UNSPECIFIED_REAL_PREC;
                column->scale = CT_UNSPECIFIED_REAL_SCALE;
                return;
            }
            column->precision = *(int32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_PRECISION);
            column->scale = *(int32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_SCALE);
            return;
            
        case CT_TYPE_BIGINT:
            column->precision = *(int32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_PRECISION);
            column->scale = 0;

        case CT_TYPE_INTEGER:
        case CT_TYPE_UINT32:
        case CT_TYPE_UINT64:
            if (column->mysql_ori_datatype == MYSQL_TYPE_ENUM || column->mysql_ori_datatype == MYSQL_TYPE_SET ||
                column->mysql_ori_datatype == MYSQL_TYPE_BIT) {
                column->precision = *(int32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_PRECISION);
                column->scale = 0;
                return;
            }
            column->precision = 0;
            column->scale = 0;
            return;

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
        case CT_TYPE_NUMBER3:
            if (prec_is_null) {
                column->precision = CT_UNSPECIFIED_NUM_PREC;
                column->scale = CT_UNSPECIFIED_NUM_SCALE;
                return;
            }
            column->precision = *(int32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_PRECISION);
            column->scale = *(int32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_SCALE);
            return;

        case CT_TYPE_INTERVAL_DS:
            knl_panic_log(!prec_is_null, "prec is null, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
            column->precision = *(int32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_PRECISION);
            column->scale = *(int32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_SCALE);
            return;

        case CT_TYPE_INTERVAL_YM:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_TZ:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
            knl_panic_log(!prec_is_null, "prec is null, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);
            column->precision = *(int32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_PRECISION);  // precision
            column->scale = 0;
            return;

        default:
            knl_panic_log(prec_is_null, "prec is not null, panic info: page %u-%u type %u table %s",
                          cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                          ((table_t *)cursor->table)->desc.name);
            column->precision = 0;
            column->scale = 0;
            return;
    }
}

status_t dc_convert_column(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity, knl_column_t *column)
{
    text_t text;

    column->uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_USER_ID);
    column->table_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_TABLE_ID);
    column->id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_ID);

    text.str = CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_NAME);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_COLUMN_COL_NAME);

    if (dc_copy_text2str(session, entity->memory, &text, &column->name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    column->datatype = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_DATATYPE);
    column->size = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_BYTES);
    if (cm_is_null_col(cursor->row, cursor->lens, SYS_COLUMN_COL_OPTIONS)) {
        column->is_collate = CT_FALSE;
    } else {
        if (DB_ATTR_COMPATIBLE_MYSQL(session)) {
            uint16 collate_id = *(uint16*)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_OPTIONS);
            if (collate_id == CT_INVALID_ID16) {
                column->is_collate = CT_FALSE;
            } else {
                column->is_collate = CT_TRUE;
                column->collate_id = collate_id;
            }
            column->mysql_ori_datatype = *(uint8*)(CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_OPTIONS) + sizeof(uint16));
            column->mysql_unsigned = *(uint8*)(CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_OPTIONS) +
                                               sizeof(uint16) + sizeof(uint8));
        }
    }
    dc_fetch_prec_and_scale(cursor, column);
    column->nullable = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_NULLABLE);
    column->flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_FLAGS);

    if (!KNL_COLUMN_IS_DEFAULT_NULL(column)) {
        if (dc_copy_column_data(session, cursor, entity, SYS_COLUMN_COL_DEFAULT_TEXT,
            &column->default_text, CT_FALSE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (!KNL_COLUMN_IS_VIRTUAL(column) && column->default_text.len != 0) {
        /* get default expr tree from defalut_text directly instead of default_data */
        if (g_knl_callback.parse_default_from_text((knl_handle_t)session, (knl_handle_t)entity,
            (knl_handle_t)column, entity->memory,
            &column->default_expr, &column->update_default_expr, column->default_text) != CT_SUCCESS) {
            if (!entity->entry->recycled) {
                return CT_ERROR;
            }
        }
    }

    if (KNL_COLUMN_IS_DELETED(column)) {
        column->nullable = CT_TRUE;
    }

    if (COLUMN_IS_LOB(column)) {
        entity->contain_lob = CT_TRUE;
    }

    if (KNL_COLUMN_IS_UPDATE_DEFAULT(column)) {
        entity->has_udef_col = CT_TRUE;
    }

    if (KNL_COLUMN_IS_SERIAL(column) && !KNL_COLUMN_IS_DELETED(column)) {
        entity->has_serial_col = CT_TRUE;
    }

    return CT_SUCCESS;
}

/*
* Description     : covert one row fetched from index$ to structure knl_index_desc_t
* Input           : cursor
* Output          : desc
* Return Value    : void
* History         : 1. 2017/4/26,  add description
*/
void dc_convert_column_list(uint32 col_count, text_t *column_list, uint16 *cols)
{
    uint32 i;
    text_t col_id;

    for (i = 0; i < col_count; i++) {
        if (cm_fetch_text(column_list, ',', '\0', &col_id)) {
            (void)cm_text2uint16(&col_id, &cols[i]);
        }
    }
}

void dc_convert_index(knl_session_t *session, knl_cursor_t *cursor, knl_index_desc_t *desc)
{
    text_t text, column_list;

    desc->uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_USER);
    desc->table_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_TABLE);
    desc->id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_ID);
    desc->space_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_SPACE);
    desc->org_scn = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_SEQUENCE);
    desc->entry = *(page_id_t *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_ENTRY);
    desc->primary = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_IS_PRIMARY);
    desc->unique = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_IS_UNIQUE);
    desc->type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_TYPE);
    desc->column_count = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_COLS);
    column_list.str = CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_COL_LIST);
    column_list.len = CURSOR_COLUMN_SIZE(cursor, SYS_INDEX_COLUMN_ID_COL_LIST);
    desc->initrans = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_INITRANS);
    desc->cr_mode = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_CR_MODE);
    desc->flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_FLAGS);
    desc->parted = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_PARTITIONED);
    desc->pctfree = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_PCTFREE);
    if (!cm_is_null_col(cursor->row, cursor->lens, SYS_INDEX_COLUMN_ID_OPTIONS) &&
        DB_ATTR_COMPATIBLE_MYSQL(session)) {
        desc->is_dsc = CT_TRUE;
    } else {
        desc->is_dsc = CT_FALSE;
    }

    dc_convert_column_list(desc->column_count, &column_list, desc->columns);

    desc->seg_scn = desc->org_scn;
    desc->is_enforced = desc->is_cons;
    text.str = CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_NAME);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_INDEX_COLUMN_ID_NAME);
    (void)cm_text2str(&text, desc->name, CT_NAME_BUFFER_SIZE);
    desc->max_key_size = btree_max_allowed_size(session, desc);
    desc->part_idx_invalid = CT_FALSE;
}

static status_t dc_load_external_table(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t* entity)
{
    text_t text;
    errno_t ret;
    knl_ext_desc_t *external_desc = NULL;
    knl_table_desc_t *desc = &entity->table.desc;

    if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(knl_ext_desc_t),
        (void **)&external_desc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ret = memset_sp(external_desc, sizeof(knl_ext_desc_t), 0, sizeof(knl_ext_desc_t));
    knl_securec_check(ret);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_EXTERNAL_ID, IX_EXTERNALTABS_001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->uid,
        sizeof(uint32), IX_COL_EXTERNALTABS_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&desc->id,
        sizeof(uint32), IX_COL_EXTERNALTABS_001_TABLE_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cursor->eof) {
        CT_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "external table", desc->name);
        return CT_ERROR;
    }

    external_desc->external_type = *(uint32*)CURSOR_COLUMN_DATA(cursor, SYS_EXTERNAL_COL_TYPE);
    text.str = CURSOR_COLUMN_DATA(cursor, SYS_EXTERNAL_COL_DIRECTORY);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_EXTERNAL_COL_DIRECTORY);
    ret = memcpy_sp(external_desc->directory, CT_FILE_NAME_BUFFER_SIZE, text.str, text.len);
    knl_securec_check(ret);

    text.str = CURSOR_COLUMN_DATA(cursor, SYS_EXTERNAL_COL_LOCATION);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_EXTERNAL_COL_LOCATION);
    ret = memcpy_sp(external_desc->location, CT_MAX_NAME_LEN, text.str, text.len);
    knl_securec_check(ret);

    external_desc->records_delimiter = *CURSOR_COLUMN_DATA(cursor, SYS_EXTERNAL_COL_RECORDS_DEL);
    external_desc->fields_terminator = *CURSOR_COLUMN_DATA(cursor, SYS_EXTERNAL_COL_FIELDS_DEL);

    desc->external_desc = external_desc;
    return CT_SUCCESS;
}

#ifdef Z_SHARDING

status_t dc_convert_table_distribute_strategy(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity)
{
    distribute_strategy_t dist_desc;
    knl_table_desc_t *desc = &entity->table.desc;
    routing_info_t *routing_info = NULL;
    lob_locator_t lob;
    uint32 len;
    errno_t err;

    if (IS_SYS_TABLE(&entity->table)) {
        return CT_SUCCESS;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_DISTRIBUTE_STRATEGY_ID,
        IX_SYS_DISTRIBUTE_STRATEGY001_ID);
    knl_init_index_scan(cursor, CT_TRUE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &desc->uid, sizeof(uint32),
        IX_COL_SYS_DISTRIBUTE_STRATEGY001_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &desc->id, sizeof(uint32),
        IX_COL_SYS_DISTRIBUTE_STRATEGY001_TABLE);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cursor->eof) {
        return CT_SUCCESS;
    }

    dist_desc.user_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, DISTRIBUTED_STRATEGY_COL_USER);
    dist_desc.table_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, DISTRIBUTED_STRATEGY_COL_TABLE);
    dist_desc.dist_text.len = CURSOR_COLUMN_SIZE(cursor, DISTRIBUTED_STRATEGY_COL_DIST_TEXT);
    dist_desc.dist_data.size = CURSOR_COLUMN_SIZE(cursor, DISTRIBUTED_STRATEGY_COL_DIST_DATA);
    dist_desc.frozen_status = *(uint32 *)CURSOR_COLUMN_DATA(cursor, DISTRIBUTED_STRATEGY_COL_FROZEN_STATUS);
    if (CURSOR_COLUMN_SIZE(cursor, DISTRIBUTED_STRATEGY_COL_SLICE_CNT) != CT_NULL_VALUE_LEN) {
        desc->slice_count = *(uint32 *)CURSOR_COLUMN_DATA(cursor, DISTRIBUTED_STRATEGY_COL_SLICE_CNT);
    } else {
        desc->slice_count = 0;
    }
    if (dist_desc.dist_text.len != CT_NULL_VALUE_LEN) {
        if (dist_desc.dist_text.len > CT_DISTRIBUTE_BUFFER_SIZE) {
            return CT_ERROR;
        }
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, dist_desc.dist_text.len,
            (void **)&dist_desc.dist_text.str) != CT_SUCCESS) {
            return CT_ERROR;
        }
        err = memcpy_sp(dist_desc.dist_text.str, dist_desc.dist_text.len,
            CURSOR_COLUMN_DATA(cursor, DISTRIBUTED_STRATEGY_COL_DIST_TEXT), dist_desc.dist_text.len);
        knl_securec_check(err);
        if (g_knl_callback.parse_distribute_from_text(session, entity, &dist_desc.dist_text) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (dist_desc.dist_data.size > CT_DISTRIBUTE_BUFFER_SIZE) {
            return CT_ERROR;
        }
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, dist_desc.dist_data.size,
            (void **)&dist_desc.dist_data.bytes) != CT_SUCCESS) {
            return CT_ERROR;
        }
        err = memcpy_sp(dist_desc.dist_data.bytes, dist_desc.dist_data.size,
            CURSOR_COLUMN_DATA(cursor, DISTRIBUTED_STRATEGY_COL_DIST_DATA), dist_desc.dist_data.size);
        knl_securec_check(err);
        if (g_knl_callback.parse_distribute_info((void *)entity, (void *)&dist_desc.dist_data) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    // only hash distribute need to read the bucktes field
    routing_info = knl_get_table_routing_info(entity);
    if (dist_desc.frozen_status == FROZEN_INIT_STATUS || dist_desc.frozen_status == FROZEN_WORKING_STATUS) {
        routing_info->frozen_status = dist_desc.frozen_status;
    } else {
        routing_info->frozen_status = FROZEN_INIT_STATUS;
    }
    
    if (routing_info->type != distribute_hash && routing_info->type != distribute_hash_basic) {
        routing_info->buckets = NULL;
        return CT_SUCCESS;
    }

    err = memcpy_sp(&lob, sizeof(lob_locator_t), CURSOR_COLUMN_DATA(cursor, DISTRIBUTED_STRATEGY_COL_BUCKETS),
        sizeof(lob_locator_t));
    knl_securec_check(err);
    len = knl_lob_size(&lob);
    knl_panic_log(len == BUCKETDATALEN, "lob size is abnormal, panic info: page %u-%u type %u table %s index %s "
                  "lob size %u", cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((table_t *)cursor->index)->desc.name, len);

    if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, BUCKETDATALEN,
        (void **)&dist_desc.buckets.bytes) != CT_SUCCESS) {
        return CT_ERROR;
    }

    err = memset_sp(dist_desc.buckets.bytes, BUCKETDATALEN, 0, BUCKETDATALEN);
    knl_securec_check(err);
    dist_desc.buckets.size = BUCKETDATALEN;

    if (knl_read_lob(session, &lob, 0, dist_desc.buckets.bytes, BUCKETDATALEN, NULL, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return g_knl_callback.parse_distribute_bkts(session, (void *)entity, (void *)&dist_desc.buckets);
}

#endif

static bool32 dc_nologging_is_ready(knl_session_t *session, dc_user_t *user, knl_table_desc_t *table)
{
    if (DB_IS_READONLY(session)) {
        /* nologging table is replicated to standby, but treat it can't be accessed to simulate sysbase tempdb */
        if (session->kernel->attr.drop_nologging) {
            CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, user->desc.name, table->name);
            return CT_FALSE;
        }

        /*
        * scenario:
        * 1. alter database convert to readonly;
        * 2. access nologging table(dc loaded but dc_reset_nologging_entry does not work);
        * 3. alter database convert to readwrite;
        * 4. DDL on nologging table(update table$); if use dc that is loaded in 2),
        *     then call dc_reset_nologging_entry(update table$), cause lock is blocked by self.
        *
        * so, for a quick and simple fix, let it can't be accessed in readonly mode.
        */
        CT_THROW_ERROR(ERR_INVALID_DC, table->name);
        return CT_FALSE;
    }

    return CT_TRUE;
}

#ifdef Z_SHARDING
static status_t dc_load_distribute_rule_entity_ex(knl_session_t *session, knl_cursor_t *cursor, uint32 uid,
    uint32 oid, dc_entity_t *entity)
{
    distribute_strategy_t dist_desc;

    routing_info_t *routing_info = NULL;
    lob_locator_t lob;
    uint32 len;
    errno_t err;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_DISTRIBUTE_RULE_ID, IX_SYS_DISTRIBUTE_RULE002_ID);
    knl_init_index_scan(cursor, CT_TRUE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &oid, sizeof(uint32),
        IX_COL_SYS_DISTRIBUTE_RULE001_NAME);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    while (!cursor->eof) {
        dist_desc.user_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_DISTRIBUTE_RULE_COL_UID);
        if (uid != dist_desc.user_id) {
            if (knl_fetch(session, cursor) != CT_SUCCESS) {
                return CT_ERROR;
            }
        } else {
            break;
        }
    }

    dist_desc.user_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_DISTRIBUTE_RULE_COL_UID);
    dist_desc.table_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_DISTRIBUTE_RULE_COL_ID);

    entity->table.desc.column_count = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_DISTRIBUTE_RULE_COLUMN_COUNT);
    entity->table.desc.uid = dist_desc.user_id;
    entity->table.desc.id = dist_desc.table_id;

    dist_desc.dist_data.size = CURSOR_COLUMN_SIZE(cursor, SYS_DISTRIBUTE_RULE_COL_DIST_DATA);
    if (dist_desc.dist_data.size > CT_DISTRIBUTE_BUFFER_SIZE) {
        CT_THROW_ERROR(ERR_SIZE_ERROR, dist_desc.dist_data.size, CT_DISTRIBUTE_BUFFER_SIZE, "char");
        return CT_ERROR;
    }

    if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, dist_desc.dist_data.size,
        (void **)&dist_desc.dist_data.bytes) != CT_SUCCESS) {
        return CT_ERROR;
    }

    err = memcpy_sp(dist_desc.dist_data.bytes, dist_desc.dist_data.size,
        CURSOR_COLUMN_DATA(cursor, SYS_DISTRIBUTE_RULE_COL_DIST_DATA), dist_desc.dist_data.size);
    knl_securec_check(err);

    if (g_knl_callback.parse_distribute_info((void *)entity, (void *)&dist_desc.dist_data) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // only hash distribute need to read the bucktes field
    routing_info = knl_get_table_routing_info(entity);
    if (routing_info->type != distribute_hash && routing_info->type != distribute_hash_basic) {
        routing_info->buckets = NULL;
        return CT_SUCCESS;
    }

    err = memcpy_sp(&lob, sizeof(lob_locator_t), CURSOR_COLUMN_DATA(cursor, SYS_DISTRIBUTE_RULE_COL_BUCKETS),
        sizeof(lob_locator_t));
    knl_securec_check(err);
    len = knl_lob_size(&lob);
    knl_panic_log(len == BUCKETDATALEN, "lob size is abnormal, panic info: page %u-%u type %u table %s index %s "
                  "lob size %u", cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((table_t *)cursor->index)->desc.name, len);

    if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, BUCKETDATALEN,
        (void **)&dist_desc.buckets.bytes) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dist_desc.buckets.size = BUCKETDATALEN;
    if (knl_read_lob(session, &lob, 0, dist_desc.buckets.bytes, BUCKETDATALEN, NULL, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return g_knl_callback.parse_distribute_bkts(session, (void *)entity, (void *)&dist_desc.buckets);
}

static status_t dc_load_distribute_rule_entity(knl_session_t *session, dc_user_t *user, uint32 oid,
    dc_entity_t *entity)
{
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    if (dc_load_distribute_rule_entity_ex(session, cursor, user->desc.id, oid, entity) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (dc_load_columns(session, cursor, entity) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}
#endif

status_t dc_load_table_parts_monitor(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity)
{
    table_t *table = &entity->table;

    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        table_part_t *table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_MON_MODS_ALL_ID, IX_MODS_003_ID);
        knl_init_index_scan(cursor, CT_TRUE);
        knl_scan_key_t *key = &cursor->scan_range.l_key;
        knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &table_part->desc.uid,
            sizeof(uint32), IX_COL_MODS_003_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &table_part->desc.table_id,
            sizeof(uint32), IX_COL_MODS_003_TABLE_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &table_part->desc.part_id,
            sizeof(uint32), IX_COL_MODS_003_PART_ID);

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cursor->eof) {
            continue;
        }

        stats_table_mon_t *tab_mon = &table_part->table_smon;
        tab_mon->inserts = *(uint32 *)CURSOR_COLUMN_DATA(cursor, STATS_MON_MODS_INSERTS_COLUMN);
        tab_mon->updates = *(uint32 *)CURSOR_COLUMN_DATA(cursor, STATS_MON_MODS_UPDATES_COLUMN);
        tab_mon->deletes = *(uint32 *)CURSOR_COLUMN_DATA(cursor, STATS_MON_MODS_DELETES_COLUMN);
        tab_mon->timestamp = *(date_t *)CURSOR_COLUMN_DATA(cursor, STATS_MON_MODS_MODIFYTIME_COLUMN);
        tab_mon->drop_segments = *(uint32 *)CURSOR_COLUMN_DATA(cursor, STATS_MON_MODS_DROP_SEG_COLUMN);
    }

    return CT_SUCCESS;
}

status_t dc_load_table_monitor(knl_session_t *session, dc_entity_t *entity)
{
    if (entity->type != DICT_TYPE_TABLE || IS_SYS_TABLE(&entity->table)) {
        return CT_SUCCESS;
    }

    uint32 part_id = CT_INVALID_ID32;
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_MON_MODS_ALL_ID, IX_MODS_003_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_scan_key_t *key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &entity->table.desc.uid,
        sizeof(uint32), IX_COL_MODS_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &entity->table.desc.id,
        sizeof(uint32), IX_COL_MODS_003_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &part_id,
        sizeof(uint32), IX_COL_MODS_003_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    }

    stats_table_mon_t *tab_mon = &entity->entry->appendix->table_smon;
    tab_mon->inserts = *(uint32 *)CURSOR_COLUMN_DATA(cursor, STATS_MON_MODS_INSERTS_COLUMN);
    tab_mon->updates = *(uint32 *)CURSOR_COLUMN_DATA(cursor, STATS_MON_MODS_UPDATES_COLUMN);
    tab_mon->deletes = *(uint32 *)CURSOR_COLUMN_DATA(cursor, STATS_MON_MODS_DELETES_COLUMN);
    tab_mon->timestamp = *(date_t *)CURSOR_COLUMN_DATA(cursor, STATS_MON_MODS_MODIFYTIME_COLUMN);
    tab_mon->drop_segments = *(uint32 *)CURSOR_COLUMN_DATA(cursor, STATS_MON_MODS_DROP_SEG_COLUMN);
    bool32 is_part = *(bool32 *)CURSOR_COLUMN_DATA(cursor, STATS_MON_MODS_PARTED);
    if (is_part) {
        if (dc_load_table_parts_monitor(session, cursor, entity) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t dc_load_entity_internal(knl_session_t *session, dc_user_t *user, uint32 oid, dc_entry_t *entry)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_entity_t *entity = entry->entity;

    session->query_scn = DB_CURR_SCN(session);

    if (dc_alloc_entity(ctx, entry) != CT_SUCCESS) {
        entry->entity = NULL;
        return CT_ERROR;
    }

    entity = entry->entity;
#ifdef Z_SHARDING
    if (entry->type == DICT_TYPE_DISTRIBUTE_RULE) {
        if (dc_load_distribute_rule_entity(session, user, oid, entry->entity) != CT_SUCCESS) {
            mctx_destroy(entry->entity->memory);
            entry->entity = NULL;
            return CT_ERROR;
        }

        return CT_SUCCESS;
    }
#endif
    dc_entry_inc_ref(entry);
    if (entry->type == DICT_TYPE_VIEW) {
        dc_entry_dec_ref(entity);
        if (dc_load_view_entity(session, user, oid, entity) != CT_SUCCESS) {
            mctx_destroy(entry->entity->memory);
            entry->entity = NULL;
            return CT_ERROR;
        }
    } else {
        if (dc_load_table_entity(session, user, oid, entity) != CT_SUCCESS) {
            dc_entry_dec_ref(entity);
            mctx_destroy(entry->entity->memory);
            entry->entity = NULL;
            return CT_ERROR;
        }

        if (entity->column_count >= session->kernel->attr.max_column_count) {
            dc_entry_dec_ref(entity);
            mctx_destroy(entry->entity->memory);
            entry->entity = NULL;
            CT_THROW_ERROR_EX(ERR_INVALID_PARAMETER,
                "the parameter MAX_COLUMN_COUNT is smaller than the columns count of table %s",
                entity->table.desc.name);
            return CT_ERROR;
        }
    }

    if (entry->appendix == NULL) {
        if (dc_alloc_appendix(session, entry) != CT_SUCCESS) {
            dc_entry_dec_ref(entity);
            mctx_destroy(entry->entity->memory);
            entry->entity = NULL;
            return CT_ERROR;
        }

        if (dc_load_table_monitor(session, entity) != CT_SUCCESS) {
            dc_entry_dec_ref(entity);
            mctx_destroy(entity->memory);
            entry->entity = NULL;
            return CT_ERROR;
        }
    }

    if (entry->sch_lock == NULL) {
        if (dc_alloc_schema_lock(session, entry) != CT_SUCCESS) {
            dc_entry_dec_ref(entity);
            mctx_destroy(entry->entity->memory);
            entry->entity = NULL;
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

void dc_wait_till_load_finish(knl_session_t *session, dc_entry_t *entry)
{
    // precondition: entry->lock is locked before this function
    // postcondition: entry->lock is locked
    for (;;) {
        if (!entry->is_loading && ((g_rc_ctx == NULL) || !RC_REFORM_RECOVERY_IN_PROGRESS)) {
            return;
        }
        cm_spin_unlock(&entry->lock);
        cm_sleep(ENTRY_IS_LOADING_INTERVAL);
        cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    }
    return;
}

status_t dc_load_entity(knl_session_t *session, dc_user_t *user, uint32 oid, dc_entry_t *entry, knl_dictionary_t *dc)
{
    dc_wait_till_load_finish(session, entry);
    if (entry->entity != NULL) { // check entity
        return CT_SUCCESS;
    }
    entry->is_loading = CT_TRUE;
    cm_spin_unlock(&entry->lock);

    while (!dls_latch_timed_s(session, &entry->ddl_latch, 1, CT_FALSE, NULL, CT_INVALID_ID32)) {
        if (dc != NULL && !dc_entry_visible(entry, dc)) {
            cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
            entry->is_loading = CT_FALSE;
            CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, user->desc.name, entry->name);
            return CT_ERROR;
        }
    }
    if (RC_REFORM_RECOVERY_IN_PROGRESS) {
        dls_unlatch(session, &entry->ddl_latch, NULL);
        cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
        knl_panic(entry->is_loading);
        entry->is_loading = CT_FALSE;
        CT_LOG_RUN_ERR("loading dc during reform");
        return CT_ERROR;
    }

    if (dc != NULL && !dc_entry_visible(entry, dc)) {
        dls_unlatch(session, &entry->ddl_latch, NULL);
        cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
        entry->is_loading = CT_FALSE;
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, user->desc.name, entry->name);
        return CT_ERROR;
    }

    status_t ret = dc_load_entity_internal(session, user, oid, entry);
    dls_unlatch(session, &entry->ddl_latch, NULL);

    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    knl_panic(entry->is_loading);
    entry->is_loading = CT_FALSE;
    if (ret != CT_ERROR && entry->entity == NULL) {
        cm_reset_error();
        CT_THROW_ERROR(ERR_DC_LOAD_CONFLICT);
        // loading conflict with dc invalidation from ddl redo in partial recovery
        CT_LOG_RUN_ERR("loading conflict, entity is null");
        ret = CT_ERROR;
    }
    return ret;
}


status_t dc_open_table_or_view(knl_session_t *session, dc_user_t *user, dc_entry_t *entry, knl_dictionary_t *dc)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    session->query_scn = DB_CURR_SCN(session);

    if (dc_load_entity(session, user, entry->id, entry, dc) != CT_SUCCESS) {
        return CT_ERROR;
    }
    dc_entity_t *entity = entry->entity;
    dc->type = entry->type;
    dc->org_scn = entry->org_scn;
    dc->chg_scn = entry->chg_scn;
    dc->kernel = session->kernel;
    dc->handle = entity;

    knl_temp_cache_t *temp_cache = NULL;
    if (IS_TEMP_TABLE_BY_DC(dc)) {
        temp_cache = knl_get_temp_cache((knl_handle_t)session, entity->table.desc.uid, entity->table.desc.id);
    }
    bool32 stat_exists = (temp_cache == NULL) ? entry->entity->stat_exists : temp_cache->stat_exists;
    if (stat_exists) {
        dc->stats_version = (temp_cache == NULL) ? entity->stats_version : temp_cache->stats_version;
    } else {
        dc->stats_version = CT_INVALID_ID32;
    }

    if (dc_into_lru_needed(entry, ctx)) {
        cm_spin_lock(&ctx->lru_queue->lock, NULL);
        if (dc_into_lru_needed(entry, ctx)) {
            dc_lru_add(ctx->lru_queue, entry->entity);
        }
        cm_spin_unlock(&ctx->lru_queue->lock);
    }

    cm_spin_lock(&entry->entity->ref_lock, NULL);
    entry->entity->ref_count++;
    cm_spin_unlock(&entry->entity->ref_lock);

    return CT_SUCCESS;
}

static status_t dc_init_entity_entry(knl_session_t *session, dc_user_t *user, knl_table_desc_t *desc, dc_entity_t *entity)
{
    if (entity->entry != NULL) {
        /* empty table entry when nologging table is first loaded(db restart) */
        if (IS_NOLOGGING_BY_TABLE_TYPE(desc->type)) {
            user->has_nologging = CT_TRUE;

            if (!dc_nologging_is_ready(session, user, desc)) {
                return CT_ERROR;
            }

            if (entity->entry->need_empty_entry) {
                desc->entry = INVALID_PAGID;
                if (dc_reset_nologging_entry(session, (knl_handle_t)desc, OBJ_TYPE_TABLE) != CT_SUCCESS) {
                    return CT_ERROR;
                }
            }
        } else {
            entity->entry->need_empty_entry = CT_FALSE;
        }
        entity->entry->org_scn = desc->org_scn;
        entity->entry->chg_scn = desc->chg_scn;
    }

    return CT_SUCCESS;
}

static void dc_load_table_heap_segment(knl_session_t *session, dc_user_t *user, knl_table_desc_t *desc,
    dc_entity_t *entity)
{
    if (spc_valid_space_object(session, desc->space_id)) {
        if (!IS_INVALID_PAGID(desc->entry)) {
            if (buf_read_page(session, desc->entry, LATCH_MODE_S,
                ENTER_PAGE_RESIDENT) != CT_SUCCESS) {
                entity->corrupted = CT_TRUE;
                CT_LOG_RUN_ERR("[DC CORRUPTED] could not load table %s.%s, segment corrupted.",
                    user->desc.name, desc->name);
                cm_reset_error();
            } else {
                page_head_t *head = (page_head_t *)CURR_PAGE(session);
                entity->table.heap.segment = HEAP_SEG_HEAD(session);
                if (head->type == PAGE_TYPE_HEAP_HEAD && entity->table.heap.segment->org_scn == desc->org_scn) {
                    uint8 cipher_reserve_size = SPACE_GET(session, desc->space_id)->ctrl->cipher_reserve_size;
                    entity->table.heap.cipher_reserve_size = cipher_reserve_size;
                    desc->seg_scn = entity->table.heap.segment->seg_scn;
                    knl_panic_log(desc->cr_mode == (entity->table.heap.segment)->cr_mode, "cr_mode of table and "
                                  "table heap's segment are not same, panic info: table %s", entity->table.desc.name);
                } else {
                    entity->corrupted = CT_TRUE;
                    CT_LOG_RUN_ERR("[DC CORRUPTED] could not load table %s.%s, segment corrupted.",
                        user->desc.name, desc->name);
                }
                buf_leave_page(session, CT_FALSE);
            }
        }
    } else {
        entity->corrupted = CT_TRUE;
        CT_LOG_RUN_ERR("[DC CORRUPTED] could not load table %s.%s, tablespace %s is offline.",
            user->desc.name, desc->name, SPACE_GET(session, desc->space_id)->ctrl->name);
    }
}

status_t dc_get_table_storage_desc(knl_session_t *session, dc_entity_t* entity)
{
    knl_table_desc_t *desc = &entity->table.desc;

    if (!desc->storaged) {
        return CT_SUCCESS;
    }

    if (db_get_storage_desc(session, &entity->table.desc.storage_desc, desc->org_scn) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t dc_load_table(knl_session_t *session, knl_cursor_t *cursor, dc_user_t *user, uint32 oid,
                       dc_entity_t *entity)
{
    knl_table_desc_t *desc = NULL;
    dc_entry_t *entry = NULL;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLE_ID, IX_SYS_TABLE_002_ID);

    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&user->desc.id,
        sizeof(uint32), IX_COL_SYS_TABLE_002_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&oid,
        sizeof(uint32), IX_COL_SYS_TABLE_002_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cursor->eof) {
        entry = DC_GET_ENTRY(user, oid);
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, user->desc.name, entry->name);
        return CT_ERROR;
    }

    desc = &entity->table.desc;
    dc_convert_table_desc(cursor, desc);
    dc_set_table_accessor(&entity->table);
    dls_init_spinlock(&entity->table.heap.lock, DR_TYPE_HEAP, desc->id, (uint16)desc->uid);
    dls_init_latch(&entity->table.heap.latch, DR_TYPE_HEAP_LATCH, desc->id, (uint16)desc->uid);

    if (dc_init_entity_entry(session, user, desc, entity) != CT_SUCCESS) {
        return CT_ERROR;
    }

    entity->table.heap.entry = desc->entry;
    entity->table.heap.table = &entity->table;

    if (dc_get_table_storage_desc(session, entity) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    if (desc->compress) {
        if (db_get_compress_algo(session, &desc->compress_algo, desc->org_scn) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    entity->table.heap.max_pages = entity->table.desc.storage_desc.max_pages;
    
    if (desc->type == TABLE_TYPE_EXTERNAL) {
        return dc_load_external_table(session, cursor, entity);
    }

    dc_load_table_heap_segment(session, user, desc, entity);

    if (!dc_is_reserved_entry(user->desc.id, oid)) {
        if (stats_seg_load_entity(session, desc->org_scn, &entity->table.heap.stat) != CT_SUCCESS) {
            CT_LOG_RUN_INF("segment statistic failed, there might be some statitics loss.");
        }
    }

    if (desc->parted) {
        if (dc_load_part_table(session, cursor, entity) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t dc_load_logical_log_part(dc_entity_t *entity, text_t *part_name)
{
    uint32 part_no = CT_INVALID_ID32;
    uint32 subpart_no = CT_INVALID_ID32;

    if (knl_find_table_part_by_name(entity, part_name, &part_no) != CT_SUCCESS) {
        cm_reset_error();
        if (knl_find_subpart_by_name(entity, part_name, &part_no, &subpart_no) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    table_t *table = &entity->table;
    table_part_t *table_part = TABLE_GET_PART(table, part_no);
    if (subpart_no != CT_INVALID_ID32) {
        table_part = PART_GET_SUBENTITY(table->part_table, table_part->subparts[subpart_no]);
    }

    if (IS_PARENT_TABPART(&table_part->desc)) {
        table_part_t *subpart = NULL;
        for (uint32 i = 0; i < table_part->desc.subpart_cnt; i++) {
            subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[i]);
            if (subpart == NULL) {
                continue;
            }

            if (subpart->desc.lrep_status != PART_LOGICREP_STATUS_ON) {
                subpart->desc.lrep_status = PART_LOGICREP_STATUS_ON;
                entity->lrep_info.parts_count++;
            }
        }
    } else {
        if (table_part->desc.lrep_status != PART_LOGICREP_STATUS_ON) {
            table_part->desc.lrep_status = PART_LOGICREP_STATUS_ON;
            entity->lrep_info.parts_count++;
        }
    }

    return CT_SUCCESS;
}

static status_t dc_load_logical_log_parts(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity)
{
    errno_t err;
    text_t text;
    char *next_token = NULL;
    lob_locator_t *src_lob = NULL;

    entity->lrep_info.parts_count = 0;
    if (entity->table.desc.parted == 0 ||
        CURSOR_COLUMN_SIZE(cursor, SYS_LOGIC_REP_COLUMN_ID_PARTITIONIDS) == CT_NULL_VALUE_LEN) {
        return CT_SUCCESS;
    }
    src_lob = (lob_locator_t *)CURSOR_COLUMN_DATA(cursor, SYS_LOGIC_REP_COLUMN_ID_PARTITIONIDS);
    text.len = knl_lob_size(src_lob);
    if (text.len == 0) {
        return CT_SUCCESS;
    }

    text.str = (char *)cm_push(session->stack, text.len + 1);
    if (text.str == NULL) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        return CT_ERROR;
    }
    next_token = text.str;
    err = memset_sp(text.str + text.len, sizeof(char), '\0', sizeof(char));
    knl_securec_check(err);

    if (knl_read_lob(session, src_lob, 0, text.str, text.len, NULL, NULL) != CT_SUCCESS) {
        cm_pop(session->stack);
        return CT_ERROR;
    }
    
    for (;;) {
        text.str = strtok_s(next_token, ",", &next_token);
        if (text.str == NULL) {
            break;
        }
        text.len = (uint32)strlen(text.str);
        if (dc_load_logical_log_part(entity, &text) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    
    cm_pop(session->stack);
    return CT_SUCCESS;
}

static status_t dc_load_logical_log_info(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
    uint32 uid, uint32 oid)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_LOGIC_REP_ID, IX_SYS_LOGICREP_001_ID);

    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &uid, sizeof(uint32),
        IX_COL_SYS_LOGICREP_001_USERID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &oid, sizeof(uint32),
        IX_COL_SYS_LOGICREP_001_TABLEID);

    if (CT_SUCCESS != knl_fetch(session, cursor)) {
        return CT_ERROR;
    }

    if (cursor->eof) {
        entity->lrep_info.status = LOGICREP_STATUS_OFF;
        entity->lrep_info.parts_count = 0;
    } else {
        entity->lrep_info.status = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOGIC_REP_COLUMN_ID_STATUS);
        entity->lrep_info.index_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOGIC_REP_COLUMN_ID_INDEXID);

        uint32 idx_count = entity->table.index_set.count;
        bool32 found = CT_FALSE;
        for (uint32 i = 0; i < idx_count; i++) {
            if (entity->table.index_set.items[i]->desc.id == entity->lrep_info.index_id) {
                entity->lrep_info.index_slot_id = entity->table.index_set.items[i]->desc.slot;
                found = CT_TRUE;
                break;
            }
        }
        if (!found) {
            CT_THROW_ERROR(ERR_INVALID_LOGICAL_INDEX);
            return CT_ERROR;
        }
        if (dc_load_logical_log_parts(session, cursor, entity) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t dc_clean_garbage_segment(knl_session_t *session, dc_entity_t *entity)
{
    if (DB_IS_BG_ROLLBACK_SE(session) || DB_IS_READONLY(session)) {
        return CT_SUCCESS;
    }

    if (IS_SYS_TABLE(&entity->table) || entity->entry->type != DICT_TYPE_TABLE) {
        return CT_SUCCESS;
    }

    if (knl_begin_auton_rm(session) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to begin auton transaction to clean garbage segment");
        return CT_ERROR;
    }

    if (db_garbage_segment_handle(session, entity->table.desc.uid, entity->table.desc.id, CT_FALSE) != CT_SUCCESS) {
        knl_end_auton_rm(session, CT_ERROR);
        CT_LOG_RUN_ERR("Failed to clean garbage segment");
        return CT_ERROR;
    }

    knl_end_auton_rm(session, CT_SUCCESS);
    return CT_SUCCESS;
}

status_t dc_reset_nologging_shadow_index(knl_session_t *session, dc_entity_t *entity)
{
    knl_index_desc_t desc;
    knl_index_part_desc_t part_desc;
    object_type_t obj_type;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    if (db_fetch_shadow_index_row(session, entity, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (!cursor->eof) {
        dc_convert_index(session, cursor, &desc);
        if (dc_reset_nologging_entry(session, &desc, OBJ_TYPE_SHADOW_INDEX) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    if (db_fetch_shadow_indexpart_row(session, entity, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        dc_convert_index_part_desc(cursor, &part_desc);
        /* for sys_shadow_index_part, the subpartcnt column is SYS_SHADOW_INDEXPART_COL_SUBPART_CNT */
        part_desc.subpart_cnt = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_SUBPART_CNT);
        obj_type = IS_SUB_IDXPART(&part_desc) ? OBJ_TYPE_SHADOW_INDEX_SUBPART : OBJ_TYPE_SHADOW_INDEX_PART;
        if (dc_reset_nologging_entry(session, &part_desc, obj_type) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t dc_load_table_entity(knl_session_t *session, dc_user_t *user, uint32 oid, dc_entity_t *entity)
{
    knl_cursor_t *cursor = NULL;
    stats_load_info_t load_info;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    if (dc_load_table(session, cursor, user, oid, entity) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (dc_load_columns(session, cursor, entity) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

#ifdef Z_SHARDING
    if (dc_convert_table_distribute_strategy(session, cursor, entity) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
#endif

    if (entity->table.desc.index_count > 0) {
        if (dc_load_indexes(session, cursor, entity) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    if (entity->contain_lob) {
        if (dc_load_lobs(session, cursor, entity) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    if (dc_load_cons(session, cursor, entity) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (!IS_SYS_TABLE(&entity->table) && entity->entry->type == DICT_TYPE_TABLE) {
        if (dc_load_policies(session, cursor, user, oid, entity) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }
    stats_set_load_info(&load_info, entity, CT_TRUE, CT_INVALID_ID32);
    // load table statistics information
    if (cbo_load_entity_statistics(session, entity, load_info) != CT_SUCCESS) {
        dc_entry_t *entry = DC_GET_ENTRY(user, oid);
        CT_LOG_RUN_INF("[DC] could not load table statistics %s.%s.",
            user->desc.name, entry->name);
    }

    // Only non-system tables support logical log
    if (user->desc.id != DB_SYS_USER_ID) {
        if (dc_load_logical_log_info(session, cursor, entity, user->desc.id, oid) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }
    if (!IS_SYS_TABLE(&entity->table) && entity->entry->type == DICT_TYPE_TABLE) {
        if (dc_load_ddm(session, cursor, entity) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    if (IS_NOLOGGING_BY_TABLE_TYPE(entity->table.desc.type) && entity->entry->need_empty_entry) {
        if (dc_reset_nologging_shadow_index(session, entity) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (dc_reset_nologging_entry(session, &entity->table.desc, OBJ_TYPE_GARBAGE_SEGMENT) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    // add trigger in entity
    if (!IS_SYS_TABLE(&entity->table) && entity->table.desc.has_trig) {
        if (dc_load_trigger_by_table_id(session, user->desc.id, (uint64)oid, &entity->trig_set) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }
    
    if (dc_clean_garbage_segment(session, entity) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    /* when db is readonly, dc_reset_nologging_entry do nothing, so the flag can not clear */
    if (!DB_IS_READONLY(session)) {
        entity->entry->need_empty_entry = CT_FALSE;
    }

    if (entity->entry->need_empty_entry) {
        CT_THROW_ERROR(ERR_INVALID_DC, entity->entry->name);
        CT_LOG_RUN_ERR("nologging table %s.%s empty entry failed.", user->desc.name, entity->entry->name);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static inline void dc_set_knl_dictionary(knl_session_t *session, dc_user_t *user, dc_entry_t *entry,
    knl_dictionary_t *dc)
{
    dc_entity_t *entity = entry->entity;
    dc->chg_scn = entry->chg_scn;
    dc->handle = entity;
    dc->is_sysnonym = CT_FALSE;
    dc->kernel = session->kernel;
    dc->oid = entry->id;
    dc->org_scn = entry->org_scn;
    dc->type = entry->type;
    dc->uid = user->desc.id;

    knl_temp_cache_t *temp_cache = NULL;
    if (IS_TEMP_TABLE_BY_DC(dc)) {
        temp_cache = knl_get_temp_cache((knl_handle_t)session, entity->table.desc.uid, entity->table.desc.id);
    }
    bool32 stat_exists = (temp_cache == NULL) ? entry->entity->stat_exists : temp_cache->stat_exists;
    if (stat_exists) {
        dc->stats_version = (temp_cache == NULL) ? entity->stats_version : temp_cache->stats_version;
    } else {
        dc->stats_version = CT_INVALID_ID32;
    }
}

static status_t dc_open_table_entry_internal(knl_session_t *session, dc_user_t *user, dc_entry_t *entry,
    knl_dictionary_t *dc)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_entity_t *entity = NULL;

    if (dc_alloc_entity(ctx, entry) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dc_entry_inc_ref(entry);

    entity = entry->entity;
    knl_set_session_scn(session, CT_INVALID_ID64);
    if (dc_load_table_entity(session, user, entry->id, entity) != CT_SUCCESS) {
        dc_entry_dec_ref(entity);
        mctx_destroy(entity->memory);
        entry->entity = NULL;
        return CT_ERROR;
    }

    if (entry->appendix == NULL) {
        if (dc_alloc_appendix(session, entry) != CT_SUCCESS) {
            dc_entry_dec_ref(entity);
            mctx_destroy(entity->memory);
            entry->entity = NULL;
            return CT_ERROR;
        }

        if (dc_load_table_monitor(session, entity) != CT_SUCCESS) {
            dc_entry_dec_ref(entity);
            mctx_destroy(entity->memory);
            entry->entity = NULL;
            return CT_ERROR;
        }
    }

    if (entry->sch_lock == NULL) {
        if (dc_alloc_schema_lock(session, entry) != CT_SUCCESS) {
            dc_entry_dec_ref(entity);
            mctx_destroy(entity->memory);
            entry->entity = NULL;
            return CT_ERROR;
        }
    }

    entity->entry = entry;
    dc_set_knl_dictionary(session, user, entry, dc);
    dc_set_table_accessor(&entity->table);
    return CT_SUCCESS;
}

static status_t dc_open_table_entry(knl_session_t *session, dc_user_t *user, dc_entry_t *entry,
    knl_dictionary_t *dc)
{
    dc_wait_till_load_finish(session, entry);
    entry->is_loading = CT_TRUE;
    cm_spin_unlock(&entry->lock);

    dls_latch_s(session, &entry->ddl_latch, session->id, CT_FALSE, NULL);
    if (RC_REFORM_RECOVERY_IN_PROGRESS) {
        dls_unlatch(session, &entry->ddl_latch, NULL);
        cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
        knl_panic(entry->is_loading);
        entry->is_loading = CT_FALSE;
        CT_LOG_RUN_ERR("loading dc during reform");
        return CT_ERROR;
    }
    status_t ret = dc_open_table_entry_internal(session, user, entry, dc);
    dls_unlatch(session, &entry->ddl_latch, NULL);
 
    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    knl_panic(entry->is_loading);
    entry->is_loading = CT_FALSE;
    if (ret != CT_ERROR && entry->entity == NULL) {
        // loading conflict with dc invalidation from ddl redo in partial recovery
        CT_LOG_RUN_ERR("loading conflict, entity is null");
        ret = CT_ERROR;
    }
    return ret;
}

status_t dc_open_table_private(knl_session_t *session, uint32 uid, uint32 oid, knl_dictionary_t *dc)
{
    dc_entry_t *entry = NULL;
    dc_user_t *user = NULL;
    dc_entity_t *entity = NULL;
    text_t obj_name;
    text_t user_name;

    if (dc_open_user_by_id(session, uid, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    entry = DC_GET_ENTRY(user, oid);
    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    entity = entry->entity;

    if (IS_LTT_BY_ID(oid)) {
        cm_str2text(user->desc.name, &user_name);
        cm_str2text(entry->name, &obj_name);
        if (dc_open_ltt(session, user, &obj_name, dc)) {
            cm_spin_unlock(&entry->lock);
            return CT_SUCCESS;
        }
        cm_spin_unlock(&entry->lock);
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&user_name), T2S_EX(&obj_name));
        return CT_ERROR;
    }

    if (dc_open_table_entry(session, user, entry, dc) != CT_SUCCESS) {
        entry->entity = entity;
        cm_spin_unlock(&entry->lock);
        return CT_ERROR;
    }

    entry->entity = entity;
    cm_spin_unlock(&entry->lock);

    return CT_SUCCESS;
}

status_t dc_open_table_directly(knl_session_t *session, uint32 uid, uint32 oid, knl_dictionary_t *dc)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_entry_t *entry = NULL;
    dc_user_t *user = NULL;

    if (dc_open_user_by_id(session, uid, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    entry = DC_GET_ENTRY(user, oid);
    knl_panic(entry != NULL);
    cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
    dc_wait_till_load_finish(session, entry);

    if (entry->entity == NULL) {
        if (dc_open_table_entry(session, user, entry, dc) != CT_SUCCESS) {
            cm_spin_unlock(&entry->lock);
            return CT_ERROR;
        }
    } else {
        dc_set_knl_dictionary(session, user, entry, dc);
    }

    if (dc_into_lru_needed(entry, ctx)) {
        cm_spin_lock(&ctx->lru_queue->lock, NULL);
        if (dc_into_lru_needed(entry, ctx)) {
            dc_lru_add(ctx->lru_queue, entry->entity);
        }
        cm_spin_unlock(&ctx->lru_queue->lock);
    }

    cm_spin_lock(&entry->entity->ref_lock, NULL);
    entry->entity->ref_count++;
    cm_spin_unlock(&entry->entity->ref_lock);
    cm_spin_unlock(&entry->lock);
    return CT_SUCCESS;
}

status_t dc_load_view(knl_session_t *session, knl_cursor_t *cursor, dc_user_t *user, text_t *name,
                      dc_entity_t *entity)
{
    knl_view_t *view = NULL;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_VIEW_ID, IX_SYS_VIEW001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&user->desc.id,
        sizeof(uint32), IX_COL_SYS_VIEW001_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)name->str,
        name->len, IX_COL_SYS_VIEW001_NAME);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    view = &entity->view;

    if (cursor->eof) {
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, user->desc.name, T2S_EX(name));
        return CT_ERROR;
    }

    if (dc_convert_view_desc(session, cursor, view, entity) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_panic_log(view->uid == user->desc.id, "the uid of view and user are not same, panic info: page %u-%u type %u "
                  "table %s index %s view's uid %u user_id %u", cursor->rowid.file, cursor->rowid.page,
                  ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name,
                  ((table_t *)cursor->index)->desc.name, view->uid, user->desc.id);

    entity->entry->org_scn = view->org_scn;
    entity->entry->chg_scn = view->chg_scn;
    return CT_SUCCESS;
}

status_t dc_load_view_entity(knl_session_t *session, dc_user_t *user, uint32 oid, dc_entity_t *entity)
{
    knl_cursor_t *cursor = NULL;
    text_t name;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    cm_str2text(entity->entry->name, &name);

    if (dc_load_view(session, cursor, user, &name, entity) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (dc_load_columns(session, cursor, entity) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    // add trigger in entity
    if (dc_load_trigger_by_table_id(session, user->desc.id, (uint64)oid, &entity->trig_set) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

void dc_create_column_index(dc_entity_t *entity)
{
    uint32 i, hash;
    knl_column_t *column = NULL;

    for (i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        if (KNL_COLUMN_IS_DELETED(column)) {
            continue;
        }
        hash = cm_hash_column_name(column->name, strlen(column->name), entity->column_count, IS_COMPATIBLE_MYSQL_INST);
        column->next = DC_GET_COLUMN_INDEX(entity, hash);
        entity->column_groups[hash / DC_COLUMN_GROUP_SIZE].column_index[hash % DC_COLUMN_GROUP_SIZE] =
            (uint16)column->id;
    }
}

status_t dc_prepare_load_columns(knl_session_t *session, dc_entity_t *entity)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    uint16 i;
    uint16 group_count;
    uint16 group_size;
    errno_t ret;

    group_count = (entity->column_count + DC_COLUMN_GROUP_SIZE - 1) / DC_COLUMN_GROUP_SIZE;
    if (dc_alloc_mem(ctx, entity->memory, sizeof(dc_column_group_t) * group_count,
        (void **)&entity->column_groups) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ret = memset_sp(entity->column_groups, sizeof(dc_column_group_t) * group_count, 0,
        sizeof(dc_column_group_t) * group_count);
    knl_securec_check(ret);

    for (i = 0; i < group_count; i++) {
        group_size = (i == group_count - 1) ? (entity->column_count - i * DC_COLUMN_GROUP_SIZE) : DC_COLUMN_GROUP_SIZE;
        if (dc_alloc_mem(ctx, entity->memory, sizeof(pointer_t) * group_size,
            (void **)&entity->column_groups[i].columns) != CT_SUCCESS) {
            return CT_ERROR;
        }

        ret = memset_sp(entity->column_groups[i].columns, sizeof(pointer_t) * group_size, 0,
            sizeof(pointer_t) * group_size);
        knl_securec_check(ret);

        if (dc_alloc_mem(ctx, entity->memory, sizeof(uint16) * group_size,
            (void **)&entity->column_groups[i].column_index) != CT_SUCCESS) {
            return CT_ERROR;
        }

        ret = memset_sp(entity->column_groups[i].column_index, sizeof(uint16) * group_size, 0xFF,
            sizeof(uint16) * group_size);
        knl_securec_check(ret);
    }

    return CT_SUCCESS;
}

static status_t db_load_virtual_column(knl_session_t *session, dc_entity_t *entity, knl_column_t *column)
{
    uint32 col_pos;
    errno_t ret;
    uint32 size;

    knl_panic_log(column->id >= DC_VIRTUAL_COL_START, "column id is invalid, panic info: table %s column id %u",
                  entity->table.desc.name, column->id);

    col_pos = column->id - DC_VIRTUAL_COL_START;

    if (entity->virtual_columns == NULL) {
        size = sizeof(pointer_t) * (col_pos + 1);
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, size,
            (void **)&entity->virtual_columns) != CT_SUCCESS) {
            return CT_ERROR;
        }

        ret = memset_sp((void *)entity->virtual_columns, size, 0, size);
        knl_securec_check(ret);
        entity->max_virtual_cols = col_pos + 1;
    }

    entity->virtual_columns[col_pos] = column;
    return CT_SUCCESS;
}

void estimate_row_len(table_t *table, knl_column_t *column)
{
    switch (column->datatype) {
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            table->desc.estimate_len += column->size / 2; // take half of a column size as estimated length
            break;
        case CT_TYPE_CLOB:
        case CT_TYPE_BLOB:
        case CT_TYPE_IMAGE:
        case CT_TYPE_ARRAY:
            table->desc.estimate_len += sizeof(lob_locator_t);
            break;
        default:
            table->desc.estimate_len += column->size;
            break;
    }
}

static inline void dc_init_csf_dec_row_len(table_t *table, uint32 column_count)
{
    table->desc.csf_dec_rowlen = col_bitmap_size(column_count);
}

static void dc_estimate_csf_dec_row_len(table_t *table, knl_column_t *column)
{
    switch (column->datatype) {
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BOOLEAN:
        case CT_TYPE_UINT64:
        case CT_TYPE_BIGINT:
        case CT_TYPE_REAL:
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
        case CT_TYPE_DATE_MYSQL:
        case CT_TYPE_INTERVAL_DS:
        case CT_TYPE_INTERVAL_YM:
            break;
        default:
            table->desc.csf_dec_rowlen += CSF_LONG_COL_DESC_LEN;
            break;
    }
}

static status_t dc_load_column(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity, table_t *table,
    uint32 *col_id)
{
    knl_column_t *column = NULL;
    errno_t err;

    if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(knl_column_t),
        (void **)&column) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return CT_ERROR;
    }

    err = memset_sp(column, sizeof(knl_column_t), 0, sizeof(knl_column_t));
    knl_securec_check(err);

    if (dc_convert_column(session, cursor, entity, column) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (KNL_COLUMN_IS_VIRTUAL(column)) {
        if (db_load_virtual_column(session, entity, column) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (KNL_COLUMN_IS_DELETED(column)) {
            column->nullable = CT_TRUE;
        }
        entity->column_groups[column->id / DC_COLUMN_GROUP_SIZE].columns[column->id % DC_COLUMN_GROUP_SIZE] =
            column;
        *col_id += 1;

        if (knl_is_table_csf(entity, cursor->part_loc)) {
            dc_estimate_csf_dec_row_len(table, column);
        }
    }

    if (entity->type != DICT_TYPE_VIEW) {
        estimate_row_len(table, column);
    }

    if (COLUMN_IS_LOB(column)) {
        entity->contain_lob = CT_TRUE;
    }

    if (KNL_COLUMN_IS_UPDATE_DEFAULT(column)) {
        entity->has_udef_col = CT_TRUE;
    }

    if (KNL_COLUMN_IS_SERIAL(column) && !KNL_COLUMN_IS_DELETED(column)) {
        entity->has_serial_col = CT_TRUE;
    }

    return CT_SUCCESS;
}

static status_t dc_load_vcolumn_default_expr(knl_session_t *session, dc_entity_t *entity)
{
    knl_column_t *column = NULL;

    for (uint32 id = 0; id < entity->max_virtual_cols; ++id) {
        column = entity->virtual_columns[id];
        if (column == NULL || KNL_COLUMN_IS_DELETED(column)) {
            continue;
        }
        CM_ASSERT(column->default_text.len != 0);

        /* get default expr tree from defalut_text directly instead of default_data */
        if (g_knl_callback.parse_default_from_text((knl_handle_t)session,
            (knl_handle_t)entity, (knl_handle_t)column, entity->memory,
            &column->default_expr, &column->update_default_expr, column->default_text) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t dc_load_columns(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity)
{
    uint32 id, table_id;
    knl_scan_key_t *l_border = NULL;
    knl_scan_key_t *r_border = NULL;
    table_t *table = NULL;
    knl_view_t *view = NULL;
    uint32 uid, entry_id;

    // begin from column 0
    id = 0;

    if (entity->type == DICT_TYPE_VIEW) {
        view = &entity->view;
        table_id = SYS_VIEWCOL_ID;
        uid = entity->view.uid;
        entry_id = entity->view.id;
        entity->column_count = entity->view.column_count;
    } else {
        table = &entity->table;
        table_id = SYS_COLUMN_ID;
        uid = entity->table.desc.uid;
        entry_id = entity->table.desc.id;
        entity->column_count = table->desc.column_count;
    }
    if (dc_prepare_load_columns(session, entity) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, table_id, IX_SYS_COLUMN_001_ID);
    cursor->index_dsc = CT_TRUE;
    l_border = &cursor->scan_range.l_key;
    r_border = &cursor->scan_range.r_key;
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_border, CT_TYPE_INTEGER, (void *)&uid, sizeof(uint32),
        IX_COL_SYS_COLUMN_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_border, CT_TYPE_INTEGER, (void *)&entry_id, sizeof(uint32),
        IX_COL_SYS_COLUMN_001_TABLE_ID);
    knl_set_key_flag(l_border, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_COLUMN_001_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_border, CT_TYPE_INTEGER, (void *)&uid, sizeof(uint32),
        IX_COL_SYS_COLUMN_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_border, CT_TYPE_INTEGER, (void *)&entry_id, sizeof(uint32),
        IX_COL_SYS_COLUMN_001_TABLE_ID);
    knl_set_key_flag(r_border, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_COLUMN_001_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (entity->type != DICT_TYPE_VIEW) {
        table->desc.estimate_len = sizeof(row_head_t) + ((table->desc.cr_mode == CR_ROW) ?
            sizeof(row_dir_t) : sizeof(pcr_row_dir_t));
    }

    if (knl_is_table_csf(entity, cursor->part_loc)) {
        dc_init_csf_dec_row_len(table, table->desc.column_count);
    }

    while (!cursor->eof) {
        if (dc_load_column(session, cursor, entity, table, &id)) {
            return CT_ERROR;
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (id != entity->column_count) { // knl_panic(?)
        if (entity->type != DICT_TYPE_VIEW) {
            CT_THROW_ERROR(ERR_INVALID_DC, table->desc.name);
        } else {
            CT_THROW_ERROR(ERR_INVALID_DC, view->name);
        }

        return CT_ERROR;
    }

    dc_create_column_index(entity);
    // load vcolumn default expr after all columns loaded
    return dc_load_vcolumn_default_expr(session, entity);
}
status_t dc_load_ddm(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity)
{
    uint32 colid;
    void *update_default_expr = NULL;
    knl_scan_key_t *l_key = NULL;
    knl_scan_key_t *r_key = NULL;
    knl_column_t *column = NULL;
    text_t ddm_text;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_DDM_ID, IX_SYS_DDM_001_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    l_key = &cursor->scan_range.l_key;
    r_key = &cursor->scan_range.r_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, CT_TYPE_INTEGER, (void *)&entity->table.desc.uid,
        sizeof(uint32), IX_COL_SYS_DDM_001_UID);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, CT_TYPE_INTEGER, (void *)&entity->table.desc.id,
        sizeof(uint32), IX_COL_SYS_DDM_001_OID);
    knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_DDM_001_COLID);

    knl_set_scan_key(INDEX_DESC(cursor->index), r_key, CT_TYPE_INTEGER, (void *)&entity->table.desc.uid, sizeof(uint32),
        IX_COL_SYS_DDM_001_UID);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_key, CT_TYPE_INTEGER, (void *)&entity->table.desc.id, sizeof(uint32),
        IX_COL_SYS_DDM_001_OID);
    knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_DDM_001_COLID);
    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }
    while (!cursor->eof) {
        colid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_DDM_COLID);
        column = dc_get_column(entity, colid);
        if (KNL_COLUMN_IS_VIRTUAL(column)) {
            if (knl_fetch(session, cursor) != CT_SUCCESS) {
                return CT_ERROR;
            }
            continue;
        }
        ddm_text.str = CURSOR_COLUMN_DATA(cursor, SYS_DDM_PARAM);
        ddm_text.len = CURSOR_COLUMN_SIZE(cursor, SYS_DDM_PARAM);

        if (ddm_text.len != 0) {
            /* get ddm_expr tree from ddm_text */
            if (g_knl_callback.parse_default_from_text((knl_handle_t)session,
                (knl_handle_t)entity, (knl_handle_t)column, entity->memory,
                &column->ddm_expr, &update_default_expr, ddm_text) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}
static void dc_load_index_segment(knl_session_t *session, index_t *index, knl_index_desc_t *desc,
    dc_entity_t *entity)
{
    page_head_t *head = NULL;
    dc_user_t *user;
    knl_tree_info_t tree_info;
    btree_page_t *page = NULL;
    knl_scn_t recycle_ver_scn = 0;

    user = session->kernel->dc_ctx.users[entity->table.desc.uid];
    if (!spc_valid_space_object(session, desc->space_id)) {
        entity->corrupted = CT_TRUE;
        CT_LOG_RUN_ERR("[DC CORRUPTED] could not load index %s of table %s.%s, tablespace %s is offline.",
            index->desc.name, user->desc.name, entity->table.desc.name,
            SPACE_GET(session, desc->space_id)->ctrl->name);
        return;
    }

    if (!IS_INVALID_PAGID(desc->entry)) {
        if (buf_read_page(session, desc->entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT) != CT_SUCCESS) {
            entity->corrupted = CT_TRUE;
            CT_LOG_RUN_ERR("[DC CORRUPTED] could not load index %s of table %s.%s,segment corrupted.",
                index->desc.name, user->desc.name, entity->table.desc.name);
            cm_reset_error();
            return;
        }

        head = (page_head_t *)CURR_PAGE(session);
        index->btree.segment = BTREE_GET_SEGMENT(session);
        index->btree.buf_ctrl = session->curr_page_ctrl;
        if (head->type != PAGE_TYPE_BTREE_HEAD || index->btree.segment->org_scn != desc->org_scn) {
            buf_leave_page(session, CT_FALSE);
            entity->corrupted = CT_TRUE;
            CT_LOG_RUN_ERR("[DC CORRUPTED] could not load index %s of table %s.%s,segment corrupted.",
                index->desc.name, user->desc.name, entity->table.desc.name);
            return;
        }
        bt_put_change_stats(&index->btree);
        index->btree.cipher_reserve_size = SPACE_GET(session, desc->space_id)->ctrl->cipher_reserve_size;
        index->desc.seg_scn = index->btree.segment->seg_scn;
        knl_panic_log(index->desc.cr_mode == (index->btree.segment)->cr_mode,
                      "the cr_mode of index and btree's segment are not same, panic info: table %s index %s",
                      entity->table.desc.name, index->desc.name);

        tree_info.value = cm_atomic_get(&index->btree.segment->tree_info.value);
        recycle_ver_scn = KNL_GET_SCN(&index->btree.segment->recycle_ver_scn);
        buf_leave_page(session, CT_FALSE);

        if (tree_info.level > 1) {
            if (buf_read_page(session, AS_PAGID(tree_info.root), LATCH_MODE_S, ENTER_PAGE_NORMAL) != CT_SUCCESS) {
                entity->corrupted = CT_TRUE;
                CT_LOG_RUN_ERR("[DC CORRUPTED] could not load index %s of table %s.%s, root page corrupted.",
                    index->desc.name, user->desc.name, entity->table.desc.name);
                cm_reset_error();
                return;
            }

            page = BTREE_CURR_PAGE(session);
            if (page_soft_damaged(&page->head)) {
                buf_leave_page(session, CT_FALSE);
                CT_LOG_RUN_ERR("[DC CORRUPTED] could not load index %s of table %s.%s, root page soft corrupted.",
                    index->desc.name, user->desc.name, entity->table.desc.name);
                entity->corrupted = CT_TRUE;
                return;
            }

            if ((index->desc.cr_mode == CR_ROW && page->head.type != PAGE_TYPE_BTREE_NODE) ||
                (index->desc.cr_mode == CR_PAGE && page->head.type != PAGE_TYPE_PCRB_NODE) ||
                page->seg_scn != index->desc.seg_scn) {
                buf_leave_page(session, CT_FALSE);
                entity->corrupted = CT_TRUE;
                CT_LOG_RUN_ERR("[DC CORRUPTED] could not load index %s of table %s.%s, root page corrupted.",
                    index->desc.name, user->desc.name, entity->table.desc.name);
                return;
            }

            /*
            * Do not cache root page for standby
            * because there is no way for standby to refresh root page copy while replay
            * btree split. If standby promote to primary, expired root page copy will cause
            * wrong result of descend index scan.
            */
            if (DB_IS_PRIMARY(&session->kernel->db)) {
                btree_copy_root_page_base(session, &index->btree, BTREE_CURR_PAGE(session), recycle_ver_scn);
            }
            buf_leave_page(session, CT_FALSE);
        } else {
            index->btree.root_copy = NULL;
        }
    }

    if (!IS_SYS_TABLE(&entity->table)) {
        if (stats_seg_load_entity(session, desc->org_scn, &index->btree.stat) != CT_SUCCESS) {
            CT_LOG_RUN_INF("segment statistic failed, there might be some statitics loss.");
        }
    }
}

static status_t dc_convert_icol_desc(knl_session_t *session, dc_entity_t *entity, uint32 icol_pos,
    index_t *index)
{
    knl_icol_info_t *icol_info;
    knl_column_t *idx_column;
    knl_column_t *arg_column = NULL;
    uint32 col_id = 0;
    text_t vcol_name;
    text_t left;
    text_t right;
    errno_t ret;

    icol_info = (knl_icol_info_t *)(index->desc.columns_info + icol_pos);
    idx_column = dc_get_column(entity, index->desc.columns[icol_pos]);
    icol_info->datatype = idx_column->datatype;
    icol_info->size = idx_column->size;

    if (idx_column->id >= DC_VIRTUAL_COL_START) {
        cm_str2text(idx_column->name, &vcol_name);
        (void)cm_split_rtext(&vcol_name, '_', 0, &left, &right);
        (void)cm_text2int(&right, (int32 *)&col_id);

        knl_panic_log(col_id < entity->column_count, "current col_id is more than column_count, panic info: "
                      "table %s index %s col_id %u column_count %u", entity->table.desc.name, index->desc.name,
                      col_id, entity->column_count);
        /* function index only supports function with one argument */
        icol_info->arg_count = 1;

        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(uint16) * icol_info->arg_count,
            (void **)&icol_info->arg_cols) != CT_SUCCESS) {
            return CT_ERROR;
        }

        ret = memset_sp(icol_info->arg_cols, sizeof(uint16) * icol_info->arg_count, 0,
            sizeof(uint16) * icol_info->arg_count);
        knl_securec_check(ret);

        icol_info->arg_cols[0] = (uint16)col_id;

        arg_column = dc_get_column(entity, icol_info->arg_cols[0]);
        icol_info->is_func = CT_TRUE;
        icol_info->is_dsc = KNL_COLUMN_IS_DESCEND(arg_column);
    } else {
        icol_info->is_func = CT_FALSE;
        icol_info->is_dsc = KNL_COLUMN_IS_DESCEND(idx_column);
    }

    return CT_SUCCESS;
}

static void dc_cal_index_maxtrans(knl_session_t *session, dc_entity_t *entity, index_t *index)
{
    uint16 max_key_len;
    uint16 free_page_size;
    uint16 itl_size;
    uint8 cipher_reserve_size = index->btree.cipher_reserve_size;

    if (index->desc.type != INDEX_TYPE_BTREE) {
        index->desc.maxtrans = CT_MAX_TRANS;
        return;
    }

    max_key_len = btree_max_key_size(index);
    if (!session->kernel->attr.enable_idx_key_len_check) {
        max_key_len = MIN(max_key_len, index->desc.max_key_size);
    }

    itl_size = (index->desc.cr_mode == CR_ROW) ? sizeof(itl_t) : sizeof(pcr_itl_t);
    free_page_size = (uint16)(session->kernel->attr.page_size - sizeof(btree_page_t) -
        cipher_reserve_size - sizeof(page_tail_t));
    index->desc.maxtrans = MIN(CT_MAX_TRANS, (free_page_size - max_key_len) / itl_size);
    index->desc.initrans = MIN(index->desc.initrans, (uint32)((free_page_size - max_key_len) / itl_size));
    knl_panic_log(index->desc.maxtrans > 0, "the maxtrans of index is abnormal, panic info: "
                  "table %s index %s maxtrans %u", entity->table.desc.name, index->desc.name, index->desc.maxtrans);
}

static status_t dc_load_index_columns(knl_session_t *session, dc_entity_t *entity, index_t *index)
{
    uint32 i;
    errno_t ret;
    uint32 alloc_size = sizeof(knl_icol_info_t) * index->desc.column_count;

    if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, alloc_size,
        (void **)&index->desc.columns_info) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ret = memset_sp(index->desc.columns_info, alloc_size, 0, alloc_size);
    knl_securec_check(ret);

    for (i = 0; i < index->desc.column_count; i++) {
        if (dc_convert_icol_desc(session, entity, i, index) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static void inline dc_load_idx_empty_stats(knl_session_t *session, knl_cursor_t *cursor, index_t *idx)
{
    if (CURSOR_COLUMN_SIZE(cursor, SYS_INDEX_COLUMN_ID_EMPTY_LEAF_BLOCKS) == CT_NULL_VALUE_LEN) {
        return;
    }

    uint32 empty_size = *(uint32*)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_EMPTY_LEAF_BLOCKS);
    idx->btree.chg_stats.empty_size = MAX(idx->btree.chg_stats.empty_size,
                                            (uint64)empty_size * DEFAULT_PAGE_SIZE(session));
    idx->btree.chg_stats.first_empty_size = 0;
}

static status_t dc_load_index(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity, table_t *table,
    uint32 *id, uint32 *valid_count)
{
    index_t *index = NULL;
    knl_index_desc_t desc;
    errno_t err;

    dc_convert_index(session, cursor, &desc);
    /* empty index entry when nologging table is first loaded(db restart) */
    if (IS_NOLOGGING_BY_TABLE_TYPE(entity->table.desc.type) && entity->entry->need_empty_entry) {
        desc.entry = INVALID_PAGID;
        if (dc_reset_nologging_entry(session, (knl_handle_t)&desc, OBJ_TYPE_INDEX) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(index_t), (void **)&index) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return CT_ERROR;
    }
    err = memset_sp((void *)index, sizeof(index_t), 0, sizeof(index_t));
    knl_securec_check(err);

    if (desc.is_invalid) {
        table->index_set.items[--(*valid_count)] = index;
        desc.slot = *valid_count;
    } else {
        table->index_set.items[*id] = index;
        desc.slot = (*id)++;
    }

    err = memcpy_sp(&index->desc, sizeof(knl_index_desc_t), &desc, sizeof(knl_index_desc_t));
    knl_securec_check(err);

    dc_set_index_profile(session, entity, index);
    dc_set_index_accessor(table, index);

    index->btree.entry = desc.entry;
    index->btree.index = index;
    index->btree.is_shadow = CT_FALSE;
    index->entity = entity;

    dls_init_latch2(&index->btree.struct_latch, DR_TYPE_BTREE_LATCH, desc.table_id, desc.uid, desc.id, CT_INVALID_ID32,
                    CT_INVALID_ID32, index->btree.is_shadow);
    if (index->desc.is_func) {
        if (dc_load_index_columns(session, entity, index) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    dc_cal_index_maxtrans(session, entity, index);
    dc_load_index_segment(session, index, &desc, entity);

    if (!IS_SYS_TABLE(table)) {
        if (stats_seg_load_entity(session, desc.org_scn, &index->btree.stat) != CT_SUCCESS) {
            CT_LOG_RUN_INF("segment statistic failed, there might be some statitics loss.");
        }
    }

    if (index->desc.parted) {
        if (dc_load_part_index(session, index) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    dc_load_idx_empty_stats(session, cursor, index);

    return CT_SUCCESS;
}

void dc_put_stats_index_assist(index_t *idx, index_part_t *idx_part, stats_idx_assist_t *idx_assist, bool32 is_part)
{
    if (!is_part) {
        idx_assist->entry = idx->desc.entry;
        idx_assist->org_scn = idx->desc.org_scn;
        idx_assist->space_id = idx->desc.space_id;
        idx_assist->seg_stats = &idx->btree.chg_stats;
        return;
    }

    idx_assist->entry = idx_part->desc.entry;
    idx_assist->org_scn = idx_part->desc.org_scn;
    idx_assist->space_id = idx_part->desc.space_id;
    idx_assist->seg_stats = &idx_part->btree.chg_stats;
}

void dc_calc_index_empty_size(knl_session_t *session, dc_entity_t *entity, uint32 slot, knl_part_locate_t part_loc,
    uint32 empty_leaf_blocks)
{
    index_t *index = entity->table.index_set.items[slot];
    btree_segment_t *seg = NULL;
    stats_idx_assist_t idx_assist = { 0 };
    uint32 part_no = part_loc.part_no;
    uint32 subpart_no = part_loc.subpart_no;

    if (IS_PART_INDEX(index)) {
        knl_panic(part_no != CT_INVALID_ID32);
        index_part_t *index_part = INDEX_GET_PART(index, part_no);
        if (IS_PARENT_IDXPART(&index_part->desc) && subpart_no != CT_INVALID_ID32) {
            index_part_t *sub_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[subpart_no]);
            dc_put_stats_index_assist(index, sub_part, &idx_assist, CT_TRUE);
        } else {
            dc_put_stats_index_assist(index, index_part, &idx_assist, CT_TRUE);
        }
    } else {
        dc_put_stats_index_assist(index, NULL, &idx_assist, CT_FALSE);
    }

    if (!spc_valid_space_object(session, idx_assist.space_id)) {
        return;
    }

    if (!IS_INVALID_PAGID(idx_assist.entry)) {
        buf_enter_page(session, idx_assist.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
        page_head_t *head = (page_head_t *)CURR_PAGE(session);
        seg = BTREE_GET_SEGMENT(session);
        if (head->type != PAGE_TYPE_BTREE_HEAD || seg->org_scn != idx_assist.org_scn) {
            buf_leave_page(session, CT_FALSE);
            return;
        }

        idx_assist.seg_stats->first_empty_size = 0;
        space_t *space = SPACE_GET(session, seg->space_id);
        uint32 seg_pages_cnt = btree_get_segment_page_count(space, seg);
        uint32 recycled_cnt = seg->del_pages.count + seg->recycled_pages.count;
        // just coalesced once
        if (recycled_cnt > INDEX_NEED_RECY_RATIO(session) * seg_pages_cnt) {
            idx_assist.seg_stats->empty_size = 0;
            buf_leave_page(session, CT_FALSE);
            return;
        }

        uint64 empty_size = session->kernel->attr.page_size * empty_leaf_blocks;
        idx_assist.seg_stats->empty_size = MAX(idx_assist.seg_stats->empty_size, empty_size);
        buf_leave_page(session, CT_FALSE);
    }
    
    if (seg == NULL) {
        idx_assist.seg_stats->empty_size = 0;
        idx_assist.seg_stats->first_empty_size = 0;
        return;
    }
}

status_t dc_load_indexes(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity)
{
    table_t *table = &entity->table;
    uint32 id = 0;

    table->index_set.total_count = table->desc.index_count;
    if (table->index_set.total_count == 0) {
        return CT_SUCCESS;
    }

    uint32 valid_count = table->index_set.total_count;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_INDEX_ID, IX_SYS_INDEX_001_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (char *)&table->desc.uid,
        sizeof(uint32), IX_COL_SYS_INDEX_001_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (char *)&table->desc.id,
        sizeof(uint32), IX_COL_SYS_INDEX_001_TABLE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_INDEX_001_ID);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (char *)&table->desc.uid,
        sizeof(uint32), IX_COL_SYS_INDEX_001_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (char *)&table->desc.id,
        sizeof(uint32), IX_COL_SYS_INDEX_001_TABLE);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEX_001_ID);

    for (;;) {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        if (dc_load_index(session, cursor, entity, table, &id, &valid_count) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (id != valid_count) {
        CT_THROW_ERROR(ERR_INVALID_DC, table->desc.name);
        return CT_ERROR;
    }

    table->index_set.count = id;

    return CT_SUCCESS;
}

status_t dc_load_shadow_index(knl_session_t *session, knl_dictionary_t *dc)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    knl_cursor_t *cursor = NULL;
    space_t *space = NULL;
    index_t *index = NULL;
    index_t *old_index = NULL;
    errno_t err;

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    if (db_fetch_shadow_index_row(session, entity, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    cm_latch_x(&entity->cbo_latch, 0, NULL);
    if (cursor->eof) {
        if (dc_load_shadow_index_part(session, cursor, entity) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            cm_unlatch(&entity->cbo_latch, NULL);
            return CT_ERROR;
        }

        CM_RESTORE_STACK(session->stack);
        cm_unlatch(&entity->cbo_latch, NULL);
        return CT_SUCCESS;
    }

    if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(shadow_index_t),
        (void **)&entity->table.shadow_index) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        cm_unlatch(&entity->cbo_latch, NULL);
        return CT_ERROR;
    }

    entity->table.shadow_index->part_loc.part_no = CT_INVALID_ID32;
    entity->table.shadow_index->part_loc.subpart_no = CT_INVALID_ID32;
    entity->table.shadow_index->is_valid = CT_TRUE;
    index = &entity->table.shadow_index->index;
    err = memset_sp(index, sizeof(index_t), 0, sizeof(index_t));
    knl_securec_check(err);
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);
    dc_convert_index(session, cursor, &index->desc);
    index->entity = entity;
    index->btree.entry = index->desc.entry;
    index->btree.index = index;
    index->btree.is_shadow = CT_TRUE;
    dc_set_index_profile(session, entity, index);
    dc_set_index_accessor(&entity->table, index);
    dls_init_latch2(&index->btree.struct_latch, DR_TYPE_BTREE_LATCH, index->desc.table_id, index->desc.uid,
                    index->desc.id, CT_INVALID_ID32, CT_INVALID_ID32, index->btree.is_shadow);

    space = SPACE_GET(session, index->desc.space_id);
    if (!SPACE_IS_ONLINE(space)) {
        entity->corrupted = CT_TRUE;
        CT_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "load shadow index failed");
        CT_LOG_RUN_ERR("[DC CORRUPTED] index %s invalid, tablespace %s is offline",
            index->desc.name, space->ctrl->name);
        CM_RESTORE_STACK(session->stack);
        cm_unlatch(&entity->cbo_latch, NULL);
        return CT_ERROR;
    }

    if (!IS_INVALID_PAGID(index->desc.entry)) {
        if (buf_read_page(session, index->desc.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DC CORRUPTED] could not load shadow index %s of table %s, segment corrupted.",
                index->desc.name, entity->table.desc.name);
            CM_RESTORE_STACK(session->stack);
            cm_unlatch(&entity->cbo_latch, NULL);
            return CT_ERROR;
        }
        index->btree.segment = BTREE_GET_SEGMENT(session);
        index->btree.buf_ctrl = session->curr_page_ctrl;
        bt_put_change_stats(&index->btree);
        buf_leave_page(session, CT_FALSE);
    }

    if (index->desc.is_func) {
        if (dc_load_index_columns(session, entity, index) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            cm_unlatch(&entity->cbo_latch, NULL);
            return CT_ERROR;
        }
    }

    if (IS_PART_INDEX(index)) {
        if (dc_load_shadow_indexparts(session, cursor, index) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            cm_unlatch(&entity->cbo_latch, NULL);
            return CT_ERROR;
        }
    }

    old_index = dc_find_index_by_id(entity, index->desc.id);
    if (old_index != NULL) {
        index->desc.primary = old_index->desc.primary;
        index->desc.unique = old_index->desc.unique;
    }

    CM_RESTORE_STACK(session->stack);
    cm_unlatch(&entity->cbo_latch, NULL);
    return CT_SUCCESS;
}

void dc_convert_lob_desc(knl_cursor_t *cursor, knl_lob_desc_t *desc)
{
    desc->uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOB_COL_USER_ID);
    desc->table_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOB_COL_TABLE_ID);
    desc->column_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOB_COL_COLUMN_ID);
    desc->space_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOB_COL_SPACE_ID);
    desc->entry = *(page_id_t *)CURSOR_COLUMN_DATA(cursor, SYS_LOB_COL_ENTRY);
    desc->org_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_LOB_COL_ORG_SCN);
    desc->chg_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_LOB_COL_CHG_SCN);
    desc->chunk = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOB_COL_CHUNK);
    desc->pctversion = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOB_COL_PCTVERSION);
    desc->retention = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOB_COL_RETENSION);
    desc->flags = *(bool32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOB_COL_FLAGS);
    desc->seg_scn = desc->org_scn;
}

static void dc_load_lob_segment(knl_session_t *session, lob_t *lob, dc_entity_t *entity)
{
    page_head_t *head = NULL;
    dc_user_t *user = NULL;
    table_t *table;

    table = &entity->table;
    user = session->kernel->dc_ctx.users[table->desc.uid];

    if (!spc_valid_space_object(session, lob->desc.space_id)) {
        entity->corrupted = CT_TRUE;
        CT_LOG_RUN_ERR("[DC CORRUPTED] could not load lob of column %s of table %s.%s, tablespace %s is offline.",
            dc_get_column(entity, lob->desc.column_id)->name, user->desc.name, table->desc.name,
            SPACE_GET(session, lob->desc.space_id)->ctrl->name);
        return;
    }

    if (IS_INVALID_PAGID(lob->lob_entity.entry)) {
        return;
    }

    if (buf_read_page(session, lob->lob_entity.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT) != CT_SUCCESS) {
        entity->corrupted = CT_TRUE;
        CT_LOG_RUN_ERR("[DC CORRUPTED] could not load lob of column %s of table %s.%s, tablespace %s is offline.",
            dc_get_column(entity, lob->desc.column_id)->name, user->desc.name, table->desc.name,
            SPACE_GET(session, lob->desc.space_id)->ctrl->name);
        cm_reset_error();
        return;
    }

    head = (page_head_t *)CURR_PAGE(session);
    lob->lob_entity.segment = LOB_SEG_HEAD(session);
    if (head->type == PAGE_TYPE_LOB_HEAD && lob->lob_entity.segment->org_scn == lob->desc.org_scn) {
        lob->lob_entity.cipher_reserve_size = SPACE_GET(session, lob->desc.space_id)->ctrl->cipher_reserve_size;
        lob->desc.seg_scn = lob->lob_entity.segment->seg_scn;
    } else {
        entity->corrupted = CT_TRUE;
        CT_LOG_RUN_ERR("[DC CORRUPTED] could not load lob of column %s of table %s.%s, segment corrupted.",
            dc_get_column(entity, lob->desc.column_id)->name, user->desc.name, table->desc.name);
    }
    buf_leave_page(session, CT_FALSE);
}

status_t dc_load_lobs(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity)
{
    uint32 i;
    lob_t *lob = NULL;
    table_t *table = NULL;
    knl_scan_key_t *l_border = NULL;
    knl_column_t *column = NULL;
    errno_t err;

    if (!entity->contain_lob) {
        return CT_SUCCESS;
    }

    table = &entity->table;

    for (i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column) && !KNL_COLUMN_IS_ARRAY(column)) {
            continue;
        }

        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_LOB_ID, IX_SYS_LOB001_ID);

        l_border = &cursor->scan_range.l_key;
        knl_init_index_scan(cursor, CT_TRUE);
        knl_set_scan_key(INDEX_DESC(cursor->index), l_border, CT_TYPE_INTEGER, &table->desc.uid, sizeof(uint32),
            IX_COL_SYS_LOB001_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), l_border, CT_TYPE_INTEGER, &table->desc.id, sizeof(uint32),
            IX_COL_SYS_LOB001_TABLE_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), l_border, CT_TYPE_INTEGER, &i, sizeof(uint32),
            IX_COL_SYS_LOB001_COLUMN_ID);

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cursor->eof) {
            CT_THROW_ERROR(ERR_TABLE_ID_NOT_EXIST, table->desc.uid, table->desc.id);
            return CT_ERROR;
        }

        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(lob_t), (void **)&lob) != CT_SUCCESS) {
            return CT_ERROR;
        }
        err = memset_sp(lob, sizeof(lob_t), 0, sizeof(lob_t));
        knl_securec_check(err);

        dc_convert_lob_desc(cursor, &lob->desc);

        /* empty table entry when nologging table is first loaded(db restart) */
        if (IS_NOLOGGING_BY_TABLE_TYPE(table->desc.type) && entity->entry->need_empty_entry) {
            lob->desc.entry = INVALID_PAGID;
            if (dc_reset_nologging_entry(session, (knl_handle_t)&lob->desc, OBJ_TYPE_LOB) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
        lob->lob_entity.entry = lob->desc.entry;
        lob->lob_entity.lob = lob;
        dls_init_latch2(&lob->lob_entity.seg_latch, DR_TYPE_LOB_LATCH, lob->desc.table_id, lob->desc.uid,
                        lob->desc.column_id, CT_INVALID_ID32, CT_INVALID_ID32, 0);

        dc_load_lob_segment(session, lob, entity);

        column->lob = (knl_handle_t)lob;

        if (IS_PART_TABLE(table)) {
            if (dc_alloc_part_lob(session, entity, lob) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (dc_load_lob_parts(session, cursor, entity, lob) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

static status_t dc_load_cons_index(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity, uint32 type,
    uint32 index_id)
{
    index_t *index = NULL;
    text_t col_list;
    uint32 col_count;
    uint16 *col_ids = NULL;
    uint32 i;
    bool32 found = CT_FALSE;
    table_t *table = NULL;

    if (index_id != CT_INVALID_ID32) {
        index = dc_find_index_by_id(entity, index_id);
        knl_panic_log(index != NULL, "index is NULL, panic info: page %u-%u type %u table %s index %s",
                      cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                      ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);
    } else {
        index = NULL;
        col_count = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_CONSDEF_COL_COLS);
        col_list.len = CURSOR_COLUMN_SIZE(cursor, SYS_CONSDEF_COL_COL_LIST);
        col_list.str = CURSOR_COLUMN_DATA(cursor, SYS_CONSDEF_COL_COL_LIST);

        col_ids = (uint16 *)cm_push(session->stack, col_count * sizeof(uint16));

        dc_convert_column_list(col_count, &col_list, col_ids);
        table = &entity->table;
        for (i = 0; i < table->index_set.total_count; i++) {
            index = table->index_set.items[i];

            if (index->desc.is_func) {
                if (DB_ATTR_COMPATIBLE_MYSQL(session)) { /* ignore check function index for constraints. */
                    found = CT_TRUE;
                    break;
                }
                continue;
            }

            if (db_index_columns_matched(session, &index->desc, entity, NULL, col_count, col_ids)) {
                found = CT_TRUE;
                break;
            }
        }
        knl_panic_log(found, "index columns match failed, panic info: page %u-%u type %u table %s index %s",
                      cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                      table->desc.name, index->desc.name);
        cm_pop(session->stack);
    }

    knl_panic_log(index != NULL, "index is NULL, panic info: page %u-%u type %u table %s index %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name,
                  ((index_t *)cursor->index)->desc.name);
    if (type == CONS_TYPE_PRIMARY) {
        index->desc.primary = CT_TRUE;
    } else {
        index->desc.unique = CT_TRUE;
    }

    index->desc.is_enforced = CT_TRUE;

    return CT_SUCCESS;
}

static status_t dc_convert_consdef_not_reference(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
    constraint_type_t type, void *cons)
{
    text_t col_list;
    uint32 size_req;
    knl_constraint_state_t cons_state;

    cons_state.option = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_FLAGS);
    if (!cons_state.is_enable && cons_state.is_validate) {
        entity->forbid_dml = CT_TRUE;
    }
    
    check_cons_t *check = (check_cons_t *)cons;
    check->col_count = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_COLUMN_COUNT);
    col_list.len = CURSOR_COLUMN_SIZE(cursor, CONSDEF_COL_COLUMN_LIST);
    col_list.str = CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_COLUMN_LIST);
    size_req = CM_ALIGN8(sizeof(uint16) * check->col_count);
    if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, size_req, (void **)&check->cols) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    errno_t ret = memset_sp(check->cols, size_req, 0, size_req);
    knl_securec_check(ret);
    
    dc_convert_column_list(check->col_count, &col_list, check->cols);
    
    if (dc_copy_column_data(session, cursor, entity, CONSDEF_COL_COND_TEXT, &check->check_text, CT_FALSE) !=
        CT_SUCCESS) {
        return CT_ERROR;
    }
    check->cons_state = cons_state;
    
    if (g_knl_callback.parse_check_from_text((knl_handle_t)session, &check->check_text,
        (knl_handle_t)entity, entity->memory, (void **)&check->condition) != CT_SUCCESS) {
        if (!entity->entry->recycled) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t dc_convert_consdef_reference(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
    constraint_type_t type, void *cons)
{
    text_t col_list;
    uint32 size_req;
    knl_constraint_state_t cons_state;

    cons_state.option = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_FLAGS);
    if (!cons_state.is_enable && cons_state.is_validate) {
        entity->forbid_dml = CT_TRUE;
    }
    ref_cons_t *ref_cons = (ref_cons_t *)cons;
    ref_cons->col_count = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_COLUMN_COUNT);
    col_list.len = CURSOR_COLUMN_SIZE(cursor, CONSDEF_COL_COLUMN_LIST);
    col_list.str = CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_COLUMN_LIST);
    ref_cons->cons_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_INDEX_ID);
    ref_cons->ref_uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_REF_USER);
    ref_cons->ref_oid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_REF_TABLE);
    ref_cons->ref_ix = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_REF_INDEX);
    ref_cons->ref_entity = NULL;
    ref_cons->cons_state = cons_state;
    ref_cons->refactor = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_REFACTOR);
    size_req = CM_ALIGN8(sizeof(uint16) * ref_cons->col_count);
    if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, size_req, (void **)&ref_cons->cols) != CT_SUCCESS) {
        return CT_ERROR;
    }
    errno_t ret = memset_sp(ref_cons->cols, size_req, 0, size_req);
    knl_securec_check(ret);
    dc_convert_column_list(ref_cons->col_count, &col_list, ref_cons->cols);
    return CT_SUCCESS;
}

static status_t dc_convert_consdef(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
    constraint_type_t type, void *cons)
{
    if (type == CONS_TYPE_REFERENCE) {
        return dc_convert_consdef_reference(session, cursor, entity, type, cons);
    } else {
        return dc_convert_consdef_not_reference(session, cursor, entity, type, cons);
    }
}

void dc_convert_table_part_desc(knl_cursor_t *cursor, knl_table_part_desc_t *desc)
{
    text_t text;

    desc->uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_USER_ID);
    desc->table_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_TABLE_ID);
    desc->part_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_PART_ID);

    text.str = CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_NAME);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_TABLEPART_COL_NAME);
    (void)cm_text2str(&text, desc->name, CT_NAME_BUFFER_SIZE);

    desc->space_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_SPACE_ID);
    desc->org_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_ORG_SCN);
    desc->entry = *(page_id_t *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_ENTRY);
    desc->initrans = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_INITRANS);
    desc->pctfree = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_PCTFREE);
    desc->flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_FLAGS);

    /* upgrade from one old version, the subpartcnt is null */
    if (CURSOR_COLUMN_SIZE(cursor, SYS_TABLEPART_COL_SUBPART_CNT) == CT_NULL_VALUE_LEN) {
        desc->subpart_cnt = 0;
    } else {
        desc->subpart_cnt = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_SUBPART_CNT);
    }
    
    desc->seg_scn = desc->org_scn;
    desc->lrep_status = PART_LOGICREP_STATUS_OFF;
    desc->compress_algo = COMPRESS_NONE;
}

void dc_convert_index_part_desc(knl_cursor_t *cursor, knl_index_part_desc_t *desc)
{
    text_t text;

    desc->uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_USER_ID);
    desc->table_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_TABLE_ID);
    desc->index_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_INDEX_ID);
    desc->part_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_PART_ID);

    text.str = CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_NAME);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_INDEXPART_COL_NAME);
    (void)cm_text2str(&text, desc->name, CT_NAME_BUFFER_SIZE);

    desc->space_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_SPACE_ID);
    desc->org_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_ORG_SCN);
    desc->entry = *(page_id_t *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_ENTRY);
    desc->initrans = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_INITRANS);
    desc->pctfree = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_PCTFREE);
    desc->flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_FLAGS);
    desc->subpart_cnt = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_SUBPART_CNT);
    desc->seg_scn = desc->org_scn;
    desc->is_not_ready = CT_FALSE;
}

void dc_convert_lob_part_desc(knl_cursor_t *cursor, knl_lob_part_desc_t *desc)
{
    desc->uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOBPART_COL_USER_ID);
    desc->table_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOBPART_COL_TABLE_ID);
    desc->column_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOBPART_COL_COLUMN_ID);
    desc->part_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOBPART_COL_PART_ID);
    desc->space_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOBPART_COL_SPACE_ID);
    desc->org_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_LOBPART_COL_ORG_SCN);
    desc->entry = *(page_id_t *)CURSOR_COLUMN_DATA(cursor, SYS_LOBPART_COL_ENTRY);
    desc->flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_LOBPART_COL_FLAGS);
    desc->seg_scn = desc->org_scn;
    desc->is_not_ready = CT_FALSE;
}

void dc_convert_part_store_desc(knl_cursor_t *cursor, knl_part_store_desc_t *desc)
{
    desc->uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTSTORE_COL_USER_ID);
    desc->table_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTSTORE_COL_TABLE_ID);
    desc->index_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTSTORE_COL_INDEX_ID);
    desc->pos_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTSTORE_COL_POSITION_ID);
    desc->space_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PARTSTORE_COL_SPACE_ID);
}

static uint8 dc_fk_indexable_columns(knl_index_desc_t *index, cons_dep_t *dep)
{
    uint8 i, j;
    uint8 col_count = (uint8)MIN(index->column_count, dep->col_count);

    for (i = 0; i < col_count; i++) {
        for (j = 0; j < dep->col_count; j++) {
            if (index->columns[i] == dep->cols[j]) {
                break;
            }
        }

        if (j == dep->col_count) {
            break;
        }
    }

    return i;
}

status_t dc_get_part_fk_range(knl_session_t *session, knl_cursor_t *parent_cursor, knl_cursor_t *cursor,
    cons_dep_t *dep, uint32 *left_part_no, uint32 *right_part_no)
{
    char *data = NULL;
    uint32 len;
    uint32 col_id;
    uint8 i, j;
    uint8 col_count;
    part_table_t *part_table;
    dc_entity_t *entity;
    knl_part_key_t part_key;

    entity = (dc_entity_t *)cursor->dc_entity;
    part_table = ((table_t *)cursor->table)->part_table;
    part_key.key = (part_key_t *)cm_push(session->stack, CT_MAX_COLUMN_SIZE);
    errno_t ret = memset_sp(part_key.key, CT_MAX_COLUMN_SIZE, 0, CT_MAX_COLUMN_SIZE);
    knl_securec_check(ret);
    part_key_init(part_key.key, part_table->desc.partkeys);
    col_count = (uint8)MIN(part_table->desc.partkeys, dep->col_count);  // partkeys is 16 at most

    for (i = 0; i < col_count; i++) {
        col_id = part_table->keycols[i].column_id;

        for (j = 0; j < dep->col_count; j++) {
            if (col_id == dep->cols[j]) {
                data = CURSOR_COLUMN_DATA(parent_cursor, j);
                len = CURSOR_COLUMN_SIZE(parent_cursor, j);
                if (len != CT_NULL_VALUE_LEN) {
                    ct_type_t type = part_table->keycols[i].datatype;
                    char temp[NUMBER_ZERO_STORAGR_LEN] = {0};
                    if (CSF_IS_DECIMAL_ZERO(parent_cursor->row->is_csf, len, type)) {
                        part_get_number_zero(type, temp, NUMBER_ZERO_STORAGR_LEN, &len);
                        data = temp;
                    }

                    if (part_put_data(part_key.key, data, len, type) != CT_SUCCESS) {
                        cm_pop(session->stack);
                        return CT_ERROR;
                    }
                } else {
                    part_put_null(part_key.key);
                }
                break;
            }
        }

        if (j == dep->col_count) {
            break;
        }
    }

    if (i == part_table->desc.partkeys) { // if id equals key
        *left_part_no = knl_locate_part_key(entity, part_key.key);
        *right_part_no = *left_part_no;
    } else if (part_table->desc.parttype == PART_TYPE_RANGE && i != 0) { // if id LE key && id GE key
        for (j = 0; j < part_table->desc.partkeys; j++) {
            part_key.closed[j] = CT_TRUE;
        }

        for (j = 0; j < part_table->desc.partkeys - i; j++) {
            part_put_min(part_key.key);
        }
        *left_part_no = knl_locate_part_border(session, entity, &part_key, CT_FALSE);

        part_key.key->column_count = part_key.key->column_count - j;
        for (j = 0; j < part_table->desc.partkeys - i; j++) {
            part_put_max(part_key.key);
        }
        *right_part_no = knl_locate_part_border(session, entity, &part_key, CT_TRUE);
    } else { // scan all parts
        *left_part_no = 0;
        *right_part_no = part_table->desc.partcnt - 1;
    }

    cm_pop(session->stack);
    return CT_SUCCESS;
}

static status_t dc_get_matched_subpartkey_cnt(knl_cursor_t *cursor, table_t *table, knl_part_key_t *part_key,
    cons_dep_t *dep, uint32 *partkey_cnt)
{
    uint32 i, j, column_id, len;
    char *data = NULL;
    part_table_t *part_table = table->part_table;
    uint32 column_count = MIN(part_table->desc.subpartkeys, dep->col_count);

    for (i = 0; i < column_count; i++) {
        column_id = part_table->sub_keycols[i].column_id;
        for (j = 0; j < dep->col_count; j++) {
            if (column_id != dep->cols[i]) {
                continue;
            }

            data = CURSOR_COLUMN_DATA(cursor, j);
            len = CURSOR_COLUMN_SIZE(cursor, j);
            if (len == CT_NULL_VALUE_LEN) {
                part_put_null(part_key->key);
                break;
            }

            ct_type_t type = part_table->sub_keycols[i].datatype;
            char temp[NUMBER_ZERO_STORAGR_LEN] = { 0 };
            if (CSF_IS_DECIMAL_ZERO(cursor->row->is_csf, len, type)) {
                part_get_number_zero(type, temp, NUMBER_ZERO_STORAGR_LEN, &len);
                data = temp;
            }

            if (part_put_data(part_key->key, data, len, part_table->sub_keycols[i].datatype) != CT_SUCCESS) {
                return CT_ERROR;
            }

            break;
        }

        if (j == dep->col_count) {
            break;
        }
    }

    *partkey_cnt = i;
    return CT_SUCCESS;
}

status_t dc_get_subpart_fk_range(knl_session_t *session, knl_cursor_t *parent_cursor, knl_cursor_t *cursor,
    cons_dep_t *dep, uint32 compart_no, uint32 *left_subpart_no, uint32 *right_subpart_no)
{
    uint32 partkey_cnt = 0;
    knl_part_key_t subpart_key;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;

    CM_SAVE_STACK(session->stack);
    subpart_key.key = (part_key_t *)cm_push(session->stack, CT_MAX_COLUMN_SIZE);
    errno_t ret = memset_sp(subpart_key.key, CT_MAX_COLUMN_SIZE, 0, CT_MAX_COLUMN_SIZE);
    knl_securec_check(ret);
    part_key_init(subpart_key.key, part_table->desc.subpartkeys);

    if (dc_get_matched_subpartkey_cnt(parent_cursor, table, &subpart_key, dep, &partkey_cnt) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (partkey_cnt == part_table->desc.subpartkeys) {
        *left_subpart_no = knl_locate_subpart_key(entity, compart_no, subpart_key.key);
        *right_subpart_no = *left_subpart_no;
    } else if (part_table->desc.subparttype == PART_TYPE_RANGE && partkey_cnt != 0) {
        uint32 j;
        for (j = 0; j < part_table->desc.subpartkeys; j++) {
            subpart_key.closed[j] = CT_TRUE;
        }

        for (j = 0; j < part_table->desc.subpartkeys - partkey_cnt; j++) {
            part_put_min(subpart_key.key);
        }

        *left_subpart_no = knl_locate_subpart_border(session, entity, &subpart_key, compart_no, CT_FALSE);
        subpart_key.key->column_count = subpart_key.key->column_count - j;
        for (j = 0; j < part_table->desc.subpartkeys - partkey_cnt; j++) {
            part_put_max(subpart_key.key);
        }

        *right_subpart_no = knl_locate_subpart_border(session, entity, &subpart_key, compart_no, CT_FALSE);
    } else {
        *left_subpart_no = 0;
        table_part_t *compart = TABLE_GET_PART(cursor->table, compart_no);
        *right_subpart_no = compart->desc.subpart_cnt - 1;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

void dc_fk_indexable(knl_session_t *session, table_t *table, cons_dep_t *dep)
{
    uint8 i, j;
    uint8 max_match = 0;
    uint8 match_cols;
    uint8 best_idx = CT_INVALID_ID8;
    index_t *index = NULL;

    for (i = 0; i < table->index_set.count; i++) {
        index = table->index_set.items[i];

        // reverse index cannot be used in range scan, so use table_full_scan here.
        if (IS_REVERSE_INDEX(&index->desc)) {
            continue;
        }

        match_cols = dc_fk_indexable_columns(&index->desc, dep);
        if (match_cols > max_match) {
            best_idx = i;
            max_match = match_cols;
        }
    }

    dep->ix_match_cols = max_match;
    if (max_match == 0) {
        dep->scan_mode = DEP_SCAN_TABLE_FULL;
        for (i = 0; i < dep->col_count; i++) {
            dep->col_map[i] = i;
        }
        return;
    } else if (max_match == dep->col_count) {
        dep->scan_mode = DEP_SCAN_INDEX_ONLY;
    } else {
        dep->scan_mode = DEP_SCAN_MIX;
    }

    dep->idx_slot = best_idx;
    index = table->index_set.items[best_idx];
    for (i = 0; i < dep->col_count; i++) {
        for (j = 0; j < dep->ix_match_cols; j++) {
            if (index->desc.columns[j] == dep->cols[i]) {
                dep->col_map[j] = i;
                break;
            }
        }

        if (j == dep->ix_match_cols) {
            dep->col_map[max_match++] = i;
        }
    }
}

static status_t dc_load_table_cons(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity)
{
    knl_scan_key_t *l_border = NULL;
    constraint_type_t type;
    check_cons_t *check = NULL;
    ref_cons_t *ref = NULL;
    table_t *table = &entity->table;
    uint32 index_id;
    errno_t err;
    uint32 ref_uid;
    uint32 ref_oid;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_CONSDEF_ID, IX_SYS_CONSDEF001_ID);
    l_border = &cursor->scan_range.l_key;

    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_border, CT_TYPE_INTEGER, &table->desc.uid, sizeof(uint32),
        IX_COL_SYS_CONSDEF001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_border, CT_TYPE_INTEGER, &table->desc.id, sizeof(uint32),
        IX_COL_SYS_CONSDEF001_TABLE_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    while (!cursor->eof) {
        type = *(constraint_type_t *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_TYPE);
        if (type == CONS_TYPE_PRIMARY || type == CONS_TYPE_UNIQUE) {
            index_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_INDEX_ID);
            if (dc_load_cons_index(session, cursor, entity, type, index_id) != CT_SUCCESS) {
                return CT_ERROR;
            }
        } else if (type == CONS_TYPE_CHECK) {
            if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(check_cons_t),
                (void **)&table->cons_set.check_cons[table->cons_set.check_count]) != CT_SUCCESS) {
                return CT_ERROR;
            }
            check = table->cons_set.check_cons[table->cons_set.check_count];
            err = memset_sp(check, sizeof(check_cons_t), 0, sizeof(check_cons_t));
            knl_securec_check(err);
            if (dc_convert_consdef(session, cursor, entity, CONS_TYPE_CHECK, (void *)check) != CT_SUCCESS) {
                return CT_ERROR;
            }
            table->cons_set.check_count++;
        } else if (type == CONS_TYPE_REFERENCE) {
            ref_uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_REF_USER);
            ref_oid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_REF_TABLE);
            index_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_INDEX_ID);
            if (DB_ATTR_COMPATIBLE_MYSQL(session) && (ref_uid == -1 && ref_oid == -1)) {
                // for support no check foreign key
                if (knl_fetch(session, cursor) != CT_SUCCESS) {
                    return CT_ERROR;
                }
                continue;
            }
            if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(ref_cons_t),
                (void **)&table->cons_set.ref_cons[table->cons_set.ref_count]) != CT_SUCCESS) {
                return CT_ERROR;
            }
            ref = table->cons_set.ref_cons[table->cons_set.ref_count];
            err = memset_sp(ref, sizeof(ref_cons_t), 0, sizeof(ref_cons_t));
            knl_securec_check(err);
            if (dc_convert_consdef(session, cursor, entity, CONS_TYPE_REFERENCE, (void *)ref) != CT_SUCCESS) {
                return CT_ERROR;
            }
            table->cons_set.ref_count++;
            if (index_id > table->cons_set.max_ref_id) {
                table->cons_set.max_ref_id = index_id;
            }
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t dc_load_depended_cons(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity)
{
    knl_scan_key_t *l_border = NULL;
    constraint_type_t type;
    cons_dep_t *dep = NULL;
    uint32 ix_id;
    index_t *index = NULL;
    text_t col_list;
    table_t *table = &entity->table;
    uint32 size_req;
    uint32 col_count;
    errno_t err;
    uint32 depended_cnt = 0;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_CONSDEF_ID, IX_SYS_CONSDEF002_ID);
    l_border = &cursor->scan_range.l_key;
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_border, CT_TYPE_INTEGER, &table->desc.uid, sizeof(uint32),
        IX_COL_SYS_CONSDEF002_REF_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_border, CT_TYPE_INTEGER, &table->desc.id, sizeof(uint32),
        IX_COL_SYS_CONSDEF002_REF_TABLE_ID);
    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }
    while (!cursor->eof) {
        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);
        type = *(constraint_type_t *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_TYPE);
        knl_panic_log(type == CONS_TYPE_REFERENCE, "the constraint type is abnormal, panic info: table %s page %u-%u "
                      "type %u index %s", table->desc.name, cursor->rowid.file, cursor->rowid.page,
                      ((page_head_t *)cursor->page_buf)->type, ((index_t *)cursor->index)->desc.name);
        ix_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_REF_INDEX);
        if (DB_ATTR_COMPATIBLE_MYSQL(session) && ix_id == CT_INVALID_ID32) {
            if (knl_fetch(session, cursor) != CT_SUCCESS) {
                return CT_ERROR;
            }
            continue;
        }
        index = dc_find_index_by_id(entity, ix_id);
        knl_panic_log(index != NULL, "index is NULL, panic info: page %u-%u type %u table %s index %s",
                      cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                      table->desc.name, ((index_t *)cursor->index)->desc.name);

        col_count = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_COLUMN_COUNT);
        size_req = sizeof(cons_dep_t) + CM_ALIGN8(sizeof(uint16) * col_count) + col_count;
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, size_req, (void **)&dep) != CT_SUCCESS) {
            return CT_ERROR;
        }

        err = memset_sp(dep, size_req, 0, size_req);
        knl_securec_check(err);
        dep->cols = (uint16 *)((char *)dep + sizeof(cons_dep_t));
        dep->col_map = (uint8 *)((char *)dep->cols + (uint32)CM_ALIGN8(sizeof(uint16) * col_count));
        dep->uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_USER);
        dep->oid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_TABLE);
        dep->col_count = (uint8)col_count;
        col_list.len = CURSOR_COLUMN_SIZE(cursor, CONSDEF_COL_COLUMN_LIST);
        col_list.str = CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_COLUMN_LIST);
        dc_convert_column_list(dep->col_count, &col_list, dep->cols);
        dep->cons_state.option = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_FLAGS);
        dep->refactor = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_REFACTOR);
        dep->next = NULL;
        if (index->dep_set.count == 0) {
            index->dep_set.first = dep;
        } else {
            index->dep_set.last->next = dep;
        }
        index->dep_set.last = dep;
        index->dep_set.count++;
        depended_cnt++;
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    table->cons_set.referenced = depended_cnt > 0 ? CT_TRUE : CT_FALSE;
    return CT_SUCCESS;
}

status_t dc_load_cons(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity)
{
    table_t *table = &entity->table;

    if (table->desc.uid == (uint32)0 && table->desc.id <= (uint32)SYS_CONSDEF_ID) {
        return CT_SUCCESS;
    }

    if (dc_load_table_cons(session, cursor, entity) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (dc_load_depended_cons(session, cursor, entity) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t dc_get_user_name(knl_handle_t session, uint32 id, text_t *name)
{
    knl_session_t *se = (knl_session_t *)session;
    dc_context_t *ctx = &se->kernel->dc_ctx;

    if (id >= CT_MAX_USERS || ctx->users[id] == NULL || (ctx->users[id]->status != USER_STATUS_NORMAL &&
        ctx->users[id]->status != USER_STATUS_LOCKED)) {
        CT_THROW_ERROR_EX(ERR_USER_NOT_EXIST, "id(%u)", id);
        return CT_ERROR;
    }
    cm_str2text(ctx->users[id]->desc.name, name);
    return CT_SUCCESS;
}

static status_t dc_convert_policy_def(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity, policy_def_t *policy)
{
    policy->object_owner_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_POLICIES_COL_OBJ_SCHEMA_ID);

    if (dc_get_user_name(session, policy->object_owner_id, &policy->object_owner) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_copy_column_data(session, cursor, entity, SYS_POLICIES_COL_OBJ_NAME,
        &policy->object_name, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (dc_copy_column_data(session, cursor, entity, SYS_POLICIES_COL_PNAME,
        &policy->policy_name, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (dc_copy_column_data(session, cursor, entity, SYS_POLICIES_COL_PF_SCHEMA,
        &policy->function_owner, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (dc_copy_column_data(session, cursor, entity, SYS_POLICIES_COL_PF_NAME,
        &policy->function, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    policy->stmt_types = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_POLICIES_COL_STMT_TYPE);
    policy->ptype = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_POLICIES_COL_PTYPE);
    policy->check_option = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_POLICIES_COL_CHK_OPTION);
    policy->enable = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_POLICIES_COL_ENABLE);
    policy->long_predicate = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_POLICIES_COL_LONG_PREDICATE);

    return CT_SUCCESS;
}

status_t dc_load_policies(knl_session_t *session, knl_cursor_t *cursor, dc_user_t *user, uint32 oid,
    dc_entity_t *entity)
{
    table_t *table = &entity->table;
    policy_def_t *plcy = NULL;
    errno_t err;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_POLICY_ID, IX_SYS_POLICY_001_ID);

    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&user->desc.id,
        sizeof(uint32), IX_COL_SYS_POLICY_001_OBJ_SCHEMA_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&user->desc.id,
        sizeof(uint32), IX_COL_SYS_POLICY_001_OBJ_SCHEMA_ID);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)table->desc.name,
        (uint16)strlen(table->desc.name), IX_COL_SYS_POLICY_001_OBJ_NAME);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_STRING, (void *)table->desc.name,
        (uint16)strlen(table->desc.name), IX_COL_SYS_POLICY_001_OBJ_NAME);

    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_POLICY_001_PNAME);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_POLICY_001_PNAME);

    for (;;) {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }
        
        if (cursor->eof) {
            break;
        }

        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(policy_def_t),
            (void **)&table->policy_set.policies[table->policy_set.plcy_count]) != CT_SUCCESS) {
            return CT_ERROR;
        }

        plcy = table->policy_set.policies[table->policy_set.plcy_count];
        err = memset_sp(plcy, sizeof(policy_def_t), 0, sizeof(policy_def_t));
        knl_securec_check(err);

        if (dc_convert_policy_def(session, cursor, entity, (void *)plcy) != CT_SUCCESS) {
            return CT_ERROR;
        }
        table->policy_set.plcy_count++;
    }

    return CT_SUCCESS;
}

status_t dc_load_trigger_by_table_id(knl_session_t *session, uint32 obj_uid, uint64 base_obj,
                                     trig_set_t *trig_set)
{
    core_ctrl_t *core = &session->kernel->db.ctrl.core;
    database_t *db = &session->kernel->db;
    trig_item_t trig_info;
    knl_cursor_t *cursor = NULL;
    status_t status = CT_SUCCESS;

    if (!core->build_completed ||
        DB_IS_UPGRADE(session) ||
        db->status < DB_STATUS_WAIT_CLEAN) {
        return CT_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TRIGGER_ID, IX_SYS_TRIGGERS_002_ID);
    knl_init_index_scan(cursor, CT_FALSE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&obj_uid,
        sizeof(obj_uid), IX_SYS_TRIGGERS_002_ID_OBJUID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&obj_uid,
        sizeof(obj_uid), IX_SYS_TRIGGERS_002_ID_OBJUID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, (void *)&base_obj,
        sizeof(base_obj), IX_SYS_TRIGGERS_002_ID_BASEOBJ);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_BIGINT, (void *)&base_obj,
        sizeof(base_obj), IX_SYS_TRIGGERS_002_ID_BASEOBJ);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_SYS_TRIGGER_002_ID_OBJ);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_SYS_TRIGGER_002_ID_OBJ);

    for (;;) {
        if (CT_SUCCESS != knl_fetch(session, cursor)) {
            status = CT_ERROR;
            break;
        }

        if (cursor->eof) {
            break;
        }

        trig_info.oid = (uint64)(*(uint32*)CURSOR_COLUMN_DATA(cursor, SYS_TRIGGER_COL_OBJ));
        trig_info.trig_type = (uint8)(*(uint32*)CURSOR_COLUMN_DATA(cursor, SYS_TRIGGER_COL_TYPE));
        trig_info.trig_enable = (uint8)(*(uint32*)CURSOR_COLUMN_DATA(cursor, SYS_TRIGGER_COL_ENABLE));
        trig_info.trig_event = (uint8)(*(uint32*)CURSOR_COLUMN_DATA(cursor, SYS_TRIGGER_COL_EVENT));
        trig_set->items[trig_set->trig_count] = trig_info;
        trig_set->trig_count++;

        CM_ASSERT(trig_set->trig_count <= CT_MAX_TRIGGER_COUNT);
    }

    CM_RESTORE_STACK(session->stack);
    return status;
}


static inline bool32 dc_match_load_mode(knl_session_t *session, space_t *space, uint32 uid, uint32 table_id)
{
    if (!SPACE_IS_ONLINE(space)) {
        return CT_FALSE;
    }
    
    if (!DB_IS_UPGRADE(session)) {
        return CT_TRUE;
    }

    return IS_CORE_SYS_TABLE(uid, table_id) ? CT_TRUE : CT_FALSE;
}

status_t dc_load_systables(knl_session_t *session, dc_context_t *ctx)
{
    knl_table_desc_t desc;
    knl_cursor_t *cursor = NULL;
    dc_entry_t *entry = NULL;
    space_t *space = NULL;

    uint32 sys_begin = 0;
    uint32 sys_end = CT_EX_SYSID_END;
    uint32 uid = 0;

    CM_SAVE_STACK(session->stack);

    knl_set_session_scn(session, CT_INVALID_ID64);
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLE_ID, IX_SYS_TABLE_002_ID);

    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), IX_COL_SYS_TABLE_002_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&sys_begin,
        sizeof(uint32), IX_COL_SYS_TABLE_002_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), IX_COL_SYS_TABLE_002_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&sys_end,
        sizeof(uint32), IX_COL_SYS_TABLE_002_ID);

    dc_user_t *user = ctx->users[0];

    for (;;) {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        dc_convert_table_desc(cursor, &desc);

        if (!dc_is_reserved_entry(desc.uid, desc.id)) {
            continue;
        }

        space = SPACE_GET(session, desc.space_id);
        if (!dc_match_load_mode(session, space, desc.uid, desc.id)) {
            continue;
        }

        entry = DC_GET_ENTRY(user, desc.id);
        cm_spin_lock(&entry->lock, &session->stat->spin_stat.stat_dc_entry);
        if (dc_load_entity(session, user, desc.id, entry, NULL) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            cm_spin_unlock(&entry->lock);
            return CT_ERROR;
        }
        cm_spin_unlock(&entry->lock);
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

/*
* allocate and initialize dc entry for all tables
* @param kernel session, dc context
* @note If the table is recycled, we should not add it to the entry bucket lists.
* So, when user query happens, user would fail to load the table entry.
*/
status_t dc_init_table_entries(knl_session_t *session, dc_context_t *ctx, uint32 uid)
{
    knl_table_desc_t desc;
    knl_cursor_t *cursor = NULL;
    knl_scan_key_t *l_border = NULL;
    knl_scan_key_t *r_border = NULL;
    uint32 uid_start, uid_end;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLE_ID, IX_SYS_TABLE_002_ID);
    l_border = &cursor->scan_range.l_key;
    r_border = &cursor->scan_range.r_key;
    knl_init_index_scan(cursor, CT_FALSE);

    if (uid <= DB_PUB_USER_ID) {
        uid_start = DB_SYS_USER_ID;
        uid_end = DB_PUB_USER_ID;
    } else {
        uid_start = uid;
        uid_end = uid;
    }

    knl_set_scan_key(INDEX_DESC(cursor->index), l_border, CT_TYPE_INTEGER, (void *)&uid_start, sizeof(uint32),
        IX_COL_SYS_TABLE_002_USER_ID);
    knl_set_key_flag(l_border, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_TABLE_002_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_border, CT_TYPE_INTEGER, (void *)&uid_end, sizeof(uint32),
        IX_COL_SYS_TABLE_002_USER_ID);
    knl_set_key_flag(r_border, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_TABLE_002_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) { // assert?
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        desc.uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_USER_ID);
        desc.id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_ID);
        /* core-systables's entries has been initialized in dc_open_core_systbl */
        if (desc.uid == (uint32)DB_SYS_USER_ID && desc.id <= (uint32)CORE_SYS_TABLE_CEIL) {
            if (knl_fetch(session, cursor) != CT_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return CT_ERROR;
            }
            continue;
        }

        dc_convert_table_desc(cursor, &desc);
        /* we can ensure ctx->users[uid] is valid here,so no need to open user by id */
        if (dc_create_table_entry(session, ctx->users[desc.uid], &desc) != CT_SUCCESS) {
            int32 err_code = cm_get_error_code();
            if ((err_code != ERR_DUPLICATE_TABLE) && (err_code != ERR_OBJECT_ID_EXISTS)) {
                CM_RESTORE_STACK(session->stack);
                return CT_ERROR;
            }
            cm_reset_error();
        }

        dc_ready(session, desc.uid, desc.id);

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t dc_init_view_entries(knl_session_t *session, dc_context_t *ctx, uint32 uid)
{
    knl_view_t view;
    core_ctrl_t *core = &session->kernel->db.ctrl.core;
    uint32 uid_start, uid_end;

    if (!core->build_completed) {
        return CT_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_VIEW_ID, IX_SYS_VIEW002_ID);
    knl_scan_key_t *l_border = &cursor->scan_range.l_key;
    knl_scan_key_t *r_border = &cursor->scan_range.r_key;
    knl_init_index_scan(cursor, CT_FALSE);

    if (uid <= DB_PUB_USER_ID) {
        uid_start = DB_SYS_USER_ID;
        uid_end = DB_PUB_USER_ID;
    } else {
        uid_start = uid;
        uid_end = uid;
    }

    knl_set_scan_key(INDEX_DESC(cursor->index), l_border, CT_TYPE_INTEGER, (void *)&uid_start, sizeof(uint32),
        IX_COL_SYS_VIEW002_USER);
    knl_set_key_flag(l_border, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_VIEW002_OBJID);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_border, CT_TYPE_INTEGER, (void *)&uid_end, sizeof(uint32),
        IX_COL_SYS_VIEW002_USER);
    knl_set_key_flag(r_border, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_VIEW002_OBJID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        if (dc_convert_view_desc(session, cursor, &view, NULL) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (dc_create_view_entry(session, ctx->users[view.uid], &view) != CT_SUCCESS) {
            int32 err_code = cm_get_error_code();
            if ((err_code != ERR_DUPLICATE_TABLE) && (err_code != ERR_OBJECT_ID_EXISTS)) {
                CM_RESTORE_STACK(session->stack);
                return CT_ERROR;
            }
            cm_reset_error();
        }

        dc_ready(session, view.uid, view.id);

        if (knl_fetch(session, cursor) != CT_SUCCESS) { // assert?
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static status_t dc_convert_synonym_desc(knl_cursor_t *cursor, knl_synonym_t *synonym, dc_entity_t *entity,
    knl_session_t *session)
{
    text_t text;

    synonym->uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_USER);
    synonym->id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_OBJID);
    synonym->org_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_ORG_SCN);
    synonym->chg_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_CHG_SCN);

    text.str = CURSOR_COLUMN_DATA(cursor, SYS_SYN_SYNONYM_NAME);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_SYN_SYNONYM_NAME);
    (void)cm_text2str(&text, synonym->name, CT_NAME_BUFFER_SIZE);

    text.str = CURSOR_COLUMN_DATA(cursor, SYS_SYN_TABLE_OWNER);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_SYN_TABLE_OWNER);
    (void)cm_text2str(&text, synonym->table_owner, CT_NAME_BUFFER_SIZE);

    text.str = CURSOR_COLUMN_DATA(cursor, SYS_SYN_TABLE_NAME);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_SYN_TABLE_NAME);
    (void)cm_text2str(&text, synonym->table_name, CT_NAME_BUFFER_SIZE);

    synonym->flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_FLAG);
    synonym->type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_TYPE);
    return CT_SUCCESS;
}

status_t dc_init_synonym_entries(knl_session_t *session, dc_context_t *ctx, uint32 uid)
{
    knl_synonym_t synonym;
    core_ctrl_t *core = &session->kernel->db.ctrl.core;
    uint32 uid_start, uid_end;

    if (!core->build_completed) {
        return CT_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SYN_ID, IX_SYS_SYNONYM002_ID);
    knl_scan_key_t *l_border = &cursor->scan_range.l_key;
    knl_scan_key_t *r_border = &cursor->scan_range.r_key;
    knl_init_index_scan(cursor, CT_FALSE);

    if (uid <= DB_PUB_USER_ID) {
        uid_start = DB_SYS_USER_ID;
        uid_end = DB_PUB_USER_ID;
    } else {
        uid_start = uid;
        uid_end = uid;
    }

    knl_set_scan_key(INDEX_DESC(cursor->index), l_border, CT_TYPE_INTEGER, (void *)&uid_start, sizeof(uint32),
        IX_COL_SYS_SYNONYM002_USER);
    knl_set_key_flag(l_border, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SYNONYM002_OBJID);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_border, CT_TYPE_INTEGER, (void *)&uid_end, sizeof(uint32),
        IX_COL_SYS_SYNONYM002_USER);
    knl_set_key_flag(r_border, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SYNONYM002_OBJID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        if (dc_convert_synonym_desc(cursor, &synonym, NULL, session) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
        // just load the entry of table or view
        if (synonym.type == OBJ_TYPE_TABLE || synonym.type == OBJ_TYPE_VIEW) {
            if (dc_create_synonym_entry(session, ctx->users[synonym.uid], &synonym) != CT_SUCCESS) {
                int32 err_code = cm_get_error_code();
                if ((err_code != ERR_DUPLICATE_TABLE) && (err_code != ERR_OBJECT_ID_EXISTS)) {
                    CM_RESTORE_STACK(session->stack);
                    return CT_ERROR;
                }
                cm_reset_error();
            }
            dc_ready(session, synonym.uid, synonym.id);
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) { // assert?
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

#ifdef Z_SHARDING
status_t dc_convert_distribute_rule_desc(knl_cursor_t *cursor, knl_table_desc_t *rule, dc_entity_t *entity,
    knl_session_t *session)
{
    text_t text;

    rule->uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_DISTRIBUTE_RULE_COL_UID);
    rule->id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_DISTRIBUTE_RULE_COL_ID);

    text.str = CURSOR_COLUMN_DATA(cursor, SYS_DISTRIBUTE_RULE_COL_NAME);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_DISTRIBUTE_RULE_COL_NAME);
    (void)cm_text2str(&text, rule->name, CT_NAME_BUFFER_SIZE);

    rule->org_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_DISTRIBUTE_RULE_COL_ORG_SCN);
    rule->chg_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_DISTRIBUTE_RULE_COL_CHG_SCN);

    return CT_SUCCESS;
}

status_t dc_load_distribute_rule(knl_session_t *session, dc_context_t *ctx)
{
    knl_table_desc_t desc;
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_DISTRIBUTE_RULE_ID, CT_INVALID_ID32);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        if (dc_convert_distribute_rule_desc(cursor, &desc, NULL, session) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (dc_create_distribute_rule_entry(session, &desc) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        dc_ready(session, desc.uid, desc.id);

        if (knl_fetch(session, cursor) != CT_SUCCESS) { // assert?
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}
#endif

static bool32 dc_recycle_precheck(knl_session_t *session, space_t *space, page_id_t entry)
{
    datafile_t *df = &session->kernel->db.datafiles[entry.file];
    if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
        return CT_FALSE;
    }
    if (entry.page >= space->head->hwms[df->file_no]) {  // the datafile may be shrinked or dropprd
        return CT_FALSE;
    }

    return CT_TRUE;
}

static void dc_recycle_compart_heap_segment(knl_session_t *session, part_table_t *part_table,
    const table_part_t *compart)
{
    space_t *space = NULL;
    page_head_t *head = NULL;
    heap_segment_t *segment = NULL;
    table_part_t *table_subpart = NULL;
    
    for (uint32 i = 0; i < compart->desc.subpart_cnt; i++) {
        table_subpart = PART_GET_SUBENTITY(part_table, compart->subparts[i]);
        if (table_subpart == NULL) {
            continue;
        }
        drc_recycle_lock_res(session, &table_subpart->heap.latch.drid, DRC_GET_CURR_REFORM_VERSION);
        drc_recycle_lock_res(session, &table_subpart->heap.lock.drid, DRC_GET_CURR_REFORM_VERSION);
        space = SPACE_GET(session, table_subpart->desc.space_id);
        if (!dc_recycle_precheck(session, space, table_subpart->desc.entry)) {
            continue;
        }
        
        if (!IS_INVALID_PAGID(table_subpart->desc.entry)) {
            buf_enter_page(session, table_subpart->desc.entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
            head = (page_head_t *)CURR_PAGE(session);
            segment = HEAP_SEG_HEAD(session);
            if (head->type != PAGE_TYPE_HEAP_HEAD || segment->org_scn != table_subpart->desc.org_scn) {
                buf_leave_page(session, CT_FALSE);
                continue;
            }
            buf_leave_page(session, CT_FALSE);
            buf_unreside_page(session, table_subpart->desc.entry);
        }
    }
}

static void dc_recycle_part_heap_segment(knl_session_t *session, table_t *table)
{
    part_table_t *part_table = table->part_table;
    table_part_t *table_part_entity = NULL;
    knl_table_part_desc_t *table_part_desc = NULL;
    page_head_t *head = NULL;
    heap_segment_t *segment = NULL;
    space_t *space = NULL;

    for (uint32 i = 0; i < TOTAL_PARTCNT(&part_table->desc); i++) {
        table_part_entity = PART_GET_ENTITY(part_table, i);
        if (!IS_READY_PART(table_part_entity)) {
            continue;
        }

        if (IS_PARENT_TABPART(&table_part_entity->desc)) {
            dc_recycle_compart_heap_segment(session, part_table, table_part_entity);
        } else {
            drc_recycle_lock_res(session, &table_part_entity->heap.latch.drid, DRC_GET_CURR_REFORM_VERSION);
            drc_recycle_lock_res(session, &table_part_entity->heap.lock.drid, DRC_GET_CURR_REFORM_VERSION);
            table_part_desc = &table_part_entity->desc;
            space = SPACE_GET(session, table_part_desc->space_id);
            if (!dc_recycle_precheck(session, space, table_part_desc->entry)) {
                continue;
            }
            if (!IS_INVALID_PAGID(table_part_desc->entry)) {
                buf_enter_page(session, table_part_desc->entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
                head = (page_head_t *)CURR_PAGE(session);
                segment = HEAP_SEG_HEAD(session);
                if (head->type != PAGE_TYPE_HEAP_HEAD || segment->org_scn != table_part_desc->org_scn) {
                    buf_leave_page(session, CT_FALSE);
                    continue;
                }
                buf_leave_page(session, CT_FALSE);
                buf_unreside_page(session, table_part_desc->entry);
            }
        }
    }
}

static void dc_recycle_heap_segment(knl_session_t *session, dc_entity_t *entity)
{
    table_t *table = &entity->table;
    knl_table_desc_t *table_desc = &table->desc;
    page_head_t *head = NULL;
    heap_segment_t *segment = NULL;
    space_t *space = NULL;

    if (IS_PART_TABLE(table)) {
        dc_recycle_part_heap_segment(session, table);
    } else if (!IS_INVALID_PAGID(table_desc->entry)) {
        space = SPACE_GET(session, table_desc->space_id);
        if (!dc_recycle_precheck(session, space, table_desc->entry)) {
            return;
        }
        drc_recycle_lock_res(session, &entity->table.heap.latch.drid, DRC_GET_CURR_REFORM_VERSION);
        drc_recycle_lock_res(session, &entity->table.heap.lock.drid, DRC_GET_CURR_REFORM_VERSION);
        buf_enter_page(session, table_desc->entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);

        head = (page_head_t *)CURR_PAGE(session);
        segment = HEAP_SEG_HEAD(session);
        if (head->type != PAGE_TYPE_HEAP_HEAD || segment->org_scn != table_desc->org_scn) {
            buf_leave_page(session, CT_FALSE);
            return;
        }
        buf_leave_page(session, CT_FALSE);
        buf_unreside_page(session, table_desc->entry);
    }
}

static void dc_recycle_compart_btree_segment(knl_session_t *session, part_index_t *part_index,
    const index_part_t *compart)
{
    space_t *space = NULL;
    page_head_t *head = NULL;
    btree_segment_t *segment = NULL;
    index_part_t *index_subpart = NULL;
    
    for (uint32 i = 0; i < compart->desc.subpart_cnt; i++) {
        index_subpart = PART_GET_SUBENTITY(part_index, compart->subparts[i]);
        if (index_subpart == NULL) {
            continue;
        }

        drc_recycle_lock_res(session, &index_subpart->btree.struct_latch.drid, DRC_GET_CURR_REFORM_VERSION);
        space = SPACE_GET(session, index_subpart->desc.space_id);
        if (!dc_recycle_precheck(session, space, index_subpart->desc.entry)) {
            continue;
        }
        
        if (!IS_INVALID_PAGID(index_subpart->desc.entry)) {
            buf_enter_page(session, index_subpart->desc.entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
            head = (page_head_t *)CURR_PAGE(session);
            segment = BTREE_GET_SEGMENT(session);
            if (head->type != PAGE_TYPE_BTREE_HEAD || segment->org_scn != index_subpart->desc.org_scn) {
                buf_leave_page(session, CT_FALSE);
                continue;
            }
            buf_leave_page(session, CT_FALSE);
            buf_unreside_page(session, index_subpart->desc.entry);
        }
    }
}

static void dc_recycle_part_btree_segment(knl_session_t *session, table_t *table, part_index_t *part_index)
{
    part_table_t *part_table = table->part_table;
    table_part_t *table_part = NULL;
    index_part_t *index_part_entity = NULL;
    knl_index_part_desc_t *index_part_desc = NULL;
    page_head_t *head = NULL;
    btree_segment_t *segment = NULL;
    space_t *space = NULL;

    for (uint32 j = 0; j < TOTAL_PARTCNT(&part_table->desc); j++) {
        table_part = PART_GET_ENTITY(part_table, j);
        index_part_entity = PART_GET_ENTITY(part_index, j);
        if (!IS_READY_PART(table_part) || index_part_entity == NULL) {
            continue;
        }

        if (IS_PARENT_IDXPART(&index_part_entity->desc)) {
            dc_recycle_compart_btree_segment(session, part_index, index_part_entity);
        } else {
            drc_recycle_lock_res(session, &index_part_entity->btree.struct_latch.drid, DRC_GET_CURR_REFORM_VERSION);
            index_part_desc = &index_part_entity->desc;
            space = SPACE_GET(session, index_part_desc->space_id);
            if (!dc_recycle_precheck(session, space, index_part_desc->entry)) {
                continue;
            }
            if (!IS_INVALID_PAGID(index_part_desc->entry)) {
                buf_enter_page(session, index_part_desc->entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
                head = (page_head_t *)CURR_PAGE(session);
                segment = BTREE_GET_SEGMENT(session);
                if (head->type != PAGE_TYPE_BTREE_HEAD || segment->org_scn != index_part_desc->org_scn) {
                    buf_leave_page(session, CT_FALSE);
                    continue;
                }
                buf_leave_page(session, CT_FALSE);
                buf_unreside_page(session, index_part_desc->entry);
            }
        }
    }
}

static void dc_recycle_btree_segment(knl_session_t *session, dc_entity_t *entity)
{
    table_t *table = &entity->table;
    index_t *index = NULL;
    knl_index_desc_t *index_desc = NULL;
    part_index_t *part_index = NULL;
    page_head_t *head = NULL;
    btree_segment_t *segment = NULL;
    space_t *space = NULL;

    for (uint32 i = 0; i < table->desc.index_count; i++) {
        index = table->index_set.items[i];
        index_desc = &index->desc;
        if (index_desc->parted) {
            part_index = index->part_index;
            dc_recycle_part_btree_segment(session, table, part_index);
        } else if (!IS_INVALID_PAGID(index_desc->entry)) {
            drc_recycle_lock_res(session, &index->btree.struct_latch.drid, DRC_GET_CURR_REFORM_VERSION);
            space = SPACE_GET(session, index_desc->space_id);
            if (!dc_recycle_precheck(session, space, index_desc->entry)) {
                continue;
            }
            buf_enter_page(session, index_desc->entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
            head = (page_head_t *)CURR_PAGE(session);
            segment = BTREE_GET_SEGMENT(session);
            if (head->type != PAGE_TYPE_BTREE_HEAD || segment->org_scn != index_desc->org_scn) {
                buf_leave_page(session, CT_FALSE);
                continue;
            }
            buf_leave_page(session, CT_FALSE);
            buf_unreside_page(session, index_desc->entry);
        }
    }
}

static void dc_recycle_compart_lob_segment(knl_session_t *session, part_lob_t *part_lob, lob_part_t *compart)
{
    space_t *space = NULL;
    page_head_t *head = NULL;
    lob_segment_t *segment = NULL;
    lob_part_t *lob_subpart = NULL;
    
    for (uint32 i = 0; i < compart->desc.subpart_cnt; i++) {
        lob_subpart = PART_GET_SUBENTITY(part_lob, compart->subparts[i]);
        if (lob_subpart == NULL) {
            continue;
        }

        drc_recycle_lock_res(session, &lob_subpart->lob_entity.seg_latch.drid, DRC_GET_CURR_REFORM_VERSION);
        space = SPACE_GET(session, lob_subpart->desc.space_id);
        if (!dc_recycle_precheck(session, space, lob_subpart->desc.entry)) {
            continue;
        }
        
        if (!IS_INVALID_PAGID(lob_subpart->desc.entry)) {
            buf_enter_page(session, lob_subpart->desc.entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
            head = (page_head_t *)CURR_PAGE(session);
            segment = LOB_SEG_HEAD(session);
            if (head->type != PAGE_TYPE_LOB_HEAD || segment->org_scn != lob_subpart->desc.org_scn) {
                buf_leave_page(session, CT_FALSE);
                continue;
            }
            buf_leave_page(session, CT_FALSE);
            buf_unreside_page(session, lob_subpart->desc.entry);
        }
    }
}

static void dc_recycle_part_lob_segment(knl_session_t *session, table_t *table, part_lob_t *part_lob)
{
    part_table_t *part_table = table->part_table;
    lob_part_t *lob_part_entity = NULL;
    table_part_t *table_part = NULL;
    knl_lob_part_desc_t *lob_part_desc = NULL;
    space_t *space = NULL;
    page_head_t *head = NULL;
    lob_segment_t *segment = NULL;

    for (uint32 j = 0; j < TOTAL_PARTCNT(&part_table->desc); j++) {
        table_part = PART_GET_ENTITY(part_table, j);
        lob_part_entity = PART_GET_ENTITY(part_lob, j);
        if (!IS_READY_PART(table_part) || lob_part_entity == NULL) {
            continue;
        }
        
        if (IS_PARENT_LOBPART(&lob_part_entity->desc)) {
            dc_recycle_compart_lob_segment(session, part_lob, lob_part_entity);
        } else {
            drc_recycle_lock_res(session, &lob_part_entity->lob_entity.seg_latch.drid, DRC_GET_CURR_REFORM_VERSION);
            lob_part_desc = &lob_part_entity->desc;
            space = SPACE_GET(session, lob_part_desc->space_id);
            if (!dc_recycle_precheck(session, space, lob_part_desc->entry)) {
                continue;
            }
            if (!IS_INVALID_PAGID(lob_part_desc->entry)) {
                buf_enter_page(session, lob_part_desc->entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
                head = (page_head_t *)CURR_PAGE(session);
                segment = LOB_SEG_HEAD(session);
                if (head->type != PAGE_TYPE_LOB_HEAD || segment->org_scn != lob_part_desc->org_scn) {
                    buf_leave_page(session, CT_FALSE);
                    continue;
                }
                buf_leave_page(session, CT_FALSE);
                buf_unreside_page(session, lob_part_desc->entry);
            }
        }
    }
}

static void dc_recycle_lob_segment(knl_session_t *session, dc_entity_t *entity)
{
    table_t *table = &entity->table;
    knl_column_t *column = NULL;
    lob_t *lob = NULL;
    part_lob_t *part_lob = NULL;
    space_t *space = NULL;
    page_head_t *head = NULL;
    lob_segment_t *segment = NULL;

    if (!entity->contain_lob) {
        return;
    }
    for (uint32 i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }
        lob = (lob_t *)column->lob;
        if (IS_PART_TABLE(table)) {
            part_lob = lob->part_lob;
            dc_recycle_part_lob_segment(session, table, part_lob);
        } else if (!IS_INVALID_PAGID(lob->desc.entry)) {
            drc_recycle_lock_res(session, &lob->lob_entity.seg_latch.drid, DRC_GET_CURR_REFORM_VERSION);
            space = SPACE_GET(session, lob->desc.space_id);
            if (!dc_recycle_precheck(session, space, lob->desc.entry)) {
                continue;
            }
            buf_enter_page(session, lob->desc.entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
            head = (page_head_t *)CURR_PAGE(session);
            segment = LOB_SEG_HEAD(session);
            if (head->type != PAGE_TYPE_LOB_HEAD || segment->org_scn != lob->desc.org_scn) {
                buf_leave_page(session, CT_FALSE);
                continue;
            }
            buf_leave_page(session, CT_FALSE);
            buf_unreside_page(session, lob->desc.entry);
        }
    }
}

latch_t g_seg_rcy_latch = { .lock = 0, .shared_count = 0, .stat = 0, .sid = 0, .unused = 0 };

void dc_segment_recycle(dc_context_t *ctx, dc_entity_t *entity)
{
    knl_instance_t *kernel = (knl_instance_t *)ctx->kernel;
    knl_session_t *session = knl_get_curr_sess() ? knl_get_curr_sess() : kernel->sessions[SESSION_ID_SEG_RCYCLE];

    if (entity->entry->type != DICT_TYPE_TABLE) {
        return;
    }

    if (session == kernel->sessions[SESSION_ID_SEG_RCYCLE]) {
        cm_latch_x(&g_seg_rcy_latch, SESSION_ID_SEG_RCYCLE, NULL);
    }

    dc_recycle_heap_segment(session, entity);
    dc_recycle_btree_segment(session, entity);
    dc_recycle_lob_segment(session, entity);

    if (session == kernel->sessions[SESSION_ID_SEG_RCYCLE]) {
        cm_unlatch(&g_seg_rcy_latch, NULL);
    }
}

static void dc_recycle_compart_heap_dls(knl_session_t *session, part_table_t *part_table, const table_part_t *compart)
{
    table_part_t *table_subpart = NULL;

    for (uint32 i = 0; i < compart->desc.subpart_cnt; i++) {
        table_subpart = PART_GET_SUBENTITY(part_table, compart->subparts[i]);
        if (table_subpart == NULL) {
            continue;
        }
        drc_recycle_lock_res(session, &table_subpart->heap.latch.drid, DRC_GET_CURR_REFORM_VERSION);
        drc_recycle_lock_res(session, &table_subpart->heap.lock.drid, DRC_GET_CURR_REFORM_VERSION);
    }
}

static void dc_recycle_part_heap_dls(knl_session_t *session, table_t *table)
{
    part_table_t *part_table = table->part_table;
    table_part_t *table_part_entity = NULL;

    for (uint32 i = 0; i < TOTAL_PARTCNT(&part_table->desc); i++) {
        table_part_entity = PART_GET_ENTITY(part_table, i);
        if (!IS_READY_PART(table_part_entity)) {
            continue;
        }

        if (IS_PARENT_TABPART(&table_part_entity->desc)) {
            dc_recycle_compart_heap_dls(session, part_table, table_part_entity);
        } else {
            drc_recycle_lock_res(session, &table_part_entity->heap.latch.drid, DRC_GET_CURR_REFORM_VERSION);
            drc_recycle_lock_res(session, &table_part_entity->heap.lock.drid, DRC_GET_CURR_REFORM_VERSION);
        }
    }
}

static void dc_recycle_heap_dls(knl_session_t *session, dc_entity_t *entity)
{
    table_t *table = &entity->table;
    knl_table_desc_t *table_desc = &table->desc;

    if (IS_PART_TABLE(table)) {
        dc_recycle_part_heap_dls(session, table);
    } else if (!IS_INVALID_PAGID(table_desc->entry)) {
        drc_recycle_lock_res(session, &entity->table.heap.latch.drid, DRC_GET_CURR_REFORM_VERSION);
        drc_recycle_lock_res(session, &entity->table.heap.lock.drid, DRC_GET_CURR_REFORM_VERSION);
    }
}

static void dc_recycle_compart_btree_dls(knl_session_t *session, part_index_t *part_index, const index_part_t *compart)
{
    index_part_t *index_subpart = NULL;

    for (uint32 i = 0; i < compart->desc.subpart_cnt; i++) {
        index_subpart = PART_GET_SUBENTITY(part_index, compart->subparts[i]);
        if (index_subpart == NULL) {
            continue;
        }
        drc_recycle_lock_res(session, &index_subpart->btree.struct_latch.drid, DRC_GET_CURR_REFORM_VERSION);
    }
}

static void dc_recycle_part_btree_dls(knl_session_t *session, table_t *table, part_index_t *part_index)
{
    part_table_t *part_table = table->part_table;
    table_part_t *table_part = NULL;
    index_part_t *index_part_entity = NULL;

    for (uint32 j = 0; j < TOTAL_PARTCNT(&part_table->desc); j++) {
        table_part = PART_GET_ENTITY(part_table, j);
        index_part_entity = PART_GET_ENTITY(part_index, j);
        if (!IS_READY_PART(table_part) || index_part_entity == NULL) {
            continue;
        }

        if (IS_PARENT_IDXPART(&index_part_entity->desc)) {
            dc_recycle_compart_btree_dls(session, part_index, index_part_entity);
        } else {
            drc_recycle_lock_res(session, &index_part_entity->btree.struct_latch.drid, DRC_GET_CURR_REFORM_VERSION);
        }
    }
}

static void dc_recycle_btree_dls(knl_session_t *session, dc_entity_t *entity)
{
    table_t *table = &entity->table;
    index_t *index = NULL;
    knl_index_desc_t *index_desc = NULL;
    part_index_t *part_index = NULL;

    for (uint32 i = 0; i < table->desc.index_count; i++) {
        index = table->index_set.items[i];
        index_desc = &index->desc;
        if (index_desc->parted) {
            part_index = index->part_index;
            dc_recycle_part_btree_dls(session, table, part_index);
        } else if (!IS_INVALID_PAGID(index_desc->entry)) {
            drc_recycle_lock_res(session, &index->btree.struct_latch.drid, DRC_GET_CURR_REFORM_VERSION);
        }
    }
}

static void dc_recycle_compart_lob_dls(knl_session_t *session, part_lob_t *part_lob, lob_part_t *compart)
{
    lob_part_t *lob_subpart = NULL;

    for (uint32 i = 0; i < compart->desc.subpart_cnt; i++) {
        lob_subpart = PART_GET_SUBENTITY(part_lob, compart->subparts[i]);
        if (lob_subpart == NULL) {
            continue;
        }

        drc_recycle_lock_res(session, &lob_subpart->lob_entity.seg_latch.drid, DRC_GET_CURR_REFORM_VERSION);
    }
}

static void dc_recycle_part_lob_dls(knl_session_t *session, table_t *table, part_lob_t *part_lob)
{
    part_table_t *part_table = table->part_table;
    lob_part_t *lob_part_entity = NULL;
    table_part_t *table_part = NULL;

    for (uint32 j = 0; j < TOTAL_PARTCNT(&part_table->desc); j++) {
        table_part = PART_GET_ENTITY(part_table, j);
        lob_part_entity = PART_GET_ENTITY(part_lob, j);
        if (!IS_READY_PART(table_part) || lob_part_entity == NULL) {
            continue;
        }
        if (IS_PARENT_LOBPART(&lob_part_entity->desc)) {
            dc_recycle_compart_lob_dls(session, part_lob, lob_part_entity);
        } else {
            drc_recycle_lock_res(session, &lob_part_entity->lob_entity.seg_latch.drid, DRC_GET_CURR_REFORM_VERSION);
        }
    }
}

static void dc_recycle_lob_dls(knl_session_t *session, dc_entity_t *entity)
{
    table_t *table = &entity->table;
    knl_column_t *column = NULL;
    lob_t *lob = NULL;
    part_lob_t *part_lob = NULL;

    if (!entity->contain_lob) {
        return;
    }
    for (uint32 i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }
        lob = (lob_t *)column->lob;
        if (IS_PART_TABLE(table)) {
            part_lob = lob->part_lob;
            dc_recycle_part_lob_dls(session, table, part_lob);
        } else if (!IS_INVALID_PAGID(lob->desc.entry)) {
            drc_recycle_lock_res(session, &lob->lob_entity.seg_latch.drid, DRC_GET_CURR_REFORM_VERSION);
        }
    }
}

void dc_release_segment_dls(knl_session_t *session, dc_entity_t *entity)
{
    if (entity->type != DICT_TYPE_TABLE || entity->entry->type != DICT_TYPE_TABLE) {
        return;
    }
    if (!DB_IS_CLUSTER(session)) {
        return;
    }

    dc_recycle_heap_dls(session, entity);
    dc_recycle_btree_dls(session, entity);
    dc_recycle_lob_dls(session, entity);
}
