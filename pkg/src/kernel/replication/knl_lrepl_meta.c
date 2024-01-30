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
 * knl_lrepl_meta.c
 *
 *
 * IDENTIFICATION
 * src/kernel/replication/knl_lrepl_meta.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_table.h"
#include "dc_tbl.h"
#include "dc_part.h"
#include "knl_mtrl.h"
#include "knl_database.h"
#include "knl_context.h"
#include "knl_lrepl_meta.h"

char *knl_meta_detail_action_get(altable_action_t action, knl_altable_def_t *def,
                                 bool32 is_rename_cross_db, bool32 is_create_table)
{
    if (def == NULL) {
        if (is_create_table) {
            return "CREATE TABLE";
        }

        if (is_rename_cross_db) {
            return "RENAME TABLE";
        } else {
            return "ALTER COPY";
        }
    }

    switch (action) {
        case ALTABLE_RENAME_TABLE:
            return "RENAME TABLE";
        case ALTABLE_ADD_COLUMN:
            return "ADD COLUMN";
        case ALTABLE_MODIFY_COLUMN:
            return "MODIFY COLUMN";
        case ALTABLE_RENAME_COLUMN:
            return "RENAME COLUMN";
        case ALTABLE_DROP_COLUMN:
            return "DROP COLUMN";

        default:
            return "UNSUPPORTED TYPE";
    }
}

bool32 knl_meta_need_record(knl_session_t *session, knl_altable_def_t *def, knl_dictionary_t *dc)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    if (session->kernel->db.ctrl.core.log_mode != ARCHIVE_LOG_ON) {
        return CT_FALSE;
    }
    if (entity->lrep_info.status == LOGICREP_STATUS_OFF && entity->lrep_info.parts_count == 0) {
        return CT_FALSE;
    }

    // create table, including SQLCOM_CREATE_TABLE and alter copy
    if (def == NULL) {
        return CT_TRUE;
    }

    switch (def->action) {
        case ALTABLE_RENAME_TABLE:
            if (def->is_mysql_copy) {
                return CT_FALSE;
            }
        case ALTABLE_ADD_COLUMN:
        case ALTABLE_MODIFY_COLUMN:
        case ALTABLE_RENAME_COLUMN:
        case ALTABLE_DROP_COLUMN:
            return CT_TRUE;

        default:
            return CT_FALSE;
    }
}

status_t knl_meta_diff_insert(knl_session_t *session, tablemeta_diff_info_t *info, knl_altable_def_t *def,
                              bool32 is_rename_cross_db, bool32 is_create_table)
{
    knl_dictionary_t dc;
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    text_t user_name = { .str = SYS_USER_NAME, .len = (uint32)strlen(SYS_USER_NAME) };
    text_t table_name = { .str = TABLEMETA_DIFF_TABLE_NAME, .len = (uint32)strlen(TABLEMETA_DIFF_TABLE_NAME) };

    if (dc_open(session, &user_name, &table_name, &dc) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[HEAP_META]: failed to open SYS.SYS_TABLEMETA_DIFF.");
        cm_reset_error();
        return CT_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->action = CURSOR_ACTION_INSERT;

    if (knl_open_cursor(session, cursor, &dc) != CT_SUCCESS) {
        dc_close(&dc);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    row_init(&ra, (char *)cursor->row, session->kernel->attr.max_row_size, SYS_TABLEMETA_DIFF_COLUMN_COUNT);
    (void)row_put_int64(&ra, info->org_scn);
    (void)row_put_str(&ra, info->user_name);
    (void)row_put_str(&ra, info->name);
    (void)row_put_int32(&ra, info->uid);
    (void)row_put_int32(&ra, info->tid);
    (void)row_put_int32(&ra, info->obj_id);
    (void)row_put_int64(&ra, info->version);
    (void)row_put_str(&ra, knl_meta_detail_action_get(info->ddl_type, def, is_rename_cross_db, is_create_table));
    (void)row_put_int64(&ra, info->chg_scn);
    (void)row_put_int64(&ra, info->invalid_scn);
    (void)row_put_null(&ra);

    if (knl_internal_insert(session, cursor) != CT_SUCCESS) {
        dc_close(&dc);
        knl_close_cursor(session, cursor);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    dc_close(&dc);
    knl_close_cursor(session, cursor);
    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

status_t knl_meta_his_construct_row(lrepl_meta_mtrl_context_t *ctx, row_assist_t *ra,
                                    tablemeta_diff_info_t *diff_info, uint32 column_idx)
{
    uint32 id, next;
    vm_ctrl_t *ctrl = NULL;
    vm_page_t *curr_page = NULL;
    uint32 column_size = sizeof(columnmeta_his_info_t);

    mtrl_segment_t *segment = ctx->mtrl_ctx.segments[ctx->seg_id];
    uint32 page_id = (uint32)(column_idx / ((CT_VMEM_PAGE_SIZE - sizeof(mtrl_page_t)) / column_size));
    uint32 row_id = (uint32)(column_idx % ((CT_VMEM_PAGE_SIZE - sizeof(mtrl_page_t)) / column_size));
    id = segment->vm_list.first;
    while (page_id > 0) {
        ctrl = vm_get_ctrl(ctx->mtrl_ctx.pool, id);
        next = ctrl->next;
        id = next;
        page_id--;
    }

    if (mtrl_open_page(&ctx->mtrl_ctx, id, &curr_page) != CT_SUCCESS) {
        return CT_ERROR;
    }
    mtrl_page_t *page = (mtrl_page_t *)curr_page->data;
    columnmeta_his_info_t *info_list = (columnmeta_his_info_t *)page;
    columnmeta_his_info_t *his_info = &info_list[row_id];

    (void)(row_put_int64(ra, diff_info->org_scn));
    (void)(row_put_int64(ra, diff_info->version));
    (void)(row_put_int32(ra, his_info->user_id));
    (void)(row_put_int32(ra, his_info->table_id));
    (void)(row_put_int32(ra, his_info->object_id));
    (void)(row_put_int32(ra, his_info->column_id));
    (void)(row_put_str(ra, his_info->column_name));
    (void)(row_put_bool(ra, his_info->primary));
    (void)(row_put_bool(ra, his_info->changed));
    (void)(row_put_int32(ra, his_info->datatype));
    (void)(row_put_int32(ra, his_info->size));
    row_put_prec_and_scale(ra, his_info->datatype, his_info->precision, his_info->scale);
    (void)(row_put_int32(ra, his_info->nullable));
    (void)(row_put_int32(ra, his_info->flags));
    if (his_info->has_default == CT_TRUE) {
        (void)(row_put_str(ra, his_info->default_text));
    } else {
        (void)row_put_null(ra);
    }
    binary_t bin;
    uint8 buf[CT_SYS_OPT_LEN] = { 0 };
    bin.bytes = buf;
    bin.is_hex_const = CT_FALSE;
    bin.size = sizeof(uint16) + sizeof(uint8) + sizeof(uint8);
    (void)memcpy_sp(buf, CT_SYS_OPT_LEN, &(his_info->collate_id), sizeof(uint16));
    (void)memcpy_sp(buf + sizeof(uint16), CT_SYS_OPT_LEN - sizeof(uint16),
                    &(his_info->mysql_ori_datatype), sizeof(uint8));
    (void)memcpy_sp(buf + sizeof(uint16) + sizeof(uint8), CT_SYS_OPT_LEN - sizeof(uint16) - sizeof(uint8),
                    &(his_info->mysql_unsigned), sizeof(uint8));
    (void)row_put_bin(ra, &bin);

    mtrl_close_page(&ctx->mtrl_ctx, id);

    return CT_SUCCESS;
}

status_t knl_meta_his_insert(knl_session_t *session, tablemeta_diff_info_t *diff_info,
                             lrepl_meta_mtrl_context_t *ctx, uint32 column_count)
{
    knl_dictionary_t dc;
    row_assist_t ra;
    text_t user_name = { .str = SYS_USER_NAME, .len = (uint32)strlen(SYS_USER_NAME) };
    text_t table_name = { .str = COLUMNMETA_HIS_TABLE_NAME, .len = (uint32)strlen(COLUMNMETA_HIS_TABLE_NAME) };
    status_t status = CT_SUCCESS;

    if (dc_open(session, &user_name, &table_name, &dc) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[HEAP_META]: failed to open SYS.SYS_COLUMNMETA_HIS.");
        cm_reset_error();
        return CT_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->action = CURSOR_ACTION_INSERT;

    if (knl_open_cursor(session, cursor, &dc) != CT_SUCCESS) {
        dc_close(&dc);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    for (uint32 i = 0; i < column_count; i++) {
        row_init(&ra, (char *)cursor->row, session->kernel->attr.max_row_size, SYS_COLUMNMETA_HIS_COLUMN_COUNT);
        if (knl_meta_his_construct_row(ctx, &ra, diff_info, i) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (knl_internal_insert(session, cursor) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }
    }

    dc_close(&dc);
    knl_close_cursor(session, cursor);
    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t knl_set_and_open_cursor_when_fetch_diff(knl_session_t *session, knl_cursor_t *cursor, index_t *index,
                                                 knl_dictionary_t *dc, knl_scn_t org_scn)
{
    cursor->scan_mode = SCAN_MODE_INDEX;
    cursor->action = CURSOR_ACTION_UPDATE;
    cursor->index = index;
    cursor->index_dsc = CT_FALSE;
    cursor->index_slot = index->desc.id;
    cursor->index_only = CT_TRUE;
    knl_init_index_scan(cursor, CT_FALSE);

    if (knl_open_cursor(session, cursor, dc) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[HEAP_META]: failed to open cursor when update latest");
        return CT_ERROR;
    }

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, (void *)&org_scn,
                     sizeof(uint64), IX_COL_TABLEMETA_DIFF001_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_TABLEMETA_DIFF001_VERSION);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_TABLEMETA_DIFF001_CHG_SCN);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_BIGINT, (void *)&org_scn,
                     sizeof(uint64), IX_COL_TABLEMETA_DIFF001_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_TABLEMETA_DIFF001_VERSION);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_TABLEMETA_DIFF001_CHG_SCN);

    return CT_SUCCESS;
}

status_t knl_meta_internal_update_latest(knl_session_t *session, knl_cursor_t *cursor,
                                         uint64 *next_version, knl_scn_t scn, bool32 *is_first_version)
{
    status_t status = CT_SUCCESS;
    uint16 size;
    row_assist_t ra;
    uint64 version;
    knl_scn_t invalid_scn;
    for (uint32 i = 0;; i++) {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (cursor->eof) {
            *is_first_version = i == 0 ? CT_TRUE : CT_FALSE;
            break;
        }

        version = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEMETA_DIFF_COL_VERSION);
        invalid_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEMETA_DIFF_COL_INVALID_SCN);
        if (invalid_scn == CT_INVALID_INT64) {
            row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ONE);
            (void)row_put_int64(&ra, *(int64 *)&scn);
            cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
            cursor->update_info.columns[0] = SYS_TABLEMETA_DIFF_COL_INVALID_SCN;
            cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);
            
            if (knl_internal_update(session, cursor) != CT_SUCCESS) {
                status = CT_ERROR;
                break;
            }

            if (next_version != NULL) {
                *next_version = version;
            }
            break;
        }

        if (next_version != NULL) {
            *next_version = *next_version > version ? *next_version : version;
        }
    }

    return status;
}

status_t knl_meta_update_latest(knl_session_t *session, knl_scn_t org_scn, uint64 *next_version, knl_scn_t scn)
{
    knl_dictionary_t dc;
    knl_cursor_t *cursor = NULL;
    text_t user_name = { .str = SYS_USER_NAME, .len = (uint32)strlen(SYS_USER_NAME) };
    text_t table_name = { .str = TABLEMETA_DIFF_TABLE_NAME, .len = (uint32)strlen(TABLEMETA_DIFF_TABLE_NAME) };
    status_t status = CT_SUCCESS;
    bool32 is_first_version = CT_FALSE;

    if (dc_open(session, &user_name, &table_name, &dc) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[HEAP_META]: failed to open SYS.SYS_TABLEMETA_DIFF.");
        cm_reset_error();
        return CT_SUCCESS;
    }

    index_t *index = dc_find_index_by_id(DC_ENTITY(&dc), IX_TABLEMETA_DIFF001_ID);
    if (index == NULL) {
        dc_close(&dc);
        return CT_SUCCESS;
    }
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    if (knl_set_and_open_cursor_when_fetch_diff(session, cursor, index, &dc, org_scn) != CT_SUCCESS) {
        dc_close(&dc);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    status = knl_meta_internal_update_latest(session, cursor, next_version, scn, &is_first_version);
    if (!is_first_version && next_version != NULL) {
        (*next_version)++;
    }

    dc_close(&dc);
    knl_close_cursor(session, cursor);
    CM_RESTORE_STACK(session->stack);

    return status;
}

bool32 db_alter_columns_is_changed(knl_altable_def_t *def, knl_dictionary_t *dc, uint32 column_id)
{
    knl_column_t *old_column = NULL;
    knl_alt_column_prop_t *col_def = NULL;
    knl_column_def_t *def_column = NULL;

    for (uint32 i = 0; i < def->column_defs.count; i++) {
        col_def = (knl_alt_column_prop_t *)cm_galist_get(&def->column_defs, i);
        def_column = &col_def->new_column;
        old_column = knl_find_column(&def_column->name, dc);

        if (column_id == old_column->id) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

bool32 db_alter_column_is_changed(knl_altable_def_t *def, knl_dictionary_t *dc, uint32 column_id)
{
    knl_alt_column_prop_t *col_def = (knl_alt_column_prop_t *)cm_galist_get(&def->column_defs, 0);
    knl_column_t *old_column = knl_find_column(&col_def->name, dc);

    return old_column->id == column_id;
}

bool32 knl_meta_column_is_changed(knl_altable_def_t *def, knl_dictionary_t *dc, uint32 column_id)
{
    uint32 column_count = knl_get_column_count(dc->handle);
    if (def == NULL) {
        return CT_FALSE;
    }
    switch (def->action) {
        case ALTABLE_ADD_COLUMN:
            return column_id >= column_count;

        case ALTABLE_MODIFY_COLUMN:
            return db_alter_columns_is_changed(def, dc, column_id);

        case ALTABLE_RENAME_COLUMN:
        case ALTABLE_DROP_COLUMN:
            return db_alter_column_is_changed(def, dc, column_id);

        default:
            return CT_FALSE;
    }
}

/* constructing new version ready insert into SYS.SYS_TABLEMETA_DIFF */
status_t knl_meta_diff_construct_info(knl_session_t *session, knl_altable_def_t *def, knl_dictionary_t *dc,
                                      tablemeta_diff_info_t *info, uint64 new_version, knl_scn_t scn)
{
    table_t *table = DC_TABLE(dc);
    dc_context_t *ctx = &session->kernel->dc_ctx;
    errno_t ret;

    info->uid = table->desc.uid;
    info->tid = table->desc.id;
    info->obj_id = table->desc.oid;
    info->org_scn = dc->org_scn;
    info->version = new_version;
    info->ddl_type = def != NULL ? def->action : ALTABLE_ADD_COLUMN;
    info->chg_scn = scn;
    info->invalid_scn = CT_INVALID_INT64;

    if (info->uid >= CT_MAX_USERS || ctx->users[info->uid] == NULL ||
        (session->drop_uid != info->uid && ctx->users[info->uid]->status != USER_STATUS_NORMAL)) {
        CT_THROW_ERROR(ERR_USER_NOT_EXIST, "");
        return CT_ERROR;
    }

    ret = strncpy_s(info->user_name, CT_NAME_BUFFER_SIZE, ctx->users[info->uid]->desc.name,
                    strlen(ctx->users[info->uid]->desc.name));
    knl_securec_check(ret);

    if (def != NULL && def->action == ALTABLE_RENAME_TABLE && !def->is_mysql_copy) {
        ret = strncpy_s(info->name, CT_NAME_BUFFER_SIZE, def->table_def.new_name.str, def->table_def.new_name.len);
    } else {
        ret = strncpy_s(info->name, CT_NAME_BUFFER_SIZE, table->desc.name, strlen(table->desc.name));
    }
    knl_securec_check(ret);

    return CT_SUCCESS;
}

status_t knl_build_diff_info_when_copy(knl_session_t *session, knl_dictionary_t *new_dc,
                                       tablemeta_diff_info_t *info, uint64 new_version, knl_scn_t scn)
{
    table_t *table = DC_TABLE(new_dc);
    dc_context_t *ctx = &session->kernel->dc_ctx;
    errno_t ret;

    info->uid = table->desc.uid;
    info->tid = table->desc.id;
    info->obj_id = table->desc.oid;
    info->org_scn = new_dc->org_scn;
    info->version = new_version;
    info->ddl_type = ALTABLE_ADD_COLUMN;
    info->chg_scn = scn;
    info->invalid_scn = CT_INVALID_INT64;

    if (info->uid >= CT_MAX_USERS || ctx->users[info->uid] == NULL ||
        (session->drop_uid != info->uid && ctx->users[info->uid]->status != USER_STATUS_NORMAL)) {
        CT_THROW_ERROR(ERR_USER_NOT_EXIST, "");
        return CT_ERROR;
    }

    ret = strncpy_s(info->user_name, CT_NAME_BUFFER_SIZE, ctx->users[info->uid]->desc.name,
                    strlen(ctx->users[info->uid]->desc.name));
    knl_securec_check(ret);

    ret = strncpy_s(info->name, CT_NAME_BUFFER_SIZE, table->desc.name, strlen(table->desc.name));

    knl_securec_check(ret);

    return CT_SUCCESS;
}

bool32 knl_is_primary_column(uint32 column_id, table_t *table)
{
    for (uint32 i = 0; i < table->index_set.count; i++) {
        if (!table->index_set.items[i]->desc.primary) {
            continue;
        }
        for (uint32 j = 0; j < table->index_set.items[i]->desc.column_count; j++) {
            if (table->index_set.items[i]->desc.columns[j] == column_id) {
                return CT_TRUE;
            }
        }
    }
    return CT_FALSE;
}

void knl_meta_his_construct_info_prepare(knl_cursor_t *cursor, knl_dictionary_t *dc,
                                         knl_altable_def_t *def, columnmeta_his_info_t *his_info)
{
    text_t column_name = { .str = NULL, .len = 0 };
    text_t default_text = { .str = NULL, .len = 0 };
    table_t *table = DC_TABLE(dc);
    his_info->user_id = table->desc.uid;
    his_info->table_id = table->desc.id;
    his_info->object_id = table->desc.oid;
    his_info->column_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_ID);

    column_name.str = CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_NAME);
    column_name.len = CURSOR_COLUMN_SIZE(cursor, SYS_COLUMN_COL_NAME);
    knl_securec_check(strncpy_s(his_info->column_name, CT_NAME_BUFFER_SIZE, column_name.str, column_name.len));

    his_info->primary = knl_is_primary_column(his_info->column_id, table);
    his_info->changed = knl_meta_column_is_changed(def, dc, his_info->column_id);
    his_info->datatype = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_DATATYPE);
    his_info->size = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_BYTES);
    his_info->precision = *(int32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_PRECISION);
    his_info->scale = *(int32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_SCALE);
    his_info->nullable = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_NULLABLE);
    his_info->flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_FLAGS);
    his_info->collate_id = *(uint16 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_OPTIONS);
    his_info->mysql_ori_datatype = *(uint8 *)(CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_OPTIONS) + sizeof(uint16));
    his_info->mysql_unsigned = *(uint8 *)(CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_OPTIONS) +
                                          sizeof(uint16) + sizeof(uint8));

    default_text.str = CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_DEFAULT_TEXT);
    default_text.len = CURSOR_COLUMN_SIZE(cursor, SYS_COLUMN_COL_DEFAULT_TEXT);
    if (default_text.len != CT_NULL_VALUE_LEN) {
        his_info->has_default = CT_TRUE;
        knl_securec_check(strncpy_s(his_info->default_text, COLUMNMETA_HIS_DEFAULT_TEXT_MAX,
                                    default_text.str, default_text.len));
    }
}

status_t knl_meta_his_construct_info(knl_cursor_t *cursor, knl_altable_def_t *def, knl_dictionary_t *dc,
                                     lrepl_meta_mtrl_context_t *ctx, uint32 column_idx)
{
    columnmeta_his_info_t *his_info = NULL;
    uint32 id = CT_INVALID_ID32;
    uint32 next;
    vm_ctrl_t *ctrl = NULL;
    vm_page_t *curr_page = NULL;
    uint32 column_info_size = sizeof(columnmeta_his_info_t);
    mtrl_segment_t *segment = ctx->mtrl_ctx.segments[ctx->seg_id];
    uint32 page_id = (uint32)(column_idx / ((CT_VMEM_PAGE_SIZE - sizeof(mtrl_page_t)) / column_info_size));
    uint32 row_id = (uint32)(column_idx % ((CT_VMEM_PAGE_SIZE - sizeof(mtrl_page_t)) / column_info_size));
    id = segment->vm_list.first;
    while (page_id > 0) {
        ctrl = vm_get_ctrl(ctx->mtrl_ctx.pool, id);
        next = ctrl->next;
        id = next;
        page_id--;
    }

    if (mtrl_open_page(&ctx->mtrl_ctx, id, &curr_page) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[HEAP_META]: failed to open mtrl page, id = %u", id);
        return CT_ERROR;
    }

    mtrl_page_t *page = (mtrl_page_t *)curr_page->data;
    columnmeta_his_info_t *info_list = (columnmeta_his_info_t *)page;
    his_info = &info_list[row_id];

    knl_meta_his_construct_info_prepare(cursor, dc, def, his_info);

    mtrl_close_page(&ctx->mtrl_ctx, id);
    return CT_SUCCESS;
}

status_t knl_meta_his_get_columns(knl_session_t *session, tablemeta_diff_info_t *diff_info,
                                  knl_altable_def_t *def, knl_dictionary_t *dc,
                                  lrepl_meta_mtrl_context_t *ctx, uint32 *column_idx)
{
    knl_cursor_t *cursor = NULL;
    knl_match_cond_t org_match_cond = session->match_cond;
    lrepl_columnmeta_his_match_cond_t cond;
    status_t status = CT_SUCCESS;

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_COLUMN_ID, IX_SYS_COLUMN_001_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &diff_info->uid,
                     sizeof(uint32), IX_COL_SYS_COLUMN_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &diff_info->tid,
                     sizeof(uint32), IX_COL_SYS_COLUMN_001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_COLUMN_001_ID);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &diff_info->uid,
                     sizeof(uint32), IX_COL_SYS_COLUMN_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &diff_info->tid,
                     sizeof(uint32), IX_COL_SYS_COLUMN_001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_COLUMN_001_ID);

    cursor->stmt = (void *)&cond;
    session->match_cond = NULL;
    cond.cursor = cursor;
    cond.invisible = CT_FALSE;

    for (;;) {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (cursor->eof) {
            break;
        }

        if (knl_meta_his_construct_info(cursor, def, dc, ctx, *column_idx) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        (*column_idx)++;
    }

    knl_close_cursor(session, cursor);
    CM_RESTORE_STACK(session->stack);
    session->match_cond = org_match_cond;
    return status;
}

status_t knl_meta_mtrl_init(knl_session_t *session, uint32 page_cnt, lrepl_meta_mtrl_context_t *ctx)
{
    mtrl_init_context(&ctx->mtrl_ctx, session);

    if (mtrl_create_segment(&ctx->mtrl_ctx, MTRL_SEGMENT_TEMP, NULL, &ctx->seg_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (mtrl_open_segment(&ctx->mtrl_ctx, ctx->seg_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    mtrl_segment_t *segment = ctx->mtrl_ctx.segments[ctx->seg_id];
    mtrl_page_t *page = MTRL_CURR_PAGE(segment);
    errno_t ret = memset_sp(MTRL_WRITE_BEGIN_PTR(page), MTRL_PAGE_CAPACITY(page), 0, MTRL_PAGE_CAPACITY(page));
    knl_securec_check(ret);
    mtrl_close_page(&ctx->mtrl_ctx, segment->vm_list.last);

    for (uint32 i = 0; i < page_cnt - 1; i++) {
        if (knl_check_session_status(session) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (mtrl_extend_segment(&ctx->mtrl_ctx, segment) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (mtrl_open_page(&ctx->mtrl_ctx, segment->vm_list.last, &segment->curr_page) != CT_SUCCESS) {
            return CT_ERROR;
        }

        page = MTRL_CURR_PAGE(segment);
        mtrl_init_page(page, segment->vm_list.last);
        ret = memset_sp(MTRL_WRITE_BEGIN_PTR(page), MTRL_PAGE_CAPACITY(page), 0, MTRL_PAGE_CAPACITY(page));
        knl_securec_check(ret);
        mtrl_close_page(&ctx->mtrl_ctx, segment->vm_list.last);
    }

    return CT_SUCCESS;
}

status_t knl_meta_his_record(knl_session_t *session, knl_altable_def_t *def,
                             knl_dictionary_t *dc, tablemeta_diff_info_t *info)
{
    lrepl_meta_mtrl_context_t ctx = { 0 };
    uint32 column_count = knl_get_column_count(dc->handle);
    uint32 column_size = sizeof(columnmeta_his_info_t);
    uint32 real_count = 0;

    if (def != NULL && def->action == ALTABLE_ADD_COLUMN) {
        column_count += def->column_defs.count;
    }

    uint32 page_cnt = (uint32)(column_count / ((CT_VMEM_PAGE_SIZE - sizeof(mtrl_page_t)) / column_size) + 1);
    if (knl_meta_mtrl_init(session, page_cnt, &ctx) != CT_SUCCESS) {
        mtrl_release_context(&ctx.mtrl_ctx);
        return CT_ERROR;
    }

    if (knl_meta_his_get_columns(session, info, def, dc, &ctx, &real_count) != CT_SUCCESS) {
        mtrl_release_context(&ctx.mtrl_ctx);
        return CT_ERROR;
    }

    if (knl_meta_his_insert(session, info, &ctx, real_count) != CT_SUCCESS) {
        mtrl_release_context(&ctx.mtrl_ctx);
        return CT_ERROR;
    }

    mtrl_release_context(&ctx.mtrl_ctx);
    return CT_SUCCESS;
}

/*
 * when the meta data of a table changes:
 * insert overview of the new version into SYS.SYS_TABLEMETA_DIFF
 * insert details of the new version into SYS.SYS_COLUMNMETA_HIS
 */
status_t knl_meta_record(knl_session_t *session, knl_altable_def_t *def, knl_dictionary_t *dc, knl_scn_t scn)
{
    tablemeta_diff_info_t info = { 0 };
    uint64 version = 0;

    if (!knl_meta_need_record(session, def, dc)) {
        return CT_SUCCESS;
    }

    /* update the chg_scn of previous version */
    if (knl_meta_update_latest(session, dc->org_scn, &version, scn) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_meta_diff_construct_info(session, def, dc, &info, version, scn) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (knl_meta_diff_insert(session, &info, def, CT_FALSE, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_meta_his_record(session, def, dc, &info) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * when alter copy:
 * insert overview of the new version into SYS.SYS_TABLEMETA_DIFF
 * insert details of the new version into SYS.SYS_COLUMNMETA_HIS
 */
status_t knl_meta_record_when_copy(knl_session_t *session, knl_dictionary_t *old_dc,
                                   knl_dictionary_t *new_dc, knl_scn_t scn, bool32 is_rename_cross_db)
{
    tablemeta_diff_info_t info = { 0 };
    uint64 version = 0;

    if (!knl_meta_need_record(session, NULL, old_dc)) {
        return CT_SUCCESS;
    }

    /* update the chg_scn of previous version */
    if (knl_meta_update_latest(session, old_dc->org_scn, &version, scn) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_build_diff_info_when_copy(session, new_dc, &info,
                                      version, scn) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (knl_meta_diff_insert(session, &info, NULL, is_rename_cross_db, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_meta_his_record(session, NULL, new_dc, &info) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t knl_meta_diff_fetch(knl_session_t *session, knl_scn_t scn, tablemeta_diff_info_t *info)
{
    knl_dictionary_t dc;
    knl_cursor_t *cursor = NULL;
    text_t user_name = { .str = SYS_USER_NAME, .len = (uint32)strlen(SYS_USER_NAME) };
    text_t table_name = { .str = TABLEMETA_DIFF_TABLE_NAME, .len = (uint32)strlen(TABLEMETA_DIFF_TABLE_NAME) };

    if (dc_open(session, &user_name, &table_name, &dc) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[HEAP_META]: failed to open SYS.SYS_TABLEMETA_DIFF.");
        cm_reset_error();
        return CT_SUCCESS;
    }

    index_t *index = dc_find_index_by_id(DC_ENTITY(&dc), IX_TABLEMETA_DIFF003_ID);
    if (index == NULL) {
        dc_close(&dc);
        return CT_SUCCESS;
    }
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    cursor->scan_mode = SCAN_MODE_INDEX;
    cursor->action = CURSOR_ACTION_SELECT;
    cursor->index = index;
    cursor->index_slot = index->desc.id;
    cursor->index_only = CT_TRUE;
    knl_init_index_scan(cursor, CT_FALSE);

    if (knl_open_cursor(session, cursor, &dc) != CT_SUCCESS) {
        dc_close(&dc);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_TABLEMETA_DIFF003_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_TABLEMETA_DIFF003_VERSION);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_TABLEMETA_DIFF003_CHG_SCN);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_TABLEMETA_DIFF003_INVALID_SCN);

    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_TABLEMETA_DIFF003_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_TABLEMETA_DIFF003_VERSION);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_TABLEMETA_DIFF003_CHG_SCN);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_BIGINT, (void *)&scn,
                     sizeof(uint64), IX_COL_TABLEMETA_DIFF003_INVALID_SCN);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        dc_close(&dc);
        knl_close_cursor(session, cursor);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        dc_close(&dc);
        knl_close_cursor(session, cursor);
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    }

    info->org_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, IX_COL_TABLEMETA_DIFF003_ID);
    info->version = *(uint64 *)CURSOR_COLUMN_DATA(cursor, IX_COL_TABLEMETA_DIFF003_VERSION);
    info->chg_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, IX_COL_TABLEMETA_DIFF003_CHG_SCN);

    dc_close(&dc);
    knl_close_cursor(session, cursor);
    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

status_t knl_meta_diff_delete(knl_session_t *session, tablemeta_diff_info_t *info)
{
    knl_dictionary_t dc;
    knl_cursor_t *cursor = NULL;
    text_t user_name = { .str = SYS_USER_NAME, .len = (uint32)strlen(SYS_USER_NAME) };
    text_t table_name = { .str = TABLEMETA_DIFF_TABLE_NAME, .len = (uint32)strlen(TABLEMETA_DIFF_TABLE_NAME) };
    status_t status = CT_SUCCESS;

    if (dc_open(session, &user_name, &table_name, &dc) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[HEAP_META]: failed to open SYS.SYS_TABLEMETA_DIFF.");
        cm_reset_error();
        return CT_SUCCESS;
    }

    index_t *index = dc_find_index_by_id(DC_ENTITY(&dc), IX_TABLEMETA_DIFF001_ID);
    if (index == NULL) {
        dc_close(&dc);
        return CT_SUCCESS;
    }
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    cursor->scan_mode = SCAN_MODE_INDEX;
    cursor->action = CURSOR_ACTION_DELETE;
    cursor->index = index;
    cursor->index_slot = index->desc.id;
    cursor->index_only = CT_TRUE;
    knl_init_index_scan(cursor, CT_TRUE);

    if (knl_open_cursor(session, cursor, &dc) != CT_SUCCESS) {
        dc_close(&dc);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, (void *)&info->org_scn,
                     sizeof(uint64), IX_COL_TABLEMETA_DIFF001_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, (void *)&info->version,
                     sizeof(uint64), IX_COL_TABLEMETA_DIFF001_VERSION);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, (void *)&info->chg_scn,
                     sizeof(uint64), IX_COL_TABLEMETA_DIFF001_CHG_SCN);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_BIGINT, (void *)&info->org_scn,
                     sizeof(uint64), IX_COL_TABLEMETA_DIFF001_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_BIGINT, (void *)&info->version,
                     sizeof(uint64), IX_COL_TABLEMETA_DIFF001_VERSION);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_BIGINT, (void *)&info->chg_scn,
                     sizeof(uint64), IX_COL_TABLEMETA_DIFF001_CHG_SCN);

    do {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (cursor->eof) {
            status = CT_SUCCESS;
            break;
        }

        if (knl_internal_delete(session, cursor) != CT_SUCCESS) {
            status = CT_ERROR;
        }
    } while (0);
    dc_close(&dc);
    knl_close_cursor(session, cursor);
    CM_RESTORE_STACK(session->stack);

    return status;
}

status_t knl_meta_his_delete(knl_session_t *session, tablemeta_diff_info_t *info)
{
    knl_dictionary_t dc;
    knl_cursor_t *cursor = NULL;
    text_t user_name = { .str = SYS_USER_NAME, .len = (uint32)strlen(SYS_USER_NAME) };
    text_t table_name = { .str = COLUMNMETA_HIS_TABLE_NAME, .len = (uint32)strlen(COLUMNMETA_HIS_TABLE_NAME) };
    status_t status = CT_SUCCESS;

    if (dc_open(session, &user_name, &table_name, &dc) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[HEAP_META]: failed to open SYS.SYS_COLUMNMETA_HIS.");
        cm_reset_error();
        return CT_SUCCESS;
    }

    index_t *index = dc_find_index_by_id(DC_ENTITY(&dc), IX_COLUMNMETA_HIS001_ID);
    if (index == NULL) {
        dc_close(&dc);
        return CT_SUCCESS;
    }
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    cursor->scan_mode = SCAN_MODE_INDEX;
    cursor->action = CURSOR_ACTION_DELETE;
    cursor->index = index;
    cursor->index_slot = index->desc.id;
    cursor->index_only = CT_TRUE;
    knl_init_index_scan(cursor, CT_FALSE);

    if (knl_open_cursor(session, cursor, &dc) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        dc_close(&dc);
        return CT_ERROR;
    }

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, (void *)&info->org_scn,
                     sizeof(uint64), IX_COL_COLUMNMETA_HIS001_ORG_SCN);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, (void *)&info->version,
                     sizeof(uint64), IX_COL_COLUMNMETA_HIS001_VERSION);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_COLUMNMETA_HIS001_COLUMN_ID);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_BIGINT, (void *)&info->org_scn,
                     sizeof(uint64), IX_COL_COLUMNMETA_HIS001_ORG_SCN);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_BIGINT, (void *)&info->version,
                     sizeof(uint64), IX_COL_COLUMNMETA_HIS001_VERSION);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_COLUMNMETA_HIS001_COLUMN_ID);

    for (;;) {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            status = CT_SUCCESS;
            break;
        }

        if (cursor->eof) {
            break;
        }

        if (knl_internal_delete(session, cursor) != CT_SUCCESS) {
            status = CT_SUCCESS;
            break;
        }
    }
    dc_close(&dc);
    knl_close_cursor(session, cursor);
    CM_RESTORE_STACK(session->stack);

    return status;
}

status_t knl_meta_delete(knl_session_t *session, knl_scn_t scn)
{
    CT_LOG_RUN_INF("[HEAP_META]: Start to clean meta sys table, arch scn %llu", (uint64)scn);
    tablemeta_diff_info_t info = { 0 };
    status_t status = CT_SUCCESS;

    if (scn == CT_INVALID_ID64) {
        return CT_SUCCESS;
    }

    do {
        info.org_scn = KNL_INVALID_SCN;
        if (knl_check_session_status(session) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (knl_meta_diff_fetch(session, scn, &info) != CT_SUCCESS) {
            status = CT_ERROR;
        }

        if (info.org_scn == KNL_INVALID_SCN) {
            break;
        }

        if (knl_meta_diff_delete(session, &info) != CT_SUCCESS) {
            status = CT_ERROR;
        }
        if (knl_meta_his_delete(session, &info) != CT_SUCCESS) {
            status = CT_ERROR;
        }

        if (status == CT_SUCCESS) {
            knl_commit(session);
        } else {
            knl_rollback(session, NULL);
            break;
        }
    } while (1);

    CT_LOG_RUN_INF("[HEAP_META]: Finish clean meta sys table");
    return status;
}
