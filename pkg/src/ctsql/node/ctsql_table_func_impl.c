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
 * ctsql_table_func_impl.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/node/ctsql_table_func_impl.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_hash.h"
#include "dml_executor.h"
#include "pl_context.h"
#include "knl_interface.h"
#include "ctsql_func.h"
#include "ctsql_package.h"
#include "srv_instance.h"
#include "knl_dc.h"
#include "knl_page.h"
#include "expr_parser.h"
#include "ctsql_privilege.h"
#include "cm_memory.h"
#include "pl_compiler.h"
#include "pl_executor.h"
#include "ctsql_mtrl.h"
#include "knl_fbdr.h"
#include "ctsql_table_func.h"
#include "pl_dbg_tab_func.h"
#include "knl_temp_space.h"
#include "dtc_dls.h"

#define CONTROL_ITEM_NUM 11
#define PARAL_RAGNE_ROW_SIZE (sizeof(uint32) + 2 * sizeof(uint64))
#define ARG_NUM_FOR_INSERT_DIST_DDL 8

typedef enum en_dba_analyze_id {
    TOTAL_PAGES = 0,
    TOTAL_EXTENTS,
    TOTAL_ROWS,
    LINKED_ROWS,
    MIRGATED_ROWS,
    AVG_ROW_SIZE,
    DBA_ANALYZE_COUNT,
} dba_analyze_id_t;

typedef struct dba_analyze_item {
    char *name;
} dba_analyze_item_t;

static dba_analyze_item_t g_dba_analyze_items[] = {
    { "total pages" },
    { "total extents" },
    { "total rows" },
    { "linked rows" },
    { "mirgated rows" },
    { "average row size" },
};

static status_t table_cast_check(variant_t *value, expr_tree_t *arg2)
{
    plv_collection_t *collection = NULL;
    plv_collection_t *type_coll = (plv_collection_t *)arg2->root->udt_type;
    if (!value->is_null && value->type != CT_TYPE_COLLECTION) {
        CT_THROW_ERROR(ERR_PLSQL_VALUE_ERROR_FMT, " cannot access rows from a non-nested table item");
        return CT_ERROR;
    }
    collection = (plv_collection_t *)value->v_collection.coll_meta;
    if (collection == NULL || !collection->is_global) {
        CT_THROW_ERROR(ERR_FUNC_ARGUMENT_WRONG_TYPE, 1, "global collection");
        return CT_ERROR;
    }
    if (collection->attr_type == UDT_COLLECTION) {
        CT_THROW_ERROR(ERR_PLSQL_VALUE_ERROR_FMT, "the 1st-arg's data type in cast func is not supported");
        return CT_ERROR;
    }
    if (collection->attr_type != type_coll->attr_type) {
        CT_THROW_ERROR(ERR_PLSQL_VALUE_ERROR_FMT, "the args datatype in cast func is not matched");
        return CT_ERROR;
    }
    if (collection->attr_type == UDT_SCALAR &&
        (!var_datatype_matched(collection->type_mode.datatype, type_coll->type_mode.datatype) ||
        arg2->root->value.v_type.is_array == CT_TRUE)) {
        CT_THROW_ERROR(ERR_TYPE_MISMATCH, get_datatype_name_str(collection->type_mode.datatype),
            get_datatype_name_str(TREE_DATATYPE(arg2)));
        return CT_ERROR;
    }
    if (collection->attr_type == UDT_OBJECT && type_coll != collection) {
        CT_THROW_ERROR(ERR_PLSQL_VALUE_ERROR_FMT, "the 2nd-arg's object data type should equal to 1st-arg's type");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t table_cast_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur)
{
    variant_t value, temp;
    expr_tree_t *arg1 = func->args;
    expr_tree_t *arg2 = func->args->next;
    plv_collection_t *type_coll = (plv_collection_t *)arg2->root->udt_type;

    SQL_EXEC_FUNC_ARG(arg1, &value, &temp, stmt);
    if (arg1->root->type == EXPR_NODE_PARAM) {
        if (value.type != CT_TYPE_COLLECTION && value.type != CT_TYPE_ARRAY) {
            CT_THROW_ERROR(ERR_TYPE_MISMATCH, get_datatype_name_str(CT_TYPE_COLLECTION),
                get_datatype_name_str(value.type));
            return CT_ERROR;
        }
    }
    if (value.type == CT_TYPE_ARRAY) {
        CT_RETURN_IFERR(ple_array_as_collection(stmt, &value, (void *)type_coll));
    }
    CT_RETURN_IFERR(table_cast_check(&value, arg2));
    MEMS_RETURN_IFERR(memcpy_s(cur->page_buf, sizeof(variant_t), &value, sizeof(variant_t)));
    cur->rowid.vmid = 0;
    return CT_SUCCESS;
}

status_t table_cast_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur)
{
    expr_tree_t *arg1 = func->args;
    row_assist_t ra;

    plv_collection_t *collection = (plv_collection_t *)arg1->next->root->udt_type;
    uint32 col;
    col = (collection->attr_type == UDT_OBJECT) ? UDT_GET_TYPE_DEF_OBJECT(collection->elmt_type)->count : 1;
    row_init(&ra, (char *)cur->row, CT_MAX_ROW_SIZE, col);
    return table_cast_fetch_core(stmt, func, cur, &ra);
}

status_t pl_try_find_global_decl(sql_stmt_t *stmt, expr_tree_t *arg, plv_decl_t **decl)
{
    var_udo_t obj;
    pl_dc_t type_dc;
    bool32 found = CT_FALSE;

    CT_RETURN_IFERR(pl_get_type_name(stmt, arg, &obj));
    CT_RETURN_IFERR(pl_try_find_type_dc(stmt, &obj, &type_dc, &found));
    if (found) {
        *decl = type_dc.entity->type_spec->decl;
    } else {
        *decl = NULL;
    }
    return CT_SUCCESS;
}

status_t table_cast_verify(sql_verifier_t *verf, sql_table_t *table)
{
    table_func_t *func = &table->func;
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    plv_decl_t *decl = NULL;
    arg1 = func->args;
    CT_RETURN_IFERR(table_func_verify(verf, func, 2, 2));
    arg2 = arg1->next;

    if (arg1->root->type != EXPR_NODE_PARAM && arg1->root->datatype != CT_TYPE_COLLECTION &&
        !arg1->root->typmod.is_array) {
        CT_THROW_ERROR(ERR_TYPE_MISMATCH, "PLSQL INDEX TABLE", get_datatype_name_str(arg1->root->datatype));
        return CT_ERROR;
    }
    CT_RETURN_IFERR(pl_try_find_global_decl(verf->stmt, arg2, &decl));
    if (decl != NULL && decl->typdef.type == PLV_COLLECTION) {
        if (decl->typdef.collection.attr_type == UDT_COLLECTION || decl->typdef.collection.attr_type == UDT_RECORD) {
            CT_THROW_ERROR(ERR_PLSQL_VALUE_ERROR_FMT, "the 2nd-arg's data type in cast func is not supported");
            return CT_ERROR;
        }
        arg2->root->datatype = CT_TYPE_COLLECTION;
        arg2->root->udt_type = &decl->typdef.collection;
    } else {
        CT_THROW_ERROR(ERR_FUNC_ARGUMENT_WRONG_TYPE, 2, "global collection");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t dba_analyze_tab_args(sql_stmt_t *stmt, table_func_t *func, text_t *user, text_t *table)
{
    variant_t var;
    variant_t new_var;
    session_t *session = stmt->session;

    CT_RETURN_IFERR(sql_exec_expr(stmt, func->args, &var));
    CT_RETURN_IFERR(sql_convert_variant(stmt, &var, CT_TYPE_STRING));
    if (var.is_null) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "", "user name can not be null");
        return CT_ERROR;
    }
    // copy variant because v_text.str may from sql_context
    sql_keep_stack_variant(stmt, &var);
    CT_RETURN_IFERR(var_deep_copy(&var, &new_var, (var_malloc_t)cm_push, (var_malloc_handle_t *)stmt->session->stack));
    *user = new_var.v_text;
    cm_text_upper(user);
    CT_RETURN_IFERR(sql_exec_expr(stmt, func->args->next, &var));
    CT_RETURN_IFERR(sql_convert_variant(stmt, &var, CT_TYPE_STRING));

    if (var.is_null || var.v_text.len == 0) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "", "the table name's length must be larger than 0");
        return CT_ERROR;
    }

    sql_keep_stack_variant(stmt, &var);
    CT_RETURN_IFERR(var_deep_copy(&var, &new_var, (var_malloc_t)cm_push, (var_malloc_handle_t *)stmt->session->stack));
    *table = new_var.v_text;
    process_name_case_sensitive(table);
    if (!cm_text_equal(&session->curr_user, user) && !sql_user_is_dba(session)) {
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t dba_analyze_tab_part(uint64 *stats, sql_stmt_t *stmt, knl_dictionary_t *dc, knl_cursor_t *knl_cur)
{
    uint32 pages, page_size, extents;

    while (!knl_cur->eof) {
        if (knl_fetch(KNL_SESSION(stmt), knl_cur) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (knl_cur->eof) {
            break;
        }
        stats[AVG_ROW_SIZE] += knl_cur->row->size;
        stats[TOTAL_ROWS]++;
        if (knl_cur->chain_count == 1) {
            stats[MIRGATED_ROWS]++;
        } else if (knl_cur->chain_count > 1) {
            stats[LINKED_ROWS]++;
        }
    }
    if (knl_get_segment_size_by_cursor(KNL_SESSION(stmt), knl_cur, &extents, &pages, &page_size) != CT_SUCCESS) {
        return CT_ERROR;
    }
    stats[TOTAL_PAGES] += (int64)pages;
    stats[TOTAL_EXTENTS] += (int64)extents;
    return CT_SUCCESS;
}

static status_t dba_analyze_parted_tab(uint64 *stats, sql_stmt_t *stmt, knl_dictionary_t *dc, knl_cursor_t *knl_cur)
{
    table_t *table_dc = DC_TABLE(dc);
    table_part_t *table_part = NULL;
    table_part_t *table_subpart = NULL;
    knl_part_locate_t part_locate;

    for (uint32 part_no = 0; part_no < table_dc->part_table->desc.partcnt; part_no++) {
        table_part = TABLE_GET_PART(table_dc, part_no);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        if (!IS_PARENT_TABPART(&table_part->desc)) {
            part_locate.part_no = part_no;
            part_locate.subpart_no = CT_INVALID_ID32;

            knl_set_table_part(knl_cur, part_locate);
            CT_RETURN_IFERR(knl_reopen_cursor(KNL_SESSION(stmt), knl_cur, dc));
            CT_RETURN_IFERR(dba_analyze_tab_part(stats, stmt, dc, knl_cur));
            continue;
        }

        for (uint32 sub_part_no = 0; sub_part_no < table_part->desc.subpart_cnt; sub_part_no++) {
            table_subpart = PART_GET_SUBENTITY(table_dc->part_table, table_part->subparts[sub_part_no]);
            if (table_subpart == NULL) {
                continue;
            }

            part_locate.part_no = part_no;
            part_locate.subpart_no = sub_part_no;

            knl_set_table_part(knl_cur, part_locate);

            CT_RETURN_IFERR(knl_reopen_cursor(KNL_SESSION(stmt), knl_cur, dc));
            CT_RETURN_IFERR(dba_analyze_tab_part(stats, stmt, dc, knl_cur));
        }
    }
    return CT_SUCCESS;
}

static status_t dba_analyze_normal_tab(uint64 *stats, sql_stmt_t *stmt, knl_dictionary_t *knl_dc, knl_cursor_t *knl_cur)
{
    return dba_analyze_tab_part(stats, stmt, knl_dc, knl_cur);
}

status_t dba_analyze_table_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur)
{
    uint64 *stats = (uint64 *)cur->page_buf;
    table_t *table_dc = NULL;
    knl_cursor_t *knl_cur = NULL;
    knl_dictionary_t dc;
    text_t user, table;
    status_t ret;

    cur->rowid.vmid = 0;
    cur->rowid.vm_slot = 0;
    MEMS_RETURN_IFERR(memset_s(stats, sizeof(uint64) * DBA_ANALYZE_COUNT, 0, sizeof(uint64) * DBA_ANALYZE_COUNT));
    // scan table full
    CT_RETURN_IFERR(dba_analyze_tab_args(stmt, func, &user, &table));

    CT_RETURN_IFERR(knl_open_dc(KNL_SESSION(stmt), &user, &table, &dc));

    if (dc.type == DICT_TYPE_UNKNOWN || dc.type >= DICT_TYPE_VIEW) {
        CT_THROW_ERROR(ERR_UNSUPPORT_FUNC, "dba_analyze_table", "non-table query");
        knl_close_dc(&dc);
        return CT_ERROR;
    }

    CTSQL_SAVE_STACK(stmt);

    if (sql_push_knl_cursor(&stmt->session->knl_session, &knl_cur) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        knl_close_dc(&dc);
        return CT_ERROR;
    }

    knl_cur->scan_mode = SCAN_MODE_TABLE_FULL;
    knl_cur->index_slot = INVALID_INDEX_SLOT;
    knl_cur->action = CURSOR_ACTION_SELECT;

    if (knl_open_cursor(KNL_SESSION(stmt), knl_cur, &dc) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        knl_close_dc(&dc);
        return CT_ERROR;
    }

    table_dc = DC_TABLE(&dc);
    do {
        ret = IS_PART_TABLE(table_dc) ? dba_analyze_parted_tab(stats, stmt, &dc, knl_cur) :
                                        dba_analyze_normal_tab(stats, stmt, &dc, knl_cur);
        CT_BREAK_IF_ERROR(ret);

        if (stats[TOTAL_ROWS] != 0) {
            stats[AVG_ROW_SIZE] = stats[AVG_ROW_SIZE] / stats[TOTAL_ROWS];
        }
    } while (0);

    CTSQL_RESTORE_STACK(stmt);
    knl_close_cursor(KNL_SESSION(stmt), knl_cur);
    knl_close_dc(&dc);

    return ret;
}

status_t dba_analyze_table_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur)
{
    uint32 id = (uint32)cur->rowid.vmid;
    uint64 *stats = (uint64 *)cur->page_buf;
    row_assist_t ra;
    // calc args
    if ((func->args == NULL) || (cur->rowid.vmid >= DBA_ANALYZE_COUNT)) {
        cur->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&ra, (char *)cur->row, CT_MAX_ROW_SIZE, ARRAY_IN(g_analyze_table_columns));
    CT_RETURN_IFERR(row_put_str(&ra, g_dba_analyze_items[id].name));
    CT_RETURN_IFERR(row_put_int64(&ra, (int64)stats[id]));
    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);
    cur->rowid.vmid++;
    return CT_SUCCESS;
}

status_t dba_analyze_table_verify(sql_verifier_t *verf, sql_table_t *table)
{
    return table_func_verify(verf, &table->func, 2, 2);
}

status_t dba_fbdr_2pc_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor)
{
    fbdr_handler_t *handler = (fbdr_handler_t *)cursor->key;
    if (fbdr_fetch(handler) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cursor->eof) {
        return CT_SUCCESS;
    }

    cursor->row = (row_head_t *)cursor->page_buf;
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    return CT_SUCCESS;
}

status_t dba_fbdr_2pc_verify(sql_verifier_t *verf, sql_table_t *table)
{
    const uint16 min_args = 2;
    const uint16 max_args = 2;
    CT_RETURN_IFERR(table_func_verify(verf, &table->func, min_args, max_args));

    return CT_SUCCESS;
}

static status_t dba_page_corruption_check_status(sql_stmt_t *stmt, table_func_t *func)
{
    knl_session_t *knl_session = &stmt->session->knl_session;
    /* Current user should be dba */
    if (!sql_user_is_dba(stmt->session)) {
        CT_SRC_THROW_ERROR(func->loc, ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }

    if (!(DB_IS_OPEN(knl_session))) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", this table function is not supported when database is not open.");
        return CT_ERROR;
    }

    if (DB_IS_CHECKSUM_OFF(knl_session)) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION,
            ", database checksum is off, this table function is not supported when DB_BLOCK_CHECKSUM is OFF.");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t dba_page_corruption_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur)
{
    if (dba_page_corruption_check_status(stmt, func) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_session_t *knl_session = &stmt->session->knl_session;
    variant_t type, common_id, page_id; // common_id could be space id or file id
    page_corrupt_type_t pc_type;
    uint32 space_id = SYS_SPACE_ID;

    cur->rowid.value = 0;
    cur->rowid.unused1 = 0;

    expr_tree_t *arg1 = func->args;
    CT_RETURN_IFERR(sql_exec_tablefunc_arg(stmt, arg1, &type, CT_TYPE_STRING, CT_TRUE));
    CT_RETURN_IFERR(get_page_corruption_scan_type(&type.v_text, &pc_type));

    expr_tree_t *arg2 = arg1->next;
    expr_tree_t *arg3 = NULL;
    if (arg2 != NULL) {
        CT_RETURN_IFERR(sql_exec_tablefunc_arg(stmt, arg2, &common_id, CT_TYPE_INTEGER, CT_TRUE));
        TBL_FUNC_RETURN_IF_INT_NEGATIVE(common_id);
        arg3 = arg2->next;
        if (arg3 != NULL) {
            CT_RETURN_IFERR(sql_exec_tablefunc_arg(stmt, arg3, &page_id, CT_TYPE_INTEGER, CT_TRUE));
            TBL_FUNC_RETURN_IF_INT_NEGATIVE(page_id);
            if (page_id.v_uint32 >= CT_MAX_DATAFILE_PAGES) {
                CT_THROW_ERROR_EX(ERR_INVALID_FUNC_PARAMS, "page id should be less than max datafile page id(%u)",
                    CT_MAX_DATAFILE_PAGES);
                return CT_ERROR;
            }
            cur->rowid.page = page_id.v_uint32;
        }
    }

    if (!pc_verify_parameter_combination(pc_type, arg2, arg3)) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "invalid argument combination for table function "
            "dba_page_corruption");
        return CT_ERROR;
    }

    if (!pc_verify_value_vaild(knl_session, cur, pc_type, &common_id, &space_id)) {
        return CT_ERROR;
    }

    pc_init_cursor_pagebuf(cur, pc_type, space_id);

    cur->eof = CT_FALSE;
    return CT_SUCCESS;
}

status_t dba_page_corruption_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur)
{
    knl_session_t *session = &stmt->session->knl_session;
    pc_buf_head_t *buf_head = (pc_buf_head_t *)(cur->page_buf);
    page_corrupt_type_t scan_type = buf_head->pc_type;
    status_t status = CT_SUCCESS;

    if (scan_type == PC_PAGE) {
        if (buf_head->page_id != cur->rowid.page) {
            cur->eof = CT_TRUE;
            return CT_SUCCESS;
        }
        status = dba_page_corruption_scan(session, cur);
    } else {
        if (scan_type == PC_DATABASE) {
            pc_update_db_position(session, cur);
        } else if (scan_type == PC_TABLESPACE) {
            pc_update_spc_position(session, buf_head->space_id, cur);
        } else if (scan_type == PC_DATAFILE) {
            pc_update_df_position(session, buf_head->file_id, cur);
        }

        if (cur->eof == CT_TRUE) {
            return CT_SUCCESS;
        }

        status = dba_file_corruption_scan(session, cur);
    }
    return status;
}

status_t dba_page_corruption_verify(sql_verifier_t *verif, sql_table_t *table)
{
    return table_func_verify(verif, &table->func, 1, 3);
}

status_t dba_table_corruption_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur)
{
    knl_dictionary_t dc;
    variant_t var;
    session_t *session = stmt->session;
    bool8 is_corrupt = CT_FALSE;

    CT_RETURN_IFERR(sql_exec_expr(stmt, func->args, &var));
    CT_RETURN_IFERR(sql_convert_variant(stmt, &var, CT_TYPE_STRING));
    if (var.is_null) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "", "user name can not be null");
        return CT_ERROR;
    }

    text_t user = var.v_text;
    cm_text_upper(&user);
    CT_RETURN_IFERR(sql_exec_expr(stmt, func->args->next, &var));
    CT_RETURN_IFERR(sql_convert_variant(stmt, &var, CT_TYPE_STRING));

    if (var.is_null || var.v_text.len == 0) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "", "the table name's length must be larger than 0");
        return CT_ERROR;
    }
    text_t table = var.v_text;

    process_name_case_sensitive(&table);
    if (!cm_text_equal(&session->curr_user, &user) && !sql_user_is_dba(session)) {
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }

    if (knl_open_dc(session, &user, &table, &dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc.type == DICT_TYPE_UNKNOWN || dc.type >= DICT_TYPE_VIEW) {
        CT_THROW_ERROR(ERR_UNSUPPORT_FUNC, "dba_table_corruption", "non-table query");
        knl_close_dc(&dc);
        return CT_ERROR;
    }

    if (IS_LTT_BY_NAME(table.str)) {
        CT_THROW_ERROR(ERR_UNSUPPORT_FUNC, "dba_table_corruption", "local temporary table query");
        knl_close_dc(&dc);
        return CT_ERROR;
    }

    cur->rowid.page = 0;
    if (dba_verify_table(KNL_SESSION(stmt), cur, &dc, &is_corrupt) != CT_SUCCESS) {
        knl_close_dc(&dc);
        return CT_ERROR;
    }

    knl_close_dc(&dc);
    cur->eof = !is_corrupt;

    return CT_SUCCESS;
}

status_t dba_table_corruption_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur)
{
    if (cur->rowid.page == 0) {
        cur->rowid.page++;
        return CT_SUCCESS;
    }
    cur->eof = CT_TRUE;

    return CT_SUCCESS;
}

status_t dba_table_corruption_verify(sql_verifier_t *verif, sql_table_t *table)
{
    return table_func_verify(verif, &table->func, 2, 2);
}

status_t dba_index_corruption_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur)
{
    knl_dictionary_t dc;
    variant_t var;
    session_t *session = stmt->session;
    bool8 is_corrupt = CT_FALSE;

    CT_RETURN_IFERR(sql_exec_expr(stmt, func->args, &var));
    CT_RETURN_IFERR(sql_convert_variant(stmt, &var, CT_TYPE_STRING));
    if (var.is_null) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "USER", "user name can not be null");
        return CT_ERROR;
    }

    text_t user = var.v_text;
    cm_text_upper(&user);
    CT_RETURN_IFERR(sql_exec_expr(stmt, func->args->next, &var));
    CT_RETURN_IFERR(sql_convert_variant(stmt, &var, CT_TYPE_STRING));

    if (var.is_null || var.v_text.len == 0) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "INDEX", "the index name's length must be larger than 0");
        return CT_ERROR;
    }
    text_t index_name = var.v_text;

    process_name_case_sensitive(&index_name);

    if (index_name.len > CT_MAX_NAME_LEN) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "INDEX", "the index name's length must less than 64");
        return CT_ERROR;
    }

    if (!cm_text_equal(&session->curr_user, &user) && !sql_user_is_dba(session)) {
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }

    if (knl_open_dc_by_index(stmt->session, &user, NULL, &index_name, &dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc.type == DICT_TYPE_UNKNOWN || dc.type >= DICT_TYPE_VIEW) {
        CT_THROW_ERROR(ERR_UNSUPPORT_FUNC, "dba_index_corruption", "non-table query");
        knl_close_dc(&dc);
        return CT_ERROR;
    }

    cur->rowid.page = 0;

    if (dba_verify_index_by_name(&session->knl_session, cur, &dc, &index_name, &is_corrupt) != CT_SUCCESS) {
        knl_close_dc(&dc);
        return CT_ERROR;
    }

    knl_close_dc(&dc);

    cur->eof = !is_corrupt;

    return CT_SUCCESS;
}

status_t dba_index_corruption_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur)
{
    if (cur->rowid.page == 0) {
        cur->rowid.page++;
        return CT_SUCCESS;
    }

    cur->eof = CT_TRUE;

    return CT_SUCCESS;
}

status_t dba_index_corruption_verify(sql_verifier_t *verif, sql_table_t *table)
{
    return table_func_verify(verif, &table->func, 2, 2);
}

status_t dba_proc_decode_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor)
{
    dba_proc_decode_t *stats = (dba_proc_decode_t *)cursor->page_buf;
    pl_dc_t pl_dc;
    variant_t user, object, type;
    pl_line_ctrl_t *line_ctrl = NULL;
    pl_line_ctrl_t *start_ctrl = NULL;
    uint32 line_num, max_line_num;
    pl_line_type_t line_type;
    pl_entity_t *entity = NULL;
    var_udo_t var_udo;
    uint32 pl_type;
    dba_proc_buf_info_t buf_info;
    session_t *session = stmt->session;
    bool32 exist = CT_FALSE;
    status_t status;
    source_location_t loc = { 1, 1 };
    pl_dc_assist_t assist = { 0 };

    CTSQL_SAVE_STACK(stmt);
    status = CT_ERROR;
    do {
        expr_tree_t *arg1 = func->args;
        CT_BREAK_IF_ERROR(sql_exec_tablefunc_arg(stmt, arg1, &user, CT_TYPE_STRING, CT_TRUE));
        sql_keep_stack_variant(stmt, &user);
        expr_tree_t *arg2 = arg1->next;
        CT_BREAK_IF_ERROR(sql_exec_tablefunc_arg(stmt, arg2, &object, CT_TYPE_STRING, CT_TRUE));
        sql_keep_stack_variant(stmt, &object);
        expr_tree_t *arg3 = arg2->next;
        CT_BREAK_IF_ERROR(sql_exec_tablefunc_arg(stmt, arg3, &type, CT_TYPE_STRING, CT_TRUE));
        sql_keep_stack_variant(stmt, &type);

        if (user.v_text.len > CT_MAX_NAME_LEN) {
            CT_THROW_ERROR(ERR_NAME_TOO_LONG, "user", user.v_text.len, CT_MAX_NAME_LEN);
            break;
        }

        if (object.v_text.len > CT_MAX_NAME_LEN) {
            CT_THROW_ERROR(ERR_NAME_TOO_LONG, "object", object.v_text.len, CT_MAX_NAME_LEN);
            break;
        }

        if (!cm_text_equal(&session->curr_user, &user.v_text) && !sql_user_is_dba(session)) {
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            break;
        }
        cm_text_upper_self_name(&type.v_text);
        CT_BREAK_IF_ERROR(pld_get_pl_type(&type.v_text, &pl_type));

        var_udo.name = object.v_text;
        var_udo.user = user.v_text;
        var_udo.pack.str = NULL;
        var_udo.pack.len = 0;
        cm_text_upper(&var_udo.user);
        process_name_case_sensitive(&var_udo.name);

        pl_dc_open_prepare_for_ignore_priv(&assist, stmt, &var_udo.user, &var_udo.name, pl_type);
        CT_BREAK_IF_ERROR(pl_dc_open(&assist, &pl_dc, &exist));
        if (!exist) {
            pl_unfound_error(stmt, &var_udo, &loc, pl_type);
            status = CT_ERROR;
            break;
        }

        status = CT_SUCCESS;
    } while (0);
    CTSQL_RESTORE_STACK(stmt);
    CT_RETURN_IFERR(status);

    entity = pl_dc.entity;
    start_ctrl = (pl_line_ctrl_t *)entity->function->body;

    proc_decode_get_max_line_num(start_ctrl, &max_line_num);
    buf_info.offset = max_line_num * sizeof(dba_proc_decode_t) + sizeof(uint32);
    if (knl_get_page_size((knl_handle_t)&stmt->session->knl_session, &buf_info.max_size) != CT_SUCCESS) {
        pl_dc_close(&pl_dc);
        return CT_ERROR;
    }
    if (buf_info.offset >= buf_info.max_size) {
        pl_dc_close(&pl_dc);
        CT_THROW_ERROR(ERR_TYPE_OVERFLOW, "Memory used by decode results");
        return CT_ERROR;
    }
    buf_info.buf = cursor->page_buf;
    buf_info.is_full = CT_FALSE;

    line_ctrl = start_ctrl;
    line_num = 0;
    while (line_ctrl != NULL) {
        proc_decode_default_sp(line_ctrl, &stats[line_num], &buf_info);
        line_type = line_ctrl->type;
        switch (line_type) {
            case LINE_BEGIN:
                proc_decode_begin_sp(start_ctrl, line_ctrl, &stats[line_num], &buf_info);
                break;
            case LINE_IF:
                proc_decode_if_sp(start_ctrl, line_ctrl, &stats[line_num], &buf_info);
                break;
            case LINE_ELSE:
                proc_decode_else_sp(start_ctrl, line_ctrl, &stats[line_num], &buf_info);
                break;
            case LINE_ELIF:
                proc_decode_elsif_sp(start_ctrl, line_ctrl, &stats[line_num], &buf_info);
                break;
            case LINE_WHEN_CASE:
                proc_decode_when_case_sp(start_ctrl, line_ctrl, &stats[line_num], &buf_info);
                break;
            case LINE_END_LOOP:
                proc_decode_end_loop_sp(start_ctrl, line_ctrl, &stats[line_num], &buf_info);
                break;
            case LINE_EXIT:
                proc_decode_exit_sp(start_ctrl, line_ctrl, &stats[line_num], &buf_info);
                break;
            case LINE_GOTO:
                proc_decode_goto_sp(start_ctrl, line_ctrl, &stats[line_num], &buf_info);
                break;
            case LINE_CONTINUE:
                proc_decode_continue_sp(start_ctrl, line_ctrl, &stats[line_num], &buf_info);
                break;
            case LINE_WHILE:
                proc_decode_while_sp(start_ctrl, line_ctrl, &stats[line_num], &buf_info);
                break;
            case LINE_FOR:
                proc_decode_for_sp(start_ctrl, line_ctrl, &stats[line_num], &buf_info);
                break;
            case LINE_EXCEPTION:
                proc_decode_except_sp(start_ctrl, line_ctrl, &stats[line_num], &buf_info);
                break;
            default:
                break;
        }
        stats[line_num].line_num = line_num + 1;

        line_ctrl = line_ctrl->next;
        line_num++;
    }
    pl_dc_close(&pl_dc);

    stats[line_num].line_num = CT_INVALID_ID32;
    cursor->rowid.vmid = 0;

    return CT_SUCCESS;
}

status_t dba_proc_decode_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor)
{
    uint32 id = (uint32)cursor->rowid.vmid;
    dba_proc_decode_t *stats = (dba_proc_decode_t *)cursor->page_buf;
    char *sp_buffer = NULL;
    row_assist_t ra;
    status_t status;
    // calc args
    if ((func->args == NULL) || (stats[id].line_num == CT_INVALID_ID32)) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    if (sql_push(stmt, stats[id].sp_instruction.len + 1, (void **)&sp_buffer) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (stats[id].sp_instruction.len == 0) {
        sp_buffer[0] = '\0';
    } else {
        CT_RETURN_IFERR(cm_text2str(&stats[id].sp_instruction, sp_buffer, stats[id].sp_instruction.len + 1));
    }

    status = CT_ERROR;
    do {
        row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, ARRAY_IN(g_proc_decode_columns));
        CT_BREAK_IF_ERROR(row_put_int32(&ra, (int32)stats[id].line_num));
        CT_BREAK_IF_ERROR(row_put_str(&ra, stats[id].type_name));
        CT_BREAK_IF_ERROR(row_put_int32(&ra, stats[id].loc_line));
        CT_BREAK_IF_ERROR(row_put_str(&ra, sp_buffer));
        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
        status = CT_SUCCESS;
    } while (0);

    CTSQL_POP(stmt);
    cursor->rowid.vmid++;
    return status;
}

status_t dba_proc_decode_verify(sql_verifier_t *verif, sql_table_t *table)
{
    table_func_t *func = &table->func;
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    expr_tree_t *arg3 = NULL;

    CT_RETURN_IFERR(table_func_verify(verif, func, 3, 3));

    arg1 = func->args;
    if (!sql_match_string_type(TREE_DATATYPE(arg1))) {
        CT_SRC_ERROR_REQUIRE_STRING(arg1->loc, TREE_DATATYPE(arg1));
        return CT_ERROR;
    }
    arg2 = arg1->next;
    if (!sql_match_string_type(TREE_DATATYPE(arg2))) {
        CT_SRC_ERROR_REQUIRE_STRING(arg2->loc, TREE_DATATYPE(arg2));
        return CT_ERROR;
    }
    arg3 = arg2->next;
    if (!sql_match_string_type(TREE_DATATYPE(arg3))) {
        CT_SRC_ERROR_REQUIRE_STRING(arg3->loc, TREE_DATATYPE(arg3));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t dba_proc_line_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur)
{
    variant_t user, obj;
    knl_session_t *knl_session = &stmt->session->knl_session;
    knl_cursor_t *proc_cursor = NULL;
    char *locator = NULL;
    dba_proc_line_record_t *record = (dba_proc_line_record_t *)cur->page_buf;
    char *head_buf = cur->page_buf + PROC_SOURCE_HEAD_OFFSET;
    uint16 head_len;
    char *source_buf = cur->page_buf + PROC_SOURCE_OFFSET;
    uint32 source_len, uid, page_size;
    status_t status;
    char pl_type;
    session_t *session = stmt->session;

    CTSQL_SAVE_STACK(stmt);
    status = CT_ERROR;
    do {
        expr_tree_t *arg1 = func->args;
        CT_BREAK_IF_ERROR(sql_exec_tablefunc_arg(stmt, arg1, &user, CT_TYPE_STRING, CT_TRUE));
        sql_keep_stack_variant(stmt, &user);
        expr_tree_t *arg2 = arg1->next;
        CT_BREAK_IF_ERROR(sql_exec_tablefunc_arg(stmt, arg2, &obj, CT_TYPE_STRING, CT_TRUE));
        sql_keep_stack_variant(stmt, &obj);

        if (obj.v_text.len > CT_MAX_NAME_LEN) {
            CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, T2S(&obj.v_text), (uint64)0, (uint64)CT_MAX_NAME_LEN);
            break;
        }

        cm_text_upper(&user.v_text);
        process_name_case_sensitive(&obj.v_text);
        if (!cm_text_equal(&session->curr_user, &user.v_text) && !sql_user_is_dba(session)) {
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            break;
        }

        CT_BREAK_IF_ERROR(sql_push_knl_cursor(knl_session, &proc_cursor));
        knl_set_session_scn(knl_session, CT_INVALID_ID64);

        if (!knl_get_user_id(knl_session, &user.v_text, &uid)) {
            CT_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&user.v_text));
            break;
        }

        knl_open_sys_cursor(knl_session, proc_cursor, CURSOR_ACTION_SELECT, SYS_PROC_ID, 0);
        knl_init_index_scan(proc_cursor, CT_FALSE);
        knl_set_scan_key(INDEX_DESC(proc_cursor->index), &proc_cursor->scan_range.l_key, CT_TYPE_STRING,
            obj.v_text.str, obj.v_text.len, 0);
        knl_set_scan_key(INDEX_DESC(proc_cursor->index), &proc_cursor->scan_range.l_key, CT_TYPE_INTEGER, &uid,
            sizeof(int32), 1);
        knl_set_key_flag(&proc_cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, 2);
        knl_set_scan_key(INDEX_DESC(proc_cursor->index), &proc_cursor->scan_range.r_key, CT_TYPE_STRING,
            obj.v_text.str, obj.v_text.len, 0);
        knl_set_scan_key(INDEX_DESC(proc_cursor->index), &proc_cursor->scan_range.r_key, CT_TYPE_INTEGER, &uid,
            sizeof(int32), 1);
        knl_set_key_flag(&proc_cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, 2);
        CT_BREAK_IF_ERROR(knl_fetch(knl_session, proc_cursor));
        if (proc_cursor->eof) {
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "object", T2S(&user.v_text), T2S_EX(&obj.v_text));
            break;
        }

        locator = CURSOR_COLUMN_DATA(proc_cursor, SYS_PROC_SOURCE_COL);
        CT_BREAK_IF_ERROR(knl_get_page_size((knl_handle_t)&stmt->session->knl_session, &page_size));
        CT_BREAK_IF_ERROR(knl_read_lob(knl_session, locator, 0, source_buf, page_size - PROC_SOURCE_HEAD_RESERVED_LEN,
            &source_len, NULL));

        pl_type = *(char *)CURSOR_COLUMN_DATA(proc_cursor, SYS_PROC_TYPE_COL);
        dba_proc_line_add_head(head_buf, PROC_SOURCE_HEAD_RESERVED_LEN, pl_type, &obj.v_text, &head_len);

        record->used_pos = PROC_SOURCE_OFFSET;
        record->line_num = 1;
        // cur->rowid.vmid keep source buf size(contain head reserved)
        cur->rowid.vmid = source_len + PROC_SOURCE_OFFSET;
        // cur->rowid.vm_tag keep source head using len
        cur->rowid.vm_tag = head_len;
        status = CT_SUCCESS;
    } while (0);

    CTSQL_RESTORE_STACK(stmt);
    return status;
}

status_t dba_proc_line_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur)
{
    dba_proc_line_record_t *record = (dba_proc_line_record_t *)cur->page_buf;
    uint32 used_pos = record->used_pos;
    uint32 line_num = record->line_num;
    uint32 source_buf_size = (uint32)cur->rowid.vmid;
    text_t current_source;
    text_t src_line = {
        .str = NULL,
        .len = 0
    };
    bool32 is_finish = CT_TRUE;
    row_assist_t ra;

    current_source.str = cur->page_buf + used_pos;
    current_source.len = 0;
    CTSQL_SAVE_STACK(stmt);

    for (uint32 i = used_pos; i < source_buf_size; i++) {
        if (cur->page_buf[i] == '\r') {
            cur->page_buf[i] = '\0';
            continue;
        }

        if (cur->page_buf[i] != '\n') {
            current_source.len++;
            continue;
        }

        cur->page_buf[i] = '\0';

        if (used_pos == PROC_SOURCE_OFFSET) {
            char *tmp_buf = NULL;
            text_t object_head;
            object_head.str = cur->page_buf + PROC_SOURCE_HEAD_OFFSET;
            object_head.len = (uint32)cur->rowid.vm_tag;
            uint32 tmp_len = object_head.len + current_source.len + 1;
            if (sql_push(stmt, tmp_len, (void **)&tmp_buf) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
            }
            src_line.str = tmp_buf;
            src_line.len = 0;
            cm_concat_text(&src_line, tmp_len, &object_head);
            cm_concat_text(&src_line, tmp_len, &current_source);
            src_line.str[src_line.len] = '\0';
        } else {
            src_line = current_source;
        }
        record->used_pos = i + 1;
        is_finish = CT_FALSE;
        break;
    }
    record->line_num++;

    if (is_finish) {
        cur->eof = CT_TRUE;
        CTSQL_RESTORE_STACK(stmt);
        return CT_SUCCESS;
    }

    row_init(&ra, (char *)cur->row, CT_MAX_ROW_SIZE, ARRAY_IN(g_proc_line_columns));
    if (row_put_int32(&ra, line_num) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    if (row_put_str(&ra, src_line.str) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);
    CTSQL_RESTORE_STACK(stmt);
    return CT_SUCCESS;
}

status_t dba_proc_line_verify(sql_verifier_t *verf, sql_table_t *table)
{
    table_func_t *func = &table->func;
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;

    CT_RETURN_IFERR(table_func_verify(verf, func, 2, 2));

    arg1 = func->args;
    if (!sql_match_string_type(TREE_DATATYPE(arg1))) {
        CT_SRC_ERROR_REQUIRE_STRING(arg1->loc, TREE_DATATYPE(arg1));
        return CT_ERROR;
    }
    arg2 = arg1->next;
    if (!sql_match_string_type(TREE_DATATYPE(arg2))) {
        CT_SRC_ERROR_REQUIRE_STRING(arg2->loc, TREE_DATATYPE(arg2));
        return CT_ERROR;
    }

    if (!(DB_IS_OPEN(KNL_SESSION(verf->stmt)))) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", this table function is not supported when database is not open.");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t dbg_break_info_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur)
{
    session_t *session = stmt->session;
    debug_control_t *dbg_ctl = session->dbg_ctl;
    debug_control_t *target_dbg_ctl = NULL;
    dbg_breakpoint_info_t *stats = (dbg_breakpoint_info_t *)cur->page_buf;
    variant_t value;
    status_t status = CT_ERROR;
    TBL_FUNC_RETURN_IF_NOT_DBG_SESSION(session);
    CT_RETURN_IFERR(sql_exec_expr(stmt, func->args, &value));
    CT_RETURN_IFERR(sql_convert_variant(stmt, &value, CT_TYPE_INTEGER));
    TBL_FUNC_RETURN_IF_INT_NEGATIVE(value);
    cm_spin_lock_if_exists(dbg_ctl->target_lock, NULL);
    cm_spin_lock_if_exists(&session->dbg_ctl_lock, NULL);
    do {
        CT_BREAK_IF_ERROR(pld_get_target_session_debug_info(stmt, dbg_ctl->target_id, &target_dbg_ctl, NULL));
        if (target_dbg_ctl->status != DBG_WAITING && target_dbg_ctl->status != DBG_IDLE) {
            CT_THROW_ERROR(ERR_DEBUG_SESSION_STATUS, "WAITING or IDLE", "PRE_WAIT or EXECUTING");
            break;
        }
        CT_BREAK_IF_ERROR(get_break_info_by_id(stmt, (uint32)value.v_int, target_dbg_ctl, stats));

        cur->rowid.vmid = 0;
        status = CT_SUCCESS;
    } while (0);
    cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
    cm_spin_unlock_if_exists(dbg_ctl->target_lock);
    return status;
}

status_t dbg_break_info_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor)
{
    uint32 id = (uint32)cursor->rowid.vmid;
    dbg_breakpoint_info_t *stats = (dbg_breakpoint_info_t *)cursor->page_buf;
    row_assist_t ra;
    char buf[CT_NAME_BUFFER_SIZE];
    text_t pl_type;

    if (stats[id].break_id == CT_INVALID_ID32) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, ARRAY_IN(g_breakpoint_info_columns));
    CT_RETURN_IFERR(row_put_int32(&ra, stats[id].break_id));

    buf[0] = '\0';
    CT_RETURN_IFERR(cm_text2str(&stats[id].owner, buf, CT_NAME_BUFFER_SIZE));
    CT_RETURN_IFERR(row_put_str(&ra, buf));
    buf[0] = '\0';
    CT_RETURN_IFERR(cm_text2str(&stats[id].object, buf, CT_NAME_BUFFER_SIZE));
    CT_RETURN_IFERR(row_put_str(&ra, buf));
    buf[0] = '\0';
    CT_RETURN_IFERR(pld_get_pl_type_text(stats[id].pl_type, &pl_type));
    CT_RETURN_IFERR(cm_text2str(&pl_type, buf, CT_NAME_BUFFER_SIZE));
    CT_RETURN_IFERR(row_put_str(&ra, buf));

    CT_RETURN_IFERR(row_put_int32(&ra, (int32)stats[id].loc_line));
    CT_RETURN_IFERR(row_put_bool(&ra, stats[id].is_valid));
    CT_RETURN_IFERR(row_put_bool(&ra, stats[id].is_enabled));
    buf[0] = '\0';
    CT_RETURN_IFERR(cm_text2str(&stats[id].cond, buf, CT_NAME_BUFFER_SIZE));
    CT_RETURN_IFERR(row_put_str(&ra, buf));
    CT_RETURN_IFERR(row_put_int32(&ra, stats[id].max_skip));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

status_t dbg_break_info_verify(sql_verifier_t *verf, sql_table_t *table)
{
    CT_RETURN_IFERR(table_func_verify(verf, &table->func, 1, 1));
    TBL_FUNC_RETURN_IF_NOT_INTEGER(table->func.loc, NODE_DATATYPE(table->func.args->root));

    return CT_SUCCESS;
}

status_t dbg_control_info_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur)
{
    session_t *session = stmt->session;
    debug_control_t *dbg_ctl = session->dbg_ctl;
    debug_control_t *target_dbg_ctl = NULL;
    spinlock_t *target_lock = NULL;
    spinlock_t *debug_lock = NULL;
    status_t status;
    dbg_control_info_t *stats = (dbg_control_info_t *)cur->page_buf;

    if (NULL == dbg_ctl) {
        CT_THROW_ERROR(ERR_DEBUG_SESSION_TYPE, "target or debug session", (session)->knl_session.id);
        return CT_ERROR;
    }

    if (dbg_ctl->type == TARGET_SESSION) {
        target_lock = &session->dbg_ctl_lock;
        debug_lock = dbg_ctl->debug_lock;
    } else {
        target_lock = dbg_ctl->target_lock;
        debug_lock = &session->dbg_ctl_lock;
    }

    status = CT_ERROR;
    cm_spin_lock_if_exists(target_lock, NULL);
    cm_spin_lock_if_exists(debug_lock, NULL);
    do {
        if (dbg_ctl->type == TARGET_SESSION) {
            target_dbg_ctl = dbg_ctl;
        } else {
            CT_BREAK_IF_ERROR(pld_get_target_session_debug_info(stmt, dbg_ctl->target_id, &target_dbg_ctl, NULL));
        }
        if (!pld_has_privilege(session, &target_dbg_ctl->debug_user, NULL)) {
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            break;
        }

        dbg_control_info_t control_info[CONTROL_ITEM_NUM] = {
            { "timeout",            target_dbg_ctl->timeout },
            { "curr_count",         target_dbg_ctl->curr_count },
            { "status",             target_dbg_ctl->status },
            { "is_force_pause",     target_dbg_ctl->is_force_pause },
            { "is_force_terminate", target_dbg_ctl->is_force_terminate },
            { "is_attached",        target_dbg_ctl->is_attached },
            { "debug_id",           target_dbg_ctl->debug_id },
            { "brk_flag",           target_dbg_ctl->brk_flag },
            { "brk_flag_stack_id",  target_dbg_ctl->brk_flag_stack_id },
            { "max_stack_id",       target_dbg_ctl->max_stack_id },
            { "max_break_id",       target_dbg_ctl->max_break_id }
        };

        for (uint32 i = 0; i < CONTROL_ITEM_NUM; i++) {
            MEMS_RETURN_IFERR(
                strncpy_s(stats[i].name, CONTROL_ITEM_NAME_MAXLEN, control_info[i].name, strlen(control_info[i].name)));
            stats[i].value = control_info[i].value;
        }

        cur->rowid.vmid = 0;
        status = CT_SUCCESS;
    } while (0);
    cm_spin_unlock_if_exists(debug_lock);
    cm_spin_unlock_if_exists(target_lock);
    return status;
}

status_t dbg_control_info_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor)
{
    uint32 id = (uint32)cursor->rowid.vmid;
    dbg_control_info_t *stats = (dbg_control_info_t *)cursor->page_buf;
    row_assist_t ra;

    if (id >= CONTROL_ITEM_NUM) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, ARRAY_IN(g_control_info_columns));
    CT_RETURN_IFERR(row_put_str(&ra, stats[id].name));
    CT_RETURN_IFERR(row_put_int32(&ra, stats[id].value));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

status_t dbg_control_info_verify(sql_verifier_t *verif, sql_table_t *table)
{
    return table_func_verify(verif, &table->func, 0, 0);
}

status_t dbg_proc_callstack_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur)
{
    session_t *session = stmt->session;
    debug_control_t *dbg_ctl = session->dbg_ctl;
    debug_control_t *target_dbg_ctl = NULL;
    status_t status = CT_ERROR;
    dbg_proc_callstack_t *stats = (dbg_proc_callstack_t *)cur->page_buf;
    variant_t stack_id;

    expr_tree_t *arg1 = func->args;
    CT_RETURN_IFERR(sql_exec_tablefunc_arg(stmt, arg1, &stack_id, CT_TYPE_INTEGER, CT_TRUE));
    TBL_FUNC_RETURN_IF_INT_NEGATIVE(stack_id);

    TBL_FUNC_RETURN_IF_NOT_DBG_SESSION(session);

    cm_spin_lock_if_exists(dbg_ctl->target_lock, NULL);
    cm_spin_lock_if_exists(&session->dbg_ctl_lock, NULL);
    do {
        CT_BREAK_IF_ERROR(pld_get_target_session_debug_info(stmt, dbg_ctl->target_id, &target_dbg_ctl, NULL));

        if (!pld_has_privilege(session, &target_dbg_ctl->debug_user, NULL)) {
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            break;
        }

        if (target_dbg_ctl->status != DBG_WAITING) {
            CT_THROW_ERROR(ERR_DEBUG_SESSION_STATUS, "WAITING", "IDLE or EXECUTING or PRE_WAIT");
            break;
        }

        CT_BREAK_IF_ERROR(dbg_proc_callstack_prepare(stmt, target_dbg_ctl, stats, (uint32)stack_id.v_int));
        cur->rowid.vmid = 0;
        status = CT_SUCCESS;
    } while (0);
    cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
    cm_spin_unlock_if_exists(dbg_ctl->target_lock);
    return status;
}

status_t dbg_proc_callstack_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor)
{
    uint32 id = (uint32)cursor->rowid.vmid;
    dbg_proc_callstack_t *stats = (dbg_proc_callstack_t *)cursor->page_buf;
    char buf[CT_NAME_BUFFER_SIZE];
    row_assist_t ra;

    if (stats[id].stack_id == CT_INVALID_ID32) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, ARRAY_IN(g_proc_callstack_columns));
    CT_RETURN_IFERR(row_put_int32(&ra, stats[id].stack_id));
    if (stats[id].owner.len == 0 || stats[id].object.len == 0) {
        CT_RETURN_IFERR(row_put_null(&ra));
        CT_RETURN_IFERR(row_put_null(&ra));
    } else {
        CT_RETURN_IFERR(row_put_int32(&ra, (int)stats[id].uid));
        CT_RETURN_IFERR(row_put_int64(&ra, (int)stats[id].oid));
    }

    buf[0] = '\0';
    CT_RETURN_IFERR(cm_text2str(&stats[id].owner, buf, CT_NAME_BUFFER_SIZE));
    CT_RETURN_IFERR(row_put_str(&ra, buf));
    buf[0] = '\0';
    CT_RETURN_IFERR(cm_text2str(&stats[id].object, buf, CT_NAME_BUFFER_SIZE));
    CT_RETURN_IFERR(row_put_str(&ra, buf));
    CT_RETURN_IFERR(row_put_int32(&ra, stats[id].loc_line));
    buf[0] = '\0';
    CT_RETURN_IFERR(cm_text2str(&stats[id].type_name, buf, CT_NAME_BUFFER_SIZE));
    CT_RETURN_IFERR(row_put_str(&ra, buf));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

status_t dbg_proc_callstack_verify(sql_verifier_t *verif, sql_table_t *table)
{
    CT_RETURN_IFERR(table_func_verify(verif, &table->func, 1, 1));
    TBL_FUNC_RETURN_IF_NOT_INTEGER(table->func.loc, TREE_DATATYPE(table->func.args));
    return CT_SUCCESS;
}

status_t dbg_show_values_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur)
{
    session_t *session = stmt->session;
    debug_control_t *dbg_ctl = session->dbg_ctl;
    debug_control_t *target_dbg_ctl = NULL;
    status_t status;
    dbg_show_values_t *stats = (dbg_show_values_t *)cur->page_buf;
    uint32 using_index = 0;
    variant_t stack_id;
    uint32 start_id, end_id, i;

    expr_tree_t *arg1 = func->args;
    CT_RETURN_IFERR(sql_exec_tablefunc_arg(stmt, arg1, &stack_id, CT_TYPE_INTEGER, CT_TRUE));
    TBL_FUNC_RETURN_IF_INT_NEGATIVE(stack_id);

    TBL_FUNC_RETURN_IF_NOT_DBG_SESSION(session);

    status = CT_ERROR;
    cm_spin_lock_if_exists(dbg_ctl->target_lock, NULL);
    cm_spin_lock_if_exists(&session->dbg_ctl_lock, NULL);
    do {
        CT_BREAK_IF_ERROR(pld_get_target_session_debug_info(stmt, dbg_ctl->target_id, &target_dbg_ctl, NULL));

        if (target_dbg_ctl->status != DBG_WAITING) {
            CT_THROW_ERROR(ERR_DEBUG_SESSION_STATUS, "WAITING", "IDLE or EXECUTING or PRE_WAIT");
            break;
        }
        if (stack_id.v_int == 0 || (uint32)stack_id.v_int > target_dbg_ctl->max_stack_id) {
            start_id = 1;
            end_id = target_dbg_ctl->max_stack_id;
        } else {
            start_id = stack_id.v_int;
            end_id = start_id;
        }
        for (i = start_id; i <= end_id; i++) {
            if (!pld_has_privilege(session, &target_dbg_ctl->debug_user, target_dbg_ctl->callstack_info[i - 1].exec)) {
                CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
                break;
            }
            CT_BREAK_IF_ERROR(dbg_show_values_prepare(stmt, target_dbg_ctl, stats, &using_index, i));
        }
        if (i <= end_id) {
            break;
        }
        cur->rowid.vmid = 0;
        status = CT_SUCCESS;
    } while (0);
    cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
    cm_spin_unlock_if_exists(dbg_ctl->target_lock);
    return status;
}

status_t dbg_show_values_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor)
{
    uint32 id = (uint32)cursor->rowid.vmid;
    dbg_show_values_t *stats = (dbg_show_values_t *)cursor->page_buf;
    char *buffer = NULL;
    row_assist_t ra;
    status_t status;
    const char *datetype_name = NULL;
    variant_t result;

    if (stats[id].stack_id == CT_INVALID_ID32) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    status = CT_ERROR;
    CTSQL_SAVE_STACK(stmt);
    do {
        CT_BREAK_IF_ERROR(sql_push(stmt, CT_MAX_COLUMN_SIZE, (void **)&buffer));

        row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, ARRAY_IN(g_show_values_columns));
        CT_BREAK_IF_ERROR(row_put_int32(&ra, stats[id].stack_id));
        buffer[0] = '\0';
        CT_BREAK_IF_ERROR(cm_text2str(&stats[id].block_name, buffer, CT_MAX_NAME_LEN));
        CT_BREAK_IF_ERROR(row_put_str(&ra, buffer));
        buffer[0] = '\0';
        CT_BREAK_IF_ERROR(cm_text2str(&stats[id].parent_name, buffer, CT_MAX_NAME_LEN));
        CT_BREAK_IF_ERROR(row_put_str(&ra, buffer));
        buffer[0] = '\0';
        CT_BREAK_IF_ERROR(cm_text2str(&stats[id].name, buffer, CT_MAX_NAME_LEN));
        CT_BREAK_IF_ERROR(row_put_str(&ra, buffer));
        CT_BREAK_IF_ERROR(row_put_int32(&ra, stats[id].block));
        CT_BREAK_IF_ERROR(row_put_int32(&ra, stats[id].id));
        CT_BREAK_IF_ERROR(row_put_int32(&ra, stats[id].m_offset));

        if (stats[id].is_attr_in_vm) {
            if (stats[id].is_obj) {
                CT_BREAK_IF_ERROR(pld_object_field_read(stmt, stats[id].obj_curr_stmt, stats[id].obj_attr,
                    &stats[id].obj_field, &result));
            } else {
                CT_BREAK_IF_ERROR(
                    pld_record_field_read(stmt, stats[id].curr_stmt, stats[id].attr, &stats[id].field, &result));
            }

            if (stats[id].attr->type == UDT_RECORD) {
                result.type = CT_TYPE_RECORD;
                result.is_null = CT_TRUE;
            } else if (stats[id].attr->type == UDT_COLLECTION) {
                result.type = CT_TYPE_COLLECTION;
                result.is_null = CT_TRUE;
            } else if (stats[id].attr->type == UDT_OBJECT) {
                result.type = CT_TYPE_OBJECT;
                result.is_null = CT_TRUE;
            } else {
                result.type = stats[id].attr->scalar_field->type_mode.datatype;
            }
        } else {
            var_copy(&stats[id].value, &result);
        }

        datetype_name = get_datatype_name_str((int32)result.type);

        buffer[0] = '\0';
        if (!result.is_null) {
            if (result.type == CT_TYPE_CURSOR) {
                CT_BREAK_IF_ERROR(pld_get_cursor_buf(buffer, CT_MAX_COLUMN_SIZE, NULL, &stats[id].cur_info));
            } else if (result.type == CT_TYPE_COLLECTION) {
                buffer = "collect type is not supported\0";
            } else if (result.type == CT_TYPE_OBJECT) {
                buffer = "object type is not supported\0";
            } else {
                CT_BREAK_IF_ERROR(sql_convert_variant(stmt, &result, CT_TYPE_STRING));
                sql_keep_stack_variant(stmt, &result);
                CT_RETURN_IFERR(cm_text2str(&result.v_text, buffer, CT_MAX_COLUMN_SIZE));
            }
        }
        CT_BREAK_IF_ERROR(row_put_str(&ra, buffer));
        CT_BREAK_IF_ERROR(row_put_str(&ra, datetype_name));
        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
        status = CT_SUCCESS;
    } while (0);
    CTSQL_RESTORE_STACK(stmt);

    cursor->rowid.vmid++;
    return status;
}

status_t dbg_show_values_verify(sql_verifier_t *verf, sql_table_t *table)
{
    CT_RETURN_IFERR(table_func_verify(verf, &table->func, 1, 1));
    TBL_FUNC_RETURN_IF_NOT_INTEGER(table->func.loc, TREE_DATATYPE(table->func.args));
    return CT_SUCCESS;
}

static inline status_t stack_copy_name(sql_stmt_t *stmt, text_t *src, text_t *dst)
{
    if (src->len > CT_MAX_NAME_LEN) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "'%s' is too long to as name", T2S(src));
        return CT_ERROR;
    }

    if (src->len != 0) {
        CT_RETURN_IFERR(sql_stack_alloc(stmt, src->len, (void **)&dst->str));
        MEMS_RETURN_IFERR(memcpy_s(dst->str, src->len, src->str, src->len));
    }

    dst->len = src->len;
    return CT_SUCCESS;
}

static inline status_t stack_copy_prefix_tenant(sql_stmt_t *stmt, text_t *src, text_t *dst)
{
    text_t name;
    char buf[CT_NAME_BUFFER_SIZE];

    CT_RETURN_IFERR(cm_text2str(src, buf, CT_NAME_BUFFER_SIZE));
    CT_RETURN_IFERR(sql_user_prefix_tenant(stmt->session, buf));

    cm_str2text(buf, &name);
    return stack_copy_name(stmt, &name, dst);
}

static status_t sql_get_word_table(sql_stmt_t *stmt, word_t *word, text_t *schema, text_t *table)
{
    if (word->ex_count == 0) {
        CT_RETURN_IFERR(stack_copy_name(stmt, &word->text.value, table));
        text_t user_name = { stmt->session->curr_schema, (uint32)strlen(stmt->session->curr_schema) };
        CT_RETURN_IFERR(stack_copy_name(stmt, &user_name, schema));
    } else if (word->ex_count == 1) {
        CT_RETURN_IFERR(stack_copy_name(stmt, &word->ex_words[0].text.value, table));
        CT_RETURN_IFERR(stack_copy_prefix_tenant(stmt, &word->text.value, schema));
    } else {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid table name");
        return CT_ERROR;
    }

    if (IS_DUAL_TABLE_NAME(table) || (IS_CASE_INSENSITIVE && !IS_DQ_STRING(word->type))) {
        cm_text_upper(table);
    }
    cm_text_upper(schema);
    return CT_SUCCESS;
}

status_t get_tab_parallel_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor)
{
    knl_dictionary_t dc;
    dc_entity_t *entity = NULL;
    knl_paral_range_t paral_ranges;
    text_t table, schema, partition_name;
    uint32 parals, r_partno, part_count, max_range_cnt;
    uint32 i, j, ret;
    word_t word;
    sql_text_t sql_arg;
    variant_t value;
    bool32 check = CT_FALSE;
    sql_cursor_t *sql_cur = CTSQL_ROOT_CURSOR(stmt);
    char *buf = NULL;
    char par_name[CT_MAX_NAME_LEN + 1] = { 0 };
    uint32 paral_ranges_cnt, write_len, cost;
    knl_part_locate_t part_locate;
    cursor->rowid.vmid = 0;
    cursor->rowid.vm_slot = 0;

    CT_RETURN_IFERR(sql_exec_expr(stmt, func->args, &value));
    CT_RETURN_IFERR(sql_convert_variant(stmt, &value, CT_TYPE_STRING));
    if (value.is_null) {
        CT_THROW_ERROR(ERR_TF_TABLE_NAME_NULL);
        return CT_ERROR;
    }
    table = value.v_text;
    sql_keep_stack_variant(stmt, &value);
    CT_RETURN_IFERR(sql_exec_expr(stmt, func->args->next, &value));
    CT_RETURN_IFERR(sql_convert_variant(stmt, &value, CT_TYPE_INTEGER));
    if (value.v_int <= 0 || value.v_int > CT_MAX_PAR_EXP_VALUE) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "table parallel", (int64)1, (int64)CT_MAX_PAR_EXP_VALUE);
        return CT_ERROR;
    }
    parals = value.v_int;

    // partition name
    if (func->args->next->next != NULL) {
        CT_RETURN_IFERR(sql_exec_expr(stmt, func->args->next->next, &value));
        CT_RETURN_IFERR(sql_convert_variant(stmt, &value, CT_TYPE_STRING));
        if (value.is_null) {
            CT_THROW_ERROR(ERR_PARTITION_NOT_EXIST, T2S(&table), "null");
            return CT_ERROR;
        } else if (value.v_text.len > CT_MAX_NAME_LEN) {
            CT_THROW_ERROR(ERR_INVALID_PART_NAME);
            return CT_ERROR;
        }
        partition_name = value.v_text;
        MEMS_RETURN_IFERR(strncpy_s(par_name, sizeof(par_name), partition_name.str, partition_name.len));
    }

    sql_arg.value = table;
    sql_arg.loc = func->args->loc;
    sql_arg.implicit = CT_FALSE;
    lex_t lex;
    lex_init_for_native_type(&lex, &sql_arg, &stmt->session->curr_user, stmt->session->call_version,
        USE_NATIVE_DATATYPE);
    lex.flags = LEX_WITH_OWNER;
    CT_RETURN_IFERR(lex_expected_fetch_variant(&lex, &word));
    CT_RETURN_IFERR(lex_expected_end(&lex));
    CT_RETURN_IFERR(sql_get_word_table(stmt, &word, &schema, &table));

    CT_RETURN_IFERR(knl_open_dc(KNL_SESSION(stmt), &schema, &table, &dc) != CT_SUCCESS);

    if (knl_is_compart_table(dc.handle)) {
        CT_THROW_ERROR(ERR_UNSUPPORT_FUNC, "get_tab_parallel func", "second partition");
        knl_close_dc(&dc);
        return CT_ERROR;
    }

    entity = DC_ENTITY(&dc);
    r_partno = CT_INVALID_ID32;
    part_count = CT_INVALID_ID32;
    if (IS_PART_TABLE(&entity->table)) {
        part_count = knl_real_part_count(dc.handle);
        r_partno = knl_part_count(dc.handle);
    }

    if (!cm_text_equal_ins(&schema, &stmt->session->curr_user)) {
        check = knl_check_sys_priv_by_name(KNL_SESSION(stmt), &stmt->session->curr_user, SELECT_ANY_TABLE);
        if (!check) {
            check = knl_check_obj_priv_by_name(KNL_SESSION(stmt), &stmt->session->curr_user, &schema, &table,
                OBJ_TYPE_TABLE, CT_PRIV_SELECT);
            if (!check) {
                CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
                knl_close_dc(&dc);
                return CT_ERROR;
            }
        }
    }

    max_range_cnt = parals * ((r_partno == CT_INVALID_ID32) ? 1 : part_count);
    cost = sizeof(uint32) + (max_range_cnt * PARAL_RAGNE_ROW_SIZE);
    if (vmc_alloc(&sql_cur->vmc, cost, (void **)&buf) != CT_SUCCESS) {
        knl_close_dc(&dc);
        return CT_ERROR;
    }

    paral_ranges_cnt = 0;
    write_len = sizeof(uint32);

    if (par_name != NULL && strlen(par_name) > 0) {
        if (!knl_is_part_table(entity)) {
            CT_THROW_ERROR(ERR_PARTITION_NOT_EXIST, T2S(&table), par_name);
            knl_close_dc(&dc);
            return CT_ERROR;
        }

        ret = knl_find_table_part_by_name(entity, &partition_name, &part_locate.part_no);
        if (ret != CT_SUCCESS) {
            knl_close_dc(&dc);
            return ret;
        }

        ret = knl_get_paral_schedule(KNL_SESSION(stmt), &dc, part_locate, parals, &paral_ranges);
        if (ret != CT_SUCCESS) {
            knl_close_dc(&dc);
            return ret;
        }

        if (paral_ranges.workers == 0) {
            CT_THROW_ERROR(ERR_PART_HAS_NO_DATA, par_name);
            knl_close_dc(&dc);
            return CT_ERROR;
        }

        paral_ranges_cnt += paral_ranges.workers;
        if (paral_ranges_cnt > max_range_cnt) {
            CT_THROW_ERROR(ERR_OUT_OF_INDEX, "range count", max_range_cnt);
            knl_close_dc(&dc);
            return CT_ERROR;
        }
        for (j = 0; j < paral_ranges.workers; j++) {
            *(uint32 *)((char *)buf + write_len) = part_locate.part_no;
            write_len += sizeof(uint32);
            *(uint64 *)((char *)buf + write_len) = *(uint64 *)(&paral_ranges.l_page[j]);
            write_len += sizeof(uint64);
            *(uint64 *)((char *)buf + write_len) = *(uint64 *)(&paral_ranges.r_page[j]);
            write_len += sizeof(uint64);
        }
    } else {
        for (i = 0; i < ((r_partno == CT_INVALID_ID32) ? 1 : r_partno); i++) {
            part_locate.part_no = (r_partno == CT_INVALID_ID32) ? CT_INVALID_ID32 : i;
            ret = knl_get_paral_schedule(KNL_SESSION(stmt), &dc, part_locate, parals, &paral_ranges);
            if (ret != CT_SUCCESS) {
                knl_close_dc(&dc);
                return ret;
            }
            paral_ranges_cnt += paral_ranges.workers;
            if (paral_ranges_cnt > max_range_cnt) {
                CT_THROW_ERROR(ERR_OUT_OF_INDEX, "range count", max_range_cnt);
                knl_close_dc(&dc);
                return CT_ERROR;
            }
            for (j = 0; j < paral_ranges.workers; j++) {
                *(uint32 *)((char *)buf + write_len) = part_locate.part_no;
                write_len += sizeof(uint32);
                *(uint64 *)((char *)buf + write_len) = *(uint64 *)(&paral_ranges.l_page[j]);
                write_len += sizeof(uint64);
                *(uint64 *)((char *)buf + write_len) = *(uint64 *)(&paral_ranges.r_page[j]);
                write_len += sizeof(uint64);
            }
        }
    }

    *(uint32 *)buf = paral_ranges_cnt;
    sql_cur->exec_data.tab_parallel = buf;

    knl_close_dc(&dc);
    return CT_SUCCESS;
}

status_t get_tab_parallel_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor)
{
    row_assist_t ra;
    sql_cursor_t *sql_cur = CTSQL_ROOT_CURSOR(stmt);
    char *buf = NULL;
    uint32 offset = sizeof(uint32) + ((uint32)(cursor->rowid.vmid)) * PARAL_RAGNE_ROW_SIZE;

    /* get table parallel data */
    buf = sql_cur->exec_data.tab_parallel;

    /* calc args */
    if ((func->args == NULL) || (cursor->rowid.vmid >= *(uint32 *)buf)) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, ARRAY_IN(g_table_paralel_columns));
    CT_RETURN_IFERR(row_put_int32(&ra, *(uint32 *)(buf + offset))); // part no
    offset += sizeof(uint32);
    CT_RETURN_IFERR(row_put_int64(&ra, *(int64 *)(buf + offset)));
    offset += sizeof(uint64);
    CT_RETURN_IFERR(row_put_int64(&ra, *(int64 *)(buf + offset)));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;

    return CT_SUCCESS;
}

status_t get_tab_paralle_verify(sql_verifier_t *verif, sql_table_t *table)
{
    return table_func_verify(verif, &table->func, 2, 3);
}

status_t get_table_rows_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor)
{
    return CT_SUCCESS;
}

status_t get_table_rows_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor)
{
    cursor->eof = CT_TRUE;
    return CT_SUCCESS;
}

status_t get_table_rows_verify(sql_verifier_t *verif, sql_table_t *table)
{
    return table_func_verify(verif, &table->func, 4, 6);
}

static status_t sql_tab_func_partno_verify(sql_table_t *tab, uint32 partno)
{
    dc_entity_t *entity = NULL;
    uint32 total_part_cnt = 0;

    if (knl_is_part_table(tab->entry->dc.handle)) {
        entity = DC_ENTITY(&tab->entry->dc);
        total_part_cnt = knl_part_count((knl_handle_t)entity);
        if (total_part_cnt <= partno) {
            CT_THROW_ERROR(ERR_PARTNO_NOT_EXIST, partno);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t pre_set_parms_get_rows(sql_stmt_t *stmt, void *handle, sql_table_t *table)
{
    knl_cursor_t *knl_cur = (knl_cursor_t *)handle;
    table_func_t *func = &table->func;
    variant_t value;

    if (table->tf_scan_flag > SEQ_TFM_SCAN) {
        // set part no
        CT_RETURN_IFERR(sql_exec_expr(stmt, func->args->next, &value));
        CT_RETURN_IFERR(sql_convert_variant(stmt, &value, CT_TYPE_INTEGER));
        knl_cur->part_loc.part_no = (uint32)value.v_int;
        CT_RETURN_IFERR(sql_tab_func_partno_verify(table, knl_cur->part_loc.part_no));
    }

    return CT_SUCCESS;
}

status_t set_parms_get_rows(sql_stmt_t *stmt, void *handle, void *sesion, sql_table_t *table)
{
    knl_cursor_t *knl_cur = (knl_cursor_t *)handle;
    knl_session_t *knl_ses = (knl_session_t *)sesion;
    table_func_t *func = &table->func;
    page_id_t l_page, r_page;
    uint64 scn = 0;
    variant_t value;
    sql_cursor_t *cursor = CTSQL_CURR_CURSOR(stmt);
    sql_table_cursor_t *tab_cur = &cursor->tables[table->id];

    // set parallel query scn
    CT_RETURN_IFERR(sql_exec_expr(stmt, func->args->next->next, &value));
    CT_RETURN_IFERR(sql_convert_variant(stmt, &value, CT_TYPE_BIGINT));
    if (!value.is_null) {
        scn = value.v_bigint;
        tab_cur->scn = scn;
    }

    if (scn >= knl_next_scn(knl_ses)) {
        CT_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAMS, "scn is an invalid value");
        return CT_ERROR;
    }

    // set scan range
    if (table->tf_scan_flag == PAR_TFM_SCAN) {
        CT_RETURN_IFERR(sql_exec_expr(stmt, func->args->next->next->next->next, &value));
        CT_RETURN_IFERR(sql_convert_variant(stmt, &value, CT_TYPE_BIGINT));
        l_page = *(page_id_t *)(&value.v_bigint);
        CT_RETURN_IFERR(sql_exec_expr(stmt, func->args->next->next->next->next->next, &value));
        CT_RETURN_IFERR(sql_convert_variant(stmt, &value, CT_TYPE_BIGINT));
        r_page = *(page_id_t *)(&value.v_bigint);
        knl_set_table_scan_range(knl_ses, knl_cur, l_page, r_page);
    }

    return CT_SUCCESS;
}
tf_scan_flag_t get_tab_rows_scan_flag(table_func_t *table_func)
{
    uint32 total = 0;
    expr_tree_t *exp_tree = NULL;

    if ((table_func != NULL) && (table_func->args != NULL)) {
        exp_tree = table_func->args;
        while (exp_tree != NULL) {
            exp_tree = exp_tree->next;
            total += 1;
        }
    }

    if (total == GET_TAB_ROWS_PARAMS_COUNT) {
        return PAR_TFM_SCAN;
    } else {
        return SEQ_TFM_SCAN;
    }
}

status_t parallel_scan_exec(sql_stmt_t *stmt, table_func_t *table_func, knl_cursor_t *cursor)
{
    return CT_SUCCESS;
}

status_t parallel_scan_fetch(sql_stmt_t *stmt, table_func_t *table_func, knl_cursor_t *cursor)
{
    cursor->eof = CT_TRUE;
    return CT_SUCCESS;
}

status_t parallel_scan_verify(sql_verifier_t *verif, sql_table_t *table)
{
    return table_func_verify(verif, &table->func, 4, 5);
}

status_t pre_set_parms_paral_scan(sql_stmt_t *stmt, void *handle, sql_table_t *table)
{
    knl_cursor_t *knl_cur = (knl_cursor_t *)handle;
    table_func_t *func = &table->func;
    variant_t value;

    // set part no
    if (func->args->next->next->next->next != NULL) {
        CT_RETURN_IFERR(sql_exec_expr(stmt, func->args->next->next->next->next, &value));
        CT_RETURN_IFERR(sql_convert_variant(stmt, &value, CT_TYPE_INTEGER));
        knl_cur->part_loc.part_no = (uint32)value.v_int;
        CT_RETURN_IFERR(sql_tab_func_partno_verify(table, knl_cur->part_loc.part_no));
    }

    return CT_SUCCESS;
}

status_t set_parms_paral_scan(sql_stmt_t *stmt, void *handle, void *session, sql_table_t *table)
{
    knl_cursor_t *knl_cur = (knl_cursor_t *)handle;
    knl_session_t *knl_ses = (knl_session_t *)session;
    table_func_t *func = &table->func;
    page_id_t l_page, r_page;
    uint64 scn;
    variant_t value;
    sql_cursor_t *cursor = CTSQL_CURR_CURSOR(stmt);
    sql_table_cursor_t *tab_cur = &cursor->tables[table->id];

    // set parallel query scn
    CT_RETURN_IFERR(sql_exec_expr(stmt, func->args->next, &value));
    CT_RETURN_IFERR(sql_convert_variant(stmt, &value, CT_TYPE_BIGINT));
    scn = value.v_bigint;

    if (scn >= knl_next_scn(knl_ses)) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "scn(%llu) < knl_next_scn(knl_ses)(%llu)", scn, knl_next_scn(knl_ses));
        return CT_ERROR;
    }

    tab_cur->scn = scn;

    // set scan range
    CT_RETURN_IFERR(sql_exec_expr(stmt, func->args->next->next, &value));
    CT_RETURN_IFERR(sql_convert_variant(stmt, &value, CT_TYPE_BIGINT));
    l_page = *(page_id_t *)(&value.v_bigint);
    CT_RETURN_IFERR(sql_exec_expr(stmt, func->args->next->next->next, &value));
    CT_RETURN_IFERR(sql_convert_variant(stmt, &value, CT_TYPE_BIGINT));
    r_page = *(page_id_t *)(&value.v_bigint);
    knl_set_table_scan_range(knl_ses, knl_cur, l_page, r_page);

    return CT_SUCCESS;
}

tf_scan_flag_t parallel_scan_flag(table_func_t *table_func)
{
    return PAR_TFM_SCAN;
}

status_t pending_trans_session_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor)
{
    /* Current user should be dba */
    if (!sql_user_is_dba(stmt->session)) {
        CT_SRC_THROW_ERROR(func->loc, ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }

    cursor->rowid.vmid = 0;
    return CT_SUCCESS;
}

status_t dba_free_space_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor)
{
    knl_session_t *session = &stmt->session->knl_session;
    /* Current user should be dba */
    if (!sql_user_is_dba(stmt->session)) {
        CT_SRC_THROW_ERROR(func->loc, ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }

    if (!(DB_IS_OPEN(session))) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", this table function is not supported when database is not open.");
        return CT_ERROR;
    }

    expr_tree_t *arg1 = func->args;
    variant_t space_id;
    CT_RETURN_IFERR(sql_exec_tablefunc_arg(stmt, arg1, &space_id, CT_TYPE_INTEGER, CT_TRUE));
    TBL_FUNC_RETURN_IF_INT_NEGATIVE(space_id);

    if (space_id.v_uint32 >= CT_MAX_SPACES) {
        CT_THROW_ERROR_EX(ERR_INVALID_FUNC_PARAMS, "space id is larger than max space id(%d)", CT_MAX_SPACES);
        return CT_ERROR;
    }

    if (!spc_valid_space_object(session, space_id.v_uint32)) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "tablespace does not belong to database.");
        return CT_ERROR;
    }

    page_id_t *page_id = (page_id_t *)cursor->page_buf;
    page_id->page = 0;
    page_id->file = INVALID_FILE_ID;
    page_id->aligned = 0;

    cursor->rowid.vm_slot = space_id.v_uint32; // 16 space id
    cursor->rowid.vmid = 0;                    // 32 free extent num
    cursor->rowid.vm_tag = 0;                  // 16 file hwm id from space
    cursor->eof = CT_FALSE;
    return CT_SUCCESS;
}

status_t free_space_set_output(knl_session_t *session, space_t *space, page_id_t start_page, uint64 page_count,
    knl_cursor_t *cursor)
{
    row_assist_t row;
    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, ARRAY_IN(g_dba_free_space_columns));
    CT_RETURN_IFERR(row_put_str(&row, space->ctrl->name));
    /* FILE_ID */
    CT_RETURN_IFERR(row_put_int32(&row, (int32)start_page.file));
    /* BLOCK_ID */
    CT_RETURN_IFERR(row_put_int32(&row, (int32)start_page.page));
    /* BLOCKS */
    CT_RETURN_IFERR(row_put_int64(&row, (int64)page_count));
    /* BYTES */
    CT_RETURN_IFERR(row_put_int64(&row, (int64)(page_count * DEFAULT_PAGE_SIZE(session))));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    return CT_SUCCESS;
}

status_t free_space_get_bitmap(knl_session_t *session, space_t *space, page_id_t *next_page_id, knl_cursor_t *cur)
{
    uint64 page_count = 0;
    uint32 start_pid = 0;
    bool32 is_last = CT_FALSE;
    uint32 file_id;

    if (!IS_INVALID_PAGID(*next_page_id)) {
        if (df_verify_pageid_by_size(session, *next_page_id) != CT_SUCCESS) {
            cur->eof = CT_TRUE;
            return CT_SUCCESS;
        }
    }

    while (cur->rowid.vm_tag < CT_MAX_SPACE_FILES) {
        file_id = space->ctrl->files[cur->rowid.vm_tag];
        if (file_id == CT_INVALID_ID32) {
            cur->rowid.vm_tag++;
            continue;
        }

        if (knl_get_free_extent(session, file_id, *next_page_id, &start_pid, &page_count, &is_last) != CT_SUCCESS) {
            // this file has no free space, move to next file
            cur->rowid.vm_tag++;
            start_pid = 0;
            page_count = 0;
        } else {
            // if this is the last extent of current datafile, switch to next datafile and set output
            // otherwise, update start_page postion and fetch again
            if (is_last) {
                cur->rowid.vm_tag++;
                *next_page_id = INVALID_PAGID;
            } else {
                next_page_id->page = (uint32)(start_pid + page_count);
                next_page_id->file = file_id;
            }
            page_id_t free_start;
            free_start.page = start_pid;
            free_start.file = file_id;
            free_space_set_output(session, space, free_start, page_count, cur);
            return CT_SUCCESS;
        }
    }

    cur->eof = CT_TRUE;
    return CT_SUCCESS;
}

status_t free_space_get_free_extent(knl_session_t *session, space_t *space, space_head_t *head, page_id_t *next_page_id,
    knl_cursor_t *cursor)
{
    uint32 extent_size = space->ctrl->extent_size;
    if (IS_INVALID_PAGID(*next_page_id)) {
        *next_page_id = head->free_extents.first;
    }

    uint32 first_page_id = next_page_id->page;
    bool32 is_swap_space = IS_SWAP_SPACE(space);
    uint32 ext_count = 1;
    page_id_t origin_page_id = *next_page_id;
    while (cursor->rowid.vmid++ < head->free_extents.count - 1) {
        origin_page_id = *next_page_id;
        *next_page_id = is_swap_space ? spc_try_get_next_temp_ext(session, *next_page_id) :
                                        spc_get_next_ext(session, *next_page_id);
        if (IS_INVALID_PAGID(*next_page_id)) {
            CT_THROW_ERROR(ERR_INVALID_PAGE_ID, ", free extent list of swap space is outdated");
            return CT_ERROR;
        }

        // free extent may be other datafile
        if (origin_page_id.file == next_page_id->file) {
            if (origin_page_id.page == next_page_id->page + extent_size) {
                // page id descend continuously, record next page id as the starting page id
                first_page_id = next_page_id->page;
            } else if (next_page_id->page != origin_page_id.page + extent_size) {
                // page id not continuously, break to make a row
                break;
            }
        }
        ext_count++;
    }

    origin_page_id.page = first_page_id;
    free_space_set_output(session, space, origin_page_id, (uint64)ext_count * extent_size, cursor);
    return CT_SUCCESS;
}

void free_space_get_file_hwm(knl_session_t *session, space_t *space, const space_head_t *head, knl_cursor_t *cursor)
{
    uint32 file_id;
    page_id_t start_page;
    while (cursor->rowid.vm_tag < CT_MAX_SPACE_FILES) {
        file_id = space->ctrl->files[cursor->rowid.vm_tag];
        if (file_id == CT_INVALID_ID32 || !DATAFILE_IS_ONLINE(DATAFILE_GET(session, file_id))) {
            cursor->rowid.vm_tag++;
            continue;
        }

        start_page.page = head->hwms[cursor->rowid.vm_tag];
        uint64 page_count = (DATAFILE_GET(session, file_id)->ctrl->size / DEFAULT_PAGE_SIZE(session)) - start_page.page;
        if (page_count == 0) {
            cursor->rowid.vm_tag++;
            continue;
        }

        start_page.file = (uint16)file_id;
        free_space_set_output(session, space, start_page, page_count, cursor);
        cursor->rowid.vm_tag++;
        return;
    }

    // finish all files, set eof
    cursor->eof = CT_TRUE;
}

status_t free_space_get_normal(knl_session_t *session, space_t *space, space_head_t *head, page_id_t *page_id,
    knl_cursor_t *cursor)
{
    if (!IS_INVALID_PAGID(*page_id)) {
        if (df_verify_pageid_by_hwm(session, *page_id) != CT_SUCCESS) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }
    }

    if (cursor->rowid.vmid < head->free_extents.count) {
        return free_space_get_free_extent(session, space, head, page_id, cursor);
    }

    free_space_get_file_hwm(session, space, head, cursor);
    return CT_SUCCESS;
}

// cursor->rowid.vmid;       // 32 free extent num
// cursor->rowid.vm_slot;    // 16 space id
// cursor->rowid.vm_tag;     // 16 file hwm id from space
// cursor->page_buf          // page_id
status_t dba_free_space_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor)
{
    knl_session_t *session = &stmt->session->knl_session;

    if ((uint32)cursor->rowid.vm_slot >= CT_MAX_SPACES) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    space_t *space = SPACE_GET(session, cursor->rowid.vm_slot);
    if (space->ctrl == NULL || !space->ctrl->used || !SPACE_IS_ONLINE(space)) {
        // space is not online, no need print error code.
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    page_id_t *page_id = (page_id_t *)cursor->page_buf;
    status_t status = CT_SUCCESS;

    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);
    space_head_t *head = SPACE_HEAD_RESIDENT(session, space);
    if (head == NULL) {
        dls_spin_unlock(session, &space->lock);
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    if (SPACE_IS_BITMAPMANAGED(space)) {
        status = free_space_get_bitmap(session, space, page_id, cursor);
    } else {
        status = free_space_get_normal(session, space, head, page_id, cursor);
    }
    dls_spin_unlock(session, &space->lock);

    return status;
}

status_t dba_free_space_verify(sql_verifier_t *verf, sql_table_t *table)
{
    return table_func_verify(verf, &table->func, 1, 1);
}
