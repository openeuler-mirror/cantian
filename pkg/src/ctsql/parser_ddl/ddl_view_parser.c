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
 * ddl_view_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_view_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ddl_view_parser.h"
#include "ddl_parser_common.h"
#include "ctsql_dependency.h"
#include "ctsql_context.h"
#include "ctsql_table_func.h"

static status_t sql_parse_view_column_defs(sql_stmt_t *stmt, lex_t *lex, knl_view_def_t *def)
{
    word_t word;
    knl_column_def_t *column = NULL;
    text_t name;

    for (;;) {
        if (lex_expected_fetch(lex, &word) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (word.ex_count != 0) {
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "too many dot for column");
            return CT_ERROR;
        }
        if (sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &name) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (sql_check_duplicate_column(&def->columns, &name) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cm_galist_new(&def->columns, sizeof(knl_column_def_t), (pointer_t *)&column) != CT_SUCCESS) {
            return CT_ERROR;
        }

        column->name = name;
        if (lex_fetch(lex, &word) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (word.type == WORD_TYPE_EOF) {
            break;
        }

        if (!IS_SPEC_CHAR(&word, ',')) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "\",\" expected but %s found", T2S(&word.text));
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static inline bool32 sql_check_context_ref_llt(sql_context_t *sql_ctx)
{
    sql_table_entry_t *table = NULL;

    for (uint32 i = 0; i < sql_ctx->tables->count; i++) {
        table = (sql_table_entry_t *)cm_galist_get(sql_ctx->tables, i);
        if (IS_LTT_BY_NAME(table->name.str)) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

static status_t sql_verify_view_column_def(sql_stmt_t *stmt, knl_view_def_t *def, sql_select_t *select_ctx)
{
    rs_column_t *rs_col = NULL;
    knl_column_def_t *col_def = NULL;
    sql_query_t *query = select_ctx->first_query;

    if (query == NULL) {
        return CT_ERROR;
    }

    if (def->columns.count == 0) {
        for (uint32 i = 0; i < query->rs_columns->count; i++) {
            rs_col = (rs_column_t *)cm_galist_get(query->rs_columns, i);
            if (sql_check_duplicate_column(&def->columns, &rs_col->name)) {
                return CT_ERROR;
            }
            if (cm_galist_new(&def->columns, sizeof(knl_column_def_t), (pointer_t *)&col_def) != CT_SUCCESS) {
                return CT_ERROR;
            }

            MEMS_RETURN_IFERR(memset_s(col_def, sizeof(knl_column_def_t), 0, sizeof(knl_column_def_t)));

            if (sql_copy_text(stmt->context, &rs_col->name, &col_def->name) != CT_SUCCESS) {
                return CT_ERROR;
            }
            col_def->typmod = rs_col->typmod;
            col_def->nullable = CT_BIT_TEST(rs_col->rs_flag, RS_NULLABLE) ? CT_TRUE : CT_FALSE;
        }
    } else {
        if (def->columns.count != query->rs_columns->count) {
            CT_THROW_ERROR(ERR_COLUMNS_MISMATCH);
            return CT_ERROR;
        }
        for (uint32 i = 0; i < def->columns.count; i++) {
            col_def = cm_galist_get(&def->columns, i);
            rs_col = (rs_column_t *)cm_galist_get(query->rs_columns, i);
            col_def->typmod = rs_col->typmod;
            col_def->nullable = CT_BIT_TEST(rs_col->rs_flag, RS_NULLABLE) ? CT_TRUE : CT_FALSE;
        }
    }
    return CT_SUCCESS;
}

static status_t sql_verify_circular_view(sql_stmt_t *stmt, knl_view_def_t *def, sql_select_t *select_ctx)
{
    text_t user, name;
    sql_context_t *sql_ctx = stmt->context;
    sql_table_entry_t *table = NULL;

    for (uint32 i = 0; i < sql_ctx->tables->count; i++) {
        table = cm_galist_get(sql_ctx->tables, i);
        if (cm_text_equal(&def->user, &table->user) && cm_text_equal(&def->name, &table->name)) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "circular view definition encountered");
            return CT_ERROR;
        }

        if (SYNONYM_EXIST(&table->dc)) {
            knl_get_link_name(&table->dc, &user, &name);
            if (cm_text_equal(&def->user, &user) && cm_text_equal(&def->name, &name)) {
                CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "circular view definition encountered");
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}


static inline status_t sql_generate_column_prefix(column_word_t *col, char *buf, uint32 buf_size, int *offset)
{
    int iret_snprintf = 0;
    if (col->user.len > 0) {
        iret_snprintf = snprintf_s(buf, buf_size, buf_size - 1, "\"%s\".", T2S(&col->user));
        PRTS_RETURN_IFERR(iret_snprintf);
        *offset = iret_snprintf;
        iret_snprintf =
            snprintf_s(buf + *offset, buf_size - *offset, buf_size - *offset - 1, "\"%s\".", T2S(&col->table));
        PRTS_RETURN_IFERR(iret_snprintf);
        *offset += iret_snprintf;
        return CT_SUCCESS;
    }

    if (col->table.len > 0) {
        iret_snprintf = snprintf_s(buf, buf_size, buf_size - 1, "\"%s\".", T2S(&col->table));
        PRTS_RETURN_IFERR(iret_snprintf);
        *offset = iret_snprintf;
    }
    return CT_SUCCESS;
}
static inline status_t sql_generate_with_subselect(sql_table_t *table, column_word_t *col, knl_view_def_t *def)
{
    int32 offset = 0;
    rs_column_t *rs_col = NULL;
    galist_t *rs_columns = NULL;
    char buf[3 * CT_MAX_NAME_LEN + 12];

    CT_RETURN_IFERR(sql_generate_column_prefix(col, buf, sizeof(buf), &offset));

    rs_columns = table->select_ctx->first_query->rs_columns;
    for (uint32 i = 0; i < rs_columns->count; i++) {
        rs_col = (rs_column_t *)cm_galist_get(rs_columns, i);
        PRTS_RETURN_IFERR(
            snprintf_s(buf + offset, sizeof(buf) - offset, sizeof(buf) - offset - 1, "\"%s\",", T2S(&rs_col->name)));
        CT_RETURN_IFERR(sql_text_concat_n_str(&def->sub_sql, CT_LARGE_PAGE_SIZE, buf, (uint32)strlen(buf)));
    }
    return CT_SUCCESS;
}

static inline status_t sql_generate_with_knl_table(sql_table_t *table, column_word_t *col, knl_view_def_t *def)
{
    int32 offset = 0;
    char buf[3 * CT_MAX_NAME_LEN + 12];
    uint32 cols;

    knl_column_t *knl_col = NULL;

    CT_RETURN_IFERR(sql_generate_column_prefix(col, buf, sizeof(buf), &offset));
    cols = knl_get_column_count(table->entry->dc.handle);
    for (uint32 i = 0; i < cols; i++) {
        knl_col = knl_get_column(table->entry->dc.handle, i);
        if (KNL_COLUMN_INVISIBLE(knl_col)) {
            continue;
        }
        PRTS_RETURN_IFERR(
            snprintf_s(buf + offset, sizeof(buf) - offset, sizeof(buf) - offset - 1, "\"%s\",", knl_col->name));
        CT_RETURN_IFERR(sql_text_concat_n_str(&def->sub_sql, CT_LARGE_PAGE_SIZE, buf, (uint32)strlen(buf)));
    }
    return CT_SUCCESS;
}

static inline status_t sql_generate_with_func_table(sql_table_t *table, column_word_t *col, knl_view_def_t *def)
{
    int32 offset = 0;
    knl_column_t *knl_col = NULL;
    uint32 cols;
    text_t name = { "CAST", 4 };
    char buf[3 * CT_MAX_NAME_LEN + 12];
    table_func_t *func = &table->func;
    expr_tree_t *arg = NULL;
    arg = func->args->next;
    plv_object_t *object = NULL;
    plv_collection_t *collection = (plv_collection_t *)arg->root->udt_type;
    CT_RETURN_IFERR(sql_generate_column_prefix(col, buf, sizeof(buf), &offset));
    if (cm_compare_text_ins(&table->func.name, &name) == 0 && collection->attr_type == UDT_OBJECT) {
        object = &collection->elmt_type->typdef.object;
        cols = object->count;
        for (uint32 i = 0; i < cols; i++) {
            plv_object_attr_t *attr = udt_seek_obj_field_byid(object, i);
            PRTS_RETURN_IFERR(
                snprintf_s(buf + offset, sizeof(buf) - offset, sizeof(buf) - offset - 1, "\"%s\",", T2S(&attr->name)));
            CT_RETURN_IFERR(sql_text_concat_n_str(&def->sub_sql, CT_LARGE_PAGE_SIZE, buf, (uint32)strlen(buf)));
        }
    } else {
        cols = table->func.desc->column_count;
        for (uint32 i = 0; i < cols; i++) {
            knl_col = &table->func.desc->columns[i];
            PRTS_RETURN_IFERR(
                snprintf_s(buf + offset, sizeof(buf) - offset, sizeof(buf) - offset - 1, "\"%s\",", knl_col->name));
            CT_RETURN_IFERR(sql_text_concat_n_str(&def->sub_sql, CT_LARGE_PAGE_SIZE, buf, (uint32)strlen(buf)));
        }
    }
    return CT_SUCCESS;
}

static status_t sql_generate_with_json_table(sql_table_t *table, column_word_t *col, knl_view_def_t *def)
{
    int32 offset = 0;
    uint32 cols_count = table->json_table_info->columns.count;
    rs_column_t *rs = NULL;
    char buf[3 * CT_MAX_NAME_LEN + 12];

    CT_RETURN_IFERR(sql_generate_column_prefix(col, buf, sizeof(buf), &offset));
    for (uint32 i = 0; i < cols_count; i++) {
        rs = (rs_column_t *)cm_galist_get(&table->json_table_info->columns, i);
        PRTS_RETURN_IFERR(
            snprintf_s(buf + offset, sizeof(buf) - offset, sizeof(buf) - offset - 1, "\"%s\",", T2S(&rs->name)));
        CT_RETURN_IFERR(sql_text_concat_n_str(&def->sub_sql, CT_LARGE_PAGE_SIZE, buf, (uint32)strlen(buf)));
    }
    return CT_SUCCESS;
}

static inline status_t sql_generate_sql_with_table(sql_table_t *table, column_word_t *col_word, knl_view_def_t *def)
{
    switch (table->type) {
        case SUBSELECT_AS_TABLE:
        case WITH_AS_TABLE:
            return sql_generate_with_subselect(table, col_word, def);
        case FUNC_AS_TABLE:
            return sql_generate_with_func_table(table, col_word, def);
        case JSON_TABLE:
            return sql_generate_with_json_table(table, col_word, def);
        default:
            return sql_generate_with_knl_table(table, col_word, def);
    }
}

static status_t sql_generate_sql_with_query(sql_stmt_t *stmt, text_t *src_sql, sql_query_t *query, knl_view_def_t *def,
    uint32 *offset)
{
    expr_node_t *node = NULL;
    sql_table_t *table = NULL;
    column_word_t *col_word = NULL;
    query_column_t *column = NULL;
    star_location_t *loc = NULL;

    for (uint32 i = 0; i < query->columns->count; i++) {
        column = (query_column_t *)cm_galist_get(query->columns, i);
        if (column->expr->root->type != EXPR_NODE_STAR) {
            continue;
        }

        if (def->status == OBJ_STATUS_INVALID) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "create or replace force view don't support select *");
            return CT_ERROR;
        }

        loc = &column->expr->star_loc;
        if (sql_text_concat_n_str(&def->sub_sql, CT_LARGE_PAGE_SIZE, src_sql->str + (*offset),
            loc->begin - (*offset)) != CT_SUCCESS) {
            return CT_ERROR;
        }

        *offset = loc->end;
        node = column->expr->root;
        col_word = &node->word.column;

        if (col_word->table.len != 0) {
            table = (sql_table_t *)sql_array_get(&query->tables, VAR_TAB(&node->value));
            CT_RETURN_IFERR(sql_generate_sql_with_table(table, col_word, def));
            CM_REMOVE_LAST(&def->sub_sql);
            continue;
        }

        for (uint32 j = 0; j < query->tables.count; j++) {
            table = (sql_table_t *)sql_array_get(&query->tables, j);
            CT_RETURN_IFERR(sql_generate_sql_with_table(table, col_word, def));
        }
        CM_REMOVE_LAST(&def->sub_sql);
    }
    return CT_SUCCESS;
}


static status_t sql_generate_sql_with_select_node(sql_stmt_t *stmt, text_t *src_sql, select_node_t *node,
    knl_view_def_t *def, uint32 *offset)
{
    if (node->type != SELECT_NODE_QUERY) {
        CT_RETURN_IFERR(sql_generate_sql_with_select_node(stmt, src_sql, node->left, def, offset));
        return sql_generate_sql_with_select_node(stmt, src_sql, node->right, def, offset);
    }
    return sql_generate_sql_with_query(stmt, src_sql, node->query, def, offset);
}

static status_t sql_generate_def_sql(sql_stmt_t *stmt, text_t *src_sql, uint32 *offset, sql_select_t *select_ctx,
    knl_view_def_t *def)
{
    int32 i = 0;
    uint64 page_count;
    knl_begin_session_wait(KNL_SESSION(stmt), LARGE_POOL_ALLOC, CT_FALSE);
    while (!mpool_try_alloc_page(KNL_SESSION(stmt)->kernel->attr.large_pool, &stmt->context->large_page_id)) {
        cm_spin_sleep_and_stat2(1);

        i++;
        if (i == CM_MPOOL_ALLOC_TRY_TIME_MAX) {
            page_count = (uint64)KNL_SESSION(stmt)->kernel->attr.large_pool->page_count;
            knl_end_session_wait(KNL_SESSION(stmt), LARGE_POOL_ALLOC);
            CT_THROW_ERROR(ERR_ALLOC_MEMORY, page_count, "mpool try alloc page");
            return CT_ERROR;
        }
    }
    knl_end_session_wait(KNL_SESSION(stmt), LARGE_POOL_ALLOC);

    def->sub_sql.len = 0;
    def->sub_sql.str = mpool_page_addr(KNL_SESSION(stmt)->kernel->attr.large_pool, stmt->context->large_page_id);

    CT_RETURN_IFERR(sql_generate_sql_with_select_node(stmt, src_sql, select_ctx->root, def, offset));
    CT_RETURN_IFERR(
        sql_text_concat_n_str(&def->sub_sql, CT_LARGE_PAGE_SIZE, src_sql->str + (*offset), src_sql->len - (*offset)));
    cm_trim_text(&def->sub_sql);
    return CT_SUCCESS;
}

status_t sql_verify_view_def(sql_stmt_t *stmt, knl_view_def_t *def, lex_t *lex, bool32 is_force)
{
    uint32 offset;
    sql_select_t *select_ctx = NULL;
    sql_verifier_t verf = { 0 };
    status_t ret = CT_SUCCESS;

    offset = (uint32)(lex->curr_text->str - lex->text.str);

    if (sql_parse_view_subselect(stmt, (text_t *)lex->curr_text, &select_ctx, &lex->loc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_check_context_ref_llt(stmt->context)) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "Prevent creating view of local temporary tables");
        return CT_ERROR;
    }

    def->select = select_ctx;
    verf.stmt = stmt;
    verf.context = stmt->context;

    do {
        ret = sql_verify_select_context(&verf, select_ctx);
        CT_BREAK_IF_ERROR(ret);
        ret = sql_verify_view_column_def(stmt, def, select_ctx);
        CT_BREAK_IF_ERROR(ret);

        ret = sql_verify_circular_view(stmt, def, select_ctx);
    } while (0);

    if (ret != CT_SUCCESS) {
        // if is_force is true, ignore verify error
        CT_RETVALUE_IFTRUE(!is_force, CT_ERROR);
        cm_reset_error();
        if (def->columns.count == 0) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "create or replace force view need assign columns");
            return ret;
        }
    }

    def->status = (ret == CT_SUCCESS ? OBJ_STATUS_VALID : OBJ_STATUS_INVALID);

    return sql_generate_def_sql(stmt, (text_t *)&lex->text, &offset, select_ctx, def);
}

static inline bool32 sql_check_context_ref_sys_tab(sql_stmt_t *stmt, knl_view_def_t *def)
{
    galist_t *objs = def->ref_objects;
    object_address_t *ref_obj = NULL;
    text_t owner_name, obj_name;
    knl_session_t *se = &stmt->session->knl_session;
    dc_context_t *ctx = &se->kernel->dc_ctx;
    uint32 i;
    object_type_t objtype;
    text_t sys_user_name = {
        .str = SYS_USER_NAME,
        .len = SYS_USER_NAME_LEN
    };
    knl_dictionary_t dc;
    if (objs->count == 0) {
        return CT_FALSE;
    }
    if (cm_compare_text(&def->user, &sys_user_name) == 0) {
        return CT_FALSE;
    }
    if (g_instance->attr.access_dc_enable == CT_FALSE) {
        for (i = 0; i < objs->count; i++) {
            ref_obj = (object_address_t *)cm_galist_get((galist_t *)objs, i);
            if (((ref_obj->tid != OBJ_TYPE_TABLE) && (ref_obj->tid != OBJ_TYPE_VIEW) &&
                (ref_obj->tid != OBJ_TYPE_SYNONYM))) {
                continue;
            }
            cm_str2text(ctx->users[ref_obj->uid]->desc.name, &owner_name);
            cm_str2text(ref_obj->name, &obj_name);
            objtype = ref_obj->tid;
            if (ref_obj->tid == OBJ_TYPE_SYNONYM) {
                if ((CT_SUCCESS ==
                    knl_open_dc_with_public(&stmt->session->knl_session, &owner_name, CT_TRUE, &obj_name, &dc)) &&
                    (dc.is_sysnonym) && (dc.type <= DICT_TYPE_GLOBAL_DYNAMIC_VIEW)) {
                    knl_get_link_name(&dc, &owner_name, &obj_name);
                    objtype = dc.type >= DICT_TYPE_VIEW ? OBJ_TYPE_VIEW : OBJ_TYPE_TABLE;
                    knl_close_dc(&dc);
                } else {
                    return CT_FALSE;
                }
            }
            if ((cm_compare_text(&owner_name, &sys_user_name) == 0) && (knl_check_obj_priv_by_name(se, &def->user,
                &owner_name, &obj_name, objtype, CT_PRIV_SELECT) == CT_FALSE)) {
                return CT_TRUE;
            }
        }
    }
    return CT_FALSE;
}

status_t sql_parse_create_view(sql_stmt_t *stmt, bool32 is_replace, bool32 is_force)
{
    word_t word;
    bool32 result = CT_FALSE;
    knl_view_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;

    stmt->context->type = CTSQL_TYPE_CREATE_VIEW;

    if (sql_alloc_mem(stmt->context, sizeof(knl_view_def_t), (pointer_t *)&def) != CT_SUCCESS) {
        return CT_ERROR;
    }
    def->is_replace = is_replace;
    cm_galist_init(&def->columns, stmt->context, sql_alloc_mem);
    lex->flags = LEX_WITH_OWNER;

    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_convert_object_name(stmt, &word, &def->user, NULL, &def->name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_try_fetch_bracket(lex, &word, &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (result == CT_TRUE) {
        CT_RETURN_IFERR(lex_push(lex, &word.text));

        if (sql_parse_view_column_defs(stmt, lex, def) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }

        lex_pop(lex);
    }

    if (lex_expected_fetch_word(lex, "AS") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_verify_view_def(stmt, def, lex, is_force) != CT_SUCCESS) {
        return CT_ERROR;
    }

    def->sql_tpye = SQL_STYLE_CT;
    stmt->context->entry = def;

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(galist_t), (void **)&def->ref_objects));
    cm_galist_init(def->ref_objects, stmt->context, sql_alloc_mem);
    CT_RETURN_IFERR(sql_append_references(def->ref_objects, stmt->context));
    if (sql_check_context_ref_sys_tab(stmt, def) == CT_TRUE) {
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}


status_t sql_parse_drop_view(sql_stmt_t *stmt)
{
    lex_t *lex = stmt->session->lex;
    knl_drop_def_t *def = NULL;
    bool32 is_cascade = CT_FALSE;
    bool32 is_restrict = CT_FALSE;
    knl_dictionary_t dc;
    bool32 if_exists;
    dc.type = DICT_TYPE_TABLE;
    lex->flags = LEX_WITH_OWNER;
    stmt->context->type = CTSQL_TYPE_DROP_VIEW;

    if (sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (void **)&def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_parse_drop_object(stmt, def) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if_exists = def->options & DROP_IF_EXISTS;
    if (if_exists == CT_FALSE) {
        if (knl_open_dc_with_public(&stmt->session->knl_session, &def->owner, CT_TRUE, &def->name, &dc) != CT_SUCCESS) {
            cm_reset_error_user(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&def->owner), T2S_EX(&def->name),
                ERR_TYPE_TABLE_OR_VIEW);
            sql_check_user_priv(stmt, &def->owner);
            return CT_ERROR;
        }
        knl_close_dc(&dc);
    }
    stmt->context->entry = def;

    if (lex_try_fetch(lex, "CASCADE", &is_cascade) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (is_cascade) {
        if (lex_expected_fetch_word(lex, "CONSTRAINTS") != CT_SUCCESS) {
            return CT_ERROR;
        }
        def->options |= DROP_CASCADE_CONS;
    }

    if (lex_try_fetch(lex, "RESTRICT", &is_restrict) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (is_restrict) {
        /* NEED TO PARSE CASCADE INFO. */
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "restrict option no implement.");
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}
