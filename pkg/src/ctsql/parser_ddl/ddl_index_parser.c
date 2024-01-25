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
 * ddl_index_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_index_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ddl_index_parser.h"
#include "ddl_parser_common.h"
#include "ddl_partition_parser.h"
#include "ddl_table_parser.h"
#include "ctsql_func.h"
#include "ctsql_serial.h"
#include "expr_parser.h"
#include "func_parser.h"

static status_t sql_parse_subpart_index(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_part_def_t *compart_def)
{
    knl_part_def_t *subpart_def = NULL;

    cm_galist_init(&compart_def->subparts, stmt->context, sql_alloc_mem);
    CT_RETURN_IFERR(lex_push(lex, &word->text));

    for (;;) {
        if (lex_expected_fetch_word(lex, "SUBPARTITION") != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }

        if (lex_expected_fetch_variant(lex, word) != CT_SUCCESS) {
            lex_pop(lex);
            cm_reset_error();
            CT_SRC_THROW_ERROR(word->text.loc, ERR_INVALID_PART_NAME);
            return CT_ERROR;
        }

        if (cm_galist_new(&compart_def->subparts, sizeof(knl_part_def_t), (pointer_t *)&subpart_def) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }

        if (sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &subpart_def->name) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }

        if (sql_parse_subpartition_attrs(stmt, lex, word, subpart_def) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }

        if (word->type == WORD_TYPE_EOF) {
            lex_pop(lex);
            return CT_SUCCESS;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            lex_pop(lex);
            CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
            return CT_ERROR;
        }
    }
}

static status_t sql_parse_part_index(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_index_def_t *def)
{
    bool32 result = CT_FALSE;
    knl_part_def_t *part_def = NULL;
    status_t status;
    def->parted = CT_TRUE;
    def->part_def = NULL;

    status = lex_try_fetch_bracket(lex, word, &result);
    CT_RETURN_IFERR(status);

    if (result == CT_FALSE) {
        return CT_SUCCESS;
    }

    status = sql_alloc_mem(stmt->context, sizeof(knl_part_obj_def_t), (pointer_t *)&def->part_def);
    CT_RETURN_IFERR(status);
    cm_galist_init(&def->part_def->parts, stmt->context, sql_alloc_mem);

    CT_RETURN_IFERR(lex_push(lex, &word->text));
    for (;;) {
        status = lex_expected_fetch_word(lex, "PARTITION");
        CT_BREAK_IF_ERROR(status);

        if (lex_expected_fetch_variant(lex, word) != CT_SUCCESS) {
            cm_reset_error();
            CT_SRC_THROW_ERROR(word->text.loc, ERR_INVALID_PART_NAME);
            status = CT_ERROR;
            break;
        }
        status = cm_galist_new(&def->part_def->parts, sizeof(knl_part_def_t), (pointer_t *)&part_def);
        CT_BREAK_IF_ERROR(status);

        status = sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &part_def->name);
        CT_BREAK_IF_ERROR(status);

        part_def->support_csf = CT_FALSE;
        part_def->exist_subparts = def->part_def->is_composite ? CT_TRUE : CT_FALSE;
        status = sql_parse_partition_attrs(stmt, lex, word, part_def);
        CT_BREAK_IF_ERROR(status);

        if (word->type == WORD_TYPE_BRACKET) { // composite part index
            def->part_def->is_composite = CT_TRUE;
            status = sql_parse_subpart_index(stmt, lex, word, part_def);
            CT_BREAK_IF_ERROR(status);
            status = lex_fetch(lex, word);
            CT_BREAK_IF_ERROR(status);
        }

        if (word->type == WORD_TYPE_EOF) {
            status = CT_SUCCESS;
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
            status = CT_ERROR;
            break;
        }
    }

    lex_pop(lex);
    return status;
}

status_t sql_check_duplicate_index_column(sql_stmt_t *stmt, galist_t *columns, knl_index_col_def_t *new_column)
{
    uint32 i;
    knl_index_col_def_t *column = NULL;

    for (i = 0; i < columns->count; i++) {
        column = (knl_index_col_def_t *)cm_galist_get(columns, i);
        CT_CONTINUE_IFTRUE(column->is_func != new_column->is_func);

        if (!column->is_func) {
            if (cm_text_equal(&column->name, &new_column->name)) {
                CT_THROW_ERROR(ERR_DUPLICATE_NAME, "column", T2S(&column->name));
                return CT_ERROR;
            }
        } else {
            if (sql_expr_node_equal(stmt, ((expr_tree_t *)column->func_expr)->root,
                ((expr_tree_t *)new_column->func_expr)->root, NULL)) {
                CT_THROW_ERROR(ERR_DUPLICATE_NAME, "column", T2S(&column->func_text));
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

/* blacklist of words can not used in function index expression
  e.g. create index ix_t on tab (nvl(f1, f1, sysdate));
*/
static reserved_wid_t g_unindexable_word[] = {
    RES_WORD_ROWNUM,
    RES_WORD_ROWID,
    RES_WORD_ROWSCN,
    RES_WORD_CURDATE,
    RES_WORD_SYSDATE,
    RES_WORD_CURTIMESTAMP,
    RES_WORD_SYSTIMESTAMP,
    RES_WORD_LOCALTIMESTAMP,
    RES_WORD_UTCTIMESTAMP,
    RES_WORD_USER,
    RES_WORD_SESSIONTZ
};

static status_t sql_verify_index_expr(visit_assist_t *va, expr_node_t **node)
{
    text_t *col_name = NULL;
    reserved_wid_t word;
    CM_ASSERT((*node)->type != EXPR_NODE_COLUMN);
    if ((*node)->type == EXPR_NODE_DIRECT_COLUMN) {
        col_name = &(*node)->word.column.name.value;
        // e.g. nvl2("F1", "f1", 100) indexed on 2 different columns.
        if (va->result0 == CT_TRUE && !cm_text_equal((text_t *)va->param0, col_name)) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "multiple columns found in function index");
            return CT_ERROR;
        }

        va->result0 = CT_TRUE;
        *(text_t *)(va->param0) = *col_name;
    }

    if ((*node)->type == EXPR_NODE_RESERVED) {
        word = (reserved_wid_t)VALUE(uint32, &(*node)->value);
        for (uint32 i = 0; i < ELEMENT_COUNT(g_unindexable_word); i++) {
            if (word == g_unindexable_word[i]) {
                CT_SRC_THROW_ERROR(NODE_LOC(*node), ERR_SQL_SYNTAX_ERROR, "unexpect word");
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

static status_t sql_verify_index_column(sql_stmt_t *stmt, expr_tree_t *expr, text_t *column_name)
{
    visit_assist_t va;
    sql_init_visit_assist(&va, stmt, NULL);
    va.param0 = column_name;
    va.result0 = CT_FALSE;
    CT_RETURN_IFERR(visit_expr_tree(&va, expr, sql_verify_index_expr));

    if (va.result0 == CT_FALSE) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "index column expected but not found");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_verify_index_column_func(sql_stmt_t *stmt, expr_tree_t *func_expr, text_t *column_name)
{
    var_func_t *v = &func_expr->root->value.v_func;
    sql_func_t *func = sql_get_func(v);

    if (!func->indexable) {
        CT_THROW_ERROR_EX(ERR_FUNCTION_NOT_INDEXABLE, T2S(&func->name));
        return CT_ERROR;
    }

    // check argument
    return sql_verify_index_column(stmt, func_expr->root->argument, column_name);
}

static status_t sql_verify_func_index_datatype(expr_node_t *node)
{
    typmode_t *typmod = &NODE_TYPMODE(node);
    ct_type_t type = typmod->datatype;

    if (CT_IS_LOB_TYPE(type)) {
        CT_SRC_THROW_ERROR(NODE_LOC(node), ERR_CREATE_INDEX_ON_TYPE, "functional", get_datatype_name_str(type));
        return CT_ERROR;
    }

    if (type == CT_TYPE_ARRAY || typmod->is_array == CT_TRUE) {
        CT_SRC_THROW_ERROR(NODE_LOC(node), ERR_CREATE_INDEX_ON_TYPE, "functional", "ARRAY");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_verify_index_column_expr(sql_stmt_t *stmt, knl_index_col_def_t *def)
{
    expr_tree_t *expr = (expr_tree_t *)def->func_expr;
    sql_verifier_t verf = { 0 };
    verf.stmt = stmt;
    verf.context = stmt->context;
    verf.is_check_cons = CT_TRUE;

    verf.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_SUBSELECT | SQL_EXCL_BIND_PARAM | SQL_EXCL_PRIOR |
        SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_ROWSCN | SQL_EXCL_SEQUENCE |
        SQL_EXCL_WIN_SORT | SQL_EXCL_GROUPING | SQL_EXCL_PATH_FUNC | SQL_EXCL_ROWNODEID;

    if (sql_verify_expr_node(&verf, expr->root) != CT_SUCCESS) {
        cm_set_error_loc(expr->loc);
        return CT_ERROR;
    }

    def->datatype = expr->root->datatype;
    def->size = expr->root->size;

    if (def->func_text.len > CT_MAX_DFLT_VALUE_LEN) {
        CT_SRC_THROW_ERROR_EX(expr->root->loc, ERR_SQL_SYNTAX_ERROR, "function express string is too long, exceed %d",
            CT_MAX_DFLT_VALUE_LEN);
        return CT_ERROR;
    }

    switch (expr->root->type) {
        case EXPR_NODE_FUNC:
            CT_RETURN_IFERR(sql_verify_index_column_func(stmt, expr, &def->name));
            break;

        case EXPR_NODE_CASE:
            CT_RETURN_IFERR(sql_verify_index_column(stmt, expr, &def->name));
            break;

        default:
            CT_SRC_THROW_ERROR_EX(expr->loc, ERR_SQL_SYNTAX_ERROR, "invalid variant/object name was found");
            return CT_ERROR;
    }

    if (sql_verify_func_index_datatype(expr->root) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_parse_index_column(sql_stmt_t *stmt, lex_t *lex, knl_index_col_def_t *column, bool32 *have_func)
{
    status_t status;
    expr_tree_t *col_expr = NULL;
    expr_node_t *node = NULL;
    text_t expr_text;
    word_t word;

    expr_text = lex->curr_text->value;
    status = lex_expected_fetch(lex, &word);
    CT_RETURN_IFERR(status);

    if (IS_VARIANT(&word)) {
        column->is_func = CT_FALSE;
        column->func_expr = NULL;
        column->func_text.len = 0;
        return sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &column->name);
    }

    if (have_func &&
        (word.type == WORD_TYPE_FUNCTION || (word.type == WORD_TYPE_KEYWORD && word.id == KEY_WORD_CASE))) {
        CT_RETURN_IFERR(sql_create_expr(stmt, &col_expr));
        col_expr->loc = LEX_LOC;
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&node));
        node->owner = col_expr;
        node->type = word.type == WORD_TYPE_FUNCTION ? EXPR_NODE_FUNC : EXPR_NODE_CASE;
        node->unary = col_expr->unary;
        node->loc = word.text.loc;
        node->dis_info.need_distinct = CT_FALSE;
        node->dis_info.idx = CT_INVALID_ID32;
        node->optmz_info = (expr_optmz_info_t) { OPTIMIZE_NONE, 0 };
        if (node->type == EXPR_NODE_FUNC) {
            CT_RETURN_IFERR(sql_build_func_node(stmt, &word, node));
            expr_text.len = (uint32)(lex->curr_text->value.str - expr_text.str);
        } else {
            CT_RETURN_IFERR(sql_parse_case_expr(stmt, &word, node));
            expr_text.len = (uint32)(word.text.str + word.text.len - expr_text.str);
        }

        col_expr->root = node;

        column->is_func = CT_TRUE;
        column->func_expr = col_expr;
        column->name.len = 0;
        cm_trim_text(&expr_text);
        CT_RETURN_IFERR(sql_copy_text(stmt->context, &expr_text, &column->func_text));
        return sql_verify_index_column_expr(stmt, column);
    } else {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid variant/object name was found");
        return CT_ERROR;
    }
}

status_t sql_parse_column_list(sql_stmt_t *stmt, lex_t *lex, galist_t *column_list, bool32 have_sort, bool32 *have_func)
{
    word_t word;
    knl_index_col_def_t *column = NULL;
    knl_index_col_def_t tmp_col;
    status_t status;

    CT_RETURN_IFERR(lex_expected_fetch_bracket(lex, &word));
    CT_RETURN_IFERR(lex_push(lex, &word.text));

    uint32 pre_flags = lex->flags;
    lex->flags = LEX_WITH_OWNER;
    if (have_sort) {
        lex->flags |= LEX_WITH_ARG;
    }
    if (have_func != NULL) {
        *have_func = CT_FALSE;
    }
    cm_galist_init(column_list, stmt->context, sql_alloc_mem);

    for (;;) {
        status = sql_parse_index_column(stmt, lex, &tmp_col, have_func);
        CT_BREAK_IF_ERROR(status);

        status = sql_check_duplicate_index_column(stmt, column_list, &tmp_col);
        CT_BREAK_IF_ERROR(status);

        status = cm_galist_new(column_list, sizeof(knl_index_col_def_t), (void **)&column);
        CT_BREAK_IF_ERROR(status);
        *column = tmp_col;

        // set func flag
        if (column->is_func && have_func) {
            *have_func = CT_TRUE;
        }

        status = lex_fetch(lex, &word);
        CT_BREAK_IF_ERROR(status);

        column->mode = SORT_MODE_ASC;
        if (have_sort && (word.id == KEY_WORD_DESC || word.id == KEY_WORD_ASC)) {
            column->mode = (word.id == KEY_WORD_DESC) ? SORT_MODE_DESC : SORT_MODE_ASC;
            status = lex_fetch(stmt->session->lex, &word);
            CT_BREAK_IF_ERROR(status);
        }

        CT_BREAK_IF_TRUE(word.type == (uint32)WORD_TYPE_EOF);

        if (!IS_SPEC_CHAR(&word, ',')) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "invalid identifier");
            status = CT_ERROR;
            break;
        }
    }

    if (status == CT_SUCCESS) {
        lex->flags = pre_flags;
    }
    lex_pop(lex);
    return status;
}

status_t sql_parse_index_online(lex_t *lex, word_t *word, bool32 *online)
{
    if (*online) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate online");
        return CT_ERROR;
    }
    *online = CT_TRUE;
    return CT_SUCCESS;
}

status_t sql_parse_index_attrs(sql_stmt_t *stmt, lex_t *lex, knl_index_def_t *index_def)
{
    status_t status;
    word_t word;

    index_def->cr_mode = CT_INVALID_ID8;
    index_def->online = CT_FALSE;
    index_def->pctfree = CT_INVALID_ID32;
    index_def->parallelism = 0;
    index_def->is_reverse = CT_FALSE;

    for (;;) {
        CT_RETURN_IFERR(lex_fetch(lex, &word));

        if (word.type == WORD_TYPE_EOF || IS_SPEC_CHAR(&word, ',')) {
            lex_back(lex, &word);
            break;
        }

        switch (word.id) {
            case KEY_WORD_TABLESPACE:
                status = sql_parse_space(stmt, lex, &word, &index_def->space);
                break;

            case KEY_WORD_INITRANS:
                status = sql_parse_trans(lex, &word, &index_def->initrans);
                break;

            case KEY_WORD_LOCAL:
                status = sql_parse_part_index(stmt, lex, &word, index_def);
                break;

            case KEY_WORD_PCTFREE:
                status = sql_parse_pctfree(lex, &word, &index_def->pctfree);
                break;

            case KEY_WORD_CRMODE:
                status = sql_parse_crmode(lex, &word, &index_def->cr_mode);
                break;

            case KEY_WORD_ONLINE:
                status = sql_parse_index_online(lex, &word, &index_def->online);
                break;

            case KEY_WORD_PARALLEL:
                status = sql_parse_parallelism(lex, &word, &index_def->parallelism, CT_MAX_INDEX_PARALLELISM);
                break;

            case KEY_WORD_REVERSE:
                status = sql_parse_reverse(&word, &index_def->is_reverse);
                break;

            case KEY_WORD_NO_LOGGING:
                index_def->nologging = CT_TRUE;
                status = CT_SUCCESS;
                break;

            default:
                CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected text %s", W2S(&word));
                return CT_ERROR;
        }

        CT_RETURN_IFERR(status);
    }

    if (index_def->initrans == 0) {
        index_def->initrans =
            cm_text_str_equal_ins(&index_def->user, "SYS") ? CT_INI_TRANS : stmt->session->knl_session.kernel->attr.initrans;
    }

    if (index_def->pctfree == CT_INVALID_ID32) {
        index_def->pctfree = CT_PCT_FREE;
    }

    if (index_def->online && index_def->parallelism != 0) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "parallel creating", "create index online");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_parse_index_def(sql_stmt_t *stmt, lex_t *lex, knl_index_def_t *def)
{
    text_t index_schema;
    word_t word;
    bool32 idx_schema_explict = CT_FALSE;

    lex->flags |= LEX_WITH_OWNER;
    word.text.str = NULL;
    word.text.len = 0;
    def->user = word.text.value;

    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_convert_object_name(stmt, &word, &index_schema, &idx_schema_explict, &def->name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "ON") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_convert_object_name(stmt, &word, &def->user, NULL, &def->table) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /*
     * if index's schema specified explicitly and differed from the table's schema(no matter specified explicitly or
     * implicitly) an error should be raised
     */
    if (idx_schema_explict == CT_TRUE && cm_compare_text_ins(&index_schema, &def->user)) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
            "index user(%s) is not consistent with table "
            "user(%s)",
            T2S(&index_schema), T2S_EX(&def->user));
        return CT_ERROR;
    }

    /*
     * regist ddl table
     */
    CT_RETURN_IFERR(sql_regist_ddl_table(stmt, &def->user, &def->table));

    cm_galist_init(&def->columns, stmt->context, sql_alloc_mem);

    if (sql_parse_column_list(stmt, lex, &def->columns, CT_TRUE, &def->is_func) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_parse_index_attrs(stmt, lex, def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/**
 * Parse create index statement
 * @param[in]    sql statement handle
 * @param[in]    if index is unique
 * @return
 * - CT_SUCCESS
 * - CT_ERROR
 * @note must call after instance is startup
 * @see sql_parse_create
 */
status_t sql_parse_create_index(sql_stmt_t *stmt, bool32 is_unique)
{
    status_t status;
    knl_index_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;

    if (sql_alloc_mem(stmt->context, sizeof(knl_index_def_t), (void **)&def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    stmt->context->type = CTSQL_TYPE_CREATE_INDEX;
    def->unique = is_unique;

    status = sql_try_parse_if_not_exists(lex, &def->options);
    CT_RETURN_IFERR(status);

    if (sql_parse_index_def(stmt, lex, def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    stmt->context->entry = def;

    CT_RETURN_IFERR(lex_expected_end(lex));
    return CT_SUCCESS;
}

status_t sql_parse_create_unique_lead(sql_stmt_t *stmt)
{
    if (CT_SUCCESS != lex_expected_fetch_word(stmt->session->lex, "INDEX")) {
        return CT_ERROR;
    }

    return sql_parse_create_index(stmt, CT_TRUE);
}

static status_t sql_parse_rebuild_index_by_type(sql_stmt_t *stmt, lex_t *lex, word_t *word,
    rebuild_index_def_t *rebuild_def)
{
    switch (word->id) {
        case KEY_WORD_ONLINE:
            if (rebuild_def->is_online) {
                CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "duplicate online found");
                return CT_ERROR;
            }
            rebuild_def->is_online = CT_TRUE;
            break;
        case KEY_WORD_TABLESPACE:
            if (sql_parse_space(stmt, lex, word, &rebuild_def->space) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;
        case KEY_WORD_PCTFREE:
            if (sql_parse_pctfree(lex, word, &rebuild_def->pctfree) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;
        case KEY_WORD_KEEP:
            if (lex_expected_fetch_word(lex, "STORAGE") != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (rebuild_def->keep_storage) {
                CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "duplicate keep found");
                return CT_ERROR;
            }

            rebuild_def->keep_storage = CT_TRUE;
            break;
        case KEY_WORD_PARALLEL:
            if (sql_parse_parallelism(lex, word, &rebuild_def->parallelism, CT_MAX_REBUILD_INDEX_PARALLELISM) !=
                CT_SUCCESS) {
                return CT_ERROR;
            }
            break;
        default:
            CT_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "unexpected word %s found.", W2S(word));
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_parse_rebuild_index_partition_list(sql_stmt_t *stmt, lex_t *lex, rebuild_index_def_t *rebuild_def,
    word_t *word)
{
    uint32 part_index = 0;

    do {
        if (part_index >= MAX_REBUILD_PARTS) {
            CT_THROW_ERROR(ERR_INVALID_REBUILD_PART_RANGE, MAX_REBUILD_PARTS + 1);
            return CT_ERROR;
        }

        rebuild_def->specified_parts++;
        if (sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text,
            &rebuild_def->part_name[part_index]) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (lex_fetch(lex, word) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (word->type == WORD_TYPE_EOF) {
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }

        if (lex_fetch(lex, word) != CT_SUCCESS) {
            return CT_ERROR;
        }

        part_index++;
    } while (word->type != WORD_TYPE_EOF);

    return CT_SUCCESS;
}

static status_t sql_parse_rebuild_index(sql_stmt_t *stmt, lex_t *lex, knl_alindex_def_t *def)
{
    word_t word;
    uint32 match_id;
    rebuild_index_def_t *rebuild_def = &def->rebuild;

    rebuild_def->cr_mode = CT_INVALID_ID8;
    rebuild_def->is_online = CT_FALSE;
    rebuild_def->build_stats = CT_FALSE;
    rebuild_def->space.len = 0;
    rebuild_def->pctfree = CT_INVALID_ID32;
    rebuild_def->keep_storage = 0;
    rebuild_def->parallelism = 0;
    rebuild_def->specified_parts = 0;
    rebuild_def->lock_timeout = LOCK_INF_WAIT;

    if (lex_try_fetch_1of2(lex, "PARTITION", "SUBPARTITION", &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (match_id != CT_INVALID_ID32) {
        def->type = (match_id == 0 ? ALINDEX_TYPE_REBUILD_PART : ALINDEX_TYPE_REBUILD_SUBPART);
        if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (sql_parse_rebuild_index_partition_list(stmt, lex, rebuild_def, &word) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        def->type = ALINDEX_TYPE_REBUILD;
        MEMS_RETURN_IFERR(memset_s(rebuild_def->part_name, MAX_REBUILD_PARTS * sizeof(text_t), 0x00,
            MAX_REBUILD_PARTS * sizeof(text_t)));

        if (lex_fetch(lex, &word) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    while (word.type != WORD_TYPE_EOF) {
        CT_RETURN_IFERR(sql_parse_rebuild_index_by_type(stmt, lex, &word, rebuild_def));
        if (lex_fetch(lex, &word) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (rebuild_def->keep_storage && !rebuild_def->is_online) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "expected word online not found");
        return CT_ERROR;
    }

    if (rebuild_def->parallelism != 0 && rebuild_def->is_online) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "parallel rebuild", "rebuild index online");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_parse_rename_index(sql_stmt_t *stmt, lex_t *lex, knl_alindex_def_t *def)
{
    word_t word;
    key_wid_t wid;
    text_t owner;
    bool32 user_existed = CT_FALSE;
    if (lex_expected_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }
    def->type = ALINDEX_TYPE_RENAME;
    wid = (key_wid_t)word.id;
    if (word.type != WORD_TYPE_KEYWORD || wid != KEY_WORD_TO) {
        CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "TO expected but %s found", W2S(&word));
        return CT_ERROR;
    }
    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_convert_object_name(stmt, &word, &owner, &user_existed, &def->idx_def.new_name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (user_existed == CT_TRUE && cm_compare_text(&owner, &def->user) != 0) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "%s expected ", T2S(&def->user));
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}

static status_t sql_parse_modify_idxpart(sql_stmt_t *stmt, lex_t *lex, modify_idxpart_def_t *def)
{
    word_t word;
    status_t status = CT_SUCCESS;

    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->part_name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type != WORD_TYPE_KEYWORD) {
        CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "unexpected word %s found.", W2S(&word));
        return CT_ERROR;
    }

    switch (word.id) {
        case KEY_WORD_COALESCE:
            def->type = MODIFY_IDXPART_COALESCE;
            status = lex_expected_end(lex);
            break;
        case KEY_WORD_INITRANS:
            def->type = MODIFY_IDXPART_INITRANS;
            status = sql_parse_trans(lex, &word, &def->initrans);
            CT_BREAK_IF_ERROR(status);
            status = lex_expected_end(lex);
            break;
        case KEY_WORD_UNUSABLE:
            def->type = MODIFY_IDXPART_UNUSABLE;
            status = lex_expected_end(lex);
            break;
        default:
            CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "unexpected word %s found.", W2S(&word));
            return CT_ERROR;
    }

    return status;
}

static status_t sql_parse_modify_idxsubpart(sql_stmt_t *stmt, lex_t *lex, modify_idxpart_def_t *def)
{
    word_t word;
    status_t status = CT_SUCCESS;

    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->part_name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type != WORD_TYPE_KEYWORD) {
        CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "unexpected word %s found.", W2S(&word));
        return CT_ERROR;
    }

    switch (word.id) {
        case KEY_WORD_COALESCE:
            def->type = MODIFY_IDXSUBPART_COALESCE;
            status = lex_expected_end(lex);
            break;
        case KEY_WORD_UNUSABLE:
            def->type = MODIFY_IDXSUBPART_UNUSABLE;
            status = lex_expected_end(lex);
            break;
        default:
            CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "unexpected word %s found.", W2S(&word));
            return CT_ERROR;
    }

    return status;
}

status_t sql_parse_modify_index(sql_stmt_t *stmt, lex_t *lex, knl_alindex_def_t *def)
{
    word_t word;
    status_t status = CT_SUCCESS;

    if (lex_expected_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type != WORD_TYPE_KEYWORD) {
        CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "unexpected word %s found.", W2S(&word));
        return CT_ERROR;
    }

    switch (word.id) {
        case KEY_WORD_PARTITION:
            def->type = ALINDEX_TYPE_MODIFY_PART;
            status = sql_parse_modify_idxpart(stmt, lex, &def->mod_idxpart);
            break;

        case KEY_WORD_SUBPARTITION:
            def->type = ALINDEX_TYPE_MODIFY_SUBPART;
            status = sql_parse_modify_idxsubpart(stmt, lex, &def->mod_idxpart);
            break;

        default:
            CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "unexpected word %s found.", W2S(&word));
            return CT_ERROR;
    }

    return status;
}

static status_t sql_parse_alter_index_action(sql_stmt_t *stmt, word_t word, lex_t *lex, knl_alindex_def_t *alter_idx_def)
{
    status_t status = CT_SUCCESS;
    switch ((key_wid_t)word.id) {
        case KEY_WORD_REBUILD:
            status = sql_parse_rebuild_index(stmt, lex, alter_idx_def);
            break;

        case KEY_WORD_COALESCE:
            alter_idx_def->type = ALINDEX_TYPE_COALESCE;
            status = lex_expected_end(lex);
            break;

        case KEY_WORD_MODIFY:
            status = sql_parse_modify_index(stmt, lex, alter_idx_def);
            break;
        case KEY_WORD_RENAME:
            status = sql_parse_rename_index(stmt, lex, alter_idx_def);
            break;
        case KEY_WORD_UNUSABLE:
            alter_idx_def->type = ALINDEX_TYPE_UNUSABLE;
            break;
        case KEY_WORD_INITRANS:
            alter_idx_def->type = ALINDEX_TYPE_INITRANS;
            status = sql_parse_trans(lex, &word, &alter_idx_def->idx_def.initrans);
            CT_BREAK_IF_ERROR(status);
            status = lex_expected_end(lex);
            break;

        default:
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected word %s found.", W2S(&word));
            return CT_ERROR;
    }
    return status;
}

status_t sql_parse_alter_index(sql_stmt_t *stmt)
{
    status_t status = CT_SUCCESS;
    word_t word;
    lex_t *lex = stmt->session->lex;
    knl_alindex_def_t *def = NULL;
    bool32 is_on = CT_FALSE;

    lex->flags |= LEX_WITH_OWNER;
    stmt->context->type = CTSQL_TYPE_ALTER_INDEX;

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_alindex_def_t), (void **)&def));

    CT_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));

    CT_RETURN_IFERR(sql_convert_object_name(stmt, &word, &def->user, NULL, &def->name));

    CT_RETURN_IFERR(lex_try_fetch(lex, "on", &is_on));

    if (!is_on) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
                              "invalid SQL syntax due to not 'on' expression before table name");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));

    if (sql_convert_object_name(stmt, &word, &def->user, NULL, &def->table) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_regist_ddl_table(stmt, &def->user, &def->table));

    CT_RETURN_IFERR(lex_fetch(stmt->session->lex, &word));

    CT_RETURN_IFERR(sql_parse_alter_index_action(stmt, word, lex, def));

    stmt->context->entry = def;
    return status;
}

status_t sql_parse_drop_index(sql_stmt_t *stmt)
{
    knl_drop_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;
    bool32 is_cascade = CT_FALSE;
    bool32 is_on = CT_FALSE;
    word_t word;

    lex->flags = LEX_WITH_OWNER;

    stmt->context->type = CTSQL_TYPE_DROP_INDEX;

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (void **)&def));
    CT_RETURN_IFERR(sql_parse_drop_object(stmt, def));

    stmt->context->entry = def;

    CT_RETURN_IFERR(lex_try_fetch(lex, "on", &is_on));

    if (!is_on) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
                              "invalid SQL syntax due to not 'on' expression before table name");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));

    if (sql_convert_object_name(stmt, &word, &def->ex_owner, NULL, &def->ex_name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_compare_text_ins(&def->owner, &def->ex_owner) != 0) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
                              "index user(%s) is not consistent with table user(%s)",
                              T2S(&def->owner), T2S_EX(&def->ex_owner));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_try_fetch(lex, "CASCADE", &is_cascade));

    if (is_cascade) {
        /* NEED TO PARSE CASCADE INFO. */
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "cascade option no implement.");
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}


status_t sql_parse_analyze_index(sql_stmt_t *stmt)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    knl_analyze_index_def_t *def = NULL;
    uint32 sample_ratio = 0;
    uint32 match_id = 0;
    bool32 is_on = CT_FALSE;

    lex->flags |= LEX_WITH_OWNER;
    stmt->context->type = CTSQL_TYPE_ANALYZE_INDEX;

    if (sql_alloc_mem(stmt->context, sizeof(knl_analyze_index_def_t), (void **)&def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_convert_object_name(stmt, &word, &def->owner, NULL, &def->name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_try_fetch(lex, "on", &is_on));

    if (!is_on) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
                              "invalid SQL syntax due to not 'on' expression before table name");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));

    if (sql_convert_object_name(stmt, &word, &def->table_owner, NULL, &def->table_name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_1of2(lex, "COMPUTE", "ESTIMATE", &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "STATISTICS") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (match_id == 0) {
        stmt->context->entry = def;
        return lex_expected_end(lex);
    } else {
        if (lex_expected_fetch_uint32(lex, &sample_ratio) != CT_SUCCESS) {
            return CT_ERROR;
        }

        def->sample_ratio = (double)sample_ratio / 100;
        stmt->context->entry = def;

        return lex_expected_end(lex);
    }
}

status_t sql_parse_purge_index(sql_stmt_t *stmt, knl_purge_def_t *def)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    bool32 result = CT_FALSE;
    status_t status;

    lex->flags = LEX_WITH_OWNER;
    stmt->context->entry = def;

    status = lex_try_fetch_variant(lex, &word, &result);
    CT_RETURN_IFERR(status);

    if (!result) {
        status = lex_expected_fetch_string(lex, &word);
        CT_RETURN_IFERR(status);

        def->type = PURGE_INDEX_OBJECT;
    } else {
        def->type = PURGE_INDEX;
    }

    status = sql_convert_object_name(stmt, &word, &def->owner, NULL, &def->name);
    CT_RETURN_IFERR(status);

    status = lex_expected_end(lex);
    CT_RETURN_IFERR(status);

    return CT_SUCCESS;
}

static status_t sql_parse_create_cons_index(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_index_def_t *def)
{
    uint32 matched_id;
    status_t status;

    if (lex_push(lex, &word->text) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "CREATE") != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    if (lex_expected_fetch_1of2(lex, "UNIQUE", "INDEX", &matched_id) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    if (matched_id == 0) {
        if (lex_expected_fetch_word(lex, "INDEX") != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        def->unique = CT_TRUE;
    } else {
        def->unique = CT_FALSE;
    }

    status = sql_parse_index_def(stmt, lex, def);
    lex_pop(lex);
    return status;
}

status_t sql_parse_using_index(sql_stmt_t *stmt, lex_t *lex, knl_constraint_def_t *cons_def)
{
    word_t word;
    knl_index_def_t *idx_def = &cons_def->index;
    status_t status;

    lex->flags |= LEX_WITH_OWNER;
    if (lex_expected_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (word.type == WORD_TYPE_BRACKET) {
        return sql_parse_create_cons_index(stmt, lex, &word, idx_def);
    }
    if (word.type == WORD_TYPE_VARIANT || word.type == WORD_TYPE_DQ_STRING) {
        idx_def->use_existed = CT_TRUE;
        return sql_convert_object_name(stmt, &word, &idx_def->user, NULL, &idx_def->name);
    }
    if (cons_def->type == CONS_TYPE_PRIMARY) {
        idx_def->primary = CT_TRUE;
    } else {
        idx_def->unique = CT_TRUE;
    }

    idx_def->online = CT_FALSE;
    idx_def->cr_mode = CT_INVALID_ID8;
    idx_def->pctfree = CT_INVALID_ID32;

    for (;;) {
        if (word.type == WORD_TYPE_EOF || IS_SPEC_CHAR(&word, ',')) {
            lex_back(lex, &word);
            break;
        }

        switch (word.id) {
            case KEY_WORD_TABLESPACE:
                status = sql_parse_space(stmt, lex, &word, &idx_def->space);
                break;
            case KEY_WORD_INITRANS:
                status = sql_parse_trans(lex, &word, &idx_def->initrans);
                break;
            case KEY_WORD_LOCAL:
                status = sql_parse_part_index(stmt, lex, &word, idx_def);
                break;
            case KEY_WORD_PCTFREE:
                status = sql_parse_pctfree(lex, &word, &idx_def->pctfree);
                break;
            case KEY_WORD_CRMODE:
                status = sql_parse_crmode(lex, &word, &idx_def->cr_mode);
                break;
            case KEY_WORD_PARALLEL:
                status = sql_parse_parallelism(lex, &word, &idx_def->parallelism, CT_MAX_INDEX_PARALLELISM);
                break;

            case KEY_WORD_REVERSE:
                status = sql_parse_reverse(&word, &idx_def->is_reverse);
                break;
            default:
                CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected text %s", W2S(&word));
                return CT_ERROR;
        }

        if (status != CT_SUCCESS) {
            return CT_ERROR;
        }

        status = lex_fetch(lex, &word);
        CT_RETURN_IFERR(status);
    }

    if (idx_def->initrans == 0) {
        idx_def->initrans = cm_text_str_equal_ins(&idx_def->user, "SYS") ? CT_INI_TRANS :
                                                                       stmt->session->knl_session.kernel->attr.initrans;
    }

    if (idx_def->pctfree == CT_INVALID_ID32) {
        idx_def->pctfree = CT_PCT_FREE;
    }

    return CT_SUCCESS;
}

status_t sql_parse_create_indexes(sql_stmt_t *stmt)
{
    word_t word;
    bool32 try_result = CT_FALSE;
    knl_indexes_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_indexes_def_t), (void **)&def));

    def->index_count = 0;
    stmt->context->type = CTSQL_TYPE_CREATE_INDEXES;
    stmt->context->entry = def;
    CT_RETURN_IFERR(lex_expected_fetch_bracket(lex, &word));
    CT_RETURN_IFERR(lex_push(lex, &word.text));
    for (;;) {
        CT_RETURN_IFERR(lex_try_fetch(lex, "unique", &try_result));
        CT_RETURN_IFERR(lex_expected_fetch_word(lex, "index"));
        if (try_result) {
            def->indexes_def[def->index_count].unique = CT_TRUE;
        }

        CT_RETURN_IFERR(sql_parse_index_def(stmt, lex, &def->indexes_def[def->index_count]));
        def->index_count++;

        CT_RETURN_IFERR(lex_fetch(lex, &word));
        if (word.type == WORD_TYPE_EOF) {
            break;
        }

        if (!IS_SPEC_CHAR(&word, ',')) {
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(&word));
            return CT_ERROR;
        }

        if (def->index_count >= CT_MAX_INDEX_COUNT_PERSQL) {
            CT_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "create more than eight indexes in one SQL statement");
            return CT_ERROR;
        }
    }

    lex_pop(lex);
    CT_RETURN_IFERR(lex_expected_end(lex));
    return CT_SUCCESS;
}
