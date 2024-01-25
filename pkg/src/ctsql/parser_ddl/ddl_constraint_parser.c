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
 * ddl_constraint_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_constraint_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ddl_constraint_parser.h"
#include "srv_instance.h"
#include "ctsql_serial.h"
#include "ddl_index_parser.h"
#include "ddl_column_parser.h"
#include "ddl_parser_common.h"
#include "cond_parser.h"

/*
 * a recursive process which will stop when encountering the first non-constraint-state word.
 * the so-called constraint-state word(s) are:
 * "USING INDEX", "ENABLE", "DISABLE", "DEFERRABLE", "NOT DEFERRABLE", "INITIALLY IMMEDIATE", "INITIALLY DEFERRED",
 * "RELY", "NORELY", "VALIDATE", "NOVALIDATE"
 * use a recursive calling because multiple constraint-state word(s) can be specified in one constraint_state clause.
 */
static status_t sql_parse_constraint_state(sql_stmt_t *stmt, lex_t *lex, knl_constraint_def_t *cons_def, word_t *next_word)
{
    knl_constraint_state_t *cons_state = NULL;
    word_t word;
    uint32 hit_index = CT_INVALID_ID32;
    CM_POINTER3(stmt, lex, cons_def);

    cons_state = &cons_def->cons_state;

    CT_RETURN_IFERR(lex_fetch(lex, &word));
    switch (word.id) {
        case KEY_WORD_USING:
            CT_RETURN_IFERR(lex_expected_fetch_word(lex, "index"));
            CT_RETURN_IFERR(sql_parse_using_index(stmt, lex, cons_def));
            if ((cons_def->type != CONS_TYPE_PRIMARY) && (cons_def->type != CONS_TYPE_UNIQUE)) {
                CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR,
                    "\"USING INDEX\" cannot be specified in a constraint clause other than primary "
                    "key constraint and unique constraint.");
                return CT_ERROR;
            }
            cons_state->is_use_index = CT_TRUE;
            break;
        case KEY_WORD_ENABLE:
            cons_state->is_enable = CT_TRUE;
            break;
        case KEY_WORD_DISABLE:
            cons_state->is_enable = CT_FALSE;
            break;
        case KEY_WORD_NOT:
            CT_RETURN_IFERR(lex_expected_fetch_word(lex, "deferrable"));
            cons_state->deferrable_ops = STATE_NOT_DEFERRABLE;
            break;
        case KEY_WORD_DEFERRABLE:
            cons_state->deferrable_ops = STATE_DEFERRABLE;
            break;
        case KEY_WORD_INITIALLY:
            CT_RETURN_IFERR(lex_expected_fetch_1of2(lex, "immediate", "deferred", &hit_index));
            if (hit_index == 0) {
                cons_state->initially_ops = STATE_INITIALLY_IMMEDIATE;
            } else {
                cons_state->initially_ops = STATE_INITIALLY_DEFERRED;
            }
            break;
        case KEY_WORD_RELY:
            cons_state->rely_ops = STATE_RELY;
            break;
        case KEY_WORD_NO_RELY:
            cons_state->rely_ops = STATE_NO_RELY;
            break;
        case KEY_WORD_VALIDATE:
            cons_state->is_validate = CT_TRUE;
            break;
        case KEY_WORD_NO_VALIDATE:
            cons_state->is_validate = CT_FALSE;
            break;
        case KEY_WORD_PARALLEL:
            if ((cons_def->type != CONS_TYPE_PRIMARY) && (cons_def->type != CONS_TYPE_UNIQUE)) {
                CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR,
                    "\"PARALLEL\" cannot be specified in a constraint clause other than primary "
                    "key constraint and unique constraint.");
                return CT_ERROR;
            }
            CT_RETURN_IFERR(sql_parse_parallelism(lex, &word, &cons_def->index.parallelism, CT_MAX_INDEX_PARALLELISM));
            break;
        case KEY_WORD_REVERSE:
            if ((cons_def->type != CONS_TYPE_PRIMARY) && (cons_def->type != CONS_TYPE_UNIQUE)) {
                CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR,
                    "\"REVERSE\" cannot be specified in a constraint clause other than primary "
                    "key constraint and unique constraint.");
                return CT_ERROR;
            }

            CT_RETURN_IFERR(sql_parse_reverse(&word, &cons_def->index.is_reverse));
            break;

        default:
            /* unrecognized word, stop the recurse and take the word out */
            *next_word = word;
            return CT_SUCCESS;
    }

    /* call sql_parse_constraint_state() itself recursivly in order to handle multiple constraint state properties */
    CT_RETURN_IFERR(sql_parse_constraint_state(stmt, lex, cons_def, &word));
    *next_word = word;
    return CT_SUCCESS;
}

status_t sql_parse_foreign_key(sql_stmt_t *stmt, lex_t *lex, knl_constraint_def_t *cons_def)
{
    knl_reference_def_t *ref = NULL;

    cons_def->type = CONS_TYPE_REFERENCE;

    if (lex_expected_fetch_word(lex, "KEY") != CT_SUCCESS) {
        return CT_ERROR;
    }

    ref = &cons_def->ref;
    if (sql_parse_column_list(stmt, lex, &cons_def->columns, CT_FALSE, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "REFERENCES") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_parse_references_clause(stmt, lex, &ref->ref_user, &ref->ref_table, &ref->refactor, &ref->ref_columns) !=
        CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cons_def->columns.count != ref->ref_columns.count) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "number of referencing columns must match referenced columns.");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_parse_primary_unique_cons(sql_stmt_t *stmt, lex_t *lex, constraint_type_t type,
                                       knl_constraint_def_t *cons_def)
{
    word_t word;

    cons_def->type = type;
    cons_def->index.cr_mode = CT_INVALID_ID8;
    cons_def->index.pctfree = CT_INVALID_ID32;

    if (type == CONS_TYPE_PRIMARY) {
        if (lex_expected_fetch_word(lex, "KEY") != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (sql_parse_column_list(stmt, lex, &cons_def->columns, CT_FALSE, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_parse_constraint_state(stmt, lex, cons_def, &word));
    if (word.type == WORD_TYPE_EOF || IS_SPEC_CHAR(&word, ',')) {
        if (!IS_USEINDEX_FLAG_SPECIFIED(cons_def)) {
            if (type == CONS_TYPE_PRIMARY) {
                cons_def->index.primary = CT_TRUE;
            } else {
                cons_def->index.unique = CT_TRUE;
            }
        }

        lex_back(lex, &word);
        return CT_SUCCESS;
    }

    CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected text %s", W2S(&word));
    return CT_ERROR;
}

static status_t sql_fetch_column_in_expr(sql_stmt_t *stmt, expr_node_t *node, void *context)
{
    sql_walker_t *walker = (sql_walker_t *)context;
    text_t *new_col = NULL;
    text_t *col = NULL;

    if (node->type != EXPR_NODE_COLUMN && node->type != EXPR_NODE_DIRECT_COLUMN) {
        return CT_SUCCESS;
    }

    for (uint32 i = 0; i < walker->columns->count; i++) {
        col = (text_t *)cm_galist_get(walker->columns, i);
        if (!cm_compare_text(col, &node->word.column.name.value)) {
            return CT_SUCCESS;
        }
    }

    CT_RETURN_IFERR(cm_galist_new(walker->columns, sizeof(text_t), (void **)&new_col));
    *new_col = node->word.column.name.value;

    return CT_SUCCESS;
}

static status_t sql_verify_outline_check(sql_stmt_t *stmt, knl_table_def_t *verf_data, knl_constraint_def_t *cons_def,
    cond_tree_t *cond)
{
    text_t save_check_text;
    knl_check_def_t *check = &cons_def->check;
    sql_verifier_t verf = { 0 };
    sql_walker_t walker = { 0 };
    verf.context = stmt->context;
    verf.stmt = stmt;
    verf.is_check_cons = CT_TRUE;
    verf.table_def = verf_data;

    verf.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_PRIOR | SQL_EXCL_SUBSELECT | SQL_EXCL_JOIN |
        SQL_EXCL_BIND_PARAM | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_LOB_COL | SQL_EXCL_SEQUENCE | SQL_EXCL_CASE |
        SQL_EXCL_ROWSCN | SQL_EXCL_WIN_SORT | SQL_EXCL_ROWNODEID;

    if (sql_verify_cond(&verf, cond) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (check->text.len > CT_MAX_CHECK_VALUE_LEN) {
        CT_SRC_THROW_ERROR_EX(cond->loc, ERR_SQL_SYNTAX_ERROR, "length of CHECK's value exceed maximum: %d",
            CT_MAX_CHECK_VALUE_LEN);
        return CT_ERROR;
    }

    cm_galist_init(&cons_def->columns, stmt->context, sql_alloc_mem);
    walker.context = stmt->context;
    walker.stmt = stmt;
    walker.columns = &cons_def->columns;
    CT_RETURN_IFERR(sql_cond_tree_walker(stmt, cond, sql_fetch_column_in_expr, (void *)&walker));
    save_check_text = check->text;
    return sql_copy_text(stmt->context, &save_check_text, &check->text);
}

status_t sql_verify_inline_check(sql_stmt_t *stmt, knl_column_def_t *def, cond_tree_t *cond)
{
    text_t save_check_text;
    sql_verifier_t verf = { 0 };
    verf.context = stmt->context;
    verf.stmt = stmt;
    verf.table_def = (knl_table_def_t *)def->table;
    verf.column = def;
    verf.is_check_cons = CT_TRUE;

    verf.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_PRIOR | SQL_EXCL_SUBSELECT | SQL_EXCL_JOIN |
        SQL_EXCL_BIND_PARAM | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_LOB_COL | SQL_EXCL_SEQUENCE | SQL_EXCL_CASE |
        SQL_EXCL_ROWSCN | SQL_EXCL_WIN_SORT | SQL_EXCL_ROWNODEID;

    if (sql_verify_cond(&verf, cond) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (def->check_text.len > CT_MAX_CHECK_VALUE_LEN) {
        CT_SRC_THROW_ERROR_EX(cond->loc, ERR_SQL_SYNTAX_ERROR, "length of CHECK's value exceed maximum: %d",
            CT_MAX_CHECK_VALUE_LEN);
        return CT_ERROR;
    }
    save_check_text = def->check_text;

    return sql_copy_text(stmt->context, &save_check_text, &def->check_text);
}

status_t sql_parse_add_check(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def, knl_constraint_def_t *cons_def)
{
    word_t word;
    status_t status;
    cond_tree_t *cond = NULL;

    cons_def->type = CONS_TYPE_CHECK;
    status = lex_expected_fetch_bracket(lex, &word);
    CT_RETURN_IFERR(status);
    CT_RETURN_IFERR(lex_push(lex, &word.text));

    cons_def->check.text = word.text.value;
    cm_trim_text(&cons_def->check.text);
    lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
    stmt->is_check = CT_TRUE;
    status = sql_create_cond_until(stmt, &cond, &word);
    stmt->is_check = CT_FALSE;
    lex_pop(lex);
    CT_RETURN_IFERR(status);

    if (word.type != WORD_TYPE_EOF) {
        CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "expected end but \"%s\" found", W2S(&word));
        return CT_ERROR;
    }

    cons_def->check.cond = cond;

    return sql_verify_outline_check(stmt, NULL, cons_def, cond);
}


status_t sql_parse_constraint(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def)
{
    word_t word;
    status_t status;
    uint32 save_flags;
    knl_constraint_def_t *cons_def = &def->cons_def.new_cons;
    if (def->action == ALTABLE_ADD_CONSTRAINT) {
        CT_RETURN_IFERR(sql_try_parse_if_not_exists(lex, &def->options));
    }
    save_flags = lex->flags;
    lex->flags = LEX_SINGLE_WORD;
    status = lex_expected_fetch_variant(lex, &word);
    lex->flags = save_flags;
    CT_RETURN_IFERR(status);

    CT_RETURN_IFERR(sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &cons_def->name));

    cons_def->cons_state.is_anonymous = CT_FALSE;

    CT_RETURN_IFERR(lex_expected_fetch(lex, &word));

    switch ((key_wid_t)word.id) {
        case KEY_WORD_PRIMARY:
            status = sql_parse_primary_unique_cons(stmt, lex, CONS_TYPE_PRIMARY, cons_def);
            break;
        case KEY_WORD_FOREIGN:
            status = sql_parse_foreign_key(stmt, lex, cons_def);
            break;
        case KEY_WORD_CHECK:
            status = sql_parse_add_check(stmt, lex, def, cons_def);
            break;
        case KEY_WORD_UNIQUE:
            status = sql_parse_primary_unique_cons(stmt, lex, CONS_TYPE_UNIQUE, cons_def);
            break;
        default:
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(&word));
            status = CT_ERROR;
            break;
    }

    return status;
}

static status_t sql_append_inline_checks_column(sql_stmt_t *stmt, knl_constraint_def_t *cons_def,
    const knl_column_def_t *column)
{
    text_t *col = NULL;

    if (!CM_IS_EMPTY(&column->inl_chk_cons_name)) {
        cons_def->cons_state.is_anonymous = CT_FALSE;
        cons_def->name = column->inl_chk_cons_name;
    }

    cm_galist_init(&cons_def->columns, stmt->context, sql_alloc_mem);
    if (cm_galist_new(&cons_def->columns, sizeof(text_t), (pointer_t *)&col) != CT_SUCCESS) {
        return CT_ERROR;
    }
    *col = column->name;
    cons_def->check.text = column->check_text;
    cons_def->check.cond = column->check_cond;
    return CT_SUCCESS;
}

static status_t sql_alloc_inline_cons(sql_stmt_t *stmt, constraint_type_t type, galist_t *constraints,
    knl_constraint_def_t **cons_def)
{
    if (cm_galist_new(constraints, sizeof(knl_constraint_def_t), (pointer_t *)cons_def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    (*cons_def)->type = type;

    if (sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (pointer_t *)&(*cons_def)->name.str) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_get_system_name(&stmt->session->knl_session, type, (*cons_def)->name.str, CT_NAME_BUFFER_SIZE);
    (*cons_def)->name.len = (uint32)strlen((*cons_def)->name.str);
    (*cons_def)->cons_state.is_anonymous = CT_TRUE;
    (*cons_def)->cons_state.is_enable = CT_TRUE;
    (*cons_def)->cons_state.is_validate = CT_TRUE;
    (*cons_def)->cons_state.is_cascade = CT_TRUE;
    return CT_SUCCESS;
}

static status_t sql_create_inline_checks(sql_stmt_t *stmt, knl_table_def_t *def)
{
    uint32 i;
    knl_column_def_t *column = NULL;
    knl_constraint_def_t *cons_def = NULL;

    for (i = 0; i < def->columns.count; i++) {
        column = cm_galist_get(&def->columns, i);
        if (!column->is_check) {
            continue;
        }

        if (sql_alloc_inline_cons(stmt, CONS_TYPE_CHECK, &def->constraints, &cons_def) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (sql_append_inline_checks_column(stmt, cons_def, column) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_append_inline_ref_column(sql_stmt_t *stmt, knl_table_def_t *def, const knl_column_def_t *column)
{
    knl_constraint_def_t *cons_def = NULL;
    text_t *name = NULL;

    if (sql_alloc_inline_cons(stmt, CONS_TYPE_REFERENCE, &def->constraints, &cons_def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!CM_IS_EMPTY(&column->inl_ref_cons_name)) {
        cons_def->name = column->inl_ref_cons_name;
        cons_def->cons_state.is_anonymous = CT_FALSE;
    }
    cm_galist_init(&cons_def->columns, stmt->context, sql_alloc_mem);

    cons_def->ref.ref_user = column->ref_user;
    cons_def->ref.ref_table = column->ref_table;

    if (cm_galist_new(&cons_def->columns, sizeof(text_t), (pointer_t *)&name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *name = column->name;
    cons_def->ref.ref_columns = column->ref_columns;
    cons_def->ref.refactor = column->refactor;
    return CT_SUCCESS;
}

static status_t sql_create_inline_refs(sql_stmt_t *stmt, knl_table_def_t *def)
{
    uint32 i;
    knl_column_def_t *column = NULL;

    for (i = 0; i < def->columns.count; i++) {
        column = cm_galist_get(&def->columns, i);
        if (!column->is_ref) {
            continue;
        }

        if (column->typmod.is_array == CT_TRUE) {
            CT_THROW_ERROR(ERR_REF_ON_ARRAY_COLUMN);
            return CT_ERROR;
        }

        if (sql_append_inline_ref_column(stmt, def, column) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}
static status_t sql_create_inline_cons_index(sql_stmt_t *stmt, knl_table_def_t *def)
{
    uint32 i;
    knl_column_def_t *column = NULL;
    knl_constraint_def_t *cons_def = NULL;
    knl_index_col_def_t *index_column = NULL;
    constraint_type_t type;

    for (i = 0; i < def->columns.count; i++) {
        column = cm_galist_get(&def->columns, i);
        if ((!column->primary) && (!column->unique)) {
            continue;
        }

        if (column->typmod.is_array == CT_TRUE) {
            CT_THROW_ERROR(ERR_INDEX_ON_ARRAY_FIELD, T2S(&column->name));
            return CT_ERROR;
        }

        type = column->primary ? CONS_TYPE_PRIMARY : CONS_TYPE_UNIQUE;
        if (sql_alloc_inline_cons(stmt, type, &def->constraints, &cons_def) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (type == CONS_TYPE_PRIMARY) {
            if (!CM_IS_EMPTY(&column->inl_pri_cons_name)) {
                cons_def->name = column->inl_pri_cons_name;
                cons_def->cons_state.is_anonymous = CT_FALSE;
            }
        } else {
            if (!CM_IS_EMPTY(&column->inl_uq_cons_name)) {
                cons_def->name = column->inl_uq_cons_name;
                cons_def->cons_state.is_anonymous = CT_FALSE;
            }
        }
        cm_galist_init(&cons_def->columns, stmt->context, sql_alloc_mem);

        if (cm_galist_new(&cons_def->columns, sizeof(knl_index_col_def_t), (pointer_t *)&index_column) != CT_SUCCESS) {
            return CT_ERROR;
        }

        index_column->name = column->name;
        index_column->mode = SORT_MODE_ASC;
        cons_def->index.primary = (type == CONS_TYPE_PRIMARY);
        cons_def->index.unique = (type == CONS_TYPE_UNIQUE);
        cons_def->index.cr_mode = CT_INVALID_ID8;
        cons_def->index.pctfree = CT_INVALID_ID32;
    }

    return CT_SUCCESS;
}

status_t sql_create_inline_cons(sql_stmt_t *stmt, knl_table_def_t *def)
{
    if (def->pk_inline || def->uq_inline) {
        if (sql_create_inline_cons_index(stmt, def) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (def->rf_inline) {
        if (sql_create_inline_refs(stmt, def) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (def->chk_inline) {
        if (sql_create_inline_checks(stmt, def) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}


static status_t sql_parse_check_outline_cons(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def,
    knl_constraint_def_t *cons_def)
{
    status_t status;
    word_t word;
    cond_tree_t *cond = NULL;

    if (cons_def == NULL) {
        status = sql_alloc_inline_cons(stmt, CONS_TYPE_CHECK, &def->constraints, &cons_def);
        CT_RETURN_IFERR(status);
    }
    cons_def->type = CONS_TYPE_CHECK;
    status = lex_expected_fetch_bracket(lex, &word);
    CT_RETURN_IFERR(status);

    CT_RETURN_IFERR(lex_push(lex, &word.text));

    cons_def->check.text = lex->curr_text->value;
    cm_trim_text(&cons_def->check.text);
    lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
    stmt->is_check = CT_TRUE;
    status = sql_create_cond_until(stmt, &cond, &word);
    stmt->is_check = CT_FALSE;
    lex_pop(lex);
    CT_RETURN_IFERR(status);

    lex->flags = LEX_SINGLE_WORD;
    if (word.type != WORD_TYPE_EOF) {
        return CT_ERROR;
    }

    cons_def->check.cond = cond;
    return CT_SUCCESS;
}

static status_t sql_try_parse_constraint(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def, bool32 *result)
{
    word_t word;
    status_t status;
    knl_constraint_def_t *cons_def = NULL;

    status = lex_try_fetch_variant_excl(lex, &word, WORD_TYPE_DATATYPE, result);
    CT_RETURN_IFERR(status);

    if (*result == CT_FALSE) {
        return CT_SUCCESS;
    }

    status = cm_galist_new(&def->constraints, sizeof(knl_constraint_def_t), (pointer_t *)&cons_def);
    CT_RETURN_IFERR(status);
    cons_def->cons_state.is_enable = CT_TRUE;
    cons_def->cons_state.is_validate = CT_TRUE;
    cons_def->cons_state.is_cascade = CT_TRUE;
    status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &cons_def->name);
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch(lex, &word);
    CT_RETURN_IFERR(status);

    switch ((key_wid_t)word.id) {
        case KEY_WORD_PRIMARY:
            status = sql_parse_primary_unique_cons(stmt, lex, CONS_TYPE_PRIMARY, cons_def);
            break;
        case KEY_WORD_FOREIGN:
            status = sql_parse_foreign_key(stmt, lex, cons_def);
            break;
        case KEY_WORD_CHECK:
            status = sql_parse_check_outline_cons(stmt, lex, def, cons_def);
            break;
        case KEY_WORD_UNIQUE:
            status = sql_parse_primary_unique_cons(stmt, lex, CONS_TYPE_UNIQUE, cons_def);
            break;
        default:
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(&word));
            status = CT_ERROR;
            break;
    }
    return status;
}

status_t sql_parse_auto_primary_key_constr_name(sql_stmt_t *stmt, text_t *constr_name, text_t *sch_name,
    text_t *tab_name)
{
    text_t md5_text;
    uint32 len, max_len;
    char name[DDL_MAX_CONSTR_NAME_LEN + 1] = { 0 };
    char md5_name[CT_MD5_SIZE + 1] = { 0 };
    uchar digest[CT_MD5_HASH_SIZE] = { 0 };
    binary_t bin = {
        .bytes = digest,
        .size = CT_MD5_HASH_SIZE
    };

    len = 0;
    max_len = DDL_MAX_CONSTR_NAME_LEN + 1;
    MEMS_RETURN_IFERR(strncpy_s(name, max_len, sch_name->str, sch_name->len));
    len += sch_name->len;
    MEMS_RETURN_IFERR(strncpy_s(name + len, max_len - len, tab_name->str, tab_name->len));
    len += tab_name->len;
    cm_calc_md5((const uchar *)&name, len, (uchar *)digest, &bin.size);

    md5_text.str = md5_name;
    md5_text.len = (uint32)sizeof(md5_name);

    if (cm_bin2text(&bin, CT_FALSE, &md5_text) != CT_SUCCESS) {
        return CT_ERROR;
    }

    PRTS_RETURN_IFERR(snprintf_s(constr_name->str, CT_MAX_NAME_LEN, CT_MAX_NAME_LEN - 1, "_PK_SYS_"));
    MEMS_RETURN_IFERR(
        strncat_s(constr_name->str, CT_MAX_NAME_LEN - strlen(constr_name->str), md5_text.str, md5_text.len));
    constr_name->len = (uint32)strlen(constr_name->str);

    return CT_SUCCESS;
}


static status_t sql_try_parse_primary_unique_cons(sql_stmt_t *stmt, lex_t *lex, constraint_type_t type,
    knl_table_def_t *def, bool32 *result)
{
    status_t status;
    word_t word;
    knl_constraint_def_t *cons_def = NULL;

    if (type == CONS_TYPE_PRIMARY) {
        status = lex_try_fetch(lex, "KEY", result);
        CT_RETURN_IFERR(status);
        if (*result == CT_FALSE) {
            return CT_SUCCESS;
        }
        status = sql_alloc_inline_cons(stmt, type, &def->constraints, &cons_def);
        CT_RETURN_IFERR(status);
        cons_def->index.primary = CT_TRUE;
        cons_def->index.cr_mode = CT_INVALID_ID8;
        cons_def->index.pctfree = CT_INVALID_ID32;

        status = sql_parse_column_list(stmt, lex, &cons_def->columns, CT_FALSE, NULL);
        CT_RETURN_IFERR(status);
    } else {
        LEX_SAVE(lex);
        status = lex_try_fetch_bracket(lex, &word, result);
        CT_RETURN_IFERR(status);
        if (*result == CT_FALSE) {
            return CT_SUCCESS;
        }
        LEX_RESTORE(lex);
        status = sql_alloc_inline_cons(stmt, type, &def->constraints, &cons_def);
        CT_RETURN_IFERR(status);
        cons_def->index.unique = CT_TRUE;
        cons_def->index.cr_mode = CT_INVALID_ID8;
        cons_def->index.pctfree = CT_INVALID_ID32;

        status = sql_parse_column_list(stmt, lex, &cons_def->columns, CT_FALSE, NULL);
        CT_RETURN_IFERR(status);
    }

    CT_RETURN_IFERR(lex_fetch(lex, &word));
    if (word.type == WORD_TYPE_EOF || IS_SPEC_CHAR(&word, ',')) {
        lex_back(lex, &word);
        return CT_SUCCESS;
    }

    switch (word.id) {
        case KEY_WORD_USING:
            status = lex_expected_fetch_word(lex, "index");
            CT_RETURN_IFERR(status);
            return sql_parse_index_attrs(stmt, lex, &cons_def->index);
        case KEY_WORD_ENABLE:
        case KEY_WORD_DISABLE:
        case KEY_WORD_NOT:
            CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "key word \"not\" for constraints");
            return CT_ERROR;
        default:
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected text %s", W2S(&word));
            return CT_ERROR;
    }
}

static status_t sql_append_primary_key_cols(sql_stmt_t *stmt, text_t *ref_user, text_t *ref_table,
    galist_t *ref_columns)
{
    knl_dictionary_t dc;
    uint32 i, count;
    status_t status = CT_SUCCESS;
    knl_index_desc_t *index_desc = NULL;
    knl_column_t *column = NULL;
    knl_index_col_def_t *index_column = NULL;

    if (ref_columns->count != 0) {
        return CT_SUCCESS;
    }

    if (CT_SUCCESS != knl_open_dc(stmt->session, ref_user, ref_table, &dc)) {
        return CT_ERROR;
    }

    count = knl_get_index_count(dc.handle);
    for (i = 0; i < count; i++) {
        index_desc = knl_get_index(dc.handle, i);
        if (index_desc->primary) {
            break;
        }
    }

    if (i == count) {
        knl_close_dc(&dc);
        CT_THROW_ERROR(ERR_REFERENCED_NO_PRIMARY_KEY);
        return CT_ERROR;
    }

    for (i = 0; i < index_desc->column_count; i++) {
        column = knl_get_column(dc.handle, index_desc->columns[i]);
        status = cm_galist_new(ref_columns, sizeof(knl_index_col_def_t), (void **)&index_column);
        CT_BREAK_IF_ERROR(status);
        index_column->mode = SORT_MODE_ASC;
        status = sql_copy_str(stmt->context, column->name, &index_column->name);
        CT_BREAK_IF_ERROR(status);
    }

    knl_close_dc(&dc);
    return status;
}

status_t sql_parse_references_clause(sql_stmt_t *stmt, lex_t *lex, text_t *ref_user, text_t *ref_table,
    knl_refactor_t *refactor, galist_t *ref_columns)
{
    bool32 result = CT_FALSE;
    word_t word;
    status_t status;

    lex->flags = LEX_WITH_OWNER;

    status = lex_expected_fetch_variant(lex, &word);
    CT_RETURN_IFERR(status);

    status = sql_convert_object_name(stmt, &word, ref_user, NULL, ref_table);
    CT_RETURN_IFERR(status);

    cm_galist_init(ref_columns, stmt->context, sql_alloc_mem);
    if (lex_try_fetch_bracket(lex, &word, &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (result) {
        lex_back(lex, &word);
        status = sql_parse_column_list(stmt, lex, ref_columns, CT_FALSE, NULL);
        CT_RETURN_IFERR(status);
    }

    *refactor = REF_DEL_NOT_ALLOWED;

    if (lex_try_fetch(lex, "ON", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (result) {
        /* on delete/update set null/cascade not supported yet */
        if (CT_SUCCESS != lex_expected_fetch_word(lex, "DELETE")) {
            return CT_ERROR;
        }

        status = lex_expected_fetch(lex, &word);
        CT_RETURN_IFERR(status);

        if (word.id == KEY_WORD_CASCADE) {
            *refactor |= REF_DEL_CASCADE;
        } else if (word.id == KEY_WORD_SET) {
            status = lex_expected_fetch_word(lex, "NULL");
            CT_RETURN_IFERR(status);
            *refactor |= REF_DEL_SET_NULL;
        } else {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "CASCADE/SET NULL expected but %s found.", W2S(&word));
            return CT_ERROR;
        }
    }

    return sql_append_primary_key_cols(stmt, ref_user, ref_table, ref_columns);
}

static status_t sql_try_parse_foreign_key(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def, bool32 *result)
{
    status_t status;
    knl_reference_def_t *ref = NULL;
    knl_constraint_def_t *cons_def = NULL;

    if (lex_try_fetch(lex, "KEY", result) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (*result == CT_FALSE) {
        return CT_SUCCESS;
    }

    status = sql_alloc_inline_cons(stmt, CONS_TYPE_REFERENCE, &def->constraints, &cons_def);
    CT_RETURN_IFERR(status);
    ref = &cons_def->ref;
    if (sql_parse_column_list(stmt, lex, &cons_def->columns, CT_FALSE, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "REFERENCES") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_parse_references_clause(stmt, lex, &ref->ref_user, &ref->ref_table, &ref->refactor, &ref->ref_columns) !=
        CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cons_def->columns.count != ref->ref_columns.count) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "number of referencing columns must match referenced columns.");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_parse_column_ref(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
    uint32 *ex_flags)
{
    if (*ex_flags & COLUMN_EX_REF) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
            "duplicate or conflicting references specifications");
        return CT_ERROR;
    }

    *ex_flags |= COLUMN_EX_REF;
    column->is_ref = CT_TRUE;

    if (CT_SUCCESS != sql_parse_references_clause(stmt, lex, &column->ref_user, &column->ref_table, &column->refactor,
        &column->ref_columns)) {
        return CT_ERROR;
    }

    if (column->ref_columns.count != 1) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "number of referencing columns must match referenced columns.");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_parse_column_check(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
    uint32 *ex_flags)
{
    status_t status;
    uint32 save_flags;
    cond_tree_t *cond = NULL;

    if (*ex_flags & COLUMN_EX_CHECK) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate or conflicting check specifications");
        return CT_ERROR;
    }

    status = lex_expected_fetch_bracket(lex, word);
    CT_RETURN_IFERR(status);
    CT_RETURN_IFERR(lex_push(lex, &word->text));

    column->check_text = word->text.value;
    cm_trim_text(&column->check_text);
    save_flags = lex->flags;
    lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
    stmt->is_check = CT_TRUE;
    status = sql_create_cond_until(stmt, &cond, word);
    stmt->is_check = CT_FALSE;

    lex_pop(lex);
    CT_RETURN_IFERR(status);
    if (word->type != WORD_TYPE_EOF) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "EOF expected but %s found",
            T2S(&word->text.value));
        return CT_ERROR;
    }

    column->is_check = CT_TRUE;
    *ex_flags |= COLUMN_EX_CHECK;

    lex->flags = save_flags;
    column->check_cond = cond;
    return CT_SUCCESS;
}

static status_t sql_parse_column_not_null(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
    uint32 *ex_flags)
{
    if (*ex_flags & COLUMN_EX_NULLABLE) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
            "duplicate or conflicting not null/null specifications");
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "NULL") != CT_SUCCESS) {
        return CT_ERROR;
    }

    *ex_flags |= COLUMN_EX_NULLABLE;
    column->nullable = CT_FALSE;
    column->has_null = CT_TRUE;

    return CT_SUCCESS;
}

static status_t sql_parse_column_primary(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
    uint32 *ex_flags)
{
    if (*ex_flags & COLUMN_EX_KEY) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "duplicate or conflicting primary key/unique specifications");
        return CT_ERROR;
    }

    CHECK_CONS_TZ_TYPE_RETURN(column->datatype);

    if (lex_expected_fetch_word(lex, "KEY") != CT_SUCCESS) {
        return CT_ERROR;
    }

    *ex_flags |= COLUMN_EX_KEY;
    column->primary = CT_TRUE;
    column->nullable = CT_FALSE;
    column->has_null = CT_TRUE;

    return CT_SUCCESS;
}

status_t sql_parse_inline_constraint_elemt(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
    uint32 *ex_flags, text_t *cons_name)
{
    status_t status;
    switch (word->id) {
        case KEY_WORD_NOT:
            status = sql_parse_column_not_null(stmt, lex, column, word, ex_flags);
            CT_RETURN_IFERR(status);
            break;

        case KEY_WORD_PRIMARY:
            status = sql_parse_column_primary(stmt, lex, column, word, ex_flags);
            CT_RETURN_IFERR(status);
            if (cons_name != NULL) {
                column->inl_pri_cons_name = *cons_name;
            }
            break;

        case RES_WORD_NULL:
            if (*ex_flags & COLUMN_EX_NULLABLE) {
                CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                    "duplicate or conflicting not null/null specifications");
                return CT_ERROR;
            }
            column->has_null = CT_TRUE;
            *ex_flags |= COLUMN_EX_NULLABLE;
            break;

        case KEY_WORD_REFERENCES:
            status = sql_parse_column_ref(stmt, lex, column, word, ex_flags);
            CT_RETURN_IFERR(status);
            if (cons_name != NULL) {
                column->inl_ref_cons_name = *cons_name;
            }
            break;

        case KEY_WORD_UNIQUE:
            if (*ex_flags & COLUMN_EX_KEY) {
                CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                    "duplicate or conflicting primary key/unique specifications");
                return CT_ERROR;
            }

            CHECK_CONS_TZ_TYPE_RETURN(column->datatype);

            *ex_flags |= COLUMN_EX_KEY;
            column->unique = CT_TRUE;
            if (cons_name != NULL) {
                column->inl_uq_cons_name = *cons_name;
            }
            break;

        case KEY_WORD_CHECK:
            status = sql_parse_column_check(stmt, lex, column, word, ex_flags);
            CT_RETURN_IFERR(status);
            if (cons_name != NULL) {
                column->inl_chk_cons_name = *cons_name;
            }
            break;

        default:
            CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "constraint expected but %s found", W2S(word));
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_parse_inline_constraint(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
    uint32 *ex_flags)
{
    text_t inl_constr = {
        .str = NULL,
        .len = 0
    };

    if (lex_expected_fetch_variant(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &inl_constr) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_parse_inline_constraint_elemt(stmt, lex, column, word, ex_flags, &inl_constr);
}


static status_t sql_parse_out_line_constraint(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def, word_t *word,
    bool32 *res)
{
    status_t status;
    switch (word->id) {
        case KEY_WORD_CONSTRAINT:
            // try_fetch_variant
            status = sql_try_parse_constraint(stmt, lex, def, res);
            break;
        case KEY_WORD_PRIMARY:
            // try fetch_word("key")
            status = sql_try_parse_primary_unique_cons(stmt, lex, CONS_TYPE_PRIMARY, def, res);
            break;
        case KEY_WORD_UNIQUE:
            // try fetch_bracket
            status = sql_try_parse_primary_unique_cons(stmt, lex, CONS_TYPE_UNIQUE, def, res);
            break;
        case KEY_WORD_CHECK:
            *res = CT_TRUE;
            status = sql_parse_check_outline_cons(stmt, lex, def, NULL);
            break;

        case KEY_WORD_FOREIGN:
        default:
            status = sql_try_parse_foreign_key(stmt, lex, def, res); // try fech key
            break;
    }

    return status;
}

status_t sql_try_parse_cons(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def, word_t *word, bool32 *result)
{
    status_t status;
    *result = CT_FALSE;
    if (!IS_CONSTRAINT_KEYWORD(word->id)) {
        return CT_SUCCESS;
    }

    status = sql_parse_out_line_constraint(stmt, lex, def, word, result);
    CT_RETURN_IFERR(status);

    if (*result == CT_FALSE) {
        return CT_SUCCESS;
    }
    status = lex_fetch(lex, word);
    CT_RETURN_IFERR(status);

    if (word->type == WORD_TYPE_EOF || IS_SPEC_CHAR(word, ',')) {
        return CT_SUCCESS;
    }

    CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
    return CT_ERROR;
}


status_t sql_verify_check_constraint(sql_stmt_t *stmt, knl_table_def_t *def)
{
    uint32 loop;
    knl_constraint_def_t *cons_def = NULL;
    knl_column_def_t *col = NULL;

    // verify check in out line constraint
    for (loop = 0; loop < def->constraints.count; loop++) {
        cons_def = (knl_constraint_def_t *)cm_galist_get(&def->constraints, loop);
        if (cons_def->type != CONS_TYPE_CHECK) {
            continue;
        }
        CT_RETURN_IFERR(sql_verify_outline_check(stmt, def, cons_def, (cond_tree_t *)cons_def->check.cond));
    }

    // verify check in column definition
    for (loop = 0; loop < def->columns.count; loop++) {
        col = (knl_column_def_t *)cm_galist_get(&def->columns, loop);
        if (!col->is_check) {
            continue;
        }
        CT_RETURN_IFERR(sql_verify_inline_check(stmt, col, (cond_tree_t *)col->check_cond));
    }
    return CT_SUCCESS;
}

static status_t sql_altable_inline_check_cons(sql_stmt_t *stmt, knl_column_def_t *column,
    knl_alt_column_prop_t *column_def)
{
    knl_constraint_def_t *cons_def = NULL;

    if (sql_verify_inline_check(stmt, column, column->check_cond) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_alloc_inline_cons(stmt, CONS_TYPE_CHECK, &column_def->constraints, &cons_def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_append_inline_checks_column(stmt, cons_def, column) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_altable_inline_cons_index(sql_stmt_t *stmt, knl_column_def_t *column,
    knl_alt_column_prop_t *column_def)
{
    knl_constraint_def_t *cons_def = NULL;
    knl_index_col_def_t *index_col = NULL;
    constraint_type_t type;

    type = column->primary ? CONS_TYPE_PRIMARY : CONS_TYPE_UNIQUE;
    if (sql_alloc_inline_cons(stmt, type, &column_def->constraints, &cons_def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (column->unique) {
        if (column->inl_uq_cons_name.len != 0) {
            cons_def->name = column->inl_uq_cons_name;
            cons_def->cons_state.is_anonymous = CT_FALSE;
        }
    } else {
        if (column->inl_pri_cons_name.len != 0) {
            cons_def->name = column->inl_pri_cons_name;
            cons_def->cons_state.is_anonymous = CT_FALSE;
        }
    }
    cm_galist_init(&cons_def->columns, stmt->context, sql_alloc_mem);
    CT_RETURN_IFERR(cm_galist_new(&cons_def->columns, sizeof(knl_index_col_def_t), (pointer_t *)&index_col));
    index_col->mode = SORT_MODE_ASC;
    index_col->name = column->name;
    cons_def->index.primary = column->primary;
    cons_def->index.unique = column->unique;
    cons_def->index.cr_mode = CT_INVALID_ID8;
    cons_def->index.pctfree = CT_INVALID_ID32;

    return CT_SUCCESS;
}

status_t sql_create_altable_inline_cons(sql_stmt_t *stmt, knl_column_def_t *column, knl_alt_column_prop_t *column_def)
{
    cm_galist_init(&column_def->constraints, stmt->context, sql_alloc_mem);

    if (column->is_check) {
        if (sql_altable_inline_check_cons(stmt, column, column_def) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (column->unique || column->primary) {
        if (sql_altable_inline_cons_index(stmt, column, column_def) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t sql_parse_altable_constraint_rename(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def)
{
    key_wid_t wid;
    word_t word;
    uint32 pre_flags = lex->flags;
    lex->flags = LEX_SINGLE_WORD;
    def->action = ALTABLE_RENAME_CONSTRAINT;
    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->cons_def.name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    wid = (key_wid_t)word.id;
    if (word.type != WORD_TYPE_KEYWORD || wid != KEY_WORD_TO) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "TO expected but %s found", W2S(&word));
        return CT_ERROR;
    }

    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->cons_def.new_cons.name) !=
        CT_SUCCESS) {
        return CT_ERROR;
    }
    lex->flags = pre_flags;
    return lex_expected_end(lex);
}
