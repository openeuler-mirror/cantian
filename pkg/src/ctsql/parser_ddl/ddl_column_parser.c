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
 * ddl_column_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_column_parser.c
 *
 * -------------------------------------------------------------------------
 */
#include "ddl_column_parser.h"
#include "ddl_constraint_parser.h"
#include "ddl_partition_parser.h"
#include "func_parser.h"
#include "ctsql_serial.h"
#include "ctsql_func.h"
#include "ctsql_cond.h"
#include "srv_instance.h"
// invoker should input the first word
static status_t sql_try_parse_column_datatype(lex_t *lex, knl_column_def_t *column, word_t *word, bool32 *found)
{
    CT_RETURN_IFERR(lex_try_match_datatype(lex, word, found));

    if (!(*found)) {
        return CT_SUCCESS;
    }

    MEMS_RETURN_IFERR(memset_s(&column->typmod, sizeof(typmode_t), 0, sizeof(typmode_t)));

    if (word->id == DTYP_SERIAL) {
        column->typmod.datatype = CT_TYPE_BIGINT;
        column->typmod.size = sizeof(int64);
        column->is_serial = CT_TRUE;
        return CT_SUCCESS;
    }

    if (sql_parse_typmode(lex, PM_NORMAL, &column->typmod, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_try_match_array(lex, &column->typmod.is_array, column->typmod.datatype) != CT_SUCCESS) {
        return CT_ERROR;
    }

    column->is_jsonb = (word->id == DTYP_JSONB);
    return CT_SUCCESS;
}

static status_t sql_parse_column_datatype(lex_t *lex, knl_column_def_t *column, word_t *word)
{
    word_t typword;

    if (sql_parse_datatype(lex, PM_NORMAL, &column->typmod, &typword) != CT_SUCCESS) {
        return CT_ERROR;
    }

    column->is_jsonb = (typword.id == DTYP_JSONB);
    column->is_serial = (typword.id == DTYP_SERIAL);
    return CT_SUCCESS;
}

status_t sql_check_duplicate_column(galist_t *columns, const text_t *name)
{
    uint32 i;
    knl_column_def_t *column = NULL;

    for (i = 0; i < columns->count; i++) {
        column = (knl_column_def_t *)cm_galist_get(columns, i);
        if (cm_text_equal(&column->name, name)) {
            CT_THROW_ERROR(ERR_DUPLICATE_NAME, "column", T2S(name));
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t sql_verify_column_default_expr(sql_verifier_t *verf, expr_tree_t *cast_expr, knl_column_def_t *def)
{
    status_t status = CT_SUCCESS;
    variant_t *pvar = NULL;
    uint32 value_len;
    const typmode_t *cmode = NULL;
    var_func_t v;
    expr_node_t *cast_func = cast_expr->root;
    expr_tree_t *default_expr = cast_func->argument;

    v.func_id = sql_get_func_id((text_t *)&cast_func->word.func.name);
    v.pack_id = CT_INVALID_ID32;
    v.is_proc = CT_FALSE;
    v.is_winsort_func = CT_FALSE;
    v.arg_cnt = CT_TRUE;
    v.orig_func_id = CT_INVALID_ID32;
    cast_func->value.type = CT_TYPE_INTEGER;
    cast_func->value.v_func = v;

    if (sql_verify_expr_node(verf, default_expr->root) != CT_SUCCESS) {
        cm_set_error_loc(default_expr->loc);
        return CT_ERROR;
    }

    cmode = &def->typmod;
    cast_func->typmod = def->typmod;
    cast_func->size = default_expr->next->root->value.v_type.size;

    if (sql_is_skipped_expr(default_expr)) {
        return CT_SUCCESS;
    }

    if (!var_datatype_matched(cmode->datatype, TREE_DATATYPE(default_expr))) {
        CT_SRC_ERROR_MISMATCH(TREE_LOC(default_expr), cmode->datatype, TREE_DATATYPE(default_expr));
        return CT_ERROR;
    }

    CT_RETVALUE_IFTRUE(!TREE_IS_CONST(default_expr), CT_SUCCESS);

    pvar = &default_expr->root->value;
    if (cmode->datatype != TREE_DATATYPE(default_expr)) {
        CT_RETVALUE_IFTRUE((pvar->is_null), CT_SUCCESS);
        CT_RETURN_IFERR(sql_convert_variant(verf->stmt, pvar, cmode->datatype));
        TREE_DATATYPE(default_expr) = cmode->datatype;
    }

    // copy string, binary, and raw datatype into SQL context
    if ((!pvar->is_null) && CT_IS_VARLEN_TYPE(pvar->type)) {
        text_t text_bak = pvar->v_text;
        CT_RETURN_IFERR(sql_copy_text(verf->stmt->context, &text_bak, &pvar->v_text));
    }

    if ((!pvar->is_null) && CT_IS_LOB_TYPE(pvar->type)) {
        var_lob_t lob_bak = pvar->v_lob;
        CT_RETURN_IFERR(sql_copy_text(verf->stmt->context, &lob_bak.normal_lob.value, &pvar->v_lob.normal_lob.value));
    }

    switch (cmode->datatype) {
        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
        case CT_TYPE_NUMBER3:
            status = cm_adjust_dec(&pvar->v_dec, cmode->precision, cmode->scale);
            break;

        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
            status = cm_adjust_timestamp(&pvar->v_tstamp, cmode->precision);
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            status = cm_adjust_timestamp_tz(&pvar->v_tstamp_tz, cmode->precision);
            break;

        case CT_TYPE_INTERVAL_DS:
            status = cm_adjust_dsinterval(&pvar->v_itvl_ds, (uint32)cmode->day_prec, (uint32)cmode->frac_prec);
            break;

        case CT_TYPE_INTERVAL_YM:
            status = cm_adjust_yminterval(&pvar->v_itvl_ym, (uint32)cmode->year_prec);
            break;

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            if (cmode->is_char) {
                CT_RETURN_IFERR(GET_DATABASE_CHARSET->length(&pvar->v_text, &value_len));
                if (pvar->v_text.len > CT_MAX_COLUMN_SIZE) {
                    CT_THROW_ERROR(ERR_VALUE_ERROR, "default string length is too long, beyond the max");
                    return CT_ERROR;
                }
            } else {
                value_len = pvar->v_text.len;
            }
            if (!pvar->is_null && value_len > cmode->size) {
                CT_THROW_ERROR(ERR_DEFAULT_LEN_TOO_LARGE, pvar->v_text.len, T2S(&def->name), cmode->size);
                status = CT_ERROR;
            }
            break;

        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            if (!pvar->is_null && pvar->v_bin.size > cmode->size) {
                CT_THROW_ERROR(ERR_DEFAULT_LEN_TOO_LARGE, pvar->v_bin.size, T2S(&def->name), cmode->size);
                status = CT_ERROR;
            }
            break;

        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BOOLEAN:
        case CT_TYPE_BIGINT:
        case CT_TYPE_UINT64:
        case CT_TYPE_REAL:
        case CT_TYPE_DATE:
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
        case CT_TYPE_DATE_MYSQL:
            return CT_SUCCESS;

        case CT_TYPE_CLOB:
        case CT_TYPE_BLOB:
        case CT_TYPE_IMAGE:
            return CT_SUCCESS;

        default:
            CT_THROW_ERROR(ERR_VALUE_ERROR, "the data type of column is not supported");
            return CT_ERROR;
    }

    if (status != CT_SUCCESS) {
        cm_set_error_loc(default_expr->loc);
    }

    return status;
}

static status_t sql_verify_cast_default_expr(sql_stmt_t *stmt, knl_column_def_t *column, expr_tree_t **expr)
{
    sql_verifier_t verf = { 0 };
    verf.context = stmt->context;
    verf.stmt = stmt;
    verf.column = column;
    verf.excl_flags = SQL_DEFAULT_EXCL;

    if (CT_SUCCESS != sql_build_cast_expr(stmt, TREE_LOC(*expr), *expr, &column->typmod, expr)) {
        CT_SRC_THROW_ERROR(TREE_LOC(*expr), ERR_CAST_TO_COLUMN, "default value", T2S(&column->name));
        return CT_ERROR;
    }

    return sql_verify_column_default_expr(&verf, *expr, column);
}

static status_t sql_verify_column_default(sql_stmt_t *stmt, knl_column_def_t *column)
{
    text_t save_text;
    lex_t *lex = stmt->session->lex;

    if (column->is_serial) {
        CT_THROW_ERROR(ERR_MUTI_DEFAULT_VALUE, T2S(&(column->name)));
        return CT_ERROR;
    }

    if (column->default_text.len > CT_MAX_DFLT_VALUE_LEN) {
        CT_SRC_THROW_ERROR_EX(TREE_LOC((expr_tree_t *)column->insert_expr), ERR_SQL_SYNTAX_ERROR,
            "default value string is too long, exceed %d", CT_MAX_DFLT_VALUE_LEN);
        return CT_ERROR;
    }

    if (sql_verify_cast_default_expr(stmt, column, (expr_tree_t **)&column->insert_expr) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (column->update_expr != NULL) {
        if (sql_verify_cast_default_expr(stmt, column, (expr_tree_t **)&column->update_expr) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (column->typmod.is_array == CT_TRUE) {
        CT_SRC_THROW_ERROR(LEX_LOC, ERR_SET_DEF_ARRAY_VAL);
        return CT_ERROR;
    }
    save_text = column->default_text;
    return sql_copy_text(stmt->context, &save_text, &column->default_text);
}

static status_t sql_parse_column_default(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
    uint32 *ex_flags)
{
    status_t status;
    text_t default_content;

    if (*ex_flags & COLUMN_EX_DEFAULT) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "duplicate or conflicting default specifications");
        return CT_ERROR;
    }

    column->default_text = lex->curr_text->value;
    lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
    status = sql_create_expr_until(stmt, (expr_tree_t **)&column->insert_expr, word);
    CT_RETURN_IFERR(status);
    column->is_default = CT_TRUE;
    *ex_flags |= COLUMN_EX_DEFAULT;

    if (word->id == KEY_WORD_ON) {
        status = lex_expected_fetch_word(lex, "UPDATE");
        CT_RETURN_IFERR(status);

        if (*ex_flags & COLUMN_EX_UPDATE_DEFAULT) {
            CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR,
                "duplicate or conflicting on update default specifications");
            return CT_ERROR;
        }

        lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
        status = sql_create_expr_until(stmt, (expr_tree_t **)&column->update_expr, word);
        CT_RETURN_IFERR(status);

        column->is_update_default = CT_TRUE;
        *ex_flags |= COLUMN_EX_UPDATE_DEFAULT;
    }

    lex->flags = LEX_SINGLE_WORD;
    if (word->type != WORD_TYPE_EOF) {
        column->default_text.len = (uint32)(word->text.str - column->default_text.str);
        lex_back(lex, word);
    }

    /* extract content of column default value */
    if (column->default_text.len > 0) {
        CT_RETURN_IFERR(sql_alloc_mem(stmt->context, column->default_text.len, (void **)&default_content.str));
        cm_extract_content(&column->default_text, &default_content);
        column->default_text = default_content;
    }
    cm_trim_text(&column->default_text);

    if (column->typmod.datatype == CT_TYPE_UNKNOWN) {
        // datatype may be know after 'as select' clause parsed,delay verify at 'sql_verify_default_column'
        column->delay_verify = CT_TRUE;
        return CT_SUCCESS;
    }

    return sql_verify_column_default(stmt, column);
}

// verify default column after column datatype get from  'as select' clause
status_t sql_delay_verify_default(sql_stmt_t *stmt, knl_table_def_t *def)
{
    galist_t *def_col = NULL;
    knl_column_def_t *column = NULL;
    uint32 loop;

    def_col = &def->columns;

    for (loop = 0; loop < def_col->count; ++loop) {
        column = (knl_column_def_t *)cm_galist_get(def_col, loop);
        // not default column or default column is already parsed before,continue
        if (!column->is_default || !column->delay_verify) {
            continue;
        }

        CT_RETURN_IFERR(sql_verify_column_default(stmt, column));
    }

    return CT_SUCCESS;
}

static status_t sql_parse_column_comment(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
    uint32 *ex_flags)
{
    if (*ex_flags & COLUMN_EX_COMMENT) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "duplicate or conflicting comment specifications");
        return CT_ERROR;
    }

    if (lex_expected_fetch_string(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_copy_text(stmt->context, (text_t *)&word->text, &column->comment) != CT_SUCCESS) {
        return CT_ERROR;
    }
    column->is_comment = CT_TRUE;
    *ex_flags |= COLUMN_EX_COMMENT;
    return CT_SUCCESS;
}

static status_t sql_parse_auto_increment(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
    uint32 *ex_flags)
{
    if ((*ex_flags & COLUMN_EX_AUTO_INCREMENT) || column->is_serial) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "duplicate or conflicting auto increment specifications");
        return CT_ERROR;
    }

    if ((*ex_flags & COLUMN_EX_DEFAULT) || (*ex_flags & COLUMN_EX_UPDATE_DEFAULT)) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "default column %s can not set to auto increment",
            T2S(&column->name));
        return CT_ERROR;
    }
    if (column->datatype == CT_TYPE_UNKNOWN) {
        // datatype may be know after 'as select' clause parsed,delay verify at 'sql_verify_auto_increment'
        column->delay_verify_auto_increment = CT_TRUE;
    } else {
        if (column->datatype != CT_TYPE_BIGINT && column->datatype != CT_TYPE_INTEGER &&
            column->datatype != CT_TYPE_UINT32) {
            CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                "auto increment column %s only support int type", T2S(&column->name));
            return CT_ERROR;
        }
    }

    column->is_serial = CT_TRUE;
    *ex_flags |= COLUMN_EX_AUTO_INCREMENT;
    return CT_SUCCESS;
}

static status_t sql_parse_col_ex_with_input_word_core(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column,
    word_t *word, uint32 *ex_flags)
{
    status_t status = CT_SUCCESS;
    switch (word->id) {
        case RES_WORD_DEFAULT:
            status = sql_parse_column_default(stmt, lex, column, word, ex_flags);
            break;

        case KEY_WORD_COMMENT:
            status = sql_parse_column_comment(stmt, lex, column, word, ex_flags);
            break;

        case KEY_WORD_AUTO_INCREMENT:
            status = sql_parse_auto_increment(stmt, lex, column, word, ex_flags);
            break;

        case KEY_WORD_COLLATE:
            status = sql_parse_collate(stmt, lex, &column->typmod.collate);
            column->is_collate = CT_TRUE;
            break;

        case KEY_WORD_PRIMARY:
            {
                status = sql_parse_inline_constraint_elemt(stmt, lex, column, word, ex_flags, NULL);
            }
            break;

        case KEY_WORD_UNIQUE:
            status = sql_parse_inline_constraint_elemt(stmt, lex, column, word, ex_flags, NULL);
            break;

        case KEY_WORD_REFERENCES:
            status = sql_parse_inline_constraint_elemt(stmt, lex, column, word, ex_flags, NULL);
            break;

        case KEY_WORD_CHECK:
            status = sql_parse_inline_constraint_elemt(stmt, lex, column, word, ex_flags, NULL);
            break;

        case KEY_WORD_WITH:
        case KEY_WORD_NOT:
        case RES_WORD_NULL:
            status = sql_parse_inline_constraint_elemt(stmt, lex, column, word, ex_flags, NULL);
            break;

        case KEY_WORD_CONSTRAINT:
            status = sql_parse_inline_constraint(stmt, lex, column, word, ex_flags);
            break;

        default:
            CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "constraint expected but %s found", W2S(word));
            return CT_ERROR;
    }
    return status;
}

static status_t sql_parse_col_ex_with_input_word(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word)
{
    status_t status;
    column->nullable = CT_TRUE;
    column->primary = CT_FALSE;
    uint32 ex_flags = 0;
    for (;;) {
        status = sql_parse_col_ex_with_input_word_core(stmt, lex, column, word, &ex_flags);
        CT_RETURN_IFERR(status);
        status = lex_fetch(lex, word);
        CT_RETURN_IFERR(status);

        if (word->type == WORD_TYPE_EOF || IS_SPEC_CHAR(word, ',')) {
            break;
        }
    }

    if (CM_IS_EMPTY(&column->default_text)) {
        if (g_instance->sql.enable_empty_string_null) {
            column->is_default_null = CT_TRUE;
        }
    }
    return CT_SUCCESS;
}

// extra attributes, such as constraints, default value, ...
static status_t sql_try_parse_column_ex(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word)
{
    status_t status;

    status = lex_fetch(lex, word);
    CT_RETURN_IFERR(status);

    if (word->type == WORD_TYPE_EOF || IS_SPEC_CHAR(word, ',')) {
        column->nullable = CT_TRUE;
        column->primary = CT_FALSE;
        return CT_SUCCESS;
    }

    return sql_parse_col_ex_with_input_word(stmt, lex, column, word);
}


static inline status_t sql_check_col_name_vaild(word_t *word)
{
    if (!IS_VARIANT(word)) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid column name '%s'", W2S(word));
        return CT_ERROR;
    }
    if (word->ex_count != 0) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "too many dot for column");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_parse_column_attr(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_table_def_t *def,
    bool32 *expect_as)
{
    text_t name;
    status_t status;
    knl_column_def_t *column = NULL;
    bool32 found = CT_FALSE;

    CT_RETURN_IFERR(sql_check_col_name_vaild(word));

    CT_RETURN_IFERR(sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &name));

    CT_RETURN_IFERR(sql_check_duplicate_column(&def->columns, &name));

    CT_RETURN_IFERR(cm_galist_new(&def->columns, sizeof(knl_column_def_t), (pointer_t *)&column));

    if (word->type == WORD_TYPE_DQ_STRING) {
        column->has_quote = CT_TRUE;
    }

    column->nullable = CT_TRUE;
    column->name = name;
    column->table = (void *)def;
    cm_galist_init(&column->ref_columns, stmt->context, sql_alloc_mem);

    // considering syntax create table(a, b, c) as select, columns may have no data type
    CT_RETURN_IFERR(lex_fetch(lex, word));

    if (word->type == WORD_TYPE_EOF || IS_SPEC_CHAR(word, ',')) {
        *expect_as = CT_TRUE;
        column->datatype = CT_TYPE_UNKNOWN;
        return CT_SUCCESS;
    }

    // try to parse datatype, considering syntax create(a not null,b default 'c',c primary key) as select
    CT_RETURN_IFERR(sql_try_parse_column_datatype(lex, column, word, &found));
    if (found) {
        // parse extended attribute, like not null, default, primary key, or is array field.
        status = sql_try_parse_column_ex(stmt, lex, column, word);
        CT_RETURN_IFERR(status);
    } else if (word->type == WORD_TYPE_KEYWORD || word->type == WORD_TYPE_RESERVED) {
        *expect_as = CT_TRUE;
        // parse extended attribute, use current word as first word
        column->datatype = CT_TYPE_UNKNOWN;
        status = sql_parse_col_ex_with_input_word(stmt, lex, column, word);
        CT_RETURN_IFERR(status);
    } else {
        CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "datatype expected, but got '%s'", W2S(word));
        return CT_ERROR;
    }

    if (column->primary) {
        if (def->pk_inline) {
            CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "table can have only one primary key.");
            return CT_ERROR;
        }
        def->pk_inline = CT_TRUE;
    }

    def->rf_inline = def->rf_inline || (column->is_ref);
    def->uq_inline = def->uq_inline || (column->unique);
    def->chk_inline = def->chk_inline || (column->is_check);

    return CT_SUCCESS;
}


status_t sql_parse_column_property(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_altable_def_t *def, uint32 *flags)
{
    status_t status;
    bool32 found = CT_FALSE;
    knl_column_t *old_column = NULL;
    sql_table_entry_t *table = NULL;
    knl_column_def_t *target_column = NULL;
    knl_alt_column_prop_t *column_def = NULL;
    knl_alt_column_prop_t *prev_def = NULL;
    text_t col_cpyname = { 0x00 };
    uint32 i;
    table_type_t table_type;

    CT_RETURN_IFERR(cm_galist_new(&def->column_defs, sizeof(knl_alt_column_prop_t), (void **)&column_def));
    target_column = &column_def->new_column;
    column_def->new_column.col_id = def->column_defs.count - 1;
    if (!IS_VARIANT(word)) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid column name '%s'", W2S(word));
        return CT_ERROR;
    }

    if (sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &col_cpyname) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* check the name of the previous columns if there is duplicate name.
    the newly inserted knl_alt_column_prop_t does not count */
    for (i = 0; i < def->column_defs.count - 1; i++) {
        prev_def = (knl_alt_column_prop_t *)cm_galist_get(&def->column_defs, i);
        if (cm_compare_text(&(prev_def->new_column.name), &col_cpyname) == 0) {
            CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicated column name \"%s\"",
                T2S((text_t *)&word->text));
            return CT_ERROR;
        }
    }
    target_column->name = col_cpyname;
    target_column->table = (void *)def;

    switch (def->action) {
        case ALTABLE_ADD_COLUMN: /* date type must be specified in ADD COLUMN */
            if (sql_parse_column_datatype(lex, target_column, word) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;
        case ALTABLE_MODIFY_COLUMN: /* date type is optional in MODIFY COLUMN */
            status = lex_fetch(lex, word);
            CT_RETURN_IFERR(status);
            if (word->type == WORD_TYPE_EOF) {
                return CT_SUCCESS;
            }

            if (sql_try_parse_column_datatype(lex, target_column, word, &found) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (!found) {
                table = (sql_table_entry_t *)cm_galist_get(stmt->context->tables, 0);
                old_column = knl_find_column(&target_column->name, &table->dc);
                if (old_column == NULL) {
                    CT_THROW_ERROR(ERR_COLUMN_NOT_EXIST, T2S(&def->name), T2S_EX(&target_column->name));
                    return CT_ERROR;
                }
                target_column->datatype = old_column->datatype;
                target_column->size = old_column->size;
                target_column->precision = old_column->precision;
                target_column->scale = old_column->scale;
                if (CT_IS_STRING_TYPE(target_column->datatype)) {
                    target_column->typmod.is_char = KNL_COLUMN_IS_CHARACTER(old_column);
                }
                lex_back(lex, word);
            }
            break;
        default:
            CT_THROW_ERROR(ERR_VALUE_ERROR, "unexpected action value found");
            return CT_ERROR;
    }

    if (CT_IS_LOB_TYPE(target_column->datatype)) {
        table = (sql_table_entry_t *)cm_galist_get(stmt->context->tables, 0);
        table_type = knl_get_table(&table->dc)->type;
        if (table_type == TABLE_TYPE_SESSION_TEMP || table_type == TABLE_TYPE_TRANS_TEMP) {
            if (target_column->datatype == CT_TYPE_CLOB || target_column->datatype == CT_TYPE_IMAGE) {
                target_column->datatype = CT_TYPE_VARCHAR;
                target_column->size = CT_MAX_COLUMN_SIZE;
            } else {
                target_column->datatype = CT_TYPE_RAW;
                target_column->size = CT_MAX_COLUMN_SIZE;
            }
        }
    }

    if (sql_try_parse_column_ex(stmt, lex, target_column, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (target_column->is_serial) {
        if (*flags & ALTAB_AUTO_INCREMENT_COLUMN) {
            CT_THROW_ERROR(ERR_DUPLICATE_AUTO_COLUMN);
            return CT_ERROR;
        }

        if (def->action == ALTABLE_ADD_COLUMN) {
            if (!(target_column->primary || target_column->unique)) {
                CT_THROW_ERROR(ERR_DUPLICATE_AUTO_COLUMN);
                return CT_ERROR;
            }
        }

        *flags |= ALTAB_AUTO_INCREMENT_COLUMN;
    }

    if (target_column->is_ref) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can't add inline constraint when altering table");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_create_altable_inline_cons(stmt, target_column, column_def));

    return CT_SUCCESS;
}

status_t sql_parse_modify_lob(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *tab_def)
{
    status_t status;
    knl_modify_lob_def_t *lob_def = &tab_def->modify_lob_def;
    word_t word;

    tab_def->action = ALTABLE_MODIFY_LOB;

    status = lex_expected_fetch_bracket(lex, &word);
    CT_RETURN_IFERR(status);

    CT_RETURN_IFERR(lex_push(lex, &word.text));
    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }
    if (sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &lob_def->name) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    lex_pop(lex);

    status = lex_expected_fetch_bracket(lex, &word);
    CT_RETURN_IFERR(status);
    CT_RETURN_IFERR(lex_push(lex, &word.text));

    if (lex_expected_fetch_word(lex, "SHRINK") != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }
    if (lex_expected_fetch_word(lex, "SPACE") != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    if (lex_expected_end(lex) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    lex_pop(lex);
    lob_def->action = MODIFY_LOB_SHRINK;
    return CT_SUCCESS;
}


status_t sql_verify_cols_without_specific(sql_stmt_t *stmt, knl_table_def_t *def)
{
    uint32 loop;
    knl_column_def_t *def_col = NULL;
    rs_column_t *rs_col = NULL;
    galist_t *def_cols = NULL;
    galist_t *rs_columns = NULL;

    def_cols = &def->columns;
    rs_columns = ((sql_select_t *)stmt->context->supplement)->first_query->rs_columns;

    for (loop = 0; loop < rs_columns->count; ++loop) {
        rs_col = (rs_column_t *)cm_galist_get(rs_columns, loop);
        if (!CT_BIT_TEST(rs_col->rs_flag, RS_SINGLE_COL) && !CT_BIT_TEST(rs_col->rs_flag, RS_EXIST_ALIAS)) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "must name expression with a column alias");
            return CT_ERROR;
        }

        CT_RETURN_IFERR(sql_check_duplicate_column(def_cols, &rs_col->name));

        CT_RETURN_IFERR(cm_galist_new(def_cols, sizeof(knl_column_def_t), (pointer_t *)&def_col));
        MEMS_RETURN_IFERR(memset_s(def_col, sizeof(knl_column_def_t), 0, sizeof(knl_column_def_t)));
        CT_RETURN_IFERR(sql_copy_text(stmt->context, &rs_col->name, &def_col->name));
        if (rs_col->size == 0) {
            CT_THROW_ERROR(ERR_COLUMN_NOT_NULL, T2S(&rs_col->name));
            return CT_ERROR;
        }

        def_col->table = def;
        def_col->typmod = rs_col->typmod;
        cm_adjust_typmode(&def_col->typmod);
        def_col->nullable = CT_BIT_TEST(rs_col->rs_flag, RS_NULLABLE) ? CT_TRUE : CT_FALSE;
        def_col->is_jsonb = rs_col->v_col.is_jsonb;
    }

    return CT_SUCCESS;
}

status_t sql_verify_cols_with_specific(sql_stmt_t *stmt, knl_table_def_t *def)
{
    uint32 loop;
    knl_column_def_t *def_col = NULL;
    rs_column_t *rs_col = NULL;
    galist_t *def_cols = NULL;
    galist_t *rs_columns = NULL;

    def_cols = &def->columns;
    rs_columns = ((sql_select_t *)stmt->context->supplement)->first_query->rs_columns;

    if (def_cols->count != rs_columns->count) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "number of defined columns mismatch that in select clause");
        return CT_ERROR;
    }
    for (loop = 0; loop < def_cols->count; ++loop) {
        def_col = (knl_column_def_t *)cm_galist_get(def_cols, loop);
        rs_col = (rs_column_t *)cm_galist_get(rs_columns, loop);
        if (def_col->nullable) {
            def_col->nullable = CT_BIT_TEST(rs_col->rs_flag, RS_NULLABLE) ? CT_TRUE : CT_FALSE;
        }
        if (def_col->datatype == CT_TYPE_UNKNOWN) {
            def_col->typmod = rs_col->typmod;
        } else {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "may not specify column datatypes in CREATE TABLE");
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t sql_verify_columns(sql_stmt_t *stmt, knl_table_def_t *def)
{
    galist_t *def_col = NULL;

    def_col = &def->columns;

    if (def_col->count != 0) {
        return sql_verify_cols_with_specific(stmt, def);
    }

    return sql_verify_cols_without_specific(stmt, def);
}

status_t sql_verify_cons_def(knl_table_def_t *def)
{
    uint32 i, j, m, n;
    text_t *col_name = NULL;
    galist_t *columns = &def->columns;
    knl_column_def_t *column = NULL;
    knl_index_col_def_t *index_col = NULL;
    knl_constraint_def_t *cons1 = NULL;
    knl_constraint_def_t *cons2 = NULL;

    for (i = 0; i < def->constraints.count; i++) {
        cons1 = (knl_constraint_def_t *)cm_galist_get(&def->constraints, i);

        for (m = 0; m < cons1->columns.count; m++) {
            if (cons1->type == CONS_TYPE_PRIMARY || cons1->type == CONS_TYPE_UNIQUE) {
                index_col = (knl_index_col_def_t *)cm_galist_get(&cons1->columns, m);
                col_name = &index_col->name;
            } else {
                col_name = (text_t *)cm_galist_get(&cons1->columns, m);
            }

            for (n = 0; n < columns->count; n++) {
                column = (knl_column_def_t *)cm_galist_get(columns, n);
                if (cm_text_equal_ins(&column->name, col_name)) {
                    break;
                }
            }

            if (n == columns->count) {
                CT_THROW_ERROR(ERR_COLUMN_NOT_EXIST, T2S(&def->schema), T2S_EX(col_name));
                return CT_ERROR;
            }
        }
        for (j = i + 1; j < def->constraints.count; j++) {
            cons2 = (knl_constraint_def_t *)cm_galist_get(&def->constraints, j);
            if (cm_text_equal(&cons1->name, &cons2->name)) {
                CT_THROW_ERROR(ERR_OBJECT_EXISTS, "constraint", T2S(&cons1->name));
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

status_t sql_verify_array_columns(table_type_t type, galist_t *columns)
{
    knl_column_def_t *column = NULL;

    if (type == TABLE_TYPE_HEAP) {
        return CT_SUCCESS;
    }

    /* non-heap table can not have array type columns */
    for (uint32 i = 0; i < columns->count; i++) {
        column = (knl_column_def_t *)cm_galist_get(columns, i);
        if (column != NULL && column->typmod.is_array == CT_TRUE) {
            CT_THROW_ERROR(ERR_WRONG_TABLE_TYPE);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t sql_verify_auto_increment(sql_stmt_t *stmt, knl_table_def_t *def)
{
    uint32 i;
    uint32 serial_colums = 0;
    knl_column_def_t *column = NULL;
    knl_column_def_t *serial_col = NULL;
    knl_constraint_def_t *cons = NULL;
    knl_index_col_def_t *index_col = NULL;

    for (i = 0; i < def->columns.count; i++) {
        column = (knl_column_def_t *)cm_galist_get(&def->columns, i);
        if (column->is_serial) {
            serial_col = column;
            serial_colums++;
            if (column->delay_verify_auto_increment == CT_TRUE && column->datatype != CT_TYPE_BIGINT &&
                column->datatype != CT_TYPE_INTEGER && column->datatype != CT_TYPE_UINT32 &&
                column->datatype != CT_TYPE_UINT64) {
                CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "auto increment column %s only support int type",
                    T2S(&column->name));
                return CT_ERROR;
            }
        }
    }

    if (serial_colums == 0) {
        return CT_SUCCESS;
    } else if (serial_colums > 1) {
        CT_THROW_ERROR(ERR_DUPLICATE_AUTO_COLUMN);
        return CT_ERROR;
    }

    for (i = 0; i < def->constraints.count; i++) {
        cons = (knl_constraint_def_t *)cm_galist_get(&def->constraints, i);
        if (cons->type == CONS_TYPE_PRIMARY || cons->type == CONS_TYPE_UNIQUE) {
            if (cons->columns.count == 0) {
                continue;
            }

            index_col = (knl_index_col_def_t *)cm_galist_get(&cons->columns, 0);
            if (cm_text_equal(&index_col->name, &serial_col->name)) {
                break;
            }
        }
    }

    if (IS_COMPATIBLE_MYSQL_INST) {
        return CT_SUCCESS;
    }

    if (i == def->constraints.count) {
        CT_THROW_ERROR(ERR_DUPLICATE_AUTO_COLUMN);
        return CT_ERROR;
    }

    variant_t value = {
        .type = CT_TYPE_BIGINT,
        .is_null = CT_FALSE,
        .v_bigint = def->serial_start
    };
    return sql_convert_variant(stmt, &value, serial_col->datatype);
}

static status_t sql_parse_add_logic_log(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def)
{
    word_t word;

    CT_RETURN_IFERR(lex_expected_fetch(lex, &word));
    if (word.id != KEY_WORD_LOG) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "LOG expected but %s found", W2S(&word));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_expected_fetch(lex, &word));
    if (word.type != WORD_TYPE_BRACKET) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "( expected but %s found", W2S(&word));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_push(lex, &word.text));

    if (lex_expected_fetch(lex, &word) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }
    if (word.id == KEY_WORD_PRIMARY) {
        if (lex_expected_fetch(lex, &word) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        if (word.id != KEY_WORD_KEY) {
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "KEY expected but %s found", W2S(&word));
            lex_pop(lex);
            return CT_ERROR;
        }
        def->logical_log_def.key_type = LOGICREP_KEY_TYPE_PRIMARY_KEY;
    } else if (word.id == KEY_WORD_UNIQUE) {
        if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        if (sql_copy_name(stmt->context, (text_t *)&word.text, &def->logical_log_def.idx_name) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }

        def->logical_log_def.key_type = LOGICREP_KEY_TYPE_UNIQUE;
    } else {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "PRIMARY or UNIQUE expected but %s found",
            W2S(&word));
        lex_pop(lex);
        return CT_ERROR;
    }

    lex_pop(lex);

    return CT_SUCCESS;
}

static status_t sql_parse_altable_add_brackets_word(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def, word_t word)
{
    status_t status;
    switch (word.id) {
        case KEY_WORD_PRIMARY:
            {
                status = sql_parse_primary_unique_cons(stmt, lex, CONS_TYPE_PRIMARY, &def->cons_def.new_cons);
            }
            break;
        case KEY_WORD_UNIQUE:
            status = sql_parse_primary_unique_cons(stmt, lex, CONS_TYPE_UNIQUE, &def->cons_def.new_cons);
            break;
        case KEY_WORD_CONSTRAINT:
            status = sql_parse_constraint(stmt, lex, def);
            break;
        case KEY_WORD_FOREIGN:
            status = sql_parse_foreign_key(stmt, lex, &def->cons_def.new_cons);
            break;
        case KEY_WORD_PARTITION:
            status = sql_parse_add_partition(stmt, lex, def);
            break;
        case KEY_WORD_CHECK:
            status = sql_parse_add_check(stmt, lex, def, &def->cons_def.new_cons);
            break;
        case KEY_WORD_LOGICAL:
            def->action = ALTABLE_ADD_LOGICAL_LOG;
            status = sql_parse_add_logic_log(stmt, lex, def);
            break;

        default:
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "constraint expected but %s found", W2S(&word));
            status = CT_ERROR;
            break;
    }
    return status;
}

/* sql_parse_altable_add_brackets_recurse() is used for handling the possible brackets in the ADD clause */
status_t sql_parse_altable_add_brackets_recurse(sql_stmt_t *stmt, lex_t *lex, bool32 enclosed, knl_altable_def_t *def)
{
    uint32 flags = 0;
    word_t word;

    CT_RETURN_IFERR(lex_expected_fetch(lex, &word));
    if (def->logical_log_def.is_parts_logical == CT_TRUE && word.id != KEY_WORD_LOGICAL) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "logical expected but %s found", W2S(&word));
        return CT_ERROR;
    }

    if (word.type == WORD_TYPE_BRACKET) {
        CT_RETURN_IFERR(lex_push(lex, &word.text));
        if (sql_parse_altable_add_brackets_recurse(stmt, lex, CT_TRUE, def) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        status_t status = lex_expected_end(lex);
        lex_pop(lex);
        return status;
    }

    if (!IS_CONSTRAINT_KEYWORD(word.id)) {
        if (cm_compare_text_str_ins(&(word.text.value), "COLUMN") == 0) {
            /* syntactically tolerant to an extra "COLUMN" */
            CT_RETURN_IFERR(lex_expected_fetch(lex, &word));
        }

        def->action = ALTABLE_ADD_COLUMN;
        cm_galist_init(&def->column_defs, stmt->context, sql_alloc_mem);
        for (;;) {
            CT_RETURN_IFERR(sql_parse_column_property(stmt, lex, &word, def, &flags));
            if (word.type == WORD_TYPE_EOF) {
                return CT_SUCCESS;
            }

            /*
             * followed by a ',' and currently enclosed in parentheses,
             * continue to parse the next column property
             */
            if (IS_SPEC_CHAR(&word, ',') && enclosed) {
                CT_RETURN_IFERR(lex_expected_fetch(lex, &word));
                if (cm_compare_text_str_ins(&(word.text.value), "COLUMN") == 0) {
                    /* syntactically tolerant to an extra "COLUMN" */
                    CT_RETURN_IFERR(lex_expected_fetch(lex, &word));
                }
                continue;
            }

            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
                "unexpected \"%s\" found in the add column clause", W2S(&word));
            return CT_ERROR;
        }
    }

    def->action = ALTABLE_ADD_CONSTRAINT;
    def->cons_def.new_cons.cons_state.is_anonymous = CT_TRUE;
    def->cons_def.new_cons.cons_state.is_enable = CT_TRUE;
    def->cons_def.new_cons.cons_state.is_validate = CT_TRUE;
    def->cons_def.new_cons.cons_state.is_cascade = CT_TRUE;

    return sql_parse_altable_add_brackets_word(stmt, lex, def, word);
}

/* sql_parse_altable_modify_brackets_recurse() is used for handling the possible brackets in the MODIFY clause */
status_t sql_parse_altable_modify_brackets_recurse(sql_stmt_t *stmt, lex_t *lex, bool32 enclosed,
    knl_altable_def_t *def)
{
    uint32 flags = 0;
    word_t word;

    CT_RETURN_IFERR(lex_expected_fetch(lex, &word));

    if (word.type == WORD_TYPE_BRACKET) {
        CT_RETURN_IFERR(lex_push(lex, &word.text));
        if (sql_parse_altable_modify_brackets_recurse(stmt, lex, CT_TRUE, def) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        status_t status = lex_expected_end(lex);
        lex_pop(lex);
        return status;
    } else if (word.id == KEY_WORD_LOB) {
        return sql_parse_modify_lob(stmt, lex, def);
    } else if (word.id == KEY_WORD_PARTITION) {
        return sql_parse_modify_partition(stmt, lex, def);
    }
    if (IS_VARIANT(&word)) {
        def->action = ALTABLE_MODIFY_COLUMN;
        cm_galist_init(&def->column_defs, stmt->context, sql_alloc_mem);
        for (;;) {
            CT_RETURN_IFERR(sql_parse_column_property(stmt, lex, &word, def, &flags));
            if (word.type == WORD_TYPE_EOF) {
                return CT_SUCCESS;
            }

            /*
             * followed by a ',' and currently enclosed in parentheses,
             * continue to parse the next column property
             */
            if (IS_SPEC_CHAR(&word, ',') && enclosed) {
                CT_RETURN_IFERR(lex_expected_fetch(lex, &word));
                continue;
            }

            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
                "unexpected \"%s\" found in the modify column clause", W2S(&word));
            return CT_ERROR;
        }
    } else {
        def->action = ALTABLE_MODIFY_CONSTRAINT;
        def->cons_def.new_cons.cons_state.is_anonymous = CT_TRUE;
        def->cons_def.new_cons.cons_state.is_enable = CT_TRUE;
        def->cons_def.new_cons.cons_state.is_validate = CT_TRUE;
        def->cons_def.new_cons.cons_state.is_cascade = CT_TRUE;
        return sql_parse_constraint(stmt, lex, def);
    }
}

status_t sql_parse_column_defs(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def, bool32 *expect_as)
{
    status_t status;
    word_t word;
    bool32 result = CT_FALSE;

    for (;;) {
        status = lex_expected_fetch(lex, &word);
        CT_RETURN_IFERR(status);

        status = sql_try_parse_cons(stmt, lex, def, &word, &result);
        CT_RETURN_IFERR(status);

        if (result) {
            if (word.type == WORD_TYPE_EOF) {
                break;
            }

            continue;
        }

        status = sql_parse_column_attr(stmt, lex, &word, def, expect_as);
        CT_RETURN_IFERR(status);

        if (word.type == WORD_TYPE_EOF) {
            break;
        }
    }

    return CT_SUCCESS;
}

status_t sql_check_duplicate_column_name(galist_t *columns, const text_t *name)
{
    uint32 i;
    text_t *column = NULL;

    for (i = 0; i < columns->count; i++) {
        column = (text_t *)cm_galist_get(columns, i);
        if (cm_text_equal(column, name)) {
            CT_THROW_ERROR(ERR_DUPLICATE_NAME, "column", T2S(name));
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t sql_parse_altable_column_rename(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def)
{
    word_t word;
    uint32 pre_flags = lex->flags;
    knl_alt_column_prop_t *col_def = NULL;
    def->action = ALTABLE_RENAME_COLUMN;
    cm_galist_init(&def->column_defs, stmt->context, sql_alloc_mem);
    lex->flags = LEX_SINGLE_WORD;

    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        lex->flags = pre_flags;
        return CT_ERROR;
    }
    lex->flags = pre_flags;
    CT_RETURN_IFERR(cm_galist_new(&def->column_defs, sizeof(knl_alt_column_prop_t), (void **)&col_def));
    if (sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &col_def->name) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (lex_expected_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if ((key_wid_t)word.id != KEY_WORD_TO) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "TO expected but %s found", W2S(&word));
        return CT_ERROR;
    }
    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        lex->flags = pre_flags;
        return CT_ERROR;
    }
    lex->flags = pre_flags;
    if (sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &col_def->new_name) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return lex_expected_end(lex);
}
