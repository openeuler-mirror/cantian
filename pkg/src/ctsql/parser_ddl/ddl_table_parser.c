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
 * ddl_table_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_table_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ddl_table_parser.h"
#include "ddl_table_attr_parser.h"
#include "ddl_partition_parser.h"
#include "ddl_column_parser.h"
#include "ddl_constraint_parser.h"
#include "ddl_parser_common.h"
#include "expr_parser.h"
#include "srv_instance.h"
#include "ctsql_select_parser.h"
#include "srv_param_common.h"

static inline bool8 sql_table_has_special_char(text_t *name)
{
    uint32 i;

    for (i = 0; i < name->len; i++) {
        if (name->str[i] == '\"') {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

static status_t sql_parse_altable_table_rename(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def)
{
    word_t word;
    lex->flags = LEX_WITH_OWNER;

    def->action = ALTABLE_RENAME_TABLE;
    text_t user;
    bool32 user_exist = CT_FALSE;

    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (sql_convert_object_name(stmt, &word, &user, &user_exist, &def->table_def.new_name) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (user_exist == CT_TRUE) {
        if (cm_compare_text(&user, &def->user) != 0) {
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
                "table user(%s) is not consistent with table "
                "user(%s)",
                T2S(&def->user), T2S_EX(&user));
            return CT_ERROR;
        }
    }
    if (sql_table_has_special_char(&def->table_def.new_name)) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid variant/object name was found");
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}

static status_t sql_parse_altable_add(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def)
{
    CT_RETURN_IFERR(sql_parse_altable_add_brackets_recurse(stmt, lex, CT_FALSE, def));

    /*
     * the enable/disable clause of the table is not supported currently,
     * so an end is expected
     */
    CT_RETURN_IFERR(lex_expected_end(lex));

    return CT_SUCCESS;
}

static status_t sql_parse_altable_modify(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def)
{
    CT_RETURN_IFERR(sql_parse_altable_modify_brackets_recurse(stmt, lex, CT_FALSE, def));

    /*
     * the enable/disable clause of the table is not supported currently,
     * so an end is expected
     */
    CT_RETURN_IFERR(lex_expected_end(lex));

    return CT_SUCCESS;
}

static status_t sql_parse_drop_logical_log(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def)
{
    word_t word;

    CT_RETURN_IFERR(lex_expected_fetch(lex, &word));
    if (word.id != KEY_WORD_LOG) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "LOG expected but %s found", W2S(&word));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_parse_altable_drop(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def)
{
    key_wid_t wid;
    word_t word;
    bool32 is_cascade = CT_FALSE;
    text_t *name = NULL;
    status_t status;
    knl_alt_column_prop_t *col_def = NULL;

    status = lex_expected_fetch(lex, &word);
    CT_RETURN_IFERR(status);
    if (def->logical_log_def.is_parts_logical == CT_TRUE && word.id != KEY_WORD_LOGICAL) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "logical expected but %s found", W2S(&word));
        return CT_ERROR;
    }

    if (IS_VARIANT(&word) && word.id != KEY_WORD_PARTITION && word.id != KEY_WORD_LOGICAL &&
        word.id != KEY_WORD_SUBPARTITION) {
        def->action = ALTABLE_DROP_COLUMN;
        cm_galist_init(&def->column_defs, stmt->context, sql_alloc_mem);
        CT_RETURN_IFERR(cm_galist_new(&def->column_defs, sizeof(knl_alt_column_prop_t), (void **)&col_def));
        name = &col_def->name;
    } else {
        wid = (key_wid_t)word.id;
        switch (wid) {
            case KEY_WORD_COLUMN:
                def->action = ALTABLE_DROP_COLUMN;
                cm_galist_init(&def->column_defs, stmt->context, sql_alloc_mem);
                CT_RETURN_IFERR(cm_galist_new(&def->column_defs, sizeof(knl_alt_column_prop_t), (void **)&col_def));
                name = &col_def->name;
                break;
            case KEY_WORD_CONSTRAINT:
                def->action = ALTABLE_DROP_CONSTRAINT;
                name = &def->cons_def.name;
                CT_RETURN_IFERR(sql_try_parse_if_exists(lex, &def->options));
                break;
            case KEY_WORD_PARTITION:
                def->action = ALTABLE_DROP_PARTITION;
                name = &def->part_def.name;
                CT_RETURN_IFERR(sql_try_parse_if_exists(lex, &def->options));
                break;
            case KEY_WORD_SUBPARTITION:
                def->action = ALTABLE_DROP_SUBPARTITION;
                name = &def->part_def.name;
                CT_RETURN_IFERR(sql_try_parse_if_exists(lex, &def->options));
                break;
            case KEY_WORD_LOGICAL:
                def->action = ALTABLE_DROP_LOGICAL_LOG;
                CT_RETURN_IFERR(sql_parse_drop_logical_log(stmt, lex, def));
                CT_RETURN_IFERR(lex_expected_end(lex));
                return CT_SUCCESS;
            default:
                CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
                    "CONSTRAINT or COLUMN or PARTITION or LOGICAL expected but %s found", W2S(&word));
                return CT_ERROR;
        }

        lex->flags = LEX_SINGLE_WORD;
        status = lex_expected_fetch_variant(lex, &word);
        CT_RETURN_IFERR(status);
    }

    CT_RETURN_IFERR(sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, name));
    if (def->action == ALTABLE_DROP_CONSTRAINT) {
        status = lex_try_fetch(lex, "CASCADE", &is_cascade);
        CT_RETURN_IFERR(status);

        if (is_cascade) {
            def->cons_def.opts |= DROP_CASCADE_CONS;
        }
    }

    return lex_expected_end(lex);
}


static status_t sql_parse_altable_rename(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def)
{
    key_wid_t wid;
    word_t word;

    if (lex_expected_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }
    wid = (key_wid_t)word.id;
    switch (wid) {
        case KEY_WORD_TO:
            return sql_parse_altable_table_rename(stmt, lex, def);
        case KEY_WORD_COLUMN:
            return sql_parse_altable_column_rename(stmt, lex, def);
        case KEY_WORD_CONSTRAINT:
            return sql_parse_altable_constraint_rename(stmt, lex, def);
        default:
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
                "CONSTRAINT or COLUMN or TO expected but %s found", W2S(&word));
            return CT_ERROR;
    }
}

static status_t sql_parse_truncate_option(sql_stmt_t *stmt, word_t *word, uint32 *option)
{
    lex_t *lex = stmt->session->lex;
    status_t status;

    *option = TRUNC_RECYCLE_STORAGE;

    for (;;) {
        status = lex_fetch(lex, word);
        CT_RETURN_IFERR(status);

        if (word->type == WORD_TYPE_EOF) {
            return CT_SUCCESS;
        }

        switch (word->id) {
            case KEY_WORD_PURGE:
                *option |= TRUNC_PURGE_STORAGE;
                break;

            case KEY_WORD_DROP:
                status = lex_expected_fetch_word(lex, "STORAGE");
                CT_RETURN_IFERR(status);
                if (*option & TRUNC_REUSE_STORAGE) {
                    CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected text conflict %s",
                        W2S(word));
                    return CT_ERROR;
                }
                *option |= TRUNC_DROP_STORAGE;
                break;

            case KEY_WORD_REUSE:
                status = lex_expected_fetch_word(lex, "STORAGE");
                CT_RETURN_IFERR(status);
                if (*option & TRUNC_DROP_STORAGE) {
                    CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected text conflict %s",
                        W2S(word));
                    return CT_ERROR;
                }
                *option |= TRUNC_REUSE_STORAGE;
                break;

            default:
                CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected text %s", W2S(word));
                return CT_ERROR;
        }
    }
}

static status_t sql_parse_altable_truncate(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def)
{
    word_t word;
    status_t status;

    status = lex_expected_fetch(lex, &word);
    CT_RETURN_IFERR(status);

    if (word.id != KEY_WORD_PARTITION && word.id != KEY_WORD_SUBPARTITION) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, " PARTITION or SUBPARTITION expected but %s found",
            W2S(&word));
        return CT_ERROR;
    }

    if (word.id == KEY_WORD_PARTITION) {
        def->action = ALTABLE_TRUNCATE_PARTITION;
    } else {
        def->action = ALTABLE_TRUNCATE_SUBPARTITION;
    }

    lex->flags = LEX_SINGLE_WORD;

    status = lex_expected_fetch_variant(lex, &word);
    CT_RETURN_IFERR(status);

    status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->part_def.name);
    CT_RETURN_IFERR(status);

    status = sql_parse_truncate_option(stmt, &word, &def->part_def.option);
    CT_RETURN_IFERR(status);

    return lex_expected_end(lex);
}

static status_t sql_parse_enable_disable_clause(sql_stmt_t *stmt, word_t *word, lex_t *lex, knl_altable_def_t *def)
{
    uint32 match_id;
    knl_constraint_def_t *cons = &def->cons_def.new_cons;
    def->action = ALTABLE_APPLY_CONSTRAINT;
    cons->cons_state.is_cascade = CT_TRUE;
    if (word->id == KEY_WORD_ENABLE) {
        cons->cons_state.is_enable = CT_TRUE;
        cons->cons_state.is_validate = CT_TRUE;
    } else if (word->id == KEY_WORD_DISABLE) {
        cons->cons_state.is_enable = CT_FALSE;
        cons->cons_state.is_validate = CT_FALSE;
    }

    if (CT_SUCCESS != lex_expected_fetch_1of3(lex, "VALIDATE", "NOVALIDATE", "CONSTRAINT", &match_id)) {
        return CT_ERROR;
    }

    if (match_id == LEX_MATCH_FIRST_WORD) {
        if (word->id == KEY_WORD_DISABLE) {
            cons->cons_state.is_validate = CT_TRUE;
        }
    } else if (match_id == LEX_MATCH_SECOND_WORD) {
        if (word->id == KEY_WORD_ENABLE) {
            cons->cons_state.is_validate = CT_FALSE;
        }
    }

    if (match_id != LEX_MATCH_THIRD_WORD) {
        if (CT_SUCCESS != lex_expected_fetch_word(lex, "CONSTRAINT")) {
            return CT_ERROR;
        }
    }

    if (lex_expected_fetch_variant(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &cons->name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}

static status_t sql_parse_altable_enable_partition(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def,
    bool32 *enable_part)
{
    word_t word;
    uint32 match_id;

    CT_RETURN_IFERR(lex_try_fetch_1of2(lex, "PARTITION", "SUBPARTITION", &match_id));
    if (match_id == CT_INVALID_ID32) {
        *enable_part = CT_FALSE;
        return CT_SUCCESS;
    }

    *enable_part = CT_TRUE;

    if (match_id == 0) {
        def->action = ALTABLE_ENABLE_PART_NOLOGGING;
    } else {
        def->action = ALTABLE_ENABLE_SUBPART_NOLOGGING;
    }

    CT_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));
    CT_RETURN_IFERR(sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->part_def.name));
    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "NOLOGGING"));
    return lex_expected_end(lex);
}

static status_t sql_parse_altable_enable(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_altable_def_t *def)
{
    bool32 result = CT_FALSE;
    bool32 enable_part = CT_FALSE;

    CT_RETURN_IFERR(sql_parse_altable_enable_partition(stmt, lex, def, &enable_part));
    if (enable_part) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(lex_try_fetch(lex, "NOLOGGING", &result));
    if (result) {
        def->action = ALTABLE_ENABLE_NOLOGGING;
        return lex_expected_end(lex);
    }

    CT_RETURN_IFERR(lex_try_fetch(lex, "ALL", &result));

    if (result) {
        CT_RETURN_IFERR(lex_expected_fetch_word(lex, "TRIGGERS"));
        def->action = ALTABLE_ENABLE_ALL_TRIG;
    } else {
        if (CT_SUCCESS != lex_try_fetch(lex, "ROW", &result)) {
            return CT_ERROR;
        }

        if (result) {
            CT_RETURN_IFERR(lex_expected_fetch_word(lex, "MOVEMENT"));
            def->action = ALTABLE_ENABLE_ROW_MOVE;
            return lex_expected_end(lex);
        }

        if (CT_SUCCESS != sql_parse_enable_disable_clause(stmt, word, lex, def)) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_parse_altable_disable_partition(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def,
    bool32 *disable_part)
{
    word_t word;
    uint32 match_id;

    CT_RETURN_IFERR(lex_try_fetch_1of2(lex, "PARTITION", "SUBPARTITION", &match_id));
    if (match_id == CT_INVALID_ID32) {
        *disable_part = CT_FALSE;
        return CT_SUCCESS;
    }

    *disable_part = CT_TRUE;
    if (match_id == 0) {
        def->action = ALTABLE_DISABLE_PART_NOLOGGING;
    } else {
        def->action = ALTABLE_DISABLE_SUBPART_NOLOGGING;
    }

    CT_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));
    CT_RETURN_IFERR(sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->part_def.name));
    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "NOLOGGING"));
    return lex_expected_end(lex);
}

static status_t sql_parse_altable_disable(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_altable_def_t *def)
{
    bool32 result = CT_FALSE;
    bool32 disable_part = CT_FALSE;

    CT_RETURN_IFERR(sql_parse_altable_disable_partition(stmt, lex, def, &disable_part));
    if (disable_part) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(lex_try_fetch(lex, "NOLOGGING", &result));
    if (result) {
        def->action = ALTABLE_DISABLE_NOLOGGING;
        return lex_expected_end(lex);
    }

    CT_RETURN_IFERR(lex_try_fetch(lex, "ALL", &result));

    if (result) {
        CT_RETURN_IFERR(lex_expected_fetch_word(lex, "TRIGGERS"));
        def->action = ALTABLE_DISABLE_ALL_TRIG;
    } else {
        if (CT_SUCCESS != lex_try_fetch(lex, "ROW", &result)) {
            return CT_ERROR;
        }

        if (result) {
            CT_RETURN_IFERR(lex_expected_fetch_word(lex, "MOVEMENT"));
            def->action = ALTABLE_DISABLE_ROW_MOVE;
            return lex_expected_end(lex);
        }

        if (CT_SUCCESS != sql_parse_enable_disable_clause(stmt, word, lex, def)) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_try_parse_shrink_timeout(lex_t *lex, uint32 *shrink_timeout)
{
    bool32 result = CT_FALSE;
    word_t word;

    if (lex_try_fetch(lex, "TIMEOUT", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!result) {
        return CT_SUCCESS;
    }

    if (lex_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type != WORD_TYPE_NUMBER) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "number expected but %s found", W2S(&word));
        return CT_ERROR;
    }

    if (cm_text2uint32((text_t *)&word.text, shrink_timeout) != CT_SUCCESS) {
        cm_reset_error();
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "the number must be an integer between 1 and 4294967294");
        return CT_ERROR;
    }

    if (*shrink_timeout >= LOCK_INF_WAIT || *shrink_timeout == 0) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "the number must be an integer between 1 and 4294967294");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_parse_shrink_parameter(lex_t *lex, uint32 *num, uint32 *shrink_timeout)
{
    bool32 result = CT_FALSE;
    word_t word;

    if (lex_try_fetch(lex, "PERCENT", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (result) {
        if (lex_fetch(lex, &word) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (word.type == WORD_TYPE_NUMBER) {
            if (cm_text2uint32((text_t *)&word.text, num) != CT_SUCCESS) {
                cm_reset_error();
                CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "the number must be an integer between 1 and 100");
                return CT_ERROR;
            }
            if (*num > CT_MAX_SHRINK_PERCENT || *num < CT_MIN_SHRINK_PERCENT) {
                CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "the number must be an integer between 1 and 100");
                return CT_ERROR;
            }
        } else {
            CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "number expected but %s found", W2S(&word));
            return CT_ERROR;
        }
    } else if (sql_try_parse_shrink_timeout(lex, shrink_timeout) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_parse_shrink_clause(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def)
{
    bool32 result = CT_FALSE;
    uint32 num = 100; // shrink 100% by default
    uint32 shrink_timeout = 0;

    if (lex_expected_fetch_word(lex, "SPACE") != CT_SUCCESS) {
        return CT_ERROR;
    }

    def->table_def.shrink_opt = SHRINK_SPACE;

    if (lex_try_fetch(lex, "COMPACT", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (result) {
        def->table_def.shrink_opt |= SHRINK_COMPACT;
    }

    if (lex_try_fetch(lex, "CASCADE", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (result) {
        def->table_def.shrink_opt |= SHRINK_CASCADE;
    }

    if (sql_parse_shrink_parameter(lex, &num, &shrink_timeout) != CT_SUCCESS) {
        return CT_ERROR;
    }

    def->table_def.shrink_percent = num;
    def->table_def.shrink_timeout = shrink_timeout;
    def->action = ALTABLE_SHRINK;

    return lex_expected_end(lex);
}


status_t sql_verify_table_storage(sql_stmt_t *stmt, knl_table_def_t *def)
{
    // check table type, not suppport for temprory table
    if (def->storage_def.initial > 0 || def->storage_def.maxsize) {
        if (def->type != TABLE_TYPE_HEAP && def->type != TABLE_TYPE_NOLOGGING) {
            CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "storage option without heap table");
            return CT_ERROR;
        }
    }

    // check table storage, initial should not large than maxsize
    if (def->storage_def.initial > 0 && def->storage_def.maxsize > 0 &&
        (def->storage_def.initial > def->storage_def.maxsize)) {
        CT_THROW_ERROR(ERR_EXCEED_SEGMENT_MAXSIZE);
        return CT_ERROR;
    }

    if (!def->parted || def->part_def == NULL) {
        return CT_SUCCESS;
    }

    knl_part_def_t *part_def = NULL;
    int64 initial;
    int64 maxsize;

    // check partition storage, initial should not large than maxsize
    for (uint32 i = 0; i < def->part_def->parts.count; i++) {
        part_def = (knl_part_def_t *)cm_galist_get(&def->part_def->parts, i);
        initial = (part_def->storage_def.initial > 0) ? (part_def->storage_def.initial) : def->storage_def.initial;
        maxsize = (part_def->storage_def.maxsize > 0) ? (part_def->storage_def.maxsize) : def->storage_def.maxsize;

        if (initial > 0 && maxsize > 0 && (initial > maxsize)) {
            CT_THROW_ERROR(ERR_EXCEED_SEGMENT_MAXSIZE);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t sql_parse_as_select(sql_stmt_t *stmt, knl_table_def_t *def)
{
    sql_select_t *select_ctx = NULL;
    lex_t *lex = stmt->session->lex;

    // parse select clause
    CT_RETURN_IFERR(sql_create_select_context(stmt, lex->curr_text, SELECT_AS_VALUES, &select_ctx));
    stmt->context->supplement = (void *)select_ctx;

    CT_RETURN_IFERR(sql_verify_select(stmt, select_ctx));

    // 1.check whether columns in select clause match that in column definition clause
    // 2.when with no column definition clause, make sure all result column has an alias
    CT_RETURN_IFERR(sql_verify_columns(stmt, def));

    def->create_as_select = CT_TRUE;
    return CT_SUCCESS;
}

status_t sql_parse_create_table(sql_stmt_t *stmt, bool32 is_temp, bool32 has_global)
{
    word_t word;
    knl_table_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;
    bool32 result = CT_FALSE;
    bool32 expect_as = CT_FALSE;
    bool32 external_table = CT_FALSE;

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_table_def_t), (pointer_t *)&def));

    def->sysid = CT_INVALID_ID32;
    stmt->context->type = CTSQL_TYPE_CREATE_TABLE;
    lex->flags |= LEX_WITH_OWNER;

    CT_RETURN_IFERR(sql_try_parse_if_not_exists(lex, &def->options));
    CT_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));

    def->type = is_temp ? TABLE_TYPE_TRANS_TEMP : TABLE_TYPE_HEAP;
    CT_RETURN_IFERR(sql_convert_object_name(stmt, &word, &def->schema, NULL, &def->name));
    if (is_temp && !has_global) {
        if (!stmt->session->knl_session.kernel->attr.enable_ltt) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                "parameter LOCAL_TEMPORARY_TABLE_ENABLED is false, can't create local temporary table");
            return CT_ERROR;
        }

        if (!knl_is_llt_by_name2(def->name.str[0])) {
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
                "local temporary table name should start with '#'");
            return CT_ERROR;
        }

    } else {
        if (knl_is_llt_by_name(def->name.str[0])) {
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "table name is invalid");
            return CT_ERROR;
        }
    }

    if (sql_table_has_special_char(&def->name)) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid variant/object name was found");
        return CT_ERROR;
    }

    cm_galist_init(&def->columns, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->constraints, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->indexs, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->lob_stores, stmt->context, sql_alloc_mem);

    CT_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));
    if (result) {
        if (word.text.len == 0) {
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "column definitions expected");
            return CT_ERROR;
        }
        CT_RETURN_IFERR(lex_push(lex, &word.text));
        status_t status = sql_parse_column_defs(stmt, lex, def, &expect_as);
        lex_pop(lex);
        CT_RETURN_IFERR(status);
    }

    CT_RETURN_IFERR(lex_try_fetch(lex, "organization", &external_table));
    if (external_table) {
        if (def->type == TABLE_TYPE_TRANS_TEMP || def->type == TABLE_TYPE_SESSION_TEMP) {
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "cannot specify TEMPORARY on external table");
            return CT_ERROR;
        }

        def->type = TABLE_TYPE_EXTERNAL;
        if (sql_check_organization_column(def) != CT_SUCCESS) {
            return CT_ERROR;
        }

        CT_RETURN_IFERR(sql_parse_organization(stmt, lex, &word, &def->external_def));
    } else {
        CT_RETURN_IFERR(sql_parse_table_attrs(stmt, lex, def, &expect_as, &word));
    }

    // syntax:1.create table (...) as select; 2.create table as select
    if (word.id == KEY_WORD_AS) {
        CT_RETURN_IFERR(sql_parse_as_select(stmt, def));
    } else if (!result || expect_as) {
        // when column is not defined, as-select clause must appear
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "As-select clause expected");
        return CT_ERROR;
    }
    // column type may be known after as-select parsed, so delay check partition table type
    CT_RETURN_IFERR(sql_delay_verify_part_attrs(stmt, def, &expect_as, &word));
    // column type may be known after as-select parsed, so delay check default/default on update verifying
    CT_RETURN_IFERR(sql_delay_verify_default(stmt, def));

    // column type may be known after as-select parsed, so delay check constraint verifying
    CT_RETURN_IFERR(sql_verify_check_constraint(stmt, def));
    CT_RETURN_IFERR(sql_create_inline_cons(stmt, def));

    CT_RETURN_IFERR(sql_verify_cons_def(def));
    CT_RETURN_IFERR(sql_verify_auto_increment(stmt, def));
    CT_RETURN_IFERR(sql_verify_array_columns(def->type, &def->columns));

    CT_RETURN_IFERR(sql_verify_table_storage(stmt, def));

    stmt->context->entry = def;
    return CT_SUCCESS;
}

status_t sql_create_temporary_lead(sql_stmt_t *stmt)
{
    word_t word;

    if (lex_fetch(stmt->session->lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.id == KEY_WORD_TABLESPACE) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create temporary lead ", "temporary tablespace");
        return CT_ERROR;
    } else if (word.id == KEY_WORD_TABLE) {
        // create temporary table: local temp table
        return sql_parse_create_table(stmt, CT_TRUE, CT_FALSE);
    } else {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "TABLE or TABLESPACE expected but %s found", W2S(&word));
        return CT_ERROR;
    }
}

status_t sql_create_global_lead(sql_stmt_t *stmt)
{
    word_t word;
    if (lex_fetch(stmt->session->lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.id != KEY_WORD_TEMPORARY) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "TEMPORARY expected but %s found", W2S(&word));
        return CT_ERROR;
    }

    if (lex_fetch(stmt->session->lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.id == KEY_WORD_TABLE) {
        return sql_parse_create_table(stmt, CT_TRUE, CT_TRUE);
    } else {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "TABLE expected but %s found", W2S(&word));
        return CT_ERROR;
    }
}

status_t sql_parse_drop_table(sql_stmt_t *stmt, bool32 is_temp)
{
    lex_t *lex = stmt->session->lex;
    knl_drop_def_t *def = NULL;
    bool32 is_cascade = CT_FALSE;
    knl_dictionary_t dc;
    bool32 if_exists;
    lex->flags = LEX_WITH_OWNER;
    dc.type = DICT_TYPE_TABLE;
    stmt->context->type = CTSQL_TYPE_DROP_TABLE;

    if (sql_alloc_mem(stmt->context, sizeof(knl_drop_def_t), (void **)&def) != CT_SUCCESS) {
        return CT_ERROR;
    }
    def->temp = is_temp;
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

    if (lex_try_fetch(stmt->session->lex, "PURGE", &def->purge) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}

status_t sql_parse_drop_temporary_lead(sql_stmt_t *stmt)
{
    word_t word;

    if (lex_fetch(stmt->session->lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (word.id != KEY_WORD_TABLE) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "TABLE expected but %s found", W2S(&word));
        return CT_ERROR;
    }
    return sql_parse_drop_table(stmt, CT_TRUE);
}

status_t sql_regist_ddl_table(sql_stmt_t *stmt, text_t *user, text_t *name)
{
    uint32 i;
    sql_table_entry_t *table = NULL;
    knl_handle_t knl = &stmt->session->knl_session;
    sql_context_t *context = stmt->context;

    for (i = 0; i < context->tables->count; i++) {
        table = (sql_table_entry_t *)cm_galist_get(context->tables, i);
        if (cm_text_equal(&table->name, name) && cm_text_equal(&table->user, user)) {
            return CT_SUCCESS;
        }
    }

    if (cm_galist_new(context->tables, sizeof(sql_table_entry_t), (pointer_t *)&table) != CT_SUCCESS) {
        return CT_ERROR;
    }

    table->name = *name;
    table->user = *user;

    knl_set_session_scn(knl, CT_INVALID_ID64);
    if (CT_SUCCESS != knl_open_dc(knl, user, name, &(table->dc))) {
        // if open dc failed for table,remove this table from table lists.
        sql_check_user_priv(stmt, user);
        context->tables->count--;
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_parse_alter_table(sql_stmt_t *stmt)
{
    status_t status;
    word_t word;
    bool32 result = CT_FALSE;
    lex_t *lex = stmt->session->lex;
    knl_altable_def_t *altable_def = NULL;

    lex->flags |= LEX_WITH_OWNER;
    stmt->context->type = CTSQL_TYPE_ALTER_TABLE;

    status = sql_alloc_mem(stmt->context, sizeof(knl_altable_def_t), (void **)&altable_def);
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch_variant(lex, &word);
    CT_RETURN_IFERR(status);

    status = sql_convert_object_name(stmt, &word, &altable_def->user, NULL, &altable_def->name);
    CT_RETURN_IFERR(status);

    if (IS_LTT_BY_NAME(altable_def->name.str)) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "alter table", "ltt(local temporary table)");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));
    if (result) {
        if (word.text.len == 0) {
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "partitions expected");
            return CT_ERROR;
        }

        cm_galist_init(&altable_def->logical_log_def.parts, stmt->context, sql_alloc_mem);
        CT_RETURN_IFERR(lex_push(lex, &word.text));
        status = sql_parse_altable_partition(stmt, &word, altable_def);
        lex_pop(lex);
        CT_RETURN_IFERR(status);
    }

    status = lex_fetch(stmt->session->lex, &word);
    CT_RETURN_IFERR(status);

    status = sql_regist_ddl_table(stmt, &altable_def->user, &altable_def->name);
    CT_RETURN_IFERR(status);

    if (altable_def->logical_log_def.is_parts_logical == CT_TRUE && word.id != KEY_WORD_ADD) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "add expected but %s found", W2S(&word));
        return CT_ERROR;
    }

    switch ((key_wid_t)word.id) {
        case KEY_WORD_ADD:
            status = sql_parse_altable_add(stmt, lex, altable_def);
            break;

        case KEY_WORD_MODIFY:
            status = sql_parse_altable_modify(stmt, lex, altable_def);
            break;

        case KEY_WORD_DROP:
            status = sql_parse_altable_drop(stmt, lex, altable_def);
            break;

        case KEY_WORD_RENAME:
            status = sql_parse_altable_rename(stmt, lex, altable_def);
            break;

        case KEY_WORD_PCTFREE:
            altable_def->table_def.pctfree = CT_INVALID_ID32;
            altable_def->action = ALTABLE_TABLE_PCTFREE;
            status = sql_parse_pctfree(lex, &word, &altable_def->table_def.pctfree);
            CT_BREAK_IF_ERROR(status);
            status = lex_expected_end(lex);
            break;

        case KEY_WORD_INITRANS:
            altable_def->action = ALTABLE_TABLE_INITRANS;
            status = sql_parse_trans(lex, &word, &altable_def->table_def.initrans);
            CT_BREAK_IF_ERROR(status);
            status = lex_expected_end(lex);
            break;

        case KEY_WORD_STORAGE:
            altable_def->action = ALTABLE_MODIFY_STORAGE;
            status = sql_parse_storage(lex, &word, &altable_def->table_def.storage_def, CT_TRUE);
            break;

        case KEY_WORD_APPENDONLY:
            altable_def->action = ALTABLE_APPENDONLY;
            status = sql_parse_appendonly(lex, &word, &altable_def->table_def.appendonly);
            CT_BREAK_IF_ERROR(status);
            status = lex_expected_end(lex);
            break;

        case KEY_WORD_TRUNCATE:
            status = sql_parse_altable_truncate(stmt, lex, altable_def);
            break;

        case KEY_WORD_ENABLE:
            status = sql_parse_altable_enable(stmt, lex, &word, altable_def);
            break;

        case KEY_WORD_DISABLE:
            status = sql_parse_altable_disable(stmt, lex, &word, altable_def);
            break;

        case KEY_WORD_SHRINK:
            status = sql_parse_shrink_clause(stmt, lex, altable_def);
            break;

        case KEY_WORD_SET:
            status = sql_parse_altable_set_clause(stmt, lex, &word, altable_def);
            break;

        case KEY_WORD_AUTO_INCREMENT:
            status = sql_parse_check_auto_increment(stmt, &word, altable_def);
            CT_BREAK_IF_ERROR(status);
            altable_def->action = ALTABLE_AUTO_INCREMENT;
            status = sql_parse_init_auto_increment(stmt, lex, (int64 *)&altable_def->table_def.serial_start);
            CT_BREAK_IF_ERROR(status);
            status = lex_expected_end(lex);
            break;

        case KEY_WORD_COALESCE:
            altable_def->action = ALTABLE_COALESCE_PARTITION;
            status = sql_parse_coalesce_partition(stmt, lex, altable_def);
            break;

        case KEY_WORD_SPLIT:
            altable_def->action = ALTABLE_SPLIT_PARTITION;
            status = sql_parse_split_partition(stmt, lex, altable_def);
            break;

        default:
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(&word));
            return CT_ERROR;
    }

    stmt->context->entry = altable_def;
    return status;
}

status_t sql_parse_analyze_table(sql_stmt_t *stmt)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    knl_analyze_tab_def_t *def = NULL;
    bool32 result = CT_FALSE;
    status_t status;
    uint32 sample_ratio = 0;

    lex->flags |= LEX_WITH_OWNER;
    stmt->context->type = CTSQL_TYPE_ANALYSE_TABLE;

    if (sql_alloc_mem(stmt->context, sizeof(knl_analyze_tab_def_t), (void **)&def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_convert_object_name(stmt, &word, &def->owner, NULL, &def->name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "COMPUTE") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "STATISTICS") != CT_SUCCESS) {
        return CT_ERROR;
    }

    status = lex_try_fetch(lex, "for", &result);
    CT_RETURN_IFERR(status);

    if (result) {
        if (lex_expected_fetch_word(lex, "report") != CT_SUCCESS) {
            return CT_ERROR;
        }

        def->is_report = CT_TRUE;

        if (lex_try_fetch(lex, "sample", &result) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (result) {
            if (lex_expected_fetch_uint32(lex, &sample_ratio) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (sample_ratio > MAX_SAMPLE_RATIO) {
                CT_SRC_THROW_ERROR(word.text.loc, ERR_INVALID_FUNC_PARAMS,
                    "the valid range of estimate_percent is [0,100]");
            }

            def->sample_ratio = sample_ratio;
            def->sample_type = STATS_SPECIFIED_SAMPLE;
        }
    }

    stmt->context->entry = def;
    return lex_expected_end(lex);
}

status_t sql_parse_truncate_table(sql_stmt_t *stmt)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    knl_trunc_def_t *def = NULL;
    knl_dictionary_t dc;
    dc.type = DICT_TYPE_TABLE;
    lex->flags |= LEX_WITH_OWNER;
    stmt->context->type = CTSQL_TYPE_TRUNCATE_TABLE;

    if (sql_alloc_mem(stmt->context, sizeof(knl_trunc_def_t), (void **)&def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    stmt->context->entry = def;

    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_convert_object_name(stmt, &word, &def->owner, NULL, &def->name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_parse_truncate_option(stmt, &word, &def->option) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (knl_open_dc_with_public(&stmt->session->knl_session, &def->owner, CT_TRUE, &def->name, &dc) != CT_SUCCESS) {
        cm_reset_error_user(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&def->owner), T2S_EX(&def->name), ERR_TYPE_TABLE_OR_VIEW);
        sql_check_user_priv(stmt, &def->owner);
        return CT_ERROR;
    }
    knl_close_dc(&dc);
    return lex_expected_end(lex);
}

static status_t sql_parse_flashback_recyclebin(sql_stmt_t *stmt, knl_flashback_def_t *def, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    bool32 result = CT_FALSE;
    status_t status;

    def->force = CT_FALSE;

    status = lex_expected_fetch(lex, word);
    CT_RETURN_IFERR(status);

    switch ((key_wid_t)word->id) {
        case KEY_WORD_DROP:

            status = lex_try_fetch(lex, "RENAME", &result);
            CT_RETURN_IFERR(status);

            if (result) {
                status = lex_expected_fetch_word(lex, "TO");
                CT_RETURN_IFERR(status);

                status = lex_expected_fetch_variant(lex, word);
                CT_RETURN_IFERR(status);

                status = sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &def->ext_name);
                CT_RETURN_IFERR(status);
            } else {
                def->ext_name.len = 0;
                def->ext_name.str = NULL;
            }

            if (def->type != FLASHBACK_INVALID_TYPE) {
                CT_THROW_ERROR(ERR_FLASHBACK_NO_SUPPORT);
                return CT_ERROR;
            }

            def->type = FLASHBACK_DROP_TABLE;
            break;

        case KEY_WORD_TRUNCATE:
            status = lex_try_fetch(lex, "FORCE", &result);
            CT_RETURN_IFERR(status);

            if (result) {
                def->force = CT_TRUE;
            }

            if (def->type == FLASHBACK_INVALID_TYPE) {
                def->type = FLASHBACK_TRUNCATE_TABLE;
            }
            break;

        default:
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "object type expected but %s found", W2S(word));
            return CT_ERROR;
    }

    return lex_fetch(lex, word);
}

static status_t sql_parse_table_version(sql_stmt_t *stmt, expr_tree_t **expr, bool32 scn_type, word_t *word)
{
    sql_array_t ssa;
    sql_verifier_t verf = { 0 };
    ct_type_t expr_type;
    uint32 flags;

    flags = stmt->session->lex->flags;
    stmt->session->lex->flags = LEX_WITH_ARG;

    CT_RETURN_IFERR(sql_create_array(stmt->context, &ssa, "SUB-SELECT", CT_MAX_SUBSELECT_EXPRS));
    CT_RETURN_IFERR(SQL_SSA_PUSH(stmt, &ssa));
    if (sql_create_expr_until(stmt, expr, word) != CT_SUCCESS) {
        SQL_SSA_POP(stmt);
        return CT_ERROR;
    }

    SQL_SSA_POP(stmt);

    if (ssa.count > 0) {
        CT_THROW_ERROR(ERR_UNEXPECTED_KEY, "SUBSELECT here");
        return CT_ERROR;
    }
    verf.context = stmt->context;
    verf.stmt = stmt;
    verf.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_COLUMN | SQL_EXCL_STAR | SQL_EXCL_SEQUENCE | SQL_EXCL_SUBSELECT |
        SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_ROWSCN | SQL_EXCL_WIN_SORT |
        SQL_EXCL_ROWNODEID;

    if (sql_verify_expr(&verf, *expr) != CT_SUCCESS) {
        return CT_ERROR;
    }

    expr_type = TREE_DATATYPE(*expr);
    if (scn_type) {
        if (!CT_IS_WEAK_NUMERIC_TYPE(expr_type)) {
            CT_SET_ERROR_MISMATCH(CT_TYPE_BIGINT, expr_type);
            return CT_ERROR;
        }
    } else {
        if (!CT_IS_DATETIME_TYPE(expr_type)) {
            CT_SET_ERROR_MISMATCH(CT_TYPE_TIMESTAMP, expr_type);
            return CT_ERROR;
        }
    }

    stmt->session->lex->flags = flags;
    return CT_SUCCESS;
}

status_t sql_parse_flashback_table(sql_stmt_t *stmt)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    knl_flashback_def_t *def = NULL;
    bool32 result = CT_FALSE;
    uint32 match_id;

    lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;
    stmt->context->type = CTSQL_TYPE_FLASHBACK_TABLE;

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_flashback_def_t), (void **)&def));

    CT_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));

    CT_RETURN_IFERR(sql_convert_object_name(stmt, &word, &def->owner, NULL, &def->name));

    stmt->context->entry = def;
    def->type = FLASHBACK_INVALID_TYPE;

    CT_RETURN_IFERR(lex_try_fetch_1of2(lex, "PARTITION", "SUBPARTITION", &match_id));
    if (match_id != CT_INVALID_ID32) {
        CT_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));
        CT_RETURN_IFERR(sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->ext_name));
        def->type = ((match_id == LEX_MATCH_FIRST_WORD) ? FLASHBACK_TABLE_PART : FLASHBACK_TABLE_SUBPART);
    }

    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "TO"));

    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
        CT_RETURN_IFERR(lex_try_fetch(lex, "SCN", &result));
        if (result) {
            CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "Flashback table to SCN on coordinator is");
            return CT_ERROR;
        }
        CT_RETURN_IFERR(lex_expected_fetch_1of2(lex, "TIMESTAMP", "BEFORE", &match_id));
        match_id++;
    } else {
        CT_RETURN_IFERR(lex_expected_fetch_1of3(lex, "SCN", "TIMESTAMP", "BEFORE", &match_id));
    }

    if (match_id == LEX_MATCH_FIRST_WORD) {
        CT_RETURN_IFERR(sql_parse_table_version(stmt, (expr_tree_t **)&def->expr, CT_TRUE, &word));

        if (def->type != FLASHBACK_INVALID_TYPE) {
            CT_THROW_ERROR(ERR_FLASHBACK_NO_SUPPORT);
            return CT_ERROR;
        }

        def->type = FLASHBACK_TO_SCN;
    } else if (match_id == LEX_MATCH_SECOND_WORD) {
        CT_RETURN_IFERR(sql_parse_table_version(stmt, (expr_tree_t **)&def->expr, CT_FALSE, &word));

        if (def->type != FLASHBACK_INVALID_TYPE) {
            CT_THROW_ERROR(ERR_FLASHBACK_NO_SUPPORT);
            return CT_ERROR;
        }

        def->type = FLASHBACK_TO_TIMESTAMP;
    } else {
        CT_RETURN_IFERR(sql_parse_flashback_recyclebin(stmt, def, &word));
    }

    if (word.type != WORD_TYPE_EOF) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "text end expected but %s found", W2S(&word));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_parse_purge_table(sql_stmt_t *stmt, knl_purge_def_t *def)
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

        status = sql_convert_object_name(stmt, &word, &def->owner, NULL, &def->name);
        CT_RETURN_IFERR(status);

        def->type = PURGE_TABLE_OBJECT;

        return lex_expected_end(lex);
    }

    status = sql_convert_object_name(stmt, &word, &def->owner, NULL, &def->name);
    CT_RETURN_IFERR(status);

    status = lex_try_fetch(lex, "PARTITION", &result);
    CT_RETURN_IFERR(status);

    if (result) {
        lex->flags = LEX_SINGLE_WORD;
        status = lex_expected_fetch_variant(lex, &word);
        CT_RETURN_IFERR(status);

        status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->part_name);
        CT_RETURN_IFERR(status);

        def->type = PURGE_PART;
    } else {
        def->type = PURGE_TABLE;
    }

    return lex_expected_end(lex);
}

static status_t sql_verify_comment_def(sql_stmt_t *stmt, knl_comment_def_t *comment_def)
{
    status_t status;
    knl_dictionary_t dc;

    status = knl_open_dc(KNL_SESSION(stmt), &comment_def->owner, &comment_def->name, &dc);
    if (status != CT_SUCCESS) {
        sql_check_user_priv(stmt, &comment_def->owner);
        return CT_ERROR;
    }

    if (dc.type > DICT_TYPE_VIEW) {
        CT_THROW_ERROR(ERR_COMMENT_OBJECT_TYPE, T2S(&comment_def->owner), T2S_EX(&comment_def->name));
        knl_close_dc(&dc);
        return CT_ERROR;
    }

    comment_def->uid = dc.uid;
    comment_def->id = dc.oid;

    if (comment_def->type == COMMENT_ON_COLUMN) {
        uint32 i, natts;
        natts = knl_get_column_count(dc.handle);

        for (i = 0; i < natts; i++) {
            knl_column_t *column = knl_get_column(dc.handle, i);

            if (KNL_COLUMN_INVISIBLE(column)) {
                /* it doesn't make any sense for the attempt to comment on a deleted/hidden column */
                continue;
            }

            if (cm_text_str_equal(&comment_def->column, column->name)) {
                comment_def->column_id = column->id;
                break;
            }
        }

        if (i == natts) {
            knl_close_dc(&dc);
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "%s: invalid identifier", T2S(&comment_def->column));
            return CT_ERROR;
        }
    }
    knl_close_dc(&dc);

    return CT_SUCCESS;
}


static inline status_t sql_convert_column_name(sql_stmt_t *stmt, word_t *word, text_t *owner, text_t *name,
    text_t *column)
{
    if (word->ex_count == 2) {
        if (sql_copy_prefix_tenant(stmt, (text_t *)&word->text, owner, sql_copy_name) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (sql_copy_object_name(stmt->context, word->ex_words[0].type, (text_t *)&word->ex_words[0].text, name) !=
            CT_SUCCESS) {
            return CT_ERROR;
        }

        if (sql_copy_object_name(stmt->context, word->ex_words[1].type, (text_t *)&word->ex_words[1].text, column) !=
            CT_SUCCESS) {
            return CT_ERROR;
        }
    } else if (word->ex_count == 1) {
        cm_str2text(stmt->session->curr_schema, owner);
        if (sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, name) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (sql_copy_object_name(stmt->context, word->ex_words[0].type, (text_t *)&word->ex_words[0].text, column) !=
            CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid column name");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_parse_comment_table(sql_stmt_t *stmt, key_wid_t wid)
{
    status_t status;
    word_t word;
    lex_t *lex = stmt->session->lex;
    knl_comment_def_t *def = NULL;

    status = sql_alloc_mem(stmt->context, sizeof(knl_comment_def_t), (void **)&def);
    CT_RETURN_IFERR(status);

    def->type = (wid == KEY_WORD_TABLE ? COMMENT_ON_TABLE : COMMENT_ON_COLUMN);
    lex->flags = LEX_WITH_OWNER;

    status = lex_expected_fetch_variant(lex, &word);
    CT_RETURN_IFERR(status);

    switch (def->type) {
        case COMMENT_ON_TABLE:
            status = sql_convert_object_name(stmt, &word, &def->owner, NULL, &def->name);
            CT_RETURN_IFERR(status);
            break;
        case COMMENT_ON_COLUMN:
            status = sql_convert_column_name(stmt, &word, &def->owner, &def->name, &def->column);
            CT_RETURN_IFERR(status);
            break;
        default:
            return CT_ERROR;
    }

    status = lex_expected_fetch_word(lex, "IS");
    CT_RETURN_IFERR(status);
    status = lex_expected_fetch_string(lex, &word);
    CT_RETURN_IFERR(status);

    if (word.text.value.len != 0) {
        if (word.text.value.len > DDL_MAX_COMMENT_LEN) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "comment content cannot exceed 4000 bytes");
            return CT_ERROR;
        }
        status = sql_copy_text_remove_quotes(stmt->context, (text_t *)&word.text, &def->comment);
        CT_RETURN_IFERR(status);
    } else {
        def->comment.str = (g_instance->sql.enable_empty_string_null == CT_TRUE) ? NULL : "";
    }

    status = lex_expected_end(lex);
    CT_RETURN_IFERR(status);

    status = sql_verify_comment_def(stmt, def);
    CT_RETURN_IFERR(status);

    stmt->context->entry = def;
    return CT_SUCCESS;
}

status_t sql_check_partition_exist(galist_t *parts, dc_entity_t *dc_entity)
{
    uint32 i;
    uint32 part_no;
    uint32 subpart_no;
    knl_part_def_t *part_def = NULL;

    for (i = 0; i < parts->count; i++) {
        part_def = (knl_part_def_t *)cm_galist_get(parts, i);
        if (knl_find_table_part_by_name(dc_entity, &part_def->name, &part_no) != CT_SUCCESS) {
            cm_reset_error();
            if (knl_find_subpart_by_name(dc_entity, &part_def->name, &part_no, &subpart_no) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }
    return CT_SUCCESS;
}

status_t sql_verify_alter_table_logical_parts(sql_stmt_t *stmt)
{
    status_t status;
    knl_dictionary_t dc;
    dc_entity_t *entity = NULL;
    knl_altable_def_t *def = (knl_altable_def_t *)stmt->context->entry;

    if (def->logical_log_def.is_parts_logical == CT_FALSE || def->action != ALTABLE_ADD_LOGICAL_LOG) {
        return CT_SUCCESS;
    }
    if (knl_open_dc(&(stmt->session->knl_session), &def->user, &def->name, &dc) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&def->user), T2S_EX(&def->name));
        return CT_ERROR;
    }
    entity = DC_ENTITY(&dc);
    if (entity == NULL) {
        CT_THROW_ERROR(ERR_INVALID_DC, T2S_EX(&def->name));
        return CT_ERROR;
    }

    if (!knl_is_part_table(entity)) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not partition table", T2S(&def->name));
        knl_close_dc(&dc);
        return CT_ERROR;
    }

    status = sql_check_partition_exist(&def->logical_log_def.parts, entity);
    knl_close_dc(&dc);
    CT_RETURN_IFERR(status);
    return CT_SUCCESS;
}

status_t sql_verify_alter_table(sql_stmt_t *stmt)
{
    status_t status;
    status = sql_verify_alter_table_logical_parts(stmt);
    CT_RETURN_IFERR(status);
    return CT_SUCCESS;
}
