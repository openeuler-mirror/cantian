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
 * ddl_parser_common.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_parser_common.c
 *
 * -------------------------------------------------------------------------
 */

#include "ddl_parser_common.h"


/*
 * @Note: if the caller wants to know if the owner(schema) was explicitly specified by user,
 * the caller should pass a pointer to a bool32 variable as the optional argument "owner_explict"
 * otherwise, a NULL is enough
 */
status_t sql_convert_object_name(sql_stmt_t *stmt, word_t *word, text_t *owner, bool32 *owner_explict, text_t *name)
{
    bool32 is_explict = CT_TRUE;
    sql_copy_func_t sql_copy_func;
    if (IS_COMPATIBLE_MYSQL_INST) {
        sql_copy_func = sql_copy_name_cs;
    } else {
        sql_copy_func = sql_copy_name;
    }

    if (word->ex_count == 1) {
        if (sql_copy_prefix_tenant(stmt, (text_t *)&word->text, owner, sql_copy_func) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (sql_copy_object_name(stmt->context, word->ex_words[0].type, (text_t *)&word->ex_words[0].text, name) !=
            CT_SUCCESS) {
            return CT_ERROR;
        }
    } else if (word->ex_count == 0) {
        cm_str2text(stmt->session->curr_schema, owner);
        is_explict = CT_FALSE;
        if (sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, name) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid name");
        return CT_ERROR;
    }

    if (owner_explict != NULL) {
        *owner_explict = is_explict;
    }

    return CT_SUCCESS;
}

status_t sql_try_parse_if_not_exists(lex_t *lex, uint32 *options)
{
    bool32 result = CT_FALSE;

    if (lex_try_fetch(lex, "IF", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (result) {
        if (lex_expected_fetch_word(lex, "NOT") != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (lex_expected_fetch_word(lex, "EXISTS") != CT_SUCCESS) {
            return CT_ERROR;
        }

        *options |= CREATE_IF_NOT_EXISTS;
    }

    return CT_SUCCESS;
}


status_t sql_try_parse_if_exists(lex_t *lex, uint32 *options)
{
    bool32 result = CT_FALSE;

    if (lex_try_fetch(lex, "IF", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (result) {
        if (lex_expected_fetch_word(lex, "EXISTS") != CT_SUCCESS) {
            return CT_ERROR;
        }

        *options |= DROP_IF_EXISTS;
    }

    return CT_SUCCESS;
}

status_t sql_parse_drop_object(sql_stmt_t *stmt, knl_drop_def_t *def)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    lex->flags = LEX_WITH_OWNER;

    if (sql_try_parse_if_exists(lex, &def->options) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_convert_object_name(stmt, &word, &def->owner, NULL, &def->name) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_parse_parallelism(lex_t *lex, word_t *word, uint32 *parallelism, int32 max_parallelism)
{
    int32 tmp_size;

#ifdef Z_SHARDING
    if (IS_COORDINATOR) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create index parallel", "coordinator mode");
        return CT_ERROR;
    }
#endif

    if (*parallelism != 0) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate %s specification", W2S(word));
        return CT_ERROR;
    }

    if (lex_expected_fetch_int32(lex, &tmp_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (tmp_size <= 0 || tmp_size > max_parallelism) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "%s must between 1 and %d ", W2S(word),
            max_parallelism);
        return CT_ERROR;
    }

    *parallelism = (uint32)tmp_size;

    return CT_SUCCESS;
}

status_t sql_parse_reverse(word_t *word, bool32 *is_reverse)
{
#ifdef Z_SHARDING
    if (IS_COORDINATOR) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create reverse index", "coordinator mode");
        return CT_ERROR;
    }
#endif

    if (*is_reverse) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate %s specification", W2S(word));
        return CT_ERROR;
    }

    *is_reverse = CT_TRUE;

    return CT_SUCCESS;
}

status_t sql_parse_trans(lex_t *lex, word_t *word, uint32 *trans)
{
    int32 tmp_size;

    if (*trans != 0) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate %s specification", W2S(word));
        return CT_ERROR;
    }

    if (lex_expected_fetch_int32(lex, &tmp_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (tmp_size <= 0 || tmp_size > CT_MAX_TRANS) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "%s must between 1 and %d ", W2S(word),
            CT_MAX_TRANS);
        return CT_ERROR;
    }

    *trans = (uint32)tmp_size;

    return CT_SUCCESS;
}

status_t sql_parse_crmode(lex_t *lex, word_t *word, uint8 *cr_mode)
{
    uint32 match_id;

    if (*cr_mode != CT_INVALID_ID8) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate %s specification", W2S(word));
        return CT_ERROR;
    }

    if (lex_expected_fetch_1of2(lex, "ROW", "PAGE", &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *cr_mode = (match_id == 0) ? (uint8)CR_ROW : (uint8)CR_PAGE;

    return CT_SUCCESS;
}

status_t sql_parse_pctfree(lex_t *lex, word_t *word, uint32 *pct_free)
{
    uint32 value;

    if (*pct_free != CT_INVALID_ID32) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, " duplicate pct_free specification");
        return CT_ERROR;
    }

    if (lex_expected_fetch_uint32(lex, &value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (value > CT_PCT_FREE_MAX) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "%s must between 0 and 80 ", W2S(word));
        return CT_ERROR;
    }

    *pct_free = value;
    return CT_SUCCESS;
}

static status_t sql_parse_storage_maxsize(lex_t *lex, word_t *word, int64 *maxsize)
{
    status_t status;

    if ((*maxsize) > 0) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate storage option specification");
        return CT_ERROR;
    }

    LEX_SAVE(lex);

    status = lex_fetch(lex, word);
    CT_RETURN_IFERR(status);

    if (word->type == WORD_TYPE_KEYWORD) {
        if (word->id != KEY_WORD_UNLIMITED) {
            CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid STORAGE option");
            return CT_ERROR;
        }
        *maxsize = CT_INVALID_INT64;
    } else {
        LEX_RESTORE(lex);
        status = lex_expected_fetch_size(lex, maxsize, CT_MIN_STORAGE_MAXSIZE, CT_MAX_STORAGE_MAXSIZE);
        CT_RETURN_IFERR(status);
    }

    return CT_SUCCESS;
}

static status_t sql_parse_storage_initial(lex_t *lex, word_t *word, int64 *initial)
{
    status_t status;

    if ((*initial) > 0) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate storage option specification");
        return CT_ERROR;
    }

    status = lex_expected_fetch_size(lex, initial, CT_MIN_STORAGE_INITIAL, CT_MAX_STORAGE_INITIAL);
    CT_RETURN_IFERR(status);

    return CT_SUCCESS;
}

static status_t sql_parse_storage_next(lex_t *lex, word_t *word, int64 *next)
{
    status_t status;

    if ((*next) > 0) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate storage option specification");
        return CT_ERROR;
    }

    status = lex_expected_fetch_size(lex, next, CT_INVALID_INT64, CT_INVALID_INT64);
    CT_RETURN_IFERR(status);

    return CT_SUCCESS;
}

static status_t sql_parse_storage_attr(lex_t *lex, word_t *word, knl_storage_def_t *storage_def, bool32 alter)
{
    status_t status;

    if ((storage_def->initial > 0) || (storage_def->next > 0) || (storage_def->maxsize > 0)) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate storage option specification");
        return CT_ERROR;
    }

    for (;;) {
        if (lex_fetch(lex, word) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (word->type == WORD_TYPE_EOF) {
            return CT_SUCCESS;
        }

        if (word->type != WORD_TYPE_KEYWORD) {
            CT_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "unexpected word %s found.", W2S(word));
            return CT_ERROR;
        }

        switch (word->id) {
            case KEY_WORD_INITIAL:
                if (alter) {
                    CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "INITIAL storage options");
                    return CT_ERROR;
                }
                status = sql_parse_storage_initial(lex, word, &storage_def->initial);
                CT_RETURN_IFERR(status);
                break;
            case KEY_WORD_NEXT:
                if (alter) {
                    CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "NEXT storage options");
                    return CT_ERROR;
                }
                status = sql_parse_storage_next(lex, word, &storage_def->next);
                CT_RETURN_IFERR(status);
                break;
            case KEY_WORD_MAXSIZE:
                status = sql_parse_storage_maxsize(lex, word, &storage_def->maxsize);
                CT_RETURN_IFERR(status);
                break;
            default:
                break;
        }
    }

    return CT_SUCCESS;
}

status_t sql_parse_storage(lex_t *lex, word_t *word, knl_storage_def_t *storage_def, bool32 alter)
{
    uint32 flags = lex->flags;
    lex->flags = LEX_SINGLE_WORD;

    CT_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    if (word->text.len == 0) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "missing STORAGE option");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_push(lex, &word->text));
    if (sql_parse_storage_attr(lex, word, storage_def, alter) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    lex_pop(lex);

    lex->flags = flags;
    return CT_SUCCESS;
}