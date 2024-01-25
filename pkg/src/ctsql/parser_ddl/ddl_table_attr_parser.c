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
 * ddl_table_attr_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_table_attr_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ddl_table_attr_parser.h"
#include "ddl_partition_parser.h"
#include "ddl_parser_common.h"

status_t sql_parse_row_format(lex_t *lex, word_t *word, bool8 *csf)
{
    uint32 match_id;
    if (*csf != CT_INVALID_ID8) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate %s specification", W2S(word));
        return CT_ERROR;
    }

    if (lex_expected_fetch_1of2(lex, "CSF", "ASF", &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *csf = (match_id == 0) ? CT_TRUE : CT_FALSE;

    return CT_SUCCESS;
}

static inline status_t sql_check_sysid(word_t *word, int32 sysid)
{
    if (sysid <= 0 || sysid >= CT_EX_SYSID_END || (sysid >= CT_RESERVED_SYSID && sysid < CT_EX_SYSID_START)) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "%s must between 1 and %d or %d and %d ", W2S(word),
            CT_RESERVED_SYSID, CT_EX_SYSID_START, CT_EX_SYSID_END);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_parse_sysid(lex_t *lex, word_t *word, uint32 *id)
{
    int32 tmp_id;
    if (*id != CT_INVALID_ID32) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate %s specification", W2S(word));
        return CT_ERROR;
    }

    if (lex_expected_fetch_int32(lex, &tmp_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_check_sysid(word, tmp_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *id = (uint32)tmp_id;
    return CT_SUCCESS;
}


static status_t sql_parse_lob_inrow(lex_t *lex, word_t *word)
{
    if (lex_expected_fetch_word(lex, "STORAGE") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "IN") != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_expected_fetch_word(lex, "ROW");
}

static status_t sql_parse_lob_parameter(sql_stmt_t *stmt, lex_t *lex, knl_lobstor_def_t *def, word_t *word)
{
    bool32 result = CT_FALSE;
    status_t status = CT_SUCCESS;

    def->in_row = CT_TRUE;
    if (lex_try_fetch_bracket(lex, word, &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!result || word->type == WORD_TYPE_EOF) {
        def->in_row = CT_TRUE;
        def->space.len = 0;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(lex_push(lex, &word->text));
    if (lex_fetch(lex, word) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    if (word->type == WORD_TYPE_EOF) {
        CT_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "A LOB storage option was not specified");
        lex_pop(lex);
        return CT_ERROR;
    }

    for (;;) {
        switch (word->id) {
            case KEY_WORD_TABLESPACE:
                status = sql_parse_space(stmt, lex, word, &def->space);
                break;
            case KEY_WORD_ENABLE:
            case KEY_WORD_DISABLE:
                def->in_row = (word->id == KEY_WORD_ENABLE);
                status = sql_parse_lob_inrow(lex, word);
                break;
            default:
                CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected text %s", W2S(word));
                status = CT_ERROR;
                break;
        }

        if (lex_fetch(lex, word) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (word->type == WORD_TYPE_EOF) {
            break;
        }
    }

    lex_pop(lex);

    return status;
}

status_t sql_parse_lob_store(sql_stmt_t *stmt, lex_t *lex, word_t *word, galist_t *defs)
{
    status_t status;
    bool32 result = CT_FALSE;
    knl_lobstor_def_t *def = NULL;

    CT_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    CT_RETURN_IFERR(lex_push(lex, &word->text));

    for (;;) {
        status = lex_expected_fetch_variant(lex, word);
        CT_BREAK_IF_ERROR(status);

        // check duplicate column
        for (uint32 i = 0; i < defs->count; i++) {
            def = (knl_lobstor_def_t *)cm_galist_get(defs, i);
            if (cm_text_equal_ins(&def->col_name, &word->text.value)) {
                CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "duplicate lob storage option specificed");
                status = CT_ERROR;
                break;
            }
        }
        CT_BREAK_IF_ERROR(status);

        status = cm_galist_new(defs, sizeof(knl_lobstor_def_t), (pointer_t *)&def);
        CT_BREAK_IF_ERROR(status);

        status = sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &def->col_name);
        CT_BREAK_IF_ERROR(status);

        status = lex_fetch(lex, word);
        CT_BREAK_IF_ERROR(status);

        if (word->type == WORD_TYPE_EOF) {
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "\",\" expected but %s found", W2S(word));
            status = CT_ERROR;
            break;
        }
    }

    lex_pop(lex);
    CT_RETURN_IFERR(status);

    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "STORE"));
    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "AS"));
    CT_RETURN_IFERR(lex_try_fetch_variant(lex, word, &result));

    if (result) {
        CT_RETURN_IFERR(sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &def->seg_name));
    } else {
        def->seg_name.len = 0;
        def->seg_name.str = NULL;
    }

    return sql_parse_lob_parameter(stmt, lex, def, word);
}


static status_t sql_parse_external_type(lex_t *lex, knl_ext_def_t *def)
{
    word_t word;
    bool32 result = CT_FALSE;
    status_t status;

    status = lex_try_fetch(lex, "type", &result);
    CT_RETURN_IFERR(status);

    if (result) {
        status = lex_expected_fetch(lex, &word);
        CT_RETURN_IFERR(status);

        if (cm_text_str_equal_ins((text_t *)&word.text, "loader")) {
            def->external_type = LOADER;
        } else if (cm_text_str_equal_ins((text_t *)&word.text, "datapump")) {
            CT_THROW_ERROR_EX(ERR_CAPABILITY_NOT_SUPPORT, "datapump external table");
            return CT_ERROR;
        } else {
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
                "external type error, expect(loader/datapump) but found %s", W2S(&word));
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_parse_external_directory(sql_stmt_t *stmt, lex_t *lex, knl_ext_def_t *def)
{
    word_t word;
    status_t status;

    status = lex_expected_fetch_word(lex, "directory");
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch_variant(lex, &word);
    CT_RETURN_IFERR(status);

    return sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->directory);
}

static status_t sql_parse_records_delimiter(lex_t *lex, knl_ext_def_t *def)
{
    word_t word;

    if (lex_expected_fetch_word(lex, "records") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "delimited") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "by") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_text_str_equal_ins((text_t *)&word.text, "newline")) {
        def->records_delimiter = '\n';
    } else {
        LEX_REMOVE_WRAP(&word);
        if (word.text.len != 1) {
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
                "only single character is supported for records delimiter");
            return CT_ERROR;
        }

        def->records_delimiter = word.text.str[0];
    }

    return CT_SUCCESS;
}

static status_t sql_parse_fields_delimiter(lex_t *lex, knl_ext_def_t *def)
{
    word_t word;

    if (lex_expected_fetch_word(lex, "fields") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "terminated") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "by") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_string(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.text.len != 1) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
            "only single character is supported for fields delimiter");
        return CT_ERROR;
    }
    def->fields_terminator = word.text.str[0];
    return CT_SUCCESS;
}

/*
optional access parameters for "LOADER":
access parameters( records delimited by newline
fields terminated by ',')
*/
static status_t sql_parse_external_params(lex_t *lex, knl_ext_def_t *def)
{
    word_t word;
    bool32 result = CT_FALSE;
    status_t status;

    if (lex_try_fetch(lex, "access", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (result) {
        status = lex_expected_fetch_word(lex, "parameters");
        CT_RETURN_IFERR(status);

        status = lex_expected_fetch_bracket(lex, &word);
        CT_RETURN_IFERR(status);

        CT_RETURN_IFERR(lex_push(lex, &word.text));

        if (sql_parse_records_delimiter(lex, def) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        if (sql_parse_fields_delimiter(lex, def) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }

        if (lex_fetch(lex, &word) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }

        if (word.type != WORD_TYPE_EOF) {
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected string %s found", W2S(&word));
            lex_pop(lex);
            return CT_ERROR;
        }

        if (def->fields_terminator == def->records_delimiter) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "the records delimiter must different from fields delimiter");
            lex_pop(lex);
            return CT_ERROR;
        }

        lex_pop(lex);
    }

    return CT_SUCCESS;
}

static status_t sql_parse_external_location(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_ext_def_t *def)
{
    if (lex_expected_fetch_word(lex, "location") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_string(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

#ifdef WIN32
    if (cm_strstri(word->text.str, "..\\") != NULL || cm_strstri(word->text.str, ".\\") != NULL) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "File name cannot contain a path specification: ..\\ or .\\");
        return CT_ERROR;
    }
#else
    if (cm_strstri(word->text.str, "../") != NULL || cm_strstri(word->text.str, "./") != NULL) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "File name cannot contain a path specification: ../ or ./");
        return CT_ERROR;
    }
#endif

    return sql_copy_text(stmt->context, (text_t *)&word->text, &def->location);
}

status_t sql_check_organization_column(knl_table_def_t *def)
{
    uint16 col_count;
    knl_column_def_t *col_def = NULL;

    for (col_count = 0; col_count < def->columns.count; col_count++) {
        col_def = cm_galist_get(&def->columns, col_count);
        if (col_def->is_serial) {
            CT_THROW_ERROR_EX(ERR_CAPABILITY_NOT_SUPPORT, "specify seialize column on external table");
            return CT_ERROR;
        }

        if (col_def->is_check) {
            CT_THROW_ERROR_EX(ERR_CAPABILITY_NOT_SUPPORT, "specify check on external table column");
            return CT_ERROR;
        }

        if (col_def->is_ref) {
            CT_THROW_ERROR_EX(ERR_CAPABILITY_NOT_SUPPORT, "specify reference for external table column");
            return CT_ERROR;
        }

        if (col_def->is_default) {
            CT_THROW_ERROR_EX(ERR_CAPABILITY_NOT_SUPPORT, "specify default value for external table column");
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t sql_parse_organization(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_ext_def_t *def)
{
    status_t status;

    def->external_type = LOADER;
    def->fields_terminator = ',';
    def->records_delimiter = '\n';

    status = lex_expected_fetch_word(lex, "external");
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch_bracket(lex, word);
    CT_RETURN_IFERR(status);

    CT_RETURN_IFERR(lex_push(lex, &word->text));

    if (sql_parse_external_type(lex, def) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    if (sql_parse_external_directory(stmt, lex, def) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    if (def->external_type == LOADER) {
        if (sql_parse_external_params(lex, def) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
    }

    if (sql_parse_external_location(stmt, lex, word, def) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    if (lex_fetch(lex, word) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    if (word->type != WORD_TYPE_EOF) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected string %s found", W2S(word));
        lex_pop(lex);
        return CT_ERROR;
    }

    lex_pop(lex);
    if (lex_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word->type != WORD_TYPE_EOF) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected string %s found", W2S(word));
        return CT_ERROR;
    }

    return status;
}

static status_t sql_parse_temp_table(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_table_def_t *def)
{
    if (lex_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word->id != KEY_WORD_COMMIT) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "COMMIT expected but %s found", W2S(word));
        return CT_ERROR;
    }

    if (lex_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word->id == KEY_WORD_DELETE) {
        def->type = TABLE_TYPE_TRANS_TEMP;
    } else if (word->id == KEY_WORD_PRESERVE) {
        def->type = TABLE_TYPE_SESSION_TEMP;
    } else {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "DELETE/PRESERVE expected but %s found", W2S(word));
        return CT_ERROR;
    }

    if (lex_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word->id != KEY_WORD_ROWS) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "ROWS expected but %s found", W2S(word));
        return CT_ERROR;
    }

    if (IS_LTT_BY_NAME(def->name.str) && def->type == TABLE_TYPE_TRANS_TEMP) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "local temporary table don't support on commit delete rows");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}


status_t sql_parse_appendonly(lex_t *lex, word_t *word, bool32 *appendonly)
{
    if (lex_expected_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!(word->id == KEY_WORD_ON || word->id == KEY_WORD_OFF)) {
        CT_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "ON or OFF expected but %s found", W2S(word));
        return CT_ERROR;
    }

    *appendonly = (word->id == KEY_WORD_ON) ? CT_TRUE : CT_FALSE;
    return CT_SUCCESS;
}

status_t sql_parse_check_auto_increment(sql_stmt_t *stmt, word_t *word, knl_altable_def_t *def)
{
    sql_table_entry_t *table = NULL;
    sql_context_t *context = stmt->context;
    table = (sql_table_entry_t *)cm_galist_get(context->tables, 0);
    dc_entity_t *entity = DC_ENTITY(&table->dc);
    if (!entity->has_serial_col) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "AUTO INCREMENT is not allowed setting");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_parse_init_auto_increment(sql_stmt_t *stmt, lex_t *lex, int64 *serial_start)
{
    bool32 result = CT_FALSE;
    if (lex_try_fetch(lex, "=", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_expected_fetch_size(lex, serial_start, 0, CT_INVALID_INT64);
}

status_t sql_parse_charset(sql_stmt_t *stmt, lex_t *lex, uint8 *charset)
{
    word_t word;
    bool32 result = CT_FALSE;
    uint16 charset_id;

    if (lex_try_fetch(lex, "SET", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_try_fetch(lex, "=", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        LEX_REMOVE_WRAP(&word);
    }

    charset_id = cm_get_charset_id_ex(&word.text.value);
    if (charset_id == CT_INVALID_ID16) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unknown charset option %s", T2S(&word.text.value));
        return CT_ERROR;
    }

    *charset = (uint8)charset_id;
    return CT_SUCCESS;
}

status_t sql_parse_collate(sql_stmt_t *stmt, lex_t *lex, uint8 *collate)
{
    word_t word;
    bool32 result = CT_FALSE;
    uint16 collate_id;

    if (lex_try_fetch(lex, "=", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        LEX_REMOVE_WRAP(&word);
    }

    collate_id = cm_get_collation_id(&word.text.value);
    if (collate_id == CT_INVALID_ID16) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unknown collation option %s",
            T2S(&word.text.value));
        return CT_ERROR;
    }

    *collate = (uint8)collate_id;
    return CT_SUCCESS;
}

status_t sql_parse_table_compress(sql_stmt_t *stmt, lex_t *lex, uint8 *type, uint8 *algo)
{
    bool32 result = CT_FALSE;
    uint32 matched_id;
    if (lex_try_fetch(lex, "for", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!result) {
        *type = COMPRESS_TYPE_GENERAL;
        if (*algo > COMPRESS_NONE) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "duplicate compress specification");
            return CT_ERROR;
        }
        *algo = COMPRESS_ZSTD;
        return CT_SUCCESS;
    }

    if (CT_SUCCESS != lex_expected_fetch_1of2(lex, "ALL", "DIRECT_LOAD", &matched_id)) {
        return CT_ERROR;
    }
    if (matched_id == LEX_MATCH_FIRST_WORD) {
        *type = COMPRESS_TYPE_ALL;
    } else {
        *type = COMPRESS_TYPE_DIRECT_LOAD;
    }

    return lex_expected_fetch_word(lex, "operations");
}

status_t sql_parse_coalesce_partition(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def)
{
    if (lex_expected_fetch_word(lex, "PARTITION") != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}

static status_t sql_set_table_attrs(sql_stmt_t *stmt, knl_table_def_t *def)
{
    if (def->initrans == 0) {
        def->initrans = cm_text_str_equal_ins(&def->schema, "SYS") ? CT_INI_TRANS :
                                                                     stmt->session->knl_session.kernel->attr.initrans;
    }

    if (def->pctfree == CT_INVALID_ID32) {
        def->pctfree = CT_PCT_FREE;
    }

    if (def->cr_mode == CT_INVALID_ID8) {
        def->cr_mode = stmt->session->knl_session.kernel->attr.cr_mode;
    }

    if (def->type != TABLE_TYPE_HEAP && def->type != TABLE_TYPE_NOLOGGING) {
        if (def->csf == ROW_FORMAT_CSF) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " not support csf for current table type.");
            return CT_ERROR;
        }
    }

    if (def->sysid != CT_INVALID_ID32 || def->csf == CT_INVALID_ID8) {
        def->csf = CT_FALSE;
        if (def->type == TABLE_TYPE_HEAP || def->type == TABLE_TYPE_NOLOGGING) {
            def->csf = (stmt->session->knl_session.kernel->attr.row_format == ROW_FORMAT_CSF);
        }
    }
    return CT_SUCCESS;
}

bool32 sql_default_dist_check_uq_outline(knl_table_def_t *def)
{
    knl_constraint_def_t *cons = NULL;
    bool32 single_uq = CT_FALSE;

    for (uint32 i = 0; i < def->constraints.count; i++) {
        cons = (knl_constraint_def_t *)cm_galist_get(&def->constraints, i);
        if (cons->type != CONS_TYPE_UNIQUE) {
            continue;
        }
        if (single_uq) {
            return CT_FALSE;
        }
        single_uq = CT_TRUE;
    }
    return CT_TRUE;
}

status_t sql_default_dist_check_uq_inline(knl_table_def_t *def)
{
    knl_column_def_t *column = NULL;
    bool32 single_uq = CT_FALSE;
    for (uint32 i = 0; i < def->columns.count; i++) {
        column = (knl_column_def_t *)cm_galist_get(&def->columns, i);
        if (!column->unique) {
            continue;
        }
        if (single_uq) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Calculating default distribute column failed");
            return CT_ERROR;
        }
        single_uq = CT_TRUE;
    }
    return CT_SUCCESS;
}

bool32 sql_check_pk_with_uq_outline(knl_table_def_t *def, text_t *col_name)
{
    knl_constraint_def_t *cons = NULL;
    knl_index_col_def_t *index_col = NULL;

    for (uint32 i = 0; i < def->constraints.count; i++) {
        cons = (knl_constraint_def_t *)cm_galist_get(&def->constraints, i);
        if (cons->type != CONS_TYPE_UNIQUE) {
            continue;
        }
        for (uint32 j = 0; j < cons->columns.count; j++) {
            index_col = (knl_index_col_def_t *)cm_galist_get(&cons->columns, j);
            if (cm_text_equal(col_name, &index_col->name)) {
                break;
            }
            if (j == cons->columns.count - 1) {
                return CT_FALSE;
            }
        }
    }
    return CT_TRUE;
}

status_t sql_default_dist_pk_with_uq_outline(knl_table_def_t *def, knl_constraint_def_t *pk_cons, sql_text_t *dist_info,
    bool32 *is_find)
{
    knl_index_col_def_t *pk_col = NULL;
    errno_t err;

    for (uint32 i = 0; i < pk_cons->columns.count; i++) {
        pk_col = (knl_index_col_def_t *)cm_galist_get(&pk_cons->columns, i);
        if (sql_check_pk_with_uq_outline(def, &pk_col->name) == CT_TRUE) {
            err = snprintf_s(dist_info->str + dist_info->len, CT_MAX_NAME_LEN + 1, CT_MAX_NAME_LEN, "%s",
                T2S(&pk_col->name));
            PRTS_RETURN_IFERR(err);
            dist_info->len += err;

            *is_find = CT_TRUE;
            return CT_SUCCESS;
        }
    }
    CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Calculating default distribute column failed");
    return CT_ERROR;
}

status_t sql_default_dist_pk_with_uq_inline(knl_table_def_t *def, knl_constraint_def_t *cons, sql_text_t *dist_info,
    bool32 *is_find)
{
    knl_column_def_t *column = NULL;
    knl_index_col_def_t *index_col = NULL;
    errno_t err;

    CT_RETURN_IFERR(sql_default_dist_check_uq_inline(def));

    for (uint32 i = 0; i < def->columns.count; i++) {
        column = (knl_column_def_t *)cm_galist_get(&def->columns, i);
        if (!column->unique) {
            continue;
        }
        for (uint32 j = 0; j < cons->columns.count; j++) {
            index_col = (knl_index_col_def_t *)cm_galist_get(&cons->columns, j);
            if (cm_text_equal(&column->name, &index_col->name)) {
                if (sql_check_pk_with_uq_outline(def, &column->name) == CT_FALSE) {
                    CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Calculating default distribute column failed");
                    return CT_ERROR;
                }
                err = snprintf_s(dist_info->str + dist_info->len, CT_MAX_NAME_LEN + 1, CT_MAX_NAME_LEN, "%s",
                    T2S(&column->name));
                PRTS_RETURN_IFERR(err);
                dist_info->len += err;

                *is_find = CT_TRUE;
                return CT_SUCCESS;
            }
        }
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Calculating default distribute column failed");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_default_dist_pk_inline(knl_table_def_t *def, sql_text_t *dist_info, bool32 *is_find)
{
    knl_column_def_t *column = NULL;
    errno_t err;
    if (def->uq_inline) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Calculating default distribute column failed");
        return CT_ERROR;
    }

    for (uint32 i = 0; i < def->columns.count; i++) {
        column = (knl_column_def_t *)cm_galist_get(&def->columns, i);
        if (!column->primary) {
            continue;
        }

        if (sql_check_pk_with_uq_outline(def, &column->name) == CT_FALSE) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Calculating default distribute column failed");
            return CT_ERROR;
        }
        err =
            snprintf_s(dist_info->str + dist_info->len, CT_MAX_NAME_LEN + 1, CT_MAX_NAME_LEN, "%s", T2S(&column->name));
        PRTS_RETURN_IFERR(err);
        dist_info->len += err;

        *is_find = CT_TRUE;
        return CT_SUCCESS;
    }
    return CT_SUCCESS;
}

bool32 sql_check_uq_not_null(knl_table_def_t *def, text_t *col_name)
{
    knl_column_def_t *column = NULL;
    const text_t null_text = {
        .str = "null",
        .len = (uint32)strlen("null")
    };

    for (uint32 i = 0; i < def->columns.count; i++) {
        column = (knl_column_def_t *)cm_galist_get(&def->columns, i);
        if (cm_text_equal(col_name, &column->name)) {
            if ((column->nullable && !column->is_default) ||
                cm_compare_text_ins(&column->default_text, &null_text) == 0) {
                return CT_FALSE;
            }
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

status_t sql_parse_table_attrs(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *table_def,
                               bool32 *expect_as, word_t *word)
{
    status_t status = CT_ERROR;
    uint32 matched_id;
    uint32 ex_flags = 0;
    uint8 algo = COMPRESS_NONE;
    uint8 type = COMPRESS_TYPE_NO;

    table_def->cr_mode = CT_INVALID_ID8;
    table_def->pctfree = CT_INVALID_ID32;
    table_def->csf = CT_INVALID_ID8;

    for (;;) {
        status = lex_fetch(lex, word);
        CT_RETURN_IFERR(status);
        if (word->type == WORD_TYPE_EOF || word->id == KEY_WORD_AS) {
            break;
        }

        switch (word->id) {
            case KEY_WORD_TABLESPACE:
                status = sql_parse_space(stmt, lex, word, &table_def->space);
                break;

            case KEY_WORD_INITRANS:
                status = sql_parse_trans(lex, word, &table_def->initrans);
                break;

            case KEY_WORD_MAXTRANS:
                status = sql_parse_trans(lex, word, &table_def->maxtrans);
                break;

            case KEY_WORD_PCTFREE:
                status = sql_parse_pctfree(lex, word, &table_def->pctfree);
                break;

            case KEY_WORD_CRMODE:
                status = sql_parse_crmode(lex, word, &table_def->cr_mode);
                break;

            case KEY_WORD_FORMAT:
                status = sql_parse_row_format(lex, word, &table_def->csf);
                break;

            case KEY_WORD_SYSTEM:
                status = sql_parse_sysid(lex, word, &table_def->sysid);
                break;

            case KEY_WORD_STORAGE:
                status = sql_parse_storage(lex, word, &table_def->storage_def, CT_FALSE);
                break;

            case KEY_WORD_LOB:
                if (table_def->type == TABLE_TYPE_SESSION_TEMP || table_def->type == TABLE_TYPE_TRANS_TEMP) {
                    CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                        "Temporary tables do not support LOB clauses");
                    return CT_ERROR;
                }
                status = sql_parse_lob_store(stmt, lex, word, &table_def->lob_stores);
                break;

            case KEY_WORD_ON:
                if (table_def->type == TABLE_TYPE_HEAP) {
                    CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "ON COMMIT only used on temporary table");
                    return CT_ERROR;
                }
                if (ex_flags & TEMP_TBL_ATTR_PARSED) {
                    CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "too many option for table");
                    return CT_ERROR;
                }
                status = sql_parse_temp_table(stmt, lex, word, table_def);
                ex_flags |= TEMP_TBL_ATTR_PARSED;
                break;
            case KEY_WORD_APPENDONLY:
                status = sql_parse_appendonly(lex, word, &table_def->appendonly);
                break;
            case KEY_WORD_PARTITION:
                status = sql_part_parse_table(stmt, word, expect_as, table_def);
                break;
            case KEY_WORD_AUTO_INCREMENT:
                if (ex_flags & TBLOPTS_EX_AUTO_INCREMENT) {
                    CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                        "duplicate or conflicting auto_increment specifications");
                    return CT_ERROR;
                }
                status = sql_parse_init_auto_increment(stmt, lex, (int64 *)&table_def->serial_start);
                ex_flags |= TBLOPTS_EX_AUTO_INCREMENT;
                break;
            case RES_WORD_DEFAULT:
                if (CT_SUCCESS !=
                    lex_expected_fetch_1ofn(stmt->session->lex, &matched_id, 3, "CHARACTER", "CHARSET", "COLLATE")) {
                    return CT_ERROR;
                }

                if (matched_id == LEX_MATCH_FIRST_WORD || matched_id == LEX_MATCH_SECOND_WORD) {
                    status = sql_parse_charset(stmt, lex, &table_def->charset);
                } else if (matched_id == LEX_MATCH_THIRD_WORD) {
                    status = sql_parse_collate(stmt, lex, &table_def->collate);
                } else {
                    status = CT_ERROR;
                }
                break;
            case KEY_WORD_CHARSET:
            case KEY_WORD_CHARACTER:
                status = sql_parse_charset(stmt, lex, &table_def->charset);
                break;
            case KEY_WORD_COLLATE:
                status = sql_parse_collate(stmt, lex, &table_def->collate);
                break;
            case KEY_WORD_CACHE:
            case KEY_WORD_NO_CACHE:
                break;
            case KEY_WORD_LOGGING:
                break;
            case KEY_WORD_NO_LOGGING:
                if (table_def->type == TABLE_TYPE_TRANS_TEMP || table_def->type == TABLE_TYPE_SESSION_TEMP) {
                    CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                        "cannot sepecify NOLOGGING on temporary table");
                    status = CT_ERROR;
                } else if (table_def->compress_algo > COMPRESS_NONE) {
                    CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                        "unexpected text %s, table compress only supported on (part)table", W2S(word));
                    status = CT_ERROR;
                } else {
                    table_def->type = TABLE_TYPE_NOLOGGING;
                }
                break;
            case KEY_WORD_COMPRESS:
                // ordinary table and partition table support compress, but sub partition table don't support.
                if (table_def->type == TABLE_TYPE_HEAP) {
                    status = sql_parse_table_compress(stmt, lex, &type, &algo);
                    table_def->compress_type = type;
                    table_def->compress_algo = algo;
                    break;
                }
                CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                    "unexpected text %s, table compress only supported on (part)table", W2S(word));
                return CT_ERROR;

            case KEY_WORD_NO_COMPRESS:
                table_def->compress_type = COMPRESS_TYPE_NO;
                break;

            default:
                CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected text %s", W2S(word));
                return CT_ERROR;
        }

        if (status != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    CT_RETURN_IFERR(sql_set_table_attrs(stmt, table_def));

    return CT_SUCCESS;
}
