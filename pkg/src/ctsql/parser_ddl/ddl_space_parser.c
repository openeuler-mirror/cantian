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
 * ddl_space_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser_ddl/ddl_space_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ddl_space_parser.h"
#include "srv_instance.h"


status_t sql_parse_space(sql_stmt_t *stmt, lex_t *lex, word_t *word, text_t *space)
{
    if (space->len != 0) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate tablespace specification");
        return CT_ERROR;
    }

    if (lex_expected_fetch_variant(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &(*space));
}

static inline status_t sql_parse_space_all_inmem(lex_t *lex, knl_space_def_t *def, word_t *word)
{
    /* got "ALL", move to the next */
    CT_RETURN_IFERR(lex_fetch(lex, word));
    if (word->id == KEY_WORD_IN) {
        /* got "ALL IN", move to the next */
        CT_RETURN_IFERR(lex_fetch(lex, word));
        if (word->id == KEY_WORD_MEMORY) {
            /*
             * got "ALL IN MEMORY", assign the "in_memory" property,
             * and move to the next word to take out of this function
             */
            def->in_memory = CT_TRUE;
            CT_RETURN_IFERR(lex_fetch(lex, word));
        }
    }

    return CT_SUCCESS;
}


static status_t sql_parse_extent_clause_core(sql_stmt_t *stmt, knl_space_def_t *def, word_t *next_word)
{
    lex_t *lex = stmt->session->lex;

    if (def->extent_size != 0) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid extent clause");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_expected_fetch(lex, next_word));
    if (next_word->id == KEY_WORD_AUTOALLOCATE) {
        def->autoallocate = CT_TRUE;
        def->extent_size = CT_MIN_EXTENT_SIZE;
    } else {
        CT_SRC_THROW_ERROR_EX(next_word->loc, ERR_SQL_SYNTAX_ERROR, "AUTOALLOCATE expected but \"%s\" found.",
            (*(W2S(next_word)) == '\0' ? "emtpy string" : W2S(next_word)));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_fetch(lex, next_word));
    return CT_SUCCESS;
}

static status_t sql_parse_autooffline_clause_core(sql_stmt_t *stmt, bool32 *autooffline, word_t *next_word)
{
    lex_t *lex = stmt->session->lex;

    CT_RETURN_IFERR(lex_expected_fetch(lex, next_word));
    if (next_word->type != WORD_TYPE_KEYWORD) {
        CT_SRC_THROW_ERROR_EX(next_word->loc, ERR_SQL_SYNTAX_ERROR, "ON or OFF expected but \"%s\" found.",
            (*(W2S(next_word)) == '\0' ? "emtpy string" : W2S(next_word)));
        return CT_ERROR;
    }

    if (next_word->id == KEY_WORD_OFF) {
        *autooffline = CT_FALSE;
    } else if (next_word->id == KEY_WORD_ON) {
        *autooffline = CT_TRUE;
    } else {
        CT_SRC_THROW_ERROR_EX(next_word->loc, ERR_SQL_SYNTAX_ERROR, "ON or OFF expected but \"%s\" found.",
            (*(W2S(next_word)) == '\0' ? "emtpy string" : W2S(next_word)));
        return CT_ERROR;
    }
    CT_RETURN_IFERR(lex_fetch(lex, next_word));

    return CT_SUCCESS;
}

static status_t sql_parse_space_attr(sql_stmt_t *stmt, lex_t *lex, knl_space_def_t *def, word_t *word)
{
    bool32 parsed_offline = CT_FALSE;
    bool32 parsed_all = CT_FALSE;
    bool32 parsed_nologging = CT_FALSE;
    bool32 parsed_extent = CT_FALSE;
    def->in_memory = CT_FALSE;

    while (word->type == WORD_TYPE_KEYWORD) {
        switch ((key_wid_t)word->id) {
            case KEY_WORD_ALL:
                if ((def->type & SPACE_TYPE_TEMP) || parsed_all) {
                    CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(word));
                    return CT_ERROR;
                }

                CT_RETURN_IFERR(sql_parse_space_all_inmem(lex, def, word));

                parsed_all = CT_TRUE;
                break;
            case KEY_WORD_NO_LOGGING:
                if (def->in_memory || parsed_nologging) {
                    CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(word));
                    return CT_ERROR;
                }

                def->type |= SPACE_TYPE_TEMP;
                CT_RETURN_IFERR(lex_fetch(lex, word));
                parsed_nologging = CT_TRUE;
                break;
            case KEY_WORD_ENCRYPTION:
                if (def->in_memory) {
                    CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(word));
                    return CT_ERROR;
                }

                def->encrypt = CT_TRUE;
                CT_RETURN_IFERR(lex_fetch(lex, word));
                break;
            case KEY_WORD_AUTOOFFLINE:
                if (parsed_offline) {
                    CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(word));
                    return CT_ERROR;
                }

                CT_RETURN_IFERR(sql_parse_autooffline_clause_core(stmt, &def->autooffline, word));

                parsed_offline = CT_TRUE;
                break;
            case KEY_WORD_EXTENT:
                if (parsed_extent) {
                    CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(word));
                    return CT_ERROR;
                }

                CT_RETURN_IFERR(sql_parse_extent_clause_core(stmt, def, word));

                def->bitmapmanaged = CT_TRUE;
                parsed_extent = CT_TRUE;
                break;
            default:
                CT_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "expected end but \"%s\" found", W2S(word));
                return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_parse_auto_extend_on(device_type_t type, sql_stmt_t *stmt, knl_autoextend_def_t *autoextend_def)
{
    bool32 next_sized = CT_FALSE;
    bool32 max_sized = CT_FALSE;
    bool32 max_ulimited = CT_FALSE;
    int64 tmp_next_size = 0;
    int64 tmp_max_size = 0;
    lex_t *lex = stmt->session->lex;

    uint32 page_size = 0;
    autoextend_def->enabled = CT_TRUE;

    /* check if next clause exists */
    CT_RETURN_IFERR(lex_try_fetch(lex, "NEXT", &next_sized));
    if (next_sized == CT_TRUE) {
        CT_RETURN_IFERR(
            lex_expected_fetch_size(lex, (int64 *)(&tmp_next_size), CT_MIN_AUTOEXTEND_SIZE, CT_INVALID_INT64));
        CT_RETURN_IFERR(cm_check_device_size(type, tmp_next_size));
    } else {
        /* "NEXTSIZE" not specified, set 0, and knl_datafile will init this value by DEFALUD VAULE */
        tmp_next_size = 0;
    }

    /* check if maxsize clause exists */
    CT_RETURN_IFERR(knl_get_page_size(KNL_SESSION(stmt), &page_size));
    CT_RETURN_IFERR(lex_try_fetch(lex, "MAXSIZE", &max_sized));
    if (max_sized == CT_TRUE) {
        CT_RETURN_IFERR(lex_try_fetch(lex, "UNLIMITED", &max_ulimited));
        if (max_ulimited != CT_TRUE) {
            CT_RETURN_IFERR(
                lex_expected_fetch_size(lex, (int64 *)(&tmp_max_size), CT_MIN_AUTOEXTEND_SIZE, CT_INVALID_INT64));
            CT_RETURN_IFERR(cm_check_device_size(type, tmp_max_size));
            if (tmp_max_size > ((int64)CT_MAX_DATAFILE_PAGES * page_size)) {
                CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                    "\"MAXSIZE\" specified in autoextend clause cannot "
                    "be greater than %lld. \"MAXSIZE\": %lld",
                    ((int64)CT_MAX_DATAFILE_PAGES * page_size), tmp_max_size);
                return CT_ERROR;
            }
        } else {
            tmp_max_size = 0;
        }
    } else {
        /* "MAXSIZE" not specified, take (CT_MAX_DATAFILE_PAGES * page_size) as the default value */
        tmp_max_size = 0;
    }

    if ((tmp_max_size > 0) && (tmp_next_size > tmp_max_size)) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
            "\"NEXT\" size specified in autoextend clause cannot be "
            "greater than the \"MAX\" size. \"Next\" size is %lld, \"MAX\" size is %lld",
            tmp_next_size, tmp_max_size);
        return CT_ERROR;
    }

    /* assign the parsed size value respectively */
    autoextend_def->nextsize = tmp_next_size;
    autoextend_def->maxsize = tmp_max_size;

    return CT_SUCCESS;
}

/*
 * the common routine for parsing auto-extend clause (keyword "AUTOEXTEND" excluded)
 * auto-extend clause (excluding "AUTOEXTEND") means:
 * { OFF | ON [ NEXT size_clause] [ MAXSIZE { UNLIMITED | size_clause }] }
 *
 * @Note:
 * 1. when "ON" specified but "NEXT" size not specified, take 16MB as the default "NEXT" size
 * 2. when "ON" specified but "MAXSIZE" size not specified, take the de-facto maxsize(*) as the default "MAXSIZE"
 * the de-facto maxsize is max_pages(4194303 pages per datafile) * length of page(8KB)
 * 3. if "ON" specified, even "MAXSIZE UNLIMITED" specified, the de-facto value of "MAXSIZE" is
 * max_pages(4194303 pages per datafile) * length of page(8KB)
 * 4. if "OFF" specified, do not use the "nextsize" and "maxsize" of the argument "autoextend_def"
 */
status_t sql_parse_autoextend_clause_core(device_type_t type, sql_stmt_t *stmt, knl_autoextend_def_t *autoextend_def,
    word_t *next_word)
{
    CM_POINTER3(stmt, autoextend_def, next_word);
    word_t word;
    lex_t *lex = stmt->session->lex;

    CT_RETURN_IFERR(lex_expected_fetch(lex, &word));
    if (word.type != WORD_TYPE_KEYWORD) {
        CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "ON or OFF expected but \"%s\" found.",
            (*(W2S(&word)) == '\0' ? "emtpy string" : W2S(&word)));
        return CT_ERROR;
    }

    if (word.id == KEY_WORD_OFF) {
        autoextend_def->enabled = CT_FALSE;
    } else if (word.id == KEY_WORD_ON) {
        CT_RETURN_IFERR(sql_parse_auto_extend_on(type, stmt, autoextend_def));
    } else {
        CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "ON or OFF expected but \"%s\" found.",
            (*(W2S(&word)) == '\0' ? "emtpy string" : W2S(&word)));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_fetch(lex, next_word));

    return CT_SUCCESS;
}


status_t sql_parse_datafile(sql_stmt_t *stmt, knl_device_def_t *dev_def, word_t *word, bool32 *isRelative)
{
    status_t status;
    lex_t *lex = stmt->session->lex;
    int64 max_filesize = (int64)g_instance->kernel.attr.page_size * CT_MAX_DATAFILE_PAGES;
    bool32 reuse_specified = CT_FALSE;

    status = lex_expected_fetch_string(lex, word);
    CT_RETURN_IFERR(status);

    if (word->text.str[0] != '/') {
        *isRelative = CT_TRUE;
    }

    status = sql_copy_file_name(stmt->context, (text_t *)&word->text, &dev_def->name);
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch_word(lex, "SIZE");
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch_size(lex, &dev_def->size, CT_MIN_USER_DATAFILE_SIZE, max_filesize);
    CT_RETURN_IFERR(status);

    device_type_t type = cm_device_type(dev_def->name.str);
    CT_RETURN_IFERR(cm_check_device_size(type, dev_def->size));

    CT_RETURN_IFERR(lex_try_fetch(lex, "REUSE", &reuse_specified));
    if (reuse_specified == CT_TRUE) {
        /* support "REUSE" only for the syntax compatibility */
        CT_LOG_RUN_WAR("\"REUSE\" specified in statement \"%s\", but it will not take effect.",
            T2S(&(lex->text.value)));
    }

    CT_RETURN_IFERR(lex_try_fetch(lex, "COMPRESS", &dev_def->compress));

    /*
     * read the next word.
     * if it is "AUTOEXTEND", start to parse the auto-extend clause
     * if not, take the word out of the function and let the caller to judge
     */
    status = lex_fetch(lex, word);
    CT_RETURN_IFERR(status);

    if (word->type == WORD_TYPE_KEYWORD && word->id == KEY_WORD_AUTOEXTEND) {
        CT_RETURN_IFERR(sql_parse_autoextend_clause_core(type, stmt, &dev_def->autoextend, word));

        if (dev_def->autoextend.enabled && dev_def->autoextend.maxsize > 0 &&
            (dev_def->autoextend.maxsize < dev_def->size)) {
            CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                "\"MAXSIZE\" specified in autoextend clause "
                "cannot be less than the value of \"SIZE\". \"MAXSIZE\": %lld, \"SIZE\": %lld",
                dev_def->autoextend.maxsize, dev_def->size);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}


static status_t sql_parse_datafile_spec(sql_stmt_t *stmt, lex_t *lex, knl_space_def_t *def, word_t *word,
    bool32 *isRelative)
{
    status_t status;
    knl_device_def_t *dev_def = NULL;

    while (1) {
        uint32 i;
        knl_device_def_t *cur = NULL;

        status = cm_galist_new(&def->datafiles, sizeof(knl_device_def_t), (pointer_t *)&dev_def);
        CT_RETURN_IFERR(status);

        status = sql_parse_datafile(stmt, dev_def, word, isRelative);
        CT_RETURN_IFERR(status);

        /* prevent the duplicate datafile being passed to storage engine */
        for (i = 0; i < def->datafiles.count; i++) {
            cur = (knl_device_def_t *)cm_galist_get(&def->datafiles, i);
            if (cur != dev_def) {
                if (cm_text_equal_ins(&dev_def->name, &cur->name)) {
                    CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                        "it is not allowed to specify duplicate datafile");
                    return CT_ERROR;
                }
            }
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }
    }

    return CT_SUCCESS;
}

status_t sql_parse_create_space(sql_stmt_t *stmt, bool32 is_temp, bool32 is_undo)
{
    knl_space_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;
    word_t word;
    status_t status;
    bool32 result = CT_FALSE;
    bool32 isRelative = CT_FALSE;
    int64 size;

    status = sql_alloc_mem(stmt->context, sizeof(knl_space_def_t), (void **)&def);
    CT_RETURN_IFERR(status);

    stmt->context->entry = def;
    stmt->context->type = CTSQL_TYPE_CREATE_TABLESPACE;
    cm_galist_init(&def->datafiles, stmt->context, sql_alloc_mem);

    if (is_undo) {
        def->type = SPACE_TYPE_UNDO;
    } else {
        def->type = SPACE_TYPE_USERS;
    }

    if (is_temp) {
        def->type |= SPACE_TYPE_TEMP;
    }

    def->in_shard = CT_FALSE;
    def->autoallocate = CT_FALSE;
    def->bitmapmanaged = CT_FALSE;

    status = lex_expected_fetch_variant(lex, &word);
    CT_RETURN_IFERR(status);

    CT_RETURN_IFERR(sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->name));

    if (lex_try_fetch(lex, "EXTENTS", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (result) {
        if (def->type & SPACE_TYPE_UNDO) {
            CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "create UNDO tablespace using extents option");
            return CT_ERROR;
        }

        if (lex_expected_fetch_size(lex, &size, CT_MIN_EXTENT_SIZE, CT_MAX_EXTENT_SIZE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (((uint64)size & ((uint64)size - 1)) != 0) {
            CT_THROW_ERROR(ERR_INVALID_PARAMETER, "EXTENTS");
            return CT_ERROR;
        }
        def->extent_size = (int32)size;
    } else {
        if (stmt->session->knl_session.kernel->attr.default_space_type == SPACE_BITMAP) {
            def->autoallocate = CT_TRUE;
            def->bitmapmanaged = CT_TRUE;
        }
    }

    if (is_temp) {
        status = lex_expected_fetch_word(lex, "TEMPFILE");
        CT_RETURN_IFERR(status);
    } else {
        status = lex_expected_fetch_word(lex, "DATAFILE");
        CT_RETURN_IFERR(status);
    }

    status = sql_parse_datafile_spec(stmt, lex, def, &word, &isRelative);
    CT_RETURN_IFERR(status);

    status = sql_parse_space_attr(stmt, lex, def, &word);
    CT_RETURN_IFERR(status);

    if (word.type != WORD_TYPE_EOF) {
        CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "expected end but \"%s\" found", W2S(&word));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}


status_t sql_parse_create_undo_space(sql_stmt_t *stmt)
{
    lex_t *lex = stmt->session->lex;
    status_t status;

    status = lex_expected_fetch_word(lex, "tablespace");
    CT_RETURN_IFERR(status);

    status = sql_parse_create_space(stmt, CT_FALSE, CT_TRUE);

    return status;
}


static status_t sql_parse_datafile_clause(sql_stmt_t *stmt, word_t *word, knl_altspace_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    knl_device_def_t *dev_def = NULL;
    bool32 isRelative = CT_FALSE;

    def->action = ALTSPACE_ADD_DATAFILE;

    if (lex_expected_fetch_word(lex, "DATAFILE") != CT_SUCCESS) {
        return CT_ERROR;
    }

    while (1) {
        uint32 i;
        knl_device_def_t *cur = NULL;

        if (cm_galist_new(&def->datafiles, sizeof(knl_device_def_t), (pointer_t *)&dev_def) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (sql_parse_datafile(stmt, dev_def, word, &isRelative) != CT_SUCCESS) {
            return CT_ERROR;
        }

        /* prevent the duplicate datafile being passed to storage engine */
        for (i = 0; i < def->datafiles.count; i++) {
            cur = (knl_device_def_t *)cm_galist_get(&def->datafiles, i);
            if (cur != dev_def) {
                if (cm_text_equal_ins(&dev_def->name, &cur->name)) {
                    CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "it is not allowed to specify duplicate datafile");
                    return CT_ERROR;
                }
            }
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }
    }

    return CT_SUCCESS;
}


static status_t sql_parse_drop_datafile(sql_stmt_t *stmt, lex_t *lex, knl_device_def_t *dev_def, word_t *word)
{
    if (lex_expected_fetch_string(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_copy_file_name(stmt->context, (text_t *)&word->text, &dev_def->name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}

static status_t sql_parse_drop_datafile_clause(sql_stmt_t *stmt, word_t *word, knl_altspace_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    bool32 result = CT_FALSE;
    knl_device_def_t *dev_def = NULL;

    def->action = ALTSPACE_DROP_DATAFILE;

    if (lex_expected_fetch_word(lex, "DATAFILE") != CT_SUCCESS) {
        return CT_ERROR;
    }

    while (1) {
        if (cm_galist_new(&def->datafiles, sizeof(knl_device_def_t), (pointer_t *)&dev_def) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (sql_parse_drop_datafile(stmt, lex, dev_def, word) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (lex_try_fetch_char(lex, ',', &result) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!result) {
            break;
        }
    }

    if (lex_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}


static status_t sql_parse_autoextend_clause(sql_stmt_t *stmt, word_t *word, knl_altspace_def_t *def)
{
    device_type_t type;
    def->action = ALTSPACE_SET_AUTOEXTEND;

    /*
     * the storage engine does not support auto-extend maxsize property,
     * neither does the structure of knl_altspace_def_t.
     * so the 5th~7th argument are all left NULL until the maxsize property
     * implemented in the storage engine
     */
    CT_RETURN_IFERR(knl_get_space_type(KNL_SESSION(stmt), &def->name, &type));
    CT_RETURN_IFERR(sql_parse_autoextend_clause_core(type, stmt, &def->autoextend, word));

    return CT_SUCCESS;
}


static status_t sql_parse_autooffline_clause(sql_stmt_t *stmt, word_t *word, knl_altspace_def_t *def)
{
    def->action = ALTSPACE_SET_AUTOOFFLINE;

    CT_RETURN_IFERR(sql_parse_autooffline_clause_core(stmt, &def->auto_offline, word));

    return CT_SUCCESS;
}


static status_t sql_parse_datafiles_name(sql_stmt_t *stmt, galist_t *list, lex_t *lex, word_t *word)
{
    bool32 result = CT_FALSE;
    knl_device_def_t *dev_def = NULL;

    while (1) {
        if (cm_galist_new(list, sizeof(knl_device_def_t), (pointer_t *)&dev_def) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (lex_expected_fetch_string(lex, word) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (sql_copy_file_name(stmt->context, (text_t *)&word->text, &dev_def->name) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (lex_try_fetch_char(lex, ',', &result) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!result) {
            return CT_SUCCESS;
        }
    }
}

static status_t sql_parse_rename_clause(sql_stmt_t *stmt, word_t *word, knl_altspace_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    bool32 result = CT_FALSE;

    if (lex_try_fetch(lex, "TO", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (result) {
        if (lex_expected_fetch_variant(lex, word) != CT_SUCCESS) {
            return CT_ERROR;
        }

        def->action = ALTSPACE_RENAME_SPACE;

        if (word->text.len > CT_MAX_NAME_LEN) {
            CT_THROW_ERROR(ERR_NAME_TOO_LONG, "tablespace", word->text.len, CT_MAX_NAME_LEN);
            return CT_ERROR;
        }

        CT_RETURN_IFERR(sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &def->rename_space));
        if (cm_text_equal(&def->name, &def->rename_space)) {
            CT_THROW_ERROR(ERR_SPACE_NAME_INVALID);
            return CT_ERROR;
        }

        if (lex_fetch(lex, word) != CT_SUCCESS) {
            return CT_ERROR;
        }

        return CT_SUCCESS;
    }

    if (lex_expected_fetch_word(lex, "DATAFILE") != CT_SUCCESS) {
        return CT_ERROR;
    }

    def->action = ALTSPACE_RENAME_DATAFILE;
    if (sql_parse_datafiles_name(stmt, &def->datafiles, lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "TO") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_parse_datafiles_name(stmt, &def->rename_datafiles, lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_parse_offline_clause(sql_stmt_t *stmt, word_t *word, knl_altspace_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    bool32 result = CT_FALSE;
    knl_device_def_t *dev_def = NULL;

    def->action = ALTSPACE_OFFLINE_DATAFILE;

    if (lex_expected_fetch_word(lex, "DATAFILE") != CT_SUCCESS) {
        return CT_ERROR;
    }

    while (1) {
        if (cm_galist_new(&def->datafiles, sizeof(knl_device_def_t), (pointer_t *)&dev_def) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (lex_expected_fetch_string(lex, word) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (sql_copy_file_name(stmt->context, (text_t *)&word->text, &dev_def->name) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (lex_try_fetch_char(lex, ',', &result) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!result) {
            break;
        }
    }

    if (lex_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}


static status_t sql_parse_autopurge_clause(sql_stmt_t *stmt, word_t *word, knl_altspace_def_t *def)
{
    lex_t *lex = stmt->session->lex;

    def->action = ALTSPACE_SET_AUTOPURGE;

    if (lex_expected_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word->id == KEY_WORD_ON) {
        def->auto_purge = CT_TRUE;
    } else if (word->id == KEY_WORD_OFF) {
        def->auto_purge = CT_FALSE;
    } else {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "ON or OFF expected but %s found", W2S(word));
        return CT_ERROR;
    }

    if (lex_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_parse_shrink_spc_clause(sql_stmt_t *stmt, word_t *word, knl_altspace_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    int64 max_size = (int64)CT_MAX_SPACE_FILES * g_instance->kernel.attr.page_size * CT_MAX_DATAFILE_PAGES;
    def->action = ALTSPACE_SHRINK_SPACE;

    CT_RETURN_IFERR(lex_expected_fetch_word2(lex, "space", "keep"));
    CT_RETURN_IFERR(lex_expected_fetch_size(lex, &def->shrink.keep_size, CT_MIN_USER_DATAFILE_SIZE, max_size));

    return lex_fetch(lex, word);
}

static status_t sql_parse_extend_segments(sql_stmt_t *stmt, knl_altspace_def_t *def, word_t *word)
{
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(KNL_SESSION(stmt));
    uint32 undo_segments = core_ctrl->undo_segments;
    lex_t *lex = stmt->session->lex;
    uint32 text_len;
    uint32 num = 0;

    if (lex_match_head(&word->text, "SEGMENTS", &text_len) && (text_len == strlen("SEGMENTS"))) {
        if (def->datafiles.count > 1) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "extend undo segments only supports one file ");
            return CT_ERROR;
        }

        if (lex_fetch(lex, word) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (word->type == WORD_TYPE_NUMBER) {
            if (cm_text2uint32((text_t *)&word->text, &num) != CT_SUCCESS) {
                cm_reset_error();
                CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "invalid segments number");
                return CT_ERROR;
            }
            if (num < 1 || num + undo_segments > CT_MAX_UNDO_SEGMENT) {
                CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "invalid segments number");
                return CT_ERROR;
            }
        } else {
            CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "number expected but %s found", W2S(word));
            return CT_ERROR;
        }

        if (lex_fetch(lex, word) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    def->undo_segments = num;

    return CT_SUCCESS;
}

status_t sql_parse_punch_spc_clause(sql_stmt_t *stmt, word_t *word, knl_altspace_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    int64 punc_size;
    bool32 result = CT_FALSE;
    def->action = ALTSPACE_PUNCH;

    if (lex_try_fetch(lex, "size", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!result) {
        def->punch_size = CT_INVALID_INT64;
        return lex_fetch(lex, word);
    }

    CT_RETURN_IFERR(lex_expected_fetch_size(lex, &punc_size, CT_MIN_USER_DATAFILE_SIZE, CT_MAX_PUNCH_SIZE));
    def->punch_size = punc_size;
    return lex_fetch(lex, word);
}

status_t sql_parse_alter_space(sql_stmt_t *stmt)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    knl_altspace_def_t *altspace_def = NULL;
    status_t status;

    lex->flags |= LEX_WITH_OWNER;
    stmt->context->type = CTSQL_TYPE_ALTER_TABLESPACE;

    status = sql_alloc_mem(stmt->context, sizeof(knl_altspace_def_t), (void **)&altspace_def);
    CT_RETURN_IFERR(status);

    stmt->context->entry = altspace_def;

    status = lex_expected_fetch(lex, &word);
    CT_RETURN_IFERR(status);

    if (word.id == KEY_WORD_DB) {
        altspace_def->is_for_create_db = CT_TRUE;
        status = lex_expected_fetch_variant(lex, &word);
        CT_RETURN_IFERR(status);
    } else if (IS_VARIANT(&word)) {
        altspace_def->is_for_create_db = CT_FALSE;
    } else{
        CT_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid variant/object name was found");
        return CT_ERROR;
    }
 

    status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &altspace_def->name);
    CT_RETURN_IFERR(status);

    cm_galist_init(&altspace_def->datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&altspace_def->rename_datafiles, stmt->context, sql_alloc_mem);

    status = lex_expected_fetch(lex, &word);
    CT_RETURN_IFERR(status);
    altspace_def->in_shard = CT_FALSE;

    switch ((key_wid_t)word.id) {
        case KEY_WORD_ADD:
            status = sql_parse_datafile_clause(stmt, &word, altspace_def);
            break;
        case KEY_WORD_DROP:
            status = sql_parse_drop_datafile_clause(stmt, &word, altspace_def);
            break;
        case KEY_WORD_AUTOEXTEND:
            status = sql_parse_autoextend_clause(stmt, &word, altspace_def);
            break;
        case KEY_WORD_AUTOOFFLINE:
            status = sql_parse_autooffline_clause(stmt, &word, altspace_def);
            break;
        case KEY_WORD_RENAME:
            status = sql_parse_rename_clause(stmt, &word, altspace_def);
            break;
        case KEY_WORD_OFFLINE:
            status = sql_parse_offline_clause(stmt, &word, altspace_def);
            break;
        case KEY_WORD_AUTOPURGE:
            status = sql_parse_autopurge_clause(stmt, &word, altspace_def);
            break;
        case KEY_WORD_SHRINK:
            status = sql_parse_shrink_spc_clause(stmt, &word, altspace_def);
            break;
        case KEY_WORD_PUNCH:
            status = sql_parse_punch_spc_clause(stmt, &word, altspace_def);
            break;
        default:
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(&word));
            status = CT_ERROR;
            break;
    }

    if (sql_parse_extend_segments(stmt, altspace_def, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type != WORD_TYPE_EOF) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "expected end but \"%s\" found", W2S(&word));
        return CT_ERROR;
    }

    return status;
}


static status_t sql_parse_drop_tablespace_opt(lex_t *lex, knl_drop_space_def_t *def)
{
    status_t status;
    bool32 result = CT_FALSE;
    uint32 mid;

    status = lex_try_fetch(lex, "including", &result);
    CT_RETURN_IFERR(status);

    if (result) {
        status = lex_expected_fetch_word(lex, "contents");
        CT_RETURN_IFERR(status);
        def->options |= TABALESPACE_INCLUDE;

        status = lex_try_fetch_1of2(lex, "and", "keep", &mid);
        CT_RETURN_IFERR(status);

        def->options |= TABALESPACE_DFS_AND;
        if (mid != CT_INVALID_ID32) {
            status = lex_expected_fetch_word(lex, "datafiles");
            CT_RETURN_IFERR(status);
            if (mid == 1) {
                def->options &= ~TABALESPACE_DFS_AND;
            }
        }

        status = lex_try_fetch(lex, "cascade", &result);
        CT_RETURN_IFERR(status);

        if (result) {
            status = lex_expected_fetch_word(lex, "constraints");
            CT_RETURN_IFERR(status);
            def->options |= TABALESPACE_CASCADE;
        }
    }

    return CT_SUCCESS;
}

status_t sql_parse_drop_tablespace(sql_stmt_t *stmt)
{
    status_t status;
    word_t word;
    lex_t *lex = stmt->session->lex;
    knl_drop_space_def_t *def = NULL;

    stmt->context->type = CTSQL_TYPE_DROP_TABLESPACE;

    status = sql_alloc_mem(stmt->context, sizeof(knl_drop_space_def_t), (void **)&def);
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch_variant(lex, &word);
    CT_RETURN_IFERR(status);

    status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->obj_name);
    CT_RETURN_IFERR(status);

    def->options = 0;
    status = sql_parse_drop_tablespace_opt(lex, def);
    CT_RETURN_IFERR(status);

    status = lex_fetch(lex, &word);
    CT_RETURN_IFERR(status);
    if (word.type != WORD_TYPE_EOF) {
        CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "invalid or duplicate drop tablespace option");
        return CT_ERROR;
    }

    stmt->context->entry = def;
    return CT_SUCCESS;
}

status_t sql_parse_purge_tablespace(sql_stmt_t *stmt, knl_purge_def_t *def)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    status_t status;

    lex->flags = LEX_SINGLE_WORD;
    stmt->context->entry = def;

    status = lex_expected_fetch_variant(lex, &word);
    CT_RETURN_IFERR(status);

    status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->name);
    CT_RETURN_IFERR(status);

    status = lex_expected_end(lex);
    CT_RETURN_IFERR(status);

    def->type = PURGE_TABLESPACE;

    return CT_SUCCESS;
}


static status_t sql_rebuild_ctrlfile_parse_filelist(sql_stmt_t *stmt, galist_t *filelist, word_t *word)
{
    status_t status;
    knl_device_def_t *file = NULL;
    lex_t *lex = stmt->session->lex;

    if (filelist->count != 0) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "datafile is already defined");
        return CT_ERROR;
    }

    status = lex_expected_fetch_bracket(lex, word);
    CT_RETURN_IFERR(status);

    CT_RETURN_IFERR(lex_push(lex, &word->text));

    while (CT_TRUE) {
        status = lex_expected_fetch_string(lex, word);
        CT_BREAK_IF_ERROR(status);

        status = cm_galist_new(filelist, sizeof(knl_device_def_t), (pointer_t *)&file);
        CT_BREAK_IF_ERROR(status);

        status = sql_copy_file_name(stmt->context, (text_t *)&word->text, &file->name);
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
    return lex_fetch(lex, word);
}

static status_t sql_rebuild_ctrlfile_parse_charset(sql_stmt_t *stmt, knl_rebuild_ctrlfile_def_t *def, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    if (def->charset.len != 0) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "CHARACTER SET is already defined");
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "SET") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_copy_text(stmt->context, (text_t *)&word->text, &def->charset) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_fetch(lex, word);
}

static status_t sql_rebuild_ctrlfile_parse_database(sql_stmt_t *stmt, knl_rebuild_ctrlfile_def_t *ctrlfile_def)
{
    word_t word;
    status_t status;
    status = lex_fetch(stmt->session->lex, &word);
    CT_RETURN_IFERR(status);

    while (word.type != WORD_TYPE_EOF) {
        switch (word.id) {
            case KEY_WORD_LOGFILE:
                status = sql_rebuild_ctrlfile_parse_filelist(stmt, &ctrlfile_def->logfiles, &word);
                break;

            case KEY_WORD_DATAFILE:
                status = sql_rebuild_ctrlfile_parse_filelist(stmt, &ctrlfile_def->datafiles, &word);
                break;

            case KEY_WORD_CHARSET:
                status = sql_rebuild_ctrlfile_parse_charset(stmt, ctrlfile_def, &word);
                break;

            case KEY_WORD_ARCHIVELOG:
                ctrlfile_def->arch_mode = ARCHIVE_LOG_ON;
                status = lex_fetch(stmt->session->lex, &word);
                break;

            case KEY_WORD_NOARCHIVELOG:
                ctrlfile_def->arch_mode = ARCHIVE_LOG_OFF;
                status = lex_fetch(stmt->session->lex, &word);
                break;

            default:
                CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(&word));
                return CT_ERROR;
        }

        if (status != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t sql_parse_create_ctrlfiles(sql_stmt_t *stmt)
{
    status_t status;
    knl_rebuild_ctrlfile_def_t *ctrlfile_def = NULL;

    status = sql_alloc_mem(stmt->context, sizeof(knl_rebuild_ctrlfile_def_t), (pointer_t *)&ctrlfile_def);
    CT_RETURN_IFERR(status);

    stmt->context->entry = ctrlfile_def;
    stmt->context->type = CTSQL_TYPE_CREATE_CTRLFILE;

    cm_galist_init(&ctrlfile_def->logfiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&ctrlfile_def->datafiles, stmt->context, sql_alloc_mem);
    if (cm_dbs_is_enable_dbs() != CT_TRUE) {
        CT_THROW_ERROR(ERR_REBUILD_WITH_STORAGE);
        return CT_ERROR;
    }
    /* parse create ctrlfile sql statement */
    status = sql_rebuild_ctrlfile_parse_database(stmt, ctrlfile_def);
    CT_RETURN_IFERR(status);

    return CT_SUCCESS;
}
