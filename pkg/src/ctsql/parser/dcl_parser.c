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
 * dcl_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/dcl_parser.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_instance.h"
#ifdef DB_DEBUG_VERSION
#endif /* DB_DEBUG_VERSION */
#include "dcl_parser.h"
#include "dcl_database_parser.h"
#include "dcl_transaction_parser.h"
#include "dcl_alter_parser.h"
#include "expr_parser.h"
#include "ctsql_verifier.h"
#include "ddl_parser.h"
#include "table_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

static compress_algo_e compress_algo[] = {COMPRESS_ZLIB, COMPRESS_ZSTD, COMPRESS_LZ4};

static status_t sql_parse_validate_datafile_page(sql_stmt_t *stmt, knl_validate_t *param)
{
    status_t status;
    uint32 datafile;
    uint32 page;

    status = lex_expected_fetch_uint32(stmt->session->lex, &datafile);
    CT_RETURN_IFERR(status);

    if (datafile >= INVALID_FILE_ID) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "datafile value should be in [%u, %u]", (uint32)0,
            (uint32)(INVALID_FILE_ID - 1));
        return CT_ERROR;
    }

    status = lex_expected_fetch_word(stmt->session->lex, "page");
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch_uint32(stmt->session->lex, &page);
    CT_RETURN_IFERR(status);

    if (page == 0) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "page value should not be 0");
        return CT_ERROR;
    }

    param->validate_type = VALIDATE_DATAFILE_PAGE;
    param->page_id.file = datafile;
    param->page_id.page = page;
    return CT_SUCCESS;
}

static status_t sql_parse_validate(sql_stmt_t *stmt)
{
    knl_validate_t *param = NULL;
    status_t status;
    uint32 matched_id;

    status = sql_alloc_mem(stmt->context, sizeof(knl_validate_t), (void **)&param);
    CT_RETURN_IFERR(status);
    stmt->context->entry = param;

    MEMS_RETURN_IFERR(memset_s(param, sizeof(knl_validate_t), 0, sizeof(knl_validate_t)));

    status = lex_expected_fetch_1of2(stmt->session->lex, "datafile", "backupset", &matched_id);
    CT_RETURN_IFERR(status);

    if (matched_id == 0) {
        status = sql_parse_validate_datafile_page(stmt, param);
        CT_RETURN_IFERR(status);
    } else {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "validate backupset not supported");
        return CT_ERROR;
    }

    return lex_expected_end(stmt->session->lex);
}

static status_t sql_parse_compress_for_build(lex_t *lex, build_param_ctrl_t *ctrl)
{
    uint32 matched_id = CT_INVALID_ID32;
    compress_algo_e algorithm = COMPRESS_ZSTD;
    bool32 fetch_result = CT_FALSE;
    uint32 level;

    ctrl->parallelism = 0;
    ctrl->is_increment = CT_FALSE;
    ctrl->base_lsn = 0;

    if (ctrl->is_repair) {
        return CT_SUCCESS;
    }

    if (lex_try_fetch(lex, "incremental", &fetch_result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (fetch_result) {
        ctrl->is_increment = CT_TRUE;
    }

    if (lex_try_fetch(lex, "compress", &fetch_result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!fetch_result) {
        ctrl->compress = COMPRESS_NONE;
        return CT_SUCCESS;
    }

    if (lex_try_fetch_1of3(lex, "zlib", "zstd", "lz4", &matched_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (matched_id != CT_INVALID_ID32) {
        algorithm = compress_algo[matched_id];
    }

    ctrl->compress = algorithm;

    if (lex_try_fetch(lex, "level", &fetch_result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!fetch_result) {
        ctrl->compress_level = Z_BEST_SPEED; // level 1 with best speed
        return CT_SUCCESS;
    }

    if (lex_expected_fetch_uint32(lex, &level) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (level < Z_BEST_SPEED || level > Z_BEST_COMPRESSION) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "level value should be in [1, 9]");
        return CT_ERROR;
    }
    ctrl->compress_level = level;

    return CT_SUCCESS;
}

static status_t sql_parse_paral_for_build(lex_t *lex, build_param_ctrl_t *ctrl)
{
    bool32 fetch_result = CT_FALSE;
    uint32 paral_num;

    if (lex_try_fetch(lex, "parallelism", &fetch_result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!fetch_result) {
        ctrl->parallelism = 0;
        return CT_SUCCESS;
    }

    if (lex_expected_fetch_uint32(lex, &paral_num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (paral_num < 1 || paral_num > (CT_MAX_BACKUP_PROCESS - BAK_PARAL_LOG_PROC_NUM - 1)) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "parallelism value should be in [%u, %u]", (uint32)1,
            (uint32)(CT_MAX_BACKUP_PROCESS - BAK_PARAL_LOG_PROC_NUM - 1));
        return CT_ERROR;
    }

    ctrl->parallelism = paral_num;
    return CT_SUCCESS;
}

static status_t sql_parse_buffer_for_build(lex_t *lex, build_param_ctrl_t *ctrl)
{
    int64 size;
    bool32 fetch_result = CT_FALSE;

    if (lex_try_fetch(lex, "buffer", &fetch_result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!fetch_result) {
        ctrl->buffer_size = 0;
        return CT_SUCCESS;
    }

    if (lex_expected_fetch_word(lex, "size") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_size(lex, &size, CT_MIN_BACKUP_BUF_SIZE, CT_MAX_BACKUP_BUF_SIZE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ctrl->buffer_size = size;

    if (ctrl->buffer_size < CT_MIN_BACKUP_BUF_SIZE || ctrl->buffer_size > CT_MAX_BACKUP_BUF_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "BACKUP_BUFFER_SIZE", (int64)CT_MIN_BACKUP_BUF_SIZE,
            (int64)CT_MAX_BACKUP_BUF_SIZE);
        return CT_ERROR;
    }

    if (ctrl->buffer_size % (uint32)SIZE_M(8) != 0) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "buffer size (%u) is not an integral multiple of 8M.",
            ctrl->buffer_size);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_parse_build(sql_stmt_t *stmt)
{
    word_t word;
    knl_build_def_t *param = NULL;
    lex_t *lex = stmt->session->lex;
    uint32 buffer_size = (uint32)stmt->session->knl_session.kernel->attr.backup_buf_size;

    if (sql_alloc_mem(stmt->context, sizeof(knl_build_def_t), (void **)&param) != CT_SUCCESS) {
        return CT_ERROR;
    }

    stmt->context->entry = param;

    if (lex_expected_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    switch ((key_wid_t)word.id) {
        case KEY_WORD_DATABASE:
            param->build_type = BUILD_AUTO;
            break;

        case KEY_WORD_CASCADED:
            param->build_type = BUILD_CASCADED_STANDBY;
            if (lex_expected_fetch_word(lex, "standby") != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (lex_expected_fetch_word(lex, "database") != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;

        case KEY_WORD_STANDBY:
            param->build_type = BUILD_STANDBY;
            if (lex_expected_fetch_word(lex, "database") != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;

        case KEY_WORD_REPAIR:
            param->build_type = BUILD_AUTO;
            param->param_ctrl.is_repair = CT_TRUE;
            if (lex_expected_fetch_word(lex, "database") != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;

        default:
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unexpectd word %s for build", W2S(&word));
            return CT_ERROR;
    }

    if (sql_parse_compress_for_build(lex, &param->param_ctrl) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_parse_paral_for_build(lex, &param->param_ctrl) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_parse_buffer_for_build(lex, &param->param_ctrl) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (param->param_ctrl.buffer_size == 0) {
        param->param_ctrl.buffer_size = buffer_size;
    }

    return lex_expected_end(lex);
}

#ifdef DB_DEBUG_VERSION
static status_t sql_parse_syncpoint_signal_wait(sql_stmt_t *stmt, lex_t *lex, syncpoint_def_t *def)
{
    status_t status;
    word_t word;
    int32 count;

    status = lex_fetch(lex, &word);
    CT_RETURN_IFERR(status);

    switch ((key_wid_t)word.id) {
        case KEY_WORD_WAIT:
            if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
                CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "signal name expected but %s found",
                    W2S(&word));
                return CT_ERROR;
            }
            status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->wait_for);
            CT_RETURN_IFERR(status);
            break;

        case KEY_WORD_SIGNAL:
            if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
                CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "signal name expected but %s found",
                    W2S(&word));
                return CT_ERROR;
            }

            status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->signal);
            CT_RETURN_IFERR(status);

            if (lex_expected_fetch_word(lex, "RAISE") != CT_SUCCESS) {
                if (lex_expected_end(lex) != CT_SUCCESS) {
                    CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "raise expected");
                    return CT_ERROR;
                }

                def->raise_count = 1;
                return CT_SUCCESS;
            }

            if (lex_expected_fetch_int32(lex, &count) != CT_SUCCESS) {
                CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "raise count not found");
                return CT_ERROR;
            }

            if (count < 1) {
                CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "raise count %d, should larger than 1",
                    count);
                return CT_ERROR;
            }

            def->raise_count = (uint32)count;
            break;
        case KEY_WORD_SET:
            if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
                CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "enable expected true/false but %s found",
                    W2S(&word));
                return CT_ERROR;
            }
            if (cm_compare_str_ins(W2S(&word), "enable") && cm_compare_str_ins(W2S(&word), "disable")) {
                CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "set expected enable/disable but %s found",
                    W2S(&word));
                return CT_ERROR;
            }
            status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->enable);
            CT_RETURN_IFERR(status);
            if (lex_expected_fetch_word(lex, "RAISE") != CT_SUCCESS) {
                if (lex_expected_end(lex) != CT_SUCCESS) {
                    CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "raise expected");
                    return CT_ERROR;
                }
                def->raise_count = 1;
                return CT_SUCCESS;
            }

            if (lex_expected_fetch_int32(lex, &count) != CT_SUCCESS) {
                CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "raise count not found");
                return CT_ERROR;
            }

            if (count < 1) {
                CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "raise count %d, should larger than 1",
                    count);
                return CT_ERROR;
            }

            def->raise_count = (uint32)count;
            break;
        default:
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "syncpoint action expected but %s found",
                W2S(&word));
            return CT_ERROR;
    }

    return lex_expected_end(lex);
}

static status_t sql_parse_syncpoint(sql_stmt_t *stmt)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    syncpoint_def_t *def = NULL;

    stmt->context->type = CTSQL_TYPE_SYNCPOINT;

    if (sql_alloc_mem(stmt->context, sizeof(syncpoint_def_t), (void **)&def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if ((key_wid_t)word.id == KEY_WORD_RESET) {
        stmt->context->entry = def;
        return lex_expected_end(lex);
    }

    if (!IS_VARIANT(&word)) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "syncpoint name expected but %s found", W2S(&word));
        return CT_ERROR;
    }

    if (sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->syncpoint_name) != CT_SUCCESS) {
        return CT_ERROR;
    }
    stmt->context->entry = def;
    return sql_parse_syncpoint_signal_wait(stmt, lex, def);
}
#endif /* DB_DEBUG_VERSION */

#define SQL_CHECK_DUPLICATE_TABLE(stmt, list, entityTypeName, fld_schema, owner, fld_name, table_name)           \
    do {                                                                                                         \
        for (uint32 i = 0; i < (list)->count; i++) {                                                             \
            entityTypeName *entity = (entityTypeName *)cm_galist_get((list), i);                                 \
            if (cm_text_equal(&(entity->fld_schema), owner) && cm_text_equal(&(entity->fld_name), table_name)) { \
                CT_THROW_ERROR(ERR_DUPLICATE_TABLE, T2S(owner), T2S(table_name));                                \
                return CT_ERROR;                                                                                 \
            }                                                                                                    \
        }                                                                                                        \
    } while (0)

static status_t sql_parse_table_defs(sql_stmt_t *stmt, lex_t *lex, lock_tables_def_t *def)
{
    word_t word;
    lock_table_t *table = NULL;
    text_t owner, table_name;
    bool32 result = CT_FALSE;

    for (;;) {
        lex->flags |= LEX_WITH_OWNER;
        if (lex_expected_fetch_variant(lex, &word) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (sql_convert_object_name(stmt, &word, &owner, NULL, &table_name) != CT_SUCCESS) {
            return CT_ERROR;
        }

        SQL_CHECK_DUPLICATE_TABLE(stmt, (&def->tables), lock_table_t, schema, &owner, name, &table_name);

        if (cm_galist_new(&def->tables, sizeof(lock_table_t), (pointer_t *)&table) != CT_SUCCESS) {
            return CT_ERROR;
        }

        table->name = table_name;
        table->schema = owner;

        if (lex_try_fetch(lex, "in", &result) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (result) {
            break;
        }

        if (lex_fetch(lex, &word) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!IS_SPEC_CHAR(&word, ',')) {
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(&word));
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

#ifdef Z_SHARDING
// for online update
shd_lock_unlock_type_t shd_diag_lock_type(sql_stmt_t *stmt)
{
    uint32 matched_id;

    if (lex_push(stmt->session->lex, stmt->session->lex->curr_text) != CT_SUCCESS) {
        return SHD_LOCK_UNLOCK_TYPE_TALBE;
    }
    if (lex_try_fetch_1of2(stmt->session->lex, "TABLE", "NODE", &matched_id) != CT_SUCCESS) {
        lex_pop(stmt->session->lex);
        return SHD_LOCK_UNLOCK_TYPE_TALBE;
    } else {
        if (matched_id != CT_INVALID_ID32) {
            lex_pop(stmt->session->lex);
            return ((matched_id == 0) ? SHD_LOCK_UNLOCK_TYPE_TALBE : SHD_LOCK_UNLOCK_TYPE_NODE);
        }
    }
    lex_pop(stmt->session->lex);
    return SHD_LOCK_UNLOCK_TYPE_TALBE;
}

shd_lock_unlock_type_t shd_diag_unlock_type(sql_stmt_t *stmt)
{
    uint32 matched_id;

    if (lex_push(stmt->session->lex, stmt->session->lex->curr_text) != CT_SUCCESS) {
        return SHD_LOCK_UNLOCK_TYPE_TALBE;
    }
    if (lex_try_fetch_1of2(stmt->session->lex, "TABLE", "NODE", &matched_id) != CT_SUCCESS) {
        lex_pop(stmt->session->lex);
        return SHD_LOCK_UNLOCK_TYPE_TALBE;
    } else {
        if (matched_id != CT_INVALID_ID32) {
            lex_pop(stmt->session->lex);
            return ((matched_id == 0) ? SHD_LOCK_UNLOCK_TYPE_TALBE : SHD_LOCK_UNLOCK_TYPE_NODE);
        }
    }
    lex_pop(stmt->session->lex);
    return SHD_LOCK_UNLOCK_TYPE_TALBE;
}

static status_t shd_parse_lock_node(sql_stmt_t *stmt)
{
    status_t status;
    int32 wait_time;
    uint32 match_id;
    shd_lock_node_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;
    stmt->context->type = CTSQL_TYPE_LOCK_NODE;

    status = sql_alloc_mem(stmt->context, sizeof(shd_lock_node_def_t), (void **)&def);
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch_word(lex, "node");
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch_word(lex, "in");
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch_1ofn(lex, &match_id, 2, "share", "exclusive");
    CT_RETURN_IFERR(status);

    def->lock_mode = (shd_lock_node_mode_t)(match_id + 1);

    status = lex_expected_fetch_word(lex, "mode");
    CT_RETURN_IFERR(status);

    def->wait_mode = SHD_WAIT_MODE_WAIT;
    def->wait_time = CT_INVALID_ID32;

    status = lex_try_fetch_1ofn(lex, &match_id, 2, "nowait", "wait");
    CT_RETURN_IFERR(status);

    if (SHD_WAIT_MODE_NO_WAIT == match_id) {
        def->wait_mode = SHD_WAIT_MODE_NO_WAIT;
        def->wait_time = 0;
    } else if (SHD_WAIT_MODE_WAIT == match_id) {
        status = lex_expected_fetch_int32(lex, &wait_time);
        CT_RETURN_IFERR(status);

        if (wait_time < 0) {
            CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "missing or invalid WAIT interval");
            return CT_ERROR;
        }
        if (wait_time == 0) {
            def->wait_mode = SHD_WAIT_MODE_NO_WAIT;
        } else {
            def->wait_time = (uint32)wait_time;
        }
    }

    stmt->context->entry = def;
    return lex_expected_end(lex);
}


static status_t shd_parse_unlock_node(sql_stmt_t *stmt)
{
    status_t status;

    lex_t *lex = stmt->session->lex;
    stmt->context->type = CTSQL_TYPE_UNLOCK_NODE;

    status = lex_expected_fetch_word(lex, "node");
    CT_RETURN_IFERR(status);

    stmt->context->entry = NULL;
    return lex_expected_end(lex);
}

#endif

static status_t sql_parse_locktable(sql_stmt_t *stmt)
{
    status_t status;
    int32 wait_time;
    uint32 match_id;
    lock_tables_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;
    stmt->context->type = CTSQL_TYPE_LOCK_TABLE;

    status = sql_alloc_mem(stmt->context, sizeof(lock_tables_def_t), (void **)&def);
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch_word(lex, "table");
    CT_RETURN_IFERR(status);

    cm_galist_init(&def->tables, stmt->context, sql_alloc_mem);

    status = sql_parse_table_defs(stmt, lex, def);
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch_1ofn(lex, &match_id, 2, "share", "exclusive");
    CT_RETURN_IFERR(status);

    def->lock_mode = (lock_table_mode_t)match_id;

    status = lex_expected_fetch_word(lex, "mode");
    CT_RETURN_IFERR(status);
    /*
    If you specify neither NOWAIT nor WAIT, then the database waits indefinitely until the
    table is available, locks it, and returns control to you. When the database is executing
    DDL statements concurrently with DML statements, a timeout or deadlock can
    sometimes result. The database detects such timeouts and deadlocks and returns an
    error.
    */
    def->wait_mode = WAIT_MODE_WAIT;
    def->wait_time = CT_INVALID_ID32;

    status = lex_try_fetch_1ofn(lex, &match_id, 2, "nowait", "wait");
    CT_RETURN_IFERR(status);

    if (WAIT_MODE_NO_WAIT == match_id) {
        def->wait_mode = WAIT_MODE_NO_WAIT;
        def->wait_time = 0;
    } else if (WAIT_MODE_WAIT == match_id) {
        status = lex_expected_fetch_int32(lex, &wait_time);
        CT_RETURN_IFERR(status);

        if (wait_time < 0) {
            CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "missing or invalid WAIT interval");
            return CT_ERROR;
        }
        if (wait_time == 0) {
            def->wait_mode = WAIT_MODE_NO_WAIT;
        } else {
            def->wait_time = (uint32)wait_time;
        }
    }

    stmt->context->entry = def;
    return lex_expected_end(lex);
}

#ifdef Z_SHARDING
static status_t sql_init_route(sql_stmt_t *stmt, sql_route_t *route_ctx)
{
    if (sql_create_list(stmt, &route_ctx->pairs) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(sql_table_t), (void **)&route_ctx->rule) != CT_SUCCESS) {
        return CT_ERROR;
    }

    route_ctx->pairs_count = 0;
    return CT_SUCCESS;
}

static status_t sql_try_parse_route_pair(sql_stmt_t *stmt, lex_t *lex, sql_route_t *route_ctx, word_t *word)
{
    column_value_pair_t *pair = NULL;

    CT_RETURN_IFERR(lex_expected_fetch_variant(lex, word));
    CT_RETURN_IFERR(cm_galist_new(route_ctx->pairs, sizeof(column_value_pair_t), (pointer_t *)&pair));
    CT_RETURN_IFERR(sql_create_list(stmt, &pair->exprs));

    if (word->type == WORD_TYPE_DQ_STRING) {
        pair->column_name_has_quote = CT_TRUE;
    }
    return sql_copy_object_name_loc(stmt->context, word->type, &word->text, &pair->column_name);
}

static status_t sql_try_parse_route_columns(sql_stmt_t *stmt, sql_route_t *route_ctx, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    bool32 result = CT_FALSE;

    if (word->type != WORD_TYPE_BRACKET) {
        return CT_SUCCESS;
    }

    lex_remove_brackets(&word->text);

    CT_RETURN_IFERR(lex_push(lex, &word->text));
    if (lex_try_fetch(lex, "SELECT", &result) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    if (result) {
        lex_pop(lex);
        return CT_SUCCESS;
    }

    for (;;) {
        lex->flags = LEX_SINGLE_WORD;
        if (sql_try_parse_route_pair(stmt, lex, route_ctx, word) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }

        if (lex_fetch(lex, word) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        if (word->type == WORD_TYPE_EOF) {
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            lex_pop(lex);
            CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
            return CT_ERROR;
        }
    }

    lex_pop(lex);
    route_ctx->cols_specified = CT_TRUE;
    return lex_fetch(lex, word);
}

static status_t sql_parse_single_route_core(sql_stmt_t *stmt, sql_route_t *route_ctx, word_t *word, bool32 is_first,
    lex_t *lex)
{
    uint32 pair_id = 0;
    column_value_pair_t *pair = NULL;
    expr_tree_t *expr = NULL;

    for (;;) {
        lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;

        if (route_ctx->cols_specified) {
            if (pair_id > route_ctx->pairs->count - 1) {
                CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "text end expected but %s found",
                    W2S(word));
                return CT_ERROR;
            }

            pair = (column_value_pair_t *)cm_galist_get(route_ctx->pairs, pair_id);
        } else {
            if (is_first) {
                CT_RETURN_IFERR(cm_galist_new(route_ctx->pairs, sizeof(column_value_pair_t), (pointer_t *)&pair));
                CT_RETURN_IFERR(sql_create_list(stmt, &pair->exprs));
            } else {
                pair = (column_value_pair_t *)cm_galist_get(route_ctx->pairs, pair_id);
            }
        }

        CT_RETURN_IFERR(sql_create_expr_until(stmt, &expr, word));
        CT_RETURN_IFERR(cm_galist_insert(pair->exprs, expr));

        pair_id++;

        CT_BREAK_IF_TRUE(word->type == WORD_TYPE_EOF);

        if (!IS_SPEC_CHAR(word, ',')) {
            CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
            return CT_ERROR;
        }
    }

    if (pair_id != route_ctx->pairs->count) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "more value expressions expected");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_parse_single_route_values(sql_stmt_t *stmt, sql_route_t *route_ctx, word_t *word, bool32 is_first)
{
    lex_t *lex = stmt->session->lex;

    CT_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    CT_RETURN_IFERR(lex_push(lex, &word->text));
    if (sql_parse_single_route_core(stmt, route_ctx, word, is_first, lex) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    lex_pop(lex);
    return lex_fetch(stmt->session->lex, word);
}

static status_t sql_parse_route_values(sql_stmt_t *stmt, sql_route_t *route_ctx, word_t *word)
{
    bool32 is_first = CT_TRUE;

    if (word->id != KEY_WORD_VALUES) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "VALUES expected but %s found", W2S(word));
        return CT_ERROR;
    }

    for (;;) {
        CT_RETURN_IFERR(sql_parse_single_route_values(stmt, route_ctx, word, is_first));
        route_ctx->pairs_count++;

        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }

        // insert into t1(f1, f2) values(1,2),(3,4),(5,6)...
        is_first = CT_FALSE;
    }

    return CT_SUCCESS;
}


status_t sql_create_route_context(sql_stmt_t *stmt, sql_route_t **route_ctx)
{
    lex_t *lex = stmt->session->lex;
    word_t word;
    sql_table_t *rule = NULL;

    uint32 matched_id;

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(sql_route_t), (void **)route_ctx));

    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "by"));

    CT_RETURN_IFERR(lex_expected_fetch_1of3(lex, "rule", "node", "null", &matched_id));

    switch (matched_id) {
        case LEX_MATCH_FIRST_WORD: {
            (*route_ctx)->type = SHD_ROUTE_BY_RULE;

            CT_RETURN_IFERR(sql_init_route(stmt, *route_ctx));

            rule = (*route_ctx)->rule;
            rule->is_distribute_rule = CT_TRUE;

            CT_RETURN_IFERR(sql_parse_table(stmt, rule, &word));
            CT_RETURN_IFERR(sql_try_parse_route_columns(stmt, *route_ctx, &word));
            CT_RETURN_IFERR(sql_parse_route_values(stmt, *route_ctx, &word));

            if (word.type != WORD_TYPE_EOF) {
                CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "text end expected but %s found", W2S(&word));
                return CT_ERROR;
            }
            break;
        }
        case LEX_MATCH_SECOND_WORD:
            (*route_ctx)->type = SHD_ROUTE_BY_NODE;
            uint32 group_id = 0;

            CT_RETURN_IFERR(lex_expected_fetch_uint32(lex, &group_id));

            (*route_ctx)->group_id = group_id;

            CT_RETURN_IFERR(lex_fetch(lex, &word));
            if (word.type != WORD_TYPE_EOF) {
                CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "text end expected but %s found", W2S(&word));
                return CT_ERROR;
            }
            break;
        case LEX_MATCH_THIRD_WORD:
            (*route_ctx)->type = SHD_ROUTE_BY_NULL;
            CT_RETURN_IFERR(lex_fetch(lex, &word));
            if (word.type != WORD_TYPE_EOF) {
                CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "text end expected but %s found", W2S(&word));
                return CT_ERROR;
            }
            break;
        default:
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_parse_route(sql_stmt_t *stmt)
{
    CT_LOG_DEBUG_INF("Begin direct route");

    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
        sql_context_t *ctx = stmt->context;

        sql_route_t **route_ctx = (sql_route_t **)&(ctx->entry);

        CT_RETURN_IFERR(sql_create_route_context(stmt, route_ctx));

        if ((*route_ctx)->type == SHD_ROUTE_BY_RULE) {
            return sql_verify_route(stmt, (sql_route_t *)stmt->context->entry);
        }

        return CT_SUCCESS;
    } else {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "ROUTE is only supported at Coordinator Node.");
        return CT_ERROR;
    }
}
#endif

status_t sql_parse_dcl(sql_stmt_t *stmt, key_wid_t key_wid)
{
    status_t status;

    stmt->session->sql_audit.audit_type = SQL_AUDIT_DCL;
    status = sql_alloc_context(stmt);
    CT_RETURN_IFERR(status);

    switch (key_wid) {
        case KEY_WORD_PREPARE:
            status = sql_parse_commit_phase1(stmt);
            break;
        case KEY_WORD_ALTER:
            status = sql_parse_dcl_alter(stmt);
            break;
        case KEY_WORD_COMMIT:
            status = sql_parse_commit(stmt);
            break;
        case KEY_WORD_ROLLBACK:
            status = sql_parse_rollback(stmt);
            break;
        case KEY_WORD_SAVEPOINT:
            status = sql_parse_savepoint(stmt);
            break;
        case KEY_WORD_RELEASE:
            status = sql_parse_release_savepoint(stmt);
            break;
        case KEY_WORD_SET:
            status = sql_parse_set(stmt);
            break;
        case KEY_WORD_BACKUP:
            stmt->context->type = CTSQL_TYPE_BACKUP;
            status = sql_parse_backup(stmt);
            break;
        case KEY_WORD_RESTORE:
            stmt->context->type = CTSQL_TYPE_RESTORE;
            status = sql_parse_restore(stmt);
            break;
        case KEY_WORD_RECOVER:
            stmt->context->type = CTSQL_TYPE_RECOVER;
            status = sql_parse_recover(stmt);
            break;
        case KEY_WORD_DAAC:
            stmt->context->type = CTSQL_TYPE_DAAC;
            status = sql_parse_daac(stmt);
            break;
        case KEY_WORD_SHUTDOWN:
            stmt->context->type = CTSQL_TYPE_SHUTDOWN;
            return sql_parse_shutdown(stmt);
        case KEY_WORD_BUILD:
            stmt->context->type = CTSQL_TYPE_BUILD;
            return sql_parse_build(stmt);

#ifdef DB_DEBUG_VERSION
        case KEY_WORD_SYNCPOINT:
            stmt->context->type = CTSQL_TYPE_SYNCPOINT;
            status = sql_parse_syncpoint(stmt);
            break;
#endif /* DB_DEBUG_VERSION */
        case KEY_WORD_LOCK:
                stmt->context->type = CTSQL_TYPE_LOCK_TABLE;
                status = sql_parse_locktable(stmt);
            break;
        case KEY_WORD_CHECKPOINT:
            stmt->context->type = CTSQL_TYPE_CHECKPOINT;
            status = lex_expected_end(stmt->session->lex);
            break;
        case KEY_WORD_VALIDATE:
            stmt->context->type = CTSQL_TYPE_VALIDATE;
            status = sql_parse_validate(stmt);
            break;

        default:
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected");
            status = CT_ERROR;
            break;
    }

    return status;
}

#ifdef __cplusplus
}
#endif
