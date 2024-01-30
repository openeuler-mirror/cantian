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
 * ctsql_context.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/ctsql_context.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_context.h"
#include "pl_context.h"
#include "srv_instance.h"
#include "ctsql_privilege.h"
#include "pragma.h"
#include "pl_udt.h"
#include "pl_memory.h"
#include "gdv_context.h"

#ifdef __cplusplus
extern "C" {
#endif

bool8 g_subselect_flags[] = { CT_FALSE, CT_TRUE, CT_TRUE, CT_FALSE, CT_FALSE, CT_TRUE, CT_FALSE };

/* object name case sensitive sql types */
static const sql_type_t g_cs_sql_types[] = {
    CTSQL_TYPE_SELECT,
    CTSQL_TYPE_UPDATE,
    CTSQL_TYPE_INSERT,
    CTSQL_TYPE_DELETE,
    CTSQL_TYPE_MERGE,
    CTSQL_TYPE_REPLACE,
    CTSQL_TYPE_LOCK_TABLE,
    CTSQL_TYPE_CREATE_SEQUENCE,
    CTSQL_TYPE_CREATE_TABLESPACE,
    CTSQL_TYPE_CREATE_TABLE,
    CTSQL_TYPE_CREATE_INDEX,
    CTSQL_TYPE_CREATE_VIEW,
    CTSQL_TYPE_CREATE_SYNONYM,
    CTSQL_TYPE_DROP_SEQUENCE,
    CTSQL_TYPE_DROP_TABLESPACE,
    CTSQL_TYPE_DROP_TABLE,
    CTSQL_TYPE_DROP_INDEX,
    CTSQL_TYPE_DROP_VIEW,
    CTSQL_TYPE_DROP_SYNONYM,
    CTSQL_TYPE_TRUNCATE_TABLE,
    CTSQL_TYPE_PURGE,
    CTSQL_TYPE_COMMENT,
    CTSQL_TYPE_FLASHBACK_TABLE,
    CTSQL_TYPE_ALTER_SEQUENCE,
    CTSQL_TYPE_ALTER_TABLESPACE,
    CTSQL_TYPE_ALTER_TABLE,
    CTSQL_TYPE_ALTER_INDEX,
    CTSQL_TYPE_ALTER_TRIGGER,
    CTSQL_TYPE_ANALYSE_TABLE,
    CTSQL_TYPE_ANONYMOUS_BLOCK,
    CTSQL_TYPE_CREATE_PROC,
    CTSQL_TYPE_CREATE_FUNC,
    CTSQL_TYPE_CREATE_TRIG,
    CTSQL_TYPE_CREATE_PACK_SPEC,
    CTSQL_TYPE_CREATE_PACK_BODY,
    CTSQL_TYPE_DROP_PROC,
    CTSQL_TYPE_DROP_FUNC,
    CTSQL_TYPE_DROP_TRIG,
    CTSQL_TYPE_DROP_PACK_SPEC,
    CTSQL_TYPE_DROP_PACK_BODY,
    CTSQL_TYPE_CREATE_USER,
    CTSQL_TYPE_ALTER_USER,
    CTSQL_TYPE_CREATE_CHECK_FROM_TEXT,
    CTSQL_TYPE_CREATE_EXPR_FROM_TEXT,
    CTSQL_TYPE_CREATE_TYPE_SPEC,
    CTSQL_TYPE_CREATE_TYPE_BODY,
    CTSQL_TYPE_DROP_TYPE_SPEC,
    CTSQL_TYPE_DROP_TYPE_BODY,
    CTSQL_TYPE_BACKUP,
    CTSQL_TYPE_RESTORE,
    CTSQL_TYPE_CREATE_INDEXES,
};
static const uint32 g_cs_type_count = sizeof(g_cs_sql_types) / sizeof(sql_type_t);

ack_sender_t *sql_get_pl_sender(void)
{
    return &g_instance->sql.pl_sender;
}

void sql_create_sender(void)
{
    ack_sender_t *sql_sender = &g_instance->sql.sender;
    sql_sender->init = (init_sender_t)sql_init_sender;
    sql_sender->send_result_success = (send_result_success_t)sql_send_result_success;
    sql_sender->send_result_error = (send_result_error_t)sql_send_result_error;
    sql_sender->send_exec_begin = (send_exec_begin_t)sql_send_exec_begin;
    sql_sender->send_exec_end = (send_exec_end_t)sql_send_exec_end;
    sql_sender->send_import_rows = (send_import_rows_t)sql_send_import_rows;
    sql_sender->send_fetch_begin = (send_fetch_begin_t)sql_send_fetch_begin;
    sql_sender->send_fetch_end = (send_fetch_end_t)sql_send_fetch_end;
    sql_sender->init_row = (init_sender_row_t)sql_init_sender_row;
    sql_sender->send_row_begin = (send_row_begin_t)sql_send_row_begin;
    sql_sender->send_row_end = (send_row_end_t)sql_send_row_end;
    sql_sender->send_row_data = (send_row_data_t)sql_send_row_entire;
    sql_sender->send_parsed_stmt = (send_parsed_stmt_t)sql_send_parsed_stmt;
    sql_sender->send_column_null = (send_column_null_t)sql_send_column_null;
    sql_sender->send_column_uint32 = (send_column_uint32_t)sql_send_column_uint32;
    sql_sender->send_column_int32 = (send_column_int32_t)sql_send_column_int32;
    sql_sender->send_column_int64 = (send_column_int64_t)sql_send_column_int64;
    sql_sender->send_column_real = (send_column_real_t)sql_send_column_real;
    sql_sender->send_column_date = (send_column_date_t)sql_send_column_date;
    sql_sender->send_column_ts = (send_column_ts_t)sql_send_column_ts;
    sql_sender->send_column_tstz = (send_column_ts_tz_t)sql_send_column_tstz;
    sql_sender->send_column_tsltz = (send_column_ts_ltz_t)sql_send_column_tsltz;
    sql_sender->send_column_str = (send_column_str_t)sql_send_column_str;
    sql_sender->send_column_text = (send_column_text_t)sql_send_column_text;
    sql_sender->send_column_bin = (send_column_bin_t)sql_send_column_bin; // cooperate pl distinguish bin and raw
    sql_sender->send_column_raw = (send_column_bin_t)sql_send_column_bin; // cooperate pl distinguish bin and raw
    sql_sender->send_column_decimal = (send_column_decimal_t)sql_send_column_decimal;
    sql_sender->send_column_decimal2 = (send_column_decimal2_t)sql_send_column_decimal2;
    sql_sender->send_column_clob = (send_column_lob_t)sql_send_column_lob;
    sql_sender->send_column_blob = (send_column_lob_t)sql_send_column_lob;
    sql_sender->send_column_bool = (send_column_bool_t)sql_send_column_int32;
    sql_sender->send_column_ymitvl = (send_column_ymitvl_t)sql_send_column_ysintvl;
    sql_sender->send_column_dsitvl = (send_column_dsitvl_t)sql_send_column_dsintvl;
    sql_sender->send_serveroutput = (send_serveroutput_t)sql_send_serveroutput;
    sql_sender->send_return_result = (send_return_result_t)sql_send_return_result;
    sql_sender->send_column_cursor = (send_column_cursor_t)sql_send_column_cursor;
    sql_sender->send_column_def = (send_column_def_t)sql_send_column_def;
    sql_sender->send_column_array = (send_column_array_t)sql_send_column_array;
    sql_sender->send_return_value = (send_return_value_t)sql_send_return_values;
    sql_sender->send_nls_feedback = (send_nls_feedback_t)sql_send_nls_feedback;
    sql_sender->send_session_tz_feedback = (send_session_tz_feedback_t)sql_send_session_tz_feedback;

    sql_sender = &g_instance->sql.pl_sender;
    sql_sender->init = (init_sender_t)pl_init_sender;
    sql_sender->send_result_success = (send_result_success_t)pl_send_result_success;
    sql_sender->send_result_error = (send_result_error_t)pl_send_result_error;
    sql_sender->send_exec_begin = (send_exec_begin_t)pl_send_exec_begin;
    sql_sender->send_exec_end = (send_exec_end_t)pl_send_exec_end;
    sql_sender->send_import_rows = (send_import_rows_t)pl_send_import_rows;
    sql_sender->send_fetch_begin = (send_fetch_begin_t)pl_send_fetch_begin;
    sql_sender->send_fetch_end = (send_fetch_end_t)pl_send_fetch_end;
    sql_sender->init_row = (init_sender_row_t)pl_init_sender_row;
    sql_sender->send_row_begin = (send_row_begin_t)pl_send_row_begin;
    sql_sender->send_row_end = (send_row_end_t)pl_send_row_end;
    sql_sender->send_row_data = (send_row_data_t)pl_send_row_entire;
    sql_sender->send_parsed_stmt = (send_parsed_stmt_t)pl_send_parsed_stmt;
    sql_sender->send_column_null = (send_column_null_t)pl_send_column_null;
    sql_sender->send_column_uint32 = (send_column_uint32_t)pl_send_column_uint32;
    sql_sender->send_column_int32 = (send_column_int32_t)pl_send_column_int32;
    sql_sender->send_column_int64 = (send_column_int64_t)pl_send_column_int64;
    sql_sender->send_column_real = (send_column_real_t)pl_send_column_real;
    sql_sender->send_column_date = (send_column_date_t)pl_send_column_date;
    sql_sender->send_column_ts = (send_column_ts_t)pl_send_column_ts;
    sql_sender->send_column_tstz = (send_column_ts_tz_t)pl_send_column_tstz;
    sql_sender->send_column_tsltz = (send_column_ts_ltz_t)pl_send_column_tsltz;
    sql_sender->send_column_str = (send_column_str_t)pl_send_column_str;
    sql_sender->send_column_text = (send_column_text_t)pl_send_column_text;
    sql_sender->send_column_bin = (send_column_bin_t)pl_send_column_bin;
    sql_sender->send_column_raw = (send_column_bin_t)pl_send_column_raw;
    sql_sender->send_column_decimal = (send_column_decimal_t)pl_send_column_decimal;
    sql_sender->send_column_decimal2 = (send_column_decimal2_t)pl_send_column_decimal;
    sql_sender->send_column_clob = (send_column_lob_t)pl_send_column_clob;
    sql_sender->send_column_blob = (send_column_lob_t)pl_send_column_blob;
    sql_sender->send_column_bool = (send_column_bool_t)pl_send_column_int32;
    sql_sender->send_column_ymitvl = (send_column_ymitvl_t)pl_send_column_yminterval;
    sql_sender->send_column_dsitvl = (send_column_dsitvl_t)pl_send_column_dsinterval;
    sql_sender->send_serveroutput = (send_serveroutput_t)pl_send_serveroutput;
    sql_sender->send_return_result = (send_return_result_t)pl_send_return_result;
    sql_sender->send_column_cursor = (send_column_cursor_t)pl_send_column_cursor;
    sql_sender->send_column_def = (send_column_def_t)pl_send_column_def;
    sql_sender->send_column_array = (send_column_array_t)pl_send_column_array;
    sql_sender->send_return_value = (send_return_value_t)pl_send_return_value;
    sql_sender->send_nls_feedback = (send_nls_feedback_t)pl_send_nls_feedback;
    sql_sender->send_session_tz_feedback = (send_session_tz_feedback_t)pl_send_session_tz_feedback;

    sql_sender = &g_instance->sql.gdv_sender;
    sql_sender->init = (init_sender_t)gdv_init_sender;
    sql_sender->send_result_success = (send_result_success_t)gdv_send_result_success;
    sql_sender->send_result_error = (send_result_error_t)gdv_send_result_error;
    sql_sender->send_exec_begin = (send_exec_begin_t)gdv_send_exec_begin;
    sql_sender->send_exec_end = (send_exec_end_t)gdv_send_exec_end;
    sql_sender->send_fetch_begin = (send_fetch_begin_t)gdv_send_fetch_begin;
    sql_sender->send_fetch_end = (send_fetch_end_t)gdv_send_fetch_end;
    sql_sender->init_row = (init_sender_row_t)gdv_init_sender_row;
    sql_sender->send_row_begin = (send_row_begin_t)gdv_send_row_begin;
    sql_sender->send_row_end = (send_row_end_t)gdv_send_row_end;
    sql_sender->send_row_data = (send_row_data_t)gdv_send_row_entire;
    sql_sender->send_parsed_stmt = (send_parsed_stmt_t)gdv_send_parsed_stmt;

    sql_sender->send_column_null = (send_column_null_t)sql_send_column_null;
    sql_sender->send_column_uint32 = (send_column_uint32_t)sql_send_column_uint32;
    sql_sender->send_column_int32 = (send_column_int32_t)sql_send_column_int32;
    sql_sender->send_column_int64 = (send_column_int64_t)sql_send_column_int64;
    sql_sender->send_column_real = (send_column_real_t)sql_send_column_real;
    sql_sender->send_column_date = (send_column_date_t)sql_send_column_date;
    sql_sender->send_column_ts = (send_column_ts_t)sql_send_column_ts;
    sql_sender->send_column_tstz = (send_column_ts_tz_t)sql_send_column_tstz;
    sql_sender->send_column_tsltz = (send_column_ts_ltz_t)sql_send_column_tsltz;
    sql_sender->send_column_str = (send_column_str_t)sql_send_column_str;
    sql_sender->send_column_text = (send_column_text_t)sql_send_column_text;
    sql_sender->send_column_bin = (send_column_bin_t)sql_send_column_bin; // cooperate pl distinguish bin and raw
    sql_sender->send_column_raw = (send_column_bin_t)sql_send_column_bin; // cooperate pl distinguish bin and raw
    sql_sender->send_column_decimal = (send_column_decimal_t)sql_send_column_decimal;
    sql_sender->send_column_clob = (send_column_lob_t)sql_send_column_lob;
    sql_sender->send_column_blob = (send_column_lob_t)sql_send_column_lob;
    sql_sender->send_column_bool = (send_column_bool_t)sql_send_column_int32;
    sql_sender->send_column_ymitvl = (send_column_ymitvl_t)sql_send_column_ysintvl;
    sql_sender->send_column_dsitvl = (send_column_dsitvl_t)sql_send_column_dsintvl;
    sql_sender->send_serveroutput = (send_serveroutput_t)sql_send_serveroutput;
    sql_sender->send_return_result = (send_return_result_t)sql_send_return_result;
    sql_sender->send_column_cursor = (send_column_cursor_t)sql_send_column_cursor;
    sql_sender->send_column_def = (send_column_def_t)sql_send_column_def;
    sql_sender->send_column_array = (send_column_array_t)sql_send_column_array;
}

status_t sql_instance_startup(void)
{
    CT_RETURN_IFERR(sql_create_context_pool());
    lex_init_keywords();
    pl_init_keywords();
    sql_create_sender();
    pl_init_udt_method();
    return CT_SUCCESS;
}

/* close the resource(like dc in sql, sqls in anonymous block) if the context ref count is 0 */
void sql_close_context_resource(context_ctrl_t *ctrl_ctx)
{
    if (ctrl_ctx->cleaned) {
        return;
    }
    sql_close_dc(ctrl_ctx);
    ctrl_ctx->cleaned = CT_TRUE;
}
/* close the dc if the context ref count is 0 */
void sql_close_dc(context_ctrl_t *ctrl_ctx)
{
    sql_context_t *sql_ctx = (sql_context_t *)ctrl_ctx;
    sql_table_entry_t *table = NULL;
    pl_dc_t *pl_dc = NULL;

    if (ctrl_ctx->cleaned) {
        return;
    }

    for (uint32 i = 0; sql_ctx->tables != NULL && i < sql_ctx->tables->count; i++) {
        table = (sql_table_entry_t *)cm_galist_get(sql_ctx->tables, i);
        // if dc open failed before,table name may be null.due to this no need close dc here
        if (table->name.str == NULL) {
            continue;
        }
        if (IS_LTT_BY_NAME(table->name.str) || IS_DBLINK_TABLE(table)) {
            // do nothing for ltt dc or dblink table dc
            continue;
        }
        knl_close_dc(&table->dc);
    }

    for (uint32 i = 0; sql_ctx->dc_lst != NULL && i < sql_ctx->dc_lst->count; i++) {
        pl_dc = (pl_dc_t *)cm_galist_get(sql_ctx->dc_lst, i);
        pl_dc_close(pl_dc);
    }
}

void sql_context_uncacheable(sql_context_t *sql_ctx)
{
    if (sql_ctx == NULL) {
        return;
    }

    sql_ctx->cacheable = CT_FALSE;
}


#ifndef TEST_MEM
void sql_free_context(sql_context_t *sql_ctx)
{
    if (sql_ctx == NULL) {
        return;
    }
    if (sql_ctx->in_sql_pool) {
        text_t sql_text;
        ctx_read_first_page_text(sql_ctx->ctrl.pool, &sql_ctx->ctrl, &sql_text);
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "cannot free context cached in sql pool, sql=[%s]", T2S(&sql_text));
        return;
    }

    if (sql_ctx->large_page_id != CT_INVALID_ID32) {
        mpool_free_page(&g_instance->sga.large_pool, sql_ctx->large_page_id);
        sql_ctx->large_page_id = CT_INVALID_ID32;
    }

    sql_close_dc(&sql_ctx->ctrl);
    CM_ASSERT(sql_ctx->ctrl.hash_next == NULL);
    CM_ASSERT(sql_ctx->ctrl.hash_prev == NULL);
    CM_ASSERT(sql_ctx->ctrl.lru_next == NULL);
    CM_ASSERT(sql_ctx->ctrl.lru_prev == NULL);
    CM_ASSERT(sql_ctx->ctrl.ref_count == 0);
    mctx_destroy(sql_ctx->ctrl.memory);
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    test_memory_pool_maps(sql_pool->memory);
#endif // DEBUG
}

void ctx_recycle_all(void)
{
    ctx_recycle_all_core(sql_pool);
}

void dc_recycle_external(void)
{
    pl_recycle_all();
    ctx_recycle_all();
}

bool32 ctx_recycle_internal(void)
{
    return ctx_recycle_internal_core(sql_pool);
}

status_t sql_alloc_mem(void *context, uint32 size, void **buf)
{
    sql_context_t *sql_ctx = (sql_context_t *)context;
    CM_ASSERT(!sql_ctx->readonly);
    return sql_ctx_alloc_mem(sql_ctx->ctrl.pool, sql_ctx->ctrl.memory, size, buf);
}
#else

void sql_free_context(sql_context_t *ctx)
{
    uint32 i = 0;

    if (ctx == NULL) {
        return;
    }

    if (ctx->in_sql_pool) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "context to be released cannot be in the pool");
        return;
    }

    if (ctx->large_page_id != CT_INVALID_ID32) {
        mpool_free_page(&g_instance->sga.large_pool, ctx->large_page_id);
        ctx->large_page_id = CT_INVALID_ID32;
    }

    for (i = 0; i < ctx->test_mem_count; ++i) {
        CM_FREE_PTR(ctx->test_mem[i]);
    }

    CM_FREE_PTR(ctx);
}

status_t sql_alloc_mem(void *context, uint32 size, void **buf)
{
    errno_t rc_memzero;
    sql_context_t *ctx = (sql_context_t *)context;

    if (ctx->test_mem_count + 1 > CT_MAX_TEST_MEM_COUNT) {
        CT_THROW_ERROR(ERR_MALLOC_MAX_MEMORY, CT_MAX_TEST_MEM_COUNT);
        return CT_ERROR;
    }
    if (size == 0) {
        CT_THROW_ERROR(ERR_MALLOC_BYTES_MEMORY, size);
        return CT_ERROR;
    }
    *buf = (void *)malloc(size);
    if (*buf == NULL) {
        CT_THROW_ERROR(ERR_MALLOC_BYTES_MEMORY, size);
        return CT_ERROR;
    }
    rc_memzero = memset_s(*buf, size, 0, size);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(*buf);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, rc_memzero);
        return CT_ERROR;
    }

    ctx->test_mem_count++;
    ctx->test_mem[ctx->test_mem_count - 1] = *buf;

    return CT_SUCCESS;
}
#endif // TEST_MEM

bool32 sql_upper_case_name(sql_context_t *ctx)
{
    if (IS_CASE_INSENSITIVE) {
        return CT_TRUE;
    }
    for (uint32 i = 0; i < g_cs_type_count; ++i) {
        if (ctx->type == g_cs_sql_types[i]) {
            return CT_FALSE;
        }
    }

    if (IS_COMPATIBLE_MYSQL_INST) {
        return CT_FALSE;
    }
    return CT_TRUE;
}

status_t sql_copy_name_cs(sql_context_t *ctx, text_t *src, text_t *dst)
{
    if (IS_CASE_INSENSITIVE) {
        return sql_copy_name(ctx, src, dst);
    }
    if (src->len > CT_MAX_NAME_LEN) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "'%s' is too long to as name", T2S(src));
        return CT_ERROR;
    }
    if (src->len == 0) {
        dst->len = 0;
        return CT_SUCCESS;
    }
    return sql_copy_text(ctx, src, dst);
}

status_t sql_copy_name(sql_context_t *ctx, text_t *src, text_t *dst)
{
    uint32 i;

    if (src->len > CT_MAX_NAME_LEN) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "'%s' is too long to as name", T2S(src));
        return CT_ERROR;
    }

    if (src->len == 0) {
        dst->len = 0;
        return CT_SUCCESS;
    }

    if (sql_alloc_mem(ctx, src->len, (void **)&dst->str) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dst->len = src->len;
    for (i = 0; i < dst->len; i++) {
        dst->str[i] = UPPER(src->str[i]);
    }

    return CT_SUCCESS;
}

status_t sql_copy_name_loc(sql_context_t *ctx, sql_text_t *src, sql_text_t *dst)
{
    dst->loc = src->loc;
    return sql_copy_name(ctx, &src->value, &dst->value);
}

status_t sql_copy_name_prefix_tenant_loc(void *stmt_in, sql_text_t *src, sql_text_t *dst)
{
    sql_stmt_t *stmt = stmt_in;
    sql_copy_func_t sql_copy_func;
    if (IS_COMPATIBLE_MYSQL_INST) {
        sql_copy_func = sql_copy_name_cs;
    } else {
        sql_copy_func = sql_copy_name;
    }

    dst->loc = src->loc;
    return sql_copy_prefix_tenant(stmt, &src->value, &dst->value, sql_copy_func);
}

status_t sql_copy_object_name(sql_context_t *ctx, word_type_t word_type, text_t *src, text_t *dst)
{
    if (IS_DQ_STRING(word_type)) {
        return sql_copy_text(ctx, src, dst);
    }
    return sql_upper_case_name(ctx) ? sql_copy_name(ctx, src, dst) : sql_copy_name_cs(ctx, src, dst);
}

status_t sql_copy_object_name_prefix_tenant(void *stmt_in, word_type_t word_type, text_t *src, text_t *dst)
{
    sql_stmt_t *stmt = stmt_in;
    if (IS_DQ_STRING(word_type)) {
        return sql_copy_prefix_tenant(stmt, src, dst, sql_copy_text);
    }
    if (sql_upper_case_name(stmt->context)) {
        return sql_copy_prefix_tenant(stmt, src, dst, sql_copy_name);
    }
    return sql_copy_prefix_tenant(stmt, src, dst, sql_copy_name_cs);
}

status_t sql_copy_prefix_tenant(void *stmt_in, text_t *src, text_t *dst, sql_copy_func_t sql_copy_func)
{
    text_t name;
    char buf[CT_NAME_BUFFER_SIZE];
    sql_stmt_t *stmt = stmt_in;

    if (sql_upper_case_name(stmt->context)) {
        cm_text2str_with_upper(src, buf, CT_NAME_BUFFER_SIZE);
    } else {
        if (cm_text2str(src, buf, CT_NAME_BUFFER_SIZE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (sql_user_prefix_tenant(stmt->session, buf) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cm_str2text(buf, &name);
    if (sql_copy_func(stmt->context, &name, dst) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_copy_object_name_loc(sql_context_t *ctx, word_type_t word_type, sql_text_t *src, sql_text_t *dst)
{
    dst->loc = src->loc;
    return sql_copy_object_name(ctx, word_type, &src->value, &dst->value);
}

status_t sql_copy_object_name_prefix_tenant_loc(void *stmt_in, word_type_t word_type, sql_text_t *src, sql_text_t *dst)
{
    sql_stmt_t *stmt = stmt_in;

    dst->loc = src->loc;
    return sql_copy_object_name_prefix_tenant(stmt, word_type, &src->value, &dst->value);
}

status_t sql_user_prefix_tenant(void *session, char *username)
{
    session_t *sess = session;
    text_t tenant;
    text_t schema;
    char temp_buf[CT_NAME_BUFFER_SIZE];
    text_t sys_user_name = {
        .str = SYS_USER_NAME,
        .len = SYS_USER_NAME_LEN
    };

    if (!sess->prefix_tenant_flag || cm_text_str_equal_ins(&g_tenantroot, sess->curr_tenant)) {
        return CT_SUCCESS;
    }

    // explicitly specify the schema/user SYS without splicing the tenant prefix
    // but only support for user in tenant$root
    if (cm_text_str_equal_ins(&sys_user_name, username)) {
        return sql_check_user_tenant(&sess->knl_session);
    }

    if (strchr(username, '$') != NULL) {
        cm_str2text(username, &schema);
        (void)cm_fetch_text(&schema, '$', 0, &tenant);
        if (cm_text_str_equal_ins(&tenant, sess->curr_tenant)) {
            return CT_SUCCESS;
        }

        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", can not cross tenant in non-root tenant");
        return CT_ERROR;
    }

    if (strlen(username) + 1 + strlen(sess->curr_tenant) > CT_MAX_NAME_LEN) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "'%s' is too long in tenant %s", username, sess->curr_tenant);
        return CT_ERROR;
    }

    PRTS_RETURN_IFERR(sprintf_s(temp_buf, CT_NAME_BUFFER_SIZE, "%s$%s", sess->curr_tenant, username));
    PRTS_RETURN_IFERR(sprintf_s(username, CT_NAME_BUFFER_SIZE, "%s", temp_buf));

    return CT_SUCCESS;
}

status_t sql_user_text_prefix_tenant(void *session_in, text_t *user, char *buf, uint32 buf_size)
{
    CT_RETURN_IFERR(cm_text2str(user, buf, buf_size));
    CT_RETURN_IFERR(sql_user_prefix_tenant(session_in, buf));
    cm_str2text(buf, user);
    return CT_SUCCESS;
}

status_t sql_copy_object_name_ci(sql_context_t *ctx, word_type_t word_type, text_t *src, text_t *dst)
{
    if (IS_DQ_STRING(word_type)) {
        return sql_copy_text(ctx, src, dst);
    }
    return sql_copy_name(ctx, src, dst);
}
status_t sql_copy_str_safe(sql_context_t *sql_ctx, char *src, uint32 len, text_t *dst)
{
    text_t src_text;
    cm_str2text_safe(src, len, &src_text);
    return sql_copy_text(sql_ctx, &src_text, dst);
}
status_t sql_copy_str(sql_context_t *sql_ctx, char *src, text_t *dst)
{
    text_t src_text;
    cm_str2text_safe(src, (uint32)strlen(src), &src_text);
    return sql_copy_text(sql_ctx, &src_text, dst);
}

status_t sql_copy_text(sql_context_t *sql_ctx, text_t *src, text_t *dst)
{
    if (sql_alloc_mem(sql_ctx, src->len, (void **)&dst->str) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (src->len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(dst->str, src->len, src->str, src->len));
    }
    dst->len = src->len;
    return CT_SUCCESS;
}

status_t sql_copy_binary(sql_context_t *sql_ctx, binary_t *src, binary_t *dst)
{
    if (sql_alloc_mem(sql_ctx, src->size, (void **)&dst->bytes) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (src->size != 0) {
        MEMS_RETURN_IFERR(memcpy_s(dst->bytes, src->size, src->bytes, src->size));
    }
    dst->size = src->size;
    return CT_SUCCESS;
}

status_t sql_copy_text_upper(sql_context_t *sql_ctx, text_t *src, text_t *dst)
{
    uint32 i;
    if (sql_alloc_mem(sql_ctx, src->len, (void **)&dst->str) != CT_SUCCESS) {
        return CT_ERROR;
    }

    dst->len = src->len;
    for (i = 0; i < dst->len; i++) {
        dst->str[i] = UPPER(src->str[i]);
    }

    return CT_SUCCESS;
}

static inline void sql_convert_slash(text_t *dst, uint32 size)
{
    for (uint32 i = 0; i < size; i++) {
        if (dst->str[i] == '/') {
            dst->str[i] = '\\';
        }
    }
}

status_t sql_copy_file_name(sql_context_t *sql_ctx, text_t *src, text_t *dst)
{
    uint32 size, home_len, offset, len;
    text_t file_name = *src;
    bool32 in_home = CT_FALSE;
    bool32 in_home_data = CT_FALSE;
    cm_trim_text(&file_name);

    if (file_name.len == 0) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "file name missing");
        return CT_ERROR;
    }

    home_len = (uint32)strlen(g_instance->home);

    if (file_name.str[0] == '?') {
        file_name.len--;
        file_name.str++;
        size = home_len + file_name.len;

        in_home = CT_TRUE;
    } else if (file_name.str[0] != '*' && file_name.str[0] != '-' && file_name.str[0] != '+' &&
        file_name.str[0] != '/' && file_name.str[1] != ':') {
        size = home_len + file_name.len + (uint32)strlen("/data/");
        in_home_data = CT_TRUE;
    } else {
        size = file_name.len;
    }

    if (size > CT_MAX_FILE_NAME_LEN) {
        CT_THROW_ERROR(ERR_NAME_TOO_LONG, "datafile", size, CT_MAX_FILE_NAME_LEN);
        return CT_ERROR;
    }
    len = size + 1;
    offset = 0;
    CT_RETURN_IFERR(sql_alloc_mem(sql_ctx, len, (void **)&dst->str));

    if (in_home) {
        if (home_len != 0) {
            MEMS_RETURN_IFERR(memcpy_s(dst->str, len, g_instance->home, home_len));
        }
        offset += home_len;
        if (file_name.len != 0) {
            MEMS_RETURN_IFERR(memcpy_s(dst->str + offset, len - offset, file_name.str, file_name.len));
        }
    } else if (in_home_data) {
        if (home_len != 0) {
            MEMS_RETURN_IFERR(memcpy_s(dst->str, len, g_instance->home, home_len));
        }
        offset += home_len;
        MEMS_RETURN_IFERR(memcpy_s(dst->str + offset, len - offset, "/data/", strlen("/data/")));

        offset += (uint32)strlen("/data/");
        if (file_name.len != 0) {
            MEMS_RETURN_IFERR(memcpy_s(dst->str + offset, len - offset, file_name.str, file_name.len));
        }
    } else {
        if (file_name.len != 0) {
            MEMS_RETURN_IFERR(memcpy_s(dst->str, len, file_name.str, file_name.len));
        }
    }

    dst->len = size;
    dst->str[size] = '\0';

#ifdef WIN32
    sql_convert_slash(dst, size);
#endif /* WIN32 */

    return CT_SUCCESS;
}

static inline bool32 sql_check_is_slach(char c)
{
#ifdef WIN32
    if (c == '\\') {
        return CT_TRUE;
    }
#else
    if (c == '/') {
        return CT_TRUE;
    }
#endif
    return CT_FALSE;
}

/*
name.str SHOULD be the absolute path
xxx:/ # cd /../../../usr
xxx:/usr #

test case:
path idx[1] path[..] error
path idx[2] path[.] error
path idx[3] path[/xx.] real_path [/xx.]
path idx[4] path[/.x] real_path [/.x]
path idx[5] path[/..x] error
path idx[6] path[/x/y/../z/./../a/../../b] real_path [/b]
path idx[7] path[/x/y/../z/./../a/../../b/] real_path [/b]
path idx[8] path[/x/y/../z/./../a/../../b/.] real_path [/b]
path idx[9] path[/x/y/../z/././../a/../../b/./.] real_path [/b]
path idx[10] path[/../../../usr] real_path [/usr]
*/
status_t sql_get_real_path(text_t *name, char *real_path)
{
    text_t file_name = *name;
    cm_trim_text(&file_name);

    uint32 i;
    uint32 j;

    // SHOULD be the absolute path
#ifdef WIN32
    if (file_name.len == 0 || file_name.str[1] != ':') {
        return CT_ERROR;
    }
    i = j = 2;
    real_path[0] = file_name.str[0];
    real_path[1] = file_name.str[1];
#else
    if (file_name.len == 0 || sql_check_is_slach(file_name.str[0]) != CT_TRUE) {
        return CT_ERROR;
    }
    i = j = 0;
#endif // WIN32

    for (; i < file_name.len; i++) {
        if (sql_check_is_slach(file_name.str[i])) {
            // "//" or  "/../" just keep one
            if (j > 0 && sql_check_is_slach(real_path[j - 1]) == CT_TRUE) {
                continue;
            } else {
                real_path[j] = file_name.str[i];
                j++;
            }
        } else if (file_name.str[i] == '.') {
            if (i < file_name.len - 1) {
                // "./"
                if (sql_check_is_slach(file_name.str[i + 1]) == CT_TRUE) {
                    continue;
                }

                // ".."
                if (file_name.str[i + 1] == '.') {
                    i++;
                    if (i < file_name.len - 1) {
                        // "..x" or "..." is error
                        if (sql_check_is_slach(file_name.str[i + 1]) != CT_TRUE) {
                            return CT_ERROR;
                        }
                    }

                    // ".." skip the last dir
                    // skip the last '/'
                    if (j > 2) {
                        j -= 2;
                    }
                    // skip the last dir
                    while (j > 0) {
                        if (sql_check_is_slach(real_path[j]) == CT_TRUE) {
                            break;
                        }
                        j--;
                    }
                } else {
                    // ".x" or "x." is ok
                    real_path[j] = file_name.str[i];
                    j++;
                }
            } else {
                // "/xx." is ok
                if (j > 0 && sql_check_is_slach(real_path[j - 1]) != CT_TRUE) {
                    real_path[j] = file_name.str[i];
                    j++;
                }
            }
        } else {
            real_path[j] = file_name.str[i];
            j++;
        }
    }

    // set "/x/" to "/x"
    if (j > 2) {
        if (sql_check_is_slach(real_path[j - 1]) == CT_TRUE) {
            j -= 1;
        }
    }

    real_path[j] = 0x00;
    return CT_SUCCESS;
}

status_t sql_check_datafile_path(text_t *name)
{
    char real_name[CT_MAX_FILE_PATH_LENGH] = {0x00};
    uint32 len;

    if (sql_get_real_path(name, real_name) != CT_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_CAPABILITY_NOT_SUPPORT, "datafile name [%s] fmt", T2S(name));
        return CT_ERROR;
    }

    // datafile SHOULD be in g_instance->home
    len = (uint32)strlen(g_instance->home);
    if (len > 2) {
        if (sql_check_is_slach(g_instance->home[len - 1]) == CT_TRUE) {
            len -= 1;
        }
    }

    if (memcmp(g_instance->home, real_name, len) != 0) {
        CT_THROW_ERROR_EX(ERR_CAPABILITY_NOT_SUPPORT, "datafile path not in home of instance");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_array_put(sql_array_t *array, pointer_t ptr)
{
    if (array->count >= array->capacity) {
        CT_THROW_ERROR(ERR_OUT_OF_INDEX, "array", array->capacity);
        return CT_ERROR;
    }

    array->items[array->count] = ptr;
    array->count++;
    return CT_SUCCESS;
}

status_t sql_array_concat(sql_array_t *array1, sql_array_t *array2)
{
    uint32 i;

    if (array1->count + array2->count > array1->capacity) {
        CT_THROW_ERROR(ERR_OUT_OF_INDEX, "array", array1->capacity);
        return CT_ERROR;
    }

    for (i = 0; i < array2->count; i++) {
        array1->items[array1->count] = array2->items[i];
        array1->count++;
    }

    return CT_SUCCESS;
}

status_t sql_array_delete(sql_array_t *array, uint32 index)
{
    if (index >= array->count) {
        CT_THROW_ERROR(ERR_OUT_OF_INDEX, "array", array->count);
        return CT_ERROR;
    }
    for (uint32 i = index; i < array->count - 1; ++i) {
        array->items[i] = array->items[i + 1];
    }
    array->count--;
    return CT_SUCCESS;
}

status_t sql_array_set(sql_array_t *array, uint32 index, pointer_t ptr)
{
    if (index >= array->count) {
        CT_THROW_ERROR(ERR_OUT_OF_INDEX, "array", array->count);
        return CT_ERROR;
    }

    array->items[index] = ptr;
    return CT_SUCCESS;
}

void sql_destroy_context_pool(void)
{
    ctx_pool_destroy(g_instance->sql.pool);
}

status_t sql_create_context_pool(void)
{
    context_pool_profile_t profile;

    profile.area = &g_instance->sga.shared_area;
    profile.name = "sql pool";
    profile.clean = sql_close_context_resource;
    profile.init_pages = CT_MIN_SQL_PAGES;
    profile.optimize_pages =
        (uint32)(int32)(g_instance->sga.shared_area.page_count * g_instance->kernel.attr.sql_pool_factor);
    if (profile.optimize_pages < CT_MIN_SQL_PAGES) {
        profile.optimize_pages = CT_MIN_SQL_PAGES;
    }
    profile.context_size = sizeof(sql_context_t);
    profile.bucket_count = CT_SQL_BUCKETS;

    if (ctx_pool_create(&profile, &sql_pool) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_get_sort_item_project_id(sql_query_t *remote_query, sort_item_t *sort_item, uint32 *project_id)
{
    expr_node_t *node = sort_item->expr->root;

    switch (node->type) {
        case EXPR_NODE_COLUMN:
            *project_id = node->value.v_col.col_info_ptr->col_pro_id;
            break;
        case EXPR_NODE_GROUP:
            *project_id = node->value.v_vm_col.id;
            break;
        case EXPR_NODE_AGGR:
            *project_id = node->value.v_int;
            break;
        default:
            /* this is for median aggregate in sharding
               CN push median column with order by to DN
               but median column can be expression
            */
            if (node->is_median_expr) {
                *project_id = 0;
                return CT_SUCCESS;
            }
            CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "expression not in type list");
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

project_col_info_t *sql_get_project_info_col(project_col_array_t *project_col_array, uint32 col_id)
{
    if (col_id >= project_col_array->count) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "col_id(%u) < project_col_array->count(%u)", col_id,
            project_col_array->count);
    }
    uint32 index = col_id / PROJECT_COL_ARRAY_STEP;
    uint32 offset = col_id % PROJECT_COL_ARRAY_STEP;
    return &project_col_array->base[index][offset];
}

bool32 sql_if_all_comma_join(sql_join_node_t *join_node)
{
    if (join_node->type == JOIN_TYPE_COMMA || join_node->type == JOIN_TYPE_CROSS) {
        return (bool32)(sql_if_all_comma_join(join_node->left) && sql_if_all_comma_join(join_node->right));
    }

    return (join_node->type == JOIN_TYPE_NONE);
}

void sql_context_inc_exec(sql_context_t *sql_ctx)
{
    context_ctrl_t *ctrl = NULL;

    if (sql_ctx == NULL) {
        return;
    }
    ctrl = &sql_ctx->ctrl;
    cm_spin_lock(&ctrl->lock, NULL);
    CM_ASSERT(ctrl->exec_count >= 0);
    ctrl->exec_count++;
    cm_spin_unlock(&ctrl->lock);
}

void sql_context_dec_exec(sql_context_t *sql_ctx)
{
    context_ctrl_t *ctrl = NULL;

    if (sql_ctx == NULL) {
        return;
    }
    ctrl = &sql_ctx->ctrl;
    ctx_dec_exec(ctrl);
}

static unnamed_tab_info_t g_unnamed_tab_info[] = {
    { TAB_TYPE_PIVOT, { (char *)"$FROM_PIVOT_", 12 } },
    { TAB_TYPE_UNPIVOT, { (char *)"$FROM_UNPIVOT_", 14 } },
    { TAB_TYPE_TABLE_FUNC, { (char *)"$FROM_FT_", 9 }},
    { TAB_TYPE_OR_EXPAND, { (char *)"$FROM_ORE_", 10 } },
    { TAB_TYPE_WINMAGIC, { (char *)"$FROM_WMR_", 10 } },
    { TAB_TYPE_SUBQRY_TO_TAB, { (char *)"$FROM_SQ_", 9 } },
    { TAB_TYPE_UPDATE_SET, { (char *)"$FROM_UUS_", 10 } },
};

status_t sql_generate_unnamed_table_name(void *stmt_in, sql_table_t *table, unnamed_tab_type_t type)
{
    sql_stmt_t *stmt = (sql_stmt_t *)stmt_in;
    text_t prefix = g_unnamed_tab_info[type].prefix;
    text_t name = { 0 };
    uint32 id = stmt->context->unnamed_tab_counter[type];
    char row_id[CT_MAX_INT32_STRLEN + 1] = { 0 };

    int32 len = snprintf_s(row_id, CT_MAX_INT32_STRLEN + 1, CT_MAX_INT32_STRLEN, PRINT_FMT_UINT32, id);
    PRTS_RETURN_IFERR(len);
    uint32 max_size = (uint32)len + prefix.len;

    CT_RETURN_IFERR(sql_push(stmt, max_size, (void **)&name.str));

    cm_concat_text(&name, max_size, &prefix);
    CT_RETURN_IFERR(cm_concat_n_string(&name, max_size, row_id, len));

    CT_RETURN_IFERR(sql_copy_text(stmt->context, &name, &table->alias.value));
    table->alias.implicit = CT_TRUE;

    stmt->context->unnamed_tab_counter[type]++;

    CTSQL_POP(stmt);

    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
