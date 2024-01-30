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
 * ctsql_table_func.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/node/ctsql_table_func.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_hash.h"
#include "ctsql_table_func.h"
#include "dml_executor.h"
#include "pl_context.h"
#include "knl_interface.h"
#include "ctsql_func.h"
#include "ctsql_package.h"
#include "srv_instance.h"
#include "knl_dc.h"
#include "knl_page.h"
#include "expr_parser.h"
#include "ctsql_privilege.h"
#include "cm_memory.h"
#include "pl_compiler.h"
#include "pl_executor.h"
#include "ctsql_mtrl.h"
#include "knl_fbdr.h"
#include "ctsql_table_func_impl.h"
#include "dtc_backup.h"

#define SOURCE_LINE_MAXLEN 8000
#define DECODE_DESCRIPTION_MAXLEN 8000

#define PARALLEL_SCAN CT_INVALID_ID32

knl_column_t g_analyze_table_columns[] = {
    { 0, "STAT_ITEM", 0, 0, CT_TYPE_VARCHAR, 128, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "VALUE", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
};
ARRAY_IN_DEF(g_analyze_table_columns)

knl_column_t g_table_paralel_columns[] = {
    { 0, "PART_ID", 0, 0, CT_TYPE_INTEGER, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "BEG",     0, 0, CT_TYPE_BIGINT,  sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "END",     0, 0, CT_TYPE_BIGINT,  sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
};
ARRAY_IN_DEF(g_table_paralel_columns)

knl_column_t g_breakpoint_info_columns[] = {
    { 0, "BREAK_ID",   0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 1, "OWNER",      0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "OBJECT",     0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "PL_TYPE",    0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "LOC_LINE",   0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 5, "IS_VALID",   0, 0, CT_TYPE_BOOLEAN, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 6, "IS_ENABLED", 0, 0, CT_TYPE_BOOLEAN, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 7, "COND",       0, 0, CT_TYPE_VARCHAR, CT_TYPE_VARCHAR, 0, 0, CT_FALSE, 0, { 0 } },
    { 8, "MAX_SKIP",   0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
};
ARRAY_IN_DEF(g_breakpoint_info_columns)

knl_column_t g_insert_dist_ddl_columns[] = {
    { 0, "result", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
};
ARRAY_IN_DEF(g_insert_dist_ddl_columns)

knl_column_t g_proc_decode_columns[] = {
    { 0, "LINE_NUM",            0, 0, CT_TYPE_INTEGER, sizeof(uint32),            0, 0, CT_FALSE, 0, { 0 } },
    { 1, "LINE_TYPE",           0, 0, CT_TYPE_VARCHAR, LINE_TYPE_NAME_MAXLEN,     0, 0, CT_FALSE, 0, { 0 } },
    { 2, "LOC_LINE",            0, 0, CT_TYPE_INTEGER, sizeof(uint32),            0, 0, CT_FALSE, 0, { 0 } },
    { 3, "SPECIAL_DESCRIPTION", 0, 0, CT_TYPE_VARCHAR, DECODE_DESCRIPTION_MAXLEN, 0, 0, CT_FALSE, 0, { 0 } },
};
ARRAY_IN_DEF(g_proc_decode_columns)

knl_column_t g_proc_callstack_columns[] = {
    { 0, "STACK_ID",  0, 0, CT_TYPE_INTEGER, sizeof(uint32),        0, 0, CT_FALSE, 0, { 0 } },
    { 0, "UID",       0, 0, CT_TYPE_INTEGER, sizeof(uint32),        0, 0, CT_FALSE, 0, { 0 } },
    { 0, "OID",       0, 0, CT_TYPE_BIGINT,  sizeof(uint64),        0, 0, CT_FALSE, 0, { 0 } },
    { 1, "OWNER",     0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,       0, 0, CT_FALSE, 0, { 0 } },
    { 2, "OBJECT",    0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,       0, 0, CT_FALSE, 0, { 0 } },
    { 3, "LOC_LINE",  0, 0, CT_TYPE_INTEGER, sizeof(uint32),        0, 0, CT_FALSE, 0, { 0 } },
    { 4, "LINE_TYPE", 0, 0, CT_TYPE_VARCHAR, LINE_TYPE_NAME_MAXLEN, 0, 0, CT_FALSE, 0, { 0 } },
};
ARRAY_IN_DEF(g_proc_callstack_columns)

knl_column_t g_proc_line_columns[] = {
    { 0, "LOC_LINE", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "SOURCE_LINE", 0, 0, CT_TYPE_VARCHAR, SOURCE_LINE_MAXLEN, 0, 0, CT_FALSE, 0, { 0 } },
};
ARRAY_IN_DEF(g_proc_line_columns)

knl_column_t g_show_values_columns[] = {
    { 0, "STACK_ID",   0, 0, CT_TYPE_INTEGER, sizeof(uint32),     0, 0, CT_FALSE, 0, { 0 } },
    { 1, "BLOCK_NAME", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,    0, 0, CT_FALSE, 0, { 0 } },
    { 2, "PARENT",     0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,    0, 0, CT_FALSE, 0, { 0 } },
    { 3, "NAME",       0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,    0, 0, CT_FALSE, 0, { 0 } },
    { 4, "VID_BLOCK",  0, 0, CT_TYPE_INTEGER, sizeof(uint32),     0, 0, CT_FALSE, 0, { 0 } },
    { 5, "VID_ID",     0, 0, CT_TYPE_INTEGER, sizeof(uint32),     0, 0, CT_FALSE, 0, { 0 } },
    { 6, "VID_OFFSET", 0, 0, CT_TYPE_INTEGER, sizeof(uint32),     0, 0, CT_FALSE, 0, { 0 } },
    { 7, "VALUE",      0, 0, CT_TYPE_VARCHAR, CT_MAX_COLUMN_SIZE, 0, 0, CT_FALSE, 0, { 0 } },
    { 8, "TYPE",       0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,    0, 0, CT_FALSE, 0, { 0 } },
};
ARRAY_IN_DEF(g_show_values_columns)

knl_column_t g_control_info_columns[] = {
    { 0, "NAME", 0, 0, CT_TYPE_VARCHAR, CONTROL_ITEM_NAME_MAXLEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "VALUE", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
};
ARRAY_IN_DEF(g_control_info_columns)

knl_column_t g_dba_free_space_columns[] = {
    { 0, "TABLESPACE_NAME", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "FILE_ID",         0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 2, "BLOCK_ID",        0, 0, CT_TYPE_INTEGER, sizeof(uint32),  0, 0, CT_FALSE, 0, { 0 } },
    { 3, "BLOCKS",          0, 0, CT_TYPE_BIGINT,  sizeof(uint64),  0, 0, CT_FALSE, 0, { 0 } },
    { 4, "BYTES",           0, 0, CT_TYPE_BIGINT,  sizeof(uint64),  0, 0, CT_FALSE, 0, { 0 } },
};
ARRAY_IN_DEF(g_dba_free_space_columns)

static knl_column_t g_cast_columns[] = {
    { 0, "COLUMN_VALUE", 0, 0, CT_TYPE_UNKNOWN, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_pending_trans_session_columns[] = {
    { 0, "SID",            0, 0, CT_TYPE_INTEGER, sizeof(uint32),             0, 0, CT_FALSE, 0, { 0 } },
    { 1, "SERIAL#",        0, 0, CT_TYPE_INTEGER, sizeof(uint32),             0, 0, CT_FALSE, 0, { 0 } },
    { 2, "FORMAT_ID",      0, 0, CT_TYPE_INTEGER, sizeof(uint64),             0, 0, CT_FALSE, 0, { 0 } },
    { 3, "BRANCH_ID",      0, 0, CT_TYPE_VARCHAR, CT_MAX_XA_BASE16_BQUAL_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "GLOBAL_TRAN_ID", 0, 0, CT_TYPE_VARCHAR, CT_MAX_XA_BASE16_GTRID_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 5, "PREPARE_SCN",    0, 0, CT_TYPE_BIGINT,  sizeof(uint64),             0, 0, CT_FALSE, 0, { 0 } },
    { 6, "COMMIT_SCN",     0, 0, CT_TYPE_BIGINT,  sizeof(uint64),             0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_page_corruption_columns[] = {
    { 0, "FILE_ID",             0, 0, CT_TYPE_INTEGER, sizeof(uint32),              0, 0, CT_FALSE, 0, { 0 } },
    { 1, "FILE_NAME",           0, 0, CT_TYPE_VARCHAR, CT_FILE_NAME_BUFFER_SIZE,    0, 0, CT_FALSE, 0, { 0 } },
    { 2, "INFO_TYPE",           0, 0, CT_TYPE_VARCHAR, 13,                          0, 0, CT_FALSE, 0, { 0 } },
    { 3, "EXAMINED_NUM",        0, 0, CT_TYPE_INTEGER, sizeof(uint32),              0, 0, CT_FALSE, 0, { 0 } },
    { 4, "SUCCEED_NUM",         0, 0, CT_TYPE_INTEGER, sizeof(uint32),              0, 0, CT_FALSE, 0, { 0 } },
    { 5, "CORRUPT_NUM",         0, 0, CT_TYPE_INTEGER, sizeof(uint32),              0, 0, CT_FALSE, 0, { 0 } },
    { 6, "PAGE_ID",             0, 0, CT_TYPE_INTEGER, sizeof(uint32),              0, 0, CT_FALSE, 0, { 0 } },
    { 7, "PAGE_TYPE",           0, 0, CT_TYPE_VARCHAR, 18,                          0, 0, CT_FALSE, 0, { 0 } },
    { 8, "MARKED_CHECKSUM",     0, 0, CT_TYPE_INTEGER, sizeof(uint32),              0, 0, CT_FALSE, 0, { 0 } },
    { 9, "CALC_CHECKSUM",       0, 0, CT_TYPE_INTEGER, sizeof(uint32),              0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_table_corruption_columns[] = {
    { 0, "PAGE_ID",             0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,        0, 0, CT_FALSE, 0, { 0 } },
    { 1, "SPACE_NAME",          0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,        0, 0, CT_FALSE, 0, { 0 } },
    { 2, "DATAFILE_NAME",       0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,        0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_index_corruption_columns[] = {
    { 0, "PAGE_ID",            0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,             0, 0, CT_FALSE, 0, { 0 } },
    { 1, "SPACE_NAME",         0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,             0, 0, CT_FALSE, 0, { 0 } },
    { 2, "DATAFILE_NAME",      0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,             0, 0, CT_FALSE, 0, { 0 } },
};

#define TABLE_CAST_COLS (sizeof(g_cast_columns) / sizeof(knl_column_t))
#define FBDR_2PC_COLS (sizeof(g_dba_fbdr_2pc_columns) / sizeof(knl_column_t))
#define PENDING_TRANS_SESSION_COLS (sizeof(g_pending_trans_session_columns) / sizeof(knl_column_t))
#define CONTROL_INFO_COLS (sizeof(g_control_info_columns) / sizeof(knl_column_t))
#define PAGE_CORRUPTION_COLS (sizeof(g_page_corruption_columns) / sizeof(knl_column_t))
#define TABLE_CORRUPTION_COLS (sizeof(g_table_corruption_columns) / sizeof(knl_column_t))
#define INDEX_CORRUPTION_COLS (sizeof(g_index_corruption_columns) / sizeof(knl_column_t))
#define ANAYLYZE_TABLE_COLS (sizeof(g_analyze_table_columns) / sizeof(knl_column_t))
#define BREAK_INFO_COLS (sizeof(g_breakpoint_info_columns) / sizeof(knl_column_t))
#define PROC_DECODE_COLS (sizeof(g_proc_decode_columns) / sizeof(knl_column_t))
#define PROC_CALLSTACK_COLS (sizeof(g_proc_callstack_columns) / sizeof(knl_column_t))
#define GET_TAB_PARALLEL_COLS (sizeof(g_table_paralel_columns) / sizeof(knl_column_t))
#define INSERT_DIST_DDL_COLS (sizeof(g_insert_dist_ddl_columns) / sizeof(knl_column_t))
#define SHOW_VALUES_COLS (sizeof(g_show_values_columns) / sizeof(knl_column_t))
#define PROC_LINE_COLS (sizeof(g_proc_line_columns) / sizeof(knl_column_t))
#define GET_FREE_SPACE_COLS (sizeof(g_dba_free_space_columns) / sizeof(knl_column_t))


#define PAGE_CORRUPT_TYPE_NUM 4
text_t g_page_corrupt_type_name[PAGE_CORRUPT_TYPE_NUM] = {
    { "DATABASE",   8 },
    { "TABLESPACE", 10 },
    { "DATAFILE",   8 },
    { "PAGE",       4 },
};

#define TBL_FUNC_RETURN_IF_NOT_STRING(loc, type)        \
    do {                                                \
        if (!sql_match_string_type(type)) {             \
            CT_SRC_ERROR_REQUIRE_STRING((loc), (type)); \
            return CT_ERROR;                            \
        }                                               \
    } while (0)

status_t sql_exec_tablefunc_arg(sql_stmt_t *stmt, expr_tree_t *expr, variant_t *value, ct_type_t type,
    bool32 check_null)
{
    variant_t result;
    SQL_EXEC_FUNC_ARG(expr, value, &result, stmt);
    if (check_null && value->is_null) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "parameter cannot be null.");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(sql_convert_variant(stmt, value, type));
    return CT_SUCCESS;
}

status_t sql_fetch_table_func(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor, bool32 *eof)
{
    bool32 is_found = CT_FALSE;

    for (;;) {
        if (func->desc->fetch(stmt, func, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }

        *eof = cursor->eof;
        if (*eof) {
            return CT_SUCCESS;
        }

        if (sql_match_cond(stmt, &is_found) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (is_found) {
            return CT_SUCCESS; // should not invoke CTSQL_RESTORE_STACK
        }
    }
}

status_t sql_exec_table_func(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor)
{
    uint32 page_size;
    cursor->row = (row_head_t *)cursor->buf;
    cursor->eof = CT_FALSE;
    cursor->is_valid = CT_TRUE;
    CT_RETURN_IFERR(knl_get_page_size((knl_handle_t)&stmt->session->knl_session, &page_size));
    cursor->page_buf = cursor->buf + page_size;

    return func->desc->exec(stmt, func, cursor);
}

status_t table_func_verify(sql_verifier_t *verf, table_func_t *tab_func, uint16 min_args, uint16 max_args)
{
    expr_node_t func;

    func.argument = tab_func->args;
    func.word.func.name.value = tab_func->name;
    func.loc = tab_func->loc;
    CM_POINTER(verf);
    return sql_verify_func_node(verf, &func, min_args, max_args, CT_INVALID_ID32);
}

status_t get_page_corruption_scan_type(text_t *type, page_corrupt_type_t *pc_type)
{
    uint32 i = 0;
    for (; i < PAGE_CORRUPT_TYPE_NUM; i++) {
        if (cm_text_equal(type, &g_page_corrupt_type_name[i])) {
            break;
        }
    }

    if (i >= PAGE_CORRUPT_TYPE_NUM) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, T2S(type), "need be [DATABASE|TABLESPACE|DATAFILE|PAGE]");
        return CT_ERROR;
    }
    *pc_type = i;
    return CT_SUCCESS;
}

// pc is short for page corruption
bool32 pc_verify_parameter_combination(page_corrupt_type_t type, expr_tree_t *arg2, expr_tree_t *arg3)
{
    if (type == PC_DATABASE) {
        if (arg2 == NULL && arg3 == NULL) {
            return CT_TRUE;
        }
    } else if (type == PC_TABLESPACE || type == PC_DATAFILE) {
        if (arg2 != NULL && arg3 == NULL) {
            return CT_TRUE;
        }
    } else {
        if (arg2 != NULL && arg3 != NULL) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

bool32 pc_verify_spaceid(knl_session_t *session, uint32 space_id)
{
    if (space_id >= CT_MAX_SPACES) {
        CT_THROW_ERROR_EX(ERR_INVALID_FUNC_PARAMS, "space id is larger than max space id(%d)", CT_MAX_SPACES);
        return CT_FALSE;
    }

    if (!spc_valid_space_object(session, space_id)) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "tablespace does not belong to database.");
        return CT_FALSE;
    }

    if (space_id == dtc_my_ctrl(session)->swap_space) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "operation is not support on TEMP space.");
        return CT_FALSE;
    }

    return CT_TRUE;
}

// If only verify file or page, offline file will be scanned
bool32 pc_verify_fileid(knl_session_t *session, uint32 file_id)
{
    if (file_id >= CT_MAX_DATA_FILES) {
        CT_THROW_ERROR_EX(ERR_INVALID_FUNC_PARAMS, "file id should be less than max datafile id(%d)",
            CT_MAX_DATA_FILES);
        return CT_FALSE;
    }

    datafile_t *df = &(session->kernel->db.datafiles[file_id]);
    if (df->space_id == dtc_my_ctrl(session)->swap_space) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "operation is not support on TEMP space.");
        return CT_FALSE;
    }

    if (!(df->ctrl->used) || DF_FILENO_IS_INVAILD(df) || !(DATAFILE_IS_ONLINE(df))) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "datafile does not belong to database");
        return CT_FALSE;
    }

    return CT_TRUE;
}

bool32 pc_verify_pageid(knl_session_t *session, uint32 file_id, uint32 page_id)
{
    database_t *db = &(session->kernel->db);

    if (file_id >= CT_MAX_DATA_FILES) {
        CT_THROW_ERROR_EX(ERR_INVALID_FUNC_PARAMS, "file id should be less than max datafile id(%d)",
            CT_MAX_DATA_FILES);
        return CT_FALSE;
    }

    datafile_t *df = &(session->kernel->db.datafiles[file_id]);
    space_t *space = SPACE_GET(session, db->datafiles[file_id].space_id);

    if (!pc_verify_fileid(session, file_id)) {
        return CT_FALSE;
    }

    uint32 df_hwm = space->head->hwms[df->file_no];
    if (page_id >= df_hwm) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "page does not belong to datafile");
        return CT_FALSE;
    }
    return CT_TRUE;
}

bool32 pc_verify_value_vaild(knl_session_t *session, knl_cursor_t *cur, page_corrupt_type_t pc_type,
    variant_t *common_id, uint32 *space_id)
{
    if (pc_type == PC_DATABASE) {
        return CT_TRUE;
    } else if (pc_type == PC_TABLESPACE) {
        cur->rowid.vmid = common_id->v_uint32;
        *space_id = common_id->v_uint32;
        return pc_verify_spaceid(session, *space_id);
    } else if (pc_type == PC_DATAFILE) {
        cur->rowid.file = common_id->v_uint32;
        return pc_verify_fileid(session, common_id->v_uint32);
    } else if (pc_type == PC_PAGE) {
        cur->rowid.file = common_id->v_uint32;
        return pc_verify_pageid(session, common_id->v_uint32, (uint32)cur->rowid.page);
    }

    CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "scan type convert error.");
    return CT_FALSE;
}

void pc_init_cursor_pagebuf(knl_cursor_t *cur, page_corrupt_type_t pc_type, uint32 space_id)
{
    // use cur->page_buf first place to trans page corruption scan type;
    pc_buf_head_t *pc_heap = (pc_buf_head_t *)(cur->page_buf);
    pc_heap->pc_type = pc_type;
    pc_heap->space_id = space_id;
    pc_heap->file_id = (uint32)cur->rowid.file;
    pc_heap->page_id = (uint32)cur->rowid.page;
    uint32 *corr_count = (uint32 *)(cur->page_buf + sizeof(pc_buf_head_t));
    *corr_count = 0;
}

static inline char *pc_alloc_mpool(knl_session_t *session, uint32 *mpool_page_id)
{
    knl_begin_session_wait(session, LARGE_POOL_ALLOC, CT_FALSE);
    while (!mpool_try_alloc_page(session->kernel->attr.large_pool, mpool_page_id)) {
        cm_spin_sleep_and_stat2(1);
    }
    knl_end_session_wait(session, LARGE_POOL_ALLOC);
    return mpool_page_addr(session->kernel->attr.large_pool, *mpool_page_id);
}

status_t df_read_datafile_device(knl_session_t *session, uint16 file_id, uint32 page_id, char *read_buf, uint32 count)
{
    datafile_t *df = DATAFILE_GET(session, file_id);
    int32 *handle = DATAFILE_FD(session, file_id);
    int64 offset = (int64)page_id * DEFAULT_PAGE_SIZE(session);

    knl_begin_session_wait(session, DB_FILE_SEQUENTIAL_READ, CT_TRUE);
    if (spc_read_datafile(session, df, handle, offset, read_buf, DEFAULT_PAGE_SIZE(session) * count) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("failed to read datafile %s, offset %lld, size %u, error code %d", df->ctrl->name, offset,
            DEFAULT_PAGE_SIZE(session) * count, errno);
        CT_THROW_ERROR(ERR_READ_FILE, errno);
        spc_close_datafile(df, handle);
        knl_end_session_wait(session, DB_FILE_SEQUENTIAL_READ);
        return CT_ERROR;
    }
    knl_end_session_wait(session, DB_FILE_SEQUENTIAL_READ);
    session->stat->disk_read_time += session->wait_pool[DB_FILE_SEQUENTIAL_READ].usecs;
    session->stat->disk_reads++;

    if (IS_UNDO_SPACE(SPACE_GET(session, df->space_id))) {
        session->stat->undo_disk_reads++;
    }

    cm_atomic_inc(&session->kernel->total_io_read);
    g_knl_callback.accumate_io(session, IO_TYPE_READ);

    return CT_SUCCESS;
}

static inline status_t pc_block_and_read_datafile(knl_session_t *session, datafile_t *df, uint32 start_page_id,
    uint32 scan_num, char *read_buf)
{
    // block ckpt write of scan_num pages and read those, as same as back up block method
    spc_try_block_datafile(df, DATAFILE_TABLE_FUNC_BLOCK_ID, (uint64)start_page_id * DEFAULT_PAGE_SIZE(session),
        ((uint64)start_page_id + scan_num) * DEFAULT_PAGE_SIZE(session));
    if (df_read_datafile_device(session, df->ctrl->id, start_page_id, read_buf, scan_num) == CT_ERROR) {
        if (DB_ATTR_CLUSTER(session)) {
            dtc_bak_file_unblocking(session, df->ctrl->id, DATAFILE_TABLE_FUNC_BLOCK_ID);
        }
        spc_unblock_datafile(df, DATAFILE_TABLE_FUNC_BLOCK_ID);
        return CT_ERROR;
    }
    if (DB_ATTR_CLUSTER(session)) {
        dtc_bak_file_unblocking(session, df->ctrl->id, DATAFILE_TABLE_FUNC_BLOCK_ID);
    }
    spc_unblock_datafile(df, DATAFILE_TABLE_FUNC_BLOCK_ID);
    return CT_SUCCESS;
}

void pc_update_df_position(knl_session_t *session, uint32 file_id, knl_cursor_t *cursor)
{
    // init file id is 0, if finish file scan, file id will ++ and page id set to 0
    if (cursor->rowid.file != file_id) {
        cursor->eof = CT_TRUE;
    }
    return;
}

void pc_update_spc_position(knl_session_t *session, uint32 space_id, knl_cursor_t *cur)
{
    uint16 file_id = (uint16)cur->rowid.file;
    datafile_t *df = NULL;

    // init file id is 0, if finish file scan, file id will ++ and page id set to 0
    while (CT_TRUE) {
        if (file_id >= CT_MAX_DATA_FILES) {
            cur->eof = CT_TRUE;
            break;
        }

        df = &(session->kernel->db.datafiles[file_id]);
        // verify space, will not scan unused or OFFLINE datafile
        if (df->space_id == space_id && df->ctrl->used && DATAFILE_IS_ONLINE(df) && !DF_FILENO_IS_INVAILD(df)) {
            if (cur->rowid.page == 0) {
                // use page_buf to count corrput page num in one datafile
                // first parameter is page_corrupt_type_t
                uint32 *count = (uint32 *)(cur->page_buf + sizeof(pc_buf_head_t));
                *count = 0;
            }
            cur->rowid.file = file_id;
            break;
        }
        file_id++;
    }
    return;
}

void pc_update_db_position(knl_session_t *session, knl_cursor_t *cur)
{
    uint16 file_id = (uint16)cur->rowid.file;
    datafile_t *df = NULL;

    // scenario: 1 new df; 2 current df, NEXT page_id
    for (;; file_id++) {
        // 1 update file_id
        if (file_id >= CT_MAX_DATA_FILES) {
            cur->eof = CT_TRUE;
            break;
        }

        // TEMP spc dont store checksum and page id(in page head), ignore TEMP space
        df = &(session->kernel->db.datafiles[file_id]);
        if (df->space_id == dtc_my_ctrl(session)->swap_space) {
            continue;
        }

        // verify db, will not scan unused or OFFLINE file
        if (df->ctrl->used && DATAFILE_IS_ONLINE(df) && !DF_FILENO_IS_INVAILD(df)) {
            if (cur->rowid.page == 0) {
                // use page_buf to count corrput page num in one datafile
                // first parameter is page_corrupt_type_t
                uint32 *count = (uint32 *)(cur->page_buf + sizeof(pc_buf_head_t));
                *count = 0;
            }
            cur->rowid.file = file_id;
            break;
        }
    }
    return;
}

static inline void pc_move_next_file(knl_cursor_t *cursor)
{
    cursor->rowid.file++;
    cursor->rowid.page = 0;
}

status_t pc_verify_page_checksum_num(knl_session_t *session, knl_cursor_t *cursor, uint32 scan_num, char *read_buf)
{
    row_assist_t row_ass;
    page_head_t *page = NULL;
    database_t *db = &(session->kernel->db);
    datafile_t *df = &db->datafiles[cursor->rowid.file];

    for (uint32 j = 0; j < scan_num; ++j) {
        page = (page_head_t *)(read_buf + j * DEFAULT_PAGE_SIZE(session));
        if (PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)) == CT_INVALID_CHECKSUM) {
            cursor->rowid.page++;
            continue;
        }

        if (!page_verify_checksum(page, DEFAULT_PAGE_SIZE(session))) {
            CT_LOG_RUN_ERR("page %u-%u corrupted: checksum level %s, checksum %u, page size %u, "
                "page type %s, space name %s, datafile name %s",
                df->ctrl->id, cursor->rowid.page, knl_checksum_level(g_cks_level),
                PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)), PAGE_SIZE(*page), page_type(page->type),
                (SPACE_GET(session, df->space_id))->ctrl->name, df->ctrl->name);
            row_init(&row_ass, (char *)cursor->row, CT_MAX_ROW_SIZE, PAGE_CORRUPTION_COLS);
            CT_RETURN_IFERR(row_put_int32(&row_ass, (int32)(df->ctrl->id)));
            CT_RETURN_IFERR(row_put_str(&row_ass, df->ctrl->name));
            CT_RETURN_IFERR(row_put_str(&row_ass, "CORRUPT PAGE"));
            CT_RETURN_IFERR(row_put_null(&row_ass));
            CT_RETURN_IFERR(row_put_null(&row_ass));
            CT_RETURN_IFERR(row_put_null(&row_ass));
            CT_RETURN_IFERR(row_put_int32(&row_ass, (int32)(cursor->rowid.page)));
            CT_RETURN_IFERR(row_put_str(&row_ass, page_type(page->type)));

            uint16 org_cks = PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session));
            CT_RETURN_IFERR(row_put_int32(&row_ass, (int32)org_cks));

            PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)) = CT_INVALID_CHECKSUM;
            CT_RETURN_IFERR(row_put_int32(&row_ass, (int32)(REDUCE_CKS2UINT16(cm_get_checksum(page,
                DEFAULT_PAGE_SIZE(session))))));
            PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)) = org_cks;

            cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
            cursor->rowid.page++;
            return CT_ERROR;
        }
        cursor->rowid.page++;
    }
    return CT_SUCCESS;
}

status_t pc_set_file_summary(datafile_t *df, knl_cursor_t *cursor, row_assist_t *row_ass, uint32 df_hwm,
                             uint32 corr_count)
{
    // df_hwm 0 means file not exit, so set success_num to 0;
    uint32 success_num = (df_hwm == 0) ? 0 : (df_hwm - corr_count);
    row_init(row_ass, (char *)cursor->row, CT_MAX_ROW_SIZE, PAGE_CORRUPTION_COLS);
    CT_RETURN_IFERR(row_put_int32(row_ass, (int32)(df->ctrl->id)));
    CT_RETURN_IFERR(row_put_str(row_ass, df->ctrl->name));
    CT_RETURN_IFERR(row_put_str(row_ass, "FILE SUMMARY"));
    CT_RETURN_IFERR(row_put_int32(row_ass, (int32)df_hwm));
    CT_RETURN_IFERR(row_put_int32(row_ass, (int32)success_num));
    CT_RETURN_IFERR(row_put_int32(row_ass, (int32)corr_count));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    return CT_SUCCESS;
}

status_t dba_file_corruption_scan(knl_session_t *session, knl_cursor_t *cursor)
{
    row_assist_t row_ass;
    database_t *db = &(session->kernel->db);
    uint32 mpool_page_id;
    uint32 scan_num;
    uint32 *corr_count = (uint32 *)(cursor->page_buf + sizeof(pc_buf_head_t));

    char *read_buf = pc_alloc_mpool(session, &mpool_page_id);
    datafile_t *df = &db->datafiles[cursor->rowid.file];

    status_t status = CT_SUCCESS;
    if (!(df->ctrl->used) || DF_FILENO_IS_INVAILD(df) || !DATAFILE_IS_ONLINE(df)) {
        status = pc_set_file_summary(df, cursor, &row_ass, 0, *corr_count);
        mpool_free_page(session->kernel->attr.large_pool, mpool_page_id);
        pc_move_next_file(cursor);
        return status;
    }

    uint32 df_hwm = (SPACE_GET(session, df->space_id))->head->hwms[df->file_no];
    uint32 max_count = CT_LARGE_PAGE_SIZE / DEFAULT_PAGE_SIZE(session);
    uint32 fetch_page_num = df_hwm - (uint32)cursor->rowid.page;
    uint32 page_blocks = (uint32)((fetch_page_num + (max_count - 1)) / max_count);
    uint32 last_fetch_page_num = ((fetch_page_num % max_count) == 0) ? max_count : (fetch_page_num % max_count);
    for (uint32 i = 0; i < page_blocks; ++i) {
        // to avoid overread, do not read uninit pages
        scan_num = (i == (page_blocks - 1)) ? last_fetch_page_num : max_count;
        if (pc_block_and_read_datafile(session, df, (uint32)cursor->rowid.page, scan_num, read_buf) != CT_SUCCESS) {
            mpool_free_page(session->kernel->attr.large_pool, mpool_page_id);
            return CT_ERROR;
        }

        if (pc_verify_page_checksum_num(session, cursor, scan_num, read_buf) != CT_SUCCESS) {
            mpool_free_page(session->kernel->attr.large_pool, mpool_page_id);
            // use page_buf to count corrput page num in one datafile
            (*corr_count)++;
            return CT_SUCCESS;
        }
    }

    // finish scan one datafile, fill in summary message, and move to next page
    status = pc_set_file_summary(df, cursor, &row_ass, df_hwm, *corr_count);
    mpool_free_page(session->kernel->attr.large_pool, mpool_page_id);
    pc_move_next_file(cursor);
    return status;
}

status_t dba_page_corruption_scan(knl_session_t *session, knl_cursor_t *cursor)
{
    database_t *db = &(session->kernel->db);
    row_assist_t row_ass;
    uint32 mpool_page_id;
    uint16 org_cks;
    uint16 calc_cks = 0;
    char *read_buf = pc_alloc_mpool(session, &mpool_page_id);
    datafile_t *df = &db->datafiles[cursor->rowid.file];

    if (pc_block_and_read_datafile(session, df, (uint32)cursor->rowid.page, 1, read_buf) != CT_SUCCESS) {
        mpool_free_page(session->kernel->attr.large_pool, mpool_page_id);
        return CT_ERROR;
    }

    page_head_t *page = (page_head_t *)read_buf;
    row_init(&row_ass, (char *)cursor->row, CT_MAX_ROW_SIZE, PAGE_CORRUPTION_COLS);
    CT_RETURN_IFERR(row_put_int32(&row_ass, (int32)(df->ctrl->id)));
    CT_RETURN_IFERR(row_put_str(&row_ass, df->ctrl->name));

    org_cks = PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session));

    if (PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)) != CT_INVALID_CHECKSUM &&
        !page_verify_checksum(page, DEFAULT_PAGE_SIZE(session))) {
        CT_LOG_RUN_ERR("page %u-%u corrupted: checksum level %s, checksum %u, page size %u, "
                       "page type %s, space name %s, datafile name %s",
                       df->ctrl->id, cursor->rowid.page, knl_checksum_level(g_cks_level),
            PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)),
            PAGE_SIZE(*page), page_type(page->type), (SPACE_GET(session, df->space_id))->ctrl->name, df->ctrl->name);

        PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)) = CT_INVALID_CHECKSUM;
        calc_cks = (REDUCE_CKS2UINT16(cm_get_checksum(page, DEFAULT_PAGE_SIZE(session))));
        CT_RETURN_IFERR(row_put_str(&row_ass, "CORRUPT PAGE"));
        CT_RETURN_IFERR(row_put_int32(&row_ass, 1)); // EXAMINED_NUM, always 1
        CT_RETURN_IFERR(row_put_int32(&row_ass, 0)); // SUCCESS_NUM
        CT_RETURN_IFERR(row_put_int32(&row_ass, 1)); // CORRUPTED_NUM
    } else {
        calc_cks = org_cks;
        CT_RETURN_IFERR(row_put_str(&row_ass, "PAGE"));
        CT_RETURN_IFERR(row_put_int32(&row_ass, 1)); // EXAMINED_NUM, always 1
        CT_RETURN_IFERR(row_put_int32(&row_ass, 1)); // SUCCESS_NUM
        CT_RETURN_IFERR(row_put_int32(&row_ass, 0)); // CORRUPTED_NUM
    }
    CT_RETURN_IFERR(row_put_int32(&row_ass, (int32)(cursor->rowid.page)));
    CT_RETURN_IFERR(row_put_str(&row_ass, page_type(page->type)));
    CT_RETURN_IFERR(row_put_int32(&row_ass, (int32)org_cks));
    CT_RETURN_IFERR(row_put_int32(&row_ass, (int32)calc_cks));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    mpool_free_page(session->kernel->attr.large_pool, mpool_page_id);
    cursor->rowid.page++;
    return CT_SUCCESS;
}

status_t dba_verify_table(knl_session_t *session, knl_cursor_t *cursor, knl_dictionary_t *dc, bool8 *is_corrupt)
{
    knl_corrupt_info_t info = { 0 };
    char str[CT_NAME_BUFFER_SIZE]; // CT_MAX_DATAFILE_PAGES is 1073741824, 32 bytes is enough

    if (knl_verify_table(session, dc, &info) == CT_SUCCESS) {
        return CT_SUCCESS;
    }

    if (DC_ENTITY(dc)->corrupted) {
        cm_reset_error();
        CT_THROW_ERROR(ERR_DC_CORRUPTED);
        return CT_ERROR;
    }

    errno_t err_code = cm_get_error_code();
    if (err_code != ERR_PAGE_CORRUPTED) {
        return CT_ERROR;
    }
    cm_reset_error();

    *is_corrupt = CT_TRUE;

    row_assist_t row_ass;
    row_init(&row_ass, (char *)cursor->row, CT_MAX_ROW_SIZE, TABLE_CORRUPTION_COLS);
    PRTS_RETURN_IFERR(sprintf_s(str, sizeof(str), "%u-%u", info.page_id.file, info.page_id.page));
    CT_RETURN_IFERR(row_put_str(&row_ass, str));
    CT_RETURN_IFERR(row_put_str(&row_ass, info.space_name));
    CT_RETURN_IFERR(row_put_str(&row_ass, info.datafile_name));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    return CT_SUCCESS;
}

static status_t read_lob_from_vmpool(sql_stmt_t *stmt, variant_t *val, text_t *ddl_info)
{
    id_list_t *vm_list = sql_get_pre_lob_list(stmt);
    vm_pool_t *vm_pool = stmt->mtrl.pool;
    uint32 remain_size, buff_size, vmid;
    vm_page_t *page = NULL;
    binary_t piece;

    ddl_info->len = 0;
    buff_size = val->v_lob.vm_lob.size + 1;
    ddl_info->str = (char *)cm_push(stmt->session->stack, buff_size);
    if (ddl_info->str == NULL) {
        CT_THROW_ERROR(ERR_TF_DDL_INFO_OVER_LEN);
        return CT_ERROR;
    }

    remain_size = val->v_lob.vm_lob.size;
    vmid = val->v_lob.vm_lob.entry_vmid;

    while (remain_size > 0) {
        if (sql_check_lob_vmid(vm_list, vm_pool, vmid) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_NO_FREE_VMEM, "vm page is invalid when table function read lob value");
            return CT_ERROR;
        }

        CT_RETURN_IFERR(vm_open(stmt->session, vm_pool, vmid, &page));

        piece.bytes = (uint8 *)page->data;
        piece.size = (CT_VMEM_PAGE_SIZE > remain_size) ? remain_size : CT_VMEM_PAGE_SIZE;
        remain_size -= piece.size;

        errno_t errcode = memcpy_s(ddl_info->str + ddl_info->len, buff_size - ddl_info->len, piece.bytes, piece.size);
        if (errcode != EOK) {
            vm_close(stmt->session, vm_pool, vmid, VM_ENQUE_HEAD);
            CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CT_ERROR;
        }
        ddl_info->len += piece.size;

        vm_close(stmt->session, vm_pool, vmid, VM_ENQUE_HEAD);
        vmid = vm_get_ctrl(vm_pool, vmid)->sort_next;
    }

    return CT_SUCCESS;
}

status_t read_lob_value(sql_stmt_t *stmt, variant_t *val, text_t *ddl_info)
{
    switch (val->v_lob.type) {
        case CT_LOB_FROM_NORMAL:
            *ddl_info = val->v_lob.normal_lob.value;
            break;
        case CT_LOB_FROM_VMPOOL:
            return read_lob_from_vmpool(stmt, val, ddl_info);
        case CT_LOB_FROM_KERNEL:
        default:
            CT_THROW_ERROR(ERR_TF_DDL_INFO_OVER_LEN);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t table_cast_put_object_row(sql_stmt_t *stmt, variant_t *val, row_assist_t *row_ass,
    plv_collection_t *collection, variant_t *index)
{
    uint32 col;
    variant_t result, temp_coll;
    plv_object_attr_t *attr = NULL;
    col = collection->elmt_type->typdef.object.count;
    CT_RETURN_IFERR(udt_coll_elemt_address(stmt, val, index, &temp_coll, NULL));
    for (uint32 i = 0; i < col; i++) {
        if (!temp_coll.is_null) {
            CT_RETURN_IFERR(udt_object_field_address(stmt, &temp_coll, i, &result, NULL));
            attr = udt_seek_obj_field_byid(&collection->elmt_type->typdef.object, i);
            CT_RETURN_IFERR(sql_put_row_value(stmt, NULL, row_ass, attr->scalar_field->type_mode.datatype, &result));
        } else {
            CT_RETURN_IFERR(row_put_null(row_ass));
        }
    }
    return CT_SUCCESS;
}

status_t table_cast_fetch_core(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor, row_assist_t *row_ass)
{
    variant_t result;
    char *buf = NULL;
    variant_t *coll_var = (variant_t *)cursor->page_buf;
    variant_t index;
    uint32 id = (uint32)cursor->rowid.vmid;
    status_t status = CT_ERROR;
    expr_tree_t *arg2 = func->args->next;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    plv_collection_t *collection = (plv_collection_t *)func->args->next->root->udt_type;
    if (coll_var->is_null) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    CTSQL_SAVE_STACK(stmt);
    OPEN_VM_PTR(&coll_var->v_collection.value, vm_ctx);

    do {
        CT_BREAK_IF_ERROR(sql_push(stmt, CT_CONVERT_BUFFER_SIZE, (void **)&buf));
        mtrl_ctrl_t *ctrl = (mtrl_ctrl_t *)d_ptr;
        if (id >= ctrl->count) {
            cursor->eof = CT_TRUE;
            status = CT_SUCCESS;
            break;
        }
        bool8 exec_default = arg2->root->exec_default ? CT_FALSE : CT_TRUE;
        index.is_null = CT_FALSE;
        index.type = CT_TYPE_INTEGER;
        index.v_int = id + 1;
        if (collection->attr_type == UDT_OBJECT) {
            CT_BREAK_IF_ERROR(table_cast_put_object_row(stmt, coll_var, row_ass, collection, &index));
        } else {
            CT_BREAK_IF_ERROR(udt_coll_elemt_address(stmt, coll_var, &index, &result, NULL));

            CT_BREAK_IF_ERROR(sql_convert_variant(stmt, &result, collection->type_mode.datatype));
            if (!result.is_null) {
                CT_BREAK_IF_ERROR(sql_apply_typmode(&result, &collection->type_mode, buf, exec_default));
            }
            CT_BREAK_IF_ERROR(sql_put_row_value(stmt, NULL, row_ass, collection->type_mode.datatype, &result));
        }
        status = CT_SUCCESS;
        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
        cursor->rowid.vmid++;
    } while (0);
    CLOSE_VM_PTR(&coll_var->v_collection.value, vm_ctx);
    CTSQL_RESTORE_STACK(stmt);

    /* in dml should free vm memory immediate, in anonymous colleciton is freed by framework */
    if (cursor->eof && stmt->pl_exec == NULL) {
        udt_invoke_coll_destructor(stmt, coll_var);
    }

    return status;
}

status_t pending_trans_session_args(sql_stmt_t *stmt, table_func_t *func, variant_t *fmt_id, variant_t *global_tran_id,
    variant_t *branch_id)
{
    CT_RETURN_IFERR(sql_exec_expr(stmt, func->args, fmt_id));
    CT_RETURN_IFERR(sql_convert_variant(stmt, fmt_id, CT_TYPE_BIGINT));
    if (fmt_id->is_null) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "fmt_id", "fmt_id can not be null");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_exec_expr(stmt, func->args->next, branch_id));
    CT_RETURN_IFERR(sql_convert_variant(stmt, branch_id, CT_TYPE_STRING));
    if (branch_id->is_null) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "branch_id", "branch_id can not be null");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_exec_expr(stmt, func->args->next->next, global_tran_id));
    CT_RETURN_IFERR(sql_convert_variant(stmt, global_tran_id, CT_TYPE_STRING));
    if (global_tran_id->is_null) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "global_tran_id", "global_tran_id can not be null");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t pending_trans_session_put(session_t *session, knl_cursor_t *cursor, variant_t *global_tran_id,
    variant_t *branch_id)
{
    row_assist_t row_ass;

    row_init(&row_ass, (char *)cursor->row, CT_MAX_ROW_SIZE, PENDING_TRANS_SESSION_COLS);
    CT_RETURN_IFERR(row_put_int32(&row_ass, session->knl_session.id));
    CT_RETURN_IFERR(row_put_int32(&row_ass, session->knl_session.serial_id));
    CT_RETURN_IFERR(row_put_int64(&row_ass, g_instance->attr.xa_fmt_id));
    CT_RETURN_IFERR(row_put_text(&row_ass, &branch_id->v_text));
    CT_RETURN_IFERR(row_put_text(&row_ass, &global_tran_id->v_text));
    CT_RETURN_IFERR(row_put_int64(&row_ass, 0));
    CT_RETURN_IFERR(row_put_int64(&row_ass, 0));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;

    return CT_SUCCESS;
}

// need be sort by ALPHABET
static table_func_desc_t g_table_funcs[] = {
    { { "sys", 3 }, { "", 0 }, { "cast", 4 }, TABLE_CAST_COLS, g_cast_columns, table_cast_exec, table_cast_fetch, table_cast_verify, NULL, NULL, NULL, NULL, TFM_MEMORY },
    { { "sys", 3 }, { "", 0 }, { "dba_analyze_table", 17 }, ANAYLYZE_TABLE_COLS, g_analyze_table_columns, dba_analyze_table_exec, dba_analyze_table_fetch, dba_analyze_table_verify, NULL, NULL, NULL, NULL, TFM_MEMORY },
    { { "sys", 3 }, { "", 0 }, { "dba_free_space", 14 }, GET_FREE_SPACE_COLS, g_dba_free_space_columns, dba_free_space_exec, dba_free_space_fetch, dba_free_space_verify, NULL, NULL, NULL, NULL, TFM_MEMORY },
    { { "sys", 3 }, { "", 0 }, { "dba_index_corruption", 20 }, INDEX_CORRUPTION_COLS, g_index_corruption_columns, dba_index_corruption_exec, dba_index_corruption_fetch, dba_index_corruption_verify, NULL, NULL, NULL, NULL, TFM_MEMORY },
    { { "sys", 3 }, { "", 0 }, { "dba_page_corruption", 19 }, PAGE_CORRUPTION_COLS, g_page_corruption_columns, dba_page_corruption_exec, dba_page_corruption_fetch, dba_page_corruption_verify, NULL, NULL, NULL, NULL, TFM_MEMORY },
    { { "sys", 3 }, { "", 0 }, { "dba_proc_decode", 15 }, PROC_DECODE_COLS, g_proc_decode_columns, dba_proc_decode_exec, dba_proc_decode_fetch, dba_proc_decode_verify, NULL, NULL, NULL, NULL, TFM_MEMORY },
    { { "sys", 3 }, { "", 0 }, { "dba_proc_line", 13 }, PROC_LINE_COLS, g_proc_line_columns, dba_proc_line_exec, dba_proc_line_fetch, dba_proc_line_verify, NULL, NULL, NULL, NULL, TFM_MEMORY },
    { { "sys", 3 }, { "", 0 }, { "dba_table_corruption", 20 }, TABLE_CORRUPTION_COLS, g_table_corruption_columns, dba_table_corruption_exec, dba_table_corruption_fetch, dba_table_corruption_verify, NULL, NULL, NULL, NULL, TFM_MEMORY },
    { { "sys", 3 }, { "", 0 }, { "dbg_break_info", 14 }, BREAK_INFO_COLS, g_breakpoint_info_columns, dbg_break_info_exec, dbg_break_info_fetch, dbg_break_info_verify, NULL, NULL, NULL, NULL, TFM_MEMORY },
    { { "sys", 3 }, { "", 0 }, { "dbg_control_info", 16 }, CONTROL_INFO_COLS, g_control_info_columns, dbg_control_info_exec, dbg_control_info_fetch, dbg_control_info_verify, NULL, NULL, NULL, NULL, TFM_MEMORY },
    { { "sys", 3 }, { "", 0 }, { "dbg_proc_callstack", 18 }, PROC_CALLSTACK_COLS, g_proc_callstack_columns, dbg_proc_callstack_exec, dbg_proc_callstack_fetch, dbg_proc_callstack_verify, NULL, NULL, NULL, NULL, TFM_MEMORY },
    { { "sys", 3 }, { "", 0 }, { "dbg_show_values", 15 }, SHOW_VALUES_COLS, g_show_values_columns, dbg_show_values_exec, dbg_show_values_fetch, dbg_show_values_verify, NULL, NULL, NULL, NULL, TFM_MEMORY },
    { { "sys", 3 }, { "", 0 }, { "get_tab_parallel", 16 }, GET_TAB_PARALLEL_COLS, g_table_paralel_columns, get_tab_parallel_exec, get_tab_parallel_fetch, get_tab_paralle_verify, NULL, NULL, NULL, NULL, TFM_MEMORY },
    { { "sys", 3 }, { "", 0 }, { "get_tab_rows", 12 }, CT_INVALID_ID32, NULL, get_table_rows_exec, get_table_rows_fetch, get_table_rows_verify, pre_set_parms_get_rows, set_parms_get_rows, get_tab_rows_scan_flag, NULL, TFM_TABLE_ROW },
    { { "sys", 3 }, { "", 0 }, { "parallel_scan", 13 }, CT_INVALID_ID32, NULL, parallel_scan_exec, parallel_scan_fetch, parallel_scan_verify, pre_set_parms_paral_scan, set_parms_paral_scan, parallel_scan_flag, NULL, TFM_TABLE_RS },
};

#define SQL_TABLE_FUNC_COUNT (sizeof(g_table_funcs) / sizeof(table_func_desc_t))

static table_func_desc_t *sql_get_table_func(uint32 func_id)
{
    return &g_table_funcs[func_id];
}

static text_t *sql_table_func_name(void *set, uint32 func_id)
{
    return &g_table_funcs[func_id].name;
}

status_t sql_get_table_func_id(sql_table_t *table, uint32 *id)
{
    text_t *func_name = &table->func.name;
    uint32 func_id = sql_func_binsearch(func_name, sql_table_func_name, NULL, SQL_TABLE_FUNC_COUNT);
    if (func_id == CT_INVALID_ID32) {
        CT_SRC_THROW_ERROR(table->func.loc, ERR_FUNCTION_NOT_EXIST, T2S(func_name));
        return CT_ERROR;
    }
    *id = func_id;
    return CT_SUCCESS;
}

status_t sql_describe_table_func(sql_verifier_t *verf, sql_table_t *table, uint32 tbl_id)
{
    uint32 id;

    if (sql_get_table_func_id(table, &id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    table_func_desc_t *desc = sql_get_table_func(id);
    if (desc->method != TFM_MEMORY && tbl_id > 0) {
        CT_THROW_ERROR(ERR_TF_ONLY_ONE_TABLE);
        return CT_ERROR;
    }

    if (desc->verify(verf, table) != CT_SUCCESS) {
        return CT_ERROR;
    }

    table->func.desc = desc;
    return CT_SUCCESS;
}

status_t dba_verify_index_by_name(knl_session_t *session, knl_cursor_t *cursor, knl_dictionary_t *dc,
    text_t *index_name, bool8 *is_corrupt)
{
    knl_corrupt_info_t info = { 0 };
    char str[CT_NAME_BUFFER_SIZE]; // CT_MAX_DATAFILE_PAGES is 1073741824, 32 bytes is enough

    if (knl_verify_index_by_name(session, dc, index_name, &info) == CT_SUCCESS) {
        return CT_SUCCESS;
    }

    if (DC_ENTITY(dc)->corrupted) {
        cm_reset_error();
        CT_THROW_ERROR(ERR_DC_CORRUPTED);
        return CT_ERROR;
    }

    errno_t err_code = cm_get_error_code();
    if (err_code != ERR_PAGE_CORRUPTED) {
        return CT_ERROR;
    }
    cm_reset_error();

    *is_corrupt = CT_TRUE;

    row_assist_t row_ass;
    row_init(&row_ass, (char *)cursor->row, CT_MAX_ROW_SIZE, INDEX_CORRUPTION_COLS);
    PRTS_RETURN_IFERR(sprintf_s(str, sizeof(str), "%u-%u", info.page_id.file, info.page_id.page));
    CT_RETURN_IFERR(row_put_str(&row_ass, str));
    CT_RETURN_IFERR(row_put_str(&row_ass, info.space_name));
    CT_RETURN_IFERR(row_put_str(&row_ass, info.datafile_name));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    return CT_SUCCESS;
}
