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
 * ctsql_statistics.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/ctsql_statistics.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_stmt.h"
#include "srv_instance.h"
#include "dml_executor.h"

#ifdef __cplusplus
extern "C" {
#endif

void sql_begin_exec_stat(void *handle)
{
    session_t *session = (session_t *)handle;
    exec_prev_stat_t *prev_stat = &session->exec_prev_stat;
    knl_stat_t *knl_stat = session->knl_session.stat;

    prev_stat->stat_level++;
    if (prev_stat->stat_level > 1) {
        return;
    }

    prev_stat->io_wait_time = knl_stat->disk_read_time;
    prev_stat->con_wait_time = knl_stat->con_wait_time;
    prev_stat->res_io_wait_time = session->stat.res_io_wait_time;
    prev_stat->dcs_net_time = knl_stat->dcs_net_time;
    (void)cm_gettimeofday(&prev_stat->tv_start);
}

void sql_end_exec_stat(void *handle)
{
    timeval_t tv_end;
    uint64 elapsed_time, io_time, con_time, res_io_time, cpu_time;
    uint64 dcs_net_time;
    session_t *session = (session_t *)handle;
    sql_stat_t *stat = &session->stat;
    exec_prev_stat_t *prev_stat = &session->exec_prev_stat;

    knl_stat_t *knl_stat = session->knl_session.stat;
    if (prev_stat->stat_level > 0) {
        prev_stat->stat_level--;
    }
    if (prev_stat->stat_level > 0) {
        return;
    }

    (void)cm_gettimeofday(&tv_end);
    elapsed_time = TIMEVAL_DIFF_US(&prev_stat->tv_start, &tv_end);
    io_time = knl_stat->disk_read_time - prev_stat->io_wait_time;
    con_time = knl_stat->con_wait_time - prev_stat->con_wait_time;
    res_io_time = stat->res_io_wait_time - prev_stat->res_io_wait_time;
    dcs_net_time = knl_stat->dcs_net_time - prev_stat->dcs_net_time;
    cpu_time = elapsed_time - io_time - con_time - res_io_time - dcs_net_time;

    stat->exec_time += elapsed_time;
    stat->cpu_time += cpu_time;
    stat->io_wait_time += io_time;
    stat->dcs_net_time += dcs_net_time;

    if (session->rsrc_group != NULL) {
        rsrc_cpu_time_add(session, cpu_time);
    }
}

static void sql_save_datafile_stats(sql_stmt_t *stmt)
{
    ctx_prev_stat_t *context_pre_stat = &stmt->session->ctx_prev_stat;
    knl_stat_t *knl_stat = stmt->session->knl_session.stat;

    context_pre_stat->scattered_reads = knl_stat->wait_count[DB_FILE_SCATTERED_READ];
    context_pre_stat->scattered_time = knl_stat->wait_time[DB_FILE_SCATTERED_READ];
    context_pre_stat->sequential_reads = knl_stat->wait_count[DB_FILE_SEQUENTIAL_READ];
    context_pre_stat->sequential_time = knl_stat->wait_time[DB_FILE_SEQUENTIAL_READ];
    context_pre_stat->wait_map = knl_stat->wait_count[ENQ_HEAP_MAP];
    context_pre_stat->wait_map_time = knl_stat->wait_time[ENQ_HEAP_MAP];
    context_pre_stat->segment_extends = knl_stat->wait_count[ENQ_SEGMENT_EXTEND];
    context_pre_stat->segment_extend_time = knl_stat->wait_time[ENQ_SEGMENT_EXTEND];
}

static void sql_save_buffer_stats(sql_stmt_t *stmt)
{
    knl_stat_t *knl_stat = stmt->session->knl_session.stat;
    ctx_prev_stat_t *context_pre_stat = &stmt->session->ctx_prev_stat;
    knl_buf_wait_t *buf_wait = stmt->session->knl_session.buf_wait;

    context_pre_stat->buf_busy_waits = knl_stat->wait_count[BUFFER_BUSY_WAIT];
    context_pre_stat->buf_busy_wait_time = knl_stat->wait_time[BUFFER_BUSY_WAIT];
    context_pre_stat->data_block = buf_wait[DATA_BLOCK].wait_count;
    context_pre_stat->data_block_time = buf_wait[DATA_BLOCK].wait_time;
    context_pre_stat->segment_header = buf_wait[SEGMENT_HEADER].wait_count;
    context_pre_stat->segment_header_time = buf_wait[SEGMENT_HEADER].wait_time;
    context_pre_stat->undo_header = buf_wait[UNDO_HEADER].wait_count;
    context_pre_stat->undo_header_time = buf_wait[UNDO_HEADER].wait_time;
    context_pre_stat->undo_block = buf_wait[UNDO_BLOCK].wait_count;
    context_pre_stat->undo_block_time = buf_wait[UNDO_BLOCK].wait_time;
    context_pre_stat->free_list = buf_wait[FREE_LIST].wait_count;
    context_pre_stat->free_list_time = buf_wait[FREE_LIST].wait_time;
}

static void sql_save_log_stats(sql_stmt_t *stmt)
{
    knl_stat_t *knl_stat = stmt->session->knl_session.stat;
    ctx_prev_stat_t *context_pre_stat = &stmt->session->ctx_prev_stat;

    context_pre_stat->log_arch = knl_stat->wait_count[LOG_FILE_SWITCH_ARCH];
    context_pre_stat->log_arch_time = knl_stat->wait_time[LOG_FILE_SWITCH_ARCH];
    context_pre_stat->log_ckpt = knl_stat->wait_count[LOG_FILE_SWITCH_CKPT];
    context_pre_stat->log_ckpt_time = knl_stat->wait_time[LOG_FILE_SWITCH_CKPT];
    context_pre_stat->log_sync = knl_stat->wait_count[LOG_FILE_SYNC];
    context_pre_stat->log_sync_time = knl_stat->wait_time[LOG_FILE_SYNC];
    context_pre_stat->log_bytes = knl_stat->redo_bytes;
}

static void sql_save_tempspace_stats(sql_stmt_t *stmt)
{
    knl_stat_t *knl_stat = stmt->session->knl_session.stat;
    ctx_prev_stat_t *context_pre_stat = &stmt->session->ctx_prev_stat;

    context_pre_stat->temp_reads = knl_stat->wait_count[DIRECT_PATH_READ_TEMP];
    context_pre_stat->temp_read_time = knl_stat->wait_time[DIRECT_PATH_READ_TEMP];
    context_pre_stat->temp_writes = knl_stat->wait_count[DIRECT_PATH_WRITE_TEMP];
    context_pre_stat->temp_write_time = knl_stat->wait_time[DIRECT_PATH_WRITE_TEMP];
    context_pre_stat->sorts = knl_stat->wait_count[MTRL_SEGMENT_SORT];
    context_pre_stat->sort_time = knl_stat->wait_time[MTRL_SEGMENT_SORT];

    context_pre_stat->disk_sorts = knl_stat->disk_sorts - context_pre_stat->disk_sorts;
}

static void sql_save_tx_stats(sql_stmt_t *stmt)
{
    knl_stat_t *knl_stat = stmt->session->knl_session.stat;
    ctx_prev_stat_t *context_pre_stat = &stmt->session->ctx_prev_stat;

    context_pre_stat->row_lock = knl_stat->wait_count[ENQ_TX_ROW];
    context_pre_stat->row_lock_time = knl_stat->wait_time[ENQ_TX_ROW];
    context_pre_stat->key_lock = knl_stat->wait_count[ENQ_TX_KEY];
    context_pre_stat->key_lock_time = knl_stat->wait_time[ENQ_TX_KEY];
    context_pre_stat->itl_alloc = knl_stat->wait_count[ENQ_TX_ITL];
    context_pre_stat->itl_alloc_time = knl_stat->wait_time[ENQ_TX_ITL];
    context_pre_stat->table_slock = knl_stat->wait_count[ENQ_TX_TABLE_S];
    context_pre_stat->table_slock_time = knl_stat->wait_time[ENQ_TX_TABLE_S];
    context_pre_stat->table_xlock = knl_stat->wait_count[ENQ_TX_TABLE_X];
    context_pre_stat->table_xlock_time = knl_stat->wait_time[ENQ_TX_TABLE_X];
    context_pre_stat->read_wait = knl_stat->wait_count[ENQ_TX_READ_WAIT];
    context_pre_stat->read_wait_time = knl_stat->wait_time[ENQ_TX_READ_WAIT];
}

static inline bool8 supported_stat_ctx_type(sql_type_t type)
{
    if (type < CTSQL_TYPE_DML_CEIL || type == CTSQL_TYPE_ANONYMOUS_BLOCK) {
        return CT_TRUE;
    }

    if (!SQL_OPT_PWD_DDL_TYPE(type)) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

void sql_begin_ctx_stat(void *handle)
{
    sql_stmt_t *stmt = (sql_stmt_t *)handle;
    ctx_prev_stat_t *context_pre_stat = &stmt->session->ctx_prev_stat;
    knl_stat_t *knl_stat = stmt->session->knl_session.stat;
    if (!g_instance->sql.enable_stat || stmt->context == NULL) {
        return;
    }
    if (!supported_stat_ctx_type(stmt->context->type)) {
        return;
    }
    context_pre_stat->disk_reads = knl_stat->disk_reads;
    context_pre_stat->buffer_gets = knl_stat->buffer_gets;
    context_pre_stat->cr_gets = knl_stat->cr_gets;
    context_pre_stat->dcs_buffer_gets = knl_stat->dcs_buffer_gets;
    context_pre_stat->dcs_buffer_sends = knl_stat->dcs_buffer_sends;
    context_pre_stat->dcs_cr_gets = knl_stat->dcs_cr_gets;
    context_pre_stat->dcs_cr_sends = knl_stat->dcs_cr_sends;
    context_pre_stat->cr_reads = knl_stat->cr_reads;
    context_pre_stat->dcs_cr_reads = knl_stat->dcs_cr_reads;
    context_pre_stat->io_wait_time = knl_stat->disk_read_time;
    context_pre_stat->con_wait_time = knl_stat->con_wait_time;
    context_pre_stat->dcs_net_time = knl_stat->dcs_net_time;
    context_pre_stat->sorts = knl_stat->sorts;
    context_pre_stat->processed_rows = knl_stat->processed_rows;

    sql_save_datafile_stats(stmt);
    sql_save_buffer_stats(stmt);
    sql_save_log_stats(stmt);
    sql_save_tempspace_stats(stmt);
    sql_save_tx_stats(stmt);

    (void)cm_gettimeofday(&context_pre_stat->tv_start);
    (void)cm_atomic_set(&stmt->context->stat.last_active_time, g_timer()->now);

    // attach sql info from context to session
    cm_spin_lock(&stmt->session->sess_lock, NULL);
    if (stmt->context->type != CTSQL_TYPE_ANONYMOUS_BLOCK) {
        ctx_read_first_page_text(sql_pool, &stmt->context->ctrl, &stmt->session->current_sql);
        stmt->session->sql_id = stmt->context->ctrl.hash_value;
    } else {
        pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
        stmt->session->current_sql = pl_ctx->anonymous->desc.sql;
        stmt->session->sql_id = pl_ctx->anonymous->desc.sql_hash;
    }

    cm_spin_unlock(&stmt->session->sess_lock);
}

/* accumulate stat info on datafile */
static void sql_datafile_statinfo_accumulate(sql_stmt_t *stmt, ctx_stat_t *context_stat)
{
    knl_stat_t *knl_stat = stmt->session->knl_session.stat;
    ctx_prev_stat_t *context_pre_stat = &stmt->session->ctx_prev_stat;

    int64 stat_temp = (int64)(knl_stat->wait_count[DB_FILE_SCATTERED_READ] - context_pre_stat->scattered_reads);
    cm_atomic_add(&context_stat->scattered_reads, stat_temp);
    stat_temp = (int64)(knl_stat->wait_time[DB_FILE_SCATTERED_READ] - context_pre_stat->scattered_time);
    cm_atomic_add(&context_stat->scattered_time, stat_temp);
    stat_temp = (int64)(knl_stat->wait_count[DB_FILE_SEQUENTIAL_READ] - context_pre_stat->sequential_reads);
    cm_atomic_add(&context_stat->sequential_reads, stat_temp);
    stat_temp = (int64)(knl_stat->wait_time[DB_FILE_SEQUENTIAL_READ] - context_pre_stat->sequential_time);
    cm_atomic_add(&context_stat->sequential_time, stat_temp);
    stat_temp = (int64)(knl_stat->wait_count[ENQ_HEAP_MAP] - context_pre_stat->wait_map);
    cm_atomic_add(&context_stat->wait_map, stat_temp);
    stat_temp = (int64)(knl_stat->wait_time[ENQ_HEAP_MAP] - context_pre_stat->wait_map_time);
    cm_atomic_add(&context_stat->wait_map_time, stat_temp);
    stat_temp = (int64)(knl_stat->wait_count[ENQ_SEGMENT_EXTEND] - context_pre_stat->segment_extends);
    cm_atomic_add(&context_stat->segment_extends, stat_temp);
    stat_temp = (int64)(knl_stat->wait_time[ENQ_SEGMENT_EXTEND] - context_pre_stat->segment_extend_time);
    cm_atomic_add(&context_stat->segment_extend_time, stat_temp);
    stat_temp = (int64)(knl_stat->aio_reads - context_pre_stat->aio_reads);
    cm_atomic_add(&context_stat->aio_reads, stat_temp);
}

/* accumulate stat info on buffer page */
static void sql_buffer_statinfo_accumulate(sql_stmt_t *stmt, ctx_stat_t *context_stat)
{
    knl_stat_t *knl_stat = stmt->session->knl_session.stat;
    ctx_prev_stat_t *context_pre_stat = &stmt->session->ctx_prev_stat;
    knl_buf_wait_t *buf_wait = stmt->session->knl_session.buf_wait;

    int64 stat_temp = (int64)(knl_stat->wait_count[BUFFER_BUSY_WAIT] - context_pre_stat->buf_busy_waits);
    cm_atomic_add(&context_stat->buf_busy_waits, stat_temp);
    stat_temp = (int64)(knl_stat->wait_time[BUFFER_BUSY_WAIT] - context_pre_stat->buf_busy_wait_time);
    cm_atomic_add(&context_stat->buf_busy_wait_time, stat_temp);
    stat_temp = (int64)(knl_stat->wait_count[BUFFER_POOL_ALLOC] - context_pre_stat->buff_pool_alloc);
    cm_atomic_add(&context_stat->buff_pool_alloc, stat_temp);
    stat_temp = (int64)(knl_stat->wait_time[BUFFER_POOL_ALLOC] - context_pre_stat->buff_pool_alloc_time);
    cm_atomic_add(&context_stat->buff_pool_alloc_time, stat_temp);
    stat_temp = (int64)(buf_wait[DATA_BLOCK].wait_count - context_pre_stat->data_block);
    cm_atomic_add(&context_stat->data_block, stat_temp);
    stat_temp = (int64)(buf_wait[DATA_BLOCK].wait_time - context_pre_stat->data_block_time);
    cm_atomic_add(&context_stat->data_block_time, stat_temp);
    stat_temp = (int64)(buf_wait[SEGMENT_HEADER].wait_count - context_pre_stat->segment_header);
    cm_atomic_add(&context_stat->segment_header, stat_temp);
    stat_temp = (int64)(buf_wait[SEGMENT_HEADER].wait_time - context_pre_stat->segment_header_time);
    cm_atomic_add(&context_stat->segment_header_time, stat_temp);
    stat_temp = (int64)(buf_wait[UNDO_HEADER].wait_count - context_pre_stat->undo_header);
    cm_atomic_add(&context_stat->undo_header, stat_temp);
    stat_temp = (int64)(buf_wait[UNDO_HEADER].wait_time - context_pre_stat->undo_header_time);
    cm_atomic_add(&context_stat->undo_header_time, stat_temp);
    stat_temp = (int64)(buf_wait[UNDO_BLOCK].wait_count - context_pre_stat->undo_block);
    cm_atomic_add(&context_stat->undo_block, context_pre_stat->undo_block);
    stat_temp = (int64)(buf_wait[UNDO_BLOCK].wait_time - context_pre_stat->undo_block_time);
    cm_atomic_add(&context_stat->undo_block_time, stat_temp);
    stat_temp = (int64)(buf_wait[FREE_LIST].wait_count - context_pre_stat->free_list);
    cm_atomic_add(&context_stat->free_list, context_pre_stat->free_list);
    stat_temp = (int64)(buf_wait[FREE_LIST].wait_time - context_pre_stat->free_list_time);
    cm_atomic_add(&context_stat->free_list_time, stat_temp);

    int dcs_time = (int64)(knl_stat->dcs_net_time - context_pre_stat->dcs_net_time);
    cm_atomic_add(&context_stat->dcs_wait_time, dcs_time);
    cm_atomic_add(&context_stat->dcs_buffer_gets, (int64)(knl_stat->dcs_buffer_gets - context_pre_stat->dcs_buffer_gets));
    cm_atomic_add(&context_stat->dcs_cr_gets, (int64)(knl_stat->dcs_cr_gets - context_pre_stat->dcs_cr_gets));
    cm_atomic_add(&context_stat->cr_gets, (int64)(knl_stat->cr_gets - context_pre_stat->cr_gets));
    cm_atomic_add(&context_stat->dcs_cr_gets, (int64)(knl_stat->dcs_cr_gets - context_pre_stat->dcs_cr_gets));
}

static void sql_log_statinfo_accumulate(sql_stmt_t *stmt, ctx_stat_t *context_stat)
{
    knl_stat_t *knl_stat = stmt->session->knl_session.stat;
    ctx_prev_stat_t *context_pre_stat = &stmt->session->ctx_prev_stat;

    int64 stat_temp = (int64)(knl_stat->wait_count[LOG_FILE_SWITCH_ARCH] - context_pre_stat->log_arch);
    cm_atomic_add(&context_stat->log_arch, stat_temp);
    stat_temp = (int64)(knl_stat->wait_time[LOG_FILE_SWITCH_ARCH] - context_pre_stat->log_arch_time);
    cm_atomic_add(&context_stat->log_arch_time, stat_temp);
    stat_temp = (int64)(knl_stat->wait_count[LOG_FILE_SWITCH_CKPT] - context_pre_stat->log_ckpt);
    cm_atomic_add(&context_stat->log_ckpt, stat_temp);
    stat_temp = (int64)(knl_stat->wait_time[LOG_FILE_SWITCH_CKPT] - context_pre_stat->log_ckpt_time);
    cm_atomic_add(&context_stat->log_ckpt_time, stat_temp);
    stat_temp = (int64)(knl_stat->wait_count[LOG_FILE_SYNC] - context_pre_stat->log_sync);
    cm_atomic_add(&context_stat->log_sync, stat_temp);
    stat_temp = (int64)(knl_stat->wait_time[LOG_FILE_SYNC] - context_pre_stat->log_sync_time);
    cm_atomic_add(&context_stat->log_sync_time, stat_temp);
    stat_temp = (int64)(knl_stat->redo_bytes - context_pre_stat->log_bytes);
    cm_atomic_add(&context_stat->log_bytes, stat_temp);
}

static void sql_tempspace_statinfo_accumulate(sql_stmt_t *stmt, ctx_stat_t *context_stat)
{
    knl_stat_t *knl_stat = stmt->session->knl_session.stat;
    ctx_prev_stat_t *context_pre_stat = &stmt->session->ctx_prev_stat;

    int64 stat_temp = (int64)(knl_stat->wait_count[DIRECT_PATH_READ_TEMP] - context_pre_stat->temp_reads);
    cm_atomic_add(&context_stat->temp_reads, stat_temp);
    stat_temp = (int64)(knl_stat->wait_time[DIRECT_PATH_READ_TEMP] - context_pre_stat->temp_read_time);
    cm_atomic_add(&context_stat->temp_read_time, stat_temp);
    stat_temp = (int64)(knl_stat->wait_count[DIRECT_PATH_WRITE_TEMP] - context_pre_stat->temp_writes);
    cm_atomic_add(&context_stat->temp_writes, stat_temp);
    stat_temp = (int64)(knl_stat->wait_time[DIRECT_PATH_WRITE_TEMP] - context_pre_stat->temp_write_time);
    cm_atomic_add(&context_stat->temp_write_time, stat_temp);
    stat_temp = (int64)(knl_stat->wait_count[MTRL_SEGMENT_SORT] - context_pre_stat->sorts);
    cm_atomic_add(&context_stat->sorts, stat_temp);
    stat_temp = (int64)(knl_stat->wait_time[MTRL_SEGMENT_SORT] - context_pre_stat->sort_time);
    cm_atomic_add(&context_stat->sort_time, stat_temp);

    stat_temp = (int64)(knl_stat->disk_sorts - context_pre_stat->disk_sorts);
    cm_atomic_add(&context_stat->disk_sorts, stat_temp);
}

static void sql_tx_statinfo_accumulate(sql_stmt_t *stmt, ctx_stat_t *context_stat)
{
    knl_stat_t *knl_stat = stmt->session->knl_session.stat;
    ctx_prev_stat_t *context_pre_stat = &stmt->session->ctx_prev_stat;

    int64 stat_temp = (int64)(knl_stat->wait_count[ENQ_TX_ROW] - context_pre_stat->row_lock);
    cm_atomic_add(&context_stat->row_lock, stat_temp);
    stat_temp = (int64)(knl_stat->wait_time[ENQ_TX_ROW] - context_pre_stat->row_lock_time);
    cm_atomic_add(&context_stat->row_lock_time, stat_temp);
    stat_temp = (int64)(knl_stat->wait_count[ENQ_TX_KEY] - context_pre_stat->key_lock);
    cm_atomic_add(&context_stat->key_lock, stat_temp);
    stat_temp = (int64)(knl_stat->wait_time[ENQ_TX_KEY] - context_pre_stat->key_lock_time);
    cm_atomic_add(&context_stat->key_lock_time, stat_temp);
    stat_temp = (int64)(knl_stat->wait_count[ENQ_TX_ITL] - context_pre_stat->itl_alloc);
    cm_atomic_add(&context_stat->itl_alloc, stat_temp);
    stat_temp = (int64)(knl_stat->wait_time[ENQ_TX_ITL] - context_pre_stat->itl_alloc_time);
    cm_atomic_add(&context_stat->itl_alloc_time, stat_temp);
    stat_temp = (int64)(knl_stat->wait_count[ENQ_TX_TABLE_S] - context_pre_stat->table_slock);
    cm_atomic_add(&context_stat->table_slock, stat_temp);
    stat_temp = (int64)(knl_stat->wait_time[ENQ_TX_TABLE_S] - context_pre_stat->table_slock_time);
    cm_atomic_add(&context_stat->table_slock_time, stat_temp);
    stat_temp = (int64)(knl_stat->wait_count[ENQ_TX_TABLE_X] - context_pre_stat->table_xlock);
    cm_atomic_add(&context_stat->table_xlock, stat_temp);
    stat_temp = (int64)(knl_stat->wait_time[ENQ_TX_TABLE_X] - context_pre_stat->table_xlock_time);
    cm_atomic_add(&context_stat->table_xlock_time, stat_temp);
    stat_temp = (int64)(knl_stat->wait_count[ENQ_TX_READ_WAIT] - context_pre_stat->read_wait);
    cm_atomic_add(&context_stat->read_wait, stat_temp);
    stat_temp = (int64)(knl_stat->wait_time[ENQ_TX_READ_WAIT] - context_pre_stat->read_wait_time);
    cm_atomic_add(&context_stat->read_wait_time, stat_temp);
}

static void sql_baseinfo_accumulate(sql_stmt_t *stmt, uint64 elapsed_time, ctx_stat_t *stat)
{
    ctx_prev_stat_t *context_pre_stat = &stmt->session->ctx_prev_stat;
    knl_stat_t *knl_stat = stmt->session->knl_session.stat;
    int64 io_time = (int64)(knl_stat->disk_read_time - context_pre_stat->io_wait_time);
    int64 con_time = (int64)(knl_stat->con_wait_time - context_pre_stat->con_wait_time);
    int64 proc_rows = (int64)(knl_stat->processed_rows - context_pre_stat->processed_rows);

    cm_atomic_add(&stat->elapsed_time, (int64)elapsed_time);
    cm_atomic_add(&stat->disk_reads, (int64)(knl_stat->disk_reads - context_pre_stat->disk_reads));
    cm_atomic_add(&stat->buffer_gets, (int64)(knl_stat->buffer_gets - context_pre_stat->buffer_gets));
    cm_atomic_add(&stat->cr_gets, (int64)(knl_stat->cr_gets - context_pre_stat->cr_gets));
    cm_atomic_add(&stat->io_wait_time, io_time);
    cm_atomic_add(&stat->con_wait_time, con_time);
    cm_atomic_add(&stat->processed_rows, proc_rows);
}

static void sql_context_accumulate(sql_stmt_t *stmt, uint64 passed_time)
{
    if (stmt->context == NULL) {
        return;
    }

    ctx_stat_t *context_stat = &stmt->context->stat;

    /* parallel session is binded to main session, count is added by main session */
    if (stmt->session->type != SESSION_TYPE_SQL_PAR) {
        cm_atomic_add(&context_stat->executions, (int64)stmt->param_info.paramset_size);
    }

    sql_baseinfo_accumulate(stmt, passed_time, context_stat);
    sql_datafile_statinfo_accumulate(stmt, context_stat);
    sql_buffer_statinfo_accumulate(stmt, context_stat);
    sql_log_statinfo_accumulate(stmt, context_stat);
    sql_tempspace_statinfo_accumulate(stmt, context_stat);
    sql_tx_statinfo_accumulate(stmt, context_stat);

    if (!cm_log_param_instance()->longsql_print_enable || stmt->stat == NULL) {
        return;
    }

    /* parallel session is binded to main session, count is added by main session */
    if (stmt->session->type != SESSION_TYPE_SQL_PAR) {
        cm_atomic_add(&stmt->stat->executions, (int64)stmt->param_info.paramset_size);
    }

    sql_baseinfo_accumulate(stmt, passed_time, stmt->stat);
    sql_datafile_statinfo_accumulate(stmt, stmt->stat);
    sql_buffer_statinfo_accumulate(stmt, stmt->stat);
    sql_log_statinfo_accumulate(stmt, stmt->stat);
    sql_tempspace_statinfo_accumulate(stmt, stmt->stat);
    sql_tx_statinfo_accumulate(stmt, stmt->stat);

    if (stmt->session->type == SESSION_TYPE_SQL_PAR) {
        sql_stmt_t *p_stmt = stmt->parent_stmt;
        sql_baseinfo_accumulate(stmt, passed_time, p_stmt->stat);
        sql_datafile_statinfo_accumulate(stmt, p_stmt->stat);
        sql_buffer_statinfo_accumulate(stmt, p_stmt->stat);
        sql_log_statinfo_accumulate(stmt, p_stmt->stat);
        sql_tempspace_statinfo_accumulate(stmt, p_stmt->stat);
        sql_tx_statinfo_accumulate(stmt, p_stmt->stat);
    }
}

void sql_ctx_stat_count(sql_stmt_t *stmt, uint64 *cnt)
{
    /* parallel session is binded to main session, count is added by main session */
    if ((stmt->status == STMT_STATUS_EXECUTING || stmt->status == STMT_STATUS_EXECUTED) &&
        stmt->session->type != SESSION_TYPE_SQL_PAR) {
        *cnt += 1;
    }
}

void sql_ctx_stat_count4single(sql_stmt_t *stmt, sql_stat_t *stat, uint64 passed_time)
{
    switch (stmt->context->type) {
        case CTSQL_TYPE_SELECT:
            stat->exec_select_time += passed_time;
            sql_ctx_stat_count(stmt, &stat->exec_selects);
            break;

        case CTSQL_TYPE_UPDATE:
            stat->exec_update_time += passed_time;
            sql_ctx_stat_count(stmt, &stat->exec_updates);
            break;

        case CTSQL_TYPE_INSERT:
            stat->exec_insert_time += passed_time;
            sql_ctx_stat_count(stmt, &stat->exec_inserts);
            break;

        case CTSQL_TYPE_DELETE:
            stat->exec_delete_time += passed_time;
            sql_ctx_stat_count(stmt, &stat->exec_deletes);
            break;

        default:
            break;
    }
}

void sql_end_ctx_stat(void *handle)
{
    timeval_t tv_end;
    uint64 passed_time;
    sql_stmt_t *stmt = (sql_stmt_t *)handle;
    sql_stat_t *stat = &stmt->session->stat;
    ctx_prev_stat_t *context_pre_stat = &stmt->session->ctx_prev_stat;

    stat->exec_count += stmt->param_info.paramset_size;
    if (!g_instance->sql.enable_stat || stmt->context == NULL) {
        return;
    }

    if (!supported_stat_ctx_type(stmt->context->type)) {
        return;
    }

    (void)cm_gettimeofday(&tv_end);
    passed_time = TIMEVAL_DIFF_US(&context_pre_stat->tv_start, &tv_end);

    // ANONYMOUS_BLOCK context can't stat, because dml context had stat already.
    if (stmt->context->type != CTSQL_TYPE_ANONYMOUS_BLOCK) {
        // Total number of rows processed on behalf of this SQL statement, accumulate total_rows of stmt.
        KNL_SESSION(stmt)->stat->processed_rows +=
            (stmt->is_explain || stmt->context->type == CTSQL_TYPE_SELECT) ? stmt->batch_rows : stmt->total_rows;
    }
    sql_context_accumulate(stmt, passed_time);

    sql_ctx_stat_count4single(stmt, stat, passed_time);

    // detach sql info from session
    cm_spin_lock(&stmt->session->sess_lock, NULL);
    stmt->session->prev_sql_id = stmt->session->sql_id;
    if (stmt->eof || stmt->context->type != CTSQL_TYPE_SELECT) {
        stmt->session->current_sql = CM_NULL_TEXT;
        stmt->session->sql_id = 0;
    }
    cm_spin_unlock(&stmt->session->sess_lock);
}

void sql_record_knl_stats_info(void *handle)
{
    sql_stmt_t *stmt = (sql_stmt_t *)handle;
    // procedure/function/trigger don't have context, no need to collect stat
    if (stmt->context == NULL) {
        return;
    }

    stmt->context->stat.knl_stat.is_statitics = CT_TRUE;
    stmt->context->stat.knl_stat.vm_open_pages = stmt->vm_stat.open_pages;
    stmt->context->stat.knl_stat.vm_close_pages = stmt->vm_stat.close_pages;
    stmt->context->stat.knl_stat.vm_alloc_pages = stmt->vm_stat.alloc_pages;
    stmt->context->stat.knl_stat.vm_free_pages = stmt->vm_stat.free_pages;
    stmt->context->stat.knl_stat.vm_swapin_pages = stmt->vm_stat.swap_in_pages;
    stmt->context->stat.knl_stat.vm_swapout_pages = stmt->vm_stat.swap_out_pages;
    stmt->context->stat.knl_stat.vm_time_elapsed = stmt->vm_stat.time_elapsed;
    stmt->context->stat.knl_stat.sort_time = stmt->session->knl_session.stat->wait_time[MTRL_SEGMENT_SORT];
    stmt->context->stat.knl_stat.cpu_time = stmt->session->knl_session.stat->disk_read_time;
    (void)cm_gettimeofday(&stmt->context->stat.knl_stat.begin_tv);
    stmt->session->knl_session.stats_parall = 1;
    stmt->context->stat.knl_stat.stats_threads = 1;
    stmt->context->stat.knl_stat.is_finished = CT_FALSE;
    stmt->context->stat.knl_stat.execute_time = 0;
}

void sql_reset_knl_stats_info(void *handle, status_t analyze_succeed)
{
    sql_stmt_t *stmt = (sql_stmt_t *)handle;
    if (stmt->context == NULL) {
        return;
    }
    knl_analyze_stat_t knl_stat = stmt->context->stat.knl_stat;
    uint64 res;
    timeval_t tv_end;
    (void)cm_gettimeofday(&tv_end);
    int64 execute_time = TIMEVAL_DIFF_US(&knl_stat.begin_tv, &tv_end);
    res = stmt->vm_stat.open_pages - knl_stat.vm_open_pages;
    stmt->context->stat.knl_stat.vm_open_pages = (res < 0) ? 0 : res;
    res = stmt->vm_stat.close_pages - knl_stat.vm_close_pages;
    stmt->context->stat.knl_stat.vm_close_pages = (res < 0) ? 0 : res;
    res = stmt->vm_stat.alloc_pages - knl_stat.vm_alloc_pages;
    stmt->context->stat.knl_stat.vm_alloc_pages = (res < 0) ? 0 : res;
    res = stmt->vm_stat.free_pages - knl_stat.vm_free_pages;
    stmt->context->stat.knl_stat.vm_free_pages = (res < 0) ? 0 : res;
    res = stmt->vm_stat.swap_in_pages - knl_stat.vm_swapin_pages;
    stmt->context->stat.knl_stat.vm_swapin_pages = (res < 0) ? 0 : res;
    stmt->context->stat.knl_stat.vm_swapout_pages = stmt->vm_stat.swap_out_pages - knl_stat.vm_swapout_pages;
    stmt->context->stat.knl_stat.vm_time_elapsed = stmt->vm_stat.time_elapsed - knl_stat.vm_time_elapsed;
    stmt->context->stat.knl_stat.sort_time =
        stmt->session->knl_session.stat->wait_time[MTRL_SEGMENT_SORT] - knl_stat.sort_time;
    stmt->context->stat.knl_stat.cpu_time =
        execute_time - (stmt->session->knl_session.stat->disk_read_time - knl_stat.cpu_time);
    stmt->context->stat.knl_stat.is_finished = (analyze_succeed != CT_SUCCESS) ? CT_FALSE : CT_TRUE;
    stmt->context->stat.knl_stat.stats_threads = stmt->session->knl_session.stats_parall;
    stmt->context->stat.knl_stat.execute_time = execute_time;
}

#ifdef __cplusplus
}
#endif
