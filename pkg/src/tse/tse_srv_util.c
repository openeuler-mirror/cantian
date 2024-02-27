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
 * tse_srv_util.c
 *
 *
 * IDENTIFICATION
 * src/tse/tse_srv_util.c
 *
 * -------------------------------------------------------------------------
 */
#include <math.h>
#include "tse_module.h"
#include "knl_context.h"
#include "srv_instance.h"
#include "dtc_dls.h"
#include "srv_agent.h"
#include "tse_ddl.h"
#include "knl_dc.h"
#include "dtc_ddl.h"
#include "tse_inst.h"
#include "cm_error.h"
#include "tse_srv_util.h"

#define UINT24_MAX  (0xFFFFFF)
#define INT24_MAX  (8388607)
#define INT24_MIN  (-8388608)


void tse_calc_max_serial_value_integer(knl_column_t *knl_column, uint64_t *limit_value)
{
    switch (knl_column->size) {
        case 1: // tinyint size为1
            *limit_value = INT8_MAX;
            break;
        case 2: // smallint size为2
            *limit_value = INT16_MAX;
            break;
        case 3: // MEDIUMINT size为3
            *limit_value = INT24_MAX;
            break;
        case 4: // INT size为4
            *limit_value = INT32_MAX;
            break;
        default:
            *limit_value = INT32_MAX;
    }
}

void tse_calc_max_serial_value_uint32(knl_column_t *knl_column, uint64_t *limit_value)
{
    switch (knl_column->size) {
        case 1: // tinyint size为1
            *limit_value = UINT8_MAX;
            break;
        case 2: // smallint size为2
            *limit_value = UINT16_MAX;
            break;
        case 3: // MEDIUMINT size为3
            *limit_value = UINT24_MAX;
            break;
        case 4: // INT size为4
            *limit_value = UINT32_MAX;
            break;
        default:
            *limit_value = UINT32_MAX;
    }
}

void tse_calc_max_serial_value_real(knl_column_t *knl_column, uint64_t *limit_value)
{
    switch (knl_column->size) {
        case 4: // float size 为4
            *limit_value = FLOAT_COL_MAX_VALUE - 1;
            break;
        case 8: // double size为8
            *limit_value = DOUBLE_COL_MAX_VALUE - 1;
            break;
        default:
            *limit_value = INT64_MAX;
    }
}

// 根据列的数据类型计算列的next自增值及返回列的自增值上限
uint64_t tse_calc_max_serial_value(knl_column_t *knl_column, uint64 *next_value)
{
    uint64_t limit_value = UINT64_MAX;
    switch (knl_column->datatype) {
        case CT_TYPE_INTEGER: {
            tse_calc_max_serial_value_integer(knl_column, &limit_value);
            break;
        }
        case CT_TYPE_UINT32: {
            tse_calc_max_serial_value_uint32(knl_column, &limit_value);
            break;
        }
        case CT_TYPE_BIGINT: {
            limit_value = INT64_MAX;
            break;
        }
        case CT_TYPE_UINT64: {
            limit_value = UINT64_MAX;
            break;
        }
        case CT_TYPE_REAL: {
            tse_calc_max_serial_value_real(knl_column, &limit_value);
            break;
        }
        default:
            break;
    }
    if (next_value != NULL) {
        *next_value = (*next_value > limit_value) ? limit_value : *next_value;
    }
    return limit_value;
}

int64 convert_float_to_rint(char *ptr)
{
    double j;
    j = *(double *)ptr;

    if ((j > FLOAT_COL_MAX_VALUE) || (j < COL_MIN_VALUE)) {
        return 0;
    }

    return (int64)rint(j);
}

int64 convert_double_to_rint(char *ptr)
{
    double j;
    j = *(double *)ptr;

    if ((j > DOUBLE_COL_MAX_VALUE) || (j < COL_MIN_VALUE)) {
        return 0;
    }

    return (int64)rint(j);
}

status_t tse_check_index_column_count(uint32_t column_cnt)
{
    if (column_cnt > CT_MAX_INDEX_COLUMNS) {
        CT_LOG_RUN_ERR("cursor index column count exceeds the max, column_cnt:%u", column_cnt);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t tse_get_curr_serial_value(knl_handle_t handle, knl_handle_t dc_entity, uint64 *value)
{
    knl_session_t *session = (knl_session_t *)handle;
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    dc_entry_t *entry = entity->entry;

    if (entity->has_serial_col != CT_TRUE) {
        CT_LOG_DEBUG_INF("The table %s.%s has no auto increment column", entry->user_name, entry->name);
        return CT_ERROR;
    }

    if (entity->type == DICT_TYPE_TEMP_TABLE_SESSION || entity->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        // tmp tables are managed by mysql and thus should never run into this branch
        CM_ABORT(0, "should never get tmp tables' serial value from Cantian");
        return CT_ERROR;
    }

    dls_spin_lock(session, &entry->serial_lock, NULL);
    uint64 start_val = entity->table.desc.serial_start;
    uint32 residue = (start_val == 0) ? 1 : 0;
    uint64 seg_val;
    if (entity->table.heap.segment == NULL) {
        seg_val = entity->table.desc.serial_start;
    } else {
        seg_val = HEAP_SEGMENT(session, entity->table.heap.entry, entity->table.heap.segment)->serial;
    }

    if (entry->serial_value == 0 || entry->serial_value == start_val) {
        // initial fetch
        *value = (start_val == 0) ? 1 : start_val;
        if (seg_val != start_val) {
            *value = seg_val;
        }
        dls_spin_unlock(session, &entry->serial_lock);
        return CT_SUCCESS;
    }

    *value = entry->serial_value;
    if ((*value - start_val) % CT_SERIAL_CACHE_COUNT == residue) {
        *value = seg_val;
    }
    dls_spin_unlock(session, &entry->serial_lock);
    return CT_SUCCESS;
}

/* to get the current AUTO_INCREMENT value, a series of value is computed by the following rule
 * AUTO_INCREMENT_VALUE = auto_inc_offset + N × auto_inc_step, N=1,2,3,...
 * then the current AUTO_INCREMENT value is assigned to *value */
status_t tse_get_curr_serial_value_auto_inc(knl_handle_t handle, knl_handle_t dc_entity, uint64 *value,
                                            uint16 auto_inc_step, uint16 auto_inc_offset)
{
    knl_session_t *session = (knl_session_t *)handle;
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    dc_entry_t *entry = entity->entry;

    if (entity->has_serial_col != CT_TRUE) {
        CT_LOG_DEBUG_INF("The table %s.%s has no auto increment column", entry->user_name, entry->name);
        return CT_ERROR;
    }

    if (entity->type == DICT_TYPE_TEMP_TABLE_SESSION || entity->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        return knl_get_serial_value_tmp_table(session, entity, value, auto_inc_step, auto_inc_offset, CT_FALSE);
    }

    dls_spin_lock(session, &entry->serial_lock, NULL);
    uint64 start_val = entity->table.desc.serial_start;
    uint64 seg_val;
    if (entity->table.heap.segment == NULL) {
        seg_val = start_val;
    } else {
        seg_val = HEAP_SEGMENT(session, entity->table.heap.entry, entity->table.heap.segment)->serial;
    }

    if (entry->serial_value == 0) {
        // initial fetch
        knl_first_serial_value_4mysql(value, start_val, auto_inc_step, auto_inc_offset);
        if (seg_val > start_val) {
            *value = AUTO_INCREMENT_VALUE(seg_val, auto_inc_offset, auto_inc_step);
        }
        dls_spin_unlock(session, &entry->serial_lock);
        return CT_SUCCESS;
    }

    if (entry->serial_value >= CT_INVALID_ID64 - auto_inc_step) {
        *value = CT_INVALID_ID64;
        dls_spin_unlock(session, &entry->serial_lock);
        return CT_SUCCESS;
    }

    knl_cal_serial_value_4mysql(entry->serial_value, value, start_val, auto_inc_step, auto_inc_offset);
    if ((*value - 1) / CT_SERIAL_CACHE_COUNT > (entry->serial_value - 1) / CT_SERIAL_CACHE_COUNT) {
        uint64 update_serial_value = *value > seg_val ? *value : seg_val;
        *value = AUTO_INCREMENT_VALUE(update_serial_value, auto_inc_offset, auto_inc_step);
    }
    dls_spin_unlock(session, &entry->serial_lock);
    return CT_SUCCESS;
}

// @ref sql_free_knl_cursor
void tse_free_session_cursor_impl(session_t *session, knl_cursor_t *cursor, char *func, int32_t line_no)
{
    if (cursor->is_valid == CT_FALSE || cursor->mysql_using == CT_FALSE) {
        CT_LOG_DEBUG_WAR("[tse_free_session_cursor_impl] cursor has been freed");
        return;
    }

    object_pool_t *pool = &session->knl_cur_pool;
    object_t *object = (object_t *)((char *)cursor - OBJECT_HEAD_SIZE);

    if (cursor->file != -1) {
        cm_close_file(cursor->file);
    }
    tse_close_cursor(&session->knl_session, cursor);
    cursor->mysql_using = CT_FALSE;
    opool_free(pool, object);
    cm_stack_reset(session->knl_session.stack); // reset space allocated for cursor->row
    CM_ASSERT(session->total_cursor_num >= 1);
    cm_oamap_remove(&session->cursor_map, cm_hash_int64((uint64)cursor), cursor);
    session->total_cursor_num--;
    CT_LOG_DEBUG_INF("tse_free_session_cursor: left_cursors=%d, called by func:%s:%d",
        session->total_cursor_num, func, line_no);
}

void tse_free_cursors(session_t *session, uint64_t *cursors, int32_t csize)
{
    for (int i = 0; i < csize && session->total_cursor_num > 0; i++) {
        if (cursors[i] != 0) {
            tse_free_session_cursor(session, (knl_cursor_t *)cursors[i]);
            cursors[i] = 0;
        }
    }
}
 
void tse_free_handler_cursor(session_t *session, tianchi_handler_t *tch)
{
    tse_free_session_cursor(session, (knl_cursor_t *)tch->cursor_addr);
    tch->cursor_addr = INVALID_VALUE64;
    tch->cursor_valid = false;
}

knl_cursor_t *tse_push_cursor(knl_session_t *knl_session)
{
    knl_cursor_t *cursor = knl_push_cursor(knl_session);
    ((session_t *)knl_session)->total_cursor_num_stack++;
    return cursor;
}

// @ref sql_alloc_knl_cursor
knl_cursor_t *tse_alloc_session_cursor(session_t *session, uint32_t part_id, uint32_t subpart_id)
{
    object_pool_t *pool = &session->knl_cur_pool;
    object_t *object = opool_alloc(pool);
    if (object == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)(OBJECT_HEAD_SIZE + g_instance->kernel.attr.cursor_size),
                       "creating kernel cursor");
        return NULL;
    }

    knl_cursor_t *cursor = (knl_cursor_t *)object->data;
    knl_init_cursor_buf(&session->knl_session, cursor);
    KNL_INIT_CURSOR(cursor);
    if (IS_TSE_PART(part_id)) {
        cursor->part_loc.part_no = part_id;
        cursor->part_loc.subpart_no = subpart_id;
    }
    cursor->stmt = NULL;
    cursor->decode_count = CT_INVALID_ID16;
    cm_oamap_insert(&session->cursor_map, cm_hash_int64((uint64)cursor), cursor, cursor);
    session->total_cursor_num++;
    cursor->mysql_using = CT_TRUE;
    return cursor;
}

static void tse_set_session_ssn_scn(knl_session_t *session, uint8_t *sql_stat_start)
{
    if (sql_stat_start == NULL) {
        return;
    }

    knl_inc_session_ssn(session);

    if (*sql_stat_start == 0) {
        return;
    }
    
    *sql_stat_start = 0;
    knl_set_session_scn(session, CT_INVALID_ID64);
    
    CT_LOG_DEBUG_INF("[TSE_SET_SESSION]:session_id=%u, ssn=%llu, session_scn=%llu, rm_query_scn=%llu",
                     session->id, session->ssn, session->query_scn, session->rm->query_scn);
}

status_t tse_try_reopen_dc(knl_session_t *knl_session, text_t *user, text_t *table, knl_dictionary_t *dc)
{
    if (dc == NULL || DC_ENTITY(dc) == NULL) {
        CT_LOG_RUN_ERR("tse_try_reopen_dc: dc has not init, table=%s", table->str);
        CT_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(user), T2S_EX(table));
        return CT_ERROR;
    }
    
    if (!(DC_ENTITY(dc)->valid)) {
        CT_LOG_DEBUG_INF("tse_try_reopen_dc: dc is invalid, try to reopen dc for table %s", table->str);
        knl_close_dc(dc);
        if (knl_open_dc(knl_session, user, table, dc) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("tse_try_reopen_dc: reopen dc failed, table=%s", table->str);
            return CT_ERROR;
        }
    }
    
    return CT_SUCCESS;
}

status_t tse_open_cursor(knl_session_t *knl_session, knl_cursor_t *cursor,
                         tse_context_t *tse_context, uint8_t *sql_stat_start, bool is_select)
{
    CT_RETURN_IFERR(tse_try_reopen_dc(knl_session, &tse_context->user, &tse_context->table, tse_context->dc));
    // must put before tse_set_session_ssn_scn
    text_t start_sv = { (char *)TSE_SQL_START_INTERNAL_SAVEPOINT, strlen(TSE_SQL_START_INTERNAL_SAVEPOINT) };
    if (sql_stat_start && *sql_stat_start == 1 &&
        (!DB_IS_READONLY(knl_session) || !is_select) && knl_set_savepoint(knl_session, &start_sv) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_open_cursor: set sql start sys savepoint failed");
        return CT_ERROR;
    }
    tse_set_session_ssn_scn(knl_session, sql_stat_start);

    if (cursor->action != CURSOR_ACTION_SELECT &&
        (check_if_operation_unsupported(tse_context->dc, "write operation"))) {
        CT_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "write operation",
                       "view, func, join table, json table, subqueries or system table");
        return CT_ERROR;
    }
    if (knl_open_cursor(knl_session, cursor, tse_context->dc) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc open cursor failed.");
        return CT_ERROR;
    }

    CT_LOG_DEBUG_INF(
        "tse_trx stmt in trx with isolation level=%u, query_scn=%llu, rm_query_scn=%llu",
        knl_session->rm->isolevel, cursor->query_scn, knl_session->rm->query_scn);
    return CT_SUCCESS;
}

void tse_close_cursor(knl_session_t *knl_session, knl_cursor_t *cursor)
{
    knl_close_cursor(knl_session, cursor);
    cursor->cond = NULL;
}

session_t* tse_get_session_by_addr(uint64_t addr)
{
    if (addr == INVALID_VALUE64 || (addr != (uint64_t)NULL && ((session_t*)addr)->tse_magic_num == 0)) {
        return NULL;
    }
    if (!(session_t*)addr || ((session_t*)addr)->tse_magic_num != TSE_MAGIC_NUM) {
        CT_LOG_RUN_ERR("[TSE_GET_SESSION]:invalid session addr:%llu", (long long unsigned int)addr);
        CM_ASSERT(0);
        return NULL;
    }
    // reset ctrl-c signal old session received
    if ((session_t *)addr != NULL && ((session_t *)addr)->knl_session.canceled) {
        ((session_t *)addr)->knl_session.canceled = CT_FALSE;
    }
    return (session_t*)addr;
}

bool32 tse_alloc_stmt_context(session_t *session)
{
    if (session->current_stmt == NULL && sql_alloc_stmt(session, &session->current_stmt) != CT_SUCCESS) {
        int err = tse_get_and_reset_err();
        CT_LOG_RUN_ERR("sql_alloc_stmt failed, errno = %d.", err);
        return CT_FALSE;
    }
    if (session->current_stmt->context == NULL && sql_alloc_context(session->current_stmt) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("sql_alloc_context failed.");
        return CT_FALSE;
    }
    return CT_TRUE;
}

tse_context_t* tse_get_ctx_by_addr(uint64_t addr)
{
    if (addr == INVALID_VALUE64 || !(tse_context_t*)addr || ((tse_context_t*)addr)->tse_magic_num != TSE_MAGIC_NUM) {
        CT_LOG_RUN_ERR("invalid handler context address %llu", (long long unsigned int)addr);
        // CM_ASSERT(0);
        return NULL;
    }
    return (tse_context_t*)addr;
}

static void tse_new_session_init(session_t *session)
{
    cm_spin_lock(&session->map_lock, NULL);
    session->is_tse = CT_TRUE;
    session->tse_magic_num = TSE_MAGIC_NUM;
    session->knl_session.status = SESSION_ACTIVE;
    CM_ASSERT(session->total_cursor_num == 0);
    CM_ASSERT(session->query_id == CT_INVALID_INT64);
    CM_ASSERT(session->tse_inst_id == CT_INFINITE32);
    CM_ASSERT(session->tse_thd_id == CT_INFINITE32);
    session->tse_inst_id = CT_INFINITE32;
    session->tse_thd_id = CT_INFINITE32;
    session->query_id = CT_INVALID_INT64;
    session->total_cursor_num = 0;
    cm_spin_unlock(&session->map_lock);
}

// @ref srv_create_replica_session
status_t tse_get_new_session(session_t **session_ptr)
{
    session_t *session = NULL;
    errno_t rc_memzero;
    agent_t *agent = (agent_t *)malloc(sizeof(agent_t));
    if (agent == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(agent_t), "replcia agent");
        return CT_ERROR;
    }

    rc_memzero = memset_s(agent, sizeof(agent_t), 0, sizeof(agent_t));
    if (rc_memzero != EOK) {
        CM_FREE_PTR(agent);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (rc_memzero));
        return CT_ERROR;
    }

    agent->session = NULL;
    status_t status;
    do {
        status = srv_create_agent_private_area(agent);
        CT_BREAK_IF_ERROR(status);
        status = srv_alloc_session(&session, NULL, SESSION_TYPE_USER);
        CT_BREAK_IF_ERROR(status);
        srv_bind_sess_agent(session, agent);
    } while (0);

    if (status != CT_SUCCESS) {
        if (agent->session != NULL) {
            srv_release_session(session);
        }
        CM_FREE_PTR(agent->area_buf);
        CM_FREE_PTR(agent);
        return CT_ERROR;
    }

    if (session->knl_session.status == SESSION_ACTIVE) {
        CT_LOG_RUN_ERR("multiple thd trying to use one session, inst_id=%d, thd_id=%d", session->tse_inst_id,
            session->tse_thd_id);
        CM_ASSERT(0);
        return CT_ERROR;
    }
    tse_new_session_init(session);
    *session_ptr = session;
    CT_LOG_DEBUG_INF("[TSE_ALLOC_SESS]:tse_get_new_sess session_id:%u", session->knl_session.id);
    return CT_SUCCESS;
}

int tse_get_or_new_session(session_t **session, tianchi_handler_t *tch,
                           bool alloc_if_null, bool need_init, bool *is_new_session)
{
    *session = tse_get_session_by_addr(tch->sess_addr);
    if (*session == NULL && alloc_if_null) {
        if (tse_get_new_session(session) != CT_SUCCESS) {
            int err = tse_get_and_reset_err();
            CT_LOG_RUN_ERR("tse_get_or_new_session:alloc new session failed, thd_id=%u, err=%d",
                           tch->thd_id, err);
            return err;
        }
        (*session)->tse_inst_id = tch->inst_id;
        (*session)->tse_thd_id = tch->thd_id;
        tch->sess_addr = (uint64)(*session);
        *is_new_session = CT_TRUE;
        CT_LOG_DEBUG_INF("tse_get_or_new_session:alloc new session for thd_id=%u, inst_id=%u, session_id=%u",
                         tch->thd_id, tch->inst_id, (*session)->knl_session.id);
    }

    if (!alloc_if_null && *session == NULL) {
        CT_LOG_RUN_ERR("tse_get_or_new_session:get session is null thd_id=%u, inst_id:%u",
                       tch->thd_id, tch->inst_id);
        return CT_ERROR;
    }

    if (need_init) {
        return init_ddl_session(*session);
    }

    return CT_SUCCESS;
}

// @ref srv_replica_thread_exit
void tse_free_session(session_t *session)
{
    agent_t *agent = session->agent;
    if (agent == NULL || session->knl_session.status != SESSION_ACTIVE) {
        return;
    }
    CT_LOG_DEBUG_INF("[TSE_CLOSE_SESS]:free tse sess, conn_id:%u, tse_inst_id:%u, knl_session_id:%u",
        session->tse_thd_id, session->tse_inst_id, session->knl_session.id);
    CM_ASSERT(session->total_cursor_num == 0);
    // for alter table故障，只需清参天表锁，dls锁已在预清理流程清理完毕
    knl_alter_table_unlock_table(&(session->knl_session));
    knl_unlock_users4mysql(&(session->knl_session));

    cm_spin_lock(&session->map_lock, NULL);
    session->is_tse = CT_FALSE;
    session->tse_magic_num = 0;
    session->tse_inst_id = CT_INFINITE32;
    session->tse_thd_id = CT_INFINITE32;
    session->query_id = CT_INVALID_INT64;
    cm_spin_unlock(&session->map_lock);
    srv_unbind_sess_agent(session, agent);
    srv_release_session(session);
    srv_free_agent_res(agent, CT_FALSE);
    CM_FREE_PTR(agent);
}

/*
delete_context控制是否删除tse_context本身
*/
void free_tse_ctx(tse_context_t **ctx, bool delete_context)
{
    CM_ASSERT((ctx != NULL) && (*ctx != NULL));
    CM_FREE_PTR((*ctx)->table.str);
    CM_FREE_PTR((*ctx)->user.str);
    if ((*ctx)->dc != NULL) {
        knl_close_dc((*ctx)->dc);
    }
    CM_FREE_PTR((*ctx)->dc);
    if (delete_context) {
        CM_FREE_PTR(*ctx);
    }
}

status_t init_tse_ctx(tse_context_t **ctx, const char *table_name, const char *user_name)
{
    errno_t errcode;
    CM_ASSERT(*ctx == NULL);

    tse_context_t *tse_context = (tse_context_t *)malloc(sizeof(tse_context_t));
    if (tse_context == NULL) {
        goto cleanup;
    }
    (void)memset_s(tse_context, sizeof(tse_context_t), 0, sizeof(tse_context_t));
    tse_context->table.len = strlen(table_name);
    tse_context->user.len = strlen(user_name);
    tse_context->table.str = (char *)malloc(tse_context->table.len + 1);
    tse_context->user.str = (char *)malloc(tse_context->user.len + 1);
    if (tse_context->user.str == NULL || tse_context->table.str == NULL) {
        goto cleanup;
    }

    errcode = memcpy_s(tse_context->table.str, CT_MAX_NAME_LEN + 1, table_name, tse_context->table.len + 1);
    if (errcode != EOK) {
        goto cleanup;
    }
    errcode = memcpy_s(tse_context->user.str, CT_MAX_NAME_LEN + 1, user_name, tse_context->user.len + 1);
    if (errcode != EOK) {
        goto cleanup;
    }
    tse_context->tse_magic_num = TSE_MAGIC_NUM;
    *ctx = tse_context;
    return CT_SUCCESS;

cleanup:
    free_tse_ctx(&tse_context, true);
    return CT_ERROR;
}

// @ref init_tse_ctx_and_open_dc
status_t init_tse_ctx_and_open_dc(session_t *session, tse_context_t **tse_context,
    const char *table_name, const char *user_name)
{
    if (init_tse_ctx(tse_context, table_name, user_name) != CT_SUCCESS) {
        return CT_ERROR;
    };
    (*tse_context)->dc = (knl_dictionary_t *)malloc(sizeof(knl_dictionary_t));
    if ((*tse_context)->dc == NULL) {
        free_tse_ctx(tse_context, true);
        return CT_ERROR;
    }
    (void)memset_s((*tse_context)->dc, sizeof(knl_dictionary_t), 0, sizeof(knl_dictionary_t));
    knl_session_t *knl_session = &session->knl_session;
    if (knl_open_dc(knl_session, &(*tse_context)->user, &(*tse_context)->table, (*tse_context)->dc) != CT_SUCCESS) {
        free_tse_ctx(tse_context, true);
        return CT_ERROR;
    }
    (*tse_context)->tse_inst_id = session->tse_inst_id;
    if (add_mysql_inst_ctx_res(session->tse_inst_id, *tse_context) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("add_mysql_inst_ctx_res failed");
        free_tse_ctx(tse_context, true);
        return CT_ERROR;
    }
    (*tse_context)->dup_key_slot = INVALID_DUP_KEY_SLOT;
    return CT_SUCCESS;
}

// @ref index_decode_row
int tse_index_only_row_fill_bitmap(knl_cursor_t *cursor, uint8_t *raw_row)
{
    knl_column_t *column = NULL;
    dc_entity_t *entity = (dc_entity_t*)cursor->dc_entity;
    uint8 bits = 0;
    uint16 len = 0;
    index_t *index = (index_t *)cursor->index;
    row_head_t *row = (row_head_t *)raw_row;

    int ret = 0;
     // 对于index_only来说bitmap只能存12列数据的bit位，超过12列就会侵占后面的数据位，所以要将数据整体往后迁移4byte
    if (index->desc.column_count > 12) {
        // cursor->row前8位为row_head_t，数据往后移从下标12开始
        ret = memmove_s((void *)row + 12, row->size - 8, (void *)row + 8,
                        row->size - 8);  // 只搬移数据，所以size减8byte
        if (ret != 0) {
            return ret;
        }
        row->size += 4;  // 数据整体后移了4byte
    }
    CT_RETURN_IFERR(tse_check_index_column_count(index->desc.column_count));
    for (uint32_t i = 0; i < index->desc.column_count; i++) {
        column = dc_get_column(entity, index->desc.columns[i]);
        len = idx_get_col_size(column->datatype, cursor->lens[i], true);
        if (cursor->lens[i] == 0XFFFF) {
            len = 0;
        }

        if (len == 0) {
            bits = COL_BITS_NULL;
        } else if (len == 4) { // field length of the column is 4 byte
            bits = COL_BITS_4;
        } else if (len == 8) { // field length of the column is 8 byte
            bits = COL_BITS_8;
        } else {
            bits = COL_BITS_VAR;
        }

        if (len != 0 && CT_IS_DECIMAL_TYPE(column->datatype)) {
            bits = COL_BITS_VAR;
        }

        row_set_column_bits2(row, bits, i);
    }

    return ret;
}

void tse_fill_update_info(knl_update_info_t *ui, uint16_t new_record_len,
                          const uint8_t *new_record, const uint16_t *upd_cols, uint16_t col_num)
{
    ui->data = (char *) new_record;
    ui->count = col_num;
    ui->columns = upd_cols;
    knl_panic(ui->offsets);
    knl_panic(ui->lens);
    cm_decode_row(ui->data, ui->offsets, ui->lens, NULL);
}

int fetch_and_delete_all_rows(knl_session_t *knl_session, knl_cursor_t *cursor, dml_flag_t flag)
{
    knl_savepoint_t savepoint;
    if (flag.ignore || (!flag.no_cascade_check)) {
        knl_savepoint(knl_session, &savepoint);
    }
    int ret = CT_SUCCESS;
    do {
        CT_RETURN_IFERR(knl_fetch(knl_session, cursor));
        if (cursor->eof) {
            break;
        }
        cursor->no_logic_logging = flag.no_logging;
        CT_RETURN_IFERR(knl_delete(knl_session, cursor));
        if (!flag.no_foreign_key_check) {
            cursor->no_cascade_check = flag.no_cascade_check;
            if (knl_verify_children_dependency(knl_session, cursor, false, 0, flag.dd_update) != CT_SUCCESS) {
                // reset error code at the outer layer
                ret = cm_get_error_code();
                if ((flag.ignore || (!flag.no_cascade_check)) && ret == ERR_ROW_IS_REFERENCED) {
                    knl_rollback(knl_session, &savepoint);
                }
                return CT_ERROR;
            }
        }
    } while (CT_TRUE);
    return CT_SUCCESS;
}

void tse_init_index_scan(knl_cursor_t *cursor, bool32 is_equal, bool32 *need_init_index)
{
    if (*need_init_index == CT_TRUE) {
        knl_init_index_scan(cursor, is_equal);
        *need_init_index = CT_FALSE;
    } else {
        cursor->scan_range.is_equal = CT_FALSE;
    }
    return;
}

static inline void tse_set_scan_range_flag(knl_cursor_t *cursor, const index_profile_t *profile)
{
    if (profile->primary == CT_TRUE || profile->unique == CT_TRUE) {
        cursor->scan_range.is_equal = CT_TRUE;
    }
}

int tse_set_index_scan_key(knl_cursor_t *cursor, uint32 col_id, bool32 *need_init_index, uint32_t column_count,
                           const index_key_info_t *index_key_info)
{
    index_t *index = (index_t *)cursor->index;
    knl_index_desc_t *desc = INDEX_DESC(index);
    index_profile_t profile = desc->profile;
    ct_type_t index_column_type = profile.types[col_id];

    // scan key
    bool32 is_closed = CT_FALSE;
    cursor->eof = 0;
    rowid_t rowid;
    (void)memset_s(&rowid, sizeof(rowid_t), 0xFF, sizeof(rowid_t));
    knl_scan_key_t *l_border = &cursor->scan_range.l_key;
    knl_scan_key_t *r_border = &cursor->scan_range.r_key;

    tse_init_index_scan(cursor, CT_FALSE, need_init_index);
    bool32 is_tse_ha_read_prefix_last = CT_FALSE;
    switch ((tse_ha_rkey_function_t)index_key_info->find_flag) {
        case TSE_HA_READ_PREFIX_LAST:
            cursor->index_dsc = CT_TRUE;
            is_tse_ha_read_prefix_last = CT_TRUE;
            // go through
        case TSE_HA_READ_KEY_EXACT:
            if (index_key_info->key_info[col_id].is_key_null) {
                if (col_id < index_key_info->key_num) {
                    knl_set_key_flag(l_border, SCAN_KEY_IS_NULL, col_id);
                    knl_set_key_flag(r_border, SCAN_KEY_IS_NULL, col_id);
                } else {
                    knl_set_key_flag(l_border, SCAN_KEY_LEFT_INFINITE, col_id);
                    knl_set_key_flag(r_border, SCAN_KEY_RIGHT_INFINITE, col_id);
                }
            } else {
                knl_set_scan_key(desc, l_border, index_column_type, index_key_info->key_info[col_id].left_key,
                                 index_key_info->key_info[col_id].left_key_len, col_id);
                knl_set_scan_key(desc, r_border, index_column_type, index_key_info->key_info[col_id].left_key,
                                 index_key_info->key_info[col_id].left_key_len, col_id);
                if (is_tse_ha_read_prefix_last == CT_FALSE) {
                    tse_set_scan_range_flag(cursor, &profile);
                }
            }
            break;
        case TSE_HA_READ_KEY_OR_NEXT:
            is_closed = CT_TRUE;
            // go through
        case TSE_HA_READ_AFTER_KEY:
            if (index_key_info->key_info[col_id].left_key_len == 0) {
                knl_set_key_flag(l_border, SCAN_KEY_LEFT_INFINITE, col_id);
            } else {
                knl_set_scan_key(desc, l_border, index_column_type, index_key_info->key_info[col_id].left_key,
                                 index_key_info->key_info[col_id].left_key_len, col_id);
                if (!is_closed) {
                    knl_set_key_rowid(desc, l_border->buf, &rowid);
                }
            }
            if (index_key_info->key_info[col_id].right_key != NULL) {
                knl_set_scan_key(desc, r_border, index_column_type, index_key_info->key_info[col_id].right_key,
                                 index_key_info->key_info[col_id].right_key_len, col_id);
            } else {
                knl_set_key_flag(r_border, SCAN_KEY_RIGHT_INFINITE, col_id);
            }
            break;
        case TSE_HA_READ_KEY_OR_PREV:
        case TSE_HA_READ_PREFIX_LAST_OR_PREV:
            is_closed = CT_TRUE;
            // go through
        case TSE_HA_READ_BEFORE_KEY:
            cursor->index_dsc = CT_TRUE;

            if (index_key_info->key_info[col_id].left_key_len == 0) {
                /*
                  is_key_null可以区分mysql传给ctc的key_len长度是否是0，is_key_null = false时，key_len = 0,
                  此时应该将右边界设置为SCAN_KEY_RIGHT_INFINITE
                */
                if (col_id < index_key_info->key_num && index_key_info->key_info[col_id].is_key_null) {
                    knl_set_key_flag(l_border, SCAN_KEY_IS_NULL, col_id);
                    knl_set_key_flag(r_border, SCAN_KEY_IS_NULL, col_id);
                } else {
                    knl_set_key_flag(r_border, SCAN_KEY_RIGHT_INFINITE, col_id);
                }
            } else {
                knl_set_scan_key(desc, r_border, index_column_type, index_key_info->key_info[col_id].left_key,
                                 index_key_info->key_info[col_id].left_key_len, col_id);
                if (is_closed) {
                    knl_set_key_rowid(desc, r_border->buf, &rowid);
                }
            }
            knl_set_key_flag(l_border, SCAN_KEY_LEFT_INFINITE, col_id);
            break;
        case TSE_HA_READ_PREFIX:
        case TSE_HA_READ_INVALID:
        default:
            CT_LOG_RUN_ERR("CTC tse_index_read find_flag:%d is not support", index_key_info->find_flag);
            return ERR_INDEX_INVALID;
    }
    return CT_SUCCESS;
}

int tse_get_index_info_and_set_scan_key(knl_cursor_t *cursor, const index_key_info_t *index_key_info)
{
    index_t *cursor_index = (index_t *)cursor->index;
    knl_index_desc_t *desc = INDEX_DESC(cursor_index);
    if (desc->column_count <= 0) {
        CT_LOG_RUN_ERR("tse_index_read: count of index column must >= 1");
        return ERR_INDEX_INVALID;
    }
 
    bool32 need_init_index = true;
    for (int col_id = 0; col_id < desc->column_count; ++col_id) {
        int error_code = tse_set_index_scan_key(cursor, col_id, &need_init_index, desc->column_count, index_key_info);
        if (error_code != CT_SUCCESS) {
            CT_LOG_RUN_ERR("tse_index_read: set index scan key error");
            return error_code;
        }
    }
 
    return CT_SUCCESS;
}

static void clean_up_session(session_t *session)
{
    CM_ASSERT(session != NULL);
    cm_oamap_iterator_t iter = 0;
    knl_cursor_t *cursor = NULL;
    cm_spin_lock(&session->map_lock, NULL);
    do {
        cm_oamap_fetch(&session->cursor_map, &iter, (void**)&cursor, (void**)&cursor);
        if (cursor != NULL) {
            CT_LOG_RUN_INF("[TSE_CLEAN_UP]:free cursor for bad mysql");
            tse_free_session_cursor(session, cursor);
        }
    } while (cursor != NULL);
    cm_oamap_destroy(&session->cursor_map);
    cm_oamap_init_mem(&session->cursor_map);
    cm_oamap_init(&session->cursor_map, 0, cm_oamap_ptr_compare);
    session->total_cursor_num = 0;
    session->tse_inst_id = CT_INFINITE32;
    session->tse_thd_id = CT_INFINITE32;
    session->query_id = CT_INVALID_INT64;
    cm_spin_unlock(&session->map_lock);

    CT_LOG_RUN_INF("[TSE_CLEAN_UP]:free session for bad mysql: session_id=%u", session->knl_session.id);
    tse_free_session(session);
}

static inline bool tse_is_session_cleanable(session_t *session, uint32_t inst_id)
{
    if (session == NULL) {
        return false;
    }

    if (!session->is_tse) {
        return false;
    }

    if (session->tse_inst_id != inst_id) {
        return false;
    }

    return session->knl_session.status != SESSION_INACTIVE;
}

void unlock_instance_for_bad_mysql(uint32_t inst_id)
{
    CT_LOG_RUN_INF("[TSE_CLEAN_UP]: Start to unlock instance when mysql is dead, inst_id=%u", inst_id);
    session_pool_t session_pool = g_instance->session_pool;
    for (int i = 0; i < CT_MAX_SESSIONS; i++) {
        session_t *session = session_pool.sessions[i];
        if (!tse_is_session_cleanable(session, inst_id) || !session->knl_session.user_locked_ddl) {
            continue;
        }
        unlock_user_ddl(session);
    }
}

int clean_up_for_bad_mysql(uint32_t inst_id)
{
    CT_LOG_RUN_INF("[TSE_CLEAN_UP]: Start to clean up when mysql is dead, inst_id=%u", inst_id);
    /**
     * 0. get_session 1.clean ctx 2.close_session
     */
    session_pool_t session_pool = g_instance->session_pool;
    for (int i = 0; i < CT_MAX_SESSIONS; i++) {
        session_t *session = session_pool.sessions[i];
        if (!tse_is_session_cleanable(session, inst_id)) {
            continue;
        }
        clean_up_session(session);
    }
    return CT_SUCCESS;
}

/* 清理与故障参天节点相关的所有mysql连接 */
int clean_up_for_bad_cantian(uint32_t cantian_inst_id)
{
    uint32_t inst_id = (cantian_inst_id << 16) | CANTIAN_DOWN_MASK; // 高16位参天节点ID, 后16位全1标识清理整个节点
    tianchi_handler_t tch = {0};
    tch.inst_id = inst_id;
    tch.sess_addr = INVALID_VALUE64;
    tch.is_broadcast = true;
    CT_LOG_RUN_WAR("[CTC_CLEAN_UP]:Release CTC resources on bad node Begin. cantian_inst_id:%u, inst_id:%u",
        cantian_inst_id, inst_id);

    // Make sure there are no queries being processed
    msg_rsp_res_pair *tse_msg_result_arr = get_tse_msg_result_arr();
    while ((uint32_t)cm_atomic32_get(&tse_msg_result_arr[cantian_inst_id].err_code) == TSE_DDL_PROCESSING) {
        usleep(TSE_DDL_WAIT_PROCESS);
        CT_LOG_RUN_WAR("[CTC_CLEAN_UP]:Have processing query... wait until it's finish. cantian_inst_id:%u",
            cantian_inst_id);
    }
    
    int ret = tse_close_mysql_connection(&tch);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_CLEAN_UP]:close mysql connection failed, ret:%d, tse_inst_id:%u",
            ret, inst_id);
    }
    return ret;
}

void tse_sql_str_remove_escape_chars(char *str, size_t len)
{
    uint32 i, j;
    for (i = 0, j = 0; i < (uint32)len && str[i] != '\0'; i++) {
        if (str[i] != '\r' && str[i] != '\n' && str[i] != '\b' &&
            str[i] != '\v' && str[i] != '\f') {
            str[j++] = str[i];
        }
    }
    str[j] = '\0';
}

char* sql_without_plaintext_password(bool contains_plaintext_password, char* sql_str, size_t sql_str_len)
{
    CM_ASSERT(sql_str_len != 0);
    tse_sql_str_remove_escape_chars(sql_str, sql_str_len);
    return contains_plaintext_password ? "(contains plaintext password)" : sql_str;
}

int tse_get_and_reset_err(void)
{
    int ret = cm_get_error_code();
    CM_ASSERT(ret != ERR_ERRNO_BASE);
    cm_reset_error();
    return (ret == ERR_ERRNO_BASE) ? CT_ERROR : ret;
}

void tse_pre_set_cursor_for_scan(uint32 index_set_count, knl_cursor_t *cursor, uint16_t active_index)
{
    cursor->action = CURSOR_ACTION_SELECT;
    if (index_set_count == 0 || active_index == MAX_INDEXES) {
        cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    } else {
        cursor->scan_mode = SCAN_MODE_INDEX;
        cursor->index_slot = (active_index == MAX_INDEXES ? 0 : active_index);
        cursor->index_only = CT_TRUE;
        cursor->index_ffs = CT_TRUE;
        cursor->scan_range.is_equal = CT_FALSE;
    }
}

int tse_count_rows(session_t *session, knl_dictionary_t *dc, knl_session_t *knl_session,
                   knl_cursor_t *cursor, uint64_t *rows)
{
    int ret = CT_SUCCESS;
    table_t *table = DC_TABLE(dc);
    if (table->index_set.total_count > 0 && cursor->scan_mode == SCAN_MODE_INDEX) {
        index_t *index = DC_INDEX(dc, cursor->index_slot);
        knl_index_desc_t *desc = INDEX_DESC(index);
        for (int col_id = 0; col_id < desc->column_count; col_id++) {
            knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, col_id);
            knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, col_id);
        }
    }
    while (!cursor->eof) {
        if (knl_fetch(knl_session, cursor) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("tse_count_rows: knl_fetch FAIL");
            return tse_get_and_reset_err();
        }
        if (!cursor->eof) {
            (*rows)++;
        }
    }
    return ret;
}

bool check_column_field_is_null(knl_cursor_t *cursor, uint16_t col)
{
    if (cursor->index_only) {
        return (cursor->lens[col] == CT_NULL_VALUE_LEN);
    }
    uint8 null_bit = row_get_column_bits2(cursor->row, col);
    return (null_bit == COL_BITS_NULL);
}

cond_pushdown_result_t update_cond_field_col(knl_cursor_t *cursor, uint16_t *cond_col, bool *col_updated)
{
    if (*col_updated == true) {
        return CPR_TRUE;
    }
    
    index_t *index = (index_t *)cursor->index;
    if (cursor->index != NULL && cursor->index_only) {
        uint32 column_count = ((index_t *)cursor->index)->desc.column_count;
        if (column_count > CT_MAX_INDEX_COLUMNS) {
            CT_LOG_RUN_ERR("update_cond_field_col: column_count exceeds the max");
            return CPR_ERROR;
        }
        for (uint32_t i = 0; i < column_count; i++) {
            if (index->desc.columns[i] == *cond_col) {
                *cond_col = i;
                break;
            }
        }
    }
    
    *col_updated = true;
    return CPR_TRUE;
}
    

bool check_value_is_compare(tse_func_type_t func_type, int32 cmp)
{
    bool ret = CT_FALSE;
    switch (func_type) {
        case TSE_EQUAL_FUNC:
        case TSE_EQ_FUNC:
            ret = (cmp == 0);
            break;
        case TSE_NE_FUNC:
            ret = (cmp != 0);
            break;
        case TSE_LT_FUNC:
            ret = (cmp < 0);
            break;
        case TSE_LE_FUNC:
            ret = (cmp <= 0);
            break;
        case TSE_GT_FUNC:
            ret = (cmp > 0);
            break;
        case TSE_GE_FUNC:
            ret = (cmp >= 0);
            break;
        default:
            return CPR_ERROR;
    }
    return ret;
}

static inline int32 compare_text_rtrim_ins(const text_t *text1, const text_t *text2)
{
    text_t l_text = *text1;
    text_t r_text = *text2;

    cm_rtrim_text(&l_text);
    cm_rtrim_text(&r_text);
    return cm_compare_text_ins(&l_text, &r_text);
}

int32 compare_var_data_ins(char *data1, uint16 size1, char *data2, uint16 size2, ct_type_t type)
{
    text_t text1, text2;

    if (size1 == 0 || size2 == 0) {
        return (size1 == size2) ? 0 : (size1 == 0) ? -1 : 1;
    }
    
    text1.str = data1;
    text1.len = size1;
    text2.str = data2;
    text2.len = size2;
    switch (type) {
        case CT_TYPE_CHAR:
            return compare_text_rtrim_ins(&text1, &text2);
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        default:
            return cm_compare_text_ins(&text1, &text2);
    }
}

cond_pushdown_result_t compare_cond_field_value(tse_conds *cond, knl_cursor_t *cursor)
{
    char *ptr = (char *)cursor->row;
    uint16 *offsets = cursor->offsets;
    uint16 *lens = cursor->lens;

    uint16 col = cond->field_info.field_no;
    uint16 col_id = col;
    if (cond->field_info.null_value) {
        return compare_cond_field_null(cond, cursor);
    } else if (check_column_field_is_null(cursor, col)) {
        return CPR_FALSE;
    }

    index_t *index = (index_t *)cursor->index;
    if (index != NULL && cursor->index_only) {
        col_id = index->desc.columns[col];
    }
    ct_type_t ct_type = (ct_type_t)(dc_get_column((dc_entity_t *)cursor->dc_entity, col_id)->datatype);
    void *fetch_value = NULL;
    uint16 fetch_size = 0;
    if (ct_type == CT_TYPE_CLOB) {
        lob_locator_t* locator = (lob_locator_t *)(ptr + offsets[col]);
        if (locator->head.is_outline) {
            return CPR_TRUE;
        }
        fetch_value = locator->data;
        fetch_size = locator->head.size;
    } else {
        fetch_value = ptr + offsets[col];
        fetch_size = lens[col];
    }
    void *field_value = cond->field_info.field_value;
    uint16 field_size = cond->field_info.field_size;
    int32 cmp = 0;
    if (CT_IS_STRING_TYPE(ct_type) || ct_type == CT_TYPE_CLOB) {
        CHARSET_COLLATION *cs = cm_get_charset_coll(cond->field_info.collate_id);
        text_t text1 = {fetch_value, fetch_size};
        text_t text2 = {field_value, field_size};
        cmp = cs->collsp(cs, &text1, &text2);
    } else {
        cmp = var_compare_data_ex(fetch_value, fetch_size, field_value, field_size, ct_type);
    }
    return (cond_pushdown_result_t)check_value_is_compare(cond->func_type, cmp);
}

cond_pushdown_result_t compare_cond_field_null(tse_conds *cond, knl_cursor_t *cursor)
{
    int col = cond->field_info.field_no;
    switch (cond->func_type) {
        case TSE_EQUAL_FUNC:
        case TSE_ISNULL_FUNC:
            return check_column_field_is_null(cursor, col);
        case TSE_ISNOTNULL_FUNC:
            return !check_column_field_is_null(cursor, col);
        default:
            return CPR_FALSE;
    }
}

cond_pushdown_result_t compare_cond_field_like(tse_conds *cond, knl_cursor_t *cursor, uint32 charset_id)
{
    char *ptr = (char *)cursor->row;
    uint16 *offsets = cursor->offsets;
    uint16 *lens = cursor->lens;

    int col = cond->field_info.field_no;
    uint16 col_id = col;
    // return CPR_FALSE when data is NULL
    CT_RETVALUE_IFTRUE(check_column_field_is_null(cursor, col), CPR_FALSE);

    index_t *index = (index_t *)cursor->index;
    if (index != NULL && cursor->index_only) {
        col_id = index->desc.columns[col];
    }
    ct_type_t ct_type = (ct_type_t)(dc_get_column((dc_entity_t *)cursor->dc_entity, col_id)->datatype);

    text_t field = {(char *)cond->field_info.field_value, cond->field_info.field_size};

    text_t fetch;
    if (ct_type != CT_TYPE_CLOB) {
        fetch.str = (char *)(ptr + offsets[col]);
        fetch.len = lens[col];
    } else {
        lob_locator_t* locator = (lob_locator_t *)(ptr + offsets[col]);
        CT_RETVALUE_IFTRUE(locator->head.is_outline, CPR_TRUE);
        fetch.str = (char *)(locator->data);
        fetch.len = locator->head.size;
    }
    
    bool32 result = CT_TRUE;
    int32 cmp_ret = 0;
    if (!cm_is_collate_sensitive(cond->field_info.collate_id)) {
        if (cond->field_info.no_backslash) {
            result = cm_text_like_ins(&fetch, &field, (charset_type_t)charset_id);
        } else {
            if (cm_text_like_escape_ins(fetch.str, fetch.str + fetch.len, field.str, field.str + field.len,
                                    '\\', &cmp_ret, (charset_type_t)charset_id) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("cm_text_like_escape_ins FAIL, errno = %d.", tse_get_and_reset_err());
                return CPR_ERROR;
            }
            result = (cmp_ret == 0);
        }
    } else {
        if (cond->field_info.no_backslash) {
            result = cm_text_like(&fetch, &field, (charset_type_t)charset_id);
        } else {
            if (cm_text_like_escape(fetch.str, fetch.str + fetch.len, field.str, field.str + field.len,
                    '\\', &cmp_ret, (charset_type_t)charset_id) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("cm_text_like_escape FAIL, errno = %d.", tse_get_and_reset_err());
                return CPR_ERROR;
            }
            result = (cmp_ret == 0);
        }
    }
    return (cond_pushdown_result_t)result;
}

cond_pushdown_result_t dfs_compare_conds(tse_conds *cond, knl_cursor_t *cursor, uint32 charset_id)
{
    tse_conds *node = cond->cond_list->first;
    bool ret = cond->func_type == TSE_COND_AND_FUNC ? CT_TRUE : CT_FALSE;
    for (int i = 0; i < cond->cond_list->elements; i++) {
        cond_pushdown_result_t cur_result = check_cond_match_one_line(node, cursor, charset_id);
        if (cur_result == CPR_ERROR) {
            return cur_result;
        }
        switch (cond->func_type) {
            case TSE_COND_AND_FUNC:
                ret = ret && cur_result;
                if (ret == CT_TRUE) {
                    break;
                } else {
                    return CT_FALSE;
                }
            case TSE_COND_OR_FUNC:
                ret = ret || cur_result;
                if (ret == CT_TRUE) {
                    return CT_TRUE;
                } else {
                    break;
                }
            case TSE_XOR_FUNC:
                ret ^= (bool)cur_result; // ret,cur_result value is (0,1)
                break;
            case TSE_NOT_FUNC:
                return !cur_result;
            default:
                return CPR_ERROR;
        }
        node = node->next;
    }
    return (cond_pushdown_result_t)ret;
}

cond_pushdown_result_t check_cond_match_one_line(tse_conds *cond, knl_cursor_t *cursor, uint32 charset_id)
{
    if (cond == NULL) {
        return CPR_TRUE;
    }
    switch (cond->func_type) {
        case TSE_COND_AND_FUNC:
        case TSE_COND_OR_FUNC:
        case TSE_XOR_FUNC:
        case TSE_NOT_FUNC:
            return dfs_compare_conds(cond, cursor, charset_id);
        case TSE_EQ_FUNC:
        case TSE_EQUAL_FUNC:
        case TSE_NE_FUNC:
        case TSE_LT_FUNC:
        case TSE_LE_FUNC:
        case TSE_GE_FUNC:
        case TSE_GT_FUNC:
            TSE_RET_IF_CPR_ERR(update_cond_field_col(cursor, &cond->field_info.field_no, &cond->field_info.col_updated));
            return compare_cond_field_value(cond, cursor);
        case TSE_ISNULL_FUNC:
        case TSE_ISNOTNULL_FUNC:
            TSE_RET_IF_CPR_ERR(update_cond_field_col(cursor, &cond->field_info.field_no, &cond->field_info.col_updated));
            return compare_cond_field_null(cond, cursor);
        case TSE_LIKE_FUNC:
            TSE_RET_IF_CPR_ERR(update_cond_field_col(cursor, &cond->field_info.field_no, &cond->field_info.col_updated));
            return compare_cond_field_like(cond, cursor, charset_id);
        case TSE_UNKNOWN_FUNC:
        default:
            return CPR_ERROR;
    }
}
status_t tse_open_dc(char *user_name, char *table_name, sql_stmt_t *stmt, knl_dictionary_t *dc)
{
    knl_handle_t knl = &stmt->session->knl_session;
    text_t user_text = { 0 };
    text_t name_text = { 0 };
    proto_str2text(user_name, &user_text);
    proto_str2text(table_name, &name_text);
    if (knl_open_dc(knl, &user_text, &name_text, dc) != CT_SUCCESS) {
        knl_close_dc(dc);
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not find", table_name);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void tse_set_no_use_other_sess4thd(session_t *session)
{
    if (session == NULL) {
        knl_set_curr_sess2tls(NULL);
    } else {
        session->knl_session.spid = cm_get_current_thread_id();
        knl_set_curr_sess2tls((void *)session);
        // set session id here, because need consider agent mode, for example, agent mode is AGENT_MODE_SHARED
        cm_log_set_session_id(session->knl_session.id);
    }
}

void tse_get_index_from_name(knl_dictionary_t *dc, char *index_name, uint16_t *active_index)
{
    if (index_name == NULL) {
        return;
    }
    int index_name_len = strlen(index_name);
    if (index_name_len == 0) {
        return;
    }
    for (int i = 0; i < DC_ENTITY(dc)->table.index_set.count; i++) {
        int dc_index_name_len = strlen(DC_INDEX(dc, i)->desc.name);
        if (dc_index_name_len != index_name_len) {
            continue;
        }
        if (strncmp(DC_INDEX(dc, i)->desc.name, index_name, dc_index_name_len) == 0) {
            *active_index = i;
            return;
        }
    }
    CT_LOG_RUN_ERR("tse_get_index_from_name FAIL");
}

bool check_if_operation_unsupported(knl_dictionary_t *dc, char *operation)
{
    if (IS_CANTIAN_SYS_DC(dc)) {
        CT_LOG_RUN_ERR("Operation %s is not supported on view, func, join table, "
                       "json table, subqueries or system table", operation);
        return true;
    } else {
        return false;
    }
}
