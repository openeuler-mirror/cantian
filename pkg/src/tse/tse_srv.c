 /*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 */

#include "tse_srv.h"
#include "cs_protocol.h"
#include "cm_atomic.h"
#include "cm_log.h"
#include "cm_row.h"
#include "cm_defs.h"
#include "cm_nls.h"
#include "cm_hash.h"
#include "cm_list.h"
#include "srv_agent.h"
#include "srv_param.h"
#include "srv_instance.h"
#include "srv_session.h"
#include "knl_table.h"
#include "tse_srv_util.h"
#include "tse_cbo.h"
#include "tse_ddl.h"
#include "cm_malloc.h"
#include "knl_interface.h"
#include "tse_inst.h"

#define TSE_MAX_MYSQL_INST_SIZE (128)

/*
 * lob text data struct
 * need for knl_write_lob interface
 */
typedef struct st_lob_text {
    char *str;
    unsigned int len;
} tianchi_lob_text_t;

int32 sint3korr(uchar *A)
{
    return ((int32)(((A[2]) & 128)
                        ? (((uint32)255L << 24) | (((uint32)A[2]) << 16) | (((uint32)A[1]) << 8) | ((uint32)A[0]))
                        : (((uint32)A[2]) << 16) | (((uint32)A[1]) << 8) | ((uint32)A[0])));
}

uint32 uint3korr(uchar *A)
{
    return (uint32)(((uint32)(A[0])) + (((uint32)(A[1])) << 8) + (((uint32)(A[2])) << 16));
}

int tse_open_table(tianchi_handler_t *tch, const char *table_name, const char *user_name)
{
    TSE_LOG_RET_VAL_IF_NUL(tch, GS_ERROR, "tse_open_table: null tch ptr");

    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    if (session == NULL) {
        status_t status = tse_get_new_session(&session);
        if (status != GS_SUCCESS) {
            GS_LOG_RUN_ERR("tse_open_table failed, thd_id=%u", tch->thd_id);
            return status;
        }
        session->tse_inst_id = tch->inst_id;
        session->tse_thd_id = tch->thd_id;
        tch->sess_addr = (uint64)session;
        GS_LOG_DEBUG_INF("tse_open_table: alloc new session for thd_id=%u, session_id=%u",
            tch->thd_id, session->knl_session.id);
    }
    tse_set_no_use_other_sess4thd(session);
    tse_context_t *tse_context = NULL;
    if (init_tse_ctx_and_open_dc(session, &tse_context, table_name, user_name) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("tse_open_table failed :thd_id:%u", tch->thd_id);
        int32 error_code = tse_get_and_reset_err();
        return error_code == 0 ? ERR_GENERIC_INTERNAL_ERROR : error_code;
    };
    tch->ctx_addr = (uint64)tse_context;
    GS_LOG_DEBUG_INF("tse_open_table: tbl=%s, thd_id=%d, session_id=%u",
        tse_context->table.str, tch->thd_id, session->knl_session.id);

    return GS_SUCCESS;
}

int tse_close_table(tianchi_handler_t *tch)
{
    if (tch->cursor_addr != 0 && tch->cursor_addr != INVALID_VALUE64) {
        (void)tse_index_end(tch);
        tch->cursor_addr = INVALID_VALUE64;
    }

    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    if (tse_context == NULL) {
        GS_LOG_RUN_WAR("tse_close_table: ctx addr invalid");
        return GS_SUCCESS;
    }
    char *table_name = "empty_table";
    if (tse_context->table.str != NULL) {
        table_name = tse_context->table.str;
    }
    GS_LOG_DEBUG_INF("tse_close_table: tbl=%s, thd_id=%u", table_name, tch->thd_id);
    tse_set_no_use_other_sess4thd(NULL);
    free_tse_ctx(&tse_context, false); // 释放tse_context持有的内存,保留tse_context的本身内存
    // 此处不管移除成功或者失败，都没关系，移除操作目前只是打上删除标记，不会真正的删除tse_context的内存
    if (remove_mysql_inst_ctx_res(tse_context->tse_inst_id, tse_context) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("tse_close_table remove error,inst_id:%u,thd_id:%u", tch->inst_id, tch->thd_id);
    }
    return GS_SUCCESS;
}

int tse_close_session(tianchi_handler_t *tch)
{
    tse_set_no_use_other_sess4thd(NULL);
    (void)tse_unlock_instance(tch);
    int ret = tse_close_mysql_connection(tch);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[TSE_CLOSE_SESSION]:close mysql connection failed, ret:%d, conn_id:%u, tse_instance_id:%u",
            ret, tch->thd_id, tch->inst_id);
    }
    return GS_SUCCESS;
}

void tse_kill_session(tianchi_handler_t *tch)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    if (session == NULL) {
        GS_LOG_RUN_ERR("session can not be null, conn_id=%u, tse_inst_id=%u", tch->thd_id, tch->inst_id);
        CM_ASSERT(0);
        return;
    }
    GS_LOG_DEBUG_INF("[TSE_KILL_SESSION]:conn_id=%u, tse_inst_id:%u, session_id=%u",
        tch->thd_id, tch->inst_id, session->knl_session.id);
    tse_set_no_use_other_sess4thd(session);
    session->knl_session.canceled = GS_TRUE;
}

// 将不同数据类型的数据填充到char*buf上
static void tse_fill_serial_col_buf(knl_column_t *knl_column, char *column_data_buf, uint64 *value)
{
    tse_calc_max_serial_value(knl_column, value);
    // 自增列能够保证datatype只会出现这几种类型，所以函数不用返回值，上层逻辑也不用判断，保持逻辑简单
    switch (knl_column->datatype) {
        case GS_TYPE_INTEGER: {
            if (knl_column->size == 1) {  // tinyint size为1
                *(int8 *)column_data_buf = (int8_t)*value;
            } else if (knl_column->size == 2) {  // smallint size为2
                *(int16 *)column_data_buf = (int16_t)*value;
            } else if (knl_column->size == 3) {  // MEDIUMINT size为3
                *(int32_t *)column_data_buf = (int32_t)*value;
            } else if (knl_column->size == 4) {  // INT size为4
                *(int32 *)column_data_buf = (int32_t)*value;
            }
            break;
        }
        case GS_TYPE_UINT32: {
            if (knl_column->size == 1) {  // tinyint size为1
                uint8_t tmp_key = (uint8_t)*value;
                if (tmp_key & 0x80) {
                    *(uint32 *)column_data_buf = (uint32)(*value) | 0xffffff00;
                } else {
                    *(uint32 *)column_data_buf = (uint8_t)*value;
                }
            } else if (knl_column->size == 2) {  // smallint size为2
                uint16_t tmp_key = (uint16_t)*value;
                if (tmp_key & 0x8000) {
                    *(uint32 *)column_data_buf = (uint32)(*value) | 0xffff0000;
                } else {
                    *(uint32 *)column_data_buf = (uint16_t)*value;
                }
            } else if (knl_column->size == 3) {  // MEDIUMINT size为3
                uint32_t tmp_key = (uint32_t)*value;
                if (tmp_key & 0x800000) {
                    *(uint32 *)column_data_buf = (uint32)(*value) | 0xff000000;
                } else {
                    *(uint32 *)column_data_buf = (uint32_t)*value;
                }
            } else if (knl_column->size == 4) {  // INT size为4
                *(uint32 *)column_data_buf = (uint32_t)*value;
            }
            break;
        }
        case GS_TYPE_BIGINT: {
            *(int64 *)column_data_buf = *value;
            break;
        }
        case GS_TYPE_UINT64: {
            *(uint64 *)column_data_buf = *value;
            break;
        }
        case GS_TYPE_REAL: {
            *(double *)column_data_buf = (double)*value;
            break;
        }
        default:
            GS_LOG_RUN_ERR("tse_fill_serial_col_buf: unspported datatype of serial column,%u", knl_column->datatype);
            break;
    }
}

// 将char*转换为对应数据类型的数值
static void tse_convert_serial_col_value(knl_column_t *knl_column, char *column_data_buf, int64 *value)
{
    // 自增列能够保证datatype只会出现这几种类型，所以函数不用返回值，上层逻辑也不用判断，保持逻辑简单
    switch (knl_column->datatype) {
        case GS_TYPE_INTEGER: {
            if (knl_column->size == 1) {  // tinyint size为1
                *value = *(int8 *)column_data_buf;
            }
            if (knl_column->size == 2) {  // smallint size为2
                *value = *(int16 *)column_data_buf;
            }
            if (knl_column->size == 3) {  // MEDIUMINT size为3
                *value = sint3korr((uchar *)((void *)column_data_buf));
            }
            if (knl_column->size == 4) {  // INT size为4
                *value = *(int32 *)column_data_buf;
            }
            break;
        }
        case GS_TYPE_UINT32: {
            if (knl_column->size == 1) {  // tinyint size为1
                *value = *(uchar *)column_data_buf;
            }
            if (knl_column->size == 2) {  // smallint size为2
                *value = *(uint16 *)column_data_buf;
            }
            if (knl_column->size == 3) {  // MEDIUMINT size为3
                *value = uint3korr((uchar *)((void *)column_data_buf));
            }
            if (knl_column->size == 4) {  // INT size为4
                *value = *(uint32 *)column_data_buf;
            }
            break;
        }
        case GS_TYPE_BIGINT: {
            *value = *(int64 *)column_data_buf;
            break;
        }
        case GS_TYPE_UINT64: {
            *value = *(uint64 *)column_data_buf;
            break;
        }
        case GS_TYPE_REAL: {
            if (knl_column->size == 4) { // float size为4
                *value = convert_float_to_rint(column_data_buf);
            }
            if (knl_column->size == 8) { // double size 为8
                *value = convert_double_to_rint(column_data_buf);
            }
            break;
        }
        default:
            GS_LOG_RUN_ERR("tse_convert_serial_col_value: unspported datatype of serial column,datatype:%u",
                           knl_column->datatype);
            break;
    }
}

status_t tse_update_serial_col(knl_session_t *session, knl_cursor_t *cursor, uint16_t serial_column_offset,
                               dml_flag_t flag, serial_t *serial, uint64_t *last_insert_id)
{
    // find the autoinc column
    knl_column_t *serial_col = NULL;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    for (int i = 0; i < entity->column_count; i++) {
        knl_column_t *col = dc_get_column(entity, i);
        if (KNL_COLUMN_IS_SERIAL(col)) {
            serial_col = col;
            break;
        }
    }
    knl_panic(serial_col != NULL);
    char *serial_buf = (char *)cursor->row + serial_column_offset;

    // if has specific explicit autoinc val, no need to get next autoinc val from kernel
    if (flag.has_explicit_autoinc) {
        // get the current value of serial column passed by mysql
        tse_convert_serial_col_value(serial_col, serial_buf, &serial->max_serial_col_value);
        serial->is_uint64 = serial_col->datatype == GS_TYPE_UINT64 ? true : false;
        return GS_SUCCESS;
    }
    
    /*
        get the next autoinc val from kernel and fill into the write buffer
        1. autoinc val is NULL
        2. autoinc val is zero and sql mode is not NO_AUTO_VALUE_ON_ZERO
    */
    uint64 serial_value = 0;
    if (tse_get_curr_serial_value_auto_inc(session, entity, &serial_value, flag.auto_inc_step,
                                           flag.auto_inc_offset) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("tse_get_curr_serial_value failed!");
        return GS_ERROR;
    }

    if (serial_value == GS_INVALID_ID64) {
        GS_THROW_ERROR(ERR_AUTOINC_READ_FAILED);
        return GS_ERROR;
    }

    if (flag.autoinc_lock_mode != CTC_AUTOINC_OLD_STYLE_LOCKING &&
        serial_value < tse_calc_max_serial_value(serial_col, NULL)) {
        serial->is_uint64 = serial_col->datatype == GS_TYPE_UINT64 ? true : false;
        if (knl_get_serial_value_auto_inc(session, entity, &serial_value, flag.auto_inc_step,
                                          flag.auto_inc_offset) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("knl_get_serial_value_auto_inc failed");
            return GS_ERROR;
        }
    }

    // if this auto_inc col is nullable and current value is NULL (see datatype_cnvrtr.cc mysql_record_to_cantian_record)
    if (serial_column_offset != 0) {
        tse_fill_serial_col_buf(serial_col, serial_buf, &serial_value);
    }
    *last_insert_id = serial_value;
    return GS_SUCCESS;
}

/*
作用：用于update 语句中获取自增列的值，
返回值:0 update语句没有修改自增列，或者表中本身没有自增列，上层逻辑无需处理
      > 0 update语句设置了自增列，上层逻辑需要调用knl_update_serial_value维护表的最大自增值
      < 0 update语句设置了自增列的值，基于mysql不允许设置负数自增值逻辑，上层不用处理
*/
static void tse_update_get_serial_col_value(dc_entity_t *entity, knl_session_t *knl_session, knl_cursor_t *cursor,
                                            serial_t *serial)
{
    int64_t serial_col_value = 0;
    char *column_data_buf = NULL;
    for (int i = 0; i < entity->column_count; i++) {
        knl_column_t *knl_column = dc_get_column(entity, i);
        if (!KNL_COLUMN_IS_SERIAL(knl_column)) {
            continue;
        }
        serial->is_uint64  = knl_column->datatype == GS_TYPE_UINT64 ? true : false;
        for (int j = 0; j < cursor->update_info.count; j++) {
            if (cursor->update_info.columns[j] == i) {
                column_data_buf = cursor->update_info.data + cursor->update_info.offsets[j];
                tse_convert_serial_col_value(knl_column, column_data_buf, (int64 *)(&serial_col_value));
                // 即使此处获取出来update语句set自增列为0也不用管，自增逻辑是只有自增值比0大，且比当前自增值大才会生效
                // alter table DEMO AUTO_INCREMENT=-10000; 或者创表语句指定的自增值< 0 mysql本身就会语法报错
                serial->max_serial_col_value = serial_col_value;
                return;
            }
        }
        break;
    }
    serial->max_serial_col_value = serial_col_value;
}

int tse_copy_cursor_row(knl_session_t *session, knl_cursor_t *cursor, row_head_t *src_row, row_head_t *compact_row,
                        uint16 *size)
{
    /* for heap row lock confliction and re-read row after that, we need to update query scn
       in order to do index scan using the new data with new query scn for mysql */
    if (cursor->scn > session->query_scn && cursor->action == CURSOR_ACTION_UPDATE) {
        session->query_scn = cursor->scn;
    }

    if (cursor->action > CURSOR_ACTION_SELECT && !tse_alloc_stmt_context((session_t *)session)) {
        return GS_ERROR;
    }

    knl_panic(src_row != compact_row);
    if (src_row != NULL) {
        errno_t ret = memcpy_sp(compact_row, src_row->size, src_row, src_row->size);
        knl_securec_check(ret);
        *size = src_row->size;
    }

    return GS_SUCCESS;
}

int insert_and_verify_for_bulk_write(knl_cursor_t *cursor, knl_session_t *knl_session,
    uint64_t rec_num, const record_info_t *record_info, uint *err_pos, tse_context_t *tse_context, dml_flag_t flag)
{
    int ret = GS_SUCCESS;
    uint8_t *cur_start = record_info->record;
    CM_SAVE_STACK(knl_session->stack);
    knl_savepoint_t savepoint;
    for (uint i = 0; i < rec_num; i++) {
        if (flag.ignore) {
            knl_savepoint(knl_session, &savepoint);
        }
        cursor->row = (row_head_t*)cur_start;
        dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
        ret = tse_copy_cursor_row(knl_session, cursor, NULL, cursor->row, &cursor->row->size);
        if (ret != GS_SUCCESS) {
            CM_RESTORE_STACK(knl_session->stack);
            tse_close_cursor(knl_session, cursor);
            return ret;
        }
        status_t status = knl_insert(knl_session, cursor);
        if (status != GS_SUCCESS) {
            ret = tse_get_and_reset_err();
            GS_LOG_RUN_ERR("tse_bulk_write failed with ret %d, i=%u", ret, i);
            if (ret == ERR_DUPLICATE_KEY) {
                *err_pos = i;
                tse_context->dup_key_slot = cursor->conflict_idx_slot;
            }
            CM_RESTORE_STACK(knl_session->stack);
            return ret;
        }

        status = knl_verify_ref_integrities(knl_session, cursor);
        if (status == GS_SUCCESS) {
            cur_start += record_info->record_len;
            continue;
        }

        ret = tse_get_and_reset_err();
        if (!(flag.no_foreign_key_check && ret == ERR_CONSTRAINT_VIOLATED_NO_FOUND)) {
            if (flag.ignore) {
                knl_rollback(knl_session, &savepoint);
            }
            GS_LOG_RUN_ERR("tse_bulk_write failed integrities check with ret %d, i=%u", ret, i);
            CM_RESTORE_STACK(knl_session->stack);
            return ret;
        }
        ret = GS_SUCCESS;
        cur_start += record_info->record_len;
    }
    CM_RESTORE_STACK(knl_session->stack);
    return ret;
}

int tse_bulk_write(tianchi_handler_t *tch, const record_info_t *record_info, uint64_t rec_num,
                   uint32_t *err_pos, dml_flag_t flag)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    CM_SAVE_STACK(knl_session->stack);
    knl_cursor_t *cursor = knl_push_cursor(knl_session);
    if (NULL == cursor) {
        GS_LOG_RUN_ERR("tse_bulk_write: knl_push_cursor FAIL");
        CM_RESTORE_STACK(knl_session->stack);
        return ERR_GENERIC_INTERNAL_ERROR;
    }

    cursor->vnc_column = NULL;
    cursor->action = CURSOR_ACTION_INSERT;
    int ret = GS_SUCCESS;
    if (tse_open_cursor(knl_session, cursor, tse_context, &tch->sql_stat_start) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("tse_bulk_write: tse_open_cursor failed");
        CM_RESTORE_STACK(knl_session->stack);
        ret = tse_get_and_reset_err();
        return ret;
    }

    ret = insert_and_verify_for_bulk_write(cursor, knl_session, rec_num, record_info, err_pos, tse_context, flag);
    CM_RESTORE_STACK(knl_session->stack);
    tse_close_cursor(knl_session, cursor);
    return ret;
}

int insert_and_verify_for_write_row(knl_session_t *knl_session, knl_cursor_t *cursor,
    serial_t *serial, uint64_t last_insert_id, tse_context_t *tse_context, dml_flag_t flag)
{
    int ret = 0;
    knl_savepoint_t savepoint;
    if (flag.ignore) {
        knl_savepoint(knl_session, &savepoint);
    }
    status_t status = knl_insert(knl_session, cursor);
    if (status != GS_SUCCESS) {
        // for on duplicate key update
        ret = tse_get_and_reset_err();
        if (ret == ERR_DUPLICATE_KEY) {
            tse_context->dup_key_slot = cursor->conflict_idx_slot;
            tse_context->conflict_rid = cursor->conflict_rid;
        }
        GS_LOG_DEBUG_ERR("tse_write_row: knl_insert FAIL");
        return ret;
    }
    
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    do {
        status = knl_verify_ref_integrities(knl_session, cursor);
        if (status != GS_SUCCESS) {
            ret = tse_get_and_reset_err();
            GS_LOG_RUN_ERR("tse_write_row failed to knl_verify_ref_integrities with ret %d", ret);
            if ((flag.ignore) && !((flag.no_foreign_key_check) && ret == ERR_CONSTRAINT_VIOLATED_NO_FOUND)) {
                break;
            }
            return ret;
        }

        if (flag.auto_inc_used) {
            if (serial->max_serial_col_value != 0) {
                status = knl_update_serial_value_auto_inc(knl_session, entity, serial->max_serial_col_value,
                                                          serial->is_uint64);
            } else if (!flag.has_explicit_autoinc && flag.autoinc_lock_mode == CTC_AUTOINC_OLD_STYLE_LOCKING) {
                status = knl_get_serial_value_auto_inc(knl_session, entity, &last_insert_id, flag.auto_inc_step,
                                                       flag.auto_inc_offset);
            }

            if (status != GS_SUCCESS) {
                ret = tse_get_and_reset_err();
                GS_LOG_RUN_ERR("tse_write_row failed to set serial with ret %d, serial_col_value=%lld",
                               ret, serial->max_serial_col_value);
            }
        }
    } while (0);

    if (ret != GS_SUCCESS && (flag.ignore)) {
        knl_rollback(knl_session, &savepoint);
    }
    return ret;
}

int tse_write_row(tianchi_handler_t *tch, const record_info_t *record_info,
    uint16_t serial_column_offset, uint64_t *last_insert_id, dml_flag_t flag)
{
    uint16_t column_offset = serial_column_offset;
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");
    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    if (tch->cursor_addr != INVALID_VALUE64 && cursor->action != CURSOR_ACTION_UPDATE) {
        tse_free_session_cursor(session, cursor);
    }
    CM_SAVE_STACK(knl_session->stack);
    cursor = knl_push_cursor(knl_session);
    if (NULL == cursor) {
        GS_LOG_RUN_ERR("tse_write_row: knl_push_cursor FAIL");
        CM_RESTORE_STACK(knl_session->stack);
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    GS_LOG_DEBUG_INF("tse_write_row: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);
    cursor->vnc_column = NULL;
    cursor->action = CURSOR_ACTION_INSERT;
    if (tse_open_cursor(knl_session, cursor, tse_context, &tch->sql_stat_start) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("tse_write_row: tse_open_cursor failed");
        CM_RESTORE_STACK(knl_session->stack);
        return tse_get_and_reset_err();
    }

    if (IS_TSE_PART(tch->part_id)) {
        knl_part_locate_t part_loc = { .part_no = tch->part_id, .subpart_no = tch->subpart_id };
        knl_set_table_part(cursor, part_loc);
    }

    cursor->row = (row_head_t*)record_info->record;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    int ret = tse_copy_cursor_row(knl_session, cursor, NULL, cursor->row, &cursor->row->size);
    if (ret != GS_SUCCESS) {
        tse_close_cursor(knl_session, cursor);
        CM_RESTORE_STACK(knl_session->stack);
        return ret;
    }

    serial_t serial = {0, false};
    if (flag.auto_inc_used) {
        knl_panic(entity->has_serial_col);
        if (tse_update_serial_col(knl_session, cursor, column_offset,
                                  flag, &serial, last_insert_id) != GS_SUCCESS) {
            tse_close_cursor(knl_session, cursor);
            CM_RESTORE_STACK(knl_session->stack);
            ret = tse_get_and_reset_err();
            return ret;
        }
    }

    ret = insert_and_verify_for_write_row(knl_session, cursor, &serial, *last_insert_id, tse_context, flag);
    tse_close_cursor(knl_session, cursor);
    CM_RESTORE_STACK(knl_session->stack);
    return ret;
}

int tse_check_update_constraint(knl_session_t *knl_session, knl_cursor_t *cursor, uint64_t conflicts,
                                dml_flag_t flag, bool *need_rollback)
{
    int ret = GS_SUCCESS;
    status_t status = GS_SUCCESS;
    do {
        if (!flag.no_foreign_key_check) {
            cursor->no_cascade_check = flag.no_cascade_check;
            status = knl_verify_children_dependency(knl_session, cursor, true);
            if (status != GS_SUCCESS) {
                ret = tse_get_and_reset_err();
                GS_LOG_RUN_ERR("tse_check_update_constraint failed to knl_verify_children_dependency with ret %d", ret);
                if ((flag.ignore || (!flag.no_cascade_check)) && ret == ERR_ROW_IS_REFERENCED) {
                    break;
                }
                return ret;
            }
        }

        status = knl_verify_ref_integrities(knl_session, cursor);
        if (status != GS_SUCCESS) {
            ret = tse_get_and_reset_err();
            GS_LOG_RUN_ERR("tse_check_update_constraint failed to knl_verify_ref_integrities with ret %d", ret);
            if ((flag.ignore) &&
                !((flag.no_foreign_key_check) && ret == ERR_CONSTRAINT_VIOLATED_NO_FOUND)) {
                break;
            }
            return ret;
        }

        status = knl_check_index_conflicts(knl_session, conflicts);
        if (status != GS_SUCCESS) {
            ret = tse_get_and_reset_err();
            GS_LOG_RUN_ERR("raw_tse_update_row violates index constraints, ret %d", ret);
            break;
        }
    } while (0);

    if (ret != GS_SUCCESS && (flag.ignore || !flag.no_cascade_check)) {
        *need_rollback = true;
    }

    return ret;
}

static int raw_tse_update_row(knl_session_t *knl_session, knl_cursor_t *cursor, uint64_t conflicts, dml_flag_t flag)
{
    int ret = GS_SUCCESS;

    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;

    serial_t serial;
    serial.max_serial_col_value = 0;
    serial.is_uint64 = false;
    if (entity->has_serial_col) {
        tse_update_get_serial_col_value(entity, knl_session, cursor, &serial);
    }

    knl_savepoint_t savepoint;
    if (flag.ignore || !flag.no_cascade_check) {
        knl_savepoint(knl_session, &savepoint);
    }

    if (knl_update(knl_session, cursor) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("raw_tse_update_row: knl_update FAIL");
        ret = tse_get_and_reset_err();
        return ret;
    }

    bool need_rollback = false;
    ret = tse_check_update_constraint(knl_session, cursor, conflicts, flag, &need_rollback);
    if (ret != GS_SUCCESS) {
        if (need_rollback) {
            knl_rollback(knl_session, &savepoint);
        }
        return ret;
    }

    if (entity->has_serial_col && serial.max_serial_col_value > 0) {
        if (knl_update_serial_value_auto_inc(knl_session, cursor->dc_entity, serial.max_serial_col_value,
                                             serial.is_uint64) != GS_SUCCESS) {
            ret = tse_get_and_reset_err();
            GS_LOG_RUN_ERR(
                "raw_tse_update_row failed to set serial column value with ret %d, max_serial_col_value:%lld",
                ret, serial.max_serial_col_value);
        }
    }

    if (ret != GS_SUCCESS && flag.ignore) {
        knl_rollback(knl_session, &savepoint);
    }

    return ret;
}

static int tse_open_cursor_and_fetch_by_rowid(knl_session_t *knl_session, knl_cursor_t *cursor,
                                              tse_context_t *tse_context, bool32 *isFound)
{
    int ret = GS_SUCCESS;
    if (tse_open_cursor(knl_session, cursor, tse_context, NULL) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("tse_update_row: tse_open_cursor failed");
        ret = tse_get_and_reset_err();
        return ret;
    }

    if (knl_fetch_by_rowid(knl_session, cursor, isFound) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("tse_update_row: knl_fetch_by_rowid FAIL");
        ret = tse_get_and_reset_err();
        return ret;
    }

    return ret;
}

int tse_update_row(tianchi_handler_t *tch, uint16_t new_record_len, const uint8_t *new_record,
                   const uint16_t *upd_cols, uint16_t col_num, dml_flag_t flag)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    int ret = GS_SUCCESS;
    uint64_t conflicts;
    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    knl_init_index_conflicts(knl_session, (uint64 *)&conflicts);
    CM_SAVE_STACK(knl_session->stack);
    if (!(flag.dup_update)) {
        GS_LOG_DEBUG_INF("tse_update_row: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);
        tse_fill_update_info(&cursor->update_info, new_record_len, new_record, upd_cols, col_num);
        ret = raw_tse_update_row(knl_session, cursor, conflicts, flag);
    } else {
        // for on duplicate key update
        cursor = knl_push_cursor(knl_session);
        if (NULL == cursor) {
            GS_LOG_RUN_ERR("tse_update_row: knl_push_cursor FAIL");
            CM_RESTORE_STACK(knl_session->stack);
            return ERR_GENERIC_INTERNAL_ERROR;
        }
        GS_LOG_DEBUG_INF("tse_update_row: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);
        cursor->rowid = tse_context->conflict_rid;
        cursor->scan_mode = SCAN_MODE_ROWID;
        cursor->action = CURSOR_ACTION_UPDATE;
        cursor->vnc_column = NULL;
        bool32 isFound = GS_FALSE;
        ret = tse_open_cursor_and_fetch_by_rowid(knl_session, cursor, tse_context, &isFound);
        if (ret != GS_SUCCESS) {
            CM_RESTORE_STACK(knl_session->stack);
            tse_close_cursor(knl_session, cursor);
            return ret;
        }
        tse_fill_update_info(&cursor->update_info, new_record_len, new_record, upd_cols, col_num);
        ret = raw_tse_update_row(knl_session, cursor, conflicts, flag);
    }
    if (ret == ERR_DUPLICATE_KEY) {
        tse_context->dup_key_slot = cursor->conflict_idx_slot;
    }
    CM_RESTORE_STACK(knl_session->stack);
    tse_close_cursor(knl_session, cursor);
    return ret;
}

int delete_and_check_constraint(knl_session_t *knl_session, knl_cursor_t *cursor, dml_flag_t flag)
{
    knl_savepoint_t savepoint;
    if (flag.ignore || !flag.no_cascade_check) {
        knl_savepoint(knl_session, &savepoint);
    }

    int ret = GS_SUCCESS;
    if (knl_delete(knl_session, cursor) != GS_SUCCESS) {
        ret = tse_get_and_reset_err();
        GS_LOG_RUN_ERR("tse_delete_row: knl_delete FAIL. ret:%d", ret);
        return ret;
    }

    if (!flag.no_foreign_key_check) {
        cursor->no_cascade_check = flag.no_cascade_check;
        if (knl_verify_children_dependency(knl_session, cursor, false) != GS_SUCCESS) {
            ret = tse_get_and_reset_err();
            GS_LOG_RUN_ERR("tse_delete_row: knl_verify_children_dependency FAIL. ret:%d.", ret);
            if ((flag.ignore || (!flag.no_cascade_check)) && ret == ERR_ROW_IS_REFERENCED) {
                knl_rollback(knl_session, &savepoint);
                return ret;
            }
        }
    }
    return ret;
}

int tse_delete_row(tianchi_handler_t *tch, uint16_t record_len, dml_flag_t flag)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");
    int ret = GS_SUCCESS;

    if (!(flag.is_replace)) {
        knl_cursor_t *prev_cursor = (knl_cursor_t *)tch->cursor_addr;
        GS_LOG_DEBUG_INF("tse_delete_row: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);
        ret = delete_and_check_constraint(knl_session, prev_cursor, flag);
        return ret;
    }

    // for replace into
    CM_SAVE_STACK(knl_session->stack);
    knl_cursor_t *cursor = knl_push_cursor(knl_session);
    if (NULL == cursor) {
        GS_LOG_RUN_ERR("tse_delete_row: knl_push_cursor FAIL");
        CM_RESTORE_STACK(knl_session->stack);
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    GS_LOG_DEBUG_INF("tse_delete_row:(replace) tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);
    cursor->rowid = tse_context->conflict_rid;
    cursor->scan_mode = SCAN_MODE_ROWID;
    cursor->action = CURSOR_ACTION_DELETE;

    bool32 isFound = GS_FALSE;
    ret = tse_open_cursor_and_fetch_by_rowid(knl_session, cursor, tse_context, &isFound);
    if (ret != GS_SUCCESS) {
        CM_RESTORE_STACK(knl_session->stack);
        tse_close_cursor(knl_session, cursor);
        return ret;
    }

    if (isFound) {
        ret = delete_and_check_constraint(knl_session, cursor, flag);
    }
    tse_close_cursor(knl_session, cursor);
    CM_RESTORE_STACK(knl_session->stack);
    return ret;
}

int tse_set_cursor_action(knl_cursor_t *cursor, expected_cursor_action_t action)
{
    switch (action) {
        case EXP_CURSOR_ACTION_INDEX_ONLY:
        case EXP_CURSOR_ACTION_SELECT:
            cursor->action = CURSOR_ACTION_SELECT;
            break;
        case EXP_CURSOR_ACTION_DELETE:
            cursor->action = CURSOR_ACTION_DELETE;
            break;
        case EXP_CURSOR_ACTION_UPDATE:
            cursor->action = CURSOR_ACTION_UPDATE;
            break;
        default:
            GS_LOG_RUN_ERR("unsupport action %d", action);
            return ERR_GENERIC_INTERNAL_ERROR;
    }
    return GS_SUCCESS;
}

int tse_rnd_init(tianchi_handler_t *tch, expected_cursor_action_t action,
                 tse_select_mode_t mode, tse_conds *cond)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    if (tch->cursor_addr != INVALID_VALUE64) {
        tse_free_session_cursor(session, (knl_cursor_t *)tch->cursor_addr);
    }

    knl_cursor_t *cursor = tse_alloc_session_cursor(session, tch->part_id, tch->subpart_id);
    if (cursor == NULL) {
        GS_LOG_RUN_ERR("tse_rnd_init: tse_alloc_session_cursor FAIL");
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    tch->cursor_addr = (uint64_t)cursor;
    GS_LOG_DEBUG_INF("tse_rnd_init: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->cond = cond;
    GS_RETURN_IFERR(tse_set_cursor_action(cursor, action));
    if (mode == SELECT_SKIP_LOCKED) {
        cursor->rowmark.type = ROWMARK_SKIP_LOCKED;
    } else if (mode == SELECT_NOWAIT) {
        cursor->rowmark.type = ROWMARK_NOWAIT;
    }
    if (tse_open_cursor(&session->knl_session, cursor, tse_context, &tch->sql_stat_start) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("tse_rnd_init: tse_open_cursor failed");
        tse_free_session_cursor(session, cursor);
        return tse_get_and_reset_err();
    }

    return GS_SUCCESS;
}

int tse_rnd_end(tianchi_handler_t *tch)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    GS_LOG_DEBUG_INF("tse_rnd_end: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

    tse_free_session_cursor(session, (knl_cursor_t *)tch->cursor_addr);
    return GS_SUCCESS;
}

static int tse_fetch_and_filter(knl_cursor_t *cursor, knl_session_t *knl_session, uint8_t *records, uint16 *size)
{
    int ret = GS_SUCCESS;
    uint32 charset_id = knl_session->kernel->db.charset_id;
    while (!cursor->eof) {
        if (knl_fetch(knl_session, cursor) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("tse_fetch_and_filter: knl_fetch FAIL");
            return tse_get_and_reset_err();
        }
        if (cursor->eof) {
            break;
        }
        cond_pushdown_result_t cond_result = check_cond_match_one_line((tse_conds *)cursor->cond, cursor, charset_id);
        if (cond_result == CPR_ERROR) {
            GS_LOG_RUN_ERR("tse_fetch_and_filter: check_cond_match_one_line FAIL");
            return GS_ERROR;
        } else if (cond_result == CPR_FALSE) {
            continue;
        } else {
            ret = tse_copy_cursor_row(knl_session, cursor, cursor->row, records, size);
            if (ret != GS_SUCCESS) {
                GS_LOG_RUN_ERR("tse_fetch_and_filter: tse_copy_cursor_row FAIL");
                return ret;
            }
            break;
        }
    }
    return ret;
}

int tse_rnd_next(tianchi_handler_t *tch, record_info_t *record_info)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    GS_LOG_DEBUG_INF("tse_rnd_next: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

    CM_SAVE_STACK(knl_session->stack);
    cursor->row = (row_head_t *)cm_push(knl_session->stack, GS_MAX_ROW_SIZE);
    if (cursor->row == NULL) {
        GS_LOG_RUN_ERR("init row space failed!");
        return GS_ERROR;
    }
    int ret = tse_fetch_and_filter(cursor, knl_session, record_info->record, &record_info->record_len);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("tse_rnd_next: tse_fetch_and_filter FAIL");
        tse_free_session_cursor(session, cursor);
        return ret;
    }
    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

int tse_scan_records(tianchi_handler_t *tch, uint64_t *num_rows, char *index_name)
{
    uint64_t rows = 0;
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");
    if (tch->cursor_addr != INVALID_VALUE64) {
        tse_free_session_cursor(session, (knl_cursor_t *)tch->cursor_addr);
    }

    knl_session_t *knl_session = &session->knl_session;
    CM_SAVE_STACK(knl_session->stack);
    knl_cursor_t *cursor = knl_push_cursor(knl_session);
    if (NULL == cursor) {
        GS_LOG_RUN_ERR("tse_scan_records: knl_push_cursor FAIL");
        CM_RESTORE_STACK(knl_session->stack);
        return ERR_GENERIC_INTERNAL_ERROR;
    }

    GS_RETURN_IFERR(tse_try_reopen_dc(knl_session, &tse_context->user, &tse_context->table, tse_context->dc));
    knl_dictionary_t *dc = tse_context->dc;

    uint16_t active_index = MAX_INDEXES;
    tse_get_index_from_name(dc, index_name, &active_index);

    tse_pre_set_cursor_for_scan(DC_TABLE(dc)->index_set.total_count, cursor, active_index);

    if (IS_TSE_PART(tch->part_id)) {
        cursor->part_loc.part_no = tch->part_id;
        cursor->part_loc.subpart_no = tch->subpart_id;
    }

    if (tse_open_cursor(knl_session, cursor, tse_context, &tch->sql_stat_start) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("tse_scan_records: tse_open_cursor failed");
        CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
        return tse_get_and_reset_err();
    }

    cursor->row = (row_head_t *)cm_push(knl_session->stack, GS_MAX_ROW_SIZE);
    if (cursor->row == NULL) {
        GS_LOG_RUN_ERR("init row space failed!");
        CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
        return GS_ERROR;
    }

    int ret = tse_count_rows(session, dc, knl_session, cursor, &rows);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("tse_scan_records: tse_count_all_rows failed");
        CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
        return ret;
    }
    *num_rows = rows;

    CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
    return GS_SUCCESS;
}

int tse_rnd_prefetch(tianchi_handler_t *tch, uint32_t rowNum, uint8_t *records,
                     uint16_t *record_lens, uint32_t *recNum, uint64_t *rowids)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    *recNum = 0;
    GS_LOG_DEBUG_INF("tse_rnd_prefetch: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

    CM_SAVE_STACK(knl_session->stack);
    cursor->row = (row_head_t *)cm_push(knl_session->stack, GS_MAX_ROW_SIZE);
    if (cursor->row == NULL) {
        GS_LOG_RUN_ERR("init row space failed!");
        return GS_ERROR;
    }
    for (uint32_t i = 0; i < rowNum; i++) {
        int ret = tse_fetch_and_filter(cursor, knl_session, records, &record_lens[i]);
        if (ret != GS_SUCCESS) {
            GS_LOG_RUN_ERR("tse_rnd_prefetch: tse_fetch_and_filter FAIL");
            tse_free_session_cursor(session, cursor);
            return ret;
        }
        if (cursor->eof) {
            record_lens[i] = 0;
            break;
        }

        rowids[i] = cursor->rowid.value;
        records += record_lens[i];
        *recNum += 1;
    }
    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

int tse_position(tianchi_handler_t *tch, uint8_t *position, uint16_t pos_length)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    GS_LOG_DEBUG_INF("tse_position: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

    rowid_t rowid = cursor->rowid;
    errno_t errcode = memcpy_s(position, pos_length, &rowid, sizeof(rowid));
    if (errcode != EOK) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

int tse_rnd_pos(tianchi_handler_t *tch, uint16_t pos_length, uint8_t *position, record_info_t *record_info)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    GS_LOG_DEBUG_INF("tse_rnd_pos: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

    CM_SAVE_STACK(knl_session->stack);
    cursor->row = (row_head_t *)cm_push(knl_session->stack, GS_MAX_ROW_SIZE);
    if (cursor->row == NULL) {
        GS_LOG_RUN_ERR("init row space failed!");
        return GS_ERROR;
    }

    cursor->scan_mode = SCAN_MODE_ROWID;
    cursor->rowid = *((rowid_t *)position);

    bool32 isFound = GS_FALSE;
    if (knl_fetch_by_rowid(knl_session, cursor, &isFound) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("tse_rnd_pos fetch failed");
        tse_free_session_cursor(session, cursor);
        return tse_get_and_reset_err();
    }

    if (!cursor->eof) {
        int ret = tse_copy_cursor_row(knl_session, cursor, cursor->row, record_info->record, &record_info->record_len);
        if (ret != GS_SUCCESS) {
            tse_free_session_cursor(session, cursor);
            return ret;
        }
    } else {
        record_info->record_len = 0;
    }
    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

static int delete_all_rows_from_part_table(knl_cursor_t *cursor, knl_session_t *knl_session,
                                           tse_context_t *tse_context, dml_flag_t flag)
{
    uint32_t part_nums = knl_part_count(tse_context->dc->handle);
    int ret = GS_SUCCESS;
    while (cursor->part_loc.part_no < part_nums) {
        ret = knl_reopen_cursor(knl_session, cursor, tse_context->dc);
        if (ret != GS_SUCCESS) {
            GS_LOG_RUN_ERR("tse_delete_all_rows: reopen cursor failed");
            break;
        }
        if (fetch_and_delete_all_rows(knl_session, cursor, flag) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("tse_delete_all_rows: fetch_and_delete_all_rows failed");
            ret = tse_get_and_reset_err();
            break;
        }
        cursor->part_loc.part_no++;
    }
    return ret;
}

int tse_delete_all_rows(tianchi_handler_t *tch, dml_flag_t flag)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");
    if (!tse_alloc_stmt_context(session)) {
        return GS_ERROR;
    }
    int ret = GS_SUCCESS;
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = &session->knl_session;
    
    CM_SAVE_STACK(knl_session->stack);
    cursor = knl_push_cursor(knl_session);
    if (NULL == cursor) {
        GS_LOG_RUN_ERR("tse_delete_all_rows: knl_push_cursor FAIL");
        CM_RESTORE_STACK(knl_session->stack);
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    GS_LOG_DEBUG_INF("tse_delete_all_rows: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->action = CURSOR_ACTION_DELETE;
    if (tse_open_cursor(knl_session, cursor, tse_context, &tch->sql_stat_start) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("tse_delete_all_rows: tse_open_cursor failed");
        CM_RESTORE_STACK(knl_session->stack);
        tse_close_cursor(knl_session, cursor);
        return tse_get_and_reset_err();
    }
    if (knl_is_part_table(tse_context->dc->handle)) {
        cursor->part_loc.part_no = 0;
        ret = delete_all_rows_from_part_table(cursor, knl_session, tse_context, flag);
    } else if (fetch_and_delete_all_rows(knl_session, cursor, flag) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("tse_delete_all_rows: fetch_and_delete_all_rows failed");
        ret = tse_get_and_reset_err();
    }
    CM_RESTORE_STACK(knl_session->stack);
    tse_close_cursor(knl_session, cursor);
    return ret;
}

static int tse_index_init(session_t *session, tse_context_t *tse_context, tianchi_handler_t *tch,
                          uint16_t index, bool sorted, expected_cursor_action_t action,
                          tse_select_mode_t mode, tse_conds *cond, const bool is_replace)
{
    knl_panic(sorted || tch->cursor_addr == INVALID_VALUE64);

    knl_session_t *knl_session = &session->knl_session;
    knl_cursor_t *cursor = tse_alloc_session_cursor(session, tch->part_id, tch->subpart_id);
    TSE_LOG_RET_VAL_IF_NUL(cursor, ERR_GENERIC_INTERNAL_ERROR, "tse_alloc_session_cursor FAIL");

    tch->cursor_addr = (uint64_t)cursor;
    GS_LOG_DEBUG_INF("tse_index_init: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

    GS_RETURN_IFERR(tse_set_cursor_action(cursor, action));
    cursor->scan_mode = SCAN_MODE_INDEX;
    cursor->index_slot = index;
    cursor->cond = cond;
    if (action == EXP_CURSOR_ACTION_INDEX_ONLY) {
        cursor->index_only = GS_TRUE;
        cursor->index_ffs = !sorted;
    }
    if (mode == SELECT_SKIP_LOCKED) {
        cursor->rowmark.type = ROWMARK_SKIP_LOCKED;
    } else if (mode == SELECT_NOWAIT) {
        cursor->rowmark.type = ROWMARK_NOWAIT;
    }
    if (tse_open_cursor(knl_session, cursor, tse_context, &tch->sql_stat_start) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("tse_index_init: tse_open_cursor failed");
        tse_free_session_cursor(session, cursor);
        return tse_get_and_reset_err();
    }

    return GS_SUCCESS;
}

int tse_index_end(tianchi_handler_t *tch)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    GS_LOG_DEBUG_INF("tse_index_end: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);
    if (tch->cursor_addr != INVALID_VALUE64) {
        tse_free_session_cursor(session, (knl_cursor_t *)tch->cursor_addr);
    }
    return GS_SUCCESS;
}

int tse_check_partition_status(tianchi_handler_t *tch, knl_cursor_t **cursor,
                               const index_key_info_t *index_key_info, tse_select_mode_t mode)
{
    int ret;
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    knl_session_t *knl_session = &session->knl_session;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);

    if (!index_key_info->sorted) {
        (*cursor)->part_loc.part_no = tch->part_id;
        (*cursor)->part_loc.subpart_no = tch->subpart_id;
        ret = knl_reopen_cursor(knl_session, *cursor, tse_context->dc);
        if (ret != GS_SUCCESS) {
            GS_LOG_RUN_ERR("tse_index_read: reopen cursor failed");
            return ret;
        }
        knl_part_locate_t part_loc = { .part_no = tch->part_id, .subpart_no = tch->subpart_id };
        knl_set_table_part(*cursor, part_loc);
    } else {
        // alloc new cursor for new part
        ret = tse_index_init(session, tse_context, tch, index_key_info->active_index,
                             index_key_info->sorted, index_key_info->action, mode, (*cursor)->cond, false);
        if (ret != GS_SUCCESS) {
            GS_LOG_RUN_ERR("tse_index_read: alloc new cursor for part %d failed", tch->part_id);
            return ret;
        }
        *cursor = (knl_cursor_t *)tch->cursor_addr;
    }

    return ret;
}

bool is_need_one_more_fetch(knl_cursor_t *cursor, const index_key_info_t *index_key_info, uint16_t find_flag)
{
    if (index_key_info->key_num == 0) { // 不带where子句
        return false;
    }

    if (find_flag != TSE_HA_READ_BEFORE_KEY && find_flag != TSE_HA_READ_AFTER_KEY) {
        return false;
    }

    index_t *cursor_index = (index_t *)cursor->index;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    knl_index_desc_t *desc = INDEX_DESC(cursor_index);

    int column_id = index_key_info->key_num - 1;
    int col_offset = cursor->index_only ? column_id : desc->columns[column_id];
    // 先判断数据长度是否相等，再将取出来的值与key作memcmp，如果值相等则返回true
    if (cursor->lens[col_offset] != 0 &&
        cursor->lens[col_offset] == index_key_info->key_info[column_id].left_key_len &&
        memcmp((uint8_t *)cursor->row + cursor->offsets[col_offset],
            index_key_info->key_info[column_id].left_key, index_key_info->key_info[column_id].left_key_len) == 0) {
        return true;
    }

    if (index_key_info->key_info[column_id].is_key_null) {
        if (cursor->index_only) {
            knl_column_t *column = dc_get_column(entity, desc->columns[column_id]);
            uint16 len = idx_get_col_size(column->datatype, cursor->lens[col_offset], true);
            if (cursor->lens[col_offset] == GS_INVALID_ID16 || len == 0) {
                return true;
            }
        } else {
            uint8 bits = row_get_column_bits2(cursor->row, col_offset);
            if (bits == COL_BITS_NULL) {
                return true;
            }
        }
    }

    return false;
}

int get_correct_pos_by_fetch(session_t *session, tse_context_t *tse_context, knl_cursor_t *cursor,
                             record_info_t *record_info, const index_key_info_t *index_key_info)
{
    int ret = GS_SUCCESS;
    knl_session_t *knl_session = &session->knl_session;
    uint32 charset_id = knl_session->kernel->db.charset_id;
    while (!cursor->eof) {
        if (knl_fetch(knl_session, cursor) != GS_SUCCESS) {
            TSE_HANDLE_KNL_FETCH_FAIL(session, cursor);
        }
        while (is_need_one_more_fetch(cursor, index_key_info, index_key_info->find_flag)) {
            if (knl_fetch(knl_session, cursor) != GS_SUCCESS) {
                TSE_HANDLE_KNL_FETCH_FAIL(session, cursor);
            }
            if (cursor->eof) {
                break;
            }
        }
        if (cursor->eof) {
            GS_LOG_DEBUG_INF("cannot find record with current key info.");
            record_info->record_len = 0;
            return ret;
        }
        cond_pushdown_result_t cond_result = check_cond_match_one_line((tse_conds *)cursor->cond, cursor, charset_id);
        if (cond_result == CPR_ERROR) {
            GS_LOG_RUN_ERR("get_correct_pos_by_fetch: check_cond_match_one_line FAIL");
            return GS_ERROR;
        } else if (cond_result == CPR_FALSE) {
            continue;
        } else {
            ret = tse_copy_cursor_row(knl_session, cursor, cursor->row, record_info->record, &record_info->record_len);
            if (ret != GS_SUCCESS) {
                GS_LOG_RUN_ERR("get_correct_pos_by_fetch: tse_copy_cursor_row FAIL");
                tse_free_session_cursor(session, cursor);
                return ret;
            }
            if (cursor->index_only) {
                ret = tse_index_only_row_fill_bitmap(cursor, record_info->record);
                record_info->record_len = ((row_head_t *)record_info->record)->size;
            }
            break;
        }
    }

    if (!IS_INVALID_ROWID(cursor->rowid)) {
        tse_context->row_id = cursor->rowid;  // using by tse_parent_child_fetch
    }

    return ret;
}

int tse_check_partition_changed(knl_cursor_t *cursor, tianchi_handler_t *tch)
{
    if (IS_TSE_PART(cursor->part_loc.part_no) && IS_TSE_PART(tch->part_id) && cursor->part_loc.part_no != tch->part_id) {
        return GS_TRUE;
    } else if (IS_TSE_PART(cursor->part_loc.subpart_no) && IS_TSE_PART(tch->subpart_id) &&
            cursor->part_loc.subpart_no != tch->subpart_id) {
        return GS_TRUE;
    }
    return GS_FALSE;
}

int tse_index_read(tianchi_handler_t *tch, record_info_t *record_info, index_key_info_t *index_info,
                   tse_select_mode_t mode, tse_conds *cond, const bool is_replace)
{
    CM_ASSERT(index_info != NULL);

    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_session_t *knl_session = &session->knl_session;
    GS_RETURN_IFERR(tse_try_reopen_dc(knl_session, &tse_context->user, &tse_context->table, tse_context->dc));
    knl_dictionary_t *dc = tse_context->dc;
    tse_get_index_from_name(dc, index_info->index_name, &index_info->active_index);
    if (index_info->active_index == MAX_INDEXES) {
        GS_LOG_RUN_ERR("tse_get_index_from_name: tse find index name failed!");
        return GS_ERROR;
    }

    if (index_info->need_init) {
        if (tch->cursor_addr != INVALID_VALUE64) {
            (void)tse_index_end(tch);
            tch->cursor_addr = INVALID_VALUE64;
        }

        int ret = tse_index_init(session, tse_context, tch, index_info->active_index,
                                 index_info->sorted, index_info->action, mode, cond, is_replace);
        if (ret != GS_SUCCESS) {
            GS_LOG_RUN_ERR("tse_index_read: tse index init failed");
            return ret;
        }
    }

    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;

    // check if partition changed during index scan
    if (tse_check_partition_changed(cursor, tch)) {
        GS_RETURN_IFERR(tse_check_partition_status(tch, &cursor, index_info, mode));
    }

    GS_LOG_DEBUG_INF("tse_index_read: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

    GS_RETURN_IFERR(tse_get_index_info_and_set_scan_key(cursor, index_info));

    CM_SAVE_STACK(knl_session->stack);
    cursor->row = (row_head_t *)cm_push(knl_session->stack, GS_MAX_ROW_SIZE);
    if (cursor->row == NULL) {
        GS_LOG_RUN_ERR("init row space failed!");
        return GS_ERROR;
    }

    int ret = get_correct_pos_by_fetch(session, tse_context, cursor, record_info, index_info);
    if (ret != GS_SUCCESS) {
        CM_RESTORE_STACK(knl_session->stack);
        return ret;
    }

    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

int tse_trx_begin(tianchi_handler_t *tch, tianchi_trx_context_t trx_context)
{
    // it's possible calling START TRANSACTION before open_table, thus session can also be added to gmap in this intf
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    if (session == NULL) {
        if (tse_get_new_session(&session) != GS_SUCCESS) {
            int err = tse_get_and_reset_err();
            GS_LOG_RUN_ERR("tse_trx begin: alloc new session failed, thd_id=%u, err=%d",
                tch->thd_id, err);
            return err;
        }
        session->tse_inst_id = tch->inst_id;
        session->tse_thd_id = tch->thd_id;
        tch->sess_addr = (uint64)session;
        GS_LOG_DEBUG_INF("tse_trx begin: alloc new session for thd_id=%u, session_id=%u",
            tch->thd_id, session->knl_session.id);
    }
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    // mysql-server侧通过is_tse_trx_begin标记，保证一个事务只会调用一次tse_trx_begin，且调进来时参天侧事务未开启
    CM_ASSERT(knl_session->rm->txn == NULL);
    if (knl_set_session_trans(knl_session, (isolation_level_t)trx_context.isolation_level) != GS_SUCCESS) {
        int err = tse_get_and_reset_err();
        GS_LOG_RUN_ERR("tse_trx begin: knl_set_session_trans failed, thd_id=%u, err=%d",
            tch->thd_id, err);
        return err;
    }
    knl_session->lock_wait_timeout = trx_context.lock_wait_timeout;
    session->auto_commit = trx_context.autocommit;
    // 这里不再主动调用tx_begin，参天引擎在DML需要undo时会自动开启txn
    GS_LOG_DEBUG_INF("tse_trx begin with thd_id=%u, session_id=%u, isolation level=%u, "
        "current_scn=%llu, rm_query_scn=%llu, lock_wait_timeout=%u, rmid=%u",
        tch->thd_id, session->knl_session.id, trx_context.isolation_level,
        knl_session->kernel->scn, knl_session->rm->query_scn, trx_context.lock_wait_timeout, knl_session->rmid);
    return GS_SUCCESS;
}

int tse_alter_commit(tianchi_handler_t *tch)
{
    tse_context_t *tse_context = NULL;
    sql_stmt_t *stmt = NULL;
    session_t *session = NULL;

    session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    if (tch->cursor_addr != INVALID_VALUE64) {
        tse_free_session_cursor(session, (knl_cursor_t *)tch->cursor_addr);
    }

    stmt = session->current_stmt;
    tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    if (tse_context == NULL) {
        tse_ddl_clear_stmt(stmt);
    }
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_alter_table_commit(&(session->knl_session), stmt, tse_context->dc, true);
    tse_ddl_clear_stmt(stmt);
    tse_alter_table_unlock(&(session->knl_session));
    return GS_SUCCESS;
}

int tse_alter_rollback(tianchi_handler_t *tch)
{
    tse_context_t *tse_context = NULL;
    session_t *session = NULL;
    sql_stmt_t *stmt = NULL;

    session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    if (tch->cursor_addr != INVALID_VALUE64) {
        tse_free_session_cursor(session, (knl_cursor_t *)tch->cursor_addr);
    }

    stmt = session->current_stmt;
    tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    if (tse_context == NULL) {
        tse_ddl_clear_stmt(stmt);
    }
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_alter_table_rollback(&(session->knl_session), tse_context->dc, true);
    tse_ddl_clear_stmt(stmt);
    tse_alter_table_unlock(&(session->knl_session));
    return GS_SUCCESS;
}

int tse_srv_commit(tianchi_handler_t *tch)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    if (tch->cursor_addr != INVALID_VALUE64) {
        tse_free_session_cursor(session, (knl_cursor_t *)tch->cursor_addr);
    }

    knl_session_t *knl_session = &session->knl_session;
    knl_commit(knl_session);
    GS_LOG_DEBUG_INF("tse_trx commit with thd_id=%u, session_id=%u, current_scn=%llu, rmid=%u",
        tch->thd_id, session->knl_session.id, session->knl_session.kernel->scn, session->knl_session.rmid);
    return GS_SUCCESS;
}

int tse_srv_rollback(tianchi_handler_t *tch)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    if (tch->cursor_addr != INVALID_VALUE64) {
        tse_free_session_cursor(session, (knl_cursor_t *)tch->cursor_addr);
    }
    knl_session_t *knl_session = &session->knl_session;
    knl_rollback(knl_session, NULL);
    GS_LOG_DEBUG_INF("tse_trx rollback with thd_id=%u, session_id=%u, current_scn=%llu, rmid=%u",
        tch->thd_id, session->knl_session.id, session->knl_session.kernel->scn, session->knl_session.rmid);

    return GS_SUCCESS;
}

int tse_srv_set_savepoint(tianchi_handler_t *tch, const char *name)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    GS_LOG_DEBUG_INF("tse_trx set savepoint with thd_id=%u, session_id=%u", tch->thd_id, session->knl_session.id);
    knl_session_t *knl_session = &session->knl_session;
    text_t nm = { (char *)name, strlen(name) };
    if (knl_set_savepoint(knl_session, &nm) != GS_SUCCESS) {
        int err = tse_get_and_reset_err();
        GS_LOG_RUN_ERR("tse_srv_set_savepoint: knl_set_savepoint failed, thd_id=%u, err=%d",
            tch->thd_id, err);
        return err;
    }
    return GS_SUCCESS;
}

int tse_srv_rollback_savepoint(tianchi_handler_t *tch, const char *name)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    GS_LOG_DEBUG_INF("tse_trx rollback savepoint with thd_id=%u, session_id=%u", tch->thd_id, session->knl_session.id);
    knl_session_t *knl_session = &session->knl_session;
    text_t nm = { (char *)name, strlen(name) };
    if (knl_rollback_savepoint(knl_session, &nm) != GS_SUCCESS) {
        int err = tse_get_and_reset_err();
        GS_LOG_RUN_ERR("tse_srv_rollback_savepoint: knl_rollback_savepoint failed, thd_id=%u, err=%d",
            tch->thd_id, err);
        return err;
    }
    return GS_SUCCESS;
}

int tse_srv_release_savepoint(tianchi_handler_t *tch, const char *name)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    GS_LOG_DEBUG_INF("tse_trx release savepoint with thd_id=%u, session_id=%u", tch->thd_id, session->knl_session.id);
    knl_session_t *knl_session = &session->knl_session;
    text_t nm = { (char *)name, strlen(name) };
    if (knl_release_savepoint(knl_session, &nm) != GS_SUCCESS) {
        int err = tse_get_and_reset_err();
        GS_LOG_RUN_ERR("tse_srv_release_savepoint: knl_release_savepoint failed, thd_id=%u, err=%d",
            tch->thd_id, err);
        return err;
    }
    return GS_SUCCESS;
}

static int tse_context_rowid_fetch(knl_cursor_t **cursor, knl_session_t *knl_session, tse_context_t *tse_context)
{
    int ret = GS_SUCCESS;
    *cursor = knl_push_cursor(knl_session);
    if (*cursor == NULL) {
        GS_LOG_RUN_ERR("tse_context_rowid_fetch: knl_push_cursor FAIL");
        return ERR_GENERIC_INTERNAL_ERROR;
    }

    (*cursor)->rowid = tse_context->row_id;
    (*cursor)->scan_mode = SCAN_MODE_ROWID;
    (*cursor)->action = CURSOR_ACTION_SELECT;

    bool32 isFound = GS_FALSE;
    ret = tse_open_cursor_and_fetch_by_rowid(knl_session, *cursor, tse_context, &isFound);
    if (ret != GS_SUCCESS) {
        tse_close_cursor(knl_session, *cursor);
        return ret;
    }
    
    if (!isFound) {
        GS_LOG_RUN_ERR("tse_context_rowid_fetch: not found.");
        tse_close_cursor(knl_session, *cursor);
        return ERR_GENERIC_INTERNAL_ERROR;
    }

    return GS_SUCCESS;
}

int tse_general_fetch(tianchi_handler_t *tch, record_info_t *record_info)
{
    int ret = GS_SUCCESS;
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_cursor_t *cursor = NULL;
    CM_SAVE_STACK(knl_session->stack);

    if (tch->cursor_addr == INVALID_VALUE64 && !IS_INVALID_ROWID(tse_context->row_id)) {
        ret = tse_context_rowid_fetch(&cursor, knl_session, tse_context);
        CM_RESTORE_STACK(knl_session->stack);
        return ret;
    } else {
        cursor = (knl_cursor_t *)tch->cursor_addr;
    }

    GS_LOG_DEBUG_INF("tse_general_fetch: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

    cursor->row = (row_head_t *)cm_push(knl_session->stack, GS_MAX_ROW_SIZE);
    if (cursor->row == NULL) {
        GS_LOG_RUN_ERR("init row space failed!");
        return GS_ERROR;
    }

    ret = tse_fetch_and_filter(cursor, knl_session, record_info->record, &record_info->record_len);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("tse_general_fetch: tse_fetch_and_filter FAIL");
        tse_free_session_cursor(session, cursor);
        CM_RESTORE_STACK(knl_session->stack);
        return ret;
    }

    if (!cursor->eof) {
        if (cursor->index_only) {
            ret = tse_index_only_row_fill_bitmap(cursor, record_info->record);
            record_info->record_len = ((row_head_t *)record_info->record)->size;
        }
    } else {
        record_info->record_len = 0;
    }

    CM_RESTORE_STACK(knl_session->stack);
    return ret;
}

int tse_general_prefetch(tianchi_handler_t *tch, uint32_t rowNum, uint8_t *records,
                         uint16_t *record_lens, uint32_t *recNum, uint64_t *rowids)
{
    int ret = GS_SUCCESS;
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    GS_LOG_DEBUG_INF("tse_general_prefetch: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

    CM_SAVE_STACK(knl_session->stack);
    cursor->row = (row_head_t *)cm_push(knl_session->stack, GS_MAX_ROW_SIZE);
    if (cursor->row == NULL) {
        GS_LOG_RUN_ERR("init row space failed!");
        return GS_ERROR;
    }
    *recNum = 0;
    for (uint32_t i = 0; i < rowNum; i++) {
        ret = tse_fetch_and_filter(cursor, knl_session, records, &record_lens[i]);
        if (ret != GS_SUCCESS) {
            GS_LOG_RUN_ERR("tse_general_prefetch: tse_fetch_and_filter FAIL");
            tse_free_session_cursor(session, cursor);
            return ret;
        }
        if (cursor->eof) {
            record_lens[i] = 0;
            break;
        }
        if (cursor->index_only) {
            ret = tse_index_only_row_fill_bitmap(cursor, records);
            record_lens[i] = ((row_head_t *)records)->size;
        }

        rowids[i] = cursor->rowid.value;
        records += record_lens[i];
        *recNum += 1;
    }
    CM_RESTORE_STACK(knl_session->stack);
    return ret;
}

static knl_column_t *tse_get_real_column(knl_cursor_t *cursor, char *column_name)
{
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    knl_column_t *tmp_column = NULL;
    for (uint32_t i = 0; i < entity->column_count; i++) {
        tmp_column = dc_get_column(entity, i);
        if (cm_strcmpi(column_name, tmp_column->name) == 0) {
            return tmp_column;
        }
    }
    return NULL;
}

int tse_knl_write_lob(tianchi_handler_t *tch, char *locator, uint32_t locator_size,
                      char *column_name, void *data, uint32_t data_len, bool force_outline, uint32_t buffer_size)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    knl_cursor_t *cursor = NULL;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    int ret = GS_SUCCESS;
    if (tch->cursor_addr != INVALID_VALUE64) {
        cursor = (knl_cursor_t *)tch->cursor_addr;
    } else {
        cursor = tse_alloc_session_cursor(session, tch->part_id, tch->subpart_id);
        if (cursor == NULL) {
            GS_LOG_RUN_ERR("tse_rnd_init: tse_alloc_session_cursor FAIL");
            return ERR_GENERIC_INTERNAL_ERROR;
        }
        tch->cursor_addr = (uint64_t)cursor;
        GS_LOG_DEBUG_INF("tse_rnd_init: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

        cursor->action = CURSOR_ACTION_INSERT;
        if (tse_open_cursor(knl_session, cursor, tse_context, &tch->sql_stat_start) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("tse_knl_write_lob: tse_open_cursor failed");
            tse_free_session_cursor(session, cursor);
            return tse_get_and_reset_err();
        }
    }
    knl_column_t *column = tse_get_real_column(cursor, column_name);
    if (column == NULL) {
        GS_LOG_RUN_ERR("tse_knl_write_lob: tse_get_real_column failed");
        return tse_get_and_reset_err();
    }
    tianchi_lob_text_t text_data;
    text_data.str = data;
    text_data.len = data_len;
    
    if (knl_write_lob(knl_session, cursor, locator, column, force_outline, &text_data) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("tse_knl_write_lob: knl_write_lob failed");
        tse_free_session_cursor(session, cursor);
        return tse_get_and_reset_err();
    }
    if (knl_session->canceled == GS_TRUE) {
        GS_LOG_RUN_ERR("tse_knl_write_lob: knl_write_lob has been canceled");
        tse_free_session_cursor(session, cursor);
        return ERR_OPERATION_CANCELED;
    }
    
    return ret;
}

int tse_knl_read_lob(tianchi_handler_t *tch, char* loc, uint32_t offset,
    void *buf, uint32_t size, uint32_t *read_size, uint32_t buffer_size)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    GS_LOG_DEBUG_INF("tse_knl_read_lob: thd_id=%u", tch->thd_id);

    knl_session_t *knl_session = &session->knl_session;
    return knl_read_lob(knl_session, loc, offset, buf, size, read_size);
}

int tse_analyze_table(tianchi_handler_t *tch, const char *db_name, const char *table_name, double sampling_ratio)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    GS_LOG_DEBUG_INF("tse_analyze_table: analyze table %s.%s, thd_id=%u", db_name, table_name, tch->thd_id);
    knl_session_t *knl_session = &session->knl_session;
    CM_SAVE_STACK(knl_session->stack);

    knl_analyze_tab_def_t *def = cm_push(knl_session->stack, sizeof(knl_analyze_tab_def_t));
    if (def == NULL) {
        GS_LOG_RUN_ERR("tse_analyze_table: out of stack, current offset=%u, max depth=%u",
            knl_session->stack->push_offset, knl_session->stack->size);
        return ERR_ALLOC_MEMORY;
    }
    status_t status = memset_s(def, sizeof(knl_analyze_tab_def_t), 0, sizeof(knl_analyze_tab_def_t));
    knl_securec_check(status);
    cm_str2text(db_name, &def->owner);
    cm_str2text(table_name, &def->name);
    def->sample_ratio = (sampling_ratio == STATS_MAX_ESTIMATE_PERCENT) ? STATS_FULL_TABLE_SAMPLE : sampling_ratio;
    def->sample_type = (sampling_ratio == STATS_MAX_ESTIMATE_PERCENT) ? STATS_AUTO_SAMPLE : STATS_SPECIFIED_SAMPLE;
    def->is_default = GS_FALSE;
    def->part_name = CM_NULL_TEXT;
    def->sample_level = BLOCK_SAMPLE;
    def->method_opt.option = FOR_ALL_COLUMNS;
    def->dynamic_type = STATS_ALL;
    def->is_report = GS_FALSE;
    if (!tse_alloc_stmt_context(session)) {
        return GS_ERROR;
    }
    def->part_no = tch->part_id;
    status = knl_analyze_table(&session->knl_session, def);
    GS_LOG_RUN_INF("tse_analyze_table: analyze table %s.%s returned with ret %d", db_name, table_name, status);
    CM_RESTORE_STACK(knl_session->stack);
    int ret = GS_SUCCESS;
    if (status != GS_SUCCESS) {
        ret = tse_get_and_reset_err();
    }
    return ret;
}

int tse_optimize_table(tianchi_handler_t *tch, const char *db_name, const char *table_name)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");
    knl_session_t *knl_session = &session->knl_session;
    GS_RETURN_IFERR(tse_try_reopen_dc(knl_session, &tse_context->user, &tse_context->table, tse_context->dc));
    knl_dictionary_t *dc = tse_context->dc;
    dc_entity_t *dc_entity = (dc_entity_t *)dc->handle;

    tse_set_no_use_other_sess4thd(session);
    if (!tse_alloc_stmt_context(session)) {
        GS_LOG_RUN_ERR("tse_alloc_stmt_context failed");
        return GS_ERROR;

    }
    sql_stmt_t *stmt = NULL;
    stmt = session->current_stmt;
    knl_alindex_def_t *def = NULL;
    GS_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_alindex_def_t), (pointer_t *)&def));
    status_t status = GS_SUCCESS;
    cm_str2text(table_name, &def->table);
    cm_str2text(db_name, &def->user);
    def->type = ALINDEX_TYPE_REBUILD;

    int ret = GS_SUCCESS;
    for (int i = 0; i < dc_entity->table.desc.index_count; i++) {
        cm_str2text(dc_entity->table.index_set.items[i]->desc.name, &def->name);
        status = knl_alter_index(&(session->knl_session), stmt, def);
        if (status != GS_SUCCESS) {
            ret = tse_get_and_reset_err();
            GS_LOG_RUN_ERR("tse_optimize_table: rebuild index %s, returned with ret %d",
                           dc_entity->table.index_set.items[i]->desc.name, status);
            tse_ddl_clear_stmt(stmt);
            return ret;
        }
    }
    GS_LOG_RUN_INF("tse_optimize_table: optimize table %s.%s returned with ret %d", db_name,
                   dc_entity->table.desc.name, status);
    tse_ddl_clear_stmt(stmt);
    return ret;
}

int tse_get_cbo_stats(tianchi_handler_t *tch, tianchi_cbo_stats_t *stats)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    GS_LOG_DEBUG_INF("tse_get_cbo_stats: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);
    
    knl_session_t *knl_session = &session->knl_session;
    GS_RETURN_IFERR(tse_try_reopen_dc(knl_session, &tse_context->user, &tse_context->table, tse_context->dc));
    
    get_cbo_stats(knl_session, DC_ENTITY(tse_context->dc), stats);
    
    return GS_SUCCESS;
}

int tse_get_index_name(tianchi_handler_t *tch, char *index_name)
{
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "session lookup failed");
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    CM_ASSERT(tse_context->dup_key_slot >= 0);
    knl_session_t *knl_session = &session->knl_session;
    GS_RETURN_IFERR(tse_try_reopen_dc(knl_session, &tse_context->user, &tse_context->table, tse_context->dc));
    knl_dictionary_t *dc = tse_context->dc;
    int len = strlen(DC_INDEX(dc, tse_context->dup_key_slot)->desc.name);
    errno_t ret = memcpy_s(index_name, TSE_MAX_KEY_NAME_LENGTH + 1,
                           DC_INDEX(dc, tse_context->dup_key_slot)->desc.name, len);
    knl_securec_check(ret);
    return GS_SUCCESS;
}

int tse_get_serial_value(tianchi_handler_t *tch, uint64_t *value, uint16_t auto_inc_step, uint16_t auto_inc_offset)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    
    if (tch->ctx_addr == INVALID_VALUE64 || ((tse_context_t *)tch->ctx_addr) == NULL) {
        GS_LOG_RUN_ERR("ctx_addr(0x%llx) is invalid.", tch->ctx_addr);
        return GS_ERROR;
    }

    knl_dictionary_t *dc = ((tse_context_t *)(tch->ctx_addr))->dc;
    dc_entity_t *entity = (dc_entity_t *)dc->handle;
    knl_session_t *knl_session = &session->knl_session;

    if (tse_get_curr_serial_value_auto_inc(knl_session, dc->handle, (uint64 *)value, (uint16)auto_inc_step,
                                           (uint16)auto_inc_offset) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("fail to get serial value");
        return GS_ERROR;
    }

    for (int i = 0; i < entity->column_count; i++) {
        knl_column_t *knl_column = dc_get_column(entity, i);
        if (!KNL_COLUMN_IS_SERIAL(knl_column)) {
            continue;
        }

        tse_calc_max_serial_value(knl_column, (uint64 *)value);
        break;
    }
    return GS_SUCCESS;
}

uint8_t *tse_alloc_buf(tianchi_handler_t *tch, uint32_t buf_size)
{
    return (uint8_t*)cm_malloc(buf_size);
}

void tse_free_buf(tianchi_handler_t *tch, uint8_t *buf)
{
    cm_free(buf);
}

int tse_get_max_sessions_per_node(uint32_t *max_sessions)
{
    *max_sessions = g_instance->session_pool.max_sessions;
    return GS_SUCCESS;
}
