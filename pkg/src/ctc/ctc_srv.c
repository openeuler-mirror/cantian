/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 */
#include "ctc_module.h"
#include "ctc_srv.h"
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
#include "dml_executor.h"
#include "knl_table.h"
#include "ctc_srv_util.h"
#include "ctc_cbo.h"
#include "ctc_ddl.h"
#include "cm_malloc.h"
#include "knl_interface.h"
#include "ctc_inst.h"
#include "ctc_ddl_list.h"
#include "cm_log.h"

#define CTC_MAX_MYSQL_INST_SIZE (128)
#define CTC_MAX_PREFETCH_NUM (100)

/*
 * lob text data struct
 * need for knl_write_lob interface
 */
typedef struct st_lob_text {
    char *str;
    unsigned int len;
} ctc_lob_text_t;

int32 sint3korr(uchar *A)
{
    return ((int32)(((A[2]) & 128)
                        ? (((uint32)255L << 24) | (((uint32)A[2]) << 16) | (((uint32)A[1]) << 8) | ((uint32)A[0]))
                        : (((uint32)A[2]) << 16) | (((uint32)A[1]) << 8) | ((uint32)A[0])));
}

EXTER_ATTACK int ctc_open_table(ctc_handler_t *tch, const char *table_name, const char *user_name)
{
    CTC_LOG_RET_VAL_IF_NUL(tch, CT_ERROR, "ctc_open_table: null tch ptr");
    INIT_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_OPEN_TABLE);
    BEGIN_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_OPEN_TABLE);

    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, tch, true, false, &is_new_session));
    ctc_set_no_use_other_sess4thd(session);
    ctc_context_t *ctc_context = NULL;
    if (init_ctc_ctx_and_open_dc(session, &ctc_context, table_name, user_name) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_open_table failed :thd_id:%u, user_name:%s, table_name:%s", tch->thd_id, user_name,
                       table_name);
        int32 error_code = ctc_get_and_reset_err();
        END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_OPEN_TABLE);
        return error_code == 0 ? ERR_GENERIC_INTERNAL_ERROR : error_code;
    };
    tch->ctx_addr = (uint64)ctc_context;
    tch->read_only_in_ct = IS_CANTIAN_SYS_DC(ctc_context->dc);
    CT_LOG_DEBUG_INF("ctc_open_table: tbl=%s, thd_id=%d, session_id=%u", ctc_context->table.str, tch->thd_id,
                     session->knl_session.id);

    END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_OPEN_TABLE);
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_close_table(ctc_handler_t *tch)
{
    INIT_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_CLOSE_TABLE);
    BEGIN_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_CLOSE_TABLE);
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    if (ctc_context == NULL) {
        CT_LOG_RUN_WAR("ctc_close_table: ctx addr invalid");
        END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_CLOSE_TABLE);
        return CT_SUCCESS;
    }
    char *table_name = "empty_table";
    if (ctc_context->table.str != NULL) {
        table_name = ctc_context->table.str;
    }
    CT_LOG_DEBUG_INF("ctc_close_table: tbl=%s, thd_id=%u", table_name, tch->thd_id);
    ctc_set_no_use_other_sess4thd(NULL);
    free_ctc_ctx(&ctc_context, false);  // 释放ctc_context持有的内存,保留ctc_context的本身内存
    // 此处不管移除成功或者失败，都没关系，移除操作目前只是打上删除标记，不会真正的删除ctc_context的内存
    if (remove_mysql_inst_ctx_res(ctc_context->ctc_inst_id, ctc_context) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_close_table remove error,inst_id:%u,thd_id:%u", tch->inst_id, tch->thd_id);
    }
    END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_CLOSE_TABLE);
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_close_session(ctc_handler_t *tch)
{
    ctc_set_no_use_other_sess4thd(NULL);
    (void)ctc_unlock_instance(NULL, tch);
    int ret = ctc_close_mysql_connection(tch);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_CLOSE_SESSION]:close mysql connection failed, ret:%d, conn_id:%u, ctc_instance_id:%u", ret,
                       tch->thd_id, tch->inst_id);
    }
    return CT_SUCCESS;
}

EXTER_ATTACK void ctc_kill_session(ctc_handler_t *tch)
{
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    if (session == NULL) {
        CT_LOG_RUN_ERR("session can not be null, conn_id=%u, ctc_inst_id=%u", tch->thd_id, tch->inst_id);
        CM_ASSERT(0);
        return;
    }
    ctc_set_no_use_other_sess4thd(session);
    CT_LOG_DEBUG_INF("[CTC_KILL_SESSION]:conn_id=%u, ctc_inst_id:%u, session_id=%u", tch->thd_id, tch->inst_id,
                     session->knl_session.id);
    session->knl_session.canceled = CT_TRUE;
}

static void ctc_fill_serial_col_buf_4int(uint32 size, char *column_data_buf, uint64 *value)
{
    switch (size) {
        case CTC_TINY_INT_SIZE: {  // tinyint
            *(int8_t *)column_data_buf = (int8_t)*value;
            break;
        }
        case CTC_SMALL_INT_SIZE: {  // smallint
            *(int16_t *)column_data_buf = (int16_t)*value;
            break;
        }
        case CTC_MEDIUM_INT_SIZE:  // mediumint
        case CTC_INTEGER_SIZE: {   // int
            *(int32_t *)column_data_buf = (int32_t)*value;
            break;
        }
        default:
            CT_LOG_RUN_ERR("error column size for ctc_fill_serial_col_buf_4int,%u", size);
            break;
    }
}

static void ctc_fill_serial_col_buf_4uint(uint32 size, char *column_data_buf, uint64 *value)
{
    switch (size) {
        case CTC_TINY_INT_SIZE: {  // unsigned tinyint
            uint8_t tmp_key = (uint8_t)*value;
            if (tmp_key & 0x80) {
                *(uint32_t *)column_data_buf = (uint32_t)(*value) | 0xffffff00;
            } else {
                *(uint32_t *)column_data_buf = (uint8_t)*value;
            }
            break;
        }
        case CTC_SMALL_INT_SIZE: {  // unsigned smallint
            uint16_t tmp_key = (uint16_t)*value;
            if (tmp_key & 0x8000) {
                *(uint32_t *)column_data_buf = (uint32_t)(*value) | 0xffff0000;
            } else {
                *(uint32_t *)column_data_buf = (uint16_t)*value;
            }
            break;
        }
        case CTC_MEDIUM_INT_SIZE: {  // unsigned mediumint
            uint32_t tmp_key = (uint32_t)*value;
            if (tmp_key & 0x800000) {
                *(uint32_t *)column_data_buf = (uint32_t)(*value) | 0xff000000;
            } else {
                *(uint32_t *)column_data_buf = (uint32_t)*value;
            }
            break;
        }
        case CTC_INTEGER_SIZE: {  // unsigned int
            *(uint32_t *)column_data_buf = (uint32_t)*value;
            break;
        }
        default:
            CT_LOG_RUN_ERR("error column size for ctc_fill_serial_col_buf_4uint,%u", size);
            break;
    }
}

// 将不同数据类型的数据填充到char*buf上
static void ctc_fill_serial_col_buf(knl_column_t *knl_column, char *column_data_buf, uint64 *value)
{
    ctc_calc_max_serial_value(knl_column, value);
    // 自增列能够保证datatype只会出现这几种类型，所以函数不用返回值，上层逻辑也不用判断，保持逻辑简单
    switch (knl_column->datatype) {
        case CT_TYPE_INTEGER: {
            ctc_fill_serial_col_buf_4int(knl_column->size, column_data_buf, value);
            break;
        }
        case CT_TYPE_UINT32: {
            ctc_fill_serial_col_buf_4uint(knl_column->size, column_data_buf, value);
            break;
        }
        case CT_TYPE_BIGINT: {
            *(int64 *)column_data_buf = *value;
            break;
        }
        case CT_TYPE_UINT64: {
            *(uint64 *)column_data_buf = *value;
            break;
        }
        case CT_TYPE_REAL: {
            *(double *)column_data_buf = (double)*value;
            break;
        }
        default:
            CT_LOG_RUN_ERR("ctc_fill_serial_col_buf: unspported datatype of serial column,%u", knl_column->datatype);
            break;
    }
}

void ctc_convert_serial_col_value_4int(uint32 size, char *column_data_buf, int64 *value)
{
    switch (size) {
        case CTC_TINY_INT_SIZE: {  // tinyint
            *value = *(int8 *)column_data_buf;
            break;
        }
        case CTC_SMALL_INT_SIZE: {  // smallint
            *value = *(int16 *)column_data_buf;
            break;
        }
        case CTC_MEDIUM_INT_SIZE: {
            *value = sint3korr((uchar *)((void *)column_data_buf));
            break;
        }
        case CTC_INTEGER_SIZE: {
            *value = *(int32 *)column_data_buf;
            break;
        }
        default:
            CT_LOG_RUN_ERR("error column size for ctc_convert_serial_col_value_4int,%u", size);
            break;
    }
}

void ctc_convert_serial_col_value_4uint(uint32 size, char *column_data_buf, int64 *value)
{
    switch (size) {
        case CTC_TINY_INT_SIZE: {  // unsigned tinyint
            *value = *(uchar *)column_data_buf;
            break;
        }
        case CTC_SMALL_INT_SIZE: {  // unsigned smallint
            *value = *(uint16 *)column_data_buf;
            break;
        }
        case CTC_MEDIUM_INT_SIZE: {  // unsigned mediumint
            *value = cm_ptr3_to_uint_big_endian((const uchar *)((void *)column_data_buf));
            break;
        }
        case CTC_INTEGER_SIZE: {  // unsigned int
            *value = *(uint32 *)column_data_buf;
            break;
        }
        default:
            CT_LOG_RUN_ERR("error column size for ctc_convert_serial_col_value_4uint,%u", size);
            break;
    }
}

// 将char*转换为对应数据类型的数值
static void ctc_convert_serial_col_value(knl_column_t *knl_column, char *column_data_buf, int64 *value)
{
    // 自增列能够保证datatype只会出现这几种类型，所以函数不用返回值，上层逻辑也不用判断，保持逻辑简单
    switch (knl_column->datatype) {
        case CT_TYPE_INTEGER: {
            ctc_convert_serial_col_value_4int(knl_column->size, column_data_buf, value);
            break;
        }
        case CT_TYPE_UINT32: {
            ctc_convert_serial_col_value_4uint(knl_column->size, column_data_buf, value);
            break;
        }
        case CT_TYPE_BIGINT: {
            *value = *(int64 *)column_data_buf;
            break;
        }
        case CT_TYPE_UINT64: {
            *value = *(uint64 *)column_data_buf;
            break;
        }
        case CT_TYPE_REAL: {
            if (knl_column->size == 4) {  // float size为4
                *value = convert_float_to_rint(column_data_buf);
            }
            if (knl_column->size == 8) {  // double size 为8
                *value = convert_double_to_rint(column_data_buf);
            }
            break;
        }
        default:
            CT_LOG_RUN_ERR("ctc_convert_serial_col_value: unspported datatype of serial column,datatype:%u",
                           knl_column->datatype);
            break;
    }
}

status_t ctc_update_serial_col(knl_session_t *session, knl_cursor_t *cursor, uint16_t serial_column_offset,
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
        ctc_convert_serial_col_value(serial_col, serial_buf, &serial->max_serial_col_value);
        serial->is_uint64 = serial_col->datatype == CT_TYPE_UINT64 ? true : false;
        return CT_SUCCESS;
    }

    /*
        get the next autoinc val from kernel and fill into the write buffer
        1. autoinc val is NULL
        2. autoinc val is zero and sql mode is not NO_AUTO_VALUE_ON_ZERO
    */
    uint64 serial_value = 0;
    if (ctc_get_curr_serial_value_auto_inc(session, entity, &serial_value, flag.auto_inc_step, flag.auto_inc_offset) !=
        CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_get_curr_serial_value failed!");
        return CT_ERROR;
    }
    if (serial_value == CT_INVALID_ID64) {
        CT_THROW_ERROR(ERR_AUTOINC_READ_FAILED);
        return CT_ERROR;
    }

    if (flag.autoinc_lock_mode != CTC_AUTOINC_OLD_STYLE_LOCKING &&
        serial_value < ctc_calc_max_serial_value(serial_col, NULL)) {
        serial->is_uint64 = serial_col->datatype == CT_TYPE_UINT64 ? true : false;
        if (knl_get_serial_value_4mysql(session, entity, &serial_value, flag.auto_inc_step, flag.auto_inc_offset) !=
            CT_SUCCESS) {
            CT_LOG_RUN_ERR("knl_get_serial_value_4mysql failed");
            return CT_ERROR;
        }
    }

    // if this auto_inc col is nullable and current value is NULL (see datatype_cnvrtr.cc
    // mysql_record_to_cantian_record)
    if (serial_column_offset != 0) {
        ctc_fill_serial_col_buf(serial_col, serial_buf, &serial_value);
    }
    *last_insert_id = serial_value;
    return CT_SUCCESS;
}

/*
作用：用于update 语句中获取自增列的值，
返回值:0 update语句没有修改自增列，或者表中本身没有自增列，上层逻辑无需处理
      > 0 update语句设置了自增列，上层逻辑需要调用knl_update_serial_value维护表的最大自增值
      < 0 update语句设置了自增列的值，基于mysql不允许设置负数自增值逻辑，上层不用处理
*/
static void ctc_update_get_serial_col_value(dc_entity_t *entity, knl_session_t *knl_session, knl_cursor_t *cursor,
                                            serial_t *serial)
{
    int64_t serial_col_value = 0;
    char *column_data_buf = NULL;
    for (int i = 0; i < entity->column_count; i++) {
        knl_column_t *knl_column = dc_get_column(entity, i);
        if (!KNL_COLUMN_IS_SERIAL(knl_column)) {
            continue;
        }
        serial->is_uint64 = knl_column->datatype == CT_TYPE_UINT64 ? true : false;
        for (int j = 0; j < cursor->update_info.count; j++) {
            if (cursor->update_info.columns[j] == i) {
                column_data_buf = cursor->update_info.data + cursor->update_info.offsets[j];
                ctc_convert_serial_col_value(knl_column, column_data_buf, (int64 *)(&serial_col_value));
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

int ctc_copy_cursor_row(knl_session_t *session, knl_cursor_t *cursor, row_head_t *src_row, row_head_t *compact_row,
                        uint16 *size)
{
    /* for heap row lock confliction and re-read row after that, we need to update query scn
       in order to do index scan using the new data with new query scn for mysql */
    if (cursor->scn > session->query_scn && cursor->action == CURSOR_ACTION_UPDATE) {
        session->query_scn = cursor->scn;
    }

    if (cursor->action > CURSOR_ACTION_SELECT && !ctc_alloc_stmt_context((session_t *)session)) {
        return CT_ERROR;
    }

    cm_assert(src_row != compact_row);
    if (src_row != NULL) {
        errno_t ret = memcpy_sp(compact_row, src_row->size, src_row, src_row->size);
        knl_securec_check(ret);
        *size = src_row->size;
    }

    return CT_SUCCESS;
}

int ctc_copy_cursor_row_read(knl_session_t *session, knl_cursor_t *cursor, record_info_t *record_info, bool copy_data)
{
    /* for heap row lock confliction and re-read row after that, we need to update query scn
       in order to do index scan using the new data with new query scn for mysql */
    if (cursor->scn > session->query_scn && cursor->action == CURSOR_ACTION_UPDATE) {
        session->query_scn = cursor->scn;
    }

    if (cursor->action > CURSOR_ACTION_SELECT && !ctc_alloc_stmt_context((session_t *)session)) {
        return CT_ERROR;
    }

    if (cursor->row == NULL) {
        return CT_SUCCESS;
    }

    record_info->record_len = cursor->row->size;
    if (copy_data) {
        errno_t ret = memcpy_sp(record_info->record, cursor->row->size, cursor->row, cursor->row->size);
        knl_securec_check(ret);
    } else {
        record_info->record = cursor->row;
        record_info->offsets = cursor->offsets;
        record_info->lens = cursor->lens;
    }
    return CT_SUCCESS;
}

static bool32 is_exceed_max_bulk_row(knl_cursor_t *cursor, uint16_t row_size)
{
    return cursor->rowid_count == KNL_ROWID_ARRAY_SIZE || (uint32)(cursor->row_offset + row_size) > CT_MAX_ROW_SIZE;
}

static bool32 is_same_partition(knl_part_locate_t *part1, knl_part_locate_t *part2)
{
    return part1->part_no == part2->part_no && part1->subpart_no == part2->subpart_no;
}

static bool32 need_insert(knl_cursor_t *cursor, uint16_t row_size, knl_part_locate_t *curr_part)
{
    table_t *table = (table_t *)cursor->table;
    return is_exceed_max_bulk_row(cursor, row_size) ||
           (IS_PART_TABLE(table) && !is_same_partition(&cursor->part_loc, curr_part));
}

int ctc_bulk_write_rows(knl_cursor_t *cursor, knl_session_t *knl_session, uint64_t rec_num,
                        const record_info_t *record_info, uint *err_pos, ctc_context_t *ctc_context,
                        ctc_part_t *part_ids)
{
    int ret = CT_SUCCESS;
    uint32_t total_rows = 0;  // how many rows have been inserted
    row_head_t *cursor_row = NULL;
    uint8_t *curr_row = record_info->record;
    table_t *table = (table_t *)cursor->table;

    for (uint i = 0; i < rec_num; i++) {
        /*
            if meet one of these conditions, insert all rows in cursor to cantian
            then put the current row to cursor
                1. if row has exceed cursor row capacity (all kind of table)
                2. current row is not the same partition as rows in cursor (part table)
        */
        if (cursor->rowid_count > 0 &&
            need_insert(cursor, record_info->record_len, (knl_part_locate_t *)&part_ids[i])) {
            uint32_t row_count = (uint32_t)cursor->rowid_count;
            if (knl_insert(knl_session, cursor) != CT_SUCCESS) {
                goto catch_err;
            }
            total_rows += row_count;
        }

        // copy current row to cursor
        cursor_row = (row_head_t *)((char *)cursor->row + cursor->row_offset);
        if (ctc_copy_cursor_row(knl_session, cursor, curr_row, cursor_row, &cursor_row->size) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("ctc_bulk_write_rows failed to copy cursor row");
            return CT_ERROR;
        }
        if (cursor->rowid_count == 0 && IS_PART_TABLE(table)) {
            knl_part_locate_t part_loc = { .part_no = part_ids[i].part_id, .subpart_no = part_ids[i].subpart_id };
            knl_set_table_part(cursor, part_loc);
        }
        cursor_row->size = MAX(cursor_row->size, KNL_MIN_ROW_SIZE);
        curr_row += record_info->record_len;
        cursor->row_offset += cursor_row->size;
        cursor->rowid_count++;
    }

    // insert all the left rows
    if (cursor->rowid_count > 0 && knl_insert(knl_session, cursor) != CT_SUCCESS) {
        goto catch_err;
    }
    return ret;

catch_err:
    ret = ctc_get_and_reset_err();
    CT_LOG_RUN_ERR("ctc_bulk_write_rows failed with ret %d", ret);
    if (ret == ERR_DUPLICATE_KEY) {
        *err_pos = total_rows + cursor->rowid_count;
        ctc_context->dup_key_slot = cursor->conflict_idx_slot;
    }
    return ret;
}

int insert_and_verify_for_bulk_write(knl_cursor_t *cursor, knl_session_t *knl_session, uint64_t rec_num,
                                     const record_info_t *record_info, uint *err_pos, ctc_context_t *ctc_context,
                                     dml_flag_t flag, ctc_part_t *part_ids)
{
    int ret = CT_SUCCESS;
    uint8_t *cur_start = record_info->record;
    knl_savepoint_t savepoint;
    table_t *table = (table_t *)cursor->table;
    for (uint i = 0; i < rec_num; i++) {
        if (flag.ignore) {
            knl_savepoint(knl_session, &savepoint);
        }

        if (IS_PART_TABLE(table)) {
            knl_part_locate_t part_loc = { .part_no = part_ids[i].part_id, .subpart_no = part_ids[i].subpart_id };
            knl_set_table_part(cursor, part_loc);
        }

        cursor->row = (row_head_t *)cur_start;
        ret = ctc_copy_cursor_row(knl_session, cursor, NULL, cursor->row, &cursor->row->size);
        if (ret != CT_SUCCESS) {
            ctc_close_cursor(knl_session, cursor);
            return ret;
        }

        status_t status = knl_insert(knl_session, cursor);
        if (status != CT_SUCCESS) {
            ret = ctc_get_and_reset_err();
            CT_LOG_RUN_ERR("ctc_bulk_write failed with ret %d, i=%u", ret, i);
            if (ret == ERR_DUPLICATE_KEY) {
                *err_pos = i;
                ctc_context->dup_key_slot = cursor->conflict_idx_slot;
            }
            return ret;
        }

        status = knl_verify_ref_integrities(knl_session, cursor);
        if (status == CT_SUCCESS) {
            cur_start += record_info->record_len;
            continue;
        }

        ret = ctc_get_and_reset_err();
        if (!(flag.no_foreign_key_check && ret == ERR_CONSTRAINT_VIOLATED_NO_FOUND)) {
            if (flag.ignore) {
                knl_rollback(knl_session, &savepoint);
            }
            CT_LOG_RUN_ERR("ctc_bulk_write failed integrities check with ret %d, i=%u", ret, i);
            return ret;
        }
        ret = CT_SUCCESS;
        cur_start += record_info->record_len;
    }
    return ret;
}

EXTER_ATTACK int ctc_bulk_write(ctc_handler_t *tch, const record_info_t *record_info, uint64_t rec_num,
                                uint32_t *err_pos, dml_flag_t flag, ctc_part_t *part_ids)
{
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");
    CTC_LOG_RET_NOT_SUPPORT(tch->read_only_in_ct, "bulk insert", ERR_OPERATIONS_NOT_SUPPORT);

    CM_SAVE_STACK(knl_session->stack);
    knl_cursor_t *cursor = ctc_push_cursor(knl_session);
    if (NULL == cursor) {
        CT_LOG_RUN_ERR("ctc_bulk_write: ctc_push_cursor FAIL");
        CTC_POP_CURSOR(knl_session);
        return ERR_GENERIC_INTERNAL_ERROR;
    }

    cursor->vnc_column = NULL;
    cursor->action = CURSOR_ACTION_INSERT;
    int ret = CT_SUCCESS;
    if (ctc_open_cursor(knl_session, cursor, ctc_context, &tch->sql_stat_start, false) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_bulk_write: ctc_open_cursor failed");
        CTC_POP_CURSOR(knl_session);
        ret = ctc_get_and_reset_err();
        return ret;
    }
    cursor->no_logic_logging = flag.no_logging;
    cursor->is_create_select = flag.is_create_select;
    if (IS_PART_TABLE((table_t *)cursor->table) && rec_num > MAX_BULK_INSERT_PART_ROWS) {
        CT_LOG_RUN_ERR("ctc_bulk_write: rec_num exceeds the max");
        CTC_POP_CURSOR(knl_session);
        return ERR_GENERIC_INTERNAL_ERROR;
    }

    if (flag.ignore || (((table_t *)cursor->table)->cons_set.ref_count > 0 && flag.no_foreign_key_check) ||
        TABLE_ACCESSOR(cursor)->do_insert != (knl_cursor_operator_t)pcrh_insert) {
        // single row insertion
        ret = insert_and_verify_for_bulk_write(cursor, knl_session, rec_num, record_info, err_pos, ctc_context, flag,
                                               part_ids);
    } else {
        // bulk row insertion, alloc space for cursor->row instead of point to cursor->buf
        // knl_insert will call knl_verify_ref_integrities for bulk write
        cursor->row = (row_head_t *)cm_push(knl_session->stack, CT_MAX_ROW_SIZE);
        if (cursor->row == NULL) {
            CT_LOG_RUN_ERR("ctc_bulk_write failed to alloc space for rows");
            CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
            return CT_ERROR;
        }
        ret = ctc_bulk_write_rows(cursor, knl_session, rec_num, record_info, err_pos, ctc_context, part_ids);
    }

    CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
    return ret;
}

int insert_and_verify_for_write_row(knl_session_t *knl_session, knl_cursor_t *cursor, serial_t *serial,
                                    uint64_t last_insert_id, ctc_context_t *ctc_context, dml_flag_t flag)
{
    int ret = 0;
    knl_savepoint_t savepoint;
    if (flag.ignore) {
        knl_savepoint(knl_session, &savepoint);
    }
    cursor->no_logic_logging = flag.no_logging;
    cursor->is_create_select = flag.is_create_select;
    status_t status = knl_insert(knl_session, cursor);
    if (status != CT_SUCCESS) {
        // for on duplicate key update
        ret = ctc_get_and_reset_err();
        if (ret == ERR_DUPLICATE_KEY) {
            ctc_context->dup_key_slot = cursor->conflict_idx_slot;
            ctc_context->conflict_rid = cursor->conflict_rid;
        }
        CT_LOG_DEBUG_ERR("ctc_write_row: knl_insert FAIL");
        return ret;
    }
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    if (knl_verify_ref_integrities(knl_session, cursor) != CT_SUCCESS) {
        ret = ctc_get_and_reset_err();
        if (flag.no_foreign_key_check && ret == ERR_CONSTRAINT_VIOLATED_NO_FOUND) {
            goto not_ret;
        }
        if (flag.ignore) {
            knl_rollback(knl_session, &savepoint);
        }
        CT_LOG_RUN_ERR("ctc_write_row failed to knl_verify_ref_integrities with ret %d", ret);
        return ret;
    }
not_ret:
    if (flag.auto_inc_used) {
        status = CT_SUCCESS;
        if (serial->max_serial_col_value != 0) {
            status = knl_update_serial_value_4mysql(knl_session, entity, serial->max_serial_col_value,
                                                    serial->is_uint64);
        } else if (!flag.has_explicit_autoinc && flag.autoinc_lock_mode == CTC_AUTOINC_OLD_STYLE_LOCKING) {
            status = knl_get_serial_value_4mysql(knl_session, entity, &last_insert_id, flag.auto_inc_step,
                                                 flag.auto_inc_offset);
        }

        if (status != CT_SUCCESS) {
            ret = ctc_get_and_reset_err();
            CT_LOG_RUN_ERR("ctc_write_row failed to set serial with ret %d, serial_col_value=%lld", ret,
                           serial->max_serial_col_value);
            if (ret != CT_SUCCESS && (flag.ignore)) {
                knl_rollback(knl_session, &savepoint);
            }
        }
    }
    return ret;
}

EXTER_ATTACK int ctc_update_job(update_job_info info)
{
    session_t *session = NULL;
    status_t status = ctc_get_new_session(&session);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ctc_update_job]: alloc new session failed");
        return status;
    }
    ctc_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    CM_SAVE_STACK(knl_session->stack);
    knl_cursor_t *cursor = ctc_push_cursor(knl_session);
    if (NULL == cursor) {
        CT_LOG_RUN_ERR("[ctc_update_job]: ctc_push_cursor FAIL");
        CTC_POP_CURSOR(knl_session);
        ctc_free_session(session);
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_JOB_ID, CT_INVALID_ID32);

    char *ptr;
    uint32 len;
    text_t job_name = { info.job_name_str, info.job_name_len };
    while (CT_TRUE) {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            status = ctc_get_and_reset_err();
            CT_LOG_RUN_ERR("[ctc_update_job]: job %s not found", info.job_name_str);
            CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
            ctc_free_session(session);
            return status;
        }
        if (cursor->eof) {
            CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
            CT_LOG_RUN_ERR("[ctc_update_job]: job %s not found", info.job_name_str);
            ctc_free_session(session);
            return CT_ERROR;
        }
        ptr = CURSOR_COLUMN_DATA(cursor, SYS_JOB_WHAT);
        len = CURSOR_COLUMN_SIZE(cursor, SYS_JOB_WHAT);
        if (len > 0 && len <= MAX_LENGTH_WHAT && strncmp(ptr, job_name.str, job_name.len) == 0) {
            break;
        }
    }

    int32 is_broken = *(int32 *)CURSOR_COLUMN_DATA(cursor, SYS_JOB_FLAG);

    knl_job_node_t job_info = { 0 };
    job_info.job_id = *(int64 *)CURSOR_COLUMN_DATA(cursor, SYS_JOB_JOB_ID);
    job_info.next_date = cm_now();
    if (!info.switch_on) {
        job_info.node_type = JOB_TYPE_BROKEN;
        job_info.is_broken = true;
    } else {
        job_info.node_type = JOB_TYPE_RUN;
        job_info.is_broken = false;
    }

    text_t user = { info.user_str, info.user_len };
    if (knl_update_job(knl_session, &user, &job_info, CT_TRUE) != CT_SUCCESS) {
        status = ctc_get_and_reset_err();
        CT_LOG_RUN_ERR("[ctc_update_job]: knl_update_job %s failed", info.job_name_str);
        knl_rollback(knl_session, NULL);
        CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
        ctc_free_session(session);
        return status;
    }
    knl_commit(knl_session);
    CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
    ctc_free_session(session);
    return status;
}

EXTER_ATTACK int ctc_write_row(ctc_handler_t *tch, const record_info_t *record_info, uint16_t serial_column_offset,
                               uint64_t *last_insert_id, dml_flag_t flag)
{
    INIT_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_WRITE_ROW);
    BEGIN_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_WRITE_ROW);
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    if (flag.write_through) {
        if (knl_begin_auton_rm(session) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("ERR to begin transaction for write_through_row.");
            END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_WRITE_ROW);
            return CT_ERROR;
        }
    }

    int ret = CT_SUCCESS;
    do {
        knl_session_t *knl_session = &session->knl_session;
        ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
        CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");
        CTC_LOG_RET_NOT_SUPPORT(tch->read_only_in_ct, "insert", ERR_OPERATIONS_NOT_SUPPORT);
        CM_SAVE_STACK(knl_session->stack);
        cm_reset_error();
        knl_cursor_t *cursor = ctc_push_cursor(knl_session);
        if (NULL == cursor) {
            CT_LOG_RUN_ERR("ctc_write_row: ctc_push_cursor FAIL");
            CTC_POP_CURSOR(knl_session);
            ret = ERR_GENERIC_INTERNAL_ERROR;
            break;
        }
        CT_LOG_DEBUG_INF("ctc_write_row: tbl=%s, thd_id=%u", ctc_context->table.str, tch->thd_id);
        cursor->vnc_column = NULL;
        cursor->action = CURSOR_ACTION_INSERT;
        if (ctc_open_cursor(knl_session, cursor, ctc_context, &tch->sql_stat_start, false) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("ctc_write_row: ctc_open_cursor failed");
            CTC_POP_CURSOR(knl_session);
            ret = ctc_get_and_reset_err();
            break;
        }

        if (IS_CTC_PART(tch->part_id)) {
            knl_part_locate_t part_loc = { .part_no = tch->part_id, .subpart_no = tch->subpart_id };
            knl_set_table_part(cursor, part_loc);
        }

        cursor->row = (row_head_t *)record_info->record;
        dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
        ret = ctc_copy_cursor_row(knl_session, cursor, NULL, cursor->row, &cursor->row->size);
        if (ret != CT_SUCCESS) {
            CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
            break;
        }

        serial_t serial = { 0, false };
        if (flag.auto_inc_used) {
            cm_assert(entity->has_serial_col);
            if (ctc_update_serial_col(knl_session, cursor, serial_column_offset, flag, &serial, last_insert_id) !=
                CT_SUCCESS) {
                CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
                ret = ctc_get_and_reset_err();
                break;
            }
        }

        ret = insert_and_verify_for_write_row(knl_session, cursor, &serial, *last_insert_id, ctc_context, flag);
        CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
    } while (0);

    if (flag.write_through) {
        knl_end_auton_rm(session, ret);
    }
    END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_WRITE_ROW);
    return ret;
}

int ctc_check_update_constraint(knl_session_t *knl_session, knl_cursor_t *cursor, uint64_t conflicts, dml_flag_t flag,
                                bool *need_rollback)
{
    int ret = CT_SUCCESS;
    status_t status = CT_SUCCESS;
    do {
        if (!flag.no_foreign_key_check) {
            cursor->no_cascade_check = flag.no_cascade_check;
            status = knl_verify_children_dependency(knl_session, cursor, CT_TRUE, 0, flag.dd_update);
            if (status != CT_SUCCESS) {
                ret = ctc_get_and_reset_err();
                CT_LOG_RUN_ERR("ctc_check_update_constraint failed to knl_verify_children_dependency with ret %d", ret);
                if ((flag.ignore || (!flag.no_cascade_check)) && ret == ERR_ROW_IS_REFERENCED) {
                    break;
                }
                return ret;
            }
        }

        status = knl_verify_ref_integrities(knl_session, cursor);
        if (status != CT_SUCCESS) {
            ret = ctc_get_and_reset_err();
            CT_LOG_RUN_ERR("ctc_check_update_constraint failed to knl_verify_ref_integrities with ret %d", ret);
            if ((flag.ignore) && !((flag.no_foreign_key_check) && ret == ERR_CONSTRAINT_VIOLATED_NO_FOUND)) {
                break;
            }
            return ret;
        }

        status = knl_check_index_conflicts(knl_session, conflicts);
        if (status != CT_SUCCESS) {
            ret = ctc_get_and_reset_err();
            CT_LOG_RUN_ERR("raw_ctc_update_row violates index constraints, ret %d", ret);
            break;
        }
    } while (0);

    if (ret != CT_SUCCESS && (flag.ignore || !flag.no_cascade_check)) {
        *need_rollback = true;
    }

    return ret;
}

int raw_ctc_update_row(knl_session_t *knl_session, knl_cursor_t *cursor, uint64_t conflicts, dml_flag_t flag)
{
    int ret = CT_SUCCESS;

    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;

    serial_t serial;
    serial.max_serial_col_value = 0;
    serial.is_uint64 = false;
    if (entity->has_serial_col) {
        ctc_update_get_serial_col_value(entity, knl_session, cursor, &serial);
    }

    knl_savepoint_t savepoint;
    if (flag.ignore || !flag.no_cascade_check) {
        knl_savepoint(knl_session, &savepoint);
    }
    cursor->no_logic_logging = flag.no_logging;
    if (knl_update(knl_session, cursor) != CT_SUCCESS) {
        CT_LOG_RUN_ERR_LIMIT(LOG_PRINT_INTERVAL_SECOND_20, "raw_ctc_update_row: knl_update FAIL");
        ret = ctc_get_and_reset_err();
        return ret;
    }

    bool need_rollback = false;
    ret = ctc_check_update_constraint(knl_session, cursor, conflicts, flag, &need_rollback);
    if (ret != CT_SUCCESS) {
        if (need_rollback) {
            knl_rollback(knl_session, &savepoint);
        }
        if (flag.no_foreign_key_check && ret == ERR_CONSTRAINT_VIOLATED_NO_FOUND) {
            goto not_ret;
        }
        return ret;
    }
not_ret:
    if (entity->has_serial_col && serial.max_serial_col_value > 0 && !flag.dd_update) {
        if (knl_update_serial_value_4mysql(knl_session, cursor->dc_entity, serial.max_serial_col_value,
                                           serial.is_uint64) != CT_SUCCESS) {
            ret = ctc_get_and_reset_err();
            CT_LOG_RUN_ERR("raw_ctc_update_row failed to set serial column value with ret %d, max_serial_col_value:%lld",
                           ret, serial.max_serial_col_value);
            if (ret != CT_SUCCESS && flag.ignore) {
                knl_rollback(knl_session, &savepoint);
            }
        }
    }

    return ret;
}

int ctc_open_cursor_and_fetch_by_rowid(knl_session_t *knl_session, knl_cursor_t *cursor, ctc_context_t *ctc_context,
                                       bool32 *isFound, bool is_select)
{
    int ret = CT_SUCCESS;
    if (ctc_open_cursor(knl_session, cursor, ctc_context, NULL, is_select) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_update_row: ctc_open_cursor failed");
        ret = ctc_get_and_reset_err();
        return ret;
    }

    cursor->rowid = ctc_context->conflict_rid;
    if (knl_fetch_by_rowid(knl_session, cursor, isFound) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_update_row: knl_fetch_by_rowid FAIL");
        ret = ctc_get_and_reset_err();
        return ret;
    }

    return ret;
}

EXTER_ATTACK int ctc_update_row(ctc_handler_t *tch, uint16_t new_record_len, const uint8_t *new_record,
                                const uint16_t *upd_cols, uint16_t col_num, dml_flag_t flag)
{
    INIT_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_UPDATE_ROW);
    BEGIN_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_UPDATE_ROW);
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");
    CTC_LOG_RET_NOT_SUPPORT(tch->read_only_in_ct, "update", ERR_OPERATIONS_NOT_SUPPORT);
    cm_reset_error();

    int ret = CT_SUCCESS;
    uint64_t conflicts;
    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    knl_init_index_conflicts(knl_session, (uint64 *)&conflicts);
    CM_SAVE_STACK(knl_session->stack);
    if (!(flag.dup_update)) {
        CT_LOG_DEBUG_INF("ctc_update_row: tbl=%s, thd_id=%u", ctc_context->table.str, tch->thd_id);
        ctc_fill_update_info(&cursor->update_info, new_record_len, new_record, upd_cols, col_num);
        ret = raw_ctc_update_row(knl_session, cursor, conflicts, flag);
    } else {
        // for on duplicate key update
        cursor = ctc_push_cursor(knl_session);
        if (NULL == cursor) {
            CT_LOG_RUN_ERR("ctc_update_row: ctc_push_cursor FAIL");
            CTC_POP_CURSOR(knl_session);
            END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_UPDATE_ROW);
            return ERR_GENERIC_INTERNAL_ERROR;
        }
        CT_LOG_DEBUG_INF("ctc_update_row: tbl=%s, thd_id=%u", ctc_context->table.str, tch->thd_id);
        do {
            cursor->scan_mode = SCAN_MODE_ROWID;
            cursor->action = CURSOR_ACTION_UPDATE;
            cursor->vnc_column = NULL;
            bool32 isFound = CT_FALSE;

            ret = ctc_open_cursor_and_fetch_by_rowid(knl_session, cursor, ctc_context, &isFound, false);
            CT_BREAK_IF_TRUE(ret != CT_SUCCESS);

            ctc_fill_update_info(&cursor->update_info, new_record_len, new_record, upd_cols, col_num);
            cursor->disable_pk_update = CT_TRUE;
            ret = raw_ctc_update_row(knl_session, cursor, conflicts, flag);
            CT_BREAK_IF_TRUE(ret != ERR_DUPLICATE_KEY || !flag.is_replace);

            ROWID_COPY(ctc_context->conflict_rid, cursor->conflict_rid);
        } while (CT_TRUE);
    }
    if (ret == ERR_DUPLICATE_KEY) {
        ctc_context->dup_key_slot = cursor->conflict_idx_slot;
    }
    CTC_POP_CURSOR(knl_session);
    ctc_close_cursor(knl_session, cursor);
    END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_UPDATE_ROW);
    return ret;
}

int delete_and_check_constraint(knl_session_t *knl_session, knl_cursor_t *cursor, dml_flag_t flag)
{
    knl_savepoint_t savepoint;
    if (flag.ignore || !flag.no_cascade_check) {
        knl_savepoint(knl_session, &savepoint);
    }

    int ret = CT_SUCCESS;
    cursor->action = CURSOR_ACTION_DELETE;
    cursor->no_logic_logging = flag.no_logging;
    if (knl_delete(knl_session, cursor) != CT_SUCCESS) {
        ret = ctc_get_and_reset_err();
        CT_LOG_RUN_ERR_LIMIT(LOG_PRINT_INTERVAL_SECOND_20, "ctc_delete_row: knl_delete FAIL. ret:%d", ret);
        return ret;
    }

    if (!flag.no_foreign_key_check) {
        cursor->no_cascade_check = flag.no_cascade_check;
        if (knl_verify_children_dependency(knl_session, cursor, false, 0, flag.dd_update) != CT_SUCCESS) {
            ret = ctc_get_and_reset_err();
            CT_LOG_RUN_ERR("ctc_delete_row: knl_verify_children_dependency FAIL. ret:%d.", ret);
            if ((flag.ignore || (!flag.no_cascade_check)) && ret == ERR_ROW_IS_REFERENCED) {
                knl_rollback(knl_session, &savepoint);
                return ret;
            }
        }
    }
    return ret;
}

EXTER_ATTACK int ctc_delete_row(ctc_handler_t *tch, uint16_t record_len, dml_flag_t flag)
{
    INIT_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_DELETE_ROW);
    BEGIN_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_DELETE_ROW);
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");
    CTC_LOG_RET_NOT_SUPPORT(tch->read_only_in_ct, "delete", ERR_OPERATIONS_NOT_SUPPORT);
    int ret = CT_SUCCESS;
    cm_reset_error();

    if (!(flag.is_replace)) {
        knl_cursor_t *prev_cursor = (knl_cursor_t *)tch->cursor_addr;
        bool valid_rowid = IS_INVALID_ROWID(ctc_context->conflict_rid);
        if (tch->cursor_addr == INVALID_VALUE64 || tch->cursor_addr == 0) {
            CT_LOG_RUN_ERR("ctc_delete_row: ctc_push_cursor FAIL, sql_command:%u, table: %s.%s, "
                           "cursor_addr:%u, rowid:%u",
                           tch->sql_command, ctc_context->user.str, ctc_context->table.str, tch->cursor_addr,
                           valid_rowid);
            END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_DELETE_ROW);
            return ERR_GENERIC_INTERNAL_ERROR;
        }
        CT_LOG_DEBUG_INF("ctc_delete_row: tbl=%s, thd_id=%u", ctc_context->table.str, tch->thd_id);
        END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_DELETE_ROW);
        return delete_and_check_constraint(knl_session, prev_cursor, flag);
    }

    // for replace into
    CM_SAVE_STACK(knl_session->stack);
    knl_cursor_t *cursor = ctc_push_cursor(knl_session);
    if (NULL == cursor) {
        CT_LOG_RUN_ERR("ctc_delete_row: ctc_push_cursor FAIL");
        CTC_POP_CURSOR(knl_session);
        END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_DELETE_ROW);
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    CT_LOG_DEBUG_INF("ctc_delete_row:(replace) tbl=%s, thd_id=%u", ctc_context->table.str, tch->thd_id);
    cursor->scan_mode = SCAN_MODE_ROWID;
    cursor->action = CURSOR_ACTION_DELETE;

    bool32 isFound = CT_FALSE;
    ret = ctc_open_cursor_and_fetch_by_rowid(knl_session, cursor, ctc_context, &isFound, false);
    if (ret != CT_SUCCESS) {
        CTC_POP_CURSOR(knl_session);
        ctc_close_cursor(knl_session, cursor);
        END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_DELETE_ROW);
        return ret;
    }

    if (isFound) {
        ret = delete_and_check_constraint(knl_session, cursor, flag);
    }
    ctc_close_cursor(knl_session, cursor);
    CTC_POP_CURSOR(knl_session);
    END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_DELETE_ROW);
    return ret;
}

int ctc_set_cursor_action(knl_cursor_t *cursor, expected_cursor_action_t action)
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
            CT_LOG_RUN_ERR("unsupport action %d", action);
            return ERR_GENERIC_INTERNAL_ERROR;
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_rnd_init(ctc_handler_t *tch, expected_cursor_action_t action, ctc_select_mode_t mode,
                              ctc_conds *cond)
{
    INIT_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_RND_INIT);
    BEGIN_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_RND_INIT);
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_cursor_t *cursor = ctc_alloc_session_cursor(session, tch->part_id, tch->subpart_id);
    if (cursor == NULL) {
        CT_LOG_RUN_ERR("ctc_rnd_init: ctc_alloc_session_cursor FAIL");
        END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_RND_INIT);
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    tch->cursor_addr = (uint64_t)cursor;
    tch->cursor_valid = true;
    tch->change_data_capture = LOGIC_REP_DB_ENABLED(&session->knl_session);
    CT_LOG_DEBUG_INF("ctc_rnd_init: tbl=%s, thd_id=%u", ctc_context->table.str, tch->thd_id);

    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->cond = cond;
    CT_RETURN_IFERR(ctc_set_cursor_action(cursor, action));
    if (mode == SELECT_SKIP_LOCKED) {
        cursor->rowmark.type = ROWMARK_SKIP_LOCKED;
    } else if (mode == SELECT_NOWAIT) {
        cursor->rowmark.type = ROWMARK_NOWAIT;
    }

    bool is_select = ctc_command_type_read(tch->sql_command);
    if (ctc_open_cursor(&session->knl_session, cursor, ctc_context, &tch->sql_stat_start, is_select) != CT_SUCCESS) {
        int ret = ctc_get_and_reset_err();
        CT_LOG_RUN_ERR("ctc_rnd_init: ctc_open_cursor failed, ret = %d", ret);
        ctc_free_handler_cursor(session, tch);
        END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_RND_INIT);
        return ret;
    }
    END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_RND_INIT);
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_rnd_end(ctc_handler_t *tch)
{
    INIT_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_RND_END);
    BEGIN_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_RND_END);
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");

    if (tch->cursor_addr != INVALID_VALUE64) {
        ctc_free_handler_cursor(session, tch);
    }
    END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_RND_END);
    return CT_SUCCESS;
}

static void ctc_fetch_cursor_rowid_pos_value(knl_session_t *knl_session, knl_cursor_t *cursor)
{
    cursor->rowid.file = cursor->rowid_pos.file;
    cursor->rowid.page = cursor->rowid_pos.page;
    cursor->rowid.vmid = cursor->rowid_pos.vmid;
    cursor->rowid.vm_slot = cursor->rowid_pos.vm_slot;
    cursor->ssn = knl_session->ssn;
}

int ctc_fetch_and_filter(knl_cursor_t *cursor, knl_session_t *knl_session, record_info_t *record_info, bool copy_data)
{
    int ret = CT_SUCCESS;
    uint32 charset_id = knl_session->kernel->db.charset_id;
    while (!cursor->eof) {
        if (knl_fetch(knl_session, cursor) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("ctc_fetch_and_filter: knl_fetch FAIL");
            return ctc_get_and_reset_err();
        }
        if (cursor->eof) {
            break;
        }
        cond_pushdown_result_t cond_result = check_cond_match_one_line((ctc_conds *)cursor->cond, cursor, charset_id);
        if (cond_result == CPR_ERROR) {
            CT_LOG_RUN_ERR("ctc_fetch_and_filter: check_cond_match_one_line FAIL");
            return CT_ERROR;
        } else if (cond_result == CPR_FALSE) {
            continue;
        } else {
            ret = ctc_copy_cursor_row_read(knl_session, cursor, record_info, copy_data);
            if (ret != CT_SUCCESS) {
                CT_LOG_RUN_ERR("ctc_fetch_and_filter: ctc_copy_cursor_row_read FAIL");
                return ret;
            }
            break;
        }
    }
    return ret;
}

EXTER_ATTACK int ctc_rnd_next(ctc_handler_t *tch, record_info_t *record_info)
{
    INIT_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_RND_NEXT);
    BEGIN_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_RND_NEXT);
    int ret = CT_SUCCESS;
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    CT_LOG_DEBUG_INF("ctc_rnd_next: tbl=%s, thd_id=%u", ctc_context->table.str, tch->thd_id);

    if (cursor->dc_type == DICT_TYPE_TEMP_TABLE_SESSION && cursor->ssn < knl_session->ssn) {
        knl_inc_session_ssn(knl_session);
        cursor->ssn = knl_session->ssn;
    }
    ret = ctc_fetch_and_filter(cursor, knl_session, record_info, !g_is_single_run_mode);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_rnd_next: ctc_fetch_and_filter FAIL");
        ctc_free_handler_cursor(session, tch);
        END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_RND_NEXT);
        return ret;
    }
    END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_RND_NEXT);
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_scan_records(ctc_handler_t *tch, uint64_t *num_rows, char *index_name)
{
    uint64_t rows = 0;
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_session_t *knl_session = &session->knl_session;
    CM_SAVE_STACK(knl_session->stack);
    knl_cursor_t *cursor = ctc_push_cursor(knl_session);
    if (NULL == cursor) {
        CT_LOG_RUN_ERR("ctc_scan_records: ctc_push_cursor FAIL");
        CTC_POP_CURSOR(knl_session);
        return ERR_GENERIC_INTERNAL_ERROR;
    }

    CT_RETURN_IFERR(ctc_try_reopen_dc(knl_session, &ctc_context->user, &ctc_context->table, ctc_context->dc));
    knl_dictionary_t *dc = ctc_context->dc;

    uint16_t active_index = MAX_INDEXES;
    ctc_get_index_from_name(dc, index_name, &active_index);

    ctc_pre_set_cursor_for_scan(DC_TABLE(dc)->index_set.total_count, cursor, active_index);

    if (IS_CTC_PART(tch->part_id)) {
        cursor->part_loc.part_no = tch->part_id;
        cursor->part_loc.subpart_no = tch->subpart_id;
    }

    bool is_select = ctc_command_type_read(tch->sql_command);
    if (ctc_open_cursor(knl_session, cursor, ctc_context, &tch->sql_stat_start, is_select) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_scan_records: ctc_open_cursor failed");
        CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
        return ctc_get_and_reset_err();
    }

    int ret = ctc_count_rows(session, dc, knl_session, cursor, &rows);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_scan_records: ctc_count_all_rows failed");
        CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
        return ret;
    }
    *num_rows = rows;

    CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
    return CT_SUCCESS;
}

int ctc_rnd_prefetch(ctc_handler_t *tch, uint8_t *records, uint16_t *record_lens, uint32_t *recNum, uint64_t *rowids,
                     int32_t max_row_size)
{
    int ret = CT_SUCCESS;
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    *recNum = 0;
    CT_LOG_DEBUG_INF("ctc_rnd_prefetch: tbl=%s, thd_id=%u", ctc_context->table.str, tch->thd_id);

    if (cursor->dc_type == DICT_TYPE_TEMP_TABLE_SESSION && cursor->ssn < knl_session->ssn) {
        knl_inc_session_ssn(knl_session);
        cursor->ssn = knl_session->ssn;
    }

    uint32_t record_buf_left_lens = MAX_RECORD_SIZE;
    for (uint32_t i = 0; i < CTC_MAX_PREFETCH_NUM && record_buf_left_lens >= max_row_size; i++) {
        record_info_t record_info = { records, 0, NULL, NULL };
        ret = ctc_fetch_and_filter(cursor, knl_session, &record_info, true);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("ctc_rnd_prefetch: ctc_fetch_and_filter FAIL");
            ctc_free_handler_cursor(session, tch);
            return ret;
        }
        if (cursor->eof) {
            record_lens[i] = 0;
            break;
        }
        record_lens[i] = ((row_head_t *)records)->size;
        rowids[i] = cursor->rowid.value;
        records += record_lens[i];
        *recNum += 1;
        record_buf_left_lens -= record_lens[i];
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_position(ctc_handler_t *tch, uint8_t *position, uint16_t pos_length)
{
    INIT_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_POSITION);
    BEGIN_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_POSITION);
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    CT_LOG_DEBUG_INF("ctc_position: tbl=%s, thd_id=%u", ctc_context->table.str, tch->thd_id);

    rowid_t rowid = cursor->rowid;
    errno_t errcode = memcpy_s(position, pos_length, &rowid, sizeof(rowid));
    if (errcode != EOK) {
        END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_POSITION);
        return CT_ERROR;
    }
    END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_POSITION);
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_rnd_pos(ctc_handler_t *tch, uint16_t pos_length, uint8_t *position, record_info_t *record_info)
{
    INIT_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_RND_POS);
    BEGIN_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_RND_POS);
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    CT_LOG_DEBUG_INF("ctc_rnd_pos: tbl=%s, thd_id=%u", ctc_context->table.str, tch->thd_id);

    cursor->scan_mode = SCAN_MODE_ROWID;
    cursor->rowid = *((rowid_t *)position);

    if (((table_t *)cursor->table)->desc.type == TABLE_TYPE_SESSION_TEMP &&
        cursor->rowid.vmid >= knl_session->temp_mtrl->pool->ctrl_hwm) {
        ctc_fetch_cursor_rowid_pos_value(knl_session, cursor);
    }

    if (IS_CTC_PART(tch->part_id)) {
        knl_part_locate_t part_loc = { .part_no = tch->part_id, .subpart_no = tch->subpart_id };
        knl_set_table_part(cursor, part_loc);
    }

    bool32 isFound = CT_FALSE;
    if (knl_fetch_by_rowid(knl_session, cursor, &isFound) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_rnd_pos fetch failed");
        ctc_free_handler_cursor(session, tch);
        END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_RND_POS);
        return ctc_get_and_reset_err();
    }

    if (!cursor->eof) {
        int ret = CT_SUCCESS;
        ret = ctc_copy_cursor_row_read(knl_session, cursor, record_info, !g_is_single_run_mode);
        if (ret != CT_SUCCESS) {
            ctc_free_handler_cursor(session, tch);
            END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_RND_POS);
            return ret;
        }
    } else {
        record_info->record_len = 0;
    }
    END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_RND_POS);
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_delete_all_rows(ctc_handler_t *tch, dml_flag_t flag)
{
    INIT_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_DELETE_ALL_ROWS);
    BEGIN_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_DELETE_ALL_ROWS);
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");
    if (!ctc_alloc_stmt_context(session)) {
        END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_DELETE_ALL_ROWS);
        return CT_ERROR;
    }
    int ret = CT_SUCCESS;
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = &session->knl_session;

    CM_SAVE_STACK(knl_session->stack);
    cursor = ctc_push_cursor(knl_session);
    if (NULL == cursor) {
        CT_LOG_RUN_ERR("ctc_delete_all_rows: ctc_push_cursor FAIL");
        CTC_POP_CURSOR(knl_session);
        END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_DELETE_ALL_ROWS);
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    CT_LOG_DEBUG_INF("ctc_delete_all_rows: tbl=%s, thd_id=%u", ctc_context->table.str, tch->thd_id);

    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->action = CURSOR_ACTION_DELETE;
    if (ctc_open_cursor(knl_session, cursor, ctc_context, &tch->sql_stat_start, false) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_delete_all_rows: ctc_open_cursor failed");
        CTC_POP_CURSOR(knl_session);
        ctc_close_cursor(knl_session, cursor);
        END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_DELETE_ALL_ROWS);
        return ctc_get_and_reset_err();
    }
    if (fetch_and_delete_all_rows(knl_session, cursor, flag) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_delete_all_rows: fetch_and_delete_all_rows failed");
        ret = ctc_get_and_reset_err();
    }
    CTC_POP_CURSOR(knl_session);
    ctc_close_cursor(knl_session, cursor);
    END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_DELETE_ALL_ROWS);
    return ret;
}

static int ctc_index_init(session_t *session, ctc_context_t *ctc_context, ctc_handler_t *tch, uint16_t index,
                          bool sorted, expected_cursor_action_t action, ctc_select_mode_t mode, ctc_conds *cond,
                          const bool is_replace)
{
    knl_session_t *knl_session = &session->knl_session;
    if (is_replace && tch->sql_stat_start == 0) {
        knl_inc_session_ssn(knl_session);
    }
    knl_cursor_t *cursor = ctc_alloc_session_cursor(session, tch->part_id, tch->subpart_id);
    CTC_LOG_RET_VAL_IF_NUL(cursor, ERR_GENERIC_INTERNAL_ERROR, "ctc_alloc_session_cursor FAIL");

    tch->cursor_addr = (uint64_t)cursor;
    tch->cursor_valid = true;
    tch->change_data_capture = LOGIC_REP_DB_ENABLED(knl_session);
    CT_LOG_DEBUG_INF("ctc_index_init: tbl=%s, thd_id=%u", ctc_context->table.str, tch->thd_id);

    CT_RETURN_IFERR(ctc_set_cursor_action(cursor, action));
    cursor->scan_mode = SCAN_MODE_INDEX;
    cursor->index_slot = index;
    cursor->cond = cond;
    if (action == EXP_CURSOR_ACTION_INDEX_ONLY) {
        cursor->index_only = CT_TRUE;
        cursor->index_ffs = !sorted;
    }
    if (mode == SELECT_SKIP_LOCKED) {
        cursor->rowmark.type = ROWMARK_SKIP_LOCKED;
    } else if (mode == SELECT_NOWAIT) {
        cursor->rowmark.type = ROWMARK_NOWAIT;
    }

    bool is_select = ctc_command_type_read(tch->sql_command);
    if (ctc_open_cursor(knl_session, cursor, ctc_context, &tch->sql_stat_start, is_select) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_index_init: ctc_open_cursor failed");
        ctc_free_handler_cursor(session, tch);
        return ctc_get_and_reset_err();
    }

    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_index_end(ctc_handler_t *tch)
{
    INIT_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_INDEX_END);
    BEGIN_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_INDEX_END);
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");

    CT_LOG_DEBUG_INF("ctc_index_end: tbl=%s, thd_id=%u", ctc_context->table.str, tch->thd_id);
    if (tch->cursor_addr != INVALID_VALUE64) {
        ctc_free_handler_cursor(session, tch);
    }
    END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_INDEX_END);
    return CT_SUCCESS;
}

int ctc_check_partition_status(ctc_handler_t *tch, knl_cursor_t **cursor, index_key_info_t *index_key_info,
                               ctc_select_mode_t mode)
{
    int ret;
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");

    if (!index_key_info->sorted) {
        (*cursor)->part_loc.part_no = tch->part_id;
        (*cursor)->part_loc.subpart_no = tch->subpart_id;
        ret = knl_reopen_cursor(knl_session, *cursor, ctc_context->dc);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("ctc_index_read: reopen cursor failed");
            return ret;
        }
        knl_part_locate_t part_loc = { .part_no = tch->part_id, .subpart_no = tch->subpart_id };
        knl_set_table_part(*cursor, part_loc);
    } else {
        // alloc new cursor for new part
        ret = ctc_index_init(session, ctc_context, tch, index_key_info->active_index, index_key_info->sorted,
                             index_key_info->action, mode, (*cursor)->cond, false);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("ctc_index_read: alloc new cursor for part %d failed", tch->part_id);
            return ret;
        }
        *cursor = (knl_cursor_t *)tch->cursor_addr;
        index_key_info->need_init = true;
    }

    return ret;
}

bool is_fetched_the_same_key(knl_cursor_t *cursor, const index_key_info_t *index_key_info, int column_id,
                             knl_index_desc_t *desc, bool *has_fetched_null)
{
    if (desc->is_func && (index_key_info->key_info[column_id].left_key_len == 0 ||
                          index_key_info->key_info[column_id].right_key_len == 0)) {
        return false;
    }
    int col_offset = cursor->index_only ? column_id : desc->columns[column_id];
    if (index_key_info->key_info[column_id].is_key_null) {
        if (cursor->index_only) {
            if (cursor->lens[col_offset] == CT_NULL_VALUE_LEN) {
                *has_fetched_null = CT_TRUE;
                return true;
            }
        } else {
            uint8 bits = row_get_column_bits2(cursor->row, col_offset);
            if (bits == COL_BITS_NULL) {
                *has_fetched_null = CT_TRUE;
                return true;
            }
        }
    }

    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    knl_column_t *column = dc_get_column(entity, desc->columns[column_id]);
    cm_assert(column != NULL);
    void *col_val = (void *)cursor->row + cursor->offsets[col_offset];
    void *key_val = (void *)index_key_info->key_info[column_id].left_key;
    uint16 left_key_len = (uint16)index_key_info->key_info[column_id].left_key_len;
    int32 cmp_res = var_compare_data_ex(col_val, left_key_len, key_val, left_key_len, column->datatype,
                                        column->collate_id);
    // 先判断数据长度是否相等，再将取出来的值与key作memcmp，如果值相等则返回true
    if (!(cursor->lens[col_offset] == 0 || cursor->lens[col_offset] != left_key_len || cmp_res != 0)) {
        return true;
    }

    return false;
}

bool is_need_one_more_fetch(knl_cursor_t *cursor, const index_key_info_t *index_key_info, uint16_t find_flag,
                            bool *has_fetched_null)
{
    if (index_key_info->key_num == 0) {  // 不带where子句
        return false;
    }

    if (find_flag != CTC_HA_READ_BEFORE_KEY && find_flag != CTC_HA_READ_AFTER_KEY) {
        return false;
    }

    index_t *cursor_index = (index_t *)cursor->index;
    knl_index_desc_t *desc = INDEX_DESC(cursor_index);

    int iter_end_id = index_key_info->index_skip_scan ? 0 : index_key_info->key_num - 1;
    for (int column_id = index_key_info->key_num - 1; column_id >= iter_end_id; column_id--) {
        if (!is_fetched_the_same_key(cursor, index_key_info, column_id, desc, has_fetched_null)) {
            return false;
        }
    }

    return true;
}

static int ctc_get_correct_pos(ctc_handler_t *tch, session_t *session, knl_cursor_t *cursor,
                               const index_key_info_t *index_key_info)
{
    int ret = CT_SUCCESS;
    knl_session_t *knl_session = &session->knl_session;
    if (knl_fetch(knl_session, cursor) != CT_SUCCESS) {
        CTC_HANDLE_KNL_FETCH_FAIL_LIMIT(session, tch);
    }
    if (cursor->eof) {
        return ret;
    }
    bool has_fetched_null = CT_FALSE;
    while (is_need_one_more_fetch(cursor, index_key_info, index_key_info->find_flag, &has_fetched_null)) {
        if (knl_fetch(knl_session, cursor) != CT_SUCCESS) {
            CTC_HANDLE_KNL_FETCH_FAIL_LIMIT(session, tch);
        }
        if (cursor->eof) {
            if (has_fetched_null) {
                break;
            } else {
                return ret;
            }
        }
    }
    return ret;
}

int get_correct_pos_by_fetch(ctc_handler_t *tch, knl_cursor_t *cursor, record_info_t *record_info,
                             const index_key_info_t *index_key_info)
{
    int ret = CT_SUCCESS;
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    knl_session_t *knl_session = &session->knl_session;
    uint32 charset_id = knl_session->kernel->db.charset_id;
    while (!cursor->eof) {
        ret = ctc_get_correct_pos(tch, session, cursor, index_key_info);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("get_correct_pos_by_fetch: ctc_fetch_correct_pos FAIL");
            return ret;
        }
        if (cursor->eof) {
            record_info->record_len = 0;
            return ret;
        }
        cond_pushdown_result_t cond_result = check_cond_match_one_line((ctc_conds *)cursor->cond, cursor, charset_id);
        if (cond_result == CPR_ERROR) {
            CT_LOG_RUN_ERR("get_correct_pos_by_fetch: check_cond_match_one_line FAIL");
            return CT_ERROR;
        } else if (cond_result == CPR_FALSE) {
            continue;
        } else {
            ret = ctc_copy_cursor_row_read(knl_session, cursor, record_info, !g_is_single_run_mode);
            if (ret != CT_SUCCESS) {
                CT_LOG_RUN_ERR("get_correct_pos_by_fetch: ctc_copy_cursor_row_read FAIL");
                ctc_free_handler_cursor(session, tch);
                return ret;
            }
            if (cursor->index_only) {
                ret = ctc_index_only_row_fill_bitmap(cursor, record_info->record);
                record_info->record_len = ((row_head_t *)record_info->record)->size;
            }
            break;
        }
    }
    return ret;
}

int ctc_check_partition_changed(knl_cursor_t *cursor, ctc_handler_t *tch)
{
    if (IS_CTC_PART(cursor->part_loc.part_no) && IS_CTC_PART(tch->part_id) &&
        cursor->part_loc.part_no != tch->part_id) {
        return CT_TRUE;
    } else if (IS_CTC_PART(cursor->part_loc.subpart_no) && IS_CTC_PART(tch->subpart_id) &&
               cursor->part_loc.subpart_no != tch->subpart_id) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

EXTER_ATTACK int ctc_index_read(ctc_handler_t *tch, record_info_t *record_info, index_key_info_t *index_info,
                                ctc_select_mode_t mode, ctc_conds *cond, const bool is_replace)
{
    INIT_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_INDEX_READ);
    BEGIN_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_INDEX_READ);
    CM_ASSERT(index_info != NULL);

    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    if (tch->pre_sess_addr != 0) {
        session = (session_t *)tch->pre_sess_addr;
    } else {
        CT_RETURN_IFERR(ctc_get_or_new_session(&session, tch, true, false, &is_new_session));
    }
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_session_t *knl_session = &session->knl_session;
    CT_RETURN_IFERR(ctc_try_reopen_dc(knl_session, &ctc_context->user, &ctc_context->table, ctc_context->dc));
    knl_dictionary_t *dc = ctc_context->dc;
    ctc_get_index_from_name(dc, index_info->index_name, &index_info->active_index);
    if (index_info->active_index == MAX_INDEXES) {
        CT_LOG_RUN_ERR("ctc_get_index_from_name: ctc find index name '%s' failed!", index_info->index_name);
        END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_INDEX_READ);
        return CT_ERROR;
    }

    if (index_info->need_init) {
        CT_RETURN_IFERR(ctc_index_init(session, ctc_context, tch, index_info->active_index, index_info->sorted,
                                       index_info->action, mode, cond, is_replace));
    }
    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;

    // check if partition changed during index scan
    if (ctc_check_partition_changed(cursor, tch)) {
        CT_RETURN_IFERR(ctc_check_partition_status(tch, &cursor, index_info, mode));
    }

    if (!index_info->need_init) {  // no alloc cursor
        knl_inc_session_ssn(knl_session);
        cursor->ssn = knl_session->ssn;
        cursor->scan_range.is_equal = CT_FALSE;
    }

    CT_LOG_DEBUG_INF("ctc_index_read: tbl=%s, thd_id=%u", ctc_context->table.str, tch->thd_id);

    CT_RETURN_IFERR(ctc_get_index_info_and_set_scan_key(cursor, index_info));

    int ret = get_correct_pos_by_fetch(tch, cursor, record_info, index_info);
    if (ret != CT_SUCCESS) {
        END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_INDEX_READ);
        return ret;
    }
    END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_INDEX_READ);
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_pq_index_read(ctc_handler_t *tch, record_info_t *record_info, index_key_info_t *index_info,
                                   ctc_scan_range_t scan_range, ctc_select_mode_t mode, ctc_conds *cond,
                                   const bool is_replace, uint64_t query_scn)
{
    CM_ASSERT(index_info != NULL);

    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    if (tch->pre_sess_addr != 0) {
        session = (session_t *)tch->pre_sess_addr;
    } else {
        CT_RETURN_IFERR(ctc_get_or_new_session(&session, tch, true, false, &is_new_session));
    }
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_session_t *knl_session = &session->knl_session;
    CT_RETURN_IFERR(ctc_try_reopen_dc(knl_session, &ctc_context->user, &ctc_context->table, ctc_context->dc));
    knl_dictionary_t *dc = ctc_context->dc;
    ctc_get_index_from_name(dc, index_info->index_name, &index_info->active_index);
    if (index_info->active_index == MAX_INDEXES) {
        CT_LOG_RUN_ERR("ctc_get_index_from_name: ctc find index name '%s' failed!", index_info->index_name);
        return CT_ERROR;
    }

    if (index_info->need_init) {
        CT_RETURN_IFERR(ctc_index_init(session, ctc_context, tch, index_info->active_index, index_info->sorted,
                                       index_info->action, mode, cond, is_replace));
    }
    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;

    // no need to check partition status as mysql side will prevent partitioned table reach this endpiont
    // keep this part of code just in case
    if (ctc_check_partition_changed(cursor, tch)) {
        CT_RETURN_IFERR(ctc_check_partition_status(tch, &cursor, index_info, mode));
    }

    if (!index_info->need_init) {  // no alloc cursor
        knl_inc_session_ssn(knl_session);
        cursor->ssn = knl_session->ssn;
        cursor->scan_range.is_equal = CT_FALSE;
    }

    CT_LOG_DEBUG_INF("ctc_pq_index_read: tbl=%s, thd_id=%u", ctc_context->table.str, tch->thd_id);

    CT_RETURN_IFERR(ctc_pq_set_scan_key(cursor, scan_range, index_info));
    cursor->query_scn = query_scn;

    int ret = get_correct_pos_by_fetch(tch, cursor, record_info, index_info);
    if (ret != CT_SUCCESS) {
        return ret;
    }

    return CT_SUCCESS;
}

// expecting mysql side should have called ctc_rnd_init before this.
// so the routine to get handle and cursor should be same as ctc_rnd_next
// set up the range of cursor with knl_set_table_scan_range
// void knl_set_table_scan_range(knl_handle_t handle, knl_cursor_t *cursor, page_id_t left, page_id_t right);
EXTER_ATTACK int ctc_pq_set_cursor_range(ctc_handler_t *tch, ctc_page_id_t l_page, ctc_page_id_t r_page,
                                         uint64_t query_scn, uint64_t ssn)
{
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    CT_LOG_DEBUG_INF("ctc_pq_set_cursor_range: tbl=%s, thd_id=%u", ctc_context->table.str, tch->thd_id);
    cursor->query_scn = query_scn;
    knl_session->query_scn = query_scn;
    knl_session->ssn = ssn;

    if (cursor->dc_type == DICT_TYPE_TEMP_TABLE_SESSION && cursor->ssn < knl_session->ssn) {
        knl_inc_session_ssn(knl_session);
        cursor->ssn = knl_session->ssn;
    }
    page_id_t left = { .page = l_page.page, .file = l_page.file, .aligned = l_page.aligned };

    page_id_t right = { .page = r_page.page, .file = r_page.file, .aligned = r_page.aligned };
    knl_set_table_scan_range(knl_session, cursor, left, right);
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_trx_begin(ctc_handler_t *tch, ctc_trx_context_t trx_context, bool is_mysql_local)
{
    // it's possible calling START TRANSACTION before open_table, thus session can also be added to gmap in this intf
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    CT_RETURN_IFERR(ctc_get_or_new_session(&session, tch, true, false, &is_new_session));
    ctc_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    // mysql-server侧通过is_ctc_trx_begin标记，保证一个事务只会调用一次ctc_trx_begin，且调进来时参天侧事务未开启
    if (knl_session->rm->txn != NULL) {
        CT_LOG_DEBUG_INF("ctc_trx_begin: knl_session->rm->txn is not NULL, thd_id=%u, session_id=%u, "
                         "isolation level=%u, current_scn=%llu, rm_query_scn=%llu, lock_wait_timeout=%u, rmid=%u",
                         tch->thd_id, session->knl_session.id, trx_context.isolation_level, knl_session->kernel->scn,
                         knl_session->rm->query_scn, trx_context.lock_wait_timeout, knl_session->rmid);
        return CT_SUCCESS;
    }
    if (is_mysql_local && DB_IS_READONLY(knl_session)) {
        CT_LOG_RUN_INF("ctc_trx_begin: operation on read only mode while ctc_ddl_local_enabled is true.");
        return CT_SUCCESS;
    }
    bool is_select = (ctc_command_type_read(tch->sql_command) && !trx_context.use_exclusive_lock) ||
                     tch->sql_command == SQLCOM_END;
    if (is_select && !knl_db_is_primary(knl_session)) {
        CT_LOG_RUN_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_20,
                             "ctc_trx_begin: select operation on read only mode in slave node.");
        return CT_SUCCESS;
    }

    if (knl_set_session_trans(knl_session, (isolation_level_t)trx_context.isolation_level, is_select) != CT_SUCCESS) {
        int err = ctc_get_and_reset_err();
        CT_LOG_RUN_ERR("ctc_trx begin: knl_set_session_trans failed, thd_id=%u, err=%d", tch->thd_id, err);
        return err;
    }
    knl_session->lock_wait_timeout = trx_context.lock_wait_timeout;
    session->auto_commit = trx_context.autocommit;
    // 这里不再主动调用tx_begin，参天引擎在DML需要undo时会自动开启txn
    CT_LOG_DEBUG_INF("ctc_trx begin with thd_id=%u, session_id=%u, isolation level=%u, "
                     "current_scn=%llu, rm_query_scn=%llu, lock_wait_timeout=%u, rmid=%u",
                     tch->thd_id, session->knl_session.id, trx_context.isolation_level, knl_session->kernel->scn,
                     knl_session->rm->query_scn, trx_context.lock_wait_timeout, knl_session->rmid);
    return CT_SUCCESS;
}

int ctc_ddl_commit_log_put(knl_session_t *knl_session, knl_handle_t stmt, ctc_ddl_def_node_t *def_node,
                           ctc_ddl_dc_array_t *dc_node)
{
    status_t status = CT_SUCCESS;
    if (def_node == NULL) {
        dc_node = NULL;
        return status;
    }

    if (def_node->uid == CT_INVALID_INT32 || def_node->oid == CT_INVALID_INT32) {
        dc_node->dc.uid = CT_INVALID_INT32;
        dc_node->dc.oid = CT_INVALID_INT32;
        CT_LOG_RUN_ERR("ctc_ddl_commit_log_put failed, def_node->uid %u, oid %u", def_node->uid, def_node->oid);
        return CT_ERROR;
    }

    if (knl_open_dc_by_id(knl_session, def_node->uid, def_node->oid, &(dc_node->dc), CT_TRUE) != CT_SUCCESS) {
        dc_node->dc.uid = CT_INVALID_INT32;
        dc_node->dc.oid = CT_INVALID_INT32;
        CT_LOG_RUN_ERR("ctc_ddl_commit_log_put open dc failed for def_mode:%d", def_node->def_mode);
        return CT_ERROR;
    }

    switch (def_node->def_mode) {
        case DROP_DEF: {
            knl_drop_def_t *drop_def = (knl_drop_def_t *)def_node->ddl_def;
            knl_drop_table_log_put(knl_session, stmt, drop_def, &(dc_node->dc));
            break;
        }
        case ALTER_DEF: {
            knl_altable_def_t *alter_def = (knl_altable_def_t *)def_node->ddl_def;
            knl_alter_table_log_put(knl_session, stmt, &(dc_node->dc), CT_TRUE);
            break;
        }
        case RENAME_DEF: {
            knl_altable_def_t *rename_def = (knl_altable_def_t *)def_node->ddl_def;
            knl_rename_table_log_put(knl_session, stmt, &(dc_node->dc), rename_def, CT_TRUE);
            break;
        }
        case CREATE_DEF: {
            knl_table_def_t *create_def = (knl_table_def_t *)def_node->ddl_def;
            if (create_def->create_as_select || create_def->is_mysql_copy) {
                status = knl_delete_temp_table_record4mysql(knl_session, create_def);
            } else {
                status = knl_create_table_log_put4mysql(knl_session, stmt, create_def, &(dc_node->dc));
            }
            break;
        }
        case TRUNC_DEF: {
            knl_truncate_table_log_put(knl_session, stmt, &(dc_node->dc));
            break;
        }
        default:
            break;
    }
    dc_node->def_mode = def_node->def_mode;
    dc_node->ddl_def = def_node->ddl_def;

    return status;
}

void ctc_ddl_table_after_commit(knl_session_t *session, ctc_ddl_dc_array_t *dc_node)
{
    switch (dc_node->def_mode) {
        case ALTER_DEF:
        case RENAME_DEF: {
            knl_alter_table_after_commit4mysql(session, &(dc_node->dc));
            knl_close_dc(&(dc_node->dc));
            break;
        }
        case DROP_DEF: {
            knl_drop_def_t *drop_def = (knl_drop_def_t *)dc_node->ddl_def;
            knl_drop_table_after_commit4mysql(session, dc_node, drop_def);
            break;
        }
        case CREATE_DEF: {
            knl_close_dc(&(dc_node->dc));
            break;
        }
        case TRUNC_DEF: {
            knl_trunc_def_t *trunc_def = (knl_trunc_def_t *)dc_node->ddl_def;
            knl_truncate_table_after_commit(session, trunc_def, &(dc_node->dc));
            knl_close_dc(&(dc_node->dc));
            break;
        }
        default:
            break;
    }
    return;
}

void ctc_ddl_table_after_commit_list(bilist_t *def_list, ctc_ddl_dc_array_t *dc_array, knl_session_t *knl_session,
                                     bool *unlock_tables)
{
    for (uint32_t i = 0; i < def_list->count; i++) {
        ctc_ddl_dc_array_t *dc_node = &(dc_array[i]);
        ctc_ddl_table_after_commit(knl_session, dc_node);
        if (dc_node->def_mode == DROP_DEF) {
            *unlock_tables = CT_FALSE;
        }
    }
    for (uint32_t i = 0; i < def_list->count; i++) {
        ctc_ddl_dc_array_t *dc_node = &(dc_array[i]);
        if (dc_node->def_mode == DROP_DEF) {
            knl_free_entry_after_commit4mysql(knl_session, dc_node);
        }
    }
}

EXTER_ATTACK int ctc_trx_commit(ctc_handler_t *tch, uint64_t *cursors, int32_t csize, bool *is_ddl_commit)
{
    bool unlock_tables = CT_TRUE;
    *is_ddl_commit = CT_TRUE;

    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    ctc_free_cursors((tch->pre_sess_addr != 0) ? ((session_t *)tch->pre_sess_addr) : session, cursors, csize);

    sql_stmt_t *stmt = session->current_stmt;
    knl_session_t *knl_session = &session->knl_session;
    if (stmt == NULL) {
        *is_ddl_commit = CT_FALSE;
        knl_commit(knl_session);
        return CT_SUCCESS;
    }
    bilist_t *def_list = &stmt->ddl_def_list;
    if (stmt->ddl_def_list.head == NULL || ctc_is_def_list_empty(def_list)) {
        *is_ddl_commit = CT_FALSE;
        knl_commit(knl_session);
        ctc_ddl_clear_stmt(stmt);
        return CT_SUCCESS;
    }
    CM_SAVE_STACK(knl_session->stack);
    ctc_ddl_dc_array_t *dc_array = (ctc_ddl_dc_array_t *)cm_push(knl_session->stack,
                                                                 def_list->count * sizeof(ctc_ddl_dc_array_t));
    CTC_LOG_RET_VAL_IF_NUL(dc_array, CT_ERROR, "ctc_trx_commit: null dc_array ptr");

    uint32_t dc_index = 0;
    bilist_node_t *node = cm_bilist_head(def_list);
    for (; node != NULL; node = BINODE_NEXT(node)) {
        ctc_ddl_def_node_t *def_node = (ctc_ddl_def_node_t *)BILIST_NODE_OF(ctc_ddl_def_node_t, node, bilist_node);
        ctc_ddl_dc_array_t *dc_node = &(dc_array[dc_index]);
        if (ctc_ddl_commit_log_put(knl_session, stmt, def_node, dc_node) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("ctc_ddl_commit_log_put failed , start rollback!");
            CTC_POP_CURSOR(knl_session);
            ctc_trx_rollback(tch, cursors, csize);
            return CT_ERROR;
        }
        dc_index++;
    }

    knl_commit4mysql(knl_session);
    ctc_ddl_table_after_commit_list(def_list, dc_array, knl_session, &unlock_tables);
    ctc_ddl_unlock_table(knl_session, unlock_tables);

    if (DB_ATTR_MYSQL_META_IN_DACC(knl_session) || !(tch->sql_command == SQLCOM_DROP_TABLE && *is_ddl_commit)) {
        ctc_ddl_clear_stmt(stmt);
    }

    CTC_POP_CURSOR(knl_session);
    return CT_SUCCESS;
}

static void ctc_set_invalid_dc_node_id(ctc_ddl_dc_array_t *dc_node)
{
    dc_node->dc.uid = CT_INVALID_INT32;
    dc_node->dc.oid = CT_INVALID_INT32;
}

int ctc_ddl_rollback_update_dc(knl_session_t *knl_session, knl_handle_t stmt, ctc_ddl_def_node_t *def_node,
                               ctc_ddl_dc_array_t *dc_node)
{
    if (def_node == NULL) {
        dc_node = NULL;
        return CT_SUCCESS;
    }
    dc_node->ddl_def = def_node->ddl_def;
    dc_node->def_mode = def_node->def_mode;

    switch (def_node->def_mode) {
        case ALTER_DEF:
        case TRUNC_DEF:
        case DROP_DEF: {
            if (knl_open_dc_by_id(knl_session, def_node->uid, def_node->oid, &(dc_node->dc), CT_TRUE) != CT_SUCCESS) {
                ctc_set_invalid_dc_node_id(dc_node);
                CT_LOG_RUN_ERR("Fail to open dc for rollback(user_id:%d, table_id:%d, def_mode:%d)!", def_node->uid,
                               def_node->oid, def_node->def_mode);
                return CT_ERROR;
            }
            break;
        }
        case RENAME_DEF: {
            knl_altable_def_t *rename_def = (knl_altable_def_t *)def_node->ddl_def;
            // if rename fail and dc_rename_table not executed
            if (knl_open_dc_by_id(knl_session, def_node->uid, def_node->oid, &(dc_node->dc), CT_TRUE) != CT_SUCCESS) {
                ctc_set_invalid_dc_node_id(dc_node);
                CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not find", T2S(&(rename_def->table_def.new_name)));
                CT_LOG_RUN_ERR("Fail to open dc for rollback in rename def(user_id:%d, table_id:%d)!", def_node->uid,
                               def_node->oid);
                return CT_ERROR;
            }
            dc_entry_t *entry = DC_ENTRY(&(dc_node->dc));
            if (cm_strcmpi(rename_def->table_def.new_name.str, entry->name) == 0) {
                dc_rename_table(knl_session, &rename_def->name, &(dc_node->dc));
            }
            break;
        }
        case CREATE_DEF: {
            knl_table_def_t *create_def = (knl_table_def_t *)def_node->ddl_def;
            if (def_node->uid != CT_INVALID_INT32 && def_node->oid != CT_INVALID_INT32) {
                if (knl_open_dc_by_id(knl_session, def_node->uid, def_node->oid, &(dc_node->dc), CT_TRUE) !=
                    CT_SUCCESS) {
                    ctc_set_invalid_dc_node_id(dc_node);
                    CT_LOG_RUN_ERR("Fail to open dc for create of copy algorithm during the rollback!");
                    return CT_ERROR;
                }
            } else {
                ctc_set_invalid_dc_node_id(dc_node);
            }
            break;
        }
        default:
            break;
    }

    return CT_SUCCESS;
}

void ctc_ddl_table_after_rollback(knl_session_t *session, ctc_ddl_dc_array_t *dc_node)
{
    if (dc_node->dc.uid == CT_INVALID_INT32 || dc_node->dc.oid == CT_INVALID_INT32 ||
        dc_node->dc.type == DICT_TYPE_UNKNOWN) {
        return;
    }

    switch (dc_node->def_mode) {
        case ALTER_DEF:
        case RENAME_DEF: {
            knl_alter_table_invalidate_dc(session, &(dc_node->dc));
            knl_close_dc(&(dc_node->dc));
            break;
        }
        case DROP_DEF: {
            knl_close_dc(&(dc_node->dc));
            break;
        }
        case CREATE_DEF: {
            knl_table_def_t *create_def = (knl_table_def_t *)dc_node->ddl_def;
            if (!create_def->create_as_select && !create_def->is_mysql_copy) {
                dc_free_broken_entry(session, dc_node->dc.uid, dc_node->dc.oid);
                knl_close_dc(&(dc_node->dc));
                break;
            }
            knl_drop_def_t drop_def = { 0 };
            proto_str2text(create_def->name.str, &drop_def.name);
            proto_str2text(create_def->schema.str, &drop_def.owner);
            drop_def.purge = true;
            if (create_def->create_as_select) {
                drop_def.options = DROP_NO_CHECK_FK;
            } else if (create_def->is_mysql_copy) {
                drop_def.new_parent_id = dc_node->dc.oid;
                drop_def.new_user_id = dc_node->dc.uid;
                drop_def.options = DROP_FOR_MYSQL_COPY;
            }
            knl_drop_garbage_table4mysql_copy(session, &drop_def);
            knl_close_dc(&(dc_node->dc));
            break;
        }
        case TRUNC_DEF: {
            knl_trunc_def_t *trunc_def = (knl_trunc_def_t *)dc_node->ddl_def;
            knl_truncate_table_after_rollback(session, trunc_def, &(dc_node->dc));
            knl_close_dc(&(dc_node->dc));
            break;
        }
        default:
            break;
    }
    return;
}

EXTER_ATTACK int ctc_trx_rollback(ctc_handler_t *tch, uint64_t *cursors, int32_t csize)
{
    bool unlock_tables = CT_TRUE;

    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    ctc_free_cursors(session, cursors, csize);

    sql_stmt_t *stmt = session->current_stmt;
    knl_session_t *knl_session = &session->knl_session;
    if (stmt == NULL) {
        knl_rollback(knl_session, NULL);
        return CT_SUCCESS;
    }
    bilist_t *def_list = &stmt->ddl_def_list;
    if (stmt->ddl_def_list.head == NULL || ctc_is_def_list_empty(def_list)) {
        knl_rollback(knl_session, NULL);
        ctc_ddl_clear_stmt(stmt);
        return CT_SUCCESS;
    }
    CM_SAVE_STACK(knl_session->stack);
    ctc_ddl_dc_array_t *dc_array = (ctc_ddl_dc_array_t *)cm_push(knl_session->stack,
                                                                 def_list->count * sizeof(ctc_ddl_dc_array_t));
    CTC_LOG_RET_VAL_IF_NUL(dc_array, CT_ERROR, "ctc_trx_rollback: null dc_array ptr");
    int32_t dc_index = def_list->count - 1;
    bilist_node_t *node = cm_bilist_tail(def_list);
    for (; node != NULL; node = BINODE_PREV(node)) {
        ctc_ddl_def_node_t *def_node = (ctc_ddl_def_node_t *)BILIST_NODE_OF(ctc_ddl_def_node_t, node, bilist_node);
        ctc_ddl_dc_array_t *dc_node = &(dc_array[dc_index]);
        if (ctc_ddl_rollback_update_dc(knl_session, stmt, def_node, dc_node) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[ctc_trx_rollback] failed to rollback for ddl");
        }
        dc_index--;
    }

    knl_rollback4mysql(knl_session);

    for (int32_t i = def_list->count - 1; i >= 0; i--) {
        ctc_ddl_dc_array_t *dc_node = &(dc_array[i]);
        ctc_ddl_table_after_rollback(knl_session, dc_node);
        if (dc_node->def_mode == CREATE_DEF) {
            knl_table_def_t *create_def = (knl_table_def_t *)dc_node->ddl_def;
            unlock_tables = !create_def->is_mysql_copy ? CT_FALSE : CT_TRUE;
        }
    }

    ctc_ddl_unlock_table(knl_session, unlock_tables);
    ctc_ddl_clear_stmt(stmt);

    CTC_POP_CURSOR(knl_session);
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_srv_set_savepoint(ctc_handler_t *tch, const char *name)
{
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    CT_LOG_DEBUG_INF("ctc_trx set savepoint with thd_id=%u, session_id=%u", tch->thd_id, session->knl_session.id);
    knl_session_t *knl_session = &session->knl_session;
    text_t nm = { (char *)name, strnlen(name, CT_MAX_NAME_LEN - 1) };
    if (knl_set_savepoint(knl_session, &nm) != CT_SUCCESS) {
        int err = ctc_get_and_reset_err();
        CT_LOG_RUN_ERR("ctc_srv_set_savepoint: knl_set_savepoint failed, thd_id=%u, err=%d", tch->thd_id, err);
        return err;
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_srv_rollback_savepoint(ctc_handler_t *tch, uint64_t *cursors, int32_t csize, const char *name)
{
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    ctc_free_cursors(session, cursors, csize);
    CT_LOG_DEBUG_INF("ctc_trx rollback savepoint with thd_id=%u, session_id=%u", tch->thd_id, session->knl_session.id);
    knl_session_t *knl_session = &session->knl_session;
    text_t nm = { (char *)name, strnlen(name, CT_MAX_NAME_LEN - 1) };
    if (knl_rollback_savepoint(knl_session, &nm) != CT_SUCCESS) {
        int err = ctc_get_and_reset_err();
        CT_LOG_RUN_ERR("ctc_srv_rollback_savepoint: knl_rollback_savepoint failed, thd_id=%u, err=%d", tch->thd_id,
                       err);
        return err;
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_srv_release_savepoint(ctc_handler_t *tch, const char *name)
{
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    CT_LOG_DEBUG_INF("ctc_trx release savepoint with thd_id=%u, session_id=%u", tch->thd_id, session->knl_session.id);
    knl_session_t *knl_session = &session->knl_session;
    text_t nm = { (char *)name, strnlen(name, CT_MAX_NAME_LEN - 1) };
    if (knl_release_savepoint(knl_session, &nm) != CT_SUCCESS) {
        int err = ctc_get_and_reset_err();
        CT_LOG_RUN_ERR("ctc_srv_release_savepoint: knl_release_savepoint failed, thd_id=%u, err=%d", tch->thd_id, err);
        return err;
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_general_fetch(ctc_handler_t *tch, record_info_t *record_info)
{
    INIT_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_GENERAL_PREFETCH);
    BEGIN_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_GENERAL_PREFETCH);
    int ret = CT_SUCCESS;
    session_t *session = NULL;
    if (tch->pre_sess_addr != 0) {
        session = (session_t *)tch->pre_sess_addr;
    } else {
        session = ctc_get_session_by_addr(tch->sess_addr);
    }
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    CT_LOG_DEBUG_INF("ctc_general_fetch: tbl=%s, thd_id=%u", ctc_context->table.str, tch->thd_id);

    ret = ctc_fetch_and_filter(cursor, knl_session, record_info, !g_is_single_run_mode);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_general_fetch: ctc_fetch_and_filter FAIL");
        ctc_free_handler_cursor(session, tch);
        END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_GENERAL_PREFETCH);
        return ret;
    }
    if (!cursor->eof) {
        if (cursor->index_only) {
            ret = ctc_index_only_row_fill_bitmap(cursor, record_info->record);
            record_info->record_len = ((row_head_t *)record_info->record)->size;
        }
    } else {
        record_info->record_len = 0;
    }
    END_CTC_EVENT_TRACKING(CTC_FUNC_TYPE_GENERAL_PREFETCH);
    return ret;
}

int ctc_general_prefetch(ctc_handler_t *tch, uint8_t *records, uint16_t *record_lens, uint32_t *recNum,
                         uint64_t *rowids, int32_t max_row_size)
{
    int ret = CT_SUCCESS;
    session_t *session = NULL;
    if (tch->pre_sess_addr != 0) {
        session = (session_t *)tch->pre_sess_addr;
    } else {
        session = ctc_get_session_by_addr(tch->sess_addr);
    }
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    CT_LOG_DEBUG_INF("ctc_general_prefetch: tbl=%s, thd_id=%u", ctc_context->table.str, tch->thd_id);

    *recNum = 0;
    uint32_t record_buf_left_lens = MAX_RECORD_SIZE;
    for (uint32_t i = 0; i < CTC_MAX_PREFETCH_NUM && record_buf_left_lens >= max_row_size; i++) {
        record_info_t record_info = { records, 0, NULL, NULL };
        ret = ctc_fetch_and_filter(cursor, knl_session, &record_info, true);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("ctc_general_prefetch: ctc_fetch_and_filter FAIL");
            ctc_free_handler_cursor(session, tch);
            return ret;
        }
        if (cursor->eof) {
            record_lens[i] = 0;
            break;
        }
        if (cursor->index_only) {
            ret = ctc_index_only_row_fill_bitmap(cursor, records);
        }

        record_lens[i] = ((row_head_t *)records)->size;
        rowids[i] = cursor->rowid.value;
        records += record_lens[i];
        *recNum += 1;
        record_buf_left_lens -= record_lens[i];
    }
    return ret;
}

int ctc_free_session_cursors(ctc_handler_t *tch, uint64_t *cursors, int32_t csize)
{
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    ctc_free_cursors(session, cursors, csize);
    return CT_SUCCESS;
}

ctc_page_id_t cast_to_ctc_page_id(page_id_t knl_page)
{
    ctc_page_id_t result;
    result.file = knl_page.file;
    result.page = knl_page.page;
    result.aligned = knl_page.aligned;
    return result;
}

// make call to knl_get_paral_schedule and return splitted task range.
EXTER_ATTACK int ctc_get_paral_schedule(ctc_handler_t *tch, uint64_t *query_scn, uint64_t *ssn, int *worker_count,
                                        ctc_index_paral_range_t *paral_range)
{
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    if (tch->pre_sess_addr != 0) {
        session = (session_t *)tch->pre_sess_addr;
    } else {
        CT_RETURN_IFERR(ctc_get_or_new_session(&session, tch, true, false, &is_new_session));
    }
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_session_t *knl_session = &session->knl_session;  // knl_handle_t handle
    CT_RETURN_IFERR(ctc_try_reopen_dc(knl_session, &ctc_context->user, &ctc_context->table, ctc_context->dc));
    knl_dictionary_t *dc = ctc_context->dc;  // knl_dictionary_t *dc
    ctc_set_session_ssn_scn(knl_session, &tch->sql_stat_start);

    *query_scn = knl_session->query_scn;
    *ssn = knl_session->ssn;

    knl_paral_range_t result_range;
    knl_part_locate_t part_loc = {
        .part_no = tch->part_id,
        .subpart_no = tch->subpart_id,
    };
    int ret = knl_get_paral_schedule(knl_session, dc, part_loc, *worker_count, &result_range);
    if (ret == CT_ERROR) {
        // the split may fail iff dc check don't pass and we may force reopen existing dc entity and retry paral
        //  schedule.
        knl_close_dc(dc);
        ret = knl_open_dc(knl_session, &ctc_context->user, &ctc_context->table, dc);
        if (ret == CT_SUCCESS) {
            ret = knl_get_paral_schedule(knl_session, dc, part_loc, *worker_count, &result_range);
        }
    }
    // for failed to re-open dc scenario, workers = 0 and paral_range->range will be all zero
    for (int i = 0; i < result_range.workers; i++) {
        paral_range->index_range[i]->l_page = cast_to_ctc_page_id(result_range.l_page[i]);
        paral_range->index_range[i]->r_page = cast_to_ctc_page_id(result_range.r_page[i]);
    }
    paral_range->workers = result_range.workers;
    *worker_count = paral_range->workers;
    return ret;
}

void generic_decode_key_column(knl_scan_key_t *scan_key, uint16 *bitmap, uint16 *offset, ct_type_t type, uint32 id,
                               bool32 is_pcr)
{
    if (!btree_get_bitmap(bitmap, id)) {
        return;
    }

    switch (type) {
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BOOLEAN:
            *offset += sizeof(uint32);
            break;
        case CT_TYPE_UINT64:
        case CT_TYPE_BIGINT:
        case CT_TYPE_REAL:
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
        case CT_TYPE_DATE_MYSQL:
            *offset += sizeof(int64);
            break;
        case CT_TYPE_TIMESTAMP_TZ:
            *offset += sizeof(timestamp_tz_t);
            break;
        case CT_TYPE_INTERVAL_DS:
            *offset += sizeof(interval_ds_t);
            break;
        case CT_TYPE_INTERVAL_YM:
            *offset += sizeof(interval_ym_t);
            break;
        case CT_TYPE_NUMBER2:
            *offset += *(uint8 *)(scan_key->buf + *offset) + sizeof(uint8);
            break;
        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER3:
        case CT_TYPE_DECIMAL:
            if (is_pcr) {
                *offset += DECIMAL_FORMAT_LEN((char *)scan_key->buf + *offset);
                break;
            }

        // fall-through
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            *offset += CM_ALIGN4(*(uint16 *)(scan_key->buf + *offset) + sizeof(uint16));
            break;
    }
}

// copy_index_to_dest make scan_range->*_key.buf point to scan_range->*.buf and portable between kernel and MySQL
//  key size should alway fit within INDEX_KEY_SIZE (4096), so the destination would
//  suffice in ctc_scan_range_t.{l/r/org}_buf
// a separated key length calculation is necessary to avoid potential segfault.
// the code below is folloing the behavior of knl_get_index_par_schedule,
//  pcrb_decode_key and btree_decode_key
void copy_index_to_dest(index_t *index, cr_mode_t mode, ctc_scan_key_t *scan_key, char *buf)
{
    int offset = 0;
    if (mode == CR_PAGE) {
        index_profile_t *profile = INDEX_PROFILE(index);
        pcrb_key_t *pcrb_key = (pcrb_key_t *)scan_key->buf;
        offset = sizeof(pcrb_key_t);
        for (uint32_t id = 0; id < profile->column_count; id++) {
            generic_decode_key_column(scan_key, &pcrb_key->bitmap, &offset, profile->types[id], id, CT_TRUE);
        }
    } else {
        dc_entity_t *entity = index->entity;
        btree_key_t *btree_key = (btree_key_t *)scan_key->buf;
        offset = sizeof(btree_key_t);
        for (uint32_t id = 0; id < index->desc.column_count; id++) {
            knl_column_t *column = dc_get_column(entity, index->desc.columns[id]);
            generic_decode_key_column(scan_key, &btree_key->bitmap, &offset, column->datatype, id, CT_FALSE);
        }
    };
    // offset is the expected source index byte count
    memcpy_sp(buf, sizeof(char) * CT_KEY_BUF_SIZE, scan_key->buf, sizeof(char) * offset);
    scan_key->buf = buf;
}

// setup everything and do parallel workload split through knl_get_index_par_schedule
EXTER_ATTACK int ctc_get_index_paral_schedule(ctc_handler_t *tch, uint64_t *query_scn, int *worker_count,
                                              char *index_name, bool reverse, bool is_index_full,
                                              ctc_scan_range_t *origin_scan_range, ctc_index_paral_range_t *sub_ranges)
{
    // this should be called from a normal thread/session that has been called with table_open
    // table_open should have set up a session_t and knl_session_t for us.
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    if (tch->pre_sess_addr != 0) {
        session = (session_t *)tch->pre_sess_addr;
    } else {
        CT_RETURN_IFERR(ctc_get_or_new_session(&session, tch, true, false, &is_new_session));
    }
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_session_t *knl_session = &session->knl_session;  // knl_handle_t handle
    CT_RETURN_IFERR(ctc_try_reopen_dc(knl_session, &ctc_context->user, &ctc_context->table, ctc_context->dc));
    // even if we reopen dc, it could still go invalid for knl_get_index_par_schedule due to stat_version mismatch.
    knl_dictionary_t *dc = ctc_context->dc;  // knl_dictionary_t *dc

    int index_slot_id = MAX_INDEXES;
    ctc_get_index_from_name(dc, index_name, &index_slot_id);
    if (index_slot_id == MAX_INDEXES) {
        // failed to get index id through dc, potentially error caused by stat_version mismatch
        return ERR_INDEX_INVALID;
    }
    *query_scn = knl_session->query_scn;

    knl_idx_paral_info_t paral_info = { .index_slot = index_slot_id,
                                        .part_loc = g_invalid_part_loc,  // don't have support for partition yet.
                                        .workers = *worker_count,
                                        .is_dsc = reverse,
                                        .is_index_full = is_index_full,
                                        .org_range = origin_scan_range };

    int ret = knl_get_index_par_schedule(knl_session, dc, paral_info, sub_ranges);
    if (ret == CT_ERROR) {
        knl_close_dc(dc);
        ret = knl_open_dc(knl_session, &ctc_context->user, &ctc_context->table, dc);
        if (ret == CT_SUCCESS) {
            ret = knl_get_index_par_schedule(knl_session, dc, paral_info, sub_ranges);
        }
    }
    dc_entity_t *entity = DC_ENTITY(dc);
    index_t *index = entity->table.index_set.items[index_slot_id];
    btree_t *btree = &index->btree;

    // in the call to knl_get_index_par_schedule, the sub_ranges->index_range[_].{l/r/origin}_key.buf may point
    // to the b-tree key, which is outside shared memory buf.
    // copy that to sub_ranges->index_range[_].{l/r/origin}_buf to make the sub_ranges portable again
    for (int i = 0; i < sub_ranges->workers; i++) {
        copy_index_to_dest(index, btree->index->desc.cr_mode, &(sub_ranges->index_range[i]->l_key),
                           &(sub_ranges->index_range[i]->l_buf[0]));
        copy_index_to_dest(index, btree->index->desc.cr_mode, &(sub_ranges->index_range[i]->r_key),
                           &(sub_ranges->index_range[i]->r_buf[0]));
    }
    *worker_count = sub_ranges->workers;
    return ret;
}

EXTER_ATTACK int ctc_knl_write_lob(ctc_handler_t *tch, char *locator, uint32_t locator_size, int column_id, void *data,
                                   uint32_t data_len, bool force_outline)
{
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");

    int ret = CT_SUCCESS;
    CM_SAVE_STACK(knl_session->stack);
    knl_cursor_t *cursor = ctc_push_cursor(knl_session);
    if (NULL == cursor) {
        CT_LOG_RUN_ERR("ctc_knl_write_lob:CTC ctc_push_cursor FAIL");
        CTC_POP_CURSOR(knl_session);
        return ERR_GENERIC_INTERNAL_ERROR;
    }

    CT_LOG_DEBUG_INF("ctc_knl_write_lob: tbl=%s, thd_id=%u", ctc_context->table.str, tch->thd_id);
    cursor->action = CURSOR_ACTION_INSERT;
    if (IS_CTC_PART(tch->part_id)) {
        cursor->part_loc.part_no = tch->part_id;
        cursor->part_loc.subpart_no = tch->subpart_id;
    }
    if (ctc_open_cursor(knl_session, cursor, ctc_context, &tch->sql_stat_start, false) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_knl_write_lob: ctc_open_cursor failed");
        CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
        return ctc_get_and_reset_err();
    }
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    knl_column_t *column = dc_get_column(entity, column_id);
    ctc_lob_text_t text_data;
    text_data.str = data;
    text_data.len = data_len;

    if (knl_write_lob(knl_session, cursor, locator, column, force_outline, &text_data) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_knl_write_lob: knl_write_lob failed");
        CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
        return ctc_get_and_reset_err();
    }
    if (knl_session->canceled == CT_TRUE) {
        CT_LOG_RUN_ERR("ctc_knl_write_lob: knl_write_lob has been canceled");
        CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
        return ERR_OPERATION_CANCELED;
    }
    CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
    return ret;
}

int ctc_knl_read_lob(ctc_handler_t *tch, char *loc, uint32_t offset, void *buf, uint32_t size, uint32_t *read_size)
{
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    CT_LOG_DEBUG_INF("ctc_knl_read_lob: thd_id=%u", tch->thd_id);

    knl_session_t *knl_session = &session->knl_session;
    return knl_read_lob(knl_session, loc, offset, buf, size, read_size, NULL);
}

EXTER_ATTACK int ctc_analyze_table(ctc_handler_t *tch, const char *db_name, const char *table_name,
                                   double sampling_ratio)
{
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    CT_LOG_DEBUG_INF("ctc_analyze_table: analyze table %s.%s, thd_id=%u", db_name, table_name, tch->thd_id);
    knl_session_t *knl_session = &session->knl_session;
    CM_SAVE_STACK(knl_session->stack);

    knl_analyze_tab_def_t *def = cm_push(knl_session->stack, sizeof(knl_analyze_tab_def_t));
    if (def == NULL) {
        CT_LOG_RUN_ERR("ctc_analyze_table: out of stack, current offset=%u, max depth=%u",
                       knl_session->stack->push_offset, knl_session->stack->size);
        return ERR_ALLOC_MEMORY;
    }
    status_t status = memset_s(def, sizeof(knl_analyze_tab_def_t), 0, sizeof(knl_analyze_tab_def_t));
    knl_securec_check(status);
    cm_str2text(db_name, &def->owner);
    cm_str2text(table_name, &def->name);
    def->sample_ratio = (sampling_ratio == STATS_MAX_ESTIMATE_PERCENT) ? STATS_FULL_TABLE_SAMPLE : sampling_ratio;
    def->sample_type = (sampling_ratio == STATS_MAX_ESTIMATE_PERCENT) ? STATS_AUTO_SAMPLE : STATS_SPECIFIED_SAMPLE;
    def->is_default = CT_FALSE;
    def->part_name = CM_NULL_TEXT;
    def->sample_level = BLOCK_SAMPLE;
    def->method_opt.option = FOR_ALL_COLUMNS;
    def->dynamic_type = STATS_ALL;
    def->is_report = CT_FALSE;
    if (!ctc_alloc_stmt_context(session)) {
        return CT_ERROR;
    }
    def->part_no = tch->part_id;
    status = knl_analyze_table(&session->knl_session, def);
    CT_LOG_RUN_INF("ctc_analyze_table: analyze table %s.%s returned with ret %d", db_name, table_name, status);
    CTC_POP_CURSOR(knl_session);
    int ret = CT_SUCCESS;
    if (status != CT_SUCCESS) {
        ret = ctc_get_and_reset_err();
    }
    return ret;
}

EXTER_ATTACK int ctc_get_cbo_stats(ctc_handler_t *tch, ctc_cbo_stats_t *stats,
                                   ctc_cbo_stats_table_t *ctc_cbo_stats_table, uint32_t first_partid,
                                   uint32_t num_part_fetch)
{
    status_t ret;
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "get_ha_context failed");

    CT_LOG_DEBUG_INF("ctc_get_cbo_stats: tbl=%s, thd_id=%u", ctc_context->table.str, tch->thd_id);

    knl_session_t *knl_session = &session->knl_session;
    CT_RETURN_IFERR(ctc_try_reopen_dc(knl_session, &ctc_context->user, &ctc_context->table, ctc_context->dc));
    SYNC_POINT_GLOBAL_START(CTC_GET_CBO_STATS_FAIL, &ret, CT_ERROR);
    ret = get_cbo_stats(knl_session, DC_ENTITY(ctc_context->dc), stats, ctc_cbo_stats_table, first_partid,
                        num_part_fetch);
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[ctc_get_cbo_stats]: get_cbo_stats failed.");
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_get_index_name(ctc_handler_t *tch, char *index_name)
{
    ctc_context_t *ctc_context = ctc_get_ctx_by_addr(tch->ctx_addr);
    CTC_LOG_RET_VAL_IF_NUL(ctc_context, ERR_INVALID_DC, "session lookup failed");
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);
    if (ctc_context->dup_key_slot < 0 || ctc_context->dup_key_slot >= CT_MAX_TABLE_INDEXES) {
        CT_LOG_RUN_ERR("ctc_context->dup_key_slot(%u) is out of range.", ctc_context->dup_key_slot);
        return CT_ERROR;
    }
    knl_session_t *knl_session = &session->knl_session;
    CT_RETURN_IFERR(ctc_try_reopen_dc(knl_session, &ctc_context->user, &ctc_context->table, ctc_context->dc));
    knl_dictionary_t *dc = ctc_context->dc;
    int len = strlen(DC_INDEX(dc, ctc_context->dup_key_slot)->desc.name);
    errno_t ret = memcpy_s(index_name, CTC_MAX_KEY_NAME_LENGTH + 1, DC_INDEX(dc, ctc_context->dup_key_slot)->desc.name,
                           len);
    knl_securec_check(ret);
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_get_serial_value(ctc_handler_t *tch, uint64_t *value, dml_flag_t flag)
{
    session_t *session = ctc_get_session_by_addr(tch->sess_addr);
    CTC_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    ctc_set_no_use_other_sess4thd(session);

    if (tch->ctx_addr == INVALID_VALUE64 || ((ctc_context_t *)tch->ctx_addr) == NULL) {
        CT_LOG_RUN_ERR("ctx_addr(0x%llx) is invalid.", tch->ctx_addr);
        return CT_ERROR;
    }

    knl_dictionary_t *dc = ((ctc_context_t *)(tch->ctx_addr))->dc;
    dc_entity_t *entity = (dc_entity_t *)dc->handle;
    knl_session_t *knl_session = &session->knl_session;
    status_t status;
    if (flag.auto_increase) {
        status = knl_get_serial_value_4mysql(session, entity, value, (uint16)flag.auto_inc_step,
                                             (uint16)flag.auto_inc_offset);
    } else {
        status = ctc_get_curr_serial_value_auto_inc(knl_session, dc->handle, value, (uint16)flag.auto_inc_step,
                                                    (uint16)flag.auto_inc_offset);
    }

    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("fail to get serial value");
        return CT_ERROR;
    }

    for (int i = 0; i < entity->column_count; i++) {
        knl_column_t *knl_column = dc_get_column(entity, i);
        if (!KNL_COLUMN_IS_SERIAL(knl_column)) {
            continue;
        }

        ctc_calc_max_serial_value(knl_column, (uint64 *)value);
        break;
    }
    return CT_SUCCESS;
}

uint8_t *ctc_alloc_buf(ctc_handler_t *tch, uint32_t buf_size)
{
    if (buf_size == 0) {
        return NULL;
    }
    return (uint8_t *)cm_malloc(buf_size);
}

void ctc_free_buf(ctc_handler_t *tch, uint8_t *buf)
{
    if (buf == NULL) {
        return;
    }
    cm_free(buf);
}

int ctc_get_max_sessions_per_node(uint32_t *max_sessions)
{
    *max_sessions = g_instance->session_pool.max_sessions;
    return CT_SUCCESS;
}