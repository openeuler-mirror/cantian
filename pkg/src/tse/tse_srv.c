 /*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 */
#include "tse_module.h"
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
#include "dml_executor.h"
#include "knl_table.h"
#include "tse_srv_util.h"
#include "tse_cbo.h"
#include "tse_ddl.h"
#include "cm_malloc.h"
#include "knl_interface.h"
#include "tse_inst.h"
#include "tse_ddl_list.h"
#include "cm_log.h"

#define TSE_MAX_MYSQL_INST_SIZE (128)
#define TSE_MAX_PREFETCH_NUM (100)

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

EXTER_ATTACK int tse_open_table(tianchi_handler_t *tch, const char *table_name, const char *user_name)
{
    TSE_LOG_RET_VAL_IF_NUL(tch, CT_ERROR, "tse_open_table: null tch ptr");

    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    CT_RETURN_IFERR(tse_get_or_new_session(&session, tch, true, false, &is_new_session));
    tse_set_no_use_other_sess4thd(session);
    tse_context_t *tse_context = NULL;
    if (init_tse_ctx_and_open_dc(session, &tse_context, table_name, user_name) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_open_table failed :thd_id:%u, user_name:%s, table_name:%s",
                       tch->thd_id, user_name, table_name);
        int32 error_code = tse_get_and_reset_err();
        return error_code == 0 ? ERR_GENERIC_INTERNAL_ERROR : error_code;
    };
    tch->ctx_addr = (uint64)tse_context;
    tch->read_only_in_ct = IS_CANTIAN_SYS_DC(tse_context->dc);
    CT_LOG_DEBUG_INF("tse_open_table: tbl=%s, thd_id=%d, session_id=%u",
        tse_context->table.str, tch->thd_id, session->knl_session.id);

    return CT_SUCCESS;
}

EXTER_ATTACK int tse_close_table(tianchi_handler_t *tch)
{
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    if (tse_context == NULL) {
        CT_LOG_RUN_WAR("tse_close_table: ctx addr invalid");
        return CT_SUCCESS;
    }
    char *table_name = "empty_table";
    if (tse_context->table.str != NULL) {
        table_name = tse_context->table.str;
    }
    CT_LOG_DEBUG_INF("tse_close_table: tbl=%s, thd_id=%u", table_name, tch->thd_id);
    tse_set_no_use_other_sess4thd(NULL);
    free_tse_ctx(&tse_context, false); // 释放tse_context持有的内存,保留tse_context的本身内存
    // 此处不管移除成功或者失败，都没关系，移除操作目前只是打上删除标记，不会真正的删除tse_context的内存
    if (remove_mysql_inst_ctx_res(tse_context->tse_inst_id, tse_context) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_close_table remove error,inst_id:%u,thd_id:%u", tch->inst_id, tch->thd_id);
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int tse_close_session(tianchi_handler_t *tch)
{
    tse_set_no_use_other_sess4thd(NULL);
    (void)tse_unlock_instance(NULL, tch);
    int ret = tse_close_mysql_connection(tch);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TSE_CLOSE_SESSION]:close mysql connection failed, ret:%d, conn_id:%u, tse_instance_id:%u",
            ret, tch->thd_id, tch->inst_id);
    }
    return CT_SUCCESS;
}

EXTER_ATTACK void tse_kill_session(tianchi_handler_t *tch)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    if (session == NULL) {
        CT_LOG_RUN_ERR("session can not be null, conn_id=%u, tse_inst_id=%u", tch->thd_id, tch->inst_id);
        CM_ASSERT(0);
        return;
    }
    CT_LOG_DEBUG_INF("[TSE_KILL_SESSION]:conn_id=%u, tse_inst_id:%u, session_id=%u",
        tch->thd_id, tch->inst_id, session->knl_session.id);
    tse_set_no_use_other_sess4thd(session);
    session->knl_session.canceled = CT_TRUE;
}

static void tse_fill_serial_col_buf_4int(uint32 size, char *column_data_buf, uint64 *value)
{
    switch (size) {
        case TSE_TINY_INT_SIZE: {  // tinyint
            *(int8_t *)column_data_buf = (int8_t)*value;
            break;
        }
        case TSE_SMALL_INT_SIZE: {  // smallint
            *(int16_t *)column_data_buf = (int16_t)*value;
            break;
        }
        case TSE_MEDIUM_INT_SIZE:  // mediumint
        case TSE_INTEGER_SIZE: {   // int
            *(int32_t *)column_data_buf = (int32_t)*value;
            break;
        }
        default:
            CT_LOG_RUN_ERR("error column size for tse_fill_serial_col_buf_4int,%u", size);
            break;
    }
}

static void tse_fill_serial_col_buf_4uint(uint32 size, char *column_data_buf, uint64 *value)
{
    switch (size) {
        case TSE_TINY_INT_SIZE: {  // unsigned tinyint
            uint8_t tmp_key = (uint8_t)*value;
            if (tmp_key & 0x80) {
                *(uint32_t *)column_data_buf = (uint32_t)(*value) | 0xffffff00;
            } else {
                *(uint32_t *)column_data_buf = (uint8_t)*value;
            }
            break;
        }
        case TSE_SMALL_INT_SIZE: {  // unsigned smallint
            uint16_t tmp_key = (uint16_t)*value;
            if (tmp_key & 0x8000) {
                *(uint32_t *)column_data_buf = (uint32_t)(*value) | 0xffff0000;
            } else {
                *(uint32_t *)column_data_buf = (uint16_t)*value;
            }
            break;
        }
        case TSE_MEDIUM_INT_SIZE: {  // unsigned mediumint
            uint32_t tmp_key = (uint32_t)*value;
            if (tmp_key & 0x800000) {
                *(uint32_t *)column_data_buf = (uint32_t)(*value) | 0xff000000;
            } else {
                *(uint32_t *)column_data_buf = (uint32_t)*value;
            }
            break;
        }
        case TSE_INTEGER_SIZE: {  // unsigned int
            *(uint32_t *)column_data_buf = (uint32_t)*value;
            break;
        }
        default:
            CT_LOG_RUN_ERR("error column size for tse_fill_serial_col_buf_4uint,%u", size);
            break;
    }
}

// 将不同数据类型的数据填充到char*buf上
static void tse_fill_serial_col_buf(knl_column_t *knl_column, char *column_data_buf, uint64 *value)
{
    tse_calc_max_serial_value(knl_column, value);
    // 自增列能够保证datatype只会出现这几种类型，所以函数不用返回值，上层逻辑也不用判断，保持逻辑简单
    switch (knl_column->datatype) {
        case CT_TYPE_INTEGER: {
            tse_fill_serial_col_buf_4int(knl_column->size, column_data_buf, value);
            break;
        }
        case CT_TYPE_UINT32: {
            tse_fill_serial_col_buf_4uint(knl_column->size, column_data_buf, value);
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
            CT_LOG_RUN_ERR("tse_fill_serial_col_buf: unspported datatype of serial column,%u", knl_column->datatype);
            break;
    }
}

void tse_convert_serial_col_value_4int(uint32 size, char *column_data_buf, int64 *value)
{
    switch (size) {
        case TSE_TINY_INT_SIZE: {  // tinyint
            *value = *(int8 *)column_data_buf;
            break;
        }
        case TSE_SMALL_INT_SIZE: {  // smallint
            *value = *(int16 *)column_data_buf;
            break;
        }
        case TSE_MEDIUM_INT_SIZE: {
            *value = sint3korr((uchar *)((void *)column_data_buf));
            break;
        }
        case TSE_INTEGER_SIZE: {
            *value = *(int32 *)column_data_buf;
            break;
        }
        default:
            CT_LOG_RUN_ERR("error column size for tse_convert_serial_col_value_4int,%u", size);
            break;
    }
}

void tse_convert_serial_col_value_4uint(uint32 size, char *column_data_buf, int64 *value)
{
    switch (size) {
        case TSE_TINY_INT_SIZE: {  // unsigned tinyint
            *value = *(uchar *)column_data_buf;
            break;
        }
        case TSE_SMALL_INT_SIZE: {  // unsigned smallint
            *value = *(uint16 *)column_data_buf;
            break;
        }
        case TSE_MEDIUM_INT_SIZE: {  // unsigned mediumint
            *value = cm_ptr3_to_uint_big_endian((const uchar *)((void *)column_data_buf));
            break;
        }
        case TSE_INTEGER_SIZE: {  // unsigned int
            *value = *(uint32 *)column_data_buf;
            break;
        }
        default:
            CT_LOG_RUN_ERR("error column size for tse_convert_serial_col_value_4uint,%u", size);
            break;
    }
}

// 将char*转换为对应数据类型的数值
static void tse_convert_serial_col_value(knl_column_t *knl_column, char *column_data_buf, int64 *value)
{
    // 自增列能够保证datatype只会出现这几种类型，所以函数不用返回值，上层逻辑也不用判断，保持逻辑简单
    switch (knl_column->datatype) {
        case CT_TYPE_INTEGER: {
            tse_convert_serial_col_value_4int(knl_column->size, column_data_buf, value);
            break;
        }
        case CT_TYPE_UINT32: {
            tse_convert_serial_col_value_4uint(knl_column->size, column_data_buf, value);
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
            if (knl_column->size == 4) { // float size为4
                *value = convert_float_to_rint(column_data_buf);
            }
            if (knl_column->size == 8) { // double size 为8
                *value = convert_double_to_rint(column_data_buf);
            }
            break;
        }
        default:
            CT_LOG_RUN_ERR("tse_convert_serial_col_value: unspported datatype of serial column,datatype:%u",
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
        serial->is_uint64 = serial_col->datatype == CT_TYPE_UINT64 ? true : false;
        return CT_SUCCESS;
    }
    
    /*
        get the next autoinc val from kernel and fill into the write buffer
        1. autoinc val is NULL
        2. autoinc val is zero and sql mode is not NO_AUTO_VALUE_ON_ZERO
    */
    uint64 serial_value = 0;
    if (tse_get_curr_serial_value_auto_inc(session, entity, &serial_value, flag.auto_inc_step,
                                           flag.auto_inc_offset) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_get_curr_serial_value failed!");
        return CT_ERROR;
    }
    if (serial_value == CT_INVALID_ID64) {
        CT_THROW_ERROR(ERR_AUTOINC_READ_FAILED);
        return CT_ERROR;
    }

    if (flag.autoinc_lock_mode != CTC_AUTOINC_OLD_STYLE_LOCKING &&
        serial_value < tse_calc_max_serial_value(serial_col, NULL)) {
        serial->is_uint64 = serial_col->datatype == CT_TYPE_UINT64 ? true : false;
        if (knl_get_serial_value_4mysql(session, entity, &serial_value, flag.auto_inc_step,
                                        flag.auto_inc_offset) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("knl_get_serial_value_4mysql failed");
            return CT_ERROR;
        }
    }

    // if this auto_inc col is nullable and current value is NULL (see datatype_cnvrtr.cc mysql_record_to_cantian_record)
    if (serial_column_offset != 0) {
        tse_fill_serial_col_buf(serial_col, serial_buf, &serial_value);
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
        serial->is_uint64  = knl_column->datatype == CT_TYPE_UINT64 ? true : false;
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

static bool32 is_exceed_max_bulk_row(knl_cursor_t *cursor, uint16_t row_size)
{
    return cursor->rowid_count == KNL_ROWID_ARRAY_SIZE ||
           (uint32)(cursor->row_offset + row_size) > CT_MAX_ROW_SIZE;
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

int tse_bulk_write_rows(knl_cursor_t *cursor, knl_session_t *knl_session,
                        uint64_t rec_num, const record_info_t *record_info,
                        uint *err_pos, tse_context_t *tse_context, ctc_part_t *part_ids)
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
            uint32_t row_count = (uint32_t) cursor->rowid_count;
            if (knl_insert(knl_session, cursor) != CT_SUCCESS) {
                goto catch_err;
            }
            total_rows += row_count;
        }

        // copy current row to cursor
        cursor_row = (row_head_t *)((char *)cursor->row + cursor->row_offset);
        if (tse_copy_cursor_row(knl_session, cursor, curr_row, cursor_row, &cursor_row->size) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("tse_bulk_write_rows failed to copy cursor row");
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
    ret = tse_get_and_reset_err();
    CT_LOG_RUN_ERR("tse_bulk_write_rows failed with ret %d", ret);
    if (ret == ERR_DUPLICATE_KEY) {
        *err_pos = total_rows + cursor->rowid_count;
        tse_context->dup_key_slot = cursor->conflict_idx_slot;
    }
    return ret;
}

int insert_and_verify_for_bulk_write(knl_cursor_t *cursor, knl_session_t *knl_session, uint64_t rec_num,
                                     const record_info_t *record_info, uint *err_pos, tse_context_t *tse_context,
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

        cursor->row = (row_head_t*)cur_start;
        ret = tse_copy_cursor_row(knl_session, cursor, NULL, cursor->row, &cursor->row->size);
        if (ret != CT_SUCCESS) {
            tse_close_cursor(knl_session, cursor);
            return ret;
        }
        
        status_t status = knl_insert(knl_session, cursor);
        if (status != CT_SUCCESS) {
            ret = tse_get_and_reset_err();
            CT_LOG_RUN_ERR("tse_bulk_write failed with ret %d, i=%u", ret, i);
            if (ret == ERR_DUPLICATE_KEY) {
                *err_pos = i;
                tse_context->dup_key_slot = cursor->conflict_idx_slot;
            }
            return ret;
        }

        status = knl_verify_ref_integrities(knl_session, cursor);
        if (status == CT_SUCCESS) {
            cur_start += record_info->record_len;
            continue;
        }

        ret = tse_get_and_reset_err();
        if (!(flag.no_foreign_key_check && ret == ERR_CONSTRAINT_VIOLATED_NO_FOUND)) {
            if (flag.ignore) {
                knl_rollback(knl_session, &savepoint);
            }
            CT_LOG_RUN_ERR("tse_bulk_write failed integrities check with ret %d, i=%u", ret, i);
            return ret;
        }
        ret = CT_SUCCESS;
        cur_start += record_info->record_len;
    }
    return ret;
}

EXTER_ATTACK int tse_bulk_write(tianchi_handler_t *tch, const record_info_t *record_info, uint64_t rec_num,
                                uint32_t *err_pos, dml_flag_t flag, ctc_part_t *part_ids)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");
    TSE_LOG_RET_NOT_SUPPORT(tch->read_only_in_ct, "bulk insert", ERR_OPERATIONS_NOT_SUPPORT);

    CM_SAVE_STACK(knl_session->stack);
    knl_cursor_t *cursor = tse_push_cursor(knl_session);
    if (NULL == cursor) {
        CT_LOG_RUN_ERR("tse_bulk_write: tse_push_cursor FAIL");
        TSE_POP_CURSOR(knl_session);
        return ERR_GENERIC_INTERNAL_ERROR;
    }

    cursor->vnc_column = NULL;
    cursor->action = CURSOR_ACTION_INSERT;
    int ret = CT_SUCCESS;
    if (tse_open_cursor(knl_session, cursor, tse_context, &tch->sql_stat_start, false) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_bulk_write: tse_open_cursor failed");
        TSE_POP_CURSOR(knl_session);
        ret = tse_get_and_reset_err();
        return ret;
    }
    cursor->no_logic_logging = flag.no_logging;
    cursor->is_create_select = flag.is_create_select;
    if (IS_PART_TABLE((table_t *)cursor->table) && rec_num > MAX_BULK_INSERT_PART_ROWS) {
        CT_LOG_RUN_ERR("tse_bulk_write: rec_num exceeds the max");
        TSE_POP_CURSOR(knl_session);
        return ERR_GENERIC_INTERNAL_ERROR;
    }

    if (flag.ignore || (((table_t *)cursor->table)->cons_set.ref_count > 0 && flag.no_foreign_key_check) ||
        TABLE_ACCESSOR(cursor)->do_insert != (knl_cursor_operator_t)pcrh_insert) {
        // single row insertion
        ret = insert_and_verify_for_bulk_write(cursor, knl_session, rec_num, record_info,
                                               err_pos, tse_context, flag, part_ids);
    } else {
        // bulk row insertion, alloc space for cursor->row instead of point to cursor->buf
        // knl_insert will call knl_verify_ref_integrities for bulk write
        cursor->row = (row_head_t *)cm_push(knl_session->stack, CT_MAX_ROW_SIZE);
        if (cursor->row == NULL) {
            CT_LOG_RUN_ERR("tse_bulk_write failed to alloc space for rows");
            CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
            return CT_ERROR;
        }
        ret = tse_bulk_write_rows(cursor, knl_session, rec_num,
                                  record_info, err_pos, tse_context, part_ids);
    }

    CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
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
    cursor->no_logic_logging = flag.no_logging;
    cursor->is_create_select = flag.is_create_select;
    status_t status = knl_insert(knl_session, cursor);
    if (status != CT_SUCCESS) {
        // for on duplicate key update
        ret = tse_get_and_reset_err();
        if (ret == ERR_DUPLICATE_KEY) {
            tse_context->dup_key_slot = cursor->conflict_idx_slot;
            tse_context->conflict_rid = cursor->conflict_rid;
        }
        CT_LOG_DEBUG_ERR("tse_write_row: knl_insert FAIL");
        return ret;
    }
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    if (knl_verify_ref_integrities(knl_session, cursor) != CT_SUCCESS) {
        ret = tse_get_and_reset_err();
        if (flag.no_foreign_key_check && ret == ERR_CONSTRAINT_VIOLATED_NO_FOUND) {
            goto not_ret;
        }
        if (flag.ignore) {
            knl_rollback(knl_session, &savepoint);
        }
        CT_LOG_RUN_ERR("tse_write_row failed to knl_verify_ref_integrities with ret %d", ret);
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
            ret = tse_get_and_reset_err();
            CT_LOG_RUN_ERR("tse_write_row failed to set serial with ret %d, serial_col_value=%lld",
                           ret, serial->max_serial_col_value);
            if (ret != CT_SUCCESS && (flag.ignore)) {
                knl_rollback(knl_session, &savepoint);
            }
        }
    }
    return ret;
}

EXTER_ATTACK int tse_write_row(tianchi_handler_t *tch, const record_info_t *record_info,
                               uint16_t serial_column_offset, uint64_t *last_insert_id, dml_flag_t flag)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");
    TSE_LOG_RET_NOT_SUPPORT(tch->read_only_in_ct, "insert", ERR_OPERATIONS_NOT_SUPPORT);
    CM_SAVE_STACK(knl_session->stack);
    cm_reset_error();
    knl_cursor_t *cursor = tse_push_cursor(knl_session);
    if (NULL == cursor) {
        CT_LOG_RUN_ERR("tse_write_row: tse_push_cursor FAIL");
        TSE_POP_CURSOR(knl_session);
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    CT_LOG_DEBUG_INF("tse_write_row: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);
    cursor->vnc_column = NULL;
    cursor->action = CURSOR_ACTION_INSERT;
    if (tse_open_cursor(knl_session, cursor, tse_context, &tch->sql_stat_start, false) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_write_row: tse_open_cursor failed");
        TSE_POP_CURSOR(knl_session);
        return tse_get_and_reset_err();
    }

    if (IS_TSE_PART(tch->part_id)) {
        knl_part_locate_t part_loc = { .part_no = tch->part_id, .subpart_no = tch->subpart_id };
        knl_set_table_part(cursor, part_loc);
    }

    cursor->row = (row_head_t*)record_info->record;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    int ret = tse_copy_cursor_row(knl_session, cursor, NULL, cursor->row, &cursor->row->size);
    if (ret != CT_SUCCESS) {
        CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
        return ret;
    }

    serial_t serial = {0, false};
    if (flag.auto_inc_used) {
        cm_assert(entity->has_serial_col);
        if (tse_update_serial_col(knl_session, cursor, serial_column_offset,
                                  flag, &serial, last_insert_id) != CT_SUCCESS) {
            CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
            ret = tse_get_and_reset_err();
            return ret;
        }
    }

    ret = insert_and_verify_for_write_row(knl_session, cursor, &serial, *last_insert_id, tse_context, flag);
    CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
    return ret;
}

int tse_check_update_constraint(knl_session_t *knl_session, knl_cursor_t *cursor, uint64_t conflicts,
                                dml_flag_t flag, bool *need_rollback)
{
    int ret = CT_SUCCESS;
    status_t status = CT_SUCCESS;
    do {
        if (!flag.no_foreign_key_check) {
            cursor->no_cascade_check = flag.no_cascade_check;
            status = knl_verify_children_dependency(knl_session, cursor, CT_TRUE, 0, flag.dd_update);
            if (status != CT_SUCCESS) {
                ret = tse_get_and_reset_err();
                CT_LOG_RUN_ERR("tse_check_update_constraint failed to knl_verify_children_dependency with ret %d", ret);
                if ((flag.ignore || (!flag.no_cascade_check)) && ret == ERR_ROW_IS_REFERENCED) {
                    break;
                }
                return ret;
            }
        }

        status = knl_verify_ref_integrities(knl_session, cursor);
        if (status != CT_SUCCESS) {
            ret = tse_get_and_reset_err();
            CT_LOG_RUN_ERR("tse_check_update_constraint failed to knl_verify_ref_integrities with ret %d", ret);
            if ((flag.ignore) &&
                !((flag.no_foreign_key_check) && ret == ERR_CONSTRAINT_VIOLATED_NO_FOUND)) {
                break;
            }
            return ret;
        }

        status = knl_check_index_conflicts(knl_session, conflicts);
        if (status != CT_SUCCESS) {
            ret = tse_get_and_reset_err();
            CT_LOG_RUN_ERR("raw_tse_update_row violates index constraints, ret %d", ret);
            break;
        }
    } while (0);

    if (ret != CT_SUCCESS && (flag.ignore || !flag.no_cascade_check)) {
        *need_rollback = true;
    }

    return ret;
}

int raw_tse_update_row(knl_session_t *knl_session, knl_cursor_t *cursor, uint64_t conflicts, dml_flag_t flag)
{
    int ret = CT_SUCCESS;

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
    cursor->no_logic_logging = flag.no_logging;
    if (knl_update(knl_session, cursor) != CT_SUCCESS) {
        CT_LOG_RUN_ERR_LIMIT(LOG_PRINT_INTERVAL_SECOND_20, "raw_tse_update_row: knl_update FAIL");
        ret = tse_get_and_reset_err();
        return ret;
    }

    bool need_rollback = false;
    ret = tse_check_update_constraint(knl_session, cursor, conflicts, flag, &need_rollback);
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
            ret = tse_get_and_reset_err();
            CT_LOG_RUN_ERR(
                "raw_tse_update_row failed to set serial column value with ret %d, max_serial_col_value:%lld",
                ret, serial.max_serial_col_value);
            if (ret != CT_SUCCESS && flag.ignore) {
                knl_rollback(knl_session, &savepoint);
            }
        }
    }

    return ret;
}

int tse_open_cursor_and_fetch_by_rowid(knl_session_t *knl_session, knl_cursor_t *cursor,
                                       tse_context_t *tse_context, bool32 *isFound, bool is_select)
{
    int ret = CT_SUCCESS;
    if (tse_open_cursor(knl_session, cursor, tse_context, NULL, is_select) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_update_row: tse_open_cursor failed");
        ret = tse_get_and_reset_err();
        return ret;
    }

    cursor->rowid = tse_context->conflict_rid;
    if (knl_fetch_by_rowid(knl_session, cursor, isFound) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_update_row: knl_fetch_by_rowid FAIL");
        ret = tse_get_and_reset_err();
        return ret;
    }

    return ret;
}

EXTER_ATTACK int tse_update_row(tianchi_handler_t *tch, uint16_t new_record_len, const uint8_t *new_record,
                                const uint16_t *upd_cols, uint16_t col_num, dml_flag_t flag)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");
    TSE_LOG_RET_NOT_SUPPORT(tch->read_only_in_ct, "update", ERR_OPERATIONS_NOT_SUPPORT);
    cm_reset_error();

    int ret = CT_SUCCESS;
    uint64_t conflicts;
    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    knl_init_index_conflicts(knl_session, (uint64 *)&conflicts);
    CM_SAVE_STACK(knl_session->stack);
    if (!(flag.dup_update)) {
        CT_LOG_DEBUG_INF("tse_update_row: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);
        tse_fill_update_info(&cursor->update_info, new_record_len, new_record, upd_cols, col_num);
        ret = raw_tse_update_row(knl_session, cursor, conflicts, flag);
    } else {
        // for on duplicate key update
        cursor = tse_push_cursor(knl_session);
        if (NULL == cursor) {
            CT_LOG_RUN_ERR("tse_update_row: tse_push_cursor FAIL");
            TSE_POP_CURSOR(knl_session);
            return ERR_GENERIC_INTERNAL_ERROR;
        }
        CT_LOG_DEBUG_INF("tse_update_row: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);
        do {
            cursor->scan_mode = SCAN_MODE_ROWID;
            cursor->action = CURSOR_ACTION_UPDATE;
            cursor->vnc_column = NULL;
            bool32 isFound = CT_FALSE;

            ret = tse_open_cursor_and_fetch_by_rowid(knl_session, cursor, tse_context, &isFound, false);
            CT_BREAK_IF_TRUE(ret != CT_SUCCESS);

            tse_fill_update_info(&cursor->update_info, new_record_len, new_record, upd_cols, col_num);
            cursor->disable_pk_update = CT_TRUE;
            ret = raw_tse_update_row(knl_session, cursor, conflicts, flag);
            CT_BREAK_IF_TRUE(ret != ERR_DUPLICATE_KEY || !flag.is_replace);

            ROWID_COPY(tse_context->conflict_rid, cursor->conflict_rid);
        } while (CT_TRUE);
    }
    if (ret == ERR_DUPLICATE_KEY) {
        tse_context->dup_key_slot = cursor->conflict_idx_slot;
    }
    TSE_POP_CURSOR(knl_session);
    tse_close_cursor(knl_session, cursor);
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
        ret = tse_get_and_reset_err();
        CT_LOG_RUN_ERR_LIMIT(LOG_PRINT_INTERVAL_SECOND_20, "tse_delete_row: knl_delete FAIL. ret:%d", ret);
        return ret;
    }

    if (!flag.no_foreign_key_check) {
        cursor->no_cascade_check = flag.no_cascade_check;
        if (knl_verify_children_dependency(knl_session, cursor, false, 0, flag.dd_update) != CT_SUCCESS) {
            ret = tse_get_and_reset_err();
            CT_LOG_RUN_ERR("tse_delete_row: knl_verify_children_dependency FAIL. ret:%d.", ret);
            if ((flag.ignore || (!flag.no_cascade_check)) && ret == ERR_ROW_IS_REFERENCED) {
                knl_rollback(knl_session, &savepoint);
                return ret;
            }
        }
    }
    return ret;
}

EXTER_ATTACK int tse_delete_row(tianchi_handler_t *tch, uint16_t record_len, dml_flag_t flag)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");
    TSE_LOG_RET_NOT_SUPPORT(tch->read_only_in_ct, "delete", ERR_OPERATIONS_NOT_SUPPORT);
    int ret = CT_SUCCESS;
    cm_reset_error();

    if (!(flag.is_replace)) {
        knl_cursor_t *prev_cursor = (knl_cursor_t *)tch->cursor_addr;
        bool valid_rowid = IS_INVALID_ROWID(tse_context->conflict_rid);
        if (tch->cursor_addr == INVALID_VALUE64 || tch->cursor_addr == 0) {
            CT_LOG_RUN_ERR("tse_delete_row: tse_push_cursor FAIL, sql_command:%u, table: %s.%s, "
                           "cursor_addr:%u, rowid:%u", tch->sql_command, tse_context->user.str,
                           tse_context->table.str, tch->cursor_addr, valid_rowid);
            return ERR_GENERIC_INTERNAL_ERROR;
        }
        CT_LOG_DEBUG_INF("tse_delete_row: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);
        return delete_and_check_constraint(knl_session, prev_cursor, flag);
    }

    // for replace into
    CM_SAVE_STACK(knl_session->stack);
    knl_cursor_t *cursor = tse_push_cursor(knl_session);
    if (NULL == cursor) {
        CT_LOG_RUN_ERR("tse_delete_row: tse_push_cursor FAIL");
        TSE_POP_CURSOR(knl_session);
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    CT_LOG_DEBUG_INF("tse_delete_row:(replace) tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);
    cursor->scan_mode = SCAN_MODE_ROWID;
    cursor->action = CURSOR_ACTION_DELETE;

    bool32 isFound = CT_FALSE;
    ret = tse_open_cursor_and_fetch_by_rowid(knl_session, cursor, tse_context, &isFound, false);
    if (ret != CT_SUCCESS) {
        TSE_POP_CURSOR(knl_session);
        tse_close_cursor(knl_session, cursor);
        return ret;
    }

    if (isFound) {
        ret = delete_and_check_constraint(knl_session, cursor, flag);
    }
    tse_close_cursor(knl_session, cursor);
    TSE_POP_CURSOR(knl_session);
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
            CT_LOG_RUN_ERR("unsupport action %d", action);
            return ERR_GENERIC_INTERNAL_ERROR;
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int tse_rnd_init(tianchi_handler_t *tch, expected_cursor_action_t action,
                              tse_select_mode_t mode, tse_conds *cond)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_cursor_t *cursor = tse_alloc_session_cursor(session, tch->part_id, tch->subpart_id);
    if (cursor == NULL) {
        CT_LOG_RUN_ERR("tse_rnd_init: tse_alloc_session_cursor FAIL");
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    tch->cursor_addr = (uint64_t)cursor;
    tch->cursor_valid = true;
    tch->change_data_capture = LOGIC_REP_DB_ENABLED(&session->knl_session);
    CT_LOG_DEBUG_INF("tse_rnd_init: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->cond = cond;
    CT_RETURN_IFERR(tse_set_cursor_action(cursor, action));
    if (mode == SELECT_SKIP_LOCKED) {
        cursor->rowmark.type = ROWMARK_SKIP_LOCKED;
    } else if (mode == SELECT_NOWAIT) {
        cursor->rowmark.type = ROWMARK_NOWAIT;
    }

    bool is_select = tse_command_type_read(tch->sql_command);
    if (tse_open_cursor(&session->knl_session, cursor, tse_context, &tch->sql_stat_start, is_select) != CT_SUCCESS) {
        int ret = tse_get_and_reset_err();
        CT_LOG_RUN_ERR("tse_rnd_init: tse_open_cursor failed, ret = %d", ret);
        tse_free_handler_cursor(session, tch);
        return ret;
    }

    return CT_SUCCESS;
}

EXTER_ATTACK int tse_rnd_end(tianchi_handler_t *tch)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    if (tch->cursor_addr != INVALID_VALUE64) {
        tse_free_handler_cursor(session, tch);
    }
    return CT_SUCCESS;
}

static void tse_fetch_cursor_rowid_pos_value(knl_session_t *knl_session, knl_cursor_t *cursor)
{
    cursor->rowid.file = cursor->rowid_pos.file;
    cursor->rowid.page = cursor->rowid_pos.page;
    cursor->rowid.vmid = cursor->rowid_pos.vmid;
    cursor->rowid.vm_slot = cursor->rowid_pos.vm_slot;
    cursor->ssn = knl_session->ssn;
}

int tse_fetch_and_filter(knl_cursor_t *cursor, knl_session_t *knl_session, uint8_t *records, uint16 *size)
{
    int ret = CT_SUCCESS;
    uint32 charset_id = knl_session->kernel->db.charset_id;
    while (!cursor->eof) {
        if (knl_fetch(knl_session, cursor) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("tse_fetch_and_filter: knl_fetch FAIL");
            return tse_get_and_reset_err();
        }
        if (cursor->eof) {
            break;
        }
        cond_pushdown_result_t cond_result = check_cond_match_one_line((tse_conds *)cursor->cond, cursor, charset_id);
        if (cond_result == CPR_ERROR) {
            CT_LOG_RUN_ERR("tse_fetch_and_filter: check_cond_match_one_line FAIL");
            return CT_ERROR;
        } else if (cond_result == CPR_FALSE) {
            continue;
        } else {
            ret = tse_copy_cursor_row(knl_session, cursor, cursor->row, records, size);
            if (ret != CT_SUCCESS) {
                CT_LOG_RUN_ERR("tse_fetch_and_filter: tse_copy_cursor_row FAIL");
                return ret;
            }
            break;
        }
    }
    return ret;
}

EXTER_ATTACK int tse_rnd_next(tianchi_handler_t *tch, record_info_t *record_info)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    CT_LOG_DEBUG_INF("tse_rnd_next: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

    if (cursor->dc_type == DICT_TYPE_TEMP_TABLE_SESSION && cursor->ssn < knl_session->ssn) {
        knl_inc_session_ssn(knl_session);
        cursor->ssn = knl_session->ssn;
    }

    int ret = tse_fetch_and_filter(cursor, knl_session, record_info->record, &record_info->record_len);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_rnd_next: tse_fetch_and_filter FAIL");
        tse_free_handler_cursor(session, tch);
        return ret;
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int tse_scan_records(tianchi_handler_t *tch, uint64_t *num_rows, char *index_name)
{
    uint64_t rows = 0;
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_session_t *knl_session = &session->knl_session;
    CM_SAVE_STACK(knl_session->stack);
    knl_cursor_t *cursor = tse_push_cursor(knl_session);
    if (NULL == cursor) {
        CT_LOG_RUN_ERR("tse_scan_records: tse_push_cursor FAIL");
        TSE_POP_CURSOR(knl_session);
        return ERR_GENERIC_INTERNAL_ERROR;
    }

    CT_RETURN_IFERR(tse_try_reopen_dc(knl_session, &tse_context->user, &tse_context->table, tse_context->dc));
    knl_dictionary_t *dc = tse_context->dc;

    uint16_t active_index = MAX_INDEXES;
    tse_get_index_from_name(dc, index_name, &active_index);

    tse_pre_set_cursor_for_scan(DC_TABLE(dc)->index_set.total_count, cursor, active_index);

    if (IS_TSE_PART(tch->part_id)) {
        cursor->part_loc.part_no = tch->part_id;
        cursor->part_loc.subpart_no = tch->subpart_id;
    }

    bool is_select = tse_command_type_read(tch->sql_command);
    if (tse_open_cursor(knl_session, cursor, tse_context, &tch->sql_stat_start, is_select) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_scan_records: tse_open_cursor failed");
        CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
        return tse_get_and_reset_err();
    }

    int ret = tse_count_rows(session, dc, knl_session, cursor, &rows);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_scan_records: tse_count_all_rows failed");
        CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
        return ret;
    }
    *num_rows = rows;

    CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
    return CT_SUCCESS;
}

int tse_rnd_prefetch(tianchi_handler_t *tch, uint8_t *records, uint16_t *record_lens,
                     uint32_t *recNum, uint64_t *rowids, int32_t max_row_size)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    *recNum = 0;
    CT_LOG_DEBUG_INF("tse_rnd_prefetch: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

    if (cursor->dc_type == DICT_TYPE_TEMP_TABLE_SESSION && cursor->ssn < knl_session->ssn) {
        knl_inc_session_ssn(knl_session);
        cursor->ssn = knl_session->ssn;
    }

    uint32_t record_buf_left_lens = MAX_RECORD_SIZE;
    for (uint32_t i = 0; i < TSE_MAX_PREFETCH_NUM && record_buf_left_lens >= max_row_size; i++) {
        int ret = tse_fetch_and_filter(cursor, knl_session, records, &record_lens[i]);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("tse_rnd_prefetch: tse_fetch_and_filter FAIL");
            tse_free_handler_cursor(session, tch);
            return ret;
        }
        if (cursor->eof) {
            record_lens[i] = 0;
            break;
        }

        rowids[i] = cursor->rowid.value;
        records += record_lens[i];
        *recNum += 1;
        record_buf_left_lens -= record_lens[i];
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int tse_position(tianchi_handler_t *tch, uint8_t *position, uint16_t pos_length)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    CT_LOG_DEBUG_INF("tse_position: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

    rowid_t rowid = cursor->rowid;
    errno_t errcode = memcpy_s(position, pos_length, &rowid, sizeof(rowid));
    if (errcode != EOK) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int tse_rnd_pos(tianchi_handler_t *tch, uint16_t pos_length, uint8_t *position, record_info_t *record_info)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    CT_LOG_DEBUG_INF("tse_rnd_pos: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

    cursor->scan_mode = SCAN_MODE_ROWID;
    cursor->rowid = *((rowid_t *)position);

    if (((table_t *)cursor->table)->desc.type == TABLE_TYPE_SESSION_TEMP &&
        cursor->rowid.vmid >= knl_session->temp_mtrl->pool->ctrl_hwm) {
        tse_fetch_cursor_rowid_pos_value(knl_session, cursor);
    }

    if (IS_TSE_PART(tch->part_id)) {
        knl_part_locate_t part_loc = { .part_no = tch->part_id, .subpart_no = tch->subpart_id };
        knl_set_table_part(cursor, part_loc);
    }

    bool32 isFound = CT_FALSE;
    if (knl_fetch_by_rowid(knl_session, cursor, &isFound) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_rnd_pos fetch failed");
        tse_free_handler_cursor(session, tch);
        return tse_get_and_reset_err();
    }

    if (!cursor->eof) {
        int ret = tse_copy_cursor_row(knl_session, cursor, cursor->row, record_info->record, &record_info->record_len);
        if (ret != CT_SUCCESS) {
            tse_free_handler_cursor(session, tch);
            return ret;
        }
    } else {
        record_info->record_len = 0;
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int tse_delete_all_rows(tianchi_handler_t *tch, dml_flag_t flag)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");
    if (!tse_alloc_stmt_context(session)) {
        return CT_ERROR;
    }
    int ret = CT_SUCCESS;
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = &session->knl_session;
    
    CM_SAVE_STACK(knl_session->stack);
    cursor = tse_push_cursor(knl_session);
    if (NULL == cursor) {
        CT_LOG_RUN_ERR("tse_delete_all_rows: tse_push_cursor FAIL");
        TSE_POP_CURSOR(knl_session);
        return ERR_GENERIC_INTERNAL_ERROR;
    }
    CT_LOG_DEBUG_INF("tse_delete_all_rows: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->action = CURSOR_ACTION_DELETE;
    if (tse_open_cursor(knl_session, cursor, tse_context, &tch->sql_stat_start, false) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_delete_all_rows: tse_open_cursor failed");
        TSE_POP_CURSOR(knl_session);
        tse_close_cursor(knl_session, cursor);
        return tse_get_and_reset_err();
    }
    if (fetch_and_delete_all_rows(knl_session, cursor, flag) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_delete_all_rows: fetch_and_delete_all_rows failed");
        ret = tse_get_and_reset_err();
    }
    TSE_POP_CURSOR(knl_session);
    tse_close_cursor(knl_session, cursor);
    return ret;
}

static int tse_index_init(session_t *session, tse_context_t *tse_context, tianchi_handler_t *tch,
                          uint16_t index, bool sorted, expected_cursor_action_t action,
                          tse_select_mode_t mode, tse_conds *cond, const bool is_replace)
{
    knl_session_t *knl_session = &session->knl_session;
    if (is_replace && tch->sql_stat_start == 0) {
        knl_inc_session_ssn(knl_session);
    }
    knl_cursor_t *cursor = tse_alloc_session_cursor(session, tch->part_id, tch->subpart_id);
    TSE_LOG_RET_VAL_IF_NUL(cursor, ERR_GENERIC_INTERNAL_ERROR, "tse_alloc_session_cursor FAIL");

    tch->cursor_addr = (uint64_t)cursor;
    tch->cursor_valid = true;
    tch->change_data_capture = LOGIC_REP_DB_ENABLED(knl_session);
    CT_LOG_DEBUG_INF("tse_index_init: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

    CT_RETURN_IFERR(tse_set_cursor_action(cursor, action));
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

    bool is_select = tse_command_type_read(tch->sql_command);
    if (tse_open_cursor(knl_session, cursor, tse_context, &tch->sql_stat_start, is_select) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_index_init: tse_open_cursor failed");
        tse_free_handler_cursor(session, tch);
        return tse_get_and_reset_err();
    }

    return CT_SUCCESS;
}

EXTER_ATTACK int tse_index_end(tianchi_handler_t *tch)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    CT_LOG_DEBUG_INF("tse_index_end: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);
    if (tch->cursor_addr != INVALID_VALUE64) {
        tse_free_handler_cursor(session, tch);
    }
    return CT_SUCCESS;
}

int tse_check_partition_status(tianchi_handler_t *tch, knl_cursor_t **cursor,
                               index_key_info_t *index_key_info, tse_select_mode_t mode)
{
    int ret;
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    knl_session_t *knl_session = &session->knl_session;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    if (!index_key_info->sorted) {
        (*cursor)->part_loc.part_no = tch->part_id;
        (*cursor)->part_loc.subpart_no = tch->subpart_id;
        ret = knl_reopen_cursor(knl_session, *cursor, tse_context->dc);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("tse_index_read: reopen cursor failed");
            return ret;
        }
        knl_part_locate_t part_loc = { .part_no = tch->part_id, .subpart_no = tch->subpart_id };
        knl_set_table_part(*cursor, part_loc);
    } else {
        // alloc new cursor for new part
        ret = tse_index_init(session, tse_context, tch, index_key_info->active_index,
                             index_key_info->sorted, index_key_info->action, mode, (*cursor)->cond, false);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("tse_index_read: alloc new cursor for part %d failed", tch->part_id);
            return ret;
        }
        *cursor = (knl_cursor_t *)tch->cursor_addr;
        index_key_info->need_init = true;
    }

    return ret;
}

bool is_fetched_the_same_key(knl_cursor_t *cursor, const index_key_info_t *index_key_info,
                             int column_id, knl_index_desc_t *desc, bool *has_fetched_null) {
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
    // 先判断数据长度是否相等，再将取出来的值与key作memcmp，如果值相等则返回true
    if (!(cursor->lens[col_offset] == 0 ||
        cursor->lens[col_offset] != index_key_info->key_info[column_id].left_key_len ||
        memcmp((uint8_t *)cursor->row + cursor->offsets[col_offset],
            index_key_info->key_info[column_id].left_key,
            index_key_info->key_info[column_id].left_key_len) != 0)) {
        return true;
    }

    return false;
}

bool is_need_one_more_fetch(knl_cursor_t *cursor, const index_key_info_t *index_key_info,
                            uint16_t find_flag, bool *has_fetched_null)
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

    int iter_end_id = index_key_info->index_skip_scan ? 0 : index_key_info->key_num - 1;
    for (int column_id = index_key_info->key_num - 1; column_id >= iter_end_id; column_id--) {
        if (!is_fetched_the_same_key(cursor, index_key_info, column_id, desc, has_fetched_null)) {
            return false;
        }
    }

    return true;
}

int get_correct_pos_by_fetch(tianchi_handler_t *tch, knl_cursor_t *cursor,
                             record_info_t *record_info, const index_key_info_t *index_key_info)
{
    int ret = CT_SUCCESS;
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    knl_session_t *knl_session = &session->knl_session;
    uint32 charset_id = knl_session->kernel->db.charset_id;
    while (!cursor->eof) {
        if (knl_fetch(knl_session, cursor) != CT_SUCCESS) {
            TSE_HANDLE_KNL_FETCH_FAIL_LIMIT(session, tch);
        }
        if (cursor->eof) {
            CT_LOG_DEBUG_INF("cannot find record with current key info.");
            record_info->record_len = 0;
            return ret;
        }
        bool has_fetched_null = CT_FALSE;
        while (is_need_one_more_fetch(cursor, index_key_info, index_key_info->find_flag, &has_fetched_null)) {
            if (knl_fetch(knl_session, cursor) != CT_SUCCESS) {
                TSE_HANDLE_KNL_FETCH_FAIL_LIMIT(session, tch);
            }
            if (cursor->eof) {
                if (has_fetched_null) {
                    break;
                } else {
                    CT_LOG_DEBUG_INF("cannot find record with current key info.");
                    record_info->record_len = 0;
                    return ret;
                }
            }
        }
        cond_pushdown_result_t cond_result = check_cond_match_one_line((tse_conds *)cursor->cond, cursor, charset_id);
        if (cond_result == CPR_ERROR) {
            CT_LOG_RUN_ERR("get_correct_pos_by_fetch: check_cond_match_one_line FAIL");
            return CT_ERROR;
        } else if (cond_result == CPR_FALSE) {
            continue;
        } else {
            ret = tse_copy_cursor_row(knl_session, cursor, cursor->row, record_info->record, &record_info->record_len);
            if (ret != CT_SUCCESS) {
                CT_LOG_RUN_ERR("get_correct_pos_by_fetch: tse_copy_cursor_row FAIL");
                tse_free_handler_cursor(session, tch);
                return ret;
            }
            if (cursor->index_only) {
                ret = tse_index_only_row_fill_bitmap(cursor, record_info->record);
                record_info->record_len = ((row_head_t *)record_info->record)->size;
            }
            break;
        }
    }
    return ret;
}

int tse_check_partition_changed(knl_cursor_t *cursor, tianchi_handler_t *tch)
{
    if (IS_TSE_PART(cursor->part_loc.part_no) && IS_TSE_PART(tch->part_id) && cursor->part_loc.part_no != tch->part_id) {
        return CT_TRUE;
    } else if (IS_TSE_PART(cursor->part_loc.subpart_no) && IS_TSE_PART(tch->subpart_id) &&
            cursor->part_loc.subpart_no != tch->subpart_id) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

EXTER_ATTACK int tse_index_read(tianchi_handler_t *tch, record_info_t *record_info, index_key_info_t *index_info,
                                tse_select_mode_t mode, tse_conds *cond, const bool is_replace)
{
    CM_ASSERT(index_info != NULL);

    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    if (tch->pre_sess_addr != 0) {
        session = (session_t *)tch->pre_sess_addr;
    } else {
        CT_RETURN_IFERR(tse_get_or_new_session(&session, tch, true, false, &is_new_session));
    }
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_session_t *knl_session = &session->knl_session;
    CT_RETURN_IFERR(tse_try_reopen_dc(knl_session, &tse_context->user, &tse_context->table, tse_context->dc));
    knl_dictionary_t *dc = tse_context->dc;
    tse_get_index_from_name(dc, index_info->index_name, &index_info->active_index);
    if (index_info->active_index == MAX_INDEXES) {
        CT_LOG_RUN_ERR("tse_get_index_from_name: tse find index name '%s' failed!", index_info->index_name);
        return CT_ERROR;
    }

    if (index_info->need_init) {
        CT_RETURN_IFERR(tse_index_init(session, tse_context, tch, index_info->active_index,
            index_info->sorted, index_info->action, mode, cond, is_replace));
    }
    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;

    // check if partition changed during index scan
    if (tse_check_partition_changed(cursor, tch)) {
        CT_RETURN_IFERR(tse_check_partition_status(tch, &cursor, index_info, mode));
    }

    if (!index_info->need_init) { // no alloc cursor
        knl_inc_session_ssn(knl_session);
        cursor->ssn = knl_session->ssn;
        cursor->scan_range.is_equal = CT_FALSE;
    }

    CT_LOG_DEBUG_INF("tse_index_read: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

    CT_RETURN_IFERR(tse_get_index_info_and_set_scan_key(cursor, index_info));

    int ret = get_correct_pos_by_fetch(tch, cursor, record_info, index_info);
    if (ret != CT_SUCCESS) {
        return ret;
    }

    return CT_SUCCESS;
}

EXTER_ATTACK int tse_trx_begin(tianchi_handler_t *tch, tianchi_trx_context_t trx_context, bool is_mysql_local)
{
    // it's possible calling START TRANSACTION before open_table, thus session can also be added to gmap in this intf
    bool is_new_session = CT_FALSE;
    session_t *session = NULL;
    CT_RETURN_IFERR(tse_get_or_new_session(&session, tch, true, false, &is_new_session));
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    // mysql-server侧通过is_tse_trx_begin标记，保证一个事务只会调用一次tse_trx_begin，且调进来时参天侧事务未开启
    if (knl_session->rm->txn != NULL) {
        CT_LOG_DEBUG_INF("tse_trx_begin: knl_session->rm->txn is not NULL, thd_id=%u, session_id=%u, "
            "isolation level=%u, current_scn=%llu, rm_query_scn=%llu, lock_wait_timeout=%u, rmid=%u",
            tch->thd_id, session->knl_session.id, trx_context.isolation_level,
            knl_session->kernel->scn, knl_session->rm->query_scn, trx_context.lock_wait_timeout, knl_session->rmid);
        return CT_SUCCESS;
    }
    if (is_mysql_local && DB_IS_READONLY(knl_session)) {
        CT_LOG_RUN_INF("tse_trx_begin: operation on read only mode while ctc_ddl_local_enabled is true.");
        return CT_SUCCESS;
    }
    bool is_select = (tse_command_type_read(tch->sql_command) && !trx_context.use_exclusive_lock) ||
        tch->sql_command == SQLCOM_END;
    if (is_select && !knl_db_is_primary(knl_session)) {
        CT_LOG_RUN_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_20, "tse_trx_begin: select operation on read only mode in slave node.");
        return CT_SUCCESS;
    }
    
    if (knl_set_session_trans(knl_session, (isolation_level_t)trx_context.isolation_level, is_select) != CT_SUCCESS) {
        int err = tse_get_and_reset_err();
        CT_LOG_RUN_ERR("tse_trx begin: knl_set_session_trans failed, thd_id=%u, err=%d",
            tch->thd_id, err);
        return err;
    }
    knl_session->lock_wait_timeout = trx_context.lock_wait_timeout;
    session->auto_commit = trx_context.autocommit;
    // 这里不再主动调用tx_begin，参天引擎在DML需要undo时会自动开启txn
    CT_LOG_DEBUG_INF("tse_trx begin with thd_id=%u, session_id=%u, isolation level=%u, "
        "current_scn=%llu, rm_query_scn=%llu, lock_wait_timeout=%u, rmid=%u",
        tch->thd_id, session->knl_session.id, trx_context.isolation_level,
        knl_session->kernel->scn, knl_session->rm->query_scn, trx_context.lock_wait_timeout, knl_session->rmid);
    return CT_SUCCESS;
}

int tse_ddl_commit_log_put(knl_session_t *knl_session, knl_handle_t stmt, tse_ddl_def_node_t *def_node,
    tse_ddl_dc_array_t *dc_node)
{
    status_t status = CT_SUCCESS;
    if (def_node == NULL) {
        dc_node = NULL;
        return status;
    }

    if (def_node->uid == CT_INVALID_INT32 || def_node->oid == CT_INVALID_INT32) {
        dc_node->dc.uid = CT_INVALID_INT32;
        dc_node->dc.oid = CT_INVALID_INT32;
        CT_LOG_RUN_ERR("tse_ddl_commit_log_put failed, def_node->uid %u, oid %u", def_node->uid, def_node->oid);
        return CT_ERROR;
    }

    if (knl_open_dc_by_id(knl_session, def_node->uid, def_node->oid, &(dc_node->dc), CT_TRUE) != CT_SUCCESS) {
        dc_node->dc.uid = CT_INVALID_INT32;
        dc_node->dc.oid = CT_INVALID_INT32;
        CT_LOG_RUN_ERR("tse_ddl_commit_log_put open dc failed for def_mode:%d", def_node->def_mode);
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

void tse_ddl_table_after_commit(knl_session_t *session, tse_ddl_dc_array_t *dc_node)
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
            knl_drop_table_after_commit4mysql(session, &(dc_node->dc), drop_def);
            knl_close_dc(&(dc_node->dc));
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

void tse_ddl_table_after_commit_list(bilist_t *def_list, tse_ddl_dc_array_t *dc_array, knl_session_t *knl_session,
                                     bool *unlock_tables)
{
    for (uint32_t i = 0; i < def_list->count; i++) {
        tse_ddl_dc_array_t *dc_node = &(dc_array[i]);
        tse_ddl_table_after_commit(knl_session, dc_node);
        if (dc_node->def_mode == DROP_DEF) {
            *unlock_tables = CT_FALSE;
        }
    }
}

EXTER_ATTACK int tse_trx_commit(tianchi_handler_t *tch, uint64_t *cursors, int32_t csize, bool *is_ddl_commit)
{
    bool unlock_tables = CT_TRUE;
    *is_ddl_commit = CT_TRUE;

    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    tse_free_cursors((tch->pre_sess_addr != 0) ? ((session_t *)tch->pre_sess_addr) : session, cursors, csize);

    sql_stmt_t *stmt = session->current_stmt;
    knl_session_t *knl_session = &session->knl_session;
    if (stmt == NULL) {
        *is_ddl_commit = CT_FALSE;
        knl_commit(knl_session);
        return CT_SUCCESS;
    }
    bilist_t *def_list = &stmt->ddl_def_list;
    if (stmt->ddl_def_list.head == NULL || tse_is_def_list_empty(def_list)) {
        *is_ddl_commit = CT_FALSE;
        knl_commit(knl_session);
        tse_ddl_clear_stmt(stmt);
        return CT_SUCCESS;
    }
    CM_SAVE_STACK(knl_session->stack);
    tse_ddl_dc_array_t *dc_array = (tse_ddl_dc_array_t *)cm_push(knl_session->stack,
                                                                 def_list->count * sizeof(tse_ddl_dc_array_t));
    TSE_LOG_RET_VAL_IF_NUL(dc_array, CT_ERROR, "tse_trx_commit: null dc_array ptr");
    
    uint32_t dc_index = 0;
    bilist_node_t *node = cm_bilist_head(def_list);
    for (; node != NULL; node = BINODE_NEXT(node)) {
        tse_ddl_def_node_t *def_node = (tse_ddl_def_node_t *)BILIST_NODE_OF(tse_ddl_def_node_t, node, bilist_node);
        tse_ddl_dc_array_t *dc_node = &(dc_array[dc_index]);
        if (tse_ddl_commit_log_put(knl_session, stmt, def_node, dc_node) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("tse_ddl_commit_log_put failed , start rollback!");
            TSE_POP_CURSOR(knl_session);
            tse_trx_rollback(tch, cursors, csize);
            return CT_ERROR;
        }
        dc_index++;
    }

    knl_commit4mysql(knl_session);
    tse_ddl_table_after_commit_list(def_list, dc_array, knl_session, &unlock_tables);
    tse_ddl_unlock_table(knl_session, unlock_tables);

    if (DB_ATTR_MYSQL_META_IN_DACC(knl_session) || !(tch->sql_command == SQLCOM_DROP_TABLE && *is_ddl_commit)) {
        tse_ddl_clear_stmt(stmt);
    }

    TSE_POP_CURSOR(knl_session);
    return CT_SUCCESS;
}

int tse_ddl_rollback_update_dc(knl_session_t *knl_session, knl_handle_t stmt, tse_ddl_def_node_t *def_node,
    tse_ddl_dc_array_t *dc_node)
{
    if (def_node == NULL) {
        dc_node = NULL;
        return CT_SUCCESS;
    }

    switch (def_node->def_mode) {
        case ALTER_DEF:
        case TRUNC_DEF:
        case DROP_DEF: {
            if (knl_open_dc_by_id(knl_session, def_node->uid, def_node->oid, &(dc_node->dc), CT_TRUE) != CT_SUCCESS) {
                CT_LOG_DEBUG_ERR("Fail to open dc for rollback(user_id:%d table_id:%d)!", def_node->uid, def_node->oid);
                return CT_ERROR;
            }
            break;
        }
        case RENAME_DEF: {
            knl_altable_def_t *rename_def = (knl_altable_def_t *)def_node->ddl_def;
            // if rename fail and dc_rename_table not executed
            if (knl_open_dc_by_id(knl_session, def_node->uid, def_node->oid, &(dc_node->dc), CT_TRUE) != CT_SUCCESS) {
                CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not find", T2S(&(rename_def->table_def.new_name)));
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
                    dc_node->dc.uid = CT_INVALID_INT32;
                    dc_node->dc.oid = CT_INVALID_INT32;
                    CT_LOG_DEBUG_ERR("Fail to open dc for create of copy algorithm during the rollback!");
                    return CT_ERROR;
                }
            } else {
                dc_node->dc.uid = CT_INVALID_INT32;
                dc_node->dc.oid = CT_INVALID_INT32;
            }
            break;
        }
        default:
            break;
    }
    dc_node->ddl_def = def_node->ddl_def;
    dc_node->def_mode = def_node->def_mode;
    
    return CT_SUCCESS;
}

void tse_ddl_table_after_rollback(knl_session_t *session, tse_ddl_dc_array_t *dc_node)
{
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
            if (dc_node->dc.uid == CT_INVALID_INT32 || dc_node->dc.oid == CT_INVALID_INT32) {
                break;
            }
            knl_table_def_t *create_def = (knl_table_def_t *)dc_node->ddl_def;
            if (!create_def->create_as_select && !create_def->is_mysql_copy) {
                dc_free_broken_entry(session, dc_node->dc.uid, dc_node->dc.oid);
                knl_close_dc(&(dc_node->dc));
                break;
            }
            knl_drop_def_t drop_def = {0};
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

EXTER_ATTACK int tse_trx_rollback(tianchi_handler_t *tch, uint64_t *cursors, int32_t csize)
{
    bool unlock_tables = CT_TRUE;

    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    tse_free_cursors(session, cursors, csize);

    sql_stmt_t *stmt = session->current_stmt;
    knl_session_t *knl_session = &session->knl_session;
    if (stmt == NULL) {
        knl_rollback(knl_session, NULL);
        return CT_SUCCESS;
    }
    bilist_t *def_list = &stmt->ddl_def_list;
    if (stmt->ddl_def_list.head == NULL || tse_is_def_list_empty(def_list)) {
        knl_rollback(knl_session, NULL);
        tse_ddl_clear_stmt(stmt);
        return CT_SUCCESS;
    }
    CM_SAVE_STACK(knl_session->stack);
    tse_ddl_dc_array_t *dc_array = (tse_ddl_dc_array_t *)cm_push(knl_session->stack,
                                                                 def_list->count * sizeof(tse_ddl_dc_array_t));
    TSE_LOG_RET_VAL_IF_NUL(dc_array, CT_ERROR, "tse_trx_rollback: null dc_array ptr");
    int32_t dc_index = def_list->count - 1;
    bilist_node_t *node = cm_bilist_tail(def_list);
    for (; node != NULL; node = BINODE_PREV(node)) {
        tse_ddl_def_node_t *def_node = (tse_ddl_def_node_t *)BILIST_NODE_OF(tse_ddl_def_node_t, node, bilist_node);
        tse_ddl_dc_array_t *dc_node = &(dc_array[dc_index]);
        if (tse_ddl_rollback_update_dc(knl_session, stmt, def_node, dc_node) != CT_SUCCESS) {
            TSE_POP_CURSOR(knl_session);
            CT_LOG_RUN_ERR("[TSE] ASSERT INFO: failed to rollback for ddl");
            CM_ASSERT(0);
        }
        dc_index--;
    }

    knl_rollback4mysql(knl_session);

    for (int32_t i = def_list->count - 1; i >= 0; i--) {
        tse_ddl_dc_array_t *dc_node = &(dc_array[i]);
        tse_ddl_table_after_rollback(knl_session, dc_node);
        if (dc_node->def_mode == CREATE_DEF) {
            knl_table_def_t *create_def = (knl_table_def_t *)dc_node->ddl_def;
            unlock_tables = !create_def->is_mysql_copy ? CT_FALSE : CT_TRUE;
        }
    }

    tse_ddl_unlock_table(knl_session, unlock_tables);
    tse_ddl_clear_stmt(stmt);

    TSE_POP_CURSOR(knl_session);
    return CT_SUCCESS;
}

EXTER_ATTACK int tse_srv_set_savepoint(tianchi_handler_t *tch, const char *name)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    CT_LOG_DEBUG_INF("tse_trx set savepoint with thd_id=%u, session_id=%u", tch->thd_id, session->knl_session.id);
    knl_session_t *knl_session = &session->knl_session;
    text_t nm = { (char *)name, strnlen(name, CT_MAX_NAME_LEN - 1) };
    if (knl_set_savepoint(knl_session, &nm) != CT_SUCCESS) {
        int err = tse_get_and_reset_err();
        CT_LOG_RUN_ERR("tse_srv_set_savepoint: knl_set_savepoint failed, thd_id=%u, err=%d",
            tch->thd_id, err);
        return err;
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int tse_srv_rollback_savepoint(tianchi_handler_t *tch, uint64_t *cursors, int32_t csize, const char *name)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    tse_free_cursors(session, cursors, csize);
    CT_LOG_DEBUG_INF("tse_trx rollback savepoint with thd_id=%u, session_id=%u", tch->thd_id, session->knl_session.id);
    knl_session_t *knl_session = &session->knl_session;
    text_t nm = { (char *)name, strnlen(name, CT_MAX_NAME_LEN - 1) };
    if (knl_rollback_savepoint(knl_session, &nm) != CT_SUCCESS) {
        int err = tse_get_and_reset_err();
        CT_LOG_RUN_ERR("tse_srv_rollback_savepoint: knl_rollback_savepoint failed, thd_id=%u, err=%d",
            tch->thd_id, err);
        return err;
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int tse_srv_release_savepoint(tianchi_handler_t *tch, const char *name)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    CT_LOG_DEBUG_INF("tse_trx release savepoint with thd_id=%u, session_id=%u", tch->thd_id, session->knl_session.id);
    knl_session_t *knl_session = &session->knl_session;
    text_t nm = { (char *)name, strnlen(name, CT_MAX_NAME_LEN - 1) };
    if (knl_release_savepoint(knl_session, &nm) != CT_SUCCESS) {
        int err = tse_get_and_reset_err();
        CT_LOG_RUN_ERR("tse_srv_release_savepoint: knl_release_savepoint failed, thd_id=%u, err=%d",
            tch->thd_id, err);
        return err;
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int tse_general_fetch(tianchi_handler_t *tch, record_info_t *record_info)
{
    int ret = CT_SUCCESS;
    session_t *session = NULL;
    if (tch->pre_sess_addr != 0) {
        session = (session_t *)tch->pre_sess_addr;
    } else {
        session = tse_get_session_by_addr(tch->sess_addr);
    }
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    CT_LOG_DEBUG_INF("tse_general_fetch: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

    ret = tse_fetch_and_filter(cursor, knl_session, record_info->record, &record_info->record_len);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_general_fetch: tse_fetch_and_filter FAIL");
        tse_free_handler_cursor(session, tch);
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

    return ret;
}

int tse_general_prefetch(tianchi_handler_t *tch, uint8_t *records, uint16_t *record_lens,
                         uint32_t *recNum, uint64_t *rowids, int32_t max_row_size)
{
    int ret = CT_SUCCESS;
    session_t *session = NULL;
    if (tch->pre_sess_addr != 0) {
        session = (session_t *)tch->pre_sess_addr;
    } else {
        session = tse_get_session_by_addr(tch->sess_addr);
    }
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    knl_cursor_t *cursor = (knl_cursor_t *)tch->cursor_addr;
    CT_LOG_DEBUG_INF("tse_general_prefetch: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);

    *recNum = 0;
    uint32_t record_buf_left_lens = MAX_RECORD_SIZE;
    for (uint32_t i = 0; i < TSE_MAX_PREFETCH_NUM && record_buf_left_lens >= max_row_size; i++) {
        ret = tse_fetch_and_filter(cursor, knl_session, records, &record_lens[i]);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("tse_general_prefetch: tse_fetch_and_filter FAIL");
            tse_free_handler_cursor(session, tch);
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
        record_buf_left_lens -= record_lens[i];
    }
    return ret;
}

int tse_free_session_cursors(tianchi_handler_t *tch, uint64_t *cursors, int32_t csize)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_free_cursors(session, cursors, csize);
    return CT_SUCCESS;
}

EXTER_ATTACK int tse_knl_write_lob(tianchi_handler_t *tch, char *locator, uint32_t locator_size,
                                   int column_id, void *data, uint32_t data_len, bool force_outline)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    knl_session_t *knl_session = &session->knl_session;
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    int ret = CT_SUCCESS;
    CM_SAVE_STACK(knl_session->stack);
    knl_cursor_t *cursor = tse_push_cursor(knl_session);
    if (NULL == cursor) {
        CT_LOG_RUN_ERR("tse_knl_write_lob:TSE tse_push_cursor FAIL");
        TSE_POP_CURSOR(knl_session);
        return ERR_GENERIC_INTERNAL_ERROR;
    }

    CT_LOG_DEBUG_INF("tse_knl_write_lob: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);
    cursor->action = CURSOR_ACTION_INSERT;
    if (IS_TSE_PART(tch->part_id)) {
        cursor->part_loc.part_no = tch->part_id;
        cursor->part_loc.subpart_no = tch->subpart_id;
    }
    if (tse_open_cursor(knl_session, cursor, tse_context, &tch->sql_stat_start, false) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_knl_write_lob: tse_open_cursor failed");
        CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
        return tse_get_and_reset_err();
    }
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    knl_column_t* column = dc_get_column(entity, column_id);
    tianchi_lob_text_t text_data;
    text_data.str = data;
    text_data.len = data_len;
    
    if (knl_write_lob(knl_session, cursor, locator, column, force_outline, &text_data) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_knl_write_lob: knl_write_lob failed");
        CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
        return tse_get_and_reset_err();
    }
    if (knl_session->canceled == CT_TRUE) {
        CT_LOG_RUN_ERR("tse_knl_write_lob: knl_write_lob has been canceled");
        CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
        return ERR_OPERATION_CANCELED;
    }
    CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor);
    return ret;
}

int tse_knl_read_lob(tianchi_handler_t *tch, char* loc, uint32_t offset,
    void *buf, uint32_t size, uint32_t *read_size)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    CT_LOG_DEBUG_INF("tse_knl_read_lob: thd_id=%u", tch->thd_id);

    knl_session_t *knl_session = &session->knl_session;
    return knl_read_lob(knl_session, loc, offset, buf, size, read_size, NULL);
}

EXTER_ATTACK int tse_analyze_table(tianchi_handler_t *tch, const char *db_name,
                                   const char *table_name, double sampling_ratio)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    CT_LOG_DEBUG_INF("tse_analyze_table: analyze table %s.%s, thd_id=%u", db_name, table_name, tch->thd_id);
    knl_session_t *knl_session = &session->knl_session;
    CM_SAVE_STACK(knl_session->stack);

    knl_analyze_tab_def_t *def = cm_push(knl_session->stack, sizeof(knl_analyze_tab_def_t));
    if (def == NULL) {
        CT_LOG_RUN_ERR("tse_analyze_table: out of stack, current offset=%u, max depth=%u",
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
    if (!tse_alloc_stmt_context(session)) {
        return CT_ERROR;
    }
    def->part_no = tch->part_id;
    status = knl_analyze_table(&session->knl_session, def);
    CT_LOG_RUN_INF("tse_analyze_table: analyze table %s.%s returned with ret %d", db_name, table_name, status);
    TSE_POP_CURSOR(knl_session);
    int ret = CT_SUCCESS;
    if (status != CT_SUCCESS) {
        ret = tse_get_and_reset_err();
    }
    return ret;
}

EXTER_ATTACK int tse_get_cbo_stats(tianchi_handler_t *tch, tianchi_cbo_stats_t *stats)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "get_ha_context failed");

    CT_LOG_DEBUG_INF("tse_get_cbo_stats: tbl=%s, thd_id=%u", tse_context->table.str, tch->thd_id);
    
    knl_session_t *knl_session = &session->knl_session;
    CT_RETURN_IFERR(tse_try_reopen_dc(knl_session, &tse_context->user, &tse_context->table, tse_context->dc));
    
    get_cbo_stats(knl_session, DC_ENTITY(tse_context->dc), stats);
    return CT_SUCCESS;
}

EXTER_ATTACK int tse_get_index_name(tianchi_handler_t *tch, char *index_name)
{
    tse_context_t *tse_context = tse_get_ctx_by_addr(tch->ctx_addr);
    TSE_LOG_RET_VAL_IF_NUL(tse_context, ERR_INVALID_DC, "session lookup failed");
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    if (tse_context->dup_key_slot < 0 || tse_context->dup_key_slot >= CT_MAX_TABLE_INDEXES) {
        CT_LOG_RUN_ERR("tse_context->dup_key_slot(%u) is out of range.", tse_context->dup_key_slot);
        return CT_ERROR;
    }
    knl_session_t *knl_session = &session->knl_session;
    CT_RETURN_IFERR(tse_try_reopen_dc(knl_session, &tse_context->user, &tse_context->table, tse_context->dc));
    knl_dictionary_t *dc = tse_context->dc;
    int len = strlen(DC_INDEX(dc, tse_context->dup_key_slot)->desc.name);
    errno_t ret = memcpy_s(index_name, TSE_MAX_KEY_NAME_LENGTH + 1,
                           DC_INDEX(dc, tse_context->dup_key_slot)->desc.name, len);
    knl_securec_check(ret);
    return CT_SUCCESS;
}

EXTER_ATTACK int tse_get_serial_value(tianchi_handler_t *tch, uint64_t *value, dml_flag_t flag)
{
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    
    if (tch->ctx_addr == INVALID_VALUE64 || ((tse_context_t *)tch->ctx_addr) == NULL) {
        CT_LOG_RUN_ERR("ctx_addr(0x%llx) is invalid.", tch->ctx_addr);
        return CT_ERROR;
    }

    knl_dictionary_t *dc = ((tse_context_t *)(tch->ctx_addr))->dc;
    dc_entity_t *entity = (dc_entity_t *)dc->handle;
    knl_session_t *knl_session = &session->knl_session;
    status_t status;
    if (flag.auto_increase) {
        status = knl_get_serial_value_4mysql(session, entity, value, (uint16)flag.auto_inc_step,
                                             (uint16)flag.auto_inc_offset);
    } else {
        status = tse_get_curr_serial_value_auto_inc(knl_session, dc->handle, value, (uint16)flag.auto_inc_step,
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

        tse_calc_max_serial_value(knl_column, (uint64 *)value);
        break;
    }
    return CT_SUCCESS;
}

uint8_t *tse_alloc_buf(tianchi_handler_t *tch, uint32_t buf_size)
{
    if (buf_size == 0) {
        return NULL;
    }
    return (uint8_t*)cm_malloc(buf_size);
}

void tse_free_buf(tianchi_handler_t *tch, uint8_t *buf)
{
    if (buf == NULL) {
        return;
    }
    cm_free(buf);
}

int tse_get_max_sessions_per_node(uint32_t *max_sessions)
{
    *max_sessions = g_instance->session_pool.max_sessions;
    return CT_SUCCESS;
}
