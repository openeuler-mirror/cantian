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
 * ctsql_update.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_update.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_instance.h"
#include "ctsql_update.h"
#include "ctsql_mtrl.h"
#include "ctsql_select.h"
#include "ctsql_proj.h"
#include "ctsql_scan.h"
#include "ctsql_insert.h"
#include "ctsql_jsonb.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CHECK_ERR_ROW_SELF_UPDATED(status, check, savepoint)     \
    {                                                            \
        if (SECUREC_UNLIKELY((status) != CT_SUCCESS)) {          \
            if (CT_ERRNO == ERR_ROW_SELF_UPDATED) {              \
                cm_reset_error();                                \
                if (!(check)) {                                  \
                    knl_rollback(KNL_SESSION(stmt), &(savepoint)); \
                    continue;                                    \
                } else {                                         \
                    CT_THROW_ERROR(ERR_TOO_MANY_ROWS);           \
                }                                                \
            }                                                    \
            return CT_ERROR;                                     \
        }                                                        \
    }


status_t sql_open_cursor_for_update(sql_stmt_t *stmt, sql_table_t *table, sql_array_t *ssa, sql_cursor_t *cur,
    knl_cursor_action_t action)
{
    cur->eof = CT_FALSE;
    cur->rownum = 0;
    cur->columns = NULL;
    cur->table_count = 1;
    cur->tables[0].table = table;
    sql_init_varea_set(stmt, &cur->tables[0]);

    cur->id_maps[0] = table->id;
    sql_reset_mtrl(stmt, cur);
    cur->tables[0].scn = cur->scn;

    if (sql_alloc_knl_cursor(stmt, &cur->tables[0].knl_cur) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cur->tables[0].knl_cur->action = action;
    cur->tables[0].action = action;

    sql_init_ssa_cursor_maps(cur, ssa->count);

    cur->is_open = CT_TRUE;
    return CT_SUCCESS;
}

static inline status_t sql_open_update_cursor(sql_stmt_t *stmt, sql_cursor_t *cur, sql_update_t *ctx)
{
    knl_cursor_action_t cursor_action;
    cursor_action = ctx->query->tables.count > 1 ? CURSOR_ACTION_FOR_UPDATE_SCAN : CURSOR_ACTION_UPDATE;

    if (sql_open_cursors(stmt, cur, ctx->query, cursor_action, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    cur->scn = CT_INVALID_ID64;
    cur->plan = ctx->plan;
    cur->update_ctx = ctx;
    return CT_SUCCESS;
}

static inline status_t sql_set_lob_value_from_normal(sql_stmt_t *stmt, knl_cursor_t *knl_cur, row_assist_t *ra,
    knl_column_t *knl_col, variant_t *value)
{
    status_t status;

    CTSQL_SAVE_STACK(stmt);
    sql_keep_stack_variant(stmt, value);

    status = knl_row_put_lob(stmt->session, knl_cur, knl_col, (void *)&value->v_lob.normal_lob.value, ra);

    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static status_t sql_set_lob_value_from_knl(sql_stmt_t *stmt, knl_cursor_t *knl_cur, row_assist_t *ra,
    knl_column_t *knl_col, variant_t *value)
{
    knl_handle_t src_locator;
    status_t status;

    CTSQL_SAVE_STACK(stmt);
    sql_keep_stack_variant(stmt, value);

    src_locator = (knl_handle_t)value->v_lob.knl_lob.bytes;
    status = knl_row_move_lob(stmt->session, knl_cur, knl_col, src_locator, ra);

    CTSQL_RESTORE_STACK(stmt);
    return status;
}

status_t sql_set_vm_lob_to_knl_lob_locator(sql_stmt_t *stmt, knl_cursor_t *knl_cur, knl_column_t *col,
                                           variant_t *value, char *locator)
{
    vm_pool_t *vm_pool = stmt->mtrl.pool;
    uint32 remain_size, vmid;
    bool32 force_outline;
    vm_page_t *vm_page = NULL;
    binary_t piece;

    remain_size = value->v_lob.vm_lob.size;
    force_outline = (remain_size > LOB_MAX_INLIINE_SIZE);
    vmid = value->v_lob.vm_lob.entry_vmid;

    /* empty string */
    if (remain_size == 0) {
        piece.bytes = NULL;
        piece.size = 0;
        CT_RETURN_IFERR(knl_write_lob(stmt->session, knl_cur, locator, col, force_outline, &piece));
        return CT_SUCCESS;
    }

    /* not empty VM lob */
    while (remain_size > 0) {
        CT_RETURN_IFERR(vm_open(stmt->session, vm_pool, vmid, &vm_page));

        piece.bytes = (uint8 *)vm_page->data;
        piece.size = (CT_VMEM_PAGE_SIZE > remain_size) ? remain_size : CT_VMEM_PAGE_SIZE;
        remain_size -= piece.size;

        if (knl_write_lob(stmt->session, knl_cur, locator, col, force_outline, &piece) != CT_SUCCESS) {
            vm_close(stmt->session, vm_pool, vmid, VM_ENQUE_HEAD);
            return CT_ERROR;
        }

        vm_close(stmt->session, vm_pool, vmid, VM_ENQUE_HEAD);
        vmid = vm_get_ctrl(vm_pool, vmid)->sort_next;
    }
    return CT_SUCCESS;
}
status_t sql_set_vm_lob_to_knl(void *stmt, knl_cursor_t *knl_cur, knl_column_t *knl_col, variant_t *value,
                               char *locator)
{
    return sql_set_vm_lob_to_knl_lob_locator((sql_stmt_t *)stmt, knl_cur, knl_col, value, locator);
}

static status_t sql_set_lob_value_from_bind(sql_stmt_t *stmt, knl_cursor_t *knl_cur, row_assist_t *ra,
    knl_column_t *knl_col, variant_t *value)
{
    char *locator = NULL;
    binary_t lob;

    CT_RETURN_IFERR(sql_push(stmt, CT_LOB_LOCATOR_BUF_SIZE, (void **)&locator));

    errno_t errcode = memset_s(locator, KNL_LOB_LOCATOR_SIZE, 0xFF, KNL_LOB_LOCATOR_SIZE);
    if (errcode != EOK) {
        CTSQL_POP(stmt);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CT_ERROR;
    }

    if (sql_set_vm_lob_to_knl_lob_locator(stmt, knl_cur, knl_col, value, locator) != CT_SUCCESS) {
        CTSQL_POP(stmt);
        return CT_ERROR;
    }

    lob.size = knl_lob_locator_size((knl_handle_t)locator);
    lob.bytes = (uint8 *)locator;
    if (row_put_bin(ra, &lob) != CT_SUCCESS) {
        CTSQL_POP(stmt);
        return CT_ERROR;
    }

    if (!((lob_locator_t *)locator)->head.is_outline) {
        knl_cur->lob_inline_num++;
    }

    CTSQL_POP(stmt);
    return CT_SUCCESS;
}

status_t sql_set_lob_value(sql_stmt_t *stmt, knl_cursor_t *knl_cur, row_assist_t *ra, knl_column_t *knl_col,
    variant_t *value)
{
    if (!CT_IS_LOB_TYPE(knl_col->datatype)) {
        CT_THROW_ERROR(ERR_COLUMN_DATA_TYPE, "(clob/blob/image)", knl_col->name);
        return CT_ERROR;
    }

    switch (value->v_lob.type) {
        case CT_LOB_FROM_KERNEL:
            return sql_set_lob_value_from_knl(stmt, knl_cur, ra, knl_col, value);

        case CT_LOB_FROM_VMPOOL:
            return sql_set_lob_value_from_bind(stmt, knl_cur, ra, knl_col, value);

        case CT_LOB_FROM_NORMAL:
            return sql_set_lob_value_from_normal(stmt, knl_cur, ra, knl_col, value);

        default:
            CT_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "do set lob value");
            return CT_ERROR;
    }
}

/* notice: only update head_offset and dir_offset in vm, not use external vm page */
static status_t sql_compress_array_in_vm(sql_stmt_t *stmt, vm_pool_t *vm_pool, var_array_t *v_array, uint32 actual_size)
{
    vm_lob_t *vlob = &v_array->value.vm_lob;

    CT_RETURN_IFERR(array_update_ctrl(KNL_SESSION(stmt), vm_pool, vlob, actual_size, v_array->count, COMPRESS_ARRAY));

    return CT_SUCCESS;
}

static status_t sql_set_array_to_lob_locator(sql_stmt_t *stmt, knl_cursor_t *knl_cur, knl_column_t *col,
    variant_t *value, char *locator, uint32 real_size, uint32 head_offset)
{
    vm_page_t *vm_page = NULL;
    vm_pool_t *vm_pool = stmt->mtrl.pool;
    var_array_t *v_array = &value->v_array;
    uint32 ctrl_size = sizeof(array_head_t) + v_array->count * sizeof(elem_dir_t);
    binary_t piece;
    uint32 vmid = v_array->value.vm_lob.entry_vmid;
    uint32 vlob_num = cm_get_vlob_page_num(vm_pool, &v_array->value.vm_lob);
    /* unused space between last dir and first element */
    uint32 unused_space = ((head_offset == ctrl_size) ? 0 : (CT_VMEM_PAGE_SIZE - ctrl_size % CT_VMEM_PAGE_SIZE));
    bool32 need_compress = (g_instance->sql.enable_arr_store_opt && vlob_num <= ARRAY_USED_VM_PAGES &&
        unused_space > ARRAY_UNUSED_SPACE_IN_VM);
    /* uncompressed_size = ctrl_size + (unused space between last dir and first element) + data_szie */
    uint32 uncompressed_size = v_array->value.vm_lob.size;

    if (need_compress) {
        CT_RETURN_IFERR(sql_compress_array_in_vm(stmt, vm_pool, v_array, real_size));
    }

    uint32 remain = (need_compress ? ctrl_size : uncompressed_size);
    while (remain > 0) {
        CM_ASSERT(vmid != CT_INVALID_ID32);
        CT_RETURN_IFERR(vm_open(KNL_SESSION(stmt), vm_pool, vmid, &vm_page));

        piece.bytes = (uint8 *)vm_page->data;
        piece.size = MIN(CT_VMEM_PAGE_SIZE, remain);

        if (knl_write_lob(KNL_SESSION(stmt), knl_cur, locator, col, CT_TRUE, &piece) != CT_SUCCESS) {
            vm_close(KNL_SESSION(stmt), vm_pool, vmid, VM_ENQUE_HEAD);
            return CT_ERROR;
        }
        vm_close(KNL_SESSION(stmt), vm_pool, vmid, VM_ENQUE_HEAD);

        remain -= piece.size;
        vmid = vm_get_ctrl(vm_pool, vmid)->sort_next;
        /* 1) when array is not compressed, the space between last dir and first element will be not equal to 0,
              and if compressed this space will not be written into kernel lob
           2) first write array ctrl(head and dir) into kernel lob, then write array element into kernel lob */
        if (remain == 0 && vmid != CT_INVALID_ID32) {
            remain = real_size - ctrl_size;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_adjust_element_by_col(sql_stmt_t *stmt, knl_column_t *knl_col, uint32 datatype, char *ele_val,
    uint32 *size, variant_t *val)
{
    uint16 offset;
    uint16 len;
    int64 date_val;
    uint32 value_len;
    row_assist_t row_ass;
    char *buf = NULL;
    status_t status = CT_SUCCESS;

    if (var_gen_variant(ele_val, *size, datatype, val) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (datatype != knl_col->datatype) {
        CT_RETURN_IFERR(sql_convert_variant(stmt, val, knl_col->datatype));
    }

    if (sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf)) {
        return CT_ERROR;
    }

    row_init(&row_ass, buf, CT_MAX_ROW_SIZE, 1);
    /* convert & check value */
    switch (knl_col->datatype) {
        case CT_TYPE_UINT32:
            status = row_put_uint32(&row_ass, val->v_uint32);
            break;

        case CT_TYPE_INTEGER:
            status = row_put_int32(&row_ass, val->v_int);
            break;

        case CT_TYPE_BOOLEAN:
            status = row_put_bool(&row_ass, val->v_bool);
            break;

        case CT_TYPE_BIGINT:
            status = row_put_int64(&row_ass, val->v_bigint);
            break;

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
            status = cm_adjust_dec(&val->v_dec, knl_col->precision, knl_col->scale);
            CT_BREAK_IF_ERROR(status);
            status = row_put_dec4(&row_ass, &val->v_dec);
            break;
        case CT_TYPE_NUMBER2:
            status = cm_adjust_dec(&val->v_dec, knl_col->precision, knl_col->scale);
            CT_BREAK_IF_ERROR(status);
            status = row_put_dec2(&row_ass, &val->v_dec);
            break;

        case CT_TYPE_REAL:
            status = cm_adjust_double(&val->v_real, knl_col->precision, knl_col->scale);
            CT_BREAK_IF_ERROR(status);
            status = row_put_real(&row_ass, val->v_real);
            break;

        case CT_TYPE_DATE:
            date_val = cm_adjust_date(val->v_date);
            status = row_put_int64(&row_ass, date_val);
            break;

        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
            status = cm_adjust_timestamp(&val->v_tstamp, knl_col->precision);
            CT_BREAK_IF_ERROR(status);
            status = row_put_int64(&row_ass, val->v_tstamp);
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            status = cm_adjust_timestamp_tz(&val->v_tstamp_tz, knl_col->precision);
            CT_BREAK_IF_ERROR(status);
            status = row_put_timestamp_tz(&row_ass, &val->v_tstamp_tz);
            break;

        case CT_TYPE_INTERVAL_DS:
            status = cm_adjust_dsinterval(&val->v_itvl_ds, (uint32)knl_col->precision, (uint32)knl_col->scale);
            CT_BREAK_IF_ERROR(status);
            status = row_put_dsinterval(&row_ass, val->v_itvl_ds);
            break;

        case CT_TYPE_INTERVAL_YM:
            status = cm_adjust_yminterval(&val->v_itvl_ym, (uint32)knl_col->precision);
            CT_BREAK_IF_ERROR(status);
            status = row_put_yminterval(&row_ass, val->v_itvl_ym);
            break;

        case CT_TYPE_CHAR:
            status = sql_convert_char(KNL_SESSION(stmt), val, knl_col->size, KNL_COLUMN_IS_CHARACTER(knl_col));
            CT_BREAK_IF_ERROR(status);
            status = row_put_text(&row_ass, &val->v_text);
            break;

        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            if (KNL_COLUMN_IS_CHARACTER(knl_col)) {
                status = GET_DATABASE_CHARSET->length(&val->v_text, &value_len);
                CT_BREAK_IF_ERROR(status);
                if (val->v_text.len > CT_MAX_COLUMN_SIZE) { // check byte number should less than 'CT_MAX_COLUMN_SIZE'
                    CT_THROW_ERROR(ERR_EXCEED_MAX_FIELD_LEN, knl_col->name, val->v_text.len, CT_MAX_COLUMN_SIZE);
                    status = CT_ERROR;
                    break;
                }
            } else {
                value_len = val->v_text.len;
            }

            if (value_len > knl_col->size) {
                CT_THROW_ERROR(ERR_EXCEED_MAX_FIELD_LEN, knl_col->name, value_len, knl_col->size);
                status = CT_ERROR;
                break;
            }
            status = row_put_text(&row_ass, &val->v_text);
            break;

        default:
            CT_THROW_ERROR(ERR_VALUE_ERROR, "the data type of column is not supported");
            status = CT_ERROR;
            break;
    }

    if (status != CT_SUCCESS) {
        CTSQL_POP(stmt);
        return CT_ERROR;
    }

    cm_decode_row((char *)row_ass.head, &offset, &len, NULL);
    *size = len;
    errno_t errcode = memcpy_sp(ele_val, CT_MAX_COLUMN_SIZE, row_ass.buf + offset, len);
    if (errcode != EOK) {
        CTSQL_POP(stmt);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CT_ERROR;
    }

    CTSQL_POP(stmt);
    return status;
}

static status_t sql_convert_array_value(sql_stmt_t *stmt, knl_column_t *column, variant_t *value, variant_t *result)
{
    uint32 dir_vmid;
    uint32 data_type;
    vm_page_t *head_page = NULL;
    vm_page_t *dir_page = NULL;
    variant_t temp_val;
    char *ele_val = NULL;
    uint32 size;
    array_assist_t array_ass;
    array_assist_t dst_ass;
    vm_lob_t *src_vlob = NULL;
    vm_lob_t *dst_vlob = NULL;
    elem_dir_t dir;
    status_t status;

    result->type = CT_TYPE_ARRAY;
    result->is_null = CT_FALSE;
    result->v_array.type = (int16)column->datatype;
    result->v_array.value.type = CT_LOB_FROM_VMPOOL;
    result->v_array.count = 0;
    dst_vlob = &result->v_array.value.vm_lob;

    if (value->v_array.value.type == CT_LOB_FROM_KERNEL) {
        vm_lob_t vlob;
        vlob.node_id = 0;
        vlob.unused = 0;
        CT_RETURN_IFERR(sql_get_array_from_knl_lob(stmt, (knl_handle_t)(value->v_array.value.knl_lob.bytes), &vlob));
        value->v_array.value.vm_lob = vlob;
        value->v_array.value.type = CT_LOB_FROM_VMPOOL;
    }

    src_vlob = &value->v_array.value.vm_lob;
    ARRAY_INIT_ASSIST_INFO(&array_ass, stmt);
    if (vm_open(array_ass.session, array_ass.pool, src_vlob->entry_vmid, &head_page) != CT_SUCCESS) {
        return CT_ERROR;
    }
    array_ass.buf = head_page->data;
    /* can not use array_ass.head after the page is closed */
    array_ass.head = (array_head_t *)(head_page->data);
    array_ass.dir_curr = sizeof(array_head_t);
    array_ass.dir_end = sizeof(array_head_t) + array_ass.head->count * sizeof(elem_dir_t);
    data_type = array_ass.head->datatype;

    /* write the converted values (ele_val, size) to dst_vlob.
       because size after converted may great than origin value size for
       CT_TYPE_CHAR/CT_TYPE_BINARY type element. we should realloc vm lob
       to store the data after converted.
    */
    status = array_init(&dst_ass, array_ass.session, array_ass.pool, array_ass.list, dst_vlob);
    if (status != CT_SUCCESS) {
        vm_close(array_ass.session, array_ass.pool, src_vlob->entry_vmid, VM_ENQUE_TAIL);
        return status;
    }

    if (array_ass.head->count == 0) {
        if (array_update_head_datatype(&dst_ass, dst_vlob, column->datatype) != CT_SUCCESS) {
            vm_close(array_ass.session, array_ass.pool, src_vlob->entry_vmid, VM_ENQUE_TAIL);
            return CT_ERROR;
        }
        vm_close(array_ass.session, array_ass.pool, src_vlob->entry_vmid, VM_ENQUE_TAIL);
        return CT_SUCCESS;
    }

    vm_close(array_ass.session, array_ass.pool, src_vlob->entry_vmid, VM_ENQUE_TAIL);
    /* scroll all elements, convert if needed */
    while (array_ass.dir_curr < array_ass.dir_end) {
        /* get the element directory page */
        dir_vmid = array_get_vmid_by_offset(&array_ass, src_vlob, array_ass.dir_curr);
        if (dir_vmid == CT_INVALID_ID32) {
            return CT_ERROR;
        }
        if (vm_open(array_ass.session, array_ass.pool, dir_vmid, &dir_page) != CT_SUCCESS) {
            return CT_ERROR;
        }
        dir = *(elem_dir_t *)(dir_page->data + array_ass.dir_curr % CT_VMEM_PAGE_SIZE);
        vm_close(array_ass.session, array_ass.pool, dir_vmid, VM_ENQUE_TAIL);

        /* null elements, copy directly */
        if (dir.size == 0) {
            status = array_append_element(&dst_ass, dir.subscript, NULL, 0, ELEMENT_IS_NULL(&dir), dir.last, dst_vlob);
            if (status != CT_SUCCESS) {
                return CT_ERROR;
            }
            array_ass.dir_curr += sizeof(elem_dir_t);
            result->v_array.count++;
            continue;
        }

        if (sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&ele_val) != CT_SUCCESS) {
            return CT_ERROR;
        }
        /* get the element's value */
        size = dir.size;
        if (array_get_value_by_dir(&array_ass, ele_val, size, src_vlob, &dir) != CT_SUCCESS) {
            CTSQL_POP(stmt);
            return CT_ERROR;
        }
        /* convert & check value */
        if (sql_adjust_element_by_col(stmt, column, data_type, ele_val, &size, &temp_val) != CT_SUCCESS) {
            CTSQL_POP(stmt);
            return CT_ERROR;
        }

        status = array_append_element(&dst_ass, dir.subscript, ele_val, size, CT_FALSE, dir.last, dst_vlob);
        if (status != CT_SUCCESS) {
            CTSQL_POP(stmt);
            return CT_ERROR;
        }

        CTSQL_POP(stmt);
        if (status != CT_SUCCESS) {
            return CT_ERROR;
        }
        /* try to convert next element */
        array_ass.dir_curr += sizeof(elem_dir_t);
        result->v_array.count++;
    }

    /* update datatype after converted */
    return array_update_head_datatype(&dst_ass, dst_vlob, column->datatype);
}

static status_t sql_row_put_outline_array(sql_stmt_t *stmt, knl_cursor_t *knl_cur, row_assist_t *row_ass,
    knl_column_t *column, variant_t *value, uint32 real_size, uint32 head_offset)
{
    char *locator = NULL;
    binary_t lob;

    CT_RETURN_IFERR(sql_push(stmt, CT_LOB_LOCATOR_BUF_SIZE, (void **)&locator));
    MEMS_RETURN_IFERR(memset_s(locator, KNL_LOB_LOCATOR_SIZE, 0xFF, KNL_LOB_LOCATOR_SIZE));

    CT_RETURN_IFERR(sql_set_array_to_lob_locator(stmt, knl_cur, column, value, locator, real_size, head_offset));

    lob.size = knl_lob_locator_size((knl_handle_t)locator);
    lob.bytes = (uint8 *)locator;
    CT_RETURN_IFERR(row_put_bin(row_ass, &lob));

    if (!((lob_locator_t *)locator)->head.is_outline) {
        knl_cur->lob_inline_num++;
    }

    return CT_SUCCESS;
}

static status_t sql_put_array_value_to_row(sql_stmt_t *stmt, knl_cursor_t *knl_cur, row_assist_t *row_ass,
    knl_column_t *column, variant_t *value)
{
    status_t status;
    uint32 real_size = 0;
    uint32 head_offset = 0;
    handle_t session = KNL_SESSION(stmt);
    CT_RETURN_IFERR(array_actual_size(session, stmt->mtrl.pool, &value->v_array, &real_size, &head_offset));

    if (g_instance->sql.enable_arr_store_opt && real_size <= LOB_MAX_INLIINE_SIZE) {
        return sql_row_put_inline_array(stmt, row_ass, &value->v_array, real_size);
    }

    CTSQL_SAVE_STACK(stmt);
    status = sql_row_put_outline_array(stmt, knl_cur, row_ass, column, value, real_size, head_offset);
    CTSQL_RESTORE_STACK(stmt);

    return status;
}

static status_t sql_set_array_value_from_lob_var(sql_stmt_t *stmt, knl_cursor_t *knl_cur, row_assist_t *row_ass,
    knl_column_t *column, variant_t *value)
{
    variant_t result;

    if (!KNL_COLUMN_IS_ARRAY(column)) {
        CT_THROW_ERROR(ERR_COLUMN_DATA_TYPE, "array", column->name);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_convert_array_value(stmt, column, value, &result));
    return sql_put_array_value_to_row(stmt, knl_cur, row_ass, column, &result);
}

static status_t sql_convert_str_to_array(sql_stmt_t *stmt, knl_column_t *column, variant_t *value, variant_t *result)
{
    char *buffer = NULL;
    uint32 size;
    uint32 sub_script;
    status_t status;
    vm_lob_t *vlob = NULL;
    variant_t tmp_val;
    bool32 is_last = CT_FALSE;
    array_assist_t aa;
    text_t element_str = { NULL, 0 };
    text_t array_str = value->v_text;
    id_list_t *vm_list = sql_get_exec_lob_list(stmt);

    if (array_str_invalid(&array_str)) {
        CT_THROW_ERROR(ERR_INVALID_ARRAY_FORMAT);
        return CT_ERROR;
    }

    result->type = CT_TYPE_ARRAY;
    result->is_null = CT_FALSE;
    result->v_array.type = (int16)column->datatype;
    result->v_array.value.type = CT_LOB_FROM_VMPOOL;
    result->v_array.count = 0;
    vlob = &result->v_array.value.vm_lob;

    if (array_init(&aa, KNL_SESSION(stmt), stmt->mtrl.pool, vm_list, vlob) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* process null array */
    if (array_str_null(&array_str)) {
        if (array_update_head_datatype(&aa, vlob, column->datatype) != CT_SUCCESS) {
            return CT_ERROR;
        }
        result->v_array.count = 0;
        return CT_SUCCESS;
    }

    sql_keep_stack_variant(stmt, value);
    if (sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buffer) != CT_SUCCESS) {
        return CT_ERROR;
    }

    element_str.str = buffer;
    element_str.len = 0;
    sub_script = 1;

    status = array_get_element_str(&array_str, &element_str, &is_last);
    while (status == CT_SUCCESS) {
        /* convert & check value */
        size = element_str.len;
        if (cm_text_str_equal_ins(&element_str, "NULL")) {
            if (array_append_element(&aa, sub_script, NULL, 0, CT_TRUE, is_last, vlob) != CT_SUCCESS) {
                CTSQL_POP(stmt);
                return CT_ERROR;
            }
            /* get the next element */
            sub_script++;
            element_str.str = buffer;
            element_str.len = 0;
            result->v_array.count++;
            if (is_last) {
                break;
            }
            status = array_get_element_str(&array_str, &element_str, &is_last);
            continue;
        }
        if (sql_adjust_element_by_col(stmt, column, (uint32)(value->type), element_str.str, &size, &tmp_val) !=
            CT_SUCCESS) {
            CTSQL_POP(stmt);
            return CT_ERROR;
        }

        status = array_append_element(&aa, sub_script, element_str.str, size, CT_FALSE, is_last, vlob);
        if (status != CT_SUCCESS) {
            CTSQL_POP(stmt);
            return CT_ERROR;
        }

        if (is_last) {
            /* no more element */
            result->v_array.count++;
            break;
        }

        /* get the next element */
        sub_script++;
        element_str.str = buffer;
        element_str.len = 0;
        result->v_array.count++;
        status = array_get_element_str(&array_str, &element_str, &is_last);
    }

    CTSQL_POP(stmt);
    CT_RETURN_IFERR(status);

    return array_update_head_datatype(&aa, vlob, column->datatype);
}

static status_t sql_put_array_to_row(sql_stmt_t *stmt, knl_cursor_t *knl_cur, row_assist_t *row_ass, knl_column_t *column,
    variant_t *value)
{
    variant_t result;

    if (value->type != CT_TYPE_CHAR && value->type != CT_TYPE_VARCHAR && value->type != CT_TYPE_STRING) {
        CT_THROW_ERROR(ERR_COLUMN_DATA_TYPE, get_datatype_name_str(value->type), column->name);
        return CT_ERROR;
    }

    /* convert string like '{1, 2, 3}' to array type */
    if (sql_convert_str_to_array(stmt, column, value, &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_put_array_value_to_row(stmt, knl_cur, row_ass, column, &result);
}

static status_t sql_put_var_to_row(sql_stmt_t *stmt, knl_cursor_t *knl_cur, row_assist_t *row_ass, knl_column_t *column,
    variant_t *value)
{
    status_t status = CT_SUCCESS;
    int64 date_val;
    uint32 value_len;

    switch (column->datatype) {
        case CT_TYPE_UINT32:
            status = row_put_uint32(row_ass, value->v_uint32);
            break;
        case CT_TYPE_INTEGER:
            status = row_put_int32(row_ass, value->v_int);
            break;

        case CT_TYPE_BOOLEAN:
            status = row_put_bool(row_ass, value->v_bool);
            break;

        case CT_TYPE_BIGINT:
            status = row_put_int64(row_ass, value->v_bigint);
            break;

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
            CT_RETURN_IFERR(cm_adjust_dec(&value->v_dec, column->precision, column->scale));
            status = row_put_dec4(row_ass, &value->v_dec);
            break;

        case CT_TYPE_NUMBER2:
            CT_RETURN_IFERR(cm_adjust_dec(&value->v_dec, column->precision, column->scale));
            status = row_put_dec2(row_ass, &value->v_dec);
            break;

        case CT_TYPE_REAL:
            CT_RETURN_IFERR(cm_adjust_double(&value->v_real, column->precision, column->scale));
            status = row_put_real(row_ass, value->v_real);
            break;

        case CT_TYPE_DATE:
            date_val = cm_adjust_date(value->v_date);
            status = row_put_int64(row_ass, date_val);
            break;

        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
            CT_RETURN_IFERR(cm_adjust_timestamp(&value->v_tstamp, column->precision));
            status = row_put_int64(row_ass, value->v_tstamp);
            break;

        case CT_TYPE_TIMESTAMP_LTZ:
            CT_RETURN_IFERR(cm_adjust_timestamp(&value->v_tstamp, column->precision));
            status = row_put_int64(row_ass, value->v_tstamp);
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            CT_RETURN_IFERR(cm_adjust_timestamp_tz(&value->v_tstamp_tz, column->precision));
            status = row_put_timestamp_tz(row_ass, &value->v_tstamp_tz);
            break;

        case CT_TYPE_INTERVAL_DS:
            CT_RETURN_IFERR(cm_adjust_dsinterval(&value->v_itvl_ds, (uint32)column->precision, (uint32)column->scale));
            status = row_put_dsinterval(row_ass, value->v_itvl_ds);
            break;

        case CT_TYPE_INTERVAL_YM:
            CT_RETURN_IFERR(cm_adjust_yminterval(&value->v_itvl_ym, (uint32)column->precision));
            status = row_put_yminterval(row_ass, value->v_itvl_ym);
            break;

        case CT_TYPE_CHAR:
            CT_RETURN_IFERR(sql_convert_char(KNL_SESSION(stmt), value, column->size, KNL_COLUMN_IS_CHARACTER(column)));
            status = row_put_text(row_ass, &value->v_text);
            break;

        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            if (KNL_COLUMN_IS_CHARACTER(column)) {
                if (value->v_text.len > CT_MAX_COLUMN_SIZE) { // check byte number should less than 'CT_MAX_COLUMN_SIZE'
                    CT_THROW_ERROR(ERR_EXCEED_MAX_FIELD_LEN, column->name, value->v_text.len, CT_MAX_COLUMN_SIZE);
                    return CT_ERROR;
                }
                CT_RETURN_IFERR(sql_get_char_length(&value->v_text, &value_len, column->size));
            } else {
                value_len = value->v_text.len;
            }

            if (value_len > column->size) {
                CT_THROW_ERROR(ERR_EXCEED_MAX_FIELD_LEN, column->name, value_len, column->size);
                return CT_ERROR;
            }
            status = row_put_text(row_ass, &value->v_text);
            break;

        case CT_TYPE_BINARY:
            CT_RETURN_IFERR(sql_convert_bin(stmt, value, column->size));
            status = row_put_bin(row_ass, &value->v_bin);
            break;
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            if (value->v_bin.size > column->size) {
                CT_THROW_ERROR(ERR_EXCEED_MAX_FIELD_LEN, column->name, value->v_bin.size, column->size);
                return CT_ERROR;
            }

            status = row_put_bin(row_ass, &value->v_bin);
            break;

        case CT_TYPE_CLOB:
        case CT_TYPE_BLOB:
        case CT_TYPE_IMAGE:
            if (knl_cur != NULL) {
                status = sql_set_lob_value_from_normal(stmt, knl_cur, row_ass, column, value);
            }
            break;

        default:
            CT_THROW_ERROR(ERR_VALUE_ERROR, "the data type of column is not supported");
            status = CT_ERROR;
            break;
    }

    return status;
}

static status_t sql_put_column_to_row(sql_stmt_t *stmt, knl_cursor_t *knl_cur, row_assist_t *row_ass, knl_column_t *column,
    variant_t *value)
{
    if (KNL_COLUMN_IS_ARRAY(column)) {
        return sql_put_array_to_row(stmt, knl_cur, row_ass, column, value);
    } else if (value->type != column->datatype) {
        CT_RETURN_IFERR(sql_convert_variant(stmt, value, column->datatype));
    }

    return sql_put_var_to_row(stmt, knl_cur, row_ass, column, value);
}

static status_t sql_set_column_value_from_lob_var(sql_stmt_t *stmt, knl_cursor_t *knl_cur, row_assist_t *row_ass,
    knl_column_t *column, variant_t *value)
{
    if (CT_IS_LOB_TYPE(column->datatype)) {
        CT_RETURN_IFERR(sql_set_lob_value(stmt, knl_cur, row_ass, column, value));
    } else {
        CT_RETURN_IFERR(sql_get_lob_value(stmt, value));
        if (value->is_null) {
            if (!column->nullable) {
                knl_cur->vnc_column = column->name;
            }
            return row_put_null(row_ass);
        }

        CT_RETURN_IFERR(sql_put_column_to_row(stmt, knl_cur, row_ass, column, value));
    }

    return CT_SUCCESS;
}

status_t sql_set_jsonb_value(sql_stmt_t *stmt, knl_column_t *column, variant_t *value)
{
    if (!KNL_COLUMN_IS_JSONB(column)) {
        return CT_SUCCESS;
    }

    if (CT_IS_STRING_TYPE(value->type) || CT_IS_CLOB_TYPE(value->type)) {
        /* if it is jsonb col, must convert the value to jsonb type firstly. */
        CT_RETURN_IFERR(sql_convert_variant_to_jsonb(stmt, value));
    } else if (CT_IS_BINARY_TYPE(value->type) || CT_IS_BLOB_TYPE(value->type) || CT_IS_RAW_TYPE(value->type)) {
        /* if it is jsonb col, input non-string data, need to check its jsonb format. */
        CT_RETURN_IFERR(sql_valiate_jsonb_format(stmt, value));
    }

    return CT_SUCCESS;
}

status_t sql_set_table_value(sql_stmt_t *stmt, knl_cursor_t *knl_cur, row_assist_t *row_ass, knl_column_t *column,
    variant_t *value)
{
    if (value->is_null) {
        if (!column->nullable) {
            knl_cur->vnc_column = column->name;
        }

        return row_put_null(row_ass);
    }

    CT_RETURN_IFERR(sql_set_jsonb_value(stmt, column, value));

    if (CT_IS_LOB_TYPE(value->type)) {
        return sql_set_column_value_from_lob_var(stmt, knl_cur, row_ass, column, value);
    }

    if (value->type == CT_TYPE_ARRAY) {
        return sql_set_array_value_from_lob_var(stmt, knl_cur, row_ass, column, value);
    }

    return sql_put_column_to_row(stmt, knl_cur, row_ass, column, value);
}

static status_t sql_update_serial_value(sql_stmt_t *stmt, knl_handle_t entity, knl_column_t *column, variant_t *value)
{
    int64 tmp = 0;
    if (!(column->flags & KNL_COLUMN_FLAG_SERIAL)) {
        return CT_SUCCESS;
    }

    if (value->is_null) {
        value->is_null = CT_FALSE;
        value->v_bigint = 0;
        value->type = CT_TYPE_BIGINT;
    }

    if (value->type != column->datatype) {
        CT_RETURN_IFERR(sql_convert_variant(stmt, value, column->datatype));
    }

    if (column->datatype == CT_TYPE_BIGINT) {
        tmp = value->v_bigint;
    } else if (column->datatype == CT_TYPE_UINT32) {
        tmp = value->v_uint32;
    } else {
        tmp = value->v_int;
    }
    return knl_update_serial_value(&stmt->session->knl_session, entity, tmp, CT_FALSE);
}

static bool32 sql_update_type_match(int32 start, int32 end, int16 type, array_update_mode *mode)
{
    if (start > 0 && (end == CT_INVALID_ID32)) {
        *mode = ARRAY_UPDATE_POINT;
    } else {
        *mode = ARRAY_UPDATE_RANGE;
    }

    if (*mode == ARRAY_UPDATE_RANGE && type != CT_TYPE_ARRAY && type != CT_TYPE_CHAR) {
        CT_THROW_ERROR(ERR_TYPE_MISMATCH, "array", get_datatype_name_str(type));
        return CT_FALSE;
    }

    if (*mode == ARRAY_UPDATE_POINT && type == CT_TYPE_ARRAY) {
        CT_THROW_ERROR(ERR_TYPE_MISMATCH, get_datatype_name_str(type), "array");
        return CT_FALSE;
    }

    return CT_TRUE;
}

static status_t sql_update_element_by_range(sql_stmt_t *stmt, array_assist_t *aa, variant_t *value,
    column_value_pair_t *pair, vm_lob_t *vlob)
{
    uint32 size, sub_script, offset;
    int32 count, expect_count;
    variant_t tmp_var;
    vm_lob_t *tmp_vlob = NULL;
    char *data = NULL;

    if (pair->ss_start <= 0 || pair->ss_end < pair->ss_start) {
        return CT_ERROR;
    }

    sql_keep_stack_variant(stmt, value);

    if (value->type == CT_TYPE_CHAR || value->type == CT_TYPE_VARCHAR) {
        CT_RETURN_IFERR(sql_convert_str_to_array(stmt, pair->column, value, &tmp_var));
    } else if (value->type == CT_TYPE_ARRAY) {
        CT_RETURN_IFERR(sql_convert_array_value(stmt, pair->column, value, &tmp_var));
    } else {
        return CT_ERROR;
    }

    expect_count = pair->ss_end - pair->ss_start + 1;
    if (tmp_var.v_array.count != expect_count) {
        CT_THROW_ERROR(ERR_WRONG_ELEMENT_COUNT);
        return CT_ERROR;
    }

    sub_script = (uint32)(pair->ss_start);
    tmp_vlob = &tmp_var.v_array.value.vm_lob;
    for (count = 1; count <= expect_count; count++) {
        /* get the element value */
        offset = 0;
        CT_RETURN_IFERR(array_get_element_info(aa, &size, &offset, tmp_vlob, count));

        data = NULL;
        if (size > 0) {
            CT_RETURN_IFERR(sql_push(stmt, size, (void **)&data));

            if (array_get_element_by_subscript(aa, data, size, tmp_vlob, count) != CT_SUCCESS) {
                CTSQL_POP(stmt);
                return CT_ERROR;
            }
        }

        bool8 is_null = (size == 0 && offset == ELEMENT_NULL_OFFSET);
        CT_RETURN_IFERR(array_update_element_by_subscript(aa, data, size, is_null, sub_script, vlob));

        if (size > 0) {
            CTSQL_POP(stmt);
        }
        sub_script++;
    }

    return CT_SUCCESS;
}

static status_t sql_update_element_by_subscript(sql_stmt_t *stmt, array_assist_t *aa, variant_t *value,
    column_value_pair_t *pair, vm_lob_t *vlob)
{
    char *buf = NULL;
    uint16 offset;
    uint16 len;
    row_assist_t row_ass;

    if (value->is_null) {
        return array_update_element_by_subscript(aa, NULL, 0, CT_TRUE, pair->ss_start, vlob);
    }

    if (value->type != pair->column->datatype) {
        CT_RETURN_IFERR(sql_convert_variant(stmt, value, pair->column->datatype));
    }

    if (sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf) != CT_SUCCESS) {
        return CT_ERROR;
    }

    row_init(&row_ass, buf, CT_MAX_ROW_SIZE, 1);
    if (sql_put_var_to_row(stmt, NULL, &row_ass, pair->column, value) != CT_SUCCESS) {
        CTSQL_POP(stmt);
        return CT_ERROR;
    }

    cm_decode_row((char *)(row_ass.head), &offset, &len, NULL);
    if (array_update_element_by_subscript(aa, row_ass.buf + offset, len, CT_FALSE, pair->ss_start, vlob) != CT_SUCCESS) {
        CTSQL_POP(stmt);
        return CT_ERROR;
    }

    CTSQL_POP(stmt);
    return CT_SUCCESS;
}

/* update array field [start:end] by value */
static status_t sql_update_array_in_vm(sql_stmt_t *stmt, column_value_pair_t *pair, variant_t *value, variant_t *result,
    array_update_mode mode)
{
    status_t status;
    vm_lob_t *vlob = NULL;
    array_assist_t array_ass;

    ARRAY_INIT_ASSIST_INFO(&array_ass, stmt);
    vlob = &result->v_array.value.vm_lob;

    result->is_null = CT_FALSE;
    result->type = CT_TYPE_ARRAY;
    result->v_array.value.type = CT_LOB_FROM_VMPOOL;

    if (array_get_last_dir_end(&array_ass, vlob, &array_ass.dir_curr) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CTSQL_SAVE_STACK(stmt);

    if (mode == ARRAY_UPDATE_POINT) {
        status = sql_update_element_by_subscript(stmt, &array_ass, value, pair, vlob);
    } else { /* ARRAY_UPDATE_RANGE */
        status = sql_update_element_by_range(stmt, &array_ass, value, pair, vlob);
    }

    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static status_t sql_update_array_value(sql_stmt_t *stmt, knl_cursor_t *knl_cur, row_assist_t *row_ass,
    column_value_pair_t *pair, variant_t *value)
{
    uint32 len;
    variant_t res;
    knl_handle_t locator;
    vm_lob_t *vlob = NULL;
    array_assist_t array_ass;
    array_update_mode mode;
    id_list_t *vm_list = sql_get_exec_lob_list(stmt);

    if (!sql_update_type_match(pair->ss_start, pair->ss_end, value->type, &mode)) {
        return CT_ERROR;
    }

    /* get the origin array value to vm lob */
    vlob = &res.v_array.value.vm_lob;
    locator = (knl_handle_t)CURSOR_COLUMN_DATA(knl_cur, pair->column_id);
    len = CURSOR_COLUMN_SIZE(knl_cur, pair->column_id);
    if (len == CT_NULL_VALUE_LEN) {
        if (array_init(&array_ass, KNL_SESSION(stmt), stmt->mtrl.pool, vm_list, vlob) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if ((sql_get_array_from_knl_lob(stmt, locator, vlob) != CT_SUCCESS)) {
            return CT_ERROR;
        }
    }

    /* update the array value in vm lob */
    if (sql_update_array_in_vm(stmt, pair, value, &res, mode) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ARRAY_INIT_ASSIST_INFO(&array_ass, stmt);
    /* update the array count in result */
    if (array_get_element_count(&array_ass, vlob, &res.v_array.count) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* update the array datatype in result */
    if (array_get_element_datatype(&array_ass, vlob, &res.v_array.type) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* write to row buf */
    return sql_put_array_value_to_row(stmt, knl_cur, row_ass, pair->column, &res);
}

static status_t sql_get_multi_subquery_result(sql_stmt_t *stmt, update_assist_t *update_ass, expr_tree_t *expr,
                                              uint32 rs_no)
{
    uint32 sub_id = expr->root->value.v_obj.id;

    if (update_ass->rs_values[sub_id] == NULL) {
        variant_t *values = NULL;
        uint32 n_rs = ((sql_select_t *)expr->root->value.v_obj.ptr)->first_query->rs_columns->count;

        CT_RETURN_IFERR(sql_push(stmt, sizeof(variant_t) * n_rs, (void **)&values));

        CT_RETURN_IFERR(sql_exec_expr(stmt, expr, values));
        for (uint32 i = 0; i < n_rs; i++) {
            sql_keep_stack_variant(stmt, &values[i]);
        }

        update_ass->rs_values[sub_id] = values;
    }

    // get update value
    update_ass->value = update_ass->rs_values[sub_id][rs_no - 1];
    return CT_SUCCESS;
}

static status_t sql_fill_update_row(sql_stmt_t *stmt, knl_cursor_t *knl_cur, column_value_pair_t *pair,
    update_assist_t *update_ass)
{
    knl_dictionary_t *dc = &update_ass->object->table->entry->dc;
    knl_update_info_t *update_info = &knl_cur->update_info;

    CT_RETURN_IFERR(sql_update_serial_value(stmt, dc->handle, pair->column, &update_ass->value));

    if (KNL_COLUMN_IS_ARRAY(pair->column) && pair->ss_start > 0) {
        CT_RETURN_IFERR(sql_update_array_value(stmt, knl_cur, &update_ass->ra, pair, &update_ass->value));
    } else {
        CT_RETURN_IFERR(sql_set_table_value(stmt, knl_cur, &update_ass->ra, pair->column, &update_ass->value));
    }

    update_info->columns[update_ass->pair_id] = pair->column_id;
    return CT_SUCCESS;
}

status_t sql_keep_vmc_variant(sql_stmt_t *stmt, variant_t *var)
{
    char *buf = NULL;

    if (var->is_null) {
        return CT_SUCCESS;
    }

    if (CT_IS_VARLEN_TYPE(var->type) && var->v_text.len > 0) {
        CT_RETURN_IFERR(vmc_alloc(&stmt->vmc, var->v_text.len, (void **)&buf));
        MEMS_RETURN_IFERR(memcpy_sp(buf, var->v_text.len, var->v_text.str, var->v_text.len));
        var->v_text.str = buf;
    } else if (CT_IS_LOB_TYPE(var->type)) {
        if (var->v_lob.type == CT_LOB_FROM_KERNEL) {
            if (var->v_lob.knl_lob.size > 0) {
                CT_RETURN_IFERR(vmc_alloc(&stmt->vmc, var->v_lob.knl_lob.size, (void **)&buf));
                MEMS_RETURN_IFERR(
                    memcpy_sp(buf, var->v_lob.knl_lob.size, (char *)var->v_lob.knl_lob.bytes, var->v_lob.knl_lob.size));
            }
            var->v_lob.knl_lob.bytes = (uint8 *)buf;
        } else if (var->v_lob.type == CT_LOB_FROM_NORMAL) {
            if (var->v_lob.normal_lob.value.len > 0) {
                CT_RETURN_IFERR(vmc_alloc(&stmt->vmc, var->v_lob.normal_lob.value.len, (void **)&buf));
                MEMS_RETURN_IFERR(memcpy_sp(buf, var->v_lob.normal_lob.value.len, var->v_lob.normal_lob.value.str,
                    var->v_lob.normal_lob.value.len));
            }
            var->v_lob.normal_lob.value.str = buf;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_get_fexec_subquery_result(sql_stmt_t *stmt, update_assist_t *update_ass, expr_tree_t *expr,
    uint32 rs_no)
{
    uint16 pair_id = update_ass->pair_id;

    if (stmt->fexec_info.first_exec_subs[pair_id] == NULL) {
        uint32 sub_id = expr->root->value.v_obj.id;

        if (update_ass->rs_values[sub_id] == NULL) {
            variant_t *values = NULL;
            uint32 n_rs = ((sql_select_t *)expr->root->value.v_obj.ptr)->first_query->rs_columns->count;

            CT_RETURN_IFERR(vmc_alloc(&stmt->vmc, sizeof(variant_t) * n_rs, (void **)&values));
            MEMS_RETURN_IFERR(memset_s(values, sizeof(variant_t) * n_rs, 0, sizeof(variant_t) * n_rs));

            CT_RETURN_IFERR(sql_exec_expr(stmt, expr, values));
            for (uint32 i = 0; i < n_rs; i++) {
                CT_RETURN_IFERR(sql_keep_vmc_variant(stmt, &values[i]));
            }

            update_ass->rs_values[sub_id] = values;
        }

        stmt->fexec_info.first_exec_subs[pair_id] = &update_ass->rs_values[sub_id][rs_no > 0 ? rs_no - 1 : 0];
    }

    // get update value
    update_ass->value = *(stmt->fexec_info.first_exec_subs[pair_id]);
    return CT_SUCCESS;
}

static inline status_t sql_can_sub_fexec_optimize(expr_tree_t *expr)
{
    if (expr->root->type != EXPR_NODE_SELECT) {
        return CT_FALSE;
    }

    sql_select_t *select_ctx = (sql_select_t *)expr->root->value.v_obj.ptr;
    return (select_ctx->is_update_value && select_ctx->can_sub_opt);
}

status_t sql_try_construct_update_data(sql_stmt_t *stmt, knl_cursor_t *knl_cur, update_assist_t *update_ass)
{
    column_value_pair_t *pair = (column_value_pair_t *)cm_galist_get(update_ass->object->pairs, update_ass->pair_id);
    expr_tree_t *expr = (expr_tree_t *)cm_galist_get(pair->exprs, 0);

    stmt->default_column = pair->column;

    /* "update t1 set f1=(select xx),(f2,f3)=(select xx)", subquery can do first execution optimized */
    if (stmt->fexec_info.first_exec_subs != NULL && sql_can_sub_fexec_optimize(expr) == CT_TRUE) {
        CT_RETURN_IFERR(sql_get_fexec_subquery_result(stmt, update_ass, expr, pair->rs_no));
        return sql_fill_update_row(stmt, knl_cur, pair, update_ass);
    }

    /* "update t1 set (f1, f2)=(select xx), update columns reference to subquery is multi" */
    if (PAIR_IN_MULTI_SET(pair)) {
        CT_RETURN_IFERR(sql_get_multi_subquery_result(stmt, update_ass, expr, pair->rs_no));
        return sql_fill_update_row(stmt, knl_cur, pair, update_ass);
    }

    /* normal update */
    CTSQL_SAVE_STACK(stmt);
    if (sql_exec_expr(stmt, expr, &update_ass->value) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    sql_keep_stack_variant(stmt, &update_ass->value);
    if (sql_fill_update_row(stmt, knl_cur, pair, update_ass) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    CTSQL_RESTORE_STACK(stmt);
    return CT_SUCCESS;
}

status_t sql_generate_update_data(sql_stmt_t *stmt, knl_cursor_t *knl_cur, update_assist_t *update_ass)
{
    knl_dictionary_t *dc = &update_ass->object->table->entry->dc;
    knl_update_info_t *update_info = &knl_cur->update_info;
    uint32 max_row_len;
    int32 code;
    const char *msg = NULL;
    bool32 is_csf;

    knl_cur->vnc_column = NULL;
    knl_cur->lob_inline_num = 0;

    /* why to be push memory need to confirm */
    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_STRING_LEN, (void **)&update_ass->value.v_text.str));

    /* init update row */
    update_info->count = update_ass->object->pairs->count;
    max_row_len = knl_table_max_row_len(dc->handle, g_instance->kernel.attr.max_row_size, knl_cur->part_loc);
    is_csf = knl_is_table_csf(dc->handle, knl_cur->part_loc);
    cm_row_init(&update_ass->ra, update_info->data, max_row_len, update_info->count, is_csf);

    CTSQL_SAVE_STACK(stmt);
    while (update_ass->pair_id < update_info->count) {
        if (sql_try_construct_update_data(stmt, knl_cur, update_ass) != CT_SUCCESS) {
            // all update information should be putted to row buffer.
            cm_get_error(&code, &msg, NULL);
            if (code != ERR_ROW_SIZE_TOO_LARGE) {
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
            }

            if (knl_is_lob_table(dc) && knl_cur->lob_inline_num > 0) {
                cm_decode_row(update_info->data, update_info->offsets, update_info->lens, NULL);

                if (knl_reconstruct_lob_update_info(&stmt->session->knl_session, dc, knl_cur, update_ass->pair_id - 1) !=
                    CT_SUCCESS) {
                    CTSQL_RESTORE_STACK(stmt);
                    return CT_ERROR;
                }

                cm_reset_error();
                continue;
            } else {
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
            }
        }

        update_ass->pair_id++;
    }

    row_end(&update_ass->ra);

    // all update information should be putted to row buffer.
    CTSQL_RESTORE_STACK(stmt);

    cm_decode_row(update_info->data, update_info->offsets, update_info->lens, NULL);
    return CT_SUCCESS;
}

bool32 sql_find_trigger_column(galist_t *update_pairs, galist_t *trigger_col)
{
    column_value_pair_t *pair = NULL;
    trigger_column_t *column = NULL;
    uint32 i, j;

    if (trigger_col->count == 0) {
        return CT_TRUE; // trig update: all cols
    }

    for (i = 0; i < update_pairs->count; ++i) {
        pair = (column_value_pair_t *)cm_galist_get(update_pairs, i);

        for (j = 0; j < trigger_col->count; ++j) {
            column = (trigger_column_t *)cm_galist_get(trigger_col, j);
            if (pair->column_id == column->id) {
                return CT_TRUE;
            }
        }
    }

    return CT_FALSE;
}

status_t sql_execute_update_trigs(sql_stmt_t *stmt, trig_set_t *set, uint32 type, knl_cursor_t *knl_cur,
                                  upd_object_t *object)
{
    pl_dc_t pl_dc;
    trig_item_t *items = NULL;
    trig_desc_t *descs = NULL;

    CTSQL_SAVE_STACK(stmt);
    for (uint32 i = 0; i < set->trig_count; ++i) {
        items = &set->items[i];
        if (!items->trig_enable) {
            continue;
        }

        if ((uint32)items->trig_type != type || (items->trig_event & TRIG_EVENT_UPDATE) == 0) {
            continue;
        }

        if (pl_dc_open_trig_by_entry(stmt, &pl_dc, items) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
        descs = &pl_dc.entity->trigger->desc;

        if (!sql_find_trigger_column(object->pairs, &descs->columns)) {
            pl_dc_close(&pl_dc);
            continue;
        }

        if (ple_exec_trigger(stmt, pl_dc.entity, TRIG_EVENT_UPDATE, knl_cur, object) != CT_SUCCESS) {
            ple_check_exec_trigger_error(stmt, pl_dc.entity);
            pl_dc_close(&pl_dc);
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
        pl_dc_close(&pl_dc);
    }

    CTSQL_RESTORE_STACK(stmt);
    return CT_SUCCESS;
}


status_t sql_execute_update_view_insteadof(sql_stmt_t *stmt, sql_table_cursor_t *table_cur, upd_object_t *object)
{
    knl_cursor_t *knl_cur = NULL;
    status_t status = CT_ERROR;
    sql_cursor_t *sql_cur_save = NULL;
    update_assist_t update_ass;

    CTSQL_SAVE_STACK(stmt);
    CT_RETURN_IFERR(sql_alloc_knl_cursor(stmt, &knl_cur));
    if (sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&knl_cur->row) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    if (sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&knl_cur->update_info.data) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(sql_init_update_assist(&update_ass, object));
    sql_cur_save = table_cur->sql_cur;
    do {
        CT_BREAK_IF_ERROR(sql_prepare_view_row_insteadof(stmt, table_cur, knl_cur));
        table_cur->table->type = NORMAL_TABLE;
        table_cur->knl_cur = knl_cur;
        CT_BREAK_IF_ERROR(sql_generate_update_data(stmt, knl_cur, &update_ass));
        CT_BREAK_IF_ERROR(sql_insteadof_triggers(stmt, table_cur->table, knl_cur, object, TRIG_EVENT_UPDATE));
        status = CT_SUCCESS;
    } while (0);
    table_cur->sql_cur = sql_cur_save;
    table_cur->table->type = VIEW_AS_TABLE;
    sql_free_knl_cursor(stmt, knl_cur);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}


static inline status_t sql_try_execute_update_table(sql_stmt_t *stmt, sql_cursor_t *cursor, knl_cursor_t *knl_cur,
    upd_object_t *object)
{
    if (object->table->type == VIEW_AS_TABLE) {
        sql_table_cursor_t *table_cur = &cursor->tables[object->table->id];
        return sql_execute_update_view_insteadof(stmt, table_cur, object);
    }

    CTSQL_SAVE_STACK(stmt);

    update_assist_t update_ass;
    CT_RETURN_IFERR(sql_init_update_assist(&update_ass, object));
    if (sql_generate_update_data(stmt, knl_cur, &update_ass) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        stmt->default_column = NULL;
        return CT_ERROR;
    }

    CTSQL_RESTORE_STACK(stmt);

    stmt->default_column = NULL;

    CT_RETURN_IFERR(sql_execute_update_triggers(stmt, TRIG_BEFORE_EACH_ROW, knl_cur, object));
    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    if (knl_update(&stmt->session->knl_session, knl_cur) != CT_SUCCESS) {
        SQL_CURSOR_POP(stmt);
        return CT_ERROR;
    }
    SQL_CURSOR_POP(stmt);
    CT_RETURN_IFERR(sql_execute_update_triggers(stmt, TRIG_AFTER_EACH_ROW, knl_cur, object));
    CT_RETURN_IFERR(knl_verify_ref_integrities(&stmt->session->knl_session, knl_cur));
    CT_RETURN_IFERR(knl_verify_children_dependency(&stmt->session->knl_session, knl_cur, false, 0));
    return CT_SUCCESS;
}

inline status_t sql_execute_update_table(sql_stmt_t *stmt, sql_cursor_t *cursor, knl_cursor_t *knl_cur,
    upd_object_t *object)
{
    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&knl_cur->update_info.data));
    status_t status = sql_try_execute_update_table(stmt, cursor, knl_cur, object);
    CTSQL_POP(stmt);
    return status;
}

static inline status_t sql_execute_update_tables(sql_stmt_t *stmt, sql_cursor_t *cursor, update_plan_t *update_p,
    knl_cursor_t **knl_curs)
{
    status_t status;
    upd_object_t *object = NULL;
    sql_table_cursor_t *table_cur = NULL;
    knl_cursor_t *knl_cur = NULL;
    knl_savepoint_t sp;

    for (uint32 i = 0; i < update_p->objects->count; i++) {
        object = (upd_object_t *)cm_galist_get(update_p->objects, i);
        table_cur = &cursor->tables[object->table->id];

        if (table_cur->knl_cur->eof ||
            sql_is_invalid_rowid(&table_cur->knl_cur->rowid, table_cur->table->entry->dc.type)) {
            continue;
        }
        // for before row trigger
        knl_savepoint(KNL_SESSION(stmt), &sp);
        // function based index may access the data by sql_cur->tab_cur->knl_cur
        knl_cur = table_cur->knl_cur;
        table_cur->knl_cur = (table_cur->hash_table ? knl_curs[object->table->id] : table_cur->knl_cur);
        status = sql_execute_update_table(stmt, cursor, table_cur->knl_cur, object);
        table_cur->knl_cur = knl_cur;
        CHECK_ERR_ROW_SELF_UPDATED(status, update_p->check_self_update, sp);
        cursor->total_rows++;
    }
    return CT_SUCCESS;
}

static inline uint16 sql_checkin_update_set_list(knl_update_info_t *update_info, uint16 column_id)
{
    for (uint16 i = 0; i < update_info->count; i++) {
        if (column_id == update_info->columns[i]) {
            return i;
        }
    }

    return CT_INVALID_ID16;
}

static status_t sql_gen_update_all_values(sql_stmt_t *stmt, knl_cursor_t *knl_cur, upd_object_t *upd_obj)
{
    knl_dictionary_t *dc = &upd_obj->table->entry->dc;
    uint32 col_count = knl_get_column_count(dc->handle);
    knl_column_t *knl_col = NULL;
    var_column_t v_col;
    uint32 i;
    variant_t row_value, value;
    uint16 idx;

    /* keep stack of update row */
    row_value.type = CT_TYPE_STRING;
    row_value.is_null = CT_FALSE;
    row_value.v_text.str = knl_cur->update_info.data;
    row_value.v_text.len = ((row_head_t *)knl_cur->update_info.data)->size;
    sql_keep_stack_variant(stmt, &row_value);
    /* generate all column values by dc order */
    CT_RETURN_IFERR(sql_push(stmt, col_count * sizeof(variant_t), (void **)&stmt->default_info.default_values));

    for (i = 0; i < col_count; i++) {
        knl_col = dc_get_column((dc_entity_t *)dc->handle, (uint16)i);
        v_col.datatype = knl_col->datatype;
        v_col.col = (uint16)knl_col->id;
        v_col.is_array = CT_FALSE;

        idx = sql_checkin_update_set_list(&knl_cur->update_info, (uint16)i);
        if (idx != CT_INVALID_ID16) {
            CT_RETURN_IFERR(sql_get_row_value(stmt, knl_cur->update_info.data + knl_cur->update_info.offsets[idx],
                knl_cur->update_info.lens[idx], &v_col, &value, CT_FALSE));
        } else {
            CT_RETURN_IFERR(sql_get_kernel_value(stmt, upd_obj->table, knl_cur, &v_col, &value));
        }

        CT_RETURN_IFERR(sql_update_default_values(stmt, i, &value));
    }

    return CT_SUCCESS;
}

static status_t sql_send_update_return_row(sql_stmt_t *stmt, knl_cursor_t *knl_cur, upd_object_t *upd_obj,
    galist_t *ret_columns)
{
    status_t status = CT_SUCCESS;

    CTSQL_SAVE_STACK(stmt);

    do {
        status = sql_gen_update_all_values(stmt, knl_cur, upd_obj);
        CT_BREAK_IF_ERROR(status);

        stmt->default_info.default_on = CT_TRUE;
        status = sql_send_return_row(stmt, ret_columns, CT_FALSE);
        stmt->default_info.default_on = CT_FALSE;
    } while (0);

    CTSQL_RESTORE_STACK(stmt);

    return status;
}

static inline status_t sql_init_update_fexec_optimize(sql_stmt_t *stmt, uint32 pairs_count)
{
    uint32 mem_size = sizeof(void *) * pairs_count;
    CT_RETURN_IFERR(vmc_alloc(&stmt->vmc, mem_size, (void **)&stmt->fexec_info.first_exec_subs));
    (void)memset_s(stmt->fexec_info.first_exec_subs, mem_size, 0, mem_size);
    return CT_SUCCESS;
}

static status_t sql_execute_single_update(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan,
    update_plan_t *update_p, sql_update_t *update_ctx)
{
    upd_object_t *upd_obj = (upd_object_t *)cm_galist_get(update_p->objects, 0);
    sql_table_cursor_t *table_cur = &cursor->tables[0];

    CT_RETURN_IFERR(sql_init_update_fexec_optimize(stmt, upd_obj->pairs->count));

    do {
        CT_RETURN_IFERR(sql_fetch_query(stmt, cursor, plan, &cursor->eof));
        if (cursor->eof) {
            /* return columns need has one row in PL */
            if (update_ctx->ret_columns != NULL && stmt->batch_rows == 0) {
                CT_RETURN_IFERR(sql_send_return_row(stmt, update_ctx->ret_columns, CT_TRUE));
            }
            return CT_SUCCESS;
        }

        CT_RETURN_IFERR(sql_execute_update_table(stmt, cursor, table_cur->knl_cur, upd_obj));
        cursor->total_rows++;

        /* gen return values if has return columns */
        if (update_ctx->ret_columns != NULL) {
            CT_RETURN_IFERR(sql_send_update_return_row(stmt, table_cur->knl_cur, upd_obj, update_ctx->ret_columns));
        }
    } while (CT_TRUE);

    return CT_SUCCESS;
}

status_t sql_execute_multi_update(sql_stmt_t *stmt, sql_cursor_t *cursor, cond_tree_t *cond, plan_node_t *plan,
    update_plan_t *update_p)
{
    status_t status = CT_ERROR;
    bool32 is_found = CT_FALSE;
    cond_tree_t *saved_cond = cursor->cond;
    knl_cursor_t *knl_curs[CT_MAX_JOIN_TABLES] = { 0 };

    CT_RETURN_IFERR(sql_init_multi_update(stmt, cursor, CURSOR_ACTION_UPDATE, knl_curs));

    CTSQL_SAVE_STACK(stmt);
    do {
        CTSQL_RESTORE_STACK(stmt);
        CT_BREAK_IF_ERROR(sql_fetch_query(stmt, cursor, plan, &cursor->eof));
        if (cursor->eof) {
            status = CT_SUCCESS;
            break;
        }
        cursor->cond = cond;
        CT_BREAK_IF_ERROR(sql_lock_row(stmt, cursor, knl_curs, CURSOR_ACTION_UPDATE, &is_found));
        if (is_found) {
            CT_BREAK_IF_ERROR(sql_execute_update_tables(stmt, cursor, update_p, knl_curs));
        }
        sql_reset_cursor_action(cursor, CURSOR_ACTION_FOR_UPDATE_SCAN);
        cursor->cond = saved_cond;
    } while (CT_TRUE);

    if (status != CT_SUCCESS && (CT_ERRNO == ERR_ROW_SELF_UPDATED && update_p->check_self_update)) {
        cm_reset_error();
        CT_THROW_ERROR(ERR_TOO_MANY_ROWS);
    }

    cursor->cond = saved_cond;
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static status_t sql_execute_lock_row_multi(sql_stmt_t *stmt, sql_cursor_t *cursor, cond_tree_t *cond, plan_node_t *plan)
{
    status_t status = CT_ERROR;
    bool32 is_found = CT_FALSE;
    cond_tree_t *saved_cond = cursor->cond;
    knl_cursor_t *knl_curs[CT_MAX_JOIN_TABLES] = { 0 };

    CT_RETURN_IFERR(sql_init_multi_update(stmt, cursor, CURSOR_ACTION_UPDATE, knl_curs));

    cursor->cond = NULL;
    CTSQL_SAVE_STACK(stmt);

    do {
        CTSQL_RESTORE_STACK(stmt);
        CT_BREAK_IF_ERROR(sql_fetch_query(stmt, cursor, plan, &cursor->eof));
        if (cursor->eof) {
            status = CT_SUCCESS;
            break;
        }
        cursor->cond = cond;

        CT_BREAK_IF_ERROR(sql_lock_row(stmt, cursor, knl_curs, CURSOR_ACTION_UPDATE, &is_found));
        sql_reset_cursor_action(cursor, CURSOR_ACTION_FOR_UPDATE_SCAN);
        cursor->cond = saved_cond;
    } while (CT_TRUE);

    cursor->cond = saved_cond;
    CTSQL_RESTORE_STACK(stmt);

    return status;
}


static status_t sql_execute_lock_row_single(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    sql_reset_cursor_action(cursor, CURSOR_ACTION_UPDATE);

    do {
        CT_RETURN_IFERR(sql_fetch_query(stmt, cursor, plan, &cursor->eof));

        if (cursor->eof) {
            return CT_SUCCESS;
        }
    } while (CT_TRUE);

    return CT_SUCCESS;
}

status_t sql_execute_lock_row(sql_stmt_t *stmt, sql_cursor_t *cursor, cond_tree_t *cond, plan_node_t *plan,
    sql_query_t *query)
{
    if (query->tables.count > 1) {
        return sql_execute_lock_row_multi(stmt, cursor, cond, plan);
    } else {
        return sql_execute_lock_row_single(stmt, cursor, plan);
    }

    return CT_SUCCESS;
}

static inline status_t sql_execute_update_restart_core(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan,
    sql_update_t *update_ctx)
{
    sql_set_scn(stmt);
    sql_set_ssn(stmt);

    CT_RETURN_IFERR(sql_open_update_cursor(stmt, cursor, update_ctx));

    CT_RETURN_IFERR(sql_execute_query_plan(stmt, cursor, plan));

    CT_RETURN_IFERR(sql_execute_lock_row(stmt, cursor, update_ctx->cond, plan, update_ctx->query));

    return CT_SUCCESS;
}

status_t sql_execute_update_restart(sql_stmt_t *stmt)
{
    uint32 count = 0;
    status_t status = CT_ERROR;
    sql_cursor_t *cursor = CTSQL_ROOT_CURSOR(stmt);
    sql_update_t *update_ctx = (sql_update_t *)stmt->context->entry;
    update_plan_t *update_p = &update_ctx->plan->update_p;
    plan_node_t *plan = update_p->next->query.next;

    CTSQL_SAVE_STACK(stmt);

    for (;;) {
        CTSQL_RESTORE_STACK(stmt);
        count++;

        status = sql_execute_update_restart_core(stmt, cursor, plan, update_ctx);
        if (status == CT_ERROR && cm_get_error_code() == ERR_NEED_RESTART) {
            cm_reset_error();
            CT_LOG_DEBUG_INF("update lock row failed, lock row restart %u time(s), sid[%u] rmid[%u]", count,
                stmt->session->knl_session.id, stmt->session->knl_session.rmid);
            continue;
        } else {
            break;
        }
    }

    CTSQL_RESTORE_STACK(stmt);

    return status;
}

static status_t sql_execute_update_core(sql_stmt_t *stmt)
{
    plan_node_t *plan = NULL;
    sql_update_t *update_ctx = NULL;
    sql_cursor_t *cur = CTSQL_ROOT_CURSOR(stmt);
    update_plan_t *update_plan = NULL;
    knl_update_info_t *old_ui = NULL;
    status_t status = CT_ERROR;
    uint64 conflicts = 0;

    cur->total_rows = 0;
    update_ctx = (sql_update_t *)stmt->context->entry;
    update_plan = &update_ctx->plan->update_p;
    plan = update_plan->next->query.next;
    knl_init_index_conflicts(KNL_SESSION(stmt), &conflicts);
    CT_RETURN_IFERR(sql_execute_update_stmt_trigs(stmt, update_plan, TRIG_BEFORE_STATEMENT));

    // set statement ssn after the before statement triggers executed
    sql_set_scn(stmt);
    sql_set_ssn(stmt);
    old_ui = KNL_SESSION(stmt)->trig_ui;
    CM_SAVE_STACK(KNL_SESSION(stmt)->stack);
    do {
        // new update_info need push memory from stack if execute update statement in trigger,
        // and save the old update_info address.
        knl_update_info_t update_info;
        if (stmt->is_sub_stmt && (stmt->pl_exec != NULL && ((pl_executor_t *)stmt->pl_exec)->trig_exec != NULL)) {
            uint16 col_cnt = KNL_SESSION(stmt)->kernel->attr.max_column_count;
            CT_BREAK_IF_ERROR(sql_push(stmt, col_cnt * sizeof(uint16), (void **)&update_info.columns));
            CT_BREAK_IF_ERROR(sql_push(stmt, col_cnt * sizeof(uint16), (void **)&update_info.offsets));
            CT_BREAK_IF_ERROR(sql_push(stmt, col_cnt * sizeof(uint16), (void **)&update_info.lens));
            KNL_SESSION(stmt)->trig_ui = &update_info;
        }

        CT_BREAK_IF_ERROR(sql_open_update_cursor(stmt, cur, update_ctx));

        CT_BREAK_IF_ERROR(sql_execute_query_plan(stmt, cur, plan));

        if (update_ctx->query->tables.count > 1) {
            CT_BREAK_IF_ERROR(sql_execute_multi_update(stmt, cur, update_ctx->cond, plan, update_plan));
        } else {
            CT_BREAK_IF_ERROR(sql_execute_single_update(stmt, cur, plan, update_plan, update_ctx));
        }

        CT_BREAK_IF_ERROR(sql_execute_update_stmt_trigs(stmt, update_plan, TRIG_AFTER_STATEMENT));

        CT_BREAK_IF_ERROR(knl_check_index_conflicts(KNL_SESSION(stmt), conflicts));
        status = CT_SUCCESS;
    } while (0);

    CM_RESTORE_STACK(KNL_SESSION(stmt)->stack);
    KNL_SESSION(stmt)->trig_ui = old_ui;

    stmt->eof = CT_TRUE;
    return status;
}

status_t sql_execute_update(sql_stmt_t *stmt)
{
    status_t status = CT_ERROR;
    knl_savepoint_t sp;

    do {
        knl_savepoint(KNL_SESSION(stmt), &sp);
        status = sql_execute_update_core(stmt);
        // execute update failed when shrink table, need restart
        if (status == CT_ERROR && cm_get_error_code() == ERR_NEED_RESTART) {
            CT_LOG_RUN_INF("update failed when shrink table, update restart, sid[%u] rmid[%u]",
                stmt->session->knl_session.id, stmt->session->knl_session.rmid);
            cm_reset_error();
            knl_rollback(KNL_SESSION(stmt), &sp);
            CT_BREAK_IF_ERROR(sql_execute_update_restart(stmt));
            sql_set_scn(stmt);
            continue;
        } else {
            break;
        }
    } while (CT_TRUE);

    return status;
}

#ifdef __cplusplus
}
#endif
