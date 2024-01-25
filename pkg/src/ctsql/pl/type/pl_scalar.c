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
 * pl_scalar.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/type/pl_scalar.c
 *
 * -------------------------------------------------------------------------
 */

#include "pl_scalar.h"
#include "srv_instance.h"

static status_t udt_check_varlen_type_size(typmode_t *cmode, variant_t *pvar)
{
    uint32 value_len;
    switch (cmode->datatype) {
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            if (cmode->is_char) {
                CT_RETURN_IFERR(GET_DATABASE_CHARSET->length(&pvar->v_text, &value_len));
                if (pvar->v_text.len > CT_MAX_COLUMN_SIZE) {
                    CT_THROW_ERROR(ERR_VALUE_ERROR, "character string buffer too small");
                    return CT_ERROR;
                }
            } else {
                value_len = pvar->v_text.len;
            }
            if (!pvar->is_null && value_len > cmode->size) {
                CT_THROW_ERROR(ERR_VALUE_ERROR, "character string buffer too small");
                return CT_ERROR;
            }
            break;

        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            if (!pvar->is_null && pvar->v_bin.size > cmode->size) {
                CT_THROW_ERROR(ERR_VALUE_ERROR, "binary buffer too small");
                return CT_ERROR;
            }
            break;

        default:
            break;
    }
    return CT_SUCCESS;
}

static status_t udt_adjust_scalar_by_type(sql_verifier_t *verf, typmode_t *cmode, expr_tree_t *tree, variant_t *pvar)
{
    status_t status = CT_SUCCESS;
    switch (cmode->datatype) {
        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
            status = cm_adjust_dec(&pvar->v_dec, cmode->precision, cmode->scale);
            break;

        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
            status = cm_adjust_timestamp(&pvar->v_tstamp, cmode->precision);
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            status = cm_adjust_timestamp_tz(&pvar->v_tstamp_tz, cmode->precision);
            break;

        case CT_TYPE_INTERVAL_DS:
            status = cm_adjust_dsinterval(&pvar->v_itvl_ds, (uint32)cmode->day_prec, (uint32)cmode->frac_prec);
            break;

        case CT_TYPE_INTERVAL_YM:
            status = cm_adjust_yminterval(&pvar->v_itvl_ym, (uint32)cmode->year_prec);
            break;

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            status = udt_check_varlen_type_size(cmode, pvar);
            break;

        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BOOLEAN:
        case CT_TYPE_BIGINT:
        case CT_TYPE_REAL:
        case CT_TYPE_DATE:
            return CT_SUCCESS;

        case CT_TYPE_CLOB:
        case CT_TYPE_BLOB:
        case CT_TYPE_IMAGE:
            return CT_SUCCESS;

        default:
            CT_SRC_THROW_ERROR(TREE_LOC(tree), ERR_VALUE_ERROR, "the data type of column is not supported");
            return CT_ERROR;
    }
    return status;
}

status_t udt_verify_scalar(sql_verifier_t *verf, typmode_t *cmode, expr_tree_t *tree)
{
    status_t status;
    variant_t *pvar = NULL;
    if (sql_is_skipped_expr(tree)) {
        return CT_SUCCESS;
    }

    if (!var_datatype_matched(cmode->datatype, TREE_DATATYPE(tree))) {
        CT_SRC_ERROR_MISMATCH(TREE_LOC(tree), cmode->datatype, TREE_DATATYPE(tree));
        return CT_ERROR;
    }

    if (CT_IS_LOB_TYPE(cmode->datatype) || !TREE_IS_CONST(tree)) {
        return CT_SUCCESS;
    }

    pvar = &tree->root->value;
    if (cmode->datatype != TREE_DATATYPE(tree)) {
        if (pvar->is_null) {
            return CT_SUCCESS;
        }
        CT_RETURN_IFERR(sql_convert_variant(verf->stmt, pvar, cmode->datatype));
        TREE_DATATYPE(tree) = cmode->datatype;
    }

    if ((!pvar->is_null) && CT_IS_VARLEN_TYPE(pvar->type)) {
        text_t text_bak = pvar->v_text;
        CT_RETURN_IFERR(sql_copy_text(verf->stmt->context, &text_bak, &pvar->v_text));
    }
    status = udt_adjust_scalar_by_type(verf, cmode, tree, pvar);
    if (status != CT_SUCCESS) {
        cm_set_error_loc(TREE_LOC(tree));
    }
    return status;
}

status_t udt_put_scalar_value(sql_stmt_t *stmt, variant_t *value, mtrl_rowid_t *row_id)
{
    dec2_t dec2;
    switch (value->type) {
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BOOLEAN:
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)value, sizeof(int32), row_id);

        case CT_TYPE_BIGINT:
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)value, sizeof(int64), row_id);
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)value, sizeof(date_t), row_id);

        case CT_TYPE_TIMESTAMP_LTZ:
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)value, sizeof(timestamp_ltz_t), row_id);

        case CT_TYPE_TIMESTAMP_TZ:
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)value, sizeof(timestamp_tz_t), row_id);

        case CT_TYPE_INTERVAL_DS:
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)value, sizeof(interval_ds_t), row_id);

        case CT_TYPE_INTERVAL_YM:
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)value, sizeof(interval_ym_t), row_id);

        case CT_TYPE_REAL:
        case CT_TYPE_FLOAT:
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)value, sizeof(double), row_id);

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            return vmctx_insert(GET_VM_CTX(stmt), value->v_text.str, value->v_text.len, row_id);

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL: {
            dec4_t d4;
            CT_RETURN_IFERR(cm_dec_8_to_4(&d4, VALUE_PTR(dec8_t, value)));
            uint32 original_size = cm_dec4_stor_sz(&d4);
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)&d4, original_size, row_id);
        }

        case CT_TYPE_NUMBER2:
            CT_RETURN_IFERR(cm_dec_8_to_2(&dec2, VALUE_PTR(dec8_t, value)));
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)GET_PAYLOAD(&dec2), cm_dec2_stor_sz(&dec2), row_id);

        case CT_TYPE_BLOB:
        case CT_TYPE_CLOB:
        case CT_TYPE_IMAGE:
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)value->v_lob.normal_lob.value.str,
                value->v_lob.normal_lob.size, row_id);

        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)value->v_bin.bytes, value->v_bin.size, row_id);
        default:
            CT_SET_ERROR_MISMATCH_EX(value->type);
            return CT_ERROR;
    }
}

status_t udt_get_varlen_databuf(typmode_t typmode, uint32 *max_len)
{
    switch (typmode.datatype) {
        case CT_TYPE_CHAR:
            if (!typmode.is_char) {
                *max_len = typmode.size;
                return CT_SUCCESS;
            }
            *max_len = typmode.size * MAX_BYTES2CHAR;
            *max_len = (*max_len > CT_MAX_COLUMN_SIZE) ? CT_MAX_COLUMN_SIZE : *max_len;
            return CT_SUCCESS;

        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            if (!typmode.is_char) {
                *max_len = typmode.size;
                return CT_SUCCESS;
            }
            *max_len = typmode.size * MAX_BYTES2CHAR;
            *max_len = (*max_len > CT_MAX_STRING_LEN) ? CT_MAX_STRING_LEN : *max_len;
            return CT_SUCCESS;

        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
        case CT_TYPE_BLOB:
        case CT_TYPE_CLOB:
        case CT_TYPE_IMAGE:
            *max_len = typmode.size;
            return CT_SUCCESS;

        default:
            CT_THROW_ERROR(ERR_INVALID_DATA_TYPE, "expect varlen datatype");
            return CT_ERROR;
    }
}


status_t udt_check_char(variant_t *src, typmode_t type)
{
    uint32 value_len, max_len;

    if (type.is_char) {
        CT_RETURN_IFERR(GET_DATABASE_CHARSET->length(&src->v_text, &value_len));
    } else {
        value_len = src->v_text.len;
    }
    CT_RETURN_IFERR(udt_get_varlen_databuf(type, &max_len));
    if ((value_len > type.size) || (src->v_text.len > max_len)) {
        CT_THROW_ERROR(ERR_VALUE_ERROR, "character string buffer too small");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t udt_convert_char(variant_t *src, variant_t *dst, typmode_t type)
{
    uint32 max_len;
    if (src->is_null) {
        dst->is_null = src->is_null;
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(udt_check_char(src, type));
    CT_RETURN_IFERR(udt_get_varlen_databuf(type, &max_len));
    if (src->v_text.len != 0) {
        MEMS_RETURN_IFERR(memmove_s(dst->v_text.str, max_len, src->v_text.str, src->v_text.len));
    }
    dst->v_text.len = src->v_text.len;
    dst->is_null = src->is_null;
    return CT_SUCCESS;
}

status_t udt_get_lob_value(sql_stmt_t *stmt, variant_t *result)
{
    if (result->is_null) {
        result->type = (result->type == CT_TYPE_CLOB || result->type == CT_TYPE_IMAGE) ? CT_TYPE_STRING : CT_TYPE_RAW;
        return CT_SUCCESS;
    }

    switch (result->v_lob.type) {
        case CT_LOB_FROM_KERNEL:
            CT_RETURN_IFERR(sql_get_lob_value_from_knl(stmt, result));
            break;

        case CT_LOB_FROM_VMPOOL:
            CT_RETURN_IFERR(sql_get_lob_value_from_vm(stmt, result));
            break;

        case CT_LOB_FROM_NORMAL:
            CT_RETURN_IFERR(sql_get_lob_value_from_normal(stmt, result));
            break;

        default:
            CT_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "do get lob value");
            return CT_ERROR;
    }

    if (g_instance->sql.enable_empty_string_null == CT_TRUE && result->v_text.len == 0 &&
        (CT_IS_STRING_TYPE(result->type) || CT_IS_BINARY_TYPE(result->type) || CT_IS_RAW_TYPE(result->type))) {
        result->is_null = CT_TRUE;
    }
    return CT_SUCCESS;
}

status_t udt_scalar_copy_char(sql_stmt_t *stmt, typmode_t typmode, variant_t *src, variant_t *dst)
{
    uint32 value_len, max_len;
    int32 code;
    if (typmode.is_char) {
        CT_RETURN_IFERR(GET_DATABASE_CHARSET->length(&src->v_text, &value_len));
    } else {
        value_len = src->v_text.len;
    }
    CT_RETURN_IFERR(udt_get_varlen_databuf(typmode, &max_len));
    if ((value_len > typmode.size) || (src->v_text.len > max_len)) {
        CT_THROW_ERROR(ERR_VALUE_ERROR, "character string buffer too small");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_push(stmt, max_len, (void **)&dst->v_text.str));
    if (src->v_text.len != 0) {
        code = memmove_s(dst->v_text.str, max_len, src->v_text.str, src->v_text.len);
        if (SECUREC_UNLIKELY(code != EOK)) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, code);
            CTSQL_POP(stmt);
            return CT_ERROR;
        }
    }
    uint32 blank_count = MIN((src->v_text.len + (typmode.size - value_len)), max_len) - src->v_text.len;
    if (blank_count > 0) {
        code = memset_s(dst->v_text.str + src->v_text.len, blank_count, ' ', blank_count);
        if (SECUREC_UNLIKELY(code != EOK)) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, code);
            CTSQL_POP(stmt);
            return CT_ERROR;
        }
    }
    dst->v_text.len = src->v_text.len + blank_count;
    return CT_SUCCESS;
}

void udt_typemode_default_init(typmode_t *type, variant_t *value)
{
    type->datatype = value->type;
    if (CT_IS_DATETIME_TYPE(value->type)) {
        type->precision = CT_MAX_DATETIME_PRECISION;
        type->scale = 0;
        type->size = sizeof(timestamp_t);
    } else if (CT_IS_NUMBER_TYPE(value->type)) {
        type->precision = 0;
        type->scale = 0;
        type->size = sizeof(dec8_t);
    } else if (CT_IS_VARLEN_TYPE(value->type)) {
        type->precision = 0;
        type->scale = 0;
        type->size = udt_outparam_default_size(value->type);
    } else {
        type->precision = 0;
        type->scale = 0;
        type->size = var_get_size(value);
    }
}

status_t udt_copy_scalar_element(sql_stmt_t *stmt, typmode_t dst_typmode, variant_t *right, variant_t *result)
{
    if (dst_typmode.datatype == CT_TYPE_UNKNOWN) {
        udt_typemode_default_init(&dst_typmode, right);
    }
    result->type = dst_typmode.datatype;
    result->is_null = right->is_null;
    if (result->is_null) {
        return CT_SUCCESS;
    }

    if (CT_IS_LOB_TYPE((ct_type_t)right->type)) {
        CT_RETURN_IFERR(udt_get_lob_value(stmt, right));
        // Lob types' is_null may be CT_FALSE at the beginning and becomes CT_TRUE after get_lob_value.
        result->is_null = right->is_null;
        if (result->is_null) {
            return CT_SUCCESS;
        }
    }

    if (right->type != result->type) {
        if (dst_typmode.is_array == CT_TRUE) {
            CT_RETURN_IFERR(sql_convert_to_array(stmt, right, &dst_typmode, CT_FALSE));
        } else {
            CT_RETURN_IFERR(sql_convert_variant(stmt, right, result->type));
        }
    }

    if (result->type == CT_TYPE_CHAR) {
        CT_RETURN_IFERR(udt_scalar_copy_char(stmt, dst_typmode, right, result));
    } else {
        CT_RETURN_IFERR(udt_check_varlen_type_size(&dst_typmode, right));
        sql_keep_stack_variant(stmt, right);
        var_copy(right, result);
    }
    return CT_SUCCESS;
}

status_t udt_make_scalar_elemt(sql_stmt_t *stmt, typmode_t type_mode, variant_t *value, mtrl_rowid_t *row_id,
    int16 *type)
{
    status_t status = CT_ERROR;
    variant_t dst;

    CTSQL_SAVE_STACK(stmt);
    do {
        CT_BREAK_IF_ERROR(udt_copy_scalar_element(stmt, type_mode, value, &dst));
        if (dst.is_null) {
            status = CT_SUCCESS;
            break;
        }
        if (type != NULL && (*type != dst.type)) {
            *type = dst.type;
        }
        CT_BREAK_IF_ERROR(udt_put_scalar_value(stmt, &dst, row_id));
        status = CT_SUCCESS;
    } while (0);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

status_t udt_clone_scalar(sql_stmt_t *stmt, mtrl_rowid_t copy_from, mtrl_rowid_t *copy_to)
{
    status_t status;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    OPEN_VM_PTR(&copy_from, vm_ctx);
    /* NO NEED TO CONSIDER THE  BITMAP EX SIZE, COLUMN COUNT = 1 */
    status = vmctx_insert(vm_ctx, (const char *)d_ptr, d_chunk->requested_size, copy_to);
    CLOSE_VM_PTR(&copy_from, vm_ctx);

    return status;
}

status_t udt_read_lob_scalar_value(sql_stmt_t *stmt, const char *d_ptr, pvm_chunk_t d_chunk, variant_t *value)
{
    VALUE_PTR(var_lob_t, value)->type = CT_LOB_FROM_NORMAL;
    VALUE_PTR(var_lob_t, value)->normal_lob.size = d_chunk->requested_size;
    VALUE_PTR(var_lob_t, value)->normal_lob.type = CT_LOB_FROM_NORMAL;
    VALUE_PTR(var_lob_t, value)->normal_lob.value.len = d_chunk->requested_size;

    if (d_chunk->requested_size == 0) {
        VALUE_PTR(var_lob_t, value)->normal_lob.value.str = NULL;
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(
        sql_push(stmt, d_chunk->requested_size, (void **)&(VALUE_PTR(var_lob_t, value)->normal_lob.value.str)));
    errno_t ret = memcpy_sp(VALUE_PTR(var_lob_t, value)->normal_lob.value.str, d_chunk->requested_size, d_ptr,
        d_chunk->requested_size);
    if (ret != EOK) {
        CTSQL_POP(stmt);
        CT_THROW_ERROR(ERR_RESET_MEMORY, "extending variate");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t udt_read_varlen_scalar_value(sql_stmt_t *stmt, const char *d_ptr, pvm_chunk_t d_chunk, variant_t *value)
{
    if (d_chunk->requested_size == 0) {
        value->v_text.str = NULL;
        value->v_text.len = 0;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_push(stmt, d_chunk->requested_size, (void **)&(VALUE_PTR(text_t, value)->str)));

    errno_t ret = memcpy_sp(VALUE_PTR(text_t, value)->str, d_chunk->requested_size, d_ptr, d_chunk->requested_size);
    if (ret != EOK) {
        CTSQL_POP(stmt);
        CT_THROW_ERROR(ERR_RESET_MEMORY, "extending variate");
        return CT_ERROR;
    }
    VALUE_PTR(text_t, value)->len = d_chunk->requested_size;
    return CT_SUCCESS;
}

status_t udt_read_scalar_value_core(sql_stmt_t *stmt, char *d_ptr, pvm_chunk_t d_chunk, variant_t *value)
{
    switch ((ct_type_t)value->type) {
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BOOLEAN:
            VALUE(int32, value) = *(int32 *)d_ptr;
            break;

        case CT_TYPE_BIGINT:
            VALUE(int64, value) = *(int64 *)d_ptr;
            break;
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
            VALUE(date_t, value) = *(date_t *)d_ptr;
            break;

        case CT_TYPE_TIMESTAMP_LTZ:
            VALUE(timestamp_ltz_t, value) = *(timestamp_ltz_t *)d_ptr;
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            VALUE(timestamp_tz_t, value) = *(timestamp_tz_t *)d_ptr;
            break;

        case CT_TYPE_INTERVAL_DS:
            VALUE(interval_ds_t, value) = *(interval_ds_t *)d_ptr;
            break;

        case CT_TYPE_INTERVAL_YM:
            VALUE(interval_ym_t, value) = *(interval_ym_t *)d_ptr;
            break;

        case CT_TYPE_REAL:
        case CT_TYPE_FLOAT:
            VALUE(double, value) = *(double *)d_ptr;
            break;
        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
            cm_dec_4_to_8(VALUE_PTR(dec8_t, value), (dec4_t *)d_ptr, d_chunk->requested_size);
            break;

        case CT_TYPE_NUMBER2:
            CT_RETURN_IFERR(cm_dec_2_to_8(VALUE_PTR(dec8_t, value), (const payload_t *)d_ptr, d_chunk->requested_size));
            break;

        case CT_TYPE_BLOB:
        case CT_TYPE_CLOB:
        case CT_TYPE_IMAGE:
            CT_RETURN_IFERR(udt_read_lob_scalar_value(stmt, d_ptr, d_chunk, value));
            break;

        default:
            CT_RETURN_IFERR(udt_read_varlen_scalar_value(stmt, d_ptr, d_chunk, value));
            break;
    }
    return CT_SUCCESS;
}

status_t udt_read_scalar_value(sql_stmt_t *stmt, mtrl_rowid_t *row_id, variant_t *value)
{
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    status_t status;

    OPEN_VM_PTR(row_id, vm_ctx);
    status = udt_read_scalar_value_core(stmt, d_ptr, d_chunk, value);
    CLOSE_VM_PTR(row_id, vm_ctx);
    value->is_null = CT_FALSE;
    return status;
}
