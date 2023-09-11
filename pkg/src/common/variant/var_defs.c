/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * var_defs.c
 *
 *
 * IDENTIFICATION
 * src/common/variant/var_defs.c
 *
 * -------------------------------------------------------------------------
 */
#include "var_defs.h"
#include "var_cast.h"

uint32 var_get_size(variant_t *var)
{
    if (var->is_null) {
        var->v_bin.size = 0;
        return GS_SIZE_OF_NULL;
    }

    switch (var->type) {
        case GS_TYPE_BOOLEAN:
        case GS_TYPE_INTEGER:
        case GS_TYPE_UINT32:
            return sizeof(uint32);

        case GS_TYPE_BIGINT:
        case GS_TYPE_REAL:
        case GS_TYPE_DATE:
        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_TIMESTAMP_LTZ:
            return sizeof(int64);

        case GS_TYPE_TIMESTAMP_TZ:
            return sizeof(timestamp_tz_t);

        case GS_TYPE_INTERVAL_DS:
            return sizeof(interval_ds_t);

        case GS_TYPE_INTERVAL_YM:
            return sizeof(interval_ym_t);

        case GS_TYPE_NUMBER:
        case GS_TYPE_NUMBER3:
        case GS_TYPE_DECIMAL:
            return cm_dec_stor_sz(&var->v_dec);

        case GS_TYPE_NUMBER2:
            return cm_dec_stor_sz2(&var->v_dec);

        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING:
            return var->v_text.len;

        case GS_TYPE_CLOB:
        case GS_TYPE_BLOB:
        case GS_TYPE_IMAGE:
            return sizeof(uint32) + MAX(var->v_lob.knl_lob.size, VM_LOB_LOCATOR_SIZE);

        case GS_TYPE_VARBINARY:
        case GS_TYPE_BINARY:
        case GS_TYPE_RAW:  // if raw size need double?
        default:
            return var->v_bin.size;
    }
}

uint32 cm_get_datatype_strlen(gs_type_t type, uint32 strlen)
{
    switch (type) {
        case GS_TYPE_UNKNOWN:
            return GS_MAX_COLUMN_SIZE;

        case GS_TYPE_INTEGER:
            return GS_MAX_INT32_STRLEN;

        case GS_TYPE_BOOLEAN:
            return GS_MAX_BOOL_STRLEN;

        case GS_TYPE_BIGINT:
            return GS_MAX_INT64_STRLEN;

        case GS_TYPE_REAL:
            return GS_MAX_REAL_OUTPUT_STRLEN;

        case GS_TYPE_UINT64:
            return GS_MAX_UINT64_STRLEN;

        case GS_TYPE_UINT32:
            return GS_MAX_UINT32_STRLEN;

        case GS_TYPE_USMALLINT:
            return GS_MAX_UINT16_STRLEN;

        case GS_TYPE_UTINYINT:
            return GS_MAX_UINT8_STRLEN;

        case GS_TYPE_TINYINT:
            return GS_MAX_INT8_STRLEN;

        case GS_TYPE_SMALLINT:
            return GS_MAX_INT16_STRLEN;

        case GS_TYPE_DATE:
        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_TIMESTAMP_TZ:
        case GS_TYPE_TIMESTAMP_LTZ:
            return GS_MAX_TIME_STRLEN;

        case GS_TYPE_NUMBER:
        case GS_TYPE_NUMBER2:
        case GS_TYPE_NUMBER3:
        case GS_TYPE_DECIMAL:
            return GS_MAX_DEC_OUTPUT_ALL_PREC;

        case GS_TYPE_INTERVAL_DS:
            return GS_MAX_DS_INTERVAL_STRLEN;

        case GS_TYPE_INTERVAL_YM:
            return GS_MAX_YM_INTERVAL_STRLEN;

        case GS_TYPE_CLOB:
        case GS_TYPE_BLOB:
        case GS_TYPE_IMAGE:
            return GS_MAX_EXEC_LOB_SIZE;

        default:
            return strlen;
    }
}

bool32 var_itvl_is_zero(variant_t *var)
{
    switch (var->type) {
        case GS_TYPE_INTERVAL_DS:
            return (var->v_itvl_ds == 0);

        case GS_TYPE_INTERVAL_YM:
            return (var->v_itvl_ym == 0);

        default:
            break;
    }

    return GS_FALSE;
}

bool32 var_num_is_zero(variant_t *var)
{
    switch (var->type) {
        case GS_TYPE_UINT32:
            return (var->v_uint32 == 0);
        case GS_TYPE_INTEGER:
            return (var->v_int == 0);

        case GS_TYPE_BIGINT:
            return (var->v_bigint == 0);

        case GS_TYPE_REAL:
            return fabs(var->v_real) < GS_REAL_PRECISION;

        case GS_TYPE_NUMBER:
        case GS_TYPE_NUMBER2:
        case GS_TYPE_DECIMAL:
            return DECIMAL8_IS_ZERO(&var->v_dec);

        default:
            break;
    }

    return GS_FALSE;
}

bool32 var_is_zero(variant_t *var)
{
    if (var->is_null) {
        return GS_FALSE;
    }
    return (var_num_is_zero(var) || var_itvl_is_zero(var));
}

bool32 var_is_negative(variant_t *var)
{
    switch (var->type) {
        case GS_TYPE_INTEGER:
            return (var->v_int < 0);

        case GS_TYPE_BIGINT:
            return (var->v_bigint < 0);

        case GS_TYPE_REAL:
            return (var->v_real < 0);

        case GS_TYPE_NUMBER:
        case GS_TYPE_NUMBER2:
        case GS_TYPE_DECIMAL:
            return IS_DEC8_NEG(&var->v_dec);

        case GS_TYPE_INTERVAL_DS:
            return (var->v_itvl_ds < 0);

        case GS_TYPE_INTERVAL_YM:
            return (var->v_itvl_ym < 0);

        default:
            break;
    }

    return GS_FALSE;
}

bool32 cm_datatype_arrayable(gs_type_t type)
{
    if (type <= GS_TYPE_BASE && type >= GS_TYPE_OPERAND_CEIL) {
        return GS_FALSE;
    }

    if (type >= GS_TYPE_BINARY && type <= GS_TYPE_COLUMN) {
        return GS_FALSE;
    }

    if (type == GS_TYPE_RAW || type == GS_TYPE_IMAGE) {
        return GS_FALSE;
    }

    if (type == GS_TYPE_ARRAY) {
        return GS_FALSE;
    }

    return GS_TRUE;
}

/* the caller should ensure that the origin element value is not null */
status_t var_gen_variant(char *ele_val, uint32 size, uint32 datatype, variant_t *val)
{
    errno_t ret;
    val->type = datatype;
    val->is_null = GS_FALSE;

    switch (datatype) {
        case GS_TYPE_NUMBER:
        case GS_TYPE_DECIMAL:
            GS_RETURN_IFERR(cm_dec_4_to_8(VALUE_PTR(dec8_t, val), (dec4_t*)ele_val, size));
            break;
        case GS_TYPE_NUMBER2:
            GS_RETURN_IFERR(cm_dec_2_to_8(VALUE_PTR(dec8_t, val), (const payload_t *)ele_val, size));
            break;

        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING:
            val->v_text.str = (char *)ele_val;
            val->v_text.len = size;
            break;

        case GS_TYPE_BINARY:
            val->v_bin.bytes = (uint8 *)ele_val;
            val->v_bin.size = size;
            val->v_bin.is_hex_const = GS_FALSE;
            break;

        default:
            ret = memcpy_sp(VALUE_PTR(int32, val), size, ele_val, size);
            if (ret != EOK) {
                GS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
                return GS_ERROR;
            }
    }

    return GS_SUCCESS;
}

status_t var_deep_copy(variant_t *src, variant_t *dst, var_malloc_t func, var_malloc_handle_t* handle)
{
    char* buff = NULL;
    char* src_buff = NULL;
    uint32 src_len;
    *dst = *src;

    if (GS_IS_VARLEN_TYPE(src->type)) {
        src_buff = src->v_text.str;
        src_len = src->v_text.len;
    } else if (GS_IS_LOB_TYPE(src->type)) {
        if (src->v_lob.type == GS_LOB_FROM_KERNEL) {
            src_buff = (char *)src->v_lob.knl_lob.bytes;
            src_len = src->v_lob.knl_lob.size;
        } else if (src->v_lob.type == GS_LOB_FROM_NORMAL) {
            src_buff = src->v_lob.normal_lob.value.str;
            src_len = src->v_lob.normal_lob.value.len;
        } else {
            return GS_SUCCESS;
        }
    } else {
        return GS_SUCCESS;
    }

    if (src_len == 0) {
        return GS_SUCCESS;
    }

    buff = func(handle, src_len);
    if (buff == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, src_len, "malloc failed for variant copy.");
        return GS_ERROR;
    }
    MEMS_RETURN_IFERR(memcpy_s(buff, src_len, src_buff, src_len));
    if (GS_IS_VARLEN_TYPE(src->type)) {
        dst->v_text.str = buff;
    } else if (GS_IS_LOB_TYPE(src->type)) {
        if (src->v_lob.type == GS_LOB_FROM_KERNEL) {
            dst->v_lob.knl_lob.bytes = (uint8 *)buff;
        } else {
            dst->v_lob.normal_lob.value.str = buff;
        }
    }
    return GS_SUCCESS;
}
