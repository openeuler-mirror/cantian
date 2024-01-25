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
 * pl_scalar.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/type/pl_scalar.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_SCALAR_H__
#define __PL_SCALAR_H__

#include "ctsql_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif
#define MAX_BYTES2CHAR 6

status_t udt_get_lob_value(sql_stmt_t *stmt, variant_t *result);
status_t udt_check_char(variant_t *src, typmode_t type);
status_t udt_convert_char(variant_t *src, variant_t *dst, typmode_t type);
status_t udt_verify_scalar(sql_verifier_t *verf, typmode_t *cmode, expr_tree_t *tree);
status_t udt_copy_scalar_element(sql_stmt_t *stmt, typmode_t dst_typmode, variant_t *right, variant_t *result);
status_t udt_make_scalar_elemt(sql_stmt_t *stmt, typmode_t type_mode, variant_t *value, mtrl_rowid_t *row_id,
    int16 *type);
status_t udt_clone_scalar(sql_stmt_t *stmt, mtrl_rowid_t copy_from, mtrl_rowid_t *copy_to);
status_t udt_read_scalar_value(sql_stmt_t *stmt, mtrl_rowid_t *row_id, variant_t *value);
status_t udt_get_varlen_databuf(typmode_t typmode, uint32 *max_len);
status_t udt_put_scalar_value(sql_stmt_t *stmt, variant_t *value, mtrl_rowid_t *row_id);
void udt_typemode_default_init(typmode_t *type, variant_t *value);

static inline uint32 udt_outparam_default_size(uint32 datatype)
{
    switch (datatype) {
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            return CT_MAX_STRING_LEN;
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
        case CT_TYPE_CHAR:
            return CT_MAX_COLUMN_SIZE;
        default:
            return 0;
    }
}

#ifdef __cplusplus
}
#endif

#endif
