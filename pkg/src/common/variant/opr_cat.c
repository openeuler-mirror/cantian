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
 * opr_cat.c
 *
 *
 * IDENTIFICATION
 * src/common/variant/opr_cat.c
 *
 * -------------------------------------------------------------------------
 */
#include "opr_cat.h"

/* !
* \brief Concatenate two variant into a string. First, the two variant are converted
* into two strings, and second the two strings are concatenated to a new string.
* **NOTE:** Here, the memory for the last string is assumed to be allocated (with
* address *OP_RESULT->v_text.str*), and with the maximal length . Therefore, if the
* length of the OP_RESULT string exceeds the maximal length, it would be cut off.
*/
status_t opr_exec_cat(opr_operand_set_t *op_set)
{
    char buf[CT_STRING_BUFFER_SIZE];
    variant_t l_var, r_var;
    text_buf_t buffer;
    uint32 result_len;

    buf[0] = '\0';
    CM_INIT_TEXTBUF(&buffer, CT_MAX_STRING_LEN, buf);

    // record len of OP_RESULT memory
    result_len = OP_RESULT(op_set)->v_text.len;
    OP_RESULT(op_set)->v_text.len = 0;

    if (OP_LEFT(op_set)->is_null && OP_RIGHT(op_set)->is_null) {
        VAR_SET_NULL(OP_RESULT(op_set), CT_DATATYPE_OF_NULL);
        return CT_SUCCESS;
    }

    if (!OP_LEFT(op_set)->is_null) {
        l_var = *OP_LEFT(op_set);
        CT_RETURN_IFERR(var_as_string(op_set->nls, &l_var, &buffer));

        l_var.v_text.len = MIN(result_len - OP_RESULT(op_set)->v_text.len, l_var.v_text.len);
        cm_concat_text(&OP_RESULT(op_set)->v_text, result_len, &l_var.v_text);
    }

    if (!OP_RIGHT(op_set)->is_null) {
        r_var = *OP_RIGHT(op_set);
        CT_RETURN_IFERR(var_as_string(op_set->nls, &r_var, &buffer));

        r_var.v_text.len = MIN(result_len - OP_RESULT(op_set)->v_text.len, r_var.v_text.len);
        cm_concat_text(&OP_RESULT(op_set)->v_text, result_len, &r_var.v_text);
    }

    OP_RESULT(op_set)->type = CT_TYPE_STRING;
    OP_RESULT(op_set)->is_null = CT_FALSE;
    return CT_SUCCESS;
}
