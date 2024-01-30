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
 * ctsql_expr.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/node/ctsql_expr.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_expr.h"
#include "cm_date.h"
#include "cm_binary.h"
#include "expr_parser.h"
#include "ctsql_func.h"
#include "ctsql_parser.h"
#include "ctsql_select.h"
#include "ctsql_aggr.h"
#include "ctsql_group.h"
#include "ctsql_proj.h"
#include "ctsql_mtrl.h"
#include "ctsql_winsort.h"
#include "ctsql_privilege.h"
#include "pl_compiler.h"
#include "pl_executor.h"
#include "pl_trigger_executor.h"
#include "ctsql_oper_func.h"
#include "ctsql_scan.h"
#include "srv_instance.h"
#include "pl_udt.h"
#include "base_compiler.h"
#ifdef Z_SHARDING
#include "shd_expr.h"
#include "shd_remote.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SQL_CONVERT_BUFFER_SIZE 80

cols_used_t g_cols_used_init;

static status_t get_first_col_in_func_index(visit_assist_t *va, expr_node_t **node)
{
    if (va->param0 != NULL) {
        return CT_SUCCESS;
    }
    if ((*node)->type == EXPR_NODE_COLUMN) {
        va->param0 = *node;
    }
    return CT_SUCCESS;
}

expr_node_t *sql_find_column_in_func(expr_node_t *node)
{
    visit_assist_t va;
    sql_init_visit_assist(&va, NULL, NULL);
    if (visit_expr_node(&va, &node, get_first_col_in_func_index) != CT_SUCCESS) {
        return NULL;
    }
    return (expr_node_t *)va.param0;
}

const text_t *sql_get_nodetype_text(expr_node_type_t node_type)
{
    for (uint32 i = 0; i < NODE_TYPE_SIZE; i++) {
        if (node_type == g_nodetype_names[i].id) {
            return &g_nodetype_names[i].name;
        }
    }

    return &g_nodetype_names[NODE_TYPE_SIZE - 1].name;
}

static inline uint32 sql_concat_result_len(variant_t *v1, variant_t *v2)
{
    uint32 len;

    if (v1->is_null) {
        len = 0;
    } else {
        if (CT_IS_STRING_TYPE(v1->type)) {
            len = v1->v_text.len;
        } else if (CT_IS_BINARY_TYPE(v1->type) || CT_IS_RAW_TYPE(v1->type)) {
            len = 2 * (v1->v_bin.size + 1);
        } else {
            len = cm_get_datatype_strlen(v1->type, SQL_CONVERT_BUFFER_SIZE);
        }
    }

    if (!v2->is_null) {
        if (CT_IS_STRING_TYPE(v2->type)) {
            len += v2->v_text.len;
        } else if (CT_IS_BINARY_TYPE(v2->type) || CT_IS_RAW_TYPE(v2->type)) {
            len += 2 * (v2->v_bin.size + 1);
        } else {
            len += cm_get_datatype_strlen(v2->type, SQL_CONVERT_BUFFER_SIZE);
        }
    }

    return MIN(len, CT_MAX_STRING_LEN);
}

static status_t sql_exec_concat_normal(sql_stmt_t *stmt, variant_t *l_var, variant_t *r_var, variant_t *result)
{
    uint32 result_len;
    result_len = sql_concat_result_len(l_var, r_var);
    CT_RETURN_IFERR(sql_push(stmt, result_len, (void **)&result->v_text.str));
    result->v_text.len = result_len;
    return opr_exec(OPER_TYPE_CAT, SESSION_NLS(stmt), l_var, r_var, result);
}

status_t sql_create_rowid_expr(sql_stmt_t *stmt, uint32 tab, expr_tree_t **expr)
{
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_tree_t), (void **)expr));
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&(*expr)->root));
    (*expr)->owner = stmt->context;
    (*expr)->root->size = ROWID_LENGTH;
    (*expr)->root->type = EXPR_NODE_RESERVED;
    (*expr)->root->datatype = CT_TYPE_STRING;
    (*expr)->root->value.type = CT_TYPE_INTEGER;
    (*expr)->root->value.v_rid.res_id = RES_WORD_ROWID;
    (*expr)->root->value.v_rid.tab_id = tab;
    (*expr)->root->value.v_rid.ancestor = 0;
    return CT_SUCCESS;
}

status_t sql_exec_concat_lob_value(sql_stmt_t *stmt, const char *buf, uint32 size, vm_lob_t *vlob)
{
    uint32 total_size, page_offset, copy_size, remain_size, write_size;
    vm_page_t *vpage = NULL;
    id_list_t *vm_list = sql_get_exec_lob_list(stmt);

    total_size = vlob->size;
    write_size = 0;

    /* check whether lob write exceeds to maximum */
    if (((uint64)vlob->size + (uint64)size) >= CT_MAX_LOB_SIZE) {
        CT_THROW_ERROR(ERR_LOB_SIZE_TOO_LARGE, "4294967295 bytes");
        return CT_ERROR;
    }

    do {
        page_offset = total_size % CT_VMEM_PAGE_SIZE;
        if (vlob->entry_vmid == CT_INVALID_ID32 || page_offset == 0) {
            CT_RETURN_IFERR(sql_extend_lob_vmem(stmt, vm_list, vlob));
            page_offset = 0;
        }

        CT_RETURN_IFERR(vm_open(stmt->session, stmt->mtrl.pool, vlob->last_vmid, &vpage));

        copy_size = CT_VMEM_PAGE_SIZE - page_offset;
        remain_size = size - write_size;
        if (copy_size > remain_size) {
            copy_size = remain_size;
        }
        if (copy_size != 0) {
            errno_t errcode = memcpy_s(vpage->data + page_offset, copy_size, buf + write_size, copy_size);
            if (errcode != EOK) {
                vm_close(stmt->session, stmt->mtrl.pool, vlob->last_vmid, VM_ENQUE_HEAD);
                CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                return CT_ERROR;
            }
        }

        vm_close(stmt->session, stmt->mtrl.pool, vlob->last_vmid, VM_ENQUE_HEAD);

        write_size += copy_size;
        page_offset += copy_size;
        total_size += copy_size;
    } while (write_size < size);

    vlob->size += size;
    return CT_SUCCESS;
}

static status_t sql_exec_concat_lob_value_from_knl(sql_stmt_t *stmt, var_lob_t *lob, vm_lob_t *vlob)
{
    char buf[SIZE_K(4)];
    uint32 buf_size = SIZE_K(4);
    knl_handle_t loc;
    uint32 remain_size, offset, size;

    loc = (knl_handle_t)lob->knl_lob.bytes;
    remain_size = knl_lob_size(loc);
    offset = 0;

    while (remain_size > 0) {
        CT_RETURN_IFERR(knl_read_lob(stmt->session, loc, offset, (void *)buf, buf_size, &size, NULL));
        remain_size -= size;
        offset += size;
        CT_RETURN_IFERR(sql_exec_concat_lob_value(stmt, buf, size, vlob));
    }

    return CT_SUCCESS;
}

static status_t sql_exec_concat_lob_value_from_vm(sql_stmt_t *stmt, var_lob_t *lob, vm_lob_t *vlob)
{
    char *buf = NULL;
    uint32 remain_size, size, vmid;
    vm_page_t *vpage = NULL;
    status_t status;
    vm_pool_t *vm_pool = stmt->mtrl.pool;

    remain_size = lob->vm_lob.size;
    vmid = lob->vm_lob.entry_vmid;

    while (remain_size > 0) {
        CT_RETURN_IFERR(vm_open(stmt->session, vm_pool, vmid, &vpage));

        buf = (char *)vpage->data;
        size = (CT_VMEM_PAGE_SIZE > remain_size) ? remain_size : CT_VMEM_PAGE_SIZE;
        remain_size -= size;

        status = sql_exec_concat_lob_value(stmt, buf, size, vlob);

        vm_close(stmt->session, vm_pool, vmid, VM_ENQUE_HEAD);
        vmid = vm_get_ctrl(vm_pool, vmid)->sort_next;

        CT_RETURN_IFERR(status);
    }

    return CT_SUCCESS;
}

static status_t sql_exec_concat_lob_value_from_normal(sql_stmt_t *stmt, var_lob_t *lob, vm_lob_t *vlob)
{
    uint32 size;
    char *buffer = lob->normal_lob.value.str;
    size = lob->normal_lob.value.len;
    return sql_exec_concat_lob_value(stmt, buffer, size, vlob);
}

static status_t sql_exec_concat_special_core(sql_stmt_t *stmt, var_lob_t *lob, vm_lob_t *vlob)
{
    switch (lob->type) {
        case CT_LOB_FROM_KERNEL:
            return sql_exec_concat_lob_value_from_knl(stmt, lob, vlob);

        case CT_LOB_FROM_VMPOOL:
            return sql_exec_concat_lob_value_from_vm(stmt, lob, vlob);

        case CT_LOB_FROM_NORMAL:
            return sql_exec_concat_lob_value_from_normal(stmt, lob, vlob);

        default:
            CT_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "do concat");
            return CT_ERROR;
    }
}

static status_t sql_exec_concat_lob(sql_stmt_t *stmt, variant_t *l_var, variant_t *r_var, variant_t *result)
{
    vm_lob_t vlob;
    char *buf1 = NULL;
    char *buf2 = NULL;
    text_buf_t text_buf1, text_buf2;

    // check whether has null
    if (l_var->is_null) {
        *result = *r_var;
        return CT_SUCCESS;
    }
    if (r_var->is_null) {
        *result = *l_var;
        return CT_SUCCESS;
    }

    // convert value to clob
    if (!CT_IS_CLOB_TYPE(l_var->type)) {
        CT_RETURN_IFERR(sql_push(stmt, CT_CONVERT_BUFFER_SIZE, (void **)&buf1));
        CM_INIT_TEXTBUF(&text_buf1, CT_CONVERT_BUFFER_SIZE, buf1);
        CT_RETURN_IFERR(var_convert(SESSION_NLS(stmt), l_var, CT_TYPE_CLOB, &text_buf1));
    }
    if (!CT_IS_CLOB_TYPE(r_var->type)) {
        CT_RETURN_IFERR(sql_push(stmt, CT_CONVERT_BUFFER_SIZE, (void **)&buf2));
        CM_INIT_TEXTBUF(&text_buf2, CT_CONVERT_BUFFER_SIZE, buf2);
        CT_RETURN_IFERR(var_convert(SESSION_NLS(stmt), r_var, CT_TYPE_CLOB, &text_buf2));
    }

    // lob value can be knl_lob or vm_lob or normal_lob
    if (l_var->v_lob.type == CT_LOB_FROM_VMPOOL) {
        vlob = l_var->v_lob.vm_lob;
        CT_RETURN_IFERR(sql_exec_concat_special_core(stmt, &r_var->v_lob, &vlob));
    } else {
        cm_reset_vm_lob(&vlob);
        CT_RETURN_IFERR(sql_exec_concat_special_core(stmt, &l_var->v_lob, &vlob));
        CT_RETURN_IFERR(sql_exec_concat_special_core(stmt, &r_var->v_lob, &vlob));
    }

    result->is_null = CT_FALSE;
    result->type = CT_TYPE_CLOB;
    result->v_lob.type = CT_LOB_FROM_VMPOOL;
    result->v_lob.vm_lob = vlob;
    return CT_SUCCESS;
}

status_t sql_exec_concat(sql_stmt_t *stmt, variant_t *l_var, variant_t *r_var, variant_t *result)
{
    if (l_var->is_null && r_var->is_null) {
        VAR_SET_NULL(result, CT_DATATYPE_OF_NULL);
        return CT_SUCCESS;
    }

    if (CT_IS_CLOB_TYPE(l_var->type) || CT_IS_CLOB_TYPE(r_var->type)) {
        return sql_exec_concat_lob(stmt, l_var, r_var, result);
    } else {
        return sql_exec_concat_normal(stmt, l_var, r_var, result);
    }
}

#define SQL_EXEC_EXPR_OPRAND(expr, var, result, stmt)                   \
    do {                                                                \
        CT_RETURN_IFERR(sql_exec_expr_node((stmt), (expr), (var)));     \
        if ((var)->type == CT_TYPE_COLUMN) {                            \
            (result)->type = CT_TYPE_COLUMN;                            \
            (result)->is_null = CT_FALSE;                               \
            return CT_SUCCESS;                                          \
        }                                                               \
        sql_keep_stack_variant((stmt), (var));                          \
    } while (0)

status_t sql_exec_oper(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    status_t status;
    variant_t l_var, r_var;

    SQL_EXEC_EXPR_OPRAND(node->left, &l_var, result, stmt);

    /* return null if result of left expression is null except concat */
    if (l_var.is_null == CT_TRUE && node->type != EXPR_NODE_CAT) {
        result->type = CT_DATATYPE_OF_NULL;
        result->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    SQL_EXEC_EXPR_OPRAND(node->right, &r_var, result, stmt);

    if (node->type == EXPR_NODE_CAT) {
        return sql_exec_concat(stmt, &l_var, &r_var, result);
    }

    status = opr_exec((operator_type_t)node->type, SESSION_NLS(stmt), &l_var, &r_var, result);
    if (SECUREC_UNLIKELY(status != CT_SUCCESS)) {
        cm_set_error_loc(node->loc);
    }

    return status;
}

status_t sql_exec_unary(expr_node_t *node, variant_t *var)
{
    if (var->is_null || node->unary == UNARY_OPER_ROOT) {
        return CT_SUCCESS;
    }

    if (var_as_num(var) != CT_SUCCESS) {
        CT_SRC_THROW_ERROR(node->loc, ERR_INVALID_NUMBER, cm_get_num_errinfo(NERR_ERROR));
        return CT_ERROR;
    }

    if (!UNARY_INCLUDE_NEGATIVE(node)) {
        return CT_SUCCESS;
    }

    switch (var->type) {
        case CT_TYPE_INTEGER:
            VALUE(int32, var) = -VALUE(int32, var);
            break;

        case CT_TYPE_BIGINT:
            VALUE(int64, var) = -VALUE(int64, var);
            break;

        case CT_TYPE_REAL:
            VALUE(double, var) = -VALUE(double, var);
            break;

        case CT_TYPE_NUMBER2:
        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
            cm_dec_negate(&var->v_dec);
            break;

        default:
            CM_NEVER;
            break;
    }

    return CT_SUCCESS;
}

static status_t sql_exec_unary_oper(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    status_t status;
    variant_t var;
    SQL_EXEC_EXPR_OPRAND(node->right, &var, result, stmt);

    if (var.is_null) {
        result->type = CT_DATATYPE_OF_NULL;
        result->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    if (var_as_num(&var) != CT_SUCCESS) {
        CT_SRC_THROW_ERROR(node->loc, ERR_INVALID_NUMBER, "");
        return CT_ERROR;
    }

    result->is_null = CT_FALSE;

    status = opr_unary(&var, result);
    if (status != CT_SUCCESS) {
        cm_set_error_loc(node->loc);
    }

    return status;
}

static status_t sql_sequence_nextval(sql_stmt_t *stmt, text_t *user, text_t *seq_name, int64 *next_val)
{
    CM_POINTER3(stmt, seq_name, next_val);

    return knl_seq_nextval(&stmt->session->knl_session, user, seq_name, next_val);
}

static status_t sql_sequence_currval(sql_stmt_t *stmt, text_t *user, text_t *seq_name, int64 *curr_val)
{
    CM_POINTER3(stmt, seq_name, curr_val);

    return knl_seq_currval(&stmt->session->knl_session, user, seq_name, curr_val);
}

status_t sql_get_sequence_value(sql_stmt_t *stmt, var_seq_t *vseq, variant_t *val)
{
    sql_seq_t *item = NULL;
    sql_seq_t temp;
    uint32 count = 0;

    val->type = CT_TYPE_BIGINT;
    val->is_null = CT_FALSE;

    if (sql_check_seq_priv(stmt, &vseq->user, &vseq->name) != CT_SUCCESS) {
        cm_reset_error();
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }

    if (stmt->pl_context != NULL) {
        pl_entity_t *entity = (pl_entity_t *)stmt->pl_context;
        count = entity->sequences.count;
    } else if (stmt->context->sequences != NULL) {
        count = stmt->context->sequences->count;
    }

    for (uint32 i = 0; i < count; ++i) {
        item = &stmt->v_sequences[i];
        item->seq.mode = vseq->mode;
        if (var_seq_equal(&item->seq, vseq)) {
            break;
        }
        item = NULL;
    }
    if (item == NULL || !(item->flags & vseq->mode) || (stmt->lang_type == LANG_PL)) {
        item = &temp;
        item->flags = vseq->mode;
        item->processed = CT_FALSE;
    }

    if (item->processed) {
        val->v_bigint = item->value;
        return CT_SUCCESS;
    }

    if (item->flags & SEQ_NEXT_VALUE) {
        if (CT_SUCCESS != sql_sequence_nextval(stmt, &vseq->user, &vseq->name, &item->value)) {
            return CT_ERROR;
        }
    } else {
        if (CT_SUCCESS != sql_sequence_currval(stmt, &vseq->user, &vseq->name, &item->value)) {
            return CT_ERROR;
        }
    }

    item->processed = CT_TRUE;
    val->v_bigint = item->value;
    return CT_SUCCESS;
}

static status_t sql_copy_rs_value(sql_stmt_t *stmt, char **buf, uint32 size, char **src, uint32 len, uint32 *offset)
{
    errno_t errcode = 0;
    if (len != 0) {
        errcode = memcpy_s(*buf, size, *src, len);
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CT_ERROR;
        }
    }
    *src = *buf;
    *buf += CT_CONVERT_BUFFER_SIZE;
    (*offset)++;
    return CT_SUCCESS;
}

static status_t sql_convert_rs_result_datatype(sql_stmt_t *stmt, typmode_t *typmod, variant_t *result)
{
    if (typmod->datatype == CT_TYPE_UNKNOWN || typmod->datatype == result->type) {
        return CT_SUCCESS;
    }
    if (typmod->is_array == CT_TRUE) {
        return sql_convert_to_array(stmt, result, typmod, CT_FALSE);
    } else {
        return sql_convert_variant(stmt, result, typmod->datatype);
    }
}

static status_t sql_get_all_rs_value(sql_stmt_t *stmt, sql_cursor_t *cursor, variant_t *result, char *buf, uint32 n_rs,
    uint32 n_rs_need_cvt, galist_t *rs_columns)
{
    uint32 offset = 0;
    status_t status = CT_SUCCESS;
    typmode_t typmod;

    for (uint32 i = 0; i < n_rs; i++) {
        typmod = ((rs_column_t *)cm_galist_get(rs_columns, i))->typmod;
        if (sql_get_rs_value(stmt, cursor, i, result) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (result->is_null) {
            result++;
            continue;
        }

        CT_RETURN_IFERR(sql_convert_rs_result_datatype(stmt, &typmod, result));

        if (CT_IS_STRING_TYPE(result->type) || CT_IS_BINARY_TYPE(result->type) || CT_IS_RAW_TYPE(result->type)) {
            status = sql_copy_rs_value(stmt, (char **)&buf, CT_CONVERT_BUFFER_SIZE * (n_rs_need_cvt - offset),
                (char **)&(result->v_text.str), result->v_text.len, &offset);
            if (status == CT_ERROR) {
                break;
            }
        } else if (CT_IS_LOB_TYPE(result->type)) {
            if (result->v_lob.type == CT_LOB_FROM_KERNEL) {
                status = sql_copy_rs_value(stmt, (char **)&buf, CT_CONVERT_BUFFER_SIZE * (n_rs_need_cvt - offset),
                    (char **)&(result->v_lob.knl_lob.bytes), result->v_lob.knl_lob.size, &offset);
                if (status == CT_ERROR) {
                    break;
                }
            } else if (result->v_lob.type == CT_LOB_FROM_NORMAL) {
                status = sql_copy_rs_value(stmt, (char **)&buf, CT_CONVERT_BUFFER_SIZE * (n_rs_need_cvt - offset),
                    (char **)&(result->v_lob.normal_lob.value.str), result->v_lob.normal_lob.value.len, &offset);
                if (status == CT_ERROR) {
                    break;
                }
            }
        }

        result++;
    }

    return status;
}

static status_t sql_push_convert_buf(sql_stmt_t *stmt, galist_t *rs_columns, expr_node_type_t node_type, char **buf,
    uint32 *n_rs, uint32 *n_rs_need_cvt)
{
    rs_column_t *rs_col = NULL;
    *n_rs_need_cvt = 0;

    if (node_type == EXPR_NODE_SELECT) {
        *n_rs = rs_columns->count;
        for (uint32 i = 0; i < *n_rs; i++) {
            rs_col = (rs_column_t *)cm_galist_get(rs_columns, i);
            // STRING/BINARY/RAW/LOB, ref to sql_get_all_rs_value
            if (CT_IS_VARLEN_TYPE(rs_col->datatype) || CT_IS_LOB_TYPE(rs_col->datatype) ||
                CT_IS_UNKNOWN_TYPE(rs_col->datatype)) {
                (*n_rs_need_cvt)++;
            }
        }
    } else {
        *n_rs = 1;
    }

    if (*n_rs_need_cvt > 0) {
        CT_RETURN_IFERR(sql_push(stmt, CT_CONVERT_BUFFER_SIZE * (*n_rs_need_cvt), (void **)buf));
    }

    return CT_SUCCESS;
}

status_t sql_get_select_value(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    bool32 pending = CT_FALSE;
    status_t status = CT_SUCCESS;
    uint32 n_rs, n_rs_need_cvt;
    uint32 row_count = 0;
    char *buf = NULL;
    sql_cursor_t *cursor = NULL;
    sql_cursor_t *parent_cur = CTSQL_CURR_CURSOR(stmt);
    var_object_t *v_obj = &node->value.v_obj;
    sql_select_t *select_ctx = (sql_select_t *)v_obj->ptr;
    galist_t *rs_columns = select_ctx->first_query->rs_columns;

    CT_RETURN_IFERR(sql_check_sub_select_pending(parent_cur, select_ctx, &pending));
    if (pending) {
        result->type = CT_TYPE_COLUMN;
        result->is_null = CT_FALSE;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_get_ssa_cursor(parent_cur, select_ctx, v_obj->id, &cursor));
    stmt = parent_cur->stmt;
    CT_RETURN_IFERR(sql_push_convert_buf(stmt, rs_columns, node->type, &buf, &n_rs, &n_rs_need_cvt));
    CT_RETURN_IFERR(sql_execute_select_plan(stmt, cursor, cursor->plan->select_p.next));

    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    for (;;) {
        if (sql_fetch_cursor(stmt, cursor, cursor->plan->select_p.next, &cursor->eof) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (cursor->eof) {
            if (row_count == 0) {
                for (uint32 i = 0; i < n_rs; i++) {
                    VAR_SET_NULL(result, ((rs_column_t *)cm_galist_get(cursor->columns, i))->datatype);
                    result++;
                }
            }
            break;
        }

        row_count++;

        if (row_count > 1) {
            CT_SRC_THROW_ERROR(node->loc, ERR_TOO_MANY_ROWS);
            status = CT_ERROR;
            break;
        }

        status = sql_get_all_rs_value(stmt, cursor, result, buf, n_rs, n_rs_need_cvt, rs_columns);
        CT_BREAK_IF_ERROR(status);
    }
    SQL_CURSOR_POP(stmt);
    sql_close_cursor(stmt, cursor);
    return status;
}

status_t sql_get_serial_value(sql_stmt_t *stmt, knl_dictionary_t *dc, variant_t *value)
{
    if (stmt->serial_value <= 0) {
        if (knl_get_serial_value((knl_handle_t)stmt->session, dc->handle, &stmt->serial_value) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    value->type = CT_TYPE_BIGINT;
    value->is_null = CT_FALSE;
    value->v_bigint = stmt->serial_value;

    return CT_SUCCESS;
}

static status_t sql_get_default(sql_stmt_t *stmt, expr_node_t *node, variant_t *value)
{
    knl_dictionary_t dc;
    bool32 is_true = CT_FALSE;

    if (stmt->default_column == NULL) {
        CT_SRC_THROW_ERROR(node->loc, ERR_UNEXPECTED_KEY, "'DEFAULT' found");
        return CT_ERROR;
    }

    knl_column_t *column = stmt->default_column;
    expr_tree_t *expr = column->default_expr;

    is_true = (stmt->context->type == CTSQL_TYPE_UPDATE && KNL_COLUMN_IS_UPDATE_DEFAULT(column));
    if (is_true) {
        expr = column->update_default_expr;
    }

    is_true = (stmt->context->type == CTSQL_TYPE_MERGE && stmt->merge_type == MERGE_TYPE_UPDATE &&
        KNL_COLUMN_IS_UPDATE_DEFAULT(column));
    if (is_true) {
        expr = column->update_default_expr;
    }

    if (expr == NULL) {
        is_true = ((stmt->context->type != CTSQL_TYPE_INSERT && stmt->context->type != CTSQL_TYPE_UPDATE &&
            stmt->context->type != CTSQL_TYPE_MERGE) ||
            !(column->flags & KNL_COLUMN_FLAG_SERIAL));
        if (is_true) {
            CT_SRC_THROW_ERROR(node->loc, ERR_UNEXPECTED_KEY, "'DEFAULT' found");
            return CT_ERROR;
        }

        if (stmt->context->type == CTSQL_TYPE_INSERT ||
            (stmt->context->type == CTSQL_TYPE_MERGE && stmt->merge_type == MERGE_TYPE_INSERT)) {
            if (knl_open_dc_by_id((knl_handle_t)stmt->session, column->uid, column->table_id, &dc, CT_TRUE) !=
                CT_SUCCESS) {
                return CT_ERROR;
            }

            if (CT_SUCCESS != sql_get_serial_value(stmt, &dc, value)) {
                knl_close_dc(&dc);
                return CT_ERROR;
            }
            knl_close_dc(&dc);
        } else if (stmt->context->type == CTSQL_TYPE_UPDATE ||
            (stmt->context->type == CTSQL_TYPE_MERGE && stmt->merge_type == MERGE_TYPE_UPDATE)) {
            value->type = CT_TYPE_BIGINT;
            value->is_null = CT_FALSE;
            value->v_bigint = 0;
        }

        return CT_SUCCESS;
    }

    return sql_exec_expr(stmt, expr, value);
}

static status_t sql_get_connect_by_isleaf(sql_stmt_t *stmt, variant_t *value)
{
    sql_cursor_t *cursor = NULL;
    CM_POINTER2(stmt, value);

    cursor = CTSQL_CURR_CURSOR(stmt);

    value->type = CT_TYPE_INTEGER;
    value->is_null = CT_FALSE;
    value->v_int = cursor->connect_data.connect_by_isleaf;

    return CT_SUCCESS;
}

static status_t sql_get_connect_by_iscycle(sql_stmt_t *stmt, variant_t *value)
{
    sql_cursor_t *cursor = NULL;
    CM_POINTER2(stmt, value);

    cursor = CTSQL_CURR_CURSOR(stmt);

    value->type = CT_TYPE_INTEGER;
    value->is_null = CT_FALSE;
    value->v_int = cursor->connect_data.connect_by_iscycle;

    return CT_SUCCESS;
}

static status_t sql_get_level(sql_stmt_t *stmt, variant_t *value)
{
    sql_cursor_t *cursor = NULL;
    CM_POINTER2(stmt, value);

    cursor = CTSQL_CURR_CURSOR(stmt);

    value->type = CT_TYPE_INTEGER;
    value->is_null = CT_FALSE;
    value->v_int = cursor->connect_data.level;

    return CT_SUCCESS;
}

static status_t sql_get_trig_res(sql_stmt_t *stmt, expr_node_t *node, variant_t *value, uint32 trig_event)
{
    pl_executor_t *exec = NULL;
    trig_executor_t *trig_exec = NULL;

    exec = stmt->pl_exec;
    if (exec == NULL || exec->trig_exec == NULL) {
        CT_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR,
            "'DELETING' or 'UPDATING' or 'INSERTING' must be in a trigger");
        return CT_ERROR;
    }

    trig_exec = exec->trig_exec;

    value->is_null = CT_FALSE;
    value->type = CT_TYPE_BOOLEAN;
    value->v_bool = CT_FALSE;

    if (trig_exec->trig_event == trig_event) {
        value->v_bool = CT_TRUE;
    }

    return CT_SUCCESS;
}
status_t sql_get_tree_datetype(sql_stmt_t *stmt, expr_tree_t *tree, ct_type_t *type)
{
    expr_node_t *node = tree->root;
    variant_t result;
    if (node->type != EXPR_NODE_PARAM) {
        *type = NODE_DATATYPE(node);
        return CT_SUCCESS;
    }
    // if get expr param error, type can be node->datatype
    if (sql_get_param_value(stmt, VALUE(uint32, &node->value), &result) != CT_SUCCESS) {
        return CT_ERROR;
    }
    *type = result.type;
    return CT_SUCCESS;
}

inline status_t sql_get_reserved_value(sql_stmt_t *stmt, expr_node_t *node, variant_t *val)
{
    switch (node->value.v_int) {
        case RES_WORD_NULL:
        case RES_WORD_DUMMY:
            val->type = CT_DATATYPE_OF_NULL;
            val->is_null = CT_TRUE;
            break;

        case RES_WORD_CURDATE:
            val->type = CT_TYPE_DATE;
            val->is_null = CT_FALSE;
            if (stmt->v_sysdate == SQL_UNINITIALIZED_DATE) {
                /* drop millsec and microsec data */
                stmt->v_sysdate = cm_adjust_date(cm_now());
            }

            /* adjust with the session time zone */
            VALUE(date_t, val) =
                cm_adjust_date_between_two_tzs(stmt->v_sysdate, g_timer()->tz, sql_get_session_timezone(stmt));

            break;

        case RES_WORD_SYSDATE:
            val->type = CT_TYPE_DATE;
            val->is_null = CT_FALSE;
            SQL_GET_STMT_SYSDATE(stmt, val);
            break;

        case RES_WORD_CURTIMESTAMP:
            if (stmt->session->call_version >= CS_VERSION_8) {
                val->type = CT_TYPE_TIMESTAMP_TZ;
                val->v_tstamp_tz.tz_offset = sql_get_session_timezone(stmt);
            } else {
                val->type = CT_TYPE_TIMESTAMP_TZ_FAKE;
            }
            val->is_null = CT_FALSE;

            if ((stmt)->v_systimestamp == SQL_UNINITIALIZED_TSTAMP) {
                (stmt)->v_systimestamp = cm_now();
            }
            /* adjust with the session time zone */
            val->v_tstamp_tz.tstamp =
                cm_adjust_date_between_two_tzs(stmt->v_systimestamp, g_timer()->tz, sql_get_session_timezone(stmt));
            break;

        case RES_WORD_SYSTIMESTAMP:
            if (stmt->session->call_version >= CS_VERSION_8) {
                val->type = CT_TYPE_TIMESTAMP_TZ;
                val->v_tstamp_tz.tz_offset = g_timer()->tz;
            } else {
                val->type = CT_TYPE_TIMESTAMP_TZ_FAKE;
            }
            val->is_null = CT_FALSE;

            if ((stmt)->v_systimestamp == SQL_UNINITIALIZED_TSTAMP) {
                (stmt)->v_systimestamp = cm_now();
            }
            val->v_tstamp_tz.tstamp = stmt->v_systimestamp;
            break;

        case RES_WORD_LOCALTIMESTAMP:
            val->type = CT_TYPE_TIMESTAMP;
            val->is_null = CT_FALSE;

            if ((stmt)->v_systimestamp == SQL_UNINITIALIZED_TSTAMP) {
                (stmt)->v_systimestamp = cm_now();
            }

            /* adjust with the session time zone */
            val->v_tstamp =
                cm_adjust_date_between_two_tzs(stmt->v_systimestamp, g_timer()->tz, sql_get_session_timezone(stmt));
            break;

        case RES_WORD_UTCTIMESTAMP:
            val->v_date = cm_utc_now();
            val->is_null = CT_FALSE;
            val->type = CT_TYPE_DATE;
            break;

        case RES_WORD_ROWNUM:
            return sql_get_rownum(stmt, val);

        case RES_WORD_ROWID:
            return sql_get_rowid(stmt, &node->value.v_rid, val);

        case RES_WORD_ROWSCN:
            return sql_get_rowscn(stmt, &node->value.v_rid, val);

        case RES_WORD_DEFAULT:
            return sql_get_default(stmt, node, val);

        case RES_WORD_TRUE:
            val->type = CT_TYPE_BOOLEAN;
            val->is_null = CT_FALSE;
            val->v_bool = CT_TRUE;
            break;

        case RES_WORD_FALSE:
            val->type = CT_TYPE_BOOLEAN;
            val->is_null = CT_FALSE;
            val->v_bool = CT_FALSE;
            break;

        case RES_WORD_DELETING:
            return sql_get_trig_res(stmt, node, val, TRIG_EVENT_DELETE);

        case RES_WORD_INSERTING:
            return sql_get_trig_res(stmt, node, val, TRIG_EVENT_INSERT);

        case RES_WORD_UPDATING:
            return sql_get_trig_res(stmt, node, val, TRIG_EVENT_UPDATE);

        case RES_WORD_LEVEL:
            return sql_get_level(stmt, val);

        case RES_WORD_CONNECT_BY_ISLEAF:
            return sql_get_connect_by_isleaf(stmt, val);

        case RES_WORD_CONNECT_BY_ISCYCLE:
            return sql_get_connect_by_iscycle(stmt, val);

        case RES_WORD_USER:
            val->type = CT_TYPE_STRING;
            val->is_null = CT_FALSE;
            val->v_text.str = stmt->session->db_user;
            val->v_text.len = (uint32)strlen(stmt->session->db_user);
            break;

        case RES_WORD_DATABASETZ:
            val->type = CT_TYPE_STRING;
            val->is_null = CT_FALSE;

            char *dbtz = srv_get_param("DB_TIMEZONE");
            val->v_text.str = dbtz;
            val->v_text.len = (uint32)strlen(dbtz);
            break;

        case RES_WORD_SESSIONTZ:
            val->type = CT_TYPE_STRING;
            val->is_null = CT_FALSE;
            CT_RETURN_IFERR(sql_push(stmt, TIMEZONE_OFFSET_STRLEN, (void **)&(val->v_text.str)));
            if (cm_tzoffset2text(sql_get_session_timezone(stmt), &(val->v_text)) != CT_SUCCESS) {
                CTSQL_POP(stmt);
                return CT_ERROR;
            }
            sql_keep_stack_variant(stmt, val);
            break;

        default:
            CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "reserved word not in list");
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

static inline status_t sql_set_connect_by_curosr(sql_stmt_t *stmt, expr_node_t *node, sql_cursor_t **cur,
    variant_t *result)
{
    sql_cursor_t *last_level_cursor = NULL;
    result->is_null = CT_FALSE;

    *cur = OBJ_STACK_CURR(&(stmt)->cursor_stack);
    if ((*cur)->connect_data.cur_level_cursor != NULL) {
        last_level_cursor = (*cur)->connect_data.cur_level_cursor->connect_data.last_level_cursor;
        if (last_level_cursor == NULL) {
            VAR_SET_NULL(result, NODE_DATATYPE(node));
            return CT_SUCCESS;
        }

        (*cur)->connect_data.cur_level_cursor = last_level_cursor;
        *cur = NULL;
        return CT_SUCCESS;
    }
    // is not first level cursor
    if (stmt->cursor_stack.depth <= 1 || (*cur)->connect_data.last_level_cursor == NULL) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "stmt->cursor_stack.depth(%u) > 1", (uint32)stmt->cursor_stack.depth);
        return CT_ERROR;
    }
    return SQL_CURSOR_PUSH(stmt, (*cur)->connect_data.last_level_cursor);
}

static inline void sql_unset_connect_by_curosr(sql_stmt_t *stmt, expr_node_t *node, sql_cursor_t *cur)
{
    if (cur != NULL) {
        SQL_CURSOR_POP(stmt);
    } else {
        cur = OBJ_STACK_CURR(&(stmt)->cursor_stack);
        // cur->connect_data.cur_level_cursor must be not null
        cur->connect_data.cur_level_cursor = cur->connect_data.cur_level_cursor->connect_data.next_level_cursor;
    }
}

static status_t sql_save_push_offsets(sql_stmt_t *stmt, uint32 **push_offset)
{
    cm_stack_t *path_stack = NULL;
    sql_cursor_t *curr_cursor = CTSQL_CURR_CURSOR(stmt);
    sql_cursor_t *first_level_cur = curr_cursor->connect_data.first_level_cursor;
    uint32 path_cnt = first_level_cur->connect_data.path_func_nodes->count;
    if (path_cnt > 0) {
        CT_RETURN_IFERR(sql_push(stmt, sizeof(uint32) * path_cnt, (void **)push_offset));
        for (uint32 i = 0; i < path_cnt; i++) {
            path_stack = first_level_cur->connect_data.path_stack + i;
            (*push_offset)[i] = path_stack->push_offset;
            cm_pop(path_stack);
        }
    }
    return CT_SUCCESS;
}

static void sql_restore_push_offsets(sql_stmt_t *stmt, uint32 *push_offset)
{
    cm_stack_t *path_stack = NULL;
    sql_cursor_t *curr_cursor = CTSQL_CURR_CURSOR(stmt);
    sql_cursor_t *first_level_cur = curr_cursor->connect_data.first_level_cursor;
    for (uint32 i = 0; i < first_level_cur->connect_data.path_func_nodes->count; i++) {
        path_stack = first_level_cur->connect_data.path_stack + i;
        path_stack->push_offset = push_offset[i];
    }
}

static status_t sql_exec_connect_by_expr(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    sql_cursor_t *cur = NULL;
    uint32 *push_offset = NULL;
    CT_RETURN_IFERR(sql_set_connect_by_curosr(stmt, node, &cur, result));
    if (result->is_null) {
        return CT_SUCCESS;
    }
    CTSQL_SAVE_STACK(stmt);
    if (sql_save_push_offsets(stmt, &push_offset) != CT_SUCCESS) {
        sql_unset_connect_by_curosr(stmt, node, cur);
        return CT_ERROR;
    }
    if (sql_exec_expr_node(stmt, node->right, result) != CT_SUCCESS) {
        sql_unset_connect_by_curosr(stmt, node, cur);
        return CT_ERROR;
    }
    sql_restore_push_offsets(stmt, push_offset);
    CTSQL_RESTORE_STACK(stmt);
    sql_unset_connect_by_curosr(stmt, node, cur);
    return CT_SUCCESS;
}

static inline status_t sql_get_case_element_value(sql_stmt_t *stmt, expr_node_t *case_node, expr_tree_t *element,
    variant_t *result)
{
    CT_RETURN_IFERR(sql_exec_expr(stmt, element, result));
    SQL_CHECK_COLUMN_VAR(result, result);
    if (result->is_null) {
        SQL_SET_NULL_VAR(result);
        return CT_SUCCESS;
    }
    if (CT_IS_LOB_TYPE(result->type) && result->type != case_node->datatype) {
        CT_RETURN_IFERR(sql_get_lob_value(stmt, result));
    }
    if (case_node->typmod.is_array) {
        return sql_convert_to_array(stmt, result, &case_node->typmod, CT_FALSE);
    } else if (result->type != case_node->datatype && case_node->datatype != CT_TYPE_UNKNOWN) {
        return sql_convert_variant(stmt, result, case_node->datatype);
    }
    return CT_SUCCESS;
}

static status_t sql_get_case_value(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    cond_result_t cond_ret = COND_FALSE;
    int32 cmp_result;
    case_pair_t *pair = NULL;
    variant_t cmp_var, when_var;
    bool32 pending = CT_FALSE;

    CM_POINTER3(stmt, node, result);

    case_expr_t *case_expr = VALUE(pointer_t, &node->value);
    CM_POINTER(case_expr);
    if (!case_expr->is_cond) {
        SQL_EXEC_FUNC_ARG(case_expr->expr, &cmp_var, result, stmt);

        sql_keep_stack_variant(stmt, &cmp_var);

        for (uint32 i = 0; i < case_expr->pairs.count; i++) {
            pair = (case_pair_t *)cm_galist_get(&case_expr->pairs, i);

            SQL_EXEC_FUNC_ARG(pair->when_expr, &when_var, result, stmt);

            if (sql_compare_variant(stmt, &cmp_var, &when_var, &cmp_result) != CT_SUCCESS) {
                return CT_ERROR;
            }
            if (cmp_result != 0) {
                continue;
            }
            return sql_get_case_element_value(stmt, node, pair->value, result);
        }
    } else {
        for (uint32 i = 0; i < case_expr->pairs.count; i++) {
            pair = (case_pair_t *)cm_galist_get(&case_expr->pairs, i);

            CT_RETURN_IFERR(sql_match_cond_argument(stmt, pair->when_cond->root, &pending, &cond_ret));
            SQL_CHECK_COND_PANDING(pending, result);

            if (cond_ret != COND_TRUE) {
                continue;
            }
            return sql_get_case_element_value(stmt, node, pair->value, result);
        }
    }

    if (case_expr->default_expr == NULL) {
        SQL_SET_NULL_VAR(result);
        return CT_SUCCESS;
    }
    return sql_get_case_element_value(stmt, node, case_expr->default_expr, result);
}

/* save the origin value to vlob, should convert value if write to table as filed value for some data types */
status_t sql_exec_array_element(sql_stmt_t *stmt, array_assist_t *aa, uint32 subscript, variant_t *element_val,
    bool32 last, vm_lob_t *vlob)
{
    uint16 offset;
    uint16 len;
    row_assist_t ra;
    date_t date_val;
    char *buf = NULL;
    status_t status = CT_SUCCESS;

    if (element_val->is_null) {
        return array_append_element(aa, subscript, NULL, 0, CT_TRUE, last, vlob);
    }

    if (sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf) != CT_SUCCESS) {
        return CT_ERROR;
    }

    row_init(&ra, buf, CT_MAX_ROW_SIZE, 1);
    switch (element_val->type) {
        case CT_TYPE_UINT32:
            status = row_put_uint32(&ra, element_val->v_uint32);
            break;

        case CT_TYPE_INTEGER:
            status = row_put_uint32(&ra, element_val->v_uint32);
            break;

        case CT_TYPE_BOOLEAN:
            status = row_put_bool(&ra, element_val->v_bool);
            break;

        case CT_TYPE_BIGINT:
            status = row_put_int64(&ra, element_val->v_bigint);
            break;

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
            status = row_put_dec4(&ra, &element_val->v_dec);
            break;
        case CT_TYPE_NUMBER2:
            status = row_put_dec2(&ra, &element_val->v_dec);
            break;

        case CT_TYPE_REAL:
            status = row_put_real(&ra, element_val->v_real);
            break;

        case CT_TYPE_DATE:
            date_val = cm_adjust_date(element_val->v_date);
            status = row_put_int64(&ra, date_val);
            break;

        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
            status = row_put_int64(&ra, element_val->v_tstamp);
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            status = row_put_timestamp_tz(&ra, &element_val->v_tstamp_tz);
            break;

        case CT_TYPE_INTERVAL_DS:
            status = row_put_dsinterval(&ra, element_val->v_itvl_ds);
            break;

        case CT_TYPE_INTERVAL_YM:
            status = row_put_yminterval(&ra, element_val->v_itvl_ym);
            break;

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            status = row_put_text(&ra, &element_val->v_text);
            break;

        default:
            CT_THROW_ERROR(ERR_UNSUPPORT_DATATYPE, get_datatype_name_str(element_val->type));
            status = CT_ERROR;
            break;
    }

    if (status != CT_SUCCESS) {
        CTSQL_POP(stmt);
        return CT_ERROR;
    }

    cm_decode_row((char *)(ra.head), &offset, &len, NULL);
    status = array_append_element(aa, subscript, ra.buf + offset, len, CT_FALSE, last, vlob);
    CTSQL_POP(stmt);
    return status;
}

/* execute the const array expr */
static status_t sql_exec_array(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    variant_t ele_val;
    vm_lob_t *vlob = NULL;
    uint32 ele_cnt;
    array_assist_t array_ass;
    vm_page_t *vpage = NULL;
    array_head_t *head = NULL;
    bool32 last = CT_FALSE;
    expr_tree_t *expr = node->argument;
    id_list_t *vm_list = sql_get_exec_lob_list(stmt);

    result->type = CT_TYPE_ARRAY;
    result->v_array.count = node->value.v_array.count;
    ele_cnt = node->value.v_array.count;

    result->is_null = CT_FALSE;
    result->v_array.type = node->datatype;
    result->v_array.value.type = CT_LOB_FROM_VMPOOL;
    vlob = &result->v_array.value.vm_lob;

    if (array_init(&array_ass, KNL_SESSION(stmt), stmt->mtrl.pool, vm_list, vlob)) {
        return CT_ERROR;
    }

    if (ele_cnt == 0) {
        return CT_SUCCESS;
    }

    while (expr != NULL) {
        CTSQL_SAVE_STACK(stmt);
        CT_RETURN_IFERR(sql_exec_expr(stmt, expr, &ele_val));
        SQL_CHECK_COLUMN_VAR(&ele_val, result);
        sql_keep_stack_variant(stmt, &ele_val);
        if (node->datatype != ele_val.type) {
            /* other elements should have the same datatype with the node or can be converted */
            CT_RETURN_IFERR(sql_convert_variant(stmt, &ele_val, node->datatype));
            sql_keep_stack_variant(stmt, &ele_val);
        }

        /* save the element value to vm_lob */
        last = expr->next == NULL ? CT_TRUE : CT_FALSE;
        CT_RETURN_IFERR(sql_exec_array_element(stmt, &array_ass, expr->subscript, &ele_val, last, vlob));
        CTSQL_RESTORE_STACK(stmt);
        expr = expr->next;
    }

    /* update datatype */
    CT_RETURN_IFERR(vm_open(KNL_SESSION(stmt), stmt->mtrl.pool, vlob->entry_vmid, &vpage));
    head = (array_head_t *)vpage->data;
    head->datatype = node->datatype;
    vlob->size = head->size;
    vm_close(KNL_SESSION(stmt), stmt->mtrl.pool, vlob->entry_vmid, VM_ENQUE_HEAD);
    return CT_SUCCESS;
}

status_t sql_get_lob_value_from_vm(sql_stmt_t *stmt, variant_t *result)
{
    uint32 vmid;
    uint32 len, copy_len, offset, remain_len;
    errno_t ret;
    char *buf = NULL;
    vm_page_t *vpage = NULL;
    vm_pool_t *vm_pool = stmt->mtrl.pool;

    len = result->v_lob.vm_lob.size;
    vmid = result->v_lob.vm_lob.entry_vmid;

    if (len > 0) {
        if (len > g_instance->attr.lob_max_exec_size) {
            CT_THROW_ERROR(ERR_ILEGAL_LOB_READ, len, g_instance->attr.lob_max_exec_size);
            return CT_ERROR;
        }

        CT_RETURN_IFERR(sql_push(stmt, len, (void **)&buf));
        offset = 0;
        remain_len = len;
        while (remain_len != 0 && vmid != CT_INVALID_ID32) {
            copy_len = MIN(remain_len, CT_VMEM_PAGE_SIZE);
            CT_RETURN_IFERR(vm_open(stmt->session, vm_pool, vmid, &vpage));
            ret = memcpy_s(buf + offset, len - offset, (char *)vpage->data, copy_len);
            if (ret != EOK) {
                vm_close(stmt->session, vm_pool, vmid, VM_ENQUE_HEAD);
                CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
                return CT_ERROR;
            }

            remain_len -= copy_len;
            offset += copy_len;
            vm_close(stmt->session, vm_pool, vmid, VM_ENQUE_HEAD);
            if (remain_len > 0) {
                vmid = vm_get_ctrl(stmt->mtrl.pool, vmid)->sort_next;
            }
        }
    }

    if (result->type == CT_TYPE_CLOB || result->type == CT_TYPE_IMAGE) {
        result->type = CT_TYPE_STRING;
        result->v_text.str = buf;
        result->v_text.len = len;
    } else {
        result->type = CT_TYPE_RAW;
        result->v_bin.bytes = (uint8 *)buf;
        result->v_bin.size = len;
    }

    return CT_SUCCESS;
}

status_t sql_get_lob_value_from_knl(sql_stmt_t *stmt, variant_t *res)
{
    char *buf = NULL;
    uint32 len;
    knl_handle_t lob_locator;

    lob_locator = (knl_handle_t)res->v_lob.knl_lob.bytes;
    len = knl_lob_size(lob_locator);
    if (len != 0) {
        if (len > g_instance->attr.lob_max_exec_size) {
            CT_THROW_ERROR(ERR_ILEGAL_LOB_READ, len, g_instance->attr.lob_max_exec_size);
            return CT_ERROR;
        }
        sql_keep_stack_variant(stmt, res);
        CT_RETURN_IFERR(sql_push(stmt, len, (void **)&buf));
        CT_RETURN_IFERR(knl_read_lob(stmt->session, lob_locator, 0, (void *)buf, len, NULL, NULL));
    }

    if (res->type == CT_TYPE_CLOB || res->type == CT_TYPE_IMAGE) {
        res->type = CT_TYPE_STRING;
        res->v_text.str = buf;
        res->v_text.len = len;
    } else {
        res->type = CT_TYPE_RAW;
        res->v_bin.bytes = (uint8 *)buf;
        res->v_bin.size = len;
    }
    return CT_SUCCESS;
}

status_t sql_get_lob_value_from_normal(sql_stmt_t *stmt, variant_t *res)
{
    text_t lob_value = res->v_lob.normal_lob.value;

    if (res->type == CT_TYPE_CLOB || res->type == CT_TYPE_IMAGE) {
        res->type = CT_TYPE_STRING;
        res->v_text = lob_value;
    } else {
        res->type = CT_TYPE_RAW;
        res->v_bin.bytes = (uint8 *)lob_value.str;
        res->v_bin.size = lob_value.len;
    }
    return CT_SUCCESS;
}

status_t sql_get_lob_value(sql_stmt_t *stmt, variant_t *result)
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

status_t sql_get_element_to_value(sql_stmt_t *stmt, array_assist_t *array_ass, vm_lob_t *src, int32 start, int32 end,
    ct_type_t type, variant_t *value)
{
    uint32 len;
    char *ele_value = NULL;

    value->is_null = CT_FALSE;
    value->type = type;
    /* get the element size first to alloc enough buffer to store */
    if (array_get_element_info(array_ass, &len, NULL, src, start) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (len == 0) {
        value->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    if (sql_push(stmt, len, (void **)&ele_value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (array_get_element_by_subscript(array_ass, ele_value, len, src, start) != CT_SUCCESS) {
        CTSQL_POP(stmt);
        return CT_ERROR;
    }

    /* for var len variant, caller should keep the value in stack */
    if (CT_IS_VARLEN_TYPE(value->type)) {
        value->v_bin.bytes = (uint8 *)ele_value;
        value->v_bin.size = len;
    } else {
        errno_t errcode = memcpy_sp(VALUE_PTR(int32, value), len, ele_value, len);
        if (errcode != EOK) {
            CTSQL_POP(stmt);
            CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CT_ERROR;
        }
    }

    if (CT_IS_DECIMAL_TYPE(value->type)) {
        CT_RETURN_IFERR(cm_dec_4_to_8(VALUE_PTR(dec8_t, value), (dec4_t *)ele_value, len));
    } else if (CT_IS_NUMBER2_TYPE(value->type)) {
        CT_RETURN_IFERR(cm_dec_2_to_8(VALUE_PTR(dec8_t, value), (const payload_t *)ele_value, len));
    }

    CTSQL_POP(stmt);
    return CT_SUCCESS;
}

status_t sql_get_subarray_to_value(array_assist_t *array_ass, vm_lob_t *src, int32 start, int32 end, ct_type_t type,
    variant_t *value)
{
    vm_lob_t dst;

    cm_reset_vm_lob(&dst);
    value->is_null = CT_FALSE;
    value->type = CT_TYPE_ARRAY;
    value->v_array.type = type;
    value->v_array.value.type = CT_LOB_FROM_VMPOOL;

    CT_RETURN_IFERR(array_get_subarray(array_ass, src, &dst, start, end));

    value->v_array.value.vm_lob = dst;
    if (dst.entry_vmid != CT_INVALID_ID32) {
        CT_RETURN_IFERR(array_get_element_count(array_ass, &dst, &value->v_array.count));
        return array_update_head_datatype(array_ass, &dst, type);
    }

    return CT_SUCCESS;
}

static sql_table_t g_init_table = {
    .id = 0,
    .type = NORMAL_TABLE,
    .remote_type = REMOTE_TYPE_LOCAL
};

status_t sql_get_param_value(sql_stmt_t *stmt, uint32 id, variant_t *result)
{
    if (stmt->is_explain) {
        result->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    if (stmt->plsql_mode == PLSQL_NONE) {
        var_copy(&stmt->param_info.params[id].value, result);
        return CT_SUCCESS;
    } else {
        sql_param_mark_t *param = (sql_param_mark_t *)cm_galist_get(stmt->context->params, id);
        return ple_get_param_value(stmt, id, param->pnid, result);
    }
}

static inline status_t sql_get_ddm_group_value(sql_stmt_t *stmt, var_vm_col_t *v_vm_col, variant_t *val)
{
    if (SECUREC_UNLIKELY(stmt->need_send_ddm && v_vm_col->is_ddm_col)) {
        expr_node_t *origin_ref = (expr_node_t *)v_vm_col->origin_ref;
        CT_RETSUC_IFTRUE(origin_ref->type != EXPR_NODE_COLUMN);
        sql_cursor_t *cur = sql_get_group_cursor(CTSQL_CURR_CURSOR(stmt));
        CT_RETURN_IFERR(sql_get_ancestor_cursor(cur, v_vm_col->ancestor, &cur));
        CT_RETSUC_IFTRUE(cur->tables == NULL);
        sql_table_cursor_t *tab_cur = &cur->tables[NODE_TAB(origin_ref)];
        if (tab_cur->table == NULL || tab_cur->table->type != NORMAL_TABLE || KNL_SESSION(stmt)->uid == 0 ||
            knl_check_sys_priv_by_uid(KNL_SESSION(stmt), KNL_SESSION(stmt)->uid, EXEMPT_REDACTION_POLICY)) {
            return CT_SUCCESS;
        }
        knl_column_t *column = dc_get_column(DC_ENTITY(&tab_cur->table->entry->dc), NODE_COL(origin_ref));
        if (column->ddm_expr != NULL) {
            return sql_exec_expr(stmt, (expr_tree_t *)column->ddm_expr, val);
        }
    }
    return CT_SUCCESS;
}

void sql_copy_first_exec_var(sql_stmt_t *stmt, variant_t *src, variant_t *dst)
{
    if (src->is_null) {
        dst->ctrl = src->ctrl;
        return;
    }

    if (!CT_IS_VARLEN_TYPE(src->type)) { // copy non-var-len datatype
        var_copy(src, dst);
        return;
    }

    // copy var-len datatype
    // if buff space is insufficient, then do not optimize
    if ((stmt->fexec_info.fexec_buff_offset + src->v_text.len) > stmt->context->fexec_vars_bytes) {
        return;
    }

    // compute the data buff address
    dst->v_text.str = (char *)stmt->fexec_info.first_exec_vars + (stmt->context->fexec_vars_cnt * sizeof(variant_t)) +
        stmt->fexec_info.fexec_buff_offset;

    if (src->v_text.len != 0) {
        MEMS_RETVOID_IFERR(memcpy_s(dst->v_text.str, src->v_text.len, src->v_text.str, src->v_text.len));
    }
    if (src->type == CT_TYPE_BINARY) {
        dst->v_bin.is_hex_const = src->v_bin.is_hex_const;
    }

    dst->ctrl = src->ctrl;
    dst->v_text.len = src->v_text.len;
    stmt->fexec_info.fexec_buff_offset += dst->v_text.len;
}

status_t sql_exec_expr_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    status_t status;
    sql_cursor_t *cur = NULL;
    sql_cursor_t *saved_cursor = NULL;
    bool32 exist_first_exec_vars = (bool32)(NODE_IS_FIRST_EXECUTABLE(node) && F_EXEC_VARS(stmt) != NULL);

    CT_RETURN_IFERR(sql_stack_safe(stmt));
    if (exist_first_exec_vars && F_EXEC_VALUE(stmt, node)->type != CT_TYPE_UNINITIALIZED) {
        var_copy(F_EXEC_VALUE(stmt, node), result);
        return CT_SUCCESS;
    }

    bool32 unary_root = ((int32)node->unary == (int32)UNARY_OPER_ROOT || (int32)node->unary == -(int32)UNARY_OPER_ROOT);

    if (SECUREC_UNLIKELY(unary_root)) {
        if (stmt->cursor_stack.depth == 0) {
            CT_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "CONNECT BY clause required in this query block");
            return CT_ERROR;
        }
        cur = CTSQL_CURR_CURSOR(stmt);
        if (cur->connect_data.first_level_cursor == NULL) {
            CT_SRC_THROW_ERROR_EX(node->loc, ERR_SQL_SYNTAX_ERROR, "CONNECT BY clause required in this query block");
            return CT_ERROR;
        }

        saved_cursor = cur->connect_data.cur_level_cursor;
        cur->connect_data.cur_level_cursor = cur->connect_data.first_level_cursor;
        CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cur));
    }

    status = sql_get_node_func(node->type)->invoke(stmt, node, result);

    if (SECUREC_UNLIKELY(unary_root)) {
        cur->connect_data.cur_level_cursor = saved_cursor;
        SQL_CURSOR_POP(stmt);
    }

    if (status != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (node->unary != UNARY_OPER_NONE) {
        CT_RETURN_IFERR(sql_exec_unary(node, result));
    }

    if (exist_first_exec_vars) {
        if (result->type == CT_TYPE_ARRAY) {
            return CT_SUCCESS;
        }
        sql_copy_first_exec_var(stmt, result, F_EXEC_VALUE(stmt, node));
    }

    if (node->type != EXPR_NODE_PARAM && !result->is_null && CT_IS_NUMBER_TYPE(result->type)) {
        CT_RETURN_IFERR(cm_dec_check_overflow(VALUE_PTR(dec8_t, result), result->type));
    }
    return CT_SUCCESS;
}

bool32 sql_expr_node_exist_table(expr_node_t *node, uint32 table_id)
{
    cols_used_t used_cols;
    biqueue_t *cols_que = NULL;
    biqueue_node_t *curr = NULL;
    biqueue_node_t *end = NULL;
    expr_node_t *col = NULL;

    init_cols_used(&used_cols);
    sql_collect_cols_in_expr_node(node, &used_cols);

    cols_que = &used_cols.cols_que[SELF_IDX];
    curr = biqueue_first(cols_que);
    end = biqueue_end(cols_que);

    while (curr != end) {
        col = OBJECT_OF(expr_node_t, curr);
        if (table_id == TAB_OF_NODE(col)) {
            return CT_TRUE;
        }
        curr = curr->next;
    }
    return CT_FALSE;
}

bool32 sql_expr_node_exist_ancestor_table(expr_node_t *node, uint32 table_id, uint32 is_ancestor)
{
    switch (node->type) {
        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MOD:
        case EXPR_NODE_CAT:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
        case EXPR_NODE_NEGATIVE:
            return CT_FALSE;

        case EXPR_NODE_COLUMN:
            return (bool32)((NODE_ANCESTOR(node) == is_ancestor && NODE_TAB(node) == table_id) ? CT_TRUE : CT_FALSE);

        case EXPR_NODE_FUNC:
            return CT_FALSE;

        default:
            return CT_FALSE;
    }
}

status_t sql_exec_default(void *stmt, void *default_expr, variant_t *val)
{
    return sql_exec_expr((sql_stmt_t *)stmt, (expr_tree_t *)default_expr, val);
}

/*
  This function will be called when create an function index.
  We should compare the expression node rather than the expression text only.
*/
bool32 sql_compare_index_expr(knl_handle_t session, text_t *func_text1, text_t *func_text2)
{
    sql_stmt_t *stmt = ((session_t *)session)->current_stmt;
    sql_text_t sql_text;
    sql_verifier_t verif = { 0 };
    expr_tree_t *expr1 = NULL;
    expr_tree_t *expr2 = NULL;

    verif.stmt = stmt;
    verif.context = stmt->context;
    verif.is_check_cons = CT_TRUE;
    verif.table_def =
        ((stmt->context->type == CTSQL_TYPE_CREATE_TABLE) && DB_ATTR_COMPATIBLE_MYSQL((knl_session_t *)session)) ?
        (knl_table_def_t *)stmt->context->entry :
        NULL;
    verif.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_SUBSELECT | SQL_EXCL_BIND_PARAM | SQL_EXCL_PRIOR |
        SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_ROWSCN | SQL_EXCL_SEQUENCE |
        SQL_EXCL_WIN_SORT | SQL_EXCL_GROUPING | SQL_EXCL_PATH_FUNC;

    sql_text.value = *func_text1;
    sql_text.loc.column = 1;
    sql_text.loc.line = 1;

    lex_t *lex = ((session_t *)session)->lex;
    lex->flags |= (LEX_WITH_ARG | LEX_WITH_OWNER);

    if (sql_create_expr_from_text(stmt, &sql_text, &expr1, WORD_FLAG_NONE) != CT_SUCCESS) {
        return CT_FALSE;
    }

    if (sql_verify_expr_node(&verif, expr1->root) != CT_SUCCESS) {
        return CT_ERROR;
    }

    sql_text.value = *func_text2;
    sql_text.loc.column = 1;
    sql_text.loc.line = 1;
    if (sql_create_expr_from_text(stmt, &sql_text, &expr2, WORD_FLAG_NONE) != CT_SUCCESS) {
        return CT_FALSE;
    }

    if (sql_verify_expr_node(&verif, expr2->root) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_expr_node_equal(stmt, expr1->root, expr2->root, NULL);
}

/*
  this function will be called when alter column's precision or datatype
*/
status_t sql_get_func_index_expr_size(knl_handle_t session, text_t *default_text, typmode_t *typmode)
{
    sql_stmt_t *stmt = ((session_t *)session)->current_stmt;
    sql_text_t sql_text;
    sql_verifier_t verif = { 0 };
    expr_tree_t *expr = NULL;

    lex_t *lex = ((session_t *)session)->lex;

    sql_text.value = *default_text;
    sql_text.loc.column = 1;
    sql_text.loc.line = 1;
    lex->flags |= (LEX_WITH_ARG | LEX_WITH_OWNER);

    if (sql_create_expr_from_text(stmt, &sql_text, &expr, WORD_FLAG_NONE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    verif.stmt = stmt;
    verif.context = stmt->context;
    verif.is_check_cons = CT_TRUE;
    verif.typmode = typmode;
    verif.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_SUBSELECT | SQL_EXCL_BIND_PARAM | SQL_EXCL_PRIOR |
        SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_ROWSCN | SQL_EXCL_SEQUENCE |
        SQL_EXCL_WIN_SORT | SQL_EXCL_GROUPING | SQL_EXCL_PATH_FUNC;

    if (sql_verify_expr_node(&verif, expr->root) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *typmode = TREE_TYPMODE(expr);
    return CT_SUCCESS;
}

/*
 * This function will be called when executing:
 * 1. add index/constraint
 * 2. insert/update
 */
status_t sql_exec_index_col_func(knl_handle_t sess, knl_handle_t knl_cursor, ct_type_t datatype, void *expr,
    variant_t *result, bool32 is_new)
{
    status_t status;
    session_t *session = (session_t *)sess;
    sql_stmt_t *stmt = session->current_stmt;
    knl_cursor_t *knl_cur = (knl_cursor_t *)knl_cursor;
    knl_cursor_t *saved_cur = stmt->direct_knl_cursor;
    bool32 saved_check = stmt->is_check;
    typmode_t *mode = &TREE_TYPMODE((expr_tree_t *)expr);

    CTSQL_SAVE_STACK(stmt);

    stmt->direct_knl_cursor = knl_cur;
    stmt->is_check = is_new;
    do {
        status = sql_exec_expr(stmt, (expr_tree_t *)expr, result);
        CT_BREAK_IF_ERROR(status);
        if (result->type != datatype) {
            status = sql_convert_variant(stmt, result, datatype);
        }
        CT_BREAK_IF_ERROR(status);
        if (!result->is_null && result->type == CT_TYPE_CHAR && datatype == CT_TYPE_CHAR) {
            status = sql_convert_char(KNL_SESSION(stmt), result, mode->size, mode->is_char);
        }
    } while (0);

    stmt->is_check = saved_check;
    stmt->direct_knl_cursor = saved_cur;

    CTSQL_RESTORE_STACK(stmt);
    return status;
}

/* !
 * \brief To decide whether an expression node is const. This function can be used
 * to optimize a SQL statement by previously computing some const expressions.
 *
 */
inline bool32 sql_is_const_expr_node(const expr_node_t *node)
{
    if (UNARY_INCLUDE_ROOT(node)) {
        return CT_FALSE;
    }

    switch (node->type) {
        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MOD:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
        case EXPR_NODE_CAT:
        case EXPR_NODE_NEGATIVE:
            return NODE_IS_OPTMZ_CONST(node);

        case EXPR_NODE_CONST:
            return CT_TRUE;

        case EXPR_NODE_RESERVED:
            return (bool32)(NODE_IS_RES_FALSE(node) || NODE_IS_RES_TRUE(node) || NODE_IS_RES_NULL(node));

        case EXPR_NODE_FUNC: {
            const sql_func_t *func = sql_get_func((var_func_t *)&node->value.v_func);
            if (func->options == FO_NORMAL || func->options == FO_SPECIAL) {
                return NODE_IS_OPTMZ_CONST(node);
            }
            return CT_FALSE;
        }

        case EXPR_NODE_UNKNOWN:

        default:
            return CT_FALSE;
    }
}

bool32 sql_is_const_expr_tree(expr_tree_t *expr)
{
    expr_tree_t *curr_expr = expr;

    // The expr_tree may be a expr tree list
    while (curr_expr != NULL) {
        if (!sql_is_const_expr_node(curr_expr->root)) {
            return CT_FALSE;
        }

        curr_expr = curr_expr->next;
    }

    return CT_TRUE;
}

/**
 * If the expr node is const, then compute the result.
 */
status_t sql_try_optimize_const_expr(sql_stmt_t *stmt, expr_node_t *node)
{
    if (sql_is_const_expr_node(node)) {
        variant_t value;
        if (sql_exec_expr_node(stmt, node, &value) != CT_SUCCESS) {
            return CT_ERROR;
        }

        node->value = value;
        node->size = var_get_size(&value);

        if (UNARY_INCLUDE_ROOT(node)) {
            node->unary = UNARY_OPER_ROOT;
        } else {
            node->unary = UNARY_OPER_NONE;
        }

        // copy string, binary, and raw datatype into SQL context
        if ((!value.is_null) && CT_IS_VARLEN_TYPE(node->value.type)) {
            CT_RETURN_IFERR(sql_copy_text(stmt->context, &value.v_text, &node->value.v_text));
        }

        if (node->type != EXPR_NODE_FUNC) {
            // func node no need to set precision, scale and size
            switch (node->value.type) {
                case CT_TYPE_TIMESTAMP:
                case CT_TYPE_TIMESTAMP_TZ_FAKE:
                case CT_TYPE_TIMESTAMP_TZ:
                case CT_TYPE_TIMESTAMP_LTZ:
                    node->precision = CT_DEFAULT_DATETIME_PRECISION;
                    break;

                case CT_TYPE_INTERVAL_YM:
                    node->typmod.year_prec = ITVL_MAX_YEAR_PREC;
                    break;

                case CT_TYPE_INTERVAL_DS:
                    node->typmod.day_prec = ITVL_MAX_DAY_PREC;
                    node->typmod.frac_prec = ITVL_MAX_SECOND_PREC;
                    break;

                default:
                    break;
            }
        }

        node->type = EXPR_NODE_CONST;
        SQL_SET_OPTMZ_MODE(node, OPTIMIZE_AS_CONST);
    }

    return CT_SUCCESS;
}

status_t sql_convert_to_scn(sql_stmt_t *stmt, void *expr, bool32 scn_type, uint64 *scn)
{
    variant_t value;

    if (sql_exec_expr(stmt, (expr_tree_t *)expr, &value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (value.is_null) {
        CT_THROW_ERROR(ERR_VALUE_ERROR, "NULL value is not a valid system change number");
        return CT_ERROR;
    }

    if (scn_type) {
        if (var_as_floor_bigint(&value) != CT_SUCCESS) {
            return CT_ERROR;
        }

        *scn = (uint64)value.v_bigint;
        if (*scn >= knl_next_scn(&stmt->session->knl_session)) {
            CT_THROW_ERROR(ERR_VALUE_ERROR, "specified number is not a valid system change number");
            return CT_ERROR;
        }
    } else {
        if (var_as_timestamp(SESSION_NLS(stmt), &value) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (knl_timestamp_to_scn(&stmt->session->knl_session, value.v_tstamp, scn) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (*scn >= knl_next_scn(&stmt->session->knl_session)) {
            CT_THROW_ERROR(ERR_VALUE_ERROR, "invalid timestamp specified");
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}
status_t sql_case_node_walker(sql_stmt_t *stmt, case_expr_t *case_expr,
    status_t (*fetch)(sql_stmt_t *stmt, expr_node_t *node, void *context), void *context)
{
    uint32 i;
    case_pair_t *pair = NULL;

    if (!case_expr->is_cond) {
        CT_RETURN_IFERR(sql_expr_tree_walker(stmt, case_expr->expr, fetch, context));
        for (i = 0; i < case_expr->pairs.count; i++) {
            pair = (case_pair_t *)cm_galist_get(&case_expr->pairs, i);
            CT_RETURN_IFERR(sql_expr_tree_walker(stmt, pair->when_expr, fetch, context));
            CT_RETURN_IFERR(sql_expr_tree_walker(stmt, pair->value, fetch, context));
        }
    } else {
        for (i = 0; i < case_expr->pairs.count; i++) {
            pair = (case_pair_t *)cm_galist_get(&case_expr->pairs, i);
            CT_RETURN_IFERR(sql_cond_tree_walker(stmt, pair->when_cond, fetch, context));
            CT_RETURN_IFERR(sql_expr_tree_walker(stmt, pair->value, fetch, context));
        }
    }
    return sql_expr_tree_walker(stmt, case_expr->default_expr, fetch, context);
}

status_t sql_expr_node_walker(sql_stmt_t *stmt, expr_node_t *node,
    status_t (*fetch)(sql_stmt_t *stmt, expr_node_t *node, void *context), void *context)
{
    case_expr_t *case_expr = NULL;
    if (node == NULL) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_expr_tree_walker(stmt, node->argument, fetch, context));
    CT_RETURN_IFERR(sql_expr_node_walker(stmt, node->left, fetch, context));
    CT_RETURN_IFERR(sql_expr_node_walker(stmt, node->right, fetch, context));

    switch (node->type) {
        case EXPR_NODE_CONST:
        case EXPR_NODE_RESERVED:
        case EXPR_NODE_SEQUENCE:
        case EXPR_NODE_COLUMN:
        case EXPR_NODE_DIRECT_COLUMN:
            CT_RETURN_IFERR(fetch(stmt, node, context));
            break;

        case EXPR_NODE_CASE:
            case_expr = VALUE(pointer_t, &node->value);
            CT_RETURN_IFERR(sql_case_node_walker(stmt, case_expr, fetch, context));
            break;
        default:
            return CT_SUCCESS;
    }

    return CT_SUCCESS;
}

status_t sql_expr_tree_walker(sql_stmt_t *stmt, expr_tree_t *expr_tree,
    status_t (*fetch)(sql_stmt_t *stmt, expr_node_t *node, void *context), void *context)
{
    expr_tree_t *sibling = expr_tree;
    while (sibling != NULL) {
        CT_RETURN_IFERR(sql_expr_node_walker(stmt, sibling->root, fetch, context));
        sibling = sibling->next;
    }
    return CT_SUCCESS;
}

static bool32 sql_expr_node_reserved_in_tab_list(sql_array_t *tables, expr_node_t *expr_node, bool32 *exist_col)
{
    switch (expr_node->value.v_int) {
        case RES_WORD_NULL:
        case RES_WORD_SYSDATE:
        case RES_WORD_SYSTIMESTAMP:
        case RES_WORD_TRUE:
        case RES_WORD_FALSE:
            return CT_TRUE;
        case RES_WORD_ROWNODEID:
        case RES_WORD_ROWID: {
            *exist_col = CT_TRUE;
            for (uint32 i = 0; i < tables->count; i++) {
                sql_table_t *table = (sql_table_t *)sql_array_get(tables, i);
                if (expr_node->value.v_rid.tab_id == table->id) {
                    return CT_TRUE;
                }
            }

            return CT_FALSE;
        }

        default:
            return CT_FALSE;
    }
}

static bool32 sql_expr_node_column_in_tab_list(sql_array_t *tables, expr_node_t *expr_node, bool32 use_remote_id,
    bool32 *exist_col)
{
    if (NODE_ANCESTOR(expr_node) > 1 || (NODE_ANCESTOR(expr_node) == 1 && !IS_COORDINATOR)) {
        return CT_TRUE;
    }
    *exist_col = CT_TRUE;
    for (uint32 i = 0; i < tables->count; i++) {
        sql_table_t *table = (sql_table_t *)sql_array_get(tables, i);
        // after join transform, we have adjusted the column tab_id, col_id, project_id
        if (use_remote_id) {
		knl_panic(0);
        } else {
            if (NODE_TAB(expr_node) != table->id) {
                continue;
            }
            if (!IS_COORDINATOR) {
                return CT_TRUE;
            }
            if (NODE_ANCESTOR(expr_node) == table->is_ancestor) {
                return CT_TRUE;
            }
        }
    }
    return CT_FALSE;
}

status_t sql_expr_node_in_tab_list(visit_assist_t *va, expr_node_t **expr_node)
{
    if (!va->result0) {
        return CT_SUCCESS;
    }

    sql_array_t *tables = (sql_array_t *)va->param0;
    switch ((*expr_node)->type) {
        case EXPR_NODE_COLUMN:
        case EXPR_NODE_TRANS_COLUMN:
            va->result0 = sql_expr_node_column_in_tab_list(tables, *expr_node, va->result1, &va->result2);
            break;
        case EXPR_NODE_RESERVED:
            va->result0 =
                (bool32)(!va->result1 && sql_expr_node_reserved_in_tab_list(tables, *expr_node, &va->result2));
            break;
        case EXPR_NODE_SELECT:
            va->result0 = CT_FALSE;
            break;
        default:
            break;
    }
    return CT_SUCCESS;
}

bool32 sql_expr_tree_in_tab_list(sql_array_t *tables, expr_tree_t *expr_tree, bool32 use_remote_id, bool32 *exist_col)
{
    visit_assist_t va;
    sql_init_visit_assist(&va, NULL, NULL);
    va.param0 = (void *)tables;
    va.result0 = CT_TRUE;
    va.result1 = use_remote_id;
    va.result2 = *exist_col;
    va.excl_flags = VA_EXCL_PRIOR;
    if (visit_expr_tree(&va, expr_tree, sql_expr_node_in_tab_list) != CT_SUCCESS) {
        *exist_col = va.result2;
        return CT_FALSE;
    }
    *exist_col = va.result2;
    return (bool32)va.result0;
}

static status_t sql_clone_bin(void *ctx, binary_t *src, binary_t *dest, ga_alloc_func_t alloc_mem_func)
{
    if (src == NULL) {
        return CT_SUCCESS;
    }

    if (dest == NULL) {
        CT_RETURN_IFERR(alloc_mem_func(ctx, sizeof(binary_t), (void **)&dest));
    }

    if (src->size > 0) {
        CT_RETURN_IFERR(alloc_mem_func(ctx, src->size, (void **)&dest->bytes));
        MEMS_RETURN_IFERR(memcpy_s(dest->bytes, src->size, src->bytes, src->size));
        dest->size = src->size;
    } else {
        dest->size = 0;
        dest->bytes = NULL;
    }
    dest->is_hex_const = src->is_hex_const;
    return CT_SUCCESS;
}

status_t sql_clone_text(void *ctx, text_t *src, text_t *dest, ga_alloc_func_t alloc_mem_func)
{
    char *buf = NULL;

    if (src == NULL) {
        return CT_SUCCESS;
    }

    if (src->len == 0 && g_instance->sql.enable_empty_string_null) {
        // empty text is used as NULL like oracle
        dest->str = NULL;
        dest->len = 0;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(alloc_mem_func(ctx, sizeof(char) * (src->len + 1), (void **)&buf));
    if (src->len > 0) {
        MEMS_RETURN_IFERR(memcpy_s(buf, src->len, src->str, src->len));
        buf[src->len] = 0;
    }

    dest->str = buf;
    dest->len = src->len;
    return CT_SUCCESS;
}

static status_t sql_clone_sql_text(void *ctx, sql_text_t *src, sql_text_t *dest, ga_alloc_func_t alloc_mem_func)
{
    CT_RETURN_IFERR(sql_clone_text(ctx, &src->value, &dest->value, alloc_mem_func));
    dest->implicit = src->implicit;
    dest->len = src->len;
    dest->loc = src->loc;
    dest->str = dest->value.str;
    return CT_SUCCESS;
}

static status_t sql_clone_var_word(expr_node_type_t type, void *ctx, var_word_t *src, var_word_t *dest,
    ga_alloc_func_t alloc_mem_func)
{
    if (src == NULL) {
        return CT_SUCCESS;
    }
    if (dest == NULL) {
        CT_RETURN_IFERR(alloc_mem_func(ctx, sizeof(var_word_t), (void **)&dest));
    }

    // 1. var_word_t is union, deep clone can't clone every union member
    // 2. func.args (expr string) may be very long ( larger than 16KB),
    //    it will cause memory alloc fail.
    *dest = *src;

    // func.user func.pack func.name should be cloned
    if (type == EXPR_NODE_FUNC || type == EXPR_NODE_USER_FUNC || type == EXPR_NODE_PROC ||
        type == EXPR_NODE_USER_PROC) {
        CT_RETURN_IFERR(sql_clone_sql_text(ctx, &src->func.user, &dest->func.user, alloc_mem_func));
        CT_RETURN_IFERR(sql_clone_sql_text(ctx, &src->func.pack, &dest->func.pack, alloc_mem_func));
        CT_RETURN_IFERR(sql_clone_sql_text(ctx, &src->func.name, &dest->func.name, alloc_mem_func));
    }

    return CT_SUCCESS;
}

status_t sql_clone_var_column(void *ctx, var_column_t *src, var_column_t *dest_col, ga_alloc_func_t alloc_mem_func)
{
    if (src == NULL) {
        return CT_SUCCESS;
    }
    if (dest_col == NULL) {
        CT_RETURN_IFERR(alloc_mem_func(ctx, sizeof(var_column_t), (void **)&dest_col));
    }

    dest_col->datatype = src->datatype;
    dest_col->tab = src->tab;
    dest_col->col = src->col;
    dest_col->ancestor = src->ancestor;
    dest_col->is_ddm_col = src->is_ddm_col;
    dest_col->is_array = src->is_array;
    dest_col->is_jsonb = src->is_jsonb;
    dest_col->ss_start = src->ss_start;
    dest_col->ss_end = src->ss_end;
    dest_col->adjusted = src->adjusted;
    dest_col->has_adjusted = src->has_adjusted;

    // only shard verifier will initialize src->col_info_ptr
    if (src->col_info_ptr == NULL) {
        dest_col->col_info_ptr = NULL;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(alloc_mem_func(ctx, sizeof(column_info_t), (void **)&dest_col->col_info_ptr));

    dest_col->col_info_ptr->col_pro_id = src->col_info_ptr->col_pro_id;
    dest_col->col_info_ptr->org_tab = src->col_info_ptr->org_tab;
    dest_col->col_info_ptr->org_col = src->col_info_ptr->org_col;
    dest_col->col_info_ptr->col_name_has_quote = src->col_info_ptr->col_name_has_quote;
    CT_RETURN_IFERR(sql_clone_text(ctx, &src->col_info_ptr->col_name, &dest_col->col_info_ptr->col_name,
                                   alloc_mem_func));
    CT_RETURN_IFERR(
        sql_clone_text(ctx, &src->col_info_ptr->tab_alias_name, &dest_col->col_info_ptr->tab_alias_name,
                       alloc_mem_func));
    CT_RETURN_IFERR(sql_clone_text(ctx, &src->col_info_ptr->tab_name, &dest_col->col_info_ptr->tab_name,
                                   alloc_mem_func));
    CT_RETURN_IFERR(sql_clone_text(ctx, &src->col_info_ptr->user_name, &dest_col->col_info_ptr->user_name,
                                   alloc_mem_func));
    return CT_SUCCESS;
}

static status_t sql_clone_lob(void *ctx, variant_t *src, variant_t *dest, ga_alloc_func_t alloc_mem_func)
{
    if (src == NULL) {
        return CT_SUCCESS;
    }
    *dest = *src;

    if (src->v_lob.type != CT_LOB_FROM_NORMAL) {
        return CT_SUCCESS;
    }

    return sql_clone_text(ctx, &src->v_lob.normal_lob.value, &dest->v_lob.normal_lob.value, alloc_mem_func);
}

/*
 * sql_clone_variant
 * - This function is used to deep clone a variant_t.
 *
 */
static status_t sql_clone_variant(void *ctx, variant_t *src, variant_t *dest, ga_alloc_func_t alloc_mem_func)
{
    dest->ctrl = src->ctrl;
    if (src->is_null) {
        return CT_SUCCESS;
    }

    switch (src->type) {
        case CT_TYPE_CHAR:    /* char(n) */
        case CT_TYPE_VARCHAR: /* varchar, varchar2 */
        case CT_TYPE_STRING:  /* native char * */
            CT_RETURN_IFERR(sql_clone_text(ctx, &src->v_text, &dest->v_text, alloc_mem_func));
            break;
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            CT_RETURN_IFERR(sql_clone_bin(ctx, &src->v_bin, &dest->v_bin, alloc_mem_func));
            break;
        case CT_TYPE_COLUMN: /* column type, internal used */
            CT_RETURN_IFERR(sql_clone_var_column(ctx, &src->v_col, &dest->v_col, alloc_mem_func));
            break;
        case CT_TYPE_IMAGE:
        case CT_TYPE_CLOB:
        case CT_TYPE_BLOB:
            CT_RETURN_IFERR(sql_clone_lob(ctx, src, dest, alloc_mem_func));
            break;
        default:
            MEMS_RETURN_IFERR(memcpy_s(dest, sizeof(variant_t), src, sizeof(variant_t)));
            break;
    }

    return CT_SUCCESS;
}

static status_t sql_clone_udo(void *ctx, var_udo_t *src_obj, var_udo_t **dst_obj, ga_alloc_func_t alloc_mem_func)
{
    var_udo_t *tmp_obj = NULL;

    CT_RETURN_IFERR(alloc_mem_func(ctx, sizeof(var_udo_t), (void **)&tmp_obj));
    CT_RETURN_IFERR(sql_clone_text(ctx, &src_obj->user, &tmp_obj->user, alloc_mem_func));
    CT_RETURN_IFERR(sql_clone_text(ctx, &src_obj->pack, &tmp_obj->pack, alloc_mem_func));
    CT_RETURN_IFERR(sql_clone_text(ctx, &src_obj->name, &tmp_obj->name, alloc_mem_func));
    tmp_obj->name_sensitive = src_obj->name_sensitive;
    tmp_obj->pack_sensitive = src_obj->pack_sensitive;

    *dst_obj = tmp_obj;
    return CT_SUCCESS;
}

static status_t sql_clone_variant_pl_dc(void *ctx, variant_t *src, variant_t *dest, ga_alloc_func_t alloc_mem_func)
{
    pl_dc_t *src_dc = (pl_dc_t *)src->v_pl_dc;
    pl_dc_t *dst_dc = NULL;
    var_udo_t *src_obj = src_dc->obj;
    var_udo_t *dst_obj = NULL;

    CT_RETURN_IFERR(alloc_mem_func(ctx, sizeof(pl_dc_t), (void **)&dst_dc));
    CT_RETURN_IFERR(sql_clone_udo(ctx, src_obj, &dst_obj, alloc_mem_func));
    *dst_dc = *src_dc;
    dst_dc->obj = dst_obj;
    dest->v_pl_dc = (pointer_t)dst_dc;

    return CT_SUCCESS;
}

static status_t sql_clone_variant_udo(void *ctx, variant_t *src, variant_t *dest, ga_alloc_func_t alloc_mem_func)
{
    dest->ctrl = src->ctrl;

    if (src->is_null) {
        return CT_SUCCESS;
    }

    if (src->type_for_pl == VAR_PL_DC) {
        return sql_clone_variant_pl_dc(ctx, src, dest, alloc_mem_func);
    }

    return sql_clone_udo(ctx, (var_udo_t *)src->v_udo, (var_udo_t **)&dest->v_udo, alloc_mem_func);
}

static status_t sql_clone_winsort_args(void *ctx, winsort_args_t *src_args, winsort_args_t **dst_args,
    ga_alloc_func_t alloc_mem_func)
{
    CT_RETURN_IFERR(alloc_mem_func(ctx, sizeof(winsort_args_t), (void **)dst_args));
    if (src_args->group_exprs != NULL) {
        expr_tree_t *expr = NULL;
        expr_tree_t *new_expr = NULL;

        CT_RETURN_IFERR(alloc_mem_func(ctx, sizeof(galist_t), (void **)&(*dst_args)->group_exprs));
        cm_galist_init((*dst_args)->group_exprs, ctx, alloc_mem_func);
        for (uint32 i = 0; i < src_args->group_exprs->count; i++) {
            expr = (expr_tree_t *)cm_galist_get(src_args->group_exprs, i);
            CT_RETURN_IFERR(sql_clone_expr_tree(ctx, expr, &new_expr, alloc_mem_func));
            CT_RETURN_IFERR(cm_galist_insert((*dst_args)->group_exprs, new_expr));
        }
    }

    if (src_args->sort_items != NULL) {
        sort_item_t *item = NULL;
        sort_item_t *new_item = NULL;

        CT_RETURN_IFERR(alloc_mem_func(ctx, sizeof(galist_t), (void **)&(*dst_args)->sort_items));
        cm_galist_init((*dst_args)->sort_items, ctx, alloc_mem_func);
        for (uint32 i = 0; i < src_args->sort_items->count; i++) {
            item = (sort_item_t *)cm_galist_get(src_args->sort_items, i);
            CT_RETURN_IFERR(cm_galist_new((*dst_args)->sort_items, sizeof(sort_item_t), (void **)&new_item));
            CT_RETURN_IFERR(sql_clone_expr_tree(ctx, item->expr, &new_item->expr, alloc_mem_func));
            new_item->sort_mode = item->sort_mode;
        }
        if (src_args->windowing != NULL) {
            windowing_args_t **new_win = &(*dst_args)->windowing;
            CT_RETURN_IFERR(alloc_mem_func(ctx, sizeof(windowing_args_t), (void **)new_win));
            CT_RETURN_IFERR(sql_clone_expr_tree(ctx, src_args->windowing->l_expr, &(*new_win)->l_expr, alloc_mem_func));
            CT_RETURN_IFERR(sql_clone_expr_tree(ctx, src_args->windowing->r_expr, &(*new_win)->r_expr, alloc_mem_func));
            (*new_win)->l_type = src_args->windowing->l_type;
            (*new_win)->r_type = src_args->windowing->r_type;
            (*new_win)->is_range = src_args->windowing->is_range;
        }
    }
    (*dst_args)->is_rs_node = src_args->is_rs_node;
    (*dst_args)->sort_columns = src_args->sort_columns;
    return CT_SUCCESS;
}

static status_t sql_clone_case_pair(void *ctx, galist_t *src_pairs, case_expr_t *dst_node,
    ga_alloc_func_t alloc_mem_func)
{
    case_pair_t *src_pair = NULL;
    case_pair_t *dst_pair = NULL;

    for (uint32 i = 0; i < src_pairs->count; i++) {
        src_pair = (case_pair_t *)cm_galist_get(src_pairs, i);
        CT_RETURN_IFERR(alloc_mem_func(ctx, sizeof(case_pair_t), (void **)&dst_pair));

        if (dst_node->is_cond) {
            CT_RETURN_IFERR(sql_clone_cond_tree(ctx, src_pair->when_cond, &dst_pair->when_cond, alloc_mem_func));
        } else {
            CT_RETURN_IFERR(sql_clone_expr_tree(ctx, src_pair->when_expr, &dst_pair->when_expr, alloc_mem_func));
        }
        CT_RETURN_IFERR(sql_clone_expr_tree(ctx, src_pair->value, &dst_pair->value, alloc_mem_func));
        CT_RETURN_IFERR(cm_galist_insert(&dst_node->pairs, dst_pair));
    }
    return CT_SUCCESS;
}

static status_t sql_clone_case_node(void *ctx, case_expr_t *src_node, case_expr_t **dst_node,
    ga_alloc_func_t alloc_mem_func)
{
    CT_RETURN_IFERR(alloc_mem_func(ctx, sizeof(case_expr_t), (void **)dst_node));
    cm_galist_init(&(*dst_node)->pairs, ctx, alloc_mem_func);
    (*dst_node)->is_cond = src_node->is_cond;

    if (!src_node->is_cond) {
        CT_RETURN_IFERR(sql_clone_expr_tree(ctx, src_node->expr, &(*dst_node)->expr, alloc_mem_func));
    }

    CT_RETURN_IFERR(sql_clone_case_pair(ctx, &src_node->pairs, *dst_node, alloc_mem_func));
    if (src_node->default_expr != NULL) {
        CT_RETURN_IFERR(sql_clone_expr_tree(ctx, src_node->default_expr, &(*dst_node)->default_expr, alloc_mem_func));
    }
    return CT_SUCCESS;
}

status_t add_node_2_parent_ref_core(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node, uint32 tab,
    uint32 temp_ancestor)
{
    uint32 ancestor = temp_ancestor;
    while (ancestor > 1) {
        if (query == NULL || query->owner == NULL || query->owner->parent == NULL) {
            return CT_SUCCESS;
        }
        query = query->owner->parent;
        ancestor--;
    }
    if (query != NULL && query->owner != NULL && query->owner->parent != NULL) {
        CT_RETURN_IFERR(sql_add_parent_refs(stmt, query->owner->parent_refs, tab, node));
    }
    return CT_SUCCESS;
}

status_t add_node_2_parent_ref(ga_alloc_func_t alloc_mem_func, expr_node_t *node)
{
    session_t *sess = (session_t *)knl_get_curr_sess();

    if (alloc_mem_func != sql_alloc_mem || sess == NULL) {
        return CT_SUCCESS;
    }
    sql_stmt_t *stmt = sess->current_stmt;

    if (node->type == EXPR_NODE_COLUMN && NODE_ANCESTOR(node) > 0) {
        CT_RETURN_IFERR(
            add_node_2_parent_ref_core(stmt, CTSQL_CURR_NODE(stmt), node, NODE_TAB(node), NODE_ANCESTOR(node)));
    } else if (NODE_IS_RES_ROWID(node) && ROWID_NODE_ANCESTOR(node) > 0) {
        var_rowid_t *v_rid = &node->value.v_rid;
        CT_RETURN_IFERR(
            add_node_2_parent_ref_core(stmt, CTSQL_CURR_NODE(stmt), node, v_rid->tab_id, ROWID_NODE_ANCESTOR(node)));
    }
    return CT_SUCCESS;
}

static status_t sql_clone_sort_items(void *ctx, galist_t *src_items, galist_t **dst_items,
    ga_alloc_func_t alloc_mem_func)
{
    sort_item_t *item = NULL;
    sort_item_t *new_item = NULL;

    CT_RETURN_IFERR(alloc_mem_func(ctx, sizeof(galist_t), (void **)dst_items));
    cm_galist_init(*dst_items, ctx, alloc_mem_func);
    for (uint32 i = 0; i < src_items->count; i++) {
        item = (sort_item_t *)cm_galist_get(src_items, i);
        CT_RETURN_IFERR(cm_galist_new(*dst_items, sizeof(sort_item_t), (void **)&new_item));
        CT_RETURN_IFERR(sql_clone_expr_tree(ctx, item->expr, &new_item->expr, alloc_mem_func));
        new_item->sort_mode = item->sort_mode;
    }
    return CT_SUCCESS;
}

static status_t sql_clone_func_node_args(void *ctx, expr_node_t *src_expr_node, expr_node_t *dest_node,
    ga_alloc_func_t alloc_mem_func)
{
    if (src_expr_node->value.v_func.is_winsort_func) {
        return CT_SUCCESS;
    }

    sql_func_t *func = sql_get_func(&src_expr_node->value.v_func);
    switch (func->builtin_func_id) {
        case ID_FUNC_ITEM_IF:
        case ID_FUNC_ITEM_LNNVL:
            if (src_expr_node->cond_arg != NULL) {
                CT_RETURN_IFERR(
                    sql_clone_cond_tree(ctx, src_expr_node->cond_arg, &dest_node->cond_arg, alloc_mem_func));
            }
            return CT_SUCCESS;

        case ID_FUNC_ITEM_TRIM:
            dest_node->ext_args = src_expr_node->ext_args;
            return CT_SUCCESS;

        case ID_FUNC_ITEM_GROUP_CONCAT:
        case ID_FUNC_ITEM_MEDIAN:
            if (src_expr_node->sort_items != NULL) {
                CT_RETURN_IFERR(
                    sql_clone_sort_items(ctx, src_expr_node->sort_items, &dest_node->sort_items, alloc_mem_func));
            }
            return CT_SUCCESS;

        default:
            return CT_SUCCESS;
    }
}
/*
 * sql_clone_expr_node
 * - This function is used to deep clone a expr node.
 *
 */
status_t sql_clone_expr_node(void *ctx, expr_node_t *src_node, expr_node_t **dest_expr_node,
    ga_alloc_func_t alloc_mem_func)
{
    expr_node_t *node = NULL;
    expr_tree_t *node_argument = NULL;
    expr_node_t *node_left = NULL;
    expr_node_t *node_right = NULL;
    case_expr_t *case_expr = NULL;

    if (src_node == NULL) {
        *dest_expr_node = NULL;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(alloc_mem_func(ctx, sizeof(expr_node_t), (void **)&node));

    /* to clone the header of the node */
    node->type = src_node->type;
    node->unary = src_node->unary;
    node->optmz_info = src_node->optmz_info;
    node->loc = src_node->loc;
    node->typmod = src_node->typmod;
    node->cond_arg = NULL;
    node->owner = NULL;
    node->json_func_attr = src_node->json_func_attr;
    node->dis_info = src_node->dis_info;
    node->exec_default = src_node->exec_default;
    node->format_json = src_node->format_json;
    node->nullaware = src_node->nullaware;
    node->has_verified = src_node->has_verified;
    node->is_median_expr = src_node->is_median_expr;
    node->ignore_nulls = src_node->ignore_nulls;
    node->lang_type = src_node->lang_type;
    node->is_pkg = src_node->is_pkg;

    /* to clone word of var_word_t type */
    CT_RETURN_IFERR(sql_clone_var_word(node->type, ctx, &src_node->word, &node->word, alloc_mem_func));

    /* to clone value of variant_t type */
    switch (node->type) {
        case EXPR_NODE_RESERVED:
            MEMS_RETURN_IFERR(memcpy_s(&node->value, sizeof(variant_t), &src_node->value, sizeof(variant_t)));
            break;

        case EXPR_NODE_SEQUENCE:
            node->value.v_seq.mode = src_node->value.v_seq.mode;
            CT_RETURN_IFERR(
                sql_clone_text(ctx, &src_node->value.v_seq.user, &node->value.v_seq.user, alloc_mem_func));
            CT_RETURN_IFERR(
                sql_clone_text(ctx, &src_node->value.v_seq.name, &node->value.v_seq.name, alloc_mem_func));
            break;

        case EXPR_NODE_FUNC:
            CT_RETURN_IFERR(sql_clone_func_node_args(ctx, src_node, node, alloc_mem_func));
            CT_RETURN_IFERR(sql_clone_variant(ctx, &src_node->value, &node->value, alloc_mem_func));
            break;

        case EXPR_NODE_OVER:
            CT_RETURN_IFERR(sql_clone_winsort_args(ctx, src_node->win_args, &node->win_args, alloc_mem_func));
            CT_RETURN_IFERR(sql_clone_variant(ctx, &src_node->value, &node->value, alloc_mem_func));
            break;

        case EXPR_NODE_CASE:
            case_expr = (case_expr_t *)src_node->value.v_pointer;
            CT_RETURN_IFERR(
                sql_clone_case_node(ctx, case_expr, (case_expr_t **)&node->value.v_pointer, alloc_mem_func));
            break;

        case EXPR_NODE_USER_FUNC:
        case EXPR_NODE_USER_PROC:
            CT_RETURN_IFERR(sql_clone_variant_udo(ctx, &src_node->value, &node->value, alloc_mem_func));
            break;

        default:
            CT_RETURN_IFERR(sql_clone_variant(ctx, &src_node->value, &node->value, alloc_mem_func));
            if (node->type == EXPR_NODE_SELECT && alloc_mem_func == sql_alloc_mem) {
                CT_RETURN_IFERR(sql_slct_add_ref_node(ctx, node, alloc_mem_func));
            }
            break;
    }

    /* to clone argument, left and right */
    if (src_node->argument != NULL) {
        CT_RETURN_IFERR(sql_clone_expr_tree(ctx, src_node->argument, &node_argument, alloc_mem_func));
    }
    if (src_node->left != NULL) {
        CT_RETURN_IFERR(sql_clone_expr_node(ctx, src_node->left, &node_left, alloc_mem_func));
    }
    if (src_node->right != NULL) {
        CT_RETURN_IFERR(sql_clone_expr_node(ctx, src_node->right, &node_right, alloc_mem_func));
    }

    /* to clone the prev and next expr_node */
    node->prev = NULL;
    node->next = NULL;

    node->argument = node_argument;
    node->left = node_left;
    node->right = node_right;
    *dest_expr_node = node;

    CT_RETURN_IFERR(add_node_2_parent_ref(alloc_mem_func, node));

    return CT_SUCCESS;
}

static status_t clone_expr_tree_inner(void *ctx, expr_tree_t *src_tree, expr_tree_t **dest_expr_tree,
    ga_alloc_func_t alloc_mem_func)
{
    expr_tree_t *node = NULL;
    expr_node_t *root_node = NULL;

    if (src_tree == NULL) {
        *dest_expr_tree = NULL;
        return CT_SUCCESS;
    }

    if (alloc_mem_func(ctx, sizeof(expr_tree_t), (void **)&node) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_clone_expr_node(ctx, src_tree->root, &root_node, alloc_mem_func));
    node->expecting = src_tree->expecting;
    node->unary = src_tree->unary;
    node->generated = src_tree->generated;
    node->loc = src_tree->loc;
    node->subscript = src_tree->subscript;
    node->root = root_node;
    CT_RETURN_IFERR(sql_clone_text(ctx, &src_tree->arg_name, &node->arg_name, alloc_mem_func));
    root_node->owner = node;
    node->chain.count = src_tree->chain.count;
    node->chain.first = root_node;
    node->chain.last = root_node;
    node->next = NULL;
    *dest_expr_tree = node;

    return CT_SUCCESS;
}

/*
 * sql_clone_expr_tree
 *
 * This function clone a expr tree.
 *
 * Parameters Description
 * stmt          : The execute sql statement
 * old_expr   : The src expr tree
 * new_expr : The dest expr tree
 */
status_t sql_clone_expr_tree(void *ctx, expr_tree_t *src_expr_tree, expr_tree_t **dest_expr_tree,
    ga_alloc_func_t alloc_mem_func)
{
    if (src_expr_tree == NULL) {
        *dest_expr_tree = NULL;
        return CT_SUCCESS;
    }

    do {
        CT_RETURN_IFERR(clone_expr_tree_inner(ctx, src_expr_tree, dest_expr_tree, alloc_mem_func));
        if (src_expr_tree != NULL) {
            src_expr_tree = src_expr_tree->next;
        }

        if (*dest_expr_tree != NULL) {
            dest_expr_tree = &(*dest_expr_tree)->next;
        }
    } while (src_expr_tree != NULL);

    return CT_SUCCESS;
}

bool32 sql_expr_tree_equal(sql_stmt_t *stmt, expr_tree_t *tree1, expr_tree_t *tree2, uint32 *tab_map)
{
    expr_tree_t *d_tree1 = (tree1);
    expr_tree_t *d_tree2 = (tree2);
    while (d_tree1 != NULL) {
        if (d_tree2 == NULL) {
            return CT_FALSE;
        }
        if (!sql_expr_node_equal(stmt, d_tree1->root, d_tree2->root, tab_map)) {
            return CT_FALSE;
        }
        d_tree1 = d_tree1->next;
        d_tree2 = d_tree2->next;
    }

    if (d_tree2 != NULL) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

static bool32 sql_case_node_equal(sql_stmt_t *stmt, case_expr_t *case_expr1, case_expr_t *case_expr2, uint32 *tab_map)
{
    uint32 i;
    case_pair_t *pair1 = NULL;
    case_pair_t *pair2 = NULL;

    if (case_expr1 == case_expr2) {
        return CT_TRUE;
    }

    if (case_expr1->is_cond ^ case_expr2->is_cond) {
        return CT_FALSE;
    }

    if (case_expr1->pairs.count != case_expr2->pairs.count) {
        return CT_FALSE;
    }

    if (!((case_expr1->default_expr == NULL && case_expr2->default_expr == NULL) ||
        (case_expr1->default_expr != NULL && case_expr2->default_expr != NULL))) {
        return CT_FALSE;
    }

    if (!case_expr1->is_cond) {
        CT_RETVALUE_IFTRUE(!sql_expr_tree_equal(stmt, case_expr1->expr, case_expr2->expr, tab_map), CT_FALSE);

        for (i = 0; i < case_expr1->pairs.count; i++) {
            pair1 = (case_pair_t *)cm_galist_get(&case_expr1->pairs, i);
            pair2 = (case_pair_t *)cm_galist_get(&case_expr2->pairs, i);
            CT_RETVALUE_IFTRUE(!sql_expr_tree_equal(stmt, pair1->when_expr, pair2->when_expr, tab_map), CT_FALSE);
            CT_RETVALUE_IFTRUE(!sql_expr_tree_equal(stmt, pair1->value, pair2->value, tab_map), CT_FALSE);
        }
    } else {
        for (i = 0; i < case_expr1->pairs.count; i++) {
            pair1 = (case_pair_t *)cm_galist_get(&case_expr1->pairs, i);
            pair2 = (case_pair_t *)cm_galist_get(&case_expr2->pairs, i);

            CT_RETVALUE_IFTRUE(!sql_cond_node_equal(stmt, pair1->when_cond->root, pair2->when_cond->root, tab_map),
                CT_FALSE);
            CT_RETVALUE_IFTRUE(!sql_expr_tree_equal(stmt, pair1->value, pair2->value, tab_map), CT_FALSE);
        }
    }
    CT_RETVALUE_IFTRUE(!sql_expr_tree_equal(stmt, case_expr1->default_expr, case_expr2->default_expr, tab_map),
        CT_FALSE);
    return CT_TRUE;
}

static bool32 sql_func_is_equal(sql_stmt_t *stmt, expr_node_t *node1, expr_node_t *node2, uint32 *tab_map)
{
    /* aggr function, for example, "sum(distinct f1)" is not equals to "sum(f1)" */
    if (node1->dis_info.need_distinct != node2->dis_info.need_distinct) {
        return CT_FALSE;
    }

    if ((node1->value.v_func.pack_id != node2->value.v_func.pack_id ||
        node1->value.v_func.func_id != node2->value.v_func.func_id) &&
        !cm_text_equal(&node1->word.func.name.value, &node2->word.func.name.value)) {
        return CT_FALSE;
    }

    if ((IS_BUILDIN_FUNCTION(node1, ID_FUNC_ITEM_JSON_VALUE) || IS_BUILDIN_FUNCTION(node1, ID_FUNC_ITEM_JSONB_VALUE)) &&
        !JSON_FUNC_ATTR_EQUAL(&node1->json_func_attr, &node2->json_func_attr)) {
        return CT_FALSE;
    }

    if (node1->type == EXPR_NODE_FUNC && node2->type == EXPR_NODE_FUNC) {
        sql_func_t *func1 = sql_get_func(&node1->value.v_func);
        sql_func_t *func2 = sql_get_func(&node2->value.v_func);

        if ((func1->builtin_func_id == ID_FUNC_ITEM_IF && func2->builtin_func_id == ID_FUNC_ITEM_IF) ||
            (func1->builtin_func_id == ID_FUNC_ITEM_LNNVL && func2->builtin_func_id == ID_FUNC_ITEM_LNNVL)) {
            if ((node1->cond_arg != NULL && node2->cond_arg == NULL) ||
                (node1->cond_arg == NULL && node2->cond_arg != NULL)) {
                return CT_FALSE;
            }

            if (node1->cond_arg != NULL && node2->cond_arg != NULL &&
                !sql_cond_node_equal(stmt, node1->cond_arg->root, node2->cond_arg->root, tab_map)) {
                return CT_FALSE;
            }
        }
    }

    expr_tree_t *arg1 = node1->argument;
    expr_tree_t *arg2 = node2->argument;

    while (arg1 != NULL) {
        if (arg2 == NULL) {
            return CT_FALSE;
        }

        if (!sql_expr_node_equal(stmt, arg1->root, arg2->root, tab_map)) {
            return CT_FALSE;
        }

        arg1 = arg1->next;
        arg2 = arg2->next;
    }

    return (arg2 == NULL);
}

static bool32 sql_group_exprs_node_equal(sql_stmt_t *stmt, galist_t *group_exprs1, galist_t *group_exprs2,
    uint32 *tab_map)
{
    expr_tree_t *expr1 = NULL;
    expr_tree_t *expr2 = NULL;

    if (group_exprs1->count == group_exprs2->count) {
        for (uint32 i = 0; i < group_exprs1->count; i++) {
            expr1 = (expr_tree_t *)cm_galist_get(group_exprs1, i);
            expr2 = (expr_tree_t *)cm_galist_get(group_exprs2, i);
            if (!sql_expr_node_equal(stmt, expr1->root, expr2->root, tab_map)) {
                return CT_FALSE;
            }
        }
    } else {
        return CT_FALSE;
    }
    return CT_TRUE;
}

static bool32 sql_sort_items_node_equal(sql_stmt_t *stmt, galist_t *sort_items1, galist_t *sort_items2, uint32 *tab_map)
{
    sort_item_t *item1 = NULL;
    sort_item_t *item2 = NULL;

    if (sort_items1->count == sort_items2->count) {
        for (uint32 i = 0; i < sort_items1->count; i++) {
            item1 = (sort_item_t *)cm_galist_get(sort_items1, i);
            item2 = (sort_item_t *)cm_galist_get(sort_items2, i);
            if (!sql_expr_node_equal(stmt, item1->expr->root, item2->expr->root, tab_map)) {
                return CT_FALSE;
            }
            if (item1->direction != item2->direction) {
                return CT_FALSE;
            }
            if (item1->nulls_pos != item2->nulls_pos) {
                return CT_FALSE;
            }
        }
    } else {
        return CT_FALSE;
    }
    return CT_TRUE;
}

static inline bool32 sql_windowing_args_equal(sql_stmt_t *stmt, windowing_args_t *arg1, windowing_args_t *arg2,
    uint32 *tab_map)
{
    if ((arg1 != NULL && arg2 == NULL) || (arg2 != NULL && arg1 == NULL)) {
        return CT_FALSE;
    }

    if (arg1 != NULL && arg2 != NULL) {
        if (arg1->is_range != arg2->is_range || arg1->l_type != arg2->l_type || arg1->r_type != arg2->r_type ||
            !sql_expr_tree_equal(stmt, arg1->l_expr, arg2->l_expr, tab_map) ||
            !sql_expr_tree_equal(stmt, arg1->r_expr, arg2->r_expr, tab_map)) {
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

static bool32 sql_over_node_equal(sql_stmt_t *stmt, expr_node_t *node1, expr_node_t *node2, uint32 *tab_map)
{
    expr_node_t *node1_func = node1->argument->root;
    expr_node_t *node2_func = node2->argument->root;
    winsort_args_t *win_args1 = (winsort_args_t *)node1->win_args;
    winsort_args_t *win_args2 = (winsort_args_t *)node2->win_args;

    if ((win_args1->sort_items != NULL && win_args2->sort_items == NULL) ||
        (win_args2->sort_items && win_args1->sort_items == NULL)) {
        return CT_FALSE;
    }

    if (win_args1->sort_items != NULL && win_args2->sort_items != NULL &&
        !sql_sort_items_node_equal(stmt, win_args1->sort_items, win_args2->sort_items, tab_map)) {
        return CT_FALSE;
    }

    if ((win_args1->group_exprs != NULL && win_args2->group_exprs == NULL) ||
        (win_args2->group_exprs && win_args1->group_exprs == NULL)) {
        return CT_FALSE;
    }

    if (win_args1->group_exprs != NULL && win_args2->group_exprs != NULL &&
        !sql_group_exprs_node_equal(stmt, win_args1->group_exprs, win_args2->group_exprs, tab_map)) {
        return CT_FALSE;
    }

    if (!sql_windowing_args_equal(stmt, win_args1->windowing, win_args2->windowing, tab_map)) {
        return CT_FALSE;
    }

    return sql_func_is_equal(stmt, node1_func, node2_func, tab_map);
}

static inline bool32 sql_reserved_node_is_equal(expr_node_t *node1, expr_node_t *node2)
{
    if (VALUE(uint32, &node1->value) != VALUE(uint32, &node2->value)) {
        return CT_FALSE;
    }

    if (VALUE(uint32, &node1->value) == RES_WORD_ROWID) {
        return (bool32)(ROWID_NODE_TAB(node1) == ROWID_NODE_TAB(node2) &&
            ROWID_NODE_ANCESTOR(node1) == ROWID_NODE_ANCESTOR(node2));
    }
    return CT_TRUE;
}
static bool32 sql_column_node_is_equal(expr_node_t *node1, expr_node_t *node2, uint32 *tab_map)
{
    if (tab_map == NULL) {
        if (VAR_ANCESTOR(&node1->value) != VAR_ANCESTOR(&node2->value) ||
            VAR_TAB(&node1->value) != VAR_TAB(&node2->value) || VAR_COL(&node1->value) != VAR_COL(&node2->value)) {
            return CT_FALSE;
        }

        /* array or array element node, need compare subscript */
        if (node1->value.v_col.is_array == CT_TRUE && node2->value.v_col.is_array == CT_TRUE) {
            return (bool32)(node1->value.v_col.ss_start == node2->value.v_col.ss_start &&
                node1->value.v_col.ss_end == node2->value.v_col.ss_end);
        } else if (VAR_COL_IS_ARRAY_ELEMENT(&node1->value.v_col) && VAR_COL_IS_ARRAY_ELEMENT(&node2->value.v_col)) {
            return (bool32)(node1->value.v_col.ss_start == node2->value.v_col.ss_start);
        }

        return CT_TRUE;
    }
    return (bool32)(tab_map[NODE_TAB(node1)] == NODE_TAB(node2) && NODE_COL(node1) == NODE_COL(node2));
}

static bool32 sql_plv_node_complex_addr_equal(sql_stmt_t *stmt, expr_node_t *node1, expr_node_t *node2, uint32 *tab_map)
{
    var_address_t *var_addr1 = NODE_VALUE_PTR(var_address_t, node1);
    var_address_t *var_addr2 = NODE_VALUE_PTR(var_address_t, node2);
    galist_t *pairs1 = var_addr1->pairs;
    galist_t *pairs2 = var_addr2->pairs;
    var_address_pair_t *addr_pair1 = NULL;
    var_address_pair_t *addr_pair2 = NULL;

    CT_RETVALUE_IFTRUE(pairs1->count != pairs2->count, CT_FALSE);
    for (uint32 i = 0; i < pairs1->count; i++) {
        addr_pair1 = (var_address_pair_t *)cm_galist_get(pairs1, (uint32)i);
        addr_pair2 = (var_address_pair_t *)cm_galist_get(pairs2, (uint32)i);
        CT_RETVALUE_IFTRUE(addr_pair1->type != addr_pair2->type, CT_FALSE);
        switch (addr_pair1->type) {
            case UDT_STACK_ADDR:
                if (addr_pair1->stack->decl != addr_pair2->stack->decl) {
                    return CT_FALSE;
                }
                break;
            case UDT_REC_FIELD_ADDR:
                if (addr_pair1->rec_field->parent != addr_pair2->rec_field->parent ||
                    addr_pair1->rec_field->id != addr_pair2->rec_field->id) {
                    return CT_FALSE;
                }
                break;
            case UDT_OBJ_FIELD_ADDR:
                if (addr_pair1->obj_field->parent != addr_pair2->obj_field->parent ||
                    addr_pair1->obj_field->id != addr_pair2->obj_field->id) {
                    return CT_FALSE;
                }
                break;
            case UDT_COLL_ELEMT_ADDR:
                if (addr_pair1->coll_elemt->parent != addr_pair2->coll_elemt->parent ||
                    !sql_expr_node_equal(stmt, addr_pair1->coll_elemt->id->root, addr_pair2->coll_elemt->id->root, tab_map)) {
                    return CT_FALSE;
                }
                break;
            case UDT_ARRAY_ADDR:
                if (addr_pair1->arr_addr->ss_start != addr_pair2->arr_addr->ss_start ||
                    addr_pair1->arr_addr->ss_end != addr_pair2->arr_addr->ss_end) {
                    return CT_FALSE;
                }
                break;
            default:
                return CT_FALSE;
        }
    }
    return CT_TRUE;
}

static bool32 sql_array_node_equal(sql_stmt_t *stmt, expr_node_t *node1, expr_node_t *node2, uint32 *tab_map)
{
    expr_tree_t *arg1 = node1->argument;
    expr_tree_t *arg2 = node2->argument;
    while (arg1 != NULL && arg2 != NULL) {
        if (!sql_expr_node_equal(stmt, arg1->root, arg2->root, tab_map)) {
            return CT_FALSE;
        }
        arg1 = arg1->next;
        arg2 = arg2->next;
    }
    if (arg1 != NULL || arg2 != NULL) {
        return CT_FALSE;
    }
    return CT_TRUE;
}

bool32 sql_expr_node_equal(sql_stmt_t *stmt, expr_node_t *node1, expr_node_t *node2, uint32 *table_map)
{
    if (node1 == node2) {
        return CT_TRUE;
    }

    if (node1->type != node2->type) {
        node1 = sql_get_origin_ref(node1);
        node2 = sql_get_origin_ref(node2);
        if (node1->type != node2->type) {
            return CT_FALSE;
        }
    }

    switch (node1->type) {
        case EXPR_NODE_CONST:
            return var_const_equal(&node1->value, &node2->value);

        case EXPR_NODE_COLUMN:
        case EXPR_NODE_DIRECT_COLUMN:
            return sql_column_node_is_equal(node1, node2, table_map);

        case EXPR_NODE_GROUP:
            return (bool32)(NODE_VM_ID(node1) == NODE_VM_ID(node2) &&
                NODE_VM_ANCESTOR(node1) == NODE_VM_ANCESTOR(node2));

        case EXPR_NODE_AGGR:
            return (bool32)(VALUE(uint32, &node1->value) == VALUE(uint32, &node2->value));

        case EXPR_NODE_RESERVED:
            return sql_reserved_node_is_equal(node1, node2);

        case EXPR_NODE_PARAM:
        case EXPR_NODE_CSR_PARAM:
            if (stmt->pl_compiler != NULL || stmt->pl_exec != NULL) {
                return CT_FALSE;
            }

            return (bool32)(VALUE(uint32, &node1->value) == VALUE(uint32, &node2->value));

        case EXPR_NODE_FUNC:
        case EXPR_NODE_USER_FUNC:
            return sql_func_is_equal(stmt, node1, node2, table_map);

        case EXPR_NODE_ADD:
        case EXPR_NODE_MUL:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
            if (sql_expr_node_equal(stmt, node1->left, node2->left, table_map) &&
                sql_expr_node_equal(stmt, node1->right, node2->right, table_map)) {
                return CT_TRUE;
            }

            return (bool32)(sql_expr_node_equal(stmt, node1->left, node2->right, table_map) &&
                sql_expr_node_equal(stmt, node1->right, node2->left, table_map));

        case EXPR_NODE_SUB:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MOD:
        case EXPR_NODE_CAT:
            return (bool32)(sql_expr_node_equal(stmt, node1->left, node2->left, table_map) &&
                sql_expr_node_equal(stmt, node1->right, node2->right, table_map));

        case EXPR_NODE_NEGATIVE:
        case EXPR_NODE_PRIOR:
            return (bool32)(sql_expr_node_equal(stmt, node1->right, node2->right, table_map));

        case EXPR_NODE_STAR:
            return CT_TRUE;

        case EXPR_NODE_CASE:
            return sql_case_node_equal(stmt, VALUE(pointer_t, &node1->value), VALUE(pointer_t, &node2->value), table_map);

        case EXPR_NODE_V_ADDR:
            return sql_plv_node_complex_addr_equal(stmt, node1, node2, table_map);

        case EXPR_NODE_OVER:
            return sql_over_node_equal(stmt, node1, node2, table_map);

        case EXPR_NODE_SELECT:
            return (node1->value.v_obj.id == node2->value.v_obj.id &&
                node1->value.v_obj.ptr == node2->value.v_obj.ptr) ?
                CT_TRUE :
                CT_FALSE;

        case EXPR_NODE_ARRAY:
            return sql_array_node_equal(stmt, node1, node2, table_map);

        default:
            return CT_FALSE;
    }
}

static inline void store_last_nodes(biqueue_node_t **last_nodes, cols_used_t *used_cols)
{
    uint32 loop;
    for (loop = 0; loop < RELATION_LEVELS; ++loop) {
        last_nodes[loop] = biqueue_last(&used_cols->cols_que[loop]);
    }
}

static inline void collect_cols_in_case_when(expr_node_t *node, cols_used_t *used_cols)
{
    case_pair_t *case_pair = NULL;
    case_expr_t *case_expr = NULL;
    biqueue_node_t *last_nodes[RELATION_LEVELS];

    case_expr = (case_expr_t *)node->value.v_pointer;

    store_last_nodes(last_nodes, used_cols);
    if (!case_expr->is_cond) {
        sql_collect_cols_in_expr_tree(case_expr->expr, used_cols);
    }

    for (uint32 i = 0; i < case_expr->pairs.count; i++) {
        case_pair = (case_pair_t *)cm_galist_get(&case_expr->pairs, i);
        if (case_expr->is_cond) {
            sql_collect_cols_in_cond(case_pair->when_cond->root, used_cols);
        } else {
            sql_collect_cols_in_expr_tree(case_pair->when_expr, used_cols);
        }
        sql_collect_cols_in_expr_tree(case_pair->value, used_cols);
    }

    if (case_expr->default_expr != NULL) {
        sql_collect_cols_in_expr_tree(case_expr->default_expr, used_cols);
    }
}

static inline void collect_cols_in_func(expr_node_t *node, cols_used_t *used_cols)
{
    sql_func_t *func = NULL;
    biqueue_node_t *last_nodes[RELATION_LEVELS];
    uint16 pred_cnt = used_cols->count[SELF_IDX];

    used_cols->level++;
    store_last_nodes(last_nodes, used_cols);
    sql_collect_cols_in_expr_tree(node->argument, used_cols);
    if (node->type == EXPR_NODE_FUNC) {
        func = sql_get_func(&node->value.v_func);
        // collect columns in condition parameter(expr_node_t::cond_arg) for function 'if'
        // not collect columns in window args(expr_node_t::win_arg) for window function
        //    , because window sort function can not appear in where clause
        if ((func->builtin_func_id == ID_FUNC_ITEM_IF || func->builtin_func_id == ID_FUNC_ITEM_LNNVL) &&
            node->cond_arg != NULL) {
            sql_collect_cols_in_cond(node->cond_arg->root, used_cols);
        }
        if ((func->aggr_type == AGGR_TYPE_GROUP_CONCAT || func->aggr_type == AGGR_TYPE_MEDIAN) &&
            node->sort_items != NULL) {
            for (uint32 i = 0; i < node->sort_items->count; i++) {
                sort_item_t *sort_item = (sort_item_t *)cm_galist_get(node->sort_items, i);
                sql_collect_cols_in_expr_tree(sort_item->expr, used_cols);
            }
        }
    }

    // set column expression which in function max level
    if (used_cols->count[SELF_IDX] > pred_cnt) {
        used_cols->func_maxlev = MAX(used_cols->func_maxlev, used_cols->level);
    }
    used_cols->level--;
}

static inline void collect_cols_in_group_node(expr_node_t *node, cols_used_t *used_cols)
{
    expr_node_t *origin_ref = sql_get_origin_ref(node);
    sql_collect_cols_in_expr_node(origin_ref, used_cols);
}

static void collect_cols_in_over_node(expr_node_t *node, cols_used_t *used_cols)
{
    sort_item_t *item = NULL;
    expr_tree_t *expr = NULL;
    expr_node_t *func_node = node->argument->root;

    if (node->win_args->group_exprs != NULL) {
        for (uint32 i = 0; i < node->win_args->group_exprs->count; i++) {
            expr = (expr_tree_t *)cm_galist_get(node->win_args->group_exprs, i);
            sql_collect_cols_in_expr_tree(expr, used_cols);
        }
    }
    if (node->win_args->sort_items != NULL) {
        for (uint32 i = 0; i < node->win_args->sort_items->count; i++) {
            item = (sort_item_t *)cm_galist_get(node->win_args->sort_items, i);
            sql_collect_cols_in_expr_tree(item->expr, used_cols);
        }
        if (node->win_args->windowing != NULL) {
            if (node->win_args->windowing->l_expr != NULL) {
                sql_collect_cols_in_expr_tree(node->win_args->windowing->l_expr, used_cols);
            }
            if (node->win_args->windowing->r_expr != NULL) {
                sql_collect_cols_in_expr_tree(node->win_args->windowing->r_expr, used_cols);
            }
        }
    }
    sql_collect_cols_in_expr_tree(func_node->argument, used_cols);
}

static inline void collect_cols(uint32 ancestor, expr_node_t *node, cols_used_t *used_cols)
{
    uint32 idx;
    expr_node_t *first_node = NULL;
    biqueue_t *cols_que = NULL;

    used_cols->ancestor = MAX(used_cols->ancestor, ancestor);
    idx = (ancestor == 0 ? SELF_IDX : (ancestor == 1 ? PARENT_IDX : ANCESTOR_IDX));
    used_cols->flags |=
        (ancestor == 0 ? FLAG_HAS_SELF_COLS : (ancestor == 1 ? FLAG_HAS_PARENT_COLS : FLAG_HAS_ANCESTOR_COLS));

    if (NODE_IS_RES_ROWID(node)) {
        used_cols->level_flags[idx] |= LEVEL_HAS_ROWID;
    }

    if (NODE_IS_RES_ROWNODEID(node)) {
        used_cols->level_flags[idx] |= LEVEL_HAS_ROWNODEID;
    }

    ++used_cols->count[idx];

    cols_que = &used_cols->cols_que[idx];
    if (!biqueue_empty(cols_que)) {
        first_node = OBJECT_OF(expr_node_t, biqueue_first(&used_cols->cols_que[idx]));
        if (TAB_OF_NODE(node) != TAB_OF_NODE(first_node)) {
            used_cols->level_flags[idx] |= LEVEL_HAS_DIFF_TABS;
        }
        if (COL_OF_NODE(node) != COL_OF_NODE(first_node)) {
            used_cols->level_flags[idx] |= LEVEL_HAS_DIFF_COLS;
        }
    }

    biqueue_add_tail(&used_cols->cols_que[idx], QUEUE_NODE_OF(node));
    return;
}

static void collect_cols_in_sub_select(expr_node_t *node, cols_used_t *used_cols)
{
    sql_select_t *select_context = (sql_select_t *)VALUE_PTR(var_object_t, &node->value)->ptr;
    used_cols->subslct_flag |= (select_context->has_ancestor > 0) ? DYNAMIC_SUB_SELECT : STATIC_SUB_SELECT;
    if (!(select_context->has_ancestor > 0 && used_cols->collect_sub_select)) {
        return;
    }
    parent_ref_t *parent_ref = NULL;
    expr_node_t *ref_col = NULL;
    for (uint32 i = 0; i < select_context->parent_refs->count; i++) {
        parent_ref = (parent_ref_t *)cm_galist_get(select_context->parent_refs, i);
        for (uint32 j = 0; j < parent_ref->ref_columns->count; j++) {
            ref_col = (expr_node_t *)cm_galist_get(parent_ref->ref_columns, j);
            ref_col = sql_get_origin_ref(ref_col);
            collect_cols(0, ref_col, used_cols);
        }
    }
}

static void inline collect_cols_in_reserved(expr_node_t *node, cols_used_t *used_cols)
{
    if (NODE_IS_RES_ROWNUM(node)) {
        used_cols->inc_flags |= FLAG_INC_ROWNUM;
        return;
    }

    if (NODE_IS_RES_ROWID(node) || NODE_IS_RES_ROWNODEID(node)) {
        collect_cols(node->value.v_rid.ancestor, node, used_cols);
        return;
    }
}

void sql_collect_cols_in_expr_node(expr_node_t *node, cols_used_t *used_cols)
{
    switch (node->type) {
        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MOD:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_CAT:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
            sql_collect_cols_in_expr_node(node->left, used_cols);
            sql_collect_cols_in_expr_node(node->right, used_cols);
            break;
        case EXPR_NODE_NEGATIVE:
            sql_collect_cols_in_expr_node(node->right, used_cols);
            break;
        case EXPR_NODE_PRIOR:
            used_cols->inc_flags |= FLAG_INC_PRIOR;
            break;
        case EXPR_NODE_PARAM:
        case EXPR_NODE_CSR_PARAM:
            used_cols->inc_flags |= FLAG_INC_PARAM;
            break;
        case EXPR_NODE_FUNC:
        case EXPR_NODE_USER_FUNC:
        case EXPR_NODE_V_METHOD:
        case EXPR_NODE_V_CONSTRUCT:
            collect_cols_in_func(node, used_cols);
            break;
        case EXPR_NODE_CASE:
            collect_cols_in_case_when(node, used_cols);
            break;
        case EXPR_NODE_SELECT:
            collect_cols_in_sub_select(node, used_cols);
            break;
        case EXPR_NODE_RESERVED:
            collect_cols_in_reserved(node, used_cols);
            break;
        case EXPR_NODE_COLUMN:
        case EXPR_NODE_TRANS_COLUMN:
            collect_cols(node->value.v_col.ancestor, node, used_cols);
            break;
        case EXPR_NODE_GROUP:
            collect_cols_in_group_node(node, used_cols);
            break;
        case EXPR_NODE_OVER:
            collect_cols_in_over_node(node, used_cols);
            break;
        default:
            break;
    }
}

void sql_collect_cols_in_expr_tree(expr_tree_t *tree, cols_used_t *used_cols)
{
    while (tree != NULL) {
        sql_collect_cols_in_expr_node(tree->root, used_cols);
        tree = tree->next;
    }
}

void sql_collect_cols_in_cond(void *cond_node, cols_used_t *used_cols)
{
    cond_node_t *cond = (cond_node_t *)cond_node;
    switch (cond->type) {
        case COND_NODE_AND:
        case COND_NODE_OR:
            sql_collect_cols_in_cond(cond->left, used_cols);
            sql_collect_cols_in_cond(cond->right, used_cols);
            break;
        case COND_NODE_COMPARE:
            sql_collect_cols_in_expr_tree(cond->cmp->left, used_cols);
            sql_collect_cols_in_expr_tree(cond->cmp->right, used_cols);
            break;
        default:
            break;
    }
}

status_t sql_get_expr_datatype(sql_stmt_t *stmt, expr_tree_t *expr, ct_type_t *type)
{
    variant_t var;
    expr_node_t *node = expr->root;
    if (node->type == EXPR_NODE_PRIOR) {
        node = node->right;
    }
    if (node->type != EXPR_NODE_PARAM && NODE_DATATYPE(node) != CT_TYPE_UNKNOWN) {
        *type = NODE_DATATYPE(node);
        return CT_SUCCESS;
    }
    if (sql_get_expr_node_value(stmt, node, &var) != CT_SUCCESS) {
        return CT_ERROR;
    }
    *type = var.type;
    return CT_SUCCESS;
}

void sql_init_visit_assist(visit_assist_t *visit_ass, sql_stmt_t *stmt, sql_query_t *query)
{
    visit_ass->stmt = stmt;
    visit_ass->query = query;
    visit_ass->excl_flags = VA_EXCL_NONE;
    visit_ass->param0 = NULL;
    visit_ass->param1 = NULL;
    visit_ass->param2 = NULL;
    visit_ass->param3 = NULL;
    visit_ass->result0 = CT_INVALID_ID32;
    visit_ass->result1 = CT_INVALID_ID32;
    visit_ass->result2 = CT_INVALID_ID32;
    visit_ass->time = 0;
}

status_t visit_func_node(visit_assist_t *visit_ass, expr_node_t *node, visit_func_t visit_func)
{
    CT_RETURN_IFERR(visit_expr_tree(visit_ass, node->argument, visit_func));
    if (node->type == EXPR_NODE_FUNC) {
        sql_func_t *func = sql_get_func(&node->value.v_func);
        if ((func->builtin_func_id == ID_FUNC_ITEM_IF || func->builtin_func_id == ID_FUNC_ITEM_LNNVL) &&
            node->cond_arg != NULL) {
            CT_RETURN_IFERR(visit_cond_node(visit_ass, node->cond_arg->root, visit_func));
        }

        if ((func->aggr_type == AGGR_TYPE_GROUP_CONCAT || func->aggr_type == AGGR_TYPE_MEDIAN) &&
            node->sort_items != NULL) {
            for (uint32 i = 0; i < node->sort_items->count; i++) {
                sort_item_t *sort_item = (sort_item_t *)cm_galist_get(node->sort_items, i);
                CT_RETURN_IFERR(visit_expr_tree(visit_ass, sort_item->expr, visit_func));
            }
        }
    }
    return CT_SUCCESS;
}

static status_t visit_case_node(visit_assist_t *visit_ass, expr_node_t *node, visit_func_t visit_func)
{
    case_expr_t *case_expr = (case_expr_t *)node->value.v_pointer;

    if (!case_expr->is_cond) {
        CT_RETURN_IFERR(visit_expr_tree(visit_ass, case_expr->expr, visit_func));
    }

    for (uint32 i = 0; i < case_expr->pairs.count; i++) {
        case_pair_t *case_pair = (case_pair_t *)cm_galist_get(&case_expr->pairs, i);
        if (case_expr->is_cond) {
            CT_RETURN_IFERR(visit_cond_node(visit_ass, case_pair->when_cond->root, visit_func));
        } else {
            CT_RETURN_IFERR(visit_expr_tree(visit_ass, case_pair->when_expr, visit_func));
        }
        CT_RETURN_IFERR(visit_expr_tree(visit_ass, case_pair->value, visit_func));
    }

    if (case_expr->default_expr != NULL) {
        CT_RETURN_IFERR(visit_expr_tree(visit_ass, case_expr->default_expr, visit_func));
    }
    return CT_SUCCESS;
}

static status_t visit_winsort_node(visit_assist_t *visit_ass, expr_node_t *winsort, visit_func_t visit_func)
{
    sort_item_t *item = NULL;
    expr_tree_t *expr = NULL;
    expr_node_t *func_node = winsort->argument->root;

    if (winsort->win_args->group_exprs != NULL) {
        for (uint32 i = 0; i < winsort->win_args->group_exprs->count; i++) {
            expr = (expr_tree_t *)cm_galist_get(winsort->win_args->group_exprs, i);
            CT_RETURN_IFERR(visit_expr_tree(visit_ass, expr, visit_func));
        }
    }
    if (winsort->win_args->sort_items != NULL) {
        for (uint32 i = 0; i < winsort->win_args->sort_items->count; i++) {
            item = (sort_item_t *)cm_galist_get(winsort->win_args->sort_items, i);
            CT_RETURN_IFERR(visit_expr_tree(visit_ass, item->expr, visit_func));
        }
        if (winsort->win_args->windowing != NULL) {
            if (winsort->win_args->windowing->l_expr != NULL) {
                CT_RETURN_IFERR(visit_expr_tree(visit_ass, winsort->win_args->windowing->l_expr, visit_func));
            }
            if (winsort->win_args->windowing->r_expr != NULL) {
                CT_RETURN_IFERR(visit_expr_tree(visit_ass, winsort->win_args->windowing->r_expr, visit_func));
            }
        }
    }

    return visit_expr_tree(visit_ass, func_node->argument, visit_func);
}

status_t visit_expr_node(visit_assist_t *visit_ass, expr_node_t **node, visit_func_t visit_func)
{
    switch ((*node)->type) {
        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MOD:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_CAT:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
            CT_RETURN_IFERR(visit_expr_node(visit_ass, &(*node)->left, visit_func));
            return visit_expr_node(visit_ass, &(*node)->right, visit_func);

        case EXPR_NODE_NEGATIVE:
            return visit_expr_node(visit_ass, &(*node)->right, visit_func);

        case EXPR_NODE_PRIOR:
            if (visit_ass->excl_flags & VA_EXCL_PRIOR) {
                return visit_func(visit_ass, node);
            }
            return visit_expr_node(visit_ass, &(*node)->right, visit_func);

        case EXPR_NODE_ARRAY:
            return visit_expr_tree(visit_ass, (*node)->argument, visit_func);

        case EXPR_NODE_FUNC:
            if (visit_ass->excl_flags & VA_EXCL_FUNC) {
                return visit_func(visit_ass, node);
            }
            // fall-through
        case EXPR_NODE_USER_FUNC:
        case EXPR_NODE_V_METHOD:
        case EXPR_NODE_V_CONSTRUCT:
            if (visit_ass->excl_flags & VA_EXCL_PROC) {
                return visit_func(visit_ass, node);
            }
            return visit_func_node(visit_ass, *node, visit_func);

        case EXPR_NODE_CASE:
            return visit_case_node(visit_ass, *node, visit_func);

        case EXPR_NODE_OVER:
            if (visit_ass->excl_flags & VA_EXCL_WIN_SORT) {
                return visit_func(visit_ass, node);
            }
            return visit_winsort_node(visit_ass, *node, visit_func);

        default:
            return visit_func(visit_ass, node);
    }
}

status_t visit_expr_tree(visit_assist_t *visit_ass, expr_tree_t *tree, visit_func_t visit_func)
{
    while (tree != NULL) {
        CT_RETURN_IFERR(visit_expr_node(visit_ass, &tree->root, visit_func));
        tree = tree->next;
    }
    return CT_SUCCESS;
}

status_t sql_get_expr_table_info(visit_assist_t *visit_ass, expr_node_t **node)
{
    if (!visit_ass->result0) {
        return CT_SUCCESS;
    }

    if ((*node)->type == EXPR_NODE_COLUMN || (*node)->type == EXPR_NODE_TRANS_COLUMN) {
        if (visit_ass->result0 == CT_INVALID_ID32) {
            // find a column, record table id and ancestor;
            visit_ass->result0 = CT_TRUE;
            visit_ass->result1 = NODE_TAB(*node);
            visit_ass->result2 = NODE_ANCESTOR(*node);
        } else {
            // exists different tables
            visit_ass->result0 = (visit_ass->result1 == NODE_TAB(*node) && visit_ass->result2 == NODE_ANCESTOR(*node));
        }
    }

    return CT_SUCCESS;
}

status_t sql_get_expr_unique_table(sql_stmt_t *stmt, expr_node_t *node, uint16 *tab, uint32 *ancestor)
{
    visit_assist_t visit_ass;
    sql_init_visit_assist(&visit_ass, stmt, NULL);
    CT_RETURN_IFERR(visit_expr_node(&visit_ass, &node, sql_get_expr_table_info));
    if (visit_ass.result0 == CT_TRUE) {
        *tab = (uint16)(visit_ass.result1);
        *ancestor = visit_ass.result2;
    }
    return CT_SUCCESS;
}

static inline status_t sql_exec_const_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    var_copy(&node->value, result);
    return CT_SUCCESS;
}

static inline status_t sql_exec_func_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    CTSQL_SAVE_STACK(stmt);
    status_t status = sql_invoke_func(stmt, node, result);
    if (status != CT_SUCCESS && sql_is_pl_exec(stmt)) {
        ple_update_func_error(stmt, node);
    }
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static inline status_t sql_exec_param_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    return sql_get_param_value(stmt, VALUE(uint32, &node->value), result);
}

#define sql_exec_column_node oprf_column
#define sql_exec_reserved_node sql_get_reserved_value

static inline status_t sql_exec_direct_column(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    return sql_get_ddm_kernel_value(stmt, &g_init_table, stmt->direct_knl_cursor, &node->value.v_col, result);
}

static inline status_t sql_exec_v_method(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    CTSQL_SAVE_STACK(stmt);
    status_t status = udt_exec_v_method(stmt, node, result);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static inline status_t sql_exec_v_construct(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    CTSQL_SAVE_STACK(stmt);
    status_t status = udt_exec_v_construct(stmt, node, result);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static inline status_t sql_exec_v_addr(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    CTSQL_SAVE_STACK(stmt);
    status_t status = udt_exec_v_addr(stmt, node, result, NULL);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static inline status_t sql_exec_rs_column(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    return sql_get_rs_value(stmt, CTSQL_CURR_CURSOR(stmt), VALUE(int32, &node->value), result);
}

static inline status_t sql_exec_user_func(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    CTSQL_SAVE_STACK(stmt);
    status_t status = ple_exec_call(stmt, node, result);
    CTSQL_RESTORE_STACK(stmt);
    if (status != CT_SUCCESS) {
        pl_check_and_set_loc(node->loc);
    }
    return status;
}

static inline status_t sql_exec_select_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    CTSQL_SAVE_STACK(stmt);
    status_t status = sql_get_select_value(stmt, node, result);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static inline status_t sql_exec_sequence_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    return sql_get_sequence_value(stmt, VALUE_PTR(var_seq_t, &node->value), result);
}

static inline status_t sql_exec_aggr_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    sql_get_aggr_value(stmt, VALUE(uint32, &node->value), result);
    return CT_SUCCESS;
}

static inline status_t sql_exec_over_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    CTSQL_SAVE_STACK(stmt);
    status_t status = sql_get_winsort_value(stmt, node, result);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static inline status_t sql_exec_group_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    var_vm_col_t *v_vm_col = (var_vm_col_t *)VALUE_PTR(var_vm_col_t, &node->value);
    CT_RETURN_IFERR(sql_get_group_value(stmt, v_vm_col, node->datatype, node->typmod.is_array, result));
    return sql_get_ddm_group_value(stmt, v_vm_col, result);
}

static inline status_t sql_exec_prior_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    if (stmt->cursor_stack.depth == 0) {
        /* the condition 'stmt->cursor_stack.depth > 0' is added for the scenario of 'connect by prior 1 = 1'
           at verify stage. as stmt->cursor_stack.depth = 0 at verify stage and the func 'sql_exec_connect_by_expr'
           will pop the stmt->cursor_stack, so it can not be invoked in this scenario.
        */
        return CT_SUCCESS;
    }
    CTSQL_SAVE_STACK(stmt);
    status_t status;
    if (!CTSQL_CURR_CURSOR(stmt)->is_mtrl_cursor) {
        status = sql_exec_connect_by_expr(stmt, node, result);
    } else {
        uint32 cursor_depth = stmt->cursor_stack.depth;
        char *cursor_buf = NULL;
        CT_RETURN_IFERR(sql_push(stmt, sizeof(pointer_t) * cursor_depth, (void **)&cursor_buf));
        MEMS_RETURN_IFERR(memcpy_s(cursor_buf, sizeof(pointer_t) * cursor_depth, stmt->cursor_stack.items,
            sizeof(pointer_t) * cursor_depth));
        while (CTSQL_CURR_CURSOR(stmt)->is_mtrl_cursor) {
            SQL_CURSOR_POP(stmt);
        }
        status = sql_exec_connect_by_expr(stmt, node, result);
        MEMS_RETURN_IFERR(memcpy_s(stmt->cursor_stack.items, sizeof(pointer_t) * cursor_depth, cursor_buf,
            sizeof(pointer_t) * cursor_depth));
        stmt->cursor_stack.depth = cursor_depth;
    }
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static inline status_t sql_exec_unary_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    CTSQL_SAVE_STACK(stmt);
    status_t status = sql_exec_unary_oper(stmt, node, result);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static inline status_t sql_exec_new_col(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    if (stmt->pl_exec == NULL) {
        CT_SRC_THROW_ERROR(node->loc, ERR_UNEXPECTED_PL_VARIANT);
        return CT_ERROR;
    }
    return ple_get_trig_new_col(stmt, VALUE_PTR(var_column_t, &node->value), result);
}

static inline status_t sql_exec_old_col(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    if (stmt->pl_exec == NULL) {
        CT_SRC_THROW_ERROR(node->loc, ERR_UNEXPECTED_PL_VARIANT);
        return CT_ERROR;
    }
    return ple_get_trig_old_col(stmt, VALUE_PTR(var_column_t, &node->value), result);
}

static inline status_t sql_exec_pl_attr(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    if (stmt->pl_exec == NULL) {
        CT_SRC_THROW_ERROR(node->loc, ERR_UNEXPECTED_PL_VARIANT);
        return CT_ERROR;
    }
    return ple_get_pl_attr(stmt, node, result);
}

static inline status_t sql_exec_case_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    CTSQL_SAVE_STACK(stmt);
    status_t status = sql_get_case_value(stmt, node, result);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static inline status_t sql_exec_array_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    CTSQL_SAVE_STACK(stmt);
    status_t status = sql_exec_array(stmt, node, result);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static inline status_t sql_exec_oper_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    CTSQL_SAVE_STACK(stmt);
    status_t status = sql_exec_oper(stmt, node, result);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static inline status_t sql_exec_invalid_node(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    CT_SRC_THROW_ERROR(node->loc, ERR_INVALID_EXPRESSION);
    return CT_ERROR;
}

node_func_tab_t g_node_calc_func_tab[] = {
    { EXPR_NODE_CONST, sql_exec_const_node },
    { EXPR_NODE_FUNC, sql_exec_func_node },
    { EXPR_NODE_JOIN, sql_exec_invalid_node },
    { EXPR_NODE_PARAM, sql_exec_param_node },
    { EXPR_NODE_COLUMN, sql_exec_column_node },
    { EXPR_NODE_RS_COLUMN, sql_exec_rs_column },
    { EXPR_NODE_STAR, sql_exec_invalid_node },
    { EXPR_NODE_RESERVED, sql_exec_reserved_node },
    { EXPR_NODE_SELECT, sql_exec_select_node },
    { EXPR_NODE_SEQUENCE, sql_exec_sequence_node },
    { EXPR_NODE_CASE, sql_exec_case_node },
    { EXPR_NODE_GROUP, sql_exec_group_node },
    { EXPR_NODE_AGGR, sql_exec_aggr_node },
    { EXPR_NODE_USER_FUNC, sql_exec_user_func },
    { EXPR_NODE_USER_PROC, sql_exec_user_func },
    { EXPR_NODE_PROC, sql_exec_func_node },
    { EXPR_NODE_NEW_COL, sql_exec_new_col },
    { EXPR_NODE_OLD_COL, sql_exec_old_col },
    { EXPR_NODE_PL_ATTR, sql_exec_pl_attr },
    { EXPR_NODE_OVER, sql_exec_over_node },
    { EXPR_NODE_TRANS_COLUMN, sql_exec_invalid_node },
    { EXPR_NODE_NEGATIVE, sql_exec_unary_node },
    { EXPR_NODE_DIRECT_COLUMN, sql_exec_direct_column },
    { EXPR_NODE_ARRAY, sql_exec_array_node },
    { EXPR_NODE_V_METHOD, sql_exec_v_method },
    { EXPR_NODE_V_ADDR, sql_exec_v_addr },
    { EXPR_NODE_V_CONSTRUCT, sql_exec_v_construct },
};

node_func_tab_t g_oper_calc_func_tab[] = {
    { OPER_TYPE_ROOT, sql_exec_invalid_node },
    { OPER_TYPE_PRIOR, sql_exec_prior_node },
    { OPER_TYPE_MUL, sql_exec_oper_node },
    { OPER_TYPE_DIV, sql_exec_oper_node },
    { OPER_TYPE_MOD, sql_exec_oper_node },
    { OPER_TYPE_ADD, sql_exec_oper_node },
    { OPER_TYPE_SUB, sql_exec_oper_node },
    { OPER_TYPE_LSHIFT, sql_exec_oper_node },
    { OPER_TYPE_RSHIFT, sql_exec_oper_node },
    { OPER_TYPE_BITAND, sql_exec_oper_node },
    { OPER_TYPE_BITXOR, sql_exec_oper_node },
    { OPER_TYPE_BITOR, sql_exec_oper_node },
    { OPER_TYPE_CAT, sql_exec_oper_node },
    { OPER_TYPE_VARIANT_CEIL, sql_exec_invalid_node },
};

node_func_tab_t *g_expr_calc_funcs[] = {
    g_oper_calc_func_tab, g_node_calc_func_tab
};

status_t sql_set_udo_for_user_func(void *verify_in, expr_node_t *node, var_udo_t *src_obj)
{
    sql_verifier_t *verif = (sql_verifier_t *)verify_in;
    sql_context_t *ctx = verif->stmt->context;
    variant_t *value = &node->value;

    CT_RETURN_IFERR(sql_clone_udo(ctx, src_obj, (var_udo_t **)&value->v_udo, sql_alloc_mem));
    value->type_for_pl = VAR_UDO;

    return CT_SUCCESS;
}

status_t sql_set_pl_dc_for_user_func(void *verify_in, expr_node_t *node, pointer_t pl_dc_in)
{
    sql_verifier_t *verif = (sql_verifier_t *)verify_in;
    variant_t *value = &node->value;
    pl_dc_t *pl_dc = (pl_dc_t *)pl_dc_in;

    if (verif->from_table_define) {
        return sql_set_udo_for_user_func(verif, node, pl_dc->obj);
    }

    value->v_pl_dc = pl_dc_in;
    value->type_for_pl = (uint8)VAR_PL_DC;
    return CT_SUCCESS;
}

var_udo_t *sql_node_get_obj(expr_node_t *node)
{
    pl_dc_t *pl_dc = NULL;
    if (node->value.type_for_pl == (uint8)VAR_PL_DC) {
        pl_dc = (pl_dc_t *)node->value.v_pl_dc;
        return pl_dc->obj;
    }
    return (var_udo_t *)node->value.v_udo;
}
#ifdef __cplusplus
}
#endif
