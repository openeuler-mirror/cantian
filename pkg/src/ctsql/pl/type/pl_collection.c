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
 * pl_collection.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/type/pl_collection.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_collection.h"
#include "pl_scalar.h"
#include "decl.h"

plv_collection_method_t *g_coll_methods[UDT_TYPE_END];

plv_coll_construct_t *g_coll_constructor[UDT_TYPE_END];

free_t g_coll_free[UDT_TYPE_END];

intr_method_t *g_coll_intr_method[UDT_TYPE_END];

clone_method_t g_coll_clone_method[UDT_TYPE_END];

address_t g_coll_address[UDT_TYPE_END];

status_t udt_verify_coll_elemt(sql_verifier_t *verif, uint32 arg_count, void *meta, expr_tree_t *tree)
{
    plv_collection_t *coll = (plv_collection_t *)meta;
    switch (coll->attr_type) {
        case UDT_SCALAR:
            return udt_verify_scalar(verif, &coll->type_mode, tree);

        case UDT_COLLECTION:
            if (!UDT_VERIFY_COLL_ASSIGN(tree->root, UDT_GET_TYPE_DEF_COLLECTION(coll->elmt_type))) {
                return CT_ERROR;
            }
            return CT_SUCCESS;
        case UDT_RECORD:
            return udt_verify_record_assign(tree->root, UDT_GET_TYPE_DEF_RECORD(coll->elmt_type));
        case UDT_OBJECT:
            return udt_verify_object_assign(tree->root, UDT_GET_TYPE_DEF_OBJECT(coll->elmt_type));
        default:
            return CT_ERROR;
    }
}

status_t udt_coll_assign(sql_stmt_t *stmt, variant_t *left, variant_t *right)
{
    plv_collection_t *coll_meta = (plv_collection_t *)left->v_collection.coll_meta;
    if (right->type == CT_TYPE_COLLECTION && UDT_IS_EQUAL_COLL_VAR(left, right)) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_stack_safe(stmt));
    if (!IS_COLLECTION_EMPTY(&left->v_collection)) {
        udt_invoke_coll_destructor(stmt, left);
    }

    if (right->is_null) {
        if (coll_meta->type == UDT_HASH_TABLE) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "associative array can't be assigned to null");
            return CT_ERROR;
        }
        left->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    if (!UDT_VERIFY_COLL_ASSIGN_EX(right, coll_meta)) {
        CT_THROW_ERROR(ERR_PL_EXPR_WRONG_TYPE);
        return CT_ERROR;
    }

    left->is_null = right->is_null;
    if (UDT_COLL_NEED_DEEP_COPY(right)) {
        CT_RETURN_IFERR(udt_clone_collection(stmt, right, &left->v_collection.value));
    } else {
        left->v_collection.value = right->v_collection.value;
    }
    return CT_SUCCESS;
}

void udt_invoke_coll_destructor(sql_stmt_t *stmt, variant_t *val)
{
    var_collection_t *coll = &val->v_collection;
    plv_collection_t *coll_meta = (plv_collection_t *)coll->coll_meta;
    if (IS_COLLECTION_EMPTY(coll)) {
        return;
    }

    if (g_coll_free[coll->type](stmt, val) != CT_SUCCESS) {
        int32 code;
        const char *message = NULL;
        cm_get_error(&code, &message, NULL);
        CT_LOG_DEBUG_ERR("collection type[%s] destructor execute error[%d]:%s.", udt_print_colltype(coll_meta->type),
            code, message);
    }

    (void)vmctx_free(GET_VM_CTX(stmt), &val->v_collection.value);
    val->v_collection.value = g_invalid_entry;
    val->is_null = CT_TRUE;
}

void udt_reg_coll_method(collection_type_t collect_type, handle_mutiple_ptrs_t *mult_ptrs)
{
    g_coll_methods[collect_type] = (plv_collection_method_t *)mult_ptrs->ptr1;
    g_coll_constructor[collect_type] = (plv_coll_construct_t *)mult_ptrs->ptr2;
    g_coll_free[collect_type] = (free_t)mult_ptrs->ptr3;
    g_coll_intr_method[collect_type] = (intr_method_t *)mult_ptrs->ptr4;
    g_coll_clone_method[collect_type] = (clone_method_t)mult_ptrs->ptr5;
    g_coll_address[collect_type] = (address_t)mult_ptrs->ptr6;
}

static status_t ple_array_as_collection_insert(sql_stmt_t *stmt, plv_collection_t *coll, variant_t *var, variant_t *res)
{
    udt_constructor_t v_cons;
    variant_t index;
    uint32 arr_count = var->v_array.count;
    uint32 subscript;
    vm_lob_t vlob;
    variant_t var_element;
    array_assist_t array_ass;

    v_cons.is_coll = CT_TRUE;
    v_cons.arg_cnt = 0;
    v_cons.meta = (void *)coll;
    CT_RETURN_IFERR(udt_invoke_coll_construct(stmt, &v_cons, NULL, res));
    if (arr_count != 0) {
        CT_RETURN_IFERR(g_coll_intr_method[coll->type][METHOD_INTR_EXTEND_NUM](stmt, res, &arr_count));
        CT_RETURN_IFERR(sql_get_array_vm_lob(stmt, &var->v_array.value, &vlob));
        index.is_null = CT_FALSE;
        index.type = CT_TYPE_INTEGER;
        ARRAY_INIT_ASSIST_INFO(&array_ass, stmt);
        for (subscript = 1; subscript <= arr_count; subscript++) {
            CTSQL_SAVE_STACK(stmt);
            if (sql_get_element_to_value(stmt, &array_ass, &vlob, subscript, arr_count,
                                         var->v_array.type, &var_element) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
            }

            if (sql_convert_variant(stmt, &var_element, coll->type_mode.datatype) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
            }

            if (CT_IS_VARLEN_TYPE(var_element.type)) {
                var_element.v_bin.size = MIN(var_element.v_bin.size, coll->type_mode.size);
            }
            sql_keep_stack_variant(stmt, &var_element);
            index.v_int = subscript;

            if (udt_coll_elemt_address(stmt, res, &index, NULL, &var_element) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
            }

            CTSQL_RESTORE_STACK(stmt);
        }
    }
    return CT_SUCCESS;
}

status_t ple_array_as_collection(sql_stmt_t *stmt, variant_t *var, void *pl_coll)
{
    variant_t res;
    uint32 arr_count = var->v_array.count;
    plv_collection_t *coll = (plv_collection_t *)pl_coll;

    if (coll->type == UDT_VARRAY && arr_count > coll->limit) {
        CT_THROW_ERROR_EX(ERR_PL_SYNTAX_ERROR_FMT, "Can not convert from array(len = %u) to varray(max len = %u)",
            arr_count, coll->limit);
        return CT_ERROR;
    }
    if (!var_datatype_matched(coll->type_mode.datatype, var->v_array.type)) {
        CT_THROW_ERROR_EX(ERR_PL_SYNTAX_ERROR_FMT,
            "Can not convert from array(element type = %s) to collection(element type = %s)",
            get_datatype_name_str(coll->type_mode.datatype), get_datatype_name_str(var->v_array.type));
        return CT_ERROR;
    }
    if (var->is_null) {
        var->type = CT_TYPE_COLLECTION;
        var->v_collection.coll_meta = pl_coll;
        var->v_collection.is_constructed = CT_FALSE;
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(ple_array_as_collection_insert(stmt, coll, var, &res));
    *var = res;
    return CT_SUCCESS;
}
