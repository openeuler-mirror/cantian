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
 * pl_varray.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/type/pl_varray.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_varray.h"
#include "pl_hash_tb.h"
#include "pl_base.h"
#include "pl_udt.h"
#include "pl_scalar.h"

static status_t udt_verify_varray_delete(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_verify_varray_trim(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_verify_varray_exists(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_verify_varray_extend(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_verify_varray_first(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_verify_varray_last(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_verify_varray_count(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_verify_varray_limit(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_verify_varray_prior(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_verify_varray_next(sql_verifier_t *verif, expr_node_t *method);

static status_t udt_varray_count(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_varray_delete(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_varray_exists(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_varray_extend(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_varray_first(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_varray_last(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);

static status_t udt_varray_limit(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_varray_prior(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_varray_next(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_varray_trim(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_varray_constructor(sql_stmt_t *stmt, udt_constructor_t *v_construct, expr_tree_t *args,
    variant_t *output);
static status_t udt_verify_varray(sql_verifier_t *verif, expr_node_t *node, plv_collection_t *collection,
    expr_tree_t *args);
static status_t udt_clone_varray_elements(sql_stmt_t *stmt, mtrl_array_head_t *collection_head, plv_collection_t *coll_meta,
    uint32 copy_from, mtrl_rowid_t *copy_to);
static status_t udt_delete_varray_elemet(sql_stmt_t *stmt, var_collection_t *v_coll, mtrl_array_head_t *collection_head,
    uint32 index);

static const plv_collection_method_t g_varray_methods[METHOD_END] = {
    { udt_varray_count,  udt_verify_varray_count, AS_FUNC, { 0 } },
    { udt_varray_delete, udt_verify_varray_delete, AS_PROC, { 0 } },
    { udt_varray_exists, udt_verify_varray_exists, AS_FUNC, { 0 } },
    { udt_varray_extend, udt_verify_varray_extend, AS_PROC, { 0 } },
    { udt_varray_first,  udt_verify_varray_first, AS_FUNC, { 0 } },
    { udt_varray_last,   udt_verify_varray_last, AS_FUNC, { 0 } },
    { udt_varray_limit,  udt_verify_varray_limit, AS_FUNC, { 0 } },
    { udt_varray_next,   udt_verify_varray_next, AS_FUNC, { 0 } },
    { udt_varray_prior,  udt_verify_varray_prior, AS_FUNC, { 0 } },
    { udt_varray_trim,   udt_verify_varray_trim, AS_PROC, { 0 } },
};

static const plv_coll_construct_t g_varray_constructor = {
    udt_varray_constructor,
    udt_verify_varray,
};
static status_t udt_varray_intr_trim(sql_stmt_t *stmt, variant_t *var, void *arg);
static status_t udt_varray_intr_extend_num(sql_stmt_t *stmt, variant_t *var, void *arg);
static const intr_method_t g_varray_intr_method[METHOD_INTR_END] = {
    udt_varray_intr_trim,
    udt_varray_intr_extend_num
};


static status_t udt_verify_varray(sql_verifier_t *verif, expr_node_t *node, plv_collection_t *collection,
    expr_tree_t *args)
{
    plv_decl_t *decl = plm_get_type_decl_by_coll(collection);
    return udt_verify_construct_base(verif, node, 0, collection->limit, &decl->name, udt_verify_coll_elemt);
}

static status_t udt_verify_varray_delete(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 0, 0) != CT_SUCCESS) {
        return CT_ERROR;
    }
    /* return type void */
    method->datatype = CT_TYPE_VARCHAR;
    method->size = 0;
    return CT_SUCCESS;
}

static status_t udt_verify_varray_trim(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 0, 1) != CT_SUCCESS) {
        return CT_ERROR;
    }

    method->datatype = CT_TYPE_VARCHAR;
    method->size = 0;

    return CT_SUCCESS;
}

static status_t udt_verify_varray_exists(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 1, 1) != CT_SUCCESS) {
        return CT_ERROR;
    }

    method->datatype = CT_TYPE_BOOLEAN;
    method->size = CT_BOOLEAN_SIZE;
    return CT_SUCCESS;
}

static status_t udt_verify_varray_extend(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, UDT_NTBL_MIN_ARGS, UDT_NTBL_MAX_ARGS) != CT_SUCCESS) {
        return CT_ERROR;
    }

    method->datatype = CT_TYPE_VARCHAR;
    method->size = 0;

    return CT_SUCCESS;
}

static status_t udt_verify_varray_first(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 0, 0) != CT_SUCCESS) {
        return CT_ERROR;
    }

    method->datatype = CT_TYPE_UINT32;
    method->size = CT_INTEGER_SIZE;

    return CT_SUCCESS;
}

static status_t udt_verify_varray_last(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 0, 0) != CT_SUCCESS) {
        return CT_ERROR;
    }

    method->datatype = CT_TYPE_UINT32;
    method->size = CT_INTEGER_SIZE;

    return CT_SUCCESS;
}

static status_t udt_verify_varray_count(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 0, 0) != CT_SUCCESS) {
        return CT_ERROR;
    }

    method->datatype = CT_TYPE_UINT32;
    method->size = CT_INTEGER_SIZE;
    return CT_SUCCESS;
}

static status_t udt_verify_varray_limit(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 0, 0) != CT_SUCCESS) {
        return CT_ERROR;
    }

    method->datatype = CT_TYPE_UINT32;
    method->size = CT_INTEGER_SIZE;

    return CT_SUCCESS;
}

static status_t udt_verify_varray_prior(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 1, 1) != CT_SUCCESS) {
        return CT_ERROR;
    }

    method->datatype = CT_TYPE_UINT32;
    method->size = CT_INTEGER_SIZE;

    return CT_SUCCESS;
}

static status_t udt_verify_varray_next(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 1, 1) != CT_SUCCESS) {
        return CT_ERROR;
    }

    method->datatype = CT_TYPE_UINT32;
    method->size = CT_TYPE_UINT32;

    return CT_SUCCESS;
}

static status_t udt_varray_count(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    mtrl_array_head_t *collection_head = NULL;

    output->type = CT_TYPE_UINT32;
    output->is_null = CT_FALSE;

    if (IS_COLLECTION_EMPTY(&var->v_collection)) {
        output->v_uint32 = 0;
        return CT_SUCCESS;
    }
    OPEN_VM_PTR(&var->v_collection.value, vm_ctx);
    collection_head = (mtrl_array_head_t *)d_ptr;
    output->v_uint32 = collection_head->ctrl.count;
    CLOSE_VM_PTR(&var->v_collection.value, vm_ctx);

    return CT_SUCCESS;
}

static status_t udt_varray_exists(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    variant_t index;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    mtrl_array_head_t *collection_head = NULL;

    output->is_null = CT_FALSE;
    output->type = CT_TYPE_BOOLEAN;
    if (IS_COLLECTION_EMPTY(&var->v_collection)) {
        output->v_bool = CT_FALSE;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_exec_expr(stmt, args, &index));
    if (index.is_null) {
        output->is_null = CT_TRUE;
        output->v_bool = CT_FALSE;
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(var_as_integer(&index));

    if (index.v_int <= 0) {
        output->v_bool = CT_FALSE;
        return CT_SUCCESS;
    }

    OPEN_VM_PTR(&var->v_collection.value, vm_ctx);
    collection_head = (mtrl_array_head_t *)d_ptr;

    if ((uint32)index.v_int > collection_head->ctrl.count) {
        output->v_bool = CT_FALSE;
        CLOSE_VM_PTR_EX(&var->v_collection.value, vm_ctx);
        return CT_SUCCESS;
    }
    output->v_bool = CT_TRUE;
    if (IS_INVALID_MTRL_ROWID(collection_head->array[index.v_int - 1])) {
        output->v_bool = CT_FALSE;
    }

    CLOSE_VM_PTR(&var->v_collection.value, vm_ctx);
    return CT_SUCCESS;
}

static status_t udt_varray_intr_extend_num(sql_stmt_t *stmt, variant_t *var, void *arg)
{
    status_t status;
    uint32 num = *(uint32 *)arg;
    plv_collection_t *coll_meta = var->v_collection.coll_meta;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    mtrl_array_head_t *collection_head = NULL;
    errno_t err;
    mtrl_rowid_t *row_id = NULL;
    if (num == 0) {
        return CT_ERROR;
    }
    OPEN_VM_PTR(&var->v_collection.value, vm_ctx);
    collection_head = (mtrl_array_head_t *)d_ptr;

    if (collection_head->ctrl.count + num > collection_head->ctrl.hwm) {
        CLOSE_VM_PTR_EX(&var->v_collection.value, vm_ctx);
        CT_THROW_ERROR(ERR_SUBSCRIPT_BEYOND_COUNT);
        return CT_ERROR;
    }

    err = memset_sp(collection_head->array + collection_head->ctrl.count, num * sizeof(mtrl_rowid_t), 0xFF,
        num * sizeof(mtrl_rowid_t));
    if (err != EOK) {
        CLOSE_VM_PTR_EX(&var->v_collection.value, vm_ctx);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CT_ERROR;
    }

    for (uint32 i = 0; i < num; i++) {
        row_id = &collection_head->array[collection_head->ctrl.count + i];
        if (coll_meta->attr_type == UDT_RECORD) {
            status = udt_record_alloc_mtrl_head(stmt, UDT_GET_TYPE_DEF_RECORD(coll_meta->elmt_type), row_id);
            if (status != CT_SUCCESS) {
                CLOSE_VM_PTR_EX(&var->v_collection.value, vm_ctx);
                return CT_ERROR;
            }
        }
    }
    collection_head->ctrl.count += num;
    CLOSE_VM_PTR(&var->v_collection.value, vm_ctx);
    return CT_SUCCESS;
}

static status_t udt_varray_extend_elements(sql_stmt_t *stmt, plv_collection_t *coll_meta, mtrl_array_head_t *collection_head,
    uint32 copy_from, bool32 is_copy, uint32 count)
{
    mtrl_rowid_t *row_id = NULL;
    MEMS_RETURN_IFERR(memset_sp(collection_head->array + collection_head->ctrl.count, count * sizeof(mtrl_rowid_t), 0xFF,
        count * sizeof(mtrl_rowid_t)));

    for (uint32 i = 0; i < count; i++) {
        row_id = &collection_head->array[collection_head->ctrl.count + i];
        if (is_copy) {
            CT_RETURN_IFERR(udt_clone_varray_elements(stmt, collection_head, coll_meta, copy_from - 1, row_id));
        } else {
            if (coll_meta->attr_type == UDT_RECORD) {
                CT_RETURN_IFERR(
                    udt_record_alloc_mtrl_head(stmt, UDT_GET_TYPE_DEF_RECORD(coll_meta->elmt_type), row_id));
            }
            if (ELMT_IS_HASH_TABLE(coll_meta)) {
                variant_t left;
                MAKE_COLL_VAR(&left, coll_meta->elmt_type, g_invalid_entry);
                CT_RETURN_IFERR(udt_hash_table_init_var(stmt, &left));
                *row_id = left.v_collection.value;
            }
        }
    }
    return CT_SUCCESS;
}

static status_t udt_varray_extend(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    status_t status;
    plv_collection_t *coll_meta = var->v_collection.coll_meta;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    mtrl_array_head_t *collection_head = NULL;
    variant_t var1, var2;
    uint32 count = 1;
    uint32 copy_from = 0;
    bool32 is_copy = CT_FALSE;

    /* extend() appends one null element to the collection */
    if (args != NULL) {
        /* extend(n) appends n null element to the collection */
        status = sql_exec_expr(stmt, args, &var1);
        CT_RETURN_IFERR(status);
        if (var1.is_null) {
            return CT_SUCCESS;
        }
        status = var_as_uint32(&var1);
        CT_RETURN_IFERR(status);
        count = VALUE(uint32, &var1);
        if (args->next != NULL) {
            /* extend(n,i) appends n copies of the ith element to the collection */
            status = sql_exec_expr(stmt, args->next, &var2);
            CT_RETURN_IFERR(status);
            if (var2.is_null) {
                return CT_SUCCESS;
            }
            status = var_as_uint32(&var2);
            CT_RETURN_IFERR(status);
            copy_from = VALUE(uint32, &var2);
            is_copy = CT_TRUE;
        }
    }

    OPEN_VM_PTR(&var->v_collection.value, vm_ctx);
    collection_head = (mtrl_array_head_t *)d_ptr;

    if ((collection_head->ctrl.count + count > collection_head->ctrl.hwm) || (is_copy && copy_from > collection_head->ctrl.count)) {
        CLOSE_VM_PTR_EX(&var->v_collection.value, vm_ctx);
        CT_THROW_ERROR(ERR_SUBSCRIPT_BEYOND_COUNT);
        return CT_ERROR;
    }

    if (udt_varray_extend_elements(stmt, coll_meta, collection_head, copy_from, is_copy, count) != CT_SUCCESS) {
        CLOSE_VM_PTR_EX(&var->v_collection.value, vm_ctx);
        return CT_ERROR;
    }
    collection_head->ctrl.count += count;
    CLOSE_VM_PTR(&var->v_collection.value, vm_ctx);
    return CT_SUCCESS;
}

static status_t udt_varray_first(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    mtrl_array_head_t *collection_head = NULL;

    if (IS_COLLECTION_EMPTY(&var->v_collection)) {
        output->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    OPEN_VM_PTR(&var->v_collection.value, vm_ctx);
    collection_head = (mtrl_array_head_t *)d_ptr;
    if (collection_head->ctrl.count > 0) {
        output->is_null = CT_FALSE;
        output->v_uint32 = 1;
        output->type = CT_TYPE_UINT32;
    } else {
        output->is_null = CT_TRUE;
    }

    CLOSE_VM_PTR(&var->v_collection.value, vm_ctx);
    return CT_SUCCESS;
}

static status_t udt_varray_last(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    mtrl_array_head_t *collection_head = NULL;

    if (IS_COLLECTION_EMPTY(&var->v_collection)) {
        output->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    OPEN_VM_PTR(&var->v_collection.value, vm_ctx);
    collection_head = (mtrl_array_head_t *)d_ptr;
    if (collection_head->ctrl.count > 0) {
        output->is_null = CT_FALSE;
        output->type = CT_TYPE_UINT32;
        output->v_uint32 = collection_head->ctrl.count;
    } else {
        output->is_null = CT_TRUE;
    }

    CLOSE_VM_PTR(&var->v_collection.value, vm_ctx);
    return CT_SUCCESS;
}

static status_t udt_varray_limit(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    mtrl_array_head_t *collection_head = NULL;
    uint32 limit;

    OPEN_VM_PTR(&var->v_collection.value, vm_ctx);
    collection_head = (mtrl_array_head_t *)d_ptr;
    limit = collection_head->ctrl.hwm;
    CLOSE_VM_PTR(&var->v_collection.value, vm_ctx);

    output->is_null = CT_FALSE;
    output->type = CT_TYPE_UINT32;
    output->v_uint32 = limit;
    return CT_SUCCESS;
}

static status_t udt_varray_prior(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    status_t status;
    variant_t index;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    mtrl_array_head_t *collection_head = NULL;
    if (IS_COLLECTION_EMPTY(&var->v_collection)) {
        output->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    status = sql_exec_expr(stmt, args, &index);
    CT_RETURN_IFERR(status);
    if (index.is_null) {
        output->is_null = CT_TRUE;
        return CT_SUCCESS;
    }
    status = var_as_integer(&index);
    CT_RETURN_IFERR(status);
    output->type = CT_TYPE_UINT32;
    if (index.v_int <= 1) {
        output->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    OPEN_VM_PTR(&var->v_collection.value, vm_ctx);
    collection_head = (mtrl_array_head_t *)d_ptr;
    if (collection_head->ctrl.count == 0) {
        output->is_null = CT_TRUE;
    } else if (index.v_int > (int32)collection_head->ctrl.count) {
        output->is_null = CT_FALSE;
        output->v_uint32 = collection_head->ctrl.count;
    } else {
        output->is_null = CT_FALSE;
        output->v_uint32 = (uint32)index.v_int - 1;
    }
    CLOSE_VM_PTR(&var->v_collection.value, vm_ctx);

    return CT_SUCCESS;
}

static status_t udt_varray_next(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    status_t status;
    variant_t index;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    mtrl_array_head_t *collection_head = NULL;

    if (IS_COLLECTION_EMPTY(&var->v_collection)) {
        output->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    status = sql_exec_expr(stmt, args, &index);
    CT_RETURN_IFERR(status);
    if (index.is_null) {
        output->is_null = CT_TRUE;
        return CT_SUCCESS;
    }
    status = var_as_integer(&index);
    CT_RETURN_IFERR(status);
    output->type = CT_TYPE_UINT32;

    if (index.v_int <= 0) {
        output->is_null = CT_FALSE;
        output->v_uint32 = 1;
        return CT_SUCCESS;
    }
    OPEN_VM_PTR(&var->v_collection.value, vm_ctx);
    collection_head = (mtrl_array_head_t *)d_ptr;
    if (collection_head->ctrl.count == 0 || index.v_int >= (int32)collection_head->ctrl.count) {
        output->is_null = CT_TRUE;
    } else {
        output->is_null = CT_FALSE;
        output->v_uint32 = (uint32)index.v_int + 1;
    }
    CLOSE_VM_PTR(&var->v_collection.value, vm_ctx);

    return CT_SUCCESS;
}

static status_t udt_varray_trim(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    status_t status;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    mtrl_array_head_t *collection_head = NULL;
    variant_t trim_var;
    uint32 trim_size = 0;

    if (IS_COLLECTION_EMPTY(&var->v_collection)) {
        CT_THROW_ERROR(ERR_SUBSCRIPT_BEYOND_COUNT);
        return CT_ERROR;
    }

    if (args == NULL) {
        trim_size = 1;
    } else {
        CT_RETURN_IFERR(sql_exec_expr(stmt, args, &trim_var));
        if (trim_var.is_null) {
            return CT_SUCCESS;
        }
        CT_RETURN_IFERR(var_as_uint32(&trim_var));
        trim_size = VALUE(uint32, &trim_var);
    }

    OPEN_VM_PTR(&var->v_collection.value, vm_ctx);
    collection_head = (mtrl_array_head_t *)d_ptr;
    if (trim_size > collection_head->ctrl.count) {
        CT_THROW_ERROR(ERR_SUBSCRIPT_BEYOND_COUNT);
        CLOSE_VM_PTR_EX(&var->v_collection.value, vm_ctx);
        return CT_ERROR;
    }

    for (int64 i = collection_head->ctrl.count - 1; i >= collection_head->ctrl.count - trim_size; i--) {
        status = udt_delete_varray_elemet(stmt, &var->v_collection, collection_head, (uint32)i);
        if (status != CT_SUCCESS) {
            CLOSE_VM_PTR_EX(&var->v_collection.value, vm_ctx);
            return CT_ERROR;
        }
    }
    collection_head->ctrl.count = collection_head->ctrl.count - trim_size;
    CLOSE_VM_PTR(&var->v_collection.value, vm_ctx);

    return CT_SUCCESS;
}

static status_t udt_varray_intr_trim(sql_stmt_t *stmt, variant_t *var, void *arg)
{
    status_t status;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    mtrl_array_head_t *collection_head = NULL;

    if (IS_COLLECTION_EMPTY(&var->v_collection)) {
        return CT_SUCCESS;
    }

    OPEN_VM_PTR(&var->v_collection.value, vm_ctx);
    collection_head = (mtrl_array_head_t *)d_ptr;
    if (collection_head->ctrl.count == 0) {
        CLOSE_VM_PTR_EX(&var->v_collection.value, vm_ctx);
        return CT_SUCCESS;
    }

    for (int64 i = collection_head->ctrl.count - 1; i >= 0; i--) {
        status = udt_delete_varray_elemet(stmt, &var->v_collection, collection_head, (uint32)i);
        if (status != CT_SUCCESS) {
            CLOSE_VM_PTR_EX(&var->v_collection.value, vm_ctx);
            return CT_ERROR;
        }
    }
    collection_head->ctrl.count = 0;
    CLOSE_VM_PTR(&var->v_collection.value, vm_ctx);

    return CT_SUCCESS;
}

static status_t udt_varray_address_write_element(sql_stmt_t *stmt, var_collection_t *v_coll,
    mtrl_array_head_t *collection_head, uint32 index, variant_t *right)
{
    variant_t left;
    plv_collection_t *coll_meta = (plv_collection_t *)v_coll->coll_meta;
    mtrl_rowid_t *row_id = &collection_head->array[index];

    switch (coll_meta->attr_type) {
        case UDT_SCALAR:
            CT_RETURN_IFERR(udt_delete_varray_elemet(stmt, v_coll, collection_head, index));
            if (!right->is_null) {
                CT_RETURN_IFERR(udt_make_scalar_elemt(stmt, coll_meta->type_mode, right, row_id, NULL));
            }
            break;

        case UDT_COLLECTION:
            MAKE_COLL_VAR(&left, coll_meta->elmt_type, *row_id);
            CT_RETURN_IFERR(udt_coll_assign(stmt, &left, right));
            *row_id = left.v_collection.value;
            break;

        case UDT_RECORD:
            MAKE_REC_VAR(&left, coll_meta->elmt_type, *row_id);
            CT_RETURN_IFERR(udt_record_assign(stmt, &left, right));
            *row_id = left.v_record.value;
            break;
        case UDT_OBJECT:
            MAKE_OBJ_VAR(&left, coll_meta->elmt_type, *row_id);
            CT_RETURN_IFERR(udt_object_assign(stmt, &left, right));
            *row_id = left.v_object.value;
            break;
        default:
            CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpect attr type");
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t udt_varray_address_write(sql_stmt_t *stmt, variant_t *var, uint32 index, variant_t *right)
{
    status_t status;
    var_collection_t *v_coll = &var->v_collection;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    mtrl_array_head_t *collection_head = NULL;

    OPEN_VM_PTR(&v_coll->value, vm_ctx);
    collection_head = (mtrl_array_head_t *)d_ptr;
    if (index >= collection_head->ctrl.count) {
        CT_THROW_ERROR(ERR_SUBSCRIPT_BEYOND_COUNT);
        CLOSE_VM_PTR_EX(&v_coll->value, vm_ctx);
        return CT_ERROR;
    }

    status = udt_varray_address_write_element(stmt, v_coll, collection_head, index, right);
    CLOSE_VM_PTR(&v_coll->value, vm_ctx);
    return status;
}

static status_t udt_varray_read_element(sql_stmt_t *stmt, uint32 index, plv_collection_t *coll_meta,
    mtrl_array_head_t *collection_head, variant_t *output)
{
    switch (coll_meta->attr_type) {
        case UDT_SCALAR:
            output->type = (int16)coll_meta->type_mode.datatype;
            CT_RETURN_IFERR(udt_read_scalar_value(stmt, &collection_head->array[index], output));
            break;
        case UDT_COLLECTION:
            output->type = CT_TYPE_COLLECTION;
            output->v_collection.type = coll_meta->elmt_type->typdef.collection.type;
            output->v_collection.coll_meta = &coll_meta->elmt_type->typdef.collection;
            output->v_collection.value = collection_head->array[index];
            output->v_collection.is_constructed = CT_FALSE;
            break;
        case UDT_RECORD:
            output->type = CT_TYPE_RECORD;
            output->v_record.count = coll_meta->elmt_type->typdef.record.count;
            output->v_record.record_meta = &coll_meta->elmt_type->typdef.record;
            output->v_record.value = collection_head->array[index];
            output->v_record.is_constructed = CT_FALSE;
            break;
        case UDT_OBJECT:
            output->type = CT_TYPE_OBJECT;
            output->v_object.count = coll_meta->elmt_type->typdef.object.count;
            output->v_object.object_meta = &coll_meta->elmt_type->typdef.object;
            output->v_object.value = collection_head->array[index];
            output->v_object.is_constructed = CT_FALSE;
            break;
        default:
            CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpect attr type");
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t udt_varray_address_read(sql_stmt_t *stmt, variant_t *var, uint32 index, variant_t *output)
{
    var_collection_t *v_coll = &var->v_collection;
    plv_collection_t *coll_meta = (plv_collection_t *)v_coll->coll_meta;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    mtrl_array_head_t *collection_head = NULL;
    status_t status;

    OPEN_VM_PTR(&v_coll->value, vm_ctx);
    collection_head = (mtrl_array_head_t *)d_ptr;
    if (index >= collection_head->ctrl.count) {
        CT_THROW_ERROR(ERR_SUBSCRIPT_BEYOND_COUNT);
        CLOSE_VM_PTR_EX(&v_coll->value, vm_ctx);
        return CT_ERROR;
    }

    if (IS_INVALID_MTRL_ROWID(collection_head->array[index])) {
        CLOSE_VM_PTR_EX(&v_coll->value, vm_ctx);
        output->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    output->is_null = CT_FALSE;
    status = udt_varray_read_element(stmt, index, coll_meta, collection_head, output);
    CLOSE_VM_PTR(&v_coll->value, vm_ctx);
    return status;
}

/**
 * fetch varray element from mtrl memory
 * @caution: index lower bound from 0
 */
status_t udt_varray_address(sql_stmt_t *stmt, variant_t *var, variant_t *index, addr_type_t type, variant_t *output,
    variant_t *right)
{
    plv_collection_t *collection = (plv_collection_t *)var->v_collection.coll_meta;
    status_t status;
    if (var_as_uint32(index) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (index->v_uint32 == 0 || index->v_uint32 > collection->limit) {
        CT_THROW_ERROR(ERR_SUBSCRIPT_OUTSIDE_LIMIT);
        return CT_ERROR;
    }

    if (type == READ_ADDR) {
        status = udt_varray_address_read(stmt, var, index->v_uint32 - 1, output);
    } else {
        status = udt_varray_address_write(stmt, var, index->v_uint32 - 1, right);
    }

    return status;
}

static status_t udt_clone_varray_elements(sql_stmt_t *stmt, mtrl_array_head_t *collection_head, plv_collection_t *coll_meta,
    uint32 copy_from, mtrl_rowid_t *copy_to)
{
    status_t status;
    variant_t var;
    plv_decl_t *ele_meta = NULL;

    if (IS_INVALID_MTRL_ROWID(ROWID_ID2_UINT64(collection_head->array[copy_from]))) {
        *copy_to = g_invalid_entry;
        return CT_SUCCESS;
    }

    switch (coll_meta->attr_type) {
        case UDT_SCALAR:
            status = udt_clone_scalar(stmt, collection_head->array[copy_from], copy_to);
            break;
        case UDT_COLLECTION:
            ele_meta = coll_meta->elmt_type;
            CM_ASSERT(ele_meta->type == PLV_TYPE);
            CM_ASSERT(ele_meta->typdef.type == PLV_COLLECTION);
            MAKE_COLL_VAR(&var, ele_meta, collection_head->array[copy_from]);
            if (ELMT_IS_HASH_TABLE(coll_meta)) {
                *copy_to = g_invalid_entry;
            }
            status = udt_clone_collection(stmt, &var, copy_to);
            break;
        case UDT_RECORD:
            ele_meta = coll_meta->elmt_type;
            CM_ASSERT(ele_meta->type == PLV_TYPE);
            CM_ASSERT(ele_meta->typdef.type == PLV_RECORD);
            MAKE_REC_VAR(&var, ele_meta, collection_head->array[copy_from]);
            status = udt_record_clone_all(stmt, &var, copy_to);
            break;
        case UDT_OBJECT:
            ele_meta = coll_meta->elmt_type;
            CM_ASSERT(ele_meta->type == PLV_TYPE);
            CM_ASSERT(ele_meta->typdef.type == PLV_OBJECT);
            MAKE_OBJ_VAR(&var, ele_meta, collection_head->array[copy_from]);
            status = udt_object_clone(stmt, &var, copy_to);
            break;
        default:
            return CT_ERROR;
    }
    return status;
}

static status_t udt_varray_alloc_mtrl_head(sql_stmt_t *stmt, plv_collection_t *coll_meta, variant_t *output)
{
    uint32 head_size;
    status_t status;
    mtrl_array_head_t *collection_head = NULL;
    errno_t err;

    output->is_null = CT_FALSE;
    output->type = (int16)CT_TYPE_COLLECTION;
    output->v_collection.coll_meta = coll_meta;
    output->v_collection.type = (uint8)UDT_VARRAY;
    head_size = (uint32)(coll_meta->limit * sizeof(mtrl_rowid_t)) + (uint32)sizeof(mtrl_array_head_t);
    CT_RETURN_IFERR(sql_push(stmt, head_size, (void **)&collection_head));
    collection_head->ctrl.datatype = GET_COLLECTION_ELEMENT_TYPE(coll_meta);
    collection_head->ctrl.hwm = coll_meta->limit;
    collection_head->ctrl.count = 0;
    err = memset_sp(collection_head->array, collection_head->ctrl.hwm * sizeof(mtrl_rowid_t), 0xFF,
        collection_head->ctrl.hwm * sizeof(mtrl_rowid_t));
    if (err != EOK) {
        CTSQL_POP(stmt);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CT_ERROR;
    }

    status = vmctx_insert(GET_VM_CTX(stmt), (const char *)collection_head, head_size, &output->v_collection.value);
    CTSQL_POP(stmt);

    return status;
}

status_t udt_varray_add_var(sql_stmt_t *stmt, mtrl_array_head_t *collection_head, plv_collection_t *coll_meta, variant_t *var,
    mtrl_rowid_t *rowid)
{
    variant_t left;
    plv_decl_t *type_decl = plm_get_type_decl_by_coll(coll_meta);

    switch (coll_meta->attr_type) {
        case UDT_SCALAR:
            if (var->type >= CT_TYPE_OPERAND_CEIL) {
                CT_THROW_ERROR(ERR_PL_WRONG_ARG_METHOD_INVOKE, T2S(&type_decl->name));
                return CT_ERROR;
            }
            if (!var->is_null) {
                CT_RETURN_IFERR(udt_make_scalar_elemt(stmt, coll_meta->type_mode, var, rowid, NULL));
            }
            break;

        case UDT_COLLECTION:
            MAKE_COLL_VAR(&left, coll_meta->elmt_type, *rowid);
            CT_RETURN_IFERR(udt_coll_assign(stmt, &left, var));
            *rowid = left.v_collection.value;
            break;
        case UDT_RECORD:
            CT_RETURN_IFERR(udt_record_alloc_mtrl_head(stmt, UDT_GET_TYPE_DEF_RECORD(coll_meta->elmt_type), rowid));
            MAKE_REC_VAR(&left, coll_meta->elmt_type, *rowid);
            CT_RETURN_IFERR(udt_record_assign(stmt, &left, var));
            *rowid = left.v_record.value;
            break;
        case UDT_OBJECT:
            MAKE_OBJ_VAR(&left, coll_meta->elmt_type, *rowid);
            CT_RETURN_IFERR(udt_object_assign(stmt, &left, var));
            *rowid = left.v_object.value;
            break;
        default:
            return CT_ERROR;
    }
    collection_head->ctrl.count++;
    return CT_SUCCESS;
}

static status_t udt_varray_constructor(sql_stmt_t *stmt, udt_constructor_t *v_construct, expr_tree_t *args,
    variant_t *output)
{
    status_t status;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    bool32 pending = CT_FALSE;
    uint32 len, i;
    variant_t *element_vars = NULL;
    plv_collection_t *coll_meta = (plv_collection_t *)v_construct->meta;

    mtrl_array_head_t *collection_head = NULL;

    len = ((args == NULL) ? 0 : sql_expr_list_len(args));
    CT_RETURN_IFERR(udt_varray_alloc_mtrl_head(stmt, coll_meta, output));
    if (len == 0) {
        return CT_SUCCESS;
    }

    if (len > coll_meta->limit) {
        CT_THROW_ERROR(ERR_SUBSCRIPT_OUTSIDE_LIMIT);
        return CT_ERROR;
    }

    CTSQL_SAVE_STACK(stmt);
    CT_RETURN_IFERR(sql_push(stmt, len * sizeof(variant_t), (void **)&element_vars));

    if (sql_exec_expr_list(stmt, args, len, element_vars, &pending, NULL) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    if (vmctx_open_row_id(vm_ctx, &output->v_collection.value, (char **)&collection_head) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    for (i = 0; i < len; i++) {
        status = udt_varray_add_var(stmt, collection_head, coll_meta, &element_vars[i], &collection_head->array[i]);
        if (status != CT_SUCCESS) {
            break;
        }
    }

    vmctx_close_row_id(vm_ctx, &output->v_collection.value);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}


static status_t udt_clone_varray(sql_stmt_t *stmt, variant_t *var, mtrl_rowid_t *result)
{
    status_t status;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    mtrl_array_head_t *collection_head = NULL;

    OPEN_VM_PTR(&var->v_collection.value, vm_ctx);
    status = vmctx_insert(vm_ctx, (const char *)d_ptr, d_chunk->requested_size, result);
    CLOSE_VM_PTR(&var->v_collection.value, vm_ctx);
    if (status != CT_SUCCESS) {
        return CT_ERROR;
    }
    OPEN_VM_PTR(result, vm_ctx);
    collection_head = (mtrl_array_head_t *)d_ptr;
    for (uint32 i = 0; i < collection_head->ctrl.count; i++) {
        status = udt_clone_varray_elements(stmt, collection_head, (plv_collection_t *)var->v_collection.coll_meta, i,
            &collection_head->array[i]);
        if (status != CT_SUCCESS) {
            CLOSE_VM_PTR_EX(result, vm_ctx);
            return CT_ERROR;
        }
    }
    CLOSE_VM_PTR(result, vm_ctx);

    return status;
}

static status_t udt_delete_varray_elemet(sql_stmt_t *stmt, var_collection_t *v_coll, mtrl_array_head_t *collection_head,
    uint32 index)
{
    variant_t var;
    status_t status;
    plv_collection_t *coll_meta = (plv_collection_t *)v_coll->coll_meta;
    plv_decl_t *ele_meta = NULL;

    if (IS_INVALID_MTRL_ROWID(collection_head->array[index])) {
        return CT_SUCCESS;
    }

    switch (coll_meta->attr_type) {
        case UDT_SCALAR:
            break;
        case UDT_COLLECTION:
            ele_meta = coll_meta->elmt_type;
            CM_ASSERT(ele_meta->type == PLV_TYPE);
            CM_ASSERT(ele_meta->typdef.type == PLV_COLLECTION);
            MAKE_COLL_VAR(&var, ele_meta, collection_head->array[index]);

            status = udt_delete_collection(stmt, &var);
            CT_RETURN_IFERR(status);
            break;
        case UDT_RECORD:
            ele_meta = coll_meta->elmt_type;
            CM_ASSERT(ele_meta->type == PLV_TYPE);
            CM_ASSERT(ele_meta->typdef.type == PLV_RECORD);
            MAKE_REC_VAR(&var, ele_meta, collection_head->array[index]);
            status = udt_record_delete(stmt, &var, CT_TRUE);
            CT_RETURN_IFERR(status);
            collection_head->array[index] = g_invalid_entry;
            return CT_SUCCESS;
        case UDT_OBJECT:
            ele_meta = coll_meta->elmt_type;
            CM_ASSERT(ele_meta->type == PLV_TYPE);
            CM_ASSERT(ele_meta->typdef.type == PLV_OBJECT);
            MAKE_OBJ_VAR(&var, ele_meta, collection_head->array[index]);
            status = udt_object_delete(stmt, &var);
            CT_RETURN_IFERR(status);
            collection_head->array[index] = g_invalid_entry;
            return CT_SUCCESS;
        default:
            return CT_ERROR;
    }

    status = vmctx_free(GET_VM_CTX(stmt), &collection_head->array[index]);
    CT_RETURN_IFERR(status);
    collection_head->array[index] = g_invalid_entry;

    return CT_SUCCESS;
}

static status_t udt_varray_delete(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    status_t status;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    mtrl_array_head_t *collection_head = NULL;
    CT_RETURN_IFERR(sql_stack_safe(stmt));
    if (IS_COLLECTION_EMPTY(&var->v_collection)) {
        return CT_SUCCESS;
    }

    OPEN_VM_PTR(&(var->v_collection.value), vm_ctx);
    collection_head = (mtrl_array_head_t *)d_ptr;
    if (collection_head->ctrl.count == 0) {
        CLOSE_VM_PTR_EX(&var->v_collection.value, vm_ctx);
        return CT_SUCCESS;
    }

    for (uint32 i = 0; i < collection_head->ctrl.count; i++) {
        status = udt_delete_varray_elemet(stmt, &var->v_collection, collection_head, i);
        if (status != CT_SUCCESS) {
            CLOSE_VM_PTR_EX(&var->v_collection.value, vm_ctx);
            return CT_ERROR;
        }
    }
    collection_head->ctrl.count = 0;
    CLOSE_VM_PTR(&var->v_collection.value, vm_ctx);
    return CT_SUCCESS;
}

static inline status_t udt_varray_free(sql_stmt_t *stmt, variant_t *var)
{
    return udt_varray_delete(stmt, var, NULL, NULL);
}

void udt_reg_varray_method(void)
{
    handle_mutiple_ptrs_t mutiple_ptrs;
    mutiple_ptrs.ptr1 = (void *)g_varray_methods;
    mutiple_ptrs.ptr2 = (void *)(&g_varray_constructor);
    mutiple_ptrs.ptr3 = (void *)udt_varray_free;
    mutiple_ptrs.ptr4 = (void *)g_varray_intr_method;
    mutiple_ptrs.ptr5 = (void *)udt_clone_varray;
    mutiple_ptrs.ptr6 = (void *)udt_varray_address;
    udt_reg_coll_method(UDT_VARRAY, &mutiple_ptrs);
}
