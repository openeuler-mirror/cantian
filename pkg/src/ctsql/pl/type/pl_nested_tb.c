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
 * pl_nested_tb.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/type/pl_nested_tb.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_nested_tb.h"
#include "pl_hash_tb.h"
#include "pl_base.h"
#include "pl_udt.h"
#include "pl_scalar.h"

static status_t udt_verify_nested_table_next(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_verify_nested_table_delete(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_verify_nested_table_trim(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_verify_nested_table_exists(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_verify_nested_table_extend(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_verify_nested_table_first(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_verify_nested_table_last(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_verify_nested_table_count(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_verify_nested_table_limit(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_verify_nested_table_prior(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_nested_table_count(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_nested_table_delete(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_nested_table_exists(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_nested_table_extend(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_nested_table_first(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_nested_table_last(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_nested_table_limit(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_nested_table_prior(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_nested_table_trim(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_nested_table_next(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_nested_table_constructor(sql_stmt_t *stmt, udt_constructor_t *v_construct, expr_tree_t *args,
    variant_t *output);
static status_t udt_verify_nested_table(sql_verifier_t *verf, expr_node_t *node, plv_collection_t *collection,
                                        expr_tree_t *args);
static status_t udt_nested_table_find_slot(sql_stmt_t *stmt, mtrl_ntbl_head_t *collection_head, uint32 index,
    mtrl_rowid_t *rd_ext_id, mtrl_rowid_t *entry, bool32 reverse);
static status_t udt_nested_table_delete_element(sql_stmt_t *stmt, plv_collection_t *coll_meta, mtrl_rowid_t *entry);
static status_t udt_nested_table_add_var(sql_stmt_t *stmt, plv_collection_t *coll_meta, mtrl_ntbl_head_t *collection_head,
    variant_t *variant);

static const plv_collection_method_t g_nested_table_methods[METHOD_END] = {
    { udt_nested_table_count,  udt_verify_nested_table_count, AS_FUNC, { 0 } },
    { udt_nested_table_delete, udt_verify_nested_table_delete, AS_PROC, { 0 } },
    { udt_nested_table_exists, udt_verify_nested_table_exists, AS_FUNC, { 0 } },
    { udt_nested_table_extend, udt_verify_nested_table_extend, AS_PROC, { 0 } },
    { udt_nested_table_first,  udt_verify_nested_table_first, AS_FUNC, { 0 } },
    { udt_nested_table_last,   udt_verify_nested_table_last, AS_FUNC, { 0 } },
    { udt_nested_table_limit,  udt_verify_nested_table_limit, AS_FUNC, { 0 } },
    { udt_nested_table_next,   udt_verify_nested_table_next, AS_FUNC, { 0 } },
    { udt_nested_table_prior,  udt_verify_nested_table_prior, AS_FUNC, { 0 } },
    { udt_nested_table_trim,   udt_verify_nested_table_trim, AS_PROC, { 0 } }
};

static const plv_coll_construct_t g_nested_table_constructor = {
    udt_nested_table_constructor,
    udt_verify_nested_table,
};

status_t udt_nested_table_intr_trim(sql_stmt_t *stmt, variant_t *var, void *arg);
status_t udt_nested_table_intr_extend_num(sql_stmt_t *stmt, variant_t *var, void *arg);

static const intr_method_t g_nested_table_intr_method[METHOD_INTR_END] = {
    udt_nested_table_intr_trim,
    udt_nested_table_intr_extend_num
};

void udt_nested_table_free_slot(vm_ntbl_ext_t *extent, mtrl_ntbl_head_t *collection_head, uint32 index)
{
    if (VM_NTBL_MAP_EXISTS(index, extent->map)) {
        collection_head->ctrl.count--;
    }
    extent->slot[index] = g_invalid_entry;
    VM_NTBL_MAP_FREE(index, extent->map);
}

static status_t udt_verify_nested_table(sql_verifier_t *verf, expr_node_t *node, plv_collection_t *collection,
                                        expr_tree_t *args)
{
    plv_decl_t *decl = plm_get_type_decl_by_coll(collection);
    return udt_verify_construct_base(verf, node, 0, CT_INVALID_ID32, &decl->name, udt_verify_coll_elemt);
}

static status_t udt_verify_nested_table_next(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 1, 1) != CT_SUCCESS) {
        return CT_ERROR;
    }

    method->datatype = CT_TYPE_UINT32;
    method->size = CT_INTEGER_SIZE;
    return CT_SUCCESS;
}
static status_t udt_verify_nested_table_delete(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, UDT_NTBL_MIN_ARGS, UDT_NTBL_MAX_ARGS) != CT_SUCCESS) {
        return CT_ERROR;
    }

    method->datatype = CT_TYPE_VARCHAR;
    method->size = 0;
    return CT_SUCCESS;
}

static status_t udt_verify_nested_table_trim(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 0, 1) != CT_SUCCESS) {
        return CT_ERROR;
    }

    method->datatype = CT_TYPE_VARCHAR;
    method->size = 0;
    return CT_SUCCESS;
}

static status_t udt_verify_nested_table_exists(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 1, 1) != CT_SUCCESS) {
        return CT_ERROR;
    }

    method->datatype = CT_TYPE_BOOLEAN;
    method->size = CT_BOOLEAN_SIZE;
    return CT_SUCCESS;
}

static status_t udt_verify_nested_table_extend(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, UDT_NTBL_MIN_ARGS, UDT_NTBL_MAX_ARGS) != CT_SUCCESS) {
        return CT_ERROR;
    }

    method->datatype = CT_TYPE_VARCHAR;
    method->size = 0;
    return CT_SUCCESS;
}

static status_t udt_verify_nested_table_first(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 0, 0) != CT_SUCCESS) {
        return CT_ERROR;
    }

    method->datatype = CT_TYPE_UINT32;
    method->size = CT_INTEGER_SIZE;
    return CT_SUCCESS;
}

static status_t udt_verify_nested_table_last(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 0, 0) != CT_SUCCESS) {
        return CT_ERROR;
    }

    method->datatype = CT_TYPE_UINT32;
    method->size = CT_INTEGER_SIZE;
    return CT_SUCCESS;
}

static status_t udt_verify_nested_table_count(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 0, 0) != CT_SUCCESS) {
        return CT_ERROR;
    }

    method->datatype = CT_TYPE_UINT32;
    method->size = CT_INTEGER_SIZE;
    return CT_SUCCESS;
}

static status_t udt_verify_nested_table_limit(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 0, 0) != CT_SUCCESS) {
        return CT_ERROR;
    }

    method->datatype = CT_TYPE_UINT32;
    method->size = CT_INTEGER_SIZE;
    return CT_SUCCESS;
}

static status_t udt_verify_nested_table_prior(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 1, 1) != CT_SUCCESS) {
        return CT_ERROR;
    }

    method->datatype = CT_TYPE_UINT32;
    method->size = CT_INTEGER_SIZE;
    return CT_SUCCESS;
}

static status_t udt_nested_table_count(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    output->type = CT_TYPE_UINT32;
    output->is_null = CT_FALSE;
    if (IS_COLLECTION_EMPTY(&var->v_collection)) {
        output->v_uint32 = 0;
        return CT_SUCCESS;
    }
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    mtrl_ntbl_head_t *collection_head = NULL;
    OPEN_VM_PTR(&(var->v_collection.value), vm_context);
    collection_head = (mtrl_ntbl_head_t *)d_ptr;

    output->v_uint32 = collection_head->ctrl.count;
    CLOSE_VM_PTR(&var->v_collection.value, vm_context);
    return CT_SUCCESS;
}

status_t udt_nested_table_exists_args(sql_stmt_t *stmt, expr_tree_t *args, int32 *id, bool32 *is_null)
{
    bool32 pending = CT_FALSE;
    variant_t element;
    const nlsparams_t *nlsparams = SESSION_NLS(stmt);

    SQL_EXEC_CMP_OPERAND_EX(args, &element, &pending, &pending, stmt);

    if (element.is_null) {
        *is_null = CT_TRUE;
        return CT_SUCCESS;
    }
    if (var_convert(nlsparams, &element, CT_TYPE_INTEGER, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }
    *id = element.v_int;
    return CT_SUCCESS;
}

status_t udt_nested_table_find_extent(sql_stmt_t *stmt, mtrl_ntbl_head_t *collection_head, uint32 index, mtrl_rowid_t *id)
{
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    vm_ntbl_ext_t *extent = collection_head->ntbl;
    mtrl_rowid_t curr_id;
    mtrl_rowid_t next_id = g_invalid_entry;
    mtrl_rowid_t prev_id = g_invalid_entry;

    CM_ASSERT(index > 1);

    curr_id = extent->next;
    for (uint32 i = 1; i < index; i++) {
        CM_ASSERT(IS_VALID_MTRL_ROWID(curr_id));

        OPEN_VM_PTR(&curr_id, vm_context);
        extent = (vm_ntbl_ext_t *)d_ptr;
        next_id = extent->next;
        CLOSE_VM_PTR(&curr_id, vm_context);
        prev_id = curr_id;
        curr_id = next_id;
    }

    *id = prev_id;
    return CT_SUCCESS;
}

// get nested table extent id and extent by index
static status_t udt_ntbl_ext_byid(sql_stmt_t *stmt, mtrl_ntbl_head_t *collection_head, uint32 id, mtrl_rowid_t *ext_id,
    vm_ntbl_ext_t **ext)
{
    if (id < VM_NTBL_EXT_SIZE) {
        *ext = collection_head->ntbl;
        return CT_SUCCESS;
    }

    if (udt_nested_table_find_extent(stmt, collection_head, UDT_NTBL_EXTNUM(id), ext_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return vmctx_open_row_id(GET_VM_CTX(stmt), ext_id, (char **)ext);
}

static status_t udt_nested_table_exists(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    int32 pos;
    bool32 is_null = CT_FALSE;
    output->type = CT_TYPE_BOOLEAN;

    CT_RETURN_IFERR(udt_nested_table_exists_args(stmt, args, &pos, &is_null));
    if (is_null) {
        output->is_null = CT_TRUE;
        output->v_bool = CT_FALSE;
        return CT_SUCCESS;
    }
    if (pos < 1) {
        output->is_null = CT_FALSE;
        output->v_bool = CT_FALSE;
        return CT_SUCCESS;
    }
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    mtrl_ntbl_head_t *collection_head = NULL;
    mtrl_rowid_t extent_id = g_invalid_entry;
    vm_ntbl_ext_t *extent = NULL;

    OPEN_VM_PTR(&(var->v_collection.value), vm_context);
    collection_head = (mtrl_ntbl_head_t *)d_ptr;
    if ((uint32)pos > collection_head->ctrl.hwm) {
        CLOSE_VM_PTR_EX(&var->v_collection.value, vm_context);
        output->is_null = CT_FALSE;
        output->v_bool = CT_FALSE;
        return CT_SUCCESS;
    }

    uint32 id = pos - 1;
    if (udt_ntbl_ext_byid(stmt, collection_head, id, &extent_id, &extent) != CT_SUCCESS) {
        CLOSE_VM_PTR_EX(&var->v_collection.value, vm_context);
        return CT_ERROR;
    }

    output->is_null = CT_FALSE;
    output->v_bool = VM_NTBL_MAP_EXISTS(id, extent->map);

    if (IS_VALID_MTRL_ROWID(extent_id)) {
        vmctx_close_row_id(GET_VM_CTX(stmt), &extent_id);
    }
    CLOSE_VM_PTR(&var->v_collection.value, vm_context);
    return CT_SUCCESS;
}

status_t udt_nested_table_extend_elements(sql_stmt_t *stmt, var_collection_t *v_coll, mtrl_ntbl_head_t *collection_head,
    uint32 num, variant_t *copy)
{
    plv_collection_t *coll_meta = (plv_collection_t *)v_coll->coll_meta;
    bool8 flag = CT_FALSE;
    if (copy->is_null) {
        flag = CT_TRUE;
    }

    for (uint32 i = 0; i < num; i++) {
        if (flag && ELMT_IS_HASH_TABLE(coll_meta)) {
            MAKE_COLL_VAR(copy, coll_meta->elmt_type, g_invalid_entry);
            CT_RETURN_IFERR(udt_hash_table_init_var(stmt, copy));
            copy->v_collection.is_constructed = CT_TRUE;
        }

        CT_RETURN_IFERR(udt_nested_table_add_var(stmt, (plv_collection_t *)v_coll->coll_meta, collection_head, copy));
    }
    return CT_SUCCESS;
}

status_t udt_nested_table_extend_args(sql_stmt_t *stmt, expr_tree_t *args, int32 *num, uint32 *id, bool32 *is_null)
{
    if (args == NULL) {
        *num = 1;
        *id = CT_INVALID_ID32;
        return CT_SUCCESS;
    }

    bool32 pending = CT_FALSE;
    variant_t *element_vars = NULL;
    const nlsparams_t *nlsparams = SESSION_NLS(stmt);

    uint32 args_count = sql_expr_list_len(args);

    CTSQL_SAVE_STACK(stmt);
    CT_RETURN_IFERR(sql_push(stmt, args_count * sizeof(variant_t), (void **)&element_vars));
    if (sql_exec_expr_list(stmt, args, args_count, element_vars, &pending, NULL) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    if (element_vars[0].is_null) {
        CTSQL_RESTORE_STACK(stmt);
        *is_null = CT_TRUE;
        return CT_SUCCESS;
    }
    if (var_convert(nlsparams, &element_vars[0], CT_TYPE_INTEGER, NULL) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    *num = element_vars[0].v_int;
    if (args_count == UDT_NTBL_MAX_ARGS) {
        if (element_vars[1].is_null) {
            *is_null = CT_TRUE;
            CTSQL_RESTORE_STACK(stmt);
            return CT_SUCCESS;
        }
        if (var_convert(nlsparams, &element_vars[1], CT_TYPE_INTEGER, NULL) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
        if (element_vars[1].v_int == -1) {
            CT_SRC_THROW_ERROR(args->loc, ERR_SUBSCRIPT_BEYOND_COUNT);
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
        *id = element_vars[1].v_uint32 - 1;
    } else {
        *id = CT_INVALID_ID32;
    }

    CTSQL_RESTORE_STACK(stmt);
    return CT_SUCCESS;
}

status_t udt_nested_table_intr_extend_num(sql_stmt_t *stmt, variant_t *var, void *arg)
{
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    mtrl_ntbl_head_t *collection_head = NULL;
    status_t status;
    variant_t copy;
    uint32 num = *(uint32 *)arg;
    if (num == 0) {
        return CT_ERROR;
    }
    OPEN_VM_PTR(&(var->v_collection.value), vm_context);
    collection_head = (mtrl_ntbl_head_t *)d_ptr;
    copy.ctrl = 0;
    copy.is_null = CT_TRUE;

    status = udt_nested_table_extend_elements(stmt, &var->v_collection, collection_head, num, &copy);
    CLOSE_VM_PTR(&var->v_collection.value, vm_context);
    return status;
}

status_t udt_nested_table_address_read_element(sql_stmt_t *stmt, plv_collection_t *coll_meta, mtrl_rowid_t row_id,
    variant_t *output)
{
    switch (coll_meta->attr_type) {
        case UDT_SCALAR:
            output->type = (int16)coll_meta->type_mode.datatype;
            CT_RETURN_IFERR(udt_read_scalar_value(stmt, &row_id, output));
            break;
        case UDT_COLLECTION:
            output->type = CT_TYPE_COLLECTION;
            output->v_collection.type = coll_meta->elmt_type->typdef.collection.type;
            output->v_collection.coll_meta = &coll_meta->elmt_type->typdef.collection;
            output->v_collection.value = row_id;
            output->v_collection.is_constructed = CT_FALSE;
            break;
        case UDT_RECORD:
            output->type = CT_TYPE_RECORD;
            output->v_record.count = coll_meta->elmt_type->typdef.record.count;
            output->v_record.record_meta = &coll_meta->elmt_type->typdef.record;
            output->v_record.value = row_id;
            output->v_record.is_constructed = CT_FALSE;
            break;
        case UDT_OBJECT:
            output->type = CT_TYPE_OBJECT;
            output->v_object.count = coll_meta->elmt_type->typdef.object.count;
            output->v_object.object_meta = &coll_meta->elmt_type->typdef.object;
            output->v_object.value = row_id;
            output->v_object.is_constructed = CT_FALSE;
            break;
        default:
            CT_THROW_ERROR(ERR_PL_WRONG_TYPE_VALUE, "element type", coll_meta->attr_type);
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t udt_nested_table_address_read(sql_stmt_t *stmt, variant_t *var, uint32 index, variant_t *output)
{
    var_collection_t *v_coll = &var->v_collection;
    plv_collection_t *coll_meta = (plv_collection_t *)v_coll->coll_meta;
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    mtrl_ntbl_head_t *collection_head = NULL;
    mtrl_rowid_t extent_id = g_invalid_entry;
    mtrl_rowid_t row_id = g_invalid_entry;
    vm_ntbl_ext_t *extent = NULL;
    status_t status;

    OPEN_VM_PTR(&v_coll->value, vm_context);
    collection_head = (mtrl_ntbl_head_t *)d_ptr;
    if (index >= collection_head->ctrl.hwm) {
        CT_THROW_ERROR(ERR_SUBSCRIPT_BEYOND_COUNT);
        CLOSE_VM_PTR_EX(&v_coll->value, vm_context);
        return CT_ERROR;
    }

    if (index < VM_NTBL_EXT_SIZE) {
        row_id = collection_head->ntbl->slot[index];
        extent = collection_head->ntbl;
    } else {
        if (udt_nested_table_find_slot(stmt, collection_head, index, &extent_id, &row_id, CT_FALSE) != CT_SUCCESS) {
            CLOSE_VM_PTR_EX(&v_coll->value, vm_context);
            return CT_ERROR;
        }
        if (vmctx_open_row_id(vm_context, &extent_id, (char **)&extent) != CT_SUCCESS) {
            CLOSE_VM_PTR_EX(&v_coll->value, vm_context);
            return CT_ERROR;
        }
    }

    if (!VM_NTBL_MAP_EXISTS(index, extent->map)) {
        CT_THROW_ERROR(ERR_PL_NO_DATA_FOUND);
        if (IS_VALID_MTRL_ROWID(extent_id)) {
            vmctx_close_row_id(vm_context, &extent_id);
        }
        CLOSE_VM_PTR_EX(&v_coll->value, vm_context);
        return CT_ERROR;
    }

    if (IS_VALID_MTRL_ROWID(extent_id)) {
        vmctx_close_row_id(vm_context, &extent_id);
    }

    if (IS_INVALID_MTRL_ROWID(row_id)) {
        CLOSE_VM_PTR_EX(&v_coll->value, vm_context);
        output->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    output->is_null = CT_FALSE;
    status = udt_nested_table_address_read_element(stmt, coll_meta, row_id, output);
    CLOSE_VM_PTR(&v_coll->value, vm_context);
    return status;
}

static status_t udt_nested_table_extend(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    mtrl_ntbl_head_t *collection_head = NULL;
    status_t status;
    int32 num;
    uint32 id;
    variant_t copy;
    bool32 is_null = CT_FALSE;

    CT_RETURN_IFERR(udt_nested_table_extend_args(stmt, args, &num, &id, &is_null));
    if (is_null || num < 1) {
        return CT_SUCCESS;
    }

    if (id == CT_INVALID_ID32) {
        status = udt_nested_table_intr_extend_num(stmt, var, (void *)&num);
    } else {
        OPEN_VM_PTR(&(var->v_collection.value), vm_context);
        collection_head = (mtrl_ntbl_head_t *)d_ptr;
        if (udt_nested_table_address_read(stmt, var, id, &copy) != CT_SUCCESS) {
            CLOSE_VM_PTR_EX(&var->v_collection.value, vm_context);
            return CT_ERROR;
        }
        status = udt_nested_table_extend_elements(stmt, &var->v_collection, collection_head, num, &copy);
        CLOSE_VM_PTR(&var->v_collection.value, vm_context);
    }
    return status;
}

// get nested table extent id and extent by index, add history extent_id info, avoid open same extent more than once
static status_t udt_ntbl_ext_byhisid(sql_stmt_t *stmt, mtrl_ntbl_head_t *collection_head, uint32 id, uint32 hisid,
    mtrl_rowid_t *ext_id, vm_ntbl_ext_t **ext)
{
    if (id < VM_NTBL_EXT_SIZE) {
        if (IS_VALID_MTRL_ROWID(*ext_id)) {
            vmctx_close_row_id(GET_VM_CTX(stmt), ext_id);
            *ext_id = g_invalid_entry;
        }
        *ext = collection_head->ntbl;
        return CT_SUCCESS;
    }

    if (IS_INVALID_MTRL_ROWID(*ext_id)) {
        // open first time
        if (udt_nested_table_find_extent(stmt, collection_head, UDT_NTBL_EXTNUM(id), ext_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
        return vmctx_open_row_id(GET_VM_CTX(stmt), ext_id, (char **)ext);
    }

    uint32 o_ext_num = UDT_NTBL_EXTNUM(hisid);
    uint32 n_ext_num = UDT_NTBL_EXTNUM(id);
    if (o_ext_num != n_ext_num) {
        // now close old extent, then fetch another extent
        vmctx_close_row_id(GET_VM_CTX(stmt), ext_id);

        if (udt_nested_table_find_extent(stmt, collection_head, n_ext_num, ext_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
        CT_RETURN_IFERR(vmctx_open_row_id(GET_VM_CTX(stmt), ext_id, (char **)ext));
    }

    return CT_SUCCESS;
}

static status_t udt_nested_table_first(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    mtrl_ntbl_head_t *collection_head = NULL;
    mtrl_rowid_t extent_id = g_invalid_entry;
    vm_ntbl_ext_t *extent = NULL;
    uint32 hisid = CT_INVALID_ID32;

    output->type = CT_TYPE_INTEGER;
    output->is_null = CT_TRUE;
    OPEN_VM_PTR(&(var->v_collection.value), vm_context);
    collection_head = (mtrl_ntbl_head_t *)d_ptr;
    if (collection_head->ctrl.hwm == 0) {
        CLOSE_VM_PTR_EX(&var->v_collection.value, vm_context);
        return CT_SUCCESS;
    }

    for (uint32 id = 0; id < collection_head->ctrl.hwm; id++) {
        if (udt_ntbl_ext_byhisid(stmt, collection_head, id, hisid, &extent_id, &extent) != CT_SUCCESS) {
            CLOSE_VM_PTR_EX(&var->v_collection.value, vm_context);
            return CT_ERROR;
        }

        if (VM_NTBL_MAP_EXISTS(id, extent->map)) {
            output->is_null = CT_FALSE;
            output->v_uint32 = id + 1;
            break;
        }
        hisid = id;
    }

    if (IS_VALID_MTRL_ROWID(extent_id)) {
        vmctx_close_row_id(GET_VM_CTX(stmt), &extent_id);
    }
    CLOSE_VM_PTR(&var->v_collection.value, vm_context);
    return CT_SUCCESS;
}

static status_t udt_nested_table_last(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    mtrl_ntbl_head_t *collection_head = NULL;
    mtrl_rowid_t extent_id = g_invalid_entry;
    vm_ntbl_ext_t *extent = NULL;
    uint32 hisid = CT_INVALID_ID32;

    output->type = CT_TYPE_INTEGER;
    output->is_null = CT_TRUE;
    OPEN_VM_PTR(&(var->v_collection.value), vm_context);
    collection_head = (mtrl_ntbl_head_t *)d_ptr;
    if (collection_head->ctrl.hwm == 0) {
        CLOSE_VM_PTR_EX(&var->v_collection.value, vm_context);
        return CT_SUCCESS;
    }

    for (uint32 id = collection_head->ctrl.hwm - 1; id >= 0; id--) {
        if (udt_ntbl_ext_byhisid(stmt, collection_head, id, hisid, &extent_id, &extent) != CT_SUCCESS) {
            CLOSE_VM_PTR_EX(&var->v_collection.value, vm_context);
            return CT_ERROR;
        }

        if (VM_NTBL_MAP_EXISTS(id, extent->map)) {
            output->is_null = CT_FALSE;
            output->v_uint32 = id + 1;
            break;
        }
        hisid = id;
    }

    if (IS_VALID_MTRL_ROWID(extent_id)) {
        vmctx_close_row_id(GET_VM_CTX(stmt), &extent_id);
    }
    CLOSE_VM_PTR(&var->v_collection.value, vm_context);
    return CT_SUCCESS;
}

status_t udt_nested_table_move_args(sql_stmt_t *stmt, expr_tree_t *args, int32 *id, bool32 prior, bool32 *is_null)
{
    CM_ASSERT(args != NULL);

    bool32 pending = CT_FALSE;
    variant_t element;
    const nlsparams_t *nlsparams = SESSION_NLS(stmt);

    uint32 args_count = sql_expr_list_len(args);
    if (sql_exec_expr_list(stmt, args, args_count, &element, &pending, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (element.is_null) {
        *is_null = CT_TRUE;
        return CT_SUCCESS;
    }
    if (var_convert(nlsparams, &element, CT_TYPE_INTEGER, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }
    *id = element.v_int;
    return CT_SUCCESS;
}

static status_t udt_nested_table_next(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    int32 pos;
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    mtrl_ntbl_head_t *collection_head = NULL;
    mtrl_rowid_t extent_id = g_invalid_entry;
    vm_ntbl_ext_t *extent = NULL;
    uint32 hisid = CT_INVALID_ID32;
    bool32 is_null = CT_FALSE;
    CT_RETURN_IFERR(udt_nested_table_move_args(stmt, args, &pos, CT_FALSE, &is_null));
    if (is_null) {
        output->is_null = CT_TRUE;
        return CT_SUCCESS;
    }
    if (pos <= 0) {
        pos = 0;
    }

    OPEN_VM_PTR(&(var->v_collection.value), vm_context);
    collection_head = (mtrl_ntbl_head_t *)d_ptr;
    if (collection_head->ctrl.hwm == 0) {
        CLOSE_VM_PTR_EX(&var->v_collection.value, vm_context);
        output->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    output->type = CT_TYPE_INTEGER;
    output->is_null = CT_TRUE;

    if ((int64)pos >= collection_head->ctrl.hwm) {
        CLOSE_VM_PTR_EX(&var->v_collection.value, vm_context);
        return CT_SUCCESS;
    }

    for (uint32 id = pos; id < collection_head->ctrl.hwm; id++) {
        if (udt_ntbl_ext_byhisid(stmt, collection_head, id, hisid, &extent_id, &extent) != CT_SUCCESS) {
            CLOSE_VM_PTR_EX(&var->v_collection.value, vm_context);
            return CT_ERROR;
        }

        if (VM_NTBL_MAP_EXISTS(id, extent->map)) {
            output->type = CT_TYPE_INTEGER;
            output->is_null = CT_FALSE;
            output->v_uint32 = id + 1;
            break;
        }
        hisid = id;
    }

    if (IS_VALID_MTRL_ROWID(extent_id)) {
        vmctx_close_row_id(GET_VM_CTX(stmt), &extent_id);
    }
    CLOSE_VM_PTR(&var->v_collection.value, vm_context);
    return CT_SUCCESS;
}

static status_t udt_nested_table_limit(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    output->type = CT_TYPE_INTEGER;
    output->is_null = CT_TRUE;

    return CT_SUCCESS;
}

static status_t udt_nested_table_prior(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    int32 pos;
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    mtrl_ntbl_head_t *collection_head = NULL;
    mtrl_rowid_t extent_id = g_invalid_entry;
    vm_ntbl_ext_t *extent = NULL;
    uint32 hisid = CT_INVALID_ID32;
    bool32 is_null = CT_FALSE;
    CT_RETURN_IFERR(udt_nested_table_move_args(stmt, args, &pos, CT_TRUE, &is_null));

    output->type = CT_TYPE_INTEGER;
    output->is_null = CT_TRUE;
    if (is_null || pos <= 1) {
        return CT_SUCCESS;
    }

    OPEN_VM_PTR(&(var->v_collection.value), vm_context);
    collection_head = (mtrl_ntbl_head_t *)d_ptr;
    if (collection_head->ctrl.hwm == 0) {
        CLOSE_VM_PTR_EX(&var->v_collection.value, vm_context);
        return CT_SUCCESS;
    }

    if ((uint32)pos > collection_head->ctrl.hwm) {
        pos = collection_head->ctrl.hwm + 1;
    }

    pos--;

    for (uint32 id = pos - 1; id >= 0; id--) {
        if (udt_ntbl_ext_byhisid(stmt, collection_head, id, hisid, &extent_id, &extent) != CT_SUCCESS) {
            CLOSE_VM_PTR_EX(&var->v_collection.value, vm_context);
            return CT_ERROR;
        }

        if (VM_NTBL_MAP_EXISTS(id, extent->map)) {
            output->is_null = CT_FALSE;
            output->v_uint32 = id + 1;
            break;
        }
        hisid = id;
    }

    if (IS_VALID_MTRL_ROWID(extent_id)) {
        vmctx_close_row_id(GET_VM_CTX(stmt), &extent_id);
    }

    CLOSE_VM_PTR(&var->v_collection.value, vm_context);
    return CT_SUCCESS;
}

status_t udt_nested_table_trim_elements(sql_stmt_t *stmt, var_collection_t *v_coll, mtrl_ntbl_head_t *collection_head,
    uint32 num)
{
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    vm_ntbl_ext_t *extent = NULL;
    mtrl_rowid_t extent_id = g_invalid_entry;
    mtrl_rowid_t entry = g_invalid_entry;

    uint32 index = collection_head->ctrl.hwm - 1;
    uint32 count = 0;
    uint32 offset;

    do {
        if (index < VM_NTBL_EXT_SIZE) {
            entry = collection_head->ntbl->slot[index];
        } else {
            CT_RETURN_IFERR(udt_nested_table_find_slot(stmt, collection_head, index, &extent_id, &entry, CT_TRUE));
        }

        CT_RETURN_IFERR(udt_nested_table_delete_element(stmt, v_coll->coll_meta, &entry));

        if (index < VM_NTBL_EXT_SIZE) {
            udt_nested_table_free_slot(collection_head->ntbl, collection_head, index);
        } else {
            OPEN_VM_PTR(&extent_id, vm_context);
            extent = (vm_ntbl_ext_t *)d_ptr;
            offset = index % VM_NTBL_EXT_SIZE;
            udt_nested_table_free_slot(extent, collection_head, offset);
            CLOSE_VM_PTR(&extent_id, vm_context);
        }
        collection_head->ctrl.hwm--;
        index--;
        count++;
    } while (count < num);
    return CT_SUCCESS;
}

status_t udt_nested_table_intr_trim(sql_stmt_t *stmt, variant_t *var, void *arg)
{
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    mtrl_ntbl_head_t *collection_head = NULL;
    mtrl_rowid_t curr, next;
    vm_ntbl_ext_t *extent = NULL;
    status_t status;
    OPEN_VM_PTR(&(var->v_collection.value), vm_context);
    collection_head = (mtrl_ntbl_head_t *)d_ptr;
    if (collection_head->ctrl.hwm == 0) {
        CLOSE_VM_PTR_EX(&var->v_collection.value, vm_context);
        return CT_SUCCESS;
    }
    curr = collection_head->ntbl->next;
    status = udt_nested_table_trim_elements(stmt, &var->v_collection, collection_head, collection_head->ctrl.hwm);
    collection_head->ntbl->next = g_invalid_entry;
    CLOSE_VM_PTR(&var->v_collection.value, vm_context);
    CT_RETURN_IFERR(status);
    /* traverse to delete all extent, except first extent */
    while (IS_VALID_MTRL_ROWID(curr)) {
        OPEN_VM_PTR(&curr, vm_context);
        extent = (vm_ntbl_ext_t *)d_ptr;
        next = extent->next;
        CLOSE_VM_PTR(&curr, vm_context);
        status = vmctx_free(GET_VM_CTX(stmt), &curr);
        CT_RETURN_IFERR(status);
        curr = next;
    }

    return status;
}

status_t udt_nested_table_trim_args(sql_stmt_t *stmt, expr_tree_t *args, uint32 *num, bool32 *is_null)
{
    if (args == NULL) {
        *num = 1;
        return CT_SUCCESS;
    }

    bool32 pending = CT_FALSE;
    variant_t element;
    const nlsparams_t *nlsparams = SESSION_NLS(stmt);

    uint32 args_count = sql_expr_list_len(args);
    CM_ASSERT(args_count < UDT_NTBL_MAX_ARGS);

    if (sql_exec_expr_list(stmt, args, args_count, &element, &pending, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (element.is_null) {
        *is_null = CT_TRUE;
        return CT_SUCCESS;
    }
    if (var_convert(nlsparams, &element, CT_TYPE_UINT32, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }
    *num = element.v_uint32;
    return CT_SUCCESS;
}

static status_t udt_nested_table_free_extent(sql_stmt_t *stmt, mtrl_rowid_t temp_curr)
{
    mtrl_rowid_t curr = temp_curr;
    mtrl_rowid_t next;
    vm_ntbl_ext_t *extent = NULL;
    pvm_context_t vm_context = GET_VM_CTX(stmt);

    while (IS_VALID_MTRL_ROWID(curr)) {
        OPEN_VM_PTR(&curr, vm_context);
        extent = (vm_ntbl_ext_t *)d_ptr;
        next = extent->next;
        CLOSE_VM_PTR(&curr, vm_context);
        CT_RETURN_IFERR(vmctx_free(vm_context, &curr));
        curr = next;
    }
    return CT_SUCCESS;
}

static status_t udt_nested_table_trim(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    mtrl_ntbl_head_t *collection_head = NULL;
    status_t status;
    uint32 num;
    bool32 is_null = CT_FALSE;
    mtrl_rowid_t curr = g_invalid_entry;
    mtrl_rowid_t extent_id = g_invalid_entry;
    mtrl_rowid_t entry = g_invalid_entry;
    vm_ntbl_ext_t *extent = NULL;

    CT_RETURN_IFERR(udt_nested_table_trim_args(stmt, args, &num, &is_null));
    if (is_null || num < 1) {
        return CT_SUCCESS;
    }

    OPEN_VM_PTR(&(var->v_collection.value), vm_context);
    collection_head = (mtrl_ntbl_head_t *)d_ptr;
    if (collection_head->ctrl.hwm == 0 || num > collection_head->ctrl.hwm) {
        CLOSE_VM_PTR_EX(&var->v_collection.value, vm_context);
        CT_THROW_ERROR(ERR_SUBSCRIPT_BEYOND_COUNT);
        return CT_ERROR;
    }

    status = udt_nested_table_trim_elements(stmt, &var->v_collection, collection_head, (uint32)num);
    CLOSE_VM_PTR(&var->v_collection.value, vm_context);
    output->is_null = CT_TRUE;
    CT_RETURN_IFERR(status);

    /* traverse to delete all extent, except first extent */
    if (collection_head->ctrl.hwm <= VM_NTBL_EXT_SIZE) {
        curr = collection_head->ntbl->next;
        CT_RETURN_IFERR(udt_nested_table_free_extent(stmt, curr));
        collection_head->ntbl->next = g_invalid_entry;
        collection_head->tail = g_invalid_entry;
    } else {
        CT_RETURN_IFERR(
            udt_nested_table_find_slot(stmt, collection_head, collection_head->ctrl.hwm - 1, &extent_id, &entry, CT_FALSE));
        OPEN_VM_PTR(&extent_id, vm_context);
        extent = (vm_ntbl_ext_t *)d_ptr;
        curr = extent->next;
        if (udt_nested_table_free_extent(stmt, curr) != CT_SUCCESS) {
            CLOSE_VM_PTR_EX(&extent_id, vm_context);
            return CT_ERROR;
        }
        extent->next = g_invalid_entry;
        CLOSE_VM_PTR(&extent_id, vm_context);
        collection_head->tail = extent_id;
    }
    return CT_SUCCESS;
}

static status_t udt_clone_nested_table_elements(sql_stmt_t *stmt, plv_collection_t *coll_meta, mtrl_rowid_t copy_from,
    mtrl_rowid_t *copy_to)
{
    status_t status;
    variant_t var;
    plv_decl_t *ele_meta = NULL;

    if (IS_INVALID_MTRL_ROWID(ROWID_ID2_UINT64(copy_from))) {
        *copy_to = g_invalid_entry;
        return CT_SUCCESS;
    }

    switch (coll_meta->attr_type) {
        case UDT_SCALAR:
            status = udt_clone_scalar(stmt, copy_from, copy_to);
            break;
        case UDT_COLLECTION:
            ele_meta = coll_meta->elmt_type;
            CM_ASSERT(ele_meta->type == PLV_TYPE);
            CM_ASSERT(ele_meta->typdef.type == PLV_COLLECTION);
            MAKE_COLL_VAR(&var, ele_meta, copy_from);
            status = udt_clone_collection(stmt, &var, copy_to);
            break;

        case UDT_RECORD:
            ele_meta = coll_meta->elmt_type;
            CM_ASSERT(ele_meta->type == PLV_TYPE);
            CM_ASSERT(ele_meta->typdef.type == PLV_RECORD);
            MAKE_REC_VAR(&var, ele_meta, copy_from);
            status = udt_record_clone_all(stmt, &var, copy_to);
            break;

        case UDT_OBJECT:
            ele_meta = coll_meta->elmt_type;
            CM_ASSERT(ele_meta->type == PLV_TYPE);
            CM_ASSERT(ele_meta->typdef.type == PLV_OBJECT);
            MAKE_OBJ_VAR(&var, ele_meta, copy_from);
            status = udt_object_clone(stmt, &var, copy_to);
            break;
        default:
            CT_THROW_ERROR(ERR_PL_WRONG_TYPE_VALUE, "element type", coll_meta->attr_type);
            return CT_ERROR;
    }
    return status;
}

static status_t udt_clone_nested_table_extents(sql_stmt_t *stmt, plv_collection_t *coll_meta, vm_ntbl_ext_t *src,
    vm_ntbl_ext_t *dst)
{
    MEMS_RETURN_IFERR(
        memcpy_s(dst->map, VM_NTBL_EXT_MAPS * sizeof(uint32), src->map, VM_NTBL_EXT_MAPS * sizeof(uint32)));

    for (uint32 i = 0; i < VM_NTBL_EXT_SIZE; i++) {
        CT_RETURN_IFERR(udt_clone_nested_table_elements(stmt, coll_meta, src->slot[i], &dst->slot[i]));
    }
    dst->next = g_invalid_entry;
    return CT_SUCCESS;
}

static status_t udt_clone_add_extent(sql_stmt_t *stmt, plv_collection_t *coll_meta, mtrl_ntbl_head_t *src_coll_head,
    mtrl_rowid_t *copyto)
{
    vm_ntbl_ext_t *dst_extent = NULL;
    vm_ntbl_ext_t *src_extent = NULL;
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    status_t status;
    mtrl_rowid_t dst_extent_id = g_invalid_entry;
    mtrl_rowid_t src_extent_id = g_invalid_entry;
    mtrl_rowid_t last_extent_id = g_invalid_entry;
    mtrl_ntbl_head_t *dst_coll_head = NULL;
    uint32 src_extent_num = UDT_NTBL_EXTNUM(src_coll_head->ctrl.hwm - 1);
    // deal next extents
    for (uint32 i = 2; i <= src_extent_num; i++) {
        if (sql_push(stmt, sizeof(vm_ntbl_ext_t), (void **)&dst_extent) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (udt_nested_table_find_extent(stmt, src_coll_head, i, &src_extent_id) != CT_SUCCESS) {
            CTSQL_POP(stmt);
            return CT_ERROR;
        }

        // prepare dst extent
        if (vmctx_open_row_id(vm_context, &src_extent_id, (char **)&src_extent) != CT_SUCCESS) {
            CTSQL_POP(stmt);
            return CT_ERROR;
        }
        status = udt_clone_nested_table_extents(stmt, coll_meta, src_extent, dst_extent);
        vmctx_close_row_id(vm_context, &src_extent_id);

        if (status != CT_SUCCESS) {
            CTSQL_POP(stmt);
            return CT_ERROR;
        }

        // insert dst extent
        status = vmctx_insert(GET_VM_CTX(stmt), (const char *)dst_extent, sizeof(vm_ntbl_ext_t), &dst_extent_id);

        CTSQL_POP(stmt);
        CT_RETURN_IFERR(status);

        // modify prev extent next ptr
        OPEN_VM_PTR(copyto, vm_context);
        dst_coll_head = (mtrl_ntbl_head_t *)d_ptr;
        last_extent_id = dst_coll_head->tail;
        dst_coll_head->tail = dst_extent_id;
        if (i == UDT_NTBL_TWO_EXTENT) {
            dst_coll_head->ntbl->next = dst_extent_id;
        } else {
            OPEN_VM_PTR(&last_extent_id, vm_context);
            dst_extent = (vm_ntbl_ext_t *)d_ptr;
            dst_extent->next = dst_extent_id;
            CLOSE_VM_PTR(&last_extent_id, vm_context);
        }
        CLOSE_VM_PTR(copyto, vm_context);
    }
    return CT_SUCCESS;
}

status_t udt_clone_nested_table(sql_stmt_t *stmt, variant_t *var, mtrl_rowid_t *copyto)
{
    errno_t ret;
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    mtrl_ntbl_head_t *dst_coll_head = NULL;
    mtrl_ntbl_head_t *src_coll_head = NULL;
    plv_collection_t *coll_meta = (plv_collection_t *)var->v_collection.coll_meta;
    // deal head
    uint32 head_size = sizeof(mtrl_ntbl_head_t) + sizeof(vm_ntbl_ext_t);
    CT_RETURN_IFERR(sql_push(stmt, head_size, (void **)&dst_coll_head));
    ret = memset_sp(dst_coll_head->ntbl, sizeof(vm_ntbl_ext_t), 0xFF, sizeof(vm_ntbl_ext_t));
    if (ret != EOK) {
        CTSQL_POP(stmt);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }
    if (vmctx_open_row_id(vm_context, &var->v_collection.value, (char **)&src_coll_head) != CT_SUCCESS) {
        CTSQL_POP(stmt);
        return CT_ERROR;
    }
    dst_coll_head->ctrl.datatype = src_coll_head->ctrl.datatype;
    dst_coll_head->ctrl.hwm = src_coll_head->ctrl.hwm;
    dst_coll_head->ctrl.count = src_coll_head->ctrl.count;

    if (udt_clone_nested_table_extents(stmt, coll_meta, &src_coll_head->ntbl[0], &dst_coll_head->ntbl[0]) !=
        CT_SUCCESS) {
        vmctx_close_row_id(vm_context, &var->v_collection.value);
        CTSQL_POP(stmt);
        return CT_ERROR;
    }
    dst_coll_head->ntbl->next = g_invalid_entry;
    if (vmctx_insert(GET_VM_CTX(stmt), (const char *)dst_coll_head, head_size, copyto) != CT_SUCCESS) {
        vmctx_close_row_id(vm_context, &var->v_collection.value);
        CTSQL_POP(stmt);
        return CT_ERROR;
    }
    CTSQL_POP(stmt);

    if (src_coll_head->ctrl.hwm < VM_NTBL_EXT_SIZE) {
        vmctx_close_row_id(vm_context, &var->v_collection.value);
        return CT_SUCCESS;
    }

    if (udt_clone_add_extent(stmt, coll_meta, src_coll_head, copyto) != CT_SUCCESS) {
        vmctx_close_row_id(vm_context, &var->v_collection.value);
        return CT_ERROR;
    }
    vmctx_close_row_id(vm_context, &var->v_collection.value);
    return CT_SUCCESS;
}

static status_t udt_nested_table_make_element(sql_stmt_t *stmt, plv_collection_t *coll_meta, variant_t *var,
    mtrl_rowid_t *row_id)
{
    variant_t left;
    plv_decl_t *type_decl = plm_get_type_decl_by_coll(coll_meta);
    switch (coll_meta->attr_type) {
        case UDT_SCALAR:
            CT_RETURN_IFERR(udt_nested_table_delete_element(stmt, coll_meta, row_id));
            if (var->is_null) {
                return CT_SUCCESS;
            }
            if (var->type >= CT_TYPE_OPERAND_CEIL) {
                CT_THROW_ERROR(ERR_PL_WRONG_ARG_METHOD_INVOKE, T2S(&type_decl->name));
                return CT_ERROR;
            }
            CT_RETURN_IFERR(udt_make_scalar_elemt(stmt, coll_meta->type_mode, var, row_id, NULL));
            break;

        case UDT_COLLECTION:
            MAKE_COLL_VAR(&left, coll_meta->elmt_type, *row_id);
            CT_RETURN_IFERR(udt_coll_assign(stmt, &left, var));
            *row_id = left.v_collection.value;
            break;
        case UDT_RECORD:
            MAKE_REC_VAR(&left, coll_meta->elmt_type, *row_id);
            CT_RETURN_IFERR(udt_record_assign(stmt, &left, var));
            *row_id = left.v_record.value;
            break;
        case UDT_OBJECT:
            MAKE_OBJ_VAR(&left, coll_meta->elmt_type, *row_id);
            CT_RETURN_IFERR(udt_object_assign(stmt, &left, var));
            *row_id = left.v_object.value;
            break;
        default:
            CT_THROW_ERROR(ERR_PL_WRONG_TYPE_VALUE, "element type", coll_meta->attr_type);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t udt_nested_table_extend_extent(sql_stmt_t *stmt, plv_collection_t *coll_meta, mtrl_rowid_t *extent_id)
{
    status_t status;
    vm_ntbl_ext_t *extent = NULL;
    uint32 head_size = sizeof(vm_ntbl_ext_t);
    errno_t err;

    CT_RETURN_IFERR(sql_push(stmt, head_size, (void **)&extent));
    do {
        err = memset_sp(extent, head_size, 0xFF, head_size);
        if (err != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
            status = CT_ERROR;
            break;
        }
        extent->next = g_invalid_entry;
        status = vmctx_insert(GET_VM_CTX(stmt), (const char *)extent, head_size, extent_id);
    } while (0);

    CTSQL_POP(stmt);

    return status;
}

status_t udt_nested_table_write_element(sql_stmt_t *stmt, plv_collection_t *coll_meta, variant_t *right,
    mtrl_rowid_t *row_id)
{
    switch (coll_meta->attr_type) {
        case UDT_SCALAR:
        case UDT_COLLECTION:
        case UDT_RECORD:
        case UDT_OBJECT:
            CT_RETURN_IFERR(udt_nested_table_make_element(stmt, coll_meta, right, row_id));
            break;
        default:
            CT_THROW_ERROR(ERR_PL_WRONG_TYPE_VALUE, "element type", coll_meta->attr_type);
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t udt_nested_table_address_write(sql_stmt_t *stmt, variant_t *var, uint32 index, variant_t *right)
{
    status_t status;
    var_collection_t *v_coll = &var->v_collection;
    plv_collection_t *coll_meta = (plv_collection_t *)v_coll->coll_meta;
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    mtrl_ntbl_head_t *collection_head = NULL;
    mtrl_rowid_t extent_id = g_invalid_entry;
    mtrl_rowid_t *row_id = NULL;
    vm_ntbl_ext_t *extent = NULL;

    OPEN_VM_PTR(&v_coll->value, vm_context);
    collection_head = (mtrl_ntbl_head_t *)d_ptr;
    if (index >= collection_head->ctrl.hwm) {
        CT_THROW_ERROR(ERR_SUBSCRIPT_BEYOND_COUNT);
        CLOSE_VM_PTR_EX(&v_coll->value, vm_context);
        return CT_ERROR;
    }

    if (index < VM_NTBL_EXT_SIZE) {
        row_id = &(collection_head->ntbl->slot[index]);
        extent = collection_head->ntbl;
    } else {
        if (udt_nested_table_find_slot(stmt, collection_head, index, &extent_id, NULL, CT_FALSE) != CT_SUCCESS) {
            CLOSE_VM_PTR_EX(&v_coll->value, vm_context);
            return CT_ERROR;
        }
        if (vmctx_open_row_id(vm_context, &extent_id, (char **)&extent) != CT_SUCCESS) {
            CLOSE_VM_PTR_EX(&v_coll->value, vm_context);
            return CT_ERROR;
        }
        row_id = &(extent->slot[index % VM_NTBL_EXT_SIZE]);
    }

    if (!VM_NTBL_MAP_EXISTS(index, extent->map)) {
        collection_head->ctrl.count++;
    }

    VM_NTBL_MAP_OCCUPY(index, extent->map);

    status = udt_nested_table_write_element(stmt, coll_meta, right, row_id);
    if (IS_VALID_MTRL_ROWID(extent_id)) {
        vmctx_close_row_id(vm_context, &extent_id);
    }

    CLOSE_VM_PTR(&v_coll->value, vm_context);
    return status;
}


status_t udt_nested_table_address(sql_stmt_t *stmt, variant_t *var, variant_t *index, addr_type_t type,
    variant_t *output, variant_t *right)
{
    status_t status;

    if (var_as_uint32(index) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (type == READ_ADDR) {
        status = udt_nested_table_address_read(stmt, var, index->v_uint32 - 1, output);
    } else {
        status = udt_nested_table_address_write(stmt, var, index->v_uint32 - 1, right);
    }

    return status;
}

static status_t udt_nested_table_free(sql_stmt_t *stmt, variant_t *var)
{
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    mtrl_ntbl_head_t *collection_head = NULL;
    mtrl_rowid_t curr;
    status_t status;

    CT_RETURN_IFERR(sql_stack_safe(stmt));
    CT_RETURN_IFERR(udt_nested_table_delete(stmt, var, NULL, NULL));

    OPEN_VM_PTR(&(var->v_collection.value), vm_context);
    collection_head = (mtrl_ntbl_head_t *)d_ptr;
    curr = collection_head->ntbl->next;

    /* traverse to delete all extent, except first extent */
    status = udt_nested_table_free_extent(stmt, curr);
    CLOSE_VM_PTR(&var->v_collection.value, vm_context);
    return status;
}

status_t udt_nested_table_delete_elements(sql_stmt_t *stmt, var_collection_t *v_coll, mtrl_ntbl_head_t *collection_head,
    uint32 start, uint32 end)
{
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    vm_ntbl_ext_t *extent = NULL;
    mtrl_rowid_t extent_id = g_invalid_entry;
    mtrl_rowid_t entry = g_invalid_entry;

    uint32 index = start;
    uint32 offset;

    do {
        if (index < VM_NTBL_EXT_SIZE) {
            entry = collection_head->ntbl->slot[index];
            udt_nested_table_free_slot(collection_head->ntbl, collection_head, index);
        } else {
            CT_RETURN_IFERR(udt_nested_table_find_slot(stmt, collection_head, index, &extent_id, &entry, CT_FALSE));
            OPEN_VM_PTR(&extent_id, vm_context);
            extent = (vm_ntbl_ext_t *)d_ptr;
            offset = index % VM_NTBL_EXT_SIZE;
            udt_nested_table_free_slot(extent, collection_head, offset);
            CLOSE_VM_PTR(&extent_id, vm_context);
        }

        if (IS_INVALID_MTRL_ROWID(entry)) {
            index++;
            continue;
        }

        CT_RETURN_IFERR(udt_nested_table_delete_element(stmt, v_coll->coll_meta, &entry));

        index++;
    } while (index < end);
    return CT_SUCCESS;
}

status_t udt_nested_table_delete_args(sql_stmt_t *stmt, expr_tree_t *args, int32 *start, int32 *end, bool32 *is_null)
{
    bool32 pending = CT_FALSE;
    variant_t *element_vars = NULL;
    const nlsparams_t *nlsparams = SESSION_NLS(stmt);

    uint32 args_count = sql_expr_list_len(args);

    CTSQL_SAVE_STACK(stmt);
    CT_RETURN_IFERR(sql_push(stmt, args_count * sizeof(variant_t), (void **)&element_vars));
    if (sql_exec_expr_list(stmt, args, args_count, element_vars, &pending, NULL) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    if (element_vars[0].is_null) {
        *is_null = CT_TRUE;
        CTSQL_RESTORE_STACK(stmt);
        return CT_SUCCESS;
    }
    if (var_convert(nlsparams, &element_vars[0], CT_TYPE_INTEGER, NULL) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    *start = element_vars[0].v_int;
    if (args_count == UDT_NTBL_MAX_ARGS) {
        if (element_vars[1].is_null) {
            *is_null = CT_TRUE;
            CTSQL_RESTORE_STACK(stmt);
            return CT_SUCCESS;
        }
        if (var_convert(nlsparams, &element_vars[1], CT_TYPE_INTEGER, NULL) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
        *end = element_vars[1].v_int;
    } else {
        *end = *start;
    }

    CTSQL_RESTORE_STACK(stmt);
    return CT_SUCCESS;
}

static status_t udt_nested_table_delete(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    mtrl_ntbl_head_t *collection_head = NULL;
    status_t status;
    int32 start, end;
    bool32 is_null = CT_FALSE;

    if (args != NULL) {
        CT_RETURN_IFERR(udt_nested_table_delete_args(stmt, args, &start, &end, &is_null));
        if (is_null || start > end || end < 1) {
            return CT_SUCCESS;
        }

        if (start <= 0) {
            start = 1;
        }
    }

    OPEN_VM_PTR(&(var->v_collection.value), vm_context);
    collection_head = (mtrl_ntbl_head_t *)d_ptr;

    if (collection_head->ctrl.count == 0) {
        CLOSE_VM_PTR_EX(&var->v_collection.value, vm_context);
        return CT_SUCCESS;
    }
    if (args == NULL) {
        // delete all
        start = 1;
        end = collection_head->ctrl.hwm;
    }

    status = udt_nested_table_delete_elements(stmt, &var->v_collection, collection_head, (uint32)(start - 1), (uint32)end);
    // when delete method doesn't have argument, collection_head->hwm should be 0.
    if (status == CT_SUCCESS && args == NULL) {
        collection_head->ctrl.hwm = 0;
    }
    CLOSE_VM_PTR(&var->v_collection.value, vm_context);
    return status;
}

static status_t udt_nested_table_init_slot(sql_stmt_t *stmt, plv_collection_t *coll_meta, uint32 args_count,
    variant_t *output)
{
    status_t status;
    mtrl_ntbl_head_t *collection_head = NULL;
    uint32 head_size = sizeof(mtrl_ntbl_head_t) + sizeof(vm_ntbl_ext_t);
    errno_t err;

    CT_RETURN_IFERR(sql_push(stmt, head_size, (void **)&collection_head));
    output->is_null = CT_FALSE;
    output->type = (int16)CT_TYPE_COLLECTION;
    output->v_collection.coll_meta = coll_meta;
    output->v_collection.type = (uint8)UDT_NESTED_TABLE;

    collection_head->ctrl.datatype = GET_COLLECTION_ELEMENT_TYPE(coll_meta);
    collection_head->ctrl.hwm = 0;
    collection_head->ctrl.count = 0;
    collection_head->tail = g_invalid_entry;

    err = memset_sp(collection_head->ntbl, sizeof(vm_ntbl_ext_t), 0xFF, sizeof(vm_ntbl_ext_t));
    if (err != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        CTSQL_POP(stmt);
        return CT_ERROR;
    }
    status = vmctx_insert(GET_VM_CTX(stmt), (const char *)collection_head, head_size, &output->v_collection.value);
    if (status != CT_SUCCESS) {
        CTSQL_POP(stmt);
        return CT_ERROR;
    }
    CTSQL_POP(stmt);
    return CT_SUCCESS;
}

static status_t udt_nested_table_add_var(sql_stmt_t *stmt, plv_collection_t *coll_meta, mtrl_ntbl_head_t *collection_head,
    variant_t *variant)
{
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    vm_ntbl_ext_t *extent = collection_head->ntbl;
    mtrl_rowid_t n_row_id = g_invalid_entry;

    uint32 n_row_index = collection_head->ctrl.hwm;
    uint32 n_ext_num = UDT_NTBL_EXTNUM(collection_head->ctrl.hwm);
    collection_head->ctrl.hwm++;
    collection_head->ctrl.count++;

    if (coll_meta->attr_type == UDT_RECORD) {
        CT_RETURN_IFERR(udt_record_alloc_mtrl_head(stmt, UDT_GET_TYPE_DEF_RECORD(coll_meta->elmt_type), &n_row_id));
    }

    if (udt_nested_table_make_element(stmt, coll_meta, variant, &n_row_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (n_row_index < VM_NTBL_EXT_SIZE) {
        extent->slot[n_row_index] = n_row_id;
        VM_NTBL_MAP_OCCUPY(n_row_index, extent->map);
        return CT_SUCCESS;
    }

    mtrl_rowid_t n_ext_id = g_invalid_entry;
    uint32 o_ext_num = UDT_NTBL_EXTNUM(n_row_index - 1);
    if (n_ext_num != o_ext_num) {
        // time to extend a extent
        CT_RETURN_IFERR(udt_nested_table_extend_extent(stmt, coll_meta, &n_ext_id));

        if (n_ext_num == UDT_NTBL_TWO_EXTENT) {
            collection_head->ntbl[0].next = n_ext_id;
        } else {
            OPEN_VM_PTR(&collection_head->tail, vm_context);
            extent = (vm_ntbl_ext_t *)d_ptr;
            extent->next = n_ext_id;
            CLOSE_VM_PTR(&collection_head->tail, vm_context);
        }
        collection_head->tail = n_ext_id;
    }

    OPEN_VM_PTR(&collection_head->tail, vm_context);
    extent = (vm_ntbl_ext_t *)d_ptr;
    extent->slot[n_row_index % VM_NTBL_EXT_SIZE] = n_row_id;
    VM_NTBL_MAP_OCCUPY(n_row_index, extent->map);
    CLOSE_VM_PTR(&collection_head->tail, vm_context);
    return CT_SUCCESS;
}

static status_t udt_nested_table_constructor(sql_stmt_t *stmt, udt_constructor_t *v_construct, expr_tree_t *args,
    variant_t *output)
{
    status_t status;
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    bool32 pending = CT_FALSE;
    uint32 args_count;
    variant_t *element_vars = NULL;
    plv_collection_t *coll_meta = (plv_collection_t *)v_construct->meta;
    mtrl_ntbl_head_t *collection_head = NULL;
    args_count = ((args == NULL) ? 0 : sql_expr_list_len(args));
    CT_RETURN_IFERR(udt_nested_table_init_slot(stmt, coll_meta, args_count, output));
    if (args_count == 0) {
        return CT_SUCCESS;
    }

    CTSQL_SAVE_STACK(stmt);
    CT_RETURN_IFERR(sql_push(stmt, args_count * sizeof(variant_t), (void **)&element_vars));
    if (sql_exec_expr_list(stmt, args, args_count, element_vars, &pending, NULL) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    if (vmctx_open_row_id(vm_context, &output->v_collection.value, (char **)&collection_head) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    for (uint32 i = 0; i < args_count; i++) {
        switch (coll_meta->attr_type) {
            case UDT_SCALAR:
            case UDT_RECORD:
            case UDT_COLLECTION:
            case UDT_OBJECT:
                status = udt_nested_table_add_var(stmt, coll_meta, collection_head, &element_vars[i]);
                break;
            default:
                vmctx_close_row_id(vm_context, &output->v_collection.value);
                CTSQL_RESTORE_STACK(stmt);
                CT_THROW_ERROR(ERR_PL_WRONG_TYPE_VALUE, "element type", coll_meta->attr_type);
                return CT_ERROR;
        }
    }

    vmctx_close_row_id(vm_context, &output->v_collection.value);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

// CAUTION: if index < VM_NTBL_EXT_SIZE cannot use this interface !
static status_t udt_nested_table_find_slot(sql_stmt_t *stmt, mtrl_ntbl_head_t *collection_head, uint32 index,
    mtrl_rowid_t *rd_ext_id, mtrl_rowid_t *entry, bool32 reverse)
{
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    vm_ntbl_ext_t *ext = NULL;
    mtrl_rowid_t extent_id = *rd_ext_id;
    uint32 o_ext_num;
    uint32 n_ext_num;
    if (reverse) {
        o_ext_num = UDT_NTBL_EXTNUM(index + 1);
    } else {
        o_ext_num = UDT_NTBL_EXTNUM(index - 1);
    }
    n_ext_num = UDT_NTBL_EXTNUM(index);
    bool32 fetch_flag = CT_TRUE;
    if (!IS_INVALID_MTRL_ROWID(extent_id)) {
        fetch_flag = (o_ext_num != n_ext_num);
    }

    if (fetch_flag) {
        CT_RETURN_IFERR(udt_nested_table_find_extent(stmt, collection_head, n_ext_num, &extent_id));
        // fetch more then update it.
        *rd_ext_id = extent_id;
    }

    if (entry != NULL) {
        OPEN_VM_PTR(&extent_id, vm_context);
        ext = (vm_ntbl_ext_t *)d_ptr;
        *entry = ext->slot[index % VM_NTBL_EXT_SIZE];
        CLOSE_VM_PTR(&extent_id, vm_context);
    }
    return CT_SUCCESS;
}

static status_t udt_nested_table_delete_element(sql_stmt_t *stmt, plv_collection_t *coll_meta, mtrl_rowid_t *entry)
{
    variant_t var;

    status_t status;
    plv_decl_t *ele_meta = NULL;
    CT_RETURN_IFERR(sql_stack_safe(stmt));
    if (IS_INVALID_MTRL_ROWID(*entry)) {
        return CT_SUCCESS;
    }

    switch (coll_meta->attr_type) {
        case UDT_SCALAR:
            break;
        case UDT_COLLECTION:
            ele_meta = coll_meta->elmt_type;
            CM_ASSERT(ele_meta->type == PLV_TYPE);
            CM_ASSERT(ele_meta->typdef.type == PLV_COLLECTION);
            MAKE_COLL_VAR(&var, ele_meta, *entry);
            status = udt_delete_collection(stmt, &var);
            CT_RETURN_IFERR(status);
            break;
        case UDT_RECORD:
            ele_meta = coll_meta->elmt_type;
            CM_ASSERT(ele_meta->type == PLV_TYPE);
            CM_ASSERT(ele_meta->typdef.type == PLV_RECORD);
            MAKE_REC_VAR(&var, ele_meta, *entry);
            status = udt_record_delete(stmt, &var, CT_TRUE);
            CT_RETURN_IFERR(status);
            *entry = g_invalid_entry;
            return CT_SUCCESS;
        case UDT_OBJECT:
            ele_meta = coll_meta->elmt_type;
            CM_ASSERT(ele_meta->type == PLV_TYPE);
            CM_ASSERT(ele_meta->typdef.type == PLV_OBJECT);
            MAKE_OBJ_VAR(&var, ele_meta, *entry);
            status = udt_object_delete(stmt, &var);
            CT_RETURN_IFERR(status);
            *entry = g_invalid_entry;
            return CT_SUCCESS;
        default:
            CT_THROW_ERROR(ERR_PL_WRONG_TYPE_VALUE, "element type", coll_meta->attr_type);
            return CT_ERROR;
    }

    status = vmctx_free(GET_VM_CTX(stmt), entry);
    CT_RETURN_IFERR(status);
    *entry = g_invalid_entry;
    return CT_SUCCESS;
}

void udt_reg_nested_table_method(void)
{
    handle_mutiple_ptrs_t mutiple_ptrs;
    mutiple_ptrs.ptr1 = (void *)g_nested_table_methods;
    mutiple_ptrs.ptr2 = (void *)(&g_nested_table_constructor);
    mutiple_ptrs.ptr3 = (void *)udt_nested_table_free;
    mutiple_ptrs.ptr4 = (void *)g_nested_table_intr_method;
    mutiple_ptrs.ptr5 = (void *)udt_clone_nested_table;
    mutiple_ptrs.ptr6 = (void *)udt_nested_table_address;
    udt_reg_coll_method(UDT_NESTED_TABLE, &mutiple_ptrs);
}
