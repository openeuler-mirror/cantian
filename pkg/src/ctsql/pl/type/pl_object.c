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
 * pl_object.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/type/pl_object.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_instance.h"
#include "ctsql_privilege.h"
#include "pl_base.h"
#include "pl_scalar.h"
#include "pl_memory.h"

plv_object_attr_t *udt_object_alloc_attr(void *entity, plv_object_t *obj)
{
    pl_obj_rmap_extent_t *extent = NULL;
    plv_object_attr_t *attr = NULL;
    if (obj->hwm == obj->count) {
        if (obj->hwm >= PL_REC_MAX_FIELD_SIZE) {
            CT_THROW_ERROR(ERR_OUT_OF_INDEX, "object", PL_REC_MAX_FIELD_SIZE);
            return NULL;
        }

        if (pl_alloc_mem(entity, sizeof(pl_obj_rmap_extent_t), (void **)&extent) != CT_SUCCESS) {
            return NULL;
        }
        SET_OBJECT_EXTENT(obj, extent);
        obj->extent_count++;
        obj->hwm += PL_RMAP_EXTENT_SIZE;
    }

    attr = udt_seek_obj_field_byid(obj, obj->count);
    attr->field_id = obj->count;
    obj->count++;
    return attr;
}

status_t udt_object_inherit_super_attr(void *entity, plv_object_t *curr, plv_object_t *super)
{
    plv_object_attr_t *curr_attr = NULL;
    plv_object_attr_t *super_attr = NULL;

    for (uint16 i = 0; i < super->count; i++) {
        super_attr = udt_seek_obj_field_byid(super, i);
        curr_attr = udt_object_alloc_attr(entity, curr);
        if (curr_attr == NULL) {
            CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "var is null");
            return CT_ERROR;
        }
        curr_attr->name = super_attr->name;
        curr_attr->type = super_attr->type;
        curr_attr->scalar_field = super_attr->scalar_field;
    }
    return CT_SUCCESS;
}

status_t udt_object_alloc_mtrl_head(sql_stmt_t *stmt, plv_object_t *obj, variant_t *output)
{
    uint16 head_size;
    status_t status;
    udt_mtrl_object_head_t *object_head = NULL;
    errno_t err;
    mtrl_rowid_t rowid;

    output->type = (int16)CT_TYPE_OBJECT;
    output->v_object.object_meta = (void *)obj;
    output->v_object.count = obj->count;
    output->is_null = CT_FALSE;

    head_size = obj->count * sizeof(udt_mtrl_object_field_t) + sizeof(udt_mtrl_object_head_t);
    CT_RETURN_IFERR(sql_push(stmt, head_size, (void **)&object_head));
    object_head->size = head_size;
    object_head->count = obj->count;
    err = memset_sp(object_head->field, obj->count * sizeof(udt_mtrl_object_field_t), 0xFF,
        object_head->count * sizeof(udt_mtrl_object_field_t));
    if (err != EOK) {
        CTSQL_POP(stmt);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CT_ERROR;
    }

    /* global object field attr can not be local record, so no need to recursively expand */
    status = vmctx_insert(GET_VM_CTX(stmt), (const char *)object_head, head_size, &rowid);
    CTSQL_POP(stmt);
    output->v_object.value = rowid;

    return status;
}

static status_t udt_object_constructor_attr(sql_stmt_t *stmt, plv_object_attr_t *attr, variant_t *right,
    udt_mtrl_object_field_t *field)
{
    variant_t left;
    if (right->is_null) {
        field->rowid = g_invalid_entry;
        return CT_SUCCESS;
    }

    switch (attr->type) {
        case UDT_SCALAR:
            CT_RETURN_IFERR(
                udt_make_scalar_elemt(stmt, attr->scalar_field->type_mode, right, &field->rowid, &field->type));
            break;

        case UDT_COLLECTION:
            MAKE_COLL_VAR(&left, attr->udt_field, field->rowid);
            CT_RETURN_IFERR(udt_coll_assign(stmt, &left, right));
            field->rowid = left.v_collection.value;
            break;

        case UDT_OBJECT:
            MAKE_OBJ_VAR(&left, attr->udt_field, field->rowid);
            CT_RETURN_IFERR(udt_object_assign(stmt, &left, right));
            field->rowid = left.v_record.value;
            break;

        default:
            CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpect attr type");
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t udt_object_constructor(sql_stmt_t *stmt, plv_object_t *object_meta, expr_tree_t *args, variant_t *output)
{
    bool32 pending = CT_FALSE;
    variant_t *field_vars = NULL;
    status_t status = CT_ERROR;
    udt_mtrl_object_head_t *mtrl_head = NULL;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    uint32 len;
    text_t user;
    text_t name;
    dc_user_t *dc_user = NULL;
    pl_entry_t *type_pl_entry = ((pl_entity_t *)object_meta->root)->entry;
    CT_RETURN_IFERR(dc_open_user_by_id(KNL_SESSION(stmt), type_pl_entry->desc.uid, &dc_user));
    cm_str2text(dc_user->desc.name, &user);
    cm_str2text(type_pl_entry->desc.name, &name);
    CT_RETURN_IFERR(sql_check_exec_type_priv(stmt, &user, &name));
    CT_RETURN_IFERR(udt_object_alloc_mtrl_head(stmt, object_meta, output));
    len = ((args == NULL) ? 0 : sql_expr_list_len(args));
    if (len == 0) {
        return CT_SUCCESS;
    }

    OPEN_VM_PTR(&output->v_object.value, vm_ctx);
    CTSQL_SAVE_STACK(stmt);
    mtrl_head = (udt_mtrl_object_head_t *)d_ptr;
    do {
        CT_BREAK_IF_TRUE(len != object_meta->count);
        CT_BREAK_IF_ERROR(sql_push(stmt, len * sizeof(variant_t), (void **)&field_vars));
        CT_BREAK_IF_ERROR(sql_exec_expr_list(stmt, args, len, field_vars, &pending, NULL));
        for (uint16 i = 0; i < len; i++) {
            if (field_vars[i].is_null) {
                continue;
            }
            plv_object_attr_t *attr = udt_seek_obj_field_byid(object_meta, i);
            CT_BREAK_IF_ERROR(udt_object_constructor_attr(stmt, attr, &field_vars[i], &mtrl_head->field[i]));
        }

        status = CT_SUCCESS;
    } while (0);
    CTSQL_RESTORE_STACK(stmt);
    CLOSE_VM_PTR(&output->v_object.value, vm_ctx);
    return status;
}

static status_t udt_object_clone_field(sql_stmt_t *stmt, plv_object_attr_t *attr, mtrl_rowid_t copy_from,
    mtrl_rowid_t *copy_to)
{
    status_t status;
    variant_t var;
    plv_decl_t *ele_meta = NULL;

    if (IS_INVALID_MTRL_ROWID(ROWID_ID2_UINT64(copy_from))) {
        *copy_to = g_invalid_entry;
        return CT_SUCCESS;
    }

    switch (attr->type) {
        case UDT_SCALAR:
            status = udt_clone_scalar(stmt, copy_from, copy_to);
            break;

        case UDT_COLLECTION:
            ele_meta = attr->udt_field;
            CM_ASSERT(ele_meta->type == PLV_TYPE);
            CM_ASSERT(ele_meta->typdef.type == PLV_COLLECTION);
            MAKE_COLL_VAR(&var, ele_meta, copy_from);
            status = udt_clone_collection(stmt, &var, copy_to);
            break;

        case UDT_OBJECT:
            ele_meta = attr->udt_field;
            CM_ASSERT(ele_meta->type == PLV_TYPE);
            CM_ASSERT(ele_meta->typdef.type == PLV_OBJECT);
            MAKE_OBJ_VAR(&var, ele_meta, copy_from);
            status = udt_object_clone(stmt, &var, copy_to);
            break;

        default:
            CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpect attr type");
            return CT_ERROR;
    }

    return status;
}

status_t udt_object_clone(sql_stmt_t *stmt, variant_t *right, mtrl_rowid_t *result)
{
    status_t status;
    plv_object_t *obj = (plv_object_t *)right->v_object.object_meta;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    udt_mtrl_object_head_t *object_head = NULL;
    plv_object_attr_t *attr = NULL;

    OPEN_VM_PTR(&right->v_object.value, vm_ctx);
    status = vmctx_insert(vm_ctx, (const char *)d_ptr, d_chunk->requested_size, result);
    CLOSE_VM_PTR(&right->v_object.value, vm_ctx);
    if (status != CT_SUCCESS) {
        return CT_ERROR;
    }

    OPEN_VM_PTR(result, vm_ctx);
    object_head = (udt_mtrl_object_head_t *)d_ptr;
    for (uint32 i = 0; i < obj->count; i++) {
        attr = udt_seek_obj_field_byid(obj, i);
        status = udt_object_clone_field(stmt, attr, object_head->field[i].rowid, &object_head->field[i].rowid);
        if (status != CT_SUCCESS) {
            CLOSE_VM_PTR_EX(result, vm_ctx);
            return CT_ERROR;
        }
    }
    CLOSE_VM_PTR(result, vm_ctx);
    return status;
}

static status_t udt_object_delete_field(sql_stmt_t *stmt, plv_object_attr_t *attr, mtrl_rowid_t *row_id)
{
    variant_t var;
    plv_decl_t *fld_meta = NULL;

    if (IS_INVALID_MTRL_ROWID(*row_id)) {
        return CT_SUCCESS;
    }

    switch (attr->type) {
        case UDT_SCALAR:
            break;
        case UDT_COLLECTION:
            fld_meta = attr->udt_field;
            CM_ASSERT(fld_meta->type == PLV_TYPE);
            CM_ASSERT(fld_meta->typdef.type == PLV_COLLECTION);
            MAKE_COLL_VAR(&var, fld_meta, *row_id);
            CT_RETURN_IFERR(udt_delete_collection(stmt, &var));
            break;
        case UDT_OBJECT:
            fld_meta = attr->udt_field;
            CM_ASSERT(fld_meta->type == PLV_TYPE);
            CM_ASSERT(fld_meta->typdef.type == PLV_OBJECT);
            MAKE_OBJ_VAR(&var, fld_meta, *row_id);
            CT_RETURN_IFERR(udt_object_delete(stmt, &var));
            *row_id = g_invalid_entry;
            return CT_SUCCESS;
        default:
            CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpect attr type");
            return CT_ERROR;
    }

    CT_RETURN_IFERR(vmctx_free(GET_VM_CTX(stmt), row_id));
    *row_id = g_invalid_entry;

    return CT_SUCCESS;
}

status_t udt_object_delete(sql_stmt_t *stmt, variant_t *var)
{
    CT_RETURN_IFERR(sql_stack_safe(stmt));
    if (IS_INVALID_MTRL_ROWID(var->v_object.value)) {
        return CT_SUCCESS;
    }

    udt_mtrl_object_head_t *mtrl_head = NULL;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    plv_object_attr_t *attr = NULL;
    plv_object_t *obj = (plv_object_t *)var->v_object.object_meta;
    OPEN_VM_PTR(&var->v_object.value, vm_ctx);
    mtrl_head = (udt_mtrl_object_head_t *)d_ptr;
    for (uint16 i = 0; i < obj->count; i++) {
        attr = udt_seek_obj_field_byid(obj, i);
        if (udt_object_delete_field(stmt, attr, &mtrl_head->field[i].rowid) != CT_SUCCESS) {
            CLOSE_VM_PTR_EX(&var->v_object.value, vm_ctx);
            return CT_ERROR;
        }
    }
    CLOSE_VM_PTR(&var->v_object.value, vm_ctx);
    CT_RETURN_IFERR(vmctx_free(GET_VM_CTX(stmt), &var->v_object.value));
    var->v_object.value = g_invalid_entry;
    var->is_null = CT_TRUE;
    return CT_SUCCESS;
}

status_t udt_object_assign(sql_stmt_t *stmt, variant_t *left, variant_t *right)
{
    plv_object_t *obj = (plv_object_t *)left->v_object.object_meta;
    if (right->type == CT_TYPE_OBJECT && UDT_IS_EQUAL_OBJECT_VAR(left, right)) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_stack_safe(stmt));
    CT_RETURN_IFERR(udt_object_delete(stmt, left));
    if (right->is_null) {
        return CT_SUCCESS;
    }

    if (right->type != CT_TYPE_OBJECT) {
        CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "right value need be object");
        return CT_ERROR;
    }

    if ((plv_object_t *)right->v_object.object_meta != obj) {
        CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "left value and right value need be the same object");
        return CT_ERROR;
    }

    left->is_null = right->is_null;
    if (UDT_OBJ_NEED_DEEP_COPY(right)) {
        CT_RETURN_IFERR(udt_object_clone(stmt, right, &left->v_record.value));
    } else {
        left->v_object.value = right->v_object.value;
    }

    return CT_SUCCESS;
}

void udt_release_obj(sql_stmt_t *stmt, variant_t *val)
{
    udt_var_object_t *obj = &val->v_object;
    if (IS_INVALID_MTRL_ROWID(obj->value)) {
        return;
    }

    if (udt_object_delete(stmt, val) != CT_SUCCESS) {
        int32 code;
        const char *message = NULL;
        cm_get_error(&code, &message, NULL);
        CT_LOG_DEBUG_ERR("object type destructor execute error[%d]:%s.", code, message);
    }
}

status_t udt_verify_object_field(sql_verifier_t *verf, plv_object_attr_t *field, expr_tree_t *tree)
{
    switch (field->type) {
        case UDT_SCALAR:
            return udt_verify_scalar(verf, &field->scalar_field->type_mode, tree);
        case UDT_COLLECTION:
            if (!UDT_VERIFY_COLL_ASSIGN(tree->root, UDT_GET_TYPE_DEF_COLLECTION(field->udt_field))) {
                return CT_ERROR;
            }
            return CT_SUCCESS;
        case UDT_OBJECT:
            return udt_verify_object_assign(tree->root, UDT_GET_TYPE_DEF_OBJECT(field->udt_field));
        default:
            CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpect field type");
            return CT_ERROR;
    }
}

status_t udt_verify_object_args(sql_verifier_t *verf, uint32 arg_count, void *meta, expr_tree_t *expr)
{
    plv_object_t *obj = (plv_object_t *)meta;
    if (arg_count >= obj->count) {
        return CT_ERROR;
    }

    plv_object_attr_t *attr = udt_seek_obj_field_byid(obj, arg_count);
    return udt_verify_object_field(verf, attr, expr);
}

status_t udt_verify_object_construct(sql_verifier_t *verf, udt_constructor_t *v_construct, expr_node_t *node)
{
    plv_object_t *obj = (plv_object_t *)v_construct->meta;
    pl_entity_t *entity = (pl_entity_t *)obj->root;
    plv_decl_t *decl = entity->type_spec->decl;
    uint32 attrs_count = decl->typdef.record.count;

    return udt_verify_construct_base(verf, node, attrs_count, attrs_count, &decl->name, udt_verify_object_args);
}

status_t udt_object_field_addr_write(sql_stmt_t *stmt, plv_object_attr_t *attr, udt_mtrl_object_field_t *field,
    variant_t *right)
{
    variant_t left;
    switch (attr->type) {
        case UDT_SCALAR:
            CT_RETURN_IFERR(udt_object_delete_field(stmt, attr, &field->rowid));
            if (!right->is_null) {
                CT_RETURN_IFERR(
                    udt_make_scalar_elemt(stmt, attr->scalar_field->type_mode, right, &field->rowid, &field->type));
            }
            break;
        case UDT_COLLECTION:
            MAKE_COLL_VAR(&left, attr->udt_field, field->rowid);
            CT_RETURN_IFERR(udt_coll_assign(stmt, &left, right));
            field->rowid = left.v_collection.value;
            break;
        case UDT_OBJECT:
            MAKE_OBJ_VAR(&left, attr->udt_field, field->rowid);
            CT_RETURN_IFERR(udt_object_assign(stmt, &left, right));
            field->rowid = left.v_object.value;
            break;
        default:
            CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpect attr type");
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t udt_object_field_addr_read(sql_stmt_t *stmt, plv_object_attr_t *attr, variant_t *res,
    udt_mtrl_object_field_t *field)
{
    if (IS_INVALID_MTRL_ROWID(field->rowid)) {
        res->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    res->is_null = CT_FALSE;
    switch (attr->type) {
        case UDT_SCALAR:
            res->type = field->type;
            CT_RETURN_IFERR(udt_read_scalar_value(stmt, &field->rowid, res));
            break;

        case UDT_COLLECTION:
            res->type = CT_TYPE_COLLECTION;
            res->v_collection.type = attr->udt_field->typdef.collection.type;
            res->v_collection.coll_meta = &attr->udt_field->typdef.collection;
            res->v_collection.value = field->rowid;
            res->v_collection.is_constructed = CT_FALSE;
            break;

        case UDT_OBJECT:
            res->type = CT_TYPE_OBJECT;
            res->v_object.count = attr->udt_field->typdef.object.count;
            res->v_object.object_meta = &attr->udt_field->typdef.object;
            res->v_object.value = field->rowid;
            res->v_object.is_constructed = CT_FALSE;
            break;

        default:
            CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpect attr type");
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t udt_object_field_address(sql_stmt_t *stmt, variant_t *var, uint16 id, variant_t *res, variant_t *right)
{
    status_t status;
    udt_var_object_t *v_object = &var->v_object;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    udt_mtrl_object_head_t *mtrl_head = NULL;
    plv_object_t *obj = v_object->object_meta;
    addr_type_t type = (right != NULL) ? WRITE_ADDR : READ_ADDR;

    if (id >= obj->count) {
        CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "invalid object field address");
        return CT_ERROR;
    }

    plv_object_attr_t *attr = udt_seek_obj_field_byid(obj, id);

    OPEN_VM_PTR(&v_object->value, vm_ctx);
    mtrl_head = (udt_mtrl_object_head_t *)d_ptr;
    if (type == WRITE_ADDR) {
        status = udt_object_field_addr_write(stmt, attr, &mtrl_head->field[id], right);
    } else {
        status = udt_object_field_addr_read(stmt, attr, res, &mtrl_head->field[id]);
    }
    CLOSE_VM_PTR(&v_object->value, vm_ctx);

    return status;
}

plv_object_attr_t *udt_object_recurse_find_attr(sql_stmt_t *stmt, uint16 *id, plv_object_t *obj, word_t *word)
{
    if (*id == word->ex_count) {
        return NULL;
    }

    if (word->ex_words[*id].type == WORD_TYPE_BRACKET) {
        return NULL;
    }

    plv_object_attr_t *attr = udt_seek_obj_field_byname(stmt, obj, &word->ex_words[*id].text,
        IS_DQ_STRING(word->ex_words[*id].type) || !IS_CASE_INSENSITIVE);
    if (attr == NULL) {
        return NULL;
    }
    if (attr->type == UDT_SCALAR) {
        if (*id != (word->ex_count - 1)) {
            return NULL;
        }
    } else if (attr->type == UDT_OBJECT) {
        (*id)++;
        attr = udt_object_recurse_find_attr(stmt, id, &attr->udt_field->typdef.object, word);
    }
    return attr;
}
