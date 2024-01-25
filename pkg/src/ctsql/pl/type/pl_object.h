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
 * pl_object.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/type/pl_object.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_OBJECT_H__
#define __PL_OBJECT_H__

#include "pl_record.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_plv_object_attr {
    text_t name;
    uint16 field_id; /* field ID identified within the object */
    int8 type;       // udt_type_t
    bool8 nullable;
    expr_tree_t *default_expr;

    union {
        field_scalar_info_t *scalar_field;
        struct st_plv_decl *udt_field;
    };
} plv_object_attr_t;

typedef struct st_pl_obj_rmap_extent {
    plv_object_attr_t attrs[PL_RMAP_EXTENT_SIZE];
    struct st_pl_obj_rmap_extent *next;
} pl_obj_rmap_extent_t;

typedef struct st_plv_object {
    void *root; // plm_entity_t or plv_decl_t
    pl_obj_rmap_extent_t *extents;
    uint16 count;
    uint16 hwm;
    uint16 extent_count;
    uint16 unuse;
} plv_object_t;

typedef struct st_udt_mtrl_object_field {
    int16 type;
    uint16 unuse;
    mtrl_rowid_t rowid;
} udt_mtrl_object_field_t;

typedef struct st_udt_mtrl_object_head {
    uint16 count; // count of fields
    uint16 size;  // size of udt_mtrl_object_head_t
    udt_mtrl_object_field_t field[0];
} udt_mtrl_object_head_t;

#define SET_OBJECT_EXTENT(object, extent)                                      \
    do {                                                                       \
        if ((object)->extent_count == 0) {                                     \
            (object)->extents = (extent);                                      \
        } else {                                                               \
            pl_obj_rmap_extent_t *d_temp = (object)->extents;                  \
            for (uint16 loop = 0; loop < (object)->extent_count - 1; loop++) { \
                d_temp = d_temp->next;                                         \
            }                                                                  \
            d_temp->next = (extent);                                           \
        }                                                                      \
    } while (0)

#define MAKE_OBJ_VAR(var, meta, vm_id)                        \
    do {                                                      \
        (var)->type = CT_TYPE_OBJECT;                         \
        (var)->is_null = CT_FALSE;                            \
        (var)->v_object.object_meta = &(meta)->typdef.object; \
        (var)->v_object.value = (vm_id);                      \
        (var)->v_object.is_constructed = CT_FALSE;            \
    } while (0)

#define UDT_IS_EQUAL_OBJECT_VAR(left, right)                           \
    ((left)->v_object.object_meta == (right)->v_object.object_meta &&  \
        (left)->v_object.value.vmid == (right)->v_object.value.vmid && \
        (left)->v_object.value.slot == (right)->v_object.value.slot)

#define UDT_OBJ_NEED_DEEP_COPY(var) (!(var)->v_object.is_constructed)
#define UDT_GET_TYPE_DEF_OBJECT(v) (&UDT_GET_TYPE_DEF(v)->object)
#define PLV_OBJ_EXIST_FIELD(decl, var_type) ((decl)->type == PLV_OBJECT && PLC_IS_MULTIEX_VARIANT(var_type))

static inline plv_object_attr_t *udt_seek_obj_field_byid(plv_object_t *object, uint16 field_id)
{
    uint16 ext_id = field_id / PL_RMAP_EXTENT_SIZE;
    uint16 id = field_id % PL_RMAP_EXTENT_SIZE;
    pl_obj_rmap_extent_t *extent = object->extents;
    for (uint16 loop = 0; (loop < ext_id) && (extent != NULL); loop++) {
        extent = extent->next;
    }

    return &extent->attrs[id];
}

static inline plv_object_attr_t *udt_seek_obj_field_byname(sql_stmt_t *stmt, plv_object_t *object, sql_text_t *name,
    bool32 case_sensitive)
{
    plv_object_attr_t *attr = NULL;

    for (uint16 i = 0; i < object->count; i++) {
        attr = udt_seek_obj_field_byid(object, i);
        if (udt_cmp_name(&attr->name, &name->value, case_sensitive)) {
            return attr;
        }
    }
    return NULL;
}

static inline status_t udt_verify_object_assign(expr_node_t *right, plv_object_t *left_object)
{
    if (right->datatype != CT_TYPE_OBJECT) {
        CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "right value need be object");
        return CT_ERROR;
    }

    return ((plv_object_t *)right->udt_type) == left_object ? CT_SUCCESS : CT_ERROR;
}

plv_object_attr_t *udt_object_alloc_attr(void *entity, plv_object_t *obj);
plv_object_attr_t *udt_object_recurse_find_attr(sql_stmt_t *stmt, uint16 *id, plv_object_t *obj, word_t *word);
status_t udt_object_inherit_super_attr(void *entity, plv_object_t *curr, plv_object_t *super);
status_t udt_object_constructor(sql_stmt_t *stmt, plv_object_t *object_meta, expr_tree_t *args, variant_t *output);
status_t udt_object_clone(sql_stmt_t *stmt, variant_t *right, mtrl_rowid_t *result);
status_t udt_object_delete(sql_stmt_t *stmt, variant_t *var);
status_t udt_object_assign(sql_stmt_t *stmt, variant_t *left, variant_t *right);
status_t udt_verify_object_construct(sql_verifier_t *verf, udt_constructor_t *v_construct, expr_node_t *node);
status_t udt_object_field_address(sql_stmt_t *stmt, variant_t *var, uint16 id, variant_t *res, variant_t *right);
status_t udt_object_field_addr_read(sql_stmt_t *stmt, plv_object_attr_t *attr, variant_t *res,
                                    udt_mtrl_object_field_t *field);
status_t udt_object_field_addr_write(sql_stmt_t *stmt, plv_object_attr_t *attr, udt_mtrl_object_field_t *field,
    variant_t *right);
void udt_release_obj(sql_stmt_t *stmt, variant_t *val);

#ifdef __cplusplus
}
#endif

#endif
