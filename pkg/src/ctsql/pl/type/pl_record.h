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
 * pl_record.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/type/pl_record.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_RECORD_H__
#define __PL_RECORD_H__

#include "var_typmode.h"
#include "ctsql_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(4)

#define PL_VMAP_EXTENT_SIZE 8

typedef struct st_field_scalar_info {
    typmode_t type_mode;
} field_scalar_info_t;

typedef struct st_plv_record_attr {
    text_t name;
    uint16 field_id; /* field ID identified within the record */
    int8 type;       // udt_type_t
    bool8 nullable;
    expr_tree_t *default_expr;

    union {
        field_scalar_info_t *scalar_field;
        struct st_plv_decl *udt_field;
    };
} plv_record_attr_t;

#define PL_ATTR_SCALAR_DATATYPE(attr) (attr)->scalar_field->type_mode.datatype

#define PL_RMAP_EXTENT_SIZE PL_VMAP_EXTENT_SIZE
#define PL_REC_MAX_FIELD_SIZE 4096 // Align the largest column

#define PLV_REC_EXIST_FIELD(decl, var_type) ((decl)->type == PLV_RECORD && PLC_IS_MULTIEX_VARIANT(var_type))

#define FIELD_IS_HASH_TABLE(attr) ((attr)->type == UDT_COLLECTION && UDT_IS_HASH_TABLE(FILED_COLL_TYPE(attr)))

typedef struct st_pl_rmap_extent {
    plv_record_attr_t attrs[PL_RMAP_EXTENT_SIZE];
    struct st_pl_rmap_extent *next;
} pl_rmap_extent_t;

typedef struct st_plv_record {
    void *root; // plm_entity_t or plv_decl_t
    pl_rmap_extent_t *extents;
    uint16 count;
    uint16 hwm;
    uint16 extent_count;
    uint16 is_anonymous; // for anonymous record, such as %rowtype
} plv_record_t;

typedef struct st_udt_mtrl_record_field {
    int16 type;
    uint16 unuse;
    mtrl_rowid_t rowid;
} udt_mtrl_record_field_t;

typedef struct st_udt_mtrl_record_head {
    uint16 count;
    uint16 size;
    udt_mtrl_record_field_t field[0];
} udt_mtrl_record_head_t;

#pragma pack()
#define UDT_REC_NEED_DEEP_COPY(var) (!(var)->v_record.is_constructed)

#define MAKE_REC_VAR(var, meta, vm_id)                        \
    do {                                                      \
        (var)->type = CT_TYPE_RECORD;                         \
        (var)->is_null = CT_FALSE;                            \
        (var)->v_record.record_meta = &(meta)->typdef.record; \
        (var)->v_record.value = (vm_id);                      \
        (var)->v_record.is_constructed = CT_FALSE;            \
    } while (0)


#define SET_RECORD_EXTENT(record, extent)                                      \
    do {                                                                       \
        if ((record)->extent_count == 0) {                                     \
            (record)->extents = (extent);                                      \
        } else {                                                               \
            pl_rmap_extent_t *d_temp = (record)->extents;                      \
            for (uint16 loop = 0; loop < (record)->extent_count - 1; loop++) { \
                d_temp = d_temp->next;                                         \
            }                                                                  \
            d_temp->next = (extent);                                           \
        }                                                                      \
    } while (0)


static inline plv_record_attr_t *udt_seek_field_by_id(plv_record_t *record, uint16 field_id)
{
    uint16 ext_id = field_id / PL_RMAP_EXTENT_SIZE;
    uint16 id = field_id % PL_RMAP_EXTENT_SIZE;
    pl_rmap_extent_t *extent = record->extents;
    for (uint16 loop = 0; (loop < ext_id) && (extent != NULL); loop++) {
        extent = extent->next;
    }

    return &extent->attrs[id];
}

static inline bool32 udt_cmp_name(text_t *name1, text_t *name2, bool32 case_sensitive)
{
    if (case_sensitive == CT_FALSE) {
        return cm_text_equal_ins2(name1, name2);
    } else {
        return cm_text_equal(name1, name2);
    }
}

static inline plv_record_attr_t *udt_seek_field_by_name(sql_stmt_t *stmt, plv_record_t *record, sql_text_t *name,
    bool32 case_sensitive)
{
    plv_record_attr_t *attr = NULL;

    for (uint16 i = 0; i < record->count; i++) {
        attr = udt_seek_field_by_id(record, i);
        if (udt_cmp_name(&attr->name, &name->value, case_sensitive)) {
            return attr;
        }
    }
    return NULL;
}
#define UDT_GET_TYPE_DEF_RECORD(v) (&UDT_GET_TYPE_DEF(v)->record)

#define UDT_IS_EQUAL_RECORD_VAR(left, right)                           \
    ((left)->v_record.record_meta == (right)->v_record.record_meta &&  \
        (left)->v_record.value.vmid == (right)->v_record.value.vmid && \
        (left)->v_record.value.slot == (right)->v_record.value.slot)

status_t udt_verify_record_attr(plv_record_t *from_record, plv_record_t *to_record);

static inline status_t udt_verify_record_typedef(plv_record_t *right_record, plv_record_t *left_record)
{
    if (right_record == left_record) {
        return CT_SUCCESS;
    }
    // Support assignment between %rowtype and record
    if (!left_record->is_anonymous && !right_record->is_anonymous) {
        CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "left value and right value need be the same record");
        return CT_ERROR;
    }
    if (left_record->count != right_record->count) {
        CT_THROW_ERROR(ERR_PL_EXPR_WRONG_TYPE);
        return CT_ERROR;
    }
    return udt_verify_record_attr(right_record, left_record);
}

/* make sure right variant is not null */
static inline status_t udt_verify_record_assign_ex(variant_t *right, plv_record_t *left_record)
{
    if (right->type != CT_TYPE_RECORD) {
        CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "right value need be record");
        return CT_ERROR;
    }
    return udt_verify_record_typedef((plv_record_t *)right->v_record.record_meta, left_record);
}

static inline status_t udt_verify_record_assign(expr_node_t *right, plv_record_t *left_record)
{
    if (right->datatype != CT_TYPE_RECORD) {
        CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "right value need be record");
        return CT_ERROR;
    }
    return udt_verify_record_typedef((plv_record_t *)right->udt_type, left_record);
}

plv_record_attr_t *udt_record_recurse_find_attr(sql_stmt_t *stmt, uint16 *id, plv_record_t *record, word_t *word);
status_t udt_record_clone(sql_stmt_t *stmt, variant_t *from, plv_record_t *to_record, mtrl_rowid_t *to_row);
status_t udt_record_delete(sql_stmt_t *stmt, variant_t *var, bool8 clean);
void udt_release_rec(sql_stmt_t *stmt, variant_t *val);
plv_record_attr_t *udt_record_alloc_attr(void *entity, plv_record_t *record);
status_t udt_record_alloc_mtrl_head(sql_stmt_t *stmt, plv_record_t *record, mtrl_rowid_t *rowid);
status_t udt_record_assign(sql_stmt_t *stmt, variant_t *left, variant_t *right);
status_t udt_record_field_address(sql_stmt_t *stmt, variant_t *var, uint16 id, variant_t *res, variant_t *right);
status_t udt_record_field_addr_read(sql_stmt_t *stmt, plv_record_attr_t *attr, variant_t *res,
                                    udt_mtrl_record_field_t *field);
status_t udt_record_field_addr_write(sql_stmt_t *stmt, plv_record_attr_t *attr, udt_mtrl_record_field_t *field,
    variant_t *right);
status_t udt_record_clone_all(sql_stmt_t *stmt, variant_t *right, mtrl_rowid_t *res);
status_t plc_verify_record_field_assign(plv_record_attr_t *left_attr, rs_column_t *right, source_location_t loc);
#ifdef __cplusplus
}
#endif

#endif
