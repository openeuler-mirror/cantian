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
 * pl_collection.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/type/pl_collection.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_COLLECTION_H__
#define __PL_COLLECTION_H__

#include "ctsql_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif
#pragma pack(4)

typedef enum st_addr_type {
    READ_ADDR,
    WRITE_ADDR
} addr_type_t;

typedef enum en_coll_intr_method {
    METHOD_INTR_TRIM,
    METHOD_INTR_EXTEND_NUM,
    METHOD_INTR_END,
} coll_intr_method_t;

typedef struct st_plv_collection {
    void *root;      // plm_entity_t or plv_decl_t
    uint8 type;      // collection_type_t
    uint8 attr_type; // udt_type_t
    bool8 is_global;
    uint8 unused1;

    union {
        struct {
            // ceil of array, null(0) if nested-table
            uint32 limit;
            uint32 unused2;
        };
        // index by hash table
        typmode_t index_typmod;
    };

    union {
        typmode_t type_mode;
        struct st_plv_decl *elmt_type;
    };
} plv_collection_t;


#define MAX_ARRAY_ELEMENT_SIZE (15360) /* 128k / sizeof(mtrl_rowid_t) - 1k */

typedef struct st_mtrl_ctrl {
    uint16 datatype;
    uint16 reserved;
    /* current collection extend hwm */
    uint32 hwm;
    /* current collection element count */
    uint32 count;
} mtrl_ctrl_t;

typedef status_t (*coll_invoke_t)(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
typedef status_t (*coll_verify_t)(sql_verifier_t *verifier, expr_node_t *method);

typedef enum en_coll_option {
    AS_PROC = 0,
    AS_FUNC,
} coll_option_t;

typedef struct st_plv_collection_method {
    coll_invoke_t invoke;
    coll_verify_t verify;
    uint16 option;
    uint16 unused[3];
} plv_collection_method_t;

typedef status_t (*constructor_t)(sql_stmt_t *stmt, udt_constructor_t *v_construct, expr_tree_t *args,
    variant_t *output);
typedef status_t (*constructor_verify_t)(sql_verifier_t *verf, expr_node_t *node, plv_collection_t *collection,
    expr_tree_t *args);
typedef status_t (*free_t)(sql_stmt_t *stmt, variant_t *var);
typedef status_t (*intr_method_t)(sql_stmt_t *stmt, variant_t *var, void *arg);
typedef status_t (*clone_method_t)(sql_stmt_t *, variant_t *, mtrl_rowid_t *);
typedef status_t (*address_t)(sql_stmt_t *, variant_t *, variant_t *, addr_type_t, variant_t *, variant_t *);

typedef struct st_plv_coll_construct {
    constructor_t constuct;
    constructor_verify_t verify;
} plv_coll_construct_t;

#define UDT_NTBL_MAX_ARGS 2
#define UDT_NTBL_MIN_ARGS 0

#define UDT_NTBL_TWO_EXTENT 2

extern plv_collection_method_t *g_coll_methods[UDT_TYPE_END];
extern plv_coll_construct_t *g_coll_constructor[UDT_TYPE_END];
extern free_t g_coll_free[UDT_TYPE_END];
extern intr_method_t *g_coll_intr_method[UDT_TYPE_END];
extern clone_method_t g_coll_clone_method[UDT_TYPE_END];
extern address_t g_coll_address[UDT_TYPE_END];

#pragma pack()

#define GET_COLLECTION_ELEMENT_TYPE(coll_meta)                                          \
    ((coll_meta)->attr_type == UDT_SCALAR ? (coll_meta)->type_mode.datatype :           \
                                            ((coll_meta)->attr_type == UDT_COLLECTION ? \
        CT_TYPE_COLLECTION :                                                            \
        ((coll_meta)->attr_type == UDT_RECORD ? CT_TYPE_RECORD : CT_TYPE_OBJECT)))

#define IS_COLLECTION_EMPTY(coll) IS_INVALID_MTRL_ROWID((coll)->value)

#define MAKE_COLL_VAR(var, meta, vm_id)                             \
    do {                                                            \
        (var)->type = CT_TYPE_COLLECTION;                           \
        (var)->is_null = CT_FALSE;                                  \
        (var)->v_collection.type = (meta)->typdef.collection.type;  \
        (var)->v_collection.coll_meta = &(meta)->typdef.collection; \
        (var)->v_collection.value = (vm_id);                        \
        (var)->v_collection.is_constructed = CT_FALSE;              \
    } while (0)

#define UDT_IS_EQUAL_COLL_VAR(left, right)                                     \
    ((left)->v_collection.coll_meta == (right)->v_collection.coll_meta &&      \
        (left)->v_collection.value.vmid == (right)->v_collection.value.vmid && \
        (left)->v_collection.value.slot == (right)->v_collection.value.slot)

#define UDT_GET_TYPE_DEF(v) (&(v)->typdef)
#define UDT_GET_TYPE_DEF_COLLECTION(v) (&UDT_GET_TYPE_DEF(v)->collection)

#define UDT_VERIFY_COLL_ASSIGN_EX(right, left_meta) \
    ((right)->type == CT_TYPE_COLLECTION && (right)->v_collection.coll_meta == (void *)(left_meta))

#define UDT_VERIFY_COLL_ASSIGN(right, left_meta) \
    ((right)->datatype == CT_TYPE_COLLECTION && (right)->udt_type == (void *)(left_meta))

#define UDT_COLL_NEED_DEEP_COPY(var) (!(var)->v_collection.is_constructed)

#define ELMT_COLL_TYPE(coll_meta) (coll_meta)->elmt_type->typdef.collection.type
#define FILED_COLL_TYPE(attr) (attr)->udt_field->typdef.collection.type
#define UDT_IS_HASH_TABLE(type) ((type) == UDT_HASH_TABLE)

#define ELMT_IS_HASH_TABLE(coll_meta) \
    ((coll_meta)->attr_type == UDT_COLLECTION && UDT_IS_HASH_TABLE(ELMT_COLL_TYPE(coll_meta)))

status_t udt_verify_coll_elemt(sql_verifier_t *verif, uint32 arg_count, void *meta, expr_tree_t *tree);
status_t udt_coll_assign(sql_stmt_t *stmt, variant_t *left, variant_t *right);
void udt_reg_coll_method(collection_type_t collect_type, handle_mutiple_ptrs_t *mult_ptrs);

static inline status_t udt_invoke_coll_construct(sql_stmt_t *stmt, udt_constructor_t *v_construct, expr_tree_t *args,
    variant_t *result)
{
    plv_collection_t *collection = (plv_collection_t *)v_construct->meta;
    return g_coll_constructor[collection->type]->constuct(stmt, v_construct, args, result);
}

static inline status_t udt_verify_coll_construct(sql_verifier_t *verifier, udt_constructor_t *v_construct,
    expr_node_t *node)
{
    node->datatype = CT_TYPE_COLLECTION;
    node->udt_type = v_construct->meta;
    plv_collection_t *collection = (plv_collection_t *)v_construct->meta;
    return g_coll_constructor[collection->type]->verify(verifier, node, collection, node->argument);
}

static inline status_t udt_invoke_coll_method(sql_stmt_t *stmt, udt_method_t *v_method, expr_node_t *node,
    variant_t *coll, variant_t *result)
{
    plv_collection_t *collection = (plv_collection_t *)v_method->meta;
    return g_coll_methods[collection->type][v_method->id].invoke(stmt, coll, node->argument, result);
}

static inline status_t udt_verify_coll_method(sql_verifier_t *verifier, udt_method_t *v_method, expr_node_t *node)
{
    plv_collection_t *collection = (plv_collection_t *)v_method->meta;
    return g_coll_methods[collection->type][v_method->id].verify(verifier, node);
}

static inline char *udt_print_colltype(collection_type_t type)
{
    switch (type) {
        case UDT_VARRAY:
            return "varray";
        case UDT_NESTED_TABLE:
            return "nested table";
        case UDT_HASH_TABLE:
            return "hash table";
        default:
            return "unknown";
    }
}

static inline status_t udt_coll_elemt_address(sql_stmt_t *stmt, variant_t *var, variant_t *index, variant_t *result,
    variant_t *right)
{
    plv_collection_t *collection = (plv_collection_t *)var->v_collection.coll_meta;
    addr_type_t type = (right != NULL ? WRITE_ADDR : READ_ADDR);

    return g_coll_address[collection->type](stmt, var, index, type, result, right);
}

static inline status_t udt_delete_collection(sql_stmt_t *stmt, variant_t *var)
{
    plv_collection_t *coll_meta = (plv_collection_t *)var->v_collection.coll_meta;
    return g_coll_free[coll_meta->type](stmt, var);
}

static inline status_t udt_clone_collection(sql_stmt_t *stmt, variant_t *var, mtrl_rowid_t *result)
{
    plv_collection_t *coll_meta = (plv_collection_t *)var->v_collection.coll_meta;
    return g_coll_clone_method[coll_meta->type](stmt, var, result);
}

void udt_invoke_coll_destructor(sql_stmt_t *stmt, variant_t *val);
status_t ple_array_as_collection(sql_stmt_t *stmt, variant_t *var, void *pl_coll);

#ifdef __cplusplus
}
#endif

#endif
