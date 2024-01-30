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
 * var_plsql.h
 *
 *
 * IDENTIFICATION
 * src/common/variant/var_plsql.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __VAR_PLSQL_H__
#define __VAR_PLSQL_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_list.h"
#include "cm_memory.h"
typedef enum en_plv_attr_type {
    PLV_ATTR_ISOPEN = 0,
    PLV_ATTR_FOUND = 1,
    PLV_ATTR_NOTFOUND = 2,
    PLV_ATTR_ROWCOUNT = 3,
} plv_attr_type_t;

#pragma pack(4)
typedef struct st_plv_id {  // PLV Procedure Language Varaint
    int16 block;            // may be negative value,but block + stack_base must be positive value
    uint16 id;
    union {
        uint32 input_id;  // for get pl variant from keeped inputs
        struct {
            uint32 m_offset : 24;  // for record type, member offset
            uint32 is_rowid : 1;   // when current of cursor, it's true
            uint32 direction : 2;
            uint32 unused : 5;
        };
    };
} plv_id_t;
#pragma pack()

#define IS_SAME_PLV_ID(id1, id2) (*(uint64 *)&(id1) == *(uint64 *)&(id2))

typedef struct st_plv_attr {
    plv_id_t id;
    uint16 type;
    uint8 reserve;
    bool8 is_implicit;
} plv_attr_t;

typedef enum en_udt_addr_type {
    UDT_STACK_ADDR = 0,       // STACK ADDRESS
    UDT_REC_FIELD_ADDR = 1,   // RECORD FIELD ADDRESS
    UDT_COLL_ELEMT_ADDR = 2,  // COLL ELEMT ADDRESS
    UDT_OBJ_FIELD_ADDR = 3,  // OBJECT ELEMT ADDRESS
    UDT_ARRAY_ADDR = 4, // ARRAY ADDRESS
} udt_addr_type_t;

#pragma pack(4)

typedef struct st_udt_stack_addr {
    struct st_plv_decl *decl;
} udt_stack_addr_t;

typedef struct st_udt_coll_elemt_addr {
    struct st_plv_collection *parent;
    struct st_expr_tree *id;
} udt_coll_elemt_addr_t;

typedef struct st_udt_rec_field_addr {
    struct st_plv_record *parent;
    uint16 id;
    uint16 reserved;
} udt_rec_field_addr_t;

typedef struct st_udt_obj_field_addr {
    struct st_plv_object *parent;
    uint16 id;
    uint16 reserved;
} udt_obj_field_addr_t;

typedef struct st_udt_array_addr {
    int32 ss_start;  // begin array subscript, for array variant
    int32 ss_end;    // end array subscript, for array variant
} udt_array_addr_t;

// define by directory order
typedef enum en_coll_method {
    METHOD_COUNT = 0,
    METHOD_DELETE,
    METHOD_EXISTS,
    METHOD_EXTEND,
    METHOD_FIRST,
    METHOD_LAST,
    METHOD_LIMIT,
    METHOD_NEXT,
    METHOD_PRIOR,
    METHOD_TRIM,
    METHOD_END,
} coll_method_t;

typedef struct st_udt_method {
    uint16 id;  // coll_method_t
    uint16 arg_cnt;

    void *meta;
    galist_t *pairs;  // var address
} udt_method_t;

typedef struct st_udt_constructor {
    uint16 arg_cnt;
    bool8 is_coll;
    bool8 reserved;
    void *meta;
} udt_constructor_t;

typedef struct st_var_address_pair {
    udt_addr_type_t type;

    union {
        udt_obj_field_addr_t *obj_field;
        udt_rec_field_addr_t *rec_field;
        udt_coll_elemt_addr_t *coll_elemt;
        udt_stack_addr_t *stack;
        udt_array_addr_t *arr_addr;
    };
} var_address_pair_t;

typedef struct st_var_address {
    struct st_galist *pairs;
} var_address_t;

typedef struct st_var_record {
    uint16 count;  // variant array limit
    bool8 is_constructed;
    uint8 reserved;

    void *record_meta;  // plv_record_t
    mtrl_rowid_t value;
} var_record_t;

typedef struct st_udt_var_object {
    uint16 count;  // variant array limit
    bool8 is_constructed;
    uint8 reserved;

    void *object_meta;  // plv_object_t
    mtrl_rowid_t value;
} udt_var_object_t;

typedef enum udt_type {
    UDT_SCALAR = 1,
    UDT_COLLECTION,
    UDT_RECORD,
    UDT_OBJECT
} udt_type_t;

typedef enum en_collection_type {
    UDT_NESTED_TABLE = 0,
    UDT_VARRAY,
    UDT_HASH_TABLE,
    UDT_TYPE_END,
} collection_type_t;

typedef struct st_var_collection {
    /* collection_type_t */
    uint8 type;
    bool8 is_constructed;
    uint8 reseved[2];
    void *coll_meta;  // plv_collection_t *
    mtrl_rowid_t value;
} var_collection_t;

#pragma pack()

#endif
