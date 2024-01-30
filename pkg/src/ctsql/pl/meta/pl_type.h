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
 * pl_type.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/meta/pl_type.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_TYPE_H__
#define __PL_TYPE_H__

#include "pl_trigger.h"
#include "pl_procedure.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TYPE_INHERIT_FINAL (uint8)0x01
#define TYPE_INHERIT_INSTANTIABLE (uint8)0x02

#define PL_IS_FINAL(flag) (((uint8)(flag) & TYPE_INHERIT_FINAL) != 0)
#define PL_IS_INSTANTIABLE(flag) (((uint8)(flag) & TYPE_INHERIT_INSTANTIABLE) != 0)

typedef struct st_udt_desc {
    char name[CT_NAME_BUFFER_SIZE]; // name
    uint64 oid;                     // object id
    knl_scn_t org_scn;              // original scn
    knl_scn_t chg_scn;              // scn when changed by DDL(alter)
    uint32 type_id;                 // typeid
    uint32 type_code;               // udt_type_t
    uint16 mods;                    // modifier_t
    uint16 inherit_flag;            // type inherit flag
    uint32 uid;                     // user id
    uint32 attributes;              // attribute count, include inherit from super type
    uint32 methods;                 // methods count, include inherit from super type
    uint32 supertypes;              // super type count, reserved
    uint32 subtypes;                // sub type count, reserved
    uint32 supertype_id;            // super type id
    uint64 supertype_oid;           // super type oid
    uint32 local_attributes;        // local type attributes
    uint32 local_methods;           // local methods
    union {
        uint32 flags;
        struct {
            uint32 unused_flag : 32;
        };
    };
} udt_desc_t;

typedef struct st_uni_type {
    udt_type_t type;
    union {
        typmode_t scalar;
        void *meta;
    };
} uni_type_t;

typedef struct st_field {
    uint8 mods; // modifier_t
    int8 type;  // udt_type_t
    bool8 nullable;
    int8 unused;
    expr_tree_t *init;
    uni_type_t var_type;
} field_t;

typedef struct st_attr_desc {
    uint64 oid;
    uint32 type_id;
    uint32 attr_id;
    text_t name;
    uint32 type_code;
    uint8 attr_type; // attr_type_t
    uint32 flags;
    uni_type_t type;
    uint32 type_owner;
    text_t type_name;
} attr_desc_t;

typedef struct st_attr {
    uint16 id;
    uint8 type; // attr_type_t
    int8 reserved;
    union {
        field_t *field;
        plv_typdef_t *typdef; // TYPE DEFS.
        plv_cursor_t *cursor;
        plv_cursor_t *pragma;
    };
} udt_attr_t;

typedef struct st_udt_obj {
    struct st_udt_obj *super_type;
    galist_t *attributes; // all variables plv_decl_t
    galist_t *methods;    // all member methods func_t
} udt_obj_t;

typedef struct st_type_body {
    galist_t *defs; // pl_line_begin_t
    uint32 *meth_map;
} type_body_t;

typedef struct st_type_spec type_spec_t;
struct st_type_spec {
    udt_desc_t desc; /* type description */
    plv_decl_t *decl;
    type_spec_t *super_type;
};

status_t pl_check_type_dependency(sql_stmt_t *stmt, obj_info_t *obj_addr, bool32 *in_table, bool32 *in_other_type);
status_t pl_get_type_name(sql_stmt_t *stmt, expr_tree_t *arg, var_udo_t *obj);
status_t pl_write_sys_types(knl_session_t *knl_session, type_spec_t *type_spec, void *desc_in);
status_t pl_init_sys_types(knl_session_t *knl_session, void *desc_in);
status_t pl_delete_sys_types(knl_session_t *session, uint32 uid, uint64 oid);
status_t pl_write_sys_type_attrs(knl_session_t *knl_session, type_spec_t *type, void *desc_in);
status_t pl_delete_sys_type_attrs(knl_session_t *session, uint32 uid, uint64 oid);
status_t pl_delete_sys_type_methods(knl_session_t *session, uint32 uid, uint64 oid);
status_t pl_write_sys_coll_types(knl_session_t *knl_session, type_spec_t *type, void *desc_in);
status_t pl_delete_sys_coll_types(knl_session_t *session, uint32 uid, uint64 oid);
status_t pl_load_entity_update_udt_table(knl_session_t *session, void *desc_in, void *entity_in);

#ifdef __cplusplus
}
#endif

#endif
