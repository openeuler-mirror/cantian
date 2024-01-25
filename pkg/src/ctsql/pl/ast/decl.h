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
 * decl.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/ast/decl.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DECL_H__
#define __DECL_H__

#include "expr_parser.h"
#include "pl_defs.h"
#include "typedef.h"
#include "pl_procedure.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef enum st_plv_direction {
    PLV_DIR_NONE = CT_INTERNAL_PARAM, /* variant declared at declare block */
    PLV_DIR_IN = CT_INPUT_PARAM,
    PLV_DIR_OUT = CT_OUTPUT_PARAM,
    PLV_DIR_INOUT = CT_INOUT_PARAM,
} plv_direction_t;

typedef enum en_plv_arg_type {
    PLV_ARG_NONE = 0,
    PLV_NORMAL_ARG = 1,
    PLV_CURSOR_ARG = 2,
} plv_arg_type_t;

typedef enum en_plv_trig_bm_type {
    PLV_TRIG_NONE = 0,
    PLV_MODIFIED_NEW_COL = 0x1, // ":NEW.F1 := 10" IN TRIGGER
    PLV_NEW_COL = 0x2,          // ":NEW.F1" IN TRIGGER
    PLV_OLD_COL = 0x4,          // ":OLD.F1" IN TRIGGER
} plv_trig_bm_type_t;

typedef struct st_plv_variant {
    typmode_t type;
} plv_variant_t;

typedef struct st_plv_exception {
    uint32 is_userdef;
    uint32 err_code;
    text_t name;
} plv_exception_t;

typedef struct st_plv_param {
    typmode_t type;
    uint32 param_id;
} plv_param_t;

typedef struct st_plv_decl {
    plv_type_t type;
    plv_id_t vid;

    union {
        uint32 resv;
        struct {
            bool8 reserved;
            bool8 nullable;
            uint16 field_type; // CAREFULL JUST BIT-16
        };
    };
    plv_arg_type_t arg_type;
    plv_trig_bm_type_t trig_type;
    source_location_t loc;
    union {
        text_t name;
        // parameter name id, for anonymous block, such as: begin :1 (pnid is 0) := 10 + :2 (pnid is 1); end;
        uint32 pnid;
    };

    plv_direction_t drct; // record direction of function's parameter explicit declare, others PLV_DIR_NONE
    expr_tree_t *default_expr;

    union {
        plv_variant_t variant;
        plv_array_t array;
        plv_exception_t excpt;
        plv_cursor_t cursor; // explicit cursor
        plv_typdef_t typdef; // TYPE DEFS.
        function_t *func;
        plv_param_t param;
        plv_record_t *record;         // record variant, for implicit record just point typdef->record
        plv_collection_t *collection; // collection variant, for implicit collection just point typdef->collection
        plv_object_t *object;         // object variant
    };
} plv_decl_t;

#define PL_VID_EQUAL(vid1, vid2) \
    (((vid1).block == (vid2).block) && ((vid1).id == (vid2).id) && ((vid1).input_id == (vid2).input_id))

#define PLC_IS_MULTIEX_VARIANT(var_type) ((var_type) == PLC_MULTIEX_VAR || (var_type) == PLC_BLOCK_MULTIEX_VAR)

typedef enum en_plc_var_type {
    PLC_NORMAL_VAR = 0, // single variant name
    PLC_TRIGGER_VAR,    // trigger variant name
    PLC_BLOCK_VAR,      // a block(label) name and a variant name
    PLC_MULTIEX_VAR,    // multiple word ex_count variant name
    PLC_BLOCK_MULTIEX_VAR
} plc_var_type_t;

#define PLV_COMPLEX_VARIANT (PLV_RECORD | PLV_OBJECT | PLV_COLLECTION | PLV_ARRAY)
#define PLV_VARIANT_ALL (PLV_VAR | PLV_COMPLEX_VARIANT)
#define PLV_VARIANT_AND_CUR (PLV_CUR | PLV_VARIANT_ALL)

typedef struct st_plv_global_collection {
    void *type_dc;
} plv_global_collection_t;

typedef struct st_plc_variant_name {
    text_t block_name;
    text_t name;
    bool32 case_sensitive;
    uint32 types;
} plc_variant_name_t;

typedef enum en_plv_inherit_type {
    REC_FIELD_INHERIT = 0x1,
    DECL_INHERIT,
    COLL_ATTR_INHERIT,
} plv_inherit_type_t;

typedef struct st_plattr_assist {
    uint8 type;    // plv_inherit_type_t
    bool8 is_args; // if true, use compiler->type_decls to store anonymous record
    uint8 unused[2];
    galist_t *decls;
    union {
        plv_decl_t *decl;
        plv_record_attr_t *attr;
        plv_object_attr_t *obj;
        plv_collection_t *coll;
    };
} plattr_assist_t;

void plc_find_in_decls(galist_t *decls, text_t *name, bool32 case_sensitive, plv_decl_t **selector);
void plc_check_duplicate(galist_t *decls, text_t *name, bool32 case_sensitive, bool32 *res);
status_t plc_parse_datatype(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword);
status_t plc_decl_equal(sql_stmt_t *stmt, plv_decl_t *decl1, plv_decl_t *decl2);
void plc_cmp_name(text_t *name1, text_t *name2, bool32 case_sensitive, bool32 *res);
#ifdef __cplusplus
}
#endif

#endif