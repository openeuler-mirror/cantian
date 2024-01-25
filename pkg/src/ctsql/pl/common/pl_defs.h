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
 * pl_defs.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/common/pl_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_DEFS_H__
#define __PL_DEFS_H__

#include "var_plsql.h"
#include "var_typmode.h"
#include "cm_error.h"

#ifdef __cplusplus
extern "C" {
#endif

// if pl_type_t change, need change DECODE_PL_TYPE_NUM too
typedef enum en_pl_type {
    PL_PROCEDURE = 0x00000001,
    PL_FUNCTION = 0x00000002,
    PL_PACKAGE_SPEC = 0x00000004,
    PL_PACKAGE_BODY = 0x00000008,
    PL_TYPE_SPEC = 0x00000010,
    PL_TYPE_BODY = 0x00000020,
    PL_TRIGGER = 0x00000040,
    PL_ANONYMOUS_BLOCK = 0x00000080,
    PL_SYNONYM = 0x00000100,
    PL_SYS_PACKAGE = 0x00000200,
    PL_UNKNOWN = 0x000007FF,
} pl_type_t;

#define PL_SYN_LINK_TYPE (PL_PROCEDURE | PL_FUNCTION | PL_PACKAGE_SPEC | PL_SYS_PACKAGE | PL_TYPE_SPEC)
#define PL_OBJECTS (PL_SYN_LINK_TYPE | PL_SYNONYM)

typedef enum en_pl_class_type {
    PL_CLASS_PROC_FUNC_PACK_TYPE = 1,
    PL_CLASS_TRIGGER,
    PL_CLASS_PACK_BODY,
    PL_CLASS_TYPE_BODY,
} pl_class_type_t;

typedef enum en_plsql_mode {
    PLSQL_NONE = 0,   // GENERAL BINDING PARAM, CONTEXT FROM AGENT BUFFER
    PLSQL_STATIC = 1, // STATIC SQL, OVERWRITE PL VARIABLES
    PLSQL_DYNSQL = 2, // DYNAMIC SQL
    PLSQL_DYNBLK = 3, // DYNAMIC ANONYMOUS BLOCK
    PLSQL_CURSOR = 4, // CURSOR, SUPPORT BIND PARAM
} plsql_mode_t;


typedef struct st_pl_source_pages {
    uint32 curr_page_id;
    uint32 curr_page_pos;
} pl_source_pages_t;

typedef enum pl_ext_lang {
    LANG_PLSQL = 0,
    LANG_C,
    LANG_END,
} pl_ext_lang_t;

typedef enum st_plv_type {
    PLV_VAR = 0x00000001,    // VARIANT
    PLV_CUR = 0x00000002,    // CURSOR
    PLV_IMPCUR = 0x00000004, // implicit CURSOR
    PLV_EXCPT = 0x00000008,  // EXCEPTION
    PLV_TYPE = 0x00000010,   // TYPE DEFINITION
    PLV_RECORD = 0x00000020, // RECORD
    PLV_PARAM = 0x00000400,
    PLV_COLLECTION = 0x00000800, // COLLECTIONs, just like nested-table, varray, associate-array
    PLV_OBJECT = 0x00001000,
    PLV_ARRAY = 0x00002000,
    PLV_FUNCTION = 0x00004000,
} plv_type_t;

/* ****************************************** COVERAGE ************************************************** */
typedef enum en_coverage {
    COVER_SESSIONID_COL = 0,
    COVER_OWNER_COL,
    COVER_OBJ_NAME_COL,
    COVER_COVER_INFO_COL,
} en_coverage_t;

#define COVER_HIT_COUNT_STR_LEN 10
#define COVER_VALID_LINE_FLAG 0x80
#define COVER_SQL_STR_LEN 1024

static inline int plm_get_pl_type(char char_type)
{
    switch (char_type) {
        case 'T':
            return PL_TRIGGER;
        case 'F':
            return PL_FUNCTION;
        case 'P':
            return PL_PROCEDURE;
        case 'S':
            return PL_PACKAGE_SPEC;
        case 'B':
            return PL_PACKAGE_BODY;
        case 'Y':
            return PL_TYPE_SPEC;
        case 'O':
            return PL_TYPE_BODY;
        default:
            return PL_ANONYMOUS_BLOCK;
    }
}

static inline char *pl_get_char_type(uint32 pl_type)
{
    switch (pl_type) {
        case PL_TRIGGER:
            return "T";
        case PL_FUNCTION:
            return "F";
        case PL_PROCEDURE:
            return "P";
        case PL_PACKAGE_SPEC:
            return "S";
        case PL_PACKAGE_BODY:
            return "B";
        case PL_TYPE_SPEC:
            return "Y";
        case PL_SYNONYM:
            return "M";
        case PL_TYPE_BODY:
        default:
            return "O";
    }
}

#ifdef __cplusplus
}
#endif

#endif
