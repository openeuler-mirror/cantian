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
 * pragma.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/ast/pragma.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PRAGMA_H__
#define __PRAGMA_H__

#include "cm_word.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_pl_exception pl_exception_t;
typedef struct st_pl_exec_exception pl_exec_exception_t;

enum en_pl_exception_type {
    RETURN_WITHOUT_VALUE = (int32)ERR_RETURN_WITHOUT_VALUE,
    ACCESS_INTO_NULL = (int32)ERR_ACCESS_INTO_NULL,
    CASE_NOT_FOUND = (int32)ERR_CASE_NOT_FOUND,
    COLLECTION_IS_NULL = (int32)ERR_COLLECTION_IS_NULL,
    CURSOR_ALREADY_OPEN = (int32)ERR_CURSOR_ALREADY_OPEN,
    DUP_VAL_ON_INDEX = (int32)ERR_DUPLICATE_KEY,
    INVALID_CURSOR = (int32)ERR_INVALID_CURSOR,
    INVALID_NUMBER = (int32)ERR_INVALID_NUMBER,
    LOGIN_DENIED = (int32)ERR_LOGIN_DENIED,
    NO_DATA_FOUND = (int32)ERR_NO_DATA_FOUND,
    NO_DATA_NEEDED = (int32)ERR_NO_DATA_NEEDED,
    NOT_LOGGED_ON = (int32)ERR_NOT_LOGGED_ON,
    PROGRAM_ERROR = (int32)ERR_PROGRAM_ERROR_FMT,
    ROWTYPE_MISMATCH = (int32)ERR_RESULT_NOT_MATCH,
    SELF_IS_NULL = (int32)ERR_SELF_IS_NULL,
    STORAGE_ERROR = (int32)ERR_STORAGE_ERROR,
    SUBSCRIPT_BEYOND_COUNT = (int32)ERR_SUBSCRIPT_BEYOND_COUNT,
    SUBSCRIPT_OUTSIDE_LIMIT = (int32)ERR_SUBSCRIPT_OUTSIDE_LIMIT,
    SYS_INVALID_ROWID = (int32)ERR_INVALID_ROWID,
    TIMEOUT_ON_RESOURCE = (int32)ERR_RESOURCE_BUSY,
    TOO_MANY_ROWS = (int32)ERR_TOO_MANY_ROWS,
    VALUE_ERROR = (int32)ERR_VALUE_ERROR,
    ZERO_DIVIDE = (int32)ERR_ZERO_DIVIDE,

    OTHERS = (int32)ERR_CODE_CEIL,

    INVALID_EXCEPTION = CT_INVALID_INT32,
};

typedef enum en_pl_exception_type pl_exception_type_t;

struct st_pl_exception {
    bool32 is_userdef; /* CT_TRUE: user defiend exception; CT_FALSE: predefined exception */
    int32 error_code;
    char message[CT_MESSAGE_BUFFER_SIZE];
    source_location_t loc;
    plv_id_t vid; /* user defined var info */
};

struct st_pl_exec_exception {
    bool32 has_exception; /* default 0 */
    pl_exception_t except;
};

typedef enum en_plc_pragma {
    AUTON_TRANS = 0,
    EXCEPTION_INIT = 1,
} plc_pragma_t;

void pl_init_keywords(void);
int32 pl_get_exception_id(word_t *word);

#ifdef __cplusplus
}
#endif

#endif