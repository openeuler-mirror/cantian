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
 * pl_compiler.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/parser/pl_compiler.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_COMPILER_H__
#define __PL_COMPILER_H__

#include "ast.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PLC_ERROR_BUFFER_SIZE (CT_MESSAGE_BUFFER_SIZE - 128)
#define PLC_ERROR_BUFFER_RESERVED 64
#define PLC_ERROR_BUFFER_MIN_RESERVED (PLC_ERROR_BUFFER_RESERVED / 2)


typedef struct st_variant_complier {
    pl_compiler_t *compiler;
    text_t *sql;
    word_t *word;
    uint32 types;
    void *usrdef;
} variant_complier_t;

typedef struct st_plc_desc {
    uint32 type;
    int64 proc_oid;
    pl_source_pages_t source_pages;
    var_udo_t *obj;
    bool32 is_synonym;
    void *entity;
} plc_desc_t;

#define IS_TRIGGER_SUPPROT_OBJECT(type)                                                                             \
    ((type) == DICT_TYPE_TEMP_TABLE_TRANS || (type) == DICT_TYPE_TABLE || (type) == DICT_TYPE_TEMP_TABLE_SESSION || \
        (type) == DICT_TYPE_TABLE_NOLOGGING || (type) == DICT_TYPE_VIEW)

void plc_set_tls_plc_error(void);
void plc_reset_tls_plc_error(void);
void plc_set_compiling_errors(sql_stmt_t *stmt, var_udo_t *obj);
status_t plc_compile(sql_stmt_t *stmt, plc_desc_t *desc, word_t *word);
void plc_diag_ctx_type(sql_context_t *context, uint32 type);
status_t plc_prepare(sql_stmt_t *stmt, pl_compiler_t *compile, plc_desc_t *desc);
status_t pl_compile_func_desc(pl_compiler_t *compiler, word_t *word, text_t *name, void *func_in);
status_t plc_compile_proc_desc(pl_compiler_t *compiler, word_t *word, text_t *name, void *proc_in);
status_t plc_compile_package_spec(pl_compiler_t *compiler, word_t *word);
plv_decl_t *plc_get_last_addr_decl(sql_stmt_t *stmt, var_address_pair_t *addr_pair);

#define IS_DML_INTO_PL_VAR(type) \
    ((type) == CTSQL_TYPE_SELECT || (type) == CTSQL_TYPE_UPDATE || (type) == CTSQL_TYPE_INSERT || (type) == CTSQL_TYPE_DELETE)

#define OBJ_SUBPROC_WORD_NUM 6
#define ROW_CHARACTER_NUM 3
static inline status_t plc_trigger_verify_row_character(const text_t *name)
{
    text_t res_row[ROW_CHARACTER_NUM] = {{"rowid", 5}, {"rownum", 6}, {"rowscn", 6}};
    for (uint32 loop = 0; loop < ROW_CHARACTER_NUM; loop++) {
        if (cm_compare_text_ins(&res_row[loop], name) == 0) {
            return CT_SUCCESS;
        }
    }
    return CT_ERROR;
}

static inline status_t pl_get_scalar_element_datatype(void *pl_coll, ct_type_t *type)
{
    plv_collection_t *coll = (plv_collection_t *)pl_coll;
    if (coll->attr_type != UDT_SCALAR) {
        return CT_ERROR;
    }
    *type = coll->type_mode.datatype;
    return CT_SUCCESS;
}

typedef struct plc_stack_item_struct plc_stack_item_t;
struct plc_stack_item_struct {
    var_udo_t obj;
    uint32 type;
    void *entity;
    void *proc;
};
status_t pl_compile_by_user(sql_stmt_t *stmt, text_t *schema_name, bool32 compile_all);

#ifdef __cplusplus
}
#endif

#endif
