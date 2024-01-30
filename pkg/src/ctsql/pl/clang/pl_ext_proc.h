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
 * pl_ext_proc.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/clang/pl_ext_proc.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_EXT_PROC_H__
#define __PL_EXT_PROC_H__

#include "pl_dc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EXT_WAIT_TIMEOUT 1000 // ms

typedef struct st_ext_assit {
    pl_dc_t *body_dc;
    pl_dc_t *func_dc;
    pl_library_t *library;
    function_t *func;
    uint64 oid;
    uint32 args_num;
    bool8 is_func;
    bool8 is_pak;
    bool8 is_exec_func;
    uint8 unused;
} ext_assist_t;

status_t pl_clear_sym_cache(knl_handle_t se, uint32 lib_uid, char *name, char *lib_path);
status_t ple_exec_call_clang_func_core(sql_stmt_t *stmt, expr_node_t *node, variant_t *result, ext_assist_t *assist);
#ifdef __cplusplus
}
#endif

#endif
