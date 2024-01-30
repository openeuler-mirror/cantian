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
 * pl_dbg_pack.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/debug/pl_dbg_pack.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_DBG_PACK_H__
#define __PL_DBG_PACK_H__

#include "pl_debugger.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FROZEN_WAIT_TIME_S 5

typedef struct st_sql_add_break_arg {
    text_t owner;
    text_t proc_name;
    uint32 pl_type;
    uint32 line_number;
    uint32 max_skip_times;
    text_t cond;
} sql_add_break_arg_t;


status_t sql_debug_add_break(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_debug_add_break(sql_verifier_t *verif, expr_node_t *func);

status_t sql_debug_attach(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_debug_attach(sql_verifier_t *verif, expr_node_t *func);

status_t sql_debug_del_break(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_debug_del_break(sql_verifier_t *verif, expr_node_t *func);

status_t sql_debug_del_break_by_name(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_debug_del_break_by_name(sql_verifier_t *verif, expr_node_t *func);

status_t sql_debug_detach(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_debug_detach(sql_verifier_t *verif, expr_node_t *func);

status_t sql_debug_get_status(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_debug_get_status(sql_verifier_t *verif, expr_node_t *func);

status_t sql_debug_get_value(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_debug_get_value(sql_verifier_t *verif, expr_node_t *func);

status_t sql_debug_get_version(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_debug_get_version(sql_verifier_t *verif, expr_node_t *func);

status_t sql_debug_init(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_debug_init(sql_verifier_t *verif, expr_node_t *func);

status_t sql_debug_pause(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_no_argument(sql_verifier_t *verif, expr_node_t *func);

status_t sql_debug_resume(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_debug_resume(sql_verifier_t *verif, expr_node_t *func);

status_t sql_debug_set_break(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_debug_set_break(sql_verifier_t *verif, expr_node_t *func);

status_t sql_debug_set_curr_count(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_debug_set_curr_count(sql_verifier_t *verif, expr_node_t *func);

status_t sql_debug_set_value(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_debug_set_value(sql_verifier_t *verif, expr_node_t *func);

status_t sql_debug_terminate(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);

status_t sql_debug_uninit(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);

status_t sql_debug_update_break(sql_stmt_t *stmt, expr_node_t *func, variant_t *result);
status_t sql_verify_debug_update_break(sql_verifier_t *verif, expr_node_t *func);


#ifdef __cplusplus
}
#endif

#endif
