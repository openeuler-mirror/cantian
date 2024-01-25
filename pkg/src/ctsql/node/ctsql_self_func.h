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
 * ctsql_self_func.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/node/ctsql_self_func.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_SELF_FUNC_H__
#define __SQL_SELF_FUNC_H__

#include "cm_defs.h"
#include "cm_list.h"
#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_sql_self_func {
    text_t user;
    char user_buff[CT_MAX_NAME_LEN + 1];
    text_t func;
    char func_buff[CT_MAX_NAME_LEN + 1];
} sql_self_func_t;

typedef int32 (*sql_self_func_compare_t)(const text_t *text1, const text_t *text2);

status_t sql_load_self_func(void);
status_t sql_load_self_func0(const char *config_file, list_t *self_func_list);
void sql_print_self_func(void);
status_t sql_self_func_sort(void);
status_t sql_self_func_sort0(sql_self_func_compare_t compare_func);

int32 self_func_compare(text_t *user, text_t *func, sql_self_func_t *self_func, sql_self_func_compare_t compare_func);
bool32 sql_self_func_configed(text_t *user, text_t *func);
bool32 sql_self_func_configed_direct(text_t *user, text_t *func); // ignore IS_CASE_INSENSITIVE, compare direct
bool32 sql_sort_self_func_configed0(text_t *user, text_t *func, sql_self_func_compare_t compare_func);
bool32 sql_unsort_self_func_configed(text_t *user, text_t *func);
bool32 sql_unsort_self_func_configed0(text_t *user, text_t *func, sql_self_func_compare_t compare_func);

#ifdef __cplusplus
}
#endif

#endif
