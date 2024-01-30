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
 * ctsql_self_func.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/node/ctsql_self_func.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_self_func.h"
#include "cm_file.h"
#include "srv_instance.h"

static char *g_self_func_config = "udf.ini";

static inline status_t copy_self_func(sql_self_func_t *func_src, sql_self_func_t *func_dst)
{
    MEMS_RETURN_IFERR(memcpy_s(func_dst->user_buff, sizeof(func_dst->user_buff), func_src->user_buff,
        sizeof(func_src->user_buff)));

    MEMS_RETURN_IFERR(memcpy_s(func_dst->func_buff, sizeof(func_dst->func_buff), func_src->func_buff,
        sizeof(func_src->func_buff)));

    func_dst->user.len = func_src->user.len;
    func_dst->func.len = func_src->func.len;
    func_dst->user.str = func_dst->user_buff;
    func_dst->func.str = func_dst->func_buff;

    return CT_SUCCESS;
}

status_t sql_load_self_func(void)
{
    char file_name[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    list_t *self_func_list = &g_instance->sql.self_func_list;

    // get config info
    PRTS_RETURN_IFERR(snprintf_s(file_name, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s/cfg/%s",
        g_instance->home, g_self_func_config));

    return sql_load_self_func0(file_name, self_func_list);
}

status_t sql_load_self_func0(const char *config_file, list_t *self_func_list)
{
    char *buffer = NULL;
    uint32 buf_size;
    text_t text, line, user, func, default_user;
    sql_self_func_t *self_func = NULL;
    int32 fp;
    errno_t rc_memzero;

    default_user.str = "SYS";
    default_user.len = SYS_USER_NAME_LEN;

    // create the list
    cm_create_list(self_func_list, sizeof(sql_self_func_t));

    if (!cm_file_exist(config_file) || cm_open_file(config_file, O_RDONLY, &fp) != CT_SUCCESS) {
        cm_reset_error();
        return CT_SUCCESS;
    }
    buffer = (char *)malloc(SIZE_K(64));
    if (buffer == NULL) {
        cm_close_file(fp);
        return CT_ERROR;
    }
    rc_memzero = memset_s(buffer, SIZE_K(64), 0, SIZE_K(64));
    if (rc_memzero != EOK) {
        cm_close_file(fp);
        CM_FREE_PTR(buffer);
        return CT_ERROR;
    }
    if (cm_read_file(fp, buffer, SIZE_K(64), (int32 *)&buf_size) != CT_SUCCESS) {
        cm_close_file(fp);
        CM_FREE_PTR(buffer);
        return CT_ERROR;
    }

    text.len = buf_size;
    text.str = buffer;

    while (cm_fetch_text(&text, '\n', '\0', &line)) {
        if (line.len == 0) {
            continue;
        }

        cm_trim_text(&line);
        cm_split_text(&line, '.', '\0', &user, &func);

        if (func.len == 0) { // only config function,no user name.
            func = user;
            user = default_user;
        }

        if (sql_unsort_self_func_configed(&user, &func)) { // ignore duplicate config.
            continue;
        }

        if (cm_list_new(self_func_list, (void *)&self_func) == CT_ERROR) {
            cm_close_file(fp);
            CM_FREE_PTR(buffer);
            return CT_ERROR;
        }

        if (user.len >= sizeof(self_func->user_buff) || func.len >= sizeof(self_func->func_buff)) {
            CT_LOG_RUN_ERR("user or function length larger than max size %lu in file %s.", sizeof(self_func->user_buff),
                config_file);
            cm_close_file(fp);
            CM_FREE_PTR(buffer);
            return CT_ERROR;
        }

        if (cm_text2str(&user, self_func->user_buff, sizeof(self_func->user_buff)) == CT_ERROR) {
            cm_close_file(fp);
            CM_FREE_PTR(buffer);
            return CT_ERROR;
        }
        if (cm_text2str(&func, self_func->func_buff, sizeof(self_func->func_buff)) == CT_ERROR) {
            cm_close_file(fp);
            CM_FREE_PTR(buffer);
            return CT_ERROR;
        }

        self_func->user.str = self_func->user_buff;
        self_func->user.len = MIN(user.len, sizeof(self_func->user_buff));
        self_func->func.str = self_func->func_buff;
        self_func->func.len = MIN(func.len, sizeof(self_func->func_buff));

        self_func = NULL;
    }

    CM_FREE_PTR(buffer);
    cm_close_file(fp);
    return sql_self_func_sort(); // do sort
}

status_t sql_self_func_sort(void)
{
    if (IS_CASE_INSENSITIVE) {
        return sql_self_func_sort0(cm_compare_text_ins);
    } else {
        return sql_self_func_sort0(cm_compare_text);
    }
}

status_t sql_self_func_sort0(sql_self_func_compare_t compare_func)
{
    list_t *func_list = &g_instance->sql.self_func_list;
    sql_self_func_t *self_func = NULL;
    sql_self_func_t *sql_func_first = NULL;
    sql_self_func_t *sql_func_min = NULL;
    sql_self_func_t swap_buff;
    uint32 begin = 0;
    if (func_list->count <= 1) {
        return CT_SUCCESS;
    }

    for (; begin < func_list->count - 1; begin++) {
        sql_func_first = (sql_self_func_t *)cm_list_get(func_list, begin);
        sql_func_min = sql_func_first;
        for (uint32 i = begin + 1; i < func_list->count; i++) {
            self_func = (sql_self_func_t *)cm_list_get(func_list, i);
            if (self_func_compare(&self_func->user, &self_func->func, sql_func_min, compare_func) < 0) {
                sql_func_min = self_func;
            }
        }
        if (sql_func_min != sql_func_first) {
            CT_RETURN_IFERR(copy_self_func(sql_func_first, &swap_buff));
            CT_RETURN_IFERR(copy_self_func(sql_func_min, sql_func_first));
            CT_RETURN_IFERR(copy_self_func(&swap_buff, sql_func_min));
        }
    }

    return CT_SUCCESS;
}

void sql_print_self_func(void)
{
    list_t *func_list = &g_instance->sql.self_func_list;
    sql_self_func_t *self_func = NULL;

    for (uint32 i = 0; i < func_list->count; i++) {
        self_func = (sql_self_func_t *)cm_list_get(func_list, i);
        CT_LOG_RUN_INF("[SELF_FUNC-%u] %s.%s", i, self_func->user_buff, self_func->func_buff);
    }
}

// user,func > self_func 1
int32 self_func_compare(text_t *user, text_t *func, sql_self_func_t *self_func, sql_self_func_compare_t compare_func)
{
    /* user name is not case sensitive */
    int32 user_cmp = cm_compare_text_ins(user, &self_func->user);
    int32 func_cmp;
    if (user_cmp == 0) {
        func_cmp = compare_func(func, &self_func->func);
        return func_cmp;
    } else {
        return user_cmp;
    }
}

bool32 sql_self_func_configed_direct(text_t *user, text_t *func)
{
    return sql_sort_self_func_configed0(user, func, cm_compare_text);
}

bool32 sql_self_func_configed(text_t *user, text_t *func)
{
    if (IS_CASE_INSENSITIVE) {
        return sql_sort_self_func_configed0(user, func, cm_compare_text_ins);
    } else {
        return sql_sort_self_func_configed0(user, func, cm_compare_text);
    }
}

bool32 sql_unsort_self_func_configed(text_t *user, text_t *func)
{
    return sql_unsort_self_func_configed0(user, func, cm_compare_text);
}

bool32 sql_unsort_self_func_configed0(text_t *user, text_t *func, sql_self_func_compare_t compare_func)
{
    list_t *func_list = &g_instance->sql.self_func_list;
    sql_self_func_t *self_func = NULL;

    for (uint32 i = 0; i < func_list->count; i++) {
        self_func = (sql_self_func_t *)cm_list_get(func_list, i);
        if (compare_func(&self_func->user, user) == 0 && compare_func(&self_func->func, func) == 0) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

bool32 sql_sort_self_func_configed0(text_t *user, text_t *func, sql_self_func_compare_t compare_func)
{
    list_t *func_list = &g_instance->sql.self_func_list;
    int32 begin = 0;
    int32 end = (int32)func_list->count - 1;
    int32 mid;
    sql_self_func_t *self_func = NULL;
    int32 compare_result;

    if (func_list->count == 0) { // empty list
        return CT_FALSE;
    }

    while (begin <= end) {
        mid = (begin + end) / 2;
        self_func = (sql_self_func_t *)cm_list_get(func_list, mid);
        compare_result = self_func_compare(user, func, self_func, compare_func);
        if (compare_result == 0) {
            return CT_TRUE;
        } else if (compare_result < 0) { // when to_found < mid
            end = mid - 1;
        } else { // when to_found > mid
            begin = mid + 1;
        }
    }

    return CT_FALSE;
}
