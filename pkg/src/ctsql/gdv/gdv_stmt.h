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
 * gdv_stmt.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/gdv/gdv_stmt.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GDV_STMT_H__
#define __GDV_STMT_H__

#include "srv_session.h"
#include "ctsql_stmt.h"
#include "cm_text.h"
#include "dtc_view.h"


#define GDV_INVOKE(func)        \
    if ((func) != CT_SUCCESS) { \
        return CT_ERROR;        \
    }

typedef struct st_gdv_dv_map {
    // uint32 id;
    char *gdv_name;
    char *dv_name;
} gdv_dv_map_t;

status_t gdv_prepare_and_exec(session_t *session, text_t *sql, sql_stmt_t **sub_stmt);
status_t gdv_free_stmt(session_t *session, sql_stmt_t *stmt);
status_t gdv_replace_gdv_sql(char *sql, gdv_dv_map_t *map, uint32 map_size, int max_len, char *new_sql);
status_t gdv_replace_gdv_sql_2(char *view_name, gdv_dv_map_t *map, uint32 map_size, int max_len, char *new_sql);
extern instance_t *g_instance;

#endif
