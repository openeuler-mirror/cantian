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
 * gdv_stmt.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/gdv/gdv_stmt.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_instance.h"
#include "ctsql_parser.h"
#include "cs_packet.h"
#include "gdv_context.h"
#include "gdv_stmt.h"


status_t gdv_prepare_and_exec(session_t *session, text_t *sql, sql_stmt_t **sub_stmt)
{
    sql_stmt_t *stmt = NULL;
    GDV_INVOKE(sql_alloc_stmt(session, &stmt));

    sql_release_resource(stmt, CT_TRUE);
    sql_release_context(stmt);
    sql_release_sql_map(stmt);

    stmt->session->sender = &g_instance->sql.gdv_sender;
    stmt->status = CT_TRUE;
    stmt->gdv_mode = GDVSQL_PREP;

    sql_push(stmt, sizeof(cs_packet_t), (void **)&stmt->session->send_pack); // alloc send_pack from stack.
    cs_packet_t *pack = stmt->session->send_pack;
    cs_init_packet(pack, CT_FALSE);
    pack->max_buf_size = g_instance->attr.max_allowed_packet;
    cs_init_set(pack, stmt->session->call_version);

    status_t status;
    source_location_t loc;
    loc.line = 1;
    loc.column = 1;
    status = sql_parse(stmt, sql, &loc);
    if (status != CT_SUCCESS) {
        sql_free_stmt(stmt);
        CT_SRC_THROW_ERROR(loc, ERR_PLSQL_ILLEGAL_LINE_FMT, "gdv parser sql error.");
        return CT_ERROR;
    }
    stmt->status = STMT_STATUS_PREPARED;

    if (sql_execute(stmt) != CT_SUCCESS) {
        sql_free_stmt(stmt);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(my_sender(stmt)->send_parsed_stmt(stmt));
    *sub_stmt = stmt;
    return CT_SUCCESS;
}


status_t gdv_free_stmt(session_t *session, sql_stmt_t *stmt)
{
    sql_free_stmt(stmt);
    return CT_SUCCESS;
}


status_t gdv_replace_gdv_sql_2(char *view_name, gdv_dv_map_t *map, uint32 map_size, int max_len, char *new_sql)
{
    char temp_sql[] = "select * from ";
    bool32 is_found = CT_FALSE;
    int i;

    for (i = 0; i < map_size; i++) {
        if (cm_strcmpi(map[i].gdv_name, view_name) == 0) {
            is_found = CT_TRUE;
            break;
        }
    }

    if (is_found == CT_FALSE) {
        return CT_ERROR;
    }

    uint32 len1 = 0;
    len1 = strlen(temp_sql);
    errno_t errcode = memcpy_s(new_sql, max_len - 1, temp_sql, len1);
    MEMS_RETURN_IFERR(errcode);

    uint32 len2 = strlen(map[i].dv_name);
    errcode = memcpy_s(new_sql + len1, max_len - 1 - len1, map[i].dv_name, len2);
    MEMS_RETURN_IFERR(errcode);
    len1 += len2;
    new_sql[len1] = '\0';
    return CT_SUCCESS;
}

status_t gdv_replace_gdv_sql(char *sql, gdv_dv_map_t *map, uint32 map_size, int max_len, char *new_sql)
{
    char *gdv = NULL;
    bool32 is_found = CT_FALSE;
    uint32 i;

    for (i = strlen(sql) - 1; i >= 0; i--) {
        if (*(sql + i) == ' ') {
            gdv = sql + i + 1;
            break;
        }
    }

    if (gdv == NULL) {
        return CT_ERROR;
    }

    for (i = 0; i < map_size; i++) {
        if (cm_strcmpi(map[i].gdv_name, gdv) == 0) {
            is_found = CT_TRUE;
            break;
        }
    }

    if (is_found == CT_FALSE) {
        return CT_ERROR;
    }

    uint32 len1 = 0;
    len1 = gdv - sql;
    errno_t errcode = memcpy_s(new_sql, max_len - 1, sql, len1);
    MEMS_RETURN_IFERR(errcode);

    uint32 len2 = strlen(map[i].dv_name);
    errcode = memcpy_s(new_sql + len1, max_len - 1 - len1, map[i].dv_name, len2);
    MEMS_RETURN_IFERR(errcode);
    len1 += len2;
    new_sql[len1] = '\0';
    return CT_SUCCESS;
}
