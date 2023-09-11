/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * gsc_inner.h
 *
 *
 * IDENTIFICATION
 * src/driver/gsc/gsc_inner.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __GSC_INNER_H__
#define __GSC_INNER_H__

#include "gsc.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
    1. this struct is used with API:gsc_desc_inner_column_by_id
    2. it used for inner C client tool to get column describe information
    3. 3rd user want to get column describe should use API:gsc_get_desc_attr to ensure compatibility
*/
typedef struct st_gsc_inner_column_desc {
    char *name;
    unsigned short size;
    unsigned char precision;
    char scale;
    unsigned short type;
    unsigned char nullable;
    unsigned char is_character;
    unsigned char is_array;
    unsigned char is_jsonb;
    unsigned char auto_increment;
} gsc_inner_column_desc_t;

int gsc_connect_inner(gsc_conn_t pconn, const char *url, const char *user, const char *password, unsigned int version);
int gsc_get_locator_info(gsc_stmt_t stmt, void *locator, unsigned int *outline, unsigned int *really_sz,
    unsigned int *loc_sz);

int gsc_read_ori_row(gsc_stmt_t stmt, void **ori_row, unsigned int *size);
int gsc_get_lob_size_by_id(gsc_stmt_t stmt, unsigned int id, unsigned int *size);
unsigned int gsc_get_call_version(gsc_conn_t conn);
unsigned int gsc_get_shd_node_type(gsc_conn_t conn);
const char *gsc_get_version();
int gsc_desc_inner_column_by_id(gsc_stmt_t stmt, unsigned int id, gsc_inner_column_desc_t *desc);
int gsc_column_as_array(gsc_stmt_t pstmt, unsigned int id, char *str, unsigned int buf_size);

#ifdef WIN32
void gsc_set_gts_scn(gsc_stmt_t *pstmt, unsigned __int64 gts_scn);
void gsc_get_charset(gsc_stmt_t stmt, unsigned __int16 *charset_id);
int gsc_set_charset(gsc_stmt_t stmt, unsigned __int16 charset_id);
#else
void gsc_set_gts_scn(gsc_stmt_t *pstmt, unsigned long long gts_scn);
void gsc_get_charset(gsc_stmt_t stmt, unsigned short *charset_id);
int gsc_set_charset(gsc_stmt_t stmt, unsigned short charset_id);
#endif

int gsc_bind_value_len_by_pos(gsc_stmt_t pstmt, unsigned int pos, const void *data, unsigned short *ind,
    unsigned int is_trans, unsigned int ind_not_null);
int gsc_sql_set_param_c_type(gsc_stmt_t pstmt, unsigned int pos, unsigned int ctype);
int gsc_get_autotrace_result(gsc_stmt_t stmt);

#ifdef __cplusplus
}
#endif

#endif
