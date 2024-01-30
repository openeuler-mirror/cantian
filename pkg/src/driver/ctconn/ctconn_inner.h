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
* ctconn_inner.h
*
*
* IDENTIFICATION
* src/driver/ctconn/ctconn_inner.h
*
* -------------------------------------------------------------------------
*/
#ifndef __CTCONN_INNER_H__
#define __CTCONN_INNER_H__

#include "ctconn.h"
#include "cm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
    1. this struct is used with API:ctconn_desc_inner_column_by_id
    2. it used for inner C client tool to get column describe information
    3. 3rd user want to get column describe should use API:ctconn_get_desc_attr to ensure compatibility
*/
typedef struct st_ctconn_inner_column_desc {
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
} ctconn_inner_column_desc_t;

int ctconn_connect_inner(ctconn_conn_t pconn, const char *url, const char *user, const char *password, unsigned int version);
int ctconn_get_locator_info(ctconn_stmt_t stmt, void *locator, unsigned int *outline, unsigned int *really_sz,
    unsigned int *loc_sz);

int ctconn_read_ori_row(ctconn_stmt_t pstmt, void **ori_row, unsigned int *size);
int ctconn_get_lob_size_by_id(ctconn_stmt_t stmt, unsigned int id, unsigned int *size);
unsigned int ctconn_get_call_version(ctconn_conn_t conn);
unsigned int ctconn_get_shd_node_type(ctconn_conn_t conn);
const char *ctconn_get_version(void);
int ctconn_desc_inner_column_by_id(ctconn_stmt_t pstmt, uint32 id, ctconn_inner_column_desc_t *desc);
int ctconn_column_as_array(ctconn_stmt_t pstmt, uint32 id, char *str, uint32 buf_size);

#ifdef WIN32
void ctconn_set_gts_scn(ctconn_stmt_t *pstmt, unsigned __int64 gts_scn);
void ctconn_get_charset(ctconn_stmt_t stmt, unsigned __int16 *charset_id);
int ctconn_set_charset(ctconn_stmt_t stmt, unsigned __int16 charset_id);
#else
void ctconn_set_gts_scn(ctconn_stmt_t *pstmt, unsigned long long gts_scn);
void ctconn_get_charset(ctconn_stmt_t stmt, unsigned short *charset_id);
int ctconn_set_charset(ctconn_stmt_t pstmt, uint16 charset_id);
#endif

int ctconn_bind_value_len_by_pos(ctconn_stmt_t pstmt, uint32 pos, const void *data, uint16 *ind, bool32 is_trans,
                              bool32 ind_not_null);
int ctconn_sql_set_param_c_type(ctconn_stmt_t pstmt, uint32 pos, bool32 ctype);
int ctconn_get_autotrace_result(ctconn_stmt_t stmt);

#ifdef __cplusplus
}
#endif

#endif
