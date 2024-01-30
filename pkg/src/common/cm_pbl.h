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
 * cm_pbl.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_pbl.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_PBL_H__
#define __CM_PBL_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PBL_FILENAME "pbl.conf"
#define CT_MAX_PBL_FILE_SIZE        SIZE_M(100)
#define CT_MIN_PBL_FILE_SIZE        SIZE_M(10)
#define CT_MAX_PBL_LINE_SIZE        (CT_PBL_PASSWD_MAX_LEN + CT_MAX_NAME_LEN + 1)

typedef struct st_pbl_entry {
    char user[CT_NAME_BUFFER_SIZE];
    SENSI_INFO char pwd[CT_PWD_BUFFER_SIZE];
} pbl_entry_t;
typedef struct st_black_context {
    spinlock_t lock;

    // user pwd black list(pbl) from pbl.conf
    list_t user_pwd_black_list;  // pbl_entry_t
} black_context_t;

bool32 cm_check_pwd_black_list(black_context_t *ctx, const char *name, char *passwd, char *log_pwd);
status_t cm_load_pbl(black_context_t *ctx, const char *file_name, uint32 buf_len);
#ifdef __cplusplus
}
#endif
#endif