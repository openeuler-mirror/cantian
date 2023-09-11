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
 * knl_user.h
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/knl_user.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef KNL_USER_H
#define KNL_USER_H

#include "cm_defs.h"
#include "cm_memory.h"
#include "knl_interface.h"
#include "knl_log.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_rd_user {
    logic_op_t op_type;
    uint32 uid;
    char name[GS_NAME_BUFFER_SIZE];
    char password[GS_PASSWORD_BUFFER_SIZE];
    date_t ctime;       // user account creation time
    date_t ptime;       // pwd change time
    date_t exptime;     // actual pwd expiration time
    date_t ltime;       // time when account is locked
    uint32 profile_id;  // resource profile#
    uint32 astatus;     // status of the account.
    uint32 lcount;      // count of failed login attempts
    uint32 data_space_id;
    uint64 data_space_org_scn;
    uint32 temp_space_id;
    uint32 tenant_id;
} rd_user_t;

typedef struct st_rd_role {
    logic_op_t op_type;
    uint32 rid;
    char name[GS_NAME_BUFFER_SIZE];
} rd_role_t;

object_type_t knl_char_pltype_to_objtype(char type);
status_t user_alter(knl_session_t *session, knl_user_def_t *def);
status_t user_create(knl_session_t *session, knl_user_def_t *def);
status_t user_drop(knl_session_t *session, knl_drop_user_t *def);
status_t user_create_role(knl_session_t *session, knl_role_def_t *def);
status_t user_drop_role(knl_session_t *session, knl_drop_def_t *def);
status_t user_encrypt_password(const char *alg, uint32 iter_count, char *plain, uint32 plain_len, char *cipher,
    uint32 cipher_len);

#ifdef __cplusplus
}
#endif

#endif

