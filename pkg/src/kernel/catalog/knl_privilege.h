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
 * knl_privilege.h
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/knl_privilege.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef KNL_PRIVILEGE_H
#define KNL_PRIVILEGE_H

#include "cm_defs.h"
#include "cm_memory.h"
#include "knl_interface.h"
#include "knl_log.h"
#include "knl_privilege_persistent.h"

#ifdef __cplusplus
extern "C" {
#endif

/* privileges operation macro */
#define DC_SET_SYS_PRIV(privs, id) ((privs)[(id) / 8] |= (0x1 << ((id) % 8)))
#define DC_GET_SYS_PRIV(privs, id) (((privs)[(id) / 8] >> ((id) % 8)) & 0x01)
#define DC_CLR_SYS_PRIV(privs, id) ((privs)[(id) / 8] &= ~(0x1 << ((id) % 8)))
#define DC_HAS_SYS_PRIV(privs, id) (1 == (((privs)[(id) / 8] >> ((id) % 8)) & 0x01))

#define DC_SET_SYS_OPT(option, id) ((option)[(id) / 8] |= (0x1 << ((id) % 8)))
#define DC_GET_SYS_OPT(option, id) (((option)[(id) / 8] >> ((id) % 8)) & 0x01)
#define DC_CLR_SYS_OPT(option, id) ((option)[(id) / 8] &= ~(uint32)(0x1 << ((id) % 8)))
#define DC_HAS_SYS_OPT(option, id) (1 == (((option)[(id) / 8] >> ((id) % 8)) & 0x01))

#define DC_SET_OBJ_PRIV(privs, id) CT_BIT_SET((privs), CT_GET_MASK(id))
#define DC_GET_OBJ_PRIV(privs, id) CT_BIT_TEST((privs), CT_GET_MASK(id))
#define DC_CLR_OBJ_PRIV(privs, id) CT_BIT_RESET(privs, CT_GET_MASK(id))
#define DC_HAS_OBJ_PRIV(privs, id) (DC_GET_OBJ_PRIV(privs, id) != 0)

#define DC_SET_OBJ_OPT(option, id) CT_BIT_SET((option), CT_GET_MASK(id))
#define DC_GET_OBJ_OPT(option, id) CT_BIT_TEST((option), CT_GET_MASK(id))
#define DC_CLR_OBJ_OPT(option, id) CT_BIT_RESET(option, CT_GET_MASK(id))
#define DC_HAS_OBJ_OPT(option, id) (DC_GET_OBJ_PRIV(option, id) != 0)
#define DC_GET_OBJPRIV_ENTRY(obj_privs, oid) (obj_privs)->groups[(oid) / DC_GROUP_SIZE]->entries[(oid) % DC_GROUP_SIZE]

#define DC_SET_PRIV_INFO(privs, option, id, admin_opt) \
    do {                                               \
        DC_SET_SYS_PRIV(privs, id);                    \
        if (1 == (admin_opt)) {                        \
            DC_SET_SYS_OPT(option, id);                \
        } else {                                       \
            DC_CLR_SYS_OPT(option, id);                \
        }                                              \
    } while (0)

typedef struct st_grant_role_t {
    priv_type_def type;
    pointer_t handle;
} grant_role_t;

typedef struct st_priv_t {
    priv_type_def type;
    uint32 id;
} priv_t;

typedef struct st_holder_t {
    type_def type;
    pointer_t handle;
} hold_t;

typedef struct st_sys_priv_name_id_def {
    sys_privs_id spid;
    char *name;
} sys_priv_name_id;

typedef struct st_obj_priv_name_id_def {
    obj_privs_id opid;
    char *name;
} obj_priv_name_id;

typedef struct st_dire_priv_name_id_def {
    obj_privs_id opid;
    char *name;
} dire_priv_name_id;

typedef struct st_user_priv_name_id_def {
    user_privs_id opid;
    char *name;
} user_priv_name_id;

typedef status_t (*priv_proc_func)(knl_handle_t session, void *def,
    knl_holders_def_t *grantee, knl_priv_def_t *priv);
typedef void (*dc_update_proc_func)(knl_handle_t session, void *def, void *privs, hold_t *h);

typedef struct st_knl_priv_proc_tab {
    priv_type_def priv_type;
    type_def grantee_type;
    priv_proc_func proc_func;
} knl_priv_proc_tab;

typedef struct st_knl_dc_update_proc_tab {
    priv_type_def priv_type;
    type_def grantee_type;
    dc_update_proc_func proc_func;
} knl_dc_update_proc_tab;

#define CT_MAX_GRANT_USERS ((KNL_LOGIC_LOG_BUF_SIZE - LOG_ENTRY_SIZE) / sizeof(rd_privs_t))

#define DC_CLR_PRIV_INFO(privs, option, id) \
    do {                                    \
        DC_CLR_SYS_PRIV(privs, id);         \
        DC_CLR_SYS_OPT(option, id);         \
    } while (0)

/*
 * fucntion definition
 */
bool32 knl_sys_priv_match(text_t *priv_name, sys_privs_id *spid);
bool32 knl_obj_priv_match(text_t *priv_name, obj_privs_id *opid);
bool32 knl_user_priv_match(text_t *priv_name, user_privs_id *upid);

status_t db_exec_grant_privs(knl_session_t *session, knl_grant_def_t *def);
status_t db_exec_revoke_privs(knl_session_t *session, knl_revoke_def_t *def);
status_t db_drop_object_privs(knl_session_t *session, uint32 uid, const char *objname, uint32 type);
status_t db_update_objname_for_priv(knl_handle_t session, uint32 uid, const char *oldname, text_t *newname,
                                    uint32 type);
status_t db_insert_user_privs(knl_handle_t session, uint32 uid, uint32 grantor_id, uint32 grantee_id,
    uint32 priv_type);
status_t db_delete_all_privs_by_id(knl_session_t *session, uint32 id, uint32 type);
status_t db_grant_dirpriv_to_user(knl_session_t *session, char *dir_name, uint32 uid, uint32 priv_id);
status_t db_revoke_dirpriv_from_grantee(knl_session_t *session, uint32 grantor_id, uint32 grantee_id,
                                        uint32 grantee_type, assist_obj_priv_item_t *item);

bool32 db_check_dirpriv_by_uid(knl_session_t *session, char *objname, uint32 uid, uint32 priv_id);
void rd_alter_privs(knl_session_t *session, log_entry_t *log);
void print_grant_privs(log_entry_t *log);
void print_revoke_privs(log_entry_t *log);

#ifdef __cplusplus
}
#endif

#endif

