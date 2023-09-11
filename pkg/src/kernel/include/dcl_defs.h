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
 * dcl_defs.h
 *
 *
 * IDENTIFICATION
 * src/kernel/include/dcl_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DCL_DEFS_H__
#define __KNL_DCL_DEFS_H__

#include "knl_defs.h"
#include "obj_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum alter_user_field {
    ALTER_USER_FIELD_PASSWORD = 0,
    ALTER_USER_FIELD_DATA_SPACE,
    ALTER_USER_FIELD_TEMP_SPACE,
    ALTER_USER_FIELD_PROFILE,
    ALTER_USER_FIELD_EXPIRE,
    ALTER_USER_FIELD_EXPIRE_GRACE,
    ALTER_USER_FIELD_LOCK,
    ALTER_USER_FIELD_LOCK_TIMED,
    ALTER_USER_FIELD_LCOUNT,
    ALTER_USER_FIELD_END,
} alter_user_field_t;

/*
 * Caution: add/delete items with g_sys_privs_def string definition.
 * new privilege item should be add at the bottom for compitable
 */
typedef enum en_sys_privs_id_def {
    ALL_PRIVILEGES = 0,
    ALTER_ANY_INDEX,
    ALTER_ANY_MATERIALIZED_VIEW,
    ALTER_ANY_PROCEDURE,
    ALTER_ANY_ROLE,
    ALTER_ANY_SEQUENCE,
    ALTER_ANY_TABLE,
    ALTER_ANY_TRIGGER,
    ALTER_DATABASE,
    ALTER_PROFILE,
    ALTER_SESSION,
    ALTER_SYSTEM,
    ALTER_TABLESPACE,
    ALTER_USER,

    CREATE_ANY_INDEX,
    CREATE_ANY_MATERIALIZED_VIEW,
    CREATE_ANY_PROCEDURE,
    CREATE_ANY_SEQUENCE,
    CREATE_ANY_SYNONYM,
    CREATE_ANY_TABLE,
    CREATE_ANY_TRIGGER,
    CREATE_ANY_VIEW,
    CREATE_DATABASE,
    CREATE_MATERIALIZED_VIEW,
    CREATE_NODE,
    CREATE_PROCEDURE,
    CREATE_PROFILE,
    CREATE_PUBLIC_SYNONYM,
    CREATE_ROLE,
    CREATE_SEQUENCE,
    CREATE_SESSION,
    CREATE_SYNONYM,
    CREATE_TABLE,
    CREATE_TABLESPACE,
    CREATE_TRIGGER,
    CREATE_USER,
    CREATE_VIEW,
    CREATE_DISTRIBUTE_RULE,

    DROP_ANY_INDEX,
    DROP_ANY_MATERIALIZED_VIEW,
    DROP_ANY_PROCEDURE,
    DROP_ANY_ROLE,
    DROP_ANY_SEQUENCE,
    DROP_ANY_SYNONYM,
    DROP_ANY_TABLE,
    DROP_ANY_TRIGGER,
    DROP_ANY_VIEW,
    DROP_PROFILE,
    DROP_PUBLIC_SYNONYM,
    DROP_TABLESPACE,
    DROP_USER,

    FLASHBACK_ANY_TABLE,
    FLASHBACK_ARCHIVE_ADMINISTER,

    GLOBAL_QUERY_REWRITE,
    GRANT_ANY_OBJECT_PRIVILEGE,
    GRANT_ANY_PRIVILEGE,
    GRANT_ANY_ROLE,
    LOCK_ANY_TABLE,
    MANAGE_TABLESPACE,
    ON_COMMIT_REFRESH,
    PURGE_DBA_RECYCLEBIN,
    READ_ANY_TABLE,
    SELECT_ANY_SEQUENCE,
    SELECT_ANY_TABLE,
    UNLIMITED_TABLESPACE,
    UNDER_ANY_VIEW,

    COMMENT_ANY_TABLE,
    UPDATE_ANY_TABLE,
    INSERT_ANY_TABLE,
    DELETE_ANY_TABLE,
    EXECUTE_ANY_PROCEDURE,
    SYSBACKUP,
    SYSDBA,
    SYSOPER,
    ANALYZE_ANY,
    DROP_NODE,
    ALTER_NODE,
    DROP_ANY_DISTRIBUTE_RULE,
    CREATE_ANY_DIRECTORY,
    DROP_ANY_DIRECTORY,
    CREATE_ANY_DISTRIBUTE_RULE,
    CREATE_ANY_SQL_MAP,
    DROP_ANY_SQL_MAP,
    CREATE_ANY_TYPE,
    CREATE_TYPE,
    DROP_ANY_TYPE,
    EXECUTE_ANY_TYPE,
    CREATE_CTRLFILE,
    CREATE_LIBRARY,
    EXEMPT_REDACTION_POLICY,
    CREATE_ANY_LIBRARY,
    DROP_ANY_LIBRARY,
    EXECUTE_ANY_LIBRARY,
    EXEMPT_ACCESS_POLICY,
    INHERIT_ANY_PRIVILEGES,
    CREATE_TENANT,
    ALTER_TENANT,
    DROP_TENANT,
    SELECT_ANY_DICTIONARY,
    FORCE_ANY_TRANSACTION,
    CREATE_DATABASE_LINK,
    ALTER_DATABASE_LINK,
    DROP_DATABASE_LINK,
    USE_ANY_TABLESPACE,
    /* GS_SYS_PRIVS_COUNT must placed at the bottom */
    GS_SYS_PRIVS_COUNT
} sys_privs_id;

// new object privilege item should be add at the bottom for compitable!!!
typedef enum en_obj_privs_id_def {
    GS_PRIV_ALTER,
    GS_PRIV_DELETE,
    GS_PRIV_EXECUTE,
    GS_PRIV_INDEX,
    GS_PRIV_INSERT,
    GS_PRIV_READ,
    GS_PRIV_REFERENCES,
    GS_PRIV_SELECT,
    GS_PRIV_UPDATE,
    GS_PRIV_DIRE_READ,
    GS_PRIV_DIRE_WRITE,
    GS_PRIV_DIRE_EXECUTE,
    /* GS_OBJ_PRIVS_COUNT must placed at the bottom */
    GS_OBJ_PRIVS_COUNT
} obj_privs_id;

// new user privilege item should be add at the bottom for compitable!!!
typedef enum en_user_privs_id_def {
    GS_PRIV_INHERIT_PRIVILEGES,
    /* GS_USER_PRIVS_COUNT must placed at the bottom */
    GS_USER_PRIVS_COUNT
} user_privs_id;

typedef enum en_priv_type_def {
    PRIV_TYPE_SYS_PRIV,
    PRIV_TYPE_OBJ_PRIV,
    PRIV_TYPE_USER_PRIV,
    PRIV_TYPE_ROLE,
    PRIV_TYPE_USER,
    PRIV_TYPE_ALL_PRIV
} priv_type_def;

typedef struct st_knl_priv_def {
    priv_type_def priv_type; /* 0: system privilege 1: object privilege, 2: role, 3: ALL PRIVILEGES */
    text_t priv_name;        /* privilege or role name, e.g. CREATE SESSION, or ROLE_TEST */
    uint32 priv_id;          /* system or object privilege id. sys_privs_id or obj_privs_id type. invalid for role */
    source_location_t start_loc;
} knl_priv_def_t;

typedef enum en_type_def {
    TYPE_USER,
    TYPE_ROLE
} type_def;

typedef struct st_knl_holders_def {
    type_def type; /* 0: user, 1: role, 2: PUBLIC */
    text_t name;   /* grantee or revokee name */
} knl_holders_def_t;

typedef struct st_knl_grant_def {
    priv_type_def priv_type; /* 0: system privilege, 1: object privilege, 2: roles to program unit */
    uint32 admin_opt;        /* with admin option ? */
    uint32 grant_opt;        /* with grant option ? */
    galist_t privs;          /* sys privs or object privs or roles list: knl_priv_def_t */
    galist_t columns;        /* object priv restricted on columns: text_t */
    galist_t grantees;       /* grantees: user, role or PUBLIC: knl_holders_def_t */
    text_t objname;          /* object's name */
    text_t schema;           /* object's schema */
    object_type_t objtype;   /* object's type : table, view, sequence or procedure */
    text_t type_name;         /* object type name, one of {"table", "view", "sequence", "procedure", "global views"} */
    galist_t privs_list;     /* for dc check */
    galist_t grantee_list;   /* for dc check */
    uint32 objowner;         /* for dc check */
    uint32 grant_uid;        /* grant user id */
} knl_grant_def_t;

typedef struct st_assist_obj_priv_item {
    uint32 objowner;                    /* object's owner user ID */
    uint32 objtype;                     /* table/view/procedure */
    uint32 privid;
    char objname[GS_NAME_BUFFER_SIZE];  /* object's name */
} assist_obj_priv_item_t;

typedef struct st_knl_revoke_def {
    priv_type_def priv_type; /* 0: system privilege, 1: object privilege, 2: roles to program unit */
    galist_t privs;          /* sys privs or object privs or roles list: knl_priv_def_t */
    galist_t revokees;       /* revokees: user, role or PUBLIC: knl_holders_def_t */
    text_t objname;          /* object's name */
    text_t schema;           /* object's schema */
    object_type_t objtype;   /* object's type : table, view, sequence or procedure */
    text_t type_name;         /* object type name, one of {"table", "view", "sequence", "procedure", "global views"} */
    uint32 cascade_opt;      /* with CASCADE CONSTRAINTS ? */
    galist_t privs_list;     /* for dc check */
    galist_t revokee_list;   /* for dc check */
    uint32 objowner;         /* for dc check */
} knl_revoke_def_t;

/*
 * privilege kernel API
 */
bool32 knl_check_sys_priv_by_name(knl_handle_t session, text_t *user, uint32 priv_id);
bool32 knl_check_sys_priv_by_uid(knl_handle_t session, uint32 uid, uint32 priv_id);
bool32 knl_check_dir_priv_by_uid(knl_handle_t session, uint32 uid, uint32 priv_id);

bool32 knl_check_obj_priv_by_name(knl_handle_t session, text_t *curr_user, text_t *obj_user, text_t *obj_name,
    object_type_t objtype, uint32 priv_id);
bool32 knl_check_obj_priv_with_option(knl_handle_t session, text_t *curr_user, text_t *obj_user, text_t *obj_name,
    object_type_t objtype, uint32 priv_id);
bool32 knl_check_user_priv_by_name(knl_handle_t session, text_t *curr_user, text_t *obj_user, uint32 priv_id);
bool32 knl_check_allobjprivs_with_option(knl_handle_t session, text_t *curr_user, text_t *obj_user,
    text_t *obj_name,
    object_type_t objtype);
status_t knl_check_obj_priv_scope(uint32 priv_id, object_type_t objtype);
void knl_get_objprivs_set(object_type_t objtype, obj_privs_id **set, uint32 *count);
bool32 knl_sys_priv_with_option(knl_handle_t session, text_t *user, uint32 priv_id);
bool32 knl_grant_role_with_option(knl_handle_t session, text_t *user, text_t *role, bool32 with_option);
status_t knl_exec_grant_privs(knl_handle_t session, knl_grant_def_t *def);
status_t knl_exec_revoke_privs(knl_handle_t session, knl_revoke_def_t *def);

typedef struct st_knl_user_def {
    char name[GS_NAME_BUFFER_SIZE];          // username
    char password[GS_PASSWORD_BUFFER_SIZE];  // if it comes from sql engine ,it's pwd string before encrypt.
    // if it comes from kernel, it's pwd string after encrypt.
    char old_password[GS_PASSWORD_BUFFER_SIZE];
    bool32 is_sys;
    bool32 is_readonly;
    bool32 is_permanent;
    struct {
        bool32 is_expire : 1;
        bool32 is_expire_grace : 1;
        bool32 is_lock : 1;
        bool32 is_lock_timed : 1;
        bool32 is_lcount_clear : 1;
        bool32 is_for_create_db : 1;
        bool32 unused : 26;
    };
    uint32 mask;
    char temp_space[GS_NAME_BUFFER_SIZE];
    char default_space[GS_NAME_BUFFER_SIZE];
    text_t profile;
    uint32 pwd_len;
    uint32 pwd_loc;
    bool32 is_encrypt;
    uint32 tenant_id;
} knl_user_def_t;

typedef struct st_knl_drop_user_def {
    text_t owner;
    bool32 purge;
    uint32 options;
} knl_drop_user_t;

typedef struct st_knl_drop_tenant_def {
    text_t name;
    bool32 purge;
    uint32 options;

    CM_MAGIC_DECLARE
} knl_drop_tenant_t;
#define knl_drop_tenant_t_MAGIC 48991555

typedef struct st_knl_role_def {
    uint32 owner_uid;                       /* user id that create the role */
    char name[GS_NAME_BUFFER_SIZE];         /* role name */
    char password[GS_PASSWORD_BUFFER_SIZE]; /* role pwd */
    text_t owner;                           /* user that created the role */
    uint32 pwd_len;
    uint32 pwd_loc;
    bool32 is_encrypt;
} knl_role_def_t;

typedef enum en_alter_tenant_sub_type {
    ALTER_TENANT_TYPE_ADD_SPACE = 0,
    ALTER_TENANT_TYPE_MODEIFY_DEFAULT,
} alter_tenant_sub_type_t;

typedef struct st_knl_tenant_def {
    char name[GS_TENANT_BUFFER_SIZE];             /* tenant name */
    char default_tablespace[GS_NAME_BUFFER_SIZE]; /* default tablespace */
    galist_t space_lst;                           /* usable tablespace for current tenant */
    uint32 sub_type;                              /* ALTER_TENANT_TYPE_ADD_SPACE/ALTER_TENANT_TYPE_MODEIFY_DEFAULT */

    CM_MAGIC_DECLARE
} knl_tenant_def_t;
#define knl_tenant_def_t_MAGIC   211984188

status_t knl_create_user(knl_handle_t session, knl_user_def_t *def);
status_t knl_drop_user(knl_handle_t session, knl_drop_user_t *def);
status_t knl_alter_user(knl_handle_t session, knl_user_def_t *def);
status_t knl_create_role(knl_handle_t session, knl_role_def_t *def);
status_t knl_drop_role(knl_handle_t session, knl_drop_def_t *def);
status_t knl_create_tenant(knl_handle_t session, knl_tenant_def_t *def);
status_t knl_drop_tenant(knl_handle_t session, knl_drop_tenant_t *def);
status_t knl_get_user_name(knl_handle_t session, uint32 id, text_t *name);
bool32 knl_get_user_id(knl_handle_t session, text_t *name, uint32 *uid);
bool32 knl_get_role_id(knl_handle_t session, text_t *name, uint32 *rid);
status_t knl_get_tenant_id(knl_handle_t session, text_t *name, uint32 *tid);

status_t knl_check_user_lock(knl_handle_t session, text_t *user);
status_t knl_check_user_lock_timed(knl_handle_t session, text_t *user, bool32 *p_lock_unlock);
status_t knl_check_user_expire(knl_handle_t session, text_t *user, char *message, uint32 message_len);
status_t knl_process_failed_login(knl_handle_t session, text_t *user, uint32 *p_lock_unlock);
bool32 knl_chk_user_status(knl_handle_t session, uint32 id);
status_t knl_check_user_tables(knl_handle_t session, uint32 uid, bool32 *isfound);
#ifdef __cplusplus
}
#endif

#endif
