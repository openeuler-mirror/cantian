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
 * knl_privilege.c
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/knl_privilege.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_privilege.h"
#include "knl_context.h"
#include "dc_priv.h"
#include "dc_log.h"
#include "knl_external.h"
#include "dtc_dls.h"

#ifdef __cplusplus
extern "C" {
#endif

/* order by name. !!! Caution: add/delete items with sys_privs_id datatype */
sys_priv_name_id g_sys_privs_def[] = {
    { ALL_PRIVILEGES,              "ALL PRIVILEGES" },
    { ALTER_ANY_INDEX,             "ALTER ANY INDEX" },
    { ALTER_ANY_MATERIALIZED_VIEW, "ALTER ANY MATERIALIZED VIEW" },
    { ALTER_ANY_PROCEDURE,         "ALTER ANY PROCEDURE" },
    { ALTER_ANY_ROLE,              "ALTER ANY ROLE" },
    { ALTER_ANY_SEQUENCE,          "ALTER ANY SEQUENCE" },
    { ALTER_ANY_TABLE,             "ALTER ANY TABLE" },
    { ALTER_ANY_TRIGGER,           "ALTER ANY TRIGGER" },
    { ALTER_DATABASE,              "ALTER DATABASE" },
    { ALTER_DATABASE_LINK,         "ALTER DATABASE LINK" },
    { ALTER_NODE,                  "ALTER NODE" },
    { ALTER_PROFILE,               "ALTER PROFILE" },
    { ALTER_SESSION,               "ALTER SESSION" },
    { ALTER_SYSTEM,                "ALTER SYSTEM" },
    { ALTER_TABLESPACE,            "ALTER TABLESPACE" },
    { ALTER_TENANT,                "ALTER TENANT" },
    { ALTER_USER,                  "ALTER USER" },
    { ANALYZE_ANY,                 "ANALYZE ANY" },

    { COMMENT_ANY_TABLE,            "COMMENT ANY TABLE" },
    { CREATE_ANY_DIRECTORY,         "CREATE ANY DIRECTORY"},
    { CREATE_ANY_DISTRIBUTE_RULE,   "CREATE ANY DISTRIBUTE RULE" },
    { CREATE_ANY_INDEX,             "CREATE ANY INDEX" },
    { CREATE_ANY_LIBRARY,           "CREATE ANY LIBRARY" },
    { CREATE_ANY_MATERIALIZED_VIEW, "CREATE ANY MATERIALIZED VIEW" },
    { CREATE_ANY_PROCEDURE,         "CREATE ANY PROCEDURE" },
    { CREATE_ANY_SEQUENCE,          "CREATE ANY SEQUENCE" },
    { CREATE_ANY_SQL_MAP,           "CREATE ANY SQL MAP" },
    { CREATE_ANY_SYNONYM,           "CREATE ANY SYNONYM" },
    { CREATE_ANY_TABLE,             "CREATE ANY TABLE" },
    { CREATE_ANY_TRIGGER,           "CREATE ANY TRIGGER" },
    { CREATE_ANY_TYPE,              "CREATE ANY TYPE" },
    { CREATE_ANY_VIEW,              "CREATE ANY VIEW" },
    { CREATE_CTRLFILE,              "CREATE CTRLFILE"},
    { CREATE_DATABASE,              "CREATE DATABASE" },
    { CREATE_DATABASE_LINK,         "CREATE DATABASE LINK" },
    { CREATE_DISTRIBUTE_RULE,       "CREATE DISTRIBUTE RULE" },
    { CREATE_LIBRARY,               "CREATE LIBRARY" },
    { CREATE_MATERIALIZED_VIEW,     "CREATE MATERIALIZED VIEW" },
    { CREATE_NODE,                  "CREATE NODE" },
    { CREATE_PROCEDURE,             "CREATE PROCEDURE" },
    { CREATE_PROFILE,               "CREATE PROFILE" },
    { CREATE_PUBLIC_SYNONYM,        "CREATE PUBLIC SYNONYM" },
    { CREATE_ROLE,                  "CREATE ROLE" },
    { CREATE_SEQUENCE,              "CREATE SEQUENCE" },
    { CREATE_SESSION,               "CREATE SESSION" },
    { CREATE_SYNONYM,               "CREATE SYNONYM" },
    { CREATE_TABLE,                 "CREATE TABLE" },
    { CREATE_TABLESPACE,            "CREATE TABLESPACE" },
    { CREATE_TENANT,                "CREATE TENANT" },
    { CREATE_TRIGGER,               "CREATE TRIGGER" },
    { CREATE_TYPE,                  "CREATE TYPE" },
    { CREATE_USER,                  "CREATE USER" },
    { CREATE_VIEW,                  "CREATE VIEW" },

    { DELETE_ANY_TABLE,           "DELETE ANY TABLE" },
    { DROP_ANY_DIRECTORY,         "DROP ANY DIRECTORY" },
    { DROP_ANY_DISTRIBUTE_RULE,   "DROP ANY DISTRIBUTE RULE" },
    { DROP_ANY_INDEX,             "DROP ANY INDEX" },

    { DROP_ANY_LIBRARY,           "DROP ANY LIBRARY" },
    { DROP_ANY_MATERIALIZED_VIEW, "DROP ANY MATERIALIZED VIEW" },
    { DROP_ANY_PROCEDURE,         "DROP ANY PROCEDURE" },
    { DROP_ANY_ROLE,              "DROP ANY ROLE" },
    { DROP_ANY_SEQUENCE,          "DROP ANY SEQUENCE" },
    { DROP_ANY_SQL_MAP,           "DROP ANY SQL MAP" },
    { DROP_ANY_SYNONYM,           "DROP ANY SYNONYM" },
    { DROP_ANY_TABLE,             "DROP ANY TABLE" },
    { DROP_ANY_TRIGGER,           "DROP ANY TRIGGER" },
    { DROP_ANY_TYPE,              "DROP ANY TYPE" },
    { DROP_ANY_VIEW,              "DROP ANY VIEW" },
    { DROP_DATABASE_LINK,         "DROP DATABASE LINK" },
    { DROP_NODE,                  "DROP NODE" },
    { DROP_PROFILE,               "DROP PROFILE" },
    { DROP_PUBLIC_SYNONYM,        "DROP PUBLIC SYNONYM" },
    { DROP_TABLESPACE,            "DROP TABLESPACE" },
    { DROP_TENANT,                "DROP TENANT" },
    { DROP_USER,                  "DROP USER" },

    { EXECUTE_ANY_LIBRARY,   "EXECUTE ANY LIBRARY" },
    { EXECUTE_ANY_PROCEDURE, "EXECUTE ANY PROCEDURE" },
    { EXECUTE_ANY_TYPE,      "EXECUTE ANY TYPE" },
    { EXEMPT_ACCESS_POLICY,        "EXEMPT ACCESS POLICY" },
    { EXEMPT_REDACTION_POLICY,     "EXEMPT REDACTION POLICY" },

    { FLASHBACK_ANY_TABLE, "FLASHBACK ANY TABLE" },
    { FLASHBACK_ARCHIVE_ADMINISTER, "FLASHBACK ARCHIVE ADMINISTER" },
    { FORCE_ANY_TRANSACTION, "FORCE ANY TRANSACTION" },

    { GLOBAL_QUERY_REWRITE,       "GLOBAL QUERY REWRITE" },
    { GRANT_ANY_OBJECT_PRIVILEGE, "GRANT ANY OBJECT PRIVILEGE" },
    { GRANT_ANY_PRIVILEGE,        "GRANT ANY PRIVILEGE" },
    { GRANT_ANY_ROLE,             "GRANT ANY ROLE" },

    { INHERIT_ANY_PRIVILEGES, "INHERIT ANY PRIVILEGES" },
    { INSERT_ANY_TABLE, "INSERT ANY TABLE" },

    { LOCK_ANY_TABLE, "LOCK ANY TABLE" },

    { MANAGE_TABLESPACE, "MANAGE TABLESPACE" },

    { ON_COMMIT_REFRESH, "ON COMMIT REFRESH" },

    { PURGE_DBA_RECYCLEBIN, "PURGE DBA_RECYCLEBIN" },

    { READ_ANY_TABLE, "READ ANY TABLE" },
    { SELECT_ANY_DICTIONARY, "SELECT ANY DICTIONARY" },
    { SELECT_ANY_SEQUENCE, "SELECT ANY SEQUENCE" },
    { SELECT_ANY_TABLE,    "SELECT ANY TABLE" },
    { SYSBACKUP,           "SYSBACKUP" },
    { SYSDBA,              "SYSDBA" },
    { SYSOPER,             "SYSOPER" },

    { UNDER_ANY_VIEW,       "UNDER ANY VIEW" },
    { UNLIMITED_TABLESPACE, "UNLIMITED TABLESPACE" },
    { UPDATE_ANY_TABLE,     "UPDATE ANY TABLE" },
    { USE_ANY_TABLESPACE,   "USE ANY TABLESPACE" },
};

// new object privilege item should be add at the bottom for compitable!!!
obj_priv_name_id g_obj_privs_def[] = {
    { GS_PRIV_ALTER,        "ALTER" },
    { GS_PRIV_DELETE,       "DELETE" },
    { GS_PRIV_EXECUTE,      "EXECUTE" },
    { GS_PRIV_INDEX,        "INDEX" },
    { GS_PRIV_INSERT,       "INSERT" },
    { GS_PRIV_READ,         "READ" },
    { GS_PRIV_REFERENCES,   "REFERENCES" },
    { GS_PRIV_SELECT,       "SELECT" },
    { GS_PRIV_UPDATE,       "UPDATE" },
    { GS_PRIV_DIRE_READ,    "READ ON DIRECTORY" },
    { GS_PRIV_DIRE_WRITE,   "WRITE ON DIRECTORY" },
    { GS_PRIV_DIRE_EXECUTE, "EXECUTE ON DIRECTORY" },
};

// new user privilege item should be add at the bottom for compitable!!!
user_priv_name_id g_user_privs_def[] = {
    { GS_PRIV_INHERIT_PRIVILEGES, "INHERIT PRIVILEGES" },
};

/* table privilege's scope */
obj_privs_id g_tab_priv[] = {
    GS_PRIV_ALTER,
    GS_PRIV_DELETE,
    GS_PRIV_INDEX,
    GS_PRIV_INSERT,
    GS_PRIV_READ,
    GS_PRIV_REFERENCES,
    GS_PRIV_SELECT,
    GS_PRIV_UPDATE
};

/* table privilege's scope */
obj_privs_id g_view_priv[] = {
    GS_PRIV_DELETE,
    GS_PRIV_INSERT,
    GS_PRIV_READ,
    GS_PRIV_REFERENCES,
    GS_PRIV_SELECT,
    GS_PRIV_UPDATE
};

/* procedure/function privilege's scope */
obj_privs_id g_proc_priv[] = {
    GS_PRIV_EXECUTE
};

/* library privilege's scope */
obj_privs_id g_lib_priv[] = {
    GS_PRIV_EXECUTE,
};

/* sequence privilege's scope */
obj_privs_id g_seq_priv[] = {
    GS_PRIV_ALTER,
    GS_PRIV_SELECT
};

obj_privs_id g_dire_priv[] = {
    GS_PRIV_DIRE_READ,
    GS_PRIV_DIRE_WRITE,
    GS_PRIV_DIRE_EXECUTE
};

user_privs_id g_user_priv[] = {
    GS_PRIV_INHERIT_PRIVILEGES
};

bool32 knl_priv_in_scope(uint32 priv_id, obj_privs_id *priv_scope, uint32 count)
{
    uint32 i;

    for (i = 0; i < count; i++) {
        /* the largest priv_scope is not larger than uint32 */
        if (priv_id == (uint32)priv_scope[i]) {
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

void knl_get_objprivs_set(object_type_t objtype, obj_privs_id **set, uint32 *count)
{
    switch (objtype) {
        case OBJ_TYPE_TABLE:
            *set = g_tab_priv;
            *count = ELEMENT_COUNT(g_tab_priv);
            break;
        case OBJ_TYPE_VIEW:
            *set = g_view_priv;
            *count = ELEMENT_COUNT(g_view_priv);
            break;
        case OBJ_TYPE_SEQUENCE:
            *set = g_seq_priv;
            *count = ELEMENT_COUNT(g_seq_priv);
            break;
        case OBJ_TYPE_PROCEDURE:
            *set = g_proc_priv;
            *count = ELEMENT_COUNT(g_proc_priv);
            break;
        case OBJ_TYPE_DIRECTORY:
            *set = g_dire_priv;
            *count = ELEMENT_COUNT(g_dire_priv);
            break;
        case OBJ_TYPE_LIBRARY:
            *set = g_lib_priv;
            *count = ELEMENT_COUNT(g_lib_priv);
            break;
        default:
            *set = NULL;
            *count = 0;
            break;
    }
}

status_t knl_check_obj_priv_scope(uint32 priv_id, object_type_t objtype)
{
    uint32 count = 0;
    obj_privs_id *set = NULL;

    knl_get_objprivs_set(objtype, &set, &count);
    if (set == NULL || count == 0) {
        GS_LOG_RUN_ERR("[PRIV] failed to get objprivs set");
        return GS_ERROR;
    }

    if (knl_priv_in_scope(priv_id, set, count)) {
        return GS_SUCCESS;
    } else {
        GS_LOG_RUN_ERR("[PRIV] priv not in scope");
        return GS_ERROR;
    }
}

bool32 knl_sys_priv_match(text_t *priv_name, sys_privs_id *spid)
{
    int32 begin_pos, end_pos, mid_pos, cmp_result;
    char *cmp_priv = NULL;

    begin_pos = 0;
    end_pos = GS_SYS_PRIVS_COUNT - 1;

    while (end_pos >= begin_pos) {
        /* mid_pos is the average of begin_pos and end_pos */
        mid_pos = (begin_pos + end_pos) / 2;
        cmp_priv = (char *)g_sys_privs_def[mid_pos].name;

        cmp_result = cm_compare_str_ins(T2S(priv_name), cmp_priv);
        if (cmp_result == 0) {
            *spid = g_sys_privs_def[mid_pos].spid;
            return GS_TRUE;
        } else if (cmp_result < 0) {
            end_pos = mid_pos - 1;
        } else {
            begin_pos = mid_pos + 1;
        }
    }

    return GS_FALSE;
}

bool32 knl_obj_priv_match(text_t *priv_name, obj_privs_id *opid)
{
    uint32 i;

    /* find by object type */
    for (i = 0; i < GS_OBJ_PRIVS_COUNT; i++) {
        if (cm_text_str_equal(priv_name, g_obj_privs_def[i].name)) {
            *opid = (obj_privs_id)i;
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

bool32 knl_user_priv_match(text_t *priv_name, user_privs_id *upid)
{
    for (uint32 i = 0; i < GS_USER_PRIVS_COUNT; i++) {
        if (cm_text_str_equal(priv_name, g_user_privs_def[i].name)) {
            *upid = (user_privs_id)i;
            return GS_TRUE;
        }
    }
    return GS_FALSE;
}

bool32 db_check_role_circle_grant(dc_role_t *role1, dc_role_t *role2)
{
    cm_list_head *item = NULL;
    dc_granted_role *child_role = NULL;

    if (role1 == role2) {
        return GS_TRUE;
    }

    cm_list_for_each(item, &role2->child_roles)
    {
        child_role = cm_list_entry(item, dc_granted_role, node);
        if (role1 == child_role->granted_role) {
            return GS_TRUE;
        } else {
            return db_check_role_circle_grant(role1, child_role->granted_role);
        }
    }

    return GS_FALSE;
}

status_t db_insert_sys_priv(knl_handle_t session, uint32 id, uint32 grantee_type, uint32 priv_id,
                            uint32 admin_opt)
{
    uint32 max_size;
    row_assist_t ra;
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;

    CM_SAVE_STACK(knl_session->stack);
    cursor = knl_push_cursor(knl_session);

    cursor->row = (row_head_t *)cursor->buf;

    max_size = knl_session->kernel->attr.max_row_size;
    row_init(&ra, cursor->buf, max_size, 4);

    (void)row_put_int32(&ra, id);
    (void)row_put_int32(&ra, grantee_type);
    (void)row_put_int32(&ra, priv_id);
    (void)row_put_int32(&ra, admin_opt);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_INSERT, SYS_PRIVS_ID, GS_INVALID_ID32);

    if (GS_SUCCESS != knl_internal_insert(session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

status_t db_delete_sys_priv(knl_handle_t session, uint32 uid, uint32 type, uint32 priv_id)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_DELETE, SYS_PRIVS_ID, IX_SYS_SYS_PRIVS_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid, sizeof(uid),
                     IX_COL_SYS_PRIVS_001_GRANTEE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&type,
                     sizeof(type), IX_COL_SYS_PRIVS_001_GRANTEE_TYPE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&priv_id,
                     sizeof(priv_id), IX_COL_SYS_PRIVS_001_RIVILEGE);

    if (GS_SUCCESS != knl_fetch(knl_session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

status_t db_update_sys_priv(knl_handle_t session, uint32 grantee_id, uint32 grantee_type,
                            uint32 priv_id, uint32 admin_value)
{
    uint32 admin_opt;
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    knl_session_t *knl_session = (knl_session_t *)session;

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(session);

    cursor->row = (row_head_t *)cursor->buf;

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_UPDATE, SYS_PRIVS_ID, IX_SYS_SYS_PRIVS_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);

    /* find the tuple by uid & priv_id */
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&grantee_id,
                     sizeof(uint32), IX_COL_SYS_PRIVS_001_GRANTEE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&grantee_type,
                     sizeof(uint32), IX_COL_SYS_PRIVS_001_GRANTEE_TYPE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&priv_id,
                     sizeof(uint32), IX_COL_SYS_PRIVS_001_RIVILEGE);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    if (!cursor->eof) {
        admin_opt = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PRIVS_COL_ADMIN_OPTION);
        if (admin_value == admin_opt) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_SUCCESS;
        } else if (admin_value == 1) {
            /* update admin option */
            row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), 1);
            (void)row_put_int32(&ra, admin_value);
            cursor->update_info.count = 1;
            cursor->update_info.columns[0] = SYS_PRIVS_COL_ADMIN_OPTION;
            cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);
            if (knl_internal_update(session, cursor) != GS_SUCCESS) {
                CM_RESTORE_STACK(knl_session->stack);
                return GS_ERROR;
            }

            CM_RESTORE_STACK(knl_session->stack);
            return GS_SUCCESS;
        }
    }

    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

static status_t db_update_user_roles(knl_handle_t session, uint32 uid, uint32 grantee_type,
                                     uint32 rid, uint32 admin_opt)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    knl_session_t *knl_session = (knl_session_t *)session;

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(knl_session);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_UPDATE, SYS_USER_ROLES_ID, IX_SYS_USER_ROLES_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);

    /* find the tuple by uid, rid, type */
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid,
                     sizeof(uint32), IX_COL_SYS_USER_ROLES_001_GRANTEE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&grantee_type,
                     sizeof(uint32), IX_COL_SYS_USER_ROLES_001_GRANTEE_TYPE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&rid,
                     sizeof(uint32), IX_COL_SYS_USER_ROLES_001_GRANTED_ROLE_ID);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    if (!cursor->eof) {
        /* update admin option */
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), 1);
        (void)row_put_int32(&ra, admin_opt);
        cursor->update_info.count = 1;
        cursor->update_info.columns[0] = SYS_USER_ROLES_COL_ADMIN_OPTION;
        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);
        if (knl_internal_update(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

status_t db_insert_object_privs(knl_handle_t session, uint32 grantee, uint32 grantee_type, uint32 privid,
                                dc_obj_priv_item *item, uint32 grant_opt, uint32 grant_uid)
{
    uint32 max_size;
    row_assist_t ra;
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(knl_session);

    cursor->row = (row_head_t *)cursor->buf;

    max_size = knl_session->kernel->attr.max_row_size;
    row_init(&ra, cursor->buf, max_size, 8);

    (void)row_put_int32(&ra, grantee);
    (void)row_put_int32(&ra, grantee_type);
    (void)row_put_int32(&ra, item->objowner);
    (void)row_put_str(&ra, item->objname);
    (void)row_put_int32(&ra, item->objtype);
    (void)row_put_int32(&ra, privid);
    (void)row_put_int32(&ra, grant_opt);
    (void)row_put_int32(&ra, grant_uid);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_INSERT, OBJECT_PRIVS_ID, GS_INVALID_ID32);

    if (GS_SUCCESS != knl_internal_insert(session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

status_t db_insert_user_privs(knl_handle_t session, uint32 uid, uint32 grantor_id, uint32 grantee_id,
                              uint32 priv_type)
{
    row_assist_t ra;
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;
    uint32 max_size = knl_session->kernel->attr.max_row_size;

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(knl_session);

    cursor->row = (row_head_t *)cursor->buf;

    row_init(&ra, cursor->buf, max_size, SYS_USER_PRIVS_COLUMN_COUNT);

    (void)row_put_int32(&ra, uid);
    (void)row_put_int32(&ra, grantor_id);
    (void)row_put_int32(&ra, grantee_id);
    (void)row_put_int32(&ra, priv_type);
    (void)row_put_int32(&ra, 0);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_INSERT, SYS_USER_PRIVS_ID, GS_INVALID_ID32);

    if (GS_SUCCESS != knl_internal_insert(session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(knl_session->stack);

    return GS_SUCCESS;
}


status_t db_update_objname_for_priv(knl_handle_t session, uint32 uid, const char *oldname, text_t *newname,
                                    uint32 type)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    knl_session_t *knl_session = (knl_session_t *)session;

    CM_SAVE_STACK(knl_session->stack);
    cursor = knl_push_cursor(knl_session);
    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_UPDATE, OBJECT_PRIVS_ID, IX_SYS_OBJECT_PRIVS_002_ID);
    knl_init_index_scan(cursor, GS_TRUE);

    /* find the tuple by uid, object name & type */
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_002_OBJECT_OWNER);
    /* the length of objname is 68, and is not larger than uint16 */
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, (void *)oldname,
                     (uint16)strlen(oldname), IX_COL_SYS_OBJECT_PRIVS_002_OBJECT_NAME);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&type,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_002_OBJECT_TYPE);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        /* update oject name */
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), 1);
        (void)row_put_text(&ra, newname);
        cursor->update_info.count = 1;
        cursor->update_info.columns[0] = OBJECT_PRIVS_COL_OBJECT_NAME;
        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);
        if (knl_internal_update(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}
status_t db_update_object_privs(knl_handle_t session, uint32 grantee, uint32 grantee_type, uint32 privid,
                                dc_obj_priv_item *item, uint32 grant_opt)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    knl_session_t *knl_session = (knl_session_t *)session;

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(knl_session);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_UPDATE, OBJECT_PRIVS_ID, IX_SYS_OBJECT_PRIVS_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);

    /* find the tuple by uid, rid, type */
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&grantee,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&grantee_type,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE_TYPE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&item->objowner,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_OWNER);
    /* the length of objname is 68, and is not larger than uint16 */
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, (void *)item->objname,
                     (uint16)strlen(item->objname), IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_NAME);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&item->objtype,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_TYPE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&privid,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_PRIVILEGE);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    if (!cursor->eof) {
        /* update admin option */
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), 1);
        (void)row_put_int32(&ra, grant_opt);
        cursor->update_info.count = 1;
        cursor->update_info.columns[0] = OBJECT_PRIVS_COL_GRANTABLE;
        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);
        if (knl_internal_update(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

status_t db_delete_obj_priv(knl_handle_t session, uint32 grantee, uint32 grantee_type, assist_obj_priv_item_t *item)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(knl_session);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_DELETE, OBJECT_PRIVS_ID, IX_SYS_OBJECT_PRIVS_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&grantee,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&grantee_type,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE_TYPE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&item->objowner,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_OWNER);
    /* the length of objname is 68, and is not larger than uint16 */
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, (void *)&item->objname,
                     (uint16)strlen(item->objname), IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_NAME);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&item->objtype,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_TYPE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&item->privid,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_PRIVILEGE);

    if (GS_SUCCESS != knl_fetch(knl_session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }
    }
    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}


status_t db_delete_all_sysprivs(knl_handle_t session, uint32 uid, uint32 type)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(knl_session);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_DELETE, SYS_PRIVS_ID, IX_SYS_SYS_PRIVS_001_ID);
    knl_init_index_scan(cursor, GS_FALSE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid, sizeof(uid),
                     IX_COL_SYS_PRIVS_001_GRANTEE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&uid, sizeof(uid),
                     IX_COL_SYS_PRIVS_001_GRANTEE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&type,
                     sizeof(type), IX_COL_SYS_PRIVS_001_GRANTEE_TYPE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&type,
                     sizeof(type), IX_COL_SYS_PRIVS_001_GRANTEE_TYPE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_PRIVS_001_RIVILEGE);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_PRIVS_001_RIVILEGE);

    if (GS_SUCCESS != knl_fetch(knl_session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

status_t db_delete_all_objprivs(knl_handle_t session, uint32 grantee, uint32 grantee_type, dc_obj_priv_item *item)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(knl_session);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_DELETE, OBJECT_PRIVS_ID, IX_SYS_OBJECT_PRIVS_001_ID);
    knl_init_index_scan(cursor, GS_FALSE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&grantee,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&grantee,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&grantee_type,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE_TYPE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&grantee_type,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE_TYPE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&item->objowner,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_OWNER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&item->objowner,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_OWNER);
    /* the length of objname is 68, and is not larger than uint16 */
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, (void *)&item->objname,
                     (uint16)strlen(item->objname), IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_NAME);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_STRING, (void *)&item->objname,
                     (uint16)strlen(item->objname), IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_NAME);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&item->objtype,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_TYPE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&item->objtype,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_TYPE);

    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_001_PRIVILEGE);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_001_PRIVILEGE);

    if (GS_SUCCESS != knl_fetch(knl_session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

static status_t db_insert_user_roles(knl_handle_t session, uint32 grantee_id, uint32 type, uint32 rid,
                                     uint32 admin_opt)
{
    uint32 max_size;
    row_assist_t ra;
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(knl_session);

    cursor->row = (row_head_t *)cursor->buf;

    max_size = knl_session->kernel->attr.max_row_size;
    row_init(&ra, cursor->buf, max_size, 5);

    (void)row_put_int32(&ra, grantee_id);
    (void)row_put_int32(&ra, type);
    (void)row_put_int32(&ra, rid);
    (void)row_put_int32(&ra, admin_opt);
    (void)row_put_int32(&ra, 0);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_INSERT, SYS_USER_ROLES_ID, GS_INVALID_ID32);

    if (GS_SUCCESS != knl_internal_insert(session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

status_t db_delete_user_roles(knl_handle_t session, uint32 grantee_id, uint32 type, uint32 rid)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(knl_session);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_DELETE, SYS_USER_ROLES_ID, IX_SYS_USER_ROLES_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&grantee_id,
                     sizeof(grantee_id), IX_COL_SYS_USER_ROLES_001_GRANTEE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&type,
                     sizeof(type), IX_COL_SYS_USER_ROLES_001_GRANTEE_TYPE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&rid, sizeof(rid),
                     IX_COL_SYS_USER_ROLES_001_GRANTED_ROLE_ID);

    if (GS_SUCCESS != knl_fetch(knl_session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

status_t db_delete_privs_by_id(knl_session_t *session, uint32 id, uint32 type)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(knl_session);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_DELETE, SYS_PRIVS_ID, IX_SYS_SYS_PRIVS_001_ID);
    knl_init_index_scan(cursor, GS_FALSE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&id, sizeof(id),
                     IX_COL_SYS_PRIVS_001_GRANTEE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&id, sizeof(id),
                     IX_COL_SYS_PRIVS_001_GRANTEE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&type,
                     sizeof(type), IX_COL_SYS_PRIVS_001_GRANTEE_TYPE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&type,
                     sizeof(type), IX_COL_SYS_PRIVS_001_GRANTEE_TYPE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_PRIVS_001_RIVILEGE);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_PRIVS_001_RIVILEGE);

    if (GS_SUCCESS != knl_fetch(knl_session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

status_t db_delete_priv_as_grantee(knl_session_t *session, uint32 id, uint32 type)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(knl_session);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_DELETE, SYS_USER_ROLES_ID, IX_SYS_USER_ROLES_001_ID);
    knl_init_index_scan(cursor, GS_FALSE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&id, sizeof(id),
                     IX_COL_SYS_USER_ROLES_001_GRANTEE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&id, sizeof(id),
                     IX_COL_SYS_USER_ROLES_001_GRANTEE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&type,
                     sizeof(type), IX_COL_SYS_USER_ROLES_001_GRANTEE_TYPE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&type,
                     sizeof(type), IX_COL_SYS_USER_ROLES_001_GRANTEE_TYPE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_USER_ROLES_001_GRANTED_ROLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_USER_ROLES_001_GRANTED_ROLE_ID);

    if (GS_SUCCESS != knl_fetch(knl_session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

status_t db_delete_role_as_granted(knl_session_t *session, uint32 id)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(knl_session);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_DELETE, SYS_USER_ROLES_ID, IX_SYS_USER_ROLES_002_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&id, sizeof(id),
                     IX_COL_SYS_USER_ROLES_002_GRANTED_ROLE_ID);

    if (GS_SUCCESS != knl_fetch(knl_session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

status_t db_delete_priv_grant_by_id(knl_session_t *session, uint32 id, uint32 type)
{
    if (db_delete_priv_as_grantee(session, id, type) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (type == 1) {
        if (db_delete_role_as_granted(session, id) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_drop_object_privs(knl_session_t *session, uint32 uid, const char *objname, uint32 type)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(knl_session);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_DELETE, OBJECT_PRIVS_ID, IX_SYS_OBJECT_PRIVS_002_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid, sizeof(uid),
                     IX_COL_SYS_OBJECT_PRIVS_002_OBJECT_OWNER);
    /* the length of objname is 68, and is not larger than uint16 */
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, (void *)objname,
                     (uint16)strlen(objname), IX_COL_SYS_OBJECT_PRIVS_002_OBJECT_NAME);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&type,
                     sizeof(type), IX_COL_SYS_OBJECT_PRIVS_002_OBJECT_TYPE);

    if (GS_SUCCESS != knl_fetch(knl_session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

status_t db_delete_obj_privs_by_grantee(knl_session_t *session, uint32 grantee, uint32 type)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(knl_session);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_DELETE, OBJECT_PRIVS_ID, IX_SYS_OBJECT_PRIVS_001_ID);
    knl_init_index_scan(cursor, GS_FALSE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&grantee,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&grantee,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&type,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE_TYPE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&type,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE_TYPE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_OWNER);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_OWNER);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_NAME);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_NAME);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_TYPE);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_TYPE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_001_PRIVILEGE);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_001_PRIVILEGE);

    if (GS_SUCCESS != knl_fetch(knl_session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

status_t db_delete_obj_privs_by_owner(knl_session_t *session, uint32 owner)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(knl_session);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_DELETE, OBJECT_PRIVS_ID, IX_SYS_OBJECT_PRIVS_002_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&owner,
                     sizeof(owner), IX_COL_SYS_OBJECT_PRIVS_002_OBJECT_OWNER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&owner,
                     sizeof(owner), IX_COL_SYS_OBJECT_PRIVS_002_OBJECT_OWNER);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_002_OBJECT_NAME);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_002_OBJECT_NAME);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_002_OBJECT_TYPE);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_002_OBJECT_TYPE);

    if (GS_SUCCESS != knl_fetch(knl_session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}
status_t db_delete_obj_priv_single(knl_handle_t session, uint32 grantee, uint32 grantee_type,
    assist_obj_priv_item_t *item, uint32 *tmp_grantor)
{
    knl_cursor_t *cursor = NULL;
    dc_user_t *user = NULL;
    dc_role_t *role = NULL;
    char *name = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;
    dc_context_t *ctx = &knl_session->kernel->dc_ctx;

    CM_SAVE_STACK(knl_session->stack);
    cursor = knl_push_cursor(knl_session);
    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_DELETE, OBJECT_PRIVS_ID, IX_SYS_OBJECT_PRIVS_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&grantee,
        sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&grantee_type,
        sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE_TYPE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&item->objowner,
        sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_OWNER);
    /* the length of objname is 68, and is not larger than uint16 */
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, (void *)&item->objname,
        (uint16)strlen(item->objname), IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_NAME);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&item->objtype,
        sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_TYPE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&item->privid,
        sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_PRIVILEGE);

    if (GS_SUCCESS != knl_fetch(knl_session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    if (!cursor->eof) {
        *tmp_grantor = *(uint32 *)CURSOR_COLUMN_DATA(cursor, OBJECT_PRIVS_COL_GRANTOR);
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }
    } else {
        CM_RESTORE_STACK(knl_session->stack);
        if (grantee_type == TYPE_USER) {
            user = ctx->users[grantee];
            name = user->desc.name;
        } else {
            role = ctx->roles[grantee];
            name = role->desc.name;
        }
        GS_THROW_ERROR(ERR_INVALID_REVOKEE, name);
        return GS_ERROR;
    }
    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}
status_t db_delete_obj_priv_by_grantor(knl_handle_t session, uint32 root_grantor,
    uint32 grantor_input, uint32 grantor_type, assist_obj_priv_item_t *item)
{
    knl_cursor_t *cursor = NULL;
    uint32 grantor = grantor_input;
    knl_session_t *knl_session = (knl_session_t *)session;
    uint32 tmp_grantor, next_grantee, next_grantee_type;
    CM_SAVE_STACK(knl_session->stack);
    cursor = knl_push_cursor(knl_session);
    while (GS_TRUE) {
        knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_SELECT, OBJECT_PRIVS_ID, IX_SYS_OBJECT_PRIVS_004_ID);
        knl_init_index_scan(cursor, GS_TRUE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&grantor,
            sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_004_GRANTOR);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&item->objowner,
            sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_004_OBJECT_OWNER);
        /* the length of objname is 68, and is not larger than uint16 */
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, (void *)&item->objname,
            (uint16)strlen(item->objname), IX_COL_SYS_OBJECT_PRIVS_004_OBJECT_NAME);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&item->objtype,
            sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_004_OBJECT_TYPE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&item->privid,
            sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_004_PRIVILEGE);
        if (GS_SUCCESS != knl_fetch(knl_session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }
        if (cursor->eof) {
            if (db_delete_obj_priv_single(knl_session, grantor, grantor_type, item, &tmp_grantor) != GS_SUCCESS) {
                CM_RESTORE_STACK(knl_session->stack);
                return GS_ERROR;
            }
            if (tmp_grantor == root_grantor) {
                CM_RESTORE_STACK(knl_session->stack);
                return GS_SUCCESS;
            } else {
                grantor = tmp_grantor;
                continue;
            }
        } else {
            next_grantee = *(uint32 *)CURSOR_COLUMN_DATA(cursor, OBJECT_PRIVS_COL_GRANTEE);
            next_grantee_type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, OBJECT_PRIVS_COL_GRANTEE_TYPE);
            if (next_grantee_type == TYPE_ROLE) {
                if (db_delete_obj_priv_single(knl_session, next_grantee, TYPE_ROLE, item, &tmp_grantor) != GS_SUCCESS) {
                    CM_RESTORE_STACK(knl_session->stack);
                    return GS_ERROR;
                }
                if (tmp_grantor == root_grantor) {
                    CM_RESTORE_STACK(knl_session->stack);
                    return GS_SUCCESS;
                } else {
                    grantor = tmp_grantor;
                    continue;
                }
            } else {
                grantor = next_grantee;
                continue;
            }
        }
    }
    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

status_t db_delete_obj_privs_by_grantor(knl_session_t *session, uint32 grantor)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;
    assist_obj_priv_item_t obj_item;
    uint32 grantee, grantee_type;
    char *column_data = NULL;
    uint32 name_len = GS_NAME_BUFFER_SIZE - 1;
    errno_t ret;

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(knl_session);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_SELECT, OBJECT_PRIVS_ID, IX_SYS_OBJECT_PRIVS_004_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&grantor,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_004_GRANTOR);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_004_OBJECT_OWNER);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_004_OBJECT_NAME);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_004_OBJECT_TYPE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_004_PRIVILEGE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&grantor,
        sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_004_GRANTOR);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_004_OBJECT_OWNER);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_004_OBJECT_NAME);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_004_OBJECT_TYPE);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_004_PRIVILEGE);

    if (GS_SUCCESS != knl_fetch(knl_session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        grantee = *(uint32 *)CURSOR_COLUMN_DATA(cursor, OBJECT_PRIVS_COL_GRANTEE);
        grantee_type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, OBJECT_PRIVS_COL_GRANTEE_TYPE);
        obj_item.objowner = *(uint32 *)CURSOR_COLUMN_DATA(cursor, OBJECT_PRIVS_COL_OBJECT_OWNER);
        column_data = CURSOR_COLUMN_DATA(cursor, OBJECT_PRIVS_COL_OBJECT_NAME);
        ret = strncpy_s(obj_item.objname, GS_NAME_BUFFER_SIZE, column_data, name_len);
        obj_item.objtype = *(uint32 *)CURSOR_COLUMN_DATA(cursor, OBJECT_PRIVS_COL_OBJECT_TYPE);
        obj_item.privid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, OBJECT_PRIVS_COL_PRIVILEGE);

        knl_securec_check(ret);

        if (db_delete_obj_priv_by_grantor(knl_session, grantor, grantee, grantee_type, &obj_item) != GS_SUCCESS) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }
        
        if (GS_SUCCESS != knl_fetch(knl_session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

status_t db_delete_user_privs_single(knl_session_t *session, uint32 uid, uint32 grantee_id, user_privs_id priv_type)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;

    CM_SAVE_STACK(knl_session->stack);
    cursor = knl_push_cursor(knl_session);
    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_DELETE, SYS_USER_PRIVS_ID, IX_USER_PRIVS_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), IX_COL_SYS_USER_PRIVS_001_UID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&grantee_id,
        sizeof(uint32), IX_COL_SYS_USER_PRIVS_001_GRANTEE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&priv_type,
        sizeof(uint32), IX_COL_SYS_USER_PRIVS_001_RIVILEGE);

    if (GS_SUCCESS != knl_fetch(knl_session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }
    }
    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

status_t db_delete_user_privs_by_uid(knl_session_t *session, uint32 uid)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(knl_session);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_DELETE, SYS_USER_PRIVS_ID, IX_USER_PRIVS_001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), IX_COL_SYS_USER_PRIVS_001_UID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), IX_COL_SYS_USER_PRIVS_001_UID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_USER_PRIVS_001_GRANTEE);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_USER_PRIVS_001_GRANTEE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_USER_PRIVS_001_RIVILEGE);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_USER_PRIVS_001_RIVILEGE);

    if (GS_SUCCESS != knl_fetch(knl_session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(knl_session->stack);

    return GS_SUCCESS;
}

status_t dc_delect_user_privs_by_grantee(knl_session_t *session, dc_context_t *ctx, knl_cursor_t *cursor)
{
    uint32 uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_PRIVS_COL_UID);
    uint32 grantee = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_PRIVS_COL_GRANTEE);
    dc_user_t *user = ctx->users[uid];
    dc_user_priv_entry_t *entry = NULL;

    if (user != NULL && user->status == USER_STATUS_NORMAL) {
        if (dc_find_user_priv_entry(&user->user_privs, grantee, &entry)) {
            dc_drop_user_entry(&user->user_privs, entry);
        }
    }

    return GS_SUCCESS;
}


status_t db_delete_user_privs_by_grantee(knl_session_t *session, uint32 grantee_id)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(knl_session);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_DELETE, SYS_USER_PRIVS_ID, IX_USER_PRIVS_001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&grantee_id,
        sizeof(uint32), IX_COL_SYS_USER_PRIVS_001_GRANTEE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&grantee_id,
        sizeof(uint32), IX_COL_SYS_USER_PRIVS_001_GRANTEE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_USER_PRIVS_001_UID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_USER_PRIVS_001_UID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_USER_PRIVS_001_RIVILEGE);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_USER_PRIVS_001_RIVILEGE);

    if (GS_SUCCESS != knl_fetch(knl_session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (dc_delect_user_privs_by_grantee(session, ctx, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(knl_session->stack);

    return GS_SUCCESS;
}

status_t db_delete_obj_privs_by_id(knl_session_t *session, uint32 id, uint32 type)
{
    if (db_delete_obj_privs_by_grantee(session, id, type) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (type == 0) {
        if (db_delete_obj_privs_by_owner(session, id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (db_delete_obj_privs_by_grantor(session, id) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_delete_user_privs_by_id(knl_session_t *session, uint32 id)
{
    if (db_delete_user_privs_by_grantee(session, id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_delete_user_privs_by_uid(session, id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}


/* drop all privileges granted when the user/role is dropped */
status_t db_delete_all_privs_by_id(knl_session_t *session, uint32 id, uint32 type)
{
    /* SYS_PRIVS$ */
    if (db_delete_privs_by_id(session, id, type) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* USER_ROLES$ */
    if (db_delete_priv_grant_by_id(session, id, type) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* OBJECT_PRIVS$ */
    if (db_delete_obj_privs_by_id(session, id, type) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* USER_PRIVS$ */
    if (type == 0) {
        if (db_delete_user_privs_by_id(session, id) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

/*
 * update the admin option flag = 1 when grant the role to the user
 */
void db_update_admin_opt(dc_role_t *role, dc_user_t *user)
{
    cm_list_head *item = NULL;
    dc_granted_role *role_granted = NULL;

    cm_list_for_each(item, &user->parent)
    {
        role_granted = cm_list_entry(item, dc_granted_role, node);
        if (role_granted->granted_role == role) {
            role_granted->admin_opt = 1;
            return;
        }
    }
}

status_t db_grant_syspriv_to_user(knl_handle_t session, void *def, knl_holders_def_t *grantee,
                                  knl_priv_def_t *priv)
{
    uint32 uid;
    dc_context_t *dc_ctx = NULL;
    dc_user_t *user = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;
    knl_grant_def_t *grant_def = (knl_grant_def_t *)def;

    if (!dc_get_user_id(knl_session, &grantee->name, &uid)) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&grantee->name));
        return GS_ERROR;
    }

    dc_ctx = &knl_session->kernel->dc_ctx;
    user = dc_ctx->users[uid];

    /* check if the user has been already directly granted the system privilege */
    if (DC_HAS_SYS_PRIV(user->sys_privs, priv->priv_id)) {
        if (grant_def->admin_opt == 1 && !DC_HAS_SYS_OPT(user->admin_opt, priv->priv_id)) {
            return db_update_sys_priv(session, uid, grantee->type, priv->priv_id, grant_def->admin_opt);
        }

        return GS_SUCCESS;
    }

    /* insert a record into SYS_PRIVS$ */
    return db_insert_sys_priv(session, uid, grantee->type, priv->priv_id, grant_def->admin_opt);
}

status_t db_grant_syspriv_to_role(knl_handle_t session, void *def, knl_holders_def_t *grantee,
                                  knl_priv_def_t *priv)
{
    uint32 rid;
    dc_context_t *dc_ctx = NULL;
    dc_role_t *role = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;
    knl_grant_def_t *grant_def = (knl_grant_def_t *)def;

    if (!dc_get_role_id(knl_session, &grantee->name, &rid)) {
        GS_THROW_ERROR(ERR_ROLE_NOT_EXIST, T2S(&grantee->name));
        return GS_ERROR;
    }

    dc_ctx = &knl_session->kernel->dc_ctx;
    role = dc_ctx->roles[rid];
    /* check if the role has been already directly granted the system privilege. */
    if (DC_HAS_SYS_PRIV(role->sys_privs, priv->priv_id)) {
        if (grant_def->admin_opt == 1 && !DC_HAS_SYS_OPT(role->admin_opt, priv->priv_id)) {
            return db_update_sys_priv(knl_session, rid, grantee->type, priv->priv_id, grant_def->admin_opt);
        }

        return GS_SUCCESS;
    }

    /* insert a record into SYS_PRIVS$ */
    return db_insert_sys_priv(session, rid, grantee->type, priv->priv_id, grant_def->admin_opt);
}

status_t db_grant_objpriv_to_user(knl_handle_t session, void *def, knl_holders_def_t *grantee,
                                  knl_priv_def_t *priv)
{
    uint32 owner_uid;
    dc_user_t *user = NULL;
    knl_grant_def_t *grant_def = (knl_grant_def_t *)def;
    dc_obj_priv_entry_t *entry = NULL;
    dc_obj_priv_item priv_item;
    dc_user_t *grant_user = NULL;

    if (dc_open_user((knl_session_t *)session, &grantee->name, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!dc_get_user_id((knl_session_t *)session, &grant_def->schema, &owner_uid)) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&grant_def->schema));
        return GS_ERROR;
    }
    /* owner has all object privileges, no need grant to self */
    if (owner_uid == user->desc.id ||
        (user->desc.id == DB_SYS_USER_ID && grant_def->priv_type != PRIV_TYPE_OBJ_PRIV)) {
        return GS_SUCCESS;
    }
    // the largest objtype is not larger than uint32
    if (dc_find_objpriv_entry(&user->obj_privs, owner_uid, &grant_def->objname, (uint32)grant_def->objtype, &entry)) {
        if (DC_HAS_OBJ_PRIV(entry->priv_item.direct_grant, priv->priv_id)) {
            /* need update the grant option ? */
            if (1 == grant_def->grant_opt && !DC_HAS_OBJ_OPT(entry->priv_item.direct_opt, priv->priv_id)) {
                return db_update_object_privs(session, user->desc.id, grantee->type, priv->priv_id, &entry->priv_item,
                                              grant_def->grant_opt);
            }

            return GS_SUCCESS;
        }
    } else {
        /* is there enough entry for current privilege item ? */
        if (!dc_has_objpriv_entry(&user->obj_privs)) {
            GS_THROW_ERROR(ERR_GRANT_OBJ_EXCEED_MAX, DC_GROUP_SIZE * DC_GROUP_SIZE);
            return GS_ERROR;
        }
    }
    
    /* not granted the privilege to the user yet */
    priv_item.objowner = owner_uid;
    (void)cm_text2str(&grant_def->objname, priv_item.objname, GS_NAME_BUFFER_SIZE);
    // the largest objtype is not larger than uint32
    priv_item.objtype = (uint32)grant_def->objtype;

    if (db_insert_object_privs(session, user->desc.id, grantee->type, priv->priv_id,
                               &priv_item, grant_def->grant_opt, grant_def->grant_uid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_open_user_by_id((knl_session_t *)session, grant_def->grant_uid, &grant_user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_add_user_grant_objpriv((knl_session_t *)session, grant_user, grantee->type, user->desc.id, &priv_item,
                                  priv->priv_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_grant_userpriv_to_user(knl_handle_t session, void *def, knl_holders_def_t *grantee,
    knl_priv_def_t *priv)
{
    uint32 grantee_id;
    dc_user_t *user = NULL;
    knl_grant_def_t *grant_def = (knl_grant_def_t *)def;
    dc_user_priv_entry_t *entry = NULL;

    if (dc_open_user((knl_session_t *)session, &grant_def->objname, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!dc_get_user_id((knl_session_t *)session, &grantee->name, &grantee_id)) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&grantee->name));
        return GS_ERROR;
    }
    
    if (dc_find_user_priv_entry(&user->user_privs, grantee_id, &entry)) {
        if (DC_HAS_OBJ_PRIV(entry->user_priv_item.privid_map, priv->priv_id)) {
            /* not support grant option */
            return GS_SUCCESS;
        }
    } else {
        /* is there enough entry for current privilege item ? */
        if (!dc_has_userpriv_entry(&user->user_privs)) {
            GS_THROW_ERROR(ERR_GRANT_OBJ_EXCEED_MAX, USER_PRIV_GROUP_COUNT * DC_GROUP_SIZE);
            return GS_ERROR;
        }
    }

    if (db_insert_user_privs(session, user->desc.id, grant_def->grant_uid, grantee_id,
        priv->priv_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}


status_t db_grant_objpriv_to_role(knl_handle_t session, void *def, knl_holders_def_t *grantee,
                                  knl_priv_def_t *priv)
{
    uint32 rid;
    uint32 owner_uid;
    dc_context_t *dc_ctx = NULL;
    dc_role_t *role = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;
    knl_grant_def_t *grant_def = (knl_grant_def_t *)def;
    dc_obj_priv_entry_t *entry = NULL;
    dc_obj_priv_item priv_item;
    dc_user_t *grant_user = NULL;

    if (!dc_get_role_id(knl_session, &grantee->name, &rid)) {
        GS_THROW_ERROR(ERR_ROLE_NOT_EXIST, T2S(&grantee->name));
        return GS_ERROR;
    }

    if (!dc_get_user_id(knl_session, &grant_def->schema, &owner_uid)) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&grant_def->schema));
        return GS_ERROR;
    }

    dc_ctx = &knl_session->kernel->dc_ctx;
    role = dc_ctx->roles[rid];
    /* check if the role has been already directly granted the object privilege. */
    /* the largest objtype is not larger than uint32 */
    if (dc_find_objpriv_entry(&role->obj_privs, owner_uid, &grant_def->objname, (uint32)grant_def->objtype, &entry)) {
        if (DC_HAS_OBJ_PRIV(entry->priv_item.direct_grant, priv->priv_id)) {
            return GS_SUCCESS;
        }
    } else {
        /* is there enough entry for current privilege item ? */
        if (!dc_has_objpriv_entry(&role->obj_privs)) {
            GS_THROW_ERROR(ERR_GRANT_OBJ_EXCEED_MAX, DC_GROUP_SIZE * DC_GROUP_SIZE);
            return GS_ERROR;
        }
    }

    /* not granted the privilege to the role yet */
    priv_item.objowner = owner_uid;
    cm_text2str_with_upper(&grant_def->objname, priv_item.objname, GS_NAME_BUFFER_SIZE);
    /* the largest objtype is not larger than uint32 */
    priv_item.objtype = (uint32)grant_def->objtype;

    if (db_insert_object_privs(session, role->desc.id, grantee->type, priv->priv_id,
                               &priv_item, grant_def->grant_opt, grant_def->grant_uid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_open_user_by_id(knl_session, grant_def->grant_uid, &grant_user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_add_user_grant_objpriv(knl_session, grant_user, grantee->type, role->desc.id, &priv_item,
                                  priv->priv_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_grant_userpriv_to_role(knl_handle_t session, void *def, knl_holders_def_t *grantee,
    knl_priv_def_t *priv)
{
    GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "user privileges can't be granted to role");
    return GS_ERROR;
}

status_t db_grant_role_to_user(knl_handle_t session, void *def, knl_holders_def_t *grantee, knl_priv_def_t *priv)
{
    uint32 uid;
    uint32 rid;
    dc_context_t *dc_ctx;
    dc_user_t *user = NULL;
    dc_role_t *role = NULL;
    dc_user_granted *user_grant = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;
    knl_grant_def_t *grant_def = (knl_grant_def_t *)def;

    dc_ctx = &knl_session->kernel->dc_ctx;
    if (!dc_get_user_id(knl_session, &grantee->name, &uid)) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&grantee->name));
        return GS_ERROR;
    }

    /* the user may dropped by others, it is not safe */
    user = dc_ctx->users[uid];

    if (!dc_get_role_id(knl_session, &priv->priv_name, &rid)) {
        GS_THROW_ERROR(ERR_ROLE_NOT_EXIST, T2S(&priv->priv_name));
        return GS_ERROR;
    }

    role = dc_ctx->roles[rid];

    /* check if the user has been already directly granted the role */
    cm_list_head *item = NULL;
    cm_list_for_each(item, &role->child_users)
    {
        /* the role has been granted to the user already */
        user_grant = cm_list_entry(item, dc_user_granted, node);
        if (user == user_grant->user_granted) {
            if (grant_def->admin_opt == 1 && user_grant->admin_opt == 0) {
                return db_update_user_roles(knl_session, uid, grantee->type, rid, grant_def->admin_opt);
            }

            return GS_SUCCESS;
        }
    }

    /* insert a record into USER_ROLES$ */
    return db_insert_user_roles(session, user->desc.id, grantee->type, role->desc.id, grant_def->admin_opt);
}

status_t db_grant_role_to_role(knl_handle_t session, void *def, knl_holders_def_t *grantee, knl_priv_def_t *priv)
{
    uint32 rid1, rid2;
    cm_list_head *item = NULL;
    dc_role_t *role1 = NULL;
    dc_role_t *role2 = NULL;
    dc_granted_role *child = NULL;
    dc_context_t *ctx = &((knl_session_t *)session)->kernel->dc_ctx;
    knl_grant_def_t *grant_def = (knl_grant_def_t *)def;

    if (!dc_get_role_id((knl_session_t *)session, &priv->priv_name, &rid1)) {
        GS_THROW_ERROR(ERR_ROLE_NOT_EXIST, T2S(&priv->priv_name));
        return GS_ERROR;
    }

    if (!dc_get_role_id((knl_session_t *)session, &grantee->name, &rid2)) {
        GS_THROW_ERROR(ERR_ROLE_NOT_EXIST, T2S(&grantee->name));
        return GS_ERROR;
    }
    role1 = ctx->roles[rid1];
    role2 = ctx->roles[rid2];
    /* check if already granted role1 to role2 */
    cm_list_for_each(item, &role1->child_roles)
    {
        child = cm_list_entry(item, dc_granted_role, node);
        if (child->granted_role == role2) {
            if (grant_def->admin_opt == 1 && child->admin_opt == 0) {
                /* the largest priv_type is not larger than uint32 */
                return db_update_user_roles(session, role2->desc.id, (uint32)priv->priv_type,
                                            role1->desc.id, grant_def->admin_opt);
            }

            return GS_SUCCESS;
        }
    }

    /* check if granted in a circle */
    if (db_check_role_circle_grant(role1, role2)) {
        GS_THROW_ERROR(ERR_ROLE_CIRCLE_GRANT);
        return GS_ERROR;
    }

    /* add tuple for USER_ROLES$ */
    return db_insert_user_roles(session, role2->desc.id, grantee->type, role1->desc.id, grant_def->admin_opt);
}

status_t db_grant_objprivs(knl_handle_t session, void *def, knl_holders_def_t *grantee,
                           obj_privs_id *privset, uint32 count)
{
    uint32 i;
    knl_priv_def_t priv_item;

    for (i = 0; i < count; i++) {
        priv_item.priv_id = privset[i];
        if (grantee->type == TYPE_USER) {
            if (db_grant_objpriv_to_user(session, def, grantee, &priv_item) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            if (db_grant_objpriv_to_role(session, def, grantee, &priv_item) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

status_t db_grant_allobjprivs(knl_handle_t session, void *def, knl_holders_def_t *grantee, knl_priv_def_t *priv)
{
    uint32 count = 0;
    obj_privs_id *set = NULL;
    knl_grant_def_t *grant_def = (knl_grant_def_t *)def;

    knl_get_objprivs_set(grant_def->objtype, &set, &count);
    if (set == NULL || count == 0) {
        GS_LOG_RUN_ERR("[PRIV] failed to get objprivs set");
        return GS_ERROR;
    }

    return db_grant_objprivs(session, def, grantee, set, count);
}

status_t db_grant_allprivs_to_user(knl_handle_t session, void *def, knl_holders_def_t *grantee,
                                   knl_priv_def_t *priv)
{
    uint32 priv_id;
    knl_priv_def_t priv_item;
    knl_grant_def_t *grant_def = (knl_grant_def_t *)def;

    if (PRIV_TYPE_SYS_PRIV == grant_def->priv_type) {
        for (priv_id = ALL_PRIVILEGES + 1; priv_id < GS_SYS_PRIVS_COUNT; priv_id++) {
            priv_item.priv_id = priv_id;
            if (db_grant_syspriv_to_user(session, def, grantee, &priv_item) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    } else { /* object privilege */
        return db_grant_allobjprivs(session, def, grantee, priv);
    }

    return GS_SUCCESS;
}

status_t db_grant_allprivs_to_role(knl_handle_t session, void *def, knl_holders_def_t *grantee,
                                   knl_priv_def_t *priv)
{
    uint32 priv_id;
    knl_priv_def_t priv_item;
    knl_grant_def_t *grant_def = (knl_grant_def_t *)def;

    if (PRIV_TYPE_SYS_PRIV == grant_def->priv_type) {
        for (priv_id = ALL_PRIVILEGES + 1; priv_id < GS_SYS_PRIVS_COUNT; priv_id++) {
            priv_item.priv_id = priv_id;
            priv_item.priv_name.str = g_sys_privs_def[priv_id].name;
            priv_item.priv_name.len = (uint32)strlen(g_sys_privs_def[priv_id].name);

            if (db_grant_syspriv_to_role(session, def, grantee, &priv_item) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    } else {
        return db_grant_allobjprivs(session, def, grantee, priv);
    }

    return GS_SUCCESS;
}

status_t db_revoke_syspriv_from_user(knl_handle_t session, void *def, knl_holders_def_t *revokee,
                                     knl_priv_def_t *priv)
{
    uint32 uid;
    knl_session_t *knl_session = (knl_session_t *)session;
    dc_context_t *ctx = &knl_session->kernel->dc_ctx;
    dc_user_t *user = NULL;

    /* check: if the revokee had been granted the privilege directly before */
    if (!dc_get_user_id(knl_session, &revokee->name, &uid)) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&revokee->name));
        return GS_ERROR;
    }

    user = ctx->users[uid];
    if (!DC_HAS_SYS_PRIV(user->sys_privs, priv->priv_id)) {
        GS_THROW_ERROR(ERR_PRIVS_NOT_GRANT,
                       T2S(&priv->priv_name), T2S_EX(&revokee->name));
        return GS_ERROR;
    }

    /* delete the tuple from sys_privs$ table */
    return db_delete_sys_priv(session, user->desc.id, revokee->type, priv->priv_id);
}

status_t db_revoke_syspriv_from_role(knl_handle_t session, void *def, knl_holders_def_t *revokee,
                                     knl_priv_def_t *priv)
{
    uint32 rid;
    dc_role_t *role = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;
    dc_context_t *ctx = &knl_session->kernel->dc_ctx;

    if (!dc_get_role_id(knl_session, &revokee->name, &rid)) {
        GS_THROW_ERROR(ERR_ROLE_NOT_EXIST, T2S(&revokee->name));
        return GS_ERROR;
    }

    role = ctx->roles[rid];
    /* check if granted the system privilege to the role before */
    if (!DC_HAS_SYS_PRIV(role->sys_privs, priv->priv_id)) {
        GS_THROW_ERROR(ERR_PRIVS_NOT_GRANT,
                       T2S(&priv->priv_name), T2S_EX(&revokee->name));
        return GS_ERROR;
    }

    /* drop the tuple */
    return db_delete_sys_priv(session, role->desc.id, revokee->type, priv->priv_id);
}
status_t db_get_grantor_id(knl_handle_t session, uint32 grantee, uint32 grantee_type,
    assist_obj_priv_item_t *item, uint32 *up_grantor)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;
    CM_SAVE_STACK(knl_session->stack);
    cursor = knl_push_cursor(knl_session);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_SELECT, OBJECT_PRIVS_ID, IX_SYS_OBJECT_PRIVS_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&grantee,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&grantee_type,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE_TYPE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&item->objowner,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_OWNER);
    /* the length of objname is 68, and is not larger than uint16 */
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, (void *)&item->objname,
                     (uint16)strlen(item->objname), IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_NAME);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&item->objtype,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_TYPE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&item->privid,
                     sizeof(uint32), IX_COL_SYS_OBJECT_PRIVS_001_PRIVILEGE);

    if (GS_SUCCESS != knl_fetch(knl_session, cursor)) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }
    *up_grantor = GS_INVALID_ID32;
    if (!cursor->eof) {
        *up_grantor = *(uint32 *)CURSOR_COLUMN_DATA(cursor, OBJECT_PRIVS_COL_GRANTOR);
    }
    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

status_t db_revoke_objpriv_from_user(knl_handle_t session, void *def, knl_holders_def_t *revokee,
                                     knl_priv_def_t *priv)
{
    uint32 objowner;
    uint32 grantorid;
    dc_user_t *user = NULL;
    assist_obj_priv_item_t item;
    dc_obj_priv_entry_t *entry = NULL;
    knl_revoke_def_t *re_def = (knl_revoke_def_t *)def;

    if (dc_open_user((knl_session_t *)session, &revokee->name, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!dc_get_user_id((knl_session_t *)session, &re_def->schema, &objowner)) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&re_def->schema));
        return GS_ERROR;
    }
    /* the largest objtype is not larger than uint32 */
    if (dc_find_objpriv_entry(&user->obj_privs, objowner, &re_def->objname, (uint32)re_def->objtype, &entry)) {
        if (!DC_HAS_OBJ_PRIV(entry->priv_item.direct_grant, priv->priv_id)) {
            GS_THROW_ERROR(ERR_PRIVS_NOT_GRANT, T2S(&priv->priv_name),
                           T2S_EX(&revokee->name));
            return GS_ERROR;
        }
    } else {
        GS_THROW_ERROR(ERR_PRIVS_NOT_GRANT, T2S(&priv->priv_name),
                       T2S_EX(&revokee->name));
        return GS_ERROR;
    }

    item.objowner = objowner;
    item.objtype = re_def->objtype;
    (void)cm_text2str(&re_def->objname, item.objname, GS_NAME_BUFFER_SIZE);
    item.privid = priv->priv_id;
    if (db_get_grantor_id(session, user->desc.id, revokee->type, &item, &grantorid) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (grantorid == GS_INVALID_ID32) {
        GS_THROW_ERROR(ERR_USER_ID_NOT_EXIST, grantorid);
        return GS_ERROR;
    }
    return db_delete_obj_priv_by_grantor(session, grantorid, user->desc.id, revokee->type, &item);
}

status_t db_revoke_userpriv_from_user(knl_handle_t session, void *def, knl_holders_def_t *revokee,
    knl_priv_def_t *priv)
{
    uint32 grantee_id;
    dc_user_t *user = NULL;
    dc_user_priv_entry_t *entry = NULL;
    knl_revoke_def_t *re_def = (knl_revoke_def_t *)def;

    if (dc_open_user((knl_session_t *)session, &re_def->objname, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!dc_get_user_id((knl_session_t *)session, &revokee->name, &grantee_id)) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&re_def->schema));
        return GS_ERROR;
    }

    if (dc_find_user_priv_entry(&user->user_privs, grantee_id, &entry)) {
        if (!DC_HAS_OBJ_PRIV(entry->user_priv_item.privid_map, priv->priv_id)) {
            GS_THROW_ERROR(ERR_PRIVS_NOT_GRANT, T2S(&priv->priv_name),
                T2S_EX(&revokee->name));
            return GS_ERROR;
        }
    } else {
        GS_THROW_ERROR(ERR_PRIVS_NOT_GRANT, T2S(&priv->priv_name),
            T2S_EX(&revokee->name));
        return GS_ERROR;
    }

    return db_delete_user_privs_single(session, user->desc.id, grantee_id, GS_PRIV_INHERIT_PRIVILEGES);
}

status_t db_revoke_objpriv_from_role(knl_handle_t session, void *def, knl_holders_def_t *revokee,
                                     knl_priv_def_t *priv)
{
    uint32 rid, objowner;
    dc_role_t *role = NULL;
    dc_context_t *ctx = &((knl_session_t *)session)->kernel->dc_ctx;
    dc_obj_priv_entry_t *entry = NULL;
    knl_revoke_def_t *re_def = (knl_revoke_def_t *)def;
    assist_obj_priv_item_t item;

    if (!dc_get_role_id((knl_session_t *)session, &revokee->name, &rid)) {
        GS_THROW_ERROR(ERR_ROLE_NOT_EXIST, T2S(&revokee->name));
        return GS_ERROR;
    }

    if (!dc_get_user_id((knl_session_t *)session, &re_def->schema, &objowner)) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&re_def->schema));
        return GS_ERROR;
    }

    role = ctx->roles[rid];
    /* the largest objtype is not larger than uint32 */
    if (dc_find_objpriv_entry(&role->obj_privs, objowner, &re_def->objname, (uint32)re_def->objtype, &entry)) {
        if (!DC_HAS_OBJ_PRIV(entry->priv_item.direct_grant, priv->priv_id)) {
            GS_THROW_ERROR(ERR_PRIVS_NOT_GRANT, T2S(&priv->priv_name),
                           T2S_EX(&revokee->name));
            return GS_ERROR;
        }
    } else {
        GS_THROW_ERROR(ERR_PRIVS_NOT_GRANT, T2S(&priv->priv_name),
                       T2S_EX(&revokee->name));
        return GS_ERROR;
    }

    item.objowner = objowner;
    item.objtype = re_def->objtype;
    (void)cm_text2str(&re_def->objname, item.objname, GS_NAME_BUFFER_SIZE);
    item.privid = priv->priv_id;
    return db_delete_obj_priv(session, role->desc.id, revokee->type, &item);
}

status_t db_revoke_userpriv_from_role(knl_handle_t session, void *def, knl_holders_def_t *revokee,
    knl_priv_def_t *priv)
{
    GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "invalid privilege on role");
    return GS_ERROR;
}

status_t db_revoke_role_from_user(knl_handle_t session, void *def, knl_holders_def_t *revokee,
                                  knl_priv_def_t *priv)
{
    uint32 uid;
    uint32 rid;
    bool32 granted = GS_FALSE;
    dc_context_t *dc_ctx;
    dc_user_t *user = NULL;
    dc_role_t *role = NULL;
    dc_user_granted *child_user = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;

    dc_ctx = &knl_session->kernel->dc_ctx;
    if (!dc_get_user_id(knl_session, &revokee->name, &uid)) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&revokee->name));
        return GS_ERROR;
    }

    /* the user may dropped by others, it is not safe */
    user = dc_ctx->users[uid];

    if (!dc_get_role_id(knl_session, &priv->priv_name, &rid)) {
        GS_THROW_ERROR(ERR_ROLE_NOT_EXIST, T2S(&priv->priv_name));
        return GS_ERROR;
    }

    role = dc_ctx->roles[rid];

    /* check if the user has been already directly granted the role */
    cm_list_head *item = NULL;
    cm_list_for_each(item, &role->child_users)
    {
        /* the role has been granted to the user already */
        child_user = cm_list_entry(item, dc_user_granted, node);
        if (user == child_user->user_granted) {
            granted = GS_TRUE;
            break;
        }
    }

    if (!granted) {
        GS_THROW_ERROR(ERR_ROLE_NOT_GRANT, role->desc.name, T2S(&revokee->name));
        return GS_ERROR;
    }

    /* drop the tuple from USER_ROLES$ */
    return db_delete_user_roles(session, user->desc.id, revokee->type, role->desc.id);
}

status_t db_revoke_role_from_role(knl_handle_t session, void *def, knl_holders_def_t *revokee,
                                  knl_priv_def_t *priv)
{
    bool32 granted = GS_FALSE;
    uint32 rid1, rid2;
    cm_list_head *item = NULL;
    dc_role_t *role1 = NULL;
    dc_role_t *role2 = NULL;
    dc_granted_role *child = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;
    dc_context_t *ctx = &knl_session->kernel->dc_ctx;

    if (!dc_get_role_id(knl_session, &priv->priv_name, &rid1)) {
        GS_THROW_ERROR(ERR_ROLE_NOT_EXIST, T2S(&priv->priv_name));
        return GS_ERROR;
    }

    if (!dc_get_role_id(knl_session, &revokee->name, &rid2)) {
        GS_THROW_ERROR(ERR_ROLE_NOT_EXIST, T2S(&revokee->name));
        return GS_ERROR;
    }

    role1 = ctx->roles[rid1];
    role2 = ctx->roles[rid2];
    /* check if already granted role1 to role2 */
    cm_list_for_each(item, &role1->child_roles)
    {
        child = cm_list_entry(item, dc_granted_role, node);
        if (child->granted_role == role2) {
            granted = GS_TRUE;
            break;
        }
    }

    if (!granted) {
        GS_THROW_ERROR(ERR_ROLE_NOT_GRANT, role1->desc.name, T2S(&revokee->name));
        return GS_ERROR;
    }

    /* drop the tupe from USER_ROLES$ */
    return db_delete_user_roles(session, role2->desc.id, revokee->type, role1->desc.id);
}

status_t db_revoke_all_sysprivs(knl_handle_t session, void *def, knl_holders_def_t *revokee)
{
    uint32 grantee;
    uint32 rid;
    dc_user_t *user = NULL;
    dc_role_t *role = NULL;
    dc_context_t *ctx = &((knl_session_t *)session)->kernel->dc_ctx;

    if (revokee->type == TYPE_USER) {
        if (dc_open_user((knl_session_t *)session, &revokee->name, &user) != GS_SUCCESS) {
            return GS_ERROR;
        }
        grantee = user->desc.id;
    } else {
        if (!dc_get_role_id((knl_session_t *)session, &revokee->name, &rid)) {
            GS_THROW_ERROR(ERR_ROLE_NOT_EXIST, T2S(&revokee->name));
            return GS_ERROR;
        }
        role = ctx->roles[rid];
        grantee = role->desc.id;
    }
    /* the largest objtype is not larger than uint32 */
    return db_delete_all_sysprivs(session, grantee, (uint32)revokee->type);
}

status_t db_revoke_all_objprivs(knl_handle_t session, void *def, knl_holders_def_t *revokee)
{
    uint32 grantee;
    uint32 rid, uid;
    dc_user_t *user = NULL;
    dc_role_t *role = NULL;
    dc_obj_priv_item priv_item;
    knl_revoke_def_t *re_def = (knl_revoke_def_t *)def;
    dc_context_t *ctx = &((knl_session_t *)session)->kernel->dc_ctx;

    if (revokee->type == TYPE_USER) {
        if (dc_open_user((knl_session_t *)session, &revokee->name, &user) != GS_SUCCESS) {
            return GS_ERROR;
        }
        grantee = user->desc.id;
    } else {
        if (!dc_get_role_id((knl_session_t *)session, &revokee->name, &rid)) {
            GS_THROW_ERROR(ERR_ROLE_NOT_EXIST, T2S(&revokee->name));
            return GS_ERROR;
        }
        role = ctx->roles[rid];
        grantee = role->desc.id;
    }

    if (!dc_get_user_id((knl_session_t *)session, &re_def->schema, &uid)) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&re_def->schema));
        return GS_ERROR;
    }

    priv_item.objowner = uid;
    priv_item.objtype = re_def->objtype;
    (void)cm_text2str(&re_def->objname, priv_item.objname, GS_NAME_BUFFER_SIZE);
    /* the largest objtype is not larger than uint32 */
    return db_delete_all_objprivs(session, grantee, (uint32)revokee->type, &priv_item);
}

status_t db_revoke_allprivs(knl_handle_t session, void *def, knl_holders_def_t *revokee, knl_priv_def_t *priv)
{
    knl_revoke_def_t *re_def = (knl_revoke_def_t *)def;

    if (PRIV_TYPE_SYS_PRIV == re_def->priv_type) {
        return db_revoke_all_sysprivs(session, def, revokee);
    } else {
        return db_revoke_all_objprivs(session, def, revokee);
    }
}

static knl_priv_proc_tab g_grant_proc_func[] = {
    { PRIV_TYPE_SYS_PRIV, TYPE_USER, db_grant_syspriv_to_user },
    { PRIV_TYPE_SYS_PRIV, TYPE_ROLE, db_grant_syspriv_to_role },

    { PRIV_TYPE_OBJ_PRIV, TYPE_USER, db_grant_objpriv_to_user },
    { PRIV_TYPE_OBJ_PRIV, TYPE_ROLE, db_grant_objpriv_to_role },

    { PRIV_TYPE_USER_PRIV, TYPE_USER, db_grant_userpriv_to_user },
    { PRIV_TYPE_USER_PRIV, TYPE_ROLE, db_grant_userpriv_to_role },

    { PRIV_TYPE_ROLE, TYPE_USER, db_grant_role_to_user },
    { PRIV_TYPE_ROLE, TYPE_ROLE, db_grant_role_to_role },

    { PRIV_TYPE_ALL_PRIV, TYPE_USER, db_grant_allprivs_to_user },
    { PRIV_TYPE_ALL_PRIV, TYPE_ROLE, db_grant_allprivs_to_role }
};

static knl_priv_proc_tab g_revoke_proc_func[] = {
    { PRIV_TYPE_SYS_PRIV, TYPE_USER, db_revoke_syspriv_from_user },
    { PRIV_TYPE_SYS_PRIV, TYPE_ROLE, db_revoke_syspriv_from_role },

    { PRIV_TYPE_OBJ_PRIV, TYPE_USER, db_revoke_objpriv_from_user },
    { PRIV_TYPE_OBJ_PRIV, TYPE_ROLE, db_revoke_objpriv_from_role },

    { PRIV_TYPE_USER_PRIV, TYPE_USER, db_revoke_userpriv_from_user },
    { PRIV_TYPE_USER_PRIV, TYPE_ROLE, db_revoke_userpriv_from_role },

    { PRIV_TYPE_ROLE, TYPE_USER, db_revoke_role_from_user },
    { PRIV_TYPE_ROLE, TYPE_ROLE, db_revoke_role_from_role },

    { PRIV_TYPE_ALL_PRIV, TYPE_USER, db_revoke_allprivs },
    { PRIV_TYPE_ALL_PRIV, TYPE_ROLE, db_revoke_allprivs }
};

void dc_grant_syspriv_to_user(knl_handle_t session, void *def, void *privs, hold_t *h)
{
    dc_context_t *dc_ctx;
    dc_user_t *user;
    knl_session_t *knl_session = (knl_session_t *)session;
    knl_grant_def_t *grant_def = (knl_grant_def_t *)def;
    priv_t *p = (priv_t *)privs;

    dc_ctx = &knl_session->kernel->dc_ctx;
    user = (dc_user_t *)h->handle;
    /* check if the user has been already directly granted the system privilege */
    if (DC_HAS_SYS_PRIV(user->sys_privs, p->id)) {
        if (grant_def->admin_opt == 1 && !DC_HAS_SYS_OPT(user->admin_opt, p->id)) {
            dls_spin_lock(session, &user->lock, NULL);
            DC_SET_SYS_OPT(user->admin_opt, p->id);
            DC_SET_SYS_OPT(user->ter_admin_opt, p->id);
            dls_spin_unlock(session, &user->lock);
            return;
        }

        return;
    }

    /* add priv item to user dc */
    cm_spin_lock(&dc_ctx->lock, NULL);
    DC_SET_PRIV_INFO(user->sys_privs, user->admin_opt, p->id, grant_def->admin_opt);
    DC_SET_SYS_PRIV(user->all_sys_privs, p->id);
    if (grant_def->admin_opt == 1) {
        DC_SET_SYS_OPT(user->ter_admin_opt, p->id);
    }
    cm_spin_unlock(&dc_ctx->lock);
}

void dc_grant_syspriv_to_role(knl_handle_t session, void *def, void *privs, hold_t *h)
{
    dc_context_t *dc_ctx;
    dc_role_t *role;
    knl_session_t *knl_session = (knl_session_t *)session;
    knl_grant_def_t *grant_def = (knl_grant_def_t *)def;
    priv_t *p = (priv_t *)privs;

    dc_ctx = &knl_session->kernel->dc_ctx;
    role = (dc_role_t *)h->handle;

    /* check if the role has been already directly granted the system privilege. */
    if (DC_HAS_SYS_PRIV(role->sys_privs, p->id)) {
        if (grant_def->admin_opt == 1 && !DC_HAS_SYS_OPT(role->admin_opt, p->id)) {
            dls_spin_lock(knl_session, &role->lock, NULL);
            DC_SET_SYS_OPT(role->admin_opt, p->id);
            dc_update_user_syspriv_by_role(role);
            dls_spin_unlock(knl_session, &role->lock);
        }

        return;
    }

    /* add priv item to role dc */
    cm_spin_lock(&dc_ctx->lock, NULL);
    DC_SET_PRIV_INFO(role->sys_privs, role->admin_opt, p->id, grant_def->admin_opt);

    /*
     * update privileges information in dc for all the users that the role granted to
     *  (include users indirectly granted through other roles)
     */
    dc_update_user_syspriv_by_role(role);
    cm_spin_unlock(&dc_ctx->lock);
}

void dc_grant_objpriv_to_user(knl_handle_t session, void *def, void *privs, hold_t *h)
{
    uint32 grantor = ((knl_session_t *)session)->uid;
    dc_user_t *user;
    knl_grant_def_t *grant_def = (knl_grant_def_t *)def;
    priv_t *p = (priv_t *)privs;
    dc_obj_priv_entry_t *entry = NULL;
    dc_context_t *ctx = &((knl_session_t *)session)->kernel->dc_ctx;

    user = (dc_user_t *)h->handle;
    if (grant_def->objowner == user->desc.id ||
        (user->desc.id == DB_SYS_USER_ID && grant_def->priv_type != PRIV_TYPE_OBJ_PRIV)) {
        return;
    }

    /* check if the user has been already directly granted the object privilege */
    /* the largest objtype is not larger than uint32 */
    if (dc_find_objpriv_entry(&user->obj_privs, grant_def->objowner, &grant_def->objname,
                              (uint32)grant_def->objtype, &entry)) {
        if (DC_HAS_OBJ_PRIV(entry->priv_item.direct_grant, p->id)) {
            /* need update the grant option ? */
            if (1 == grant_def->grant_opt && !DC_HAS_OBJ_OPT(entry->priv_item.direct_opt, p->id)) {
                DC_SET_OBJ_OPT(entry->priv_item.direct_opt, p->id);
                DC_SET_OBJ_OPT(entry->priv_item.privopt_map, p->id);
            }

            return;
        }
    } else {
        /* add a entry for the object */
        GS_RETVOID_IFERR(dc_alloc_objpriv_entry(ctx, &user->obj_privs, user->memory, grant_def->objowner,
                                                &grant_def->objname, grant_def->objtype, &entry));
    }

    /* add priv item to user dc */
    cm_spin_lock(&entry->bucket->lock, NULL);
    DC_SET_OBJ_PRIV(entry->priv_item.direct_grant, p->id);
    DC_SET_OBJ_PRIV(entry->priv_item.privid_map, p->id);
    entry->priv_item.grantor[p->id] = grantor;
    if (grant_def->grant_opt == 1) {
        DC_SET_OBJ_OPT(entry->priv_item.direct_opt, p->id);
        DC_SET_OBJ_OPT(entry->priv_item.privopt_map, p->id);
    }
    cm_spin_unlock(&entry->bucket->lock);
}

void dc_grant_userpriv_to_user(knl_handle_t session, void *def, void *privs, hold_t *h)
{
    uint32 grantor = ((knl_session_t *)session)->uid;
    dc_user_t *user = NULL;
    dc_user_t *grantee = NULL;
    priv_t *p = (priv_t *)privs;
    dc_user_priv_entry_t *entry = NULL;
    knl_grant_def_t *grant_def = (knl_grant_def_t *)def;
    dc_context_t *ctx = &((knl_session_t *)session)->kernel->dc_ctx;

    grantee = (dc_user_t *)h->handle;

    if (dc_open_user((knl_session_t *)session, &grant_def->objname, &user) != GS_SUCCESS) {
        return;
    }

    if (dc_find_user_priv_entry(&user->user_privs, grantee->desc.id, &entry)) {
        if (DC_HAS_OBJ_PRIV(entry->user_priv_item.privid_map, p->id)) {
            return;
        }
    } else {
        GS_RETVOID_IFERR(dc_alloc_user_priv_entry(ctx, &user->user_privs, user->memory,
            grantee->desc.id, &entry));
    }

    /* add user priv to user dc */
    cm_spin_lock(&entry->bucket->lock, NULL);
    DC_SET_OBJ_PRIV(entry->user_priv_item.privid_map, p->id);
    entry->user_priv_item.grantor[p->id] = grantor;
    cm_spin_unlock(&entry->bucket->lock);
}

void dc_grant_objpriv_to_role(knl_handle_t session, void *def, void *privs, hold_t *h)
{
    uint32 grantor = ((knl_session_t *)session)->uid;
    dc_role_t *role;
    knl_grant_def_t *grant_def = (knl_grant_def_t *)def;
    priv_t *p = (priv_t *)privs;
    dc_obj_priv_entry_t *entry = NULL;
    dc_context_t *ctx = &((knl_session_t *)session)->kernel->dc_ctx;

    role = (dc_role_t *)h->handle;

    /* check if the role has been already directly granted the object privilege */
    /* the largest objtype is not larger than uint32 */
    if (dc_find_objpriv_entry(&role->obj_privs, grant_def->objowner, &grant_def->objname,
                              (uint32)grant_def->objtype, &entry)) {
        if (DC_HAS_OBJ_PRIV(entry->priv_item.direct_grant, p->id)) {
            return;
        }
    } else {
        /* alloc an entry for the object */
        GS_RETVOID_IFERR(dc_alloc_objpriv_entry(ctx, &role->obj_privs, role->memory, grant_def->objowner,
                                                &grant_def->objname, grant_def->objtype, &entry));
    }

    /* add priv item to dc */
    cm_spin_lock(&entry->bucket->lock, NULL);
    DC_SET_OBJ_PRIV(entry->priv_item.direct_grant, p->id);
    entry->priv_item.grantor[p->id] = grantor;
    cm_spin_unlock(&entry->bucket->lock);
    dc_update_user_objpriv_by_role(ctx, role, &entry->priv_item);
}

bool32 dc_rela_role_to_user(knl_session_t *sess, dc_user_t *user,
    dc_role_t *role, knl_grant_def_t *grant_def)
{
    dc_granted_role *grant_role = NULL;
    dc_user_granted *user_grant = NULL;
    cm_list_head *item = NULL;

    if (cm_list_is_empty(&role->child_users_free)) {
        if (dc_alloc_mem(&sess->kernel->dc_ctx, role->memory, sizeof(dc_user_granted),
            (void **)&user_grant) != GS_SUCCESS) {
            return GS_FALSE;
        }
    } else {
        item = role->child_users_free.next;
        user_grant = cm_list_entry(item, dc_user_granted, node);
        cm_list_remove(item);
    }
    user_grant->admin_opt = grant_def->admin_opt;
    user_grant->user_granted = user;
    if (cm_list_is_empty(&user->parent_free)) {
        if (dc_alloc_mem(&sess->kernel->dc_ctx, user->memory, sizeof(dc_granted_role),
            (void **)&grant_role) != GS_SUCCESS) {
            return GS_FALSE;
        }
    } else {
        item = user->parent_free.next;
        grant_role = cm_list_entry(item, dc_granted_role, node);
        cm_list_remove(item);
    }
    grant_role->admin_opt = grant_def->admin_opt;
    grant_role->granted_role = role;
    /* add the user to the list of the role */
    cm_list_add(&user_grant->node, &role->child_users);
    cm_list_add(&grant_role->node, &user->parent);
    return GS_TRUE;
}


void dc_grant_role_to_user(knl_handle_t session, void *def, void *privs, hold_t *h)
{
    dc_user_t *user;
    dc_role_t *role;
    dc_user_granted *user_grant = NULL;
    knl_grant_def_t *grant_def = (knl_grant_def_t *)def;
    grant_role_t *g = (grant_role_t *)privs;
    knl_session_t *sess = (knl_session_t *)session;

    /* the user may dropped by others, it is not safe */
    user = (dc_user_t *)h->handle;
    role = (dc_role_t *)g->handle;
    dls_spin_lock(session, &user->lock, NULL);
    dls_spin_lock(session, &role->lock, NULL);

    /* check if the user has been already directly granted the role */
    cm_list_head *item = NULL;
    cm_list_for_each(item, &role->child_users)
    {
        /* the role has been granted to the user already */
        user_grant = cm_list_entry(item, dc_user_granted, node);
        if (user == user_grant->user_granted) {
            if (grant_def->admin_opt == 1 && user_grant->admin_opt == 0) {
                user_grant->admin_opt = 1;
                db_update_admin_opt(role, user);
                dls_spin_unlock(session, &user->lock);
                dls_spin_unlock(session, &role->lock);
                return;
            }
            dls_spin_unlock(session, &user->lock);
            dls_spin_unlock(session, &role->lock);
            return;
        }
    }
    if (dc_rela_role_to_user(sess, user, role, grant_def) == GS_FALSE) {
        dls_spin_unlock(session, &user->lock);
        dls_spin_unlock(session, &role->lock);
        return;
    }
    dls_spin_unlock(session, &user->lock);
    dls_spin_unlock(session, &role->lock);

    /* update the user's system & object privileges */
    dc_update_user_syspriv_info(user);
    dc_update_all_objprivs_info(sess, user);
}
bool32 dc_rela_role_to_role(knl_session_t *sess,
    dc_role_t *role1, dc_role_t *role2, knl_grant_def_t *grant_def)
{
    cm_list_head *item = NULL;
    dc_granted_role *child = NULL;
    dc_granted_role *parent = NULL;

    if (cm_list_is_empty(&role1->child_roles_free)) {
        if (dc_alloc_mem(&sess->kernel->dc_ctx, role1->memory, sizeof(dc_granted_role),
            (void **)&child) != GS_SUCCESS) {
            return GS_FALSE;
        }
    } else {
        item = role1->child_roles_free.next;
        child = cm_list_entry(item, dc_granted_role, node);
        cm_list_remove(item);
    }

    child->admin_opt = grant_def->admin_opt;
    child->granted_role = role2;

    if (cm_list_is_empty(&role2->parent_free)) {
        if (dc_alloc_mem(&sess->kernel->dc_ctx, role2->memory, sizeof(dc_granted_role),
            (void **)&parent) != GS_SUCCESS) {
            return GS_FALSE;
        }
    } else {
        item = role2->parent_free.next;
        parent = cm_list_entry(item, dc_granted_role, node);
        cm_list_remove(item);
    }
    parent->admin_opt = grant_def->admin_opt;
    parent->granted_role = role1;
    cm_list_add(&child->node, &role1->child_roles);
    cm_list_add(&parent->node, &role2->parent);
    return GS_TRUE;
}

void dc_grant_role_to_role(knl_handle_t session, void *def, void *privs, hold_t *h)
{
    bool32 granted = GS_FALSE;
    cm_list_head *item = NULL;
    dc_role_t *role1, *role2;
    dc_granted_role *child = NULL;
    knl_grant_def_t *grant_def = (knl_grant_def_t *)def;
    grant_role_t *g = (grant_role_t *)privs;
    knl_session_t *sess = (knl_session_t *)session;

    role1 = (dc_role_t *)g->handle;
    role2 = (dc_role_t *)h->handle;
    dls_spin_lock(sess, &role1->lock, NULL);  // TODO: check dls
    dls_spin_lock(sess, &role2->lock, NULL);

    /* check if already granted role1 to role2 */
    cm_list_for_each(item, &role1->child_roles)
    {
        child = cm_list_entry(item, dc_granted_role, node);
        if (child->granted_role == role2) {
            granted = GS_TRUE;
            if (grant_def->admin_opt == 1 && child->admin_opt == 0) {
                child->admin_opt = 1;
            }
        }
    }
    if (!granted) {
        if (dc_rela_role_to_role(sess, role1, role2, grant_def) == GS_FALSE) {
            dls_spin_unlock(sess, &role1->lock);
            dls_spin_unlock(sess, &role2->lock);
            return;
        }
    }
    dls_spin_unlock(sess, &role1->lock);
    dls_spin_unlock(sess, &role2->lock);
    /* update the user's system & object privileges */
    dc_update_user_syspriv_by_role(role2);
    /* for each object granted to role1, merge its' privileges to all the role2's child users */
    dc_update_all_objprivs_by_role(sess, role2);
}

void dc_grant_objpriv(knl_handle_t session, void *def, hold_t *h, obj_privs_id *privset, uint32 count)
{
    uint32 i;
    priv_t p;

    p.type = PRIV_TYPE_OBJ_PRIV;

    for (i = 0; i < count; i++) {
        p.id = privset[i];
        if (h->type == TYPE_USER) {
            dc_grant_objpriv_to_user(session, def, &p, h);
        } else {
            dc_grant_objpriv_to_role(session, def, &p, h);
        }
    }
}

void dc_grant_allobjprivs(knl_handle_t session, void *def, hold_t *h)
{
    uint32 count = 0;
    obj_privs_id *set = NULL;
    knl_grant_def_t *grant_def = (knl_grant_def_t *)def;

    knl_get_objprivs_set(grant_def->objtype, &set, &count);
    if (set == NULL || count == 0) {
        return;
    }

    dc_grant_objpriv(session, def, h, set, count);
}

void dc_grant_allprivs_to_user(knl_handle_t session, void *def, void *privs, hold_t *h)
{
    uint32 priv_id;
    priv_t priv_item;
    knl_grant_def_t *grant_def = (knl_grant_def_t *)def;

    if (grant_def->priv_type == PRIV_TYPE_SYS_PRIV) {
        for (priv_id = ALL_PRIVILEGES + 1; priv_id < GS_SYS_PRIVS_COUNT; priv_id++) {
            priv_item.id = priv_id;
            priv_item.type = PRIV_TYPE_SYS_PRIV;
            dc_grant_syspriv_to_user(session, def, &priv_item, h);
        }
    } else {
        dc_grant_allobjprivs(session, def, h);
    }
}

void dc_grant_allprivs_to_role(knl_handle_t session, void *def, void *privs, hold_t *h)
{
    uint32 priv_id;
    priv_t priv_item;
    knl_grant_def_t *grant_def = (knl_grant_def_t *)def;

    if (grant_def->priv_type == PRIV_TYPE_SYS_PRIV) {
        for (priv_id = ALL_PRIVILEGES + 1; priv_id < GS_SYS_PRIVS_COUNT; priv_id++) {
            priv_item.id = priv_id;
            priv_item.type = PRIV_TYPE_SYS_PRIV;
            dc_grant_syspriv_to_role(session, def, &priv_item, h);
        }
    } else {
        dc_grant_allobjprivs(session, def, h);
    }
}

void dc_revoke_syspriv_from_user(knl_handle_t session, void *def, void *privs, hold_t *h)
{
    knl_session_t *knl_session = (knl_session_t *)session;
    dc_context_t *ctx = &knl_session->kernel->dc_ctx;
    dc_user_t *user = NULL;
    priv_t *p = (priv_t *)privs;

    /* update revokee's privilege information in user dc */
    cm_spin_lock(&ctx->lock, NULL);
    user = (dc_user_t *)h->handle;
    DC_CLR_PRIV_INFO(user->sys_privs, user->admin_opt, p->id);
    dc_update_user_syspriv_info(user);
    cm_spin_unlock(&ctx->lock);
}

void dc_revoke_syspriv_from_role(knl_handle_t session, void *def, void *privs, hold_t *h)
{
    dc_role_t *role;
    priv_t *p = (priv_t *)privs;

    role = (dc_role_t *)h->handle;
    /* update the role and all the users terminal system privileges */
    DC_CLR_PRIV_INFO(role->sys_privs, role->admin_opt, p->id);
    dc_update_user_syspriv_by_role(role);
}

void dc_revoke_objpriv_from_user(knl_handle_t session, void *def, void *privs, hold_t *h)
{
    priv_t *p = (priv_t *)privs;
    dc_obj_priv_item item;
    knl_revoke_def_t *re_def = (knl_revoke_def_t *)def;
    knl_session_t *knl_session = (knl_session_t *)session;

    dc_user_t *user = (dc_user_t *)h->handle;
    item.objowner = re_def->objowner;
    item.objtype = re_def->objtype;
    (void)cm_text2str(&re_def->objname, item.objname, GS_NAME_BUFFER_SIZE);
    dc_revoke_objpriv_from_user_by_id(&knl_session->kernel->dc_ctx, user, &item, p->id);
}

void dc_revoke_userpriv_from_user(knl_handle_t session, void *def, void *privs, hold_t *h)
{
    dc_user_t *user = NULL;
    dc_user_t *grantee = NULL;
    priv_t *p = (priv_t *)privs;
    knl_revoke_def_t *re_def = (knl_revoke_def_t *)def;
    knl_session_t *knl_session = (knl_session_t *)session;

    if (dc_open_user(session, &re_def->objname, &user) != GS_SUCCESS) {
        return;
    }

    grantee = (dc_user_t *)h->handle;
    dc_revoke_userpriv_from_user_by_id(&knl_session->kernel->dc_ctx, user, grantee->desc.id, p->id);
}

void dc_revoke_objpriv_from_role(knl_handle_t session, void *def, void *privs, hold_t *h)
{
    dc_role_t *role;
    priv_t *p = (priv_t *)privs;
    dc_obj_priv_item item;
    knl_revoke_def_t *re_def = (knl_revoke_def_t *)def;
    knl_session_t *knl_session = (knl_session_t *)session;

    role = (dc_role_t *)h->handle;
    item.objowner = re_def->objowner;
    item.objtype = re_def->objtype;
    (void)cm_text2str(&re_def->objname, item.objname, GS_NAME_BUFFER_SIZE);
    dc_revoke_objpriv_from_role_by_id(&knl_session->kernel->dc_ctx, role, &item, p->id);
}

void dc_revoke_role_from_user(knl_handle_t session, void *def, void *privs, hold_t *h)
{
    bool32 granted = GS_FALSE;
    dc_granted_role *parent_role = NULL;
    dc_user_granted *child_user = NULL;
    grant_role_t *g = (grant_role_t *)privs;

    /* the user may dropped by others, it is not safe */
    dc_user_t *user = (dc_user_t *)h->handle;
    dc_role_t *role = (dc_role_t *)g->handle;
    dls_spin_lock(session, &user->lock, NULL);
    dls_spin_lock(session, &role->lock, NULL);

    /* check if the user has been already directly granted the role */
    cm_list_head *temp = NULL;
    cm_list_head *item = NULL;
    cm_list_for_each_safe(item, temp, &role->child_users)
    {
        /* the role has been granted to the user already */
        child_user = cm_list_entry(item, dc_user_granted, node);
        if (user == child_user->user_granted) {
            granted = GS_TRUE;
            cm_list_remove(item);
            cm_list_add(&child_user->node, &role->child_users_free);
            break;
        }
    }

    if (!granted) {
        dls_spin_unlock(session, &user->lock);
        dls_spin_unlock(session, &role->lock);
        return;
    }

    /* delete the user from roles' list */
    cm_list_for_each_safe(item, temp, &user->parent)
    {
        parent_role = cm_list_entry(item, dc_granted_role, node);
        if (parent_role->granted_role == role) {
            cm_list_remove(item);
            cm_list_add(&parent_role->node, &user->parent_free);
            break;
        }
    }
    dls_spin_unlock(session, &user->lock);
    dls_spin_unlock(session, &role->lock);

    /* update the user's & all the users' (granted the role) privileges */
    dc_update_user_syspriv_info(user);

    /* for each object granted to the role & all its' parents, update the user's object privileges */
    dc_update_all_objprivs_info((knl_session_t *)session, user);
}

void dc_revoke_role_from_role(knl_handle_t session, void *def, void *privs, hold_t *h)
{
    bool32 granted = GS_FALSE;
    cm_list_head *temp = NULL;
    cm_list_head *item = NULL;
    dc_role_t *role1, *role2;
    dc_granted_role *child = NULL;
    dc_granted_role *parent = NULL;
    grant_role_t *g = (grant_role_t *)privs;
    knl_session_t *sess = (knl_session_t *)session;

    role1 = (dc_role_t *)g->handle;
    role2 = (dc_role_t *)h->handle;
    dls_spin_lock(sess, &role1->lock, NULL);
    dls_spin_lock(sess, &role2->lock, NULL);
    /* check if already granted role1 to role2 */
    cm_list_for_each_safe(item, temp, &role1->child_roles)
    {
        child = cm_list_entry(item, dc_granted_role, node);
        if (child->granted_role == role2) {
            granted = GS_TRUE;
            cm_list_remove(item);
            cm_list_add(&child->node, &role1->child_roles_free);
            break;
        }
    }

    if (!granted) {
        dls_spin_unlock(sess, &role1->lock);
        dls_spin_unlock(sess, &role2->lock);
        return;
    }

    cm_list_for_each_safe(item, temp, &role2->parent)
    {
        parent = cm_list_entry(item, dc_granted_role, node);
        if (parent->granted_role == role1) {
            cm_list_remove(item);
            cm_list_add(&parent->node, &role2->parent_free);
            break;
        }
    }
    dls_spin_unlock(sess, &role1->lock);
    dls_spin_unlock(sess, &role2->lock);
    dc_update_user_syspriv_by_role(role2);
    /* for each object granted to role1, revoke the privileges from role2 */
    dc_update_all_objprivs_by_role((knl_session_t *)session, role2);
}

void dc_revoke_all_sysprivs(knl_handle_t session, void *def, hold_t *h)
{
    dc_user_t *user = NULL;
    dc_role_t *role = NULL;
    errno_t ret;

    if (h->type == TYPE_USER) {
        user = (dc_user_t *)h->handle;
        ret = memset_sp(user->sys_privs, GS_SYS_PRIVS_BYTES, 0, GS_SYS_PRIVS_BYTES);
        knl_securec_check(ret);
        ret = memset_sp(user->admin_opt, GS_SYS_PRIVS_BYTES, 0, GS_SYS_PRIVS_BYTES);
        knl_securec_check(ret);
        dc_update_user_syspriv_info(user);
    } else {
        role = (dc_role_t *)h->handle;
        ret = memset_sp(role->sys_privs, GS_SYS_PRIVS_BYTES, 0, GS_SYS_PRIVS_BYTES);
        knl_securec_check(ret);
        ret = memset_sp(role->admin_opt, GS_SYS_PRIVS_BYTES, 0, GS_SYS_PRIVS_BYTES);
        knl_securec_check(ret);
        dc_update_user_syspriv_by_role(role);
    }
}

void dc_revoke_all_objprivs(knl_handle_t session, void *def, hold_t *h)
{
    dc_user_t *user = NULL;
    dc_role_t *role = NULL;
    knl_revoke_def_t *re_def = (knl_revoke_def_t *)def;
    dc_obj_priv_t *group = NULL;
    dc_obj_priv_entry_t *entry = NULL;
    dc_context_t *ctx = &((knl_session_t *)session)->kernel->dc_ctx;

    if (h->type == TYPE_USER) {
        user = (dc_user_t *)h->handle;
        group = &user->obj_privs;
    } else {
        role = (dc_role_t *)h->handle;
        group = &role->obj_privs;
    }
    /* the largest objtype is not larger than uint32 */
    if (dc_find_objpriv_entry(group, re_def->objowner, &re_def->objname, (uint32)re_def->objtype, &entry)) {
        entry->priv_item.direct_grant = 0;
        entry->priv_item.direct_opt = 0;
        if (h->type == TYPE_USER) {
            dc_update_user_objpriv_info(ctx, user, &entry->priv_item);
        } else {
            dc_update_user_objpriv_by_role(ctx, role, &entry->priv_item);
        }
    } else {
        /* the user or role has not grant any object privilege before */
        return;
    }
}

void dc_revoke_allprivs(knl_handle_t session, void *def, void *privs, hold_t *h)
{
    knl_revoke_def_t *revoke_def = (knl_revoke_def_t *)def;

    if (PRIV_TYPE_SYS_PRIV == revoke_def->priv_type) {
        dc_revoke_all_sysprivs(session, def, h);
    } else if (PRIV_TYPE_OBJ_PRIV == revoke_def->priv_type) {
        dc_revoke_all_objprivs(session, def, h);
    }
}

static knl_dc_update_proc_tab g_grant_dc_update_func[] = {
    { PRIV_TYPE_SYS_PRIV, TYPE_USER, dc_grant_syspriv_to_user },
    { PRIV_TYPE_SYS_PRIV, TYPE_ROLE, dc_grant_syspriv_to_role },

    { PRIV_TYPE_OBJ_PRIV, TYPE_USER, dc_grant_objpriv_to_user },
    { PRIV_TYPE_OBJ_PRIV, TYPE_ROLE, dc_grant_objpriv_to_role },

    { PRIV_TYPE_USER_PRIV, TYPE_USER, dc_grant_userpriv_to_user },

    { PRIV_TYPE_ROLE, TYPE_USER, dc_grant_role_to_user },
    { PRIV_TYPE_ROLE, TYPE_ROLE, dc_grant_role_to_role },

    { PRIV_TYPE_ALL_PRIV, TYPE_USER, dc_grant_allprivs_to_user },
    { PRIV_TYPE_ALL_PRIV, TYPE_ROLE, dc_grant_allprivs_to_role }
};

static knl_dc_update_proc_tab g_revoke_dc_update_func[] = {
    { PRIV_TYPE_SYS_PRIV, TYPE_USER, dc_revoke_syspriv_from_user },
    { PRIV_TYPE_SYS_PRIV, TYPE_ROLE, dc_revoke_syspriv_from_role },

    { PRIV_TYPE_OBJ_PRIV, TYPE_USER, dc_revoke_objpriv_from_user },
    { PRIV_TYPE_OBJ_PRIV, TYPE_ROLE, dc_revoke_objpriv_from_role },

    { PRIV_TYPE_USER_PRIV, TYPE_USER, dc_revoke_userpriv_from_user },

    { PRIV_TYPE_ROLE, TYPE_USER, dc_revoke_role_from_user },
    { PRIV_TYPE_ROLE, TYPE_ROLE, dc_revoke_role_from_role },

    { PRIV_TYPE_ALL_PRIV, TYPE_USER, dc_revoke_allprivs },
    { PRIV_TYPE_ALL_PRIV, TYPE_ROLE, dc_revoke_allprivs }
};

#define PRIV_GRANT_PROC_FUNC_COUNT       (sizeof(g_grant_proc_func) / sizeof(knl_priv_proc_tab))
#define PRIV_REVOKE_PROC_FUNC_COUNT      (sizeof(g_revoke_proc_func) / sizeof(knl_priv_proc_tab))
#define PRIV_GRANT_DC_UPDATE_FUNC_COUNT  (sizeof(g_grant_dc_update_func) / sizeof(knl_dc_update_proc_tab))
#define PRIV_REVOKE_DC_UPDATE_FUNC_COUNT (sizeof(g_revoke_dc_update_func) / sizeof(knl_dc_update_proc_tab))

priv_proc_func find_priv_proc_function(knl_priv_proc_tab *proc_tab, uint32 count,
                                       priv_type_def priv_type, type_def grantee_type)
{
    uint32 i;

    for (i = 0; i < count; i++) {
        if (proc_tab[i].priv_type == priv_type && proc_tab[i].grantee_type == grantee_type) {
            return proc_tab[i].proc_func;
        }
    }

    return NULL;
}

dc_update_proc_func find_dc_update_proc_function(knl_dc_update_proc_tab *proc_tab, uint32 count,
                                                 priv_type_def priv_type, type_def grantee_type)
{
    uint32 i;

    for (i = 0; i < count; i++) {
        if (proc_tab[i].priv_type == priv_type && proc_tab[i].grantee_type == grantee_type) {
            return proc_tab[i].proc_func;
        }
    }

    return NULL;
}

status_t db_exec_grant_write_table(knl_handle_t session, knl_grant_def_t *def)
{
    uint32 i, j;
    knl_holders_def_t *grantee = NULL;
    knl_priv_def_t *priv = NULL;
    priv_proc_func proc_func = NULL;

    for (i = 0; i < def->grantees.count; i++) {
        grantee = (knl_holders_def_t *)cm_galist_get(&def->grantees, i);
        if (grantee == NULL) {
            GS_LOG_RUN_ERR("[PRIV] failed to load grantee:%u", i);
            return GS_ERROR;
        }

        for (j = 0; j < def->privs.count; j++) {
            priv = (knl_priv_def_t *)cm_galist_get(&def->privs, j);
            if (def->objtype == OBJ_TYPE_DIRECTORY) {
                bool32 dire_exists = GS_FALSE;
                if (db_fetch_directory_path(session, T2S(&def->objname), NULL, 0, &dire_exists) != GS_SUCCESS) {
                    return GS_ERROR;
                }

                if (!dire_exists) {
                    GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "directory", T2S(&def->objname));
                    return GS_ERROR;
                }

                if (priv->priv_id != GS_PRIV_DIRE_READ) {
                    GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "grant write/excute privilege on directory");
                    return GS_ERROR;
                }
            }
            
            proc_func = find_priv_proc_function(g_grant_proc_func, PRIV_GRANT_PROC_FUNC_COUNT,
                                                priv->priv_type, grantee->type);
            if (proc_func == NULL) {
                GS_LOG_RUN_ERR("[PRIV] failed to find priv proc function");
                return GS_ERROR;
            }

            if (proc_func(session, def, grantee, priv) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }
    return GS_SUCCESS;
}

static status_t db_check_privs_before_grant(knl_session_t *session, knl_grant_def_t *def)
{
    uint32 i;
    grant_role_t *g = NULL;
    priv_t *p = NULL;
    knl_priv_def_t *priv = NULL;
    uint32 rid;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    for (i = 0; i < def->privs.count; i++) {
        priv = (knl_priv_def_t *)cm_galist_get(&def->privs, i);
        if (priv->priv_type == PRIV_TYPE_ROLE) {
            if (!dc_get_role_id(session, &priv->priv_name, &rid)) {
                GS_THROW_ERROR(ERR_ROLE_NOT_EXIST, T2S(&priv->priv_name));
                return GS_ERROR;
            }
            if (cm_galist_new(&def->privs_list, sizeof(grant_role_t), (void **)&g) != GS_SUCCESS) {
                return GS_ERROR;
            }
            g->type = PRIV_TYPE_ROLE;
            g->handle = ctx->roles[rid];
        } else {
            if (cm_galist_new(&def->privs_list, sizeof(priv_t), (void **)&p) != GS_SUCCESS) {
                return GS_ERROR;
            }
            p->type = priv->priv_type;
            p->id = priv->priv_id;
        }
    }

    return GS_SUCCESS;
}

static status_t db_check_grantees_before_grant(knl_session_t *session, knl_grant_def_t *def)
{
    uint32 i;
    hold_t *h = NULL;
    knl_holders_def_t *grantee = NULL;
    uint32 rid, uid;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    for (i = 0; i < def->grantees.count; i++) {
        grantee = (knl_holders_def_t *)cm_galist_get(&def->grantees, i);
        if (grantee->type == TYPE_ROLE) {
            if (!dc_get_role_id(session, &grantee->name, &rid)) {
                GS_THROW_ERROR(ERR_ROLE_NOT_EXIST, T2S(&grantee->name));
                return GS_ERROR;
            }
            if (cm_galist_new(&def->grantee_list, sizeof(hold_t), (void **)&h) != GS_SUCCESS) {
                return GS_ERROR;
            }
            h->type = TYPE_ROLE;
            h->handle = ctx->roles[rid];
        } else {
            if (!dc_get_user_id(session, &grantee->name, &uid)) {
                GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&grantee->name));
                return GS_ERROR;
            }
            if (cm_galist_new(&def->grantee_list, sizeof(hold_t), (void **)&h) != GS_SUCCESS) {
                return GS_ERROR;
            }
            h->type = TYPE_USER;
            h->handle = ctx->users[uid];
        }
    }

    return GS_SUCCESS;
}

static status_t db_exec_grant_check(knl_session_t *session, knl_grant_def_t *def)
{
    /* check privs */
    if (db_check_privs_before_grant(session, def) != GS_SUCCESS) {
        return GS_ERROR;
    }
    /* check grantees */
    if (db_check_grantees_before_grant(session, def) != GS_SUCCESS) {
        return GS_ERROR;
    }
    /* check object user */
    if (def->schema.len != 0 && !dc_get_user_id(session, &def->schema, &def->objowner)) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

void db_grant_update_dc(knl_session_t *session, knl_grant_def_t *def)
{
    uint32 i, j;
    dc_update_proc_func proc_func = NULL;
    void *priv = NULL;
    hold_t *h = NULL;

    for (i = 0; i < def->grantee_list.count; i++) {
        h = (hold_t *)cm_galist_get(&def->grantee_list, i);

        for (j = 0; j < def->privs_list.count; j++) {
            priv = cm_galist_get(&def->privs_list, j);

            proc_func = find_dc_update_proc_function(g_grant_dc_update_func, PRIV_GRANT_DC_UPDATE_FUNC_COUNT,
                                                     *(priv_type_def *)priv, h->type);
            if (proc_func != NULL) {
                proc_func(session, def, priv, h);
            }
        }
    }
    return;
}

status_t db_exec_grant_update_dc(knl_session_t *session, knl_grant_def_t *def)
{
    if (db_exec_grant_check(session, def) != GS_SUCCESS) {
        return GS_ERROR;
    }
    cm_reset_error();
    db_grant_update_dc(session, def);
    if ((g_tls_error.code == ERR_GRANT_OBJ_EXCEED_MAX) ||
        (g_tls_error.code == ERR_DC_BUFFER_FULL) ||
        (g_tls_error.code == ERR_ALLOC_GA_MEMORY)) {
        knl_rollback(session, NULL);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

void priv_log_put(knl_session_t *session, galist_t *holders)
{
    uint32 i;
    rd_privs_t redo;
    hold_t *grantee = NULL;

    redo.op_type = RD_GRANT_PRIVS;

    for (i = 0; i < holders->count; i++) {
        grantee = (hold_t *)cm_galist_get(holders, i);
        redo.type = (uint16)grantee->type;

        if (redo.type == TYPE_USER) {
            redo.id = (uint16)((dc_user_t *)(grantee->handle))->desc.id;
        } else {
            redo.id = (uint16)((dc_role_t *)(grantee->handle))->desc.id;
        }

        log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_privs_t), LOG_ENTRY_FLAG_NONE);
    }
}

void user_priv_log_put(knl_session_t *session, text_t *user)
{
    uint32 uid;
    rd_privs_t redo;

    if (!dc_get_user_id(session, user, &uid)) {
        return;
    }

    redo.type = TYPE_USER;
    redo.op_type = RD_GRANT_PRIVS;
    redo.id = (uint16)uid;
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_privs_t), LOG_ENTRY_FLAG_NONE);
}

void grant_log_put(knl_session_t *session, knl_grant_def_t *def)
{
    if (def->priv_type == PRIV_TYPE_USER_PRIV) {
        user_priv_log_put(session, &def->objname);
    } else {
        priv_log_put(session, &def->grantee_list);
    }
}

void revoke_log_put(knl_session_t *session, knl_revoke_def_t *def)
{
    if (def->priv_type == PRIV_TYPE_USER_PRIV) {
        user_priv_log_put(session, &def->objname);
    } else {
        priv_log_put(session, &def->revokee_list);
    }
}

status_t db_exec_grant_privs(knl_session_t *session, knl_grant_def_t *def)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;

    if (def->grantees.count == 0 || def->privs.count == 0) {
        GS_LOG_RUN_ERR("[PRIV] failed to exec grant privs");
        return GS_ERROR;
    }

    if (def->grantees.count > GS_MAX_GRANT_USERS) {
        GS_THROW_ERROR(ERR_GRANTEE_EXCEED_MAX, "grantee", GS_MAX_GRANT_USERS);
        return GS_ERROR;
    }

    dls_spin_lock(session, &ctx->paral_lock, NULL);
    if (db_exec_grant_write_table(session, def) != GS_SUCCESS) {
        dls_spin_unlock(session, &ctx->paral_lock);
        return GS_ERROR;
    }

    if (db_exec_grant_update_dc(session, def) != GS_SUCCESS) {
        dls_spin_unlock(session, &ctx->paral_lock);
        return GS_ERROR;
    }

    dls_spin_unlock(session, &ctx->paral_lock);
    grant_log_put(session, def);
    return GS_SUCCESS;
}

void rd_load_privileges(knl_session_t *session, uint32 id, uint32 type)
{
    if (dc_load_sys_privs_by_id(session, id, type) != GS_SUCCESS) {
        GS_LOG_RUN_WAR("[DC] load system privilege faild(id: %u, type: %u)", id, type);
        return;
    }

    if (dc_load_role_privs_by_id(session, id, type) != GS_SUCCESS) {
        GS_LOG_RUN_WAR("[DC] load role privilege faild(id: %u, type: %u)", id, type);
        return;
    }

    if (dc_load_obj_privs_by_id(session, id, type) != GS_SUCCESS) {
        GS_LOG_RUN_WAR("[DC] load object privilege faild(id: %u, type: %u)", id, type);
        return;
    }

    if (dc_load_user_privs_by_id(session, id) != GS_SUCCESS) {
        GS_LOG_RUN_WAR("[DC] load user privilege faild(id: %u)", id);
        return;
    }
}

void redo_refresh_sys_user_privs(knl_session_t *session)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    dc_user_t *sys_user = ctx->users[DB_SYS_USER_ID];

    dc_clear_all_userprivs(&sys_user->user_privs);

    if (dc_load_user_privs_by_id(session, DB_SYS_USER_ID) != GS_SUCCESS) {
        GS_LOG_RUN_WAR("[DC] load user privilege faild(id: %u)", DB_SYS_USER_ID);
        return;
    }
}

void rd_alter_privs(knl_session_t *session, log_entry_t *log)
{
    rd_privs_t *rd = (rd_privs_t *)log->data;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    if ((type_def)rd->type == TYPE_USER) {
        if (rd->id == DB_SYS_USER_ID) {
            redo_refresh_sys_user_privs(session);
            return;
        }

        rd_clear_user_priv(ctx, ctx->users[rd->id]);
    } else {
        dc_clear_role_priv(session, ctx->roles[rd->id]);
    }

    rd_load_privileges(session, rd->id, rd->type);
}

void print_grant_privs(log_entry_t *log)
{
    printf("grant privs\n");
}

void print_revoke_privs(log_entry_t *log)
{
    printf("revoke privs\n");
}

status_t db_exec_revoke_write_table(knl_session_t *session, knl_revoke_def_t *def)
{
    uint32 i, j;
    knl_holders_def_t *revokee = NULL;
    knl_priv_def_t *priv = NULL;
    priv_proc_func proc_func = NULL;

    for (i = 0; i < def->revokees.count; i++) {
        revokee = (knl_holders_def_t *)cm_galist_get(&def->revokees, i);
        if (revokee == NULL) {
            GS_LOG_RUN_ERR("[PRIV] failed to load revokee:%u", i);
            return GS_ERROR;
        }

        for (j = 0; j < def->privs.count; j++) {
            priv = (knl_priv_def_t *)cm_galist_get(&def->privs, j);

            proc_func = find_priv_proc_function(g_revoke_proc_func, PRIV_REVOKE_PROC_FUNC_COUNT,
                                                priv->priv_type, revokee->type);
            if (proc_func == NULL) {
                GS_LOG_RUN_ERR("[PRIV] failed to find priv proc function");
                return GS_ERROR;
            }

            if (proc_func(session, def, revokee, priv) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t db_check_privs_before_revoke(knl_session_t *session, knl_revoke_def_t *def)
{
    uint32 i;
    uint32 rid;
    knl_priv_def_t *priv = NULL;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    grant_role_t *g = NULL;
    priv_t *p = NULL;

    for (i = 0; i < def->privs.count; i++) {
        priv = (knl_priv_def_t *)cm_galist_get(&def->privs, i);
        if (priv->priv_type == PRIV_TYPE_ROLE) {
            if (!dc_get_role_id(session, &priv->priv_name, &rid)) {
                GS_THROW_ERROR(ERR_ROLE_NOT_EXIST, T2S(&priv->priv_name));
                return GS_ERROR;
            }
            if (cm_galist_new(&def->privs_list, sizeof(grant_role_t), (void **)&g) != GS_SUCCESS) {
                return GS_ERROR;
            }
            g->type = PRIV_TYPE_ROLE;
            g->handle = ctx->roles[rid];
        } else {
            if (cm_galist_new(&def->privs_list, sizeof(priv_t), (void **)&p) != GS_SUCCESS) {
                return GS_ERROR;
            }
            p->type = priv->priv_type;
            p->id = priv->priv_id;
        }
    }

    return GS_SUCCESS;
}

static status_t db_check_grantees_before_revoke(knl_session_t *session, knl_revoke_def_t *def)
{
    uint32 i;
    uint32 rid, uid;
    knl_holders_def_t *revokee = NULL;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    hold_t *h = NULL;

    for (i = 0; i < def->revokees.count; i++) {
        revokee = (knl_holders_def_t *)cm_galist_get(&def->revokees, i);
        if (revokee->type == TYPE_ROLE) {
            if (!dc_get_role_id(session, &revokee->name, &rid)) {
                GS_THROW_ERROR(ERR_ROLE_NOT_EXIST, T2S(&revokee->name));
                return GS_ERROR;
            }
            if (cm_galist_new(&def->revokee_list, sizeof(hold_t), (void **)&h) != GS_SUCCESS) {
                return GS_ERROR;
            }
            h->type = TYPE_ROLE;
            h->handle = ctx->roles[rid];
        } else {
            if (!dc_get_user_id(session, &revokee->name, &uid)) {
                GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&revokee->name));
                return GS_ERROR;
            }
            if (cm_galist_new(&def->revokee_list, sizeof(hold_t), (void **)&h) != GS_SUCCESS) {
                return GS_ERROR;
            }
            h->type = TYPE_USER;
            h->handle = ctx->users[uid];
        }
    }

    return GS_SUCCESS;
}

static status_t db_exec_revoke_check(knl_session_t *session, knl_revoke_def_t *def)
{
    /* check privs */
    if (db_check_privs_before_revoke(session, def) != GS_SUCCESS) {
        return GS_ERROR;
    }
    /* check grantees */
    if (db_check_grantees_before_revoke(session, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* check object user */
    if (def->schema.len != 0 && !dc_get_user_id(session, &def->schema, &def->objowner)) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void db_revoke_update_dc(knl_session_t *session, knl_revoke_def_t *def)
{
    uint32 i, j;
    dc_update_proc_func proc_func = NULL;
    void *priv = NULL;
    hold_t *h = NULL;

    for (i = 0; i < def->revokee_list.count; i++) {
        h = (hold_t *)cm_galist_get(&def->revokee_list, i);

        for (j = 0; j < def->privs_list.count; j++) {
            priv = cm_galist_get(&def->privs_list, j);

            proc_func = find_dc_update_proc_function(g_revoke_dc_update_func, PRIV_REVOKE_DC_UPDATE_FUNC_COUNT,
                                                     *(priv_type_def *)priv, h->type);
            if (proc_func != NULL) {
                proc_func(session, def, priv, h);
            }
        }
    }

    return;
}

status_t db_exec_revoke_update_dc(knl_session_t *session, knl_revoke_def_t *def)
{
    if (db_exec_revoke_check(session, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    db_revoke_update_dc(session, def);
    return GS_SUCCESS;
}

status_t db_exec_revoke_privs(knl_session_t *session, knl_revoke_def_t *def)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;
    
    if (def->revokees.count == 0 || def->privs.count == 0) {
        GS_LOG_RUN_ERR("[PRIV] failed to exec revoke privs");
        return GS_ERROR;
    }

    if (def->revokees.count > GS_MAX_GRANT_USERS) {
        GS_THROW_ERROR(ERR_GRANTEE_EXCEED_MAX, "revokee", GS_MAX_GRANT_USERS);
        return GS_ERROR;
    }

    dls_spin_lock(session, &ctx->paral_lock, NULL);
    if (db_exec_revoke_write_table(session, def) != GS_SUCCESS) {
        dls_spin_unlock(session, &ctx->paral_lock);
        return GS_ERROR;
    }

    if (db_exec_revoke_update_dc(session, def) != GS_SUCCESS) {
        dls_spin_unlock(session, &ctx->paral_lock);
        return GS_ERROR;
    }

    dls_spin_unlock(session, &ctx->paral_lock);
    revoke_log_put(session, def);
    return GS_SUCCESS;
}

static status_t db_grant_dirpriv_insert_objpriv(knl_session_t *session, text_t *dir_name, dc_user_t *user,
                                                uint32 priv_id)
{
    dc_obj_priv_item priv_item;
    dc_obj_priv_entry_t *entry = NULL;

    /* if the user already has the privilege, return gs_success */
    if (dc_find_objpriv_entry(&user->obj_privs, DB_SYS_USER_ID, dir_name, OBJ_TYPE_DIRECTORY, &entry)) {
        if (DC_HAS_OBJ_PRIV(entry->priv_item.direct_grant, priv_id)) {
            return GS_SUCCESS;
        }
    } else {
        /* judge if there is enough entry for current privilege item  */
        if (!dc_has_objpriv_entry(&user->obj_privs)) {
            GS_THROW_ERROR(ERR_GRANT_OBJ_EXCEED_MAX, DC_GROUP_SIZE * DC_GROUP_SIZE);
            return GS_ERROR;
        }
    }

    priv_item.objowner = DB_SYS_USER_ID;
    if (cm_text2str(dir_name, priv_item.objname, GS_NAME_BUFFER_SIZE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    priv_item.objtype = OBJ_TYPE_DIRECTORY;

    /* write system table SYS_SYS_OBJECT_PRIVS */
    if (db_insert_object_privs(session, user->desc.id, TYPE_USER, priv_id, &priv_item, 0,
                               DB_SYS_USER_ID) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_revoke_dirpriv_delete_objpriv(knl_session_t *session, uint32 grantor_id, uint32 grantee_id,
                                                 uint32 grantee_type, assist_obj_priv_item_t *item)
{
    dc_user_t *user = NULL;
    dc_role_t *role = NULL;
    dc_obj_priv_entry_t *entry = NULL;
    text_t dirname;

    cm_str2text(item->objname, &dirname);
    if (grantee_type == TYPE_USER) {
        if (dc_open_user_by_id(session, grantee_id, &user) != GS_SUCCESS) {
            return GS_ERROR;
        }
        
        /* if the user do not have the privilege, return gs_success */
        if (dc_find_objpriv_entry(&user->obj_privs, DB_SYS_USER_ID, &dirname, (uint32)OBJ_TYPE_DIRECTORY, &entry)) {
            if (!DC_HAS_OBJ_PRIV(entry->priv_item.direct_grant, item->privid)) {
                return GS_SUCCESS;
            }
        } else {
            return GS_SUCCESS;
        }
    } else if (grantee_type == TYPE_ROLE) {
        role = session->kernel->dc_ctx.roles[grantee_id];
        if (dc_find_objpriv_entry(&role->obj_privs, DB_SYS_USER_ID, &dirname, (uint32)OBJ_TYPE_DIRECTORY, &entry)) {
            if (!DC_HAS_OBJ_PRIV(entry->priv_item.direct_grant, item->privid)) {
                return GS_SUCCESS;
            }
        } else {
            return GS_SUCCESS;
        }
    }
    return db_delete_obj_priv_by_grantor(session, grantor_id, grantee_id, grantee_type, item);
}

static status_t db_grant_dirpriv_update_dc(knl_session_t *session, text_t *dir_name, dc_user_t *user, uint32 priv_id)
{
    dc_obj_priv_entry_t *entry = NULL;
    dc_context_t *ctx = &((knl_session_t *)session)->kernel->dc_ctx;
    
    if (dc_find_objpriv_entry(&user->obj_privs, DB_SYS_USER_ID, dir_name, OBJ_TYPE_DIRECTORY, &entry)) {
        if (DC_HAS_OBJ_PRIV(entry->priv_item.direct_grant, priv_id)) {
            return GS_SUCCESS;
        }
    } else {
        /* add a entry for the object */
        if (dc_alloc_objpriv_entry(ctx, &user->obj_privs, user->memory, DB_SYS_USER_ID, dir_name,
                                   OBJ_TYPE_DIRECTORY, &entry) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    /* add priv item to user dc */
    cm_spin_lock(&entry->bucket->lock, NULL);
    DC_SET_OBJ_PRIV(entry->priv_item.direct_grant, priv_id);
    DC_SET_OBJ_PRIV(entry->priv_item.privid_map, priv_id);
    entry->priv_item.grantor[priv_id] = DB_SYS_USER_ID;
    cm_spin_unlock(&entry->bucket->lock);

    return GS_SUCCESS;
}

static status_t db_revoke_dirpriv_update_dc(knl_session_t *session, text_t *dir_name, uint32 grantee_id,
                                            uint32 grantee_type, uint32 priv_id)
{
    dc_obj_priv_item item;
    dc_user_t *user = NULL;
    dc_role_t *role = NULL;
    
    item.objowner = DB_SYS_USER_ID;
    item.objtype = OBJ_TYPE_DIRECTORY;
    if (cm_text2str(dir_name, item.objname, GS_NAME_BUFFER_SIZE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (grantee_type == TYPE_USER) {
        if (dc_open_user_by_id(session, grantee_id, &user) != GS_SUCCESS) {
            return GS_ERROR;
        }
        
        dc_revoke_objpriv_from_user_by_id(&session->kernel->dc_ctx, user, &item, priv_id);
    } else if (grantee_type == TYPE_ROLE) {
        role = session->kernel->dc_ctx.roles[grantee_id];
        dc_revoke_objpriv_from_role_by_id(&session->kernel->dc_ctx, role, &item, priv_id);
    }

    return GS_SUCCESS;
}

status_t db_grant_dirpriv_to_user(knl_session_t *session, char *dir_name, uint32 uid, uint32 priv_id)
{
    text_t dirname;
    rd_privs_t redo;
    dc_user_t *user = NULL;

    if (dc_open_user_by_id(session, uid, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (uid == DB_SYS_USER_ID) {
        return GS_SUCCESS;
    }
    
    cm_str2text(dir_name, &dirname);
    if (db_grant_dirpriv_insert_objpriv(session, &dirname, user, priv_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_grant_dirpriv_update_dc(session, &dirname, user, priv_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    redo.op_type = RD_GRANT_PRIVS;
    redo.type = TYPE_USER;
    redo.id = user->desc.id;
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_privs_t), LOG_ENTRY_FLAG_NONE);
    
    return GS_SUCCESS;
}

status_t db_revoke_dirpriv_from_grantee(knl_session_t *session, uint32 grantor_id, uint32 grantee_id,
                                        uint32 grantee_type, assist_obj_priv_item_t *item)
{
    text_t dirname;
    rd_privs_t redo;

    cm_str2text(item->objname, &dirname);
    if (db_revoke_dirpriv_delete_objpriv(session, grantor_id, grantee_id, grantee_type, item) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_revoke_dirpriv_update_dc(session, &dirname, grantee_id, grantee_type, item->privid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    redo.op_type = RD_GRANT_PRIVS;
    redo.type = grantee_type;
    redo.id = grantee_id;
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_privs_t), LOG_ENTRY_FLAG_NONE);

    return GS_SUCCESS;
}

bool32 db_check_dirpriv_by_uid(knl_session_t *session, char *objname, uint32 uid, uint32 priv_id)
{
    text_t dir_name;
    dc_user_t *user = NULL;
    bool32 user_has = GS_FALSE;
    bool32 public_has = GS_FALSE;
    dc_obj_priv_entry_t *entry = NULL;

    /* sys user has all priv on the directory */
    if (uid == DB_SYS_USER_ID) {
        return GS_TRUE;
    }

    /* check current user if has read priv on the directory */
    if (dc_open_user_by_id(session, uid, &user) != GS_SUCCESS) {
        return GS_FALSE;
    }
    
    cm_str2text(objname, &dir_name);
    if (dc_find_objpriv_entry(&user->obj_privs, DB_SYS_USER_ID, &dir_name, OBJ_TYPE_DIRECTORY, &entry)) {
        cm_spin_lock(&entry->bucket->lock, NULL);
        if (DC_HAS_OBJ_PRIV(entry->priv_item.privid_map, GS_PRIV_DIRE_READ)) {
            user_has = GS_TRUE;
        }
        cm_spin_unlock(&entry->bucket->lock);
    }

    /* check public user if has read priv on the directory */
    if (dc_open_user_by_id(session, DB_PUB_USER_ID, &user) != GS_SUCCESS) {
        return GS_FALSE;
    }
    
    cm_str2text(objname, &dir_name);
    if (dc_find_objpriv_entry(&user->obj_privs, DB_SYS_USER_ID, &dir_name, OBJ_TYPE_DIRECTORY, &entry)) {
        cm_spin_lock(&entry->bucket->lock, NULL);
        if (DC_HAS_OBJ_PRIV(entry->priv_item.privid_map, GS_PRIV_DIRE_READ)) {
            public_has = GS_TRUE;
        }
        cm_spin_unlock(&entry->bucket->lock);
    }

    if (user_has || public_has) {
        return GS_TRUE;
    } else {
        return GS_FALSE;
    }
}

#ifdef __cplusplus
}
#endif
