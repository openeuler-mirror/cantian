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
 * dc_priv.c
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/dc_priv.c
 *
 * -------------------------------------------------------------------------
 */
#include "dc_priv.h"
#include "cm_log.h"
#include "knl_context.h"
#include "dtc_dls.h"

void dc_clear_all_objprivs(dc_obj_priv_t *obj_privs)
{
    uint32 oid = 0;

    dc_obj_priv_entry_t *entry = NULL;
    cm_spin_lock(&obj_privs->lock, NULL);
    for (oid = 0; oid < obj_privs->hwm; oid++) {
        entry = DC_GET_OBJPRIV_ENTRY(obj_privs, oid);
        if (entry != NULL) {
            dc_drop_obj_entry(obj_privs, entry);
        }
    }
    cm_spin_unlock(&obj_privs->lock);
}

void dc_clr_objpriv_by_uid(dc_obj_priv_t *obj_privs, uint32 ownerid)
{
    uint32 oid;
    dc_obj_priv_entry_t *entry = NULL;
    cm_spin_lock(&obj_privs->lock, NULL);
    for (oid = 0; oid < obj_privs->hwm; oid++) {
        entry = DC_GET_OBJPRIV_ENTRY(obj_privs, oid);
        if (entry != NULL && entry->valid && entry->priv_item.objowner == ownerid) {
            dc_drop_obj_entry(obj_privs, entry);
        }
    }
    cm_spin_unlock(&obj_privs->lock);
}

void dc_clear_all_userprivs(dc_user_priv_t *user_privs)
{
    dc_user_priv_entry_t *entry = NULL;

    cm_spin_lock(&user_privs->lock, NULL);
    for (uint32 oid = 0; oid < user_privs->hwm; oid++) {
        entry = DC_GET_OBJPRIV_ENTRY(user_privs, oid);
        if (entry != NULL) {
            dc_drop_user_entry(user_privs, entry);
        }
    }
    cm_spin_unlock(&user_privs->lock);
}

void dc_clr_role_objpriv_by_uid(dc_context_t *ctx, dc_role_t *role, uint32 ownerid)
{
    uint32 oid;
    dc_obj_priv_entry_t *entry = NULL;
    dc_obj_priv_t *obj_privs = &role->obj_privs;
    cm_spin_lock(&obj_privs->lock, NULL);
    for (oid = 0; oid < obj_privs->hwm; oid++) {
        entry = DC_GET_OBJPRIV_ENTRY(obj_privs, oid);
        if (entry != NULL && entry->valid && entry->priv_item.objowner == ownerid) {
            dc_drop_obj_entry(obj_privs, entry);
            dc_update_user_objpriv_by_role(ctx, role, &entry->priv_item);
        }
    }
    cm_spin_unlock(&obj_privs->lock);
}

void dc_clear_others_objprivs(dc_context_t *ctx, dc_user_t *user)
{
    uint32 id;

    for (id = 0; id < GS_MAX_USERS; id++) {
        if (!ctx->users[id] || id == user->desc.id) {
            continue;
        }

        if (ctx->users[id]->status == USER_STATUS_NORMAL) {
            dc_clr_objpriv_by_uid(&ctx->users[id]->obj_privs, user->desc.id);
        }
    }

    for (id = 0; id < GS_MAX_ROLES; id++) {
        if (!ctx->roles[id]) {
            continue;
        }

        dc_clr_role_objpriv_by_uid(ctx, ctx->roles[id], user->desc.id);
        /* need update all the role' children privileges */
    }
}

void dc_revoke_objpriv_by_grantor(dc_context_t *ctx, dc_user_t *user, dc_obj_priv_item *priv_item, uint32 privid)
{
    dc_user_t *grantee_user = NULL;
    dc_role_t *grantee_role = NULL;
    cm_list_head *item = NULL;
    cm_list_head *temp = NULL;
    dc_grant_obj_priv *entry = NULL;

    cm_list_for_each_safe(item, temp, &user->grant_obj_privs)
    {
        entry = cm_list_entry(item, dc_grant_obj_priv, node);
        if (entry->priv_item.objowner == priv_item->objowner && entry->priv_item.objtype == priv_item->objtype &&
            cm_str_equal(entry->priv_item.objname, priv_item->objname) && entry->priv_id == privid) {
            if (entry->grantee_type == TYPE_USER) {
                grantee_user = ctx->users[entry->grantee_id];
                (void)dc_revoke_objpriv_from_user_by_id(ctx, grantee_user, priv_item, privid);
            } else if (entry->grantee_type == TYPE_ROLE) {
                grantee_role = ctx->roles[entry->grantee_id];
                (void)dc_revoke_objpriv_from_role_by_id(ctx, grantee_role, priv_item, privid);
            }
            cm_list_remove(item);
        }
    }
}

void dc_clear_grantor_objpriv_item(dc_context_t *ctx, dc_obj_priv_entry_t *entry, dc_obj_priv_item *priv_item,
    uint32 privid, uint32 grantee_id, uint32 grantee_type)
{
    uint32 grant_uid;
    cm_list_head *item = NULL;
    cm_list_head *temp = NULL;
    dc_grant_obj_priv *grant_item = NULL;

    /* clear items saved by grantor */
    grant_uid = entry->priv_item.grantor[privid];
    if (grant_uid < GS_MAX_USERS && ctx->users[grant_uid] != NULL &&
        ctx->users[grant_uid]->status == USER_STATUS_NORMAL) {
        cm_list_for_each_safe(item, temp, &ctx->users[grant_uid]->grant_obj_privs)
        {
            grant_item = cm_list_entry(item, dc_grant_obj_priv, node);
            if (grant_item->grantee_id == grantee_id &&
                grant_item->priv_id == privid &&
                grant_item->grantee_type == grantee_type &&
                grant_item->priv_item.objowner == grant_uid &&
                grant_item->priv_item.objtype == priv_item->objtype &&
                cm_str_equal(grant_item->priv_item.objname, priv_item->objname)) {
                cm_list_remove(item);
                break;
            }
        }
    }
}

void dc_revoke_objpriv_from_user_by_id(dc_context_t *ctx, dc_user_t *user, dc_obj_priv_item *priv_item,
    uint32 privid)
{
    dc_obj_priv_entry_t *entry = NULL;
    text_t obj_name;
    cm_str2text(priv_item->objname, &obj_name);

    if (dc_find_objpriv_entry(&user->obj_privs, priv_item->objowner, &obj_name, (uint32)priv_item->objtype, &entry)) {
        if (!DC_HAS_OBJ_PRIV(entry->priv_item.direct_grant, privid)) {
            entry->priv_item.grantor[privid] = GS_INVALID_ID32;
            return;
        } else {
            dc_clear_grantor_objpriv_item(ctx, entry, priv_item, privid, user->desc.id, TYPE_USER);
        }
    } else {
        return;
    }
    entry->priv_item.grantor[privid] = GS_INVALID_ID32;
    cm_spin_lock(&entry->bucket->lock, NULL);
    DC_CLR_OBJ_PRIV(entry->priv_item.direct_grant, privid);
    DC_CLR_OBJ_OPT(entry->priv_item.direct_opt, privid);
    cm_spin_unlock(&entry->bucket->lock);
    dc_update_user_objpriv_info(ctx, user, priv_item);

    dc_revoke_objpriv_by_grantor(ctx, user, priv_item, privid);
}

void dc_revoke_userpriv_from_user_by_id(dc_context_t *ctx, dc_user_t *user, uint32 grantee, uint32 privid)
{
    dc_user_priv_entry_t *entry = NULL;

    if (dc_find_user_priv_entry(&user->user_privs, grantee, &entry)) {
        if (!DC_HAS_OBJ_PRIV(entry->user_priv_item.privid_map, privid)) {
            entry->user_priv_item.grantor[privid] = GS_INVALID_ID32;
            return;
        }
    } else {
        return;
    }
    cm_spin_lock(&entry->bucket->lock, NULL);
    DC_CLR_OBJ_PRIV(entry->user_priv_item.privid_map, privid);
    entry->user_priv_item.grantor[privid] = GS_INVALID_ID32;
    cm_spin_unlock(&entry->bucket->lock);

    if (entry->user_priv_item.privid_map == 0) {
        dc_drop_user_entry(&user->user_privs, entry);
    }
}
void dc_revoke_objpriv_from_role_by_id(dc_context_t *ctx, dc_role_t *role,
    dc_obj_priv_item *priv_item, uint32 privid)
{
    text_t obj_name;
    dc_obj_priv_entry_t *entry = NULL;

    cm_str2text(priv_item->objname, &obj_name);
    if (dc_find_objpriv_entry(&role->obj_privs, priv_item->objowner, &obj_name, (uint32)priv_item->objtype, &entry)) {
        if (!DC_HAS_OBJ_PRIV(entry->priv_item.direct_grant, privid)) {
            entry->priv_item.grantor[privid] = GS_INVALID_ID32;
            return;
        } else {
            dc_clear_grantor_objpriv_item(ctx, entry, priv_item, privid, role->desc.id, TYPE_ROLE);
        }
    } else {
        return;
    }

    entry->priv_item.grantor[privid] = GS_INVALID_ID32;
    cm_spin_lock(&entry->bucket->lock, NULL);
    DC_CLR_OBJ_PRIV(entry->priv_item.direct_grant, privid);
    DC_CLR_OBJ_OPT(entry->priv_item.direct_opt, privid);
    cm_spin_unlock(&entry->bucket->lock);

    dc_update_user_objpriv_by_role(ctx, role, priv_item);

    if (entry->priv_item.direct_grant == 0) {
        dc_drop_obj_entry(&role->obj_privs, entry);
    }
}

void dc_clear_grantee_objprivs(dc_context_t *ctx, dc_user_t *user)
{
    dc_user_t *grantee_user = NULL;
    dc_role_t *grantee_role = NULL;
    cm_list_head *item = NULL;
    cm_list_head *temp = NULL;
    dc_grant_obj_priv *entry = NULL;

    cm_list_for_each_safe(item, temp, &user->grant_obj_privs)
    {
        entry = cm_list_entry(item, dc_grant_obj_priv, node);
        if (entry->grantee_type == TYPE_USER) {
            grantee_user = ctx->users[entry->grantee_id];
            if (grantee_user->status == USER_STATUS_NORMAL) {
                dc_revoke_objpriv_from_user_by_id(ctx, grantee_user, &entry->priv_item, entry->priv_id);
            }
        } else if (entry->grantee_type == TYPE_ROLE) {
            grantee_role = ctx->roles[entry->grantee_id];
            /* the role may be dropped before */
            if (grantee_role != NULL) {
                dc_revoke_objpriv_from_role_by_id(ctx, grantee_role, &entry->priv_item, entry->priv_id);
            }
        }
        cm_list_remove(item);
    }
}

void dc_clear_grantor_objprivs(dc_context_t *ctx, dc_obj_priv_t *obj_privs, uint32 grantee_id, uint32 grantee_type)
{
    uint32 oid;
    uint32 pid;
    uint32 grantor_uid;
    cm_list_head *item = NULL;
    cm_list_head *temp = NULL;
    dc_user_t *grantor = NULL;
    dc_obj_priv_entry_t *entry = NULL;
    dc_grant_obj_priv *grant_item = NULL;

    for (oid = 0; oid < obj_privs->hwm; oid++) {
        entry = DC_GET_OBJPRIV_ENTRY(obj_privs, oid);
        if (entry != NULL && entry->valid) {
            for (pid = 0; pid < GS_OBJ_PRIVS_COUNT; pid++) {
                grantor_uid = entry->priv_item.grantor[pid];
                if (grantor_uid < GS_MAX_USERS) {
                    grantor = ctx->users[grantor_uid];
                    if (grantor == NULL || grantor->status != USER_STATUS_NORMAL) {
                        continue;
                    }

                    cm_list_for_each_safe(item, temp, &grantor->grant_obj_privs)
                    {
                        grant_item = cm_list_entry(item, dc_grant_obj_priv, node);
                        if (grant_item->grantee_id == grantee_id && grant_item->grantee_type == grantee_type) {
                            cm_list_remove(item);
                        }
                    }
                }
            }
        }
    }
}

void dc_update_role_owner(dc_context_t *ctx, uint32 uid)
{
    dc_role_t *role = NULL;

    for (uint32 i = 0; i < GS_MAX_ROLES; i++) {
        role = ctx->roles[i];
        if (role != NULL && role->desc.owner_uid == uid) {
            role->desc.owner_uid = 0;
        }
    }
}

void dc_clear_role_priv(knl_session_t *session, dc_role_t *role)
{
    dc_role_t *child = NULL;
    dc_role_t *parent = NULL;
    dc_user_t *user = NULL;
    dc_granted_role *child_role = NULL;
    dc_granted_role *parent_role = NULL;
    dc_user_granted *child_user = NULL;
    cm_list_head *item1 = NULL;
    cm_list_head *item2 = NULL;
    cm_list_head *temp1 = NULL;
    cm_list_head *temp2 = NULL;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    if (role == NULL) {
        GS_LOG_RUN_ERR("[DC] load role privilege failed, the role not exist");
        return;
    }
    dls_spin_lock(session, &role->lock, NULL);
    dc_clear_grantor_objprivs(ctx, &role->obj_privs, role->desc.id, TYPE_ROLE);

    /* update child users' privileges */
    cm_list_for_each_safe(item1, temp1, &role->child_users)
    {
        child_user = cm_list_entry(item1, dc_user_granted, node);
        cm_list_remove(item1);
        cm_list_add(&child_user->node, &role->child_users_free);

        user = child_user->user_granted;
        dls_spin_lock(session, &user->lock, NULL);
        cm_list_for_each_safe(item2, temp2, &user->parent)
        {
            parent_role = cm_list_entry(item2, dc_granted_role, node);
            if (role == parent_role->granted_role) {
                cm_list_remove(item2);
                cm_list_add(&parent_role->node, &user->parent_free);
                break;
            }
        }
        dls_spin_unlock(session, &user->lock);
        dc_update_user_syspriv_info(user);
        dc_update_all_objprivs_info(session, user);
    }
    cm_list_init(&role->child_users);

    /* update child roles' privileges */
    cm_list_for_each_safe(item1, temp1, &role->child_roles)
    {
        child_role = cm_list_entry(item1, dc_granted_role, node);
        cm_list_remove(item1);
        cm_list_add(&child_role->node, &role->child_roles_free);

        child = child_role->granted_role;
        dls_spin_lock(session, &child->lock, NULL);
        cm_list_for_each_safe(item2, temp2, &child->parent)
        {
            parent_role = cm_list_entry(item2, dc_granted_role, node);
            if (parent_role->granted_role == role) {
                cm_list_remove(item2);
                cm_list_add(&parent_role->node, &child->parent_free);
                break;
            }
        }
        dls_spin_unlock(session, &child->lock);
        dc_update_user_syspriv_by_role(child);
        dc_update_all_objprivs_by_role(session, child);
    }
    cm_list_init(&role->child_roles);

    /* update parent roles' list */
    cm_list_for_each_safe(item1, temp1, &role->parent)
    {
        parent_role = cm_list_entry(item1, dc_granted_role, node);
        cm_list_remove(item1);
        cm_list_add(&parent_role->node, &role->parent_free);
        parent = parent_role->granted_role;
        dls_spin_lock(session, &parent->lock, NULL);
        cm_list_for_each_safe(item2, temp2, &parent->child_roles)
        {
            child_role = cm_list_entry(item2, dc_granted_role, node);
            if (role == child_role->granted_role) {
                cm_list_remove(item2);
                cm_list_add(&child_role->node, &parent->child_roles_free);
                break;
            }
        }
        dls_spin_unlock(session, &parent->lock);
    }
    cm_list_init(&role->parent);
    dls_spin_unlock(session, &role->lock);
    errno_t err = memset_sp(role->sys_privs, sizeof(role->sys_privs), 0, sizeof(role->sys_privs));
    knl_securec_check(err);
    dc_clear_all_objprivs(&role->obj_privs);
}

void dc_clear_user_priv(dc_context_t *ctx, dc_user_t *user)
{
    dc_user_granted *child_user = NULL;
    dc_granted_role *parent = NULL;
    cm_list_head *item1 = NULL;
    cm_list_head *item2 = NULL;
    cm_list_head *temp1 = NULL;
    cm_list_head *temp2 = NULL;
    errno_t err;

    /* clear system privileges */
    err = memset_sp(user->sys_privs, sizeof(user->sys_privs), 0, sizeof(user->sys_privs));
    knl_securec_check(err);
    err = memset_sp(user->admin_opt, sizeof(user->admin_opt), 0, sizeof(user->admin_opt));
    knl_securec_check(err);
    err = memset_sp(user->all_sys_privs, sizeof(user->all_sys_privs), 0, sizeof(user->all_sys_privs));
    knl_securec_check(err);
    err = memset_sp(user->ter_admin_opt, sizeof(user->ter_admin_opt), 0, sizeof(user->ter_admin_opt));
    knl_securec_check(err);

    /* clear all object privileges that granted other users/role when the object's owner is dropped */
    dc_clear_others_objprivs(ctx, user);

    /* clear all object privilege items saved by the grantor */
    dc_clear_grantor_objprivs(ctx, &user->obj_privs, user->desc.id, TYPE_USER);
    dc_clear_grantee_objprivs(ctx, user);

    /* clear all object privileges */
    dc_clear_all_objprivs(&user->obj_privs);
    dc_clear_all_userprivs(&user->user_privs);

    /* delete the parent nodes in list */
    cm_list_for_each_safe(item1, temp1, &user->parent)
    {
        parent = cm_list_entry(item1, dc_granted_role, node);
        cm_list_remove(item1);
        cm_list_add(&parent->node, &user->parent_free);

        cm_list_for_each_safe(item2, temp2, &parent->granted_role->child_users)
        {
            child_user = cm_list_entry(item2, dc_user_granted, node);
            if (user == child_user->user_granted) {
                cm_list_remove(item2);
                cm_list_add(&child_user->node, &parent->granted_role->child_users_free);
                break;
            }
        }
    }

    /* change the owner for all roles that created by the user */
    dc_update_role_owner(ctx, user->desc.id);

    cm_list_init(&user->parent);
    cm_list_init(&user->grant_obj_privs);
}

status_t dc_load_sys_priv(knl_session_t *session, knl_cursor_t *cursor)
{
    dc_context_t *ctx = &session->kernel->dc_ctx;

    uint32 grantee_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PRIVS_COL_GRANTEE_ID);
    uint32 grantee_type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PRIVS_COL_GRANTEE_TYPE);
    uint32 priv_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PRIVS_COL_PRIVILEGE);
    bool32 admin_option = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_PRIVS_COL_ADMIN_OPTION);

    /* user type */
    if (grantee_type == 0) {
        cm_spin_lock(&ctx->lock, NULL);
        if (grantee_id >= GS_MAX_USERS || !ctx->users[grantee_id]) {
            cm_spin_unlock(&ctx->lock);
            GS_THROW_ERROR(ERR_GRANTEE_EXCEED_MAX, "grantee", GS_MAX_USERS);
            return GS_ERROR;
        }

        dc_user_t *user = ctx->users[grantee_id];
        DC_SET_PRIV_INFO(user->sys_privs, user->admin_opt, priv_id, admin_option);
        DC_SET_SYS_PRIV(user->all_sys_privs, priv_id);
        if (admin_option == 1) {
            DC_SET_SYS_OPT(user->ter_admin_opt, priv_id);
        }
        cm_spin_unlock(&ctx->lock);
    } else { /* role type */
        cm_spin_lock(&ctx->lock, NULL);
        if (grantee_id >= GS_MAX_ROLES || !ctx->roles[grantee_id]) {
            cm_spin_unlock(&ctx->lock);
            GS_THROW_ERROR(ERR_GRANTEE_EXCEED_MAX, "grantee", GS_MAX_ROLES);
            return GS_ERROR;
        }

        dc_role_t *role = ctx->roles[grantee_id];
        DC_SET_PRIV_INFO(role->sys_privs, role->admin_opt, priv_id, admin_option);

        /*
        * update privileges information in dc for all the users that the role granted to
        *  (include users indirectly granted through other roles)
        */
        dc_update_user_syspriv_by_role(role);
        cm_spin_unlock(&ctx->lock);
    }

    return GS_SUCCESS;
}

status_t dc_load_objpriv(knl_session_t *session, dc_context_t *ctx, knl_cursor_t *cursor)
{
    uint32 grantee_id;
    uint32 grantee_type;
    uint32 owner_id;
    uint32 option;
    uint32 objtype;
    uint32 privid;
    text_t objname;
    uint32 grant_uid;
    dc_user_t *user = NULL;
    dc_role_t *role = NULL;
    dc_user_t *grantor_user = NULL;
    dc_obj_priv_entry_t *entry = NULL;

    grantee_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, OBJECT_PRIVS_COL_GRANTEE);
    grantee_type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, OBJECT_PRIVS_COL_GRANTEE_TYPE);
    owner_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, OBJECT_PRIVS_COL_OBJECT_OWNER);
    objname.str = CURSOR_COLUMN_DATA(cursor, OBJECT_PRIVS_COL_OBJECT_NAME);
    objname.len = CURSOR_COLUMN_SIZE(cursor, OBJECT_PRIVS_COL_OBJECT_NAME);
    objtype = *(uint32 *)CURSOR_COLUMN_DATA(cursor, OBJECT_PRIVS_COL_OBJECT_TYPE);
    privid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, OBJECT_PRIVS_COL_PRIVILEGE);
    option = *(uint32 *)CURSOR_COLUMN_DATA(cursor, OBJECT_PRIVS_COL_GRANTABLE);
    grant_uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, OBJECT_PRIVS_COL_GRANTOR);

    /* grantee is user */
    if (grantee_type == 0) {
        if (grantee_id == owner_id) {
            return GS_SUCCESS;
        }

        user = ctx->users[grantee_id];
        if (!dc_find_objpriv_entry(&user->obj_privs, owner_id, &objname, objtype, &entry)) {
            if (dc_alloc_objpriv_entry(ctx, &user->obj_privs, user->memory, owner_id,
                &objname, objtype, &entry) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        /* add priv item to user dc */
        DC_SET_OBJ_PRIV(entry->priv_item.direct_grant, privid);
        DC_SET_OBJ_PRIV(entry->priv_item.privid_map, privid);
        entry->priv_item.grantor[privid] = grant_uid;
        if (option == 1) {
            DC_SET_OBJ_OPT(entry->priv_item.direct_opt, privid);
            DC_SET_OBJ_OPT(entry->priv_item.privopt_map, privid);
        }
    } else {
        role = ctx->roles[grantee_id];
        if (!dc_find_objpriv_entry(&role->obj_privs, owner_id, &objname, objtype, &entry)) {
            if (dc_alloc_objpriv_entry(ctx, &role->obj_privs, role->memory, owner_id,
                &objname, objtype, &entry) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        /* add priv item to dc */
        DC_SET_OBJ_PRIV(entry->priv_item.direct_grant, privid);
        entry->priv_item.grantor[privid] = grant_uid;
        dc_update_user_objpriv_by_role(ctx, role, &entry->priv_item);
    }
    if (GS_SUCCESS == dc_open_user_by_id(session, grant_uid, &grantor_user)) {
        if (dc_add_user_grant_objpriv(session, grantor_user, grantee_type, grantee_id, &entry->priv_item,
            privid) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t dc_load_user_priv(knl_session_t *session, dc_context_t *ctx, knl_cursor_t *cursor)
{
    uint32 uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_PRIVS_COL_UID);
    uint32 grantor = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_PRIVS_COL_GRANTOR);
    uint32 grantee = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_PRIVS_COL_GRANTEE);
    uint32 privid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_PRIVS_COL_PRIVILEGE);
    dc_user_t *user = ctx->users[uid];
    dc_user_priv_entry_t *entry = NULL;

    if (!dc_find_user_priv_entry(&user->user_privs, grantee, &entry)) {
        if (dc_alloc_user_priv_entry(ctx, &user->user_privs, user->memory, grantee, &entry) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    DC_SET_OBJ_PRIV(entry->user_priv_item.privid_map, privid);
    entry->user_priv_item.grantor[privid] = grantor;
    
    return GS_SUCCESS;
}
status_t dc_load_role_priv(knl_session_t *session, dc_context_t *ctx, knl_cursor_t *cursor)
{
    uint32 grantee_id;
    uint32 grantee_type;
    dc_user_t *user = NULL;
    dc_role_t *role;
    dc_role_t *role2 = NULL;
    uint32 granted_role_id;
    bool32 admin_option;
    dc_user_granted *user_grant = NULL;
    dc_granted_role *parent = NULL;
    dc_granted_role *child = NULL;
    errno_t ret;

    grantee_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_ROLES_COL_GRANTEE_ID);
    grantee_type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_ROLES_COL_GRANTEE_TYPE);
    granted_role_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_ROLES_COL_GRANTED_ROLE_ID);
    admin_option = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_USER_ROLES_COL_ADMIN_OPTION);

    role = ctx->roles[granted_role_id];
    if (role == NULL) {
        GS_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "granted role", granted_role_id);
        GS_LOG_RUN_ERR("[DC] failed to load role id:%u", granted_role_id);
        return GS_ERROR;
    }
    /* user type */
    if (grantee_type == 0) {
        cm_spin_lock(&ctx->lock, NULL);
        if (grantee_id >= GS_MAX_USERS || !ctx->users[grantee_id]) {
            cm_spin_unlock(&ctx->lock);
            GS_THROW_ERROR(ERR_GRANTEE_EXCEED_MAX, "grantee", GS_MAX_USERS);
            GS_LOG_RUN_ERR("[DC] failed to load user id:%u", grantee_id);
            return GS_ERROR;
        }

        user = ctx->users[grantee_id];
        if (dc_alloc_mem(ctx, role->memory, sizeof(dc_user_granted), (void **)&user_grant) != GS_SUCCESS) {
            cm_spin_unlock(&ctx->lock);
            return GS_ERROR;
        }

        ret = memset_sp(user_grant, sizeof(dc_user_granted), 0, sizeof(dc_user_granted));
        knl_securec_check(ret);

        user_grant->admin_opt = admin_option;
        user_grant->user_granted = user;

        if (dc_alloc_mem(&session->kernel->dc_ctx, user->memory, sizeof(dc_granted_role),
            (void **)&parent) != GS_SUCCESS) {
            cm_spin_unlock(&ctx->lock);
            return GS_ERROR;
        }

        ret = memset_sp(parent, sizeof(dc_granted_role), 0, sizeof(dc_granted_role));
        knl_securec_check(ret);
        parent->admin_opt = admin_option;
        parent->granted_role = role;

        /* add the user to the list of the role */
        cm_list_add(&user_grant->node, &role->child_users);
        cm_list_add(&parent->node, &user->parent);

        /* update the user's system & object privileges */
        dc_update_user_syspriv_info(user);
        dc_update_all_objprivs_info(session, user);
        cm_spin_unlock(&ctx->lock);
    } else { /* role type */
        cm_spin_lock(&ctx->lock, NULL);
        if (grantee_id >= GS_MAX_ROLES || !ctx->roles[grantee_id]) {
            cm_spin_unlock(&ctx->lock);
            GS_THROW_ERROR(ERR_GRANTEE_EXCEED_MAX, "grantee", GS_MAX_ROLES);
            GS_LOG_RUN_ERR("[DC] failed to load role id:%u", grantee_id);
            return GS_ERROR;
        }

        role2 = ctx->roles[grantee_id];

        /* add to the list */
        if (dc_alloc_mem(&session->kernel->dc_ctx, role->memory, sizeof(dc_granted_role),
            (void **)&child) != GS_SUCCESS) {
            cm_spin_unlock(&ctx->lock);
            return GS_ERROR;
        }

        ret = memset_sp(child, sizeof(dc_granted_role), 0, sizeof(dc_granted_role));
        knl_securec_check(ret);

        child->admin_opt = admin_option;
        child->granted_role = role2;

        if (dc_alloc_mem(&session->kernel->dc_ctx, role2->memory, sizeof(dc_granted_role),
            (void **)&parent) != GS_SUCCESS) {
            cm_spin_unlock(&ctx->lock);
            return GS_ERROR;
        }

        ret = memset_sp(parent, sizeof(dc_granted_role), 0, sizeof(dc_granted_role));
        knl_securec_check(ret);

        parent->admin_opt = admin_option;
        parent->granted_role = role;

        cm_list_add(&child->node, &role->child_roles);
        cm_list_add(&parent->node, &role2->parent);

        /* update the user's system & object privleges */
        dc_update_user_syspriv_by_role(role2);
        dc_update_all_objprivs_by_role(session, role2);
        cm_spin_unlock(&ctx->lock);
    }

    return GS_SUCCESS;
}

status_t dc_load_sys_privs_by_id(knl_session_t *session, uint32 id, uint32 type)
{
    knl_cursor_t *cursor = NULL;
    knl_scan_key_t *l_border = NULL;
    knl_scan_key_t *r_border = NULL;

    CM_SAVE_STACK(session->stack);

    /* restore privileges from SYS_PRIVS$ table: privileges directly granted to the user */
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_PRIVS_ID, IX_SYS_SYS_PRIVS_001_ID);

    l_border = &cursor->scan_range.l_key;
    r_border = &cursor->scan_range.r_key;
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_border, GS_TYPE_INTEGER, (void *)&id, sizeof(uint32),
        IX_COL_SYS_PRIVS_001_GRANTEE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_border, GS_TYPE_INTEGER, (void *)&type, sizeof(uint32),
        IX_COL_SYS_PRIVS_001_GRANTEE_TYPE);
    knl_set_key_flag(l_border, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_PRIVS_001_RIVILEGE);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_border, GS_TYPE_INTEGER, (void *)&id, sizeof(uint32),
        IX_COL_SYS_PRIVS_001_GRANTEE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_border, GS_TYPE_INTEGER, (void *)&type, sizeof(uint32),
        IX_COL_SYS_PRIVS_001_GRANTEE_TYPE);
    knl_set_key_flag(r_border, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_PRIVS_001_RIVILEGE);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (dc_load_sys_priv(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t dc_load_role_privs_as_grantee(knl_session_t *session, uint32 id, uint32 type)
{
    knl_cursor_t *cursor = NULL;
    knl_scan_key_t *l_border = NULL;
    knl_scan_key_t *r_border = NULL;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    CM_SAVE_STACK(session->stack);
    /* restore privileges from USER_ROLES$ table */
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_USER_ROLES_ID, IX_SYS_USER_ROLES_001_ID);
    l_border = &cursor->scan_range.l_key;
    r_border = &cursor->scan_range.r_key;
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_border, GS_TYPE_INTEGER, (void *)&id, sizeof(uint32),
        IX_COL_SYS_USER_ROLES_001_GRANTEE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_border, GS_TYPE_INTEGER, (void *)&type, sizeof(uint32),
        IX_COL_SYS_USER_ROLES_001_GRANTEE_TYPE);
    knl_set_key_flag(l_border, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_USER_ROLES_001_GRANTED_ROLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_border, GS_TYPE_INTEGER, (void *)&id, sizeof(uint32),
        IX_COL_SYS_USER_ROLES_001_GRANTEE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_border, GS_TYPE_INTEGER, (void *)&type, sizeof(uint32),
        IX_COL_SYS_USER_ROLES_001_GRANTEE_TYPE);
    knl_set_key_flag(r_border, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_USER_ROLES_001_GRANTED_ROLE_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (dc_load_role_priv(session, ctx, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t dc_load_role_privs_as_granted(knl_session_t *session, uint32 id)
{
    knl_cursor_t *cursor = NULL;
    knl_scan_key_t *l_border = NULL;
    knl_scan_key_t *r_border = NULL;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    CM_SAVE_STACK(session->stack);
    /* restore privileges from USER_ROLES$ table */
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_USER_ROLES_ID, IX_SYS_USER_ROLES_002_ID);
    l_border = &cursor->scan_range.l_key;
    r_border = &cursor->scan_range.r_key;
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_border, GS_TYPE_INTEGER, (void *)&id, sizeof(uint32),
        IX_COL_SYS_USER_ROLES_002_GRANTED_ROLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_border, GS_TYPE_INTEGER, (void *)&id, sizeof(uint32),
        IX_COL_SYS_USER_ROLES_002_GRANTED_ROLE_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (dc_load_role_priv(session, ctx, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t dc_load_role_privs_by_id(knl_session_t *session, uint32 id, uint32 type)
{
    if (dc_load_role_privs_as_grantee(session, id, type) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if ((type_def)type == TYPE_ROLE) {
        return dc_load_role_privs_as_granted(session, id);
    }

    return GS_SUCCESS;
}

status_t dc_load_obj_privs_by_id(knl_session_t *session, uint32 id, uint32 type)
{
    knl_cursor_t *cursor = NULL;
    knl_scan_key_t *l_border = NULL;
    knl_scan_key_t *r_border = NULL;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    CM_SAVE_STACK(session->stack);
    /* restore privileges from OBJECT_PRIVS$ table */
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, OBJECT_PRIVS_ID, IX_SYS_OBJECT_PRIVS_001_ID);
    l_border = &cursor->scan_range.l_key;
    r_border = &cursor->scan_range.r_key;
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_border, GS_TYPE_INTEGER, (void *)&id, sizeof(uint32),
        IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_border, GS_TYPE_INTEGER, (void *)&type, sizeof(uint32),
        IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE_TYPE);
    knl_set_key_flag(l_border, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_OWNER);
    knl_set_key_flag(l_border, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_NAME);
    knl_set_key_flag(l_border, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_TYPE);
    knl_set_key_flag(l_border, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_001_PRIVILEGE);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_border, GS_TYPE_INTEGER, (void *)&id, sizeof(uint32),
        IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_border, GS_TYPE_INTEGER, (void *)&type, sizeof(uint32),
        IX_COL_SYS_OBJECT_PRIVS_001_GRANTEE_TYPE);
    knl_set_key_flag(r_border, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_OWNER);
    knl_set_key_flag(r_border, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_NAME);
    knl_set_key_flag(r_border, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_001_OBJECT_TYPE);
    knl_set_key_flag(r_border, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_OBJECT_PRIVS_001_PRIVILEGE);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (dc_load_objpriv(session, ctx, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t dc_load_user_privs_by_id(knl_session_t *session, uint32 uid)
{
    knl_cursor_t *cursor = NULL;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    CM_SAVE_STACK(session->stack);

    /* restore privileges from USER_PRIVS$ table */
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_USER_PRIVS_ID, IX_USER_PRIVS_001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), IX_COL_SYS_USER_PRIVS_001_UID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), IX_COL_SYS_USER_PRIVS_001_UID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_USER_PRIVS_001_GRANTEE);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_USER_PRIVS_001_GRANTEE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_USER_PRIVS_001_RIVILEGE);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_USER_PRIVS_001_RIVILEGE);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (dc_load_user_priv(session, ctx, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

static status_t dc_load_sys_privs(knl_session_t *session, dc_context_t *ctx)
{
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    /* restore privileges from SYS_PRIVS$ table: privileges directly granted to the user */
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_PRIVS_ID, GS_INVALID_ID32);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (dc_load_sys_priv(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t dc_load_role_privs(knl_session_t *session, dc_context_t *ctx)
{
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);
    /* restore privileges from USER_ROLES$ table */
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_USER_ROLES_ID, GS_INVALID_ID32);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (dc_load_role_priv(session, ctx, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t dc_load_obj_privs(knl_session_t *session, dc_context_t *ctx)
{
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);
    /* restore privileges from OBJECT_PRIVS$ table */
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, OBJECT_PRIVS_ID, GS_INVALID_ID32);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (dc_load_objpriv(session, ctx, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t dc_load_user_privs(knl_session_t *session, dc_context_t *ctx)
{
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);
    /* restore privileges from SYS_USER_PRIVS table */
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_USER_PRIVS_ID, GS_INVALID_ID32);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (dc_load_user_priv(session, ctx, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}
status_t dc_load_privileges(knl_session_t *session, dc_context_t *ctx)
{
    if (dc_load_sys_privs(session, ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_load_role_privs(session, ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_load_obj_privs(session, ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_load_user_privs(session, ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

bool32 dc_find_user_grant_objpriv(dc_user_t *user, uint32 grantee_type, uint32 grantee_id,
    dc_obj_priv_item *priv_item, dc_grant_obj_priv **grant_obj_priv, uint32 priv_id)
{
    cm_list_head *item = NULL;
    dc_grant_obj_priv *entry = NULL;
    cm_list_for_each(item, &user->grant_obj_privs)
    {
        entry = cm_list_entry(item, dc_grant_obj_priv, node);
        if (entry->grantee_type == grantee_type && entry->grantee_id == grantee_id &&
            entry->priv_item.objowner == priv_item->objowner && entry->priv_item.objtype == priv_item->objtype &&
            cm_str_equal(entry->priv_item.objname, priv_item->objname) && entry->priv_id == priv_id) {
            *grant_obj_priv = entry;
            return GS_TRUE;
        }
    }
    return GS_FALSE;
}

status_t dc_add_user_grant_objpriv(knl_session_t *session, dc_user_t *user, uint32 grantee_type, uint32 grantee_id,
    dc_obj_priv_item *priv_item, uint32 priv_id)
{
    dc_grant_obj_priv *grant_obj_priv = NULL;
    dc_context_t *ctx = &session->kernel->dc_ctx;
    uint32 objname_len;
    errno_t err;

    if (!dc_find_user_grant_objpriv(user, grantee_type, grantee_id, priv_item, &grant_obj_priv, priv_id)) {
        if (dc_alloc_mem(ctx, user->memory, sizeof(dc_grant_obj_priv),
            (void **)&grant_obj_priv) != GS_SUCCESS) {
            return GS_ERROR;
        }

        err = memset_sp(grant_obj_priv, sizeof(dc_grant_obj_priv), 0, sizeof(dc_grant_obj_priv));
        knl_securec_check(err);

        grant_obj_priv->grantee_type = grantee_type;
        grant_obj_priv->grantee_id = grantee_id;
        grant_obj_priv->priv_item.objowner = priv_item->objowner;
        grant_obj_priv->priv_item.objtype = priv_item->objtype;
        grant_obj_priv->priv_id = priv_id;
        objname_len = GS_NAME_BUFFER_SIZE - 1;
        err = strncpy_s(grant_obj_priv->priv_item.objname, GS_NAME_BUFFER_SIZE, priv_item->objname,
            objname_len);
        knl_securec_check(err);
        cm_list_add(&grant_obj_priv->node, &user->grant_obj_privs);
    }
    return GS_SUCCESS;
}

bool32 dc_check_sys_priv_by_name(knl_session_t *session, text_t *username, uint32 priv_id)
{
    dc_user_t *user = NULL;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    if (username == NULL || username->len == 0) {
        return GS_FALSE;
    }

    if (dc_open_user_direct(session, username, &user) != GS_SUCCESS) {
        return GS_FALSE;
    }

    if (DC_HAS_SYS_PRIV(user->all_sys_privs, priv_id)) {
        return GS_TRUE;
    }

    /* check if the privilege granted to public */
    user = ctx->users[DB_PUB_USER_ID];
    if (DC_HAS_SYS_PRIV(user->all_sys_privs, priv_id)) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

bool32 dc_check_sys_priv_by_uid(knl_session_t *session, uint32 uid, uint32 priv_id)
{
    dc_user_t *user = NULL;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    user = ctx->users[uid];
    if (user == NULL || user->status != USER_STATUS_NORMAL) {
        return GS_FALSE;
    }

    if (DC_HAS_SYS_PRIV(user->all_sys_privs, priv_id)) {
        return GS_TRUE;
    }

    /* check if the privilege granted to public */
    user = ctx->users[DB_PUB_USER_ID];
    if (DC_HAS_SYS_PRIV(user->all_sys_privs, priv_id)) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

bool32 dc_check_dir_priv_by_uid(knl_session_t *session, uint32 uid, uint32 priv_id)
{
    dc_user_t *user = NULL;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    user = ctx->users[uid];
    if (user == NULL || user->status != USER_STATUS_NORMAL) {
        return GS_FALSE;
    }

    if (DC_HAS_SYS_PRIV(user->sys_privs, priv_id)) {
        return GS_TRUE;
    }

    if (DC_HAS_SYS_PRIV(user->all_sys_privs, priv_id)) {
        return GS_TRUE;
    }

    /* check if the privilege granted to public */
    user = ctx->users[DB_PUB_USER_ID];
    if (DC_HAS_SYS_PRIV(user->sys_privs, priv_id)) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

bool32 dc_check_obj_priv_by_name(knl_session_t *session, text_t *curr_user, text_t *objuser,
                                 text_t *objname, object_type_t objtype, uint32 privid)
{
    uint32 owner;
    dc_user_t *user = NULL;
    dc_obj_priv_entry_t *entry = NULL;
    text_t pub_user = { PUBLIC_USER, (uint32)strlen(PUBLIC_USER) };

    if (dc_open_user(session, curr_user, &user) != GS_SUCCESS) {
        return GS_FALSE;
    }

    if (!dc_get_user_id(session, objuser, &owner)) {
        return GS_FALSE;
    }

    if (dc_find_objpriv_entry(&user->obj_privs, owner, objname, (uint32)objtype, &entry)) {
        cm_spin_lock(&entry->bucket->lock, NULL);
        if (DC_HAS_OBJ_PRIV(entry->priv_item.privid_map, privid)) {
            cm_spin_unlock(&entry->bucket->lock);
            return GS_TRUE;
        }
        cm_spin_unlock(&entry->bucket->lock);
    }

    /* check if the privilege granted to public */
    if (cm_text_equal(&pub_user, curr_user)) {
        return GS_FALSE;
    }

    return dc_check_obj_priv_by_name(session, &pub_user, objuser, objname, objtype, privid);
}

bool32 dc_check_user_priv_by_name(knl_session_t *session, text_t *curr_user, text_t *objuser, uint32 privid)
{
    uint32 grantee;
    dc_user_t *user = NULL;
    dc_user_priv_entry_t *entry = NULL;
    text_t pub_user = { PUBLIC_USER, (uint32)strlen(PUBLIC_USER) };

    if (dc_open_user(session, curr_user, &user) != GS_SUCCESS) {
        return GS_FALSE;
    }

    if (!dc_get_user_id(session, objuser, &grantee)) {
        return GS_FALSE;
    }

    if (dc_find_user_priv_entry(&user->user_privs, grantee, &entry)) {
        cm_spin_lock(&entry->bucket->lock, NULL);
        if (DC_HAS_OBJ_PRIV(entry->user_priv_item.privid_map, privid)) {
            cm_spin_unlock(&entry->bucket->lock);
            return GS_TRUE;
        }
        cm_spin_unlock(&entry->bucket->lock);
    }

    /* check if the privilege granted to public */
    if (cm_text_equal(&pub_user, objuser)) {
        return GS_FALSE;
    }

    return dc_check_user_priv_by_name(session, curr_user, &pub_user, privid);
}

bool32 dc_check_obj_priv_with_option(knl_session_t *session, text_t *curr_user, text_t *objuser, text_t *objname,
                                     object_type_t objtype, uint32 privid)
{
    uint32 owner;
    dc_user_t *user = NULL;
    dc_obj_priv_t *obj_privs = NULL;
    uint32 hash, eid;
    dc_bucket_t *bucket = NULL;
    dc_obj_priv_entry_t *entry = NULL;
    text_t pub_user = { PUBLIC_USER, (uint32)strlen(PUBLIC_USER) };

    if (dc_open_user(session, curr_user, &user) != GS_SUCCESS) {
        return GS_FALSE;
    }

    if (!dc_get_user_id(session, objuser, &owner)) {
        return GS_FALSE;
    }

    hash = dc_hash(objname);
    bucket = &(user->obj_privs.buckets[hash]);

    cm_spin_lock(&bucket->lock, NULL);
    eid = bucket->first;
    obj_privs = &user->obj_privs;
    while (eid != GS_INVALID_ID32) {
        entry = DC_GET_OBJPRIV_ENTRY(obj_privs, eid);
        if (owner == entry->priv_item.objowner &&
            (uint32)objtype == entry->priv_item.objtype &&
            cm_text_str_equal(objname, entry->priv_item.objname)) {
            if (DC_HAS_OBJ_PRIV(entry->priv_item.privid_map, privid) &&
                DC_HAS_OBJ_OPT(entry->priv_item.privopt_map, privid)) {
                cm_spin_unlock(&bucket->lock);
                return GS_TRUE;
            }
        }

        eid = entry->next;
    }

    cm_spin_unlock(&bucket->lock);

    /* check if the privilege granted to public */
    if (cm_text_equal(&pub_user, curr_user)) {
        return GS_FALSE;
    }

    return dc_check_obj_priv_with_option(session, &pub_user, objuser, objname, objtype, privid);
}

bool32 dc_check_allobjprivs_with_option(knl_session_t *session, text_t *curr_user, text_t *objuser,
                                        text_t *objname, object_type_t objtype)
{
    uint32 i;
    uint32 count;
    uint32 owner;
    dc_user_t *user = NULL;
    dc_obj_priv_t *obj_privs = NULL;
    uint32 hash, eid;
    dc_bucket_t *bucket = NULL;
    dc_obj_priv_entry_t *entry = NULL;
    obj_privs_id *privset = NULL;
    text_t pub_user = { PUBLIC_USER, (uint32)strlen(PUBLIC_USER) };

    if (dc_open_user(session, curr_user, &user) != GS_SUCCESS) {
        return GS_FALSE;
    }

    if (!dc_get_user_id(session, objuser, &owner)) {
        return GS_FALSE;
    }

    knl_get_objprivs_set(objtype, &privset, &count);
    if (privset == NULL || count == 0) {
        return GS_FALSE;
    }

    hash = dc_hash(objname);
    bucket = &(user->obj_privs.buckets[hash]);

    cm_spin_lock(&bucket->lock, NULL);
    eid = bucket->first;
    obj_privs = &user->obj_privs;
    while (eid != GS_INVALID_ID32) {
        entry = DC_GET_OBJPRIV_ENTRY(obj_privs, eid);
        if (owner == entry->priv_item.objowner &&
            (uint32)objtype == entry->priv_item.objtype &&
            cm_text_str_equal(objname, entry->priv_item.objname)) {
            for (i = 0; i < count; i++) {
                if (!(DC_HAS_OBJ_PRIV(entry->priv_item.privid_map, privset[i]) &&
                    DC_HAS_OBJ_OPT(entry->priv_item.privopt_map, privset[i]))) {
                    cm_spin_unlock(&bucket->lock);
                    return GS_FALSE;
                }
            }
            cm_spin_unlock(&bucket->lock);
            return GS_TRUE;
        }

        eid = entry->next;
    }

    cm_spin_unlock(&bucket->lock);

    /* check if the privilege granted to public */
    if (cm_text_equal(&pub_user, curr_user)) {
        return GS_FALSE;
    }

    return dc_check_allobjprivs_with_option(session, &pub_user, objuser, objname, objtype);
}

bool32 dc_sys_priv_with_option(knl_session_t *session, text_t *user, uint32 priv_id)
{
    uint32 i;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    if (user == NULL || user->len == 0) {
        return GS_FALSE;
    }

    for (i = 0; i < GS_MAX_USERS; i++) {
        cm_spin_lock(&ctx->lock, NULL);
        if (ctx->users[i] != NULL && cm_text_str_equal(user, ctx->users[i]->desc.name)) {
            if (DC_HAS_SYS_PRIV(ctx->users[i]->all_sys_privs, priv_id) &&
                DC_HAS_SYS_OPT(ctx->users[i]->ter_admin_opt, priv_id)) {
                cm_spin_unlock(&ctx->lock);
                return GS_TRUE;
            }
        }
        cm_spin_unlock(&ctx->lock);
    }

    /* check if the privilege granted to public with admin option */
    if (DC_HAS_SYS_PRIV(ctx->users[DB_PUB_USER_ID]->all_sys_privs, priv_id) &&
        DC_HAS_SYS_OPT(ctx->users[DB_PUB_USER_ID]->ter_admin_opt, priv_id)) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

bool32 dc_grant_role_with_option(knl_session_t *session, text_t *username, text_t *rolename, bool32 with_option)
{
    uint32 rid;
    cm_list_head *item = NULL;
    dc_user_t *user = NULL;
    dc_role_t *role = NULL;
    dc_granted_role *parent = NULL;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    if (dc_open_user(session, username, &user) != GS_SUCCESS) {
        return GS_FALSE;
    }

    if (!dc_get_role_id(session, rolename, &rid)) {
        GS_THROW_ERROR(ERR_ROLE_NOT_EXIST, T2S(rolename));
        return GS_FALSE;
    }

    role = ctx->roles[rid];
    if (role->desc.owner_uid == user->desc.id) {
        return GS_TRUE;
    }

    cm_list_for_each(item, &user->parent)
    {
        parent = cm_list_entry(item, dc_granted_role, node);
        if (role == parent->granted_role) {
            if (with_option && parent->admin_opt != 1) {
                return GS_FALSE;
            }
            return GS_TRUE;
        }
    }

    /* other user can not drop the role created by PUBLIC without DROP ANY ROLE privilege */
    user = ctx->users[DB_PUB_USER_ID];
    cm_list_for_each(item, &user->parent)
    {
        parent = cm_list_entry(item, dc_granted_role, node);
        if (role == parent->granted_role) {
            if (with_option && parent->admin_opt != 1) {
                return GS_FALSE;
            }
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

void dc_update_obj_entry(dc_obj_priv_entry_t *entry, const char *oldname, text_t *newname)
{
    if (!entry->valid) {
        return;
    }

    cm_spin_lock(&entry->bucket->lock, NULL);
    if (!entry->valid) {
        cm_spin_unlock(&entry->bucket->lock);
        return;
    }

    if (cm_str_equal(oldname, entry->priv_item.objname)) {
        (void)cm_text2str(newname, entry->priv_item.objname, GS_NAME_BUFFER_SIZE);
    }

    cm_spin_unlock(&entry->bucket->lock);
}

void dc_drop_object_privs(dc_context_t *ctx, uint32 objowner, char *objname, uint32 objtype)
{
    uint32 i;
    text_t name;
    dc_user_t *user = NULL;
    dc_role_t *role = NULL;
    dc_obj_priv_entry_t *entry = NULL;

    cm_str2text(objname, &name);
    for (i = 0; i < GS_MAX_USERS; i++) {
        user = ctx->users[i];
        if (user != NULL && user->status == USER_STATUS_NORMAL) {
            if (dc_find_objpriv_entry(&user->obj_privs, objowner, &name, objtype, &entry)) {
                dc_drop_obj_entry(&user->obj_privs, entry);
            }
        }
    }

    for (i = 0; i < GS_MAX_ROLES; i++) {
        role = ctx->roles[i];
        if (role != NULL) {
            if (dc_find_objpriv_entry(&role->obj_privs, objowner, &name, objtype, &entry)) {
                dc_drop_obj_entry(&role->obj_privs, entry);
            }
        }
    }
}

void dc_collect_roles_privs(dc_role_t *role, uint8 *sys_privs, uint8 *admin_opt)
{
    uint32 i;
    cm_list_head *item = NULL;
    dc_granted_role *parent = NULL;
    dc_role_t *dc_role = NULL;

    cm_list_for_each(item, &role->parent)
    {
        parent = cm_list_entry(item, dc_granted_role, node);
        /* get a role, update the privileges and admin options */
        dc_role = parent->granted_role;
        for (i = 0; i < GS_SYS_PRIVS_BYTES; i++) {
            sys_privs[i] = dc_role->sys_privs[i] | sys_privs[i];
            admin_opt[i] = dc_role->admin_opt[i] | admin_opt[i];
        }
        dc_collect_roles_privs(dc_role, sys_privs, admin_opt);
    }
}

/*
* collect all the roles that granted to the user
*  (include indirectly granted through other roles) in to a list
*/
void dc_collect_user_priv(dc_user_t *user, uint8 *sys_privs, uint8 *admin_opt, uint32 array_len)
{
    uint32 i;
    cm_list_head *item = NULL;
    dc_granted_role *parent = NULL;
    dc_role_t *role = NULL;

    knl_panic(array_len <= GS_SYS_PRIVS_BYTES);

    cm_list_for_each(item, &user->parent)
    {
        parent = cm_list_entry(item, dc_granted_role, node);
        role = parent->granted_role;
        /* get a role, update the privileges and admin options */
        for (i = 0; i < array_len; i++) {
            sys_privs[i] = role->sys_privs[i] | sys_privs[i];
            admin_opt[i] = role->admin_opt[i] | admin_opt[i];
        }
        dc_collect_roles_privs(role, sys_privs, admin_opt);
    }
}

void dc_update_user_syspriv_info(dc_user_t *user)
{
    uint32 i;
    uint8 sys_privs[GS_SYS_PRIVS_BYTES];
    uint8 admin_opt[GS_SYS_PRIVS_BYTES];
    errno_t err;

    err = memset_sp(sys_privs, GS_SYS_PRIVS_BYTES, 0x0, GS_SYS_PRIVS_BYTES);
    knl_securec_check(err);
    err = memset_sp(admin_opt, GS_SYS_PRIVS_BYTES, 0x0, GS_SYS_PRIVS_BYTES);
    knl_securec_check(err);

    /* collect roles that granted to the user */
    dc_collect_user_priv(user, sys_privs, admin_opt, GS_SYS_PRIVS_BYTES);

    /* merge result: roles' privileges + user's privileges = (user's finall system privileges) */
    for (i = 0; i < GS_SYS_PRIVS_BYTES; i++) {
        sys_privs[i] = user->sys_privs[i] | sys_privs[i];
        admin_opt[i] = user->admin_opt[i] | admin_opt[i];
    }

    err = memcpy_sp(user->all_sys_privs, GS_SYS_PRIVS_BYTES, sys_privs, GS_SYS_PRIVS_BYTES);
    knl_securec_check(err);
    err = memcpy_sp(user->ter_admin_opt, GS_SYS_PRIVS_BYTES, admin_opt, GS_SYS_PRIVS_BYTES);
    knl_securec_check(err);

    return;
}

void dc_collect_roles_objprivs(dc_role_t *role, uint32 *objprivs, dc_obj_priv_item *priv_item)
{
    text_t objname;
    cm_list_head *item = NULL;
    dc_granted_role *parent = NULL;
    dc_role_t *dc_role = NULL;
    dc_obj_priv_entry_t *entry = NULL;

    cm_list_for_each(item, &role->parent)
    {
        parent = cm_list_entry(item, dc_granted_role, node);
        dc_role = parent->granted_role;

        cm_str2text(priv_item->objname, &objname);
        if (dc_find_objpriv_entry(&dc_role->obj_privs, priv_item->objowner, &objname,
            priv_item->objtype, &entry)) {
            *objprivs |= entry->priv_item.direct_grant;
        }

        dc_collect_roles_objprivs(dc_role, objprivs, priv_item);
    }
}

/*
* collect all the roles that granted to the user
*  (include indirectly granted through other roles) in to a list
*/
void dc_collect_user_objpriv(dc_user_t *user, uint32 *objprivs, dc_obj_priv_item *priv_item)
{
    text_t objname;
    cm_list_head *item = NULL;
    dc_granted_role *parent = NULL;
    dc_role_t *role = NULL;
    dc_obj_priv_entry_t *entry = NULL;

    cm_list_for_each(item, &user->parent)
    {
        parent = cm_list_entry(item, dc_granted_role, node);
        role = parent->granted_role;

        cm_str2text(priv_item->objname, &objname);
        if (dc_find_objpriv_entry(&role->obj_privs, priv_item->objowner, &objname,
            priv_item->objtype, &entry)) {
            *objprivs |= entry->priv_item.direct_grant;
        }

        dc_collect_roles_objprivs(role, objprivs, priv_item);
    }
}

void dc_update_user_objpriv_info(dc_context_t *ctx, dc_user_t *user, dc_obj_priv_item *priv_item)
{
    uint32 priv = 0;
    text_t objname;
    dc_obj_priv_entry_t *entry = NULL;

    if (priv_item->objowner == user->desc.id) {
        return;
    }

    /* collect roles' privileges that granted to the user */
    dc_collect_user_objpriv(user, &priv, priv_item);

    /* merge result: roles' privileges + user's privileges = (user's final object privileges) */
    cm_str2text(priv_item->objname, &objname);
    if (!dc_find_objpriv_entry(&user->obj_privs, priv_item->objowner, &objname, priv_item->objtype, &entry)) {
        /* allocate an object entry for the user */
        if (dc_alloc_objpriv_entry(ctx, &user->obj_privs, user->memory, priv_item->objowner,
            &objname, priv_item->objtype, &entry) != GS_SUCCESS) {
            return;
        }
    }

    /* update the privileges */
    cm_spin_lock(&entry->bucket->lock, NULL);
    entry->priv_item.privid_map = priv | entry->priv_item.direct_grant;
    cm_spin_unlock(&entry->bucket->lock);

    if (entry->priv_item.privid_map == 0) {
        dc_drop_obj_entry(&user->obj_privs, entry);
    }
    return;
}

void dc_merge_role_objpriv_to_user(knl_session_t *session, dc_role_t *role, dc_user_t *user)
{
    uint32 eid;
    text_t objname;
    dc_obj_priv_entry_t *entry = NULL;
    dc_obj_priv_entry_t *user_entry = NULL;
    dc_obj_priv_t *obj_privs = &role->obj_privs;
    for (eid = 0; eid < role->obj_privs.hwm; eid++) {
        entry = DC_GET_OBJPRIV_ENTRY(obj_privs, eid);
        if (entry != NULL && entry->valid && entry->priv_item.objowner != user->desc.id) {
            /* merge parents' privilege to user */
            cm_str2text(entry->priv_item.objname, &objname);
            if (!dc_find_objpriv_entry(&user->obj_privs, entry->priv_item.objowner, &objname,
                entry->priv_item.objtype, &user_entry)) {
                /* allocate an object entry for the user */
                if (dc_alloc_objpriv_entry(&session->kernel->dc_ctx, &user->obj_privs,
                    user->memory, entry->priv_item.objowner,
                    &objname, entry->priv_item.objtype,
                    &user_entry) != GS_SUCCESS) {
                    return;
                }
            }

            cm_spin_lock(&user_entry->bucket->lock, NULL);
            user_entry->priv_item.privid_map |= entry->priv_item.direct_grant;
            user_entry->priv_item.privid_map |= user_entry->priv_item.direct_grant;
            cm_spin_unlock(&user_entry->bucket->lock);
        }
    }
}

void dc_merge_parent_objprivs(knl_session_t *session, dc_user_t *user, cm_list_head *rolelist)
{
    cm_list_head *item1 = NULL;
    dc_role_t *role = NULL;
    dc_granted_role *parent = NULL;

    cm_list_for_each(item1, rolelist)
    {
        parent = cm_list_entry(item1, dc_granted_role, node);
        role = parent->granted_role;
        if (role == NULL) {
            continue;
        }

        dc_merge_role_objpriv_to_user(session, role, user);

        /* inherit privileges from role's parents */
        dc_merge_parent_objprivs(session, user, &role->parent);
    }
}

void dc_update_all_objprivs_info(knl_session_t *session, dc_user_t *user)
{
    uint32 eid;
    dc_obj_priv_entry_t *entry = NULL;
    dc_obj_priv_t *obj_privs = &user->obj_privs;
    /* clear privileges that inherited from roles */
    for (eid = 0; eid < user->obj_privs.hwm; eid++) {
        entry = DC_GET_OBJPRIV_ENTRY(obj_privs, eid);
        if (entry != NULL && entry->valid) {
            cm_spin_lock(&entry->bucket->lock, NULL);
            entry->priv_item.privid_map = entry->priv_item.direct_grant;
            entry->priv_item.privopt_map = entry->priv_item.direct_opt;
            cm_spin_unlock(&entry->bucket->lock);
        }
    }

    dc_merge_parent_objprivs(session, user, &user->parent);

    /* drop invalid entries */
    for (eid = 0; eid < user->obj_privs.hwm; eid++) {
        entry = DC_GET_OBJPRIV_ENTRY(obj_privs, eid);
        if (entry != NULL && entry->valid) {
            if (entry->priv_item.privid_map == 0) {
                dc_drop_obj_entry(&user->obj_privs, entry);
            }
        }
    }
}

/*
* update system privileges information for all the users that the role
* granted to(include indirectly users granted through other roles)
* @param[in]    ctx : dc context
* @param[in]    role : role's description who's system privileges changed
* @return NA
* @see NA
*/
void dc_update_user_syspriv_by_role(dc_role_t *role)
{
    cm_list_head *item = NULL;
    dc_user_granted *child_user = NULL;
    dc_granted_role *child_role = NULL;

    cm_list_for_each(item, &role->child_users)
    {
        child_user = cm_list_entry(item, dc_user_granted, node);
        dc_update_user_syspriv_info(child_user->user_granted);
    }

    cm_list_for_each(item, &role->child_roles)
    {
        child_role = cm_list_entry(item, dc_granted_role, node);
        dc_update_user_syspriv_by_role(child_role->granted_role);
    }
}

/*
* update object privileges information for all the users that the role
* granted to(include indirectly users granted through other roles)
* @param[in]    ctx : dc context
* @param[in]    role : role's description who's system privileges changed
* @return NA
* @see NA
*/
void dc_update_user_objpriv_by_role(dc_context_t *ctx, dc_role_t *role, dc_obj_priv_item *priv_item)
{
    cm_list_head *item = NULL;
    dc_user_granted *child_user = NULL;
    dc_granted_role *child_role = NULL;

    cm_list_for_each(item, &role->child_users)
    {
        child_user = cm_list_entry(item, dc_user_granted, node);
        dc_update_user_objpriv_info(ctx, child_user->user_granted, priv_item);
    }

    cm_list_for_each(item, &role->child_roles)
    {
        child_role = cm_list_entry(item, dc_granted_role, node);
        dc_update_user_objpriv_by_role(ctx, child_role->granted_role, priv_item);
    }
}

void dc_update_all_objprivs_by_role(knl_session_t *session, dc_role_t *role)
{
    dc_user_t *user = NULL;
    dc_user_granted *child_user = NULL;
    dc_granted_role *child_role = NULL;
    cm_list_head *item = NULL;

    cm_list_for_each(item, &role->child_users)
    {
        child_user = cm_list_entry(item, dc_user_granted, node);
        user = child_user->user_granted;
        dc_update_all_objprivs_info(session, user);
    }

    cm_list_for_each(item, &role->child_roles)
    {
        child_role = cm_list_entry(item, dc_granted_role, node);
        dc_update_all_objprivs_by_role(session, child_role->granted_role);
    }
}

static void dc_remove_from_objpriv(dc_obj_priv_t *obj_privs, dc_obj_priv_entry_t *entry)
{
    dc_obj_priv_entry_t *prev = NULL;
    dc_obj_priv_entry_t *next = NULL;

    if (entry->valid == GS_FALSE) {
        return;
    }

    cm_spin_lock(&entry->bucket->lock, NULL);

    if (entry->next != GS_INVALID_ID32) {
        next = DC_GET_OBJPRIV_ENTRY(obj_privs, entry->next);
        next->prev = entry->prev;
    }

    if (entry->prev != GS_INVALID_ID32) {
        prev = DC_GET_OBJPRIV_ENTRY(obj_privs, entry->prev);
        prev->next = entry->next;
    }

    if (entry->bucket->first == entry->id) {
        entry->bucket->first = entry->next;
    }

    cm_spin_unlock(&entry->bucket->lock);
}

static void dc_insert_into_objpriv(dc_obj_priv_t *obj_privs, dc_obj_priv_entry_t *entry)
{
    dc_obj_priv_entry_t *first_entry = NULL;
    dc_bucket_t *bucket = NULL;
    uint32 hash;
    text_t name;

    cm_str2text(entry->priv_item.objname, &name);
    hash = dc_hash(&name);
    bucket = &obj_privs->buckets[hash];
    entry->bucket = bucket;

    cm_spin_lock(&bucket->lock, NULL);
    entry->next = bucket->first;
    entry->prev = GS_INVALID_ID32;

    if (bucket->first != GS_INVALID_ID32) {
        first_entry = DC_GET_OBJPRIV_ENTRY(obj_privs, bucket->first);
        first_entry->prev = entry->id;
    }

    bucket->first = entry->id;
    entry->valid = GS_TRUE;
    cm_spin_unlock(&bucket->lock);
}

bool32 dc_try_reuse_objpriv_entry(dc_obj_priv_t *obj_privs, dc_obj_priv_entry_t **dc_entry)
{
    dc_obj_priv_entry_t *entry = NULL;

    entry = (dc_obj_priv_entry_t *)dc_list_remove(&obj_privs->free_entries);
    if (entry == NULL) {
        return GS_FALSE;
    }

    *dc_entry = entry;

    return GS_TRUE;
}

bool32 dc_try_reuse_userpriv_entry(dc_user_priv_t *user_privs, dc_user_priv_entry_t **dc_entry)
{
    dc_user_priv_entry_t *entry = NULL;
    
    entry = (dc_user_priv_entry_t *)dc_list_remove(&user_privs->free_entries);
    if (entry == NULL) {
        return GS_FALSE;
    }

    *dc_entry = entry;

    return GS_TRUE;
}

static void dc_insert_into_user_priv(dc_user_priv_t *user_privs, dc_user_priv_entry_t *entry)
{
    dc_user_priv_entry_t *first_entry = NULL;
    dc_bucket_t *bucket = NULL;
    uint32 hash;

    hash = entry->user_priv_item.grantee_id % DC_HASH_SIZE;
    bucket = &user_privs->buckets[hash];
    entry->bucket = bucket;

    cm_spin_lock(&bucket->lock, NULL);
    entry->next = bucket->first;
    entry->prev = GS_INVALID_ID32;

    if (bucket->first != GS_INVALID_ID32) {
        first_entry = DC_GET_OBJPRIV_ENTRY(user_privs, bucket->first);
        first_entry->prev = entry->id;
    }

    bucket->first = entry->id;
    entry->valid = GS_TRUE;
    cm_spin_unlock(&bucket->lock);
}

void dc_update_objname_for_privs(knl_session_t *session, uint32 uid, char *oldname, text_t *newname, uint32 type)
{
    uint32 i;
    text_t obj_name;
    dc_user_t *user = NULL;
    dc_role_t *role = NULL;
    dc_obj_priv_entry_t *entry = NULL;
    cm_list_head *item = NULL;
    dc_context_t *ctx = &session->kernel->dc_ctx;

    cm_str2text(oldname, &obj_name);

    for (i = 0; i < GS_MAX_USERS; i++) {
        user = ctx->users[i];
        if (user != NULL && user->status == USER_STATUS_NORMAL) {
            while (dc_find_objpriv_entry(&user->obj_privs, uid, &obj_name, type, &entry)) {
                /* update the object name */
                dc_remove_from_objpriv(&user->obj_privs, entry);
                dc_update_obj_entry(entry, oldname, newname);
                dc_insert_into_objpriv(&user->obj_privs, entry);
            }

            /* update grant object privilege information save by user */
            cm_list_for_each(item, &user->grant_obj_privs)
            {
                dc_grant_obj_priv *grant_obj_priv = cm_list_entry(item, dc_grant_obj_priv, node);

                if (cm_str_equal(grant_obj_priv->priv_item.objname, oldname) &&
                    (grant_obj_priv->priv_item.objowner == uid) &&
                    (grant_obj_priv->priv_item.objtype == type)) {
                    (void)cm_text2str(newname, grant_obj_priv->priv_item.objname, GS_NAME_BUFFER_SIZE);
                }
            }
        }
    }

    for (i = 0; i < GS_MAX_ROLES; i++) {
        role = ctx->roles[i];
        if (role != NULL) {
            while (dc_find_objpriv_entry(&role->obj_privs, uid, &obj_name, type, &entry)) {
                /* update the object name */
                dc_remove_from_objpriv(&role->obj_privs, entry);
                dc_update_obj_entry(entry, oldname, newname);
                dc_insert_into_objpriv(&role->obj_privs, entry);
            }
        }
    }
}

bool32 dc_has_objpriv_entry(dc_obj_priv_t *obj_privs)
{
    if ((obj_privs->free_entries.count != 0) || (obj_privs->hwm < DC_GROUP_SIZE * DC_GROUP_SIZE)) {
        return GS_TRUE;
    }
    return GS_FALSE;
}

bool32 dc_has_userpriv_entry(dc_user_priv_t *user_privs)
{
    if (user_privs->free_entries.count != 0 || user_privs->hwm < USER_PRIV_GROUP_COUNT * DC_GROUP_SIZE) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

void dc_init_objpriv_entry(dc_obj_priv_entry_t *entry, uint32 owner_uid, text_t *obj_name, uint32 obj_type)
{
    uint32 pid;
    /* fill the privilege information */
    (void)cm_text2str(obj_name, entry->priv_item.objname, GS_NAME_BUFFER_SIZE);
    entry->priv_item.objowner = owner_uid;
    entry->priv_item.objtype = obj_type;
    entry->priv_item.direct_grant = 0;
    entry->priv_item.direct_opt = 0;
    entry->priv_item.privid_map = 0;
    entry->priv_item.privopt_map = 0;
    for (pid = 0; pid < GS_OBJ_PRIVS_COUNT; pid++) {
        entry->priv_item.grantor[pid] = GS_INVALID_ID32;
    }
    return;
}
status_t dc_alloc_objpriv_entry(dc_context_t *ctx, dc_obj_priv_t *obj_privs, memory_context_t *memory, uint32 owner_uid,
                                text_t *obj_name, uint32 obj_type, dc_obj_priv_entry_t **dc_entry)
{
    uint32 gid, eid;
    char *page = NULL;
    errno_t ret;
    dc_obj_priv_entry_t *entry = NULL;
    cm_spin_lock(&obj_privs->lock, NULL);
    uint32 oid = obj_privs->hwm;

    if (!dc_try_reuse_objpriv_entry(obj_privs, &entry)) {
        if (oid >= DC_GROUP_SIZE * DC_GROUP_SIZE) {
            GS_THROW_ERROR(ERR_GRANT_OBJ_EXCEED_MAX, DC_GROUP_SIZE * DC_GROUP_SIZE);
            GS_LOG_RUN_ERR("[DC] failed to alloc objpriv entry");
            cm_spin_unlock(&obj_privs->lock);
            return GS_ERROR;
        }
        eid = oid % DC_GROUP_SIZE;
        gid = oid / DC_GROUP_SIZE;

        do {
            if (obj_privs->groups[gid] == NULL) {
                if (dc_alloc_page(ctx, &page) != GS_SUCCESS) {
                    cm_spin_unlock(&obj_privs->lock);
                    return GS_ERROR;
                }
                obj_privs->groups[gid] = (object_priv_group_t *)page;
            }

            if (dc_alloc_mem(ctx, memory, sizeof(dc_obj_priv_entry_t), (void **)&entry) != GS_SUCCESS) {
                GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
                cm_spin_unlock(&obj_privs->lock);
                return GS_ERROR;
            }

            ret = memset_sp(entry, sizeof(dc_obj_priv_entry_t), 0, sizeof(dc_obj_priv_entry_t));
            knl_securec_check(ret);

            obj_privs->groups[gid]->entries[eid] = entry;
            obj_privs->hwm++;
            entry->id = oid;
        } while (0);
    }
    cm_spin_unlock(&obj_privs->lock);
    *dc_entry = entry;
    /* init entry */
    dc_init_objpriv_entry(entry, owner_uid, obj_name, obj_type);
    /* add entry to the bucket */
    dc_insert_into_objpriv(obj_privs, entry);
    return GS_SUCCESS;
}

status_t dc_alloc_user_priv_entry(dc_context_t *ctx, dc_user_priv_t *user_privs, memory_context_t *memory,
                                  uint32 grantee, dc_user_priv_entry_t **dc_entry)
{
    uint32 eid, gid, pid;
    char *page = NULL;
    dc_user_priv_entry_t *entry = NULL;
    errno_t ret;
    cm_spin_lock(&user_privs->lock, NULL);
    uint32 oid = user_privs->hwm;

    if (!dc_try_reuse_userpriv_entry(user_privs, &entry)) {
        if (oid >= USER_PRIV_GROUP_COUNT * DC_GROUP_SIZE) {
            GS_THROW_ERROR(ERR_GRANT_OBJ_EXCEED_MAX, USER_PRIV_GROUP_COUNT * DC_GROUP_SIZE);
            GS_LOG_RUN_ERR("[DC] failed to alloc userpriv entry");
            cm_spin_unlock(&user_privs->lock);
            return GS_ERROR;
        }

        eid = oid % DC_GROUP_SIZE;
        gid = oid / DC_GROUP_SIZE;
        do {
            if (user_privs->groups[gid] == NULL) {
                if (dc_alloc_page(ctx, &page) != GS_SUCCESS) {
                    cm_spin_unlock(&user_privs->lock);
                    return GS_ERROR;
                }
                user_privs->groups[gid] = (user_group_priv_t *)page;
            }
            if (dc_alloc_mem(ctx, memory, sizeof(dc_user_priv_entry_t), (void **)&entry) != GS_SUCCESS) {
                GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
                cm_spin_unlock(&user_privs->lock);
                return GS_ERROR;
            }
            ret = memset_sp(entry, sizeof(dc_user_priv_entry_t), 0, sizeof(dc_user_priv_entry_t));
            knl_securec_check(ret);
            user_privs->groups[gid]->entries[eid] = entry;
            user_privs->hwm++;
            entry->id = oid;
        } while (0);
    }

    entry->user_priv_item.grantee_id = grantee;
    entry->user_priv_item.privid_map = 0;
    
    for (pid = 0; pid < GS_USER_PRIVS_COUNT; pid++) {
        entry->user_priv_item.grantor[pid] = GS_INVALID_ID32;
    }

    cm_spin_unlock(&user_privs->lock);
    *dc_entry = entry;

    /* add entry to the bucket */
    dc_insert_into_user_priv(user_privs, entry);

    return GS_SUCCESS;
}

void dc_drop_obj_entry(dc_obj_priv_t *obj_priv, dc_obj_priv_entry_t *entry)
{
    dc_obj_priv_entry_t *prev = NULL;
    dc_obj_priv_entry_t *next = NULL;
    errno_t err;
    uint32 eid = 0;
    uint32 gid = 0;

    if (entry->valid == GS_FALSE) {
        return;
    }

    cm_spin_lock(&entry->bucket->lock, NULL);

    if (entry->next != GS_INVALID_ID32) {
        gid = entry->next / DC_GROUP_SIZE;
        eid = entry->next % DC_GROUP_SIZE;
        next = obj_priv->groups[gid]->entries[eid];
        next->prev = entry->prev;
    }

    if (entry->prev != GS_INVALID_ID32) {
        gid = entry->prev / DC_GROUP_SIZE;
        eid = entry->prev % DC_GROUP_SIZE;
        prev = obj_priv->groups[gid]->entries[eid];
        prev->next = entry->next;
    }

    if (entry->bucket->first == entry->id) {
        entry->bucket->first = entry->next;
    }

    entry->valid = GS_FALSE;
    err = memset_sp(&entry->priv_item, sizeof(dc_obj_priv_item), 0, sizeof(dc_obj_priv_item));
    knl_securec_check(err);
    entry->prev = GS_INVALID_ID32;
    entry->next = GS_INVALID_ID32;
    dc_list_add(&obj_priv->free_entries, (dc_list_node_t *)entry);
    cm_spin_unlock(&entry->bucket->lock);
    entry->bucket = NULL;
}

void dc_drop_user_entry(dc_user_priv_t *user_privs, dc_user_priv_entry_t *entry)
{
    dc_user_priv_entry_t *prev = NULL;
    dc_user_priv_entry_t *next = NULL;
    errno_t err;

    if (entry->valid == GS_FALSE) {
        return;
    }

    dc_bucket_t *bucket = entry->bucket;
    cm_spin_lock(&bucket->lock, NULL);

    if (entry->next != GS_INVALID_ID32) {
        next = DC_GET_OBJPRIV_ENTRY(user_privs, entry->next);
        next->prev = entry->prev;
    }

    if (entry->prev != GS_INVALID_ID32) {
        prev = DC_GET_OBJPRIV_ENTRY(user_privs, entry->prev);
        prev->next = entry->next;
    }

    if (bucket->first == entry->id) {
        bucket->first = entry->next;
    }

    entry->valid = GS_FALSE;
    err = memset_sp(&entry->user_priv_item, sizeof(dc_user_priv_item_t), 0, sizeof(dc_user_priv_item_t));
    dc_list_add(&user_privs->free_entries, (dc_list_node_t *)entry);
    knl_securec_check(err);
    entry->bucket = NULL;
    cm_spin_unlock(&bucket->lock);
}

bool32 dc_find_objpriv_entry(dc_obj_priv_t *obj_privs, uint32 uid, text_t *obj_name, uint32 obj_type,
    dc_obj_priv_entry_t **dc_entry)
{
    uint32 hash, eid;
    dc_bucket_t *bucket;
    dc_obj_priv_entry_t *entry = NULL;

    hash = dc_hash(obj_name);
    bucket = &obj_privs->buckets[hash];

    cm_spin_lock(&bucket->lock, NULL);
    eid = bucket->first;
    entry = NULL;

    while (eid != GS_INVALID_ID32) {
        entry = DC_GET_OBJPRIV_ENTRY(obj_privs, eid);
        if (uid == entry->priv_item.objowner &&
            obj_type == entry->priv_item.objtype &&
            cm_text_str_equal(obj_name, entry->priv_item.objname)) {
            break;
        }

        eid = entry->next;
    }

    if (eid == GS_INVALID_ID32) {
        cm_spin_unlock(&bucket->lock);
        return GS_FALSE;
    }

    *dc_entry = entry;
    cm_spin_unlock(&bucket->lock);
    return GS_TRUE;
}
bool32 dc_find_user_priv_entry(dc_user_priv_t *user_privs, uint32 grantee, dc_user_priv_entry_t **dc_entry)
{
    uint32 hash, eid;
    dc_bucket_t *bucket;
    dc_user_priv_entry_t *entry = NULL;

    hash = grantee % DC_HASH_SIZE;
    bucket = &user_privs->buckets[hash];

    cm_spin_lock(&bucket->lock, NULL);
    eid = bucket->first;
    entry = NULL;

    while (eid != GS_INVALID_ID32) {
        entry = DC_GET_OBJPRIV_ENTRY(user_privs, eid);
        if (entry->user_priv_item.grantee_id == grantee) {
            break;
        }

        eid = entry->next;
    }

    if (eid == GS_INVALID_ID32) {
        cm_spin_unlock(&bucket->lock);
        return GS_FALSE;
    }

    *dc_entry = entry;
    cm_spin_unlock(&bucket->lock);
    return GS_TRUE;
}
