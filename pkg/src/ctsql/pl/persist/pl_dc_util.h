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
 * pl_dc_util.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/persist/pl_dc_util.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __PL_DC_UTIL_H__
#define __PL_DC_UTIL_H__

#include "pl_anonymous.h"
#include "pl_procedure.h"
#include "pl_trigger.h"
#include "pl_type.h"
#include "pl_package.h"
#include "pl_library.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_pl_entity pl_entity_t;
typedef struct st_pl_entry pl_entry_t;
typedef struct st_pl_list pl_list_t;

struct st_pl_list {
    latch_t latch;
    bilist_t lst;
};

typedef struct st_pl_create_def pl_create_def_t;
struct st_pl_create_def {
    uint32 large_page_id;
    bool32 compl_result;
    text_t source;
    create_option_t create_option;
};

struct st_pl_entity {
    pl_entry_t *entry;        // searching path: bucket->entry->entity
    memory_context_t *memory; // independent memory object
    bilist_node_t lru_link;
    bilist_node_t bucket_link;

    union {
        anonymous_t *anonymous;
        function_t *function;
        procedure_t *procedure;
        trigger_t *trigger;
        type_spec_t *type_spec;
        type_body_t *type_body;
        package_spec_t *package_spec;
        package_body_t *package_body;
    };

    volatile bool8 valid; // valid or not, changed by ddl
    bool8 is_auton_trans; // enable autonmous transaction
    bool8 cached;
    bool8 cacheable;
    atomic32_t ref_count; // reference number, inc/dec by sql
    spinlock_t lock;
    uint32 pl_type;
    uint32 find_hash : 24;
    uint32 lru_hash : 8;
    var_udo_t def;
    pl_create_def_t *create_def;
    sql_context_t *context;
    galist_t sqls;
    galist_t dc_lst;
    galist_t sequences;
    galist_t ref_list; // All dependencies only for write table
    galist_t knl_list; // direct dependent tables or views
#ifdef Z_SHARDING
    // flag used in execution phase
    bool32 has_sharding_tab : 1;
    bool32 unused : 31;
#endif
};


typedef struct st_trig_def {
    uint32 obj_uid;
    uint64 obj_oid;
} trig_def_t;

typedef struct st_pl_desc {
    char name[CT_NAME_BUFFER_SIZE];
    uint32 uid;
    uint64 oid; // object id, if type == PL_SYS_PACKAGE, oid is package id
    uint32 type;
    object_status_t status;
    knl_scn_t chg_scn;
    knl_scn_t org_scn;
    union {
        trig_def_t trig_def;
        struct {
            char link_user[CT_NAME_BUFFER_SIZE];
            char link_name[CT_NAME_BUFFER_SIZE];
        };
    };
    union {
        uint32 flags;
        struct {
            uint32 is_aggr : 1;
            uint32 pipelined : 1;
            uint32 is_synonym : 1;
            uint32 lang_type : 2; /* is plsql or clang */
            uint32 unused_flag : 27;
        };
    };
} pl_desc_t;

struct st_pl_entry {
    spinlock_t lock;
    spinlock_t write_lock;
    uint32 bucket_id : 24;
    bool32 ready : 8;
    pl_desc_t desc;
    void *meta_lock;
    pl_entity_t *entity;
    bilist_node_t bucket_link;
    bilist_node_t free_link;
    bilist_node_t oid_link;
};

typedef struct st_pl_entry_info {
    pl_entry_t *entry;
    knl_scn_t scn;
} pl_entry_info_t;

void pl_entry_lock(pl_entry_t *pl_entry);
void pl_entry_unlock(pl_entry_t *pl_entry);
void pl_entity_lock(pl_entity_t *pl_entity);
void pl_entity_unlock(pl_entity_t *pl_entity);
void pl_set_entity_valid(pl_entity_t *pl_entity, bool8 valid);
void pl_list_insert_head(pl_list_t *list_node, bilist_node_t *node, bool32 need_lock);
void pl_list_del(pl_list_t *list_node, bilist_node_t *node, bool32 need_lock);

#define pl_lru_insert pl_list_insert_head
#define pl_lru_remove pl_list_del
void pl_lru_shift(pl_list_t *list_node, bilist_node_t *node, bool32 need_lock);

void pl_entry_delete_from_oid_bucket(pl_entry_t *entry);
void pl_set_entry_status(pl_entry_t *pl_entry, bool32 ready);
void pl_entity_invalidate(pl_entity_t *pl_entity);
void pl_entity_invalidate_by_entry(pl_entry_t *pl_entry);
void pl_update_entry_desc(pl_entry_t *entry, pl_desc_t *desc);
void pl_desc_set_trig_def(pl_desc_t *desc, trig_desc_t *trig_desc);
void pl_entry_drop(pl_entry_t *pl_entry);
void pl_free_entry(pl_entry_t *entry);
status_t pl_alloc_source_page(knl_session_t *sess, pl_source_pages_t *source_pages, uint32 source_len, char **ret_buf,
    bool32 *new_page);
void pl_free_source_page(pl_source_pages_t *src_page, bool32 new_page);

void pl_entity_ref_inc(pl_entity_t *pl_entity);
void pl_entity_ref_dec(pl_entity_t *pl_entity);
void pl_entity_uncacheable(pl_entity_t *pl_entity);

status_t pl_find_entry(knl_session_t *session, text_t *user, text_t *name, uint32 type, pl_entry_t **entry_out,
    bool32 *found);
status_t pl_find_entry_with_public(knl_session_t *session, text_t *user, text_t *name, bool32 explict, uint32 type,
    pl_entry_t **entry_out, bool32 *found);
status_t pl_find_or_create_entry(sql_stmt_t *stmt, dc_user_t *dc_user, pl_desc_t *desc, pl_entry_info_t *entry_info,
    bool32 *found);
void pl_find_entry_for_desc(dc_user_t *dc_user, text_t *name, uint32 type, pl_entry_info_t *entry_info, bool32 *found);
void pl_free_broken_entry(pl_entry_t *entry);
void pl_find_entry_by_oid(uint64 oid, uint32 type, pl_entry_info_t *entry_info);
void pl_set_entity(pl_entry_t *entry, pl_entity_t **entity_out);
void pl_set_entity_for_recompile(pl_entry_t *entry, pl_entity_t *entity);
void pl_entry_insert_into_oid_bucket(pl_entry_t *entry);
bool32 pl_entry_check(pl_entry_t *entry, uint32 uid, const char *name, uint32 type);
#ifdef __cplusplus
}
#endif
#endif