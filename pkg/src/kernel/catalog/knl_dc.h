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
 * knl_dc.h
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/knl_dc.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DC_H__
#define __KNL_DC_H__

#include "cm_defs.h"
#include "cm_memory.h"
#include "knl_interface.h"
#include "knl_session.h"
#include "pcr_heap.h"
#include "knl_lob.h"
#include "knl_privilege.h"
#include "knl_profile.h"
#include "cm_bilist.h"

#ifdef __cplusplus
extern "C" {
#endif

/* the limitation of max table DC_GROUP_COUNT * DC_GROUP_SIZE */
#define DC_ENTRY(dc)                         ((dc_entry_t *)(DC_ENTITY(dc))->entry)
#define DC_ENTRY_NAME(dc)                    (DC_ENTRY(dc)->name)
#define DC_ENTRY_USER_NAME(dc)               (DC_ENTRY(dc)->user->desc.name)
#define DC_GROUP_COUNT                       (GS_SHARED_PAGE_SIZE / sizeof(pointer_t))
#define DC_GROUP_SIZE                        (GS_SHARED_PAGE_SIZE / sizeof(pointer_t))
#define DC_GROUP_CURRVAL_COUNT               (GS_SHARED_PAGE_SIZE / sizeof(dc_currval_t))
#define DC_SESSION_GROUP_COUNT               ((GS_MAX_SESSIONS + DC_GROUP_CURRVAL_COUNT - 1) / DC_GROUP_CURRVAL_COUNT)
#define DC_CACHED_SERIAL_VALUE(value, start)                                \
    (((value) - (start)) / GS_SERIAL_CACHE_COUNT * GS_SERIAL_CACHE_COUNT +  \
    ((start) == 0 ? 1 : (start)) + GS_SERIAL_CACHE_COUNT)
#define DC_COLUMN_GROUP_SIZE                 512
#define DC_GET_SCH_LOCK(entry)               ((entry)->sch_lock)

#define DC_VIRTUAL_COL_START 60000

#define IS_SYS_DC(dc)   dc_is_reserved_entry(((knl_dictionary_t *)(dc))->uid, ((knl_dictionary_t *)(dc))->oid)
#define IS_SYS_TABLE(table) dc_is_reserved_entry((table)->desc.uid, (table)->desc.id)
#define IS_SYS_STATS_TABLE(uid, oid)         (((uid) == 0) && ((oid) == SYS_HIST_HEAD_ID || (oid) == SYS_HISTGRM_ID))
#define SYS_STATS_TABLE_ENABLE_TRUNCATE(dc, session)  (IS_SYS_STATS_TABLE((dc).uid, (dc).oid) && DB_IS_RESTRICT(session))

#define DC_ENTRY_IS_MONITORED(entry)                                        \
        ((entry)->type == DICT_TYPE_TABLE || (entry)->type == DICT_TYPE_TABLE_NOLOGGING)


#define KNL_RESET_DC(dc)              \
    do {                              \
        (dc)->handle = NULL;          \
        (dc)->syn_handle = NULL;      \
        (dc)->is_sysnonym = GS_FALSE; \
    } while (0)

typedef struct st_dc_list_node {
    void *next;
} dc_list_node_t;

typedef struct st_dc_bucket {
    spinlock_t lock;
    uint32 first;
} dc_bucket_t;

typedef enum en_user_status {
    USER_STATUS_NORMAL = 1,
    USER_STATUS_LOCKED = 2,
    USER_STATUS_OFFLINE = 3,
    USER_STATUS_DROPPED = 4
} user_status_t;

typedef enum en_dblink_status {
    DBLINK_STATUS_NORMAL = 1,
    DBLINK_STATUS_DROPPED
} dblink_status_t;

typedef struct st_sequence_desc {
    uint32 id;
    uint32 uid;
    char name[GS_MAX_NAME_LEN + 1];
    char reserved[3];
    int64 minval;
    int64 maxval;
    int64 step;
    uint64 cache;
    uint32 is_cyclable : 1;
    uint32 is_order : 1;
    uint32 is_cache : 1;
    uint32 unused : 29;
    knl_scn_t org_scn;
    knl_scn_t chg_scn;
    int64 lastval;
#ifdef Z_SHARDING
    binary_t dist_data;
#endif
} sequence_desc_t;

#define DC_HASH_SIZE (GS_SHARED_PAGE_SIZE / sizeof(dc_bucket_t))
#define USER_PRIV_GROUP_COUNT             (GS_MAX_USERS / DC_GROUP_SIZE + 1)

typedef struct st_dc_currval {
    int64 data;
    uint32 serial_id;
} dc_currval_t;

typedef struct st_dc_sequence {
    uint32 id;
    uint32 uid;
    char name[GS_MAX_NAME_LEN + 1];
    char reserved[3];
    uint16 is_cyclable : 1;
    uint16 is_order : 1;
    uint16 is_cache : 1;
    uint16 unused : 13;
    int64 minval;
    int64 maxval;
    int64 step;
    int64 cache_size;
    int64 cache_pos;
    struct st_sequence_entry *entry;
    bool32 valid; /* valid or not, changed by ddl */
    spinlock_t ref_lock;
    atomic32_t ref_count; /* reference number, inc/dec by sql */
    memory_context_t *memory;
    int64 lastval;
    int64 rsv_nextval; /* reserved nextval */
    binary_t dist_data;
    volatile uint32 version;
    struct st_dc_currval *currvals[DC_SESSION_GROUP_COUNT];
} dc_sequence_t;

typedef struct st_sequence_entry {
    dc_list_node_t node;
    drlock_t lock;
    knl_dict_type_t type;
    uint32 id;
    struct st_dc_bucket *bucket;
    struct st_dc_user *user;
    char name[GS_NAME_BUFFER_SIZE];
    uint32 uid;
    bool8 used;
    bool8 is_free;
    knl_scn_t org_scn;     /* scn when creating table */
    knl_scn_t chg_scn;     /* scn changed by the last ddl(alter) */
    dc_sequence_t *entity; /* the entity of table dictionary */
    uint32 prev;           /* for hash map or free entry list */
    uint32 next;           /* for hash map or free entry list */
} sequence_entry_t;

typedef enum en_dc_lrep_status {
    LOGICREP_STATUS_OFF,
    LOGICREP_STATUS_ON,
} dc_lrep_status_t;

typedef struct st_dc_list {
    spinlock_t lock;
    uint32 count;
    void *first;
} dc_list_t;

typedef struct st_dc_lrep_info {
    dc_lrep_status_t status;  // status of logicrep, currently: 0 - off, 1 - on
    uint32 index_id;          // which index is used for logic replication key: primary key, unique...
    uint32 index_slot_id;
    uint32 parts_count;  // the number of partition logicrep
} dc_lrep_info_t;

typedef struct st_dc_column_group {
    uint16 *column_index;   /* hash index, by column name */
    knl_column_t **columns; /* column array */
} dc_column_group_t;


typedef struct st_trig_item {
    uint8 trig_enable : 1;
    uint8 trig_event : 3;
    uint8 trig_type : 3;
    uint8 unused : 1;
    uint8 reserved[3];
    int64 oid;
} trig_item_t;

typedef struct st_trig_set {
    trig_item_t items[GS_MAX_TRIGGER_COUNT];
    uint32 trig_count;
} trig_set_t;

typedef struct st_dc_entity {
    struct st_dc_entry *entry; /* searching path: bucket->entry->entity */
    memory_context_t *memory;  /* independent memory object */
    dc_column_group_t *column_groups;
    knl_column_t **virtual_columns; /* virtual columns used for function based indexes */
    struct st_dc_entity *lru_prev;
    struct st_dc_entity *lru_next;
    union {
        table_t table;
        dynview_desc_t *dview;
        knl_view_t view;
    };
    volatile bool32 valid;         /* valid or not, changed by ddl */
    atomic32_t ref_count; /* reference number, inc/dec by sql */
    spinlock_t ref_lock;
    uint32 column_count;      /* column count */
    uint32 max_virtual_cols; /* max virtual column id */
    bool32 contain_lob;
    bool32 corrupted; /* table segment corrupted */
    knl_dict_type_t type;
    bool32 has_udef_col;  // table has update default column
    latch_t cbo_latch;    // for CBO statistics sync object
    cbo_stats_table_t *cbo_table_stats;
    uint32 stats_version;  // version of statistics
    bool32 stat_exists;    // statistics info exists or not
    dc_lrep_info_t lrep_info;
    bool32 forbid_dml;      // if any constraint state is disable and validate, forbit dml operation
    bool32 has_serial_col;  // table has serial/auto_increment column
    bool32 is_analyzing;
    bool32 stats_locked;
    trig_set_t trig_set;
} dc_entity_t;

typedef struct st_dc_lru_queue {
    spinlock_t lock;
    uint32 count;
    dc_entity_t *head;
    dc_entity_t *tail;
} dc_lru_queue_t;

typedef struct st_synonym_link {
    dc_list_node_t node;             // !!! must be the first memeber of structure
    char user[GS_NAME_BUFFER_SIZE];  // link user
    char name[GS_NAME_BUFFER_SIZE];  // link name
    object_type_t type;          // type of real object
} synonym_link_t;

typedef struct st_dc_appendix {
    void *node;
    synonym_link_t *synonym_link;
    stats_table_mon_t table_smon;
} dc_appendix_t;

typedef struct st_dc_entry {
    bilist_node_t node;  // !!!this member must be the first one
    spinlock_t lock;
    uint32 id;
    dc_bucket_t *bucket; /* hash bucket */
    union {
        struct st_dc_user *user;
        struct st_dc_dblink *dblink;
    };
    char user_name[GS_NAME_BUFFER_SIZE]; /* table user name */
    char name[GS_NAME_BUFFER_SIZE];      /* table name */
    drlock_t serial_lock;
    uint64 serial_value;
    uint16 uid;
    uint8 type;  // knl_dict_type_t
    bool8 recycled;
    volatile bool8 ready;
    volatile bool8 need_empty_entry; /* empty entry when nologging table is first loaded */
    bool8 used;
    bool8 is_free;
    knl_scn_t org_scn;
    knl_scn_t chg_scn;
    dc_entity_t *entity;
    uint32 prev; /* for hash map or free entry list */
    uint32 next; /* for hash map or free entry list */

    spinlock_t sch_lock_mutex;
    union {
        schema_lock_t *sch_lock;   /* for table */
        lock_mode_t ltt_lock_mode; /* for local temp table */
    };

    dc_appendix_t *appendix;
    volatile uint32 version;
    spinlock_t ref_lock;
    atomic32_t ref_count;
    drlatch_t ddl_latch;
} dc_entry_t;

typedef struct st_dc_group {
    dc_entry_t *entries[DC_GROUP_SIZE];
} dc_group_t;

typedef struct st_sequence_group {
    sequence_entry_t *entries[DC_GROUP_SIZE];
} sequence_group_t;

typedef struct st_sequence_context {
    dc_bucket_t *buckets;
    sequence_group_t **groups;
    dc_list_t free_entries;
    uint32 sequence_hwm;
    volatile bool8 is_loaded;
} sequence_set_t;

#define GS_SYS_PRIVS_BYTES     (GS_SYS_PRIVS_COUNT / 8 + 1)
#define DC_OBJ_PRIV_ENTRY_SIZE (GS_SHARED_PAGE_SIZE / sizeof(pointer_t))

typedef struct st_dc_obj_priv_item {
    uint32 objowner;                    /* object's owner user ID */
    char objname[GS_NAME_BUFFER_SIZE];  /* object's name */
    uint32 objtype;                     /* table/view/procedure */
    uint32 privid_map;                  /* privilege join set : directly granted & inherits from all roles */
    uint32 direct_grant;                /* is the privilege directly granted ? */
    uint32 privopt_map;                 /* privilege option join set : directly granted & inherits from all roles */
    uint32 direct_opt;                  /* is the privilege directly granted with grant option ? */
    uint32 grantor[GS_OBJ_PRIVS_COUNT]; /* grantor uid for each object privilege,
                                           GS_INVALID_ID32 means the privilege is inherited from roles */
} dc_obj_priv_item;
                                           
typedef struct st_dc_obj_privs_entry {
    dc_list_node_t node;  // !!!this member must be the first one
    uint32 id;
    bool32 valid;
    uint32 prev;
    uint32 next;
    dc_obj_priv_item priv_item;
    dc_bucket_t *bucket;
} dc_obj_priv_entry_t;

typedef struct st_object_priv_group {
    dc_obj_priv_entry_t *entries[DC_GROUP_SIZE];
} object_priv_group_t;

typedef struct st_dc_object_priv  {
    dc_bucket_t *buckets;
    object_priv_group_t **groups;
    dc_list_t free_entries;
    uint32 hwm;
    spinlock_t lock;
} dc_obj_priv_t;

typedef struct st_dc_user_privs_item {
    uint32 grantee_id;                            /* grantee uid */
    uint32 privid_map;                            /* privilege bit set */
    uint32 grantor[GS_USER_PRIVS_COUNT];           /* grantor uid for each user privilege */
} dc_user_priv_item_t;

typedef struct st_dc_user_privs_entry {
    dc_list_node_t node;  // !!!this member must be the first one
    uint32 id;
    bool32 valid;
    uint32 prev;
    uint32 next;
    dc_user_priv_item_t user_priv_item;
    dc_bucket_t *bucket;
} dc_user_priv_entry_t;

typedef struct st_user_priv_group {
    dc_user_priv_entry_t *entries[DC_GROUP_SIZE];
} user_group_priv_t;

typedef struct st_dc_user_priv {
    uint32 hwm;
    spinlock_t lock;
    dc_bucket_t *buckets;
    user_group_priv_t *groups[USER_PRIV_GROUP_COUNT];
    dc_list_t free_entries;
} dc_user_priv_t;

typedef struct st_knl_role_desc {
    uint32 id;                              /* role id */
    uint32 owner_uid;                       /* user id that create the role */
    char name[GS_NAME_BUFFER_SIZE];         /* role name */
    char password[GS_PASSWORD_BUFFER_SIZE]; /* role pwd */
} knl_role_desc_t;

typedef struct st_dc_role {
    drlock_t lock;                    /* lock */
    uint32 bucket_page_id;              /* bucket page id */
    uint32 entry_page_id;               /* bucket page id */
    knl_role_desc_t desc;               /* role description */
    memory_context_t *memory;           /* role memory context */
    uint8 sys_privs[GS_SYS_PRIVS_BYTES]; /* system privileges directly granted to the role,
                                                           data source: SYS_PRIVS$, grantee_type = 1 */
    uint8 admin_opt[GS_SYS_PRIVS_BYTES]; /* system privileges with admin option ? 1: yes, 0: no */
    dc_obj_priv_t obj_privs;            /* object privileges directly granted to the role,
                                                           data source: OBJECT_PRIVS$, grantee_type = 1 */
    cm_list_head parent;                /* roles list that granted to the role: dc_granted_role */
    cm_list_head child_users;           /* users list that the role granted to: dc_user_granted */
    cm_list_head child_roles;           /* roles list that the role granted to: dc_granted_role */
    cm_list_head parent_free;           /* roles list that the role revoke from: dc_granted_role */
    cm_list_head child_users_free;      /* users list that the role revoke from: dc_user_granted */
    cm_list_head child_roles_free;      /* roles list that the role revoke from: dc_granted_role */
} dc_role_t;

#define ACCOUNT_STATUS_OPEN          0x00000000
#define ACCOUNT_STATUS_EXPIRED       0x00000001
#define ACCOUNT_STATUS_EXPIRED_GRACE 0x00000002
#define ACCOUNT_STATUS_LOCK_TIMED    0x00000004
#define ACCOUNT_STATUS_LOCK          0x00000008
#define ACCOUNT_SATTUS_PERMANENT     0x00000010

typedef struct st_knl_user_desc {
    uint32 id;
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
    uint32 temp_space_id;
    uint32 tenant_id;
} knl_user_desc_t;

typedef struct st_dc_user {
    drlock_t lock;
    knl_user_desc_t desc;
    spinlock_t load_lock;                    /* spin lock for is_loaded flag */
    memory_context_t *memory;
    dc_group_t **groups;
    dc_bucket_t *buckets;
    dc_bucket_t *user_bucket;
    dc_bucket_t *tenant_bucket;
    sequence_set_t sequence_set;
    uint8 sys_privs[GS_SYS_PRIVS_BYTES];     /* system privileges directly granted to the user,
                                                               data source: SYS_PRIVS$, grantee_type = 1 */
    uint8 admin_opt[GS_SYS_PRIVS_BYTES];     /* system privileges with admin option ? 1: yes, 0: no */
    uint8 all_sys_privs[GS_SYS_PRIVS_BYTES]; /* all system privileges merged from user and granted roles */
    uint8 ter_admin_opt[GS_SYS_PRIVS_BYTES]; /* admin option for each privilege merged from user and roles */
    cm_list_head parent;                    /* roles that granted to the user */
    cm_list_head parent_free;               /* roles that granted to the user */
    dc_obj_priv_t obj_privs;                /* object privilegs directly granted to the user */
    dc_user_priv_t user_privs;
    uint32 prev;                            /* for user bucket */
    uint32 next;                            /* for user bucket */
    uint32 prev1;                           /* for tenant bucket */
    uint32 next1;                           /* for tenant bucket */
    uint32 entry_hwm;
    uint32 entry_lwm;
    bilist_t free_entries;
    spinlock_t free_entries_lock;
    cm_list_head grant_obj_privs; /* object privilegs the user directly granted to others */
    volatile bool8 is_loaded;
    bool8 has_nologging;
    user_status_t status;
    drlock_t s_lock;                       /* avoid changing user status concurrently */
    drlatch_t user_latch;                  /* avoid concurrent execution of drop user and create/drop object */
    drlatch_t lib_latch;
    uint32 user_locked_owner;
} dc_user_t;

typedef struct st_knl_tenant_desc {
    uint32 id;
    char name[GS_TENANT_BUFFER_SIZE];
    uint32 ts_id;
    date_t ctime;
    uint32 ts_num;
    uint8 ts_bitmap[GS_SPACES_BITMAP_SIZE];

    CM_MAGIC_DECLARE
} knl_tenant_desc_t;
#define knl_tenant_desc_t_MAGIC  289114898

typedef struct st_dc_tenant {
    dc_list_node_t node;  // !!!this member must be the first one
    spinlock_t lock;
    knl_tenant_desc_t desc;
    int32 ref_cnt;

    CM_MAGIC_DECLARE
} dc_tenant_t;
#define dc_tenant_t_MAGIC    787891859

typedef struct st_dc_grant_obj_priv {
    uint32 grantee_type;
    uint32 grantee_id;
    dc_obj_priv_item priv_item;
    uint32 priv_id;
    cm_list_head node;
} dc_grant_obj_priv;

typedef struct st_dc_dblink {
    latch_t latch;
    knl_dblink_desc_t desc;
    dblink_status_t status;
} dc_dblink_t;

typedef struct st_dc_context {
    spinlock_t lock;
    drlock_t paral_lock;
    volatile bool32 completed;
    volatile bool32 ready; /* ready for current open/mount/nomount mode */
    memory_pool_t pool;
    memory_context_t *memory;
    dc_bucket_t *user_buckets;
    dc_user_t *users[GS_MAX_USERS];
    dc_role_t *roles[GS_MAX_ROLES];
    dc_bucket_t *tenant_buckets;
    dc_tenant_t *tenants[GS_MAX_TENANTS];
    dc_dblink_t *dblinks[GS_MAX_DBLINKS];
    struct st_dc_spm *dc_spm;
    profile_array_t profile_array;
    dc_lru_queue_t *lru_queue;
    dc_list_t free_appendixes;
    dc_list_t free_schema_locks;
    dc_list_t free_trig_sets;
    dc_list_t free_synonym_links;
    dc_list_t free_tenants;
    uint32 user_hwm;
    volatile uint32 version;
    knl_handle_t kernel;
    latch_t tenant_latch;
} dc_context_t;

typedef struct st_dc_granted_role {
    cm_list_head node;       /* head list */
    uint32 admin_opt;        /* granted with admin option ? */
    dc_role_t *granted_role; /* granted role description */
} dc_granted_role;

typedef struct st_dc_user_granted {
    cm_list_head node;       /* head list */
    uint32 admin_opt;        /* granted with admin option ? */
    dc_user_t *user_granted; /* user granted description */
} dc_user_granted;

typedef struct st_rd_table {
    uint32 op_type;
    uint32 uid;
    uint32 oid;
} rd_table_t;

typedef struct st_create_heap_entry {
    rd_table_t tab_op;
    knl_part_locate_t part_loc;
    page_id_t entry;
} rd_create_heap_entry_t;

typedef struct st_create_btree_entry {
    rd_table_t tab_op;
    knl_part_locate_t part_loc;
    page_id_t entry;
    uint8 index_id;
    bool8 is_shadow;
} rd_create_btree_entry_t;

typedef struct st_create_lob_entry {
    rd_table_t tab_op;
    knl_part_locate_t part_loc;
    uint32 column_id;
    page_id_t entry;
} rd_create_lob_entry_t;

typedef struct st_rd_create_interval {
    rd_table_t tab_op;
    uint32 part_no;
    uint32 part_cnt;
} rd_create_interval_t;

typedef struct st_rd_create_table {
    uint32 op_type;
    uint32 uid;
    uint32 oid;
    char obj_name[GS_NAME_BUFFER_SIZE];
    knl_scn_t org_scn;
    knl_scn_t chg_scn;
    table_type_t type;
} rd_create_table_t;

typedef struct st_logic_col_info {
    uint32 id;        // column id
    uint32 datatype;  // column type
    uint32 size;      // column size
    int32 precision;  // precision, for number type
    int32 scale;      // scale, for number type
    char name[GS_NAME_BUFFER_SIZE];
} logic_col_info_t;

typedef struct st_rd_create_segment {
    uint32 op_type;
    uint32 uid;
    uint32 oid;
} rd_create_segment_t;

typedef struct st_rd_rename_table {
    uint32 op_type;
    uint32 uid;
    uint32 oid;
    char new_name[GS_NAME_BUFFER_SIZE];
} rd_rename_table_t;

typedef struct st_rd_drop_table {
    uint32 op_type;
    bool32 purge;
    uint32 uid;
    uint32 oid;
    char name[GS_NAME_BUFFER_SIZE];
    knl_scn_t org_scn;
} rd_drop_table_t;

static inline bool32 dc_is_reserved_entry(uint32 uid, uint32 entry_id)
{
    if (uid != 0) {
        return GS_FALSE;
    }

    if (entry_id < GS_RESERVED_SYSID || (entry_id >= GS_EX_SYSID_START && entry_id < GS_EX_SYSID_END)) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

#define DC_GET_ENTRY                    dc_get_entry
#define DC_ENTITY(dc)                   ((dc_entity_t *)(dc)->handle)
#define DC_LRU(dc)                      ((dc_lru_queue_t *)(DC_ENTITY(dc)->lru))
#define DC_INDEX(dc, slot)              (DC_ENTITY(dc)->table.index_set.items[slot])
#define DC_TABLE_INDEX(table, slot)     ((table)->index_set.items[slot])
#define DC_TABLE(dc)                    (&DC_ENTITY(dc)->table)
#define DC_IS_READY(session)            ((session)->kernel->db.status >= DB_STATUS_WAIT_CLEAN)
#define DC_GET_SEQ_CURRVAL(entity, id) \
    (((entity)->currvals[(id) / DC_GROUP_CURRVAL_COUNT]) + ((id) % DC_GROUP_CURRVAL_COUNT))

#define DC_RESET_SEQ_CURRVAL(entry, id) \
    (DC_GET_SEQ_CURRVAL((entry), (id))->serial = KNL_INVALID_SERIAL_ID)

#define DC_MIN_FREE_PAGES               1000
#define DC_MAX_POOL_PAGES(kernel) \
    (uint32)(int32)((kernel)->attr.shared_area->page_count * (1.0 - (kernel)->attr.sql_pool_factor))
#define DC_TRY_LOAD_TIMES               50
#define DC_TRY_LOAD_WAIT_TIMES          10
#define DC_TABLE_MAX_ROW_SIZE(dc)       (DC_TABLE(dc)->desc.max_row_size)
#define DC_VIRTUAL_COLUMN(entity, id)   ((entity)->virtual_columns[(id) - DC_VIRTUAL_COL_START])
#define DC_NORMAL_COLUMN(entity, id) \
    ((entity)->column_groups[(id) / DC_COLUMN_GROUP_SIZE].columns[(id) % DC_COLUMN_GROUP_SIZE])
#define DC_GET_COLUMN_PTR(entity, id) \
    (((id) < DC_VIRTUAL_COL_START) ? DC_NORMAL_COLUMN(entity, id) : DC_VIRTUAL_COLUMN(entity, id))
#define DC_GET_COLUMN_INDEX(entity, id) \
    ((entity)->column_groups[(id) / DC_COLUMN_GROUP_SIZE].column_index[(id) % DC_COLUMN_GROUP_SIZE])

/* common function */
void knl_open_core_cursor(knl_session_t *session, knl_cursor_t *cursor, knl_cursor_action_t action, uint32 id);
void knl_open_sys_cursor(knl_session_t *session, knl_cursor_t *cursor, knl_cursor_action_t action, uint32 table_id,
    uint32 index_slot);
status_t knl_open_sys_temp_cursor(knl_session_t *session, knl_cursor_t *cursor, knl_cursor_action_t action,
    uint32 table_id, uint32 index_slot);
void dc_set_table_accessor(table_t *table);
void dc_set_index_accessor(table_t *table, index_t *index);

bool32 dc_locked_by_self(knl_session_t *session, dc_entry_t *entry);
bool32 dc_entry_visible(dc_entry_t *entry, knl_dictionary_t *dc);
bool32 dc_is_locked(dc_entry_t *entry);
uint32 dc_hash(text_t *name);
const char *dc_type2name(knl_dict_type_t type);
status_t dc_copy_text2str(knl_session_t *session, memory_context_t *context, text_t *src, char **dst);
status_t dc_preload(knl_session_t *session, db_status_t status);
status_t dc_init(knl_session_t *session);
status_t dc_init_all_entry_for_upgrade(knl_session_t *session);
status_t dc_init_entries(knl_session_t *session, dc_context_t *ctx, uint32 uid);
void dc_invalidate(knl_session_t *session, dc_entity_t *entity);
void dc_invalidate_parents(knl_session_t *session, dc_entity_t *entity);
void dc_invalidate_children(knl_session_t *session, dc_entity_t *entity);
void dc_invalidate_nologging(knl_session_t *session);
void dc_invalidate_remote(knl_session_t *session, dc_entity_t *entity);
void dc_invalidate_remote(knl_session_t *session, dc_entity_t *entity);
void dc_invalidate_shadow_index(knl_handle_t dc_entity);
void dc_drop(knl_session_t *session, dc_entity_t *entity);
void dc_free_broken_entry(knl_session_t *session, uint32 uid, uint32 eid);
void dc_free_entry(knl_session_t *session, dc_entry_t *entry);
void dc_free_entry_list_add(dc_user_t *user, dc_entry_t *entry);
void dc_remove(knl_session_t *session, dc_entity_t *entity, text_t *name);
void dc_remove_from_bucket(knl_session_t *session, dc_entry_t *entry);
void dc_ready(knl_session_t *session, uint32 uid, uint32 oid);
bool32 dc_restore(knl_session_t *session, dc_entity_t *entity, text_t *name);
status_t dc_open(knl_session_t *session, text_t *user_name, text_t *obj_name, knl_dictionary_t *dc);
status_t dc_open_table_directly(knl_session_t *session, uint32 uid, uint32 oid, knl_dictionary_t *dc);
dc_entry_t *dc_get_entry(dc_user_t *user, uint32 id);
dc_entry_t *dc_get_entry_private(knl_session_t *session, text_t *username, text_t *name, knl_dictionary_t *dc);
void dc_reset_not_ready_by_nlg(knl_session_t *session);
void dc_set_ready(knl_session_t *session);
void dc_close(knl_dictionary_t *dc);
void dc_close_entity(knl_handle_t kernel, dc_entity_t *entity, bool32 need_lru_lock);
void dc_close_table_private(knl_dictionary_t *dc);

heap_t *dc_get_heap(knl_session_t *session, uint32 uid, uint32 oid, knl_part_locate_t part_loc, knl_dictionary_t *dc);
bool32 dc_find_by_id(knl_session_t *session, dc_user_t *user, uint32 oid, bool32 ex_recycled);
index_t *dc_find_index_by_id(dc_entity_t *dc_entity, uint32 index_id);
index_t *dc_find_index_by_name(dc_entity_t *dc_entity, text_t *index_name);
index_t *dc_find_index_by_name_ins(dc_entity_t *dc_entity, text_t *index_name);
index_t *dc_find_index_by_scn(dc_entity_t *dc_entity, knl_scn_t scn);
index_t *dc_get_index(knl_session_t *session, uint32 uid, uint32 oid, uint32 idx_id, knl_dictionary_t *dc);
btree_t *dc_get_btree(knl_session_t *session, page_id_t entry, knl_part_locate_t part_loc, bool32 is_shadow,
                      knl_dictionary_t *dc);
btree_t *dc_get_btree_by_id(knl_session_t *session, dc_entity_t *entity, uint16 index_id, knl_part_locate_t part_loc,
                            bool32 is_shadow);
status_t dc_create_entry(knl_session_t *session, dc_user_t *user, text_t *name, uint32 oid,
    bool8 is_recycled, dc_entry_t **entry);
status_t dc_create_entry_with_oid(knl_session_t *session, dc_user_t *user, text_t *name, uint32 oid,
    dc_entry_t **entry);
bool32 dc_find(knl_session_t *session, dc_user_t *user, text_t *name, knl_dictionary_t *dc);
void dc_insert_into_index(dc_user_t *user, dc_entry_t *entry, bool8 is_recycled);
void dc_set_index_profile(knl_session_t *session, dc_entity_t *entity, index_t *index);
void dc_get_entry_status(dc_entry_t *entry, text_t *status);
status_t dc_scan_all_tables(knl_session_t *session, uint32 *uid, uint32 *table_id, bool32 *eof);
status_t dc_scan_tables_by_user(knl_session_t *session, uint32 uid, uint32 *table_id, bool32 *eof);
bool32 dc_object_exists(knl_session_t *session, text_t *owner, text_t *name, knl_dict_type_t *type);
status_t dc_alloc_mem(dc_context_t *ctx, memory_context_t *mem, uint32 size, void **buf);
status_t dc_alloc_memory_page(dc_context_t *ctx, uint32 *page_id);
status_t dc_alloc_page(dc_context_t *ctx, char **page);
status_t dc_create_memory_context(dc_context_t *ctx, memory_context_t **memory);
status_t dc_alloc_schema_lock(knl_session_t *session, dc_entry_t *entry);
status_t dc_alloc_appendix(knl_session_t *session, dc_entry_t *entry);
status_t dc_alloc_entity(dc_context_t *ctx, dc_entry_t *entry);
bool32 dc_into_lru_needed(dc_entry_t *entry, dc_context_t *ctx);
void dc_load_child_entity(knl_session_t *session, cons_dep_t *dep, knl_dictionary_t *child_dc);
status_t dc_synctime_load_entity(knl_session_t *session);
status_t dc_get_part_fk_range(knl_session_t *session, knl_cursor_t *parent_cursor, knl_cursor_t *cursor,
    cons_dep_t *dep, uint32 *left_part_no, uint32 *right_part_no);
status_t dc_get_subpart_fk_range(knl_session_t *session, knl_cursor_t *parent_cursor, knl_cursor_t *cursor,
    cons_dep_t *dep, uint32 compart_no, uint32 *left_subpart_no, uint32 *right_subpart_no);
bool32 dc_locked_by_xa(knl_session_t *session, dc_entry_t *entry);
status_t dc_check_stats_version(knl_session_t *session, knl_dictionary_t *dc, dc_entity_t *entity);

/* table and view function */
void dc_convert_table_desc(knl_cursor_t *cursor, knl_table_desc_t *desc);
status_t dc_copy_column_data(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity, uint32 id,
    void *dest, bool32 is_reserved);
status_t dc_create_table_entry(knl_session_t *session, dc_user_t *user, knl_table_desc_t *desc);
status_t dc_create_view_entry(knl_session_t *session, dc_user_t *user, knl_view_t *view);
status_t dc_reset_nologging_entry(knl_session_t *session, knl_handle_t desc, object_type_t type);
status_t dc_rename_table(knl_session_t *session, text_t *new_name, knl_dictionary_t *dc);
status_t dc_load_part_table(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity);
status_t dc_load_part_index(knl_session_t *session, index_t *index);
status_t dc_load_shadow_indexparts(knl_session_t *session, knl_cursor_t *cursor, index_t *index);
status_t dc_load_shadow_index_part(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity);
status_t dc_alloc_part_lob(knl_session_t *session, dc_entity_t *entity, lob_t *lob);
status_t dc_load_lob_parts(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity, lob_t *lob);
status_t dc_open_table_private(knl_session_t *session, uint32 uid, uint32 oid, knl_dictionary_t *dc);
status_t dc_load_shadow_index(knl_session_t *session, knl_dictionary_t *dc);
status_t dc_prepare_load_columns(knl_session_t *session, dc_entity_t *entity);
status_t dc_load_core_table(knl_session_t *session, uint32 oid);
status_t dc_convert_view_desc(knl_session_t *session, knl_cursor_t *cursor, knl_view_t *view, dc_entity_t *entity);
knl_column_t *dc_get_column(const dc_entity_t *entity, uint16 id);
void dc_create_column_index(dc_entity_t *entity);
void dc_create_column_index(dc_entity_t *entity);
void dc_convert_table_part_desc(knl_cursor_t *cursor, knl_table_part_desc_t *desc);
void dc_convert_index_part_desc(knl_cursor_t *cursor, knl_index_part_desc_t *desc);
void dc_convert_lob_desc(knl_cursor_t *cursor, knl_lob_desc_t *desc);
void dc_convert_lob_part_desc(knl_cursor_t *cursor, knl_lob_part_desc_t *desc);
void dc_convert_part_store_desc(knl_cursor_t *cursor, knl_part_store_desc_t *desc);
void dc_convert_user_desc(knl_cursor_t *cursor, knl_user_desc_t *desc);
void dc_convert_index(knl_session_t *session, knl_cursor_t *cursor, knl_index_desc_t *desc);
void dc_calc_index_empty_size(knl_session_t *session, dc_entity_t *entity, uint32 slot, knl_part_locate_t part_loc,
    uint32 empty_leaf_blocks);
void dc_convert_tenant_desc(knl_cursor_t *cursor, knl_tenant_desc_t *desc);

/* ltt function */
bool32 dc_open_ltt(knl_session_t *session, dc_user_t *user, text_t *obj_name, knl_dictionary_t *dc);
status_t dc_find_ltt(knl_session_t *session, dc_user_t *user, text_t *table_name, knl_dictionary_t *dc,
    bool32 *found);
status_t dc_create_ltt_entry(knl_session_t *session, memory_context_t *ctx, dc_user_t *user,
    knl_table_desc_t *desc, uint32 slot_id, dc_entry_t **entry);
status_t dc_open_ltt_entity(knl_session_t *session, uint32 uid, uint32 oid, knl_dictionary_t *dc);

/* sequence function */
status_t dc_seq_open(knl_session_t *session, text_t *user_name, text_t *seq_name, knl_dictionary_t *dc);
void dc_seq_close(knl_dictionary_t *dc);

/* user and role function */
status_t dc_open_user(knl_session_t *session, text_t *username, dc_user_t **user);
status_t dc_open_user_direct(knl_session_t *session, text_t *username, dc_user_t **user);
status_t dc_open_user_by_id(knl_session_t *session, uint32 uid, dc_user_t **user);
// for create user sync_ddl replay node, do not init entries in user, to avoid buf_read page inside replay_logic lock
status_t dc_open_user_by_id_for_replay(knl_session_t *session, uint32 uid, dc_user_t **user);
status_t dc_set_user_status(knl_session_t *session, text_t *username, uint32 status);
status_t dc_try_lock_table_ux(knl_session_t *session, dc_entry_t *entry);
status_t dc_check_user_lock(knl_session_t *session, text_t *username);
status_t dc_check_user_lock_timed(knl_session_t *session, text_t *username, bool32 *p_lock_unlock);
status_t dc_check_user_expire(knl_session_t *session, text_t *username, char *message, uint32 message_len);
status_t dc_process_failed_login(knl_session_t *session, text_t *username, uint32 *p_lock_unlock);
status_t dc_update_user(knl_session_t *session, const char *user_name, bool32 *is_found);
bool32 dc_get_user_id(knl_session_t *session, const text_t *user, uint32 *uid);
status_t dc_get_user_default_spc(knl_session_t *session, uint32 uid, uint32 *spc_id);
status_t dc_get_user_temp_spc(knl_session_t *session, uint32 uid, uint32 *spc_id);
bool32 dc_get_role_id(knl_session_t *session, const text_t *role, uint32 *rid);
status_t dc_open_tenant_by_id(knl_session_t *session, uint32 tid, dc_tenant_t **tenant);
void dc_set_tenant_tablespace_bitmap(knl_tenant_desc_t* desc, uint32 ts_id);
bool32 dc_get_tenant_tablespace_bitmap(knl_tenant_desc_t* desc, uint32 ts_id);
status_t dc_open_tenant(knl_session_t *session, const text_t *tenantname, dc_tenant_t **tenant_out);
status_t dc_open_tenant_core(knl_session_t *session, const text_t *tenantname, dc_tenant_t **tenant_out);
void dc_close_tenant(knl_session_t *session, uint32 tenant_id);
status_t dc_update_tenant(knl_session_t *session, const char *tenant_name, bool32 *is_found);

/* privilege function */
void dc_init_sys_user_privs(dc_user_t *user);
bool32 dc_check_sys_priv_by_name(knl_session_t *session, text_t *username, uint32 priv_id);
bool32 dc_check_sys_priv_by_uid(knl_session_t *session, uint32 uid, uint32 priv_id);
bool32 dc_check_dir_priv_by_uid(knl_session_t *session, uint32 uid, uint32 priv_id);
bool32 dc_check_obj_priv_by_name(knl_session_t *session, text_t *curr_user, text_t *objuser,
    text_t *objname, object_type_t objtype, uint32 privid);
bool32 dc_check_obj_priv_with_option(knl_session_t *session, text_t *curr_user, text_t *objuser,
    text_t *objname, object_type_t objtype, uint32 privid);
bool32 dc_check_user_priv_by_name(knl_session_t *session, text_t *curr_user, text_t *objuser, uint32 privid);
bool32 dc_check_allobjprivs_with_option(knl_session_t *session, text_t *curr_user, text_t *objuser,
    text_t *objname, object_type_t objtype);
bool32 dc_sys_priv_with_option(knl_session_t *session, text_t *user, uint32 priv_id);
bool32 dc_grant_role_with_option(knl_session_t *session, text_t *username, text_t *rolename, bool32 with_option);
void rd_heap_create_entry(knl_session_t *session, log_entry_t *log);
void print_heap_create_entry(log_entry_t *log);
void rd_btree_create_entry(knl_session_t *session, log_entry_t *log);
void print_btree_create_entry(log_entry_t *log);
void rd_lob_create_entry(knl_session_t *session, log_entry_t *log);
void print_lob_create_entry(log_entry_t *log);
void rd_create_interval(knl_session_t* session, log_entry_t* log);
void print_create_interval(log_entry_t* log);

//performance case use dtc_dc_locked_by_id instead
bool32 dc_locked_by_self(knl_session_t *session, dc_entry_t *entry);

bool32 dc_find_objpriv_entry(dc_obj_priv_t *obj_privs, uint32 uid, text_t *obj_name, uint32 obj_type,
                             dc_obj_priv_entry_t **dc_entry);
bool32 dc_find_user_priv_entry(dc_user_priv_t *user_privs, uint32 grantee, dc_user_priv_entry_t **dc_entry);
void dc_drop_object_privs(dc_context_t *ctx, uint32 objowner, char *objname, uint32 objtype);

dc_entity_t *dc_get_entity_from_lru(knl_session_t *session, uint32 pos, bool32 *is_found);
bool32 dc_replication_enabled(knl_session_t *session, dc_entity_t *entity, knl_part_locate_t part_loc);
void dc_recycle_table_dls(knl_session_t *session, dc_entry_t *entry);

#ifdef Z_SHARDING
status_t dc_create_distribute_rule_entry(knl_session_t *session, knl_table_desc_t *desc);
typedef struct st_distribute_strategy_desc {
    uint32 user_id;
    uint32 table_id;
    binary_t dist_data;
    binary_t buckets;
    text_t dist_text;
    uint32  frozen_status;
} distribute_strategy_t;

typedef struct st_rd_distribute_rule {
    uint32 op_type;
    uint32 uid;
    uint32 oid;
    char name[GS_NAME_BUFFER_SIZE];
} rd_distribute_rule_t;
#endif

#ifdef __cplusplus
}
#endif

#endif
