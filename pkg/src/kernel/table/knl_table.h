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
 * knl_table.h
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_table.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_TABLE_H__
#define __KNL_TABLE_H__

#include "cm_defs.h"
#include "knl_dc.h"
#include "knl_interface.h"
#include "knl_session.h"
#include "knl_mtrl.h"
#include "index_defs.h"
#ifdef __cplusplus
extern "C" {
#endif

#define COLUMN_LIST_BUF_LEN (GS_MAX_INDEX_COLUMNS * 8)
#define TABLE_IS_TEMP(type) (type == TABLE_TYPE_SESSION_TEMP || type == TABLE_TYPE_TRANS_TEMP)

typedef struct st_rebuild_info_t {
    bool32 is_alter;
    knl_parts_locate_t parts_loc;
    uint32 spc_id;
    alter_index_type_t alter_index_type;
}rebuild_info_t;

typedef struct st_rd_altable_rename_table {
    char user_str[GS_NAME_BUFFER_SIZE];
    char name_str[GS_NAME_BUFFER_SIZE];
    char new_name_str[GS_NAME_BUFFER_SIZE];
} rd_altable_rename_table_t;

typedef struct st_rd_view {
    uint32 op_type;
    uint32 uid;
    uint32 oid;
    char obj_name[GS_NAME_BUFFER_SIZE];
} rd_view_t;

typedef enum en_sys_consdef_col_id {
    CONSDEF_COL_USER = 0,
    CONSDEF_COL_TABLE,
    CONSDEF_COL_NAME,
    CONSDEF_COL_TYPE,
    CONSDEF_COL_COLUMN_COUNT,
    CONSDEF_COL_COLUMN_LIST,
    CONSDEF_COL_INDEX_ID,
    CONSDEF_COL_REF_USER,
    CONSDEF_COL_REF_TABLE,
    CONSDEF_COL_REF_INDEX,
    CONSDEF_COL_COND_TEXT,
    CONSDEF_COL_COND_DATA,
    CONSDEF_COL_FLAGS,
    CONSDEF_COL_REFACTOR,
} sys_consdef_col_id_t;

typedef enum en_sys_icol_col_id {
    ICOL_COL_USER = 0,
    ICOL_COL_TABLE,
    ICOL_COL_INDEX,
    ICOL_COL_COLUMN,
    ICOL_COL_POS,
    ICOL_COL_ARG_COUNT,
    ICOL_COL_ARG_LIST,
} icols_col_id_t;

typedef struct st_rd_synonym {
    uint32 op_type;
    uint32 uid;
    uint32 id;
} rd_synonym_t;

/* heap accessor structure */
typedef struct st_table_accessor {
    knl_cursor_operator_t do_fetch;
    knl_cursor_operator_t do_rowid_fetch;
    knl_cursor_operator_t do_fetch_by_rowid;
    knl_cursor_operator1_t do_lock_row;
    knl_cursor_operator_t do_insert;
    knl_cursor_operator_t do_update;
    knl_cursor_operator_t do_delete;
} table_accessor_t;

/* table version */
typedef enum en_table_version {
    TABLE_VERSION_START = 0,
    TABLE_VERSION_NEW_HASH = 1,    // from this version, the hash table will apply new hash algorithm

    TABLE_VERSION_COUNT,
} table_version_t;

status_t db_create_table(knl_session_t *session, knl_table_def_t *def, table_t *table, bool32 *is_referenced);
status_t db_create_part_table(knl_session_t *session, knl_cursor_t *cursor, table_t *table, knl_table_def_t *table_def);
status_t db_altable_add_part(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_altable_add_subpartition(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_altable_split_part(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_altable_coalesce_partition(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_altable_coalesce_subpartition(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_drop_table(knl_session_t *session, knl_handle_t stmt, knl_dictionary_t *dc);
status_t db_drop_part_table(knl_session_t *session, knl_cursor_t *cursor, part_table_t *part_table);
status_t db_update_part_count(knl_session_t *session, uint32 uid, uint32 tid, uint32 iid, bool32 is_add);
status_t part_update_interval_part_count(knl_session_t *session, table_t *table, uint32 part_no, uint32 iid,
                                         bool32 is_add);
status_t db_drop_part_btree_segments(knl_session_t *session, index_t *index, knl_parts_locate_t parts_loc);
bool32 db_table_has_segment(knl_session_t *session, knl_dictionary_t *dc);
status_t db_drop_part_segments(knl_session_t *session, knl_dictionary_t *dc, uint32 part_no);
void db_unreside_table_segments(knl_session_t *session, knl_dictionary_t *dc);
bool32 db_table_is_referenced(knl_session_t *session, table_t *table, bool32 check_state);
status_t db_create_index(knl_session_t *session, knl_index_def_t *def, knl_dictionary_t *dc, bool32 is_cons,
                         uint32 *index_id);
status_t db_alter_index_rebuild_part(knl_session_t *session, knl_alindex_def_t *def, knl_dictionary_t *dc,
                                     index_t *index);
status_t knl_alter_index_rename(knl_handle_t session, knl_alt_index_prop_t *def, knl_dictionary_t *dc,
                                index_t *old_index);
status_t db_create_part_index(knl_session_t *session, knl_cursor_t *cursor, index_t *index,
                              knl_part_obj_def_t *def);
status_t db_create_part_shadow_index(knl_session_t *session, knl_dictionary_t *dc, index_t *index,
    knl_part_obj_def_t *def, rebuild_info_t rebuild_info);
status_t db_drop_index(knl_session_t *session, index_t *index, knl_dictionary_t *dc);
status_t db_fetch_index_desc(knl_session_t *session, uint32 uid, uint32 table_id, text_t *name,
                             knl_index_desc_t *desc);
status_t db_update_index_status(knl_session_t *session, index_t *index, bool32 is_invalid, bool32 *is_changed);
status_t db_update_table_chgscn(knl_session_t *session, knl_table_desc_t *desc);
status_t db_update_index_count(knl_session_t *session, knl_cursor_t *cursor, knl_table_desc_t *desc,
                               bool32 is_add);
status_t db_update_table_trig_flag(knl_session_t *session, knl_table_desc_t *desc, bool32 has_trig);
status_t db_update_table_entry(knl_session_t *session, knl_table_desc_t *desc, page_id_t entry);
status_t db_update_table_flag(knl_session_t *session, uint32 user_id, uint32 table_id, table_flag_type_e flag_type);
status_t db_update_table_part_entry(knl_session_t *session, knl_table_part_desc_t *desc, page_id_t entry);
status_t db_update_subtabpart_entry(knl_session_t *session, knl_table_part_desc_t *desc, page_id_t entry);
status_t db_update_index_entry(knl_session_t *session, knl_index_desc_t *desc, page_id_t entry);
status_t db_upd_idx_part_entry(knl_session_t *session, knl_index_part_desc_t *desc, page_id_t entry);
status_t db_update_shadow_index_entry(knl_session_t *session, knl_index_desc_t *desc, page_id_t entry);
status_t db_upd_shadow_idx_part_entry(knl_session_t *session, knl_index_part_desc_t *desc, page_id_t entry,
    bool32 is_sub);
status_t db_upd_sub_idx_part_entry(knl_session_t *session, knl_index_part_desc_t *desc, page_id_t entry);
status_t db_upd_idx_part(knl_session_t *session, knl_index_part_desc_t *desc);
status_t db_upd_idx_subpart(knl_session_t *session, knl_index_part_desc_t *desc);
status_t db_switch_shadow_idx_partitions(knl_session_t *session, knl_cursor_t *cursor, index_t *index);
status_t db_create_lob(knl_session_t *session, table_t *table, knl_column_t *column, knl_table_def_t *def);
status_t db_create_part_lob(knl_session_t *session, knl_cursor_t *cursor, table_t *table, knl_table_def_t *def,
                            lob_t *lob);
status_t db_update_lob_entry(knl_session_t *session, knl_lob_desc_t *desc, page_id_t entry);
status_t db_update_lob_part_entry(knl_session_t *session, knl_lob_part_desc_t *desc, page_id_t entry);
status_t db_update_sublobpart_entry(knl_session_t *session, knl_lob_part_desc_t *desc, page_id_t entry);
status_t db_update_parent_tabpartid(knl_session_t *session, uint32 uid, uint32 table_id, uint32 old_partid,
    uint32 new_partid);
status_t db_upd_parent_idx_partid(knl_session_t *session, knl_index_desc_t *desc, uint32 old_partid,
    uint32 new_partid);
status_t db_update_parent_lobpartid(knl_session_t *session, knl_lob_desc_t *desc, uint32 old_partid, uint32 new_partid);
status_t db_update_table_name(knl_session_t *session, uint32 uid, const char *name, text_t *new_name,
                              bool32 recycled);
status_t db_update_index_name(knl_session_t *session, uint32 uid, uint32 table_id, const char *name, text_t *new_name);
bool32 part_idx_find_by_name(part_index_t *part_index, text_t *name, index_part_t **idx_part);
status_t db_init_table_desc(knl_session_t *session, knl_table_desc_t *desc, knl_table_def_t *def);
bool32 db_index_columns_matched(knl_session_t *session, knl_index_desc_t *desc, dc_entity_t *entity,
                                knl_handle_t def_cols, uint32 col_count, uint16 *columns);
status_t db_create_ltt(knl_session_t *session, knl_table_def_t *def, dc_entity_t *entity);
status_t db_drop_ltt(knl_session_t *session, knl_dictionary_t *dc);
status_t db_create_ltt_index(knl_session_t *session, knl_index_def_t *def, knl_dictionary_t *dc,
                             bool32 need_fill_index);
status_t db_altable_rename_constraint(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_altable_add_column(knl_session_t *session, knl_dictionary_t *dc, void *stmt, knl_altable_def_t *def);
status_t db_altable_drop_column(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_altable_add_cons(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_altable_drop_cons(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_altable_modify_column(knl_session_t *session, knl_dictionary_t *dc, void *stmt,
                                  knl_altable_def_t *def);
status_t db_altable_rename_column(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_altable_rename_table(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def,
                                 void *trig_list);
status_t db_altable_pctfree(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_altable_initrans(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_altable_storage(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_altable_part_initrans(knl_session_t *session, knl_dictionary_t *dc, knl_alt_part_t *def);
status_t db_altable_part_storage(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_altable_appendonly(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_altable_drop_logical_log_inner(knl_session_t *session, knl_cursor_t *cursor,
    const uint32 uid, const uint32 tableid);
status_t db_altable_update_logical_log(knl_session_t *session, knl_cursor_t *cursor,
    const uint32 uid, const uint32 tableid, text_t *text);
status_t db_altable_drop_part(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def,
                              bool32 is_part_add_or_coalesce);
status_t db_altable_truncate_part(knl_session_t *session, knl_dictionary_t *dc, knl_alt_part_t *def);
status_t db_altable_set_interval_part(knl_session_t *session, knl_dictionary_t *dc, knl_alt_part_t *def);
status_t db_need_invalidate_index(knl_session_t *session, knl_dictionary_t *dc, table_t *table,
                                  table_part_t *table_part, bool32 *is_need);
status_t db_create_view(knl_session_t *session, knl_handle_t stmt, knl_view_def_t *def);
status_t db_drop_view(knl_session_t *session, knl_handle_t stmt, knl_dictionary_t *dc);
status_t db_create_or_replace_view(knl_session_t *session, knl_handle_t stmt, knl_view_def_t *def);
status_t db_drop_all_cons(knl_session_t *session, uint32 uid, uint32 oid, bool32 only_fk);
status_t db_drop_cascade_cons(knl_session_t *session, uint32 uid, uint32 oid);
status_t db_invalid_fk_cons(knl_session_t *session, knl_dictionary_t *dc);
status_t db_delete_from_sys_user(knl_session_t *session, uint32 uid);
status_t db_drop_table_by_user(knl_session_t *session, text_t *user);
status_t db_delete_job_by_user(knl_session_t *session, text_t *user);
bool32 db_user_has_objects(knl_session_t *session, uint32 uid, text_t *uname);
status_t db_insert_ptrans(knl_session_t *session, knl_xa_xid_t *xa_xid, uint64 ltid, binary_t *tlocklob,
                          rowid_t *rowid);
status_t db_fetch_ptrans_by_gtid(knl_session_t *session, knl_xa_xid_t *xa_xid, uint64 *ltid, bool32 *is_found,
                                 rowid_t *rowid);
status_t db_fetch_ptrans_by_ltid(knl_session_t *session, uint64 ltid, knl_xa_xid_t *xa_xid,
                                 binary_t *tlocklob, bool32 *is_found, knl_rm_t *rm);
status_t db_delete_ptrans_by_rowid(knl_session_t *session, knl_xa_xid_t *xa_xid, uint64 ltid, rowid_t rowid);
status_t db_delete_ptrans_remained(knl_session_t *session, knl_xa_xid_t *xa_xid, uint64 *ltid, bool32 *is_found);


status_t db_delete_from_sysdep(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, int64 oid, uint32 tid);
status_t db_delete_dependency(knl_session_t *session, uint32 uid, int64 oid, uint32 tid);
status_t db_create_synonym(knl_session_t *session, knl_handle_t stmt, knl_synonym_def_t *def);
status_t db_drop_synonym(knl_session_t *session, knl_handle_t stmt, knl_dictionary_t *dc);
status_t db_drop_view_by_user(knl_session_t *session, text_t *username, uint32 uid);
status_t db_fetch_syssynonym_by_user(knl_session_t *session, uint32 uid, knl_cursor_t *cursor);
status_t db_drop_synonym_by_user(knl_session_t *session, uint32 uid);
status_t db_delete_from_sys_roles(knl_session_t *session, uint32 rid);
status_t db_delete_table_stats(knl_session_t *session, text_t *ownname, text_t *tabname, text_t *partname);
status_t db_analyze_table(knl_session_t *session, knl_analyze_tab_def_t *def, bool32 is_dynamic);
status_t db_analyze_table_part(knl_session_t *session, knl_analyze_tab_def_t *def, bool32 is_dynamic);
status_t db_analyze_index(knl_session_t *session, knl_analyze_index_def_t *def, bool32 is_dynamic);
status_t db_alter_index_rebuild(knl_session_t *session, knl_alindex_def_t *def, knl_dictionary_t *dc,
                                index_t *old_index);
status_t db_create_index_online(knl_session_t *session, knl_index_def_t *def, knl_dictionary_t *dc);

bool32 db_fetch_systable_by_user(knl_session_t *session, uint32 uid, knl_cursor_t *cursor);

status_t db_delete_from_syspartobject(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id,
                                      uint32 index_id);
status_t db_delete_from_sys_partcolumn(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id);
status_t db_delete_from_systablepart(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id,
                                     uint32 part_id);
status_t db_delete_from_sysindexpart(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id,
                                     uint32 index_id, uint32 part_id);
status_t db_delete_from_shadow_sysindexpart(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id,
                                            uint32 index_id);
status_t db_delete_from_syslobpart(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id,
                                   uint32 column_id, uint32 part_id);
status_t db_write_partindex(knl_session_t *session, knl_cursor_t *cursor, index_t *index);

status_t db_alter_part_index_coalesce(knl_session_t *session, knl_dictionary_t *dc, knl_alindex_def_t *def,
                                      index_t *index);
status_t db_alter_subpart_index_coalesce(knl_session_t *session, knl_dictionary_t *dc, knl_alindex_def_t *def,
    index_t *index);
status_t db_alter_index_coalesce(knl_session_t *session, knl_dictionary_t *dc, index_t *index);
status_t db_fetch_sysindex_row(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id,
                               text_t *index_name, knl_cursor_action_t action, bool32 *is_found);
status_t db_fetch_shadow_indexpart_row(knl_session_t *session, knl_handle_t dc_entity, knl_cursor_t *cursor);
status_t db_fetch_shadow_index_row(knl_session_t *session, knl_handle_t dc_entity, knl_cursor_t *cursor);
status_t db_truncate_table_prepare(knl_session_t *session, knl_dictionary_t *dc, bool32 reuse_storage,
                                   bool32 *is_changed);
status_t heap_segment_prepare(knl_session_t *session, table_t *table, bool32 reuse, seg_op_t op_type);
status_t heap_part_segment_prepare(knl_session_t *session, table_part_t *table_part, bool32 reuse,
                                   seg_op_t op_type);
status_t btree_segment_prepare(knl_session_t *session, index_t *index, bool32 reuse, seg_op_t op_type);
status_t btree_part_segment_prepare(knl_session_t *session, index_part_t *index_part, bool32 reuse,
                                    seg_op_t op_type);
status_t lob_segment_prepare(knl_session_t *session, lob_t *lob, bool32 reuse, seg_op_t op_type);
status_t lob_part_segment_prepare(knl_session_t *session, lob_part_t *lob_part, bool32 reuse, seg_op_t op_type);

status_t db_check_policies_before_delete(knl_session_t *session, const char *table_name, uint32 uid);

status_t db_update_table_increment_start(knl_session_t *session, knl_table_desc_t *desc, uint64 serial_start);
status_t db_altable_auto_increment(knl_session_t *session, knl_dictionary_t *dc, uint64 serial_start);
status_t db_altable_set_all_trig_status(knl_session_t *session, knl_dictionary_t *dc, bool32 enable);
status_t db_altable_apply_constraint(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_altable_add_logical_log(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_altable_drop_logical_log(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_drop_ddm_rule_by_name(knl_session_t *session,  knl_ddm_def_t *def);
status_t db_check_rule_exists_by_name(knl_session_t *session, knl_ddm_def_t *def);
status_t db_altable_enable_nologging(knl_session_t *session, knl_dictionary_t *dc);
status_t db_altable_disable_nologging(knl_session_t *session, knl_dictionary_t *dc);
status_t db_altable_enable_part_nologging(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_altable_disable_part_nologging(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_altable_enable_subpart_nologging(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_altable_disable_subpart_nologging(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);

void db_convert_column_def(knl_column_t *column, uint32 uid, uint32 obj_id, knl_column_def_t *def,
                           knl_column_t *old_column, uint32 id);
status_t db_delete_columns(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 oid);
status_t db_write_sysdep(knl_session_t *session, knl_cursor_t *cursor, object_address_t *depender,
                         object_address_t *ref_obj, uint32 order);
status_t db_write_sysdep_list(knl_session_t *knl_session, object_address_t *depender, galist_t *referenced_list);

status_t db_write_sysddm(knl_session_t *session, knl_ddm_def_t *def);

status_t db_write_sysjob(knl_session_t *session, knl_job_def_t *def);
status_t db_update_sysjob(knl_session_t *session, text_t *user, knl_job_node_t *job, bool32 should_exist);
status_t db_delete_sysjob(knl_session_t *session, text_t *user, int64 jobno, bool32 should_exist);
status_t db_altable_modify_lob(knl_session_t *session, knl_altable_def_t *def);
status_t db_alter_sql_sysmap(knl_session_t *session, knl_sql_map_t *sql_map);
status_t db_delete_sql_sysmap(knl_session_t *session, knl_sql_map_t *sql_map, bool8 *is_exist);
status_t db_delete_sql_map_by_user(knl_session_t *session, uint32 uid);
status_t db_update_sql_map_hash(knl_session_t *session, knl_cursor_t *cursor, uint32 hash_value);

/* db interface for resource manager */
status_t db_create_control_group(knl_session_t *session, knl_rsrc_group_t *group);
status_t db_delete_control_group(knl_session_t *session, text_t *group_name);
status_t db_update_control_group(knl_session_t *session, knl_rsrc_group_t *group);
status_t db_create_rsrc_plan(knl_session_t *session, knl_rsrc_plan_t *plan);
status_t db_delete_rsrc_plan(knl_session_t *session, text_t *plan_name);
status_t db_update_rsrc_plan(knl_session_t *session, knl_rsrc_plan_t *plan);
status_t db_create_rsrc_plan_rule(knl_session_t *session, knl_rsrc_plan_rule_def_t *def);
status_t db_delete_rsrc_plan_rule(knl_session_t *session, text_t *plan_name, text_t *group_name);
status_t db_update_rsrc_plan_rule(knl_session_t *session, knl_rsrc_plan_rule_def_t *def);
status_t db_set_cgroup_mapping(knl_session_t *session, knl_rsrc_group_mapping_t *mapping);

status_t db_init_synonmy_desc(knl_session_t *session, knl_synonym_t *synonym, knl_synonym_def_t *def);
status_t db_write_syssyn(knl_session_t *session, knl_cursor_t *cursor, knl_synonym_t *synonym);
status_t db_write_sysdep(knl_session_t *session, knl_cursor_t *cursor, object_address_t *depender,
                         object_address_t *ref_obj, uint32 order);

status_t db_invalid_cursor_operation(knl_session_t *session, knl_cursor_t *cursor);
status_t db_get_fk_part_no(knl_session_t *session, knl_cursor_t *cursor, index_t *index, knl_handle_t dc_entity,
    ref_cons_t *cons, uint32 *part_no);
status_t db_get_fk_subpart_no(knl_session_t *session, knl_cursor_t *cursor, index_t *index, knl_handle_t dc_entity,
    ref_cons_t *cons, uint32 compart_no, uint32 *subpart_no);
status_t db_drop_shadow_indexpart(knl_session_t *session, uint32 uid, uint32 table_id, bool32 clean_segment);
status_t db_clean_all_shadow_indexes(knl_session_t *session);
status_t db_clean_all_shadow_indexparts(knl_session_t *session, knl_cursor_t *cursor);
status_t db_delete_dist_rules_by_user(knl_session_t *session, uint32 uid);
status_t db_get_storage_desc(knl_session_t *session, knl_storage_desc_t *storage_desc, knl_scn_t org_scn);
status_t db_delete_from_sysstorage(knl_session_t *session, knl_cursor_t *cursor, uint64 orgscn);
status_t db_alter_index_unusable(knl_session_t *session, index_t *index);
status_t db_alter_index_initrans(knl_session_t *session, knl_alindex_def_t *def, index_t *index);
status_t db_alter_index_partition(knl_session_t *session, knl_alindex_def_t *def, knl_dictionary_t *dc,
    index_t *index);
status_t db_alter_index_subpartition(knl_session_t *session, knl_alindex_def_t *def, knl_dictionary_t *dc,
    index_t *index);
status_t db_query_consis_hash_strategy(knl_session_t *session, uint32 *slice_count, uint32 *group_count,
    knl_cursor_t *cursor, bool32 *is_found);
status_t db_altable_drop_subpartition(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def,
    bool32 is_coalesce);
status_t db_drop_subpartition(knl_session_t *session, knl_dictionary_t *dc, table_part_t *subpart);
status_t db_delete_from_sys_tenant(knl_session_t *session, uint32 tid);
status_t db_fill_index_entity(knl_session_t *session, knl_cursor_t *cursor, index_t *index,
    btree_mt_context_t *ctx, mtrl_sort_ctrl_t *sort_ctrl);
status_t db_fill_index_entity_paral(knl_session_t *session, knl_dictionary_t *dc, index_t *index,
    knl_part_locate_t part_loc, uint32 paral_no, bool32 nologging);
void db_force_truncate_table(knl_session_t *session, knl_dictionary_t *dc,
    bool32 reuse_storage, bool32 is_not_recyclebin);
status_t db_fill_multi_indexes_paral(knl_session_t *session, knl_dictionary_t *dc, index_t **indexes,
    uint32 index_cnt, uint32 paral_cnt, knl_part_locate_t part_loc, bool32 nologging);
status_t db_fill_shadow_index_parallel(knl_session_t *session, knl_cursor_t *cursor, knl_dictionary_t *dc,
    knl_part_locate_t part_loc, index_build_mode_t build_mode);
status_t db_rebuild_idxpart_parallel(knl_session_t *session, knl_dictionary_t *dc,
    knl_part_locate_t part_loc, uint32 paral_count);
status_t db_update_nologobj_cnt(knl_session_t *session, bool32 is_add);
status_t db_truncate_sys_table(knl_session_t *session, uint32 table_id);

bool32 is_idx_part_existed(knl_part_locate_t *current_part_loc, knl_parts_locate_t parts_loc, bool32 is_sub);
status_t db_allow_indexpart_rebuild(knl_session_t *session, uint32 spc_id,
    index_part_t *old_part);
status_t db_create_indexes(knl_session_t *session, knl_indexes_def_t *def, knl_dictionary_t *dc);
status_t db_alter_indexpart_rebuild_verify(knl_session_t *session, knl_alindex_def_t *def, uint32 *spc_id,
    index_t *index, int32 index_i);
status_t db_write_syscompress(knl_session_t *session, knl_cursor_t *cursor, uint32 space_id, uint64 org_scn,
    uint32 compress_mode, compress_object_type_t obj_type);
status_t db_delete_from_syscompress(knl_session_t *session, knl_cursor_t *cursor, uint64 org_scn);
status_t db_get_compress_algo(knl_session_t *session, uint8 *compress_mode, uint64 org_scn);
bool32 db_rebuild_get_part(knl_alindex_def_t *def, index_t *index, index_part_t **old_part, int part_i);

status_t db_create_hash_part_index_segment(knl_session_t *session, knl_dictionary_t *dc, uint32 index_id);
status_t db_create_index_segment_of_hash_parts(knl_session_t *session, knl_dictionary_t *dc, table_t *table);
status_t db_create_hash_part_segment(knl_session_t *session, knl_dictionary_t *dc);
status_t db_create_hash_part_heap_segment_impl(knl_session_t *session, table_part_t *table_part,
                                               knl_part_locate_t part_loc);
status_t db_create_hash_lob_part_segment(knl_session_t *session, knl_dictionary_t *dc, uint32 column_idx);

status_t make_column_name_list_str(text_t *txt_column_name, uint32_t column_cnt, galist_t *columns);
status_t fill_ref_info_when_reftab_not_exist(knl_constraint_def_t *def, row_assist_t *ra);
status_t db_invalidate_children_for_update_ref_cons(knl_session_t *session, bool32 is_referenced, table_t *table);

extern table_accessor_t g_heap_acsor;
extern table_accessor_t g_pcr_heap_acsor;
extern table_accessor_t g_temp_heap_acsor;
extern table_accessor_t g_external_table_acsor;
extern table_accessor_t g_invalid_table_acsor;
extern table_accessor_t g_poly_table_acsor;

#define TABLE_ACCESSOR(cursor) (((table_t *)(cursor)->table)->acsor)

#ifdef __cplusplus
}
#endif

#endif
