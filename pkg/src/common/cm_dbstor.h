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
* cm_dbstor.h
*
*
* IDENTIFICATION
* src/common/cm_dbstor.h
*
* -------------------------------------------------------------------------
*/

#ifndef __CM_DBSTOR_H__
#define __CM_DBSTOR_H__

#include "cm_dbs_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DBS_CONFIG_NAME "dbstor_config.ini"
#define DBS_CONFIG_NAME_WITHOUT_SUFFIX "dbstor_config"
#define CSS_MAX_FSNAME_LEN 256
#define CSS_MAX_NAME_LEN 68
#define DBS_DIR_MAX_FILE_NUM 10240
#define DBS_DIR_DEFAULT_FILE_NUM 1024
#define DBS_ADDR_STR_LEN 20
#define DBS_MAX_LINK_NUMS 32
#define FS_SNAP_UUID_LEN 16

typedef struct {
   uint64 offset;
   uint64 length;
   uint64 start_lsn;
} ulog_archive_option_t;

typedef struct {
   uint64 end_lsn;
   uint64 real_len;
} ulog_archive_result_t;

typedef struct {
   char local_ip[DBS_ADDR_STR_LEN];
   char remote_ip[DBS_ADDR_STR_LEN];
} dbs_ip_pairs;

typedef struct {
   char *fsName;
   uint32_t vstorId;
   char *snapName;
   char *buffer;
   char *bufferLen;
} dbs_get_page_from_sf_snap_param;

typedef struct {
   char snapName[CSS_MAX_FSNAME_LEN];
   uint32_t snapshotID;
   uint32_t timepoint;
   uint8_t  snapUUID[FS_SNAP_UUID_LEN];
} snapshot_result_info;

typedef struct {
   uint8_t buf[FS_SNAP_UUID_LEN];
} SNAP_UUID_S;

// libdbstorClient.so
// namespace
typedef int (*create_namespace_t)(char *, NameSpaceAttr *);
typedef int (*open_namespace_t)(char *, NameSpaceAttr *);
typedef int (*set_term_access_mode_for_ns_t)(char *, TermAccessAttr *);
typedef void (*dbs_set_ns_term_handle_t)(NsTermHandle *);
typedef int (*dbs_ns_io_forbidden_t)(char *, bool);
typedef int (*dbs_get_ns_io_forbidden_stat_t)(char *, bool *);

// dbs
typedef int (*dbs_client_set_uuid_lsid_t)(const char *, uint32_t);
typedef int (*dbs_client_lib_init_t)(const char *, char *);
typedef void (*dbs_set_init_mode_t)(uint32_t);
typedef int (*dbs_client_flush_log_t)(void);
typedef int (*dbs_link_down_event_reg_t)(void (*dbs_link_down_exit)(void));
typedef int (*reg_role_info_callback_t)(regCallback);
typedef int (*dbs_init_lock_t)(char *, uint32_t, uint32_t, int32_t *);
typedef int (*dbs_inst_lock_t)(uint32_t, uint32_t);
typedef int (*dbs_inst_unlock_t)(uint32_t, uint32_t);
typedef int (*dbs_inst_unlock_force_t)(uint32_t, uint32_t);
typedef bool (*dbs_check_inst_heart_beat_is_normal_t)(uint32_t);
typedef int (*dbs_file_open_root_t)(char *, object_id_t *);
typedef int (*dbs_file_open_root_by_vstorid_t)(char *, uint32_t, object_id_t *);
typedef int (*dbs_file_create_t)(object_id_t *, char *, uint32_t, object_id_t *);
typedef int (*dbs_file_open_t)(object_id_t *, char *, uint32_t, object_id_t *);
typedef int (*dbs_file_write_t)(object_id_t *, uint64_t, char *, uint32_t);
typedef int (*dbs_file_read_t)(object_id_t *, uint64_t, char *, uint32_t, uint32 *);
typedef int (*dbs_file_remove_t)(object_id_t *, char *);
typedef int (*dbs_clear_cms_name_space_t)(void);
typedef int (*dbs_file_create_by_path_t)(object_id_t *, char *, uint32_t, object_id_t *);
typedef int (*dbs_file_open_by_path_t)(object_id_t *, char *, uint32_t, object_id_t *);
typedef int (*dbs_file_rename_t)(object_id_t *, char *, char *);
typedef int (*dbs_file_get_num_t)(object_id_t *, uint32_t *);
typedef int (*dbs_file_get_list_t)(object_id_t *, void *, uint32_t *);
typedef int (*dbs_file_get_list_detail_t)(object_id_t *, void *, uint32_t *);
typedef int (*dbs_get_file_size_t)(object_id_t *, uint64 *);
typedef int (*dbs_ulog_archive_t)(object_id_t *, object_id_t *, ulog_archive_option_t *, ulog_archive_result_t *);
typedef int (*dbs_get_ip_pairs_t)(dbs_ip_pairs *, uint32_t *);
typedef int (*dbs_create_link_t)(char *, char *);
typedef int (*dbs_check_single_link_t)(char *, char *, uint32_t *);
typedef int (*dbs_query_fs_info_t)(char *, uint32_t, void *);

//pagepool
typedef int (*create_pagepool_t)(char *, PagePoolAttr *, PagePoolId *);
typedef int (*destroy_pagepool_t)(char *, PagePoolAttr *);
typedef int (*open_pagepool_t)(char *, PagePoolAttr *, PagePoolId *);
typedef int (*close_pagepool_t)(PagePoolId *);
typedef int (*dbs_put_page_async_t)(PagePoolId *, DbsPageId, DbsPageOption *, PageValue *, uint32_t);
typedef int (*sync_page_by_part_index_t)(PagePoolId *, uint32_t);
typedef int (*dbs_mput_continue_pages_t)(PagePoolId *, DbsPageId, uint32_t, DbsPageOption *, PageValue *);
typedef int (*dbs_mget_page_t)(PagePoolId *, DbsPageId, uint32_t, DbsPageOption *, PageValue *);
typedef int (*get_pagepool_logic_capacity_t)(PagePoolId *, PagePoolAttr *, uint64_t *);
typedef int (*expand_pagepool_logic_capacity_t)(PagePoolId *, PagePoolAttr *, uint64_t, uint64_t);
typedef int (*rename_pagepool_t)(char *, char *, PagePoolAttr *);

// ulog
typedef int (*create_ulog_t)(char *, UlogAttr *, UlogId *);
typedef int (*destroy_ulog_t)(char *, UlogAttr *);
typedef int (*open_ulog_t)(char *, UlogAttr *, UlogId *);
typedef int (*append_ulog_record_t)(UlogId *, AppendOption *, LogRecord *, AppendResult *);
typedef int (*truncate_ulog_t)(UlogId *, TruncLogOption *, TruncResult*);
typedef int (*read_ulog_record_list_t)(UlogId *, ReadBatchLogOption *, LogRecordList *, ReadResult *);
typedef int (*get_ulog_used_cap_t)(UlogId *, UlogAttr *, LogLsn, uint32_t, uint32_t *);
typedef int (*get_ulog_init_capacity_t)(uint64_t *);

// libdbstor_tool.so
typedef int32_t (*get_curr_log_offset_t)(char*, uint32_t, uint32_t*, uint32_t*, uint64_t*);
typedef int32_t (*get_correct_page_id_t)(uint32_t, uint32_t, uint32_t, uint64_t);

// snapshot
typedef int (*create_fs_snap)(char *, uint32_t, snapshot_result_info *);
typedef int (*delete_fs_snap)(char *, uint32_t, uint32_t, uint32_t, SNAP_UUID_S);

typedef struct st_dbs_interface {
   void *dbs_handle;
   // namespace
   create_namespace_t   create_namespace;
   open_namespace_t open_namespace;
   set_term_access_mode_for_ns_t set_term_access_mode_for_ns;
   dbs_set_ns_term_handle_t dbs_set_ns_term_handle;
   dbs_ns_io_forbidden_t dbs_ns_io_forbidden;
   dbs_get_ns_io_forbidden_stat_t dbs_get_ns_io_forbidden_stat;

   // dbs
   dbs_client_set_uuid_lsid_t dbs_client_set_uuid_lsid;
   dbs_client_lib_init_t dbs_client_lib_init;
   dbs_set_init_mode_t dbs_set_init_mode;
   dbs_client_flush_log_t dbs_client_flush_log;
   reg_role_info_callback_t reg_role_info_callback;
   dbs_link_down_event_reg_t dbs_link_down_event_reg;
   dbs_init_lock_t dbs_init_lock;
   dbs_inst_lock_t dbs_inst_lock;
   dbs_inst_unlock_t dbs_inst_unlock;
   dbs_inst_unlock_force_t dbs_inst_unlock_force;
   dbs_check_inst_heart_beat_is_normal_t dbs_check_inst_heart_beat_is_normal;
   dbs_file_open_root_t dbs_file_open_root;
   dbs_file_open_root_by_vstorid_t dbs_file_open_root_by_vstorid;
   dbs_file_create_t dbs_file_create;
   dbs_file_open_t dbs_file_open;
   dbs_file_write_t dbs_file_write;
   dbs_file_read_t dbs_file_read;
   dbs_file_remove_t dbs_file_remove;
   dbs_clear_cms_name_space_t dbs_clear_cms_name_space;
   dbs_file_create_by_path_t dbs_file_create_by_path;
   dbs_file_open_by_path_t dbs_file_open_by_path;
   dbs_file_rename_t dbs_file_rename;
   dbs_file_get_num_t dbs_file_get_num;
   dbs_file_get_list_t dbs_file_get_list;
   dbs_file_get_list_detail_t dbs_file_get_list_detail;
   dbs_get_file_size_t dbs_get_file_size;
   dbs_ulog_archive_t dbs_ulog_archive;
   dbs_get_ip_pairs_t dbs_get_ip_pairs;
   dbs_create_link_t dbs_create_link;
   dbs_check_single_link_t dbs_check_single_link;
   dbs_query_fs_info_t dbs_query_fs_info;

   // pagepool
   create_pagepool_t create_pagepool;
   destroy_pagepool_t destroy_pagepool;
   open_pagepool_t open_pagepool;
   close_pagepool_t close_pagepool;
   dbs_put_page_async_t dbs_put_page_async;
   sync_page_by_part_index_t sync_page_by_part_index;
   dbs_mput_continue_pages_t dbs_mput_continue_pages;
   dbs_mget_page_t dbs_mget_page;
   get_pagepool_logic_capacity_t get_pagepool_logic_capacity;
   expand_pagepool_logic_capacity_t expand_pagepool_logic_capacity;
   rename_pagepool_t rename_pagepool;

   // ulog
   create_ulog_t create_ulog;
   destroy_ulog_t destroy_ulog;
   open_ulog_t open_ulog;
   append_ulog_record_t append_ulog_record;
   truncate_ulog_t truncate_ulog;
   read_ulog_record_list_t read_ulog_record_list;
   get_ulog_used_cap_t get_ulog_used_cap;
   get_ulog_init_capacity_t get_ulog_init_capacity;

   // snapshot
   create_fs_snap create_fs_snap;
   delete_fs_snap delete_fs_snap;

} dbs_interface_t;

typedef struct st_dbs_tool_interface {
   void *dbs_tool_handle;
   get_curr_log_offset_t get_curr_log_offset;
   get_correct_page_id_t get_correct_page_id;
} dbs_tool_interface_t;

typedef enum {
   CS_FILE_TYPE_DIR = 0,
   CS_FILE_TYPE_FILE,
   CS_FILE_TYPE_BUTT,
} cs_file_type;

typedef struct cm_dbstor_file_info {
   char file_name[CSS_MAX_NAME_LEN];
   cs_file_type type;
   object_id_t handle;
} dbstor_file_info;

typedef struct cm_dbstor_file_info_detail {
   char file_name[CSS_MAX_NAME_LEN];
   cs_file_type type;
   object_id_t handle;
   uint32_t file_size;
   uint32_t mode;
   uint32_t uid;
   uint32_t gid;
   uint64_t mtimeSec;
   uint64_t mtimeNsec;
   uint64_t crtimeSec;
   uint64_t crtimeNsec;
} dbstor_file_info_detail;

dbs_interface_t *dbs_global_handle(void);
dbs_tool_interface_t *dbs_tool_global_handle(void);
status_t dbs_init_lib(void);
status_t dbs_tool_init_lib(void);
void dbs_close_lib(void);
void dbs_tool_close_lib(void);

typedef struct cm_dbstor_fs_info {
   uint64 actual_size;
   uint64 total_capacity;
   uint64 used_size;
   uint32 fs_id;
   uint32 cluster_id;
   uint32 pool_id;
   uint32 grain_size;
   uint32 block_size;
   uint32 work_load_type_id;
   uint8 fs_mode;
   uint8 fs_type;
   uint8 is_gfs;
   uint8 fs_type_verify_switch;
   uint8 fs_status;
   bool is_dedup;
   bool is_compress;
} dbstor_fs_info;

#ifdef __cplusplus
}
#endif

#endif // __CM_DBSTOR_H__