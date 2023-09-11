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
 * knl_archive.h
 *
 *
 * IDENTIFICATION
 * src/kernel/persist/knl_archive.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_ARCHIVE_H__
#define __KNL_ARCHIVE_H__

#include "cm_defs.h"
#include "cm_thread.h"
#include "knl_compress.h"
#include "knl_log.h"
#include "knl_session.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ARCH_DEFAULT_DEST 1
#define ARCH_FAIL_PRINT_THRESHOLD (2 * MICROSECS_PER_MIN)
#define TMP_ARCH_FILE_NAME "arch_file.tmp"
#define ARCH_TRY_CAP_INTERVAL 6
#define ARCH_DEST_PREFIX_LENGTH 9
#define GS_MAX_ARCHIVE_BUFFER_SIZE  (int64)SIZE_M(32) /* 32M */

typedef struct st_arch_file {
    log_file_head_t head;
    char name[GS_FILE_NAME_BUFFER_SIZE];
    int32 handle;
} arch_file_t;

/** LOG_ARCHIVE_DEST_STATE_n value definition  @see e_arch_dest_state */
typedef enum e_arch_dest_state {
    STATE_ENABLE = 0,
    STATE_DEFER = 1,
    STATE_ALTERNATE = 2,
    STATE_DSIABLE = 3
} arch_dest_state_t;

typedef union st_arch_log_id {
    struct {
        uint32 rst_id;
        uint32 asn;
    };
    uint64 arch_log;
} arch_log_id_t;

typedef struct st_arch_log_record_id {
    uint32 rst_id;
    uint32 asn;
    uint64 start_lsn;
    uint64 end_lsn;
    uint64 cur_lsn;
    uint64 offset;
    knl_scn_t first_scn;
} st_arch_log_record_id_t;

typedef struct st_arch_record_time {
    timeval_t start_time;
    timeval_t start_intf_time;
    uint64 used_time;
} st_arch_record_time_t;

typedef enum en_arch_affirm {
    LOG_ARCH_DEFAULT = 0,
    LOG_ARCH_AFFIRM = 1,
    LOG_ARCH_NOAFFIRM = 2
} arch_affirm_t;

typedef enum en_trans_mode {
    LOG_TRANS_MODE_DEFAULT = 0,
    LOG_TRANS_MODE_ARCH = 1,
    LOG_TRANS_MODE_LGWR = 2
} trans_mode_t;

typedef enum en_arch_dest_type {
    LOG_ARCH_DEST_DEFAULT = 0,
    LOG_ARCH_DEST_LOCATION = 1,
    LOG_ARCH_DEST_SERVICE = 2
} arch_dest_type_t;

typedef struct st_arch_service {
    char host[GS_HOST_NAME_BUFFER_SIZE];
    uint16 port;
    uint16 reserved;
} arch_service_t;

typedef enum en_net_trans_mode {
    LOG_NET_TRANS_MODE_DEFAULT = 0,
    LOG_NET_TRANS_MODE_SYNC = 1,
    LOG_NET_TRANS_MODE_ASYNC = 2
} net_trans_mode_t;

typedef enum en_log_sync_mode {
    LOG_SYNC_MODE_DEFAULT = 0,
    LOG_SYNC_MODE_FIRST = 1,
    LOG_SYNC_MODE_ANY = 2,
    LOG_SYNC_MODE_INVALID = 3,
} log_sync_mode_t;

typedef enum en_role_valid {
    VALID_FOR_DEFAULT = 0,
    VALID_FOR_ALL_ROLES = 1,
    VALID_FOR_PRIMARY_ROLE = 2,
    VALID_FOR_STANDBY_ROLE = 3
} role_valid_t;

typedef struct st_force_archive_param {
    bool32 force_archive;
    bool32 force_switch;
    uint64 end_lsn;
} force_archive_param_t;
typedef struct st_archived_info {
    uint32 recid;
    uint32 dest_id;
    uint32 rst_id;
    uint32 asn;
    int64 stamp;
    uint64 start_lsn;
    uint64 end_lsn;
    int32 blocks;
    int32 block_size;
    knl_scn_t first;
    knl_scn_t last;
    int64 real_size;
    uint8 reserve[24];
    char name[GS_FILE_NAME_BUFFER_SIZE];
} arch_ctrl_t;

typedef struct st_arch_clean_attr {
    uint64 hwm_size;
    uint64 opt_size;
    log_point_t min_rcy_point;
    log_point_t backup_rcy_point;
} arch_clean_attr_t;

typedef struct st_arch_attr {
    arch_affirm_t affirm_mode;
    trans_mode_t trans_mode;
    arch_dest_type_t dest_mode;
    arch_service_t service;
    char local_path[GS_MAX_FILE_NAME_LEN];
    net_trans_mode_t net_mode;
    role_valid_t role_valid;
    bool32 used;
    bool32 enable;
    char local_host[GS_HOST_NAME_BUFFER_SIZE];
    compress_algo_e compress_alg;
} arch_attr_t;

typedef struct st_log_sync_param {
    log_sync_mode_t mode_type;
    uint32 sync_num;
} log_sync_param_t;

typedef struct st_arch_proc_context {
    spinlock_t record_lock;  // lock for record archive info
    uint32 arch_id;
    bool32 enabled;
    thread_t thread;
    knl_session_t *session;
    char arch_dest[GS_FILE_NAME_BUFFER_SIZE];
    arch_dest_state_t dest_status;
    uint32 last_file_id;
    uint32 next_file_id;
    bool32 alarmed;
    bool32 need_file_archive;
    bool32 is_force_archive;
    arch_log_id_t last_archived_log;
    st_arch_log_record_id_t last_archived_log_record;
    st_arch_record_time_t   arch_record_time;
    int64 curr_arch_size;
    aligned_buf_t arch_buf;
    date_t fail_time;
    knl_compress_t cmp_ctx;
    int64 redo_log_filesize;
    knl_scn_t first_scn;
} arch_proc_context_t;

typedef struct st_archive_ctx {
    spinlock_t dest_lock;
    spinlock_t record_lock;  // lock for record archive info
    bool32 is_archive;
    bool32 initialized;
    char arch_format[GS_FILE_NAME_BUFFER_SIZE];
    arch_proc_context_t arch_proc[GS_MAX_ARCH_DEST];
    uint16 arch_dest_num;
    uint16 reserved;
    uint32 archived_recid;
    uint32 dtc_archived_recid[64];
    log_point_t *rcy_point;
    uint32 arch_trace;
    uint64 total_bytes;    /* archived total bytes of current archive file */
    uint64 begin_redo_bytes; /* flushed redo bytes when current file begin to archive */
    uint64 prev_redo_bytes;
    volatile bool32 arch_dest_state_changed;
    uint32 inst_id;
    force_archive_param_t force_archive_param;
    uint64 arch_file_size;
    uint64 arch_size;
    uint64 arch_time;
} arch_context_t;

typedef enum en_arch_dest_sync {
    ARCH_DEST_SYNCHRONIZED = 0,
    ARCH_DEST_NO_SYNCHRONIZED = 1,
    ARCH_DEST_UNKNOWN = 2,
} arch_dest_sync_t;

status_t arch_init(knl_session_t *session);
status_t arch_start(knl_session_t *session);
void arch_close(knl_session_t *session);
void arch_last_archived_log(knl_session_t *session, uint32 dest_pos, arch_log_id_t *arch_log_out);
void arch_set_archive_log_name(knl_session_t *session, uint32 rst_id, uint32 asn,
                               uint32 dest_pos, char *buf, uint32 buf_size, uint32 node_id);
status_t arch_record_archinfo(knl_session_t *session, uint32 dest_pos, const char *file_name,
                              log_file_head_t *log_head, uint32 node_id);
status_t ctarch_do_arch_info_record(knl_session_t *ct_se, uint32 arch_dest, const char *arch_file_name,
    log_file_head_t *log_head);
status_t arch_set_dest(arch_context_t *arch_ctx, char *value, uint32 pos);
status_t arch_set_dest_state(knl_session_t *session, const char *value, uint32 cur_pos, bool32 notify);
status_t arch_set_format(arch_context_t *arch_ctx, char *value);
status_t arch_set_format_with_lsn(arch_context_t *arch_ctx, char *value);
status_t arch_set_max_processes(knl_session_t *session, char *value);
status_t arch_set_min_succeed(arch_context_t *ctx, char *value);
status_t arch_set_trace(char *value, uint32 *arch_trace);

void arch_get_last_rstid_asn(knl_session_t *session, uint32 *rst_id, uint32 *asn);
char *arch_get_dest_type(knl_session_t *session, uint32 id, arch_attr_t *attr, bool32 *is_primary);
void arch_get_dest_path(knl_session_t *session, uint32 id, arch_attr_t *arch_attr, char *path, uint32 path_size);
char *arch_get_sync_status(knl_session_t *session, uint32 id, arch_attr_t *arch_attr, arch_dest_sync_t *sync_type);
char *arch_get_dest_sync(const arch_dest_sync_t *sync_type);

status_t arch_force_clean(knl_session_t *session, knl_alterdb_archivelog_t *def);

void arch_reset_file_id(knl_session_t *session, uint32 dest_pos);
bool32 arch_get_archived_log_name(knl_session_t *session, uint32 rst_id, uint32 asn, uint32 dest_pos, char *buf,
                                  uint32 buf_size, uint32 node_id);
bool32 arch_archive_log_recorded(knl_session_t *session, uint32 rst_id, uint32 asn, uint32 dest_pos, uint32 node_id);
bool32 arch_dest_state_disabled(knl_session_t *session, uint32 inx);
void arch_set_deststate_disabled(knl_session_t *session, uint32 inx);
status_t arch_regist_archive(knl_session_t *session, const char *name);
status_t arch_try_regist_archive(knl_session_t *session, uint32 rst_id, uint32 *asn);
bool32 arch_dest_state_match_role(knl_session_t *session, arch_attr_t *arch_attr);
status_t arch_check_dest_service(void *attr, arch_attr_t *arch_attr, uint32 slot);
bool32 arch_has_valid_arch_dest(knl_session_t *session);
void arch_reset_archfile(knl_session_t *session, uint32 replay_asn);
bool32 arch_log_not_archived(knl_session_t *session, uint32 req_rstid, uint32 req_asn);
void arch_get_bind_host(knl_session_t *session, const char *srv_host, char *bind_host, uint32 buf_size);
void arch_get_files_num(knl_session_t *session, uint32 dest_id, uint32 node_id, uint32 *arch_num);

arch_ctrl_t *arch_get_archived_log_info(knl_session_t *session, uint32 rst_id, uint32 asn, uint32 dest_pos,
                                        uint32 node_id);
status_t arch_archive_file(knl_session_t *session, aligned_buf_t buf, log_file_t *logfile,
    const char *arch_file_name, knl_compress_t *compress_ctx);
arch_ctrl_t *arch_get_last_log(knl_session_t *session);
arch_ctrl_t *arch_dtc_get_last_log(knl_session_t *session, uint32 inst_id);
status_t arch_process_existed_archfile(knl_session_t *session, const char *arch_name,
    log_file_head_t head, bool32 *ignore_data);
status_t arch_redo_alloc_resource(knl_session_t *session, aligned_buf_t *log_buf, aligned_buf_t *arch_buf,
    knl_compress_t *compress_ctx);
status_t arch_archive_redo(knl_session_t *session, log_file_t *logfile, aligned_buf_t arch_buf,
    aligned_buf_t log_buf, bool32 *is_continue, knl_compress_t *compress_ctx);
status_t arch_try_arch_redo(knl_session_t *session, uint32 *max_asn);
status_t ctarch_do_arch_log(knl_session_t *ct_se, uint32 rstid, uint32 asn);
int64 ctarch_get_arch_ctrl_size(arch_ctrl_t *arch_ctrl);
bool32 ctarch_check_cmpr(arch_ctrl_t *arch_ctrl);

void arch_init_arch_ctrl(knl_session_t *session, arch_ctrl_t *arch_ctrl, uint32 recid, uint32 dest_id,
    const char *file_name, log_file_head_t *log_head);
uint32 arch_get_arch_start(knl_session_t *session, uint32 node_id);
uint32 arch_get_arch_end(knl_session_t *session, uint32 node_id);
void arch_set_arch_start(knl_session_t *session, uint32 start, uint32 node_id);
void arch_set_arch_end(knl_session_t *session, uint32 end, uint32 node_id);
void arch_init_arch_files_size(knl_session_t *session, uint32 dest_id);

void arch_record_arch_ctrl(arch_ctrl_t *arch_ctrl, knl_session_t *session, uint32 dest_id, const char *file_name,
                           log_file_head_t *log_head, int64 real_file_size);
status_t arch_lsn_asn_convert(knl_session_t *session, uint64 lsn, uint32 *asn);
status_t arch_switch_archfile_trigger(knl_session_t *session, bool32 wait);
status_t arch_force_archive_trigger(knl_session_t *session, uint64 end_lsn, bool32 wait);
void arch_set_archive_log_name_with_lsn(knl_session_t *session, uint32 rst_id, uint32 asn,
                                        uint32 dest_pos, char *buf, uint32 buf_size,
                                        uint32 node_id, uint64 start, uint64 end);
bool32 arch_need_archive_dbstor(arch_proc_context_t *proc_ctx, log_context_t *redo_ctx);
arch_ctrl_t *arch_get_archived_log_info_for_recovery(knl_session_t *session, uint32 rst_id, uint32 asn,
                                                     uint32 dest_pos, uint64 lsn, uint32 node_id);
status_t arch_find_archive_log_name(knl_session_t *session, uint32 rst_id, uint32 node_id,
                                    uint64 lsn, char *buf, uint32 buf_size, uint64* out_lsn, uint32* out_asn);
status_t arch_find_archive_asn_log_name(knl_session_t *session, uint32 rst_id, uint32 node_id,
                                        uint32 arch_asn, char *buf, uint32 buf_size);
status_t arch_find_first_archfile_rst(knl_session_t *session, uint32 rst_id, uint32 node_id,
                                      char *buf, uint32 buf_size, uint32 *out_asn);
status_t arch_read_file(knl_session_t *session, char *file_name, int64 head_size, uint64 *out_lsn,
                        uint32 node_id, arch_proc_context_t *proc_ctx);
void arch_set_process_alarmed(arch_proc_context_t *proc_ctx, char *arch_file_name, status_t arch_ret);
status_t arch_force_archive_file(knl_session_t *session, uint32 node_id, int32 block_size,
                                 device_type_t type, int32 handle);
void arch_dbstor_do_archive(knl_session_t *session, arch_proc_context_t *proc_ctx);
status_t arch_get_tmp_file_last_lsn(char *buf, int32 size_read, uint64 *lsn, uint32 *data_size);
void arch_set_first_scn(void *buf, knl_scn_t *scn);
status_t arch_flush_head(device_type_t arch_file_type, const char *dst_name, arch_proc_context_t *proc_ctx,
                         log_file_t *file, log_file_head_t *head);
bool32 arch_can_be_cleaned(arch_ctrl_t *arch_ctrl, log_point_t *rcy_point, log_point_t *backup_rcy,
                           knl_alterdb_archivelog_t *def);
status_t arch_check_log_valid(int32 data_size, char *buf);
bool32 arch_need_print_error(knl_session_t *session, arch_proc_context_t *proc_ctx);
status_t arch_dbstor_archive_file(const char *src_name, char *arch_file_name, log_file_t *logfile,
                                  log_file_head_t *head, arch_proc_context_t *proc_ctx);
void arch_set_force_endlsn(bool32 force_archive, arch_proc_context_t *proc_ctx, uint64 *end_lsn);
status_t arch_check_bak_proc_status(knl_session_t *session);
void wait_archive_finished(knl_session_t *session);
void arch_wake_force_thread(arch_proc_context_t *proc_ctx);
void arch_dbstor_archive(arch_proc_context_t *proc_ctx);

status_t clean_arch_file(arch_ctrl_t *arch_ctrl, uint32 archived_start, uint32 archived_end,
    log_point_t *rcy_point, log_point_t *backup_rcy);
status_t arch_clean_arch_files(knl_session_t *session, arch_proc_context_t *proc_ctx,
    knl_alterdb_archivelog_t *def, arch_clean_attr_t clean_attr);
status_t arch_do_real_clean(knl_session_t *session, arch_proc_context_t *proc_ctx, log_point_t *rcy_point,
    log_point_t *backup_rcy, uint64 target_size, knl_alterdb_archivelog_t *def);
status_t arch_write_file(const char *src_name, const char *dst_name, device_type_t arch_file_type,
    log_file_t *logfile, arch_proc_context_t *proc_ctx, uint64 start_lsn_input, uint64 end_lsn);
status_t arch_create_open_file(arch_proc_context_t *proc_ctx, const char *file_name,
    device_type_t arch_file_type, int32 *dst_file);
#ifdef __cplusplus
}
#endif

#endif
