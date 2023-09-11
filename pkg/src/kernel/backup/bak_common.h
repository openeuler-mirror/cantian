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
 * bak_common.h
 *
 *
 * IDENTIFICATION
 * src/kernel/backup/bak_common.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __BAK_COMMON_H__
#define __BAK_COMMON_H__

#include "cs_pipe.h"
#include "cs_uds.h"
#include "cm_encrypt.h"
#include "knl_compress.h"
#include "knl_session.h"
#include "knl_log.h"
#include "knl_ckpt.h"
#include "knl_db_ctrl.h"
#include "openssl/evp.h"
#include "knl_page.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 1. lock database, prevent alter system(add log file/datafile)
 * 2. full checkpoint  ---ckpt_do_full_ckpt
 * 3. prevent checkpoint
 * 4. switch log file, record logfile sequence no, prevent recycle rcy log file
 * 6. copy datafile
 * 7. copy logfile from rcy to lry
 * 8. allow recycle logfile
 * 8. allow checkpoint
 * 9. unlock database
 */

#define BAK_LOG_SLEEP_TIME        100 // 100ms
#define BAK_IS_TABLESPCE_RESTORE(bak) ((bak)->spc_name[0] != '\0')
#define DEFAULT_BAKCUPFILE_FORMAT "%s/backup/%llu"
#define DEFAULT_TAG_FORMAT        "%llu_%llu"
#define BAK_SUN_PATH_FORMAT       "%s/protect/%s.sock"
#define BAK_AGENT_PROTOCOL        (uint8)1
#define BAK_MAX_FILE_NUM          (2048 * DATAFILE_MAX_BLOCK_NUM)
#define BAK_MAX_INCR_NUM          10000
#define BAK_MAX_SECTION_THRESHOLD (SIZE_T(32))
#define BAK_MIN_SECTION_THRESHOLD ((uint64)SIZE_M(128))
#define BAK_VERSION_MAJOR         2
#define BAK_VERSION_MIN           1
#define BAK_VERSION_MAGIC         0
#define BAK_VERSION_MIN_WITH_ENCRYPTION   2
#define BAK_COMMON_PROC           0
#define BAK_LOG_COMMON_PROC       1
#define BAK_DEFAULT_PARALLELISM   4
#define BAK_SECTION_SIZE_RATIO    ((double)(1.2))
#define BAK_DEFAULT_GCM_IV_LENGTH 12
#define BAK_BUILD_INIT_RETRY_TIME  0
#define BAK_BUILD_CTRL_SEND_TIME   2
#define BAK_BUILD_CTRL_FILE_INDEX  1
#define PRIMARY_IS_BUILDING(ctx) (BAK_IS_BUILDING(ctx) || !BAK_NOT_WORK(ctx))
#define BAK_IS_BUILDING(ctx) ((ctx)->bak.is_building)
#define BAK_NOT_WORK(ctx) ((ctx)->bak_condition == NOT_RUNNING)
#define BAK_IS_RUNNING(ctx) ((ctx)->bak_condition == RUNNING)
#define BAK_IS_KEEP_ALIVE(ctx) ((ctx)->bak_condition == KEEP_ALIVE)
#define BAK_IS_FULL_BUILDING(bak) ((bak)->is_building && (bak)->record.attr.level == 0)
#define BAK_IS_UDS_DEVICE(bak)    ((bak)->record.device == DEVICE_UDS)
#define BAK_FILE_NEED_PUNCH(df)   (DATAFILE_IS_COMPRESS(df) || DATAFILE_IS_PUNCHED(df))
#define BACKUP_STREAM_BUFSIZE(session, bak) (BACKUP_BUFFER_SIZE(bak) - PAGE_GROUP_COUNT * DEFAULT_PAGE_SIZE(session))
#define BAK_HEAD_STRUCT_SIZE      SIZE_K(8)
#define BAK_HEAD_UNUSED_SIZE 2056
#define BAK_STREAM_BUFFER_NUM     2
#define BUILD_SINGLE_THREAD       1
#define BUILD_DEFAULT_PARALLELISM 1
#define BAK_IS_STREAM_READING(ctx) (BAK_IS_UDS_DEVICE(&((ctx)->bak)) || BAK_IS_BUILDING(ctx))
#define BAK_PARAL_LOG_PROC_NUM    3
#define BAK_PARAL_DATA_START_POS  2
#define BAK_DTC_LSN_LENGTH (782)
#define BAK_IS_DBSOTR(bak) (((bak_t *)(bak))->record.data_type == DATA_TYPE_DBSTOR)
#define BAK_IS_DBSTOR_BY_TYPE(type) ((type) == DATA_TYPE_DBSTOR)

#define CT_SUCCESS 0
#define CT_ERROR -1
#define CT_MAX_NAME_LEN (uint32)64
#define CT_NAME_BUFFER_SIZE (uint32)CM_ALIGN4(CT_MAX_NAME_LEN + 1)
#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

/*
 * backup/restore
 * -------------------------------------------------
 * |CTRL|          DATA          |  LOG       |HEAD|
 * --------------------------------------------------
 * 0    4%                      84%         98%    99%
 *
 * full build
 * -------------------------------------------------------
 * |PARAM|CTRL|          DATA          |  LOG       |HEAD|
 * -------------------------------------------------------
 * 0    1%    5%                      85%         99%   100%
 */
#define BAK_PARAM_WEIGHT 1
#define BAK_HEAD_WEIGHT 1
#define BAK_CTRL_WEIGHT 4
#define BAK_DATE_WEIGHT 80
#define BAK_LOG_WEIGHT  14

// for uds backup & resotre
typedef enum en_bak_package_type {
    BAK_PKG_START = 1,
    BAK_PKG_SET_START = 2,
    BAK_PKG_FILE_START = 3,
    BAK_PKG_ACK = 4,
    BAK_PKG_DATA = 5,
    BAK_PKG_FILE_END = 6,
    BAK_PKG_SET_END = 7,
    BAK_PKG_END = 8,
    BAK_PKG_ERROR = 9,
} bak_package_type_t;

typedef struct st_bak_agent_head {
    uint8 ver;
    uint8 cmd;
    uint16 flags;
    uint32 len;
    uint32 serial_number;
    uint32 reserved;
} bak_agent_head_t;

#define BAK_MSG_TYPE_PARAM (uint32)0  // for build, send config param
#define BAK_MSG_TYPE_CTRL  (uint32)1
#define BAK_MSG_TYPE_DATA  (uint32)2
#define BAK_MSG_TYPE_ARCH  (uint32)3
#define BAK_MSG_TYPE_LOG   (uint32)4
#define BAK_MSG_TYPE_HEAD  (uint32)5

typedef struct st_bak_start_msg {
    uint32 type;
    uint32 file_id;
    uint32 frag_id;
    uint32 curr_file_index;
    char policy[GS_BACKUP_PARAM_SIZE];
    char path[GS_FILE_NAME_BUFFER_SIZE];
} bak_start_msg_t;

typedef struct st_bak_read_cursor {
    spinlock_t lock;
    uint64 offset;
    uint64 read_size;
    uint64 file_size;

    uint32 block_id;
    uint32 file_id;
    uint32 file_type;
    uint32 curr_thread;
} bak_read_cursor_t;

typedef struct st_bak_block_head {
    uint32 file_id;
    uint32 origin_size;

    uint32 block_size;
    uint32 read_size;
    uint64 offset;
    uint32 block_id;
    uint32 checksum;
    uint64 magic_num;
} bak_block_head_t;

typedef struct st_bak_block_tail {
    uint32 block_id;
    uint32 magic_num;
} bak_block_tail_t;

typedef struct st_bak_stream_buf {
    spinlock_t lock;
    uint32 buf_size;
    uint16 wid;  // buffer id for disk data memcpy
    uint16 fid;  // buffer id for send or recieve with UDS
    uint32 curr_block_id;
    uint64 read_offset;
    uint64 bakfile_size;

    uint32 data_size[BAK_STREAM_BUFFER_NUM];
    aligned_buf_t bufs[BAK_STREAM_BUFFER_NUM];
} bak_stream_buf_t;

typedef struct st_rst_stream_buf {
    spinlock_t lock;
    uint32 buf_size;
    uint16 wid;  // buffer id for disk data memcpy
    uint16 fid;  // buffer id for send or recieve with UDS
    uint32 prev_block;
    uint32 curr_block_offset;
    bool32 is_eof;
    uint64 curr_file_tail;
    uint64 base_filesize;

    uint32 usable_size[BAK_STREAM_BUFFER_NUM];
    uint32 recv_size[BAK_STREAM_BUFFER_NUM];
    aligned_buf_t bufs[BAK_STREAM_BUFFER_NUM];
} rst_stream_buf_t;

typedef enum en_bak_file_type {
    BACKUP_CTRL_FILE = 0,
    BACKUP_DATA_FILE = 1,
    BACKUP_LOG_FILE = 2,
    BACKUP_ARCH_FILE = 3,
    BACKUP_HEAD_FILE = 4,
} bak_file_type_t;

typedef enum en_bak_status {
    BACKUP_SUCCESS = 0,
    BACKUP_PROCESSING = 1,
    BACKUP_FAILED = 2,
} bak_status_t;

typedef struct st_rst_file_info {
    rst_file_type_t file_type;
    uint32 file_id;
    bool32 exist_repair_file;
    log_point_t rcy_point;
} rst_file_info_t;

typedef struct st_bak_dependence {
    backup_device_t device;
    char policy[GS_BACKUP_PARAM_SIZE];
    char file_dest[GS_FILE_NAME_BUFFER_SIZE];
} bak_dependence_t;

typedef struct st_bak_version {
    uint16 major_ver;
    uint16 min_ver;
    uint32 magic;
} bak_version_t;

typedef struct st_bak_attr {
    char tag[GS_NAME_BUFFER_SIZE];
    uint64 base_lsn;  // for incremental backup
    char base_tag[GS_NAME_BUFFER_SIZE];
    backup_type_t backup_type;
    uint32 level;
    compress_algo_e compress;
    uint16 head_checksum;
    uint16 file_checksum;
    char compress_func[GS_NAME_BUFFER_SIZE];
    uint32 base_buffer_size;
    char db_version[GS_DB_NAME_LEN];
} bak_attr_t;

typedef struct st_bak_ctrlinfo {
    log_point_t rcy_point;
    log_point_t lrp_point;
    log_point_t dtc_rcy_point[GS_MAX_INSTANCES];
    log_point_t dtc_lrp_point[GS_MAX_INSTANCES];
    knl_scn_t scn;
    uint64 lsn;
    uint64 max_rcy_lsn;
} bak_ctrlinfo_t;

typedef struct st_bak_encrypt {
    encrypt_algorithm_t encrypt_alg;
    char salt[GS_KDF2SALTSIZE];
} bak_encrypt_t;

typedef struct st_bak_head {
    bak_version_t version;
    bak_attr_t attr;
    bak_ctrlinfo_t ctrlinfo;

    uint32 file_count;
    uint32 depend_num;

    char control_files[GS_MAX_CONFIG_LINE_SIZE];
    uint64 start_time;
    uint64 completion_time;

    // encryption version add
    char sys_pwd[GS_PASSWORD_BUFFER_SIZE];
    bak_encrypt_t encrypt_info;
    uint32 log_fisrt_slot; // first log slot after restore in raft mode

    // database info
    uint32 db_id;
    time_t db_init_time;
    repl_role_t db_role;
    char db_name[GS_DB_NAME_LEN];
    char db_version[GS_DB_NAME_LEN];
    uint32 df_struc_version;
    uint32 max_buffer_size;
    uint64 ddl_pitr_lsn;

    char unused[BAK_HEAD_UNUSED_SIZE];  // unused bytes
} bak_head_t;

typedef struct st_bak_old_version_head {
    bak_version_t version;
    bak_attr_t attr;
    bak_ctrlinfo_t ctrlinfo;

    uint32 file_count;
    uint32 depend_num;

    char control_files[GS_MAX_CONFIG_LINE_SIZE];
    uint64 start_time;
    uint64 completion_time;

    // encryption version add
    char sys_pwd[GS_PASSWORD_BUFFER_SIZE];
    bak_encrypt_t encrypt_info;
    uint32 log_fisrt_slot;  // first log slot after restore in raft mode
    uint32 unused;
} bak_old_version_head_t;

typedef struct st_bak_local {
    char name[GS_FILE_NAME_BUFFER_SIZE];  // backup file name
    int32 handle;                         // backup file handle
    int64 size;                           // uncomprss backup file size
    device_type_t type;
} bak_local_t;

typedef struct st_bak_ctrl {
    char name[GS_FILE_NAME_BUFFER_SIZE];  // database file name
    volatile uint64 offset;               // database file read/write pos
    int32 handle;                         // database file handle
    device_type_t type;
    bool32 arch_compressed;
} bak_ctrl_t;

typedef enum en_bak_task_type {
    BAK_INVALID_TASK = 0,
    BAK_BACKUP_TASK = 1,
    BAK_RESTORE_TASK = 2,
    BAK_EXTEND_TASK = 3,
    BAK_STREAM_BACKUP_TASK = 4,
    BAK_STREAM_RESTORE_TASK = 5,
    BAK_BUILD_BACKUP_TASK = 6,
    BAK_BUILD_RESTORE_TASK = 7,
} bak_task_t;

typedef struct st_bak_assignment {
    bak_file_type_t type;
    bak_task_t task;
    uint32 file_id;
    uint32 sec_id;
    bool32 is_section;
    uint32 log_block_size;
    uint32 arch_id;
    uint32 bak_index;
    uint32 file_hwm_start;
    uint64 file_size;   /* data end pos */
    uint64 fill_offset; /* fill datafile during restore */

    uint64 start;
    uint64 end;
    uint64 section_start;
    uint64 section_end;
    uint32 log_asn;

    // file type in paral log backup up
    bool32 is_paral_log_backup;

    bak_local_t bak_file;
} bak_assignment_t;

typedef struct st_bak_encrypt_ctx_t {
    EVP_CIPHER_CTX *ctx;
    aligned_buf_t encrypt_buf;
} bak_encrypt_ctx_t;

typedef struct st_bak_process_stat {
    uint64 read_size;
    date_t read_time;
    uint64 encode_size;
    date_t encode_time;  // compress/decompress, encrypt/decrypt
    uint64 write_size;
    date_t write_time;
} bak_process_stat_t;

typedef struct st_bak_table_compress_ctx {
    aligned_buf_t read_buf;
    aligned_buf_t unzip_buf;
    aligned_buf_t zip_buf;
} bak_table_compress_ctx_t;

typedef struct st_bak_process {
    thread_t thread;
    knl_session_t *session;
    uint32 proc_id;
    aligned_buf_t backup_buf;
    char *fill_buf;  // for fill gap or extend file
    knl_compress_t compress_ctx;
    bak_encrypt_ctx_t encrypt_ctx;
    bak_table_compress_ctx_t table_compress_ctx;

    bak_assignment_t assign_ctrl;  // modify
    bak_ctrl_t ctrl;
    volatile int32 write_size;
    volatile int32 read_size;     // from src_offset
    volatile int32 left_size;     // left size of backup_buf
    volatile uint64 curr_offset;  // current read offset in restore
    volatile uint64 uncompressed_offset; // current read uncompressed offset in disk restore
    volatile bool32 is_free;

    char datafile_name[GS_MAX_DATA_FILES][GS_FILE_NAME_BUFFER_SIZE];
    device_type_t file_type[GS_MAX_DATA_FILES];
    int32 datafiles[GS_MAX_DATA_FILES];
    int64 datafile_size[GS_MAX_DATA_FILES];
    uint32 datafile_version[GS_MAX_DATA_FILES];
    char logfile_name[GS_MAX_LOG_FILES][GS_FILE_NAME_BUFFER_SIZE];
    device_type_t log_type[GS_MAX_LOG_FILES];
    bak_process_stat_t stat;
} bak_process_t;

typedef struct st_bak_remote {
    uint32 serial_number;
    uint32 remain_data_size;

    // for uds
    uds_link_t uds_link;

    // for build
    cs_pipe_t send_pipe;
    cs_pipe_t *pipe;
    cs_packet_t *recv_pack;
    cs_packet_t *send_pack;
} bak_remote_t;

typedef struct st_bak_error {
    spinlock_t err_lock;
    int32 err_code;
    char err_msg[GS_MESSAGE_BUFFER_SIZE];
} bak_error_t;

typedef struct st_bak_progress {
    spinlock_t lock;
    spinlock_t update_lock;
    bak_stage_t stage;
    int32 base_rate;
    int32 weight;
    uint64 data_size;
    uint64 processed_size;
    build_progress_t build_progress;
} bak_progress_t;

typedef struct st_bak_buf {
    char *buf;
    volatile uint32 buf_size;
    volatile uint32 offset;
} bak_buf_t;

typedef struct st_bak_file {
    bak_file_type_t type;
    uint32 id;
    uint32 sec_id;
    uint32 reserved;
    uint64 start_lsn;
    uint64 end_lsn;
    uint64 size;
    uint64 sec_start;
    uint64 sec_end;
    char spc_name[GS_NAME_BUFFER_SIZE];
    unsigned char gcm_iv[BAK_DEFAULT_GCM_IV_LENGTH];
    char gcm_tag[EVP_GCM_TLS_TAG_LEN];
    uint32 inst_id;
    uint32 rst_id;
    char unused[8];  // reserved field
} bak_file_t;

typedef struct st_bak_stat {
    atomic_t reads;
    atomic_t writes;
} bak_stat_t;

typedef struct st_bak_record {
    bak_attr_t attr;
    bool32 data_only;
    bool32 log_only;
    bool32 is_increment;  // incremental build
    bool32 is_repair;     // repair build

    volatile bak_status_t status;
    backup_device_t device;
    backup_data_type_t data_type;
    char path[GS_FILE_NAME_BUFFER_SIZE];
    char policy[GS_BACKUP_PARAM_SIZE];

    bak_ctrlinfo_t ctrlinfo;
    knl_scn_t finish_scn;
    uint64 start_time;
    uint64 completion_time;
} bak_record_t;

typedef struct st_arch_bak_status {
    bool32 bak_done[BAK_MAX_FILE_NUM];
    uint32 start_asn;
} arch_bak_status_t;

typedef struct st_build_analyse_item {
    page_id_t *page_id;
    struct st_build_analyse_item *next;
} build_analyse_item_t;

typedef struct st_build_analyse_bucket {
    uint32 count;
    build_analyse_item_t *first;
} build_analyse_bucket_t;

typedef struct st_bak_datafile {
    char name[GS_FILE_NAME_BUFFER_SIZE];
    uint64 file_size;
    uint32 hwm_start;
    uint32 id;
    uint32 type;
    uint32 sec_num;
} bak_datafile_t;

typedef struct st_bak_device {
    uint32 sec_number;
    bak_datafile_t datafile[BAK_MAX_FILE_NUM];
} bak_device_t;

typedef struct st_bak_reform_check {
    void *view;
    thread_t thread;
    bool8 running;
    bool8 is_reforming;
} bak_reform_check_t;

typedef struct st_bak {
    struct st_knl_instance *kernel;
    bool32 restore;      // current is restore or backup
    bool32 is_building;  // current is build
    bak_record_t record;
    volatile bool32 build_stopped;  // used for build is stopped by command
    volatile bool32 failed;
    volatile bool32 need_retry;  // used for send/receive failed : need to try again to rebuild
    volatile bool32 is_first_link; // used for recording : break-point building has occured
    volatile bool32 need_check; // used for start_stage check : if break-point at the end of the file
    uint32 build_retry_time;
    char peer_host[GS_HOST_NAME_BUFFER_SIZE];
    char *ctrl_data_buf;
    bak_error_t error_info;
    bak_progress_t progress;
    char *compress_buf;
    knl_compress_t compress_ctx;
    bak_buf_t send_buf;
    aligned_buf_t align_buf;
    char *backup_buf;
    char *ctrl_backup_buf;
    char *ctrl_backup_bak_buf;
    char spc_name[GS_NAME_BUFFER_SIZE];
    knl_backup_targetinfo_t target_info;
    bool32 exclude_spcs[GS_MAX_SPACES];
    bool32 include_spcs[GS_MAX_SPACES];
    uint32 backup_buf_size;

    // for head
    uint32 file_count;
    uint32 depend_num;
    bak_file_t files[BAK_MAX_FILE_NUM];
    bak_dependence_t *depends;

    arch_bak_status_t arch_stat;
    uint64 backup_size;
    // for disk
    bak_local_t local;
    uint32 proc_count;

    // for paral log bak
    uint32 backup_log_prealloc;
    uint32 log_proc_count;
    bak_device_t device;
    bool32 paral_log_bak_complete;
    uint32 paral_log_bak_number;
    uint32 paral_last_asn;
    bool32 arch_is_lost;
    bak_local_t log_local;
    bool32 log_proc_is_ready;

    // for agent
    bak_remote_t remote;  // for build
    volatile bool32 head_is_built;

    // for backup
    uint64 recid;
    bool32 cumulative;
    uint32 curr_file_index;
    uint64 section_threshold;
    uint64 max_lrp_lsn;

    // for restore
    bool32 restored;  // has performed restore database
    uint32 log_first_slot;
    uint32 curr_id;
    volatile uint32 curr_arch_id;
    volatile bool32 ctrlfile_completed;
    volatile bool32 logfiles_created;
    bool32 is_noparal_version;  // backupset can not use paraller restore
    thread_t restore_thread;
    uint64 lfn; // for repair page using backup, the replay end point lfn
    rst_file_info_t rst_file;
    uint64 ddl_pitr_lsn;
    // for stat
    bak_stat_t stat;

    // for encroption
    bak_encrypt_t encrypt_info;
    char key[GS_AES256KEYSIZE];
    char password[GS_PASSWORD_BUFFER_SIZE]; // for restore, before encryption
    char sys_pwd[GS_PASSWORD_BUFFER_SIZE]; // for backup, after encryption

    bak_read_cursor_t read_cursor;
    bak_stream_buf_t send_stream;
    rst_stream_buf_t recv_stream;

    // for repair analyse
    aligned_buf_t build_aly_mem;
    page_id_t *build_aly_pages;
    build_analyse_item_t *build_aly_items;
    build_analyse_bucket_t *build_aly_buckets;
    build_analyse_bucket_t build_aly_free_list;
    uint32 page_count;
    aligned_buf_t log_buf;
    bool32 arch_keep_compressed;

    // for rcy_stop_backup
    char unsafe_redo[GS_NAME_BUFFER_SIZE];
    volatile bool32 rcy_stop_backup;  // used for stop standby backup when replaying unsupported redo

    // for dtc
    uint32 inst_id;
    bak_reform_check_t reform_check;
    uint64 target_bits;
} bak_t;

typedef enum st_bak_condition {
    NOT_RUNNING = 0,
    RUNNING = 1,
    KEEP_ALIVE = 2,
} bak_condition_t;

typedef struct st_bak_context {
    drlock_t lock;  // dls spinlock, backup running
    bak_condition_t bak_condition;
    time_t keep_live_start_time;
    bool32 block_repairing;
    bak_process_t process[GS_MAX_BACKUP_PROCESS];
    bak_t bak;
    uint32 stage_weight[BACKUP_MAX_STAGE_NUM];
} bak_context_t;

#define BAK_MAX_DEPEND_NUM \
    ((GS_BACKUP_BUFFER_SIZE - sizeof(bak_head_t) - BAK_MAX_FILE_NUM * sizeof(bak_file_t)) / sizeof(bak_dependence_t))
typedef struct st_bak_page_search {
    int32 handle;
    uint32 page_size;
    page_id_t page_id;
    log_point_t rcy_point;
    log_point_t max_rcy_point; /* for increment backup type, the rcy point of latset increment buckup */
    uint64 sec_start;
    aligned_buf_t read_buf;
    device_type_t file_type;
} bak_page_search_t;

typedef struct st_bak_record_lsn_info {
    uint32_t node_id;
    uint64_t lsn;
} bak_record_lsn_info;

void bak_init(knl_session_t *session);
bool32 bak_paral_task_enable(knl_session_t *session);
bool32 ctbak_paral_logfile_enable(bak_t *ct_bak);
status_t bak_check_session_status(knl_session_t *session);
status_t rst_restore_database(knl_session_t *session, knl_restore_t *param);
status_t bak_validate_backupset(knl_session_t *session, knl_validate_t *param);

status_t bak_agent_command(bak_t *bak, bak_package_type_t type);
status_t bak_agent_file_start(bak_t *bak, const char *path, uint32 type, uint32 file_id);
status_t bak_agent_send_pkg(bak_t *bak, bak_package_type_t end_type);
status_t bak_agent_write(bak_t *process, const char *buf, int32 size);
status_t bak_agent_wait_pkg(bak_t *bak, bak_package_type_t ack);
status_t bak_alloc_compress_context(knl_session_t *session, bool32 is_compress);
void bak_free_compress_context(knl_session_t *session, bool32 is_compress);
status_t bak_write_lz4_compress_head(bak_t *bak, bak_process_t *proc, bak_local_t *bak_file);

status_t bak_record_backup_set(knl_session_t *session, bak_record_t *record);
status_t bak_delete_backup_set(knl_session_t *session, knl_alterdb_backupset_t *def);

void bak_calc_head_checksum(bak_head_t *head, uint32 size);
void bak_calc_ctrlfile_checksum(knl_session_t *session, char *ctrl_buf, uint32 count);
status_t rst_verify_ctrlfile_checksum(knl_session_t *session, const char *name);
status_t bak_verify_datafile_checksum(knl_session_t *session, bak_process_t *ctx, uint64 offset, const char *name);
status_t rst_verify_datafile_checksum(knl_session_t *session, bak_process_t *ctx, char *buf, uint32 page_count,
                                      const char *name);
status_t rst_truncate_datafile(knl_session_t *session);
status_t rst_extend_file(knl_session_t *session, const char *name, device_type_t type, int64 size, char *buf,
                         uint32 buf_size);
status_t bak_get_free_proc(knl_session_t *session, bak_process_t **proc, bool32 is_paral_log_proc);
void bak_wait_paral_proc(knl_session_t *session, bool32 is_paral_log_proc);

void bak_get_error(knl_session_t *session, int32 *code, const char **message);
status_t rst_prepare(knl_session_t *session, knl_restore_t *param);
status_t rst_restore_backupset_head(knl_session_t *session, bool32 fetch_catalog);
status_t rst_alloc_resource(knl_session_t *session, bak_t *bak);
status_t rst_proc(knl_session_t *session);
void bak_end(knl_session_t *session, bool32 restore);

void bak_set_progress(knl_session_t *session, bak_stage_t stage, uint64 data_size);
void bak_update_progress(bak_t *bak, uint64 size);
void bak_set_progress_end(bak_t *bak);
void bak_reset_progress(bak_progress_t *progress);
void bak_reset_error(bak_error_t *error);
uint32 bak_get_package_type(bak_file_type_t type);
status_t bak_head_verify_checksum(knl_session_t *session, bak_head_t *head, uint32 size, bool32 is_check_file);
status_t bak_init_uds(uds_link_t *link, const char *sun_path);
status_t bak_read_param(knl_session_t *session);
void bak_reset_process(bak_process_t *ctx);
void bak_reset_stats(knl_session_t *session);
void bak_reset_process_ctrl(bak_t *bak, bool32 restore);
void bak_set_error(bak_error_t *error_info);
status_t bak_set_running(knl_session_t *session, bak_context_t *ctx);
status_t bak_set_build_running(knl_session_t *session, bak_context_t *ctx, build_progress_t *build_progress);
void bak_unset_running(knl_session_t *session, bak_context_t *ctx);
void bak_unset_build_running(knl_session_t *session, bak_context_t *ctx);
status_t rst_agent_read(bak_t *bak, char *buf, uint32 buf_size, int32 *read_size, bool32 *read_end);
void bak_generate_bak_file(knl_session_t *session, const char *path, bak_file_type_t type, uint32 index, uint32 file_id,
                           uint32 sec_id, char *file_name);
void bak_set_fail_error(bak_error_t *error_info, const char *str);
status_t rst_agent_read_head(bak_t *process, bak_package_type_t expected_type, uint32 *data_size, bool32 *read_end);
status_t bak_agent_recv(bak_t *bak, char *buf, int32 size);
status_t bak_agent_send(bak_t *bak, const char *buf, int32 size);

void bak_replace_password(char *password);
status_t bak_encrypt_rand_iv(bak_file_t *file);
status_t bak_encrypt_init(bak_t *bak, bak_encrypt_ctx_t *encrypt_ctx, bak_file_t *file, bool32 is_encrypt);
status_t bak_encrypt_end(bak_t *bak, bak_encrypt_ctx_t *encrypt_ctx);
status_t bak_decrypt_end(bak_t *bak, bak_encrypt_ctx_t *encrypt_ctx, bak_file_t *file, bool32 ignore_logfile);
status_t bak_alloc_encrypt_context(knl_session_t *session);
void bak_free_encrypt_context(knl_session_t *session);
status_t rst_decrypt_data(bak_process_t *proc, const char *buf, int32 size, uint32 left_size);
status_t bak_encrypt_data(bak_process_t *proc, const char *buf, int32 size);
void build_disconnect(bak_t *bak);
uint32 bak_get_build_stage(bak_stage_t *stage);
bool32 bak_filter_incr(knl_session_t *session, knl_cursor_t *cursor, backup_device_t device, uint32 rst_value,
    bool32 cumulative);
status_t bak_select_incr_info(knl_session_t *session, bak_t *bak);
status_t bak_set_incr_info(knl_session_t *session, bak_t *bak);
status_t bak_set_data_path(knl_session_t *session, bak_t *bak, text_t *format);
status_t bak_set_exclude_space(knl_session_t *session, bak_t *bak, galist_t *exclude_spcs);
status_t bak_set_include_space(knl_session_t *session, bak_t *bak, galist_t *include_spcs);
bool32 bak_datafile_contains_dw(knl_session_t *session, bak_assignment_t *assign_ctrl);
uint64 bak_set_datafile_read_size(knl_session_t *session, uint64 offset, bool32 contains_dw,
    uint64 file_size, uint32 hwm_start);
bool32 bak_need_decompress(knl_session_t *session, bak_process_t *bak_proc);
status_t bak_decompress_and_verify_datafile(knl_session_t *session, bak_process_t *bak_proc);
status_t bak_construct_decompress_group(knl_session_t *session, char *first_page);
page_id_t bak_first_compress_group_id(knl_session_t *session, page_id_t page_id);
uint32 ctbak_get_datafile_sec_cnt(knl_session_t *ct_se, uint64 file_size, uint32 hwm_start,
    uint64 *sec_size, bool32 *diveded);
bool32 ctbak_wait_log_arch_finish(knl_session_t *ct_se);
void ctbak_support_log_entry(knl_session_t *ct_se, log_entry_t *redo_log, bool32 *unblock_bak);
void ctbak_unsupport_log_entry(knl_session_t *ct_se, log_entry_t *redo_log, bool32 *unblock_bak);
void backup_safe_entry(knl_session_t *session, log_entry_t *log, bool32 *need_unblock_backup);
status_t bak_set_process_running(knl_session_t *session);
void bak_unset_process_running(knl_session_t *session);
status_t knl_check_db_status(knl_session_t *se, knl_backup_t *param);
void bak_reset_params(knl_session_t *session, bool32 restore);

static inline const char *bak_compress_algorithm_name(compress_algo_e compress)
{
    switch (compress) {
        case COMPRESS_ZLIB:
            return "zlib";
        case COMPRESS_ZSTD:
            return "zstd";
        case COMPRESS_LZ4:
            return "lz4";
        default:
            return "NONE";
    }
}

static inline uint32 bak_get_align_size(device_type_t type, uint32 src_size, uint32 unit_size)
{
    if (type == DEV_TYPE_RAW) {
        return CM_CALC_ALIGN(src_size, unit_size);
    } else {
        return src_size;
    }
}

static inline uint32 bak_get_align_size2(device_type_t type, uint32 src_size1, uint32 src_size2, uint32 unit_size)
{
    if (type == DEV_TYPE_RAW) {
        return CM_CALC_ALIGN(src_size1, unit_size) + CM_CALC_ALIGN(src_size2, unit_size);
    } else {
        return src_size1 + src_size2;
    }
}

uint32 bak_get_rst_id(bak_t *bak, uint32 asn, reset_log_t *rst_log);
uint32 bak_log_get_id(knl_session_t *session, backup_data_type_t backup_type, uint32 rst_id, uint32 asn);

#ifdef __cplusplus
}
#endif

#endif
