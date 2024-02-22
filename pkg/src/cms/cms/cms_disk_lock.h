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
 * cms_disk_lock.h
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_disk_lock.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMS_DISK_LOCK
#define CMS_DISK_LOCK

#include "cm_defs.h"
#include "cms_defs.h"
#include "cm_disk.h"
#include "cm_dlock.h"
#include "cm_thread.h"
#include "cms_gcc.h"
#include "cms_detect_error.h"

#define CMS_LOCK_TRY_INTERVAL 100
#define CMS_MASTER_INFO_MAGIC         (*((uint64*)"CMS_MASTER_INFO"))

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _st_cms_disk_lock_t cms_disk_lock_t;
typedef bool32(*active_func_t)(cms_disk_lock_t* lock, uint64 inst_id);

typedef union u_cms_file_lock_t {
    struct {
        uint64      magic;
        uint8       node_id;
        time_t      lock_time;
        uint64      l_start; // used for nas only
        uint64      l_len; // used for nas only
        bool32      is_write;
        char        file_name[CMS_FILE_NAME_BUFFER_SIZE];
        char        data[DISK_LOCK_BODY_LEN];
    };
    char            lock_area[CMS_BLOCK_SIZE];
}cms_flock_t;


typedef struct _st_cms_disk_lock_t {
    uint64          offset;
    int64           inst_id;
    int64           int64_param1;
    active_func_t   active_func;
    cms_dev_type_t  type;
    union {
        int32           fd;
        disk_handle_t   disk_handle;
    };
    union {
        dlock_t             dlock;
        cms_flock_t*        flock;
    };
    thread_lock_t       tlock; // used in disk_try_lock and disk_unlock
    thread_lock_t       slock; // protect seek&read(reopen) or seek&write(reopen) as atomic operation
    uint32              flag;
    char                dev_name[CMS_FILE_NAME_BUFFER_SIZE];
    object_id_t*        dbs_fd; // only used when type is CMS_DEV_TYPE_DBSTORE
    int                 fd_len; // only used when type is CMS_DEV_TYPE_DBSTORE
    char                file_name[CMS_MAX_NAME_LEN]; // only used when type is CMS_DEV_TYPE_DBSTORE
}cms_disk_lock_t;

typedef union u_cms_master_info_t {
    struct {
        uint64      magic;
        uint8       node_id;
        time_t      lock_time;
        char        data[DISK_LOCK_BODY_LEN];
    };
    char            lock_area[CMS_BLOCK_SIZE];
}cms_master_info_t;

#define CMS_DLOCK_THREAD   0x1
#define CMS_DLOCK_PROCESS  0x2

#define CMS_STAT_LOCK_MAGIC         (*((uint64*)"CMS_LOCK"))
#define CMS_DISK_LOCK_TIMEOUT       10
#define CMS_EXIT_NUM 128
#define CMS_EXIT_COUNT_MAX 20

#define CMS_DBS_LAST_FILE_HANDLE_IDX 1
#define CMS_DBS_LAST_DIR_HANDLE_IDX 2

extern cms_flock_t* g_invalid_lock;
extern cms_master_info_t* g_master_info;
extern spinlock_t g_exit_num_lock;
status_t cms_disk_lock_init(cms_dev_type_t type, const char* dev, const char* file, uint64 offset,
    uint64 l_start, uint64 l_len, int64 inst_id, cms_disk_lock_t* lock, active_func_t active_func,
    uint32 flag, bool32 is_write);
status_t cms_disk_lock(cms_disk_lock_t* lock, uint32 timeout_ms, uint8 lock_type);

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
status_t _cms_disk_try_lock(cms_disk_lock_t* lock, uint8 lock_type, const char* file, int32 line);
status_t _cms_disk_unlock(cms_disk_lock_t* lock, uint8 lock_type, const char* file, int32 line);
status_t _cms_disk_lock_get_inst(cms_disk_lock_t* lock, uint64* inst_id, const char* file, int32 line);
#define cms_disk_try_lock(lock, lock_type) _cms_disk_try_lock((lock), (lock_type), __FILE__, __LINE__)
#define cms_disk_unlock(lock, lock_type) _cms_disk_unlock((lock), (lock_type), __FILE__, __LINE__)
#define cms_disk_lock_get_inst(lock, inst_id) _cms_disk_lock_get_inst((lock), (inst_id), __FILE__, __LINE__)
#else
status_t cms_disk_try_lock(cms_disk_lock_t* lock, uint8 lock_type);
status_t cms_disk_unlock(cms_disk_lock_t* lock, uint8 lock_type);
status_t cms_disk_lock_get_inst(cms_disk_lock_t* lock, uint64* inst_id);
#endif
status_t cms_disk_lock_get_data(cms_disk_lock_t* lock, char* data, uint32 size);
status_t cms_disk_lock_set_data(cms_disk_lock_t* lock, char* data, uint32 size);
status_t cms_disk_unlock_file(cms_disk_lock_t* lock);
status_t cms_disk_unlock_nfs(cms_disk_lock_t* lock);
status_t cms_get_exit_num(uint32 *exit_num);
status_t cms_reopen_lock_file(cms_disk_lock_t* lock);
void cms_disk_lock_destroy(cms_disk_lock_t* lock);
void cms_kill_self_by_exit(void);
void cms_inc_exit_num(cms_res_t res);
void cms_exec_exit_proc(void);

#ifdef __cplusplus
}
#endif

#endif
