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
 * cm_shm.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_shm.c
 *
 * -------------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <sys/types.h>
#include <sys/shm.h>
#include <errno.h>
#include <sys/mman.h>
#endif
#include "cm_log.h"
#include "cm_shm.h"
#include "cm_malloc.h"
#include "cm_error.h"
#include "cm_memory.h"
#include "cm_thread.h"
#include "cm_date.h"
#include "cm_defs.h"

uint32 g_instance_id = 0;

/* shared memory mapping */
cm_shm_map_t g_shm_map;
static thread_lock_t g_shm_map_lock;
static bool32 g_shm_inited = GS_FALSE;

#define CM_INVALID_SHM_KEY (0)

cm_shm_ctrl_t *cm_shm_ctrl(void)
{
    return (cm_shm_ctrl_t *)g_shm_map.entries[SHM_ID_MNG_CTRL].addr;
}

uint32 cm_shm_idx_of(cm_shm_type_e type, uint32 id)
{
    uint32 result;

    if (SHM_TYPE_FIXED == type) {
        if (id > CM_FIXED_SHM_MAX_ID) {
            GS_LOG_DEBUG_ERR("Fixed shared memory ID is out of  range : %u", id);
            return CM_INVALID_SHM_IDX;
        }
        result = id;
    } else if (SHM_TYPE_HASH == type) {
        if (id > CM_HASH_SHM_MAX_ID) {
            GS_LOG_DEBUG_ERR("GA shared memory ID is out of range : %u", id);
            return CM_INVALID_SHM_IDX;
        }
        result = CM_FIXED_SHM_MAX_ID + 1 + id;
    } else if (SHM_TYPE_GA == type) {
        if (id > CM_GA_SHM_MAX_ID) {
            GS_LOG_DEBUG_ERR("GA shared memory ID is out of range : %u", id);
            return CM_INVALID_SHM_IDX;
        }
        result = CM_FIXED_SHM_MAX_ID + CM_HASH_SHM_MAX_ID + 1 + id;
    } else {
        GS_LOG_DEBUG_ERR("invalid type, type: %d", type);
        return CM_INVALID_SHM_IDX;
    }

    if (result >= CM_SHM_MAX_BLOCK) {
        GS_LOG_DEBUG_ERR("Shared memory ID is out of range:%u, type: %d, ID: %u", CM_SHM_MAX_BLOCK, type, result);
        return CM_INVALID_SHM_IDX;
    }

    return result;
}

cm_shm_key_t cm_shm_key_of(cm_shm_type_e type, uint32 id)
{
    uint32 idx = cm_shm_idx_of(type, id);

    return idx != CM_INVALID_SHM_IDX ? CM_SHM_IDX_TO_KEY(idx) : CM_INVALID_SHM_KEY;
}

#define CM_SHM_MAP_ENTRY_OF(key) (&g_shm_map.entries[CM_SHM_KEY2IDX(key)])
#define SHM_ADDR_OF(key) (CM_SHM_MAP_ENTRY_OF(key)->addr)
#define SHM_ADDR_BAK_OF(key) (CM_SHM_MAP_ENTRY_OF(key)->addr_bak)

static bool32 cm_lock_shm_map(void)
{
    cm_thread_lock(&g_shm_map_lock);
    return GS_TRUE;
}

static void cm_unlock_shm_map(void)
{
    cm_thread_unlock(&g_shm_map_lock);
}

#ifdef WIN32
static void cm_fill_shm_name(char *name, cm_shm_key_t key)
{
    errno_t err;
    err = snprintf_s(name, GS_FILE_NAME_BUFFER_SIZE, "gmdb_0x%08x", key);
    PRTS_RETURN_IFERR(err);
}
#endif

cm_shm_handle_t cm_native_create_shm(cm_shm_key_t key, uint64 size, uint32 permission)
{
#ifdef WIN32
    char name[GS_FILE_NAME_BUFFER_SIZE];
    uint32 high = (uint32)(size >> 32);
    uint32 low = (uint32)(size & 0xFFFFFFFF);
    (void)permission;

    cm_fill_shm_name(name, key);

    return CreateFileMapping(CM_INVALID_SHM_HANDLE, NULL, PAGE_READWRITE, high, low, name);
#else
    /*lint -save -e712 */
    /*PL/MDE:qinchaoli 00150442 712:Loss of precision (Context) (Type to Type)*/
    return shmget((key_t)key, size, (int32)(IPC_CREAT | IPC_EXCL | permission));
/*lint -restore */
#endif
}

void cm_native_close_shm(cm_shm_handle_t handle)
{
#ifdef WIN32
    (void)CloseHandle(handle);
#else
    (void)handle;
#endif
}

void *cm_native_attach_shm(cm_shm_handle_t handle, uint32 flag)
{
#ifdef WIN32
    return MapViewOfFile(handle, flag, 0, 0, 0);
#else
    uint32 retry_num = SHM_MAX_RETRY_ATTACH_NUM;
    uint64 offset;
    void *result = NULL;
    for (uint32 i = 0; i < retry_num; i++) {
        result = shmat(handle, result, flag);
        /* shmat will return -1 when error */
        if (-1 == (int64)result) {
            return NULL;
        } else {
            offset = ((uint64)result) % GS_GSS_ALIGN_SIZE;
            if (offset == 0) {
                return result;
            } else {
                shmdt(result);
                result = (char *)result + (GS_GSS_ALIGN_SIZE - offset) + GS_GSS_ALIGN_SIZE * retry_num;
            }
        }
    }
    return NULL;
#endif
}

static void *cm_create_shm(cm_shm_key_t key, uint64 size, uint32 flag, uint32 permission)
{
    cm_shm_map_entry_t *entry = &g_shm_map.entries[CM_SHM_KEY2IDX(key)];
    errno_t ret;
    entry->handle = cm_native_create_shm(key, size, permission);
    if (CM_INVALID_SHM_HANDLE == entry->handle) {
        GS_LOG_WITH_OS_MSG(
            "Failed to create shared memory, key=0x%08x, size=%llu. The system memory may be insufficient, please check it firstly. Or there may be existent shared memory which is created by other process or last existed gmdb instance, please delete it manually and retry again",
            key, size);
        return NULL;
    }

    entry->addr = cm_native_attach_shm(entry->handle, flag);
    if (NULL == entry->addr) {
        GS_LOG_WITH_OS_MSG(
            "Failed to attach shared memory, handle=%d, key=0x%08x, size=%llu. The existent shared memory may be created by other process or last existed gmdb instance, please delete it manually and retry again",
            entry->handle, key, size);
        (void)cm_native_del_shm(entry->handle);
        entry->handle = CM_INVALID_SHM_HANDLE;
    } else {
#ifdef WIN32
        /* for Windows 32bit OS, the memory address can't bigger than 4G,
         * so convert uint64 to uint32.
         * IMPORTANT: NOT portable for Windows 64bit OS
         */
        ret = memset_s(entry->addr, (uint32)size, 0, (uint32)size);
        if (SECUREC_UNLIKELY(ret != EOK)) {
            GS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
            return NULL;
        }
#else
        /*lint -save -e712 */
        ret = memset_s(entry->addr, size, 0, size);
        if (SECUREC_UNLIKELY(ret != EOK)) {
            GS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
            return NULL;
        }
/*lint -restore */
#endif
    }

    return entry->addr;
}

cm_shm_handle_t cm_native_open_shm(uint32 key)
{
#ifdef WIN32
    char name[GS_FILE_NAME_BUFFER_SIZE];
    cm_shm_handle_t result;

    cm_fill_shm_name(name, key);
    result = OpenFileMapping(FILE_MAP_ALL_ACCESS, GS_FALSE, name);

    return (NULL == result) ? CM_INVALID_SHM_HANDLE : result;
#else
    return shmget((int32)key, 0, 0);
#endif
}

uint64 cm_native_shm_size(cm_shm_key_t key)
{
#ifdef WIN32
    (void)key;
    return 0;
#else
    cm_shm_handle_t handle = cm_native_open_shm(key);
    if (CM_INVALID_SHM_HANDLE == handle) {
        return 0;
    } else {
        struct shmid_ds shm_stat;
        int32 ret;

        ret = shmctl(handle, IPC_STAT, &shm_stat);
        if (ret != -1) {
            return shm_stat.shm_segsz;
        } else {
            return 0;
        }
    }
#endif
}

bool32 cm_native_detach_shm(void *addr)
{
#ifdef WIN32
    return UnmapViewOfFile(addr);
#else
    int32 result = shmdt(addr);
    return result != -1;
#endif
}

bool32 cm_shm_check_size(cm_shm_type_e type, uint32 id, uint64 size)
{
    uint64 shm_size;
    cm_shm_key_t key = cm_shm_key_of(type, id);
    if (CM_INVALID_SHM_KEY == key) {
        return GS_FALSE;
    }

    shm_size = cm_native_shm_size(key);
    if (size == shm_size) {
        return GS_TRUE;
    } else {
        return GS_FALSE;
    }
}

cm_shm_block_t *cm_shm_block(cm_shm_key_t key)
{
    return &cm_shm_ctrl()->blocks[CM_SHM_KEY2IDX(key)];
}

db_pid cm_get_pid(void)
{
#ifdef WIN32
    return GetCurrentProcessId();
#else
    return getpid();
#endif
}

#define CM_SHM_PIDS(key) (cm_shm_block(key)->pids)

#define SHM_CTRL_LOCK (cm_shm_ctrl()->lock_for_self)
#define SHM_GMSRV_LOCK (&cm_shm_ctrl()->lock_for_gmsrv)

bool32 cm_lock_shm_ctrl(void)
{
    // return cm_try_pid_lock(SHM_CTRL_LOCK, 10) == GS_SUCCESS;
    return GS_SUCCESS;
}

void cm_unlock_shm_ctrl(void)
{
    // cm_pid_unlock(SHM_CTRL_LOCK);
}

static void do_reg_attached_shm_block(cm_shm_key_t key, uint64 size)
{
    /*cm_shm_block(key)->key = key;
    if(size != 0)
    {
        cm_shm_block(key)->size = size;
    }

    cm_attach_pid_to_ctrl(key);
    cm_shm_block(key)->used = GS_TRUE;
    */
}

static void cm_register_attached_shm_block(cm_shm_key_t key, uint64 size)
{
    if (cm_lock_shm_ctrl()) {
        do_reg_attached_shm_block(key, size);
        cm_unlock_shm_ctrl();
    }
}

static void *cm_attach_to_existing_shm(cm_shm_key_t key, cm_shm_handle_t handle, uint64 size, uint32 flag)
{
    void *result = cm_native_attach_shm(handle, flag);

    if (result == NULL) {
        GS_LOG_WITH_OS_MSG(
            "Failed to attach shared memory, handle=%d, key=0x%08x, size=%llu. The existent shared memory may be created by other process or last existed gmdb instance, please delete it manually and retry again.",
            handle, key, size);
    }

#ifndef WIN32
    if ((result != NULL) && (size != 0)) {
        if (cm_native_shm_size(key) != size) {
            GS_LOG_DEBUG_ERR(
                "Failed to attach shared memory, key=0x%08x, reason=expected size %llu can not match actual size %llu. The existent shared memory may be created by other process or last existed gmdb instance, please delete it manually and retry again.",
                key, size, cm_native_shm_size(key));
            (void)cm_native_detach_shm(result);
            result = NULL;
        }
    }
#endif

    return result;
}

void *cm_do_attach_shm_without_register(cm_shm_key_t key, uint64 size, uint32 flag, bool32 logging_open_err)
{
    cm_shm_map_entry_t *entry = CM_SHM_MAP_ENTRY_OF(key);

    if (entry->addr != NULL) {
        return entry->addr;
    }

#ifndef WIN32
    entry->handle = cm_native_open_shm(key);
#else
    if (CM_INVALID_SHM_HANDLE == entry->handle) {
        entry->handle = cm_native_open_shm(key);
    }
#endif

    if (CM_INVALID_SHM_HANDLE == entry->handle) {
        if (logging_open_err) {
            GS_LOG_WITH_OS_MSG("Failed to open shared memory, key=0x%08x, size=%llu", key, size);
        }
        return NULL;
    } else {
        entry->addr = cm_attach_to_existing_shm(key, entry->handle, size, flag);
        return entry->addr;
    }
}

static void *cm_do_attach_shm(cm_shm_key_t key, uint64 size, uint32 flag, bool32 logging_open_err)
{
    void *result = cm_do_attach_shm_without_register(key, size, flag, logging_open_err);

    if (result != NULL) {
        cm_register_attached_shm_block(key, size);
    }

    return result;
}

static void cm_register_new_shm_block(cm_shm_key_t key, uint64 size)
{
    if (cm_lock_shm_ctrl()) {
        cm_shm_block(key)->create_time = cm_day_usec();
        do_reg_attached_shm_block(key, size);
        cm_unlock_shm_ctrl();
    }
}

#define CM_SHM_CTRL_KEY CM_SHM_IDX_TO_KEY((uint32)SHM_ID_MNG_CTRL)

static status_t cm_create_shm_ctrl(void)
{
    if (cm_create_shm(CM_SHM_CTRL_KEY, CM_SHM_SIZE_OF_CTRL, CM_SHM_ATTACH_RW, 0660) == NULL) {
        GS_THROW_ERROR(ERR_GSS_SHM_CREATE, CM_SHM_SIZE_OF_CTRL, CM_SHM_ATTACH_RW);
        return GS_ERROR;
    }

    GS_INIT_SPIN_LOCK(SHM_CTRL_LOCK);
    memcpy_s(cm_shm_ctrl()->magic, sizeof(cm_shm_ctrl()->magic), CM_SHM_MAGIC, sizeof(cm_shm_ctrl()->magic));
    cm_shm_ctrl()->self_version = CM_SHM_CTRL_CURRENT_VERSION;
    cm_shm_ctrl()->instance_id = CM_SHM_KEY2INSTANCE(CM_SHM_CTRL_KEY);

    cm_register_new_shm_block(CM_SHM_CTRL_KEY, CM_SHM_SIZE_OF_CTRL);

    return GS_SUCCESS;
}

static void *cm_create_shm_block(cm_shm_key_t key, uint64 size, uint32 flag, uint32 permission)
{
    void *result = cm_create_shm(key, size, flag, permission);

    if (NULL == result) {
        return NULL;
    }

    cm_register_new_shm_block(key, size);

    return result;
}

static void init_entry(cm_shm_map_entry_t *entry)
{
    CM_POINTER(entry);

    entry->handle = CM_INVALID_SHM_HANDLE;
    entry->addr = NULL;
}

static void cm_init_shm_map(void)
{
    uint32 i = 0;

    for (i = 0; i < ELEMENT_COUNT(g_shm_map.entries); i++) {
        init_entry(&g_shm_map.entries[i]);
    }

    return;
}

static status_t cm_check_shm_ctrl(void)
{
#ifndef WIN32
    if (CM_SHM_SIZE_OF_CTRL != cm_native_shm_size(CM_SHM_CTRL_KEY)) {
        GS_THROW_ERROR(ERR_GSS_SHM_CHECK, CM_SHM_CTRL_KEY, "mismatched size");
        return GS_ERROR;
    }
#endif

    if (0 != memcmp(cm_shm_ctrl()->magic, CM_SHM_MAGIC, sizeof(cm_shm_ctrl()->magic))) {
        GS_THROW_ERROR(ERR_GSS_SHM_CHECK, CM_SHM_CTRL_KEY, "mismatched magic number");
        return GS_ERROR;
    }

    if (cm_shm_ctrl()->self_version != CM_SHM_CTRL_CURRENT_VERSION) {
        GS_LOG_DEBUG_ERR(
            "Failed to check shared memory ctrl ,key=0x%08x, reason=expected version %u can not match actual version %u.",
            CM_SHM_CTRL_KEY, CM_SHM_CTRL_CURRENT_VERSION, cm_shm_ctrl()->self_version);
        GS_THROW_ERROR(ERR_GSS_SHM_CHECK, CM_SHM_CTRL_KEY, "expected version can not match actual version");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static void cm_do_detach_pid_from_ctrl(cm_shm_key_t key)
{
    uint32 i = 0;
    for (; i < CM_SHM_BLOCK_PID_CNT; i++) {
        if (cm_get_pid() == CM_SHM_PIDS(key)[i]) {
            CM_SHM_PIDS(key)[i] = 0;
            break;
        }
    }
}

static bool32 cm_shm_ctrl_exists(void)
{
    return cm_shm_ctrl() != NULL;
}

static void cm_detach_pid_from_ctrl(cm_shm_key_t key)
{
    if (cm_shm_ctrl_exists() && cm_lock_shm_ctrl()) {
        cm_do_detach_pid_from_ctrl(key);
        cm_unlock_shm_ctrl();
    }
}

static bool32 cm_do_detach_shm(cm_shm_key_t key, bool32 unregistering, bool32 logging_err)
{
    void *addr = SHM_ADDR_OF(key);

    if (NULL == addr) {
        return GS_TRUE;
    }

    if (cm_native_detach_shm(addr)) {
        SHM_ADDR_BAK_OF(key) = addr;

        SHM_ADDR_OF(key) = NULL;
        if (unregistering) {
            cm_detach_pid_from_ctrl(key);
        }

        return GS_TRUE;
    } else {
        if (logging_err) {
            GS_LOG_WITH_OS_MSG("Failed to detach shared memory,key=0x%08x", key);
        }
        return GS_FALSE;
    }
}

static status_t cm_init_shm_ctrl()
{
    cm_shm_key_t key = CM_SHM_CTRL_KEY;
    // int32 idx = SHM_ID_MNG_CTRL;
    if (cm_do_attach_shm_without_register(key, 0, CM_SHM_ATTACH_RW, GS_TRUE) == NULL) {
        return cm_create_shm_ctrl();
    } else {
        status_t result = cm_check_shm_ctrl();
        if (result == GS_SUCCESS) {
            cm_register_attached_shm_block(CM_SHM_CTRL_KEY, CM_SHM_SIZE_OF_CTRL);
        } else {
            (void)cm_do_detach_shm(CM_SHM_CTRL_KEY, GS_FALSE, GS_FALSE);
        }

        return result;
    }
}

status_t cm_do_init_shm(uint32 instance_id)
{
    int32 result;

    g_instance_id = instance_id;

    cm_init_shm_map();
    cm_init_thread_lock(&g_shm_map_lock);

    result = cm_init_shm_ctrl();
    if (result != GS_SUCCESS) {
        (void)cm_destroy_thread_lock(&g_shm_map_lock);
    }

    return result;
}

status_t cm_init_shm(uint32 instance_id)
{
    if (g_shm_inited) {
        return GS_SUCCESS;
    } else {
        status_t result = cm_do_init_shm(instance_id);
        if (GS_SUCCESS == result) {
            g_shm_inited = GS_TRUE;
        }

        return result;
    }
}

bool32 cm_is_shm_block_used(cm_shm_key_t key)
{
    return cm_shm_block(key)->used;
}

static void *cm_do_get_shm(cm_shm_key_t key, uint64 size, uint32 flag, uint32 permission)
{
    void *result = cm_do_attach_shm(key, size, flag, GS_FALSE);

    return result != NULL ? result : cm_create_shm_block(key, size, flag, permission);
}

void *cm_get_shm(cm_shm_type_e type, uint32 id, uint64 size, uint32 flag, uint32 permission)
{
    cm_shm_key_t key = cm_shm_key_of(type, id);
    if (CM_INVALID_SHM_KEY == key) {
        return NULL;
    }

    if (cm_lock_shm_map()) {
        void *result = cm_do_get_shm(key, size, flag, permission);
        cm_unlock_shm_map();
        return result;
    } else {
        return NULL;
    }
}

void *cm_get_shm_without_lock(cm_shm_type_e type, uint32 id, uint64 size, uint32 flag, uint32 permission)
{
    cm_shm_key_t key = cm_shm_key_of(type, id);
    if (CM_INVALID_SHM_KEY == key) {
        return NULL;
    }

    return cm_do_get_shm(key, size, flag, permission);
}

void *cm_attach_shm(cm_shm_type_e type, uint32 id, uint64 size, uint32 flag)
{
    cm_shm_key_t key = cm_shm_key_of(type, id);
    if (CM_INVALID_SHM_KEY == key) {
        return NULL;
    }

    if (cm_lock_shm_map()) {
        void *result = cm_do_attach_shm(key, size, flag, GS_TRUE);
        cm_unlock_shm_map();

        return result;
    } else {
        return NULL;
    }
}

void *cm_attach_shm_directly(cm_shm_type_e type, uint32 id, uint64 size, uint32 flag)
{
    cm_shm_key_t key = cm_shm_key_of(type, id);
    if (CM_INVALID_SHM_KEY == key) {
        return NULL;
    }

    return cm_do_attach_shm_without_register(key, size, flag, GS_TRUE);
}

bool32 cm_native_shm_exists(cm_shm_key_t key)
{
    cm_shm_handle_t handle = cm_native_open_shm(key);
    if (handle != CM_INVALID_SHM_HANDLE) {
        cm_native_close_shm(handle);

        return GS_TRUE;
    } else {
        return GS_FALSE;
    }
}

bool32 cm_shm_exists(cm_shm_type_e type, uint32 id)
{
    cm_shm_key_t key = cm_shm_key_of(type, id);

    return (CM_INVALID_SHM_KEY == key) ? GS_FALSE : cm_native_shm_exists(key);
}

bool32 cm_shm_exists_by_idx(uint32 idx)
{
    return cm_native_shm_exists(CM_SHM_IDX_TO_KEY(idx));
}

#define CM_SHM_HANDLE_OF(key) (g_shm_map.entries[CM_SHM_KEY2IDX(key)].handle)

bool32 cm_native_del_shm(cm_shm_handle_t handle)
{
#ifdef WIN32
    return CloseHandle(handle);
#else
    int32 ret = shmctl(handle, IPC_RMID, NULL);
    return ret != -1;
#endif
}

bool32 do_del_shm_directly(cm_shm_key_t key)
{
    cm_shm_handle_t handle;

#ifdef WIN32
    handle = CM_SHM_HANDLE_OF(key);
#else
    handle = cm_native_open_shm(key);
#endif
    if (CM_INVALID_SHM_HANDLE == handle) {
        return GS_TRUE;
    }

    return cm_native_del_shm(handle);
}

static void cm_unregister_shm_block(cm_shm_key_t key)
{
    /*
    if(cm_shm_ctrl_exists() && cm_lock_shm_ctrl())
    {
        cm_shm_block(key)->used = GS_FALSE;
        cm_unlock_shm_ctrl();
    }
    */
}

static bool32 cm_del_shm_block(cm_shm_key_t key)
{
    if (!do_del_shm_directly(key)) {
        GS_LOG_WITH_OS_MSG("Failed to delete shared memory,key=0x%08x", key);
        return GS_FALSE;
    }

    CM_SHM_HANDLE_OF(key) = CM_INVALID_SHM_HANDLE;

    cm_unregister_shm_block(key);

    return GS_TRUE;
}

static bool32 cm_do_del_shm(cm_shm_key_t key)
{
    return cm_do_detach_shm(key, GS_TRUE, GS_TRUE) ? cm_del_shm_block(key) : GS_FALSE;
}

static bool32 del_shm_by_key(cm_shm_key_t key)
{
    if (cm_lock_shm_map()) {
        bool32 result = cm_do_del_shm(key);
        cm_unlock_shm_map();

        return result;
    } else {
        return GS_FALSE;
    }
}

bool32 cm_del_shm(cm_shm_type_e type, uint32 id)
{
    cm_shm_key_t key = cm_shm_key_of(type, id);
    if (CM_INVALID_SHM_KEY == key) {
        return GS_FALSE;
    }

    return del_shm_by_key(key);
}

bool32 cm_del_shm_directly(cm_shm_type_e type, uint32 id)
{
    cm_shm_key_t key = cm_shm_key_of(type, id);
    if (CM_INVALID_SHM_KEY == key) {
        return GS_FALSE;
    }

    return do_del_shm_directly(key);
}

bool32 cm_detach_all_shms(void)
{
    int i = 0;
    for (; i < CM_SHM_MAX_BLOCK; i++) {
        if (!cm_do_detach_shm(CM_SHM_IDX_TO_KEY(i), GS_TRUE, GS_FALSE)) {
            return GS_FALSE;
        }
    }

    return GS_TRUE;
}

bool32 cm_detach_all_shms_except_log(void)
{
    uint32 i = 0;
    for (; i < CM_SHM_MAX_BLOCK; i++) {
        if (!cm_do_detach_shm(CM_SHM_IDX_TO_KEY(i), GS_TRUE, GS_FALSE)) {
            return GS_FALSE;
        }
    }

    return GS_TRUE;
}

bool32 cm_detach_all_shms_forcibly(void)
{
    bool32 result = GS_TRUE;

    int i = 0;
    for (; i < CM_SHM_MAX_BLOCK; i++) {
        if (!cm_do_detach_shm(CM_SHM_IDX_TO_KEY(i), GS_TRUE, GS_FALSE)) {
            result = GS_FALSE;
        }
    }

    return result;
}

bool32 cm_clear_shm_space(void)
{
    int i = 0;
    for (; i < CM_SHM_MAX_BLOCK; i++) {
        if (!cm_do_del_shm(CM_SHM_IDX_TO_KEY(i))) {
            return GS_FALSE;
        }
    }

    return GS_TRUE;
}

bool32 cm_clear_shm_space_forcibly(uint32 instance_id)
{
    bool32 result = GS_TRUE;

    int i = 0;
    for (; i < CM_SHM_MAX_BLOCK; i++) {
        if (!do_del_shm_directly(CM_SHM_MAKE_KEY(instance_id, i))) {
            result = GS_FALSE;
        }
    }

    return result;
}

bool32 cm_del_all_existing_shms_directly(void)
{
    bool32 result = GS_TRUE;

    int i = 0;
    for (; i < CM_SHM_MAX_BLOCK; i++) {
        if (cm_native_shm_exists(CM_SHM_IDX_TO_KEY(i)) && !do_del_shm_directly(CM_SHM_IDX_TO_KEY(i))) {
            result = GS_FALSE;
        }
    }

    return result;
}

bool32 cm_del_all_shms_except_common(void)
{
    uint32 i = 0;
    for (; i < CM_SHM_MAX_BLOCK; i++) {
        if (i == (uint32)SHM_ID_MNG_CTRL) {
            continue;
        }

        if (!del_shm_by_key(CM_SHM_IDX_TO_KEY(i))) {
            return GS_FALSE;
        }
    }

    return GS_TRUE;
}

void *cm_shm_addr_in_map(cm_shm_type_e type, uint32 id)
{
    return SHM_ADDR_OF(cm_shm_key_of(type, id));
}

void *cm_shm_addr_bak_in_map(cm_shm_type_e type, uint32 id)
{
    return SHM_ADDR_BAK_OF(cm_shm_key_of(type, id));
}

cm_shm_handle_t cm_get_shm_handle(cm_shm_type_e type, uint32 id)
{
    return CM_SHM_HANDLE_OF(cm_shm_key_of(type, id));
}

void cm_clear_shm_handle(cm_shm_type_e type, uint32 id)
{
    CM_SHM_HANDLE_OF(cm_shm_key_of(type, id)) = CM_INVALID_SHM_HANDLE;
}

void cm_clear_all_shm_handles(void)
{
    uint32 i = 0;
    for (; i < ELEMENT_COUNT(g_shm_map.entries); i++) {
        g_shm_map.entries[i].handle = CM_INVALID_SHM_HANDLE;
    }
}

bool32 cm_detach_shm(cm_shm_type_e type, uint32 id)
{
    cm_shm_key_t key = cm_shm_key_of(type, id);
    if (CM_INVALID_SHM_KEY == key) {
        return GS_FALSE;
    }

    if (cm_lock_shm_map()) {
        bool32 result = cm_do_detach_shm(key, GS_TRUE, GS_TRUE);
        cm_unlock_shm_map();

        return result;
    } else {
        return GS_FALSE;
    }
}

bool32 cm_detach_shm_directly(cm_shm_type_e type, uint32 id)
{
    cm_shm_key_t key = cm_shm_key_of(type, id);
    if (CM_INVALID_SHM_KEY == key) {
        return GS_FALSE;
    }

    return cm_do_detach_shm(key, GS_FALSE, GS_TRUE);
}

int32 cm_do_destroy_shm(void)
{
    cm_destroy_thread_lock(&g_shm_map_lock);

    memset_s(&g_shm_map_lock, sizeof(g_shm_map_lock), 0, sizeof(g_shm_map_lock));

    return GS_SUCCESS;
}

int32 cm_destroy_shm(void)
{
    if (g_shm_inited) {
        int32 result = cm_do_destroy_shm();
        if (GS_SUCCESS == result) {
            g_shm_inited = GS_FALSE;
        }

        return result;
    } else {
        return GS_SUCCESS;
    }
}

void cm_set_shm_ctrl_flag(uint64 value)
{
    cm_shm_ctrl()->flag = value;
    CM_MFENCE
}

uint64 cm_get_shm_ctrl_flag(void)
{
    return cm_shm_ctrl()->flag;
}

void cm_set_shm_ctrl_pid(db_pid value)
{
    cm_shm_ctrl()->pid = value;
    CM_MFENCE
}

db_pid cm_get_shm_ctrl_pid(void)
{
    return cm_shm_ctrl()->pid;
}

uint64 cm_get_shm_mng_create_time(void)
{
    return cm_shm_block(CM_SHM_CTRL_KEY)->create_time;
}

sh_mem_p cm_trans_shm_offset(uint32_t key, void *ptr)
{
    sh_mem_p ptr_uint64;
    sh_mem_t *shm_ptr = (sh_mem_t *)(void *)&ptr_uint64;
    cm_shm_map_entry_t *entry = CM_SHM_MAP_ENTRY_OF(key);

    shm_ptr->offset = (uint32)((char *)ptr - (char *)entry->addr);  //lint !e613
    shm_ptr->seg = CM_SHM_KEY2IDX(key);

    return ptr_uint64;
}
