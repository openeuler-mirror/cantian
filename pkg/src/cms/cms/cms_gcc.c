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
 * cms_gcc.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_gcc.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_log_module.h"
#include "cms_defs.h"
#include "cms_instance.h"
#include "cms_gcc.h"
#include "cm_disk.h"
#include "cms_param.h"
#include "cm_file.h"
#include "cm_malloc.h"
#include "cm_utils.h"
#include "cms_log.h"
#include "cm_dbs_defs.h"

typedef struct st_gcc_buffer {
    uint64      buff[CMS_BLOCK_SIZE / sizeof(uint64)][(sizeof(cms_gcc_t) / CMS_BLOCK_SIZE + 1)];
}cms_gcc_buffer_t;

static cms_gcc_buffer_t g_gcc_buff;
static cms_rwlock_t g_gcc_rwlock = CMS_RWLOCK_INITIALIZER;
static cms_sync_t  gcc_loader_sync;

#define CMS_RLOCK_GCC_LOCK_START        0
#define CMS_RLOCK_GCC_LOCK_LEN          (sizeof(cms_gcc_storage_t) - CMS_BLOCK_SIZE)
#define CMS_GCC_LOCK_POS                (OFFSET_OF(cms_gcc_storage_t, gcc_lock))
#define CMS_VALID_GCC_OFFSET(gcc_id)    ((size_t)&(((cms_gcc_storage_t*)NULL)->gcc[gcc_id]))
#define CMS_GCC_READ_OFFSET(gcc_id)     (CMS_VALID_GCC_OFFSET(gcc_id))
#define CMS_GCC_WRITE_OFFSET(gcc_id)    (CMS_VALID_GCC_OFFSET(((gcc_id) == 1) ? 0 : 1))
#define CMS_GCC_FILE_SIZE               (1024 * 1024 * 1024)
#define CMS_WRITE_GCC_PER_SIZE          (1024 * 1024)

#define CMS_LOCK_RETRY_INTERVAL 100
#define GCC_LOCK_WAIT_TIMEOUT   5000

void cms_rdlock_gcc(void)
{
    if (!g_cms_inst->is_server) {
        return;
    }
    while (cms_rwlock_rdlock(&g_gcc_rwlock) != 0) {
        CMS_LOG_ERR("read lock gcc failed:error code:%d,%s", errno, strerror(errno));
        cm_sleep(CMS_LOCK_RETRY_INTERVAL);
    }
}

void cms_wrlock_gcc(void)
{
    if (!g_cms_inst->is_server) {
        return;
    }
    while (cms_rwlock_wrlock(&g_gcc_rwlock) != 0) {
        CMS_LOG_ERR("write lock gcc failed:error code:%d,%s", errno, strerror(errno));
        cm_sleep(CMS_LOCK_RETRY_INTERVAL);
    }
}

void cms_unlock_gcc(void)
{
    if (!g_cms_inst->is_server) {
        return;
    }
    while (cms_rwlock_unlock(&g_gcc_rwlock) != 0) {
        CMS_LOG_ERR("unlock gcc failed:error code:%d,%s", errno, strerror(errno));
        cm_sleep(CMS_LOCK_RETRY_INTERVAL);
    }
}

const cms_gcc_t* cms_get_read_gcc(void)
{
    cms_rdlock_gcc();
    return (const cms_gcc_t*)CMS_ALIGN_ADDR_512(&g_gcc_buff);
}

cms_gcc_t* cms_get_write_gcc(void)
{
    cms_wrlock_gcc();
    return (cms_gcc_t*)CMS_ALIGN_ADDR_512(&g_gcc_buff);
}

void cms_release_gcc(const cms_gcc_t** gcc)
{
    if (*gcc != NULL) {
        *gcc = NULL;
    }
    cms_unlock_gcc();
}

void cms_release_write_gcc(cms_gcc_t** gcc)
{
    if (*gcc != NULL) {
        *gcc = NULL;
    }
    cms_unlock_gcc();
}

status_t cms_init_gcc_disk_lock(void)
{
    return cms_disk_lock_init(g_cms_param->gcc_type, g_cms_param->gcc_home, "", CMS_GCC_LOCK_POS,
        CMS_RLOCK_GCC_LOCK_START, CMS_RLOCK_GCC_LOCK_LEN, g_cms_param->node_id, &g_cms_inst->gcc_lock,
        NULL, 0, CT_FALSE);
}

status_t cms_lock_gcc_disk(void)
{
    return cms_disk_lock(&g_cms_inst->gcc_lock, GCC_LOCK_WAIT_TIMEOUT, DISK_LOCK_WRITE);
}

status_t cms_unlock_gcc_disk(void)
{
    return cms_disk_unlock(&g_cms_inst->gcc_lock, DISK_LOCK_WRITE);
}

static status_t cms_read_gcc_info(cms_local_ctx_t *ctx, uint64 offset, char* data, uint32 size)
{
    if (g_cms_param->gcc_type != CMS_DEV_TYPE_DBS) {
        return cm_read_disk(ctx->gcc_handle, offset, data, size);
    }
    return cm_read_dbs_file(&ctx->gcc_dbs_handle, CMS_GCC_FILE_NAME, offset, data, size);
}

static status_t cms_write_gcc_info(cms_local_ctx_t *ctx, uint64 offset, char* data, uint32 size)
{
    if (g_cms_param->gcc_type != CMS_DEV_TYPE_DBS) {
        return cm_write_disk(ctx->gcc_handle, offset, data, size);
    }
    return cm_write_dbs_file(&ctx->gcc_dbs_handle, CMS_GCC_FILE_NAME, offset, data, size);
}

static status_t cms_get_valid_gcc_id(cms_local_ctx_t *ctx, uint32 *gcc_id)
{
    uint32 *gcc_id_align = (uint32*)cm_malloc_align(CMS_BLOCK_SIZE, CMS_BLOCK_SIZE);
    if (gcc_id_align == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(uint32), "malloc gcc_id_align");
        return CT_ERROR;
    }
    errno_t ret;

    ret = memset_sp(gcc_id_align, CMS_BLOCK_SIZE, 0, CMS_BLOCK_SIZE);
    if (ret != EOK) {
        CM_FREE_PTR(gcc_id_align);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    if (cms_lock_gcc_disk() != CT_SUCCESS) {
        CM_FREE_PTR(gcc_id_align);
        return CT_ERROR;
    }

    if (cms_read_gcc_info(ctx, 0, (char *)gcc_id_align, CMS_BLOCK_SIZE) != CT_SUCCESS) {
        cms_unlock_gcc_disk();
        CM_FREE_PTR(gcc_id_align);
        CMS_LOG_ERR("read disk failed, gcc_id(%u)", *gcc_id);
        return CT_ERROR;
    }
    cms_unlock_gcc_disk();
    *gcc_id = *gcc_id_align;

    if (*gcc_id != 0 && *gcc_id != 1) {
        CMS_LOG_ERR("invalid gcc_id:%u", *gcc_id_align);
        CM_FREE_PTR(gcc_id_align);
        return CT_ERROR;
    }

    CM_FREE_PTR(gcc_id_align);

    return CT_SUCCESS;
}

static status_t cms_set_valid_gcc_id(cms_local_ctx_t *ctx, uint32 gcc_id)
{
    uint32 *gcc_id_align = (uint32*)cm_malloc_align(CMS_BLOCK_SIZE, CMS_BLOCK_SIZE);
    if (gcc_id_align == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(uint32), "malloc gcc_id_align");
        return CT_ERROR;
    }
    errno_t ret;

    ret = memset_sp(gcc_id_align, CMS_BLOCK_SIZE, 0, CMS_BLOCK_SIZE);
    if (ret != EOK) {
        CM_FREE_PTR(gcc_id_align);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    *gcc_id_align = gcc_id;
    if (cms_lock_gcc_disk() != CT_SUCCESS) {
        CM_FREE_PTR(gcc_id_align);
        return CT_ERROR;
    }

    if (cms_write_gcc_info(ctx, 0, (char *)gcc_id_align, CMS_BLOCK_SIZE) != CT_SUCCESS) {
        cms_unlock_gcc_disk();
        CM_FREE_PTR(gcc_id_align);
        CMS_LOG_ERR("write disk failed, gcc_id(%u)", gcc_id);
        return CT_ERROR;
    }
    cms_unlock_gcc_disk();
    CM_FREE_PTR(gcc_id_align);

    return CT_SUCCESS;
}

static status_t cms_gcc_read_disk(cms_gcc_t* gcc, bool32* stop_reading)
{
    status_t ret;
    uint32 gcc_id = CT_INVALID_ID32;
    *stop_reading = CT_FALSE;
    cms_local_ctx_t *ctx = NULL;
    CT_RETURN_IFERR(cms_get_local_ctx(&ctx));
    CT_RETURN_IFERR(cms_get_valid_gcc_id(ctx, &gcc_id));

    if (cms_lock_gcc_disk() != CT_SUCCESS) {
        CMS_LOG_ERR("cms lock gcc disk failed");
        return CT_ERROR;
    }

    ret = cms_read_gcc_info(ctx, CMS_GCC_READ_OFFSET(gcc_id), (char *)gcc, sizeof(cms_gcc_t));
    cms_unlock_gcc_disk();
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("read gcc failed.");
        return CT_ERROR;
    }

    if (gcc->head.magic != CMS_GCC_HEAD_MAGIC) {
        CMS_LOG_ERR("gcc head is invalid, load gcc failed.");
        CT_THROW_ERROR(ERR_CMS_INVALID_GCC);
        return CT_ERROR;
    }

    const cms_gcc_t* current_gcc = cms_get_read_gcc();
    if (gcc->head.magic == current_gcc->head.magic &&
       gcc->head.data_ver == current_gcc->head.data_ver) {
        *stop_reading = CT_TRUE;
        cms_release_gcc(&current_gcc);
        return CT_SUCCESS;
    }
    cms_release_gcc(&current_gcc);
    return CT_SUCCESS;
}

status_t cms_gcc_write_disk(cms_gcc_t* gcc)
{
    uint32 gcc_id = CT_INVALID_ID32;
    cms_local_ctx_t *ctx = NULL;
    CT_RETURN_IFERR(cms_get_local_ctx(&ctx));
    CT_RETURN_IFERR(cms_get_valid_gcc_id(ctx, &gcc_id));

    CT_RETURN_IFERR(cms_write_gcc_info(ctx, CMS_GCC_WRITE_OFFSET(gcc_id), (char *)gcc, sizeof(cms_gcc_t)));

    gcc_id = gcc_id == 0 ? 1 : 0;
    CT_RETURN_IFERR(cms_set_valid_gcc_id(ctx, gcc_id));

    return CT_SUCCESS;
}

status_t cms_delete_gcc(void)
{
    object_id_t root_handle = { 0 };
    object_id_t cluster_name_dir_handle = { 0 };
    char cluster_dir_name[CMS_PATH_BUFFER_SIZE] = { 0 };
    int32 ret = sprintf_s(cluster_dir_name, CMS_PATH_BUFFER_SIZE, "%s_cms", (char *)g_cms_param->cluster_name);
    PRTS_RETURN_IFERR(ret);

    if (cm_get_dbs_root_dir_handle((char *)g_cms_param->fs_name, &root_handle) != CT_SUCCESS) {
        printf("Failed to open root dir\n");
        return CT_ERROR;
    }

    if (cm_get_dbs_dir_handle(&root_handle, cluster_dir_name, &cluster_name_dir_handle) != CT_SUCCESS) {
        printf("Failed to open cluster dir\n");
        return CT_ERROR;
    }

    if (cm_rm_dbs_dir_file(&cluster_name_dir_handle, CMS_GCC_DIR_NAME) != CT_SUCCESS) {
        printf("Failed to delete gcc dir\n");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cms_create_gcc(void)
{
    // object_id_t root_handle = { 0 };
    // object_id_t gcc_file_handle = { 0 };

    object_id_t gcc_home_handle = { 0 };
    object_id_t gcc_dir_handle = { 0 };
    if (cm_get_dbs_last_file_handle(g_cms_param->gcc_home, &gcc_home_handle)) {
        printf("Failed to get gcc file handle\n");
        return CT_ERROR;
    }
    if (cm_get_dbs_last_dir_handle(g_cms_param->gcc_dir, &gcc_dir_handle)) {
        printf("Failed to get gcc dir handle\n");
        return CT_ERROR;
    }

    int32_t times = CMS_GCC_FILE_SIZE / (CMS_WRITE_GCC_PER_SIZE);
    char buffer[CMS_WRITE_GCC_PER_SIZE];
    errno_t ret = memset_sp(buffer, CMS_WRITE_GCC_PER_SIZE, 0, CMS_WRITE_GCC_PER_SIZE);
    if (ret != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }
    for (int32_t i = 0 ; i < times; i++) {
        if (cm_write_dbs_file(&gcc_dir_handle, CMS_GCC_FILE_NAME, i * CMS_WRITE_GCC_PER_SIZE, buffer,
            sizeof(buffer)) != CT_SUCCESS) {
            printf("Failed to init gcc file\n");
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t cms_load_gcc(void)
{
    cms_gcc_t* temp_gcc;
    bool32 stop_loading;
    errno_t ret;

    temp_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (temp_gcc == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "loading gcc");
        return CT_ERROR;
    }
    ret = memset_sp(temp_gcc, sizeof(cms_gcc_t), 0, sizeof(cms_gcc_t));
    if (ret != EOK) {
        CM_FREE_PTR(temp_gcc);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    if (cms_gcc_read_disk(temp_gcc, &stop_loading) != CT_SUCCESS) {
        CM_FREE_PTR(temp_gcc);
        CMS_LOG_ERR("read disk failed when load gcc");
        return CT_ERROR;
    }
    if (stop_loading) {
        CM_FREE_PTR(temp_gcc);
        return CT_SUCCESS;
    }

    cms_gcc_t* gcc = cms_get_write_gcc();
    ret = memcpy_sp(gcc, sizeof(cms_gcc_t), temp_gcc, sizeof(cms_gcc_t));
    cms_release_write_gcc(&gcc);
    if (ret != EOK) {
        CM_FREE_PTR(temp_gcc);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    CM_FREE_PTR(temp_gcc);
    return CT_SUCCESS;
}

status_t cms_update_local_gcc(void)
{
    cms_gcc_t *temp_gcc = NULL;
    int32 handle;
    char file_name[CMS_FILE_NAME_BUFFER_SIZE] = { 0 };
    errno_t ret;

    ret = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s/local/",
        g_cms_param->cms_home);
    PRTS_RETURN_IFERR(ret);

    if (!cm_dir_exist(file_name)) {
        CT_RETURN_IFERR(cm_create_dir(file_name));
    }

    ret = memset_sp(file_name, CMS_FILE_NAME_BUFFER_SIZE, 0, CMS_FILE_NAME_BUFFER_SIZE);
    MEMS_RETURN_IFERR(ret);
    ret = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s/local/local_gcc",
        g_cms_param->cms_home);
    PRTS_RETURN_IFERR(ret);

    if (!cm_file_exist(file_name)) {
        if (cm_create_file(file_name, O_RDWR | O_TRUNC | O_BINARY | O_CREAT, &handle) != CT_SUCCESS) {
            CMS_LOG_ERR("failed to create file %s", file_name);
            return CT_ERROR;
        }
        if (cm_chmod_file(FILE_PERM_OF_DATA, handle) != CT_SUCCESS) {
            cm_close_file(handle);
            CMS_LOG_ERR("failed to chmod gcc backup file ");
            return CT_ERROR;
        }
    } else {
        CT_RETURN_IFERR(cm_open_file_ex(file_name, O_SYNC | O_RDWR | O_BINARY | O_CLOEXEC, S_IRUSR, &handle));
    }

    temp_gcc = (cms_gcc_t*)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (temp_gcc == NULL) {
        cm_close_file(handle);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "updating local gcc");
        return CT_ERROR;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();
    ret = memcpy_sp(temp_gcc, sizeof(cms_gcc_t), gcc, sizeof(cms_gcc_t));
    if (ret != EOK) {
        cms_release_gcc(&gcc);
        CM_FREE_PTR(temp_gcc);
        cm_close_file(handle);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }
    cms_release_gcc(&gcc);

    if (cm_pwrite_file(handle, (const char *)temp_gcc, sizeof(cms_gcc_t), 0) != CT_SUCCESS) {
        CM_FREE_PTR(temp_gcc);
        cm_close_file(handle);
        return CT_ERROR;
    }

    CM_FREE_PTR(temp_gcc);
    cm_close_file(handle);
    return CT_SUCCESS;
}

status_t cms_reset_gcc(void)
{
    errno_t ret;
    cms_gcc_storage_t *gcc_stor = NULL;

    gcc_stor = (cms_gcc_storage_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_storage_t));
    if (gcc_stor == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "reseting gcc");
        return CT_ERROR;
    }
    ret = memset_sp(gcc_stor, sizeof(cms_gcc_storage_t), 0, sizeof(cms_gcc_storage_t));
    if (ret != EOK) {
        CM_FREE_PTR(gcc_stor);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    gcc_stor->gcc[0].head.magic = CMS_GCC_HEAD_MAGIC;
    gcc_stor->gcc[1].head.magic = CMS_GCC_HEAD_MAGIC;
    gcc_stor->gcc[0].resgrp[0].magic = CMS_GCC_RES_GRP_MAGIC;
    gcc_stor->gcc[1].resgrp[0].magic = CMS_GCC_RES_GRP_MAGIC;
    ret = strcpy_sp(gcc_stor->gcc[0].resgrp[0].name, CMS_NAME_BUFFER_SIZE, "default");
    if (ret != EOK) {
        CM_FREE_PTR(gcc_stor);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }
    ret = strcpy_sp(gcc_stor->gcc[1].resgrp[0].name, CMS_NAME_BUFFER_SIZE, "default");
    if (ret != EOK) {
        CM_FREE_PTR(gcc_stor);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    cms_local_ctx_t *ctx = NULL;
    if (cms_get_local_ctx(&ctx) != CT_SUCCESS) {
        CM_FREE_PTR(gcc_stor);
        return CT_ERROR;
    }
 
    if (cms_lock_gcc_disk() != CT_SUCCESS) {
        CM_FREE_PTR(gcc_stor);
        return CT_ERROR;
    }
 
    if (cms_write_gcc_info(ctx, 0, (char *)gcc_stor, sizeof(cms_gcc_storage_t) - CMS_BLOCK_SIZE) != CT_SUCCESS) {
        cms_unlock_gcc_disk();
        CM_FREE_PTR(gcc_stor);
        return CT_ERROR;
    }

    cms_unlock_gcc_disk();
    CM_FREE_PTR(gcc_stor);
    return CT_SUCCESS;
}

static inline status_t cms_gcc_set_node(cms_node_def_t* node_def, uint32 node_id, const char* name,
    const char* ip, uint32 port)
{
    errno_t ret;

    node_def->magic = CMS_GCC_NODE_MAGIC;
    ret = strcpy_sp(node_def->name, CMS_NAME_BUFFER_SIZE, name);
    if (ret != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    ret = strcpy_sp(node_def->ip, CT_MAX_INST_IP_LEN, ip);
    if (ret != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }
    node_def->port = port;
    node_def->node_id = node_id;
    return CT_SUCCESS;
}

static inline status_t cms_find_unused_node_id(const cms_gcc_t *gcc, uint32 *node_id)
{
    uint32 id;
    for (id = 0; id < CMS_MAX_NODE_COUNT; id++) {
        if (gcc->node_def[id].magic != CMS_GCC_NODE_MAGIC) {
            break;
        }
    }
    if (id == CMS_MAX_NODE_COUNT) {
        CT_THROW_ERROR(ERR_CMS_NUM_EXCEED, "node", (uint32)CMS_MAX_NODE_COUNT);
        return CT_ERROR;
    }

    *node_id = id;
    return CT_SUCCESS;
}

status_t cms_check_node_exists(const cms_gcc_t* gcc, const char* name, const char* ip, uint32 port)
{
    uint32 node_id = 0;
    const cms_node_def_t* node_def = NULL;

    for (; node_id < MIN(gcc->head.node_count, CMS_MAX_NODE_COUNT); node_id++) {
        node_def = &gcc->node_def[node_id];
        if (node_def->magic == CMS_GCC_NODE_MAGIC) {
            if (cm_strcmpi(name, node_def->name) == 0) {
                CT_THROW_ERROR_EX(ERR_CMS_OBJECT_EXISTS, "node '%s'", name);
                return CT_ERROR;
            }
            if (cm_strcmpi(ip, node_def->ip) == 0 && port == node_def->port) {
                CT_THROW_ERROR_EX(ERR_CMS_OBJECT_EXISTS, "node @%s:%u", ip, port);
                return CT_ERROR;
            }
        }
    }
    return CT_SUCCESS;
}

status_t cms_add_node(const char* name, const char* ip, uint32 port)
{
    CT_RETURN_IFERR(cms_load_gcc());
    uint32 node_id = 0;
    cms_gcc_t* new_gcc;
    errno_t ret;

    new_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (new_gcc == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "adding node");
        return CT_ERROR;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();
    ret = memcpy_sp(new_gcc, sizeof(cms_gcc_t), gcc, sizeof(cms_gcc_t));
    cms_release_gcc(&gcc);
    if (ret != EOK) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    if (cms_check_node_exists(new_gcc, name, ip, port) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        return CT_ERROR;
    }

    if (cms_find_unused_node_id(new_gcc, &node_id) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        return CT_ERROR;
    }

    if (cms_gcc_set_node(&new_gcc->node_def[node_id], node_id, name, ip, port) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        CMS_LOG_ERR("set node failed. node_id(%u), name(%s), ip(%s), port(%u)", node_id, name, ip, port);
        return CT_ERROR;
    }
    new_gcc->head.magic = CMS_GCC_HEAD_MAGIC;
    new_gcc->head.data_ver++;
    new_gcc->head.node_count = MAX(node_id + 1, new_gcc->head.node_count);

    if (cms_gcc_write_disk(new_gcc) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        CMS_LOG_ERR("write disk failed. name(%s), ip(%s), port(%u)", name, ip, port);
        return CT_ERROR;
    }

    CM_FREE_PTR(new_gcc);
    return CT_SUCCESS;
}

status_t cms_insert_node(uint32 node_id, const char* name, const char* ip, uint32 port)
{
    if (node_id >= CMS_MAX_NODE_COUNT) {
        CMS_LOG_ERR("node id exceeds the maximum %d, insert node failed.", CMS_MAX_NODE_COUNT - 1);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cms_load_gcc());
    cms_gcc_t* new_gcc = NULL;
    errno_t ret;
    
    new_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (new_gcc == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "adding node");
        return CT_ERROR;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();
    ret = memcpy_sp(new_gcc, sizeof(cms_gcc_t), gcc, sizeof(cms_gcc_t));
    cms_release_gcc(&gcc);
    if (ret != EOK) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    if (new_gcc->node_def[node_id].magic == CMS_GCC_NODE_MAGIC) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR_EX(ERR_CMS_OBJECT_EXISTS, "node_id '%u'", node_id);
        return CT_ERROR;
    }

    if (cms_check_node_exists(new_gcc, name, ip, port) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        return CT_ERROR;
    }

    if (cms_gcc_set_node(&new_gcc->node_def[node_id], node_id, name, ip, port) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        CMS_LOG_ERR("set node failed. node_id(%u), name(%s), ip(%s), port(%u)", node_id, name, ip, port);
        return CT_ERROR;
    }
    new_gcc->head.magic = CMS_GCC_HEAD_MAGIC;
    new_gcc->head.data_ver++;
    new_gcc->head.node_count = MAX(node_id + 1, new_gcc->head.node_count);

    if (cms_gcc_write_disk(new_gcc) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        CMS_LOG_ERR("write disk failed. name(%s), ip(%s), port(%u)", name, ip, port);
        return CT_ERROR;
    }
    CM_FREE_PTR(new_gcc);
    return CT_SUCCESS;
}

status_t cms_del_node(uint32 node_id)
{
    if (node_id >= CMS_MAX_NODE_COUNT) {
        CMS_LOG_ERR("node id exceeds the maximum %d, delete node failed.", CMS_MAX_NODE_COUNT - 1);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cms_load_gcc());
    cms_gcc_t* new_gcc = NULL;
    errno_t ret;

    const cms_gcc_t* gcc = cms_get_read_gcc();
    if (gcc->head.magic != CMS_GCC_HEAD_MAGIC ||
        gcc->node_def[node_id].magic != CMS_GCC_NODE_MAGIC) {
        cms_release_gcc(&gcc);
        CT_THROW_ERROR_EX(ERR_CMS_OBJECT_NOT_FOUND, "the node");
        return CT_ERROR;
    }
    cms_release_gcc(&gcc);

    new_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (new_gcc == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "deleting node");
        return CT_ERROR;
    }

    gcc = cms_get_read_gcc();
    ret = memcpy_sp(new_gcc, sizeof(cms_gcc_t), gcc, sizeof(cms_gcc_t));
    cms_release_gcc(&gcc);
    if (ret != EOK) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    new_gcc->node_def[node_id].magic = 0;
    new_gcc->head.magic = CMS_GCC_HEAD_MAGIC;
    new_gcc->head.data_ver++;
    if (cms_gcc_write_disk(new_gcc) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        return CT_ERROR;
    }
    CM_FREE_PTR(new_gcc);
    return CT_SUCCESS;
}

cms_votedisk_t* cms_find_votedisk(cms_gcc_t* gcc, const char* path)
{
    cms_votedisk_t* votedisk = NULL;
    for (uint32 disk_id = 0; disk_id < CMS_MAX_VOTEDISK_COUNT; disk_id++) {
        if (gcc->votedisks[disk_id].magic == CMS_GCC_VOTEDISK_MAGIC &&
            strcmp(gcc->votedisks[disk_id].path, path) == 0) {
            votedisk = &gcc->votedisks[disk_id];
            break;
        }
    }

    return votedisk;
}

static inline status_t cms_find_unused_votedisk_id(const cms_gcc_t *gcc, uint32 *disk_id)
{
    uint32 id;
    for (id = 0; id < CMS_MAX_VOTEDISK_COUNT; id++) {
        if (gcc->votedisks[id].magic != CMS_GCC_VOTEDISK_MAGIC) {
            break;
        }
    }
    if (id == CMS_MAX_VOTEDISK_COUNT) {
        CT_THROW_ERROR(ERR_CMS_NUM_EXCEED, "votedisk", (uint32)CMS_MAX_VOTEDISK_COUNT);
        return CT_ERROR;
    }

    *disk_id = id;
    return CT_SUCCESS;
}

status_t cms_check_votedisk(const char* votedisk)
{
    status_t ret;
#ifdef _WIN32
    struct _stat stat_buf;
    ret = _stat(votedisk, &stat_buf);
    if (ret != 0) {
        CMS_LOG_ERR("stat failed.errno=%d,%s.", errno, strerror(errno));
        return CT_ERROR;
    }

    if (_S_IFREG == (stat_buf.st_mode & _S_IFREG)) {
        return CT_SUCCESS;
    } else {
        CT_THROW_ERROR(ERR_CMS_INVALID_VOTEDISK);
        return CT_ERROR;
    }
#else
    struct stat stat_buf;
    ret = stat(votedisk, &stat_buf);
    if (ret != 0) {
        CMS_LOG_ERR("stat failed.errno=%d,%s.", errno, strerror(errno));
        CT_THROW_ERROR(ERR_CMS_INVALID_VOTEDISK);
        return CT_ERROR;
    }

    if (!S_ISREG(stat_buf.st_mode) && !S_ISBLK(stat_buf.st_mode)) {
        CT_THROW_ERROR(ERR_CMS_INVALID_VOTEDISK);
        return CT_ERROR;
    }

    if (access(votedisk, R_OK | W_OK) != 0) {
        CT_THROW_ERROR(ERR_CMS_VOTEDISK_AUTHORITY);
        return CT_ERROR;
    }

    return CT_SUCCESS;
#endif
}

status_t cms_add_votedisk(const char* path)
{
    CT_RETURN_IFERR(cms_load_gcc());
    uint32 disk_id = 0;
    char real_path[CMS_FILE_NAME_BUFFER_SIZE];
    cms_gcc_t* new_gcc = NULL;
    cms_votedisk_t *votedisk = NULL;
    errno_t ret;

    if (realpath_file(path, real_path, CMS_FILE_NAME_BUFFER_SIZE) != CT_SUCCESS) {
        cm_reset_error();
        CT_THROW_ERROR(ERR_CMS_VOTEDISK_PATH, CMS_MAX_FILE_NAME_LEN);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cms_check_votedisk(real_path));

    new_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (new_gcc == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "adding votedisk");
        return CT_ERROR;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();
    ret = memcpy_sp(new_gcc, sizeof(cms_gcc_t), gcc, sizeof(cms_gcc_t));
    cms_release_gcc(&gcc);
    if (ret != EOK) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    votedisk = cms_find_votedisk(new_gcc, real_path);
    if (votedisk != NULL) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR_EX(ERR_CMS_OBJECT_EXISTS, "the votedisk");
        return CT_ERROR;
    }
    if (cms_find_unused_votedisk_id(new_gcc, &disk_id) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        return CT_ERROR;
    }

    new_gcc->votedisks[disk_id].magic = CMS_GCC_VOTEDISK_MAGIC;
    ret = strcpy_sp(new_gcc->votedisks[disk_id].path, CMS_FILE_NAME_BUFFER_SIZE, real_path);
    if (ret != EOK) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    new_gcc->head.magic = CMS_GCC_HEAD_MAGIC;
    new_gcc->head.data_ver++;
    if (cms_gcc_write_disk(new_gcc) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        CMS_LOG_ERR("add votedisk failed: write gcc failed");
        return CT_ERROR;
    }

    CM_FREE_PTR(new_gcc);
    return CT_SUCCESS;
}

status_t cms_del_votedisk(const char* path)
{
    CT_RETURN_IFERR(cms_load_gcc());
    cms_gcc_t* new_gcc;
    cms_votedisk_t *votedisk = NULL;
    errno_t ret;

    new_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (new_gcc == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "deleting votedisk");
        return CT_ERROR;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();
    ret = memcpy_sp(new_gcc, sizeof(cms_gcc_t), gcc, sizeof(cms_gcc_t));
    cms_release_gcc(&gcc);
    if (ret != EOK) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    votedisk = cms_find_votedisk(new_gcc, path);
    if (votedisk == NULL) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR_EX(ERR_CMS_OBJECT_NOT_FOUND, "the votedisk");
        return CT_ERROR;
    }

    votedisk->magic = 0;
    new_gcc->head.magic = CMS_GCC_HEAD_MAGIC;
    new_gcc->head.data_ver++;
    if (cms_gcc_write_disk(new_gcc) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        CMS_LOG_ERR("del votedisk fialed : write gcc failed");
        return CT_ERROR;
    }

    CM_FREE_PTR(new_gcc);
    return CT_SUCCESS;
}

const cms_resgrp_t* cms_find_resgrp(const cms_gcc_t* gcc, const char* name)
{
    const cms_resgrp_t* resgrp = NULL;
    for (uint32 resgrp_id = 0; resgrp_id < CMS_MAX_RESOURCE_GRP_COUNT; resgrp_id++) {
        if (gcc->resgrp[resgrp_id].magic == CMS_GCC_RES_GRP_MAGIC &&
            cm_strcmpi(gcc->resgrp[resgrp_id].name, name) == 0) {
            resgrp = &gcc->resgrp[resgrp_id];
            break;
        }
    }

    return resgrp;
}

static inline status_t cms_find_unused_resgrp_id(const cms_gcc_t *gcc, uint32 *grp_id)
{
    uint32 id;
    for (id = 0; id < CMS_MAX_RESOURCE_GRP_COUNT; id++) {
        if (gcc->resgrp[id].magic != CMS_GCC_RES_GRP_MAGIC) {
            break;
        }
    }
    if (id == CMS_MAX_RESOURCE_GRP_COUNT) {
        CT_THROW_ERROR(ERR_CMS_NUM_EXCEED, "resource group", (uint32)CMS_MAX_RESOURCE_GRP_COUNT);
        return CT_ERROR;
    }

    *grp_id = id;
    return CT_SUCCESS;
}

status_t cms_add_resgrp(const char* name)
{
    CT_RETURN_IFERR(cms_load_gcc());
    uint32 resgrp_id;
    cms_gcc_t* new_gcc;
    const cms_resgrp_t *resgrp = NULL;
    errno_t ret;

    new_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (new_gcc == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "adding resource group");
        return CT_ERROR;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();
    ret = memcpy_sp(new_gcc, sizeof(cms_gcc_t), gcc, sizeof(cms_gcc_t));
    cms_release_gcc(&gcc);
    if (ret != EOK) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    resgrp = cms_find_resgrp(new_gcc, name);
    if (resgrp != NULL) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR_EX(ERR_CMS_OBJECT_EXISTS, "the resource group");
        return CT_ERROR;
    }

    if (cms_find_unused_resgrp_id(new_gcc, &resgrp_id) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        return CT_ERROR;
    }

    new_gcc->resgrp[resgrp_id].magic = CMS_GCC_RES_GRP_MAGIC;
    ret = strcpy_sp(new_gcc->resgrp[resgrp_id].name, CMS_NAME_BUFFER_SIZE, name);
    if (ret != EOK) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }
    new_gcc->resgrp[resgrp_id].grp_id = resgrp_id;

    new_gcc->head.magic = CMS_GCC_HEAD_MAGIC;
    new_gcc->head.data_ver++;

    if (cms_gcc_write_disk(new_gcc) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        return CT_ERROR;
    }
    CM_FREE_PTR(new_gcc);
    return CT_SUCCESS;
}

bool32 cms_check_resgrp_has_res(const cms_gcc_t* gcc, const char* grp_name)
{
    for (uint32 i = 0; i < CMS_MAX_RESOURCE_COUNT; i++) {
        const cms_res_t* res = &gcc->res[i];
        if (res->magic == CMS_GCC_RES_MAGIC &&
            cm_strcmpi(gcc->resgrp[res->grp_id].name, grp_name) == 0) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

status_t cms_del_resgrp(const char* name)
{
    CT_RETURN_IFERR(cms_load_gcc());
    cms_gcc_t* new_gcc;
    const cms_resgrp_t *resgrp = NULL;
    errno_t ret;

    new_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (new_gcc == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "deleting resource group");
        return CT_ERROR;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();
    ret = memcpy_sp(new_gcc, sizeof(cms_gcc_t), gcc, sizeof(cms_gcc_t));
    cms_release_gcc(&gcc);
    if (ret != EOK) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    resgrp = cms_find_resgrp(new_gcc, name);
    if (resgrp == NULL) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR_EX(ERR_CMS_OBJECT_NOT_FOUND, "the resource group");
        return CT_ERROR;
    }
    if (cms_check_resgrp_has_res(new_gcc, name)) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR(ERR_CMS_RES_GROUP_NOT_NULL);
        return CT_ERROR;
    }

    new_gcc->resgrp[resgrp->grp_id].magic = 0;
    new_gcc->head.magic = CMS_GCC_HEAD_MAGIC;
    new_gcc->head.data_ver++;
    if (cms_gcc_write_disk(new_gcc) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        return CT_ERROR;
    }

    CM_FREE_PTR(new_gcc);
    return CT_SUCCESS;
}

bool8 cms_fetch_text(text_t *text, char split_char, char enclose_char, text_t *sub)
{
    if (!cm_fetch_text(text, split_char, enclose_char, sub)) {
        return CT_FALSE;
    }
    if (text->len == 0) {
        return CT_FALSE;
    }
    return CT_TRUE;
}

status_t cms_parse_attrs_env_value(text_t* value, text_t* path)
{
    text_t left, env_home;
    char home_char[CMS_NAME_BUFFER_SIZE];
    if (cms_fetch_text(value, '%', 0, &left) == CT_FALSE) {
        cm_concat_text(path, CMS_FILE_NAME_BUFFER_SIZE, &left);
        return CT_SUCCESS;
    }
    cm_concat_text(path, CMS_FILE_NAME_BUFFER_SIZE, &left);

    if (cms_fetch_text(value, '%', 0, &env_home) == CT_FALSE) {
        CT_THROW_ERROR(ERR_CMS_RES_INVALID_ATTR);
        return CT_ERROR;
    }

    cm_text2str(&env_home, home_char, CMS_NAME_BUFFER_SIZE);
    char *home = getenv(home_char);
    if (home == NULL) {
        CT_THROW_ERROR(ERR_HOME_PATH_NOT_FOUND, home_char);
        return CT_ERROR;
    }
    cm_concat_string(path, CMS_FILE_NAME_BUFFER_SIZE, home);
    cm_concat_text(path, CMS_FILE_NAME_BUFFER_SIZE, value);
    return CT_SUCCESS;
}

status_t cms_save_res_attrs(text_t* key, text_t* value, cms_res_t* res)
{
    errno_t ret;
    char path_char[CMS_FILE_NAME_BUFFER_SIZE];
    text_t path = { path_char, 0 };
    uint32 num_value = 0;

    if (cm_text_str_equal_ins(key, "SCRIPT")) {
        CT_RETURN_IFERR(cms_parse_attrs_env_value(value, &path));
        if (!cms_check_path_valid(path.str, path.len)) {
            CT_THROW_ERROR(ERR_CMS_INVALID_PATH, "script");
            return CT_ERROR;
        }
        ret = strncpy_sp(res->script, CMS_FILE_NAME_BUFFER_SIZE, path.str, path.len);
        MEMS_RETURN_IFERR(ret);
    } else if (cm_text_str_equal_ins(key, "START_TIMEOUT")) {
        CT_RETURN_IFERR(cms_text2uint32(value, &num_value));
        res->start_timeout = num_value;
    } else if (cm_text_str_equal_ins(key, "STOP_TIMEOUT")) {
        CT_RETURN_IFERR(cms_text2uint32(value, &num_value));
        res->stop_timeout = num_value;
    } else if (cm_text_str_equal_ins(key, "CHECK_TIMEOUT")) {
        CT_RETURN_IFERR(cms_text2uint32(value, &num_value));
        res->check_timeout = num_value;
    } else if (cm_text_str_equal_ins(key, "CHECK_INTERVAL")) {
        CT_RETURN_IFERR(cms_text2uint32(value, &num_value));
        res->check_interval = num_value;
    } else if (cm_text_str_equal_ins(key, "HB_TIMEOUT")) {
        CT_RETURN_IFERR(cms_text2uint32(value, &num_value));
        res->hb_timeout = num_value;
    } else if (cm_text_str_equal_ins(key, "RESTART_TIMES")) {
        if (cm_text_str_equal_ins(value, "unlimited")) {
            res->restart_times = -1;
        } else {
            CT_RETURN_IFERR(cms_text2uint32(value, &num_value));
            res->restart_times = (int32)num_value;
        }
    } else if (cm_text_str_equal_ins(key, "RESTART_INTERVAL")) {
        CT_RETURN_IFERR(cms_text2uint32(value, &num_value));
        res->restart_interval = num_value;
    } else {
        CT_THROW_ERROR(ERR_CMS_INVALID_RES_ATTRS);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cms_parse_res_attrs(const char* attrs, cms_res_t* res)
{
    text_t temp = { (char *)attrs, (uint32)strlen(attrs) };
    text_t script = { "SCRIPT", 6 };
    while (CT_TRUE) {
        text_t key, value;

        if (!cm_fetch_text(&temp, '=', 0, &key)) {
            break;
        }

        cm_trim_text(&key);
        cm_trim_text(&temp);
        
        if (cm_text_equal_ins(&key, &script) && temp.len == 0) {
            errno_t ret = memset_sp(res->script, CMS_FILE_NAME_BUFFER_SIZE, 0, CMS_FILE_NAME_BUFFER_SIZE);
            MEMS_RETURN_IFERR(ret);
            break;
        }

        if (!cm_fetch_text(&temp, ',', 0, &value)) {
            CT_THROW_ERROR(ERR_CMS_RES_INVALID_ATTR);
            return CT_ERROR;
        }

        if (value.len > CMS_MAX_FILE_NAME_LEN) {
            CT_THROW_ERROR(ERR_FILE_PATH_TOO_LONG, CMS_MAX_FILE_NAME_LEN);
            return CT_ERROR;
        }
        CT_RETURN_IFERR(cms_save_res_attrs(&key, &value, res));
    }

    return CT_SUCCESS;
}

const cms_res_t* cms_find_res(const cms_gcc_t* gcc, const char* name)
{
    const cms_res_t* res = NULL;
    for (uint32 res_id = 0; res_id < CMS_MAX_RESOURCE_COUNT; res_id++) {
        if (gcc->res[res_id].magic == CMS_GCC_RES_MAGIC &&
            cm_strcmpi(gcc->res[res_id].name, name) == 0) {
            res = &gcc->res[res_id];
            break;
        }
    }

    return res;
}

const cms_res_t* cms_find_res_type(const cms_gcc_t* gcc, const char* res_type)
{
    const cms_res_t* res = NULL;
    for (uint32 res_id = 0; res_id < CMS_MAX_RESOURCE_COUNT; res_id++) {
        if (gcc->res[res_id].magic == CMS_GCC_RES_MAGIC &&
           cm_strcmpi(gcc->res[res_id].type, res_type) == 0) {
            res = &gcc->res[res_id];
            break;
        }
        CMS_LOG_WAR("res type is not found, res_id = %u, res[res_id].magic = %llu, CMS_GCC_RES_MAGIC = "
            "%llu,res[res_id].type = %s, ",
            res_id, gcc->res[res_id].magic, CMS_GCC_RES_MAGIC, gcc->res[res_id].type);
    }

    return res;
}


bool8 cms_check_resgrp_has_type(const cms_gcc_t* gcc, const char* grp_name, const char* type)
{
    for (uint32 i = 0; i < CMS_MAX_RESOURCE_COUNT; i++) {
        const cms_res_t* res = &gcc->res[i];
        if (res->magic != CMS_GCC_RES_MAGIC) {
            continue;
        }

        if (strcmp(gcc->resgrp[res->grp_id].name, grp_name) == 0 &&
           strcmp(res->type, type) == 0) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

static inline status_t cms_gcc_set_res(cms_res_t* res, uint32 res_id, const char* name, const char* type, uint32 group_id)
{
    errno_t ret;
    res->magic = CMS_GCC_RES_MAGIC;
    res->res_id = res_id;
    res->grp_id = group_id;
    res->level = 0;
    res->auto_start = CT_FALSE;
    res->start_timeout = CMS_RES_START_TIMEOUT;
    res->stop_timeout = CMS_RES_STOP_TIMEOUT;
    res->check_timeout = CMS_RES_CHECK_TIMEOUT;
    res->check_interval = CMS_RES_CHECK_INTERVAL;
    res->hb_timeout = CMS_RES_HB_TIMEOUT;
    
    #ifdef DB_DEBUG_VERSION
        res->restart_times = 0;
    #else
        res->restart_times = CMS_RES_RESTART_TIMES;
    #endif
    res->restart_interval = CMS_RES_RESTART_INTERVAL;

    ret = memset_sp(res->script, CMS_FILE_NAME_BUFFER_SIZE, 0, CMS_FILE_NAME_BUFFER_SIZE);
    MEMS_RETURN_IFERR(ret);

    ret = strcpy_sp(res->name, CMS_NAME_BUFFER_SIZE, name);
    if (ret != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }
    ret = strcpy_sp(res->type, CMS_NAME_BUFFER_SIZE, type);
    if (ret != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static inline status_t cms_find_unused_res_id(const cms_gcc_t *gcc, uint32 *res_id)
{
    uint32 id;
    for (id = 0; id < CMS_MAX_RESOURCE_COUNT; id++) {
        if (gcc->res[id].magic != CMS_GCC_RES_MAGIC) {
            break;
        }
    }
    if (id == CMS_MAX_RESOURCE_COUNT) {
        CT_THROW_ERROR(ERR_CMS_NUM_EXCEED, "resource", (uint32)CMS_MAX_RESOURCE_COUNT);
        return CT_ERROR;
    }

    *res_id = id;
    return CT_SUCCESS;
}

static inline status_t cms_check_res_and_resgrp(cms_gcc_t *gcc, const char* grp, const char* res_name,
    const char* res_type, uint32* resgrp_id)
{
    const cms_res_t *res = NULL;
    const cms_resgrp_t* resgrp;
    errno_t ret;

    *resgrp_id = -1;
    resgrp = cms_find_resgrp(gcc, grp);
    if (resgrp == NULL) {
        if (strcmp(grp, "default") == 0) {
            uint32 grp_id;
            if (cms_find_unused_resgrp_id(gcc, &grp_id) != CT_SUCCESS) {
                return CT_ERROR;
            }
            gcc->resgrp[grp_id].magic = CMS_GCC_RES_GRP_MAGIC;
            gcc->resgrp[grp_id].grp_id = grp_id;
            ret = strcpy_sp(gcc->resgrp[grp_id].name, CMS_NAME_BUFFER_SIZE, "default");
            MEMS_RETURN_IFERR(ret);
            *resgrp_id = grp_id;
        } else {
            CT_THROW_ERROR(ERR_CMS_OBJECT_NOT_FOUND, "the resource group");
            return CT_ERROR;
        }
    } else {
        *resgrp_id = resgrp->grp_id;
    }

    res = cms_find_res(gcc, res_name);
    if (res != NULL) {
        CT_THROW_ERROR(ERR_CMS_OBJECT_EXISTS, "the resource");
        return CT_ERROR;
    }
    if (cms_check_resgrp_has_type(gcc, grp, res_type) == CT_TRUE) {
        CT_THROW_ERROR(ERR_CMS_SAME_RESOURCE_TYPE, grp);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cms_add_res(const char* name, const char* res_type, const char* grp, const char* attrs)
{
    CT_RETURN_IFERR(cms_load_gcc());
    uint32 res_id;
    uint32 resgrp_id;
    cms_gcc_t* new_gcc;
    errno_t ret;

    new_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (new_gcc == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "adding resource");
        return CT_ERROR;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();
    ret = memcpy_sp(new_gcc, sizeof(cms_gcc_t), gcc, sizeof(cms_gcc_t));
    cms_release_gcc(&gcc);
    if (ret != EOK) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    if (cms_check_res_and_resgrp(new_gcc, grp, name, res_type, &resgrp_id) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        CMS_LOG_ERR("check res and resgrp failed.");
        return CT_ERROR;
    }

    if (cms_find_unused_res_id(new_gcc, &res_id) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        CMS_LOG_ERR("find unused res_id failed.");
        return CT_ERROR;
    }

    if (cms_gcc_set_res(&new_gcc->res[res_id], res_id, name, res_type, resgrp_id) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        CMS_LOG_ERR("set gcc failed.");
        return CT_ERROR;
    }
    if (strlen(attrs) != 0) {
        if (cms_parse_res_attrs(attrs, &new_gcc->res[res_id]) != CT_SUCCESS) {
            CM_FREE_PTR(new_gcc);
            return CT_ERROR;
        }
    }

    new_gcc->head.magic = CMS_GCC_HEAD_MAGIC;
    new_gcc->head.data_ver++;
    if (cms_gcc_write_disk(new_gcc) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        CMS_LOG_ERR("gcc write disk failed. name(%s), grp(%s)", name, grp);
        return CT_ERROR;
    }
    CM_FREE_PTR(new_gcc);
    return CT_SUCCESS;
}

status_t cms_edit_res(const char* name, const char* attrs)
{
    CT_RETURN_IFERR(cms_load_gcc());
    const cms_res_t *res = NULL;
    cms_gcc_t* new_gcc;
    errno_t ret;
    
    new_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (new_gcc == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "editing resource");
        return CT_ERROR;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();
    ret = memcpy_sp(new_gcc, sizeof(cms_gcc_t), gcc, sizeof(cms_gcc_t));
    cms_release_gcc(&gcc);
    if (ret != EOK) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    res = cms_find_res(new_gcc, name);
    if (res == NULL) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR_EX(ERR_CMS_OBJECT_NOT_FOUND, "the resource");
        return CT_ERROR;
    }

    if (cms_parse_res_attrs(attrs, &new_gcc->res[res->res_id]) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        return CT_ERROR;
    }

    new_gcc->head.magic = CMS_GCC_HEAD_MAGIC;
    new_gcc->head.data_ver++;
    if (cms_gcc_write_disk(new_gcc) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        return CT_ERROR;
    }

    CM_FREE_PTR(new_gcc);
    return CT_SUCCESS;
}

status_t cms_del_res(const char* name)
{
    CT_RETURN_IFERR(cms_load_gcc());
    const cms_res_t *res = NULL;
    cms_gcc_t* new_gcc;
    errno_t ret;

    new_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (new_gcc == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "deleting resource");
        return CT_ERROR;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();
    ret = memcpy_sp(new_gcc, sizeof(cms_gcc_t), gcc, sizeof(cms_gcc_t));
    cms_release_gcc(&gcc);
    if (ret != EOK) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    res = cms_find_res(new_gcc, name);
    if (res == NULL) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR_EX(ERR_CMS_OBJECT_NOT_FOUND, "the resource");
        return CT_ERROR;
    }

    new_gcc->res[res->res_id].magic = 0;
    new_gcc->head.magic = CMS_GCC_HEAD_MAGIC;
    new_gcc->head.data_ver++;
    if (cms_gcc_write_disk(new_gcc) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        return CT_ERROR;
    }

    CM_FREE_PTR(new_gcc);
    return CT_SUCCESS;
}

status_t cms_del_resgrp_res(cms_gcc_t* gcc, const char* name)
{
    cms_res_t* res = NULL;
    for (uint32 i = 0; i < CMS_MAX_RESOURCE_COUNT; i++) {
        res = &gcc->res[i];
        if (res->magic == CMS_GCC_RES_MAGIC &&
            cm_strcmpi(gcc->resgrp[res->grp_id].name, name) == 0) {
            res->magic = 0;
        }
    }
    return CT_SUCCESS;
}

status_t cms_del_resgrp_force(const char* name)
{
    CT_RETURN_IFERR(cms_load_gcc());
    cms_gcc_t* new_gcc;
    const cms_resgrp_t *resgrp = NULL;
    errno_t ret;
    
    new_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (new_gcc == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "deleting resource group");
        return CT_ERROR;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();
    ret = memcpy_sp(new_gcc, sizeof(cms_gcc_t), gcc, sizeof(cms_gcc_t));
    cms_release_gcc(&gcc);
    if (ret != EOK) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    resgrp = cms_find_resgrp(new_gcc, name);
    if (resgrp == NULL) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR_EX(ERR_CMS_OBJECT_NOT_FOUND, "the resource group");
        return CT_ERROR;
    }

    if (cms_check_resgrp_has_res(new_gcc, name)) {
        if (cms_del_resgrp_res(new_gcc, name) != CT_SUCCESS) {
            CM_FREE_PTR(new_gcc);
            return CT_ERROR;
        }
    }

    new_gcc->resgrp[resgrp->grp_id].magic = 0;
    new_gcc->head.magic = CMS_GCC_HEAD_MAGIC;
    new_gcc->head.data_ver++;
    if (cms_gcc_write_disk(new_gcc) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        return CT_ERROR;
    }

    CM_FREE_PTR(new_gcc);
    return CT_SUCCESS;
}

bool32 cms_check_name_valid(const char* name, uint32 name_len)
{
    if (!CM_IS_LETER(*name)) {
        return CT_FALSE;
    }

    for (uint32 i = 0; i < name_len; i++) {
        if (!CM_IS_NAMING_LETER(name[i])) {
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

bool32 cms_check_path_valid(const char* path, uint32 path_len)
{
    uint32 i;
    if (cm_check_exist_special_char(path, path_len)) {
        return CT_FALSE;
    }

    for (i = 0; i < path_len; i++) {
        if (path[i] == '-') {
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

bool32 cms_gcc_head_is_invalid(void)
{
    const cms_gcc_t* gcc = cms_get_read_gcc();

    if (gcc->head.magic == CMS_GCC_HEAD_MAGIC) {
        cms_release_gcc(&gcc);
        return CT_FALSE;
    }

    cms_release_gcc(&gcc);
    return CT_TRUE;
}

bool32 cms_node_is_invalid(uint32 node_id)
{
    if (node_id >= CMS_MAX_NODE_COUNT) {
        return CT_TRUE;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();

    if (gcc->node_def[node_id].magic == CMS_GCC_NODE_MAGIC) {
        cms_release_gcc(&gcc);
        return CT_FALSE;
    }

    cms_release_gcc(&gcc);
    return CT_TRUE;
}

bool32 cms_res_is_invalid(uint32 res_id)
{
    if (res_id >= CMS_MAX_RESOURCE_COUNT) {
        return CT_TRUE;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();

    if (gcc->res[res_id].magic == CMS_GCC_RES_MAGIC) {
        cms_release_gcc(&gcc);
        return CT_FALSE;
    }

    cms_release_gcc(&gcc);
    return CT_TRUE;
}

bool32 cms_resgrp_is_invalid(uint32 grp_id)
{
    if (grp_id >= CMS_MAX_RESOURCE_GRP_COUNT) {
        return CT_TRUE;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();

    if (gcc->resgrp[grp_id].magic == CMS_GCC_RES_GRP_MAGIC) {
        cms_release_gcc(&gcc);
        return CT_FALSE;
    }

    cms_release_gcc(&gcc);
    return CT_TRUE;
}

bool32 cms_votedisk_is_invalid(uint32 vd_id)
{
    if (vd_id >= CMS_MAX_VOTEDISK_COUNT) {
        return CT_TRUE;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();

    if (gcc->votedisks[vd_id].magic == CMS_GCC_VOTEDISK_MAGIC) {
        cms_release_gcc(&gcc);
        return CT_FALSE;
    }

    cms_release_gcc(&gcc);
    return CT_TRUE;
}

uint32 cms_get_gcc_node_count(void)
{
    uint32 n_count;
    const cms_gcc_t* gcc = cms_get_read_gcc();

    n_count = gcc->head.node_count;
    cms_release_gcc(&gcc);

    return n_count;
}

status_t cms_get_node_by_id(uint32 node_id, cms_node_def_t* node)
{
    if (node_id >= CMS_MAX_NODE_COUNT) {
        CMS_LOG_ERR("node is invalid ,node_id:%u", node_id);
        return CT_ERROR;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();
    const cms_node_def_t* node_def = &gcc->node_def[node_id];

    if (node_def->magic != CMS_GCC_NODE_MAGIC) {
        cms_release_gcc(&gcc);
        // CMS_LOG_ERR("node def is invalid ,node_id:%u", node_id);
        return CT_ERROR;
    }
    *node = *node_def;

    cms_release_gcc(&gcc);
    return CT_SUCCESS;
}

status_t cms_get_res_by_id(uint32 res_id, cms_res_t* res)
{
    if (res_id >= CMS_MAX_RESOURCE_COUNT) {
        CMS_LOG_ERR("res_id is invalid ,res_id:%u", res_id);
        return CT_ERROR;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();
    const cms_res_t* gcc_res = &gcc->res[res_id];

    if (gcc_res->magic != CMS_GCC_RES_MAGIC) {
        cms_release_gcc(&gcc);
        return CT_ERROR;
    }
    *res = *gcc_res;

    cms_release_gcc(&gcc);
    return CT_SUCCESS;
}

status_t cms_get_res_by_name(const char* name, cms_res_t* res)
{
    const cms_gcc_t* gcc = cms_get_read_gcc();
    const cms_res_t* gcc_res = cms_find_res(gcc, name);

    if (gcc_res == NULL) {
        cms_release_gcc(&gcc);
        CMS_LOG_ERR("resource name not found in gcc.");
        return CT_ERROR;
    }
    *res = *gcc_res;

    cms_release_gcc(&gcc);
    return CT_SUCCESS;
}

status_t cms_get_resgrp_by_name(const char* name, cms_resgrp_t* resgrp)
{
    const cms_gcc_t* gcc = cms_get_read_gcc();
    const cms_resgrp_t* gcc_resgrp = cms_find_resgrp(gcc, name);

    if (gcc_resgrp == NULL) {
        cms_release_gcc(&gcc);
        CMS_LOG_ERR("resource group is not found ,resource group name:%s", name);
        return CT_ERROR;
    }
    *resgrp = *gcc_resgrp;

    cms_release_gcc(&gcc);
    return CT_SUCCESS;
}

status_t cms_get_res_id_by_type(const char* res_type, uint32 *res_id)
{
    const cms_gcc_t* gcc = cms_get_read_gcc();
    const cms_res_t* res = cms_find_res_type(gcc, res_type);

    if (res == NULL) {
        cms_release_gcc(&gcc);
        CMS_LOG_ERR("resource type is not found in gcc.");
        return CT_ERROR;
    }
    *res_id = res->res_id;

    cms_release_gcc(&gcc);
    return CT_SUCCESS;
}

status_t cms_get_res_id_by_name(const char* name, uint32 *res_id)
{
    const cms_gcc_t* gcc = cms_get_read_gcc();
    const cms_res_t* res = cms_find_res(gcc, name);

    if (res == NULL) {
        cms_release_gcc(&gcc);
        CMS_LOG_ERR("resource name is not found in gcc.");
        return CT_ERROR;
    }
    *res_id = res->res_id;

    cms_release_gcc(&gcc);
    return CT_SUCCESS;
}

status_t cms_get_votedisk_by_id(uint32 vd_id, cms_votedisk_t* votedisk)
{
    if (vd_id >= CMS_MAX_VOTEDISK_COUNT) {
        return CT_ERROR;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();
    const cms_votedisk_t* gcc_vd = &gcc->votedisks[vd_id];

    if (gcc_vd->magic != CMS_GCC_VOTEDISK_MAGIC) {
        cms_release_gcc(&gcc);
        return CT_ERROR;
    }
    *votedisk = *gcc_vd;

    cms_release_gcc(&gcc);
    return CT_SUCCESS;
}

void cms_gcc_loader_entry(thread_t * thread)
{
    cms_sync_init(&gcc_loader_sync);
    while (!thread->closed) {
        CMS_LOG_TIMER("refresh gcc");
        cms_load_gcc();
        cms_sync_wait(&gcc_loader_sync, MILLISECS_PER_SECOND);
    }
}

void cms_notify_load_gcc(void)
{
    cms_sync_notify(&gcc_loader_sync);
}

status_t cms_update_gcc_ver(uint16 main_ver, uint16 major_ver, uint16 revision, uint16 inner)
{
    CMS_LOG_INF("begin cms update gcc version");
    CT_RETURN_IFERR(cms_load_gcc());
    errno_t ret;
    cms_gcc_t* new_gcc;
    new_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (new_gcc == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "cms update gcc ver");
        return CT_ERROR;
    }

    const cms_gcc_t* gcc = cms_get_read_gcc();
    ret = memcpy_sp(new_gcc, sizeof(cms_gcc_t), gcc, sizeof(cms_gcc_t));
    cms_release_gcc(&gcc);
    if (ret != EOK) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    new_gcc->head.ver_magic = CMS_GCC_UPGRADE_MAGIC;
    new_gcc->head.ver_main = main_ver;
    new_gcc->head.ver_major = major_ver;
    new_gcc->head.ver_revision = revision;
    new_gcc->head.ver_inner = inner;

    new_gcc->head.magic = CMS_GCC_HEAD_MAGIC;
    new_gcc->head.data_ver++;
    CMS_SYNC_POINT_GLOBAL_START(CMS_UPGRADE_VERSION_WRITE_GCC_ABORT, NULL, 0);
    CMS_SYNC_POINT_GLOBAL_END;
    // 开始写盘
    if (cms_gcc_write_disk(new_gcc) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        CMS_LOG_ERR("cms update gcc write disk failed.");
        return CT_ERROR;
    }
    CM_FREE_PTR(new_gcc);
    CMS_LOG_INF("end cms update gcc version");
    return CT_SUCCESS;
}

status_t cms_get_gcc_ver(uint16* main_ver, uint16* major_ver, uint16* revision, uint16* inner)
{
    errno_t err;
    cms_gcc_t* new_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (new_gcc == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "loading gcc");
        return CT_ERROR;
    }
    err = memset_sp(new_gcc, sizeof(cms_gcc_t), 0, sizeof(cms_gcc_t));
    if (err != EOK) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CT_ERROR;
    }
    if (cms_gcc_read_disk_direct(new_gcc) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        CMS_LOG_ERR("read disk failed when load gcc.");
        return CT_ERROR;
    }
    if (new_gcc->head.ver_magic != CMS_GCC_UPGRADE_MAGIC) {
        CM_FREE_PTR(new_gcc);
        CMS_LOG_ERR("gcc is invalid.");
        return CT_ERROR;
    }
    *main_ver = new_gcc->head.ver_main;
    *major_ver = new_gcc->head.ver_major;
    *revision = new_gcc->head.ver_revision;
    *inner = new_gcc->head.ver_inner;
    CM_FREE_PTR(new_gcc);
    return CT_SUCCESS;
}

status_t cms_gcc_read_disk_direct(cms_gcc_t* gcc)
{
    uint32 gcc_id = CT_INVALID_ID32;
    cms_local_ctx_t *ctx = NULL;
    CT_RETURN_IFERR(cms_get_local_ctx(&ctx));
    CT_RETURN_IFERR(cms_get_valid_gcc_id(ctx, &gcc_id));

    if (cms_lock_gcc_disk() != CT_SUCCESS) {
        CMS_LOG_ERR("cms lock gcc disk failed");
        return CT_ERROR;
    }

    if (cms_read_gcc_info(ctx, CMS_GCC_READ_OFFSET(gcc_id), (char *)gcc, sizeof(cms_gcc_t)) != CT_SUCCESS) {
        CMS_LOG_ERR("cms lock gcc cms read gcc info failed.");
        return CT_ERROR;
    }

    cms_unlock_gcc_disk();

    if (gcc->head.magic != CMS_GCC_HEAD_MAGIC) {
        CMS_LOG_ERR("gcc head is invalid, load gcc failed, magic %llu.", gcc->head.magic);
        CT_THROW_ERROR(ERR_CMS_INVALID_GCC);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}