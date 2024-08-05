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
 * cm_dbs_file.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_dbs_file.c
 *
 * -------------------------------------------------------------------------
 */
 
#include <stdint.h>
#include <fcntl.h>
#include <semaphore.h>
 
#include "cm_dbs_module.h"
#include "cm_dbs_file.h"
#include "cm_spinlock.h"
#include "cm_log.h"
#include "cm_file.h"
#include "cm_error.h"
#include "cm_dbs_map.h"
#include "cm_dbs_ctrl.h"
#include "cm_dbs_intf.h"
#include "cm_dbs_defs.h"
#include "cm_dbstore.h"

#define DBSTOR_MAX_FILE_SIZE (1024ULL * 1024 * 1024 * 1024)
#define DBSTOR_MAX_RWBUF_SIZE (1 * 1024 * 1024)
#define DBSTOR_RETRY_COUNT 3

#define DBSTOR_ULOG_ARCHIVE_END 21

status_t cm_check_file_path(const char *file_path)
{
    uint32 len = strlen(file_path);
    if (len == 0 || len >= MAX_DBS_FS_FILE_PATH_LEN) {
        CT_LOG_RUN_ERR("[CM_DEVICE] invalid file path %s, len %u", file_path, len);
        return CT_ERROR;        
    }

    if (cm_check_exist_special_char(file_path, strlen(file_path))) {
        CT_LOG_RUN_ERR("[CM_DEVICE] invalid file path %s", file_path);
        return CT_ERROR;
    }
    if (file_path[0] != '/') {
        CT_LOG_RUN_ERR("[CM_DEVICE] invalid file path %s", file_path);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void cm_remove_extra_delim(char *file_path, const char delim)
{
    uint32 length = strlen(file_path);
    uint32 i = 0, j = 0;
    for (; i < length; i++) {
        if (i == 0 || file_path[i] != delim) {
            file_path[j++] = file_path[i];
        } else if (file_path[i-1] != delim) {
            file_path[j++] = file_path[i];
        }
    }
    file_path[j] = '\0';
    if (j > 0 && file_path[j - 1] == delim) {
        file_path[j - 1] = '\0';
    }
    return;
}

char* cm_find_fix_delim(char *file_path, const char delim, uint32 fix_num)
{
    uint32 length = strlen(file_path);
    uint32 cur_num = 0;
    for (uint32 i = 0; i < length; i++) {
        if (file_path[i] == delim) {
            cur_num++;
        }
        if (cur_num == fix_num) {
            return file_path + i;
        }
    }
    return NULL;
}

status_t cm_get_fs_name(const char *file_path, const char *delim, char *fs_name)
{
    char *context = NULL;
    char *token = NULL;

    char file[MAX_DBS_FS_FILE_PATH_LEN] = { 0 };
    MEMS_RETURN_IFERR(strcpy_sp(file, MAX_DBS_FS_FILE_PATH_LEN, file_path));
    token = strtok_s(file, delim, &context);
    if (token == NULL) {
        CT_LOG_RUN_ERR("[CM_DEVICE] get fs name failed, file_path %s", file);
        return CT_ERROR;
    }
    if (strlen(token) >= MAX_DBS_FS_NAME_LEN) {
        CT_LOG_RUN_ERR("[CM_DEVICE] invalid fs name %s, len %lu", token, strlen(token));
        return CT_ERROR;
    }
    MEMS_RETURN_IFERR(strcpy_s(fs_name, MAX_DBS_FS_NAME_LEN, token));
    return CT_SUCCESS;
}

status_t cm_get_file_name_and_dir(const char *file_path, uint32 path_depth, const char *delim, char *file_name, char *file_dir)
{
    char *context = NULL;
    char *token = NULL;
    uint32 cur_depth = 0;
    char file[MAX_DBS_FS_FILE_PATH_LEN] = { 0 };
    MEMS_RETURN_IFERR(strcpy_sp(file, MAX_DBS_FS_FILE_PATH_LEN, file_path));
    token = strtok_s(file, delim, &context);
    while (token != NULL) {
        if (cur_depth >= path_depth) {
            CT_LOG_RUN_INF("[CM_DEVICE] get file name failed, cur depth %u, path depth %u",
                cur_depth, path_depth);
            return CT_ERROR;
        }
        if (cur_depth == path_depth - 1) {
            MEMS_RETURN_IFERR(strcpy_s(file_name, MAX_DBS_FILE_NAME_LEN, token));
            break;
        } else {
            MEMS_RETURN_IFERR(strcat_s(file_dir, MAX_DBS_FS_FILE_PATH_LEN, "/"));
            MEMS_RETURN_IFERR(strcat_s(file_dir, MAX_DBS_FS_FILE_PATH_LEN, token));
        }
        cur_depth++;
        token = strtok_s(NULL, delim, &context);
    }
    return CT_SUCCESS;
}

status_t cm_dbs_open_root(char *fs_name, int32 *root_handle)
{
    cm_dbs_map_item_s root_item = { 0 };
    status_t ret = dbs_global_handle()->dbs_file_open_root(fs_name, &root_item.obj_id);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] open fs root failed, ret %d, fs name %s", ret, fs_name);
        return CT_ERROR;
    }

    if (cm_dbs_map_set(fs_name, &root_item, root_handle, DEV_TYPE_DBSTOR_FILE) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] map set item to handle failed");
        return CT_ERROR;
    } 
    return CT_SUCCESS;
}

status_t cm_dbs_open_file_common(const char *name, uint32 file_type, int32 *handle)
{
    if (*handle != CT_INVALID_HANDLE) {
        return CT_SUCCESS;
    }

    char file_path[MAX_DBS_FS_FILE_PATH_LEN] = { 0 };
    MEMS_RETURN_IFERR(strcpy_sp(file_path, MAX_DBS_FS_FILE_PATH_LEN, name));
    cm_remove_extra_delim(file_path, '/');

    if (cm_check_file_path(file_path) != CT_SUCCESS) {
        return CT_ERROR;
    }

    int path_depth = 0;
    if (cm_get_file_path_depth(file_path, "/", &path_depth) != CT_SUCCESS || path_depth < 1) {
        CT_LOG_RUN_ERR("[CM_DEVICE] get dbs file path %s depth failed", file_path);
        return CT_ERROR;
    }

    char fs_name[MAX_DBS_FS_NAME_LEN] = { 0 };
    if (cm_get_fs_name(file_path, "/", fs_name) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] get fs name failed, file path %s", file_path);
        return CT_ERROR;
    }
    if (path_depth == 1) {
        return cm_dbs_open_root(fs_name, handle);
    }

    object_id_t root_obj_id = { 0 };
    status_t ret = dbs_global_handle()->dbs_file_open_root(fs_name, &root_obj_id);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] open fs root failed, ret %d, fs name %s", ret, fs_name);
        return CT_ERROR;
    }

    char *fix_file_path = cm_find_fix_delim(file_path, '/', 2);
    cm_dbs_map_item_s file_item = { 0 };
    ret = dbs_global_handle()->dbs_file_open_by_path(&root_obj_id, fix_file_path + 1, file_type, &file_item.obj_id);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] open file failed, ret %d, file path %s", ret, file_path);
        return CT_ERROR;
    }

    if (cm_dbs_map_set(file_path, &file_item, handle, DEV_TYPE_DBSTOR_FILE) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] map set item to handle failed");
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[CM_DEVICE_TEST] open file path %s success, handle %u", file_path, *handle);
    return CT_SUCCESS;
}

void cm_dbs_close_file(int32 handle)
{
    int32 tmp_handle = handle;
    if (handle == CT_INVALID_HANDLE) {
        return;
    }
    cm_dbs_map_remove(handle);
    CT_LOG_RUN_INF("[CM_DEVICE_TEST] close handle %u success", tmp_handle);
    return;
}

status_t cm_dbs_create_file_common(const char *name, uint32 file_type, int32 *handle)
{
    if (cm_check_file_path(name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    char file_path[MAX_DBS_FS_FILE_PATH_LEN] = { 0 };
    MEMS_RETURN_IFERR(strcpy_sp(file_path, MAX_DBS_FS_FILE_PATH_LEN, name));
    cm_remove_extra_delim(file_path, '/');

    int path_depth = 0;
    if (cm_get_file_path_depth(file_path, "/", &path_depth) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] get dbs file path %s depth failed", file_path);
        return CT_ERROR;
    }

    // 必须在已有文件系统下创建
    if (path_depth < 2) {
        CT_LOG_RUN_ERR("[CM_DEVICE] invalid path %s depth %u to create file", file_path, path_depth);
        return CT_ERROR;
    }

    char fs_name[MAX_DBS_FS_NAME_LEN] = { 0 };
    object_id_t root_obj_id = { 0 };
    if (cm_get_fs_name(file_path, "/", fs_name) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] get fs name failed, file path %s", file_path);
        return CT_ERROR;
    }
    status_t ret = dbs_global_handle()->dbs_file_open_root(fs_name, &root_obj_id);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] open fs root failed, ret %d, fs name %s", ret, fs_name);
        return CT_ERROR;
    }

    char *fix_file_path = cm_find_fix_delim(file_path, '/', 2);
    cm_dbs_map_item_s file_item = { 0 };
    ret = dbs_global_handle()->dbs_file_create_by_path(&root_obj_id, fix_file_path + 1, file_type, &file_item.obj_id);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] create file failed, ret %d, file path %s", ret, file_path);
        return CT_ERROR;
    }

    if (cm_dbs_map_set(file_path, &file_item, handle, DEV_TYPE_DBSTOR_FILE) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] map set item to handle failed");
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[CM_DEVICE_TEST] create file path %s success, handle %u", file_path, *handle);
    return CT_SUCCESS;
}

status_t cm_dbs_get_dir_handle(char *file_dir, uint32 dir_path_depth, object_id_t *obj_id)
{
    char fs_name[MAX_DBS_FS_NAME_LEN] = { 0 };
    if (cm_get_fs_name(file_dir, "/", fs_name) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[CM_DEVICE] begin to open root, file dir %s, fs_name %s", file_dir, fs_name);
    object_id_t root_obj_id = { 0 };
    status_t ret = dbs_global_handle()->dbs_file_open_root(fs_name, &root_obj_id);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] open fs root failed, ret %d, fs name %s", ret, fs_name);
        return CT_ERROR;
    }
    
    if (dir_path_depth == 1) {
        *obj_id = root_obj_id;
        return CT_SUCCESS;
    } 
    
    char *fix_file_path = cm_find_fix_delim(file_dir, '/', 2);
    ret = dbs_global_handle()->dbs_file_open_by_path(&root_obj_id, fix_file_path + 1, DIR_TYPE, obj_id);   
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] open file dir failed, ret %d, file dir %s", ret, file_dir);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cm_dbs_remove_file(const char *name)
{
    char file_path[MAX_DBS_FS_FILE_PATH_LEN] = { 0 };
    MEMS_RETURN_IFERR(strcpy_sp(file_path, MAX_DBS_FS_FILE_PATH_LEN, name));
    cm_remove_extra_delim(file_path, '/');

    if (cm_check_file_path(file_path) != CT_SUCCESS) {
        return CT_ERROR;
    }

    int path_depth = 0;
    if (cm_get_file_path_depth(file_path, "/", &path_depth) != CT_SUCCESS || path_depth <= 1) {
        CT_LOG_RUN_ERR("[CM_DEVICE] get dbs file path %s depth failed", file_path);
        return CT_ERROR;
    }
    if (path_depth < 2) {
        CT_LOG_RUN_INF("[CM_DEVICE] invalid file path %s", file_path);
        return CT_ERROR;
    }

    char file_name[MAX_DBS_FILE_NAME_LEN] = { 0 };
    char file_dir[MAX_DBS_FS_FILE_PATH_LEN] = { 0 };
    if (cm_get_file_name_and_dir(file_path, path_depth, "/", file_name, file_dir) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] get dbs file name and dir failed, file path %s", file_path);
        return CT_ERROR;
    }

    object_id_t dir_obj_id = { 0 };
    if (cm_dbs_get_dir_handle(file_dir, path_depth - 1, &dir_obj_id) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] get dbs file dir handle failed, file dir %s", file_dir);
        return CT_ERROR;
    }

    status_t ret = dbs_global_handle()->dbs_file_remove(&dir_obj_id, file_name);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] remove file failed, ret %d, file path %s", ret, file_path);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[CM_DEVICE_TEST] remove file success, file path %s", file_path);
    return CT_SUCCESS;
}

status_t cm_dbs_remove_dir(const char *name)
{
    return cm_dbs_remove_file(name);
}

status_t cm_dbs_open_fs(const char *name, int32 *root_handle) 
{
    if (cm_check_file_path(name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (strlen(name) >= MAX_DBS_FS_NAME_LEN) {
        CT_LOG_RUN_ERR("[CM_DEVICE] invalid fs name %s, len %lu", name, strlen(name));
        return CT_ERROR;
    }

    char fs_name[MAX_DBS_FS_NAME_LEN] = { 0 };
    MEMS_RETURN_IFERR(strcpy_sp(fs_name, MAX_DBS_FS_NAME_LEN, name));
    cm_remove_extra_delim(fs_name, '/');

    int path_depth = 0;
    if (cm_get_file_path_depth(fs_name, "/", &path_depth) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] get dbs file path %s depth failed", fs_name);
        return CT_ERROR;
    }
    if (path_depth != 1) {
        CT_LOG_RUN_ERR("[CM_DEVICE] invalid fs name %s", fs_name);
        return CT_ERROR;
    }

    if (cm_dbs_open_root(fs_name, root_handle) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE_TEST] open fs %s failed", fs_name);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[CM_DEVICE_TEST] open fs %s success", fs_name);
    return CT_SUCCESS;
}

status_t cm_dbs_create_file(const char *name, int32 *handle)
{
    return cm_dbs_create_file_common(name, FILE_TYPE, handle);
}

status_t cm_dbs_create_dir(const char *name, int32 *handle)
{
    return cm_dbs_create_file_common(name, DIR_TYPE, handle);
}

status_t cm_dbs_open_file(const char *name, int32 *handle)
{
    return cm_dbs_open_file_common(name, FILE_TYPE, handle);
}

status_t cm_dbs_open_dir(const char *name, int32 *handle)
{
    return cm_dbs_open_file_common(name, DIR_TYPE, handle);
}

status_t cm_do_dbs_file_read(object_id_t *obj_id, uint32_t offset, char *buf, uint32_t size, uint32 *real_read_size)
{
    int32 ret;
    for (uint32 i = 0; i < DBSTOR_RETRY_COUNT; i++)
    {
        ret = dbs_global_handle()->dbs_file_read(obj_id, offset, buf, size, real_read_size);
        if (ret != 0) {
            CT_LOG_RUN_ERR("[CM_DEVICE] Failed to read file count %d ret:%u.", i + 1, ret);
            continue;
        }
        return CT_SUCCESS;
    }
    return CT_ERROR;
    
}

status_t cm_dbs_read_file(int32 handle, int64 offset, const void *buf, int32 size, int32 *return_size)
{
    if (offset + size > DBSTOR_MAX_FILE_SIZE) {
        CT_LOG_RUN_ERR("[CM_DEVICE] invalid file offset %llu and size %d", offset, size);
        return CT_ERROR;
    }

    int32 already_r_size = 0;
    int32 read_size = 0;
    int64 read_offset = offset;
    char *read_buf = (char *)buf;
    int32 total_size = size;
    CT_LOG_RUN_INF("[CM_DEVICE] Begin to read file handle %d offset %lld size %d.", handle, offset, size);
    cm_dbs_map_item_s obj = { 0 };
    if (cm_dbs_map_get(handle, &obj) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] Failed to get dbstor file to read by handle(%d).", handle);
        return CT_ERROR;
    }
    uint32 real_read_size = 0;
    CT_LOG_RUN_INF("[CM_DEVICE] Success to get dbstor file to read by handle(%d).", handle);
    while (total_size > 0) {
        read_size = total_size > DBSTOR_MAX_RWBUF_SIZE ? DBSTOR_MAX_RWBUF_SIZE : total_size;
        real_read_size = 0;
        if(cm_do_dbs_file_read(&obj.obj_id, read_offset, read_buf, read_size, &real_read_size) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[CM_DEVICE] Failed to read file total_size: %d already read size: %d.", size, already_r_size);
            return CT_ERROR;
        }

        if (real_read_size == 0) {
            break;
        } 
        read_offset += real_read_size;
        read_buf += real_read_size;
        already_r_size += real_read_size;
        total_size -= real_read_size;
    }
    
    *return_size = already_r_size;
    CT_LOG_RUN_INF("[CM_DEVICE] Success to read file total_size: %d already read size: %d.", size, *return_size);
    return CT_SUCCESS;
}

status_t cm_do_dbs_file_write(object_id_t *obj_id, uint64 offset, char *buf, uint32 size)
{
    int32 ret;
    for (uint32 i = 0; i < DBSTOR_RETRY_COUNT; i++)
    {
        ret = dbs_global_handle()->dbs_file_write(obj_id, offset, buf, size);
        if (ret != 0) {
            CT_LOG_RUN_ERR("[CM_DEVICE] Failed to write file count %u ret:%u.", i + 1, ret);
            continue;
        }
        return CT_SUCCESS;
    }
    return CT_ERROR;
}

status_t cm_dbs_write_file(int32 handle, int64 offset, const void *buf, int32 size)
{
    if (offset + size > DBSTOR_MAX_FILE_SIZE) {
        CT_LOG_RUN_ERR("[CM_DEVICE] invalid file offset %llu and size %d", offset, size);
        return CT_ERROR;
    }

    int32 write_size = 0;
    int64 off = offset;
    int32 total_size = size;
    char *w_buf = (char *)buf;
    CT_LOG_RUN_INF("[CM_DEVICE] Begin to write file handle %d offset %lld size %d.", handle, offset, size);
    cm_dbs_map_item_s obj = { 0 };
    if (cm_dbs_map_get(handle, &obj) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] Failed to get dbstor file to write by handle(%d).", handle);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[CM_DEVICE] Success to get dbstor file to write by handle(%d).", handle);

    while (total_size > 0) {
        write_size = total_size > DBSTOR_MAX_RWBUF_SIZE ? DBSTOR_MAX_RWBUF_SIZE : total_size;
        if (cm_do_dbs_file_write(&obj.obj_id, off, w_buf, write_size) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[CM_DEVICE] Failed to write file total size: %d already write size: %d.",
                size, size - total_size);
            return CT_ERROR;
        }
        off += write_size;
        w_buf += write_size;
        total_size -= write_size;
    }

    CT_LOG_RUN_INF("[CM_DEVICE] Success to write file total_size %d offset %lld already write size %d.",
        size, off, size - total_size);
    return CT_SUCCESS;
}

status_t cm_dbs_rename_file(const char *src_name, const char *dst_name)
{
    if (cm_check_file_path(src_name) != CT_SUCCESS || cm_check_file_path(dst_name) != CT_SUCCESS) {
        return CT_FALSE;
    }

    char src_path[MAX_DBS_FS_FILE_PATH_LEN] = { 0 };
    char dst_path[MAX_DBS_FS_FILE_PATH_LEN] = { 0 };
    MEMS_RETURN_IFERR(strcpy_sp(src_path, MAX_DBS_FS_FILE_PATH_LEN, src_name));
    cm_remove_extra_delim(src_path, '/');
    MEMS_RETURN_IFERR(strcpy_sp(dst_path, MAX_DBS_FS_FILE_PATH_LEN, dst_name));
    cm_remove_extra_delim(dst_path, '/');
    int src_path_depth = 0;
    int dst_path_depth = 0;
    if (cm_get_file_path_depth(src_path, "/", &src_path_depth) != CT_SUCCESS || src_path_depth <= 1) {
        CT_LOG_RUN_ERR("[CM_DEVICE] get dbs file path %s depth failed", src_path);
        return CT_FALSE;
    }
    if (cm_get_file_path_depth(dst_path, "/", &dst_path_depth) != CT_SUCCESS || dst_path_depth <= 1) {
        CT_LOG_RUN_ERR("[CM_DEVICE] get dbs file path %s depth failed", dst_path);
        return CT_FALSE;
    }

     if (!cm_dbs_exist_file(src_path, DIR_TYPE) && !cm_dbs_exist_file(src_path, FILE_TYPE)) {
        CT_LOG_RUN_ERR("[CM_DEVICE] file or dir path %s is not exist", src_path);
        return CT_ERROR;
     }

    char src_file_name[MAX_DBS_FILE_NAME_LEN] = { 0 };
    char src_file_dir[MAX_DBS_FS_FILE_PATH_LEN] = { 0 };
    char dst_file_name[MAX_DBS_FILE_NAME_LEN] = { 0 };
    char dst_file_dir[MAX_DBS_FS_FILE_PATH_LEN] = { 0 };
    if (cm_get_file_name_and_dir(src_path, src_path_depth, "/", src_file_name, src_file_dir) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] get dbs src file name and dir failed, file path %s", src_path);
        return CT_ERROR;
    }
    if (cm_get_file_name_and_dir(dst_path, dst_path_depth, "/", dst_file_name, dst_file_dir) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] get dbs dst file name and dir failed, file path %s", dst_path);
        return CT_ERROR;
    }

    if (strcmp(dst_file_dir, src_file_dir) != 0 || strcmp(dst_file_name, src_file_name) == 0) {
        CT_LOG_RUN_ERR("[CM_DEVICE] invalid src file path %s and dst file path %s", src_path, dst_path);
        return CT_ERROR;
    }

    object_id_t dir_obj_id = { 0 };
    if (cm_dbs_get_dir_handle(dst_file_dir, dst_path_depth - 1, &dir_obj_id) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] get dbs file dir handle failed, file dir %s", dst_file_dir);
        return CT_ERROR;
    }

    status_t ret = dbs_global_handle()->dbs_file_rename(&dir_obj_id, src_file_name, dst_file_name);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] rename %s to %s failed, file dir %s", src_file_name, dst_file_name, dst_file_dir);
        return CT_ERROR;
    }

    CT_LOG_RUN_INF("[CM_DEVICE] rename %s to %s success, file dir %s", src_file_name, dst_file_name, dst_file_dir);
    return CT_SUCCESS;
}

bool32 cm_dbs_exist_file(const char *name, uint32 file_type)
{
    if (cm_check_file_path(name) != CT_SUCCESS) {
        return CT_FALSE;
    }

    char file_path[MAX_DBS_FS_FILE_PATH_LEN] = { 0 };
    MEMS_RETURN_IFERR(strcpy_sp(file_path, MAX_DBS_FS_FILE_PATH_LEN, name));
    cm_remove_extra_delim(file_path, '/');

    int path_depth = 0;
    if (cm_get_file_path_depth(file_path, "/", &path_depth) != CT_SUCCESS || path_depth < 1) {
        CT_LOG_RUN_ERR("[CM_DEVICE] get dbs file path %s depth failed", file_path);
        return CT_FALSE;
    }

    char fs_name[MAX_DBS_FS_NAME_LEN] = { 0 };
    if (cm_get_fs_name(file_path, "/", fs_name) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] get fs name failed, file path %s", file_path);
        return CT_FALSE;
    }
    object_id_t root_obj_id = { 0 };
    status_t ret = dbs_global_handle()->dbs_file_open_root(fs_name, &root_obj_id);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] open fs root failed, ret %d, fs name %s", ret, fs_name);
        return CT_FALSE;
    }
    if (path_depth == 1) {
        return CT_TRUE;
    }

    char *fix_file_path = cm_find_fix_delim(file_path, '/', 2);
    object_id_t file_obj_id = { 0 };
    ret = dbs_global_handle()->dbs_file_open_by_path(&root_obj_id, fix_file_path + 1, file_type, &file_obj_id);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_INF("[CM_DEVICE] file probably does not exist, ret %d, file path %s", ret, file_path);
        return CT_FALSE;
    }

    return CT_TRUE;
}

status_t cm_dbs_access_file(const char *name, int32 *handle)
{
    return cm_dbs_open_file(name, handle);
}

status_t cm_dbs_query_dir(const char *name, void *file_list, uint32 *file_num)
{
    CT_LOG_RUN_INF("[CM_DEVICE] begin to get file list, file dir %s", name);
    char file_dir[MAX_DBS_FILE_PATH_LEN] = { 0 };
    MEMS_RETURN_IFERR(strcpy_sp(file_dir, MAX_DBS_FILE_PATH_LEN, name));
    cm_remove_extra_delim(file_dir, '/');
    if (cm_check_file_path(file_dir) != CT_SUCCESS) {
        return CT_ERROR;
    }

    int path_depth = 0;
    if (cm_get_file_path_depth(file_dir, "/", &path_depth) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] get dbs file dir %s depth failed", file_dir);
        return CT_ERROR;
    }

    object_id_t dir_obj_id = { 0 };
    if (cm_dbs_get_dir_handle(file_dir, path_depth, &dir_obj_id) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] get dbs file dir handle failed, file dir %s", file_dir);
        return CT_ERROR;
    }

    int32 ret = dbs_global_handle()->dbs_file_get_list(&dir_obj_id, file_list, file_num);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] Failed to get file list, ret %d, file dir %s", ret, file_dir);
        return CT_ERROR;
    }

    CT_LOG_RUN_INF("[CM_DEVICE] Success to get file list, file_num %u, file dir %s", *file_num, file_dir);
    return CT_SUCCESS;
}

status_t cm_dbs_get_file_size(int32 handle, int64 *file_size)
{
    uint64 size = 0;
    if (handle == CT_INVALID_HANDLE) {
        CT_LOG_RUN_ERR("[CM_DEVICE] Invalid handle %d", handle);
        return CT_ERROR;
    }

    cm_dbs_map_item_s item = { 0 };
    if (cm_dbs_map_get(handle, &item) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] Failed to get dbstor file to get file size by handle(%d).", handle);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[CM_DEVICE] Success to get dbstor file to get file size by handle(%d).", handle);

    int32 ret = dbs_global_handle()->dbs_get_file_size(&item.obj_id, &size);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_DEVICE] Failed to get file size, ret %d, handle %d", ret, handle);
        return CT_ERROR;
    }

    *file_size = (int64)size;
    return CT_SUCCESS;
}

status_t cm_dbs_ulog_archive(int32 src_file, int32 dst_file, uint64 offset, uint64 start_lsn,
                             uint64 arch_size, uint64 *real_arch_size, uint64 *last_lsn)
{
    if (src_file == CT_INVALID_HANDLE || dst_file == CT_INVALID_HANDLE) {
        CT_LOG_RUN_ERR("[CM_ARCH] invalid file handle, src %d, dst %d", src_file, dst_file);
        return CT_ERROR;
    }

    if (offset + arch_size > DBSTOR_MAX_FILE_SIZE) {
        CT_LOG_RUN_ERR("[CM_ARCH] invalid file offset %llu and arch_size %llu", offset, arch_size);
        return CT_ERROR;
    }

    cm_dbs_map_item_s src_item = { 0 };
    if (cm_dbs_map_get(src_file, &src_item) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_ARCH] Failed to get dbstor object id by handle(%d).", src_file);
        return CT_ERROR;
    }
    cm_dbs_map_item_s dst_item = { 0 };
    if (cm_dbs_map_get(dst_file, &dst_item) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_ARCH] Failed to get dbstor object id by handle(%d).", dst_file);
        return CT_ERROR;
    }

    ulog_archive_option_t option = { offset, arch_size, start_lsn };
    ulog_archive_result_t result = { 0 };
    int32 ret = dbs_global_handle()->dbs_ulog_archive(&src_item.obj_id, &dst_item.obj_id, &option, &result);
    if (ret == DBSTOR_ULOG_ARCHIVE_END) {
        CT_LOG_RUN_WAR("[CM_ARCH] redo log has been archived to the end, ret %d, offset %llu, start lsn %llu", 
                       ret, offset, start_lsn);
        *real_arch_size = 0;
        return CT_SUCCESS;
    }
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CM_ARCH] Failed to arch redo log, ret %d, offset %llu, start lsn %llu",
                       ret, offset, start_lsn);
        return CT_ERROR;
    }
    *last_lsn = result.end_lsn;
    *real_arch_size = result.real_len;
    CT_LOG_RUN_INF("[CM_ARCH] ulog archive redo successful, offset %llu, start lsn %llu, "
                   "last lsn %llu, real_arch_size %llu.", offset, start_lsn, *last_lsn, *real_arch_size);
    return CT_SUCCESS;
}