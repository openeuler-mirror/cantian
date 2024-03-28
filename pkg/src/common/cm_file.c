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
 * cm_file.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_file.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "cm_file.h"
#include "cm_log.h"
#include "cm_system.h"
#include "cm_date.h"
#include "cm_dbstore.h"

#ifdef WIN32
#else
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <poll.h>
#endif

#ifndef CM_FALLOC_KEEP_SIZE
#define CM_FALLOC_KEEP_SIZE 0x01
#endif
#ifndef CM_FALLOC_PUNCH_HOLE
#define CM_FALLOC_PUNCH_HOLE 0x02
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define CT_WRITE_BUFFER_SIZE SIZE_M(2)

#define IS_DIR_SEPARATOR(c)	((c) == '/' || (c) == '\\')

/*
 * On Windows, a path may begin with "X:" or "//network/". Skip these and point to the effective start.
 */
#ifdef WIN32
static char *cm_skip_drive(const char *path)
{
    if (IS_DIR_SEPARATOR(path[0]) && IS_DIR_SEPARATOR(path[1])) {
        path += strlen("\\");
        while (*path && !IS_DIR_SEPARATOR(*path)) {
            path++;
        }
    } else if (isalpha((unsigned char)path[0]) && path[1] == ':') {
        path += strlen("X:");
    }
    return (char *)path;
}
#else
#define cm_skip_drive(path)	(path)
#endif

status_t cm_fsync_file(int32 file)
{
#ifndef WIN32
    if (fsync(file) != 0) {
        CT_THROW_ERROR(ERR_DATAFILE_FSYNC, errno);
        return CT_ERROR;
    }
#endif

    return CT_SUCCESS;
}

status_t cm_fdatasync_file(int32 file)
{
#ifndef WIN32
    if (fdatasync(file) != 0) {
        CT_THROW_ERROR(ERR_DATAFILE_FDATASYNC, errno);
        return CT_ERROR;
    }
#endif

    return CT_SUCCESS;
}

// file name could not include black space before string on windows, auto-remove it
status_t cm_open_file(const char *file_name, uint32 mode, int32 *file)
{
    uint32 perm = ((mode & O_CREAT) != 0) ? S_IRUSR | S_IWUSR : 0;

    if (strlen(file_name) > CT_MAX_FILE_NAME_LEN) {
        CT_THROW_ERROR(ERR_INVALID_FILE_NAME, file_name, (uint32)CT_MAX_FILE_NAME_LEN);
        return CT_ERROR;
    }

    *file = open(file_name, (int)mode, perm);

    if ((*file) == -1) {
        if ((mode & O_CREAT) != 0) {
            CT_THROW_ERROR(ERR_CREATE_FILE, file_name, errno);
        } else {
            CT_THROW_ERROR(ERR_OPEN_FILE, file_name, errno);
        }
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_reopen_file(int fd, const char* file_name, int* out_fd)
{
    int32 old_fd = fd;
    int32 new_fd = -1;
    status_t ret = cm_open_file(file_name,
                                O_CREAT | O_RDWR | O_NONBLOCK | O_NDELAY | O_BINARY | O_CLOEXEC | O_SYNC | O_DIRECT,
                                &new_fd);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("open file %s failed, error code %d.", file_name, errno);
        return CT_ERROR;
    }
    cm_close_file(old_fd);
    *out_fd = new_fd;
    CT_LOG_RUN_INF("reopen file %s success, old_fd %d new_fd %d.", file_name, old_fd, new_fd);
    return CT_SUCCESS;
}

/* 获取文件名file_name的层级数，delim为层级的分割符.例如：file_name为"/a/b/c/d"， 分割数为"/"， 层级数为4级 */
status_t cm_get_file_path_depth(const char* file_name, const char* delim, int* depth)
{
    if (file_name == NULL || delim == NULL || depth == NULL) {
        CT_LOG_RUN_ERR("get file path depth failed, invalid param.");
        return CT_ERROR;
    }
    if (strlen(file_name) == 0 || strlen(delim) == 0) {
        CT_LOG_RUN_ERR("get file path depth failed, file name or delim is invalid.");
        return CT_ERROR;
    }
    char file[CT_FILE_NAME_BUFFER_SIZE] = {0};
    char* token = NULL;
    char* context = NULL;
    errno_t err = strcpy_sp(file, CT_MAX_FILE_NAME_LEN, file_name);
    if (err != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        CT_LOG_RUN_ERR("Secure C lib has thrown an error %d", (err));
        return CT_ERROR;
    }
    *depth = 0;
    token = strtok_s(file, delim, &context);
    while (token != NULL) {
        (*depth)++;
        token = strtok_s(NULL, delim, &context);
    }
    return CT_SUCCESS;
}

/* 获取路径中最后一层的文件名，delim为层级的分割符.例如：file_name为"/a/b/c/d"， 分割数为'/'， 层级数为4级 */
status_t cm_get_path_file_name(const char* path, char* file_name, uint32 name_len)
{
    if (path == NULL || file_name == NULL) {
        CT_LOG_RUN_ERR("get path file name failed, invalid param.");
        return CT_ERROR;
    }
    char* p = strrchr(path, '/');
    const char* s = (p == NULL ? path : p + 1); // p == NULL说明path就是name
    errno_t err = strcpy_sp(file_name, name_len, s);
    if (err != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        CT_LOG_RUN_ERR("Secure C lib has thrown an error %d", (err));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

/* root目录是新建在fs目录下 */
status_t cm_get_dbs_root_dir_handle(char* fs_name, object_id_t* root_handle)
{
    int ret = 0;
    if (fs_name == NULL || root_handle == NULL) {
        CT_LOG_RUN_ERR("get dbstore root dir fd failed, invalid param.");
        return CT_ERROR;
    }

    // 先尝试打开再创建根目录
    ret = dbs_global_handle()->dbs_file_open_root(fs_name, root_handle);
    if (ret != 0) {
        CT_LOG_RUN_ERR("Failed(%d) open fs (%s) root dir.", ret, fs_name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/* 目录是新建在root目录下 */
status_t cm_get_dbs_dir_handle(object_id_t* phandle, char* dir_name, object_id_t* handle)
{
    int ret = 0;
    if (phandle == NULL || dir_name == NULL || handle == NULL) {
        CT_LOG_RUN_ERR("get dbstore dir handle failed, invalid param.");
        return CT_ERROR;
    }
    ret = dbs_global_handle()->dbs_file_open(phandle, dir_name, DIR_TYPE, handle);
    if (ret != 0) {
        ret = dbs_global_handle()->dbs_file_create(phandle, dir_name, DIR_TYPE, handle);
        CT_LOG_RUN_INF("dir(%s) not exist, new create.", dir_name);
    }

    return (ret == 0 ? CT_SUCCESS : CT_ERROR);
}

status_t cm_open_dbs_dir_handle(object_id_t* phandle, char* dir_name, object_id_t* handle)
{
    int ret = 0;
    if (phandle == NULL || dir_name == NULL || handle == NULL) {
        CT_LOG_RUN_ERR("get dbstore dir handle failed, invalid param.");
        return CT_ERROR;
    }
    ret = dbs_global_handle()->dbs_file_open(phandle, dir_name, DIR_TYPE, handle);
    return (ret == 0 ? CT_SUCCESS : CT_ERROR);
}

/* 文件是新建在目录下 */
status_t cm_get_dbs_file_handle(object_id_t* phandle, char* file_name, object_id_t* handle)
{
    int ret = 0;
    if (phandle == NULL || file_name == NULL || handle == NULL) {
        CT_LOG_RUN_ERR("get dbstore file handle failed, invalid param.");
        return CT_ERROR;
    }

    // 先打开再创建文件
    ret = dbs_global_handle()->dbs_file_open(phandle, file_name, FILE_TYPE, handle);
    if (ret != 0) {
        ret = dbs_global_handle()->dbs_file_create(phandle, file_name, FILE_TYPE, handle);
        CT_LOG_RUN_INF("file_name(%s) not exist, new create.", file_name);
    }

    return (ret == 0 ? CT_SUCCESS : CT_ERROR);
}

/* 重新打开文件获取句柄信息 */
status_t cm_open_dbs_file(object_id_t* pHandle, char* file, object_id_t* handle)
{
    status_t ret;
    char file_name[CT_FILE_NAME_BUFFER_SIZE] = {0};
    if (pHandle == NULL || file == NULL || handle == NULL) {
        CT_LOG_RUN_ERR("get dbstore file fd failed, invalid param.");
        return CT_ERROR;
    }
    ret = cm_get_path_file_name(file, file_name, CT_FILE_NAME_BUFFER_SIZE);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("get path from file(%s) failed.", file);
        return CT_ERROR;
    }

    // 打开文件
    int err = dbs_global_handle()->dbs_file_open(pHandle, file_name, FILE_TYPE, handle);
    if (err != 0) {
        CT_LOG_RUN_ERR("dbs open file_name(%s) failed.", file_name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/* 获取文件路径上各级目录和文件的句柄 path格式：/fs_name/cluster_name_cms/gcc_home/file_name; 它是一个文件的全路径名. */
status_t cm_get_dbs_file_path_handle(const char* path, const char* delim, object_id_t* handle_ids, int handle_len)
{
    if (path == NULL || handle_ids == NULL || handle_len == 0) {
        CT_LOG_RUN_ERR("get dbstore file path fd failed, invalid param.");
        return CT_ERROR;
    }
    char* token = NULL;
    char* context = NULL;
    char file[CT_FILE_NAME_BUFFER_SIZE] = {0};
    char fs_name[CT_FILE_NAME_BUFFER_SIZE] = {0};
    int cur_depth = 0;
    errno_t err = strcpy_sp(file, CT_MAX_FILE_NAME_LEN, path);
    if (err != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        CT_LOG_RUN_ERR("Secure C lib has thrown an error %d", (err));
        return CT_ERROR;
    }
    token = strtok_s(file, delim, &context);
    while (token != NULL) {
        if (cur_depth >= handle_len) {
            CT_LOG_RUN_ERR("get dbs file(%s) fd failed, fd len exceed (%d - %d).", path, handle_len, cur_depth);
            return CT_ERROR;
        }
        if (cur_depth == 0) { // token中保存的是根目录名
            MEMS_RETURN_IFERR(strcpy_sp(fs_name, CT_MAX_FILE_NAME_LEN, token));
            if (cm_get_dbs_root_dir_handle(fs_name, &handle_ids[cur_depth]) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("get dbstore fs(%s) root dir(%s) fd failed.", fs_name, token);
                return CT_ERROR;
            }
        } else if (cur_depth < handle_len - 1) { // token中保存的是目录名
            if (cm_get_dbs_dir_handle(&handle_ids[cur_depth - 1], token, &handle_ids[cur_depth]) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("get dbstore fs(%s) dir(%s) fd failed.", fs_name, token);
                return CT_ERROR;
            }
        } else if (cur_depth == handle_len - 1) { // token中保存的是文件名
            if (cm_get_dbs_file_handle(&handle_ids[cur_depth - 1], token, &handle_ids[cur_depth]) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("get dbstore fs(%s) file(%s) fd failed.", fs_name, token);
                return CT_ERROR;
            }
        }
        cur_depth++;
        token = strtok_s(NULL, delim, &context);
    }
    return CT_SUCCESS;
}

/* 获取dbs文件路径中最后一级文件(xxx_file)对应的句柄, file格式:/fs_name/cluster_name_cms/gcc_home/xxx_file */
status_t cm_get_dbs_last_file_handle(const char* file, object_id_t* last_handle)
{
    errno_t ret = 0;
    int path_depth = 0;
    if (cm_get_file_path_depth(file, "/", &path_depth) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("get dbstore file(%s) path depth failed.", file);
        return CT_ERROR;
    }
    object_id_t* handle = (object_id_t *)malloc((path_depth + 1) * sizeof(object_id_t));
    if (handle == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)((path_depth + 1) * sizeof(object_id_t)), "dbs file fd");
        return CT_ERROR;
    }
    if (cm_get_dbs_file_path_handle(file, "/", handle, path_depth) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("get dbstore file path fd failed, file %s, ret %d", file, ret);
        CM_FREE_PTR(handle);
        return CT_ERROR;
    }
    ret = memcpy_s((void *)last_handle, sizeof(object_id_t), (void *)&handle[path_depth - 1], sizeof(object_id_t));
    if (ret != EOK) {
        CM_FREE_PTR(handle);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        CT_LOG_RUN_ERR("Secure C lib has thrown an error %d", ret);
        return CT_ERROR;
    }
    CM_FREE_PTR(handle);
    return CT_SUCCESS;
}

/* 获取全目录路径的句柄.path格式：/fs_name/cluster_name_cms/gcc_home; 它是一个目录的全路径名，其中fs_name为文件系统名 */
status_t cm_get_dbs_full_dir_handle(const char* path, const char* delim, object_id_t* handle_ids, int handle_len)
{
    if (path == NULL || handle_ids == NULL || handle_len == 0) {
        CT_LOG_RUN_ERR("get dbstore file path fd failed, invalid param.");
        return CT_ERROR;
    }
    char* token = NULL;
    char* context = NULL;
    char file[CT_FILE_NAME_BUFFER_SIZE] = {0};
    char fs_name[CT_FILE_NAME_BUFFER_SIZE] = {0};
    int cur_depth = 0;
    errno_t err = strcpy_sp(file, CT_MAX_FILE_NAME_LEN, path);
    if (err != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        CT_LOG_RUN_ERR("Secure C lib has thrown an error %d", (err));
        return CT_ERROR;
    }
    token = strtok_s(file, delim, &context);
    while (token != NULL) {
        if (cur_depth >= handle_len) {
            CT_LOG_RUN_ERR("get dbstore file(%s) fd failed, fd len exceed (%d - %d).", path, handle_len, cur_depth);
            return CT_ERROR;
        }
        if (cur_depth == 0) {
            MEMS_RETURN_IFERR(strcpy_sp(fs_name, CT_MAX_FILE_NAME_LEN, token));
            if (cm_get_dbs_root_dir_handle(fs_name, &handle_ids[cur_depth]) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("get dbstore fs(%s) root dir(%s) fd failed.", fs_name, token);
                return CT_ERROR;
            }
        } else if (cur_depth <= handle_len - 1) { // token中保存的是目录名
            if (cm_get_dbs_dir_handle(&handle_ids[cur_depth - 1], token, &handle_ids[cur_depth]) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("get dbstore fs(%s) dir(%s) fd failed.", fs_name, token);
                return CT_ERROR;
            }
        }
        cur_depth++;
        token = strtok_s(NULL, delim, &context);
    }
    return CT_SUCCESS;
}

/* 获取dbs文件路径中最后一级目录对应的句柄, file格式:/fs_name/cluster_name_cms/gcc_home */
status_t cm_get_dbs_last_dir_handle(const char* file, object_id_t* last_handle)
{
    errno_t ret = 0;
    int path_depth = 0;
    if (cm_get_file_path_depth(file, "/", &path_depth) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("get dbstore file(%s) path depth failed.", file);
        return CT_ERROR;
    }
    object_id_t* handle = (object_id_t *)malloc((path_depth + 1) * sizeof(object_id_t));
    if (handle == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)((path_depth + 1) * sizeof(object_id_t)), "dbs file fd");
        return CT_ERROR;
    }
    if (cm_get_dbs_full_dir_handle(file, "/", handle, path_depth) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("get dbstore file path fd failed, file %s, ret %d", file, ret);
        CM_FREE_PTR(handle);
        return CT_ERROR;
    }
    ret = memcpy_s((void *)last_handle, sizeof(object_id_t), (void *)&handle[path_depth - 1], sizeof(object_id_t));
    if (ret != EOK) {
        CM_FREE_PTR(handle);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        CT_LOG_RUN_ERR("Secure C lib has thrown an error %d", ret);
        return CT_ERROR;
    }
    CM_FREE_PTR(handle);
    return CT_SUCCESS;
}

status_t cm_rm_dbs_dir_file(object_id_t* phandle, char* name)
{
    int ret = 0;
    if (phandle == NULL || name == NULL) {
        CT_LOG_RUN_ERR("delete dbstore file or dir failed, invalid param.");
        return CT_ERROR;
    }

    // 先打开再创建文件
    ret = dbs_global_handle()->dbs_file_remove(phandle, name);
    if (ret != 0) {
        CT_LOG_RUN_ERR("Failed(%d) delete file or dir(%s).", ret, name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_chmod_file(uint32 perm, int32 fd)
{
#ifndef WIN32
    int32 err_no = fchmod(fd, perm);
    if (err_no != 0) {
        CT_THROW_ERROR(ERR_CREATE_FILE, "", err_no);
        return CT_ERROR;
    }
#endif  // !WIN32
    return CT_SUCCESS;
}

status_t cm_fopen(const char *filename, const char *mode, uint32 perm, FILE **fp)
{
    *fp = fopen(filename, mode);
    if (*fp == NULL) {
        CT_THROW_ERROR(ERR_OPEN_FILE, filename, errno);
        return CT_ERROR;
    }
#ifndef WIN32
    int32 err_no = fchmod(cm_fileno(*fp), perm);
    if (err_no != 0) {
        fclose(*fp);
        *fp = NULL;
        CT_THROW_ERROR(ERR_OPEN_FILE, filename, err_no);
        return CT_ERROR;
    }
#endif  // !WIN32

    return CT_SUCCESS;
}

status_t cm_open_file_ex(const char *file_name, uint32 mode, uint32 perm, int32 *file)
{
    if (strlen(file_name) > CT_MAX_FILE_NAME_LEN) {
        CT_THROW_ERROR(ERR_INVALID_FILE_NAME, file_name, (uint32)CT_MAX_FILE_NAME_LEN);
        return CT_ERROR;
    }

    *file = open(file_name, (int)mode, perm);

    if ((*file) == -1) {
        if ((mode & O_CREAT) != 0) {
            CT_THROW_ERROR(ERR_CREATE_FILE, file_name, errno);
        } else {
            CT_THROW_ERROR(ERR_OPEN_FILE, file_name, errno);
        }
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_create_file(const char *file_name, uint32 mode, int32 *file)
{
    return cm_open_file(file_name, mode | O_CREAT | O_TRUNC, file);
}

void cm_close_file(int32 file)
{
    int32 ret;

    if (file == -1) {
        return;
    }

    ret = close(file);
    if (ret != 0) {
        CT_LOG_RUN_ERR("failed to close file with handle %d, error code %d", file, errno);
    }
}

status_t cm_read_file(int32 file, void *buf, int32 len, int32 *read_size)
{
    int32 total_size = 0;
    int32 curr_size = 0;
    int32 size = len;
    do {
        curr_size = read(file, (char *)buf + total_size, size);
        if (curr_size == -1) {
            CT_THROW_ERROR(ERR_READ_FILE, errno);
            CT_LOG_RUN_ERR("read failed:error code:%d,%s", errno, strerror(errno));
            return CT_ERROR;
        }
        size -= curr_size;
        total_size += curr_size;
    } while (size > 0 && curr_size > 0);

    if (read_size != NULL) {
        *read_size = total_size;
    }

    return CT_SUCCESS;
}

int32 cm_read_dbs_file(object_id_t* phandle, char *file_name, uint32 offset, void* buf, uint32 length)
{
    int64 start = cm_now();
    object_id_t handle;
    int32 ret =  dbs_global_handle()->dbs_file_open(phandle, file_name, FILE_TYPE, &handle);
    if (ret != 0) {
        CT_THROW_ERROR(ERR_OPEN_FILE, ret);
        CT_LOG_RUN_ERR("cm_read_dbs_file get file %s handle failed.", file_name);
        return ret;
    }

    ret = dbs_global_handle()->dbs_file_read(&handle, offset, (char *)buf, length);
    if (ret != 0) {
        CT_THROW_ERROR(ERR_READ_FILE, ret);
        CT_LOG_RUN_ERR("cm_read_dbs_file file %s offset:%u len:%u failed.", file_name, offset, length);
        return ret;
    }

    int64 end = cm_now();
    if (end - start > 50 * MICROSECS_PER_MILLISEC) {
        CT_LOG_RUN_WAR_LIMIT(LOG_PRINT_INTERVAL_SECOND_20, "cm_read_dbs_file %u elapsed:%lld(ms)",
                             length, (end - start) / MICROSECS_PER_MILLISEC);
    }
    return ret;
}

status_t cm_write_dbs_file(object_id_t* phandle, char *file_name, uint32 offset, void* buf, uint32 length)
{
    int64 start = cm_now();
    object_id_t handle;
    int32 ret =  dbs_global_handle()->dbs_file_open(phandle, file_name, FILE_TYPE, &handle);
    if (ret != 0) {
        CT_THROW_ERROR(ERR_OPEN_FILE, ret);
        CT_LOG_RUN_ERR("cm_write_dbs_file get file %s handle failed.", file_name);
        return CT_ERROR;
    }
    ret = dbs_global_handle()->dbs_file_write(&handle, offset, (char *)buf, length);
    if (ret != 0) {
        CT_THROW_ERROR(ERR_WRITE_FILE, ret);
        CT_LOG_RUN_ERR("cm_write_dbs_file write file %s offset:%u len:%u failed.", file_name, offset, length);
        return CT_ERROR;
    }

    int64 end = cm_now();
    if (end - start > 50 * MICROSECS_PER_MILLISEC) {
        CT_LOG_RUN_WAR_LIMIT(LOG_PRINT_INTERVAL_SECOND_20, "cm_write_dbs_file %u elapsed:%lld(ms)",
                             length, (end - start) / MICROSECS_PER_MILLISEC);
    }
    return CT_SUCCESS;
}

status_t cm_io_poll(int32 fd, uint32 wait_type, int32 timeout_ms)
{
    struct pollfd fds = {0};
    int32 tv = (timeout_ms < 0 ? -1 : timeout_ms);
    fds.fd = fd;
    fds.events = (wait_type == FILE_WAIT_FOR_READ ? POLLIN : POLLOUT);
    fds.revents = 0;
    int32 ret = poll(&fds, 1, tv);
    if (ret <= 0) {
        CT_LOG_RUN_WAR("listen fd(%d) event_type(%u) failed(%d) errno(%d).", fd, wait_type, ret, errno);
    }
    return (ret > 0 ? CT_SUCCESS : CT_ERROR);
}

status_t cm_read_file_try_timeout(const char* file_name, int32* fd, void *buf, int32 len, int32 timeout_ms)
{
    int32 try_times = 0;
    int32 cur_fd = *fd;
    int32 read_size = 0;
    int64 start_time = cm_now();
    int64 timeo_us = (int64)(timeout_ms * MICROSECS_PER_MILLISEC);
    status_t ret = CT_SUCCESS;
    do {
        ret = cm_io_poll(cur_fd, FILE_WAIT_FOR_READ, FILE_POLL_TIMEOUT_MS);
        if (ret != CT_SUCCESS) {
            if (++try_times >= CT_WRITE_TRY_TIMES) {
                cm_reopen_file(cur_fd, file_name, &cur_fd);
            }
            cm_sleep(REOPEN_SLEEP_TIMES);
            continue;
        }
        try_times = 0;
        ret = cm_read_file(cur_fd, buf, len, &read_size);
        if (ret != CT_SUCCESS) {
            if (++try_times >= CT_WRITE_TRY_TIMES) {
                cm_reopen_file(cur_fd, file_name, &cur_fd);
            }
            cm_sleep(REOPEN_SLEEP_TIMES);
            continue;
        }
        try_times = 0;
    } while (start_time + timeo_us >= cm_now() && ret != CT_SUCCESS);
    if (read_size != len) {
        CT_LOG_RUN_WAR("read file (%s) fd(%d-%d) size(%d) neq size(%d).", file_name, cur_fd, *fd, read_size, len);
    }
    *fd = cur_fd;
    return ret;
}

status_t cm_write_file(int32 file, const void *buf, int32 size)
{
    int32 write_size = 0;
    int32 try_times = 0;

    while (try_times < CT_WRITE_TRY_TIMES) {
        write_size = write(file, buf, size);
        if (write_size == 0) {
            cm_sleep(5);
            try_times++;
            continue;
        } else if (write_size == -1) {
            CT_THROW_ERROR(ERR_WRITE_FILE, errno);
            CT_LOG_RUN_ERR("write failed:error code:%d,%s", errno, strerror(errno));
            return CT_ERROR;
        } else {
            break;
        }
    }

    if (write_size != size) {
        CT_THROW_ERROR(ERR_WRITE_FILE_PART_FINISH, write_size, size);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_pread_file(int32 file, void *buf, int length, int64 i_offset, int32 *read_size)
{
#ifdef WIN32
    if (cm_seek_file(file, offset, SEEK_SET) != offset) {
        CT_THROW_ERROR(ERR_SEEK_FILE, offset, SEEK_SET, errno);
        return CT_ERROR;
    }

    if (cm_read_file(file, buf, size, read_size) != CT_SUCCESS) {
        return CT_ERROR;
    }
#else
    int32 curr_size;
    int32 total_size = 0;
    int64 offset = i_offset;
    int size = length;
    do {
        curr_size = pread64(file, (char *)buf + total_size, size, offset);
        if (curr_size == -1) {
            CT_THROW_ERROR(ERR_READ_FILE, errno);
            return CT_ERROR;
        }

        total_size += curr_size;
        offset += curr_size;
        size -= curr_size;
    } while (size > 0 && curr_size > 0);

    if (read_size != NULL) {
        *read_size = total_size;
    }
#endif
    return CT_SUCCESS;
}

status_t cm_pwrite_file(int32 file, const char *buf, int32 size, int64 offset)
{
#ifdef WIN32
    if (cm_seek_file(file, offset, SEEK_SET) != offset) {
        CT_THROW_ERROR(ERR_SEEK_FILE, offset, SEEK_SET, errno);
        return CT_ERROR;
    }

    if (cm_write_file(file, buf, size) != CT_SUCCESS) {
        return CT_ERROR;
    }
#else
    int32 write_size;
    int32 try_times = 0;

    while (try_times < CT_WRITE_TRY_TIMES) {
        write_size = pwrite64(file, buf, size, offset);
        if (write_size == 0) {
            cm_sleep(5);
            try_times++;
            continue;
        } else if (write_size == -1) {
            CT_THROW_ERROR(ERR_WRITE_FILE, errno);
            return CT_ERROR;
        } else {
            break;
        }
    }

    if (write_size != size) {
        CT_THROW_ERROR(ERR_WRITE_FILE_PART_FINISH, write_size, size);
        return CT_ERROR;
    }
#endif
    return CT_SUCCESS;
}

int64 cm_seek_file(int32 file, int64 offset, int32 origin)
{
    return (int64)lseek64(file, (off64_t)offset, origin);
}

status_t cm_check_file(const char *name, int64 size)
{
    int32 file;
    if (cm_open_file(name, O_BINARY | O_RDONLY, &file) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (size != cm_seek_file(file, 0, SEEK_END)) {
        cm_close_file(file);
        CT_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_SET, errno);
        return CT_ERROR;
    }

    cm_close_file(file);
    return CT_SUCCESS;
}

status_t cm_create_dir(const char *dir_name)
{
    if (make_dir(dir_name, S_IRWXU) != 0) {
        CT_THROW_ERROR(ERR_CREATE_DIR, dir_name, errno);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_rename_file(const char *src, const char *dst)
{
#ifdef WIN32
    uint32 loop = 0;
    while (!MoveFileEx(src, dst, MOVEFILE_REPLACE_EXISTING)) {
        DWORD err = GetLastError();
        if ((err == ERROR_ACCESS_DENIED ||
            err == ERROR_SHARING_VIOLATION ||
            err == ERROR_LOCK_VIOLATION) && ++loop <= RENAME_DEFAULT_RETRYS) {
            cm_sleep(RENAME_SLEEP_TIMES);
            continue;
        }
        CT_THROW_ERROR(ERR_RENAME_FILE, src, dst, err);
#else
    if (rename(src, dst) != 0) {
        CT_THROW_ERROR(ERR_RENAME_FILE, src, dst, errno);
#endif
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static void cm_get_parent_dir(char *path, uint32 len)
{
    char *p = NULL;

    if (len == 0) {
        return;
    }

    path = cm_skip_drive(path);
    if (path[0] == '\0') {
        return;
    }

    /* Exclude trailing slash(es) */
    for (p = path + strlen(path) - 1; IS_DIR_SEPARATOR(*p) && p > path; p--) {
        ;
    }

    /* Exclude file name */
    for (; !IS_DIR_SEPARATOR(*p) && p > path; p--) {
        ;
    }

    /* If multiple slashes before directory name, remove 'em all */
    for (; p > path && IS_DIR_SEPARATOR(*(p - 1)); p--) {
        ;
    }

    /* Don't erase a leading slash */
    if (p == path && IS_DIR_SEPARATOR(*p)) {
        p++;
    }

    *p = '\0';
}

/* cm_fsync_file_ex: try to fsync a file */
static status_t cm_fsync_file_ex(const char *file, bool32 isdir)
{
    int32 flags = O_BINARY;
    flags |= (!isdir) ? O_RDWR : O_RDONLY;

    int32 fd = open(file, flags, 0);

    /* Some OSes don't allow to open directories (Windows returns EACCES), just ignore the error in that case. */
    if (fd < 0 && isdir && (errno == EISDIR || errno == EACCES)) {
        return CT_SUCCESS;
    } else if (fd < 0) {
        CT_THROW_ERROR(ERR_OPEN_FILE, file, errno);
        return CT_ERROR;
    }

    /* Some OSes don't allow us to fsync directories at all, just ignore those errors. */
    if (cm_fsync_file(fd) != CT_SUCCESS && !(isdir && (errno == EBADF || errno == EINVAL))) {
        close(fd);
        return CT_ERROR;
    }

    close(fd);
    return CT_SUCCESS;
}

/* cm_fsync_parent_path: try to fsync a directory */
static status_t cm_fsync_parent_path(const char *fname)
{
    char  parentpath[CT_FILE_NAME_BUFFER_SIZE] = {0};

    int32 ret = strncpy_s(parentpath, sizeof(parentpath), fname, strlen(fname));
    if (ret != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    cm_get_parent_dir(parentpath, (uint32)strlen(parentpath));
    if (strlen(parentpath) == 0) {
        parentpath[0] = '.';
        parentpath[1] = '\0';
    }

    if (cm_fsync_file_ex(parentpath, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_rename_file_durably(const char *src, const char *dst)
{
    /* First fsync the src file to ensure that they are properly persistent on disk. */
    if (cm_fsync_file_ex(src, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (rename(src, dst) != 0) {
        CT_THROW_ERROR(ERR_RENAME_FILE, src, dst, errno);
        return CT_ERROR;
    }

    /* To guarantee renaming the file is persistent, fsync the file with its new name. */
    if (cm_fsync_file_ex(dst, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* To guarantee containing directory is persistent too. */
    if (cm_fsync_parent_path(dst) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cm_copy_file_ex(const char *src, const char *dst, char *buf, uint32 buffer_size, bool32 over_write)
{
    int32 src_file, dst_file, data_size;
    uint32 mode;

    if (cm_open_file(src, O_RDONLY | O_BINARY, &src_file) != CT_SUCCESS) {
        return CT_ERROR;
    }

    int64 file_size = cm_file_size(src_file);
    if (file_size < 0 || file_size > buffer_size) {
        cm_close_file(src_file);
        CT_THROW_ERROR(ERR_FILE_SIZE_MISMATCH, file_size, (uint64)buffer_size);
        return CT_ERROR;
    }

    if (cm_seek_file(src_file, 0, SEEK_SET) != 0) {
        cm_close_file(src_file);
        CT_LOG_RUN_ERR("seek file failed :%s.", src);
        return CT_ERROR;
    }

    mode = over_write ? O_RDWR | O_BINARY | O_SYNC : O_RDWR | O_BINARY | O_EXCL | O_SYNC;

    if (cm_create_file(dst, mode, &dst_file) != CT_SUCCESS) {
        cm_close_file(src_file);
        return CT_ERROR;
    }

    if (cm_seek_file(dst_file, 0, SEEK_SET) != 0) {
        cm_close_file(src_file);
        cm_close_file(dst_file);
        CT_LOG_RUN_ERR("seek file failed :%s.", dst);
        return CT_ERROR;
    }

    if (cm_read_file(src_file, buf, (int32)buffer_size, &data_size) != CT_SUCCESS) {
        cm_close_file(src_file);
        cm_close_file(dst_file);
        return CT_ERROR;
    }

    while (data_size > 0) {
        if (cm_write_file(dst_file, buf, data_size) != CT_SUCCESS) {
            cm_close_file(src_file);
            cm_close_file(dst_file);
            return CT_ERROR;
        }

        if (cm_read_file(src_file, buf, (int32)buffer_size, &data_size) != CT_SUCCESS) {
            cm_close_file(src_file);
            cm_close_file(dst_file);
            return CT_ERROR;
        }
    }

    cm_close_file(src_file);
    cm_close_file(dst_file);
    return CT_SUCCESS;
}

status_t cm_copy_file(const char *src, const char *dst, bool32 over_write)
{
    errno_t rc_memzero;

    char *buf = (char *)malloc(CT_WRITE_BUFFER_SIZE);
    if (buf == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_WRITE_BUFFER_SIZE, "copying file");
        return CT_ERROR;
    }
    rc_memzero = memset_sp(buf, (uint32)CT_WRITE_BUFFER_SIZE, 0, (uint32)CT_WRITE_BUFFER_SIZE);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(buf);
        CT_THROW_ERROR(ERR_RESET_MEMORY, "buf");
        return CT_ERROR;
    }
    status_t status = cm_copy_file_ex(src, dst, buf, CT_WRITE_BUFFER_SIZE, over_write);
    CM_FREE_PTR(buf);
    return status;
}

status_t cm_remove_file(const char *file_name)
{
    if (remove(file_name) != 0) {
        CT_LOG_RUN_ERR("remove file %s failed, error code %d.", file_name, errno);
        CT_THROW_ERROR(ERR_REMOVE_FILE, file_name, errno);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

#ifndef WIN32
status_t cm_remove_dir(const char *path)
{
    struct dirent *dirp = NULL;
    char *cwdir = getcwd(NULL, 0);
    if (cwdir == NULL) {
        CT_LOG_RUN_ERR("get current work directory failed, error code %d.", errno);
        return CT_ERROR;
    }
    DIR *dir = opendir(path);
    if (dir == NULL) {
        free(cwdir);
        CT_LOG_RUN_ERR("open directory %s failed, error code %d", path, errno);
        return CT_ERROR;
    }

    if (chdir(path) == -1) {
        free(cwdir);
        (void)closedir(dir);
        CT_LOG_RUN_ERR("change current work directory to %s failed, error code %d.", path, errno);
        return CT_ERROR;
    }

    while ((dirp = readdir(dir)) != NULL) {
        if ((strcmp(dirp->d_name, ".") == 0) || (strcmp(dirp->d_name, "..") == 0)) {
            continue;
        }

        if (cm_dir_exist(dirp->d_name)) {
            if (cm_remove_dir(dirp->d_name) == CT_SUCCESS) {
                continue;
            }
            (void)closedir(dir);
            free(cwdir);
            return CT_ERROR;
        }

        if (cm_remove_file(dirp->d_name) != CT_SUCCESS) {
            (void)closedir(dir);
            free(cwdir);
            return CT_ERROR;
        }
    }
    (void)closedir(dir);

    if (chdir(cwdir) == -1) {
        CT_LOG_RUN_ERR("change current work directory to %s failed, error code %d.", cwdir, errno);
        free(cwdir);
        return CT_ERROR;
    }
    free(cwdir);
    return(cm_remove_file(path));
}
#endif

bool32 cm_file_exist(const char *file_path)
{
    int32 fd = open(file_path, O_RDONLY);
    if (fd == -1) {
        return CT_FALSE;
    }

    close(fd);
    return CT_TRUE;
}

bool32 cm_dir_exist(const char *dir_path)
{
    int32 ret;
#ifdef WIN32
    struct _stat stat_buf;
#else
    struct stat stat_buf;
#endif

#ifdef WIN32
    ret = _stat(dir_path, &stat_buf);
#else
    ret = stat(dir_path, &stat_buf);
#endif
    if (ret != 0) {
        return CT_FALSE;
    }

#ifdef WIN32
    if (_S_IFDIR == (stat_buf.st_mode & _S_IFDIR)) {
#else
    /* S_ISREG: judge whether it's a directory or not by the flag */
    if (S_ISDIR(stat_buf.st_mode)) {
#endif
        return CT_TRUE;
    }

    return CT_FALSE;
}

bool32 cm_check_exist_special_char(const char *dir_path, uint32 size)
{
    uint32 i, j;
    char special_char[9] = { '|', ';', '&', '$', '>', '<', '`', '!', '\n'};
    for (i = 0; i < size; i++) {
        for (j = 0; j < 9; j++) {
            if (dir_path[i] == special_char[j]) {
                return CT_TRUE;
            }
        }
    }
    return CT_FALSE;
}

bool32 cm_check_uds_path_special_char(const char *dir_path, uint32 size)
{
    uint32 i, j;
    char special_char[10] = { '|', ';', '&', '$', '>', '<', '`', '!', '\n', '%'};
    for (i = 0; i < size; i++) {
        for (j = 0; j < 10; j++) {
            if (dir_path[i] == special_char[j]) {
                return CT_TRUE;
            }
        }
    }
    return CT_FALSE;
}

void cm_trim_dir(const char *file_name, uint32 size, char *buf)
{
    int32 i;
    uint32 len;
    errno_t errcode = 0;

    len = (uint32)strlen(file_name);
    if (len == 0) {
        buf[0] = '\0';
        return;
    }

    for (i = (int32)len - 1; i >= 0; i--) {
        if (file_name[i] == '\\' || file_name[i] == '/') {
            break;
        }
    }
    
    if (i == (int32)len - 1) {
        buf[0] = '\0';
        return;
    } else if (i < 0) {
        errcode = strncpy_s(buf, (size_t)size, file_name, (size_t)len);
        if (errcode != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return;
        }
        return;
    }

    errcode = strncpy_s(buf, (size_t)size, file_name + i + 1, (size_t)(len - (uint32)i - 1));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }

    return;
}

void cm_trim_filename(const char *file_name, uint32 size, char *buf)
{
    int32 i;
    uint32 len;

    len = (uint32)strlen(file_name);
    if (len == 0) {
        buf[0] = '\0';
        return;
    }
    errno_t errcode = strncpy_s(buf, (size_t)size, file_name, (size_t)len);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }
    len = (uint32)strlen(buf);

    for (i = (int32)len - 1; i >= 0; i--) {
        if (buf[i] == '\\' || buf[i] == '/') {
            buf[i + 1] = '\0';
            break;
        }
    }
}

/*
 * trim serial character '\' or '/' in the right of home path
 * etc. transform /home/cantian/ to /home/cantian
 */
void cm_trim_home_path(char *home_path, uint32 len)
{
    int32 i;

    for (i = (int32)len - 1; i >= 0; i--) {
        if (home_path[i] == '\\' || home_path[i] == '/') {
            home_path[i] = '\0';
        } else {
            break;
        }
    }
}

status_t cm_access_file(const char *file_name, uint32 mode)
{
    if (access(file_name, mode) != 0) {
        CT_THROW_ERROR(ERR_FILE_ACCESS, errno);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

bool32 cm_filename_equal(const text_t *text, const char *str)
{
#ifdef WIN32
    return cm_text_str_equal_ins(text, str);
#else
    return cm_text_str_equal(text, str);
#endif /* WIN32 */
}

status_t cm_create_dir_ex(const char *dir_name)
{
    char dir[CT_MAX_FILE_NAME_LEN + 1];
    size_t dir_len = strlen(dir_name);
    uint32 i;

    errno_t errcode = strncpy_s(dir, (size_t)CT_MAX_FILE_NAME_LEN, dir_name, (size_t)dir_len);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CT_ERROR;
    }
    if (dir[dir_len - 1] != '\\' && dir[dir_len - 1] != '/') {
        dir[dir_len] = '/';
        dir_len++;
        dir[dir_len] = '\0';
    }

    for (i = 0; i < dir_len; i++) {
        if (dir[i] == '\\' || dir[i] == '/') {
            if (i == 0) {
                continue;
            }

            dir[i] = '\0';
            if (cm_dir_exist(dir)) {
                dir[i] = '/';
                continue;
            }

            if (cm_create_dir(dir) != CT_SUCCESS) {
                return CT_ERROR;
            }
            dir[i] = '/';
        }
    }

    return CT_SUCCESS;
}

status_t cm_truncate_file(int32 fd, int64 offset)
{
#ifdef WIN32
    if (_chsize_s(fd, offset) != 0) {
#else
    if (ftruncate(fd, offset) != 0) {
#endif
        CT_THROW_ERROR(ERR_TRUNCATE_FILE, offset, errno);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_fallocate_file(int32 fd, int32 mode, int64 offset, int64 len)
{
#ifdef WIN32
    CT_LOG_RUN_ERR("fallocate not support on WINDOWS");
    return CT_ERROR;
#else
    if (fallocate(fd, mode, offset, len) != 0) {
        CT_LOG_RUN_ERR("Failed to fallocate the file, mode: %d, offset: %lld, length: %lld, error code %d.", mode,
                       offset, len, errno);
        CT_THROW_ERROR(ERR_FALLOCATE_FILE, errno);
        return CT_ERROR;
    }
    return CT_SUCCESS;
#endif
}

status_t cm_lock_fd(int32 fd)
{
#ifdef WIN32
    return CT_SUCCESS;
#else
    struct flock lk;

    lk.l_type = F_WRLCK;
    lk.l_whence = SEEK_SET;
    lk.l_start = lk.l_len = 0;

    if (fcntl(fd, F_SETLK, &lk) != 0) {
        CT_THROW_ERROR(ERR_LOCK_FILE, errno);
        return CT_ERROR;
    }

    return CT_SUCCESS;
#endif
}

status_t cm_unlock_fd(int32 fd)
{
#ifdef WIN32
    return CT_SUCCESS;
#else
    struct flock lk;

    lk.l_type = F_UNLCK;
    lk.l_whence = SEEK_SET;
    lk.l_start = lk.l_len = 0;

    if (fcntl(fd, F_SETLK, &lk) != 0) {
        CT_THROW_ERROR(ERR_UNLOCK_FILE, errno);
        return CT_ERROR;
    }

    return CT_SUCCESS;
#endif
}

void cm_show_lock_info(int32 fd)
{
#ifndef WIN32
    struct flock lk;
    if (fcntl(fd, F_GETLK, &lk) == 0) {
        CT_LOG_RUN_INF("The fd(%d) has been locked by process(%d) with type(%d).", fd, lk.l_pid, lk.l_type);
    } else {
        CT_LOG_RUN_WAR("Failed to get lock info by fd(%d), error code %d.", fd, errno);
    }
#endif
}

// if val = 700, log_file_permissions is (S_IRUSR | S_IWUSR | S_IXUSR)
uint32 cm_file_permissions(uint16 val)
{
    uint16 usr_perm;
    uint16 grp_perm;
    uint16 oth_perm;
    uint32 file_perm = 0;

    usr_perm = (val / 100) % 10;
    if (usr_perm & 1) {
        file_perm |= S_IXUSR;
    }

    if (usr_perm & 2) {
        file_perm |= S_IWUSR;
    }

    if (usr_perm & 4) {
        file_perm |= S_IRUSR;
    }

    grp_perm = (val / 10) % 10;
    if (grp_perm & 1) {
        file_perm |= S_IXGRP;
    }

    if (grp_perm & 2) {
        file_perm |= S_IWGRP;
    }

    if (grp_perm & 4) {
        file_perm |= S_IRGRP;
    }

    oth_perm = val % 10;
    if (oth_perm & 1) {
        file_perm |= S_IXOTH;
    }

    if (oth_perm & 2) {
        file_perm |= S_IWOTH;
    }

    if (oth_perm & 4) {
        file_perm |= S_IROTH;
    }
    return file_perm;
}

#ifndef WIN32
status_t cm_verify_file_host(char *realfile)
{
    char file_host[CT_FILE_NAME_BUFFER_SIZE];
    if (cm_get_file_host_name(realfile, file_host) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (!cm_str_equal(file_host, cm_sys_user_name())) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}
#endif

void cm_get_filesize(const char *filename, int64 *filesize)
{
    struct stat statbuf;
    stat(filename, &statbuf);
    *filesize = statbuf.st_size;
}

#define MAX_DUMP_ROW_SIZE 400
void cm_dump(cm_dump_t *dump, const char *str, ...)
{
    uint32 size_left = dump->buf_size - dump->offset;
    uint32 msg_size = MIN(size_left, MAX_DUMP_ROW_SIZE);
    va_list args;
    char *msg = dump->buf + dump->offset;

    va_start(args, str);
    int ret = vsnprintf_s(msg, msg_size, msg_size - 1, str, args);
    va_end(args);
    if (ret < 0) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return;
    }
    dump->offset += (uint32)strlen(msg);  // offset is less than 8K
}

status_t cm_dump_flush(cm_dump_t *dump)
{
    if (cm_write_file(dump->handle, dump->buf, dump->offset) != CT_SUCCESS) {
        return CT_ERROR;
    }
    dump->offset = 0;
    return CT_SUCCESS;
}

status_t cm_file_punch_hole(int32 handle, uint64 offset, int len)
{
    return cm_fallocate_file(handle, CM_FALLOC_PUNCH_HOLE | CM_FALLOC_KEEP_SIZE, offset, len);
}

status_t cm_file_get_status(const char *path, struct stat *stat_info)
{
#ifdef WIN32
    CT_LOG_RUN_ERR("stat not support on WINDOWS");
    return CT_ERROR;
#else
    int	ret = stat(path, stat_info);

    if (ret && (errno == ENOENT || errno == ENOTDIR)) {
        CT_THROW_ERROR(ERR_FILE_NOT_EXIST, "stat", "specifical");
        return CT_ERROR;
    } else if (ret) {
        CT_THROW_ERROR(ERR_READ_FILE, errno);
        return CT_ERROR;
    }

    return CT_SUCCESS;
#endif
}

#ifdef __cplusplus
}
#endif

