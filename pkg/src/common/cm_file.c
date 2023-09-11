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
 * cm_file.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_file.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_file.h"
#include "cm_log.h"
#include "cm_system.h"

#ifdef WIN32
#else
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
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

#define GS_WRITE_BUFFER_SIZE SIZE_M(2)

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
        GS_THROW_ERROR(ERR_DATAFILE_FSYNC, errno);
        return GS_ERROR;
    }
#endif

    return GS_SUCCESS;
}

status_t cm_fdatasync_file(int32 file)
{
#ifndef WIN32
    if (fdatasync(file) != 0) {
        GS_THROW_ERROR(ERR_DATAFILE_FDATASYNC, errno);
        return GS_ERROR;
    }
#endif

    return GS_SUCCESS;
}

// file name could not include black space before string on windows, auto-remove it
status_t cm_open_file(const char *file_name, uint32 mode, int32 *file)
{
    uint32 perm = ((mode & O_CREAT) != 0) ? S_IRUSR | S_IWUSR : 0;

    if (strlen(file_name) > GS_MAX_FILE_NAME_LEN) {
        GS_THROW_ERROR(ERR_INVALID_FILE_NAME, file_name, (uint32)GS_MAX_FILE_NAME_LEN);
        return GS_ERROR;
    }

    *file = open(file_name, (int)mode, perm);

    if ((*file) == -1) {
        if ((mode & O_CREAT) != 0) {
            GS_THROW_ERROR(ERR_CREATE_FILE, file_name, errno);
        } else {
            GS_THROW_ERROR(ERR_OPEN_FILE, file_name, errno);
        }
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t cm_chmod_file(uint32 perm, int32 fd)
{
#ifndef WIN32
    int32 err_no = fchmod(fd, perm);
    if (err_no != 0) {
        GS_THROW_ERROR(ERR_CREATE_FILE, "", err_no);
        return GS_ERROR;
    }
#endif  // !WIN32
    return GS_SUCCESS;
}

status_t cm_fopen(const char *filename, const char *mode, uint32 perm, FILE **fp)
{
    *fp = fopen(filename, mode);
    if (*fp == NULL) {
        GS_THROW_ERROR(ERR_OPEN_FILE, filename, errno);
        return GS_ERROR;
    }
#ifndef WIN32
    int32 err_no = fchmod(cm_fileno(*fp), perm);
    if (err_no != 0) {
        fclose(*fp);
        *fp = NULL;
        GS_THROW_ERROR(ERR_OPEN_FILE, filename, err_no);
        return GS_ERROR;
    }
#endif  // !WIN32

    return GS_SUCCESS;
}

status_t cm_open_file_ex(const char *file_name, uint32 mode, uint32 perm, int32 *file)
{
    if (strlen(file_name) > GS_MAX_FILE_NAME_LEN) {
        GS_THROW_ERROR(ERR_INVALID_FILE_NAME, file_name, (uint32)GS_MAX_FILE_NAME_LEN);
        return GS_ERROR;
    }

    *file = open(file_name, (int)mode, perm);

    if ((*file) == -1) {
        if ((mode & O_CREAT) != 0) {
            GS_THROW_ERROR(ERR_CREATE_FILE, file_name, errno);
        } else {
            GS_THROW_ERROR(ERR_OPEN_FILE, file_name, errno);
        }
        return GS_ERROR;
    }

    return GS_SUCCESS;
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
        GS_LOG_RUN_ERR("failed to close file with handle %d, error code %d", file, errno);
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
            GS_THROW_ERROR(ERR_READ_FILE, errno);
            return GS_ERROR;
        }
        size -= curr_size;
        total_size += curr_size;
    } while (size > 0 && curr_size > 0);

    if (read_size != NULL) {
        *read_size = total_size;
    }

    return GS_SUCCESS;
}

status_t cm_write_file(int32 file, const void *buf, int32 size)
{
    int32 write_size = 0;
    int32 try_times = 0;

    while (try_times < GS_WRITE_TRY_TIMES) {
        write_size = write(file, buf, size);
        if (write_size == 0) {
            cm_sleep(5);
            try_times++;
            continue;
        } else if (write_size == -1) {
            GS_THROW_ERROR(ERR_WRITE_FILE, errno);
            return GS_ERROR;
        } else {
            break;
        }
    }

    if (write_size != size) {
        GS_THROW_ERROR(ERR_WRITE_FILE_PART_FINISH, write_size, size);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t cm_pread_file(int32 file, void *buf, int length, int64 i_offset, int32 *read_size)
{
#ifdef WIN32
    if (cm_seek_file(file, offset, SEEK_SET) != offset) {
        GS_THROW_ERROR(ERR_SEEK_FILE, offset, SEEK_SET, errno);
        return GS_ERROR;
    }

    if (cm_read_file(file, buf, size, read_size) != GS_SUCCESS) {
        return GS_ERROR;
    }
#else
    int32 curr_size;
    int32 total_size = 0;
    int64 offset = i_offset;
    int size = length;
    do {
        curr_size = pread64(file, (char *)buf + total_size, size, offset);
        if (curr_size == -1) {
            GS_THROW_ERROR(ERR_READ_FILE, errno);
            return GS_ERROR;
        }

        total_size += curr_size;
        offset += curr_size;
        size -= curr_size;
    } while (size > 0 && curr_size > 0);

    if (read_size != NULL) {
        *read_size = total_size;
    }
#endif
    return GS_SUCCESS;
}

status_t cm_pwrite_file(int32 file, const char *buf, int32 size, int64 offset)
{
#ifdef WIN32
    if (cm_seek_file(file, offset, SEEK_SET) != offset) {
        GS_THROW_ERROR(ERR_SEEK_FILE, offset, SEEK_SET, errno);
        return GS_ERROR;
    }

    if (cm_write_file(file, buf, size) != GS_SUCCESS) {
        return GS_ERROR;
    }
#else
    int32 write_size;
    int32 try_times = 0;

    while (try_times < GS_WRITE_TRY_TIMES) {
        write_size = pwrite64(file, buf, size, offset);
        if (write_size == 0) {
            cm_sleep(5);
            try_times++;
            continue;
        } else if (write_size == -1) {
            GS_THROW_ERROR(ERR_WRITE_FILE, errno);
            return GS_ERROR;
        } else {
            break;
        }
    }

    if (write_size != size) {
        GS_THROW_ERROR(ERR_WRITE_FILE_PART_FINISH, write_size, size);
        return GS_ERROR;
    }
#endif
    return GS_SUCCESS;
}

int64 cm_seek_file(int32 file, int64 offset, int32 origin)
{
    return (int64)lseek64(file, (off64_t)offset, origin);
}

status_t cm_check_file(const char *name, int64 size)
{
    int32 file;
    if (cm_open_file(name, O_BINARY | O_RDONLY, &file) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (size != cm_seek_file(file, 0, SEEK_END)) {
        cm_close_file(file);
        GS_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_SET, errno);
        return GS_ERROR;
    }

    cm_close_file(file);
    return GS_SUCCESS;
}

status_t cm_create_dir(const char *dir_name)
{
    if (make_dir(dir_name, S_IRWXU) != 0) {
        GS_THROW_ERROR(ERR_CREATE_DIR, dir_name, errno);
        return GS_ERROR;
    }

    return GS_SUCCESS;
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
        GS_THROW_ERROR(ERR_RENAME_FILE, src, dst, err);
#else
    if (rename(src, dst) != 0) {
        GS_THROW_ERROR(ERR_RENAME_FILE, src, dst, errno);
#endif
        return GS_ERROR;
    }

    return GS_SUCCESS;
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
        return GS_SUCCESS;
    } else if (fd < 0) {
        GS_THROW_ERROR(ERR_OPEN_FILE, file, errno);
        return GS_ERROR;
    }

    /* Some OSes don't allow us to fsync directories at all, just ignore those errors. */
    if (cm_fsync_file(fd) != GS_SUCCESS && !(isdir && (errno == EBADF || errno == EINVAL))) {
        close(fd);
        return GS_ERROR;
    }

    close(fd);
    return GS_SUCCESS;
}

/* cm_fsync_parent_path: try to fsync a directory */
static status_t cm_fsync_parent_path(const char *fname)
{
    char  parentpath[GS_FILE_NAME_BUFFER_SIZE] = {0};

    int32 ret = strncpy_s(parentpath, sizeof(parentpath), fname, strlen(fname));
    if (ret != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return GS_ERROR;
    }

    cm_get_parent_dir(parentpath, (uint32)strlen(parentpath));
    if (strlen(parentpath) == 0) {
        parentpath[0] = '.';
        parentpath[1] = '\0';
    }

    if (cm_fsync_file_ex(parentpath, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t cm_rename_file_durably(const char *src, const char *dst)
{
    /* First fsync the src file to ensure that they are properly persistent on disk. */
    if (cm_fsync_file_ex(src, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (rename(src, dst) != 0) {
        GS_THROW_ERROR(ERR_RENAME_FILE, src, dst, errno);
        return GS_ERROR;
    }

    /* To guarantee renaming the file is persistent, fsync the file with its new name. */
    if (cm_fsync_file_ex(dst, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* To guarantee containing directory is persistent too. */
    if (cm_fsync_parent_path(dst) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cm_copy_file_ex(const char *src, const char *dst, char *buf, uint32 buffer_size, bool32 over_write)
{
    int32 src_file, dst_file, data_size;
    uint32 mode;

    if (cm_open_file(src, O_RDONLY | O_BINARY, &src_file) != GS_SUCCESS) {
        return GS_ERROR;
    }

    int64 file_size = cm_file_size(src_file);
    if (file_size < 0 || file_size > buffer_size) {
        cm_close_file(src_file);
        GS_THROW_ERROR(ERR_FILE_SIZE_MISMATCH, file_size, (uint64)buffer_size);
        return GS_ERROR;
    }

    if (cm_seek_file(src_file, 0, SEEK_SET) != 0) {
        cm_close_file(src_file);
        GS_LOG_RUN_ERR("seek file failed :%s.", src);
        return GS_ERROR;
    }

    mode = over_write ? O_RDWR | O_BINARY | O_SYNC : O_RDWR | O_BINARY | O_EXCL | O_SYNC;

    if (cm_create_file(dst, mode, &dst_file) != GS_SUCCESS) {
        cm_close_file(src_file);
        return GS_ERROR;
    }

    if (cm_seek_file(dst_file, 0, SEEK_SET) != 0) {
        cm_close_file(src_file);
        cm_close_file(dst_file);
        GS_LOG_RUN_ERR("seek file failed :%s.", dst);
        return GS_ERROR;
    }

    if (cm_read_file(src_file, buf, (int32)buffer_size, &data_size) != GS_SUCCESS) {
        cm_close_file(src_file);
        cm_close_file(dst_file);
        return GS_ERROR;
    }

    while (data_size > 0) {
        if (cm_write_file(dst_file, buf, data_size) != GS_SUCCESS) {
            cm_close_file(src_file);
            cm_close_file(dst_file);
            return GS_ERROR;
        }

        if (cm_read_file(src_file, buf, (int32)buffer_size, &data_size) != GS_SUCCESS) {
            cm_close_file(src_file);
            cm_close_file(dst_file);
            return GS_ERROR;
        }
    }

    cm_close_file(src_file);
    cm_close_file(dst_file);
    return GS_SUCCESS;
}

status_t cm_copy_file(const char *src, const char *dst, bool32 over_write)
{
    errno_t rc_memzero;

    char *buf = (char *)malloc(GS_WRITE_BUFFER_SIZE);
    if (buf == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_WRITE_BUFFER_SIZE, "copying file");
        return GS_ERROR;
    }
    rc_memzero = memset_sp(buf, (uint32)GS_WRITE_BUFFER_SIZE, 0, (uint32)GS_WRITE_BUFFER_SIZE);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(buf);
        GS_THROW_ERROR(ERR_RESET_MEMORY, "buf");
        return GS_ERROR;
    }
    status_t status = cm_copy_file_ex(src, dst, buf, GS_WRITE_BUFFER_SIZE, over_write);
    CM_FREE_PTR(buf);
    return status;
}

status_t cm_remove_file(const char *file_name)
{
    if (remove(file_name) != 0) {
        GS_LOG_RUN_ERR("remove file %s failed, error code %d.", file_name, errno);
        GS_THROW_ERROR(ERR_REMOVE_FILE, file_name, errno);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

#ifndef WIN32
status_t cm_remove_dir(const char *path)
{
    struct dirent *dirp = NULL;
    char *cwdir = getcwd(NULL, 0);
    if (cwdir == NULL) {
        GS_LOG_RUN_ERR("get current work directory failed, error code %d.", errno);
        return GS_ERROR;
    }
    DIR *dir = opendir(path);
    if (dir == NULL) {
        free(cwdir);
        GS_LOG_RUN_ERR("open directory %s failed, error code %d", path, errno);
        return GS_ERROR;
    }

    if (chdir(path) == -1) {
        free(cwdir);
        (void)closedir(dir);
        GS_LOG_RUN_ERR("change current work directory to %s failed, error code %d.", path, errno);
        return GS_ERROR;
    }

    while ((dirp = readdir(dir)) != NULL) {
        if ((strcmp(dirp->d_name, ".") == 0) || (strcmp(dirp->d_name, "..") == 0)) {
            continue;
        }

        if (cm_dir_exist(dirp->d_name)) {
            if (cm_remove_dir(dirp->d_name) == GS_SUCCESS) {
                continue;
            }
            (void)closedir(dir);
            free(cwdir);
            return GS_ERROR;
        }

        if (cm_remove_file(dirp->d_name) != GS_SUCCESS) {
            (void)closedir(dir);
            free(cwdir);
            return GS_ERROR;
        }
    }
    (void)closedir(dir);

    if (chdir(cwdir) == -1) {
        GS_LOG_RUN_ERR("change current work directory to %s failed, error code %d.", cwdir, errno);
        free(cwdir);
        return GS_ERROR;
    }
    free(cwdir);
    return(cm_remove_file(path));
}
#endif

bool32 cm_file_exist(const char *file_path)
{
    int32 ret;
#ifdef WIN32
    struct _stat stat_buf;
#else
    struct stat stat_buf;
#endif

#ifdef WIN32
    ret = _stat(file_path, &stat_buf);
#else
    ret = stat(file_path, &stat_buf);
#endif
    if (ret != 0) {
        return GS_FALSE;
    }

#ifdef WIN32
    if (_S_IFREG == (stat_buf.st_mode & _S_IFREG)) {
#else
    /* S_ISREG: judge whether it's a regular file or not by the flag */
    if (S_ISREG(stat_buf.st_mode)) {
#endif
        return GS_TRUE;
    }

    return GS_FALSE;
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
        return GS_FALSE;
    }

#ifdef WIN32
    if (_S_IFDIR == (stat_buf.st_mode & _S_IFDIR)) {
#else
    /* S_ISREG: judge whether it's a directory or not by the flag */
    if (S_ISDIR(stat_buf.st_mode)) {
#endif
        return GS_TRUE;
    }

    return GS_FALSE;
}

bool32 cm_check_exist_special_char(const char *dir_path, uint32 size)
{
    uint32 i, j;
    char special_char[9] = { '|', ';', '&', '$', '>', '<', '`', '!', '\n'};
    for (i = 0; i < size; i++) {
        for (j = 0; j < 9; j++) {
            if (dir_path[i] == special_char[j]) {
                return GS_TRUE;
            }
        }
    }
    return GS_FALSE;
}

bool32 cm_check_uds_path_special_char(const char *dir_path, uint32 size)
{
    uint32 i, j;
    char special_char[10] = { '|', ';', '&', '$', '>', '<', '`', '!', '\n', '%'};
    for (i = 0; i < size; i++) {
        for (j = 0; j < 10; j++) {
            if (dir_path[i] == special_char[j]) {
                return GS_TRUE;
            }
        }
    }
    return GS_FALSE;
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
            GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return;
        }
        return;
    }

    errcode = strncpy_s(buf, (size_t)size, file_name + i + 1, (size_t)(len - (uint32)i - 1));
    if (errcode != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
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
        GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
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
        GS_THROW_ERROR(ERR_FILE_ACCESS, errno);
        return GS_ERROR;
    }
    return GS_SUCCESS;
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
    char dir[GS_MAX_FILE_NAME_LEN + 1];
    size_t dir_len = strlen(dir_name);
    uint32 i;

    errno_t errcode = strncpy_s(dir, (size_t)GS_MAX_FILE_NAME_LEN, dir_name, (size_t)dir_len);
    if (errcode != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return GS_ERROR;
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

            if (cm_create_dir(dir) != GS_SUCCESS) {
                return GS_ERROR;
            }
            dir[i] = '/';
        }
    }

    return GS_SUCCESS;
}

status_t cm_truncate_file(int32 fd, int64 offset)
{
#ifdef WIN32
    if (_chsize_s(fd, offset) != 0) {
#else
    if (ftruncate(fd, offset) != 0) {
#endif
        GS_THROW_ERROR(ERR_TRUNCATE_FILE, offset, errno);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t cm_fallocate_file(int32 fd, int32 mode, int64 offset, int64 len)
{
#ifdef WIN32
    GS_LOG_RUN_ERR("fallocate not support on WINDOWS");
    return GS_ERROR;
#else
    if (fallocate(fd, mode, offset, len) != 0) {
        GS_LOG_RUN_ERR("Failed to fallocate the file, mode: %d, offset: %lld, length: %lld, error code %d.", mode,
                       offset, len, errno);
        GS_THROW_ERROR(ERR_FALLOCATE_FILE, errno);
        return GS_ERROR;
    }
    return GS_SUCCESS;
#endif
}

status_t cm_lock_fd(int32 fd)
{
#ifdef WIN32
    return GS_SUCCESS;
#else
    struct flock lk;

    lk.l_type = F_WRLCK;
    lk.l_whence = SEEK_SET;
    lk.l_start = lk.l_len = 0;

    if (fcntl(fd, F_SETLK, &lk) != 0) {
        GS_THROW_ERROR(ERR_LOCK_FILE, errno);
        return GS_ERROR;
    }

    return GS_SUCCESS;
#endif
}

status_t cm_unlock_fd(int32 fd)
{
#ifdef WIN32
    return GS_SUCCESS;
#else
    struct flock lk;

    lk.l_type = F_UNLCK;
    lk.l_whence = SEEK_SET;
    lk.l_start = lk.l_len = 0;

    if (fcntl(fd, F_SETLK, &lk) != 0) {
        GS_THROW_ERROR(ERR_UNLOCK_FILE, errno);
        return GS_ERROR;
    }

    return GS_SUCCESS;
#endif
}

void cm_show_lock_info(int32 fd)
{
#ifndef WIN32
    struct flock lk;
    if (fcntl(fd, F_GETLK, &lk) == 0) {
        GS_LOG_RUN_INF("The fd(%d) has been locked by process(%d) with type(%d).", fd, lk.l_pid, lk.l_type);
    } else {
        GS_LOG_RUN_WAR("Failed to get lock info by fd(%d), error code %d.", fd, errno);
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
    char file_host[GS_FILE_NAME_BUFFER_SIZE];
    if (cm_get_file_host_name(realfile, file_host) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (!cm_str_equal(file_host, cm_sys_user_name())) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
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
        GS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return;
    }
    dump->offset += (uint32)strlen(msg);  // offset is less than 8K
}

status_t cm_dump_flush(cm_dump_t *dump)
{
    if (cm_write_file(dump->handle, dump->buf, dump->offset) != GS_SUCCESS) {
        return GS_ERROR;
    }
    dump->offset = 0;
    return GS_SUCCESS;
}

status_t cm_file_punch_hole(int32 handle, uint64 offset, int len)
{
    return cm_fallocate_file(handle, CM_FALLOC_PUNCH_HOLE | CM_FALLOC_KEEP_SIZE, offset, len);
}

status_t cm_file_get_status(const char *path, struct stat *stat_info)
{
#ifdef WIN32
    GS_LOG_RUN_ERR("stat not support on WINDOWS");
    return GS_ERROR;
#else
    int	ret = stat(path, stat_info);

    if (ret && (errno == ENOENT || errno == ENOTDIR)) {
        GS_THROW_ERROR(ERR_FILE_NOT_EXIST, "stat", "specifical");
        return GS_ERROR;
    } else if (ret) {
        GS_THROW_ERROR(ERR_READ_FILE, errno);
        return GS_ERROR;
    }

    return GS_SUCCESS;
#endif
}

#ifdef __cplusplus
}
#endif

