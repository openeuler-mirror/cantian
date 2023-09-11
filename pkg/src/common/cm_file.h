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
 * cm_file.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_file.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_FILE_H__
#define __CM_FILE_H__

#ifdef WIN32
#include <io.h>
#include <direct.h>
#else
#include <errno.h>
#endif
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "cm_defs.h"
#include "cm_text.h"
#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#define RENAME_DEFAULT_RETRYS 100
#define RENAME_SLEEP_TIMES 100

#ifdef WIN32
#define PATH_MAX 4096
#ifndef S_IRUSR
#define S_IRUSR _S_IREAD
#define S_IWUSR _S_IWRITE
#define S_IXUSR _S_IEXEC
#define S_IRWXU 0
#define S_IRGRP _S_IRGRP
#define S_IWGRP _S_IWGRP
#define S_IXGRP _S_IXGRP
#define S_IROTH 0
#define S_IWOTH 0
#define S_IXOTH 0
#define O_SYNC  0
#define O_CLOEXEC 0
#ifndef O_DIRECT
#define O_DIRECT 0
#endif
#ifndef O_DSYNC
#define O_DSYNC 0
#endif

#ifndef F_OK
#define F_OK 0x0000
#endif

#ifndef W_OK
#define W_OK 0x0002
#endif

#ifndef R_OK
#define R_OK 0x0004
#endif

#ifndef X_OK
#define X_OK 0x0004
#endif

#define open                _open
#define close               _close
#define read                _read
#define write               _write
#define lseek64             _lseeki64
#define off64_t             int64
#define make_dir(dir, mode) _mkdir(dir)
#define chmod(path, mode)   _chmod(path, mode)
#define __unlink            _unlink
#define access              _access
#define cm_getcwd           _getcwd
#define cm_chdir            _chdir
#define cm_fileno           _fileno
#endif
#else
#define O_BINARY            0
#define make_dir(dir, mode) mkdir(dir, mode)
#define __unlink            unlink
#define cm_getcwd           getcwd
#define cm_chdir            chdir
#define cm_fileno           fileno
#endif

#define GS_WRITE_TRY_TIMES 5

#define GS_NULL_FILE (int32)(-1)

typedef int32 file_t;

status_t cm_open_file(const char *file_name, uint32 mode, int32 *file);
status_t cm_chmod_file(uint32 perm, int32 fd);

/**
 * Security requirements require that the permissions of
 * + sensitive data file <= 0600
 * + log file            <= 0644
 * + executable file     <= 0750
 * + un-executable file  <= 0640
 */
#define FILE_PERM_OF_DATA   0600
#define FILE_PERM_OF_LOG    0644
#define FILE_PERM_OF_EXE    0750
#define FILE_PERM_OF_NORMAL 0640

static inline status_t cm_fchmod(uint32 perm, FILE *fp)
{
    return cm_chmod_file(perm, cm_fileno(fp));
}

status_t cm_fopen(const char *filename, const char *mode, uint32 perm, FILE **fp);
status_t cm_fsync_file(int32 file);
status_t cm_fdatasync_file(int32 file);

status_t cm_create_file(const char *file_name, uint32 mode, int32 *file);
void cm_close_file(int32 file);
status_t cm_read_file(int32 file, void *buf, int32 len, int32 *read_size);
status_t cm_write_file(int32 file, const void *buf, int32 size);
status_t cm_pwrite_file(int32 file, const char *buf, int32 size, int64 offset);
status_t cm_pread_file(int32 file, void *buf, int length, int64 i_offset, int32 *read_size);
status_t cm_truncate_file(int32 fd, int64 offset);
status_t cm_fallocate_file(int32 fd, int32 mode, int64 offset, int64 len);
status_t cm_lock_fd(int32 fd);
status_t cm_unlock_fd(int32 fd);
void cm_show_lock_info(int32 fd);
int64 cm_seek_file(int32 file, int64 offset, int32 origin);
status_t cm_check_file(const char *name, int64 size);
status_t cm_create_dir(const char *dir_name);
status_t cm_rename_file(const char *src, const char *dst);
status_t cm_rename_file_durably(const char *src, const char *dst);
status_t cm_copy_file_ex(const char *src, const char *dst, char *buf, uint32 buffer_size, bool32 over_write);
status_t cm_copy_file(const char *src, const char *dst, bool32 over_write);
status_t cm_remove_file(const char *file_name);
bool32 cm_file_exist(const char *file_path);
bool32 cm_dir_exist(const char *dir_path);
bool32 cm_check_exist_special_char(const char *dir_path, uint32 size);
bool32 cm_check_uds_path_special_char(const char *dir_path, uint32 size);
void cm_trim_filename(const char *file_name, uint32 size, char *buf);
void cm_trim_dir(const char *file_name, uint32 size, char *buf);
bool32 cm_filename_equal(const text_t *text, const char *str);
status_t cm_create_dir_ex(const char *dir_name);
void cm_trim_home_path(char *home_path, uint32 len);
status_t cm_access_file(const char *file_name, uint32 mode);
status_t cm_file_punch_hole(int32 handle, uint64 offset, int len);
status_t cm_file_get_status(const char *path, struct stat *stat_info);

#ifndef WIN32
status_t cm_verify_file_host(char *realfile);
status_t cm_remove_dir(const char *path);
#endif

status_t cm_open_file_ex(const char *file_name, uint32 mode, uint32 perm, int32 *file);

static inline status_t cm_write_str(int32 file, const char *str)
{
    return cm_write_file(file, (void *)str, (int32)strlen(str));
}

#define cm_file_size(file) cm_seek_file(file, 0, SEEK_END)

#ifdef WIN32
#define OS_DIRECTORY_SEPARATOR '\\'
#else
#define OS_DIRECTORY_SEPARATOR '/'
#endif  // WIN32

static inline void cm_convert_os_path(text_t *filepath)
{
    for (uint32 i = 0; i < filepath->len; i++) {
#ifdef WIN32
        if (filepath->str[i] == '/') {
#else
        if (filepath->str[i] == '\\') {
#endif  // WIN32
            filepath->str[i] = OS_DIRECTORY_SEPARATOR;
        }
    }
}

uint32 cm_file_permissions(uint16 val);
void cm_get_filesize(const char *filename, int64 *filesize);

typedef struct st_dump_page {
    int32 handle;
    uint32 buf_size;
    int32 offset;
    char *buf;
} cm_dump_t;

void cm_dump(cm_dump_t *dump, const char *str, ...);
status_t cm_dump_flush(cm_dump_t *dump);
#ifdef __cplusplus
}
#endif

#endif

