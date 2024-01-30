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
 * cm_log.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_log.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "cm_file.h"
#include "cm_date.h"
#include "cm_log.h"
#include "cm_thread.h"
#include "cm_timer.h"
#include "cm_dbs_intf.h"
#include "cm_dbstore.h"
#include <regex.h>

#ifndef _WIN32
#include <dirent.h>
#include <execinfo.h>
#endif

static char *g_module_info[] = {
    "DB",
    "INDEX",
    "DC",
    "SPACE",
    "BUFFER",
    "FLASH_BACK",
    "PERSIST",
    "TABLE",
    "XACT",
    "CLUSTER",
    "COMMON",
    "RC",
    "TBOX",
    "PE",
    "DBSTORE",
    "TSE",
    "SERVER",
    "KNL_COMM",
    "CMS",
    "MES",
    "ZENFS",
    "EXT_PROC",
    "BACKUP",
    "ARCHIVE",
    "DEVICE",
    "REPLICATION",
    "PROTOCOL",
    "ODBC",
    "SHARD",
    "TMS",
    "CTBACKUP"
};

typedef struct st_log_info_t {
    uint32 sess_id;
} log_info_t;

#ifdef WIN32
__declspec(thread)log_info_t g_log_info = { 0 };
#else
__thread log_info_t g_log_info = { 0 };
#endif

static log_file_handle_t g_logger[LOG_COUNT];
log_file_handle_t *cm_log_logger_file(uint32 log_count)
{
    return &g_logger[log_count];
}
static log_param_t g_log_param;
inline log_param_t *cm_log_param_instance(void)
{
    return &g_log_param;
}

void cm_log_set_session_id(uint32 sess_id)
{
    g_log_info.sess_id = sess_id;
}

static void cm_log_remove_file(const char *file_name)
{
    (void)chmod(file_name, S_IRUSR | S_IWUSR | S_IXUSR);
    (void)__unlink(file_name);
}

bool32 g_filter_enable = 0;

regex_conf_t g_regex_conf[] = {
    {REGEX_LINE,     ENABLE_REGEX, "\n"}, // newline
    {REGEX_SECURITY, ENABLE_REGEX, "security:\\S*"}, // security key
    {REGEX_TOKEN,    ENABLE_REGEX, "[Tt][Oo][Kk][Ee][Nn]((\\S*)|(\\s*:\\s*)"
    "|(\\s*=\\s*)|(\\s*-\\s*)|(\\s*\\(\\s*)|(\\s*\\[\\s*)|(\\s*\\{\\s*))\\S*"}, // token
    {REGEX_PASSWORD, ENABLE_REGEX, "[Pp][Aa][Ss][Ss]([Ww]|[Ww][Dd]|[Ww][Oo][Rr][Dd])((\\S*)"
     "|(\\s*:\\s*)|(\\s*=\\s*)|(\\s*-\\s*)|(\\s*\\(\\s*)|(\\s*\\[\\s*)|(\\s*\\{\\s*))\\S*"}, // password
};

int compile_regex(regex_t *reg, const char *regex)
{
    return regcomp(reg, regex, REG_EXTENDED);
}

void replace_filter_str(char *str, int start, int end)
{
    int str_len = strlen(str);
    if (start < 0 || end <= 0 || start >= end || (end - start) > str_len) {
        return;
    }
    for (int index = start; index < end; index++) {
        switch (*(str + index)) {
            case ' ':
            case ',':
                break;
            default:
                *(str + index) = '*';
                break;
        }
    }
    return;
}

int exec_replace_regex(regex_t *reg, char *filter_str)
{
    int offset = 0, ret_val = 0;
    int str_len = strlen(filter_str);
    regmatch_t reg_match[1];
    int reg_len = sizeof(reg_match) / sizeof(reg_match[0]);
    errno_t err;

    while (offset < str_len) {
        err = memset_s(&reg_match, sizeof(reg_match), 0, sizeof(reg_match));
        if (err != EOK) {
            return CT_ERROR;
        }
        int status = regexec(reg, filter_str + offset, reg_len, reg_match, 0);
        switch (status) {
            case REG_NOERROR:
                replace_filter_str(filter_str + offset, reg_match[0].rm_so, reg_match[0].rm_eo);
                offset += reg_match[0].rm_eo;
                break;
            case REG_NOMATCH:
                return ret_val;
            default:
                ret_val = status;
                return ret_val;
        }
    }
    return ret_val;
}

status_t replace_all(char *filter_str, const char *regex)
{
    if (filter_str == NULL || strlen(filter_str) > MAX_FILTER_STR_LEN) {
        return CT_ERROR;
    }
    regex_t reg;
    errno_t err;
    err = memset_s(&reg, sizeof(reg), 0, sizeof(reg));
    if (err != EOK) {
        return CT_ERROR;
    }
    if (compile_regex(&reg, regex) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (exec_replace_regex(&reg, filter_str) != CT_SUCCESS) {
        return CT_ERROR;
    }
    regfree(&reg);

    return CT_SUCCESS;
}

static void do_security_filter(char *filter_str)
{
    status_t ret = CT_SUCCESS;
    for (int index = 0; index < sizeof(g_regex_conf) / sizeof(g_regex_conf[0]); index++) {
        if (g_regex_conf[index].regex_status == ENABLE_REGEX) {
            ret = replace_all(filter_str, g_regex_conf[index].regex);
            if (ret != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[do filter]:do log security filter check failed.");
            }
        }
    }
}

static int32 cm_log_convert_token(const char *src, char *dst, size_t len)
{
    int32 count = 0;

    if (src == NULL || dst == NULL) {
        return 0;
    }

    size_t file_name_len = strlen(src);
    if (file_name_len >= len) {
        return 0;
    }

    if (strncpy_s(dst, len, src, file_name_len) != EOK) {
        return 0;
    }

    char *psz = dst;
    char *pszEnd = psz + strlen(dst);
    while (psz < pszEnd) {
        // replace instances of the specified character only
        if (*psz == '\\') {
            *psz = '/';
            count++;
        }
        psz++;
    }

    return count;
}

static status_t cm_log_create_directory(const char *log_dir)
{
    char tmp[CT_MAX_PATH_BUFFER_SIZE] = { 0 };
    char path_name[CT_MAX_PATH_BUFFER_SIZE] = { 0 };

    (void)cm_log_convert_token(log_dir, tmp, CT_MAX_PATH_BUFFER_SIZE);
    size_t len = strlen(tmp);
    size_t count;

    if (tmp[len - 1] != '/') {
        tmp[len] = '/';
        len++;
        tmp[len] = '\0';
    }

    // Create the specified directory recursively to achieve the effect of the mkdir -p command.
    size_t lastPos = 0;
    for (size_t i = 1; i < len; i++) {
        if (tmp[i] == '/') {
            count = i - lastPos + 1;
            MEMS_RETURN_IFERR(strncat_s(path_name, CT_MAX_PATH_BUFFER_SIZE, &tmp[lastPos], (size_t)count));
            lastPos = i;
            if (make_dir(path_name, g_log_param.log_path_permissions) != 0 && errno != EEXIST && errno != EACCES) {
                return CT_ERROR;
            }
        }
    }
    return CT_SUCCESS;
}

static status_t cm_log_get_dir(char *log_dir, uint32 buf_size, const char *file_name)
{
    char *p = NULL;
    size_t file_name_len = strlen(file_name);

    MEMS_RETURN_IFERR(strncpy_s(log_dir, buf_size, file_name, file_name_len));
    p = strrchr(log_dir, '/');
    if (p == NULL) {
        return CT_SUCCESS;
    }
    *p = '\0';

    return CT_SUCCESS;
}

// The current log has a maximum of two paths: log/debug(run)
static void cm_log_chmod_dir(const char *log_dir, log_id_t log_id)
{
    (void)chmod(log_dir, g_log_param.log_path_permissions);

    if (log_id == LOG_ALARM) {
        return;
    }

    char *p = strrchr(log_dir, '/');
    if (p == NULL) {
        return;
    }
    *p = '\0';
    (void)chmod(log_dir, g_log_param.log_path_permissions);
}

static void cm_log_create_dir(log_file_handle_t *log_file_handle)
{
    char log_dir[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    if (cm_log_get_dir(log_dir, CT_FILE_NAME_BUFFER_SIZE, log_file_handle->file_name) != CT_SUCCESS) {
        return;
    }
    (void)cm_log_create_directory((const char *)log_dir);
    cm_log_chmod_dir(log_dir, log_file_handle->log_id);
}

static void cm_log_build_normal_head(char *buf, uint32 buf_size, log_level_t log_level, const char *module_name)
{
    int tz_hour, tz_min;
    char date[CT_MAX_TIME_STRLEN] = { 0 };
    errno_t errcode;
    const char *log_level_str = NULL;

    switch (log_level) {
        case LEVEL_ERROR:
            log_level_str = "ERROR";
            break;
        case LEVEL_WARN:
            log_level_str = "WARN";
            break;
        default:
            log_level_str = "INFO";
            break;
    }

    (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", date, CT_MAX_TIME_STRLEN);
    tz_hour = TIMEZONE_GET_HOUR(g_timer()->tz);
    tz_min = TIMEZONE_GET_MINUTE(g_timer()->tz);
    if (tz_hour >= 0) {
        // truncation CT_MAX_LOG_HEAD_LENGTH content
        errcode = snprintf_s(buf, (size_t)buf_size, CT_MAX_LOG_HEAD_LENGTH - 1, "UTC+%02d:%02d %s|%s|%05u|%u|%s>",
            tz_hour, tz_min, date, module_name, g_log_info.sess_id, cm_get_current_thread_id(), log_level_str);
    } else {
        // truncation CT_MAX_LOG_HEAD_LENGTH content
        errcode = snprintf_s(buf, (size_t)buf_size, CT_MAX_LOG_HEAD_LENGTH - 1, "UTC%02d:%02d %s|%s|%05u|%u|%s>",
            tz_hour, tz_min, date, module_name, g_log_info.sess_id, cm_get_current_thread_id(), log_level_str);
    }

    if (SECUREC_UNLIKELY(errcode == -1)) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }
}

static void cm_log_close_file(log_file_handle_t *log_file_handle)
{
    if (log_file_handle->file_handle != -1) {
        close(log_file_handle->file_handle);
        log_file_handle->file_handle = -1;
        log_file_handle->file_inode = 0;
    }
}

static bool32 cm_log_stat_file(log_file_handle_t *log_file_handle, uint64 *file_size, uint32 *file_inode)
{
    struct stat st;

    /*
    The value of the two output parameters is unpredictable when the function returns false,
    so the file_size and file_inode are initialized to 0��
    */
    *file_size = 0;
    *file_inode = 0;

    if (stat(log_file_handle->file_name, &st) != 0) {
        return CT_FALSE;
    }

    *file_size = (uint64)st.st_size;
    *file_inode = (uint32)st.st_ino;
    return CT_TRUE;
}

/*
The parameter bak_file_name is the backup file name that is currently searched.
for example, "cantian_20081104160845999.log"
The parameter log_file_name is the file name of the log file��for example, "cantian"
The parameter log_ext_name is the extension of the log file��for example, ".log"
*/
static bool32 is_backup_file(const char *bak_file_name, const char *log_file_name, const char *log_ext_name)
{
    size_t log_file_name_len = strlen(log_file_name);
    size_t log_ext_name_len = strlen(log_ext_name);
    size_t bak_file_name_len = strlen(bak_file_name);
    size_t timestamp_len = strlen("_yyyymmddhhmissfff");
    // the 1 in the if condition is the length of the '.'
    if (log_file_name_len + timestamp_len + log_ext_name_len + 1 != bak_file_name_len) {
        return CT_FALSE;
    }

    // Compare the file names.
    if (strncmp(bak_file_name, log_file_name, (size_t)log_file_name_len) != 0) {
        return CT_FALSE;
    }

    // Compare the extension of the log file.
    // the 1 in the if condition is the length of the '.'
    const char *bak_file_ext_name = bak_file_name + log_file_name_len + timestamp_len + 1;
    if (strcmp(bak_file_ext_name, log_ext_name) != 0) {
        return CT_FALSE;
    }

    const char *timestamp = bak_file_name + log_file_name_len;
    if (timestamp[0] != '_') {
        return CT_FALSE;
    }
    for (unsigned int i = 1; i < timestamp_len; i++) {
        if (timestamp[i] < '0' || timestamp[i] > '9') {
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

// left_file_name is the backup file already in the list, and right_file_name is the new file to be inserted.
static bool32 cm_log_compare_file(const char *left_file_name, const char *right_file_name)
{
    struct stat left_file_stat;
    struct stat right_file_stat;

    // if left has a problem, continues to iterate, the left early deletion
    if (stat(left_file_name, &left_file_stat) != 0) {
        return CT_FALSE;
    }

    // if right has a problem, insert list, the right early deletion
    if (stat(right_file_name, &right_file_stat) != 0) {
        return CT_TRUE;
    }

    if (left_file_stat.st_mtime == right_file_stat.st_mtime) {
        return (strcmp(left_file_name, right_file_name) > 0);
    }

    return left_file_stat.st_mtime > right_file_stat.st_mtime;
}

static status_t cm_log_add_backup_file(char *backup_file_name[CT_MAX_LOG_FILE_COUNT], uint32 *backup_file_count,
    const char *log_dir, const char *bak_file)
{
    uint32 i, j;
    bool32 need_insert = CT_TRUE;
    errno_t errcode;

    char *file_name = (char *)malloc(CT_FILE_NAME_BUFFER_SIZE); // free in remove_bak_file
    if (file_name == NULL) {
        CT_THROW_ERROR(ERR_MALLOC_BYTES_MEMORY, CT_FILE_NAME_BUFFER_SIZE);
        return CT_ERROR;
    }

    errcode = snprintf_s(file_name, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/%s", log_dir, bak_file);
    if (SECUREC_UNLIKELY(errcode == -1)) {
        CM_FREE_PTR(file_name);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CT_ERROR;
    }

    // sort by filename from small to large.
    for (i = 0; i < *backup_file_count; ++i) {
        CT_BREAK_IF_TRUE(cm_log_compare_file(backup_file_name[i], file_name));
    }

    if (*backup_file_count == CT_MAX_LOG_FILE_COUNT) {
        if (i == 0) {
            cm_log_remove_file(file_name);
            CM_FREE_PTR(file_name);
            need_insert = CT_FALSE;
        } else {
            cm_log_remove_file(backup_file_name[0]);
            CM_FREE_PTR(backup_file_name[0]);
            for (j = 0; j < (*backup_file_count - 1); ++j) {
                backup_file_name[j] = backup_file_name[j + 1];
            }
            backup_file_name[j] = NULL;
            i--;
        }
    } else {
        (*backup_file_count)++;
    }

    if (need_insert) {
        for (j = (*backup_file_count) - 1; j > i; j--) {
            backup_file_name[j] = backup_file_name[j - 1];
        }
        backup_file_name[i] = file_name;
    }

    return CT_SUCCESS;
}

#ifdef _WIN32
static status_t cm_log_search_backup_file(char *backup_file_name[CT_MAX_LOG_FILE_COUNT], uint32 *backup_file_count,
    const char *log_dir, const char *log_file_name, const char *log_ext_name)
{
    char bak_file_fmt[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    WIN32_FIND_DATA data;

    PRTS_RETURN_IFERR(snprintf_s(bak_file_fmt, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/%s*.%s", log_dir,
        log_file_name, log_ext_name));

    HANDLE handle = FindFirstFile(bak_file_fmt, &data);
    if (handle == INVALID_HANDLE_VALUE) {
        CT_THROW_ERROR(ERR_INVALID_DIR, bak_file_fmt);
        return CT_ERROR;
    }

    do {
        if (is_backup_file(data.cFileName, log_file_name, log_ext_name)) {
            if (cm_log_add_backup_file(backup_file_name, backup_file_count, log_dir, data.cFileName) != CT_SUCCESS) {
                FindClose(handle);
                return CT_ERROR;
            }
        }
    } while (FindNextFile(handle, &data));

    FindClose(handle);
    return CT_SUCCESS;
}
#else
static status_t cm_log_search_backup_file(char *backup_file_name[CT_MAX_LOG_FILE_COUNT], uint32 *backup_file_count,
    const char *log_dir, const char *file_name, const char *log_ext_name)
{
    struct dirent *ent = NULL;

    DIR *dir = opendir(log_dir);
    if (dir == NULL) {
        CT_THROW_ERROR(ERR_INVALID_DIR, log_dir);
        return CT_ERROR;
    }

    ent = readdir(dir);
    while (ent != NULL) {
        if (is_backup_file(ent->d_name, file_name, log_ext_name)) {
            if (cm_log_add_backup_file(backup_file_name, backup_file_count, log_dir, ent->d_name) != CT_SUCCESS) {
                (void)closedir(dir);
                return CT_ERROR;
            }
        }
        ent = readdir(dir);
    }

    (void)closedir(dir);
    return CT_SUCCESS;
}
#endif

status_t cm_log_get_bak_file_list(char *backup_file_name[CT_MAX_LOG_FILE_COUNT], uint32 *backup_file_count,
    const char *log_file)
{
    // 1.The log file path, the file name, and extension of the log file are parsed from the input parameters
    const char *log_dir = NULL;
    const char *log_file_name = NULL;
    const char *log_ext_name = NULL;
    errno_t errcode;
    /*
    for example , if log_file = "/home/enipcore/log/run/cantian.log"
    then log_dir = "/home/enipcore/log/run", log_file_name = "cantian", log_ext_name = "log"
    */
    char buf[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    errcode = strncpy_s(buf, CT_FILE_NAME_BUFFER_SIZE, log_file, CT_MAX_FILE_NAME_LEN);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CT_ERROR;
    }

    char *p = NULL;
    p = strrchr(buf, '/');
    if (p == NULL) {
        CT_THROW_ERROR(ERR_INVALID_DIR, log_file);
        return CT_ERROR;
    }
    *p = '\0';
    log_dir = buf;

    log_file_name = p + 1;
    p = strrchr((char *)log_file_name, '.');
    if (p == NULL) {
        CT_THROW_ERROR(ERR_INVALID_DIR, log_file);
        return CT_ERROR;
    }
    *p = '\0';

    log_ext_name = p + 1;

    // 2.Iterate through the directory and add the found backup files to the backup_file_name.
    return cm_log_search_backup_file(backup_file_name, backup_file_count, log_dir, log_file_name, log_ext_name);
}

// Deletes redundant backup files with the number of files that need to be preserved
static void cm_log_remove_bak_file(char *backup_file_name[CT_MAX_LOG_FILE_COUNT], uint32 *remove_file_count,
    uint32 backup_file_count, uint32 need_backup_count)
{
    uint32 i;
    *remove_file_count = 0;

    if (backup_file_count > need_backup_count) {
        *remove_file_count = backup_file_count - need_backup_count;
    }

    for (i = 0; i < backup_file_count; ++i) {
        if (i < *remove_file_count) {
            cm_log_remove_file(backup_file_name[i]);
        } else {
            /* free name of file that is not removed
            name of removed file will be freed after log */
            CM_FREE_PTR(backup_file_name[i]);
        }
    }
}

static void cm_log_get_bak_file_name(log_file_handle_t *log_file_handle, char *bak_file)
{
    /*
    The name of the backup log��logFile.ext ==> logFile_yyyymmddhhmissff3.ext
    Where logFile is the file name, ext is the file extension, and yyyymmddhhmissff3 is in milliseconds.
    */
    char file_name[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    char ext_name[64] = { 0 };
    char timestamp[64] = { 0 };
    char *file_ext_name = NULL;
    size_t name_len = CT_MAX_FILE_NAME_LEN;
    errno_t errcode;
    date_detail_t detail;
    cm_now_detail(&detail);

    errcode = snprintf_s(timestamp, sizeof(timestamp), sizeof(timestamp) - 1, "%4u%02u%02u%02d%02u%02u%03u",
        detail.year, detail.mon, detail.day, detail.hour, detail.min, detail.sec, detail.millisec);
    if (SECUREC_UNLIKELY(errcode == -1)) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }

    // Gets the file name and extension of the backup file.
    errcode = strncpy_s(file_name, sizeof(file_name), log_file_handle->file_name, (size_t)name_len);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }

    /*
    Find the character '.' from the file_name.
    Because the log file name is generated inside the code, there must be a character '.'
    */
    char *p = strrchr(file_name, '.');
    if (p == NULL) {
        return;
    }
    *p = '\0';

    file_ext_name = p + 1;
    name_len = (uint32)strlen(file_ext_name);
    errcode = strncpy_s(ext_name, sizeof(ext_name), file_ext_name, (size_t)name_len);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }
    errcode = snprintf_s(bak_file, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s_%s.%s", file_name, timestamp,
        ext_name);
    if (SECUREC_UNLIKELY(errcode == -1)) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }
}

/*
    1.Back up the current log file (ensure that the current log file has been turned off before backing up the file)
    2.bak_file_name : all backup file name before transfer, 0 ~ remove_file_count need to be removed
    3.new_bak_file_name : a new log file name cantiand.rlog transferred to, for example cantiand_20190414041002173.rlog
*/
static status_t cm_rmv_and_bak_log_file(log_file_handle_t *log_file_handle, char *bak_file_name[CT_MAX_LOG_FILE_COUNT],
    char new_bak_file_name[CT_FILE_NAME_BUFFER_SIZE], uint32 *remove_file_count)
{
    uint32 backup_file_count = 0;
    uint64 file_size;
    uint32 file_inode;
    uint32 need_bak_file_count =
        log_file_handle->log_id == LOG_AUDIT ? g_log_param.audit_backup_file_count : g_log_param.log_backup_file_count;
    uint32 file_name_len = CT_MAX_FILE_NAME_LEN;

    // When you do not back up, delete the log file directly, and re-open will automatically generate a new empty file.
    if (need_bak_file_count == 0) {
        cm_log_remove_file(log_file_handle->file_name);
        bak_file_name[0] = (char *)malloc(CT_FILE_NAME_BUFFER_SIZE);
        if (bak_file_name[0] == NULL) {
            return CT_ERROR;
        }
        *remove_file_count = 1;
        MEMS_RETURN_IFERR(
            strncpy_s(bak_file_name[0], CT_FILE_NAME_BUFFER_SIZE, log_file_handle->file_name, (size_t)file_name_len));
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(cm_log_get_bak_file_list(bak_file_name, &backup_file_count, log_file_handle->file_name));

    // Passing need_bak_file_count - 1 is because log_file_handle->file_name is about to be converted to a backup file.
    cm_log_remove_bak_file(bak_file_name, remove_file_count, backup_file_count, need_bak_file_count - 1);

    cm_log_get_bak_file_name(log_file_handle, new_bak_file_name);
    cm_log_remove_file(new_bak_file_name);
    if (log_file_handle->log_id == LOG_OPER && cm_log_stat_file(log_file_handle, &file_size, &file_inode) == CT_TRUE) {
        if (file_size < g_log_param.max_log_file_size) {
            // multi ctsqls write one ctsql.olog: ctsql.olog has already be renamed
            // double check ctsql.olog size
            return CT_SUCCESS;
        }
    }

    if (rename(log_file_handle->file_name, new_bak_file_name) == 0 &&
        chmod(new_bak_file_name, g_log_param.log_bak_file_permissions) == 0) {
        return CT_SUCCESS;
    }

    return CT_ERROR;
}

static inline int cm_log_open_flag(log_id_t log_id)
{
    // run/longsql/alarm/oper/blackbox should be written synchronously to avoid erroneous data caused by power failure
    switch (log_id) {
        case LOG_RUN:
        case LOG_ALARM:
        case LOG_LONGSQL:
        case LOG_OPER:
        case LOG_ODBC:
        case LOG_CTENCRYPT_OPER:
        case LOG_BLACKBOX:
        default:
            return O_RDWR | O_APPEND | O_CREAT;
    }
}

void cm_log_open_file(log_file_handle_t *log_file_handle)
{
    uint64 file_size;
    uint32 file_inode;

    log_file_handle->file_inode = 0;
    log_file_handle->file_handle = -1;

    // check log dir, if have not dir, then create dir
    cm_log_create_dir(log_file_handle);

    int flags = cm_log_open_flag(log_file_handle->log_id);
    int handle = open(log_file_handle->file_name, flags, g_log_param.log_file_permissions);
    if (handle == -1) {
        return;
    }

    if (!cm_log_stat_file(log_file_handle, &file_size, &file_inode)) {
        close(handle);
        return;
    }

    log_file_handle->file_handle = handle;
    log_file_handle->file_inode = file_inode;
}

static void cm_write_log_file(log_file_handle_t *log_file_handle, char *buf, uint32 size_input)
{
    uint32 size = size_input;
    if (log_file_handle->file_handle == -1) {
        cm_log_open_file(log_file_handle);
    }

    // It is possible to fail because of the open file.
    if (log_file_handle->file_handle != -1 && buf != NULL) {
        // Replace the string terminator '\0' with newline character '\n'.
        if (log_file_handle->log_id != LOG_BLACKBOX) {
            buf[size] = '\n';
            size++;
        }
        if (write(log_file_handle->file_handle, buf, size) == -1) {
            return;
        }
    }
}

static void cm_write_longsql_file(log_file_handle_t *log_file_handle, char *buf, uint32 size)
{
    if (log_file_handle->file_handle == -1) {
        cm_log_open_file(log_file_handle);
    }

    // It is possible to fail because of the open file.
    if (log_file_handle->file_handle != -1 && buf != NULL) {
        if (write(log_file_handle->file_handle, buf, size) == -1) {
            return;
        }
    }
}

static void cm_write_rmv_and_bak_file_log(char *bak_file_name[CT_MAX_LOG_FILE_COUNT], uint32 remove_file_count,
    char curr_bak_file_name[CT_FILE_NAME_BUFFER_SIZE])
{
    for (uint32 i = 0; i < remove_file_count; ++i) {
        CT_LOG_RUN_FILE_INF(CT_FALSE, "[LOG] file '%s' is removed", bak_file_name[i]);
    }

    if (strlen(curr_bak_file_name) != 0) {
        CT_LOG_RUN_FILE_INF(CT_FALSE, "[LOG] file '%s' is added", curr_bak_file_name);
    }
}

static void cm_stat_and_write_log(log_file_handle_t *log_file_handle, char *buf, uint32 size, bool32 need_rec_filelog,
    cm_log_write_func_t func)
{
    uint64 file_size = 0;
    uint32 file_inode = 0;
    // TEST RESULT: 10000 timeout_ticks is approximately 1 second
    // in SUSE 11 (8  Intel(R) Xeon(R) CPU E5-2690 v2 @ 3.00GHz)
    uint32 timeout_ticks = 10000;
    char new_bak_file_name[CT_FILE_NAME_BUFFER_SIZE];
    char *bak_file_name[CT_MAX_LOG_FILE_COUNT];
    uint32 remove_file_count = 0;
    int handle_before_log;
    uint64 max_file_size;
    new_bak_file_name[0] = '\0';
    status_t ret = CT_SUCCESS;

    if (LOG_DEBUG_INF_ON || (g_log_param.audit_param.audit_level & SQL_AUDIT_DML)) {
        timeout_ticks = 100000;
    }

    if (!cm_spin_timed_lock(&log_file_handle->lock, timeout_ticks)) {
        return;
    }

    if (!cm_log_stat_file(log_file_handle, &file_size, &file_inode)) {
        cm_log_close_file(log_file_handle);
    }

    if (file_inode != log_file_handle->file_inode) {
        cm_log_close_file(log_file_handle);
    }

    max_file_size =
        log_file_handle->log_id == LOG_AUDIT ? g_log_param.max_audit_file_size : g_log_param.max_log_file_size;
    if ((file_size + 100 > max_file_size && need_rec_filelog == CT_TRUE) ||
        /*
        1.reserve 2000 bytes in case of run log increasing continuously with backup file log
        2.in case of dead loop when file_size larger than max_file_size + SIZE_K(2)
        */
        (file_size < max_file_size + SIZE_K(3) && file_size > max_file_size + SIZE_K(2) &&
        need_rec_filelog == CT_FALSE)) {
        cm_log_close_file(log_file_handle);
        ret = cm_rmv_and_bak_log_file(log_file_handle, bak_file_name, new_bak_file_name, &remove_file_count);
    }

    if (ret == CT_SUCCESS) {
        handle_before_log = log_file_handle->file_handle;
        func(log_file_handle, buf, size);
        cm_spin_unlock(&log_file_handle->lock);
        cm_write_rmv_and_bak_file_log(bak_file_name, remove_file_count, new_bak_file_name);
        if (handle_before_log == -1 && log_file_handle->file_handle != -1) {
            CT_LOG_RUN_FILE_INF(CT_FALSE, "[LOG] file '%s' is added", log_file_handle->file_name);
        }
    } else {
        cm_spin_unlock(&log_file_handle->lock);
    }
    for (uint32 i = 0; i < remove_file_count; ++i) {
        CM_FREE_PTR(bak_file_name[i]);
    }
}

static void cm_log_write_large_buf(const char *buf, bool32 need_rec_filelog, const char *format, va_list ap,
    log_file_handle_t *log_file_hanle)
{
    size_t log_head_len = strlen(buf);
    va_list ap1;
    errno_t errcode;
    va_copy(ap1, ap);
    char *pTmp = (char *)malloc(CT_MAX_LOG_NEW_BUFFER_SIZE);
    if (pTmp == NULL) {
        va_end(ap1);
        return;
    }

    errcode = strncpy_s(pTmp, CT_MAX_LOG_NEW_BUFFER_SIZE, buf, log_head_len);
    if (errcode != EOK) {
        CM_FREE_PTR(pTmp);
        va_end(ap1);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }
    errcode = vsnprintf_s(pTmp + log_head_len, (size_t)(CT_MAX_LOG_NEW_BUFFER_SIZE - log_head_len),
        (size_t)(CT_MAX_LOG_NEW_BUFFER_SIZE - log_head_len - 1), format, ap1);
    va_end(ap1);
    if (errcode >= 0) {
        cm_stat_and_write_log(log_file_hanle, pTmp, (uint32)strlen(pTmp), need_rec_filelog, cm_write_log_file);
    } else {
        // if the security function fails, continue to write the log after the string is truncated
        cm_stat_and_write_log(log_file_hanle, pTmp, (uint32)strlen(pTmp), need_rec_filelog, cm_write_log_file);
    }
    CM_FREE_PTR(pTmp);
}

static void cm_log_fulfil_write_buf(log_file_handle_t *log_file_handle, text_t *buf_text, uint32 buf_size,
    bool32 need_rec_filelog, const char *format, va_list ap)
{
    va_list ap1;
    va_copy(ap1, ap);
    int32 iRtn = vsnprintf_s(buf_text->str + buf_text->len, (size_t)(buf_size - buf_text->len),
        (size_t)(buf_size - buf_text->len - 1), format, ap1);
    va_end(ap1);
    if (iRtn < 0) {
        CM_NULL_TERM(buf_text);
        cm_log_write_large_buf(buf_text->str, need_rec_filelog, format, ap, log_file_handle);
        return;
    }
    if (g_filter_enable) {
        do_security_filter(buf_text->str);
    }

    cm_stat_and_write_log(log_file_handle, buf_text->str, (uint32)strlen(buf_text->str), need_rec_filelog,
        cm_write_log_file);
}

void cm_write_normal_log(log_id_t log_id, log_level_t log_level, const char *code_file_name, uint32 code_line_num,
    const int module_id, bool32 need_rec_filelog, const char *format, ...)
{
    int32 error_code = 0;
    char buf[CT_MAX_LOG_CONTENT_LENGTH + CT_MAX_LOG_HEAD_LENGTH + 2] = { 0 };
    char new_format[CT_MAX_LOG_CONTENT_LENGTH] = { 0 };
    log_file_handle_t *log_file_handle = &g_logger[log_id];
    text_t buf_text;
    char *last_file = NULL;
    const char *err_msg = NULL;
    log_param_t *log_param = cm_log_param_instance();
    errno_t errcode;

#ifdef WIN32
    last_file = strrchr(code_file_name, '\\');
#else
    last_file = strrchr(code_file_name, '/');
#endif

    if (log_param->log_instance_startup) {
        errcode = snprintf_s(new_format, CT_MAX_LOG_CONTENT_LENGTH, CT_MAX_LOG_CONTENT_LENGTH - 1, "%s [%s:%u]", format,
            last_file + 1, code_line_num);
    } else {
        if (log_id == LOG_RUN) {
            cm_get_error(&error_code, &err_msg, NULL);
        }

        if (error_code == 0 || need_rec_filelog == CT_FALSE) {
            errcode = snprintf_s(new_format, CT_MAX_LOG_CONTENT_LENGTH, CT_MAX_LOG_CONTENT_LENGTH - 1, "%s [%s:%u]",
                format, last_file + 1, code_line_num);
        } else if (error_code == ERR_ASSERT_ERROR) {
            errcode = snprintf_s(new_format, CT_MAX_LOG_CONTENT_LENGTH, CT_MAX_LOG_CONTENT_LENGTH - 1,
                "CT-%05d:%s,%s [%s:%u]", error_code, format, err_msg, last_file + 1, code_line_num);
        } else {
            errcode = snprintf_s(new_format, CT_MAX_LOG_CONTENT_LENGTH, CT_MAX_LOG_CONTENT_LENGTH - 1,
                "CT-%05d:%s,%s [%s:%u]", error_code, format, err_msg, last_file + 1, code_line_num);
        }
    }
 
    cm_log_build_normal_head((char *)buf, sizeof(buf), log_level, g_module_info[module_id]);
 
    va_list args;
    va_start(args, format);
    buf_text.str = buf;
    buf_text.len = (uint32)strlen(buf);
    if (errcode >= 0) {
        cm_log_fulfil_write_buf(log_file_handle, &buf_text, sizeof(buf), need_rec_filelog, new_format, args);
    } else {
        // if the security function fails, continue to write the log after the string is truncated
        cm_log_fulfil_write_buf(log_file_handle, &buf_text, sizeof(buf), need_rec_filelog, new_format, args);
    }
    va_end(args);
}

void cm_write_audit_log(const char *format, ...)
{
    char buf[CT_MAX_LOG_CONTENT_LENGTH + 1] = { 0 };
    text_t buf_text;
    log_file_handle_t *log_file_handle = &g_logger[LOG_AUDIT];
    va_list args;
    va_start(args, format);
    buf_text.str = buf;
    buf_text.len = 0;
    cm_log_fulfil_write_buf(log_file_handle, &buf_text, sizeof(buf), CT_TRUE, format, args);
    va_end(args);
}

uint32 g_warn_id[] = {
    WARN_FILEDESC_ID,      WARN_DEADLOCK_ID,       WARN_DEGRADE_ID,        WARN_REPL_PASSWD_ID, WARN_JOB_ID,
    WARN_AGENT_ID,         WARN_MAXCONNECTIONS_ID, WARN_ARCHIVE_ID,        WARN_FLUSHREDO_ID,   WARN_FLUSHBUFFER_ID,
    WARN_SPACEUSAGE_ID,    WARN_FILEMONITOR_ID,    WARN_MALICIOUSLOGIN_ID, WARN_PARAMCHANGE_ID, WARN_PASSWDCHANGE_ID,
    WARN_PROFILECHANGE_ID, WARN_AUDITLOG_ID,       WARN_PAGE_CORRUPTED_ID, WARN_UNDO_USAGE_ID,  WARN_NOLOG_OBJ_ID,
};

char *g_warning_desc[] = {
    "InsufficientDataInstFileDesc",
    "Deadlock",
    "Degrade",
    "ReplPasswd",
    "Job",
    "AttachAgent",
    "MaxConnections",
    "Archive",
    "FlushRedo",
    "FlushBuffer",
    "TablespaceUsage",
    "FileMonitor",
    "MaliciousLogin",
    "Parameter",
    "Password",
    "Profile",
    "AuditLog",
    "PageCorrupt",
    "UndospaceUsage",
    "NologgingInsertObejct",
};

void cm_write_alarm_log(uint32 warn_id, const char *format, ...)
{
    char buf[CT_MAX_LOG_CONTENT_LENGTH + 2] = { 0 };
    text_t buf_text;
    log_file_handle_t *log_file_handle = &g_logger[LOG_ALARM];
    char date[CT_MAX_TIME_STRLEN] = { 0 };
    errno_t errcode;

    (void)cm_date2str(cm_now(), "yyyy-mm-dd hh24:mi:ss", date, CT_MAX_TIME_STRLEN);
    // Format: Date | Warn_Id | Warn_Desc | Components | Instance_name | parameters
    errcode = snprintf_s(buf, sizeof(buf), CT_MAX_LOG_CONTENT_LENGTH + 1,
        "%s|%u|%s|%s|%s|{'component-name':'%s','datanode-name':'%s',", date, g_warn_id[warn_id],
        g_warning_desc[warn_id], "DN", g_log_param.instance_name, "DN", g_log_param.instance_name);
    if (errcode < 0) {
        return;
    }

    va_list args;
    va_start(args, format);
    buf_text.str = buf;
    buf_text.len = (uint32)strlen(buf);
    cm_log_fulfil_write_buf(log_file_handle, &buf_text, sizeof(buf), CT_TRUE, format, args);
    va_end(args);
}

void cm_write_alarm_log_cn(uint32 warn_id, const char *format, ...)
{
    char buf[CT_MAX_LOG_CONTENT_LENGTH + 2] = { 0 };
    text_t buf_text;
    log_file_handle_t *log_file_handle = &g_logger[LOG_ALARM];
    char date[CT_MAX_TIME_STRLEN] = { 0 };
    errno_t rc_memzero;

    (void)cm_date2str(cm_now(), "yyyy-mm-dd hh24:mi:ss", date, CT_MAX_TIME_STRLEN);
    // Format: Date | Warn_Id | Warn_Desc | Components | Instance_name | parameters
    rc_memzero = snprintf_s(buf, sizeof(buf), CT_MAX_LOG_CONTENT_LENGTH + 1, "%s|%u|%s|%s|%s|", date,
        g_warn_id[warn_id], g_warning_desc[warn_id], "CN", g_log_param.instance_name);
    if (rc_memzero < 0) {
        return;
    }

    va_list args;
    va_start(args, format);
    buf_text.str = buf;
    buf_text.len = (uint32)strlen(buf);
    cm_log_fulfil_write_buf(log_file_handle, &buf_text, sizeof(buf), CT_TRUE, format, args);
    va_end(args);
}

void cm_write_longsql_log(const char *format, ...)
{
    char buf[CT_LOG_LONGSQL_LENGTH_16K + sizeof(uint32) + 1] = { 0 };
    log_file_handle_t *log_file_handle = &g_logger[LOG_LONGSQL];
    va_list args;
    errno_t errcode;
    va_start(args, format);
    errcode = vsnprintf_s(buf + sizeof(uint32), CT_LOG_LONGSQL_LENGTH_16K + 1, CT_LOG_LONGSQL_LENGTH_16K, format, args);

    *((uint32 *)buf) = (uint32)strlen(buf + sizeof(uint32));
    if (errcode >= 0) {
        cm_stat_and_write_log(log_file_handle, buf, *((uint32 *)buf) + sizeof(uint32), CT_TRUE, cm_write_longsql_file);
    } else {
        // if the security function fails, continue to write the log after the string is truncated
        cm_stat_and_write_log(log_file_handle, buf, *((uint32 *)buf) + sizeof(uint32), CT_TRUE, cm_write_longsql_file);
    }

    va_end(args);
}

void cm_write_max_longsql_log(const char *format, ...)
{
    errno_t rc_memzero;
    char *buf = (char *)malloc(CT_MAX_LOG_LONGSQL_LENGTH + sizeof(uint32) + 1);
    if (buf == NULL) {
        return;
    }
    rc_memzero = memset_s(buf, CT_MAX_LOG_LONGSQL_LENGTH, 0, CT_MAX_LOG_LONGSQL_LENGTH);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(buf);
        return;
    }

    log_file_handle_t *log_file_handle = &g_logger[LOG_LONGSQL];
    va_list args;
    va_start(args, format);
    rc_memzero =
        vsnprintf_s(buf + sizeof(uint32), CT_MAX_LOG_LONGSQL_LENGTH + 1, CT_MAX_LOG_LONGSQL_LENGTH, format, args);

    *((uint32 *)buf) = (uint32)strlen(buf + sizeof(uint32));
    if (rc_memzero >= 0) {
        cm_stat_and_write_log(log_file_handle, buf, *((uint32 *)buf) + sizeof(uint32), CT_TRUE, cm_write_longsql_file);
    } else {
        // if the security function fails, continue to write the log after the string is truncated
        cm_stat_and_write_log(log_file_handle, buf, *((uint32 *)buf) + sizeof(uint32), CT_TRUE, cm_write_longsql_file);
    }

    CM_FREE_PTR(buf);
    va_end(args);
}

void cm_write_oper_log(char *buf, uint32 len)
{
    log_file_handle_t *log_file_handle = &g_logger[LOG_OPER];

    if (len > 0) {
        cm_stat_and_write_log(log_file_handle, buf, len, CT_TRUE, cm_write_log_file);
    }
}

void cm_write_pe_oper_log(char *buf, uint32 len)
{
    log_file_handle_t *log_file_handle = &g_logger[LOG_CTENCRYPT_OPER];

    if (len > 0) {
        cm_stat_and_write_log(log_file_handle, buf, len, CT_TRUE, cm_write_log_file);
    }
}

void cm_write_trace_log(const char *format, ...)
{
    char buf[CT_LOG_LONGSQL_LENGTH_16K] = { 0 }; // print deadlock sql log, use long sql length
    log_file_handle_t *log_file_handle = &g_logger[LOG_TRACE];
    va_list args;
    errno_t errcode;
    va_start(args, format);
    errcode = vsnprintf_s(buf, CT_LOG_LONGSQL_LENGTH_16K, CT_LOG_LONGSQL_LENGTH_16K - 1, format, args);
    if (errcode >= 0) {
        cm_stat_and_write_log(log_file_handle, buf, (uint32)strlen(buf), CT_TRUE, cm_write_log_file);
    } else {
        // if the security function fails, continue to write the log after the string is truncated
        cm_stat_and_write_log(log_file_handle, buf, (uint32)strlen(buf), CT_TRUE, cm_write_log_file);
    }

    va_end(args);
}

void cm_log_allinit(void)
{
    log_file_handle_t *log_file = NULL;
    for (uint32 log_id = 0; log_id < LOG_COUNT; log_id++) {
        log_file = &g_logger[log_id];
        CT_INIT_SPIN_LOCK(log_file->lock);
        log_file->file_handle = -1;
        log_file->file_inode = 0;
        log_file->log_id = log_id;
    }
}

void cm_log_init(log_id_t log_id, const char *file_name)
{
    log_file_handle_t *log_file = &g_logger[log_id];
    uint32 file_name_len = CT_MAX_FILE_NAME_LEN;
    errno_t errcode;

    CT_INIT_SPIN_LOCK(log_file->lock);

    errcode = strncpy_s(log_file->file_name, CT_FILE_NAME_BUFFER_SIZE, file_name, (size_t)file_name_len);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }

    log_file->file_handle = -1;
    log_file->file_inode = 0;
    log_file->log_id = log_id;
}

// if val = 700, log_file_permissions is (S_IRUSR | S_IWUSR | S_IXUSR)
void cm_log_set_file_permissions(uint16 val)
{
    uint16 usr_perm;
    uint16 grp_perm;
    uint16 oth_perm;
    uint32 log_file_perm = 0;
    uint32 log_bak_file_perm = 0;

    usr_perm = (val / 100) % 10;
    if (usr_perm & 1) {
        log_file_perm |= S_IXUSR;
    }

    if (usr_perm & 2) {
        log_file_perm |= S_IWUSR;
    }

    if (usr_perm & 4) {
        log_file_perm |= S_IRUSR;
        log_bak_file_perm |= S_IRUSR;
    }

    grp_perm = (val / 10) % 10;
    if (grp_perm & 1) {
        log_file_perm |= S_IXGRP;
        log_bak_file_perm |= S_IXGRP;
    }

    if (grp_perm & 2) {
        log_file_perm |= S_IWGRP;
    }

    if (grp_perm & 4) {
        log_file_perm |= S_IRGRP;
        log_bak_file_perm |= S_IRGRP;
    }

    oth_perm = val % 10;
    if (oth_perm & 1) {
        log_file_perm |= S_IXOTH;
        log_bak_file_perm |= S_IXOTH;
    }

    if (oth_perm & 2) {
        log_file_perm |= S_IWOTH;
    }

    if (oth_perm & 4) {
        log_file_perm |= S_IROTH;
        log_bak_file_perm |= S_IROTH;
    }

    g_log_param.log_bak_file_permissions = log_bak_file_perm;
    g_log_param.log_file_permissions = log_file_perm;
}

// if val = 700, log_path_permissions is (S_IRUSR | S_IWUSR | S_IXUSR)
void cm_log_set_path_permissions(uint16 val)
{
    uint16 usr_perm;
    uint16 grp_perm;
    uint16 oth_perm;
    uint32 log_path_perm = 0;

    usr_perm = (val / 100) % 10;
    if (usr_perm & 1) {
        log_path_perm |= S_IXUSR;
    }

    if (usr_perm & 2) {
        log_path_perm |= S_IWUSR;
    }

    if (usr_perm & 4) {
        log_path_perm |= S_IRUSR;
    }

    grp_perm = (val / 10) % 10;
    if (grp_perm & 1) {
        log_path_perm |= S_IXGRP;
    }

    if (grp_perm & 2) {
        log_path_perm |= S_IWGRP;
    }

    if (grp_perm & 4) {
        log_path_perm |= S_IRGRP;
    }

    oth_perm = val % 10;
    if (oth_perm & 1) {
        log_path_perm |= S_IXOTH;
    }

    if (oth_perm & 2) {
        log_path_perm |= S_IWOTH;
    }

    if (oth_perm & 4) {
        log_path_perm |= S_IROTH;
    }

    g_log_param.log_path_permissions = log_path_perm;
}

void cm_fync_logfile(void)
{
#ifndef _WIN32
    if (cm_dbs_is_enable_dbs() == CT_TRUE) {
        (void)dbs_global_handle()->dbs_client_flush_log();
    }
    for (int i = 0; i < LOG_COUNT; i++) {
        if (g_logger[i].file_handle != -1) {
            (void)fsync(g_logger[i].file_handle);
            cm_log_close_file(&g_logger[i]);
        }
    }
#endif
}

void cm_write_blackbox_log(const char *format, ...)
{
    char buf[CT_MAX_LOG_CONTENT_LENGTH + 1] = { 0 };
    text_t buf_text;
    log_file_handle_t *log_file_handle = &g_logger[LOG_BLACKBOX];

    va_list args;
    va_start(args, format);
    buf_text.str = buf;
    buf_text.len = (uint32)strlen(buf);
    cm_log_fulfil_write_buf(log_file_handle, &buf_text, sizeof(buf), CT_TRUE, format, args);
    va_end(args);
}

void cm_dump_mem(void *dump_addr, uint32 dump_len)
{
    uint32 index;
    uchar *dump_loc;
    uchar row_data[16] = { 0 };
    uint32 row_index = 0;

    dump_loc = (uchar *)dump_addr;

    if ((dump_addr == NULL) || (dump_len == 0)) {
        CT_LOG_BLACKBOX("[DUMP] dump memory Fail, dump_addr or dump_len equal zero\r\n");
        return;
    }

    for (index = 0; index < dump_len; dump_loc++, index++, row_index++) {
        if ((index % 4) == 0) {
            if ((index % 16) == 0) {
                for (row_index = 0; ((row_index < 16) && (index != 0)); row_index++) {
                    CT_LOG_BLACKBOX("%c", row_data[row_index]);
                    row_data[row_index] = 0;
                }

                row_index = 0;
            } else {
                CT_LOG_BLACKBOX(" ");
            }
        }

        row_data[row_index] = *dump_loc;
        CT_LOG_BLACKBOX("%2x ", *dump_loc);
    }

    if ((index % 16) != 0) {
        while ((index % 16) != 0) {
            if ((index % 4) == 0) {
                if ((index % 16) != 0) {
                    CT_LOG_BLACKBOX(" ");
                }
            }

            CT_LOG_BLACKBOX("   ");
            row_data[row_index] = 0;
            index++;
            row_index++;
        }

        for (row_index = 0; row_index < 16; row_index++) {
            CT_LOG_BLACKBOX("%c", row_data[row_index]);
        }
    }
    CT_LOG_BLACKBOX("\r\n");
    return;
}

void cm_print_call_link(uint32 stack_depth)
{
#ifndef WIN32
    void *array[CT_MAX_BLACK_BOX_DEPTH] = { 0 };
    size_t size;

    size = backtrace(array, stack_depth);
    CT_LOG_BLACKBOX("\nStack information when exception\n");
    log_file_handle_t *log_file_handle = cm_log_logger_file(LOG_BLACKBOX);
    backtrace_symbols_fd(array, size, log_file_handle->file_handle);
#endif
}

uint64_t cm_print_memory_usage(void)
{
#ifndef WIN32

    uint64_t rss_page_cnt;
    uint64_t vm_page_cnt;
    uint64_t pid = getpid();
    char statm_path[CT_FILE_NAME_BUFFER_SIZE] = { 0 };

    errno_t err = sprintf_s(statm_path, sizeof(statm_path), "/proc/%llu/statm", pid);
    if (err == -1) {
        return 0;
    }

    FILE *file = fopen(statm_path, "rb");
    if (file == NULL) {
        return 0;
    }

    if (fscanf_s(file, "%llu %llu", &vm_page_cnt, &rss_page_cnt) < 0) {
        (void)fclose(file);
        return 0;
    }
    (void)fclose(file);
    return rss_page_cnt;
#else
    return 0;
#endif
}
