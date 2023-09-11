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
 * cm_config.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_config.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_config.h"
#include "cm_hash.h"
#include "cm_file.h"

#ifndef WIN32
#include <termios.h>
#else
#include <conio.h>
#endif  // !WIN32

#ifdef __cplusplus
extern "C" {
#endif
static spinlock_t g_config_lock = 0;
static status_t cm_parse_config(config_t *config, char *buf, uint32 buf_len, bool32 is_ifile, bool32 set_alias);
static status_t cm_set_config_item(config_t *config, text_t *name, text_t *value, text_t *comment,
                                   bool32 is_infile, bool32 set_alias);

static status_t cm_alloc_config_buf(config_t *config, uint32 size_input, char **buf)
{
    uint32 size = size_input;
    CM_POINTER2(config, buf);
    errno_t errcode = 0;
    if (config->value_buf == NULL) {
        if (config->value_buf_size == 0) {
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)config->value_buf_size, "config value");
            return GS_ERROR;
        }
        config->value_buf = (char *)malloc(config->value_buf_size);
        if (config->value_buf == NULL) {
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)config->value_buf_size, "config value");
            return GS_ERROR;
        }
        errcode = memset_sp(config->value_buf, (size_t)config->value_buf_size, 0, (size_t)config->value_buf_size);
        if (errcode != EOK) {
            CM_FREE_PTR(config->value_buf);
            GS_THROW_ERROR(ERR_RESET_MEMORY, "config->value_buf");
            return GS_ERROR;
        }
    }
    size = CM_ALIGN4(size);
    if (config->value_offset + size > config->value_buf_size) {
        GS_THROW_ERROR(ERR_CONFIG_BUFFER_FULL);
        return GS_ERROR;
    }

    *buf = config->value_buf + config->value_offset;
    config->value_offset += size;
    return GS_SUCCESS;
}

config_item_t* cm_get_config_item(const config_t *config, text_t *name, bool32 set_alias)
{
    uint32 hash_value;
    config_item_t *item = NULL;
    
    CM_POINTER2(config, name);

    hash_value = cm_hash_text(name, GS_CONFIG_HASH_BUCKETS);
    item = config->name_map[hash_value];

    while (item != NULL) {
        if (cm_text_str_equal_ins(name, item->name)) {
            if (set_alias) {
                item->hit_alias = GS_FALSE;
            }
            return item;
        }

        item = item->hash_next;
    }
    hash_value = cm_hash_text(name, GS_CONFIG_ALIAS_HASH_BUCKETS);
    item = config->alias_map[hash_value];
    while (item != NULL) {
        if (cm_text_str_equal_ins(name, item->alias)) {
            if (set_alias) {
                item->hit_alias = GS_TRUE;
            }
            return item;
        }

        item = item->hash_next2;
    }
    return NULL;
}

char *cm_get_config_value(const config_t *config, const char *name)
{
    config_item_t *item = NULL;
    text_t text;
    CM_POINTER(config);

    cm_str2text((char *)name, &text);
    item = cm_get_config_item(config, &text, GS_FALSE);
    if (item == NULL) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER_NAME, name);
        return NULL;
    }

    if (item->is_default) {
        return item->default_value;
    }

    return item->value;
}

static status_t cm_get_fullpath(config_t *config, text_t *filepath, char *fullpath, uint32 len)
{
    text_t text;
    char buf[GS_FILE_NAME_BUFFER_SIZE];
    bool32 is_fullpath = (filepath->len == 0 || CM_TEXT_FIRST(filepath) == '/' || CM_TEXT_FIRST(filepath) == '\\');

#ifdef WIN32
    is_fullpath = is_fullpath || (cm_get_first_pos(filepath, ':') != GS_INVALID_ID32);
#endif
    if (!is_fullpath) {
        text.str = buf;
        text.len = 0;
        GS_RETURN_IFERR(cm_concat_string(&text, GS_FILE_NAME_BUFFER_SIZE, config->file_name));
        text.len = cm_get_last_pos(&text, '/');
        if ((text.len == GS_INVALID_ID32) || (text.len + filepath->len + 1 >= len)) {
            return GS_ERROR;
        }
        text.len++;
        cm_concat_text(&text, GS_FILE_NAME_BUFFER_SIZE, filepath);
        buf[text.len] = '\0';
    } else {
        GS_RETURN_IFERR(cm_text2str(filepath, buf, sizeof(buf)));
    }

#ifdef WIN32
    (void)_fullpath(fullpath, buf, len);
#else
    char resolved_path[PATH_MAX];
    uint32 path_len;
    errno_t errcode;

    if (realpath(buf, resolved_path) == NULL) {
        GS_THROW_ERROR(ERR_PATH_NOT_EXIST_OR_ACCESSABLE, buf);
        return GS_ERROR;
    }
    path_len = (uint32)strlen(resolved_path);
    if (path_len >= len) {
        GS_THROW_ERROR(ERR_INVALID_FILE_NAME, resolved_path, len);
        return GS_ERROR;
    }
    errcode = strncpy_s(fullpath, (size_t)len, resolved_path, (size_t)path_len);
    if (errcode != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return GS_ERROR;
    }
#endif
    return GS_SUCCESS;
}

static status_t cm_set_ifile_value(config_t *config, config_item_t *ifile, const char *file_name, uint32 file_name_len)
{
    uint32 file_name_size;
    errno_t errcode;

    file_name_size = file_name_len + 1;
    if (cm_alloc_config_buf(config, file_name_size, &ifile->value) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (cm_alloc_config_buf(config, file_name_size, &ifile->pfile_value) != GS_SUCCESS) {
        return GS_ERROR;
    }

    errcode = strncpy_s(ifile->value, (size_t)file_name_size, file_name, (size_t)file_name_len);
    if (errcode != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return GS_ERROR;
    }

    errcode = strncpy_s(ifile->pfile_value, (size_t)file_name_size, file_name, (size_t)file_name_len);
    if (errcode != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return GS_ERROR;
    }
    ifile->is_diff = GS_FALSE;

    return GS_SUCCESS;
}

static inline status_t cm_config_check_ifile_exists(config_t *config, const char *file_name)
{
    config_item_t *next_file = config->first_file;
    while (next_file != NULL) {
        if (cm_str_equal_ins(next_file->value, file_name)) {
            GS_THROW_ERROR(ERR_DUPLICATE_FILE, file_name);
            return GS_ERROR;
        }
        next_file = next_file->next_file;
    }
    return GS_SUCCESS;
}

static status_t cm_set_config_ifile(config_t *config, text_t *value, config_item_t **item)
{
    char file_name[GS_FILE_NAME_BUFFER_SIZE];
    config_item_t *ifile = NULL;
    uint32 buf_len = GS_MAX_CONFIG_FILE_SIZE;
    status_t status;
    char *file_buf = (char*)malloc(GS_MAX_CONFIG_FILE_SIZE);

    if (file_buf == NULL || memset_sp(file_buf, GS_MAX_CONFIG_FILE_SIZE, 0, GS_MAX_CONFIG_FILE_SIZE) != EOK) {
        CM_FREE_PTR(file_buf);
        return GS_ERROR;
    }

    /* get full file path */
    if (cm_get_fullpath(config, value, file_name, sizeof(file_name)) != GS_SUCCESS) {
        CM_FREE_PTR(file_buf);
        return GS_ERROR;
    }
    if (cm_read_config_file(file_name, file_buf, &buf_len, GS_TRUE, GS_TRUE) != GS_SUCCESS) {
        CM_FREE_PTR(file_buf);
        return GS_ERROR;
    }
    if (cm_alloc_config_buf(config, sizeof(config_item_t), (char **)&ifile) != GS_SUCCESS) {
        CM_FREE_PTR(file_buf);
        return GS_ERROR;
    }
    ifile->name = (char *)"IFILE";
    ifile->is_default = GS_FALSE;
    ifile->attr = ATTR_READONLY;
    ifile->flag = FLAG_NONE;
    ifile->next = ifile->next_file = NULL;
    (*item) = ifile;

    if (cm_config_check_ifile_exists(config, file_name) != GS_SUCCESS) {
        CM_FREE_PTR(file_buf);
        return GS_ERROR;
    }

    if (cm_set_ifile_value(config, ifile, file_name, (uint32)strlen(file_name)) != GS_SUCCESS) {
        CM_FREE_PTR(file_buf);
        return GS_ERROR;
    }

    if (config->first_file == NULL) {
        config->first_file = ifile;
        config->last_file = ifile;
    } else {
        config->last_file->next_file = ifile;
        config->last_file = ifile;
    }
    status = cm_parse_config(config, file_buf, buf_len, GS_TRUE, GS_FALSE);

    CM_FREE_PTR(file_buf);
    return status;
}

static inline status_t cm_get_cfg_item_by_name(text_t *name, bool32 is_infile, config_item_t **item)
{
    while (*item != NULL) {
        if (cm_text_str_equal_ins(name, (*item)->name) ||
            ((*item)->alias != NULL && cm_text_str_equal_ins(name, (*item)->alias))) {
            /* check duplicate parameter in main file */
            if (!is_infile && ((*item)->flag & FLAG_ZFILE)) {
                GS_THROW_ERROR(ERR_DUPLICATE_PARAMETER, (*item)->name);
                return GS_ERROR;
            }
            break;
        }
        *item = (*item)->next;
    }
    return GS_SUCCESS;
}

static inline status_t cm_check_invalid_cfg_item(config_item_t *item, text_t *name, text_t *value)
{
    if (value->len >= GS_PARAM_BUFFER_SIZE && !(item->attr & ATTR_READONLY)) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, T2S(name), (int64)GS_PARAM_BUFFER_SIZE - 1);
        return GS_ERROR;
    }
    /* HAVE_SSL or _FACTOR_KEY cannot be loaded from config file */
    if (cm_str_equal(item->name, "HAVE_SSL") || cm_str_equal(item->name, "_FACTOR_KEY")) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER_NAME, T2S(name));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static inline status_t cm_set_cfg_item_value(config_t *config, config_item_t *item, text_t *value)
{
    uint32 buf_size = (value->len >= GS_PARAM_BUFFER_SIZE) ? value->len + 1 : GS_PARAM_BUFFER_SIZE;

    /* reuse previous allocated buffer if possible */
    if (buf_size > GS_PARAM_BUFFER_SIZE || item->is_default) {
        GS_RETURN_IFERR(cm_alloc_config_buf(config, buf_size, &item->value));
        GS_RETURN_IFERR(cm_alloc_config_buf(config, buf_size, &item->pfile_value));
        GS_RETURN_IFERR(cm_alloc_config_buf(config, buf_size, &item->runtime_value));
    }

    GS_RETURN_IFERR(cm_text2str(value, item->value, buf_size));
    GS_RETURN_IFERR(cm_text2str(value, item->pfile_value, buf_size));
    GS_RETURN_IFERR(cm_text2str(value, item->runtime_value, buf_size));
    item->is_diff = GS_FALSE;

    return GS_SUCCESS;
}

static inline status_t cm_set_cfg_item_comment(config_t *config, config_item_t *item, text_t *comment)
{
    if (comment->len > 0) {
        uint32 buf_size = comment->len + 1;

        if (cm_alloc_config_buf(config, buf_size, &item->comment) != GS_SUCCESS) {
            return GS_ERROR;
        }

        GS_RETURN_IFERR(cm_text2str(comment, item->comment, buf_size));
    }

    return GS_SUCCESS;
}

static status_t cm_set_config_item(config_t *config, text_t *name, text_t *value, text_t *comment, bool32 is_infile,
                                   bool32 set_alias)
{
    bool32 ifile_item = GS_FALSE;
    config_item_t *item = NULL;
    config_item_t *temp = NULL;
    CM_POINTER3(config, value, comment);

    /* Use IFILE to embed another parameter file within current parameter file */
    if (cm_text_str_equal_ins(name, "IFILE")) {
        if (is_infile) {
            GS_THROW_ERROR(ERR_UNSUPPORTED_EMBEDDED_PARAMETER, T2S(name));
            return GS_ERROR;
        }
        GS_RETURN_IFERR(cm_set_config_ifile(config, value, &item));
        temp = NULL;
        ifile_item = GS_TRUE;
    } else {
        item = cm_get_config_item(config, name, set_alias);
        temp = config->first_item;
        ifile_item = GS_FALSE;
    }

    if (item == NULL) {
        if (!config->ignore) {
            GS_THROW_ERROR(ERR_INVALID_PARAMETER_NAME, T2S(name));
            return GS_ERROR;
        }
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(cm_get_cfg_item_by_name(name, is_infile, &temp));
    GS_RETURN_IFERR(cm_check_invalid_cfg_item(item, name, value));
    if (!ifile_item) {
        GS_RETURN_IFERR(cm_set_cfg_item_value(config, item, value));
    }
    GS_RETURN_IFERR(cm_set_cfg_item_comment(config, item, comment));

    item->is_default = GS_FALSE;
    if (is_infile) {
        item->flag |= FLAG_INFILE;
        return GS_SUCCESS;
    }
    item->flag = FLAG_ZFILE;

    if (config->first_item == NULL) {
        config->first_item = item;
        config->last_item = item;
    } else if (temp == NULL) {
        config->last_item->next = item;
        config->last_item = item;
    }
    return GS_SUCCESS;
}

status_t cm_read_config_file(const char *file_name, char *buf, uint32 *buf_len, bool32 is_ifile,
                             bool32 read_only)
{
    int32 file_fd;
    status_t status;
    uint32 mode = (read_only || is_ifile) ? (O_RDONLY | O_BINARY) : (O_CREAT | O_RDWR | O_BINARY);

    if (!cm_file_exist(file_name)) {
        GS_THROW_ERROR(ERR_FILE_NOT_EXIST, "config", file_name);
        return GS_ERROR;
    }

    if (cm_open_file(file_name, mode, &file_fd) != GS_SUCCESS) {
        return GS_ERROR;
    }

    int64 size = cm_file_size(file_fd);
    if (size == -1) {
        cm_close_file(file_fd);
        GS_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno);
        return GS_ERROR;
    }

    if (size > (int64)(*buf_len)) {
        cm_close_file(file_fd);
        GS_THROW_ERROR(ERR_FILE_SIZE_TOO_LARGE, file_name);
        return GS_ERROR;
    }

    if (cm_seek_file(file_fd, 0, SEEK_SET) != 0) {
        cm_close_file(file_fd);
        GS_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_SET, errno);
        return GS_ERROR;
    }

    status = cm_read_file(file_fd, buf, (int32)size, (int32 *)buf_len);
    cm_close_file(file_fd);
    return status;
}

static status_t cm_parse_config(config_t *config, char *buf, uint32 buf_len, bool32 is_ifile, bool32 set_alias)
{
    uint32 line_no;
    text_t text, line, comment, name, value;
    CM_POINTER(config);

    text.len = buf_len;
    text.str = buf;

    comment.str = text.str;
    comment.len = 0;
    line_no = 0;

    while (cm_fetch_text(&text, '\n', '\0', &line)) {
        if (line.len == 0) {
            continue;
        }

        line_no++;
        cm_trim_text(&line);
        if (line.len >= GS_MAX_CONFIG_LINE_SIZE) {
            GS_THROW_ERROR(ERR_LINE_SIZE_TOO_LONG, line_no);
            return GS_ERROR;
        }

        if (line.len == 0 || *line.str == '#') { /* commentted line */
            continue;
        }

        comment.len = (uint32)(line.str - comment.str);

        cm_split_text(&line, '=', '\0', &name, &value);
        cm_text_upper(&name);  // Case insensitive
        cm_trim_text(&name);
        if (name.len == 0) {
            GS_THROW_ERROR(ERR_INVALID_PARAMETER_NAME, " ");
            return GS_ERROR;
        }
        cm_trim_text(&value);
        cm_trim_text(&comment);

        if (cm_set_config_item(config, &name, &value, &comment, is_ifile, set_alias) != GS_SUCCESS) {
            return GS_ERROR;
        }

        comment.str = text.str;
        comment.len = 0;
    }

    return GS_SUCCESS;
}

void cm_init_config(config_item_t *items, uint32 item_count, config_t *config)
{
    uint32 i, hash_value;
    config_item_t *item = NULL;

    CM_POINTER2(items, config);
    MEMS_RETVOID_IFERR(memset_sp(config, sizeof(config_t), 0, sizeof(config_t)));

    config->items = items;
    config->item_count = item_count;
    config->value_buf_size = CM_ALIGN4(item_count) * SIZE_K(4);
    for (i = 0; i < item_count; i++) {
        item = &config->items[i];
        item->next = NULL;

        /* initialize hash map by name */
        hash_value = cm_hash_string(item->name, GS_CONFIG_HASH_BUCKETS);
        item->hash_next = config->name_map[hash_value];
        config->name_map[hash_value] = item;
        if (item->alias != NULL) {
            hash_value = cm_hash_string(item->alias, GS_CONFIG_ALIAS_HASH_BUCKETS);
            item->hash_next2 = config->alias_map[hash_value];
            config->alias_map[hash_value] = item;
        }
    }
}

status_t cm_load_config(config_item_t *items, uint32 item_count, const char *file_name, config_t *config,
                        bool32 set_alias)
{
    CM_POINTER3(items, file_name, config);
    size_t name_len = strlen(file_name);
    errno_t errcode;

    cm_init_config(items, item_count, config);
    errcode = strncpy_s(config->file_name, GS_FILE_NAME_BUFFER_SIZE, file_name, (size_t)name_len);
    if (errcode != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return GS_ERROR;
    }

    config->text_size = sizeof(config->file_buf);
    if (cm_read_config_file(file_name, config->file_buf, &config->text_size, GS_FALSE, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return cm_parse_config(config, config->file_buf, config->text_size, GS_FALSE, set_alias);
}

static status_t cm_open_config_stream(config_t *config, config_stream_t *stream)
{
    char backup_name[GS_FILE_NAME_BUFFER_SIZE] = { '\0' };
    CM_POINTER2(stream, config);

    stream->config = config;
    stream->offset = 0;

    PRTS_RETURN_IFERR(snprintf_s(backup_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s_bak",
                                 config->file_name));

    if (cm_copy_file(config->file_name, backup_name, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    // write a tempory file avoid risk operating config file when disk full
    PRTS_RETURN_IFERR(snprintf_s(backup_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s_tmp",
                                 config->file_name));

    if (cm_open_file(backup_name, O_CREAT | O_RDWR | O_BINARY | O_SYNC | O_TRUNC, &config->file) != GS_SUCCESS) {
        return GS_ERROR;
    }
    (void)cm_chmod_file(S_IRUSR | S_IWUSR, config->file);

    return GS_SUCCESS;
}

static status_t cm_write_config_stream(config_stream_t *stream, const char *str)
{
    uint32 len;
    CM_POINTER2(stream, str);

    if (str == NULL) {
        return GS_SUCCESS;
    }

    len = (uint32)strlen(str);
    if (len == 0) {
        return GS_SUCCESS;
    }

    if (stream->offset + len > GS_MAX_CONFIG_FILE_SIZE) {
        if (cm_write_file(stream->config->file, stream->config->file_buf, (int32)stream->offset) != GS_SUCCESS) {
            return GS_ERROR;
        }

        stream->offset = 0;
    }

    MEMS_RETURN_IFERR(memcpy_sp(stream->config->file_buf + stream->offset,
                                (size_t)(GS_MAX_CONFIG_FILE_SIZE - stream->offset), str, (size_t)len));

    stream->offset += len;
    return GS_SUCCESS;
}

static status_t cm_close_config_stream(config_stream_t *stream)
{
    CM_POINTER(stream);

    if (stream->offset > 0) {
        if (cm_write_file(stream->config->file, stream->config->file_buf, (int32)stream->offset) != GS_SUCCESS) {
            return GS_ERROR;
        }

        stream->offset = 0;
    }

    cm_close_file(stream->config->file);

    // a tempory file rename formal config file
    char temp_name[GS_FILE_NAME_BUFFER_SIZE];
    PRTS_RETURN_IFERR(snprintf_s(temp_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s_tmp",
                                 stream->config->file_name));

    if (cm_rename_file(temp_name, stream->config->file_name) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("rename config failed:%s to %s errno:%d,msg=%s", temp_name, stream->config->file_name, errno,
                       strerror(errno));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t cm_save_config(config_t *config)
{
    config_stream_t stream;
    CM_POINTER(config);

    if (cm_open_config_stream(config, &stream) != GS_SUCCESS) {
        return GS_ERROR;
    }

    config_item_t *item = config->first_item;

    while (item != NULL) {
        /* skip item loaded from embeded parameter file */
        if (item->flag & FLAG_INFILE) {
            item = item->next;
            continue;
        }

        /* don't save factor_key/have_ssl in parameter file */
        if (cm_str_equal_ins(item->name, "_FACTOR_KEY") || cm_str_equal_ins(item->name, "HAVE_SSL")) {
            item = item->next;
            continue;
        }

        if (!CM_IS_EMPTY_STR(item->comment)) {
            if (cm_write_config_stream(&stream, item->comment) != GS_SUCCESS) {
                return GS_ERROR;
            }
            if (cm_write_config_stream(&stream, "\n") != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (item->hit_alias) {
            if (cm_write_config_stream(&stream, item->alias) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            if (cm_write_config_stream(&stream, item->name) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (cm_write_config_stream(&stream, " = ") != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (cm_write_config_stream(&stream, item->pfile_value) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (cm_write_config_stream(&stream, "\n") != GS_SUCCESS) {
            return GS_ERROR;
        }

        item = item->next;
    }

    return cm_close_config_stream(&stream);
}

// fixing IFILE problems, move changing item to the bottom of config each time
static void cm_set_config_first_last_item(config_t *config, config_item_t *item)
{
    config_item_t *prev_item = NULL;

    if (config->last_item == NULL) {
        config->first_item = item;
        config->last_item = item;
        return;
    }

    if (config->first_item == item) {
        config->first_item = item->next;
    } else if (item->next != NULL) {
        prev_item = config->first_item;
        while ((prev_item != NULL) && (prev_item->next != item)) {
            prev_item = prev_item->next;
        }
        if (prev_item != NULL) {
            prev_item->next = item->next;
        }
    }
    item->next = NULL;
    config->last_item->next = item;
    config->last_item = item;
}

status_t cm_threads_valid(const config_t *config, const text_t *name, const config_item_t *item,
                          const char *value_new)
{
    config_item_t *other_item = NULL;
    text_t name_text;
    char *other_value = NULL;
    int32 ret, size, other_size;
    bool8 change_max = GS_FALSE;
    GS_RETVALUE_IFTRUE(config == NULL, GS_ERROR);
    GS_RETVALUE_IFTRUE(item == NULL, GS_ERROR);
    GS_RETVALUE_IFTRUE(value_new == NULL, GS_ERROR);
    GS_RETVALUE_IFTRUE(name == NULL, GS_ERROR);

    GS_RETURN_IFERR(cm_str2int(value_new, &size));

    if (cm_text_str_equal_ins(name, "MAX_WORKER_THREADS")) {
        cm_str2text("OPTIMIZED_WORKER_THREADS", &name_text);
        change_max = GS_TRUE;
    } else {
        cm_str2text("MAX_WORKER_THREADS", &name_text);
    }

    other_item = cm_get_config_item(config, &name_text, GS_FALSE);
    GS_RETVALUE_IFTRUE(other_item == NULL, GS_ERROR);

    other_value = (other_item->is_default) ? other_item->default_value : other_item->value;

    GS_RETVALUE_IFTRUE(other_value == NULL, GS_ERROR);
    GS_RETURN_IFERR(cm_str2int(other_value, &other_size));

    ret = size - other_size;

    if (change_max == GS_TRUE && ret > 0) {
        return GS_SUCCESS;
    }

    if (change_max == GS_FALSE && ret < 0) {
        return GS_SUCCESS;
    }

    if (ret == 0) {
        return GS_SUCCESS;
    }

    if (change_max == GS_TRUE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "MAX_WORKER_THREADS", (int64)other_size);
    } else {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "OPTIMIZED_WORKER_THREADS", (int64)other_size);
    }

    return GS_ERROR;
}

status_t cm_connsize_valid(const config_t *config, const text_t *name, const config_item_t *item, const char *value_new)
{
    config_item_t *item_new = NULL;
    text_t name_text;
    char *value = NULL;
    int32 ret;
    int32 size = 0;
    int32 size_old = 0;
    bool8 change_max = GS_FALSE;
    GS_RETVALUE_IFTRUE(config == NULL, GS_ERROR);
    GS_RETVALUE_IFTRUE(item == NULL, GS_ERROR);
    GS_RETVALUE_IFTRUE(value_new == NULL, GS_ERROR);
    GS_RETVALUE_IFTRUE(name == NULL, GS_ERROR);

    GS_RETURN_IFERR(cm_str2int(value_new, &size));
    change_max = cm_text_str_equal_ins(name, "MAX_CONNECTION_POOL_SIZE");
    if (change_max) {
        cm_str2text("MIN_CONNECTION_POOL_SIZE", &name_text);
    } else {
        cm_str2text("MAX_CONNECTION_POOL_SIZE", &name_text);
    }

    if (size <= 0 || size > 4000) {
        if (change_max) {
            GS_THROW_ERROR(ERR_INVALID_PARAMETER, "MAX_CONNECTION_POOL_SIZE");
        } else {
            GS_THROW_ERROR(ERR_INVALID_PARAMETER, "MIN_CONNECTION_POOL_SIZE");
        }
        return GS_ERROR;
    }

    item_new = cm_get_config_item(config, &name_text, GS_FALSE);
    GS_RETVALUE_IFTRUE(item_new == NULL, GS_ERROR);
    value = (item_new->is_default) ? item_new->default_value : item_new->value;
    GS_RETVALUE_IFTRUE(value == NULL, GS_ERROR);
    GS_RETURN_IFERR(cm_str2int(value, &size_old));
    ret = size - size_old;
    if ((change_max == GS_TRUE && ret > 0) || (change_max == GS_FALSE && ret < 0) || ret == 0) {
        return GS_SUCCESS;
    }

    if (change_max == GS_TRUE) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "MAX_CONNECTION_POOL_SIZE");
    } else {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "MIN_CONNECTION_POOL_SIZE");
    }
    return GS_ERROR;
}

static bool32 cm_check_config_same(config_item_t *item, const char *value)
{
    if (item->is_diff) {
        return GS_FALSE;
    }

    char *old_value = item->is_default ? item->default_value : item->value;
    /* config value is not changed */
    return cm_str_equal(old_value, value);
}

static status_t cm_alter_config_item(config_t *config, config_item_t *item, const char *value, config_scope_t scope)
{
    size_t value_len;
    errno_t errcode;

    if (item->is_default) {
        if (cm_alloc_config_buf(config, GS_PARAM_BUFFER_SIZE, &item->value) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (cm_alloc_config_buf(config, GS_PARAM_BUFFER_SIZE, &item->pfile_value) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    item->is_default = GS_FALSE;

    value_len = (uint32)strlen(value);
    if (scope != CONFIG_SCOPE_DISK) {
        errcode = strncpy_s(item->value, GS_PARAM_BUFFER_SIZE, value, (size_t)value_len);
        if (errcode != EOK) {
            GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return GS_ERROR;
        }
    }
    item->flag &= ~FLAG_INFILE;
    if (scope != CONFIG_SCOPE_MEMORY) {
        errcode = strncpy_s(item->pfile_value, GS_PARAM_BUFFER_SIZE, value, (size_t)value_len);
        if (errcode != EOK) {
            GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return GS_ERROR;
        }
        if (item != config->last_item) {
            cm_set_config_first_last_item(config, item);
        }
        if (cm_save_config(config) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    item->is_diff = (scope != CONFIG_SCOPE_BOTH) ? GS_TRUE : GS_FALSE;
    return GS_SUCCESS;
}

status_t cm_alter_config(config_t *config, const char *name, const char *value, config_scope_t scope, bool32 force)
{
    text_t name_text;
    config_item_t *item = NULL;
    status_t status;

    CM_POINTER3(config, name, value);
    cm_str2text((char *)name, &name_text);
    item = cm_get_config_item(config, &name_text, GS_FALSE);
    if (item == NULL) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER_NAME, name);
        return GS_ERROR;
    }
    if ((item->attr & ATTR_READONLY) && !force) {
        GS_THROW_ERROR(ERR_ALTER_READONLY_PARAMETER, name);
        return GS_ERROR;
    }

    GS_RETSUC_IFTRUE(cm_check_config_same(item, value));

    if (cm_text_str_equal_ins(&name_text, "MAX_CONNECTION_POOL_SIZE") ||
        cm_text_str_equal_ins(&name_text, "MIN_CONNECTION_POOL_SIZE")) {
        GS_RETURN_IFERR(cm_connsize_valid(config, &name_text, item, value));
    }
    if (cm_text_str_equal_ins(&name_text, "OPTIMIZED_WORKER_THREADS") ||
        cm_text_str_equal_ins(&name_text, "MAX_WORKER_THREADS")) {
        GS_RETURN_IFERR(cm_threads_valid(config, &name_text, item, value));
    }

    cm_spin_lock(&g_config_lock, NULL);

    if (cm_access_file(config->file_name, F_OK | R_OK | W_OK) != GS_SUCCESS) {
        cm_spin_unlock(&g_config_lock);
        GS_THROW_ERROR(ERR_OPEN_FILE, config->file_name, errno);
        return GS_ERROR;
    }

    status = cm_alter_config_item(config, item, value, scope);
    cm_spin_unlock(&g_config_lock);
    return status;
}

status_t cm_read_config(const char *file_name, config_t *config)
{
    CM_POINTER2(file_name, config);
    size_t name_len = strlen(file_name);

    errno_t errcode = strncpy_s(config->file_name, GS_FILE_NAME_BUFFER_SIZE, file_name, (size_t)name_len);
    if (errcode != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return GS_ERROR;
    }

    config->text_size = sizeof(config->file_buf);
    if (cm_read_config_file(file_name, config->file_buf, &config->text_size, GS_FALSE, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return cm_parse_config(config, config->file_buf, config->text_size, GS_FALSE, GS_FALSE);
}

status_t cm_modify_runtimevalue(config_t *config, const char *name, const char *value)
{
    size_t value_len;
    text_t name_text;
    config_item_t *item = NULL;
    errno_t errcode;

    CM_POINTER3(config, name, value);

    cm_str2text((char *)name, &name_text);
    item = cm_get_config_item(config, &name_text, GS_FALSE);
    if (item == NULL) {
        return GS_ERROR;
    }

    value_len = (uint32)strlen(value);
    
    cm_spin_lock(&g_config_lock, NULL);

    if (item->runtime_value == NULL || item->default_value == item->runtime_value) {
        if (cm_alloc_config_buf(config, GS_PARAM_BUFFER_SIZE, &item->runtime_value) != GS_SUCCESS) {
            cm_spin_unlock(&g_config_lock);
            return GS_ERROR;
        }
    }
    
    errcode = strncpy_s(item->runtime_value, GS_PARAM_BUFFER_SIZE, value, (size_t)value_len);
    if (errcode != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        cm_spin_unlock(&g_config_lock);
        return GS_ERROR;
    }
    
    cm_spin_unlock(&g_config_lock);
    return GS_SUCCESS;
}

void cm_free_config_buf(config_t *config)
{
    if (config->value_buf != NULL) {
        free(config->value_buf);
        config->value_buf = NULL;
    }
}

char *cm_fgets_nonblock(char *buf, uint32 buf_len, FILE *stream)
{
    char *ch = NULL;

#ifndef WIN32
    struct termios oldt, newt;
    int oldf;

    (void)tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag |= (ICANON | ECHO);
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
    (void)fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);
    ch = fgets(buf, (int)buf_len, stream);
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    (void)fcntl(STDIN_FILENO, F_SETFL, oldf);

    return ch;
#else
    if (_kbhit()) {
        ch = fgets(buf, buf_len, stream);
    }

    return ch;
#endif
}

#ifdef __cplusplus
}
#endif
