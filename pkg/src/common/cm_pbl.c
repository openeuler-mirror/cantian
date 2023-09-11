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
 * cm_pbl.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_pbl.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_pbl.h"
#include "cm_file.h"
#include "cm_hba.h"
#include "cm_util.h"
#include "cm_regexp.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline bool32 cm_copy_pbl_pwd(char *log_pwd, pbl_entry_t *pbl_entry)
{
    errno_t errcode = memcpy_sp(log_pwd, (size_t)GS_PWD_BUFFER_SIZE, pbl_entry->pwd, (size_t)GS_PWD_BUFFER_SIZE);
    if (SECUREC_UNLIKELY(errcode != EOK)) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return GS_FALSE;
    }
    return GS_TRUE;
}

bool32 cm_check_pwd_black_list(black_context_t *ctx, const char *name, char *passwd, char *log_pwd)
{
    list_t *pbl = &ctx->user_pwd_black_list;
    bool32 pbl_configed = pbl->count > 0;
    int32 pos = 0;
    text_t pwd_text = { .str = passwd, .len = (uint32)strlen(passwd)};
    if (!pbl_configed) {
        return GS_FALSE;
    }
    cm_spin_lock(&ctx->lock, NULL);
    for (uint32 i = 0; i < pbl->count; i++) {
        pbl_entry_t *pbl_entry = (pbl_entry_t *)cm_list_get(pbl, i);
        if ((cm_compare_str_ins(name, pbl_entry->user) == 0) || (cm_compare_str_ins("*", pbl_entry->user) == 0)) {
            cm_text_reg_match(&pwd_text, pbl_entry->pwd, &pos, CHARSET_UTF8);
            if (pos != 0) {
                bool32 result = cm_copy_pbl_pwd(log_pwd, pbl_entry);
                cm_spin_unlock(&ctx->lock);
                return result;
            }
        }
    }
    cm_spin_unlock(&ctx->lock);
    return GS_FALSE;
}

static status_t cm_parse_pbl_line(text_t *line, uint32 line_no, pbl_entry_t *pbl_entry)
{
    text_t user, pwd_mode;

    cm_trim_text(line);
    cm_split_text(line, ' ', '\0', &user, &pwd_mode);
    cm_trim_text(&pwd_mode);
    if (pwd_mode.len > GS_PBL_PASSWD_MAX_LEN || user.len > GS_MAX_NAME_LEN) {
        GS_THROW_ERROR(ERR_LINE_SIZE_TOO_LONG, line_no);
        return GS_ERROR;
    }
    /* format user. */
    if (GS_SUCCESS != get_format_user(&user)) {
        GS_THROW_ERROR(ERR_INVALID_HBA_ITEM, "Pbl", line_no);
        return GS_ERROR;
    }
    if (CM_IS_EMPTY(&pwd_mode)) {
        GS_THROW_ERROR(ERR_INVALID_HBA_ITEM, "Pbl", line_no);
        return GS_ERROR;
    }
    MEMS_RETURN_IFERR(memcpy_sp(pbl_entry->user, (size_t)GS_MAX_NAME_LEN, user.str, (size_t)user.len));
    MEMS_RETURN_IFERR(memcpy_sp(pbl_entry->pwd, (size_t)GS_PWD_BUFFER_SIZE, pwd_mode.str, (size_t)pwd_mode.len));
    return GS_SUCCESS;
}

static status_t cm_check_pwd_mode(pbl_entry_t *pbl_entry)
{
    void *code = NULL;
    text_t match_param = { .str = "i", .len = 1 };  // ignore case
    if (cm_regexp_compile(&code, pbl_entry->pwd, &match_param, CHARSET_UTF8) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("The password regexp is invalid: %s ", pbl_entry->pwd);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t cm_parse_pbl(black_context_t *ctx, char *buf, uint32 buf_len)
{
    uint32 line_no = 0;
    text_t lines, line;
    list_t new_pbl;  // pwd black list
    pbl_entry_t *pbl_entry = NULL;
    CM_POINTER(buf);
    lines.len = buf_len;
    lines.str = buf;

    cm_create_list(&new_pbl, sizeof(pbl_entry_t));
    while (cm_fetch_text(&lines, '\n', '\0', &line)) {
        line_no++;
        // ignore comment or empty line
        cm_trim_text(&line);
        if (line.len == 0 || line.str[0] == '#') {
            continue;
        }
        if (cm_list_new(&new_pbl, (pointer_t *)&pbl_entry) != GS_SUCCESS ||
            cm_parse_pbl_line(&line, line_no, pbl_entry) != GS_SUCCESS) {
            cm_destroy_list(&new_pbl);
            return GS_ERROR;
        }
        if (cm_check_pwd_mode(pbl_entry) != GS_SUCCESS) {
            cm_destroy_list(&new_pbl);
            return GS_ERROR;
        }
    }

    cm_spin_lock(&ctx->lock, NULL);
    cm_destroy_list(&ctx->user_pwd_black_list);
    ctx->user_pwd_black_list = new_pbl;
    cm_spin_unlock(&ctx->lock);

    return GS_SUCCESS;
}


static status_t cm_read_pbl_file(const char *file_name, char *buf, uint32 *buf_len)
{
    int32 file_fd;
    status_t status;
    uint32 mode = O_RDONLY | O_BINARY;

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

status_t cm_load_pbl(black_context_t *ctx, const char *file_name, uint32 buf_len)
{
    if (buf_len == 0) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)buf_len, "pbl memory");
        return GS_ERROR;
    }
    char *file_buf = (char *)malloc(buf_len);
    if (file_buf == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)(buf_len), "pbl");
        return GS_ERROR;
    }

    errno_t ret = memset_sp(file_buf, buf_len, 0, buf_len);
    if (ret != EOK) {
        CM_FREE_PTR(file_buf);
        GS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return GS_ERROR;
    }

    if (cm_read_pbl_file(file_name, file_buf, &buf_len) != GS_SUCCESS) {
        CM_FREE_PTR(file_buf);
        return GS_ERROR;
    }
    if (cm_parse_pbl(ctx, file_buf, buf_len) != GS_SUCCESS) {
        CM_FREE_PTR(file_buf);
        return GS_ERROR;
    }

    CM_FREE_PTR(file_buf);
    return GS_SUCCESS;
}
#ifdef __cplusplus
}

#endif

