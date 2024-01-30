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
 * ctsql_exp_bin.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctsql/ctsql_exp_bin.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_exp_bin.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline void init_cur_buffer(exp_mem_block_t *block, char *buf, uint32 size)
{
    block->block_size = (uint32 *)buf;
    block->offset = (uint32 *)(buf + sizeof(uint32));
    block->buffer = buf;
    *(block->block_size) = size;
    *(block->offset) = CTSQL_EXP_BIN_MEM_BLOCK_RESERVED_SIZE;
}

static status_t extent_exp_bin_memory_block(exp_bin_memory_mgr_t *mem_mgr)
{
    char *buf = NULL;

    CT_RETURN_IFERR(cm_list_new(&mem_mgr->mems, (void **)&buf));

    init_cur_buffer(&mem_mgr->cur_buf, buf, CTSQL_EXP_BIN_MEM_BLOCK_SIZE);

    return CT_SUCCESS;
}

status_t init_exp_bin_memory_mgr(exp_bin_memory_mgr_t *mem_mgr)
{
    mem_mgr->len_addr = NULL;
    mem_mgr->tmp_write_len = 0;
    mem_mgr->sub_len_addr = NULL;
    mem_mgr->sub_tmp_write_len = 0;
    cm_create_list2(&mem_mgr->mems, 1, MAX_LIST_EXTENTS, CTSQL_EXP_BIN_MEM_BLOCK_SIZE);
    return extent_exp_bin_memory_block(mem_mgr);
}

status_t exp_bin_memory_mgr_begin(exp_bin_memory_mgr_t *mgr, exp_filetype_t filetype)
{
    char *buf = NULL;

    if (filetype == FT_TXT) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(get_mem_address(mgr, &buf, sizeof(uint32)));
    mgr->len_addr = (uint32 *)buf;
    *(mgr->len_addr) = 0;
    mgr->tmp_write_len = 0;
    return CT_SUCCESS;
}

void exp_bin_memory_mgr_end(exp_bin_memory_mgr_t *mgr, exp_filetype_t filetype)
{
    if (filetype == FT_TXT) {
        return;
    }

    *(mgr->len_addr) = mgr->tmp_write_len;
    mgr->len_addr = NULL;
    mgr->tmp_write_len = 0;
}

status_t exp_bin_memory_mgr_sub_begin(exp_bin_memory_mgr_t *mgr, exp_filetype_t filetype)
{
    char *buf = NULL;

    if (filetype == FT_TXT) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(get_mem_address(mgr, &buf, sizeof(uint32)));
    mgr->sub_len_addr = (uint32 *)buf;
    *(mgr->sub_len_addr) = 0;
    mgr->sub_tmp_write_len = 0;
    return CT_SUCCESS;
}
void exp_bin_memory_mgr_sub_end(exp_bin_memory_mgr_t *mgr, exp_filetype_t filetype)
{
    if (filetype == FT_TXT) {
        return;
    }

    *(mgr->sub_len_addr) = mgr->sub_tmp_write_len;
    mgr->sub_len_addr = NULL;
    mgr->sub_tmp_write_len = 0;
}

status_t get_mem_address(exp_bin_memory_mgr_t *mgr, char **buf, uint32 required_size)
{
    *buf = NULL;
    if (required_size > CTSQL_EXP_BIN_MEM_BLOCK_SIZE - 8) {
        return CT_ERROR;
    }

    if (required_size > CTSQL_EXP_BIN_MEM_BLOCK_SIZE - *(mgr->cur_buf.offset)) {
        CT_RETURN_IFERR(extent_exp_bin_memory_block(mgr));
    }

    *buf = mgr->cur_buf.buffer + *(mgr->cur_buf.offset);
    *(mgr->cur_buf.offset) = *(mgr->cur_buf.offset) + required_size;

    if (mgr->len_addr != NULL) {
        mgr->tmp_write_len += required_size;
    }

    if ((mgr->sub_len_addr != NULL)) {
        mgr->sub_tmp_write_len += required_size;
    }

    return CT_SUCCESS;
}

status_t get_short_bin_bufer_addr(exp_bin_memory_mgr_t *mgr, short_bin_buffer_t *bin_buf, uint16 required_size)
{
    char *buf = NULL;
    int ret;

    bin_buf->size = NULL;
    bin_buf->buffer = NULL;
    ret = get_mem_address(mgr, &buf, (uint32)(required_size + sizeof(uint16)));
    if (ret == CT_SUCCESS) {
        bin_buf->size = (uint16 *)buf;
        bin_buf->buffer = buf + sizeof(uint16);

        *(bin_buf->size) = required_size;
    }

    return ret;
}

status_t get_bin_bufer_addr(exp_bin_memory_mgr_t *mgr, bin_buffer_t *bin_buf, uint32 required_size)
{
    char *buf = NULL;
    int ret;

    bin_buf->size = NULL;
    bin_buf->buffer = NULL;
    ret = get_mem_address(mgr, &buf, required_size + sizeof(uint32));
    if (ret == CT_SUCCESS) {
        bin_buf->size = (uint32 *)buf;
        bin_buf->buffer = buf + sizeof(uint32);

        *(bin_buf->size) = required_size;
    }

    return ret;
}

static inline int mem_writer_encrypt_s(char *buf, uint32 size, FILE *filehand, EVP_CIPHER_CTX *gcm_ctx)
{
    char *encrypt_buf = NULL;

    encrypt_buf = (char *)malloc(SIZE_M(16));
    if (encrypt_buf == NULL) {
        return CT_ERROR;
    }

    if (cm_encrypt_data_by_gcm(gcm_ctx, encrypt_buf, buf, size) != CT_SUCCESS) {
        CM_FREE_PTR(encrypt_buf);
        return CT_ERROR;
    }

    if (fwrite(encrypt_buf, 1, size, filehand) == 0) {
        CT_THROW_ERROR(ERR_CLT_WRITE_FILE_ERR, errno);
        CM_FREE_PTR(encrypt_buf);
        return CT_ERROR;
    }

    CM_FREE_PTR(encrypt_buf);
    return CT_SUCCESS;
}

status_t mem_block_write_file(exp_bin_memory_mgr_t *mgr, FILE *hand, crypt_file_t *crypt_file, bool32 encrypt_flag)
{
    uint32 pos;
    char *buf = NULL;

    if (hand == NULL) {
        return CT_ERROR;
    }

    for (pos = 0; pos < mgr->mems.count; ++pos) {
        buf = (char *)cm_list_get(&mgr->mems, pos);
        if (buf != NULL) {
            if (encrypt_flag && crypt_file != NULL) {
                (void)mem_writer_encrypt_s(buf + CTSQL_EXP_BIN_MEM_BLOCK_RESERVED_SIZE,
                    (*(uint32 *)(buf + sizeof(uint32)) - CTSQL_EXP_BIN_MEM_BLOCK_RESERVED_SIZE), hand,
                    crypt_file->crypt_ctx.gcm_ctx);
            } else {
                (void)fwrite((buf + CTSQL_EXP_BIN_MEM_BLOCK_RESERVED_SIZE), 1,
                    (*(uint32 *)(buf + sizeof(uint32)) - CTSQL_EXP_BIN_MEM_BLOCK_RESERVED_SIZE), hand);
            }
        }
    }

    return CT_SUCCESS;
}

void init_bin_file_fixed_head(exp_bin_memory_mgr_t *mgr, bin_file_fixed_head_t **head)
{
    char *buf = NULL;
    int ret;
    ret = get_mem_address(mgr, &buf, sizeof(bin_file_fixed_head_t));
    if (ret != CT_SUCCESS) {
        return;
    }

    *head = (bin_file_fixed_head_t *)buf;
    ret = memset_s(*head, sizeof(bin_file_fixed_head_t), 0, sizeof(bin_file_fixed_head_t));
    if (ret != CT_SUCCESS) {
        return;
    }

    (*head)->split_flag = 1;  // Separation of metadata and data files
}

#ifdef __cplusplus
}
#endif
