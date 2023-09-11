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
 * gsql_common.c
 *
 *
 * IDENTIFICATION
 * src/utils/gsql/gsql_common.c
 *
 * -------------------------------------------------------------------------
 */
#include "gsql_common.h"
#include "cm_file.h"
#include "cm_util.h"
#include "cm_regexp.h"

status_t gsc_common_z_init_read(FILE *fp, gsc_z_stream *zstream)
{
    int zret;

    zstream->fp = fp;  // cached 'fp'.

    GSC_COMMON_ZSTREAM(zstream).zalloc = Z_NULL;
    GSC_COMMON_ZSTREAM(zstream).zfree = Z_NULL;
    GSC_COMMON_ZSTREAM(zstream).opaque = Z_NULL;
    GSC_COMMON_ZSTREAM(zstream).avail_in = 0;
    GSC_COMMON_ZSTREAM(zstream).next_in = Z_NULL;

    zret = inflateInit(&GSC_COMMON_ZSTREAM(zstream));
    if (zret != Z_OK) {
        return GS_ERROR;
    }
    zstream->seek_rpos = 0;
    return GS_SUCCESS;
}

status_t gsc_common_z_read_compress(gsc_z_stream *zstream, crypt_info_t *crypt_info, char *swap_buffer,
                                    uint32 swap_len, bool8 *eof)
{
    crypt_file_t *decrypt_ctx = NULL;
    char *decrypt_buf = NULL;
    errno_t errcode;

    if (crypt_info->crypt_flag) {
        GS_RETURN_IFERR(gsql_get_encrypt_file(crypt_info, &decrypt_ctx, cm_fileno(zstream->fp)));
        decrypt_buf = (char *)malloc(SIZE_M(10));
        if (decrypt_buf == NULL) {
            return GSC_ERROR;
        }

        errcode = memset_s(decrypt_buf, SIZE_M(10), 0, SIZE_M(10));
        if (errcode != EOK) {
            CM_FREE_PTR(decrypt_buf);
            GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return GS_ERROR;
        }

        GSC_COMMON_ZSTREAM(zstream).avail_in = (uInt)fread(decrypt_buf, 1, (size_t)swap_len, zstream->fp);
        if (ferror(zstream->fp)) {
            CM_FREE_PTR(decrypt_buf);
            return GS_ERROR;
        }
        if (cm_decrypt_data_by_gcm(decrypt_ctx->crypt_ctx.gcm_ctx, swap_buffer, decrypt_buf,
                                   GSC_COMMON_ZSTREAM(zstream).avail_in) != GS_SUCCESS) {
            CM_FREE_PTR(decrypt_buf);
            return GSC_ERROR;
        }

        CM_FREE_PTR(decrypt_buf);
    } else {
        GSC_COMMON_ZSTREAM(zstream).avail_in = (uInt)fread(swap_buffer, 1, (size_t)swap_len, zstream->fp);
        if (ferror(zstream->fp)) {
            return GS_ERROR;
        }
    }

    GSC_COMMON_ZSTREAM(zstream).next_in = (unsigned char *)swap_buffer;
    *eof = (GSC_COMMON_ZSTREAM(zstream).avail_in == 0) ? GS_TRUE : GS_FALSE;
    return GS_SUCCESS;
}

status_t gsc_common_z_read_data(gsc_z_stream *zstream, char *data_buffer, uint32 len, uint32 *readed_len,
                                bool8 *eof)
{
    int zret;

    if (GSC_COMMON_ZSTREAM(zstream).avail_in == Z_NULL) {
        *eof = GS_TRUE;
        *readed_len = 0;
        return GS_SUCCESS;
    }

    GSC_COMMON_ZSTREAM(zstream).avail_out = len;
    GSC_COMMON_ZSTREAM(zstream).next_out = (unsigned char *)data_buffer;

    zret = inflate(&GSC_COMMON_ZSTREAM(zstream), Z_NO_FLUSH);
    if (zret != Z_OK && zret != Z_STREAM_END) {
        return GS_ERROR;
    }

    *readed_len = len - GSC_COMMON_ZSTREAM(zstream).avail_out;
    zstream->seek_rpos += *readed_len;
    *eof = (zret == Z_STREAM_END) ? GS_TRUE : GS_FALSE;
    return GS_SUCCESS;
}

status_t gsc_common_z_read_direct(gsc_z_stream *zstream, crypt_info_t *crypt_info,
    char *swap_buffer, uint32 swap_len,
    char *data_buffer, uint32 len, uint32 *readed_len, bool8 *eof)
{
    uint32 readed_once = 0;

    if (gsc_common_z_read_data(zstream, (char *)data_buffer, len, readed_len, eof) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (*readed_len == len) {
        return GS_SUCCESS;
    }

    if (gsc_common_z_read_compress(zstream, crypt_info, swap_buffer, swap_len, eof) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (*eof) {
        return GS_SUCCESS;
    } else {
        GS_RETURN_IFERR(gsc_common_z_read_direct(zstream, crypt_info, swap_buffer, swap_len,
            data_buffer + *readed_len, len - *readed_len, &readed_once, eof));
        *readed_len += readed_once;
        return GS_SUCCESS;
    }
}

status_t gsc_common_z_read_seek(gsc_z_stream *zstream, crypt_info_t *crypt_info,
                                int64 pos, char *swap_buffer, uint32 swap_len)
{
    uint32 to_read_len = 0;
    int64 remain_len = 0;
    char temp_buffer[SIZE_K(4)];
    int32 ret_seek;
    bool8 eof;

    if (zstream->seek_rpos == pos) {
        return GS_SUCCESS;
    } else if (zstream->seek_rpos < pos) {
        remain_len = pos - zstream->seek_rpos;
    } else {
        remain_len = pos;
        ret_seek = fseek(zstream->fp, 0, SEEK_SET);
        if (ret_seek != 0) {
            return GS_ERROR;
        }
    }

    while (remain_len > 0) {
        to_read_len = MIN((uint32)remain_len, sizeof(temp_buffer));
        GS_RETURN_IFERR(gsc_common_z_read_direct(zstream, crypt_info, swap_buffer, swap_len, temp_buffer,
            to_read_len, &to_read_len, &eof));
        if (to_read_len == 0) {
            return GS_ERROR;
        }
        remain_len -= to_read_len;
    }
    return GS_SUCCESS;
}

status_t gsc_common_z_uninit_read(gsc_z_stream *zstream)
{
    return inflateEnd(&GSC_COMMON_ZSTREAM(zstream));
}

status_t gsc_common_z_init_write(FILE *fp, gsc_z_stream *zstream, uint32 level)
{
    int zret;

    zstream->fp = fp;  // cached 'fp'.

    GSC_COMMON_ZSTREAM(zstream).zalloc = Z_NULL;
    GSC_COMMON_ZSTREAM(zstream).zfree = Z_NULL;
    GSC_COMMON_ZSTREAM(zstream).opaque = Z_NULL;

    zret = deflateInit(&GSC_COMMON_ZSTREAM(zstream), level);
    if (zret != Z_OK) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t gsql_reset_crypfile(FILE *fp, crypt_info_t *crypt_info)
{
    crypt_file_t *decrypt_ctx = NULL;
    uint32 i = 0;

    if (crypt_info->crypt_flag) {
        for (i = 0; i < crypt_info->crypt_list.count; i++) {
            decrypt_ctx = (crypt_file_t *)cm_list_get(&crypt_info->crypt_list, i);
            if (cm_fileno(fp) == decrypt_ctx->fp) {
                decrypt_ctx->fp = -1;
                break;
            }
        }

        if (i >= crypt_info->crypt_list.count) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t gsql_get_encrypt_file(crypt_info_t *crypt_info, crypt_file_t **encrypt_file, int fp)
{
    for (uint32 i = 0; i < crypt_info->crypt_list.count; i++) {
        *encrypt_file = (crypt_file_t *)cm_list_get(&crypt_info->crypt_list, i);
        if (fp == (*encrypt_file)->fp) {
            return GS_SUCCESS;
        }
    }
    return GS_ERROR;
}

status_t gsql_set_encrpyt_fp(crypt_info_t *crypt_info, const char* filename, int32 fp)
{
    char name[GS_FILE_NAME_BUFFER_SIZE + 1];
    cm_trim_dir(filename, (uint32)sizeof(name), name);
    crypt_file_t *encrypt_file = NULL;
    for (uint32 i = 0; i < crypt_info->crypt_list.count; i++) {
        encrypt_file = (crypt_file_t *)cm_list_get(&crypt_info->crypt_list, i);
        if (cm_str_equal((const char *)name, encrypt_file->filename)) {
            encrypt_file->fp = fp;
            return GS_SUCCESS;
        }
    }
    return GS_ERROR;
}

status_t gsc_common_z_write_core(gsc_z_stream *zstream, crypt_info_t *crypt_info, char *swap_buffer, uint32 *to_write_len, crypt_file_t *encrypt_file)
{
    char *encrypt_buf = NULL;
    errno_t errcode;

    if (*to_write_len > 0) {
        if (crypt_info->crypt_flag) {
            encrypt_buf = (char *)malloc(SIZE_M(16));
            if (encrypt_buf == NULL) {
                return GSC_ERROR;
            }

            errcode = memset_s(encrypt_buf, SIZE_M(16), 0, SIZE_M(16));
            if (errcode != EOK) {
                CM_FREE_PTR(encrypt_buf);
                GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                return GS_ERROR;
            }

            if (cm_encrypt_data_by_gcm(encrypt_file->crypt_ctx.gcm_ctx, encrypt_buf, swap_buffer,
                *to_write_len) != GS_SUCCESS) {
                CM_FREE_PTR(encrypt_buf);
                return GS_ERROR;
            }

            if (fwrite(encrypt_buf, 1, *to_write_len, zstream->fp) != *to_write_len) {
                CM_FREE_PTR(encrypt_buf);
                return GS_ERROR;
            }

            CM_FREE_PTR(encrypt_buf);
        } else {
            if (fwrite(swap_buffer, 1, *to_write_len, zstream->fp) != *to_write_len) {
                return GS_ERROR;
            }
        }
    }
    return GS_SUCCESS;
}

status_t gsc_common_z_write(gsc_z_stream *zstream, crypt_info_t *crypt_info, char *swap_buffer, uint32 swap_len,
                            char *buffer, uint32 len, bool8 eof)
{
    int zret;
    uint32 to_write_len = 0;
    crypt_file_t *encrypt_file = NULL;

    if (crypt_info->crypt_flag) {
        GS_RETURN_IFERR(gsql_get_encrypt_file(crypt_info, &encrypt_file, cm_fileno(zstream->fp)));
    }

    GSC_COMMON_ZSTREAM(zstream).avail_in = len;
    GSC_COMMON_ZSTREAM(zstream).next_in = (unsigned char *)buffer;

    zstream->flush = eof ? Z_FINISH : Z_NO_FLUSH;

    do {
        GSC_COMMON_ZSTREAM(zstream).avail_out = swap_len;
        GSC_COMMON_ZSTREAM(zstream).next_out = (unsigned char *)swap_buffer;

        zret = deflate(&GSC_COMMON_ZSTREAM(zstream), zstream->flush);
        if (zret == Z_STREAM_ERROR) {
            return GS_ERROR;
        }
        to_write_len = swap_len - GSC_COMMON_ZSTREAM(zstream).avail_out;

        GS_RETURN_IFERR(gsc_common_z_write_core(zstream, crypt_info, swap_buffer, &to_write_len, encrypt_file));
    } while (to_write_len > 0);

    if (zret != Z_STREAM_END && zstream->flush == Z_FINISH) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t gsc_common_z_uninit_write(gsc_z_stream *zstream)
{
    return deflateEnd(&GSC_COMMON_ZSTREAM(zstream));
}

status_t gsc_common_init_fixed_memory_pool(fixed_memory_pool_t *pool, uint32 block_size, uint32 block_count)
{
    return gsc_common_init_fixed_memory_pool_ex(pool, block_size, block_count, 0);
}

status_t gsc_common_init_fixed_extend_mpool(fixed_memory_pool_t *pool, uint32 max_ext_cnt)
{
    int32 err_code;
    uint64 size;

    pool->extended_cnt = 0;
    pool->max_ext_cnt = max_ext_cnt;

    if (pool->max_ext_cnt > 0) {
        size = sizeof(char*) * pool->max_ext_cnt;
        pool->ext_buffer_list = (char**)malloc((size_t)size);
        if (pool->ext_buffer_list == NULL) {
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, size, "alloc memory for extended fixed memory pool.");
            return GS_ERROR;
        }
            
        err_code = memset_s(pool->ext_buffer_list, (size_t)size, 0, (size_t)size);
        if (err_code != EOK) {
            CM_FREE_PTR(pool->ext_buffer_list);
            GS_THROW_ERROR(ERR_SYSTEM_CALL, err_code);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

void gsc_common_fixed_extend_mpool_add(fixed_memory_pool_t *pool, char* buffer)
{
    for (uint32 i = 0; i < pool->max_ext_cnt; i++) {
        if (pool->ext_buffer_list[i] == NULL) {
            pool->ext_buffer_list[i] = buffer;
            return;
        }
    }
    // try alloc memory larger than max_ext_cnt
    CM_NEVER;
}

void gsc_common_fixed_extend_mpool_remove(fixed_memory_pool_t *pool, const char* buffer)
{
    for (uint32 i = 0; i < pool->max_ext_cnt; i++) {
        if (pool->ext_buffer_list[i] == buffer) {
            pool->ext_buffer_list[i] = NULL;
            return;
        }
    }
    // try free memory not from pool
    CM_NEVER;
}

void gsc_common_fixed_extend_mpool_free(fixed_memory_pool_t *pool)
{
    for (uint32 i = 0; i < pool->max_ext_cnt; i++) {
        CM_FREE_PTR(pool->ext_buffer_list[i]);
    }
    CM_FREE_PTR(pool->ext_buffer_list);
}

status_t gsc_common_init_fixed_memory_pool_ex(fixed_memory_pool_t *pool, uint32 block_size,
    uint32 block_count, uint32 max_ext_cnt)
{
    char *buffer = NULL;
    pool->block_size = block_size;
    pool->total_cnt = block_count;
    uint64 alloc_size = sizeof(char *) * pool->total_cnt + pool->total_cnt * block_size;

    buffer = (char *)malloc((size_t)alloc_size);
    if (buffer == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, alloc_size, "alloc memory for fixed memory pool.");
        return GS_ERROR;
    }

    pool->buffer_list = (char **)buffer;
    pool->idle_cnt = pool->total_cnt;
    pool->lock = 0;

    for (uint32 i = 0; i < pool->total_cnt; i++) {
        pool->buffer_list[i] = buffer + sizeof(char *) * pool->total_cnt + pool->block_size * i;
    }

    if (gsc_common_init_fixed_extend_mpool(pool, max_ext_cnt) != GS_SUCCESS) {
        CM_FREE_PTR(buffer);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void gsc_common_uninit_fixed_memory_pool(fixed_memory_pool_t *pool)
{
    CM_FREE_PTR(pool->buffer_list);
    gsc_common_fixed_extend_mpool_free(pool);
}

char *gsc_common_alloc_fixed_buffer(fixed_memory_pool_t *pool)
{
    char *buffer = NULL;
    cm_spin_lock(&(pool->lock), NULL);
    if (pool->idle_cnt > 0) {
        buffer = pool->buffer_list[pool->idle_cnt - 1];
        pool->idle_cnt--;
    } else if (pool->extended_cnt < pool->max_ext_cnt) {
        buffer = (char*)malloc(pool->block_size);
        if (buffer != NULL) {
            pool->extended_cnt++;
            gsc_common_fixed_extend_mpool_add(pool, buffer);
        }
    }
    cm_spin_unlock(&(pool->lock));
    return buffer;
}

void gsc_common_free_fixed_buffer(fixed_memory_pool_t *pool, char *buffer)
{
    cm_spin_lock(&(pool->lock), NULL);

    if (gsc_common_fixed_buffer_inpool(pool, buffer)) {
#ifdef _DEBUG
        CM_ASSERT(buffer >= (char *)pool->buffer_list + sizeof(char *) * pool->total_cnt);
        CM_ASSERT(buffer < ((char *)pool->buffer_list + (sizeof(char *) + pool->block_size) * pool->total_cnt));
        CM_ASSERT((buffer - (char *)pool->buffer_list - sizeof(char *) * pool->total_cnt) % pool->block_size == 0);
#endif

        pool->buffer_list[pool->idle_cnt] = buffer;
        pool->idle_cnt++;
    } else {
        gsc_common_fixed_extend_mpool_remove(pool, buffer);
        CM_FREE_PTR(buffer);
        pool->extended_cnt--;
    }

    cm_spin_unlock(&(pool->lock));
}

bool8 gsc_common_fixed_buffer_inpool(fixed_memory_pool_t *pool, const char *buffer)
{
    char *first_buffer = (char*)pool->buffer_list + sizeof(char*) * pool->total_cnt;
    return buffer >= first_buffer &&
        buffer <= (first_buffer + pool->block_size * (pool->total_cnt - 1));
}

int gsql_generate_obj(list_t *obj_list, const char *obj_name)
{
    char *ptr = NULL;

    for (uint32 i = 0; i < obj_list->count; i++) {
        ptr = cm_list_get(obj_list, i);
        if (cm_str_equal(obj_name, ptr)) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "\"%s\" appears multiple times", obj_name);
            return GS_ERROR;
        }
    }

    GS_RETURN_IFERR(cm_list_new(obj_list, (void **)&ptr));
    MEMS_RETURN_IFERR(strncpy_s(ptr, GSQL_MAX_OBJECT_LEN, obj_name, GSQL_MAX_OBJECT_LEN - 1));
    return GS_SUCCESS;
}

void gsql_reset_crypt_info(crypt_info_t *encrypt_info)
{
    encrypt_info->crypt_flag = GS_FALSE;
    MEMS_RETVOID_IFERR(memset_s(encrypt_info->crypt_pwd, GS_PASSWD_MAX_LEN + 1, 0, GS_PASSWD_MAX_LEN + 1));
    MEMS_RETVOID_IFERR(memset_s(encrypt_info->hash_key, GS_PASSWORD_BUFFER_SIZE, 0, GS_PASSWORD_BUFFER_SIZE));
    cm_reset_list(&encrypt_info->crypt_list);
    cm_create_list(&encrypt_info->crypt_list, sizeof(crypt_file_t));
    encrypt_info->hash_key_len = 0;
    encrypt_info->version = GSQL_ENCRYPT_VERSION;
    encrypt_info->filename_len = GS_MAX_NAME_LEN;
    encrypt_info->iv_len = GS_EVP_MAX_IV_LENGTH;
    encrypt_info->salt_len = GS_KDF2SALTSIZE;
    encrypt_info->tag_len = EVP_GCM_TLS_TAG_LEN;
    encrypt_info->cfg_file = -1;
}

status_t gsql_crypt_init(gcm_encrypt_t *crypt_ctx)
{
    crypt_ctx->gcm_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(crypt_ctx->gcm_ctx);

    MEMS_RETURN_IFERR(memset_s(crypt_ctx->gcm_salt, GS_KDF2SALTSIZE, 0, GS_KDF2SALTSIZE));

    MEMS_RETURN_IFERR(memset_s(crypt_ctx->gcm_iv, GS_EVP_MAX_IV_LENGTH, 0, GS_EVP_MAX_IV_LENGTH));

    MEMS_RETURN_IFERR(memset_s(crypt_ctx->gcm_tag, EVP_GCM_TLS_TAG_LEN, 0, EVP_GCM_TLS_TAG_LEN));

    return GS_SUCCESS;
}

status_t gsql_gen_encrypt_hash(crypt_info_t *crypt_info)
{
    uint32 chiper_len = GS_PASSWORD_BUFFER_SIZE - 1;
    if (cm_generate_scram_sha256(crypt_info->crypt_pwd,
                                 (uint32)strlen(crypt_info->crypt_pwd), GS_KDF2DEFITERATION,
                                 (uchar *)crypt_info->hash_key, &chiper_len) != GS_SUCCESS) {
        return GS_ERROR;
    }
    crypt_info->hash_key_len = chiper_len;
    return GS_SUCCESS;
}

status_t gsql_encrypt_set_config(gcm_encrypt_t *encrypt_ctx, char *filename, int32 cfg_file)
{
    if (cfg_file != -1) {
        GS_RETURN_IFERR(cm_write_file(cfg_file, filename, GS_MAX_NAME_LEN));
        GS_RETURN_IFERR(cm_write_file(cfg_file, encrypt_ctx->gcm_iv, GS_EVP_MAX_IV_LENGTH));
        GS_RETURN_IFERR(cm_write_file(cfg_file, encrypt_ctx->gcm_salt, GS_KDF2SALTSIZE));
        GS_RETURN_IFERR(cm_write_file(cfg_file, encrypt_ctx->gcm_tag, EVP_GCM_TLS_TAG_LEN));
    }

    return GS_SUCCESS;
}

status_t gsql_encrypt_open_config(char *filename, FILE **cfg_file, int *filehand)
{
    char path[GS_MAX_FILE_PATH_LENGH] = { 0x00 };
    char realfile[GS_MAX_FILE_PATH_LENGH] = { 0x00 };

    GS_RETURN_IFERR(realpath_file(filename, realfile, GS_MAX_FILE_PATH_LENGH));
    cm_trim_filename(realfile, GS_MAX_FILE_PATH_LENGH, path);

    MEMS_RETURN_IFERR(strncat_s(path, GS_MAX_FILE_PATH_LENGH, GSQL_CRYPT_CFG_NAME, GS_FILE_NAME_BUFFER_SIZE - 1));

    GS_RETURN_IFERR(cm_fopen(path, "wb+", FILE_PERM_OF_DATA, cfg_file));
    *filehand = cm_fileno(*cfg_file);
    return GS_SUCCESS;
}

status_t gsql_parse_encrypt_config_core(crypt_info_t *crypt_info, gcm_encrypt_t *decrypt_ctx, const char *buf, char *filename)
{
    const char *temp = buf;
    MEMS_RETURN_IFERR(memcpy_s(filename, crypt_info->filename_len, temp, crypt_info->filename_len));

    temp = temp + crypt_info->filename_len;
    MEMS_RETURN_IFERR(memcpy_s(decrypt_ctx->gcm_iv, crypt_info->iv_len, temp, crypt_info->iv_len));

    temp = temp + crypt_info->iv_len;

    MEMS_RETURN_IFERR(memcpy_s(decrypt_ctx->gcm_salt, crypt_info->salt_len, temp, crypt_info->salt_len));

    temp = temp + crypt_info->salt_len;
    MEMS_RETURN_IFERR(memcpy_s(decrypt_ctx->gcm_tag, crypt_info->tag_len, temp, crypt_info->tag_len));

    return GS_SUCCESS;
}

status_t gsql_copy_encrypt_info(char *dst, uint32 dst_len, uint32 copy_len, const char *src, uint32 src_len)
{
    if (copy_len > src_len) {
        GS_THROW_ERROR(ERR_NAME_TOO_LONG, "crypt_info", copy_len, src_len);
        return GS_ERROR;
    }

    MEMS_RETURN_IFERR(memcpy_s(dst, dst_len, src, copy_len));
    return GS_SUCCESS;
}

status_t gsql_decode_encrypt_head(crypt_info_t *crypt_info, const char *file_buf, uint32 buf_size, uint32 *readed_size)
{
    uint32 to_read_size = sizeof(uint32);

    *readed_size = 0;

    // fetch 4bytes encrypt version
    GS_RETURN_IFERR(gsql_copy_encrypt_info((char*)&crypt_info->version, sizeof(uint32),
        to_read_size, file_buf + *readed_size, buf_size - *readed_size));
    *readed_size += to_read_size;

    // fetch 4bytes encrypt pwd hash key length
    GS_RETURN_IFERR(gsql_copy_encrypt_info((char*)&crypt_info->hash_key_len, sizeof(uint32),
        to_read_size, file_buf + *readed_size, buf_size - *readed_size));
    *readed_size += to_read_size;

    // fetch encrypt pwd hash key
    to_read_size = crypt_info->hash_key_len;
    GS_RETURN_IFERR(gsql_copy_encrypt_info(crypt_info->hash_key, sizeof(crypt_info->hash_key),
        to_read_size, file_buf + *readed_size, buf_size - *readed_size));
    *readed_size += to_read_size;

    // fetch 4bytes encrypt file name max length
    to_read_size = sizeof(uint32);
    GS_RETURN_IFERR(gsql_copy_encrypt_info((char*)&crypt_info->filename_len, sizeof(uint32),
        to_read_size, file_buf + *readed_size, buf_size - *readed_size));
    *readed_size += to_read_size;

    // fetch 4bytes encrypt file count
    GS_RETURN_IFERR(gsql_copy_encrypt_info((char*)&crypt_info->file_cnt, sizeof(uint32),
        to_read_size, file_buf + *readed_size, buf_size - *readed_size));
    *readed_size += to_read_size;

    // fetch 4bytes encrypt iv length
    GS_RETURN_IFERR(gsql_copy_encrypt_info((char*)&crypt_info->iv_len, sizeof(uint32),
        to_read_size, file_buf + *readed_size, buf_size - *readed_size));
    *readed_size += to_read_size;

    // fetch 4bytes encrypt salt length
    GS_RETURN_IFERR(gsql_copy_encrypt_info((char*)&crypt_info->salt_len, sizeof(uint32),
        to_read_size, file_buf + *readed_size, buf_size - *readed_size));
    *readed_size += to_read_size;

    // fetch 4bytes encrypt tag length
    GS_RETURN_IFERR(gsql_copy_encrypt_info((char*)&crypt_info->tag_len, sizeof(uint32),
        to_read_size, file_buf + *readed_size, buf_size - *readed_size));
    *readed_size += to_read_size;

    return GS_SUCCESS;
}

status_t gsql_decode_encrypt_file(crypt_info_t *crypt_info, crypt_file_t *file_ctx, const char *file_buf, uint32 buf_size)
{
    int32 res;
    uchar cipher[GS_PASSWORD_BUFFER_SIZE] = { 0 };

    GS_RETURN_IFERR(gsql_crypt_init(&file_ctx->crypt_ctx));

    if (gsql_parse_encrypt_config_core(crypt_info, &file_ctx->crypt_ctx, file_buf,
        file_ctx->filename) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_encrypt_KDF2((uchar *)crypt_info->crypt_pwd, (uint32)strlen(crypt_info->crypt_pwd),
        (uchar *)file_ctx->crypt_ctx.gcm_salt, GS_KDF2SALTSIZE, GS_KDF2DEFITERATION,
        cipher, GS_AES256KEYSIZE) != GS_SUCCESS) {
        return GS_ERROR;
    }
    EVP_CIPHER_CTX_ctrl(file_ctx->crypt_ctx.gcm_ctx, EVP_CTRL_AEAD_SET_IVLEN,
        sizeof(file_ctx->crypt_ctx.gcm_iv), NULL);
    res = EVP_DecryptInit_ex(file_ctx->crypt_ctx.gcm_ctx, EVP_aes_256_gcm(), NULL, (const unsigned char *)cipher,
        (const unsigned char *)file_ctx->crypt_ctx.gcm_iv);
    if (res == 0) {
        GS_THROW_ERROR(ERR_ENCRYPTION_ERROR, "backup ", "failed to init cryption ctx");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t gsql_decode_encrypt_info(crypt_info_t *crypt_info, const char *file_buf, uint32 buf_size)
{
    uint32 readed_size = 0;
    uint32 to_read_size;
    crypt_file_t *file_ctx = NULL;

    GS_RETURN_IFERR(gsql_decode_encrypt_head(crypt_info, file_buf, buf_size, &readed_size));
  
    to_read_size = crypt_info->filename_len + crypt_info->iv_len + crypt_info->salt_len + crypt_info->tag_len;

    for (uint32 i = 0; i < crypt_info->file_cnt; i++) {
        if (to_read_size + readed_size > buf_size) {
            GS_THROW_ERROR(ERR_NAME_TOO_LONG, "crypt_file_info", to_read_size + readed_size, buf_size);
            return GS_ERROR;
        }

        GS_RETURN_IFERR(cm_list_new(&crypt_info->crypt_list, (void *)&file_ctx));
        
        GS_RETURN_IFERR(gsql_decode_encrypt_file(crypt_info, file_ctx, file_buf + readed_size, buf_size - readed_size));
        readed_size += to_read_size;
    }
    return GS_SUCCESS;
}

status_t gsql_parse_encrypt_config(crypt_info_t *crypt_info, char *cfg_path, char *file_buf,
                                   uint32 *buf_size, text_t *s_cipher)
{
    if (cm_read_config_file(cfg_path, file_buf, buf_size, GS_FALSE, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsql_decode_encrypt_info(crypt_info, file_buf, *buf_size));
    
    cm_str2text_safe(crypt_info->hash_key, crypt_info->hash_key_len, s_cipher);
    s_cipher->str[crypt_info->hash_key_len] = '\0';
    
    return GS_SUCCESS;
}

status_t gsql_encrypt_prepare(gcm_encrypt_t *encrypt_ctx, char *encrypt_pwd)
{
    int32 res;
    uchar kdf2_key[GS_PASSWORD_BUFFER_SIZE] = { 0 };

    GS_RETURN_IFERR(gsql_crypt_init(encrypt_ctx));

    if (cm_rand((uchar *)encrypt_ctx->gcm_iv, GS_EVP_MAX_IV_LENGTH) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_ENCRYPTION_ERROR, "backup ", "failed to acquire random iv");
        return GS_ERROR;
    }

    if (cm_rand((uchar *)encrypt_ctx->gcm_salt, GS_KDF2SALTSIZE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_encrypt_KDF2((uchar *)encrypt_pwd, (uint32)strlen(encrypt_pwd), (uchar *)encrypt_ctx->gcm_salt,
        GS_KDF2SALTSIZE, GS_KDF2DEFITERATION, kdf2_key, GS_AES256KEYSIZE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    EVP_CIPHER_CTX_ctrl(encrypt_ctx->gcm_ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(encrypt_ctx->gcm_iv), NULL);
    res = EVP_EncryptInit_ex(encrypt_ctx->gcm_ctx, EVP_aes_256_gcm(), NULL, (const unsigned char *)kdf2_key,
                             (const unsigned char *)encrypt_ctx->gcm_iv);
    if (res == 0) {
        GS_THROW_ERROR(ERR_ENCRYPTION_ERROR, "backup ", "failed to init cryption ctx");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t gsql_decrypt_prepare(crypt_info_t *decrypt_info, const char *realfile)
{
    char *file_buf = NULL;

    char path[GS_MAX_FILE_PATH_LENGH] = { 0x00 };
    text_t c_cipher, s_cipher;
    int64 filesize = 0;
    char *cfg_path = NULL;

    cm_trim_filename(realfile, GS_MAX_FILE_PATH_LENGH, path);
    MEMS_RETURN_IFERR(strncat_s(path, GS_MAX_FILE_PATH_LENGH, GSQL_CRYPT_CFG_NAME, GS_FILE_NAME_BUFFER_SIZE - 1));

    cfg_path = path;
    cm_get_filesize(cfg_path, &filesize);
    file_buf = (char *)malloc(filesize + 1);
    if (file_buf == NULL) {
        return GS_ERROR;
    }

    uint32 size = (uint32)filesize;
    if (gsql_parse_encrypt_config(decrypt_info, cfg_path, file_buf, &size, &s_cipher) != GS_SUCCESS) {
        CM_FREE_PTR(file_buf);
        return GS_ERROR;
    }
    CM_FREE_PTR(file_buf);

    cm_str2text(decrypt_info->crypt_pwd, &c_cipher);
    status_t ret = cm_check_password(&c_cipher, &s_cipher);
    MEMS_RETURN_IFERR(memset_s(decrypt_info->crypt_pwd, sizeof(decrypt_info->crypt_pwd), 0,
        sizeof(decrypt_info->crypt_pwd)));

    if (ret != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_CRYPTION_ERROR, "incorrect password");
    }

    return ret;
}

void gsql_encrypt_end_core(crypt_info_t *encrypt_info, char *filename, FILE **cfg_file)
{
    crypt_file_t *encrypt_file = NULL;

    if (gsql_encrypt_open_config(filename, cfg_file, &encrypt_info->cfg_file) != GS_SUCCESS) {
        return;
    }

    if (encrypt_info->cfg_file != -1) {
        // 4 bytes for encrypt version
        (void)cm_write_file(encrypt_info->cfg_file, (char *)&encrypt_info->version, sizeof(uint32));
        // 4 bytes for encrypt pwd hash key length
        (void)cm_write_file(encrypt_info->cfg_file, (char *)&encrypt_info->hash_key_len, sizeof(uint32));
        // encrypt pwd hash key
        (void)cm_write_file(encrypt_info->cfg_file, encrypt_info->hash_key, encrypt_info->hash_key_len);
        // 4 bytes for encrypt file name max length
        (void)cm_write_file(encrypt_info->cfg_file, (char *)&encrypt_info->filename_len, sizeof(uint32));
        // 4 bytes for encrypt file count
        (void)cm_write_file(encrypt_info->cfg_file, (char *)&encrypt_info->crypt_list.count, sizeof(uint32));
        // 4 bytes for encrypt iv length
        (void)cm_write_file(encrypt_info->cfg_file, (char *)&encrypt_info->iv_len, sizeof(uint32));
        // 4 bytes for encrypt salt length
        (void)cm_write_file(encrypt_info->cfg_file, (char *)&encrypt_info->salt_len, sizeof(uint32));
        // 4 bytes for encrypt tag length
        (void)cm_write_file(encrypt_info->cfg_file, (char *)&encrypt_info->tag_len, sizeof(uint32));
    }

    for (uint32 i = 0; i < encrypt_info->crypt_list.count; i++) {
        encrypt_file = (crypt_file_t *)cm_list_get(&encrypt_info->crypt_list, i);

        (void)cm_encrypt_end_by_gcm(encrypt_file->crypt_ctx.gcm_ctx, encrypt_file->crypt_ctx.gcm_tag);

        if (gsql_encrypt_set_config(&encrypt_file->crypt_ctx, encrypt_file->filename,
                                    encrypt_info->cfg_file) != GS_SUCCESS) {
            return;
        }

        if (encrypt_file->crypt_ctx.gcm_ctx != NULL) {
            EVP_CIPHER_CTX_free(encrypt_file->crypt_ctx.gcm_ctx);
            encrypt_file->crypt_ctx.gcm_ctx = NULL;
        }

        continue;
    }
}

void gsql_encrypt_end(crypt_info_t *encrypt_info, char *filename)
{
    FILE *cfg_file_ptr = NULL;
    if (encrypt_info->crypt_flag && encrypt_info->crypt_list.count > 0) {
        gsql_encrypt_end_core(encrypt_info, filename, &cfg_file_ptr);
        if (cfg_file_ptr != NULL) {
            cm_close_file(encrypt_info->cfg_file);
            cfg_file_ptr = NULL;
        }
    }

    MEMS_RETVOID_IFERR(memset_s(encrypt_info->crypt_pwd, GS_PASSWD_MAX_LEN + 1, 0, GS_PASSWD_MAX_LEN + 1));
    cm_reset_list(&encrypt_info->crypt_list);
}

void gsql_decrypt_end(crypt_info_t *decrypt_info)
{
    crypt_file_t *decrypt_file = NULL;

    if (decrypt_info->crypt_flag && decrypt_info->crypt_list.count > 0) {
        for (uint32 i = 0; i < decrypt_info->crypt_list.count; i++) {
            decrypt_file = (crypt_file_t *)cm_list_get(&decrypt_info->crypt_list, i);
            (void)cm_dencrypt_end_by_gcm(decrypt_file->crypt_ctx.gcm_ctx, decrypt_file->crypt_ctx.gcm_tag);

            if (decrypt_file->crypt_ctx.gcm_ctx != NULL) {
                EVP_CIPHER_CTX_free(decrypt_file->crypt_ctx.gcm_ctx);
                decrypt_file->crypt_ctx.gcm_ctx = NULL;
            }
        }
    }

    MEMS_RETVOID_IFERR(memset_s(decrypt_info->crypt_pwd, GS_PASSWD_MAX_LEN + 1, 0, GS_PASSWD_MAX_LEN + 1));
    cm_reset_list(&decrypt_info->crypt_list);
}

bool8 find_remap(list_t *map_list, const char *src, char *dest, uint32 dest_len)
{
    uint32 i;
    re_map_t *re_map = NULL;

    for (i = 0; i < map_list->count; i++) {
        re_map = (re_map_t *)cm_list_get(map_list, i);
        if (cm_strcmpi(re_map->src, src) == 0) {
            if (strncpy_s(dest, dest_len, re_map->dest, strlen(re_map->dest)) != EOK) {
                return GS_FALSE;
            }

            return GS_TRUE;
        }
    }
    return GS_FALSE;
}

status_t gsql_setup_conn_nls(gsql_conn_info_t *main_conn, gsql_conn_info_t *sub_conn)
{
    int32 nls_attrs[] = { GSC_ATTR_NLS_DATE_FORMAT, GSC_ATTR_NLS_TIMESTAMP_FORMAT,
        GSC_ATTR_NLS_TIMESTAMP_TZ_FORMAT, GSC_ATTR_NLS_TIME_FORMAT, GSC_ATTR_NLS_TIME_TZ_FORMAT };
    char main_nls[MAX_NLS_PARAM_LENGTH];
    char sub_nls[MAX_NLS_PARAM_LENGTH];
    uint32 main_nls_len, sub_nls_len;

    for (uint32 i = 0; i < sizeof(nls_attrs) / sizeof(int32); i++) {
        GS_RETURN_IFERR(gsc_get_conn_attr(main_conn->conn, nls_attrs[i], main_nls, sizeof(main_nls), &main_nls_len));
        GS_RETURN_IFERR(gsc_get_conn_attr(sub_conn->conn, nls_attrs[i], sub_nls, sizeof(sub_nls), &sub_nls_len));
        if (main_nls_len != sub_nls_len || !cm_str_equal((const char *)main_nls, (const char *)sub_nls)) {
            GS_RETURN_IFERR(gsc_set_conn_attr(sub_conn->conn, nls_attrs[i], main_nls, main_nls_len));
        }
    }

    return GS_SUCCESS;
}

status_t gsql_set_session_interactive_mode(bool32 enable_interactive)
{
    int iret_sprintf;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "ALTER SESSION %s INTERACTIVE TIMEOUT ", (enable_interactive ? "ENABLE" : "DISABLE"));
    if (iret_sprintf == -1) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));
    return GS_SUCCESS;
}

status_t gsql_get_curr_schema(text_t *schema_buf)
{
    uint32 rows, size, is_null;
    void *data = NULL;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL, "SELECT CURR_SCHEMA FROM DV_ME"));
    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));
    GS_RETURN_IFERR(gsc_fetch(STMT, &rows));

    if (rows == 0) {
        GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "current schema does not exist!");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsc_get_column_by_id(STMT, 0, (void **)&data, &size, &is_null));
    MEMS_RETURN_IFERR(memcpy_s(schema_buf->str, GS_MAX_NAME_LEN, (char *)data, size));

    schema_buf->len = size;
    *(schema_buf->str + size) = '\0';

    return GS_SUCCESS;
}

status_t gsql_check_dba_user(bool8 *is_dba)
{
    uint32 rows;
    *is_dba = GS_FALSE;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL, "SELECT * FROM MY_ROLE_PRIVS where GRANTED_ROLE='DBA'"));

    if (!IS_CONN) {
        (void)gsql_print_disconn_error();
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));

    GS_RETURN_IFERR(gsc_execute(STMT));

    GS_RETURN_IFERR(gsc_fetch(STMT, &rows));

    if (rows > 0) {
        *is_dba = GS_TRUE;
    }
    return GS_SUCCESS;
}

status_t gsql_check_tenant(void)
{
    uint32 rows;
    int iret_sprintf;
    char tenant[GS_TENANT_BUFFER_SIZE];
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    if (gsc_get_call_version(CONN) <= CS_VERSION_17) {
        return GS_SUCCESS;
    }

    iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL, "SELECT SYS_CONTEXT('USERENV', 'TENANT_NAME')");
    if (iret_sprintf == -1) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));
    GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
    if (rows == 0) {
        GS_THROW_ERROR(ERR_TENANT_NOT_EXIST, "of current session");
        return GS_ERROR;
    }
    GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, tenant, GS_TENANT_BUFFER_SIZE));
    if (!cm_str_equal_ins((const char *)tenant, "TENANT$ROOT")) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "export/import", "non-root tenant");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t gsql_switch_user(gsql_conn_info_t *conn_info)
{
    if (conn_info->connect_by_install_user) {
        if (conn_info->is_clsmgr) {
            PRTS_RETURN_IFERR(sprintf_s(conn_info->username, GS_NAME_BUFFER_SIZE, "%s", CM_CLSMGR_USER_NAME));
        } else {
            PRTS_RETURN_IFERR(sprintf_s(conn_info->username, GS_NAME_BUFFER_SIZE, "%s", CM_SYSDBA_USER_NAME));
        }
    }

    return GS_SUCCESS;
}

status_t gsql_reset_case_insensitive(bool8 *is_case_insensitive)
{
    uint32 rows;
    int iret_sprintf;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];
    char str_buf[GSQL_MAX_OBJECT_TYPE_LEN] = { 0 };

    iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT CASE WHEN UPPER(VALUE)='TRUE' THEN '1' ELSE '0' END "
        "FROM DV_USER_PARAMETERS WHERE NAME = 'UPPER_CASE_TABLE_NAMES'");
    if (iret_sprintf == -1) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));

    GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
    if (rows == 0) {
        *is_case_insensitive = GS_TRUE;
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, str_buf, GSQL_MAX_OBJECT_TYPE_LEN));
    *is_case_insensitive = cm_str_equal((const char *)str_buf, "0") ? GS_FALSE : GS_TRUE;

    return GS_SUCCESS;
}

status_t gsql_get_crypt_pwd(lex_t *lex, char *crypt_pwd, uint32 max_pwd_len, char *key_word_info)
{
    status_t ret;
    errno_t errcode;
    char pwd_str[GS_PASSWD_MAX_LEN + 1] = { 0 };

    do {
        ret = lex_expected_fetch_str(lex, pwd_str, GS_PASSWD_MAX_LEN, key_word_info);
        GS_BREAK_IF_ERROR(ret);

        errcode = strncpy_s(crypt_pwd, max_pwd_len, pwd_str, GS_PASSWD_MAX_LEN);
        if (errcode != EOK) {
            ret = GS_ERROR;
            GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            break;
        }

        ret = cm_verify_password_str(NULL, crypt_pwd, GS_PASSWD_MIN_LEN);
    } while (0);

    MEMS_RETURN_IFERR(memset_s(pwd_str, GS_PASSWD_MAX_LEN + 1, 0, GS_PASSWD_MAX_LEN + 1));
    return ret;
}

void gsql_erase_string(char *str)
{
    errno_t errcode;

    if (str != NULL) {
        errcode = memset_s(str, strlen(str), 0, strlen(str));
        if (errcode != EOK) {
            gsql_printf("Secure C lib has thrown an error %d", errcode);
        }
    }
}

void gsql_regular_match_sensitive(const char *sql, uint32 sql_len, text_t *output_sql)
{
    text_t matched_sql;
    matched_sql.str = (char *)sql;
    matched_sql.len = sql_len;

#if !defined(_DEBUG) && !defined(DEBUG) && !defined(DB_DEBUG_VERSION)
    bool32 matched = GS_FALSE;
    int32 match_type;
    if (matched_sql.len > 0) {
        cm_text_try_map_key2type(&matched_sql, &match_type, &matched);
        if (matched == GS_TRUE) {
            matched_sql.str = g_key_pattern[match_type].type_desc;
            matched_sql.len = (uint32)strlen(g_key_pattern[match_type].type_desc);
        }
    }
#endif

    output_sql->str = matched_sql.str;
    output_sql->len = matched_sql.len;
}