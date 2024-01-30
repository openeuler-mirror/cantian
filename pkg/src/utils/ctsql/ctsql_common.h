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
 * ctsql_common.h
 *
 *
 * IDENTIFICATION
 * src/utils/ctsql/ctsql_common.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CTSQL_COMMON_H__
#define __CTSQL_COMMON_H__

#include "ctconn.h"
#include "cm_defs.h"
#include "zlib.h"
#include "cm_spinlock.h"
#include "cm_list.h"
#include "cm_encrypt.h"
#include "cm_config.h"
#include "ctconn_common.h"
#include "ctconn_stmt.h"
#include "ctconn_conn.h"
#include "ctsql.h"
#include "cm_lex.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CTSQL_NO_ENCLOSED_CHAR CT_INVALID_INT8

#define CTSQL_DEFAULT_ENCLOSED_CHAR        CTSQL_NO_ENCLOSED_CHAR
#define CTSQL_DEFAULT_FIELD_SEPARATOR_CHAR ','
#define CTSQL_DEFAULT_FIELD_SEPARATOR_STR  ","
#define CTSQL_DEFAULT_LINE_SEPARATOR_STR   "\n"

#define CTSQL_HAS_ENCLOSED_CHAR(c) (CM_IS_VALID_ENCLOSED_CHAR(c))

#define CTSQL_COMMIT_BATCH (uint32)1000
#define CTSQL_FEEDBACK     (uint32)10000
#define CTSQL_INSERT_BATCH (uint32)10000
#define CTSQL_AUTO_COMMIT  (uint32)1000
#define CTSQL_MAX_OBJECT_LEN (CT_MAX_NAME_LEN + 1)
#define CTSQL_MAX_OBJECT_TYPE_LEN 13
#define CTSQL_MAX_QUOTE_NAME_SIZE 200
#define CTSQL_CRYPT_CFG_NAME   "encrypt.cfg"
#define CTSQL_ENCRYPT_VERSION   (uint32)0
#define CTSQL_MAX_TEMP_SQL      (uint32)4096

/* compress file read/write(with zlib) */
typedef struct st_ctconn_z_stream {
    z_stream zs;
    int32 flush;
    FILE *fp;
    int64 seek_rpos;
} ctconn_z_stream;

typedef struct st_crypt_info {
    bool32 crypt_flag;
    SENSI_INFO char crypt_pwd[CT_PASSWD_MAX_LEN + 1];
    char hash_key[CT_PASSWORD_BUFFER_SIZE];
    uint32 version;
    uint32 hash_key_len;
    uint32 filename_len;
    uint32 iv_len;
    uint32 salt_len;
    uint32 tag_len;
    uint32 file_cnt;
    int cfg_file;
    list_t crypt_list;
} crypt_info_t;

typedef struct st_encrypt_file {
    gcm_encrypt_t crypt_ctx;
    char filename[CT_MAX_NAME_LEN + 1];
    int32 fp;
} crypt_file_t;

typedef struct {
    char src[CT_MAX_NAME_LEN + 1];
    char dest[CT_MAX_NAME_LEN + 1];
} re_map_t;

#define CTCONN_COMMON_ZSTREAM(stream) ((stream)->zs)

/* compress file read (with zlib) interface */
status_t ctconn_common_z_init_read(FILE *fp, ctconn_z_stream *zstream);
status_t ctconn_common_z_read_compress(ctconn_z_stream *zstream, crypt_info_t *crypt_info, char *swap_buffer,
                                    uint32 swap_len, bool8 *eof);
status_t ctconn_common_z_read_data(ctconn_z_stream *zstream, char *data_buffer, uint32 len, uint32 *readed_len,
                                bool8 *eof);
status_t ctconn_common_z_read_direct(ctconn_z_stream *zstream, crypt_info_t *crypt_info,
                                  char *swap_buffer, uint32 swap_len,
                                  char *data_buffer, uint32 len, uint32 *readed_len, bool8 *eof);
status_t ctconn_common_z_read_seek(ctconn_z_stream *zstream, crypt_info_t *crypt_info,
                                int64 pos, char *swap_buffer, uint32 swap_len);
status_t ctconn_common_z_uninit_read(ctconn_z_stream *zstream);

/* compress file write(with zlib) interface */
status_t ctconn_common_z_init_write(FILE *fp, ctconn_z_stream *zstream, uint32 level);
status_t ctconn_common_z_write(ctconn_z_stream *zstream, crypt_info_t *crypt_info, char *swap_buffer, uint32 swap_len,
                            char *buffer, uint32 len, bool8 eof);
status_t ctconn_common_z_uninit_write(ctconn_z_stream *zstream);

/* fixed memory pool */
typedef struct {
    char **buffer_list;
    char **ext_buffer_list;
    uint32 idle_cnt;
    uint32 total_cnt;
    uint32 block_size;
    uint32 extended_cnt;
    uint32 max_ext_cnt; // can extend block from system
    spinlock_t lock;
} fixed_memory_pool_t;

/* interface for fixed buffer pool */
status_t ctconn_common_init_fixed_memory_pool(fixed_memory_pool_t *pool, uint32 block_size, uint32 block_count);
status_t ctconn_common_init_fixed_memory_pool_ex(fixed_memory_pool_t *pool, uint32 block_size,
    uint32 block_count, uint32 max_ext_cnt);
void ctconn_common_uninit_fixed_memory_pool(fixed_memory_pool_t *pool);
char *ctconn_common_alloc_fixed_buffer(fixed_memory_pool_t *pool);
void ctconn_common_free_fixed_buffer(fixed_memory_pool_t *pool, char *buffer);
bool8 ctconn_common_fixed_buffer_inpool(fixed_memory_pool_t *pool, const char *buffer);

int ctsql_generate_obj(list_t *obj_list, const char *obj_name);

/* interface for data encrypt and decrypt */
void ctsql_reset_crypt_info(crypt_info_t *encrypt_info);
status_t ctsql_gen_encrypt_hash(crypt_info_t *crypt_info);
status_t ctsql_encrypt_prepare(gcm_encrypt_t *encrypt_ctx, char *encrypt_pwd);
status_t ctsql_decrypt_prepare(crypt_info_t *decrypt_info, const char *realfile);
status_t ctsql_get_encrypt_file(crypt_info_t *crypt_info, crypt_file_t **encrypt_file, int fp);
status_t ctsql_set_encrpyt_fp(crypt_info_t *crypt_info, const char* filename, int32 fp);
void ctsql_encrypt_end(crypt_info_t *encrypt_info, char *filename);
void ctsql_decrypt_end(crypt_info_t *decrypt_info);
status_t ctsql_reset_crypfile(FILE *fp, crypt_info_t *crypt_info);
bool8 find_remap(list_t *map_list, const char *src, char *dest, uint32 dest_len);
status_t ctsql_set_session_interactive_mode(bool32 enable_interactive);
status_t ctsql_get_curr_schema(text_t *schema_buf);
status_t ctsql_check_dba_user(bool8 *is_dba);
status_t ctsql_check_tenant(void);
status_t ctsql_switch_user(ctsql_conn_info_t *conn_info);

/* interface for clone connection nls attr */
status_t ctsql_setup_conn_nls(ctsql_conn_info_t *main_conn, ctsql_conn_info_t *sub_conn);

status_t ctsql_reset_case_insensitive(bool8 *is_case_insensitive);
status_t ctsql_get_crypt_pwd(lex_t *lex, char *crypt_pwd, uint32 max_pwd_len, char *key_word_info);

void ctsql_erase_string(char *str);
void ctsql_regular_match_sensitive(const char *sql, uint32 sql_len, text_t *output_sql);

#ifdef __cplusplus
}
#endif

#endif  // __CTSQL_COMMON_H__