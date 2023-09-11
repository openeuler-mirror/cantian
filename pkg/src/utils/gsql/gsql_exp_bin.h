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
 * gsql_exp_bin.h
 *
 *
 * IDENTIFICATION
 * src/utils/gsql/gsql_exp_bin.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __GSQL_EXP_BIN_H__
#define __GSQL_EXP_BIN_H__

#include "cm_binary.h"
#include "cm_list.h"
#include "gsql_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GSQL_EXP_BIN_MEM_BLOCK_SIZE          (uint32)(5 * 1024 * 1024)
#define GSQL_EXP_BIN_MEM_BLOCK_RESERVED_SIZE (uint32)8
#define EXP_OBJECT_END_FLAG                  (uint32)0xdbdbdbdb

typedef enum {
    FT_BIN,
    FT_TXT
} exp_filetype_t;

typedef struct st_short_bin_buffer {
    uint16 *size;
    char *buffer;
} short_bin_buffer_t;

typedef struct st_bin_buffer {
    uint32 *size;
    char *buffer;
} bin_buffer_t;

typedef struct st_huge_bin_buffer {
    uint64 *size;
    char *buffer;
} huge_bin_buffer_t;

typedef struct st_exp_mem_block {
    uint32 *block_size;
    uint32 *offset;
    char *buffer;
} exp_mem_block_t;

typedef struct st_exp_bin_memory_mgr {
    struct st_exp_mem_block cur_buf;
    uint32 *len_addr;
    uint32 tmp_write_len;
    uint32 *sub_len_addr;
    uint32 sub_tmp_write_len;
    list_t mems;
} exp_bin_memory_mgr_t;

status_t exp_bin_memory_mgr_begin(exp_bin_memory_mgr_t *mgr, exp_filetype_t filetype);
void exp_bin_memory_mgr_end(exp_bin_memory_mgr_t *mgr, exp_filetype_t filetype);
status_t exp_bin_memory_mgr_sub_begin(exp_bin_memory_mgr_t *mgr, exp_filetype_t filetype);
void exp_bin_memory_mgr_sub_end(exp_bin_memory_mgr_t *mgr, exp_filetype_t filetype);

status_t init_exp_bin_memory_mgr(exp_bin_memory_mgr_t *mem_mgr);
static inline void destroy_memory_mgr(exp_bin_memory_mgr_t *mgr)
{
    cm_destroy_list(&mgr->mems);
}
status_t get_mem_address(exp_bin_memory_mgr_t *mgr, char **buf, uint32 required_size);
status_t get_bin_bufer_addr(exp_bin_memory_mgr_t *mgr, bin_buffer_t *bin_buf, uint32 required_size);
status_t get_short_bin_bufer_addr(exp_bin_memory_mgr_t *mgr, short_bin_buffer_t *bin_buf, uint16 required_size);
status_t mem_block_write_file(exp_bin_memory_mgr_t *mgr, FILE *hand, crypt_file_t *crypt_file, bool32 encrypt_flag);

typedef struct st_exp_bin_records_mgr {
    struct st_exp_bin_memory_mgr mem_mgr;
    FILE *data_file_handle;
    bool32 par_flag;
    uint32 mem_cache_block;
    uint64 recored_total;
    char file_name[GS_MAX_FILE_PATH_LENGH];
} exp_bin_records_mgr_t;

typedef enum en_exp_client_version {
    EXP_CLI_VERSION_0 = 0,  /* base version */
    EXP_CLI_VERSION_1 = 1,  /* exp support subfile write in data dir */
    EXP_CLI_VERSION_2 = 2,  /* exp support synonym */
    EXP_CLI_VERSION_3 = 3   /* exp support bin format of array datatype */
} exp_client_version_t;

#define CLI_LOCAL_EXP_VERSION (uint16) EXP_CLI_VERSION_3

typedef struct st_bin_file_fixed_head {
    uint64 exp_time;            // time info[8bytes]
    uint16 split_flag;          // File splitting flag[2bytes] 0: Non-split 1: split
    uint16 exp_type;            // [2bytes]
    char char_set[16];          // Character set[16bytes]
    // delete char client_ver[16], use [2bytes] for client version and reserve [14bytes]
    uint16 client_ver;          // client version used [2bytes]
    char reserved[14];
    char server_ver[16];        // server version[16bytes]
    char crc[32];               // Verification information[32bytes]
    uint32 comp_flag;           // Compression flag [4bytes]
    uint32 commit_batch;        // number of commit[4bytes]
    uint32 insert_batch;        // Number of entries inserted in each batch[4bytes]
    uint64 schema_info_offset;  // index position of schema[8bytes]
    uint64 master_file_size;    // export master file size [8bytes]
} bin_file_fixed_head_t;

void init_bin_file_fixed_head(exp_bin_memory_mgr_t *mgr, bin_file_fixed_head_t **head);

typedef struct st_bin_file_head {
    struct st_bin_file_fixed_head fixed_head;  // sizeof(bin_file_fixed_head_t)
    struct st_bin_buffer exp_command;          // export command info
    struct st_bin_buffer session_param;        // Session parameters
} bin_file_head_t;

typedef struct st_exp_schema_constranints {
    struct st_bin_buffer ext_key;  // External key domain
    struct st_bin_buffer view;     // View Domain
    struct st_bin_buffer fun_obj;  // Functions, triggers, and stored procedure domains
} exp_schema_constranints_t;

typedef struct st_exp_data_file_info {
    binary_t file_bin;
} exp_data_file_info_t;

typedef struct st_exp_table_index_split {
    uint64 tab_meta_offset;
    list_t exp_data_files;  // (exp_data_file_info_t)
    uint64 tab_index_offset;
} exp_table_index_split_t;

typedef struct st_exp_table_index {
    uint64 tab_meta_offset;
    uint64 tab_data_offset;
    uint64 tab_index_offset;
} exp_table_index_t;

typedef struct st_exp_schema_info {
    uint16 split_flag;
    binary_t schema_name;
    uint64 schema_offset;  // [8bytes]
    list_t tables;
    uint64 schema_constraints_offset;  // [8bytes]
} exp_schema_info_t;

typedef struct st_schema_object_index {
    uint32 schema_total;  // schema total[4bytes]
    list_t schemas;
} schema_object_index_t;

#ifdef __cplusplus
}
#endif

#endif /* __GSQL_EXP_BIN_H__ */
