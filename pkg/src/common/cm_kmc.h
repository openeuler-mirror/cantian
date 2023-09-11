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
 * cm_kmc.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_kmc.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef _KMC_ITF
#define _KMC_ITF

#include "cm_defs.h"
#include "cm_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GS_KMC_FILENAMEA   "kmc_a.ksf"
#define GS_KMC_FILENAMEB   "kmc_b.ksf"
#define GS_KMC_PRIVILEGE   "priv.bin"
#define GS_CLIENT           (uint32)0
#define GS_SERVER           (uint32)1
#define GS_KMC_MK_LEN       (uint32)32
#define GS_KMC_PRVI_LEN     (uint32)192
#define GS_KMC_MK_EXPIRE    (uint32)1046576
#define GS_KMC_RAND_LEN     (uint32)32
#define GS_KMC_ACTIVE_MK_LEN   (uint32)1024
#define GS_KMC_MAX_KEYFILE_NUM (uint32)2
#define GS_KMC_MAX_MK_SIZE     (uint32)256 // WSEC_MK_LEN_MAX
#define GS_KMC_MAX_MK_COUNT    (uint32)256
#define GS_KMC_MK_HASH_LEN     (uint32)8 // WSEC_MK_HASH_REC_LEN
#define GS_KMC_MAX_CIPHER_SIZE (uint32)256

#define GS_ENCRYPT_VER      "V003$" // kmc v3
#define GS_ENCRYPT_VER_LEN  (uint32)5
#define GS_ENCRYPT_KMC_LIKE "AAAAA"
#define GS_ENCRYPT_KMC_LIKE_LEN (uint32)5

typedef struct keyfile_ctrl {
    int64 size;
} keyfile_ctrl_t;

#define GS_KMC_MAX_KEY_SIZE ((uint32)SIZE_M(2) + sizeof(keyfile_ctrl_t))

typedef enum st_encrypt_version {
    NO_ENCRYPT          = 0,
    KMC_DEFAULT_ENCRYPT = 1,
    KMC_ALGID_AES256_GCM = 2,
    KMC_ALGID_AES256_CBC = 3,
    KMC_ALGID_MAX
} encrypt_version_t;
typedef enum st_domain_type {
    GS_KMC_DOMAIN_BEGIN  = 9,
    GS_KMC_SERVER_DOMAIN,
    GS_KMC_KERNEL_DOMAIN,
    GS_KMC_DOMAIN_END, // max domain must <= 255
} domain_type_t;

typedef struct encrypt_manager {
    encrypt_version_t version;
    uint32 cipher_alg_type;
    uint32 hmac_alg_type;
} encrypt_manager_t;

typedef struct st_page_cipher_ctrl {
    uint16 cipher_expanded_size;
    uint16 offset;
    uint16 plain_cks;
    uint8 encrypt_version;
    uint8 reserved;
} cipher_ctrl_t;

typedef struct st_rd_create_mk_begin {
    uint32 op_type;
    uint32 max_mkid;
    uint64 reserved;
} rd_create_mk_begin_t;

typedef struct st_rd_mk_data {
    uint32 op_type;
    uint32 len;
    uint64 offset;
    uint32 reserved;
    char data[GS_KMC_MAX_MK_SIZE];
} rd_mk_data_t;

typedef struct st_rd_create_mk_end {
    uint32 op_type;
    uint32 mk_id;
    uint32 hash_len;
    uint32 reserved;
    char hash[GS_KMC_MK_HASH_LEN];
} rd_create_mk_end_t;

typedef struct st_rd_alter_server_mk {
    uint32 op_type;
    uint64 reserved;
} rd_alter_server_mk_t;

typedef struct st_keyfile_item {
    char name[GS_FILE_NAME_BUFFER_SIZE];
} keyfile_item_t;

typedef struct {
    bool32 kmc_disable_ver;
    uint32 kmc_domain;
    encrypt_version_t kmc_ver;
    uint32 plain_len;
    uint32 cipher_len;
    char *plain;
    char *cipher;
    char *fator;
    char *local;
    char *fator_new;
    char *local_new;
    char *kmc_mhome;  // master home
    char *kmc_shome;  // standby home
} aes_and_kmc_t;

status_t cm_kmc_init(bool32 is_server, char *key_file_a, char *key_file_b);
status_t cm_kmc_reset(void);
status_t cm_kmc_finalize(void);
status_t cm_kmc_load_domain(uint32 domain);
status_t cm_kmc_init_domain(uint32 domain);
status_t cm_get_cipher_len(uint32 plain_len, uint32 *cipher_len);
status_t cm_kmc_encrypt(uint32 domain, encrypt_version_t version, const void *plain_text, uint32 plain_len,
                        void *cipher_text, uint32 *cipher_len);
status_t cm_kmc_decrypt(uint32 domain, const void *cipher_text, uint32 cipher_len, void *plain_text, uint32 *plain_len);
status_t cm_kmc_create_masterkey(uint32 domain, uint32 *keyid);
status_t cm_kmc_get_masterkey(uint32 domain, uint32 keyid, char *key_buf, uint32 *key_len);
status_t cm_kmc_active_masterkey(uint32 domain, uint32 keyid);
status_t cm_get_masterkey_count(uint32 *count);
status_t cm_get_masterkey_hash(uint32 domain, uint32 keyid, char *hash, uint32 *len);
status_t cm_get_masterkey_byhash(const char *hash, uint32 len, char *key, uint32 *key_len);
status_t cm_kmc_export_keyfile(char *dst_keyfile);
status_t cm_kmc_get_max_mkid(uint32 domain, uint32 *max_id);

void cm_kmc_set_aes_key_with_config(aes_and_kmc_t *aes_kmc, config_t *config);
void cm_kmc_set_aes_key(aes_and_kmc_t *aes_kmc, char *fator, char *local);
void cm_kmc_set_aes_new_key(aes_and_kmc_t *aes_kmc, char *fator_new, char *local_new);
void cm_kmc_set_aes_key_with_new(aes_and_kmc_t *aes_kmc, char *fator, char *local, char *fator_new, char *local_new);

void cm_kmc_set_kmc(aes_and_kmc_t *aes_kmc, uint32 kmc_domain, encrypt_version_t kmc_ver);
void cm_kmc_set_buf(aes_and_kmc_t *aes_kmc, char *plain, uint32 plain_len, char *cipher, uint32 cipher_len);
status_t cm_kmc_encrypt_pwd(aes_and_kmc_t *aes_kmc);
status_t cm_kmc_decrypt_pwd(aes_and_kmc_t *aes_kmc);
status_t cm_aes_to_kmc(aes_and_kmc_t *aes_kmc);
status_t cm_aes_may_to_aes_new(aes_and_kmc_t *aes_kmc);
status_t cm_aes_may_to_kmc(aes_and_kmc_t *aes_kmc);
status_t cm_kmc_to_aes(aes_and_kmc_t *aes_kmc);
status_t cm_encrypt_passwd_with_key(aes_and_kmc_t *aes_kmc);
status_t cm_decrypt_passwd_with_key(aes_and_kmc_t *aes_kmc);
status_t cm_encrypt_passwd_with_key_by_kmc(aes_and_kmc_t *aes_kmc);
status_t cm_decrypt_passwd_with_key_by_kmc(aes_and_kmc_t *aes_kmc);

#ifdef __cplusplus
}
#endif

#endif
