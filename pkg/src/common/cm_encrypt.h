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
 * cm_encrypt.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_encrypt.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_ENCRYPT_H__
#define __CM_ENCRYPT_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "openssl/evp.h"
#include "openssl/ssl.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum e_cipheralg {
    E_ALG_AES_256_CBC,
    E_ALG_SHA1,
    E_ALG_HMAC_SHA256,
    E_ALG_SHA256,
    E_ALG_PBKDF2,
    E_ALG_SCRAM_SHA256,
    E_ALG_BUTT
} cipher_alg_type;

#define CT_MAX_WORK_KEY_CLEAR_LEN       64
#define CT_MAX_LOCAL_KEY_STR_LEN        24
#define CT_MAX_FACTOR_KEY_STR_LEN       24
#define CT_MAX_LOCAL_KEY_STR_LEN_DOUBLE 88  // local key ��˫����Կʱ�ĳ���
#define CT_MAX_CIPHER_LEN               128
#define CT_AESBLOCKSIZE                 16
#define CT_AES256KEYSIZE                32
#define CT_HMAC256SALTSIZE              16
#define CT_HMAC256MAXSIZE               32 // IPSI_HMAC_SHA256_SIZE
#define CT_HMAC256MAXSTRSIZE            64 // ((HMAC256SALTSIZE+HMAC256MAXSIZE )/3*4
#define CT_KDF2KEYSIZE                  32
#define CT_KDF2SALTSIZE                 16
#define CT_KDF2SALTSIZE_DOUBLE          16 // ˫����Կ��ȡ��ʼ��Կʱ����ֵ����
#define CT_KDF2MAXSTRSIZE               64 // ((KDF2SALTSIZE+KDF2KEYSIZE )/3*4
#define CT_MAX_SHA1_BINLEN              20
#define CT_MAX_CHALLENGE_LEN            32
#define CT_ENCRYPTION_SIZE              512
#define CT_SCRAM256KEYSIZE              64  // stored_key+server_key
#define CT_SCRAM256HEADSIZE             8   // rand(4)+alg(2)+iter(2)
#define CT_SCRAM256MAXSIZE              88  // CT_SCRAM256HEADSIZE+CT_KDF2SALTSIZE+CT_SCRAM256KEYSIZE
#define CT_SCRAM256MAXSTRSIZE           128 // (KDF2SALTSIZE+CT_SCRAM256KEYSIZE)/3*4
#define CT_CLIENT_KEY                   "Zenith_Client_Key"
#define CT_SERVER_KEY                   "Zenith_Server_Key"
#ifdef _DEBUG
#define CT_KDF2MINITERATION             1000
#define CT_KDF2MAXITERATION             10000000
#define CT_KDF2DEFITERATION             10000
#else
#define CT_KDF2MINITERATION             1000
#define CT_KDF2MAXITERATION             20000000
#define CT_KDF2DEFITERATION             1000000
#endif
#define CT_AES_PWD_ADD_SPACE_LEN        4
#define CT_EVP_MAX_IV_LENGTH            12

typedef struct st_cm_encrypt_ctrl {
    bool32 is_init;
    cipher_alg_type alg_type;
    uchar key[CT_AES256KEYSIZE];
    int key_len;
    pointer_t evp_cipher;
} cm_encrypt_ctrl;

typedef struct st_scram_data {
    uchar padding[4];
    uint8 alg_id;
    uint8 iter_hi;  // high 8-bits of iteration, to support _ENCRYPTION_ITERATION up to 10000000
    uint16 iter_lo; // low 16-bits of iteration, keep compatible with previous version
    uchar salt[CT_KDF2SALTSIZE];
    uchar stored_key[CT_HMAC256MAXSIZE];
    uchar server_key[CT_HMAC256MAXSIZE];
} scram_data_t;

typedef struct st_salt_cipher {
    uchar *salted_pwd;
    uint32 salted_pwd_len;
    char *cipher;
    uint32 cipher_len;
} salt_cipher_t;

typedef struct st_gcm_encrypt {
    char gcm_iv[CT_EVP_MAX_IV_LENGTH];
    char gcm_salt[CT_KDF2SALTSIZE];
    char gcm_tag[EVP_GCM_TLS_TAG_LEN];
    EVP_CIPHER_CTX *gcm_ctx;
} gcm_encrypt_t;

#define CM_GET_ITERATION(scram_data)    \
    ((((uint32)(scram_data)->iter_hi) << 16) | ((uint32)(scram_data)->iter_lo & 0xFFFF))

#define CM_SET_ITERATION(scram_data, iter)                            \
    do {                                                              \
        (scram_data)->iter_lo = (uint16)((iter) & (uint32)0xFFFF);    \
        (scram_data)->iter_hi = (uint8)(((iter) >> 16) & 0xFF);       \
    } while (0)

uint32 cm_base64_encode_len(uint32 length);
uint32 cm_base64_decode_len(const char *src);

status_t cm_base64_encode(uchar *src, uint32 src_len, char *cipher, uint32 *cipher_len);
uint32 cm_base64_decode(const char *src, uint32 src_len, uchar *dest_data, uint32 buff_len);

status_t cm_rand(uchar *buf, uint32 len);
status_t cm_encrypt_HMAC(uchar *key, uint32 key_len, uchar *plain, uint32 plain_len, uchar *cipher,
                         uint32 *cipher_len);
status_t cm_encrypt_KDF2(uchar *plain, uint32 plain_len, uchar *salt, uint32 salt_len, uint32 iter_count,
                         uchar *str_KDF2, uint32 str_len);
status_t cm_generate_kdf2(char *plain, uint32 plain_len, uchar *cipher, uint32 *cipher_len);
status_t cm_generate_scram_sha256(char *plain, uint32 plain_len, uint32 iter_count, uchar *cipher,
                                  uint32 *cipher_len);
status_t cm_convert_kdf2_scram_sha256(const char *kdf2_str, char *scram_str, uint32 scram_buf_len);
status_t cm_generate_sha1(char *plain, uint32 plain_len, uchar *cipher, uint32 *cipher_len);
status_t cm_generate_sha256(uchar *plain, uint32 plain_len, uchar *cipher, uint32 *cipher_len);

/*
  @\brief check whether input str is valid scram_sha256 cipher
  @\parval pwd str cipher
  @\retval CT_TRUE if valid
*/
bool32 cm_is_password_valid(const char *sys_pwd);

/*
  @\brief verify login user pwd
  @\parval plain plain pwd
  @\parval cipher db stored pwd cipher
  @\retval CT_SUCCESS if success
*/
status_t cm_check_password(text_t *plain_password, text_t *cipher_password);

/*
 @\brief check user plain pwd
 @\parval c_cipher client proof data
 @\parval s_cipher db stored pwd
 @\retval CT_SUCCESS if success
*/
status_t cm_verify_password(text_t *c_cipher, const text_t *s_cipher);

/*
 @\brief Generate a random work key by factor key
 @\param [in] factor_key factor key base64 encoded cipher
 @\param [out] work_key buffer to store work key
 @\param [in] workkey_len work key buffer length
 @\retval CT_SUCCESS if success, CT_ERROR if failure
*/
status_t cm_generate_work_key(const char *fkey, char *wkey, uint32 wkey_len);

status_t cm_decrypt_passwd(bool32 is_double_enc, const char *cipher_str, uint32 cipher_len,
    char *plain_str_buf, uint32 *plain_str_len, const char *local_key, const char *factor_key_str);

status_t cm_encrypt_passwd(bool32 is_double_enc, char *plain_str_buf, uint32 plain_str_len, char *cipher_str,
                           uint32 *cipher_len, const char *local_key_str, const char *factor_key_str);

status_t cm_generate_repl_key(char *fkey, uint32 flen, char *wkey, uint32 wlen);
status_t cm_generate_repl_cipher(const char *plain, const char *fkey, const char *wkey, char *cipher, uint32 clen);
status_t cm_pwd_fetch_plain(const char *path, char *buf, uint32 buf_len);
status_t cm_pwd_store_keys(const char *path, const char *cipher, const char *fkey, const char *wkey);
status_t cm_pwd_read_file(const char *path, const char *name, char *buf, uint32 len);

status_t cm_encrypt_data_by_gcm(EVP_CIPHER_CTX *ctx, char *out_buf, const char *in_buf, int32 in_bufsize);
status_t cm_encrypt_end_by_gcm(EVP_CIPHER_CTX *ctx, char *out_buf);
status_t cm_decrypt_data_by_gcm(EVP_CIPHER_CTX *ctx, char *out_buf, const char *in_buf, int32 in_bufsize);
status_t cm_dencrypt_end_by_gcm(EVP_CIPHER_CTX *ctx, char *out_buf);
#ifdef __cplusplus
}
#endif

#endif

