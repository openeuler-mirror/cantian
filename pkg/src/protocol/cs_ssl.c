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
 * cs_ssl.c
 *
 *
 * IDENTIFICATION
 * src/protocol/cs_ssl.c
 *
 * -------------------------------------------------------------------------
 */
#include "cs_ssl.h"
#include "ssl.h"
#include "err.h"
#include "cs_pipe.h"
#include "cm_signal.h"
#include "cm_file.h"
#include "x509v3.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GS_SSL_FREE_CTX_AND_RETURN(err, ctx, ret)                         \
    do {                                                                  \
        GS_THROW_ERROR(ERR_SSL_INIT_FAILED, cs_ssl_init_err_string(err)); \
        SSL_CTX_free(ctx);                                                \
        return ret;                                                       \
    } while (0)

#define GS_SSL_EMPTY_STR_TO_NULL(str)        \
    if ((str) != NULL && (str)[0] == '\0') { \
        (str) = NULL;                        \
    }

#define SSL_CTX_PTR(ctx) ((SSL_CTX*)(ctx))
#define SSL_SOCK(sock)   ((SSL*)(sock))
#define SSL_VERIFY_DEPTH 10

static spinlock_t g_ssl_init_lock = 0;
static volatile bool32 g_ssl_initialized = 0;
static spinlock_t g_get_pem_passwd_lock = 0;

const char *g_ssl_default_cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384:"
                                        "ECDHE-ECDSA-AES128-GCM-SHA256:"
                                        "ECDHE-RSA-AES256-GCM-SHA384:"
                                        "ECDHE-RSA-AES128-GCM-SHA256:"
                                        "DHE-RSA-AES256-GCM-SHA384:"
                                        "DHE-RSA-AES128-GCM-SHA256:"
                                        "DHE-DSS-AES256-GCM-SHA384:"
                                        "DHE-DSS-AES128-GCM-SHA256:"
                                        "DHE-RSA-AES256-CCM:"
                                        "DHE-RSA-AES128-CCM";

const char *g_ssl_tls13_default_cipher_list = "TLS_AES_256_GCM_SHA384:"
                                              "TLS_CHACHA20_POLY1305_SHA256:"
                                              "TLS_AES_128_GCM_SHA256:"
                                              "TLS_AES_128_CCM_8_SHA256:"
                                              "TLS_AES_128_CCM_SHA256";

const char *g_ssl_cipher_names[] = {
    // GCM
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-DSS-AES256-GCM-SHA384",
    "DHE-DSS-AES128-GCM-SHA256",
    // CCM
    "DHE-RSA-AES256-CCM",
    "DHE-RSA-AES128-CCM",
    NULL
};

const char *g_ssl_tls13_cipher_names[] = {
    // TLS1.3
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
    "TLS_AES_128_CCM_SHA256",
    // TERM
    NULL
};

typedef enum en_ssl_init_error {
    SSL_INITERR_NONE = 0,
    SSL_INITERR_CERT,
    SSL_INITERR_KEY,
    SSL_INITERR_KEYPWD,
    SSL_INITERR_NOMATCH,
    SSL_INITERR_LOAD_CA,
    SSL_INITERR_LOAD_CRL,
    SSL_INITERR_CIPHERS,
    SSL_INITERR_MEMFAIL,
    SSL_INITERR_NO_USABLE_CTX,
    SSL_INITERR_DHFAIL,
    SSL_INITERR_VERIFY,
    SSL_INITERR_VERSION_INVALID,
    SSL_INITERR_SIGNATURE_ALG,
    SSL_INITERR_SET_PURPOSE,
    SSL_INITERR_LASTERR
} ssl_init_error_t;

static const char *ssl_error_string[] = {
    "No error",
    "Unable to get certificate",
    "Unable to get private key",
    "Private key password is invalid",
    "Private key does not match the certificate public key",
    "Load CA certificate file failed",
    "Load Certificate revocation list failed",
    "Failed to set ciphers to use",
    "Create new SSL_CTX failed",
    "SSL context is not usable without certificate and private key",
    "SSL_CTX_SET_TEMPDH failed",
    "SSL set verify mode or depth failed",
    "TLS version is invalid",
    "Failed to set signature algorithms",
    "SSL_CTX_set_purpose failed",
    "",
};

static const char *cs_ssl_init_err_string(ssl_init_error_t err)
{
    if (err > SSL_INITERR_NONE && err < SSL_INITERR_LASTERR) {
        return ssl_error_string[err];
    }
    return ssl_error_string[0];
}

/*
  Get the last SSL error code and reason
*/
static const char *cs_ssl_last_err_string(char *buf, uint32 size)
{
    buf[0] = '\0';

    ulong err = ERR_get_error();
    if (err) {
        const char *fstr = ERR_func_error_string(err);
        const char *rstr = ERR_reason_error_string(err);

        if (snprintf_s(buf, size, size - 1, "error code = %lu, reason code = %d, ssl function = %s:%s ",
            err, ERR_GET_REASON(err), (fstr ? fstr : "<null>"), (rstr ? rstr : "<null>")) == -1) {
            return buf;
        }
    }
    return buf;
}

/*
Diffie-Hellman key.
Generated using: >openssl dhparam -5 -C 3072
*/
static unsigned char g_dh3072_p[] = {
    0x8D,
    0xAF,
    0xE5,
    0xD7,
    0x9A,
    0x0A,
    0x6A,
    0x9A,
    0xF0,
    0x7F,
    0xF2,
    0xBD,
    0xC2,
    0xE5,
    0x4B,
    0x56,
    0x07,
    0x3F,
    0x81,
    0x02,
    0x0E,
    0x64,
    0xC9,
    0xA4,
    0xA0,
    0x49,
    0x78,
    0xE8,
    0x4C,
    0xD0,
    0x8E,
    0xD7,
    0x1F,
    0x71,
    0xC7,
    0x97,
    0x3F,
    0x5D,
    0x42,
    0x7D,
    0x9F,
    0xC3,
    0x1C,
    0x69,
    0x8C,
    0x81,
    0xA3,
    0x5C,
    0x18,
    0xCA,
    0xED,
    0xBC,
    0xA0,
    0x82,
    0xD8,
    0x01,
    0x78,
    0x6E,
    0x64,
    0xAC,
    0x4A,
    0xB2,
    0x2C,
    0x74,
    0xC1,
    0x8C,
    0x66,
    0x13,
    0xBE,
    0xC8,
    0x7F,
    0x32,
    0x3D,
    0x68,
    0xA5,
    0x12,
    0x98,
    0x86,
    0x86,
    0x3E,
    0xDA,
    0x20,
    0x62,
    0x5F,
    0x47,
    0xDC,
    0x8B,
    0xF6,
    0xF4,
    0x37,
    0xF6,
    0x0A,
    0x9C,
    0xF9,
    0x10,
    0xE9,
    0x5D,
    0x82,
    0xE3,
    0x41,
    0xC1,
    0x9C,
    0x7A,
    0xA3,
    0x77,
    0x54,
    0x28,
    0x6F,
    0x76,
    0xF6,
    0xD5,
    0x29,
    0xCB,
    0x8D,
    0xA8,
    0x18,
    0x51,
    0xCA,
    0xE5,
    0xB3,
    0xF2,
    0xCF,
    0xDA,
    0xB5,
    0x26,
    0x6E,
    0xA5,
    0xB5,
    0x22,
    0x12,
    0x2C,
    0xFC,
    0x53,
    0xAA,
    0x16,
    0xD8,
    0x74,
    0x79,
    0x17,
    0x83,
    0x54,
    0xE8,
    0x40,
    0xC0,
    0x1C,
    0x9E,
    0x95,
    0x7D,
    0x87,
    0x46,
    0x8D,
    0x2F,
    0xA4,
    0x8C,
    0x48,
    0x43,
    0x3C,
    0xC8,
    0x50,
    0x7C,
    0x14,
    0x9A,
    0x5B,
    0x00,
    0xFF,
    0xA0,
    0x7E,
    0x76,
    0xD2,
    0x0E,
    0x97,
    0x56,
    0x2E,
    0xEB,
    0x03,
    0x20,
    0xAC,
    0x41,
    0x61,
    0x73,
    0xB8,
    0x7A,
    0x9F,
    0x07,
    0xDB,
    0xA5,
    0x4F,
    0x20,
    0x3D,
    0x9D,
    0x01,
    0x7C,
    0x06,
    0x56,
    0x3E,
    0xA1,
    0x18,
    0x22,
    0xB9,
    0x36,
    0x1D,
    0x80,
    0xD3,
    0xC5,
    0x9B,
    0x4F,
    0x03,
    0x99,
    0x72,
    0x1A,
    0x86,
    0xC6,
    0x82,
    0xC9,
    0x87,
    0x75,
    0x9A,
    0xF9,
    0xFA,
    0xC1,
    0x6F,
    0x71,
    0x0E,
    0x83,
    0x80,
    0x3B,
    0x1E,
    0x92,
    0xA5,
    0x7D,
    0xB3,
    0x82,
    0xB0,
    0xB9,
    0x92,
    0x08,
    0x40,
    0x32,
    0x50,
    0xEE,
    0x95,
    0x08,
    0x48,
    0x4C,
    0x0A,
    0x2D,
    0x88,
    0x82,
    0x94,
    0x1A,
    0x47,
    0x22,
    0xE2,
    0x98,
    0x0B,
    0x80,
    0x22,
    0xBB,
    0x65,
    0x7C,
    0x45,
    0x63,
    0xC9,
    0xF4,
    0xC1,
    0x90,
    0x89,
    0xBE,
    0x61,
    0x3A,
    0x88,
    0xF4,
    0x3A,
    0x24,
    0xE2,
    0x7E,
    0x0D,
    0xF1,
    0x4C,
    0xFF,
    0x47,
    0xF9,
    0x7E,
    0xFA,
    0x1D,
    0xE4,
    0x59,
    0x43,
    0xFD,
    0xDE,
    0x0F,
    0xF5,
    0x36,
    0x9E,
    0x36,
    0x63,
    0x54,
    0x9A,
    0x6C,
    0xB1,
    0xDD,
    0x65,
    0x2F,
    0x11,
    0xF4,
    0x89,
    0xC6,
    0xD2,
    0x21,
    0x1A,
    0x2E,
    0x5A,
    0x2B,
    0x8B,
    0x26,
    0xDF,
    0x5B,
    0x68,
    0x6A,
    0xF3,
    0xFE,
    0xA7,
    0x3D,
    0x2F,
    0x1D,
    0x45,
    0xFB,
    0xAE,
    0xE2,
    0x98,
    0x78,
    0x2F,
    0xB8,
    0x74,
    0x94,
    0x87,
    0x3A,
    0x6B,
    0x1A,
    0xB4,
    0x45,
    0xB5,
    0xAA,
    0x13,
    0x3E,
    0xDD,
    0x70,
    0x49,
    0x6F,
    0x97,
    0x78,
    0x9B,
    0xDA,
    0xED,
    0xF1,
    0x6B,
    0x33,
    0x76,
    0x49,
    0xEE,
    0xB3,
    0xFF,
    0xF2,
    0x14,
    0x12,
    0xB4,
    0xE3,
    0xEE,
    0xE5,
    0xB0,
    0xA7,
    0x0B,
    0xDA,
    0xFA,
    0x5B,
    0x22,
    0xCF,
    0x61,
    0xBF,
    0x26,
    0x78,
    0x72,
    0x7B,
    0x1B,
};

static unsigned char g_dh3072_g[] = {
    0x05,
};

/* function to generate DH key pair */
static DH *get_dh3072(void)
{
    DH *dh_key;
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;

    dh_key = DH_new();
    if (dh_key == NULL) {
        return NULL;
    }

    p = BN_bin2bn(g_dh3072_p, sizeof(g_dh3072_p), NULL);
    g = BN_bin2bn(g_dh3072_g, sizeof(g_dh3072_g), NULL);
    if ((p == NULL) || (g == NULL) || !DH_set0_pqg(dh_key, p, NULL, g)) {
        DH_free(dh_key);
        BN_free(p);
        BN_free(g);
        return NULL;
    }

    return dh_key;
}

/**
* Callback function for get PEM info for SSL, add thread lock protect call for 'PEM_def_callback'.
*/
static int32 cs_ssl_cb_get_pem_passwd(char *buf, int size, int rwflag, void *userdata)
{
    int32 ret;
    if (userdata == NULL) {
        cm_spin_lock(&g_get_pem_passwd_lock, NULL);
        ret = PEM_def_callback(buf, size, rwflag, userdata);
        cm_spin_unlock(&g_get_pem_passwd_lock);
    } else {
        ret = PEM_def_callback(buf, size, rwflag, userdata);
    }
    return ret;
}

static status_t cs_ssl_init(void)
{
    if (g_ssl_initialized) {
        return GS_SUCCESS;
    }

    cm_spin_lock(&g_ssl_init_lock, NULL);

    if (g_ssl_initialized) {
        cm_spin_unlock(&g_ssl_init_lock);
        return GS_SUCCESS;
    }

    if (OPENSSL_init_ssl(OPENSSL_INIT_SSL_DEFAULT, NULL) == 0) {
        cm_spin_unlock(&g_ssl_init_lock);
        GS_THROW_ERROR(ERR_SSL_INIT_FAILED, "Init SSL library failed");
        return GS_ERROR;
    }

    g_ssl_initialized = GS_TRUE;
    cm_spin_unlock(&g_ssl_init_lock);
    return GS_SUCCESS;
}

static void cs_ssl_deinit(void)
{
    if (!g_ssl_initialized) {
        return;
    }
}

/**
 * Obtain the equivalent system error status for the last SSL I/O operation.
 *
 * @param ssl_err  The result code of the failed TLS/SSL I/O operation.
 */
static void cs_ssl_set_sys_error(int32 ssl_err)
{
    int32 error = 0;
    switch (ssl_err) {
        case SSL_ERROR_ZERO_RETURN:
            error = ECONNRESET;
            break;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
            error = EWOULDBLOCK;
            break;
        case SSL_ERROR_SSL:
        /* Protocol error */
#ifdef EPROTO
            error = EPROTO;
#else
            error = ECONNRESET;
#endif
            break;
        default:
            error = ECONNRESET;
            break;
    }
    /* Set error status to equivalent of the SSL error */
    if (error != 0) {
        cm_set_sock_error(error);
    }
}

static status_t cs_ssl_match_cipher(text_t left, char *cipher, uint32_t *offset, bool32 *support, bool32 is_tls13)
{
    uint32 i, count;
    errno_t errcode;
    const char** cipher_list;
    if (is_tls13) {
        count = ELEMENT_COUNT(g_ssl_tls13_cipher_names) - 1;
        cipher_list = g_ssl_tls13_cipher_names;
    } else {
        count = ELEMENT_COUNT(g_ssl_cipher_names) - 1;
        cipher_list = g_ssl_cipher_names;
    }

    for (i = 0; i < count; i++) {
        if (cm_text_str_equal_ins(&left, cipher_list[i])) {
            *support = GS_TRUE;
            if (*offset > 0) {
                // join ":"
                errcode = strncpy_s(cipher + *offset, GS_MAX_SSL_CIPHER_LEN - *offset, ":", strlen(":"));
                if (errcode != EOK) {
                    GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
                    return GS_ERROR;
                }
                *offset += 1;
            }
            errcode = strncpy_s(cipher + *offset, GS_MAX_SSL_CIPHER_LEN - *offset, left.str, left.len);
            if (errcode != EOK) {
                GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
                return GS_ERROR;
            }
            *offset += left.len;
            break;
        }
    }

    return GS_SUCCESS;
}

static status_t cs_ssl_distinguish_cipher(const char *cipher, char *tls12_cipher, uint32_t *tls12_offset,
                                          char *tls13_cipher, uint32_t *tls13_offset)
{
    bool32 support = GS_FALSE;
    text_t text, left, right;
    cm_str2text((char *)cipher, &text);
    cm_split_text(&text, ':', '\0', &left, &right);
    text = right;

    while (left.len > 0) {
        support = GS_FALSE;
        // match TLS1.2-cipher
        if (cs_ssl_match_cipher(left, tls12_cipher, tls12_offset, &support, GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (!support) {
            // match TLS1.3-cipher
            if (cs_ssl_match_cipher(left, tls13_cipher, tls13_offset, &support, GS_TRUE) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
        /* cipher not supported or invalid */
        if (support != GS_TRUE) {
            return GS_ERROR;
        }
        cm_split_text(&text, ':', '\0', &left, &right);
        text = right;
    }

    return GS_SUCCESS;
}

static status_t cs_ssl_set_cipher(SSL_CTX *ctx, ssl_config_t *config, bool32* is_using_tls13)
{
    char tls12_cipher[GS_MAX_SSL_CIPHER_LEN] = { 0 };
    char tls13_cipher[GS_MAX_SSL_CIPHER_LEN] = { 0 };
    uint32_t tls12_len = 0;
    uint32_t tls13_len = 0;
    const char *tls12_cipher_str = NULL;
    const char *tls13_cipher_str = NULL;

    if (!CM_IS_EMPTY_STR(config->cipher)) {
        if (cs_ssl_distinguish_cipher(config->cipher, tls12_cipher, &tls12_len, tls13_cipher, &tls13_len) !=
            GS_SUCCESS) {
            return GS_ERROR;
        }

        if (tls12_len > 0) {
            tls12_cipher_str = tls12_cipher;
        } else {
            tls12_cipher_str = g_ssl_default_cipher_list;
        }
        
        if (tls13_len > 0) {
            *is_using_tls13 = GS_TRUE;
            tls13_cipher_str = tls13_cipher;
        } else {
            tls13_cipher_str = g_ssl_tls13_default_cipher_list;
        }
    } else {
        /* load default cipher list if SSL_CIPHER is not specified */
        tls12_cipher_str = g_ssl_default_cipher_list;
        tls13_cipher_str = g_ssl_tls13_default_cipher_list;
        *is_using_tls13 = GS_TRUE;
    }

    if (tls12_cipher_str != NULL && 1 != SSL_CTX_set_cipher_list(ctx, tls12_cipher_str)) {
        return GS_ERROR;
    }

    if (tls13_cipher_str != NULL && 1 != SSL_CTX_set_ciphersuites(ctx, tls13_cipher_str)) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static inline void cs_ssl_fetch_file_name(text_t *files, text_t *name)
{
    if (!cm_fetch_text(files, ',', '\0', name)) {
        return;
    }

    cm_trim_text(name);
    if (name->str[0] == '\'') {
        name->str++;
        name->len -= 2;
        cm_trim_text(name);
    }
}

static status_t cs_ssl_set_ca_chain(SSL_CTX *ctx, ssl_config_t *config, bool32 is_client)
{
    text_t file_list, file_name;
    char filepath[GS_FILE_NAME_BUFFER_SIZE];

    if (config->ca_file != NULL) {
        cm_str2text((char *)config->ca_file, &file_list);
        cm_remove_brackets(&file_list);

        cs_ssl_fetch_file_name(&file_list, &file_name);
        while (file_name.len > 0) {
            GS_RETURN_IFERR(cm_text2str(&file_name, filepath, sizeof(filepath)));

            if (cs_ssl_verify_file_stat(filepath) != GS_SUCCESS) {
                if (!is_client) {
                    CM_ABORT(0, "SSL CA certificate file \"%s\" has execute, group or world access permission", filepath);
                }

                return GS_ERROR;
            }

            if (SSL_CTX_load_verify_locations(ctx, (const char *)filepath, NULL) == 0) {
                return GS_ERROR;
            }

            cs_ssl_fetch_file_name(&file_list, &file_name);
        }
    }

    return GS_SUCCESS;
}

static status_t cs_load_crl_file(SSL_CTX *ctx, const char *file)
{
    long ret;
    BIO *in = NULL;
    X509_CRL *crl = NULL;
    X509_STORE *st = NULL;

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        return GS_ERROR;
    }

    if (BIO_read_filename(in, file) <= 0) {
        (void)BIO_free(in);
        return GS_ERROR;
    }

    crl = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
    if (crl == NULL) {
        (void)BIO_free(in);
        return GS_ERROR;
    }

    st = SSL_CTX_get_cert_store(ctx);
    if (!X509_STORE_add_crl(st, crl)) {
        X509_CRL_free(crl);
        (void)BIO_free(in);
        return GS_ERROR;
    }

    ret = SSL_CTX_set1_verify_cert_store(ctx, st);
    X509_CRL_free(crl);
    (void)BIO_free(in);

    return ret == 1 ? GS_SUCCESS : GS_ERROR;
}

static status_t cs_ssl_set_crl_file(SSL_CTX *ctx, ssl_config_t *config)
{
    text_t file_list, file_name;
    char filepath[GS_FILE_NAME_BUFFER_SIZE];

    if (config->crl_file != NULL) {
        cm_str2text((char *)config->crl_file, &file_list);
        cm_remove_brackets(&file_list);

        cs_ssl_fetch_file_name(&file_list, &file_name);
        while (file_name.len > 0) {
            GS_RETURN_IFERR(cm_text2str(&file_name, filepath, sizeof(filepath)));
            if (cs_load_crl_file(ctx, filepath) != GS_SUCCESS) {
                return GS_ERROR;
            }

            cs_ssl_fetch_file_name(&file_list, &file_name);
        }

        /* Enable CRL checking when performing certificate verification during SSL connections
           associated with an SSL_CTX structure ctx */
        X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
        (void)X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK);

        if (!SSL_CTX_set1_param(ctx, param)) {
            X509_VERIFY_PARAM_free(param);
            return GS_ERROR;
        }

        X509_VERIFY_PARAM_free(param);
    }

    return GS_SUCCESS;
}

static void cs_ssl_throw_error(int32 ssl_err)
{
    char err_buf1[GS_MESSAGE_BUFFER_SIZE] = { 0 };
    char err_buf2[GS_MESSAGE_BUFFER_SIZE] = { 0 };
    uint32 err_len = 0;
    ulong ret_code;
    const char *file = NULL;
    const char *data = NULL;
    int32 line = 0;
    int32 flags = 0;
    int32 ret = 0;

    cs_ssl_set_sys_error(ssl_err);
    /* try get line data from ssl error queue */
    while ((ret_code = ERR_get_error_line_data(&file, &line, &data, &flags))) {
        ret = snprintf_s(err_buf1 + err_len, GS_MESSAGE_BUFFER_SIZE - err_len, GS_MESSAGE_BUFFER_SIZE - 1 - err_len,
            "OpenSSL:%s-%s-%d-%s", ERR_error_string(ret_code, err_buf2), file, line,
            ((uint32)flags & ERR_TXT_STRING) ? data : "");
        if (ret == -1) {
            break;
        }
        err_len = (uint32)strlen(err_buf1);
    }

    if (ret == -1) {
        GS_THROW_ERROR(ERR_SSL_RECV_FAILED, ssl_err, cm_get_sock_error(), err_buf1);
        return;
    }

    /* try get ssl last error if line data is null */
    do {
        if (err_len == 0) {
            const char *err_msg = cs_ssl_last_err_string(err_buf2, sizeof(err_buf2));
            ret = snprintf_s(err_buf1, GS_MESSAGE_BUFFER_SIZE, GS_MESSAGE_BUFFER_SIZE - 1, "%s", err_msg);
            if (ret == -1) {
                break;
            }
        }
    } while (0);
    
    GS_THROW_ERROR(ERR_SSL_RECV_FAILED, ssl_err, cm_get_sock_error(), err_buf1);
}

/**
    This function indicates whether the SSL I / O operation must be retried in the future,
    and clear the SSL error queue, so the next SSL operation can be performed even after
    the iPSI-SSL call fails.

    @param ssl  SSL connection.
    @param ret  a SSL I/O function.
    @param [out] event             The type of I/O event to wait/retry.
    @param [out] ssl_err_holder    The SSL error code.

    @return Whether the SSL I / O operation should be delayed.
    @retval true    Temporary failure, retry operation.
    @retval false   Indeterminate failure.
*/
static bool32 cs_ssl_should_retry(ssl_link_t *link, int32 ret, uint32 *wait_event, int32 *ssl_err_holder)
{
    int32 ssl_err;
    bool32 retry = GS_TRUE;
    SSL *ssl = SSL_SOCK(link->ssl_sock);

    /* Retrieve the result for the SSL I/O operation */
    ssl_err = SSL_get_error(ssl, ret);

    switch (ssl_err) {
        case SSL_ERROR_WANT_READ:
            *wait_event = CS_WAIT_FOR_READ;
            break;
        case SSL_ERROR_WANT_WRITE:
            *wait_event = CS_WAIT_FOR_WRITE;
            break;
        default:
            GS_LOG_DEBUG_ERR("SSL read/write failed. SSL error: %d", ssl_err);
            cs_ssl_throw_error(ssl_err);
            ERR_clear_error();
            retry = GS_FALSE;
            break;
    }
    
    if (ssl_err_holder != NULL) {
        (*ssl_err_holder) = ssl_err;
    }
    
    return retry;
}

static status_t cs_ssl_wait_on_error(ssl_link_t *link, int32 ret, int32 timeout)
{
    int32 ssl_err;
    long v_result;
    uint32 cs_event;
    bool32 is_ready = GS_FALSE;
    char err_buf[GS_BUFLEN_256] = {0};
    const char *err_msg = NULL;
    SSL *ssl = SSL_SOCK(link->ssl_sock);

    /* Retrieve the result for the SSL I/O operation */
    ssl_err = SSL_get_error(ssl, ret);

    switch (ssl_err) {
        case SSL_ERROR_NONE:
            return GS_SUCCESS;
        case SSL_ERROR_WANT_READ:
            cs_event = CS_WAIT_FOR_READ;
            break;
        case SSL_ERROR_WANT_WRITE:
            cs_event = CS_WAIT_FOR_WRITE;
            break;
        default:
            v_result = SSL_get_verify_result(ssl);
            if (v_result != X509_V_OK) {
                err_msg = X509_verify_cert_error_string(v_result);
                GS_LOG_RUN_ERR("SSL verify certificate failed: result code is %ld, %s", v_result, err_msg);
                GS_THROW_ERROR(ERR_SSL_VERIFY_CERT, err_msg);
            } else {
                err_msg = cs_ssl_last_err_string(err_buf, sizeof(err_buf));
                GS_THROW_ERROR(ERR_SSL_CONNECT_FAILED, err_msg);
                GS_LOG_RUN_ERR("SSL connect failed: SSL error %d, %s", ssl_err, err_msg);
            }
            (void)ERR_clear_error();
            cs_ssl_set_sys_error(ssl_err);
            return GS_ERROR;
    }

    /* Wait for SSL I/O operation */
    GS_RETURN_IFERR(cs_tcp_wait(&link->tcp, cs_event, timeout, &is_ready));

    return (is_ready ? GS_SUCCESS : GS_TIMEDOUT);
}

static status_t cs_ssl_resolve_file_name(const char *filename, char *buf, uint32 buf_len, const char **res_buf)
{
    text_t text;
    if (CM_IS_EMPTY_STR(filename) || filename[0] != '\'') {
        *res_buf = filename;
        return GS_SUCCESS;
    }
    cm_str2text((char *)filename, &text);
    CM_REMOVE_ENCLOSED_CHAR(&text);
    GS_RETURN_IFERR(cm_text2str(&text, buf, buf_len));
    *res_buf = buf;
    return GS_SUCCESS;
}

static status_t cs_ssl_set_cert_auth(SSL_CTX *ctx, const char *cert_file, const char *key_file,
                                     const char *key_pwd)
{
    char file_name[GS_FILE_NAME_BUFFER_SIZE];

    if (cert_file == NULL && key_file != NULL) {
        cert_file = key_file;
    }
    if (cert_file != NULL && key_file == NULL) {
        key_file = cert_file;
    }

    if (cert_file != NULL) {
        GS_RETURN_IFERR(cs_ssl_resolve_file_name(cert_file, file_name, sizeof(file_name), &cert_file));

        if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
            GS_SSL_FREE_CTX_AND_RETURN(SSL_INITERR_CERT, ctx, GS_ERROR);
        }
    }
    if (key_file != NULL) {
        GS_RETURN_IFERR(cs_ssl_resolve_file_name(key_file, file_name, sizeof(file_name), &key_file));

        if (!CM_IS_EMPTY_STR(key_pwd)) {
            SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)key_pwd);
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
            GS_SSL_FREE_CTX_AND_RETURN(SSL_INITERR_KEY, ctx, GS_ERROR);
        }
    }
    
    if (cert_file != NULL && SSL_CTX_check_private_key(ctx) != 1) {
        GS_SSL_FREE_CTX_AND_RETURN(SSL_INITERR_NOMATCH, ctx, GS_ERROR);
    }
    return GS_SUCCESS;
}

static status_t cs_ssl_set_tmp_dh(SSL_CTX *ctx)
{
    DH *dh = get_dh3072();
    if (dh == NULL) {
        return GS_ERROR;
    }

    if (SSL_CTX_set_tmp_dh(ctx, dh) == 0) {
        DH_free(dh);
        return GS_ERROR;
    }

    DH_free(dh);
    return GS_SUCCESS;
}

/**
 * create a new ssl context object.
 * @param [in]   ca_file      SSL CA file path
 * @param [in]   cert_file    SSL certificate file path
 * @param [in]   key_file     SSL private key file path
 * @param [in]   is_client    setting for ssl
 * @return  pointer to SSL_CTX on success, NULL on failure
 */
static SSL_CTX *cs_ssl_create_context(ssl_config_t *config, bool32 is_client)
{
    int purpose;
    bool32 is_using_tls13 = GS_FALSE;

    /* Init SSL library */
    GS_RETVALUE_IFTRUE(cs_ssl_init() != GS_SUCCESS, NULL);

    /* Set empty string to null */
    GS_SSL_EMPTY_STR_TO_NULL(config->ca_file);
    GS_SSL_EMPTY_STR_TO_NULL(config->cert_file);
    GS_SSL_EMPTY_STR_TO_NULL(config->key_file);
    GS_SSL_EMPTY_STR_TO_NULL(config->crl_file);

    SSL_CTX *ctx = NULL;
    const SSL_METHOD *method = NULL;

    /* Negotiate highest available SSL/TLS version */
    method = is_client ? TLS_client_method() : TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        GS_THROW_ERROR(ERR_SSL_INIT_FAILED, cs_ssl_init_err_string(SSL_INITERR_MEMFAIL));
        return NULL;
    }

    /* set peer cert's purpose */
    purpose = is_client ? X509_PURPOSE_SSL_SERVER : X509_PURPOSE_SSL_CLIENT;
    if (!SSL_CTX_set_purpose(ctx, purpose)) {
        GS_SSL_FREE_CTX_AND_RETURN(SSL_INITERR_SET_PURPOSE, ctx, NULL);
    }

    /* disable SSLv2, SSLv3, TLSv1.0 and TLSv1.1 */
    (void)SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    /*
      Disable moving-write-buffer sanity check, because it may causes
      unnecessary failures in non-blocking send cases.
     */
    (void)SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    /* setup PEM info callback. */
    SSL_CTX_set_default_passwd_cb(ctx, cs_ssl_cb_get_pem_passwd);

    /* When choosing a cipher, use the server's preferences instead of the client preferences */
    (void)SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

    /* Set available cipher suite */
    if (cs_ssl_set_cipher(ctx, config, &is_using_tls13) != GS_SUCCESS) {
        GS_SSL_FREE_CTX_AND_RETURN(SSL_INITERR_CIPHERS, ctx, NULL);
    }

    /* disable TLSv1.3 */
    if (!is_using_tls13) {
        (void)SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);
    }

    /* Support CA file chain */
    if (cs_ssl_set_ca_chain(ctx, config, is_client) != GS_SUCCESS) {
        GS_SSL_FREE_CTX_AND_RETURN(SSL_INITERR_LOAD_CA, ctx, NULL);
    }

    /* Load CRL */
    if (cs_ssl_set_crl_file(ctx, config) != GS_SUCCESS) {
        GS_SSL_FREE_CTX_AND_RETURN(SSL_INITERR_LOAD_CRL, ctx, NULL);
    }

    /* Verify cert and key files */
    GS_RETVALUE_IFTRUE(
        cs_ssl_set_cert_auth(ctx, config->cert_file, config->key_file, config->key_password) != GS_SUCCESS, NULL);

    /* Server specific check: Must have certificate and key file */
    if (!is_client && config->key_file == NULL && config->cert_file == NULL) {
        GS_SSL_FREE_CTX_AND_RETURN(SSL_INITERR_NO_USABLE_CTX, ctx, NULL);
    }

    /* DH stuff */
    if (cs_ssl_set_tmp_dh(ctx) != GS_SUCCESS) {
        GS_SSL_FREE_CTX_AND_RETURN(SSL_INITERR_DHFAIL, ctx, NULL);
    }

    /* ECDH stuff : ECDH is always enabled now in openssl 1.1.1 version, no need to set */
    return ctx;
}

/*
 * Certificate verification callback
 *
 * This callback allows us to log intermediate problems during
 * verification, but for now we'll see if the final error message
 * contains enough information.
 *
 * This callback also allows us to override the default acceptance
 * criteria(e.g. accepting self-signed or expired certs), but
 * for now we accept the default checks.
 *
 */
static int32 cs_ssl_verify_cb(int32 ok, X509_STORE_CTX *ctx)
{
    return ok;
}

int32 ssl_get_expire_day(const ASN1_TIME *ctm, time_t *curr_time)
{
    int day, sec;
    ASN1_TIME *asn1_cmp_time = NULL;

    asn1_cmp_time = X509_time_adj(NULL, 0, curr_time);
    if (asn1_cmp_time == NULL) {
        return -1;
    }

    if (!ASN1_TIME_diff(&day, &sec, asn1_cmp_time, ctm)) {
        return -1;
    }

    return day;
}

void ssl_check_cert_expire(X509 *cert, int32 alert_day, cert_type_t type)
{
    const ASN1_TIME *not_after = NULL;
    int32 expire_day;

    if (cert == NULL) {
        return;
    }

    not_after = X509_get0_notAfter(cert);
    if (X509_cmp_current_time(not_after) <= 0) {
        GS_LOG_RUN_WAR("The %s is expired", type == CERT_TYPE_SERVER_CERT ? "server certificate" : "ca");
    } else {
        time_t curr_time = cm_current_time();
        expire_day = ssl_get_expire_day(not_after, &curr_time);
        if (expire_day >= 0 && alert_day >= expire_day) {
            GS_LOG_RUN_WAR("The %s will expire in %d days", type == CERT_TYPE_SERVER_CERT ? "server certificate" : "ca",
                           expire_day);
        }
    }
}

void ssl_ca_cert_expire(const ssl_ctx_t *ssl_context, int32 alert_day)
{
    SSL_CTX *ctx = SSL_CTX_PTR(ssl_context);
    X509 *cert = NULL;
    X509_STORE *cert_store = NULL;
    X509_OBJECT *obj = NULL;

    if (ssl_context == NULL) {
        return;
    }

    cert = SSL_CTX_get0_certificate(ctx);
    if (cert != NULL) {
        ssl_check_cert_expire(cert, alert_day, CERT_TYPE_SERVER_CERT);
    }

    cert_store = SSL_CTX_get_cert_store(ctx);
    if (cert_store == NULL) {
        return;
    }

    STACK_OF(X509_OBJECT)* objects = X509_STORE_get0_objects(cert_store);
    for (int i = 0; i < sk_X509_OBJECT_num(objects); i++) {
        obj = sk_X509_OBJECT_value(objects, i);
        /* only check for CA certificate, no need for CRL */
        if (X509_OBJECT_get_type(obj) == X509_LU_X509) {
            cert = X509_OBJECT_get0_X509(obj);
            ssl_check_cert_expire(cert, alert_day, CERT_TYPE_CA_CERT);
        }
    }

    return;
}

ssl_ctx_t *cs_ssl_create_acceptor_fd(ssl_config_t *config)
{
    SSL_CTX *ssl_fd = NULL;
    int32 verify = SSL_VERIFY_PEER;

    /* Cannot verify peer if the server don't have the CA */
    if (CM_IS_EMPTY_STR(config->ca_file)) {
        verify = SSL_VERIFY_NONE;
    } else if (config->verify_peer) {
        verify = (uint32)verify | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }

    ssl_fd = cs_ssl_create_context(config, GS_FALSE);
    if (ssl_fd == NULL) {
        return NULL;
    }

    /* Init the SSL_CTX as a "acceptor" ie. the server side
       Set max number of cached sessions, returns the previous size */
    (void)SSL_CTX_sess_set_cache_size(ssl_fd, GS_BUFLEN_128);

    /* Set maximum verify depth */
    SSL_CTX_set_verify(ssl_fd, verify, cs_ssl_verify_cb);
    SSL_CTX_set_verify_depth(ssl_fd, SSL_VERIFY_DEPTH);

    /*
      Set session_id - an identifier for this server session
    */
    (void)SSL_CTX_set_session_id_context(ssl_fd, (const uchar *)&ssl_fd, sizeof(ssl_fd));
    return (ssl_ctx_t *)ssl_fd;
}

ssl_ctx_t *cs_ssl_create_connector_fd(ssl_config_t *config)
{
    SSL_CTX *ssl_fd = NULL;
    int32 verify = SSL_VERIFY_PEER;

    /*
      Turn off verification of servers certificate if both
      ca_file and ca_path is set to NULL
    */
    if (CM_IS_EMPTY_STR(config->ca_file)) {
        verify = SSL_VERIFY_NONE;
    }
    
    ssl_fd = cs_ssl_create_context(config, GS_TRUE);
    if (ssl_fd == NULL) {
        return NULL;
    }

    /* Init the SSL_CTX as a "connector" ie. the client side */
    SSL_CTX_set_verify(ssl_fd, verify, NULL);
    SSL_CTX_set_verify_depth(ssl_fd, SSL_VERIFY_DEPTH);

    return (ssl_ctx_t *)ssl_fd;
}

void cs_ssl_free_context(ssl_ctx_t *ctx)
{
    SSL_CTX_free(SSL_CTX_PTR(ctx));
    cs_ssl_deinit();
}

static SSL *cs_ssl_create_socket(SSL_CTX *ctx, socket_t sock)
{
    SSL *ssl_sock = SSL_new(ctx);
    if (ssl_sock == NULL) {
        GS_THROW_ERROR(ERR_SSL_INIT_FAILED, "Create SSL socket failed");
        return NULL;
    }
    (void)SSL_clear(ssl_sock);
    if (SSL_set_fd(ssl_sock, (int)sock) == 0) {
        SSL_free(ssl_sock);
        return NULL;
    }
    return ssl_sock;
}


static char *get_common_name(X509_NAME *cert_name, char *buf, uint32 len)
{
    char *name = NULL;
    int32 cn_loc;
    ASN1_STRING *cn_asn1 = NULL;
    X509_NAME_ENTRY *cn_entry = NULL;
    errno_t errcode;

    // find cn location in the subject
    cn_loc = X509_NAME_get_index_by_NID(cert_name, NID_commonName, -1);
    if (cn_loc < 0) {
        GS_LOG_DEBUG_ERR("[SSL] failed to get CN location in the certificate subject");
        return "NONE";
    }
    // get cn entry for given location
    cn_entry = X509_NAME_get_entry(cert_name, cn_loc);
    if (cn_entry == NULL) {
        GS_LOG_DEBUG_ERR("[SSL] failed to get CN entry using CN location");
        return "NONE";
    }
    // get CN from common name entry
    cn_asn1 = X509_NAME_ENTRY_get_data(cn_entry);
    if (cn_asn1 == NULL) {
        GS_LOG_DEBUG_ERR("[SSL] failed to get CN from CN entry");
        return "NONE";
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    name = (char *)ASN1_STRING_data(cn_asn1);
#else  /* OPENSSL_VERSION_NUMBER < 0x10100000L */
    name = (char *)ASN1_STRING_get0_data(cn_asn1);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
    if (name == NULL) {
        GS_LOG_DEBUG_ERR("[SSL] failed to get ASN1 data");
        return "NONE";
    }

    if ((size_t)ASN1_STRING_length(cn_asn1) != strlen(name)) {
        GS_LOG_DEBUG_ERR("[SSL] NULL embedded in the certificate CN");
        return "NONE";
    }
    errcode = strncpy_s(buf, len, name, strlen(name));
    if (errcode != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return "NONE";
    }
    return buf;
}

static void cs_ssl_show_certs(SSL *ssl)
{
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    /* Print some info abort the peer */
    char buf[GS_BUFLEN_512] = {0};
    const SSL_CIPHER *cipher = NULL;
    X509 *cert = NULL;
    X509_NAME *cert_name = NULL;

    GS_LOG_DEBUG_INF("SSL connection succeeded");

    cipher = SSL_get_current_cipher(ssl);
    GS_LOG_DEBUG_INF("Using cipher: %s", (cipher == NULL) ? "NONE" : SSL_CIPHER_get_name(cipher));

    GS_LOG_DEBUG_INF("Peer certificate:");
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        cert_name = X509_get_subject_name(cert);
        if (cert_name != NULL) {
            GS_LOG_DEBUG_INF("\tSubject: %s", get_common_name(cert_name, buf, sizeof(buf)));
        }
        cert_name = X509_get_issuer_name(cert);
        if (cert_name != NULL) {
            GS_LOG_DEBUG_INF("\tIssuer: %s", get_common_name(cert_name, buf, sizeof(buf)));
        }
        X509_free(cert);
    } else {
        GS_LOG_DEBUG_INF("Peer does not have certificate.");
    }
    GS_LOG_DEBUG_INF("\tSRV_TLS_VERSION: %s", SSL_get_version(ssl));
#endif
}

status_t cs_ssl_accept_socket(ssl_link_t *link, socket_t sock, int32 timeout)
{
    int32 ret;
    int32 tv = 0;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    status_t status = GS_SUCCESS;

    ctx = SSL_CTX_PTR(link->ssl_ctx);
    GS_RETVALUE_IFTRUE(ctx == NULL, GS_ERROR);

    ssl = cs_ssl_create_socket(ctx, sock);
    GS_RETVALUE_IFTRUE(ssl == NULL, GS_ERROR);
    link->tcp.sock = sock;
    link->ssl_sock = (ssl_sock_t *)ssl;

    do {
        /* Always look for connection attempts. */
        ret = SSL_accept(ssl);
        if (ret == 1) {
            status = GS_SUCCESS;
            break;
        }
        status = cs_ssl_wait_on_error(link, ret, GS_NETWORK_IO_TIMEOUT);
        if (status == GS_ERROR) {
            break;
        } else if (status == GS_TIMEDOUT) {
            tv += GS_NETWORK_IO_TIMEOUT;
        }
    } while (tv < timeout && !SSL_is_init_finished(ssl));

    if (status == GS_SUCCESS) {
        cs_ssl_show_certs(ssl);
        return GS_SUCCESS;
    }
    
    if (status == GS_TIMEDOUT) {
        GS_LOG_RUN_ERR("ssl accept timeout(%d ms)", GS_SSL_IO_TIMEOUT);
    }

    SSL_free(ssl);
    link->ssl_sock = NULL;
    return GS_ERROR;
}

status_t cs_ssl_connect_socket(ssl_link_t *link, socket_t sock, int32 timeout)
{
    int32 ret;
    int32 tv = 0;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    status_t status = GS_SUCCESS;

    ctx = SSL_CTX_PTR(link->ssl_ctx);
    GS_RETVALUE_IFTRUE(ctx == NULL, GS_ERROR);

    ssl = cs_ssl_create_socket(ctx, sock);
    GS_RETVALUE_IFTRUE(ssl == NULL, GS_ERROR);
    link->tcp.sock = sock;
    link->ssl_sock = (ssl_sock_t *)ssl;

    do {
        ret = SSL_connect(ssl);
        status = cs_ssl_wait_on_error(link, ret, GS_NETWORK_IO_TIMEOUT);
        if (status == GS_ERROR) {
            break;
        } else if (status == GS_TIMEDOUT) {
            tv += GS_NETWORK_IO_TIMEOUT;
        }
    } while (tv < timeout && !SSL_is_init_finished(ssl));

    if (status == GS_SUCCESS) {
        return GS_SUCCESS;
    }

    SSL_free(ssl);
    link->ssl_sock = NULL;
    return GS_ERROR;
}

void cs_ssl_disconnect(ssl_link_t *link)
{
    if (link->tcp.closed) {
        CM_ASSERT(link->tcp.sock == CS_INVALID_SOCKET);
        return;
    }
    SSL *ssl = SSL_SOCK(link->ssl_sock);
    GS_RETVOID_IFTRUE(ssl == NULL);
    SSL_set_quiet_shutdown(ssl, 1);
    if (SSL_shutdown(ssl) != 1) {
        GS_LOG_DEBUG_WAR("shutdown SSL failed.");
    }

    /* Close tcp socket */
    cs_tcp_disconnect(&link->tcp);

    SSL_free(ssl);
    link->ssl_sock = NULL;
}

status_t cs_ssl_send(ssl_link_t *link, const char *buf, uint32 size, int32 *send_size)
{
    int32 ret, err;
    uint32 wait_event;
    SSL *ssl = SSL_SOCK(link->ssl_sock);

    if (size == 0) {
        *send_size = 0;
        return GS_SUCCESS;
    }

    /* clear the error queue before the SSL I/O operation */
    cm_set_sock_error(0);
    ERR_clear_error();

    ret = SSL_write(ssl, buf, size);
    if (ret > 0) {
        (*send_size) = ret;
        return GS_SUCCESS;
    }

    if (!cs_ssl_should_retry(link, ret, &wait_event, &err)) {
        if (cm_get_sock_error() == EWOULDBLOCK) {
            (*send_size) = 0;
            return GS_SUCCESS;
        }
        GS_THROW_ERROR(ERR_PEER_CLOSED_REASON, "ssl", err);
        return GS_ERROR;
    }
    (*send_size) = 0;
    return GS_SUCCESS;
}

status_t cs_ssl_send_timed(ssl_link_t *link, const char *buf, uint32 size, uint32 timeout)
{
    uint32 remain_size;
    uint32 offset = 0;
    int32 writen_size = 0;
    uint32 wait_interval = 0;
    bool32 ready = GS_FALSE;

    if (link->ssl_sock == NULL) {
        GS_THROW_ERROR(ERR_PEER_CLOSED, "ssl");
        return GS_ERROR;
    }

    /* for most cases, all data are written by the following call */
    if (cs_ssl_send(link, buf, size, &writen_size) != GS_SUCCESS) {
        return GS_ERROR;
    }

    remain_size = size;
    if (writen_size > 0) {
        remain_size = size - writen_size;
        offset = (uint32)writen_size;
    }

    while (remain_size > 0) {
        if (cs_ssl_wait(link, CS_WAIT_FOR_WRITE, GS_POLL_WAIT, &ready) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!ready) {
            wait_interval += GS_POLL_WAIT;
            if (wait_interval >= timeout) {
                GS_THROW_ERROR(ERR_TCP_TIMEOUT, "send data");
                return GS_ERROR;
            }

            continue;
        }

        if (cs_ssl_send(link, buf + offset, remain_size, &writen_size) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (writen_size > 0) {
            remain_size -= writen_size;
            offset += writen_size;
        }
    }

    return GS_SUCCESS;
}

status_t cs_ssl_recv(ssl_link_t *link, char *buf, uint32 size, int32 *recv_size, uint32 *wait_event)
{
    int32 ret, err;
    SSL *ssl = SSL_SOCK(link->ssl_sock);

    if (size == 0) {
        (*recv_size) = 0;
        return GS_SUCCESS;
    }

    for (;;) {
        /* clear the error queue before the SSL I/O operation */
        cm_set_sock_error(0);
        ERR_clear_error();

        ret = SSL_read(ssl, (void *)buf, (int32)size);
        if (ret > 0) {
            break;
        }

        if (!cs_ssl_should_retry(link, ret, wait_event, &err)) {
            err = cm_get_sock_error();
            if (err == EINTR || err == EAGAIN) {
                continue;
            }

            if (err == ECONNRESET) {
                GS_THROW_ERROR(ERR_PEER_CLOSED, "ssl");
            }

            return GS_ERROR;
        }

        *recv_size = 0;
        return GS_SUCCESS;
    }

    *recv_size = ret;
    return GS_SUCCESS;
}

status_t cs_ssl_recv_remain(ssl_link_t *link, char *buf, uint32 offset_left, uint32 remain_size_left,
                            uint32 wait_event, uint32 timeout)
{
    int32 recv_size;
    uint32 wait_interval = 0;
    bool32 ready = GS_FALSE;

    int remain_size = remain_size_left;
    int offset = offset_left;
    while (remain_size > 0) {
        GS_RETURN_IFERR(cs_ssl_wait(link, wait_event, GS_POLL_WAIT, &ready) != GS_SUCCESS);

        if (!ready) {
            wait_interval += GS_POLL_WAIT;
            if (wait_interval >= timeout) {
                GS_THROW_ERROR(ERR_TCP_TIMEOUT, "recv data");
                return GS_ERROR;
            }

            continue;
        }

        GS_RETURN_IFERR(cs_ssl_recv(link, buf + offset, remain_size, &recv_size, &wait_event) != GS_SUCCESS);
        remain_size -= recv_size;
        offset += recv_size;
    }

    return GS_SUCCESS;
}

status_t cs_ssl_recv_timed(ssl_link_t *link, char *buf, uint32 size, uint32 timeout)
{
    uint32 remain_size, offset;
    int32 recv_size;
    uint32 wait_event = 0;

    remain_size = size;
    offset = 0;
    GS_RETURN_IFERR(cs_ssl_recv(link, buf + offset, remain_size, &recv_size, &wait_event) != GS_SUCCESS);
    remain_size -= recv_size;
    offset += recv_size;
    wait_event = (wait_event == 0) ? CS_WAIT_FOR_READ : wait_event;

    return cs_ssl_recv_remain(link, buf, offset, remain_size, wait_event, timeout);
}

status_t cs_ssl_wait(ssl_link_t *link, uint32 wait_for, int32 timeout, bool32 *ready)
{
    return cs_tcp_wait(&link->tcp, wait_for, timeout, ready);
}

status_t cs_ssl_read_buffer(ssl_link_t *link, char *buf, uint32 size, int32 *recv_size)
{
    if (SSL_has_pending(SSL_SOCK(link->ssl_sock)) != 1) {
        return GS_ERROR;
    }
    uint32 pending_size = SSL_pending(SSL_SOCK(link->ssl_sock));
    uint32 wait_event = CS_WAIT_FOR_READ;
    if (pending_size >= size) {
        return cs_ssl_recv(link, buf, size, recv_size, &wait_event);
    } else {
        return GS_ERROR;
    }
}

status_t cs_ssl_verify_certificate(ssl_link_t *link, ssl_verify_t vmode, const char *name, const char **errptr)
{
    status_t ret = GS_SUCCESS;
    SSL *ssl = SSL_SOCK(link->ssl_sock);
    X509 *cert = NULL;
    X509_NAME *attr = NULL;
    char buf[GS_BUFLEN_512];

    if (ssl == NULL) {
        (*errptr) = "No SSL pointer found";
        return GS_ERROR;
    }

    cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL && vmode != VERIFY_SSL) {
        (*errptr) = "Cannot get peer certificate";
        return GS_ERROR;
    }
    switch (vmode) {
        case VERIFY_SSL:
        case VERIFY_CERT:
            ret = GS_SUCCESS;
            break;
        case VERIFY_ISSUER:
            attr = X509_get_issuer_name(cert);
            if ((attr != NULL) && (name != NULL) &&
                cm_str_equal(name, get_common_name(attr, buf, sizeof(buf)))) {
                ret = GS_SUCCESS;
            } else {
                (*errptr) = "SSL certificate issuer validation failure";
                ret = GS_ERROR;
            }
            break;
        case VERIFY_SUBJECT:
            attr = X509_get_subject_name(cert);
            if ((attr != NULL) && (name != NULL) &&
                cm_str_equal(name, get_common_name(attr, buf, sizeof(buf)))) {
                ret = GS_SUCCESS;
            } else {
                (*errptr) = "SSL certificate subject validation failure";
                ret = GS_ERROR;
            }
            break;
        default:
            break;
    }
    X509_free(cert);
    return ret;
}

const char **cs_ssl_get_default_cipher_list(void)
{
    return g_ssl_cipher_names;
}

const char **cs_ssl_tls13_get_default_cipher_list(void)
{
    return g_ssl_tls13_cipher_names;
}

status_t cs_ssl_verify_file_stat(const char *file_name)
{
#ifndef WIN32
    struct stat stat_buf;
    if (file_name && stat(file_name, &stat_buf) == 0) {
        if (!S_ISREG(stat_buf.st_mode) || stat_buf.st_mode & (S_IRWXG | S_IRWXO | S_IXUSR)) {
            GS_THROW_ERROR(ERR_SSL_FILE_PERMISSION, file_name);
            return GS_ERROR;
        }
    }
#endif
    return GS_SUCCESS;
}

#ifdef __cplusplus
}
#endif