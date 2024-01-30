/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2020. All rights reserved.
 * Description: SDP V3 internal header file, which is not open to external systems.
 * Create: 2014-06-16
 */

#ifndef KMC_SRC_SDP_SDPV3_TYPE_H
#define KMC_SRC_SDP_SDPV3_TYPE_H

#include "wsecv2_type.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/* Ciphertext structure version */
#define SDP_CIPHER_TEXT_VER1 1
#define SDP_HMAC_VER         1
#define SDP_HMAC_VER2        2
#define SDP_CIPHER_TEXT_VER2 2
#define SDP_CIPHER_TEXT_VER3 3 /* Compared with the V2 format, the V3 format changes only the HMAC key length. */

/* Boundary Value Definition */
#define SDP_SALT_LEN             16u
#define SDP_IV_MAX_LEN           16u /* Length of the IV used by the symmetric algorithm */
#define SDP_SALT_LEN_V2          8u
/* Length of the plaintext HMAC in the cipher-text header of the symmetric algorithm */
#define SDP_PTMAC_MAX_LEN        64u
#define SDP_KEY_MAX_LEN         128u
#define SDP_SYM_MAX_BLOCK_SIZE   16u /* Maximum block length for symmetric encryption */
#define SDP_HMAC_MAX_SIZE        64u /* HMAC algorithm longest result */
#define SDP_DIGEST_MAX_SIZE      64u
#define WSEC_AES_GCM_TAGLEN  16
#define KMC_WORK_KEY_ITER_COUNT 1

#define DEFAULT_SDP_DOMAIN_ID 0
#define KMC_ITER_COUNT_MIN  1
#define KMC_ITER_COUNT_MAX  100000
#define KMC_IS_KEYITERATIONS_VALID(iter) ((KMC_ITER_COUNT_MIN <= (iter)) && ((iter) <= KMC_ITER_COUNT_MAX))

typedef enum {
    WSEC_ALGTYPE_UNKNOWN,
    WSEC_ALGTYPE_SYM,
    WSEC_ALGTYPE_HMAC,
    WSEC_ALGTYPE_DIGEST,
    WSEC_ALGTYPE_PBKDF
} WsecAlgtype;

typedef struct {
    unsigned char *salt;
    WsecUint32 saltLen;
    int iter;
} Pbkdf2Param;

typedef struct {
    const unsigned char *salt;
    WsecUint32 saltLen;
    int iter;
} Pbkdf2ParamConst;

/* File Time Settings */
typedef WsecBool(*CallbackGetFileDateTime)(const char *fileName,
    WsecSysTime *createTime, WsecSysTime *lastEditTime);
/* Obtaining the File Time */
typedef WsecVoid(*CallbackSetFileDateTime)(const char *fileName,
    const WsecSysTime *createTime, const WsecSysTime *lastEditTime);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* KMC_SRC_SDP_SDPV3_TYPE_H */
