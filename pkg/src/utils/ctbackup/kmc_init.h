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
 * kmc_init.h
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/kmc_init.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef KMC_INIT
#define KMC_INIT

#include <stdint.h>

#if defined(__LINUX__) || defined(__linux__)
#include <linux/limits.h>
#define SEC_PATH_MAX PATH_MAX
#elif (defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER))
/* win10 1607 remove MAX_PATH define so we defined here for short path */
#define SEC_PATH_MAX 248
#else
#error "NOT SUPPORT OTHER PLATFROM"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TagKeCallBackParam {
    void *notifyCbCtx;
    void *loggerCtx;
    void *hwCtx;
} KeCallBackParam;

typedef struct TagKmcConfig {
    char primaryKeyStoreFile[SEC_PATH_MAX];
    char standbyKeyStoreFile[SEC_PATH_MAX];
    int32_t domainCount;
    int32_t role;
    int32_t procLockPerm;
    int32_t sdpAlgId;
    int32_t hmacAlgId;
    int32_t semKey;
    int32_t innerSymmAlgId;
    int32_t innerHashAlgId;
    int32_t innerHmacAlgId;
    int32_t innerKdfAlgId;
    int32_t workKeyIter;
    int32_t rootKeyIter;
    uint16_t version; // 0 is write read ksf file， 1 is memory ksf
} KmcConfig;

typedef struct TagKmcHardWareParm {
    int32_t len;
    char *hardParam;
} KmcHardWareParm;

typedef struct TagKmcConfigEx {
    int32_t enableHw;
    KmcHardWareParm kmcHardWareParm;
    KeCallBackParam *keCbParam;
    KmcConfig kmcConfig;
} KmcConfigEx;

typedef int32_t (*KeDecryptByDomainEx_t)(const void *ctx, uint32_t domainID,
    const char *cipherText, int32_t cipherTextLen, char **plainText, int32_t *plainTextLen);
typedef int32_t (*KeInitializeEx_t)(KmcConfigEx *kmcConfig, void **ctx);
typedef int32_t (*KeFinalizeEx_t)(void **ctx);
typedef struct st_kmc_interface {
    void *kmc_handle;
    KeDecryptByDomainEx_t KeDecryptByDomainEx;
    KeInitializeEx_t KeInitializeEx;
    KeFinalizeEx_t KeFinalizeEx;
} kmc_interface_t;

int32_t init_KMC(void);
int32_t KMC_decrypt(uint32_t domianId, char *cipherText, int32_t length, char **plainText, int32_t *plainTextLength);
int32_t KMC_finalize(void);

status_t kmc_init_lib(void);
void kmc_close_lib(void);
kmc_interface_t *kmc_global_handle(void);

#ifdef __cplusplus
}
#endif

#endif