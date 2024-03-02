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
 * kmc_init.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/kmc_init.c
 *
 * -------------------------------------------------------------------------
 */
#include <sys/wait.h>
#include "dpax_typedef.h"
#include "cm_common_module.h"
#include "cm_utils.h"
#include "cm_error.h"
#include "kmc_init.h"
#include "cm_log.h"

#define MAX_TIER_NUM 10000
#define MIN_PRO_PERMIT 0600
#define DEFAULT_SEM_KEY 0x20161227
 
#define MY_PID 666
#define DEFAULT_DOMAIN_COUNT 2
#define DEFAULT_LOGGER_LEVEL 4

#define PRIMARY_KEY_FILEPATH "/opt/cantian/common/config/primary_keystore_bak.ks"
#define STANDBY_KEY_FILEPATH "/opt/cantian/common/config/standby_keystore_bak.ks"

typedef enum HMAC_ALGORITHM {
    UNKNOWN_ALGORITHM = 0,
    HMAC_SHA256 = 2052,
    HMAC_SHA384 = 2053,
    HMAC_SHA512 = 2054,
    HMAC_SM3 = 2055 // 21.0.1版本开始支持
} HMAC_ALGORITHM;

typedef enum SDP_ALGORITHM {
    UNKNOWN_SDP_ALGORITHM = 0, // 未知加密算法
    AES128_CBC = 5, // AES-128 algorithm CBC mode
    AES256_CBC = 7, // AES-256 algorithm CBC mode
    AES128_GCM = 8, // AES-128 algorithm GCM mode
    AES256_GCM = 9, // AES-256 algorithm GCM mode
    SM4_CBC = 10, // SM4 algorithm CBC mode
    SM4_CTR = 11 // SM4 algorithm CTR mode
} SDP_ALGORITHM;
 
typedef enum HASH_ALGORITHM {
    UNKNOWN_HASH_ALGORITHM = 0,
    HASH_SHA256 = 1028,
    HASH_SM3 = 1031
} HASH_ALGORITHM;
 
typedef enum KDF_ALGORITHM {
    PBKDF2_HMAC_SHA256 = 3076,
    PBKDF2_HMAC_SM3 = 3079
} KDF_ALGORITHM;
 
typedef enum KMC_CONSTANT {
    SUCCESS = 0
} KMC_CONSTANT;
 
//  kmc角色
typedef enum KMC_ROLE {
    ROLE_AGENT = 0,
    ROLE_MASTER = 1
} KMC_ROLE;
 
static void *g_kmc_ctx = NULL;
static kmc_interface_t g_kmc_interface = { .kmc_handle = NULL };

kmc_interface_t *kmc_global_handle(void)
{
    return &g_kmc_interface;
}

static status_t kmc_load_symbol(void *lib_handle, char *symbol, void **sym_lib_handle)
{
    const char *dlsym_err = NULL;
 
    *sym_lib_handle = dlsym(lib_handle, symbol);
    dlsym_err = dlerror();
    if (dlsym_err != NULL) {
        CT_THROW_ERROR(ERR_LOAD_SYMBOL, symbol, dlsym_err);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t kmc_init_lib(void)
{
    kmc_interface_t *intf = &g_kmc_interface;
    intf->kmc_handle = dlopen("libkmcext.so", RTLD_LAZY);
    const char *dlopen_err = NULL;
    dlopen_err = dlerror();
    if (intf->kmc_handle == NULL) {
        CT_LOG_RUN_ERR("failed to load libkmcext.so, maybe lib path error, errno %s.", dlopen_err);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(kmc_load_symbol(intf->kmc_handle, "KeInitializeEx", (void **)(&intf->KeInitializeEx)));
    CT_RETURN_IFERR(kmc_load_symbol(intf->kmc_handle, "KeDecryptByDomainEx", (void **)(&intf->KeDecryptByDomainEx)));
    CT_RETURN_IFERR(kmc_load_symbol(intf->kmc_handle, "KeFinalizeEx", (void **)(&intf->KeFinalizeEx)));
    CT_RETURN_IFERR(kmc_load_symbol(intf->kmc_handle, "KmcAddDomainEx", (void **)(&intf->KmcAddDomainEx)));
    CT_RETURN_IFERR(kmc_load_symbol(intf->kmc_handle, "KmcAddDomainKeyTypeEx", (void **)(&intf->KmcAddDomainKeyTypeEx)));
    CT_RETURN_IFERR(kmc_load_symbol(intf->kmc_handle, "WsecFinalizeEx", (void **)(&intf->WsecFinalizeEx)));
    CT_RETURN_IFERR(kmc_load_symbol(intf->kmc_handle, "KmcCreateMkEx", (void **)(&intf->KmcCreateMkEx)));
    CT_RETURN_IFERR(kmc_load_symbol(intf->kmc_handle, "KmcActivateMk", (void **)(&intf->KmcActivateMk)));
    CT_RETURN_IFERR(kmc_load_symbol(intf->kmc_handle, "KmcGetMkDetail", (void **)(&intf->KmcGetMkDetail)));
    CT_RETURN_IFERR(kmc_load_symbol(intf->kmc_handle, "KmcGetMkDetailByHash", (void **)(&intf->KmcGetMkDetailByHash)));
    CT_RETURN_IFERR(kmc_load_symbol(intf->kmc_handle, "WsecInitializeEx", (void **)(&intf->WsecInitializeEx)));
    CT_RETURN_IFERR(kmc_load_symbol(intf->kmc_handle, "KmcGetActiveMk", (void **)(&intf->KmcGetActiveMk)));
    CT_RETURN_IFERR(kmc_load_symbol(intf->kmc_handle, "WsecResetEx", (void **)(&intf->WsecResetEx)));
    CT_RETURN_IFERR(kmc_load_symbol(intf->kmc_handle, "KmcGetMkCount", (void **)(&intf->KmcGetMkCount)));
    CT_RETURN_IFERR(kmc_load_symbol(intf->kmc_handle, "KmcGetMkHash", (void **)(&intf->KmcGetMkHash)));
    CT_RETURN_IFERR(kmc_load_symbol(intf->kmc_handle, "KmcGetMaxMkId", (void **)(&intf->KmcGetMaxMkId)));
    CT_RETURN_IFERR(kmc_load_symbol(intf->kmc_handle, "KmcGenerateKsfAll", (void **)(&intf->KmcGenerateKsfAll)));
    CT_RETURN_IFERR(kmc_load_symbol(intf->kmc_handle, "WsecRegFuncEx", (void **)(&intf->WsecRegFuncEx)));

    CT_LOG_RUN_INF("load libkmcext.so done.");
    return CT_SUCCESS;
}

status_t sdp_init_lib(void)
{
    kmc_interface_t *intf = &g_kmc_interface;
    intf->sdp_handle = dlopen("libsdp.so", RTLD_LAZY);
    const char *dlopen_err = NULL;
    dlopen_err = dlerror();
    if (intf->sdp_handle == NULL) {
        CT_LOG_RUN_ERR("failed to load libsdp.so, maybe lib path error, errno %s.", dlopen_err);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(kmc_load_symbol(intf->sdp_handle, "SdpGetCipherDataLenEx", (void **)(&intf->SdpGetCipherDataLenEx)));
    CT_RETURN_IFERR(kmc_load_symbol(intf->sdp_handle, "SdpEncryptEx", (void **)(&intf->SdpEncryptEx)));
    CT_RETURN_IFERR(kmc_load_symbol(intf->sdp_handle, "SdpDecryptEx", (void **)(&intf->SdpDecryptEx)));

    CT_LOG_RUN_INF("load libsdp.so done.");
    return CT_SUCCESS;
}
void kmc_close_lib(void)
{
    kmc_interface_t *intf = &g_kmc_interface;
    if (intf->kmc_handle != NULL) {
        (void)dlclose(intf->kmc_handle);
    }
    if (intf->sdp_handle != NULL) {
        (void)dlclose(intf->sdp_handle);
    }
}

void init_ke_callback_param(KeCallBackParam *callBackParam)
{
    callBackParam->hwCtx = NULL;
    callBackParam->loggerCtx = NULL;
    callBackParam->notifyCbCtx = NULL;
}
 
void init_kmc_hardware_parm(KmcHardWareParm *hardWareParm)
{
    hardWareParm->len = 0;
    hardWareParm->hardParam = "args";
}

void init_kmc_config(KmcConfig *kmcConfig)
{
    kmcConfig->domainCount = DEFAULT_DOMAIN_COUNT;
    errno_t ret = 0;
    ret = strcpy_s(kmcConfig->primaryKeyStoreFile, SEC_PATH_MAX, PRIMARY_KEY_FILEPATH);
    if (ret != 0) {
        printf("strcpy primary ks failed, ret=(%d).", ret);
    }
    strcpy_s(kmcConfig->standbyKeyStoreFile, SEC_PATH_MAX, STANDBY_KEY_FILEPATH);
    if (ret != 0) {
        printf("strcpy primary ks failed, ret=(%d).", ret);
    }
    kmcConfig->role = ROLE_MASTER;
    kmcConfig->sdpAlgId = AES256_GCM;
    kmcConfig->hmacAlgId = HMAC_SHA256;
    kmcConfig->innerKdfAlgId = PBKDF2_HMAC_SHA256;
    kmcConfig->innerHashAlgId = HASH_SHA256;
    kmcConfig->rootKeyIter = MAX_TIER_NUM;
    kmcConfig->workKeyIter = MAX_TIER_NUM;
    kmcConfig->innerSymmAlgId = AES256_GCM;
    kmcConfig->innerHmacAlgId = HMAC_SHA256;
    kmcConfig->procLockPerm = MIN_PRO_PERMIT;
    kmcConfig->semKey = DEFAULT_SEM_KEY;
}

int32_t init_KMC(void)
{
    kmc_interface_t *intf = kmc_global_handle();
    KmcConfig kmcConfig = { 0 };
    KeCallBackParam keCallBackParam = {0};
    KmcHardWareParm kmcHardWareParm = {0};
    init_ke_callback_param(&keCallBackParam);
    init_kmc_config(&kmcConfig);
    init_kmc_hardware_parm(&kmcHardWareParm);
    KmcConfigEx kmcConfigEx = {
        .enableHw = false,
        .keCbParam = &keCallBackParam,
        .kmcConfig = kmcConfig,
        .kmcHardWareParm = kmcHardWareParm
    };
    int32_t ret;
    ret = intf->KeInitializeEx(&kmcConfigEx, &g_kmc_ctx);
    return ret;
}

void *getContext(void)
{
    return g_kmc_ctx;
}

int32_t KMC_decrypt(uint32_t domianId, char *cipherText, int32_t length, char **plainText, int32_t *plainTextLength)
{
    kmc_interface_t *intf = kmc_global_handle();
    return intf->KeDecryptByDomainEx(g_kmc_ctx, domianId, cipherText, length, plainText, plainTextLength);
}

int32_t KMC_finalize(void)
{
    kmc_interface_t *intf = kmc_global_handle();
    return intf->KeFinalizeEx(&g_kmc_ctx);
}
