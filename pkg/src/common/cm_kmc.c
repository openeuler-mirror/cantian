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
 * cm_kmc.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_kmc.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_encrypt.h"
#include "cm_file.h"
#include "cm_binary.h"
#include "cm_kmc.h"
#include "cm_base.h"
#include "cm_types.h"
#include "cm_debug.h"
#include "cm_device.h"
#include <limits.h>
#include <float.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include "securec.h"
#include "cm_system.h"

#ifdef _WIN32
#include <windows.h>
#include <Wincrypt.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <direct.h>
#include <io.h>
#else
#include <pthread.h>
#include "unistd.h"
#include <sys/stat.h>
#include "sys/types.h"
#include <fcntl.h>
#include <semaphore.h>
#include <sys/wait.h>
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>
#endif
#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#include <time.h>
#endif

#define VERSION2 "CANTIAND"


ulong get_random_numbers(uchar *buff, uint32 len)
{
    return GS_SUCCESS;
}

void cm_kmc_write_log(int32 nLevel, const char *module, const char *filename, int32 numline, const char *pszLog)
{
    return;
}
void cm_kmc_recv_notify(uint32 eNtfCode, const void *data, size_t nDataSize)
{
    GS_LOG_DEBUG_WAR("kmc write notify eNtfCode:[%u]", eNtfCode);
}

void cm_kmc_do_events(void)
{
    return;
}

int32 cm_kmc_create_thread_lock(void **phMutex)
{
    return GS_SUCCESS;
}

void cm_kmc_destroy_thread_lock(void *hMutex)
{
#ifdef _WIN32
    CRITICAL_SECTION *css = (CRITICAL_SECTION *)hMutex;
#else
    pthread_mutex_t *css = (pthread_mutex_t *)hMutex;
#endif
    if (css == NULL) {
        GS_LOG_RUN_INF("Destroy Thread Lock hMutex is NULL");
        return;
    }
#ifdef _WIN32
    DeleteCriticalSection(css);
#else
    (void)pthread_mutex_destroy(css);
#endif
    free(css);
    css = NULL;
}

void cm_kmc_thread_lock(void *hMutex)
{
    return;
}

void cm_kmc_thread_unlock(void *hMutex)
{
    return;
}

void cm_kmc_destroy_proc_lock(void *DProcLock)
{
    return;
}

void cm_kmc_proc_lock(void *ProcLock)
{
    return;
}
void cm_kmc_proc_unlock(void *ProcUnlock)
{
    return;
}

int32 cm_kmc_get_entropy(uchar **ppEnt, size_t buffLen)
{
    return 0;
}

void cm_kmc_clean_entropy(uchar *pEnt, size_t buffLen)
{
    return;
}

int32 cm_kmc_close_file(void *stream)
{
    return 0;
}

int32 cm_kmc_read_file(void *buffer, size_t count, void *stream)
{
    return GS_SUCCESS;
}

int32 cm_kmc_flush_file(void *stream)
{
    return 0;
}

int32 cm_kmc_remove_file(const char *path)
{
    return remove(path);
}
long cm_kmc_tell_file(void *stream)
{
    return 0;
}

int32 cm_kmc_eof_file(void *stream, int32 *endOfFile)
{
    return 0;
}
int32 cm_kmc_errno_file(void *stream)
{
    return 0;
}

int32 cm_kmc_exist_file(const char *filePathName)
{
    return 0;
}

int32 cm_kmc_utc_time(const time_t *curTime, struct tm *curTm)
{
    return 0;
}

status_t regkmcfuc(void)
{
    return 0;
}

status_t cm_kmc_export_keyfile(char *dst_keyfile)
{
    return GS_SUCCESS;
}

status_t cm_kmc_init(bool32 is_server, char *key_file_a, char *key_file_b)
{
    return GS_SUCCESS;
}

status_t cm_kmc_finalize(void)
{
    return GS_SUCCESS;
}

status_t cm_kmc_create_masterkey(uint32 domain, uint32 *keyid)
{
    return GS_SUCCESS;
}

status_t cm_kmc_active_masterkey(uint32 domain, uint32 keyid)
{
    return GS_SUCCESS;
}

status_t cm_kmc_get_masterkey(uint32 domain, uint32 keyid, char *key_buf, uint32 *key_len)
{
    return GS_SUCCESS;
}

status_t cm_kmc_load_domain(uint32 domain)
{
    return GS_SUCCESS;
}

status_t cm_kmc_init_domain(uint32 domain)
{
    return GS_SUCCESS;
}

status_t cm_kmc_reset(void)
{
    return GS_SUCCESS;
}

status_t cm_get_cipher_len(uint32 plain_len, uint32 *cipher_len)
{
    *cipher_len = plain_len;
    return GS_SUCCESS;
}

status_t cm_kmc_encrypt(uint32 domain, encrypt_version_t version, const void *plain_text, uint32 plain_len,
    void *cipher_text, uint32 *cipher_len)
{
    (void)memcpy_s(cipher_text, *cipher_len, plain_text, plain_len);
    *cipher_len = plain_len;
    return GS_SUCCESS;
}

status_t cm_kmc_decrypt(uint32 domain, const void *cipher_text, uint32 cipher_len, void *plain_text, uint32 *plain_len)
{
    (void)memcpy_s(plain_text, *plain_len, cipher_text, cipher_len);
    *plain_len = cipher_len;
    return GS_SUCCESS;
}

status_t cm_get_masterkey_count(uint32 *count)
{
    *count = 0;
    return GS_SUCCESS;
}

status_t cm_get_masterkey_hash(uint32 domain, uint32 keyid, char *hash, uint32 *len)
{
    return GS_SUCCESS;
}

status_t cm_get_masterkey_byhash(const char *hash, uint32 len, char *key, uint32 *key_len)
{
    return GS_SUCCESS;
}

status_t cm_kmc_get_max_mkid(uint32 domain, uint32 *max_id)
{
    return GS_SUCCESS;
}

void cm_kmc_set_aes_key_with_config(aes_and_kmc_t *aes_kmc, config_t *config)
{
    aes_kmc->fator = cm_get_config_value(config, "_FACTOR_KEY");
    aes_kmc->local = cm_get_config_value(config, "LOCAL_KEY");
}

void cm_kmc_set_aes_key(aes_and_kmc_t *aes_kmc, char *fator, char *local)
{
    aes_kmc->fator = fator;
    aes_kmc->local = local;
}

void cm_kmc_set_aes_new_key(aes_and_kmc_t *aes_kmc, char *fator_new, char *local_new)
{
    aes_kmc->fator_new = fator_new;
    aes_kmc->local_new = local_new;
}

void cm_kmc_set_aes_key_with_new(aes_and_kmc_t *aes_kmc, char *fator, char *local, char *fator_new, char *local_new)
{
    cm_kmc_set_aes_key(aes_kmc, fator, local);
    cm_kmc_set_aes_new_key(aes_kmc, fator_new, local_new);
}

void cm_kmc_set_kmc(aes_and_kmc_t *aes_kmc, uint32 kmc_domain, encrypt_version_t kmc_ver)
{
    aes_kmc->kmc_domain = kmc_domain;
    aes_kmc->kmc_ver = kmc_ver;
}

void cm_kmc_set_buf(aes_and_kmc_t *aes_kmc, char *plain, uint32 plain_len, char *cipher, uint32 cipher_len)
{
    aes_kmc->plain_len = plain_len;
    aes_kmc->cipher_len = cipher_len;
    aes_kmc->plain = plain;
    aes_kmc->cipher = cipher;
}

status_t cm_kmc_encrypt_pwd(aes_and_kmc_t *aes_kmc)
{
    return GS_SUCCESS;
}

static inline bool32 cm_kmc_check_encrypt_is_kmc(aes_and_kmc_t *aes_kmc)
{
    return GS_FALSE;
}

status_t cm_kmc_decrypt_pwd(aes_and_kmc_t *aes_kmc)
{
    return GS_SUCCESS;
}

// Set the old pwd to aes_kmc->plain, and get the new pwd in the aes_kmc->cipher
status_t cm_aes_to_kmc(aes_and_kmc_t *aes_kmc)
{
    return GS_SUCCESS;
}

// Set the old pwd to aes_kmc->plain, and get the new pwd in the aes_kmc->cipher
status_t cm_aes_may_to_aes_new(aes_and_kmc_t *aes_kmc)
{
    return GS_SUCCESS;
}

// Set the old pwd to aes_kmc->plain, and get the new pwd in the aes_kmc->cipher
status_t cm_aes_may_to_kmc(aes_and_kmc_t *aes_kmc)
{
    return GS_SUCCESS;
}

// Set the old pwd to aes_kmc->plain, and get the new pwd in the aes_kmc->cipher
status_t cm_kmc_to_aes(aes_and_kmc_t *aes_kmc)
{
    return GS_SUCCESS;
}

status_t cm_encrypt_passwd_with_key(aes_and_kmc_t *aes_kmc)
{
    if (cm_encrypt_passwd(GS_TRUE, aes_kmc->plain, aes_kmc->plain_len, aes_kmc->cipher, &aes_kmc->cipher_len,
        aes_kmc->local, aes_kmc->fator) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("Fail to encrypt aes data.\n");
        GS_THROW_ERROR(ERR_ENCRYPTION_ERROR);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/**
 * try to decrypt using factor-key & local-key
 * Hint : remember to erase the pwd after used.
 */
status_t cm_decrypt_passwd_with_key(aes_and_kmc_t *aes_kmc)
{
    if (cm_decrypt_passwd(GS_TRUE, aes_kmc->cipher, aes_kmc->cipher_len, aes_kmc->plain, &aes_kmc->plain_len,
        aes_kmc->local, aes_kmc->fator) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("Fail to decrypt aes data.\n");
        GS_THROW_ERROR(ERR_ENCRYPTION_ERROR);
        return GS_ERROR;
    }

    // cm_decrypt_passwd may not set the 0x00 at the end, so set it
    aes_kmc->plain[aes_kmc->plain_len] = '\0';

    return GS_SUCCESS;
}

status_t cm_encrypt_passwd_with_key_by_kmc(aes_and_kmc_t *aes_kmc)
{
    return GS_SUCCESS;
}

status_t cm_decrypt_passwd_with_key_by_kmc(aes_and_kmc_t *aes_kmc)
{

    return GS_SUCCESS;
}
