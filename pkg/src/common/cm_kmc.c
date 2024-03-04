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
 * cm_kmc.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_kmc.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "cm_encrypt.h"
#include "cm_file.h"
#include "cm_binary.h"
#include "cm_kmc.h"
#include "cm_base.h"
#include "cm_types.h"
#include "cm_debug.h"
#include "cm_device.h"
#include <stdlib.h>
#include "wsecv2_errorcode.h"
#include "wsecv2_type.h"
#include "securec.h"
#include "cm_system.h"
#include "wsecv2_util.h"
#include "wsecv2_datetime.h"
#include "kmc_init.h"

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

#define VERSION1 "Cantian100-OLTP-V100R006C10"
#define VERSION2 "CANTIAND"


static encrypt_manager_t g_encrypt_mgrs[] = {
    { NO_ENCRYPT, WSEC_ALGID_UNKNOWN, WSEC_ALGID_UNKNOWN },
    { KMC_DEFAULT_ENCRYPT, WSEC_ALGID_AES128_GCM, WSEC_ALGID_UNKNOWN },
    { KMC_ALGID_AES256_GCM, WSEC_ALGID_AES256_GCM, WSEC_ALGID_UNKNOWN },
    { KMC_ALGID_AES256_CBC, WSEC_ALGID_AES256_CBC, WSEC_ALGID_UNKNOWN },
};

ulong get_random_numbers(uchar *buff, uint32 len)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    return cm_rand(buff, len);
}

void cm_kmc_write_log(int32 nLevel, const char *module, const char *filename, int32 numline, const char *pszLog)
{
    if (!kmc_lib_load_flag) {
        return;
    }
    if (nLevel == WSEC_LOG_ERR) {
        CT_LOG_DEBUG_ERR("kmc write log module:[%s] filename:[%s] nLevel:[%d] pszLog:[%s] numline[%d]", module,
            filename, nLevel, pszLog, numline);
    }
    return;
}
void cm_kmc_recv_notify(uint32 eNtfCode, const void *data, size_t nDataSize)
{
    CT_LOG_DEBUG_WAR("kmc write notify eNtfCode:[%u]", eNtfCode);
}

void cm_kmc_do_events(void)
{
    return;
}

int32 cm_kmc_create_thread_lock(void **phMutex)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    int32 RetVal = WSEC_FALSE;
    errno_t err;
    if (phMutex == NULL) {
        CT_LOG_RUN_INF("create thread lock phMutex is NULL");
        return WSEC_FALSE;
    }
    if (*phMutex != NULL) {
        CT_LOG_RUN_INF("create thread lock phMutex already exists");
        return WSEC_FALSE;
    }
#ifdef _WIN32
    CRITICAL_SECTION *css = (CRITICAL_SECTION *)malloc(sizeof(CRITICAL_SECTION));
#else
    pthread_mutex_t *css = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
#endif
    if (css == NULL) {
        return WSEC_FALSE;
    }
#ifdef _WIN32
    err = memset_s(css, sizeof(CRITICAL_SECTION), 0, sizeof(CRITICAL_SECTION));
    if (err != EOK) {
        CM_FREE_PTR(css);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return WSEC_FALSE;
    }
    InitializeCriticalSection(css);
    RetVal = WSEC_TRUE;
#else
    err = memset_s(css, sizeof(pthread_mutex_t), 0, sizeof(pthread_mutex_t));
    if (err != EOK) {
        CM_FREE_PTR(css);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return WSEC_FALSE;
    }
    RetVal = 0 == pthread_mutex_init(css, NULL) ? WSEC_TRUE : WSEC_FALSE;
#endif
    if (RetVal) {
        *phMutex = css;
    }
    return RetVal;
}

void cm_kmc_destroy_thread_lock(void *hMutex)
{
#ifdef _WIN32
    CRITICAL_SECTION *css = (CRITICAL_SECTION *)hMutex;
#else
    pthread_mutex_t *css = (pthread_mutex_t *)hMutex;
#endif
    if (css == NULL) {
        CT_LOG_RUN_INF("Destroy Thread Lock hMutex is NULL");
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
    if (!kmc_lib_load_flag) {
        return;
    }
#ifdef _WIN32
    CRITICAL_SECTION *css = (CRITICAL_SECTION *)hMutex;
#else
    pthread_mutex_t *css = (pthread_mutex_t *)hMutex;
#endif
    if (css == NULL) {
        CT_LOG_RUN_INF("Thread Lock hMutex is NULL");
        return;
    }
#ifdef _WIN32
    EnterCriticalSection(css);
#else
    (void)pthread_mutex_lock(css);
#endif
}

void cm_kmc_thread_unlock(void *hMutex)
{
    if (!kmc_lib_load_flag) {
        return;
    }
#ifdef _WIN32
    CRITICAL_SECTION *css = (CRITICAL_SECTION *)hMutex;
#else
    pthread_mutex_t *css = (pthread_mutex_t *)hMutex;
#endif
    if (css == NULL) {
        CT_LOG_RUN_INF("Thread Unlock hMutex is NULL");
        return;
    }
#ifdef _WIN32
    LeaveCriticalSection(css);
#else
    (void)pthread_mutex_unlock(css);
#endif
}

int32 cm_kmc_create_proc_lock(void **CProcLock)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    return WSEC_TRUE;
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
    if (!kmc_lib_load_flag) {
        return 0;
    }
    int32 bre = WSEC_FALSE;
    errno_t errcode;
    if (buffLen == 0) {
        return bre;
    }
    *ppEnt = malloc(buffLen);
    if (*ppEnt == NULL) {
        return bre;
    }
    status_t ret = get_random_numbers(*ppEnt, (uint32)buffLen);
    if (ret == CT_SUCCESS) {
        bre = WSEC_TRUE;
    }
    if (bre != WSEC_TRUE) {
        errcode = memset_s(*ppEnt, buffLen, 0, buffLen);
        if (errcode != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        }
        CM_FREE_PTR(*ppEnt);
    }
    return bre;
}

void cm_kmc_clean_entropy(uchar *pEnt, size_t buffLen)
{
    if (!kmc_lib_load_flag) {
        return;
    }
    errno_t errcode;
    errcode = memset_s(pEnt, buffLen, 0, buffLen);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
    }
    free(pEnt);
    pEnt = NULL;
}

void *cm_kmc_open_file(const char *filePathName, const KmcFileOpenMode mode)
{
    int32 *ret = NULL;
    if (!kmc_lib_load_flag) {
        return ret;
    }
    int32 flag = 0;
    int32 retFd;
#ifndef _WIN32
    if (mode == KMC_FILE_READ_BINARY) {
        flag = O_RDONLY;
    } else if (mode == KMC_FILE_WRITE_BINARY) {
        flag = O_CREAT | O_WRONLY | O_SYNC;
    } else if (mode == KMC_FILE_READWRITE_BINARY) {
        flag = O_CREAT | O_RDWR | O_SYNC;
    } else {
        return NULL;
    }
    retFd = open(filePathName, flag, S_IRUSR | S_IWUSR);
#else
    if (mode == KMC_FILE_READ_BINARY) {
        flag = _O_BINARY | _O_RDONLY;
    } else if (mode == KMC_FILE_WRITE_BINARY) {
        flag = _O_CREAT | _O_BINARY | _O_WRONLY | _O_TRUNC;
    } else if (mode == KMC_FILE_READWRITE_BINARY) {
        flag = _O_CREAT | _O_BINARY | _O_RDWR;
    } else {
        return NULL;
    }
    retFd = _open(filePathName, flag, _S_IREAD | _S_IWRITE);
#endif
    if (-1 != retFd) {
        ret = (int32 *)malloc(sizeof(int));
        if (ret == NULL) {
            cm_close_file(retFd);
            return NULL;
        }
        *ret = retFd;
    }
    return ret;
}

int32 cm_kmc_close_file(void *stream)
{
    if (!kmc_lib_load_flag) {
        return 0;
    }
    int32 fd = *(int32 *)stream;
    int32 ret;
#ifndef _WIN32
    ret = close(fd);
#else
    ret = _close(fd);
#endif
    free(stream);
    stream = NULL;
    return ret;
}

int32 cm_kmc_read_file(void *buffer, size_t count, void *stream)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    int32 fd = *(int32 *)stream;
    int32 ret;

#ifndef _WIN32
    ret = (int32)read(fd, buffer, count);
#else
    ret = (int32)_read(fd, buffer, (uint32)count);
#endif
    return (count != (size_t)ret || ret == -1) ? WSEC_FALSE : WSEC_TRUE;
}

int32 cm_kmc_write_file(const void *buffer, size_t count, void *stream)
{
    if (!kmc_lib_load_flag) {
        return 0;
    }
    int32 fd = *(int32 *)stream;
    int32 ret;

#ifndef _WIN32
    ret = (int32)write(fd, buffer, count);
    if (0 != fsync(fd)) {
        return WSEC_FALSE;
    }
#else
    ret = (int32)_write(fd, buffer, (uint32)count);
    if (0 != _commit(fd)) {
        return WSEC_FALSE;
    }
#endif
    return (count != (size_t)ret || ret == -1) ? WSEC_FALSE : WSEC_TRUE;
}

int32 cm_kmc_flush_file(void *stream)
{
    if (!kmc_lib_load_flag) {
        return 0;
    }
    int32 fd = *(int32 *)stream;
    int32 ret;
#ifndef _WIN32
    ret = fsync(fd);
#else
    ret = _commit(fd);
#endif
    return ret;
}

int32 cm_kmc_remove_file(const char *path)
{
    return remove(path);
}
long cm_kmc_tell_file(void *stream)
{
    if (!kmc_lib_load_flag) {
        return 0;
    }
    int32 fd = *(int32 *)stream;
    long ret;
#ifndef _WIN32
    ret = lseek(fd, 0, SEEK_CUR);
#else
    ret = _tell(fd);
#endif
    return ret;
}

long cm_kmc_seek_file(void *stream, long offset, KmcFileSeekPos origin)
{
    if (!kmc_lib_load_flag) {
        return 0;
    }
    int32 realOri = 0;
    int32 fd = *(int32 *)stream;
    int32 ret;
    if (origin == KMC_FILE_SEEK_CUR) {
        realOri = SEEK_CUR;
    } else if (origin == KMC_FILE_SEEK_SET) {
        realOri = SEEK_SET;
    } else if (origin == KMC_FILE_SEEK_END) {
        realOri = SEEK_END;
    } else {
        return -1;
    }
#ifndef _WIN32
    ret = lseek(fd, offset, realOri);
#else
    ret = _lseek(fd, offset, realOri);
#endif
    return ret;
}
int32 cm_kmc_eof_file(void *stream, int32 *endOfFile)
{
    if (!kmc_lib_load_flag) {
        return 0;
    }
    int32 fd = *(int32 *)stream;
    long len = 0;

    if (endOfFile == NULL) {
        return -1;
    }
#ifndef _WIN32
    int32 curPos = lseek(fd, 0, SEEK_CUR);
    if (curPos == -1) {
        return -1;
    }
    len = lseek(fd, 0, SEEK_END);
    if (len == -1) {
        return -1;
    }
    if (lseek(fd, curPos, SEEK_SET) != curPos) {
        return -1;
    }
    if (len != curPos) {
        *endOfFile = WSEC_FALSE;
    } else {
        *endOfFile = WSEC_TRUE;
    }
#else
    int32 ret = _eof(fd);
    if (ret == -1) {
        return -1;
    }
    if (ret != 1) {
        *endOfFile = WSEC_FALSE;
    } else {
        *endOfFile = WSEC_TRUE;
    }
#endif
    return 0;
}
int32 cm_kmc_errno_file(void *stream)
{
#ifndef _WIN32
    return errno;
#else
    return GetLastError();
#endif
}

int32 cm_kmc_exist_file(const char *filePathName)
{
    if (!kmc_lib_load_flag) {
        return 0;
    }
    int32 ret;
#ifndef _WIN32
    ret = access(filePathName, F_OK);
#else
    ret = _access(filePathName, 0);
#endif
    return ret == 0 ? WSEC_TRUE : WSEC_FALSE;
}

int32 cm_kmc_utc_time(const time_t *curTime, struct tm *curTm)
{
    if (!kmc_lib_load_flag) {
        return 0;
    }
    int32 ret;
#ifndef _WIN32
    ret = gmtime_r(curTime, curTm) == NULL ? WSEC_FALSE : WSEC_TRUE;
#else
    ret = gmtime_s(curTm, curTime) == 0 ? WSEC_TRUE : WSEC_FALSE;
#endif
    return ret;
}

status_t regkmcfuc(void)
{
    if (!kmc_lib_load_flag) {
        return 0;
    }
    uint32 returnValue;
    WsecCallbacks stMandatoryFun = { { 0 }, { 0 }, { 0 }, { 0 }, { 0 }, { 0 }, { 0 } };

    stMandatoryFun.basicRelyCallbacks.writeLog = cm_kmc_write_log;
    stMandatoryFun.basicRelyCallbacks.notify = cm_kmc_recv_notify;
    stMandatoryFun.basicRelyCallbacks.doEvents = cm_kmc_do_events;

    // Regis self thread func
    stMandatoryFun.lockCallbacks.lock = cm_kmc_thread_lock;
    stMandatoryFun.lockCallbacks.unlock = cm_kmc_thread_unlock;
    stMandatoryFun.lockCallbacks.createLock = cm_kmc_create_thread_lock;
    stMandatoryFun.lockCallbacks.destroyLock = cm_kmc_destroy_thread_lock;

    stMandatoryFun.procLockCallbacks.createProcLock = cm_kmc_create_proc_lock;
    stMandatoryFun.procLockCallbacks.destroyProcLock = cm_kmc_destroy_proc_lock;
    stMandatoryFun.procLockCallbacks.procLock = cm_kmc_proc_lock;
    stMandatoryFun.procLockCallbacks.procUnlock = cm_kmc_proc_unlock;

    stMandatoryFun.fileCallbacks.fileOpen = cm_kmc_open_file;
    stMandatoryFun.fileCallbacks.fileClose = cm_kmc_close_file;
    stMandatoryFun.fileCallbacks.fileRead = cm_kmc_read_file;
    stMandatoryFun.fileCallbacks.fileWrite = cm_kmc_write_file;
    stMandatoryFun.fileCallbacks.fileRemove = cm_kmc_remove_file;
    stMandatoryFun.fileCallbacks.fileSeek = cm_kmc_seek_file;
    stMandatoryFun.fileCallbacks.fileTell = cm_kmc_tell_file;
    stMandatoryFun.fileCallbacks.fileFlush = cm_kmc_flush_file;
    stMandatoryFun.fileCallbacks.fileEof = cm_kmc_eof_file;
    stMandatoryFun.fileCallbacks.fileErrno = cm_kmc_errno_file;
    stMandatoryFun.fileCallbacks.fileExist = cm_kmc_exist_file;

    stMandatoryFun.rngCallbacks.getRandomNum = NULL;
    stMandatoryFun.rngCallbacks.getEntropy = cm_kmc_get_entropy;
    stMandatoryFun.rngCallbacks.cleanupEntropy = cm_kmc_clean_entropy;
    stMandatoryFun.timeCallbacks.gmTimeSafe = cm_kmc_utc_time;

    returnValue = kmc_global_handle()->WsecRegFuncEx(&stMandatoryFun);
    if (returnValue != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Registered Kmc functions return Value=%u", returnValue);
        return CT_ERROR;
    }
    return returnValue;
}

status_t cm_kmc_export_keyfile(char *dst_keyfile)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    int32 handle = CT_INVALID_HANDLE;
    ulong ret = kmc_global_handle()->KmcGenerateKsfAll(dst_keyfile);
    device_type_t type = cm_device_type((const char *)dst_keyfile);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("fail to import keyfile to %s.returnValue=%lu", dst_keyfile, ret);
        return CT_ERROR;
    }

    if (cm_open_device((const char *)dst_keyfile, type, O_SYNC, &handle) != CT_SUCCESS) {
        return CT_ERROR;
    }
    (void)cm_chmod_file(S_IRUSR | S_IWUSR, handle);
    cm_close_device(type, &handle);
    return CT_SUCCESS;
}

status_t cm_kmc_init(bool32 is_server, char *key_file_a, char *key_file_b)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    int32 handle = CT_INVALID_HANDLE;
    KmcKsfName ksfile;
    ksfile.keyStoreFile[0] = key_file_a;
    ksfile.keyStoreFile[1] = key_file_b;

    char path[CT_MAX_FILE_PATH_LENGH];

    cm_trim_filename(key_file_a, CT_MAX_FILE_PATH_LENGH, path);
    if (!cm_dir_exist(path)) {
        CT_LOG_RUN_ERR("%s not exist", path);
        return CT_ERROR;
    }

    cm_trim_filename(key_file_b, CT_MAX_FILE_PATH_LENGH, path);
    if (!cm_dir_exist(path)) {
        CT_LOG_RUN_ERR("%s not exist", path);
        return CT_ERROR;
    }
    if ((!is_server) && (!cm_file_exist(key_file_a) || !cm_file_exist(key_file_b))) {
        CT_LOG_RUN_ERR("client can't get file_a and file_b");
        return CT_ERROR;
    }
    ulong ret = regkmcfuc();
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("regKmcfuc failed Value=%lu", ret);
        return CT_ERROR;
    }

    ret = kmc_global_handle()->WsecInitializeEx(is_server, &ksfile, CT_FALSE, NULL);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Init Kmc return Value=%lu", ret);
        return CT_ERROR;
    }

    if (!is_server) {
        return CT_SUCCESS;
    }

    device_type_t type = cm_device_type((const char *)key_file_a);
    if (cm_open_device((const char *)key_file_a, type, O_SYNC, &handle) != CT_SUCCESS) {
        return CT_ERROR;
    }
    (void)cm_chmod_file(S_IRUSR | S_IWUSR, handle);
    cm_close_device(type, &handle);

    if (cm_open_device((const char *)key_file_b, type, O_SYNC, &handle) != CT_SUCCESS) {
        return CT_ERROR;
    }
    (void)cm_chmod_file(S_IRUSR | S_IWUSR, handle);
    cm_close_device(type, &handle);

    return CT_SUCCESS;
}

status_t cm_kmc_finalize(void)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    ulong ret = kmc_global_handle()->WsecFinalizeEx();
    if (ret != 0) {
        CT_LOG_RUN_ERR("Finalize Kmc error %lu", ret);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_kmc_create_masterkey(uint32 domain, uint32 *keyid)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    ulong ret = kmc_global_handle()->KmcCreateMkEx(domain, keyid);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Create Mk Ex failed.returnValue = %lu", ret);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_kmc_active_masterkey(uint32 domain, uint32 keyid)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    ulong ret = kmc_global_handle()->KmcActivateMk(domain, keyid);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Activate Mk failed.returnValue = %lu", ret);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cm_kmc_get_masterkey(uint32 domain, uint32 keyid, char *key_buf, uint32 *key_len)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    ulong ret = kmc_global_handle()->KmcGetMkDetail(domain, keyid, NULL, (uchar *)key_buf, key_len);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Get Mk failed.returnValue = %lu", ret);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cm_kmc_load_domain(uint32 domain)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    const KmcCfgKeyType keyTypeCfg = { KMC_KEY_TYPE_ENCRPT_INTEGRITY, CT_KMC_MK_LEN, CT_KMC_MK_EXPIRE, { 0 } };
    KmcCfgDomainInfo domainInfo = { domain, KMC_MK_GEN_BY_INNER, "this mk is added", 0, { 0 } };

    ulong ret = kmc_global_handle()->KmcAddDomainEx(&domainInfo);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Add DomainEx failed.returnValue = %lu", ret);
        return CT_ERROR;
    }
    ret = kmc_global_handle()->KmcAddDomainKeyTypeEx(domain, &keyTypeCfg);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Add Domain Key TypeEx failed.returnValue = %lu", ret);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_kmc_init_domain(uint32 domain)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    KmcMkInfo activeMkInfo;
    uchar activeMkBuf[CT_KMC_ACTIVE_MK_LEN] = { 0 };
    WsecUint32 activeMkLen = CT_KMC_ACTIVE_MK_LEN;
    uint32 keyid = 0;

    if (cm_kmc_load_domain(domain) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* success means curr domain have active master key */
    if (kmc_global_handle()->KmcGetActiveMk(domain, &activeMkInfo, activeMkBuf,
                                            &activeMkLen) == CT_SUCCESS) {
        CT_LOG_DEBUG_INF("Domain %u have active master key.", domain);
        MEMS_RETURN_IFERR(memset_s(activeMkBuf, sizeof(activeMkBuf), 0x00, sizeof(activeMkBuf)));
        return CT_SUCCESS;
    }

    if (cm_kmc_create_masterkey(domain, &keyid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_kmc_active_masterkey(domain, keyid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_kmc_reset(void)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    uint32 domain;
    ulong ret = kmc_global_handle()->WsecResetEx();
    if (ret != 0) {
        CT_LOG_RUN_ERR("Reset Kmc error %lu", ret);
        return CT_ERROR;
    }

    for (domain = CT_KMC_DOMAIN_BEGIN + 1; domain < CT_KMC_DOMAIN_END; domain++) {
        if (cm_kmc_init_domain(domain) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t cm_get_cipher_len(uint32 plain_len, uint32 *cipher_len)
{
    if (!kmc_lib_load_flag) {
        *cipher_len = plain_len;
        return CT_SUCCESS;
    }
    return kmc_global_handle()->SdpGetCipherDataLenEx((WsecUint32)plain_len, (WsecUint32 *)cipher_len);
}

status_t cm_kmc_encrypt(uint32 domain, encrypt_version_t version, const void *plain_text, uint32 plain_len,
    void *cipher_text, uint32 *cipher_len)
{
    if (!kmc_lib_load_flag) {
        (void)memcpy_s(cipher_text, *cipher_len, plain_text, plain_len);
        *cipher_len = plain_len;
        return CT_SUCCESS;
    }
    ulong ret = kmc_global_handle()->SdpEncryptEx((int)domain, g_encrypt_mgrs[version].cipher_alg_type, (uchar *)plain_text,
        (WsecUint32)plain_len, (uchar *)cipher_text, (WsecUint32 *)cipher_len);
    if (ret != 0) {
        CT_LOG_RUN_ERR("fail to encrypt.returnValue=%lu", ret);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_kmc_decrypt(uint32 domain, const void *cipher_text, uint32 cipher_len, void *plain_text, uint32 *plain_len)
{
    if (!kmc_lib_load_flag) {
        (void)memcpy_s(plain_text, *plain_len, cipher_text, cipher_len);
        *plain_len = cipher_len;
        return CT_SUCCESS;
    }
    ulong ret = kmc_global_handle()->SdpDecryptEx((int)domain, (const uchar *)cipher_text, (WsecUint32)cipher_len, (uchar *)plain_text,
        (WsecUint32 *)plain_len);
    if (ret != 0) {
        CT_LOG_RUN_ERR("fail to decrypt.returnValue=%lu", ret);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_get_masterkey_count(uint32 *count)
{
    if (!kmc_lib_load_flag) {
        *count = 0;
        return CT_SUCCESS;
    }
    int32 ret = kmc_global_handle()->KmcGetMkCount();
    if (ret < 0) {
        CT_LOG_RUN_ERR("fail to get master key count.returnValue=%d", ret);
        return CT_ERROR;
    }

    *count = (uint32)ret;

    return CT_SUCCESS;
}

status_t cm_get_masterkey_hash(uint32 domain, uint32 keyid, char *hash, uint32 *len)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    ulong ret = kmc_global_handle()->KmcGetMkHash(domain, keyid, (uchar *)hash, len);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("fail to get keyid %u hash.returnValue=%lu", keyid, ret);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_get_masterkey_byhash(const char *hash, uint32 len, char *key, uint32 *key_len)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    ulong ret = kmc_global_handle()->KmcGetMkDetailByHash((const uchar *)hash, len, NULL, (uchar *)key, key_len);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("fail to get masterkey by hash.returnValue=%lu", ret);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_kmc_get_max_mkid(uint32 domain, uint32 *max_id)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    ulong ret = kmc_global_handle()->KmcGetMaxMkId(domain, max_id);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("fail to get domain %u max keyid.returnValue = %lu", domain, ret);
        return CT_ERROR;
    }

    return CT_SUCCESS;
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
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    char buff[CT_ENCRYPTION_SIZE + 1];
    uint32 buff_len = CT_ENCRYPTION_SIZE;
    uint32 ret = 0;
    char *cipher = NULL;

    if ((uint32)aes_kmc->kmc_ver >= (uint32)KMC_ALGID_MAX || aes_kmc->cipher_len < CT_ENCRYPT_VER_LEN) {
        CT_LOG_RUN_ERR("kmc_ver error.\n");
        CT_THROW_ERROR(ERR_ENCRYPTION_ERROR);
        return CT_ERROR;
    }

    ret = kmc_global_handle()->SdpEncryptEx((int)aes_kmc->kmc_domain, g_encrypt_mgrs[aes_kmc->kmc_ver].cipher_alg_type,
        (uchar *)aes_kmc->plain, (WsecUint32)aes_kmc->plain_len, (uchar *)buff, (WsecUint32 *)&buff_len);
    if (ret != WSEC_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to encode kmc data, kmc error [%u].\n", ret);
        CT_THROW_ERROR(ERR_ENCRYPTION_ERROR);
        return CT_ERROR;
    }
    buff[buff_len] = 0x00;

    cipher = (char *)aes_kmc->cipher;
    ret = memcpy_s(cipher, aes_kmc->cipher_len, CT_ENCRYPT_VER, CT_ENCRYPT_VER_LEN);
    if (ret != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }
    cipher += CT_ENCRYPT_VER_LEN;
    aes_kmc->cipher_len -= CT_ENCRYPT_VER_LEN;

    if (cm_base64_encode((uchar *)buff, buff_len, cipher, &aes_kmc->cipher_len) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to encode kmc data.\n");
        CT_THROW_ERROR(ERR_DECODE_ERROR);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline bool32 cm_kmc_check_encrypt_is_kmc(aes_and_kmc_t *aes_kmc)
{
    if (!kmc_lib_load_flag) {
        return CT_FALSE;
    }
    if (memcmp(aes_kmc->cipher, CT_ENCRYPT_VER, CT_ENCRYPT_VER_LEN) == 0 ||
        memcmp(aes_kmc->cipher, CT_ENCRYPT_KMC_LIKE, CT_ENCRYPT_KMC_LIKE_LEN) == 0) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

status_t cm_kmc_decrypt_pwd(aes_and_kmc_t *aes_kmc)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    char buff[CT_ENCRYPTION_SIZE + 1];
    uint32 buff_len = CT_ENCRYPTION_SIZE;
    uint32 ret = 0;
    uint32 de_len = 0;
    char *cipher = (char *)aes_kmc->cipher;
    uint32 cipher_len = aes_kmc->cipher_len;

    if (aes_kmc->kmc_disable_ver != CT_TRUE) {
        if (memcmp(aes_kmc->cipher, CT_ENCRYPT_VER, CT_ENCRYPT_VER_LEN) == 0) {
            cipher += CT_ENCRYPT_VER_LEN;
            cipher_len -= CT_ENCRYPT_VER_LEN;
        } else if (memcmp(aes_kmc->cipher, CT_ENCRYPT_KMC_LIKE, CT_ENCRYPT_KMC_LIKE_LEN) != 0) {
            CT_LOG_RUN_ERR("Fail to decode kmc data.\n");
            return CT_ERROR;
        }
    }

    de_len = cm_base64_decode(cipher, cipher_len, (uchar *)buff, buff_len);
    if (de_len == 0) {
        CT_LOG_RUN_ERR("Fail to decode kmc data.\n");
        CT_THROW_ERROR(ERR_DECODE_ERROR);
        return CT_ERROR;
    }
    buff[de_len] = 0x00;

    ret = kmc_global_handle()->SdpDecryptEx((int)aes_kmc->kmc_domain, (const uchar *)buff, (WsecUint32)de_len, (uchar *)aes_kmc->plain,
        (WsecUint32 *)&aes_kmc->plain_len);
    if (ret != WSEC_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to decrypt kmc data, kmc error[%u].\n", ret);
        CT_THROW_ERROR(ERR_ENCRYPTION_ERROR);
        return CT_ERROR;
    }
    aes_kmc->plain[aes_kmc->plain_len] = 0x00;

    return CT_SUCCESS;
}

// Set the old pwd to aes_kmc->plain, and get the new pwd in the aes_kmc->cipher
status_t cm_aes_to_kmc(aes_and_kmc_t *aes_kmc)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    char plain[CT_ENCRYPTION_SIZE + 1];
    uint32 plain_len = CT_ENCRYPTION_SIZE;

    aes_and_kmc_t aes_kmc2;

    if (cm_decrypt_passwd(CT_TRUE, aes_kmc->plain, aes_kmc->plain_len, plain, &plain_len, aes_kmc->local,
        aes_kmc->fator) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to aes decrypt data.\n");
        CT_THROW_ERROR(ERR_ENCRYPTION_ERROR);
        return CT_ERROR;
    }
    // cm_decrypt_passwd may not set the 0x00 at the end, so set it
    plain[plain_len] = 0x00;

    aes_kmc2 = *aes_kmc;
    aes_kmc2.plain = plain;
    aes_kmc2.plain_len = plain_len;
    if (cm_kmc_encrypt_pwd(&aes_kmc2) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to kmc encrypt data.\n");
        MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0x00, sizeof(plain)));
        return CT_ERROR;
    }
    aes_kmc->cipher_len = aes_kmc2.cipher_len;

    MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0x00, sizeof(plain)));

    return CT_SUCCESS;
}

// Set the old pwd to aes_kmc->plain, and get the new pwd in the aes_kmc->cipher
status_t cm_aes_may_to_aes_new(aes_and_kmc_t *aes_kmc)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    char plain[CT_ENCRYPTION_SIZE + 1];
    uint32 plain_len = CT_ENCRYPTION_SIZE;

    aes_and_kmc_t aes_kmc2;

    aes_kmc2 = *aes_kmc;
    cm_kmc_set_buf(&aes_kmc2, plain, plain_len, aes_kmc->plain, aes_kmc->plain_len);
    if (cm_decrypt_passwd_with_key_by_kmc(&aes_kmc2) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to aes(may) decrypt data.\n");
        return CT_ERROR;
    }

    plain_len = (uint32)strlen(plain);
    if (cm_encrypt_passwd(CT_TRUE, plain, plain_len, aes_kmc->cipher, &aes_kmc->cipher_len, aes_kmc->local_new,
        aes_kmc->fator_new) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to encrypt aes data.\n");
        CT_THROW_ERROR(ERR_ENCRYPTION_ERROR);
        MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0x00, sizeof(plain)));
        return CT_ERROR;
    }

    MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0x00, sizeof(plain)));

    return CT_SUCCESS;
}

// Set the old pwd to aes_kmc->plain, and get the new pwd in the aes_kmc->cipher
status_t cm_aes_may_to_kmc(aes_and_kmc_t *aes_kmc)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    char plain[CT_ENCRYPTION_SIZE + 1];
    uint32 plain_len = CT_ENCRYPTION_SIZE;

    aes_and_kmc_t aes_kmc2;

    aes_kmc2 = *aes_kmc;
    cm_kmc_set_buf(&aes_kmc2, plain, plain_len, aes_kmc->plain, aes_kmc->plain_len);
    if (cm_decrypt_passwd_with_key_by_kmc(&aes_kmc2) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to aes(may) decrypt data.\n");
        return CT_ERROR;
    }

    aes_kmc2 = *aes_kmc;
    aes_kmc2.plain = plain;
    aes_kmc2.plain_len = (uint32)strlen(plain);
    if (cm_kmc_encrypt_pwd(&aes_kmc2) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to kmc encrypt data.\n");
        MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0x00, sizeof(plain)));
        return CT_ERROR;
    }
    aes_kmc->cipher_len = aes_kmc2.cipher_len;

    MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0x00, sizeof(plain)));

    return CT_SUCCESS;
}

// Set the old pwd to aes_kmc->plain, and get the new pwd in the aes_kmc->cipher
status_t cm_kmc_to_aes(aes_and_kmc_t *aes_kmc)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    char plain[CT_ENCRYPTION_SIZE + 1];
    uint32 plain_len = CT_ENCRYPTION_SIZE;

    aes_and_kmc_t aes_kmc2;

    aes_kmc2 = *aes_kmc;
    aes_kmc2.plain = plain;
    aes_kmc2.plain_len = plain_len;
    aes_kmc2.cipher = aes_kmc->plain;
    aes_kmc2.cipher_len = aes_kmc->plain_len;
    if (cm_kmc_decrypt_pwd(&aes_kmc2) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to decrypt kmc data.\n");
        return CT_ERROR;
    }

    if (cm_encrypt_passwd(CT_TRUE, aes_kmc2.plain, aes_kmc2.plain_len, aes_kmc->cipher, &aes_kmc->cipher_len,
        aes_kmc->local, aes_kmc->fator) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to encrypt aes data.\n");
        CT_THROW_ERROR(ERR_ENCRYPTION_ERROR);
        MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0x00, sizeof(plain)));
        return CT_ERROR;
    }

    MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0x00, sizeof(plain)));
    return CT_SUCCESS;
}

status_t cm_encrypt_passwd_with_key(aes_and_kmc_t *aes_kmc)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    if (cm_encrypt_passwd(CT_TRUE, aes_kmc->plain, aes_kmc->plain_len, aes_kmc->cipher, &aes_kmc->cipher_len,
        aes_kmc->local, aes_kmc->fator) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to encrypt aes data.\n");
        CT_THROW_ERROR(ERR_ENCRYPTION_ERROR);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/**
 * try to decrypt using factor-key & local-key
 * Hint : remember to erase the pwd after used.
 */
status_t cm_decrypt_passwd_with_key(aes_and_kmc_t *aes_kmc)
{
    if (cm_decrypt_passwd(CT_TRUE, aes_kmc->cipher, aes_kmc->cipher_len, aes_kmc->plain, &aes_kmc->plain_len,
        aes_kmc->local, aes_kmc->fator) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to decrypt aes data.\n");
        CT_THROW_ERROR(ERR_ENCRYPTION_ERROR);
        return CT_ERROR;
    }

    // cm_decrypt_passwd may not set the 0x00 at the end, so set it
    aes_kmc->plain[aes_kmc->plain_len] = '\0';

    return CT_SUCCESS;
}

status_t cm_encrypt_passwd_with_key_by_kmc(aes_and_kmc_t *aes_kmc)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    if (cm_kmc_encrypt_pwd(aes_kmc) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to encrypt kmc data.\n");
        CT_THROW_ERROR(ERR_ENCRYPTION_ERROR);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_decrypt_passwd_with_key_by_kmc(aes_and_kmc_t *aes_kmc)
{
    if (!kmc_lib_load_flag) {
        return CT_SUCCESS;
    }
    uint32 buff_len = aes_kmc->plain_len;
    bool32 kmc_disable_ver = aes_kmc->kmc_disable_ver;

    if (cm_kmc_check_encrypt_is_kmc(aes_kmc) == CT_TRUE) {
        if (cm_kmc_decrypt_pwd(aes_kmc) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Fail to decrypt kmc data.\n");
            return CT_ERROR;
        }
    } else {
        if (cm_decrypt_passwd_with_key(aes_kmc) != CT_SUCCESS) {
            // get along with "enc with factor and local key mode"
            aes_kmc->plain_len = buff_len;
            aes_kmc->kmc_disable_ver = CT_TRUE;

            // SHOULD NOT come here,  for ver check exception of kmc
            if (cm_kmc_decrypt_pwd(aes_kmc) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("Fail to decrypt aes(kmc) data.\n");
                aes_kmc->kmc_disable_ver = kmc_disable_ver;
                return CT_ERROR;
            }

            cm_reset_error();
            aes_kmc->kmc_disable_ver = kmc_disable_ver;
        }
    }

    return CT_SUCCESS;
}
