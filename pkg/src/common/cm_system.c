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
 * cm_system.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_system.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_system.h"
#include "cm_spinlock.h"
#include "cm_text.h"
#include "cm_log.h"
#include "cm_ip.h"
#ifdef WIN32
#include <winsock2.h>
#else
#include <pwd.h>
#include <fcntl.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <pwd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif


static bool32 volatile g_system_initialized = GS_FALSE;
static spinlock_t g_system_lock;
static char g_program_name[GS_FILE_NAME_BUFFER_SIZE + 1] = {0};
static char g_user_name[GS_NAME_BUFFER_SIZE] = {0};
static char g_host_name[GS_HOST_NAME_BUFFER_SIZE] = {0};
static char g_platform_name[GS_NAME_BUFFER_SIZE] = {0};
static uint64 g_process_id = 0;
static uint32 g_nprocs = 0;

static void cm_get_host_name()
{
    (void)gethostname(g_host_name, GS_HOST_NAME_BUFFER_SIZE);
}

static void cm_get_process_id(void)
{
#ifdef WIN32
    g_process_id = (uint64)GetCurrentProcessId();
#else
    g_process_id = (uint64)getpid();
#endif
}

static void cm_get_program_name(void)
{
    int64 len;

#ifdef WIN32
    len = GetModuleFileName(NULL, g_program_name, GS_FILE_NAME_BUFFER_SIZE);
#elif defined(AIX)
    pid_t pid;
    struct procentry64 processInfo;

    while (getprocs64(&processInfo, sizeof(processInfo), 0, 0, &pid, 1) > 0) {
        if (uint64)
            (processInfo.pi_pid == g_process_id)
        {
            len = getargs(&processInfo, sizeof(processInfo), g_program_name, GS_FILE_NAME_BUFFER_SIZE);
            break;
        }
    }
#else /* linux */
    len = readlink("/proc/self/exe", g_program_name, GS_FILE_NAME_BUFFER_SIZE);
    if (len > 0) {
        g_program_name[len] = '\0';
        return;
    }
#endif

    // Handle error, just set the error information into audit log, and
    // set g_program_name as empty, here We do not return Error, as the
    // architecture is hard to be allowed
    if (len == 0) {
        GS_THROW_ERROR(ERR_INIT_SYSTEM, cm_get_os_error());
        PRTS_RETVOID_IFERR(snprintf_s(g_program_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1,
                                      "<empty>"));
    }
}

static void cm_get_user_name(void)
{
#ifdef WIN32
    uint32 size = GS_NAME_BUFFER_SIZE;
    GetUserName(g_user_name, &size);
#else
    struct passwd *pw = getpwuid(geteuid());
    uint32 name_len;
    if (pw == NULL) {
        g_user_name[0] = '\0';
        return;
    }
    name_len = strlen(pw->pw_name);
    if (strncpy_s(g_user_name, GS_NAME_BUFFER_SIZE, pw->pw_name, name_len) != EOK) {
        GS_LOG_RUN_ERR("Secure C lib has thrown an error while getting user name");
        return;
    }
#endif
}

static void cm_get_platform_name(void)
{
#ifdef WIN32
    static char *platform_name = "Windows";

    if (strncpy_s(g_platform_name, GS_NAME_BUFFER_SIZE, platform_name, strlen(platform_name)) != EOK) {
        GS_LOG_RUN_ERR("Secure C lib has thrown an error while getting platform name");
        return;
    }
#else
    FILE *fp = fopen("/etc/system-release", "r");
    if (fp == NULL) {
        fp = fopen("/etc/SuSE-release", "r");
        if (fp == NULL) {
            g_platform_name[0] = '\0';
            return;
        }
    }

    if (fgets(g_platform_name, sizeof(g_platform_name) - 1, fp) == NULL) {
        g_platform_name[0] = '\0';
    }
    fclose(fp);
#endif
}

status_t cm_get_host_ip(char *ipstr, uint32 len)
{
    errno_t errcode;
#ifdef WIN32
    errcode = strncpy_s(ipstr, len, LOOPBACK_ADDRESS, strlen(LOOPBACK_ADDRESS));
    if (errcode != EOK) {
        return GS_ERROR;
    }
#else
    struct ifaddrs *ifa = NULL;
    struct ifaddrs *if_list = NULL;
    if (getifaddrs(&if_list) == -1) {
        return GS_FALSE;
    }
    for (ifa = if_list; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }
        sa_family_t family = ifa->ifa_addr->sa_family;

        if (family == AF_INET || family == AF_INET6) {
            (void)cm_inet_ntop(ifa->ifa_addr, ipstr, len);
            break;
        }
    }
    if (ipstr[0] == '\0') {
        errcode = strncpy_s(ipstr, len, LOOPBACK_ADDRESS, strlen(LOOPBACK_ADDRESS));
        if (errcode != EOK) {
            freeifaddrs(if_list);
            return GS_ERROR;
        }
    }
    freeifaddrs(if_list);
#endif
    return GS_SUCCESS;
}

static void cm_get_sys_nprocs(void)
{
#ifdef WIN32
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    g_nprocs = (uint32)info.dwNumberOfProcessors;
#else
    g_nprocs = (uint32)get_nprocs();
#endif // WIN32
}

void cm_try_init_system(void)
{
    if (g_system_initialized) {
        return;
    }

    cm_spin_lock(&g_system_lock, NULL);

    if (g_system_initialized) {
        cm_spin_unlock(&g_system_lock);
        return;
    }

    cm_get_process_id();
    cm_get_host_name();
    cm_get_user_name();
    cm_get_program_name();
    cm_get_platform_name();
    cm_get_sys_nprocs();

    g_system_initialized = GS_TRUE;

    cm_spin_unlock(&g_system_lock);
}

uint64 cm_sys_pid(void)
{
    cm_try_init_system();
    return g_process_id;
}

char *cm_sys_program_name(void)
{
    cm_try_init_system();
    return g_program_name;
}

char *cm_sys_user_name(void)
{
    cm_try_init_system();
    return g_user_name;
}

char *cm_sys_host_name(void)
{
    cm_try_init_system();
    return g_host_name;
}

char *cm_sys_platform_name(void)
{
    cm_try_init_system();
    return g_platform_name;
}

#ifdef WIN32

static time_t cm_convert_filetime(FILETIME *ft)
{
    ULARGE_INTEGER ull;
    CM_POINTER(ft);
    ull.LowPart = ft->dwLowDateTime;
    ull.HighPart = ft->dwHighDateTime;
    return ull.QuadPart / 10000000ULL - 11644473600ULL;
}
#endif

int64 cm_sys_process_start_time(uint64 pid)
{
#ifdef WIN32
    FILETIME create_time, exit_time, kernel_time, user_time;

    HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
    if (handle == 0) {
        return 0;
    }

    if (GetProcessTimes(handle, &create_time, &exit_time, &kernel_time, &user_time) != 0) {
        CloseHandle(handle);
        return 0;
    }

    CloseHandle(handle);
    return (int64)cm_convert_filetime(&create_time);

#else
    char path[32] = {0};
    char stat_buf[2048];
    int32 size, ret;
    int64 ticks;
    text_t stat_text, ticks_text;
    int iret_snprintf;

    iret_snprintf = snprintf_s(path, sizeof(path), sizeof(path) - 1, "/proc/%llu/stat", pid);
    if (SECUREC_UNLIKELY(iret_snprintf == -1)) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
        return 0;
    }
    int32 fd = open(path, O_RDONLY);
    if (fd == -1) {
        return 0;
    }

    size = (int32)read(fd, stat_buf, sizeof(stat_buf) - 1);
    if (size == -1) {
        ret = close(fd);
        if (ret != 0) {
            GS_LOG_RUN_ERR("failed to close file with handle %d, error code %d", fd, errno);
        }
        return 0;
    }

    ret = close(fd);
    if (ret != 0) {
        GS_LOG_RUN_ERR("failed to close file with handle %d, error code %d", fd, errno);
    }
    stat_buf[size] = '\0';
    cm_str2text_safe(stat_buf, strlen(stat_buf), &stat_text);

    /* remove first section */
    for (uint32 i = 0; i <= 21; ++i) {
        (void)cm_fetch_text(&stat_text, ' ', '\0', &ticks_text);
    }
    /*
    * Time the process started after system boot.
    * The value is expressed in clock ticks.
    */
    (void)cm_text2bigint(&ticks_text, &ticks);
    return ticks;
#endif
}

bool32 cm_sys_process_alived(uint64 pid, int64 start_time)
{
    int64 process_time = cm_sys_process_start_time(pid);

#ifdef WIN32
    return (llabs(start_time - process_time) <= 1);

#else
    return (start_time == process_time);
#endif
}

uint32 cm_sys_get_nprocs(void)
{
    cm_try_init_system();
    return g_nprocs;
}

#ifndef WIN32
status_t cm_get_file_host_name(char *path, char *host_name)
{
    struct stat st;
    if (stat(path, &st) == GS_ERROR) {
        return GS_ERROR;
    }
    struct passwd *pw = getpwuid(st.st_uid);
    uint32 name_len;
    if (pw == NULL) {
        host_name[0] = '\0';
        return GS_SUCCESS;
    }
    name_len = strlen(pw->pw_name);
    MEMS_RETURN_IFERR(strncpy_s(host_name, GS_NAME_BUFFER_SIZE, pw->pw_name, name_len));
    
    return GS_SUCCESS;
}
#endif

#ifdef __cplusplus
}
#endif
