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
 * cm_coredump.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_coredump.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_CORE_DUMP_H_
#define __CM_CORE_DUMP_H_
#include "cm_base.h"
#include <stdlib.h>
#include <stdio.h>
#include "cm_types.h"
#include "cm_defs.h"

#define CRASH_SILENTLY 1
#if defined(_MSC_VER) && CRASH_SILENTLY
#include <windows.h>
#include <Dbghelp.h>
#include <tchar.h>

typedef BOOL (WINAPI *MINIDUMPWRITEDUMP)(HANDLE hProcess, DWORD dwPid, HANDLE hFile, MINIDUMP_TYPE DumpType,
                                        CONST PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
                                        CONST PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
                                        CONST PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

#define MAX_DUMP_FILE_NAME_LEN 1024
char g_dump_file_name[MAX_DUMP_FILE_NAME_LEN];

void create_minidump(EXCEPTION_POINTERS *apExceptionInfo)
{
    HMODULE mhLib = LoadLibrary(_T("dbghelp.dll"));
    MINIDUMPWRITEDUMP pDump = (MINIDUMPWRITEDUMP)GetProcAddress(mhLib, "MiniDumpWriteDump");

    HANDLE hFile = CreateFile(_T(g_dump_file_name), GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);

    MINIDUMP_EXCEPTION_INFORMATION ExInfo;
    ExInfo.ThreadId = GetCurrentThreadId();
    ExInfo.ExceptionPointers = apExceptionInfo;
    ExInfo.ClientPointers = FALSE;

    pDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, MiniDumpNormal, &ExInfo, NULL, NULL);
    CloseHandle(hFile);
}

static long __stdcall cm_crash_handler(EXCEPTION_POINTERS *excp)
{
    printf("Core dump happens! \n");
    printf("Error address   %p\n", excp->ExceptionRecord->ExceptionAddress);
    printf("CPU   register:\n");

#ifdef _WIN64
    printf("eax   %x   ebx   %x   ecx   %x   edx   %x\n",
        (uint32)excp->ContextRecord->Rax,
        (uint32)excp->ContextRecord->Rbx,
        (uint32)excp->ContextRecord->Rcx,
        (uint32)excp->ContextRecord->Rdx);
#else
    printf("eax   %x   ebx   %x   ecx   %x   edx   %x\n",
        (uint32)excp->ContextRecord->Eax,
        (uint32)excp->ContextRecord->Ebx,
        (uint32)excp->ContextRecord->Ecx,
        (uint32)excp->ContextRecord->Edx);
#endif // WIN64

    printf("The core file is \"%s\" \n", g_dump_file_name);
    create_minidump(excp);

    fflush(NULL);
    return EXCEPTION_EXECUTE_HANDLER;
}
#define SET_UNHANDLED_EXECEPTION_FILTER(core_dump_file)                                                      \
    do {                                                                                                     \
        (void)_getcwd(g_dump_file_name, MAX_DUMP_FILE_NAME_LEN);                                             \
        SetUnhandledExceptionFilter(cm_crash_handler);                                                       \
        MEMS_RETURN_IFERR(strcat_sp(g_dump_file_name, MAX_DUMP_FILE_NAME_LEN, "\\" core_dump_file ".dmp"));  \
    } while (0)

#else
#define SET_UNHANDLED_EXECEPTION_FILTER(core_dump_file)
#endif

#endif  // end __CM_CORE_DUMP_H_
