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
 * cms_blackbox.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_blackbox.c
 *
 * -------------------------------------------------------------------------
 */
#ifndef WIN32
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <ucontext.h>
#include "cms_log_module.h"
#include "cm_signal.h"
#include "cm_memory.h"
#include "cm_context_pool.h"
#include "cm_file.h"
#include "cm_timer.h"
#include "cm_system.h"
#include "cms_blackbox.h"

int32  g_sign_array[] = { SIGINT, SIGQUIT, SIGILL, SIGBUS,
                          SIGFPE, SIGSEGV, SIGALRM, SIGTERM,
                          SIGTSTP, SIGTTIN, SIGTTOU, SIGXCPU, SIGXFSZ,
                          SIGVTALRM, SIGPROF, SIGPWR, SIGSYS };

box_excp_item_t g_excep_info = {0};

#if (!defined(__cplusplus)) && (!defined(NO_CPP_DEMANGLE))
#define NO_CPP_DEMANGLE
#endif

#ifndef NO_CPP_DEMANGLE
#include <cxxabi.h>
#ifdef __cplusplus
using __cxxabiv1::__cxa_demangle;
#endif
#endif

#if (defined __x86_64__)
#define REGFORMAT "%s0x%016llx\n"
#elif (defined __aarch64__)
#define REGFORMAT "x[%02d]    0x%016llx\n"
#endif


const char *const g_known_signal_info[] = {
    "Signal 0 %d",
    "Hangup %d",
    "Interrupt %d",
    "Quit %d",
    "Illegal instruction %d",
    "Trace/breakpoint trap %d",
    "IOT trap %d",
    "EMT trap %d",
    "Floating point exception %d",
    "Killed %d",
    "Bus error %d",
    "Segmentation fault %d",
    "Bad system call %d",
    "Broken pipe %d",
    "Alarm clock %d",
    "Terminated %d",
    "Urgent I/O condition %d",
    "Stopped (signal) %d",
    "Stopped %d",
    "Continued %d",
    "Child exited %d",
    "Stopped (tty input) %d",
    "Stopped (tty output) %d",
    "I/O possible %d",
    "CPU time limit exceeded %d",
    "File size limit exceeded %d",
    "Virtual timer expired %d",
    "Profiling timer expired %d",
    "Window changed %d",
    "Resource lost %d",
    "User defined signal 1 %d",
    "User defined signal 2 %d",
    NULL
};
const char * const g_other_signal_formt = "Real-time signal %d";
const char * const g_unkown_signal_format = "Unknown signal %d";

void get_signal_info(int signum, char* buf, uint32 buf_size)
{
    const char *sig_info = NULL;
    int len;
    
    if (signum >= 0 && signum <= NSIG) {
        sig_info = g_known_signal_info[signum];
        if (sig_info != NULL) {
            len = snprintf_s (buf, buf_size, buf_size - 1, sig_info, signum);
            if (len < 0) {
                // ignore the error when call in blackbox
                buf[0] = 0x00;
            }
        }
    }
    
#ifdef SIGRTMIN
    if (sig_info == NULL) {
        if (signum >= SIGRTMIN && signum <= SIGRTMAX) {
            len = snprintf_s (buf, buf_size, buf_size - 1, g_other_signal_formt, signum);
            if (len < 0) {
                // ignore the error when call in blackbox
                buf[0] = 0x00;
            }
            sig_info = buf;
        }
    }
#endif

    if (sig_info == NULL) {
        len = snprintf_s (buf, buf_size, buf_size - 1, g_unkown_signal_format, signum);
        if (len < 0) {
            // ignore the error when call in blackbox
            buf[0] = 0x00;
        }
    }
}

static void print_sig_info(box_excp_item_t *excep_info, void  *cpu_info)
{
    CT_LOG_BLACKBOX("\n================= exception info =================\n");
    CT_LOG_BLACKBOX("Exception Date          = %s\n", excep_info->date);
    CT_LOG_BLACKBOX("Exception Number        = %d\n", excep_info->sig_index);
    CT_LOG_BLACKBOX("Exception Code          = %d\n", excep_info->sig_code);
    CT_LOG_BLACKBOX("Exception Name          = %s\n", excep_info->sig_name);
    CT_LOG_BLACKBOX("Exception Process       = 0x%016llx\n", excep_info->loc_id);
    CT_LOG_BLACKBOX("Exception Thread        = 0x%016llx\n", (uint64)excep_info->thread_id);
    CT_LOG_BLACKBOX("Exception Process name  = %s\n", excep_info->loc_name);
    CT_LOG_BLACKBOX("Version                 = %s\n", excep_info->version);
    CT_LOG_BLACKBOX("Platform                = %s\n", excep_info->platform);
    return;
}

static void print_reg(box_reg_info_t *reg_info)
{
    CT_LOG_BLACKBOX("\nRegister Contents:\n");
#if (defined __x86_64__)
    CT_LOG_BLACKBOX(REGFORMAT, "reg:  RAX    ", reg_info->rax);
    CT_LOG_BLACKBOX(REGFORMAT, "reg:  RBX    ", reg_info->rbx);
    CT_LOG_BLACKBOX(REGFORMAT, "reg:  RCX    ", reg_info->rcx);
    CT_LOG_BLACKBOX(REGFORMAT, "reg:  RDX    ", reg_info->rdx);
    CT_LOG_BLACKBOX(REGFORMAT, "reg:  RSI    ", reg_info->rsi);
    CT_LOG_BLACKBOX(REGFORMAT, "reg:  RDI    ", reg_info->rdi);
    CT_LOG_BLACKBOX(REGFORMAT, "reg:  RBP    ", reg_info->rbp);
    CT_LOG_BLACKBOX(REGFORMAT, "reg:  RSP    ", reg_info->rsp);

    CT_LOG_BLACKBOX(REGFORMAT, "reg:  R8     ", reg_info->r8);
    CT_LOG_BLACKBOX(REGFORMAT, "reg:  R9     ", reg_info->r9);
    CT_LOG_BLACKBOX(REGFORMAT, "reg:  R10    ", reg_info->r10);
    CT_LOG_BLACKBOX(REGFORMAT, "reg:  R11    ", reg_info->r11);
    CT_LOG_BLACKBOX(REGFORMAT, "reg:  R12    ", reg_info->r12);
    CT_LOG_BLACKBOX(REGFORMAT, "reg:  R13    ", reg_info->r13);
    CT_LOG_BLACKBOX(REGFORMAT, "reg:  R14    ", reg_info->r14);
    CT_LOG_BLACKBOX(REGFORMAT, "reg:  R15    ", reg_info->r15);

    CT_LOG_BLACKBOX(REGFORMAT, "reg:  RIP    ", reg_info->rip);
    CT_LOG_BLACKBOX(REGFORMAT, "reg:  EFLAGS ", reg_info->eflags);
    CT_LOG_BLACKBOX(REGFORMAT, "reg:  CS     ", reg_info->cs);
    CT_LOG_BLACKBOX(REGFORMAT, "reg:  ERR    ", reg_info->err);
    CT_LOG_BLACKBOX(REGFORMAT, "reg:  TRAPNO ", reg_info->trapno);
    CT_LOG_BLACKBOX(REGFORMAT, "reg:  OM     ", reg_info->oldmask);
    CT_LOG_BLACKBOX(REGFORMAT, "reg:  CR2    ", reg_info->cr2);

#elif (defined __aarch64__)
    for (uint32 i = 0; i < BOX_ARM_REG_NUM; i++) {
        CT_LOG_BLACKBOX(REGFORMAT, i, reg_info->reg[i]);
    }

    CT_LOG_BLACKBOX("sp       0x%016llx\n", reg_info->sp);
    CT_LOG_BLACKBOX("pc       0x%016llx\n", reg_info->pc);
#endif
}

/* This block is used as resident memory, mainly to prevent exception handling,
   in the application of memory, again generate an exception */
static status_t proc_sign_init(void)
{
    errno_t ret = memset_s(&g_excep_info, sizeof(box_excp_item_t), 0, sizeof(box_excp_item_t));
    if (ret != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void proc_get_register_info(box_reg_info_t *cpu_info, ucontext_t *uc)
{
    if ((cpu_info == NULL) || (uc == NULL)) {
        return;
    }

#if (defined __x86_64__)
    cpu_info->rax = uc->uc_mcontext.gregs[REG_RAX];
    cpu_info->rbx = uc->uc_mcontext.gregs[REG_RBX];
    cpu_info->rcx = uc->uc_mcontext.gregs[REG_RCX];
    cpu_info->rdx = uc->uc_mcontext.gregs[REG_RDX];
    cpu_info->rsi = uc->uc_mcontext.gregs[REG_RSI];
    cpu_info->rdi = uc->uc_mcontext.gregs[REG_RDI];
    cpu_info->rbp = uc->uc_mcontext.gregs[REG_RBP];
    cpu_info->rsp = uc->uc_mcontext.gregs[REG_RSP];

    cpu_info->r8  = uc->uc_mcontext.gregs[REG_R8];
    cpu_info->r9  = uc->uc_mcontext.gregs[REG_R9];
    cpu_info->r10 = uc->uc_mcontext.gregs[REG_R10];
    cpu_info->r11 = uc->uc_mcontext.gregs[REG_R11];
    cpu_info->r12 = uc->uc_mcontext.gregs[REG_R12];
    cpu_info->r13 = uc->uc_mcontext.gregs[REG_R13];
    cpu_info->r14 = uc->uc_mcontext.gregs[REG_R14];
    cpu_info->r15 = uc->uc_mcontext.gregs[REG_R15];

    cpu_info->rip     = uc->uc_mcontext.gregs[REG_RIP];
    cpu_info->eflags  = uc->uc_mcontext.gregs[REG_EFL];
    cpu_info->cs      = uc->uc_mcontext.gregs[REG_CSGSFS];
    cpu_info->err     = uc->uc_mcontext.gregs[REG_ERR];
    cpu_info->trapno  = uc->uc_mcontext.gregs[REG_TRAPNO];
    cpu_info->oldmask = uc->uc_mcontext.gregs[REG_OLDMASK];
    cpu_info->cr2     = uc->uc_mcontext.gregs[REG_CR2];
    
#elif (defined __aarch64__)
        for (uint32 i = 0; i < BOX_ARM_REG_NUM; i++) {
            cpu_info->reg[i] = uc->uc_mcontext.regs[i];
        }
        cpu_info->sp = uc->uc_mcontext.sp;
        cpu_info->pc = uc->uc_mcontext.pc;
#endif

    return;
}

void proc_sig_get_header(box_excp_item_t *excep_info, int32 sig_num,
                         siginfo_t *siginfo, void *context)
{
    uint32  loop = 0;
    box_excp_item_t *buff = excep_info;
    char signal_name[CT_NAME_BUFFER_SIZE];
    char *platform_name = NULL;
    char *loc_name = NULL;
    buff->magic    = (uint32)BOX_EXCP_MAGIC;
    buff->trace_tail[loop] = (uint32)BOX_EXCP_TO_LOG;

    for (loop = 1; loop < BOX_SPACE_SIZE; loop++) {
        buff->trace_tail[loop] = (uint32)BOX_TAIL_MAGIC;
    }

    signal_name[0] = 0x00;
    get_signal_info(sig_num, signal_name, sizeof(signal_name) - 1);
    int ret = strncpy_s(buff->sig_name, CT_NAME_BUFFER_SIZE, signal_name, strlen(signal_name));
    MEMS_RETVOID_IFERR(ret);
    buff->sig_index = sig_num;

    buff->loc_id  = cm_sys_pid();
    buff->thread_id = pthread_self();
    platform_name = cm_sys_platform_name();
    ret = strncpy_s(buff->platform, CT_NAME_BUFFER_SIZE, platform_name, strlen(platform_name));
    MEMS_RETVOID_IFERR(ret);
    
    loc_name = cm_sys_program_name();
    ret = strncpy_s(buff->loc_name, CT_FILE_NAME_BUFFER_SIZE + 1, loc_name, strlen(loc_name));
    MEMS_RETVOID_IFERR(ret);
    
    if (siginfo != NULL) {
        buff->sig_code = siginfo->si_code;
    }
    (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", buff->date, CT_MAX_TIME_STRLEN);
    return;
}

bool32 check_stack_is_available(uintptr_t *sp, uint32 *max_dump_len)
{
    size_t  stacksize = 0;
    void   *stack_top_addr  = NULL;
    uintptr_t safe_addr;
    uintptr_t stack_end;
    pthread_attr_t thread_attr;
    uintptr_t sub_sp = *sp - 512;
    *max_dump_len = BOX_STACK_SIZE;
    status_t ret = pthread_getattr_np((pthread_t)pthread_self(), &thread_attr);
    if (ret != CT_SUCCESS) {
        return CT_TRUE;
    }
     
    ret = pthread_attr_getstack(&thread_attr, &stack_top_addr, &stacksize);
    if (ret != CT_SUCCESS) {
        return CT_TRUE;
    }
    /* thread guard size */
    safe_addr = (uintptr_t)stack_top_addr + CT_DFLT_THREAD_GUARD_SIZE;
    stack_end = (uintptr_t)stack_top_addr + stacksize;

    if ((sub_sp > safe_addr) && (sub_sp < stack_end)) {
        *sp = sub_sp;
        /* print 512---sp---1024 default stack contect */
        if ((stack_end - sub_sp) < BOX_STACK_SIZE) {
            *max_dump_len = stack_end - sub_sp;
        }
        return CT_TRUE;
    }

    *sp = stack_end - BOX_STACK_SIZE;

    return CT_FALSE;
}


uintptr_t proc_get_stack_point(box_reg_info_t *reg_info, uint32 *max_dump_len)
{
    uintptr_t sp;

#if (defined __x86_64__)
    sp = (uintptr_t)reg_info->rsp;
#elif (defined __aarch64__)
    sp = (uintptr_t)reg_info->reg[BOX_ARM_RSP_LOC];
#endif
    
    (void)check_stack_is_available(&sp, max_dump_len);
    
    return sp;
}

static void save_proc_maps_file(box_excp_item_t *excep_info)
{
    int32 fd;
    int32 cnt;
    char buffer[512] = {0};
   
    (void)sprintf_s(buffer, sizeof(buffer), "/proc/%u/maps", (uint32)excep_info->loc_id);

    CT_LOG_BLACKBOX("\nProc maps information:\n");

    if (cm_open_file_ex(buffer, O_SYNC | O_RDONLY | O_BINARY, S_IRUSR, &fd) != CT_SUCCESS) {
        return;
    }
    cnt = read(fd, buffer, sizeof(buffer) - 1);
    while (cnt > 0) {
        ((char *)buffer)[cnt] = '\0';
        CT_LOG_BLACKBOX("%s", buffer);
        cnt = read(fd, buffer, sizeof(buffer) - 1);
    }
    
    CT_LOG_BLACKBOX("\n");
    cm_close_file(fd);

    return;
}


uint32 g_sign_mutex = 0;
void proc_sign_func(int32 sig_num, siginfo_t *siginfo, void *context)
{
    box_excp_item_t *excep_info = &g_excep_info;
    uint64 locId = 0;
    sigset_t sign_old_mask;
    sigset_t sign_mask;
    uint32 max_dump_len = 0;
    char signal_name[CT_NAME_BUFFER_SIZE] = { 0 };
    char date[CT_MAX_TIME_STRLEN] = { 0 };

    if (g_sign_mutex != 0) {
        return;
    }
    
    g_sign_mutex = 1;
    
    (void)sigprocmask(0, NULL, &sign_old_mask);
    (void)sigfillset(&sign_mask);
    (void)sigprocmask(SIG_SETMASK, &sign_mask, NULL);
 
    if (sig_num == SIGALRM || sig_num == SIGTSTP || sig_num == SIGTTIN || sig_num == SIGTERM ||
        sig_num == SIGTTOU || sig_num == SIGVTALRM || sig_num == SIGPROF || sig_num == SIGPWR) {
        locId = cm_sys_pid();
        get_signal_info(sig_num, signal_name, sizeof(signal_name) - 1);
        (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", date, CT_MAX_TIME_STRLEN);
        CT_LOG_BLACKBOX("Location[0x%016llx] has been terminated, signal name : %s, current date : %s\n",
            locId, signal_name, date);
        cm_fync_logfile();
        return;
    }
    
    if (excep_info != NULL) {
        cm_reset_error();

        errno_t ret = memset_sp((void *)excep_info, sizeof(box_excp_item_t), 0, sizeof(box_excp_item_t));
        MEMS_RETVOID_IFERR(ret);
         
        proc_sig_get_header(excep_info, sig_num, siginfo, context);

        proc_get_register_info(&(excep_info->reg_info), (ucontext_t *)context);
        
        print_sig_info(excep_info, (void *)&(excep_info->reg_info));

        print_reg(&excep_info->reg_info);

        cm_print_call_link(CT_DEFAUT_BLACK_BOX_DEPTH);
        
        excep_info->stack_addr  = proc_get_stack_point(&(excep_info->reg_info), &max_dump_len);
        ret = memcpy_s(excep_info->stack_memory, BOX_STACK_SIZE, (const void *)excep_info->stack_addr, max_dump_len);
        MEMS_RETVOID_IFERR(ret);
        
        CT_LOG_BLACKBOX("\nDump stack(total %dBytes,  %dBytes/line:\n", BOX_STACK_SIZE, STACK_SIZE_EACH_ROW);
        CT_UTIL_DUMP_MEM((void *)excep_info->stack_addr, BOX_STACK_SIZE);

        save_proc_maps_file(excep_info);
    }
    
    g_sign_mutex = 0;
    
    /* At last recover the sigset */
    (void)sigprocmask(SIG_SETMASK, &sign_old_mask, NULL);
    cm_fync_logfile();
    return;
}

static status_t sigcap_reg_proc(int32 sig_num)
{
    status_t uiRetCode;

    uiRetCode = cm_regist_signal_ex(sig_num, proc_sign_func);
    if (uiRetCode != CT_SUCCESS) {
        CT_LOG_DEBUG_ERR("[DBG] Register the signal cap failed:%d", sig_num);
        return CT_ERROR;
    }

    CT_LOG_DEBUG_INF("[DBG] Register the signal cap success:%d", sig_num);
    return CT_SUCCESS;
}


status_t sigcap_handle_reg(void)
{
    if (proc_sign_init() != CT_SUCCESS) {
        return CT_ERROR;
    }
    // Ensure that backtrace is loaded successfully.
    void *array[CT_MAX_BLACK_BOX_DEPTH] = {0};
    size_t size;
    size = backtrace(array, CT_MAX_BLACK_BOX_DEPTH);
    log_file_handle_t *log_file_handle = cm_log_logger_file(LOG_BLACKBOX);
    backtrace_symbols_fd(array, size, log_file_handle->file_handle);

    for (uint32 temp = 0; temp < ARRAY_NUM(g_sign_array); temp++) {
        if (sigcap_reg_proc(g_sign_array[temp]) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
        
    /*
     * In some scenarios, for example, after executing the 'expect' command in a shell, SIGHUP signal will be
     * sent to the application, causing the database process to be killed. So SIGHUP should not captured here.
     */
    (void)signal(SIGINT, SIG_DFL);
    return CT_SUCCESS;
}

#endif