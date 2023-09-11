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
 * srv_blackbox.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_blackbox.c
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
#include "cm_signal.h"
#include "cm_memory.h"
#include "cm_context_pool.h"
#include "cm_file.h"
#include "srv_instance.h"
#include "srv_blackbox.h"
const char* g_hook_func_desc[HOOK_FUNC_TAIL] = {
    "sql",
    "kernel",
};

int32  g_sign_array[] = { SIGINT, SIGQUIT, SIGILL, SIGBUS,
                          SIGFPE, SIGSEGV, SIGALRM, SIGTERM,
                          SIGTSTP, SIGTTIN, SIGTTOU, SIGXCPU, SIGXFSZ,
                          SIGVTALRM, SIGPROF, SIGPWR, SIGSYS };

box_excp_item_t g_excep_info = { 0 };

/* app register sig process function */
signal_handle_hook_func   g_app_sig_func[SIGMAX][HOOK_FUNC_TAIL] = {0};

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

void get_signal_info(int signum, char *buf, uint32 buf_size)
{
    const char *sig_info = NULL;
    int len;

    if (signum >= 0 && signum <= NSIG) {
        sig_info = g_known_signal_info[signum];
        if (sig_info != NULL) {
            len = snprintf_s(buf, buf_size, buf_size - 1, sig_info, signum);
            if (len < 0) {
                // ignore the error when call in blackbox
                buf[0] = 0x00;
            }
        }
    }

#ifdef SIGRTMIN
    if (sig_info == NULL) {
        if (signum >= SIGRTMIN && signum <= SIGRTMAX) {
            len = snprintf_s(buf, buf_size, buf_size - 1, g_other_signal_formt, signum);
            if (len < 0) {
                // ignore the error when call in blackbox
                buf[0] = 0x00;
            }
            sig_info = buf;
        }
    }
#endif

    if (sig_info == NULL) {
        len = snprintf_s(buf, buf_size, buf_size - 1, g_unkown_signal_format, signum);
        if (len < 0) {
            // ignore the error when call in blackbox
            buf[0] = 0x00;
        }
    }
}

static void print_signal_info(box_excp_item_t *excep_info, void *cpu_info)
{
    GS_LOG_BLACKBOX("\n================= exception info =================\n");
    GS_LOG_BLACKBOX("Exception Date          = %s\n", excep_info->date);
    GS_LOG_BLACKBOX("Exception Number        = %d\n", excep_info->sig_index);
    GS_LOG_BLACKBOX("Exception Code          = %d\n", excep_info->sig_code);
    GS_LOG_BLACKBOX("Exception Name          = %s\n", excep_info->sig_name);
    GS_LOG_BLACKBOX("Exception Process       = 0x%016llx\n", excep_info->loc_id);
    GS_LOG_BLACKBOX("Exception Thread        = 0x%016llx\n", (uint64)excep_info->thread_id);
    GS_LOG_BLACKBOX("Exception Process name  = %s\n", excep_info->loc_name);
    GS_LOG_BLACKBOX("Version                 = %s\n", excep_info->version);
    GS_LOG_BLACKBOX("Platform                = %s\n", excep_info->platform);
    return;
}

static void print_register(box_reg_info_t *reg_info)
{
    GS_LOG_BLACKBOX("\nRegister Contents:\n");
#if (defined __x86_64__)
    GS_LOG_BLACKBOX(REGFORMAT, "reg:  RAX    ", reg_info->rax);
    GS_LOG_BLACKBOX(REGFORMAT, "reg:  RBX    ", reg_info->rbx);
    GS_LOG_BLACKBOX(REGFORMAT, "reg:  RCX    ", reg_info->rcx);
    GS_LOG_BLACKBOX(REGFORMAT, "reg:  RDX    ", reg_info->rdx);
    GS_LOG_BLACKBOX(REGFORMAT, "reg:  RSI    ", reg_info->rsi);
    GS_LOG_BLACKBOX(REGFORMAT, "reg:  RDI    ", reg_info->rdi);
    GS_LOG_BLACKBOX(REGFORMAT, "reg:  RBP    ", reg_info->rbp);
    GS_LOG_BLACKBOX(REGFORMAT, "reg:  RSP    ", reg_info->rsp);

    GS_LOG_BLACKBOX(REGFORMAT, "reg:  R8     ", reg_info->r8);
    GS_LOG_BLACKBOX(REGFORMAT, "reg:  R9     ", reg_info->r9);
    GS_LOG_BLACKBOX(REGFORMAT, "reg:  R10    ", reg_info->r10);
    GS_LOG_BLACKBOX(REGFORMAT, "reg:  R11    ", reg_info->r11);
    GS_LOG_BLACKBOX(REGFORMAT, "reg:  R12    ", reg_info->r12);
    GS_LOG_BLACKBOX(REGFORMAT, "reg:  R13    ", reg_info->r13);
    GS_LOG_BLACKBOX(REGFORMAT, "reg:  R14    ", reg_info->r14);
    GS_LOG_BLACKBOX(REGFORMAT, "reg:  R15    ", reg_info->r15);

    GS_LOG_BLACKBOX(REGFORMAT, "reg:  RIP    ", reg_info->rip);
    GS_LOG_BLACKBOX(REGFORMAT, "reg:  EFLAGS ", reg_info->eflags);
    GS_LOG_BLACKBOX(REGFORMAT, "reg:  CS     ", reg_info->cs);
    GS_LOG_BLACKBOX(REGFORMAT, "reg:  ERR    ", reg_info->err);
    GS_LOG_BLACKBOX(REGFORMAT, "reg:  TRAPNO ", reg_info->trapno);
    GS_LOG_BLACKBOX(REGFORMAT, "reg:  OM     ", reg_info->oldmask);
    GS_LOG_BLACKBOX(REGFORMAT, "reg:  CR2    ", reg_info->cr2);

#elif (defined __aarch64__)
    for (uint32 i = 0; i < 31; i++) {
        GS_LOG_BLACKBOX(REGFORMAT, i, reg_info->reg[i]);
    }

    GS_LOG_BLACKBOX("sp       0x%016llx\n", reg_info->sp);
    GS_LOG_BLACKBOX("pc       0x%016llx\n", reg_info->pc);
#endif
}

static char *get_session_status(session_t *session)
{
    if (session->knl_session.canceled) {
        return "CANCELED";
    } else if (session->knl_session.killed) {
        return "KILLED";
    }

    switch (session->knl_session.status) {
        case SESSION_INACTIVE:
            return "INACTIVE";
        case SESSION_ACTIVE:
            return "ACTIVE";
        case SESSION_SUSPENSION:
            return "SUSPENSION";
        default:
            return "UNKNOWN";
    }
}

static void print_session_info(session_t *session)
{
    char ip_str[CM_MAX_IP_LEN] = { 0 };
    GS_LOG_BLACKBOX("\n================= session info =================\n");
    GS_LOG_BLACKBOX("session id             %u\n", session->knl_session.id);
    GS_LOG_BLACKBOX("session serial#        %u\n", session->knl_session.serial_id);
    GS_LOG_BLACKBOX("session type           %d\n", session->type);
    if (session->type == SESSION_TYPE_USER || session->type == SESSION_TYPE_EMERG) {
        GS_LOG_BLACKBOX("session user           %s\n", session->db_user);
        GS_LOG_BLACKBOX("session schema         %s\n", session->curr_schema);
        GS_LOG_BLACKBOX("session osuser         %s\n", session->os_user);
        GS_LOG_BLACKBOX("session machine        %s\n", session->os_host);
        GS_LOG_BLACKBOX("session program        %s\n", session->os_prog);
        GS_LOG_BLACKBOX("session module         %d\n", session->client_kind);
        GS_LOG_BLACKBOX("session client version %d\n", (int32)session->client_version);
        GS_LOG_BLACKBOX("session call version   %d\n", (int32)session->call_version);
        GS_LOG_BLACKBOX("session status         %s\n", get_session_status(session));
        if (session->pipe->type == CS_TYPE_TCP || session->pipe->type == CS_TYPE_SSL) {
            GS_LOG_BLACKBOX("session client ip      %s\n",
                cm_inet_ntop(SOCKADDR(SESSION_TCP_REMOTE(session)), ip_str, CM_MAX_IP_LEN));
            GS_LOG_BLACKBOX("session client port    %d\n", ntohs(SOCKADDR_PORT(SESSION_TCP_REMOTE(session))));
            GS_LOG_BLACKBOX("session server ip      %s\n",
                cm_inet_ntop(SOCKADDR(SESSION_TCP_LOCAL(session)), ip_str, CM_MAX_IP_LEN));
            GS_LOG_BLACKBOX("session server port    %d\n", ntohs(SOCKADDR_PORT(SESSION_TCP_LOCAL(session))));
        }
    }
}

static void print_sql_info(session_t *session)
{
    text_t sql;
    sql_stmt_t *stmt = session->current_stmt;
    text_buf_t buffer;

    if (stmt == NULL || stmt->lang_type != LANG_DML) {
        return;
    }

    if (stmt->context != NULL && !stmt->context->ctrl.is_free && stmt->context->ctrl.valid &&
        stmt->context->in_sql_pool) {
        sql.len = stmt->context->ctrl.text_size + 1;
        if (sql_push(stmt, sql.len, (void **)&sql.str) != GS_SUCCESS ||
            ctx_read_text(sql_pool, &stmt->context->ctrl, &sql, GS_FALSE) != GS_SUCCESS) {
            ctx_read_first_page_text(sql_pool, &stmt->context->ctrl, &sql);
        }
    } else {
        if (session->lex == NULL || lex_is_empty(session->lex)) {
            return;
        }

        sql.str = session->lex->text.str;
        sql.len = session->lex->text.len;
    }

    GS_LOG_BLACKBOX("\n================= sql info =================\n");
    GS_LOG_BLACKBOX("current sql             %s\n", T2S(&sql));

    if (stmt->status >= STMT_STATUS_PREPARED && stmt->context != NULL && stmt->context->params->count != 0) {
        for (uint32 i = 0; i < stmt->context->params->count; i++) {
            sql_param_t *param = &stmt->param_info.params[i];
            char *data = NULL;
            uint32 length = 0;
            variant_t *value = &param->value;
            if (value->is_null) {
                GS_LOG_BLACKBOX("PARAM-VALUE:id=[%u], direct=[%d], type=[%d], len=[%d], value=[NULL] \n", i,
                    param->direction, value->type, -1);
                continue;
            }
            CM_INIT_TEXTBUF(&buffer, GS_T2S_LARGER_BUFFER_SIZE, g_tls_error.t2s_buf1);
            switch (value->type) {
                case GS_TYPE_UINT32:
                case GS_TYPE_INTEGER:
                case GS_TYPE_BIGINT:
                case GS_TYPE_REAL:
                case GS_TYPE_NUMBER:
                case GS_TYPE_DECIMAL:
                case GS_TYPE_NUMBER2:
                case GS_TYPE_DATE:
                case GS_TYPE_TIMESTAMP:
                case GS_TYPE_BOOLEAN:
                case GS_TYPE_TIMESTAMP_TZ_FAKE:
                case GS_TYPE_TIMESTAMP_TZ:
                case GS_TYPE_TIMESTAMP_LTZ:
                    if (var_as_string(SESSION_NLS(stmt), value, &buffer) != GS_SUCCESS) {
                        continue;
                    }
                    data = value->v_text.str;
                    length = value->v_text.len;
                    break;

                case GS_TYPE_BINARY:
                case GS_TYPE_VARBINARY:
                case GS_TYPE_RAW:
                    if (var_as_string(SESSION_NLS(stmt), value, &buffer) != GS_SUCCESS) {
                        continue;
                    }

                    data = value->v_text.str;
                    length = value->v_text.len;
                    break;

                case GS_TYPE_CLOB:
                case GS_TYPE_BLOB:
                case GS_TYPE_IMAGE:
                    data = "LOB";
                    length = 3;
                    break;

                case GS_TYPE_CHAR:
                case GS_TYPE_VARCHAR:
                case GS_TYPE_STRING:
                    data = value->v_text.str;
                    length = value->v_text.len;
                    break;

                default:
                    GS_LOG_BLACKBOX("PARAM-VALUE:id=[%u], direct=[%d], type=[%d], len=[-2], value=[NULL] \n", i,
                        param->direction, value->type);
            }

            if (!GS_IS_LOB_TYPE(value->type) && length > 0 && data != NULL) {
                data[length] = '\0';
            }

            GS_LOG_BLACKBOX("PARAM-VALUE:id=[%u], direct=[%d], type=[%d], len=[%u], value=[%s] \n", i, param->direction,
                value->type, length, (length == 0) ? "" : data);
        }
    }
}

void sql_signal_hook(box_excp_item_t *excep_info, int signo, siginfo_t *siginfo, void *context)
{
    session_t *session = knl_get_curr_sess();
    if (session == NULL || session->is_free || session->agent == NULL ||
        session->agent->thread.id != excep_info->thread_id) {
        return;
    }

    /* 1. session info info */
    print_session_info(session);

    /* 2. execute sql and binding parameter */
    print_sql_info(session);

    /* 3. print vm memory */
    _protech_vm_print_stack();
}


status_t reg_signal_proc(int32 sig, signal_handle_hook_func func, hook_func_type_t type)
{
    if ((func == NULL) || (sig >= SIGMAX) || type >= HOOK_FUNC_TAIL) {
        return GS_ERROR;
    }

    GS_LOG_DEBUG_INF("App reg sig proc func, signal is %d, type %s.", sig, g_hook_func_desc[type]);

    g_app_sig_func[sig][type] = func;
    return GS_SUCCESS;
}


status_t unreg_signal_proc(int32 sig, hook_func_type_t type)
{
    if (sig >= SIGMAX || type >= HOOK_FUNC_TAIL) {
        return GS_ERROR;
    }

    GS_LOG_DEBUG_INF("App un reg sig proc func, signal is %d, type %s.", sig, g_hook_func_desc[type]);

    g_app_sig_func[sig][type] = NULL;
    return GS_SUCCESS;
}

/* This block is used as resident memory, mainly to prevent exception handling,
   in the application of memory, again generate an exception */
static status_t proc_signal_init(void)
{
    errno_t ret = memset_s(&g_excep_info, sizeof(box_excp_item_t), 0, sizeof(box_excp_item_t));
    if (ret != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}


void proc_app_register(box_excp_item_t *excep_info, int32 sig_num, siginfo_t *siginfo, void *context)
{
    if (g_app_sig_func[sig_num] != NULL) {
        for (uint32 i = 0; i < HOOK_FUNC_TAIL; i++) {
            if (g_app_sig_func[sig_num][i] != NULL) {
                GS_LOG_BLACKBOX("start to process exception num %d, %s hook \n", sig_num, g_hook_func_desc[i]);
                g_app_sig_func[sig_num][i](excep_info, sig_num, siginfo, context);
                GS_LOG_BLACKBOX("end to process exception num %d, %s hook \n", sig_num, g_hook_func_desc[i]);
            }
        }
    }

    return;
}

void process_get_register_info(box_reg_info_t *cpu_info, ucontext_t *uc)
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

    cpu_info->r8 = uc->uc_mcontext.gregs[REG_R8];
    cpu_info->r9 = uc->uc_mcontext.gregs[REG_R9];
    cpu_info->r10 = uc->uc_mcontext.gregs[REG_R10];
    cpu_info->r11 = uc->uc_mcontext.gregs[REG_R11];
    cpu_info->r12 = uc->uc_mcontext.gregs[REG_R12];
    cpu_info->r13 = uc->uc_mcontext.gregs[REG_R13];
    cpu_info->r14 = uc->uc_mcontext.gregs[REG_R14];
    cpu_info->r15 = uc->uc_mcontext.gregs[REG_R15];

    cpu_info->rip = uc->uc_mcontext.gregs[REG_RIP];
    cpu_info->eflags = uc->uc_mcontext.gregs[REG_EFL];
    cpu_info->cs = uc->uc_mcontext.gregs[REG_CSGSFS];
    cpu_info->err = uc->uc_mcontext.gregs[REG_ERR];
    cpu_info->trapno = uc->uc_mcontext.gregs[REG_TRAPNO];
    cpu_info->oldmask = uc->uc_mcontext.gregs[REG_OLDMASK];
    cpu_info->cr2 = uc->uc_mcontext.gregs[REG_CR2];

#elif (defined __aarch64__)
    for (uint32 i = 0; i < 31; i++) {
        cpu_info->reg[i] = uc->uc_mcontext.regs[i];
    }
    cpu_info->sp = uc->uc_mcontext.sp;
    cpu_info->pc = uc->uc_mcontext.pc;
#endif

    return;
}

void proc_signal_get_header(box_excp_item_t *excep_info, int32 sig_num, siginfo_t *siginfo, void *context)
{
    uint32 loop = 0;
    box_excp_item_t *buff = excep_info;
    char signal_name[GS_NAME_BUFFER_SIZE];
    char *platform_name = NULL;
    char *loc_name = NULL;
    char *version = NULL;
    buff->magic = (uint32)BOX_EXCP_MAGIC;
    buff->trace_tail[loop] = (uint32)BOX_EXCP_TO_LOG;

    for (loop = 1; loop < BOX_SPACE_SIZE; loop++) {
        buff->trace_tail[loop] = (uint32)BOX_TAIL_MAGIC;
    }

    signal_name[0] = 0x00;
    get_signal_info(sig_num, signal_name, sizeof(signal_name) - 1);
    int ret = strncpy_s(buff->sig_name, GS_NAME_BUFFER_SIZE, signal_name, strlen(signal_name));
    knl_securec_check(ret);
    buff->sig_index = sig_num;

    version = cantiand_get_dbversion();
    ret = strncpy_s(buff->version, BOX_VERSION_LEN, version, strlen(version));
    knl_securec_check(ret);

    buff->loc_id = cm_sys_pid();
    buff->thread_id = pthread_self();
    platform_name = cm_sys_platform_name();
    ret = strncpy_s(buff->platform, GS_NAME_BUFFER_SIZE, platform_name, strlen(platform_name));
    knl_securec_check(ret);

    loc_name = cm_sys_program_name();
    ret = strncpy_s(buff->loc_name, GS_FILE_NAME_BUFFER_SIZE + 1, loc_name, strlen(loc_name));
    knl_securec_check(ret);

    if (siginfo != NULL) {
        buff->sig_code = siginfo->si_code;
    }
    (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", buff->date, GS_MAX_TIME_STRLEN);
    return;
}

bool32 check_stack_available(uintptr_t *sp, uint32 *max_dump_len)
{
    size_t stacksize = 0;
    void *stack_top_addr = NULL;
    uintptr_t safe_addr;
    uintptr_t stack_end;
    pthread_attr_t thread_attr;
    uintptr_t sub_sp = *sp - 512;
    *max_dump_len = BOX_STACK_SIZE;
    status_t ret = pthread_getattr_np((pthread_t)pthread_self(), &thread_attr);
    if (ret != GS_SUCCESS) {
        return GS_TRUE;
    }

    ret = pthread_attr_getstack(&thread_attr, &stack_top_addr, &stacksize);
    if (ret != GS_SUCCESS) {
        return GS_TRUE;
    }
    /* thread guard size */
    safe_addr = (uintptr_t)stack_top_addr + GS_DFLT_THREAD_GUARD_SIZE;
    stack_end = (uintptr_t)stack_top_addr + stacksize;

    if ((sub_sp > safe_addr) && (sub_sp < stack_end)) {
        *sp = sub_sp;
        /* print 512---sp---1024 default stack contect */
        if ((stack_end - sub_sp) < BOX_STACK_SIZE) {
            *max_dump_len = stack_end - sub_sp;
        }
        return GS_TRUE;
    }

    *sp = stack_end - BOX_STACK_SIZE;

    return GS_FALSE;
}


uintptr_t process_get_stack_point(box_reg_info_t *reg_info, uint32 *max_dump_len)
{
    uintptr_t sp;

#if (defined __x86_64__)
    sp = (uintptr_t)reg_info->rsp;
#elif (defined __aarch64__)
    sp = (uintptr_t)reg_info->reg[29];
#endif

    (void)check_stack_available(&sp, max_dump_len);

    return sp;
}

static void save_process_maps_file(box_excp_item_t *excep_info)
{
    int32 fd;
    int32 cnt;
    char buffer[512] = {0};

    (void)sprintf_s(buffer, sizeof(buffer), "/proc/%u/maps", (uint32)excep_info->loc_id);

    GS_LOG_BLACKBOX("\nProc maps information:\n");

    if (cm_open_file_ex(buffer, O_SYNC | O_RDONLY | O_BINARY, S_IRUSR, &fd) != GS_SUCCESS) {
        return;
    }
    cnt = read(fd, buffer, sizeof(buffer) - 1);
    while (cnt > 0) {
        ((char *)buffer)[cnt] = '\0';
        GS_LOG_BLACKBOX("%s", buffer);
        cnt = read(fd, buffer, sizeof(buffer) - 1);
    }

    GS_LOG_BLACKBOX("\n");
    cm_close_file(fd);

    return;
}

#define CORE_DUMP_DATA_BUFFER (g_instance->attr.core_dump_config & 0x00000001)
#define CORE_DUMP_TMP_BUFFER (g_instance->attr.core_dump_config & 0x00000002)
#define CORE_DUMP_SHARED_POOL (g_instance->attr.core_dump_config & 0x00000004)
#define CORE_DUMP_LOG_BUFFER (g_instance->attr.core_dump_config & 0x00000008)
#define CORE_DUMP_CR_POOL (g_instance->attr.core_dump_config & 0x00000010)
#define CORE_DUMP_VAR_MEM (g_instance->attr.core_dump_config & 0x00000020)
#define CORE_DUMP_LARGE_VAR_MEM (g_instance->attr.core_dump_config & 0x00000040)
#define CORE_DUMP_LARGE_POOL (g_instance->attr.core_dump_config & 0x00000080)
#define CORE_DUMP_DBWR_BUFFER (g_instance->attr.core_dump_config & 0x00000100)
#define CORE_DUMP_TRAN_BUFFER (g_instance->attr.core_dump_config & 0x00000200)
#define CORE_DUMP_LGWR_BUFFER (g_instance->attr.core_dump_config & 0x00000400)
#define CORE_DUMP_INDEX_BUFFER (g_instance->attr.core_dump_config & 0x00000800)
#define CORE_DUMP_LGWR_ASYNC_BUFFER (g_instance->attr.core_dump_config & 0x00001000)
#define CORE_DUMP_LGWR_HEAD_BUFFER (g_instance->attr.core_dump_config & 0x00002000)
#define CORE_DUMP_LGWR_CIPHER_BUFFER (g_instance->attr.core_dump_config & 0x00004000)
#define CORE_DUMP_PMA_BUFFER (g_instance->attr.core_dump_config & 0x00008000)

static void cut_core_dump_log_writer(sga_t *sga, knl_instance_t *kernel)
{
    if (CORE_DUMP_LGWR_BUFFER) {
        mem_remove_from_coredump((void *)sga->lgwr_buf, kernel->attr.lgwr_buf_size);
    }
    if (CORE_DUMP_LGWR_CIPHER_BUFFER) {
        mem_remove_from_coredump((void *)sga->lgwr_cipher_buf, kernel->attr.lgwr_cipher_buf_size);
    }
    if (CORE_DUMP_LGWR_ASYNC_BUFFER) {
        mem_remove_from_coredump((void *)sga->lgwr_async_buf, kernel->attr.lgwr_async_buf_size);
    }
    if (CORE_DUMP_LGWR_HEAD_BUFFER) {
        mem_remove_from_coredump((void *)sga->lgwr_head_buf, kernel->attr.lgwr_head_buf_size);
    }
}

static void cut_core_dumpfile(void)
{
    sga_t *sga = &g_instance->sga;
    knl_instance_t *kernel = &g_instance->kernel;
    if (g_instance->attr.core_dump_config == 0) {
        return;
    }

    GS_LOG_RUN_ERR("start to cut dumpfile");
    if (CORE_DUMP_DATA_BUFFER) {
        mem_remove_from_coredump((void *)sga->data_buf, kernel->attr.data_buf_size);
    }
    if (CORE_DUMP_TMP_BUFFER) {
        mem_remove_from_coredump((void *)sga->temp_buf, kernel->attr.temp_buf_size);
    }
    if (CORE_DUMP_SHARED_POOL) {
        mem_remove_from_coredump((void *)sga->shared_buf, kernel->attr.shared_area_size);
    }
    if (CORE_DUMP_LOG_BUFFER) {
        mem_remove_from_coredump((void *)sga->log_buf, kernel->attr.log_buf_size);
    }
    if (CORE_DUMP_VAR_MEM) {
        mem_remove_from_coredump((void *)sga->vma_buf, kernel->attr.vma_size);
    }
    if (CORE_DUMP_LARGE_VAR_MEM) {
        mem_remove_from_coredump((void *)sga->vma_large_buf, kernel->attr.large_vma_size);
    }
    if (CORE_DUMP_LARGE_POOL) {
        mem_remove_from_coredump((void *)sga->large_buf, kernel->attr.large_pool_size);
    }
    if (CORE_DUMP_DBWR_BUFFER) {
        mem_remove_from_coredump((void *)sga->dbwr_buf, kernel->attr.dbwr_buf_size);
    }
    if (CORE_DUMP_TRAN_BUFFER) {
        mem_remove_from_coredump((void *)sga->tran_buf, kernel->attr.tran_buf_size);
    }
    if (CORE_DUMP_INDEX_BUFFER) {
        mem_remove_from_coredump((void *)sga->index_buf, kernel->attr.index_buf_size);
    }
    if (CORE_DUMP_PMA_BUFFER) {
        mem_remove_from_coredump((void *)sga->pma_buf, kernel->attr.pma_size);
    }
    cut_core_dump_log_writer(sga, kernel);
    GS_LOG_RUN_ERR("cut dumpfile end");
}


uint32 g_sign_mutex = 0;
void process_sign_func(int32 sig_num, siginfo_t *siginfo, void *context)
{
    box_excp_item_t *excep_info = &g_excep_info;
    uint64 locId = 0;
    sigset_t sign_old_mask;
    sigset_t sign_mask;
    uint32 max_dump_len = 0;
    char signal_name[GS_NAME_BUFFER_SIZE] = { 0 };
    char date[GS_MAX_TIME_STRLEN] = { 0 };

    if (g_sign_mutex != 0) {
        return;
    }

    g_sign_mutex = 1;

    (void)sigprocmask(0, NULL, &sign_old_mask);
    (void)sigfillset(&sign_mask);
    (void)sigprocmask(SIG_SETMASK, &sign_mask, NULL);

    if (sig_num == SIGALRM || sig_num == SIGTSTP || sig_num == SIGTTIN || sig_num == SIGTERM || sig_num == SIGTTOU ||
        sig_num == SIGVTALRM || sig_num == SIGPROF || sig_num == SIGPWR) {
        locId = cm_sys_pid();
        get_signal_info(sig_num, signal_name, sizeof(signal_name) - 1);
        (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", date, GS_MAX_TIME_STRLEN);
        GS_LOG_BLACKBOX("Location[0x%016llx] has been terminated, signal name : %s, current date : %s\n", locId,
            signal_name, date);
        cm_fync_logfile();
        return;
    }

    if (excep_info != NULL) {
        cm_reset_error();

        errno_t ret = memset_sp((void *)excep_info, sizeof(box_excp_item_t), 0, sizeof(box_excp_item_t));
        knl_securec_check(ret);

        proc_signal_get_header(excep_info, sig_num, siginfo, context);

        process_get_register_info(&(excep_info->reg_info), (ucontext_t *)context);

        print_signal_info(excep_info, (void *)&(excep_info->reg_info));

        print_register(&excep_info->reg_info);

        cm_print_call_link(g_instance->attr.black_box_depth);

        excep_info->stack_addr = process_get_stack_point(&(excep_info->reg_info), &max_dump_len);
        ret = memcpy_s(excep_info->stack_memory, BOX_STACK_SIZE, (const void *)excep_info->stack_addr, max_dump_len);
        knl_securec_check(ret);

        GS_LOG_BLACKBOX("\nDump stack(total %dBytes,  %dBytes/line:\n", BOX_STACK_SIZE, STACK_SIZE_EACH_ROW);
        GS_UTIL_DUMP_MEM((void *)excep_info->stack_addr, BOX_STACK_SIZE);

        save_process_maps_file(excep_info);

        proc_app_register(excep_info, sig_num, siginfo, context);
    }

    g_sign_mutex = 0;

    /* At last recover the sigset */
    (void)sigprocmask(SIG_SETMASK, &sign_old_mask, NULL);
    cut_core_dumpfile();
    cm_fync_logfile();
    abort();

    return;
}

static status_t signal_cap_reg_proc(int32 sig_num)
{
    status_t uiRetCode;

    uiRetCode = cm_regist_signal_ex(sig_num, process_sign_func);
    if (uiRetCode != GS_SUCCESS) {
        GS_LOG_DEBUG_ERR("[DBG] Register the signal cap failed:%d", sig_num);
        return GS_ERROR;
    }

    GS_LOG_DEBUG_INF("[DBG] Register the signal cap success:%d", sig_num);
    return GS_SUCCESS;
}


status_t signal_cap_handle_reg()
{
    if (proc_signal_init() != GS_SUCCESS) {
        return GS_ERROR;
    }
    // Ensure that backtrace is loaded successfully.
    void *array[GS_MAX_BLACK_BOX_DEPTH] = {0};
    size_t size;
    size = backtrace(array, GS_MAX_BLACK_BOX_DEPTH);
    log_file_handle_t *log_file_handle = cm_log_logger_file(LOG_BLACKBOX);
    backtrace_symbols_fd(array, size, log_file_handle->file_handle);

    for (uint32 temp = 0; temp < ARRAY_NUM(g_sign_array); temp++) {
        if (signal_cap_reg_proc(g_sign_array[temp]) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    /* register SIGSEGV sql module hook */
    if (reg_signal_proc(SIGSEGV, sql_signal_hook, HOOK_FUNC_SQL) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /*
     * In some scenarios, for example, after executing the 'expect' command in a shell, SIGHUP signal will be
     * sent to the application, causing the database process to be killed. So SIGHUP should not captured here.
     */
    (void)signal(SIGINT, SIG_DFL);

    return GS_SUCCESS;
}

#endif
