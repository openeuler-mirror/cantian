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
 * srv_blackbox.h
 *
 *
 * IDENTIFICATION
 * src/server/srv_blackbox.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_BLACKBOX_H__
#define __SRV_BLACKBOX_H__
#include <signal.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* max signal type */
#define SIGMAX 0xFF


/*  |<----512 ----sp----1024---->| */
#define BOX_STACK_SIZE (1536)
#define STACK_SIZE_EACH_ROW (16)

/* Record 16 bytes of content before and after the address of the exception instruction,
   mainly to locate the abnormal program. */
#define BOX_INS_CONT_LEN (32)

/* version length */
#define BOX_VERSION_LEN (64)

/* stack funtion name len */
#define BOX_STACK_FUNC_LEN (128)

#define BOX_SPACE_SIZE (2)

#define BOX_EXCP_MAGIC (0xECECECEC)
#define BOX_EXCP_TO_LOG (0x12345678)
#define BOX_TAIL_MAGIC (0xFFFFFFFF)

#define BOX_SPACE_SIZE (2)

typedef enum en_hook_func_type {
    HOOK_FUNC_SQL = 0,
    HOOK_FUNC_KERNEL = 1,
    HOOK_FUNC_TAIL
} hook_func_type_t;

#if (defined __x86_64__)
typedef struct st_box_reg_info {
    int64 r8;
    int64 r9;
    int64 r10;
    int64 r11;
    int64 r12;
    int64 r13;
    int64 r14;
    int64 r15;
    int64 rdi;
    int64 rsi;
    int64 rbp;
    int64 rbx;
    int64 rdx;
    int64 rax;
    int64 rcx;
    int64 rsp;
    int64 rip;
    int64 eflags; /* RFLAGS */
    int64 cs;

    int64 err;
    int64 trapno;
    int64 oldmask;
    int64 cr2;
} box_reg_info_t;

#elif (defined __aarch64__)
typedef struct st_box_reg_info {
    uint64 reg[31]; /* arm register */
    uint64 sp;
    uint64 pc;
} box_reg_info_t;

#endif

extern char *cantiand_get_dbversion(void);

typedef struct st_box_excp_item {
    uint32 magic;                                /* magic number */
    uint64 loc_id;                               /* location id */
    pthread_t thread_id;                         /* thread id */
    uint32 sig_index;                            /* exception type, in linux os means signal type */
    int32 sig_code;                              /* signal code, specifically
                                                    showing the cause of the signal */
    box_reg_info_t reg_info;                     /* register info */
    uintptr_t stack_addr;                        /* stack top pointer minus 512 bytes  */
    char sig_name[CT_NAME_BUFFER_SIZE];          /* signal name */
    char loc_name[CT_FILE_NAME_BUFFER_SIZE + 1]; /* location name */
    char platform[CT_NAME_BUFFER_SIZE];          /* platform name */
    uchar stack_memory[BOX_STACK_SIZE];          /* system stack info */
    uchar ins_content[BOX_INS_CONT_LEN];         /* 16 bytes before and after exception
                                                    instruction address */
    char version[BOX_VERSION_LEN];               /* database version */
    char date[CT_MAX_TIME_STRLEN];               /* exception date */
    uint32 trace_tail[BOX_SPACE_SIZE];           /* protect info */
} box_excp_item_t;

typedef void (*signal_handle_hook_func)(box_excp_item_t *, int32, siginfo_t *, void *);
status_t sigcap_handle_reg(void);
status_t reg_sign_proc(int32 sig, signal_handle_hook_func func, hook_func_type_t type);
status_t unreg_sign_proc(int32 sig, hook_func_type_t type);

#ifdef __cplusplus
}
#endif

#endif
