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
 * cm_raft.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_raft.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_RAFT_H__
#define __CM_RAFT_H__

#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef int64 (*Raft_InitConsistency)(uint64 p0, char *p1, char *p2, char *p3, char *p4, void *p5, int32 p6);
typedef char *(*Raft_QueryInfo)(char *);
typedef int64 (*Raft_AddMember)(uint64 p0, char *p1, uint64 p2, int64 p3);
typedef int64 (*Raft_DeleteMember)(uint64 p0, uint64 p1);
typedef int64 (*Raft_InitDBEngines)(int32 p0);
typedef int64 (*Raft_Register)(char *p1, void *p2);
typedef int64 (*Raft_SendMessage)(uint64 p1, void *, int32);
typedef int64 (*Raft_ExecWriteLogCmd)(uint64 p1, void *, uint64);
typedef int64 (*Raft_PromoteLeader)(uint64, uint64);
typedef void (*Raft_StopConsistency)(void);
typedef char *(*Raft_GetVersion)(void);
typedef int32 (*Raft_SetParam)(char *, void *);
typedef char *(*Raft_Monitor)(void);

typedef struct raft_funcs {
    void *lib_handle;
    Raft_InitConsistency init_consistency;
    Raft_QueryInfo query_info;
    Raft_AddMember add_member;
    Raft_DeleteMember delete_member;
    Raft_InitDBEngines init_db_engines;
    Raft_Register register_callback;
    Raft_SendMessage send_message;
    Raft_ExecWriteLogCmd exec_writelog_cmd;
    Raft_PromoteLeader promote_leader;
    Raft_StopConsistency stop_consistency;
    Raft_GetVersion get_version;
    Raft_SetParam set_param;
    Raft_Monitor monitor;
} raft_procs_t;

status_t raft_load_lib(raft_procs_t *procs);
void raft_close_lib(raft_procs_t *procs);
int64 raft_lib_init_consistency(raft_procs_t *procs, uint64 p0, char *p1, char *p2, char *p3, char *p4, void *p5,
                                int32 p6);
char *raft_lib_query_info(raft_procs_t *procs, char *type);
int64 raft_lib_add_member(raft_procs_t *procs, uint64 p0, char *p1, uint64 p2, int64 p3);
int64 raft_lib_delete_member(raft_procs_t *procs, uint64 p0, uint64 p1);
int64 raft_lib_initDBEngines(raft_procs_t *procs, int32 p0);
int64 raft_lib_register(raft_procs_t *procs, char *p0, void *p1);
int64 raft_lib_sendmessage(raft_procs_t *procs, uint64 p0, void *p1, int32 p2);
int64 raft_lib_exec_writelog_cmd(raft_procs_t *procs, uint64 p0, void *p1, uint64 p2);
int64 raft_lib_promote_leader(raft_procs_t *procs, uint64 p0, uint64 p1);
void raft_lib_stop_consistency(raft_procs_t *procs);
char *raft_lib_get_version(raft_procs_t *procs);
int32 raft_lib_set_param(raft_procs_t *procs, char *p0, void *p1);
char *raft_lib_monitor(raft_procs_t *procs);

#ifdef __cplusplus
}
#endif
#endif
