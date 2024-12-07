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
 * dbs_adp.h
 *
 *
 * IDENTIFICATION
 * src/dbstool/dbs_adp.h
 *
 * -------------------------------------------------------------------------
 */

#include "cm_defs.h"
#include "cm_log.h"

#ifndef MODULE_ID
#define MODULE_ID DBSTORE
#endif

#define NUM_ONE     1
#define NUM_TWO     2
#define NUM_THREE   3
#define NUM_FOUR    4
#define NUM_FIVE    5
#define NUM_SIX     6
#define NUM_SEVEN   7
#define NUM_EIGHT   8
#define NUM_NINE    9
#define DEFAULT_LINK_CHECK_TIMEOUT 5
#define LINK_STATE_UNKNOWN 7

#define DBS_PERF_ITEM_NAME_LEN 32
#define DBS_UDS_BUFFER_SIZE 1024
#define DBS_UDS_MSG_TIMEOUT_MS 10000    //10s
#define DBS_UDS_HEARTBEAT_MS 1000     //1s

typedef enum {
    DBS_UDS_MSG_TYPE_PERF_REQ = 0,
    DBS_UDS_MSG_TYPE_HEARTBEAT,
    DBS_UDS_MSG_TYPE_BUTT
} dbs_uds_msg_type;

typedef struct {
    uint32 success_cnt;
    uint32 fail_cnt;
    uint32 max_delay;
    uint32 min_delay;
    uint64 total_delay;
    uint64 io_size;
} dbs_stat_item;

typedef struct {
    char name[DBS_PERF_ITEM_NAME_LEN];
    dbs_stat_item item;
    uint32 avg_delay;
    uint32 iops;
    uint32 bandWidth;
} dbs_stat_item_query;

typedef struct {
    dbs_uds_msg_type opcode;
    char buffer[DBS_UDS_BUFFER_SIZE];
} dbs_uds_req_comm_msg;

typedef struct {
    dbs_uds_msg_type opcode;
    int32 result;
    uint32 item_num;
    char buffer[DBS_UDS_BUFFER_SIZE];
} dbs_uds_rsp_comm_msg;

status_t dbstool_init();
int32 dbs_arch_import(int32 argc, char *argv[]);
int32 dbs_arch_export(int32 argc, char *argv[]);
int32 dbs_arch_clean(int32 argc, char *argv[]);
int32 dbs_arch_query(int32 argc, char *argv[]);
int32 dbs_ulog_clean(int32 argc, char *argv[]);
int32 dbs_pagepool_clean(int32 argc, char *argv[]);
int32 dbs_create_path_or_file(int32 argc, char *argv[]);
int32 dbs_copy_file(int32 argc, char *argv[]);
int32 dbs_delete_path_or_file(int32 argc, char *argv[]);
int32 dbs_query_file(int32 argc, char *argv[]);
int32 dbs_ulog_export(int32 argc, char *argv[]);
int32 dbs_page_export(int32 argc, char *argv[]);
int32 dbs_set_link_timeout(int32 argc, char *argv[]);
int32 dbs_set_ns_io_forbidden(int32 argc, char *argv[]);
int32 dbs_link_check(int32 argc, char *argv[]);
int32 dbs_get_ns_io_forbidden_stat(int32 argc, char *argv[]);
int32 dbs_get_link_timeout(int32 argc, char *argv[]);
int32 dbs_query_fs_info(int32 argc, char *argv[]);
int32 dbs_perf_show(int32 argc, char *argv[]);
