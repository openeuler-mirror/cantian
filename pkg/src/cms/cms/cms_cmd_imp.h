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
 * cms_cmd_imp.h
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_cmd_imp.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMS_CMD_IMP_H
#define CMS_CMD_IMP_H

#include "cm_date.h"
#include "cm_defs.h"
#include "cms_client.h"
#include "cms_msg_def.h"
#include "cms_gcc.h"
#include "cms_stat.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
char *cantiand_get_dbversion(void)
{
    return "NONE";
}
#else
extern char *cantiand_get_dbversion(void);
#endif

typedef struct st_cms_msg_iostat_contrast_t {
    char *msg_name;
} cms_msg_iostat_contrast_t;

#define PARAM_RES_STOP_RESNAME_IDX      3
#define PARAM_RES_STOP_NODEID_IDX       5
#define PARAM_IOF_UNREG_RESNAME_IDX     3
#define PARAM_IOF_UNREG_NODEID_IDX      5

#define CM_DBS_CONFIG_FILE_NAME_LEN 32
#define CM_WAIT_CONFIG_INTERVAL_TIME 2000
#define CM_WAIT_CONFIG_RETRY_NUM 2

EXTER_ATTACK int32 cms_server_start(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_server_stop(int32 argc, char* argv[]);

EXTER_ATTACK int32 cms_gcc_create(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_gcc_delete(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_gcc_list(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_gcc_reset(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_gcc_reset_force(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_gcc_export(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_gcc_import(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_gcc_backup(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_gcc_restore(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_create_mark_file(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_check_mark_file(int32 argc, char* argv[]);

EXTER_ATTACK int32 cms_node_list(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_node_connected(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_node_add(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_node_add_with_id(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_node_del(int32 argc, char* argv[]);

EXTER_ATTACK int32 cms_resgrp_add(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_resgrp_del(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_resgrp_list(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_resgrp_recursive_del(int32 argc, char* argv[]);

EXTER_ATTACK int32 cms_res_add(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_res_add_with_grp(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_res_add_without_attr(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_res_add_with_grp_without_attr(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_res_edit(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_res_del(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_res_list(int32 argc, char* argv[]);

EXTER_ATTACK int32 cms_res_init_cmd(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_res_init_with_node(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_res_start_cmd(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_res_start_with_node(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_res_stop_cmd(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_res_stop_with_node(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_res_stop_with_node_force(int32 argc, char* argv[]);

EXTER_ATTACK int32 cms_stat_cluster(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_stat_res(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_stat_node(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_stat_server(int32 argc, char* argv[]);

EXTER_ATTACK void cms_date2str(date_t date, char* str, uint32 max_size);

EXTER_ATTACK int32 cms_iostat(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_iostat_reset(int32 argc, char *argv[]);
status_t cm_alloc_conf_file_retry(char *config_name);
int32 cms_local_disk_iostat(int32 argc, char* argv[]);
void cms_print_iostat_inner(cms_tool_msg_res_iostat_t *res, char *msg_name, uint8 msg_type);
void cms_print_iostat(cms_tool_msg_res_iostat_t *res_msg, uint8 msg_type);
status_t cms_add_res_server(cms_res_desc_t* cms_res_desc);
status_t cms_edit_res_local(char* name, char* attrs, char* err_info, uint32 err_len);
status_t cms_add_res_local(cms_res_desc_t* cms_res_desc);
status_t cms_lock_gcc_disk(void);
status_t cms_add_res(const char* name, const char* res_type, const char* grp, const char* attrs);
status_t cms_edit_res_server(char* name, char* attrs, char* err_info, uint32 err_len);
status_t cms_unlock_gcc_disk(void);
void cms_print_index(void);
void cms_print_disk_iostat(cms_tool_msg_res_disk_iostat_t *res_msg);
#ifdef DB_DEBUG_VERSION
int32 cms_enable_inject(int32 argc, char* argv[]);
#endif

status_t cms_send_to_server(cms_packet_head_t *req, cms_packet_head_t *res, uint32 res_size, int32 timeout_ms,
    char* err_info);
void cms_print_online_node_info(uint64 *cms_online_bitmap);
status_t cms_instance_init_with_dbs(dbs_init_mode init_mode);

#ifdef __cplusplus
}
#endif

#endif
