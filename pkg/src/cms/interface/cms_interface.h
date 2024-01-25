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
 * cms_interface.h
 *
 *
 * IDENTIFICATION
 * src/cms/interface/cms_interface.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_INTERFACE_H
#define CMS_INTERFACE_H

#include "cm_defs.h"
#include "cms_client.h"
#include "cms_uds_client.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define CMS_ENV_CMS_HOME            "CMS_HOME"
#define CMS_CFG_FILENAME            "cms.ini"
#define CMS_RES_TYPE_CTSTORE            "CTSTORE"
#define CMS_RES_TYPE_DB             "DB"
#define CMS_MAX_RES_SLOT_COUNT      8
#define CMS_CLI_HB_INTERVAL         (MICROSECS_PER_SECOND * 2)
#define CMS_CLI_UDS_SEND_TMOUT      1000
#define CMS_CLI_UDS_RECV_TMOUT      4000
#define CMS_CLI_RETRY_RECV_TMOUT    1000
#define CMS_CLI_UDS_HB_INTERVAL     1000
#define CMS_CLI_SLEEP_INTERVAL      100
#define CMS_CLI_INVALID_SESS_ID     (-1)

#define RC_CMS_REMOTE_CURRENT     0  // RC CMS REMOTE_CURRENT slot id, persist the db resource current status
#define RC_CMS_REMOTE_TARGET      1  // RC CMS REMOTE_TARGET slot id, persist the db resource target  status
#define RC_CMS_ABORT_REF_MAP      2  // RC CMS ABORT_REF_MAP slot id, persist the db resource abort reference status
#define RC_REFORM_TRIGGER_VERSION 3  // RC REFORM TRIGER VERSION slot id, persist the db reform version

typedef enum e_reform_work_state {
    RC_JOINING          = 0,
    RC_JOINED           = 1,
    RC_LEAVING          = 2,
    RC_LEFT             = 3,
    RC_WORK_STATE_COUNT = 4,     // enum end for work state count
} reform_work_state_t;

typedef struct st_upgrade_version {
    uint16 main;
    uint16 major;
    uint16 revision;
    uint16 inner;
} upgrade_version_t;

typedef void(*cms_notify_func_t)(cms_res_status_list_t* res_list);
typedef status_t(*cms_master_op_t)(uint8 oper);                     // 1 rise, 2 drop
typedef status_t(*cms_upgrade_op_t)(void *func_ptr);

status_t cms_cli_init(void);
status_t cms_res_inst_register(const char res_type[CMS_MAX_RES_TYPE_LEN], uint8 inst_id, res_init_info_t *res_init_info,
    cms_notify_func_t notify_func, cms_master_op_t master_func);
status_t cms_res_inst_unregister(void);
status_t cms_res_inst_unregister_inner(void);
status_t cms_send_disconn_req(void);
status_t cms_set_res_work_stat(uint8 stat);
status_t cms_get_res_stat_list(cms_res_status_list_t* res_list);
status_t cms_get_res_stat_list1(const char* res_type, cms_res_status_list_t* res_list);
const char* cms_stat_str(cms_stat_t stat);
status_t cms_set_res_data_new(uint32 slot_id, char* data, uint32 size, uint64 old_version);
status_t cms_get_res_data_new(uint32 slot_id, char* data, uint32 max_size, uint32* size, uint64* new_version);
status_t cms_set_res_data(uint32 slot_id, char* data, uint32 size);
status_t cms_get_res_data(uint32 slot_id, char* data, uint32 max_size, uint32* size);
status_t cms_env_init(void);
void cms_res_inst_register_upgrade(cms_upgrade_op_t upgrade_func);

#ifdef __cplusplus
}
#endif
#endif
