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
 * mes_uc_interface.h
 *
 *
 * IDENTIFICATION
 * src/mec/mes_uc_interface.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __MES_UC_INTERFACE_H__
#define __MES_UC_INTERFACE_H__

#include "lvos_list.h"
#include "dpax_errno.h"
#include "dpuc_api.h"
#include "dpumm_cmm.h"
#include "dsw_boot.h"
#include "dplog.h"
#include "dpax_log.h"

#ifdef __cplusplus
extern "C" {
#endif

//uc
typedef dpuc_msg* (*dpuc_msg_alloc_t)(dpuc_msg_alloc_param *, const char *);
typedef s32 (*dpuc_msg_free_t)(dpuc_msg *, const char *);
typedef s32 (*dpuc_msgparam_set_t)(dpuc_msg *, dpuc_eid_t, dpuc_eid_t, u32, const char *);
typedef s32 (*dpuc_msgmem_reg_integrate_t)(dpuc_eid_obj *, dpuc_ctrl_msg_reg *, dpuc_datamsg_mem_ops *, const char *);
typedef s32 (*dpuc_msg_send_t)(dpuc_msg *, dpuc_send_rst_cb_func, void *, const char *);
typedef u32 (*dpuc_msglen_get_t)(dpuc_msg *, const char *);
typedef s32 (*dpuc_sgl_addr_set_t)(dpuc_msg *, SGL_S *, u32, const char *);
typedef SGL_S *(*dpuc_sgl_addr_get_t)(dpuc_msg *, const char *);
typedef void *(*dpuc_data_addr_get_t)(dpuc_msg *, const char *);
typedef s32 (*dpuc_eid_make_t)(MSGTYPE_E, u16, u16, u32, dpuc_eid_t *, const char *);
typedef s32 (*dpuc_eid_reg_t)(dpuc_comm_mgr *, dpuc_eid_t, dpuc_msg_recv_s *, dpuc_eid_obj **, const char *);
typedef s32 (*dpuc_set_src_eid_addr_t)(dpuc_eid_obj *, dpuc_addr *, u32, dpuc_addr_type, const char *);
typedef s32 (*dpuc_set_dst_eid_addr_t)(dpuc_comm_mgr *, dpuc_eid_t, dpuc_addr *, u32, const char *);
typedef s32 (*dpuc_set_eid_reactor_t)(dpuc_eid_obj *, const char *, dpuc_sched_conf_info_s *, const char *);
typedef int32_t (*dpuc_set_subhealth_threshold_t)(dpuc_subhealth_threshold, const char *);
typedef s32 (*dpuc_process_set_config_t)(dpuc_necessary_config_param_t *,dpuc_optional_config_param_t *, const char *);
typedef void (*dpuc_xnet_set_process_ver_t)(uint64_t);
typedef dpuc_comm_mgr *(*dpuc_all_init_t)(dpuc_comm_mgr_param *, const char *);
typedef int32_t (*dpuc_regist_link_event_t)(dpuc_eid_t, const dpucLinkEventOps*, const char *);
typedef int32_t (*dpuc_link_create_with_addr_t)(dpuc_eid_obj*, dpuc_eid_t, const dpuc_conn_params_t*, const char *);
typedef int32_t (*dpuc_qlink_close_t)(uint32_t, dpuc_disConn_type, dpuc_plane_type_e, const char *);
//dsw
typedef int32_t (*dsw_core_init_t)(dsw_dpmm_pool_t *, int32_t, char *);
//umm
typedef void (*allocate_multi_pages_sync_t)(uint32_t, SGL_S **, uint32_t, const char *, const int32_t);
typedef void (*free_multi_pages_t)(SGL_S *, uint32_t, const char *, const int32_t);
typedef int32_t (*copy_data_from_buf_to_sgl_t)(SGL_S *, uint32_t, char *, uint32_t);
typedef int32_t (*copy_data_from_sgl_to_buf_t)(SGL_S *, uint32_t, char *, uint32_t);
typedef s32 (*dpumm_set_config_path_t)(char *, const char *, const u32);
typedef void (*get_last_sgl_t)(SGL_S *, SGL_S **, uint32_t *);
//dplog
typedef int32_t (*dplog_init_t)(void);
typedef int32_t (*dplog_set_backup_num_t)(uint32_t);
typedef int32_t (*dplog_set_file_path_ext_t)(char *, char *);

typedef struct st_mes_interface {
    void *uc_handle;
    void *dsw_handle;
    void *umm_handle;
    void *dplog_handle;

    //uc
    dpuc_msg_alloc_t dpuc_msg_alloc;
    dpuc_msg_free_t dpuc_msg_free;
    dpuc_msgparam_set_t dpuc_msgparam_set;
    dpuc_msgmem_reg_integrate_t dpuc_msgmem_reg_integrate;
    dpuc_msg_send_t dpuc_msg_send;
    dpuc_msglen_get_t dpuc_msglen_get;
    dpuc_sgl_addr_set_t dpuc_sgl_addr_set;
    dpuc_sgl_addr_get_t dpuc_sgl_addr_get;
    dpuc_data_addr_get_t dpuc_data_addr_get;
    dpuc_eid_make_t dpuc_eid_make;
    dpuc_eid_reg_t dpuc_eid_reg;
    dpuc_set_src_eid_addr_t dpuc_set_src_eid_addr;
    dpuc_set_dst_eid_addr_t dpuc_set_dst_eid_addr;
    dpuc_set_eid_reactor_t dpuc_set_eid_reactor;
    dpuc_set_subhealth_threshold_t dpuc_set_subhealth_threshold;
    dpuc_process_set_config_t dpuc_process_set_config;
    dpuc_xnet_set_process_ver_t dpuc_xnet_set_process_ver;
    dpuc_all_init_t dpuc_all_init;
    dpuc_regist_link_event_t dpuc_regist_link_event;
    dpuc_link_create_with_addr_t dpuc_link_create_with_addr;
    dpuc_qlink_close_t dpuc_qlink_close;

    //dsw
    dsw_core_init_t dsw_core_init;

    //umm
    allocate_multi_pages_sync_t allocate_multi_pages_sync;
    free_multi_pages_t free_multi_pages;
    copy_data_from_buf_to_sgl_t copy_data_from_buf_to_sgl;
    copy_data_from_sgl_to_buf_t copy_data_from_sgl_to_buf;
    dpumm_set_config_path_t dpumm_set_config_path;
    get_last_sgl_t get_last_sgl;

    //dplog
    dplog_init_t dplog_init;
    dplog_set_backup_num_t dplog_set_backup_num;
    dplog_set_file_path_ext_t dplog_set_file_path_ext;

} mes_interface_t;

#ifdef __cplusplus
}
#endif
#endif