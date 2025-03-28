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

#include "cm_types.h"
#include "cm_thread.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _PCLINT_
typedef struct list_head list_head_t;
#else
typedef struct list_head {
    struct list_head *prev;
    struct list_head *next;
} list_head_t;
#endif

#ifndef __KERNEL__
#if !defined(_BASIC_TYPEDEF_)
#define _BASIC_TYPEDEF_
typedef char                   s8;
typedef unsigned char          u8;

typedef short                  s16;
typedef unsigned short         u16;

typedef int                    s32;
typedef unsigned int           u32;

typedef int64_t                s64;
typedef uint64_t               u64;
#endif /* _BASIC_TYPEDEF_ */
#endif

typedef u64     dpuc_eid_t;

typedef struct tagDPUC_MSG       dpuc_msg;

typedef struct tagDPUC_EID_OBJ   dpuc_eid_obj;

typedef struct tagDPUC_COMM_MGR  dpuc_comm_mgr;

typedef enum tagMSGTYPE_E
{
    NORMAL_TYPE   =  0,
    APITOMSG      =  1,
    LOCALE_TYPE   =  2,
    DPUC_MSG_INSTACNE_SIMU = 3,
    DPUC_MSG_TYPE_BUTT = 0x8
} MSGTYPE_E;

typedef enum tagDpucMsgMemFreeMode
{
    DPUC_AUTO_FREE = 0,
    DPUC_SELF_FREE = 1,
    DPUC_INVALID_FREE = 0xFF,
} dpuc_msg_mem_free_mode_e;

typedef enum tagDpucPlaneType
{
    DPUC_MANAGE_PLANE   = 0,
    DPUC_COTROL_PLANE   = 1,
    DPUC_DATA_PLANE     = 2,
    DPUC_DEFAULT_PLANE  = 3,
    DPUC_INVALID_PLANE  = 0xFF,
}dpuc_plane_type_e;

typedef enum tagDpucAddrFamily
{
    DPUC_ADDR_FAMILY_IPV4 = 0,
    DPUC_ADDR_FAMILY_IPV6 = 1,
    DPUC_ADDR_FAMILY_UNIX_SOCK = 2,
    DPUC_ADDR_FAMILY_IPV4_RDMA = 3,
    DPUC_ADDR_FAMILY_IPV6_RDMA = 4,
    DPUC_ADDR_FAMILY_IPV4_RDMA_IBV = 5,
    DPUC_ADDR_FAMILY_IPV6_RDMA_IBV = 6,
    DPUC_ADDR_FAMILY_IPV4_ENCRYPT = 7,
    DPUC_ADDR_FAMILY_IPV6_ENCRYPT = 8,
    DPUC_ADDR_FAMILY_IPV4_WAL = 9,
    DPUC_ADDR_FAMILY_IPV6_WAL  = 10,
    DPUC_ADDR_FAMILY_INVALID
} dpuc_addr_family;

typedef enum tagDpucAddrType
{
    DPUC_ADDR_CLIENT  = 0,
    DPUC_ADDR_SERVER  = 1,
    DPUC_ADDR_BUTT    = 0xFF
} dpuc_addr_type;

typedef enum {
    DPUC_CGW_TCP = 0,
    DPUC_CGW_RDMA = 1,
    DPUC_XNET_TCP = 2,
    DPUC_XNET_RDMA = 3,
    DPUC_LINK_TYPE_BUTT
} dpuc_subhealth_link_type_e;

typedef enum tagDpucQlinkEvent
{
    DPUC_QLINK_UP = 1,
    DPUC_QLINK_DOWN,
    DPUC_QLINK_STOP,
    DPUC_QLINK_SUBHEALTH,
    DPUC_QLINK_BUTT = 0xFF
}dpuc_qlink_event;

typedef enum tagDpucQlinkCause
{
    DPUC_QLINK_DOWN_KA_TIMEOUT   = 0,
    DPUC_QLINK_DOWN_PEER_OFFLINE = 1,
    DPUC_QLINK_DOWN_UNKOWN_CAUSE = 2,
    DPUC_QLINK_DOWN_UP_CAUSE_BUTT = 0xFF
}dupc_qlink_cause_t;

typedef enum
{
    DPUC_LINK_STATE_EVENT_UP               = 0,
    DPUC_LINK_STATE_EVENT_DOWN             = 1,
    DPUC_LINK_STATE_EVENT_SUBHEALTH_ORIGIN = 2,
    DPUC_LINK_STATE_EVENT_SUBHEALTH_CLEAR  = 3,
    DPUC_LINK_EVENT_KA_LOST                = 4,
    DPUC_LINK_EVENT_IO_FINISH              = 5,
    DPUC_LINK_EVENT_SUBHEALTH_REPORT       = 6,
    DPUC_LINK_EVENT_LINK_FLASH             = 7,
    DPUC_LINK_STATE_EVENT_BUTT = 0xFF
}dpuc_link_state_event_t;

typedef enum tagDpucConnRecvPri
{
    DPUC_CONN_RECVOERY_H   = 0,
    DPUC_CONN_RECVOERY_L   = 1,
    DPUC_CONN_RECVOERY_BOTTOM = 0XFF
}dpuc_conn_recovery_pri_t;

typedef enum
{
    DPUC_PERSISTENT_CONN        = 0,
    DPUC_SHORT_CONN             = 1,
    DPUC_CONN_RUNNING_MODE_BOTT = 0xFF
}dpuc_conn_running_mode_t;

typedef enum tagDpucDisConnType
{
    DPUC_DISCONNS_LINK        = 0,
    DPUC_DESTROY_LINK         = 1,
    DPUC_INVALID_DISCONN_TYPE = 0xFF,
}dpuc_disConn_type;

typedef enum
{
    DSW_DPMM_IO_POOL = 0,
    DSW_DPMM_FMT_POOL,
    DSW_DPMM_NORMAL_POOL,
} dsw_dpmm_pool_type;

typedef enum {
    DPUC_SUBHEALTH_TYPE_NET = 0,
    DPUC_SUBHEALTH_TYPE_IO  = 1,
    DPUC_SUBHEALTH_TYPE_BUTT
} dpuc_subhealth_type_t;

typedef enum {
    DPUC_SUBHEALTH_LEVEL_MINOR = 0,
    DPUC_SUBHEALTH_LEVEL_MAJOR = 1,
    DPUC_SUBHEALTH_LEVEL_BUTT
}dpuc_subhealth_level_t;

typedef enum {
    DPUC_SUBHEALTH_ALGO_CONTINUE = 0,
    DPUC_SUBHEALTH_ALGO_CUMULATE = 1,
    DPUC_SUBHEALTH_ALGO_BUTT
}dpuc_subhealth_algo_t;

typedef enum tagDpucResultType
{
    DPUC_RESULT_OK                = 0,
    DPUC_RESULT_NO_EID            = 1,
    DPUC_RESULT_QUE_NULL          = 2,
    DPUC_RESULT_SEND_QUE_FULL     = 3,
    DPUC_RESULT_QUE_FULL          = 4,
    DPUC_RESULT_RECV_PROCESS_EXIT = 5,
    DPUC_RSP_TIMEOUT              = 6,
    DPUC_RESULT_PARAM_REPEAT_SET  = 7,
    DPUC_RESULT_DSTEID_NO_REQFUNC = 11,
    DPUC_RESULT_DSTEID_NO_RSPFUNC = 12,
    DPUC_RESUTL_RSP_NO_REQ        = 13,
    DPUC_RESUTL_UPDATING          = 14,

    DPUC_XNET_MSG_SUCCESS         = DPUC_RESULT_OK,
    DPUC_XNET_SEND_TIMEOUT        = 100,
    DPUC_XNET_SEND_FAIL           = 101,
    DPUC_XNET_RCV_FAIL            = 102,
    DPUC_XNET_RSP_TIMEOUT         = 103,
    DPUC_XNET_QUEUE_FULL          = 104,
    DPUC_XNET_RESULT_NULL         = 105,
    DPUC_RESULT_XNET              = 106,
    DPUC_XNET_AGENT_UNLINK        = 107,

    DPUC_RESULT_MIS_LINK          = 200,
    DPUC_RESULT_NO_MEM            = 201,
    DPUC_RESULT_DISCONNECT        = 202,
    DPUC_RESULT_XIO               = 203,

    DPUC_RESULT_XIO_OK            = DPUC_RESULT_OK,
    DPUC_RESULT_CST_FAIL          = 204,
    DPUC_RESULT_CTL_FAIL          = 205,
    DPUC_RESULT_SGL_FAIL          = 206,
    DPUC_RESULT_UNLOAD            = 207,

	DPUC_RETURN_OK                = DPUC_RESULT_OK,
    DPUC_TIMEOUT                  = DPUC_RSP_TIMEOUT,
    DPUC_XNET_LINK_ERROR          = DPUC_RESULT_DISCONNECT,
    DPUC_NO_RESOURCE              = DPUC_RESULT_NO_MEM,
    DPUC_RETURN_FAIL              = 300,
    DPUC_INVALID_PARAMETER        = 301,
    DPUC_EID_NOT_BIND_IP          = 302,
    DPUC_SEND_MODE_NOT_SUPPORT    = 303,
    DPUC_RESULT_BUTT              = 0xFFFF
} dpuc_result_type_e;

typedef enum tagMbufType
{
    DPUC_CTRL   = 1,
    DPUC_DATA   = 2,
    DPUC_DATA_XRB = 3,
    DPUC_MBUF_BUTT = 0XFF
} dpuc_mbuf_e;

typedef enum tagDpucMsgType
{
    DPUC_TYPE_POST  = 1,
    DPUC_TYPE_REQ   = 2,
    DPUC_TYPE_RSP   = 3
} dpuc_msgtype_e;

typedef enum
{
    DPUC_PHY_PROTOCOL_TCP  = 0,
    DPUC_PHY_PROTOCOL_ROCE = 1,
    DPUC_PHY_PROTOCOL_IBV  = 2,
    DPUC_PHY_PROTOCOL_BUTT  = 0xFF
}dpuc_phy_protocol_type_t;

typedef struct tagDpucMsgAllocParam
{
    dpuc_eid_obj  *pEidObj;
    dpuc_msg      *pMsgTemplate;
    uint32        uiSize;
    uint8         ucDataType;
    uint8         ucMsgType;
} dpuc_msg_alloc_param;

typedef struct tagDpucCtrlMsgInfo
{
    uint32 uiMsgSize;
    uint32 uiReserveNum;
    uint32 uiMaxNum;
} dpuc_ctrl_msg_info;

typedef struct tagDpucCtrlMsgReg
{
    dpuc_ctrl_msg_info* pSendMsg;
    uint32              uiSendMsgNum;
    dpuc_ctrl_msg_info* pRecvMsg;
    uint32              uiRecvMsgNum;
    uint32              uiMemMode;
} dpuc_ctrl_msg_reg;

typedef struct
{
    char   *buf;
    void   *pageCtrl;
    uint32 len;
    uint32 pad;
} SGL_ENTRY_S;

typedef struct tagSGL_S
{
    struct tagSGL_S  *nextSgl;
    uint16           entrySumInChain;
    uint16           entrySumInSgl;
    uint32           flag;
    u64              serialNum;
    SGL_ENTRY_S      entrys[ENTRY_PER_SGL];
    struct list_head stSglNode;
    uint32           cpuid;
} SGL_S;

typedef int32 (*dpuc_alloc_req_msgmem)(dpuc_msg* pMsg, uint32 uiSglDataLen, SGL_S **pSgl, void **pContext);
typedef int32 (*dpuc_alloc_rsp_msgmem)(dpuc_msg* pMsg, uint32 uiSglDataLen, SGL_S **pSgl, void* pContext);
typedef void (*dpuc_free_msgmem)(dpuc_msg* pMsg, void* pContext);

typedef struct tagDpucDatamsgMemOps
{
    dpuc_alloc_req_msgmem  pfnReqAllocMsgMem;
    dpuc_alloc_rsp_msgmem  pfnRspAllocMsgMem;
    dpuc_free_msgmem       pfnFreeMsgMem;
    uint32 uiSendDataMsgNumReserve;
    uint32 uiSendDatamsgNumMax;
    uint32 uiRecvDataMsgNumReserve;
    uint32 uiRecvDatamsgNumMax;
} dpuc_datamsg_mem_ops;

typedef int32 (*dpuc_req_recv_func)(dpuc_msg* pMsg, dpuc_msg_mem_free_mode_e* pMsgMemFreeMode);
typedef int32 (*dpuc_rsp_recv_func)(int32 siResult, dpuc_msg *pMsg, void *pContext,
    dpuc_msg_mem_free_mode_e *pMsgMemFreeMode);

typedef struct tagDpucMsgRecv
{
    dpuc_req_recv_func  pfnHpucReqRecvFun;
    dpuc_rsp_recv_func  pfnHpucRspRecvFun;
}dpuc_msg_recv_s;

typedef struct tagDpucAddr
{
    dpuc_plane_type_e   PlaneType;
    dpuc_addr_family    AddrFamily;
    char Url[DPUC_URL_LEN];
} dpuc_addr;

typedef struct tagDPUC_XNET_THREAD_INFO {
    uint32    pri;
    cpu_set_t cpu_set;
}dpuc_xnet_thread_info_s;

typedef struct tagDPUC_SCHED_CONF_INFO {
    int32                   bind;
    int32                   dead_loop;
    dpuc_xnet_thread_info_s *thread_info;
    uint32                  thread_num;
}dpuc_sched_conf_info_s;

typedef struct {
    dpuc_subhealth_link_type_e type;
    uint32 hop;
    u64    upgradeTimeNs;
    u64    degradeTimeNs;
    dpuc_plane_type_e plane;
    u64    time_ns[DPUC_SUBHEALTH_TYPE_BUTT][DPUC_SUBHEALTH_LEVEL_BUTT][DPUC_SUBHEALTH_ALGO_BUTT];
} dpuc_subhealth_threshold;

typedef struct tagDpucNecessaryConfigParam {
    uint32 maxDstSerId;

    uint16 eidMaxNum;
    uint16 planeNeed;
    u64    maxSendMsgQuota;
    u64    maxReveMsgQuota;

    uint32 ctrlMaxTcpConnNums;
    uint32 ctrlMaxRdmaConnNums;
    uint32 dataMaxTcpConnNums;
    uint32 dataMaxRdmaConnNums;
}dpuc_necessary_config_param_t;

typedef struct tagDpucCtrlBufferConfigParam {
    struct  tagDpucBufferParam {
        uint32 bufferSize64KMin;
        uint32 bufferSize128KMin;
        uint32 bufferSize256KMin;
        uint32 bufferSize512KMin;
        uint16 bufferSize1MMin;
        uint16 bufferSize4MMin;
        uint16 bufferExtend;
    }bufferConfig;
    uint16 activeBufferConfig;
}dpuc_buffer_config_param_t;

typedef struct tagDpucOptinalParam {
    uint8 activeConfig;
    uint8 reserve[3];
    int32 configValue;
}dpuc_optinal_param_t;

typedef struct tagDupcOptinalConfigParam {
    dpuc_buffer_config_param_t bufferParam;
    dpuc_optinal_param_t multiMsgMaxNum;
    dpuc_optinal_param_t rspCtrlExtendMin;
    dpuc_optinal_param_t rspDataExtendMin;
    dpuc_optinal_param_t serverListenNum;

    dpuc_optinal_param_t rqQepth;
    dpuc_optinal_param_t immMsgLen;
    dpuc_optinal_param_t immDataLen;
    dpuc_optinal_param_t privateLen;

    dpuc_optinal_param_t bind;
    dpuc_optinal_param_t deadLoop;
}dpuc_optional_config_param_t;

typedef struct tagDpucCommMgrParam
{
    uint32 uiRecvQueueSize;
    uint32 uiRstQueueSize;
    uint16 usPid;
    uint32 uiServiceId;
    uint8  ucMode;
} dpuc_comm_mgr_param;

typedef int32 (*dpuc_link_Event_func)(uint32 uiDstlsId, dpuc_qlink_event qlinkEvent, dpuc_plane_type_e planeType,
    dupc_qlink_cause_t qlinkCause);
typedef int32 (*dpuc_link_state_change_func)(uint32 uiDstlsId, dpuc_link_state_event_t qlinkEvent,
    dpuc_plane_type_e planeType, void *param);
typedef int32 (*dpuc_exclude_link_Event_func)(dpuc_eid_t uiDstEid, dpuc_qlink_event qlinkEvent, 
    dpuc_plane_type_e planeType);

typedef struct tagDpucLinkEventOps
{
    dpuc_link_Event_func         pfndpucLinkeventFun;
    dpuc_link_state_change_func  pfndpucLinkStateChangeFun;
    dpuc_exclude_link_Event_func pfndpucExcludeLinkeventFun;
}dpucLinkEventOps;

typedef struct dpuc_conn_params
{
    uint32 pri;
    uint32 time_out;

    uint32 hop;
    dpuc_conn_recovery_pri_t recovery_pri;

    dpuc_addr *pSrcAddr;
    dpuc_addr *pDstAddr;

    uint32 uisl;
    uint32 kaInterval;
    uint32 kaTimeoutTimes;

    dpuc_conn_running_mode_t runMode;
}dpuc_conn_params_t;

typedef struct {
    bool   security_cert_switch;
    uint32 user_id;
    char   pri_key_file[DPUC_MAX_FILE_NAME_LEN];
    char   pub_key_file[DPUC_MAX_FILE_NAME_LEN];
    char   pri_key_pass_file[DPUC_MAX_FILE_NAME_LEN];
    int32  (*get_pub_key_func)(uint32 user_id, char *pub_key_file, uint32 *pub_key_file_len);
    int32  (*kmca_decrypt_func)(char *pass_key, uint32 pass_key_len, char *plain_key, uint32 max_key_len, uint32 *plain_key_len);
} dpuc_security_cert_info_t;

typedef struct
{
    dsw_dpmm_pool_type pool_type;
    const char* name;
    u64    size;
    u64    block_size;
    u64    pool_id;
} dsw_dpmm_pool_t;

typedef struct tagDpucMsgParam
{
    dpuc_msg  *pMsg;
    dpuc_eid_t sendEid;
    dpuc_eid_t recvEid;
    uint16     usSrcNid;
    uint16     usDstNid;
    uint32     uiSrcServiceId;
    uint32     uiDstServiceId;
    uint32     uiOpcode;
} dpuc_msg_param_s;

typedef struct
{
    dpuc_phy_protocol_type_t protocol_type;
    char *local_ip;
    char *remote_ip;
    dpuc_subhealth_type_t type;
    dpuc_subhealth_level_t level;
}dpuc_subhealth_info_t;

//uc
typedef dpuc_msg* (*dpuc_msg_alloc_t)(dpuc_msg_alloc_param *, const char *);
typedef int32 (*dpuc_msg_free_t)(dpuc_msg *, const char *);
typedef int32 (*dpuc_msgparam_set_t)(dpuc_msg *, dpuc_eid_t, dpuc_eid_t, uint32, const char *);
typedef int32 (*dpuc_msgmem_reg_integrate_t)(dpuc_eid_obj *, dpuc_ctrl_msg_reg *, dpuc_datamsg_mem_ops *, const char *);
typedef int32 (*dpuc_send_rst_cb_func)(int32 siResult, dpuc_msg_param_s *pMsgParam, void *pContext);
typedef int32 (*dpuc_msg_send_t)(dpuc_msg *, dpuc_send_rst_cb_func, void *, const char *);
typedef uint32 (*dpuc_msglen_get_t)(dpuc_msg *, const char *);
typedef int32 (*dpuc_sgl_addr_set_t)(dpuc_msg *, SGL_S *, uint32, const char *);
typedef SGL_S *(*dpuc_sgl_addr_get_t)(dpuc_msg *, const char *);
typedef void *(*dpuc_data_addr_get_t)(dpuc_msg *, const char *);
typedef int32 (*dpuc_eid_make_t)(MSGTYPE_E, uint16, uint16, uint32, dpuc_eid_t *, const char *);
typedef int32 (*dpuc_eid_reg_t)(dpuc_comm_mgr *, dpuc_eid_t, dpuc_msg_recv_s *, dpuc_eid_obj **, const char *);
typedef int32 (*dpuc_set_src_eid_addr_t)(dpuc_eid_obj *, dpuc_addr *, uint32, dpuc_addr_type, const char *);
typedef int32 (*dpuc_set_dst_eid_addr_t)(dpuc_comm_mgr *, dpuc_eid_t, dpuc_addr *, uint32, const char *);
typedef int32 (*dpuc_set_eid_reactor_t)(dpuc_eid_obj *, const char *, dpuc_sched_conf_info_s *, const char *);
typedef int32 (*dpuc_set_subhealth_threshold_t)(dpuc_subhealth_threshold, const char *);
typedef int32 (*dpuc_process_set_config_t)(dpuc_necessary_config_param_t *,dpuc_optional_config_param_t *, const char *);
typedef void (*dpuc_xnet_set_process_ver_t)(u64);
typedef dpuc_comm_mgr *(*dpuc_all_init_t)(dpuc_comm_mgr_param *, const char *);
typedef int32 (*dpuc_regist_link_event_t)(dpuc_eid_t, const dpucLinkEventOps*, const char *);
typedef int32 (*dpuc_link_create_with_addr_t)(dpuc_eid_obj*, dpuc_eid_t, const dpuc_conn_params_t*, const char *);
typedef int32 (*dpuc_qlink_close_t)(uint32, dpuc_disConn_type, dpuc_plane_type_e, const char *);
typedef int32 (*dpuc_set_security_cert_info_t)(dpuc_security_cert_info_t *, const char *, uint32);
//dsw
typedef int32 (*dsw_core_init_t)(dsw_dpmm_pool_t *, int32, char *);
//umm
typedef void (*allocate_multi_pages_sync_t)(uint32, SGL_S **, uint32, const char *, const int32);
typedef void (*free_multi_pages_t)(SGL_S *, uint32, const char *, const int32);
typedef int32 (*copy_data_from_buf_to_sgl_t)(SGL_S *, uint32, char *, uint32);
typedef int32 (*copy_data_from_sgl_to_buf_t)(SGL_S *, uint32, char *, uint32);
typedef int32 (*dpumm_set_config_path_t)(char *, const char *, const uint32);
typedef void (*get_last_sgl_t)(SGL_S *, SGL_S **, uint32 *);
//dplog
typedef int32 (*dplog_init_t)(void);
typedef int32 (*dplog_set_backup_num_t)(uint32);
typedef int32 (*dplog_set_file_path_ext_t)(char *, char *);

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
    dpuc_set_security_cert_info_t dpuc_set_security_cert_info;

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