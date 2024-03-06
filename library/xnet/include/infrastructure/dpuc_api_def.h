/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: The head file of unified communication interface prototype and data structure definition

 * Create: 2019-12-12
 * Notes: NA
 * History: 2019-12-12:water:Split header file
 *
 */

#ifndef DPUC_API_DEF_H
#define DPUC_API_DEF_H

#include "dpax_typedef.h"
#include "req_sgl.h"
#include <sched.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

#define DPUC_MAX_U8       0xFF
#define DPUC_MAX_U16      0xFFFF
#define DPUC_MAX_U32      0xFFFFFFFF
#define DPUC_MAX_U64      0xFFFFFFFFFFFFFFFF
#define DPUC_INVALID_EID  0xFFFFFFFFFFFFFFFF
#define DPUC_DEFAULT_MSG_VERSION (0ULL)
#define DPUC_DEFAULT_MSG_ID (0ULL)

#define DPUC_MAX_BUFF_OF_BUFFERLIST (4)

#define DPUC_URL_LEN (64)

#ifdef __DPUC_ROC__
#define DPUC_SGL_CTRL_LEN_MAX (320)
#else
#define DPUC_SGL_CTRL_LEN_MAX (512)
#endif

#define DPUC_PID_MAX (2047)

#define DPUC_RETURN_VALUE_OK  (0)
#define DPUC_PARAM_INVALID    (22)

#define DPUC_HEALTH_CHK_NOT_START  (101)
#define DPUC_HEALTH_UNKNOWN        (102)
#define DPUC_HEALTH_NO_LINK        (103)
#define DPUC_HEALTH_DISCONNECT     (104)
#define DPUC_HEALTH_CHK_FAIL       (105)
#define DPUC_XNET_MAX_THRD_NUM     (32)
#define DPUC_MAX_REACTOR_NAME_LEN  (12)

typedef u64    dpuc_eid_t;
typedef u64    dpuc_request_id;

typedef struct tagDPUC_COMM_MGR  dpuc_comm_mgr;

typedef struct tagDPUC_EID_OBJ   dpuc_eid_obj;

typedef struct tagDPUC_MSG       dpuc_msg;

typedef enum tagDpucMsgType
{
    DPUC_TYPE_POST  = 1,
    DPUC_TYPE_REQ   = 2,
    DPUC_TYPE_RSP   = 3
} dpuc_msgtype_e;

typedef enum tagDpucInstanceMode
{
    DPUC_MOD_NORM  = 0,
    DPUC_MOD_ENCRYPT = 1,
    DPUC_MOD_BUTT
} dpuc_instance_mode_e;

typedef enum tagDpucMsgRole {
    DPUC_MSG_SEND = 1,
    DPUC_MSG_RECV = 2,
} dpuc_msgrole_t;

#define LOCAL_NODEID (0XFF)

typedef enum tagMSGTYPE_E
{
    NORMAL_TYPE   =  0,
    APITOMSG      =  1,
    LOCALE_TYPE   =  2,
    DPUC_MSG_INSTACNE_SIMU = 3,
    DPUC_MSG_TYPE_BUTT = 0x8
} MSGTYPE_E;

typedef enum tagMbufType
{
    DPUC_CTRL   = 1,
    DPUC_DATA   = 2,
    DPUC_DATA_XRB = 3,
    DPUC_MBUF_BUTT = 0XFF
} dpuc_mbuf_e;

typedef enum tagDpucPrio
{
    DPUC_PRIO_1 = 0,
    DPUC_PRIO_2 = 1,
    DPUC_PRIO_3 = 2,
    DPUC_PRIO_4 = 3,
    DPUC_PRIO_5 = 4,
    DPUC_PRIO_6 = 5,
    DPUC_PRIO_7 = 6,
    DPUC_PRIO_8 = 7,

    DPUC_PRIO_ABS = 0xF0,

    DPUC_PRIO_INVALID = 0xFF
}dpuc_prio_e;

typedef enum tagDpucResultType
{
    DPUC_RESULT_OK                = 0,
    DPUC_RESULT_NO_EID            = 1,
    DPUC_RESULT_QUE_NULL          = 2,
    DPUC_RESULT_SEND_QUE_FULL     = 3,
    DPUC_RESULT_QUE_FULL          = 4,
    DPUC_RESULT_RECV_PROCESS_EXIT = 5,
    DPUC_RSP_TIMEOUT              = 6,
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

typedef enum tagDpucPlaneType
{
    DPUC_MANAGE_PLANE   = 0,
    DPUC_COTROL_PLANE   = 1,
    DPUC_DATA_PLANE     = 2,
    DPUC_DEFAULT_PLANE  = 3,
    DPUC_INVALID_PLANE  = 0xFF,
}dpuc_plane_type_e;

typedef enum tagDpucDisConnType
{
    DPUC_DISCONNS_LINK        = 0,
    DPUC_DESTROY_LINK         = 1,
    DPUC_INVALID_DISCONN_TYPE = 0xFF,
}dpuc_disConn_type;

typedef enum tagDpucLinkProtocol
{
    DPUC_LINK_PROTOCOL_RDMA = 0,
    DPUC_LINK_PROTOCOL_TCP  = 1,
    DPUC_LINK_PROTOCOL_ALL  = 2,
    DPUC_LINK_PROTOCOL_BUTT = 0xFF,
}dpuc_link_protocol;

typedef enum tagDpucMsgMemFreeMode
{
    DPUC_AUTO_FREE = 0,
    DPUC_SELF_FREE = 1,
    DPUC_INVALID_FREE = 0xFF,
} dpuc_msg_mem_free_mode_e;

typedef enum tagDpucXnetQueueCacheMode
{
    DPUC_XNETQ_NO_NEED_CACHE = 0,
    DPUC_XNETQ_NEED_CACHE    = 1,
}dpuc_xnet_q_cache_mode_e;

typedef struct tagDpucMsgParam
{
    dpuc_msg  *pMsg;
    dpuc_eid_t sendEid;
    dpuc_eid_t recvEid;
    u16        usSrcNid;
    u16        usDstNid;
    u32        uiSrcServiceId;
    u32        uiDstServiceId;
    u32        uiOpcode;
} dpuc_msg_param_s;

typedef struct dpuc_buffer
{
    char* buf;
    uint32_t len;
}dpuc_buffer_t;

typedef struct dpuc_bufflist
{
    uint16_t cnt;
    dpuc_buffer_t buffers[DPUC_MAX_BUFF_OF_BUFFERLIST];
}dpuc_bufflist_t;

typedef struct tagDpucRspRst
{
    s32 siResult;
    dpuc_msg *pMsg;
    dpuc_msg_param_s MsgParam;
} dpuc_rsp_rst_s;

typedef s32 (*dpuc_multi_rsp_recv_func)(dpuc_rsp_rst_s* pRspList, u32 uiRspListNum, void* pContext);

typedef struct tagDpucSendRst
{
    s32 sResult;
    dpuc_msg_param_s MsgParam;
} dpuc_send_rst_s;

typedef s32 (*dpuc_multi_send_rst_cb_func)(dpuc_send_rst_s* pRstList, u32 uiRstListNum, void* pContext);

typedef s32 (*dpuc_alloc_req_msgmem)(dpuc_msg* pMsg, u32 uiSglDataLen, SGL_S **pSgl, void **pContext);

typedef s32 (*dpuc_alloc_rsp_msgmem)(dpuc_msg* pMsg, u32 uiSglDataLen, SGL_S **pSgl, void* pContext);

typedef void (*dpuc_free_msgmem)(dpuc_msg* pMsg, void* pContext);

typedef struct tagDpucDatamsgMemOps
{
    dpuc_alloc_req_msgmem  pfnReqAllocMsgMem;
    dpuc_alloc_rsp_msgmem  pfnRspAllocMsgMem;
    dpuc_free_msgmem       pfnFreeMsgMem;
    u32 uiSendDataMsgNumReserve;
    u32 uiSendDatamsgNumMax;
    u32 uiRecvDataMsgNumReserve;
    u32 uiRecvDatamsgNumMax;
} dpuc_datamsg_mem_ops;

typedef struct tagDpucDatamsgMemWithcacheOps
{
    dpuc_alloc_req_msgmem  pfnReqAllocMsgMem;
    dpuc_alloc_rsp_msgmem  pfnRspAllocMsgMem;
    dpuc_free_msgmem       pfnFreeMsgMem;
    u32 uiSendDataMsgNumReserve;
    u32 uiSendDatamsgNumMax;
    u32 uiRecvDataMsgNumReserve;
    u32 uiRecvDatamsgNumMax;
    u32 uiCacheNum;
    u32 uiCacheSize;
} dpuc_datamsg_mem_withcache_ops;

typedef struct tagDpucCtrlMsgInfo
{
    u32 uiMsgSize;
    u32 uiReserveNum;
    u32 uiMaxNum;
} dpuc_ctrl_msg_info;

typedef struct tagDpucCtrlMsgWithcacheInfo
{
    u32 uiMsgSize;
    u32 uiReserveNum;
    u32 uiMaxNum;
    u32 uiCacheNum;
    u32 uiCacheSize;
} dpuc_ctrl_msg_withcache_info;

typedef enum tagDpucMsgMemMode
{
    DPUC_CTRL_MSG_BUFF_DEFAULT = 0,
    DPUC_CTRL_MSG_BUFF_REVERSE = 1,
    DPUC_CTRL_MSG_BUFF_BUTT    = 0xFF
} dpuc_msg_mem_mode_e;

typedef struct tagDpucCtrlMsgReg
{
    dpuc_ctrl_msg_info* pSendMsg;
    u32                 uiSendMsgNum;
    dpuc_ctrl_msg_info* pRecvMsg;
    u32                 uiRecvMsgNum;
    u32                 uiMemMode;
} dpuc_ctrl_msg_reg;

typedef struct tagDpucCtrlMsgWithcacheReg
{
    dpuc_ctrl_msg_withcache_info* pSendMsg;
    u32                           uiSendMsgNum;
    dpuc_ctrl_msg_withcache_info* pRecvMsg;
    u32                           uiRecvMsgNum;
    u32                           uiMemMode;
} dpuc_ctrl_msg_withcache_reg;

typedef enum tagDpucAddrType
{
    DPUC_ADDR_CLIENT  = 0,
    DPUC_ADDR_SERVER  = 1,
    DPUC_ADDR_BUTT    = 0xFF
} dpuc_addr_type;


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

typedef struct tagDpucAddr
{
    dpuc_plane_type_e   PlaneType;
    dpuc_addr_family    AddrFamily;
    char Url[DPUC_URL_LEN];
} dpuc_addr;

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

typedef enum
{
    DPUC_PHY_PROTOCOL_TCP  = 0,
    DPUC_PHY_PROTOCOL_ROCE = 1,
    DPUC_PHY_PROTOCOL_IBV  = 2,
    DPUC_PHY_PROTOCOL_BUTT  = 0xFF
}dpuc_phy_protocol_type_t;

typedef struct
{
    dpuc_phy_protocol_type_t protocol_type;
    dupc_qlink_cause_t link_cause;
}dpuc_link_change_info_t;

typedef enum {
    DPUC_SUBHEALTH_ALGO_CONTINUE = 0,
    DPUC_SUBHEALTH_ALGO_CUMULATE = 1,
    DPUC_SUBHEALTH_ALGO_BUTT
}dpuc_subhealth_algo_t;

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

typedef struct
{
    dpuc_phy_protocol_type_t protocol_type;
    char *local_ip;
    char *remote_ip;
    dpuc_subhealth_type_t type;
    dpuc_subhealth_level_t level;
}dpuc_subhealth_info_t;

typedef struct {
    uint64_t latency[DPUC_SUBHEALTH_TYPE_BUTT];
    uint32_t subhealth_status[DPUC_SUBHEALTH_TYPE_BUTT];
    uint32_t is_link_flash;
}dpuc_xnet_queue_subhealth_status_t;

typedef struct
{
    char *local_ip;
    char *remote_ip;
}dpuc_ka_lost_info_t;

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

typedef struct dpuc_conn_params
{
    uint32_t pri;
    uint32_t time_out;

    uint32_t hop;
    dpuc_conn_recovery_pri_t recovery_pri;

    dpuc_addr *pSrcAddr;
    dpuc_addr *pDstAddr;

    uint32_t uisl;
    uint32_t kaInterval;
    uint32_t kaTimeoutTimes;

    dpuc_conn_running_mode_t runMode;
}dpuc_conn_params_t;

typedef struct tagDpucMsgMultisendParam
{
    dpuc_eid_t *pDstEidId;
    u32 uiDstEidIdNum;
    u32  uiTimeout;
    void *pSendRstContext;
    dpuc_multi_send_rst_cb_func pfnSentRetCb;
    void *pRspContext;
    dpuc_multi_rsp_recv_func    pfnRspRecvCb;
} dpuc_msg_multisend_param;

s32 dpuc_request_multisend(dpuc_msg *pMsg, dpuc_msg_multisend_param *pMsgMultisendParam, const char *funcName);

typedef s32 (*dpuc_req_recv_func)(dpuc_msg* pMsg, dpuc_msg_mem_free_mode_e* pMsgMemFreeMode);

typedef s32 (*dpuc_rsp_recv_func)(s32 siResult, dpuc_msg *pMsg, void *pContext,
    dpuc_msg_mem_free_mode_e *pMsgMemFreeMode);

typedef s32 (*dpuc_send_rst_cb_func)(s32 siResult, dpuc_msg_param_s *pMsgParam, void *pContext);

typedef s32 (*dpuc_link_Event_func)(u32 uiDstlsId, dpuc_qlink_event qlinkEvent, dpuc_plane_type_e planeType,
    dupc_qlink_cause_t qlinkCause);

typedef s32 (*dpuc_link_state_change_func)(u32 uiDstlsId, dpuc_link_state_event_t qlinkEvent,
    dpuc_plane_type_e planeType, void *param);

typedef s32 (*dpuc_exclude_link_Event_func)(dpuc_eid_t uiDstEid, dpuc_qlink_event qlinkEvent, 
    dpuc_plane_type_e planeType);

typedef struct tagDpucMsgRecv
{
    dpuc_req_recv_func  pfnHpucReqRecvFun;
    dpuc_rsp_recv_func  pfnHpucRspRecvFun;
}dpuc_msg_recv_s;

typedef struct tagDpucLinkEventOps
{
    dpuc_link_Event_func pfndpucLinkeventFun;
    dpuc_link_state_change_func pfndpucLinkStateChangeFun;
    dpuc_exclude_link_Event_func pfndpucExcludeLinkeventFun;
}dpucLinkEventOps;

typedef struct tagDpucCommMgrParam
{
    u32 uiRecvQueueSize;
    u32 uiRstQueueSize;
    u16 usPid;
    u32 uiServiceId;
    u8  ucMode;
} dpuc_comm_mgr_param;

dpuc_comm_mgr *dpuc_all_init(dpuc_comm_mgr_param *pCommMgrParam, const char *funcName);

s32 dpuc_all_fini(dpuc_comm_mgr *commMgr, const char *funcName);

typedef struct tagDpucMsgAllocParam
{
    dpuc_eid_obj  *pEidObj;
    dpuc_msg       *pMsgTemplate;
    u32             uiSize;
    u8              ucDataType;
    u8              ucMsgType;
} dpuc_msg_alloc_param;

dpuc_msg* dpuc_msg_alloc(dpuc_msg_alloc_param *pMsgAllocParam, const char *funcName);

s32 dpuc_msg_free(dpuc_msg *pMsg, const char *funcName);

dpuc_msg* dpuc_copy_msg(dpuc_msg *srcMsg, dpuc_msgrole_t role, const char *funcName);

s32 dpuc_msgparam_set(dpuc_msg *pMsg, dpuc_eid_t sendEid, dpuc_eid_t recvEid, u32 uiOpCode,
    const char *funcName);

typedef enum {
    DPUC_RECV_BUFFER_SGL = 1,
    DPUC_RECV_BUFFER_BUFFERLIST,
    DPUC_RECV_BUFFER_BUTT
}dpuc_recv_buffer_type_e;

typedef enum {
    DPUC_CONN_SHARED_TYPE = 1,
    DPUC_CONN_EXCLUE_TYPE,
    DPUC_CONN_SHARE_TYPE_BUTT = 0xFF
}dpuc_conn_share_type_e;

typedef enum {
    DPUC_MSG_FLOW_CONTROL_UNSUPPORT = 0,
    DPUC_MSG_FLOW_CONTROL_SUPPORT,
    DPUC_MSG_FLOW_CONTROL_INVAILD = 0xFF
}dpuc_msg_flow_control_type_e;

typedef enum {
    DPUC_MSG_IO_MODE_DEFAULT = 0,
    DPUC_MSG_IO_MODE_BY_PASS,
    DPUC_MSG_IO_MODE_INVAILD = 0xFF
}dpuc_msg_io_mode_type_e;

typedef enum {
    DPUC_MSG_ACK_TYPE_DEFAULT = 0,
    DPUC_MSG_NO_ACK,
    DPUC_MSG_ACK_TYPE_INVAILD = 0xFF
}dpuc_msg_ack_type_e;

typedef enum {
    DPUC_MSG_CONN_TYPE = 0,
    DPUC_MSG_RECV_BUFFER_TYPE,
    DPUC_MSG_FLOW_CONTROL_TYPE,
    DPUC_MSG_IO_MODE_TYPE,
    DPUC_MSG_ROUTE_KEY,
    DPUC_MSG_ACK_TYPE,
    DPUC_MSG_RECV_NUMA,
    DPUC_RSP_MSG_RECV_NUMA,
    DPUC_SET_RSP_TIMEOUT_TYPE,
    DPUC_LOGIC_PORT_ID,
    DPUC_MSG_ATTR_BUFF = 0xFF
}dpuc_msg_attr_t;

typedef enum tagDpucLsidType {
    DPUC_STORAGE_LSID             = 0,
    DPUC_COMPUTE_TO_STORAGE_LSID  = 2,
} dpuc_lsid_type_e;

typedef enum {
    DPUC_RSP_TIMEOUT_DEFAULT = 0,
    DPUC_FORCE_SET_RSP_TIMEOUT,
    DPUC_RSP_TIMEOUT_INVAILD = 0xFF
}dpuc_rsp_timeout_type_e;
int32_t dpuc_msg_attr_set(dpuc_msg* msg, dpuc_msg_attr_t msg_attr_type, void* msg_attr_value,
    const char* func_name);

int32_t dpuc_msg_attr_get(dpuc_msg* msg, dpuc_msg_attr_t msg_attr_type, void* msg_attr_value,
    const char* func_name);

s32 dpuc_msg_set_memmode(dpuc_msg *pMsg, dpuc_msg_mem_free_mode_e MsgMemFreeMode,
    const char *funcName);
    
u32 dpuc_opcode_get(dpuc_msg *pMsg, const char *funcName);

void *dpuc_data_addr_get(dpuc_msg *pMsg, const char *funcName);

u32 dpuc_msglen_get(dpuc_msg *pMsg, const char *funcName);

s32 dpuc_sgl_addr_set(dpuc_msg *pMsg, SGL_S *pSgl, u32 uiSglLen,
    const char *funcName);

SGL_S *dpuc_sgl_addr_get(dpuc_msg *pMsg, const char *funcName);

s32 dpuc_bufferlist_addr_set(dpuc_msg *pMsg, dpuc_bufflist_t  *pBufferList,
    const char *funcName);

void dpuc_bufferlist_addr_get(dpuc_msg *pMsg, dpuc_bufflist_t *pBufferList,
    const char *funcName);

dpuc_eid_t dpuc_src_eid_get(dpuc_msg *pMsg, const char *funcName);

dpuc_eid_t dpuc_dst_eid_get(dpuc_msg *pMsg, const char *funcName);

u8 dpuc_msgtype_get(dpuc_msg *pMsg, const char *funcName);

u8 dpuc_mbuftype_get(dpuc_msg *pMsg, const char *funcName);

s32 dpuc_msg_set_prio(dpuc_msg *pMsg, dpuc_prio_e  Prio, const char *funcName);

dpuc_prio_e dpuc_msg_get_prio(dpuc_msg *pMsg, const char *funcName);

s32 dpuc_result_set(dpuc_msg *pMsg, s32 sResult, const char *funcName);

s32 dpuc_result_get(dpuc_msg *pMsg, const char *funcName);

int32_t dpuc_timeout_set(dpuc_msg *pMsg, u32 uiTimeOut, const char *funcName);

s32 dpuc_get_msg_user_version(dpuc_msg *pMsg, u64 *ullVersion, const char *funcName);

s32 dpuc_set_msg_user_version(dpuc_msg *pMsg, u64 ullversion, const char *funcName);

s32 dpuc_set_msg_peer_cpu(dpuc_msg *pMsg, u32 peerCpu,  const char *funcName);

s32 dpuc_msg_send(dpuc_msg *pMsg, dpuc_send_rst_cb_func pfnCb, void *pContext,
    const char *funcName);

s32 dpuc_msg_send_ex(dpuc_msg *pMsg, dpuc_send_rst_cb_func pfnCb, void *pContext,
    const char *funcName);

s32 dpuc_request_send(dpuc_msg *pMsg, u32 uiTimeout, dpuc_send_rst_cb_func pfnCb,void *pContext,
    const char *funcName);

dpuc_request_id dpuc_requestid_get(dpuc_msg *pReqMsg, const char *funcName);

s32 dpuc_response_send(dpuc_msg *pRspMsg, dpuc_request_id requestID, dpuc_send_rst_cb_func pfnCb,
    void *pContext, const char *funcName);

s32 dpuc_rsp_set_req(dpuc_msg *pRspMsg, dpuc_msg *pReqMsg, const char *funcName);

s32 dpuc_recall_msg(u32 uiDstSerId, dpuc_plane_type_e planeType, const char *funcName);

uint32_t dpuc_make_communicate_lsid(dpuc_lsid_type_e lsid_type, uint8_t clutser_id, uint8_t proc_id,
    uint16_t node_id, const char *func_name);

dpuc_lsid_type_e dpuc_get_communicate_lsid_type(uint32_t lsid, const char *func_name);

uint8_t dpuc_get_communicate_cluster_id(uint32_t lsid, const char *func_name);

uint8_t dpuc_get_communicate_proc_id(uint32_t lsid, const char *func_name);

uint16_t dpuc_get_communicate_node_id(uint32_t lsid, const char *func_name);

s32 dpuc_eid_make(MSGTYPE_E MsgTypeId, u16 usPid,  u16 usSubPid, u32 uiServiceId, dpuc_eid_t *pEid,
    const char *funcName);

s32 dpuc_eid_reg(dpuc_comm_mgr *pCommMgr, dpuc_eid_t Eid, dpuc_msg_recv_s *pFunc, dpuc_eid_obj **pEidObj,
    const char *funcName);

s32 dpuc_eid_unreg(dpuc_eid_obj *pEidObj, const char *funcName);

s32 dpuc_msgmem_reg_integrate(dpuc_eid_obj* pEidObj, dpuc_ctrl_msg_reg* pCtrlMsgReg,
    dpuc_datamsg_mem_ops* pDataMsgMemOps, const char* funcName);

s32 dpuc_msgmem_withcache_reg_integrate(dpuc_eid_obj *pEidObj, dpuc_ctrl_msg_withcache_reg *pCtrlMsgReg,
    dpuc_datamsg_mem_withcache_ops *pDataMsgMemOps, const char *funcName);
    
s32 dpuc_msgmem_unreg_integrate(dpuc_eid_obj *pEidObj, const char *funcName);

u32 dpuc_get_serviceid_from_eid(dpuc_eid_t Eid, const char *funcName);

u16 dpuc_get_pid_from_eid(dpuc_eid_t Eid, const char *funcName);

u8 dpuc_get_type_from_eid(dpuc_eid_t Eid, const char *funcName);

u16 dpuc_get_subpid_from_eid(dpuc_eid_t Eid, const char *funcName);

s32 dpuc_set_src_eid_addr(dpuc_eid_obj *pEidObj, dpuc_addr *pAddr, u32 uiAddrNum, dpuc_addr_type AddrType,
    const char *funcName);

s32 dpuc_set_src_eid_addr_new(dpuc_eid_t Eid, dpuc_addr *pAddr, u32 uiAddrNum, dpuc_addr_type AddrType,
    dpuc_comm_mgr *pCommMgr, dpuc_eid_obj **pEidObj, const char *funcName);

s32 dpuc_set_dst_eid_addr(dpuc_comm_mgr *pCommMgr, dpuc_eid_t DstEid, dpuc_addr *pAddr, u32 uiAddrNum,
    const char *funcName);

int32_t dpuc_clear_src_eid_addr(dpuc_eid_obj* eid_obj, dpuc_addr_type addr_type, const char *func_name);

int32_t dpuc_link_create(dpuc_eid_obj* src_eid_obj, dpuc_eid_t dst_eid, const char* func_name);

int32_t dpuc_set_link_param(dpuc_eid_t dst_eid, dpuc_conn_params_t* conn_param, const char* func_name);

int32_t dpuc_link_create_with_addr(dpuc_eid_obj* src_eid_obj, dpuc_eid_t dst_eid,
    const dpuc_conn_params_t* conn_param, const char* func_name);

int32_t dpuc_link_destroy(dpuc_eid_obj* src_eid_obj, dpuc_eid_t dst_eid, const char* func_name);

int32_t dpuc_qlink_close(uint32_t dst_lsid, dpuc_disConn_type dis_conn_type, dpuc_plane_type_e plane_type,
    const char* func_name);

int32_t dpuc_link_disconn_with_addr(dpuc_eid_t dst_eid, dpuc_addr* dst_addr, dpuc_disConn_type dis_conn_type,
    dpuc_plane_type_e planeType, const char *funcName);

int32_t dpuc_close_all_link(const char *funcName);

int32_t dpuc_regist_link_event(dpuc_eid_t eid, const dpucLinkEventOps* event_func, const char* func_name);

int32_t dpuc_check_link_status(uint32_t dst_lsid, dpuc_link_protocol link_portocol, dpuc_plane_type_e plane_type,
    const char *func_name);

typedef enum {
    DPUC_LINK_STAT_INVALID  = 0x0UL,
    DPUC_LINK_STAT_INIT     = 0x1UL,
    DPUC_LINK_STAT_STRATING = 0x2UL,
    DPUC_LINK_STAT_UP       = 0x4UL,
    DPUC_LINK_STAT_DOWN     = 0x8UL,
}dpuc_link_status_e;

typedef struct tagDpucLinkInfoStatus {
    dpuc_eid_t src_eid;
    dpuc_eid_t dst_eid;
    dpuc_plane_type_e plane;
    dpuc_conn_share_type_e conn_share_type;
    dpuc_link_status_e status;
    int32_t pad;
}dpuc_link_status_info_t;

typedef struct tagDpucLinkStatus {
    dpuc_link_status_info_t *link_status_infos;
    uint32_t array_len;
    uint32_t valid_len;
    uint32_t conn_num;
    int32_t pad;
}dpuc_link_status_t;

int32_t dpuc_get_all_link_status(dpuc_plane_type_e plane, uint64_t status, dpuc_link_status_t *link_status_result,
    const char *func);

dpuc_link_status_e dpuc_get_cache_link_status(dpuc_eid_t dst_eid, dpuc_plane_type_e plane,
    dpuc_conn_share_type_e conn_share_type, const char *func);

int32_t dpuc_check_cache_link_status(uint32_t dst_lsid, dpuc_plane_type_e plane, const char *func_name);

int32_t dpuc_check_link_status_byip(uint32_t dst_lsid, const char* url, dpuc_addr_family addr_type,
    dpuc_plane_type_e plane_type, const char *func_name);

int32_t dpuc_set_link_cache_strategy(dpuc_eid_obj* src_eid_obj, dpuc_eid_t dst_eid, dpuc_plane_type_e plane_type, 
    dpuc_xnet_q_cache_mode_e cache_mode, const char* func_name);

typedef struct tagDPUC_XNET_THREAD_INFO {
    uint32_t    pri;
    cpu_set_t   cpu_set;
}dpuc_xnet_thread_info_s;

typedef struct tagDPUC_SCHED_CONF_INFO {
    int32_t                 bind;
    int32_t                 dead_loop;
    dpuc_xnet_thread_info_s *thread_info;
    uint32_t                thread_num;
}dpuc_sched_conf_info_s;

s32 dpuc_set_sched_info(dpuc_eid_obj *pSrcEidObj, const char *cfgName, dpuc_sched_conf_info_s *cfgInfo,
    const char *funcName);

typedef enum tagDpucCfgPara {
    DPUC_COMM_MNG_MAX_NUM = 0,
    DPUC_EID_MAX_NUM = 1,
    DPUC_ROUTE_MAX_NUM = 2,
    DPUC_LINK_MAX_NUM = 3,
    DPUC_MULTI_MSG_MAX_NUM = 4,
    DPUC_CLIENT_THREAD_NUM = 5,
    DPUC_SERVER_THREAD_NUM = 6,
    DPUC_MSG_THREAD_NUM = 7,
    DPUC_CFG_BUTT
} dpuc_cfg_para_en;

s32 dpuc_set_cfg_file_path(char *xmlFilePath, const char *funcName);

s32 dpuc_set_cfg_para(dpuc_cfg_para_en cfgType,u32 cfgValue, const char *funcName);

typedef struct tagDpucNecessaryConfigParam {
    u32 maxDstSerId;

    u16 eidMaxNum;
    u16 planeNeed;
    u64 maxSendMsgQuota;
    u64 maxReveMsgQuota;

    u32 ctrlMaxTcpConnNums;
    u32 ctrlMaxRdmaConnNums;
    u32 dataMaxTcpConnNums;
    u32 dataMaxRdmaConnNums;
}dpuc_necessary_config_param_t;

typedef struct tagDpucCtrlBufferConfigParam {
    struct  tagDpucBufferParam {
        u32 bufferSize64KMin;
        u32 bufferSize128KMin;
        u32 bufferSize256KMin;
        u32 bufferSize512KMin;
        u16 bufferSize1MMin;
        u16 bufferSize4MMin;
        u16 bufferExtend;
    }bufferConfig;
    u16 activeBufferConfig;
}dpuc_buffer_config_param_t;

typedef struct tagDpucOptinalParam {
    u8  activeConfig;
    u8  reserve[3];
    s32 configValue;
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

s32 dpuc_process_set_config(dpuc_necessary_config_param_t *pNeedConfig,
    dpuc_optional_config_param_t *pOptConfig, const char *funcName);

typedef enum tagDupcPlanePramater {
    DPUC_VRF_PLANE = 0,
    DPUC_PLANE_PARAM_BUTT=0xFF,
}dpuc_plane_param_e;

s32 dpuc_set_plane_info(dpuc_plane_type_e plane, dpuc_plane_param_e paramType,
    void *paramValue, const char *funcName);

typedef struct tagDpucNoRspMsgInfo {
    uint16_t srcMid;
    uint8_t reserve[2];
    uint32_t uiMsgNum;
    dpuc_eid_t dstEid;
}dpuc_rsp_result_info_s;

typedef struct tagDpucNoRspMsgBuf {
    uint32_t arrayLen;
    uint32_t validLen;
    dpuc_rsp_result_info_s *rspResult;
}dpuc_rsp_msg_buf;

typedef struct tagDpucRspCheckInfo
{
    uint16_t srcMid;
    dpuc_plane_type_e plane;
}dpuc_rsp_check_info_s;

s32 dpuc_get_no_response_msg_info(u64 timeInval, dpuc_rsp_check_info_s *rspCheckInfo,
    dpuc_rsp_msg_buf *rspMsgInfo, const char *funcName);

typedef enum {
    DPUC_REACTOR_DISPATCH_SLAVE_SMART = 0,
    DPUC_REACTOR_DISPATCH_SLAVE_FORCE = 1,
    DPUC_REACTOR_DISPATCH_SLAVE_BUTT
} dpuc_reactor_dispatch_ploy_e;

typedef enum {
    DPUC_REACTOR_THREAD_NUM = 0,
    DPUC_REACTOR_CB_FUNC,
    DPUC_REACTOR_SLAVE_THD_TIMES,
    DPUC_REACTOR_THRD_HEAL_TIME,
    DPUC_REACTOR_DISPATCH_PLOY,
    DPUC_REACTOR_ATTR_TYPE_BUTT
} dpuc_reactor_attr_e;

typedef enum {
    DPUC_REACTOR_FUNC_BREAK = 0,
    DPUC_REACTOR_FUNC_CONTINUE = 1
} dpuc_reactor_fn_mode;

typedef uint32_t (*reactor_cb_fn)(dpuc_reactor_fn_mode *mode);

int32_t dpuc_get_reactor_attr(const char* reactor_name, dpuc_reactor_attr_e attr_type, void* attr_value,
    const char *func_name);

int32_t dpuc_set_reactor_attr(const char* reactor_name, dpuc_reactor_attr_e attr_type, void* attr_value,
    const char *func_name);

typedef enum {
    DPUC_GET_DATA_PLANE_USER_NEG_DATA = 0,
    DPUC_CHECK_DATA_PLANE_USER_NEG_DATA,
    DPUC_GET_CTRL_PLANE_USER_NEG_DATA,
    DPUC_CHECK_CTRL_PLANE_USER_NEG_DATA,
    DPUC_EIDOBJ_ATTR_TYPE_BUTT
} dpuc_eidobj_attr_e;

typedef int32_t (*dpuc_get_user_neg_data_func)(void *user_neg_data_buff, int32_t neg_data_buff_len,
    int32_t *valid_data_len, uint32_t *check_mid, uint32_t *check_submid);

typedef int32_t (*dpuc_check_user_neg_data_func)(void *user_neg_data, int32_t data_len);

int32_t dpuc_set_eidobj_attr(dpuc_eid_obj *eid_obj, dpuc_eidobj_attr_e attr_type, void* attr_value,
    const char *func_name);

void dpuc_xnet_set_process_ver(uint64_t proc_ver);

typedef enum {
    DPUC_CGW_TCP = 0,
    DPUC_CGW_RDMA = 1,
    DPUC_XNET_TCP = 2,
    DPUC_XNET_RDMA = 3,
    DPUC_LINK_TYPE_BUTT
} dpuc_subhealth_link_type_e;

typedef struct {
    dpuc_subhealth_link_type_e type;
    uint32_t hop;
    uint64_t upgradeTimeNs;
    uint64_t degradeTimeNs;
    dpuc_plane_type_e plane;
    uint64_t time_ns[DPUC_SUBHEALTH_TYPE_BUTT][DPUC_SUBHEALTH_LEVEL_BUTT][DPUC_SUBHEALTH_ALGO_BUTT];
} dpuc_subhealth_threshold;
 
int32_t dpuc_set_subhealth_threshold(dpuc_subhealth_threshold threshold, const char* func_name);

void dpuc_query_queue_subhealth_info(dpuc_eid_t src_eid, dpuc_eid_t dst_eid, dpuc_plane_type_e plane,
    dpuc_conn_share_type_e conn_type, dpuc_xnet_queue_subhealth_status_t *queue_subhealth_status, const char *func_name);

#define DPUC_MAX_FILE_NAME_LEN 512
typedef struct {
    bool security_cert_switch;
    uint32_t user_id;
    char pri_key_file[DPUC_MAX_FILE_NAME_LEN];
    char pub_key_file[DPUC_MAX_FILE_NAME_LEN];
    char pri_key_pass_file[DPUC_MAX_FILE_NAME_LEN];
    int32_t (*get_pub_key_func)(uint32_t user_id, char *pub_key_file, uint32_t *pub_key_file_len);
    int32_t (*kmca_decrypt_func)(char *pass_key, uint32_t pass_key_len, char *plain_key, uint32_t max_key_len, uint32_t *plain_key_len);
} dpuc_security_cert_info_t;

int32_t dpuc_set_security_cert_info(dpuc_security_cert_info_t *security_cert_info, const char *func_name, uint32_t pid);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#endif
