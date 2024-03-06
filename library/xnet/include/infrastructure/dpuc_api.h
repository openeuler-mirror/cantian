/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2020. All rights reserved.
 * Description: The head file of the uniform communication api

 * Create: 2015-08-11
 * Notes: NA
 * History: 2019-12-12:water:Split header file
 *
 */

#ifndef DPUC_API_H
#define DPUC_API_H

#include "dpuc_api_def.h"
#include "dpuc_outsite_api.h"
#include "dpuc_multi_instance_api.h"

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

#define DPUC_MSGMEM_REG_INTEGRATE(pEidObj, pCtrlMsgReg, pDataMsgMemOps) \
    dpuc_msgmem_reg_integrate((pEidObj), (pCtrlMsgReg), (pDataMsgMemOps), __FUNCTION__)

#define DPUC_MSGMEM_WITHCACHE_REG_INTEGRATE(pEidObj, pCtrlMsgReg, pDataMsgMemOps) \
        dpuc_msgmem_withcache_reg_integrate((pEidObj), (pCtrlMsgReg), (pDataMsgMemOps), __FUNCTION__)

#define DPUC_MSGMEM_UNREG_INTEGRATE(pEidObj) \
    dpuc_msgmem_unreg_integrate((pEidObj), __FUNCTION__)

#define DPUC_REQUEST_MULTISEND(pMsg, pMsgMultisendParam) \
    dpuc_request_multisend((pMsg), (pMsgMultisendParam), __FUNCTION__)

#define DPUC_ALL_INIT(pCommMgrParam) \
    dpuc_all_init((pCommMgrParam), __FUNCTION__)

#define DPUC_ALL_FINI(commMgr) dpuc_all_fini((commMgr), __FUNCTION__)

#define DPUC_EID_REG(pCommMgr, Eid, pFunc, pEidObj) \
    dpuc_eid_reg((pCommMgr), (Eid), (pFunc), (pEidObj), __FUNCTION__)

#define DPUC_SET_EIDOBJ_ATTR(pEidObj, attr_type, attr_value) \
    dpuc_set_eidobj_attr((pEidObj), (attr_type), (attr_value), __FUNCTION__)

#define DPUC_EID_UNREG(pEidObj) \
    dpuc_eid_unreg((pEidObj), __FUNCTION__)

#define DPUC_MSG_ALLOC(pMsgAllocParam) \
    dpuc_msg_alloc((pMsgAllocParam), __FUNCTION__)

#define DPUC_MSG_FREE(pMsg) \
    dpuc_msg_free((pMsg), __FUNCTION__)

#define DPUC_MSGPARAM_SET(pMsg, sendEid, recvEid, uiOpCode) \
    dpuc_msgparam_set((pMsg), (sendEid), (recvEid), (uiOpCode), __FUNCTION__)

#define DPUC_MSG_ATTR_SET(msg, msg_attr_type, msg_attr_value) \
    dpuc_msg_attr_set((msg), (msg_attr_type), (msg_attr_value), __FUNCTION__)

#define DPUC_MSG_ATTR_GET(msg, msg_attr_type, msg_attr_value) \
    dpuc_msg_attr_get((msg), (msg_attr_type), (msg_attr_value), __FUNCTION__)

#define DPUC_DATA_ADDR_GET(pMsg) \
    dpuc_data_addr_get((pMsg), __FUNCTION__)

#define DPUC_SGL_ADDR_SET(pMsg, pSgl, uiSglLen) \
    dpuc_sgl_addr_set((pMsg), (pSgl), (uiSglLen), __FUNCTION__)

#define DPUC_SGL_ADDR_GET(pMsg) \
    dpuc_sgl_addr_get((pMsg), __FUNCTION__)

#define DPUC_BUFFERLIST_ADDR_SET(pMsg, pBufferList) \
    dpuc_bufferlist_addr_set((pMsg), (pBufferList), __FUNCTION__)

#define DPUC_BUFFERLIST_ADDR_GET(pMsg, pBufferList) \
    dpuc_bufferlist_addr_get((pMsg), (pBufferList), __FUNCTION__)

#define DPUC_MSGLEN_GET(pMsg) \
    dpuc_msglen_get((pMsg), __FUNCTION__)

#define DPUC_SRC_EID_GET(pMsg) \
    dpuc_src_eid_get((pMsg), __FUNCTION__)

#define DPUC_DST_EID_GET(pMsg) \
    dpuc_dst_eid_get((pMsg), __FUNCTION__)

#define DPUC_OPCODE_GET(pMsg) \
    dpuc_opcode_get((pMsg), __FUNCTION__)

#define DPUC_MSGTYPE_GET(pMsg) \
    dpuc_msgtype_get((pMsg), __FUNCTION__)

#define DPUC_MBUFTYPE_GET(pMsg) \
    dpuc_mbuftype_get((pMsg), __FUNCTION__)

#define DPUC_MSG_SET_PRIO(pMsg, Prio) \
    dpuc_msg_set_prio((pMsg), (Prio), __FUNCTION__)

#define DPUC_MSG_GET_PRIO(pMsg) dpuc_msg_get_prio((pMsg), __FUNCTION__)

#define DPUC_RESULT_GET(pMsg) \
    dpuc_result_get((pMsg), __FUNCTION__)

#define DPUC_TIMEOUT_SET(pMsg, uiTimeOut) \
    dpuc_timeout_set((pMsg), (uiTimeOut), __FUNCTION__)

#define DPUC_RESULT_SET(pMsg, sResult) \
    dpuc_result_set((pMsg), (sResult), __FUNCTION__)

#define DPUC_MSG_SEND(pMsg, pfnCb, pContext) \
    dpuc_msg_send((pMsg), (pfnCb), (pContext), __FUNCTION__)

#define DPUC_POST(pMsg, pfnCb, pContext) \
    dpuc_msg_send((pMsg), (pfnCb), (pContext), __FUNCTION__)

#define DPUC_REQUEST_SEND(pMsg, uiTimeout, pfnCb, pContext) \
    dpuc_request_send((pMsg), (uiTimeout), (pfnCb), (pContext), __FUNCTION__)

#define DPUC_REQUESTID_GET(pReqMsg) \
    dpuc_requestid_get((pReqMsg), __FUNCTION__)

#define DPUC_RESPONSE_SEND(pRspMsg, requestID, pfnCb, pContext) \
    dpuc_response_send((pRspMsg), (requestID), (pfnCb), (pContext), __FUNCTION__)

#define DPUC_RESPONSE(pRspMsg, requestID, pfnCb, pContext) \
    dpuc_response_send((pRspMsg), (requestID), (pfnCb), (pContext), __FUNCTION__)

#define DPUC_RSP_SET_REQ(pRspMsg, pReqMsg) \
    dpuc_rsp_set_req((pRspMsg), (pReqMsg), __FUNCTION__)

#define DPUC_MSG_SET_MEMMODE(pMsg, MsgMemFreeMode) \
    dpuc_msg_set_memmode((pMsg), (MsgMemFreeMode), __FUNCTION__)

#define DPUC_MAKE_COMMUNICATE_LSID(lsid_type, clutser_id, proc_id, node_id) \
    dpuc_make_communicate_lsid((lsid_type), (clutser_id), (proc_id), (node_id), __FUNCTION__)

#define DPUC_GET_COMMUNICATE_LSID_TYPE(lsid) \
    dpuc_get_communicate_lsid_type((lsid), __FUNCTION__)

#define DPUC_GET_COMMUNICATE_CLUSTER_ID(lsid) \
    dpuc_get_communicate_cluster_id((lsid), __FUNCTION__)

#define DPUC_GET_COMMUNICATE_PROC_ID(lsid) \
    dpuc_get_communicate_proc_id((lsid), __FUNCTION__)

#define DPUC_GET_COMMUNICATE_NODE_ID(lsid) \
    dpuc_get_communicate_node_id((lsid), __FUNCTION__)

#define DPUC_DEFAULT_INIT_LSID 0

#define DPUC_EID_MAKE(MsgTypeId, usPid, usSubPid, uiServiceId, pEid) \
    dpuc_eid_make((MsgTypeId), (usPid), (usSubPid), (uiServiceId), (pEid), __FUNCTION__)

#define DPUC_NODEID_LEN 16
#define DPUC_LSID_MAKE(usPid, usNodeId) (((usPid) << DPUC_NODEID_LEN) | (usNodeId))

#define DPUC_GET_SERVICEID_FROM_EID(Eid) \
    dpuc_get_serviceid_from_eid((Eid), __FUNCTION__)

#define DPUC_GET_PID_FROM_EID(Eid) \
    dpuc_get_pid_from_eid((Eid), __FUNCTION__)

#define DPUC_GET_TYPE_FROM_EID(Eid) \
    dpuc_get_type_from_eid((Eid), __FUNCTION__)

#define DPUC_GET_SUBPID_FROM_EID(Eid) \
    dpuc_get_subpid_from_eid((Eid), __FUNCTION__)

#define DPUC_SET_SRC_EID_ADDR(pEidObj, pAddr, uiAddrNum, AddrType) \
    dpuc_set_src_eid_addr((pEidObj), (pAddr), (uiAddrNum), (AddrType), __FUNCTION__)

#define DPUC_SET_SRC_EID_ADDR_NEW(Eid, pAddr, uiAddrNum, AddrType, pCommMgr, pEidObj) \
    dpuc_set_src_eid_addr_new((Eid), (pAddr), (uiAddrNum), (AddrType),(pCommMgr),(pEidObj), __FUNCTION__)

#define DPUC_SET_DST_EID_ADDR(pCommMgr, DstEid, pAddr, uiAddrNum) \
    dpuc_set_dst_eid_addr((pCommMgr), (DstEid), (pAddr), (uiAddrNum), __FUNCTION__)

#define DPUC_SET_LINK_PARAM(dst_eid, conn_param)    \
    dpuc_set_link_param((dst_eid), (conn_param), __FUNCTION__)

#define DPUC_LINK_CREATE(pSrcEidObj, DstEid) \
    dpuc_link_create((pSrcEidObj), (DstEid), __FUNCTION__)

#define DPUC_LINK_CREATE_WITH_ADDR(pSrcEidObj, DstEid, pConnParam) \
    dpuc_link_create_with_addr((pSrcEidObj), (DstEid), (pConnParam), __FUNCTION__)

#define DPUC_LINK_DESTROY(pSrcEidObj, DstEid) \
    dpuc_link_destroy((pSrcEidObj), (DstEid), __FUNCTION__)

#define DPUC_SET_CFG_FILE_PATH(xmlFilePath) \
    dpuc_set_cfg_file_path((xmlFilePath),__FUNCTION__)

#define DPUC_SET_CFG_PARA(cfgType,cfgValue) \
    dpuc_set_cfg_para(cfgType,cfgValue,__FUNCTION__)

#define DPUC_RECALL_MSG(uiDstSerId, planeType) \
    dpuc_recall_msg((uiDstSerId), (planeType), __FUNCTION__)

#define DPUC_QLINK_CLOSE(uiDstSerId, disConnType, planeType) \
    dpuc_qlink_close((uiDstSerId),(disConnType), (planeType), __FUNCTION__)

#define DPUC_LINK_DISCONN_WITH_ADDR(dstEid, pDstAddr, disConnType, planeType) \
    dpuc_link_disconn_with_addr((dstEid), (pDstAddr), (disConnType), (planeType),__FUNCTION__)

#define DPUC_CLOSE_ALL_LINK() \
    dpuc_close_all_link(__FUNCTION__)

#define DPUC_REGIST_LINK_EVENT(Eid, pFunc) \
    dpuc_regist_link_event((Eid), (pFunc), __FUNCTION__)

#define DPUC_CHECK_LINK_STATUS(dstLsid, linkPortocol, planeType) \
    dpuc_check_link_status((dstLsid), (linkPortocol),(planeType),__FUNCTION__)

#define DPUC_GET_CACHE_LINK_STATUS(dst_eid, plane, conn_share_type) \
    dpuc_get_cache_link_status((dst_eid), (plane), (conn_share_type), __FUNCTION__)

#define DPUC_CHECK_CACHE_LINK_STATUS(dst_lsid, plane) \
    dpuc_check_cache_link_status((dst_lsid), (plane), __FUNCTION__)

#define DPUC_GET_ALL_LINK_STATUS(plane, status, link_status_result)    \
    dpuc_get_all_link_status(plane, status, link_status_result, __FUNCTION__)

#define DPUC_COPY_MSG(srcMsg) \
    dpuc_copy_msg((srcMsg), DPUC_MSG_RECV, __FUNCTION__)

#define DPUC_COPY_SEND_MSG(srcMsg) \
    dpuc_copy_msg((srcMsg), DPUC_MSG_SEND, __FUNCTION__)

#define DPUC_SET_LINK_CACHE_STRATEGY(pSrcEidObj, DstEid, planeType, cacheMode) \
    dpuc_set_link_cache_strategy((pSrcEidObj), (DstEid), (planeType), (cacheMode), __FUNCTION__)

#define DPUC_SET_DST_EID_ADDR_EX(pCommMgr, DstEid, pAddr, uiAddrNum, bufType) \
    dpuc_set_dst_eid_addr((pCommMgr), (DstEid), (pAddr), (uiAddrNum), __FUNCTION__)

#define DPUC_MSG_SEND_EX(pMsg, pfnCb, pContext) \
    dpuc_msg_send_ex((pMsg), (pfnCb), (pContext), __FUNCTION__)

#define DPUC_SET_SCHED_INFO(pSrcEidObj, cfgName) \
    dpuc_set_sched_info((pSrcEidObj), (cfgName), NULL, __FUNCTION__)

#define DPUC_SET_EID_REACTOR(pSrcEidObj, cfgName, cfgInfo) \
    dpuc_set_sched_info((pSrcEidObj), (cfgName), (cfgInfo), __FUNCTION__)

#define DPUC_GET_MSG_USER_VERSION(pMsg, ullVersion) \
    dpuc_get_msg_user_version((pMsg), (ullVersion), __FUNCTION__)

#define DPUC_SET_MSG_USER_VERSION(pMsg, ullversion) \
    dpuc_set_msg_user_version((pMsg), (ullversion), __FUNCTION__)

#define DPUC_PROCESS_SET_CONFIG(pNeedConfig, pOptConfig) \
    dpuc_process_set_config((pNeedConfig), (pOptConfig), __FUNCTION__)

#define DPUC_SET_MSG_PEER_CPU(pMsg, peerCpu) \
    dpuc_set_msg_peer_cpu((pMsg), (peerCpu), __FUNCTION__)

#define DPUC_SET_PLANE_INFO(plane, paramType, paramValue)\
    dpuc_set_plane_info((plane), (paramType), (paramValue), __FUNCTION__)

#define DPUC_CHECK_LINK_STATUS_BYIP(dstLsid, url, AddrType, planeType) \
    dpuc_check_link_status_byip((dstLsid), (url), (AddrType), (planeType),__FUNCTION__)

#define DPUC_GET_NO_RESPONSE_MSG_INFO(timeInval, rspCheckInfo, rspMsgInfo) \
    dpuc_get_no_response_msg_info((timeInval), (rspCheckInfo), (rspMsgInfo), __FUNCTION__)

#define DPUC_GET_REACTOR_ATTR(reactor_name, attr_type, attr_value) \
    dpuc_get_reactor_attr((reactor_name), (attr_type), (attr_value), __FUNCTION__)

#define DPUC_SET_REACTOR_ATTR(reactor_name, attr_type, attr_value) \
    dpuc_set_reactor_attr((reactor_name), (attr_type), (attr_value), __FUNCTION__)

#define DPUC_CLEAR_SRC_EID_ADDR(pEidObj, AddrType) \
    dpuc_clear_src_eid_addr((pEidObj), (AddrType), __FUNCTION__)

#define DPUC_XNET_SET_PROCESS_VER(proc_ver) \
    dpuc_xnet_set_process_ver(proc_ver)

#define DPUC_SET_SUNHEALTH_THRESHOLD(threshold) \
    dpuc_set_subhealth_threshold((threshold), __FUNCTION__)

#define DPUC_QUERY_QUEUE_SUBHEALTH_INFO(src_eid, dst_eid, plane, conn_type, queue_subhealth_status) \
    dpuc_query_queue_subhealth_info((src_eid), (dst_eid), (plane), (conn_type), (queue_subhealth_status), __FUNCTION__)

#define DPUC_SET_SECURITY_CERT_INFO(param) dpuc_set_security_cert_info((param), __FUNCTION__, MY_PID)

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cpluscplus */
#endif /* __cpluscplus */


#endif

/**@defgroup dpuc*/

