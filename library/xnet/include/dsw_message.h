/******************************************************************************

           版权所有 (c) 华为技术有限公司 2018-2019

  文 件 名   : dsw_message.h
  版 本 号   : 初稿
  作    者   : 尹欢 yinhuan
  创建日期   : 2019年3月12日
  最近修改   :
  功能说明   : datanet message 消息管理

******************************************************************************/
#ifndef __dsw_message_pub_h__
#define __dsw_message_pub_h__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <securec.h>

#include "dpax_list.h"
#include "dsw_multi_instance.h"
#include "dsw_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#pragma pack(1)

/*
 * Description word of message segment
 *
 * Define the number of data segment in the message to make pre-allocate memory for processing at the time of 
 * module receiving message possible, and avoiding memory copy cost
 *
 * In the DSWare, since it is xnet_required to align IO data with 512, the type of message segment should be shown clearly,
 * and special memory pool should be used
 */
#define DSW_MESSAGE_SEGMENT_FMT        0x00
#define DSW_MESSAGE_SEGMENT_NORMAL     0x01
#define DSW_MESSAGE_SEGMENT_IO         0x02
#define DSW_MESSAGE_SEGMENT_SHM_NORMAL 0x03
#define DSW_MESSAGE_SEGMENT_SHM_IO     0x04
#define DSW_DEFALUT_FILEID             0XFFFF

#define DSW_MESSAGE_TIMESTAMP_MAGIC 0xE0

/* 该结构在传输过程中, 占用msg head中的预留字段: reserved[16], 所以大小不能超过16 */
typedef struct dsw_message_timestamp_s {
    dsw_u8 point;      /* message时间戳处理阶段 */
    dsw_u16 send_time; /* 发送时间戳 */
    dsw_u16 recv_time; /* 接收时间戳 */
} dsw_message_timestamp_t;

typedef struct {
    dsw_u32 type; /* Data type */
    dsw_u32 length;
} dsw_message_segment_desc_t;

/*
 * Definition of mesage head
 *
 * Message composes of head and body. The message body defined by DSWare has at most four data segments,
 * and each segment has a determined data type. See message decription word for details.
 *
 * Request ID is a unique ID created by source node of each message and is composed of high 32 bits and low 32 bits.
 * High 32 bits is the node ID of source node, while low 32 bits is the atomic variable value of current node.
 *
 * Source node ID as well as target node has three parts, namely 16 bits cluster ID, 16 bits current node type and 32 bits
 * node number
 *
 * Message service type means the type of service used by current message. When users send network message, the attribute is
 * used to inform network module sending message through corresponding port
 */
#define DSW_MESSAGE_MAGIC       0x12345678
#define INNER_ITF_MSG_VER_NULL  0 // 无效版本号
#define INNER_ITF_MSG_VER_1     1 // 内部消息接口版本号1: R3C00/R3C01中使用
#define INNER_ITF_MSG_VER_2     2 // 内部消息接口版本号2: R3C02中使用
#define INNER_ITF_MSG_VER_3     3
#define INNER_ITF_MSG_VER_4     4
#define INNER_ITF_MSG_VER_5     5
#define INNER_ITF_MSG_VER_6     6
#define INNER_ITF_MSG_VER_7     7
#define INNER_ITF_MSG_VER_8     8
#define INNER_ITF_MSG_VER_9     9
#define INNER_ITF_MSG_VER_10    10
#define INNER_ITF_MSG_VER_14    14
#define INNER_ITF_MSG_VER_15    15
#define INNER_ITF_MSG_VER_16    16
#define INNER_ITF_MSG_VER_17    17
#define INNER_ITF_MSG_VER_20    20 // add for ec
#define INNER_ITF_MSG_VER_21    21 // add for eccache bst
#define INNER_ITF_MSG_VER_25    25 // add for fs 6.3 async replication
#define INNER_ITF_MSG_VER_26    26 // add for fs 6.3 C30SPC100
#define INNER_ITF_MSG_VER_27    27 // add for fs 6.3 C30SPC200 IPV4&&IPV6
#define INNER_ITF_MSG_VER_35    35 // add for fs 6.3 IP confilct

// P层pclint使用
DECLARE_OSD_VAR(dsw_u32, g_cluster_cur_ver);
#define g_cluster_cur_ver OSD_VAR(g_cluster_cur_ver)
// P层pclint使用end
#define DSW_MESSAGE_VERSION                          (INNER_ITF_MSG_VER_35)
#define DSW_MESSAGE_HANA_NET_NEGOTIATION_VERSION     (XNET_NULL_DWORD - 1)  // 网络协商消息接口版本号1: R3C02中使用
#define DSW_MESSAGE_HANA_NET_NEGOTIATION_ACK_VERSION (XNET_NULL_DWORD - 2)

// 网络协商消息接口版本号2: R3C03中使用, 两端版本不匹配时使用INNER_ITF_MSG_VER_1
#define DSW_MESSAGE_NET_NEGOTIATION_VERSION_2     (XNET_NULL_DWORD - 3)
#define DSW_MESSAGE_NET_NEGOTIATION_ACK_VERSION_2 (XNET_NULL_DWORD - 4)

// 网络协商消息接口版本号3: R3C03中使用, 10GE双平面引入，不匹配时使用INNER_ITF_MSG_VER_1
#define DSW_MESSAGE_NET_NEGOTIATION_VERSION_3     (XNET_NULL_DWORD - 5)
#define DSW_MESSAGE_NET_NEGOTIATION_ACK_VERSION_3 (XNET_NULL_DWORD - 6)

#define DSW_MESSAGE_SEGMENT_DESC_NUM_MAX  4
#define DSW_MESSAGE_SEG_BUF_MAX_LENGTH   (100 * 1024 * 1024)  // 100M

#define DSW_MESSAGE_TS_NORMAL  0
#define DSW_MESSAGE_TS_DROPED  0xFFFFFFFFFFFFFFFF

#define DSW_NET_CRC_NO_CHK  0

#define DSW_NET_SET_CRC_DEFAULT    0
#define DSW_NET_SET_TCP_CRC        1
#define DSW_NET_SET_RDMA_HEAD_CRC  2
#define DSW_NET_SET_RDMA_BUF_CRC   3

/** 
  * @ingroup Message
  * message时间戳阶段点：发送memsage请求。
 */
#define DSW_MESSAGE_TIMESTAMP_REQ  0x1

/** 
  * @ingroup Message
  * message时间戳阶段点：发送memsage响应。
 */
#define DSW_MESSAGE_TIMESTAMP_RESP 0x2

typedef struct token_latency_timestamp_s {
    dsw_u16 start_time;
    dsw_u16 latency;
} token_latency_timestamp_t;

typedef enum {
    IO_TYPE_COMM_READ = 0,
    IO_TYPE_COMM_WRITE,
    IO_TYPE_META_READ,
    IO_TYPE_META_WRITE,
    IO_TYPE_MAX
} io_type_e;

/* reserved for updating
 * 1. detect msg use 6 bytes for apm lids
 * 2. unhealthy used the first 5 bytes, and negotiation used 6th byte
 * 3. 前面的#pragma pack(1)保证了内存一字节对齐
 */
typedef union message_head_reserved_s {
    dsw_u8 reserved[12];

    /**
     * client模块:
     * update map when IOView is changed.
     * delete_all_osd_in_pool 1:删除池子内所有osd，0:删除指定osd
    */
    struct update_map_in_del_pool_s {
        dsw_u32 osd_id;
        dsw_u8 delete_all_osd_in_pool;
    } update_map_in_del_pool;

    dsw_u16 pool_id;  // client 模块
    dsw_u8 io_type;   // vbp/kvs-client判断是否双活IO
    dsw_u32 rep_scsi_tmout;  // 同步FS6.3 双活端到端超时时间

    // WARN:don't expand this struct ,or will cause conflict with "struct token_latency_s"
    struct unhealthy_and_negoation_s {
        dsw_message_timestamp_t message_timestamp;  // unhealthy used the first 5 bytes
        dsw_u8 ret_code;                           // negotiation used 6th byte
    } unhealthy_and_negoation;

    struct token_latency_s {
        dsw_u8 padding[6];                                 // padding for unhealthy_and_negoation
        token_latency_timestamp_t token_latency_timestamp;  // rsm使用
    } token_latency;

    // VBS合入
    struct kv_io_timeout_s {
        dsw_u32 timeout;  // kvs module
        dsw_u8 kv_flag;   // true: kv io
    } kv_io_timeout;
    
    // VBS合入end
    struct msg_ipv6_is_convert_s {
        dsw_u8                     padding[11];    //padding
        dsw_u8                     convert_flag;   //用于标识该消息在支持ipv4/ipv6的版本中是否已经被转换
    } is_convert;
} message_head_reserved_t;

/** 
   * @ingroup Message
   * message时间戳阶段点：所有阶段点。
 */
typedef struct {
    dsw_u32 magic;
    dsw_u32 version;
    dsw_u64 request_id; /* Request ID */
    dsw_u32 src_nid;    /* Source node ID */
    dsw_u32 dst_nid;    /* Destination node ID */
    dsw_u8 net_point;   /* Type of net point */
    dsw_u8 src_mid;
    dsw_u8 dst_mid;
    dsw_u32 cmd_type;  /* Command type */
    dsw_u16 slice_id;  /* Message slice ID */
    dsw_u16 priority;  /* Message priority */
    dsw_u16 handle_id; /* IO trace handle ID */
    dsw_u8 seg_num;
    dsw_message_segment_desc_t seg_desc[DSW_MESSAGE_SEGMENT_DESC_NUM_MAX];
    dsw_u32 crc;    /* crc of the msg */
    dsw_u64 try_id; /* 消息发送序列号 */

    /* reserved for updating
     * 1. detect msg use 6 bytes for apm lids
     * 2. unhealthy used the first 5 bytes, and negotiation used 6th byte
    */
    message_head_reserved_t reserved_u;
    dsw_u32 head_crc; /* crc of msg head */
} dsw_message_head_t;

/*
 * Definition of message block
 *
 * A whole message block mainly cotains a message head and at most four message data. Meanwhile, the node which creates the message block
 * should record time stamp for the node (Notice: the time stamp is a 64 bits value generated by local tick generator, and is only valid locally)
 * The Time stamp will been initialized to be DSW_MESSAGE_TS_NORMAL as default. If DSW_MESSAGE_TS_DROPED, the message will been discarded directly by net module.
 */
typedef struct {
    dsw_message_head_t head;
    void *seg_buf[DSW_MESSAGE_SEGMENT_DESC_NUM_MAX];
    dsw_u64 ts; /* Time stamp */
    dsw_u32 seg_buf_crc;
    struct list_head msg_node;
    void *sgl;
    dsw_u64 time_recv_begin_ns;

    dsw_u8 conn_mid;        // 接收到消息的连接的mid
    dsw_u8 conn_net_point;  // 接收到消息的连接的net_point
    dsw_int conn_socket_fam;
    dsw_u32 conn_dst_nid;
} dsw_message_block_t;

/**
 * NOTICE:
 * Remenber modify the "DSW_USP_ACK_RESERVED_SIZE" while adding any member in
 * struct "dsw_usp_ack_t".
 */
#define DSW_USP_ACK_SIZE          (64)
#define DSW_USP_ACK_RESERVED_SIZE (DSW_USP_ACK_SIZE - sizeof(dsw_u32))

typedef struct {
    dsw_u32 req_cmd; /* Original req cmd */
    dsw_u8 reserved[DSW_USP_ACK_RESERVED_SIZE];
} dsw_usp_ack_t;

#ifdef __arm__
#pragma pack(0)
#else
#pragma pack()
#endif

typedef dsw_int (*xnet_msg_entry_t)(dsw_message_block_t *msg);

dsw_message_block_t *__dsw_message_alloc_dynamic(dsw_u8 mid, dsw_u8 lock, dsw_u16 file_id, dsw_u16 line_no);
dsw_message_block_t *__dsw_message_alloc_dynamic_func(dsw_u8 mid, dsw_u8 lock, dsw_u16 file_id,
                                                      dsw_u16 line_no, const char *func_name);
#ifndef FAULT_INJECT
#define dsw_message_alloc(mid, lock) \
    __dsw_message_alloc_dynamic_func(mid, lock, DSW_DEFALUT_FILEID, __LINE__, __func__)
#else
#define dsw_message_alloc(mid, lock) \
    (dsw_mem_debug_is_msg_allocatable(mid, __func__) ? __dsw_message_alloc_dynamic(mid, lock, DSW_DEFALUT_FILEID, __LINE__) : 0)
#endif

#define dsw_message_alloc_ex(slab_id, mid) \
    __dsw_message_alloc_dynamic_ex(slab_id, mid, __func__)

void __dsw_message_free(dsw_message_block_t *msg, dsw_u16 file_id, dsw_u16 line_no);
void __dsw_message_free_func(dsw_message_block_t *msg, dsw_u16 file_id, dsw_u16 line_no, const char *func_name);
#define dsw_message_free(msg) \
    __dsw_message_free_func(msg, DSW_DEFALUT_FILEID, __LINE__, __func__)

#define dsw_message_safe_free(unit) \
    if (NULL != (unit)) {           \
        dsw_message_free(unit);     \
        (unit) = NULL;              \
    }

dsw_int __dsw_message_inc_ref(dsw_message_block_t *msg, dsw_u16 file_id, dsw_u16 line_no);
dsw_int __dsw_message_inc_ref_func(dsw_message_block_t *msg, 
                                   dsw_u16 file_id, 
                                   dsw_u16 line_no,
                                   const char *func_name);

#define dsw_message_inc_ref(msg) \
    __dsw_message_inc_ref_func(msg, DSW_DEFALUT_FILEID, __LINE__, __func__)

dsw_int dsw_message_send(dsw_message_block_t *msg);
dsw_int dsw_message_net_send(dsw_u8 mid, dsw_message_block_t *msg);

/* vbs已经使用多线程内存接口，在这里打桩实现 */
dsw_message_block_t *__dsw_message_bs_alloc(dsw_u8 mid, dsw_u16 file_id, dsw_u16 line_no);
#define dsw_message_bs_alloc(mid) \
    __dsw_message_bs_alloc(mid, DSW_DEFALUT_FILEID, __LINE__)

extern dsw_int dsw_message_set_crc(dsw_message_block_t *msg);
extern dsw_int dsw_message_check_crc(dsw_message_block_t *msg);
extern dsw_int dsw_message_head_chk_crc(dsw_message_head_t *head);
extern dsw_int dsw_message_head_set_crc(dsw_message_head_t *head);
extern void dsw_message_head_print(const dsw_message_block_t *head);

dsw_int dsw_message_check(dsw_message_block_t *frm_msg);

/* 设置message时间戳处理阶段点，主要为req阶段和resp阶段 */
dsw_int dsw_message_set_timestamp_point(dsw_message_block_t *msg, dsw_u8 point);

/* 获取message发送时间戳 */
dsw_int dsw_message_get_sendtime(dsw_message_block_t *msg, dsw_u16 *sendtime);

/* 设置message发送时间戳 */
dsw_int dsw_message_set_sendtime(dsw_message_block_t *msg, dsw_u16 sendtime);

/* 获取memsage接收时间戳 */
dsw_int dsw_message_get_recvtime(dsw_message_block_t *msg, dsw_u16 *recvtime);

/* 设置message接收时间戳 */
dsw_int dsw_message_set_recvtime(dsw_message_block_t *msg, dsw_u16 recvtime);

/* 获取系统当前时间戳 */
extern dsw_u16 dsw_message_get_curr_timestamp(void);

/* 检查message时间戳处理阶段点 */
extern dsw_bool dsw_message_timestamp_point_check(dsw_message_block_t *msg, dsw_u16 point);

dsw_u32 dsw_get_cluster_cur_ver();
void dsw_set_cluster_cur_ver(dsw_u32 ver);

typedef enum dsw_msg_crc_check_type {
    MSG_CRC_CHECK_DEFAULT = 0, /* set&check message crc by module configure */
    MSG_CRC_CHECK_HEAD = 1,    /* set&check message crc only for head */
    MSG_CRC_CHECK_PARTIAL = 2, /* set&check message crc for head and seg_buf[0] */
    MSG_CRC_CHECK_ENTIRE = 3,  /* set&check message crc for head and all seg_bufs */
} dsw_msg_crc_check_type_e;

/*
 * command crc check config function
 */
typedef dsw_msg_crc_check_type_e (*dsw_message_get_crc_cfg_func_t)(dsw_u32 cmd);

void dsw_message_crc_cfg_func_register(dsw_message_get_crc_cfg_func_t func);

/* 解决升级过程mdc handle and hb线程时序，导致消息版本号不一致，其他模块出错 */
static inline dsw_u32 dsw_get_optimize_cluster_cur_ver(dsw_u32 msg_version)
{
    return (dsw_get_cluster_cur_ver() == DSW_NULL_DWORD) ? msg_version : dsw_get_cluster_cur_ver();
}

#ifdef __cplusplus
}
#endif  /* __cpluscplus */
#endif  // __dsw_message_pub_h__
