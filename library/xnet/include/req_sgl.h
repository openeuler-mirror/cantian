/******************************************************************************
     版权所有 (C) 2010 - 2010  华为赛门铁克科技有限公司
*******************************************************************************
* 版 本 号: 初稿
* 生成日期: 2011年7月28日
* 功能描述: 系统全局REQ/SGL结构定义
* 备    注:
* 修改记录:
*         1)时间    :
*          修改人  :
*          修改内容:
******************************************************************************/
#ifndef _REQ_SGL_H
#define _REQ_SGL_H

#ifdef __cplusplus
extern "C" {
#endif


#include "lvos.h"
#define INVALID_VOLUME_ID 0xffffffffffffffff
#define INVALID_CKG_ID 0xffffffff
typedef uint64_t volumeid_t;

/** \addtogroup objpub  业务对象公共定义
    \section intro_sec 说明
    @{
*/

/** \brief 定义REQ操作码 */
typedef enum
{
    OP_NOP          = 0,              /* do nothing */
    OP_WRITE        = 0x13218000,
    OP_READ         = 0x00128001,
    OP_WRITE_ALLOC  = 4,              /* 目标器申请空间来存放写数据 */

    OP_FORMAT       = 6,              /* 格式化，清零 */
    OP_VERIFY       = 7,              /* 校验 */
    OP_RECONSTRUCT  = 8,              /* 重构 */
    OP_RECOVER      = 9,              /* 恢复重构 */
    OP_RESTORE      = 10,             /* 坏道修复 */
    OP_WRITEHOLE    = 11,             /* writehole恢复写，带脏校验数据 */
    OP_PRECOPY      = 12,             /* 预拷贝 */

    OP_READ_THROUGH = 13,             /* 透读，即释放掉CACHE中的干净数据后，直接读盘 */
    OP_EBC_MSG      = 14,             /* 发送EBC消息 */

    OP_LEVELING     = 15,             /* 均衡 */
    /* 问题单号:P12N-3240, 元数据透读和写修复实现, c90005714, 2012/09/22,begin*/
    OP_REPAIR_WRITE = 16,             /* 元数据透读成功后修复写 */
    OP_STRIPE_REPAIR = 17,             /* 分条修复 */
    /* 问题单号:P12N-3240, 元数据透读和写修复实现, c90005714, 2012/09/22,end*/

    OP_RSS_REPAIR_WRITE = 18,           /* 增值特性修复写 */
    OP_RSS_REPAIR_READ = 19,            /* 增值特性修复读 */

    /*SCSI下发的私有请求 begin*/
    OP_SCSI_PRIVATE_WRITE_ALLOC = 20,
    OP_SCSI_PRIVATE_WRITE = 21,
    OP_SCSI_PRIVATE_READ = 22,
    /*SCSI下发的私有请求 end*/

    OP_READ_THROUGH_FOR_RETRY = 23,    /* 透读重试请求*/
                                       /*前端在读 IO 发生DIF校验错误时下发，在cache
                                         中命中的脏数据返回，非脏数据下盘读取。
                                         对读盘数据先校验分条一致性，若一致则成功返回；
                                         否则说明盘上数据不可靠，返回失败*/
    OP_STRIPE_INCON_RESTORE = 24,
    /*BEGIN,V3R3 版本中修改，以下四个枚举，盘古支持V3之前的老硬件需要*/
    OP_SNAP_READ  =  (OP_READ  | 0x00000040),  /* 虚拟快照读 OP_READ  | 100,0000b(0x40) */
    OP_SNAP_WRITE =  (OP_WRITE | 0x20000040),  /* 虚拟快照写 OP_WRITE | 100,0000b(0x40) */

    OP_CLN_READ   =  (OP_READ  | 0x00000080),  /* 分裂镜像读OP_READ  | 1000,0000b(0x80) */
    OP_CLN_WRITE  =  (OP_WRITE | 0x20000080),  /* 分裂镜像写OP_WRITE | 1000,0000b(0x80) */
    /*END*/

    OP_CPY_READ   =  (OP_READ  | 0x000000c0),  /* LUN拷贝读OP_READ  | 1100,0000b(0xc0) */
    OP_CPY_WRITE  =  (OP_WRITE | 0x200000c0),  /* LUN拷贝写OP_WRITE | 1100,0000b(0xc0) */

    /*BEGIN,V3R3 版本中修改，以下八个枚举，盘古支持V3之前的老硬件需要*/
    OP_LM_READ    =  (OP_READ  | 0x00000100),  /* lun迁移读OP_READ  | 1,0000,0000b(0x100) */
    OP_LM_WRITE   =  (OP_WRITE | 0x20000100),  /* lun迁移写OP_WRITE | 1,0000,0000b(0x100) */

    OP_RM_READ    =  (OP_READ  | 0x00000140),  /* 远程镜像读OP_READ  | 1,0100,0000b(0x140) */
    OP_RM_WRITE   =  (OP_WRITE | 0x20000140),  /* 远程镜像写OP_WRITE | 1,0100,0000b(0x140) */

    OP_ECP_READ   =  (OP_READ  | 0x00000180),  /* FULLCOPY读OP_READ  | 1,1000,0000b(0x180) */
    OP_ECP_WRITE  =  (OP_WRITE | 0x20000180),  /* FULLCOPY写OP_WRITE | 1,1000,0000b(0x180) */

    OP_LMR_READ   =  (OP_READ  | 0x00000280),  /* 卷镜像读OP_READ  | 10,1000,0000b(0x280) */
    OP_LMR_WRITE  =  (OP_WRITE | 0x20000280),  /* 卷镜像写OP_WRITE | 10,1000,0000b(0x280) */
    /*END*/

    /*BEGIN, Dorado V3版本新增，Pool用该命令释放SSD空间，BDM需处理该命令 */
    OP_TRIM       = 25,              /* 释放SSD空间 */
    /*END*/

    /*远程复制，双活使用*/
    OP_REMOTE_READ    =  (OP_READ  | 0x00000140),  /* 远程镜像读OP_READ  | 1,0100,0000b(0x140) */
    OP_REMOTE_WRITE   =  (OP_WRITE | 0x20000140),  /* 远程镜像写OP_WRITE | 1,0100,0000b(0x140) */

    /* 兼容老阵列需要用到 */
    OP_PRIVATE_WRITE = 53,
    OP_PRIVATE_MIRROR_WRITE = 54,
    OP_PRIVATE_DIRECT_WRITE = 55,
    OP_DELETE_CACHE = 56,         /* 删除CACHE数据 */

    /* 对象(文件)复制使用 */
    OP_OBJSET_REP_ALLOC = 70, /* 对象复制写分配 */
    OP_OBJSET_REP_WRITE = 71, /* 对象复制写执行 */

    /*增值读写使用统一的操作码（快照、克隆、lm、lmr等）*/
	OP_REP_READ  = 72,
	OP_REP_WRITE = 73,

    /*阵列间SCSI元数据写*/
	OP_REP_SCSI_WRITE  = 74,

    /*双活转发双写*/
    OP_REP_TRANS_WRITE = 75,

    OP_REP_SCSI_READ  = 76,
#ifdef DECLARE_FOR_DRV_COMPAT
    /* only used by DMP */
    OP_DMP_WRITE       =  0x1c018020,
    OP_DMP_READ         =  0x0c028021,
    /* modify end by lixuhui(65736), for DE4 IBS, 20070706 */
    OP_MIRROR_READ = 11,
    OP_MIRROR_WRITE  =  0x12018010,

    OP_MIRROR_MSG      =  0x11018011,

    OP_PRIVATE_READ = 50,
    OP_PRIVATE_WRITE_PARSE = 51,
    OP_PRIVATE_WRITE_ALLOC = 52,
#endif

    OP_PVT_MSG = 0x3c018000,         /* 发送私有消息 */
    OP_INFO_READ = 0x3c028000,       /* 查询快照差异位图 */
    /*新特性合入: windows2012认证新增代码,SR-0000341803，20140118，start*/
    OP_QUERY = 0X4c0a8000,  /*查询类命令*/
    /*新特性合入: windows2012认证新增代码,SR-0000341803，20140118，end*/


    OP_HOST_WRITE_REQ_NEED_ABORT = 0x5c0a8000,
    OP_HOST_WRITE_REQ_FINISH_ABORT = 0x5c0b8000,


    OP_BUTT
} REQ_OP_E;

typedef struct tagIOD_S
{
    struct list_head iodQueueNode;   /*用于将REQ挂入调度队列链表节点 */
    int64_t  delayTime;              /*超时时间,用于延迟执行*/
    uint16_t pid;                     /*模块pid*/
    uint16_t validFlag;              /* 合法性校验标记 */
    uint8_t ioThreadid;             /*线程ID，第一次调度的IOD线程ID*/
    uint8_t  isInQueue;              /*是否挂入IOD队列，防止重复挂入*/
    uint8_t  type;                    /* 类型REQ/CMD */
    uint8_t  pri;                     /* 优先级 */
} IOD_S;

typedef struct
{
    char     *buf;         /* 页面数据起始地址 */
    void     *pageCtrl;    /* 页面控制头地址 */
    uint32_t len;          /* 有效数据长度，单位为byte */
    uint32_t pad;
} SGL_ENTRY_S;

#define ENTRY_PER_SGL 64
typedef struct tagSGL_S
{
    struct tagSGL_S *nextSgl;           /* 下一个sgl指针，用于组成sgl链 */
    uint16_t     entrySumInChain;       /* sgl链中sgl_entry总数，该字段自在sgl链第一个sgl中有效 */
    uint16_t     entrySumInSgl;         /* 本sgl中sgl_entry数据 */
    uint32_t     flag;                  /* 数据标记，用于标识该sgl中是否包含零页面、bst页面等 */
    uint64_t     serialNum;             /* sgl序列号*/
    SGL_ENTRY_S  entrys[ENTRY_PER_SGL]; /* sgl_entry数组*/
    struct list_head stSglNode;
    uint32_t     cpuid ;                /* 保存申请该结构体时的cpu */
} SGL_S;

typedef struct tagREQ_S  REQ_S;
#define MAX_REQ_OPS_NAME_LEN 40
typedef struct tagREQ_OPS_S
{
    char name[MAX_REQ_OPS_NAME_LEN];   /**< 本REQ操作名称 */
    int32_t  (*start)(REQ_S *req);         /**< 本REQ执行函数 */
    int32_t  (*done)(REQ_S *req);          /**< 本REQ处理完成回调处理函数 */
    void (*childDone)(REQ_S *selfReq, REQ_S *childReq);   /**< 子REQ处理完成回调函数，父REQ提供，子REQ调用 */
    void (*del)(REQ_S *req);        /**< 本REQ资源释放操作函数，一般由父REQ调用 */
} REQ_OPS_S;

#define MAX_REQ_PRIVATE 32
/** \brief REQ结构 */
struct tagREQ_S
{
    IOD_S iodPrivate;              /**< IOD使用的私有信息 */

    uint32_t opCode;             /**< IO操作码，参考enum ReqOpCode_e定义的枚举值 */
    volumeid_t volumeId;           /**< Volume id，不使用时填全F */
    uint64_t objectId;           /**< 访问对象id，根据访问对象不同可以填extent id、ckg id、disk id等 */
    uint64_t objectLba;          /**< 访问的起始扇区 */
    uint32_t length;             /**< 访问的扇区数量 */

    int32_t  result;             /**< REQ执行结果 */

    uint64_t ctrlFlag;           /**< 控制标记(REQ_CTRL_FLAG_XXX)*/

    SGL_S    *sgl;               /**< REQ关联的所有本地页面 */
    SGL_S    *remoteSgl;         /**< REQ关联的所有镜像页面 */
    uint32_t bufOffsetNByte;  /**< 本REQ能够使用的sgl内偏移地址(字节数) */

    uint16_t priority;           /**< IO优先级*/
    uint16_t objectType;               /**< 对齐填充*/

    REQ_OPS_S   *ops;         /**< 该REQ的所有操作方法 */

    REQ_S           *parent;     /**< 本REQ的父REQ */
    struct list_head childList;  /**< 子节点链表头，本REQ为父节点时使用 */
    struct list_head childNode;  /**< 子节点链表节点，用于加入父节点的子节点链表 */
    atomic_t         notBackNum; /**< 未返回的子REQ数量 */
    uint32_t         childSum;   /**< 子REQ总数 */

    uint64_t producerPrivate[MAX_REQ_PRIVATE]; /* 用于私有用途 ，生成该REQ的模块使用*/
    uint64_t consumerPrivate[MAX_REQ_PRIVATE]; /* 用于私有用途 ，接收该REQ的模块使用*/
    void     *parentSaveInfo;                  /**< 父REQ保存在子REQ中的私有信息, 父REQ使用 */

    uint64_t onFlyProcess;       /**< REQ处理状态标记*/

    uint64_t ioSeiralNumber;     /**< REQ IO序列号，生成REQ时填写，用于IO时延统计*/
    uint64_t ioStartTime;        /**< REQ开始执行的时间*/

    int32_t  stat;               /**< 主要用于与驱动之间传递信息*/
    uint32_t pad2;               /**< 对齐填充*/

    int8_t   readHit;            /**< 是否命中标志*/
    uint8_t  pad3;               /**< 对齐填充*/
    uint8_t  readThroughTimes;   /**< 用于透读时传递重试次数*/
    uint8_t pad4;                /**< 对齐填充*/
    uint32_t pad5;               /**< 对齐填充*/
    //TRACEINFO_S traceInfo;  /**< FTDS跟踪透传信息，FTDS专用*/
    REQ_S   *nextReq;              /**< 指向下一个REQ，用于组织REQ链*/
};

/* REQ相关的操作宏定义 */
#define REQ_CHILDDONE(req, childReq)  \
    ((req)->ops->childDone((req), (childReq)))
#define REQ_DELETE(req)               ((req)->ops->del((req)))
#define REQ_START(req)                ((req)->ops->start((req)))
#define REQ_DONE(req)                 ((req)->ops->done((req)))

/* 设置和获取req的读命中标志 */
#define SET_REQ_READ_HIT(req) ((req)->readHit = TRUE)
#define SET_REQ_NOT_READ_HIT(req) ((req)->readHit = FALSE)
#define REQ_IS_READ_HIT(req)  (TRUE == (req)->readHit)

/**
\brief REQ ctrl flag定义
*/
    /* 大数据块，4096+64格式。不置该位则为512+8格式*/
#define REQ_CTRL_FLAG_LONG_BLOCK    (1<<0)
    /* 该请求无DIF保护。该请求不插入DIF */
#define REQ_CTRL_FLAG_NO_DIF_PROTECT    (1<<1)
    /* 该请求不做DIF校验。该请求不做DIF校验*/
#define REQ_CTRL_FLAG_NO_DIF_VERIFY    (1<<2)
    /* 该请求不做DIF校验。该请求不做DIF校验*/
#define REQ_CTRL_FLAG_WRITE_THROUGH    (1ULL<<63)

/**
\brief REQ ctrl flag操作宏定义
*/
/* 置ctrl Flag位, 同时置多个位可用或运算符连接flag */
#define SET_REQ_CTRL_FLAG(req, flag)    ((req->ctrlFlag) |= (flag))
/* 清除ctrl Flag位, 同时清除多个位可用或运算符连接flag */
#define CLEAR_REQ_CTRL_FLAG(req, flag)    ((req->ctrlFlag) &= ~(flag))
/* 判断某ctrl Flag位是否置1 */
#define TEST_REQ_CTRL_FLAG(req, flag)    ((req->ctrlFlag) & (flag))

/** \brief GENIO_S结构，用于生成IO时将父REQ信息传递给子REQ，相关字段含义与REQ对应字段相同 */
//更换GENIO_S结构体的顺序和REQ_S对应，减小cachemiss
typedef struct
{
    uint32_t opCode;             /**< IO操作码，参考enum ReqOpCode_e定义的枚举值 */
    volumeid_t volumeId;           /**< Volume id，不使用时填全F */
    uint64_t objectId;           /**< 访问对象id，根据访问对象不同可以填extent id、ckg id、disk id等 */
    uint64_t objectLba;          /**< 访问的起始扇区 */
    uint32_t length;             /**< 访问的扇区数量 */
    uint16_t objectType;
    uint16_t pad2;               /**< 对齐填充*/
    uint64_t ctrlFlag;           /**< 控制标记，标记回透写、是否镜像等*/

    SGL_S    *sgl;               /**< REQ关联的所有本地页面 */
    SGL_S    *remoteSgl;         /**< REQ关联的所有镜像页面 */

    uint32_t bufOffsetNByte;     /**< 本REQ能够使用的sgl内偏移地址(字节数) */
    uint16_t priority;           /**< 优先级 */
    uint8_t  readThroughTimes;   /**< 用于透读时传递重试次数*/
    uint8_t  notNeedDIF;         /**< IO是否不需要作DIF校验, TRUE:不需要作校验, FALSE:需要做校验*/
    REQ_S    *parent;            /**< 本REQ的父REQ */

    void     *parentSaveInfo;   /**< 父REQ保存在子REQ中的私有信息, 父REQ使用 */
    /* toChildInfo不要了，各模块提供iogen的时候可以有自定义参数，在iogen函数中拷贝自定义参数的内容到私有数据中即可 */

    uint64_t ioSeiralNumber;     /**< REQ IO序列号，生成REQ时填写，用于IO时延统计*/
    uint64_t volumeLba;
    //TRACEINFO_S traceInfo;  /**< FTDS跟踪透传信息，FTDS专用*/
} GENIO_S;

/** \brief      用来遍历一个有数据的SGL chain
 \param[in,out]  sglPtr 错误时输出NULL
 \param[in,out]  entryIndex 输出下一个Entry在SGL中的数组下标，错误时输出0
 \retval     无
*/
void move2NextEntryAndModifyPSgl(SGL_S** sglPtr, uint32_t* entryIndex);
/** \brief      向sgl添加页面后，向后移动当前entry位置和sgl指针，并更新sgl页面计数
 \param[in,out] sglPtr      输出sgl，错误时输出NULL
 \param[in,out] entryIndex  移动后的entry在SGL中的数组下标，错误时输出0
 \param[in]     sglHead     sgl链表头
 \retval     无
 */
void move2NextEntryAndIncEntrySum(SGL_S** sglPtr, uint32_t* entryIndex, SGL_S* sglHead);
/** \brief      sgl偏移多个页面
 \param[in,out]  sglPtr      sgl指针地址
 \param[out]     entryIndex  Entry在SGL内的数组下标
 \param[in]      offset      偏移页面数量
 \retval     无
*/
void sglAndEntryOffsetPages(SGL_S **sglPtr, uint32_t *entryIndex, uint32_t offset);
/** \brief      查找SGL链最后的SGL和entry
 \param[in]   inSgl    输入SGL -- SGL链的头
 \param[out]  outSgl  输出SGL
 \param[out]  singleEntry   输出Entry -- Entry位置(从1开始计数)
 \retval     无
 \see
 \note
 */
void getLastSgl(SGL_S *inSgl, SGL_S **outSgl, uint32_t *singleEntry);
/** \brief      获取sgl 中有效的页面数
    \param[in]  sglPtr        SGL
    \param[in]  sglOffsetByte 偏移字节数
    \param[in]  lengthByte    长度
    \retval     sgl中有效页面数
*/
uint32_t getValidSglPageNum(SGL_S * sglPtr, uint32_t sglOffsetByte, uint32_t lengthByte);

/** \brief      将一个sgl中指定entry的页面替换成零页面, 同时释放原页面
    \param[in]  SGL_S *  sglPtr sgl地址
    \param[in]  uint8_t entryArray[] 存放entry的索引号
    \param[in]  uint8_t entryNum     需要替换的entry的总数，即数组元素个数
    \retval     无
*/
void exchangeZeroPageBySglEntryIdx(SGL_S* sglPtr, uint8_t entryArray[], uint8_t entryNum);

/** \brief      复制一个SGL中的全部页面到新的写页面中
    \param[in]   srcSgl         拷贝的源SGL
    \param[in]   volumeId       目标SGL要写入的volume
    \param[in]   tierType       目标SGL要写入的tier类型
    \param[in]   pageType       目标SGL页面用途
    \param[in]   inputReqCtrlFlag   输入的REQ回透写标志
    \param[in]   callbackFunc   回调函数
    \param[in]   callBackArg    回调参数
    \retval     函数执行的结果
*/
int32_t copySglForWrite(SGL_S* srcSgl,
                        volumeid_t volumeId,
                        uint32_t tierType,
                        uint32_t pageType,
                        uint64_t inputReqCtrlFlag,
                        void (*callbackFunc)(SGL_S* targetSgl, void* callbackArg),
                        void* callBackArg);
/** \brief      复制一个SGL中的某些页面到新的写页面中
    \param[in]  srcSgl      拷贝的源SGL
    \param[in]  offsetByte  源SGL的OFFSET
    \param[in]  length      源数据页面的的LENGTH
    \param[in]  reqLba      源数据页面的LBA
    \param[in]  volumeId    目标SGL要写入的volume
    \param[in]  tierType    目标SGL要写入的tier类型
    \param[in]  pageType    目标SGL页面用途
    \param[in]  inputReqCtrlFlag   输入的REQ回透写标志
    \param[in]  callbackFunc  回调函数
    \param[in]  callBackArg   回调参数
    \retval     函数执行的结果
    \note       新生成的sgl的offsetByte是0，外面req要重新赋值为0
*/
int32_t copySglForWriteByOffset(SGL_S *srcSgl,
                                uint32_t offsetByte,
                                uint32_t length,
                                uint64_t reqLba,
                                volumeid_t volumeId,
                                uint32_t tierType,
                                uint32_t pageType,
                                uint64_t inputReqCtrlFlag,
                                void (*callbackFunc)(SGL_S *targetSgl, void *callbackArg),
                                void *callBackArg);

/** \brief      通过offset获取其对应的sgl和entry
    \param[in]  sglPtr            sgl链的链头地址
    \param[in]  offseByte       有效数据的偏移量
    \param[out] outSgl        偏移地址处的sgl
    \param[out] singleEntry    偏移地址处的entry 下标号
    \param[out] bufOffset      在entry中的偏移
    \retval     函数执行的结果
*/
int32_t  getCurrentSglByOffset(SGL_S *      sglPtr,
                               uint32_t     offseByte,
                               SGL_S **     outSgl,
                               uint32_t*    singleEntry,
                               uint32_t*    bufOffset);

/** \brief      显示sgl信息
    \param[in]  sglPtr 要显示的sgl
    \retval     无
*/
void showSglShell(SGL_S* sglPtr);

/** \brief 显示sgl的数据
 \param[in] sglPtr 预显示的sgl指针
 \retval     无
*/
void showSglData(SGL_S* sglPtr);

/** \brief 将req的信息拷贝到genio
    \param[in]     req     复制的源req
    \param[in,out] genio   目标genio
    \retval     无
    \see  copyGenio2Req
    \note (一般在调用genio函数之前调用)
*/
void copyReq2Genio(GENIO_S *genio, REQ_S *req);

/** \brief        将genio的信息拷贝到req
    \param[in]     genio 拷贝的源genio
    \param[in,out] req   复制的目标req
    \retval       无
    \see  copyReq2Genio
    \note (一般在genio函数中调用)
*/
void copyGenio2Req(REQ_S *req, GENIO_S *genio);

/** \brief        转换内存空间到sgl
    \param[in]    buf      内存空间地址
    \param[in]    length   内存长度(字节数)
    \retval       sgl链
*/
SGL_S *fillBufToSgl(char *buf, uint32_t length);

/** \brief        计算sgl中的页面的产生校验码
    \param[in]    srcSgl     带页面的sgl
    \param[in]    offsetByte 有效数据的偏移量
    \param[in]    length   数据长度(字节数)
    \param[out]   crc     出处CRC检验值
    \retval       执行结果
*/
int32_t createSglCrc32c(SGL_S *srcSgl, uint32_t offsetByte,
                        uint32_t length, uint32_t *crc);
/** \brief      对一个sgl中的数据做CRC校验,sgl中的页面大小为4160，针对于前4K为数据后64字
                节为dif数据的页面，此函数不计算每个页面的后64字节数据，仅计算前4K空间内的有效数据。
  \param[in]    SGL_S *srcSgl     带页面的sgl
  \param[in]    uint32_t offsetByte 有效数据的偏移量(不包含DIF数据)
  \param[in]    uint32_t length   数据长度(字节数)
  \param[in]    uint32_t *crc     出处CRC检验值
  \retval       执行结果
  \see
 \note          (HVSC99 DIF，元数据校验使用)
*/
int32_t createSglCrc32IgnoreDif(SGL_S *srcSgl, uint32_t offsetByte,
                                uint32_t length, uint32_t *crc);

/** \brief      从一块连续内存拷贝数据到sgl
 \param[in]     dstSgl          目标sgl链头指针
 \param[in]     dstOffsetInByte 目标sgl拷贝的起始偏移(字节)
 \param[in]     buffer          拷贝的源数据地址
 \param[in]     dataLength      拷贝的数据长度(字节)
 \retval        RETURN_OK     拷贝成功
 \retval        RETURN_ERROR  拷贝失败

 */
int32_t copyDataFromBufferToSgl(SGL_S *dstSgl, uint32_t dstOffsetInByte,
                                char *buffer, uint32_t dataLength);

/** \brief      从sgl拷贝数据到一块连续内存
 \param[in]     srcSgl          源sgl链头指针
 \param[in]     srcOffsetInByte 源sgl拷贝的起始偏移(字节)
 \param[in]     buffer          拷贝的目标数据地址
 \param[in]     dataLength      拷贝的数据长度(字节)
 \retval        RETURN_OK     拷贝成功
 \retval        RETURN_ERROR  拷贝失败

 */
int32_t copyDataFromSglToBuffer(SGL_S *srcSgl, uint32_t srcOffsetInByte,
                                char *buffer, uint32_t dataLength);



/** \brief      通过offset获取其对应的sgl和entry(忽略64B的DIF数据)
    \param[in]  SGL_S *  v_pstSgl sgl链的链头地址
    \param[in]  OSP_U32  v_uiOffseByte有效数据的偏移量(不包含DIF数据)
    \param[out] SGL_S ** v_ppstOutSgl偏移地址处的sgl
    \param[out] OSP_U32 *v_puiSingleEntry 偏移地址处的entry 下标号
    \param[out] OSP_U32 *v_puiBufOffset  在entry中的偏移
    \retval     函数执行的结果
    \see
    \note      (HVSC99 DIF，适用4K + 64页面类型)
*/
int32_t  getCurrentSglByOffsetIgnoreDif(SGL_S *      sglPtr,
                                        uint32_t     offseByteNoDif,
                                        SGL_S **     outSgl,
                                        uint32_t*    singleEntry,
                                        uint32_t*    bufOffset);


/** \brief    从一块连续内存拷贝数据到sgl，每个entry只填充4KB 的数据,忽略DIF数据
 \param[in]   dstSgl          : 目标sgl链头指针
 \param[in]   offseByteNoDif  : 目标sgl拷贝的起始偏移(字节，不包含DIF数据)
 \param[in]   buffer          : 拷贝的源数据地址
 \param[in]   dataLength      : 拷贝的数据长度(字节)
 \retval      int32_t         : OK 拷贝成功，ERROR 拷贝失败
 \see
 \note        (HVSC99 DIF，适用4K + 64页面类型)
 */
int32_t copyDataFromBufferToSglIgnoreDif(SGL_S *dstSgl, uint32_t offseByteNoDif,
                                         char *buffer, uint32_t dataLength);

/** \brief    从sgl拷贝数据到一块连续内存，仅拷贝有效数据，不拷贝DIF数据
              参数dstOffsetInByte是有效数据的偏移，不包含DIF数据
 \param[in]   srcSgl          : 源sgl链头指针
 \param[in]   offseByteNoDif  : 源sgl拷贝的起始偏移(字节，不包含DIF数据)
 \param[in]   buffer          : 拷贝的目标数据地址
 \param[in]   dataLength      : 拷贝的数据长度(字节，有效数据长度，不包含DIF数据)
 \retval      int32_t         : OK 拷贝成功，ERROR 拷贝失败
 \see
 \note        (HVSC99 DIF，适用4K + 64页面类型)
 */
int32_t copyDataFromSglToBufferIgnoreDif(SGL_S *srcSgl, uint32_t offseByteNoDif,
                                         char *buffer, uint32_t dataLength);

/** \brief      设置sgl壳中页面的属性为只读
 \param[in]     sgl           sgl链头指针
 \retval        无
 \note          此函数不能在锁保护的临界区中使用，只能将sgl中的满页面设置为只读
*/
void setSglPageRO(SGL_S *sgl);

/** \brief      设置sgl壳中页面的属性为可读写
 \param[in]     sgl           sgl链头指针
 \retval        无
 \see
 \note          此函数不能在锁保护的临界区中使用
*/
void setSglPageRW(SGL_S *sgl);

#ifdef _DEBUG
#define SET_SGLPAGE_RO(sgl) setSglPageRO((sgl))
#define SET_SGLPAGE_RW(sgl) setSglPageRW((sgl))
#else
#define SET_SGLPAGE_RO(sgl)
#define SET_SGLPAGE_RW(sgl)
#endif /* _DEBUG */

/** @} */

#ifdef __cplusplus
}
#endif


#endif

