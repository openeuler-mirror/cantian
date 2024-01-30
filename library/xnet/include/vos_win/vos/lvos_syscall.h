#ifndef _LVOS_SYSCALL_H
#define _LVOS_SYSCALL_H

#define LVOS_SYSCALL_GROUP_CUSTOMIZE   (1)  /* 规格定义模块 */
#define LVOS_SYSCALL_GROUP_OM_DEPENDS  (2)
#define LVOS_SYSCALL_GROUP_UPGRADE     (3)
#define LVOS_SYSCALL_GROUP_AGENT       (4)  /* ISM的AGENT */
#define LVOS_SYSCALL_GROUP_AUTH        (5)  /* 用户管理模块 */

/* 该系统调用类型为直接调用，
   系统调用处理函数需要自己处理copy_from_user/copy_to_user, 
   v_pvParam直接透传给回调函数
   仅在用户态调用且调用频繁和需要拷贝的内容较多时建议使用此方式
*/
#define LVOS_SYSCALL_TYPE_DIRECT      0

/* 该系统调用类型为间接调用，
   v_pvParam为内核地址，系统调用机制处理内核到用户态的拷贝
   此方式会多一次内存拷贝, 输入/输出缓冲区有最大限制: LVOS_SYSCALL_MAX_IN_OUT_BUF_LEN
*/
#define LVOS_SYSCALL_TYPE_INDIRECT    1



#define LVOS_SYSCALL_CMD(group, id)   (((group) << 8) + (id))

#define LVOS_SYSCALL_MAX_IN_OUT_BUF_LEN   (510)
#define LVOS_MAX_GROUP_NUM                (32)

#define FILL_SYSCALL_PARAM(param, inBuf, inLen, outBuf, outLen) \
do { \
    (param).pvInBuf     = (inBuf);  \
    (param).uiInBufLen  = (inLen);  \
    (param).pvOutBuf    = (outBuf); \
    (param).uiOutBufLen = (outLen); \
    (param).uiRetBufLen = 0;        \
} while(0)

/* 调用系统调用的参数 */
typedef struct
{
    OSP_U32 uiInBufLen;   /* 传入的有效数据长度 */
    OSP_U32 uiOutBufLen;  /* 传入的OutBuf缓冲区长度 */
    OSP_U32 uiRetBufLen;  /* 返回的OutBuf实际内容长度 */
    void *pvInBuf;        /* 该系统调用的输入缓冲区指针 */
    void *pvOutBuf;       /* 该系统调用的输出缓冲区指针 */
} LVOS_SYSCALL_PARAM_S;

/* 注册系统调用的参数 */
typedef struct
{
    OSP_U32 uiCmd;
    OSP_U32 uiType;   /* LVOS_SYSCALL_TYPE_DIRECT or LVOS_SYSCALL_TYPE_INDIRECT */
    OSP_S32 (*pfnSysCall)(OSP_U32 uiCmd, LVOS_SYSCALL_PARAM_S *);
} LVOS_GROUP_SYSCALL_S;

/**
    \brief 调用注册的系统调用的接口
    \param[in] v_uiCmd  私有系统调用的命令字
    \param[inout] v_pvParam 系统调用的参数，允许为NULL，为NULL时下面自己处理
*/
OSP_S32 LVOS_SysCall(OSP_U32 v_uiCmd, LVOS_SYSCALL_PARAM_S *v_pvParam);

/** \brief 向VOS注册系统调用处理函数
*/
OSP_S32 LVOS_RegSysCall(OSP_U32 v_uiGroupId, LVOS_GROUP_SYSCALL_S *v_pstSysCalls, OSP_U32 v_uiCount);

/** \brief 反注册系统调用处理函数
*/
void LVOS_UnRegSysCall(OSP_U32 v_uiGroupId);

#endif

