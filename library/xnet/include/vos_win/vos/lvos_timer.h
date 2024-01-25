/******************************************************************************

                  版权所有 (C), 2008-2008, 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : lvos_timer.h
  版 本 号   : 初稿

  生成日期   : 2009年5月24日
  最近修改   :
  功能描述   : 定时器处理函数头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2009年5月24日

    修改内容   : 创建文件

******************************************************************************/
/** \addtogroup LIB    Hima公共库
    @{ 
*/
/**
    \file  lvos_timer.h
    \brief 系统定时器功能，仿照linux内核态下的定时器接口
    \note  支持windows/linux_kernel
    \date 2009年5月24日
*/

#ifndef __LVOS_TIMER_H__
#define __LVOS_TIMER_H__

#define LVOS_MAX_TIMER_TIMEOUT  ((long)(~0UL>>1))

#if defined WIN32 || defined __KERNEL__
/********************** 定义windows平台下使用的数据结构 及函数声明begin ************************/
#ifdef WIN32
/** \brief 获取系统启动后经历的32位节拍数，只存在于windows和linux内核态下 */
#define jiffies GetTickCount()
#define HZ 1000     /**< windows下定义HZ为1000，因为GetTickCount()返回毫秒计的开机时间 */
#define LVOS_TIMER_STATUS_EMPTY 1      /* 定义Win32下定时器状态 */
#define LVOS_TIMER_STATUS_WAITING 2    /* 定义Win32下定时器状态 */
#define LVOS_TIMER_THREAD_STATUS_RUNNING 1 /* 线程标志位:1-运行,其它-退出 */

static inline OSP_S32 time_after(OSP_ULONG v_ulA,OSP_ULONG v_ulB)
{
    OSP_LONG vlTemp = (OSP_LONG)(v_ulB - v_ulA);
    return (vlTemp < 0);
}

static inline OSP_S32 time_after_eq(OSP_ULONG v_ulA,OSP_ULONG v_ulB)
{
    OSP_LONG vlTemp = (OSP_LONG)(v_ulB - v_ulA);
    return (vlTemp <= 0);
}
#define LVOS_TIME_AFTER(a,b) time_after(a,b)
#define LVOS_TIME_AFTER_EQ(a,b) time_after_eq(a,b)
#define LVOS_TIME_BEFORE(a,b) time_after(b,a)

#ifdef ESTOR_X64
typedef OSP_VOID (*LVOS_TIMER_FUNC_PFN)(OSP_U64 v_ulData);    /**切64位传入参数为8字节指针，因此修改参数类型 */
#else
typedef OSP_VOID (*LVOS_TIMER_FUNC_PFN)(OSP_ULONG v_ulData);    /**< 定时器处理函数类型 */
#endif
#define TIMER_NAME_LEN (50)

typedef struct tagLVOS_TIMER_LIST_S
{
    int expires;
    struct list_head stTimerList;
#ifdef ESTOR_X64
	unsigned long long data;	/*切64位传入参数为8字节指针，因此修改参数类型*/
#else
    unsigned long data;
#endif
    int iTimeMicroSec;
    char szName[TIMER_NAME_LEN];
#ifdef ESTOR_X64
	void  (*function)(unsigned long long);	/*切64位传入参数为8字节指针，因此修改参数类型*/
#else
    void  (*function)(unsigned long);
#endif
} LVOS_TIMER_LIST_S;

int TIMER_InitTimer(LVOS_TIMER_LIST_S *my_timer);
int TIMER_AddTimer(LVOS_TIMER_LIST_S *v_pstTimer);
int TIMER_ModTimer(LVOS_TIMER_LIST_S *my_timer,unsigned long new_delay);
int TIMER_DelTimer(LVOS_TIMER_LIST_S *my_timer);
int TIMER_Pending(LVOS_TIMER_LIST_S *my_timer);

#ifdef ESTOR_X64
/*切64位传入参数v_ulData为8字节指针，因此修改参数类型*/
OSP_S32 TIMER_NEX_InitTimer(LVOS_TIMER_LIST_S *v_pstTimer, OSP_ULONG v_ulExpires, 
                           OSP_U64 v_ulData, 
                           LVOS_TIMER_FUNC_PFN v_pfnTimerHandler);
#else
OSP_S32 TIMER_NEX_InitTimer(LVOS_TIMER_LIST_S *v_pstTimer, OSP_ULONG v_ulExpires, 
                           OSP_ULONG v_ulData, 
                           LVOS_TIMER_FUNC_PFN v_pfnTimerHandler);
#endif

/* VOS提供的对外公共接口begin */
#define LVOS_InitTimer                      TIMER_NEX_InitTimer
#define LVOS_AddTimer(v_timer)              TIMER_AddTimer(v_timer)
#define LVOS_ModTimer(v_timer, v_delay)     TIMER_ModTimer(v_timer, v_delay)
#define LVOS_DelTimer(v_timer)              TIMER_DelTimer(v_timer)
#define LVOS_DelTimerSync(v_timer)          TIMER_DelTimer(v_timer)
#define LVOS_IsTimerActivated(v_timer)		TIMER_Pending(v_timer)
/* VOS提供的对外公共接口end */

/* 为兼容ISCSI模块定义的仿真接口，这些接口只在仿真平台上使用begin */
#define LVOS_mod_timer(v_timer, v_delay)    TIMER_ModTimer(v_timer, v_delay)
#define LVOS_del_timer_sync(v_timer)        TIMER_DelTimer(v_timer)
#define LVOS_timer_pending(v_timer)         TIMER_Pending(v_timer)

#define init_timer      TIMER_InitTimer
#define add_timer       ISCSI_AddTimer
#define mod_timer       LVOS_mod_timer
#define del_timer       LVOS_DelTimer
#define del_timer_sync  LVOS_del_timer_sync
#define timer_pending   LVOS_timer_pending
/* 为兼容ISCSI模块定义的仿真接口，这些接口只在仿真平台上使用end */
/********************** 定义windows平台下使用的数据结构 及函数声明end ************************/

/********************** 定义linux平台下内核态使用的数据结构 及函数声明begin ************************/
#else
#include <linux/timer.h>

typedef OSP_VOID (*LVOS_TIMER_FUNC_PFN)(OSP_ULONG v_ulData);
typedef struct tagLVOS_TIMER_LIST_S
{
    struct timer_list stTimer;
    OSP_ULONG ulExpireTime;
    OSP_CHAR * pFunc;
    OSP_ULONG uiLine;
}LVOS_TIMER_LIST_S;

/********************** 定义linux平台下内核态使用的数据结构 end ************************/
/********************** 定义linux平台下内核态使用的宏begin ************************/
#define LVOS_TIME_AFTER(a,b) time_after(a,b)
#define LVOS_TIME_AFTER_EQ(a,b) time_after_eq(a,b)
#define LVOS_TIME_BEFORE(a,b) time_before(a,b)

/********************** 定义linux平台下内核态使用的宏end ************************/

/*****************************************************************************
 函 数 名  : LVOS_InitTimer
 功能描述  : 初始化定时器
 输入参数  : LVOS_TIMER_LIST_S *v_pstTimer
             OSP_U64 v_ullExpires
             OSP_ULONG v_ulData
             LVOS_TIMER_FUNC_PFN
 输出参数  : 无
 返 回 值  : OSP_S32
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2009年5月25日

    修改内容   : 新生成函数

*****************************************************************************/
/**
    \brief 初始化定时器
    \note 支持windows/linux_kernel    
    \note 后续激活/修改/删除定时器时，均需要使用此定时器结构体，因此最好不要使用局部变量，使用者需要保证这一点
    \note 不同于linux_kernel下的超时时间为绝对时间，这里的超时时间为相对时间，即从定时器激活经历v_uiExpires毫秒后，定时器处理函数被调用
    \param[in] v_pstTimer           定时器结构体
    \param[in] v_ulExpires          以毫秒计的超时时间
    \param[in] v_ulData             定时器处理函数的输入参数
    \param[in] v_pfnTimerHandler    定时器处理函数
    \retval RETURN_OK               初始化定时器成功
    \retval RETURN_ERROR            初始化定时器失败
*/
OSP_S32 LVOS_DbgInitTimer(LVOS_TIMER_LIST_S *v_pstTimer, OSP_ULONG v_ulExpires, 
                       OSP_ULONG v_ulData, 
                       LVOS_TIMER_FUNC_PFN v_pfnTimerHandler, const OSP_CHAR * v_pFunc, OSP_U32 v_uiLine);

#define LVOS_InitTimer( v_pstTimer, v_ulExpires, v_ulData, v_pfnTimerHandler)\
            LVOS_DbgInitTimer(v_pstTimer, v_ulExpires, v_ulData, v_pfnTimerHandler, __FUNCTION__, __LINE__)


/*****************************************************************************
 函 数 名  : LVOS_AddTimer
 功能描述  : 激活定时器，该定时器将只激活一次，超时后即自动销毁
 输入参数  : LVOS_TIMER_LIST_S *v_pstTimer
 输出参数  : 无
 返 回 值  : OSP_VOID
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2009年5月25日

    修改内容   : 新生成函数

*****************************************************************************/
/**
    \brief 激活定时器，该定时器将只激活一次，超时后即自动销毁
    \note 支持windows/linux_kernel
    \param[in] v_pstTimer   定时器结构体
    \retval RETURN_OK       激活定时器成功
    \retval RETURN_ERROR    激活定时器失败
*/
OSP_S32 LVOS_DbgAddTimer( LVOS_TIMER_LIST_S *v_pstTimer, 
                                                        const OSP_CHAR * v_pFunc, OSP_U32 v_uiLine);
#define LVOS_AddTimer(v_pstTimer)\
    LVOS_DbgAddTimer(v_pstTimer,__FUNCTION__,__LINE__)

/*****************************************************************************
 函 数 名  : LVOS_ModTimer
 功能描述  : 修改定时器超时时间，如果此时定时器还没有激活或者已经销毁，此接口将导致
             激活定时器或者重新生成一个定时器并激活
 输入参数  : LVOS_TIMER_LIST_S *v_pstTimer
             OSP_ULONG v_ulExpires
 输出参数  : 无
 返 回 值  : OSP_S32
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2009年5月25日

    修改内容   : 新生成函数

*****************************************************************************/
/**
    \brief 修改定时器超时时间
    \note 支持windows/linux_kernel
    \note 如果此时定时器还没有激活或者已经销毁，此接口将导致激活定时器或者重新生成一个定时器并激活
    \param[in] v_pstTimer    定时器结构体
    \param[in] v_ulExpires   新的定时器超时时间
    \retval RETURN_OK        修改定时器成功
    \retval RETURN_ERROR     修改定时器失败
*/
OSP_S32 LVOS_ModTimer( LVOS_TIMER_LIST_S *v_pstTimer, OSP_ULONG v_ulExpires );

/**
    \brief 删除定时器
    \note 支持windows/linux_kernel
    \param[in] v_pstTimer    定时器结构体
    \retval RETURN_OK        删除定时器成功
    \retval RETURN_ERROR     删除定时器失败
*/
OSP_S32 LVOS_DelTimer( LVOS_TIMER_LIST_S *v_pstTimer );

/*****************************************************************************
 函 数 名  : LVOS_DelTimer
 功能描述  : 同步 删除定时器
 输入参数  : LVOS_TIMER_LIST_S *v_pstTimer
 输出参数  : 无
 返 回 值  : OSP_S32
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2009年11月17日

    修改内容   : 新生成函数

*****************************************************************************/
/**
    \brief 同步 删除定时器
    \note 在多处理器下使用
    \param[in] v_pstTimer    定时器结构体
    \retval RETURN_OK        删除定时器成功
    \retval RETURN_ERROR     删除定时器失败
*/
OSP_S32 LVOS_DelTimerSync( LVOS_TIMER_LIST_S *v_pstTimer );

/*****************************************************************************
 函 数 名  : LVOS_IsTimerActivated
 功能描述  :  判断定时器是否已经激活
 输入参数  : LVOS_TIMER_LIST_S *v_pstTimer
 输出参数  : 
 返 回 值  : OSP_BOOL  TRUE 已激活
                                        FALSE 未激活
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2009年12月2日

    修改内容   : 新生成函数
*****************************************************************************/
/**
    \brief 判断定时器是否已经激活
    \note 
    \param[in] v_pstTimer    定时器结构体   
    \retval TRUE      已激活
    \retval FALSE     未激活
*/
OSP_BOOL LVOS_IsTimerActivated( LVOS_TIMER_LIST_S *v_pstTimer );

#endif
/********************** 定义linux平台下内核态使用的数据结构 及函数声明end ************************/

/*********************************** 各平台均使用的函数的声明 begin ************************************/
/*****************************************************************************
 函 数 名  : LVOS_DestroyTimer
 功能描述  :  销毁定时器
 输入参数  : LVOS_TIMER_LIST_S *v_pstTimer
 输出参数  : 无
 返 回 值  : OSP_VOID
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2009年12月2日

    修改内容   : 新生成函数

*****************************************************************************/
/**
    \brief 销毁定时器
    \note 从alps移植过来 
    \param[in] v_pstTimer    定时器结构体   
*/
static inline OSP_VOID LVOS_DestroyTimer( LVOS_TIMER_LIST_S *v_pstTimer )
{
    if (NULL != v_pstTimer)
    {
        (OSP_VOID)LVOS_DelTimerSync(v_pstTimer);
    }
    return;
}

#endif

/*********************************** 各平台均使用的函数的声明 end ************************************/

#endif  /* __LVOS_TIMER_LIST_H__ */

