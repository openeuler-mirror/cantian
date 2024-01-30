/******************************************************************************

                  版权所有 (C), 2009-2009, 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : lvos_wait.h
  版 本 号   : 初稿

  生成日期   : 2009年5月12日
  最近修改   :
  功能描述   : 与等待队列相关的通用功能接口头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2009年5月12日

    修改内容   : 创建文件

******************************************************************************/
/**
    \file  lvos_wait.h
    \brief 等待队列功能，仿照linux内核态下的等待队列接口
    \note  支持windows/linux_kernel，等待队列有可能导致调用者阻塞，因此不适用于不允许阻塞的调用上下文
    \date 2009年5月12日
*/

/** \addtogroup VOS_WAIT 等待队列功能
    @{
*/

#ifndef __LVOS_WAIT_H__
#define __LVOS_WAIT_H__

#if defined(WIN32) || defined(__KERNEL__)
/********************** 定义windows平台下使用的等待队列数据结构 begin ************************/
#ifdef WIN32
/** \brief 等待队列，封装linux下的struct wait_queue_head_t */
typedef struct
{
    CRITICAL_SECTION CriticalSection;
    HANDLE hEvent;
}LVOS_WAIT_QUEUE_S;

/**
    \brief Linux内核态下等待事件发生
    \param[in] wq      等待队列指针
    \param[in] condition       唤醒条件
    \retval    void
*/

#define LVOS_WaitEvent(wq,condition) \
do {\
    LVOS_MightSleep(); \
    while (!(condition))\
    {\
        DWORD dwRet;\
        dwRet = WaitForSingleObject((wq).hEvent,(OSP_ULONG)INFINITE); \
        if (WAIT_OBJECT_0 != dwRet)\
        {\
            DBG_ASSERT_EXPR(0, "WaitForSingleObject return an unexpected error :0x%x, LastError: %u", dwRet, GetLastError()); \
            break;\
        }\
    }\
}while (0)

/**
    \brief Linux内核态下等待事件发生
    \param[in] wq      等待队列指针
    \param[in] condition       唤醒条件
    \param[in] timeout         超时时间
    \retval    void
*/
#define LVOS_WaitEventTimeout(wq,condition,timeout) \
do {\
    LVOS_MightSleep();\
    if (!(condition))\
    {\
        (void)WaitForSingleObject((wq).hEvent,(timeout));\
    }\
}while (0)

/**
    \brief 唤醒所有等待事件的进程
    \note  唤醒所有等待队列上等待事件的进程
    \param[in] wq        等待队列指针
    \retval    void
*/
#define LVOS_WakeUp(wq)\
do {\
    (void)SetEvent((wq)->hEvent);\
}while (0)

/**
    \brief Windows下初始化等待队列
    \param[in] v_pstWQ        等待队列指针
    \retval    void
*/
static inline void LVOS_InitWaitQueue( LVOS_WAIT_QUEUE_S *v_pstWQ )
{
    _ASSERT(NULL != v_pstWQ);

    InitializeCriticalSection(&(v_pstWQ->CriticalSection));

    v_pstWQ->hEvent = CreateEvent( NULL,               /* default security attributes*/
                                    FALSE,               /* manual-reset event*/
                                    FALSE,              /* initial state is nonsignaled*/
                                    NULL
                                    );

    return;
}

/**
    \brief Windows下销毁指定的等待队列
    \param[in] v_pstWQ       等待队列指针
    \retval    void
*/
static inline void LVOS_DestroyWaitQueue( LVOS_WAIT_QUEUE_S *v_pstWQ )
{

    _ASSERT(NULL != v_pstWQ);

    DeleteCriticalSection(&(v_pstWQ->CriticalSection));
    CloseHandle(v_pstWQ->hEvent);
    return;
}


#elif defined(__KERNEL__)
#include <linux/wait.h>

typedef wait_queue_head_t LVOS_WAIT_QUEUE_S;

/**
    \brief Linux内核态下等待事件发生
    \param[in] v_pstWQ      等待队列指针
    \param[in] condition       唤醒条件
    \retval    void
*/
#define LVOS_WaitEvent(wq,condition) wait_event(wq, condition)

/**
    \brief Linux内核态下等待事件发生
    \param[in] v_pstWQ      等待队列指针
    \param[in] condition       唤醒条件
    \param[in] timeout         超时时间
    \retval    void
*/
#define LVOS_WaitEventTimeout(wq, condition, timeout) wait_event_timeout(wq, condition, timeout)

/**
    \brief Linux内核态下初始化等待队
    \param[in] v_pstWQ        等待队列指针
    \retval    void
*/
#define LVOS_InitWaitQueue(wq) init_waitqueue_head(wq)

/**
    \brief Linux内核态下销毁指定的等待队列
    \note  该函数在Linux内核态下为空
    \param[in] v_pstWQ        等待队列头指针
    \retval    void
*/
#define LVOS_DestroyWaitQueue(pstWQHead)

/**
    \brief 唤醒一个等待事件的进程
    \note  唤醒一个等待队列上等待事件 的进程
    \param[in] v_pstWQ        等待队列指针
    \retval    void
*/
#define LVOS_WakeUp(v_pstWQ) wake_up_all(v_pstWQ)
#endif
#endif

#endif /* __LVOS_WATI_H__ */

/** @} */

