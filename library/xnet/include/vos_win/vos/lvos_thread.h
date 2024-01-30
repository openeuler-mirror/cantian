 /******************************************************************************

                  版权所有 (C), 2008-2008, 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : lvos_thread.h
  版 本 号   : 初稿

  生成日期   : 2008年6月3日
  最近修改   :
  功能描述   : 线程管理功能封装
  函数列表   :
  修改历史   :
  1.日    期   : 2008年6月3日

    修改内容   : 创建文件

******************************************************************************/
/**
    \file  lvos_thread.h
    \brief 线程管理对外接口
    \date 2009年5月19日
*/

/** \addtogroup VOS_THREAD 线程接口
    @{ 
*/

#ifndef __LVOS_THREAD_H__
#define __LVOS_THREAD_H__

#include "dpax_thrd.h"

/** \brief 线程优先级枚举，使用时请直接使用宏，不要直接使用宏值 */
typedef enum tagLVOS_THRD_PRI_E
{
    LVOS_THRD_PRI_HIGHEST = 0,        /**< 最高级 */
    LVOS_THRD_PRI_HIGH,               /**< 高级 */
    LVOS_THRD_PRI_SUBHIGH,            /**< 次高 */
    LVOS_THRD_PRI_MIDDLE,             /**< 中间级 */
    LVOS_THRD_PRI_LOW,                /**< 低级 */
    LVOS_THRD_PRI_BUTT
} LVOS_THRD_PRI_E;

#ifndef WIN32
#define WINAPI /* 为兼容WINDOWS程序定义  */
#endif

/** \brief 线程处理函数原型
    \sa LVOS_CreateThread
*/
typedef OSP_S32 (WINAPI *PLVOSTHREAD_START_ROUTINE)(void *);

/** \brief 创建线程
    \param[in] v_pfnStartRoutine 线程处理函数
    \param[in] v_pArg 传入v_pfnStartRoutine函数的参数
    \param[out] v_pulThreadId 传出成功创建的线程ID
    \retval RETURN_OK 创建成功
    \retval RETURN_ERROR 创建失败
    \attention 线程处理函数为了兼容WIN32下面需要加入WINAPI作为函数call类型
    \sa LVOS_SetThreadName
*/
/*lint -sem(LVOS_CreateThread, custodial(2)) */
OSP_S32 LVOS_CreateThread(PLVOSTHREAD_START_ROUTINE v_pfnStartRoutine, void *v_pArg, OSP_ULONG *v_pulThreadId);

/** \brief 设置线程名并将线程推到后台执行(内核态的daemonize函数封装)
    \param[in] ... 和printf一样的格式化字符串和参数
    \note  该宏只有Linux内核态有用，用户态和WIN32下定义为空。同步接口，可能会导致调用者阻塞
    \note  内核态实现如下:
    \code  
    #define LVOS_SetThreadName(...) \
    do                          \
    {                           \
        daemonize(__VA_ARGS__); \
    }while(0)
    \endcode
    \note 使用举例:
    \code
    LVOS_SetThreadName("function1");
    LVOS_SetThreadName("func_%s", "name1");
    \endcode
    \sa LVOS_CreateThread
*/
#define LVOS_SetThreadName(...) 

#if defined(__KERNEL__) && !defined(_PCLINT_)
#undef LVOS_SetThreadName
#define LVOS_SetThreadName(...) \
do                          \
{                           \
    daemonize(__VA_ARGS__); \
}while(0)

#endif


/** \brief 设置线程优先级
    \param[in] v_uiThrdPri 线程优先级:合法值请参考宏类型\ref LVOS_THRD_PRI_E
*/
void LVOS_SetCurThrdPriority(dpax_thrd_prio_e v_uiThrdPri);

/** \brief 获得当前进程的PID
    \retval 当前进程的PID
    \note windows下的获得进程id 
*/
OSP_S32 LVOS_GetPid(void);

/** \brief 获得当前线程ID
      \retval 当前线程ID
      \note windows下的获得线程id 
*/
dpax_pthread_t LVOS_GetTid(void);

#endif
/** @} */

