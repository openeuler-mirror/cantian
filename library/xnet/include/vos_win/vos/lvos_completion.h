/******************************************************************************

                  版权所有 (C), 2008-2008, 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : lvos_completion.h
  版 本 号   : 初稿

  生成日期   : 2009年5月19日
  最近修改   :
  功能描述   : 完成变量对外接口，适用于windows仿真和linux内核态
  函数列表   :
  修改历史   :
  1.日    期   : 2009年5月19日

    修改内容   : 创建文件

******************************************************************************/
/**
    \file  lvos_completion.h
    \brief 完成变量对外接口，适用于windows仿真和linux内核态，不支持linux用户态

    \date 2009年5月19日
*/

/** \addtogroup VOS_COMPLETION  完成变量
    完成变量对外接口，适用于windows仿真和linux内核态，不支持linux用户态\n
    完成变量功能类似于信号量，使用过程中有可能导致调用进程阻塞，因此，对于不能阻塞的调用\n
    上下文(如中断等)，不要使用完成变量。
    @{ 
*/

#ifndef __LVOS_COMPLETION_H__
#define __LVOS_COMPLETION_H__
#if 0
#if defined(WIN32) || defined(_PCLINT_)

/** \brief 完成变量结构体 */
typedef struct
{
    LVOS_SEMAPHORE_S stDone;
} LVOS_COMPLETION_S;

/**
    \brief 初始化完成变量
    \param[in] v_pstCompletion    完成变量指针
    \retval    void
*/
void LVOS_InitCompletion(LVOS_COMPLETION_S *v_pstCompletion);

/**
    \brief 销毁完成变量
    \note  需要销毁完成变量是因为需要销毁windows下的信号量句柄
    \param[in] v_pstCompletion    完成变量指针
    \retval    无
*/
void LVOS_DestroyCompletion(LVOS_COMPLETION_S *v_pstCompletion);

/**
    \brief 等待获取完成变量
    \note  本函数调用使用过程中有可能导致调用进程阻塞
    \param[in] v_pstCompletion    完成变量指针
    \retval    无
*/
void LVOS_WaitForCompletion(LVOS_COMPLETION_S *v_pstCompletion);

/**
    \brief 唤醒完成变量
    \param[in] v_pstCompletion    完成变量指针
    \retval    无
*/
void LVOS_Complete(LVOS_COMPLETION_S *v_pstCompletion);

/**
    \brief 唤醒完成变量后退出线程
    \param[in] v_pstCompletion    完成变量指针    
    \param[in] lExitCode          退出码
    \retval    无
*/
void LVOS_CompleteAndExit(LVOS_COMPLETION_S *v_pstCompletion, OSP_LONG lExitCode);

#elif defined (__KERNEL__)
#include <linux/completion.h>

/* linux内核态下的完成变量结构体  */
typedef struct completion LVOS_COMPLETION_S;
#define LVOS_InitCompletion(cmp)             init_completion(cmp)
#define LVOS_WaitForCompletion(cmp)          wait_for_completion(cmp)
#define LVOS_Complete(cmp)                   complete(cmp)
#define LVOS_CompleteAndExit(cmp, exitcode)  complete_and_exit(cmp, exitcode)
#define LVOS_DestroyCompletion(cmp)    /* 该函数是用于销毁windows下模拟完成变量用的句柄的，linux下为空 */

#endif
#endif

#endif

/** @} */

