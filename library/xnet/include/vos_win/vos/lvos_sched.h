/******************************************************************************

                  版权所有 (C), 2008-2008, 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : lvos_sched.h
  版 本 号   : 初稿

  生成日期   : 2009年5月11日
  最近修改   :
  功能描述   : 线程调度的通用功能接口头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2009年5月11日

    修改内容   : 创建文件

******************************************************************************/

/**
    \file  lvos_sched.h
    \brief 线程调度的通用功能接口头文件
    \note  中断处理程序等不允许进程调度的上下文中不要使用本文件中的函数

    \date 2009年5月11日
*/

/** \addtogroup VOS_SCHED 延时调度类接口
    @{ 
*/

#ifndef __LVOS_SCHED_H__
#define __LVOS_SCHED_H__

/** \brief 计算延迟的毫秒数
    \param[in] x  延迟秒数
    \return 毫秒数
*/
#define DELAY_SEC(x)    ((x) * 100)

/** \brief 计算延迟秒数
    \param[in] x  延迟多少十秒数
    \return 毫秒数
*/
#define DELAY_10MS(x)   ((x))

/** \brief      以微妙为单位的延时函数
    \param[in]  us 以us为单位的睡眠时间
    \retval     void
*/
void LVOS_usleep(unsigned int us);

/** \brief      进程睡眠函数，输入参数的单位为10ms
    \note       支持windows/linux_kernel/linux_user
    \param[in]  ten_ms 以10ms为单位的睡眠时间
    \retval     void
    \attention  lvos_sleep可被信号提前唤醒
*/
void LVOS_sleep(unsigned int ten_ms);

/** \brief      进程睡眠函数，输入参数的单位为1ms
    \note       支持windows/linux_kernel/linux_user
    \param[in]  ms 以ms为单位的睡眠时间
    \retval     void
    \attention  lvos_sleep可被信号提前唤醒
*/
void LVOS_msleep(unsigned int ms);

/** \brief      进程调度函数，进程主动进行任务调度
    \note       支持windows仿真平台和linux内核态
*/
void LVOS_Schedule(void);

/** \brief      进程主动放弃CPU
    \note       支持windows仿真平台和linux内核态
*/
void LVOS_Yield(void);

/** \brief  线程可能sleep的调试功能，如果线程不允许休眠调用该函数则会报告错误
    \note  调试功能
*/
#ifdef WIN32
void LVOS_MightSleep(void);
#elif defined(__KERNEL__)
#define LVOS_MightSleep might_sleep
#else
#define LVOS_MightSleep()
#endif

#ifdef WIN32

/** \brief 设置线程在中断上下文标志
    \note  调试功能
*/
void LVOS_SetThreadInterruptFlag(OSP_S32 v_iFlag);

/** \brief 设置线程在IOD上下文标志
    \note  调试功能
*/
void LVOS_SetThreadIodFlag(OSP_S32 v_iFlag);

/** \brief spinlock计数增加g_iThreadInterruptFlag
    \note  调试功能
*/
void LVOS_IncThreadSpinCount(void);

/** \brief spinlock计数减一
    \note  调试功能
*/
void LVOS_DecThreadSpinCount(void);

/** \brief 调试打印专用
    \note 调试功能
*/
void LVOS_SetDebugPrintFlag(OSP_S32 v_iFlag);

#else
#define LVOS_SetThreadInterruptFlag(v_iFlag)
#define LVOS_SetThreadIodFlag(v_iFlag)
#define LVOS_IncThreadSpinCount()
#define LVOS_DecThreadSpinCount()
#define LVOS_SetDebugPrintFlag(v_iFlag)
#endif

#endif /* __LVOS_SHCED_H__ */

/** @} */

