/******************************************************************************

                  版权所有 (C) 2008-2008 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : lvos_lib.h
  版 本 号   : 初稿
  
  生成日期   : 2008年8月19日
  最近修改   :
  功能描述   : 系统基本信息
  函数列表   :
  修改历史   :
  1.日    期   : 2008年8月19日
    
    修改内容   : 创建文件

******************************************************************************/
/** \addtogroup VOS_SYSINFO  系统基本信息
  @{
*/

#ifndef _VOS_SYSINFO_H_
#define _VOS_SYSINFO_H_


/** \brief 当前系统的CPU利用率
    \note  支持windows、linux用户态、linux内核态
    \note  同步接口，该函数将会导致调用进程睡眠片刻(500ms)，以计算CPU利用率
    \retval OSP_S32         获取成功，返回当前系统的CPU利用率百分比
    \retval RETURN_ERROR    获取失败
*/
OSP_S32 LVOS_GetCpuUsage(void);

/** \brief 当前系统的内存利用率
    \note  支持windows、linux用户态、linux内核态
    \note  同步接口，可能导致调用者阻塞
    \retval OSP_S32         获取成功，返回当前系统的内存利用率百分比
    \retval RETURN_ERROR    获取失败
*/
OSP_S32 LVOS_GetMemUsage(void);

/** \brief 获取当前系统CPU数量
    \return 返回CPU数量
    \note   Linux内核态和Windows可用
*/
OSP_S32 LVOS_GetCpuNumber(void);

OSP_S32 LVOS_SysInfoInit(void);


#define CPU_MIN_NUM_ALLOW_BIND0 8
#define LVOS_IS_CPU_ALLOW_BIND_CPU0  (LVOS_GetCpuNumber() > CPU_MIN_NUM_ALLOW_BIND0)


#endif

/** @} */
