/******************************************************************************

                  版权所有 (C), 2008-2008, 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : lvos_mb.h
  版 本 号   : 初稿
  作    者   : c90004010
  生成日期   : 2013年07月31日
  最近修改   :
  功能描述   : 定义了内存屏障的相关函数
  函数列表   :
  修改历史   :
  1.日    期   : 2013年07月31日
    作    者   : c90004010
    修改内容   : 创建文件

******************************************************************************/
#ifndef __LVOS_MB_H__
#define __LVOS_MB_H__

#if defined(WIN32) || defined(_PCLINT_)

/* 函数功能在winodws和linux下不一样，这里仅保证pclint和windows下的编译通过 */

#define barrier MemoryBarrier
#define smp_mb MemoryBarrier
#define smp_rmb MemoryBarrier
#define smp_wmb MemoryBarrier
#define smp_read_barrier_depends MemoryBarrier
#define mb MemoryBarrier
#define rmb MemoryBarrier
#define wmb MemoryBarrier

#endif

#endif
