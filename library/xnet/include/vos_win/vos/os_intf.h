/**************************************************************************

    (C) 2007 ~2019   华为赛门铁克科技有限公司  版权所有，保留一切权利。

***************************************************************************
 版 本 号:  初稿
 作    者:  x00001559
 完成日期:  2011年9月23日
 功能描述:  OS提供给上层模块调用的接口
 备    注:  
 修改记录:  
        1.时     间 :
          修 改 人 :
          修改内容 :
**************************************************************************/
#ifndef OS_INTF_H
#define OS_INTF_H

#if defined(WIN32) || defined(__KERNEL__)
#if defined(__KERNEL__) && !defined(_PCLINT_)
#include <linux/blkdev.h>
#endif /* __KERNEL__ && !(_PCLINT_) */

/* 最多允许有CACHEMEMMAX个cache类型的内存段 */
#define CACHEMEMMAX 4
typedef struct tagOS_CACHE_MEM_INFO
{
    OSP_U32 nr_cache;       /* cache内存段的个数 */
    struct cacheEntry
    {
        OSP_U64 addr;       /* 内存段的起始线性地址 */
        OSP_U64 size;       /* 内存段长度，单位:字节 */
    }map[CACHEMEMMAX];      /* 内存段数组，最多CACHEMEMMAX个成员 */
}OS_CACHE_MEM_INFO;

/**
    \brief 复位本控制器，复位原因是 software
*/
static inline OSP_U32 OS_ResetLocalBoard(void)
{
	return 0;
}
OSP_S32 OS_SetMemoryRO(OSP_VOID *addr, OSP_S32 numpages);
OSP_S32 OS_SetMemoryRW(OSP_VOID *addr, OSP_S32 numpages);
OSP_VOID OS_GetCacheMemInfo(OS_CACHE_MEM_INFO *v_pstCacheMemInfo);
OSP_S32 OS_GetMemoryRW(OSP_VOID *addr);

extern OSP_U32 uiSetMem;
#define OS_SETMEMORY_RO(addr, numpages) \
do \
{ \
    if ( 1 == uiSetMem )\
    {\
        (void)OS_SetMemoryRO(addr, numpages); \
    }\
} while (0)
#define OS_SETMEMORY_RW(addr, numpages) \
do \
{ \
    if ( 1 == uiSetMem )\
    {\
        (void)OS_SetMemoryRW(addr, numpages); \
    }\
} while (0)

#ifdef __KERNEL__
void OS_BlkExecuteRqNowait(struct request_queue *q,
                           struct gendisk *bd_disk,
                           struct request *rq, OSP_S32 at_head,
                           rq_end_io_fn *done);
/**
    \brief 打开串口打印
*/
OSP_U32 OS_TtySPrintOn(void);
/**
    \brief 关闭串口打印
*/
OSP_U32 OS_TtySPrintOff(void);
OSP_S32 OS_SetThrdAffinityCPU(OSP_ULONG v_ulCpu);
#endif /* __KERNEL__ */

#endif /* WIN32 || __KERNEL__ */

#endif /* OS_INTF_H */
