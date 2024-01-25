/******************************************************************************

                  版权所有 (C) 2008-2008 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : lvos_bitops.h
  版 本 号   : 初稿
  作    者   : x00001559
  生成日期   : 2008年7月8日
  最近修改   :
  功能描述   : Linux内核的bit操作功能仿真
  函数列表   :
  修改历史   :
  1.日    期   : 2008年7月8日
    作    者   : x00001559
    修改内容   : 创建文件

******************************************************************************/
/**
    \file  lvos_bitops.h
    \brief bit操作功能

    \date 2008-05-27
*/

/** \addtogroup VOS_BITOPS 位操作
    @{ 
*/

#ifndef __LVOS_BITOPS_H__
#define __LVOS_BITOPS_H__

#if defined(WIN32) || defined(_PCLINT_)
/**
    \brief 原子的设置addr所指对象第nr位
    \note  适用于windows、linux内核态、linux用户态(不保证原子性)，这里保留支持linux用户态只是为了兼容以前的代码，
    \note  linux用户态请尽量不要使用内核态的位操作方式。
    \note  无调用上下文限制
    \param[in] nr        要设置第几位
    \param[in] addr      对象地址
    \return  无
*/
void set_bit( OSP_S32 nr, void *addr);

/**
    \brief 原子的清空addr所指对象第nr位
    \note  适用于windows、linux内核态、linux用户态(不保证原子性)，这里保留支持linux用户态只是为了兼容以前的代码，
    \note  linux用户态请尽量不要使用内核态的位操作方式。
    \note  无调用上下文限制
    \param[in] nr        要清空第几位
    \param[in] addr      对象地址
    \return    无
*/
void clear_bit(OSP_S32 nr, void *addr);

/**
    \brief 原子的测试addr所指对象第nr位，为0则返回0，否则返回非0
    \note  适用于windows、linux内核态、linux用户态(不保证原子性)，这里保留支持linux用户态只是为了兼容以前的代码，
    \note  linux用户态请尽量不要使用内核态的位操作方式。
    \note  无调用上下文限制
    \attention 如果原有bit值不是0的话，会返回非0，不一定就是1
    \param[in] nr        要测试第几位
    \param[in] addr      对象地址
    \retval    0   原有bit值为0
    \retval    非0 原有bit值不为0
*/
OSP_S32 test_bit(OSP_S32 nr, void *addr);


/**
    \brief 原子的设置addr所指对象第nr位，并测试原有bit值是否为0。为0则返回0，否则返回非0
    \note  支持windows和linux内核态，不支持linux用户态
    \note  无调用上下文限制    
    \attention 如果原有bit值不是0的话，会返回非0，不一定就是1
    \param[in] nr        要设置第几位
    \param[in] addr      对象地址
    \retval    0   原有bit值为0
    \retval    非0 原有bit值不为0
*/

OSP_S32 test_and_set_bit(OSP_S32 nr, void *addr);

/**
    \brief 原子的设置addr所指对象第nr位，并返回设置前的bit值
    \note  支持windows和linux内核态，不支持linux用户态
    \note  无调用上下文限制    
    \attention 如果原有bit值不是0的话，会返回非0，不一定就是1
    \param[in] nr        要清空第几位
    \param[in] addr      对象地址
    \retval    0   原有bit值为0
    \retval    非0 原有bit值不为0
*/
OSP_S32 test_and_clear_bit(OSP_S32 nr, void *addr);

/**
    \brief 原子的翻转addr所指对象第nr位，并返回翻转前的bit值
    \note  支持windows和linux内核态，不支持linux用户态
    \note  无调用上下文限制
    \attention 如果原有bit值不是0的话，会返回非0，不一定就是1
    \param[in] nr        要清空第几位
    \param[in] addr      对象地址
    \retval    0   原有bit值为0
    \retval    非0 原有bit值不为0
*/
OSP_S32 test_and_change_bit(OSP_S32 nr, void *addr);

/**
    \brief 计算w中为1的bit的数量
*/
OSP_U32 hweight32(OSP_U32 w);

/* 计算w中为1的bit的数量 */
unsigned long hweight64(uint64_t w);

#elif defined(__LINUX_USR__)
#ifdef mips
#include <asm/bitops.h>
#else
static inline void set_bit(OSP_S32 nr, void *addr)
{
    asm volatile("lock;" "bts %1,%0" : "+m" (addr) : "Ir" (nr) : "memory");
}

static inline OSP_S32 test_bit(OSP_S32 nr, void *addr)
{
    int oldbit;

    asm volatile("bt %2,%1\n\t"
             "sbb %0,%0"
             : "=r" (oldbit)
             : "m" (*(unsigned long *)addr), "Ir" (nr));

    return oldbit;
}

static inline void clear_bit(OSP_S32 nr, void *addr)
{
    asm volatile("lock;" "btr %1,%0" : "+m" (addr) : "Ir" (nr));
}
#endif
#elif defined(__KERNEL__)
#include <asm/bitops.h>

#else
#error "platform not specify"
#endif

#define LVOS_set_bit                             set_bit            
#define LVOS_test_bit                            test_bit           
#define LVOS_clear_bit                           clear_bit          
#define LVOS_test_and_set_bit                    test_and_set_bit   
#define LVOS_test_and_clear_bit                  test_and_clear_bit 
#define LVOS_test_and_change_bit                 test_and_change_bit

/**
    Dorado_V3新增7个非原子变量位操作仿真接口，使用原子变量方法实现。
    代码中没有非原子变量位操作实现方法，且两种方法在功能上没有差别，只有性能上的差距。
    仿真不关心性能，固使用原子变量位操作方法重新封装。
    新增时间：2016/06/20
*/
#define LVOS_set_bit_non_atomic                  set_bit
#define LVOS_clear_bit_non_atomic                clear_bit
#define LVOS_test_and_set_bit_non_atomic         test_and_set_bit
#define LVOS_test_and_clear_bit_non_atomic       test_and_clear_bit
#define LVOS_test_and_change_bit_non_atomic      test_and_change_bit
#define LVOS_change_bit_non_atomic               (void)test_and_change_bit

/**
    \brief 查找第一个为1的bit位(非原子操作)
    \param[in]  v_pAddr  需要查找的起始地址
    \param[in]  iSize   查找的长度(单位为bit位)
    \param[out] v_pIndex 传出找到的索引(单位为bit位)
    \retval     TRUE     成功找到为1的bit位
    \retval     FALSE    没有找到
*/
OSP_BOOL LVOS_FindFirst1Bit(const void *v_pAddr, OSP_S32 iSize, OSP_S32 *v_pIndex);

/**
    \brief 查找第一个为0的bit位(非原子操作)
    \param[in]  v_pAddr  需要查找的起始地址
    \param[in]  iSize    查找的长度(单位为bit位)
    \param[out] v_pIndex 传出找到的索引(单位为bit位)
    \retval     TRUE     成功找到为0的bit位
    \retval     FALSE    没有找到
*/
OSP_BOOL LVOS_FindFirst0Bit(const void *v_pAddr, OSP_S32 iSize, OSP_S32 *v_pIndex);

/**
    \brief 查找下一个为1的bit位(非原子操作)
    \param[in]  addr     需要查找的起始地址
    \param[in]  size     查找的长度(单位为bit位)
    \param[in]  offset   查找起始位置
    \param[out] index    传出找到的索引(单位为bit位)
    \retval     TRUE     成功找到为1的bit位
    \retval     FALSE    没有找到
*/
bool LVOS_FindNext1Bit(const void *addr, int32_t size, int32_t offset, int32_t *index);

#ifdef WIN32 /* Linux下直接用内核的 */
/*
    \brief 查找第一个为1的bit位(非原子操作)
    \return 找到返回索引，找不到返回值 >= size
*/
unsigned long find_first_bit(const unsigned long * addr, unsigned long size);
/*
    \brief 查找下一个为1的bit位(非原子操作)
    \return 找到返回索引，找不到返回 >= size
*/
unsigned long find_next_bit(const unsigned long *addr, unsigned long size, unsigned long offset);

unsigned long find_next_zero_bit(const unsigned long *addr, unsigned long size, unsigned long offset);

/*
    \brief   查找第一个为1的bit最低位
    \return  返回找到的bit位的索引 1 ~ 32, 为 0 表示没有找到
*/
int ffs(int x);

/*
    \brief   查找第一个为1的bit最高位 
    \return  返回找到的bit位的索引 1 ~ 32, 为 0 表示没有找到
*/
int fls(int x);

#endif

#endif /* __LVOS_BITOPS_H__ */
/**
    @}
*/

