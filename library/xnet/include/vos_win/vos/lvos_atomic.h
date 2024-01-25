/******************************************************************************

                  版权所有 (C) 2008-2008 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : lvos_atomic.h
  版 本 号   : 初稿

  生成日期   : 2008年7月8日
  最近修改   :
  功能描述   : Linux内核的atomic功能仿真
  函数列表   :
  修改历史   :
  1.日    期   : 2008年7月8日

    修改内容   : 创建文件

  2.日    期   : 2008年11月18日

    修改内容   : 增加atomic_inc 和atomic_dec

******************************************************************************/
/**
    \file  lvos_atomic.h
    \brief 原子操作相关接口定义

    \date 2010-05-08
*/

/** \addtogroup VOS_ATOMIC 原子操作
    @{ 
*/

#ifndef __LVOS_ATOMIC_H__
#define __LVOS_ATOMIC_H__

#if defined(WIN32) || defined(_PCLINT_) || defined(__LINUX_USR__)

/** \brief 原子变量类型定义 */
typedef struct { 
    volatile long counter;
} atomic_t;

/**
    \brief 初始化原子变量
    \note  适用于windows和linux内核态，不支持linux用户态
    \note  无调用上下文限制
    \param[in] i    原子变量的初始化值
    \retval    初始化后的原子变量
*/
#define ATOMIC_INIT(i)  { (i) }


/**
    \brief 设置原子变量值
    \note  适用于windows、linux内核态、linux用户态，这里保留支持linux用户态只是为了兼容以前的代码，
    \note  linux用户态有自己的同步方法，因此请尽量不要使用内核态的同步方式。
    \note  无调用上下文限制
*/
void atomic_set(atomic_t *v, OSP_S32 val);

/**
    \brief 原子加，返回相加后的值
    \note  适用于windows、linux内核态，不支持linux用户态
    \note  无调用上下文限制
    \param[in] i    原子变量要增加的值
    \param[in] v 原子变量指针
    \return    原子变量相加后的值
*/
OSP_S32 atomic_add_return(OSP_S32 i, atomic_t *v);


/**
    \brief 原子加，但无返回值    
    \note  适用于windows、linux内核态、linux用户态(不保证原子性)，这里保留支持linux用户态只是为了兼容以前的代码，
    \note  linux用户态有自己的同步方法，因此请尽量不要使用内核态的同步方式。
    \note  无调用上下文限制
    \param[in] i 原子变量要增加的值
    \param[in] v 原子变量指针
    \return    无
*/
void atomic_add(OSP_S32 i, atomic_t *v);

/**
    \brief 获取原子变量值
    \note  适用于windows、linux内核态、linux用户态，这里保留支持linux用户态只是为了兼容以前的代码，
    \note  linux用户态有自己的同步方法，因此请尽量不要使用内核态的同步方式。
    \note  无调用上下文限制
    \param[in] v 原子变量指针
    \retval    OSP_S32   原子变量的值
*/
OSP_S32 atomic_read(atomic_t *v);

/**
    \brief 原子减，返回相减后的值
    \note  适用于windows和linux内核态，不支持linux用户态
    \note  无调用上下文限制
    \param[in] i    原子变量要减少的值
    \param[in] v 原子变量指针
    \retval    OSP_S32   原子变量相减后的值
*/
OSP_S32 atomic_sub_return(OSP_S32 i, atomic_t *v);


/**
    \brief 原子减
    \note  适用于windows、linux内核态、linux用户态(不保证原子性)，这里保留支持linux用户态只是为了兼容以前的代码，
    \note  linux用户态有自己的同步方法，因此请尽量不要使用内核态的同步方式。
    \note  无调用上下文限制
    \param[in]  i  原子变量要减少的值
    \param[in]  v  原子变量指针
    \return     无
*/
void atomic_sub(OSP_S32 i, atomic_t *v);


/**
    \brief 原子减并测试结果是否为0
    \note  适用于windows、linux内核态、linux用户态(不保证原子性)，这里保留支持linux用户态只是为了兼容以前的代码，
    \note  linux用户态有自己的同步方法，因此请尽量不要使用内核态的同步方式。
    \note  无调用上下文限制
    \param[in] i    原子变量要减少的值
    \param[in] v 原子变量指针
    \retval    FALSE       相减后的值不为0
    \retval    TRUE        相减后的值为0
*/
OSP_BOOL atomic_sub_and_test(OSP_S32 i, atomic_t *v);


/**
    \brief 原子自增
    \note  适用于windows、linux内核态、linux用户态(不保证原子性)，这里保留支持linux用户态只是为了兼容以前的代码，
    \note  linux用户态有自己的同步方法，因此请尽量不要使用内核态的同步方式。
    \note  无调用上下文限制
    \param[in] v 原子变量指针
    \return    无
*/
void atomic_inc(atomic_t *v);


/**
    \brief 原子自增并返回自增后的值
    \note  适用于windows、linux内核态、linux用户态(不保证原子性)，这里保留支持linux用户态只是为了兼容以前的代码，
    \note  linux用户态有自己的同步方法，因此请尽量不要使用内核态的同步方式。
    \note  无调用上下文限制
    \param[in] v 原子变量指针
    \return    返回增加后的值
*/
OSP_S32 atomic_inc_return(atomic_t *v);


/**
    \brief 原子自减
    \note  适用于windows、linux内核态、linux用户态(不保证原子性)，这里保留支持linux用户态只是为了兼容以前的代码，
    \note  linux用户态有自己的同步方法，因此请尽量不要使用内核态的同步方式。
    \note  无调用上下文限制
    \param[in] v 原子变量指针
    \retval    void
*/
void atomic_dec(atomic_t *v);


/**
    \brief 原子自减并返回自减后的值
    \note  适用于windows、linux内核态、linux用户态(不保证原子性)，这里保留支持linux用户态只是为了兼容以前的代码，
    \note  linux用户态有自己的同步方法，因此请尽量不要使用内核态的同步方式。
    \note  无调用上下文限制
    \param[in] v 原子变量指针
    \retval    void
*/
OSP_S32 atomic_dec_return(atomic_t *v);

/**
    \brief 自增原子变量并测试结果是否为0
    \note  适用于windows和linux内核态，不支持linux用户态
    \note  无调用上下文限制
    \param[in] v 原子变量指针
    \retval    TRUE  自增后的结果为0
    \retval    FALSE 自增后的结果不为0
*/
OSP_BOOL atomic_inc_and_test(atomic_t *v);

/**
    \brief 自减原子变量并测试结果是否为0
    \note  适用于windows和linux内核态，不支持linux用户态
    \note  无调用上下文限制
    \param[in] v 原子变量指针
    \retval    TRUE  自减后的结果为0，返回TRUE
    \retval    FALSE 自减后的结果不为0，返回FALSE
*/
OSP_BOOL atomic_dec_and_test(atomic_t *v);

/**
    \brief 64位原子变量版本仿真
*/
typedef struct {
    volatile OSP_S64 counter;
} atomic64_t;

#define ATOMIC64_INIT(i) { (i) }

/**
    \brief 设置原子变量值
    \note  适用于windows、linux内核态、linux用户态，这里保留支持linux用户态只是为了兼容以前的代码，
    \note  linux用户态有自己的同步方法，因此请尽量不要使用内核态的同步方式。
    \note  无调用上下文限制
*/
void atomic64_set(atomic64_t *v, OSP_S64 val);

/**
    \brief 获取原子变量值
    \note  适用于windows、linux内核态、linux用户态，这里保留支持linux用户态只是为了兼容以前的代码，
    \note  linux用户态有自己的同步方法，因此请尽量不要使用内核态的同步方式。
    \note  无调用上下文限制
    \param[in] v 原子变量指针
    \retval    OSP_S32   原子变量的值
*/
OSP_S64 atomic64_read(atomic64_t *v);

/**
    \brief 原子自增
    \note  适用于windows、linux内核态、linux用户态(不保证原子性)，这里保留支持linux用户态只是为了兼容以前的代码，
    \note  linux用户态有自己的同步方法，因此请尽量不要使用内核态的同步方式。
    \note  无调用上下文限制
    \param[in] v 原子变量指针
    \return    无
*/
void atomic64_inc(atomic64_t *v);

/**
    \brief 原子自增并返回自增后的值
    \note  适用于windows、linux内核态、linux用户态(不保证原子性)，这里保留支持linux用户态只是为了兼容以前的代码，
    \note  linux用户态有自己的同步方法，因此请尽量不要使用内核态的同步方式。
    \note  无调用上下文限制
    \param[in] v 原子变量指针
    \return    返回增加后的值
*/
OSP_S64 atomic64_inc_return(atomic64_t *v);

/**
    \brief 原子自减
    \note  适用于windows、linux内核态、linux用户态(不保证原子性)，这里保留支持linux用户态只是为了兼容以前的代码，
    \note  linux用户态有自己的同步方法，因此请尽量不要使用内核态的同步方式。
    \note  无调用上下文限制
    \param[in] v 原子变量指针
    \retval    void
*/
void atomic64_dec(atomic64_t *v);


/**
    \brief 原子自减并返回自减后的值
    \note  适用于windows、linux内核态、linux用户态(不保证原子性)，这里保留支持linux用户态只是为了兼容以前的代码，
    \note  linux用户态有自己的同步方法，因此请尽量不要使用内核态的同步方式。
    \note  无调用上下文限制
    \param[in] v 原子变量指针
    \retval    void
*/
OSP_S64 atomic64_dec_return(atomic64_t *v);

/**
    \brief 原子加，但无返回值    
    \note  适用于windows、linux内核态、linux用户态(不保证原子性)，这里保留支持linux用户态只是为了兼容以前的代码，
    \note  linux用户态有自己的同步方法，因此请尽量不要使用内核态的同步方式。
    \note  无调用上下文限制
    \param[in] i 原子变量要增加的值
    \param[in] v 原子变量指针
    \return    无
*/
void atomic64_add(OSP_S64 i, atomic64_t *v);

/**
    \brief 64位原子加法并返回相加后的值
    \note  适用于windows、linux内核态、linux用户态(不保证原子性)，这里保留支持linux用户态只是为了兼容以前的代码，
    \note  linux用户态有自己的同步方法，因此请尽量不要使用内核态的同步方式。
    \note  无调用上下文限制
    \param[in] v ,i
    \retval    OSP_S64
*/

OSP_S64 atomic64_add_return(OSP_S64 i, atomic64_t *v);

/**
    \brief 64位原子减法并返回相减后的值
    \note  适用于windows、linux内核态、linux用户态(不保证原子性)，这里保留支持linux用户态只是为了兼容以前的代码，
    \note  linux用户态有自己的同步方法，因此请尽量不要使用内核态的同步方式。
    \note  无调用上下文限制
    \param[in] v ,i
    \retval    OSP_S64
*/
OSP_S64 atomic64_sub_return(OSP_S64 i, atomic64_t *v);


#elif defined(__KERNEL__)
#include <asm/atomic.h>
#else
#error "platform not specify"
#endif

#endif /* __LVOS_ATOMIC_H__ */

/** @} */

