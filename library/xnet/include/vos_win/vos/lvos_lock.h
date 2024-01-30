/******************************************************************************

                  版权所有 (C), 2008-2008, 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : lvos_lock.h
  版 本 号   : 初稿
  
  生成日期   : 2008年6月3日
  最近修改   :
  功能描述   : 定义了信号量、互斥锁、自旋锁等相关内容
  函数列表   :
              LVOS_sema_destroy
              LVOS_sema_down
              LVOS_sema_init
              LVOS_sema_up
  修改历史   :
  1.日    期   : 2008年6月3日
    
    修改内容   : 创建文件

******************************************************************************/
#ifndef __LVOS_LOCK_H__
#define __LVOS_LOCK_H__

#if 0
/**
    \file  lvos_lock.h
    \brief 锁包含自旋锁、互斥锁、信号量

    \date 2008-08-19
*/

/** \addtogroup VOS_SPINLOCK 自旋锁
    注意:  init和destroy必须配套使用，如果不使用则在Windows(仿真)上会存在句柄泄漏\n
    自旋锁以Linux内核为原型封装\n
    自旋锁加锁过程中不能有可能导致线程切换的操作，如休眠，加互斥锁，申请信号量，调用socket函数等
    @{ 
*/
#if DESC("自旋锁")
#if defined(WIN32) || defined(_PCLINT_)

/** \brief 自旋锁类型定义 */
typedef struct
{
    int32_t magic;
    HANDLE hMutex;
} spinlock_t;

typedef spinlock_t rwlock_t;


typedef spinlock_t mcs_spinlock_t;


void spin_lock_init_inner(spinlock_t *v_pLock, OSP_U32 v_uiPid);
/** \brief 初始化自旋锁 */
#define spin_lock_init(v_pLock) spin_lock_init_inner(v_pLock, MY_PID)

/** \brief 自旋锁加锁 */
void spin_lock(spinlock_t *v_pLock);

/** \brief 自旋锁尝试加锁
    \retval TRUE  加锁成功
    \retval FALSE 加锁失败
*/
OSP_S32 spin_trylock(spinlock_t *v_pLock);

/** \brief 自旋锁解锁 */
void spin_unlock(spinlock_t *v_pLock);

void spin_lock_destroy_inner(spinlock_t *v_pLock, OSP_U32 v_uiPid);
/** \brief 销毁自旋锁 */
#define spin_lock_destroy(v_pLock) spin_lock_destroy_inner(v_pLock, MY_PID)

/** \brief 自旋锁加锁，保存中断标志 */
#define spin_lock_irqsave(pLock, flag)   { spin_lock(pLock); (void)(flag); } 

/** \brief 自旋锁加锁，保存中断标志, 返回值同 \ref spin_trylock */
#define spin_trylock_irqsave(pLock, flag)   { spin_trylock(pLock); (void)(flag); } 

/** \brief 自旋锁解锁，恢复中断标志 */
#define spin_unlock_irqrestore(pLock, flag) { spin_unlock(pLock); (void)(flag); }


#define mcs_spin_lock_init          spin_lock_init
#define mcs_spin_lock               spin_lock
#define mcs_spin_unlock             spin_unlock
#define mcs_spin_lock_irqsave       spin_lock_irqsave
#define mcs_spin_unlock_irqrestore  spin_unlock_irqrestore
#define mcs_spin_lock_destroy       spin_lock_destroy



struct rcu_head {
    struct rcu_head *next;
    void (*func)(struct rcu_head *head);
};

/* 仿真下, 使用一个全局锁模拟RCU互斥机制 */
spinlock_t g_rcuLock;

/* 读共享数据加读锁, 仅禁抢占和用于标识访问共享数据的区间, 实际无锁 */
inline void rcu_read_lock(void)
{
    spin_lock(&g_rcuLock);
}

/* 读共享数据解读锁, 仅禁抢占和用于标识访问共享数据的区间, 实际无锁 */
inline void rcu_read_unlock(void)
{
    spin_unlock(&g_rcuLock);
}

/*与rcu_read_lock功能相同, 区别在于使用rcu_read_lock_bh的场景，
  会将软中断结束也作为上下文切换的标识 */
inline void rcu_read_lock_bh(void)
{
    spin_lock(&g_rcuLock);
}

/*与rcu_read_unlock功能相同, 区别在于使用rcu_read_unlock_bh的场景，
  会将软中断结束也作为上下文切换的标识 */
inline void rcu_read_unlock_bh(void)
{
    spin_unlock(&g_rcuLock);
}

/* 写/修改共享数据时加写锁的功能, 仅在仿真使用, 内核中为空 */
inline void rcu_write_lock(void)
{
    spin_lock(&g_rcuLock);
}

/* 写/修改共享数据时解写锁的功能, 仅在仿真使用, 内核中为空 */
inline void rcu_write_unlock(void)
{
    spin_unlock(&g_rcuLock);
}

/* 与rcu_write_lock功能相同, 与rcu_read_lock_bh对应使用 */
inline void rcu_write_lock_bh(void)
{
    spin_lock(&g_rcuLock);
}
/* 与rcu_write_unlock功能相同, 与rcu_read_unlock_bh对应使用 */
inline void rcu_write_unlock_bh(void)
{
    spin_unlock(&g_rcuLock);
}

/*用于注册释放共享资源旧数据内存函数, func函数被调用，
  表示head的引用为0,可直接释放资源, head为结构rcu_head指针 */
#define OS_CallRcu(head, func)        do {(func)(head);} while (0)

/* 与call_rcu功能相同, 与带bh标记的加解锁函数对应使用 */
#define OS_CallRcuBh(head, func)     do {(func)(head);} while (0)



/* 将一个节点加入RCU链表头 */
inline void list_add_rcu(struct list_head *new_node, struct list_head *head)
{
    list_add((new_node), (head));
}

/* 将一个节点加入RCU链表尾 */
inline void list_add_tail_rcu(struct list_head *new_node, 
                              struct list_head *head)
{
    list_add_tail(new_node, head);
}

/* 从一个RCU链表上删除一个节点 */
inline void list_del_rcu(struct list_head *entry)
{
    list_del(entry);
}

/* 替换一个RCU节点 */
inline void list_replace_rcu(struct list_head *old_node,
                             struct list_head *new_node)
{
    new_node->next = old_node->next;
    new_node->prev = old_node->prev;
    new_node->prev->next = new_node;
    new_node->next->prev = new_node;
    INIT_LIST_NODE(old_node);
}

/* 功能同list_entry */
#define list_entry_rcu(ptr, type, member)           \
        list_entry(ptr, type, member)

/* 对ptr的下一个节点做list_entry操作 */
#define list_first_entry_rcu(ptr, type, member)     \
        list_entry_rcu((ptr)->next, type, member)

/* 继续从pos开始遍历RCU链表 */
#define list_for_each_continue_rcu(pos, head)       \
        for ((pos) = (pos)->next; (pos) != (head); (pos) = (pos)->next)



#ifndef BUILD_WITH_ACE
#define rwlock_init  spin_lock_init
#define read_lock    spin_lock
#define read_unlock  spin_unlock
#define write_lock   spin_lock
#define write_unlock spin_unlock
#define read_lock_irqsave       spin_lock_irqsave
#define read_unlock_irqrestore  spin_unlock_irqrestore
#define write_lock_irqsave      spin_lock_irqsave
#define write_unlock_irqrestore spin_unlock_irqrestore
#define rwlock_destroy spin_lock_destroy
#endif

/* 下面两个仅在驱动中使用 */
#define spin_lock_bh    spin_lock
#define spin_unlock_bh  spin_unlock

#elif defined(__LINUX_USR__)
#include <semaphore.h>
#include <pthread.h>

#if defined(__USE_XOPEN2K)
typedef pthread_spinlock_t spinlock_t;
#define spin_lock_init(lock) pthread_spin_init(lock, 0)
#define spin_lock pthread_spin_lock
#define spin_unlock pthread_spin_unlock
#define spin_lock_destroy  pthread_spin_destroy
#else
typedef pthread_mutex_t spinlock_t;
#define spin_lock_init(lock)    pthread_mutex_init(lock, NULL)
#define spin_lock               pthread_mutex_lock
#define spin_unlock             pthread_mutex_unlock
#define spin_lock_destroy       pthread_mutex_destroy
#endif

#define spin_lock_irqsave(pLock, flag)  do { spin_lock(pLock); (void)(flag); } while(0)
#define spin_unlock_irqrestore(pLock, flag) { spin_unlock(pLock); (void)(flag); }
#define spin_lock_bh    spin_lock
#define spin_unlock_bh  spin_unlock


#if defined(__USE_XOPEN2K)
typedef pthread_spinlock_t          mcs_spinlock_t;
#define mcs_spin_lock_init(lock)    pthread_spin_init(lock, 0)
#define mcs_spin_lock               pthread_spin_lock
#define mcs_spin_unlock             pthread_spin_unlock
#define mcs_spin_lock_destroy       pthread_spin_destroy
#else
typedef pthread_mutex_t             mcs_spinlock_t;
#define mcs_spin_lock_init(lock)    pthread_mutex_init(lock, NULL)
#define mcs_spin_lock               pthread_mutex_lock
#define mcs_spin_unlock             pthread_mutex_unlock
#define mcs_spin_lock_destroy       pthread_mutex_destroy
#endif

#define mcs_spin_lock_irqsave(pLock, flag)  do { mcs_spin_lock(pLock); (void)(flag); } while(0)
#define mcs_spin_unlock_irqrestore(pLock, flag) do { mcs_spin_unlock(pLock); (void)(flag); } while(0)


#elif defined(__KERNEL__)
/* 直接使用内核定义的自旋锁 */
#define spin_lock_destroy(pLock)
#define rwlock_destroy(pLock)


/* 内核不存在, 需要屏蔽写锁 */
#define rcu_write_lock(lock)
#define rcu_write_unlock(lock)
#define rcu_write_lock_bh(lock)
#define rcu_write_unlock_bh(lock)



#define mcs_spin_lock_destroy(lock)

#include <linux/irqflags.h>
#include <asm/processor.h>
#include <asm/cmpxchg.h>

typedef struct _mcs_lock_node {
    volatile int waiting;
    struct _mcs_lock_node *volatile next;
}mcs_lock_node;

typedef mcs_lock_node *volatile mcs_lock;

typedef struct {
    mcs_lock slock;
    mcs_lock_node nodes[NR_CPUS];
} mcs_spinlock_t;

/*****************************************************************************
 函 数 名  : mcs_spin_lock_init
 功能描述  : MCS锁初始化
 输入参数  : mcs_spinlock_t *lock
 输出参数  : 无
 返 回 值     : 无
 调用函数  : 无
 被调函数  :  
 
 修改历史      :
  1.日    期   : 2012年1月10
    
    修改内容   : 新生成函数
*****************************************************************************/
static inline void mcs_spin_lock_init (mcs_spinlock_t *lock)
{
    int i;
    
    lock->slock = NULL;
    for (i = 0; i < NR_CPUS; i++) {
        lock->nodes[i].waiting = 0;
        lock->nodes[i].next = NULL;
    }
}
/*****************************************************************************
 函 数 名  : mcs_spin_lock
 功能描述  : MCS锁加锁
 输入参数  : mcs_spinlock_t *lock
 输出参数  : 无
 返 回 值     : 无
 调用函数  : 1) raw_smp_processor_id
                           2) xchg
 被调函数  :  
 
 修改历史      :
  1.日    期   : 2012年1月10
    
    修改内容   : 新生成函数
*****************************************************************************/
static inline void mcs_spin_lock(mcs_spinlock_t *lock)
{
    int cpu;
    mcs_lock_node *me;
    mcs_lock_node *tmp;
    mcs_lock_node *pre;
    
    cpu = raw_smp_processor_id();
    me = &(lock->nodes[cpu]);
    tmp = me;
    me->next = NULL;

    pre = xchg(&lock->slock, tmp);
    if (pre == NULL) {
        /* mcs_lock is free */
        return;
    }

    me->waiting = 1;
    smp_wmb();
    pre->next = me;
    
    while (me->waiting) {
        cpu_relax();
    }   
}
/*****************************************************************************
 函 数 名  : mcs_spin_unlock
 功能描述  : MCS锁解锁
 输入参数  : mcs_spinlock_t *lock
 输出参数  : 无
 返 回 值     : 无
 调用函数  : 1) raw_smp_processor_id
                           2) cmpxchg
 被调函数  :  
 
 修改历史      :
  1.日    期   : 2012年1月10
    
    修改内容   : 新生成函数
*****************************************************************************/
static inline void mcs_spin_unlock(mcs_spinlock_t *lock)
{
    int cpu;
    mcs_lock_node *me;
    mcs_lock_node *tmp;
    
    cpu = raw_smp_processor_id();
    me = &(lock->nodes[cpu]);
    tmp = me;

    if (me->next == NULL) {
        if (cmpxchg(&lock->slock, tmp, NULL) == me) {
            /* mcs_lock I am the last. */
            return;
        }
        while (me->next == NULL)
            continue;
    }

    /* mcs_lock pass to next. */
    me->next->waiting = 0;
}

#define mcs_spin_lock_irqsave(lock, flags) \
    do {                        \
        local_irq_save(flags);  \
        mcs_spin_lock(lock);    \
    } while (0)

#define mcs_spin_unlock_irqrestore(lock, flags) \
    do {                            \
        mcs_spin_unlock(lock);    \
        local_irq_restore(flags);   \
    } while (0)




#endif
#endif /* DESC("自旋锁") */
/** @} */


/** \addtogroup VOS_MUTEX 互斥锁
    注意:  init和destroy必须配套使用，如果不使用则在Windows(仿真)上会存在句柄泄漏
    @{ 
*/
#if DESC("互斥锁")
#if defined(WIN32) || defined(_PCLINT_)

/** \brief 互斥类型定义 */
typedef struct 
{
    HANDLE hMutex;
} LVOS_MUTEX_S;

#elif defined(__LINUX_USR__)
typedef pthread_mutex_t LVOS_MUTEX_S;
#elif defined(__KERNEL__)
typedef struct semaphore LVOS_MUTEX_S;
#endif

#if defined(WIN32) || defined(_PCLINT_) || defined(__KERNEL__)

void LVOS_mutex_init_inner(LVOS_MUTEX_S *v_pMutex, OSP_U32 v_uiPid);
/** \brief 初始化互斥锁 */
#define LVOS_mutex_init(v_pMutex) LVOS_mutex_init_inner(v_pMutex, MY_PID)

/** \brief 互斥锁加锁 */
void LVOS_mutex_lock(LVOS_MUTEX_S *v_pMutex);

/** \brief 互斥锁解锁 */
void LVOS_mutex_unlock(LVOS_MUTEX_S *v_pMutex);

void LVOS_mutex_destroy_inner(LVOS_MUTEX_S *v_pMutex, OSP_U32 v_uiPid);
/** \brief 销毁互斥锁 */
#define LVOS_mutex_destroy(v_pMutex) LVOS_mutex_destroy_inner(v_pMutex, MY_PID)

#else
#define LVOS_mutex_init(v_mutex)     pthread_mutex_init(v_mutex, NULL)
#define LVOS_mutex_lock(v_mutex)     pthread_mutex_lock(v_mutex)
#define LVOS_mutex_unlock(v_mutex)   pthread_mutex_unlock(v_mutex)
#define LVOS_mutex_destroy(v_mutex)  pthread_mutex_destroy(v_mutex)
#endif

#endif /* DESC("互斥锁") */
/** @} */



/** \addtogroup VOS_SEMA 信号量
    注意: 请勿使用信号量做互斥，请使用互斥锁\n
    注意:  init和destroy必须配套使用，如果不使用则在Windows(仿真)上会存在句柄泄漏
    @{ 
*/
#if DESC("信号量")
#if defined(WIN32) || defined(_PCLINT_)

/** \brief 信号量类型定义 */
typedef struct 
{
    HANDLE hHandle;
    atomic_t count;
} LVOS_SEMAPHORE_S;

#elif defined(__LINUX_USR__)
typedef sem_t LVOS_SEMAPHORE_S;
#elif defined(__KERNEL__)
typedef struct semaphore LVOS_SEMAPHORE_S;
#endif

#if defined(WIN32) || defined(_PCLINT_) || defined(__KERNEL__)


void LVOS_sema_init_inner(LVOS_SEMAPHORE_S *v_pSema, OSP_S32 v_iVal, OSP_U32 v_uiPid);
/** \brief 初始化信号量 */
#define LVOS_sema_init(v_pSema, v_iVal) LVOS_sema_init_inner(v_pSema, v_iVal, MY_PID)

/** \brief 信号量down */
void LVOS_sema_down(LVOS_SEMAPHORE_S *v_pSema);

/** \brief 信号量up */
void LVOS_sema_up(LVOS_SEMAPHORE_S *v_pSema);

void LVOS_sema_destroy_inner(LVOS_SEMAPHORE_S *v_pSema, OSP_U32 v_uiPid);
/** \brief 销毁信号量 */
#define LVOS_sema_destroy(v_pSema) LVOS_sema_destroy_inner(v_pSema, MY_PID)

#else
#define LVOS_sema_init(sem, val)    sem_init(sem, 0, val)
#define LVOS_sema_down(sem)\
do{ \
    int _ret = -1;\
    _ret = sem_wait((sem)); \
    while (0 != _ret && EINTR == errno) \
    { \
        _ret = sem_wait((sem));\
    }\
}while(0)
#define LVOS_sema_up(sem)           sem_post(sem)
#define LVOS_sema_destroy(sem)      sem_destroy(sem)
#endif

#endif /* DESC("信号量") */
/** @} */

#endif

#endif


