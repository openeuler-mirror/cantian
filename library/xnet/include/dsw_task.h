/**
 *          Copyright 2011 - 2015, Huawei Tech. Co., Ltd.
 *                      ALL RIGHTS RESERVED
 *
 * dsw_task.h
 *

 * @create: 2012-04-23
 *
 */

#ifndef __DSW_TASK_H__
#define __DSW_TASK_H__

#include <pthread.h>
#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#define DSW_TASK_NAME_BUF_LEN       (32)
#define DSW_TASK_NAME_LEN_MAX       (DSW_TASK_NAME_BUF_LEN - 1)

#define DSW_MODULE_TASK_NUM_MAX     (32) /*vbs多线程拆分后，单mid支持多个线程*/
#define DSW_SYSTEM_TASK_NUM_MAX     (DSW_MID_NR * DSW_MODULE_TASK_NUM_MAX)

#define DSW_TASK_PRIORITY_HIGH      0
#define DSW_TASK_PRIORITY_MIDDLE    1
#define DSW_TASK_PRIORITY_LOW       2
#define DSW_TASK_PRIORITY_DEFAULT   -1

#define DSW_TASK_BIND_CPU_MASK_DEFAULT  0xFFFFFFFFFFFFFFFF

#define DSW_TASK_IN_WAIT            1
#define DSW_TASK_NOT_IN_WAIT        0

typedef enum
{
    DSW_TASK_SUSPENDING,
    DSW_TASK_ACTIVE,
    DSW_TASK_CANCELLED,
    
    DSW_TASK_STATE_COUNT
} dsw_task_run_state_t;

/*
 * Definition of Module Task
 *
 * Each module has at most DSW_MODULE_TASK_NUM_MAX tasks, and each task
 * corresponds to a thread.
 *
 * Creation of thread is completed with call back function supplied by user and
 * the thread of module must wait for the unified start message from DSWare.
 *
 * Data introduced by user at the time of creating thread must be stored in
 * user data collection first, and then be got out in the thread function.
 */
typedef dsw_int (*dsw_task_routine_t) (void *arg);

typedef struct dsw_task_s
{
    dsw_module_t               *module;
    char                        name[DSW_TASK_NAME_BUF_LEN];

    pthread_t                   tid;
    pid_t                       pid;
    dsw_int                     priority;
    dsw_u64                     run_cpu_mask;
    dsw_task_routine_t          routine_func;           /* thread function */
    void                       *arg;                    /* user data */

    pthread_cond_t              cond;
    pthread_mutex_t             mutex;
    volatile dsw_task_run_state_t  task_state;
    dsw_u32                     task_in_wait;   /*DSW_TASK_IN_WAIT表示线程处于等待唤醒状态*/
} dsw_task_t;

// extern dsw_int g_bind_task_to_cpu;
// extern dsw_u64 g_bind_cpu;
DECLARE_OSD_VAR(dsw_u64, g_bind_cpus);
#define g_bind_cpu OSD_VAR(g_bind_cpus)

dsw_int dsw_task_init();
dsw_int dsw_task_register_info(dsw_u8, char *, dsw_int, dsw_u64, dsw_task_routine_t, void *);
dsw_int dsw_task_create(dsw_task_t *);
dsw_int dsw_task_run(dsw_task_t *);
dsw_int dsw_task_cancel(dsw_task_t *);
dsw_int dsw_task_wait_exit(dsw_task_t *);
dsw_int dsw_task_wait_all_exit(int max_wait_seconds);
dsw_int dsw_set_thread_name(char* thread_name);
dsw_int dsw_get_thread_name(char* thread_name);

/*
 * - 在支持进程内多实例的场景下，一个实例退出时，进程并不退出，其它的实例仍需要运行
 *
 * - 而在这个具体的实例退出时，实例中的各个模块的线程都需要退出，并在退出前清理自身的资源
 *   如内存、锁、网络连接、文件等等
 *
 * - 而各个模块的线程退出的时间并非完全同步，从而会引起: A模块线程已退出，已销毁A模块的资源;
 *   但B模块仍未运行完，仍在使用A模块的资源，就会产生资源使用错误的问题。
 *
 * - 因此增加一个同步点，在各模块的线程运行完，销毁资源之前，要等待其它模块的线程都到达此同步
 *   点才能继续执行，进行资源销毁
 *
 * - 模块线程函数示意代码如下:
 *   void module_a_task(void *task)
 *   {
 *       while (shoule_be_running())
 *       {
 *           process_a();
 *       }
 *
 *       XXXX                  <--- synchronize point(同步点)
 *
 *       destroy_resources_a();
 *   }
 *
 * - 具体方法是借鉴 Java 中的 CountDownLatch 的概念，用计数表示当前未执行到同步点的线程数，每个线
 *   程执行到同步点的时候，就将计数器减1，然后在这里等待到计数器归0，再往后面执行销毁资源的操作
 */

/**
 * 初始化本实例的 CountDownLatch
 */
dsw_int dsw_init_count_down_latch(void);

/**
 * 将 CountDownLatch 计数器增加1，表示多了一个模块线程在执行
 */
dsw_int dsw_increase_count_down_latch(void);

/**
 * 将 CountDownLatch 计数器减少1，表示有一个模块线程运行到了同步点
 */
dsw_int dsw_decrease_count_down_latch(void);

/**
 * 等待计数器归0，会阻塞调用线程
 */
void dsw_count_down_latch_wait(void);

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif /* __DSW_TASK_H__ */

