#ifndef _LVOS_SCHED_WORK_H
#define _LVOS_SCHED_WORK_H

/** \brief 工作队列结构体，封装linux下的struct work_struct，不同于linux原定义，因为有些字段没用到 */
typedef struct tagLVOS_SCHED_WORK_S
{
    OSP_U32 uiPid;
    struct list_head stNode;
    OSP_VOID *pData;                /**< 用户自己保存的数据 */
    void (*pfnWorkHandler)(void *); /**< 工作队列处理函数，参数是整个工作队列结构体指针 */
} LVOS_SCHED_WORK_S;

/** \brief 工作队列项初始化宏 */
#define LVOS_INIT_WORK(work, func, pdata)       \
    do                                          \
    {                                           \
        (work)->uiPid = MY_PID;                 \
        INIT_LIST_NODE(&((work)->stNode));    \
        (work)->pData = pdata;                  \
        (work)->pfnWorkHandler = func;          \
    } while(0)

/** \brief 工作队列调度函数
    \param[in] v_pstWork    工作队列结构体
*/
/*lint -sem(LVOS_SchedWork, custodial(1)) */
void LVOS_SchedWork(LVOS_SCHED_WORK_S *v_pstWork);

/* 初始化该模块，仅供 Linux用户态需要使用该模块的时候单独初始化 */
OSP_S32 LVOS_SchedWorkInit(void);

#endif

