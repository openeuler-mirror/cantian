/**
 *          Copyright 2011 - 2015, Huawei Tech. Co., Ltd.
 *                      ALL RIGHTS RESERVED
 *
 * dsw_typedef.h

 * @create: 2012-04-16
 *
 */

#ifndef __DSW_TYPEDEF_H__
#define __DSW_TYPEDEF_H__

#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#ifndef UNREFERENCE_PARAM
#define UNREFERENCE_PARAM(para)     ((void)(para))
#endif


#ifndef Coverity_Tainted_Get
#define Coverity_Tainted_Get(p) (p)
#endif

typedef int                 dsw_int;
typedef int                 dsw_bool;
typedef long                dsw_long;

typedef int8_t              dsw_s8;
typedef uint8_t             dsw_u8;
typedef int16_t             dsw_s16;
typedef uint16_t            dsw_u16;
typedef int32_t             dsw_s32;
typedef uint32_t            dsw_u32;
typedef int64_t             dsw_s64;
typedef uint64_t            dsw_u64;
typedef dsw_u64             plog_inner_id_t;
typedef pthread_rwlockattr_t DSW_THREAD_RWLOCKATTR_T;
#define U32_MAX     (0xFFFFFFFFU)
#define DSW_OK              (0)
#define DSW_ERROR           (-1)
#define DSW_TIMEOUT         (-2)
#define DSW_ERROR_EXIST     (-3)
#define DSW_ERROR_CRC       (-4)
#define DSW_TASK_NOT_EXIST  (-5)

#define DSW_ADD_DEVICE_FAIL  (-4)
#define DSW_CONFIRM_AGAIN   (-5)
#define DSW_LLD_IMAGE_FAIL   (-6)
#define DSW_CLI_PRO_NUM_MAX   (-7)
typedef uint8_t az_id_type;
#define DR_META_VOL_RELOAD     (2)
#define DSW_TRUE            (1)
#define DSW_FALSE           (0)
#ifndef EOK
//#define EOK                 (0)
#endif

#define BYTE_PER_KB (1024)
#define BYTE_PER_MB (1048576)
#define MB_PER_GB (1024)

#define DSW_NULL_BYTE       (0XFF)
#define DSW_NULL_WORD       (0XFFFF)
#define DSW_NULL_DWORD      (0XFFFFFFFF)
#define DSW_NULL_QWORD      (0XFFFFFFFFFFFFFFFF)


#define PACKFLAG __attribute__((__packed__))
#define required
#define optional

#define DSW_MEDIA_INDEX_SATA            (0)
#define DSW_MEDIA_INDEX_SSD             (1)
#define DSW_MEDIA_INDEX_NVDIMM             (2)
#define DSW_SSD_CARD_ESN_LEN (64)
#define DSW_SSD_OSD_ESN_LEN (DSW_SSD_CARD_ESN_LEN+3)
/*lint --emacro((718), DSW_OFFSET_OF) --emacro((78), DSW_OFFSET_OF)*/
#define DSW_OFFSET_OF(type, member)   offsetof(type, member)

#define DSW_TYPEOF(x)   typeof((x))

typedef struct
{
    pthread_mutex_t initLock;	
    int inited;
} dsw_multi_auto_init_t;

enum dsw_business_module_callback_type  //business module can set callback type
{
    DSW_CALLBACK_EXIT = 0,

    DSW_CALLBACK_NR
};

typedef void (*pfn_process_exit_cb)(char *errorinfo);

extern void __dsw_assert(dsw_u64 exp, const char *exp_str, const char *file, int line, const char *func);
extern void __dsw_assert_inner(dsw_u64 exp, const char *exp_str, const char *file, int line, const char *func);
/*lint --emacro((506), DSW_ASSERT) --emacro((571), DSW_ASSERT)*/
//#define DSW_ASSERT(x) __dsw_assert((dsw_u64)(x), #x, __FILE__, __LINE__, __FUNCTION__)
#define DSW_ASSERT(x)\
{\
    if (0 == (dsw_u64)(x))\
    {\
        __dsw_assert((dsw_u64)(x), #x, __FILE__, __LINE__, __FUNCTION__);\
    }\
}

//#define DSW_ASSERT_INNER(x) __dsw_assert_inner((dsw_u64)(x), #x, __FILE__, __LINE__, __FUNCTION__)
#define DSW_ASSERT_INNER(x)\
{\
    if (0 == (dsw_u64)(x))\
    {\
        __dsw_assert_inner((dsw_u64)(x), #x, __FILE__, __LINE__, __FUNCTION__);\
    }\
}

/* 字节转换宏 */
#define DSW_KBYTES_TO_BYTES(x)                  ((x)<<10)

#define DSW_MBYTES_TO_BYTES(x)                  ((x)<<20)
#define DSW_MBYTES_TO_KBYTES(x)                 ((x)<<10)

#define DSW_GBYTES_TO_BYTES(x)                  ((x)<<30)
#define DSW_GBYTES_TO_KBYTES(x)                 ((x)<<20)
#define DSW_GBYTES_TO_MBYTES(x)                 ((x)<<10)


#ifdef __RW_DIE_LOCK_RECORD__
extern void  set_rd_pre(const char * func_name);
extern void  set_rd_get(const char * func_name);
extern void  set_wr_pre(const char * func_name);
extern void  set_wr_get(const char * func_name);
void  set_rw_clear(const char * func_name);
extern pthread_rwlock_t* get_test_lock(void);

extern void init_rw_record_head(void);
#endif

#define DSW_THREAD_MUTEX_INIT(mutex, attr)\
do{\
    int inner_retval = pthread_mutex_init((mutex), (attr));\
    if ((0 != inner_retval) && (EBUSY != inner_retval))\
    {\
        DSW_ASSERT_INNER(0);\
    }\
}while(0)

#define DSW_THREAD_MUTEX_LOCK(mutex)\
do{\
    int inner_retval = pthread_mutex_lock((mutex));\
    if ((0 != inner_retval) && (EDEADLK != inner_retval))\
    {\
        DSW_ASSERT_INNER(0);\
    }\
}while(0)

#define DSW_THREAD_MUTEX_UNLOCK(mutex)\
do{\
    int inner_retval = pthread_mutex_unlock((mutex));\
    if ((0 != inner_retval) && (EPERM != inner_retval))\
    {\
        DSW_ASSERT_INNER(0);\
    }\
}while(0)

#define DSW_THREAD_SPIN_INIT(mutex, attr)\
do{\
    int inner_retval = pthread_spin_init((mutex), 0);\
    if ((0 != inner_retval) && (EBUSY != inner_retval))\
    {\
        DSW_ASSERT_INNER(0);\
    }\
}while(0)

#define DSW_THREAD_SPIN_LOCK(mutex)\
do{\
    int inner_retval = pthread_spin_lock((mutex));\
    if ((0 != inner_retval) && (EDEADLK != inner_retval))\
    {\
        DSW_ASSERT_INNER(0);\
    }\
}while(0)

#define DSW_THREAD_SPIN_UNLOCK(mutex)\
do{\
    int inner_retval = pthread_spin_unlock((mutex));\
    if ((0 != inner_retval) && (EPERM != inner_retval))\
    {\
        DSW_ASSERT_INNER(0);\
    }\
}while(0)

#define DSW_THREAD_SPIN_DESTROY(mutex)\
do{\
    int inner_retval = pthread_spin_destroy((mutex));\
    if ((0 != inner_retval) && (EPERM != inner_retval))\
    {\
        DSW_ASSERT_INNER(0);\
    }\
}while(0)

#define DSW_THREAD_RWLOCKATTR_SET_WRITE_PRIORITY(attr)\
do{\
    pthread_rwlockattr_init((attr));\
    pthread_rwlockattr_setkind_np ((attr), PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);\
}while(0)


#ifdef __RW_DIE_LOCK_RECORD__ 
#define DSW_THREAD_RWLOCK_INIT(mutex, attr)\
do{\
    if (get_test_lock() == mutex)    \
        init_rw_record_head();                             \
    int inner_retval = pthread_rwlock_init((mutex), (attr));\
    if ((0 != inner_retval) && (EBUSY != inner_retval))\
    {\
        DSW_ASSERT_INNER(0);\
    }\
}while(0)

#define DSW_THREAD_RWLOCK_RDLOCK(mutex)\
do{\
    if (get_test_lock() == mutex)    \
        set_rd_pre(__FUNCTION__);                             \
    int inner_retval = pthread_rwlock_rdlock((mutex));\
    if ((0 != inner_retval))\
    {\
        DSW_ASSERT_INNER(0);\
    }\
    if (get_test_lock() == mutex)    \
        set_rd_get(__FUNCTION__);                             \
}while(0)

#define DSW_THREAD_RWLOCK_WRLOCK(mutex)\
do{\
    if (get_test_lock() == mutex)    \
        set_wr_pre(__FUNCTION__);                             \
    int inner_retval = pthread_rwlock_wrlock((mutex));\
    if ((0 != inner_retval))\
    {\
        DSW_ASSERT_INNER(0);\
    }\
    if (get_test_lock() == mutex)    \
        set_wr_get(__FUNCTION__);                             \
}while(0)

#define DSW_THREAD_RWLOCK_TRYWRLOCK(mutex) pthread_rwlock_trywrlock(mutex)

#define DSW_THREAD_RWLOCK_UNLOCK(mutex)\
do{\
    int inner_retval = pthread_rwlock_unlock((mutex));\
    if ((0 != inner_retval) && (EPERM != inner_retval))\
    {\
        DSW_ASSERT_INNER(0);\
    }\
    if (get_test_lock() == mutex)    \
        set_rw_clear(__FUNCTION__);                             \
}while(0)

#else

#define DSW_THREAD_RWLOCK_INIT(mutex, attr)\
do{\
    int inner_retval = pthread_rwlock_init((mutex), (attr));\
    if ((0 != inner_retval) && (EBUSY != inner_retval))\
    {\
        DSW_ASSERT_INNER(0);\
    }\
}while(0)

#define DSW_THREAD_RWLOCK_RDLOCK(mutex)\
do{\
    int inner_retval = pthread_rwlock_rdlock((mutex));\
    if ((0 != inner_retval))\
    {\
        DSW_ASSERT_INNER(0);\
    }\
}while(0)

#define DSW_THREAD_RWLOCK_WRLOCK(mutex)\
do{\
    int inner_retval = pthread_rwlock_wrlock((mutex));\
    if ((0 != inner_retval))\
    {\
        DSW_ASSERT_INNER(0);\
    }\
}while(0)

#define DSW_THREAD_RWLOCK_TRYWRLOCK(mutex) pthread_rwlock_trywrlock(mutex)

#define DSW_THREAD_RWLOCK_UNLOCK(mutex)\
do{\
    int inner_retval = pthread_rwlock_unlock((mutex));\
    if ((0 != inner_retval) && (EPERM != inner_retval))\
    {\
        DSW_ASSERT_INNER(0);\
    }\
}while(0)

#endif
#define DSW_THREAD_COND_WAIT(cond_signal,mutex)\
do{\
    int retval = pthread_cond_wait((cond_signal),(mutex));\
    if ((0 != retval) && (EPERM != retval))\
    {\
        DSW_ASSERT_INNER(0);\
    }\
}while(0)

#define DSW_PTHREAD_COND_SINGNAL(cond_signal)  \
do{\
    if(0 != pthread_cond_signal(cond_signal)) \
    {\
        DSW_ASSERT_INNER(0);\
    }\
}while(0)
#ifndef DSW_MAX
#define DSW_MAX(a,b) ((a)>(b)?(a):(b))
#endif

#ifndef DSW_MIN
#define DSW_MIN(a,b) ((a)<(b)?(a):(b))
#endif

enum dsw_init_phase_definition
{
    DSW_INIT_PHASE_0 = 0,
    DSW_INIT_PHASE_1,
    DSW_INIT_PHASE_2,
    DSW_INIT_PHASE_3,
    DSW_INIT_PHASE_4,

    DSW_INIT_PHASE_NR,     //第一阶段启动项
    
    DSW_INIT_PHASE_2PC_0,
    DSW_INIT_PHASE_2PC_NR 
};

enum dsw_init_order_definition
{
    DSW_INIT_FIRST,
    DSW_INIT_SECOND,

    DSW_INIT_ORDER_NR
};

enum dsw_subsys_type_definition
{
    DSW_SUBSYS_MDC = 0x01,
    DSW_SUBSYS_VDB = 0x02,
    DSW_SUBSYS_VBI = 0x04,
};

typedef enum EN_POOL_POLICY
{
    REPLICA_POOL         = 0,
    EC_POOL              = 1,

    MAX_POOL_REDUNDANCY_POLICY
}en_pool_redundancy_policy;


enum dsw_ssd_use
{
    SSD_USED_BY_MAINSTORAGE = 0X00,
    SSD_USED_BY_CACHE       = 0X01,
};

/* interface to agent to require to respawn dsware or not */
enum dsw_agent_init_retcode
{
    INIT_OK_AGENT_RESPAWN = 0,              //初始化成功，进程退出时返回0
    INIT_ERR_AGENT_NOT_RESPAWN = 1,         //初始化失败，不需要拉，且不需要告警，进程退出时返回1
    INIT_ERR_AGENT_RESPAWN = 2,             //初始化失败，需要重新拉起，进程退出时返回2
    INIT_ERR_AGENT_NOT_RESPAWN_SEND_WARN = 3    //初始化失败，不需要拉，且需要告警，进程退出时返回3
};

enum dsw_agent_safe_exit_retcode
{
    SAFE_EXIT_OK_AGENT_RESPAWN = 0,              //进程正常，进程退出时返回0
    SAFE_EXIT_ERR_AGENT_NOT_RESPAWN = 1,         //进程出错，不需要拉，且不需要告警，进程退出时返回1
    SAFE_EXIT_ERR_AGENT_RESPAWN = 2,             //进程出错，需要重新拉起，进程退出时返回2
    SAFE_EXIT_ERR_AGENT_NOT_RESPAWN_SEND_WARN = 3,    //进程出错，不需要拉，且需要告警，进程退出时返回3
    SAFE_EXIT_ERR_AGENT_UNKNOWN = 4              //MDC无法获知自己是否在集群中
};

#define RCV_BUF_LEN (1024*1024)

#ifdef __DFV_VERSION__
#define SECTOR_SIZE                     (4096)         //from config osd.cfg
#else

#ifndef SECTOR_SIZE
//Merge: dfv与ds 6.0不同，暂时以dsware6.0为准
#define SECTOR_SIZE                     (512)
#define SECTOR_SIZE_SHIFT               (9U)
#endif

#endif

#ifndef SECTOR_SHIFT
#define SECTOR_SHIFT                    (dsw_get_g_sector_shift())        //from config osd.cfg
#endif

#define SECTOR_MASK                     (SECTOR_SIZE - 1)     //from config osd.cfg

/* 4K --- 512 */
#define SECTOR_SIZE_4K      (4096)        /* 4k sector size */
#define SECTOR_4K_SHIFT  (12)
#define SECTOR_SIZE_512     (512)        /* 512 sector size */
#define SECTOR_SIZE_520     (520)        /* 512+8 sector size */
#define SECTOR_512_SHIFT  (9)

#define SECTOR_SIZE_PAGE_ALIGN          (4096)
#define BYTE_SIZE                       (8)
#define BYTE_SIZE_SHIFT                 (3)
#define MAX_DISK_NUM                    (24)
#define MAX_SSD_DEV_NUM                 (4)
#define DSW_ESN_LENGTH                  (64)
#define SSD_PCIE_LEN                    (16)
#define SSD_CARD_SECTOR_SIZE            (4096)
#define METADATA_ALIGN_UNIT_ON_BLK_DEV  (1048576)

#define SSD_CARD_SYNC_RW_UNIT_SIZE      (1048576)
#define AIO_RESERVE_SIZE_ON_SSD         (2097152)
#define HDD_SECTOR_SIZE                 (SECTOR_SIZE)
#define ALIGN_HDD_SECTOR(var)           !((var) & (HDD_SECTOR_SIZE - 1))
#define ALIGN_SSD_CARD_SECTOR(var)      !((var) & (SSD_CARD_SECTOR_SIZE - 1))
#define ALIGN_SSD_CARD_BUF_SECTOR(var)  !((var) & (SECTOR_SIZE - 1))
#define ALIGN_ON_METADATA_DEV(var)      !((var) & (METADATA_ALIGN_UNIT_ON_BLK_DEV - 1))

//#define MAX_POOL_NUM                    (128)
#define GLOBAL_META_VOLUME_NUM          (3)
#define MAX_TASK_POOL_NUM               (MAX_POOL_NUM+1)
#define COMM_POOL_IDX                   (MAX_POOL_NUM)
#define MAX_METADATA_TREEID_NUM         (MAX_POOL_NUM + GLOBAL_META_VOLUME_NUM + 1)

#define MAX_DS_CLUSTER_NUM              (128)
#define MAX_CG_NUM_PER_CLUSTER          (1000)
#define PER_VOLUME_VIRTUAL_ATTCH_VBS_NUM (4)

#define INVALID_POOL_ID ((dsw_u16)(-1))
#define DEFAULT_POOL_ID_FOR_UPGRADE 0

#define _FILE_OFFSET_BITS                 (64)
#define HOST_NR_PER_VBS_SHIFT             (5)
#define THREAD_ID_BITS_MASK               (0x7FFFFFFFFFFFFFFULL)

#define TASK_ID_RAND_SHIT        (14)
#define TASK_ID_RAND_MASK       (0xF0003FFFFFFFFFFFULL)
    
#define MAX_OSD_THREAD_NUM                (4)
#define OSD_THREAD_NUM                    get_osd_multi_thread_num()

/* VSC支持的单VBS最大host数，可以预留较大，必须与VSC保持同步 */
#define MAX_HOST_COUNT_PER_VBS            (32)
/* VBS实际支持的最大host数，涉及到内存占用，所以小于等于MAX_HOST_COUNT_PER_VBS */
#define MAX_HOST_NR_PER_VBS               (32)
#define HOST_NR_PER_VBS                   (get_vbs_multi_thread_num())
#define HOST_NR_PER_DGW                 (dgw_get_multi_thread_num())

#define MAX_VBS_DATANET_NUM               (G_ATTRIB_VBS_DATANET_THREAD_MAX)
#define VBS_DATANET_NUM                   (get_vbs_datanet_thread_num())

#define MAX_EPOLL_FD_PER_THREAD           (10)
#define DSW_ERRNO_STR_MAX_LEN             (1024)

#define KVS_DATANET_NUM                   (get_kvs_datanet_thread_num())

#define KVS_IO_DEPTH                          (get_kvs_io_depth())

#define KVS_THREAD                              (get_kvs_multi_thread_num())

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif /* __DSW_TYPEDEF_H__ */
