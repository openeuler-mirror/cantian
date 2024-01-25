 /*
 * Copyright Notice:
 *      Copyright  1998-2014, Huawei Technologies Co., Ltd.  ALL Rights Reserved.
*/

#ifndef DPUMM_MM_H
#define DPUMM_MM_H

#include "dpax_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(IN)
#define IN
#endif

#if !defined(OUT)
#define OUT
#endif

#if !defined(INOUT)
#define INOUT
#endif

#ifndef DP_UMM_MEM_NAME_LEN
#define DP_UMM_MEM_NAME_LEN 32
#endif

typedef enum
{
    UMM_MEMTYPE_OS = 0,
    UMM_MEMTYPE_CMM = 1,
    UMM_MEMTYPE_BUTT,

}UMM_MEMTYPE_E;

#ifndef DPUMM_MPOOL_ID_T
#define DPUMM_MPOOL_ID_T
typedef ulong dpumm_mpool_id_t;
#endif

typedef ulong dpumm_numa_map_t;

#ifndef _DPUMM_MPOOL_TYPE_T
#define _DPUMM_MPOOL_TYPE_T
typedef ulong dpumm_mpool_type_t;
#endif

typedef ulong dpumm_partition_type_t;

typedef ulong dpumm_partition_id_t;

s32 dp_mm_pool_init(void);
#define DP_MM_POOL_INIT() dp_mm_pool_init()

s32 dp_mm_pool_exit(void);
#define DP_MM_POOL_EXIT() dp_mm_pool_exit()

dpumm_partition_id_t  dpumm_partition_create(dpumm_partition_type_t  type,
                                             dpumm_numa_map_t numa_map,
                                             ulong max_size,
                                             u8 *part_name);
#define DPUMM_PARTITION_CREATE(type, numa_map, max_size, part_name) \
        dpumm_partition_create(type, numa_map, max_size, part_name)

s32 dpumm_partition_delete(dpumm_partition_id_t partition_id);/*”√ªß”√*/
#define DPUMM_PARTITION_DELETE(part_id) dpumm_partition_delete((part_id))

#define DP_MEMPOOL_ATTR_NONE    0x0UL

#define DP_MEMPOOL_ATTR_MAGIC    0x1UL

#define DP_MEMPOOL_ATTR_DOUBLE_FREE 0x2UL

#define DP_MEMPOOL_ATTR_LOCALCASH 0x4UL

#define DP_MEMPOOL_ATTR_TIMESTAMP 0X10UL

#define DP_MEMPOOL_ATTR_REMAP 0X20UL

#define DP_MEMPOOL_ATTR_EXHAUSTDETECTABLE 0X40UL

#define DP_MEMPOOL_ATTR_LEAKDETECTABLE 0X80UL

#define DP_MEMPOOL_ATTR_NON_IMPORTANT    0x100UL

#define DP_MEMPOOL_ATTR_DESTROY_FORCE  0X200UL

#define DP_MEMPOOL_ATTR_MAX_EFFECTIVE  0X400UL

#define DP_MEMPOOL_ATTR_DEF    (DP_MEMPOOL_ATTR_DOUBLE_FREE)


uint32_t getLocalCacheDefaultNum(void);
uint32_t getLocalCacheDefaultSize(void);

#define DEFAULT_LOCALCACHE_NUM    getLocalCacheDefaultNum()
#define DEFAULT_LOCALCACHE_SIZE   getLocalCacheDefaultSize()

typedef struct tagStruct_mm_mempool_in_para
{
    dpumm_partition_id_t v_partitionid;
    uint64_t v_fixsize;
    u32 v_alignsize;
    ulong v_minnum;
    ulong v_maxnum;
    u32 v_mid;
    dpumm_mpool_type_t v_mem_type;
    u32 v_localCacheNum;
    u32 v_localCacheSize;
    s8 v_name[DP_UMM_MEM_NAME_LEN];
}mm_mempool_in_para_s;

void dpumm_mpool_para_init(mm_mempool_in_para_s *mm_mempool_para);
#define DPUMM_MPOOL_PARA_INIT(mm_mempool_para) \
        dpumm_mpool_para_init(mm_mempool_para)

dpumm_mpool_id_t dpumm_mpool_create(mm_mempool_in_para_s *mm_mempool_para);
#define DPUMM_MPOOL_CREATE(mm_mempool_para) \
        dpumm_mpool_create(mm_mempool_para)

dpumm_mpool_id_t dpumm_mpool_create_with_cache_num(mm_mempool_in_para_s *mm_mempool_para);
#define DPUMM_MPOOL_CREATE_WITH_CACHE_NUM(mm_mempool_para) \
        dpumm_mpool_create_with_cache_num(mm_mempool_para)

s32 dpumm_mpool_delete(const dpumm_mpool_id_t mpool_id);
#define DPUMM_MPOOL_DELETE(pool_id) dpumm_mpool_delete((pool_id))

void* dpumm_mpool_alloc_i(const dpumm_mpool_id_t mpool_id, u32 pid, const char* funcName);

#define dpumm_mpool_alloc(mpool_id, pid) \
                    dpumm_mpool_alloc_i((mpool_id), (pid), __FUNCTION__)
#define DPUMM_MPOOL_ALLOC(mpool_id, pid) \
                    dpumm_mpool_alloc_i((mpool_id), (pid), __FUNCTION__)

void dpumm_mpool_free_i(const dpumm_mpool_id_t mpool_id,void *free_addr, u32 pid, const char* funcName);

#define dpumm_mpool_free(mpool_id, free_addr) \
                    dpumm_mpool_free_i((mpool_id), (free_addr), (MY_PID), __FUNCTION__)
#define DPUMM_MPOOL_FREE(mpool_id, free_addr) \
                    dpumm_mpool_free_i((mpool_id), (free_addr), (MY_PID), __FUNCTION__)

s32 dpumm_memlocalcash_clean(void);
#define DPUMM_MEMLOCALCASH_CLEAN() dpumm_memlocalcash_clean()

s32 dpumm_mpool_mulalloc_i(const dpumm_mpool_id_t mpool_id, void** addrs, s32 num, u32 pid, const char* funcName);

#define dpumm_mpool_mulalloc(mpool_id, addrs, num, pid) \
                    dpumm_mpool_mulalloc_i((mpool_id), (addrs), (num), (pid), __FUNCTION__)
#define DPUMM_MPOOL_MULALLOC(mpool_id, addrs, num, pid) \
                    dpumm_mpool_mulalloc_i((mpool_id), (addrs), (num), (pid), __FUNCTION__)

void dpumm_mpool_mulfree_i(const dpumm_mpool_id_t mpool_id, void** addrs, s32 num, u32 pid, const char* funcName);

#define dpumm_mpool_mulfree(mpool_id, addrs, num) \
                    dpumm_mpool_mulfree_i((mpool_id), (addrs), (num), (MY_PID), __FUNCTION__)
#define DPUMM_MPOOL_MULFREE(mpool_id, addrs, num) \
                    dpumm_mpool_mulfree_i((mpool_id), (addrs), (num), (MY_PID), __FUNCTION__)

dpumm_partition_id_t get_default_partition(void);
#define GET_DEFAULT_PARTITION() \
        get_default_partition()

void * pub_mpool_alloc_i(u32 size, u32 pid, const char* funcName);
#define pub_mpool_alloc(size, pid) \
                    pub_mpool_alloc_i((size), (pid), __FUNCTION__)
#define PUB_MPOOL_ALLOC(size, pid) \
                    pub_mpool_alloc_i((size), (pid), __FUNCTION__)

void pub_mpool_free_i (void *ptr, u32 pid, const char* funcName);

#define pub_mpool_free(ptr) \
                    pub_mpool_free_i((ptr), (MY_PID), __FUNCTION__)
#define PUB_MPOOL_FREE(ptr) \
                    pub_mpool_free_i((ptr), (MY_PID), __FUNCTION__)

ulong ucmm_mpool_create(ulong v_partitionid,
                                ulong v_fixsize,
                                ulong v_alignsize,
                                ulong v_minnum,
                                ulong v_maxnum,
                                u32 v_mid,
                                u8 *v_name);

void* ucmm_mpool_alloc_i(const dpumm_mpool_id_t mpool_id, u32 pid, const char* funcName);

#define ucmm_mpool_alloc(mpool_id, pid) \
                    ucmm_mpool_alloc_i((mpool_id), (pid), (__FUNCTION__))
#define UCMM_MPOOL_ALLOC(mpool_id, pid) \
                    ucmm_mpool_alloc_i((mpool_id), (pid), (__FUNCTION__))

ulong mmGetObjectSum(dpumm_mpool_id_t pool_id);
#define MM_GET_OBJECT_NUM(mempoolId) \
    mmGetObjectSum(mempoolId)

ulong mmGetBusyObjectSum(dpumm_mpool_id_t pool_id);
#define MM_GET_BUSY_OBJECT_NUM(mempoolId) \
    mmGetBusyObjectSum(mempoolId)

s32 dpumm_set_config_path (char *path, const char* funcName, const u32 line);
#define DPUMM_SET_CONFIG_PATH(path) dpumm_set_config_path((path),__FUNCTION__,__LINE__)

int32_t get_mpool_alloc_info(dpumm_mpool_id_t mpool_id, uint32_t *total_cnt, uint32_t *alloc_cnt);

int32_t createStackPartition(char       *part_name,
                         uint64_t   stack_size,
                         uint64_t   read_only_size,
                         uint64_t   stack_count,
                         uint32_t   owner_modid,
                         uint32_t   part_attr,
                         uint32_t   *part_id,
                         char       **stack_space_start_addr);

s32 createStackPartitionByNuma(char    *v_part_name,
                                             u32     numa_id,     
                                             ulong   v_stack_size,
                                             ulong   v_read_only_size,
                                             ulong   v_stack_count,
                                             u32     v_owner_modid,
                                             u32     v_part_attr,
                                             u32     *v_part_id,
                                             char    **v_stack_space_start_addr);

s32 destoryStackPartition(u32 part_id, u32 owner_modid, const char* func_name);

#ifdef __cplusplus
}
#endif

#endif
