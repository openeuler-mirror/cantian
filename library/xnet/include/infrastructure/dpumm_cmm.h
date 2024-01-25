#ifndef _DPUMM_CMM_H
#define _DPUMM_CMM_H

#include "req_sgl.h"
#include "dpumm_mm.h"
#include "infrastructure_init.h"

#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

#define CMM_MEM_PARTITION_NAME_LEN 31


typedef enum tagPAGE_TYPE
{
    PAGE_TYPE_CRITICAL  = 0,
    PAGE_TYPE_NORMAL  = 1,
    PAGE_TYPE_BUTT
}PAGE_TYPE_E;

/* brief 分区属性控制 */
#define PART_ATTR_NONE              0x0
#define PART_ATTR_RECOVERABLE       0x1
#define PART_ATTR_LEAKDETECTABLE    0x2
#define PART_ATTR_EXHAUSTDETECTABLE 0x4
#define PART_ATTR_CRITICALRESOURCE  0x8
#define PART_ATTR_LOCALCACHE        0X10
#define PART_ATTR_NON_IMPORTANT     0x20
#define PART_ATTR_MAX_EFFECTIVE     0X40

#define ALLOCT_CONTEXT_BASE 1

typedef enum tagALLOC_CONTEXT_TYPE_E
{
    THREAD_ONLY = ALLOCT_CONTEXT_BASE,
    SOFT_INTERRUPT_ONLY,
    HARD_INTERRUPT_ONLY,
    BOTH_THREAD_AND_SOFT_INTERRUPT,
    BOTH_THREAD_AND_HARD_INTERRUPT,
    BOTH_SOFT_AND_HARD_INTERRUPT,
    ALL_CONTEXT,

    ALLOC_CONTEXT_BUTT
}ALLOC_CONTEXT_TYPE_E;

typedef struct tagSTRUCTURE_POOL_CREATE_PARA_S
{
    uint64_t   magic;
    uint32_t   cntLow;
    uint32_t   cntHigh;
    char*      partitionName;
    uint32_t   ownerModuleID;
    uint32_t   partAttr;
    uint32_t   objSize;
    uint32_t   localCacheNum;
    uint32_t   localCacheSize;
    void (*initFunc)(void*);
    void (*destroyFunc)(void*);
    ALLOC_CONTEXT_TYPE_E contextType;
}STRUCTURE_POOL_CREATE_PARA_S;

int32_t cmm_module_init(void);

int32_t cmm_module_init_ext(infra_cmm_param_t *cmm_param);

int32_t cmm_module_exit(void);
#define CMM_MODULE_EXIT()  cmm_module_exit()

int32_t  createStructurePartition(uint32_t   structureCnt,
                                  char*      partitionName,
                                  uint32_t   ownerModuleID,
                                  uint32_t   partAttr,
                                  uint32_t   objSize,
                                  uint32_t * partitionID,
                                  void (*initFunc)(void*),
                                  void (*destroyFunc)(void*),
                                  ALLOC_CONTEXT_TYPE_E allocContextType,
                                  uint32_t   ftdsSize);

#define CREATE_STRUCTURE_PARTITION(structurCnt, \
                                   partitionName, ownerModuleID, partAttr, objSize, partitionID, allocContextType) \
    createStructurePartition((structurCnt), \
                             (partitionName), \
                             (ownerModuleID), \
                             (partAttr), \
                             (objSize), \
                             (partitionID), \
                              NULL, NULL, allocContextType,0)

#define CREATE_STRUCTURE_PARTITION_WITH_FN(structureCnt, \
                                           partitionName, ownerModuleID, partAttr, objSize, partitionID, \
                                           initFunc, destroyFunc, allocContextType) \
    createStructurePartition((structureCnt), \
                             (partitionName), \
                             (ownerModuleID), \
                             (partAttr), \
                             (objSize), \
                             (partitionID), \
                             (initFunc), \
                             (destroyFunc), \
                             (allocContextType),0)

int32_t  createExpStructurePartition(uint32_t   structureCntLow,
                                     uint32_t   structureCntHigh,
                                     char*      partitionName,
                                     uint32_t   ownerModuleID,
                                     uint32_t   partAttr,
                                     uint32_t   objSize,
                                     uint32_t * partitionID,
                                     void (*initFunc)(void*),
                                     void (*destroyFunc)(void*),
                                     ALLOC_CONTEXT_TYPE_E allocContextType);

#define CREATE_EXPANDABLE_STRUCTURE_PARTITION(structurCntLow, structurCntHigh, \
                                              partitionName, ownerModuleID, partAttr, \
                                              objSize, partitionID, allocContextType) \
    createExpStructurePartition((structurCntLow),                       \
                                (structurCntHigh),                      \
                                (partitionName),                        \
                                (ownerModuleID),                        \
                                (partAttr),                             \
                                (objSize),                              \
                                (partitionID),                          \
                                NULL, NULL,                             \
                                (allocContextType))

int32_t  createContinuousPartition(uint64_t   partitionSizeInBytes,
                                   char*      partitionName,
                                   uint32_t   ownerModuleID,
                                   uint32_t   partAttr,
                                   uint32_t *partitionID,
                                   char**     partitionStartAddress,
                                   const char* funcName);
#define CREATE_CONTINUOUS_PARTITION(partitionSizeInBytes, partitionName, \
                                    ownerModuleID, partAttr, partitionId, partitionStartAddr) \
    createContinuousPartition((partitionSizeInBytes), \
                              (partitionName), \
                              (ownerModuleID), \
                              (partAttr), \
                              (partitionId), \
                              (partitionStartAddr),\
                              __FUNCTION__)

void initStructureMempoolPara(STRUCTURE_POOL_CREATE_PARA_S *createPara);
#define INIT_STRUCTURE_POOL_PARA(poolCreatePara)  initStructureMempoolPara((poolCreatePara))

int32_t createStructureMempool(STRUCTURE_POOL_CREATE_PARA_S *createPara, uint32_t *partitionID);
#define  CREATE_STRUCTURE_MEMPOOL(createPara,  partitionID)  createStructureMempool ((createPara),  (partitionID))

int32_t setPartitionLeakTimeout(uint32_t partitionId, uint32_t leakTimeout);
#define SET_PARTITION_LEAK_TIMEOUT(partitionId, leakTimeout) \
    setPartitionLeakTimeout((partitionId), (leakTimeout))

void    deletePartitionByID(uint32_t partitionID);
#define DELETE_MEMORY_PARTITION(partitionID) deletePartitionByID((partitionID))

int32_t deleteStructurePartition(uint32_t partitionID);
#define DELETE_STRUCTURE_PARTITION(partitionID) deleteStructurePartition((partitionID))

void    allocStructure(uint32_t pid, uint32_t partitionID, void **  outstructurePtr, const char* funcName, const int32_t fileLine);
#define ALLOCATE_STRUCTURE(pid, partitionID, outStructurePtr) \
    allocStructure((pid), (partitionID), (outStructurePtr), __FUNCTION__, __LINE__)

void    freeStructure(void *structurePtr, uint32_t partitionID, uint32_t pid, const char* funcName, const int32_t fileLine);
#define FREE_STRUCTURE(structurePtr, partitionID) \
    freeStructure((structurePtr), (partitionID), (MY_PID), __FUNCTION__, __LINE__)

int32_t findStructurePartitionByAddr(void * addr, uint32_t * part_id);

uint32_t getObjectSum(uint32_t partitionID);
#define GET_OBJECT_NUM(partitionID) getObjectSum((partitionID))

uint32_t getBusyObjectSum(uint32_t partitionID);
#define GET_BUSY_OBJECT_NUM(partitionID) getBusyObjectSum((partitionID))

int32_t getPartitionAllocInfo(uint32_t partId, uint32_t *totalCnt, uint32_t *allocCnt);
#define GET_PARTITION_ALLOC_INFO(partId, totalCnt, allocCnt) \
    getPartitionAllocInfo((partId), (totalCnt), (allocCnt))

int32_t allocStructureFromPubPool(uint32_t structSize, void** outStructPtr, const char* funcName, const int32_t fileLine, uint32_t owner_modid);
#define ALLOCATE_PUB_STRUCTURE(structureSize, outStructurePtr) \
    allocStructureFromPubPool((structureSize), (outStructurePtr), __FUNCTION__, __LINE__, (MY_PID))

void freeStructureToPubPool(void * objPtr, uint32_t pid, const char* funcName, const int32_t fileLine);
#define FREE_PUB_STRUCTURE(objPtr) freeStructureToPubPool((objPtr), (MY_PID), __FUNCTION__, __LINE__)

void  allocReq(REQ_S **req, uint32_t moduleID, const char* funcName, const int32_t fileLine);
#define ALLOCATE_REQ(reqOutPtr) \
    allocReq((reqOutPtr), (MY_PID), __FUNCTION__, __LINE__)

void allocReqByNuma(REQ_S **req, uint32_t numa_mask, uint32_t moduleID, const char* funcName, const int32_t fileLine);
#define ALLOCATE_REQ_BY_NUMA(reqOutPtr, numa_mask) \
    allocReqByNuma((reqOutPtr), numa_mask, (MY_PID), __FUNCTION__, __LINE__)

void  freeReq(REQ_S* req, uint32_t pid, const char* funcName, const int32_t fileLine);
#define FREE_REQ(reqPtr) \
    freeReq((reqPtr), (MY_PID), __FUNCTION__, __LINE__)

void allocReqWithoutInit(REQ_S **req, uint32_t moduleID, const char* funcName, const int32_t fileLine);
#define ALLOCATE_REQ_WITHOUT_INIT(reqOutPtr) \
    allocReqWithoutInit((reqOutPtr), (MY_PID), __FUNCTION__, __LINE__)

void printReqInfo(REQ_S * req);
#define PRINT_REQ_INFO(req) printReqInfo(req)

void  allocOneSgl(SGL_S **sgl, uint32_t moduleID, const char* funcName, const int32_t fileLine);
#define ALLOCATE_SGL(sglOutPtr) \
        allocOneSgl((sglOutPtr), (MY_PID), __FUNCTION__, __LINE__)

void  allocSglChain(SGL_S** sglChain, uint32_t pageCnt, uint32_t moduleID, const char* funcName, const int32_t fileLine);
#define ALLOCATE_SGL_CHAIN(sglChainOutPtr, pageCnt) \
    allocSglChain((sglChainOutPtr), (pageCnt), (MY_PID), __FUNCTION__, __LINE__)

#define ALLOCATE_SGL_CHAIN_WITH_PID(sglChainOutPtr, pageCnt, pid) \
    allocSglChain((sglChainOutPtr), (pageCnt), (pid), __FUNCTION__, __LINE__)

void  freeSglChain(SGL_S* sglChain, uint32_t pid, const char* funcName, const int32_t fileLine);
#define FREE_SGL_CHAIN(sglChainPtr) \
    freeSglChain((sglChainPtr), (MY_PID), __FUNCTION__, __LINE__)

int32_t cloneSglChain(SGL_S *sgl_src, SGL_S **sgl_dst);

void freeCloneSgl(SGL_S *sgl_src);

void cloneSgl(SGL_S *checkSgl, uint64_t sglSerialNo, SGL_S** sglPtrNew,
                    uint32_t owner_modid, const char*  owner_func, const int32_t fileLine);
#define CLONE_SGL(sglPtr, sglSerialNo, sglPtrNew) \
              cloneSgl((sglPtr), (sglSerialNo), (sglPtrNew), (MY_PID), __FUNCTION__, __LINE__)

#define GET_SGL_BY_OFFSET(sglPtr, offseByte, outSgl, pEntry, pBufOffset) \
              getCurrentSglByOffset((sglPtr), (offseByte), (outSgl), (pEntry), (pBufOffset))

#define COPY_DATA_FROM_BUF_TO_SGL(dstSgl, offseByte, buffer, dataLength) \
              copyDataFromBufferToSgl((dstSgl), (offseByte), (buffer), (dataLength))

#define COPY_DATA_FROM_SGL_TO_BUF(srcSgl, offseByte, buffer, dataLength) \
              copyDataFromSglToBuffer((srcSgl), (offseByte), (buffer), (dataLength))

void allocMultiPagesSync(uint32_t page_cnt,
                    SGL_S **sgl_ptr,
                    uint32_t owner_modid,
                    const char *owner_func,
                    const int32_t owner_file_line);
#define ALLOCATE_MULTI_PAGES_SYNC(pageCnt, sglOutPtr, moduleID, funcName, fileLine) \
            allocMultiPagesSync((pageCnt), (sglOutPtr), moduleID, funcName, fileLine)

void freeMultiPages(SGL_S      *sgl,
                uint32_t   owner_modid,
                const char *owner_func,
                const int32_t owner_file_line);
#define FREE_MULTI_PAGES(sglContainPages, funcName, fileLine) \
            freeMultiPages((sglContainPages),(MY_PID), (funcName), (fileLine))

void *allocOnePageSync(uint32_t owner_modid,
                    const char * owner_func,
                    const int32_t owner_file_line);
#define ALLOCATE_ONE_PAGE_SYNC(moduleID, funcName, fileLine) \
            allocOnePageSync((moduleID), (funcName), (fileLine))

void freeOnePage(void *_page_ctrl,
               uint32_t owner_modid,
               const char *owner_func,
               const int32_t owner_file_line);
#define FREE_ONE_PAGE(pageCtrl, funcName, fileLine) \
            freeOnePage((pageCtrl), (MY_PID), (funcName), (fileLine))

void syncAllocMultiPagesForPagePool(uint32_t pageCnt,
                             SGL_S **sgl,
                             uint32_t pageUsage,
                             uint32_t moduleID,
                             const char* funcName,
                             const int32_t fileLine);

#define PAGEPOOL_SYNC_ALLOCATE_MULTI_PAGES(pageCnt, sglOutPtr, pageUsage, moduleID, funcName, fileLine) \
    syncAllocMultiPagesForPagePool((pageCnt), (sglOutPtr), (pageUsage), moduleID, funcName, fileLine)

void syncAllocMultiPagesForPagePoolByNuma(uint32_t pageCnt,
                             SGL_S **sgl,
                             uint32_t pageUsage,
                             uint32_t numaMask,
                             uint32_t moduleID,
                             const char* funcName,
                             const int32_t fileLine);

#define PAGEPOOL_SYNC_ALLOCATE_MULTI_PAGES_BY_NUMA(pageCnt, sglOutPtr, pageUsage, numaMask, moduleID, funcName, fileLine) \
    syncAllocMultiPagesForPagePoolByNuma((pageCnt), (sglOutPtr), (pageUsage),(numaMask), moduleID, funcName, fileLine)

void* syncAllocOnePageForPagePoolByNuma(
                                uint32_t page_usage,
                                uint32_t numa_mask,
                                uint32_t owner_modid,
                                const char *owner_func,
                                const int32_t owner_file_line);
#define PAGEPOOL_SYNC_ALLOCATE_ONE_PAGE_BY_NUMA(pageUsage, numaMask, moduleID, funcName, fileLine) \
    syncAllocOnePageForPagePoolByNuma((pageUsage), (numaMask), (moduleID), (funcName), (fileLine))

void  freeMultiPagesForPagePool(SGL_S * sgl, const char* funcName, const int32_t fileLine);
#define PAGEPOOL_FREE_MULTI_PAGES(sglContainPages, funcName, fileLine) \
    freeMultiPagesForPagePool((sglContainPages),(funcName), (fileLine))

void    allocMultiPagesForPagePool(
                                   uint32_t     pageCnt,
                                   uint32_t     pageUsage,
                                   void         (*cbFunc)(SGL_S *sgl, void *cbArg),
                                   void          *cbCtx,
                                   void         (*cbFailure)(void *cbArg),
                                   void          *cbFailureCtx,
                                   uint32_t       moduleID,
                                   const char    *funcName,
                                   const int32_t  fileLine);

#define PAGEPOOL_ALLOCATE_MULTI_PAGES(pageCnt, pageUsage, callbackFunc, cbCtx, failcallbackFunc, failcbCtx, moduleID, funcName, fileLine) \
            allocMultiPagesForPagePool((pageCnt), (pageUsage), (callbackFunc), (cbCtx), (failcallbackFunc), (failcbCtx), (moduleID), (funcName), (fileLine))

void    allocOnePageForPagePool(
                                uint32_t        pageUsage,
                                void          (*cbFunc)(void *pageCtrl, void *cbArg),
                                void           *cbCtx,
                                void          (*cbFailure)(void *cbArg),
                                void           *cbFailureCtx,
                                uint32_t        moduleID,
                                const char     *funcName,
                                const int32_t   fileLine);

#define PAGEPOOL_ALLOCATE_ONE_PAGE(pageUsage, cbFunc, cbCtx, failcallbackFunc, failcbCtx, moduleID, funcName, fileLine) \
    allocOnePageForPagePool((pageUsage), (cbFunc), (cbCtx), (failcallbackFunc), (failcbCtx), (moduleID), (funcName), (fileLine))

void    freeOnePageForPagePool(void *pageCtrl, const char* funcName, const int32_t fileLine);
#define PAGEPOOL_FREE_ONE_PAGE(pageCtrl, funcName, fileLine) \
    freeOnePageForPagePool((pageCtrl), (funcName), (fileLine))

void* syncAllocOnePageForPagePool(
                                uint32_t page_usage,
                                uint32_t owner_modid,
                                const char *owner_func,
                                const int32_t owner_file_line);
#define PAGEPOOL_SYNC_ALLOCATE_ONE_PAGE(pageUsage, moduleID, funcName, fileLine) \
    syncAllocOnePageForPagePool((pageUsage), (moduleID), (funcName), (fileLine))

void allocOnePageForPagePoolTimeOut(
    uint32_t pageUsage,
    uint32_t timeOut,
    void(*cbFunc)(void * pageCtrl, void * cbArg, int32_t result),
    void * cbCtx,
    void(*failcallbackFunc)(void * cbArg),
    void * failcbCtx,
    uint32_t moduleID,
    const char * funcName,
    const int32_t fileLine);

#define PAGEPOOL_ALLOCATE_ONE_PAGE_TIMEOUT(pageUsage, timeOut, cbFunc, cbCtx, failcallbackFunc, failcbCtx, moduleID, funcName, fileLine) \
    allocOnePageForPagePoolTimeOut((pageUsage), (timeOut), (cbFunc), (cbCtx), (failcallbackFunc), (failcbCtx), (moduleID), (funcName), (fileLine))

void allocMultiPagesForPagePoolTimeOut(
    uint32_t pageCnt,
    uint32_t pageUsage,
    uint32_t timeOut,
    void(*cbFunc)(SGL_S *sgl, void *cbArg, int32_t result),
    void * cbCtx,
    void(*failcallbackFunc)(void * cbArg),
    void * failcbCtx,
    uint32_t moduleID,
    const char * funcName,
    const int32_t fileLine);

#define PAGEPOOL_ALLOCATE_MULTI_PAGES_TIMEOUT(pageCnt, pageUsage, timeOut, callbackFunc, cbCtx, failcallbackFunc, failcbCtx, moduleID, funcName, fileLine) \
    allocMultiPagesForPagePoolTimeOut((pageCnt), (pageUsage), (timeOut), (callbackFunc), (cbCtx), (failcallbackFunc), (failcbCtx), (moduleID), (funcName), (fileLine))

void allocMultiPagesForPagePoolTimeOutByNuma(
    uint32_t pageCnt,
    uint32_t pageUsage,
    uint32_t timeOut,
    uint32_t numaMask,
    void(*cbFunc)(SGL_S *sgl, void *cbArg, int32_t result),
    void * cbCtx,
    void(*failcallbackFunc)(void * cbArg),
    void * failcbCtx,
    uint32_t moduleID,
    const char * funcName,
    const int32_t fileLine);

#define PAGEPOOL_ALLOC_MULTI_PAGES_TIMEOUT_BY_NUMA(pageCnt, pageUsage, timeOut, numaMask,callbackFunc, cbCtx, failcallbackFunc, failcbCtx, moduleID, funcName, fileLine) \
    allocMultiPagesForPagePoolTimeOutByNuma((pageCnt), (pageUsage), (timeOut), (numaMask),(callbackFunc), (cbCtx), (failcallbackFunc), (failcbCtx), (moduleID), (funcName), (fileLine))

int32_t incAndRetPageReference(void *_page_ctrl,
                           const char *owner_func,
                           const int32_t owner_file_line);
#define INC_AND_RET_PAGE_REFERENCE(pageCtrl, funcName, fileLine) \
    incAndRetPageReference((pageCtrl), (funcName), (fileLine))

int32_t decAndRetPageReference(void *_page_ctrl,
                               uint32_t owner_modid,
                               const char *owner_func,
                               const int32_t owner_file_line);
#define DEC_AND_RET_PAGE_REFERENCE(pageCtrl, funcName, fileLine) \
    decAndRetPageReference((pageCtrl), (MY_PID), (funcName), (fileLine))

int32_t getPageReference(void *_page_ctrl,
                      const char *owner_func,
                      const int32_t owner_file_line);
#define GET_PAGE_REFERENCE(pageCtrl, funcName, fileLine) \
    getPageReference((pageCtrl), (funcName), (fileLine))

char *getPageAddrByPageCtrl(void *page_ctrl);
#define GET_PAGE_ADDR(pageCtrl)  getPageAddrByPageCtrl((pageCtrl))

void getPageZeroFlags(void *page_ctrl, bool *is_zero);
#define GET_PAGE_ZERO_FLAGS(pageCtrl, isZeroPage) \
        getPageZeroFlags((pageCtrl), (isZeroPage))

OSP_BOOL getPageZeroFlagsByAddr(void *addr);
#define GET_PAGE_ZERO_FLAGS_BY_ADDR(addr) \
        getPageZeroFlagsByAddr((addr))

void* getZeroPageCtrlWithoutDif(void);
#define GET_ZERO_PAGE_CTRL_WITHOUT_DIF()\
        getZeroPageCtrlWithoutDif()

void* getZeroPageCtrl(void);
#define GET_ZERO_PAGE_CTRL()\
        getZeroPageCtrl()

void setPageZeroFlags(void *page_ctrl, bool is_zero);
#define SET_PAGE_ZERO_FLAGS(pageCtrl, isZeroFlags) \
    setPageZeroFlags((pageCtrl), (isZeroFlags));

typedef enum
{
    DPUMM_EVICT_ASYNC = 0,
    DPUMM_EVICT_TYPE_BUTT
} DPUMM_EVICT_TYPE;

typedef int32_t (*dpummPageEvictHandler)(void *ctx);
int32_t dpumm_page_evict_handler_reg(
    DPUMM_EVICT_TYPE type,
    dpummPageEvictHandler handler,
    void *ctx,
    uint32_t module_id,
    const char *owner_func);
#define DPUMM_PAGE_EVICT_HANDLER_REG(type, handler, ctx, module_id) \
    dpumm_page_evict_handler_reg(type, handler, ctx, module_id, __FUNCTION__)

typedef uint64_t dpumm_pool_id_t;

int32_t dpumm_sgl_slab_create(dpumm_pool_id_t pool_id, uint32_t module_id, const char *owner_func);

int32_t dpumm_sgl_get_usage_info(uint64_t* busy_number, uint64_t* total_number);

int32_t dpumm_sgl_get_usage_by_numa(uint32_t numa_id, uint64_t* busy_number);

int32_t dpumm_page_slab_create(dpumm_pool_id_t pool_id, uint32_t module_id, const char *owner_func);

int32_t dpumm_page_get_usage_info(uint64_t* busy_number, uint64_t* total_number);

int32_t dpumm_page_get_numaid(void *page_ctrl);

int32_t dpumm_page_get_usage_by_numa(uint32_t numa_id, uint64_t* busy_number);

void updateSglPageOwner(SGL_S *sgl, void *page_ctrl, uint32_t owner_modid, const char *owner_func);

void updateSglAndPagesOwner(SGL_S *sgl, uint32_t owner_modid, const char *owner_func);

int32_t incPageReferenceBySgl(SGL_S *sgl, uint32_t owner_modid, const char *owner_func);

int32_t decPageReferenceBySgl(SGL_S *sgl, uint32_t owner_modid, const char *owner_func);

int32_t pagepool_get_info(void **start_address, uint64_t *length, uint32_t numa_node_number);

typedef uint64_t dpumm_page_pool_key_t;
typedef uint64_t dpumm_page_pool_id_t;

#define PAGE_ATTR_MAX_EFFECTIVE    0x0001
#define PAGE_ATTR_DELAY_RECLAIM    0x0002
#define PAGE_ATTR_EXHAUST_NOT_HEAL 0x0004

typedef struct
{
    char name[DP_UMM_MEM_NAME_LEN];
    dpumm_page_pool_key_t key;
    uint32_t magic;
    uint32_t module_id;
    uint64_t attribute;
    uint64_t min_number;
    uint64_t max_number;
    uint64_t numa_node_mask;
} dpumm_page_pool_param_t;

int32_t dpumm_page_pool_para_init(dpumm_page_pool_param_t *page_pool_para);

dpumm_page_pool_id_t  dpumm_page_pool_create(dpumm_page_pool_param_t *create_para,
                                            uint32_t module_id,
                                            const char* function_name);

void *dpumm_page_alloc(dpumm_page_pool_id_t  pool_id, 
                            uint32_t numa_mask,
                            uint32_t time_out,
                            uint32_t owner_modid,
                            const char * owner_func,
                            const int32_t owner_file_line);

void dpumm_page_multi_alloc(dpumm_page_pool_id_t  pool_id,
                                uint32_t page_cnt,
                                SGL_S **sgl_ptr,
                                uint32_t numa_mask,
                                uint32_t time_out,
                                uint32_t owner_modid,
                                const char *owner_func,
                                const int32_t owner_file_line);

int32_t rdmapool_get_info(uint32_t numa_id, void **start_address, uint64_t *size);

void* dsw_buffer_malloc(uint64_t size, uint32_t module_id, const char* function_name);

int32_t dsw_buffer_free(void *object, uint32_t module_id, const char* function_name);

int32_t dpshm_buffer_to_sgl(void *buffer, int64_t length, int64_t offset, SGL_S **sgl);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif   //_DPUMM_CMM_H
