/**
 *          Copyright 2011 - 2015, Huawei Tech. Co., Ltd.
 *                      ALL RIGHTS RESERVED
 *
 * dsw_module.h

 * @create: 2012-04-16
 *
 */


#ifndef __DSW_MODULE_H__
#define __DSW_MODULE_H__

#include "dsw_multi_instance.h"
#include "dsw_attrib.h"
#include "dsw_task.h"
#include "dsw_id.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#define DSW_MODULE_NAME_BUF_LEN     (32)
#define DSW_MODULE_NAME_LEN_MAX     (DSW_MODULE_NAME_BUF_LEN - 1)

#define DSW_PROCESS_HIGHEST_PRI      (-20)

#define DSW_MODULE_MAX_THR_NUMS     (16)
#define DSW_MODULE_PATH_MODULE_CNT  (2)

#ifndef INVALID_IP
#define INVALID_IP ((dsw_u32)DSW_ERROR)
#endif
/*
 * Module Static Configuration Table
 *
 * Each subsystem, that is a node, should provide a module static configuration
 * table to list the static configuration information of module table that is
 * started in this subsystem.
 *
 * Module root function is provided by user and is mainly used to register
 * module-related callback function. Meanwhile, it could be used for some
 * necessary initialization operation (Notice: basic initialization operation
 * should be done by phase-seperated initialization function of each module.
 *
 * Module static configuration table is the description table of module
 * attributes; see attribute static configuration table in "dsw_attrib.h" for
 * details.
 *
 * Important: the attribute static configuration table of each module must be
 * appended with EOB (End of Block).
 */
typedef dsw_int (*dsw_module_root_t) (void);

typedef struct
{
    dsw_u8                      mid;
    char                       *name;
    dsw_module_root_t           root_func;              /* module root function */
    dsw_attrib_config_table_t  *attrib_config_table;    /* attributes static configuration table */
} dsw_module_config_table_t;

/* EOB of static configuration table */
#define DSW_MODULE_CONFIG_TABLE_END { DSW_MID_NR, NULL, NULL, NULL }

/*
 * Private Heap of Module
 *
 * Each module has most one private heap to store private global data of module
 * and the size of heap is calculated by call back function.
 *
 * The size of private heap is calculated by call back function supplied by
 * user and the setting of relative attributes is done by DSWare system before
 * calculating size of private heap.
 */
typedef dsw_u32 (*dsw_calc_heap_size_t) (void);

typedef struct
{
    dsw_u32                     size;
    dsw_calc_heap_size_t        calc_func;              /* calculate the size of private heap */
} dsw_heap_t;

/*
 * NVRAM Memory of Module
 *
 * Some modules of DSWare system could have a segment of NVRAM memory to store
 * the global data that needs power-down protection; and the memory size of
 * NVRAM is calcuated by call back function supplied by user.
 *
 * NVRAM memory size is calculated by call back function supplied by user and
 * the setting of relative attributes is done by DSWare system before
 * calculating NVRAM size.
 */
typedef dsw_u64 (*dsw_calc_nvram_size_t) (void);

typedef struct
{
    dsw_u64                     size;
    dsw_calc_nvram_size_t       calc_func;              /* calculate memory size of NVRAM */
} dsw_nvram_t;

/* that means support 512K size block */
#define DSW_MODULE_MEM_FMT_MAX_NUM      (128 * 1024)

// dsware ONLY support 2 memory pool CURRENTLY, so DO NOT change this macro definition
#define DSW_MODULE_MEM_POOL_MAX_NUM     (2)

/** //added by h90005209 for FS8.0-memory_reduce on 2018-06-19
 * 新增unsecured_*_num变量，表示扩展内存资源数量，不静态预留，需要是动态扩展//added by h90005209 for FS8.0-memory_reduce on 2018-06-19
 * 如fmt://added by h90005209 for FS8.0-memory_reduce on 2018-06-19
 *      1、unit_num : 表示fmt资源最大值//added by h90005209 for FS8.0-memory_reduce on 2018-06-19
 *      2、unit_num - unsecured_unit_num : 表示fmt资源最小值，静态预留资源数//added by h90005209 for FS8.0-memory_reduce on 2018-06-19
 *      3、0 <= unsecured_unit_num <= unit_num//added by h90005209 for FS8.0-memory_reduce on 2018-06-19
*/ //added by h90005209 for FS8.0-memory_reduce on 2018-06-19
typedef struct {
    dsw_u32 unit_size;
    dsw_u32 unit_num;
    dsw_u32 unsecured_unit_num;
    dsw_u8  need_lock;
    uint32_t line;
    const char *function_name;
} dsw_module_memfmt_info_t;

typedef struct {
    dsw_u32 blk_size;
    dsw_u32 max_coinstant_units_num;
    dsw_u32 blk_num;
    dsw_u32 unsecured_blk_num;
    dsw_u8 type;
    dsw_u8 need_lock;
    dsw_u8 use_rdma;
} dsw_module_mempool_info_t;

typedef struct {
    dsw_u32 unit_size;
    dsw_u32 unit_num;
    dsw_u32 unsecured_unit_num;
} dsw_module_membs_info_t;


typedef dsw_int (*dsw_set_fmt_info)(dsw_u32* fmt_num, dsw_module_memfmt_info_t* fmt_info);
typedef dsw_int (*dsw_set_pool_info)(dsw_u32* pool_num, dsw_module_mempool_info_t* pool_info);
typedef dsw_int (*dsw_set_bs_info)();

typedef struct {
    dsw_set_fmt_info            set_fmt_func;
    dsw_set_fmt_info            set_simple_fmt_func;
    dsw_set_pool_info           set_pool_func;
    dsw_set_bs_info             set_bs_func;
    dsw_u32                     fmt_num;
    dsw_module_memfmt_info_t    *fmt_info;
    dsw_u32                     simple_fmt_num;
    dsw_module_memfmt_info_t    *simple_fmt_info;
    dsw_u32                     pool_num;
    dsw_module_mempool_info_t   pool_info[DSW_MODULE_MEM_POOL_MAX_NUM];
} dsw_memfmt_t;

/*
 * Definition of Module
 *
 * For a whole module, DSWare system initialize information of each module with
 * module static configuration table and register the callback function needed
 * for module running by module root function.
 *
 * Module is unenabled by default. DSWare enables the module configured in the
 * module static table at the initialization phase and unenabling module would
 * be reconsidered at the file configuration phase according to the
 * configuration in the configuration file.
 *
 * Module initialization function, provided by user, could complete all the
 * basic initialization operation (Notice: the initialization can be completed
 * according to different phase, so that the initialization reliance problem
 * between modules could be solved).
 *
 * Message entry function provided by user is the communicating message sending
 * function between modules. The function is called directly to send message at
 * the moment of intercommunication between modules (Notice: the function could
 * only be used for message queue related operation, excluding time consuming
 * operation).
 *
 * Module configuration object, that is the collection of attributes of each
 * module, is actually a structually static instance that contains several
 * members and the type currently supported includes integer, string, boolean.
 *
 * User provides callback function to create configuration object and the
 * callback function should initialize all the members in the configuration
 * object and the pointer to the configuration object should be returned.
 *
 * User provides configuration post-process function according to the actual
 * need of module, so that the configuration object member relying on the
 * attributes value of other module could be configured.
 *
 * Module attribute table stores all the original text data of attribute value
 * read from configuration file in cache; see the module attribute definition
 * in "dsw_attrib.h" in details.
 *
 * Attributes static configuration table is the description table of each
 * module; see attributes static configuration table in "dsw_attrib.h" for
 * details.
 */

typedef dsw_int (*dsw_init_module_t) (dsw_u8);          /* initialization phase */
typedef dsw_int (*dsw_wait_module_t) (void);
typedef dsw_int (*dsw_msg_entry_t) (dsw_message_block_t *);
typedef void *  (*dsw_create_config_t) (void);
typedef dsw_int (*dsw_config_post_t) (void);
typedef dsw_u32 (*dsw_get_io_depth_func_t) (void);

//外部消息验证使用
typedef dsw_int (*dsw_msg_cmdtype_t) (void);
dsw_int dsw_module_register_msg_cmdtype(dsw_u8 mid, dsw_msg_cmdtype_t blacklist_func);
dsw_int dsw_module_set_msg_cmdtype_info();

struct dsw_module_s
{
    dsw_u8                      mid;
    char                       *name;
    dsw_bool                    enable;                 /* sign of module enable */

    dsw_init_module_t           init_func;              /* module initialization function */
    dsw_msg_entry_t             entry_func;             /* message entry function */
    dsw_msg_cmdtype_t           msg_cmdtype_func;       /* module msg cmdtype register */

    dsw_task_t                 *task[DSW_MODULE_TASK_NUM_MAX];
    dsw_u8                      task_num;

    void                       *config;                 /* configuration object */
    dsw_create_config_t         config_create_func;     /* create configuration object */
    dsw_config_post_t           config_post_func;       /* configure post-process function */
    dsw_get_io_depth_func_t     get_io_depth_func;      /* 获取模块的IO队列深度仅网络模块使用(VBSDATANET/OSDDATANET) */

    dsw_attrib_t               *attrib;                 /* module attributes table */
    dsw_attrib_config_table_t  *attrib_config_table;    /* attributes static configuration table */
    dsw_u8                      attrib_num;

    dsw_u8                      is_network;
    dsw_u8                      network_use_rdma;
    dsw_u32                     max_conn;
    dsw_heap_t                  heap;
    dsw_nvram_t                 nvram;
    dsw_memfmt_t                memfmt;
    dsw_u32                     io_pool_mgr_unit_num;
    dsw_u32                     normal_pool_mgr_unit_num;

    dsw_u32                     thr_nums;      /* config thread nums */
    dsw_u32                     path_mode;     /* choose path mode */
};


dsw_int dsw_module_register_base_info(dsw_u8 mid, dsw_init_module_t init_func, dsw_msg_entry_t entry_func);
dsw_int dsw_module_register_task_info(dsw_u8 mid, char *task_name, dsw_int priority, dsw_u64 run_cpu_mask, dsw_task_routine_t routine_func, void *arg);
dsw_int dsw_module_register_config_info(dsw_u8 mid, dsw_create_config_t config_create_func, dsw_config_post_t config_post_func);
dsw_int dsw_module_register_heap_info(dsw_u8 mid, dsw_calc_heap_size_t calc_func);
dsw_int dsw_module_register_nvram_info(dsw_u8 mid, dsw_calc_nvram_size_t calc_func);
dsw_int dsw_module_register_fmt_info(dsw_u8 mid, dsw_set_fmt_info set_fmt_func);
dsw_int dsw_module_register_simple_fmt_info(dsw_u8 mid, dsw_set_fmt_info set_simple_fmt_func);
dsw_int dsw_module_register_pool_info(dsw_u8 mid, dsw_set_pool_info set_pool_func);
dsw_int dsw_module_enable_network(dsw_u8 mid, dsw_u8 use_rdma, dsw_u32 max_conn);
dsw_int dsw_module_register_bs_info(dsw_u8 mid, dsw_set_bs_info set_bs_func);
dsw_int dsw_module_register_msg_cmdtype(dsw_u8 mid, dsw_msg_cmdtype_t blacklist_func);
dsw_int dsw_enable_module(dsw_u8 mid, char*name, dsw_attrib_config_table_t* attrib_config_table);
/* 注册IO队列深度计算函数 */
dsw_int dsw_module_register_io_depth(dsw_u8 mid, dsw_get_io_depth_func_t get_io_depth_func);

dsw_int dsw_module_init();
dsw_int dsw_disable_module(dsw_u8 mid);
dsw_int dsw_module_is_enabled(dsw_u8 mid);
dsw_int dsw_module_config_all(char *file_path/*, bool is_reload*/);
dsw_int dsw_module_update_nvram_size(dsw_u8 mid, dsw_u64 size);
dsw_int dsw_module_init_all(void);
dsw_int dsw_module_launch_all(void);
dsw_int dsw_module_cancel_all(void);
dsw_int dsw_module_wait_all(void);
dsw_int dsw_module_timedwait_all(int max_wait_seconds);
dsw_module_t *dsw_module_reference_by_name(char *name);
extern dsw_u64 dsw_module_get_nvram_size(dsw_u8 mid);
dsw_int dsw_msg_head_check(dsw_message_head_t *head);
dsw_int check_nid_mid(dsw_u32 nid, dsw_u8 mid);
dsw_int dsw_get_node_manage_ip(char *ip_addr, const dsw_u32 ip_addr_len);

//extern dsw_module_t g_dsw_module[DSW_MID_NR];
DECLARE_OSD_ARRAY_VAR(dsw_module_t, g_dsw_module, [DSW_MID_NR]);
#define g_dsw_module OSD_VAR(g_dsw_module)

static inline dsw_bool dsw_module_check_mid(dsw_u8 mid)
{
    if (mid >= DSW_MID_NR)
    {
        return DSW_FALSE;
    }

    dsw_module_t   *module = g_dsw_module + mid;

    if (!module->enable)
    {
        return DSW_FALSE;
    }

    return DSW_TRUE;
}

dsw_int dsw_msg_nid_ntype_check(dsw_u32 nid, dsw_u8 node_type);

void dsw_set_rptread_time(void);

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif /* __DSW_MODULE_H__ */
