/**
 *          Copyright 2011 - 2015, Huawei Tech. Co., Ltd.
 *                      ALL RIGHTS RESERVED
 *
 * dsw_boot.h
 *

 * @create: 2013-01-16
 *
 */

#ifndef __DSW_BOOT_H__
#define __DSW_BOOT_H__

#include "dsw_typedef.h"
#include "dsw_attrib.h"
#include "dsw_module.h"
#include "dsw_multi_instance.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#define DSW_MAX_PHY_NUM     128
#define DSW_MAX_NVRAM_INDEX 128

#define DSW_BOOT_PARAM_PARSE_OK 8
#define DSW_MAX_VBS_ID      (0xFFFF)
#define DGW_DEFALUT_ID      (1)

//SSD only, each osd max size is 1T, each ssd max size is 16T
#define DSW_OFFSET_FOR_SSD  (0x10000000000)
#define DSW_SSD_OFFSET_MAX  (0xF0000000000)
#define DSW_LENGTH_FOR_SSD  (0x10000000000)
#define DSW_SSD_LENGTH_MAX  (0x10000000000)
#define SSD_MEM_ALIGN       (4096)

typedef struct dsw_boot_param dsw_boot_param_t;
typedef dsw_int (*DSW_BOOT_CONFIG)(dsw_boot_param_t* boot_param);
typedef dsw_int (*DSW_PARAM_PARSE)(int argc, char *argv[], dsw_boot_param_t* boot_param);
struct dsw_boot_param
{
    dsw_bool create_task;
    dsw_u8  node_type;
    dsw_u16 nvram_index;
    dsw_u32 phy_no;
    dsw_u32 kvs_id;
    dsw_u32 libclient_id;
    dsw_u32 vbs_id;
    dsw_u32 vfs_id;   //vfs client id
    char  disk_esn[DSW_ATTRIB_VALUE_BUF_LEN];
    char  disk_path[DSW_ATTRIB_VALUE_BUF_LEN];
    char  flashcache_path[DSW_ATTRIB_VALUE_BUF_LEN];
    char  cfg_file[DSW_ATTRIB_VALUE_BUF_LEN];
    dsw_u8  media;
    dsw_u8  query_type;
    dsw_u64 offset_for_ssd;
    dsw_u64 length_for_ssd;
    dsw_u64 hotcache_offset_for_ssd;//nvdim做wb，ssd做hotcache场景下，由启动参数配置hotcache的偏移
    dsw_module_config_table_t* app_module_table;
    DSW_BOOT_CONFIG fnConfig;
    DSW_PARAM_PARSE fnParamParse;
    void (*keep_run)(dsw_boot_param_t *);
    void (*run_exit)(dsw_boot_param_t *);
    void (*system_init_failed_proc)(dsw_boot_param_t *);
    dsw_u32 snm_id;
    dsw_u32 snm_version;
};

//extern dsw_bool g_create_task;
DECLARE_OSD_VAR(dsw_bool, g_create_task);
#ifndef g_create_task
#define g_create_task OSD_VAR(g_create_task)
#endif

extern dsw_int dsw_boot_param_parse(int argc, char *argv[], dsw_boot_param_t* boot_param);

#ifdef __DFV_DATANET__
extern dsw_int dfv_boot_and_run(int argc, char *argv[], dsw_boot_param_t *boot_param, struct dsw_hdr_version *ver);
static inline dsw_int dsw_boot_and_run(int argc, char *argv[], dsw_boot_param_t *boot_param)
{
    static struct dsw_hdr_version  p_ver = DSW_HDR_VER_DEF;
    return dfv_boot_and_run(argc, argv, boot_param, &p_ver);
}

#else /*__DFV_DATANET__ */
extern dsw_int dsw_boot_and_run(int argc, char *argv[], dsw_boot_param_t* boot_param);
#endif /* __DFV_DATANET__ */

void dsw_boot_snd_state_to_agent(dsw_boot_param_t* boot_param, dsw_u32 retcode, dsw_u32 detail_ret);
void dsw_exit_snd_state_to_agent(dsw_int msg_flag, dsw_u32 retcode, dsw_u32 detail_ret);


typedef enum
{
    DSW_DPMM_IO_POOL = 0,
    DSW_DPMM_FMT_POOL,
    DSW_DPMM_NORMAL_POOL,
} dsw_dpmm_pool_type;

typedef struct
{
    dsw_dpmm_pool_type pool_type;
    const char* name;
    dsw_u64 size;
    dsw_u64 block_size;
    uint64_t pool_id;
} dsw_dpmm_pool_t;

int32_t dsw_core_init(dsw_dpmm_pool_t *pool, int32_t pool_count, char *cfg_file);

dsw_int dsw_boot_daemonize();
dsw_int dsw_boot_fail_proc(dsw_boot_param_t * boot_param);

typedef dsw_int (*MUTI_THREAD_JION_FUNC)(void);
void dsware_init_muti_join_register(MUTI_THREAD_JION_FUNC jion_func);
#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif /* __DSW_BOOT_H__ */
