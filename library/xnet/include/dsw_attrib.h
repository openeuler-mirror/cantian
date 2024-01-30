/**
 *          Copyright 2011 - 2015, Huawei Tech. Co., Ltd.
 *                      ALL RIGHTS RESERVED
 *
 * dsw_attrib.h

 * @create: 2012-04-16
 *
 */


#ifndef __dsw_attrib_pub_h__
#define __dsw_attrib_pub_h__ 1

#include "dsw_typedef.h"
#include "dsw_message.h"
#include "dsw_id.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

typedef struct dsw_module_s dsw_module_t;

#define DSW_ATTRIB_NAME_BUF_LEN     (64)
#define DSW_ATTRIB_VALUE_BUF_LEN    (256) //多实例编译，此项过于巨大引起g_dsw_attrib编译错误，从3936修改到256
#define DSW_ATTRIB_SECTION_BUF_LEN  (64)
#define DSW_ATTRIB_LINE_BUF_LEN    (DSW_ATTRIB_NAME_BUF_LEN + DSW_ATTRIB_VALUE_BUF_LEN)

#define DSW_ATTRIB_NAME_LEN_MAX     (DSW_ATTRIB_NAME_BUF_LEN - 1)
#define DSW_ATTRIB_VALUE_LEN_MAX    (DSW_ATTRIB_VALUE_BUF_LEN - 1)

#define DSW_ATTRIB_NUM_MAX          (210)


/*
 * Static Attributes Configuration Table
 *
 * Each module should have a static configuration table of attributes for
 * providing static configuration information of all the attributes
 *
 * Three attributes setting function are self contained in DSWare, and the
 * setting of attributes including integer type, string type and boolean type
 * is supported
 *
 * Attribute address is the relative address to the module attributes
 * configuration object, and can be reached by offset
 *
 * Important: the attributes static configuration table of each module must be
 * enclosed with EOB of static attributes configuration table
 */
typedef dsw_int (*dsw_set_attrib_t) (void *config, dsw_s32 offset, char *text);
typedef dsw_int (*dsw_mod_attrib_t) (dsw_message_block_t *msg, dsw_s32 para_idx);
typedef struct
{
    char                       *name;
    dsw_set_attrib_t            set_func;               /*Attributes setting function*/
    dsw_mod_attrib_t            mod_func;               /*Attributes online modifying function*/
    dsw_s32                     offset;                 /*Attributes address*/
} dsw_attrib_config_table_t;

typedef struct dynamic_mod_functions_s
{
    // cache
    dsw_mod_attrib_t dmp_default_recently_access_time_threshold;
    dsw_mod_attrib_t dmp_high_average_same_lba_period;
    dsw_mod_attrib_t dmp_high_threshold;
    dsw_mod_attrib_t dmp_low_average_same_lba_period;
    dsw_mod_attrib_t dmp_low_threshold;
    dsw_mod_attrib_t dmp_mid_average_same_lba_period;
    dsw_mod_attrib_t dmp_mid_threshold;
    dsw_mod_attrib_t dmp_period_time;
    dsw_mod_attrib_t dmp_p_cache_high_waterlevel;
    dsw_mod_attrib_t dmp_p_cache_low_waterlevel;
    dsw_mod_attrib_t dmp_p_cache_rw_low_waterlevel;
    dsw_mod_attrib_t dmp_p_cache_transfer_sleep_time;
    dsw_mod_attrib_t dmp_p_cache_transfer_threshold;
    dsw_mod_attrib_t dmp_p_crb_write_through_switch;
    dsw_mod_attrib_t dmp_p_hot_cache_transf_ratio;
    dsw_mod_attrib_t dmp_p_write_through_size;
    dsw_mod_attrib_t dmp_p_write_through_switch;
    dsw_mod_attrib_t dmp_recently_access_time_threshold;
    dsw_mod_attrib_t dmp_g_period_flush_switch;

    // rsm
    dsw_mod_attrib_t dmp_p_rsm_default_get_throughput;
    dsw_mod_attrib_t dmp_p_rsm_default_put_throughput;
    dsw_mod_attrib_t dmp_p_rsm_max_get_throughput;

    // vbs
    dsw_mod_attrib_t dmp_g_pair_iops_limit_per_vbs;
    dsw_mod_attrib_t dmp_g_pair_iobw_limit_per_vbs;
    dsw_mod_attrib_t dmp_g_iops_limit_per_vbs;
    dsw_mod_attrib_t dmp_g_iobw_limit_per_vbs;
    dsw_mod_attrib_t dmp_g_r_iops_limit_per_vbs;
    dsw_mod_attrib_t dmp_g_r_iobw_limit_per_vbs;
    dsw_mod_attrib_t dmp_g_w_iops_limit_per_vbs;
    dsw_mod_attrib_t dmp_g_w_iobw_limit_per_vbs;
    dsw_mod_attrib_t dmp_g_io_limit_alarm_ratio;
    dsw_mod_attrib_t dmp_g_io_limit_restore_ratio;
    dsw_mod_attrib_t dmp_g_io_limit_alarm_time_threshold;
    dsw_mod_attrib_t dmp_g_io_limit_alarm_report_period;
    dsw_mod_attrib_t dmp_g_vbs_cert_check_switch;
    dsw_mod_attrib_t dmp_g_vbs_io_check_switch;


    dsw_mod_attrib_t dmp_g_vbs_detect_slow_io_threshold_lvl4;
    dsw_mod_attrib_t dmp_g_vbs_detect_slow_io_threshold_cycle_lvl4;
    dsw_mod_attrib_t dmp_g_vbs_detect_slow_io_total_cycle_lvl4;
    dsw_mod_attrib_t dmp_g_vbs_detect_slow_io_threshold_lvl5;
    dsw_mod_attrib_t dmp_g_vbs_detect_slow_io_threshold_cycle_lvl5;
    dsw_mod_attrib_t dmp_g_vbs_detect_slow_io_total_cycle_lvl5;    
    dsw_mod_attrib_t dmp_g_vbs_detect_slow_io_threshold_lvl6; 
    dsw_mod_attrib_t dmp_g_vbs_detect_slow_io_total_cycle_lvl6;
    dsw_mod_attrib_t dmp_g_vbs_detect_slow_io_total_cnt;
} dynamic_mod_functions_t;

#define DSW_ATTRIB_CONFIG_TABLE_END { NULL, NULL, NULL, 0 }   /*End of BLock of attributes configuration table*/

/*
 * Definition of Module Attributes
 *
 * For each attribute of the module, DSWare reads the configuration file at the
 * initial phase and initialize the parameters of module in combination of
 * static attributes configuration table (Important: while module attributes
 * have a default value, DSWare only replaces the default value with the
 * information of configuration file
 *
 * The configuration information in the text form, read from configuration
 * file, would be stored in the cache by DSWare
 */
typedef struct
{
    dsw_module_t               *module;
    dsw_attrib_config_table_t  *attrib_config_table;
    char                        value[DSW_ATTRIB_VALUE_BUF_LEN];
} dsw_attrib_t;


dsw_int dsw_attrib_init();
dsw_int dsw_attrib_read_config(char *file_path);
dsw_int dsw_attrib_dyn_read_config(char *file_path);
dsw_int dsw_attrib_assign_to_module(void);
dsw_int dsw_attrib_set_number_s32(void *config, dsw_s32 offset, char *text);
dsw_int dsw_attrib_set_number_double(void *config, dsw_s32 offset, char *text);
dsw_int dsw_attrib_set_number_s64(void *config, dsw_s32 offset, char *text);
dsw_int dsw_attrib_set_string(void *config, dsw_s32 offset, char *text);
dsw_int dsw_attrib_cpy_string(void *config, dsw_s32 offset, char *text);
dsw_int dsw_attrib_cpy_string_max_len_64(void *config, dsw_s32 offset, char *text);
dsw_int dsw_attrib_cpy_url_string(void *config, dsw_s32 offset, char *text);
dsw_int dsw_attrib_set_boolean(void *config, dsw_s32 offset, char *text);
dsw_attrib_config_table_t *dsw_attrib_config_table_reference_by_name(dsw_module_t *module, char *name);
dsw_bool dsw_attrib_is_ignored_mid(dsw_u8 mid);
dsw_int dsw_attrib_set_number_s16(void *config, dsw_s32 offset, char *text);
/* mock */
dsw_bool dsw_mock_for_disk_sector();
/* mock */

DECLARE_OSD_ARRAY_VAR(dsw_attrib_t, g_dsw_attrib, [DSW_MID_NR + GLOBAL_AND_POOL][DSW_ATTRIB_NUM_MAX]);
#define g_dsw_attrib OSD_VAR(g_dsw_attrib)

DECLARE_OSD_ARRAY_VAR(dsw_u32, g_dsw_attrib_num, [DSW_MID_NR + GLOBAL_AND_POOL]);
#define g_dsw_attrib_num OSD_VAR(g_dsw_attrib_num)

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif /* __DSW_ATTRIB_H__ */

