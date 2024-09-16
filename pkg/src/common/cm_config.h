/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * Cantian is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * cm_config.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_config.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_CONFIG_H__
#define __CM_CONFIG_H__

#include "cm_defs.h"
#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CT_CONFIG_HASH_BUCKETS                 512
#define CT_CONFIG_ALIAS_HASH_BUCKETS           30
#define LOG_LONGSQL_VALUE_ON(value)           ((value) & 0x00000100)
#define LOG_FATAL_ON(value)                   (!((value) ^ 0xFFFFFFFF))
#define LOG_DEBUG_ON(value)                   (((value) & 0x00000077) == 0x00000077)
#define LOG_WARN_ON(value)                    (((value) & 0x00000037) == 0x00000037)
#define LOG_ERROR_ON(value)                   (((value) & 0x00000017) == 0x00000017)
#define LOG_RUN_ON(value)                     (((value) & 0x00000007) == 0x00000007)
#define SET_LOG_LONGSQL_VALUE_ON(value)       ((value) |= 0x00000100)
#define SET_LOG_LONGSQL_VALUE_OFF(value)      ((value) &= (~0x00000100))
#define SET_LOG_FATAL_ON(value)               ((value) |= 0xFFFFFFFF)
#define SET_LOG_DEBUG_ON(value)               ((value) = ((value) & 0x000000FF) | 0x00000077)
#define SET_LOG_WARN_ON(value)                ((value) = ((value) & 0x000000BF) | 0x00000037)
#define SET_LOG_ERROR_ON(value)               ((value) = ((value) & 0x0000009F) | 0x00000017)
#define SET_LOG_RUN_ON(value)                 ((value) = ((value) & 0x0000008F) | 0x00000007)
#define IS_LOG_LEVEL_MODE(name)               (strcmp(name, "_LOG_LEVEL_MODE") == 0)
#define IS_LONGSQL_LOG_MODE(name)             (strcmp(name, "LONGSQL_LOG_MODE") == 0)
#define IS_LOG_LEVEL(name)                    (strcmp(name, "_LOG_LEVEL") == 0)
#define IS_LOG_MODE(name)                     (IS_LOG_LEVEL_MODE(name)  || \
                                               IS_LONGSQL_LOG_MODE(name))
#define LOG_MODE_MAP_LENGTH                   (sizeof(g_log_map_set) / sizeof(log_mode_map_t))

typedef status_t (*config_verify_t)(void *se, void *lex, void *def);
typedef status_t (*config_notify_t)(void *se, void *item, char *value);

typedef enum en_config_effect {
    EFFECT_IMMEDIATELY = 0,
    EFFECT_RECONNECT = 1,
    EFFECT_REBOOT = 2
} config_effect_t;

typedef enum en_config_scale {
    CFG_DB = 0,
    CFG_INS = 1,
    CFG_SE = 2,
} config_scale_t;

typedef enum en_config_flag {
    FLAG_NONE = 0,
    FLAG_ZFILE = 1,  /* item loaded from main config file */
    FLAG_INFILE = 2, /* the item is loaded from include file */
} config_flag_t;

typedef enum en_config_attr {
    ATTR_NONE = 0x0,
    ATTR_READONLY = 0x1,
    ATTR_HIDDEN = 0x2,
} config_attr_t;

typedef struct st_config_item {
    /* config item array must be predefined */
    char *name; /* param name */
    bool32 is_default;
    uint32 attr;
    char *default_value;
    /* param in memory value, when scope = memory diff with item.pfile_value, others same with pfile_value. */
    char *value;
    char *runtime_value; /* value used in running time */
    char *description;
    char *range;
    char *datatype;

    /* following fields will be fixed when instance load the configuration file and check it */
    /* the item_no is start with commment if any comment over the definition */
    char *comment;
    uint32 id;
    config_effect_t effect;

    config_scale_t scale;
    config_verify_t verify;
    config_notify_t notify;        // called by noargs / scope = memory / scope = both
    config_notify_t notify_pfile;  // called by scope = pfile
    char           *alias;        /* alias name */

    /* next item id that occurs in config file, default item never be writen in file */
    struct st_config_item *next;
    struct st_config_item *hash_next;
    struct st_config_item *hash_next2;
    struct st_config_item *next_file;

    uint32 flag; /* flag indicates whether to write back the config item */
    char *pfile_value;  /* param in config file value.when scope = pfile set pfile_value, others same with item.value */
    bool32 is_diff;     /* when specified scope memory or pfile, the flag will be true */
    bool32 hit_alias;   /* alias name hit */
} config_item_t;

typedef struct st_debug_config_item {
    char *name;
    char *default_value;
    char curr_value[CT_PARAM_BUFFER_SIZE];
    char *range;
    char *datatype;
    config_verify_t verify;
    config_notify_t notify;
} debug_config_item_t;

typedef struct st_config {
    int32 file;
    char file_name[CT_FILE_NAME_BUFFER_SIZE];
    char file_buf[CT_MAX_CONFIG_FILE_SIZE];
    char *value_buf;
    uint32 value_offset;
    uint32 value_buf_size;
    uint32 text_size;
    uint32 item_count;
    config_item_t *items;

    config_item_t *first_item; /* the first item, that occurs in config file */
    config_item_t *last_item;  /* the last item, that occurs in config file */

    config_item_t *name_map[CT_CONFIG_HASH_BUCKETS];
    config_item_t *alias_map[CT_CONFIG_ALIAS_HASH_BUCKETS];

    config_item_t *first_file; /* the first include file that occurs in config file */
    config_item_t *last_file;  /* the last include file that occurs in config file */
    bool32 ignore;             /* ignore unknown parameter */
} config_t;

typedef struct st_config_stream {
    config_t *config;
    uint32 offset;
} config_stream_t;

typedef enum en_config_scope {
    CONFIG_SCOPE_MEMORY = 1,
    CONFIG_SCOPE_DISK = 2,
    CONFIG_SCOPE_BOTH = 3,
} config_scope_t;

void cm_init_config(config_item_t *items, uint32 item_count, config_t *config);
status_t cm_load_config(config_item_t *items, uint32 item_count, const char *file_name, config_t *config,
                        bool32 set_alias);
status_t cm_save_config(config_t *config);
status_t cm_alter_config(config_t *config, const char *name, const char *value, config_scope_t scope,
                         bool32 force);
char *cm_get_config_value(const config_t *config, const char *name);
status_t cm_read_config(const char *file_name, config_t *config);
status_t cm_read_config_file(const char *file_name, char *buf, uint32 *buf_len, bool32 is_ifile,
                             bool32 read_only);
void cm_free_config_buf(config_t *config);
char *cm_fgets_nonblock(char *buf, uint32 buf_len, FILE *stream);
config_item_t *cm_get_config_item(const config_t *config, text_t *name, bool32 set_alias);

status_t cm_modify_runtimevalue(config_t *config, const char *name, const char *value);

#ifdef __cplusplus
}
#endif

#endif
