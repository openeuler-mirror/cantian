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
 * cms_gcc.h
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_gcc.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMS_GCC_H
#define CMS_GCC_H

#include "cm_thread.h"
#include "cm_date.h"
#include "cms_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CMS_GCC_HEAD_MAGIC       (*((uint64*)"GCC_HEAD"))
#define CMS_GCC_NODE_MAGIC       (*((uint64*)"GCC_NODE"))
#define CMS_GCC_RES_MAGIC        (*((uint64*)"GCC_RES "))
#define CMS_GCC_RES_GRP_MAGIC    (*((uint64*)"RES_GRP "))
#define CMS_GCC_VOTEDISK_MAGIC   (*((uint64*)"VOTEDISK"))
#define CMS_GCC_UPGRADE_MAGIC    (*((uint64*)"UPGRADE"))

#define CMS_GCC_DIR_NAME         "gcc_home"
#define CMS_GCC_FILE_NAME        "gcc_file"
#define CMS_MASTER_FILE_NAME     "gcc_file_master_lock"
#define CMS_VOTE_FILE_NAME       "gcc_file_vote_file"
typedef union un_cms_res_t {
    struct {
        uint64          magic;
        uint32          res_id;
        uint32          grp_id;
        uint32          level;
        bool32          auto_start;
        uint32          start_timeout;
        uint32          stop_timeout;
        uint32          check_timeout;
        uint32          hb_timeout;
        uint32          check_interval;
        int32           restart_times;
        uint32          restart_interval;
        char            name[CMS_NAME_BUFFER_SIZE];
        char            type[CMS_NAME_BUFFER_SIZE];
        char            script[CMS_FILE_NAME_BUFFER_SIZE];
    };
    char    placeholder[CMS_BLOCK_SIZE];
}cms_res_t;

CM_STATIC_ASSERT(sizeof(cms_res_t) == CMS_BLOCK_SIZE);

typedef union un_cms_resgrp_t {
    struct {
        uint64          magic;
        uint32          grp_id;
        char            name[CMS_NAME_BUFFER_SIZE];
    };
    char    placeholder[CMS_BLOCK_SIZE];
}cms_resgrp_t;

CM_STATIC_ASSERT(sizeof(cms_resgrp_t) == CMS_BLOCK_SIZE);

typedef union un_cms_node_def_t {
    struct {
        uint64          magic;
        char            name[CMS_NAME_BUFFER_SIZE];
        uint32          node_id;
        uint32          port;
        char            ip[CT_MAX_INST_IP_LEN];
    };
    char    placeholder[CMS_BLOCK_SIZE];
}cms_node_def_t;

CM_STATIC_ASSERT(sizeof(cms_node_def_t) == CMS_BLOCK_SIZE);

typedef union un_cms_votedisk_t {
    struct {
        uint64          magic;
        char            path[CMS_FILE_NAME_BUFFER_SIZE];
    };
    char    placeholder[CMS_BLOCK_SIZE];
}cms_votedisk_t;

CM_STATIC_ASSERT(sizeof(cms_votedisk_t) == CMS_BLOCK_SIZE);

typedef union un_cms_gcc_head {
    struct {
        uint64          magic;
        uint32          cheksum;
        uint32          meta_ver;
        uint32          data_ver;
        uint32          node_count;
        uint64          ver_magic;
        uint16 			ver_main;
        uint16 			ver_major;
        uint16 			ver_revision;
        uint16 			ver_inner;
    };
    char    placeholder[CMS_BLOCK_SIZE];
}cms_gcc_head_t;

CM_STATIC_ASSERT(sizeof(cms_gcc_head_t) == CMS_BLOCK_SIZE);

typedef struct st_cms_gcc {
    cms_gcc_head_t          head;
    cms_votedisk_t          votedisks[CMS_MAX_VOTEDISK_COUNT];
    cms_node_def_t          node_def[CMS_MAX_NODE_COUNT];
    cms_resgrp_t            resgrp[CMS_MAX_RESOURCE_GRP_COUNT];
    cms_res_t               res[CMS_MAX_RESOURCE_COUNT];
}cms_gcc_t;

typedef struct st_gcc_storage {
    union {
        uint32      valid_gcc_id;
        char        placeholder[CMS_BLOCK_SIZE];
    };
    cms_gcc_t       gcc[CMS_GCC_STORAGE_NUM];
    char            gcc_lock[CMS_BLOCK_SIZE];
}cms_gcc_storage_t;

typedef struct st_gcc_auto_bak {
    bool32          is_backuping;
    date_t          latest_bak;
}cms_gcc_auto_bak_t;

#define CMS_GCC_DISK_SIZE   SIZE_M(8)
CM_STATIC_ASSERT(CMS_GCC_DISK_SIZE > sizeof(cms_gcc_t) * 2 + CMS_BLOCK_SIZE * 2);

status_t cms_gcc_read_disk_direct(cms_gcc_t* gcc);
status_t cms_gcc_write_disk(cms_gcc_t* gcc);
status_t cms_update_local_gcc(void);
status_t cms_backup_gcc(void);
status_t cms_backup_gcc_auto(void);
status_t cms_restore_gcc(const char* file_name);

void cms_gcc_loader_entry(thread_t* thread);
void cms_gcc_backup_entry(thread_t* thread);
void cms_notify_load_gcc(void);
status_t cms_reset_gcc(void);
status_t cms_load_gcc(void);
status_t cms_export_gcc(const char* path);
status_t cms_import_gcc(const char* path);
status_t cms_add_node(const char *name, const char *ip, uint32 port);
status_t cms_insert_node(uint32 node_id, const char *name, const char *ip, uint32 port);
status_t cms_del_node(uint32 node_id);
status_t cms_add_votedisk(const char* path);
status_t cms_del_votedisk(const char* path);
status_t cms_add_resgrp(const char* name);
status_t cms_del_resgrp(const char* name);
status_t cms_add_res(const char* name, const char* res_type, const char* grp, const char* attrs);
status_t cms_edit_res(const char* name, const char* attrs);
status_t cms_del_res(const char* name);
status_t cms_del_resgrp_force(const char* name);

const cms_resgrp_t* cms_find_resgrp(const cms_gcc_t* gcc, const char* name);
const cms_res_t* cms_find_res(const cms_gcc_t* gcc, const char* name);
bool32 cms_check_resgrp_has_res(const cms_gcc_t* gcc, const char* grp_name);
bool32 cms_check_name_valid(const char* name, uint32 name_len);
bool32 cms_check_path_valid(const char* path, uint32 path_len);
status_t cms_check_votedisk(const char* votedisk);
status_t cms_check_node_exists(const cms_gcc_t* gcc, const char* name, const char* ip, uint32 port);

status_t cms_init_gcc_disk_lock(void);
status_t cms_lock_gcc_disk(void);
status_t cms_unlock_gcc_disk(void);
const cms_gcc_t* cms_get_read_gcc(void);
void cms_release_gcc(const cms_gcc_t** gcc);

bool32 cms_gcc_head_is_invalid(void);
bool32 cms_node_is_invalid(uint32 node_id);
bool32 cms_res_is_invalid(uint32 res_id);
bool32 cms_resgrp_is_invalid(uint32 grp_id);
bool32 cms_votedisk_is_invalid(uint32 vd_id);

uint32 cms_get_gcc_node_count(void);
status_t cms_get_node_by_id(uint32 node_id, cms_node_def_t* node);
status_t cms_get_res_by_id(uint32 res_id, cms_res_t* res);
status_t cms_get_votedisk_by_id(uint32 vd_id, cms_votedisk_t* votedisk);
status_t cms_get_res_by_name(const char* name, cms_res_t* res);
status_t cms_get_res_id_by_type(const char* res_type, uint32 *res_id);
status_t cms_get_res_id_by_name(const char* name, uint32 *res_id);
status_t cms_get_resgrp_by_name(const char* name, cms_resgrp_t* resgrp);

status_t cms_text2uint32(const text_t* text_src, uint32* value);

status_t cms_update_gcc_ver(uint16 main_ver, uint16 major_ver, uint16 revision, uint16 inner);
status_t cms_get_gcc_ver(uint16* main_ver, uint16* major_ver, uint16* revision, uint16* inner);
status_t cms_create_gcc(void);
status_t cms_delete_gcc(void);
#ifdef __cplusplus
}
#endif
#endif