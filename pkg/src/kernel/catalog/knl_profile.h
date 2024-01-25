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
 * knl_profile.h
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/knl_profile.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_PROFILE_H__
#define __KNL_PROFILE_H__

#include "knl_session.h"
#include "knl_log.h"
#include "knl_interface.h"
#include "knl_profile_persistent.h"
#ifdef __cplusplus
extern "C" {
#endif

#define PROFILE_COLUMN_NUM          4
#define PROFILE_NAME_COLUMN_ID      0
#define PROFILE_PROFILE_COLUMN_ID   1
#define PROFILE_RESOURCE_COLUMN_ID  2
#define PROFILE_THRESHOLD_COLUMN_ID 3

#define MAX_PROFILE_SIZE  (CT_SHARED_PAGE_SIZE / sizeof(pointer_t))
#define PROFILE_HASH_SIZE (CT_SHARED_PAGE_SIZE / sizeof(bucket_t))

typedef struct st_status_desc {
    uint32 id;
    char *name;
    char *description;
} status_desc_t;

typedef struct st_bucket {
    latch_t latch;
    uint32 count;
    uint32 first;
} bucket_t;

typedef struct st_resource_item {
    char *name;           /* resource name */
    resource_type_t type; /* resource type */
    uint64 default_value; /* default value */
    char *description;    /* desc */
    char *comment;        /* desc */
} resource_item_t;

typedef struct st_profile {
    drlock_t lock;
    bucket_t *bucket;
    char name[CT_NAME_BUFFER_SIZE];
    uint32 id;
    uint32 mask;
    uint64 limit[RESOURCE_PARAM_END];
    bool32 used;
    bool32 valid;
    uint32 prev;
    uint32 next;
} profile_t;

typedef struct st_profile_array {
    bucket_t *buckets;
    profile_t **profiles;
} profile_array_t;

#define ACCOUNT_STATUS_TOTAL         18
extern const resource_item_t g_resource_map[RESOURCE_PARAM_END];
extern const status_desc_t g_user_astatus_map[ACCOUNT_STATUS_TOTAL];

status_t profile_create(knl_session_t *session, profile_t *profile);

status_t profile_drop(knl_session_t *session, knl_drop_def_t *def, profile_t *profile);

status_t profile_alter(knl_session_t *session, knl_profile_def_t *def);

status_t profile_get_param_limit(knl_session_t *session, uint32 profile_id, resource_param_t param_id,
                                 uint64 *limit);
bucket_t *profile_get_bucket(knl_session_t *session, text_t *name);

bool32 profile_find_by_name(knl_session_t *session, text_t *name, bucket_t *bucket, profile_t **r_profile);

bool32 profile_find_by_id(knl_session_t *session, uint32 id, profile_t **r_profile);

status_t profile_load(knl_session_t *session);

status_t profile_build_sysprofile(knl_session_t *session, knl_cursor_t *cursor);

status_t profile_alloc_and_insert_bucket(knl_session_t *session, knl_profile_def_t *def, bucket_t *bucket,
                                         profile_t **r_profile);

void rd_create_profile(knl_session_t *session, log_entry_t *log);

void rd_alter_profile(knl_session_t *session, log_entry_t *log);

void rd_drop_profile(knl_session_t *session, log_entry_t *log);

void print_create_profile(log_entry_t *log);

void print_alter_profile(log_entry_t *log);

void print_drop_profile(log_entry_t *log);

#ifdef __cplusplus
}
#endif

#endif
