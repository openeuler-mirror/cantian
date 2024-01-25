/**
 * @file infrastructure_init.h
 * @copyright 2018 Huawei. All rights reserved.

 *
 * @brief infrastructure initializate entry
 */
#ifndef INFRASTRUCTURE_INIT_H
#define INFRASTRUCTURE_INIT_H

#include "dpax_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    const char *key;
    const char *value;
} infra_extern_param_t;

#define INFRA_UMM_NOT_USE   0
#define INFRA_UMM_NOT_LIMIT 0xFFFFFFFFFFFFFFFF

int32_t infra_os_init_extern(uint32_t process_id, const char *process_name, const char *log_path
    , uint64_t umm_max, infra_extern_param_t *extern_param, int32_t extern_count);

static inline int32_t infra_os_init(uint32_t process_id, const char *process_name, const char *log_path, uint64_t umm_max)
{
    return infra_os_init_extern(process_id, process_name, log_path, umm_max, NULL, 0);
}

void infra_os_exit(void);

typedef struct
{
    uint64_t magic;
    uint64_t pool_id;

    struct
    {
        uint32_t min_count;
        uint32_t max_count;
    } req, sgl, page;
} infra_cmm_param_t;

void infra_cmm_param_init(infra_cmm_param_t *param);

int32_t infra_cmm_init(infra_cmm_param_t *cmm_param);

void infra_cmm_exit(void);

typedef struct
{
    uint32_t count;
    int32_t cpu_affinity;
    uint32_t stack_size;
    uint32_t frame_count;
    uint64_t cpu_mask[4];
    uint32_t thread_num;
    void *reserved;
} infra_lwt_param_t;

void infra_lwt_param_init(infra_lwt_param_t *param);

int32_t infra_lwt_init(infra_lwt_param_t *param);

void infra_lwt_exit(void);

#ifdef __cplusplus
}
#endif

#endif

