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
 * ctsql_resource.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/ctsql_resource.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_RESOURCE_H__
#define __SQL_RESOURCE_H__

#include "knl_interface.h"
#include "cm_sync.h"
#include "cm_queue.h"
#include "cm_thread.h"

#ifdef __cplusplus
extern "C" {
#endif

struct st_resource_plan;
typedef struct st_io_stat {
    atomic_t disk_reads;
    atomic_t commits;
    date_t snap_time;
} io_stat_t;

typedef struct st_resource_monitor {
    atomic32_t ref_count;
    atomic32_t active_sess;
    atomic_t cpu_time;
    atomic_t io_wait_time;
    atomic_t io_waits;
    uint32 que_length;
    uint64 sess_queued_time;
    uint64 sess_total_queues;
    uint64 sess_queue_timeouts;
    uint64 session_limit_hit;
    io_stat_t io_stat;
} rsrc_monitor_t;

typedef struct st_resource_group {
    knl_rsrc_group_t knl_group; // resource group handle
    uint32 max_cpus;            // maximum amount of cpu this group can consume
    uint32 max_sessions;        // maximum attached sessions
    uint32 max_active_sess;     // maximum activate sessions
    uint32 max_queue_time;      // maximum wait time in second for queued inactive sessions
    uint32 max_est_exec_time;   // maximum allowed estimated execution time, unit: second
    uint32 max_temp_pool;       // maximum temp buffer size(MB) for this group
    uint32 max_iops;            // maximum I/O operation per second
    uint32 max_commit_ps;       // maximum commits per second
    cpu_set_t cpuset;           // cpuset for control group
    galist_t *attr_maps;        // attribute key-value pair list and resource monitor by tenant/user
    struct st_resource_plan *plan;
    rsrc_monitor_t rsrc_monitor; // monitoring of the group
    atomic32_t read_iops;        // average read I/O per second
    atomic32_t commit_ps;        // average commit per second
    vm_pool_t *temp_pool;
    io_stat_t io_snapshot[2];
    spinlock_t lock;    // lock for queue
    biqueue_t sess_que; // queued sessions
} rsrc_group_t;

typedef struct st_resource_attr_map {
    text_t key;
    text_t value;

    rsrc_monitor_t rsrc_monitor; // monitoring of the attr
    rsrc_group_t *rsrc_group;
} rsrc_attr_map_t;

typedef struct st_resource_plan {
    knl_rsrc_plan_t knl_plan;
    uint32 group_count;
    rsrc_group_t *groups[CT_MAX_PLAN_GROUPS];
    memory_context_t *memory;
    date_t iops_time;
    uint32 total_cpus;
    atomic32_t ref_count;
    volatile bool8 is_valid;
    uint8 type;
    uint8 unused[2];
    // don't change the definition order of prev and next
    // so rsrc_plan_t can be change to biqueue_node_t by macro QUEUE_NODE_OF and be added to a bi-queue
    struct st_resource_plan *prev;
    struct st_resource_plan *next;
} rsrc_plan_t;

typedef struct st_resource_manager {
    rsrc_plan_t *plan;    // current working plan
    biqueue_t free_plans; // previous resource plan queue
    thread_t thread;
    cm_event_t event; // when idle agent is available, this event will be triggered.
    spinlock_t lock;
    bool32 started;
    cpu_set_t cpuset;
} rsrc_mgr_t;

status_t rsrc_load_plan(knl_handle_t sess, const char *name, rsrc_plan_t **plan);
status_t rsrc_reload_plan(knl_handle_t session, const char *plan_name);
status_t rsrc_start_manager(rsrc_mgr_t *rsrc_mgr);
void rsrc_stop_manager(rsrc_mgr_t *rsrc_mgr);
status_t rsrc_attach_group(knl_handle_t session, rsrc_plan_t *plan);
void rsrc_detach_group(knl_handle_t session);
void rsrc_accumate_io(knl_handle_t session, io_type_t type);
status_t rsrc_calc_cpuset(uint32 cpu_low, uint32 cpu_high, rsrc_plan_t *plan);
status_t rsrc_thread_bind_cpu(thread_t *thread, cpu_set_t *cpuset);

static inline status_t rsrc_cpuset_is_equal(cpu_set_t *cs1, cpu_set_t *cs2)
{
    return (bool32)(memcmp(cs1, cs2, sizeof(cpu_set_t)) == 0);
}

#ifdef __cplusplus
}
#endif

#endif
