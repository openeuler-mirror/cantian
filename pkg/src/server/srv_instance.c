/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * srv_instance.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_instance.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_defs.h"
#include "knl_defs.h"
#include "cm_file.h"
#include "srv_instance.h"
#include "load_others.h"
#include "load_kernel.h"
#include "srv_view.h"
#include "cm_signal.h"
#include "cm_uuid.h"
#include "cm_license.h"
#include "srv_blackbox.h"
#include "cm_regexp.h"
#include "cm_utils.h"
#include "srv_query.h"
#include <locale.h>
#include "cm_thread_pool.h"
#include "cm_ip.h"
#include "srv_stat.h"
#include "dtc_dcs.h"
#include "dtc_context.h"
#include "dtc_dls.h"
#include "dtc_database.h"
#include "srv_mq.h"
#include "tse_inst.h"

#ifdef __cplusplus
extern "C" {
#endif


instance_t *g_instance = NULL;
char *g_database_home = NULL;
static const char *g_lock_file = "cantiand.lck";

static status_t server_wait_agents_completed(void);
static void server_close_threads(bool32 knl_flag);
static void server_deinit_resource(void);

os_run_desc_t g_os_stat_desc_array[TOTAL_OS_RUN_INFO_TYPES] = {
    /* cpu numbers */
    { "NUM_CPUS",        "Number of CPUs or processors available",                                                                                                                GS_FALSE, GS_FALSE },
    { "NUM_CPU_CORES",   "Number of CPU cores available (includes subcores of multicore CPUs as well as single-core CPUs)",                                                       GS_FALSE, GS_FALSE },
    { "NUM_CPU_SOCKETS", "Number of CPU sockets available (represents an absolute count of CPU chips on the system, regardless of ""multithreading or multi-core architectures)", GS_FALSE, GS_FALSE },
    /* cpu times */
    { "IDLE_TIME",   "Number of hundredths of a second that a processor has been idle, totalled over all processors",                                  GS_TRUE, GS_FALSE },
    { "BUSY_TIME",   "Number of hundredths of a second that a processor has been busy executing user or kernel code, totalled over ""all processors",    GS_TRUE, GS_FALSE },
    { "USER_TIME",   "Number of hundredths of a second that a processor has been busy executing user code, totalled over all ""processors",              GS_TRUE, GS_FALSE },
    { "SYS_TIME",    "Number of hundredths of a second that a processor has been busy executing kernel code, totalled over all ""processors",            GS_TRUE, GS_FALSE },
    { "IOWAIT_TIME", "Number of hundredths of a second that a processor has been waiting for I/O to complete, totalled over all ""processors",           GS_TRUE, GS_FALSE },
    { "NICE_TIME",   "Number of hundredths of a second that a processor has been busy executing low-priority user code, totalled over ""all processors", GS_TRUE, GS_FALSE },
    /* avg cpu times */
    { "AVG_IDLE_TIME",   "Number of hundredths of a second that a processor has been idle, averaged over all processors",                                  GS_TRUE, GS_FALSE },
    { "AVG_BUSY_TIME",   "Number of hundredths of a second that a processor has been busy executing user or kernel code, averaged over ""all processors",    GS_TRUE, GS_FALSE },
    { "AVG_USER_TIME",   "Number of hundredths of a second that a processor has been busy executing user code, averaged over all ""processors",              GS_TRUE, GS_FALSE },
    { "AVG_SYS_TIME",    "Number of hundredths of a second that a processor has been busy executing kernel code, averaged over all ""processors",            GS_TRUE, GS_FALSE },
    { "AVG_IOWAIT_TIME", "Number of hundredths of a second that a processor has been waiting for I/O to complete, averaged over all ""processors",           GS_TRUE, GS_FALSE },
    { "AVG_NICE_TIME",   "Number of hundredths of a second that a processor has been busy executing low-priority user code, averaged over ""all processors", GS_TRUE, GS_FALSE },
    /* virtual memory page in/out data */
    { "VM_PAGE_IN_BYTES", "Total number of bytes of data that have been paged in due to virtual memory paging", GS_TRUE, GS_FALSE },
    { "VM_PAGE_OUT_BYTES", "Total number of bytes of data that have been paged out due to virtual memory paging", GS_TRUE, GS_FALSE },
    /* os run load */
    { "LOAD", "Current number of processes that are either running or in the ready state, waiting to be selected by the ""operating-system scheduler to run. On many platforms, this statistic reflects the average load over the past ""minute.", GS_FALSE, GS_FALSE },
    /* physical memory size */
    { "PHYSICAL_MEMORY_BYTES", "Total number of bytes of physical memory", GS_FALSE, GS_FALSE }
};

const char *g_shutdown_mode_desc[SHUTDOWN_MODE_END] = {
    "normal", "immediate", "signal", "abort"
};

void handle_signal_fatal(int sig_no)
{
    g_instance->lsnr_abort_status = GS_TRUE;
}

void executive_abnormal_terminal(void)
{
    GS_LOG_RUN_WAR("executive_abnormal_terminal");
    server_instance_abort();
}

static void server_destory_reserved_session(void)
{
    session_t *session = NULL;
    uint32 i;

    for (i = 0; i < g_instance->kernel.reserved_sessions; i++) {
        session = g_instance->session_pool.sessions[i];
        if (session != NULL) {
            knl_destroy_session(&g_instance->kernel, i);
            CM_FREE_PTR(session->stack);
            CM_FREE_PTR(session);
            g_instance->session_pool.sessions[i] = NULL;
        }
    }

    for (i = 0; i < g_instance->rm_pool.page_count; i++) {
        CM_FREE_PTR(g_instance->rm_pool.pages[i]);
    }
}

status_t server_ssl_check_params(int32 *alert_day)
{
    int32 detect_day;
    if (GS_SUCCESS != cm_str2int(cm_get_config_value(&g_instance->config, "SSL_EXPIRE_ALERT_THRESHOLD"), alert_day)) {
        return GS_ERROR;
    }

    if (!(*alert_day >= GS_MIN_SSL_EXPIRE_THRESHOLD && *alert_day <= GS_MAX_SSL_EXPIRE_THRESHOLD)) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "SSL_EXPIRE_ALERT_THRESHOLD", (int64)GS_MIN_SSL_EXPIRE_THRESHOLD,
            (int64)GS_MAX_SSL_EXPIRE_THRESHOLD);
        return GS_ERROR;
    }

    if (GS_SUCCESS != cm_str2int(cm_get_config_value(&g_instance->config, "SSL_PERIOD_DETECTION"), &detect_day)) {
        return GS_ERROR;
    }

    if (!(detect_day >= GS_MIN_SSL_PERIOD_DETECTION && detect_day <= GS_MAX_SSL_PERIOD_DETECTION)) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "SSL_PERIOD_DETECTION", (int64)GS_MIN_SSL_PERIOD_DETECTION,
            (int64)GS_MAX_SSL_PERIOD_DETECTION);
        return GS_ERROR;
    }

    if (detect_day > *alert_day) {
        GS_LOG_RUN_ERR("SSL disabled: the value of SSL_PERIOD_DETECTION "
            "is bigger than the value of SSL_EXPIRE_ALERT_THRESHOLD");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t server_init_ssl_communication()
{
    ssl_config_t para;
    char *keypwd_cipher = NULL;
    char *verify_peer = NULL;
    char plain[GS_PASSWD_MAX_LEN + GS_AESBLOCKSIZE + 4];
    g_instance->ssl_acceptor_fd = NULL;
    int32 alert_day = 0;
    char real_path[GS_FILE_NAME_BUFFER_SIZE] = { 0 };

    MEMS_RETURN_IFERR(memset_s(&para, sizeof(ssl_config_t), 0, sizeof(ssl_config_t)));
    // load SSL parameters
    para.ca_file = cm_get_config_value(&g_instance->config, "SSL_CA");
    para.cert_file = cm_get_config_value(&g_instance->config, "SSL_CERT");
    para.key_file = cm_get_config_value(&g_instance->config, "SSL_KEY");
    para.crl_file = cm_get_config_value(&g_instance->config, "SSL_CRL");
    para.cipher = cm_get_config_value(&g_instance->config, "SSL_CIPHER");
    keypwd_cipher = cm_get_config_value(&g_instance->config, "SSL_KEY_PASSWORD");
    verify_peer = cm_get_config_value(&g_instance->config, "SSL_VERIFY_PEER");
    if (cm_str_equal_ins(verify_peer, "TRUE")) {
        para.verify_peer = GS_TRUE;
    } else if (cm_str_equal_ins(verify_peer, "FALSE")) {
        para.verify_peer = GS_FALSE;
    } else {
        GS_LOG_RUN_ERR("the value of parameter \"SSL_VERIFY_PEER\" is invalid");
        return GS_ERROR;
    }
    (void)cm_alter_config(&g_instance->config, "HAVE_SSL", "FALSE", CONFIG_SCOPE_MEMORY, GS_TRUE);

    if (CM_IS_EMPTY_STR(para.ca_file) && para.verify_peer) {
        para.verify_peer = GS_FALSE;
        (void)cm_alter_config(&g_instance->config, "SSL_VERIFY_PEER", "FALSE", CONFIG_SCOPE_MEMORY, GS_TRUE);
    }

    /* For server side, certifiate and key files are required */
    if (CM_IS_EMPTY_STR(para.cert_file) || CM_IS_EMPTY_STR(para.key_file)) {
        GS_LOG_RUN_INF("SSL disabled: server certificate or private key file is not available.");
        return GS_SUCCESS;
    }

    /* Require no public access to key file */
    GS_RETURN_IFERR(realpath_file(para.ca_file, real_path, GS_FILE_NAME_BUFFER_SIZE));
    if (cs_ssl_verify_file_stat(real_path) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("SSL CA certificate file \"%s\" has execute, group or world access permission.", para.ca_file);
        return GS_ERROR;
    }
    GS_RETURN_IFERR(realpath_file(para.cert_file, real_path, GS_FILE_NAME_BUFFER_SIZE));
    if (cs_ssl_verify_file_stat(real_path) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("SSL server certificate file \"%s\" has execute, group or world access permission.",
            para.cert_file);
        return GS_ERROR;
    }
    GS_RETURN_IFERR(realpath_file(para.key_file, real_path, GS_FILE_NAME_BUFFER_SIZE));
    if (cs_ssl_verify_file_stat(real_path) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("SSL private key file \"%s\" has execute, group or world access permission.", para.key_file);
        return GS_ERROR;
    }

    // decrypt cipher if not null
    if (!CM_IS_EMPTY_STR(keypwd_cipher)) {
        aes_and_kmc_t aes_kmc = { 0 };
        cm_kmc_set_aes_key_with_config(&aes_kmc, &g_instance->config);
        cm_kmc_set_kmc(&aes_kmc, GS_KMC_SERVER_DOMAIN, KMC_ALGID_AES256_CBC);
        cm_kmc_set_buf(&aes_kmc, plain, sizeof(plain) - 1, keypwd_cipher, (uint32)strlen(keypwd_cipher));
        if (cm_decrypt_passwd_with_key_by_kmc(&aes_kmc) != GS_SUCCESS) {
            GS_LOG_RUN_INF("SSL disabled: decrypt SSL private key password failed.");
            return GS_SUCCESS;
        }
        plain[aes_kmc.plain_len] = '\0';
        para.key_password = plain;
    }

    // create acceptor context
    g_instance->ssl_acceptor_fd = cs_ssl_create_acceptor_fd(&para);

    if (g_instance->ssl_acceptor_fd == NULL) {
        GS_LOG_RUN_INF("SSL disabled: create SSL context failed.");
    } else {
        (void)cm_alter_config(&g_instance->config, "HAVE_SSL", "TRUE", CONFIG_SCOPE_MEMORY, GS_TRUE);

        GS_LOG_RUN_INF("SSL context initialized.");

        GS_RETURN_IFERR(server_ssl_check_params(&alert_day));

        ssl_ca_cert_expire(g_instance->ssl_acceptor_fd, alert_day);
    }

    MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0, sizeof(plain)));

    return GS_SUCCESS;
}

status_t server_ssl_expire_warning(void)
{
    int32 alert_day, detect_day;
    if (GS_SUCCESS != cm_str2int(cm_get_config_value(&g_instance->config, "SSL_EXPIRE_ALERT_THRESHOLD"), &alert_day)) {
        return GS_ERROR;
    }

    if (GS_SUCCESS != cm_str2int(cm_get_config_value(&g_instance->config, "SSL_PERIOD_DETECTION"), &detect_day)) {
        return GS_ERROR;
    }

    // the range of SSL_PERIOD_DETECTION is [1,180]
    if ((g_timer()->systime / SECONDS_PER_DAY) % detect_day == 0) {
        ssl_ca_cert_expire(g_instance->ssl_acceptor_fd, alert_day);
    }
    return GS_SUCCESS;
}

static status_t server_init_session_pool(void)
{
    uint32 i, id;

    // init transaction resource manager pool
    resource_manager_pool_init(&g_instance->rm_pool);

    stat_pool_init(&g_instance->stat_pool);

    // init sql cursor pools for all sessions
    g_instance->sql_cur_pool.lock = 0;
    g_instance->sql_cur_pool.cnt = 0;
    GS_RETURN_IFERR(server_init_sql_cur_pools());
    // init system sessions
    for (i = 0; i < g_instance->kernel.reserved_sessions; i++) {
        if (server_alloc_reserved_session(&id) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    g_instance->session_pool.lock = 0;

    biqueue_init(&g_instance->session_pool.idle_sessions);
    biqueue_init(&g_instance->session_pool.priv_idle_sessions);
    g_instance->session_pool.service_count = 0;
    g_instance->session_pool.epollfd = epoll_create1(0);
    return GS_SUCCESS;
}

static status_t server_adjust_log_sender(void)
{
    knl_instance_t *kernel = &g_instance->kernel;
    knl_session_t *session = kernel->sessions[SESSION_ID_LSND];
    arch_context_t *ctx = &kernel->arch_ctx;

    if (g_instance->shutdown_ctx.phase >= SHUTDOWN_PHASE_INPROGRESS) {
        return GS_SUCCESS;
    }

    lsnd_close_disabled_thread(session);

    if (ctx->arch_dest_state_changed) {
        if (lsnd_init(session) != GS_SUCCESS) {
            ctx->arch_dest_state_changed = GS_FALSE;
            return GS_ERROR;
        }
        ctx->arch_dest_state_changed = GS_FALSE;
    }

    return GS_SUCCESS;
}

static void server_record_backup(uint32 client_id)
{
    knl_session_t *session = g_instance->kernel.sessions[SESSION_ID_BRU];
    lsnd_context_t *lsnd_ctx = &g_instance->kernel.lsnd_ctx;
    lsnd_bak_task_t *bak_task = &lsnd_ctx->lsnd[client_id]->bak_task;
    bool32 task_failed = GS_FALSE;

    GS_LOG_RUN_INF("server_record_backup");

    bak_task->record.status = BACKUP_SUCCESS;
    if (bak_record_backup_set(session, &bak_task->record) != GS_SUCCESS) {
        task_failed = GS_TRUE;
    }

    lsnd_trigger_task_response(session, client_id, task_failed);
}

static void server_process_record_backup_task(void)
{
    knl_session_t *session = g_instance->kernel.sessions[SESSION_ID_BRU];
    bak_context_t *ctx = &session->kernel->backup_ctx;
    uint32 build_keep_alive_timeout = session->kernel->attr.build_keep_alive_timeout;
    uint32 i;

    for (i = 0; i < GS_MAX_PHYSICAL_STANDBY; i++) {
        if (!g_instance->kernel.record_backup_trigger[i]) {
            continue;
        }

        server_record_backup(i);
        g_instance->kernel.record_backup_trigger[i] = GS_FALSE;
    }

    if (!BAK_IS_KEEP_ALIVE(ctx)) {
        return;
    }

    dls_spin_lock(session, &ctx->lock, NULL);
    if (!BAK_IS_KEEP_ALIVE(ctx)) {
        dls_spin_unlock(session, &ctx->lock);
        return;
    }
    if (cm_current_time() - ctx->keep_live_start_time > build_keep_alive_timeout || ctx->bak.build_stopped) {
        knl_panic(!ctx->bak.need_retry);
        ctx->bak_condition = NOT_RUNNING;
        GS_LOG_RUN_INF("[BUILD] cancel keep alive condition while reaching timeout "
            "or build cancelled: %u",
            ctx->bak.build_stopped);
    }
    dls_spin_unlock(session, &ctx->lock);
}

void server_terminal_zombie_session(void)
{
    session_t *sess = NULL;
    int loop, nfds;
    struct epoll_event events[GS_EV_WAIT_NUM];
    struct epoll_event *ev = NULL;
    nfds = epoll_wait(g_instance->session_pool.epollfd, events, GS_EV_WAIT_NUM, GS_EV_WAIT_TIMEOUT);
    if (nfds == -1) {
        if (errno != EINTR) {
            GS_LOG_RUN_ERR("Failed to wait for connection request, OS error:%d", cm_get_os_error());
        }
        return;
    }
    if (nfds == 0) {
        return;
    }

    for (loop = 0; loop < nfds; ++loop) {
        ev = &events[loop];
        sess = (session_t *)ev->data.ptr;

        if (!sess->knl_session.killed && sess->knl_session.status != SESSION_INACTIVE) {
            srv_mark_sess_killed(sess, GS_FALSE, sess->knl_session.serial_id);
        }
    }
}

status_t server_instance_loop(void)
{
    int64 periods = 0;
    int64 period_one_day = MILLISECS_PER_SECOND * SECONDS_PER_DAY / 5;
    g_instance->shutdown_ctx.enabled = GS_TRUE;

    while (1) {
        if (g_instance->shutdown_ctx.phase == SHUTDOWN_PHASE_DONE) {
            server_close_threads(GS_FALSE);
            server_deinit_resource();
            return GS_SUCCESS;
        }
        if (g_instance->lsnr_abort_status == GS_TRUE) {
            executive_abnormal_terminal();
            return GS_SUCCESS;
        }

        server_expire_unauth_timeout_session();
        if (periods == period_one_day && IS_SSL_ENABLED) {
            periods = 0;
            GS_RETURN_IFERR(server_ssl_expire_warning());
        }

#ifndef WIN32
        server_terminal_zombie_session();
#endif
        GS_RETURN_IFERR(server_adjust_log_sender());

        server_process_record_backup_task();

        cm_sleep(5);
        periods++;
    }
}

status_t server_kernel_startup(bool32 is_coordinator)
{
    knl_instance_t *kernel = &g_instance->kernel;
    kernel->attr.xpurpose_buf = cm_aligned_buf(g_instance->xpurpose_buf);
    kernel->attr.config = &g_instance->config;
    kernel->attr.timer = g_timer();
    kernel->attr.max_sessions = g_instance->session_pool.expanded_max_sessions;

    GS_LOG_RUN_INF("begin start kernel.");
    knl_init_attr(kernel);
    kernel->home = g_instance->home;
    kernel->id = kernel->dtc_attr.inst_id;
    g_local_inst_id = kernel->id;

    if (alck_init_ctx(kernel) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_START_INSTANCE_ERROR);
        return GS_ERROR;
    }
    kernel->id = kernel->dtc_attr.inst_id;
    if (GS_SUCCESS != knl_startup(kernel)) {
        GS_THROW_ERROR(ERR_START_INSTANCE_ERROR);
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("kernel startup finish.");
    return GS_SUCCESS;
}

status_t server_kernel_open(db_startup_phase_t phase)
{
    knl_instance_t *kernel = &g_instance->kernel;
    knl_session_t *knl_session = kernel->sessions[SESSION_ID_KERNEL];
    knl_alterdb_def_t def;
    status_t ret;

    MEMS_RETURN_IFERR(memset_s(&def, sizeof(knl_alterdb_def_t), 0, sizeof(knl_alterdb_def_t)));
    if (phase == STARTUP_MOUNT) {
        def.action = STARTUP_DATABASE_MOUNT;
    } else {
        def.action = STARTUP_DATABASE_OPEN;
    }
    ret = knl_alter_database(knl_session, &def);
    return ret;
}

status_t server_init_resource_manager_null(knl_handle_t sess)
{
    return GS_SUCCESS;
}

status_t server_callback_null_func2_uid(knl_handle_t knl_session, uint32 uid)
{
    return GS_SUCCESS;
}

status_t server_callback_null_func2_dc(knl_handle_t knl_session, knl_dictionary_t *dc)
{
    return GS_SUCCESS;
}

void server_callback_null_func2_dc_void(knl_handle_t knl_session, knl_dictionary_t *dc)
{
}

status_t server_callback_null_func3_text(knl_handle_t sess, uint32 uid, text_t *syn_name)
{
    return GS_SUCCESS;
}

status_t server_callback_null_func3_ptr(knl_handle_t sess, uint32 uid, void *syn_name)
{
    return GS_SUCCESS;
}

status_t server_callback_null_func4_dc_text(knl_handle_t knl_session, knl_dictionary_t *dc, text_t *name, text_t *new_name)
{
    return GS_SUCCESS;
}

void rsrc_accumulate_io_null(knl_handle_t sess, io_type_t type)
{
	return;
}

status_t init_sql_maps_null(knl_handle_t sess)
{
	return GS_SUCCESS;
}

status_t sql_update_dependant_status_null(knl_handle_t sess, obj_info_t *obj)
{
	return GS_SUCCESS;
}

status_t gss_raw_device_op_init_null(const char *conn_path)
{
	return GS_SUCCESS;
}
static void server_set_kernel_callback_ex(void)
{
    g_knl_callback.set_stmt_check = sql_set_stmt_check;
    g_knl_callback.before_commit = (knl_before_commit_t)knl_clean_before_commit;
    g_knl_callback.alloc_knl_session = server_alloc_knl_session;
    g_knl_callback.release_knl_session = server_release_knl_session;
    g_knl_callback.parse_check_from_text = sql_parse_check_from_text;
    g_knl_callback.parse_default_from_text = sql_parse_default_from_text;
    g_knl_callback.verify_default_from_text = sql_verify_default_from_text;
    g_knl_callback.update_depender = sql_update_dependant_status_null;
    g_knl_callback.accumate_io = rsrc_accumulate_io_null;
    g_knl_callback.init_resmgr = server_init_resource_manager_null;
    g_knl_callback.import_rows = NULL;
    g_knl_callback.sysdba_privilege = server_sysdba_privilege;
    g_knl_callback.backup_keyfile = server_backup_keyfile;
    g_knl_callback.update_server_masterkey = server_update_server_masterkey;
    g_knl_callback.have_ssl = server_have_ssl;
    g_knl_callback.clear_sym_cache = NULL; // pl_clear_sym_cache;
    g_knl_callback.get_func_index_size = sql_get_func_index_expr_size;
    g_knl_callback.compare_index_expr = sql_compare_index_expr;
    g_knl_callback.whether_login_with_user = server_whether_login_with_user;
    g_knl_callback.pl_drop_synonym_by_user = server_callback_null_func3_text;
    g_knl_callback.init_vmc = sql_init_mtrl_vmc;
    g_knl_callback.get_ddl_sql = NULL;
    g_knl_callback.convert_char = sql_convert_char_cb;
    g_knl_callback.device_init = gss_raw_device_op_init_null;
}

static void server_set_kernel_callback(void)
{
    g_knl_callback.exec_default = sql_exec_default;
    g_knl_callback.set_vm_lob_to_knl = NULL;
    g_knl_callback.keep_stack_variant = sql_keep_stack_var;
    g_knl_callback.alloc_rm = server_alloc_resource_manager;
    g_knl_callback.release_rm = server_release_resource_manager;
    g_knl_callback.alloc_auton_rm = server_alloc_auton_resource_manager;
    g_knl_callback.release_auton_rm = server_release_auton_resource_manager;
    g_knl_callback.get_xa_xid = server_get_xa_xid;
    g_knl_callback.add_xa_xid = server_add_xa_xid;
    g_knl_callback.delete_xa_xid = server_delete_xa_xid;
    g_knl_callback.attach_suspend_rm = server_attach_suspend_resource_manager;
    g_knl_callback.detach_suspend_rm = server_detach_suspend_resource_manager;
    g_knl_callback.attach_pending_rm = server_attach_pending_resource_manager;
    g_knl_callback.detach_pending_rm = server_detach_pending_resource_manager;
    g_knl_callback.shrink_xa_rms = server_shrink_xa_rms;
    g_knl_callback.load_scripts = sql_load_scripts;
    g_knl_callback.exec_sql = NULL; 
    g_knl_callback.invalidate_cursor = clean_open_curs;
    g_knl_callback.invalidate_temp_cursor = clean_open_temp_curs;
    g_knl_callback.invalidate_space = invalidate_tablespaces;
    g_knl_callback.decode_check_cond = NULL;
    g_knl_callback.match_cond_tree = sql_match_cond_tree;
    g_knl_callback.dc_recycle_external = dc_recycle_external;
    g_knl_callback.pl_drop_object = server_callback_null_func2_uid;
    g_knl_callback.pl_db_drop_triggers = server_callback_null_func2_dc;
    g_knl_callback.pl_update_tab_from_sysproc = server_callback_null_func4_dc_text;
    g_knl_callback.pl_free_trig_entity_by_tab = server_callback_null_func2_dc_void;
    g_knl_callback.pl_drop_triggers_entry = server_callback_null_func2_dc_void;
    g_knl_callback.pl_logic_log_replay = server_callback_null_func3_ptr;
    g_knl_callback.exec_check = sql_execute_check;
    g_knl_callback.func_idx_exec = sql_exec_index_col_func;
    g_knl_callback.kill_session = srv_mark_sess_killed;
    g_knl_callback.init_sql_maps = init_sql_maps_null;
    g_knl_callback.get_sql_text = server_get_sql_text;
    g_knl_callback.set_min_scn = server_set_min_scn;
    server_set_kernel_callback_ex();
}

status_t server_get_home(void)
{
    bool32 exist;
    char home[GS_MAX_PATH_BUFFER_SIZE];

    if (g_database_home == NULL) {
        g_database_home = getenv(GS_ENV_HOME);
        if (g_database_home == NULL) {
            GS_THROW_ERROR(ERR_HOME_PATH_NOT_FOUND, GS_ENV_HOME);
            return GS_ERROR;
        }
    }
    GS_RETURN_IFERR(realpath_file(g_database_home, home, GS_MAX_PATH_BUFFER_SIZE));

    exist = cm_check_exist_special_char(home, (uint32)strlen(home));
    if (exist) {
        GS_THROW_ERROR(ERR_INVALID_DIR, GS_ENV_HOME);
        return GS_ERROR;
    }

    exist = cm_dir_exist(home);
    if (!exist) {
        GS_THROW_ERROR(ERR_HOME_PATH_NOT_FOUND, GS_ENV_HOME);
        return GS_ERROR;
    }

    cm_trim_home_path(g_database_home, (uint32)strlen(g_database_home));
    MEMS_RETURN_IFERR(strncpy_s(g_instance->home, GS_MAX_PATH_BUFFER_SIZE, g_database_home, strlen(g_database_home)));

    return GS_SUCCESS;
}

char *start_up_mode(db_startup_phase_t phase)
{
    switch (phase) {
        case STARTUP_NOMOUNT:
            return "nomount";

        case STARTUP_MOUNT:
            return "mount";

        default:
            return "normal";
    }
}

static void server_reg_os_rinfo(void)
{
    for (int i = 0; i < TOTAL_OS_RUN_INFO_TYPES; i++) {
        g_instance->os_rinfo[i].desc = &g_os_stat_desc_array[i];
    }
}

static void server_init_lob_locator(void)
{
    g_instance->sql.sql_lob_locator_size = MAX(KNL_LOB_LOCATOR_SIZE, VM_LOB_LOCATOR_SIZE);
}

static void server_init_uuid_info(st_uuid_info_t *uuid_info)
{
    uuid_info->lock = 0;
    uuid_info->self_increase_seq = cm_random(GS_MAX_RAND_RANGE);
    cm_init_mac_address(uuid_info->mac_address, GS_MAC_ADDRESS_LEN);
}

status_t server_init_g_instance(void)
{
    errno_t errcode;
    g_instance = (instance_t *)malloc(sizeof(instance_t));
    if (g_instance == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(instance_t), "creating instance");
        return GS_ERROR;
    }

    errcode = memset_s(g_instance, sizeof(instance_t), 0, sizeof(instance_t));
    if (errcode != EOK) {
        CM_FREE_PTR(g_instance);
        GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return GS_ERROR;
    }

    g_instance->lock_fd = -1;
    g_instance->inc_rebalance = GS_FALSE;
    g_instance->frozen_starttime = 0;
    g_instance->frozen_waittime = 0;
    cm_rand((uchar *)g_instance->rand_for_md5, GS_KDF2SALTSIZE);
    server_init_uuid_info(&g_instance->g_uuid_info);

    errcode = memset_s(g_dtc, sizeof(dtc_instance_t), 0, sizeof(dtc_instance_t));
    if (errcode != EOK) {
        CM_FREE_PTR(g_instance);
        GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return GS_ERROR;
    }

    g_dtc->kernel = &g_instance->kernel;
    shutdown_context_t *ctx = &g_instance->shutdown_ctx;
    dls_init_latch(&(ctx->shutdown_latch), DR_TYPE_SHUTDOWN, 0, 0);

    return GS_SUCCESS;
}

status_t server_sysdba_privilege()
{
    // avoid to rewriting privilege file, when same socket listen conflict. init sysdba must after start lsnr
    if (GET_ENABLE_SYSDBA_LOGIN) {
        if (server_init_sysdba_privilege() != GS_SUCCESS) {
            server_instance_destroy();
            GS_LOG_RUN_ERR("[Privilege] failed to init Sysdba Privilege");
            return GS_ERROR;
        }
    } else {
        (void)server_remove_sysdba_privilege();
    }
    return GS_SUCCESS;
}

static status_t server_init_parallel_sessions(void)
{
    sql_par_pool_t *par_pool = &g_instance->sql_par_pool;
    uint32 i, id;

    // init sql parallel sessions
    par_pool->lock = 0;
    par_pool->used_sessions = 0;

    for (i = 0; i < par_pool->max_sessions; i++) {
        GS_RETURN_IFERR(server_alloc_reserved_session(&id));
        g_instance->session_pool.sessions[id]->type = SESSION_TYPE_SQL_PAR;
        g_instance->session_pool.sessions[id]->knl_session.match_cond = sql_match_cond;
        par_pool->sessions[i] = g_instance->session_pool.sessions[id];
    }

    g_instance->kernel.reserved_sessions += par_pool->max_sessions;

    // init stat of parallel
    par_pool->par_stat.parallel_executions = 0;
    par_pool->par_stat.under_trans_cnt = 0;
    par_pool->par_stat.res_limited_cnt = 0;
    par_pool->par_stat.break_proc_cnt = 0;

    return GS_SUCCESS;
}

status_t server_lock_db(void)
{
    char file_name[GS_FILE_NAME_BUFFER_SIZE] = { 0 };

    PRTS_RETURN_IFERR(snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s/%s",
        g_instance->home, g_lock_file));

    if (cm_open_file(file_name, O_CREAT | O_RDWR | O_BINARY, &g_instance->lock_fd) != GS_SUCCESS) {
        return GS_ERROR;
    }

    status_t ret = cm_lock_fd(g_instance->lock_fd);
    if (ret != GS_SUCCESS) {
        cm_show_lock_info(g_instance->lock_fd);
    }
    return ret;
}

void server_unlock_db(void)
{
    GS_LOG_RUN_INF("Unlock db lock at %d.", g_instance->lock_fd);
    if (g_instance->lock_fd != -1) {
        cm_unlock_fd(g_instance->lock_fd);
        cm_close_file(g_instance->lock_fd);
    }
}

static void server_setup_json_mpool(void)
{
    g_instance->sql.json_mpool.lock = 0;
    g_instance->sql.json_mpool.used_json_dyn_buf = 0;
}

static void server_set_locale(void)
{
    if (setlocale(LC_ALL, "") == NULL) {
        g_instance->is_setlocale_success = GS_FALSE;
        GS_LOG_RUN_ERR("Set locale failed, errno %d", errno);
        printf("Set locale failed, errno %d\n", errno);
        return;
    }
    g_instance->is_setlocale_success = GS_TRUE;
}

status_t server_backup_keyfile(char *event)
{
    char keyfile_name[GS_FILE_NAME_BUFFER_SIZE];

    errno_t ret = snprintf_s(keyfile_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s.bak.%s",
        g_instance->kernel.attr.kmc_key_files[0].name, event);
    knl_securec_check_ss(ret);

    if (cm_kmc_export_keyfile(keyfile_name) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("fail to export curr ksf to %s", keyfile_name);
        return GS_ERROR;
    }

    ret = snprintf_s(keyfile_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s.bak.before.%s",
        g_instance->kernel.attr.kmc_key_files[1].name, event);
    knl_securec_check_ss(ret);

    if (cm_kmc_export_keyfile(keyfile_name) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("fail to export curr ksf to %s", keyfile_name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t server_update_server_masterkey(void)
{
    uint32 keyid = 0;
    uint32 count = 0;

    if (cm_get_masterkey_count(&count) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (count >= GS_KMC_MAX_MK_COUNT) {
        GS_LOG_RUN_WAR("find total masterkey count %u le max masterkey count %u", count, GS_KMC_MAX_MK_COUNT);
        return GS_ERROR;
    }

    if (cm_kmc_create_masterkey(GS_KMC_SERVER_DOMAIN, &keyid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_kmc_active_masterkey(GS_KMC_SERVER_DOMAIN, keyid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("finish update server masterkey");
    return GS_SUCCESS;
}

int g_instance_startuped = GS_ERROR;
int is_instance_startuped(void)
{
    return g_instance_startuped;
}

status_t server_instance_startup(db_startup_phase_t phase, bool32 is_coordinator, bool32 is_datanode, bool32 is_gts)
{
#ifdef WIN32
    if (GS_SUCCESS != epoll_init()) {
        printf("Failed to initialize epoll");
        return GS_ERROR;
    }
#endif
    if (cm_start_timer(g_timer()) != GS_SUCCESS) {
        printf("Aborted due to starting timer thread");
        return GS_ERROR;
    }

    if (server_init_drbg() != GS_SUCCESS) {
        printf("Aborted due to initialize ssl drbg");
        return GS_ERROR;
    }

    if (server_init_g_instance() != GS_SUCCESS) {
        return GS_ERROR;
    }
    (void)server_setup_json_mpool();
    (void)server_set_locale();
    (void)server_init_ip_white();
    (void)server_init_pwd_black();
    (void)server_init_ip_login_addr();

    if (server_get_home() != GS_SUCCESS) {
        CM_FREE_PTR(g_instance);
        printf("%s\n", "Failed to get home");
        return GS_ERROR;
    }

    if (server_load_params() != GS_SUCCESS) {
        CM_FREE_PTR(g_instance);
        GS_LOG_RUN_ERR("failed to load params");
        printf("%s\n", "Failed to load params");
        return GS_ERROR;
    }

    (void)cm_lic_init();
    server_print_params();

    if (server_lock_db() != GS_SUCCESS) {
        CM_FREE_PTR(g_instance);
        GS_LOG_RUN_ERR("Another db is running");
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("starting instance(%s), memory usage(%lu)", start_up_mode(phase), cm_print_memory_usage());
    printf("starting instance(%s)\n", start_up_mode(phase));

    if (server_load_hba(GS_TRUE) != GS_SUCCESS) {
        CM_FREE_PTR(g_instance);
        GS_LOG_RUN_ERR("failed to load hba");
        return GS_ERROR;
    }
    if (server_load_pbl(GS_TRUE) != GS_SUCCESS) {
        CM_FREE_PTR(g_instance);
        GS_LOG_RUN_ERR("failed to load pbl");
        return GS_ERROR;
    }

#ifndef WIN32
    if (signal_cap_handle_reg() != GS_SUCCESS) {
        CM_FREE_PTR(g_instance);
        GS_LOG_RUN_ERR("Failed to initialize SIGSEGV func");
        return GS_ERROR;
    }
#endif

    server_set_kernel_callback();
    server_reg_os_rinfo();
    server_regist_dynamic_views();

    if (server_create_sga() != GS_SUCCESS) {
        CM_FREE_PTR(g_instance);
        GS_LOG_RUN_ERR("failed to create sga");
        return GS_ERROR;
    }

    if (sql_instance_startup() != GS_SUCCESS) {
        server_destroy_sga();
        CM_FREE_PTR(g_instance);
        GS_LOG_RUN_ERR("failed to startup sql instance");
        return GS_ERROR;
    }

    if (server_init_session_pool() != GS_SUCCESS) {
        server_destroy_sga();
        CM_FREE_PTR(g_instance);
        GS_LOG_RUN_ERR("failed to init session pool");
        return GS_ERROR;
    }

    if (server_kernel_startup(is_coordinator) != GS_SUCCESS) {
        knl_shutdown(NULL, &g_instance->kernel, GS_FALSE);
        server_destroy_sga();
        server_destory_reserved_session();
        CM_FREE_PTR(g_instance);
        GS_LOG_RUN_ERR("failed to startup kernel");
        return GS_ERROR;
    }

    /* Caution: parallel sessions pool init below the server_kernel_startup, because inst->attr.cursor_size assignment
     in knl_init_attr */
    if (server_init_parallel_sessions() != GS_SUCCESS) {
        knl_shutdown(NULL, &g_instance->kernel, GS_FALSE);
        server_destroy_sga();
        server_destory_reserved_session();
        CM_FREE_PTR(g_instance);
        GS_LOG_RUN_ERR("failed to init parallel sessions");
        return GS_ERROR;
    }

    /* init parallel thread pool */
    cm_init_thread_pool(&g_instance->par_thread_pool);

    server_init_lob_locator();

    // create reactor thread pool if in shared mode
    if (reactor_create_pool() != GS_SUCCESS) {
        knl_shutdown(NULL, &g_instance->kernel, GS_FALSE);
        server_destroy_sga();
        server_destory_reserved_session();
        CM_FREE_PTR(g_instance);
        GS_LOG_RUN_ERR("failed to create reactor pool");
        return GS_ERROR;
    }

    if (server_start_lsnr() != GS_SUCCESS) {
        knl_shutdown(NULL, &g_instance->kernel, GS_FALSE);
        reactor_destroy_pool();
        server_destroy_sga();
        server_destory_reserved_session();
        CM_FREE_PTR(g_instance);
        GS_LOG_RUN_ERR("failed to start lsnr");
        return GS_ERROR;
    }
    // avoid to rewriting privilege file, when same socket listen conflict. init sysdba must after start lsnr
    if (server_sysdba_privilege() != GS_SUCCESS) {
        return GS_ERROR;
    }
    // create ssl acceptor
    if (server_init_ssl_communication() != GS_SUCCESS) {
        server_instance_destroy();
        GS_LOG_RUN_ERR("failed to init SSL communication");
        return GS_ERROR;
    }

    g_instance->kernel.is_ssl_initialized = GS_TRUE;

    if (phase == STARTUP_MOUNT || phase == STARTUP_OPEN) {
        if (server_kernel_open(phase) != GS_SUCCESS) {
            server_instance_destroy();
            GS_LOG_RUN_ERR("failed to open kernel");
            return GS_ERROR;
        }
    }


    g_instance->lsnr_abort_status = GS_FALSE;
    if (cm_regist_signal(SIGUSR1, handle_signal_fatal) != GS_SUCCESS) {
        server_instance_destroy();
        GS_LOG_RUN_ERR("failed to initialize SIGUSR1 func");
        return GS_ERROR;
    }

#ifndef WITH_DAAC
    if (mq_srv_init() != GS_SUCCESS) {
        server_instance_destroy();
        printf("Aborted due to start mq");
        return GS_ERROR;
    }
#endif

    if (init_mysql_inst() != GS_SUCCESS) {
        GS_LOG_RUN_INF("init_mysql_inst failed.");
        printf("init_mysql_inst failed.\n");
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("instance started, memory usage(%lu)", cm_print_memory_usage());
    printf("%s\n", "instance started");
    fflush(stdout);
    g_instance_startuped = GS_SUCCESS;
    return GS_SUCCESS;
}

void server_instance_destroy(void)
{
    while (1) {
        if (g_instance->shutdown_ctx.phase == SHUTDOWN_PHASE_DONE || cm_spin_try_lock(&g_instance->kernel.db.lock)) {
            break;
        }
        cm_sleep(SHUTDOWN_WAIT_INTERVAL);
        GS_LOG_RUN_INF("wait for shutdown to complete");
    }

    if (g_instance->shutdown_ctx.phase == SHUTDOWN_PHASE_DONE) {
        return;
    }

    g_instance->shutdown_ctx.phase = SHUTDOWN_PHASE_INPROGRESS;
    g_instance->shutdown_ctx.session = NULL;
    g_instance->shutdown_ctx.mode = SHUTDOWN_MODE_ABORT;

    if (GS_SUCCESS != server_wait_agents_completed()) {
        GS_LOG_RUN_INF("kill canceled, all listener resumed");
        reactor_resume_pool();
        server_resume_lsnr(LSNR_TYPE_ALL);
        g_instance->shutdown_ctx.phase = SHUTDOWN_PHASE_NOT_BEGIN;
        cm_spin_unlock(&g_instance->kernel.db.lock);
        return;
    }
    server_close_threads(GS_TRUE);

    server_deinit_resource();
    g_instance->shutdown_ctx.phase = SHUTDOWN_PHASE_DONE;
    CM_FREE_PTR(g_instance);
}

status_t server_stop_all_session(shutdown_context_t *ctx)
{
    knl_session_t *session = g_instance->kernel.sessions[SESSION_ID_KERNEL];
    switch (ctx->mode) {
        case SHUTDOWN_MODE_IMMEDIATE:
            if (session->kernel->db.status == DB_STATUS_RECOVERY) {
                GS_THROW_ERROR(ERR_RESTORE_IN_PROGRESS);
                return GS_ERROR;
            }
            server_kill_all_session(ctx->session, GS_FALSE);
            /* fall-through */
        case SHUTDOWN_MODE_NORMAL:
            if (session->kernel->db.status == DB_STATUS_RECOVERY) {
                GS_THROW_ERROR(ERR_RESTORE_IN_PROGRESS);
                return GS_ERROR;
            }

            // If log receiver thread has been created, need to first stop it.
            if (session->kernel->lrcv_ctx.session != NULL) {
                lrcv_close(session);
            }

            return server_wait_all_session_be_killed(ctx->session);
        case SHUTDOWN_MODE_ABORT:
            server_kill_all_session(ctx->session, GS_TRUE);
            return server_wait_all_session_be_killed(ctx->session);
        default:
            GS_THROW_ERROR(ERR_INVALID_OPERATION, "shutdown signal");
            return GS_ERROR;
    }
}

static status_t server_wait_agents_completed(void)
{
    shutdown_context_t *ctx = &g_instance->shutdown_ctx;

    GS_LOG_RUN_INF("begin to shutdown, mode %s", g_shutdown_mode_desc[ctx->mode]);

    GS_LOG_RUN_INF("begin to pause all listener");
    server_pause_lsnr(LSNR_TYPE_ALL);

    if (ctx->mode != SHUTDOWN_MODE_NORMAL) {
        GS_LOG_RUN_INF("begin to pause reactor");
        reactor_pause_pool();
    }

    // stop all session
    if (ctx->session != NULL) {
        GS_LOG_RUN_INF("begin to stop all session");
        if (GS_SUCCESS != server_stop_all_session(ctx)) {
            GS_LOG_RUN_ERR("stop all session failed");
            return GS_ERROR;
        }
    } else {
        GS_LOG_RUN_INF("begin to stop all session without self session");
        server_kill_all_session(NULL, GS_FALSE);
        server_wait_all_session_free();
    }

    GS_LOG_RUN_INF("wait all agents done ended");
    return GS_SUCCESS;
}

static void server_close_threads(bool32 knl_flag)
{
    shutdown_context_t *ctx = &g_instance->shutdown_ctx;
    bool32 need_ckpt = GS_FALSE;
    // stop listener
    GS_LOG_RUN_INF("begin to stop all listener");
    server_stop_lsnr(LSNR_TYPE_ALL);

    // stop reactor
    GS_LOG_RUN_INF("begin to stop reactor");
    reactor_destroy_pool();

    // stop parallel threads
    GS_LOG_RUN_INF("begin to stop parallel thread");
    cm_destroy_thread_pool(&g_instance->par_thread_pool);

    // stop rsrc manager
    GS_LOG_RUN_INF("begin to stop resource manager");

    if (knl_flag == GS_TRUE) {
        need_ckpt = ctx->mode > SHUTDOWN_MODE_SIGNAL ? GS_FALSE : GS_TRUE;
        GS_LOG_RUN_INF("begin to stop kernel");
        knl_shutdown(NULL, &g_instance->kernel, need_ckpt);
    }
}

static void server_deinit_resource()
{
    // free ssl context
    if (g_instance->ssl_acceptor_fd != NULL) {
        GS_LOG_RUN_INF("begin to free ssl acceptor fd.");
        cs_ssl_free_context(g_instance->ssl_acceptor_fd);
        g_instance->ssl_acceptor_fd = NULL;
    }

    GS_LOG_RUN_INF("begin to destory reserved session.");
    server_destory_reserved_session();

    GS_LOG_RUN_INF("begin to destory user session.");
    server_destory_session();

    GS_LOG_RUN_INF("begin to finalize kmc.");
    (void)cm_kmc_finalize();

    GS_LOG_RUN_INF("begin to destory sequence pool.");

    GS_LOG_RUN_INF("begin to free memory occupied by SGA.");
    server_destroy_sga();
    GS_LOG_RUN_INF("begin to free configuration buffer.");
    cm_free_config_buf(&g_instance->config);
    GS_LOG_RUN_INF("begin to free ctrl buffer.");
    cm_aligned_free(&g_instance->kernel.db.ctrl.buf);

    GS_LOG_RUN_INF("finish to shutdown, mode %s, db lock %s", g_shutdown_mode_desc[g_instance->shutdown_ctx.mode],
        g_instance->kernel.db.lock ? "true" : "false");
}

status_t server_shutdown_wait(session_t *session, shutdown_mode_t mode, shutdown_context_t *ctx)
{
    knl_session_t *knl_session = g_instance->kernel.sessions[SESSION_ID_KERNEL];
    bool32 is_prohibited = GS_TRUE;

    // 1.shutdown is prohibited during some operations that can't be interrupted(include shutdown)
    if (!cm_spin_try_lock(&g_instance->kernel.db.lock)) {
        GS_THROW_ERROR(ERR_SHUTDOWN_IN_PROGRESS, session->knl_session.id);
        return GS_ERROR;
    }

    // if reform in progress, shutdown is not allowed;
    if (DB_IS_CLUSTER(&(session->knl_session))) {
        if (!rc_reform_trigger_disable()) {
            cm_spin_unlock(&g_instance->kernel.db.lock);
            GS_THROW_ERROR(ERR_SHUTDOWN_IN_PROGRESS, session->knl_session.id);
            return GS_ERROR;
        }
    }

    do {
        // 2.if rcy is looping,shutdown is allowed to break loop
        cm_spin_lock(&g_instance->kernel.rcy_ctx.lock, NULL);
        if (knl_session->kernel->rcy_ctx.is_working) {
            g_instance->kernel.rcy_ctx.is_closing = GS_TRUE;
            cm_spin_unlock(&g_instance->kernel.rcy_ctx.lock);
            is_prohibited = GS_FALSE;
            break;
        }
        cm_spin_unlock(&g_instance->kernel.rcy_ctx.lock);

        // 3.if db enter server_instance_loop,shutdown is allowed
        if (g_instance->shutdown_ctx.enabled) {
            is_prohibited = GS_FALSE;
        }
    } while (0);

    if (is_prohibited) {
        cm_spin_unlock(&g_instance->kernel.db.lock);
        rc_reform_trigger_enable();
        GS_THROW_ERROR(ERR_SHUTDOWN_IN_PROGRESS, session->knl_session.id);
        return GS_ERROR;
    }

    /* shutdown is always divided into 3 steps:
    step 1: wait other agents process done
    step 2: release sql/sharding/kernel threads
    step 3: free memory resource, for sga
    step 2, step 3 should be processed at main thread */
    ctx->phase = SHUTDOWN_PHASE_INPROGRESS;
    ctx->session = session;
    ctx->mode = mode;

    if (GS_SUCCESS != server_wait_agents_completed()) {
        GS_LOG_RUN_INF("shutdown canceled, all listener resumed");
        reactor_resume_pool();
        server_resume_lsnr(LSNR_TYPE_ALL);
        ctx->phase = SHUTDOWN_PHASE_NOT_BEGIN;
        cm_spin_unlock(&g_instance->kernel.db.lock);
        rc_reform_trigger_enable();
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t server_shutdown(session_t *session, shutdown_mode_t mode)
{
    shutdown_context_t *ctx = &g_instance->shutdown_ctx;
    bool32 need_ckpt;

    if (session->knl_session.rm->txn != NULL) {
        if (session->knl_session.rm->txn->status != (uint8)XACT_END) {
            GS_THROW_ERROR(ERR_SHUTDOWN_IN_TRANS);
            return GS_ERROR;
        }
    }

    if (DB_IS_CLUSTER(&(session->knl_session))) {
        if (!dls_latch_timed_x(&(session->knl_session), &(ctx->shutdown_latch), session->knl_session.id, 1, NULL)) {
            GS_LOG_RUN_WAR("sql get shutdown lock failed, other node in shutdown progress");
            GS_THROW_ERROR(ERR_SHUTDOWN_IN_PROGRESS, session->knl_session.id);
            return GS_ERROR;
        }
        GS_LOG_RUN_INF("sql get shutdown lock, execute shutdown");
    }

    if (server_shutdown_wait(session, mode, ctx) != GS_SUCCESS) {
        if (DB_IS_CLUSTER(&(session->knl_session))) {
            dls_unlatch(&(session->knl_session), &(ctx->shutdown_latch), NULL);
        }
        return GS_ERROR;
    }

    need_ckpt = ctx->mode > SHUTDOWN_MODE_SIGNAL ? GS_FALSE : GS_TRUE;
    GS_LOG_RUN_INF("begin to stop kernel");
    knl_shutdown(NULL, &g_instance->kernel, need_ckpt);
    CM_MFENCE;
    ctx->phase = SHUTDOWN_PHASE_DONE;
    GS_LOG_RUN_INF("end of stop kernel");
    return GS_SUCCESS;
}

void server_instance_abort()
{
    shutdown_context_t *ctx = &g_instance->shutdown_ctx;
    if (!cm_spin_try_lock(&g_instance->kernel.db.lock)) {
        return;
    }
    if (g_instance->shutdown_ctx.phase != SHUTDOWN_PHASE_NOT_BEGIN) {
        return;
    }
    ctx->session = NULL;
    ctx->phase = SHUTDOWN_PHASE_INPROGRESS;
    ctx->mode = SHUTDOWN_MODE_SIGNAL;
    (void)server_wait_agents_completed();
    server_close_threads(GS_TRUE);
    server_deinit_resource();
    ctx->phase = SHUTDOWN_PHASE_DONE;
}

bool32 server_is_kernel_reserve_session(session_type_e type)
{
    if (type == SESSION_TYPE_KERNEL_RESERVE) {
        return GS_TRUE;
    }
    return GS_FALSE;
}

#ifdef __cplusplus
}
#endif
