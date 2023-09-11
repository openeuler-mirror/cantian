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
 * gsc_balance.c
 *
 *
 * IDENTIFICATION
 * src/driver/gsc/gsc_balance.c
 *
 * -------------------------------------------------------------------------
 */
#include <stdlib.h>
#include "cm_text.h"
#include "gsc_balance.h"
#include "cm_error.h"
#include "cm_thread.h"
#include "gsc_conn.h"

#ifdef __cplusplus
extern "C" {
#endif

static cluster_manager_t g_cluster_manager = {
    // cluster global infos
    .lock = 0,
    .inited = GS_FALSE,
    .thread_process = GS_FALSE,
};

static inline cluster_manager_t *get_cls_mgr_instance()
{
    if (!g_cluster_manager.inited) {
        cm_spin_lock(&g_cluster_manager.lock, NULL);
        if (!g_cluster_manager.inited) {
            cm_create_list2(&g_cluster_manager.clusters, NODE_LIST_EXTEND_SIZE, MAX_LIST_EXTENTS, sizeof(cluster_t));
            cm_create_list2(&g_cluster_manager.check_pool, NODE_LIST_EXTEND_SIZE, MAX_LIST_EXTENTS,
                sizeof(check_entry_t));
            g_cluster_manager.inited = GS_TRUE;
        }
        cm_spin_unlock(&g_cluster_manager.lock);
    }

    return &g_cluster_manager;
}

static inline bool32 find_info_from_list(list_t *list, text_t *url_wt)
{
    text_t new_node_url, node_weight;
    cm_split_text(url_wt, '_', '\0', &new_node_url, &node_weight);

    node_info_t *node_info = NULL;
    for (uint32 i = 0; i < list->count; i++) {
        node_info = (node_info_t *)cm_list_get(list, i);
        if (cm_text_equal_ins(&new_node_url, &node_info->node_url)) {
            return GS_TRUE;
        }
    }
    return GS_FALSE;
}

// if has weight: ip:port_wt, like: 127.0.0.1:1611_0.5
static inline status_t init_node_info(node_info_t *node, text_t *url)
{
    text_t new_node_url, node_weight;
    cm_split_text(url, '_', '\0', &new_node_url, &node_weight);
    node->node_url = new_node_url;

    if (node_weight.len == 0) {
        node->weight = 1;
    } else {
        GS_RETURN_IFERR(cm_text2real(&node_weight, &node->weight));
        if (cm_compare_double(node->weight, 0) != 1) {
            GS_THROW_ERROR(ERR_VALUE_ERROR, "the weight value of url must be greater than zero");
            return GS_ERROR;
        }
    }

    node->lock = 0;
    node->ref_count = 0;
    node->status = NODE_STATUS_ONLINE;
    node->check_entry = NULL;

    return GS_SUCCESS;
}

static status_t cluster_ssl_copy(char *conn_ssl, char *cluster_ssl, uint32 len)
{
    if (conn_ssl == NULL) {
        return GS_SUCCESS;
    }

    if (len < strlen(conn_ssl)) {
        GS_THROW_ERROR(ERR_INVALID_FILE_NAME, conn_ssl, len);
        return GS_ERROR;
    }

    errno_t errcode = memcpy_s(cluster_ssl, len, conn_ssl, strlen(conn_ssl));
    if (errcode != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return GS_ERROR;
    }

    cluster_ssl[strlen(conn_ssl)] = '\0';
    return GS_SUCCESS;
}

// init cluster ssl for heart beat
static status_t init_cluster_ssl(clt_options_t *conn_options, cluster_info_t *cluster_info, const char *ssl_keypwd)
{
    cluster_info->ssl_mode = conn_options->ssl_mode;
    GS_RETURN_IFERR(cluster_ssl_copy(conn_options->ssl_ca, cluster_info->ssl_ca, GS_FILE_NAME_BUFFER_SIZE));
    GS_RETURN_IFERR(cluster_ssl_copy(conn_options->ssl_cert, cluster_info->ssl_cert, GS_FILE_NAME_BUFFER_SIZE));
    GS_RETURN_IFERR(cluster_ssl_copy(conn_options->ssl_key, cluster_info->ssl_key, GS_FILE_NAME_BUFFER_SIZE));
    GS_RETURN_IFERR(cluster_ssl_copy(conn_options->ssl_crl, cluster_info->ssl_crl, GS_FILE_NAME_BUFFER_SIZE));
    GS_RETURN_IFERR(cluster_ssl_copy(conn_options->ssl_cipher, cluster_info->ssl_cipher, GS_PARAM_BUFFER_SIZE));

    cluster_info->ssl_keypwd[0] = 0x00;
    if (strlen(ssl_keypwd) != 0) {
        GS_RETURN_IFERR((status_t)gsc_encrypt_password((char *)ssl_keypwd, (unsigned int)strlen(ssl_keypwd),
            cluster_info->local_key, cluster_info->factor_key, cluster_info->ssl_keypwd, &cluster_info->keypwd_len));
    }
    return GS_SUCCESS;
}

static status_t init_cluster_cipher(cluster_info_t *cluster_info)
{
    if ((uint32)strlen(cluster_info->factor_key) != GS_MAX_FACTOR_KEY_STR_LEN) {
        char rand_buf[GS_AES256KEYSIZE / 2 + 4];
        uint32 rand_len = GS_AES256KEYSIZE / 2;

        MEMS_RETURN_IFERR(memset_s(cluster_info->local_key, GS_MAX_LOCAL_KEY_LEN, 0, GS_MAX_LOCAL_KEY_LEN));
        MEMS_RETURN_IFERR(memset_s(cluster_info->factor_key, GS_MAX_FACTOR_KEY_LEN, 0, GS_MAX_FACTOR_KEY_LEN));

        /* generate 128bit rand_buf and then base64 encode */
        GS_RETURN_IFERR(cm_rand((uchar *)rand_buf, rand_len));
        uint32 rand_factor_key_len = GS_MAX_FACTOR_KEY_LEN;
        GS_RETURN_IFERR(cm_base64_encode((uchar *)rand_buf, rand_len, cluster_info->factor_key, &rand_factor_key_len));
        GS_RETURN_IFERR(cm_generate_work_key(cluster_info->factor_key, cluster_info->local_key, GS_MAX_LOCAL_KEY_LEN));
    }
    return GS_SUCCESS;
}

static status_t init_cluster(clt_conn_t *conn, text_t *cluster_url, cluster_t **cluster)
{
    cluster_t *cluster_in = *cluster;
    GS_RETURN_IFERR(init_cluster_cipher(&cluster_in->cluster_info));

    (*cluster)->lock = 0;
    cm_create_list2(&(*cluster)->node_list, NODE_LIST_EXTEND_SIZE, MAX_LIST_EXTENTS, sizeof(node_info_t));

    text_t *new_cls_url = &(*cluster)->cluster_url;
    GS_RETURN_IFERR(clt_strndup(cluster_url->str, cluster_url->len, &(new_cls_url->str)));
    if (new_cls_url->str == NULL) {
        CLT_THROW_ERROR(conn, ERR_ALLOC_MEMORY, (uint64)(cluster_url->len + 1), "create cluster url");
        return GS_ERROR;
    }
    new_cls_url->len = cluster_url->len;

    text_t left_url = *new_cls_url;
    text_t tmp_url, node_url_wt;
    node_info_t *node_info = NULL;
    while (left_url.len > 0) {
        tmp_url = left_url;
        // url like: 127.0.0.1:1611_0.5,127.0.0.1:1612_1.5...
        cm_split_text(&tmp_url, ',', '\0', &node_url_wt, &left_url);

        if (find_info_from_list(&(*cluster)->node_list, &node_url_wt)) {
            continue;
        }

        if (cm_list_new(&(*cluster)->node_list, (void **)&node_info) != GS_SUCCESS) {
            cm_destroy_list(&(*cluster)->node_list);
            CM_FREE_PTR(new_cls_url->str);
            clt_copy_local_error(conn);
            return GS_ERROR;
        }

        if (init_node_info(node_info, &node_url_wt) != GS_SUCCESS) {
            cm_destroy_list(&(*cluster)->node_list);
            CM_FREE_PTR(new_cls_url->str);
            clt_copy_local_error(conn);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static inline status_t get_cluster_info(clt_conn_t *conn, text_t *cluster_url, cluster_t **cluster)
{
    list_t *cluster_list = &get_cls_mgr_instance()->clusters;

    cluster_t *tmp_cluster = NULL;
    uint32 count = g_cluster_manager.cluster_count;
    for (uint32 i = 0; i < count; i++) {
        tmp_cluster = (cluster_t *)cm_list_get(cluster_list, i);
        if (cm_text_equal_ins(cluster_url, &tmp_cluster->cluster_url)) {
            *cluster = tmp_cluster;
            return GS_SUCCESS;
        }
    }

    // g_cluster_manager must be inited here
    cm_spin_lock(&g_cluster_manager.lock, NULL);
    uint32 count2 = g_cluster_manager.cluster_count;
    for (uint32 i = count; i < count2; i++) {
        tmp_cluster = (cluster_t *)cm_list_get(cluster_list, i);
        if (cm_text_equal_ins(cluster_url, &tmp_cluster->cluster_url)) {
            *cluster = tmp_cluster;
            cm_spin_unlock(&g_cluster_manager.lock);
            return GS_SUCCESS;
        }
    }

    if (count2 < cluster_list->count) {
        tmp_cluster = cm_list_get(cluster_list, count2);
    } else {
        if (cm_list_new(cluster_list, (void **)&tmp_cluster) != GS_SUCCESS) {
            cm_spin_unlock(&g_cluster_manager.lock);
            clt_copy_local_error(conn);
            return GS_ERROR;
        }
    }

    if (init_cluster(conn, cluster_url, &tmp_cluster) != GS_SUCCESS) {
        cm_spin_unlock(&g_cluster_manager.lock);
        return GS_ERROR;
    }

    g_cluster_manager.cluster_count++;
    *cluster = tmp_cluster;
    cm_spin_unlock(&g_cluster_manager.lock);

    return GS_SUCCESS;
}

static inline bool32 find_from_node_ptlist_fast(ptlist_t *exclude_node_list, node_info_t *node)
{
    for (uint32 i = 0; i < exclude_node_list->count; i++) {
        node_info_t *node_info = (node_info_t *)cm_ptlist_get(exclude_node_list, i);
        // exclude_node_list and node are all from same cluster, so if they are same,there addr must be same
        if (node_info == node) {
            return GS_TRUE;
        }
    }
    return GS_FALSE;
}

static status_t update_min_ref_node(clt_conn_t *conn, ptlist_t *min_nodes, node_info_t *tmp_node, node_info_t *min_node)
{
    double min_redio, tmp_redio;

    if (min_nodes->count == 0) {
        if (cm_ptlist_add(min_nodes, tmp_node) != GS_SUCCESS) {
            cm_destroy_ptlist(min_nodes);
            clt_copy_local_error(conn);
            return GS_ERROR;
        }
    } else {
        min_node = cm_ptlist_get(min_nodes, 0);
        min_redio = min_node->ref_count / min_node->weight;
        tmp_redio = tmp_node->ref_count / tmp_node->weight;
        if (min_redio >= tmp_redio) {
            if (min_redio > tmp_redio) {
                cm_ptlist_reset(min_nodes);
            }

            if (cm_ptlist_add(min_nodes, tmp_node) != GS_SUCCESS) {
                cm_destroy_ptlist(min_nodes);
                clt_copy_local_error(conn);
                return GS_ERROR;
            }
        }
    }
    return GS_SUCCESS;
}

static inline status_t get_min_ref_node(clt_conn_t *conn, cluster_t *cluster, ptlist_t *exclude_nodes,
    node_info_t **node)
{
    node_info_t *tmp_node = NULL;
    node_info_t *min_node = NULL;
    ptlist_t min_nodes;
    cm_ptlist_init(&min_nodes);
    uint32 count = cluster->node_list.count;
    for (uint32 i = 0; i < count; i++) {
        tmp_node = cm_list_get(&cluster->node_list, i);
        if (tmp_node->status == NODE_STATUS_ONLINE && !find_from_node_ptlist_fast(exclude_nodes, tmp_node)) {
            // first value
            GS_RETURN_IFERR(update_min_ref_node(conn, &min_nodes, tmp_node, min_node));
        }
    }

    if (min_nodes.count > 0) {
        // find a random node to avoid parallel get same node
        min_node = cm_ptlist_get(&min_nodes, cm_random(min_nodes.count));
        cm_spin_lock(&min_node->lock, NULL);
        min_node->ref_count++;
        cm_spin_unlock(&min_node->lock);
        cm_destroy_ptlist(&min_nodes);

        *node = min_node;
        return GS_SUCCESS;
    } else {
        cm_destroy_ptlist(&min_nodes);
        CLT_THROW_ERROR(conn, ERR_CLT_CLUSTER_INVALID, "nodes count %u, but no useful nodes available", count);
        return GS_ERROR;
    }
}

static void heart_beat_stop(void)
{
    if (!g_cluster_manager.heart_thread.closed) {
        cm_close_thread(&g_cluster_manager.heart_thread);
    }
}

static void check_clusters();
/* heart thread */
static void heart_beat_proc(thread_t *thread)
{
    atexit(heart_beat_stop);
    while (!thread->closed) {
        check_clusters();
        cm_sleep(HEART_BEAT_CHECK_INTERVEL);
    }
}

static status_t init_heart_beat_thread(clt_conn_t *conn)
{
    if (!g_cluster_manager.thread_process) {
        cm_spin_lock(&g_cluster_manager.lock, NULL);
        if (!g_cluster_manager.thread_process) {
            if (cm_create_thread(heart_beat_proc, 0, (void *)NULL, &g_cluster_manager.heart_thread) == GS_SUCCESS) {
                g_cluster_manager.thread_process = GS_TRUE;
            } else {
                cm_spin_unlock(&g_cluster_manager.lock);
                clt_copy_local_error(conn);
                return GS_ERROR;
            }
        }
        cm_spin_unlock(&g_cluster_manager.lock);
    }
    return GS_SUCCESS;
}

status_t clt_cluster_connect(clt_conn_t *conn, text_t *cls_url, const char *user, const char *password,
    const char *ssl_keypwd, const char *tenant)
{
    // 1. get cluster item using cluster url
    cluster_t *cluster = NULL;
    GS_RETURN_IFERR(get_cluster_info(conn, cls_url, &cluster));

    // 2. get min ref node
    // buff for connect err detail
    int32 first_errcode = 0;
    char first_errmsg[GS_MESSAGE_BUFFER_SIZE];

    node_info_t *node = NULL;
    ptlist_t exclude_nodes;
    cm_ptlist_init(&exclude_nodes);
    errno_t errcode;
    uint32 count = cluster->node_list.count;
    for (uint32 i = 0; i < count; i++) {
        // find a min node and add ref_count
        if (get_min_ref_node(conn, cluster, &exclude_nodes, &node) != GS_SUCCESS) {
            cm_destroy_ptlist(&exclude_nodes);
            return GS_ERROR;
        }

        // get url
        char node_url[CM_MAX_IP_LEN + 1] = { 0 };
        if (cm_text2str(&node->node_url, node_url, CM_MAX_IP_LEN) != GS_SUCCESS) {
            cm_spin_lock(&node->lock, NULL);
            node->ref_count--;
            cm_spin_unlock(&node->lock);
            cm_destroy_ptlist(&exclude_nodes);
            clt_copy_local_error(conn);
            return GS_ERROR;
        }

        // get connection
        if (clt_connect(conn, node_url, user, password, tenant, CS_LOCAL_VERSION) != GS_SUCCESS) {
            cm_spin_lock(&node->lock, NULL);
            node->ref_count--;
            cm_spin_unlock(&node->lock);

            // record first error
            if (first_errcode == 0) {
                first_errcode = conn->error_code;
                errcode = memcpy_s(first_errmsg, GS_MESSAGE_BUFFER_SIZE, conn->message, strlen(conn->message));
                if (errcode != EOK) {
                    cm_destroy_ptlist(&exclude_nodes);
                    CLT_THROW_ERROR(conn, ERR_SYSTEM_CALL, "error system call", (errcode));
                    return GS_ERROR;
                }
                first_errmsg[strlen(conn->message)] = '\0';
            }

            if (cm_ptlist_add(&exclude_nodes, node) != GS_SUCCESS) {
                cm_destroy_ptlist(&exclude_nodes);
                clt_copy_local_error(conn);
                return GS_ERROR;
            }
            if (strlen(ssl_keypwd) != 0) {
                if (clt_set_conn_attr(conn, GSC_ATTR_SSL_KEYPWD, ssl_keypwd, (uint32)strlen(ssl_keypwd)) !=
                    GS_SUCCESS) {
                    cm_destroy_ptlist(&exclude_nodes);
                    clt_copy_local_error(conn);
                    return GS_ERROR;
                }
            }
        } else {
            // if node is not primary, do not connect
            if (conn->server_info.db_role != ROLE_PRIMARY) {
                if (cm_ptlist_add(&exclude_nodes, node) != GS_SUCCESS) {
                    cm_destroy_ptlist(&exclude_nodes);
                    clt_copy_local_error(conn);
                    return GS_ERROR;
                }
                continue;
            }

            conn->node = node;
            cm_spin_lock(&cluster->cluster_info.lock, NULL);

            // record ssl
            if (conn->options.ssl_mode != GSC_SSL_DISABLED) {
                if (init_cluster_ssl(&conn->options, &cluster->cluster_info, ssl_keypwd) != GS_SUCCESS) {
                    cm_spin_unlock(&cluster->cluster_info.lock);
                    gsc_disconnect((gsc_conn_t)conn);
                    cm_destroy_ptlist(&exclude_nodes);
                    clt_copy_local_error(conn);
                    return GS_ERROR;
                }
            }

            // record user and password
            errcode = memcpy_sp(cluster->cluster_info.user, GS_NAME_BUFFER_SIZE - 1, user, strlen(user));
            if (errcode != EOK) {
                cm_spin_unlock(&cluster->cluster_info.lock);
                gsc_disconnect((gsc_conn_t)conn);
                cm_destroy_ptlist(&exclude_nodes);
                CLT_THROW_ERROR(conn, ERR_SYSTEM_CALL, "error system call", (errcode));
                return GS_ERROR;
            }
            cluster->cluster_info.user[strlen(user)] = '\0';

            if ((status_t)gsc_encrypt_password((char *)password, (unsigned int)strlen(password),
                cluster->cluster_info.local_key, cluster->cluster_info.factor_key, cluster->cluster_info.cipher,
                &cluster->cluster_info.cipher_len) != GS_SUCCESS) {
                cm_spin_unlock(&cluster->cluster_info.lock);
                gsc_disconnect((gsc_conn_t)conn);
                cm_destroy_ptlist(&exclude_nodes);
                CLT_THROW_ERROR(conn, ERR_GENERATE_CIPHER);
                return GS_ERROR;
            }

            cm_spin_unlock(&cluster->cluster_info.lock);
            cm_destroy_ptlist(&exclude_nodes);

            // init heart beat thread
            if (init_heart_beat_thread(conn) != GS_SUCCESS) {
                gsc_disconnect((gsc_conn_t)conn);
                return GS_ERROR;
            }
            return GS_SUCCESS;
        }
    }

    cm_destroy_ptlist(&exclude_nodes);
    if (first_errcode != 0) {
        CLT_THROW_ERROR(conn, ERR_CLT_CLUSTER_INVALID, first_errmsg);
    } else {
        CLT_THROW_ERROR(conn, ERR_CLT_CLUSTER_INVALID, "No useful nodes found");
    }
    return GS_ERROR;
}

// set ssl attribution of heartbeat
static status_t set_conn_attr(gsc_conn_t conn, cluster_info_t *info)
{
    GS_RETURN_IFERR(gsc_set_conn_attr(conn, GSC_ATTR_SSL_MODE, &info->ssl_mode, sizeof(info->ssl_mode)));

    GS_RETURN_IFERR(gsc_set_conn_attr(conn, GSC_ATTR_SSL_CA, info->ssl_ca, (uint32)strlen(info->ssl_ca)));

    GS_RETURN_IFERR(gsc_set_conn_attr(conn, GSC_ATTR_SSL_CERT, info->ssl_cert, (uint32)strlen(info->ssl_cert)));

    GS_RETURN_IFERR(gsc_set_conn_attr(conn, GSC_ATTR_SSL_KEY, info->ssl_key, (uint32)strlen(info->ssl_key)));

    GS_RETURN_IFERR(gsc_set_conn_attr(conn, GSC_ATTR_SSL_CRL, info->ssl_crl, (uint32)strlen(info->ssl_crl)));

    GS_RETURN_IFERR(gsc_set_conn_attr(conn, GSC_ATTR_SSL_CIPHER, info->ssl_cipher, (uint32)strlen(info->ssl_cipher)));

    if (info->ssl_keypwd[0] != 0x00) {
        char keypwd[GS_PASSWORD_BUFFER_SIZE * 2];
        GS_RETURN_IFERR((status_t)gsc_decrypt_password(keypwd, (unsigned int)sizeof(keypwd), info->local_key,
            info->factor_key, info->ssl_keypwd, info->keypwd_len));
        GS_RETURN_IFERR(gsc_set_conn_attr(conn, GSC_ATTR_SSL_KEYPWD, keypwd, (uint32)strlen(keypwd)));
        MEMS_RETURN_IFERR(memset_s(keypwd, GS_PASSWORD_BUFFER_SIZE * 2, 0, GS_PASSWORD_BUFFER_SIZE * 2));
    }

    return GS_SUCCESS;
}

static const char *CHECK_SQL = "select 1";

static bool32 check_ok(check_entry_t *check_entry, cluster_info_t *cluster_info)
{
    if (g_cluster_manager.heart_thread.closed) {
        return GS_FALSE;
    }

    if (!check_entry->conn_valid) {
        if (gsc_alloc_conn(&check_entry->conn) != GS_SUCCESS) {
            return GS_FALSE;
        }

        int32 connect_timeout = HEART_BEAT_CONNECT_TIMEOUT;
        int32 socket_timeout = HEART_BEAT_SOCKET_TIMEOUT;
        if (gsc_set_conn_attr(check_entry->conn, GSC_ATTR_CONNECT_TIMEOUT, &connect_timeout, sizeof(int32)) !=
            GS_SUCCESS) {
            gsc_free_conn(check_entry->conn);
            return GS_FALSE;
        }

        if (gsc_set_conn_attr(check_entry->conn, GSC_ATTR_SOCKET_TIMEOUT, &socket_timeout, sizeof(int32)) !=
            GS_SUCCESS) {
            gsc_free_conn(check_entry->conn);
            return GS_FALSE;
        }

        char url[CM_MAX_IP_LEN + 1] = { 0 };
        if (cm_text2str(&check_entry->ip_port, url, CM_MAX_IP_LEN) != GS_SUCCESS) {
            gsc_free_conn(check_entry->conn);
            return GS_FALSE;
        }

        // Copy ssl username and password
        cm_spin_lock(&cluster_info->lock, NULL);
        if (cluster_info->ssl_mode != GSC_SSL_DISABLED) {
            if (set_conn_attr(check_entry->conn, cluster_info) != GS_SUCCESS) {
                cm_spin_unlock(&cluster_info->lock);
                gsc_free_conn(check_entry->conn);
                return GS_FALSE;
            }
        }

        errno_t errcode;
        char user[GS_NAME_BUFFER_SIZE];
        char passwd[GS_PASSWORD_BUFFER_SIZE * 2];
        errcode = strcpy_s(user, GS_NAME_BUFFER_SIZE, cluster_info->user);
        if (errcode != EOK) {
            cm_spin_unlock(&cluster_info->lock);
            gsc_free_conn(check_entry->conn);
            return GS_FALSE;
        }

        if ((status_t)gsc_decrypt_password(passwd, (unsigned int)sizeof(passwd), cluster_info->local_key,
            cluster_info->factor_key, cluster_info->cipher, cluster_info->cipher_len) != GS_SUCCESS) {
            cm_spin_unlock(&cluster_info->lock);
            gsc_free_conn(check_entry->conn);
            return GS_FALSE;
        }

        cm_spin_unlock(&cluster_info->lock);
        if (gsc_connect(check_entry->conn, url, user, passwd) != GS_SUCCESS) {
            gsc_free_conn(check_entry->conn);
            MEMS_RETURN_IFERR(memset_s(passwd, GS_PASSWORD_BUFFER_SIZE * 2, 0, GS_PASSWORD_BUFFER_SIZE * 2));
            return GS_FALSE;
        }
        errcode = memset_s(passwd, GS_PASSWORD_BUFFER_SIZE * 2, 0, GS_PASSWORD_BUFFER_SIZE * 2);
        if (errcode != EOK) {
            gsc_disconnect(check_entry->conn);
            gsc_free_conn(check_entry->conn);
            GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return GS_FALSE;
        }
        (void)memset_s(passwd, GS_PASSWORD_BUFFER_SIZE * 2, 0, GS_PASSWORD_BUFFER_SIZE * 2);
    }

    if (gsc_query(check_entry->conn, CHECK_SQL) != GS_SUCCESS) {
        check_entry->conn_valid = GS_FALSE;
        gsc_disconnect(check_entry->conn);
        gsc_free_conn(check_entry->conn);
        return GS_FALSE;
    }

    check_entry->conn_valid = GS_TRUE;
    return GS_TRUE;
}

// user,passwd only for new connection
static void check_node(node_info_t *node, cluster_info_t *cluster_info)
{
    if (node->check_entry == NULL) {
        check_entry_t *check_entry = NULL;
        for (uint32 i = 0; i < g_cluster_manager.check_pool.count; i++) {
            check_entry = (check_entry_t *)cm_list_get(&g_cluster_manager.check_pool, i);
            if (cm_text_equal_ins(&node->node_url, &check_entry->ip_port)) {
                node->check_entry = check_entry;
                break;
            }
        }

        if (node->check_entry == NULL) {
            if (cm_list_new(&g_cluster_manager.check_pool, (void **)&check_entry) != GS_SUCCESS) {
                return;
            }
            check_entry->ip_port = node->node_url;
            check_entry->conn_valid = GS_FALSE;

            node->check_entry = check_entry;
        }
    }

    for (uint32 i = 0; i < HEART_BEAT_TRY_TIMES; i++) {
        if (g_cluster_manager.heart_thread.closed) {
            return;
        }
        if (check_ok(node->check_entry, cluster_info)) {
            node->status = NODE_STATUS_ONLINE;
            return;
        }
        cm_sleep(HEART_BEAT_TRY_INTERVEL);
    }

    node->status = NODE_STATUS_OFFLINE;
}

static void check_clusters()
{
    cluster_t *cluster = NULL;
    node_info_t *node_info = NULL;
    for (uint32 i = 0; i < g_cluster_manager.cluster_count; i++) {
        cluster = (cluster_t *)cm_list_get(&g_cluster_manager.clusters, i);
        for (uint32 j = 0; j < cluster->node_list.count; j++) {
            if (g_cluster_manager.heart_thread.closed) {
                return;
            }
            node_info = (node_info_t *)cm_list_get(&cluster->node_list, j);
            check_node(node_info, &cluster->cluster_info);
        }
    }
}

void decrease_cluster_count(clt_conn_t *conn)
{
    if (conn->node == NULL) {
        return;
    }

    node_info_t *node = (node_info_t *)conn->node;

    cm_spin_lock(&node->lock, NULL);
    node->ref_count--;
    cm_spin_unlock(&node->lock);
    conn->node = NULL;
}

#ifdef __cplusplus
}
#endif
