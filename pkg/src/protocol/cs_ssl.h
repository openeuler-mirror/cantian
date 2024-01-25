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
 * cs_ssl.h
 *
 *
 * IDENTIFICATION
 * src/protocol/cs_ssl.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CS_SSL_H__
#define __CS_SSL_H__

#include "cs_tcp.h"
#include "ssl.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_ssl_ctx {
    void *reserved;
} ssl_ctx_t;

typedef struct st_ssl_socket {
    void *reserved;
} ssl_sock_t;

typedef struct st_ssl_link {
    tcp_link_t tcp;
    ssl_ctx_t *ssl_ctx;
    ssl_sock_t *ssl_sock;
} ssl_link_t;

typedef struct st_ssl_config {
    const char *ca_file;
    const char *cert_file;
    const char *key_file;
    SENSI_INFO const char *key_password;
    const char *crl_file;
    const char *cipher;
    bool32 verify_peer;
} ssl_config_t;

typedef enum en_ssl_verify {
    VERIFY_SSL,
    VERIFY_CERT,
    VERIFY_ISSUER,
    VERIFY_SUBJECT
} ssl_verify_t;

typedef enum en_cert_type {
    CERT_TYPE_SERVER_CERT,
    CERT_TYPE_CA_CERT
} cert_type_t;

EVP_PKEY *get_dh3072(void);
/**
 * create a new ssl context object for acceptor (server side).
 * @param [in]   ca_file      SSL CA file path
 * @param [in]   cert_file    SSL certificate file path
 * @param [in]   key_file     SSL private key file path
 * @param [in]   verify_client Indicates whether verify the client cert
 * @return  ssl context worked as a framework for ssl/tls function on success, NULL on failure
 */
ssl_ctx_t *cs_ssl_create_acceptor_fd(ssl_config_t *config);

/**
 * create a new ssl context object for connector (client side).
 * @param [in]   ca_file      SSL CA file path
 * @param [in]   cert_file    SSL certificate file path
 * @param [in]   key_file     SSL private key file path
 * @param [in]   is_client    setting for ssl
 * @return  ssl context worked as a framework for ssl/tls function on success, NULL on failure
 */
ssl_ctx_t *cs_ssl_create_connector_fd(ssl_config_t *config);

/**
 * free a ssl context object.
 * @param [in] pSslContext ssl context
 * @return  void
 */
void cs_ssl_free_context(ssl_ctx_t *ctx);

/**
 * get default cipher suites supported by SSL
 * @param void
 * @retval string array of all supported ciphers, the array is terminated by NULL
 * @note cannot free or modify the cipher list
 */
const char **cs_ssl_get_default_cipher_list(void);
const char **cs_ssl_tls13_get_default_cipher_list(void);

/**
 * accept a client with a tcp socket
 * @param [in,out]  link   ssl link with context created
 * @param [in]      sock   tcp socket already accepted
 * @param [in]      timeout       timeout, unit:ms; block if < 0
 * @return
 * @retval CT_SUCCESS  accept a client successfully
 * @retval GS_TIMEOUT  accept timeout, no incoming client
 * @retval CT_ERROR   ssl connection is shutdown
 */
status_t cs_ssl_accept_socket(ssl_link_t *link, socket_t sock, int32 timeout);

/**
 * create a ssl connect with a tcp socket
 * @param [in|out]  SSL link with context created
 * @param [in]      sock tcp socket already connected
 * @param [in]      timeout  timeout, unit: ms
 * @return
 * @retval CT_SUCCESS  connect to the server successfully
 * @retval GS_TIMEOUT  connect timeout
 * @retval CT_ERROR    ssl connection is shutdown or other errors
 */
status_t cs_ssl_connect_socket(ssl_link_t *link, socket_t sock, int32 timeout);

/**
 * disconnect and free ssl socket
 * @param [in] ssl_link ssl link
 * @return  void
 */
void cs_ssl_disconnect(ssl_link_t *link);

/**
 * write specified number of bytes, till success or timeout
 * @param [in]      link      ssl socket link
 * @param [in]      buf       data buffer
 * @param [in]      size      input data length
 * @param [out]     send_size sent data length
 * @return
 * @retval CT_SUCCESS      write successfully
 * @retval CT_ERROR        other error
*/
status_t cs_ssl_send(ssl_link_t *link, const char *buf, uint32 size, int32 *send_size);
status_t cs_ssl_send_timed(ssl_link_t *link, const char *buf, uint32 size, uint32 timeout);

/**
 * read specified number of bytes, till success or timeout
 * @param [in]      link      ssl socket link
 * @param [in]      buf       data buffer
 * @param [in]      size      data buffer max length
 * @param [out]     recv_size read data length
 * @return
 * @retval CT_SUCCESS      write successfully
 * @retval CT_ERROR        other error
*/
status_t cs_ssl_recv(ssl_link_t *link, char *buf, uint32 size, int32 *recv_size, uint32 *wait_event);
status_t cs_ssl_recv_timed(ssl_link_t *link, char *buf, uint32 size, uint32 timeout);

/**
 * wait on SSL socket, till success or timeout
 * @param [in]      link      ssl socket link
 * @param [in]      wait_for  wait event
 * @param [in]      timeout   wait timeout
 * @param [out]     ready     wait event occured
 * @return
 * @retval CT_SUCCESS      write successfully
 * @retval CT_ERROR        other error
 */
status_t cs_ssl_wait(ssl_link_t *link, uint32 wait_for, int32 timeout, bool32 *ready);

/*
 Check the server's (subject) Common Name against the
 hostname we connected to

 @param[in]  link         pointer to a SSL connected vio
 @param[in]  vmode        verify mode, should be one of VERIFY_SSL, VERIFY_CERT, VERIFY_ISSUER, VERIFY_SUBJECT
 @param[in]  name         if verify issuer, name pointer to required issuer common name
                          if verify subject name pointer to required subject common name
 @param[out] errptr       if we fail, we'll return (a pointer to a string describing) the reason here

 RETURN VALUES
 @retval CT_SUCCESS Success
 @retval CT_ERROR   Failed to validate server
*/
status_t cs_ssl_verify_certificate(ssl_link_t *link, ssl_verify_t vmode, const char *name, const char **errptr);

/*
  Check ssl certificate file access permission,
  the file should not have group or world access permission

  @param[in] file_name    ssl certificate file name

  RETURN VALUES
  @retval CT_SUCCESS Success
  @retval CT_ERROR   Failed to verify
*/
status_t cs_ssl_verify_file_stat(const char *file_name);

status_t cs_ssl_read_buffer(ssl_link_t *link, char *buf, uint32 size, int32 *recv_size);

void ssl_ca_cert_expire(const ssl_ctx_t *ssl_context, int32 alert_day);

#ifdef __cplusplus
}
#endif

#endif
