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
 * srv_sess_security.h
 *
 *
 * IDENTIFICATION
 * src/server/srv_sess_security.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_SESS_SECURITY_H__
#define __SRV_SESS_SECURITY_H__

#pragma once
#include "srv_session.h"

status_t server_process_handshake(session_t *session);
status_t server_process_auth_init(session_t *session);
uint32 server_get_user_sessions_count(text_t *username);
status_t server_process_login(session_t *session);
void server_judge_login(session_t *session);
void server_judge_login_success(char *os_host);
status_t server_check_authenticate_sysdba(session_t *session, text_t *password, cs_packet_t *send_pack, char *privilege);

bool32 server_match_restricted_status(session_t *session);
status_t server_auth_and_check_privs(session_t *session, text_t *password, bool32 is_coord);

status_t server_init_sysdba_privilege(void);
status_t server_store_sysdba_privilege(const char *privilege, uint32 priv_len, const char *name);
status_t server_remove_sysdba_privilege(void);
status_t server_refresh_sysdba_privilege(void);
status_t server_load_hba(bool32 allow_not_exists);
status_t server_load_pbl(bool32 allow_not_exists);
#endif
