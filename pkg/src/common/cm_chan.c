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
 * cm_chan.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_chan.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "cm_chan.h"
#include "cm_error.h"

// create an new chan
chan_t *cm_chan_new(uint32 capacity, uint32 size)
{
    errno_t rc_memzero;
    uint32 real_size;
    if (capacity == 0 || size == 0) {
        return NULL;
    }

    chan_t *chan = (chan_t *)malloc(sizeof(*chan));
    if (chan == NULL) {
        return NULL;
    }
    rc_memzero = memset_sp(chan, sizeof(*chan), 0, sizeof(*chan));
    if (rc_memzero != EOK) {
        CM_FREE_PTR(chan);
        return NULL;
    }
    chan->capacity = capacity;
    chan->count = 0;
    chan->size = size;
    real_size = size * capacity;
    if (real_size / capacity != size) {
        CM_FREE_PTR(chan);
        return NULL;
    }
    chan->buf = (uint8 *)malloc(real_size);
    if (chan->buf == NULL) {
        CM_FREE_PTR(chan);
        return NULL;
    }
    rc_memzero = memset_sp(chan->buf, (size_t)real_size, 0, (size_t)real_size);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(chan->buf);
        CM_FREE_PTR(chan);
        return NULL;
    }
    chan->buf_end = chan->buf + size * (capacity);
    chan->begin = chan->buf;
    chan->end = chan->buf;

    chan->lock = 0;
    (void)cm_event_init(&chan->event_send);
    (void)cm_event_init(&chan->event_recv);
    chan->waittime_ms = 100;

    chan->is_closed = CT_FALSE;
    chan->ref_count = 0;

    return chan;
}

status_t cm_chan_send_timeout(chan_t *chan, const void *elem, uint32 timeout_ms)
{
    errno_t errcode;
    if (chan == NULL || elem == NULL) {
        return CT_ERROR;
    }

    cm_spin_lock(&chan->lock, NULL);
    {
        if (chan->buf == NULL || chan->is_closed) {
            cm_spin_unlock(&chan->lock);
            return CT_ERROR;
        }

        // chan is full
        while (chan->count == chan->capacity) {
            cm_spin_unlock(&chan->lock);

            // wait for the recv signal
            if (CT_TIMEDOUT == cm_event_timedwait(&chan->event_recv, timeout_ms)) {
                return CT_TIMEDOUT;
            }

            cm_spin_lock(&chan->lock, NULL);

            if (chan->count < chan->capacity) {
                break;
            }
        }

        // ring
        if (chan->end >= chan->buf_end) {
            chan->end = chan->buf;
        }

        // send
        if (chan->size != 0) {
            errcode = memcpy_sp(chan->end, (size_t)(chan->buf_end - chan->end), elem, (size_t)chan->size);
            if (errcode != EOK) {
                cm_spin_unlock(&chan->lock);
                CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                return CT_ERROR;
            }
        }
        chan->end += chan->size;
        chan->count++;
    }
    cm_spin_unlock(&chan->lock);

    cm_event_notify(&chan->event_send);

    return CT_SUCCESS;
}

// send an element, will block until there are space to store
status_t cm_chan_send(chan_t *chan, const void *elem)
{
    return cm_chan_send_timeout(chan, elem, 0xFFFFFFFF);
}

// recv an element, will block until there are elems in the chan
status_t cm_chan_recv_timeout(chan_t *chan, void *elem, uint32 timeout_ms)
{
    errno_t errcode;
    if (chan == NULL || elem == NULL) {
        return CT_ERROR;
    }

    cm_spin_lock(&chan->lock, NULL);
    {
        if (chan->buf == NULL) {
            cm_spin_unlock(&chan->lock);
            return CT_ERROR;
        }

        // chan is empty
        while (chan->count == 0) {
            if (chan->is_closed) {
                cm_spin_unlock(&chan->lock);
                return CT_ERROR;
            }

            cm_spin_unlock(&chan->lock);

            // wait for the send signal
            if (CT_TIMEDOUT == cm_event_timedwait(&chan->event_send, timeout_ms)) {
                return CT_TIMEDOUT;
            }

            cm_spin_lock(&chan->lock, NULL);

            if (chan->count > 0) {
                break;
            }
        }

        // ring
        if (chan->begin >= chan->buf_end) {
            chan->begin = chan->buf;
        }

        // recv
        if (chan->size != 0) {
            errcode = memcpy_sp(elem, (size_t)chan->size, chan->begin, (size_t)chan->size);
            if (errcode != EOK) {
                cm_spin_unlock(&chan->lock);
                CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                return CT_ERROR;
            }
        }
        chan->begin += chan->size;
        chan->count--;
    }
    cm_spin_unlock(&chan->lock);

    cm_event_notify(&chan->event_recv);

    return CT_SUCCESS;
}

// send an element, will block until there are space to store
status_t cm_chan_recv(chan_t *chan, void *elem)
{
    return cm_chan_recv_timeout(chan, elem, 0xFFFFFFFF);
}

// is the chan empty
bool32 cm_chan_empty(chan_t *chan)
{
    cm_spin_lock(&chan->lock, NULL);
    if (chan->count == 0) {
        cm_spin_unlock(&chan->lock);
        return CT_TRUE;
    }

    cm_spin_unlock(&chan->lock);
    return CT_FALSE;
}

// close the chan, notify all block sender and receiver to exit
void cm_chan_close(chan_t *chan)
{
    if (chan == NULL) {
        return;
    }

    cm_spin_lock(&chan->lock, NULL);
    if (chan->is_closed) {
        cm_spin_unlock(&chan->lock);
        return;
    }

    chan->is_closed = CT_TRUE;

    uint32 i = 0;
    for (i = 0; i < chan->ref_count; i++) {
        cm_event_notify(&chan->event_recv);
        cm_event_notify(&chan->event_send);
    }

    cm_spin_unlock(&chan->lock);
}

// free memory
void cm_chan_free(chan_t *chan)
{
    if (chan == NULL) {
        return;
    }

    cm_event_destory(&chan->event_recv);
    cm_event_destory(&chan->event_send);

    CM_FREE_PTR(chan->buf);
    chan->begin = NULL;
    chan->end = NULL;
    chan->buf_end = NULL;

    chan->capacity = 0;
    chan->count = 0;
    chan->size = 0;

    chan->is_closed = CT_TRUE;
    chan->ref_count = 0;

    CM_FREE_PTR(chan);
}
