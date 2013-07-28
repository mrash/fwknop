/*
 *****************************************************************************
 *
 * File:    fko_state.h
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Defines various states and flags for libfko operations.
 *
 * Copyright 2009-2013 Damien Stuart (dstuart@dstuart.org)
 *
 *  License (GNU General Public License):
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *****************************************************************************
*/
#ifndef FKO_STATE_H
#define FKO_STATE_H 1

/* General state flag bit values.
*/
typedef enum {
    FKO_CTX_SET                 = 1,        /* Set when ctx is initialized */
    FKO_DATA_MODIFIED           = 1 << 1,
    FKO_STATE_RESERVED_2        = 1 << 2,
    STATE_RESERVED_3            = 1 << 3,
    STATE_RESERVED_4            = 1 << 4,
    STATE_RESERVED_5            = 1 << 5,
    FKO_SPA_MSG_TYPE_MODIFIED   = 1 << 6,
    FKO_CTX_SET_2               = 1 << 7,   /* Set when ctx is initialized */
    STATE_RESERVED_8            = 1 << 8,
    STATE_RESERVED_9            = 1 << 9,
    STATE_RESERVED_10           = 1 << 10,
    STATE_RESERVED_11           = 1 << 11,
    FKO_DIGEST_TYPE_MODIFIED    = 1 << 12,
    FKO_ENCRYPT_TYPE_MODIFIED   = 1 << 13,
    STATE_RESERVED_14           = 1 << 14,
    FKO_BACKWARD_COMPATIBLE     = 1 << 15,
    FKO_ENCRYPT_MODE_MODIFIED   = 1 << 16,
    FKO_HMAC_MODE_MODIFIED      = 1 << 17
} fko_state_flags_t;

/* This is used in conjunction with the ctx->initial value as a means to
 * determine if the ctx has been properly initialized.  However, this
 * may not work 100% of the time as it is possible (though not likely)
 * an ctx may have values that match both the flags and the ctx->initial
 * value.
*/
#define FKO_CTX_INITIALIZED  (FKO_CTX_SET|FKO_CTX_SET_2)

#define FKO_SET_CTX_INITIALIZED(ctx) \
    (ctx->state |= (FKO_CTX_INITIALIZED))

#define FKO_CLEAR_CTX_INITIALIZED(ctx) \
    (ctx->state &= (0xffff & ~FKO_CTX_INITIALIZED))

/* Consolidate all SPA data modified flags.
*/
#define FKO_SPA_DATA_MODIFIED ( \
    FKO_DATA_MODIFIED | FKO_SPA_MSG_TYPE_MODIFIED \
      | FKO_DIGEST_TYPE_MODIFIED | FKO_ENCRYPT_TYPE_MODIFIED )
 
/* This should return true if any SPA data field has been modifed since the
 * last encode/encrypt.
*/
#define FKO_IS_SPA_DATA_MODIFIED(ctx) (ctx->state & FKO_SPA_DATA_MODIFIED)

/* Clear all SPA data modified flags.  This is normally called after a
 * succesful encode/digest/encryption cycle.
*/
#define FKO_CLEAR_SPA_DATA_MODIFIED(ctx) \
    (ctx->state &= (0xffff & ~FKO_SPA_DATA_MODIFIED))

/* Macros used for determining ctx initialization state.
*/
#define CTX_INITIALIZED(ctx) (ctx != NULL && ctx->initval == FKO_CTX_INITIALIZED)

#endif /* FKO_STATE_H */

/***EOF***/
