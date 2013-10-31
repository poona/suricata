/* Copyright (C) 2007-2013 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __APP_LAYER_DETECT_PROTO__H__
#define __APP_LAYER_DETECT_PROTO__H__

#include "stream.h"
#include "detect-content.h"
#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "flow-proto-private.h"

#define FLOW_IS_PM_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags & FLOW_TS_PM_ALPROTO_DETECT_DONE) : ((f)->flags & FLOW_TC_PM_ALPROTO_DETECT_DONE))
#define FLOW_IS_PP_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags & FLOW_TS_PP_ALPROTO_DETECT_DONE) : ((f)->flags & FLOW_TC_PP_ALPROTO_DETECT_DONE))

#define FLOW_SET_PM_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags |= FLOW_TS_PM_ALPROTO_DETECT_DONE) : ((f)->flags |= FLOW_TC_PM_ALPROTO_DETECT_DONE))
#define FLOW_SET_PP_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags |= FLOW_TS_PP_ALPROTO_DETECT_DONE) : ((f)->flags |= FLOW_TC_PP_ALPROTO_DETECT_DONE))

#define FLOW_RESET_PM_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags &= ~FLOW_TS_PM_ALPROTO_DETECT_DONE) : ((f)->flags &= ~FLOW_TC_PM_ALPROTO_DETECT_DONE))
#define FLOW_RESET_PP_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags &= ~FLOW_TS_PP_ALPROTO_DETECT_DONE) : ((f)->flags &= ~FLOW_TC_PP_ALPROTO_DETECT_DONE))

/***** Anoop *****/

/**
 * \brief Inits and returns an app layer protocol detection context.
 *
 * \retval On success, pointer to the context;
 *         On failure, NULL.
 */
void *AlpdGetCtx(void);
/**
 * \brief Destroys the app layer protocol detection context.
 *
 * \param ctx Pointer to the app layer protocol detection context.
 */
void AlpdDestoryCtx(void *ctx);

/**
 * \brief Registers a protocol for protocol detection phase.
 *
 *        This is the first function to be called after getting a new context
 *        from AlpdGetCtx(), before calling any other
 *        app layer functions, alpd or alp, alike.
 *        With this function you are associating/registering a string
 *        that can be used by users to write rules, i.e.
 *        you register the http protocol for protocol detection using
 *        AlpdRegisterProtocol(ctx, ALPROTO_HTTP, "http");
 *        Following which you can write rules like this -
 *        alert http any any -> any any (sid:1;)
 *        which basically matches on the HTTP protocol.
 *
 * \param ctx Pointer to the app layer protocol detection context.
 * \param alproto The protocol.
 * \param alproto_str The string to associate with the above "alproto".
 *                    Please send a static string that won't be destroyed
 *                    post making this call, since this function won't
 *                    create a copy of the received argument.
 *
 * \retval  0 On success;
 *         -1 on failure.
 */
int AlpdRegisterProtocol(void *ctx,
                         uint16_t alproto, const char *alproto_str);

/**
 * \brief Given a protocol name, checks if proto detection is enabled in the
 *        conf file.
 *
 * \param al_proto Name of the app layer protocol.
 *
 * \retval 1 If enabled.
 * \retval 0 If disabled.
 */
int AlpdConfProtoDetectionEnabled(const char *alproto);

/**
 * \brief Inits and returns an app layer protocol detection thread context.

 * \param ctx Pointer to the app layer protocol detection context.
 *
 * \retval On success, pointer to the thread context;
 *         On failure, NULL.
 */
void *AlpdGetCtxThread(void *ctx);
/**
 * \brief Destroys the app layer protocol detection thread context.
 *
 * \param ctx  Pointer to the app layer protocol detection context.
 * \param tctx Pointer to the app layer protocol detection thread context.
 */
void AlpdDestroyCtxThread(void *ctx, void *tctx);

/**
 * \brief Registers a case-sensitive pattern for protocol detection.
 */
int AlpdPMRegisterPatternCS(void *ctx,
                            uint16_t ipproto, uint16_t alproto,
                            const char *pattern,
                            uint16_t depth, uint16_t offset,
                            uint8_t direction);
/**
 * \brief Registers a case-insensitive pattern for protocol detection.
 */
int AlpdPMRegisterPatternCI(void *ctx,
                            uint16_t ipproto, uint16_t alproto,
                            const char *pattern,
                            uint16_t depth, uint16_t offset,
                            uint8_t direction);

/**
 * \brief Prepares the internal state for protocol detection.
 *
 * \param ctx Poniter to the app layer protocol detection context.
 */
void AlpdPrepareState(void *ctx);

/**
 * \brief Returns the app layer protocol given a buffer.
 *
 * \param ctx Pointer to the app layer protocol detection context.
 * \param tctx Pointer to the app layer protocol detection thread context.
 * \param f Pointer to the flow.
 * \param buf The buf to be inspected.
 * \param buflen The length of the above buffer.
 * \param flags The flags field.
 * \param ipproto The ip protocol.
 *
 * \retval The app layer protocol.
 */
AppProto AlpdGetProto(AlpProtoDetectCtx *ctx, AlpProtoDetectThreadCtx *tctx,
                      Flow *f, uint8_t *buf, uint32_t buflen,
                      uint8_t flags, uint8_t ipproto);

void AlpdRegisterTests(void);

#endif /* __APP_LAYER_DETECT_PROTO__H__ */
