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
 *
 * A simple application layer (L7) protocol detector. It works by allowing
 * developers to set a series of patterns that if exactly matching indicate
 * that the session is a certain protocol.
 *
 * \todo More advanced detection methods, regex maybe.
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-content.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "util-mpm.h"
#include "util-print.h"
#include "util-pool.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "flow.h"
#include "flow-util.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"

#include "util-spm.h"
#include "util-cuda.h"
#include "util-debug.h"

#define INSPECT_BYTES  32

typedef struct AlpdPMSignature_ {
    AppProto alproto;
    /* todo Change this into a non-pointer */
    DetectContentData *cd;
    struct AlpdPMSignature_ *next;
} AlpdPMSignature;

typedef struct AlpdPMCtx_ {
    uint16_t max_len;
    uint16_t min_len;
    MpmCtx mpm_ctx;

    /** Mapping between pattern id and signature.  As each signature has a
     *  unique pattern with a unique id, we can lookup the signature by
     *  the pattern id. */
    AlpdPMSignature **map;
    AlpdPMSignature *head;
} AlpdPMCtx;

typedef struct AlpdCtxIpproto_ {
    /* 0 - toserver, 1 - toclient */
    AlpdPMCtx ctx_pm[2];
    AlpdPPCtx *ctx_pp;
};

/**
 * \brief The app layer protocol detection context.
 */
typedef struct AlpdCtx_ {
    /* Context per ip_proto.
     * \todo Modify ctx_ipp to hold for only tcp and udp. The rest can be
     *       implemented if needed.  Waste of space otherwise. */
    AlpdCtxIpproto ctx_ipp[FLOW_PROTO_MAX];

    /* Indicates the protocols that have registered themselves
     * for protocol detection.  This table is independent of the
     * ipproto. */
    const char *[ALPROTO_MAX];
} AlpdCtx;

/**
 * \brief The app layer protocol detection thread context.
 */
typedef struct AlpdCtxThread_ {
    PatternMatcherQueue pmq;
    /* The value 2 is for direction(0 - toserver, 1 - toclient). */
    MpmThreadCtx mpm_tctx[FLOW_PROTO_MAX][2];
} AlpdCtxThread;

/***** API *****/

static int AlpdPMSetContentIDs(AlpdPMCtx *ctx)
{
    SCEnter();

    typedef struct TempContainer_ {
        PatIntId id;
        uint16_t content_len;
        uint8_t *content;
    } TempContainer;

    AlpdPMSignature *s;
    uint32_t struct_total_size = 0;
    uint32_t content_total_size = 0;
    /* array hash buffer */
    uint8_t *ahb;
    uint8_t *content = NULL;
    uint8_t content_len = 0;
    PatIntId max_id = 0;
    TempContainer *struct_offset;
    uint8_t *content_offset;
    TempContainer *dup;
    int ret = 0;

    for (s = ctx->head; s != NULL; s = s->next) {
        struct_total_size += sizeof(TempStruct);
        content_total_size += s->cd->content_len;
    }

    ahb = SCMalloc(sizeof(uint8_t) * (struct_total_size + content_total_size));
    if (unlikely(ahb == NULL))
        goto error;

    struct_offset = (TempContainer *)ahb;
    content_offset = ahb + struct_total_size;
    for (s = ctx->head; s != NULL; s = s->next) {
        dup = (TempContainer *)ahb;
        content = s->cd->content;
        content_len = s->cd->content_len;

        for (; dup != struct_offset; dup++) {
            if (dup->content_len != content_len ||
                SCMemcmp(dup->content, content, dup->content_len) != 0)
            {
                continue;
            }
            break;
        }

        if (dup != struct_offset) {
            s->cd->id = dup->id;
            continue;
        }

        struct_offset->content_len = content_len;
        struct_offset->content = content_offset;
        content_offset += content_len;
        memcpy(struct_offset->content, content, content_len);
        struct_offset->id = max_id++;
        s->cd->id = struct_offset->id;

        struct_offset++;
    }

    goto end;
 error:
    ret = -1;
 end:
    if (ahb != NULL)
        SCFree(ahb);
    SCReturnInt(ret);
}

static int AlpdPMMapSignatures(AlpdPMCtx *ctx)
{
    SCEnter();

    int ret = 0;
    PatIntID max_pat_id = 0, tmp_pat_id;
    AlpdPMSignature *s, *next_s;
    int is_ci;
    int mpm_ret;

    for (s = ctx->head; s != NULL; s = s->next) {
        if (s->cd->id < max_pat_id)
            max_pat_id = s->cd->id;
    }

    ctx->map = SCMalloc((max_pat_id + 1) * sizeof(ctx->map));
    if (ctx->map == NULL)
        goto error;
    memset(ctx->map, 0, (max_pat_id + 1) * sizeof(ctx->map));

    for (s = ctx->head; s != NULL;) {
        next_s = s->next;
        s->next = ctx->map[s->cd->id];
        ctx->map[s->cd->id] = s;

        s = next_s;
    }

    for (tmp_pat_id = 0; tmp_pat_id <= max_pat_id; tmp_pat_id++) {
        is_ci = 0;
        for (s = ctx->map[tmp_pat_id]; s != NULL; s = s->next) {
            if (s->cd->flags & DETECT_CONTENT_NOCASE) {
                is_ci = 1;
                break;
            }
        }
        if (is_ci) {
            mpm_ret = MpmAddPatternCI(ctx->mpm_ctx,
                                      s->cd->content, s->cd->content_len,
                                      0, 0,
                                      tmp_pat_id, 0, 0);
            if (mpm_ret < 0)
                goto error;
        } else {
            s = ctx->map[tmp_pat_id];
            mpm_ret = MpmAddPatternCS(ctx->mpm_ctx,
                                      s->cd->content, s->cd->content_len,
                                      0, 0,
                                      tmp_pat_id, 0, 0);
            if (mpm_ret < 0)
                goto error;
        }
    }

    goto end;
 error:
    ret = -1;
 end:
    SCReturnInt(ret);
}

static int AlpdPrepareMpm(AlpdPMCtx *ctx)
{
    SCEnter();

    int ret = 0;
    MpmCtx *mpm_ctx = ctx_pm->mpm_ctx;

    if (mpm_table_table[mpm_ctx->mpm_type].Prepare(mpm_ctx) < 0)
        goto error;

 error:
    ret = -1;
 end:
    SCReturnInt(ret);
}

static int AlpdPMAddSignature(AlpdPMCtx *ctx, DetectContentData *cd,
                              AppProto alproto)
{
    SCEnter();

    int ret = 0;
    AlpdPMSignature *s = SCMalloc(sizeof(*s))
    if (unlikely(s == NULL))
        goto error;
    memset(s, 0, sizeof(*s));

    s->alproto = alproto;
    s->cd = cd;

    /* prepend to the list */
    s->next = ctx->head;
    ctx->head = s;

    goto end;
 error:
    ret = -1;
 end:
    SCReturnInt(ret);
}

static int AlpdPMRegisterPattern(void *ctx,
                                 uint16_t ipproto, uint16_t alproto,
                                 const char *pattern,
                                 uint16_t depth, uint16_t offset,
                                 uint8_t direction,
                                 uint8_t is_cs)
{
    SCEnter();

    AlpdCtx *ctx_alpd = (AlpdCtx *)ctx;
    AlpdCtxIpproto *ctx_ipp = &alpd_ctx->ctx_ipp[FlowGetProtoMapping(ipproto)];
    AlpdPMCtx *ctx_pm = NULL;
    DetectContentData *cd;
    int ret = 0;

    cd = DetectContentParseEncloseQuotes(content);
    if (cd == NULL)
        goto error;
    cd->depth = depth;
    cd->offset = offset;
    if (is_cs)
        cd->flags |= DETECT_CONTENT_NOCASE;
    if (depth < cd->content_len)
        goto error;

    if (direction & STREAM_TOSERVER)
        ctx_pm = (AlpdPMCtx *)ctx_ipp->ctx_pm[0];
    else
        ctx_pm = (AlpdPMCtx *)ctx_ipp->ctx_pm[1];

    if (depth > ctx_pm->max_len)
        ctx_pm->max_len = depth;
    if (depth < ctx_pm->min_len)
        ctx_pm->min_len = depth;

    /* Finally turn it into a signature and add to the ctx. */
    AlpdPMAddSignature(ctx_pm, cd, alproto);

    goto end;
 error:
    ret = -1;
 end:
    SCReturnInt(ret);
}

static uint16_t AlpdPMMatchSignature(AlpdPMSignature *s,
                                     uint8_t *buf, uint16_t buflen,
                                     uint16_t ip_proto)
{
    SCEnter();
    uint16_t proto = ALPROTO_UNKNOWN;
    uint8_t *found = NULL;

    if (s->ip_proto != ip_proto) {
        goto end;
    }

    if (s->co->offset > buflen) {
        SCLogDebug("s->co->offset (%"PRIu16") > buflen (%"PRIu16")",
                s->co->offset, buflen);
        goto end;
    }

    if (s->co->depth > buflen) {
        SCLogDebug("s->co->depth (%"PRIu16") > buflen (%"PRIu16")",
                s->co->depth, buflen);
        goto end;
    }

    uint8_t *sbuf = buf + s->co->offset;
    uint16_t sbuflen = s->co->depth - s->co->offset;
    SCLogDebug("s->co->offset (%"PRIu16") s->co->depth (%"PRIu16")",
                s->co->offset, s->co->depth);

    if (s->co->flags & DETECT_CONTENT_NOCASE)
        found = SpmNocaseSearch(sbuf, sbuflen, s->co->content, s->co->content_len);
    else
        found = SpmSearch(sbuf, sbuflen, s->co->content, s->co->content_len);
    if (found != NULL)
        proto = s->proto;

end:
    SCReturnInt(proto);
}

static uint16_t AlpdPMGetProto(AlpProtoDetectCtx *ctx,
                               AlpProtoDetectThreadCtx *tctx,
                               Flow *f,
                               uint8_t *buf, uint16_t buflen,
                               uint8_t flags,
                               uint8_t ipproto,
                               Appproto *pm_results)
{
    SCEnter();

    uint16_t pm_matches = 0;
    pm_results[0] = ALPROTO_UNKNOWN;

    AlpProtoDetectDirection *dir;
    AlpProtoDetectDirectionThread *tdir;
    uint16_t max_len;

    if (flags & STREAM_TOSERVER) {
        dir = &ctx->toserver;
        tdir = &tctx->toserver;
        max_len = ctx->toserver.max_len;
    } else {
        dir = &ctx->toclient;
        tdir = &tctx->toclient;
        max_len = ctx->toclient.max_len;
    }

    if (dir->id == 0) {
        goto end;
    }

    /* see if we can limit the data we inspect */
    uint16_t searchlen = buflen;
    if (searchlen > dir->max_len)
        searchlen = dir->max_len;

    uint32_t search_cnt = 0;

    /* do the mpm search */
    search_cnt = mpm_table[dir->mpm_ctx.mpm_type].Search(&dir->mpm_ctx,
                                                         &tdir->mpm_ctx,
                                                         &tdir->pmq, buf,
                                                         searchlen);
    SCLogDebug("search cnt %" PRIu32 "", search_cnt);
    if (search_cnt == 0)
        goto end;

    /* alproto bit field */
    uint8_t pm_results_bf[ALPROTO_MAX / 8];
    memset(pm_results_bf, 0, sizeof(pm_results_bf));

    for (uint8_t s_cnt = 0; s_cnt < search_cnt; s_cnt++) {
        AlpProtoSignature *s = ctx->map[tdir->pmq.pattern_id_array[s_cnt]];
        SCLogDebug("array count is %"PRIu32" patid %"PRIu16"",
                   tdir->pmq.pattern_id_array_cnt,
                   tdir->pmq.pattern_id_array[s_cnt]);
        while (s != NULL) {
            uint16_t proto = AlpProtoMatchSignature(s, buf, buflen, ipproto);
            if (proto != ALPROTO_UNKNOWN &&
                !(pm_results_bf[proto / 8] & (1 << (proto % 8))) )
            {
                pm_results[pm_matches++] = proto;
                pm_results_bf[proto / 8] |= 1 << (proto % 8);
            }
            s = s->map_next;
        }
    }

end:
    PmqReset(&tdir->pmq);

    if (mpm_table[dir->mpm_ctx.mpm_type].Cleanup != NULL) {
        mpm_table[dir->mpm_ctx.mpm_type].Cleanup(&tdir->mpm_ctx);
    }
    if (buflen >= max_len)
        FLOW_SET_PM_DONE(f, flags);
    SCReturnUInt(pm_matches);
}

/**
 * \todo Not finished yet.
 */
static void AlpdPMCtxDestroy(AlpdPMCtx *ctx)
{
    SCEnter();

    SCReturn;
}

/**
 * \todo Not finished yet.
 */
static void AlpdPPCtxDestroy(AlpdPPCtx *ctx)
{
    SCReturn();

    SCReturn;
}

/***** Public API *****/

void *AlpdGetCtx(void)
{
    SCEnter();

    AlpdCtx *ctx = NULL;
    int i;

    ctx = SCMalloc(sizeof(*ctx));
    if (ctx == NULL)
        goto error;
    memset(ctx, 0, sizeof(*ctx));

    for (i = 0; i < FLOW_PROTO_MAX; i++) {
        MpmInitCtx(&ctx->ctx_ipp[i].ctx_pm[0].mpm_ctx);
        MpmInitCtx(&ctx->ctx_ipp[i].ctx_pm[1].mpm_ctx);
    }

    goto end;
 error:
    ctx = NULL;
 end:
    SCReturnPtr(ctx, "void *");
}

void AlpdDestoryCtx(void *ctx)
{
    SCEnter();

    AlpdCtx *alpd_ctx = (AlpdCtx *)ctx;
    int i;

    for (i = 0; i < FLOW_PROTO_MAX; i++) {
        AlpdPMCtxDestroy(&alpd_ctx->ctx_ipp[i].ctx_pm[0]);
        AlpdPMCtxDestroy(&alpd_ctx->ctx_ipp[i].ctx_pm[1]);
        AlpdPPCtxDestroy(alpd_ctx->ctx_ipp[i].ctx_pp);
    }
    SCFree(ctx);

    SCReturn;
}

int AlpdRegisterProtocol(void *ctx,
                         AppProto alproto, const char *alproto_str)
{
    SCEnter();

    int ret = 0;
    AlpdCtx *alpd_ctx = (AlpdCtx *)ctx;

    if (alpd_ctx->alproto[alproto] != NULL) {
        SCLogError(SC_ERR_APP_LAYER_PROTOCOL_DETECTION, "App Protocol \"%s("
                   "%"PRIu16"\" already registered for protocol detection.");
        goto error;
    }
    ctx->alproto[alproto] = alproto_str;

    goto end;
 error:
    ret = -1;
 end:
    SCReturnInt(ret);
}

int AlpdConfProtoDetectionEnabled(const char *alproto)
{
    int ret = 0;
    int enabled = 1;
    char param[100];
    ConfNode *node;
    int r;

    r = snprintf(param, sizeof(param), "%s%s%s", "app-layer.protocols.",
                 alproto, ".enabled");
    if (r < 0) {
        SCLogError(SC_ERR_FATAL, "snprintf failure.");
        goto error;
    } else if (r > (int)sizeof(param)) {
        SCLogError(SC_ERR_FATAL, "buffer not big enough to write param.");
        goto error;
    }

    node = ConfGetNode(param);
    if (node == NULL) {
        SCLogInfo("Entry for %s not found.", param);
        goto end;
    }

    if (strcasecmp(node->val, "yes") == 0) {
        enabled = 1;
    } else if (strcasecmp(node->val, "no") == 0) {
        enabled = 0;
    } else if (strcasecmp(node->val, "detection-only") == 0) {
        enabled = 1;
    } else {
        SCLogError(SC_ERR_FATAL, "Invalid value found for %s.", param);
        goto error;
    }

    goto end;
 error:
    ret = -1;
 end:
    return enabled;
}

void *AlpdGetCtxThread(void *ctx)
{
    SCEnter();

    AlpdCtx *alpd_ctx = (AlpdCtx *)ctx;
    AlpdCtxThread *alpd_tctx = NULL;
    MpmCtx *mpm_ctx;
    MpmThreadCtx *mpm_tctx;
    int i, j;

    tctx = SCMalloc(sizeof(*alpd_ctx));
    if (alpd_ctx == NULL)
        goto error;
    memset(alpd_ctx, 0, sizeof(*alpd_ctx));

    /* Get the max pat id for all the mpm ctxs. */
    if (PmqSetup(&alpd_tctx->pmq, sig_maxid, pat_maxid) < 0)
        goto error;

    for (i = 0; i < FLOW_PROTO_MAX; i++) {
        for (j = 0; j < 2; j++) {
            mpm_ctx = &alpd_ctx->ctx_ipp[i].pm_ctx[j].mpm_ctx;
            mpm_tctx = &alpd_tctx->mpm_tctx[i][j];
            mpm_table[mpm_ctx->mpm_type].InitThreadCtx(mpm_ctx, mpm_tctx,
                                                       sig_maxid);
        }
    }

    goto end;
 error:
    if (alpd_tctx != NULL)
        AlpdDestroyCtxThread(alpd_ctx, alpd_tctx);
    alpd_tctx = NULL;
 end:
    SCReturnPtr(alpd_tctx, "void *");
}

void AlpdDestroyCtxThread(void *ctx, void *tctx)
{
    SCEnter();

    AlpdCtx *alpd_ctx = (AlpdCtx *)ctx;
    AlpdCtxThread *alpd_tctx = (AlpdCtxThread *)tctx;
    MpmCtx *mpm_ctx;
    MpmThreadCtx *mpm_tctx;
    int i, j;

    for (i = 0; i < FLOW_PROTO_MAX; i++) {
        for (j = 0; j < 2; j++) {
            mpm_ctx = &alpd_ctx->ctx_ipp[i].pm_ctx[j].mpm_ctx;
            mpm_tctx = &alpd_tctx->mpm_tctx[i][j];
            mpm_table[mpm_ctx->mpm_type].DestroyThreadCtx(mpm_ctx, mpm_tctx);
        }
    }
    PmqFree(&alpd_tctx->pmq);
    SCFree(tctx);

    SCReturn;
}

int AlpdPMRegisterPatternCS(void *ctx,
                            uint16_t ipproto, uint16_t alproto,
                            const char *pattern,
                            uint16_t depth, uint16_t offset,
                            uint8_t direction)
{
    SCEnter();
    SCReturn(AlpdPMRegisterPattern(ctx,
                                   alproto, ipproto,
                                   pattern,
                                   depth, offset,
                                   direction,
                                   1 /* case-sensitive */));
}

int AlpdPMRegisterPatternCI(void *ctx,
                            uint16_t ipproto, uint16_t alproto,
                            const char *pattern,
                            uint16_t depth, uint16_t offset,
                            uint8_t direction)
{
    SCEnter();
    SCReturn(AlpdPMRegisterPattern(ctx,
                                   alproto, ipproto,
                                   pattern,
                                   depth, offset,
                                   direction,
                                   0 /* !case-sensitive */));
}

int AlpdPrepareState(void *ctx)
{
    AlpdCtx *alpd_ctx = (AlpdCtx *)ctx;
    AlpdPMCtx *ctx_pm;
    MpmCtx *mpm_ctx;
    int i, j;
    PatIntId max_id;
    AlpdPMSignature *s;
    int ret = 0;

    for (i = 0; i < FLOW_PROTO_MAX; i++) {
        for (j = 0; j < 2; j++) {
            ctx_pm = &alpd_ctx->ctx_ipp[i].pm_ctx[j];

            if (AlpdPMSetContentIDs(ctx_pm) < 0)
                goto error;
            if (AlpdPMMapSignatures(ctx_pm) < 0)
                goto error;
            if (AlpdPMPrepareMpm(ctx_pm) < 0)
                goto error;
        }
    }

    goto end;
 error:
    ret = -1;
 end:
    SCReturnInt(ret);
}

uint16_t AlpdGetProto(void *ctx, void *tctx,
                      Flow *f,
                      uint8_t *buf, uint32_t buflen,
                      uint8_t direction, uint8_t ipproto)
{
    AppProto alproto = ALPROTO_UNKNOWN;
    uint16_t pm_results[ALPROTO_MAX];
    uint16_t pm_matches;
    uint8_t dir;
    uint16_t i;

    if (!FLOW_IS_PM_DONE(f, flags)) {
        pm_matches = AlpdPMGetProto(ctx, tctx,
                                    f,
                                    buf, buflen,
                                    flags,
                                    ipproto,
                                    pm_results);
        if (pm_matches > 0)
            alproto = pm_results[0];
    }

 end:
    return alproto;
}

/******************************Unittests******************************/

#ifdef UNITTESTS

//static int AlpdTest01(void)
//{
//    char *buf = SCStrdup("HTTP");
//    int r = 1;
//    AlpProtoDetectCtx ctx;
//
//    AlpProtoInit(&ctx);
//
//    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
//    SCFree(buf);
//
//    if (ctx.toclient.id != 1) {
//        r = 0;
//    }
//
//    buf = SCStrdup("GET");
//    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOSERVER);
//    if (ctx.toserver.id != 1) {
//        r = 0;
//    }
//    SCFree(buf);
//
//    AlpProtoTestDestroy(&ctx);
//
//    return r;
//}
//
//static int AlpdTest02(void)
//{
//    char *buf = SCStrdup("HTTP");
//    int r = 1;
//    AlpProtoDetectCtx ctx;
//
//    AlpProtoInit(&ctx);
//
//    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
//    SCFree(buf);
//
//    if (ctx.toclient.id != 1) {
//        r = 0;
//    }
//
//    buf = SCStrdup("220 ");
//    AlpProtoAdd(&ctx, "ftp", IPPROTO_TCP, ALPROTO_FTP, buf, 4, 0, STREAM_TOCLIENT);
//    SCFree(buf);
//
//    if (ctx.toclient.id != 2) {
//        r = 0;
//    }
//
//    AlpProtoTestDestroy(&ctx);
//
//    return r;
//}
//
//static int AlpdTest03(void)
//{
//    uint8_t l7data[] = "HTTP/1.1 200 OK\r\nServer: Apache/1.0\r\n\r\n";
//    char *buf = SCStrdup("HTTP");
//    int r = 1;
//    AlpProtoDetectCtx ctx;
//    AlpProtoDetectThreadCtx tctx;
//
//    AlpProtoInit(&ctx);
//
//    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
//    SCFree(buf);
//
//    if (ctx.toclient.id != 1) {
//        r = 0;
//    }
//
//    buf = SCStrdup("220 ");
//    AlpProtoAdd(&ctx, "ftp", IPPROTO_TCP, ALPROTO_FTP, buf, 4, 0, STREAM_TOCLIENT);
//    SCFree(buf);
//
//    if (ctx.toclient.id != 2) {
//        r = 0;
//    }
//
//    AlpProtoFinalizeGlobal(&ctx);
//    AlpProtoFinalizeThread(&ctx, &tctx);
//
//    uint32_t cnt = mpm_table[ctx.toclient.mpm_ctx.mpm_type].Search(&ctx.toclient.mpm_ctx, &tctx.toclient.mpm_ctx, NULL, l7data, sizeof(l7data));
//    if (cnt != 1) {
//        printf("cnt %u != 1: ", cnt);
//        r = 0;
//    }
//
//    AlpProtoTestDestroy(&ctx);
//
//    return r;
//}
//
//static int AlpdTest04(void)
//{
//    uint8_t l7data[] = "HTTP/1.1 200 OK\r\nServer: Apache/1.0\r\n\r\n";
//    char *buf = SCStrdup("200 ");
//    int r = 1;
//    AlpProtoDetectCtx ctx;
//    AlpProtoDetectThreadCtx tctx;
//
//    AlpProtoInit(&ctx);
//
//    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
//    SCFree(buf);
//
//    if (ctx.toclient.id != 1) {
//        r = 0;
//    }
//
//    AlpProtoFinalizeGlobal(&ctx);
//    AlpProtoFinalizeThread(&ctx, &tctx);
//
//    uint32_t cnt = mpm_table[ctx.toclient.mpm_ctx.mpm_type].Search(&ctx.toclient.mpm_ctx, &tctx.toclient.mpm_ctx, &tctx.toclient.pmq, l7data, sizeof(l7data));
//    if (cnt != 1) {
//        printf("cnt %u != 1: ", cnt);
//        r = 0;
//    }
//
//    AlpProtoTestDestroy(&ctx);
//
//    return r;
//}
//
//static int AlpdTest05(void)
//{
//    uint8_t l7data[] = "HTTP/1.1 200 OK\r\nServer: Apache/1.0\r\n\r\n<HTML><BODY>Blahblah</BODY></HTML>";
//    char *buf = SCStrdup("HTTP");
//    int r = 1;
//
//    AlpProtoDetectCtx ctx;
//    AlpProtoDetectThreadCtx tctx;
//
//    AlpProtoInit(&ctx);
//
//    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
//    SCFree(buf);
//
//    if (ctx.toclient.id != 1) {
//        r = 0;
//    }
//
//    buf = SCStrdup("220 ");
//    AlpProtoAdd(&ctx, "ftp", IPPROTO_TCP, ALPROTO_FTP, buf, 4, 0, STREAM_TOCLIENT);
//    SCFree(buf);
//
//    if (ctx.toclient.id != 2) {
//        r = 0;
//    }
//
//    AlpProtoFinalizeGlobal(&ctx);
//    AlpProtoFinalizeThread(&ctx, &tctx);
//
//    uint16_t pm_results[ALPROTO_MAX];
//    Flow f;
//    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data,sizeof(l7data), STREAM_TOCLIENT, IPPROTO_TCP, pm_results);
//    if (pm_results[0] != ALPROTO_HTTP) {
//        printf("proto %" PRIu8 " != %" PRIu8 ": ", pm_results[0], ALPROTO_HTTP);
//        r = 0;
//    }
//
//    AlpProtoTestDestroy(&ctx);
//
//    return r;
//}
//
//static int AlpdTest06(void)
//{
//    uint8_t l7data[] = "220 Welcome to the OISF FTP server\r\n";
//    char *buf = SCStrdup("HTTP");
//    int r = 1;
//    AlpProtoDetectCtx ctx;
//    AlpProtoDetectThreadCtx tctx;
//
//    AlpProtoInit(&ctx);
//
//    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
//    SCFree(buf);
//
//    if (ctx.toclient.id != 1) {
//        r = 0;
//    }
//
//    buf = SCStrdup("220 ");
//    AlpProtoAdd(&ctx, "ftp", IPPROTO_TCP, ALPROTO_FTP, buf, 4, 0, STREAM_TOCLIENT);
//    SCFree(buf);
//
//    if (ctx.toclient.id != 2) {
//        r = 0;
//    }
//
//    AlpProtoFinalizeGlobal(&ctx);
//    AlpProtoFinalizeThread(&ctx, &tctx);
//
//    uint16_t pm_results[ALPROTO_MAX];
//    Flow f;
//    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data,sizeof(l7data), STREAM_TOCLIENT, IPPROTO_TCP, pm_results);
//    if (pm_results[0] != ALPROTO_FTP) {
//        printf("proto %" PRIu8 " != %" PRIu8 ": ", pm_results[0], ALPROTO_FTP);
//        r = 0;
//    }
//
//    AlpProtoTestDestroy(&ctx);
//
//    return r;
//}
//
//static int AlpdTest07(void)
//{
//    uint8_t l7data[] = "220 Welcome to the OISF HTTP/FTP server\r\n";
//    char *buf = SCStrdup("HTTP");
//    int r = 1;
//    AlpProtoDetectCtx ctx;
//    AlpProtoDetectThreadCtx tctx;
//
//    AlpProtoInit(&ctx);
//
//    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
//    SCFree(buf);
//
//    if (ctx.toclient.id != 1) {
//        r = 0;
//    }
//
//    AlpProtoFinalizeGlobal(&ctx);
//    AlpProtoFinalizeThread(&ctx, &tctx);
//
//    uint16_t pm_results[ALPROTO_MAX];
//    Flow f;
//    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data,sizeof(l7data), STREAM_TOCLIENT, IPPROTO_TCP, pm_results);
//    if (pm_results[0] != ALPROTO_UNKNOWN) {
//        printf("proto %" PRIu8 " != %" PRIu8 ": ", pm_results[0], ALPROTO_UNKNOWN);
//        r = 0;
//    }
//
//    AlpProtoTestDestroy(&ctx);
//
//    return r;
//}
//
//static int AlpdTest08(void)
//{
//    uint8_t l7data[] = "\x00\x00\x00\x85"  // NBSS
//        "\xff\x53\x4d\x42\x72\x00\x00\x00" // SMB
//        "\x00\x18\x53\xc8\x00\x00\x00\x00"
//        "\x00\x00\x00\x00\x00\x00\x00\x00"
//        "\x00\x00\xff\xfe\x00\x00\x00\x00"
//        "\x00" // WordCount
//        "\x62\x00" // ByteCount
//        "\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20"
//        "\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73"
//        "\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c"
//        "\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54"
//        "\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00";
//    char *buf = SCStrdup("|ff|SMB");
//    int r = 1;
//    AlpProtoDetectCtx ctx;
//    AlpProtoDetectThreadCtx tctx;
//
//    AlpProtoInit(&ctx);
//
//    AlpProtoAdd(&ctx, "smb", IPPROTO_TCP, ALPROTO_SMB, buf, 8, 4, STREAM_TOCLIENT);
//    SCFree(buf);
//
//    if (ctx.toclient.id != 1) {
//        r = 0;
//    }
//
//    AlpProtoFinalizeGlobal(&ctx);
//    AlpProtoFinalizeThread(&ctx, &tctx);
//
//    uint16_t pm_results[ALPROTO_MAX];
//    Flow f;
//    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data,sizeof(l7data), STREAM_TOCLIENT, IPPROTO_TCP, pm_results);
//    if (pm_results[0] != ALPROTO_SMB) {
//        printf("proto %" PRIu8 " != %" PRIu8 ": ", pm_results[0], ALPROTO_SMB);
//        r = 0;
//    }
//
//    AlpProtoTestDestroy(&ctx);
//
//    return r;
//}
//
//static int AlpdTest09(void)
//{
//    uint8_t l7data[] =
//        "\x00\x00\x00\x66" // NBSS
//        "\xfe\x53\x4d\x42\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00" // SMB2
//        "\x3f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
//        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
//        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
//        "\x24\x00\x01\x00x00\x00\x00\x00\x00\x00\x0\x00\x00\x00\x00\x00\x00\x00\x00"
//        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x02";
//
//    char *buf = SCStrdup("|fe|SMB");
//    int r = 1;
//    AlpProtoDetectCtx ctx;
//    AlpProtoDetectThreadCtx tctx;
//
//    AlpProtoInit(&ctx);
//
//    AlpProtoAdd(&ctx, "smb2", IPPROTO_TCP, ALPROTO_SMB2, buf, 8, 4, STREAM_TOCLIENT);
//    SCFree(buf);
//
//    if (ctx.toclient.id != 1) {
//        r = 0;
//    }
//
//    AlpProtoFinalizeGlobal(&ctx);
//    AlpProtoFinalizeThread(&ctx, &tctx);
//
//    uint16_t pm_results[ALPROTO_MAX];
//    Flow f;
//    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data,sizeof(l7data), STREAM_TOCLIENT, IPPROTO_TCP, pm_results);
//    if (pm_results[0] != ALPROTO_SMB2) {
//        printf("proto %" PRIu8 " != %" PRIu8 ": ", pm_results[0], ALPROTO_SMB2);
//        r = 0;
//    }
//
//    AlpProtoTestDestroy(&ctx);
//
//    return r;
//}
//
//static int AlpdTest10(void)
//{
//    uint8_t l7data[] = "\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00"
//        "\x00\x00\x00\x00\xd0\x16\xd0\x16\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00"
//        "\x01\x00\xb8\x4a\x9f\x4d\x1c\x7d\xcf\x11\x86\x1e\x00\x20\xaf\x6e\x7c\x57"
//        "\x00\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10"
//        "\x48\x60\x02\x00\x00\x00";
//    char *buf = SCStrdup("|05 00|");
//    int r = 1;
//    AlpProtoDetectCtx ctx;
//    AlpProtoDetectThreadCtx tctx;
//
//    AlpProtoInit(&ctx);
//
//    AlpProtoAdd(&ctx, "dcerpc", IPPROTO_TCP, ALPROTO_DCERPC, buf, 4, 0, STREAM_TOCLIENT);
//    SCFree(buf);
//
//    if (ctx.toclient.id != 1) {
//        r = 0;
//    }
//
//    AlpProtoFinalizeGlobal(&ctx);
//    AlpProtoFinalizeThread(&ctx, &tctx);
//
//    uint16_t pm_results[ALPROTO_MAX];
//    Flow f;
//    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data,sizeof(l7data), STREAM_TOCLIENT, IPPROTO_TCP, pm_results);
//    if (pm_results[0] != ALPROTO_DCERPC) {
//        printf("proto %" PRIu8 " != %" PRIu8 ": ", pm_results[0], ALPROTO_DCERPC);
//        r = 0;
//    }
//
//    AlpProtoTestDestroy(&ctx);
//
//    return r;
//}
//
///** \test why we still get http for connect... obviously because we also match on the reply, duh */
//static int AlpdTest11(void)
//{
//    uint8_t l7data[] = "CONNECT www.ssllabs.com:443 HTTP/1.0\r\n";
//    uint8_t l7data_resp[] = "HTTP/1.1 405 Method Not Allowed\r\n";
//    int r = 1;
//    AlpProtoDetectCtx ctx;
//    AlpProtoDetectThreadCtx tctx;
//
//    AlpProtoInit(&ctx);
//
//    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, "HTTP", 4, 0, STREAM_TOSERVER);
//    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, "GET", 3, 0, STREAM_TOSERVER);
//    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, "PUT", 3, 0, STREAM_TOSERVER);
//    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, "POST", 4, 0, STREAM_TOSERVER);
//    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, "TRACE", 5, 0, STREAM_TOSERVER);
//    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, "OPTIONS", 7, 0, STREAM_TOSERVER);
//    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, "HTTP", 4, 0, STREAM_TOCLIENT);
//
//    if (ctx.toserver.id != 6) {
//        printf("ctx.toserver.id %u != 6: ", ctx.toserver.id);
//        r = 0;
//    }
//
//    AlpProtoFinalizeGlobal(&ctx);
//    AlpProtoFinalizeThread(&ctx, &tctx);
//
//    uint16_t pm_results[ALPROTO_MAX];
//    Flow f;
//    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data, sizeof(l7data), STREAM_TOCLIENT, IPPROTO_TCP, pm_results);
//    if (pm_results[0] == ALPROTO_HTTP) {
//        printf("proto %" PRIu8 " == %" PRIu8 ": ", pm_results[0], ALPROTO_HTTP);
//        r = 0;
//    }
//
//    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data_resp, sizeof(l7data_resp), STREAM_TOSERVER, IPPROTO_TCP, pm_results);
//    if (pm_results[0] != ALPROTO_HTTP) {
//        printf("proto %" PRIu8 " != %" PRIu8 ": ", pm_results[0], ALPROTO_HTTP);
//        r = 0;
//    }
//
//    AlpProtoTestDestroy(&ctx);
//    return r;
//}
//
///** \test AlpProtoSignature test */
//static int AlpdTest12(void)
//{
//    AlpProtoDetectCtx ctx;
//    int r = 0;
//
//    AlpProtoInit(&ctx);
//    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, "HTTP", 4, 0, STREAM_TOSERVER);
//    AlpProtoFinalizeGlobal(&ctx);
//
//    if (ctx.head == NULL) {
//        printf("ctx.head == NULL: ");
//        goto end;
//    }
//
//    if (ctx.head->proto != ALPROTO_HTTP) {
//        printf("ctx.head->proto != ALPROTO_HTTP: ");
//        goto end;
//    }
//
//    if (ctx.sigs != 1) {
//        printf("ctx.sigs %"PRIu16", expected 1: ", ctx.sigs);
//        goto end;
//    }
//
//    r = 1;
//end:
//    return r;
//}
//
///**
// * \test What about if we add some sigs only for udp but call for tcp?
// *       It should not detect any proto
// */
//static int AlpdTest13(void)
//{
//    uint8_t l7data[] = "CONNECT www.ssllabs.com:443 HTTP/1.0\r\n";
//    uint8_t l7data_resp[] = "HTTP/1.1 405 Method Not Allowed\r\n";
//    int r = 1;
//    AlpProtoDetectCtx ctx;
//    AlpProtoDetectThreadCtx tctx;
//
//    AlpProtoInit(&ctx);
//
//    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "HTTP", 4, 0, STREAM_TOSERVER);
//    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "GET", 3, 0, STREAM_TOSERVER);
//    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "PUT", 3, 0, STREAM_TOSERVER);
//    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "POST", 4, 0, STREAM_TOSERVER);
//    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "TRACE", 5, 0, STREAM_TOSERVER);
//    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "OPTIONS", 7, 0, STREAM_TOSERVER);
//    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "HTTP", 4, 0, STREAM_TOCLIENT);
//
//    if (ctx.toserver.id != 6) {
//        printf("ctx.toserver.id %u != 6: ", ctx.toserver.id);
//        r = 0;
//    }
//
//    AlpProtoFinalizeGlobal(&ctx);
//    AlpProtoFinalizeThread(&ctx, &tctx);
//
//    uint16_t pm_results[ALPROTO_MAX];
//    Flow f;
//    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data, sizeof(l7data), STREAM_TOCLIENT, IPPROTO_TCP, pm_results);
//    if (pm_results[0] == ALPROTO_HTTP) {
//        printf("proto %" PRIu8 " == %" PRIu8 ": ", pm_results[0], ALPROTO_HTTP);
//        r = 0;
//    }
//
//    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data_resp, sizeof(l7data_resp), STREAM_TOSERVER, IPPROTO_TCP, pm_results);
//    if (pm_results[0] == ALPROTO_HTTP) {
//        printf("proto %" PRIu8 " != %" PRIu8 ": ", pm_results[0], ALPROTO_HTTP);
//        r = 0;
//    }
//
//    AlpProtoTestDestroy(&ctx);
//    return r;
//}
//
///**
// * \test What about if we add some sigs only for udp calling it for UDP?
// *       It should detect ALPROTO_HTTP (over udp). This is just a check
// *       to ensure that TCP/UDP differences work correctly.
// */
//static int AlpdTest14(void)
//{
//    uint8_t l7data[] = "CONNECT www.ssllabs.com:443 HTTP/1.0\r\n";
//    uint8_t l7data_resp[] = "HTTP/1.1 405 Method Not Allowed\r\n";
//    int r = 1;
//    AlpProtoDetectCtx ctx;
//    AlpProtoDetectThreadCtx tctx;
//
//    AlpProtoInit(&ctx);
//
//    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "HTTP", 4, 0, STREAM_TOSERVER);
//    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "GET", 3, 0, STREAM_TOSERVER);
//    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "PUT", 3, 0, STREAM_TOSERVER);
//    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "POST", 4, 0, STREAM_TOSERVER);
//    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "TRACE", 5, 0, STREAM_TOSERVER);
//    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "OPTIONS", 7, 0, STREAM_TOSERVER);
//    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "HTTP", 4, 0, STREAM_TOCLIENT);
//
//    if (ctx.toserver.id != 6) {
//        printf("ctx.toserver.id %u != 6: ", ctx.toserver.id);
//        r = 0;
//    }
//
//    AlpProtoFinalizeGlobal(&ctx);
//    AlpProtoFinalizeThread(&ctx, &tctx);
//
//    uint16_t pm_results[ALPROTO_MAX];
//    Flow f;
//    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data, sizeof(l7data), STREAM_TOCLIENT, IPPROTO_UDP, pm_results);
//    if (pm_results[0] == ALPROTO_HTTP) {
//        printf("proto %" PRIu8 " == %" PRIu8 ": ", pm_results[0], ALPROTO_HTTP);
//        r = 0;
//    }
//
//    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data_resp, sizeof(l7data_resp), STREAM_TOSERVER, IPPROTO_UDP, pm_results);
//    if (pm_results[0] != ALPROTO_HTTP) {
//        printf("proto %" PRIu8 " != %" PRIu8 ": ", pm_results[0], ALPROTO_HTTP);
//        r = 0;
//    }
//
//    AlpProtoTestDestroy(&ctx);
//    return r;
//}
//
///** \test test if the engine detect the proto and match with it */
//static int AlpdTest15(void)
//{
//    int result = 0;
//    Flow *f = NULL;
//    HtpState *http_state = NULL;
//    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
//        "User-Agent: Mozilla/1.0\r\n"
//        "Cookie: hellocatch\r\n\r\n";
//    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
//    TcpSession ssn;
//    Packet *p = NULL;
//    Signature *s = NULL;
//    ThreadVars tv;
//    DetectEngineThreadCtx *det_ctx = NULL;
//    DetectEngineCtx *de_ctx = NULL;
//
//    memset(&tv, 0, sizeof(ThreadVars));
//    memset(&ssn, 0, sizeof(TcpSession));
//
//    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
//    if (p == NULL) {
//        printf("packet setup failed: ");
//        goto end;
//    }
//
//    f = UTHBuildFlow(AF_INET, "1.1.1.1", "2.2.2.2", 1024, 80);
//    if (f == NULL) {
//        printf("flow setup failed: ");
//        goto end;
//    }
//    f->protoctx = &ssn;
//    p->flow = f;
//
//    p->flowflags |= FLOW_PKT_TOSERVER;
//    p->flowflags |= FLOW_PKT_ESTABLISHED;
//    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
//
//    f->alproto = ALPROTO_HTTP;
//
//    StreamTcpInitConfig(TRUE);
//
//    de_ctx = DetectEngineCtxInit();
//    if (de_ctx == NULL) {
//        goto end;
//    }
//    de_ctx->mpm_matcher = MPM_B2G;
//    de_ctx->flags |= DE_QUIET;
//
//    s = de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
//                                   "(msg:\"Test content option\"; "
//                                   "sid:1;)");
//    if (s == NULL) {
//        goto end;
//    }
//
//    SigGroupBuild(de_ctx);
//    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);
//
//   SCMutexLock(&f->m);
//   int r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
//    if (r != 0) {
//        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
//        SCMutexUnlock(&f->m);
//        goto end;
//    }
//    SCMutexUnlock(&f->m);
//
//    http_state = f->alstate;
//    if (http_state == NULL) {
//        printf("no http state: ");
//        goto end;
//    }
//
//    /* do detect */
//    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
//
//    if (!PacketAlertCheck(p, 1)) {
//        printf("sig 1 didn't alert, but it should: ");
//        goto end;
//    }
//    result = 1;
//end:
//    if (det_ctx != NULL)
//        DetectEngineThreadCtxDeinit(&tv, det_ctx);
//    if (de_ctx != NULL)
//        SigGroupCleanup(de_ctx);
//    if (de_ctx != NULL)
//        DetectEngineCtxFree(de_ctx);
//
//    StreamTcpFreeConfig(TRUE);
//
//    UTHFreePackets(&p, 1);
//    UTHFreeFlow(f);
//    return result;
//}
//
///** \test test if the engine detect the proto on a non standar port
// * and match with it */
//static int AlpdTest16(void)
//{
//    int result = 0;
//    Flow *f = NULL;
//    HtpState *http_state = NULL;
//    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
//        "User-Agent: Mozilla/1.0\r\n"
//        "Cookie: hellocatch\r\n\r\n";
//    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
//    TcpSession ssn;
//    Packet *p = NULL;
//    Signature *s = NULL;
//    ThreadVars tv;
//    DetectEngineThreadCtx *det_ctx = NULL;
//    DetectEngineCtx *de_ctx = NULL;
//
//    memset(&tv, 0, sizeof(ThreadVars));
//    memset(&ssn, 0, sizeof(TcpSession));
//
//    p = UTHBuildPacketSrcDstPorts(http_buf1, http_buf1_len, IPPROTO_TCP, 12345, 88);
//
//    f = UTHBuildFlow(AF_INET, "1.1.1.1", "2.2.2.2", 1024, 80);
//    if (f == NULL)
//        goto end;
//    f->protoctx = &ssn;
//    p->flow = f;
//    p->flowflags |= FLOW_PKT_TOSERVER;
//    p->flowflags |= FLOW_PKT_ESTABLISHED;
//    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
//    f->alproto = ALPROTO_HTTP;
//
//    StreamTcpInitConfig(TRUE);
//
//    de_ctx = DetectEngineCtxInit();
//    if (de_ctx == NULL) {
//        goto end;
//    }
//    de_ctx->mpm_matcher = MPM_B2G;
//    de_ctx->flags |= DE_QUIET;
//
//    s = de_ctx->sig_list = SigInit(de_ctx, "alert http any !80 -> any any "
//                                   "(msg:\"http over non standar port\"; "
//                                   "sid:1;)");
//    if (s == NULL) {
//        goto end;
//    }
//
//    SigGroupBuild(de_ctx);
//    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);
//
//    SCMutexLock(&f->m);
//    int r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
//    if (r != 0) {
//        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
//        SCMutexUnlock(&f->m);
//        goto end;
//    }
//    SCMutexUnlock(&f->m);
//
//    http_state = f->alstate;
//    if (http_state == NULL) {
//        printf("no http state: ");
//        goto end;
//    }
//
//    /* do detect */
//    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
//
//    if (!PacketAlertCheck(p, 1)) {
//        printf("sig 1 didn't alert, but it should: ");
//        goto end;
//    }
//
//    result = 1;
//
//end:
//    if (det_ctx != NULL)
//        DetectEngineThreadCtxDeinit(&tv, det_ctx);
//    if (de_ctx != NULL)
//        SigGroupCleanup(de_ctx);
//    if (de_ctx != NULL)
//        DetectEngineCtxFree(de_ctx);
//
//    StreamTcpFreeConfig(TRUE);
//
//    UTHFreePackets(&p, 1);
//    UTHFreeFlow(f);
//    return result;
//}
//
///** \test test if the engine detect the proto and doesn't match
// * because the sig expects another proto (ex ftp)*/
//static int AlpdTest17(void)
//{
//    int result = 0;
//    Flow *f = NULL;
//    HtpState *http_state = NULL;
//    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
//        "User-Agent: Mozilla/1.0\r\n"
//        "Cookie: hellocatch\r\n\r\n";
//    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
//    TcpSession ssn;
//    Packet *p = NULL;
//    Signature *s = NULL;
//    ThreadVars tv;
//    DetectEngineThreadCtx *det_ctx = NULL;
//    DetectEngineCtx *de_ctx = NULL;
//
//    memset(&tv, 0, sizeof(ThreadVars));
//    memset(&ssn, 0, sizeof(TcpSession));
//
//    p = UTHBuildPacket(http_buf1, http_buf1_len, IPPROTO_TCP);
//
//    f = UTHBuildFlow(AF_INET, "1.1.1.1", "2.2.2.2", 1024, 80);
//    if (f == NULL)
//        goto end;
//    f->protoctx = &ssn;
//    p->flow = f;
//    p->flowflags |= FLOW_PKT_TOSERVER;
//    p->flowflags |= FLOW_PKT_ESTABLISHED;
//    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
//    f->alproto = ALPROTO_HTTP;
//
//    StreamTcpInitConfig(TRUE);
//
//    de_ctx = DetectEngineCtxInit();
//    if (de_ctx == NULL) {
//        goto end;
//    }
//    de_ctx->mpm_matcher = MPM_B2G;
//    de_ctx->flags |= DE_QUIET;
//
//    s = de_ctx->sig_list = SigInit(de_ctx, "alert ftp any any -> any any "
//                                   "(msg:\"Test content option\"; "
//                                   "sid:1;)");
//    if (s == NULL) {
//        goto end;
//    }
//
//    SigGroupBuild(de_ctx);
//    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);
//
//    SCMutexLock(&f->m);
//    int r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
//    if (r != 0) {
//        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
//        SCMutexUnlock(&f->m);
//        goto end;
//    }
//    SCMutexUnlock(&f->m);
//
//    http_state = f->alstate;
//    if (http_state == NULL) {
//        printf("no http state: ");
//        goto end;
//    }
//
//    /* do detect */
//    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
//
//    if (PacketAlertCheck(p, 1)) {
//        printf("sig 1 alerted, but it should not (it's not ftp): ");
//        goto end;
//    }
//
//    result = 1;
//end:
//    if (det_ctx != NULL)
//        DetectEngineThreadCtxDeinit(&tv, det_ctx);
//    if (de_ctx != NULL)
//        SigGroupCleanup(de_ctx);
//    if (de_ctx != NULL)
//        DetectEngineCtxFree(de_ctx);
//
//    StreamTcpFreeConfig(TRUE);
//
//    UTHFreePackets(&p, 1);
//    UTHFreeFlow(f);
//    return result;
//}
//
///** \test test if the engine detect the proto and doesn't match
// * because the packet has another proto (ex ftp) */
//static int AlpdTest18(void)
//{
//    int result = 0;
//    Flow *f = NULL;
//    uint8_t http_buf1[] = "MPUT one\r\n";
//    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
//    TcpSession ssn;
//    Packet *p = NULL;
//    Signature *s = NULL;
//    ThreadVars tv;
//    DetectEngineThreadCtx *det_ctx = NULL;
//    DetectEngineCtx *de_ctx = NULL;
//
//    memset(&tv, 0, sizeof(ThreadVars));
//    memset(&ssn, 0, sizeof(TcpSession));
//
//    p = UTHBuildPacketSrcDstPorts(http_buf1, http_buf1_len, IPPROTO_TCP, 12345, 88);
//
//    f = UTHBuildFlow(AF_INET, "1.1.1.1", "2.2.2.2", 1024, 80);
//    if (f == NULL)
//        goto end;
//    f->protoctx = &ssn;
//    p->flow = f;
//    p->flowflags |= FLOW_PKT_TOSERVER;
//    p->flowflags |= FLOW_PKT_ESTABLISHED;
//    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
//    f->alproto = ALPROTO_FTP;
//
//    StreamTcpInitConfig(TRUE);
//
//    de_ctx = DetectEngineCtxInit();
//    if (de_ctx == NULL) {
//        goto end;
//    }
//    de_ctx->mpm_matcher = MPM_B2G;
//    de_ctx->flags |= DE_QUIET;
//
//    s = de_ctx->sig_list = SigInit(de_ctx, "alert http any !80 -> any any "
//                                   "(msg:\"http over non standar port\"; "
//                                   "sid:1;)");
//    if (s == NULL) {
//        goto end;
//    }
//
//    SigGroupBuild(de_ctx);
//    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);
//
//    SCMutexLock(&f->m);
//    int r = AppLayerParse(NULL, f, ALPROTO_FTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
//    if (r != 0) {
//        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
//        SCMutexUnlock(&f->m);
//        goto end;
//    }
//    SCMutexUnlock(&f->m);
//
//    /* do detect */
//    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
//
//    if (PacketAlertCheck(p, 1)) {
//        printf("sig 1 alerted, but it should not (it's ftp): ");
//        goto end;
//    }
//
//    result = 1;
//
//end:
//    if (det_ctx != NULL)
//        DetectEngineThreadCtxDeinit(&tv, det_ctx);
//    if (de_ctx != NULL)
//        SigGroupCleanup(de_ctx);
//    if (de_ctx != NULL)
//        DetectEngineCtxFree(de_ctx);
//
//    StreamTcpFreeConfig(TRUE);
//    UTHFreePackets(&p, 1);
//    UTHFreeFlow(f);
//    return result;
//}
//
///** \test test if the engine detect the proto and match with it
// *        and also against a content option */
//static int AlpdTest19(void)
//{
//    int result = 0;
//    Flow *f = NULL;
//    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
//        "User-Agent: Mozilla/1.0\r\n"
//        "Cookie: hellocatch\r\n\r\n";
//    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
//    TcpSession ssn;
//    Packet *p = NULL;
//    Signature *s = NULL;
//    ThreadVars tv;
//    DetectEngineThreadCtx *det_ctx = NULL;
//    DetectEngineCtx *de_ctx = NULL;
//
//    memset(&tv, 0, sizeof(ThreadVars));
//    memset(&ssn, 0, sizeof(TcpSession));
//
//    p = UTHBuildPacket(http_buf1, http_buf1_len, IPPROTO_TCP);
//
//    f = UTHBuildFlow(AF_INET, "1.1.1.1", "2.2.2.2", 1024, 80);
//    if (f == NULL)
//        goto end;
//    f->protoctx = &ssn;
//    p->flow = f;
//    p->flowflags |= FLOW_PKT_TOSERVER;
//    p->flowflags |= FLOW_PKT_ESTABLISHED;
//    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
//    f->alproto = ALPROTO_HTTP;
//    f->proto = IPPROTO_TCP;
//    p->flags |= PKT_STREAM_ADD;
//    p->flags |= PKT_STREAM_EOF;
//
//    de_ctx = DetectEngineCtxInit();
//    if (de_ctx == NULL) {
//        goto end;
//    }
//
//    StreamTcpInitConfig(TRUE);
//
//    StreamMsg *stream_msg = StreamMsgGetFromPool();
//    if (stream_msg == NULL) {
//        printf("no stream_msg: ");
//        goto end;
//    }
//
//    memcpy(stream_msg->data.data, http_buf1, http_buf1_len);
//    stream_msg->data.data_len = http_buf1_len;
//
//    ssn.toserver_smsg_head = stream_msg;
//    ssn.toserver_smsg_tail = stream_msg;
//
//    de_ctx->mpm_matcher = MPM_B2G;
//    de_ctx->flags |= DE_QUIET;
//
//    s = de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
//                                   "(msg:\"Test content option\"; "
//                                   "content:\"one\"; sid:1;)");
//    if (s == NULL) {
//        goto end;
//    }
//
//    SigGroupBuild(de_ctx);
//    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);
//
//    SCMutexLock(&f->m);
//    int r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
//    if (r != 0) {
//        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
//        SCMutexUnlock(&f->m);
//        goto end;
//    }
//    SCMutexUnlock(&f->m);
//
//    /* do detect */
//    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
//
//    if (!PacketAlertCheck(p, 1)) {
//        printf("sig 1 didn't alert, but it should: ");
//        goto end;
//    }
//
//    result = 1;
//
//end:
//    if (det_ctx != NULL)
//        DetectEngineThreadCtxDeinit(&tv, det_ctx);
//    if (de_ctx != NULL)
//        SigGroupCleanup(de_ctx);
//    if (de_ctx != NULL)
//        DetectEngineCtxFree(de_ctx);
//
//    StreamTcpFreeConfig(TRUE);
//    UTHFreePackets(&p, 1);
//    UTHFreeFlow(f);
//    return result;
//}

#endif /* UNITTESTS */

void AlpdRegisterTests(void)
{
#ifdef UNITTESTS
//    UtRegisterTest("AlpdTest01", AlpdTest01, 1);
//    UtRegisterTest("AlpdTest02", AlpdTest02, 1);
//    UtRegisterTest("AlpdTest03", AlpdTest03, 1);
//    UtRegisterTest("AlpdTest04", AlpdTest04, 1);
//    UtRegisterTest("AlpdTest05", AlpdTest05, 1);
//    UtRegisterTest("AlpdTest06", AlpdTest06, 1);
//    UtRegisterTest("AlpdTest07", AlpdTest07, 1);
//    UtRegisterTest("AlpdTest08", AlpdTest08, 1);
//    UtRegisterTest("AlpdTest09", AlpdTest09, 1);
//    UtRegisterTest("AlpdTest10", AlpdTest10, 1);
//    UtRegisterTest("AlpdTest11", AlpdTest11, 1);
//    UtRegisterTest("AlpdTest12", AlpdTest12, 1);
//    UtRegisterTest("AlpdTest13", AlpdTest13, 1);
//    UtRegisterTest("AlpdTest14", AlpdTest14, 1);
//    UtRegisterTest("AlpdTest15", AlpdTest15, 1);
//    UtRegisterTest("AlpdTest16", AlpdTest16, 1);
//    UtRegisterTest("AlpdTest17", AlpdTest17, 1);
//    UtRegisterTest("AlpdTest18", AlpdTest18, 1);
//    UtRegisterTest("AlpdTest19", AlpdTest19, 1);
#endif /* UNITTESTS */

    return;
}
