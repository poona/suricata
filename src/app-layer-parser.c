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
 *
 * Generic App-layer parsing functions.
 */

#include "suricata-common.h"
#include "debug.h"
#include "util-unittest.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"

#include "flow-util.h"

#include "detect-engine-state.h"
#include "detect-engine-port.h"

#include "stream-tcp.h"
#include "stream-tcp-private.h"
#include "stream.h"
#include "stream-tcp-reassemble.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-smb.h"
#include "app-layer-smb2.h"
#include "app-layer-dcerpc.h"
#include "app-layer-dcerpc-udp.h"
#include "app-layer-htp.h"
#include "app-layer-ftp.h"
#include "app-layer-ssl.h"
#include "app-layer-ssh.h"
#include "app-layer-smtp.h"
#include "app-layer-dns-udp.h"
#include "app-layer-dns-tcp.h"

#include "conf.h"
#include "util-spm.h"

#include "util-debug.h"
#include "decode-events.h"
#include "util-unittest-helper.h"
#include "util-validate.h"

typedef struct AlpCtxThread_ {
    void *alproto_local_storage[ALPROTO_MAX];
} AlpCtxThread;

typedef struct AlpCtx_
{
    AppProto *alproto;
    char logger; /**< does this proto have a logger enabled? */

    void *(*StateAlloc)(void);
    void (*StateFree)(void *);
    void (*StateTransactionFree)(void *, uint64_t);
    void *(*LocalStorageAlloc)(void);
    void (*LocalStorageFree)(void *);

    /** truncate state after a gap/depth event */
    void (*Truncate)(void *, uint8_t);
    FileContainer *(*StateGetFiles)(void *, uint8_t);
    AppLayerDecoderEvents *(*StateGetEvents)(void *, uint64_t);
    /* bool indicating a state has decoder/parser events */
    int (*StateHasEvents)(void *);

    int (*StateGetAlstateProgress)(void *alstate, uint8_t direction);
    uint64_t (*StateGetTxCnt)(void *alstate);
    void *(*StateGetTx)(void *alstate, uint64_t tx_id);
    int (*StateGetAlstateProgressCompletionStatus)(uint8_t direction);
    int (*StateGetEventInfo)(const char *event_name,
                             int *event_id, AppLayerEventType *event_type);

    /* Indicates the direction the parser is ready to see the data
     * the first time for a flow.  Values accepted -
     * STREAM_TOSERVER, STREAM_TOCLIENT */
    uint8_t first_data_dir;

    int (*AppLayerParser)(Flow *f, void *protocol_state, AppLayerParserState
                          *parser_state, uint8_t *input, uint32_t input_len,
                          void *local_storage, AppLayerParserResult *output);

#ifdef UNITTESTS
    void (*RegisterUnittests)(void);
#endif
} AlpCtx;

AppLayerProto al_proto_table[ALPROTO_MAX];   /**< Application layer protocol
                                                table mapped to their
                                                corresponding parsers */

/** \brief Get the file container flow
 *  \param f flow pointer to a LOCKED flow
 *  \retval files void pointer to the state
 *  \retval direction flow direction, either STREAM_TOCLIENT or STREAM_TOSERVER
 *  \retval NULL in case we have no state */
FileContainer *AppLayerGetFilesFromFlow(Flow *f, uint8_t direction) {
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

    uint16_t alproto = f->alproto;

    if (alproto == ALPROTO_UNKNOWN)
        SCReturnPtr(NULL, "FileContainer");

    if (al_proto_table[alproto].StateGetFiles != NULL) {
        FileContainer *ptr = al_proto_table[alproto].StateGetFiles(AppLayerGetProtoStateFromFlow(f), direction);
        SCReturnPtr(ptr, "FileContainer");
    } else {
        SCReturnPtr(NULL, "FileContainer");
    }
}

/** \brief Get the decoder events from the flow
 *  \param f flow pointer to a LOCKED flow
 *  \param tx_id transaction id
 *  \retval files void pointer to the state
 *  \retval NULL in case we have no state */
AppLayerDecoderEvents *AppLayerGetEventsFromFlowByTx(Flow *f, uint64_t tx_id) {
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

    uint16_t alproto = f->alproto;
    if (alproto == ALPROTO_UNKNOWN)
        SCReturnPtr(NULL, "AppLayerDecoderEvents");

    if (al_proto_table[alproto].StateGetEvents != NULL) {
        AppLayerDecoderEvents *ptr = al_proto_table[alproto].StateGetEvents(AppLayerGetProtoStateFromFlow(f), tx_id);
        SCReturnPtr(ptr, "AppLayerDecoderEvents");
    } else {
        SCReturnPtr(NULL, "AppLayerDecoderEvents");
    }
}

/** \brief check if we have decoder events
 *  \retval 1 yes
 *  \retval 0 no */
int AppLayerFlowHasDecoderEvents(Flow *f, uint8_t flags) {
    AppLayerDecoderEvents *decoder_events;

    DEBUG_ASSERT_FLOW_LOCKED(f);

    if (f->alproto <= ALPROTO_UNKNOWN || f->alproto >= ALPROTO_MAX)
        return 0;

    if (AppLayerProtoIsTxEventAware(f->alproto)) {
        /* fast path if supported by proto */
        if (al_proto_table[f->alproto].StateHasEvents != NULL) {
            if (al_proto_table[f->alproto].StateHasEvents(f->alstate) == 1)
                return 1;
        } else {
            /* check each tx */
            uint64_t tx_id = AppLayerTransactionGetInspectId(f, flags);
            uint64_t max_id = AppLayerGetTxCnt(f->alproto, f->alstate);

            for ( ; tx_id < max_id; tx_id++) {
                decoder_events = AppLayerGetEventsFromFlowByTx(f, tx_id);
                if (decoder_events && decoder_events->cnt)
                    return 1;
            }
        }
    }

    decoder_events = AppLayerGetDecoderEventsForFlow(f);
    if (decoder_events && decoder_events->cnt)
        return 1;

    return 0;
}

/** \brief Return true if alproto uses per TX events
 *  \param alproto proto to check
 */
int AppLayerProtoIsTxEventAware(uint16_t alproto) {
    if (alproto > ALPROTO_UNKNOWN && alproto < ALPROTO_MAX &&
        al_proto_table[alproto].StateGetEvents != NULL)
        return 1;

    return 0;
}

/** \brief Alloc a AppLayerParserResultElmt func for the pool */
static void *AlpResultElmtPoolAlloc()
{
    AppLayerParserResultElmt *e = NULL;

    e = (AppLayerParserResultElmt *)SCMalloc
        (sizeof(AppLayerParserResultElmt));
    if (e == NULL)
        return NULL;

#ifdef DEBUG
    al_result_pool_elmts++;
    SCLogDebug("al_result_pool_elmts %"PRIu32"", al_result_pool_elmts);
#endif /* DEBUG */
    return e;
}

int AppLayerGetAlstateProgress(uint16_t alproto, void *state, uint8_t direction)
{
    return al_proto_table[alproto].StateGetAlstateProgress(state, direction);
}

uint64_t AppLayerGetTxCnt(uint16_t alproto, void *alstate)
{
    return al_proto_table[alproto].StateGetTxCnt(alstate);
}

void *AppLayerGetTx(uint16_t alproto, void *alstate, uint64_t tx_id)
{
    return al_proto_table[alproto].StateGetTx(alstate, tx_id);
}

int AppLayerGetAlstateProgressCompletionStatus(uint16_t alproto, uint8_t direction)
{
    return al_proto_table[alproto].StateGetAlstateProgressCompletionStatus(direction);
}

int AppLayerAlprotoSupportsTxs(uint16_t alproto)
{
    return (al_proto_table[alproto].StateTransactionFree != NULL);
}

static void AlpResultElmtPoolCleanup(void *e)
{
    AppLayerParserResultElmt *re = (AppLayerParserResultElmt *)e;

    if (re->flags & ALP_RESULT_ELMT_ALLOC) {
        if (re->data_ptr != NULL)
            SCFree(re->data_ptr);
    }

#ifdef DEBUG
    al_result_pool_elmts--;
    SCLogDebug("al_result_pool_elmts %"PRIu32"", al_result_pool_elmts);
#endif /* DEBUG */
}

static AppLayerParserResultElmt *AlpGetResultElmt(void)
{
    SCMutexLock(&al_result_pool_mutex);
    AppLayerParserResultElmt *e = (AppLayerParserResultElmt *)PoolGet(al_result_pool);
    SCMutexUnlock(&al_result_pool_mutex);

    if (e == NULL) {
        return NULL;
    }
    e->next = NULL;
    return e;
}

static void AlpReturnResultElmt(AppLayerParserResultElmt *e)
{
    if (e->flags & ALP_RESULT_ELMT_ALLOC) {
        if (e->data_ptr != NULL)
            SCFree(e->data_ptr);
    }
    e->flags = 0;
    e->data_ptr = NULL;
    e->data_len = 0;
    e->next = NULL;

    SCMutexLock(&al_result_pool_mutex);
    PoolReturn(al_result_pool, (void *)e);
    SCMutexUnlock(&al_result_pool_mutex);
}

static void AlpAppendResultElmt(AppLayerParserResult *r, AppLayerParserResultElmt *e)
{
    if (r->head == NULL) {
        r->head = e;
        r->tail = e;
        r->cnt = 1;
    } else {
        r->tail->next = e;
        r->tail = e;
        r->cnt++;
    }
}

/**
 *  \param alloc Is ptr alloc'd (1) or a ptr to static mem (0).
 *  \retval -1 error
 *  \retval 0 ok
 */
static int AlpStoreField(AppLayerParserResult *output, uint16_t idx,
                         uint8_t *ptr, uint32_t len, uint8_t alloc)
{
    SCEnter();

    AppLayerParserResultElmt *e = AlpGetResultElmt();
    if (e == NULL) {
        SCLogError(SC_ERR_POOL_EMPTY, "App layer \"al_result_pool\" is empty");
        SCReturnInt(-1);
    }

    if (alloc == 1)
        e->flags |= ALP_RESULT_ELMT_ALLOC;

    e->name_idx = idx;
    e->data_ptr = ptr;
    e->data_len = len;
    AlpAppendResultElmt(output, e);

    SCReturnInt(0);
}

void AppLayerSetEOF(Flow *f)
{
    if (f == NULL)
        return;

    AppLayerParserStateStore *parser_state_store =
        (AppLayerParserStateStore *)f->alparser;
    if (parser_state_store != NULL) {
        parser_state_store->id_flags |= APP_LAYER_TRANSACTION_EOF;
        parser_state_store->to_client.flags |= APP_LAYER_PARSER_EOF;
        parser_state_store->to_server.flags |= APP_LAYER_PARSER_EOF;
        /* increase version so we will inspect it one more time
         * with the EOF flags now set */
        parser_state_store->version++;
    }
}

/** \brief Parse a field up to we reach the size limit
 *
 * \retval  1 Field found and stored.
 * \retval  0 Field parsing in progress.
 * \retval -1 error
 */
int AlpParseFieldBySize(AppLayerParserResult *output, AppLayerParserState *pstate,
                        uint16_t field_idx, uint32_t size, uint8_t *input,
                        uint32_t input_len, uint32_t *offset)
{
    SCEnter();

    if ((pstate->store_len + input_len) < size) {
        if (pstate->store_len == 0) {
            pstate->store = SCMalloc(input_len);
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store, input, input_len);
            pstate->store_len = input_len;
        } else {
            pstate->store = SCRealloc(pstate->store, (input_len + pstate->store_len));
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store+pstate->store_len, input, input_len);
            pstate->store_len += input_len;
        }
    } else {
        if (pstate->store_len == 0) {
            int r = AlpStoreField(output, field_idx, input, size, /* static mem */0);
            if (r == -1) {
                SCLogError(SC_ERR_ALPARSER, "Failed to store field value");
                SCReturnInt(-1);
            }
            (*offset) += size;

            SCReturnInt(1);
        } else {
            uint32_t diff = size - pstate->store_len;

            pstate->store = SCRealloc(pstate->store, (diff + pstate->store_len));
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store+pstate->store_len, input, diff);
            pstate->store_len += diff;

            int r = AlpStoreField(output, field_idx, pstate->store,
                                  pstate->store_len, /* alloc mem */1);
            if (r == -1) {
                SCLogError(SC_ERR_ALPARSER, "Failed to store field value");
                SCReturnInt(-1);
            }

            (*offset) += diff;

            pstate->store = NULL;
            pstate->store_len = 0;

            SCReturnInt(1);
        }
    }

    SCReturnInt(0);
}

/** \brief Parse a field up to the EOF
 *
 * \retval  1 Field found and stored.
 * \retval  0 Field parsing in progress.
 * \retval -1 error
 */
int AlpParseFieldByEOF(AppLayerParserResult *output, AppLayerParserState *pstate,
                       uint16_t field_idx, uint8_t *input, uint32_t input_len)
{
    SCEnter();

    if (pstate->store_len == 0) {
        if (pstate->flags & APP_LAYER_PARSER_EOF) {
            SCLogDebug("store_len 0 and EOF");

            int r = AlpStoreField(output, field_idx, input, input_len, 0);
            if (r == -1) {
                SCLogError(SC_ERR_ALPARSER, "Failed to store field value");
                SCReturnInt(-1);
            }

            SCReturnInt(1);
        } else {
            SCLogDebug("store_len 0 but no EOF");

            /* delimiter field not found, so store the result for the next run */
            pstate->store = SCMalloc(input_len);
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store, input, input_len);
            pstate->store_len = input_len;
        }
    } else {
        if (pstate->flags & APP_LAYER_PARSER_EOF) {
            SCLogDebug("store_len %" PRIu32 " and EOF", pstate->store_len);

            pstate->store = SCRealloc(pstate->store, (input_len + pstate->store_len));
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store+pstate->store_len, input, input_len);
            pstate->store_len += input_len;

            int r = AlpStoreField(output, field_idx, pstate->store, pstate->store_len, 1);
            if (r == -1) {
                SCLogError(SC_ERR_ALPARSER, "Failed to store field value");
                SCReturnInt(-1);
            }

            pstate->store = NULL;
            pstate->store_len = 0;

            SCReturnInt(1);
        } else {
            SCLogDebug("store_len %" PRIu32 " but no EOF", pstate->store_len);

            /* delimiter field not found, so store the result for the next run */
            pstate->store = SCRealloc(pstate->store, (input_len + pstate->store_len));
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store+pstate->store_len, input, input_len);
            pstate->store_len += input_len;
        }

    }

    SCReturnInt(0);
}

/** \brief Parse a field up to a delimeter.
 *
 * \retval  1 Field found and stored.
 * \retval  0 Field parsing in progress.
 * \retval -1 error
 */
int AlpParseFieldByDelimiter(AppLayerParserResult *output, AppLayerParserState *pstate,
                            uint16_t field_idx, const uint8_t *delim, uint8_t delim_len,
                            uint8_t *input, uint32_t input_len, uint32_t *offset)
{
    SCEnter();
    SCLogDebug("pstate->store_len %" PRIu32 ", delim_len %" PRIu32 "",
                pstate->store_len, delim_len);

    if (pstate->store_len == 0) {
        uint8_t *ptr = SpmSearch(input, input_len, (uint8_t*)delim, delim_len);
        if (ptr != NULL) {
            uint32_t len = ptr - input;
            SCLogDebug(" len %" PRIu32 "", len);

            int r = AlpStoreField(output, field_idx, input, len, 0);
            if (r == -1) {
                SCLogError(SC_ERR_ALPARSER, "Failed to store field value");
                SCReturnInt(-1);
            }
            (*offset) += (len + delim_len);
            SCReturnInt(1);
        } else {
            if (pstate->flags & APP_LAYER_PARSER_EOF) {
                SCLogDebug("delim not found and EOF");
                SCReturnInt(0);
            }

            SCLogDebug("delim not found, continue");

            /* delimiter field not found, so store the result for the next run */
            pstate->store = SCMalloc(input_len);
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store, input, input_len);
            pstate->store_len = input_len;
        }
    } else {
        uint8_t *ptr = SpmSearch(input, input_len, (uint8_t*)delim, delim_len);
        if (ptr != NULL) {
            uint32_t len = ptr - input;
            SCLogDebug("len %" PRIu32 " + %" PRIu32 " = %" PRIu32 "", len,
                        pstate->store_len, len + pstate->store_len);

            pstate->store = SCRealloc(pstate->store, (len + pstate->store_len));
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store+pstate->store_len, input, len);
            pstate->store_len += len;

            int r = AlpStoreField(output, field_idx, pstate->store,
                                  pstate->store_len, 1);
            if (r == -1) {
                SCLogError(SC_ERR_ALPARSER, "Failed to store field value");
                SCReturnInt(-1);
            }
            pstate->store = NULL;
            pstate->store_len = 0;

            (*offset) += (len + delim_len);
            SCReturnInt(1);
        } else {
            if (pstate->flags & APP_LAYER_PARSER_EOF) {
                /* if the input len is smaller than the delim len we search the
                 * pstate->store since we may match there. */
                if (delim_len > input_len) {
                    /* delimiter field not found, so store the result for the
                     * next run */
                    pstate->store = SCRealloc(pstate->store, (input_len +
                                            pstate->store_len));
                    if (pstate->store == NULL)
                        SCReturnInt(-1);

                    memcpy(pstate->store+pstate->store_len, input, input_len);
                    pstate->store_len += input_len;
                    SCLogDebug("input_len < delim_len, checking pstate->store");

                    if (pstate->store_len >= delim_len) {
                        ptr = SpmSearch(pstate->store, pstate->store_len, (uint8_t*)delim,
                                        delim_len);
                        if (ptr != NULL) {
                            SCLogDebug("now we found the delim");

                            uint32_t len = ptr - pstate->store;
                            int r = AlpStoreField(output, field_idx,
                                                  pstate->store, len, 1);
                            if (r == -1) {
                                SCLogError(SC_ERR_ALPARSER, "Failed to store "
                                           "field value");
                                SCReturnInt(-1);
                            }

                            pstate->store = NULL;
                            pstate->store_len = 0;

                            (*offset) += (input_len);

                            SCLogDebug("offset %" PRIu32 "", (*offset));
                            SCReturnInt(1);
                        }
                        goto free_and_return;
                    }
                    goto free_and_return;
                }
            free_and_return:
                SCLogDebug("not found and EOF, so free what we have so far.");
                SCFree(pstate->store);
                pstate->store = NULL;
                pstate->store_len = 0;
                SCReturnInt(0);
            }

            /* delimiter field not found, so store the result for the next run */
            pstate->store = SCRealloc(pstate->store, (input_len + pstate->store_len));
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store+pstate->store_len, input, input_len);
            pstate->store_len += input_len;

            /* if the input len is smaller than the delim len we search the
             * pstate->store since we may match there. */
            if (delim_len > input_len && delim_len <= pstate->store_len) {
                SCLogDebug("input_len < delim_len, checking pstate->store");

                ptr = SpmSearch(pstate->store, pstate->store_len, (uint8_t*)delim, delim_len);
                if (ptr != NULL) {
                    SCLogDebug("now we found the delim");

                    uint32_t len = ptr - pstate->store;
                    int r = AlpStoreField(output, field_idx, pstate->store, len, 1);
                    if (r == -1) {
                        SCLogError(SC_ERR_ALPARSER, "Failed to store field value");
                        SCReturnInt(-1);
                    }
                    pstate->store = NULL;
                    pstate->store_len = 0;

                    (*offset) += (input_len);

                    SCLogDebug("ffset %" PRIu32 "", (*offset));
                    SCReturnInt(1);
                }
            }
        }

    }

    SCReturnInt(0);
}

uint16_t AppLayerGetProtoByName(const char *name)
{
    uint8_t u = 1;
    SCLogDebug("looking for name %s", name);

    for ( ; u < ALPROTO_MAX; u++) {
        if (al_proto_table[u].name == NULL)
            continue;

        SCLogDebug("name %s proto %"PRIu16"",
            al_proto_table[u].name, u);

        if (strcasecmp(name,al_proto_table[u].name) == 0) {
            SCLogDebug("match, returning %"PRIu16"", u);
            return u;
        }
    }

    AppLayerProbingParser *pp = alp_proto_ctx.probing_parsers;
    while (pp != NULL) {
        AppLayerProbingParserPort *pp_port = pp->port;
        while (pp_port != NULL) {
            AppLayerProbingParserElement *pp_pe = pp_port->toserver;
            while (pp_pe != NULL) {
                if (strcasecmp(pp_pe->al_proto_name, name) == 0) {
                    return pp_pe->al_proto;
                }

                pp_pe = pp_pe->next;
            }

            pp_pe = pp_port->toclient;
            while (pp_pe != NULL) {
                if (strcasecmp(pp_pe->al_proto_name, name) == 0) {
                    return pp_pe->al_proto;
                }

                pp_pe = pp_pe->next;
            }

            pp_port = pp_port->next;
        }
        pp = pp->next;
    }

    return ALPROTO_UNKNOWN;
}

const char *AppLayerGetProtoString(int proto)
{

    if ((proto >= ALPROTO_MAX) || (proto < 0)) {
        return "Undefined";
    }

    if (al_proto_table[proto].name == NULL)  {
        return "Unset";
    } else {
        return al_proto_table[proto].name;
    }
}

/** \brief Description: register a parser.
 *
 * \param name full parser name, e.g. "http.request_line"
 * \todo do we need recursive, so a "http" and a "request_line" where the engine
 *       knows it's actually "http.request_line"... same difference maybe.
 * \param AppLayerParser pointer to the parser function
 *
 * \retval 0 on success
 * \retval -1 on error
 */
int AppLayerRegisterParser(char *name, uint16_t proto, uint16_t parser_id,
                           int (*AppLayerParser)(Flow *f, void *protocol_state,
                                                 AppLayerParserState *parser_state,
                                                 uint8_t *input, uint32_t input_len,
                                                 void *local_data,
                                                 AppLayerParserResult *output),
                           char *dependency)
{

    al_max_parsers++;

    if(al_max_parsers >= MAX_PARSERS){
        SCLogInfo("Failed to register %s al_parser_table array full",name);
        exit(EXIT_FAILURE);
    }

    al_parser_table[al_max_parsers].name = name;
    al_parser_table[al_max_parsers].proto = proto;
    al_parser_table[al_max_parsers].parser_local_id = parser_id;
    al_parser_table[al_max_parsers].AppLayerParser = AppLayerParser;

    SCLogDebug("registered %p at proto %" PRIu32 ", al_proto_table idx "
               "%" PRIu32 ", parser_local_id %" PRIu32 "",
                AppLayerParser, proto, al_max_parsers,
                parser_id);
    return 0;
}

/** \brief Description: register a protocol parser.
 *
 * \param name full parser name, e.g. "http.request_line"
 * \todo do we need recursive, so a "http" and a "request_line" where the engine
 *       knows it's actually "http.request_line"... same difference maybe.
 * \param AppLayerParser pointer to the parser function
 *
 * \retval 0 on success
 * \retval -1 on error
 */
int AppLayerRegisterProto(char *name, uint8_t proto, uint8_t flags,
                          int (*AppLayerParser)(Flow *f, void *protocol_state,
                                                AppLayerParserState *parser_state,
                                                uint8_t *input, uint32_t input_len,
                                                void *local_data, AppLayerParserResult *output))
{

    al_max_parsers++;

    if(al_max_parsers >= MAX_PARSERS){
        SCLogInfo("Failed to register %s al_parser_table array full",name);
        exit(EXIT_FAILURE);
    }

    /* register name here as well so pp only protocols will work */
    if (al_proto_table[proto].name != NULL) {
        BUG_ON(strcmp(al_proto_table[proto].name, name) != 0);
    } else {
        al_proto_table[proto].name = name;
    }

    al_parser_table[al_max_parsers].name = name;
    al_parser_table[al_max_parsers].AppLayerParser = AppLayerParser;

    /* create proto, direction -- parser mapping */
    if (flags & STREAM_TOSERVER) {
        al_proto_table[proto].to_server = al_max_parsers;
    } else if (flags & STREAM_TOCLIENT) {
        al_proto_table[proto].to_client = al_max_parsers;
    }

    SCLogDebug("registered %p at proto %" PRIu32 " flags %02X, al_proto_table "
                "idx %" PRIu32 ", %s", AppLayerParser, proto,
                flags, al_max_parsers, name);
    return 0;
}

#ifdef UNITTESTS
void AppLayerParserRegisterUnittests(uint16_t proto, void (*RegisterUnittests)(void)) {
    al_proto_table[proto].RegisterUnittests = RegisterUnittests;
}
#endif

void AppLayerRegisterStateFuncs(uint16_t proto, void *(*StateAlloc)(void),
                                void (*StateFree)(void *))
{
    al_proto_table[proto].StateAlloc = StateAlloc;
    al_proto_table[proto].StateFree = StateFree;
}

void AppLayerRegisterTxFreeFunc(uint16_t proto,
        void (*StateTransactionFree)(void *, uint64_t))
{
    al_proto_table[proto].StateTransactionFree = StateTransactionFree;
}

void AppLayerRegisterLocalStorageFunc(uint16_t proto,
                                      void *(*LocalStorageAlloc)(void),
                                      void (*LocalStorageFree)(void *))
{
    al_proto_table[proto].LocalStorageAlloc = LocalStorageAlloc;
    al_proto_table[proto].LocalStorageFree = LocalStorageFree;

    return;
}

void AppLayerRegisterTruncateFunc(uint16_t proto, void (*Truncate)(void *, uint8_t))
{
    al_proto_table[proto].Truncate = Truncate;

    return;
}

void AppLayerStreamTruncated(uint16_t proto, void *state, uint8_t flags) {
    if (al_proto_table[proto].Truncate != NULL) {
        al_proto_table[proto].Truncate(state, flags);
    }
}

void *AppLayerGetProtocolParserLocalStorage(uint16_t proto)
{
    if (al_proto_table[proto].LocalStorageAlloc != NULL) {
        return al_proto_table[proto].LocalStorageAlloc();
    }

    return NULL;
}

void AppLayerRegisterGetFilesFunc(uint16_t proto,
        FileContainer *(*StateGetFiles)(void *, uint8_t))
{
    al_proto_table[proto].StateGetFiles = StateGetFiles;
}

void AppLayerRegisterGetAlstateProgressFunc(uint16_t alproto,
                                            int (*StateGetAlstateProgress)(void *alstate, uint8_t direction))
{
    al_proto_table[alproto].StateGetAlstateProgress = StateGetAlstateProgress;
}

void AppLayerRegisterGetTxCnt(uint16_t alproto,
                              uint64_t (*StateGetTxCnt)(void *alstate))
{
    al_proto_table[alproto].StateGetTxCnt = StateGetTxCnt;
}

void AppLayerRegisterGetTx(uint16_t alproto,
                           void *(StateGetTx)(void *alstate, uint64_t tx_id))
{
    al_proto_table[alproto].StateGetTx = StateGetTx;
}

void AppLayerRegisterGetAlstateProgressCompletionStatus(uint16_t alproto,
    int (*StateGetAlstateProgressCompletionStatus)(uint8_t direction))
{
    al_proto_table[alproto].StateGetAlstateProgressCompletionStatus =
        StateGetAlstateProgressCompletionStatus;
}

void AppLayerRegisterGetEventsFunc(uint16_t proto,
        AppLayerDecoderEvents *(*StateGetEvents)(void *, uint64_t))
{
    al_proto_table[proto].StateGetEvents = StateGetEvents;
}

void AppLayerRegisterHasEventsFunc(uint16_t proto,
        int (*StateHasEvents)(void *)) {
    al_proto_table[proto].StateHasEvents = StateHasEvents;
}

/** \brief Indicate to the app layer parser that a logger is active
 *         for this protocol.
 */
void AppLayerRegisterLogger(uint16_t proto) {
    al_proto_table[proto].logger = TRUE;
}

void AppLayerRegisterGetEventInfo(uint16_t alproto,
                                  int (*StateGetEventInfo)(const char *event_name,
                                                           int *event_id,
                                                           AppLayerEventType *event_type))
{
    al_proto_table[alproto].StateGetEventInfo = StateGetEventInfo;
}

AppLayerParserStateStore *AppLayerParserStateStoreAlloc(void)
{
    AppLayerParserStateStore *s = (AppLayerParserStateStore *)SCMalloc
                                    (sizeof(AppLayerParserStateStore));
    if (s == NULL)
        return NULL;

    memset(s, 0, sizeof(AppLayerParserStateStore));

    return s;
}

/** \brief free a AppLayerParserStateStore structure
 *  \param s AppLayerParserStateStore structure to free */
void AppLayerParserStateStoreFree(AppLayerParserStateStore *s)
{
    if (s->to_server.store != NULL)
        SCFree(s->to_server.store);
    if (s->to_client.store != NULL)
        SCFree(s->to_client.store);
    if (s->decoder_events != NULL)
        AppLayerDecoderEventsFreeEvents(s->decoder_events);
    s->decoder_events = NULL;

    SCFree(s);
}

static void AppLayerParserResultCleanup(AppLayerParserResult *result)
{
    AppLayerParserResultElmt *e = result->head;
    while (e != NULL) {
        AppLayerParserResultElmt *next_e = e->next;

        result->head = next_e;
        if (next_e == NULL)
            result->tail = NULL;
        result->cnt--;

        AlpReturnResultElmt(e);
        e = next_e;
    }
}

static int AppLayerDoParse(void *local_data, Flow *f,
                           void *app_layer_state,
                           AppLayerParserState *parser_state,
                           uint8_t *input, uint32_t input_len,
                           uint16_t parser_idx,
                           uint16_t proto)
{
    SCEnter();
    DEBUG_ASSERT_FLOW_LOCKED(f);

    int retval = 0;
    AppLayerParserResult result = { NULL, NULL, 0 };

    SCLogDebug("parser_idx %" PRIu32 "", parser_idx);
    //printf("--- (%u)\n", input_len);
    //PrintRawDataFp(stdout, input,input_len);
    //printf("---\n");

    /* invoke the parser */
    int r = al_parser_table[parser_idx].
        AppLayerParser(f, app_layer_state,
                       parser_state, input, input_len,
                       local_data, &result);
    if (r < 0) {
        if (r == -1) {
            AppLayerParserResultCleanup(&result);
            SCReturnInt(-1);
#ifdef DEBUG
        } else {
            BUG_ON(r);  /* this is not supposed to happen!! */
#else
            SCReturnInt(-1);
#endif
        }
    }

    /* process the result elements */
    AppLayerParserResultElmt *e = result.head;
    for (; e != NULL; e = e->next) {
        SCLogDebug("e %p e->name_idx %" PRIu32 ", e->data_ptr %p, e->data_len "
                   "%" PRIu32 ", map_size %" PRIu32 "", e, e->name_idx,
                   e->data_ptr, e->data_len, al_proto_table[proto].map_size);

        /* no parser defined for this field. */
        if (e->name_idx >= al_proto_table[proto].map_size ||
                al_proto_table[proto].map[e->name_idx] == NULL)
        {
            SCLogDebug("no parser for proto %" PRIu32 ", parser_local_id "
                        "%" PRIu32 "", proto, e->name_idx);
            continue;
        }

        uint16_t idx = al_proto_table[proto].map[e->name_idx]->parser_id;

        /* prepare */
        uint16_t tmp = parser_state->parse_field;
        parser_state->parse_field = 0;
        parser_state->flags |= APP_LAYER_PARSER_EOF;

        r = AppLayerDoParse(local_data, f, app_layer_state, parser_state, e->data_ptr,
                            e->data_len, idx, proto);

        /* restore */
        parser_state->flags &= ~APP_LAYER_PARSER_EOF;
        parser_state->parse_field = tmp;

        /* bail out on a serious error */
        if (r < 0) {
            if (r == -1) {
                retval = -1;
                break;
#ifdef DEBUG
            } else {
                BUG_ON(r);  /* this is not supposed to happen!! */
#else
                SCReturnInt(-1);
#endif
            }
        }
    }

    AppLayerParserResultCleanup(&result);
    SCReturnInt(retval);
}

/**
 * \brief remove obsolete (inspected and logged) transactions
 */
static void AppLayerTransactionsCleanup(AppLayerProto *p, AppLayerParserStateStore *parser_state_store, void *app_layer_state)
{
    if (p->StateTransactionFree == NULL)
        return;

    uint64_t inspect = 0, log = 0;
    if (parser_state_store->inspect_id[0] < parser_state_store->inspect_id[1])
        inspect = parser_state_store->inspect_id[0];
    else
        inspect = parser_state_store->inspect_id[1];
    log = parser_state_store->log_id;

    if (p->logger == TRUE) {
        uint64_t min = log < inspect ? log : inspect;
        if (min > 0) {
            SCLogDebug("freeing %"PRIu64" (with logger) %p", min - 1, p->StateTransactionFree);
            p->StateTransactionFree(app_layer_state, min - 1);
        }
    } else {
        if (inspect > 0) {
            SCLogDebug("freeing %"PRIu64" (no logger) %p", inspect - 1, p->StateTransactionFree);
            p->StateTransactionFree(app_layer_state, inspect - 1);
        }
    }
}

#ifdef DEBUG
uint32_t applayererrors = 0;
uint32_t applayerhttperrors = 0;
#endif

/**
 * \brief Layer 7 Parsing main entry point.
 *
 * \param f Properly initialized and locked flow.
 * \param proto L7 proto, e.g. ALPROTO_HTTP
 * \param flags Stream flags
 * \param input Input L7 data
 * \param input_len Length of the input data.
 *
 * \retval -1 error
 * \retval 0 ok
 */
int AppLayerParse(void *local_data, Flow *f, uint8_t proto,
                  uint8_t flags, uint8_t *input, uint32_t input_len)
{
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

    uint16_t parser_idx = 0;
    AppLayerProto *p = &al_proto_table[proto];
    TcpSession *ssn = NULL;

    /* Used only if it's TCP */
    ssn = f->protoctx;

    /* Do this check before calling AppLayerParse */
    if (flags & STREAM_GAP) {
        SCLogDebug("stream gap detected (missing packets), this is not yet supported.");

        if (f->alstate != NULL)
            AppLayerStreamTruncated(proto, f->alstate, flags);
        goto error;
    }

    /* Get the parser state (if any) */
    AppLayerParserStateStore *parser_state_store = f->alparser;
    if (parser_state_store == NULL) {
        parser_state_store = AppLayerParserStateStoreAlloc();
        if (parser_state_store == NULL)
            goto error;

        f->alparser = (void *)parser_state_store;
    }

    parser_state_store->version++;
    SCLogDebug("app layer state version incremented to %"PRIu16,
            parser_state_store->version);

    AppLayerParserState *parser_state = NULL;
    if (flags & STREAM_TOSERVER) {
        SCLogDebug("to_server msg (flow %p)", f);

        parser_state = &parser_state_store->to_server;
        if (!(parser_state->flags & APP_LAYER_PARSER_USE)) {
            parser_idx = p->to_server;
            parser_state->cur_parser = parser_idx;
            parser_state->flags |= APP_LAYER_PARSER_USE;
        } else {
            SCLogDebug("using parser %" PRIu32 " we stored before (to_server)",
                        parser_state->cur_parser);
            parser_idx = parser_state->cur_parser;
        }
    } else {
        SCLogDebug("to_client msg (flow %p)", f);

        parser_state = &parser_state_store->to_client;
        if (!(parser_state->flags & APP_LAYER_PARSER_USE)) {
            parser_idx = p->to_client;
            parser_state->cur_parser = parser_idx;
            parser_state->flags |= APP_LAYER_PARSER_USE;
        } else {
            SCLogDebug("using parser %" PRIu32 " we stored before (to_client)",
                        parser_state->cur_parser);
            parser_idx = parser_state->cur_parser;
        }
    }

    if (parser_idx == 0 || (parser_state->flags & APP_LAYER_PARSER_DONE)) {
        SCLogDebug("no parser for protocol %" PRIu32 "", proto);
        SCReturnInt(0);
    }

    if (flags & STREAM_EOF)
        parser_state->flags |= APP_LAYER_PARSER_EOF;

    /* See if we already have a 'app layer' state */
    void *app_layer_state = f->alstate;
    if (app_layer_state == NULL) {
        /* lock the allocation of state as we may
         * alloc more than one otherwise */
        app_layer_state = p->StateAlloc();
        if (app_layer_state == NULL) {
            goto error;
        }

        f->alstate = app_layer_state;
        SCLogDebug("alloced new app layer state %p (name %s)",
                app_layer_state, al_proto_table[f->alproto].name);
    } else {
        SCLogDebug("using existing app layer state %p (name %s))",
                app_layer_state, al_proto_table[f->alproto].name);
    }

    /* invoke the recursive parser, but only on data. We may get empty msgs on EOF */
    if (input_len > 0) {
        int r = AppLayerDoParse(local_data, f, app_layer_state, parser_state,
                                input, input_len, parser_idx, proto);
        if (r < 0)
            goto error;
    }

    /* set the packets to no inspection and reassembly if required */
    if (parser_state->flags & APP_LAYER_PARSER_NO_INSPECTION) {
        AppLayerSetEOF(f);
        FlowSetNoPayloadInspectionFlag(f);
        FlowSetSessionNoApplayerInspectionFlag(f);

        /* Set the no reassembly flag for both the stream in this TcpSession */
        if (parser_state->flags & APP_LAYER_PARSER_NO_REASSEMBLY) {
            if (ssn != NULL) {
                StreamTcpSetSessionNoReassemblyFlag(ssn,
                        flags & STREAM_TOCLIENT ? 1 : 0);
                StreamTcpSetSessionNoReassemblyFlag(ssn,
                        flags & STREAM_TOSERVER ? 1 : 0);
            }
        }
    }

    /* next, see if we can get rid of transactions now */
    AppLayerTransactionsCleanup(p, parser_state_store, app_layer_state);

    if (parser_state->flags & APP_LAYER_PARSER_EOF) {
        SCLogDebug("eof, flag Transaction id's");
        parser_state_store->id_flags |= APP_LAYER_TRANSACTION_EOF;
    }

    /* stream truncated, inform app layer */
    if (flags & STREAM_DEPTH) {
        AppLayerStreamTruncated(proto, app_layer_state, flags);
    }

    SCReturnInt(0);

error:
    if (ssn != NULL) {
#ifdef DEBUG
        if (FLOW_IS_IPV4(f)) {
            char src[16];
            char dst[16];
            PrintInet(AF_INET, (const void*)&f->src.addr_data32[0], src,
                      sizeof (src));
            PrintInet(AF_INET, (const void*)&f->dst.addr_data32[0], dst,
                      sizeof (dst));

            SCLogDebug("Error occured in parsing \"%s\" app layer "
                       "protocol, using network protocol %"PRIu8", source IP "
                       "address %s, destination IP address %s, src port %"PRIu16" and "
                       "dst port %"PRIu16"", al_proto_table[f->alproto].name,
                       f->proto, src, dst, f->sp, f->dp);
            fflush(stdout);
        } else if (FLOW_IS_IPV6(f)) {
            char dst6[46];
            char src6[46];

            PrintInet(AF_INET6, (const void*)&f->src.addr_data32, src6,
                      sizeof (src6));
            PrintInet(AF_INET6, (const void*)&f->dst.addr_data32, dst6,
                      sizeof (dst6));

            SCLogDebug("Error occured in parsing \"%s\" app layer "
                       "protocol, using network protocol %"PRIu8", source IPv6 "
                       "address %s, destination IPv6 address %s, src port %"PRIu16" and "
                       "dst port %"PRIu16"", al_proto_table[f->alproto].name,
                       f->proto, src6, dst6, f->sp, f->dp);
            fflush(stdout);
        }
        applayererrors++;
        if (f->alproto == ALPROTO_HTTP)
            applayerhttperrors++;
#endif
        /* Set the no app layer inspection flag for both
         * the stream in this Flow */
        FlowSetSessionNoApplayerInspectionFlag(f);
        AppLayerSetEOF(f);
    }

    SCReturnInt(-1);
}

void AppLayerTransactionUpdateLogId(Flow *f)
{
    DEBUG_ASSERT_FLOW_LOCKED(f);
    ((AppLayerParserStateStore *)f->alparser)->log_id++;

    return;
}

uint64_t AppLayerTransactionGetLogId(Flow *f)
{
    DEBUG_ASSERT_FLOW_LOCKED(f);

    return ((AppLayerParserStateStore *)f->alparser)->log_id;
}

uint16_t AppLayerGetStateVersion(Flow *f)
{
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

    uint16_t version = 0;
    AppLayerParserStateStore *parser_state_store = NULL;

    parser_state_store = (AppLayerParserStateStore *)f->alparser;
    if (parser_state_store != NULL) {
        version = parser_state_store->version;
    }

    SCReturnUInt(version);
}

uint64_t AppLayerTransactionGetInspectId(Flow *f, uint8_t flags)
{
    DEBUG_ASSERT_FLOW_LOCKED(f);

    return ((AppLayerParserStateStore *)f->alparser)->
        inspect_id[flags & STREAM_TOSERVER ? 0 : 1];
}

void AppLayerTransactionUpdateInspectId(Flow *f, uint8_t flags)
{
    uint8_t direction = (flags & STREAM_TOSERVER) ? 0 : 1;

    FLOWLOCK_WRLOCK(f);
    uint64_t total_txs = AppLayerGetTxCnt(f->alproto, f->alstate);
    uint64_t idx = AppLayerTransactionGetInspectId(f, flags);
    int state_done_progress = AppLayerGetAlstateProgressCompletionStatus(f->alproto, direction);
    void *tx;
    int state_progress;

    for (; idx < total_txs; idx++) {
        tx = AppLayerGetTx(f->alproto, f->alstate, idx);
        if (tx == NULL)
            continue;
        state_progress = AppLayerGetAlstateProgress(f->alproto, tx, direction);
        if (state_progress >= state_done_progress)
            continue;
        else
            break;
    }
    ((AppLayerParserStateStore *)f->alparser)->inspect_id[direction] = idx;
    FLOWLOCK_UNLOCK(f);

    return;
}

void AppLayerListSupportedProtocols(void)
{
    uint32_t i;
    uint32_t temp_alprotos_buf[ALPROTO_MAX];
    memset(temp_alprotos_buf, 0, sizeof(temp_alprotos_buf));

    printf("=========Supported App Layer Protocols=========\n");

    /* for each proto, alloc the map array */
    for (i = 0; i < ALPROTO_MAX; i++) {
        if (al_proto_table[i].name == NULL)
            continue;

        temp_alprotos_buf[i] = 1;
        printf("%s\n", al_proto_table[i].name);
    }

    AppLayerProbingParser *pp = alp_proto_ctx.probing_parsers;
    while (pp != NULL) {
        AppLayerProbingParserPort *pp_port = pp->port;
        while (pp_port != NULL) {
            AppLayerProbingParserElement *pp_pe = pp_port->toserver;
            while (pp_pe != NULL) {
                if (temp_alprotos_buf[pp_pe->al_proto] == 1) {
                    pp_pe = pp_pe->next;
                    continue;
                }

                printf("%s\n", pp_pe->al_proto_name);
                pp_pe = pp_pe->next;
            }

            pp_pe = pp_port->toclient;
            while (pp_pe != NULL) {
                if (temp_alprotos_buf[pp_pe->al_proto] == 1) {
                    pp_pe = pp_pe->next;;
                    continue;
                }

                printf("%s\n", pp_pe->al_proto_name);
                pp_pe = pp_pe->next;
            }

            pp_port = pp_port->next;
        }
        pp = pp->next;
    }

    return;
}

AppLayerDecoderEvents *AppLayerGetDecoderEventsForFlow(Flow *f)
{
    DEBUG_ASSERT_FLOW_LOCKED(f);

    /* Get the parser state (if any) */
    AppLayerParserStateStore *parser_state_store = NULL;

    if (f == NULL || f->alparser == NULL) {
        return NULL;
    }

    parser_state_store = (AppLayerParserStateStore *)f->alparser;
    if (parser_state_store != NULL) {
        return parser_state_store->decoder_events;
    }

    return NULL;
}

/**
 *  \brief Trigger "raw" stream reassembly from the app layer.
 *
 *  This way HTTP for example, can trigger raw stream inspection right
 *  when the full request body is received. This is often smaller than
 *  our raw reassembly size limit.
 *
 *  \param f flow, for access the stream state
 */
void AppLayerTriggerRawStreamReassembly(Flow *f) {
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

#ifdef DEBUG
    BUG_ON(f == NULL);
#endif

    if (f != NULL && f->protoctx != NULL) {
        TcpSession *ssn = (TcpSession *)f->protoctx;
        StreamTcpReassembleTriggerRawReassembly(ssn);
    }

    SCReturn;
}

void RegisterAppLayerParsers(void)
{
    /** \todo move to general init function */
    memset(&al_proto_table, 0, sizeof(al_proto_table));
    memset(&al_parser_table, 0, sizeof(al_parser_table));

    RegisterHTPParsers();
    RegisterSSLParsers();
    RegisterSMBParsers();
    /** \todo bug 719 */
    //RegisterSMB2Parsers();
    RegisterDCERPCParsers();
    RegisterDCERPCUDPParsers();
    RegisterFTPParsers();
    /* we are disabling the ssh parser temporarily, since we are moving away
     * from some of the archaic features we use in the app layer.  We will
     * reintroduce this parser.  Also do note that keywords that rely on
     * the ssh parser would now be disabled */
#if 0
    RegisterSSHParsers();
#endif
    RegisterSMTPParsers();
    RegisterDNSUDPParsers();
    RegisterDNSTCPParsers();

    /** IMAP */
    if (AppLayerProtoDetectionEnabled("imap")) {
        if (AlpdRegisterProtocol(alpd_ctx, ALPROTO_IMAP, "imap") < 0)
            return;
        if (AlpdPMRegisterPatternCI(alpd_ctx, IPPROTO_TCP, ALPROTO_IMAP,
                                    "1|20|capability", 12, 0, STREAM_TOSERVER) < 0)
        {
            return -1;
        }
#if 0
        AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_IMAP, "|2A 20|OK|20|", 5, 0, STREAM_TOCLIENT);
#endif
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol.",
                  "imap");
        return;
    }

    /** MSN Messenger */
    if (AppLayerProtoDetectionEnabled("msn")) {
        if (AlpdRegisterProtocol(alpd_ctx, ALPROTO_MSN, "msn") < 0)
            return;
        if (AlpdPMRegisterPatternCI(alpd_ctx, IPPROTO_TCP, ALPROTO_MSN,
                                    "MSNP", 10, 6, STREAM_TOSERVER) < 0)
        {
            return -1;
        }
#if 0
        AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_MSN, "MSNP", 10, 6, STREAM_TOCLIENT);
#endif
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol.",
                  "msn");
        return;
    }

#if 0
    /** Jabber */
    if (AppLayerProtoDetectionEnabled("jabber")) {
        if (AlpRegisterProtocolForDetection(&alp_proto_ctx,
                                            ALPROTO_JABBER, jabber) < 0)
        {
            /* We need to overload the exit function to figure out where
             * we exited from. */
            exit(EXIT_FAILURE);
        }

        AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_JABBER, "xmlns='jabber|3A|client'", 74, 53, STREAM_TOCLIENT);
        AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_JABBER, "xmlns='jabber|3A|client'", 74, 53, STREAM_TOSERVER);
    } else {
        SCLogInfo("Protocol detection disabled for %s protocol and as a "
                  "consequence the conf param \"app-layer.protocols.%s."
                  "parser-enabled\" will now be ignored.", "jabber", "jabber");
        return;
    }
#endif

    return;
}

void AppLayerParserCleanupState(Flow *f)
{
    if (f == NULL) {
        SCLogDebug("no flow");
        return;
    }
    if (f->alproto >= ALPROTO_MAX) {
        SCLogDebug("app layer proto unknown");
        return;
    }

    /* free the parser protocol state */
    AppLayerProto *p = &al_proto_table[f->alproto];
    if (p->StateFree != NULL && f->alstate != NULL) {
        SCLogDebug("calling StateFree");
        p->StateFree(f->alstate);
        f->alstate = NULL;
    }

    /* free the app layer parser api state */
    if (f->alparser != NULL) {
        SCLogDebug("calling AppLayerParserStateStoreFree");
        AppLayerParserStateStoreFree(f->alparser);
        f->alparser = NULL;
    }
}

/*************************App Layer Conf Options Parsing***********************/

int AlpConfParserEnabled(const char *alproto)
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
        enabled = 0;
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

/**
 * \brief Gets event info for this alproto.
 *
 * \param alproto The app layer protocol.
 * \param event_name The event name.
 * \param event_id The event id.
 * \param The type of event, as represented by AppLayerEventType.
 *
 * \retval 0 On succesfully returning back info.
 * \retval -1 On failure.
 */
int AppLayerGetEventInfo(uint16_t alproto, const char *event_name,
                         int *event_id, AppLayerEventType *event_type)
{
    if (al_proto_table[alproto].StateGetEventInfo == NULL)
        return -1;

    return al_proto_table[alproto].StateGetEventInfo(event_name,
                                                     event_id, event_type);
}

/***** Anoop *****/

void *AlpGetCtxThread(void *ctx)
{
    SCEnter();

    AppProto *alproto = 0;
    AlpCtxThread *tctx;

    tctx = SCMalloc(sizeof(*tctx));
    if (tctx == NULL)
        goto error;
    memset(tctx, 0, sizeof(*tctx));

    for (alproto = 0; alproto < ALPROTO_MAX; alproto++) {
        tctx->alproto_local_storage[alproto] =
            AppLayerGetProtocolParserLocalStorage(ctx, alproto);
    }

 error:
    tctx = NULL;
 end:
    SCReturnPtr(tctx, "void *");
}

void AlpDestroyCtxThread(void *tctx)
{
    SCEnter();

    SCFree(tctx);

    SCReturn;
}


/**************************************Unittests*******************************/

#ifdef UNITTESTS

typedef struct TestState_ {
    uint8_t test;
}TestState;

/**
 *  \brief  Test parser function to test the memory deallocation of app layer
 *          parser of occurence of an error.
 */
static int TestProtocolParser(Flow *f, void *test_state, AppLayerParserState *pstate,
                              uint8_t *input, uint32_t input_len,
                              void *local_data, AppLayerParserResult *output)
{
    return -1;
}

/** \brief Function to allocates the Test protocol state memory
 */
static void *TestProtocolStateAlloc(void)
{
    void *s = SCMalloc(sizeof(TestState));
    if (unlikely(s == NULL))
        return NULL;

    memset(s, 0, sizeof(TestState));
    return s;
}

/** \brief Function to free the Test Protocol state memory
 */
static void TestProtocolStateFree(void *s)
{
    SCFree(s);
}

static AppLayerProto al_proto_table_ut_backup[ALPROTO_MAX];

void AppLayerParserBackupAlprotoTable(void)
{
    int i;
    for (i = ALPROTO_UNKNOWN; i < ALPROTO_MAX; i++)
        al_proto_table_ut_backup[i].StateGetEventInfo = al_proto_table[i].StateGetEventInfo;

    return;
}

void AppLayerParserRestoreAlprotoTable(void)
{
    int i;
    for (i = ALPROTO_UNKNOWN; i < ALPROTO_MAX; i++)
        al_proto_table[i].StateGetEventInfo = al_proto_table_ut_backup[i].StateGetEventInfo;

    return;
}

/**
 * \test Test the deallocation of app layer parser memory on occurance of
 *       error in the parsing process.
 */
static int AppLayerParserTest01 (void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t testbuf[] = { 0x11 };
    uint32_t testlen = sizeof(testbuf);
    TcpSession ssn;

    memset(&ssn, 0, sizeof(ssn));

    /* Register the Test protocol state and parser functions */
    AppLayerRegisterProto("test", ALPROTO_TEST, STREAM_TOSERVER,
                          TestProtocolParser);
    AppLayerRegisterStateFuncs(ALPROTO_TEST, TestProtocolStateAlloc,
                                TestProtocolStateFree);

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "4.3.2.1", 20, 40);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;

    f->alproto = ALPROTO_TEST;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f->m);
    int r = AppLayerParse(NULL, f, ALPROTO_TEST, STREAM_TOSERVER|STREAM_EOF, testbuf,
                          testlen);
    if (r != -1) {
        printf("returned %" PRId32 ", expected -1: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

    if (!(f->flags & FLOW_NO_APPLAYER_INSPECTION))
    {
        printf("flag should have been set, but is not: ");
        goto end;
    }

    result = 1;
end:
    StreamTcpFreeConfig(TRUE);

    UTHFreeFlow(f);
    return result;
}

/**
 * \test Test the deallocation of app layer parser memory on occurance of
 *       error in the parsing process for UDP.
 */
static int AppLayerParserTest02 (void)
{
    int result = 1;
    Flow *f = NULL;
    uint8_t testbuf[] = { 0x11 };
    uint32_t testlen = sizeof(testbuf);

    /* Register the Test protocol state and parser functions */
    AppLayerRegisterProto("test", ALPROTO_TEST, STREAM_TOSERVER,
                          TestProtocolParser);
    AppLayerRegisterStateFuncs(ALPROTO_TEST, TestProtocolStateAlloc,
                                TestProtocolStateFree);

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "4.3.2.1", 20, 40);
    if (f == NULL)
        goto end;
    f->alproto = ALPROTO_TEST;
    f->proto = IPPROTO_UDP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f->m);
    int r = AppLayerParse(NULL, f, ALPROTO_TEST, STREAM_TOSERVER|STREAM_EOF, testbuf,
                          testlen);
    if (r != -1) {
        printf("returned %" PRId32 ", expected -1: \n", r);
        result = 0;
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

end:
    StreamTcpFreeConfig(TRUE);
    UTHFreeFlow(f);
    return result;
}

typedef struct AppLayerPPTestDataElement_ {
    char *al_proto_name;
    uint16_t al_proto;
    uint16_t port;
    uint32_t al_proto_mask;
    uint32_t min_depth;
    uint32_t max_depth;
} AppLayerPPTestDataElement;

typedef struct AppLayerPPTestDataPort_ {
    uint16_t port;
    uint32_t toserver_al_proto_mask;
    uint32_t toclient_al_proto_mask;
    uint16_t toserver_max_depth;
    uint16_t toclient_max_depth;

    AppLayerPPTestDataElement *toserver_element;
    AppLayerPPTestDataElement *toclient_element;
    int ts_no_of_element;
    int tc_no_of_element;
} AppLayerPPTestDataPort;


typedef struct AppLayerPPTestDataIPProto_ {
    uint16_t ip_proto;

    AppLayerPPTestDataPort *port;
    int no_of_port;
} AppLayerPPTestDataIPProto;

int AppLayerPPTestData(AppLayerProbingParser *pp,
                       AppLayerPPTestDataIPProto *ip_proto, int no_of_ip_proto)
{
    int result = 0;
    int i, j, k;
#ifdef DEBUG
    int dir = 0;
#endif
    for (i = 0; i < no_of_ip_proto; i++, pp = pp->next) {
        if (pp->ip_proto != ip_proto[i].ip_proto)
            goto end;

        AppLayerProbingParserPort *pp_port = pp->port;
        for (k = 0; k < ip_proto[i].no_of_port; k++, pp_port = pp_port->next) {
            if (pp_port->port != ip_proto[i].port[k].port)
                goto end;
            if (pp_port->toserver_al_proto_mask != ip_proto[i].port[k].toserver_al_proto_mask)
                goto end;
            if (pp_port->toclient_al_proto_mask != ip_proto[i].port[k].toclient_al_proto_mask)
                goto end;
            if (pp_port->toserver_max_depth != ip_proto[i].port[k].toserver_max_depth)
                goto end;
            if (pp_port->toclient_max_depth != ip_proto[i].port[k].toclient_max_depth)
                goto end;

            AppLayerProbingParserElement *pp_element = pp_port->toserver;
#ifdef DEBUG
            dir = 0;
#endif
            for (j = 0 ; j < ip_proto[i].port[k].ts_no_of_element;
                 j++, pp_element = pp_element->next) {

                if ((strlen(pp_element->al_proto_name) !=
                     strlen(ip_proto[i].port[k].toserver_element[j].al_proto_name)) ||
                    strcasecmp(pp_element->al_proto_name,
                               ip_proto[i].port[k].toserver_element[j].al_proto_name) != 0) {
                    goto end;
                }
                if (pp_element->al_proto != ip_proto[i].port[k].toserver_element[j].al_proto) {
                    goto end;
                }
                if (pp_element->port != ip_proto[i].port[k].toserver_element[j].port) {
                    goto end;
                }
                if (pp_element->al_proto_mask != ip_proto[i].port[k].toserver_element[j].al_proto_mask) {
                    goto end;
                }
                if (pp_element->min_depth != ip_proto[i].port[k].toserver_element[j].min_depth) {
                    goto end;
                }
                if (pp_element->max_depth != ip_proto[i].port[k].toserver_element[j].max_depth) {
                    goto end;
                }
            } /* for */
            if (pp_element != NULL)
                goto end;

            pp_element = pp_port->toclient;
#ifdef DEBUG
            dir = 1;
#endif
            for (j = 0 ; j < ip_proto[i].port[k].tc_no_of_element; j++, pp_element = pp_element->next) {
                if ((strlen(pp_element->al_proto_name) !=
                     strlen(ip_proto[i].port[k].toclient_element[j].al_proto_name)) ||
                    strcasecmp(pp_element->al_proto_name,
                               ip_proto[i].port[k].toclient_element[j].al_proto_name) != 0) {
                    goto end;
                }
                if (pp_element->al_proto != ip_proto[i].port[k].toclient_element[j].al_proto) {
                    goto end;
                }
                if (pp_element->port != ip_proto[i].port[k].toclient_element[j].port) {
                    goto end;
                }
                if (pp_element->al_proto_mask != ip_proto[i].port[k].toclient_element[j].al_proto_mask) {
                    goto end;
                }
                if (pp_element->min_depth != ip_proto[i].port[k].toclient_element[j].min_depth) {
                    goto end;
                }
                if (pp_element->max_depth != ip_proto[i].port[k].toclient_element[j].max_depth) {
                    goto end;
                }
            } /* for */
            if (pp_element != NULL)
                goto end;
        }
        if (pp_port != NULL)
            goto end;
    }
    if (pp != NULL)
        goto end;

    result = 1;
 end:
#ifdef DEBUG
    printf("i = %d, k = %d, j = %d(%s)\n", i, k, j, (dir == 0) ? "ts" : "tc");
#endif
    return result;
}

uint16_t ProbingParserDummyForTesting(uint8_t *input, uint32_t input_len, uint32_t *offset)
{
    return 0;
}

static int AppLayerProbingParserTest01(void)
{
    int result = 0;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "80",
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "80",
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 6,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "80",
                                  "ftp",
                                  ALPROTO_FTP,
                                  7, 10,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);

    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "81",
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "81",
                                  "ftp",
                                  ALPROTO_FTP,
                                  7, 15,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "0",
                                  "smtp",
                                  ALPROTO_SMTP,
                                  12, 0,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "0",
                                  "tls",
                                  ALPROTO_TLS,
                                  12, 18,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);

    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "85",
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "85",
                                  "ftp",
                                  ALPROTO_FTP,
                                  7, 15,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);
    result = 1;

    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_UDP,
                                  "85",
                                  "imap",
                                  ALPROTO_IMAP,
                                  12, 23,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);

    /* toclient */
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "0",
                                  "jabber",
                                  ALPROTO_JABBER,
                                  12, 23,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "0",
                                  "irc",
                                  ALPROTO_IRC,
                                  12, 14,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);

    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "85",
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "81",
                                  "ftp",
                                  ALPROTO_FTP,
                                  7, 15,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "0",
                                  "tls",
                                  ALPROTO_TLS,
                                  12, 18,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "80",
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "81",
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "90",
                                  "ftp",
                                  ALPROTO_FTP,
                                  7, 15,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "80",
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 6,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_UDP,
                                  "85",
                                  "imap",
                                  ALPROTO_IMAP,
                                  12, 23,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "0",
                                  "smtp",
                                  ALPROTO_SMTP,
                                  12, 17,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "80",
                                  "ftp",
                                  ALPROTO_FTP,
                                  7, 10,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);

    //AppLayerPrintProbingParsers(ctx.probing_parsers);

    AppLayerPPTestDataElement element_ts_80[] =
        { { "http", ALPROTO_HTTP, 80, 1 << ALPROTO_HTTP, 5, 8 },
          { "smb", ALPROTO_SMB, 80, 1 << ALPROTO_SMB, 5, 6 },
          { "ftp", ALPROTO_FTP, 80, 1 << ALPROTO_FTP, 7, 10 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 0 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 25 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
        };
    AppLayerPPTestDataElement element_tc_80[] =
        { { "http", ALPROTO_HTTP, 80, 1 << ALPROTO_HTTP, 5, 8 },
          { "smb", ALPROTO_SMB, 80, 1 << ALPROTO_SMB, 5, 6 },
          { "ftp", ALPROTO_FTP, 80, 1 << ALPROTO_FTP, 7, 10 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 14 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 17 }
        };

    AppLayerPPTestDataElement element_ts_81[] =
        { { "dcerpc", ALPROTO_DCERPC, 81, 1 << ALPROTO_DCERPC, 9, 10 },
          { "ftp", ALPROTO_FTP, 81, 1 << ALPROTO_FTP, 7, 15 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 0 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 25 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
        };
    AppLayerPPTestDataElement element_tc_81[] =
        { { "ftp", ALPROTO_FTP, 81, 1 << ALPROTO_FTP, 7, 15 },
          { "dcerpc", ALPROTO_DCERPC, 81, 1 << ALPROTO_DCERPC, 9, 10 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 14 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 17 }
        };

    AppLayerPPTestDataElement element_ts_85[] =
        { { "dcerpc", ALPROTO_DCERPC, 85, 1 << ALPROTO_DCERPC, 9, 10 },
          { "ftp", ALPROTO_FTP, 85, 1 << ALPROTO_FTP, 7, 15 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 0 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 25 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
        };
    AppLayerPPTestDataElement element_tc_85[] =
        { { "dcerpc", ALPROTO_DCERPC, 85, 1 << ALPROTO_DCERPC, 9, 10 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 14 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 17 }
        };

    AppLayerPPTestDataElement element_ts_90[] =
        { { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 0 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 25 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
        };
    AppLayerPPTestDataElement element_tc_90[] =
        { { "ftp", ALPROTO_FTP, 90, 1 << ALPROTO_FTP, 7, 15 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 14 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 17 }
        };

    AppLayerPPTestDataElement element_ts_0[] =
        { { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 0 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 25 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
        };
    AppLayerPPTestDataElement element_tc_0[] =
        { { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 14 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 17 }
        };


    AppLayerPPTestDataElement element_ts_85_udp[] =
        { { "imap", ALPROTO_IMAP, 85, 1 << ALPROTO_IMAP, 12, 23 },
        };
    AppLayerPPTestDataElement element_tc_85_udp[] =
        { { "imap", ALPROTO_IMAP, 85, 1 << ALPROTO_IMAP, 12, 23 },
        };

    AppLayerPPTestDataPort ports_tcp[] =
        { { 80,
            ((1 << ALPROTO_HTTP) | (1 << ALPROTO_SMB) | (1 << ALPROTO_FTP) |
             (1 << ALPROTO_SMTP) | (1 << ALPROTO_TLS) | (1 << ALPROTO_IRC) | (1 << ALPROTO_JABBER)),
            ((1 << ALPROTO_HTTP) | (1 << ALPROTO_SMB) | (1 << ALPROTO_FTP) |
             (1 << ALPROTO_JABBER) | (1 << ALPROTO_IRC) | (1 << ALPROTO_TLS) | (1 << ALPROTO_SMTP)),
            0, 23,
            element_ts_80, element_tc_80,
            sizeof(element_ts_80) / sizeof(AppLayerPPTestDataElement),
            sizeof(element_tc_80) / sizeof(AppLayerPPTestDataElement),
            },
          { 81,
            ((1 << ALPROTO_DCERPC) | (1 << ALPROTO_FTP) |
             (1 << ALPROTO_SMTP) | (1 << ALPROTO_TLS) | (1 << ALPROTO_IRC) | (1 << ALPROTO_JABBER)),
            ((1 << ALPROTO_FTP) | (1 << ALPROTO_DCERPC) |
             (1 << ALPROTO_JABBER) | (1 << ALPROTO_IRC) | (1 << ALPROTO_TLS) | (1 << ALPROTO_SMTP)),
            0, 23,
            element_ts_81, element_tc_81,
            sizeof(element_ts_81) / sizeof(AppLayerPPTestDataElement),
            sizeof(element_tc_81) / sizeof(AppLayerPPTestDataElement),
          },
          { 85,
            ((1 << ALPROTO_DCERPC) | (1 << ALPROTO_FTP) |
             (1 << ALPROTO_SMTP) | (1 << ALPROTO_TLS) | (1 << ALPROTO_IRC) | (1 << ALPROTO_JABBER)),
            ((1 << ALPROTO_DCERPC) |
             (1 << ALPROTO_JABBER) | (1 << ALPROTO_IRC) | (1 << ALPROTO_TLS) | (1 << ALPROTO_SMTP)),
            0, 23,
            element_ts_85, element_tc_85,
            sizeof(element_ts_85) / sizeof(AppLayerPPTestDataElement),
            sizeof(element_tc_85) / sizeof(AppLayerPPTestDataElement)
          },
          { 90,
            ((1 << ALPROTO_SMTP) | (1 << ALPROTO_TLS) | (1 << ALPROTO_IRC) | (1 << ALPROTO_JABBER)),
            ((1 << ALPROTO_FTP) |
             (1 << ALPROTO_JABBER) | (1 << ALPROTO_IRC) | (1 << ALPROTO_TLS) | (1 << ALPROTO_SMTP)),
            0, 23,
            element_ts_90, element_tc_90,
            sizeof(element_ts_90) / sizeof(AppLayerPPTestDataElement),
            sizeof(element_tc_90) / sizeof(AppLayerPPTestDataElement)
          },
          { 0,
            ((1 << ALPROTO_SMTP) | (1 << ALPROTO_TLS) | (1 << ALPROTO_IRC) | (1 << ALPROTO_JABBER)),
            ((1 << ALPROTO_JABBER) | (1 << ALPROTO_IRC) | (1 << ALPROTO_TLS) | (1 << ALPROTO_SMTP)),
            0, 23,
            element_ts_0, element_tc_0,
            sizeof(element_ts_0) / sizeof(AppLayerPPTestDataElement),
            sizeof(element_tc_0) / sizeof(AppLayerPPTestDataElement)
          }
        };

    AppLayerPPTestDataPort ports_udp[] =
        { { 85,
            (1 << ALPROTO_IMAP),
            (1 << ALPROTO_IMAP),
            23, 23,
            element_ts_85_udp, element_tc_85_udp,
            sizeof(element_ts_85_udp) / sizeof(AppLayerPPTestDataElement),
            sizeof(element_tc_85_udp) / sizeof(AppLayerPPTestDataElement),
            },
        };

    AppLayerPPTestDataIPProto ip_proto[] =
        { { IPPROTO_TCP,
            ports_tcp,
            sizeof(ports_tcp) / sizeof(AppLayerPPTestDataPort),
            },
          { IPPROTO_UDP,
            ports_udp,
            sizeof(ports_udp) / sizeof(AppLayerPPTestDataPort),
          },
        };


    if (AppLayerPPTestData(ctx.probing_parsers, ip_proto,
                           sizeof(ip_proto) / sizeof(AppLayerPPTestDataIPProto)) == 0) {
       goto end;
    }
    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

#endif /* UNITESTS */

void AppLayerParserRegisterTests(void)
{
#ifdef UNITTESTS
    int i;
    for (i = 0; i < ALPROTO_MAX; i++) {
        AppLayerProto *p = &al_proto_table[i];

        if (p->name == NULL)
            continue;

        g_ut_modules++;

        if (p->RegisterUnittests != NULL) {
            p->RegisterUnittests();
            g_ut_covered++;
        } else {
            if (coverage_unittests)
                SCLogWarning(SC_WARN_NO_UNITTESTS, "app layer module %s has no "
                        "unittests", p->name);
        }
    }

    UtRegisterTest("AppLayerParserTest01", AppLayerParserTest01, 1);
    UtRegisterTest("AppLayerParserTest02", AppLayerParserTest02, 1);
    UtRegisterTest("AppLayerProbingParserTest01",
                   AppLayerProbingParserTest01, 1);
#endif /* UNITTESTS */

    return;
}
