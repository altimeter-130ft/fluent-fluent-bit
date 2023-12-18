/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2023 Seigo Tanimura <seigo.tanimura@gmail.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <math.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>

#include <msgpack.h>

#include "in_sysctl.h"

/*
 * The internal plugin data, for the use in this source only.
 *
 * The configuration is mutable.
 */
struct in_sysctl_internal {
    /*
     * Configuration parameters.
     */
    struct in_sysctl_config isc_iscc;

    /*
     * Execution context.
     */
    struct in_sysctl_ctx    isc_iscx;
};

/* The data format configuration table. */
struct in_sysctl_format_tab {
    const char              *iscft_key;
    enum in_sysctl_format   iscft_value;
};
static const struct in_sysctl_format_tab in_sysctl_format_tab[] = {
    {"flat",    ISC_FMT_FLAT},
    {"nested",  ISC_FMT_NESTED},
    {NULL,      -1}
};

/* The output content configuration table. */
struct in_sysctl_content_tab {
    const char              *iscct_key;
    enum in_sysctl_content  iscct_value;
};
static const struct in_sysctl_content_tab in_sysctl_content_tab[] = {
    {"values",              ISC_CNT_VALUES},
    {"es_explicit_mapping", ISC_CNT_ES_EXPLICIT_MAPPING},
    {NULL,      -1}
};

static int in_sysctl_collect(
    struct flb_input_instance * restrict ins,
    struct flb_config *restrict config,
    void * restrict in_context);
static int config_destroy(struct in_sysctl_internal *ictx);
static int configure(struct in_sysctl_internal *ictx);
static int in_sysctl_init(struct flb_input_instance *in,
    struct flb_config *config,
    void *data);
static void in_sysctl_pause(void *data, struct flb_config *config);
static void in_sysctl_resume(void *data, struct flb_config *config);
static int in_sysctl_exit(void *data, struct flb_config *config);

/* Collect the input log. */
static int in_sysctl_collect(
    struct flb_input_instance * restrict ins,
    struct flb_config *restrict config,
    void * restrict in_context)
{
    int ret;
    double exit_sleep;
    struct in_sysctl_internal *ictx;
    struct flb_time timestamp;
    struct mk_list *name;
    struct flb_slist_entry *name_e;
    msgpack_sbuffer msg_sb;
    msgpack_packer msg_pk;
    struct timespec ts;

    ictx = (struct in_sysctl_internal *)in_context;
    const struct in_sysctl ctx_exported = {
        .isc_iscc = &ictx->isc_iscc,
        .isc_iscx = &ictx->isc_iscx,
    };
    const struct in_sysctl *ctx = &ctx_exported;

    flb_time_get(&timestamp);

    msgpack_sbuffer_init(&msg_sb);
    msgpack_packer_init(&msg_pk, &msg_sb, msgpack_sbuffer_write);

    flb_log_event_encoder_reset(ctx->isc_iscx->iscx_event_encoder);

    flb_log_event_encoder_begin_record(ctx->isc_iscx->iscx_event_encoder);
    flb_log_event_encoder_set_timestamp(
        ctx->isc_iscx->iscx_event_encoder,
        &timestamp);

    mk_list_foreach(name, ctx->isc_iscc->iscc_names) {
        name_e = mk_list_entry(name, struct flb_slist_entry, _head);
        ret = in_sysctl_collect_by_name(ctx, name_e->str, &msg_pk);
        if (0 != ret) {
            flb_plg_error(
                ctx->isc_iscx->iscx_input,
                "name = %s, ret = %d",
                name_e->str, ret);
        }
    }

    ret = flb_log_event_encoder_set_body_from_raw_msgpack(
        ctx->isc_iscx->iscx_event_encoder,
        msg_sb.data,
        msg_sb.size);
    if (FLB_EVENT_ENCODER_SUCCESS != ret) {
        flb_plg_error(
            ctx->isc_iscx->iscx_input,
            "flb_log_event_encoder_set_body_from_raw_msgpack failed");
        goto err;
    }

    /* TODO: set the event metadata. */

    ret = flb_log_event_encoder_commit_record(
        ctx->isc_iscx->iscx_event_encoder);
    if (0 != ret) {
        flb_plg_error(
            ctx->isc_iscx->iscx_input,
            "flb_log_event_encoder_commit_record failed");
        goto err;
    }
    if (0 == ctx->isc_iscx->iscx_event_encoder->output_length) {
        flb_plg_error(ctx->isc_iscx->iscx_input, "no log encoded");
        goto err;
    }

    flb_input_log_append(ctx->isc_iscx->iscx_input,
        NULL,
        0,
        ctx->isc_iscx->iscx_event_encoder->output_buffer,
        ctx->isc_iscx->iscx_event_encoder->output_length);

    msgpack_sbuffer_destroy(&msg_sb);

    if (ISC_CNT_ES_EXPLICIT_MAPPING == ctx->isc_iscc->iscc_content) {
        /* The Elasticsearch explicit mapping is a one-shot run. */
        flb_plg_info(
            ctx->isc_iscx->iscx_input,
            "Elasticsearch explicit mapping content, exitting without looping");
        /*
         * Sleep for half of the measurement period to tidy up the log before
         * exitting.
         * XXX Is the graceful exit supported by the fluent-bit API?
         */
        exit_sleep = ctx->isc_iscc->iscc_period / 2.0;
        ts.tv_sec = floor(exit_sleep);
        ts.tv_nsec = exit_sleep - ts.tv_sec * 1e+9;
        nanosleep(&ts, NULL);
        kill(getpid(), SIGTERM);
    }

    return 0;

err:
    msgpack_sbuffer_destroy(&msg_sb);

    return -1;
}

static int config_destroy(struct in_sysctl_internal *ictx)
{
    if (NULL != ictx->isc_iscx.iscx_event_encoder) {
        flb_log_event_encoder_destroy(ictx->isc_iscx.iscx_event_encoder);
    }

    flb_free(ictx);

    return 0;
}

/* Validate the parameters and configure the plugin. */
static int configure(struct in_sysctl_internal *ictx)
{
    int ret;
    struct in_sysctl_config *config;
    const struct in_sysctl_format_tab *iscft;
    const struct in_sysctl_content_tab *iscct;

    config = &ictx->isc_iscc;

    ret = flb_input_config_map_set(ictx->isc_iscx.iscx_input, (void *)config);
    if (ret == -1) {
        goto err;
    }

    if (config->iscc_period <= 0) {
        flb_plg_error(ictx->isc_iscx.iscx_input, "period MUST be positive");
        goto err;
    }

    if ((NULL == config->iscc_names) ||
        (0 == mk_list_is_empty(config->iscc_names))) {
        flb_plg_error(
            ictx->isc_iscx.iscx_input,
            "sysctl(3) names MUST be configured");
        goto err;
    }

    for (iscft = in_sysctl_format_tab; NULL != iscft->iscft_key; iscft++) {
        if (0 == strcmp(iscft->iscft_key, config->iscc_format_str)) {
            config->iscc_format = iscft->iscft_value;
            break;
        }
    }
    if (NULL == iscft->iscft_key) {
        flb_plg_error(
            ictx->isc_iscx.iscx_input,
            "unsupported data format %s",
            config->iscc_format_str);
        goto err;
    }

    for (iscct = in_sysctl_content_tab; NULL != iscct->iscct_key; iscct++) {
        if (0 == strcmp(iscct->iscct_key, config->iscc_content_str)) {
            config->iscc_content = iscct->iscct_value;
            break;
        }
    }
    if (NULL == iscct->iscct_key) {
        flb_plg_error(
            ictx->isc_iscx.iscx_input,
            "unsupported content %s",
            config->iscc_content_str);
        goto err;
    }

    return 0;

err:
    return -1;
}

/* Initialize the plugin. */
static int in_sysctl_init(struct flb_input_instance *in,
    struct flb_config *config,
    void *data)
{
    int ret;
    struct in_sysctl_internal *ictx;

    /* Allocate space for the configuration. */
    ictx = flb_malloc(sizeof(struct in_sysctl_internal));
    if (ictx == NULL) {
        goto err;
    }
    memset(ictx, 0, sizeof(*ictx));
    ictx->isc_iscx.iscx_input = in;
    ictx->isc_iscc.iscc_format = ISC_FMT_FLAT;

    /* Initialize the head config. */
    ret = configure(ictx);
    if (ret < 0) {
        goto err;
    }

    ictx->isc_iscx.iscx_event_encoder =
        flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (ictx->isc_iscx.iscx_event_encoder == NULL) {
        flb_plg_error(
            ictx->isc_iscx.iscx_input,
            "flb_log_event_encoder_create failed");
        goto err;
    }

    flb_input_set_context(ictx->isc_iscx.iscx_input, ictx);

    ret = flb_input_set_collector_time(ictx->isc_iscx.iscx_input,
        in_sysctl_collect,
        (time_t)floor(ictx->isc_iscc.iscc_period),
        (long)((ictx->isc_iscc.iscc_period -
            floor(ictx->isc_iscc.iscc_period)) * 1e+9),
        config);
    if (ret < 0) {
        flb_plg_error(
            ictx->isc_iscx.iscx_input,
            "flb_input_set_collector_time failed");
        goto err;
    }

    ictx->isc_iscx.iscx_collector = ret;

    return 0;

err:
    if (NULL != ictx)
        config_destroy(ictx);
    return -1;
}

static void in_sysctl_pause(void *data, struct flb_config *config)
{
    struct in_sysctl_internal *ictx = data;

    flb_input_collector_pause(
        ictx->isc_iscx.iscx_collector,
        ictx->isc_iscx.iscx_input);
}

static void in_sysctl_resume(void *data, struct flb_config *config)
{
    struct in_sysctl_internal *ictx = data;

    flb_input_collector_resume(
        ictx->isc_iscx.iscx_collector,
        ictx->isc_iscx.iscx_input);
}

static int in_sysctl_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct in_sysctl_internal *ictx = data;

    config_destroy(ictx);

    return 0;
}

/* Configuration properties map. */
static struct flb_config_map sysctl_config_map[] = {
   {
    FLB_CONFIG_MAP_DOUBLE, "period", "10.0",
    0, FLB_TRUE, offsetof(struct in_sysctl_config, iscc_period),
    "measurement period in seconds."
   },
   {
    FLB_CONFIG_MAP_SLIST, "names", NULL,
    0, FLB_TRUE, offsetof(struct in_sysctl_config, iscc_names),
    "set the sample record to be generated. It should be a JSON object."
   },
   {
    FLB_CONFIG_MAP_STR, "format", "flat",
    0, FLB_TRUE, offsetof(struct in_sysctl_config, iscc_format_str),
    "data format. (flat, nested)"
   },
   {
    FLB_CONFIG_MAP_BOOL, "nested_oid_fullname", "false",
    0, FLB_TRUE, offsetof(struct in_sysctl_config, iscc_nested_oid_fullname),
    "use the full OID name in the nested format."
   },
   {
    FLB_CONFIG_MAP_STR, "content", "values",
    0, FLB_TRUE, offsetof(struct in_sysctl_config, iscc_content_str),
    "content. (values, es_explicit_mapping)"
   },
   {0}
};

/* Input plugin structure. */
struct flb_input_plugin in_sysctl_plugin = {
    .name         = "sysctl",
    .description  = "Sysctl(3)",
    .cb_init      = in_sysctl_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_sysctl_collect,
    .cb_flush_buf = NULL,
    .config_map   = sysctl_config_map,
    .cb_pause     = in_sysctl_pause,
    .cb_resume    = in_sysctl_resume,
    .cb_exit      = in_sysctl_exit
};
