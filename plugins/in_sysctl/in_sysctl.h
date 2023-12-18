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

#ifndef FLB_IN_SYSCTL_H
#define FLB_IN_SYSCTL_H

struct flb_input_instance;
struct flb_log_event_encoder;
struct mk_list;
/* XXX */
struct msgpack_packer;

/*
 * The output data format.
 */
enum in_sysctl_format {
    /*
     * Flat:
     * The data is a simple map, where the keys are the full OID names.
     */
    ISC_FMT_FLAT,
    /*
     * Nested:
     * The data is in the nested maps a la the filesystem hierarchy.
     * The keys may be either the full OID names or its rightmst component
     * only.
     */
    ISC_FMT_NESTED,
};

/*
 * The output content.
 */
enum in_sysctl_content {
    /*
     * Values:
     * The values.
     */
    ISC_CNT_VALUES,
    /*
     * Elasticsearch mapping:
     * The explicit mapping definition of Elasticsearch.
     */
    ISC_CNT_ES_EXPLICIT_MAPPING,
};

/*
 * The plugin configuration.
 */
struct in_sysctl_config {
	/* Measurement period in seconds. */
	double                  iscc_period;

	/* Sysctl(3) names. */
	struct mk_list          *iscc_names;

	/*
     * Data format.
     * The string from the configuration map is mapped into the enum.
     */
	flb_sds_t               iscc_format_str;
    enum in_sysctl_format   iscc_format;

    /* If true, use the full OID name in the nested format. */
    int                     iscc_nested_oid_fullname;

	/*
     * Output content.
     * The string from the configuration map is mapped into the enum.
     */
	flb_sds_t               iscc_content_str;
    enum in_sysctl_content  iscc_content;
};

/*
 * The plugin context.
 */
struct in_sysctl_ctx {
    /* Input instance. */
    struct flb_input_instance       *iscx_input;

    /* Event encoder. */
    struct flb_log_event_encoder    *iscx_event_encoder;

    /* Interval-driven collector. */
    int                             iscx_collector;
};

/*
 * The plugin data.
 */
struct in_sysctl {
    /*
     * Configuration parameters.
     */
    const struct in_sysctl_config   *isc_iscc;

    /*
     * Execution context.
     */
    struct in_sysctl_ctx            *isc_iscx;
};

int in_sysctl_collect_by_name(
    const struct in_sysctl * restrict ctx,
    const char * restrict name,
    struct msgpack_packer * restrict msg_pk);

#endif
