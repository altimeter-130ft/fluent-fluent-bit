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

/*
 * The sysctl(3) node tree, in the style a la a filesystem hierarchy.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <sys/sysctl.h>

#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event.h>

#include "in_sysctl.h"
#include "in_sysctl_tree.h"

#define KEY_DELIMITER   '.'

#define ES_EXPLICIT_MAPPING_FIELDS      "fields"
#define ES_EXPLICIT_MAPPING_PROPERTIES  "properties"
#define ES_EXPLICIT_MAPPING_TYPE        "type"

#define ES_EXPLICIT_MAPPING_MULTIVALUE_TEXT "text"

struct sysctl_tree_node_type_tab {
    int         nt_type;
    const char  *nt_str;
};
static const struct sysctl_tree_node_type_tab in_sysctl_tree_node_types[] = {
    {NODETYPE_ROOT,     "root"},
    {NODETYPE_NODE,     "node"},
    {NODETYPE_INT,      "int"},
    {NODETYPE_STRING,   "string"},
    {NODETYPE_S64,      "s64"},
    /* TODO. */
    /* {NODETYPE_OPAQUE,   "opaque"}, */
    {NODETYPE_UINT,     "uint"},
    {NODETYPE_LONG,     "long"},
    {NODETYPE_ULONG,    "ulong"},
    {NODETYPE_U64,      "u64"},
    {NODETYPE_U8,       "u8"},
    {NODETYPE_U16,      "u16"},
    {NODETYPE_S8,       "s8"},
    {NODETYPE_S16,      "s16"},
    {NODETYPE_S32,      "s32"},
    {NODETYPE_U32,      "u32"},
    {0,                 NULL},
};

static int in_sysctl_tree_node_depth(const struct in_sysctl_tree_node *node);
static flb_sds_t in_sysctl_tree_node_key_above_depth(
    const struct in_sysctl_tree_node *node,
    int depth);
static flb_sds_t in_sysctl_tree_node_format_value(
    const struct in_sysctl_tree_node * restrict node);
static const char *in_sysctl_tree_node_type(
    enum in_sysctl_tree_node_type type);
static int in_sysctl_tree_node_pack_string(
    const char * restrict str,
    msgpack_packer * restrict msg_pk);
static size_t in_sysctl_tree_count_leaves(
    const struct in_sysctl_tree_node * restrict node);
static int in_sysctl_tree_node_count_children(
    const struct in_sysctl * restrict ctx,
    const struct in_sysctl_tree_node * restrict node);
static int in_sysctl_tree_node_pack_value(
    const struct in_sysctl * restrict ctx,
    const struct in_sysctl_tree_node * restrict node,
    msgpack_packer * restrict msg_pk);
static int in_sysctl_tree_node_pack_es_explicit_mapping_scalar(
    const struct in_sysctl * restrict ctx,
    const char *type,
    msgpack_packer * restrict msg_pk);
static int in_sysctl_tree_node_pack_es_explicit_mapping(
    const struct in_sysctl * restrict ctx,
    const struct in_sysctl_tree_node * restrict node,
    msgpack_packer * restrict msg_pk);

/*
 * Allocate a new tree node.
 *
 * Its value must be filled in by the caller.
 */
struct in_sysctl_tree_node *in_sysctl_tree_node_alloc(
    int type,
    const char *key)
{
    struct in_sysctl_tree_node *node;

    node = NULL;

    if (((NODETYPE_ROOT == type) && (NULL != key)) ||
        ((NODETYPE_ROOT != type) && (NULL == key))) {
        errno = EINVAL;
        goto err;
    }

    node = flb_malloc(sizeof(struct in_sysctl_tree_node));
    if (NULL == node) {
        goto err;
    }

    mk_list_entry_init(&node->istn_glue);
    node->istn_parent = NULL;
    if (NODETYPE_ROOT != type) {
        node->istn_key = flb_sds_create(key);
        if (NULL == node->istn_key) {
            goto err;
        }
    } else {
        node->istn_key = NULL;
    }
    node->istn_type = type;

    switch (node->istn_type) {
    case NODETYPE_ROOT:
    case NODETYPE_NODE:
        mk_list_init(&node->istn_value.istnv_node);
        break;

    case NODETYPE_STRING:
        node->istn_value.istnv_string = NULL;
        break;

    default:
        memset(&node->istn_value, 0, sizeof(node->istn_value));
        break;
    }

    return node;

err:
    if (NULL != node) {
        flb_sds_destroy(node->istn_key);
        flb_free(node);
    }
    return NULL;
}

/*
 * Free a tree node.
 */
void in_sysctl_tree_node_free(struct in_sysctl_tree_node *node)
{
    struct mk_list *child, *next;
    struct in_sysctl_tree_node *child_node;

    if (NULL == node) {
        return;
    }

    switch (node->istn_type) {
    case NODETYPE_ROOT:
    case NODETYPE_NODE:
        mk_list_foreach_safe(child, next, &node->istn_value.istnv_node) {
            mk_list_del(child);
            child_node = mk_list_entry(child, struct in_sysctl_tree_node, istn_glue);
            in_sysctl_tree_node_free(child_node);
        }
        break;

    case NODETYPE_STRING:
        flb_sds_destroy(node->istn_value.istnv_string);
        break;

    default:
        break;
    }

    node->istn_parent = NULL;
    flb_sds_destroy(node->istn_key);
    memset(&node->istn_value, 0, sizeof(node->istn_value));
    flb_free(node);
}

/*
 * Evaluate the expected depth of a node by its key.
 *
 * The root node depth is -1.
 */
static int in_sysctl_tree_node_depth(const struct in_sysctl_tree_node *node)
{
    const char *p;
    int depth;

    depth = -1;
    p = node->istn_key;
    while (NULL != p) {
        depth++;
        p = strchr(p, KEY_DELIMITER);
        if (NULL != p) {
            p++;
        }
    }

    return depth;
}

/*
 * Extract the part of the key above the given depth, inclusive.
 *
 * The first component is at the zero depth.
 */
static flb_sds_t in_sysctl_tree_node_key_above_depth(
    const struct in_sysctl_tree_node *node,
    int depth)
{
    char *p, *c;
    int node_depth;

    node_depth = in_sysctl_tree_node_depth(node);
    if ((node_depth < 0) || (node_depth < depth)) {
        errno = EINVAL;
        goto err;
    }

    p = node->istn_key;
    while (depth >= 0) {
        p = strchr(p, KEY_DELIMITER);
        if (NULL == p) {
            p = strchr(p, '\0');
        } else {
            p++;
        }
        depth--;
    }
    if ((NULL != p) && ('\0' != *p)) {
        p--;
    }

    c = flb_sds_create_len(node->istn_key, p - node->istn_key);
    if (NULL == c) {
        goto err;
    }

    return c;

err:
    return NULL;
}

/*
 * Insert a node into a tree.
 *
 * The intermediate nodes are created if not found.
 */
int in_sysctl_tree_node_insert(
    struct in_sysctl_tree_node * restrict root,
    struct in_sysctl_tree_node * restrict node)
{
    int root_depth, node_depth, ret, found;
    flb_sds_t component;
    struct mk_list *child;
    struct in_sysctl_tree_node *child_node, *component_node;

    component = NULL;

    if (!((NODETYPE_ROOT == root->istn_type) ||
        (NODETYPE_NODE == root->istn_type))) {
        errno = EINVAL;
        goto err;
    }

    root_depth = in_sysctl_tree_node_depth(root);
    node_depth = in_sysctl_tree_node_depth(node);

    if ((root_depth + 1) > node_depth) {
        errno = EINVAL;
        goto err;
    }

    if ((root_depth + 1) == node_depth) {
        /* Insert at this depth in the ascending order of the key. */
        found = 0;
        mk_list_foreach(child, &root->istn_value.istnv_node) {
            child_node = mk_list_entry(child, struct in_sysctl_tree_node, istn_glue);
            ret = strcmp(child_node->istn_key, node->istn_key);
            if (0 == ret) {
                errno = EEXIST;
                goto err;
            }
            if (ret > 0) {
                found = 1;
                break;
            }
        }
        if (found) {
            mk_list_add_before(&node->istn_glue, child, &root->istn_value.istnv_node);
        } else {
            mk_list_append(&node->istn_glue, &root->istn_value.istnv_node);
        }
        node->istn_parent = root;
    } else {
        /* Dig one more depth. */
        component = in_sysctl_tree_node_key_above_depth(node, root_depth + 1);
        found = 0;
        mk_list_foreach(child, &root->istn_value.istnv_node) {
            child_node = mk_list_entry(child, struct in_sysctl_tree_node, istn_glue);
            ret = strcmp(child_node->istn_key, component);
            if (ret >= 0) {
                if (0 == ret) {
                    found = 1;
                }
                break;
            }
        }
        if (!found) {
            /* Add a new intermediate component. */
            component_node = in_sysctl_tree_node_alloc(NODETYPE_NODE, component);
            if (NULL == component_node) {
                goto err;
            }
            ret = in_sysctl_tree_node_insert(root, component_node);
            if (0 != ret) {
                in_sysctl_tree_node_free(component_node);
                component_node = NULL;
                goto err;
            }
        } else {
            component_node = child_node;
        }
        ret = in_sysctl_tree_node_insert(component_node, node);
        component_node = NULL;
        if (0 != ret) {
            goto err;
        }
    }

    flb_sds_destroy(component);

    return 0;

err:
    flb_sds_destroy(component);

    return -1;
}

#define in_sysctl_tree_node_format_value_alloc(buf)\
    do {\
        (buf) = flb_sds_create_size(0);\
        if (NULL == (buf)) {\
            goto err;\
        }\
    } while (0)
#define in_sysctl_tree_node_format_value_check_result(p)\
    do {\
        if (NULL == (p)) {\
            goto err;\
        }\
    } while (0)

/*
 * Format a node value for logging.
 *
 * The result is not the representation for the precise node reproduction.
 */
static flb_sds_t in_sysctl_tree_node_format_value(
    const struct in_sysctl_tree_node * restrict node)
{
    flb_sds_t buf, p;

    buf = NULL;

    switch (node->istn_type) {
#if 0
    /* TODO. */
    case NODETYPE_DOUBLE:
        break;
#endif

    case NODETYPE_ROOT:
    case NODETYPE_NODE:
        break;

    case NODETYPE_INT:
        in_sysctl_tree_node_format_value_alloc(buf);
        p = flb_sds_printf(&buf, "%d (0x%x)",
            node->istn_value.istnv_int, node->istn_value.istnv_int);
        in_sysctl_tree_node_format_value_check_result(p);
        break;

    case NODETYPE_UINT:
        in_sysctl_tree_node_format_value_alloc(buf);
        p = flb_sds_printf(&buf, "%u (0x%x)",
            node->istn_value.istnv_uint, node->istn_value.istnv_uint);
        in_sysctl_tree_node_format_value_check_result(p);
        break;

    case NODETYPE_LONG:
        in_sysctl_tree_node_format_value_alloc(buf);
        p = flb_sds_printf(&buf, "%ld (0x%lx)",
            node->istn_value.istnv_long, node->istn_value.istnv_long);
        in_sysctl_tree_node_format_value_check_result(p);
        break;

    case NODETYPE_ULONG:
        in_sysctl_tree_node_format_value_alloc(buf);
        p = flb_sds_printf(&buf, "%lu (0x%lx)",
            node->istn_value.istnv_ulong, node->istn_value.istnv_ulong);
        in_sysctl_tree_node_format_value_check_result(p);
        break;

    case NODETYPE_S8:
        in_sysctl_tree_node_format_value_alloc(buf);
        p = flb_sds_printf(&buf, "%d (0x%x)",
            (int)node->istn_value.istnv_i8, (int)node->istn_value.istnv_i8);
        in_sysctl_tree_node_format_value_check_result(p);
        break;

    case NODETYPE_U8:
        in_sysctl_tree_node_format_value_alloc(buf);
        p = flb_sds_printf(&buf, "%u (0x%x)",
            (u_int)node->istn_value.istnv_u8, (u_int)node->istn_value.istnv_u8);
        in_sysctl_tree_node_format_value_check_result(p);
        break;

    case NODETYPE_S16:
        in_sysctl_tree_node_format_value_alloc(buf);
        p = flb_sds_printf(&buf, "%d (0x%x)",
            (int)node->istn_value.istnv_i16, (int)node->istn_value.istnv_i16);
        in_sysctl_tree_node_format_value_check_result(p);
        break;

    case NODETYPE_U16:
        in_sysctl_tree_node_format_value_alloc(buf);
        p = flb_sds_printf(&buf, "%u (0x%x)",
            (u_int)node->istn_value.istnv_u16, (u_int)node->istn_value.istnv_u16);
        in_sysctl_tree_node_format_value_check_result(p);
        break;

    case NODETYPE_S32:
        in_sysctl_tree_node_format_value_alloc(buf);
        p = flb_sds_printf(&buf, "%ld (0x%lx)",
            (long)node->istn_value.istnv_i32, (long)node->istn_value.istnv_i32);
        in_sysctl_tree_node_format_value_check_result(p);
        break;

    case NODETYPE_U32:
        in_sysctl_tree_node_format_value_alloc(buf);
        p = flb_sds_printf(&buf, "%lu (0x%lx)",
            (u_long)node->istn_value.istnv_u32, (u_long)node->istn_value.istnv_u32);
        in_sysctl_tree_node_format_value_check_result(p);
        break;

    case NODETYPE_S64:
        in_sysctl_tree_node_format_value_alloc(buf);
        p = flb_sds_printf(&buf, "%lld (0x%llx)",
            (long long)node->istn_value.istnv_i64, (long long)node->istn_value.istnv_i64);
        in_sysctl_tree_node_format_value_check_result(p);
        break;

    case NODETYPE_U64:
        in_sysctl_tree_node_format_value_alloc(buf);
        p = flb_sds_printf(&buf, "%llu (0x%llx)",
            (unsigned long long)node->istn_value.istnv_u64, (unsigned long long)node->istn_value.istnv_u64);
        in_sysctl_tree_node_format_value_check_result(p);
        break;

    case NODETYPE_STRING:
        in_sysctl_tree_node_format_value_alloc(buf);
        p = flb_sds_printf(&buf, "\"%s\"",
            node->istn_value.istnv_string);
        in_sysctl_tree_node_format_value_check_result(p);
        break;

#if 0
    /* TODO. */
    case NODETYPE_OPAQUE:
        break;
#endif

    default:
        break;
    }

    return buf;

err:
    flb_sds_destroy(buf);
    return NULL;
}

/*
 * Log the content of a node tree.
 */
void in_sysctl_tree_node_log(
    const struct in_sysctl_tree_node * restrict node,
    const struct in_sysctl * restrict ctx)
{
    int depth;
    char *p;
    flb_sds_t value_buf;
    struct mk_list *child;
    struct in_sysctl_tree_node *child_node;

    depth = in_sysctl_tree_node_depth(node) + 1;

    p = node->istn_key;
    if (NULL == p) {
        p = "(root)";
    }
    value_buf = in_sysctl_tree_node_format_value(node);
    if (NULL != value_buf) {
        flb_plg_debug(
            ctx->isc_iscx->iscx_input,
            "%*s: [%s] %s",
            (int)(depth + strlen(p)), p,
            in_sysctl_tree_node_type(node->istn_type),
            value_buf);
        flb_sds_destroy(value_buf);
    } else {
        flb_plg_debug(
            ctx->isc_iscx->iscx_input,
            "%*s: [%s]",
            (int)(depth + strlen(p)), p,
            in_sysctl_tree_node_type(node->istn_type));
    }

    if ((NODETYPE_ROOT == node->istn_type) ||
        (NODETYPE_NODE == node->istn_type)) {
        mk_list_foreach(child, &node->istn_value.istnv_node) {
            child_node = mk_list_entry(
                child, struct in_sysctl_tree_node, istn_glue);
            in_sysctl_tree_node_log(child_node, ctx);
        }
    }

    return;
}

/*
 * Look up the string representing a tree node type.
 */
static const char *in_sysctl_tree_node_type(
    enum in_sysctl_tree_node_type type)
{
    const struct sysctl_tree_node_type_tab *p;

    for (p = in_sysctl_tree_node_types; NULL != p->nt_str; p++) {
        if (type == p->nt_type) {
            return p->nt_str;
        }
    }

    return NULL;
}

/*
 * Pack a string.
 */
static int in_sysctl_tree_node_pack_string(
    const char * restrict str,
    msgpack_packer * restrict msg_pk)
{
    int ret;
    size_t len;

    len = strlen(str);

    ret = msgpack_pack_str(msg_pk, len);
    if (0 != ret) {
        goto err;
    }

    if (0 == len) {
        return 0;
    }

    ret = msgpack_pack_str_body(msg_pk, str, len);
    if (0 != ret) {
        goto err;
    }

    return 0;

err:
    return -1;
}

/*
 * Count the leaves under a tree node.
 */
static size_t in_sysctl_tree_count_leaves(
    const struct in_sysctl_tree_node * restrict node)
{
    size_t num;
    struct mk_list *child;
    struct in_sysctl_tree_node *child_node;

    switch (node->istn_type) {
    case NODETYPE_ROOT:
    case NODETYPE_NODE:
        num = 0;
        mk_list_foreach(child, &node->istn_value.istnv_node) {
            child_node = mk_list_entry(child, struct in_sysctl_tree_node, istn_glue);
            num += in_sysctl_tree_count_leaves(child_node);
        }

        break;

#if 0
    /* TODO. */
    case NODETYPE_OPAQUE:
        break;
#endif

    default:
        num = 1;

        break;
    }

    return num;
}

#define in_sysctl_tree_node_pack_value_check_result(ret, node, func)\
    do {\
        if (0 != (ret)) {\
            flb_plg_error(\
                ctx->isc_iscx->iscx_input,\
                "%s(%s) failed",\
                #func, (node)->istn_key);\
            goto err;\
        }\
    } while (0)

/*
 * Pack a node by msgpack.
 *
 * The node key is packed by its parent.
 */
int in_sysctl_tree_node_pack(
    const struct in_sysctl * restrict ctx,
    const struct in_sysctl_tree_node * restrict node,
    msgpack_packer * restrict msg_pk)
{
    int ret;
    const char *p;
    struct mk_list *child;
    struct in_sysctl_tree_node *child_node;

    switch (ctx->isc_iscc->iscc_content) {
    case ISC_CNT_VALUES:
        ret = in_sysctl_tree_node_pack_value(ctx, node, msg_pk);
        break;

    case ISC_CNT_ES_EXPLICIT_MAPPING:
        ret = in_sysctl_tree_node_pack_es_explicit_mapping(ctx, node, msg_pk);
        break;
    }
    if (0 != ret) {
        goto err;
    }

    switch (node->istn_type) {
    case NODETYPE_ROOT:
    case NODETYPE_NODE:
        mk_list_foreach(child, &node->istn_value.istnv_node) {
            child_node = mk_list_entry(child, struct in_sysctl_tree_node, istn_glue);
            if ((ISC_FMT_NESTED == ctx->isc_iscc->iscc_format) ||
                ((NODETYPE_ROOT != child_node->istn_type) &&
                (NODETYPE_NODE != child_node->istn_type) /* TODO: &&
                (NODETYPE_OPAQUE != child_node->istn_type)*/)) {
                p = NULL;
                if ((ISC_FMT_NESTED == ctx->isc_iscc->iscc_format) &&
                    !ctx->isc_iscc->iscc_nested_oid_fullname) {
                    p = strrchr(child_node->istn_key, KEY_DELIMITER);
                }
                if (NULL == p) {
                    p = child_node->istn_key;
                } else {
                    p++;
                }
                ret = in_sysctl_tree_node_pack_string(p, msg_pk);
                in_sysctl_tree_node_pack_value_check_result(
                    ret, node, in_sysctl_tree_node_pack_string);
            }
            ret = in_sysctl_tree_node_pack(ctx, child_node, msg_pk);
            in_sysctl_tree_node_pack_value_check_result(
                ret, node, in_sysctl_tree_node_pack);
        }

        break;

    default:
        break;
    }

    return 0;

err:
    return -1;
}

/*
 * Count the children of a node, taking account of the format.
 */
static int in_sysctl_tree_node_count_children(
    const struct in_sysctl * restrict ctx,
    const struct in_sysctl_tree_node * restrict node)
{
    int children_num;

    children_num = -1;

    switch (node->istn_type) {
    case NODETYPE_ROOT:
    case NODETYPE_NODE:
        if (ISC_FMT_NESTED == ctx->isc_iscc->iscc_format) {
            /* Nested; count the immediate children. */
            children_num = mk_list_size(
                /* XXX const */(struct mk_list *)&node->istn_value.istnv_node);
        } else if (NODETYPE_ROOT == node->istn_type) {
            /* Flat; count all leaves. */
            children_num = in_sysctl_tree_count_leaves(node);
        }

        break;

    default:
        break;
    }

    return children_num;
}

/*
 * Pack the value of a node by msgpack.
 */
static int in_sysctl_tree_node_pack_value(
    const struct in_sysctl * restrict ctx,
    const struct in_sysctl_tree_node * restrict node,
    msgpack_packer * restrict msg_pk)
{
    int ret, children_num;

    switch (node->istn_type) {
    case NODETYPE_ROOT:
    case NODETYPE_NODE:
        children_num = in_sysctl_tree_node_count_children(ctx, node);
        if (-1 != children_num) {
            ret = msgpack_pack_map(msg_pk, children_num);
            in_sysctl_tree_node_pack_value_check_result(
                ret, node, msgpack_pack_map);
        }
        /* The children are packed by in_sysctl_tree_node_pack(). */
        break;

    case NODETYPE_INT:
        ret = msgpack_pack_int(msg_pk, node->istn_value.istnv_int);
        in_sysctl_tree_node_pack_value_check_result(
            ret, node, msgpack_pack_int);
        break;

    case NODETYPE_UINT:
        ret = msgpack_pack_unsigned_int(msg_pk, node->istn_value.istnv_uint);
        in_sysctl_tree_node_pack_value_check_result(
            ret, node, msgpack_pack_unsigned_int);
        break;

    case NODETYPE_LONG:
        ret = msgpack_pack_long(msg_pk, node->istn_value.istnv_long);
        in_sysctl_tree_node_pack_value_check_result(
            ret, node, msgpack_pack_long);
        break;

    case NODETYPE_ULONG:
        ret = msgpack_pack_unsigned_long(msg_pk, node->istn_value.istnv_ulong);
        in_sysctl_tree_node_pack_value_check_result(
            ret, node, msgpack_pack_unsigned_long);
        break;

    case NODETYPE_S8:
        ret = msgpack_pack_int8(msg_pk, node->istn_value.istnv_i8);
        in_sysctl_tree_node_pack_value_check_result(
            ret, node, msgpack_pack_int8);
        break;

    case NODETYPE_U8:
        ret = msgpack_pack_uint8(msg_pk, node->istn_value.istnv_u8);
        in_sysctl_tree_node_pack_value_check_result(
            ret, node, msgpack_pack_uint8);
        break;

    case NODETYPE_S16:
        ret = msgpack_pack_int16(msg_pk, node->istn_value.istnv_i16);
        in_sysctl_tree_node_pack_value_check_result(
            ret, node, msgpack_pack_int16);
        break;

    case NODETYPE_U16:
        ret = msgpack_pack_uint16(msg_pk, node->istn_value.istnv_u16);
        in_sysctl_tree_node_pack_value_check_result(
            ret, node, msgpack_pack_uint16);
        break;

    case NODETYPE_S32:
        ret = msgpack_pack_int32(msg_pk, node->istn_value.istnv_i32);
        in_sysctl_tree_node_pack_value_check_result(
            ret, node, msgpack_pack_int32);
        break;

    case NODETYPE_U32:
        ret = msgpack_pack_uint32(msg_pk, node->istn_value.istnv_u32);
        in_sysctl_tree_node_pack_value_check_result(
            ret, node, msgpack_pack_uint32);
        break;

    case NODETYPE_S64:
        ret = msgpack_pack_int64(msg_pk, node->istn_value.istnv_i64);
        in_sysctl_tree_node_pack_value_check_result(
            ret, node, msgpack_pack_int64);
        break;

    case NODETYPE_U64:
        ret = msgpack_pack_uint64(msg_pk, node->istn_value.istnv_u64);
        in_sysctl_tree_node_pack_value_check_result(
            ret, node, msgpack_pack_uint64);
        break;

#if 0
    /* TODO. */
    case NODETYPE_DOUBLE:
        ret = msgpack_pack_double(msg_pk, node->istn_value.istnv_double);
        in_sysctl_tree_node_pack_value_check_result(
            ret, node, msgpack_pack_double);
        break;
#endif

    case NODETYPE_STRING:
        ret = in_sysctl_tree_node_pack_string(node->istn_value.istnv_string, msg_pk);
        in_sysctl_tree_node_pack_value_check_result(
            ret, node, in_sysctl_tree_node_pack_string);
        break;

#if 0
    /* TODO. */
    case NODETYPE_OPAQUE:
        break;
#endif
    }

    return 0;

err:
    return -1;
}

#define in_sysctl_tree_node_pack_type_check_result(ret, type, func)\
    do {\
        if (0 != (ret)) {\
            flb_plg_error(\
                ctx->isc_iscx->iscx_input,\
                "%s(%s) failed",\
                #func, (type));\
            goto err;\
        }\
    } while (0)

/*
 * Pack the Elasticsearch explicit mapping of a scalar type by msgpack.
 */
static int in_sysctl_tree_node_pack_es_explicit_mapping_scalar(
    const struct in_sysctl * restrict ctx,
    const char *type,
    msgpack_packer * restrict msg_pk)
{
    int ret;

    ret = msgpack_pack_map(msg_pk, 1);
    in_sysctl_tree_node_pack_type_check_result(
        ret, type, msgpack_pack_map);

    ret = in_sysctl_tree_node_pack_string(ES_EXPLICIT_MAPPING_TYPE, msg_pk);
    in_sysctl_tree_node_pack_type_check_result(
        ret, type, in_sysctl_tree_node_pack_string);
    ret = in_sysctl_tree_node_pack_string(type, msg_pk);
    in_sysctl_tree_node_pack_type_check_result(
        ret, type, in_sysctl_tree_node_pack_string);

    return 0;

err:
    return -1;
}

/*
 * Pack the Elasticsearch explicit mapping of a node by msgpack.
 */
static int in_sysctl_tree_node_pack_es_explicit_mapping(
    const struct in_sysctl * restrict ctx,
    const struct in_sysctl_tree_node * restrict node,
    msgpack_packer * restrict msg_pk)
{
    int ret, children_num;

    switch (node->istn_type) {
    case NODETYPE_ROOT:
    case NODETYPE_NODE:
        children_num = in_sysctl_tree_node_count_children(ctx, node);
        if (-1 != children_num) {
            if (NODETYPE_NODE == node->istn_type) {
                /*
                 * The explicit mapping is required for the nested format node only.
                 */
                ret = msgpack_pack_map(msg_pk, 2);
                in_sysctl_tree_node_pack_value_check_result(
                    ret, node, msgpack_pack_map);

                ret = in_sysctl_tree_node_pack_string(ES_EXPLICIT_MAPPING_TYPE, msg_pk);
                in_sysctl_tree_node_pack_value_check_result(
                    ret, node, in_sysctl_tree_node_pack_string);
                ret = in_sysctl_tree_node_pack_string("nested", msg_pk);
                in_sysctl_tree_node_pack_value_check_result(
                    ret, node, in_sysctl_tree_node_pack_string);

                ret = in_sysctl_tree_node_pack_string(ES_EXPLICIT_MAPPING_PROPERTIES, msg_pk);
                in_sysctl_tree_node_pack_value_check_result(
                    ret, node, in_sysctl_tree_node_pack_string);
            }

            ret = msgpack_pack_map(msg_pk, children_num);
            in_sysctl_tree_node_pack_value_check_result(
                ret, node, msgpack_pack_map);
        } else {
            ret = 0;
        }

        break;

    case NODETYPE_INT:
        ret = in_sysctl_tree_node_pack_es_explicit_mapping_scalar(
            ctx,
            "integer",
            msg_pk);
        break;

    case NODETYPE_LONG:
        ret = in_sysctl_tree_node_pack_es_explicit_mapping_scalar(
            ctx,
            "long",
            msg_pk);
        break;

    case NODETYPE_S8:
        ret = in_sysctl_tree_node_pack_es_explicit_mapping_scalar(
            ctx,
            "byte",
            msg_pk);
        break;

    case NODETYPE_S16:
        ret = in_sysctl_tree_node_pack_es_explicit_mapping_scalar(
            ctx,
            "short",
            msg_pk);
        break;

    case NODETYPE_S32:
        ret = in_sysctl_tree_node_pack_es_explicit_mapping_scalar(
            ctx,
            "integer",
            msg_pk);
        break;

    case NODETYPE_S64:
        ret = in_sysctl_tree_node_pack_es_explicit_mapping_scalar(
            ctx,
            "long",
            msg_pk);
        break;

    case NODETYPE_UINT:
    case NODETYPE_ULONG:
    case NODETYPE_U8:
    case NODETYPE_U16:
    case NODETYPE_U32:
    case NODETYPE_U64:
        /*
         * As of Elasticsearch 8.11, unsigned_long is the sole type for an
         * unsigned integer.
         */
        ret = in_sysctl_tree_node_pack_es_explicit_mapping_scalar(
            ctx,
            "unsigned_long",
            msg_pk);
        break;

#if 0
    /* TODO. */
    case NODETYPE_DOUBLE:
        ret = in_sysctl_tree_node_pack_es_explicit_mapping_scalar(
            ctx,
            "double",
            msg_pk);
        break;
#endif

    case NODETYPE_STRING:
        /* Store primarily as a keyword and additionally as a text. */
        ret = msgpack_pack_map(msg_pk, 2);
        in_sysctl_tree_node_pack_value_check_result(
            ret, node, msgpack_pack_map);

        ret = in_sysctl_tree_node_pack_string(ES_EXPLICIT_MAPPING_TYPE, msg_pk);
        in_sysctl_tree_node_pack_value_check_result(
            ret, node, in_sysctl_tree_node_pack_string);
        ret = in_sysctl_tree_node_pack_string("keyword", msg_pk);
        in_sysctl_tree_node_pack_value_check_result(
            ret, node, in_sysctl_tree_node_pack_string);

        ret = in_sysctl_tree_node_pack_string(ES_EXPLICIT_MAPPING_FIELDS, msg_pk);
        in_sysctl_tree_node_pack_value_check_result(
            ret, node, in_sysctl_tree_node_pack_string);
        ret = msgpack_pack_map(msg_pk, 1);
        in_sysctl_tree_node_pack_value_check_result(
            ret, node, msgpack_pack_map);

        ret = in_sysctl_tree_node_pack_string(ES_EXPLICIT_MAPPING_MULTIVALUE_TEXT, msg_pk);
        in_sysctl_tree_node_pack_value_check_result(
            ret, node, in_sysctl_tree_node_pack_string);
        ret = in_sysctl_tree_node_pack_es_explicit_mapping_scalar(
            ctx,
            "text",
            msg_pk);
        in_sysctl_tree_node_pack_value_check_result(
            ret, node, in_sysctl_tree_node_pack_es_explicit_mapping_scalar);
        break;

#if 0
    /* TODO. */
    case NODETYPE_OPAQUE:
        ret = 0;
        break;
#endif
    }

    return ret;

err:
    return -1;
}
