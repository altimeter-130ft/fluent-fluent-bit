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

#ifndef FLB_IN_SYSCTL_TREE_H
#define FLB_IN_SYSCTL_TREE_H

struct in_sysctl_tree_node;

/*
 * The sysctl(3) tree node types, mostly taken from the sysctl(3) value types.
 */
enum in_sysctl_tree_node_type {
    /* TODO. */
    /* NODETYPE_DOUBLE = -2, */
    NODETYPE_ROOT   = -1,
    NODETYPE_NODE   = CTLTYPE_NODE,
    NODETYPE_INT    = CTLTYPE_INT,
    NODETYPE_STRING = CTLTYPE_STRING,
    NODETYPE_S64    = CTLTYPE_S64,
    /* TODO. */
    /* NODETYPE_OPAQUE  = CTLTYPE_OPAQUE, */
    NODETYPE_UINT   = CTLTYPE_UINT,
    NODETYPE_LONG   = CTLTYPE_LONG,
    NODETYPE_ULONG  = CTLTYPE_ULONG,
    NODETYPE_U64    = CTLTYPE_U64,
    NODETYPE_U8     = CTLTYPE_U8,
    NODETYPE_U16    = CTLTYPE_U16,
    NODETYPE_S8     = CTLTYPE_S8,
    NODETYPE_S16    = CTLTYPE_S16,
    NODETYPE_S32    = CTLTYPE_S32,
    NODETYPE_U32    = CTLTYPE_U32,
};

/*
 * The sysctl(3) tree node value.
 */
union in_sysctl_tree_node_value {
    /* NODETYPE_ROOT and NODETYPE_NODE. */
    struct mk_list  istnv_node;
    /* NODETYPE_INT. */
    int             istnv_int;
    /* NODETYPE_STRING. */
    flb_sds_t       istnv_string;
    /* NODETYPE_S64. */
    int64_t         istnv_i64;
    /* TODO: NODETYPE_OPAQUE. */
    /* void         *istnv_opaque */
    /* NODETYPE_UINT. */
    u_int           istnv_uint;
    /* NODETYPE_LONG. */
    long            istnv_long;
    /* NODETYPE_ULONG. */
    u_long          istnv_ulong;
    /* NODETYPE_U64. */
    uint64_t        istnv_u64;
    /* NODETYPE_U8. */
    uint8_t         istnv_u8;
    /* NODETYPE_U16. */
    uint16_t        istnv_u16;
    /* NODETYPE_S8. */
    int8_t          istnv_i8;
    /* NODETYPE_S16. */
    int16_t         istnv_i16;
    /* NODETYPE_S32. */
    int32_t         istnv_i32;
    /* NODETYPE_U32. */
    uint32_t        istnv_u32;
};

/*
 * The sysctl(3) tree node.
 */
struct in_sysctl_tree_node
{
    /* The glue of the siblings. */
    struct mk_list                      istn_glue;
    /* The parent. */
    struct in_sysctl_tree_node          *istn_parent;
    /* The node name. */
    flb_sds_t                           istn_key;
    /* The node type. */
    enum in_sysctl_tree_node_type       istn_type;
    /* The node values. */
    union in_sysctl_tree_node_value     istn_value;
};

#define in_sysctl_tree_node_alloc_root()    (in_sysctl_tree_node_alloc(NODETYPE_ROOT, NULL))

struct in_sysctl_tree_node *in_sysctl_tree_node_alloc(
    int type,
    const char *key);
void in_sysctl_tree_node_free(struct in_sysctl_tree_node *node);
int in_sysctl_tree_node_insert(
    struct in_sysctl_tree_node * restrict root,
    struct in_sysctl_tree_node * restrict node);
void in_sysctl_tree_node_log(
    const struct in_sysctl_tree_node * restrict node,
    const struct in_sysctl * restrict ctx);
int in_sysctl_tree_node_pack(
    const struct in_sysctl * restrict ctx,
    const struct in_sysctl_tree_node * restrict node,
    msgpack_packer * restrict msg_pk);

#endif
