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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <sys/sysctl.h>
#include <time.h>

#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>

#include <msgpack.h>

#include "in_sysctl.h"
#include "in_sysctl_tree.h"

#define CTL_EXTRANAME   (2)
#define BUF_LEN         (256)

/*
 * The OID with the extra spaces for the sysctl(3) commands.
 */
struct in_sysctl_oid {
    /* The OID. */
    int     isco_oid[CTL_MAXNAME + CTL_EXTRANAME];
    /*
     * The valid names in isco_oid.
     * (0 <= isco_num <= CTL_MAXNAME + CTL_EXTRANAME)
     */
    size_t  isco_num;
};

/*
 * The buffer of the sysctl(3) value.
 *
 * This structure and the value buffer are meant to be allocated as a single
 * memory block.  The value is stored in the buffer starting from iscv_value.
 *
 * Also, the content in the value buffer should be accessed by sysctl(3) only.
 * For the access by the application, copy it to a separate variable allocated
 * with the appropriate alignement.
 */
struct in_sysctl_value {
    /* The allocated value size. */
    size_t  iscv_buflen;
    /* The valid value size. (iscv_validlen <= iscv_buflen) */
    size_t  iscv_validlen;
    /* The value buffer. */
    uint8_t iscv_value[0];
};
#define in_sysctl_value_buffer(value) ((void *)((value)->iscv_value))
#define in_sysctl_value_buffer_const(value) ((const void *)((value)->iscv_value))

static int in_sysctl_oid_format(
    const struct in_sysctl_oid * restrict oid,
    char * restrict buf,
    size_t len);
static int in_sysctl_name_to_oid(
    const char * restrict name,
    struct in_sysctl_oid * restrict oid);
static int in_sysctl_oid_prefix(
    const struct in_sysctl_oid * restrict oid,
    const struct in_sysctl_oid * restrict oid_prefix);
static int in_sysctl_make_command(
    int cmd,
    const struct in_sysctl_oid * restrict oid_arg,
    struct in_sysctl_oid * restrict oid_cmd);
static int in_sysctl_oid_to_name(
    const struct in_sysctl_oid * restrict oid,
    char * restrict buf,
    size_t len);
static int in_sysctl_oid_kind_format(
    const struct in_sysctl_oid * restrict oid,
    u_int * restrict kind,
    char * restrict fmt_buf,
    size_t fmt_len);
static int in_sysctl_oid_next(
    const struct in_sysctl_oid * restrict oid,
    struct in_sysctl_oid * restrict oid_next);
static int in_sysctl_collect_by_oid(
    const struct in_sysctl *ctx,
    const struct in_sysctl_oid * restrict oid,
    struct in_sysctl_tree_node * restrict root,
    struct in_sysctl_value * restrict * restrict valuep);
static struct in_sysctl_value *in_sysctl_value_alloc(void);
static void in_sysctl_value_clear(struct in_sysctl_value *value);
static int in_sysctl_value_resize(
    struct in_sysctl_value * restrict * restrict valuep,
    size_t len);
static void in_sysctl_value_free(struct in_sysctl_value *value);
static int in_sysctl_collect_value(
    const struct in_sysctl_oid * restrict oid,
    struct in_sysctl_value * restrict * restrict valuep);
static size_t in_sysctl_type_integer_size(int type);

/*
 * Collect the sysctl(3) value of the given string name.
 */
int in_sysctl_collect_by_name(
    const struct in_sysctl * restrict ctx,
    const char * restrict name,
    struct msgpack_packer * restrict msg_pk)
{
    int ret;
    char buf[BUF_LEN], *errbufp;
    struct in_sysctl_oid oid;
    struct in_sysctl_tree_node *root;
    struct in_sysctl_value * restrict value;

    value = NULL;

    ret = in_sysctl_name_to_oid(name, &oid);
    if (0 != ret) {
#ifdef FLB_HAVE_GNU_STRERROR_R
        errbufp = strerror_r(errno, buf, sizeof(buf));
#else
        strerror_r(errno, buf, sizeof(buf));
        errbufp = buf;
#endif
        flb_plg_error(
            ctx->isc_iscx->iscx_input,
            "in_sysctl_name_to_oid(%s): %s",
            name, errbufp);
        goto err;
    }

    root = in_sysctl_tree_node_alloc_root();
    if (NULL == root) {
        goto err;
    }

    value = in_sysctl_value_alloc();
    if (NULL == value) {
#ifdef FLB_HAVE_GNU_STRERROR_R
        errbufp = strerror_r(errno, buf, sizeof(buf));
#else
        strerror_r(errno, buf, sizeof(buf));
        errbufp = buf;
#endif
        flb_plg_error(ctx->isc_iscx->iscx_input,
            "in_sysctl_value_alloc: %s",
            errbufp);
        goto err;
    }

    ret = in_sysctl_collect_by_oid(ctx, &oid, root, &value);
    if (0 != ret) {
        goto err;
    }

    /* XXX For debugging. */
    in_sysctl_tree_node_log(root, ctx);

    ret = in_sysctl_tree_node_pack(ctx, root, msg_pk);
    if (0 != ret) {
        goto err;
    }

    in_sysctl_tree_node_free(root);
    in_sysctl_value_free(value);

    return ret;

err:
    in_sysctl_value_free(value);
    return -1;
}

/*
 * Format an OID into a string.
 */
static int in_sysctl_oid_format(
    const struct in_sysctl_oid * restrict oid,
    char * restrict buf,
    size_t len)
{
    int i, written;
    char *origbuf;

    origbuf = buf;

    for (i = 0; (len > 1) && (i < oid->isco_num); i++) {
        written = snprintf(buf, len, "%d", oid->isco_oid[i]);
        buf += written;
        len -= written;
        if (len <= 1) {
            goto err;
        }

        if ((i + 1) < oid->isco_num) {
            strcpy(buf, ".");
            buf++;
            len--;
            if (len <= 1) {
                goto err;
            }
        }
    }

    return 0;

err:
    *origbuf = '\0';
    return (-1);
}

/*
 * Get the OID of a name string.
 */
static int in_sysctl_name_to_oid(
    const char * restrict name,
    struct in_sysctl_oid * restrict oid)
{
    oid->isco_num = sizeof(oid->isco_oid) / sizeof(*oid->isco_oid) - CTL_EXTRANAME;
    return sysctlnametomib(name, oid->isco_oid, &oid->isco_num);
}

/*
 * Test if an OID has the given prefix.
 */
static int in_sysctl_oid_prefix(
    const struct in_sysctl_oid * restrict oid,
    const struct in_sysctl_oid * restrict oid_prefix)
{
    if (oid->isco_num < oid_prefix->isco_num) {
        return 0;
    }

    return (0 == memcmp(
        oid->isco_oid,
        oid_prefix->isco_oid,
        oid_prefix->isco_num * sizeof(*oid_prefix->isco_oid)));
}

/*
 * Make the sysctl(3) command OID with the given argument.
 */
static int in_sysctl_make_command(
    int cmd,
    const struct in_sysctl_oid * restrict oid_arg,
    struct in_sysctl_oid * restrict oid_cmd)
{
    if (oid_arg->isco_num > CTL_MAXNAME) {
        errno = EINVAL;
        goto err;
    }
    oid_cmd->isco_oid[0] = CTL_SYSCTL;
    oid_cmd->isco_oid[1] = cmd;
    memcpy(&oid_cmd->isco_oid[CTL_EXTRANAME],
        oid_arg->isco_oid,
        oid_arg->isco_num * sizeof(*oid_arg->isco_oid));
    oid_cmd->isco_num = CTL_EXTRANAME + oid_arg->isco_num;

    return 0;

err:
    return -1;
}

/*
 * Get the name string of an OID.
 */
static int in_sysctl_oid_to_name(
    const struct in_sysctl_oid * restrict oid,
    char * restrict buf,
    size_t len)
{
    int ret;
    struct in_sysctl_oid oid_cmd;

    ret = in_sysctl_make_command(CTL_SYSCTL_NAME, oid, &oid_cmd);
    if (0 != ret) {
        goto err;
    }

    ret = sysctl(oid_cmd.isco_oid, oid_cmd.isco_num, buf, &len, 0, 0);
    if (0 != ret) {
        goto err;
    }

    return 0;

err:
    return -1;
}

/*
 * Get the value kind and format of an OID.
 */
static int in_sysctl_oid_kind_format(
    const struct in_sysctl_oid * restrict oid,
    u_int * restrict kind,
    char * restrict fmt_buf,
    size_t fmt_len)
{
    int ret;
    char buf[sizeof(int) + fmt_len];
    size_t len;
    struct in_sysctl_oid oid_cmd;

    ret = in_sysctl_make_command(CTL_SYSCTL_OIDFMT, oid, &oid_cmd);
    if (0 != ret) {
        goto err;
    }

    len = sizeof(buf);
    ret = sysctl(oid_cmd.isco_oid, oid_cmd.isco_num, buf, &len, 0, 0);
    if (0 != ret) {
        goto err;
    }

    if (NULL != kind) {
        *kind = *(u_int *)buf;
    }

    if (NULL != fmt_buf) {
        strncpy(fmt_buf, &buf[sizeof(int)], fmt_len - 1);
        fmt_buf[fmt_len - 1] = '\0';
    }

    return 0;

err:
    return -1;
}

/*
 * Get the next OID, skipping the non-leaf nodes.
 */
static int in_sysctl_oid_next(
    const struct in_sysctl_oid * restrict oid,
    struct in_sysctl_oid * restrict oid_next)
{
    int ret;
    struct in_sysctl_oid oid_cmd;

    ret = in_sysctl_make_command(CTL_SYSCTL_NEXT, oid, &oid_cmd);
    if (0 != ret) {
        goto err;
    }

    memset(oid_next->isco_oid, 0, sizeof(oid_next->isco_oid));
    oid_next->isco_num = CTL_MAXNAME;
    ret = sysctl(
        oid_cmd.isco_oid,
        oid_cmd.isco_num,
        oid_next->isco_oid,
        &oid_next->isco_num,
        0, 0);
    if (0 != ret) {
        goto err;
    }

    for (oid_next->isco_num = 0;
        (oid_next->isco_num < sizeof(oid_next->isco_oid) /
            sizeof(*oid_next->isco_oid)) &&
            (0 != oid_next->isco_oid[oid_next->isco_num]);
        oid_next->isco_num++);

    return 0;

err:
    return -1;
}

/*
 * Collect the sysctl(3) value of the given OID.
 *
 * The caller is responsible to provide the sysctl(3) value buffer so that it
 * can be reused during the iteration.
 */
static int in_sysctl_collect_by_oid(
    const struct in_sysctl *ctx,
    const struct in_sysctl_oid * restrict oid,
    struct in_sysctl_tree_node * restrict root,
    struct in_sysctl_value * restrict * restrict valuep)
{
    int ret;
    u_int kind;
    char buf[BUF_LEN], *errbufp;
    char namebuf[BUF_LEN], oidbuf[BUF_LEN], formatbuf[BUF_LEN], nextnamebuf[BUF_LEN];
    size_t int_size;
    struct in_sysctl_oid oid_this, oid_next;
    struct in_sysctl_tree_node *node;

    ret = in_sysctl_oid_to_name(oid, namebuf, sizeof(namebuf));
    if (0 != ret) {
        /* TODO: the error log. */
        goto err;
    }

    ret = in_sysctl_oid_format(oid, oidbuf, sizeof(oidbuf));
    if (0 != ret) {
        /* TODO: the error log. */
        goto err;
    }

    ret = in_sysctl_oid_kind_format(oid, &kind, formatbuf, sizeof(formatbuf));
    if (0 != ret) {
        /* TODO: the error log. */
        goto err;
    }

    flb_plg_debug(
        ctx->isc_iscx->iscx_input,
        "name = %s, oid = %s, kind = 0x%x, format = %s.",
        namebuf,
        oidbuf,
        kind,
        formatbuf);

    node = in_sysctl_tree_node_alloc(kind & CTLTYPE, namebuf);
    if (NULL == node) {
        /* TODO: the error log. */
        goto err;
    }
    ret = in_sysctl_tree_node_insert(root, node);
    if (0 != ret) {
        /* TODO: the error log. */
        in_sysctl_tree_node_free(node);
        node = NULL;
        goto err;
    }

    if (CTLTYPE_NODE == (kind & CTLTYPE)) {
        /*
         * CTLTYPE_NODE is handled separately; it does not require reading the
         * value but does dig down to its children.
         */
        oid_this = *oid;

        for (;; oid_this = oid_next) {
            ret = in_sysctl_oid_next(&oid_this, &oid_next);
            if (0 != ret) {
                if (ENOENT == errno) {
                    break;
                }
#ifdef FLB_HAVE_GNU_STRERROR_R
                errbufp = strerror_r(errno, buf, sizeof(buf));
#else
                strerror_r(errno, buf, sizeof(buf));
                errbufp = buf;
#endif
                flb_plg_error(
                    ctx->isc_iscx->iscx_input,
                    "in_sysctl_oid_next(%s): %s",
                    namebuf, errbufp);
                goto err;
            }

            if (!in_sysctl_oid_prefix(&oid_next, oid)) {
                break;
            }

            ret = in_sysctl_oid_to_name(&oid_next, nextnamebuf, sizeof(nextnamebuf));
            if (0 != ret) {
                /* TODO: the error log. */
                goto err;
            }

            ret = in_sysctl_collect_by_oid(
                ctx,
                &oid_next,
                root,
                valuep);
            if (0 != ret) {
#ifdef FLB_HAVE_GNU_STRERROR_R
                errbufp = strerror_r(errno, buf, sizeof(buf));
#else
                strerror_r(errno, buf, sizeof(buf));
                errbufp = buf;
#endif
                flb_plg_error(
                    ctx->isc_iscx->iscx_input,
                    "in_sysctl_collect_by_oid(%s): %s",
                    nextnamebuf, errbufp);
                goto err;
            }
        }

        return 0;
    }

    ret = in_sysctl_collect_value(oid, valuep);
    if (0 != ret) {
        /* TODO: the error log. */
        goto err;
    }

    int_size = in_sysctl_type_integer_size(kind & CTLTYPE);
    if ((size_t)-1 != int_size) {
        /* An integer type can be simply copied in general. */
        if (int_size != (*valuep)->iscv_validlen) {
            flb_plg_error(
                ctx->isc_iscx->iscx_input,
                "in_sysctl_collect_by_oid(%s): integer size mismatch, %zu != %zu",
                namebuf, int_size, (*valuep)->iscv_validlen);
            goto err;
        }
        memcpy(
            &node->istn_value,
            in_sysctl_value_buffer_const(*valuep),
            int_size);

        /* TODO: Handle the "K" format, the scaled fixed point. */

        return 0;
    }

    if (NODETYPE_STRING == (kind & CTLTYPE)) {
        /* Keep the copy of the string. */
        node->istn_value.istnv_string = flb_sds_create_len(
            in_sysctl_value_buffer_const(*valuep),
            (*valuep)->iscv_validlen);

        return 0;
    }

    return 0;

err:
    return -1;
}

/*
 * Allocate a new sysctl(3) value buffer with the initial size for int, which
 * is hopefully reasonable.
 */
static struct in_sysctl_value *in_sysctl_value_alloc(void)
{
    struct in_sysctl_value *value;
    static const size_t len = sizeof(int);

    value = flb_malloc(sizeof(*value) + len);
    if (NULL == value) {
        goto err;
    }

    value->iscv_buflen = len;
    in_sysctl_value_clear(value);

    return value;

err:
    flb_free(value);
    return NULL;
}

/*
 * Clear a sysctl(3) value buffer and make all of the allocated buffer valid.
 */
static void in_sysctl_value_clear(struct in_sysctl_value *value)
{
    memset(in_sysctl_value_buffer(value), 0, value->iscv_buflen);
    value->iscv_validlen = value->iscv_buflen;
}

/*
 * Resize a sysctl(3) value buffer to the given size.
 *
 * This implementation reallocates the value buffer whenever its size is
 * changed, assuming the value buffer is only expanded.  That is both
 * sufficient and efficient for sysctl(3).
 */
static int in_sysctl_value_resize(
    struct in_sysctl_value * restrict * restrict valuep,
    size_t len)
{
    struct in_sysctl_value *newvalue;

    if (len == (*valuep)->iscv_buflen) {
        return 0;
    }

    newvalue = flb_realloc(*valuep, sizeof(**valuep) + len);
    if (NULL == newvalue) {
        goto err;
    }

    newvalue->iscv_buflen = len;
    if (newvalue->iscv_validlen > newvalue->iscv_buflen) {
        newvalue->iscv_validlen = newvalue->iscv_buflen;
    }

    *valuep = newvalue;

    return 0;

err:
    return -1;
}

/*
 * Free a sysctl(3) value buffer.
 */
static void in_sysctl_value_free(struct in_sysctl_value *value)
{
    flb_free(value);
}

/*
 * Read the value of a sysctl(3) OID.
 *
 * The value buffer may be resized up to twice the required size as returned by
 * sysctl(3) with the ENOMEM error.
 */
static int in_sysctl_collect_value(
    const struct in_sysctl_oid * restrict oid,
    struct in_sysctl_value * restrict * restrict valuep)
{
    int ret;

    for (;;) {
        in_sysctl_value_clear(*valuep);
        ret = sysctl(
            oid->isco_oid, oid->isco_num,
            in_sysctl_value_buffer(*valuep), &((*valuep)->iscv_validlen),
            NULL, 0);
        if (0 == ret) {
            break;
        }
        if (ENOMEM != errno) {
            goto err;
        }
        ret = in_sysctl_value_resize(valuep, 2 * (*valuep)->iscv_validlen);
        if (0 != ret) {
            goto err;
        }
    }

    return 0;

err:
    return -1;
}

/*
 * Return the type size for an integer type.
 *
 * Return (size_t)-1 if the type is not an integer.
 */
static size_t in_sysctl_type_integer_size(int type)
{
    switch (type) {
    case CTLTYPE_INT:
    case CTLTYPE_UINT:
        return sizeof(int);

    case CTLTYPE_LONG:
    case CTLTYPE_ULONG:
        return sizeof(long);

    case CTLTYPE_S8:
    case CTLTYPE_U8:
        return sizeof(int8_t);

    case CTLTYPE_S16:
    case CTLTYPE_U16:
        return sizeof(int16_t);

    case CTLTYPE_S32:
    case CTLTYPE_U32:
        return sizeof(int32_t);

    case CTLTYPE_S64:
    case CTLTYPE_U64:
        return sizeof(int64_t);

    default:
        break;
    }

    return (size_t)-1;
}
