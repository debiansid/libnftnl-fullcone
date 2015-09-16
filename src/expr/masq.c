/*
 * (C) 2014 by Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>

#include <linux/netfilter/nf_tables.h>

#include "internal.h"
#include <libmnl/libmnl.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

struct nftnl_expr_masq {
	uint32_t	flags;
};

static int
nftnl_expr_masq_set(struct nftnl_expr *e, uint16_t type,
		       const void *data, uint32_t data_len)
{
	struct nftnl_expr_masq *masq = nftnl_expr_data(e);

	switch (type) {
	case NFTNL_EXPR_MASQ_FLAGS:
		masq->flags = *((uint32_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nftnl_expr_masq_get(const struct nftnl_expr *e, uint16_t type,
		       uint32_t *data_len)
{
	struct nftnl_expr_masq *masq = nftnl_expr_data(e);

	switch (type) {
	case NFTNL_EXPR_MASQ_FLAGS:
		*data_len = sizeof(masq->flags);
		return &masq->flags;
	}
	return NULL;
}

static int nftnl_expr_masq_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_MASQ_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case NFTA_MASQ_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_expr_masq_build(struct nlmsghdr *nlh, struct nftnl_expr *e)
{
	struct nftnl_expr_masq *masq = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_MASQ_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_MASQ_FLAGS, htobe32(masq->flags));
}

static int
nftnl_expr_masq_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_masq *masq = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_MASQ_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nftnl_expr_masq_cb, tb) < 0)
		return -1;

	if (tb[NFTA_MASQ_FLAGS]) {
		masq->flags = be32toh(mnl_attr_get_u32(tb[NFTA_MASQ_FLAGS]));
		e->flags |= (1 << NFTNL_EXPR_MASQ_FLAGS);
	}

	return 0;
}

static int
nftnl_expr_masq_json_parse(struct nftnl_expr *e, json_t *root,
			      struct nftnl_parse_err *err)
{
#ifdef JSON_PARSING
	uint32_t flags;

	if (nftnl_jansson_parse_val(root, "flags", NFTNL_TYPE_U32, &flags,
				  err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_MASQ_FLAGS, flags);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nftnl_expr_masq_xml_parse(struct nftnl_expr *e, mxml_node_t *tree,
			     struct nftnl_parse_err *err)
{
#ifdef XML_PARSING
	uint32_t flags;

	if (nftnl_mxml_num_parse(tree, "flags", MXML_DESCEND_FIRST, BASE_DEC,
			       &flags, NFTNL_TYPE_U32, NFTNL_XML_MAND, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_MASQ_FLAGS, flags);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}
static int nftnl_expr_masq_export(char *buf, size_t size,
				     struct nftnl_expr *e, int type)
{
	struct nftnl_expr_masq *masq = nftnl_expr_data(e);
	NFTNL_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFTNL_EXPR_MASQ_FLAGS))
		nftnl_buf_u32(&b, type, masq->flags, FLAGS);

	return nftnl_buf_done(&b);
}

static int nftnl_expr_masq_snprintf_default(char *buf, size_t len,
					       struct nftnl_expr *e)
{
	struct nftnl_expr_masq *masq = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_MASQ_FLAGS))
		return snprintf(buf, len, "flags 0x%x ", masq->flags);

	return 0;
}

static int nftnl_expr_masq_snprintf(char *buf, size_t len, uint32_t type,
				       uint32_t flags, struct nftnl_expr *e)
{
	switch (type) {
	case NFTNL_OUTPUT_DEFAULT:
		return nftnl_expr_masq_snprintf_default(buf, len, e);
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		return nftnl_expr_masq_export(buf, len, e, type);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_masq = {
	.name		= "masq",
	.alloc_len	= sizeof(struct nftnl_expr_masq),
	.max_attr	= NFTA_MASQ_MAX,
	.set		= nftnl_expr_masq_set,
	.get		= nftnl_expr_masq_get,
	.parse		= nftnl_expr_masq_parse,
	.build		= nftnl_expr_masq_build,
	.snprintf	= nftnl_expr_masq_snprintf,
	.xml_parse	= nftnl_expr_masq_xml_parse,
	.json_parse	= nftnl_expr_masq_json_parse,
};
