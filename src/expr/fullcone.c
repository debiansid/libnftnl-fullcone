/*
 * (C) 2022 wongsyrone
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

struct nftnl_expr_fullcone {
	uint32_t		flags;
	enum nft_registers	sreg_proto_min;
	enum nft_registers	sreg_proto_max;
};

static int
nftnl_expr_fullcone_set(struct nftnl_expr *e, uint16_t type,
		       const void *data, uint32_t data_len)
{
	struct nftnl_expr_fullcone *fullcone = nftnl_expr_data(e);

	switch (type) {
	case NFTNL_EXPR_FULLCONE_FLAGS:
		memcpy(&fullcone->flags, data, sizeof(fullcone->flags));
		break;
	case NFTNL_EXPR_FULLCONE_REG_PROTO_MIN:
		memcpy(&fullcone->sreg_proto_min, data, sizeof(fullcone->sreg_proto_min));
		break;
	case NFTNL_EXPR_FULLCONE_REG_PROTO_MAX:
		memcpy(&fullcone->sreg_proto_max, data, sizeof(fullcone->sreg_proto_max));
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nftnl_expr_fullcone_get(const struct nftnl_expr *e, uint16_t type,
		       uint32_t *data_len)
{
	struct nftnl_expr_fullcone *fullcone = nftnl_expr_data(e);

	switch (type) {
	case NFTNL_EXPR_FULLCONE_FLAGS:
		*data_len = sizeof(fullcone->flags);
		return &fullcone->flags;
	case NFTNL_EXPR_FULLCONE_REG_PROTO_MIN:
		*data_len = sizeof(fullcone->sreg_proto_min);
		return &fullcone->sreg_proto_min;
	case NFTNL_EXPR_FULLCONE_REG_PROTO_MAX:
		*data_len = sizeof(fullcone->sreg_proto_max);
		return &fullcone->sreg_proto_max;
	}
	return NULL;
}

static int nftnl_expr_fullcone_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_FULLCONE_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case NFTA_FULLCONE_REG_PROTO_MIN:
	case NFTA_FULLCONE_REG_PROTO_MAX:
	case NFTA_FULLCONE_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_expr_fullcone_build(struct nlmsghdr *nlh, const struct nftnl_expr *e)
{
	struct nftnl_expr_fullcone *fullcone = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_FULLCONE_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_FULLCONE_FLAGS, htobe32(fullcone->flags));
	if (e->flags & (1 << NFTNL_EXPR_FULLCONE_REG_PROTO_MIN))
		mnl_attr_put_u32(nlh, NFTA_FULLCONE_REG_PROTO_MIN,
				 htobe32(fullcone->sreg_proto_min));
	if (e->flags & (1 << NFTNL_EXPR_FULLCONE_REG_PROTO_MAX))
		mnl_attr_put_u32(nlh, NFTA_FULLCONE_REG_PROTO_MAX,
				 htobe32(fullcone->sreg_proto_max));
}

static int
nftnl_expr_fullcone_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_fullcone *fullcone = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_FULLCONE_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nftnl_expr_fullcone_cb, tb) < 0)
		return -1;

	if (tb[NFTA_FULLCONE_FLAGS]) {
		fullcone->flags = be32toh(mnl_attr_get_u32(tb[NFTA_FULLCONE_FLAGS]));
		e->flags |= (1 << NFTNL_EXPR_FULLCONE_FLAGS);
        }
	if (tb[NFTA_FULLCONE_REG_PROTO_MIN]) {
		fullcone->sreg_proto_min =
			be32toh(mnl_attr_get_u32(tb[NFTA_FULLCONE_REG_PROTO_MIN]));
		e->flags |= (1 << NFTNL_EXPR_FULLCONE_REG_PROTO_MIN);
	}
	if (tb[NFTA_FULLCONE_REG_PROTO_MAX]) {
		fullcone->sreg_proto_max =
			be32toh(mnl_attr_get_u32(tb[NFTA_FULLCONE_REG_PROTO_MAX]));
		e->flags |= (1 << NFTNL_EXPR_FULLCONE_REG_PROTO_MAX);
	}

	return 0;
}

static int nftnl_expr_fullcone_snprintf(char *buf, size_t remain,
				    uint32_t flags, const struct nftnl_expr *e)
{
	struct nftnl_expr_fullcone *fullcone = nftnl_expr_data(e);
	int offset = 0, ret = 0;

	if (e->flags & (1 << NFTNL_EXPR_FULLCONE_REG_PROTO_MIN)) {
		ret = snprintf(buf + offset, remain, "proto_min reg %u ",
			       fullcone->sreg_proto_min);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	}
	if (e->flags & (1 << NFTNL_EXPR_FULLCONE_REG_PROTO_MAX)) {
		ret = snprintf(buf + offset, remain, "proto_max reg %u ",
			       fullcone->sreg_proto_max);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	}
	if (e->flags & (1 << NFTNL_EXPR_FULLCONE_FLAGS)) {
		ret = snprintf(buf + offset, remain, "flags 0x%x ", fullcone->flags);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	}

	return offset;
}

struct expr_ops expr_ops_fullcone = {
	.name		= "fullcone",
	.alloc_len	= sizeof(struct nftnl_expr_fullcone),
	.max_attr	= NFTA_FULLCONE_MAX,
	.set		= nftnl_expr_fullcone_set,
	.get		= nftnl_expr_fullcone_get,
	.parse		= nftnl_expr_fullcone_parse,
	.build		= nftnl_expr_fullcone_build,
	.output		= nftnl_expr_fullcone_snprintf,
};

