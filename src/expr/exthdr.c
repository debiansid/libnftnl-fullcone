/*
 * (C) 2012-2013 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Sophos Astaro <http://www.sophos.com>
 */

#include "internal.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <arpa/inet.h>
#include <errno.h>
#include <libmnl/libmnl.h>

#include <linux/netfilter/nf_tables.h>

#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

#include "expr_ops.h"

#ifndef IPPROTO_MH
#define IPPROTO_MH 135
#endif

struct nft_expr_exthdr {
	enum nft_registers	dreg;
	uint32_t		offset;
	uint32_t		len;
	uint8_t			type;
};

static int
nft_rule_expr_exthdr_set(struct nft_rule_expr *e, uint16_t type,
			  const void *data, uint32_t data_len)
{
	struct nft_expr_exthdr *exthdr = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_EXTHDR_DREG:
		exthdr->dreg = *((uint32_t *)data);
		break;
	case NFT_EXPR_EXTHDR_TYPE:
		exthdr->type = *((uint8_t *)data);
		break;
	case NFT_EXPR_EXTHDR_OFFSET:
		exthdr->offset = *((uint32_t *)data);
		break;
	case NFT_EXPR_EXTHDR_LEN:
		exthdr->len = *((uint32_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_exthdr_get(const struct nft_rule_expr *e, uint16_t type,
			 uint32_t *data_len)
{
	struct nft_expr_exthdr *exthdr = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_EXTHDR_DREG:
		*data_len = sizeof(exthdr->dreg);
		return &exthdr->dreg;
	case NFT_EXPR_EXTHDR_TYPE:
		*data_len = sizeof(exthdr->type);
		return &exthdr->type;
	case NFT_EXPR_EXTHDR_OFFSET:
		*data_len = sizeof(exthdr->offset);
		return &exthdr->offset;
	case NFT_EXPR_EXTHDR_LEN:
		*data_len = sizeof(exthdr->len);
		return &exthdr->len;
	}
	return NULL;
}

static int nft_rule_expr_exthdr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_EXTHDR_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_EXTHDR_TYPE:
		if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_EXTHDR_DREG:
	case NFTA_EXTHDR_OFFSET:
	case NFTA_EXTHDR_LEN:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nft_rule_expr_exthdr_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_exthdr *exthdr = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_EXTHDR_DREG))
		mnl_attr_put_u32(nlh, NFTA_EXTHDR_DREG, htonl(exthdr->dreg));
	if (e->flags & (1 << NFT_EXPR_EXTHDR_TYPE))
		mnl_attr_put_u8(nlh, NFTA_EXTHDR_TYPE, exthdr->type);
	if (e->flags & (1 << NFT_EXPR_EXTHDR_OFFSET))
		mnl_attr_put_u32(nlh, NFTA_EXTHDR_OFFSET, htonl(exthdr->offset));
	if (e->flags & (1 << NFT_EXPR_EXTHDR_LEN))
		mnl_attr_put_u32(nlh, NFTA_EXTHDR_LEN, htonl(exthdr->len));
}

static int
nft_rule_expr_exthdr_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_exthdr *exthdr = nft_expr_data(e);
	struct nlattr *tb[NFTA_EXTHDR_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nft_rule_expr_exthdr_cb, tb) < 0)
		return -1;

	if (tb[NFTA_EXTHDR_DREG]) {
		exthdr->dreg = ntohl(mnl_attr_get_u32(tb[NFTA_EXTHDR_DREG]));
		e->flags |= (1 << NFT_EXPR_EXTHDR_DREG);
	}
	if (tb[NFTA_EXTHDR_TYPE]) {
		exthdr->type = mnl_attr_get_u8(tb[NFTA_EXTHDR_TYPE]);
		e->flags |= (1 << NFT_EXPR_EXTHDR_TYPE);
	}
	if (tb[NFTA_EXTHDR_OFFSET]) {
		exthdr->offset = ntohl(mnl_attr_get_u32(tb[NFTA_EXTHDR_OFFSET]));
		e->flags |= (1 << NFT_EXPR_EXTHDR_OFFSET);
	}
	if (tb[NFTA_EXTHDR_LEN]) {
		exthdr->len = ntohl(mnl_attr_get_u32(tb[NFTA_EXTHDR_LEN]));
		e->flags |= (1 << NFT_EXPR_EXTHDR_LEN);
	}

	return 0;
}

static const char *exthdr_type2str(uint32_t type)
{
	switch (type) {
	case IPPROTO_HOPOPTS:
		return "hopopts";
	case IPPROTO_ROUTING:
		return "routing";
	case IPPROTO_FRAGMENT:
		return "fragment";
	case IPPROTO_DSTOPTS:
		return "dstopts";
	case IPPROTO_MH:
		return "mh";
	default:
		return "unknown";
	}
}

static inline int str2exthdr_type(const char *str)
{
	if (strcmp(str, "hopopts") == 0)
		return IPPROTO_HOPOPTS;
	else if (strcmp(str, "routing") == 0)
		return IPPROTO_ROUTING;
	else if (strcmp(str, "fragment") == 0)
		return IPPROTO_FRAGMENT;
	else if (strcmp(str, "dstopts") == 0)
		return IPPROTO_DSTOPTS;
	else if (strcmp(str, "mh") == 0)
		return IPPROTO_MH;

	return -1;
}

static int
nft_rule_expr_exthdr_json_parse(struct nft_rule_expr *e, json_t *root,
				struct nft_parse_err *err)
{
#ifdef JSON_PARSING
	const char *exthdr_type;
	uint32_t uval32;
	int type;

	if (nft_jansson_parse_reg(root, "dreg", NFT_TYPE_U32, &uval32,
				  err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_EXTHDR_DREG, uval32);

	exthdr_type = nft_jansson_parse_str(root, "exthdr_type", err);
	if (exthdr_type != NULL) {
		type = str2exthdr_type(exthdr_type);
		if (type < 0)
			return -1;
		nft_rule_expr_set_u32(e, NFT_EXPR_EXTHDR_TYPE, type);
	}

	if (nft_jansson_parse_val(root, "offset", NFT_TYPE_U32, &uval32,
				  err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_EXTHDR_OFFSET, uval32);

	if (nft_jansson_parse_val(root, "len", NFT_TYPE_U32, &uval32, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_EXTHDR_LEN, uval32);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_exthdr_xml_parse(struct nft_rule_expr *e, mxml_node_t *tree,
			       struct nft_parse_err *err)
{
#ifdef XML_PARSING
	const char *exthdr_type;
	int type;
	uint32_t dreg, len, offset;

	if (nft_mxml_reg_parse(tree, "dreg", &dreg, MXML_DESCEND_FIRST,
			       NFT_XML_MAND, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_EXTHDR_DREG, dreg);

	exthdr_type = nft_mxml_str_parse(tree, "exthdr_type",
					 MXML_DESCEND_FIRST, NFT_XML_MAND, err);
	if (exthdr_type != NULL) {
		type = str2exthdr_type(exthdr_type);
		if (type < 0)
			return -1;
		nft_rule_expr_set_u8(e, NFT_EXPR_EXTHDR_TYPE, type);
	}

	/* Get and set <offset> */
	if (nft_mxml_num_parse(tree, "offset", MXML_DESCEND_FIRST, BASE_DEC,
			       &offset, NFT_TYPE_U32, NFT_XML_MAND, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_EXTHDR_OFFSET, offset);

	/* Get and set <len> */
	if (nft_mxml_num_parse(tree, "len", MXML_DESCEND_FIRST, BASE_DEC,
			       &len, NFT_TYPE_U32, NFT_XML_MAND, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_EXTHDR_LEN, len);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nft_rule_expr_exthdr_snprintf_json(char *buf, size_t len,
					      struct nft_rule_expr *e)
{
	struct nft_expr_exthdr *exthdr = nft_expr_data(e);
	int ret, size = len, offset = 0;

	if (e->flags & (1 << NFT_EXPR_EXTHDR_DREG)) {
		ret = snprintf(buf, len, "\"dreg\":%u,", exthdr->dreg);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (e->flags & (1 << NFT_EXPR_EXTHDR_TYPE)) {
		ret = snprintf(buf + offset, len, "\"exthdr_type\":\"%s\",",
			       exthdr_type2str(exthdr->type));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (e->flags & (1 << NFT_EXPR_EXTHDR_OFFSET)) {
		ret = snprintf(buf + offset, len, "\"offset\":%u,",
			       exthdr->offset);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (e->flags & (1 << NFT_EXPR_EXTHDR_LEN)) {
		ret = snprintf(buf + offset, len, "\"len\":%u,",
			       exthdr->len);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	/* Remove the last comma characther */
	if (offset > 0)
		offset--;

	return offset;
}

static int nft_rule_expr_exthdr_snprintf_xml(char *buf, size_t len,
					     struct nft_rule_expr *e)
{
	struct nft_expr_exthdr *exthdr = nft_expr_data(e);
	int ret, size = len, offset = 0;

	if (e->flags & (1 << NFT_EXPR_EXTHDR_DREG)) {
		ret = snprintf(buf, len, "<dreg>%u</dreg>", exthdr->dreg);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (e->flags & (1 << NFT_EXPR_EXTHDR_TYPE)) {
		ret = snprintf(buf + offset, len,
			       "<exthdr_type>%s</exthdr_type>",
			       exthdr_type2str(exthdr->type));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (e->flags & (1 << NFT_EXPR_EXTHDR_OFFSET)) {
		ret = snprintf(buf + offset, len, "<offset>%u</offset>",
			       exthdr->offset);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (e->flags & (1 << NFT_EXPR_EXTHDR_LEN)) {
		ret = snprintf(buf + offset, len, "<len>%u</len>", exthdr->len);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int nft_rule_expr_exthdr_snprintf_default(char *buf, size_t len,
						 struct nft_rule_expr *e)
{
	struct nft_expr_exthdr *exthdr = nft_expr_data(e);

	return snprintf(buf, len, "load %ub @ %u + %u => reg %u ",
			exthdr->len, exthdr->type, exthdr->offset,
			exthdr->dreg);
}

static int
nft_rule_expr_exthdr_snprintf(char *buf, size_t len, uint32_t type,
			       uint32_t flags, struct nft_rule_expr *e)
{
	switch(type) {
	case NFT_OUTPUT_DEFAULT:
		return nft_rule_expr_exthdr_snprintf_default(buf, len, e);
	case NFT_OUTPUT_XML:
		return nft_rule_expr_exthdr_snprintf_xml(buf, len, e);
	case NFT_OUTPUT_JSON:
		return nft_rule_expr_exthdr_snprintf_json(buf, len, e);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_exthdr = {
	.name		= "exthdr",
	.alloc_len	= sizeof(struct nft_expr_exthdr),
	.max_attr	= NFTA_EXTHDR_MAX,
	.set		= nft_rule_expr_exthdr_set,
	.get		= nft_rule_expr_exthdr_get,
	.parse		= nft_rule_expr_exthdr_parse,
	.build		= nft_rule_expr_exthdr_build,
	.snprintf	= nft_rule_expr_exthdr_snprintf,
	.xml_parse	= nft_rule_expr_exthdr_xml_parse,
	.json_parse	= nft_rule_expr_exthdr_json_parse,
};

static void __init expr_exthdr_init(void)
{
	nft_expr_ops_register(&expr_ops_exthdr);
}
