/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Sophos Astaro <http://www.sophos.com>
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter/nf_tables.h>

#include "internal.h"
#include <libmnl/libmnl.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>
#include "expr_ops.h"

#ifndef NFT_META_MAX
#define NFT_META_MAX (NFT_META_L4PROTO + 1)
#endif

struct nft_expr_meta {
	enum nft_meta_keys	key;
	enum nft_registers	dreg;
	enum nft_registers	sreg;
};

static int
nft_rule_expr_meta_set(struct nft_rule_expr *e, uint16_t type,
		       const void *data, uint32_t data_len)
{
	struct nft_expr_meta *meta = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_META_KEY:
		meta->key = *((uint32_t *)data);
		break;
	case NFT_EXPR_META_DREG:
		meta->dreg = *((uint32_t *)data);
		break;
	case NFT_EXPR_META_SREG:
		meta->sreg = *((uint32_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_meta_get(const struct nft_rule_expr *e, uint16_t type,
		       uint32_t *data_len)
{
	struct nft_expr_meta *meta = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_META_KEY:
		*data_len = sizeof(meta->key);
		return &meta->key;
	case NFT_EXPR_META_DREG:
		*data_len = sizeof(meta->dreg);
		return &meta->dreg;
	case NFT_EXPR_META_SREG:
		*data_len = sizeof(meta->sreg);
		return &meta->sreg;
	}
	return NULL;
}

static int nft_rule_expr_meta_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_META_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_META_KEY:
	case NFTA_META_DREG:
	case NFTA_META_SREG:
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
nft_rule_expr_meta_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_meta *meta = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_META_KEY))
		mnl_attr_put_u32(nlh, NFTA_META_KEY, htonl(meta->key));
	if (e->flags & (1 << NFT_EXPR_META_DREG))
		mnl_attr_put_u32(nlh, NFTA_META_DREG, htonl(meta->dreg));
	if (e->flags & (1 << NFT_EXPR_META_SREG))
		mnl_attr_put_u32(nlh, NFTA_META_SREG, htonl(meta->sreg));
}

static int
nft_rule_expr_meta_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_meta *meta = nft_expr_data(e);
	struct nlattr *tb[NFTA_META_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nft_rule_expr_meta_cb, tb) < 0)
		return -1;

	if (tb[NFTA_META_KEY]) {
		meta->key = ntohl(mnl_attr_get_u32(tb[NFTA_META_KEY]));
		e->flags |= (1 << NFT_EXPR_META_KEY);
	}
	if (tb[NFTA_META_DREG]) {
		meta->dreg = ntohl(mnl_attr_get_u32(tb[NFTA_META_DREG]));
		e->flags |= (1 << NFT_EXPR_META_DREG);
	}
	if (tb[NFTA_META_SREG]) {
		meta->sreg = ntohl(mnl_attr_get_u32(tb[NFTA_META_SREG]));
		e->flags |= (1 << NFT_EXPR_META_SREG);
	}

	return 0;
}

static const char *meta_key2str_array[NFT_META_MAX] = {
	[NFT_META_LEN]		= "len",
	[NFT_META_PROTOCOL]	= "protocol",
	[NFT_META_NFPROTO]	= "nfproto",
	[NFT_META_L4PROTO]	= "l4proto",
	[NFT_META_PRIORITY]	= "priority",
	[NFT_META_MARK]		= "mark",
	[NFT_META_IIF]		= "iif",
	[NFT_META_OIF]		= "oif",
	[NFT_META_IIFNAME]	= "iifname",
	[NFT_META_OIFNAME]	= "oifname",
	[NFT_META_IIFTYPE]	= "iiftype",
	[NFT_META_OIFTYPE]	= "oiftype",
	[NFT_META_SKUID]	= "skuid",
	[NFT_META_SKGID]	= "skgid",
	[NFT_META_NFTRACE]	= "nftrace",
	[NFT_META_RTCLASSID]	= "rtclassid",
	[NFT_META_SECMARK]	= "secmark",
};

static const char *meta_key2str(uint8_t key)
{
	if (key < NFT_META_MAX)
		return meta_key2str_array[key];

	return "unknown";
}

static inline int str2meta_key(const char *str)
{
	int i;

	for (i = 0; i < NFT_META_MAX; i++) {
		if (strcmp(str, meta_key2str_array[i]) == 0)
			return i;
	}

	errno = EINVAL;
	return -1;
}

static int nft_rule_expr_meta_json_parse(struct nft_rule_expr *e, json_t *root,
					 struct nft_parse_err *err)
{
#ifdef JSON_PARSING
	const char *key_str;
	uint32_t reg;
	int key;

	key_str = nft_jansson_parse_str(root, "key", err);
	if (key_str == NULL)
		return -1;

	key = str2meta_key(key_str);
	if (key < 0)
		return -1;

	nft_rule_expr_set_u32(e, NFT_EXPR_META_KEY, key);

	if (nft_jansson_node_exist(root, "dreg")) {
		if (nft_jansson_parse_reg(root, "dreg", NFT_TYPE_U32, &reg,
					  err) < 0)
			return -1;

		nft_rule_expr_set_u32(e, NFT_EXPR_META_DREG, reg);
	}

	if (nft_jansson_node_exist(root, "sreg")) {
		if (nft_jansson_parse_reg(root, "sreg", NFT_TYPE_U32, &reg,
					  err) < 0)
			return -1;

		nft_rule_expr_set_u32(e, NFT_EXPR_META_SREG, reg);
	}

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}


static int nft_rule_expr_meta_xml_parse(struct nft_rule_expr *e, mxml_node_t *tree,
					struct nft_parse_err *err)
{
#ifdef XML_PARSING
	struct nft_expr_meta *meta = nft_expr_data(e);
	const char *key_str;
	int key;
	uint32_t reg;

	key_str = nft_mxml_str_parse(tree, "key", MXML_DESCEND_FIRST,
				     NFT_XML_MAND, err);
	if (key_str == NULL)
		return -1;

	key = str2meta_key(key_str);
	if (key < 0)
		return -1;

	meta->key = key;
	e->flags |= (1 << NFT_EXPR_META_KEY);

	if (nft_mxml_reg_parse(tree, "dreg", &reg, MXML_DESCEND_FIRST,
			       NFT_XML_OPT, err) >= 0) {
		meta->dreg = reg;
		e->flags |= (1 << NFT_EXPR_META_DREG);
	}

	if (nft_mxml_reg_parse(tree, "sreg", &reg, MXML_DESCEND_FIRST,
			       NFT_XML_OPT, err) >= 0) {
		meta->sreg = reg;
		e->flags |= (1 << NFT_EXPR_META_SREG);
	}

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_meta_snprintf_default(char *buf, size_t len,
				    struct nft_rule_expr *e)
{
	struct nft_expr_meta *meta = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_META_SREG)) {
		return snprintf(buf, len, "set %s with reg %u ",
				meta_key2str(meta->key), meta->sreg);
	}
	if (e->flags & (1 << NFT_EXPR_META_DREG)) {
		return snprintf(buf, len, "load %s => reg %u ",
				meta_key2str(meta->key), meta->dreg);
	}
	return 0;
}

static int
nft_rule_expr_meta_snprintf_xml(char *buf, size_t size,
				struct nft_rule_expr *e)
{
	int ret, len = size, offset = 0;
	struct nft_expr_meta *meta = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_META_DREG)) {
		ret = snprintf(buf+offset, len, "<dreg>%u</dreg>",
			       meta->dreg);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (e->flags & (1 << NFT_EXPR_META_KEY)) {
		ret = snprintf(buf+offset, len, "<key>%s</key>",
						meta_key2str(meta->key));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (e->flags & (1 << NFT_EXPR_META_SREG)) {
		ret = snprintf(buf+offset, len, "<sreg>%u</sreg>",
			       meta->sreg);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int
nft_rule_expr_meta_snprintf_json(char *buf, size_t size,
				 struct nft_rule_expr *e)
{
	int ret, len = size, offset = 0;
	struct nft_expr_meta *meta = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_META_DREG)) {
		ret = snprintf(buf+offset, len, "\"dreg\":%u,",
			       meta->dreg);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (e->flags & (1 << NFT_EXPR_META_KEY)) {
		ret = snprintf(buf+offset, len, "\"key\":\"%s\",",
						meta_key2str(meta->key));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (e->flags & (1 << NFT_EXPR_META_SREG)) {
		ret = snprintf(buf+offset, len, "\"sreg\":%u,",
			       meta->sreg);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	/* Remove the last separator characther */
	buf[offset-1] = '\0';

	return offset-1;
}

static int
nft_rule_expr_meta_snprintf(char *buf, size_t len, uint32_t type,
			    uint32_t flags, struct nft_rule_expr *e)
{
	switch(type) {
	case NFT_OUTPUT_DEFAULT:
		return nft_rule_expr_meta_snprintf_default(buf, len, e);
	case NFT_OUTPUT_XML:
		return nft_rule_expr_meta_snprintf_xml(buf, len, e);
	case NFT_OUTPUT_JSON:
		return nft_rule_expr_meta_snprintf_json(buf, len, e);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_meta = {
	.name		= "meta",
	.alloc_len	= sizeof(struct nft_expr_meta),
	.max_attr	= NFTA_META_MAX,
	.set		= nft_rule_expr_meta_set,
	.get		= nft_rule_expr_meta_get,
	.parse		= nft_rule_expr_meta_parse,
	.build		= nft_rule_expr_meta_build,
	.snprintf	= nft_rule_expr_meta_snprintf,
	.xml_parse 	= nft_rule_expr_meta_xml_parse,
	.json_parse 	= nft_rule_expr_meta_json_parse,
};

static void __init expr_meta_init(void)
{
	nft_expr_ops_register(&expr_ops_meta);
}
