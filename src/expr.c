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
#include "internal.h"

#include <time.h>
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libnftnl/expr.h>

struct nftnl_expr *nftnl_expr_alloc(const char *name)
{
	struct nftnl_expr *expr;
	struct expr_ops *ops;

	ops = nftnl_expr_ops_lookup(name);
	if (ops == NULL)
		return NULL;

	expr = calloc(1, sizeof(struct nftnl_expr) + ops->alloc_len);
	if (expr == NULL)
		return NULL;

	/* Manually set expression name attribute */
	expr->flags |= (1 << NFTNL_EXPR_NAME);
	expr->ops = ops;

	return expr;
}
EXPORT_SYMBOL_ALIAS(nftnl_expr_alloc, nft_rule_expr_alloc);

void nftnl_expr_free(struct nftnl_expr *expr)
{
	if (expr->ops->free)
		expr->ops->free(expr);

	xfree(expr);
}
EXPORT_SYMBOL_ALIAS(nftnl_expr_free, nft_rule_expr_free);

bool nftnl_expr_is_set(const struct nftnl_expr *expr, uint16_t type)
{
	return expr->flags & (1 << type);
}
EXPORT_SYMBOL_ALIAS(nftnl_expr_is_set, nft_rule_expr_is_set);

void
nftnl_expr_set(struct nftnl_expr *expr, uint16_t type,
		  const void *data, uint32_t data_len)
{
	switch(type) {
	case NFTNL_EXPR_NAME:	/* cannot be modified */
		return;
	default:
		if (expr->ops->set(expr, type, data, data_len) < 0)
			return;
	}
	expr->flags |= (1 << type);
}
EXPORT_SYMBOL_ALIAS(nftnl_expr_set, nft_rule_expr_set);

void
nftnl_expr_set_u8(struct nftnl_expr *expr, uint16_t type, uint8_t data)
{
	nftnl_expr_set(expr, type, &data, sizeof(uint8_t));
}
EXPORT_SYMBOL_ALIAS(nftnl_expr_set_u8, nft_rule_expr_set_u8);

void
nftnl_expr_set_u16(struct nftnl_expr *expr, uint16_t type, uint16_t data)
{
	nftnl_expr_set(expr, type, &data, sizeof(uint16_t));
}
EXPORT_SYMBOL_ALIAS(nftnl_expr_set_u16, nft_rule_expr_set_u16);

void
nftnl_expr_set_u32(struct nftnl_expr *expr, uint16_t type, uint32_t data)
{
	nftnl_expr_set(expr, type, &data, sizeof(uint32_t));
}
EXPORT_SYMBOL_ALIAS(nftnl_expr_set_u32, nft_rule_expr_set_u32);

void
nftnl_expr_set_u64(struct nftnl_expr *expr, uint16_t type, uint64_t data)
{
	nftnl_expr_set(expr, type, &data, sizeof(uint64_t));
}
EXPORT_SYMBOL_ALIAS(nftnl_expr_set_u64, nft_rule_expr_set_u64);

void
nftnl_expr_set_str(struct nftnl_expr *expr, uint16_t type, const char *str)
{
	nftnl_expr_set(expr, type, str, strlen(str)+1);
}
EXPORT_SYMBOL_ALIAS(nftnl_expr_set_str, nft_rule_expr_set_str);

const void *nftnl_expr_get(const struct nftnl_expr *expr,
			      uint16_t type, uint32_t *data_len)
{
	const void *ret;

	if (!(expr->flags & (1 << type)))
		return NULL;

	switch(type) {
	case NFTNL_EXPR_NAME:
		ret = expr->ops->name;
		break;
	default:
		ret = expr->ops->get(expr, type, data_len);
		break;
	}

	return ret;
}
EXPORT_SYMBOL_ALIAS(nftnl_expr_get, nft_rule_expr_get);

uint8_t nftnl_expr_get_u8(const struct nftnl_expr *expr, uint16_t type)
{
	const void *data;
	uint32_t data_len;

	data = nftnl_expr_get(expr, type, &data_len);
	if (data == NULL)
		return 0;

	if (data_len != sizeof(uint8_t))
		return 0;

	return *((uint8_t *)data);
}
EXPORT_SYMBOL_ALIAS(nftnl_expr_get_u8, nft_rule_expr_get_u8);

uint16_t nftnl_expr_get_u16(const struct nftnl_expr *expr, uint16_t type)
{
	const void *data;
	uint32_t data_len;

	data = nftnl_expr_get(expr, type, &data_len);
	if (data == NULL)
		return 0;

	if (data_len != sizeof(uint16_t))
		return 0;

	return *((uint16_t *)data);
}
EXPORT_SYMBOL_ALIAS(nftnl_expr_get_u16, nft_rule_expr_get_u16);

uint32_t nftnl_expr_get_u32(const struct nftnl_expr *expr, uint16_t type)
{
	const void *data;
	uint32_t data_len;

	data = nftnl_expr_get(expr, type, &data_len);
	if (data == NULL)
		return 0;

	if (data_len != sizeof(uint32_t))
		return 0;

	return *((uint32_t *)data);
}
EXPORT_SYMBOL_ALIAS(nftnl_expr_get_u32, nft_rule_expr_get_u32);

uint64_t nftnl_expr_get_u64(const struct nftnl_expr *expr, uint16_t type)
{
	const void *data;
	uint32_t data_len;

	data = nftnl_expr_get(expr, type, &data_len);
	if (data == NULL)
		return 0;

	if (data_len != sizeof(uint64_t))
		return 0;

	return *((uint64_t *)data);
}
EXPORT_SYMBOL_ALIAS(nftnl_expr_get_u64, nft_rule_expr_get_u64);

const char *nftnl_expr_get_str(const struct nftnl_expr *expr, uint16_t type)
{
	uint32_t data_len;

	return (const char *)nftnl_expr_get(expr, type, &data_len);
}
EXPORT_SYMBOL_ALIAS(nftnl_expr_get_str, nft_rule_expr_get_str);

void
nftnl_expr_build_payload(struct nlmsghdr *nlh, struct nftnl_expr *expr)
{
	struct nlattr *nest;

	mnl_attr_put_strz(nlh, NFTA_EXPR_NAME, expr->ops->name);

	nest = mnl_attr_nest_start(nlh, NFTA_EXPR_DATA);
	expr->ops->build(nlh, expr);
	mnl_attr_nest_end(nlh, nest);
}

static int nftnl_rule_parse_expr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_EXPR_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case NFTA_EXPR_NAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			abi_breakage();
		break;
	case NFTA_EXPR_DATA:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

struct nftnl_expr *nftnl_expr_parse(struct nlattr *attr)
{
	struct nlattr *tb[NFTA_EXPR_MAX+1] = {};
	struct nftnl_expr *expr;

	if (mnl_attr_parse_nested(attr, nftnl_rule_parse_expr_cb, tb) < 0)
		goto err1;

	expr = nftnl_expr_alloc(mnl_attr_get_str(tb[NFTA_EXPR_NAME]));
	if (expr == NULL)
		goto err1;

	if (tb[NFTA_EXPR_DATA] &&
	    expr->ops->parse(expr, tb[NFTA_EXPR_DATA]) < 0)
		goto err2;

	return expr;

err2:
	xfree(expr);
err1:
	return NULL;
}

int nftnl_expr_snprintf(char *buf, size_t size, struct nftnl_expr *expr,
			   uint32_t type, uint32_t flags)
{
	int ret;
	unsigned int offset = 0, len = size;

	ret = expr->ops->snprintf(buf+offset, len, type, flags, expr);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}
EXPORT_SYMBOL_ALIAS(nftnl_expr_snprintf, nft_rule_expr_snprintf);
