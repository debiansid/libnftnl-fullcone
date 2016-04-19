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

#include <time.h>
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <inttypes.h>
#include <ctype.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libnftnl/rule.h>
#include <libnftnl/set.h>
#include <libnftnl/expr.h>

struct nftnl_rule {
	struct list_head head;

	uint32_t	flags;
	uint32_t	family;
	const char	*table;
	const char	*chain;
	uint64_t	handle;
	uint64_t	position;
	struct {
			void		*data;
			uint32_t	len;
	} user;
	struct {
			uint32_t	flags;
			uint32_t	proto;
	} compat;

	struct list_head expr_list;
};

struct nftnl_rule *nftnl_rule_alloc(void)
{
	struct nftnl_rule *r;

	r = calloc(1, sizeof(struct nftnl_rule));
	if (r == NULL)
		return NULL;

	INIT_LIST_HEAD(&r->expr_list);

	return r;
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_alloc, nft_rule_alloc);

void nftnl_rule_free(struct nftnl_rule *r)
{
	struct nftnl_expr *e, *tmp;

	list_for_each_entry_safe(e, tmp, &r->expr_list, head)
		nftnl_expr_free(e);

	if (r->table != NULL)
		xfree(r->table);
	if (r->chain != NULL)
		xfree(r->chain);

	xfree(r);
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_free, nft_rule_free);

bool nftnl_rule_is_set(const struct nftnl_rule *r, uint16_t attr)
{
	return r->flags & (1 << attr);
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_is_set, nft_rule_attr_is_set);

void nftnl_rule_unset(struct nftnl_rule *r, uint16_t attr)
{
	if (!(r->flags & (1 << attr)))
		return;

	switch (attr) {
	case NFTNL_RULE_TABLE:
		if (r->table) {
			xfree(r->table);
			r->table = NULL;
		}
		break;
	case NFTNL_RULE_CHAIN:
		if (r->chain) {
			xfree(r->chain);
			r->chain = NULL;
		}
		break;
	case NFTNL_RULE_HANDLE:
	case NFTNL_RULE_COMPAT_PROTO:
	case NFTNL_RULE_COMPAT_FLAGS:
	case NFTNL_RULE_POSITION:
	case NFTNL_RULE_FAMILY:
	case NFTNL_RULE_USERDATA:
		break;
	}

	r->flags &= ~(1 << attr);
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_unset, nft_rule_attr_unset);

static uint32_t nftnl_rule_validate[NFTNL_RULE_MAX + 1] = {
	[NFTNL_RULE_HANDLE]		= sizeof(uint64_t),
	[NFTNL_RULE_COMPAT_PROTO]	= sizeof(uint32_t),
	[NFTNL_RULE_COMPAT_FLAGS]	= sizeof(uint32_t),
	[NFTNL_RULE_FAMILY]		= sizeof(uint32_t),
	[NFTNL_RULE_POSITION]	= sizeof(uint64_t),
};

void nftnl_rule_set_data(struct nftnl_rule *r, uint16_t attr,
			    const void *data, uint32_t data_len)
{
	if (attr > NFTNL_RULE_MAX)
		return;

	nftnl_assert_validate(data, nftnl_rule_validate, attr, data_len);

	switch(attr) {
	case NFTNL_RULE_TABLE:
		if (r->table)
			xfree(r->table);

		r->table = strdup(data);
		break;
	case NFTNL_RULE_CHAIN:
		if (r->chain)
			xfree(r->chain);

		r->chain = strdup(data);
		break;
	case NFTNL_RULE_HANDLE:
		r->handle = *((uint64_t *)data);
		break;
	case NFTNL_RULE_COMPAT_PROTO:
		r->compat.proto = *((uint32_t *)data);
		break;
	case NFTNL_RULE_COMPAT_FLAGS:
		r->compat.flags = *((uint32_t *)data);
		break;
	case NFTNL_RULE_FAMILY:
		r->family = *((uint32_t *)data);
		break;
	case NFTNL_RULE_POSITION:
		r->position = *((uint64_t *)data);
		break;
	case NFTNL_RULE_USERDATA:
		r->user.data = (void *)data;
		r->user.len = data_len;
		break;
	}
	r->flags |= (1 << attr);
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_set_data, nft_rule_attr_set_data);

void nftnl_rule_set(struct nftnl_rule *r, uint16_t attr, const void *data)
{
	nftnl_rule_set_data(r, attr, data, nftnl_rule_validate[attr]);
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_set, nft_rule_attr_set);

void nftnl_rule_set_u32(struct nftnl_rule *r, uint16_t attr, uint32_t val)
{
	nftnl_rule_set_data(r, attr, &val, sizeof(uint32_t));
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_set_u32, nft_rule_attr_set_u32);

void nftnl_rule_set_u64(struct nftnl_rule *r, uint16_t attr, uint64_t val)
{
	nftnl_rule_set_data(r, attr, &val, sizeof(uint64_t));
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_set_u64, nft_rule_attr_set_u64);

void nftnl_rule_set_str(struct nftnl_rule *r, uint16_t attr, const char *str)
{
	nftnl_rule_set_data(r, attr, str, strlen(str));
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_set_str, nft_rule_attr_set_str);

const void *nftnl_rule_get_data(const struct nftnl_rule *r, uint16_t attr,
				   uint32_t *data_len)
{
	if (!(r->flags & (1 << attr)))
		return NULL;

	switch(attr) {
	case NFTNL_RULE_FAMILY:
		*data_len = sizeof(uint32_t);
		return &r->family;
	case NFTNL_RULE_TABLE:
		return r->table;
	case NFTNL_RULE_CHAIN:
		return r->chain;
	case NFTNL_RULE_HANDLE:
		*data_len = sizeof(uint64_t);
		return &r->handle;
	case NFTNL_RULE_COMPAT_PROTO:
		*data_len = sizeof(uint32_t);
		return &r->compat.proto;
	case NFTNL_RULE_COMPAT_FLAGS:
		*data_len = sizeof(uint32_t);
		return &r->compat.flags;
	case NFTNL_RULE_POSITION:
		*data_len = sizeof(uint64_t);
		return &r->position;
	case NFTNL_RULE_USERDATA:
		*data_len = r->user.len;
		return r->user.data;
	}
	return NULL;
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_get_data, nft_rule_attr_get_data);

const void *nftnl_rule_get(const struct nftnl_rule *r, uint16_t attr)
{
	uint32_t data_len;
	return nftnl_rule_get_data(r, attr, &data_len);
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_get, nft_rule_attr_get);

const char *nftnl_rule_get_str(const struct nftnl_rule *r, uint16_t attr)
{
	return nftnl_rule_get(r, attr);
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_get_str, nft_rule_attr_get_str);

uint32_t nftnl_rule_get_u32(const struct nftnl_rule *r, uint16_t attr)
{
	uint32_t data_len;
	const uint32_t *val = nftnl_rule_get_data(r, attr, &data_len);

	nftnl_assert(val, attr, data_len == sizeof(uint32_t));

	return val ? *val : 0;
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_get_u32, nft_rule_attr_get_u32);

uint64_t nftnl_rule_get_u64(const struct nftnl_rule *r, uint16_t attr)
{
	uint32_t data_len;
	const uint64_t *val = nftnl_rule_get_data(r, attr, &data_len);

	nftnl_assert(val, attr, data_len == sizeof(uint64_t));

	return val ? *val : 0;
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_get_u64, nft_rule_attr_get_u64);

uint8_t nftnl_rule_get_u8(const struct nftnl_rule *r, uint16_t attr)
{
	uint32_t data_len;
	const uint8_t *val = nftnl_rule_get_data(r, attr, &data_len);

	nftnl_assert(val, attr, data_len == sizeof(uint8_t));

	return val ? *val : 0;
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_get_u8, nft_rule_attr_get_u8);

void nftnl_rule_nlmsg_build_payload(struct nlmsghdr *nlh, struct nftnl_rule *r)
{
	struct nftnl_expr *expr;
	struct nlattr *nest, *nest2;

	if (r->flags & (1 << NFTNL_RULE_TABLE))
		mnl_attr_put_strz(nlh, NFTA_RULE_TABLE, r->table);
	if (r->flags & (1 << NFTNL_RULE_CHAIN))
		mnl_attr_put_strz(nlh, NFTA_RULE_CHAIN, r->chain);
	if (r->flags & (1 << NFTNL_RULE_HANDLE))
		mnl_attr_put_u64(nlh, NFTA_RULE_HANDLE, htobe64(r->handle));
	if (r->flags & (1 << NFTNL_RULE_POSITION))
		mnl_attr_put_u64(nlh, NFTA_RULE_POSITION, htobe64(r->position));
	if (r->flags & (1 << NFTNL_RULE_USERDATA)) {
		mnl_attr_put(nlh, NFTA_RULE_USERDATA, r->user.len,
			     r->user.data);
	}

	if (!list_empty(&r->expr_list)) {
		nest = mnl_attr_nest_start(nlh, NFTA_RULE_EXPRESSIONS);
		list_for_each_entry(expr, &r->expr_list, head) {
			nest2 = mnl_attr_nest_start(nlh, NFTA_LIST_ELEM);
			nftnl_expr_build_payload(nlh, expr);
			mnl_attr_nest_end(nlh, nest2);
		}
		mnl_attr_nest_end(nlh, nest);
	}

	if (r->flags & (1 << NFTNL_RULE_COMPAT_PROTO) &&
	    r->flags & (1 << NFTNL_RULE_COMPAT_FLAGS)) {

		nest = mnl_attr_nest_start(nlh, NFTA_RULE_COMPAT);
		mnl_attr_put_u32(nlh, NFTA_RULE_COMPAT_PROTO,
				 htonl(r->compat.proto));
		mnl_attr_put_u32(nlh, NFTA_RULE_COMPAT_FLAGS,
				 htonl(r->compat.flags));
		mnl_attr_nest_end(nlh, nest);
	}
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_nlmsg_build_payload, nft_rule_nlmsg_build_payload);

void nftnl_rule_add_expr(struct nftnl_rule *r, struct nftnl_expr *expr)
{
	list_add_tail(&expr->head, &r->expr_list);
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_add_expr, nft_rule_add_expr);

static int nftnl_rule_parse_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_RULE_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_RULE_TABLE:
	case NFTA_RULE_CHAIN:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			abi_breakage();
		break;
	case NFTA_RULE_HANDLE:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0)
			abi_breakage();
		break;
	case NFTA_RULE_COMPAT:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0)
			abi_breakage();
		break;
	case NFTA_RULE_POSITION:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0)
			abi_breakage();
		break;
	case NFTA_RULE_USERDATA:
		if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int nftnl_rule_parse_expr(struct nlattr *nest, struct nftnl_rule *r)
{
	struct nftnl_expr *expr;
	struct nlattr *attr;

	mnl_attr_for_each_nested(attr, nest) {
		if (mnl_attr_get_type(attr) != NFTA_LIST_ELEM)
			return -1;

		expr = nftnl_expr_parse(attr);
		if (expr == NULL)
			return -1;

		list_add_tail(&expr->head, &r->expr_list);
	}
	return 0;
}

static int nftnl_rule_parse_compat_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_RULE_COMPAT_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_RULE_COMPAT_PROTO:
	case NFTA_RULE_COMPAT_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int nftnl_rule_parse_compat(struct nlattr *nest, struct nftnl_rule *r)
{
	struct nlattr *tb[NFTA_RULE_COMPAT_MAX+1] = {};

	if (mnl_attr_parse_nested(nest, nftnl_rule_parse_compat_cb, tb) < 0)
		return -1;

	if (tb[NFTA_RULE_COMPAT_PROTO]) {
		r->compat.proto =
			ntohl(mnl_attr_get_u32(tb[NFTA_RULE_COMPAT_PROTO]));
		r->flags |= (1 << NFTNL_RULE_COMPAT_PROTO);
	}
	if (tb[NFTA_RULE_COMPAT_FLAGS]) {
		r->compat.flags =
			ntohl(mnl_attr_get_u32(tb[NFTA_RULE_COMPAT_FLAGS]));
		r->flags |= (1 << NFTNL_RULE_COMPAT_FLAGS);
	}
	return 0;
}

int nftnl_rule_nlmsg_parse(const struct nlmsghdr *nlh, struct nftnl_rule *r)
{
	struct nlattr *tb[NFTA_RULE_MAX+1] = {};
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	int ret = 0;

	if (mnl_attr_parse(nlh, sizeof(*nfg), nftnl_rule_parse_attr_cb, tb) < 0)
		return -1;

	if (tb[NFTA_RULE_TABLE]) {
		xfree(r->table);
		r->table = strdup(mnl_attr_get_str(tb[NFTA_RULE_TABLE]));
		r->flags |= (1 << NFTNL_RULE_TABLE);
	}
	if (tb[NFTA_RULE_CHAIN]) {
		xfree(r->chain);
		r->chain = strdup(mnl_attr_get_str(tb[NFTA_RULE_CHAIN]));
		r->flags |= (1 << NFTNL_RULE_CHAIN);
	}
	if (tb[NFTA_RULE_HANDLE]) {
		r->handle = be64toh(mnl_attr_get_u64(tb[NFTA_RULE_HANDLE]));
		r->flags |= (1 << NFTNL_RULE_HANDLE);
	}
	if (tb[NFTA_RULE_EXPRESSIONS])
		ret = nftnl_rule_parse_expr(tb[NFTA_RULE_EXPRESSIONS], r);
	if (tb[NFTA_RULE_COMPAT])
		ret = nftnl_rule_parse_compat(tb[NFTA_RULE_COMPAT], r);
	if (tb[NFTA_RULE_POSITION]) {
		r->position = be64toh(mnl_attr_get_u64(tb[NFTA_RULE_POSITION]));
		r->flags |= (1 << NFTNL_RULE_POSITION);
	}
	if (tb[NFTA_RULE_USERDATA]) {
		const void *udata =
			mnl_attr_get_payload(tb[NFTA_RULE_USERDATA]);

		if (r->user.data)
			xfree(r->user.data);

		r->user.len = mnl_attr_get_payload_len(tb[NFTA_RULE_USERDATA]);

		r->user.data = malloc(r->user.len);
		if (r->user.data == NULL)
			return -1;

		memcpy(r->user.data, udata, r->user.len);
		r->flags |= (1 << NFTNL_RULE_USERDATA);
	}

	r->family = nfg->nfgen_family;
	r->flags |= (1 << NFTNL_RULE_FAMILY);

	return ret;
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_nlmsg_parse, nft_rule_nlmsg_parse);

#ifdef JSON_PARSING
int nftnl_jansson_parse_rule(struct nftnl_rule *r, json_t *tree,
			   struct nftnl_parse_err *err,
			   struct nftnl_set_list *set_list)
{
	json_t *root, *array;
	struct nftnl_expr *e;
	const char *str = NULL;
	uint64_t uval64;
	uint32_t uval32;
	int i, family;

	root = nftnl_jansson_get_node(tree, "rule", err);
	if (root == NULL)
		return -1;

	if (nftnl_jansson_node_exist(root, "family")) {
		if (nftnl_jansson_parse_family(root, &family, err) != 0)
			goto err;

		nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);
	}

	if (nftnl_jansson_node_exist(root, "table")) {
		str = nftnl_jansson_parse_str(root, "table", err);
		if (str == NULL)
			goto err;

		nftnl_rule_set_str(r, NFTNL_RULE_TABLE, str);
	}

	if (nftnl_jansson_node_exist(root, "chain")) {
		str = nftnl_jansson_parse_str(root, "chain", err);
		if (str == NULL)
			goto err;

		nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, str);
	}

	if (nftnl_jansson_node_exist(root, "handle")) {
		if (nftnl_jansson_parse_val(root, "handle", NFTNL_TYPE_U64, &uval64,
					  err) < 0)
			goto err;

		nftnl_rule_set_u64(r, NFTNL_RULE_HANDLE, uval64);
	}

	if (nftnl_jansson_node_exist(root, "compat_proto") ||
	    nftnl_jansson_node_exist(root, "compat_flags")) {
		if (nftnl_jansson_parse_val(root, "compat_proto", NFTNL_TYPE_U32,
					  &uval32, err) < 0)
			goto err;

		nftnl_rule_set_u32(r, NFTNL_RULE_COMPAT_PROTO, uval32);

		if (nftnl_jansson_parse_val(root, "compat_flags", NFTNL_TYPE_U32,
					  &uval32, err) < 0)
			goto err;

		nftnl_rule_set_u32(r, NFTNL_RULE_COMPAT_FLAGS, uval32);
	}

	if (nftnl_jansson_node_exist(root, "position")) {
		if (nftnl_jansson_parse_val(root, "position", NFTNL_TYPE_U64,
					  &uval64, err) < 0)
			goto err;

		nftnl_rule_set_u64(r, NFTNL_RULE_POSITION, uval64);
	}

	array = json_object_get(root, "expr");
	if (array == NULL) {
		err->error = NFTNL_PARSE_EMISSINGNODE;
		err->node_name = "expr";
		goto err;
	}

	for (i = 0; i < json_array_size(array); ++i) {

		e = nftnl_jansson_expr_parse(json_array_get(array, i), err,
					   set_list);
		if (e == NULL)
			goto err;

		nftnl_rule_add_expr(r, e);
	}

	return 0;
err:
	return -1;
}
#endif

static int nftnl_rule_json_parse(struct nftnl_rule *r, const void *json,
			       struct nftnl_parse_err *err,
			       enum nftnl_parse_input input,
			       struct nftnl_set_list *set_list)
{
#ifdef JSON_PARSING
	json_t *tree;
	json_error_t error;
	int ret;

	tree = nftnl_jansson_create_root(json, &error, err, input);
	if (tree == NULL)
		return -1;

	ret = nftnl_jansson_parse_rule(r, tree, err, set_list);

	nftnl_jansson_free_root(tree);
	return ret;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

#ifdef XML_PARSING
int nftnl_mxml_rule_parse(mxml_node_t *tree, struct nftnl_rule *r,
			struct nftnl_parse_err *err,
			struct nftnl_set_list *set_list)
{
	mxml_node_t *node;
	struct nftnl_expr *e;
	const char *table, *chain;
	int family;

	family = nftnl_mxml_family_parse(tree, "family", MXML_DESCEND_FIRST,
				       NFTNL_XML_MAND, err);
	if (family >= 0)
		nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);

	table = nftnl_mxml_str_parse(tree, "table", MXML_DESCEND_FIRST,
				   NFTNL_XML_MAND, err);
	if (table != NULL)
		nftnl_rule_set_str(r, NFTNL_RULE_TABLE, table);

	chain = nftnl_mxml_str_parse(tree, "chain", MXML_DESCEND_FIRST,
				   NFTNL_XML_MAND, err);
	if (chain != NULL)
		nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, chain);

	if (nftnl_mxml_num_parse(tree, "handle", MXML_DESCEND_FIRST, BASE_DEC,
			      &r->handle, NFTNL_TYPE_U64, NFTNL_XML_MAND, err) >= 0)
		r->flags |= (1 << NFTNL_RULE_HANDLE);

	if (nftnl_mxml_num_parse(tree, "compat_proto", MXML_DESCEND_FIRST,
			       BASE_DEC, &r->compat.proto, NFTNL_TYPE_U32,
			       NFTNL_XML_OPT, err) >= 0)
		r->flags |= (1 << NFTNL_RULE_COMPAT_PROTO);

	if (nftnl_mxml_num_parse(tree, "compat_flags", MXML_DESCEND_FIRST,
			       BASE_DEC, &r->compat.flags, NFTNL_TYPE_U32,
			       NFTNL_XML_OPT, err) >= 0)
		r->flags |= (1 << NFTNL_RULE_COMPAT_FLAGS);

	if (nftnl_rule_is_set(r, NFTNL_RULE_COMPAT_PROTO) !=
			nftnl_rule_is_set(r, NFTNL_RULE_COMPAT_FLAGS)) {
		errno = EINVAL;
	}

	if (nftnl_mxml_num_parse(tree, "position", MXML_DESCEND_FIRST,
			       BASE_DEC, &r->position, NFTNL_TYPE_U64,
			       NFTNL_XML_OPT, err) >= 0)
		r->flags |= (1 << NFTNL_RULE_POSITION);

	/* Iterating over <expr> */
	for (node = mxmlFindElement(tree, tree, "expr", "type",
				    NULL, MXML_DESCEND);
		node != NULL;
		node = mxmlFindElement(node, tree, "expr", "type",
				       NULL, MXML_DESCEND)) {
		e = nftnl_mxml_expr_parse(node, err, set_list);
		if (e == NULL)
			return -1;

		nftnl_rule_add_expr(r, e);
	}

	return 0;
}
#endif

static int nftnl_rule_xml_parse(struct nftnl_rule *r, const void *xml,
			      struct nftnl_parse_err *err,
			      enum nftnl_parse_input input,
			      struct nftnl_set_list *set_list)
{
#ifdef XML_PARSING
	int ret;
	mxml_node_t *tree = nftnl_mxml_build_tree(xml, "rule", err, input);
	if (tree == NULL)
		return -1;

	ret = nftnl_mxml_rule_parse(tree, r, err, set_list);
	mxmlDelete(tree);
	return ret;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nftnl_rule_do_parse(struct nftnl_rule *r, enum nftnl_parse_type type,
			     const void *data, struct nftnl_parse_err *err,
			     enum nftnl_parse_input input)
{
	int ret;
	struct nftnl_parse_err perr;

	switch (type) {
	case NFTNL_PARSE_XML:
		ret = nftnl_rule_xml_parse(r, data, &perr, input, NULL);
		break;
	case NFTNL_PARSE_JSON:
		ret = nftnl_rule_json_parse(r, data, &perr, input, NULL);
		break;
	default:
		ret = -1;
		errno = EOPNOTSUPP;
		break;
	}
	if (err != NULL)
		*err = perr;

	return ret;
}
int nftnl_rule_parse(struct nftnl_rule *r, enum nftnl_parse_type type,
		   const char *data, struct nftnl_parse_err *err)
{
	return nftnl_rule_do_parse(r, type, data, err, NFTNL_PARSE_BUFFER);
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_parse, nft_rule_parse);

int nftnl_rule_parse_file(struct nftnl_rule *r, enum nftnl_parse_type type,
			FILE *fp, struct nftnl_parse_err *err)
{
	return nftnl_rule_do_parse(r, type, fp, err, NFTNL_PARSE_FILE);
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_parse_file, nft_rule_parse_file);

static int nftnl_rule_snprintf_json(char *buf, size_t size, struct nftnl_rule *r,
					 uint32_t type, uint32_t flags)
{
	int ret, len = size, offset = 0;
	struct nftnl_expr *expr;

	ret = snprintf(buf, len, "{\"rule\":{");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (r->flags & (1 << NFTNL_RULE_FAMILY)) {
		ret = snprintf(buf+offset, len, "\"family\":\"%s\",",
			       nftnl_family2str(r->family));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->flags & (1 << NFTNL_RULE_TABLE)) {
		ret = snprintf(buf+offset, len, "\"table\":\"%s\",",
			       r->table);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->flags & (1 << NFTNL_RULE_CHAIN)) {
		ret = snprintf(buf+offset, len, "\"chain\":\"%s\",",
			       r->chain);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (r->flags & (1 << NFTNL_RULE_HANDLE)) {
		ret = snprintf(buf+offset, len, "\"handle\":%llu,",
			       (unsigned long long)r->handle);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->flags & (1 << NFTNL_RULE_COMPAT_PROTO) ||
	    r->flags & (1 << NFTNL_RULE_COMPAT_FLAGS)) {
		ret = snprintf(buf+offset, len, "\"compat_flags\":%u,"
					        "\"compat_proto\":%u,",
			       r->compat.flags, r->compat.proto);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->flags & (1 << NFTNL_RULE_POSITION)) {
		ret = snprintf(buf+offset, len, "\"position\":%"PRIu64",",
			       r->position);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	ret = snprintf(buf+offset, len, "\"expr\":[");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	list_for_each_entry(expr, &r->expr_list, head) {
		ret = snprintf(buf+offset, len,
			       "{\"type\":\"%s\",", expr->ops->name);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = expr->ops->snprintf(buf+offset, len, type, flags, expr);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		/*
		 * Remove comma from the first element if there is type
		 * key-value pair only. Example: "expr":[{"type":"log"}]
		 */
		if (ret == 0) {
			offset--;
			len--;
		}

		ret = snprintf(buf+offset, len, "},");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	}
	/* Remove comma from last element */
	offset--;
	ret = snprintf(buf+offset, len, "]}}");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int nftnl_rule_snprintf_xml(char *buf, size_t size, struct nftnl_rule *r,
				 uint32_t type, uint32_t flags)
{
	int ret, len = size, offset = 0;
	struct nftnl_expr *expr;

	ret = snprintf(buf, len, "<rule>");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (r->flags & (1 << NFTNL_RULE_FAMILY)) {
		ret = snprintf(buf+offset, len, "<family>%s</family>",
			       nftnl_family2str(r->family));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->flags & (1 << NFTNL_RULE_TABLE)) {
		ret = snprintf(buf+offset, len, "<table>%s</table>",
			       r->table);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->flags & (1 << NFTNL_RULE_CHAIN)) {
		ret = snprintf(buf+offset, len, "<chain>%s</chain>",
			       r->chain);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (r->flags & (1 << NFTNL_RULE_HANDLE)) {
		ret = snprintf(buf+offset, len, "<handle>%llu</handle>",
			       (unsigned long long)r->handle);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->compat.flags != 0 || r->compat.proto != 0) {
		ret = snprintf(buf+offset, len,
			       "<compat_flags>%u</compat_flags>"
			       "<compat_proto>%u</compat_proto>",
			       r->compat.flags, r->compat.proto);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->flags & (1 << NFTNL_RULE_POSITION)) {
		ret = snprintf(buf+offset, len,
			       "<position>%"PRIu64"</position>",
			       r->position);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	list_for_each_entry(expr, &r->expr_list, head) {
		ret = snprintf(buf+offset, len,
				"<expr type=\"%s\">", expr->ops->name);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nftnl_expr_snprintf(buf+offset, len, expr,
					     type, flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = snprintf(buf+offset, len, "</expr>");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	}
	ret = snprintf(buf+offset, len, "</rule>");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int nftnl_rule_snprintf_default(char *buf, size_t size, struct nftnl_rule *r,
				     uint32_t type, uint32_t flags)
{
	struct nftnl_expr *expr;
	int ret, len = size, offset = 0, i;

	if (r->flags & (1 << NFTNL_RULE_FAMILY)) {
		ret = snprintf(buf+offset, len, "%s ",
			       nftnl_family2str(r->family));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->flags & (1 << NFTNL_RULE_TABLE)) {
		ret = snprintf(buf+offset, len, "%s ",
			       r->table);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->flags & (1 << NFTNL_RULE_CHAIN)) {
		ret = snprintf(buf+offset, len, "%s ",
			       r->chain);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (r->flags & (1 << NFTNL_RULE_HANDLE)) {
		ret = snprintf(buf+offset, len, "%llu ",
			       (unsigned long long)r->handle);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->flags & (1 << NFTNL_RULE_POSITION)) {
		ret = snprintf(buf+offset, len, "%llu ",
			       (unsigned long long)r->position);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	ret = snprintf(buf+offset, len, "\n");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	list_for_each_entry(expr, &r->expr_list, head) {
		ret = snprintf(buf+offset, len, "  [ %s ", expr->ops->name);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nftnl_expr_snprintf(buf+offset, len, expr,
					     type, flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = snprintf(buf+offset, len, "]\n");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->user.len) {
		ret = snprintf(buf+offset, len, "  userdata = { ");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		for (i = 0; i < r->user.len; i++) {
			char *c = r->user.data;

			ret = snprintf(buf+offset, len, "%c",
				       isalnum(c[i]) ? c[i] : 0);
			SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
		}

		ret = snprintf(buf+offset, len, " }\n");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	}

	return offset;
}

static int nftnl_rule_cmd_snprintf(char *buf, size_t size, struct nftnl_rule *r,
				 uint32_t cmd, uint32_t type, uint32_t flags)
{
	int ret, len = size, offset = 0;
	uint32_t inner_flags = flags;

	inner_flags &= ~NFTNL_OF_EVENT_ANY;

	ret = nftnl_cmd_header_snprintf(buf + offset, len, cmd, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	switch(type) {
	case NFTNL_OUTPUT_DEFAULT:
		ret = nftnl_rule_snprintf_default(buf+offset, len, r, type,
						inner_flags);
		break;
	case NFTNL_OUTPUT_XML:
		ret = nftnl_rule_snprintf_xml(buf+offset, len, r, type,
					    inner_flags);
		break;
	case NFTNL_OUTPUT_JSON:
		ret = nftnl_rule_snprintf_json(buf+offset, len, r, type,
					     inner_flags);
		break;
	default:
		return -1;
	}

	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = nftnl_cmd_footer_snprintf(buf + offset, len, cmd, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

int nftnl_rule_snprintf(char *buf, size_t size, struct nftnl_rule *r,
		      uint32_t type, uint32_t flags)
{
	return nftnl_rule_cmd_snprintf(buf, size, r, nftnl_flag2cmd(flags), type,
				     flags);
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_snprintf, nft_rule_snprintf);

static inline int nftnl_rule_do_snprintf(char *buf, size_t size, void *r,
				       uint32_t cmd, uint32_t type,
				       uint32_t flags)
{
	return nftnl_rule_snprintf(buf, size, r, type, flags);
}

int nftnl_rule_fprintf(FILE *fp, struct nftnl_rule *r, uint32_t type,
		     uint32_t flags)
{
	return nftnl_fprintf(fp, r, NFTNL_CMD_UNSPEC, type, flags,
			   nftnl_rule_do_snprintf);
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_fprintf, nft_rule_fprintf);

int nftnl_expr_foreach(struct nftnl_rule *r,
                          int (*cb)(struct nftnl_expr *e, void *data),
                          void *data)
{
       struct nftnl_expr *cur, *tmp;
       int ret;

       list_for_each_entry_safe(cur, tmp, &r->expr_list, head) {
               ret = cb(cur, data);
               if (ret < 0)
                       return ret;
       }
       return 0;
}
EXPORT_SYMBOL_ALIAS(nftnl_expr_foreach, nft_rule_expr_foreach);

struct nftnl_expr_iter {
	struct nftnl_rule		*r;
	struct nftnl_expr	*cur;
};

struct nftnl_expr_iter *nftnl_expr_iter_create(struct nftnl_rule *r)
{
	struct nftnl_expr_iter *iter;

	iter = calloc(1, sizeof(struct nftnl_expr_iter));
	if (iter == NULL)
		return NULL;

	iter->r = r;
	if (list_empty(&r->expr_list))
		iter->cur = NULL;
	else
		iter->cur = list_entry(r->expr_list.next, struct nftnl_expr,
				       head);

	return iter;
}
EXPORT_SYMBOL_ALIAS(nftnl_expr_iter_create, nft_rule_expr_iter_create);

struct nftnl_expr *nftnl_expr_iter_next(struct nftnl_expr_iter *iter)
{
	struct nftnl_expr *expr = iter->cur;

	if (expr == NULL)
		return NULL;

	/* get next expression, if any */
	iter->cur = list_entry(iter->cur->head.next, struct nftnl_expr, head);
	if (&iter->cur->head == iter->r->expr_list.next)
		return NULL;

	return expr;
}
EXPORT_SYMBOL_ALIAS(nftnl_expr_iter_next, nft_rule_expr_iter_next);

void nftnl_expr_iter_destroy(struct nftnl_expr_iter *iter)
{
	xfree(iter);
}
EXPORT_SYMBOL_ALIAS(nftnl_expr_iter_destroy, nft_rule_expr_iter_destroy);

struct nftnl_rule_list {
	struct list_head list;
};

struct nftnl_rule_list *nftnl_rule_list_alloc(void)
{
	struct nftnl_rule_list *list;

	list = calloc(1, sizeof(struct nftnl_rule_list));
	if (list == NULL)
		return NULL;

	INIT_LIST_HEAD(&list->list);

	return list;
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_list_alloc, nft_rule_list_alloc);

void nftnl_rule_list_free(struct nftnl_rule_list *list)
{
	struct nftnl_rule *r, *tmp;

	list_for_each_entry_safe(r, tmp, &list->list, head) {
		list_del(&r->head);
		nftnl_rule_free(r);
	}
	xfree(list);
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_list_free, nft_rule_list_free);

int nftnl_rule_list_is_empty(struct nftnl_rule_list *list)
{
	return list_empty(&list->list);
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_list_is_empty, nft_rule_list_is_empty);

void nftnl_rule_list_add(struct nftnl_rule *r, struct nftnl_rule_list *list)
{
	list_add(&r->head, &list->list);
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_list_add, nft_rule_list_add);

void nftnl_rule_list_add_tail(struct nftnl_rule *r, struct nftnl_rule_list *list)
{
	list_add_tail(&r->head, &list->list);
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_list_add_tail, nft_rule_list_add_tail);

void nftnl_rule_list_del(struct nftnl_rule *r)
{
	list_del(&r->head);
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_list_del, nft_rule_list_del);

int nftnl_rule_list_foreach(struct nftnl_rule_list *rule_list,
			  int (*cb)(struct nftnl_rule *r, void *data),
			  void *data)
{
	struct nftnl_rule *cur, *tmp;
	int ret;

	list_for_each_entry_safe(cur, tmp, &rule_list->list, head) {
		ret = cb(cur, data);
		if (ret < 0)
			return ret;
	}
	return 0;
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_list_foreach, nft_rule_list_foreach);

struct nftnl_rule_list_iter {
	struct nftnl_rule_list	*list;
	struct nftnl_rule		*cur;
};

struct nftnl_rule_list_iter *nftnl_rule_list_iter_create(struct nftnl_rule_list *l)
{
	struct nftnl_rule_list_iter *iter;

	iter = calloc(1, sizeof(struct nftnl_rule_list_iter));
	if (iter == NULL)
		return NULL;

	iter->list = l;
	if (nftnl_rule_list_is_empty(l))
		iter->cur = NULL;
	else
		iter->cur = list_entry(l->list.next, struct nftnl_rule, head);

	return iter;
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_list_iter_create, nft_rule_list_iter_create);

struct nftnl_rule *nftnl_rule_list_iter_cur(struct nftnl_rule_list_iter *iter)
{
	return iter->cur;
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_list_iter_cur, nft_rule_list_iter_cur);

struct nftnl_rule *nftnl_rule_list_iter_next(struct nftnl_rule_list_iter *iter)
{
	struct nftnl_rule *r = iter->cur;

	if (r == NULL)
		return NULL;

	/* get next rule, if any */
	iter->cur = list_entry(iter->cur->head.next, struct nftnl_rule, head);
	if (&iter->cur->head == iter->list->list.next)
		return NULL;

	return r;
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_list_iter_next, nft_rule_list_iter_next);

void nftnl_rule_list_iter_destroy(struct nftnl_rule_list_iter *iter)
{
	xfree(iter);
}
EXPORT_SYMBOL_ALIAS(nftnl_rule_list_iter_destroy, nft_rule_list_iter_destroy);
