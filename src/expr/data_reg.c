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
#include <limits.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>
#include "internal.h"

#ifdef JSON_PARSING
static int nftnl_data_reg_verdict_json_parse(union nftnl_data_reg *reg, json_t *data,
					   struct nftnl_parse_err *err)
{
	int verdict;
	const char *verdict_str;
	const char *chain;

	verdict_str = nftnl_jansson_parse_str(data, "verdict", err);
	if (verdict_str == NULL)
		return DATA_NONE;

	if (nftnl_str2verdict(verdict_str, &verdict) != 0) {
		err->node_name = "verdict";
		err->error = NFTNL_PARSE_EBADTYPE;
		errno = EINVAL;
		return -1;
	}

	reg->verdict = (uint32_t)verdict;

	if (nftnl_jansson_node_exist(data, "chain")) {
		chain = nftnl_jansson_parse_str(data, "chain", err);
		if (chain == NULL)
			return DATA_NONE;

		reg->chain = strdup(chain);
	}

	return DATA_VERDICT;
}

static int nftnl_data_reg_value_json_parse(union nftnl_data_reg *reg, json_t *data,
					 struct nftnl_parse_err *err)
{
	int i;
	char node_name[6];

	if (nftnl_jansson_parse_val(data, "len", NFTNL_TYPE_U8, &reg->len, err) < 0)
			return DATA_NONE;

	for (i = 0; i < div_round_up(reg->len, sizeof(uint32_t)); i++) {
		sprintf(node_name, "data%d", i);

		if (nftnl_jansson_str2num(data, node_name, BASE_HEX,
					&reg->val[i], NFTNL_TYPE_U32, err) != 0)
			return DATA_NONE;
	}

	return DATA_VALUE;
}

int nftnl_data_reg_json_parse(union nftnl_data_reg *reg, json_t *data,
			    struct nftnl_parse_err *err)
{

	const char *type;

	type = nftnl_jansson_parse_str(data, "type", err);
	if (type == NULL)
		return -1;

	/* Select what type of parsing is needed */
	if (strcmp(type, "value") == 0)
		return nftnl_data_reg_value_json_parse(reg, data, err);
	else if (strcmp(type, "verdict") == 0)
		return nftnl_data_reg_verdict_json_parse(reg, data, err);

	return DATA_NONE;
}
#endif

#ifdef XML_PARSING
static int nftnl_data_reg_verdict_xml_parse(union nftnl_data_reg *reg,
					  mxml_node_t *tree,
					  struct nftnl_parse_err *err)
{
	int verdict;
	const char *verdict_str;
	const char *chain;

	verdict_str = nftnl_mxml_str_parse(tree, "verdict", MXML_DESCEND_FIRST,
					 NFTNL_XML_MAND, err);
	if (verdict_str == NULL)
		return DATA_NONE;

	if (nftnl_str2verdict(verdict_str, &verdict) != 0) {
		err->node_name = "verdict";
		err->error = NFTNL_PARSE_EBADTYPE;
		errno = EINVAL;
		return DATA_NONE;
	}

	reg->verdict = (uint32_t)verdict;

	chain = nftnl_mxml_str_parse(tree, "chain", MXML_DESCEND_FIRST,
				   NFTNL_XML_OPT, err);
	if (chain != NULL) {
		if (reg->chain)
			xfree(reg->chain);

		reg->chain = strdup(chain);
	}

	return DATA_VERDICT;
}

static int nftnl_data_reg_value_xml_parse(union nftnl_data_reg *reg,
					mxml_node_t *tree,
					struct nftnl_parse_err *err)
{
	int i;
	char node_name[6];

	if (nftnl_mxml_num_parse(tree, "len", MXML_DESCEND_FIRST, BASE_DEC,
			       &reg->len, NFTNL_TYPE_U8, NFTNL_XML_MAND, err) != 0)
		return DATA_NONE;

	for (i = 0; i < div_round_up(reg->len, sizeof(uint32_t)); i++) {
		sprintf(node_name, "data%d", i);

		if (nftnl_mxml_num_parse(tree, node_name, MXML_DESCEND_FIRST,
				       BASE_HEX, &reg->val[i], NFTNL_TYPE_U32,
				       NFTNL_XML_MAND, err) != 0)
			return DATA_NONE;
	}

	return DATA_VALUE;
}

int nftnl_data_reg_xml_parse(union nftnl_data_reg *reg, mxml_node_t *tree,
			   struct nftnl_parse_err *err)
{
	const char *type;
	mxml_node_t *node;

	node = mxmlFindElement(tree, tree, "reg", "type", NULL,
			       MXML_DESCEND_FIRST);
	if (node == NULL)
		goto err;

	type = mxmlElementGetAttr(node, "type");

	if (type == NULL)
		goto err;

	if (strcmp(type, "value") == 0)
		return nftnl_data_reg_value_xml_parse(reg, node, err);
	else if (strcmp(type, "verdict") == 0)
		return nftnl_data_reg_verdict_xml_parse(reg, node, err);

	return DATA_NONE;
err:
	errno = EINVAL;
	err->node_name = "reg";
	err->error = NFTNL_PARSE_EMISSINGNODE;
	return DATA_NONE;
}
#endif

static int
nftnl_data_reg_value_snprintf_json(char *buf, size_t size,
					   union nftnl_data_reg *reg,
					   uint32_t flags)
{
	int len = size, offset = 0, ret, i, j;
	uint32_t utemp;
	uint8_t *tmp;

	ret = snprintf(buf, len, "\"reg\":{\"type\":\"value\",");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = snprintf(buf+offset, len, "\"len\":%u,", reg->len);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	for (i = 0; i < div_round_up(reg->len, sizeof(uint32_t)); i++) {
		ret = snprintf(buf+offset, len, "\"data%d\":\"0x", i);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		utemp = htonl(reg->val[i]);
		tmp = (uint8_t *)&utemp;

		for (j = 0; j<sizeof(uint32_t); j++) {
			ret = snprintf(buf+offset, len, "%.02x", tmp[j]);
			SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
		}

		ret = snprintf(buf+offset, len, "\",");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	offset--;
	ret = snprintf(buf+offset, len, "}");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static
int nftnl_data_reg_value_snprintf_xml(char *buf, size_t size,
				    union nftnl_data_reg *reg, uint32_t flags)
{
	int len = size, offset = 0, ret, i, j;
	uint32_t be;
	uint8_t *tmp;

	ret = snprintf(buf, len, "<reg type=\"value\">");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = snprintf(buf+offset, len, "<len>%u</len>", reg->len);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	for (i = 0; i < div_round_up(reg->len, sizeof(uint32_t)); i++) {
		ret = snprintf(buf+offset, len, "<data%d>0x", i);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		be = htonl(reg->val[i]);
		tmp = (uint8_t *)&be;

		for (j = 0; j < sizeof(uint32_t); j++) {
			ret = snprintf(buf+offset, len, "%.02x", tmp[j]);
			SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
		}

		ret = snprintf(buf+offset, len, "</data%d>", i);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	ret = snprintf(buf+offset, len, "</reg>");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int
nftnl_data_reg_value_snprintf_default(char *buf, size_t size,
				    union nftnl_data_reg *reg, uint32_t flags)
{
	int len = size, offset = 0, ret, i;

	for (i = 0; i < div_round_up(reg->len, sizeof(uint32_t)); i++) {
		ret = snprintf(buf+offset, len, "0x%.8x ", reg->val[i]);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int
nftnl_data_reg_verdict_snprintf_def(char *buf, size_t size,
				  union nftnl_data_reg *reg, uint32_t flags)
{
	int len = size, offset = 0, ret = 0;

	ret = snprintf(buf, size, "%s ", nftnl_verdict2str(reg->verdict));
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (reg->chain != NULL) {
		ret = snprintf(buf+offset, len, "-> %s ", reg->chain);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int
nftnl_data_reg_verdict_snprintf_xml(char *buf, size_t size,
				  union nftnl_data_reg *reg, uint32_t flags)
{
	int len = size, offset = 0, ret = 0;

	ret = snprintf(buf, size, "<reg type=\"verdict\">"
		       "<verdict>%s</verdict>", nftnl_verdict2str(reg->verdict));
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (reg->chain != NULL) {
		ret = snprintf(buf+offset, len, "<chain>%s</chain>",
			       reg->chain);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	ret = snprintf(buf+offset, len, "</reg>");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int
nftnl_data_reg_verdict_snprintf_json(char *buf, size_t size,
				   union nftnl_data_reg *reg, uint32_t flags)
{
	int len = size, offset = 0, ret = 0;

	ret = snprintf(buf, size, "\"reg\":{\"type\":\"verdict\","
		       "\"verdict\":\"%s\"", nftnl_verdict2str(reg->verdict));
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (reg->chain != NULL) {
		ret = snprintf(buf+offset, len, ",\"chain\":\"%s\"",
			       reg->chain);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	ret = snprintf(buf+offset, len, "}");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

int nftnl_data_reg_snprintf(char *buf, size_t size, union nftnl_data_reg *reg,
			  uint32_t output_format, uint32_t flags, int reg_type)
{
	switch(reg_type) {
	case DATA_VALUE:
		switch(output_format) {
		case NFTNL_OUTPUT_DEFAULT:
			return nftnl_data_reg_value_snprintf_default(buf, size,
								   reg, flags);
		case NFTNL_OUTPUT_XML:
			return nftnl_data_reg_value_snprintf_xml(buf, size,
							       reg, flags);
		case NFTNL_OUTPUT_JSON:
			return nftnl_data_reg_value_snprintf_json(buf, size,
							       reg, flags);
		default:
			break;
		}
	case DATA_VERDICT:
	case DATA_CHAIN:
		switch(output_format) {
		case NFTNL_OUTPUT_DEFAULT:
			return nftnl_data_reg_verdict_snprintf_def(buf, size,
								 reg, flags);
		case NFTNL_OUTPUT_XML:
			return nftnl_data_reg_verdict_snprintf_xml(buf, size,
								 reg, flags);
		case NFTNL_OUTPUT_JSON:
			return nftnl_data_reg_verdict_snprintf_json(buf, size,
								  reg, flags);
		default:
			break;
		}
	default:
		break;
	}

	return -1;
}

static int nftnl_data_parse_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_DATA_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_DATA_VALUE:
		if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0)
			abi_breakage();
		break;
	case NFTA_DATA_VERDICT:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0)
			abi_breakage();
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int nftnl_verdict_parse_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_VERDICT_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_VERDICT_CODE:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	case NFTA_VERDICT_CHAIN:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			abi_breakage();
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int
nftnl_parse_verdict(union nftnl_data_reg *data, const struct nlattr *attr, int *type)
{
	struct nlattr *tb[NFTA_VERDICT_MAX+1];

	if (mnl_attr_parse_nested(attr, nftnl_verdict_parse_cb, tb) < 0) {
		perror("mnl_attr_parse_nested");
		return -1;
	}

	if (!tb[NFTA_VERDICT_CODE])
		return -1;

	data->verdict = ntohl(mnl_attr_get_u32(tb[NFTA_VERDICT_CODE]));

	switch(data->verdict) {
	case NF_ACCEPT:
	case NF_DROP:
	case NF_QUEUE:
	case NFT_CONTINUE:
	case NFT_BREAK:
	case NFT_RETURN:
		if (type)
			*type = DATA_VERDICT;
		data->len = sizeof(data->verdict);
		break;
	case NFT_JUMP:
	case NFT_GOTO:
		if (!tb[NFTA_VERDICT_CHAIN])
			return -1;

		data->chain = strdup(mnl_attr_get_str(tb[NFTA_VERDICT_CHAIN]));
		if (type)
			*type = DATA_CHAIN;
		break;
	default:
		return -1;
	}

	return 0;
}

static int
__nftnl_parse_data(union nftnl_data_reg *data, const struct nlattr *attr)
{
	void *orig = mnl_attr_get_payload(attr);
	uint32_t data_len = mnl_attr_get_payload_len(attr);

	if (data_len == 0)
		return -1;

	if (data_len > sizeof(data->val))
		return -1;

	memcpy(data->val, orig, data_len);
	data->len = data_len;

	return 0;
}

int nftnl_parse_data(union nftnl_data_reg *data, struct nlattr *attr, int *type)
{
	struct nlattr *tb[NFTA_DATA_MAX+1] = {};
	int ret = 0;

	if (mnl_attr_parse_nested(attr, nftnl_data_parse_cb, tb) < 0) {
		perror("mnl_attr_parse_nested");
		return -1;
	}
	if (tb[NFTA_DATA_VALUE]) {
		if (type)
			*type = DATA_VALUE;

		ret = __nftnl_parse_data(data, tb[NFTA_DATA_VALUE]);
		if (ret < 0)
			return ret;
	}
	if (tb[NFTA_DATA_VERDICT])
		ret = nftnl_parse_verdict(data, tb[NFTA_DATA_VERDICT], type);

	return ret;
}

void nftnl_free_verdict(union nftnl_data_reg *data)
{
	switch(data->verdict) {
	case NFT_JUMP:
	case NFT_GOTO:
		xfree(data->chain);
		break;
	default:
		break;
	}
}
