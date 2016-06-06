/*
 * (C) 2012-2016 by Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2016 by Carlos Falgueras García <carlosfg@riseup.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <libnftnl/udata.h>
#include <udata.h>
#include <utils.h>

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

struct nftnl_udata_buf *nftnl_udata_buf_alloc(uint32_t data_size)
{
	struct nftnl_udata_buf *buf;

	buf = malloc(sizeof(struct nftnl_udata_buf) + data_size);
	if (!buf)
		return NULL;
	buf->size = data_size;
	buf->end = buf->data;

	return buf;
}
EXPORT_SYMBOL(nftnl_udata_buf_alloc);

void nftnl_udata_buf_free(const struct nftnl_udata_buf *buf)
{
	xfree(buf);
}
EXPORT_SYMBOL(nftnl_udata_buf_free);

uint32_t nftnl_udata_buf_len(const struct nftnl_udata_buf *buf)
{
	return (uint32_t)(buf->end - buf->data);
}
EXPORT_SYMBOL(nftnl_udata_buf_len);

void *nftnl_udata_buf_data(const struct nftnl_udata_buf *buf)
{
	return (void *)buf->data;
}
EXPORT_SYMBOL(nftnl_udata_buf_data);

void nftnl_udata_buf_put(struct nftnl_udata_buf *buf, const void *data,
			 uint32_t len)
{
	memcpy(buf->data, data, len <= buf->size ? len : buf->size);
	buf->end = buf->data + len;
}
EXPORT_SYMBOL(nftnl_udata_buf_put);

struct nftnl_udata *nftnl_udata_start(const struct nftnl_udata_buf *buf)
{
	return (struct nftnl_udata *)buf->data;
}
EXPORT_SYMBOL(nftnl_udata_start);

struct nftnl_udata *nftnl_udata_end(const struct nftnl_udata_buf *buf)
{
	return (struct nftnl_udata *)buf->end;
}
EXPORT_SYMBOL(nftnl_udata_end);

bool nftnl_udata_put(struct nftnl_udata_buf *buf, uint8_t type, uint32_t len,
		     const void *value)
{
	struct nftnl_udata *attr;

	if (buf->size < len + sizeof(struct nftnl_udata))
		return false;

	attr = (struct nftnl_udata *)buf->end;
	attr->len  = len;
	attr->type = type;
	memcpy(attr->value, value, len);

	buf->end = (char *)nftnl_udata_next(attr);

	return true;
}
EXPORT_SYMBOL(nftnl_udata_put);

bool nftnl_udata_put_strz(struct nftnl_udata_buf *buf, uint8_t type,
			  const char *strz)
{
	return nftnl_udata_put(buf, type, strlen(strz) + 1, strz);
}
EXPORT_SYMBOL(nftnl_udata_put_strz);

uint8_t nftnl_udata_type(const struct nftnl_udata *attr)
{
	return attr->type;
}
EXPORT_SYMBOL(nftnl_udata_type);

uint8_t nftnl_udata_len(const struct nftnl_udata *attr)
{
	return attr->len;
}
EXPORT_SYMBOL(nftnl_udata_len);

void *nftnl_udata_get(const struct nftnl_udata *attr)
{
	return (void *)attr->value;
}
EXPORT_SYMBOL(nftnl_udata_get);

struct nftnl_udata *nftnl_udata_next(const struct nftnl_udata *attr)
{
	return (struct nftnl_udata *)&attr->value[attr->len];
}
EXPORT_SYMBOL(nftnl_udata_next);

int nftnl_udata_parse(const void *data, uint32_t data_len, nftnl_udata_cb_t cb,
		      void *cb_data)
{
	int ret = 0;
	const struct nftnl_udata *attr;

	nftnl_udata_for_each_data(data, data_len, attr) {
		ret = cb(attr, cb_data);
		if (ret < 0)
			return ret;
	}

	return ret;
}
EXPORT_SYMBOL(nftnl_udata_parse);
