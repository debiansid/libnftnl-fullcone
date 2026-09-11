/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <stdio.h>
#include <stdlib.h>

#include <linux/netfilter/nf_tables.h>
#include <libmnl/libmnl.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

static int test_ok = 1;

static void print_err(const char *msg)
{
	test_ok = 0;
	printf("\033[31mERROR:\e[0m %s\n", msg);
}

static void cmp_nftnl_expr(struct nftnl_expr *a, struct nftnl_expr *b)
{
	if (nftnl_expr_get_u32(a, NFTNL_EXPR_FULLCONE_FLAGS) !=
	    nftnl_expr_get_u32(b, NFTNL_EXPR_FULLCONE_FLAGS))
		print_err("Expr NFTNL_EXPR_FULLCONE_FLAGS mismatches");
	if (nftnl_expr_get_u32(a, NFTNL_EXPR_FULLCONE_REG_PROTO_MIN) !=
	    nftnl_expr_get_u32(b, NFTNL_EXPR_FULLCONE_REG_PROTO_MIN))
		print_err("Expr NFTNL_EXPR_FULLCONE_REG_PROTO_MIN mismatches");
	if (nftnl_expr_get_u32(a, NFTNL_EXPR_FULLCONE_REG_PROTO_MAX) !=
	    nftnl_expr_get_u32(b, NFTNL_EXPR_FULLCONE_REG_PROTO_MAX))
		print_err("Expr NFTNL_EXPR_FULLCONE_REG_PROTO_MAX mismatches");
}

int main(int argc, char *argv[])
{
	struct nftnl_rule *a = nftnl_rule_alloc();
	struct nftnl_rule *b = nftnl_rule_alloc();
	struct nftnl_expr *ex, *rule_a, *rule_b;
	struct nftnl_expr_iter *iter_a, *iter_b;
	struct nlmsghdr *nlh;
	char buf[4096];

	if (!a || !b)
		print_err("OOM");
	ex = nftnl_expr_alloc("fullcone");
	if (!ex)
		print_err("OOM");

	nftnl_expr_set_u32(ex, NFTNL_EXPR_FULLCONE_FLAGS, 0x1234568);
	nftnl_expr_set_u32(ex, NFTNL_EXPR_FULLCONE_REG_PROTO_MIN, 0x5432178);
	nftnl_expr_set_u32(ex, NFTNL_EXPR_FULLCONE_REG_PROTO_MAX, 0x8765421);
	nftnl_rule_add_expr(a, ex);

	nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_NEWRULE, AF_INET, 0, 1234);
	nftnl_rule_nlmsg_build_payload(nlh, a);
	if (nftnl_rule_nlmsg_parse(nlh, b) < 0)
		print_err("parsing problems");

	iter_a = nftnl_expr_iter_create(a);
	iter_b = nftnl_expr_iter_create(b);
	rule_a = nftnl_expr_iter_next(iter_a);
	rule_b = nftnl_expr_iter_next(iter_b);
	if (!rule_a || !rule_b)
		print_err("OOM");
	else
		cmp_nftnl_expr(rule_a, rule_b);

	if (nftnl_expr_iter_next(iter_a) || nftnl_expr_iter_next(iter_b))
		print_err("More 1 expr.");

	nftnl_expr_iter_destroy(iter_a);
	nftnl_expr_iter_destroy(iter_b);
	nftnl_rule_free(a);
	nftnl_rule_free(b);

	if (!test_ok)
		return EXIT_FAILURE;
	printf("%s: \033[32mOK\e[0m\n", argv[0]);
	return EXIT_SUCCESS;
}
