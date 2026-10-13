/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Robustness test for the packet parsers. Builds valid IPv4/IPv6 packets
 * (TCP/UDP, TLS ClientHello, DNS answers), mutates them randomly and feeds
 * them to handle_l3() and dns_learn() from the real engine source. Meant to be
 * built with -fsanitize=address,undefined (make fuzz); any memory error or
 * undefined behaviour aborts the run.
 *
 *   ./fuzz [iterations] [seed]
 */

#define main l7engine_main
#include "../src/main.c"
#undef main

#include <stdlib.h>

static uint32_t rng_state = 1;

static uint32_t
rnd(void)
{
	rng_state = rng_state * 1664525u + 1013904223u;
	return rng_state >> 8;
}

static void
put16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

/* TLS ClientHello with an SNI extension */
static int
build_clienthello(uint8_t *b, const char *sni)
{
	int n = 0, sl = (int)strlen(sni), ext_start, i;

	b[n++] = 0x16;
	b[n++] = 0x03;
	b[n++] = 0x01;
	n += 2;			/* record length, patched below */
	b[n++] = 0x01;		/* ClientHello */
	n += 3;			/* handshake length */
	b[n++] = 0x03;
	b[n++] = 0x03;
	for (i = 0; i < 32; i++)
		b[n++] = (uint8_t)rnd();
	b[n++] = 0;		/* session id */
	put16(b + n, 4);
	n += 2;
	b[n++] = 0x13;
	b[n++] = 0x01;
	b[n++] = 0xc0;
	b[n++] = 0x2f;
	b[n++] = 1;
	b[n++] = 0;		/* compression */
	ext_start = n;
	n += 2;
	put16(b + n, 0);	/* server_name */
	n += 2;
	put16(b + n, (uint16_t)(sl + 5));
	n += 2;
	put16(b + n, (uint16_t)(sl + 3));
	n += 2;
	b[n++] = 0;
	put16(b + n, (uint16_t)sl);
	n += 2;
	memcpy(b + n, sni, (size_t)sl);
	n += sl;
	put16(b + ext_start, (uint16_t)(n - ext_start - 2));
	put16(b + 3, (uint16_t)(n - 5));
	b[6] = 0;
	put16(b + 7, (uint16_t)(n - 9));
	return n;
}

static int
dns_put_name(uint8_t *b, const char *name)
{
	int n = 0;
	const char *p = name;

	while (*p) {
		const char *dot = strchr(p, '.');
		int l = dot ? (int)(dot - p) : (int)strlen(p);

		b[n++] = (uint8_t)l;
		memcpy(b + n, p, (size_t)l);
		n += l;
		p += l + (dot ? 1 : 0);
	}
	b[n++] = 0;
	return n;
}

/* DNS response with two A records and a CNAME-style compressed name */
static int
build_dns_answer(uint8_t *b, const char *name)
{
	int n = 12, q;

	memset(b, 0, 12);
	put16(b, 0x1234);
	put16(b + 2, 0x8180);
	put16(b + 4, 1);
	put16(b + 6, 2);
	q = n;
	n += dns_put_name(b + n, name);
	put16(b + n, 1);
	put16(b + n + 2, 1);
	n += 4;
	for (int i = 0; i < 2; i++) {
		put16(b + n, (uint16_t)(0xc000 | q));
		put16(b + n + 2, 1);
		put16(b + n + 4, 1);
		b[n + 6] = 0;
		b[n + 7] = 0;
		put16(b + n + 8, 60);
		put16(b + n + 10, 4);
		b[n + 12] = 142;
		b[n + 13] = 250;
		b[n + 14] = 1;
		b[n + 15] = (uint8_t)(i + 1);
		n += 16;
	}
	return n;
}

static int
wrap_ip4(uint8_t *out, int proto, int sport, int dport, const uint8_t *pl, int pll)
{
	int n = 20, l4;

	memset(out, 0, 20);
	out[0] = 0x45;
	out[8] = 64;
	out[9] = (uint8_t)proto;
	out[12] = 10; out[13] = 77; out[14] = 0; out[15] = 2;
	out[16] = 142; out[17] = 250; out[18] = 1; out[19] = 1;
	if (proto == IPPROTO_TCP) {
		memset(out + n, 0, 20);
		put16(out + n, (uint16_t)sport);
		put16(out + n + 2, (uint16_t)dport);
		out[n + 12] = 0x50;
		out[n + 13] = 0x18;
		l4 = 20;
	} else {
		put16(out + n, (uint16_t)sport);
		put16(out + n + 2, (uint16_t)dport);
		put16(out + n + 4, (uint16_t)(8 + pll));
		l4 = 8;
	}
	memcpy(out + n + l4, pl, (size_t)pll);
	n += l4 + pll;
	put16(out + 2, (uint16_t)n);
	return n;
}

static int
wrap_ip6(uint8_t *out, int proto, int sport, int dport, const uint8_t *pl, int pll)
{
	int l4 = proto == IPPROTO_TCP ? 20 : 8;

	memset(out, 0, 40);
	out[0] = 0x60;
	out[6] = (uint8_t)proto;
	out[7] = 64;
	out[8] = 0x20; out[9] = 0x01; out[23] = 2;
	out[24] = 0x20; out[25] = 0x01; out[39] = 1;
	memset(out + 40, 0, (size_t)l4);
	put16(out + 40, (uint16_t)sport);
	put16(out + 42, (uint16_t)dport);
	if (proto == IPPROTO_TCP)
		out[40 + 12] = 0x50;
	else
		put16(out + 44, (uint16_t)(8 + pll));
	memcpy(out + 40 + l4, pl, (size_t)pll);
	put16(out + 4, (uint16_t)(l4 + pll));
	return 40 + l4 + pll;
}

static void
mutate(uint8_t *b, int *len)
{
	int k = 1 + (int)(rnd() % 6);

	while (k--) {
		switch (rnd() % 5) {
		case 0:
			b[rnd() % (uint32_t)*len] = (uint8_t)rnd();
			break;
		case 1:
			b[rnd() % (uint32_t)*len] ^= (uint8_t)(1u << (rnd() % 8));
			break;
		case 2:
			*len = 1 + (int)(rnd() % (uint32_t)*len);	/* truncate */
			break;
		case 3: {
			int a = (int)(rnd() % (uint32_t)*len), c = (int)(rnd() % (uint32_t)*len);
			uint8_t t = b[a];

			b[a] = b[c];
			b[c] = t;
			break;
		}
		default:
			b[rnd() % (uint32_t)*len] = (rnd() & 1) ? 0xff : 0x00;
		}
	}
}

int
main(int argc, char **argv)
{
	long iters = argc > 1 ? atol(argv[1]) : 200000;
	long it;
	uint8_t pl[1500], pkt[1600], copy[1600];
	static const char *names[] = { "www.youtube.com", "github.com", "a.b.c.d.example.org",
	    "x", "www.facebook.com", "very-long-label-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.net" };
	policy_t pol[2];
	uint64_t t = 1700000000000ull;

	rng_state = argc > 2 ? (uint32_t)atol(argv[2]) : 12345u;
	if (ndpi_start() != 0) {
		fprintf(stderr, "nDPI init failed\n");
		return 1;
	}
	tabsz = 1 << 12;
	tab = calloc(tabsz, sizeof(*tab));
	memset(&cfg, 0, sizeof(cfg));
	cfg.max_flows = 5000;
	cfg.flow_timeout = 5;
	cfg.enforce = 0;		/* never touch pf */
	memset(pol, 0, sizeof(pol));
	pol[0].id = 1;
	snprintf(pol[0].name, sizeof(pol[0].name), "fuzz-block");
	pol[0].action = ACT_BLOCK;
	snprintf(pol[0].apps[0], sizeof(pol[0].apps[0]), "youtube");
	pol[0].napps = 1;
	snprintf(pol[0].hosts[0], sizeof(pol[0].hosts[0]), "github.com");
	pol[0].nhosts = 1;
	pol[0].day_mask = 0x7f;
	snprintf(pol[0].table, sizeof(pol[0].table), "l7_blk_1");
	policy_set(pol, 1);

	for (it = 0; it < iters; it++) {
		const char *name = names[rnd() % (sizeof(names) / sizeof(names[0]))];
		int pll, len, kind = (int)(rnd() % 6);

		switch (kind) {
		case 0:
			pll = build_clienthello(pl, name);
			len = wrap_ip4(pkt, IPPROTO_TCP, 40000 + (int)(rnd() % 50), 443, pl, pll);
			break;
		case 1:
			pll = build_clienthello(pl, name);
			len = wrap_ip6(pkt, IPPROTO_TCP, 40000 + (int)(rnd() % 50), 443, pl, pll);
			break;
		case 2:
			pll = build_dns_answer(pl, name);
			len = wrap_ip4(pkt, IPPROTO_UDP, 53, 40000 + (int)(rnd() % 50), pl, pll);
			pkt[12] = 10; pkt[13] = 77; pkt[14] = 0; pkt[15] = 1;
			pkt[16] = 10; pkt[17] = 77; pkt[18] = 0; pkt[19] = 2;
			break;
		case 3:
			pll = build_dns_answer(pl, name);
			len = wrap_ip6(pkt, IPPROTO_UDP, 53, 40000 + (int)(rnd() % 50), pl, pll);
			break;
		case 4:
			pll = (int)(rnd() % 600);
			for (int i = 0; i < pll; i++)
				pl[i] = (uint8_t)rnd();
			len = wrap_ip4(pkt, (rnd() & 1) ? IPPROTO_TCP : IPPROTO_UDP, 1024 + (int)(rnd() % 100),
			    (rnd() & 1) ? 80 : 53, pl, pll);
			break;
		default:
			len = (int)(rnd() % 120);
			if (len == 0)
				len = 1;
			for (int i = 0; i < len; i++)
				pkt[i] = (uint8_t)rnd();
			break;
		}
		if (rnd() % 4 != 0)
			mutate(pkt, &len);
		/* copy to an exact-size heap buffer so ASan catches over-reads */
		{
			uint8_t *exact = malloc((size_t)len);

			memcpy(exact, pkt, (size_t)len);
			memcpy(copy, pkt, (size_t)len);
			handle_l3(exact, len, t, "fz0");
			free(exact);
		}
		t += 1 + (rnd() % 50);
		if (it % 5000 == 0)
			sweep(0);
	}
	sweep(1);
	printf("fuzz ok: %ld packets, %llu flows, %llu classified, dns learned %llu\n", iters,
	    (unsigned long long)flows_total, (unsigned long long)classified_total,
	    (unsigned long long)dns_learned_total);
	return 0;
}
