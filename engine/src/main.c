/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * l7engine - captures packets with libpcap, tracks flows, classifies them with
 * nDPI, stores them in SQLite and enforces block policies through pf tables.
 *
 *   l7engine -c /usr/local/etc/layer7security/engine.conf   run (foreground)
 *   l7engine --list-apps | --list-categories                JSON for the GUI
 *   l7engine --version
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>

#include <pcap/pcap.h>
#include "ndpi_api.h"

#include "l7.h"

#define ETH_HLEN 14
#define SNAPLEN 1600
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04

typedef struct flow {
	struct flow *next;
	uint64_t db_id;
	addr_t cli, srv;
	uint16_t cport, sport;
	uint8_t l4;
	uint8_t classified, decided, ended;
	uint8_t action;
	uint32_t hash;
	uint64_t t_first_ms, t_last_ms;
	time_t t_written;
	uint64_t bytes[2], pkts[2];
	uint32_t npkts;
	char iface[16];
	char master[40], app[48], cat[40], host[96], policy[64];
	char country[4];	/* server country, empty when unknown or local */
	char ai[24];		/* AI service id, empty for other traffic */
	struct ndpi_flow_struct *nf;
	uint8_t dirty;
} flow_t;

typedef struct {
	pcap_t *h;
	char name[32];
	int dlt;
	int fd;
} cap_t;

static config_t cfg;
static struct ndpi_global_context *g_ctx;
static struct ndpi_detection_module_struct *mod;
static flow_t **tab;
static size_t tabsz = 1 << 16;
static size_t nflows;
static uint64_t flows_total, classified_total, pkts_total, bytes_total;
static time_t started;
static volatile sig_atomic_t stop_flag, reload_flag;
static cap_t caps[L7_MAX_IFACES];
static int skip_tagged;
static const char *cfg_path = "/usr/local/etc/layer7security/engine.conf";
int g_debug;

void
l7_log(const char *fmt, ...)
{
	va_list ap;
	char ts[32];
	time_t now = time(NULL);
	struct tm tm;

	localtime_r(&now, &tm);
	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);
	fprintf(stderr, "%s ", ts);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static void
on_signal(int s)
{
	if (s == SIGHUP)
		reload_flag = 1;
	else
		stop_flag = 1;
}

/* ---------------------------------------------------------------- nDPI */

static int
ndpi_start(void)
{
	if ((g_ctx = ndpi_global_init()) == NULL)
		return -1;
#if defined(NDPI_MAJOR) && NDPI_MAJOR >= 6
	/*
	 * nDPI 6 asks which license applies. The default is the not-for-profit
	 * LGPL mode, which suits this open-source project; a commercial
	 * deployment must hold a license from ntop and build with
	 * -DL7_NDPI_LICENSE=<enum ndpi_license_type value>.
	 */
#ifndef L7_NDPI_LICENSE
#define L7_NDPI_LICENSE NDPI_LICENSE_NOT_FOR_PROFIT_LGPL
#endif
	if ((mod = ndpi_init_detection_module(g_ctx, L7_NDPI_LICENSE)) == NULL)
		return -1;
#else
	if ((mod = ndpi_init_detection_module(g_ctx)) == NULL)
		return -1;
#endif
	if (ndpi_finalize_initialization(mod) != 0)
		return -1;
	return 0;
}

static void
list_apps(void)
{
	unsigned i, n;
	int first = 1;

	if (ndpi_start() != 0) {
		fprintf(stderr, "nDPI init failed\n");
		exit(1);
	}
	n = ndpi_get_num_protocols(mod);
	printf("[");
	for (i = 1; i < n; i++) {
		ndpi_protocol pr;
		const char *name = ndpi_get_proto_name(mod, (u_int16_t)i);
		const char *cat;

		if (name == NULL || *name == '\0')
			continue;
		memset(&pr, 0, sizeof(pr));
		pr.proto.app_protocol = (u_int16_t)i;
		cat = ndpi_category_get_name(mod, ndpi_get_proto_category(mod, pr));
		printf("%s{\"id\":%u,\"name\":\"%s\",\"category\":\"%s\"}", first ? "" : ",", i,
		    name, cat ? cat : "");
		first = 0;
	}
	printf("]\n");
}

static void
list_categories(void)
{
	int i, first = 1;

	if (ndpi_start() != 0) {
		fprintf(stderr, "nDPI init failed\n");
		exit(1);
	}
	printf("[");
	for (i = 0; i < NDPI_PROTOCOL_NUM_CATEGORIES; i++) {
		const char *n = ndpi_category_get_name(mod, (ndpi_protocol_category_t)i);

		if (n == NULL || *n == '\0')
			continue;
		printf("%s\"%s\"", first ? "" : ",", n);
		first = 0;
	}
	printf("]\n");
}

/* ---------------------------------------------------------------- flows */

static uint32_t
fnv(const void *p, size_t n, uint32_t h)
{
	const uint8_t *b = p;

	while (n--) {
		h ^= *b++;
		h *= 16777619u;
	}
	return h;
}

static int
addr_cmp(const addr_t *a, const addr_t *b)
{
	if (a->af != b->af)
		return a->af - b->af;
	return memcmp(a->a, b->a, a->af == AF_INET ? 4 : 16);
}

static uint32_t
tuple_hash(const addr_t *a, uint16_t pa, const addr_t *b, uint16_t pb, uint8_t l4)
{
	uint32_t h = 2166136261u;
	const addr_t *lo = a, *hi = b;
	uint16_t plo = pa, phi = pb;

	if (addr_cmp(a, b) > 0 || (addr_cmp(a, b) == 0 && pa > pb)) {
		lo = b;
		hi = a;
		plo = pb;
		phi = pa;
	}
	h = fnv(lo->a, lo->af == AF_INET ? 4 : 16, h);
	h = fnv(hi->a, hi->af == AF_INET ? 4 : 16, h);
	h = fnv(&plo, 2, h);
	h = fnv(&phi, 2, h);
	return fnv(&l4, 1, h);
}

static void
flow_free(flow_t *f)
{
	if (f->nf)
		ndpi_free_flow(f->nf);
	free(f);
}

static void
flow_persist(flow_t *f, int final)
{
	char s[64], d[64];
	time_t now = time(NULL);
	const char *act = f->action == ACT_BLOCK ? "block" : f->action == ACT_ALLOW ? "allow" : "monitor";

	if (f->db_id == 0) {
		if (!f->classified && f->npkts < 2 && !final)
			return;
		if (f->npkts < 2 && !f->classified)
			return;	/* scan noise */
		addr_str(&f->cli, s, sizeof(s));
		addr_str(&f->srv, d, sizeof(d));
		f->db_id = store_flow_insert(f->iface, f->l4, s, d, f->cport, f->sport, f->master,
		    f->app, f->cat, f->host, (time_t)(f->t_first_ms / 1000), act, f->policy, f->country, f->ai);
		f->t_written = now;
		if (f->db_id == 0)
			return;
	} else if (!final && (!f->dirty || now - f->t_written < 5)) {
		return;
	}
	store_flow_update(f->db_id, (time_t)(f->t_last_ms / 1000), f->bytes[0], f->bytes[1],
	    f->pkts[0], f->pkts[1], f->master, f->app, f->cat, f->host, act, f->policy, f->ai);
	f->t_written = now;
	f->dirty = 0;
}

/* one "ai-use" / "ai-block" event per client and AI service every five minutes */
static int
ai_event_due(const char *cli, const char *ai)
{
	static struct {
		char key[96];
		time_t ts;
	} t[256];
	char key[96];
	time_t now = time(NULL);
	uint32_t h = 2166136261u;
	size_t i, slot;
	int k;

	snprintf(key, sizeof(key), "%s|%s", cli, ai);
	h = fnv(key, strlen(key), h);
	slot = h % 256;
	for (k = 0; k < 8; k++) {
		i = (slot + (size_t)k) % 256;
		if (t[i].key[0] == '\0' || strcmp(t[i].key, key) == 0) {
			int due = t[i].key[0] == '\0' || now - t[i].ts >= 300;

			if (due) {
				snprintf(t[i].key, sizeof(t[i].key), "%s", key);
				t[i].ts = now;
			}
			return due;
		}
	}
	/* crowded: overwrite the home slot */
	snprintf(t[slot].key, sizeof(t[slot].key), "%s", key);
	t[slot].ts = now;
	return 1;
}

/* AI service matched by a flow: tag it, log it, steer it to the proxy / off QUIC */
static void
ai_flow_actions(flow_t *f, const policy_t *p)
{
	char s[64], d[64], detail[96];

	addr_str(&f->cli, s, sizeof(s));
	addr_str(&f->srv, d, sizeof(d));
	if (p->ai[0] && ai_event_due(s, p->ai)) {
		snprintf(detail, sizeof(detail), "%s %s%s", p->action == ACT_BLOCK ? "blocked" :
		    p->action == ACT_ALLOW ? "allowed" : "monitored", f->l4 == IPPROTO_UDP ? "udp/" : "tcp/",
		    f->l4 == IPPROTO_UDP ? "quic" : "tls");
		store_event(p->action == ACT_BLOCK ? "ai-block" : "ai-use", s, d, p->ai, "AI", f->host,
		    p->name, detail);
	}
	if (p->action == ACT_BLOCK)
		return;
	/* newly learned addresses kill the uninspected first connection so the retry is proxied */
	if (p->inspect && cfg.ai_inspect && f->l4 == IPPROTO_TCP)
		pf_add_table(&cfg, AI_TABLE_BUMP, &f->cli, &f->srv, 1, 1);
	if (p->quic && cfg.ai_quic == 1)
		pf_add_table(&cfg, AI_TABLE_QUIC, &f->cli, &f->srv, 1, f->l4 == IPPROTO_UDP);
}

static void
flow_decide(flow_t *f)
{
	policy_t *p;

	/*
	 * DNS lookups are never policy targets: blocking the resolver would
	 * cut the client off. DNS answers are handled by dns_learn() and DNS
	 * filtering instead.
	 */
	if (f->cport == 53 || f->sport == 53 || f->cport == 5353 || f->sport == 5353 ||
	    strcmp(f->master, "DNS") == 0 || strcmp(f->app, "DNS") == 0) {
		f->decided = 1;
		return;
	}
	p = policy_find(&f->cli, f->master, f->app, f->cat, f->host);
	if (p == NULL) {
		if (f->npkts > 12)
			f->decided = 1;
		return;
	}
	f->decided = 1;
	snprintf(f->policy, sizeof(f->policy), "%s", p->name);
	f->action = (uint8_t)p->action;
	f->dirty = 1;
	if (p->ai[0] || p->inspect || p->quic) {
		snprintf(f->ai, sizeof(f->ai), "%s", p->ai);
		ai_flow_actions(f, p);
	}
	if (p->action == ACT_BLOCK) {
		char s[64], d[64];

		if (pf_block(&cfg, p, &f->cli, &f->srv)) {
			addr_str(&f->cli, s, sizeof(s));
			addr_str(&f->srv, d, sizeof(d));
			store_event("block", s, d, f->app, f->cat, f->host, p->name, p->table);
			l7_log("BLOCK %s -> %s app=%s cat=%s host=%s policy=%s", s, d, f->app, f->cat,
			    f->host, p->name);
		}
	}
}

static void
flow_names(flow_t *f, const ndpi_protocol *pr)
{
	uint16_t m = pr->proto.master_protocol, a = pr->proto.app_protocol;
	const char *mn, *an, *cn;

	mn = ndpi_get_proto_name(mod, m ? m : a);
	an = ndpi_get_proto_name(mod, a ? a : m);
	cn = ndpi_category_get_name(mod, pr->category);
	snprintf(f->master, sizeof(f->master), "%s", mn ? mn : "Unknown");
	snprintf(f->app, sizeof(f->app), "%s", an ? an : "Unknown");
	snprintf(f->cat, sizeof(f->cat), "%s", cn ? cn : "Unspecified");
	if (f->nf && f->nf->host_server_name[0])
		snprintf(f->host, sizeof(f->host), "%s", f->nf->host_server_name);
}

static void
flow_classify(flow_t *f, const uint8_t *l3, uint16_t l3len, uint64_t ts_ms, int dir)
{
	struct ndpi_flow_input_info in;
	ndpi_protocol pr;
	int known;

	if (f->nf == NULL)
		return;
	memset(&in, 0, sizeof(in));
	in.in_pkt_dir = dir == 0 ? NDPI_IN_PKT_DIR_C_TO_S : NDPI_IN_PKT_DIR_S_TO_C;
	pr = ndpi_detection_process_packet(mod, f->nf, l3, l3len, ts_ms, &in);

	if (f->npkts >= 16 && pr.state != NDPI_STATE_CLASSIFIED)
		pr = ndpi_detection_giveup(mod, f->nf);
	known = pr.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN ||
	    pr.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN;
	if (known || pr.state == NDPI_STATE_CLASSIFIED) {
		int first = !f->classified;

		flow_names(f, &pr);
		f->dirty = 1;
		if (first) {
			f->classified = 1;
			classified_total++;
		}
	}
	if (f->classified && !f->decided)
		flow_decide(f);
	if (pr.state == NDPI_STATE_CLASSIFIED || (f->npkts >= 16 && f->decided)) {
		/* nDPI is done: keep the names, release the heavy state */
		ndpi_free_flow(f->nf);
		f->nf = NULL;
	}
	if (f->classified)
		flow_persist(f, 0);
}

static flow_t *
flow_get(const addr_t *a, uint16_t pa, const addr_t *b, uint16_t pb, uint8_t l4, int *dir,
    const char *iface, uint64_t ts_ms, uint8_t tcpflags)
{
	uint32_t h = tuple_hash(a, pa, b, pb, l4);
	size_t idx = h & (tabsz - 1);
	flow_t *f;

	for (f = tab[idx]; f; f = f->next) {
		if (f->hash != h || f->l4 != l4)
			continue;
		if (addr_cmp(&f->cli, a) == 0 && addr_cmp(&f->srv, b) == 0 && f->cport == pa && f->sport == pb) {
			*dir = 0;
			return f;
		}
		if (addr_cmp(&f->cli, b) == 0 && addr_cmp(&f->srv, a) == 0 && f->cport == pb && f->sport == pa) {
			*dir = 1;
			return f;
		}
	}
	if (nflows >= (size_t)cfg.max_flows)
		return NULL;
	/* a bare reset never starts a flow: it only trails a connection we already dropped */
	if (l4 == IPPROTO_TCP && (tcpflags & TCP_RST) && !(tcpflags & TCP_SYN))
		return NULL;
	if ((f = calloc(1, sizeof(*f))) == NULL)
		return NULL;
	f->nf = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
	if (f->nf == NULL) {
		free(f);
		return NULL;
	}
	memset(f->nf, 0, SIZEOF_FLOW_STRUCT);
	/*
	 * The sender of the first packet is the client, except when we picked the
	 * flow up mid-stream or on a reply: a SYN-ACK, or a well-known source port
	 * talking to an unprivileged one, means the sender is the server.
	 */
	{
		int src_is_server = 0;

		if (l4 == IPPROTO_TCP && (tcpflags & TCP_SYN) && (tcpflags & 0x10))
			src_is_server = 1;
		else if (!(l4 == IPPROTO_TCP && (tcpflags & TCP_SYN)) && pa != 0 && pa < 1024 && pb >= 1024)
			src_is_server = 1;
		if (src_is_server) {
			f->cli = *b;
			f->srv = *a;
			f->cport = pb;
			f->sport = pa;
			*dir = 1;
		} else {
			f->cli = *a;
			f->srv = *b;
			f->cport = pa;
			f->sport = pb;
			*dir = 0;
		}
	}
	f->l4 = l4;
	f->hash = h;
	f->t_first_ms = ts_ms;
	snprintf(f->country, sizeof(f->country), "%s", geo_lookup(&f->srv));
	snprintf(f->iface, sizeof(f->iface), "%s", iface);
	snprintf(f->master, sizeof(f->master), "Unknown");
	snprintf(f->app, sizeof(f->app), "Unknown");
	snprintf(f->cat, sizeof(f->cat), "Unspecified");
	f->next = tab[idx];
	tab[idx] = f;
	nflows++;
	flows_total++;
	return f;
}

static void
sweep(int force_all)
{
	size_t i;
	uint64_t now_ms = (uint64_t)time(NULL) * 1000;
	uint64_t idle = (uint64_t)cfg.flow_timeout * 1000;

	if (nflows > (size_t)cfg.max_flows * 9 / 10)
		idle /= 4;
	for (i = 0; i < tabsz; i++) {
		flow_t **pp = &tab[i];

		while (*pp) {
			flow_t *f = *pp;
			uint64_t lim = f->ended ? 5000 : idle;

			if (force_all || now_ms - f->t_last_ms > lim) {
				*pp = f->next;
				flow_persist(f, 1);
				flow_free(f);
				nflows--;
			} else {
				flow_persist(f, 0);
				pp = &f->next;
			}
		}
	}
}

/* ------------------------------------------------------- DNS learning */

static uint64_t dns_learned_total;
static struct ndpi_flow_struct *scratch_flow;

/* read a (possibly compressed) DNS name at off; returns 0 and sets *next */
static int
dns_name(const uint8_t *msg, int len, int off, char *out, size_t outlen, int *next)
{
	size_t o = 0;
	int jumped = 0, hops = 0;

	*next = -1;
	for (;;) {
		int l;

		if (off < 0 || off >= len || hops++ > 32)
			return -1;
		l = msg[off];
		if (l == 0) {
			if (!jumped)
				*next = off + 1;
			break;
		}
		if ((l & 0xc0) == 0xc0) {
			if (off + 1 >= len)
				return -1;
			if (!jumped)
				*next = off + 2;
			jumped = 1;
			off = ((l & 0x3f) << 8) | msg[off + 1];
			continue;
		}
		if ((l & 0xc0) != 0 || off + 1 + l > len)
			return -1;
		if (o + (size_t)l + 2 > outlen)
			return -1;
		if (o)
			out[o++] = '.';
		memcpy(out + o, msg + off + 1, (size_t)l);
		o += (size_t)l;
		off += 1 + l;
	}
	out[o] = '\0';
	return 0;
}

/*
 * A DNS answer to a client: classify the queried name with nDPI and, when a
 * block policy matches, put every returned address into the policy's pf table
 * before the client connects. This closes the "first connection" gap that
 * flow-based blocking has and covers round-robin address sets.
 */
static void
dns_learn(const uint8_t *msg, int len, const addr_t *client)
{
	char name[256];
	addr_t addrs[24];
	int naddr = 0, qd, an, off = 12, next, i;
	uint16_t flags, app = 0;
	policy_t *p;
	ndpi_protocol_match_result res;
	const char *appname = "", *catname = "";
	ndpi_protocol pr;

	if (len < 12 || npolicies_block() == 0)
		return;
	flags = (uint16_t)((msg[2] << 8) | msg[3]);
	if (!(flags & 0x8000) || (flags & 0x000f) != 0)
		return;
	qd = (msg[4] << 8) | msg[5];
	an = (msg[6] << 8) | msg[7];
	if (qd < 1 || an < 1)
		return;
	if (dns_name(msg, len, off, name, sizeof(name), &next) != 0)
		return;
	off = next + 4;
	for (i = 1; i < qd; i++) {	/* skip extra questions */
		char tmp[256];

		if (dns_name(msg, len, off, tmp, sizeof(tmp), &next) != 0)
			return;
		off = next + 4;
	}
	for (i = 0; i < an && naddr < 24; i++) {
		char tmp[256];
		int type, rdlen;

		if (dns_name(msg, len, off, tmp, sizeof(tmp), &next) != 0 || next + 10 > len)
			return;
		type = (msg[next] << 8) | msg[next + 1];
		rdlen = (msg[next + 8] << 8) | msg[next + 9];
		off = next + 10;
		if (off + rdlen > len)
			return;
		if (type == 1 && rdlen == 4) {
			memset(&addrs[naddr], 0, sizeof(addrs[naddr]));
			addrs[naddr].af = AF_INET;
			memcpy(addrs[naddr].a, msg + off, 4);
			naddr++;
		} else if (type == 28 && rdlen == 16) {
			memset(&addrs[naddr], 0, sizeof(addrs[naddr]));
			addrs[naddr].af = AF_INET6;
			memcpy(addrs[naddr].a, msg + off, 16);
			naddr++;
		}
		off += rdlen;
	}
	if (naddr == 0)
		return;
	for (i = 0; name[i]; i++)
		name[i] = (char)tolower((unsigned char)name[i]);

	if (scratch_flow == NULL) {
		scratch_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
		if (scratch_flow == NULL)
			return;
	}
	memset(scratch_flow, 0, SIZEOF_FLOW_STRUCT);
	memset(&res, 0, sizeof(res));
	app = ndpi_match_host_subprotocol(mod, scratch_flow, name, (u_int)strlen(name), &res,
	    NDPI_PROTOCOL_TLS, 0);
	if (app != NDPI_PROTOCOL_UNKNOWN) {
		memset(&pr, 0, sizeof(pr));
		pr.proto.app_protocol = app;
		appname = ndpi_get_proto_name(mod, app);
		catname = ndpi_category_get_name(mod, ndpi_get_proto_category(mod, pr));
	}
	p = policy_find(client, NULL, appname, catname, name);
	if (p != NULL && p->action == ACT_BLOCK) {
		int n = pf_block_addrs(&cfg, p, client, addrs, naddr);

		if (n > 0) {
			char c[64], detail[96];

			addr_str(client, c, sizeof(c));
			snprintf(detail, sizeof(detail), "dns-learn %d addr -> %s", n, p->table);
			store_event("block", c, "", appname, catname, name, p->name, detail);
			dns_learned_total += (uint64_t)n;
			l7_log("DNS-LEARN %s asked %s (app=%s cat=%s) -> %d address(es) to %s", c, name,
			    *appname ? appname : "-", *catname ? catname : "-", n, p->table);
		}
	} else if (p != NULL && (p->ai[0] || p->inspect || p->quic)) {
		/* allowed / monitored AI service: steer it to the inspection proxy and off QUIC */
		int nb = 0, nq = 0;

		if (p->inspect && cfg.ai_inspect)
			nb = pf_add_table(&cfg, AI_TABLE_BUMP, client, addrs, naddr, 1);
		if (p->quic && cfg.ai_quic == 1)
			nq = pf_add_table(&cfg, AI_TABLE_QUIC, client, addrs, naddr, 0);
		if (nb + nq > 0) {
			char c[64];

			addr_str(client, c, sizeof(c));
			dns_learned_total += (uint64_t)(nb + nq);
			l7_log("DNS-LEARN %s asked %s (ai=%s) -> %d to proxy table, %d to quic table", c, name,
			    p->ai, nb, nq);
		}
	}
}

/* ------------------------------------------------------------ packets */

static void
handle_l3(const uint8_t *l3, int len, uint64_t ts_ms, const char *iface)
{
	addr_t a, b;
	uint16_t pa = 0, pb = 0;
	uint8_t proto;
	int hl, dir;
	const uint8_t *l4;
	flow_t *f;
	uint8_t tcpflags = 0;

	if (len < 20)
		return;
	memset(&a, 0, sizeof(a));
	memset(&b, 0, sizeof(b));
	if ((l3[0] >> 4) == 4) {
		uint16_t tot, frag;

		hl = (l3[0] & 0x0f) * 4;
		if (hl < 20 || len < hl)
			return;
		tot = (uint16_t)((l3[2] << 8) | l3[3]);
		frag = (uint16_t)(((l3[6] << 8) | l3[7]) & 0x1fff);
		if (frag != 0)
			return;
		if (tot >= hl && tot < len)
			len = tot;
		proto = l3[9];
		a.af = b.af = AF_INET;
		memcpy(a.a, l3 + 12, 4);
		memcpy(b.a, l3 + 16, 4);
	} else if ((l3[0] >> 4) == 6) {
		uint8_t nh;
		int off = 40, guard = 0;

		if (len < 40)
			return;
		nh = l3[6];
		a.af = b.af = AF_INET6;
		memcpy(a.a, l3 + 8, 16);
		memcpy(b.a, l3 + 24, 16);
		while ((nh == 0 || nh == 43 || nh == 60 || nh == 44) && guard++ < 6) {
			if (len < off + 8)
				return;
			if (nh == 44) {
				if (((l3[off + 2] << 8 | l3[off + 3]) & 0xfff8) != 0)
					return;
				nh = l3[off];
				off += 8;
			} else {
				nh = l3[off];
				off += (l3[off + 1] + 1) * 8;
			}
		}
		proto = nh;
		hl = off;
		if (len < hl)
			return;
	} else {
		return;
	}
	/* link-local multicast / broadcast chatter carries no policy value */
	if (a.af == AF_INET && (b.a[0] >= 224 || (b.a[0] == 255)))
		return;
	if (a.af == AF_INET6 && b.a[0] == 0xff)
		return;

	l4 = l3 + hl;
	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		if (len < hl + 8)
			return;
		pa = (uint16_t)((l4[0] << 8) | l4[1]);
		pb = (uint16_t)((l4[2] << 8) | l4[3]);
		if (proto == IPPROTO_TCP) {
			if (len < hl + 14)
				return;
			tcpflags = l4[13];
		}
	} else if (proto != IPPROTO_ICMP && proto != 58) {
		return;
	}

	if (proto == IPPROTO_UDP && pa == 53 && len > hl + 8 + 12)
		dns_learn(l4 + 8, len - hl - 8, &b);

	f = flow_get(&a, pa, &b, pb, proto, &dir, iface, ts_ms, tcpflags);
	if (f == NULL)
		return;
	f->t_last_ms = ts_ms;
	f->bytes[dir] += (uint64_t)len;
	f->pkts[dir]++;
	f->npkts++;
	f->dirty = 1;
	pkts_total++;
	bytes_total += (uint64_t)len;
	if (tcpflags & (TCP_FIN | TCP_RST))
		f->ended = 1;
	flow_classify(f, l3, (uint16_t)len, ts_ms, dir);
}

static void
on_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *pkt)
{
	cap_t *c = (cap_t *)user;
	const u_char *p = pkt;
	int len = (int)h->caplen;
	uint64_t ts_ms = (uint64_t)h->ts.tv_sec * 1000 + (uint64_t)h->ts.tv_usec / 1000;

	if (c->dlt == DLT_EN10MB) {
		uint16_t et;

		if (len < ETH_HLEN)
			return;
		et = (uint16_t)((p[12] << 8) | p[13]);
		p += ETH_HLEN;
		len -= ETH_HLEN;
		while ((et == 0x8100 || et == 0x88a8) && len >= 4) {
			/*
			 * A monitored VLAN interface (vlanX) sees the same frames
			 * untagged; counting the tagged copy on its parent would
			 * double every flow, so skip tagged frames in that case.
			 */
			if (skip_tagged)
				return;
			et = (uint16_t)((p[2] << 8) | p[3]);
			p += 4;
			len -= 4;
		}
		if (et == 0x0806) {
			/* ARP: htype 1, ptype IPv4, hlen 6, plen 4; sender MAC at +8, sender IP at +14 */
			if (len >= 28 && p[0] == 0 && p[1] == 1 && p[2] == 8 && p[3] == 0 && p[4] == 6 &&
			    p[5] == 4) {
				addr_t sip;

				memset(&sip, 0, sizeof(sip));
				sip.af = AF_INET;
				memcpy(sip.a, p + 14, 4);
				dev_seen(&cfg, p + 8, &sip, c->name, 1);
			}
			return;
		}
		if (et == 0x0800 && len >= 20) {
			addr_t sip;

			memset(&sip, 0, sizeof(sip));
			sip.af = AF_INET;
			memcpy(sip.a, p + 12, 4);
			dev_seen(&cfg, pkt + 6, &sip, c->name, 0);
		}
		if (et != 0x0800 && et != 0x86dd)
			return;
	} else if (c->dlt != DLT_RAW) {
		return;
	}
	handle_l3(p, len, ts_ms, c->name);
}

/* -------------------------------------------------------------- status */

static void
write_status(void)
{
	char tmp[300];
	FILE *f;
	int i;
	time_t now = time(NULL);

	snprintf(tmp, sizeof(tmp), "%s.tmp", cfg.status_path);
	if ((f = fopen(tmp, "w")) == NULL)
		return;
	fprintf(f, "{\"version\":\"%s\",\"pid\":%d,\"started\":%ld,\"ts\":%ld,"
	    "\"packets\":%llu,\"bytes\":%llu,\"flows_active\":%zu,\"flows_total\":%llu,"
	    "\"classified\":%llu,\"dns_learned\":%llu,\"blocks\":%llu,\"db_rows\":%llu,\"policies\":%d,"
	    "\"devices_new\":%llu,\"mac_spoofs\":%llu,\"geo_ranges\":%zu,\"ifaces\":[",
	    L7_VERSION, (int)getpid(), (long)started, (long)now, (unsigned long long)pkts_total,
	    (unsigned long long)bytes_total, nflows, (unsigned long long)flows_total,
	    (unsigned long long)classified_total, (unsigned long long)dns_learned_total,
	    (unsigned long long)pf_blocks_total(),
	    (unsigned long long)store_rows(), policy_count(), (unsigned long long)dev_new(),
	    (unsigned long long)dev_spoofs(), geo_ranges());
	for (i = 0; i < cfg.niface; i++) {
		struct pcap_stat ps;

		memset(&ps, 0, sizeof(ps));
		if (caps[i].h)
			pcap_stats(caps[i].h, &ps);
		fprintf(f, "%s{\"name\":\"%s\",\"recv\":%u,\"drop\":%u}", i ? "," : "", caps[i].name,
		    ps.ps_recv, ps.ps_drop);
	}
	fprintf(f, "]}\n");
	fclose(f);
	rename(tmp, cfg.status_path);
}

static void
reload_policies(void)
{
	static policy_t buf[L7_MAX_POLICIES];
	int n = policies_load(cfg.policy_path, buf, L7_MAX_POLICIES);

	pf_flush_all(&cfg);
	policy_set(buf, n);
	l7_log("loaded %d policies, %d bindings, %d geo ranges, %d sessions", n,
	    dev_load_bindings(cfg.bindings_path), geo_load(cfg.geo_dir), sess_load(cfg.sessions_path));
}

/* ---------------------------------------------------------------- main */

int
main(int argc, char **argv)
{
	int i, opened = 0;
	time_t last_sweep = 0, last_status = 0, last_prune = 0, last_expire = 0, last_sess = 0, sess_mtime = 0;
	off_t sess_size = -1;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pollfd pfd[L7_MAX_IFACES];

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--version") == 0) {
			printf("l7engine %s\n", L7_VERSION);
			return 0;
		} else if (strcmp(argv[i], "--list-apps") == 0) {
			list_apps();
			return 0;
		} else if (strcmp(argv[i], "--list-categories") == 0) {
			list_categories();
			return 0;
		} else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
			cfg_path = argv[++i];
		} else {
			fprintf(stderr, "usage: l7engine -c conf | --list-apps | --list-categories | --version\n");
			return 2;
		}
	}
	if (config_load(&cfg, cfg_path) != 0) {
		l7_log("cannot read config %s", cfg_path);
		return 1;
	}
	g_debug = cfg.debug;
	if (cfg.niface == 0) {
		l7_log("no interface configured");
		return 1;
	}
	if (ndpi_start() != 0) {
		l7_log("nDPI initialisation failed");
		return 1;
	}
	if ((tab = calloc(tabsz, sizeof(*tab))) == NULL)
		return 1;
	{
		char dir[256], *sl;

		snprintf(dir, sizeof(dir), "%s", cfg.db_path);
		if ((sl = strrchr(dir, '/')) != NULL) {
			*sl = '\0';
			mkdir(dir, 0750);
		}
		snprintf(dir, sizeof(dir), "%s", cfg.status_path);
		if ((sl = strrchr(dir, '/')) != NULL) {
			*sl = '\0';
			mkdir(dir, 0755);
		}
	}
	if (store_open(cfg.db_path) != 0)
		return 1;

	for (i = 0; i < cfg.niface; i++) {
		pcap_t *h = pcap_create(cfg.iface[i], errbuf);

		if (h == NULL) {
			l7_log("pcap_create %s: %s", cfg.iface[i], errbuf);
			continue;
		}
		pcap_set_snaplen(h, SNAPLEN);
		pcap_set_promisc(h, 0);
		pcap_set_timeout(h, 100);
		pcap_set_immediate_mode(h, 1);
		pcap_set_buffer_size(h, 8 * 1024 * 1024);
		if (pcap_activate(h) < 0) {
			l7_log("pcap_activate %s: %s", cfg.iface[i], pcap_geterr(h));
			pcap_close(h);
			continue;
		}
		snprintf(caps[opened].name, sizeof(caps[opened].name), "%s", cfg.iface[i]);
		caps[opened].h = h;
		caps[opened].dlt = pcap_datalink(h);
		caps[opened].fd = pcap_get_selectable_fd(h);
		pcap_setnonblock(h, 1, errbuf);
		l7_log("capturing on %s (dlt %d)", caps[opened].name, caps[opened].dlt);
		opened++;
	}
	if (opened == 0) {
		l7_log("no usable capture interface");
		return 1;
	}
	cfg.niface = opened;
	for (i = 0; i < opened; i++)
		if (strncmp(caps[i].name, "vlan", 4) == 0)
			skip_tagged = 1;

	signal(SIGTERM, on_signal);
	signal(SIGINT, on_signal);
	signal(SIGHUP, on_signal);
	signal(SIGPIPE, SIG_IGN);
	started = time(NULL);
	dev_init_own();
	reload_policies();
	l7_log("l7engine %s started, %d interface(s)", L7_VERSION, opened);

	while (!stop_flag) {
		time_t now;

		for (i = 0; i < opened; i++) {
			pfd[i].fd = caps[i].fd;
			pfd[i].events = POLLIN;
			pfd[i].revents = 0;
		}
		if (poll(pfd, (nfds_t)opened, 500) > 0) {
			for (i = 0; i < opened; i++)
				if (pfd[i].revents & POLLIN)
					pcap_dispatch(caps[i].h, 256, on_packet, (u_char *)&caps[i]);
		}
		now = time(NULL);
		if (reload_flag) {
			reload_flag = 0;
			reload_policies();
		}
		store_tick(0);
		if (cfg.sessions_path[0] && now - last_sess >= 2) {
			struct stat sb;

			last_sess = now;
			if (stat(cfg.sessions_path, &sb) == 0 && (sb.st_mtime != sess_mtime || sb.st_size != sess_size)) {
				sess_mtime = sb.st_mtime;
				sess_size = sb.st_size;
				sess_load(cfg.sessions_path);
			}
		}
		if (now - last_sweep >= 2) {
			sweep(0);
			last_sweep = now;
		}
		if (now - last_status >= 5) {
			write_status();
			last_status = now;
		}
		if (now - last_expire >= 30) {
			pf_expire_all(&cfg);
			policy_sweep_schedules(&cfg);
			last_expire = now;
		}
		if (now - last_prune >= 3600) {
			store_prune(cfg.retention_days);
			last_prune = now;
		}
	}
	l7_log("stopping");
	sweep(1);
	store_close();
	pf_flush_all(&cfg);
	write_status();
	for (i = 0; i < opened; i++)
		pcap_close(caps[i].h);
	return 0;
}
