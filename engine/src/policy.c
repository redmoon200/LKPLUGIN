/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Policy matching and pf enforcement.
 *
 * A "block" policy adds the server address of a matching flow to the pf table
 * l7_blk_<id>; the plugin's firewall hook installs a quick block rule
 * "from <policy sources> to <l7_blk_id>" so later connections are dropped.
 * Existing states for the pair are killed. Table entries expire after
 * block_ttl seconds.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fnmatch.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "l7.h"

static policy_t pols[L7_MAX_POLICIES];
static int npols;
static uint64_t blocks_total;

#define DEDUP 512
static struct {
	char key[96];
	time_t until;
} seen[DEDUP];

void
policy_set(policy_t *p, int n)
{
	if (n > L7_MAX_POLICIES)
		n = L7_MAX_POLICIES;
	memcpy(pols, p, sizeof(policy_t) * (size_t)n);
	npols = n;
}

int
policy_count(void)
{
	return npols;
}

int
npolicies_block(void)
{
	int i, n = 0;

	for (i = 0; i < npols; i++)
		if (pols[i].action == ACT_BLOCK || pols[i].inspect || pols[i].quic)
			n++;
	return n;
}

policy_t *
policy_get(int i)
{
	return (i >= 0 && i < npols) ? &pols[i] : NULL;
}

static int
sched_active(const policy_t *p)
{
	time_t now = time(NULL);
	struct tm tm;
	int mins;

	localtime_r(&now, &tm);
	if (!(p->day_mask & (1 << tm.tm_wday)))
		return 0;
	if (p->start_min == p->end_min)
		return 1;
	mins = tm.tm_hour * 60 + tm.tm_min;
	if (p->start_min < p->end_min)
		return mins >= p->start_min && mins < p->end_min;
	return mins >= p->start_min || mins < p->end_min;	/* wraps midnight */
}

/*
 * Host patterns: "example.com" matches the name and every sub-domain;
 * a pattern with * or ? ("*.example.com", "*instagram.com", "ad*.example.net")
 * is a case-insensitive glob over the whole name where * also crosses dots.
 * A leading "*." also covers the bare domain, so "*.example.com" blocks
 * example.com and everything below it.
 */
static int
host_match(const char *pat, const char *host)
{
	size_t lp = strlen(pat), lh = strlen(host);

	if (lp == 0)
		return 0;
	if (strpbrk(pat, "*?") != NULL) {
		if (pat[0] == '*' && pat[1] == '.' && strpbrk(pat + 2, "*?") == NULL &&
		    host_match(pat + 2, host))
			return 1;
		return fnmatch(pat, host, FNM_CASEFOLD) == 0;
	}
	if (lh < lp)
		return 0;
	if (strcasecmp(host + lh - lp, pat) != 0)
		return 0;
	return lh == lp || host[lh - lp - 1] == '.';
}

/* ---- signed-in users (written by the portal): client address -> user name ---- */

static struct {
	addr_t a;
	char user[48];
} sess[L7_MAX_SESSIONS];
static int nsess;

int
sess_load(const char *path)
{
	FILE *f;
	char line[256];
	int n = 0;

	if (path == NULL || *path == '\0' || (f = fopen(path, "r")) == NULL) {
		nsess = 0;
		return 0;
	}
	while (fgets(line, sizeof(line), f) && n < L7_MAX_SESSIONS) {
		char *tab, *nl;

		if ((nl = strpbrk(line, "\r\n")) != NULL)
			*nl = '\0';
		if (line[0] == '#' || (tab = strchr(line, '\t')) == NULL)
			continue;
		*tab++ = '\0';
		if (addr_parse(line, &sess[n].a) != 0 || *tab == '\0')
			continue;
		snprintf(sess[n].user, sizeof(sess[n].user), "%s", tab);
		n++;
	}
	fclose(f);
	nsess = n;
	return n;
}

const char *
sess_user(const addr_t *a)
{
	int i;

	for (i = 0; i < nsess; i++)
		if (sess[i].a.af == a->af && memcmp(sess[i].a.a, a->a, a->af == AF_INET ? 4 : 16) == 0)
			return sess[i].user;
	return NULL;
}

policy_t *
policy_find(const addr_t *client, const char *master, const char *app, const char *cat,
    const char *host)
{
	int i, j, k;
	char lapp[48], lmaster[48], lcat[48];

	snprintf(lapp, sizeof(lapp), "%s", app ? app : "");
	snprintf(lmaster, sizeof(lmaster), "%s", master ? master : "");
	snprintf(lcat, sizeof(lcat), "%s", cat ? cat : "");
	for (k = 0; lapp[k]; k++)
		lapp[k] = (char)tolower((unsigned char)lapp[k]);
	for (k = 0; lmaster[k]; k++)
		lmaster[k] = (char)tolower((unsigned char)lmaster[k]);
	for (k = 0; lcat[k]; k++)
		lcat[k] = (char)tolower((unsigned char)lcat[k]);

	for (i = 0; i < npols; i++) {
		policy_t *p = &pols[i];
		int src_ok = (p->ncidr == 0 && !p->restrict_src), hit = 0;

		for (j = 0; j < p->ncidr && !src_ok; j++)
			if (cidr_match(&p->cidr[j], client))
				src_ok = 1;
		if (!src_ok && p->nusers) {
			const char *u = sess_user(client);

			for (j = 0; u && j < p->nusers && !src_ok; j++)
				if (strcasecmp(p->users[j], u) == 0)
					src_ok = 1;
		}
		if (!src_ok || !sched_active(p))
			continue;
		for (j = 0; j < p->napps && !hit; j++)
			if (strcmp(p->apps[j], lapp) == 0 || strcmp(p->apps[j], lmaster) == 0)
				hit = 1;
		for (j = 0; j < p->ncats && !hit; j++)
			if (strcmp(p->cats[j], lcat) == 0)
				hit = 1;
		for (j = 0; j < p->nhosts && !hit && host && *host; j++)
			if (host_match(p->hosts[j], host))
				hit = 1;
		if (hit)
			return p;
	}
	return NULL;
}


/* ---- direct pf(4) access: microseconds instead of a pfctl fork/exec ---- */

static int pf_fd = -1;

static int
pf_dev(void)
{
	if (pf_fd < 0)
		pf_fd = open("/dev/pf", O_RDWR | O_CLOEXEC);
	return pf_fd;
}

static void
pfaddr_set(struct pf_addr *pa, const addr_t *a)
{
	memset(pa, 0, sizeof(*pa));
	memcpy(pa, a->a, a->af == AF_INET ? 4 : 16);
}

static void
pfaddr_mask(struct pf_addr *pa, int af)
{
	memset(pa, 0xff, af == AF_INET ? 4 : 16);
}

/* add addresses to a pf table; returns number added or -1 on failure */
static int
tbl_add(const char *table, const addr_t *addrs, int n)
{
	struct pfioc_table io;
	struct pfr_addr ad[64];
	int i, fd = pf_dev();

	if (fd < 0 || n <= 0 || n > 64)
		return -1;
	memset(ad, 0, sizeof(ad));
	for (i = 0; i < n; i++) {
		ad[i].pfra_af = (u_int8_t)addrs[i].af;
		ad[i].pfra_net = addrs[i].af == AF_INET ? 32 : 128;
		memcpy(&ad[i].pfra_u, addrs[i].a, addrs[i].af == AF_INET ? 4 : 16);
	}
	memset(&io, 0, sizeof(io));
	if (strlcpy(io.pfrio_table.pfrt_name, table, sizeof(io.pfrio_table.pfrt_name)) >=
	    sizeof(io.pfrio_table.pfrt_name))
		return -1;
	io.pfrio_buffer = ad;
	io.pfrio_esize = sizeof(ad[0]);
	io.pfrio_size = n;
	if (ioctl(fd, DIOCRADDADDRS, &io) < 0)
		return -1;
	return io.pfrio_nadd;
}

/* kill all states between two hosts; returns 0 on success */
static int
kill_states(const addr_t *src, const addr_t *dst)
{
	struct pfioc_state_kill psk;
	int fd = pf_dev();

	if (fd < 0)
		return -1;
	memset(&psk, 0, sizeof(psk));
	psk.psk_af = (sa_family_t)src->af;
	pfaddr_set(&psk.psk_src.addr.v.a.addr, src);
	pfaddr_mask(&psk.psk_src.addr.v.a.mask, src->af);
	pfaddr_set(&psk.psk_dst.addr.v.a.addr, dst);
	pfaddr_mask(&psk.psk_dst.addr.v.a.mask, dst->af);
	return ioctl(fd, DIOCKILLSTATES, &psk) < 0 ? -1 : 0;
}

/* run pfctl with a fixed argv; no shell involved */
static int
run_pfctl(const config_t *c, char *const argv[])
{
	pid_t pid;
	int status, fd;

	if (!c->enforce)
		return 0;
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		fd = open("/dev/null", O_RDWR);
		if (fd >= 0) {
			dup2(fd, 0);
			dup2(fd, 1);
			dup2(fd, 2);
		}
		execv(c->pfctl, argv);
		_exit(127);
	}
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int
addr_blockable(const addr_t *a)
{
	if (a->af == AF_INET)
		return !(a->a[0] == 127 || a->a[0] == 0 || (a->a[0] == 169 && a->a[1] == 254));
	if (a->af == AF_INET6) {
		static const uint8_t zero[16];

		return memcmp(a->a, zero, 16) != 0 && !(a->a[0] == 0xfe && (a->a[1] & 0xc0) == 0x80);
	}
	return 0;
}

int
pf_block(const config_t *c, const policy_t *p, const addr_t *cli, const addr_t *srv)
{
	if (!addr_blockable(srv))
		return 0;

	char s[64], d[64], key[96];
	char *add[] = { (char *)"pfctl", (char *)"-q", (char *)"-t", (char *)p->table,
	    (char *)"-T", (char *)"add", d, NULL };
	char *kill[] = { (char *)"pfctl", (char *)"-q", (char *)"-k", s, (char *)"-k", d, NULL };
	time_t now = time(NULL);
	int i, slot = -1;

	addr_str(cli, s, sizeof(s));
	addr_str(srv, d, sizeof(d));
	snprintf(key, sizeof(key), "%s|%s", p->table, d);
	for (i = 0; i < DEDUP; i++) {
		if (strcmp(seen[i].key, key) == 0 && seen[i].until > now)
			return 0;
		if (slot < 0 && seen[i].until <= now)
			slot = i;
	}
	if (slot < 0)
		slot = (int)(now % DEDUP);
	snprintf(seen[slot].key, sizeof(seen[slot].key), "%s", key);
	seen[slot].until = now + (c->block_ttl > 60 ? c->block_ttl / 2 : 30);

	if (!c->enforce) {
		blocks_total++;
		return 1;
	}
	if (tbl_add(p->table, srv, 1) < 0 && run_pfctl(c, add) != 0)
		l7_log("add %s %s failed", p->table, d);
	if (kill_states(cli, srv) < 0)
		run_pfctl(c, kill);
	blocks_total++;
	return 1;
}

/*
 * Add several addresses learned from a DNS answer to a policy table in one
 * pfctl call (no states exist yet, so nothing needs to be killed).
 */
int
pf_add_table(const config_t *c, const char *table, const addr_t *cli, const addr_t *addrs, int n,
    int kill)
{
	enum { MAXA = 24 };
	char names[MAXA][64];
	char *argv[MAXA + 8];
	time_t now = time(NULL);
	int i, j, argc = 0, added = 0;

	argv[argc++] = (char *)"pfctl";
	argv[argc++] = (char *)"-q";
	argv[argc++] = (char *)"-t";
	argv[argc++] = (char *)table;
	argv[argc++] = (char *)"-T";
	argv[argc++] = (char *)"add";
	for (i = 0; i < n && added < MAXA; i++) {
		char key[96];
		int slot = -1, dup = 0;

		addr_str(&addrs[i], names[added], sizeof(names[added]));
		snprintf(key, sizeof(key), "%s|%s", table, names[added]);
		for (j = 0; j < DEDUP; j++) {
			if (strcmp(seen[j].key, key) == 0 && seen[j].until > now) {
				dup = 1;
				break;
			}
			if (slot < 0 && seen[j].until <= now)
				slot = j;
		}
		if (dup)
			continue;
		if (slot < 0)
			slot = (int)(now % DEDUP);
		snprintf(seen[slot].key, sizeof(seen[slot].key), "%s", key);
		seen[slot].until = now + (c->block_ttl > 60 ? c->block_ttl / 2 : 30);
		argv[argc++] = names[added];
		added++;
	}
	if (added == 0)
		return 0;
	argv[argc] = NULL;
	if (!c->enforce) {
		if (strncmp(table, "l7_blk", 6) == 0)
			blocks_total += (uint64_t)added;
		return added;
	}
	{
		addr_t list[MAXA];
		int k, m = 0;

		for (k = 0; k < added; k++)
			if (addr_parse(names[k], &list[m]) == 0)
				m++;
		if (tbl_add(table, list, m) < 0 && run_pfctl(c, argv) != 0)
			l7_log("add %s (%d addresses) failed", table, added);
		/*
		 * The client may already have raced the answer and opened a
		 * connection; established states bypass the block rule, so
		 * drop them now.
		 */
		if (kill)
			for (k = 0; k < m; k++)
				kill_states(cli, &list[k]);
	}
	if (strncmp(table, "l7_blk", 6) == 0)
			blocks_total += (uint64_t)added;
	return added;
}

int
pf_block_addrs(const config_t *c, const policy_t *p, const addr_t *cli, const addr_t *addrs, int n)
{
	return pf_add_table(c, p->table, cli, addrs, n, 1);
}

void
pf_expire_all(const config_t *c)
{
	int i;
	char ttl[16];

	snprintf(ttl, sizeof(ttl), "%d", c->block_ttl);
	for (i = 0; i < npols; i++) {
		char *argv[] = { (char *)"pfctl", (char *)"-q", (char *)"-t", pols[i].table,
		    (char *)"-T", (char *)"expire", ttl, NULL };

		if (pols[i].action == ACT_BLOCK)
			run_pfctl(c, argv);
	}
	{
		char *tabs[] = { (char *)AI_TABLE_BUMP, (char *)AI_TABLE_QUIC };
		size_t k;

		for (k = 0; k < sizeof(tabs) / sizeof(tabs[0]); k++) {
			char *argv[] = { (char *)"pfctl", (char *)"-q", (char *)"-t", tabs[k], (char *)"-T",
			    (char *)"expire", ttl, NULL };

			run_pfctl(c, argv);
		}
	}
}

/* lift blocks whose schedule window has ended */
void
policy_sweep_schedules(const config_t *c)
{
	int i;

	for (i = 0; i < npols; i++) {
		char *argv[] = { (char *)"pfctl", (char *)"-q", (char *)"-t", pols[i].table,
		    (char *)"-T", (char *)"flush", NULL };

		if (pols[i].action == ACT_BLOCK && !sched_active(&pols[i])) {
			run_pfctl(c, argv);
			memset(seen, 0, sizeof(seen));
		}
	}
}

void
pf_flush_all(const config_t *c)
{
	int i;

	for (i = 0; i < npols; i++) {
		char *argv[] = { (char *)"pfctl", (char *)"-q", (char *)"-t", pols[i].table,
		    (char *)"-T", (char *)"flush", NULL };

		if (pols[i].action == ACT_BLOCK)
			run_pfctl(c, argv);
	}
	{
		char *tabs[] = { (char *)AI_TABLE_BUMP, (char *)AI_TABLE_QUIC };
		size_t k;

		for (k = 0; k < sizeof(tabs) / sizeof(tabs[0]); k++) {
			char *argv[] = { (char *)"pfctl", (char *)"-q", (char *)"-t", tabs[k], (char *)"-T",
			    (char *)"flush", NULL };

			run_pfctl(c, argv);
		}
	}
	memset(seen, 0, sizeof(seen));
}

uint64_t
pf_blocks_total(void)
{
	return blocks_total;
}
