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
#include <sys/wait.h>
#include <ctype.h>
#include <errno.h>
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

static int
host_match(const char *pat, const char *host)
{
	size_t lp = strlen(pat), lh = strlen(host);

	if (lp == 0 || lh < lp)
		return 0;
	if (strcasecmp(host + lh - lp, pat) != 0)
		return 0;
	return lh == lp || host[lh - lp - 1] == '.';
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
		int src_ok = (p->ncidr == 0), hit = 0;

		for (j = 0; j < p->ncidr && !src_ok; j++)
			if (cidr_match(&p->cidr[j], client))
				src_ok = 1;
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

int
pf_block(const config_t *c, const policy_t *p, const addr_t *cli, const addr_t *srv)
{
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

	if (run_pfctl(c, add) != 0)
		l7_log("pfctl add %s %s failed", p->table, d);
	run_pfctl(c, kill);
	blocks_total++;
	return 1;
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
	memset(seen, 0, sizeof(seen));
}

uint64_t
pf_blocks_total(void)
{
	return blocks_total;
}
