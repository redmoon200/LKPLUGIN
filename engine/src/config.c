/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Configuration and policy file parsing.
 *
 * engine.conf:  key=value per line, '#' comments.
 * policies.conf: one policy per line, TAB separated:
 *   id name action cidrs apps cats hosts days start end
 * list fields are comma separated; '-' means empty.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "l7.h"

static void
trim(char *s)
{
	size_t n = strlen(s);

	while (n > 0 && isspace((unsigned char)s[n - 1]))
		s[--n] = '\0';
}

int
addr_parse(const char *s, addr_t *a)
{
	memset(a, 0, sizeof(*a));
	if (inet_pton(AF_INET, s, a->a) == 1) {
		a->af = AF_INET;
		return 0;
	}
	if (inet_pton(AF_INET6, s, a->a) == 1) {
		a->af = AF_INET6;
		return 0;
	}
	return -1;
}

void
addr_str(const addr_t *a, char *buf, size_t len)
{
	if (inet_ntop(a->af, a->a, buf, len) == NULL)
		snprintf(buf, len, "?");
}

int
cidr_match(const cidr_t *c, const addr_t *a)
{
	int full, rem;

	if (c->net.af != a->af)
		return 0;
	full = c->plen / 8;
	rem = c->plen % 8;
	if (full > 0 && memcmp(c->net.a, a->a, full) != 0)
		return 0;
	if (rem) {
		uint8_t mask = (uint8_t)(0xff << (8 - rem));

		if ((c->net.a[full] & mask) != (a->a[full] & mask))
			return 0;
	}
	return 1;
}

int
cidr_parse(const char *s, cidr_t *c)
{
	char buf[64], *slash;
	int max;

	snprintf(buf, sizeof(buf), "%s", s);
	slash = strchr(buf, '/');
	if (slash)
		*slash++ = '\0';
	if (addr_parse(buf, &c->net) != 0)
		return -1;
	max = c->net.af == AF_INET ? 32 : 128;
	c->plen = slash ? atoi(slash) : max;
	if (c->plen < 0 || c->plen > max)
		return -1;
	return 0;
}

int
config_load(config_t *c, const char *path)
{
	FILE *f;
	char line[512], *eq, *k, *v;

	memset(c, 0, sizeof(*c));
	snprintf(c->db_path, sizeof(c->db_path), "/var/db/layer7security/l7.db");
	snprintf(c->status_path, sizeof(c->status_path), "/var/run/layer7security/status.json");
	snprintf(c->policy_path, sizeof(c->policy_path), "/usr/local/etc/layer7security/policies.conf");
	snprintf(c->pfctl, sizeof(c->pfctl), "/sbin/pfctl");
	c->retention_days = 7;
	c->flow_timeout = 60;
	c->block_ttl = 3600;
	c->max_flows = 200000;
	c->enforce = 1;

	if ((f = fopen(path, "r")) == NULL)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		trim(line);
		k = line;
		while (isspace((unsigned char)*k))
			k++;
		if (*k == '#' || *k == '\0' || (eq = strchr(k, '=')) == NULL)
			continue;
		*eq = '\0';
		v = eq + 1;
		trim(k);
		if (strcmp(k, "db") == 0)
			snprintf(c->db_path, sizeof(c->db_path), "%s", v);
		else if (strcmp(k, "status") == 0)
			snprintf(c->status_path, sizeof(c->status_path), "%s", v);
		else if (strcmp(k, "policies") == 0)
			snprintf(c->policy_path, sizeof(c->policy_path), "%s", v);
		else if (strcmp(k, "pfctl") == 0)
			snprintf(c->pfctl, sizeof(c->pfctl), "%s", v);
		else if (strcmp(k, "interface") == 0) {
			if (c->niface < L7_MAX_IFACES && *v)
				snprintf(c->iface[c->niface++], sizeof(c->iface[0]), "%s", v);
		} else if (strcmp(k, "retention_days") == 0)
			c->retention_days = atoi(v);
		else if (strcmp(k, "flow_timeout") == 0)
			c->flow_timeout = atoi(v);
		else if (strcmp(k, "block_ttl") == 0)
			c->block_ttl = atoi(v);
		else if (strcmp(k, "max_flows") == 0)
			c->max_flows = atoi(v);
		else if (strcmp(k, "enforce") == 0)
			c->enforce = atoi(v);
		else if (strcmp(k, "debug") == 0)
			c->debug = atoi(v);
		else if (strcmp(k, "bindings") == 0)
			snprintf(c->bindings_path, sizeof(c->bindings_path), "%s", v);
		else if (strcmp(k, "geo_dir") == 0)
			snprintf(c->geo_dir, sizeof(c->geo_dir), "%s", v);
		else if (strcmp(k, "net") == 0) {
			if (c->nnet < 16 && cidr_parse(v, &c->nets[c->nnet]) == 0)
				c->nnet++;
		}
	}
	fclose(f);
	if (c->flow_timeout < 5)
		c->flow_timeout = 5;
	if (c->max_flows < 1000)
		c->max_flows = 1000;
	return 0;
}

/* split a comma list into fixed-size slots, lower-casing when asked */
static int
split_list(char *s, char (*out)[48], int max, int lower, size_t slot)
{
	int n = 0;
	char *tok, *save = NULL;

	if (strcmp(s, "-") == 0)
		return 0;
	for (tok = strtok_r(s, ",", &save); tok && n < max; tok = strtok_r(NULL, ",", &save)) {
		char *dst = (char *)out + (size_t)n * slot;
		size_t i;

		snprintf(dst, slot, "%s", tok);
		if (lower)
			for (i = 0; dst[i]; i++)
				dst[i] = (char)tolower((unsigned char)dst[i]);
		n++;
	}
	return n;
}

static int
hhmm(const char *s)
{
	int h = 0, m = 0;

	if (sscanf(s, "%d:%d", &h, &m) < 1)
		return 0;
	return h * 60 + m;
}

int
policies_load(const char *path, policy_t *p, int max)
{
	FILE *f;
	char line[2048];
	int n = 0;

	if ((f = fopen(path, "r")) == NULL)
		return 0;
	while (fgets(line, sizeof(line), f) && n < max) {
		char *fld[10], *s = line, *t;
		int i, nf = 0;
		policy_t *q = &p[n];
		char cidrs[1024];
		char *c, *save = NULL;

		trim(line);
		if (line[0] == '#' || line[0] == '\0')
			continue;
		memset(fld, 0, sizeof(fld));
		while (nf < 10 && (t = strsep(&s, "\t")) != NULL)
			fld[nf++] = t;
		if (nf < 10)
			continue;
		memset(q, 0, sizeof(*q));
		q->id = atoi(fld[0]);
		if (q->id <= 0)
			continue;
		snprintf(q->name, sizeof(q->name), "%s", fld[1]);
		q->action = strcmp(fld[2], "block") == 0 ? ACT_BLOCK :
		    strcmp(fld[2], "allow") == 0 ? ACT_ALLOW : ACT_MONITOR;
		snprintf(cidrs, sizeof(cidrs), "%s", fld[3]);
		if (strcmp(cidrs, "-") != 0)
			for (c = strtok_r(cidrs, ",", &save); c && q->ncidr < L7_MAX_CIDR;
			    c = strtok_r(NULL, ",", &save))
				if (cidr_parse(c, &q->cidr[q->ncidr]) == 0)
					q->ncidr++;
		q->napps = split_list(fld[4], q->apps, L7_MAX_LIST, 1, sizeof(q->apps[0]));
		q->ncats = split_list(fld[5], q->cats, L7_MAX_LIST, 1, sizeof(q->cats[0]));
		/* hosts use wider slots */
		if (strcmp(fld[6], "-") != 0) {
			char *h, *hs = NULL;

			for (h = strtok_r(fld[6], ",", &hs); h && q->nhosts < L7_MAX_LIST;
			    h = strtok_r(NULL, ",", &hs)) {
				snprintf(q->hosts[q->nhosts], sizeof(q->hosts[0]), "%s", h);
				for (i = 0; q->hosts[q->nhosts][i]; i++)
					q->hosts[q->nhosts][i] =
					    (char)tolower((unsigned char)q->hosts[q->nhosts][i]);
				q->nhosts++;
			}
		}
		q->day_mask = atoi(fld[7]);
		if (q->day_mask <= 0 || q->day_mask > 0x7f)
			q->day_mask = 0x7f;
		q->start_min = hhmm(fld[8]);
		q->end_min = hhmm(fld[9]);
		snprintf(q->table, sizeof(q->table), "l7_blk_%d", q->id);
		n++;
	}
	fclose(f);
	return n;
}
