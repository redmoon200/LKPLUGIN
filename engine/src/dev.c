/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Device discovery and MAC binding checks. Every Ethernet frame (IPv4 from a
 * monitored network, or ARP) tells us which MAC currently uses which IP. New
 * pairs go to the devices table; a pair that contradicts a binding raises a
 * "mac-spoof" event. Enforcement itself is done by pf ether rules.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "l7.h"

#define SLOTS 4096
#define MAX_BIND 512
#define MAX_OWN 16

typedef struct {
	char mac[18];
	addr_t ip;
	char iface[16];
	time_t last_write;	/* last database write */
	time_t last_alert;
	uint32_t hits;
	uint8_t used;
} dev_t_;

typedef struct {
	char mac[18];
	addr_t ip;		/* af == 0: any address */
	char iface[16];		/* empty: any interface */
	char name[64];
} bind_t;

static dev_t_ slots[SLOTS];
static bind_t binds[MAX_BIND];
static int nbinds;
static uint8_t own[MAX_OWN][6];
static int nown;
static uint64_t devices_total, spoofs_total;

void
mac_str(const uint8_t *m, char *buf, size_t len)
{
	snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* the firewall's own interface addresses are not "devices" */
void
dev_init_own(void)
{
	struct ifaddrs *ifap, *ifa;

	nown = 0;
	if (getifaddrs(&ifap) != 0)
		return;
	for (ifa = ifap; ifa && nown < MAX_OWN; ifa = ifa->ifa_next) {
		struct sockaddr_dl *sdl;

		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_LINK)
			continue;
		sdl = (struct sockaddr_dl *)ifa->ifa_addr;
		if (sdl->sdl_alen != 6)
			continue;
		memcpy(own[nown++], LLADDR(sdl), 6);
	}
	freeifaddrs(ifap);
}

static int
is_own(const uint8_t *m)
{
	int i;

	for (i = 0; i < nown; i++)
		if (memcmp(own[i], m, 6) == 0)
			return 1;
	return 0;
}

int
dev_load_bindings(const char *path)
{
	FILE *f;
	char line[300];

	nbinds = 0;
	if (path == NULL || (f = fopen(path, "r")) == NULL)
		return 0;
	while (fgets(line, sizeof(line), f) && nbinds < MAX_BIND) {
		char *fld[4], *s = line, *t;
		int nf = 0, i;
		bind_t *b = &binds[nbinds];
		size_t n = strlen(line);

		while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
			line[--n] = '\0';
		if (line[0] == '#' || line[0] == '\0')
			continue;
		while (nf < 4 && (t = strsep(&s, "\t")) != NULL)
			fld[nf++] = t;
		if (nf < 4 || strlen(fld[0]) != 17)
			continue;
		memset(b, 0, sizeof(*b));
		for (i = 0; fld[0][i]; i++)
			b->mac[i] = (char)tolower((unsigned char)fld[0][i]);
		if (strcmp(fld[1], "-") != 0 && addr_parse(fld[1], &b->ip) != 0)
			continue;
		if (strcmp(fld[2], "-") != 0)
			snprintf(b->iface, sizeof(b->iface), "%s", fld[2]);
		snprintf(b->name, sizeof(b->name), "%s", fld[3]);
		nbinds++;
	}
	fclose(f);
	return nbinds;
}

static int
in_nets(const config_t *c, const addr_t *a)
{
	int i;

	if (c->nnet == 0)
		return 0;
	for (i = 0; i < c->nnet; i++)
		if (cidr_match(&c->nets[i], a))
			return 1;
	return 0;
}

/* a frame from this MAC claims this IP; ip->af == 0 for a MAC-only sighting */
void
dev_seen(const config_t *c, const uint8_t *mac6, const addr_t *ip, const char *iface, int via_arp)
{
	char mac[18], ips[64];
	time_t now = time(NULL);
	uint32_t h = 2166136261u;
	size_t i, idx;
	dev_t_ *d = NULL;
	int k;

	if (ip->af != AF_INET || is_own(mac6))
		return;
	if (ip->a[0] == 0 || ip->a[0] >= 224)
		return;
	if (!via_arp && !in_nets(c, ip))
		return;
	mac_str(mac6, mac, sizeof(mac));
	addr_str(ip, ips, sizeof(ips));

	for (i = 0; mac[i]; i++)
		h = (h ^ (uint8_t)mac[i]) * 16777619u;
	for (i = 0; i < 4; i++)
		h = (h ^ ip->a[i]) * 16777619u;
	idx = h % SLOTS;
	for (k = 0; k < 64; k++) {
		dev_t_ *s = &slots[(idx + (size_t)k) % SLOTS];

		if (!s->used) {
			d = s;
			break;
		}
		if (strcmp(s->mac, mac) == 0 && s->ip.af == ip->af && memcmp(s->ip.a, ip->a, 4) == 0 &&
		    strcmp(s->iface, iface) == 0) {
			d = s;
			break;
		}
	}
	if (d == NULL)
		d = &slots[idx];	/* table crowded: overwrite */
	if (!d->used || strcmp(d->mac, mac) != 0 || memcmp(d->ip.a, ip->a, 4) != 0) {
		memset(d, 0, sizeof(*d));
		snprintf(d->mac, sizeof(d->mac), "%s", mac);
		d->ip = *ip;
		snprintf(d->iface, sizeof(d->iface), "%s", iface);
		d->used = 1;
	}
	d->hits++;

	/* binding check: a bound address used by another MAC */
	for (k = 0; k < nbinds; k++) {
		bind_t *b = &binds[k];

		if (b->ip.af == 0 || memcmp(b->ip.a, ip->a, 4) != 0)
			continue;
		if (b->iface[0] && strcmp(b->iface, iface) != 0)
			continue;
		if (strcmp(b->mac, mac) != 0 && now - d->last_alert >= 60) {
			char detail[160];

			d->last_alert = now;
			spoofs_total++;
			snprintf(detail, sizeof(detail), "%s is bound to %s (%s) but %s sent as that address%s",
			    ips, b->mac, b->name, mac, via_arp ? " (ARP)" : "");
			store_event("mac-spoof", ips, "", "", "", mac, b->name, detail);
			l7_log("MAC-SPOOF %s", detail);
		}
	}

	if (now - d->last_write >= 60 || d->last_write == 0) {
		int isnew = store_device(ips, mac, iface, now, d->hits);

		d->last_write = now;
		d->hits = 0;
		if (isnew > 0) {
			devices_total++;
			store_event("device-new", ips, "", "", "", mac, "", iface);
		}
	}
}

uint64_t
dev_spoofs(void)
{
	return spoofs_total;
}

uint64_t
dev_new(void)
{
	return devices_total;
}
