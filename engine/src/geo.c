/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Country lookup. Loads v4.tsv ("<start> <end> <CC>", decimal) and v6.tsv
 * ("<start hex32> <end hex32> <CC>"), both sorted by start, written by
 * geo.py, and answers lookups with a binary search.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "l7.h"

typedef struct {
	uint32_t s, e;
	char cc[3];
} r4_t;

typedef struct {
	uint8_t s[16], e[16];
	char cc[3];
} r6_t;

static r4_t *g4;
static size_t n4;
static r6_t *g6;
static size_t n6;

static int
hex16(const char *h, uint8_t *out)
{
	int i;

	for (i = 0; i < 16; i++) {
		unsigned v;

		if (!isxdigit((unsigned char)h[2 * i]) || !isxdigit((unsigned char)h[2 * i + 1]))
			return -1;
		if (sscanf(h + 2 * i, "%2x", &v) != 1)
			return -1;
		out[i] = (uint8_t)v;
	}
	return 0;
}

static void
geo_free(void)
{
	free(g4);
	free(g6);
	g4 = NULL;
	g6 = NULL;
	n4 = n6 = 0;
}

int
geo_load(const char *dir)
{
	char path[300], line[160];
	FILE *f;
	size_t cap;

	geo_free();
	if (dir == NULL || *dir == '\0')
		return 0;

	snprintf(path, sizeof(path), "%s/v4.tsv", dir);
	if ((f = fopen(path, "r")) != NULL) {
		cap = 1024;
		g4 = malloc(cap * sizeof(*g4));
		while (g4 && fgets(line, sizeof(line), f)) {
			unsigned long s, e;
			char cc[8];

			if (sscanf(line, "%lu %lu %7s", &s, &e, cc) != 3 || strlen(cc) != 2)
				continue;
			if (n4 == cap) {
				r4_t *t = realloc(g4, cap * 2 * sizeof(*g4));

				if (t == NULL)
					break;
				g4 = t;
				cap *= 2;
			}
			g4[n4].s = (uint32_t)s;
			g4[n4].e = (uint32_t)e;
			memcpy(g4[n4].cc, cc, 3);
			n4++;
		}
		fclose(f);
	}
	snprintf(path, sizeof(path), "%s/v6.tsv", dir);
	if ((f = fopen(path, "r")) != NULL) {
		cap = 1024;
		g6 = malloc(cap * sizeof(*g6));
		while (g6 && fgets(line, sizeof(line), f)) {
			char a[40], b[40], cc[8];

			if (sscanf(line, "%39s %39s %7s", a, b, cc) != 3 || strlen(a) != 32 ||
			    strlen(b) != 32 || strlen(cc) != 2)
				continue;
			if (n6 == cap) {
				r6_t *t = realloc(g6, cap * 2 * sizeof(*g6));

				if (t == NULL)
					break;
				g6 = t;
				cap *= 2;
			}
			if (hex16(a, g6[n6].s) != 0 || hex16(b, g6[n6].e) != 0)
				continue;
			memcpy(g6[n6].cc, cc, 3);
			n6++;
		}
		fclose(f);
	}
	return (int)(n4 + n6);
}

const char *
geo_lookup(const addr_t *a)
{
	size_t lo, hi;

	if (a->af == AF_INET) {
		uint32_t x = ((uint32_t)a->a[0] << 24) | ((uint32_t)a->a[1] << 16) |
		    ((uint32_t)a->a[2] << 8) | a->a[3];

		lo = 0;
		hi = n4;
		while (lo < hi) {			/* last range with s <= x */
			size_t mid = lo + (hi - lo) / 2;

			if (g4[mid].s <= x)
				lo = mid + 1;
			else
				hi = mid;
		}
		if (lo > 0 && x <= g4[lo - 1].e)
			return g4[lo - 1].cc;
	} else if (a->af == AF_INET6) {
		lo = 0;
		hi = n6;
		while (lo < hi) {
			size_t mid = lo + (hi - lo) / 2;

			if (memcmp(g6[mid].s, a->a, 16) <= 0)
				lo = mid + 1;
			else
				hi = mid;
		}
		if (lo > 0 && memcmp(a->a, g6[lo - 1].e, 16) <= 0)
			return g6[lo - 1].cc;
	}
	return "";
}

size_t
geo_ranges(void)
{
	return n4 + n6;
}
