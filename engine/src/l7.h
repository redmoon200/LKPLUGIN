/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * l7engine - Layer-7 flow classifier for os-layer7security.
 * Shared declarations.
 */

#ifndef L7_H
#define L7_H

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define L7_VERSION "0.4.0"
#define L7_MAX_IFACES 8
#define L7_MAX_POLICIES 256
#define L7_MAX_LIST 128
#define L7_MAX_CIDR 64
#define L7_MAX_PUSERS 32
#define L7_MAX_SESSIONS 4096

typedef struct {
	int af;			/* AF_INET or AF_INET6 */
	uint8_t a[16];
} addr_t;

typedef struct {
	addr_t net;
	int plen;
} cidr_t;

enum { ACT_MONITOR = 0, ACT_ALLOW = 1, ACT_BLOCK = 2 };

typedef struct {
	int id;
	char name[64];
	int action;
	int ncidr;
	cidr_t cidr[L7_MAX_CIDR];
	int napps;
	char apps[L7_MAX_LIST][48];
	int ncats;
	char cats[L7_MAX_LIST][48];
	int nhosts;
	char hosts[L7_MAX_LIST][96];
	int day_mask;		/* bit0 = Sunday ... bit6 = Saturday; 0x7f = all */
	int start_min;		/* minutes after midnight */
	int end_min;		/* equal to start_min => all day */
	char table[32];		/* pf table name, l7_blk_<id> */
	char ai[24];		/* AI service id when this is an AI policy, else empty */
	int inspect;		/* AI policy: send this service through the inspection proxy */
	int quic;		/* AI policy: force the service off QUIC (UDP/443) */
	int restrict_src;	/* sources/users configured: no address and no session match = no match */
	int nusers;		/* signed-in users the policy applies to (matched through the session map) */
	char users[L7_MAX_PUSERS][48];
} policy_t;

typedef struct {
	char db_path[256];
	char status_path[256];
	char policy_path[256];
	char pfctl[64];
	int niface;
	char iface[L7_MAX_IFACES][32];
	int retention_days;
	int flow_timeout;	/* idle seconds */
	int block_ttl;		/* seconds an address stays in a pf table */
	int max_flows;
	int enforce;		/* 0 = never touch pf */
	int debug;
	char bindings_path[256];
	char geo_dir[256];
	int nnet;		/* networks of the monitored interfaces (device discovery) */
	cidr_t nets[16];
	int ai_inspect;		/* 1: fill l7_ai_bump so the proxy sees AI traffic */
	int ai_quic;		/* 0 off, 1 AI services only (table), 2 all QUIC (pf rule only) */
	char sessions_path[256]; /* signed-in users: "ip<TAB>user" per line, written by the portal */
} config_t;

#define AI_TABLE_BUMP "l7_ai_bump"
#define AI_TABLE_QUIC "l7_ai_quic"

/* config.c */
int config_load(config_t *c, const char *path);
int policies_load(const char *path, policy_t *p, int max);
int addr_parse(const char *s, addr_t *a);
void addr_str(const addr_t *a, char *buf, size_t len);
int cidr_match(const cidr_t *c, const addr_t *a);
int cidr_parse(const char *s, cidr_t *c);

/* store.c */
int store_open(const char *path);
void store_close(void);
void store_tick(int force_commit);
uint64_t store_flow_insert(const char *iface, int l4, const char *cli, const char *srv,
    int cport, int sport, const char *master, const char *app, const char *cat,
    const char *host, time_t t0, const char *action, const char *policy, const char *country,
    const char *ai);
int store_device(const char *ip, const char *mac, const char *iface, time_t now, uint32_t hits);
void store_flow_update(uint64_t id, time_t t1, uint64_t bu, uint64_t bd, uint64_t pu,
    uint64_t pd, const char *master, const char *app, const char *cat, const char *host,
    const char *action, const char *policy, const char *ai);
void store_event(const char *type, const char *cli, const char *srv, const char *app,
    const char *cat, const char *host, const char *policy, const char *detail);
void store_prune(int retention_days);
uint64_t store_rows(void);

/* sessions (policy.c): signed-in users by client address */
int sess_load(const char *path);
const char *sess_user(const addr_t *a);

/* policy.c */
void policy_set(policy_t *p, int n);
int host_match(const char *pat, const char *host);
policy_t *policy_find(const addr_t *client, const char *master, const char *app,
    const char *cat, const char *host);
int policy_count(void);
int npolicies_block(void);
policy_t *policy_get(int i);
int pf_block(const config_t *c, const policy_t *p, const addr_t *cli, const addr_t *srv);
int pf_block_addrs(const config_t *c, const policy_t *p, const addr_t *cli, const addr_t *addrs,
    int n);
int pf_add_table(const config_t *c, const char *table, const addr_t *cli, const addr_t *addrs,
    int n, int kill);
void pf_expire_all(const config_t *c);
void policy_sweep_schedules(const config_t *c);
void pf_flush_all(const config_t *c);
uint64_t pf_blocks_total(void);

/* geo.c */
int geo_load(const char *dir);
const char *geo_lookup(const addr_t *a);
size_t geo_ranges(void);

/* dev.c */
void mac_str(const uint8_t *m, char *buf, size_t len);
void dev_init_own(void);
int dev_load_bindings(const char *path);
void dev_seen(const config_t *c, const uint8_t *mac6, const addr_t *ip, const char *iface, int via_arp);
uint64_t dev_spoofs(void);
uint64_t dev_new(void);

/* log */
void l7_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
extern int g_debug;

#endif
