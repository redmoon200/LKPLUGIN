/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * SQLite persistence. Writes are batched in one open transaction that is
 * committed about once a second; the database is in WAL mode so the GUI
 * backend can read concurrently.
 */

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "l7.h"

static sqlite3 *db;
static sqlite3_stmt *st_ins, *st_upd, *st_evt;
static int in_tx;
static time_t last_commit;
static uint64_t rows;

static int
exec(const char *sql)
{
	char *err = NULL;

	if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
		l7_log("sqlite: %s (%s)", err ? err : "error", sql);
		sqlite3_free(err);
		return -1;
	}
	return 0;
}

int
store_open(const char *path)
{
	if (sqlite3_open(path, &db) != SQLITE_OK) {
		l7_log("cannot open db %s: %s", path, db ? sqlite3_errmsg(db) : "?");
		return -1;
	}
	sqlite3_busy_timeout(db, 5000);
	exec("PRAGMA journal_mode=WAL");
	exec("PRAGMA synchronous=NORMAL");
	if (exec("CREATE TABLE IF NOT EXISTS flows("
	    "id INTEGER PRIMARY KEY, ts_start INTEGER, ts_end INTEGER, iface TEXT,"
	    "l4 INTEGER, client TEXT, server TEXT, cport INTEGER, sport INTEGER,"
	    "master TEXT, app TEXT, category TEXT, host TEXT,"
	    "bytes_up INTEGER DEFAULT 0, bytes_down INTEGER DEFAULT 0,"
	    "pkts_up INTEGER DEFAULT 0, pkts_down INTEGER DEFAULT 0,"
	    "action TEXT, policy TEXT)") != 0)
		return -1;
	exec("CREATE INDEX IF NOT EXISTS flows_end ON flows(ts_end)");
	exec("CREATE INDEX IF NOT EXISTS flows_client ON flows(client)");
	exec("CREATE INDEX IF NOT EXISTS flows_app ON flows(app)");
	exec("CREATE TABLE IF NOT EXISTS events("
	    "id INTEGER PRIMARY KEY, ts INTEGER, type TEXT, client TEXT, server TEXT,"
	    "app TEXT, category TEXT, host TEXT, policy TEXT, detail TEXT)");
	exec("CREATE INDEX IF NOT EXISTS events_ts ON events(ts)");
	exec("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)");

	if (sqlite3_prepare_v2(db,
	    "INSERT INTO flows(ts_start,ts_end,iface,l4,client,server,cport,sport,master,app,"
	    "category,host,action,policy) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", -1, &st_ins, NULL) != SQLITE_OK ||
	    sqlite3_prepare_v2(db,
	    "UPDATE flows SET ts_end=?,bytes_up=?,bytes_down=?,pkts_up=?,pkts_down=?,master=?,"
	    "app=?,category=?,host=?,action=?,policy=? WHERE id=?", -1, &st_upd, NULL) != SQLITE_OK ||
	    sqlite3_prepare_v2(db,
	    "INSERT INTO events(ts,type,client,server,app,category,host,policy,detail)"
	    " VALUES(?,?,?,?,?,?,?,?,?)", -1, &st_evt, NULL) != SQLITE_OK) {
		l7_log("sqlite prepare: %s", sqlite3_errmsg(db));
		return -1;
	}
	last_commit = time(NULL);
	return 0;
}

static void
begin(void)
{
	if (!in_tx && exec("BEGIN") == 0)
		in_tx = 1;
}

void
store_tick(int force_commit)
{
	time_t now = time(NULL);

	if (in_tx && (force_commit || now != last_commit)) {
		exec("COMMIT");
		in_tx = 0;
		last_commit = now;
	}
}

void
store_close(void)
{
	store_tick(1);
	if (st_ins)
		sqlite3_finalize(st_ins);
	if (st_upd)
		sqlite3_finalize(st_upd);
	if (st_evt)
		sqlite3_finalize(st_evt);
	if (db)
		sqlite3_close(db);
	db = NULL;
}

static void
bind_text(sqlite3_stmt *s, int i, const char *v)
{
	sqlite3_bind_text(s, i, v ? v : "", -1, SQLITE_TRANSIENT);
}

uint64_t
store_flow_insert(const char *iface, int l4, const char *cli, const char *srv, int cport,
    int sport, const char *master, const char *app, const char *cat, const char *host,
    time_t t0, const char *action, const char *policy)
{
	if (!db)
		return 0;
	begin();
	sqlite3_reset(st_ins);
	sqlite3_bind_int64(st_ins, 1, t0);
	sqlite3_bind_int64(st_ins, 2, t0);
	bind_text(st_ins, 3, iface);
	sqlite3_bind_int(st_ins, 4, l4);
	bind_text(st_ins, 5, cli);
	bind_text(st_ins, 6, srv);
	sqlite3_bind_int(st_ins, 7, cport);
	sqlite3_bind_int(st_ins, 8, sport);
	bind_text(st_ins, 9, master);
	bind_text(st_ins, 10, app);
	bind_text(st_ins, 11, cat);
	bind_text(st_ins, 12, host);
	bind_text(st_ins, 13, action);
	bind_text(st_ins, 14, policy);
	if (sqlite3_step(st_ins) != SQLITE_DONE) {
		l7_log("insert flow: %s", sqlite3_errmsg(db));
		return 0;
	}
	rows++;
	return (uint64_t)sqlite3_last_insert_rowid(db);
}

void
store_flow_update(uint64_t id, time_t t1, uint64_t bu, uint64_t bd, uint64_t pu, uint64_t pd,
    const char *master, const char *app, const char *cat, const char *host,
    const char *action, const char *policy)
{
	if (!db || id == 0)
		return;
	begin();
	sqlite3_reset(st_upd);
	sqlite3_bind_int64(st_upd, 1, t1);
	sqlite3_bind_int64(st_upd, 2, (sqlite3_int64)bu);
	sqlite3_bind_int64(st_upd, 3, (sqlite3_int64)bd);
	sqlite3_bind_int64(st_upd, 4, (sqlite3_int64)pu);
	sqlite3_bind_int64(st_upd, 5, (sqlite3_int64)pd);
	bind_text(st_upd, 6, master);
	bind_text(st_upd, 7, app);
	bind_text(st_upd, 8, cat);
	bind_text(st_upd, 9, host);
	bind_text(st_upd, 10, action);
	bind_text(st_upd, 11, policy);
	sqlite3_bind_int64(st_upd, 12, (sqlite3_int64)id);
	if (sqlite3_step(st_upd) != SQLITE_DONE)
		l7_log("update flow: %s", sqlite3_errmsg(db));
}

void
store_event(const char *type, const char *cli, const char *srv, const char *app,
    const char *cat, const char *host, const char *policy, const char *detail)
{
	if (!db)
		return;
	begin();
	sqlite3_reset(st_evt);
	sqlite3_bind_int64(st_evt, 1, time(NULL));
	bind_text(st_evt, 2, type);
	bind_text(st_evt, 3, cli);
	bind_text(st_evt, 4, srv);
	bind_text(st_evt, 5, app);
	bind_text(st_evt, 6, cat);
	bind_text(st_evt, 7, host);
	bind_text(st_evt, 8, policy);
	bind_text(st_evt, 9, detail);
	if (sqlite3_step(st_evt) != SQLITE_DONE)
		l7_log("insert event: %s", sqlite3_errmsg(db));
}

void
store_prune(int retention_days)
{
	char sql[160];
	long cutoff;

	if (!db || retention_days <= 0)
		return;
	cutoff = (long)time(NULL) - (long)retention_days * 86400L;
	store_tick(1);
	snprintf(sql, sizeof(sql), "DELETE FROM flows WHERE ts_end < %ld", cutoff);
	exec(sql);
	snprintf(sql, sizeof(sql), "DELETE FROM events WHERE ts < %ld", cutoff);
	exec(sql);
}

uint64_t
store_rows(void)
{
	return rows;
}
