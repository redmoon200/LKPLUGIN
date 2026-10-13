/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Helpers shared by the Layer 7 Security console pages.
 */
window.L7 = (function ($) {
    'use strict';

    var ENT = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};

    function esc(s) {
        return String(s === null || s === undefined ? '' : s).replace(/[&<>"']/g, function (c) { return ENT[c]; });
    }

    function bytes(n) {
        n = Number(n) || 0;
        var u = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0;
        while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
        return (i === 0 ? String(Math.round(n)) : n.toFixed(n < 10 ? 2 : 1)) + ' ' + u[i];
    }

    function rate(bps) {
        bps = Number(bps) || 0;
        if (bps < 1) { return '0 B/s'; }
        return bytes(bps) + '/s';
    }

    function dur(sec) {
        sec = Math.max(0, Math.floor(Number(sec) || 0));
        if (sec < 60) { return sec + 's'; }
        if (sec < 3600) { return Math.floor(sec / 60) + 'm ' + (sec % 60) + 's'; }
        if (sec < 86400) { return Math.floor(sec / 3600) + 'h ' + Math.floor((sec % 3600) / 60) + 'm'; }
        return Math.floor(sec / 86400) + 'd ' + Math.floor((sec % 86400) / 3600) + 'h';
    }

    function ago(ts) {
        if (!ts) { return ''; }
        var d = Math.floor(Date.now() / 1000) - Number(ts);
        return d < 5 ? 'just now' : dur(d) + ' ago';
    }

    function when(ts) {
        if (!ts) { return ''; }
        var d = new Date(Number(ts) * 1000);
        function p(n) { return (n < 10 ? '0' : '') + n; }
        return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
    }

    function num(n) {
        return Number(n || 0).toLocaleString();
    }

    /** status pill: kind is ok, warn, bad, info or empty */
    function pill(text, kind) {
        return '<span class="l7-pill ' + esc(kind || '') + '">' + esc(text) + '</span>';
    }

    function tag(text, kind) {
        return '<span class="l7-tag ' + esc(kind || '') + '">' + esc(text) + '</span>';
    }

    /** dashboard tile */
    function tile(value, label, sub, kind) {
        return '<div class="l7-tile ' + esc(kind || '') + '"><div class="v">' + esc(value) + '</div><div class="l">' +
            esc(label) + '</div>' + (sub ? '<div class="s">' + esc(sub) + '</div>' : '') + '</div>';
    }

    function empty(icon, text) {
        return '<div class="l7-empty"><i class="fa fa-' + esc(icon || 'info-circle') + '"></i>' + esc(text) + '</div>';
    }

    /** JSON request, resolves with the parsed answer */
    function api(method, url, data) {
        var opts = {url: url, type: method, dataType: 'json', timeout: 120000};
        if (data !== undefined && method !== 'GET') {
            opts.data = JSON.stringify(data);
            opts.contentType = 'application/json';
        } else if (data !== undefined) {
            opts.data = data;
        }
        return $.ajax(opts);
    }

    function get(url, data) { return api('GET', url, data); }
    function post(url, data) { return api('POST', url, data === undefined ? {} : data); }

    function toast(text, kind) {
        var el = $('<div class="l7-toast"></div>').text(text).css({
            position: 'fixed', right: '20px', bottom: '20px', zIndex: 20000, maxWidth: '380px',
            padding: '10px 16px', borderRadius: '8px', color: '#fff', fontSize: '13px',
            boxShadow: '0 4px 14px rgba(0,0,0,.3)',
            background: kind === 'bad' ? '#d03b3b' : (kind === 'warn' ? '#c78a00' : '#2e9e57')
        });
        $('body').append(el);
        setTimeout(function () { el.fadeOut(300, function () { el.remove(); }); }, kind === 'bad' ? 7000 : 3500);
    }

    /** confirmation dialog: opts {title, message (html allowed, escape yourself), yes, danger, onYes} */
    function confirm(opts) {
        BootstrapDialog.show({
            type: opts.danger ? BootstrapDialog.TYPE_DANGER : BootstrapDialog.TYPE_PRIMARY,
            title: opts.title,
            message: opts.message,
            closable: true,
            buttons: [
                {label: opts.cancel || 'Cancel', action: function (d) { d.close(); }},
                {label: opts.yes || 'OK', cssClass: opts.danger ? 'btn-danger' : 'btn-primary', action: function (d) {
                    d.close();
                    if (opts.onYes) { opts.onYes(); }
                }}
            ]
        });
    }

    /** Apply: write the configuration to the engine, DNS filter and firewall */
    function apply() {
        return post('/api/layer7security/service/reconfigure');
    }

    /** turn a button into the standard Apply button */
    function applyButton(sel, onDone) {
        $(sel).SimpleActionButton({
            onAction: function (data) {
                if (data && data.status === 'failed') {
                    BootstrapDialog.show({
                        type: BootstrapDialog.TYPE_DANGER,
                        title: 'Apply failed',
                        message: $('<div>').text(data.message || '').html()
                    });
                }
                $('#l7-pending').hide();
                if (onDone) { onDone(data); }
            }
        });
    }

    function pending() { $('#l7-pending').show(); }

    /** engine pill in the page header */
    function engineStatus(sel) {
        get('/api/layer7security/service/status').done(function (d) {
            var run = d && d.status === 'running';
            $(sel).replaceWith($(pill(run ? 'Engine running' : 'Engine stopped', run ? 'ok' : 'bad')).attr('id', sel.replace('#', '')));
        });
    }

    /** regional indicator flag from an ISO country code */
    function flag(cc) {
        if (!cc || cc.length !== 2 || !/^[A-Za-z]{2}$/.test(cc)) { return ''; }
        cc = cc.toUpperCase();
        return String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65, 0x1F1E6 + cc.charCodeAt(1) - 65);
    }

    /** "www.shop.example.co.uk" -> "example.co.uk" (small heuristic, no public suffix list) */
    function registrable(host) {
        var p = String(host || '').toLowerCase().split('.');
        if (p.length <= 2) { return p.join('.'); }
        var sld = {co: 1, com: 1, org: 1, net: 1, gov: 1, ac: 1, edu: 1, or: 1, ne: 1, go: 1};
        if (p[p.length - 1].length === 2 && sld[p[p.length - 2]]) { return p.slice(-3).join('.'); }
        return p.slice(-2).join('.');
    }

    /** keep the selected tab across reloads (and allow #tab links) */
    function rememberTabs(key) {
        try {
            var want = location.hash || sessionStorage.getItem('l7tab:' + key);
            if (want && $('.l7 .nav-tabs a[href="' + want + '"]').length) {
                $('.l7 .nav-tabs a[href="' + want + '"]').tab('show');
            }
        } catch (e) { /* storage blocked */ }
        $('.l7 .nav-tabs a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
            try { sessionStorage.setItem('l7tab:' + key, $(e.target).attr('href')); } catch (x) { /* ignore */ }
        });
    }

    /** simple horizontal bar list: rows [{label, value, text}] */
    function bars(rows, max) {
        if (!rows || !rows.length) { return empty('bar-chart', 'Nothing to show yet'); }
        max = max || Math.max.apply(null, rows.map(function (r) { return r.value; })) || 1;
        return rows.map(function (r) {
            return '<div style="margin:0 0 9px 0"><div style="display:flex;justify-content:space-between;gap:8px;font-size:13px">' +
                '<span class="trunc" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(r.label) + '</span>' +
                '<span class="l7-muted" style="white-space:nowrap">' + esc(r.text) + '</span></div>' +
                '<div class="l7-bar"><span style="width:' + Math.max(2, Math.round(100 * r.value / max)) + '%"></span></div></div>';
        }).join('');
    }

    return {
        esc: esc, bytes: bytes, rate: rate, dur: dur, ago: ago, when: when, num: num, pill: pill, tag: tag, tile: tile,
        empty: empty, api: api, get: get, post: post, toast: toast, confirm: confirm, apply: apply,
        applyButton: applyButton, pending: pending, engineStatus: engineStatus, flag: flag, registrable: registrable,
        rememberTabs: rememberTabs, bars: bars
    };
}(jQuery));
