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

    /**
     * turn a button into the standard Apply button; forms (ids) are saved first
     * so that "Apply changes" never loses what was typed
     */
    function applyButton(sel, onDone, forms) {
        var opts = {
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
        };
        if (forms && forms.length) {
            opts.onPreAction = function () {
                var dfObj = new $.Deferred(), i = 0;
                (function next() {
                    if (i >= forms.length) { dfObj.resolve(); return; }
                    saveFormToEndpoint('/api/layer7security/settings/set', forms[i++], next, true, function () { dfObj.reject(); });
                }());
                return dfObj;
            };
        }
        $(sel).SimpleActionButton(opts);
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

    /** the maker of the plugin: shown in the page header, the footer and the About card on the License page */
    var brand = {
        company: 'Rootsecurity Solutions Pvt. Ltd.',
        product: 'Layer 7 Security',
        site: 'https://rootsecuritysolution.com',
        email: 'info@rootsecuritysolution.com',
        phone: '+91 93604 41918',
        address: "No: 16A, Auditor's Colony, Mannivakkam, Chennai - 600048, India",
        about: 'Rootsecurity provides structured cybersecurity services, VAPT, SOC, application and network security, to help organizations reduce cyber risk and build a stronger security foundation.',
        services: ['Web Application VAPT', 'API Security Testing', 'Network Penetration Testing', 'Cloud Security Assessment', 'SOC Services', 'GRC Consulting'],
        links: {
            LinkedIn: 'https://www.linkedin.com/in/rootsecuritysolutions',
            Facebook: 'https://www.facebook.com/61583307814387/',
            Instagram: 'https://www.instagram.com/root.security_official/'
        },
        logo: '/ui/img/layer7security/logo.png'
    };

    function brandInit() {
        var $root = $('.l7').first();
        if (!$root.length) { return; }
        if (!$root.find('.l7-brand').length) {
            $root.find('.l7-head-side').first().prepend('<a class="l7-brand" href="' + esc(brand.site) + '" target="_blank" rel="noopener" title="' +
                esc(brand.company) + '"><img src="' + esc(brand.logo) + '" alt="' + esc(brand.company) + '">' +
                '<span class="l7-brand-text"><strong>Rootsecurity Solutions</strong><span>' + esc(brand.product) + '</span></span></a>');
        }
        if (!$root.find('.l7-foot').length) {
            $root.append('<div class="l7-foot">' + esc(brand.product) + ' by <a href="' + esc(brand.site) + '" target="_blank" rel="noopener">' + esc(brand.company) +
                '</a> &middot; <a href="mailto:' + esc(brand.email) + '">' + esc(brand.email) + '</a> &middot; ' + esc(brand.phone) + '</div>');
        }
    }
    $(brandInit);

    /* The OPNsense grid (Tabulator) sizes itself to the height of the window: on a small window a table of 25 rows shows
       four and scrolls inside a box of its own. Our pages let the grid grow with its rows and the page scroll instead.
       A page can still ask for the old behaviour with options: {disableScroll: false}. */
    function growingGrids() {
        if (!$.fn.UIBootgrid || $.fn.UIBootgrid.l7growing) { return; }
        var original = $.fn.UIBootgrid;
        $.fn.UIBootgrid = function (params) {
            params = params || {};
            params.options = params.options || {};
            if (params.options.disableScroll === undefined) { params.options.disableScroll = true; }
            return original.call(this, params);
        };
        $.fn.UIBootgrid.l7growing = true;
    }
    $(growingGrids);

    /* "Full view" for the log tables: the table (with its search and period controls) fills the whole browser window and
       scrolls by itself. The button sits next to Refresh; Esc or the same button closes it. */
    var FULL_VIEW_GRIDS = ['grid-flows', 'grid-audit', 'grid-av'];
    function closeFullView() {
        $('.l7-fullview').removeClass('l7-fullview').css({'background-color': '', top: ''});
        $('body').removeClass('l7-noscroll');
        $('.l7-full-btn .icon').removeClass('fa-compress').addClass('fa-expand');
        $('.l7-full-btn').attr('title', 'Full view');
    }
    function openFullView($wrap) {
        var bg = '', el = $wrap[0];
        while (el && el.nodeType === 1) {
            bg = window.getComputedStyle(el).backgroundColor;
            if (bg && bg !== 'transparent' && bg !== 'rgba(0, 0, 0, 0)') { break; }
            el = el.parentElement;
        }
        // the OPNsense top bar stays above anything we draw: start below it so no control is hidden
        var nav = document.querySelector('nav.navbar'), top = nav ? Math.max(0, Math.round(nav.getBoundingClientRect().bottom)) : 0;
        $wrap.addClass('l7-fullview').css({'background-color': bg && bg !== 'rgba(0, 0, 0, 0)' ? bg : '#fff', top: top + 'px'});
        $('body').addClass('l7-noscroll');
        $('.l7-full-btn .icon').removeClass('fa-expand').addClass('fa-compress');
        $('.l7-full-btn').attr('title', 'Close full view (Esc)');
    }
    function fullViewInit() {
        function addButtons() {
            FULL_VIEW_GRIDS.forEach(function (id) {
                var $group = $('#' + id + '-actions-group');
                if (!$group.length || $group.find('.l7-full-btn').length) { return; }
                $('<button type="button" class="btn btn-default l7-full-btn" title="Full view"><span class="icon fa-solid fa-expand"></span></button>')
                    .appendTo($group)
                    .on('click', function () {
                        var $wrap = $('#' + id).parent();
                        if ($wrap.hasClass('l7-fullview')) { closeFullView(); } else { openFullView($wrap); }
                    });
            });
        }
        addButtons();
        // the grids build their toolbar after the page is ready (and after a tab is shown for the first time)
        new MutationObserver(addButtons).observe(document.body, {childList: true, subtree: true});
        $(document).on('keydown', function (e) { if (e.key === 'Escape') { closeFullView(); } });
    }
    $(fullViewInit);

    return {
        brand: brand, esc: esc, bytes: bytes, rate: rate, dur: dur, ago: ago, when: when, num: num, pill: pill, tag: tag, tile: tile,
        empty: empty, api: api, get: get, post: post, toast: toast, confirm: confirm, apply: apply,
        applyButton: applyButton, pending: pending, engineStatus: engineStatus, flag: flag, registrable: registrable,
        rememberTabs: rememberTabs, bars: bars
    };
}(jQuery));
