<div class="l7">
    {{ partial('OPNsense/Layer7Security/partials/header', [
        'title': lang._('License'),
        'subtitle': lang._('Your license, this firewall and the cloud server.'),
        'icon': 'key',
        'accent': 'con',
        'apply': false
    ]) }}

    <div class="l7-hint" id="lic-locked" style="display:none"><strong>{{ lang._('Protection is switched off.') }}</strong> <span id="lic-locked-msg"></span> {{ lang._('Your network traffic is not affected.') }}</div>

    <div class="l7-tiles" id="lic-tiles"></div>

    <div class="l7-grid2">
        <div class="l7-card">
            <h3>{{ lang._('License key') }}</h3>
            <textarea id="lic-key" class="form-control" rows="4" spellcheck="false" placeholder="ABCDE-FGHIJ-..." style="font-family:monospace"></textarea>
            <div style="margin-top:10px">
                <button class="btn btn-primary" id="lic-activate" type="button"><i class="fa fa-check"></i> {{ lang._('Activate key') }}</button>
                <button class="btn btn-default" id="lic-trial" type="button"><i class="fa fa-clock-o"></i> {{ lang._('Start 30-day trial') }}</button>
                <button class="btn btn-default" id="lic-remove" type="button" style="display:none"><i class="fa fa-trash-o"></i> {{ lang._('Remove key') }}</button>
            </div>
            <div class="l7-muted" id="lic-keyinfo" style="margin-top:10px"></div>
        </div>
        <div class="l7-card">
            <h3>{{ lang._('This firewall') }}</h3>
            <table class="l7-table"><tbody>
                <tr><td>{{ lang._('Installation id') }}</td><td><code id="lic-install" style="font-size:15px"></code> <button class="btn btn-xs btn-default" id="lic-copy" type="button"><i class="fa fa-copy"></i></button></td></tr>
                <tr><td>{{ lang._('Key id') }}</td><td><code id="lic-keyid">-</code></td></tr>
                <tr><td>{{ lang._('Tied to this firewall') }}</td><td id="lic-bound">-</td></tr>
            </tbody></table>
        </div>
        <div class="l7-card" style="grid-column:1/-1">
            <h3>{{ lang._('Cloud server') }}</h3>
            <div class="l7-toolbar">
                <strong>{{ lang._('Address') }}</strong>
                <input type="text" id="lic-server" class="form-control" style="width:340px" placeholder="http://192.168.1.73:8080/feeds">
                <button class="btn btn-default" id="lic-save" type="button">{{ lang._('Save') }}</button>
                <button class="btn btn-primary" id="lic-sync" type="button"><i class="fa fa-cloud-download"></i> {{ lang._('Check in and update now') }}</button>
            </div>
            <div class="l7-tiles" id="lic-cloud" style="margin:12px 0 0"></div>
        </div>
        <div class="l7-card" style="grid-column:1/-1">
            <h3>{{ lang._('Updates') }}</h3>
            <div class="l7-tiles" id="upd-tiles" style="margin:0 0 12px"></div>
            <div class="l7-muted" id="upd-notes" style="white-space:pre-line;margin-bottom:10px"></div>
            <div class="l7-toolbar">
                <button class="btn btn-primary" id="upd-install" type="button" style="display:none"><i class="fa fa-download"></i> {{ lang._('Install the update') }}</button>
                <button class="btn btn-default" id="upd-check" type="button"><i class="fa fa-refresh"></i> {{ lang._('Check for updates') }}</button>
                <button class="btn btn-default" id="upd-rollback" type="button" style="display:none"><i class="fa fa-undo"></i> {{ lang._('Go back to the previous version') }}</button>
                <select id="upd-channel" class="form-control" style="width:auto"><option value="stable">{{ lang._('Stable releases') }}</option><option value="beta">{{ lang._('Beta releases too') }}</option></select>
                <label style="font-weight:normal;margin:0"><input type="checkbox" id="upd-auto"> {{ lang._('Install plugin updates automatically') }}</label>
            </div>
            <p class="l7-muted" style="margin-top:10px">{{ lang._('Releases are signed by the vendor and checked before they are installed. If a new version does not start correctly, the old one is put back automatically.') }}</p>
            <div id="upd-fw" style="margin-top:6px"></div>
        </div>
        <div class="l7-card" style="grid-column:1/-1">
            <h3>{{ lang._('Remote support') }}</h3>
            <p class="l7-muted">{{ lang._('Lets your vendor help you from the cloud server. Switched off, nothing can be seen or changed. Every command is signed by the vendor, valid for ten minutes and listed below. You can switch this off at any time.') }}</p>
            <select id="sup-level" class="form-control" style="width:auto;display:inline-block">
                <option value="off">{{ lang._('Off') }}</option>
                <option value="view">{{ lang._('View only: settings, blocked and allowed sites, events') }}</option>
                <option value="manage">{{ lang._('Full support: view and change settings') }}</option>
            </select>
            <div class="l7-muted" id="sup-note" style="margin-top:8px"></div>
            <table class="l7-table" style="margin-top:12px"><thead><tr><th>{{ lang._('Time') }}</th><th>{{ lang._('Action') }}</th><th>{{ lang._('Details') }}</th><th>{{ lang._('Result') }}</th></tr></thead><tbody id="sup-log"></tbody></table>
        </div>
        <div class="l7-card" style="grid-column:1/-1">
            <h3>{{ lang._('Monitoring') }}</h3>
            <p class="l7-muted">{{ lang._('Once a minute this firewall tells the cloud server how it is doing: CPU, memory, disk, gateways, internet, and counters of blocked traffic with the public addresses that were blocked on the way in. Your vendor uses this to see outages and support you. No browsing history, client names or user names are sent.') }}</p>
            <label style="font-weight:normal"><input type="checkbox" id="mon-enabled"> {{ lang._('Send health and security status to the cloud server') }}</label>
            <div class="l7-tiles" id="mon-tiles" style="margin:12px 0 0"></div>
        </div>
        <div class="l7-card" style="grid-column:1/-1" id="about-card"></div>
    </div>
</div>

<script>
$(document).ready(function () {
    var E = L7.esc, ST = null;
    L7.engineStatus('#l7-engine-pill');
    $('#l7-module-pill').remove();

    function dayStr(ts) { return ts ? new Date(ts * 1000).toISOString().slice(0, 10) : ''; }
    var STATE = {valid: ['Active', 'ok'], none: ['No license', 'bad'], expired: ['Expired', 'bad'], invalid: ['Invalid key', 'bad'],
                 wrongmachine: ['Other firewall', 'bad'], revoked: ['Withdrawn', 'bad'], rollback: ['Clock is behind', 'bad']};

    function renderAbout(version) {
        var b = L7.brand;
        $('#about-card').html('<div class="l7-about"><img src="' + E(b.logo) + '" alt="' + E(b.company) + '"><div class="l7-about-text"><h3>' + E(b.product) + (version ? ' ' + E(version) : '') +
            '</h3><p>' + E(b.about) + '</p><div class="l7-about-services">' + b.services.map(function (x) { return '<span>' + E(x) + '</span>'; }).join('') + '</div>' +
            '<table class="l7-table"><tbody>' +
            '<tr><td>{{ lang._('Made by') }}</td><td><strong>' + E(b.company) + '</strong></td></tr>' +
            '<tr><td>{{ lang._('Website') }}</td><td><a href="' + E(b.site) + '" target="_blank" rel="noopener">' + E(b.site.replace('https://', '')) + '</a></td></tr>' +
            '<tr><td>{{ lang._('Email') }}</td><td><a href="mailto:' + E(b.email) + '">' + E(b.email) + '</a></td></tr>' +
            '<tr><td>{{ lang._('Phone') }}</td><td>' + E(b.phone) + '</td></tr>' +
            '<tr><td>{{ lang._('Address') }}</td><td>' + E(b.address) + '</td></tr>' +
            '<tr><td>{{ lang._('Follow us') }}</td><td>' + Object.keys(b.links).map(function (k) { return '<a href="' + E(b.links[k]) + '" target="_blank" rel="noopener">' + E(k) + '</a>'; }).join(' &middot; ') + '</td></tr>' +
            '</tbody></table></div></div>');
    }

    function render(d) {
        ST = d;
        var l = d.license, c = d.cloud || {}, s = STATE[l.state] || [l.state, 'bad'];
        $('#lic-tiles').html(
            L7.tile(s[0], '{{ lang._('License') }}', l.message, s[1]) +
            L7.tile(l.label || '-', '{{ lang._('Type') }}', l.key_id ? '' : '') +
            L7.tile(l.type === 'lifetime' ? '{{ lang._('Never') }}' : (l.expires ? dayStr(l.expires) : '-'), '{{ lang._('Expires') }}',
                    l.days_left !== null && l.valid ? l.days_left + ' {{ lang._('days left') }}' : '', l.warn ? 'warn' : '') +
            L7.tile(l.install_id, '{{ lang._('Installation id') }}', ''));
        $('#lic-locked').toggle(!l.valid);
        $('#lic-locked-msg').text(l.message);
        $('#lic-install').text(l.install_id);
        $('#lic-keyid').text(l.key_id || '-');
        $('#lic-bound').text(l.key_id ? (l.bound ? '{{ lang._('Yes') }}' : '{{ lang._('No, works on any firewall') }}') : '-');
        $('#lic-keyinfo').text(d.key ? '{{ lang._('Current key') }}: ' + d.key : '');
        $('#lic-remove').toggle(!!d.key);
        $('#lic-trial').toggle(!l.valid);
        if (document.activeElement !== document.getElementById('lic-server')) { $('#lic-server').val(d.server || ''); }
        var contact = c.ts ? L7.ago(c.ts) : '{{ lang._('never') }}';
        var cloudKind = !d.server ? 'warn' : (c.ok === false ? 'bad' : (c.ts ? 'ok' : 'warn'));
        $('#lic-cloud').html(
            L7.tile(!d.server ? '{{ lang._('Not set') }}' : (c.ok === false ? '{{ lang._('Not reachable') }}' : (c.ts ? '{{ lang._('Connected') }}' : '{{ lang._('Not contacted yet') }}')),
                    '{{ lang._('Cloud server') }}', c.error || '', cloudKind) +
            L7.tile(contact, '{{ lang._('Last check-in') }}', c.server_message || '') +
            L7.tile(c.feedUpdate ? L7.ago(c.feedUpdate) : '{{ lang._('never') }}', '{{ lang._('Last list update') }}', ''));
        if (document.activeElement !== document.getElementById('sup-level')) { $('#sup-level').val(d.support || 'off'); }
        $('#sup-note').text(d.support === 'manage' ? '{{ lang._('Your vendor can currently view and change settings of this plugin.') }}' : (d.support === 'view' ? '{{ lang._('Your vendor can currently only look.') }}' : '{{ lang._('Remote support is off.') }}'));
        L7.get('/api/layer7security/license/supportlog').done(function (r) {
            $('#sup-log').html((r.rows || []).map(function (x) {
                return '<tr><td>' + E(new Date(x.ts * 1000).toLocaleString()) + '</td><td>' + E(x.action) + '</td><td><code>' + E(x.detail || '') + '</code></td><td>' + E(x.result || '') + '</td></tr>';
            }).join('') || '<tr><td colspan="4" class="l7-muted">{{ lang._('Nothing yet: your vendor has not used remote support.') }}</td></tr>');
        });
        renderUpdates(d.updates || {});
        renderAbout(((d.updates || {}).plugin || {}).installed);
        var m = d.monitoring || {};
        $('#mon-enabled').prop('checked', m.enabled !== false);
        var mkind = m.enabled === false ? 'warn' : (m.error ? 'bad' : (m.lastOk ? 'ok' : 'warn'));
        $('#mon-tiles').html(
            L7.tile(m.enabled === false ? '{{ lang._('Off') }}' : (m.error ? '{{ lang._('Problem') }}' : (m.lastOk ? '{{ lang._('Reporting') }}' : '{{ lang._('Waiting') }}')),
                    '{{ lang._('Monitoring') }}', m.error || '', mkind) +
            L7.tile(m.lastOk ? L7.ago(m.lastOk) : '{{ lang._('never') }}', '{{ lang._('Last report') }}', m.enrolled ? '{{ lang._('Registered with the cloud server') }}' : '') +
            L7.tile(m.alertsOpen || 0, '{{ lang._('Open alerts at the vendor') }}', '', m.alertsOpen ? 'warn' : 'ok'));
    }

    var updPoll = null;
    function renderUpdates(u) {
        var p = u.plugin || {}, f = u.firmware || {}, cfg = u.settings || {};
        var st = p.state === 'installing' ? ['{{ lang._('Updating...') }}', 'warn'] : (p.state === 'failed' ? ['{{ lang._('Update failed') }}', 'bad'] : (p.available ? ['{{ lang._('Available') }}', 'warn'] : ['{{ lang._('Up to date') }}', 'ok']));
        $('#upd-tiles').html(
            L7.tile(p.installed || '-', '{{ lang._('Plugin version') }}', p.latest && p.available ? '{{ lang._('New') }}: ' + p.latest : '') +
            L7.tile(st[0], '{{ lang._('Plugin updates') }}', p.error || p.blocked || (p.checked ? '{{ lang._('checked') }} ' + L7.ago(p.checked) : '{{ lang._('not checked yet') }}'), st[1]) +
            L7.tile(f.patch_count || 0, '{{ lang._('OPNsense updates waiting') }}', f.checked ? '{{ lang._('checked') }} ' + L7.ago(f.checked) : '{{ lang._('not checked yet') }}', f.patch_count ? 'warn' : 'ok') +
            L7.tile(f.needs_reboot ? '{{ lang._('Restart needed') }}' : '-', '{{ lang._('OPNsense restart') }}', '', f.needs_reboot ? 'warn' : ''));
        $('#upd-notes').text(p.available && p.notes ? p.notes : '');
        $('#upd-install').toggle(!!p.available && p.state !== 'installing').text(' {{ lang._('Install') }} ' + (p.latest || ''));
        $('#upd-rollback').toggle(!!p.rollback && p.state !== 'installing');
        if (document.activeElement !== document.getElementById('upd-channel')) { $('#upd-channel').val(cfg.channel || 'stable'); }
        $('#upd-auto').prop('checked', !!cfg.auto);
        var fw = '';
        if (f.major) { fw += '<div class="l7-hint">' + (f.major.eol ? '<strong>{{ lang._('OPNsense') }} ' + E(f.abi || '') + ' {{ lang._('has reached end of life.') }}</strong> ' : '') + '{{ lang._('Version') }} ' + E(f.major.version) + ' {{ lang._('is available. A major upgrade needs planning.') }}</div>'; }
        if (f.patch_count) { fw += '<div class="l7-muted">' + E(f.patches.slice(0, 6).map(function (x) { return x.name + ' ' + x.from + ' > ' + x.to; }).join(', ')) + (f.patch_count > 6 ? ' ...' : '') + '. <a href="/ui/core/firmware">{{ lang._('Install them under System > Firmware') }}</a></div>'; }
        $('#upd-fw').html(fw);
        if (p.state === 'installing') { if (!updPoll) { updPoll = setInterval(function () { L7.get('/api/layer7security/license/status').done(function (d) { render(d); if ((d.updates.plugin || {}).state !== 'installing') { clearInterval(updPoll); updPoll = null; } }); }, 4000); } }
    }

    function load() {
        L7.get('/api/layer7security/license/status').done(render).fail(function () { L7.toast('{{ lang._('The license state could not be read.') }}', 'bad'); });
    }

    function busy(btn, on) { btn.prop('disabled', on); }

    $('#lic-activate').on('click', function () {
        var b = $(this); busy(b, true);
        L7.post('/api/layer7security/license/activate', {key: $('#lic-key').val()}).done(function (r) {
            L7.toast(r.message || '', r.ok ? 'ok' : 'bad');
            if (r.ok) { $('#lic-key').val(''); }
            load();
        }).fail(function () { L7.toast('{{ lang._('The request failed.') }}', 'bad'); }).always(function () { busy(b, false); });
    });
    $('#lic-trial').on('click', function () {
        var b = $(this); busy(b, true);
        L7.post('/api/layer7security/license/trial', {}).done(function (r) {
            L7.toast(r.message || '', r.ok ? 'ok' : 'bad'); load();
        }).fail(function () { L7.toast('{{ lang._('The request failed.') }}', 'bad'); }).always(function () { busy(b, false); });
    });
    $('#lic-remove').on('click', function () {
        L7.confirm({title: '{{ lang._('Remove the license key?') }}', message: '{{ lang._('Protection switches off until a key is activated again.') }}', danger: true, yes: '{{ lang._('Remove') }}', cancel: '{{ lang._('Cancel') }}', onYes: function () {
            L7.post('/api/layer7security/license/remove', {}).done(function () { load(); });
        }});
    });
    $('#lic-save').on('click', function () {
        L7.post('/api/layer7security/license/server', {server: $('#lic-server').val()}).done(function (r) {
            L7.toast(r.ok ? '{{ lang._('Saved') }}' : (r.message || ''), r.ok ? 'ok' : 'bad'); load();
        });
    });
    $('#lic-sync').on('click', function () {
        var b = $(this); busy(b, true);
        L7.post('/api/layer7security/license/sync', {}).done(function (r) {
            var c = r.checkin || {};
            L7.toast(c.ok ? '{{ lang._('Checked in with the cloud server.') }}' : (c.error || '{{ lang._('The cloud server could not be reached.') }}'), c.ok ? 'ok' : 'bad');
            if (r.status) { render(r.status); }
        }).fail(function () { L7.toast('{{ lang._('The request failed.') }}', 'bad'); }).always(function () { busy(b, false); });
    });
    $('#mon-enabled').on('change', function () {
        var on = $(this).prop('checked');
        L7.post('/api/layer7security/license/monitoring', {enabled: on ? '1' : '0'}).done(function (r) {
            L7.toast(r.ok ? (on ? '{{ lang._('Monitoring is on.') }}' : '{{ lang._('Monitoring is off.') }}') : (r.message || ''), r.ok ? 'ok' : 'bad'); load();
        }).fail(function () { L7.toast('{{ lang._('The request failed.') }}', 'bad'); load(); });
    });
    $('#sup-level').on('change', function () {
        var v = $(this).val();
        L7.post('/api/layer7security/license/support', {level: v}).done(function (r) {
            L7.toast(r.ok ? '{{ lang._('Saved') }}' : (r.message || ''), r.ok ? 'ok' : 'bad'); load();
        }).fail(function () { L7.toast('{{ lang._('The request failed.') }}', 'bad'); load(); });
    });
    $('#upd-check').on('click', function () {
        var b = $(this); busy(b, true);
        L7.post('/api/layer7security/license/updatecheck', {}).done(function (r) {
            L7.toast(r.ok ? '{{ lang._('Checked. OPNsense is looking for updates in the background.') }}' : ((r.check || {}).error || '{{ lang._('The update server could not be reached.') }}'), r.ok ? 'ok' : 'bad');
            if (r.updates) { renderUpdates(r.updates); }
        }).fail(function () { L7.toast('{{ lang._('The request failed.') }}', 'bad'); }).always(function () { busy(b, false); });
    });
    $('#upd-install').on('click', function () {
        L7.confirm({title: '{{ lang._('Install the update?') }}', message: '{{ lang._('The plugin restarts for a few seconds. Your network traffic is not affected. If the new version does not start, the old one is restored.') }}', yes: '{{ lang._('Install') }}', cancel: '{{ lang._('Cancel') }}', onYes: function () {
            L7.post('/api/layer7security/license/updateinstall', {}).done(function (r) { L7.toast(r.message || '', r.ok ? 'ok' : 'bad'); load(); });
        }});
    });
    $('#upd-rollback').on('click', function () {
        L7.confirm({title: '{{ lang._('Go back to the previous version?') }}', message: '', danger: true, yes: '{{ lang._('Go back') }}', cancel: '{{ lang._('Cancel') }}', onYes: function () {
            L7.post('/api/layer7security/license/updaterollback', {}).done(function (r) { L7.toast(r.message || '', r.ok ? 'ok' : 'bad'); load(); });
        }});
    });
    $('#upd-channel, #upd-auto').on('change', function () {
        L7.post('/api/layer7security/license/updatesettings', {channel: $('#upd-channel').val(), auto: $('#upd-auto').prop('checked') ? '1' : '0'}).done(function (r) {
            L7.toast(r.ok ? '{{ lang._('Saved') }}' : (r.message || ''), r.ok ? 'ok' : 'bad'); load();
        });
    });
    $('#lic-copy').on('click', function () {
        if (navigator.clipboard) { navigator.clipboard.writeText($('#lic-install').text()); L7.toast('{{ lang._('Copied') }}', 'ok'); }
    });

    load();
    setInterval(load, 30000);
});
</script>
