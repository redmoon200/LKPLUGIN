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
    $('#lic-copy').on('click', function () {
        if (navigator.clipboard) { navigator.clipboard.writeText($('#lic-install').text()); L7.toast('{{ lang._('Copied') }}', 'ok'); }
    });

    load();
    setInterval(load, 30000);
});
</script>
