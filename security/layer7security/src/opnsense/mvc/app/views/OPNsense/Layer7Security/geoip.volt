<div class="l7">
    {{ partial('OPNsense/Layer7Security/partials/header', [
        'title': lang._('GeoIP'),
        'subtitle': lang._('Allow or block traffic to and from countries.'),
        'icon': 'globe',
        'accent': 'con',
        'apply': true
    ]) }}

<div>
    <div class="alert alert-info" role="alert" style="margin: 15px;">
        {{ lang._('Country data maps address ranges by registry allocation. It is accurate for most addresses but not for CDNs, VPNs or mobile carriers; use it as a coarse filter, not as proof of location.') }}
    </div>
    {{ partial("layout_partials/base_form", ['fields': geoForm, 'id': 'frm_geo']) }}
    <div class="col-md-12">
        <p><strong>{{ lang._('Database') }}:</strong> <span id="geo-db">-</span></p>
        <h3>{{ lang._('Policies') }}</h3>
        <table id="grid-geo" class="table table-condensed table-hover table-striped" data-editDialog="DialogGeo" data-editAlert="geoChangeMessage">
            <thead>
                <tr>
                    <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                    <th data-column-id="enabled" data-width="6em" data-type="string" data-formatter="rowtoggle">{{ lang._('Enabled') }}</th>
                    <th data-column-id="name" data-type="string">{{ lang._('Name') }}</th>
                    <th data-column-id="action" data-type="string">{{ lang._('Action') }}</th>
                    <th data-column-id="direction" data-type="string">{{ lang._('Direction') }}</th>
                    <th data-column-id="countries" data-type="string">{{ lang._('Countries') }}</th>
                    <th data-column-id="interfaces" data-type="string">{{ lang._('Interfaces') }}</th>
                    <th data-column-id="exceptions" data-type="string">{{ lang._('Exceptions') }}</th>
                    <th data-column-id="commands" data-width="7em" data-formatter="commands" data-sortable="false">{{ lang._('Commands') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot>
                <tr>
                    <td></td>
                    <td>
                        <button data-action="add" type="button" class="btn btn-xs btn-primary"><span class="fa fa-fw fa-plus"></span></button>
                        <button data-action="deleteSelected" type="button" class="btn btn-xs btn-default"><span class="fa fa-fw fa-trash-o"></span></button>
                    </td>
                </tr>
            </tfoot>
        </table>
        <div id="geoChangeMessage" class="alert alert-info" style="display: none" role="alert">
            {{ lang._('After changing policies, click Apply to rebuild the country tables and reload the firewall.') }}
        </div>
        <h3>{{ lang._('Tables and dropped traffic') }}</h3>
        <table class="table table-condensed table-striped" id="tbl-geo" style="max-width: 720px;">
            <thead><tr><th>{{ lang._('Policy') }}</th><th>{{ lang._('Table entries') }}</th><th>{{ lang._('Packets dropped') }}</th><th>{{ lang._('Bytes dropped') }}</th></tr></thead>
            <tbody></tbody>
        </table>
        <button class="btn btn-default" id="geoUpdate" type="button">
            <i id="geoUpdate_progress"></i> {{ lang._('Update database') }}
        </button>
        <br/><br/>
    </div>
</div>
</div>

{{ partial("layout_partials/base_dialog", ['fields': formDialogGeo, 'id': 'DialogGeo', 'label': lang._('Edit GeoIP policy')]) }}


<script>
    $(document).ready(function () {
        L7.engineStatus('#l7-engine-pill');
        $('#l7-module-pill').remove();
        function esc(value) {
            return $('<div>').text(value === null || value === undefined ? '' : String(value)).html();
        }
        function bytes(n) {
            n = Number(n) || 0;
            const units = ['B', 'KB', 'MB', 'GB'];
            let i = 0;
            while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
            return (i === 0 ? n.toFixed(0) : n.toFixed(1)) + ' ' + units[i];
        }

        mapDataToFormUI({ 'frm_geo': '/api/layer7security/settings/get' }).done(function () {
            $('.selectpicker').selectpicker('refresh');
        });

        $("#grid-geo").UIBootgrid({
            search: '/api/layer7security/settings/search_geo',
            get: '/api/layer7security/settings/get_geo/',
            set: '/api/layer7security/settings/set_geo/',
            add: '/api/layer7security/settings/add_geo/',
            del: '/api/layer7security/settings/del_geo/',
            toggle: '/api/layer7security/settings/toggle_geo/'
        });

        function loadStatus() {
            ajaxGet('/api/layer7security/geo/status', {}, function (d) {
                if (!d) { return; }
                const meta = d.meta || {};
                $('#geo-db').text(d.ready
                    ? meta.v4_ranges + ' IPv4 / ' + meta.v6_ranges + ' IPv6 ranges, updated ' + new Date(meta.updated * 1000).toLocaleString() + ' (' + meta.source + ')'
                    : "{{ lang._('not loaded: press Update database') }}");
                const body = $('#tbl-geo tbody').empty();
                (d.tables || []).forEach(function (t) {
                    let pk = 0, by = 0;
                    ['in', 'out'].forEach(function (dir) {
                        const l = (d.labels || {})['l7geo_' + t.id + '_' + dir];
                        if (l) { pk += l.packets; by += l.bytes; }
                    });
                    body.append('<tr><td>' + esc(t.name) + '</td><td>' + esc(t.entries) + '</td><td>' + esc(pk) + '</td><td>' + esc(bytes(by)) + '</td></tr>');
                });
            });
        }
        loadStatus();

        $("#reconfigureAct").SimpleActionButton({
            onPreAction: function () {
                const dfObj = new $.Deferred();
                saveFormToEndpoint("/api/layer7security/settings/set", 'frm_geo', function () { dfObj.resolve(); }, true, function () { dfObj.reject(); });
                return dfObj;
            },
            onAction: function (data, status) {
                if (data && data.status === 'failed') {
                    BootstrapDialog.show({
                        type: BootstrapDialog.TYPE_DANGER,
                        title: "{{ lang._('Apply failed') }}",
                        message: $('<div>').text(data.message || '').html()
                    });
                }
                loadStatus();
            }
        });

        $("#geoUpdate").click(function () {
            $("#geoUpdate_progress").addClass("fa fa-spinner fa-pulse");
            ajaxCall('/api/layer7security/geo/update', {}, function (data, status) {
                $("#geoUpdate_progress").removeClass("fa fa-spinner fa-pulse");
                let msg = data && data.message ? data.message : '';
                if (data && data.result === 'ok') {
                    msg = data.v4_ranges + ' IPv4 and ' + data.v6_ranges + ' IPv6 ranges loaded.';
                }
                stdDialogInform("{{ lang._('GeoIP database') }}", $('<div>').text(msg).html(), "{{ lang._('Close') }}");
                loadStatus();
            });
        });
    });
</script>
