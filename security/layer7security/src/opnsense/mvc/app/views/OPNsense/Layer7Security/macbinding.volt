<script>
    $(document).ready(function () {
        function esc(value) {
            return $('<div>').text(value === null || value === undefined ? '' : String(value)).html();
        }
        const stateLabel = {
            'bound': ['label-success', "{{ lang._('bound') }}"],
            'spoof': ['label-danger', "{{ lang._('SPOOF: address bound to another MAC') }}"],
            'mac-bound': ['label-info', "{{ lang._('MAC allow-listed') }}"],
            'unbound': ['label-default', "{{ lang._('unbound') }}"]
        };

        mapDataToFormUI({ 'frm_mac': '/api/layer7security/settings/get' }).done(function () {
            $('.selectpicker').selectpicker('refresh');
        });

        $("#grid-bindings").UIBootgrid({
            search: '/api/layer7security/settings/search_binding',
            get: '/api/layer7security/settings/get_binding/',
            set: '/api/layer7security/settings/set_binding/',
            add: '/api/layer7security/settings/add_binding/',
            del: '/api/layer7security/settings/del_binding/',
            toggle: '/api/layer7security/settings/toggle_binding/'
        });

        function loadDevices() {
            ajaxGet('/api/layer7security/dashboard/devices', { period: $('#dev-period').val() }, function (d) {
                const body = $('#tbl-devices tbody').empty();
                if (!d || !d.rows) { return; }
                if (d.rows.length === 0) {
                    body.append('<tr><td colspan="7" class="text-muted">{{ lang._("No devices seen yet. Devices appear when the engine is running and they send traffic or ARP.") }}</td></tr>');
                }
                d.rows.forEach(function (r) {
                    const st = stateLabel[r.state] || stateLabel.unbound;
                    const action = (r.state === 'unbound')
                        ? '<button class="btn btn-xs btn-primary bind-btn" data-ip="' + esc(r.ip) + '" data-mac="' + esc(r.mac) + '"><span class="fa fa-link"></span> {{ lang._("Bind") }}</button>'
                        : '';
                    body.append('<tr><td>' + esc(r.ip) + '</td><td><code>' + esc(r.mac) + '</code></td><td>' + esc(r.iface) +
                        '</td><td>' + esc(new Date(r.last_seen * 1000).toLocaleString()) +
                        '</td><td><span class="label ' + st[0] + '">' + esc(st[1]) + '</span> ' + esc(r.bound_name) +
                        '</td><td>' + esc(r.hits) + '</td><td>' + action + '</td></tr>');
                });
            });
        }
        loadDevices();
        $('#dev-period').on('change', loadDevices);
        $('#refreshDevices').click(loadDevices);

        // one click: bind a discovered device to the IP and MAC it is using now
        $('#tbl-devices').on('click', '.bind-btn', function () {
            const ip = $(this).data('ip'), mac = $(this).data('mac');
            ajaxCall('/api/layer7security/settings/add_binding', {
                binding: { enabled: '1', name: 'device-' + ip, mac: mac, ip: ip, interface: '', description: 'bound from the discovered devices list' }
            }, function (data) {
                if (data && data.result === 'saved') {
                    $('#grid-bindings').bootgrid('reload');
                    loadDevices();
                } else {
                    stdDialogInform("{{ lang._('Cannot bind') }}", JSON.stringify(data && data.validations ? data.validations : data), "{{ lang._('Close') }}");
                }
            });
        });

        $("#reconfigureAct").SimpleActionButton({
            onPreAction: function () {
                const dfObj = new $.Deferred();
                saveFormToEndpoint("/api/layer7security/settings/set", 'frm_mac', function () { dfObj.resolve(); }, true, function () { dfObj.reject(); });
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
                loadDevices();
            }
        });
    });
</script>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#bindings">{{ lang._('Bindings') }}</a></li>
    <li><a data-toggle="tab" href="#devices">{{ lang._('Discovered devices') }}</a></li>
    <li><a data-toggle="tab" href="#settings">{{ lang._('Mode') }}</a></li>
</ul>
<div class="tab-content content-box">
    <div id="bindings" class="tab-pane fade in active">
        <table id="grid-bindings" class="table table-condensed table-hover table-striped" data-editDialog="DialogBinding" data-editAlert="bindingChangeMessage">
            <thead>
                <tr>
                    <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                    <th data-column-id="enabled" data-width="6em" data-type="string" data-formatter="rowtoggle">{{ lang._('Enabled') }}</th>
                    <th data-column-id="name" data-type="string">{{ lang._('Name') }}</th>
                    <th data-column-id="mac" data-type="string">{{ lang._('MAC address') }}</th>
                    <th data-column-id="ip" data-type="string">{{ lang._('IPv4 address') }}</th>
                    <th data-column-id="interface" data-type="string">{{ lang._('Interface') }}</th>
                    <th data-column-id="description" data-type="string">{{ lang._('Description') }}</th>
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
        <div id="bindingChangeMessage" class="alert alert-info" style="display: none" role="alert">
            {{ lang._('After changing bindings, click Apply so the firewall enforces them.') }}
        </div>
    </div>
    <div id="devices" class="tab-pane fade in">
        <div class="form-inline" style="margin: 10px 0;">
            <label for="dev-period">{{ lang._('Seen in the last') }}</label>
            <select id="dev-period" class="selectpicker" data-width="auto">
                <option value="3600">{{ lang._('hour') }}</option>
                <option value="86400" selected="selected">{{ lang._('24 hours') }}</option>
                <option value="604800">{{ lang._('7 days') }}</option>
            </select>
            <button class="btn btn-default" id="refreshDevices" type="button"><span class="fa fa-refresh"></span> {{ lang._('Refresh') }}</button>
        </div>
        <table class="table table-condensed table-striped" id="tbl-devices">
            <thead>
                <tr>
                    <th>{{ lang._('IPv4 address') }}</th><th>{{ lang._('MAC address') }}</th><th>{{ lang._('Interface') }}</th>
                    <th>{{ lang._('Last seen') }}</th><th>{{ lang._('State') }}</th><th>{{ lang._('Frames') }}</th><th></th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>
    <div id="settings" class="tab-pane fade in">
        {{ partial("layout_partials/base_form", ['fields': macForm, 'id': 'frm_mac']) }}
    </div>
    <div class="col-md-12">
        <hr/>
        <button class="btn btn-primary" id="reconfigureAct"
                data-endpoint="/api/layer7security/service/reconfigure"
                data-label="{{ lang._('Apply') }}"
                data-error-title="{{ lang._('Error applying MAC bindings') }}"
                type="button"></button>
        <br/><br/>
    </div>
</div>

{{ partial("layout_partials/base_dialog", ['fields': formDialogBinding, 'id': 'DialogBinding', 'label': lang._('Edit binding')]) }}
