<div class="content-box" style="padding: 15px;">
    <div class="form-inline" style="margin-bottom: 10px;">
        <label for="flow-period">{{ lang._('Period') }}</label>
        <select id="flow-period" class="selectpicker" data-width="auto">
            <option value="300">{{ lang._('Last 5 minutes') }}</option>
            <option value="3600">{{ lang._('Last hour') }}</option>
            <option value="21600">{{ lang._('Last 6 hours') }}</option>
            <option value="86400" selected="selected">{{ lang._('Last 24 hours') }}</option>
            <option value="604800">{{ lang._('Last 7 days') }}</option>
        </select>
        &nbsp;
        <label><input type="checkbox" id="flow-blocked"> {{ lang._('Blocked only') }}</label>
    </div>
    <table id="grid-flows" class="table table-condensed table-hover table-striped" data-store-selection="false">
        <thead>
            <tr>
                <th data-column-id="ts_end" data-formatter="time" data-width="10em">{{ lang._('Last seen') }}</th>
                <th data-column-id="client" data-type="string">{{ lang._('Client') }}</th>
                <th data-column-id="server" data-type="string">{{ lang._('Server') }}</th>
                <th data-column-id="country" data-type="string" data-width="5em">{{ lang._('Country') }}</th>
                <th data-column-id="sport" data-type="numeric" data-width="5em">{{ lang._('Port') }}</th>
                <th data-column-id="app" data-type="string">{{ lang._('Application') }}</th>
                <th data-column-id="category" data-type="string">{{ lang._('Category') }}</th>
                <th data-column-id="host" data-type="string">{{ lang._('Host') }}</th>
                <th data-column-id="bytes_down" data-formatter="bytes" data-width="7em">{{ lang._('Down') }}</th>
                <th data-column-id="bytes_up" data-formatter="bytes" data-width="7em">{{ lang._('Up') }}</th>
                <th data-column-id="action" data-formatter="action" data-width="6em">{{ lang._('Action') }}</th>
                <th data-column-id="policy" data-type="string">{{ lang._('Policy') }}</th>
            </tr>
        </thead>
        <tbody></tbody>
    </table>
</div>

<script>
    $(document).ready(function () {
        function esc(value) {
            return $('<div>').text(value === null || value === undefined ? '' : String(value)).html();
        }
        function bytes(n) {
            n = Number(n) || 0;
            const units = ['B', 'KB', 'MB', 'GB', 'TB'];
            let i = 0;
            while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
            return (i === 0 ? n.toFixed(0) : n.toFixed(1)) + ' ' + units[i];
        }

        const grid = $("#grid-flows").UIBootgrid({
            search: '/api/layer7security/flows/search',
            options: {
                rowCount: [25, 50, 100, 250],
                requestHandler: function (request) {
                    request.period = $('#flow-period').val();
                    request.only = $('#flow-blocked').is(':checked') ? 'blocked' : 'all';
                    return request;
                },
                formatters: {
                    time: function (column, row) {
                        return esc(new Date(row.ts_end * 1000).toLocaleString());
                    },
                    bytes: function (column, row) {
                        return esc(bytes(row[column.id]));
                    },
                    action: function (column, row) {
                        const cls = row.action === 'block' ? 'label-danger' : (row.action === 'allow' ? 'label-success' : 'label-default');
                        return '<span class="label ' + cls + '">' + esc(row.action) + '</span>';
                    }
                }
            }
        });
        $('#flow-period, #flow-blocked').on('change', function () {
            $("#grid-flows").bootgrid('reload');
        });
    });
</script>
