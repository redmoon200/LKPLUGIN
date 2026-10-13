<script>
    $(document).ready(function () {
        $("#grid-policies").UIBootgrid({
            search: '/api/layer7security/settings/search_policy',
            get: '/api/layer7security/settings/get_policy/',
            set: '/api/layer7security/settings/set_policy/',
            add: '/api/layer7security/settings/add_policy/',
            del: '/api/layer7security/settings/del_policy/',
            toggle: '/api/layer7security/settings/toggle_policy/'
        });

        $("#reconfigureAct").SimpleActionButton({
            onAction: function (data, status) {
                if (data && data.status === 'failed') {
                    BootstrapDialog.show({
                        type: BootstrapDialog.TYPE_DANGER,
                        title: "{{ lang._('Apply failed') }}",
                        message: $('<div>').text(data.message || '').html()
                    });
                }
            }
        });
    });
</script>

<div class="content-box">
    <table id="grid-policies" class="table table-condensed table-hover table-striped" data-editDialog="DialogPolicy" data-editAlert="policyChangeMessage">
        <thead>
            <tr>
                <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                <th data-column-id="enabled" data-width="6em" data-type="string" data-formatter="rowtoggle">{{ lang._('Enabled') }}</th>
                <th data-column-id="sequence" data-width="6em" data-type="numeric">{{ lang._('Seq') }}</th>
                <th data-column-id="name" data-type="string">{{ lang._('Name') }}</th>
                <th data-column-id="action" data-width="7em" data-type="string">{{ lang._('Action') }}</th>
                <th data-column-id="applications" data-type="string">{{ lang._('Applications') }}</th>
                <th data-column-id="categories" data-type="string">{{ lang._('Categories') }}</th>
                <th data-column-id="interfaces" data-type="string">{{ lang._('Interfaces') }}</th>
                <th data-column-id="sources" data-type="string">{{ lang._('Sources') }}</th>
                <th data-column-id="users" data-type="string">{{ lang._('Users') }}</th>
                <th data-column-id="startTime" data-width="6em" data-type="string">{{ lang._('From') }}</th>
                <th data-column-id="endTime" data-width="6em" data-type="string">{{ lang._('To') }}</th>
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
    <div class="col-md-12">
        <div id="policyChangeMessage" class="alert alert-info" style="display: none" role="alert">
            {{ lang._('After changing policies, click Apply to push them to the engine, firewall and DNS filter.') }}
        </div>
        <br/>
        <button class="btn btn-primary" id="reconfigureAct"
                data-endpoint="/api/layer7security/service/reconfigure"
                data-label="{{ lang._('Apply') }}"
                data-error-title="{{ lang._('Error applying Layer 7 policies') }}"
                type="button"></button>
        <br/><br/>
    </div>
</div>

{{ partial("layout_partials/base_dialog", ['fields': formDialogPolicy, 'id': 'DialogPolicy', 'label': lang._('Edit policy')]) }}
