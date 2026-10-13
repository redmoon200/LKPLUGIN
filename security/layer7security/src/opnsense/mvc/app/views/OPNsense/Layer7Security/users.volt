<script>
    $(document).ready(function () {
        $("#grid-users").UIBootgrid({
            search: '/api/layer7security/settings/search_user',
            get: '/api/layer7security/settings/get_user/',
            set: '/api/layer7security/settings/set_user/',
            add: '/api/layer7security/settings/add_user/',
            del: '/api/layer7security/settings/del_user/'
        });

        $("#reconfigureAct").SimpleActionButton();
    });
</script>

<div class="content-box">
    <table id="grid-users" class="table table-condensed table-hover table-striped" data-editDialog="DialogUser" data-editAlert="userChangeMessage">
        <thead>
            <tr>
                <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                <th data-column-id="name" data-type="string">{{ lang._('Name') }}</th>
                <th data-column-id="addresses" data-type="string">{{ lang._('IP addresses') }}</th>
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
    <div class="col-md-12">
        <div id="userChangeMessage" class="alert alert-info" style="display: none" role="alert">
            {{ lang._('After changing users, click Apply so policies that reference them are updated.') }}
        </div>
        <br/>
        <button class="btn btn-primary" id="reconfigureAct"
                data-endpoint="/api/layer7security/service/reconfigure"
                data-label="{{ lang._('Apply') }}"
                data-error-title="{{ lang._('Error applying Layer 7 configuration') }}"
                type="button"></button>
        <br/><br/>
    </div>
</div>

{{ partial("layout_partials/base_dialog", ['fields': formDialogUser, 'id': 'DialogUser', 'label': lang._('Edit user')]) }}
