<div class="l7">
    {{ partial('OPNsense/Layer7Security/partials/header', [
        'title': lang._('Layer 7 Settings'),
        'subtitle': lang._('Switch the engine on, choose the networks it watches and how long data is kept.'),
        'icon': 'cog',
        'accent': 'con',
        'apply': true
    ]) }}

<div>
    {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general']) }}
    <div class="col-md-12">
        <button class="btn btn-default" id="catalogAct" type="button">
            <i id="catalogAct_progress"></i> {{ lang._('Refresh application catalog') }}
        </button>
        <br/><br/>
    </div>
</div>
</div>

<script>
    $(document).ready(function () {
        L7.engineStatus('#l7-engine-pill');
        $('#l7-module-pill').remove();
        mapDataToFormUI({ 'frm_general': '/api/layer7security/settings/get' }).done(function () {
            $('.selectpicker').selectpicker('refresh');
            updateServiceControlUI('layer7security');
        });

        $("#reconfigureAct").SimpleActionButton({
            onPreAction: function () {
                const dfObj = new $.Deferred();
                saveFormToEndpoint("/api/layer7security/settings/set", 'frm_general', function () { dfObj.resolve(); }, true, function () { dfObj.reject(); });
                return dfObj;
            },
            onAction: function (data, status) {
                updateServiceControlUI('layer7security');
                if (data && data.status === 'failed') {
                    BootstrapDialog.show({
                        type: BootstrapDialog.TYPE_DANGER,
                        title: "{{ lang._('Apply failed') }}",
                        message: $('<div>').text(data.message || '').html()
                    });
                }
            }
        });

        $("#catalogAct").click(function () {
            $("#catalogAct_progress").addClass("fa fa-spinner fa-pulse");
            ajaxCall('/api/layer7security/settings/catalog', {}, function (data, status) {
                $("#catalogAct_progress").removeClass("fa fa-spinner fa-pulse");
                stdDialogInform("{{ lang._('Application catalog') }}", (data && data.response) ? data.response : 'failed', "{{ lang._('Close') }}");
            });
        });
    });
</script>
