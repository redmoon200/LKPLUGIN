{# Shared page header of the Layer 7 Security console.
   Parameters: title, subtitle, icon (font-awesome name), accent (prot | ai | con), apply (true shows the Apply button) #}
<link rel="stylesheet" type="text/css" href="{{ cache_safe('/ui/css/layer7security/console.css') }}"/>
<script src="{{ cache_safe('/ui/js/layer7security/console.js') }}"></script>
<div class="l7-head">
    <div class="l7-head-icon {{ accent|default('con') }}"><i class="fa fa-{{ icon|default('shield') }}"></i></div>
    <div class="l7-head-text">
        <h1>{{ title }}</h1>
        <p>{{ subtitle }}</p>
    </div>
    <div class="l7-head-side">
        <span id="l7-module-pill" class="l7-pill">{{ lang._('Checking...') }}</span>
        <span id="l7-engine-pill" class="l7-pill">{{ lang._('Engine') }}</span>
        {% if apply|default(false) %}
        <button class="btn btn-primary" id="reconfigureAct"
                data-endpoint="/api/layer7security/service/reconfigure"
                data-label="{{ lang._('Apply changes') }}"
                data-error-title="{{ lang._('Error applying Layer 7 settings') }}"
                type="button"></button>
        {% endif %}
    </div>
</div>
<div id="l7-pending" class="l7-pending">
    <i class="fa fa-exclamation-triangle"></i>
    {{ lang._('You have changes that are not active yet. Click "Apply changes" to put them to work.') }}
</div>
