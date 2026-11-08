/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Lobby widget: the maker's logo and name, the plugin version, the license and the engine state.
 */

export default class Layer7Security extends BaseWidget {
    constructor(config) {
        super(config);
        this.tickTimeout = 30;
    }

    getGridOptions() {
        return {
            minH: 2
        };
    }

    getMarkup() {
        return $(`
            <div id="l7w-${this.id}" class="widget-content" style="padding: 8px 12px; text-align: center;">
                <a href="https://rootsecuritysolution.com" target="_blank" rel="noopener">
                    <img src="/ui/img/layer7security/logo.png" alt="Rootsecurity Solutions" style="max-width: 100%; height: 54px; width: auto; background: #fff; border-radius: 8px; padding: 2px 6px;">
                </a>
                <div style="font-size: 15px; font-weight: 600; margin-top: 6px;">${this.translations.product} <span id="l7w-version-${this.id}"></span></div>
                <div class="text-muted" style="font-size: 12px;">${this.translations.by}
                    <a href="https://rootsecuritysolution.com" target="_blank" rel="noopener">Rootsecurity Solutions Pvt. Ltd.</a></div>
                <table class="table table-condensed" style="margin: 8px 0 2px 0; text-align: left;">
                    <tbody>
                        <tr><td style="white-space: nowrap;">${this.translations.engine}</td><td id="l7w-engine-${this.id}">-</td></tr>
                        <tr><td style="white-space: nowrap;">${this.translations.license}</td><td id="l7w-license-${this.id}">-</td></tr>
                        <tr><td style="white-space: nowrap;">${this.translations.support}</td><td><a href="mailto:info@rootsecuritysolution.com">${this.translations.contact}</a></td></tr>
                    </tbody>
                </table>
            </div>
        `);
    }

    async onMarkupRendered() {
        await this.onWidgetTick();
    }

    async onWidgetTick() {
        const lic = await this.ajaxCall('/api/layer7security/license/status');
        const svc = await this.ajaxCall('/api/layer7security/service/status');
        const t = this.translations;
        const text = (value) => $('<span>').text(value).html();

        const version = (((lic || {}).updates || {}).plugin || {}).installed;
        $(`#l7w-version-${this.id}`).text(version || '');

        const status = (svc || {}).status;
        const engine = {
            running: ['text-success', 'fa-check-circle', t.running],
            stopped: ['text-danger', 'fa-times-circle', t.stopped],
            disabled: ['text-muted', 'fa-minus-circle', t.disabled]
        }[status] || ['text-muted', 'fa-question-circle', status || '-'];
        $(`#l7w-engine-${this.id}`).html(`<span class="${engine[0]}"><i class="fa fa-fw ${engine[1]}"></i> ${text(engine[2])}</span>`);

        const l = (lic || {}).license || {};
        let label = l.label || l.state || '-';
        if (l.days_left !== null && l.days_left !== undefined) {
            label += ` (${l.days_left} ${t.days})`;
        }
        $(`#l7w-license-${this.id}`).html(`<a href="/ui/layer7security/license"><span class="${l.valid ? 'text-success' : 'text-danger'}">` +
            `<i class="fa fa-fw ${l.valid ? 'fa-check-circle' : 'fa-exclamation-circle'}"></i> ${text(label)}</span></a>`);

        this.config.callbacks.updateGrid();
    }
}
