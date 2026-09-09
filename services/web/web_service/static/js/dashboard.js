/* Dashboard date-range filter (dashboard.html). Registered as an Alpine
 * component because the CSP build cannot evaluate function bodies inside an
 * x-data attribute. Initial state comes from data-* attributes on the root
 * element, which Jinja autoescapes; the B&R dates are a JSON array. */
(function () {
    'use strict';

    document.addEventListener('alpine:init', function () {
        Alpine.data('dateRangeFilter', function () {
            return {
                preset: 'all',
                dateFrom: '',
                dateTo: '',
                bnrDates: [],

                init: function () {
                    var ds = this.$el.dataset;
                    this.preset = ds.preset || 'all';
                    this.dateFrom = ds.dateFrom || '';
                    this.dateTo = ds.dateTo || '';
                    try {
                        this.bnrDates = JSON.parse(ds.bnrDates || '[]');
                    } catch (e) {
                        this.bnrDates = [];
                    }
                },

                localDate: function (d) {
                    var y = d.getFullYear();
                    var m = String(d.getMonth() + 1).padStart(2, '0');
                    var day = String(d.getDate()).padStart(2, '0');
                    return y + '-' + m + '-' + day;
                },

                // <select x-model="preset" @change="onPresetChange">
                onPresetChange: function () {
                    if (this.preset !== 'custom') this.selectPreset(this.preset);
                },

                // Editing either date input turns the preset into "custom".
                markCustom: function () {
                    this.preset = 'custom';
                },

                selectPreset: function (value) {
                    if (value === 'all' || value === '0') {
                        this.dateFrom = '';
                        this.dateTo = '';
                    } else if (value.indexOf('bnr_') === 0) {
                        var idx = parseInt(value.split('_')[1], 10) - 1;
                        if (idx >= 0 && idx < this.bnrDates.length) {
                            this.dateFrom = this.bnrDates[idx];
                            this.dateTo = this.localDate(new Date());
                        }
                    } else {
                        var days = parseInt(value, 10);
                        var to = new Date();
                        var from = new Date();
                        from.setDate(from.getDate() - days + 1);
                        this.dateFrom = this.localDate(from);
                        this.dateTo = this.localDate(to);
                    }
                    this.navigate();
                },

                navigate: function () {
                    var params = new URLSearchParams(window.location.search);
                    if (this.dateFrom) params.set('date_from', this.dateFrom);
                    else params.delete('date_from');
                    if (this.dateTo) params.set('date_to', this.dateTo);
                    else params.delete('date_to');
                    window.location.href = '/dashboard' + (params.toString() ? '?' + params.toString() : '');
                }
            };
        });
    });
})();
