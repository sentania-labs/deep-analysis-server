/* Metagame page (metagame.html): time-window switcher, tier table and the
 * archetype trends chart. The initial payload is rendered by the server into
 * a <script type="application/json"> data block inside the component root;
 * JSON data blocks are never executed, so script-src 'self' does not apply.
 * Chart.js is the vendored copy in static/vendor. */
(function () {
    'use strict';

    var CHART_COLORS = [
        '#4e7cff', '#22c55e', '#ef4444', '#eab308', '#a855f7',
        '#ec4899', '#14b8a6', '#f97316', '#6366f1', '#64748b'
    ];

    document.addEventListener('alpine:init', function () {
        Alpine.data('metagame', function () {
            // Kept outside the reactive state on purpose: Alpine would
            // otherwise wrap the Chart instance in a deep proxy.
            var chart = null;

            return {
                currentWindow: '30d',
                windows: ['14d', '30d', '90d', 'all'],
                format: '',
                tierRows: [],
                totalResults: 0,
                tiersLoading: false,
                trendLabels: [],
                trendDatasets: [],
                trendsLoading: false,

                init: function () {
                    var node = this.$el.querySelector('script[type="application/json"][data-metagame]');
                    var data = JSON.parse(node.textContent);
                    this.currentWindow = data.window || '30d';
                    this.format = data.format || '';
                    this.tierRows = data.tiers || [];
                    this.totalResults = data.total_results || 0;
                    this.trendLabels = data.trend_labels || [];
                    this.trendDatasets = data.trend_datasets || [];
                    var self = this;
                    this.$nextTick(function () { self.renderChart(); });
                },

                // :style binding for the popularity bar. Object form only:
                // Alpine writes a string :style with setAttribute('style'),
                // which CSP treats as an inline style.
                popularityStyle: function (tier) {
                    return { width: Math.min(tier.popularity_pct, 100) + '%' };
                },

                switchWindow: async function (w) {
                    if (w === this.currentWindow) return;
                    this.currentWindow = w;
                    this.tiersLoading = true;
                    this.trendsLoading = true;
                    try {
                        var tiersResp = await fetch('/metagame/api/tiers/' + encodeURIComponent(this.format) + '?window=' + w);
                        if (tiersResp.ok) {
                            var tiersData = await tiersResp.json();
                            this.tierRows = tiersData.tiers || [];
                            this.totalResults = tiersData.total_results || 0;
                        }
                    } catch (e) { console.error('Failed to fetch tiers', e); }
                    this.tiersLoading = false;

                    try {
                        var trendsResp = await fetch('/metagame/api/trends/' + encodeURIComponent(this.format) + '?window=' + w);
                        if (trendsResp.ok) {
                            var trendsData = await trendsResp.json();
                            this.trendLabels = trendsData.labels || [];
                            this.trendDatasets = trendsData.datasets || [];
                        }
                    } catch (e) { console.error('Failed to fetch trends', e); }
                    this.trendsLoading = false;
                    var self = this;
                    this.$nextTick(function () { self.renderChart(); });
                },

                renderChart: function () {
                    var canvas = document.getElementById('trendsChart');
                    if (!canvas) return;
                    if (chart) { chart.destroy(); chart = null; }
                    if (!this.trendLabels.length) return;
                    var isDark = document.documentElement.classList.contains('dark');
                    var gridColor = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)';
                    var textColor = isDark ? '#8b8b9e' : '#6b6b7e';
                    chart = new Chart(canvas, {
                        type: 'line',
                        data: {
                            labels: this.trendLabels.slice(),
                            datasets: this.trendDatasets.map(function (ds, i) {
                                return {
                                    label: ds.label,
                                    data: ds.data.slice(),
                                    borderColor: CHART_COLORS[i % CHART_COLORS.length],
                                    backgroundColor: CHART_COLORS[i % CHART_COLORS.length] + '20',
                                    borderWidth: 2,
                                    tension: 0.3,
                                    pointRadius: 2,
                                    fill: false
                                };
                            })
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: {
                                    position: 'bottom',
                                    labels: { color: textColor, boxWidth: 12, padding: 16, font: { size: 11 } }
                                }
                            },
                            scales: {
                                x: { grid: { color: gridColor }, ticks: { color: textColor, font: { size: 10 } } },
                                y: { grid: { color: gridColor }, ticks: { color: textColor, font: { size: 10 } }, beginAtZero: true }
                            }
                        }
                    });
                }
            };
        });
    });
})();
