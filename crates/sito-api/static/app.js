// Static application helpers (served from /static/app.js).
// Kept as an external file so the CSP can avoid 'unsafe-inline' for scripts.

function toggleTheme() {
  const current = localStorage.getItem('sito_theme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  localStorage.setItem('sito_theme', next);
}

function initQueryChart() {
  const el = document.getElementById('chart-container');
  if (!el || typeof uPlot === 'undefined') return;

  let times = [];
  let totals = [];
  let blocked = [];
  try {
    times = JSON.parse(el.dataset.times || '[]');
    totals = JSON.parse(el.dataset.totals || '[]');
    blocked = JSON.parse(el.dataset.blocked || '[]');
  } catch (err) {
    return;
  }

  const width = el.clientWidth || 800;
  const data = [times, totals, blocked];

  const opts = {
    width: width,
    height: 260,
    cursor: { sync: { key: 'querychart' } },
    scales: { x: { time: true } },
    axes: [
      {
        stroke: '#94a3b8',
        grid: { stroke: 'rgba(148, 163, 184, 0.1)' },
        ticks: { stroke: '#94a3b8' },
      },
      {
        stroke: '#94a3b8',
        grid: { stroke: 'rgba(148, 163, 184, 0.1)' },
        ticks: { stroke: '#94a3b8' },
      },
    ],
    series: [
      {},
      {
        label: 'Total Queries',
        stroke: '#10b981',
        fill: 'rgba(16, 185, 129, 0.15)',
        width: 2,
      },
      {
        label: 'Blocked',
        stroke: '#ef4444',
        fill: 'rgba(239, 68, 68, 0.2)',
        width: 2,
      },
    ],
  };

  const chart = new uPlot(opts, data, el);
  window.addEventListener('resize', () => {
    chart.setSize({ width: el.clientWidth, height: 260 });
  });
}

document.addEventListener('DOMContentLoaded', initQueryChart);
