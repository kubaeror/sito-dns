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

// ---------------------------------------------------------------------------
// Query-log history mode
//
// "Load older" appends an older page and pauses the 3 s live poll so a poll
// response cannot replace the rows the operator is reading. "Back to live" and
// filter/refresh requests clear the mode. The pause lives here (rather than in
// an inline handler) because the CSP forbids inline scripts.
// ---------------------------------------------------------------------------

let queryLogFocusAfterSwap = false;
let queryLogFocusedControl = null;

function queryLogHistoryControls() {
  return document.getElementById('query-history-controls');
}

function setQueryLogHistoryMode(enabled) {
  const controls = queryLogHistoryControls();
  if (controls) controls.dataset.historyMode = enabled ? 'true' : 'false';
}

function queryLogHistoryModeActive() {
  const controls = queryLogHistoryControls();
  return !!controls && controls.dataset.historyMode === 'true';
}

function dedupeQueryLogRows() {
  const tbody = document.getElementById('query-table-body');
  if (!tbody) return;
  const seen = new Set();
  tbody.querySelectorAll('tr[data-querylog-row-key]').forEach((row) => {
    const key = row.dataset.querylogRowKey;
    if (!key) return;
    if (seen.has(key)) {
      row.remove();
    } else {
      seen.add(key);
    }
  });
}

document.addEventListener('htmx:beforeRequest', (event) => {
  const elt = event.detail && event.detail.elt;
  if (!elt) return;

  if (elt.hasAttribute('data-querylog-load-older')) {
    // Enter history mode before the request starts so a poll scheduled during
    // the round trip is cancelled.
    queryLogFocusAfterSwap = true;
    setQueryLogHistoryMode(true);
    return;
  }

  if (elt.hasAttribute('data-querylog-back-live')) {
    setQueryLogHistoryMode(false);
    queryLogFocusAfterSwap = true;
    return;
  }

  // The rows container only issues the 3 s poll; filters and refresh start on
  // their own controls, so those still reset history mode via the OOB response.
  if (elt.id === 'query-table-body' && queryLogHistoryModeActive()) {
    event.preventDefault();
  }
});

document.addEventListener('htmx:beforeSwap', (event) => {
  const elt = event.detail && event.detail.elt;
  // A live poll may already be in flight when history mode begins. Drop its
  // response instead of letting it replace the rows just appended below.
  if (elt && elt.id === 'query-table-body' && queryLogHistoryModeActive()) {
    event.detail.shouldSwap = false;
  }
});

document.addEventListener('htmx:afterSwap', (event) => {
  const target = event.detail && event.detail.target;
  if (target && target.id === 'query-table-body') {
    dedupeQueryLogRows();
  }
});

// The controls area is replaced out of band on every live poll as well as on
// history loads. Remember which control had focus and restore it to the
// replacement so a poll cannot silently drop keyboard focus.
document.addEventListener('htmx:oobBeforeSwap', (event) => {
  const target = event.detail && event.detail.target;
  if (!target || target.id !== 'query-history-controls') return;
  const active = document.activeElement;
  if (!active || !target.contains(active)) return;
  if (active.hasAttribute('data-querylog-load-older')) {
    queryLogFocusedControl = 'data-querylog-load-older';
  } else if (active.hasAttribute('data-querylog-back-live')) {
    queryLogFocusedControl = 'data-querylog-back-live';
  }
});

document.addEventListener('htmx:oobAfterSwap', (event) => {
  const target = event.detail && event.detail.target;
  if (!target || target.id !== 'query-history-controls' || !queryLogFocusedControl) {
    return;
  }
  const selector = `[${queryLogFocusedControl}]`;
  queryLogFocusedControl = null;
  const replacement = document.querySelector(selector);
  if (replacement && !replacement.disabled) replacement.focus();
});

document.addEventListener('htmx:afterSettle', (event) => {
  const target = event.detail && event.detail.target;
  if (!target || target.id !== 'query-table-body' || !queryLogFocusAfterSwap) {
    return;
  }
  queryLogFocusAfterSwap = false;

  const controls = queryLogHistoryControls();
  if (!controls) return;
  const loadOlder = controls.querySelector('[data-querylog-load-older]');
  if (loadOlder && !loadOlder.disabled) {
    // Keep keyboard focus on the control the operator just used.
    loadOlder.focus();
    return;
  }
  const back = controls.querySelector('[data-querylog-back-live]');
  if (back) back.focus();
});
