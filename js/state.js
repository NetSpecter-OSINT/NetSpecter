// state.js - shared mutable application state

export const state = {
  currentTab:    'dns',
  currentTarget: '',
  scanning:      false,
  queryCount:    0,
  hitCount:      0,
};

export function bumpQuery() {
  state.queryCount++;
  const el = document.getElementById('query-count');
  if (el) el.textContent = state.queryCount;
}

export function bumpHit(n = 1) {
  state.hitCount += n;
  const el = document.getElementById('hit-count');
  if (el) el.textContent = state.hitCount;
}

export function resetCounters() {
  state.queryCount = 0;
  state.hitCount   = 0;
  const qEl = document.getElementById('query-count');
  const hEl = document.getElementById('hit-count');
  if (qEl) qEl.textContent = '0';
  if (hEl) hEl.textContent = '0';
}
