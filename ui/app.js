'use strict';
const $ = id => document.getElementById(id);
let runs = [], selected = null;
const make = (tag, text, cls) => { const el = document.createElement(tag); if (text !== undefined) el.textContent = text; if (cls) el.className = cls; return el; };
const date = value => value ? new Date(value).toLocaleString() : 'Timestamp unavailable';
function renderRuns() {
  const query = $('search').value.toLowerCase(); $('runs').replaceChildren();
  for (const run of runs.filter(r => `${r.id} ${r.assessment.domain}`.toLowerCase().includes(query))) {
    const button = make('button', undefined, selected?.id === run.id ? 'active' : '');
    button.append(make('strong', run.assessment.domain || run.id), make('small', `${run.id} · ${date(run.assessment.checked_at)}`));
    button.onclick = () => selectRun(run); $('runs').append(button);
  }
  if (!$('runs').children.length && runs.length) $('runs').append(make('p', 'No matching runs.'));
}
function selectRun(run) {
  selected = run; renderRuns(); $('empty').hidden = true; $('detail').hidden = false;
  const a = run.assessment;
  $('title').textContent = a.domain || run.id; $('subtitle').textContent = `Run ${run.id} · ${date(a.checked_at)}`;
  $('score').textContent = a.score ? `${a.score} / 100` : '—'; $('risk').textContent = a.risk_level || 'Unknown';
  $('finding-count').textContent = run.evidence.length;
  const uncertain = a.error || /verification|challenge|unknown/i.test(a.validation_notes || '') || a.reachable !== 'true';
  $('status').textContent = uncertain ? 'Needs review' : 'Recorded'; $('checked').textContent = uncertain ? 'Check errors and reachability fields' : 'Verify findings with your team';
  $('baseline').replaceChildren();
  for (const other of runs.filter(r => r.id !== run.id && r.assessment.domain === a.domain)) { const option = make('option', `${other.id} · ${date(other.assessment.checked_at)}`); option.value = other.id; $('baseline').append(option); }
  renderFindings(); renderFields(); renderComparison();
}
function renderFindings() {
  $('finding-list').replaceChildren();
  const priority = {critical:0,high:1,medium:2,low:3};
  const items = selected.evidence.filter(e => $('severity').value === 'all' || e.severity === $('severity').value).sort((a,b) => (priority[a.severity] ?? 4)-(priority[b.severity] ?? 4));
  for (const finding of items) {
    const card = make('details', undefined, 'finding'); const summary = make('summary');
    summary.append(make('span', finding.severity, `badge ${['critical','high','medium','low'].includes(finding.severity) ? finding.severity : ''}`), make('span', finding.finding));
    const evidence = make('dl', undefined, 'evidence');
    for (const key of ['confidence','evidence_url','detection_method','observed_at','http_status','response_sha256','manual_review_status']) {
      evidence.append(make('dt', key.replaceAll('_',' '))); const dd = make('dd', finding[key] || 'Not recorded');
      if (key === 'evidence_url' && finding[key]) { try { const url = new URL(finding[key]); if (['https:','http:'].includes(url.protocol)) { const a = make('a', finding[key]); a.href = url.href; a.target = '_blank'; a.rel = 'noopener noreferrer'; dd.replaceChildren(a); } } catch {} }
      evidence.append(dd);
    }
    card.append(summary,evidence); $('finding-list').append(card);
  }
  if (!items.length) $('finding-list').append(make('p', 'No findings match this view. Inspect all fields for incomplete checks.'));
}
function renderFields() {
  $('fields').replaceChildren(); if (!selected) return;
  const query = $('field-search').value.toLowerCase();
  for (const [key,value] of Object.entries(selected.assessment).sort()) { if (!`${key} ${value}`.toLowerCase().includes(query)) continue; const row = make('tr'); row.append(make('td',key),make('td',value || '—')); $('fields').append(row); }
}
function renderComparison() {
  $('comparison').replaceChildren(); const previous = runs.find(r => r.id === $('baseline').value);
  if (!previous) { $('comparison').append(make('p','Save another run for this domain to compare results.')); return; }
  const table = make('table'), head = make('tr'); for (const text of ['Field','Baseline','Selected run']) head.append(make('th',text)); const thead = make('thead'); thead.append(head); table.append(thead);
  const body = make('tbody'); const keys = [...new Set([...Object.keys(previous.assessment), ...Object.keys(selected.assessment)])].sort();
  for (const key of keys) { const before = previous.assessment[key] ?? '', after = selected.assessment[key] ?? ''; if (before === after) continue; const row = make('tr'); row.append(make('td',key),make('td',before || '—'),make('td',after || '—')); body.append(row); }
  if (!body.children.length) { $('comparison').append(make('p','No assessment fields changed.')); return; }
  table.append(body); const wrap = make('div',undefined,'table-wrap'); wrap.append(table); $('comparison').append(wrap);
}
async function refresh() {
  $('refresh').disabled = true;
  try { const response = await fetch('/api/runs'); if (!response.ok) throw new Error(`Could not load reports (${response.status})`); const data = await response.json(); runs = data.runs; $('count').textContent = runs.length;
    $('notice').textContent = data.errors.length ? data.errors.map(e => `Could not read ${e.id}: ${e.error}`).join('\n') : '';
    if (runs.length) selectRun(runs.find(r => r.id === selected?.id) || runs[0]); else { selected = null; $('detail').hidden = true; $('empty').hidden = false; $('title').textContent = 'Your review workspace'; $('subtitle').textContent = 'Understand what changed. Decide what to review next.'; renderRuns(); }
  } catch (error) { $('notice').textContent = `${error.message}. Check that the local server is running and try Refresh.`; } finally { $('refresh').disabled = false; }
}
$('search').oninput = renderRuns; $('refresh').onclick = refresh; $('severity').onchange = renderFindings; $('field-search').oninput = renderFields; $('baseline').onchange = renderComparison;
for (const button of document.querySelectorAll('[data-tab]')) button.onclick = () => { for (const tab of document.querySelectorAll('[data-tab]')) { const active = tab === button; tab.classList.toggle('active',active); $(tab.dataset.tab).hidden = !active; } };
$('download').onclick = () => { if (!selected) return; const url = URL.createObjectURL(new Blob([JSON.stringify(selected.assessment,null,2)],{type:'application/json'})); const a = make('a'); a.href = url; a.download = 'assessment.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url),1000); };
refresh();
