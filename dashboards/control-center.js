const S = {
  key: localStorage.getItem('aiops_api_key') || '',
  summary: null,
  incidents: [],
  services: [],
  health: null,
  agents: [],
  agentMetrics: [],
  selected: null,
  detail: null,
  memoryLoadingFor: null,
  view: 'overview'
};

const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const lower = v => String(v ?? '').toLowerCase();
const fmtDate = v => v ? new Date(v).toLocaleString() : '—';
const fmtShortDate = v => v ? new Date(v).toLocaleString([], {month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit'}) : '—';
const pct = v => `${Math.round((Number(v) || 0) * 100)}%`;
const isOpen = i => !['closed', 'resolved'].includes(lower(i.status));
const THEME_STORAGE = 'aiops.chatbot.theme';

function initialTheme() {
  const saved = localStorage.getItem(THEME_STORAGE);
  if (saved === 'light' || saved === 'dark') return saved;
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

function applyTheme(value, {persist = true} = {}) {
  const theme = value === 'light' ? 'light' : 'dark';
  document.documentElement.dataset.theme = theme;
  if (persist) localStorage.setItem(THEME_STORAGE, theme);

  const toggle = $('#themeToggle');
  const moon = $('#themeMoon');
  const sun = $('#themeSun');
  const label = $('#themeLabel');
  const switchTo = theme === 'dark' ? 'روشن' : 'تیره';
  if (toggle) {
    toggle.dataset.theme = theme;
    toggle.setAttribute('aria-label', 'تغییر به پوسته ' + switchTo);
    toggle.title = 'تغییر به پوسته ' + switchTo;
  }
  if (moon) moon.classList.toggle('hidden', theme !== 'dark');
  if (sun) sun.classList.toggle('hidden', theme !== 'light');
  if (label) label.textContent = theme === 'dark' ? 'تیره' : 'روشن';

  const themeColor = document.querySelector('meta[name="theme-color"]');
  if (themeColor) themeColor.setAttribute('content', theme === 'light' ? '#F6F8FA' : '#0B0F14');
  return theme;
}

function toggleTheme() {
  applyTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light');
}

function pill(v = '') {
  const s = lower(v);
  let c = '';
  if (/critical|failed|failure|rejected|unhealthy|error|blocked/.test(s)) c = 'red';
  else if (/success|approved|resolved|healthy|ready|verified|completed|persisted|consumed/.test(s)) c = 'green';
  else if (/pending|high|warning|degraded|partial|inconclusive|not_persisted/.test(s)) c = 'amber';
  else if (/analyz|running|medium|current/.test(s)) c = 'violet';
  return `<span class="pill ${c}">${esc(v || '—')}</span>`;
}

function headers() {
  const h = {'Accept': 'application/json'};
  if (S.key) h['X-API-Key'] = S.key;
  return h;
}

async function api(path, opts = {}) {
  const r = await fetch(path, {...opts, headers: {...headers(), ...(opts.headers || {})}});
  if (!r.ok) {
    let d;
    try { d = await r.json(); } catch {}
    throw new Error(`${r.status} ${d?.detail || r.statusText}`);
  }
  return r.json();
}

function showError(msg = '') {
  const el = $('#error');
  el.textContent = msg;
  el.classList.toggle('hidden', !msg);
}

function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2600);
}

function saveKey() {
  S.key = $('#apiKey').value.trim();
  localStorage.setItem('aiops_api_key', S.key);
  toast('API identity updated');
  loadAll();
}

function syncGlobalSearch(v) {
  if ($('#incidentSearch')) $('#incidentSearch').value = v;
  if ($('#serviceSearch')) $('#serviceSearch').value = v;
  renderIncidents();
  renderServices();
}

function setView(v) {
  S.view = v;
  $$('.view').forEach(x => x.classList.toggle('active', x.dataset.view === v));
  $$('.nav button').forEach(x => x.classList.toggle('active', x.dataset.view === v));
  const titles = {
    overview: ['Command Center', 'Prioritized live operational state across incidents, governed remediation and external dependencies.'],
    incidents: ['Incident Workbench', 'Evidence, agent coordination, evaluator gate, approval binding, execution, verification and memory in one durable view.'],
    services: ['Service Health', 'Service-centric impact derived only from durable incident and governance state.'],
    agents: ['Agents & RCA', 'Analysis-only specialist agents, routing, collaboration and runtime quality signals.'],
    mcp: ['MCP Fabric', 'Operational MCP connectivity plus the separate governed Cognia Knowledge boundary.'],
    audit: ['Audit & Governance', 'Durable decision, approval, capability, execution, verification and learning history.']
  };
  $('#pageTitle').textContent = titles[v][0];
  $('#pageSub').textContent = titles[v][1];
  if (v === 'agents') loadAgents();
  if (v === 'services') renderServices();
  if (v === 'mcp') renderMcp();
  if (v === 'audit') renderAudit();
}

function serviceState(s) {
  if (Number(s.critical_active) > 0 || Number(s.failed_executions) > 0 || Number(s.failed_verifications) > 0) return 'critical';
  if (
    Number(s.high_active) > 0 ||
    Number(s.incidents_active) > 0 ||
    Number(s.approvals_pending) > 0 ||
    Number(s.approvals_approved) > 0 ||
    Number(s.partial_verifications) > 0 ||
    Number(s.inconclusive_verifications) > 0
  ) return 'degraded';
  return 'healthy';
}

function attentionReason(i) {
  const reasons = [];
  if (lower(i.severity) === 'critical') reasons.push('critical severity');
  else if (lower(i.severity) === 'high') reasons.push('high severity');
  if (lower(i.approval_status) === 'pending') reasons.push('approval pending');
  if (lower(i.approval_status) === 'approved') reasons.push('approved, awaiting execution');
  if (/failed|failure|blocked/.test(lower(i.execution_status))) reasons.push(`execution ${lower(i.execution_status)}`);
  if (/failed|failure/.test(lower(i.verification_status))) reasons.push('verification failed');
  if (/partial|inconclusive/.test(lower(i.verification_status))) reasons.push(`verification ${lower(i.verification_status)}`);
  if (lower(i.memory_status) === 'not_persisted' && /success|verified/.test(lower(i.verification_status))) reasons.push('memory not persisted');
  if (Number(i.confidence || 0) > 0 && Number(i.confidence) < .5) reasons.push('low confidence');
  return reasons;
}

function attentionRank(i) {
  let n = 0;
  if (lower(i.severity) === 'critical') n += 100;
  else if (lower(i.severity) === 'high') n += 60;
  else if (lower(i.severity) === 'medium') n += 20;
  if (lower(i.approval_status) === 'pending') n += 30;
  if (lower(i.approval_status) === 'approved') n += 35;
  if (/failed|failure|blocked/.test(lower(i.execution_status))) n += 70;
  if (/failed|failure/.test(lower(i.verification_status))) n += 65;
  if (/partial|inconclusive/.test(lower(i.verification_status))) n += 25;
  if (lower(i.memory_status) === 'not_persisted' && /success|verified/.test(lower(i.verification_status))) n += 15;
  if (Number(i.confidence || 0) > 0 && Number(i.confidence) < .5) n += 15;
  return n;
}

function attentionLevel(score) {
  return score >= 100 ? 'P0' : score >= 60 ? 'P1' : 'P2';
}

function dependencyEntries() {
  const h = S.health?.components || {};
  const ext = h.external || {};
  const rows = [
    {name: 'PostgreSQL + pgvector', healthy: h.database?.status === 'healthy', kind: 'state', meta: h.database?.migration?.valid === false ? 'migration drift' : 'durable state + operational memory'},
    {name: 'Zabbix MCP', healthy: ext.zabbix_mcp?.healthy, kind: 'mcp', meta: 'monitoring evidence'},
    {name: 'Elastic Agent Builder MCP', healthy: ext.elasticsearch_mcp?.healthy, kind: 'mcp', meta: 'governed ES|QL evidence'},
    {name: 'Prometheus MCP', healthy: ext.prometheus_mcp?.healthy, kind: 'mcp', meta: 'metrics evidence'}
  ];
  if (Object.prototype.hasOwnProperty.call(ext, 'vm_mcp')) rows.push({name: 'VM Edge MCP', healthy: ext.vm_mcp?.healthy, kind: 'mcp-write', meta: 'VM telemetry + governed remediation'});
  if (Object.prototype.hasOwnProperty.call(ext, 'kubernetes_mcp')) rows.push({name: 'Kubernetes MCP', healthy: ext.kubernetes_mcp?.healthy, kind: 'mcp-write', meta: 'optional Kubernetes boundary'});
  if (Object.prototype.hasOwnProperty.call(ext, 'jenkins_mcp')) rows.push({name: 'Jenkins MCP', healthy: ext.jenkins_mcp?.healthy, kind: 'mcp-write', meta: 'optional delivery boundary'});
  if (Object.prototype.hasOwnProperty.call(ext, 'cognia')) rows.push({name: 'Cognia Knowledge', healthy: ext.cognia?.healthy, kind: 'knowledge', meta: ext.cognia?.configured === false ? 'not configured' : 'governed Knowledge API'});
  return rows;
}

function renderOverview() {
  const x = S.summary || {};
  $('#kActive').textContent = x.incidents_active ?? '—';
  $('#kCritical').textContent = x.incidents_critical ?? '—';
  $('#kPending').textContent = x.approvals_pending ?? '—';
  $('#kApproved').textContent = x.approvals_approved ?? '—';
  $('#kExec').textContent = x.execution_success ?? '—';
  $('#kSuccess').textContent = x.successful_remediations ?? '—';
  $('#kPartial').textContent = Number(x.verification_partial || 0) + Number(x.verification_inconclusive || 0);
  $('#kMemory').textContent = x.memory_entries_total ?? x.memory_persisted ?? '—';
  $('#kRate').textContent = pct(x.automation_success_rate);
  $('#kConfidence').textContent = pct(x.mean_confidence);

  const live = x.data_status === 'live';
  const platformHealthy = live && lower(S.health?.status) === 'ok';
  $('#liveDot').classList.toggle('ok', platformHealthy);
  $('#platformState').textContent = !live ? 'Unavailable' : platformHealthy ? 'Live' : 'Degraded';
  $('#platformState').classList.toggle('live', platformHealthy);
  $('#platformVersion').textContent = S.health?.version || '—';
  $('#lastUpdated').textContent = live ? new Date().toLocaleTimeString() : '—';

  const attention = S.incidents.filter(i => isOpen(i) && attentionReason(i).length).sort((a, b) => attentionRank(b) - attentionRank(a));
  const atRisk = S.services.filter(s => serviceState(s) !== 'healthy');
  const degradedDeps = dependencyEntries().filter(d => !d.healthy);
  $('#attentionCount').textContent = attention.length;
  $('#serviceRiskCount').textContent = atRisk.length;
  $('#dependencyRiskCount').textContent = degradedDeps.length;
  $('#attentionBadge').textContent = `${attention.length} live`;

  $('#attentionQueue').innerHTML = attention.slice(0, 7).map(i => {
    const score = attentionRank(i);
    const level = attentionLevel(score);
    const critical = level === 'P0' ? 'critical' : '';
    return `<div class="attention-item" onclick="openIncident('${esc(i.id)}')"><i class="attention-marker ${critical}"></i><div><div class="attention-title">${esc(i.service || 'Unknown service')} · ${esc(i.summary || 'Incident')}</div><div class="attention-meta">${esc(attentionReason(i).join(' · '))} · ${fmtShortDate(i.created_at)}</div></div><div class="attention-score"><strong>${level}</strong><small>${esc(i.severity || '')}</small></div></div>`;
  }).join('') || '<div class="empty-state">No active incident currently requires elevated operator attention.</div>';

  $('#servicePreview').innerHTML = S.services.slice(0, 6).map(s => {
    const state = serviceState(s);
    return `<div class="service-row"><div><div class="service-name">${esc(s.service)}</div><div class="service-summary">${esc(s.latest_summary || 'No recent incident summary')}</div></div><div><div class="health-bar"><i class="${state}" style="width:${state === 'healthy' ? 100 : state === 'degraded' ? 58 : 28}%"></i></div></div><div class="service-counts"><b>${s.incidents_active}</b>active · ${esc(state)}</div></div>`;
  }).join('') || '<div class="empty-state">No durable service incident history is available.</div>';

  renderLifecycleSummary();
  renderSeverity();
  renderAuditPreview();
}

function renderLifecycleSummary() {
  const x = S.summary || {};
  const items = [
    ['Pending approval', x.approvals_pending || 0, 'human gate'],
    ['Approved', x.approvals_approved || 0, 'awaiting resume'],
    ['Consumed', x.approvals_consumed || 0, 'one-time authorization used'],
    ['Execution success', x.execution_success || 0, `${x.execution_failed || 0} failed · ${x.execution_blocked || 0} blocked`],
    ['Verification success', x.verification_success || 0, `${x.verification_partial || 0} partial · ${x.verification_inconclusive || 0} inconclusive`],
    ['Memory episodes', x.memory_entries_total || 0, `${x.memory_entries_active || 0} active`],
    ['Embedding ready', x.memory_embedding_ready || 0, `${x.memory_embedding_backlog || 0} backlog · ${x.memory_embedding_contract_mismatch || 0} contract mismatch · ${x.memory_embedding_failed || 0} failed · ${x.memory_embedding_pending || 0} pending`],
    ['Memory write-back audit', x.memory_persisted || 0, `${x.memory_not_persisted || 0} not persisted`]
  ];
  $('#automationLifecycle').innerHTML = items.map(([label, value, meta]) => `<div class="lifecycle-node"><span>${esc(label)}</span><strong>${esc(value)}</strong><small>${esc(meta)}</small></div>`).join('');
}

function renderSeverity() {
  const sev = {critical: 0, high: 0, medium: 0, low: 0};
  S.incidents.filter(isOpen).forEach(i => { const s = lower(i.severity); if (sev[s] != null) sev[s]++; });
  const total = Object.values(sev).reduce((a, b) => a + b, 0);
  const colors = {critical:'var(--red)', high:'var(--amber)', medium:'var(--blue)', low:'var(--green)'};
  $('#severityBreakdown').innerHTML = total ? Object.entries(sev).map(([k, n]) => `<div class="severity-row"><span>${k}</span><div class="severity-bar"><i style="width:${n / total * 100}%;background:${colors[k]}"></i></div><b>${n}</b></div>`).join('') : '<div class="empty-state">No active incidents.</div>';
}

function auditSummary(a) {
  const m = a.metadata || {};
  const parts = [];
  if (a.action) parts.push(a.action);
  if (a.status) parts.push(a.status);
  if (m.requested_action) parts.push(m.requested_action);
  if (m.tool_name || m.tool) parts.push(m.tool_name || m.tool);
  if (m.target) parts.push(m.target);
  if (m.verification_status) parts.push(`verify:${m.verification_status}`);
  if (m.status && !parts.includes(m.status)) parts.push(m.status);
  if (typeof m.persisted === 'boolean') parts.push(`memory:${m.persisted ? 'persisted' : 'not persisted'}`);
  return parts.join(' · ') || 'Governance event recorded';
}

function timelineItem(a) {
  return `<div class="timeline-item"><div class="timeline-title">${esc(a.event_type || 'event')}</div><div class="timeline-meta">${fmtShortDate(a.created_at)} · ${esc(String(a.incident_id || 'no incident').slice(0, 8))}${a.actor ? ` · ${esc(a.actor)}` : ''}</div><div class="timeline-body">${esc(auditSummary(a))}</div></div>`;
}

function renderAuditPreview() {
  const audit = S.summary?.recent_audit || [];
  $('#auditPreview').innerHTML = audit.slice(0, 3).map(timelineItem).join('') || '<div class="empty-state">No audit events recorded.</div>';
}

function renderHealth() {
  const defs = dependencyEntries();
  $('#components').innerHTML = defs.map(x => `<div class="component"><div class="component-top"><span class="component-name">${esc(x.name)}</span><span class="dot ${x.healthy ? 'green' : ''}" style="${x.healthy ? '' : 'background:var(--red)'}"></span></div><div class="component-state ${x.healthy ? 'ok' : 'bad'}">${x.healthy ? 'Healthy' : 'Unavailable'}</div><small>${esc(x.meta)}</small></div>`).join('');
}

function renderIncidents() {
  const q = lower($('#incidentSearch')?.value);
  const sev = $('#severityFilter')?.value || '';
  const status = $('#statusFilter')?.value || '';
  const rows = S.incidents.filter(i => (!q || lower([i.id, i.service, i.summary, i.execution_target, i.execution_tool, i.runbook_id].join(' ')).includes(q)) && (!sev || lower(i.severity) === sev) && (!status || lower(i.status) === status));
  if ($('#incidentCount')) $('#incidentCount').textContent = `${rows.length} incidents`;
  if (!$('#incidentRows')) return;
  $('#incidentRows').innerHTML = rows.map(i => `<tr class="${S.selected === i.id ? 'selected' : ''}" onclick="selectIncident('${esc(i.id)}')"><td><div class="incident-main">${esc(String(i.id).slice(0, 8))}</div><div class="incident-sub">${esc(i.summary || '')}</div></td><td>${esc(i.service || '—')}</td><td>${pill(i.severity)}</td><td>${pill(i.status)}</td><td>${pct(i.confidence)}</td><td>${pill(i.risk_level || '—')}</td><td>${pill(i.approval_status || '—')}</td><td>${pill(i.execution_status || '—')}</td><td>${pill(i.verification_status || '—')}</td><td>${pill(i.memory_status || '—')}</td><td>${fmtShortDate(i.created_at)}</td></tr>`).join('') || '<tr><td colspan="11"><div class="empty-state">No incidents match the current filters.</div></td></tr>';
}

function renderServices() {
  if (!$('#serviceGrid')) return;
  const q = lower($('#serviceSearch')?.value);
  const risk = $('#serviceRiskFilter')?.value || '';
  const rows = S.services.filter(s => (!q || lower([s.service, s.latest_summary].join(' ')).includes(q)) && (!risk || serviceState(s) === risk));
  $('#serviceCount').textContent = `${rows.length} services`;
  $('#serviceGrid').innerHTML = rows.map(s => {
    const state = serviceState(s);
    return `<article class="panel service-card"><div class="service-card-top"><div><span class="section-kicker">Service</span><h3>${esc(s.service)}</h3></div>${pill(state)}</div><p>${esc(s.latest_summary || 'No incident summary available.')}</p><div class="service-metrics"><div class="service-metric"><label>Active</label><strong>${s.incidents_active}</strong></div><div class="service-metric"><label>Critical / High</label><strong>${s.critical_active} / ${s.high_active}</strong></div><div class="service-metric"><label>Confidence</label><strong>${pct(s.mean_active_confidence)}</strong></div><div class="service-metric"><label>Awaiting approval/exec</label><strong>${Number(s.approvals_pending || 0) + Number(s.approvals_approved || 0)}</strong></div><div class="service-metric"><label>Verified</label><strong>${s.successful_verifications || 0}</strong></div><div class="service-metric"><label>Learned</label><strong>${s.memory_persisted || 0}</strong></div></div><div class="service-footer"><span>${s.failed_executions || 0} execution failures · ${s.failed_verifications || 0} verification failures · ${Number(s.partial_verifications || 0) + Number(s.inconclusive_verifications || 0)} uncertain</span><span>${fmtShortDate(s.last_incident_at)}</span></div></article>`;
  }).join('') || '<div class="panel empty-state">No services match the current filter.</div>';
}

function openIncident(id) {
  setView('incidents');
  selectIncident(id);
}

async function selectIncident(id) {
  S.selected = id;
  S.memoryLoadingFor = null;
  renderIncidents();
  $('#detail').innerHTML = '<div class="empty-state tall">Loading durable incident state…</div>';
  try {
    const [context, evidence, lifecycle, verification] = await Promise.all([
      api(`/api/v1/incidents/${id}/context`),
      api(`/api/v1/incidents/${id}/evidence?limit=100`),
      api(`/api/v1/incidents/${id}/lifecycle`),
      api(`/api/v1/incidents/${id}/verification`)
    ]);
    S.detail = {context, evidence, lifecycle, verification, memory: null};
    renderDetail('overview');
  } catch (e) {
    $('#detail').innerHTML = `<div class="empty-state tall">${esc(e.message)}</div>`;
  }
}

async function loadIncidentMemory(id) {
  if (!id || S.memoryLoadingFor === id) return;
  S.memoryLoadingFor = id;
  try {
    const memory = await api(`/api/v1/incidents/${id}/memory?limit=5`)
      .catch(error => ({items: [], error: error.message}));
    if (S.selected !== id || !S.detail) return;
    S.detail.memory = memory;
    renderDetail('memory');
  } finally {
    if (S.memoryLoadingFor === id) S.memoryLoadingFor = null;
  }
}

function memoryState(l) {
  const event = (l.audit || []).find(a => lower(a.event_type) === 'memory_writeback');
  if (!event) return 'not_recorded';
  const persisted = event.metadata?.persisted;
  return persisted === true || lower(persisted) === 'true' ? 'persisted' : 'not_persisted';
}

function workflowStages(l) {
  const evidenceCount = S.detail?.evidence?.items?.length || 0;
  const approvalStatus = lower(l.approval?.status);
  const verificationStatus = lower(l.verification?.status || S.incidents.find(x => x.id === S.selected)?.verification_status);
  const mem = memoryState(l);
  const stages = [
    ['signal', true, false],
    ['evidence', evidenceCount > 0, false],
    ['triage', Object.keys(l.triage || {}).length > 0, false],
    ['agents', (l.agents || []).length > 0, false],
    ['evaluator', Object.keys(l.evaluation || {}).length > 0, false],
    ['decision', !!l.decision, false],
    ['approval', ['approved','consumed','rejected'].includes(approvalStatus), approvalStatus === 'pending'],
    ['execution', !!l.execution, approvalStatus === 'approved' && !l.execution],
    ['verification', !!l.verification, !!l.execution && !l.verification],
    ['memory', mem === 'persisted', !!l.verification && mem === 'not_recorded']
  ];
  return stages.map(([name, done, current]) => {
    let cls = done ? 'done' : current ? 'current' : '';
    if (name === 'approval' && approvalStatus === 'rejected') cls = 'failed';
    if (name === 'verification' && /failed|failure/.test(verificationStatus)) cls = 'failed';
    if (name === 'memory' && mem === 'not_persisted') cls = 'warning';
    return `<div class="stage ${cls}">${name}</div>`;
  }).join('');
}

function confidenceBlock(label, value) {
  const n = Math.max(0, Math.min(1, Number(value) || 0));
  return `<div class="insight-card"><h4>${esc(label)}</h4><div class="confidence-line"><div class="confidence-meter"><i style="width:${n * 100}%"></i></div><b>${pct(n)}</b></div></div>`;
}

function renderBinding(approval = {}) {
  const m = approval.metadata || {};
  const binding = {
    binding_complete: m.binding_complete,
    binding_version: m.binding_version,
    binding_digest: m.binding_digest,
    environment: m.environment,
    tool_name: m.tool_name,
    target: m.target,
    timeout: m.timeout,
    runbook_id: m.runbook_id,
    runbook_version: m.runbook_version,
    rollback: m.rollback
  };
  return `<div class="insight-card"><h4>Execution binding</h4><p>Approval is scoped to this immutable execution intent. The signed execution capability itself is intentionally not exposed in the dashboard.</p><div class="json">${esc(JSON.stringify(binding, null, 2))}</div></div>`;
}

function renderVerification(l, v, incident) {
  const result = l.verification || {};
  const status = result.status || incident.verification_status || v.items?.[0]?.metadata?.status || 'not_recorded';
  const changes = result.changes || [];
  return `<div class="verification-hero"><div><span class="section-kicker">Independent verification</span><h3>${esc(status)}</h3><p>${esc(result.message || 'Verification is based on post-execution operational evidence, not command exit status alone.')}</p></div>${pill(status)}</div><div class="fact-grid verification-facts"><div class="fact"><label>Confidence</label><strong>${result.confidence != null ? pct(result.confidence) : '—'}</strong></div><div class="fact"><label>Comparable metrics</label><strong>${result.comparable_metrics ?? '—'}</strong></div><div class="fact"><label>Evidence refs</label><strong>${result.evidence_refs?.length ?? '—'}</strong></div><div class="fact"><label>Memory</label><strong>${esc(memoryState(l))}</strong></div></div>${changes.length ? `<div class="insight-card"><h4>Before → after</h4>${changes.map(x => `<div class="change-row">${esc(x)}</div>`).join('')}</div>` : ''}<div class="insight-card"><h4>Verification result</h4><div class="json">${esc(JSON.stringify(result, null, 2))}</div></div>${(v.items || []).map(x => `<div class="insight-card"><h4>${esc(x.event_type || 'verification audit')}</h4><div class="json">${esc(JSON.stringify(x, null, 2))}</div></div>`).join('')}`;
}

function renderDetail(tab = 'overview') {
  if (!S.detail) return;
  const {context: c, evidence: e, lifecycle: l, verification: v, memory} = S.detail;
  const incident = S.incidents.find(x => x.id === S.selected) || {};
  const approvalStatus = l.approval?.status || incident.approval_status || 'not requested';
  const executionStatus = l.execution?.success === true ? 'success' : l.execution?.blocked === true ? 'blocked' : l.execution ? 'failed' : incident.execution_status || 'not recorded';
  const verificationStatus = l.verification?.status || incident.verification_status || 'not recorded';

  $('#detail').innerHTML = `<div class="detail-head"><div class="detail-title-row"><div><div class="detail-title">${esc(c.service || incident.service || 'Incident')}</div><div class="detail-id">${esc(c.incident_id || S.selected)}</div></div>${pill(c.severity || incident.severity)}</div><div class="detail-summary">${esc(c.summary || incident.summary || 'No incident summary')}</div><div class="fact-grid"><div class="fact"><label>Status</label><strong>${esc(c.status || incident.status || '—')}</strong></div><div class="fact"><label>Current node</label><strong>${esc(l.current_node || l.checkpoint_status || '—')}</strong></div><div class="fact"><label>Risk</label><strong>${esc(incident.risk_level || l.decision?.risk || l.decision?.risk_level || '—')}</strong></div><div class="fact"><label>Evidence rounds</label><strong>${esc(l.evidence_rounds ?? 0)}</strong></div></div><div class="control-state-row">${pill(`approval: ${approvalStatus}`)}${pill(`execution: ${executionStatus}`)}${pill(`verification: ${verificationStatus}`)}${pill(`memory: ${memoryState(l)}`)}</div></div><div class="tabs">${['overview','evidence','agents','decision','verification','memory','audit'].map(t => `<button class="${t === tab ? 'active' : ''}" onclick="renderDetail('${t}')">${t}</button>`).join('')}</div><div id="detailPane" class="detail-pane"></div>`;

  const pane = $('#detailPane');
  if (tab === 'overview') {
    const coord = l.coordination || {};
    const evaln = l.evaluation || {};
    const routing = l.routing || {};
    pane.innerHTML = `<div class="workflow">${workflowStages(l)}</div>${confidenceBlock('Incident confidence', incident.confidence)}<div class="insight-card"><h4>Routing / RCA / evaluator</h4><p>${esc(coord.summary || coord.statement || l.terminal_reason || 'Structured coordination and evaluator state are available below.')}</p><div class="json">${esc(JSON.stringify({routing, triage:l.triage, coordination:coord, evaluation:evaln}, null, 2))}</div></div><div class="insight-card"><h4>Governed control state</h4><p>Decision ${esc(l.decision?.decision || incident.decision || 'pending')} · Approval ${esc(approvalStatus)} · Execution ${esc(executionStatus)} · Verification ${esc(verificationStatus)} · Memory ${esc(memoryState(l))}</p></div>`;
  }
  if (tab === 'evidence') pane.innerHTML = (e.items || []).map(x => `<div class="evidence-card"><h4>${esc(x.source || 'evidence')} · ${esc(x.type || 'record')}</h4><p>${esc(x.reference || x.query || 'Durable production evidence')}</p><div class="json">${esc(JSON.stringify(x.raw_data || {}, null, 2))}</div></div>`).join('') || '<div class="empty-state">No evidence recorded.</div>';
  if (tab === 'agents') pane.innerHTML = `<div class="insight-card"><h4>Specialist routing</h4><div class="json">${esc(JSON.stringify(l.routing || {}, null, 2))}</div></div>` + ((l.agents || []).map(a => `<div class="agent-card"><h4>${esc(a.agent_name || a.agent || 'agent')}</h4><p>${esc(a.statement || a.finding_type || 'Structured specialist analysis')}</p><div class="confidence-line"><div class="confidence-meter"><i style="width:${Math.max(0, Math.min(1, Number(a.confidence) || 0)) * 100}%"></i></div><b>${pct(a.confidence)}</b></div><div class="json">${esc(JSON.stringify(a, null, 2))}</div></div>`).join('') || '<div class="empty-state">No specialist findings recorded.</div>');
  if (tab === 'decision') pane.innerHTML = `<div class="insight-card"><h4>Evaluator gate</h4><div class="json">${esc(JSON.stringify(l.evaluation || {}, null, 2))}</div></div><div class="insight-card"><h4>Decision / policy</h4><div class="json">${esc(JSON.stringify(l.decision || {}, null, 2))}</div></div><div class="insight-card"><h4>Final remediation plan</h4><p>${esc(l.final_plan || 'No final plan recorded.')}</p></div>${renderBinding(l.approval || {})}<div class="insight-card"><h4>Approval</h4><div class="json">${esc(JSON.stringify(l.approval || {}, null, 2))}</div></div><div class="insight-card"><h4>Execution receipt</h4><div class="json">${esc(JSON.stringify(l.execution || {}, null, 2))}</div></div>`;
  if (tab === 'verification') pane.innerHTML = renderVerification(l, v, incident);
  if (tab === 'memory') {
    if (!memory) {
      pane.innerHTML = '<div class="empty-state">Loading historical Operational Memory on demand…</div>';
      loadIncidentMemory(S.selected);
      return;
    }
    const writeback = (l.audit || []).filter(a => lower(a.event_type).startsWith('memory_writeback'));
    const episode = memory?.current_episode || null;
    const policy = memory?.policy || {};
    const episodeFacts = episode ? `<div class="fact-grid"><div class="fact"><label>Outcome</label><strong>${esc(episode.memory_outcome_class || '—')}</strong></div><div class="fact"><label>Root cause status</label><strong>${esc(episode.root_cause_status || '—')}</strong></div><div class="fact"><label>Embedding</label><strong>${esc(episode.embedding_status || '—')}</strong></div><div class="fact"><label>Reuse</label><strong>${esc(episode.reuse_count ?? 0)}</strong></div></div>` : '';
    pane.innerHTML = `<div class="insight-card"><h4>Operational Memory policy</h4><p>${esc(policy.label || 'HISTORICAL OPERATIONAL EXPERIENCE')} · Historical memory is auxiliary context, never current Evidence, and every reused action requires fresh validation.</p></div><div class="insight-card"><h4>Current incident episode</h4>${episodeFacts}<div class="json">${esc(JSON.stringify(episode || {status:'not_recorded'}, null, 2))}</div></div><div class="insight-card"><h4>Memory write-back audit</h4><p>Successful, partial, failed and blocked outcomes may be retained as labeled historical experience. Cognia Knowledge remains a separate governed domain.</p><div class="json">${esc(JSON.stringify(writeback, null, 2))}</div></div><div class="insight-card"><h4>Historical Operational Memory ≠ Live Evidence</h4><p>Similar incidents, historical RCA, previous actions and failed attempts are advisory only.</p><div class="fact-grid"><div class="fact"><label>Similar incidents</label><strong>${esc((memory?.similar_incidents || memory?.items || []).length)}</strong></div><div class="fact"><label>Failed previous attempts</label><strong>${esc((memory?.failed_previous_attempts || []).length)}</strong></div></div>${memory?.error ? `<p>${esc(memory.error)}</p>` : ''}<div class="json">${esc(JSON.stringify({similar_incidents: memory?.similar_incidents || memory?.items || [], historical_rca: memory?.historical_rca || [], previous_actions: memory?.previous_actions || [], failed_previous_attempts: memory?.failed_previous_attempts || []}, null, 2))}</div></div>`;
  }
  if (tab === 'audit') pane.innerHTML = (l.audit || []).map(timelineItem).join('') || '<div class="empty-state">No incident audit events.</div>';
}

async function loadAgents() {
  try {
    const [c, m] = await Promise.all([api('/api/v1/agents/catalog'), api('/api/v1/agents/metrics')]);
    S.agents = c.items || [];
    S.agentMetrics = m.items || [];
    const metrics = {};
    S.agentMetrics.forEach(x => metrics[x.agent_name || x.agent] = x);
    $('#agentsGrid').innerHTML = S.agents.map(a => {
      const met = metrics[a.name] || {};
      return `<article class="panel agent-manifest"><div style="display:flex;justify-content:space-between">${pill(a.enabled ? 'enabled' : 'disabled')}<span class="muted" style="font-size:7px">${esc(a.version || '')}</span></div><h3>${esc(a.name)}</h3><p>${esc(a.description || a.responsibility || 'Analysis-only specialist')}</p><div class="tags">${(a.capabilities || a.read_capabilities || []).slice(0, 8).map(x => `<span>${esc(x)}</span>`).join('')}</div><div class="mini-metrics"><div><label>Invocations</label><strong>${met.invocations ?? 0}</strong></div><div><label>Avg confidence</label><strong>${pct(met.average_confidence || 0)}</strong></div></div></article>`;
    }).join('') || '<div class="panel empty-state">No agents available.</div>';
  } catch (e) { showError(e.message); }
}

function renderMcp() {
  if (!$('#mcpGrid')) return;
  const ext = S.health?.components?.external || {};
  const defs = [
    ['Zabbix MCP', 'zabbix_mcp', 'Monitoring alerts, problems and host context', 'Operational Evidence'],
    ['Elastic Agent Builder MCP', 'elasticsearch_mcp', 'Logs and governed ES|QL evidence', 'Operational Evidence'],
    ['Prometheus MCP', 'prometheus_mcp', 'Metrics, series and alert evidence', 'Operational Evidence']
  ];
  if (Object.prototype.hasOwnProperty.call(ext, 'vm_mcp')) defs.push(['VM Edge MCP', 'vm_mcp', 'VM telemetry plus governed service remediation', 'Execution Boundary']);
  if (Object.prototype.hasOwnProperty.call(ext, 'kubernetes_mcp')) defs.push(['Kubernetes MCP', 'kubernetes_mcp', 'Optional Kubernetes operational boundary', 'Execution Boundary']);
  if (Object.prototype.hasOwnProperty.call(ext, 'jenkins_mcp')) defs.push(['Jenkins MCP', 'jenkins_mcp', 'Optional governed delivery boundary', 'Execution Boundary']);
  if (Object.prototype.hasOwnProperty.call(ext, 'cognia')) defs.push(['Cognia Knowledge API', 'cognia', 'Sole governed organizational Knowledge RAG; not an MCP operational tool', 'Knowledge Boundary']);
  $('#mcpGrid').innerHTML = defs.map(([name, key, desc, boundary]) => {
    const x = ext[key] || {};
    return `<article class="panel mcp-card"><div class="mcp-card-head"><div class="mcp-icon">◇</div>${pill(x.healthy ? 'healthy' : x.configured === false ? 'not configured' : 'unavailable')}</div><span class="section-kicker">${esc(boundary)}</span><h3>${esc(name)}</h3><p>${esc(desc)}</p><div class="mcp-status"><span>Connection</span><strong>${x.healthy ? 'Healthy' : 'Unavailable'}</strong></div>${x.error ? `<div class="dependency-error">${esc(x.error)}</div>` : ''}</article>`;
  }).join('');
}

function renderAudit() {
  if (!$('#auditList')) return;
  const a = S.summary?.recent_audit || [];
  $('#auditList').innerHTML = a.map(timelineItem).join('') || '<div class="empty-state">No audit events recorded.</div>';
}

async function loadAll() {
  showError();
  $('#apiKey').value = S.key;
  try {
    const [summary, incidents, services, health] = await Promise.all([
      api('/api/v1/dashboard/summary'),
      api('/api/v1/dashboard/incidents?limit=100'),
      api('/api/v1/dashboard/services?limit=100'),
      api('/api/v1/health')
    ]);
    S.summary = summary;
    S.incidents = incidents.items || [];
    S.services = services.items || [];
    S.health = health;
    renderOverview();
    renderHealth();
    renderIncidents();
    renderServices();
    renderMcp();
    renderAudit();
    if (!S.selected && S.incidents[0] && S.view === 'incidents') selectIncident(S.incidents[0].id);
  } catch (e) {
    showError(`Live dashboard unavailable: ${e.message}`);
    $('#liveDot').classList.remove('ok');
    $('#platformState').textContent = 'Unavailable';
  }
}

window.saveKey = saveKey;
window.setView = setView;
window.syncGlobalSearch = syncGlobalSearch;
window.selectIncident = selectIncident;
window.loadIncidentMemory = loadIncidentMemory;
window.openIncident = openIncident;
window.renderDetail = renderDetail;
window.renderIncidents = renderIncidents;
window.renderServices = renderServices;
window.renderMcp = renderMcp;
window.renderAudit = renderAudit;
window.loadAll = loadAll;
window.toggleTheme = toggleTheme;

window.addEventListener('storage', event => {
  if (event.key === THEME_STORAGE && (event.newValue === 'light' || event.newValue === 'dark')) {
    applyTheme(event.newValue, {persist: false});
  }
});

window.addEventListener('DOMContentLoaded', () => {
  applyTheme(initialTheme(), {persist: false});
  $('#themeToggle')?.addEventListener('click', toggleTheme);
  if (S.key) $('#apiKey').value = S.key;
  loadAll();
  setInterval(loadAll, 60000);
});
