const S = {
  key: localStorage.getItem('aiops_api_key') || '',
  summary: null,
  incidents: [],
  archivedIncidents: [],
  incidentPeriod: 'recent',
  archiveLoaded: false,
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
const fmtDate = v => v ? new Date(v).toLocaleString('fa-IR') : '—';
const fmtShortDate = v => v ? new Date(v).toLocaleString('fa-IR', {month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit'}) : '—';
const pct = v => `${Math.round((Number(v) || 0) * 100)}%`;
const isOpen = i => !['closed', 'resolved'].includes(lower(i.status));
const visibleOnThisDashboard = i => !(
  typeof window.isIncidentDismissed === 'function' &&
  window.isIncidentDismissed(i.id)
);
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
  return `<span class="pill ${c}">${esc(faStatus(v || '—'))}</span>`;
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
    if (r.status === 503 && d?.detail?.code === 'DATABASE_MIGRATION_DRIFT') {
      throw new Error('پایگاه‌داده هنوز به نسخه جدید ارتقا نیافته است. عملیات موقتاً برای حفظ امنیت متوقف شده؛ مدیر سیستم باید پس از تهیه بکاپ Migration را اجرا کند.');
    }
    throw new Error(`${r.status} ${typeof d?.detail === 'string' ? d.detail : (d?.detail?.code || r.statusText)}`);
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
  toast('کلید API به‌روزرسانی شد.');
  loadAll();
}

function syncGlobalSearch(v) {
  if ($('#incidentSearch')) $('#incidentSearch').value = v;
  if ($('#serviceSearch')) $('#serviceSearch').value = v;
  renderIncidents();
  renderServices();
}

async function setIncidentPeriod(period) {
  if (!['recent', 'archived'].includes(period)) return;
  S.incidentPeriod = period;
  if (period === 'recent') {
    renderIncidents();
    return;
  }
  S.archiveLoaded = false;
  renderIncidents();
  try {
    // Archive is requested on demand and never replaces S.incidents.
    // Live operator attention and KPI views must keep the rolling 24h set.
    const result = await api('/api/v1/dashboard/incidents?limit=200&scope=archived');
    if (S.incidentPeriod !== 'archived') return;
    S.archivedIncidents = result.items || [];
    S.archiveLoaded = true;
    renderIncidents();
  } catch (error) {
    if (S.incidentPeriod === 'archived') {
      showError('بارگذاری آرشیو رخدادها ناموفق بود: ' + error.message);
      const list = $('#incidentRows');
      if (list) list.innerHTML = '<div class="empty-state">آرشیو در دسترس نیست؛ دوباره تلاش کن.</div>';
    }
  }
}

function setView(v) {
  S.view = v;
  $$('.view').forEach(x => x.classList.toggle('active', x.dataset.view === v));
  $$('.nav button').forEach(x => x.classList.toggle('active', x.dataset.view === v));
  const titles = {
    overview: ['مرکز فرمان', 'نمای زنده و اولویت‌بندی‌شده رخدادها، بازیابی‌های تحت نظارت و وابستگی‌های سامانه.'],
    incidents: ['مدیریت رخدادها', 'فهرست رخدادها، شواهد ثبت‌شده، تحلیل و روند رسیدگی.'],
    services: ['سلامت سرویس‌ها', 'وضعیت و میزان اثرگذاری رخدادهای ثبت‌شده بر سرویس‌ها.'],
    agents: ['ایجنت‌ها و تحلیل علت ریشه‌ای', 'عملکرد ایجنت‌های تخصصی، هماهنگی تحلیل‌ها و کیفیت خروجی‌ها.'],
    mcp: ['زیرساخت MCP', 'وضعیت اتصال ابزارهای عملیاتی و مرز مستقل دانش سازمانی Cognia.'],
    knowledge: ['پایگاه دانش', 'مرتب‌سازی و بازبینی تجربه‌های رخداد و انتشار دانش Cognia پس از تأیید انسانی.'],
    audit: ['ممیزی و حاکمیت', 'سوابق تصمیم، تأیید، اجرا، راستی‌آزمایی و یادگیری عملیاتی.']
  };
  $('#pageTitle').textContent = titles[v][0];
  $('#pageSub').textContent = titles[v][1];
  if (v === 'agents') loadAgents();
  if (v === 'services') renderServices();
  if (v === 'mcp') renderMcp();
  if (v === 'audit') renderAudit();
  if (v === 'knowledge' && typeof window.loadKnowledgeReviews === 'function') window.loadKnowledgeReviews();
}

// Human-readable labels only. Never change provider status values used by gates.
function faStatus(value) {
  const v = lower(value);
  return ({
    critical: 'بحرانی', high: 'زیاد', medium: 'متوسط', low: 'کم',
    healthy: 'سالم', degraded: 'دچار اختلال', unhealthy: 'ناسالم', unavailable: 'در دسترس نیست', not_configured: 'پیکربندی نشده',
    active: 'فعال', inactive: 'غیرفعال', open: 'باز', closed: 'بسته‌شده',
    analyzing: 'در حال تحلیل', escalated: 'ارجاع‌شده', resolved: 'رفع‌شده',
    pending: 'در انتظار تأیید', pending_validation: 'در انتظار اعتبارسنجی کانفیگ', approved: 'تأییدشده', rejected: 'ردشده',
    consumed: 'مصرف‌شده', failed: 'ناموفق', failure: 'ناموفق', not_persisted: 'ثبت‌نشده',
    blocked: 'مسدودشده', partial: 'ناقص', inconclusive: 'نامشخص',
    verified: 'راستی‌آزمایی‌شده', completed: 'تکمیل‌شده',
    success: 'موفق', running: 'در حال اجرا', warning: 'هشدار',
    unknown: 'نامشخص', not_recorded: 'ثبت نشده', not_requested: 'درخواست نشده',
    not_persisted: 'در حافظه ثبت نشده', persisted: 'در حافظه ثبت شده',
    enabled: 'فعال', disabled: 'غیرفعال', ready: 'آماده', queued: 'در صف',
    in_progress: 'در حال انجام', skipped: 'انجام نشده', timeout: 'پایان مهلت',
    awaiting_approval: 'در انتظار تأیید', awaiting_execution: 'در انتظار اجرا',
    not_applicable: 'قابل اعمال نیست', pending_review: 'در انتظار بازبینی',
    published: 'منتشرشده', submitted: 'ارسال‌شده', publishing: 'در حال انتشار',
    publish_failed: 'انتشار ناموفق', approved_pending_execution: 'تأییدشده، منتظر اجرا',
    passed: 'موفق', error: 'خطا', stale: 'قدیمی', fresh: 'تازه',
    unreachable: 'غیرقابل دسترس', healthy_verified: 'سلامت تأیید شد'
  })[v] || String(value ?? 'نامشخص');
}

function faAction(value) {
  const v = lower(value);
  return ({
    start_service: 'راه‌اندازی سرویس', stop_service: 'توقف سرویس',
    restart_service: 'راه‌اندازی مجدد سرویس',
    reload_service: 'بارگذاری مجدد سرویس',
    approval_requested: 'درخواست تأیید',
    approval_granted: 'تأیید اجرا'
  })[v] || String(value ?? 'نامشخص');
}

function faEvent(value) {
  const map = {
    incident_created: 'ایجاد رخداد',
    approval_requested: 'درخواست تأیید',
    approval_approved: 'تأیید درخواست',
    approval_rejected: 'رد درخواست',
    execution_started: 'شروع اجرا',
    execution_completed: 'پایان اجرا',
    verification_completed: 'اتمام راستی‌آزمایی'
  };
  return map[lower(value)] || String(value ?? 'رویداد');
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
  if (lower(i.severity) === 'critical') reasons.push('شدت بحرانی');
  else if (lower(i.severity) === 'high') reasons.push('شدت زیاد');
  if (lower(i.approval_status) === 'pending') reasons.push('در انتظار تأیید');
  if (lower(i.approval_status) === 'pending_validation') reasons.push('درخواست اصلاح کانفیگ در انتظار اعتبارسنجی فنی');
  if (lower(i.approval_status) === 'approved') reasons.push('تأییدشده و در انتظار اجرا');
  if (/failed|failure|blocked/.test(lower(i.execution_status))) reasons.push(`اجرای ${faStatus(i.execution_status)}`);
  if (/failed|failure/.test(lower(i.verification_status))) reasons.push('راستی‌آزمایی ناموفق');
  if (/partial|inconclusive/.test(lower(i.verification_status))) reasons.push(`راستی‌آزمایی ${faStatus(i.verification_status)}`);
  if (lower(i.memory_status) === 'not_persisted' && /success|verified/.test(lower(i.verification_status))) reasons.push('نتیجه در حافظه ثبت نشده');
  if (Number(i.confidence || 0) > 0 && Number(i.confidence) < .5) reasons.push('اطمینان پایین تحلیل');
  return reasons;
}

function attentionRank(i) {
  let n = 0;
  if (lower(i.severity) === 'critical') n += 100;
  else if (lower(i.severity) === 'high') n += 60;
  else if (lower(i.severity) === 'medium') n += 20;
  if (lower(i.approval_status) === 'pending') n += 30;
  if (lower(i.approval_status) === 'pending_validation') n += 20;
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
    {name: 'PostgreSQL + pgvector', healthy: h.database?.status === 'healthy', kind: 'state', meta: h.database?.migration?.valid === false ? 'ناسازگاری نسخه پایگاه‌داده' : 'اطلاعات پایدار و حافظه عملیاتی'},
    {name: 'Zabbix MCP', healthy: ext.zabbix_mcp?.healthy, kind: 'mcp', meta: 'شواهد سامانه پایش'},
    {name: 'Elastic Agent Builder MCP', healthy: ext.elasticsearch_mcp?.healthy, kind: 'mcp', meta: 'شواهد ES|QL با کنترل دسترسی'},
    {name: 'Prometheus MCP', healthy: ext.prometheus_mcp?.healthy, kind: 'mcp', meta: 'شواهد متریک‌ها'}
  ];
  if (Object.prototype.hasOwnProperty.call(ext, 'vm_mcp')) rows.push({name: 'VM Edge MCP', healthy: ext.vm_mcp?.healthy, kind: 'mcp-write', meta: 'پایش ماشین مجازی و بازیابی تحت نظارت'});
  if (Object.prototype.hasOwnProperty.call(ext, 'kubernetes_mcp')) rows.push({name: 'Kubernetes MCP', healthy: ext.kubernetes_mcp?.healthy, kind: 'mcp-write', meta: 'اتصال اختیاری Kubernetes'});
  if (Object.prototype.hasOwnProperty.call(ext, 'jenkins_mcp')) rows.push({name: 'Jenkins MCP', healthy: ext.jenkins_mcp?.healthy, kind: 'mcp-write', meta: 'اتصال اختیاری فرایند انتشار'});
  if (Object.prototype.hasOwnProperty.call(ext, 'cognia')) {
    const c = ext.cognia || {};
    const httpStatus = Number.isInteger(c.http_status) ? ' · HTTP '+c.http_status : '';
    rows.push({name: 'Cognia Knowledge', healthy: c.healthy, kind: 'knowledge',
      meta: c.configured === false ? 'پیکربندی نشده · /swagger/index.html' :
        'دسترسی HTTP کاگنیا · /swagger/index.html'+httpStatus});
  }
  return rows;
}

function renderOverview() {
  const x = S.summary || {};
  $('#kActive').textContent = x.incidents_active ?? '—';
  $('#kCritical').textContent = x.incidents_critical ?? '—';
  $('#kPending').textContent = x.approvals_pending ?? '—';
  $('#kValidationPending').textContent = x.approvals_validation_pending ?? '—';
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
  $('#platformState').textContent = !live ? 'در دسترس نیست' : platformHealthy ? 'فعال' : 'دچار اختلال';
  $('#platformState').classList.toggle('live', platformHealthy);
  $('#platformVersion').textContent = S.health?.version || '—';
  $('#lastUpdated').textContent = live ? new Date().toLocaleTimeString('fa-IR') : '—';

  const attention = S.incidents.filter(i => visibleOnThisDashboard(i) && isOpen(i) && attentionReason(i).length).sort((a, b) => attentionRank(b) - attentionRank(a));
  const atRisk = S.services.filter(s => serviceState(s) !== 'healthy');
  const degradedDeps = dependencyEntries().filter(d => !d.healthy);
  $('#attentionCount').textContent = attention.length;
  $('#serviceRiskCount').textContent = atRisk.length;
  $('#dependencyRiskCount').textContent = degradedDeps.length;
  $('#attentionBadge').textContent = `${attention.length.toLocaleString('fa-IR')} مورد فعال`;

  $('#attentionQueue').innerHTML = attention.slice(0, 7).map(i => {
    const score = attentionRank(i);
    const level = attentionLevel(score);
    const critical = level === 'P0' ? 'critical' : '';
    return `<a class="attention-item" href="/dashboard/incidents/${encodeURIComponent(i.id)}" aria-label="گزارش و تصمیم‌گیری رخداد ${esc(i.service || i.id)}"><i class="attention-marker ${critical}"></i><div><div class="attention-title">${esc(i.service || 'سرویس نامشخص')} · ${esc(i.summary || 'رخداد')}</div><div class="attention-meta">${esc(attentionReason(i).join(' · '))} · ${fmtShortDate(i.created_at)}</div></div><div class="attention-score"><strong>${level}</strong><small>${esc(faStatus(i.severity || ''))}</small></div></a>`;
  }).join('') || '<div class="empty-state">در حال حاضر رخداد فعالی نیازمند رسیدگی فوری اپراتور نیست.</div>';

  $('#servicePreview').innerHTML = S.services.slice(0, 6).map(s => {
    const state = serviceState(s);
    return `<div class="service-row"><div><div class="service-name">${esc(s.service)}</div><div class="service-summary">${esc(s.latest_summary || 'گزارش جدیدی ثبت نشده است')}</div></div><div><div class="health-bar"><i class="${state}" style="width:${state === 'healthy' ? 100 : state === 'degraded' ? 58 : 28}%"></i></div></div><div class="service-counts"><b>${s.incidents_active}</b>فعال · ${esc(faStatus(state))}</div></div>`;
  }).join('') || '<div class="empty-state">هنوز سابقه مستندی از رخدادهای سرویس‌ها ثبت نشده است.</div>';

  renderLifecycleSummary();
  renderSeverity();
  renderAuditPreview();
}

function renderLifecycleSummary() {
  const x = S.summary || {};
  const items = [
    ['در انتظار اعتبارسنجی', x.approvals_validation_pending || 0, 'تأیید و اجرای کانفیگ هنوز مجاز نیست'],
    ['در انتظار تأیید', x.approvals_pending || 0, 'نیازمند تأیید انسانی'],
    ['تأییدشده', x.approvals_approved || 0, 'در انتظار ادامه اجرا'],
    ['مجوز مصرف‌شده', x.approvals_consumed || 0, 'مجوز یک‌بارمصرف استفاده شده'],
    ['اجرای موفق', x.execution_success || 0, `${x.execution_failed || 0} ناموفق · ${x.execution_blocked || 0} مسدودشده`],
    ['راستی‌آزمایی موفق', x.verification_success || 0, `${x.verification_partial || 0} ناقص · ${x.verification_inconclusive || 0} نامشخص`],
    ['تجربه‌های حافظه', x.memory_entries_total || 0, `${x.memory_entries_active || 0} فعال`],
    ['بردارسازی آماده', x.memory_embedding_ready || 0, `${x.memory_embedding_backlog || 0} در صف · ${x.memory_embedding_contract_mismatch || 0} ناسازگار · ${x.memory_embedding_failed || 0} ناموفق · ${x.memory_embedding_pending || 0} منتظر`],
    ['ثبت نتیجه در حافظه', x.memory_persisted || 0, `${x.memory_not_persisted || 0} ثبت‌نشده`]
  ];
  $('#automationLifecycle').innerHTML = items.map(([label, value, meta]) => `<div class="lifecycle-node"><span>${esc(label)}</span><strong>${esc(value)}</strong><small>${esc(meta)}</small></div>`).join('');
}

function renderSeverity() {
  const sev = {critical: 0, high: 0, medium: 0, low: 0};
  S.incidents.filter(i => visibleOnThisDashboard(i) && isOpen(i)).forEach(i => { const s = lower(i.severity); if (sev[s] != null) sev[s]++; });
  const total = Object.values(sev).reduce((a, b) => a + b, 0);
  const colors = {critical:'var(--red)', high:'var(--amber)', medium:'var(--blue)', low:'var(--green)'};
  $('#severityBreakdown').innerHTML = total ? Object.entries(sev).map(([k, n]) => `<div class="severity-row"><span>${esc(faStatus(k))}</span><div class="severity-bar"><i style="width:${n / total * 100}%;background:${colors[k]}"></i></div><b>${n}</b></div>`).join('') : '<div class="empty-state">رخداد فعالی وجود ندارد.</div>';
}

function auditSummary(a) {
  const m = a.metadata || {};
  const parts = [];
  if (a.action) parts.push(faAction(a.action));
  if (a.status) parts.push(faStatus(a.status));
  if (m.requested_action) parts.push(faAction(m.requested_action));
  if (m.tool_name || m.tool) parts.push(m.tool_name || m.tool);
  if (m.target) parts.push(m.target);
  if (m.verification_status) parts.push(`راستی‌آزمایی: ${faStatus(m.verification_status)}`);
  if (m.status && !parts.includes(faStatus(m.status))) parts.push(faStatus(m.status));
  if (typeof m.persisted === 'boolean') parts.push(`حافظه: ${m.persisted ? 'ثبت‌شده' : 'ثبت‌نشده'}`);
  return parts.join(' · ') || 'رویداد حاکمیتی ثبت شده است';
}

function timelineItem(a) {
  return `<div class="timeline-item"><div class="timeline-title">${esc(faEvent(a.event_type || 'event'))}</div><div class="timeline-meta">${fmtShortDate(a.created_at)} · ${esc(String(a.incident_id || 'بدون رخداد').slice(0, 8))}${a.actor ? ` · ${esc(a.actor)}` : ''}</div><div class="timeline-body">${esc(auditSummary(a))}</div></div>`;
}

function renderAuditPreview() {
  const audit = S.summary?.recent_audit || [];
  $('#auditPreview').innerHTML = audit.slice(0, 3).map(timelineItem).join('') || '<div class="empty-state">رویداد ممیزی ثبت نشده است.</div>';
}

function renderHealth() {
  const defs = dependencyEntries();
  $('#components').innerHTML = defs.map(x => `<div class="component"><div class="component-top"><span class="component-name">${esc(x.name)}</span><span class="dot ${x.healthy ? 'green' : ''}" style="${x.healthy ? '' : 'background:var(--red)'}"></span></div><div class="component-state ${x.healthy ? 'ok' : 'bad'}">${x.healthy ? 'سالم' : 'در دسترس نیست'}</div><small>${esc(x.meta)}</small></div>`).join('');
}

function renderIncidents() {
  const q = lower($('#incidentSearch')?.value);
  const sev = $('#severityFilter')?.value || '';
  const status = $('#statusFilter')?.value || '';
  const rows = S.incidents.filter(i => (!q || lower([i.id, i.service, i.summary, i.execution_target, i.execution_tool, i.runbook_id].join(' ')).includes(q)) && (!sev || lower(i.severity) === sev) && (!status || lower(i.status) === status));
  if ($('#incidentCount')) $('#incidentCount').textContent = `${rows.length} رخداد`;
  if (!$('#incidentRows')) return;
  $('#incidentRows').innerHTML = rows.map(i => `<tr class="${S.selected === i.id ? 'selected' : ''}" onclick="selectIncident('${esc(i.id)}')"><td><div class="incident-main">${esc(String(i.id).slice(0, 8))}</div><div class="incident-sub">${esc(i.summary || '')}</div></td><td>${esc(i.service || '—')}</td><td>${pill(i.severity)}</td><td>${pill(i.status)}</td><td>${pct(i.confidence)}</td><td>${pill(i.risk_level || '—')}</td><td>${pill(i.approval_status || '—')}</td><td>${pill(i.execution_status || '—')}</td><td>${pill(i.verification_status || '—')}</td><td>${pill(i.memory_status || '—')}</td><td>${fmtShortDate(i.created_at)}</td></tr>`).join('') || '<tr><td colspan="11"><div class="empty-state">هیچ رخدادی با فیلترهای انتخاب‌شده مطابقت ندارد.</div></td></tr>';
}

function renderServices() {
  if (!$('#serviceGrid')) return;
  const q = lower($('#serviceSearch')?.value);
  const risk = $('#serviceRiskFilter')?.value || '';
  const rows = S.services.filter(s => (!q || lower([s.service, s.latest_summary].join(' ')).includes(q)) && (!risk || serviceState(s) === risk));
  $('#serviceCount').textContent = `${rows.length} سرویس`;
  $('#serviceGrid').innerHTML = rows.map(s => {
    const state = serviceState(s);
    return `<article class="panel service-card"><div class="service-card-top"><div><span class="section-kicker">سرویس</span><h3>${esc(s.service)}</h3></div>${pill(state)}</div><p>${esc(s.latest_summary || 'خلاصه‌ای از رخداد ثبت نشده است.')}</p><div class="service-metrics"><div class="service-metric"><label>رخداد فعال</label><strong>${s.incidents_active}</strong></div><div class="service-metric"><label>بحرانی / زیاد</label><strong>${s.critical_active} / ${s.high_active}</strong></div><div class="service-metric"><label>میزان اطمینان</label><strong>${pct(s.mean_active_confidence)}</strong></div><div class="service-metric"><label>منتظر تأیید یا اجرا</label><strong>${Number(s.approvals_pending || 0) + Number(s.approvals_approved || 0)}</strong></div><div class="service-metric"><label>راستی‌آزمایی‌شده</label><strong>${s.successful_verifications || 0}</strong></div><div class="service-metric"><label>ثبت‌شده در حافظه</label><strong>${s.memory_persisted || 0}</strong></div></div><div class="service-footer"><span>${s.failed_executions || 0} اجرای ناموفق · ${s.failed_verifications || 0} راستی‌آزمایی ناموفق · ${Number(s.partial_verifications || 0) + Number(s.inconclusive_verifications || 0)} نامشخص</span><span>${fmtShortDate(s.last_incident_at)}</span></div></article>`;
  }).join('') || '<div class="panel empty-state">هیچ سرویسی با فیلتر انتخاب‌شده مطابقت ندارد.</div>';
}

function openIncident(id) {
  // All queue and attention entry points use one unambiguous full-page workflow.
  window.location.assign('/dashboard/incidents/' + encodeURIComponent(id));
}

async function selectIncident(id) {
  S.selected = id;
  S.memoryLoadingFor = null;
  renderIncidents();
  $('#detail').innerHTML = '<div class="empty-state tall">در حال دریافت وضعیت ثبت‌شدهٔ رخداد…</div>';
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
    return `<div class="stage ${cls}">${esc(({signal:'سیگنال',evidence:'شواهد',triage:'دسته‌بندی',agents:'ایجنت‌ها',evaluator:'ارزیابی',decision:'تصمیم',approval:'تأیید انسانی',execution:'اجرا',verification:'راستی‌آزمایی',memory:'حافظه'})[name] || name)}</div>`;
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
  return `<div class="insight-card"><h4>اتصال مجوز به عملیات</h4><p>تأیید فقط برای همین عملیاتِ ثبت‌شده معتبر است. مجوز امضاشدهٔ اجرا برای حفظ امنیت در داشبورد نمایش داده نمی‌شود.</p><div class="json">${esc(JSON.stringify(binding, null, 2))}</div></div>`;
}

function renderVerification(l, v, incident) {
  const result = l.verification || {};
  const status = result.status || incident.verification_status || v.items?.[0]?.metadata?.status || 'not_recorded';
  const changes = result.changes || [];
  return `<div class="verification-hero"><div><span class="section-kicker">راستی‌آزمایی مستقل</span><h3>${esc(faStatus(status))}</h3><p>${esc(result.message || 'راستی‌آزمایی براساس شواهد عملیاتی پس از اجرا انجام می‌شود، نه صرفاً کد خروج دستور.')}</p></div>${pill(status)}</div><div class="fact-grid verification-facts"><div class="fact"><label>میزان اطمینان</label><strong>${result.confidence != null ? pct(result.confidence) : '—'}</strong></div><div class="fact"><label>متریک‌های قابل مقایسه</label><strong>${result.comparable_metrics ?? '—'}</strong></div><div class="fact"><label>ارجاعات شواهد</label><strong>${result.evidence_refs?.length ?? '—'}</strong></div><div class="fact"><label>حافظهٔ عملیاتی</label><strong>${esc(faStatus(memoryState(l)))}</strong></div></div>${changes.length ? `<div class="insight-card"><h4>قبل و بعد از اقدام</h4>${changes.map(x => `<div class="change-row">${esc(x)}</div>`).join('')}</div>` : ''}<div class="insight-card"><h4>نتیجهٔ راستی‌آزمایی</h4><div class="json">${esc(JSON.stringify(result, null, 2))}</div></div>${(v.items || []).map(x => `<div class="insight-card"><h4>${esc(x.event_type || 'ممیزی راستی‌آزمایی')}</h4><div class="json">${esc(JSON.stringify(x, null, 2))}</div></div>`).join('')}`;
}

function renderDetail(tab = 'overview') {
  if (!S.detail) return;
  const {context: c, evidence: e, lifecycle: l, verification: v, memory} = S.detail;
  const incident = S.incidents.find(x => x.id === S.selected) || {};
  const approvalStatus = l.approval?.status || incident.approval_status || 'not_requested';
  const executionStatus = l.execution?.success === true ? 'success' : l.execution?.blocked === true ? 'blocked' : l.execution ? 'failed' : incident.execution_status || 'not_recorded';
  const verificationStatus = l.verification?.status || incident.verification_status || 'not_recorded';

  $('#detail').innerHTML = `<div class="detail-head"><div class="detail-title-row"><div><div class="detail-title">${esc(c.service || incident.service || 'رخداد')}</div><div class="detail-id">${esc(c.incident_id || S.selected)}</div></div>${pill(c.severity || incident.severity)}</div><div class="detail-summary">${esc(c.summary || incident.summary || 'خلاصهٔ رخداد ثبت نشده است')}</div><div class="fact-grid"><div class="fact"><label>وضعیت</label><strong>${esc(faStatus(c.status || incident.status || '—'))}</strong></div><div class="fact"><label>مرحلهٔ جاری</label><strong>${esc(l.current_node || l.checkpoint_status || '—')}</strong></div><div class="fact"><label>ریسک</label><strong>${esc(faStatus(incident.risk_level || l.decision?.risk || l.decision?.risk_level || '—'))}</strong></div><div class="fact"><label>دفعات جمع‌آوری شواهد</label><strong>${esc(l.evidence_rounds ?? 0)}</strong></div></div><div class="control-state-row">${pill(`تأیید: ${faStatus(approvalStatus)}`)}${pill(`اجرا: ${faStatus(executionStatus)}`)}${pill(`راستی‌آزمایی: ${faStatus(verificationStatus)}`)}${pill(`حافظه: ${faStatus(memoryState(l))}`)}</div></div><div class="tabs">${['overview','evidence','agents','decision','verification','memory','audit'].map(t => `<button class="${t === tab ? 'active' : ''}" onclick="renderDetail('${t}')">${({overview:'نمای کلی',evidence:'شواهد',agents:'ایجنت‌ها',decision:'تصمیم',verification:'راستی‌آزمایی',memory:'حافظهٔ عملیاتی',audit:'ممیزی'})[t] || t}</button>`).join('')}</div><div id="detailPane" class="detail-pane"></div>`;

  const pane = $('#detailPane');
  if (tab === 'overview') {
    const coord = l.coordination || {};
    const evaln = l.evaluation || {};
    const routing = l.routing || {};
    pane.innerHTML = `<div class="workflow">${workflowStages(l)}</div>${confidenceBlock('اطمینان تحلیل رخداد', incident.confidence)}<div class="insight-card"><h4>مسیریابی / تحلیل علت / ارزیاب</h4><p>${esc(coord.summary || coord.statement || l.terminal_reason || 'نتیجهٔ هماهنگی ایجنت‌ها و ارزیابی تصمیم در ادامه آمده است.')}</p><div class="json">${esc(JSON.stringify({routing, triage:l.triage, coordination:coord, evaluation:evaln}, null, 2))}</div></div><div class="insight-card"><h4>وضعیت کنترل و مجوز عملیات</h4><p>Decision ${esc(l.decision?.decision || incident.decision || 'pending')} · Approval ${esc(approvalStatus)} · Execution ${esc(executionStatus)} · Verification ${esc(verificationStatus)} · Memory ${esc(faStatus(memoryState(l)))}</p></div>`;
  }
  if (tab === 'evidence') pane.innerHTML = (e.items || []).map(x => `<div class="evidence-card"><h4>${esc(x.source || 'evidence')} · ${esc(x.type || 'رکورد')}</h4><p>${esc(x.reference || x.query || 'شواهد ماندگار محیط عملیاتی')}</p><div class="json">${esc(JSON.stringify(x.raw_data || {}, null, 2))}</div></div>`).join('') || '<div class="empty-state">شواهدی ثبت نشده است.</div>';
  if (tab === 'agents') pane.innerHTML = `<div class="insight-card"><h4>مسیریابی ایجنت‌های متخصص</h4><div class="json">${esc(JSON.stringify(l.routing || {}, null, 2))}</div></div>` + ((l.agents || []).map(a => `<div class="agent-card"><h4>${esc(a.agent_name || a.agent || 'ایجنت')}</h4><p>${esc(a.statement || a.finding_type || 'تحلیل ساختاریافتهٔ متخصص')}</p><div class="confidence-line"><div class="confidence-meter"><i style="width:${Math.max(0, Math.min(1, Number(a.confidence) || 0)) * 100}%"></i></div><b>${pct(a.confidence)}</b></div><div class="json">${esc(JSON.stringify(a, null, 2))}</div></div>`).join('') || '<div class="empty-state">یافته‌ای از ایجنت‌های متخصص ثبت نشده است.</div>');
  if (tab === 'decision') pane.innerHTML = `<div class="insight-card"><h4>کنترل ارزیاب</h4><div class="json">${esc(JSON.stringify(l.evaluation || {}, null, 2))}</div></div><div class="insight-card"><h4>تصمیم و سیاست‌ها</h4><div class="json">${esc(JSON.stringify(l.decision || {}, null, 2))}</div></div><div class="insight-card"><h4>برنامهٔ نهایی اصلاح</h4><p>${esc(l.final_plan || 'برنامهٔ نهایی ثبت نشده است.')}</p></div>${renderBinding(l.approval || {})}<div class="insight-card"><h4>تأیید انسانی</h4><div class="json">${esc(JSON.stringify(l.approval || {}, null, 2))}</div></div><div class="insight-card"><h4>رسید اجرا</h4><div class="json">${esc(JSON.stringify(l.execution || {}, null, 2))}</div></div>`;
  if (tab === 'verification') pane.innerHTML = renderVerification(l, v, incident);
  if (tab === 'memory') {
    if (!memory) {
      pane.innerHTML = '<div class="empty-state">در حال دریافت حافظهٔ عملیاتی تاریخی…</div>';
      loadIncidentMemory(S.selected);
      return;
    }
    const writeback = (l.audit || []).filter(a => lower(a.event_type).startsWith('memory_writeback'));
    const episode = memory?.current_episode || null;
    const policy = memory?.policy || {};
    const episodeFacts = episode ? `<div class="fact-grid"><div class="fact"><label>نتیجه</label><strong>${esc(episode.memory_outcome_class || '—')}</strong></div><div class="fact"><label>وضعیت علت ریشه‌ای</label><strong>${esc(episode.root_cause_status || '—')}</strong></div><div class="fact"><label>بردار دانش</label><strong>${esc(episode.embedding_status || '—')}</strong></div><div class="fact"><label>دفعات استفادهٔ مجدد</label><strong>${esc(episode.reuse_count ?? 0)}</strong></div></div>` : '';
    pane.innerHTML = `<div class="insight-card"><h4>سیاست حافظهٔ عملیاتی</h4><p>${esc(policy.label || 'تجربهٔ عملیاتی تاریخی')} · حافظهٔ تاریخی فقط زمینهٔ کمکی است و هر اقدام برگرفته از آن نیاز به اعتبارسنجی تازه دارد.</p></div><div class="insight-card"><h4>سابقهٔ همین رخداد</h4>${episodeFacts}<div class="json">${esc(JSON.stringify(episode || {status:'not_recorded'}, null, 2))}</div></div><div class="insight-card"><h4>ممیزی ثبت در حافظه</h4><p>نتایج موفق، ناقص، ناموفق و مسدود ممکن است با برچسب مناسب در تجربه‌های تاریخی ثبت شوند. دانش کاگنیا مستقل است.</p><div class="json">${esc(JSON.stringify(writeback, null, 2))}</div></div><div class="insight-card"><h4>حافظهٔ تاریخی جایگزین شواهد زنده نیست</h4><p>رخدادهای مشابه، تحلیل علت تاریخی و اقدامات قبلی صرفاً راهنما هستند.</p><div class="fact-grid"><div class="fact"><label>رخدادهای مشابه</label><strong>${esc((memory?.similar_incidents || memory?.items || []).length)}</strong></div><div class="fact"><label>اقدامات ناموفق پیشین</label><strong>${esc((memory?.failed_previous_attempts || []).length)}</strong></div></div>${memory?.error ? `<p>${esc(memory.error)}</p>` : ''}<div class="json">${esc(JSON.stringify({similar_incidents: memory?.similar_incidents || memory?.items || [], historical_rca: memory?.historical_rca || [], previous_actions: memory?.previous_actions || [], failed_previous_attempts: memory?.failed_previous_attempts || []}, null, 2))}</div></div>`;
  }
  if (tab === 'audit') pane.innerHTML = (l.audit || []).map(timelineItem).join('') || '<div class="empty-state">رویداد ممیزی برای این رخداد ثبت نشده است.</div>';
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
      return `<article class="panel agent-manifest"><div style="display:flex;justify-content:space-between">${pill(a.enabled ? 'enabled' : 'disabled')}<span class="muted" style="font-size:7px">${esc(a.version || '')}</span></div><h3>${esc(a.name)}</h3><p>${esc(a.description || a.responsibility || 'ایجنت متخصص تحلیل')}</p><div class="tags">${(a.capabilities || a.read_capabilities || []).slice(0, 8).map(x => `<span>${esc(x)}</span>`).join('')}</div><div class="mini-metrics"><div><label>دفعات فراخوانی</label><strong>${met.invocations ?? 0}</strong></div><div><label>میانگین اطمینان</label><strong>${pct(met.average_confidence || 0)}</strong></div></div></article>`;
    }).join('') || '<div class="panel empty-state">ایجنتی در دسترس نیست.</div>';
  } catch (e) { showError(e.message); }
}

function renderMcp() {
  if (!$('#mcpGrid')) return;
  const ext = S.health?.components?.external || {};
  const defs = [
    ['Zabbix MCP', 'zabbix_mcp', 'پایش هشدارها، مشکلات و اطلاعات میزبان', 'شواهد عملیاتی'],
    ['Elastic Agent Builder MCP', 'elasticsearch_mcp', 'لاگ‌ها و شواهد ES|QL تحت نظارت', 'شواهد عملیاتی'],
    ['Prometheus MCP', 'prometheus_mcp', 'متریک‌ها، سری‌های زمانی و شواهد هشدار', 'شواهد عملیاتی']
  ];
  if (Object.prototype.hasOwnProperty.call(ext, 'vm_mcp')) defs.push(['VM Edge MCP', 'vm_mcp', 'پایش ماشین مجازی و اصلاح کنترل‌شدهٔ سرویس', 'مرز اجرا']);
  if (Object.prototype.hasOwnProperty.call(ext, 'kubernetes_mcp')) defs.push(['Kubernetes MCP', 'kubernetes_mcp', 'مرز اختیاری عملیات کوبرنتیز', 'مرز اجرا']);
  if (Object.prototype.hasOwnProperty.call(ext, 'jenkins_mcp')) defs.push(['Jenkins MCP', 'jenkins_mcp', 'مرز اختیاری انتشار تحت نظارت', 'مرز اجرا']);
  if (Object.prototype.hasOwnProperty.call(ext, 'cognia')) defs.push(['Cognia Knowledge API', 'cognia', 'بررسی دسترسی HTTP از /swagger/index.html؛ پاسخ ۲۰۰ به معنی سلامت کامل یا مجوز پایگاه دانش نیست', 'مرز دانش']);
  $('#mcpGrid').innerHTML = defs.map(([name, key, desc, boundary]) => {
    const x = ext[key] || {};
    return `<article class="panel mcp-card"><div class="mcp-card-head"><div class="mcp-icon">◇</div>${pill(x.healthy ? 'healthy' : x.configured === false ? 'not_configured' : 'unavailable')}</div><span class="section-kicker">${esc(boundary)}</span><h3>${esc(name)}</h3><p>${esc(desc)}</p><div class="mcp-status"><span>${key === 'cognia' ? 'دسترسی HTTP · /swagger/index.html' : 'اتصال'}</span><strong>${x.healthy ? 'سالم' : 'در دسترس نیست'}</strong></div>${key === 'cognia' && Number.isInteger(x.http_status) ? `<div class="mcp-status"><span>پاسخ HTTP</span><strong>${x.http_status}</strong></div>` : ''}${x.error ? `<div class="dependency-error">${esc(x.error)}</div>` : ''}</article>`;
  }).join('');
}

function renderAudit() {
  if (!$('#auditList')) return;
  const a = S.summary?.recent_audit || [];
  $('#auditList').innerHTML = a.map(timelineItem).join('') || '<div class="empty-state">رویداد ممیزی ثبت نشده است.</div>';
}

let incidentQueueRefreshBusy = false;

// Poll only the small incident list while its view is visible. Never reload
// the document, drop filters, reset selected view or overlap requests.
async function refreshIncidentQueue() {
  if (incidentQueueRefreshBusy || document.hidden || S.view !== 'incidents' ||
      S.incidentPeriod === 'archived') return;
  incidentQueueRefreshBusy = true;
  const indicator = $('#incidentLiveSync');
  try {
    const response = await api('/api/v1/dashboard/incidents?limit=100');
    const next = response.items || [];
    if (JSON.stringify(next) !== JSON.stringify(S.incidents)) {
      S.incidents = next;
      renderIncidents();
    }
    if (indicator) indicator.textContent =
      'به‌روزرسانی خودکار · آخرین بررسی ' + new Date().toLocaleTimeString('fa-IR');
  } catch (_) {
    // Preserve last known data and clearly expose stale connectivity.
    if (indicator) indicator.textContent = 'به‌روزرسانی خودکار ناموفق؛ تلاش مجدد تا ۶ ثانیه دیگر';
  } finally {
    incidentQueueRefreshBusy = false;
  }
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
    // No implicit selection: operators explicitly open an Incident in its full-page workspace.
  } catch (e) {
    showError(`اتصال به داشبورد زنده برقرار نشد: ${e.message}`);
    $('#liveDot').classList.remove('ok');
    $('#platformState').textContent = 'در دسترس نیست';
  }
}

window.setIncidentPeriod = setIncidentPeriod;
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
  const requestedView = new URLSearchParams(window.location.search).get('view');
  if (['incidents', 'knowledge', 'audit', 'services'].includes(requestedView)) setView(requestedView);
  loadAll();
  setInterval(loadAll, 60000);
  setInterval(() => { void refreshIncidentQueue(); }, 6000);
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) void refreshIncidentQueue();
  });
});
