/* Read-only Incident Decision Brief; approval and execution remain in existing governed controls. */
(() => {
  const originalSelect = window.selectIncident;
  const originalRender = window.renderDetail;
  let activeId = null;
  let brief = null;
  let loading = false;
  let failed = null;
  let narrative = null;
  let narrativePendingKey = null;
  const narrativeCache = new Map();
  const storageKey = 'aiops.incident.decision_brief.language';
  let language = (() => {
    try { return localStorage.getItem(storageKey) === 'en' ? 'en' : 'fa'; }
    catch (_) { return 'fa'; }
  })();
  const dict = {
    fa: {
      tab:'گزارش تصمیم‌گیری', title:'گزارش تصمیم‌گیری Incident', lead:'خلاصه پیش از تأیید',
      loading:'در حال خواندن شواهد ثبت‌شده…', unavailable:'گزارش در دسترس نیست؛ Approval بدون بازبینی شواهد توصیه نمی‌شود.',
      unknown:'نامشخص', noData:'اطلاعات تأییدشده‌ای ثبت نشده است.', sources:'شواهد معتبر / MCP',
      agents:'عملکرد Agentها', knowledge:'دانش سازمانی Cognia', memory:'تجربه Incidentهای قبلی',
      risks:'شواهد ناقص یا متناقض', action:'چرا این اقدام پیشنهاد شده؟',
      before:'پیش از تأیید', execution:'اجرا و Verification', timeline:'خط زمانی',
      raw:'مشاهده شواهد خام', approval:'رفتن به پنل Approval', copy:'کپی گزارش',
      copyDone:'متن گزارش کپی شد.', readOnly:'این گزارش مجوز اجرا نیست؛ تأیید و Resume باید از مسیر امن موجود انجام شود.',
      source:'متن منبع (ممکن است انگلیسی باشد)', retrieved:'بازیابی شده', cited:'استفاده مستند در Agent',
      notVerified:'تأثیر در تصمیم نهایی تأیید نشده', review:'مشاهده پیش‌نویس بازبینی دانش',
      older:'شواهد قدیمی هستند؛ پیش از تأیید دوباره بررسی کنید.', missing:'بررسی شواهد بیشتری لازم است.',
      agreement:'موافقت Agentها', rca:'اطمینان RCA', evaluator:'اطمینان Evaluator',
      none:'هیچ موردی ثبت نشده', fresh:'تازه', stale:'قدیمی', status:'وضعیت',
      verified:'به‌صورت مستقل تأیید شود', explain:'بازیابی سابقه به‌تنهایی به معنی صحت RCA یا اجازه اجرا نیست.',
      fail:'ناموفق', pending:'در انتظار ارزیابی اپراتور', actionSeparate:'Approve به‌تنهایی اجرا نمی‌کند؛ پس از آن Resume با کنترل‌های مجدد انجام می‌شود.',
      timestamp:'به‌روزرسانی', record:'شناسه سند', tool:'ابزار', target:'هدف', environment:'محیط',
      risk:'ریسک', binding:'اتصال مجوز', freshness:'تازگی داده', verification:'نتیجه Verification', result:'نتیجه اجرا',
      narrative:'جمع‌بندی AIOps برای تصمیم‌گیری اپراتور', generated:'تحلیل فارسی مبتنی بر شواهد',
      narrativeFallback:'خلاصه ساختاریافته؛ تحلیل پیشرفته LLM در دسترس نیست.', citations:'استناد به شواهد',
      providerMissing:'این منبع در دسترس نبود؛ نتیجه‌گیری بدون داده‌های آن انجام شده است.', mixed:'ترکیبی از شواهد تازه و قدیمی/نامشخص'
    },
    en: {
      tab:'Decision Brief',title:'Incident Decision Brief',lead:'Operator decision summary',
      loading:'Reading durable incident records…',unavailable:'Brief unavailable. Review evidence before approving.',
      unknown:'Unknown',noData:'No verified information recorded.',sources:'MCP and infrastructure evidence',
      agents:'Agent findings',knowledge:'Cognia organizational knowledge',memory:'Historical Operational Memory',
      risks:'Missing or conflicting evidence',action:'Why was this action proposed?',
      before:'Before you approve',execution:'Execution and verification',timeline:'Detailed timeline',
      raw:'View raw evidence',approval:'Open Approval controls',copy:'Copy report',
      copyDone:'Report copied.',readOnly:'This brief does not authorize execution. Approval and resume use the existing governed workflow.',
      source:'Original source content',retrieved:'Retrieved',cited:'Cited by an agent',
      notVerified:'Impact on final decision not verified',review:'View Knowledge Review draft',
      older:'Evidence is stale; verify again before approval.',missing:'Further evidence review required.',
      agreement:'Agent agreement',rca:'RCA confidence',evaluator:'Evaluator confidence',
      none:'No records',fresh:'Fresh',stale:'Stale',status:'Status',
      verified:'Requires independent verification',explain:'Historical retrieval alone does not prove RCA or authorize execution.',
      fail:'Failed',pending:'Human review required',actionSeparate:'Approval does not execute an action. Resume performs separate authorization checks.',
      timestamp:'Generated',record:'Source ID',tool:'Tool',target:'Target',environment:'Environment',
      risk:'Risk',binding:'Approval binding',freshness:'Data freshness',verification:'Verification result',result:'Execution result',
      narrative:'AIOps operator decision summary', generated:'Grounded AI narrative',
      narrativeFallback:'Deterministic summary; enhanced LLM narrative unavailable.', citations:'Evidence references',
      providerMissing:'This monitoring source was unavailable; the assessment was made without its data.', mixed:'Mixed fresh, stale or unknown evidence'
    }
  };
  const t = key => dict[language][key] || key;
  const fieldFa = {
    'Incident ID':'شناسه رخداد', 'Port':'پورت', 'Started':'زمان شروع',
    'Likely cause':'وضعیت علت احتمالی', 'Action':'عملیات', 'Blast radius':'دامنه تأثیر',
    'Risk of inaction':'ریسک اقدام نکردن', 'Expected outcome':'نتیجه مورد انتظار',
    'Verification plan':'برنامه راستی‌آزمایی', 'Execution binding':'اتصال مجوز اجرا',
    'Evidence snapshot binding':'اتصال مجوز به نسخه شواهد',
    'Rollback supported':'امکان بازگشت', 'Timeout (s)':'مهلت اجرا (ثانیه)',
    'Timestamp basis':'مبنای زمان', 'Actor':'عامل', 'Event':'رویداد',
    'Outcome':'نتیجه', 'Memory ID':'شناسه حافظه', 'Relevance':'ارتباط',
    'Runbook':'راهنمای عملیاتی', 'Approval ID':'شناسه تأیید',
    'Snapshot':'نسخه گزارش', 'Evidence':'شواهد', 'Agent':'عامل تحلیل',
    'Incident confidence':'اطمینان رخداد', 'Target':'هدف', 'Status':'وضعیت',
    'Elapsed (seconds)':'مدت سپری‌شده (ثانیه)', 'Namespace':'فضای نام', 'Cluster':'کلاستر',
    'Host':'میزبان', 'Verified observations':'شواهد تازه و غیرخطا',
    'Monitoring sources':'منابع پایش', 'Cause':'علت احتمالی', 'Mission':'مأموریت',
    'Tools':'ابزارهای استفاده‌شده', 'Health':'سلامت', 'Trace ID':'شناسه ردگیری',
    'Phase':'مرحله جمع‌آوری', 'Similarity':'شباهت', 'Source status':'وضعیت منبع',
    'Cause certainty':'قطعیت علت', 'Evidence source':'منبع شواهد',
    'LLM status':'وضعیت تحلیل هوشمند', 'Approver':'تأییدکننده',
    'Verification confidence':'اطمینان راستی‌آزمایی', 'Memory outcome':'نتیجه تجربه',
    'Source type':'نوع داده', 'Document':'سند', 'Historical context':'زمینه تاریخی'
  };
  const statesFa = {
    available:'در دسترس', empty:'بدون نتیجه', failed:'ناموفق', error:'خطا',
    unavailable:'در دسترس نیست', not_queried:'جست‌وجو نشده', unknown:'نامشخص',
    not_verified:'تأیید نشده', cited_by_agent:'دارای استناد Agent',
    pending:'در انتظار تأیید', approved:'تأیید شده', rejected:'رد شده',
    consumed:'مصرف شده', success:'موفق', partial:'ناقص', stale:'قدیمی',
    fresh:'تازه', mixed:'ترکیبی', queried:'جست‌وجو شده', skipped:'اجرا نشده',
    not_pending:'در انتظار نیست', human_review_required:'نیازمند بررسی انسانی',
    observed:'مشاهده شده', not_executed:'اجرا نشده'
  };
  const fmt = value => {
    if (value == null || value === '') return t('unknown');
    if (typeof value === 'number') return new Intl.NumberFormat(language === 'fa' ? 'fa-IR' : 'en-US').format(value);
    const text = String(value);
    return language === 'fa' && Object.prototype.hasOwnProperty.call(statesFa, text) ? statesFa[text] : text;
  };
  const html = value => esc(fmt(value));
  const sClass = value => {
    const str = String(value || '').toLowerCase();
    if (['failed','stale','rejected','blocked','error','unavailable'].includes(str)) return 'failed';
    if (['success','fresh','approved','verified','cited_by_agent'].includes(str)) return 'success';
    return 'unknown';
  };
  const flag = value => '<span class="db-flag ' + sClass(value) + '">' + html(value) + '</span>';
  const field = (name, value) => '<div class="db-field"><span>' + esc(language === 'fa' ? fieldFa[name] || name : name) + '</span><strong>' + html(value) + '</strong></div>';
  const linkRefs = refs => (refs || []).length
    ? '<div class="db-refs">' + refs.map(r => '<code>' + html(r) + '</code>').join('') + '</div>'
    : '';
  const originalText = value => value
    ? '<p class="db-source" dir="auto"><span>' + t('source') + ':</span> ' + html(value) + '</p>'
    : '<p class="db-subtle">' + t('noData') + '</p>';
  const list = items => (items || []).length
    ? '<ul class="db-list">' + items.map(item => '<li>' + html(item) + '</li>').join('') + '</ul>'
    : '<p class="db-subtle">' + t('none') + '</p>';
  const section = (key, content, opened = false) =>
    '<details class="db-section"' + (opened ? ' open' : '') + '><summary>' + t(key) + '</summary><div class="db-section-body">' + content + '</div></details>';
  const confidence = score => score == null ? t('unknown') : new Intl.NumberFormat(language === 'fa' ? 'fa-IR' : 'en-US').format(Math.round(Number(score) * 100)) + (language === 'fa' ? '٪' : '%');

  function body(b) {
    const i = b.incident_summary || {};
    const a = b.approval_readiness || {};
    const r = b.remediation_recommendation || {};
    const c = b.cognia_knowledge || {};
    const m = b.operational_memory || {};
    const outcome = b.execution_outcome || {};
    const verify = b.verification_result || {};
    const learning = b.knowledge_learning_status || {};
    const deterministicNarrative = b.localized_narrative || {};
    const agents = b.agent_findings || [];
    const mcp = b.mcp_evidence || [];
    const resources = b.monitoring_sources || [];
    const timeline = b.timeline || [];
    const matchedNarrative = narrative && narrative.snapshot_id === b.snapshot_id && narrative.language === language ? narrative : null;
    const narrativeRows = matchedNarrative?.status === 'available' ? (matchedNarrative.sections || []) : [];
    const narrativeSection = narrativeRows.length
      ? '<div class="db-narrative">' + narrativeRows.map(x => '<article class="db-narrative-part"><h4>' + html(x.heading) + '</h4><p>' + html(x.text) + '</p>' + linkRefs(x.citations) + '</article>').join('') + '</div>'
      : '<p class="db-subtle">' + (narrativePendingKey === (activeId + ':' + b.snapshot_id + ':' + language) ? t('loading') : t('narrativeFallback')) + '</p>';
    const direction = language === 'fa' ? 'rtl' : 'ltr';
    const agentCards = agents.map(x => '<div class="db-record"><div class="db-record-head"><b>' +
      html(x.agent) + '</b>' + flag(x.status) + '</div>' + originalText(x.finding) +
      field('Mission', x.mission) + field('Tools', (x.tools || []).join('، ')) +
      field('Health', x.health_status) + field('Trace ID', x.trace_id) +
      field(t('rca'), confidence(x.confidence)) + linkRefs(x.evidence_refs) +
      list(x.missing_evidence) + (x.conflicting_evidence_refs?.length ? linkRefs(x.conflicting_evidence_refs) : '') +
      '</div>').join('') || '<p class="db-subtle">' + t('none') + '</p>';
    const incidentObserved = i.observed_service_state || {};
    const observedCards = Object.entries(incidentObserved).map(([name, obj]) => {
      if (!obj || typeof obj !== 'object') return '';
      const facts = Object.entries(obj).filter(([, value]) => value != null &&
        ['string', 'number', 'boolean'].includes(typeof value)).slice(0, 10);
      return '<div class="db-record"><b>' + html(name) + '</b><div class="db-fields">' +
        facts.map(([key, value]) => field(key, value)).join('') + '</div></div>';
    }).join('');
    const mcpCards = mcp.map(x => '<div class="db-record"><div class="db-record-head"><b>' +
      html(x.server) + ' / ' + html(x.tool) + '</b>' + flag(x.status) + '</div>' +
      field(t('timestamp'), x.collected_at) + field(t('freshness'), x.freshness) + field('Timestamp basis', x.time_basis) + field('Phase', x.phase) +
      originalText(x.finding) + linkRefs(x.evidence_ref ? [x.evidence_ref] : []) + '</div>').join('');
    const healthCards = resources.map(x => '<div class="db-record"><div class="db-record-head"><b>' + html(x.source) + '</b>' + flag(x.status) + '</div>' + field(t('freshness'), x.freshness) + (['unavailable','error'].includes(x.status) ? '<p class="db-warning">' + t('providerMissing') + '</p>' : '') + '</div>').join('');
    const knowledgeCards = (c.items || []).map(x => '<div class="db-record"><div class="db-record-head"><b>' +
      html(x.title || x.source_id) + '</b>' + flag(x.use_status) + '</div>' +
      field(t('record'), [x.knowledge_base_id,x.knowledge_id,x.revision_id].filter(Boolean).join(' / ')) +
      field('Relevance', confidence(x.relevance)) + field('Document', x.source_id) + originalText(x.excerpt) + '</div>').join('');
    const memoryCards = (m.items || []).map(x => '<div class="db-record"><div class="db-record-head"><b>' +
      html(x.memory_id) + '</b>' + flag(x.use_status) + '</div>' +
      field('Incident ID', x.previous_incident_id) + field(t('verification'), x.verification) +
      field('Outcome', x.outcome) + field('Similarity', confidence(x.similarity)) +
      field('Cause certainty', x.root_cause_status) + originalText(x.root_cause) + originalText(x.action) + '</div>').join('');
    const conf = b.rca_assessment || {};
    const warnings = [];
    if (b.data_freshness === 'stale') warnings.push(t('older'));
    if (b.data_freshness === 'mixed') warnings.push(t('mixed'));
    if (resources.some(x => ['unavailable','error'].includes(x.status))) warnings.push(t('providerMissing'));
    if (b.data_freshness === 'unknown') warnings.push(t('missing'));
    if ((b.missing_evidence || []).length || (b.evidence_conflicts || []).length) warnings.push(t('missing'));
    if (c.retrieved_count && c.use_status !== 'cited_by_agent') warnings.push(t('notVerified'));
    const summary = '<header class="db-header"><div><span class="db-kicker">' + t('lead') +
      '</span><h3>' + t('title') + '</h3><p>' + html(i.service) + ' · ' + html(i.severity) +
      ' · ' + html(i.status) + '</p></div><div class="db-tools">' +
      '<button type="button" data-db-lang="fa" aria-pressed="' + (language === 'fa') + '">فارسی</button>' +
      '<button type="button" data-db-lang="en" aria-pressed="' + (language === 'en') + '">English</button>' +
      '<button type="button" data-db-copy="1">' + t('copy') + '</button></div></header>' +
      '<p class="db-lead">' + html(language === 'fa' ? deterministicNarrative.fa : deterministicNarrative.en) + '</p>' +
      '<div class="db-fields">' + field('Incident ID', i.incident_id) +
      field(t('freshness'), b.data_freshness) + field(t('risk'), r.risk_level) +
      field('Approval', a.approval_status) + field('Evidence', b.source_references?.length ?? 0) +
      field(t('timestamp'), b.generated_at) +
      field(t('target'), i.target) + field('Port', i.port) +
      field('Started', i.started_at) + field('Elapsed (seconds)', i.elapsed_seconds) +
      field('Host', i.host) + field('Namespace', i.namespace) + field('Cluster', i.cluster) +
      field('Verified observations', i.valid_evidence_count) +
      field('Monitoring sources', i.observed_sources) +
      field('Cause', i.likely_cause) + field('Likely cause', i.cause_status) + '</div>' +
      (warnings.length ? '<div class="db-warning">' + list([...new Set(warnings)]) + '</div>' : '') +
      '<p class="db-notice">' + t('readOnly') + '</p>';
    const agentsSection = '<div class="db-fields">' + field(t('rca'), confidence(conf.rca_confidence)) +
      field(t('evaluator'), confidence(conf.evaluator_confidence)) +
      field(t('agreement'), confidence(conf.agent_agreement)) + '</div>' +
      '<p class="db-notice">' + (language === 'fa' ?
        'اطمینان RCA احتمال درستی علت است؛ اطمینان Evaluator ارزیابی برنامه پیشنهادی است؛ توافق Agentها میزان هم‌نظر بودن تحلیل‌گران است. این سه معیار یکسان نیستند.' :
        'RCA confidence assesses the suspected cause; evaluator confidence assesses the plan; agreement measures cross-agent consensus. These are different signals.') +
      '</p>' + agentCards;
    const sourcesSection = '<div class="db-fields">' + healthCards + '</div>' +
      observedCards + (mcpCards || '<p class="db-subtle">' + t('noData') + '</p>');
    const cSection = field(t('status'), c.status) + field(t('retrieved'), c.retrieved_count) +
      '<p class="db-notice">' + t('explain') + '</p>' +
      (knowledgeCards || '<p class="db-subtle">' + t('none') + '</p>');
    const memorySection = '<p class="db-notice">' + t('explain') + '</p>' +
      (memoryCards || '<p class="db-subtle">' + t('none') + '</p>');
    const gapsSection = '<h4>' + (language === 'fa' ? 'شواهد ناقص' : 'Missing evidence') +
      '</h4>' + list(b.missing_evidence) + '<h4>' +
      (language === 'fa' ? 'ارجاعات متناقض' : 'Conflicting evidence refs') +
      '</h4>' + list(b.evidence_conflicts);
    const actionSection = '<div class="db-fields">' + field(t('tool'), r.tool) +
      field(t('target'), r.target) + field('Action', r.action) +
      field(t('risk'), r.risk_level) + field('Blast radius', r.blast_radius) +
      field('Risk of inaction', r.risk_of_inaction) +
      field('Expected outcome', r.expected_outcome) +
      field('Verification plan', r.verification_plan) + '</div><p class="db-notice">' +
      (language === 'fa' ? 'پیشنهاد فقط از Action Plan ذخیره‌شده خوانده شده است؛ ارتباط علّی بدون Citation قطعی نیست.' :
       'Proposal comes from the recorded action plan. Causal support is not assumed without citations.') +
      '</p>' + linkRefs(i.cause_evidence_refs);
    const beforeSection = '<div class="db-fields">' +
      field('Approval ID', a.approval_id) + field(t('binding'), a.binding_complete ? 'Complete' : 'Not verified') +
      field(t('tool'), a.tool) + field(t('target'), a.target) +
      field(t('environment'), a.environment) + field('Runbook', [a.runbook_id,a.runbook_version].filter(Boolean).join(' @ ')) +
      field(t('freshness'), a.data_freshness) +
      field('Execution binding', a.binding_digest ? 'Recorded' : 'Not verified') +
      field('Evidence snapshot binding', a.evidence_snapshot_binding) +
      field('Rollback supported', a.rollback_supported ? 'Recorded' : 'Not verified') +
      field('Timeout (s)', a.timeout_seconds) + field('Approver', a.approver) + '</div>' +
      '<p class="db-warning">' + t('actionSeparate') + '</p>' +
      '<div class="db-buttons"><button type="button" data-db-nav="decision">' + t('approval') + '</button>' +
      '<button type="button" data-db-nav="evidence">' + t('raw') + '</button>' +
      '<button type="button" data-db-nav="audit">' + t('timeline') + '</button></div>';
    const timelineSection = timeline.length ? timeline.map(x =>
      '<div class="db-record">' + field('Event', x.event) + field(t('status'), x.status) +
      field('Actor', x.actor) + field(t('timestamp'), x.timestamp) + '</div>'
    ).join('') : '<p class="db-subtle">' + t('noData') + '</p>';
    const postSection = '<div class="db-fields">' + field(t('result'), outcome.status) +
      field(t('tool'), outcome.tool) + field(t('target'), outcome.target) +
      field(t('verification'), verify.status) +
      field('Memory ID', learning.memory_id) +
      field('Approver', a.approver) + field('Verification confidence', confidence(verify.confidence)) +
      field('Approval ID', outcome.approval_id) + '</div>' +
      originalText(outcome.error || outcome.details) + originalText(verify.message) +
      list(verify.changes) +
      linkRefs(verify.evidence_refs) + (learning.review_available ? '<button type="button" data-db-knowledge="' +
      html(learning.review_id) + '">' + t('review') + '</button>' : '');
    return '<div class="decision-brief" dir="' + direction + '" lang="' + language + '" data-snapshot="' +
      html(b.snapshot_id) + '">' + summary +
      section('narrative', narrativeSection, true) +
      section('agents', agentsSection, true) + section('sources', sourcesSection, true) +
      section('knowledge', cSection) + section('memory', memorySection) +
      section('risks', gapsSection, (b.missing_evidence || []).length > 0) +
      section('action', actionSection, true) + section('before', beforeSection, true) +
      section('execution', postSection) + section('timeline', timelineSection) + '</div>';
  }

  async function ensureNarrative() {
    if (!brief || String(S.selected) !== String(activeId)) return;
    const snapshot = brief.snapshot_id;
    const currentLang = language;
    const requestedId = String(activeId);
    const key = snapshot + ':' + currentLang;
    const requestKey = requestedId + ':' + key;
    if (narrativePendingKey === requestKey) return;
    if (narrativeCache.has(key)) {
      narrative = narrativeCache.get(key);
      return;
    }
    narrativePendingKey = requestKey;
    try {
      const result = await api('/api/v1/incidents/' + encodeURIComponent(requestedId) + '/decision-brief/narrative?lang=' + encodeURIComponent(currentLang));
      if (result?.snapshot_id !== snapshot || result?.language !== currentLang) throw new Error('narrative_snapshot_mismatch');
      narrativeCache.set(key, result);
      if (String(S.selected) === requestedId && brief?.snapshot_id === snapshot && language === currentLang) narrative = result;
    } catch (_) {
      // A missing model or transient connectivity never disables durable Incident evidence.
      const fallback = {snapshot_id: snapshot, language: currentLang, status: 'fallback', sections: []};
      narrativeCache.set(key, fallback);
      if (String(S.selected) === requestedId && brief?.snapshot_id === snapshot && language === currentLang) narrative = fallback;
    } finally {
      if (narrativePendingKey === requestKey) narrativePendingKey = null;
      if (S.detail && String(S.selected) === requestedId && brief?.snapshot_id === snapshot && document.querySelector('.decision-brief')) {
        window.renderDetail('brief');
      }
    }
  }

  function paint(tab = 'overview') {
    const tabs = document.querySelector('#detail .tabs');
    if (!tabs) return;
    if (!tabs.querySelector('[data-db-tab]')) {
      const button = document.createElement('button');
      button.type = 'button';
      button.setAttribute('data-db-tab', '1');
      button.textContent = t('tab');
      button.addEventListener('click', () => window.renderDetail('brief'));
      tabs.insertBefore(button, tabs.firstChild);
    }
    const button = tabs.querySelector('[data-db-tab]');
    button.textContent = t('tab');
    button.classList.toggle('active', tab === 'brief');
    if (tab !== 'brief') return;
    const pane = document.querySelector('#detailPane');
    if (!pane) return;
    pane.innerHTML = loading ? '<div class="db-placeholder">' + t('loading') + '</div>' :
      failed ? '<div class="db-placeholder db-error">' + t('unavailable') + ' ' + html(failed) + '</div>' :
      brief ? body(brief) : '<div class="db-placeholder">' + t('noData') + '</div>';
    if (brief && !narrativeCache.has(brief.snapshot_id + ':' + language)) void ensureNarrative();
  }

  window.selectIncident = selectIncident = async function selectWithDecisionBrief(id) {
    activeId = String(id);
    brief = null;
    narrative = null;
    narrativePendingKey = null;
    failed = null;
    loading = true;
    const request = api('/api/v1/incidents/' + encodeURIComponent(id) + '/decision-brief')
      .then(data => ({data})).catch(error => ({error: error.message}));
    await originalSelect(id);
    if (String(S.selected) !== String(id) || activeId !== String(id)) return;
    const response = await request;
    if (String(S.selected) !== String(id) || activeId !== String(id)) return;
    brief = response.data || null;
    failed = response.error || null;
    loading = false;
    const status = String(S.detail?.lifecycle?.approval?.status || '').toLowerCase();
    window.renderDetail(status === 'pending' ? 'brief' : 'overview');
  };
  window.renderDetail = renderDetail = function renderWithDecisionBrief(tab = 'overview') {
    originalRender(tab);
    paint(tab);
  };

  document.addEventListener('click', async event => {
    const lang = event.target.closest('[data-db-lang]');
    if (lang) {
      language = lang.getAttribute('data-db-lang') === 'en' ? 'en' : 'fa';
      try { localStorage.setItem(storageKey, language); } catch (_) {}
      narrative = narrativeCache.get(brief?.snapshot_id + ':' + language) || null;
      window.renderDetail('brief');
      return;
    }
    const copy = event.target.closest('[data-db-copy]');
    if (copy && brief) {
      const intro = (language === 'fa' ? brief.localized_narrative?.fa : brief.localized_narrative?.en) || '';
      const detailed = narrative?.snapshot_id === brief.snapshot_id && narrative?.language === language &&
        narrative?.status === 'available' ? (narrative.sections || []).map(x =>
          x.heading + '\n' + x.text + '\n' + (x.citations || []).join(', ')
        ).join('\n\n') : '';
      const report = [intro, detailed,
        'Incident ID: ' + brief.incident_summary.incident_id,
        'Snapshot: ' + brief.snapshot_id,
        'Action: ' + (brief.remediation_recommendation?.action || 'Unknown'),
        'Target: ' + (brief.remediation_recommendation?.target || 'Unknown'),
        'Evidence: ' + (brief.source_references || []).join(', '),
      ].filter(Boolean).join('\n\n');
      try { await navigator.clipboard.writeText(report); toast(t('copyDone')); }
      catch (_) { toast(t('unavailable')); }
      return;
    }
    const nav = event.target.closest('[data-db-nav]');
    if (nav) { window.renderDetail(nav.getAttribute('data-db-nav')); return; }
    const knowledge = event.target.closest('[data-db-knowledge]');
    if (knowledge && typeof setView === 'function') {
      setView('knowledge');
      if (typeof window.loadKnowledgeReviews === 'function') window.loadKnowledgeReviews(knowledge.getAttribute('data-db-knowledge'));
    }
  });
})();
