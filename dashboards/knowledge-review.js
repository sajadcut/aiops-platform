/* Human Knowledge Review UI. All writes are enforced by server-side RBAC/DB gates. */
(() => {
  'use strict';
  let reviews = [];
  let selectedId = null;
  let selectedDetails = null;
  let loading = false;
  let actionPending = false;
  let showAllSimilarReviews = false;
  let recoveryReconciled = false;
  let incidentReconciled = false;
  let incidentSyncOffset = 0;
  let incidentSyncHasMore = true;
  let reviewPageCount = 1;
  let reviewHasMore = false;
  let reviewTotal = 0;
  let reviewSort = 'created_desc';
  let reviewStatus = '';
  let reviewPeriod = '';
  let reviewQuery = '';
  let queryTimer = null;
  let reloadRequested = false;
  const dateFormatter = new Intl.DateTimeFormat('fa-IR-u-ca-persian', {
    year:'numeric', month:'2-digit', day:'2-digit',
    hour:'2-digit', minute:'2-digit', hourCycle:'h23'
  });

  function timeLabel(value) {
    if (!value) return '—';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '—' : dateFormatter.format(date);
  }
  function displayTime(value) {
    return '<time datetime="'+esc(value || '')+'" title="'+esc(value || '')+'">'+
      esc(timeLabel(value))+'</time>';
  }

  let monitorLoading = false;
  let monitorData = null;
  let monitorHealth = null;
  const monitorLabels = {
    pending_review:'در انتظار بازبینی', approved:'تأییدشده، ارسال‌نشده',
    publishing:'در حال ارسال', submitted:'ارسال‌شده، در انتظار فعال‌سازی',
    published:'انتشار تأییدشده', publish_failed:'انتشار ناموفق',
    rejected:'ردشده'
  };
  const monitorNumber = value => value === null || value === undefined ? '—' :
    Number(value).toLocaleString('fa-IR');
  const monitorPercent = value => value === null || value === undefined ?
    '—' : Number(value).toLocaleString('fa-IR', {maximumFractionDigits:1})+'٪';

  function monitorFact(label, value) {
    return '<div class="knowledge-monitor-fact"><span>'+esc(label)+'</span><strong>'+
      esc(monitorNumber(value))+'</strong></div>';
  }

  function renderKnowledgeMonitor() {
    if (!monitorData) return;
    const r = monitorData.reviews || {};
    const counts = r.by_status || {};
    const rag = monitorData.retrieval || {};
    const coverage = monitorData.coverage || {};
    const total = Number(r.total || 0);
    const kpis = [
      ['سوابق ثبت‌شدهٔ AIOps', total, 'همه وضعیت‌ها · سوابق محلی'],
      ['در انتظار بازبینی', counts.pending_review, 'هنوز برای انتشار تأیید نشده', counts.pending_review ? 'warning' : ''],
      ['در انتظار ارسال', counts.approved, 'نسخهٔ تأییدشده در صف ارسال'],
      ['فعال‌شده در Cognia', counts.published, 'فعال‌سازی نسخه تأیید شده', 'success'],
      ['ارسال‌شده، در انتظار فعال‌سازی', counts.submitted, 'ثبت در Cognia ≠ قابل جست‌وجو', counts.submitted ? 'warning' : ''],
      ['انتشار ناموفق', counts.publish_failed, 'نیازمند بررسی و تلاش مجدد', counts.publish_failed ? 'danger' : ''],
      ['پیش‌نویس‌های بازه', r.created_in_period, 'در '+monitorNumber(monitorData.period_days)+' روز اخیر'],
      ['پوشش رخدادهای ماندگار', monitorPercent(coverage.percentage),
       monitorNumber(coverage.incidents_with_review)+' رخداد از '+monitorNumber(coverage.durable_incidents)]
    ];
    const grid = el('knowledgeMonitorKpis');
    if (grid) grid.innerHTML = kpis.map(([title, value, hint, tone]) =>
      '<article class="knowledge-monitor-kpi" data-tone="'+esc(tone||'')+'"><span>'+
      esc(title)+'</span><strong>'+esc(typeof value==='string'?value:monitorNumber(value))+
      '</strong><small>'+esc(hint)+'</small></article>').join('');

    const stages = [
      ['pending_review','km-pending'],['approved','km-approved'],
      ['publishing','km-submitted'],['submitted','km-submitted'],
      ['published','km-published'],['publish_failed','km-failed'],
      ['rejected','km-other']
    ];
    const lifecycle = el('knowledgeMonitorLifecycle');
    if (lifecycle) {
      const segments = stages.map(([status, css]) => {
        const value = Number(counts[status] || 0);
        return value > 0 && total > 0 ?
          '<span class="'+css+'" style="width:'+(value/total*100).toFixed(2)+'%" title="'+
          esc(monitorLabels[status])+': '+monitorNumber(value)+'"></span>' : '';
      }).join('');
      lifecycle.innerHTML =
        '<div class="knowledge-monitor-meter" aria-label="توزیع وضعیت سوابق">'+segments+'</div>'+
        '<div class="knowledge-monitor-facts">'+stages.map(([status])=>
          monitorFact(monitorLabels[status],counts[status])).join('')+
          monitorFact('منتشرشده در بازه',r.published_in_period)+
          monitorFact('انتظار بازبینی بیش از ۲۴ ساعت',r.review_overdue_24h)+
          monitorFact('ارسال متوقف بیش از ۳ دقیقه',r.publication_stalled_3m)+
          monitorFact('فعال‌سازی معطل بیش از ۲۴ ساعت',r.activation_overdue_24h)+
        '</div>'+
        '<p class="knowledge-monitor-hint">آخرین انتشار تأییدشده: '+
          esc(timeLabel(r.latest_published_at))+' · داده‌ها فقط متعلق به سوابق ارسال‌شده توسط AIOps هستند.</p>';
    }

    const timeline = r.daily_last_14_days || [];
    const highest = Math.max(1, ...timeline.flatMap(x => [Number(x.drafted||0), Number(x.published||0)]));
    const trend = el('knowledgeMonitorTrend');
    if (trend) trend.innerHTML =
      '<div class="knowledge-monitor-trend" role="img" aria-label="روند روزانهٔ ثبت و انتشار ۱۴ روز اخیر">'+
      timeline.map(x => {
        const label = String(x.day || '').slice(-2);
        const draft = Math.max(2, Math.round(100*Number(x.drafted||0)/highest));
        const published = Math.max(2, Math.round(100*Number(x.published||0)/highest));
        return '<div class="knowledge-monitor-day" title="'+esc(x.day)+
          ' · ثبت '+monitorNumber(x.drafted)+' · انتشار '+monitorNumber(x.published)+'">'+
          '<div class="km-bars"><i style="height:'+draft+'%" aria-hidden="true"></i>'+
          '<i style="height:'+published+'%" aria-hidden="true"></i></div>'+
          '<small>'+esc(label)+'</small></div>';
      }).join('')+'</div><div class="knowledge-monitor-legend">'+
      '<span><b></b>ثبت پیش‌نویس</span><span><b class="km-legend-green"></b>فعال‌سازی تأییدشده</span>'+
      '</div><p class="knowledge-monitor-hint">نمودار بر مبنای تاریخ UTC است؛ ارتفاع ۲ پیکسلی یعنی صفر، نه مقدار واقعی.</p>';

    const rStatus = rag.by_status || {};
    const good = Number(rStatus.available || 0), empty = Number(rStatus.empty || 0),
      filtered = Number(rStatus.filtered_empty || 0);
    const errors = Math.max(0, Number(rag.observed_calls || 0) - good - empty - filtered);
    const retrieval = el('knowledgeMonitorRetrieval');
    if (retrieval) retrieval.innerHTML = '<div class="knowledge-monitor-facts">'+
      monitorFact('جست‌وجوهای ثبت‌شده در این بازه', rag.observed_calls)+
      monitorFact('پاسخ حاوی دانش مرتبط',good)+
      monitorFact('نتیجهٔ خالی',empty)+
      monitorFact('نتیجهٔ نامرتبط و حذف‌شده',filtered)+
      monitorFact('خطا یا وضعیت‌های دیگر',errors)+
      monitorFact('تعداد قطعه‌های پذیرفته‌شده',rag.returned_items_total)+
      '</div><p class="knowledge-monitor-hint">فقط جست‌وجوهای ثبت‌شده در رویداد context_loaded؛ شامل همهٔ فراخوانی‌های چت‌بات و سرویس‌های دیگر نیست. آخرین ثبت: '+
      esc(timeLabel(rag.last_observed_at))+'</p>'+
      '<p class="knowledge-monitor-hint">P95 تأخیر، ارتباط معنایی، صحت استناد و Groundedness: <strong>اندازه‌گیری نشده</strong>. بدون Trace و ارزیابی مستقل، عددی برای کیفیت تولید نمی‌شود.</p>';

    renderKnowledgeCognia();
    const state = el('knowledgeMonitorState');
    if (state) {
      state.dataset.error = 'false';
      state.textContent = 'آمار ماندگار تا '+timeLabel(monitorData.sampled_at)+
        ' · '+monitorNumber(monitorData.period_days)+' روز برای روندهای بازه‌ای · کل سوابق محلی بدون فیلتر';
    }
  }

  function renderKnowledgeCognia() {
    const box = el('knowledgeMonitorCognia');
    if (!box || !monitorData) return;
    const cognia = monitorData.cognia || {};
    const h = monitorHealth;
    const status = !h ? 'نامشخص' : h.configured === false ? 'پیکربندی نشده' :
      h.healthy ? 'پاسخ HTTP موفق' : 'عدم دسترسی HTTP';
    const tone = !h ? 'unknown' : h.healthy ? 'ok' : 'bad';
    const statusCode = h?.http_status;
    const kbIds = (cognia.configured_kb_ids || []).map(String).join('، ') || '—';
    box.innerHTML =
      '<div class="knowledge-monitor-connection"><span class="knowledge-monitor-dot" data-status="'+
        tone+'"></span><strong>'+esc(status)+'</strong><span class="muted">'+
        esc(cognia.health_probe || '/swagger/index.html')+
        (Number.isInteger(statusCode) ? ' · HTTP '+esc(statusCode) : '')+'</span></div>'+
      '<div class="knowledge-monitor-facts">'+
      '<div class="knowledge-monitor-fact"><span>شناسهٔ پایگاه‌های دانش تنظیم‌شده</span><strong>'+
        esc(kbIds)+'</strong></div>'+
      '<div class="knowledge-monitor-fact"><span>کل اسناد Cognia (سراسری)</span><strong>نامشخص</strong></div>'+
      '</div>'+
      '<p class="knowledge-monitor-hint">بررسی Swagger فقط دسترسی HTTP را نشان می‌دهد، نه آمادگی موتور جست‌وجو یا مجوز KB. کل اسناد داخل Cognia از این API قابل شمارش نیست؛ عدد فعال‌شدهٔ بالا فقط متعلق به انتشارهای تأییدشدهٔ AIOps است.</p>';
  }

  let monitorReloadRequested = false;
  async function loadKnowledgeMonitoring() {
    if (monitorLoading) { monitorReloadRequested = true; return; }
    if (!el('knowledgeMonitorKpis')) return;
    monitorLoading = true;
    const days = Number(el('knowledgeMonitorPeriod')?.value || 30);
    const state = el('knowledgeMonitorState');
    if (state) { state.textContent = 'در حال بازخوانی شاخص‌های پایگاه دانش…'; state.dataset.error='false'; }
    try {
      monitorData = await api('/api/v1/knowledge-reviews/monitoring?days='+encodeURIComponent(days));
      renderKnowledgeMonitor();
    } catch (err) {
      monitorData = null;
      if (state) {
        state.dataset.error='true';
        state.textContent = 'داده‌های مانیتورینگ قابل دریافت نیستند: '+err.message;
      }
      for (const id of ['knowledgeMonitorKpis','knowledgeMonitorLifecycle',
                        'knowledgeMonitorTrend','knowledgeMonitorRetrieval','knowledgeMonitorCognia']) {
        if (el(id)) el(id).textContent = '';
      }
    } finally {
      monitorLoading = false;
      if (monitorReloadRequested) {
        monitorReloadRequested = false;
        void loadKnowledgeMonitoring();
        return;
      }
    }
    // Health is separate from the local outbox report. A slow/down external
    // dependency must not hide durable review counts or be treated as healthy.
    try {
      const status = await api('/api/v1/health');
      monitorHealth = status?.components?.external?.cognia || null;
    } catch (_) {
      monitorHealth = null;
    }
    renderKnowledgeCognia();
  }

  const el = id => document.getElementById(id);
  const current = () => selectedDetails && selectedDetails.id === selectedId ? selectedDetails : null;
  const pendingStatuses = new Set(['pending_review', 'approved', 'publish_failed', 'submitted', 'publishing']);

  function notice(message) {
    if (typeof toast === 'function') toast(message);
    else if (typeof showError === 'function') showError(message);
  }

  function renderQueue() {
    const list = el('knowledgeReviewQueue');
    if (!list) return;
    el('knowledgePendingCount').textContent = String(reviewTotal);
    const summary = el('knowledgeQueueSummary');
    if (summary) summary.textContent = 'نمایش '+reviews.length+' مورد از '+reviewTotal+
      ' نتیجه · تاریخ و ساعت به وقت محلی مرورگر · انتشار فقط با تأیید انسانی';
    const more = el('knowledgeLoadMore');
    if (more) more.hidden = !reviewHasMore;
    const syncButton = el('knowledgeSyncMoreIncidents');
    if (syncButton) syncButton.hidden = !incidentSyncHasMore;
    const status = el('knowledgeSyncCoverageStatus');
    if (status) status.textContent = incidentSyncHasMore ?
      'همگام‌سازی رخدادهای قدیمی‌تر هنوز کامل نیست؛ برای ادامه از دکمهٔ پایین استفاده کنید.' :
      'همگام‌سازی تاریخچهٔ رخدادها تکمیل شده است.';
    // Group identical *display* titles for one incident. No row is deleted,
    // merged, silently published, or overwritten; expand to inspect every
    // historically distinct version/evidence reference.
    const key = r => [r.incident_id || '', r.source_type || '',
                       r.status || '', r.title || ''].join('\u241f');
    const totals = new Map();
    for (const item of reviews) totals.set(key(item), (totals.get(key(item)) || 0) + 1);
    const seen = new Set();
    const visible = showAllSimilarReviews ? reviews : reviews.filter(item => {
      const group = key(item);
      if (item.id === selectedId) return true;
      if (seen.has(group)) return false;
      seen.add(group);
      return true;
    });
    const hidden = reviews.length - visible.length;
    const toggle = totals.size < reviews.length ?
      '<button type="button" class="knowledge-queue-toggle" data-knowledge-show-similar="1">'+
      esc(showAllSimilarReviews ? 'جمع‌کردن عنوان‌های تکراری' :
          'نمایش همهٔ پیش‌نویس‌ها (شامل موارد مشابه)')+'</button>':'';
    list.innerHTML = toggle + visible.map(r => {
      const copies = totals.get(key(r)) || 0;
      const repeated = copies > 1 && !showAllSimilarReviews ?
        ' · '+esc(copies)+' پیش‌نویس با همین عنوان':'';
      return '<button type="button" class="knowledge-queue-item '+
        (r.id === selectedId?'selected':'')+
        '" data-knowledge-select="'+esc(r.id)+'" aria-pressed="'+(r.id===selectedId)+'">'+
        '<span class="knowledge-queue-title">'+esc(r.title)+'</span>'+
        '<span class="knowledge-queue-metadata">'+pill(r.status)+
        '<span>'+esc(r.source_type)+' · KB #'+esc(r.kb_id)+repeated+'</span></span>'+
        '<span class="knowledge-queue-metadata"><span>ثبت:</span>'+displayTime(r.created_at)+
        '<span>آخرین تغییر:</span>'+displayTime(r.updated_at)+'</span></button>';
    }).join('') || '<div class="empty-state">هنوز موردی برای بازبینی دانش ثبت نشده است.</div>';
  }

  function renderSelection() {
    const r = current();
    const box = el('knowledgeReviewDetails');
    if (!box) return;
    el('knowledgeReviewHeading').textContent = r ? r.title : 'یک مورد را انتخاب کنید';
    el('knowledgeReviewStatus').textContent = r ? faStatus(r.status) : 'موردی انتخاب نشده';
    if (!r) {
      box.innerHTML = '<div class="empty-state">یک پیش‌نویس از صف انتخاب کنید.</div>';
      return;
    }
    const editable = ['pending_review', 'rejected', 'approved'].includes(r.status);
    const reviewable = r.status === 'pending_review';
    const publishable = ['approved', 'publish_failed'].includes(r.status);
    const canRefresh = ['submitted', 'published'].includes(r.status);
    const coverageDraft = r.created_by === 'system:incident-coverage';
    const canRefreshEvidence = r.status==='pending_review' &&
      String(r.created_by||'').startsWith('system:') && !r.reviewed_by &&
      (coverageDraft ? r.review_reason==='incident_coverage:v1' :
        r.revision===1 && !!r.incident_dossier?.config_diagnostic &&
        !r.content.includes('شواهد فنی مرتبط با کانفیگ'));
    box.innerHTML = `
      <div class="knowledge-facts">
        <div><label>منبع</label><strong>${esc(r.source_type === 'incident' ? 'رخداد بازیابی‌شده و تأییدشده' : coverageDraft ? 'گزارش رخداد (نیازمند تصمیم ذخیره یا رد)' : r.source_type === 'incident_followup' ? 'بررسی تکمیلی رخداد (نیازمند بازبینی)' : 'دانش دستی')}</strong></div>
        <div><label>مقصد</label><strong>Cognia KB #${esc(r.kb_id)}</strong></div>
        <div><label>نسخه</label><strong>${esc(r.revision)}</strong></div>
        <div><label>تاریخ و ساعت ثبت</label><strong>${displayTime(r.created_at)}</strong></div>
        <div><label>آخرین به‌روزرسانی</label><strong>${displayTime(r.updated_at)}</strong></div>
        <div><label>بازبین</label><strong>${esc(r.reviewed_by || 'در انتظار بازبینی')}</strong></div>
        <div><label>رخداد</label><strong>${esc(r.incident_id || '—')}</strong></div>
        <div><label>حافظهٔ عملیاتی</label><strong>${esc(r.memory_id || '—')}</strong></div>
      </div>
      <p class="muted">پیش از تأیید، شواهد پشتیبان، علت تأییدشده، اقدام واقعی، نتیجه و اطلاعات حساس را بررسی کنید. هر ویرایش تأیید قبلی را باطل می‌کند.</p>
      ${r.incident_dossier?.facts?.length ? `
        <section class="knowledge-evidence-facts" aria-label="شواهد فنی ثبت‌شدهٔ رخداد">
          <h3>مشکل ثبت‌شده، اصلاح واقعی و نتیجهٔ بازیابی</h3>
          <p class="muted">از شواهد و ممیزی همین رخداد؛ این بخش فقط برای بازبینی است و به‌طور خودکار جزو متن ارسالی به کاگنیا نیست.</p>
          <ul>${r.incident_dossier.facts.map(fact => `<li>${esc(fact)}</li>`).join('')}</ul>
          ${r.incident_dossier.config_diagnostic && !r.content.includes(r.incident_dossier.config_diagnostic.config_file) ?
            '<p class="knowledge-alert">متن پیش‌نویس هنوز مسیر فایل و خطای کانفیگ را ندارد؛ پیش از انتشار، آن را به‌روزرسانی کنید.</p>' : ''}
        </section>
      ` : ''}
      ${r.incident_id ? `<button type="button" class="approval-btn" data-knowledge-incident="${esc(r.incident_id)}">مشاهدهٔ رخداد و شواهد</button>` : ''}
      <label for="knowledgeEditTitle">عنوان دانش</label>
      <input id="knowledgeEditTitle" maxlength="500" value="${esc(r.title)}" ${editable ? '' : 'readonly'}>
      <label for="knowledgeEditContent">محتوای بررسی‌شده (متن دقیق ارسالی به کاگنیا)</label>
      <textarea id="knowledgeEditContent" rows="15" ${editable ? '' : 'readonly'}>${esc(r.content)}</textarea>
      <div class="knowledge-actions">
        ${canRefreshEvidence ? '<button type="button" class="approval-btn" data-knowledge-op="refresh-evidence">'+
          (coverageDraft ? 'بازخوانی آخرین وضعیت و شواهد رخداد' : 'افزودن شواهد کانفیگ به پیش‌نویس')+'</button>' : ''}
        ${editable ? '<button type="button" data-knowledge-op="edit">ذخیرهٔ تغییرات</button>' : ''}
        ${reviewable ? '<button type="button" class="approval-btn execute" data-knowledge-op="approve">تأیید و انتشار</button><button type="button" class="approval-btn reject" data-knowledge-op="reject">رد درخواست</button>' : ''}
        ${publishable ? '<button type="button" class="approval-btn execute" data-knowledge-op="publish">انتشار نسخهٔ تأییدشده</button>' : ''}
        ${canRefresh ? '<button type="button" data-knowledge-op="refresh">بررسی فعال‌شدن دانش در کاگنیا</button>' : ''}
      </div>
      ${r.publish_error_code ? `<p class="knowledge-alert">انتشار ناموفق: ${esc(r.publish_error_code)}</p>` : ''}
      ${r.status === 'submitted' ? '<p class="muted">کاگنیا ثبت دانش را پذیرفته است، اما فعال‌سازی یا نمایه‌سازی هنوز تأیید نشده است.</p>' : ''}
      ${r.status === 'published' ? '<p class="knowledge-success">فعال‌شدن نسخهٔ دانش در کاگنیا تأیید شد؛ اکنون این نسخه می‌تواند در جست‌وجوی دانش استفاده شود.</p>' : ''}
      ${r.cognia_knowledge_id ? `<p class="muted">دانش کاگنیا شمارهٔ ${esc(r.cognia_knowledge_id)} · نسخهٔ ${esc(r.cognia_revision_id || '—')}</p>` : ''}
      ${r.review_reason ? `<p class="muted">یادداشت بازبینی: ${esc(r.review_reason)}</p>` : ''}
    `;
  }

  async function loadSelected() {
    const id = selectedId;
    selectedDetails = null;
    renderSelection();
    if (!id) return;
    try {
      const detail = await api('/api/v1/knowledge-reviews/' + encodeURIComponent(id));
      if (selectedId === id) {
        selectedDetails = detail;
        renderSelection();
      }
    } catch (err) {
      notice('دریافت محتوای بازبینی ناموفق بود: ' + err.message);
    }
  }

  async function reload(preferred = selectedId) {
    if (loading) {
      reloadRequested = true;
      return;
    }
    loading = true;
    try {
      // A prior approved Restart can be recorded in Audit and Operational
      // Memory without a Cognia review if verification was inconclusive.
      // This POST only reconciles evidence-backed, local pending drafts.
      // It never approves, publishes or executes an operational change.
      if (!recoveryReconciled) {
        recoveryReconciled = true;
        try {
          const sync = await api('/api/v1/knowledge-reviews/reconcile-recent?limit=30',
                                 {method:'POST'});
          if (sync.errors?.length) {
            notice('بازیابی پیش‌نویس‌های جاافتاده ناقص است: ' + sync.errors.join('، '));
          }
        } catch (err) {
          notice('بررسی پیش‌نویس‌های جاافتاده انجام نشد: ' + err.message);
        }
      }
      if (!incidentReconciled) {
        incidentReconciled = true;
        try {
          const sync = await api('/api/v1/knowledge-reviews/reconcile-incidents?limit=40&offset=0',
                                 {method:'POST'});
          if (sync.errors?.length) {
            incidentSyncHasMore = true;
            notice('برخی رخدادها وارد صف دانش نشدند: ' + sync.errors.join('، '));
          } else {
            incidentSyncOffset = sync.next_offset || 0;
            incidentSyncHasMore = sync.has_more === true;
          }
        } catch (err) {
          incidentSyncHasMore = true;
          incidentReconciled = false;
          notice('تهیهٔ پیش‌نویس رخدادهای اخیر ناموفق بود: ' + err.message);
        }
      }
      // Fetch every page the reviewer has explicitly opened. The former
      // single 100-row window hid older drafts even when already persisted.
      const collected = [];
      reviewHasMore = false;
      for (let page = 0; page < reviewPageCount; page++) {
        const params = new URLSearchParams({
          limit:'100', offset:String(page*100), sort_by:reviewSort
        });
        if (reviewStatus) params.set('status', reviewStatus);
        if (reviewPeriod) params.set('period_days', reviewPeriod);
        if (reviewQuery) params.set('q', reviewQuery);
        const result = await api('/api/v1/knowledge-reviews?'+params.toString());
        collected.push(...(result.items || []));
        reviewTotal = Number(result.total ?? collected.length);
        reviewHasMore = result.has_more === true;
        if (!reviewHasMore) break;
      }
      reviews = collected;
      selectedId = reviews.some(r => r.id === preferred) ? preferred : (reviews[0]?.id || null);
      renderQueue();
      await loadSelected();
      void loadKnowledgeMonitoring();
    } catch (err) {
      const list = el('knowledgeReviewQueue');
      if (list) list.textContent = 'بارگذاری بازبینی دانش ناموفق بود: ' + err.message;
      notice('بازبینی دانش در دسترس نیست: ' + err.message);
    } finally {
      loading = false;
      if (reloadRequested) {
        reloadRequested = false;
        void reload();
      }
    }
  }

  async function invoke(op) {
    const row = current();
    if (!row || actionPending) return;
    const id = encodeURIComponent(row.id);
    const base = '/api/v1/knowledge-reviews/' + id;
    actionPending = true;
    try {
      if (op === 'refresh-evidence') {
        if (el('knowledgeEditTitle')?.value!==row.title ||
            el('knowledgeEditContent')?.value!==row.content) {
          notice('ابتدا تغییرات در حال ویرایش را ذخیره کنید؛ بازسازی نباید آن‌ها را از بین ببرد.');
          return;
        }
        if (!window.confirm('آخرین شواهد ثبت‌شدهٔ رخداد جایگزین پیش‌نویس دست‌نخورده شود؟ تصمیم شما لازم است و چیزی در Cognia منتشر نمی‌شود.')) return;
        await api(base + '/refresh-evidence', {method:'POST',
          headers:{'Content-Type':'application/json'},
          body:JSON.stringify({expected_revision:row.revision})});
        notice('آخرین شواهد رخداد در پیش‌نویس ثبت شد؛ نسخهٔ جدید نیازمند بازبینی است.');
      } else if (op === 'edit') {
        const title = el('knowledgeEditTitle').value;
        const content = el('knowledgeEditContent').value;
        await api(base, {method: 'PUT', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({title, content, expected_revision: row.revision})});
        notice('پیش‌نویس ذخیره شد. نسخهٔ اصلاح‌شده نیازمند تأیید تازه است.');
      } else if (op === 'approve' || op === 'reject') {
        const title = el('knowledgeEditTitle').value;
        const content = el('knowledgeEditContent').value;
        if (title !== row.title || content !== row.content) {
          notice('قبل از تأیید این نسخه، تغییرات را ذخیره کنید.');
          return;
        }
        const reason = window.prompt(op === 'approve' ? 'Reason for approving this exact knowledge revision:' : 'Reason for rejecting this knowledge:');
        if (!reason || reason.trim().length < 3) return;
        if (op === 'approve' && !window.confirm('Approve this reviewed content and publish it to Cognia KB #' + row.kb_id + '?')) return;
        await api(base + '/' + op, {method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({expected_revision: row.revision, reason: reason.trim()})});
        if (op === 'approve') {
          notice('Approved; sending to Cognia...');
          await api(base + '/publish', {method: 'POST'});
          notice('به کاگنیا ارسال شد؛ پیش از اعلام انتشار موفق، فعال‌شدن آن را بررسی کنید.');
        } else {
          notice('دانش رد شد و چیزی در کاگنیا منتشر نشد.');
        }
      } else if (op === 'publish') {
        if (!window.confirm('Retry approved, immutable revision to Cognia?')) return;
        await api(base + '/publish', {method: 'POST'});
        notice('درخواست ثبت دانش در کاگنیا ارسال شد.');
      } else if (op === 'refresh') {
        await api(base + '/refresh', {method: 'POST'});
        notice('وضعیت فعال‌سازی دانش در کاگنیا به‌روزرسانی شد.');
      }
    } catch (err) {
      notice('اقدام بازبینی دانش ناموفق بود: ' + err.message);
    } finally {
      actionPending = false;
      await reload(row.id);
    }
  }

  async function createDraft(path, payload) {
    if (actionPending) return;
    actionPending = true;
    try {
      const row = await api(path, {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)
      });
      selectedId = row.id;
      await reload(row.id);
      notice('پیش‌نویس در انتظار بازبینی ساخته شد؛ هنوز چیزی منتشر نشده است.');
    } catch (err) {
      notice('ساخت پیش‌نویس ناموفق بود: ' + err.message);
    } finally {
      actionPending = false;
    }
  }

  function applyQueueFilters() {
    reviewSort = el('knowledgeSort')?.value || 'created_desc';
    reviewStatus = el('knowledgeStatusFilter')?.value || '';
    reviewPeriod = el('knowledgePeriod')?.value || '';
    reviewQuery = el('knowledgeSearch')?.value.trim() || '';
    reviewPageCount = 1;
    void reload();
  }

  document.addEventListener('change', e => {
    if (['knowledgeSort', 'knowledgeStatusFilter', 'knowledgePeriod'].includes(e.target.id)) {
      applyQueueFilters();
    }
  });
  document.addEventListener('input', e => {
    if (e.target.id !== 'knowledgeSearch') return;
    window.clearTimeout(queryTimer);
    queryTimer = window.setTimeout(applyQueueFilters, 320);
  });

  window.loadKnowledgeReviews = reload;
  window.loadKnowledgeMonitoring = loadKnowledgeMonitoring;
  document.addEventListener('change', event => {
    if (event.target?.id === 'knowledgeMonitorPeriod') void loadKnowledgeMonitoring();
  });
  window.setInterval(() => {
    if (typeof S !== 'undefined' && S.view === 'knowledge' && !document.hidden) {
      void loadKnowledgeMonitoring();
    }
  }, 60000);
  window.loadMoreKnowledgeReviews = async () => {
    if (loading || actionPending || !reviewHasMore) return;
    reviewPageCount += 1;
    await reload();
  };
  window.syncMoreIncidentKnowledge = async () => {
    if (loading || actionPending || !incidentSyncHasMore) return;
    actionPending = true;
    try {
      const response = await api('/api/v1/knowledge-reviews/reconcile-incidents?limit=100&offset='+
        encodeURIComponent(incidentSyncOffset), {method:'POST'});
      if (response.errors?.length) {
        // Keep the same cursor on failure; the backend uses stable IDs and
        // never overwrites a reviewed, rejected or published draft.
        notice('همگام‌سازی برخی رخدادها ناموفق بود: ' + response.errors.join('، '));
      } else {
        incidentSyncOffset = response.next_offset || incidentSyncOffset;
        incidentSyncHasMore = response.has_more === true;
        notice('بازبینی '+response.scanned+' رخداد · '+response.created+
          ' پیش‌نویس جدید · '+response.existing+' مورد موجود؛ بدون انتشار خودکار.');
      }
    } catch (err) {
      notice('همگام‌سازی رخدادها ناموفق بود: ' + err.message);
    } finally {
      actionPending = false;
      await reload();
    }
  };
  window.createKnowledgeFromMemory = () => {
    const memory_id = el('knowledgeMemoryId')?.value.trim();
    if (!memory_id) return notice('Enter a verified Operational Memory ID.');
    return createDraft('/api/v1/knowledge-reviews/from-memory', {memory_id});
  };
  window.createManualKnowledgeDraft = () => {
    const title = el('knowledgeManualTitle')?.value.trim();
    const content = el('knowledgeManualContent')?.value.trim();
    if (!title || !content) return notice('Title and content are required.');
    return createDraft('/api/v1/knowledge-reviews/manual', {title, content});
  };
  document.addEventListener('click', e => {
    if (e.target.closest('[data-knowledge-show-similar]')) {
      showAllSimilarReviews = !showAllSimilarReviews;
      renderQueue();
      return;
    }
    const incidentLink = e.target.closest('[data-knowledge-incident]');
    if (incidentLink) {
      const id = incidentLink.getAttribute('data-knowledge-incident');
      if (/^[0-9a-fA-F-]{36}$/.test(id) && typeof window.openIncident === 'function') {
        window.openIncident(id);
      }
      return;
    }
    const choose = e.target.closest('[data-knowledge-select]');
    if (choose) {
      selectedId = choose.getAttribute('data-knowledge-select');
      renderQueue();
      loadSelected();
      return;
    }
    const action = e.target.closest('[data-knowledge-op]');
    if (action) invoke(action.getAttribute('data-knowledge-op'));
  });
})();
