(() => {
  const baseSelectIncident = selectIncident;
  const baseRenderDetail = renderDetail;
  const baseLoadAll = loadAll;
  const displayStatus = value =>
    typeof faStatus === 'function' ? faStatus(value) : String(value ?? 'نامشخص');
  const displayAction = value =>
    typeof faAction === 'function' ? faAction(value) : String(value ?? 'نامشخص');

  function configPreApprovalPanel() {
    const request = S.configPreApproval;
    if (request?.approval_queue_registered && request?.approval_id) return '';
    if (S.configPreApprovalError) {
      return `<article class="approval-card neutral" data-config-validation-visibility="error">
        <div class="approval-card-head"><div><span class="section-kicker">درخواست اصلاح کانفیگ</span>
        <h4>وضعیت درخواست قابل دریافت نیست</h4></div></div>
        <p>وضعیت بازبینی از API دریافت نشد؛ وجود یا نبود مجوز اجرایی را نمی‌توان از این خطا نتیجه گرفت.</p>
      </article>`;
    }
    if (!request || request.status === 'not_responded') return '';
    const recorded = request.status === 'awaiting_isolated_validation';
    const id = encodeURIComponent(S.selected || '');
    return `<article class="approval-card neutral" data-config-validation-visibility="recorded">
      <div class="approval-card-head"><div><span class="section-kicker">درخواست اصلاح کانفیگ · پیش از Approval</span>
      <h4>${recorded ? 'درخواست بررسی اصلاح ثبت شده؛ تأیید اجرایی هنوز مجاز نیست' :
        'وضعیت پاسخ اپراتور به پیشنهاد اصلاح'}</h4></div>${pill('not_requested')}</div>
      <div class="approval-facts">
        <div><label>وضعیت درخواست</label><strong>${esc(request.status)}</strong></div>
        <div><label>وضعیت اعتبارسنجی</label><strong>${esc(request.validation_status || 'UNVERIFIED')}</strong></div>
        <div><label>سرویس</label><strong>${esc(request.service || '—')}</strong></div>
        <div><label>فایل بررسی‌شده</label><strong dir="ltr">${esc(request.config_file || '—')}</strong></div>
        <div><label>Approval اجرایی</label><strong>ایجاد نشده</strong></div>
        <div><label>زمان ثبت</label><strong>${esc(request.created_at || '—')}</strong></div>
      </div>
      <p class="approval-note">${recorded ?
        'این صرفاً درخواست اعتبارسنجی است، نه صف فعال اعتبارسنجی یا Approval اجرایی. سرویس اعتبارسنجی ایزوله و قرارداد ایمن اعمال فایل هنوز پیاده‌سازی نشده‌اند؛ بنابراین دکمهٔ تأیید و اجرای فایل نباید فعال باشد.' :
        'درخواست رد یا بررسی شده است؛ ثبت این پاسخ هیچ مجوز اجرایی صادر نمی‌کند.'}</p>
      <a href="/dashboard/incidents/${id}#ic-ai-proposed-fix">مشاهده Diff و جزئیات اصلاح در اتاق رخداد ←</a>
    </article>`;
  }

  function approvalPanel() {
    const lifecycle = S.detail?.lifecycle || {};
    const approval = lifecycle.approval || null;
    const decision = lifecycle.decision || {};
    if (!approval) {
      return `<div class="approval-card neutral">
        <div class="approval-card-head"><div><span class="section-kicker">تأیید انسانی</span><h4>درخواست تأییدی ثبت نشده</h4></div>${pill('not_requested')}</div>
        <p>هنوز درخواست تأییدی برای این رخداد ثبت نشده است؛ پس از دیدن Diff می‌توانید یک درخواست مشخص با هش نسخه در صف Approval ایجاد کنید.</p>
      </div>`;
    }

    const status = lower(approval.status || 'unknown');
    const meta = approval.metadata || {};
    const risk = approval.risk_level || decision.risk_level || decision.risk || 'unknown';
    const pending = status === 'pending';
    const pendingValidation = status === 'pending_validation';
    const approved = status === 'approved';
    const consumed = status === 'consumed';
    const reason = meta.rejection_reason || '';
    const actor = meta.approved_by || meta.rejected_by || approval.approver || '—';
    const when = approval.approved_at || approval.rejected_at || approval.created_at;
    const binding = meta.binding_complete === true || lower(meta.binding_complete) === 'true';

    let controls = '';
    if (pending) {
      controls = `<div class="approval-controls">
        <textarea id="rejectReason" maxlength="1000" placeholder="دلیل رد درخواست (الزامی)"></textarea>
        <div class="approval-buttons">
          <button class="approval-btn reject" onclick="rejectCurrentApproval()">رد درخواست</button>
          <button class="approval-btn approve" onclick="approveCurrentApproval()">تأیید درخواست</button>
        </div>
      </div>`;
    } else if (pendingValidation) {
      controls = `<div class="approval-controls">
        <p role="status" class="approval-warning">درخواست تغییر ثبت شد. این رکورد واقعی در صف Approval است، اما هنوز مجوز اجرا نیست. اعتبارسنجی ایزوله و قرارداد اعمال فایل باید تکمیل و ثبت شوند؛ تا آن زمان تأیید یا اجرای فایل مجاز نیست.</p>
        <p><strong>فایل:</strong> ${esc(meta.config_file || '—')}</p>
        <p><strong>Source SHA-256:</strong> ${esc(meta.original_sha256 || '—')}</p>
        <p><strong>Candidate SHA-256:</strong> ${esc(meta.candidate_sha256 || '—')}</p>
      </div>`;
    } else if (approved) {
      const complete = lower(lifecycle.checkpoint_status)==='completed';
      const executeLabel = complete ? 'اجرای عملیات تأییدشده' : 'ادامه و اجرا';
      controls = `<div class="execution-controls">
        <div class="execution-ready"><span class="dot green"></span><div><strong>مجوز تأیید شد؛ اجرا هنوز شروع نشده است</strong><small>تأیید مجوز به معنی اجرا نیست. تحلیل تکمیل‌شده با شناسهٔ مجوز اجرا می‌شود و تحلیل متوقف‌شده ادامه می‌یابد. هر دو مسیر نیازمند بررسی تازه، مجوز یک‌بارمصرف و راستی‌آزمایی مستقل هستند.</small></div></div>
        <button id="resumeExecutionBtn" class="approval-btn execute" onclick="resumeCurrentWorkflow()" ${binding ? '' : 'disabled'}>${executeLabel}</button>
        ${binding ? '' : '<p class="approval-warning">اتصال مجوز به عملیات ناقص است؛ ادامهٔ اجرا عمداً غیرفعال شده است.</p>'}
      </div>`;
    } else if (consumed) {
      controls = `<div class="execution-consumed"><strong>مجوز یک‌بارمصرف استفاده شد</strong><p>این مجوز قابل استفادهٔ دوباره نیست. هر اجرای جدید نیازمند تصمیم جدید و تأیید مستقل است.</p></div>`;
    }

    return `<div class="approval-card ${pending ? 'pending' : status}">
      <div class="approval-card-head">
        <div><span class="section-kicker">مجوز تحت نظارت</span><h4>${esc(displayAction(approval.action || decision.action || 'اصلاح پیشنهادی'))}</h4></div>
        ${pill(status)}
      </div>
      <div class="approval-facts">
        <div><label>شناسهٔ تأیید</label><strong>${esc(String(approval.approval_id || '').slice(0, 12) || '—')}</strong></div>
        <div><label>ریسک</label><strong>${esc(displayStatus(risk))}</strong></div>
        <div><label>اتصال مجوز</label><strong>${binding ? 'کامل' : 'ناقص'}</strong></div>
        <div><label>محیط</label><strong>${esc(meta.environment || '—')}</strong></div>
        <div><label>ابزار</label><strong>${esc(meta.tool_name || '—')}</strong></div>
        <div><label>اقدام</label><strong>${esc(displayAction(approval.action || decision.action || '—'))}</strong></div>
        <div><label>مقصد</label><strong>${esc(meta.target || '—')}</strong></div>
        <div><label>راهنمای اجرا</label><strong>${esc([meta.runbook_id, meta.runbook_version].filter(Boolean).join(' @ ') || '—')}</strong></div>
      </div>
      <p class="approval-note">تأیید فقط عملیات مشخص و متصل به همان مجوز را مجاز می‌کند؛ به‌تنهایی اجرایی انجام نمی‌شود. مجوز امضاشده فقط هنگام ادامهٔ گردش‌کار ساخته می‌شود و در مرورگر نمایش داده نخواهد شد.</p>
      ${controls}
      ${!pending && !approved && !consumed ? `<div class="approval-result">
        <div><label>اقدام‌کننده</label><strong>${esc(actor)}</strong></div>
        <div><label>زمان</label><strong>${fmtDate(when)}</strong></div>
        ${reason ? `<div class="approval-reason"><label>علت رد</label><p>${esc(reason)}</p></div>` : ''}
      </div>` : ''}
    </div>`;
  }

  function summaryBadge(label, state = 'unknown') {
    return `<span class="operator-summary-badge ${esc(state)}">${esc(label)}</span>`;
  }

  function causeBadge(summary) {
    return summaryBadge(summary.cause_confidence_fa || 'نامشخص', lower(summary.cause_confidence || 'unknown'));
  }

  function approvalBadge(status) {
    const value = lower(status);
    if (value === 'pending') return summaryBadge('نیازمند تأیید', 'probable');
    if (value === 'pending_validation') return summaryBadge('در انتظار اعتبارسنجی فنی', 'probable');
    if (value === 'approved') return summaryBadge('تأیید صادر شده', 'confirmed');
    if (value === 'consumed') return summaryBadge('مجوز استفاده شده', 'confirmed');
    if (value === 'rejected') return summaryBadge('تأیید رد شد', 'failed');
    return summaryBadge('تأییدی ثبت نشده', 'unknown');
  }

  function executionBadge(status) {
    const value = lower(status);
    if (value === 'success') return summaryBadge('اجرا موفق', 'confirmed');
    if (value === 'failed' || value === 'blocked') return summaryBadge('اجرا ناموفق', 'failed');
    return summaryBadge('اجرا نشده', 'unknown');
  }

  function verificationBadge(status) {
    const value = lower(status);
    if (['success', 'succeeded', 'verified'].includes(value)) return summaryBadge('راستی‌آزمایی موفق', 'confirmed');
    if (['failed', 'failure'].includes(value)) return summaryBadge('راستی‌آزمایی ناموفق', 'failed');
    return summaryBadge('راستی‌آزمایی ناقص', value === 'partial' || value === 'inconclusive' ? 'probable' : 'unknown');
  }

  function memoryBadge(status) {
    const value = lower(status);
    if (value === 'persisted') return summaryBadge('در حافظهٔ عملیاتی ذخیره شد', 'confirmed');
    if (value === 'not_persisted') return summaryBadge('در حافظه ذخیره نشد', 'probable');
    return summaryBadge('در حافظه ثبت نشده', 'unknown');
  }

  function observedStateRows(observed = {}) {
    const rows = [];
    const svc = observed.service_status || {};
    if (observed.service) rows.push(['سرویس', observed.service]);
    if (observed.target) rows.push(['میزبان / IP', observed.target]);
    if (observed.port) rows.push(['درگاه', observed.port]);
    if (svc.active_state || svc.sub_state) rows.push(['وضعیت سرویس', [svc.active_state, svc.sub_state].filter(Boolean).join('/')]);
    if (observed.process_status?.running != null) rows.push(['پردازش', observed.process_status.running ? `در حال اجرا (${observed.process_status.count ?? '—'})` : 'متوقف']);
    if (observed.port_listener_status?.listening != null) rows.push(['شنوندهٔ درگاه', observed.port_listener_status.listening ? 'فعال' : 'غیرفعال']);
    if (observed.tcp_check?.reachable != null) rows.push(['TCP', observed.tcp_check.reachable ? 'قابل دسترس' : 'غیرقابل دسترس']);
    if (observed.config_validate?.valid != null) rows.push(['کانفیگ', observed.config_validate.valid ? 'معتبر' : 'نامعتبر']);
    return rows.map(([label, value]) => `<div class="operator-summary-fact"><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`).join('') || '<p class="operator-summary-muted">شواهد ساختاریافتهٔ کافی برای وضعیت دقیق سرویس/Process/Port موجود نیست.</p>';
  }

  function evidenceRows(items = []) {
    return items.slice(0, 8).map(item => `<div class="operator-summary-evidence"><div><b>${esc(item.diagnostic || item.type || item.source || 'شواهد')}</b><span>${esc(item.source || 'unknown')}</span></div><p>${esc(item.summary || 'شواهد ثبت‌شده')}</p><code>${esc(item.evidence_id || item.reference || 'بدون شناسه')}</code></div>`).join('') || '<p class="operator-summary-muted">شواهد کلیدی قابل نمایش ثبت نشده است.</p>';
  }

  const RECOMMENDATION_LANGUAGE_KEY = 'aiops.operator.recommendation_language';
  function storedRecommendationLanguage() {
    // Always open operator panels in Persian. Original English remains opt-in.
    return 'fa';
  }
  S.recommendationLanguage = storedRecommendationLanguage();

  // Cache per Incident and exact English source. Never mutate the durable
  // recommendation or feed translations into operational execution paths.
  const recommendationTranslations = new Map();
  function recommendationTranslationKey(id, source) {
    return String(id) + ':' + String(source);
  }
  function translatedRecommendation(action) {
    const entry = recommendationTranslations.get(
      recommendationTranslationKey(S.selected, action?.text_en)
    );
    return entry?.status === 'success' ? entry.text : null;
  }
  async function ensurePersianRecommendation(action) {
    if (!action?.needs_persian_translation || !action.text_en || !S.selected) return;
    const id = String(S.selected);
    const source = String(action.text_en);
    const key = recommendationTranslationKey(id, source);
    if (recommendationTranslations.has(key)) return;
    recommendationTranslations.set(key, {status: 'pending'});
    try {
      const result = await api(
        `/api/v1/incidents/${encodeURIComponent(id)}/operator-recommendation/fa`
      );
      if (result?.incident_id !== id || !result.text_fa) throw new Error('translation_invalid');
      recommendationTranslations.set(key, {status: 'success', text: result.text_fa});
    } catch (_) {
      recommendationTranslations.set(key, {status: 'error'});
    }
    // An async translation must never update another Incident's selected card.
    if (String(S.selected) !== id ||
        S.operatorSummary?.recommended_action?.text_en !== source) return;
    const text = document.querySelector('#detail .operator-recommendation [data-recommendation-text]');
    if (text && S.recommendationLanguage === 'fa') {
      text.textContent = actionText(action, 'fa');
    }
  }

  function actionText(action, language = 'fa') {
    if (!action) {
      return language === 'en'
        ? 'No structured AIOps recommendation has been recorded.'
        : 'پیشنهاد عملیاتی ساختاریافته ثبت نشده است.';
    }
    if (language === 'en') {
      if (action.text_en) {
        const source = String(action.text_en);
        try {
          return JSON.stringify(JSON.parse(source), null, 2);
        } catch (_) {
          return source;
        }
      }
      // Backward compatibility for incidents returned by older API versions:
      // derive a description only from existing governed fields.
      const pieces = [
        action.action ? `Proposed action: ${action.action}` : '',
        action.tool ? `via ${action.tool}` : '',
        action.target ? `on ${action.target}` : '',
      ].filter(Boolean);
      return pieces.length
        ? pieces.join(' ') + '.'
        : 'An English translation is not available for this recorded recommendation.';
    }
    if (action.needs_persian_translation) {
      const translation = translatedRecommendation(action);
      if (translation) return translation;
      const cache = recommendationTranslations.get(
        recommendationTranslationKey(S.selected, action.text_en)
      );
      return cache?.status === 'error'
        ? 'ترجمه فارسی فعلاً در دسترس نیست. برای مشاهده تحلیل اصلی گزینهٔ انگلیسی را انتخاب کنید.'
        : 'در حال آماده‌سازی ترجمه فارسی تحلیل AIOps…';
    }
    const pieces = [action.action, action.tool ? `از طریق ${action.tool}` : '', action.target ? `روی ${action.target}` : ''].filter(Boolean);
    return action.text_fa || pieces.join(' ') || 'پیشنهاد عملیاتی ساختاریافته ثبت نشده است.';
  }

  function recommendationHasUntranslatedOriginal(action) {
    return Boolean(action?.text_fa && !action.text_en && !action.action && !action.tool && !action.target);
  }

  function recommendationArticle(action) {
    const language = S.recommendationLanguage === 'en' ? 'en' : 'fa';
    const original = recommendationHasUntranslatedOriginal(action);
    return `<article class="operator-recommendation">
      <div class="operator-recommendation-head">
        <h4>پیشنهاد AIOps</h4>
        <div class="operator-recommendation-switch" role="group" aria-label="زبان پیشنهاد AIOps">
          <button type="button" data-recommendation-lang="fa" lang="fa" aria-pressed="${language === 'fa'}">فارسی</button>
          <button type="button" data-recommendation-lang="en" lang="en" aria-pressed="${language === 'en'}">انگلیسی</button>
        </div>
      </div>
      <p class="operator-recommendation-text" data-recommendation-text lang="${language}" dir="${language === 'en' ? 'ltr' : 'rtl'}">${esc(actionText(action, language))}</p>
      ${original ? `<p class="operator-recommendation-original" data-recommendation-original lang="fa" dir="auto" ${language === 'en' ? '' : 'hidden'}>${esc(action.text_fa)}</p>` : ''}
    </article>`;
  }

  document.addEventListener('click', event => {
    const button = event.target.closest('[data-recommendation-lang]');
    if (!button || !document.querySelector('#detail')?.contains(button)) return;
    const language = button.getAttribute('data-recommendation-lang');
    if (language !== 'fa' && language !== 'en') return;
    S.recommendationLanguage = language;
    try {
      localStorage.setItem(RECOMMENDATION_LANGUAGE_KEY, language);
    } catch (_) {
      // Keep the in-memory preference when storage is unavailable.
    }
    const card = button.closest('.operator-recommendation');
    if (!card) return;
    card.querySelectorAll('[data-recommendation-lang]').forEach(option => {
      option.setAttribute('aria-pressed', String(option.getAttribute('data-recommendation-lang') === language));
    });
    const text = card.querySelector('[data-recommendation-text]');
    if (text) {
      text.textContent = actionText(S.operatorSummary?.recommended_action, language);
      text.setAttribute('lang', language);
      text.setAttribute('dir', language === 'en' ? 'ltr' : 'rtl');
    }
    const original = card.querySelector('[data-recommendation-original]');
    if (original) original.hidden = language !== 'en';
    if (language === 'fa') void ensurePersianRecommendation(S.operatorSummary?.recommended_action);
  });

  function controlRows(summary) {
    const decision = summary.decision || {};
    const approval = summary.approval || {};
    return `<div class="operator-summary-control-grid">
      <div><span>ریسک</span><strong>${esc(displayStatus(summary.risk_level || 'unknown'))}</strong></div>
      <div><span>تصمیم</span><strong>${esc(displayAction(decision.action || decision.decision || '—'))}</strong></div>
      <div><span>تأیید</span><strong>${esc(displayStatus(summary.approval_status || 'not_requested'))}</strong></div>
      <div><span>تأییدکننده</span><strong>${esc(summary.approver || '—')}</strong></div>
      <div><span>اتصال مجوز</span><strong>${approval.binding_complete ? 'کامل' : 'ناقص / ثبت نشده'}</strong></div>
    </div>`;
  }

  function executionText(summary) {
    const execution = summary.execution;
    if (!execution) return 'عملیاتی اجرا نشده است.';
    const parts = [execution.tool, execution.action, execution.target].filter(Boolean).join(' → ');
    const result = execution.reason || execution.error || (execution.result ? JSON.stringify(execution.result) : '');
    return `${parts || 'اجرای ثبت‌شده'}${result ? ` · ${result}` : ''}`;
  }

  function verificationText(summary) {
    const verification = summary.verification;
    if (!verification) return 'راستی‌آزمایی هنوز ثبت نشده است.';
    const details = [];
    if (verification.message) details.push(verification.message);
    if (verification.confidence != null) details.push(`اطمینان=${pct(verification.confidence)}`);
    if (verification.evidence_refs?.length) details.push(`تعداد شواهد=${verification.evidence_refs.length}`);
    return details.join(' · ') || `وضعیت=${displayStatus(verification.status || summary.verification_status)}`;
  }

  function operatorSummaryCard(summary) {
    const human = summary.human_action_indicator || {};
    return `<section class="operator-summary-card" dir="rtl" lang="fa">
      <div class="operator-summary-head">
        <div><span class="section-kicker">پشتیبانی تصمیم · شواهد ماندگار</span><h3>خلاصه فارسی رخداد</h3></div>
        <div class="operator-summary-badges">${causeBadge(summary)}${approvalBadge(summary.approval_status)}${executionBadge(summary.execution_status)}${verificationBadge(summary.verification_status)}</div>
      </div>
      <p class="operator-summary-lead">${esc(summary.summary_fa || 'خلاصه فارسی از داده‌های فعلی قابل تولید نیست.')}</p>
      <div class="operator-summary-sections">
        <article><h4>چه چیزی مشاهده شد؟</h4><div class="operator-summary-facts">${observedStateRows(summary.observed_state)}</div></article>
        <article><h4>علت محتمل ${causeBadge(summary)}</h4><p>${esc(summary.likely_cause || 'نامشخص')}</p></article>
        <article><h4>نشانه‌های اقدام انسانی ${summaryBadge(human.status_fa || 'نامشخص', lower(human.status || 'unknown'))}</h4><p>${esc(human.text_fa || 'شواهد کافی موجود نیست.')}</p></article>
        ${recommendationArticle(summary.recommended_action)}
        <article><h4>وضعیت کنترل ${approvalBadge(summary.approval_status)}</h4>${controlRows(summary)}</article>
        <article><h4>اجرای عملیات ${executionBadge(summary.execution_status)}</h4><p>${esc(executionText(summary))}</p></article>
        <article><h4>راستی‌آزمایی ${verificationBadge(summary.verification_status)}</h4><p>${esc(verificationText(summary))}</p></article>
        <article><h4>حافظهٔ عملیاتی ${memoryBadge(summary.memory_status)}</h4><p>${summary.memory_status === 'persisted' ? 'نتیجه تأییدشده در حافظهٔ عملیاتی ثبت شده است.' : summary.memory_status === 'not_persisted' ? 'تلاش برای ثبت در حافظه انجام شد اما نتیجه ذخیره نشد.' : 'هیچ سابقهٔ ثبت در حافظه برای این رخداد موجود نیست.'}</p></article>
        <article class="operator-summary-wide"><h4>شواهد کلیدی</h4><div class="operator-summary-evidence-list">${evidenceRows(summary.key_evidence || [])}</div></article>
        <article class="operator-summary-wide next-step"><h4>پیشنهاد به اپراتور</h4><p>${esc(summary.operator_next_step || 'شواهد و وضعیت کنترل‌های اجرایی را بازبینی کنید.')}</p></article>
      </div>
      <div class="operator-summary-policy">این خلاصه صرفاً برای کمک به تصمیم‌گیری است؛ مجوز تأیید یا اجرا ایجاد نمی‌کند و از شواهدی خارج از همین رخداد استفاده نمی‌کند.</div>
    </section>`;
  }

  function injectOperatorSummary() {
    const detail = document.querySelector('#detail');
    const head = detail?.querySelector('.detail-head');
    if (!detail || !head) return;
    detail.querySelector('.operator-summary-card')?.remove();
    if (S.operatorSummaryPending) {
      head.insertAdjacentHTML('afterend', '<section class="operator-summary-card loading" dir="rtl" lang="fa"><h3>خلاصه فارسی رخداد</h3><p>در حال خواندن وضعیت ثبت‌شدهٔ رخداد…</p></section>');
      return;
    }
    if (S.operatorSummaryError) {
      head.insertAdjacentHTML('afterend', `<section class="operator-summary-card unavailable" dir="rtl" lang="fa"><h3>خلاصه فارسی رخداد</h3><p>${esc(S.operatorSummaryError)}</p><small>داده‌های ساختاریافته Incident در بخش‌های زیر همچنان قابل مشاهده هستند.</small></section>`);
      return;
    }
    if (S.operatorSummary) {
      head.insertAdjacentHTML('afterend', operatorSummaryCard(S.operatorSummary));
      if (S.recommendationLanguage === 'fa') {
        void ensurePersianRecommendation(S.operatorSummary.recommended_action);
      }
    }
  }

  async function refreshIncidentDecision() {
    const id = S.selected;
    if (!id) return;
    await selectIncident(id);
    renderDetail('decision');
  }

  window.approveCurrentApproval = async function approveCurrentApproval() {
    const approval = S.detail?.lifecycle?.approval;
    if (!approval?.approval_id || lower(approval.status) !== 'pending') return;
    const risk = lower(approval.risk_level);
    const first = window.confirm(`آیا اقدام «${approval.action}» را تأیید می‌کنید؟\n\nتأیید شما فقط مجوز صادر می‌کند و هنوز عملیاتی انجام نخواهد شد.`);
    if (!first) return;
    if (['high', 'critical'].includes(risk) && !window.confirm('تأیید پرریسک: مطمئن شوید مقصد، ابزار، شواهد، راهنمای اجرا و دامنهٔ تأثیر را بررسی کرده‌اید.')) return;
    try {
      await api(`/api/v1/approvals/${encodeURIComponent(approval.approval_id)}/approve`, {method: 'POST'});
      toast('مجوز تأیید شد؛ گردش‌کار تا انتخاب «ادامه و اجرا» متوقف می‌ماند.');
      await refreshIncidentDecision();
    } catch (error) {
      showError(error.message);
      toast('تأیید مجوز ناموفق بود');
    }
  };

  window.rejectCurrentApproval = async function rejectCurrentApproval() {
    const approval = S.detail?.lifecycle?.approval;
    if (!approval?.approval_id || lower(approval.status) !== 'pending') return;
    const input = document.querySelector('#rejectReason');
    const reason = String(input?.value || '').trim();
    if (!reason) {
      toast('ثبت دلیل رد الزامی است');
      input?.focus();
      return;
    }
    if (!window.confirm(`آیا درخواست اجرای اقدام «${approval.action}» را رد می‌کنید؟`)) return;
    try {
      await api(`/api/v1/approvals/${encodeURIComponent(approval.approval_id)}/reject`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({reason})
      });
      toast('درخواست رد و در سوابق ممیزی ثبت شد');
      await refreshIncidentDecision();
    } catch (error) {
      showError(error.message);
      toast('رد درخواست ناموفق بود');
    }
  };

  window.resumeCurrentWorkflow = async function resumeCurrentWorkflow() {
    const lifecycle = S.detail?.lifecycle || {};
    const approval = lifecycle.approval;
    const id = S.selected;
    if (!id || !approval?.approval_id || lower(approval.status) !== 'approved') return;
    const meta = approval.metadata || {};
    const binding = meta.binding_complete === true || lower(meta.binding_complete) === 'true';
    if (!binding) {
      toast('اتصال مجوز اجرا ناقص است');
      return;
    }
    const summary = [meta.tool_name, approval.action, meta.target].filter(Boolean).join(' → ');
    if (!window.confirm(`آیا گردش‌کار تأییدشده ادامه یابد و اقدام مشخص‌شده اجرا شود؟\n\n${summary}\n\nبا شروع اجرا، مجوز فقط یک‌بار مصرف خواهد شد.`)) return;
    if (['high', 'critical'].includes(lower(approval.risk_level)) && !window.confirm('اجرای پرریسک: تأیید کنید که قصد دارید همین حالا مجوز را مصرف و عملیات را اجرا کنید.')) return;

    const button = document.querySelector('#resumeExecutionBtn');
    if (button) {
      button.disabled = true;
      button.textContent = 'در حال اجرا…';
    }
    showError();
    try {
      // Never send a completed incident to the pause-only resume endpoint.
      // Re-read the durable approval and checkpoint immediately before POST.
      const fresh = await api(`/api/v1/incidents/${encodeURIComponent(id)}/lifecycle`);
      const liveApproval = fresh.approval || {};
      const liveBinding = liveApproval.metadata?.binding_complete === true ||
        lower(liveApproval.metadata?.binding_complete) === 'true';
      if (String(liveApproval.approval_id || '') !== String(approval.approval_id) ||
          lower(liveApproval.status) !== 'approved' || !liveBinding) {
        throw new Error('approval_changed_or_binding_unverified');
      }
      const checkpoint = lower(fresh.checkpoint_status);
      const endpoint = checkpoint === 'completed'
        ? `/api/v1/approvals/${encodeURIComponent(approval.approval_id)}/execute`
        : checkpoint === 'paused'
          ? `/api/v1/workflow/e2e/${encodeURIComponent(id)}/resume`
          : null;
      if (!endpoint) throw new Error('checkpoint_not_executable: '+(checkpoint||'unknown'));
      const result = await api(endpoint, {method: 'POST'});
      const verification = result.verification_result?.status || result.verification?.status || 'not recorded';
      toast(`پاسخ اجرا دریافت شد · راستی‌آزمایی: ${displayStatus(verification)}`);
      await loadAll();
      await refreshIncidentDecision();
    } catch (error) {
      const safeMessage = error.message === 'approval_changed_or_binding_unverified'
        ? 'مجوز تغییر کرده یا اتصال آن تأیید نشده است.'
        : error.message.startsWith('checkpoint_not_executable: ')
          ? 'مرحلهٔ فعلی برای اجرا مجاز نیست.' : error.message;
      showError(`ادامهٔ گردش‌کار/اجرا ناموفق: ${safeMessage}`);
      toast('اجرا کامل نشد');
      await refreshIncidentDecision();
    }
  };

  selectIncident = async function selectIncidentWithOperatorSummary(id) {
    S.configPreApproval = null;
    S.configPreApprovalError = null;
    const configRequest = api(`/api/v1/incidents/${encodeURIComponent(id)}/configuration-review-response`)
      .then(value => ({value, error: null}))
      .catch(error => ({value: null, error: error.message}));
    S.operatorSummary = null;
    S.operatorSummaryError = null;
    S.operatorSummaryPending = true;
    S.detail = null;
    const summaryRequest = api(`/api/v1/incidents/${encodeURIComponent(id)}/operator-summary`)
      .then(value => ({value, error: null}))
      .catch(error => ({value: null, error: error.message}));
    await baseSelectIncident(id);
    if (S.selected !== id) return;
    const [result, review] = await Promise.all([summaryRequest, configRequest]);
    if (S.selected !== id) return;
    S.configPreApproval = review.value;
    S.configPreApprovalError = review.error;
    S.operatorSummary = result.value;
    S.operatorSummaryError = result.error;
    S.operatorSummaryPending = false;
    if (S.detail?.context?.incident_id === id) renderDetail('overview');
  };

  renderDetail = function enhancedRenderDetail(tab = 'overview') {
    baseRenderDetail(tab);
    injectOperatorSummary();
    if (tab !== 'decision') return;
    const pane = document.querySelector('#detailPane');
    if (!pane) return;
    const existing = pane.innerHTML;
    pane.innerHTML = `${configPreApprovalPanel()}${approvalPanel()}${existing}`;
  };

  loadAll = async function loadAllWithCurrentIncidentSummary() {
    const selectedBeforeRefresh = S.selected;
    await baseLoadAll();
    if (selectedBeforeRefresh && S.selected === selectedBeforeRefresh && S.view === 'incidents') {
      await selectIncident(selectedBeforeRefresh);
    }
  };

  window.selectIncident = selectIncident;
  window.renderDetail = renderDetail;
  window.loadAll = loadAll;
})();

(() => {
  const baseRenderDetailForAgentAnalysis = window.renderDetail;
  const baseLoadAgentsForCompatibility = typeof loadAgents === 'function' ? loadAgents : window.loadAgents;

  const list = value => Array.isArray(value) ? value : value == null ? [] : [value];
  const uniqueText = values => [...new Set(values.flatMap(list).map(value => String(value ?? '').trim()).filter(Boolean))];

  function safeJson(value, limit = 18000) {
    try {
      const raw = JSON.stringify(value ?? {}, null, 2);
      return raw.length > limit ? `${raw.slice(0, limit)}\n… dashboard preview truncated; full payload remains durable in the API.` : raw;
    } catch {
      return '{"error":"unserializable dashboard payload"}';
    }
  }

  function detailsFor(agent) {
    return agent?.analysis_details && typeof agent.analysis_details === 'object' && !Array.isArray(agent.analysis_details)
      ? agent.analysis_details
      : {};
  }

  function analyzerKeys(details) {
    return Object.keys(details)
      .filter(key => key.endsWith('_analysis') && !['deterministic_analysis', 'shared_deterministic_analysis'].includes(key))
      .slice(0, 8);
  }

  function candidateCount(details) {
    return Object.entries(details).reduce((total, [key, value]) => {
      if (!Array.isArray(value)) return total;
      return /(candidate|hypoth|contributor|cause)/i.test(key) ? total + value.length : total;
    }, 0);
  }

  function agentAnalysisCard(agent) {
    const details = detailsFor(agent);
    const telemetry = details.analyzer_telemetry && typeof details.analyzer_telemetry === 'object'
      ? details.analyzer_telemetry
      : {};
    const analyzers = analyzerKeys(details);
    const missing = uniqueText([
      ...(agent.missing_evidence || []),
      ...(details.missing_evidence || []),
      ...(details.evidence_gaps || []),
    ]).slice(0, 10);
    const stale = uniqueText(details.stale_evidence_ids || []).slice(0, 10);
    const nextBest = uniqueText(details.next_best_evidence || []).slice(0, 8);
    const handoffs = uniqueText([
      ...(agent.handoff_agents || []),
      ...(details.handoff_agents || []),
    ]).slice(0, 8);
    const candidates = candidateCount(details);
    const executionBoundary = details.execution_boundary || details.policy?.execution_boundary || 'analysis_only';
    const analyzerDuration = telemetry.duration_ms != null ? `${Number(telemetry.duration_ms).toFixed(1)} ms` : '—';

    return `<article class="agent-card">
      <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start">
        <div><span class="section-kicker">تحلیل ایجنت متخصص</span><h4>${esc(agent.agent_name || agent.agent || 'ایجنت')}</h4></div>
        ${pill(agent.health_status || agent.severity || 'analyzed')}
      </div>
      <p>${esc(agent.statement || agent.finding_type || 'تحلیل ساختاریافتهٔ ایجنت متخصص')}</p>
      <div class="fact-grid">
        <div class="fact"><label>میزان اطمینان</label><strong>${pct(agent.confidence)}</strong></div>
        <div class="fact"><label>پوشش شواهد</label><strong>${pct(agent.evidence_coverage)}</strong></div>
        <div class="fact"><label>گزینه‌های بررسی‌شده</label><strong>${candidates}</strong></div>
        <div class="fact"><label>زمان تحلیل</label><strong>${esc(analyzerDuration)}</strong></div>
        <div class="fact"><label>شواهد ناقص</label><strong>${missing.length}</strong></div>
        <div class="fact"><label>شواهد قدیمی</label><strong>${stale.length}</strong></div>
      </div>
      <div class="tags">${analyzers.map(key => `<span>${esc(key.replace(/_analysis$/, ''))}</span>`).join('')}${handoffs.map(name => `<span>ارجاع:${esc(name)}</span>`).join('')}<span>${esc(executionBoundary)}</span></div>
      ${missing.length ? `<div class="insight-card"><h4>شواهد ناقص</h4><p>${esc(missing.join(' · '))}</p></div>` : ''}
      ${nextBest.length ? `<div class="insight-card"><h4>شواهد پیشنهادی بعدی</h4><p>${esc(nextBest.join(' · '))}</p></div>` : ''}
      ${stale.length ? `<div class="insight-card"><h4>شواهد قدیمی کنارگذاشته یا کم‌اثر شده</h4><p>${esc(stale.join(' · '))}</p></div>` : ''}
      <details class="insight-card"><summary>مشاهدهٔ کل تحلیل ساختاریافته</summary><div class="json">${esc(safeJson(agent))}</div></details>
    </article>`;
  }

  renderDetail = function renderDetailWithAgentAnalysis(tab = 'overview') {
    baseRenderDetailForAgentAnalysis(tab);
    if (tab !== 'agents') return;
    const pane = document.querySelector('#detailPane');
    if (!pane) return;
    const lifecycle = S.detail?.lifecycle || {};
    const agents = Array.isArray(lifecycle.agents) ? lifecycle.agents : [];
    const coordination = lifecycle.coordination || {};
    const routing = lifecycle.routing || {};
    pane.innerHTML = `<div class="insight-card"><h4>مسیریابی و هماهنگی متخصص‌ها</h4><p>${esc(coordination.summary || coordination.statement || 'مسیریابی، هماهنگی ایجنت‌ها و درخواست‌های جمع‌آوری شواهد در ادامه ثبت شده است.')}</p><div class="json">${esc(safeJson({routing, coordination}, 10000))}</div></div>`
      + (agents.map(agentAnalysisCard).join('') || '<div class="empty-state">یافته‌ای از ایجنت‌ها ثبت نشده است.</div>');
  };
  window.renderDetail = renderDetail;

  if (typeof baseLoadAgentsForCompatibility === 'function') {
    loadAgents = async function loadAgentsWithReliabilityContract() {
      await baseLoadAgentsForCompatibility();
      const metricByAgent = {};
      (S.agentMetrics || []).forEach(metric => {
        metricByAgent[metric.agent_name || metric.agent] = metric;
      });
      document.querySelectorAll('#agentsGrid .agent-manifest').forEach((card, index) => {
        const agent = (S.agents || [])[index] || {};
        const metric = metricByAgent[agent.name] || {};
        const requirements = uniqueText(agent.evidence_requirements || []).slice(0, 6);
        const handoffs = uniqueText(agent.handoff_targets || []).slice(0, 6);
        card.insertAdjacentHTML('beforeend', `<div class="tags"><span>${esc(agent.production_status || 'analysis_only')}</span>${requirements.map(item => `<span>شاهد:${esc(item)}</span>`).join('')}${handoffs.map(item => `<span>ارجاع:${esc(item)}</span>`).join('')}</div><div class="mini-metrics"><div><label>پوشش شواهد</label><strong>${pct(metric.average_evidence_coverage || 0)}</strong></div><div><label>خطاها</label><strong>${metric.failures ?? 0}</strong></div><div><label>ارجاع‌ها</label><strong>${metric.handoffs ?? 0}</strong></div><div><label>تعارض‌ها</label><strong>${metric.conflicts ?? 0}</strong></div></div>`);
      });
    };
    window.loadAgents = loadAgents;
  }
})();