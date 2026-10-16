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
    el('knowledgePendingCount').textContent =
      String(reviews.filter(r => r.status === 'pending_review').length) +
      (reviewHasMore ? '+' : '');
    const more = el('knowledgeLoadMore');
    if (more) more.hidden = !reviewHasMore;
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
        '<span>'+pill(r.status)+' · '+esc(r.source_type)+' · KB #'+esc(r.kb_id)+
        repeated+'</span></button>';
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
    const canRefreshEvidence = r.status==='pending_review' && r.revision===1 &&
      String(r.created_by||'').startsWith('system:') && !r.reviewed_by &&
      !!r.incident_dossier?.config_diagnostic &&
      !r.content.includes('شواهد فنی مرتبط با کانفیگ');
    box.innerHTML = `
      <div class="knowledge-facts">
        <div><label>منبع</label><strong>${esc(r.source_type === 'incident' ? 'رخداد بازیابی‌شده و تأییدشده' : r.source_type === 'incident_followup' ? 'بررسی تکمیلی رخداد (نیازمند بازبینی)' : 'دانش دستی')}</strong></div>
        <div><label>مقصد</label><strong>Cognia KB #${esc(r.kb_id)}</strong></div>
        <div><label>نسخه</label><strong>${esc(r.revision)}</strong></div>
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
        ${canRefreshEvidence ? '<button type="button" class="approval-btn" data-knowledge-op="refresh-evidence">افزودن شواهد کانفیگ به پیش‌نویس</button>' : ''}
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
    if (loading) return;
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
        const result = await api('/api/v1/knowledge-reviews?limit=100&offset='+(page*100));
        collected.push(...(result.items || []));
        reviewHasMore = result.has_more === true;
        if (!reviewHasMore) break;
      }
      reviews = collected;
      selectedId = reviews.some(r => r.id === preferred) ? preferred : (reviews[0]?.id || null);
      renderQueue();
      await loadSelected();
    } catch (err) {
      const list = el('knowledgeReviewQueue');
      if (list) list.textContent = 'بارگذاری بازبینی دانش ناموفق بود: ' + err.message;
      notice('بازبینی دانش در دسترس نیست: ' + err.message);
    } finally {
      loading = false;
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
        if (!window.confirm('شواهد ثبت‌شدهٔ کانفیگ به نسخهٔ جدیدِ پیش‌نویس اضافه شود؟ هنوز چیزی در Cognia منتشر نمی‌شود.')) return;
        await api(base + '/refresh-evidence', {method:'POST',
          headers:{'Content-Type':'application/json'},
          body:JSON.stringify({expected_revision:row.revision})});
        notice('شواهد واقعی کانفیگ به پیش‌نویس افزوده شد؛ نسخهٔ جدید نیازمند بازبینی است.');
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

  window.loadKnowledgeReviews = reload;
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
