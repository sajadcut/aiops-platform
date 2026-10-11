/* Human Knowledge Review UI. All writes are enforced by server-side RBAC/DB gates. */
(() => {
  'use strict';
  let reviews = [];
  let selectedId = null;
  let loading = false;
  let actionPending = false;

  const el = id => document.getElementById(id);
  const current = () => reviews.find(row => row.id === selectedId);
  const pendingStatuses = new Set(['pending_review', 'approved', 'publish_failed', 'submitted', 'publishing']);

  function notice(message) {
    if (typeof toast === 'function') toast(message);
    else if (typeof showError === 'function') showError(message);
  }

  function renderQueue() {
    const list = el('knowledgeReviewQueue');
    if (!list) return;
    el('knowledgePendingCount').textContent = String(reviews.filter(r => r.status === 'pending_review').length);
    list.innerHTML = reviews.map(r => `
      <button type="button" class="knowledge-queue-item ${r.id === selectedId ? 'selected' : ''}"
        data-knowledge-select="${esc(r.id)}" aria-pressed="${r.id === selectedId}">
        <span class="knowledge-queue-title">${esc(r.title)}</span>
        <span>${pill(r.status)} · ${esc(r.source_type)} · KB #${esc(r.kb_id)}</span>
      </button>`).join('') || '<div class="empty-state">No Knowledge Review candidates yet.</div>';
  }

  function renderSelection() {
    const r = current();
    const box = el('knowledgeReviewDetails');
    if (!box) return;
    el('knowledgeReviewHeading').textContent = r ? r.title : 'Select a candidate';
    el('knowledgeReviewStatus').textContent = r ? r.status : 'No selection';
    if (!r) {
      box.innerHTML = '<div class="empty-state">Choose a draft from the queue.</div>';
      return;
    }
    const editable = ['pending_review', 'rejected', 'approved'].includes(r.status);
    const reviewable = r.status === 'pending_review';
    const publishable = ['approved', 'publish_failed'].includes(r.status);
    const canRefresh = ['submitted', 'published'].includes(r.status);
    box.innerHTML = `
      <div class="knowledge-facts">
        <div><label>Source</label><strong>${esc(r.source_type === 'incident' ? 'Verified Incident' : 'Manual Knowledge')}</strong></div>
        <div><label>Destination</label><strong>Cognia KB #${esc(r.kb_id)}</strong></div>
        <div><label>Revision</label><strong>${esc(r.revision)}</strong></div>
        <div><label>Reviewer</label><strong>${esc(r.reviewed_by || 'Pending Review')}</strong></div>
        <div><label>Incident</label><strong>${esc(r.incident_id || '—')}</strong></div>
        <div><label>Operational Memory</label><strong>${esc(r.memory_id || '—')}</strong></div>
      </div>
      <p class="muted">Review supporting evidence, confirmed cause, real action, outcome and secrets before approval. Edits invalidate an earlier approval.</p>
      <label for="knowledgeEditTitle">Knowledge title</label>
      <input id="knowledgeEditTitle" maxlength="500" value="${esc(r.title)}" ${editable ? '' : 'readonly'}>
      <label for="knowledgeEditContent">Reviewed content (the exact bytes sent to Cognia)</label>
      <textarea id="knowledgeEditContent" rows="15" ${editable ? '' : 'readonly'}>${esc(r.content)}</textarea>
      <div class="knowledge-actions">
        ${editable ? '<button type="button" data-knowledge-op="edit">Save Edit</button>' : ''}
        ${reviewable ? '<button type="button" class="approval-btn execute" data-knowledge-op="approve">Approve &amp; Publish</button><button type="button" class="approval-btn reject" data-knowledge-op="reject">Reject</button>' : ''}
        ${publishable ? '<button type="button" class="approval-btn execute" data-knowledge-op="publish">Publish approved revision</button>' : ''}
        ${canRefresh ? '<button type="button" data-knowledge-op="refresh">Check Cognia activation</button>' : ''}
      </div>
      ${r.publish_error_code ? `<p class="knowledge-alert">Publication failed: ${esc(r.publish_error_code)}</p>` : ''}
      ${r.status === 'submitted' ? '<p class="muted">Cognia accepted registration; activation/indexing is not yet verified.</p>' : ''}
      ${r.status === 'published' ? '<p class="knowledge-success">Cognia active revision verified. This knowledge is now eligible for RAG search.</p>' : ''}
      ${r.cognia_knowledge_id ? `<p class="muted">Cognia Knowledge #${esc(r.cognia_knowledge_id)} · Revision #${esc(r.cognia_revision_id || '—')}</p>` : ''}
      ${r.review_reason ? `<p class="muted">Review note: ${esc(r.review_reason)}</p>` : ''}
    `;
  }

  async function reload(preferred = selectedId) {
    if (loading) return;
    loading = true;
    try {
      const result = await api('/api/v1/knowledge-reviews?limit=100');
      reviews = result.items || [];
      selectedId = reviews.some(r => r.id === preferred) ? preferred : (reviews[0]?.id || null);
      renderQueue();
      renderSelection();
    } catch (err) {
      const list = el('knowledgeReviewQueue');
      if (list) list.textContent = 'Unable to load Knowledge Review: ' + err.message;
      notice('Knowledge Review unavailable: ' + err.message);
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
      if (op === 'edit') {
        const title = el('knowledgeEditTitle').value;
        const content = el('knowledgeEditContent').value;
        await api(base, {method: 'PUT', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({title, content, expected_revision: row.revision})});
        notice('Draft saved. Approval is required for the updated revision.');
      } else if (op === 'approve' || op === 'reject') {
        const title = el('knowledgeEditTitle').value;
        const content = el('knowledgeEditContent').value;
        if (title !== row.title || content !== row.content) {
          notice('Save your changes before reviewing this exact revision.');
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
          notice('Submitted to Cognia. Check activation before counting it published.');
        } else {
          notice('Knowledge rejected; no Cognia publication.');
        }
      } else if (op === 'publish') {
        if (!window.confirm('Retry approved, immutable revision to Cognia?')) return;
        await api(base + '/publish', {method: 'POST'});
        notice('Cognia registration submitted.');
      } else if (op === 'refresh') {
        await api(base + '/refresh', {method: 'POST'});
        notice('Cognia activation status refreshed.');
      }
    } catch (err) {
      notice('Knowledge Review action failed: ' + err.message);
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
      notice('Pending Review draft created. No knowledge was published.');
    } catch (err) {
      notice('Could not create draft: ' + err.message);
    } finally {
      actionPending = false;
    }
  }

  window.loadKnowledgeReviews = reload;
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
    const choose = e.target.closest('[data-knowledge-select]');
    if (choose) {
      selectedId = choose.getAttribute('data-knowledge-select');
      renderQueue();
      renderSelection();
      return;
    }
    const action = e.target.closest('[data-knowledge-op]');
    if (action) invoke(action.getAttribute('data-knowledge-op'));
  });
})();
