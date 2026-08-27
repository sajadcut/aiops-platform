(() => {
  const baseRenderDetail = renderDetail;

  function approvalPanel() {
    const lifecycle = S.detail?.lifecycle || {};
    const approval = lifecycle.approval || null;
    const decision = lifecycle.decision || {};
    if (!approval) {
      return `<div class="approval-card neutral">
        <div class="approval-card-head"><div><span class="section-kicker">Human gate</span><h4>No approval request</h4></div>${pill('not requested')}</div>
        <p>No durable approval is currently associated with this incident. Approval actions appear only after the workflow creates a governed request.</p>
      </div>`;
    }

    const status = lower(approval.status || 'unknown');
    const meta = approval.metadata || {};
    const risk = approval.risk_level || decision.risk_level || 'unknown';
    const pending = status === 'pending';
    const reason = meta.rejection_reason || '';
    const actor = meta.approved_by || meta.rejected_by || approval.approver || '—';
    const when = approval.approved_at || approval.rejected_at || approval.created_at;

    return `<div class="approval-card ${pending ? 'pending' : status}">
      <div class="approval-card-head">
        <div><span class="section-kicker">Governed authorization</span><h4>${esc(approval.action || decision.action || 'Proposed remediation')}</h4></div>
        ${pill(status)}
      </div>
      <div class="approval-facts">
        <div><label>Approval ID</label><strong>${esc(String(approval.approval_id || '').slice(0, 12) || '—')}</strong></div>
        <div><label>Risk</label><strong>${esc(risk)}</strong></div>
        <div><label>Tool</label><strong>${esc(meta.tool_name || '—')}</strong></div>
        <div><label>Target</label><strong>${esc(meta.target || '—')}</strong></div>
      </div>
      <p class="approval-note">Approval authorizes the bound action only. It does not execute the action by itself; execution remains a separate audited boundary and consumes the approval exactly once.</p>
      ${pending ? `<div class="approval-controls">
        <textarea id="rejectReason" maxlength="1000" placeholder="Rejection reason (required for Reject)"></textarea>
        <div class="approval-buttons">
          <button class="approval-btn reject" onclick="rejectCurrentApproval()">Reject</button>
          <button class="approval-btn approve" onclick="approveCurrentApproval()">Approve</button>
        </div>
      </div>` : `<div class="approval-result">
        <div><label>Actor</label><strong>${esc(actor)}</strong></div>
        <div><label>Time</label><strong>${fmtDate(when)}</strong></div>
        ${reason ? `<div class="approval-reason"><label>Rejection reason</label><p>${esc(reason)}</p></div>` : ''}
      </div>`}
    </div>`;
  }

  async function refreshApprovalDecision() {
    const id = S.selected;
    if (!id) return;
    const lifecycle = await api(`/api/v1/incidents/${id}/lifecycle`);
    S.detail.lifecycle = lifecycle;
    await loadAll();
    renderDetail('decision');
  }

  window.approveCurrentApproval = async function approveCurrentApproval() {
    const approval = S.detail?.lifecycle?.approval;
    if (!approval?.approval_id || lower(approval.status) !== 'pending') return;
    const risk = lower(approval.risk_level);
    const first = window.confirm(`Approve governed action "${approval.action}"?\n\nThis does NOT execute it yet.`);
    if (!first) return;
    if (risk === 'high' && !window.confirm('HIGH-RISK approval: confirm that you reviewed target, tool, evidence and blast radius.')) return;
    try {
      await api(`/api/v1/approvals/${encodeURIComponent(approval.approval_id)}/approve`, {method: 'POST'});
      toast('Approval granted. Execution remains separately governed.');
      await refreshApprovalDecision();
    } catch (error) {
      showError(error.message);
      toast('Approval failed');
    }
  };

  window.rejectCurrentApproval = async function rejectCurrentApproval() {
    const approval = S.detail?.lifecycle?.approval;
    if (!approval?.approval_id || lower(approval.status) !== 'pending') return;
    const input = document.querySelector('#rejectReason');
    const reason = String(input?.value || '').trim();
    if (!reason) {
      toast('Rejection reason is required');
      input?.focus();
      return;
    }
    if (!window.confirm(`Reject governed action "${approval.action}"?`)) return;
    try {
      await api(`/api/v1/approvals/${encodeURIComponent(approval.approval_id)}/reject`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({reason})
      });
      toast('Approval rejected and audited');
      await refreshApprovalDecision();
    } catch (error) {
      showError(error.message);
      toast('Rejection failed');
    }
  };

  renderDetail = function enhancedRenderDetail(tab = 'overview') {
    baseRenderDetail(tab);
    if (tab !== 'decision') return;
    const pane = document.querySelector('#detailPane');
    if (!pane) return;
    const existing = pane.innerHTML;
    pane.innerHTML = `${approvalPanel()}${existing}`;
  };
})();
