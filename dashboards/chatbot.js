(() => {
  "use strict";

  const KEY_STORAGE = "aiops.chatbot.apiKey";
  const SESSION_STORAGE = "aiops.chatbot.sessionId";
  const THEME_STORAGE = "aiops.chatbot.theme";
  const STREAM_TIMEOUT_MS = 180000;

  const $ = (id) => document.getElementById(id);
  const dom = {
    loginView: $("loginView"), chatView: $("chatView"), loginForm: $("loginForm"), apiKeyInput: $("apiKey"),
    loginError: $("loginError"), identity: $("identity"), sidebar: $("sidebar"), sidebarOpen: $("sidebarOpen"),
    sidebarClose: $("sidebarClose"), sidebarBackdrop: $("sidebarBackdrop"), sessionList: $("sessionList"),
    sessionSearch: $("sessionSearch"), sessionCount: $("sessionCount"), conversationTitle: $("conversationTitle"),
    messages: $("messages"), scrollToBottom: $("scrollToBottom"), runtimeStatus: $("runtimeStatus"),
    statusText: $("statusText"), statusMeta: $("statusMeta"), chatForm: $("chatForm"), messageInput: $("messageInput"),
    charCount: $("charCount"), sendButton: $("sendButton"), logout: $("logout"), newChat: $("newChat"),
    themeToggle: $("themeToggle"), renameDialog: $("renameDialog"), renameForm: $("renameForm"),
    renameInput: $("renameInput"), deleteDialog: $("deleteDialog"), deleteForm: $("deleteForm"), toastRegion: $("toastRegion"),
  };

  const state = {sessions: [], activeController: null, streamTimeout: null, stopReason: "", dialogSessionId: "", drafts: new Map()};
  const apiKey = () => sessionStorage.getItem(KEY_STORAGE) || "";
  const sessionId = () => sessionStorage.getItem(SESSION_STORAGE) || "";

  function authHeaders(extra = {}) {
    const key = apiKey();
    if (!key) throw Object.assign(new Error("authentication_required"), {status: 401});
    return {"Content-Type": "application/json", "X-API-Key": key, ...extra};
  }

  async function api(path, options = {}) {
    const response = await fetch(path, {...options, headers: {...authHeaders(), ...(options.headers || {})}, cache: "no-store"});
    if (response.status === 204) return null;
    let payload = {};
    try { payload = await response.json(); } catch (_) { payload = {}; }
    if (!response.ok) {
      const error = new Error(String(payload.detail || (payload.error && payload.error.message) || `HTTP ${response.status}`));
      error.status = response.status;
      throw error;
    }
    return payload;
  }

  function friendlyHttpError(error) {
    if (error.status === 401) return "نشست معتبر نیست. دوباره وارد شوید.";
    if (error.status === 403) return "دسترسی کافی ندارید.";
    if (error.status === 404) return "گفت‌وگو پیدا نشد.";
    if (error.status === 409) return "وضعیت درخواست تغییر کرده است. دوباره بررسی کنید.";
    if (error.status === 429) return "تعداد درخواست‌ها زیاد است. کمی بعد دوباره تلاش کنید.";
    if (error.status >= 500) return "سرویس موقتاً پاسخ نداد. دوباره تلاش کنید.";
    return "درخواست قابل انجام نبود. ورودی را بررسی کنید.";
  }

  function toast(message) {
    const node = document.createElement("div"); node.className = "toast"; node.textContent = String(message || ""); dom.toastRegion.appendChild(node);
    window.setTimeout(() => node.remove(), 2500);
  }

  async function copyText(value) {
    try { await navigator.clipboard.writeText(String(value || "")); toast("کپی شد"); }
    catch (_) { toast("کپی انجام نشد"); }
  }

  function appendInline(parent, value) {
    const source = String(value || ""); const pattern = /(\*\*[^*\n]+\*\*|`[^`\n]+`)/g; let cursor = 0;
    for (let match = pattern.exec(source); match; match = pattern.exec(source)) {
      if (match.index > cursor) parent.appendChild(document.createTextNode(source.slice(cursor, match.index)));
      const token = match[0]; const node = document.createElement(token.startsWith("**") ? "strong" : "code");
      node.textContent = token.startsWith("**") ? token.slice(2, -2) : token.slice(1, -1); parent.appendChild(node); cursor = pattern.lastIndex;
    }
    if (cursor < source.length) parent.appendChild(document.createTextNode(source.slice(cursor)));
  }

  function tableCells(line) { let value = String(line || "").trim(); if (value.startsWith("|")) value = value.slice(1); if (value.endsWith("|")) value = value.slice(0, -1); return value.split("|").map((cell) => cell.trim()); }
  const isTableSeparator = (line) => { const cells = tableCells(line); return cells.length > 1 && cells.every((cell) => /^:?-{3,}:?$/.test(cell.replace(/\s+/g, ""))); };

  function renderSafeMarkdown(node, value) {
    const lines = String(value || "").replace(/\r\n/g, "\n").split("\n"); const fragment = document.createDocumentFragment(); let index = 0;
    while (index < lines.length) {
      const line = lines[index]; const fence = line.match(/^\s*```([\w.+#-]*)\s*$/);
      if (fence) {
        const codeLines = []; index += 1; while (index < lines.length && !/^\s*```\s*$/.test(lines[index])) codeLines.push(lines[index++]); if (index < lines.length) index += 1;
        const block = document.createElement("div"); block.className = "code-block"; const head = document.createElement("div"); head.className = "code-head";
        const label = document.createElement("span"); label.textContent = fence[1] || "code"; const copy = document.createElement("button"); copy.type = "button"; copy.className = "copy-code"; copy.textContent = "Copy";
        const text = codeLines.join("\n"); copy.addEventListener("click", () => copyText(text)); const pre = document.createElement("pre"); const code = document.createElement("code"); code.textContent = text; code.setAttribute("dir", "ltr");
        pre.appendChild(code); head.append(label, copy); block.append(head, pre); fragment.appendChild(block); continue;
      }
      if (index + 1 < lines.length && line.includes("|") && isTableSeparator(lines[index + 1])) {
        const table = document.createElement("table"); table.className = "message-table"; const thead = document.createElement("thead"); const hr = document.createElement("tr");
        for (const value of tableCells(line)) { const th = document.createElement("th"); appendInline(th, value); hr.appendChild(th); }
        thead.appendChild(hr); table.appendChild(thead); const tbody = document.createElement("tbody"); index += 2;
        while (index < lines.length && lines[index].trim() && lines[index].includes("|")) { const tr = document.createElement("tr"); for (const value of tableCells(lines[index++])) { const td = document.createElement("td"); appendInline(td, value); tr.appendChild(td); } tbody.appendChild(tr); }
        table.appendChild(tbody); const wrap = document.createElement("div"); wrap.className = "table-wrap"; wrap.appendChild(table); fragment.appendChild(wrap); continue;
      }
      const bullet = line.match(/^\s*[-*]\s+(.+)$/); const numbered = line.match(/^\s*\d+[.)]\s+(.+)$/);
      if (bullet || numbered) {
        const list = document.createElement(numbered ? "ol" : "ul");
        while (index < lines.length) { const match = numbered ? lines[index].match(/^\s*\d+[.)]\s+(.+)$/) : lines[index].match(/^\s*[-*]\s+(.+)$/); if (!match) break; const li = document.createElement("li"); appendInline(li, match[1]); list.appendChild(li); index += 1; }
        fragment.appendChild(list); continue;
      }
      const quote = line.match(/^\s*>\s?(.*)$/); if (quote) { const block = document.createElement("blockquote"); appendInline(block, quote[1]); fragment.appendChild(block); index += 1; continue; }
      if (!line.trim()) { index += 1; continue; }
      const parts = [line]; index += 1; while (index < lines.length && lines[index].trim() && !/^\s*```/.test(lines[index]) && !/^\s*[-*]\s+/.test(lines[index]) && !/^\s*\d+[.)]\s+/.test(lines[index]) && !/^\s*>/.test(lines[index])) parts.push(lines[index++]);
      const p = document.createElement("p"); appendInline(p, parts.join("\n")); fragment.appendChild(p);
    }
    node.replaceChildren(fragment);
  }

  function messagesInner() { let inner = dom.messages.querySelector(".messages-inner"); if (!inner) { inner = document.createElement("div"); inner.className = "messages-inner"; dom.messages.appendChild(inner); } return inner; }
  function renderEmptyState() {
    dom.messages.replaceChildren(); const root = document.createElement("div"); root.className = "empty-state"; root.id = "emptyState";
    const logo = document.createElement("div"); logo.className = "empty-logo"; logo.textContent = "A"; const title = document.createElement("h1"); title.textContent = "چه چیزی را بررسی کنیم؟";
    const text = document.createElement("p"); text.textContent = "طبیعی سؤال کنید؛ Copilot برای داده زنده از ابزارهای MCP مجاز استفاده می‌کند و عملیات تغییردهنده را فقط بعد از Approval اجرا می‌کند.";
    const chips = document.createElement("div"); chips.className = "capability-row"; for (const label of ["VM Metrics", "Service Status", "Zabbix", "Kubernetes", "Governed Actions"]) { const chip = document.createElement("span"); chip.className = "capability-chip"; chip.textContent = label; chips.appendChild(chip); }
    root.append(logo, title, text, chips); dom.messages.appendChild(root);
  }
  function clearConversation(showEmpty = true) { dom.messages.replaceChildren(); hideStatus(); if (showEmpty) renderEmptyState(); }
  function removeEmptyState() { const node = $("emptyState"); if (node) node.remove(); }
  function scrollToLatest(force = false) { if (force || dom.messages.scrollHeight - dom.messages.scrollTop - dom.messages.clientHeight < 140) dom.messages.scrollTop = dom.messages.scrollHeight; }
  function badge(parent, value) { if (!value) return; const node = document.createElement("span"); node.className = "source-badge"; node.textContent = String(value); parent.appendChild(node); }
  function addDetails(card, data) { if (data === undefined || data === null) return; const details = document.createElement("details"); details.className = "tool-details"; const summary = document.createElement("summary"); summary.textContent = "جزئیات منبع"; const pre = document.createElement("pre"); try { pre.textContent = JSON.stringify(data, null, 2); } catch (_) { pre.textContent = String(data); } details.append(summary, pre); card.appendChild(details); }

  function addMessage(role, text, kind = "answer", options = {}) {
    removeEmptyState(); const article = document.createElement("article"); article.className = `message ${role === "user" ? "user" : "assistant"}`;
    if (kind === "tool_result") article.classList.add("tool-result"); if (kind === "action_proposal") article.classList.add("proposal"); if (kind === "execution_result") article.classList.add("execution"); if (kind === "policy_block" || kind === "error") article.classList.add("error-message");
    const avatar = document.createElement("div"); avatar.className = "message-avatar"; avatar.textContent = role === "user" ? "U" : kind === "tool_result" ? "M" : kind === "error" ? "!" : "A";
    const wrap = document.createElement("div"); wrap.className = "message-content-wrap"; const heading = document.createElement("div"); heading.className = "message-heading"; const label = document.createElement("strong"); label.textContent = role === "user" ? "شما" : kind === "action_proposal" ? "Action Proposal" : "Operations Copilot"; heading.appendChild(label); badge(heading, options.source); if (options.tool && options.tool !== options.source) badge(heading, options.tool);
    const card = document.createElement("div"); card.className = "message-card"; const body = document.createElement("div"); body.className = "message-body"; body.setAttribute("dir", "auto"); renderSafeMarkdown(body, text); card.appendChild(body); if (kind === "tool_result") addDetails(card, options.data);
    const actions = document.createElement("div"); actions.className = "message-actions"; if (role !== "user" && kind !== "action_proposal") { const copy = document.createElement("button"); copy.type = "button"; copy.className = "message-action"; copy.textContent = "کپی"; copy.addEventListener("click", () => copyText(body.textContent || text)); actions.appendChild(copy); }
    if (kind === "error" && options.retryMessage) { const retry = document.createElement("button"); retry.type = "button"; retry.className = "retry-button"; retry.textContent = "تلاش مجدد"; retry.addEventListener("click", () => sendMessage(options.retryMessage)); actions.appendChild(retry); }
    wrap.append(heading, card); if (actions.childElementCount) wrap.appendChild(actions); article.append(avatar, wrap); messagesInner().appendChild(article); scrollToLatest(true); return {article, wrap, heading, card, body, actions};
  }

  function addProposalControls(view, proposal) {
    if (!proposal || !proposal.proposal_id) return; const facts = document.createElement("div"); facts.className = "proposal-summary"; const entries = [["Action", proposal.action], ["Target", proposal.target], ["Risk", proposal.risk_level]]; if (proposal.parameters && proposal.parameters.service) entries.splice(2, 0, ["Service", proposal.parameters.service]);
    for (const [name, value] of entries) { const fact = document.createElement("div"); fact.className = "proposal-fact"; const small = document.createElement("span"); small.textContent = name; const strong = document.createElement("strong"); strong.textContent = String(value || "-"); fact.append(small, strong); facts.appendChild(fact); }
    const controls = document.createElement("div"); controls.className = "proposal-actions"; const confirm = document.createElement("button"); confirm.type = "button"; confirm.className = "confirm"; confirm.textContent = "تأیید و اجرا"; const reject = document.createElement("button"); reject.type = "button"; reject.className = "reject"; reject.textContent = "رد کردن"; controls.append(confirm, reject); view.card.append(facts, controls);
    async function decide(value) { confirm.disabled = true; reject.disabled = true; showStatus(value ? "در حال اجرای کنترل‌شده عملیات…" : "در حال رد کردن درخواست…", "approval"); try { const result = await api(`/api/v1/chatbot/actions/${encodeURIComponent(proposal.proposal_id)}/decision`, {method: "POST", body: JSON.stringify({confirm: value})}); controls.remove(); renderResponse(result); await loadSessions(); } catch (error) { confirm.disabled = false; reject.disabled = false; addMessage("assistant", friendlyHttpError(error), "error"); } finally { hideStatus(); } }
    confirm.addEventListener("click", () => decide(true)); reject.addEventListener("click", () => decide(false));
  }

  function renderResponse(result) { if (result.session_id) sessionStorage.setItem(SESSION_STORAGE, String(result.session_id)); const view = addMessage("assistant", result.message, result.kind || "answer", result); if (result.kind === "action_proposal") addProposalControls(view, result.proposal); return view; }
  function renderTerminalError(data, retryMessage) { return addMessage("assistant", String((data && data.message) || "خطای موقت رخ داد. دوباره تلاش کنید."), "error", {retryMessage}); }
  function showStatus(message, meta = "") { dom.statusText.textContent = String(message || "در حال پردازش…"); dom.statusMeta.textContent = String(meta || ""); dom.runtimeStatus.classList.remove("hidden"); }
  function hideStatus() { dom.runtimeStatus.classList.add("hidden"); dom.statusText.textContent = ""; dom.statusMeta.textContent = ""; }

  function activeSession() { return state.sessions.find((item) => String(item.session_id) === sessionId()) || null; }
  function renderSessionList() {
    dom.sessionList.replaceChildren(); const query = String(dom.sessionSearch.value || "").trim().toLocaleLowerCase("fa"); const rows = state.sessions.filter((item) => !query || String(item.title || "گفت‌وگو").toLocaleLowerCase("fa").includes(query)); dom.sessionCount.textContent = String(rows.length); const current = sessionId();
    for (const item of rows) { const id = String(item.session_id || ""); const row = document.createElement("div"); row.className = `session-row${id === current ? " active" : ""}`; const main = document.createElement("button"); main.type = "button"; main.className = "session-main"; const title = document.createElement("span"); title.className = "session-title"; title.setAttribute("dir", "auto"); title.textContent = item.title || "گفت‌وگو"; const time = document.createElement("span"); time.className = "session-time"; try { time.textContent = new Intl.DateTimeFormat("fa-IR", {month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"}).format(new Date(item.updated_at)); } catch (_) { time.textContent = ""; } main.append(title, time); main.addEventListener("click", () => selectSession(id)); const actions = document.createElement("div"); actions.className = "session-actions"; const rename = document.createElement("button"); rename.type = "button"; rename.className = "session-action"; rename.textContent = "✎"; rename.addEventListener("click", () => { state.dialogSessionId = id; dom.renameInput.value = item.title || ""; dom.renameDialog.showModal(); }); const remove = document.createElement("button"); remove.type = "button"; remove.className = "session-action delete"; remove.textContent = "×"; remove.addEventListener("click", () => { state.dialogSessionId = id; dom.deleteDialog.showModal(); }); actions.append(rename, remove); row.append(main, actions); dom.sessionList.appendChild(row); }
    if (!rows.length) { const empty = document.createElement("div"); empty.className = "history-empty"; empty.textContent = query ? "گفت‌وگویی پیدا نشد." : "هنوز گفت‌وگویی ندارید."; dom.sessionList.appendChild(empty); }
    const currentRow = activeSession(); dom.conversationTitle.textContent = currentRow && currentRow.title ? currentRow.title : "Operations Copilot";
  }

  async function loadSessions() { try { const result = await api("/api/v1/chatbot/sessions", {method: "GET"}); state.sessions = Array.isArray(result) ? result : []; renderSessionList(); } catch (error) { state.sessions = []; renderSessionList(); toast(friendlyHttpError(error)); } }
  function draftKey(id = sessionId()) { return id || "__new__"; }
  function saveDraft() { state.drafts.set(draftKey(), dom.messageInput.value); }
  function restoreDraft(id) { dom.messageInput.value = state.drafts.get(id || "__new__") || ""; updateComposerMetrics(); }

  async function loadHistory() {
    const current = sessionId(); if (!current) { clearConversation(true); return; }
    try { const history = await api(`/api/v1/chatbot/sessions/${encodeURIComponent(current)}/history`, {method: "GET"}); dom.messages.replaceChildren(); let previousUser = ""; let visible = 0; for (const item of history.messages || []) { if (item.role === "tool") continue; const meta = item.metadata || {}; const kind = meta.kind || "answer"; if (item.role === "user") previousUser = item.content; const view = addMessage(item.role, item.content, kind, {source: meta.source, tool: meta.tool, retryMessage: kind === "error" ? previousUser : ""}); if (kind === "action_proposal" && meta.proposal_id) addProposalControls(view, {proposal_id: meta.proposal_id}); visible += 1; } if (!visible) renderEmptyState(); scrollToLatest(true); }
    catch (error) { if (error.status === 404) { sessionStorage.removeItem(SESSION_STORAGE); clearConversation(true); await loadSessions(); return; } clearConversation(false); renderTerminalError({message: `تاریخچه بارگذاری نشد. ${friendlyHttpError(error)}`}, ""); }
  }
  async function selectSession(id) { if (!id || id === sessionId() || state.activeController) return; saveDraft(); sessionStorage.setItem(SESSION_STORAGE, id); renderSessionList(); showStatus("در حال بارگذاری گفت‌وگو…"); try { await loadHistory(); restoreDraft(id); closeSidebar(); } finally { hideStatus(); dom.messageInput.focus(); } }

  function parseSseBlock(block) { let event = "message"; const data = []; for (const raw of block.split("\n")) { const line = raw.replace(/\r$/, ""); if (line.startsWith("event:")) event = line.slice(6).trim(); if (line.startsWith("data:")) data.push(line.slice(5).trimStart()); } if (!data.length) return null; try { return {event, data: JSON.parse(data.join("\n"))}; } catch (_) { return {event, data: {}}; } }
  async function streamMessage(payload, onEvent, signal) { const response = await fetch("/api/v1/chatbot/message/stream", {method: "POST", headers: authHeaders({"Accept": "text/event-stream"}), body: JSON.stringify(payload), cache: "no-store", signal}); if (!response.ok) { const error = new Error(`HTTP ${response.status}`); error.status = response.status; throw error; } if (!response.body) throw new Error("stream_body_unavailable"); const reader = response.body.getReader(); const decoder = new TextDecoder("utf-8"); let buffer = ""; let terminal = false; while (true) { const {value, done} = await reader.read(); if (done) break; buffer += decoder.decode(value, {stream: true}).replace(/\r\n/g, "\n"); let boundary; while ((boundary = buffer.indexOf("\n\n")) >= 0) { const parsed = parseSseBlock(buffer.slice(0, boundary)); buffer = buffer.slice(boundary + 2); if (!parsed) continue; onEvent(parsed.event, parsed.data); if (["complete", "error"].includes(parsed.event)) terminal = true; } } if (!terminal && !signal.aborted) throw new Error("stream_ended_without_terminal_event"); }
  function setStreaming(active) { dom.sendButton.classList.toggle("stop-mode", active); dom.sendButton.querySelector(".send-icon").classList.toggle("hidden", active); dom.sendButton.querySelector(".stop-icon").classList.toggle("hidden", !active); dom.messageInput.setAttribute("aria-busy", active ? "true" : "false"); }
  function stopGeneration(reason = "user") { if (!state.activeController) return; state.stopReason = reason; state.activeController.abort(); }
  function createStreamView(meta) { const view = addMessage("assistant", "", meta.kind || "answer", {source: meta.source, tool: meta.tool}); view.body.replaceChildren(); const textNode = document.createTextNode(""); const cursor = document.createElement("span"); cursor.className = "typing-cursor"; view.body.append(textNode, cursor); return {view, textNode, cursor, value: ""}; }
  function finishStream(stream, result) { if (!stream) return renderResponse(result); stream.cursor.remove(); stream.value = String(result.message || stream.value || ""); renderSafeMarkdown(stream.view.body, stream.value); if (result.kind === "tool_result") addDetails(stream.view.card, result.data); if (result.kind === "action_proposal") addProposalControls(stream.view, result.proposal); scrollToLatest(true); return stream.view; }

  async function sendMessage(rawMessage) {
    const message = String(rawMessage || "").trim(); if (!message || state.activeController) return; addMessage("user", message); dom.messageInput.value = ""; updateComposerMetrics(); const payload = {message}; if (sessionId()) payload.session_id = sessionId(); const controller = new AbortController(); state.activeController = controller; state.stopReason = ""; setStreaming(true); showStatus("در حال تحلیل درخواست…"); let stream = null; let terminal = false; state.streamTimeout = window.setTimeout(() => stopGeneration("timeout"), STREAM_TIMEOUT_MS);
    try { await streamMessage(payload, (event, data) => { if (event === "session" && data.session_id) { sessionStorage.setItem(SESSION_STORAGE, String(data.session_id)); return; } if (event === "status" || event === "heartbeat") { showStatus(data.message || "در حال پردازش…", data.elapsed_seconds ? `${data.elapsed_seconds}s` : (data.source || "")); return; } if (event === "answer_start") { stream = createStreamView(data); showStatus("در حال نوشتن پاسخ…", data.source || ""); return; } if (event === "delta") { if (!stream) stream = createStreamView({}); const chunk = String(data.text || ""); stream.value += chunk; stream.textNode.appendData(chunk); scrollToLatest(false); return; } if (event === "complete") { terminal = true; if (data.session_id) sessionStorage.setItem(SESSION_STORAGE, String(data.session_id)); finishStream(stream, data); hideStatus(); return; } if (event === "error") { terminal = true; if (stream) stream.view.article.remove(); renderTerminalError(data, message); hideStatus(); } }, controller.signal); if (!terminal && !controller.signal.aborted) renderTerminalError({message: "پاسخ کامل دریافت نشد. دوباره تلاش کنید."}, message); await loadSessions(); }
    catch (error) { if (controller.signal.aborted) { if (stream) stream.view.article.remove(); const timeout = state.stopReason === "timeout"; renderTerminalError({message: timeout ? "درخواست بیش از حد طول کشید. دوباره تلاش کنید." : "پاسخ متوقف شد."}, timeout ? message : ""); } else if (error.status === 401) { sessionStorage.removeItem(KEY_STORAGE); dom.chatView.classList.add("hidden"); dom.loginView.classList.remove("hidden"); dom.loginError.textContent = "نشست معتبر نیست. دوباره وارد شوید."; } else renderTerminalError({message: friendlyHttpError(error)}, message); }
    finally { if (state.streamTimeout) window.clearTimeout(state.streamTimeout); state.streamTimeout = null; state.activeController = null; state.stopReason = ""; setStreaming(false); hideStatus(); dom.messageInput.focus(); }
  }

  async function validateLogin() { const profile = await api("/api/v1/chatbot/me", {method: "GET"}); dom.identity.textContent = `${profile.subject} · ${(profile.roles || []).join(", ")}`; dom.loginView.classList.add("hidden"); dom.chatView.classList.remove("hidden"); clearConversation(true); await loadSessions(); await loadHistory(); dom.messageInput.focus(); }
  function updateComposerMetrics() { dom.charCount.textContent = `${dom.messageInput.value.length} / 4000`; dom.messageInput.style.height = "auto"; dom.messageInput.style.height = `${Math.min(dom.messageInput.scrollHeight, 190)}px`; }
  function openSidebar() { dom.sidebar.classList.add("open"); dom.sidebarBackdrop.classList.remove("hidden"); }
  function closeSidebar() { dom.sidebar.classList.remove("open"); dom.sidebarBackdrop.classList.add("hidden"); }
  function applyTheme(value) { const theme = value === "light" ? "light" : "dark"; document.documentElement.dataset.theme = theme; sessionStorage.setItem(THEME_STORAGE, theme); dom.themeToggle.textContent = theme === "dark" ? "☾" : "☀"; }

  dom.loginForm.addEventListener("submit", async (event) => { event.preventDefault(); dom.loginError.textContent = ""; const key = dom.apiKeyInput.value.trim(); if (!key) return; sessionStorage.setItem(KEY_STORAGE, key); dom.apiKeyInput.value = ""; try { await validateLogin(); } catch (error) { sessionStorage.removeItem(KEY_STORAGE); dom.loginError.textContent = friendlyHttpError(error); } });
  dom.chatForm.addEventListener("submit", (event) => { event.preventDefault(); if (state.activeController) stopGeneration("user"); else sendMessage(dom.messageInput.value); });
  dom.messageInput.addEventListener("keydown", (event) => { if (event.key === "Enter" && !event.shiftKey && !event.isComposing) { event.preventDefault(); if (!state.activeController) dom.chatForm.requestSubmit(); } }); dom.messageInput.addEventListener("input", updateComposerMetrics);
  dom.newChat.addEventListener("click", () => { if (state.activeController) return; saveDraft(); sessionStorage.removeItem(SESSION_STORAGE); clearConversation(true); renderSessionList(); restoreDraft(""); closeSidebar(); dom.messageInput.focus(); });
  dom.logout.addEventListener("click", () => { if (state.activeController) stopGeneration("user"); sessionStorage.removeItem(KEY_STORAGE); sessionStorage.removeItem(SESSION_STORAGE); state.sessions = []; state.drafts.clear(); clearConversation(true); renderSessionList(); dom.chatView.classList.add("hidden"); dom.loginView.classList.remove("hidden"); dom.apiKeyInput.focus(); });
  dom.sessionSearch.addEventListener("input", renderSessionList); dom.scrollToBottom.addEventListener("click", () => scrollToLatest(true)); dom.sidebarOpen.addEventListener("click", openSidebar); dom.sidebarClose.addEventListener("click", closeSidebar); dom.sidebarBackdrop.addEventListener("click", closeSidebar); dom.themeToggle.addEventListener("click", () => applyTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light"));
  dom.renameForm.addEventListener("submit", async (event) => { event.preventDefault(); const title = dom.renameInput.value.trim(); if (!state.dialogSessionId || !title) return; try { await api(`/api/v1/chatbot/sessions/${encodeURIComponent(state.dialogSessionId)}`, {method: "PATCH", body: JSON.stringify({title})}); dom.renameDialog.close(); await loadSessions(); toast("عنوان ذخیره شد"); } catch (error) { toast(friendlyHttpError(error)); } });
  dom.deleteForm.addEventListener("submit", async (event) => { event.preventDefault(); if (!state.dialogSessionId) return; try { await api(`/api/v1/chatbot/sessions/${encodeURIComponent(state.dialogSessionId)}`, {method: "DELETE"}); dom.deleteDialog.close(); if (sessionId() === state.dialogSessionId) { sessionStorage.removeItem(SESSION_STORAGE); clearConversation(true); } await loadSessions(); toast("گفت‌وگو حذف شد"); } catch (error) { toast(friendlyHttpError(error)); } });
  document.querySelectorAll("[data-close-dialog]").forEach((button) => button.addEventListener("click", () => { const dialog = $(button.dataset.closeDialog || ""); if (dialog && dialog.close) dialog.close(); })); window.addEventListener("beforeunload", saveDraft);

  document.body.setAttribute("dir", "auto"); document.documentElement.setAttribute("dir", "rtl");
  applyTheme(sessionStorage.getItem(THEME_STORAGE) || "dark"); updateComposerMetrics(); renderSessionList();
  if (apiKey()) validateLogin().catch(() => { sessionStorage.removeItem(KEY_STORAGE); dom.chatView.classList.add("hidden"); dom.loginView.classList.remove("hidden"); dom.apiKeyInput.focus(); }); else { clearConversation(true); dom.apiKeyInput.focus(); }
})();
