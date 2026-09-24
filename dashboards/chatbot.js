import {
  SIDEBAR_STORAGE,
  THEME_STORAGE,
  addBadge,
  addDetails,
  addErrorMeta,
  addOperationalFacts,
  applyTheme,
  copyText,
  formatMessageTime,
  initialTheme,
  renderSafeMarkdown,
} from "./chatbot-ui.js?v=8";
import {createTransport} from "./chatbot-transport.js?v=8";

const KEY_STORAGE = "aiops.chatbot.apiKey";
const SESSION_STORAGE = "aiops.chatbot.sessionId";
const STREAM_TIMEOUT_MS = 180000;

const $ = (id) => document.getElementById(id);

const dom = {
  loginView: $("loginView"),
  chatView: $("chatView"),
  loginForm: $("loginForm"),
  apiKeyInput: $("apiKey"),
  apiKeyToggle: $("apiKeyToggle"),
  loginError: $("loginError"),
  identity: $("identity"),
  apiStatus: $("apiStatus"),
  sidebar: $("sidebar"),
  sidebarOpen: $("sidebarOpen"),
  sidebarClose: $("sidebarClose"),
  sidebarCollapse: $("sidebarCollapse"),
  sidebarBackdrop: $("sidebarBackdrop"),
  sessionList: $("sessionList"),
  sessionSearch: $("sessionSearch"),
  sessionCount: $("sessionCount"),
  conversationTitle: $("conversationTitle"),
  messages: $("messages"),
  scrollToBottom: $("scrollToBottom"),
  runtimeStatus: $("runtimeStatus"),
  statusText: $("statusText"),
  statusMeta: $("statusMeta"),
  chatForm: $("chatForm"),
  messageInput: $("messageInput"),
  charCount: $("charCount"),
  sendButton: $("sendButton"),
  logout: $("logout"),
  newChat: $("newChat"),
  themeToggle: $("themeToggle"),
  themeMoon: $("themeMoon"),
  themeSun: $("themeSun"),
  themeLabel: $("themeLabel"),
  renameDialog: $("renameDialog"),
  renameForm: $("renameForm"),
  renameInput: $("renameInput"),
  deleteDialog: $("deleteDialog"),
  deleteForm: $("deleteForm"),
  deleteCancel: $("deleteCancel"),
  toastRegion: $("toastRegion"),
};

const state = {
  sessions: [],
  activeController: null,
  streamTimeout: null,
  stopReason: "",
  dialogSessionId: "",
  drafts: new Map(),
};

const apiKey = () => sessionStorage.getItem(KEY_STORAGE) || "";
const sessionId = () => sessionStorage.getItem(SESSION_STORAGE) || "";
const {api, friendlyHttpError, streamMessage} = createTransport(apiKey);

function toast(message) {
  const node = document.createElement("div");
  node.className = "toast";
  node.textContent = String(message || "");
  dom.toastRegion.appendChild(node);
  window.setTimeout(() => node.remove(), 2500);
}

function isNearBottom() {
  return dom.messages.scrollHeight - dom.messages.scrollTop - dom.messages.clientHeight < 120;
}

function updateScrollAffordance() {
  const hasOverflow = dom.messages.scrollHeight > dom.messages.clientHeight + 40;
  dom.scrollToBottom.classList.toggle("hidden", !hasOverflow || isNearBottom());
}

function scrollToLatest(force = false) {
  if (force || isNearBottom()) {
    dom.messages.scrollTop = dom.messages.scrollHeight;
  }
  window.requestAnimationFrame(updateScrollAffordance);
}

function messagesInner() {
  let inner = dom.messages.querySelector(".messages-inner");
  if (!inner) {
    inner = document.createElement("div");
    inner.className = "messages-inner";
    dom.messages.appendChild(inner);
  }
  return inner;
}

function renderEmptyState() {
  dom.messages.replaceChildren();

  const root = document.createElement("div");
  root.className = "empty-state";
  root.id = "emptyState";

  const logo = document.createElement("div");
  logo.className = "empty-logo";
  logo.textContent = "N";
  logo.setAttribute("aria-hidden", "true");

  const title = document.createElement("h1");
  title.textContent = "NeoBanking Chatbot Operation Platform";

  const text = document.createElement("p");
  text.textContent = "از وضعیت سرویس‌ها، VMها، Kubernetes یا رخدادهای عملیاتی سؤال کنید.";

  const chips = document.createElement("div");
  chips.className = "capability-row";
  for (const label of ["VM", "Kubernetes", "Zabbix", "Logs", "Service Health"]) {
    const chip = document.createElement("span");
    chip.className = "capability-chip";
    chip.textContent = label;
    chips.appendChild(chip);
  }

  root.append(logo, title, text, chips);
  dom.messages.appendChild(root);
  updateScrollAffordance();
}

function clearConversation(showEmpty = true) {
  dom.messages.replaceChildren();
  hideStatus();
  if (showEmpty) renderEmptyState();
}

function removeEmptyState() {
  const node = $("emptyState");
  if (node) node.remove();
}

function addMessage(role, text, kind = "answer", options = {}) {
  const keepPinned = isNearBottom();
  removeEmptyState();

  const article = document.createElement("article");
  article.className = `message ${role === "user" ? "user" : "assistant"}`;

  if (kind === "tool_result") article.classList.add("tool-result");
  if (kind === "action_proposal") article.classList.add("proposal");
  if (kind === "execution_result") article.classList.add("execution");
  if (kind === "policy_block" || kind === "error") article.classList.add("error-message");

  const avatar = document.createElement("div");
  avatar.className = "message-avatar";
  avatar.setAttribute("aria-hidden", "true");
  avatar.textContent = role === "user" ? "U" : kind === "tool_result" ? "M" : kind === "error" ? "!" : "N";

  const wrap = document.createElement("div");
  wrap.className = "message-content-wrap";

  const heading = document.createElement("div");
  heading.className = "message-heading";

  const label = document.createElement("strong");
  label.textContent = role === "user"
    ? "شما"
    : kind === "action_proposal"
      ? "Action Proposal"
      : "Operations Copilot";
  heading.appendChild(label);

  addBadge(heading, options.source);
  if (options.tool && options.tool !== options.source) addBadge(heading, options.tool);

  const time = document.createElement("time");
  time.className = "message-time";
  time.textContent = formatMessageTime(options.created_at || new Date());
  heading.appendChild(time);

  const card = document.createElement("div");
  card.className = "message-card";

  const body = document.createElement("div");
  body.className = "message-body";
  body.setAttribute("dir", "auto");
  renderSafeMarkdown(body, text, toast);
  card.appendChild(body);

  if (kind === "tool_result") {
    addOperationalFacts(card, options.data);
    addDetails(card, options.data);
  }

  if (kind === "error") {
    addErrorMeta(card, options);
  }

  const actions = document.createElement("div");
  actions.className = "message-actions";

  if (kind !== "action_proposal") {
    const copy = document.createElement("button");
    copy.type = "button";
    copy.className = "message-action";
    copy.textContent = "کپی";
    copy.setAttribute("aria-label", role === "user" ? "کپی پیام شما" : "کپی پاسخ");
    copy.addEventListener("click", () => copyText(role === "user" ? text : (body.textContent || text)));
    actions.appendChild(copy);
  }

  if (kind === "error" && options.retryMessage) {
    const retry = document.createElement("button");
    retry.type = "button";
    retry.className = "retry-button ui-regenerate";
    retry.textContent = "تلاش مجدد";
    retry.addEventListener("click", () => sendMessage(options.retryMessage));
    actions.appendChild(retry);
  }

  wrap.append(heading, card);
  if (actions.childElementCount) wrap.appendChild(actions);
  article.append(avatar, wrap);
  messagesInner().appendChild(article);
  scrollToLatest(keepPinned);
  return {article, wrap, heading, card, body, actions};
}

function addProposalControls(view, proposal) {
  if (!proposal || !proposal.proposal_id) return;

  const entries = [
    ["Action", proposal.action],
    ["Target", proposal.target],
  ];

  if (proposal.parameters && proposal.parameters.service) {
    entries.push(["Service", proposal.parameters.service]);
  }
  if (proposal.risk_level) {
    entries.push(["Risk", proposal.risk_level]);
  }
  if (proposal.source || proposal.tool) {
    entries.push(["Source", proposal.source || proposal.tool]);
  }

  const facts = document.createElement("div");
  facts.className = "proposal-summary";

  for (const [name, value] of entries) {
    if (value === undefined || value === null || value === "") continue;

    const fact = document.createElement("div");
    fact.className = "proposal-fact";
    const small = document.createElement("span");
    small.textContent = name;
    const strong = document.createElement("strong");
    strong.textContent = String(value);

    if (name === "Risk") {
      const normalized = String(value).toLowerCase().replace(/[^a-z]/g, "");
      strong.classList.add("risk-badge");
      if (["low", "medium", "high", "critical"].includes(normalized)) {
        strong.classList.add(`risk-${normalized}`);
      }
    }

    fact.append(small, strong);
    facts.appendChild(fact);
  }

  if (facts.childElementCount) view.card.appendChild(facts);

  const controls = document.createElement("div");
  controls.className = "proposal-actions";

  const confirm = document.createElement("button");
  confirm.type = "button";
  confirm.className = "confirm";
  confirm.textContent = "تأیید و اجرا";

  const reject = document.createElement("button");
  reject.type = "button";
  reject.className = "reject";
  reject.textContent = "رد کردن";

  controls.append(confirm, reject);
  view.card.appendChild(controls);

  async function decide(value) {
    confirm.disabled = true;
    reject.disabled = true;
    showStatus(value ? "در حال اجرای کنترل‌شده عملیات…" : "در حال رد کردن درخواست…", "approval");

    try {
      const result = await api(
        `/api/v1/chatbot/actions/${encodeURIComponent(proposal.proposal_id)}/decision`,
        {method: "POST", body: JSON.stringify({confirm: value})},
      );
      controls.remove();
      renderResponse(result);
      await loadSessions();
    } catch (error) {
      confirm.disabled = false;
      reject.disabled = false;
      renderTerminalError(
        {
          message: friendlyHttpError(error),
          component: "approval",
          code: error.status ? `HTTP_${error.status}` : "APPROVAL_FAILED",
        },
        "",
      );
    } finally {
      hideStatus();
    }
  }

  confirm.addEventListener("click", () => decide(true));
  reject.addEventListener("click", () => decide(false));
}

function renderResponse(result) {
  if (result.session_id) sessionStorage.setItem(SESSION_STORAGE, String(result.session_id));
  const view = addMessage("assistant", result.message, result.kind || "answer", result);
  if (result.kind === "action_proposal") addProposalControls(view, result.proposal);
  return view;
}

function renderTerminalError(data = {}, retryMessage = "") {
  return addMessage(
    "assistant",
    String(data.message || "خطای موقت رخ داد."),
    "error",
    {
      retryMessage,
      source: data && data.component ? String(data.component).toUpperCase() : "",
      request_id: data.request_id,
      component: data.component,
      code: data.code,
      timestamp: data.timestamp || new Date().toISOString(),
    },
  );
}

function showStatus(message, meta = "") {
  dom.statusText.textContent = String(message || "در حال پردازش…");
  dom.statusMeta.textContent = String(meta || "");
  dom.runtimeStatus.classList.remove("hidden");
  dom.messages.setAttribute("aria-busy", "true");
}

function hideStatus() {
  dom.runtimeStatus.classList.add("hidden");
  dom.statusText.textContent = "";
  dom.statusMeta.textContent = "";
  dom.messages.setAttribute("aria-busy", "false");
}

function activeSession() {
  return state.sessions.find((item) => String(item.session_id) === sessionId()) || null;
}

function formatSessionTime(value) {
  try {
    return new Intl.DateTimeFormat("fa-IR", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }).format(new Date(value));
  } catch (_) {
    return "";
  }
}

function renderSessionSkeleton() {
  dom.sessionList.replaceChildren();
  dom.sessionCount.textContent = "…";

  for (let index = 0; index < 4; index += 1) {
    const row = document.createElement("div");
    row.className = "session-skeleton";
    row.setAttribute("aria-hidden", "true");
    dom.sessionList.appendChild(row);
  }
}

function renderSessionList() {
  dom.sessionList.replaceChildren();

  const query = String(dom.sessionSearch.value || "").trim().toLocaleLowerCase("fa");
  const rows = state.sessions.filter((item) => {
    const title = String(item.title || "گفت‌وگو").toLocaleLowerCase("fa");
    return !query || title.includes(query);
  });

  dom.sessionCount.textContent = String(rows.length);
  const current = sessionId();

  for (const item of rows) {
    const id = String(item.session_id || "");
    const row = document.createElement("div");
    row.className = `session-row${id === current ? " active" : ""}`;

    const main = document.createElement("button");
    main.type = "button";
    main.className = "session-main";
    main.setAttribute("aria-current", id === current ? "page" : "false");
    main.setAttribute("aria-label", `باز کردن ${item.title || "گفت‌وگو"}`);

    const title = document.createElement("span");
    title.className = "session-title";
    title.setAttribute("dir", "auto");
    title.textContent = item.title || "گفت‌وگو";

    const time = document.createElement("span");
    time.className = "session-time";
    time.textContent = formatSessionTime(item.updated_at);

    main.append(title, time);
    main.addEventListener("click", () => selectSession(id));

    const actions = document.createElement("div");
    actions.className = "session-actions";

    const rename = document.createElement("button");
    rename.type = "button";
    rename.className = "session-action";
    rename.textContent = "✎";
    rename.setAttribute("aria-label", `تغییر نام ${item.title || "گفت‌وگو"}`);
    rename.title = "تغییر نام";
    rename.addEventListener("click", () => {
      state.dialogSessionId = id;
      dom.renameInput.value = item.title || "";
      dom.renameDialog.showModal();
      window.requestAnimationFrame(() => dom.renameInput.focus());
    });

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "session-action delete";
    remove.textContent = "×";
    remove.setAttribute("aria-label", `حذف ${item.title || "گفت‌وگو"}`);
    remove.title = "حذف";
    remove.addEventListener("click", () => {
      state.dialogSessionId = id;
      dom.deleteDialog.showModal();
      window.requestAnimationFrame(() => dom.deleteCancel.focus());
    });

    actions.append(rename, remove);
    row.append(main, actions);
    dom.sessionList.appendChild(row);
  }

  if (!rows.length) {
    const empty = document.createElement("div");
    empty.className = "history-empty";
    empty.textContent = query ? "گفت‌وگویی پیدا نشد." : "هنوز گفت‌وگویی ندارید.";
    dom.sessionList.appendChild(empty);
  }

  const currentRow = activeSession();
  dom.conversationTitle.textContent = currentRow && currentRow.title ? currentRow.title : "گفت‌وگوی جدید";
}

async function loadSessions() {
  renderSessionSkeleton();

  try {
    const result = await api("/api/v1/chatbot/sessions", {method: "GET"});
    state.sessions = Array.isArray(result) ? result : [];
    renderSessionList();
  } catch (error) {
    state.sessions = [];
    renderSessionList();
    toast(friendlyHttpError(error));
  }
}

function draftKey(id = sessionId()) {
  return id || "__new__";
}

function saveDraft() {
  state.drafts.set(draftKey(), dom.messageInput.value);
}

function restoreDraft(id) {
  dom.messageInput.value = state.drafts.get(id || "__new__") || "";
  updateComposerMetrics();
}

async function loadHistory() {
  const current = sessionId();
  if (!current) {
    clearConversation(true);
    return;
  }

  showStatus("در حال بارگذاری تاریخچه…", "history");

  try {
    const history = await api(
      `/api/v1/chatbot/sessions/${encodeURIComponent(current)}/history`,
      {method: "GET"},
    );

    dom.messages.replaceChildren();
    let previousUser = "";
    let visible = 0;

    for (const item of history.messages || []) {
      if (item.role === "tool") continue;

      const meta = item.metadata || {};
      const kind = meta.kind || "answer";
      if (item.role === "user") previousUser = item.content;

      const view = addMessage(item.role, item.content, kind, {
        source: meta.source,
        tool: meta.tool,
        data: meta.data,
        created_at: item.created_at,
        retryMessage: kind === "error" ? previousUser : "",
        request_id: meta.request_id,
        component: meta.component,
        code: meta.code,
        timestamp: item.created_at,
      });

      if (kind === "action_proposal" && meta.proposal_id) {
        addProposalControls(view, {
          proposal_id: meta.proposal_id,
          action: meta.action,
          target: meta.target,
          risk_level: meta.risk_level,
          parameters: meta.parameters,
          source: meta.source,
          tool: meta.tool,
        });
      }

      visible += 1;
    }

    if (!visible) renderEmptyState();
    scrollToLatest(true);
  } catch (error) {
    if (error.status === 404) {
      sessionStorage.removeItem(SESSION_STORAGE);
      clearConversation(true);
      await loadSessions();
      return;
    }

    clearConversation(false);
    renderTerminalError(
      {
        message: "تاریخچه بارگذاری نشد.",
        component: "history",
        code: error.status ? `HTTP_${error.status}` : "HISTORY_LOAD_FAILED",
      },
      "",
    );
  } finally {
    hideStatus();
  }
}

async function selectSession(id) {
  if (!id || id === sessionId() || state.activeController) return;

  saveDraft();
  sessionStorage.setItem(SESSION_STORAGE, id);
  renderSessionList();

  try {
    await loadHistory();
    restoreDraft(id);
    closeSidebar();
  } finally {
    dom.messageInput.focus();
  }
}

function setStreaming(active) {
  dom.sendButton.classList.toggle("stop-mode", active);
  dom.sendButton.querySelector(".send-icon").classList.toggle("hidden", active);
  dom.sendButton.querySelector(".stop-icon").classList.toggle("hidden", !active);
  dom.sendButton.type = active ? "button" : "submit";
  dom.sendButton.setAttribute("aria-label", active ? "توقف پاسخ" : "ارسال پیام");
  dom.messageInput.setAttribute("aria-busy", active ? "true" : "false");
  dom.messages.setAttribute("aria-busy", active ? "true" : "false");
  updateComposerMetrics();
}

function stopGeneration(reason = "user") {
  if (!state.activeController) return;
  state.stopReason = reason;
  if (reason === "user") showStatus("در حال توقف پاسخ…", "cancel");
  state.activeController.abort();
}

function createStreamView(meta) {
  const view = addMessage("assistant", "", meta.kind || "answer", {
    source: meta.source,
    tool: meta.tool,
  });

  view.body.replaceChildren();
  const textNode = document.createTextNode("");
  const cursor = document.createElement("span");
  cursor.className = "typing-cursor";
  cursor.setAttribute("aria-hidden", "true");
  view.body.append(textNode, cursor);

  return {view, textNode, cursor, value: ""};
}

function finishStream(stream, result) {
  if (!stream) return renderResponse(result);

  stream.cursor.remove();
  stream.value = String(result.message || stream.value || "");
  renderSafeMarkdown(stream.view.body, stream.value, toast);

  if (result.kind === "tool_result") {
    addOperationalFacts(stream.view.card, result.data);
    addDetails(stream.view.card, result.data);
  }

  if (result.kind === "action_proposal") {
    addProposalControls(stream.view, result.proposal);
  }

  scrollToLatest(false);
  return stream.view;
}

async function sendMessage(rawMessage) {
  const message = String(rawMessage || "").trim();
  if (!message || state.activeController) return;

  addMessage("user", message);
  dom.messageInput.value = "";
  updateComposerMetrics();

  const payload = {message};
  if (sessionId()) payload.session_id = sessionId();

  const controller = new AbortController();
  state.activeController = controller;
  state.stopReason = "";
  setStreaming(true);
  showStatus("در حال تحلیل درخواست…");

  let stream = null;
  let terminal = false;

  state.streamTimeout = window.setTimeout(
    () => stopGeneration("timeout"),
    STREAM_TIMEOUT_MS,
  );

  try {
    await streamMessage(
      payload,
      (event, data) => {
        if (event === "session" && data.session_id) {
          sessionStorage.setItem(SESSION_STORAGE, String(data.session_id));
          return;
        }

        if (event === "status" || event === "heartbeat") {
          const meta = data.elapsed_seconds
            ? `${data.elapsed_seconds}s`
            : (data.source || data.tool || "");
          showStatus(data.message || "در حال پردازش…", meta);
          return;
        }

        if (event === "answer_start") {
          stream = createStreamView(data);
          showStatus("در حال نوشتن پاسخ…", data.source || data.tool || "");
          return;
        }

        if (event === "delta") {
          if (!stream) stream = createStreamView({});
          const chunk = String(data.text || "");
          stream.value += chunk;
          stream.textNode.appendData(chunk);
          scrollToLatest(false);
          return;
        }

        if (event === "complete") {
          terminal = true;
          if (data.session_id) sessionStorage.setItem(SESSION_STORAGE, String(data.session_id));
          finishStream(stream, data);
          hideStatus();
          return;
        }

        if (event === "error") {
          terminal = true;
          if (stream) stream.view.article.remove();
          renderTerminalError(data, message);
          hideStatus();
        }
      },
      controller.signal,
    );

    if (!terminal && !controller.signal.aborted) {
      renderTerminalError(
        {
          message: "پاسخ کامل دریافت نشد.",
          component: "chat",
          code: "INCOMPLETE_STREAM",
        },
        message,
      );
    }

    await loadSessions();
  } catch (error) {
    if (controller.signal.aborted) {
      if (stream) stream.view.article.remove();
      const timeout = state.stopReason === "timeout";

      renderTerminalError(
        {
          message: timeout ? "درخواست بیش از حد طول کشید." : "پاسخ متوقف شد.",
          component: "chat",
          code: timeout ? "CLIENT_TIMEOUT" : "REQUEST_STOPPED",
        },
        timeout ? message : "",
      );
    } else if (error.status === 401) {
      sessionStorage.removeItem(KEY_STORAGE);
      dom.apiStatus.classList.add("hidden");
      dom.chatView.classList.add("hidden");
      dom.loginView.classList.remove("hidden");
      dom.loginError.textContent = "نشست معتبر نیست. دوباره وارد شوید.";
    } else {
      renderTerminalError(
        {
          message: friendlyHttpError(error),
          component: "chat",
          code: error.status ? `HTTP_${error.status}` : "CHAT_REQUEST_FAILED",
        },
        message,
      );
    }
  } finally {
    if (state.streamTimeout) window.clearTimeout(state.streamTimeout);
    state.streamTimeout = null;
    state.activeController = null;
    state.stopReason = "";
    setStreaming(false);
    hideStatus();
    dom.messageInput.focus();
  }
}

async function validateLogin() {
  const profile = await api("/api/v1/chatbot/me", {method: "GET"});
  const roles = (profile.roles || []).join(", ");
  dom.identity.textContent = roles ? `${profile.subject} · ${roles}` : String(profile.subject || "");
  dom.apiStatus.classList.remove("hidden");
  dom.loginView.classList.add("hidden");
  dom.chatView.classList.remove("hidden");
  clearConversation(true);
  await loadSessions();
  await loadHistory();
  dom.messageInput.focus();
}

function updateComposerMetrics() {
  dom.charCount.textContent = `${dom.messageInput.value.length} / 4000`;
  dom.messageInput.style.height = "auto";
  dom.messageInput.style.height = `${Math.min(dom.messageInput.scrollHeight, 190)}px`;
  dom.sendButton.disabled = state.activeController ? false : !dom.messageInput.value.trim();
}

function openSidebar() {
  dom.sidebar.classList.add("open");
  dom.sidebarBackdrop.classList.remove("hidden");
  dom.sidebarOpen.setAttribute("aria-expanded", "true");
  dom.sidebarClose.focus();
}

function closeSidebar() {
  dom.sidebar.classList.remove("open");
  dom.sidebarBackdrop.classList.add("hidden");
  dom.sidebarOpen.setAttribute("aria-expanded", "false");
}

function setSidebarCollapsed(collapsed) {
  const resolved = Boolean(collapsed);
  dom.chatView.classList.toggle("sidebar-collapsed", resolved);
  dom.sidebarCollapse.setAttribute("aria-expanded", resolved ? "false" : "true");
  dom.sidebarCollapse.setAttribute(
    "aria-label",
    resolved ? "باز کردن نوار کناری" : "جمع کردن نوار کناری",
  );
  dom.sidebarCollapse.title = resolved ? "باز کردن نوار کناری" : "جمع کردن نوار کناری";
  localStorage.setItem(SIDEBAR_STORAGE, resolved ? "1" : "0");
}

function setTheme(value) {
  return applyTheme(value, {
    toggle: dom.themeToggle,
    moon: dom.themeMoon,
    sun: dom.themeSun,
    label: dom.themeLabel,
  });
}

function toggleApiKeyVisibility() {
  const visible = dom.apiKeyInput.type === "text";
  dom.apiKeyInput.type = visible ? "password" : "text";
  dom.apiKeyToggle.textContent = visible ? "نمایش" : "پنهان";
  dom.apiKeyToggle.setAttribute("aria-pressed", visible ? "false" : "true");
  dom.apiKeyToggle.setAttribute(
    "aria-label",
    visible ? "نمایش کلید دسترسی" : "پنهان کردن کلید دسترسی",
  );
  dom.apiKeyInput.focus();
}

dom.loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  dom.loginError.textContent = "";

  const key = dom.apiKeyInput.value.trim();
  if (!key) return;

  sessionStorage.setItem(KEY_STORAGE, key);
  dom.apiKeyInput.value = "";

  try {
    await validateLogin();
  } catch (error) {
    sessionStorage.removeItem(KEY_STORAGE);
    dom.loginError.textContent = friendlyHttpError(error);
  }
});

dom.apiKeyToggle.addEventListener("click", toggleApiKeyVisibility);

dom.chatForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (state.activeController) stopGeneration("user");
  else sendMessage(dom.messageInput.value);
});

dom.sendButton.addEventListener("click", (event) => {
  if (!state.activeController) return;
  event.preventDefault();
  stopGeneration("user");
});

dom.messageInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
    event.preventDefault();
    if (!state.activeController && dom.messageInput.value.trim()) {
      dom.chatForm.requestSubmit();
    }
  }
});

dom.messageInput.addEventListener("input", updateComposerMetrics);

dom.newChat.addEventListener("click", () => {
  if (state.activeController) return;
  saveDraft();
  sessionStorage.removeItem(SESSION_STORAGE);
  clearConversation(true);
  renderSessionList();
  restoreDraft("");
  closeSidebar();
  dom.messageInput.focus();
});

dom.logout.addEventListener("click", () => {
  if (state.activeController) stopGeneration("user");
  sessionStorage.removeItem(KEY_STORAGE);
  sessionStorage.removeItem(SESSION_STORAGE);
  state.sessions = [];
  state.drafts.clear();
  clearConversation(true);
  renderSessionList();
  dom.apiStatus.classList.add("hidden");
  dom.identity.textContent = "";
  dom.chatView.classList.add("hidden");
  dom.loginView.classList.remove("hidden");
  dom.apiKeyInput.focus();
});

dom.sessionSearch.addEventListener("input", renderSessionList);
dom.messages.addEventListener("scroll", updateScrollAffordance, {passive: true});
dom.scrollToBottom.addEventListener("click", () => scrollToLatest(true));
dom.sidebarOpen.addEventListener("click", openSidebar);
dom.sidebarClose.addEventListener("click", closeSidebar);
dom.sidebarBackdrop.addEventListener("click", closeSidebar);

dom.sidebarCollapse.addEventListener("click", () => {
  setSidebarCollapsed(!dom.chatView.classList.contains("sidebar-collapsed"));
});

dom.themeToggle.addEventListener("click", () => {
  setTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light");
});

window.addEventListener("storage", (event) => {
  if (event.key === THEME_STORAGE && (event.newValue === "light" || event.newValue === "dark")) {
    applyTheme(event.newValue, {
      toggle: dom.themeToggle,
      moon: dom.themeMoon,
      sun: dom.themeSun,
      label: dom.themeLabel,
    });
  }
});

dom.renameForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const title = dom.renameInput.value.trim();
  if (!state.dialogSessionId || !title) return;

  try {
    await api(
      `/api/v1/chatbot/sessions/${encodeURIComponent(state.dialogSessionId)}`,
      {method: "PATCH", body: JSON.stringify({title})},
    );
    dom.renameDialog.close();
    await loadSessions();
    toast("عنوان ذخیره شد");
  } catch (error) {
    toast(friendlyHttpError(error));
  }
});

dom.deleteForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.dialogSessionId) return;

  try {
    await api(
      `/api/v1/chatbot/sessions/${encodeURIComponent(state.dialogSessionId)}`,
      {method: "DELETE"},
    );
    dom.deleteDialog.close();

    if (sessionId() === state.dialogSessionId) {
      sessionStorage.removeItem(SESSION_STORAGE);
      clearConversation(true);
    }

    await loadSessions();
    toast("گفت‌وگو حذف شد");
  } catch (error) {
    toast(friendlyHttpError(error));
  }
});

document.querySelectorAll("[data-close-dialog]").forEach((button) => {
  button.addEventListener("click", () => {
    const dialog = $(button.dataset.closeDialog || "");
    if (dialog && dialog.close) dialog.close();
  });
});

window.addEventListener("beforeunload", saveDraft);

document.body.setAttribute("dir", "auto");
document.documentElement.setAttribute("dir", "rtl");
setTheme(initialTheme());
setSidebarCollapsed(localStorage.getItem(SIDEBAR_STORAGE) === "1");
updateComposerMetrics();
renderSessionList();
updateScrollAffordance();

if (apiKey()) {
  validateLogin().catch(() => {
    sessionStorage.removeItem(KEY_STORAGE);
    dom.apiStatus.classList.add("hidden");
    dom.chatView.classList.add("hidden");
    dom.loginView.classList.remove("hidden");
    dom.apiKeyInput.focus();
  });
} else {
  clearConversation(true);
  dom.apiKeyInput.focus();
}
