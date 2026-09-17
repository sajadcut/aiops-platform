(() => {
  "use strict";

  const KEY_STORAGE = "aiops.chatbot.apiKey";
  const SESSION_STORAGE = "aiops.chatbot.sessionId";

  const loginView = document.getElementById("loginView");
  const chatView = document.getElementById("chatView");
  const loginForm = document.getElementById("loginForm");
  const apiKeyInput = document.getElementById("apiKey");
  const loginError = document.getElementById("loginError");
  const identityNode = document.getElementById("identity");
  const sessionListNode = document.getElementById("sessionList");
  const messagesNode = document.getElementById("messages");
  const statusNode = document.getElementById("status");
  const chatForm = document.getElementById("chatForm");
  const messageInput = document.getElementById("messageInput");
  const sendButton = document.getElementById("sendButton");
  const logoutButton = document.getElementById("logout");
  const newChatButton = document.getElementById("newChat");

  let sessions = [];
  const sessionTitles = new Map();

  function apiKey() {
    return sessionStorage.getItem(KEY_STORAGE) || "";
  }

  function sessionId() {
    return sessionStorage.getItem(SESSION_STORAGE) || "";
  }

  function setBusy(busy, label = "") {
    sendButton.disabled = busy;
    messageInput.disabled = busy;
    statusNode.textContent = label;
  }

  function authHeaders() {
    const key = apiKey();
    if (!key) throw new Error("authentication_required");
    return {"Content-Type": "application/json", "X-API-Key": key};
  }

  async function api(path, options = {}) {
    const response = await fetch(path, {
      ...options,
      headers: {...authHeaders(), ...(options.headers || {})},
      cache: "no-store",
    });
    let payload = null;
    try { payload = await response.json(); } catch (_) { payload = {}; }
    if (!response.ok) {
      const detail = payload && payload.detail ? payload.detail : `HTTP ${response.status}`;
      const error = new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
      error.status = response.status;
      throw error;
    }
    return payload;
  }

  function friendlyError(error) {
    if (error.status === 500) {
      return "خطای داخلی سرور. اگر Chatbot را تازه فعال کرده‌اید، migration دیتابیس را بررسی کنید.";
    }
    return String(error.message || "خطای نامشخص");
  }

  function renderEmptyState() {
    if (messagesNode.childElementCount) return;
    const empty = document.createElement("div");
    empty.id = "emptyState";
    empty.className = "empty-state";
    const title = document.createElement("h1");
    title.textContent = "چه کمکی از دستم برمیاد؟";
    const text = document.createElement("p");
    text.textContent = "درخواست را طبیعی بنویسید؛ فارسی، انگلیسی یا ترکیبی. برای اطلاعات زنده زیرساخت، Copilot با LLM ابزار امن مناسب را انتخاب می‌کند.";
    empty.append(title, text);
    messagesNode.appendChild(empty);
  }

  function clearConversation(showEmpty = true) {
    messagesNode.replaceChildren();
    statusNode.textContent = "";
    if (showEmpty) renderEmptyState();
  }

  function removeEmptyState() {
    const empty = document.getElementById("emptyState");
    if (empty) empty.remove();
  }

  function addMessage(role, text, kind = "") {
    removeEmptyState();
    const article = document.createElement("article");
    const normalized = role === "user" ? "user" : "assistant";
    article.className = `message ${normalized}`;
    if (kind === "tool_result") article.classList.add("tool");
    if (kind === "action_proposal") article.classList.add("proposal");
    if (kind === "execution_result") article.classList.add("execution");
    if (kind === "policy_block" || kind === "error") article.classList.add("error-message");

    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = role === "user" ? "شما" : (kind === "tool_result" ? "نتیجه ابزار AIOps" : "AIOps Copilot");

    const body = document.createElement("div");
    body.className = "message-body";
    body.setAttribute("dir", "auto");
    body.textContent = String(text || "");
    article.append(meta, body);
    messagesNode.appendChild(article);
    messagesNode.scrollTop = messagesNode.scrollHeight;
    return article;
  }

  function addProposalControls(article, proposalId) {
    const controls = document.createElement("div");
    controls.className = "proposal-actions";
    const confirm = document.createElement("button");
    confirm.type = "button";
    confirm.textContent = "تأیید و اجرا";
    const reject = document.createElement("button");
    reject.type = "button";
    reject.className = "reject";
    reject.textContent = "رد کردن";
    controls.append(confirm, reject);
    article.appendChild(controls);

    async function decide(value) {
      confirm.disabled = true;
      reject.disabled = true;
      setBusy(true, value ? "در حال اعمال approval و اجرای کنترل‌شده…" : "در حال رد کردن درخواست…");
      try {
        const result = await api(`/api/v1/chatbot/actions/${encodeURIComponent(proposalId)}/decision`, {
          method: "POST",
          body: JSON.stringify({confirm: value}),
        });
        controls.remove();
        renderResponse(result);
        await loadSessions();
      } catch (error) {
        confirm.disabled = false;
        reject.disabled = false;
        addMessage("assistant", `عملیات انجام نشد: ${friendlyError(error)}`, "error");
      } finally {
        setBusy(false, "");
      }
    }
    confirm.addEventListener("click", () => decide(true));
    reject.addEventListener("click", () => decide(false));
  }

  function shortTitle(value) {
    const normalized = String(value || "").replace(/\s+/g, " ").trim();
    if (!normalized) return "گفت‌وگوی جدید";
    return normalized.length > 52 ? `${normalized.slice(0, 52)}…` : normalized;
  }

  function historyTitle(messages) {
    const firstUser = (messages || []).find((item) => item && item.role === "user" && item.content);
    return firstUser ? shortTitle(firstUser.content) : "گفت‌وگوی جدید";
  }

  function formatSessionTime(value) {
    try {
      return new Intl.DateTimeFormat("fa-IR", {
        month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
      }).format(new Date(value));
    } catch (_) {
      return "";
    }
  }

  function renderSessionList() {
    sessionListNode.replaceChildren();
    if (!sessions.length) {
      const empty = document.createElement("div");
      empty.className = "history-empty";
      empty.textContent = "هنوز تاریخچه‌ای ندارید.";
      sessionListNode.appendChild(empty);
      return;
    }

    const current = sessionId();
    for (const item of sessions) {
      const id = String(item.session_id || "");
      const button = document.createElement("button");
      button.type = "button";
      button.className = "session-item";
      if (id && id === current) button.classList.add("active");
      button.dataset.sessionId = id;

      const title = document.createElement("span");
      title.className = "session-title";
      title.setAttribute("dir", "auto");
      title.textContent = sessionTitles.get(id) || "گفت‌وگو";

      const time = document.createElement("span");
      time.className = "session-time";
      time.textContent = formatSessionTime(item.updated_at || item.created_at);

      button.append(title, time);
      button.addEventListener("click", () => selectSession(id));
      sessionListNode.appendChild(button);
    }
  }

  async function loadSessions() {
    try {
      const result = await api("/api/v1/chatbot/sessions", {method: "GET"});
      sessions = Array.isArray(result) ? result : [];
      renderSessionList();
    } catch (error) {
      sessions = [];
      renderSessionList();
      statusNode.textContent = `تاریخچه در دسترس نیست: ${friendlyError(error)}`;
    }
  }

  function renderResponse(result) {
    if (result.session_id) sessionStorage.setItem(SESSION_STORAGE, result.session_id);
    const article = addMessage("assistant", result.message, result.kind || "answer");
    if (result.kind === "action_proposal" && result.proposal && result.proposal.proposal_id) {
      addProposalControls(article, result.proposal.proposal_id);
    }
    renderSessionList();
  }

  async function loadHistory() {
    const current = sessionId();
    if (!current) {
      clearConversation(true);
      renderSessionList();
      return;
    }
    try {
      const history = await api(`/api/v1/chatbot/sessions/${encodeURIComponent(current)}/history`, {method: "GET"});
      sessionTitles.set(current, historyTitle(history.messages));
      clearConversation(false);
      let visibleMessages = 0;
      for (const item of history.messages || []) {
        if (item.role === "tool") continue;
        const kind = item.metadata && item.metadata.kind ? item.metadata.kind : "";
        const article = addMessage(item.role, item.content, kind);
        visibleMessages += 1;
        if (kind === "action_proposal" && item.metadata && item.metadata.proposal_id) {
          addProposalControls(article, item.metadata.proposal_id);
        }
      }
      if (!visibleMessages) renderEmptyState();
      renderSessionList();
    } catch (error) {
      if (error.status === 404) {
        sessionStorage.removeItem(SESSION_STORAGE);
        clearConversation(true);
        renderSessionList();
        return;
      }
      clearConversation(false);
      addMessage("assistant", `تاریخچه بارگذاری نشد: ${friendlyError(error)}`, "error");
    }
  }

  async function selectSession(id) {
    if (!id || id === sessionId()) return;
    sessionStorage.setItem(SESSION_STORAGE, id);
    renderSessionList();
    setBusy(true, "در حال بارگذاری گفت‌وگو…");
    try {
      await loadHistory();
    } finally {
      setBusy(false, "");
      messageInput.focus();
    }
  }

  async function validateLogin() {
    const profile = await api("/api/v1/chatbot/me", {method: "GET"});
    identityNode.textContent = `${profile.subject} · ${Array.isArray(profile.roles) ? profile.roles.join(", ") : ""}`;
    loginView.classList.add("hidden");
    chatView.classList.remove("hidden");
    clearConversation(true);
    await loadSessions();
    await loadHistory();
    messageInput.focus();
  }

  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    loginError.textContent = "";
    const key = apiKeyInput.value.trim();
    if (!key) return;
    sessionStorage.setItem(KEY_STORAGE, key);
    apiKeyInput.value = "";
    try {
      await validateLogin();
    } catch (error) {
      sessionStorage.removeItem(KEY_STORAGE);
      loginError.textContent = error.status === 401 || error.status === 403
        ? "API key نامعتبر است یا دسترسی کافی ندارید."
        : `ورود ناموفق بود: ${friendlyError(error)}`;
    }
  });

  chatForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const message = messageInput.value.trim();
    if (!message) return;
    addMessage("user", message);
    messageInput.value = "";
    setBusy(true, "در حال فهم درخواست و بررسی ابزارهای مجاز…");
    try {
      const payload = {message};
      if (sessionId()) payload.session_id = sessionId();
      const result = await api("/api/v1/chatbot/message", {method: "POST", body: JSON.stringify(payload)});
      renderResponse(result);
      if (result.session_id && !sessionTitles.has(String(result.session_id))) {
        sessionTitles.set(String(result.session_id), shortTitle(message));
      }
      await loadSessions();
    } catch (error) {
      if (error.status === 401) {
        sessionStorage.removeItem(KEY_STORAGE);
        chatView.classList.add("hidden");
        loginView.classList.remove("hidden");
        loginError.textContent = "نشست احراز هویت منقضی شده است. دوباره وارد شوید.";
      } else {
        addMessage("assistant", `درخواست ناموفق بود: ${friendlyError(error)}`, "error");
      }
    } finally {
      setBusy(false, "");
      messageInput.focus();
    }
  });

  messageInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      chatForm.requestSubmit();
    }
  });

  logoutButton.addEventListener("click", () => {
    sessionStorage.removeItem(KEY_STORAGE);
    sessionStorage.removeItem(SESSION_STORAGE);
    sessions = [];
    sessionTitles.clear();
    clearConversation(true);
    renderSessionList();
    identityNode.textContent = "";
    chatView.classList.add("hidden");
    loginView.classList.remove("hidden");
    apiKeyInput.value = "";
    apiKeyInput.focus();
  });

  newChatButton.addEventListener("click", () => {
    sessionStorage.removeItem(SESSION_STORAGE);
    clearConversation(true);
    renderSessionList();
    messageInput.focus();
  });

  window.addEventListener("pageshow", () => {
    apiKeyInput.value = "";
  });

  if (apiKey()) {
    validateLogin().catch(() => {
      sessionStorage.removeItem(KEY_STORAGE);
      chatView.classList.add("hidden");
      loginView.classList.remove("hidden");
    });
  } else {
    clearConversation(true);
    renderSessionList();
    apiKeyInput.focus();
  }
})();
