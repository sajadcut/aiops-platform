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
  const messagesNode = document.getElementById("messages");
  const statusNode = document.getElementById("status");
  const chatForm = document.getElementById("chatForm");
  const messageInput = document.getElementById("messageInput");
  const sendButton = document.getElementById("sendButton");
  const logoutButton = document.getElementById("logout");
  const newChatButton = document.getElementById("newChat");

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

  function clearConversation() {
    messagesNode.replaceChildren();
    statusNode.textContent = "";
  }

  function addMessage(role, text, kind = "") {
    const article = document.createElement("article");
    const normalized = role === "user" ? "user" : "assistant";
    article.className = `message ${normalized}`;
    if (kind === "tool_result") article.classList.add("tool");
    if (kind === "action_proposal") article.classList.add("proposal");
    if (kind === "execution_result") article.classList.add("execution");
    if (kind === "policy_block" || kind === "error") article.classList.add("error-message");

    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = role === "user" ? "You" : (kind === "tool_result" ? "AIOps tool result" : "Operations Copilot");

    const body = document.createElement("div");
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
    confirm.textContent = "Confirm exact action";
    const reject = document.createElement("button");
    reject.type = "button";
    reject.className = "reject";
    reject.textContent = "Reject";
    controls.append(confirm, reject);
    article.appendChild(controls);

    async function decide(value) {
      confirm.disabled = true;
      reject.disabled = true;
      setBusy(true, value ? "Applying approval and governed execution…" : "Rejecting proposal…");
      try {
        const result = await api(`/api/v1/chatbot/actions/${encodeURIComponent(proposalId)}/decision`, {
          method: "POST",
          body: JSON.stringify({confirm: value}),
        });
        controls.remove();
        renderResponse(result);
      } catch (error) {
        confirm.disabled = false;
        reject.disabled = false;
        addMessage("assistant", `Action decision failed: ${error.message}`, "error");
      } finally {
        setBusy(false, "");
      }
    }
    confirm.addEventListener("click", () => decide(true));
    reject.addEventListener("click", () => decide(false));
  }

  function renderResponse(result) {
    if (result.session_id) sessionStorage.setItem(SESSION_STORAGE, result.session_id);
    const article = addMessage("assistant", result.message, result.kind || "answer");
    if (result.kind === "action_proposal" && result.proposal && result.proposal.proposal_id) {
      addProposalControls(article, result.proposal.proposal_id);
    }
  }

  async function loadHistory() {
    const current = sessionId();
    if (!current) return;
    try {
      const history = await api(`/api/v1/chatbot/sessions/${encodeURIComponent(current)}/history`, {method: "GET"});
      clearConversation();
      for (const item of history.messages || []) {
        if (item.role === "tool") continue;
        const kind = item.metadata && item.metadata.kind ? item.metadata.kind : "";
        const article = addMessage(item.role, item.content, kind);
        if (kind === "action_proposal" && item.metadata && item.metadata.proposal_id) {
          addProposalControls(article, item.metadata.proposal_id);
        }
      }
    } catch (error) {
      if (error.status === 404) {
        sessionStorage.removeItem(SESSION_STORAGE);
        clearConversation();
        return;
      }
      addMessage("assistant", `Could not load chat history: ${error.message}`, "error");
    }
  }

  async function validateLogin() {
    const profile = await api("/api/v1/chatbot/me", {method: "GET"});
    identityNode.textContent = `${profile.subject} · ${Array.isArray(profile.roles) ? profile.roles.join(", ") : ""}`;
    loginView.classList.add("hidden");
    chatView.classList.remove("hidden");
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
      loginError.textContent = error.status === 401 || error.status === 403 ? "Invalid API key or insufficient role." : `Login failed: ${error.message}`;
    }
  });

  chatForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const message = messageInput.value.trim();
    if (!message) return;
    addMessage("user", message);
    messageInput.value = "";
    setBusy(true, "Thinking and checking governed tools…");
    try {
      const payload = {message};
      if (sessionId()) payload.session_id = sessionId();
      const result = await api("/api/v1/chatbot/message", {method: "POST", body: JSON.stringify(payload)});
      renderResponse(result);
    } catch (error) {
      if (error.status === 401) {
        sessionStorage.removeItem(KEY_STORAGE);
        chatView.classList.add("hidden");
        loginView.classList.remove("hidden");
        loginError.textContent = "Session authentication expired. Sign in again.";
      } else {
        addMessage("assistant", `Request failed: ${error.message}`, "error");
      }
    } finally {
      setBusy(false, "");
      messageInput.focus();
    }
  });

  logoutButton.addEventListener("click", () => {
    sessionStorage.removeItem(KEY_STORAGE);
    sessionStorage.removeItem(SESSION_STORAGE);
    clearConversation();
    identityNode.textContent = "";
    chatView.classList.add("hidden");
    loginView.classList.remove("hidden");
    apiKeyInput.value = "";
    apiKeyInput.focus();
  });

  newChatButton.addEventListener("click", () => {
    sessionStorage.removeItem(SESSION_STORAGE);
    clearConversation();
    messageInput.focus();
  });

  for (const button of document.querySelectorAll("[data-prompt]")) {
    button.addEventListener("click", () => {
      messageInput.value = button.dataset.prompt || "";
      messageInput.focus();
    });
  }

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
    apiKeyInput.focus();
  }
})();
