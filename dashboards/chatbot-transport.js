export function createTransport(getApiKey) {
  function authHeaders(extra = {}) {
    const key = String(getApiKey() || "");
    if (!key) throw Object.assign(new Error("authentication_required"), {status: 401});
    return {"Content-Type": "application/json", "X-API-Key": key, ...extra};
  }

  async function api(path, options = {}) {
    const response = await fetch(path, {
      ...options,
      headers: {...authHeaders(), ...(options.headers || {})},
      cache: "no-store",
    });

    if (response.status === 204) return null;

    let payload = {};
    try {
      payload = await response.json();
    } catch (_) {
      payload = {};
    }

    if (!response.ok) {
      const error = new Error(String(payload.detail || (payload.error && payload.error.message) || `HTTP ${response.status}`));
      error.status = response.status;
      error.payload = payload;
      throw error;
    }

    return payload;
  }

  function friendlyHttpError(error) {
    if (error.status === 401) return "نشست معتبر نیست. دوباره وارد شوید.";
    if (error.status === 403) return "دسترسی کافی ندارید.";
    if (error.status === 404) return "گفت‌وگو پیدا نشد.";
    if (error.status === 409) return "وضعیت درخواست تغییر کرده است.";
    if (error.status === 429) return "تعداد درخواست‌ها زیاد است. کمی بعد دوباره تلاش کنید.";
    if (error.status >= 500) return "سرویس موقتاً پاسخ نداد.";
    return "درخواست قابل انجام نبود.";
  }

  function parseSseBlock(block) {
    let event = "message";
    const data = [];

    for (const raw of block.split("\n")) {
      const line = raw.replace(/\r$/, "");
      if (line.startsWith("event:")) event = line.slice(6).trim();
      if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
    }

    if (!data.length) return null;

    try {
      return {event, data: JSON.parse(data.join("\n"))};
    } catch (_) {
      return {event, data: {}};
    }
  }

  async function streamMessage(payload, onEvent, signal) {
    const response = await fetch("/api/v1/chatbot/message/stream", {
      method: "POST",
      headers: authHeaders({"Accept": "text/event-stream"}),
      body: JSON.stringify(payload),
      cache: "no-store",
      signal,
    });

    if (!response.ok) {
      const error = new Error(`HTTP ${response.status}`);
      error.status = response.status;
      throw error;
    }

    if (!response.body) throw new Error("stream_body_unavailable");

    const reader = response.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let buffer = "";
    let terminal = false;

    while (true) {
      const {value, done} = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, {stream: true}).replace(/\r\n/g, "\n");
      let boundary;

      while ((boundary = buffer.indexOf("\n\n")) >= 0) {
        const parsed = parseSseBlock(buffer.slice(0, boundary));
        buffer = buffer.slice(boundary + 2);
        if (!parsed) continue;

        onEvent(parsed.event, parsed.data);
        if (["complete", "error"].includes(parsed.event)) terminal = true;
      }
    }

    if (!terminal && !signal.aborted) {
      throw new Error("stream_ended_without_terminal_event");
    }
  }

  return {api, friendlyHttpError, streamMessage};
}
