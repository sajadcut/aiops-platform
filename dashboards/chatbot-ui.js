export const THEME_STORAGE = "aiops.chatbot.theme";
export const SIDEBAR_STORAGE = "aiops.chatbot.sidebarCollapsed";

export function initialTheme() {
  const saved = localStorage.getItem(THEME_STORAGE);
  if (saved === "light" || saved === "dark") return saved;
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

export function applyTheme(value, {toggle, icon, label} = {}) {
  const theme = value === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = theme;
  localStorage.setItem(THEME_STORAGE, theme);
  const switchTo = theme === "dark" ? "روشن" : "تیره";
  if (toggle) {
    toggle.setAttribute("aria-label", `تغییر به پوسته ${switchTo}`);
    toggle.title = `تغییر به پوسته ${switchTo}`;
    toggle.dataset.theme = theme;
  }
  if (icon) icon.textContent = theme === "dark" ? "☾" : "☀";
  if (label) label.textContent = theme === "dark" ? "تیره" : "روشن";
  return theme;
}

export async function copyText(value, notify = () => {}) {
  try {
    await navigator.clipboard.writeText(String(value || ""));
    notify("کپی شد");
  } catch (_) {
    notify("کپی انجام نشد");
  }
}

function appendInline(parent, value) {
  const source = String(value || "");
  const pattern = /(\*\*[^*\n]+\*\*|\`[^\`\n]+\`)/g;
  let cursor = 0;

  for (let match = pattern.exec(source); match; match = pattern.exec(source)) {
    if (match.index > cursor) {
      parent.appendChild(document.createTextNode(source.slice(cursor, match.index)));
    }

    const token = match[0];
    const node = document.createElement(token.startsWith("**") ? "strong" : "code");
    node.textContent = token.startsWith("**") ? token.slice(2, -2) : token.slice(1, -1);
    parent.appendChild(node);
    cursor = pattern.lastIndex;
  }

  if (cursor < source.length) {
    parent.appendChild(document.createTextNode(source.slice(cursor)));
  }
}

function tableCells(line) {
  let value = String(line || "").trim();
  if (value.startsWith("|")) value = value.slice(1);
  if (value.endsWith("|")) value = value.slice(0, -1);
  return value.split("|").map((cell) => cell.trim());
}

function isTableSeparator(line) {
  const cells = tableCells(line);
  return cells.length > 1 && cells.every((cell) => /^:?-{3,}:?$/.test(cell.replace(/\s+/g, "")));
}

export function renderSafeMarkdown(node, value, notify = () => {}) {
  const lines = String(value || "").replace(/\r\n/g, "\n").split("\n");
  const fragment = document.createDocumentFragment();
  let index = 0;

  while (index < lines.length) {
    const line = lines[index];
    const fence = line.match(/^\s*\`\`\`([\w.+#-]*)\s*$/);

    if (fence) {
      const codeLines = [];
      index += 1;
      while (index < lines.length && !/^\s*\`\`\`\s*$/.test(lines[index])) {
        codeLines.push(lines[index++]);
      }
      if (index < lines.length) index += 1;

      const block = document.createElement("div");
      block.className = "code-block";
      const head = document.createElement("div");
      head.className = "code-head";
      const language = document.createElement("span");
      language.textContent = fence[1] || "code";
      const copy = document.createElement("button");
      copy.type = "button";
      copy.className = "copy-code";
      copy.textContent = "Copy";
      copy.setAttribute("aria-label", "کپی کد");

      const text = codeLines.join("\n");
      copy.addEventListener("click", () => copyText(text, notify));

      const pre = document.createElement("pre");
      const code = document.createElement("code");
      code.textContent = text;
      code.setAttribute("dir", "ltr");
      pre.appendChild(code);
      head.append(language, copy);
      block.append(head, pre);
      fragment.appendChild(block);
      continue;
    }

    if (index + 1 < lines.length && line.includes("|") && isTableSeparator(lines[index + 1])) {
      const table = document.createElement("table");
      table.className = "message-table";
      const thead = document.createElement("thead");
      const headerRow = document.createElement("tr");

      for (const cellValue of tableCells(line)) {
        const th = document.createElement("th");
        appendInline(th, cellValue);
        headerRow.appendChild(th);
      }

      thead.appendChild(headerRow);
      table.appendChild(thead);
      const tbody = document.createElement("tbody");
      index += 2;

      while (index < lines.length && lines[index].trim() && lines[index].includes("|")) {
        const tr = document.createElement("tr");
        for (const cellValue of tableCells(lines[index++])) {
          const td = document.createElement("td");
          appendInline(td, cellValue);
          tr.appendChild(td);
        }
        tbody.appendChild(tr);
      }

      table.appendChild(tbody);
      const wrap = document.createElement("div");
      wrap.className = "table-wrap";
      wrap.appendChild(table);
      fragment.appendChild(wrap);
      continue;
    }

    const heading = line.match(/^\s*(#{1,3})\s+(.+)$/);
    if (heading) {
      const headingLevel = heading[1].length + 2;
      const title = document.createElement(`h${headingLevel}`);
      appendInline(title, heading[2]);
      fragment.appendChild(title);
      index += 1;
      continue;
    }

    const bullet = line.match(/^\s*[-*]\s+(.+)$/);
    const numbered = line.match(/^\s*\d+[.)]\s+(.+)$/);
    if (bullet || numbered) {
      const list = document.createElement(numbered ? "ol" : "ul");
      while (index < lines.length) {
        const match = numbered
          ? lines[index].match(/^\s*\d+[.)]\s+(.+)$/)
          : lines[index].match(/^\s*[-*]\s+(.+)$/);
        if (!match) break;

        const li = document.createElement("li");
        appendInline(li, match[1]);
        list.appendChild(li);
        index += 1;
      }
      fragment.appendChild(list);
      continue;
    }

    const quote = line.match(/^\s*>\s?(.*)$/);
    if (quote) {
      const block = document.createElement("blockquote");
      appendInline(block, quote[1]);
      fragment.appendChild(block);
      index += 1;
      continue;
    }

    if (!line.trim()) {
      index += 1;
      continue;
    }

    const parts = [line];
    index += 1;
    while (
      index < lines.length
      && lines[index].trim()
      && !/^\s*\`\`\`/.test(lines[index])
      && !/^\s*#{1,3}\s+/.test(lines[index])
      && !/^\s*[-*]\s+/.test(lines[index])
      && !/^\s*\d+[.)]\s+/.test(lines[index])
      && !/^\s*>/.test(lines[index])
    ) {
      parts.push(lines[index++]);
    }

    const paragraph = document.createElement("p");
    appendInline(paragraph, parts.join("\n"));
    fragment.appendChild(paragraph);
  }

  node.replaceChildren(fragment);
}

export function addBadge(parent, value) {
  if (!value) return;
  const node = document.createElement("span");
  node.className = "source-badge";
  node.textContent = String(value);
  parent.appendChild(node);
}

export function addDetails(card, data) {
  if (data === undefined || data === null) return;

  const details = document.createElement("details");
  details.className = "tool-details";
  const summary = document.createElement("summary");
  summary.textContent = "جزئیات منبع";
  const pre = document.createElement("pre");

  try {
    pre.textContent = JSON.stringify(data, null, 2);
  } catch (_) {
    pre.textContent = String(data);
  }

  details.append(summary, pre);
  card.appendChild(details);
}

function operationalEntries(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return [];

  const source = data.data && typeof data.data === "object" && !Array.isArray(data.data) ? data.data : data;
  const first = (...keys) => {
    for (const key of keys) {
      if (source[key] !== undefined && source[key] !== null && source[key] !== "") return source[key];
    }
    return null;
  };

  const entries = [
    ["Status", first("status", "active_state", "active")],
    ["SubState", first("substate", "sub_state")],
    ["PID", first("pid", "main_pid")],
    ["CPU", first("cpu_usage", "cpu_percent")],
    ["Memory", first("memory_usage", "memory_percent")],
    ["Available", first("available", "available_bytes")],
  ];

  return entries.filter(([, value]) => value !== null).slice(0, 4);
}

export function addOperationalFacts(card, data) {
  const entries = operationalEntries(data);
  if (!entries.length) return;

  const facts = document.createElement("div");
  facts.className = "operational-facts";

  for (const [name, rawValue] of entries) {
    const item = document.createElement("div");
    item.className = "operational-fact";
    const label = document.createElement("span");
    label.textContent = name;
    const value = document.createElement("strong");
    const shouldAddPercent = ["CPU", "Memory"].includes(name) && typeof rawValue === "number";
    value.textContent = shouldAddPercent ? `${rawValue}%` : String(rawValue);
    item.append(label, value);
    facts.appendChild(item);
  }

  card.appendChild(facts);
}

export function addErrorMeta(card, data = {}) {
  const values = [
    ["Request", data.request_id],
    ["Component", data.component],
    ["Code", data.code],
  ].filter(([, value]) => Boolean(value));

  if (!values.length) return;
  const meta = document.createElement("div");
  meta.className = "error-meta";
  for (const [label, value] of values) {
    const chip = document.createElement("span");
    chip.textContent = `${label}: ${String(value)}`;
    meta.appendChild(chip);
  }
  card.appendChild(meta);
}
