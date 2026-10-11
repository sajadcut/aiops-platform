"""Browser-level regression: English JSON cannot leak into Persian view."""
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_persian_tab_fetches_translation_only_once_and_ignores_stale_incident():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js required for JS behavior test")
    runner = r"""
const fs = require('fs'), vm = require('vm'), assert = require('assert');
const source = fs.readFileSync(process.argv[1], 'utf8');
let lastMarkup = '', count = 0;
let resolveFirst;
const calls = [];
const translatedText = {
  textContent: null,
  setAttribute: () => {},
};
const detail = {
  contains: () => true,
  querySelector: selector => selector === '.detail-head'
    ? {insertAdjacentHTML: (_pos, html) => {lastMarkup = html;}} : null,
};
const document = {
  addEventListener: () => {},
  querySelector: selector => selector === '#detail' ? detail
    : selector === '#detail .operator-recommendation [data-recommendation-text]' ? translatedText : null,
};
const plan = JSON.stringify({assessment: {summary: 'TCP port 86 is down on 10.100.6.199'}});
const S = { selected: 'incident-1', operatorSummary: {
  summary_fa: 'خلاصه فارسی',
  recommended_action: {
    tool: null, action: null, target: null,
    text_fa: null, text_en: plan, needs_persian_translation: true,
  },
}};
const context = {
  window: null, document, S,
  localStorage: {getItem: () => null, setItem: () => {}},
  renderDetail: () => {},
  selectIncident: () => {}, loadAll: () => {}, loadAgents: () => {},
  api: path => {
    count++;
    calls.push(path);
    return new Promise(resolve => {resolveFirst = resolve;});
  },
  lower: value => String(value ?? '').toLowerCase(),
  esc: value => String(value ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c])),
  pct: value => String(value ?? ''),
};
context.window = context;
vm.runInNewContext(source, context, {filename: 'approval-actions.js'});

(async () => {
  context.renderDetail('overview');
  assert.ok(lastMarkup.includes('در حال آماده‌سازی ترجمه فارسی'), lastMarkup);
  assert.ok(!lastMarkup.includes('TCP port 86 is down'), 'English JSON leaked into Persian tab');
  assert.strictEqual(count, 1);
  assert.strictEqual(calls[0], '/api/v1/incidents/incident-1/operator-recommendation/fa');
  context.renderDetail('overview');
  assert.strictEqual(count, 1, 're-render must not trigger duplicate LLM call');
  resolveFirst({
    incident_id: 'incident-1',
    text_fa: 'پورت 86 روی میزبان 10.100.6.199 قطع است؛ علت دقیق هنوز تأیید نشده است.',
  });
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
  assert.ok(translatedText.textContent.includes('پورت 86'), translatedText.textContent);
  assert.ok(!translatedText.textContent.includes('TCP port 86'));
  context.renderDetail('overview');
  assert.strictEqual(count, 1);
  assert.ok(lastMarkup.includes('پورت 86 روی میزبان'));

  S.selected = 'incident-2';
  S.operatorSummary.recommended_action.text_en = plan + ' second incident';
  context.renderDetail('overview');
  assert.strictEqual(count, 2);
  const oldText = translatedText.textContent;
  S.selected = 'incident-3';
  resolveFirst({
    incident_id: 'incident-2',
    text_fa: 'نباید در رخداد دیگری نمایش داده شود.',
  });
  await Promise.resolve();
  await Promise.resolve();
  assert.strictEqual(translatedText.textContent, oldText);
})().catch(error => {process.stderr.write(String(error.stack || error));process.exitCode=1;});
"""
    result = subprocess.run(
        [node, "-e", runner, str(ROOT / "dashboards/approval-actions.js")],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr
