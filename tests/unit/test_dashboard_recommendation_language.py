"""Language-switch regression for the incident's AIOps recommendation card."""
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]


def test_dashboard_recommendation_has_accessible_bilingual_controls():
    js = (ROOT / "dashboards/approval-actions.js").read_text(encoding="utf-8")
    css = (ROOT / "dashboards/approval-actions.css").read_text(encoding="utf-8")
    assert 'data-recommendation-lang="fa"' in js
    assert 'data-recommendation-lang="en"' in js
    assert "aria-pressed" in js
    assert "setAttribute('dir', language === 'en' ? 'ltr' : 'rtl')" in js
    assert "action.text_en" in js
    assert "action.text_fa" in js
    assert "recommendationArticle(summary.recommended_action)" in js
    assert ".operator-recommendation-switch button:focus-visible" in css
    assert ".operator-recommendation-original[hidden]" in css


def test_dashboard_recommendation_switches_between_persian_and_english_without_api_calls():
    node = shutil.which("node")
    if not node:
        pytest.skip("node is required for browser behavior regression")

    runner = r"""
const fs = require('fs'), vm = require('vm'), assert = require('assert');
const source = fs.readFileSync(process.argv[1], 'utf8');
const saved = new Map();
let clickHandler;
let lastMarkup = '';
let calls = 0;
const detail = {
  contains: () => true,
  querySelector: selector => selector === '.detail-head' ? {} : null,
  insertAdjacentHTML: (_location, html) => { lastMarkup = html; },
};
const document = {
  addEventListener: (type, handler) => { if (type === 'click') clickHandler = handler; },
  querySelector: selector => selector === '#detail' ? detail : null,
};
const summary = {
  summary_fa: 'خلاصه',
  recommended_action: {
    action: 'start_service', tool: 'ssh_vm', target: 'vm-01',
    text_fa: 'شروع سرویس روی vm-01',
    text_en: 'Proposed action: start_service via ssh_vm on vm-01.',
  },
};
const state = {operatorSummary: summary, selected: 'incident-1'};
const context = {
  window: null, document, S: state,
  localStorage: {
    getItem: name => saved.get(name) || null,
    setItem: (name, value) => { saved.set(name, value); },
  },
  renderDetail: () => {},
  selectIncident: () => {},
  loadAll: () => {},
  loadAgents: () => {},
  lower: v => String(v ?? '').toLowerCase(),
  esc: v => String(v ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c])),
  pct: v => String(v),
};
context.window = context;
vm.runInNewContext(source, context, {filename: 'approval-actions.js'});

context.renderDetail('overview');
assert.ok(lastMarkup.includes('>فارسی</button>'));
assert.ok(lastMarkup.includes('>English</button>'));
assert.ok(lastMarkup.includes('lang="fa" dir="rtl"'));
assert.ok(lastMarkup.includes('شروع سرویس روی vm-01'));
assert.strictEqual(state.recommendationLanguage, 'fa');
assert.strictEqual(typeof clickHandler, 'function');

const attrs = lang => ({
  'data-recommendation-lang': lang,
  'aria-pressed': 'false',
});
const enAttrs = attrs('en'), faAttrs = attrs('fa');
const content = {
  textContent: null,
  attributes: {},
  setAttribute: (key, value) => { content.attributes[key] = value; },
};
const card = {
  querySelectorAll: () => [faButton, enButton],
  querySelector: selector => selector === '[data-recommendation-text]' ? content : null,
};
const button = (values) => ({
  getAttribute: key => values[key],
  setAttribute: (key, value) => { values[key] = value; },
  closest: () => card,
});
const faButton = button(faAttrs), enButton = button(enAttrs);

clickHandler({target: {closest: () => enButton}});
assert.strictEqual(state.recommendationLanguage, 'en');
assert.strictEqual(saved.get('aiops.operator.recommendation_language'), 'en');
assert.strictEqual(enAttrs['aria-pressed'], 'true');
assert.strictEqual(faAttrs['aria-pressed'], 'false');
assert.strictEqual(content.textContent, summary.recommended_action.text_en);
assert.strictEqual(content.attributes.dir, 'ltr');
assert.strictEqual(content.attributes.lang, 'en');
assert.strictEqual(calls, 0);

context.renderDetail('overview');
assert.ok(lastMarkup.includes('lang="en" dir="ltr"'));
assert.ok(lastMarkup.includes('Proposed action: start_service via ssh_vm on vm-01.'));
clickHandler({target: {closest: () => faButton}});
assert.strictEqual(content.textContent, summary.recommended_action.text_fa);
assert.strictEqual(content.attributes.dir, 'rtl');

state.operatorSummary = {
  recommended_action: {text_fa: 'برای بررسی بیشتر مجوز لازم است'},
};
context.renderDetail('overview');
assert.ok(lastMarkup.includes('data-recommendation-original'));
assert.ok(lastMarkup.includes('hidden'));
clickHandler({target: {closest: () => enButton}});
context.renderDetail('overview');
assert.ok(lastMarkup.includes('An English translation is not available'));
assert.ok(lastMarkup.includes('برای بررسی بیشتر مجوز لازم است'));
assert.ok(!lastMarkup.includes('data-recommendation-original" lang="fa" dir="auto" hidden'));
"""
    result = subprocess.run(
        [node, "-e", runner, str(ROOT / "dashboards/approval-actions.js")],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr
