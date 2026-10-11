"""Exercise the actual browser Decision Brief wrapper with Node (no DOM package)."""
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(shutil.which("node") is None, reason="Node runtime is required for JS runtime test")
def test_decision_brief_renders_real_llm_sections_and_language_switch():
    script = r"""
const fs = require('fs');
const vm = require('vm');
const assert = require('node:assert/strict');

(async () => {
  const listeners = {};
  const pane = {innerHTML: ''};
  const button = {classList: {toggle() {}}, textContent: ''};
  const tabs = {querySelector: () => button, insertBefore() {}};
  global.window = global;
  global.S = {selected: null, detail: null};
  global.selectIncident = async id => {
    S.selected = id;
    S.detail = {context: {incident_id: id}, lifecycle: {approval: {status: 'pending'}}};
  };
  global.renderDetail = () => {};
  global.document = {
    querySelector(sel) {
      if (sel === '#detail .tabs') return tabs;
      if (sel === '#detailPane') return pane;
      if (sel === '.decision-brief') return pane.innerHTML.includes('decision-brief') ? pane : null;
      return null;
    },
    addEventListener(name, fn) {listeners[name] = fn;},
    createElement() {return {setAttribute() {}, addEventListener() {}, classList: {toggle() {}}};}
  };
  global.esc = value => String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;');
  global.localStorage = {getItem: () => 'fa', setItem() {}};
  global.toast = () => {};
  global.navigator = {clipboard: {writeText: async () => {}}};
  const incident = id => ({
    snapshot_id: 'snapshot-' + id, incident_summary: {incident_id: id, service: 'nginx'},
    localized_narrative: {fa: 'شرح فارسی ثبت‌شده', en: 'Stored incident facts'},
    remediation_recommendation: {action: 'restart_service', target: 'host-1'},
    approval_readiness: {status: 'human_review_required'}, source_references: ['ev-1'],
    agent_findings: [], mcp_evidence: [], monitoring_sources: [],
    cognia_knowledge: {status: 'empty', retrieved_count: 0}, operational_memory: {}
  });
  global.api = async url => {
    const pathIncident = url.match(/incidents\\/([^/]+)/)?.[1];
    if (url.endsWith('/decision-brief')) return incident(pathIncident);
    const lang = new URL('https://test.local' + url).searchParams.get('lang');
    const sectionText = lang === 'fa' ?
      'این گزارش بر اساس شواهد ثبت‌شده تهیه شده و تأیید عملیاتی لازم دارد.' :
      'This report uses durable evidence and requires operator approval.';
    return {snapshot_id: incident(pathIncident).snapshot_id, status: 'available',
      language: lang, sections: [{heading: lang === 'fa' ? 'شرح اتفاق' : 'Incident',
        text: sectionText, citations: ['ev-1']}]};
  };
  vm.runInThisContext(fs.readFileSync('dashboards/decision-brief.js', 'utf8'));
  await window.selectIncident('incident-1');
  await new Promise(resolve => setImmediate(resolve));
  assert.match(pane.innerHTML, /شرح اتفاق/);
  assert.match(pane.innerHTML, /بر اساس شواهد ثبت‌شده/);
  assert.match(pane.innerHTML, /ev-1/);
  assert.match(pane.innerHTML, /dir="rtl"/);
  await listeners.click({target: {closest(sel) {
    return sel === '[data-db-lang]' ? {getAttribute: () => 'en'} : null;
  }}});
  await new Promise(resolve => setImmediate(resolve));
  assert.match(pane.innerHTML, /This report uses durable evidence/);
  assert.match(pane.innerHTML, /dir="ltr"/);
  console.log('decision brief browser runtime passed');
})().catch(err => {console.error(err); process.exitCode = 1;});
"""
    result = subprocess.run(
        [shutil.which("node"), "-e", script],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert "browser runtime passed" in result.stdout
