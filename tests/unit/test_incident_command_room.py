"""Full-screen Incident Command Room acceptance: navigation, real controls, mobile and safety."""
from pathlib import Path
import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient

from apps.api.main import app


ROOT = Path(__file__).resolve().parents[2]
INCIDENT = "11111111-1111-4111-8111-111111111111"


def test_dedicated_page_is_a_real_deep_link_not_a_compressed_dashboard_side_panel():
    client = TestClient(app)
    response = client.get(f"/dashboard/incidents/{INCIDENT}")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert 'dir="rtl"' in response.text
    assert 'id="ic-main"' in response.text
    assert 'id="ic-decision-card"' in response.text
    assert 'id="ic-evidence"' in response.text
    assert 'id="ic-outcome"' in response.text
    assert "detail-panel" not in response.text
    assert "/dashboard/incident-command-room.js" in response.text
    assert client.get("/dashboard/incidents/not-a-uuid").status_code == 404
    assert client.get("/dashboard/incident-command-room.js").status_code == 200
    assert client.get("/dashboard/incident-command-room.css").status_code == 200


def test_dashboard_incident_queue_routes_attention_to_full_screen():
    html = (ROOT / "dashboards/index.html").read_text(encoding="utf-8")
    js = (ROOT / "dashboards/control-center.js").read_text(encoding="utf-8")
    css = (ROOT / "dashboards/control-center.css").read_text(encoding="utf-8")
    assert "incident-queue-card" in html
    assert "needs-decision" in html
    assert "فهرست رخدادهای ثبت‌شده" in html
    assert "const sourceRows = archived ? S.archivedIncidents : S.incidents;" in html
    assert "sourceRows.filter" in html
    assert "S.incidents = incidents.items || []" in js
    assert "S.archivedIncidents = result.items || []" in js
    assert "encodeURIComponent(i.id)" in html
    assert "selectIncident('${esc(i.id)}')" not in html
    assert "window.location.assign('/dashboard/incidents/'" in js
    assert "No implicit selection" in js
    assert "grid-template-columns:repeat(2,minmax(0,1fr))" in css
    assert "@media(max-width:650px)" in css


def test_command_room_has_readable_mobile_layout_and_two_stage_actions():
    html = (ROOT / "dashboards/incident-command-room.html").read_text(encoding="utf-8")
    css = (ROOT / "dashboards/incident-command-room.css").read_text(encoding="utf-8")
    js = (ROOT / "dashboards/incident-command-room.js").read_text(encoding="utf-8")
    for part in ("ic-overview", "ic-review", "ic-analysis", "ic-evidence", "ic-knowledge",
                 "ic-outcome", "ic-history", "ic-decision-column", "ic-archive-banner"):
        assert part in html or part in css
    assert 'href="/dashboard?view=incidents"' in html
    assert 'data-lang="fa"' in html and 'data-lang="en"' in html
    assert "aiops.chatbot.theme" in html
    assert "aiops.decision-brief.language" in js
    assert "max-width:650px" in css
    assert "prefers-reduced-motion:reduce" in css
    assert "position:sticky" in css
    assert "minmax(310px,365px)" in css
    assert "firstApprove" in js and "firstResume" in js
    assert "['high','critical'].includes" in js
    assert "/api/v1/approvals/" in js
    assert "/api/v1/workflow/e2e/" in js
    assert "/api/v1/execute" not in js
    assert "reviewedSnapshot" in js
    assert "latest.snapshot_id!==snapshot" in js
    assert "if(state.busy||state.historic" in js
    assert "navigator.clipboard.writeText" in js
    assert "No implicit selection" in (ROOT / "dashboards/control-center.js").read_text(encoding="utf-8")


@pytest.mark.skipif(shutil.which("node") is None, reason="Node required for real UI JavaScript runtime")
def test_command_room_renders_and_only_posts_after_deliberate_confirmed_approval():
    script = r"""
const fs = require('fs');
const vm = require('vm');
const assert = require('node:assert/strict');
(async () => {
  const elements = {};
  const listeners = {};
  const el = selector => elements[selector] ||= {
    hidden:false, innerHTML:'', textContent:'', value:'', dataset:{},
    classList:{add(){},remove(){},toggle(){}},
    addEventListener(name, cb) {this.events ||= {}; this.events[name] = cb;},
    focus(){}, setAttribute(){},
  };
  const langNode = lang => ({dataset:{lang},events:{},setAttribute(){},
    addEventListener(name,cb){this.events[name]=cb;}});
  const l10n = [langNode('fa'),langNode('en')];
  global.window = global;
  global.addEventListener = (type,handler) => {listeners['window:'+type]=handler;};
  global.location = {pathname:'/dashboard/incidents/11111111-1111-4111-8111-111111111111'};
  global.document = {
    readyState:'complete',
    documentElement:{lang:'fa',dir:'rtl',dataset:{theme:'dark'}},
    querySelector: el,
    querySelectorAll(selector) {return selector==='[data-lang]'?l10n:[];},
    addEventListener(type,handler) {listeners[type]=handler;},
  };
  global.localStorage = {
    store:new Map([['aiops_api_key','ci-test-key']]),
    getItem(key){return this.store.get(key)||null;},
    setItem(key,val){this.store.set(key,val);}
  };
  global.confirm = () => true;
  global.navigator = {clipboard:{writeText: async()=>{}}};
  global.scrollTo = () => {};
  global.URLSearchParams = URLSearchParams;
  const events = [];
  const incidentId='11111111-1111-4111-8111-111111111111';
  let approvalStatus='pending', version=0;
  const brief=()=>({
    snapshot_id:'durable-snapshot-'+approvalStatus+'-'+version,
    incident_summary:{incident_id:incidentId,service:'nginx',summary:'systemd reported inactive',
      severity:'high',status:'escalated',valid_evidence_count:3,started_at:'2026-10-11T02:00:00Z',
      likely_cause:'Service stopped',cause_status:'hypothesis',elapsed_seconds:3600},
    approval_readiness:{approval_id:'22222222-2222-4222-8222-222222222222',
      approval_status:approvalStatus,binding_complete:true,tool:'ssh_vm',
      target:'vm-01',action:'start_service',evidence_snapshot_binding:'matched_at_read'},
    remediation_recommendation:{action:'start_service',tool:'ssh_vm',target:'vm-01',risk_level:'high',
      why:'Collected state says inactive'},
    localized_narrative:{fa:'سرویس از دسترس خارج شده است.',en:'Service is offline.'},
    rca_assessment:{rca_confidence:0.72,evaluator_confidence:0.67,agent_agreement:0.7},
    operator_explanation:{
      headline_fa:'خطای معتبر در کانفیگ JSON پیدا شد؛ هنوز Start مجاز نیست.',
      confirmed_findings:[{text_fa:'JSON فایل appsettings.json خط ۳۲ نامعتبر است.',
        evidence_refs:['ev-config']}],
      uncertainties_fa:['علت توقف اولیه هنوز اثبات نشده است.'],
      next_steps_fa:['بررسی خط ۳۲؛ اصلاح کنترل‌شده، سپس تست مجدد و تأیید مستقل.'],
      approval_explanation_fa:'در حال حاضر هیچ اقدام اجرایی قابل تأیید ثبت نشده است.'
    },
    configuration_diagnostic:{status:'invalid',config_file:'/etc/nginx/nginx.conf',
      error_line:42,syntax_error:'unknown directive on config line',evidence_refs:['ev-config'],
      repair_then_revalidate:true,start_requires_valid_config_and_approval:true},
    unknown_guidance:{status:'suggested',execution_authority:false,
      items:[{topic:'config_syntax_repair_guidance',subject:'nginx',
        validation_approach:'Inspect offending directive in vendor documentation'}]},
    disk_file_causality:{
      files:[{path:'/var/log/gfpapi/error.log',size_bytes:37000000000,mount:'/var',
        growth_measured:true,growth_confirmed:true,growth_bytes_over_2_seconds:700160000,
        open_handles:[{pid:2020,process_name:'gfpapi',writable_handle_observed:true,
          writer_causality_verified:false}],safe_to_delete:false,causal_attribution:'unknown'}],
      related_error_log_observations:[{reference:'elastic1'}],
      zabbix_alert_refs:['zbx1'],
      candidate_temporal_overlaps:[{file:'/var/log/gfpapi/error.log',error_ref:'elastic1',
        meaning:'temporal_coincidence_only',causality_confirmed:false}],
      delete_recommendation_allowed:false,
    },
    agent_findings:[
      {agent:'VM',status:'partial',finding:'systemd inactive',confidence:0.93,evidence_coverage:0.71,
       findings:['active_state=inactive','valid=true'],evidence_refs:['vm:vm01:service_status:2026','vm:vm01:config_validate:2026'],
       hypotheses:[{text:'Possibly stopped manually',probability:0.34,falsification_checks:['Read auditd events']}],
       missing_evidence:['auditd logs for systemctl commands'],recommended_checks:['Read system journal']},
      {agent:'network',status:'success',confidence:0.32,evidence_coverage:0.6,
       finding:'No network failure confirmed',findings:['Port 8080 is not listening',
         'Custom BGP neighbor anomaly requires correlation'],
       evidence_refs:['vm:vm01:tcp_check:2026']},
    ],
    monitoring_sources:[{source:'Prometheus',status:'unavailable'}],
    mcp_evidence:[{server:'VM Edge',tool:'service_status',status:'success',finding:'inactive',evidence_ref:'ev1'}],
    cognia_knowledge:{status:'empty',retrieved_count:0},operational_memory:{retrieved_count:0},
    missing_evidence:['Prometheus unavailable'],data_freshness:'mixed',
    source_references:['ev1'],timeline:[]
  });
  global.fetch = async (url,options={})=>{
    const method=options.method||'GET'; events.push([method,url,options]);
    let data;
    if(method==='GET'&&url.endsWith('/progress/stream')) {
      assert.equal(options.headers['X-API-Key'],'ci-test-key');
      const live={schema:'incident_progress.v1',analysis_percent:17,
        analysis_completed:1,analysis_total:6,execution_percent:0,execution_total:3,
        incident_status:'escalated',approval_status:'pending',checkpoint_status:'paused',
        current_stage:'triage',started_at:'2026-10-13T12:00:00Z',
        last_event_at:'2026-10-13T12:00:20Z',
        stages:{context:{status:'completed',at:'2026-10-13T12:00:10Z'},
          triage:{status:'started',at:'2026-10-13T12:00:20Z'}},
        providers:{zabbix:{status:'completed',at:'2026-10-13T12:00:06Z'},
          vm_mcp:{status:'completed',at:'2026-10-13T12:00:09Z'}}};
      const message='event: progress\ndata: '+JSON.stringify(live)+'\n\n';
      return {ok:true,body:new ReadableStream({start(controller){
        controller.enqueue(new TextEncoder().encode(message));controller.close();
      }})};
    }
    if(method==='GET'&&url.endsWith('/decision-brief'))data=brief();
    else if(method==='GET'&&url.endsWith('/lifecycle'))
      data={checkpoint_status:'paused',approval:{approval_id:'22222222-2222-4222-8222-222222222222',status:approvalStatus,risk_level:'high'}};
    else if(method==='GET'&&url.includes('/narrative?'))
      data={snapshot_id:brief().snapshot_id,language:'fa',status:'fallback',sections:[]};
    else if(method==='GET'&&url.includes('/history?'))data={items:[]};
    else if(method==='POST'&&url.endsWith('/approve')){approvalStatus='approved';data={status:'approved'};}
    else if(method==='POST'&&url.includes('/resume')){approvalStatus='consumed';version++;data={status:'completed'};}
    else if(method==='POST'&&url.endsWith('/reject')){approvalStatus='rejected';data={status:'rejected'};}
    else throw Error('unexpected '+method+' '+url);
    return {ok:true,json:async()=>data};
  };
  vm.runInThisContext(fs.readFileSync('dashboards/incident-command-room.js','utf8'));
  const settle=async()=>{for(let i=0;i<8;i++)await new Promise(resolve=>setImmediate(resolve));};
  await settle();
  assert.equal(el('#ic-main').hidden,false);
  assert.match(el('#ic-title').textContent,/nginx/);
  assert.match(el('#ic-flow-percent').textContent,/۱۷٪/);
  assert.equal(el('#ic-flow-bar').value,17);
  assert.match(el('#ic-flow-steps').innerHTML,/Zabbix MCP/);
  assert.match(el('#ic-flow-steps').innerHTML,/VM MCP/);
  assert.match(el('#ic-flow-steps').innerHTML,/تریاژ آلارم/);
  assert.match(el('#ic-flow-caution').textContent,/تخمین زمان باقی‌مانده نیست/);
  assert.match(el('#ic-brief-lead').innerHTML,/سرویس از دسترس/);
  const briefing=el('#ic-operator-explanation').innerHTML;
  assert.match(briefing,/خطای معتبر در کانفیگ JSON/);
  assert.match(briefing,/چه چیزهایی واقعاً بررسی و تأیید شده/);
  assert.match(briefing,/appsettings.json خط ۳۲/);
  assert.match(briefing,/چه چیزهایی هنوز نامشخص است/);
  assert.match(briefing,/قدم بعدی پیشنهادی AIOps/);
  assert.match(briefing,/هیچ اقدام اجرایی قابل تأیید/);
  assert.match(el('#ic-sources').innerHTML,/Prometheus/);
  assert.match(el('#ic-agent-summary').innerHTML,/ایجنت‌های ثبت‌شده/);
  const configCard=el('#ic-config-diagnostic').innerHTML;
  assert.match(configCard,/آخرین تست ثبت‌شده، خطای کانفیگ را نشان می‌دهد/);
  assert.match(configCard,/nginx.conf/);
  assert.match(configCard,/خط ۴۲/);
  assert.match(configCard,/اصلاح/);
  assert.match(configCard,/Start سرویس برای تأیید اپراتور پیشنهاد/);
  assert.match(configCard,/استعلام موارد نامشخص از LLM/);
  assert.match(configCard,/هیچ فرمانی از LLM اجرا نشده/);
  const diskCard=el('#ic-disk-forensics').innerHTML;
  assert.match(diskCard,/gfpapi\/error.log/);
  assert.match(diskCard,/رشد مشاهده‌شده/);
  assert.match(diskCard,/gfpapi/);
  assert.match(diskCard,/PID/);
  assert.match(diskCard,/هم‌زمانی نزدیک تغییر فایل با خطا/);
  assert.match(diskCard,/حذف مجاز نیست/);
  assert.match(diskCard,/هیچ درخواست پاک‌سازی صادر نشده/);
  const agentHtml=el('#ic-agents').innerHTML;
  assert.equal((agentHtml.match(/class="ic-agent-card"/g)||[]).length,2);
  assert.match(agentHtml,/بررسی ماشین مجازی/);
  assert.match(agentHtml,/بررسی شبکه/);
  assert.match(agentHtml,/VMAgent/);
  assert.match(agentHtml,/NetworkAgent/);
  assert.match(agentHtml,/متن اصلی ثبت‌شده توسط ایجنت \(ترجمه نشده\)/);
  assert.match(agentHtml,/Custom BGP neighbor anomaly requires correlation/);
  assert.doesNotMatch(agentHtml,/شرح فارسی تأییدشده برای این یافته موجود نیست/);
  assert.doesNotMatch(agentHtml,/متخصص/);
  assert.match(agentHtml,/۹۳٪/);
  assert.match(agentHtml,/۳۲٪/);
  assert.match(agentHtml,/۷۱٪/);
  assert.match(agentHtml,/سرویس متوقف است/);
  assert.match(agentHtml,/بررسی درستی تنظیمات/);
  assert.match(agentHtml,/اطلاعات موردنیاز برای قطعیت بیشتر/);
  assert.match(agentHtml,/فرضیه‌های این ایجنت/);
  assert.match(agentHtml,/اجرای مستقیم SSH یا MCP/);
  assert.match(el('#ic-action-controls').innerHTML,/disabled/);
  assert.equal(events.filter(x=>x[0]==='POST').length,0);
  listeners.change({target:{id:'ic-check',checked:true}});
  assert.doesNotMatch(el('#ic-action-controls').innerHTML.match(/id="ic-approve"[^>]*>/)[0],/disabled/);
  const click=(selector)=>listeners.click({target:{closest(sel){return sel===selector?{}:null;}}});
  // The backend changes its durable snapshot after the operator reviewed it.
  // The first click MUST NOT authorize an action on that stale report.
  version++;
  click('#ic-approve');
  await settle();
  assert.equal(events.filter(x=>x[0]==='POST').length,0);
  assert.match(el('#ic-action-controls').innerHTML,/disabled/);
  listeners.change({target:{id:'ic-check',checked:true}});
  click('#ic-approve');
  await settle();
  assert.equal(events.filter(x=>x[0]==='POST'&&x[1].endsWith('/approve')).length,1);
  assert.equal(events.filter(x=>x[0]==='POST'&&x[1].includes('/resume')).length,0);
  assert.match(el('#ic-action-controls').innerHTML,/ic-resume/);
  listeners.change({target:{id:'ic-check',checked:true}});
  click('#ic-resume');
  await settle();
  assert.equal(events.filter(x=>x[0]==='POST'&&x[1].includes('/resume')).length,1);
  assert.match(el('#ic-action-state').innerHTML,/consumed|مصرف/);
  // Language switching is real, not a header-only cosmetic toggle.
  const english=l10n[1].dataset.lang;
  const callback = l10n[1].events.click;
  assert.equal(typeof callback,'function');
  callback();
  assert.equal(document.documentElement.dir,'ltr');
  assert.match(el('#ic-action-state').innerHTML,/Consumed|consumed/);
  console.log('Incident Command Room safe approval runtime PASS');
})().catch(e=>{console.error(e);process.exitCode=1;});
"""
    proc = subprocess.run(
        [shutil.which("node"), "-e", script],
        cwd=ROOT, capture_output=True, text=True, timeout=20,
    )
    assert proc.returncode == 0, proc.stderr
    assert "safe approval runtime PASS" in proc.stdout


@pytest.mark.skipif(shutil.which("node") is None, reason="Node required for browser runtime regression")
def test_completed_chat_incident_routes_execute_to_approved_api_not_workflow_resume():
    # Reuse the realistic browser harness above with a *completed* checkpoint,
    # exactly as reproduced by GFPAPI on 2026-10-13. This verifies the actual
    # click handler, not just the existence of endpoint strings.
    source = Path(__file__).read_text(encoding="utf-8")
    start = source.index('    script = r"""') + len('    script = r"""')
    end = source.index('"""', start)
    script = source[start:end]
    patterns = (
        ("let approvalStatus='pending', version=0;",
         "let approvalStatus='pending', version=0;"),
        ("data={checkpoint_status:'paused',approval:{approval_id:'22222222-2222-4222-8222-222222222222',status:approvalStatus,risk_level:'high'}};",
         "data={checkpoint_status:'completed',approval:{approval_id:'22222222-2222-4222-8222-222222222222',status:approvalStatus,risk_level:'high'}};"),
        ("else if(method==='POST'&&url.includes('/resume')){approvalStatus='consumed';version++;data={status:'completed'};}",
         "else if(method==='POST'&&url.endsWith('/execute')){approvalStatus='consumed';version++;data={status:'completed'};}"),
        ("assert.equal(events.filter(x=>x[0]==='POST'&&x[1].includes('/resume')).length,1);",
         "assert.equal(events.filter(x=>x[0]==='POST'&&x[1].endsWith('/execute')).length,1);\n"
         "  assert.equal(events.filter(x=>x[0]==='POST'&&x[1].includes('/resume')).length,0);"),
    )
    for before, after in patterns:
        assert before in script, before
        script = script.replace(before, after, 1)
    proc = subprocess.run(
        [shutil.which("node"), "-e", script],
        cwd=ROOT, capture_output=True, text=True, timeout=20,
    )
    assert proc.returncode == 0, proc.stderr
    assert "safe approval runtime PASS" in proc.stdout


def test_completed_incident_execution_route_matches_governed_backend():
    room = (ROOT / "dashboards/incident-command-room.js").read_text(encoding="utf-8")
    dashboard = (ROOT / "dashboards/approval-actions.js").read_text(encoding="utf-8")
    api = (ROOT / "apps/api/remediation.py").read_text(encoding="utf-8")
    for source in (room, dashboard):
        assert "checkpoint==='completed'" in source or "checkpoint === 'completed'" in source
        assert "checkpoint==='paused'" in source or "checkpoint === 'paused'" in source
        assert "/api/v1/approvals/" in source and "/execute" in source
        assert "/api/v1/workflow/e2e/" in source and "/resume" in source
    assert '@router.post("/approvals/{approval_id}/execute")' in api
    assert 'require_permission("execute:approved")' in api
