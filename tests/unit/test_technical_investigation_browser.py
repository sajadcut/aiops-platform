"""Browser-runtime regression for the full-screen Incident Command Room SRE audit."""
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(shutil.which("node") is None, reason="Node required for DOM runtime test")
def test_section_01_shows_evidence_attributed_sre_report_without_commands():
    script = r"""
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
(async()=>{
  const els={};
  const el=id=>els[id]||=( {
    innerHTML:'',textContent:'',hidden:false,value:'',dataset:{},
    classList:{add(){},remove(){},toggle(){}},
    setAttribute(){},addEventListener(){},focus(){}
  });
  global.window=global;
  global.addEventListener=()=>{};
  global.location={pathname:'/dashboard/incidents/11111111-1111-4111-8111-111111111111'};
  global.localStorage={getItem:k=>k==='aiops_api_key'?'ci-test-key':null,setItem(){}};
  global.document={
    readyState:'complete',
    documentElement:{lang:'fa',dir:'rtl',dataset:{theme:'dark'}},
    querySelector:el,querySelectorAll:()=>[],
    addEventListener(){}
  };
  global.navigator={clipboard:{writeText:async()=>{}}};
  global.confirm=()=>true;
  global.scrollTo=()=>{};
  global.URLSearchParams=URLSearchParams;
  const posted=[];
  const report={
    snapshot_id:'sre-snapshot-123',generated_at:'2026-10-14T10:00:00Z',
    incident_summary:{incident_id:'11111111-1111-4111-8111-111111111111',service:'gfpapi',
      severity:'critical',status:'analyzing',total_evidence_count:40,valid_evidence_count:25},
    remediation_recommendation:{risk_level:'high'},
    approval_readiness:{status:'not_pending',approval_status:null,binding_complete:false},
    rca_assessment:{rca_confidence:0.2},
    localized_narrative:{fa:'شواهد ثبت‌شده',en:'Recorded evidence'},
    configuration_diagnostic:{status:'invalid',path_source:'dotnet_config_syntax',
      config_file:'/data/gfp/gfpapi/appsettings.json',error_line:32,error_column:3,
      syntax_error:'نام کلید باید داخل کوتیشن دوتایی باشد.',
      remote_python_required:false,validator_location:'aiops_worker'},
    operator_explanation:{headline_fa:'خطای ساختار JSON در کانفیگ GFPAPI تأیید شده است.',
      confirmed_findings:[{text_fa:'بررسی appsettings.json خط ۳۲ ناموفق است.',
        evidence_refs:['evidence-config-32']}],
      uncertainties_fa:['ارتباط خطا با Timeout هنوز قطعی نیست.'],
      next_steps_fa:['اصلاح فایل با فرایند مجاز، تست دوباره و درخواست Approval.'],
      approval_explanation_fa:'هیچ اقدام اجرایی مجاز نیست.'},
    mcp_evidence:[],agent_findings:[],monitoring_sources:[],
    source_references:[],timeline:[],
    technical_investigation:{
      service:'gfpapi',host:'10.248.16.82',
      executive_lines:['gfpapi failed on 10.248.16.82','systemd Result=timeout',
        'Elasticsearch queried: Match=0','Journal not collected',
        'RAM unknown','Disk unknown','Read-only: inspect journal'],
      domains:[
        {key:'systemd',title:'سرویس و systemd',status:'investigated',
         technical_result:'ActiveState=failed; Result=timeout; MainPID=0',
         importance:'بحرانی',observed_at:'2026-10-14T10:00:00Z',
         source:'vm_mcp',evidence:[{id:'evidence-systemd-123',tool:'service_status',
           observed_at:'2026-10-14T10:00:00Z',freshness:'fresh',
           facts:{active_state:'failed',result:'timeout',main_pid:0}}]},
        {key:'elastic',title:'Elasticsearch / ELK',status:'queried_zero_results',
         technical_result:'Query موفق: 1؛ Match=0؛ صفر نتیجه، سلامت سرویس را ثابت نمی‌کند.',
         importance:'بالا',source:'elasticsearch',evidence:[]},
        {key:'journal',title:'لاگ سیستم‌عامل و Journal',status:'not_queried',
         technical_result:'برای این حوزه نتیجهٔ فنی ثبت نشده است.',
         missing_reason:'Journal جمع‌آوری نشده است.',
         collection_hint:'VM MCP: service_logs',importance:'بالا',source:'vm_mcp',evidence:[]}
      ],
      rca:{confirmed_facts:[{text:'توقف systemd تأیید شد.',evidence_refs:['evidence-systemd-123']}],
        likely_hypotheses:[{title:'Startup dependency',
          supporting:['evidence-systemd-123'],opposing:[],
          check:'Journal و Dependency را تطبیق دهید.',kind:'Hypothesis'}],
        remaining_unknowns:[{domain:'Journal',reason:'جمع‌آوری نشده',next_check:'service_logs'}],
        ruled_out:[],cause_confirmed:false,note:'Timeout به‌تنهایی علت نیست.'},
      actions:{read_only:[{title:'Journal',goal:'بررسی Startup',
        tool:'vm_mcp',prerequisite:'Read-only',status:'proposed_not_executed',
        expected:'service_logs',if_positive:'Correlate',if_negative:'Escalate',
        approval_required:false}],
        conditional:[{title:'Restart',goal:'Recovery',tool:'Governed',
          prerequisite:'Approval',status:'proposed_not_executed',
          expected:'Verification',if_positive:'Verify',if_negative:'Escalate',
          approval_required:true}],
        prohibited:['حذف syslog بدون مجوز']}
    }
  };
  global.fetch=async(url,options={})=>{
    const method=options.method||'GET';
    if(method!=='GET') posted.push([method,url]);
    if(url.endsWith('/progress/stream'))return {ok:false,status:404,json:async()=>({})};
    let data={};
    if(url.endsWith('/decision-brief'))data=report;
    else if(url.endsWith('/lifecycle'))data={approval:{status:'not_pending'}};
    else if(url.includes('/narrative?'))data={snapshot_id:report.snapshot_id,language:'fa',
      status:'available',sections:[
        {key:'cause',heading:'تحلیل هوشمند علت',text:'خطای JSON در appsettings تأیید شده؛ علت Timeout هنوز قطعی نیست.',citations:['evidence-config-32']},
        {key:'evidence_gaps',heading:'شواهد موردنیاز',text:'لاگ شروع برنامه را باید با خطای کانفیگ تطبیق داد.',citations:['evidence-config-32']},
        {key:'advice',heading:'پیشنهاد بررسی',text:'ابتدا بررسی و اصلاح مجاز، سپس تست مجدد و درخواست مجوز جداگانه.',citations:['evidence-config-32']},
      ]};
    return {ok:true,status:200,json:async()=>data};
  };
  vm.runInThisContext(fs.readFileSync('dashboards/incident-command-room.js','utf8'));
  for(let i=0;i<18;i++)await new Promise(resolve=>setImmediate(resolve));
  const page=el('#ic-technical-report').innerHTML;
  const diagnosis=el('#ic-diagnosis').innerHTML;
  const intelligence=el('#ic-intelligence-report').innerHTML;
  assert.match(intelligence,/گزارش هوشمندِ مبتنی بر شواهد/);
  assert.match(intelligence,/توقف سرویس از طریق Systemd تأیید شده است/);
  assert.match(intelligence,/ActiveState=failed; Result=timeout; MainPID=0/);
  assert.match(intelligence,/evidence-systemd-123/);
  assert.match(intelligence,/Elasticsearch/);
  assert.match(intelligence,/Query موفق؛ صفر نتیجه/);
  assert.match(intelligence,/صفر نتیجه، سلامت سرویس را ثابت نمی‌کند/);
  assert.match(intelligence,/appsettings.json/);
  assert.match(intelligence,/فقط ساختار JSON/);
  assert.match(intelligence,/علت ریشه‌ای هنوز تأیید نشده است/);
  assert.match(intelligence,/Approval/);
  assert.doesNotMatch(intelligence,/علت ریشه‌ای در شواهد این گزارش تأیید شده است/);
  assert.doesNotMatch(intelligence,/undefined/);

  assert.match(diagnosis,/خطای ساختار JSON/);
  assert.match(diagnosis,/appsettings.json/);
  assert.match(diagnosis,/خط ۳۲/);
  assert.match(diagnosis,/کوتیشن/);
  assert.match(diagnosis,/نیازی به نصب Python روی VM/);
  assert.match(diagnosis,/چه چیزی واقعاً بررسی و تأیید شده/);
  assert.match(diagnosis,/چه چیزی هنوز قطعی نیست/);
  assert.match(diagnosis,/AIOps پیشنهاد می‌کند چه کار کنیم/);
  assert.match(diagnosis,/Start ایمن تأیید نشده/);
  assert.match(el('#ic-brief-lead').innerHTML,/توضیح تکمیلی مبتنی بر شواهد/);
  assert.match(el('#ic-brief-lead').innerHTML,/تحلیل هوشمند علت/);
  assert.match(el('#ic-brief-lead').innerHTML,/لاگ شروع برنامه/);
  assert.doesNotMatch(diagnosis,/اجرای عملیات.*موفق/);
  assert.match(page,/جمع‌بندی تخصصی اولیه/);
  assert.match(page,/گزارش کامل فنی و ممیزی/);
  assert.match(page,/<details class="ic-diagnosis-drilldown">/);
  assert.match(page,/سرویس و systemd/);
  assert.match(page,/Result=timeout/);
  assert.match(page,/evidence-systemd-123/);
  assert.match(page,/استعلام شد؛ بدون نتیجه/);
  assert.match(page,/Journal جمع‌آوری نشده/);
  assert.match(page,/Root Cause Analysis/);
  assert.match(page,/Startup dependency/);
  assert.match(page,/Approval REQUIRED/);
  assert.match(page,/حذف syslog بدون مجوز/);
  assert.equal(posted.length,0);
  assert.doesNotMatch(page,/undefined/);
})();
"""
    result = subprocess.run(
        ["node", "-e", script], cwd=ROOT, capture_output=True,
        text=True, timeout=25,
    )
    assert result.returncode == 0, result.stdout + "\n" + result.stderr


def test_section_01_has_real_render_target_and_accessible_evidence_table():
    html = (ROOT / "dashboards/incident-command-room.html").read_text(encoding="utf-8")
    js = (ROOT / "dashboards/incident-command-room.js").read_text(encoding="utf-8")
    css = (ROOT / "dashboards/incident-command-room.css").read_text(encoding="utf-8")
    assert 'id="ic-technical-report"' in html
    assert 'id="ic-intelligence-report"' in html
    assert 'ic-overview-details' in html
    assert 'id="ic-diagnosis"' in html
    assert "renderOperatorDiagnosis" in js
    assert "ic-diagnosis-drilldown" in css
    assert "renderTechnicalInvestigation" in js
    assert "renderIntelligenceReport" in js
    assert 'data-report-version="evidence-narrative-v1"' in js
    assert "ic-sre-table" in css
    assert "ic-sre-drilldown" in js
    assert "details" in js
