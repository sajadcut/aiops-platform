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
    else if(url.includes('/narrative?'))data={snapshot_id:report.snapshot_id,language:'fa',status:'fallback',sections:[]};
    return {ok:true,status:200,json:async()=>data};
  };
  vm.runInThisContext(fs.readFileSync('dashboards/incident-command-room.js','utf8'));
  for(let i=0;i<18;i++)await new Promise(resolve=>setImmediate(resolve));
  const page=el('#ic-technical-report').innerHTML;
  assert.match(page,/Executive Incident Assessment/);
  assert.match(page,/سرویس و systemd/);
  assert.match(page,/Result=timeout/);
  assert.match(page,/evidence-systemd-123/);
  assert.match(page,/queried_zero_results/);
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
    assert "renderTechnicalInvestigation" in js
    assert "ic-sre-table" in css
    assert "ic-sre-drilldown" in js
    assert "details" in js
