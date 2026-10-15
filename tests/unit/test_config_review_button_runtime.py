"""Execute the real Incident Room click handler: buttons must POST read-only requests."""
from pathlib import Path
import shutil
import subprocess
import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js required")
def test_config_buttons_dispatch_mcp_read_without_execution_and_refresh_report():
    script = r"""
const fs=require('fs'),vm=require('vm'),assert=require('node:assert/strict');
(async()=>{
  const elements={}, listeners={}, requests=[];
  const el=s=>elements[s] ||= {
    hidden:false,innerHTML:'',textContent:'',value:'',dataset:{},attrs:{},
    disabled:false,classList:{add(){},remove(){},toggle(){}},
    setAttribute(k,v){this.attrs[k]=v;},
    addEventListener(k,fn){(this.handlers??={})[k]=fn;},
    focus(){},scrollIntoView(){},
  };
  global.window=global;
  global.location={pathname:'/dashboard/incidents/11111111-1111-4111-8111-111111111111'};
  global.document={
    readyState:'complete',documentElement:{lang:'fa',dir:'rtl',dataset:{theme:'dark'}},
    querySelector:el,
    querySelectorAll(){return []},
    addEventListener(k,fn){(listeners[k]??=[]).push(fn)},
  };
  global.addEventListener=()=>{};
  global.localStorage={getItem:k=>k==='aiops_api_key'?'test-key':null,setItem(){}};
  global.navigator={clipboard:{writeText:async()=>{}}};
  global.confirm=()=>true;
  global.scrollTo=()=>{};
  const base='/api/v1/incidents/11111111-1111-4111-8111-111111111111';
  let reads=0;
  const report={
    snapshot_id:'sha-1',
    incident_summary:{service:'nginx',status:'open',summary:'invalid config'},
    configuration_diagnostic:{status:'invalid',config_file:'/etc/nginx/nginx.conf',
                              error_line:103},
    dynamic_investigation:{
      status:'advisory',
      config_proposal:{status:'candidate_proposed',config_file:'/etc/nginx/nginx.conf',
        error_line:103,original_sha256:'a'.repeat(64),candidate_sha256:'b'.repeat(64),
        validation_status:'UNVERIFIED',apply_eligible:false},
      config_discovery:{status:'verified_candidates',
        files:[{path:'/etc/nginx/nginx.conf',verified_exists:true}]}
    },
    remediation_recommendation:{},approval_readiness:{status:'not_pending'},
    agent_findings:[],mcp_evidence:[],monitoring_sources:[],
    cognia_knowledge:{status:'not_queried',items:[]},operational_memory:{items:[]},
    timeline:[],source_references:[],
  };
  global.fetch=async (url,opts={})=>{
    const method=opts.method||'GET';
    requests.push({url,method,body:opts.body});
    let data;
    if(method==='POST' && url===base+'/chat'){
      data={followup_integration:{status:'reassessed_read_only',evidence_ref:'evidence-new',
        reassessed:true},answer:'بررسی MCP اجرا شد'};
    }else if(url===base+'/decision-brief'){
      reads++;data=report;
    }else if(url===base+'/lifecycle'){
      data={analysis_in_progress:false,checkpoint_status:'completed'};
    }else if(url===base+'/chat'){
      data={items:[],status:'ready'};
    }else if(url===base+'/configuration-review-response'){
      data={status:'not_responded'};
    }else if(url.includes('/decision-brief/narrative?')){
      data={status:'fallback',language:'fa',snapshot_id:'sha-1',sections:[]};
    }else if(url.includes('/received-signals?')){
      data={items:[],has_more:false};
    }else {
      data={};
    }
    return {ok:true,json:async()=>data};
  };
  vm.runInThisContext(fs.readFileSync('dashboards/incident-command-room.js','utf8'));
  for(let n=0;n<18;n++)await new Promise(resolve=>setImmediate(resolve));
  const banner=el('#ic-config-action-banner').innerHTML;
  assert.match(banner,/در خط/);
  assert.match(banner,/۱۰۳/);
  assert.match(banner,/\/etc\/nginx\/nginx.conf/);
  assert.match(banner,/خطای نحوی کانفیگ/);
  assert.match(banner,/بررسی و مشاهده اصلاح/);
  assert.doesNotMatch(banner,/فایل‌های تأییدشده: ۰|مشورت LLM: unavailable/);
  assert.match(banner,/جزئیات فنی/);
  const click=kind=>{
    const preview={dataset:{configPreview:kind}};
    for(const handler of listeners.click||[])handler({
      target:{closest:selector=>selector==='[data-config-preview]'?preview:null},
      preventDefault(){}
    });
  };
  click('nginx');
  for(let n=0;n<35;n++)await new Promise(resolve=>setImmediate(resolve));
  let calls=requests.filter(x=>x.method==='POST'&&x.url===base+'/chat');
  assert.equal(calls.length,1);
  assert.match(JSON.parse(calls[0].body).message,/^nginx_config_review:/);
  assert.ok(reads>=2,'completed MCP follow-up refreshes decision brief');
  assert.doesNotMatch(requests.map(x=>x.url).join(' '),/\/execute|\/restart|\/approve/);
  click('review');
  for(let n=0;n<35;n++)await new Promise(resolve=>setImmediate(resolve));
  calls=requests.filter(x=>x.method==='POST'&&x.url===base+'/chat');
  assert.equal(calls.length,2);
  assert.match(JSON.parse(calls[1].body).message,/^service_config_review:/);
  click('generic');
  for(let n=0;n<35;n++)await new Promise(resolve=>setImmediate(resolve));
  calls=requests.filter(x=>x.method==='POST'&&x.url===base+'/chat');
  assert.equal(calls.length,3);
  assert.match(JSON.parse(calls[2].body).message,/^service_config_discovery:/);
  assert.doesNotMatch(requests.map(x=>x.url).join(' '),/\/execute|\/restart|\/approve/);
  console.log('Read-only config button click PASS');
})().catch(error=>{console.error(error.stack||error);process.exitCode=1;});
"""
    result=subprocess.run([shutil.which("node"),"-e",script],cwd=ROOT,
                          capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
    assert "Read-only config button click PASS" in result.stdout
