"""Browser-level check that the new tab renders real multi-source ingress safely."""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js required")
def test_zabbix_tags_prometheus_labels_and_elk_original_alert_render():
    script = r"""
const fs=require('fs'),vm=require('vm'),assert=require('node:assert/strict');
(async()=>{
  const elements={}, listeners={}, langListeners=[];
  const el=s=>elements[s] ||= {
    hidden:false,innerHTML:'',textContent:'',value:'',dataset:{},attrs:{},
    classList:{add(){},remove(){},toggle(){}},
    setAttribute(k,v){this.attrs[k]=v;},
    addEventListener(k,fn){(this.handlers??={})[k]=fn;},
  };
  global.window=global;global.location={pathname:'/dashboard/incidents/11111111-1111-4111-8111-111111111111'};
  global.document={
    readyState:'complete',documentElement:{lang:'fa',dir:'rtl',dataset:{theme:'dark'}},
    querySelector:el,
    querySelectorAll(selector){return selector==='[data-lang]'?langListeners:[];},
    addEventListener(k,fn){(listeners[k]??=[]).push(fn);}
  };
  global.addEventListener=(k,fn)=>{};
  global.localStorage={getItem:k=>k==='aiops_api_key'?'test-key':null,setItem(){}};
  global.confirm=()=>true;global.scrollTo=()=>{};
  global.navigator={clipboard:{writeText:async()=>{}}};
  global.fetch=async (url,opts={})=>{
    assert.equal(opts.method||'GET','GET','viewing alerts cannot execute an action');
    let data;
    if(url.endsWith('/decision-brief'))data={
      snapshot_id:'s-1',
      incident_summary:{service:'nginx',summary:'Service unavailable'},
      remediation_recommendation:{},
      approval_readiness:{status:'not_pending'},
      agent_findings:[],mcp_evidence:[],monitoring_sources:[],
      cognia_knowledge:{status:'not_queried',items:[]},
      operational_memory:{items:[]},timeline:[],source_references:[],
    };
    else if(url.endsWith('/lifecycle'))data={};
    else if(url.includes('/decision-brief/narrative?'))data={
      status:'fallback',language:'fa',snapshot_id:'s-1',sections:[]
    };
    else if(url.includes('/received-signals?'))data={
      incident_id:'11111111-1111-4111-8111-111111111111',
      items:[
        {source:'zabbix',source_name:'Zabbix',source_id:'111',
          capture_kind:'received_redacted',message:'Port 86 is down\n<script>alert(1)</script>',
          payload:{eventid:'111',message:'Port 86 is down\n<script>alert(1)</script>',
            tags:[{tag:'service',value:'nginx'},{tag:'authorization',value:'[REDACTED]'}]}},
        {source:'prometheus',source_name:'Prometheus / Alertmanager',source_id:'fingerprint',
          capture_kind:'received_redacted',message:'Host down',
          payload:{labels:{alertname:'InstanceDown',severity:'critical'},
            annotations:{summary:'Host down'}}},
        {source:'elasticsearch',source_name:'Elasticsearch / ELK',source_id:'event-3',
          capture_kind:'normalized_stored',message:'Anomaly detected',
          payload:{rule:{tags:['service:nginx']},anomaly:{message:'Anomaly detected'}}}
      ],
      has_more:false,
    };
    else throw Error('Unexpected URL '+url);
    return {ok:true,json:async()=>data};
  };
  vm.runInThisContext(fs.readFileSync('dashboards/incident-command-room.js','utf8'));
  for(let n=0;n<12;n++) await new Promise(resolve=>setImmediate(resolve));
  const output=el('#ic-received-signals').innerHTML;
  assert.match(output,/Zabbix/);
  assert.match(output,/Prometheus \/ Alertmanager/);
  assert.match(output,/Elasticsearch \/ ELK/);
  assert.match(output,/Port 86 is down/);
  assert.match(output,/service/);
  assert.match(output,/nginx/);
  assert.match(output,/InstanceDown/);
  assert.match(output,/Host down/);
  assert.match(output,/service:nginx/);
  assert.match(output,/نسخه ثبت‌شده و نرمال‌شده/);
  assert.match(output,/نمایش تمام فیلدهای ثبت‌شده/);
  assert.match(output,/data-copy-received="0"/);
  assert.doesNotMatch(output,/<script>alert\(1\)<\/script>/);
  assert.match(output,/&lt;script&gt;/);
  assert.equal(el('#ic-received-signals').attrs['aria-busy'],'false');
  console.log('Received-source tab browser rendering PASS');
})().catch(error=>{console.error(error.stack||error);process.exitCode=1;});
"""
    result = subprocess.run(
        [shutil.which("node"), "-e", script],
        cwd=ROOT, capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert "browser rendering PASS" in result.stdout
