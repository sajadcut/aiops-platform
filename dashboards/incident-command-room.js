/* Full-screen, evidence-first Incident Command Room. Operational writes use only existing governed APIs. */
(() => {
  'use strict';
  const match = location.pathname.match(/^\/dashboard\/incidents\/([0-9a-fA-F-]{36})\/?$/);
  const incidentId = match && match[1];
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  const $ = q => document.querySelector(q);
  const safe = x => String(x == null || x === '' ? '—' : x);
  const esc = x => safe(x).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'}[c]));
  const arr = x => Array.isArray(x) ? x : [];
  const low = x => String(x || '').toLowerCase();
  const truncate = (x, limit = 340) => { const s = safe(x); return s.length > limit ? s.slice(0, limit) + '…' : s; };
  const vocabulary = {
    fa: {
      brandDetail:'فضای تصمیم‌گیری عملیاتی',dashboard:'داشبورد',incidents:'رخدادها',thisIncident:'این رخداد',
      refresh:'↻ تازه‌سازی',back:'بازگشت به رخدادها',loading:'در حال خواندن گزارش مستند از داده‌های ثبت‌شده رخداد…',
      heroKicker:'اتاق بررسی و تصمیم‌گیری',navOverview:'خلاصه تصمیم',navReview:'قبل از تأیید',
      navAnalysis:'تحلیل Agentها',navEvidence:'شواهد و MCP',navKnowledge:'دانش و تجربه',navOutcome:'نتیجه اجرا',navHistory:'تاریخچه',
      readFirst:'وضعیت رخداد به زبان ساده',overviewTitle:'خلاصه وضعیت و پیشنهاد AIOps',decisionSafety:'بررسی ریسک پیش از اقدام',
      reviewTitle:'اگر تأیید کنم، چه کاری انجام می‌شود؟',agentSubtitle:'نتیجه واقعی متخصص‌ها',
      agentsTitle:'هر ایجنت چه چیزی فهمیده است؟',sourceSubtitle:'فقط شواهد ثبت‌شده',evidenceTitle:'MCP و وضعیت منابع',
      knowledgeSubtitle:'دانش بازیابی‌شده، نه واقعیت قطعی',knowledgeTitle:'Cognia و تجربیات قبلی',cognia:'دانش سازمانی Cognia',
      memory:'Operational Memory',afterSubtitle:'بعد از تأیید چه اتفاقی افتاد؟',outcomeTitle:'اجرا، راستی‌آزمایی و یادگیری',
      historySubtitle:'قابل پیگیری و قابل ممیزی',historyTitle:'زمان‌بندی اتفاقات و نسخه‌ها',
      rawShow:'مشاهده شواهد خام (اختیاری)',loadRaw:'دریافت شواهد ثبت‌شده',archiveShow:'نمایش نسخه‌های تاریخی ذخیره‌شده',
      archiveLoading:'برای دیدن نسخه‌های قبلی این بخش را باز کنید.',archivedNotice:'در حال مشاهده نسخه تاریخی هستید',
      archiveHint:'این نسخه فقط برای ممیزی است و مبنای تأیید یا اجرای فعلی نیست.',returnLive:'بازگشت به نسخه فعلی',
      footerTrust:'تصمیم نهایی انسانی است؛ گزارش فقط بر مبنای داده ذخیره‌شده تهیه شده است.',
      decisionDesk:'میز تصمیم اپراتور',actionTitle:'اقدام بعدی چیست؟',
      neverAuto:'تأیید و اجرا دو مرحله جداگانه‌اند. این صفحه مجوز جدید ایجاد نمی‌کند.',
      helpTitle:'وقتی شک داری، اجرا نکن',helpText:'اول «شواهد و MCP» و «قبل از تأیید» را بخوان؛ برای رد کردن تصمیم، دلیل ثبت کن.',
      authTitle:'برای دیدن اطلاعات واقعی این رخداد، اتصال مجاز لازم است.',apiKey:'کلید دسترسی API',
      connect:'اتصال امن',authNote:'کلید فقط برای درخواست‌های احرازهویت‌شده همین مرورگر استفاده می‌شود.',
      unknown:'نامشخص',service:'سرویس',severity:'شدت',status:'وضعیت رخداد',started:'زمان شروع',
      duration:'مدت اختلال',target:'هدف',host:'میزبان',cluster:'کلاستر',namespace:'فضای نام',
      approval:'تأیید انسانی',risk:'سطح ریسک',action:'اقدام پیشنهادشده',tool:'ابزار اجرا',freshness:'تازگی شواهد',
      evidence:'شواهد معتبر',cause:'علت احتمالی',causeStatus:'میزان اطمینان به علت',why:'چرا این اقدام؟',
      criticalWarning:'پیش از تصمیم‌گیری به این هشدارها توجه کنید.',agents:'Agentهای اجراشده',
      mcp:'یافته‌های MCP',monitoring:'پایش زیرساخت',none:'اطلاعات قابل‌استنادی ثبت نشده است.',
      infoUnavailable:'اطلاعاتی برای این بخش ثبت نشده است؛ نتیجه‌گیری جدیدی ساخته نمی‌شود.',
      notUsed:'کاگنیا تجربه‌های مشابهی پیدا کرده؛ اما هنوز معلوم نیست این تجربه‌ها در تصمیم نهایی اثر داشته‌اند یا نه.',
      approvalPending:'در انتظار تصمیم شما',approvalApproved:'تأیید شده، منتظر اجرای جداگانه',
      approvalFinished:'مجوز دیگر در انتظار نیست',approvalNoRecord:'برای این رخداد مجوز فعالی ثبت نشده است.',
      reviewCheckbox:'بررسی کردم چه کاری، روی کدام سرور و با چه ریسکی انجام می‌شود.',
      approveOnly:'تأیید مجوز — بدون اجرا',reject:'رد کردن اقدام',rejectReason:'دلیل رد (الزامی)',
      rejectHint:'دلیل رد این پیشنهاد را بنویسید…',confirmReject:'ثبت رد و دلیل',
      resume:'اجرای مجاز و شروع Verification',resumeCheckbox:'تأیید می‌کنم که قصد اجرای واقعی همین اقدام و مصرف یک‌باره مجوز را دارم.',
      execBound:'تنها اقدام دقیقاً متصل به این مجوز قابل اجرا است.',approvalSeparate:'تأیید به معنی اجرای فوری نیست.',
      rereview:'اطلاعات این رخداد تغییر کرده است؛ گزارش تازه شد. قبل از اقدام دوباره بررسی کنید.',
      noBinding:'اتصال مجوز به عملیات کامل یا تأییدشده نیست؛ اجرا مسدود است.',
      drift:'شواهد یا برنامه از زمان صدور مجوز تغییر کرده؛ برای عملیات باید تأیید جدید صادر شود.',
      freshUnknown:'تازگی شواهد نامشخص است؛ قبل از تصمیم بررسی کنید.',
      stale:'زمان بعضی اطلاعات گذشته است؛ قبل از اجرا وضعیت سرویس دوباره بررسی شود.',sourceUnavailable:'یکی از ابزارهای مانیتورینگ جواب نداده؛ تحلیل بدون داده‌های آن انجام شده است.',
      missing:'برای نتیجه‌گیری مطمئن، بعضی بررسی‌ها هنوز کامل نشده‌اند.',awaitModel:'در حال تهیه توضیح تکمیلی با مدل…',
      modelUnavailable:'توضیح تکمیلی مدل در دسترس نیست؛ خلاصه قطعی از داده‌های ذخیره‌شده نمایش داده می‌شود.',
      narrative:'توضیح تکمیلی مستند',copied:'گزارش کپی شد.',copy:'کپی خلاصه',
      timeout:'زمان مجاز عملیات',rollback:'امکان بازگشت',runbook:'راهنمای عملیاتی',
      blast:'دامنه اثر',inaction:'ریسک اقدام نکردن',expected:'نتیجه مورد انتظار',verificationPlan:'برنامه راستی‌آزمایی',
      evaluator:'اطمینان Evaluator',agreement:'توافق Agentها',rca:'اطمینان RCA',refs:'ارجاع شواهد',
      server:'منبع',sampleTime:'زمان جمع‌آوری',phase:'مرحله',finding:'یافته',confidence:'اطمینان',
      verification:'نتیجه Verification',execute:'وضعیت اجرا',reviewDraft:'مشاهده پیش‌نویس بازبینی دانش',
      authDenied:'دسترسی مجاز نیست؛ کلید دسترسی را بررسی کنید.',failure:'دریافت اطلاعات رخداد ناموفق بود.',
      noHistory:'نسخه تاریخی ذخیره‌شده‌ای برای این رخداد وجود ندارد.',loadHistoryError:'خواندن تاریخچه ممکن نشد.',
      historical:'نسخه تاریخی',returnCurrent:'نسخه فعلی',loadingHistory:'در حال دریافت نسخه‌ها…',
      noExecution:'هنوز نتیجه اجرایی ثبت نشده است. هیچ عملیاتی صرفاً با دیدن گزارش اجرا نمی‌شود.',
      needReview:'برای فعال شدن دکمه، ابتدا چک‌باکس بررسی را تأیید کنید.',
      reasonMissing:'دلیل رد را وارد کنید.',processing:'در حال ثبت درخواست…',
      reload:'داده‌های تازه بارگذاری شد.',elapsedSeconds:'ثانیه',result:'نتیجه',description:'شرح',
      evidenceRefs:'منابع مستند',approvalId:'شناسه تأیید',trace:'ردیابی',sourceOnly:'متن اصلی ثبت‌شده',
      riskMeaning:'این درصد برای همین ارزیابی است؛ به‌معنی قطعی بودن علت خرابی نیست.',
      agentNone:'برای دیدن شناسه شواهد و جزئیات فنی، هر مورد را باز کن.',
      producerNote:'هیچ Tool یا Workflow فقط با بازکردن این صفحه اجرا نمی‌شود.',
      highConfirm:'این عملیات پرریسک است؛ هدف، ابزار، Runbook، شواهد و دامنه اثر را دوباره تأیید کنید.',
      firstApprove:'آیا همین مجوز را تأیید می‌کنید؟ اجرای عملیات در مرحله‌ای جداگانه خواهد بود.',
      firstResume:'آیا مطمئن هستید عملیات واقعی و متصل به این مجوز آغاز شود؟ این مجوز یک‌بارمصرف است.',
      firstReject:'آیا از رد این درخواست و ثبت دلیل آن مطمئن هستید؟',successApprove:'مجوز تأیید شد؛ هنوز اجرا نشده است.',
      successReject:'رد درخواست ثبت شد.',successResume:'درخواست اجرا ثبت شد؛ وضعیت و راستی‌آزمایی را بررسی کنید.',
      pending:'در انتظار',approved:'تأیید شده',rejected:'رد شده',consumed:'مصرف شده',failed:'ناموفق',success:'موفق',
      resolved:'رفع شده',unknownStatus:'نامشخص',fresh:'تازه',mixed:'ترکیبی',unavailable:'در دسترس نیست',not_verified:'تأییدنشده',
      matched_at_read:'مطابق در زمان مشاهده',drift_detected:'مغایرت نسخه شواهد',not_pending:'منتظر تأیید نیست',
      unverified:'تأییدنشده',reviewNext:'قبل از اجرا',knowledgeNotProof:'این‌ها تجربه‌های قبلی‌اند؛ وضعیت فعلی سرویس باید جداگانه بررسی شود.',
      inspectSource:'برای جزئیات، شواهد ثبت‌شده را باز کنید.',backendGate:'اجرای نهایی فقط با گیت‌های امنیتی Backend انجام می‌شود.'
    },
    en: {
      brandDetail:'Dedicated operational decision workspace',dashboard:'Dashboard',incidents:'Incidents',thisIncident:'This incident',
      refresh:'↻ Refresh',back:'Back to incidents',loading:'Loading durable evidence and incident state…',
      heroKicker:'Incident command room',navOverview:'Quick brief',navReview:'Before approval',navAnalysis:'Agent analysis',
      navEvidence:'Evidence & MCP',navKnowledge:'Knowledge & memory',navOutcome:'Execution result',navHistory:'History',
      readFirst:'Start here',overviewTitle:'Incident summary and recommendation',decisionSafety:'Risk review',
      reviewTitle:'What exactly am I authorizing?',agentSubtitle:'Recorded specialist findings',
      agentsTitle:'Agent analysis & RCA confidence',sourceSubtitle:'Durable observations only',evidenceTitle:'MCP and evidence health',
      knowledgeSubtitle:'Retrieved context is not proof',knowledgeTitle:'Cognia & operational memory',
      cognia:'Cognia organizational knowledge',memory:'Operational Memory',afterSubtitle:'What happened after approval?',
      outcomeTitle:'Execution, verification & learning',historySubtitle:'Auditable record',historyTitle:'Timeline and snapshots',
      rawShow:'View raw evidence (optional)',loadRaw:'Load durable evidence',archiveShow:'Browse stored historical versions',
      archiveLoading:'Open this section to inspect historical snapshots.',archivedNotice:'Viewing a historical snapshot',
      archiveHint:'Historical versions are read-only, never authorization for current execution.',returnLive:'Return to current report',
      footerTrust:'Human operators retain authority. The report is derived from persisted incident evidence.',
      decisionDesk:'Operator decision desk',actionTitle:'What happens next?',neverAuto:'Approval and execution are separate. This page creates no authority.',
      helpTitle:'When uncertain, do not execute',helpText:'Review evidence and the exact bound action before approving; document your reason for rejection.',
      authTitle:'Authorized access is required to read this incident.',apiKey:'API access key',connect:'Connect',
      authNote:'The key is used only for authenticated requests from this browser.',
      unknown:'Unknown',service:'Service',severity:'Severity',status:'Incident status',started:'Started',
      duration:'Elapsed',target:'Target',host:'Host',cluster:'Cluster',namespace:'Namespace',approval:'Approval',
      risk:'Risk',action:'Proposed action',tool:'Execution tool',freshness:'Evidence freshness',evidence:'Usable evidence',
      cause:'Likely cause',causeStatus:'Cause certainty',why:'Why this action?',criticalWarning:'Review these warnings before deciding.',
      agents:'Specialists',mcp:'MCP findings',monitoring:'Monitoring',none:'No verified evidence was recorded for this section.',
      infoUnavailable:'No durable data recorded; no result is inferred.',notUsed:'Retrieval does not prove causal influence.',
      approvalPending:'Waiting for your decision',approvalApproved:'Approved; execution still separate',
      approvalFinished:'No pending authorization',approvalNoRecord:'No active approval request for this incident.',
      reviewCheckbox:'I reviewed the target, risk, evidence and consequences.',
      approveOnly:'Grant approval — do not execute',reject:'Reject proposed action',rejectReason:'Reason for rejection (required)',
      rejectHint:'Describe why this request is being rejected…',confirmReject:'Confirm rejection',
      resume:'Execute authorized action & verify',resumeCheckbox:'I intend to execute this exact action and consume its one-time authorization.',
      execBound:'Only the action bound to this approval may execute.',approvalSeparate:'Approval does not execute the action.',
      rereview:'Incident data changed. Please review the refreshed report again before acting.',
      noBinding:'Execution intent binding is incomplete; execution is blocked.',
      drift:'Plan or evidence changed since approval. Fresh authorization is required.',
      freshUnknown:'Evidence freshness is unknown. Review before deciding.',stale:'Some evidence is stale or has unknown collection time.',
      sourceUnavailable:'A monitoring provider was unavailable.',missing:'Evidence is missing or contradictory.',
      awaitModel:'Loading optional grounded narrative…',modelUnavailable:'LLM prose is unavailable; deterministic evidence remains visible.',
      narrative:'Source-grounded explanation',copied:'Report copied.',copy:'Copy summary',
      timeout:'Execution timeout',rollback:'Rollback available',runbook:'Runbook',blast:'Blast radius',
      inaction:'Risk of inaction',expected:'Expected outcome',verificationPlan:'Verification plan',
      evaluator:'Evaluator confidence',agreement:'Agent agreement',rca:'RCA confidence',refs:'Evidence references',
      server:'Source',sampleTime:'Collected at',phase:'Phase',finding:'Finding',confidence:'Confidence',
      verification:'Verification',execute:'Execution',reviewDraft:'Open knowledge review draft',
      authDenied:'Access denied. Check your API key.',failure:'Could not load this incident.',
      noHistory:'No archived snapshots for this incident yet.',loadHistoryError:'Could not load history.',
      historical:'Archived snapshot',returnCurrent:'Current version',loadingHistory:'Loading history…',
      noExecution:'No execution outcome recorded. Reading this report does not execute anything.',
      needReview:'Confirm your review checkbox to enable this action.',reasonMissing:'Provide a rejection reason.',
      processing:'Submitting…',reload:'Current data refreshed.',elapsedSeconds:'seconds',result:'Result',description:'Description',
      evidenceRefs:'Evidence references',approvalId:'Approval ID',trace:'Trace',sourceOnly:'Original recorded text',
      riskMeaning:'RCA, evaluator quality and agent agreement are separate metrics, not a single certainty score.',
      agentNone:'Agents without actual recorded results are not shown as successful.',
      producerNote:'Opening this page never runs tools or workflows.',highConfirm:'HIGH RISK: verify target, tool, runbook, evidence and blast radius again.',
      firstApprove:'Grant this authorization? It does NOT execute the operation yet.',
      firstResume:'Execute the bound action now? Approval is consumed exactly once.',
      firstReject:'Reject this request and record the reason?',successApprove:'Approval granted. Nothing has executed yet.',
      successReject:'Rejection recorded.',successResume:'Execution requested. Inspect independent verification.',
      pending:'Pending',approved:'Approved',rejected:'Rejected',consumed:'Consumed',failed:'Failed',
      success:'Success',resolved:'Resolved',unknownStatus:'Unknown',fresh:'Fresh',mixed:'Mixed',
      unavailable:'Unavailable',not_verified:'Not verified',matched_at_read:'Matched at read',
      drift_detected:'Evidence snapshot drift',not_pending:'Not pending',unverified:'Not verified',reviewNext:'Before execution',
      knowledgeNotProof:'Historical experience is not current live evidence.',inspectSource:'Inspect durable evidence for details.',
      backendGate:'The server enforces all execution authorization gates.'
    }
  };

  const state = {
    language: (() => { try { return localStorage.getItem('aiops.decision-brief.language') === 'en' ? 'en' : 'fa'; } catch (_) {return 'fa';} })(),
    key: (() => { try {return localStorage.getItem('aiops_api_key') || '';} catch (_) {return '';} })(),
    report: null, lifecycle: null, narrative: null, historic: null, history: null,
    loadingToken: 0, busy: false, reviewedSnapshot: null, rejectionVisible: false, error: null
  };
  const tr = key => vocabulary[state.language][key] || key;
  const value = v => v === null || v === undefined || v === '' ? tr('unknown') : safe(v);
  const txt = v => esc(value(v));
  const num = v => v === null || v === undefined ? tr('unknown') : new Intl.NumberFormat(state.language === 'fa' ? 'fa-IR' : 'en-US').format(v);
  const date = v => { if(!v) return tr('unknown'); const d = new Date(v); return Number.isNaN(d.getTime()) ? tr('unknown') : new Intl.DateTimeFormat(state.language === 'fa' ? 'fa-IR' : 'en-US',{dateStyle:'medium',timeStyle:'short'}).format(d); };
  const numberPct = v => v === null || v === undefined || v === '' || !Number.isFinite(Number(v)) ? tr('unknown') :
    new Intl.NumberFormat(state.language === 'fa' ? 'fa-IR' : 'en-US',{maximumFractionDigits:0}).format(Number(v)*100) + '٪';
  const code = v => '<span dir="ltr" class="ic-identifier">' + txt(v) + '</span>';
  const tone = x => /critical|failed|error|blocked|rejected|unavailable|stale|drift/.test(low(x)) ? 'danger' :
    /pending|high|mixed|unknown|partial|inconclusive|not_verified|unbound/.test(low(x)) ? 'warn' :
    /success|approved|resolved|verified|fresh|matched|consumed|healthy/.test(low(x)) ? 'ok' : 'neutral';
  const labels = {pending:'pending',approved:'approved',rejected:'rejected',consumed:'consumed',failed:'failed',success:'success',
    resolved:'resolved',fresh:'fresh',mixed:'mixed',stale:'stale',not_verified:'not_verified',drift_detected:'drift_detected',
    matched_at_read:'matched_at_read',not_pending:'not_pending',unavailable:'unavailable'};
  const operationStatesFA = {
    critical:'بحرانی',high:'زیاد',medium:'متوسط',low:'کم',open:'باز',analyzing:'در حال تحلیل',
    escalated:'ارجاع‌شده',closed:'بسته‌شده',hypothesis:'فرضیه',confirmed:'تأییدشده',
    not_requested:'درخواست نشده',not_executed:'اجرا نشده',not_recorded:'ثبت نشده',
    partial:'ناقص',inconclusive:'نامطمئن',queried:'پرس‌وجو انجام شده',not_queried:'پرس‌وجو نشده',
    cited_by_agent:'مورد استناد Agent',skipped:'اجرا نشده',error:'خطا',unknown:'نامشخص',
    unavailable:'در دسترس نیست',legacy_unbound:'بدون اتصال Snapshot',blocked:'مسدود',completed:'تکمیل شده',
    probable:'احتمالی، هنوز قطعی نیست',unconfirmed:'هنوز تأیید نشده',
    successful_recovery:'رفع موفق قبلی',failed_recovery:'رفع ناموفق قبلی',
    recorded:'ثبت شده',retryable:'دوباره قابل بررسی',approval_granted:'تأیید اقدام',
    approval_precondition_retryable:'پیش‌شرط اجرا هنوز آماده نیست',decision_made:'تصمیم‌گیری AIOps',
    remediation_plan_generated:'تهیه برنامه رفع مشکل',evaluation_completed:'بررسی کیفیت پیشنهاد',
    rca_completed:'بررسی علت مشکل',specialist_analysis_completed:'نتیجه بررسی ایجنت‌ها',
    agent_evidence_round_completed:'جمع‌آوری شواهد',context_loaded:'جمع‌آوری اطلاعات اولیه',
    human_review_required:'نیازمند بررسی انسانی',new_approval_required:'نیازمند تأیید جدید'
  };
  const status = x => {
    const k=low(x);
    return (state.language==='fa' && operationStatesFA[k]) ||
      vocabulary[state.language][labels[k]] || value(x);
  };
  const pill = x => '<span class="ic-status" data-tone="' + tone(x) + '">' + esc(status(x)) + '</span>';
  const empty = message => '<p class="ic-empty">' + esc(message || tr('none')) + '</p>';

  // Plain-language presentation only. All original Evidence IDs, payloads and
  // execution bindings stay intact. Unrecognised English remains expandable,
  // never silently portrayed as a verified Persian interpretation.
  const isFaText = v => /[آ-ی]/.test(String(v || ''));
  const actionFa = {start_service:'راه‌اندازی سرویس',restart_service:'راه‌اندازی مجدد سرویس',
    reload_service:'بارگذاری دوباره تنظیمات سرویس',stop_service:'متوقف کردن سرویس'};
  const agentFa = {triage:'بررسی اولیه',network:'بررسی شبکه',vm:'بررسی ماشین مجازی',
    application:'بررسی برنامه',infrastructure:'بررسی زیرساخت',dependency:'بررسی وابستگی‌ها',
    rca:'بررسی علت خرابی',evaluator:'ارزیابی پیشنهاد'};
  const toolFa = {ssh_vm:'اتصال به سرور با SSH',vm_mcp:'ابزار بررسی ماشین مجازی',
    zabbix:'زبیکس',prometheus:'پرومتئوس',elasticsearch:'جست‌وجوی لاگ‌ها',
    service_status:'بررسی وضعیت سرویس',process_status:'بررسی پردازش',
    tcp_check:'تست اتصال به پورت',port_listener_status:'بررسی پورت باز',
    config_validate:'بررسی درستی تنظیمات',service_logs:'بررسی لاگ سرویس',
    collect_vm_metrics:'بررسی منابع سرور',source_observation:'اطلاعات ثبت‌شده ابزار',
    host_info:'اطلاعات سرور',disk_status:'بررسی دیسک'};
  const humanAction = x => state.language === 'fa' && actionFa[low(x)]
    ? actionFa[low(x)] + ' (' + safe(x) + ')' : value(x);
  const humanAgent = x => state.language === 'fa' ? (agentFa[low(x)] || value(x)) : value(x);
  const humanTool = x => state.language === 'fa' ? (toolFa[low(x)] || value(x)) : value(x);
  function signalFacts(raw) {
    const x=String(raw || ''),facts=[];
    if(/active_state\s*=\s*inactive|service (?:is |was )?(?:inactive|stopped)|inactive \(dead\)/i.test(x)) facts.push('سرویس متوقف است');
    if(/running\s*=\s*false|process(?:es)? (?:are |is )?not running|process count (?:is )?0/i.test(x)) facts.push('پردازش سرویس اجرا نمی‌شود');
    if(/listening\s*=\s*false|not listening locally|port \d+ is not listening/i.test(x)) facts.push('پورت مورد انتظار باز نیست');
    if(/reachable\s*=\s*false|TCP connectivity check .*fails|TCP port .*unreachable/i.test(x)) facts.push('ارتباط با پورت برقرار نمی‌شود');
    if(/valid\s*=\s*true|syntax (?:is )?(?:valid|OK)|configuration validation passed/i.test(x)) facts.push('تنظیمات سرویس از نظر ساختاری درست است');
    if(/clean stop|stopped cleanly|exit status 0\/SUCCESS/i.test(x)) facts.push('سرویس بدون خطای توقف بسته شده، ولی دلیل آن معلوم نیست');
    const cpu=x.match(/name=cpu_usage;\s*value=([\d.]+)/i);
    const memory=x.match(/name=memory_usage;\s*value=([\d.]+)/i);
    if(cpu) facts.push('مصرف CPU: '+cpu[1]+' درصد');
    if(memory) facts.push('مصرف RAM: '+memory[1]+' درصد');
    return [...new Set(facts)].slice(0,6);
  }
  const plain = (raw,fallback) => {
    if(state.language!=='fa' || isFaText(raw)) return value(raw);
    const facts=signalFacts(raw);
    return facts.length ? facts.join('؛ ') + '.' :
      (fallback || 'متن این بررسی به فارسی آماده نشده است؛ برای جزئیات، متن اصلی را باز کن.');
  };
  const original = (raw,label) => state.language==='fa' && raw && !isFaText(raw) ?
    '<details class="ic-technical"><summary>'+esc(label || 'متن تخصصی اصلی')+'</summary><p dir="ltr">'+txt(raw)+'</p></details>' : '';
  const humanCause = raw => state.language==='fa' && raw && !isFaText(raw) ?
    (/clean (?:stop|shutdown)|stopped cleanly/i.test(raw) ?
      'سرویس بدون خطای توقف بسته شده؛ هنوز معلوم نیست چه چیزی آن را متوقف کرده است.' :
      'علت اصلی هنوز مشخص نشده است؛ اطلاعات فنی و شواهد را بررسی کن.') : value(raw);

  function previousExperience(item, kind) {
    if (state.language !== 'fa') return truncate(kind==='cognia'?item.excerpt:item.root_cause,400);
    const source=String(kind==='cognia'?item.excerpt:item.root_cause||'');
    const action=String(item.action || (/historical\):\s*(start_service|restart_service|reload_service)/i.exec(source)||[])[1] || '');
    const outcome=kind==='memory'?low(item.verification):/verification status:\s*success/i.test(source)?'success':'unknown';
    const prefix=kind==='cognia'?'کاگنیا یک تجربه مشابه پیدا کرده. ':'در حافظه عملیاتی، تجربه مشابهی ثبت شده. ';
    const used=action?'در آن تجربه، '+humanAction(action)+' انجام شده. ':'';
    const verified=outcome==='success'?'بعد از اجرا، نتیجه بررسی سرویس موفق ثبت شده. ':'نتیجه نهایی رفع مشکل در این خلاصه مشخص نیست. ';
    const caution=/unconfirmed|not independently confirmed/i.test(source)?'علت اصلی آن مشکل هم تأیید نشده بود. ':'';
    return prefix+used+verified+caution+'قبل از تکرار اقدام باید وضعیت فعلی جداگانه بررسی شود.';
  }
  function explanation(r) {
    const x=r.remediation_recommendation||{};
    if(state.language!=='fa') return value(x.why);
    const tools=arr(r.mcp_evidence).filter(e=>!['failed','error','unavailable'].includes(low(e.status)));
    const observations=[...new Set(tools.flatMap(e=>signalFacts(e.finding)))];
    if(low(x.action)==='start_service' && observations.includes('سرویس متوقف است')) {
      return 'ابزار بررسی سرور نشان داده سرویس متوقف است. به همین دلیل سیستم پیشنهاد داده آن را دوباره روشن کنیم. '+
        'اگر شواهد قدیمی شده‌اند، وضعیت فعلی باید دوباره بررسی شود. این اقدام لزوماً علت توقف سرویس را برطرف نمی‌کند.';
    }
    if(isFaText(x.why)) return value(x.why);
    return 'این اقدام با توجه به شواهد ثبت‌شده پیشنهاد شده، اما برای تأیید آن باید گزارش بررسی سرویس و ریسک اجرا را ببینی.';
  }
  function plainLead(r) {
    if(state.language!=='fa') return r.localized_narrative?.en || tr('infoUnavailable');
    const i=r.incident_summary||{},x=r.remediation_recommendation||{};
    const findings=arr(r.mcp_evidence).filter(y=>!['failed','error','unavailable'].includes(low(y.status)));
    const facts=[...new Set(findings.flatMap(y=>signalFacts(y.finding)))].slice(0,4);
    const subject='سرویس '+safe(i.service);
    const host=i.host||i.target||x.target;
    const where=host?' روی سرور '+safe(host):'';
    const situation=facts.length?'بررسی ابزارها نشان می‌دهد: '+facts.join('؛ ')+'.' :
      'هنوز اطلاعات کافی برای توضیح دقیق وضعیت سرویس نداریم.';
    const next=x.action?'پیشنهاد سیستم '+humanAction(x.action)+' است.':'هنوز کاری برای اجرا پیشنهاد نشده است.';
    return 'برای '+subject+where+' رخداد ثبت شده. '+situation+' '+next+
      ' دلیل اصلی مشکل هنوز به‌طور قطعی روشن نشده است؛ تأیید و اجرای اقدام دو مرحله جدا هستند.';
  }

  const refs = values => arr(values).length ?
    '<details class="ic-technical ic-evidence-refs"><summary>'+
    (state.language==='fa'?'دیدن شناسه شواهد ('+num(arr(values).length)+')':'Evidence references ('+arr(values).length+')')+
    '</summary><div class="ic-ref-list">'+arr(values).map(x=>'<code dir="ltr">'+txt(x)+'</code>').join('')+'</div></details>' : '';

  const fact = (key, v) => '<div class="ic-fact"><span class="ic-fact-label">' + esc(tr(key)) +
    '</span><strong class="ic-fact-value">' + txt(v) + '</strong></div>';
  const mini = (key,v) => '<div><span>' + esc(tr(key)) + '</span><b>' + txt(v) + '</b></div>';
  const show = (q,html) => { const el=$(q); if(el) el.innerHTML=html; };
  function notify(message,error=false) {
    const box=$('#ic-toast');box.textContent=message;box.classList.add('show');
    box.dataset.error=String(error);
    clearTimeout(notify.timeout);notify.timeout=setTimeout(()=>box.classList.remove('show'),4200);
  }
  function alert(message) { const el=$('#ic-alert');el.hidden=!message;el.textContent=message || ''; }
  async function api(path, options={}) {
    const headers={'Accept':'application/json', ...(state.key ? {'X-API-Key':state.key}:{}),...(options.headers||{})};
    const response=await fetch(path,{...options,headers,credentials:'same-origin'});
    if(!response.ok){
      let detail='',code='';
      try {
        const body=await response.json();
        code=body?.detail?.code||body?.error?.code||'';
        detail=typeof body.detail==='string'?body.detail:JSON.stringify(body.detail||'');
      }catch(_){}
      const message=code==='DATABASE_MIGRATION_DRIFT'?
        (state.language==='fa'?
          'نسخه دیتابیس قدیمی است و عملیات به‌صورت ایمن متوقف شده. مدیر سیستم باید پس از بکاپ، Alembic migration را اجرا کند.':
          'Database schema is behind the application. Operations are safely blocked; a DBA must back up and apply Alembic migrations.') :
        response.status+' '+(detail||response.statusText);
      const e=new Error(message);e.status=response.status;e.code=code;throw e;
    }
    return response.json();
  }
  const base='/api/v1/incidents/'+encodeURIComponent(incidentId);
  function setLang(lang) {
    state.language = lang === 'en' ? 'en' : 'fa';
    document.documentElement.lang=state.language;
    document.documentElement.dir=state.language==='fa'?'rtl':'ltr';
    document.title=state.language==='fa'?'اتاق تصمیم‌گیری رخداد | AIOps':'Incident Command Room | AIOps';
    document.querySelectorAll('[data-i18n]').forEach(el=>{el.textContent=tr(el.dataset.i18n);});
    document.querySelectorAll('[data-lang]').forEach(el=>el.setAttribute('aria-pressed',String(el.dataset.lang===state.language)));
    try{localStorage.setItem('aiops.decision-brief.language',state.language);}catch(_){}
    render();
    if(state.report && !state.historic) void loadNarrative();
  }
  function renderHero(r) {
    const i=r.incident_summary||{},a=r.approval_readiness||{},action=r.remediation_recommendation||{};
    $('#ic-title').textContent=value(i.service);
    $('#ic-description').textContent=value(i.summary);
    $('#ic-short-id').textContent='#'+String(incidentId).slice(0,8);
    show('#ic-hero-badges',pill(i.severity)+pill(i.status)+pill(a.approval_status));
    const authStatus=low(a.approval_status);
    const pulseTitle=authStatus==='pending'?tr('approvalPending'):authStatus==='approved'?tr('approvalApproved'):tr('approvalFinished');
    show('#ic-decision-pulse','<small>'+tr('decisionDesk')+'</small><strong>'+esc(pulseTitle)+'</strong><p>'+
      txt(authStatus==='approved'?tr('approvalSeparate'):tr('backendGate'))+'</p>');
    const quick=[
      ['started',date(i.started_at)],['duration',i.elapsed_seconds==null?tr('unknown'):num(Math.max(0,Math.floor(i.elapsed_seconds/60)))+' '+(state.language==='fa'?'دقیقه':'min')],
      ['risk',status(action.risk_level)],['evidence',num(i.valid_evidence_count??r.source_references?.length??0)]
    ];
    show('#ic-quick-facts',quick.map(([k,v])=>'<div><small>'+esc(tr(k))+'</small><strong>'+esc(v)+'</strong></div>').join(''));
  }
  function warningMessages(r) {
    const a=r.approval_readiness||{},c=r.cognia_knowledge||{};
    const messages=[];
    if(a.evidence_snapshot_binding==='drift_detected') messages.push({text:tr('drift'),critical:true});
    if(r.data_freshness==='stale'||r.data_freshness==='mixed')messages.push({text:tr('stale')});
    if(r.data_freshness==='unknown')messages.push({text:tr('freshUnknown')});
    if(arr(r.monitoring_sources).some(s=>['error','unavailable'].includes(low(s.status)))) messages.push({text:tr('sourceUnavailable')});
    if(arr(r.missing_evidence).length||arr(r.evidence_conflicts).length)messages.push({text:tr('missing')});
    if(Number(c.retrieved_count)>0 && arr(c.items).every(x=>x.use_status!=='cited_by_agent'))messages.push({text:tr('notUsed')});
    return messages;
  }
  function renderOverview(r) {
    const i=r.incident_summary||{},act=r.remediation_recommendation||{},a=r.approval_readiness||{};
    const deterministic=plainLead(r);
    const n=state.narrative;
    const matched=n && n.snapshot_id===r.snapshot_id && n.language===state.language && !state.historic && n.status==='available';
    const narrative=matched?'<details class="ic-reveal"><summary>'+esc(tr('narrative'))+'</summary><div class="ic-reveal-content">'+arr(n.sections).map(s=>
      '<article class="ic-detail-card"><h4>'+txt(s.heading)+'</h4><p>'+txt(s.text)+'</p>'+refs(s.citations)+'</article>').join('')+'</div></details>':'';
    show('#ic-brief-lead','<p>'+txt(deterministic)+'</p>'+narrative);
    show('#ic-key-answer',[
      fact('cause',humanCause(i.likely_cause)),fact('causeStatus',status(i.cause_status)),
      fact('action',humanAction(act.action)),fact('target',act.target),
      fact('tool',humanTool(act.tool)),fact('freshness',status(r.data_freshness))
    ].join(''));
    const warnings=warningMessages(r);
    show('#ic-warning-list',warnings.length?warnings.map(x=>'<div class="ic-warning'+(x.critical?' critical':'')+'">'+esc(x.text)+'</div>').join('') :
      '<div class="ic-callout"><strong>'+esc(tr('evidenceRefs'))+'</strong><p>'+esc(tr('inspectSource'))+'</p></div>');
  }
  function renderReview(r) {
    const i=r.incident_summary||{},a=r.approval_readiness||{},x=r.remediation_recommendation||{};
    show('#ic-proposal',[
      fact('action',humanAction(x.action)),fact('tool',humanTool(a.tool||x.tool)),fact('target',a.target||x.target),fact('risk',status(x.risk_level)),
      fact('host',i.host||i.target),fact('cluster',i.cluster),fact('namespace',i.namespace),
      fact('blast',x.blast_radius),fact('inaction',x.risk_of_inaction),
      fact('runbook',[a.runbook_id,a.runbook_version].filter(Boolean).join(' @ ')||null),
      fact('rollback',a.rollback_supported? (state.language==='fa'?'ثبت شده':'Recorded'):tr('not_verified')),
      fact('timeout',a.timeout_seconds),
      fact('freshness',status(a.data_freshness)),
      fact('approvalId',a.approval_id),
      fact('verificationPlan',x.verification_plan),fact('expected',x.expected_outcome)
    ].join(''));
    show('#ic-preconditions','<div class="ic-callout"><strong>'+esc(tr('why'))+'</strong><p>'+txt(explanation(r))+'</p>'+
      refs(i.cause_evidence_refs)+'</div>'+
      (arr(x.unverified_assumptions).length?'<div class="ic-warnings">'+arr(x.unverified_assumptions).slice(0,10).map(y=>'<div class="ic-warning">'+txt(y)+'</div>').join('')+'</div>':''));
  }
  function renderAnalysis(r) {
    const c=r.rca_assessment||{};
    show('#ic-confidence',[
      ['rca',c.rca_confidence],['evaluator',c.evaluator_confidence],['agreement',c.agent_agreement]
    ].map(([key,v])=>'<div class="ic-confidence-card"><span>'+esc(tr(key))+'</span><strong>'+esc(numberPct(v))+'</strong><small>'+esc(tr('riskMeaning'))+'</small></div>').join(''));
    const agents=arr(r.agent_findings);
    show('#ic-agents',agents.length?agents.map(a=>'<article class="ic-detail-card"><div class="ic-detail-head"><h4>'+txt(humanAgent(a.agent))+'</h4>'+pill(a.status)+'</div>'+
      '<p>'+txt(plain(a.finding))+'</p>'+original(a.finding)+'<div class="ic-meta">'+tr('confidence')+': '+esc(numberPct(a.confidence))+
      (a.mission?' · '+tr('description')+': '+txt(a.mission):'')+
      (arr(a.tools).length?' · '+tr('tool')+': '+arr(a.tools).map(txt).join(', '):'')+'</div>'+refs(a.evidence_refs)+
      (arr(a.missing_evidence).length?'<p class="ic-warning">'+tr('missing')+': '+arr(a.missing_evidence).map(txt).join('، ')+'</p>':'')+
      '</article>').join('')+ '<p class="ic-callout">'+esc(tr('agentNone'))+'</p>':empty(tr('none')));
  }
  function renderEvidence(r) {
    const sources=arr(r.monitoring_sources),mcp=arr(r.mcp_evidence);
    show('#ic-sources',sources.length?sources.map(x=>'<article class="ic-source-card"><strong>'+txt(x.source)+'</strong>'+pill(x.status)+
      '<p>'+tr('freshness')+': '+txt(status(x.freshness))+'</p>'+
      (['error','unavailable'].includes(low(x.status))?'<p class="ic-warning">'+tr('sourceUnavailable')+'</p>':'')+'</article>').join(''):empty());
    show('#ic-mcp',mcp.length?mcp.map(x=>'<article class="ic-detail-card"><div class="ic-detail-head"><h4>'+
      txt(humanTool(x.server))+' / '+txt(humanTool(x.tool))+'</h4>'+pill(x.status)+'</div>'+
      '<p>'+txt(plain(x.finding))+'</p>'+original(x.finding)+'<div class="ic-meta">'+tr('sampleTime')+': '+txt(date(x.collected_at))+
      ' · '+tr('freshness')+': '+txt(status(x.freshness))+' · '+tr('phase')+': '+txt(x.phase)+'</div>'+
      refs(x.evidence_ref?[x.evidence_ref]:[])+'</article>').join(''):empty());
  }
  function renderKnowledge(r) {
    const k=r.cognia_knowledge||{},m=r.operational_memory||{};
    $('#ic-cognia-count').textContent=num(k.retrieved_count||0);
    $('#ic-memory-count').textContent=num(m.retrieved_count||0);
    show('#ic-cognia','<div class="ic-callout"><strong>'+txt(status(k.status))+'</strong><p>'+tr('notUsed')+'</p></div>'+
      (arr(k.items).length?arr(k.items).map(x=>'<article class="ic-detail-card"><div class="ic-detail-head"><h4>'+
        txt(state.language==='fa' && /Verified Incident Experience/.test(x.excerpt||'') ? 'تجربه حل مشکل مشابه' : (x.title||x.source_id))+'</h4>'+pill(x.use_status)+'</div>'+
        '<p>'+txt(previousExperience(x,"cognia"))+'</p>'+original(truncate(x.excerpt,1600),"متن اصلی دانش کاگنیا")+'<p class="ic-technical-spacer"+'</p><div class="ic-meta">KB: '+txt(x.knowledge_base_id)+
        ' · ID: '+txt(x.knowledge_id)+' · '+tr('confidence')+': '+esc(numberPct(x.relevance))+'</div>'+
        refs(x.source_id?[x.source_id]:[])+'</article>').join(''):empty()));
    show('#ic-memory','<div class="ic-callout"><strong>'+tr('knowledgeNotProof')+'</strong></div>'+
      (arr(m.items).length?arr(m.items).map(x=>'<article class="ic-detail-card"><div class="ic-detail-head"><h4>'+
        txt(state.language==='fa'?'تجربه رخداد قبلی':x.memory_id)+'</h4>'+pill(x.use_status)+'</div><p>'+txt(previousExperience(x,"memory"))+'</p>'+
        '<div class="ic-meta">'+tr('action')+': '+txt(humanAction(x.action))+' · '+tr('verification')+': '+txt(status(x.verification))+
        ' · '+tr('result')+': '+txt(status(x.outcome))+' · '+tr('confidence')+': '+esc(numberPct(x.similarity))+'</div>'+
        refs(x.previous_incident_id?[x.previous_incident_id]:[])+'</article>').join(''):empty()));
  }
  function renderOutcome(r) {
    const o=r.execution_outcome||{},v=r.verification_result||{},learn=r.knowledge_learning_status||{},a=r.approval_readiness||{};
    const performed=o.status && !['not_executed','not_recorded','unknown'].includes(low(o.status));
    const first=performed?'<div class="ic-outcome-heading"><strong>'+tr('execute')+'</strong>'+pill(o.status)+'</div>':
      '<p class="ic-empty">'+tr('noExecution')+'</p>';
    show('#ic-outcome-view',first+'<div class="ic-proposal">'+
      fact('action',humanAction(o.action))+fact('tool',humanTool(o.tool))+fact('target',o.target)+fact('approvalId',o.approval_id||a.approval_id)+
      fact('verification',status(v.status))+fact('confidence',numberPct(v.confidence))+
      fact('memory',learn.memory_id)+fact('result',v.message||o.error||o.details)+'</div>'+
      (arr(v.changes).length?'<div class="ic-callout"><strong>'+tr('verification')+'</strong><p>'+arr(v.changes).map(txt).join(' · ')+'</p></div>':'')+
      refs(v.evidence_refs)+
      (learn.review_available?'<a class="ic-btn ic-btn-muted" href="/dashboard?view=knowledge&review='+encodeURIComponent(learn.review_id)+'">'+tr('reviewDraft')+'</a>':''));
  }
  function renderTimeline(r) {
    const rows=arr(r.timeline);
    show('#ic-timeline',rows.length?rows.slice(0,70).map(e=>'<div class="ic-timeline-item"><strong>'+
      txt(status(e.event))+'</strong>'+pill(e.status)+'<p>'+txt(date(e.timestamp))+' · '+txt(e.actor)+'</p></div>').join(''):empty());
  }
  function renderDecision(r) {
    const a=r.approval_readiness||{},x=r.remediation_recommendation||{},statusValue=low(a.approval_status);
    const archived=!!state.historic;
    const snapshotBad=a.evidence_snapshot_binding==='drift_detected'||a.status==='new_approval_required';
    const binding=Boolean(a.binding_complete)&&!snapshotBad;
    const pending=statusValue==='pending', approved=statusValue==='approved';
    let heading=pending?tr('approvalPending'):approved?tr('approvalApproved'):tr('approvalFinished');
    if(archived)heading=tr('historical');
    show('#ic-action-state','<div class="ic-decision-status"><strong>'+esc(heading)+'</strong><p>'+
      esc(archived?tr('archiveHint'):pending?tr('approvalSeparate'):tr('execBound'))+'</p>'+
      pill(statusValue)+'</div><div class="ic-mini-facts">'+
      mini('action',humanAction(a.action||x.action))+mini('target',a.target||x.target)+mini('risk',status(x.risk_level))+
      mini('tool',humanTool(a.tool||x.tool))+mini('freshness',status(a.data_freshness))+
      mini('approvalId',a.approval_id)+'</div>');
    if(archived) {
      show('#ic-action-checks','');
      show('#ic-action-controls','<p class="ic-warning critical">'+tr('archiveHint')+'</p>'+
        '<button type="button" class="ic-btn ic-btn-primary" id="ic-archive-action-return">'+tr('returnLive')+'</button>');
      return;
    }
    const liveSnapshot=state.report?.snapshot_id===r.snapshot_id;
    const acknowledged=state.reviewedSnapshot===r.snapshot_id;
    const canAct=Boolean(a.approval_id&&binding&&liveSnapshot);
    show('#ic-action-checks',pending||approved?'<label class="ic-checkbox-row"><input id="ic-check" type="checkbox"'+
      (acknowledged?' checked':'')+(state.busy?' disabled':'')+'><span>'+
      esc(pending?tr('reviewCheckbox'):tr('resumeCheckbox'))+'</span></label>':'');
    let controls='';
    if(snapshotBad)controls+='<p class="ic-action-error">'+tr('drift')+'</p>';
    else if(!binding&&(pending||approved))controls+='<p class="ic-action-error">'+tr('noBinding')+'</p>';
    if(pending){
      controls+='<div class="ic-action-buttons"><button type="button" id="ic-approve" class="ic-btn ic-btn-primary"'+
        (!canAct||!acknowledged||state.busy?' disabled':'')+'>'+esc(state.busy?tr('processing'):tr('approveOnly'))+'</button>'+
        '<button type="button" id="ic-toggle-reject" class="ic-btn ic-btn-danger"'+(state.busy?' disabled':'')+'>'+tr('reject')+'</button></div>'+
        (state.rejectionVisible?'<div class="ic-reject-box"><label for="ic-reject-reason">'+tr('rejectReason')+
        '</label><textarea id="ic-reject-reason" placeholder="'+esc(tr('rejectHint'))+'" maxlength="1000"></textarea>'+
        '<button type="button" id="ic-confirm-reject" class="ic-btn ic-btn-danger"'+(state.busy?' disabled':'')+'>'+tr('confirmReject')+'</button></div>':'');
    }else if(approved){
      controls+='<div class="ic-action-buttons"><button type="button" id="ic-resume" class="ic-btn ic-btn-primary"'+
      (!canAct||!acknowledged||state.busy?' disabled':'')+'>'+esc(state.busy?tr('processing'):tr('resume'))+'</button></div>';
    }else {
      controls+='<p class="ic-empty">'+tr('approvalNoRecord')+'</p>';
    }
    show('#ic-action-controls',controls);
  }
  function render() {
    if(!state.report)return;
    const r=state.historic||state.report;
    $('#ic-archive-banner').hidden=!state.historic;
    renderHero(r);renderOverview(r);renderReview(r);renderAnalysis(r);renderEvidence(r);
    renderKnowledge(r);renderOutcome(r);renderTimeline(r);renderDecision(r);
    $('#ic-snapshot-label').textContent='Snapshot '+String(r.snapshot_id||'').slice(0,14);
  }
  async function loadNarrative() {
    if(!state.report||state.historic)return;
    const snapshot=state.report.snapshot_id,lang=state.language;
    try {
      const narrative=await api(base+'/decision-brief/narrative?lang='+encodeURIComponent(lang));
      if(state.report?.snapshot_id!==snapshot||state.language!==lang||state.historic)return;
      if(narrative.snapshot_id!==snapshot||narrative.language!==lang)return;
      state.narrative=narrative;render();
    }catch(_){if(state.report?.snapshot_id===snapshot&&state.language===lang)state.narrative=null;}
  }
  async function load({preserveHistory=false}={}) {
    if(!incidentId||!UUID.test(incidentId)){alert(tr('failure')+' · Invalid Incident ID');$('#ic-loader').hidden=true;return;}
    const token=++state.loadingToken;
    if(!state.report){$('#ic-loader').hidden=false;$('#ic-main').hidden=true;}
    try{
      const [report,lifecycle]=await Promise.all([api(base+'/decision-brief'),api(base+'/lifecycle')]);
      if(token!==state.loadingToken)return;
      const prev=state.report?.snapshot_id, prevApproval=state.lifecycle?.approval?.approval_id;
      state.report=report;state.lifecycle=lifecycle;
      if(prev!==report.snapshot_id||prevApproval!==lifecycle?.approval?.approval_id)state.reviewedSnapshot=null;
      if(!preserveHistory)state.historic=null;
      state.narrative=null;state.error=null;state.rejectionVisible=false;
      $('#ic-auth').hidden=true;$('#ic-loader').hidden=true;$('#ic-main').hidden=false;alert('');
      render();void loadNarrative();
    }catch(e){
      if(token!==state.loadingToken)return;
      $('#ic-loader').hidden=true;
      if(e.status===401||e.status===403){$('#ic-auth').hidden=false;$('#ic-main').hidden=true;alert(tr('authDenied'));}
      else {state.error=e.message;alert(tr('failure')+' · '+e.message);if(!state.report)$('#ic-main').hidden=true;}
    }
  }
  function returnLive(){state.historic=null;state.reviewedSnapshot=null;render();}
  async function loadHistory() {
    show('#ic-snapshots','<p>'+tr('loadingHistory')+'</p>');
    try{
      const response=await api(base+'/decision-brief/history?limit=35');
      state.history=arr(response.items);
      show('#ic-snapshots',state.history.length?state.history.map(h=>
        '<button class="ic-history-item" type="button" data-snapshot-id="'+txt(h.id)+'"><span><b>'+
        txt(h.event_type)+'</b><br><small>'+txt(date(h.created_at))+'</small></span><span>←</span></button>').join(''):empty(tr('noHistory')));
    }catch(e){show('#ic-snapshots',empty(tr('loadHistoryError')+' · '+e.message));}
  }
  async function openHistory(snapshotId){
    if(!UUID.test(snapshotId))return;
    try{
      const previous=await api(base+'/decision-brief/history/'+encodeURIComponent(snapshotId));
      state.historic=previous;state.reviewedSnapshot=null;render();
      window.scrollTo({top:0,behavior:'smooth'});
    }catch(e){notify(tr('loadHistoryError')+' · '+e.message,true);}
  }
  async function loadRaw(){
    const el=$('#ic-raw-text');el.textContent=tr('loading');
    try{
      const response=await api(base+'/evidence?limit=100');
      const content=JSON.stringify(response,null,2);
      el.textContent=content.length>42000?content.slice(0,42000)+'\n…':content;
    }catch(e){el.textContent=tr('failure')+' · '+e.message;}
  }
  function approvalCurrent() {
    const r=state.report||{},l=state.lifecycle||{};
    const a=r.approval_readiness||{},stored=l.approval||{};
    return a.approval_id&&stored.approval_id&&String(a.approval_id)===String(stored.approval_id)&&
      low(stored.status)===low(a.approval_status)&&
      a.binding_complete&&a.evidence_snapshot_binding!=='drift_detected';
  }
  async function action(kind) {
    if(state.busy||state.historic||!state.report||!approvalCurrent()) {
      notify(tr('rereview'),true);await load();return;
    }
    const approval=state.lifecycle.approval;
    const id=approval.approval_id,snapshot=state.report.snapshot_id;
    const pending=kind==='approve'||kind==='reject';
    if(low(approval.status)!==(pending?'pending':'approved'))return;
    if(kind!=='reject'&&state.reviewedSnapshot!==snapshot){notify(tr('needReview'),true);return;}
    const reason=kind==='reject'?String($('#ic-reject-reason')?.value||'').trim():'';
    if(kind==='reject'&&!reason){notify(tr('reasonMissing'),true);$('#ic-reject-reason')?.focus();return;}
    if(!confirm(tr(kind==='approve'?'firstApprove':kind==='resume'?'firstResume':'firstReject')))return;
    if(kind!=='reject'&&['high','critical'].includes(low(approval.risk_level))&&!confirm(tr('highConfirm')))return;
    state.busy=true;renderDecision(state.report);
    try{
      // Do not trust an old tab or long-lived approval card.
      // Compare exact persisted snapshot and durable approval ID before POST.
      const [latest,live]=await Promise.all([api(base+'/decision-brief'),api(base+'/lifecycle')]);
      if(latest.snapshot_id!==snapshot||live.approval?.approval_id!==id||
        low(live.approval?.status)!==(pending?'pending':'approved')||
        latest.approval_readiness?.evidence_snapshot_binding==='drift_detected'){
        state.busy=false;await load();notify(tr('rereview'),true);return;
      }
      if(kind==='approve'){
        await api('/api/v1/approvals/'+encodeURIComponent(id)+'/approve',{method:'POST'});
      }else if(kind==='reject'){
        await api('/api/v1/approvals/'+encodeURIComponent(id)+'/reject',{
          method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({reason})
        });
      }else{
        await api('/api/v1/workflow/e2e/'+encodeURIComponent(incidentId)+'/resume',{method:'POST'});
      }
      notify(tr(kind==='approve'?'successApprove':kind==='reject'?'successReject':'successResume'));
    }catch(e){notify(tr('failure')+' · '+e.message,true);alert(e.message);}
    finally{state.busy=false;state.reviewedSnapshot=null;await load();}
  }
  function bind(){
    document.querySelectorAll('[data-lang]').forEach(el=>el.addEventListener('click',()=>setLang(el.dataset.lang)));
    $('#ic-theme').addEventListener('click',()=>{const theme=document.documentElement.dataset.theme==='light'?'dark':'light';document.documentElement.dataset.theme=theme;try{localStorage.setItem('aiops.chatbot.theme',theme);}catch(_){}});
    $('#ic-copy').addEventListener('click',async()=>{
      const r=state.historic||state.report;
      if(!r)return;
      const i=r.incident_summary||{},a=r.approval_readiness||{},x=r.remediation_recommendation||{};
      const summary=[
        tr('service')+': '+value(i.service),
        tr('status')+': '+status(i.status),
        tr('cause')+': '+value(i.likely_cause),
        tr('action')+': '+value(x.action),
        tr('tool')+': '+value(x.tool),
        tr('target')+': '+value(x.target),
        tr('risk')+': '+status(x.risk_level),
        tr('approval')+': '+status(a.approval_status),
        tr('freshness')+': '+status(r.data_freshness),
        'Incident ID: '+incidentId,
        'Snapshot: '+r.snapshot_id,
        tr('refs')+': '+arr(r.source_references).join(', ')
      ].join('\n');
      try{await navigator.clipboard.writeText(summary);notify(tr('copied'));}
      catch(_){notify(tr('failure'),true);}
    });
    $('#ic-refresh').addEventListener('click',()=>{state.reviewedSnapshot=null;void load();});
    $('#ic-connect').addEventListener('click',()=>{state.key=$('#ic-key').value.trim();try{localStorage.setItem('aiops_api_key',state.key);}catch(_){}void load();});
    $('#ic-key').addEventListener('keydown',e=>{if(e.key==='Enter')$('#ic-connect').click();});
    $('#ic-return-live').addEventListener('click',returnLive);
    $('#ic-fetch-raw').addEventListener('click',()=>{void loadRaw();});
    $('#ic-history-details').addEventListener('toggle',e=>{if(e.target.open)void loadHistory();});
    document.addEventListener('click',e=>{
      const h=e.target.closest('[data-snapshot-id]');
      if(h){void openHistory(h.dataset.snapshotId);return;}
      if(e.target.closest('#ic-archive-action-return')){returnLive();return;}
      if(e.target.closest('#ic-toggle-reject')){state.rejectionVisible=!state.rejectionVisible;renderDecision(state.report);return;}
      if(e.target.closest('#ic-approve')){void action('approve');return;}
      if(e.target.closest('#ic-confirm-reject')){void action('reject');return;}
      if(e.target.closest('#ic-resume')){void action('resume');}
    });
    document.addEventListener('change',e=>{
      if(e.target.id==='ic-check'){
        state.reviewedSnapshot=e.target.checked?state.report.snapshot_id:null;
        renderDecision(state.report);
      }
    });
    window.addEventListener('storage',e=>{
      if(e.key==='aiops.chatbot.theme'&&(e.newValue==='light'||e.newValue==='dark'))document.documentElement.dataset.theme=e.newValue;
    });
    window.addEventListener('pageshow',e=>{if(e.persisted)void load();});
    setLang(state.language);
    void load();
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bind,{once:true});
  else bind();
})();
