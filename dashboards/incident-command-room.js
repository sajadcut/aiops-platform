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
      heroKicker:'اتاق بررسی و تصمیم‌گیری',navOverview:'خلاصه تصمیم',navReceived:'آلارم دریافتی',navReview:'قبل از تأیید',
      navAnalysis:'تحلیل Agentها',navEvidence:'شواهد و MCP',navKnowledge:'دانش و تجربه',navOutcome:'نتیجه اجرا',navHistory:'تاریخچه',
      receivedTitle:'آلارم دریافتی',receivedSubtitle:'آنچه واقعاً از سیستم مانیتورینگ دریافت شده',
      receivedNote:'متن و اطلاعات اصلی ثبت‌شده در زمان دریافت آلارم را می‌بینی. اطلاعات محرمانه پنهان شده‌اند. موارد قدیمی ممکن است قبل از ذخیره‌سازی نرمال شده باشند.',
      receivedLoading:'در حال دریافت آلارم ثبت‌شده…',receivedEmpty:'برای این رخداد، پیام اولیه‌ای از منابع ثبت‌شده پیدا نشد.',
      receivedOriginal:'ساختار پیام دریافتی، پس از پنهان‌سازی اطلاعات محرمانه',receivedNormalized:'نسخه ثبت‌شده و نرمال‌شده؛ بدنه دقیق اولیه در پایگاه داده موجود نیست',
      receivedWhen:'زمان دریافت',receivedEventTime:'زمان وقوع از دید منبع',receivedIdentifier:'شناسه در منبع',
      receivedMessage:'متن آلارم',receivedTags:'تگ‌های زبیکس',receivedLabels:'لیبل‌های Prometheus',
      receivedAnnotations:'توضیحات Alertmanager',receivedPayload:'نمایش تمام فیلدهای ثبت‌شده (JSON)',
      receivedCopy:'کپی اطلاعات آلارم',receivedCount:'تعداد سیگنال‌های ثبت‌شده',
      receivedMore:'فقط بخشی از آلارم‌ها نمایش داده می‌شوند؛ از API برای صفحه‌بندی داده‌های بیشتر استفاده کن.',
      receivedProblem:'آلارم مشکل',receivedRecovery:'اعلام رفع مشکل',receivedError:'دریافت آلارم اولیه ممکن نشد.',
      readFirst:'وضعیت رخداد به زبان ساده',overviewTitle:'خلاصه وضعیت و پیشنهاد AIOps',decisionSafety:'بررسی ریسک پیش از اقدام',
      reviewTitle:'اگر تأیید کنم، چه کاری انجام می‌شود؟',agentSubtitle:'گزارش قابل ممیزی عملکرد ایجنت‌ها',
      agentsTitle:'هر Agent چه چیزی بررسی کرد و به چه نتیجه‌ای رسید؟',sourceSubtitle:'فقط شواهد ثبت‌شده',evidenceTitle:'MCP و وضعیت منابع',
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
      serviceIdentity:'وضعیت شناسایی سرویس',suspectedService:'سرویس احتمالی (تأیید نشده)',identityBasis:'منبع تشخیص سرویس',
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
      heroKicker:'Incident command room',navOverview:'Quick brief',navReceived:'Received alert',navReview:'Before approval',navAnalysis:'Agent analysis',
      navEvidence:'Evidence & MCP',navKnowledge:'Knowledge & memory',navOutcome:'Execution result',navHistory:'History',
      receivedTitle:'Received alert',receivedSubtitle:'The notification actually sent by monitoring',
      receivedNote:'Original stored notification data with secrets removed. Older notifications may have been normalized before storage.',
      receivedLoading:'Loading recorded source notification…',receivedEmpty:'No stored ingress notification found for this Incident.',
      receivedOriginal:'Original received JSON structure (with credentials redacted)',
      receivedNormalized:'Normalized stored record; the precise original HTTP body is not retained',
      receivedWhen:'Received at',receivedEventTime:'Source event time',receivedIdentifier:'Source ID',
      receivedMessage:'Alert message',receivedTags:'Zabbix tags',receivedLabels:'Prometheus labels',
      receivedAnnotations:'Alertmanager annotations',receivedPayload:'All recorded fields (JSON)',
      receivedCopy:'Copy alert payload',receivedCount:'Stored signals',receivedMore:'Results limited; query the API for more.',
      receivedProblem:'Problem alert',receivedRecovery:'Recovery event',receivedError:'Could not load the source notification.',
      readFirst:'Start here',overviewTitle:'Incident summary and recommendation',decisionSafety:'Risk review',
      reviewTitle:'What exactly am I authorizing?',agentSubtitle:'Auditable specialist activity report',
      agentsTitle:'What did each agent examine and conclude?',sourceSubtitle:'Durable observations only',evidenceTitle:'MCP and evidence health',
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
      serviceIdentity:'Service identity status',suspectedService:'Suspected service (unverified)',identityBasis:'Service identity source',
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
    loadingToken: 0, busy: false, reviewedSnapshot: null, rejectionVisible: false, error: null,
    receivedSignals: null, receivedSignalsStatus: 'loading',
    lifecyclePolling: false, lastLiveCheck: null, lifecyclePollError: false,
    progress: null, progressConnected: false, progressAbort: null,
    progressStreamRunning: false, progressRetries: 0, progressFailure: false
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
    reported:'ثبت‌شده در آلارم',observed:'در ابزار پایش دیده شده (ارتباط هنوز تأیید نشده)',
    verified:'با شواهد مستقل تأیید شده',suspected:'احتمالی؛ نیازمند بررسی زنده',
    no_verified_service_identity:'هویت سرویس مشخص نیست',source_declared_service:'Tag یا فیلد معتبر آلارم',
    live_observed_service:'شواهد زنده MCP',source_fqdn_matches_knowledge:'تطابق دامنه با دانش کاگنیا',
    unavailable:'نامشخص',unverified_knowledge_hint_blocked:'حدس نامعتبر دانش مسدود شده',
    trigger_evidence_merged:'ثبت هشدار و اطلاعات اولیه',agent_handoff_completed:'ارجاع به ایجنت‌های تخصصی',
    triage_completed:'پایان بررسی اولیه',approval_requested:'درخواست تأیید از اپراتور',
    remediation_execution_precondition_verified:'بررسی دوباره شرایط اجرا',
    execution_completed:'عملیات اجرا شد',verification_completed:'پایان بررسی نتیجه اجرا',
    memory_writeback:'ثبت تجربه در حافظه عملیاتی',approval_rejected:'اپراتور اقدام را رد کرد',
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
    storage:'بررسی ذخیره‌سازی',kubernetes:'بررسی کوبرنتیز',database:'بررسی پایگاه داده',
    recovery:'بررسی بازیابی',security:'بررسی امنیت',identity:'بررسی هویت',
    messaging:'بررسی پیام‌رسانی',change:'بررسی تغییرات',
    rca:'بررسی علت خرابی',evaluator:'ارزیابی پیشنهاد'};
  const agentNamesEN = {
    triage:'TriageAgent',network:'NetworkAgent',vm:'VMAgent',
    application:'ApplicationAgent',infrastructure:'InfrastructureAgent',
    dependency:'DependencyAgent',storage:'StorageAgent',
    kubernetes:'KubernetesAgent',database:'DatabaseAgent',
    recovery:'RecoveryAgent',security:'SecurityAgent',identity:'IdentityAgent',
    messaging:'MessagingAgent',change:'ChangeAgent',
    rca:'RCA',evaluator:'Evaluator'
  };
  const agentNameEN = key => agentNamesEN[low(key)] || String(key||'Unknown Agent');
  const toolFa = {ssh_vm:'اتصال به سرور با SSH',vm_mcp:'ابزار بررسی ماشین مجازی',
    zabbix:'زبیکس',prometheus:'پرومتئوس',elasticsearch:'جست‌وجوی لاگ‌ها',
    service_status:'بررسی وضعیت سرویس',process_status:'بررسی پردازش',
    tcp_check:'تست اتصال به پورت',port_listener_status:'بررسی پورت باز',
    config_validate:'بررسی درستی تنظیمات',service_logs:'بررسی لاگ سرویس',
    collect_vm_metrics:'بررسی منابع سرور',source_observation:'اطلاعات ثبت‌شده ابزار',
    host_info:'اطلاعات سرور',disk_status:'بررسی دیسک',disk_forensics:'شناسایی فایل‌های حجیم'};
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
    const identity=i.service_identity||{};
    const unknownService=['','unknown','none','نامشخص'].includes(low(i.service));
    const subject=unknownService?'این هشدار سرور':'سرویس '+safe(i.service);
    const host=identity.source_host||i.host||i.target||x.target;
    const where=host?' '+(unknownService?'':'روی سرور ')+safe(host):'';
    const situation=facts.length?'بررسی ابزارها نشان می‌دهد: '+facts.join('؛ ')+'.' :
      'هنوز اطلاعات کافی برای توضیح دقیق وضعیت سرویس نداریم.';
    const stored=String(r.localized_narrative?.fa || '').trim();
    const storedNote=isFaText(stored) && stored.length <= 280 &&
      !/^رخداد سرویس|^شواهد ثبت شده|^برای این رخداد/.test(stored) ? stored+' ' : '';
    const next=x.action?'پیشنهاد سیستم '+humanAction(x.action)+' است.':'هنوز کاری برای اجرا پیشنهاد نشده است.';
    return 'برای '+subject+where+' رخداد ثبت شده. '+storedNote+situation+' '+next+
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
  const progressStageFa={
    context:'جمع‌آوری شواهد و اطلاعات دارایی',
    triage:'تریاژ آلارم و انتخاب ایجنت‌ها',
    parallel_agents:'تحلیل ایجنت‌ها و جمع‌بندی یافته‌ها',
    rca:'بررسی علت ریشه‌ای با LLM',
    evaluator:'ارزیابی شواهد و کیفیت نتیجه',
    decision:'تهیه پیشنهاد و تصمیم AIOps',
    approval:'در انتظار تصمیم اپراتور',
    execution:'اجرای عملیات تأییدشده',
    verification:'راستی‌آزمایی اثر عملیات',
    memory:'ثبت نتیجه در حافظه عملیاتی',
    end:'اتمام پردازش Workflow',
    knowledge:'بررسی دانش سازمانی Cognia',
    zabbix:'دریافت اطلاعات از Zabbix MCP',
    vm_mcp:'بررسی سرور با VM MCP',
    elasticsearch:'بررسی خطاها در Elastic MCP',
    prometheus:'بررسی Prometheus MCP',
    kubernetes_api:'بررسی Kubernetes MCP',
  };
  const progressStageEn={
    context:'Collecting live evidence and asset context',
    triage:'Triage and agent selection',
    parallel_agents:'Running specialist agents',
    rca:'LLM root-cause analysis',
    evaluator:'Evaluating evidence and decision quality',
    decision:'Preparing the operational decision',
    approval:'Waiting for operator approval',
    execution:'Executing approved remediation',
    verification:'Verifying recovery',
    memory:'Recording operational experience',
    end:'Workflow finished',
    knowledge:'Consulting Cognia knowledge',
    zabbix:'Checking Zabbix MCP',
    vm_mcp:'Inspecting VM MCP',
    elasticsearch:'Checking Elastic MCP logs',
    prometheus:'Checking Prometheus MCP',
    kubernetes_api:'Checking Kubernetes MCP',
  };
  const phaseName = key => String(key||'').startsWith('agent:')
    ? (state.language==='fa'?'در حال تحلیل توسط ':'Analyzing with ')+
      humanAgent(key.slice(6))+' ('+agentNameEN(key.slice(6))+')'
    : (state.language==='fa'?progressStageFa:progressStageEn)[key] || String(key||'');
  function updateProgressClock() {
    const element=$('#ic-flow-elapsed');
    if(!element || !state.progress?.started_at || !element.closest || state.historic)return;
    const seconds=Math.max(0,Math.floor((Date.now()-new Date(state.progress.started_at).getTime())/1000));
    if(Number.isFinite(seconds))element.textContent=num(Math.floor(seconds/60))+
      (state.language==='fa'?' دقیقه ':'m ')+num(seconds%60)+(state.language==='fa'?' ثانیه':'s');
  }
  function renderAnalysisProgress() {
    const box=$('#ic-analysis-progress');
    if(!box)return;
    const l=state.lifecycle||{},r=state.report||{},p=state.progress||{};
    const approval=low(l.approval?.status||p.approval_status||r.approval_readiness?.approval_status);
    const statusValue=low(l.incident_status||p.incident_status||r.incident_summary?.status);
    const running=l.analysis_in_progress===true ||
      (l.analysis_in_progress==null && statusValue==='analyzing' &&
       !['pending','approved','rejected'].includes(approval) &&
       !['paused','completed','failed'].includes(low(l.checkpoint_status)));
    const awaiting=['pending','approved'].includes(approval);
    const terminal=['completed','failed'].includes(low(p.checkpoint_status));
    const hasEvents=Boolean(p.last_event_at);
    if(state.historic || (!running && !awaiting && !hasEvents)){box.hidden=true;return;}
    box.hidden=false;
    const fa=state.language==='fa';
    const execution=approval==='consumed' &&
      (p.current_stage==='execution'||p.current_stage==='verification'||p.current_stage==='memory' ||
       (l.analysis_phase==='executing'&&!terminal));
    const currentStage=awaiting?'approval':
      (execution&&!['execution','verification','memory'].includes(p.current_stage))?
        'execution':p.current_stage||(execution?'execution':running?'context':null);
    const activeAgent=Object.entries(p.agents||{})
      .filter(([_,v])=>v?.status==='started')
      .sort((a,b)=>String(b[1].at).localeCompare(String(a[1].at)))[0];
    const activeProvider=Object.entries(p.providers||{})
      .filter(([_,v])=>v?.status==='started')
      .sort((a,b)=>String(b[1].at).localeCompare(String(a[1].at)))[0];
    const activeLabel=activeProvider && currentStage==='context'?
      phaseName(activeProvider[0]):activeAgent && currentStage==='parallel_agents'?
      phaseName('agent:'+activeAgent[0]):phaseName(currentStage);
    const spinner=$('#ic-analysis-spinner');
    if(spinner)spinner.hidden=awaiting||terminal||!running&&!(execution&&currentStage);
    const title=$('#ic-analysis-title'),detail=$('#ic-analysis-detail');
    if(title)title.textContent=activeLabel||
      (terminal?(fa?'بررسی رخداد تکمیل شده است':'Incident analysis finished'):
        fa?'در حال دریافت وضعیت تحلیل…':'Loading analysis progress…');
    if(detail)detail.textContent=awaiting?
      (fa?'تحلیل متوقف است؛ منتظر تصمیم انسانی':'Analysis is paused for human approval'):
      terminal?(fa?'گزارش مراحل واقعی ثبت‌شده':'Recorded workflow milestones'):
      state.progressFailure?(fa?'ارتباط زنده موقتاً قطع شده؛ تلاش برای اتصال مجدد…':'Live connection lost; reconnecting…'):
      (fa?'رویدادهای واقعی از سرور دریافت می‌شوند':'Receiving actual events from the server');
    const percent=execution?p.execution_percent:p.analysis_percent;
    const bar=$('#ic-flow-bar'),pct=$('#ic-flow-percent');
    if(bar) {
      if(hasEvents && Number.isFinite(percent)){bar.value=Math.max(0,Math.min(100,percent));}
      else bar.removeAttribute?.('value');
    }
    if(pct)pct.textContent=hasEvents&&Number.isFinite(percent)?num(percent)+'٪':'—';
    const caption=$('#ic-flow-caption');
    if(caption)caption.textContent=execution?
      (fa?'پیشرفت مراحل اجرا و راستی‌آزمایی':'Execution and verification milestones'):
      (fa?'پیشرفت مراحل تحلیل':'Analysis milestones');
    const caution=$('#ic-flow-caution');
    if(caution)caution.textContent=fa?
      'درصد فقط از مراحل واقعاً تکمیل‌شده است، نه تخمین زمان باقی‌مانده.':
      'Percentage is based on verified stage completion, not time remaining.';
    const timeline=[...Object.entries(p.stages||{}),...Object.entries(p.providers||{}),
      ...Object.entries(p.agents||{}).map(([key,v])=>['agent:'+key,v])]
      .filter(([_,v])=>v&&v.at)
      .sort((x,y)=>String(x[1].at).localeCompare(String(y[1].at))).slice(-8);
    show('#ic-flow-steps',timeline.map(([key,v])=>{
      const status=low(v.status),icon=status==='completed'?'✓':status==='failed'?'!':
        status==='skipped'?'–':'';
      const suffix=status==='completed'?(fa?' · بررسی انجام شد':' · checked'):
        status==='failed'?(fa?' · ناموفق':' · failed'):'';
      return '<li data-state="'+esc(status)+'"><span class="ic-flow-step-icon" aria-hidden="true">'+
        esc(icon)+'</span><span>'+esc(phaseName(key)+suffix)+'</span></li>';
    }).join(''));
    const connection=$('#ic-flow-connection');
    if(connection)connection.textContent=state.progressConnected?
      (fa?'● اتصال زنده برقرار است · SSE':'● Live SSE connected'):
      (fa?'○ تلاش برای اتصال زنده؛ وضعیت قبلی حفظ شده است':'○ Reconnecting; last state preserved');
    updateProgressClock();
  }

  function updateProgressSnapshot(snapshot) {
    if(!snapshot || snapshot.schema!=='incident_progress.v1'||state.historic)return;
    const prior=state.progress||{};
    state.progress=snapshot;
    state.progressFailure=false;
    state.lastLiveCheck=Date.now();
    renderAnalysisProgress();
    // Only material lifecycle changes cause a full report refresh. Progress
    // events alone must never reset the operator's review/approval checkbox.
    const oldApproval=low(state.lifecycle?.approval?.status||state.report?.approval_readiness?.approval_status);
    const newApproval=low(snapshot.approval_status);
    const oldIncident=low(state.lifecycle?.incident_status||state.report?.incident_summary?.status);
    const statusChanged=(newApproval && oldApproval && newApproval!==oldApproval) ||
      (snapshot.incident_status && oldIncident && snapshot.incident_status!==oldIncident);
    if(statusChanged && !state.busy && state.report && !state.historic &&
       (snapshot.last_event_at!==prior.last_event_at||
        snapshot.approval_status!==prior.approval_status||
        snapshot.incident_status!==prior.incident_status))
      void load({preserveHistory:true});
  }

  let progressRetryTimer=null;
  async function connectProgressStream() {
    if(state.progressStreamRunning||document.hidden||state.historic||!incidentId||!state.report)return;
    state.progressStreamRunning=true;
    const controller=new AbortController();
    state.progressAbort=controller;
    try{
      const headers={'Accept':'text/event-stream','Cache-Control':'no-cache'};
      if(state.key)headers['X-API-Key']=state.key;
      const response=await fetch(base+'/progress/stream',{
        method:'GET',headers,credentials:'same-origin',signal:controller.signal
      });
      if(!response.ok||!response.body||typeof response.body.getReader!=='function')
        throw new Error('progress_stream_unavailable');
      state.progressConnected=true;state.progressRetries=0;state.progressFailure=false;
      renderAnalysisProgress();
      const reader=response.body.getReader(),decoder=new TextDecoder();
      let buffer='';
      while(!controller.signal.aborted) {
        const {done,value}=await reader.read();
        if(done)break;
        buffer=(buffer+decoder.decode(value,{stream:true})).replace(/\r/g,'');
        if(buffer.length>100000)throw new Error('oversized_progress_event');
        let pos;
        while((pos=buffer.indexOf('\n\n'))>=0) {
          const packet=buffer.slice(0,pos).replace(/\r/g,'');
          buffer=buffer.slice(pos+2);
          const message=packet.split('\n').find(line=>line.startsWith('data: '));
          if(!message)continue;
          if(packet.includes('event: unavailable')){state.progressFailure=true;continue;}
          if(!packet.includes('event: progress'))continue;
          try{updateProgressSnapshot(JSON.parse(message.slice(6)));}catch(_){}
        }
      }
    }catch(_){
      if(!controller.signal.aborted)state.progressFailure=true;
    }finally{
      if(state.progressAbort===controller)state.progressAbort=null;
      state.progressConnected=false;state.progressStreamRunning=false;
      renderAnalysisProgress();
      if(!controller.signal.aborted && !document.hidden && !state.historic){
        const retry=Math.min(20000,1500*Math.pow(2,Math.min(4,++state.progressRetries)));
        progressRetryTimer=setTimeout(()=>{void connectProgressStream();},retry);
        if(typeof progressRetryTimer?.unref==='function')progressRetryTimer.unref();
      }
    }
  }
  // Use a lightweight durable lifecycle GET, not repeated heavy LLM narratives.
  // Reload the report only when a material workflow phase/version changes.
  async function pollLifecycle() {
    if(state.progressConnected || state.lifecyclePolling || document.hidden || state.historic || state.busy ||
       !state.report || !incidentId)return;
    state.lifecyclePolling=true;
    try {
      const latest=await api(base+'/analysis-status');
      if(state.busy || state.historic)return;
      const previous=state.lifecycle||{};
      const changed=latest.incident_status!==previous.incident_status ||
        latest.analysis_in_progress!==previous.analysis_in_progress ||
        latest.analysis_phase!==previous.analysis_phase ||
        latest.checkpoint_status!==previous.checkpoint_status ||
        latest.checkpoint_version!==previous.checkpoint_version ||
        latest.current_node!==previous.current_node ||
        latest.approval?.approval_id!==previous.approval?.approval_id ||
        latest.approval?.status!==previous.approval?.status;
      state.lastLiveCheck=Date.now();
      state.lifecyclePollError=false;
      if(changed) {
        await load({preserveHistory:true});
      } else {
        // Keep full lifecycle details for the report and approval controls;
        // the lightweight status response must never replace those fields.
        state.lifecycle={...previous,analysis_in_progress:latest.analysis_in_progress,
          analysis_phase:latest.analysis_phase,incident_status:latest.incident_status};
        renderAnalysisProgress();
      }
    }catch(_){
      state.lifecyclePollError=true;
      renderAnalysisProgress();
    }finally{state.lifecyclePolling=false;}
  }

  function renderHero(r) {
    const i=r.incident_summary||{},a=r.approval_readiness||{},action=r.remediation_recommendation||{};
    const identity=i.service_identity||{};
    const serviceUnknown=['','unknown','none','نامشخص'].includes(low(i.service));
    $('#ic-title').textContent=serviceUnknown
      ? (state.language==='fa' ? 'هشدار سرور'+(identity.source_host?' '+identity.source_host:'؛ سرویس نامشخص') : 'Host alert: '+(identity.source_host||'unidentified service'))
      : value(i.service);
    $('#ic-description').textContent=value(i.summary);
    $('#ic-short-id').textContent='#'+String(incidentId).slice(0,8);
    show('#ic-hero-badges',pill(i.severity)+pill(i.status)+pill(a.approval_status));
    const authStatus=low(a.approval_status);
    const analyzing=state.lifecycle?.analysis_in_progress===true;
    const pulseTitle=analyzing
      ? (state.language==='fa'?'در حال بررسی و تحلیل':'Investigation in progress')
      : authStatus==='pending'?tr('approvalPending'):authStatus==='approved'?tr('approvalApproved'):tr('approvalFinished');
    show('#ic-decision-pulse','<small>'+tr('decisionDesk')+'</small><strong>'+esc(pulseTitle)+'</strong><p>'+
      txt(analyzing
        ? (state.language==='fa'?'Agentها در حال گردآوری شواهد و بررسی رخداد هستند.':'Agents are analyzing the incident and gathering evidence.')
        : authStatus==='approved'?tr('approvalSeparate'):tr('backendGate'))+'</p>');
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
    show('#ic-brief-lead','<p>'+txt(deterministic)+'</p>'+original(i.likely_cause,'شرح علت احتمالی در گزارش اصلی')+narrative);
    show('#ic-key-answer',[
      fact('cause',humanCause(i.likely_cause)),fact('causeStatus',status(i.cause_status)),
      fact('serviceIdentity',status(i.service_identity?.status)),
      (i.service_identity?.suspected_service?fact('suspectedService',i.service_identity.suspected_service):''),
      fact('identityBasis',status(i.service_identity?.basis)),
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
    show('#ic-preconditions','<div class="ic-callout"><strong>'+esc(tr('why'))+'</strong><p>'+txt(explanation(r))+'</p>'+original(x.why,'توضیح فنی دلیل پیشنهاد')+
      refs(i.cause_evidence_refs)+'</div>'+
      (arr(x.unverified_assumptions).length?'<div class="ic-warning">'+tr('missing')+'</div><details class="ic-technical"><summary>مشاهده بررسی‌های باقی‌مانده</summary><p dir="auto">'+arr(x.unverified_assumptions).slice(0,10).map(txt).join('، ')+'</p></details>':''));
  }
  // Specialized display is strictly informational. "Referenced evidence" is
  // NOT an audit claim that the specialist itself called an MCP/SSH tool.
  const agentScopes = {
    triage:['دسته‌بندی هشدار و تعیین مسیر بررسی','هویت سرویس، شدت گزارش‌شده و انتخاب ایجنت‌ها'],
    network:['شبکه و مسیر ارتباطی','پورت، اتصال TCP، DNS و مسیر شبکه'],
    vm:['وضعیت ماشین مجازی و سرویس','systemd، پردازش، منابع و کانفیگ'],
    application:['سلامت برنامه','لاگ برنامه، کانفیگ، پردازش و پاسخ سرویس'],
    infrastructure:['زیرساخت میزبان','منابع میزبان، دیسک، ظرفیت و پایداری'],
    dependency:['وابستگی‌های سرویس','اتصال و سلامت سرویس‌های وابسته'],
    storage:['ذخیره‌سازی','ظرفیت، دیسک، I/O و فایل‌سیستم'],
    kubernetes:['کوبرنتیز','Pod، Namespace، Deployment و وضعیت کلاستر'],
    database:['پایگاه داده','اتصالات، درخواست‌ها و وضعیت دیتابیس'],
    recovery:['بازیابی خدمت','پیش‌شرط‌های ایمن و بررسی‌های بعد از بازیابی'],
    security:['امنیت','نشانه‌های دسترسی غیرعادی و شواهد امنیتی'],
    identity:['احراز هویت','هویت‌ها و مجوزهای دسترسی'],
    messaging:['پیام‌رسانی','صف‌ها و ارتباط سامانهٔ پیام'],
    change:['تغییرات','تغییر کانفیگ و استقرارهای اخیر'],
  };
  const agentEvidenceFocus = {
    triage:/zabbix|alert|service_status|host_info/i,
    network:/tcp_check|port_listener_status|network_status|dns_check|route_check|firewall_status/i,
    vm:/service_status|process_status|config_validate|cpu_usage|memory_usage|swap_usage|disk_status|host_info|service_logs/i,
    application:/config_validate|service_logs|process_status|port_listener_status|tcp_check/i,
    infrastructure:/cpu_usage|memory_usage|swap_usage|io_wait|disk_status|host_info|collect_vm_metrics/i,
    dependency:/tcp_check|dns_check|route_check|dependency|prometheus/i,
    storage:/disk_status|disk_forensics|io_wait|filesystem|storage|inode/i,
    kubernetes:/pod|namespace|kubernetes|deployment/i,
    database:/database|db|connection_pool/i,
    recovery:/config_validate|service_status|process_status|port_listener_status/i,
    security:/firewall_status|security|audit/i,
    change:/config_validate|change|journal|audit/i
  };
  const agentEvidenceLabel = ref => {
    const match=String(ref||'').match(/(?:^|:)(service_status|service_logs|process_status|config_validate|port_listener_status|tcp_check|host_info|disk_status|disk_forensics|cpu_usage|memory_usage|swap_usage|io_wait|route_check|dns_check|firewall_status|collect_vm_metrics)(?::|$)/i);
    if(match)return humanTool(match[1])+(match[1]==='cpu_usage'?' (CPU)':match[1]==='memory_usage'?' (RAM)':'');
    if(/zabbix/i.test(ref))return 'اطلاعات زبیکس';
    if(/prom/i.test(ref))return 'اطلاعات پرومتئوس';
    if(/elastic/i.test(ref))return 'جست‌وجوی لاگ‌ها';
    return null;
  };
  const agentMissingFa = raw => {
    const s=String(raw||'');
    if(state.language!=='fa')return s;
    const table=[
      [/auditd.*systemctl|audit logs.*admin/i,'لاگ ممیزی دستورهای مدیریتی و توقف سرویس'],
      [/automation|orchestration.*logs/i,'لاگ سامانه‌های اتوماسیون و استقرار'],
      [/bash history/i,'تاریخچه فرمان‌های مدیریتی (در صورت دسترسی و اعتبار)'],
      [/nginx error logs|error\.log/i,'لاگ خطاهای Nginx'],
      [/journal|system logs/i,'لاگ رویدادهای سیستم و سرویس'],
      [/kernel logs|dmesg|oom|segfault/i,'لاگ کرنل و خطاهای حافظه'],
      [/distributed trace/i,'ردیابی درخواست‌ها میان سرویس‌ها'],
      [/local TCP|connectivity|port/i,'بررسی اتصال و پورت سرویس از میزبان'],
      [/configuration|config.*test/i,'تأیید اعتبار کانفیگ سرویس'],
      [/structured.*analysis/i,'خروجی معتبر و ساختاریافتهٔ تحلیل ایجنت'],
      [/fresh evidence/i,'جمع‌آوری شواهد تازه'],
      [/permission|sudo/i,'بررسی دسترسی لازم برای ابزار تشخیصی'],
    ];
    const known=table.find(([pattern])=>pattern.test(s));
    return known?known[1]:'بررسی تکمیلی: '+s;
  };
  const agentFindingFa = raw => {
    const x=String(raw||'');
    if(state.language!=='fa'||isFaText(x))return x;
    const findings=signalFacts(x);
    if(findings.length)return findings.join('؛ ')+'.';
    if(/Incident triaged to/i.test(x)) {
      const target=(x.match(/triaged to\s+([\w-]+)/i)||[])[1];
      const layer=(x.match(/affected_layer\s*=\s*([\w-]+)/i)||[])[1];
      const severity=(x.match(/severity\s*=\s*([\w-]+)/i)||[])[1];
      return 'بررسی اولیه: هشدار برای بررسی تخصصی به '+(target?humanAgent(target):'ایجنت مربوط')+
        ' ارجاع شده'+(layer?'؛ لایهٔ گزارش‌شده: '+(layer==='vm'?'ماشین مجازی':layer):'')+
        (severity?'؛ شدت برآوردی این مرحله: '+status(severity):'')+
        (/no customer impact.*evidenced/i.test(x)?'؛ شواهد کافی از اثر بر مشتری ثبت نشده است':'')+'.';
    }
    if(/(?:manual stop possible|manual(?:ly)? stop(?:ped)?(?: service)? is possible|A manual stop is possible but not proven)/i.test(x))
      return 'توقف دستی سرویس یک فرضیه است؛ عامل توقف و عمدی‌بودن آن هنوز تأیید نشده است.';
    if(/no confirmed domain fault yet/i.test(x))return 'با شواهد فعلی خرابی مستقلی در این حوزه تأیید نشده است.';
    if(/configuration (?:validation|check|syntax).*(?:success|passed|valid)/i.test(x))return 'تست ساختار تنظیمات سرویس با موفقیت انجام شده است.';
    if(/(?:agent|analysis).*timed out|readtimeout|timeout/i.test(x))return 'تحلیل این ایجنت به دلیل پایان مهلت پاسخ کامل نشده است.';
    return null;
  };
  const agentLine = raw => {
    const originalText=String(raw||'').trim();
    if(!originalText)return '<span>'+esc(state.language==='fa'?'شرحی در خروجی این ایجنت ثبت نشده است.':'No finding was recorded.')+'</span>';
    const translated=agentFindingFa(originalText);
    if(translated)return '<span>'+esc(translated)+'</span>';
    // Unknown phrases are NOT invalid findings. Show their exact, escaped
    // source text instead of an alarming "no verified Persian" placeholder.
    return '<span class="ic-agent-source-label">'+esc(state.language==='fa'?
        'متن اصلی ثبت‌شده توسط ایجنت (ترجمه نشده):':'Original agent finding:')+'</span>'+
      '<span class="ic-agent-source-text" dir="auto">'+txt(originalText)+'</span>';
  };
  const agentBullets = (items, mapper=agentLine, max=6) =>
    '<ul class="ic-agent-bullets">'+items.slice(0,max).map(x=>'<li>'+mapper(x)+'</li>').join('')+'</ul>';
  const agentDetail = (title, body, count) =>
    '<details class="ic-agent-fold"><summary>'+esc(title)+(count===undefined?'':' ('+num(count)+')')+'</summary><div class="ic-agent-fold-body">'+body+'</div></details>';

  function renderConfigDiagnostic(r) {
    const config=r.configuration_diagnostic||{};
    const advice=r.unknown_guidance||{},fa=state.language==='fa';
    const kind=low(config.status);
    const items=[];
    if(kind==='invalid') {
      const location=[config.config_file || (fa?'مسیر فایل ثبت نشده':'File not recorded'),
        Number.isInteger(config.error_line)?(fa?'خط '+num(config.error_line):'line '+num(config.error_line)):null]
        .filter(Boolean).join(' — ');
      items.push('<article class="ic-config-check" data-config-status="invalid"><h3>'+
        esc(fa?'خطای واقعی در کانفیگ سرویس شناسایی شد':'Service configuration validation failed')+'</h3>'+
        '<p><b>'+esc(fa?'محل خطا:':'Reported location:')+'</b> <span dir="auto">'+txt(location)+'</span></p>'+
        (config.syntax_error?'<p><b>'+esc(fa?'پیام ابزار بررسی سینتکس:':'Validator error:')+
          '</b> <span dir="auto">'+txt(config.syntax_error)+'</span></p>':'')+
        '<p>'+esc(fa?
          'کانفیگ فعلی تست معتبر را رد کرده است. ابتدا خطای گزارش‌شده با فرایند تغییرات مجاز اصلاح شود، سپس کانفیگ دوباره تست شود. فقط بعد از موفقیت تست، Start سرویس برای تأیید اپراتور پیشنهاد می‌شود. علت توقف اولیه هنوز مشخص نیست.':
          'The current syntax check failed. Repair under change control, revalidate, and only then propose an operator-approved start. The original stop cause remains unknown.')+'</p>'+
        refs(config.evidence_refs)+'</article>');
    } else if(kind==='valid') {
      items.push('<article class="ic-config-check" data-config-status="valid"><h3>'+
        esc(fa?'تست سینتکس کانفیگ موفق بوده است':'Configuration syntax check passed')+'</h3><p>'+
        esc(fa?'این نتیجه سلامت اجرای سرویس یا تمام وابستگی‌های آن را تضمین نمی‌کند.':'This does not guarantee service health or dependencies.')+
        '</p>'+(config.config_file?'<p>'+esc(fa?'فایل بررسی‌شده:':'Checked file:')+' <span dir="ltr">'+
          txt(config.config_file)+'</span></p>':'')+refs(config.evidence_refs)+'</article>');
    }
    if(arr(advice.items).length) {
      items.push('<article class="ic-config-check" data-config-status="advisory"><h3>'+
        esc(fa?'استعلام موارد نامشخص از LLM':'LLM consultation for unknown diagnostics')+'</h3><p>'+
        esc(fa?'این پاسخ‌ها فقط روش پیشنهادی بررسی هستند؛ هیچ فرمانی از LLM اجرا نشده و کانفیگ تأیید نشده است.':
          'These are advisory suggestions only; no LLM-generated command has been executed or validated.')+
        '</p><ul class="ic-agent-bullets">'+arr(advice.items).slice(0,5).map(x=>
          '<li><b>'+txt(x.subject||x.topic)+'</b> — '+txt(x.validation_approach||x.explanation)+
          '</li>').join('')+'</ul></article>');
    } else if(kind==='unverified') {
      items.push('<article class="ic-config-check" data-config-status="unknown"><h3>'+
        esc(fa?'روش یا نتیجهٔ معتبر تست کانفیگ هنوز مشخص نیست':'Config validation is unverified')+
        '</h3>'+(config.config_file?'<p>'+
          esc(fa?'مسیر احتمالی کانفیگ از تعریف systemd (هنوز تست نشده):':'Systemd config candidate (not validated):')+
          ' <span dir="ltr">'+txt(config.config_file)+'</span></p>':'')+
        '<p>'+esc(fa?
          'AIOps نباید سالم بودن کانفیگ یا امکان Start ایمن را حدس بزند. در صورت نامشخص بودن روش بررسی، استعلام از LLM فقط راهنمای اپراتور است.':
          'Do not guess that the configuration is valid. LLM guidance cannot replace a real check.')+'</p></article>');
    }
    show('#ic-config-diagnostic',items.join(''));
  }

  function renderDiskFileCausality(r) {
    const data=r.disk_file_causality||{},fa=state.language==='fa';
    const files=arr(data.files);
    if(!files.length){show('#ic-disk-forensics','');return;}
    const title=fa?'بررسی علت مصرف فضای دیسک':'Disk usage cause investigation';
    const notice=fa?
      'این اطلاعات از فایل‌های حجیم و در بعضی موارد نمونه‌برداری کوتاهِ رشد و پردازش‌های دارای فایل باز به‌دست آمده است. بازبودن فایل لزوماً به معنی ایجادکننده بودن پردازش نیست. علت تاریخی رشد، سیاست نگهداری و ایمنی حذف هنوز تأیید نشده و هیچ درخواست پاک‌سازی صادر نشده است.':
      'File metadata, short-term growth and open handles cannot establish historical cause or deletion safety. No cleanup action is authorized.';
    const top=files.slice(0,12).map(file=>{
      const growth=file.growth_confirmed===true
        ?(fa?'رشد مشاهده‌شده: ':'Observed growth: ')+
          num(Math.round((Number(file.growth_bytes_over_2_seconds)||0)/1048576))+
          ' MB / 2s'
        :file.growth_measured===true
          ?(fa?'در نمونه کوتاه رشد ثبت نشد':'No growth during short sample')
          :(fa?'رشد اندازه‌گیری نشده':'Growth not measured');
      const holders=arr(file.open_handles).slice(0,3).map(h=>
        txt(h.process_name||'process')+' (PID '+esc(h.pid)+')'
      ).join('، ');
      const activity='<div>'+esc(growth)+'</div>'+
        (holders?'<div>'+esc(fa?'فایل باز در: ':'Open file: ')+holders+'</div>':'');
      return '<tr><td dir="auto">'+txt(file.path)+'</td><td>'+
        esc(num(Math.round((Number(file.size_bytes)||0)/1048576)))+' MB</td><td>'+
        esc(file.mount||'—')+'</td><td>'+activity+'</td><td>'+
        esc(fa?'علت قطعی نامشخص؛ حذف مجاز نیست':'Cause unverified; do not delete')+
        '</td></tr>';
    }).join('');
    const logs=arr(data.related_error_log_observations),alerts=arr(data.zabbix_alert_refs);
    const overlaps=arr(data.candidate_temporal_overlaps);
    const correlation=fa?
      'شواهد خطای قابل‌بررسی: '+num(logs.length)+' مورد؛ آلارم‌های زبیکس: '+num(alerts.length)+
      ' مورد؛ هم‌زمانی نزدیک تغییر فایل با خطا: '+num(overlaps.length)+' مورد. این‌ها فقط سرنخ هستند؛ تولیدکنندهٔ فایل یا علت رشد هنوز ثابت نشده است.':
      'Potential log observations: '+logs.length+', Zabbix alerts: '+alerts.length+
      ', file/error time overlaps: '+overlaps.length+'. Correlation never establishes the file producer.';
    show('#ic-disk-forensics','<article class="ic-config-check" data-config-status="advisory">'+
      '<h3>'+esc(title)+'</h3><p>'+esc(notice)+'</p>'+
      '<div class="ic-disk-file-wrap"><table class="ic-disk-file-table"><thead><tr>'+
      '<th>'+esc(fa?'مسیر فایل':'File')+'</th><th>'+esc(fa?'حجم تقریبی':'Size')+
      '</th><th>'+esc(fa?'فایل‌سیستم':'Mount')+'</th><th>'+
      esc(fa?'شواهد فعالیت':'Observed activity')+'</th><th>'+
      esc(fa?'تصمیم فعلی':'Current decision')+'</th></tr></thead><tbody>'+top+
      '</tbody></table></div><p>'+esc(correlation)+'</p><p>'+
      esc(fa?'گام بعد: یافتن فرایند تولیدکننده، بررسی رشد در زمان و خطاهای Elastic/Zabbix، کنترل Log Rotation و سیاست نگهداری؛ سپس ارائهٔ اصلاح دقیق با شواهد.':
        'Next: identify producing process, confirm growth/error correlation, retention and log rotation before proposing a scoped repair.')+
      '</p></article>');
  }

  function renderAnalysis(r) {
    renderDiskFileCausality(r);
    renderConfigDiagnostic(r);
    const c=r.rca_assessment||{},agents=arr(r.agent_findings);
    const fa=state.language==='fa';
    const metrics=[
      [fa?'اطمینان به علت ریشه‌ای':'Root-cause confidence',c.rca_confidence,
        fa?'چقدر از علت اصلی خرابی اطمینان داریم؛ نه درصد پیشرفت تحلیل.':'Confidence in the root cause, not completion.'],
      [fa?'اطمینان ارزیاب تصمیم':'Decision evaluator confidence',c.evaluator_confidence,
        fa?'ارزیابی کیفیت تصمیم؛ الزاماً برابر اطمینان به علت خرابی نیست.':'Quality of the decision evaluation; distinct from RCA.'],
      [fa?'توافق ایجنت‌ها':'Specialist agreement',c.agent_agreement,
        fa?'میزان هم‌نظر بودن Agentها؛ با صحت نتیجه یکسان نیست.':'Agreement among agents, not a proof of correctness.'],
    ];
    show('#ic-confidence',metrics.map(([label,note,description]) =>
      '<div class="ic-confidence-card"><span>'+esc(label)+'</span><strong>'+esc(numberPct(note))+
      '</strong><small>'+esc(description)+'</small></div>').join(''));
    const success=agents.filter(a=>low(a.status)==='success').length;
    const partial=agents.filter(a=>low(a.status)==='partial').length;
    const failed=agents.filter(a=>['failed','error'].includes(low(a.status))).length;
    const missing=agents.filter(a=>['unknown','skipped'].includes(low(a.status))).length;
    const intro=fa?
      'هر کارت نشان می‌دهد ایجنت چه داده‌ای دریافت کرده، چه نتیجه‌ای نوشته، چه فرضیه‌ای داشته و چه چیزی هنوز معلوم نیست. استناد به شواهد به معنی اجرای مستقیم ابزار توسط آن Agent نیست.':
      'Each card distinguishes the specialist’s recorded findings, cited evidence, open hypotheses and suggested next checks. Citing evidence does not mean the agent itself executed a tool.';
    show('#ic-agent-summary','<div class="ic-agent-overview"><p>'+esc(intro)+'</p>'+
      '<div class="ic-agent-totals"><span>'+esc(fa?'ایجنت‌های ثبت‌شده':'Recorded agents')+' <b>'+num(agents.length)+'</b></span>'+
      '<span>'+esc(fa?'تحلیل کامل':'Complete')+' <b>'+num(success)+'</b></span>'+
      '<span>'+esc(fa?'تحلیل ناقص':'Partial')+' <b>'+num(partial)+'</b></span>'+
      '<span>'+esc(fa?'ناموفق':'Failed')+' <b>'+num(failed)+'</b></span>'+
      (missing?'<span>'+esc(fa?'نامشخص/اجرا نشده':'Unknown / skipped')+' <b>'+num(missing)+'</b></span>':'')+'</div></div>');
    const cards=agents.map((a,i)=>{
      const agent=low(a.agent);
      const scope=agentScopes[agent]||[humanAgent(a.agent),fa?'محدودهٔ بررسی این ایجنت در داده‌ها توضیح داده نشده است.':'Scope not recorded'];
      const coverage=a.evidence_coverage;
      const directFindings=arr(a.findings).filter(x=>typeof x==='string'&&x.trim());
      const hypotheses=arr(a.hypotheses).filter(x=>x&&x.text);
      const advice=arr(a.recommended_checks).filter(x=>typeof x==='string'&&x.trim());
      const recommendations=arr(a.recommendations).filter(x=>typeof x==='string'&&x.trim());
      const missingEvidence=arr(a.missing_evidence);
      const linked=arr(a.evidence_refs).filter(x=>typeof x==='string'&&x);
      const focusPattern=agentEvidenceFocus[agent];
      const relevant=linked.filter(ref=>focusPattern&&focusPattern.test(ref));
      const linkedNames=[...new Set(relevant.map(agentEvidenceLabel).filter(Boolean))].slice(0,6);
      const summary=directFindings.length?
        agentBullets(directFindings):(
          a.finding?'<p>'+agentLine(a.finding)+'</p>':
            '<p class="ic-agent-empty">'+esc(fa?
              'یافته‌ای در خروجی این ایجنت ثبت نشده است.':
              'No finding was recorded by this agent.')+'</p>');
      const evidenceHtml=linkedNames.length?
        '<p>'+esc(fa?'شواهد ارجاع‌شده مرتبط با حوزهٔ این Agent:':'Relevant evidence available to this specialist:')+
        '</p><div class="ic-agent-chips">'+linkedNames.map(x=>'<span>'+esc(x)+'</span>').join('')+'</div>':
        '<p class="ic-agent-empty">'+esc(fa?
          'شاهد اختصاصی قابل انتساب به این حوزه در شناسه‌های گزارش‌شده مشخص نیست.':
          'No domain-specific evidence can be identified from cited references.')+'</p>';
      const recordedTools=arr(a.tools).length?'<p>'+esc(fa?'ابزارهای اعلام‌شده در خروجی Agent:':'Tools explicitly listed by the agent:')+
        ' '+arr(a.tools).map(x=>txt(humanTool(x))).join('، ')+'</p>':'';
      const metric='<div class="ic-agent-scores"><div><span>'+esc(fa?'اطمینان به نتیجهٔ این Agent':'Agent confidence')+'</span><strong>'+
        esc(numberPct(a.confidence))+'</strong></div><div><span>'+esc(fa?'پوشش شواهد':'Evidence coverage')+
        '</span><strong>'+esc(numberPct(coverage))+'</strong></div></div>';
      const candidates=hypotheses.length?agentDetail(fa?'فرضیه‌های این ایجنت؛ هنوز اثبات‌نشده':'Unverified hypotheses',
        '<ol class="ic-agent-bullets">'+hypotheses.map(h=>'<li><strong>'+esc(numberPct(h.probability))+'</strong> '+
          agentLine(h.text)+(arr(h.falsification_checks).length?
          '<p>'+esc(fa?'روش رد یا تأیید فرضیه (پیشنهادی):':'Suggested falsification checks:')+' '+
          arr(h.falsification_checks).slice(0,3).map(x=>txt(agentMissingFa(x))).join('، ')+'</p>':'')+'</li>').join('')+'</ol>',hypotheses.length):'';
      const proposed=recommendations.length?agentDetail(
        fa?'توصیه‌های این Agent؛ به‌معنی مجوز اجرا نیست':'Specialist recommendations (not authorized)',
        agentBullets(recommendations,x=>agentLine(x),6),recommendations.length):'';
      const pending=missingEvidence.length?agentDetail(fa?'اطلاعات موردنیاز برای قطعیت بیشتر':'Missing evidence',
        agentBullets(missingEvidence,x=>'<span>'+esc(agentMissingFa(x))+'</span>',10),missingEvidence.length):'';
      const nextChecks=advice.length?agentDetail(fa?'بررسی‌های پیشنهادی؛ اجرای آنها تأیید نشده':'Suggested checks (not executed)',
        agentBullets(advice,x=>'<span>'+esc(agentMissingFa(x))+'</span>',8),advice.length):'';
      const originalReport=(a.finding?original(a.finding,fa?'متن اصلی نتیجهٔ Agent':'Original agent result'):'')+
        (linked.length?refs(linked):'')+
        (arr(a.conflicting_evidence_refs).length?
          '<p class="ic-agent-conflict">'+esc(fa?'شواهد متعارض گزارش شده‌اند:':'Conflicting evidence reported:')+'</p>'+
          refs(a.conflicting_evidence_refs):'');
      return '<article class="ic-agent-card" data-agent="'+esc(agent)+'"><header class="ic-agent-head">'+
        '<div class="ic-agent-name"><span class="ic-agent-index">'+num(i+1)+'</span><div><h3>'+txt(humanAgent(a.agent))+
        ' <span class="ic-agent-en-name" dir="ltr">('+txt(agentNameEN(a.agent))+')</span></h3>'+
        '<p>'+esc(fa?scope[0]:a.agent)+'</p></div></div>'+
        '<div class="ic-agent-status">'+pill(a.status)+'</div></header>'+
        '<div class="ic-agent-mission"><b>'+esc(fa?'حوزهٔ مسئولیت:':'Responsibility:')+'</b> '+
        esc(fa?scope[1]:(a.mission||'Specialist scope; no additional mission description recorded'))+
        (a.analysis_at?' · '+esc(fa?'زمان ثبت تحلیل:':'Analysis recorded:')+' '+txt(date(a.analysis_at)):'')+'</div>'+
        metric+
        '<div class="ic-agent-subsection"><h4>'+esc(fa?'یافته‌ها و نتیجهٔ ثبت‌شده':'Recorded findings and outcome')+'</h4>'+summary+'</div>'+
        '<div class="ic-agent-subsection"><h4>'+esc(fa?'شواهدی که در تحلیل به آنها ارجاع شده':'Evidence referenced in the analysis')+'</h4>'+
        evidenceHtml+recordedTools+
        '<p class="ic-agent-disclaimer">'+esc(fa?
          'نمایش شواهد به معنی اجرای مستقیم SSH یا MCP توسط این Agent نیست؛ تعداد شناسه‌ها نیز تعداد شواهد تأییدشده نیست.':
          'Referenced evidence does not prove direct tool execution; IDs do not count as verified facts.')+'</p></div>'+
        (a.uncertainty_reason?'<p class="ic-agent-uncertainty"><b>'+
          esc(fa?'دلیل عدم قطعیت:':'Uncertainty:')+'</b> '+txt(agentMissingFa(a.uncertainty_reason))+'</p>':'')+
        (a.requires_human_review?'<p class="ic-agent-review">'+esc(fa?
          'این ایجنت بررسی انسانی را لازم دانسته است.':'Human review required by this specialist.')+'</p>':'')+
        candidates+pending+nextChecks+proposed+
        agentDetail(fa?'متن اصلی و شناسه‌های قابل ممیزی':'Original details and references',
          originalReport||empty(fa?'اطلاعات فنی بیشتری ثبت نشده است.':'No further details recorded'))+
        '</article>';
    });
    show('#ic-agents',cards.length?cards.join(''):empty(fa?'هنوز خروجی ایجنتی ثبت نشده است.':'No specialist result recorded.'));
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
        txt(state.language==='fa' ? (/Verified Incident Experience/.test(x.excerpt||'') ? 'تجربه حل مشکل مشابه' : 'دانش مرتبط بازیابی‌شده از کاگنیا') : (x.title||x.source_id))+'</h4>'+pill(x.use_status)+'</div>'+
        '<p>'+txt(previousExperience(x,"cognia"))+'</p>'+original(truncate(x.excerpt,1600),"متن اصلی دانش کاگنیا")+'<div class="ic-meta">پایگاه دانش: '+txt(x.knowledge_base_id)+
        ' · ID: '+txt(x.knowledge_id)+' · '+tr('confidence')+': '+esc(numberPct(x.relevance))+'</div>'+
        refs(x.source_id?[x.source_id]:[])+'</article>').join(''):empty()));
    show('#ic-memory','<div class="ic-callout"><strong>'+tr('knowledgeNotProof')+'</strong></div>'+
      (arr(m.items).length?arr(m.items).map(x=>'<article class="ic-detail-card"><div class="ic-detail-head"><h4>'+
        txt(state.language==='fa'?'تجربه رخداد قبلی':x.memory_id)+'</h4>'+pill(x.use_status)+'</div><p>'+txt(previousExperience(x,"memory"))+'</p>'+original(truncate(x.root_cause,1000))+
        '<div class="ic-meta">'+tr('action')+': '+txt(humanAction(x.action))+' · '+tr('verification')+': '+txt(status(x.verification))+
        ' · '+tr('result')+': '+txt(status(x.outcome))+' · '+tr('confidence')+': '+esc(numberPct(x.similarity))+'</div>'+
        refs(x.previous_incident_id?[x.previous_incident_id]:[])+'</article>').join(''):empty()));
  }
  function renderOutcome(r) {
    const o=r.execution_outcome||{},v=r.verification_result||{},learn=r.knowledge_learning_status||{},a=r.approval_readiness||{};
    const performed=o.status && !['not_executed','not_recorded','unknown'].includes(low(o.status));
    const consumed=low(a.approval_status)==='consumed';
    const running=consumed && state.lifecycle?.analysis_in_progress===true;
    const first=performed?'<div class="ic-outcome-heading"><strong>'+tr('execute')+'</strong>'+pill(o.status)+'</div>':
      running?'<div class="ic-analysis-progress" role="status"><span class="ic-analysis-spinner" aria-hidden="true"></span><div><strong>'+
        (state.language==='fa'?'عملیات تأییدشده در حال اجرا یا راستی‌آزمایی است…':'Approved execution or verification in progress…')+
        '</strong><small>'+(state.language==='fa'?'در انتظار ثبت نتیجهٔ نهایی؛ از اجرای مجدد خودداری کنید.':'Awaiting a final durable result; do not retry the action.')+'</small></div></div>':
      consumed?'<p class="ic-empty">'+
        (state.language==='fa'?'مجوز قبلاً مصرف شده ولی نتیجهٔ اجرای نهایی در این گزارش موجود نیست؛ Audit و وضعیت Workflow را بررسی کنید.':'Approval has been consumed but no final outcome is recorded; check audit and workflow status.')+
        '</p>':
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
  function receivedPairs(data, label) {
    const pairs = Array.isArray(data)
      ? data.filter(x=>x&&typeof x==='object').map(x=>[x.tag||x.key||'',x.value??''])
      : data && typeof data==='object' ? Object.entries(data) : [];
    if(!pairs.length)return '';
    return '<div class="ic-received-fields"><strong>'+esc(label)+'</strong><dl>'+
      pairs.map(([key,val])=>'<div><dt dir="auto">'+txt(key)+'</dt><dd dir="auto">'+
      txt(typeof val==='object'?JSON.stringify(val):val)+'</dd></div>').join('')+'</dl></div>';
  }
  function renderReceivedSignals() {
    const target=$('#ic-received-signals');
    if(!target)return;
    target.setAttribute('aria-busy',String(state.receivedSignalsStatus==='loading'));
    if(state.receivedSignalsStatus==='loading'){
      show('#ic-received-signals',empty(tr('receivedLoading')));return;
    }
    if(state.receivedSignalsStatus==='failed'){
      show('#ic-received-signals',empty(tr('receivedError')));return;
    }
    const records=arr(state.receivedSignals?.items);
    if(!records.length){show('#ic-received-signals',empty(tr('receivedEmpty')));return;}
    const content=records.map((item,index)=>{
      const payload=item.payload && typeof item.payload==='object' ? item.payload:{};
      const full=JSON.stringify(payload,null,2);
      const name=item.source_name || item.source || tr('unknown');
      const capture=item.capture_kind==='received_redacted'?tr('receivedOriginal'):tr('receivedNormalized');
      const lifecycle=item.lifecycle==='recovery'?tr('receivedRecovery'):tr('receivedProblem');
      const tags=item.source==='zabbix'?receivedPairs(payload.tags,tr('receivedTags')):'';
      const labels=item.source==='prometheus'?receivedPairs(payload.labels,tr('receivedLabels')):'';
      const annotations=item.source==='prometheus'?receivedPairs(payload.annotations,tr('receivedAnnotations')):'';
      const ruleTags=item.source==='elasticsearch'?
        receivedPairs(payload.rule?.tags?.map(tag=>({tag,value:''})),state.language==='fa'?'تگ‌های قانون ELK':'ELK rule tags'):'';
      return '<article class="ic-received-card"><div class="ic-received-heading"><h3>'+txt(name)+'</h3>'+
        '<span class="ic-tag">'+esc(lifecycle)+'</span></div>'+
        '<p class="ic-received-capture">'+esc(capture)+'</p>'+
        '<div class="ic-received-details"><div><small>'+tr('receivedWhen')+'</small><b>'+txt(date(item.received_at))+'</b></div>'+
        '<div><small>'+tr('receivedEventTime')+'</small><b>'+txt(date(item.occurred_at))+'</b></div>'+
        '<div><small>'+tr('receivedIdentifier')+'</small><b dir="ltr">'+txt(item.source_id)+'</b></div></div>'+
        '<div class="ic-received-message"><strong>'+tr('receivedMessage')+'</strong>'+
        '<pre dir="auto">'+txt(item.message||tr('unknown'))+'</pre></div>'+
        tags+labels+annotations+ruleTags+
        '<details class="ic-received-raw"><summary>'+tr('receivedPayload')+'</summary>'+
        '<pre dir="ltr">'+esc(full)+'</pre></details>'+
        '<button type="button" class="ic-btn ic-btn-muted ic-received-copy" data-copy-received="'+index+'">'+
        tr('receivedCopy')+'</button></article>';
    }).join('');
    show('#ic-received-signals',
      '<p class="ic-received-total">'+tr('receivedCount')+': '+num(records.length)+'</p>'+content+
      (state.receivedSignals?.has_more?'<p class="ic-warning">'+tr('receivedMore')+'</p>':''));
  }
  async function loadReceivedSignals(token) {
    state.receivedSignalsStatus='loading';renderReceivedSignals();
    try{
      const result=await api(base+'/received-signals?limit=100');
      if(token!==state.loadingToken)return;
      state.receivedSignals=result;state.receivedSignalsStatus='loaded';
    }catch(_){
      if(token!==state.loadingToken)return;
      state.receivedSignals=null;state.receivedSignalsStatus='failed';
    }
    renderReceivedSignals();
  }

  function renderDecision(r) {
    const a=r.approval_readiness||{},x=r.remediation_recommendation||{},statusValue=low(a.approval_status);
    const archived=!!state.historic;
    const pending=statusValue==='pending', approved=statusValue==='approved';
    // A consumed approval is intentionally one-time. Snapshot changes from
    // actual execution/verification must never be shown as a NEW approval drift.
    const snapshotBad=(pending||approved)&&
      (a.evidence_snapshot_binding==='drift_detected'||a.status==='new_approval_required');
    const binding=Boolean(a.binding_complete)&&!snapshotBad;
    const executed=low(r.execution_outcome?.status)==='success';
    const verified=['success','verified','succeeded'].includes(low(r.verification_result?.status));
    const executing=statusValue==='consumed' && state.lifecycle?.analysis_in_progress===true;
    let heading=pending?tr('approvalPending'):approved?tr('approvalApproved'):
      executing?(state.language==='fa'?'در حال اجرای عملیات تأییدشده':'Approved execution in progress'):
      statusValue==='consumed' && executed && verified
        ?(state.language==='fa'?'بازیابی سرویس تأیید شد':'Service recovery verified'):
      statusValue==='consumed'
        ?(state.language==='fa'?'مجوز مصرف شده؛ نتیجهٔ عملیات را بررسی کنید':'Approval consumed; review execution outcome'):
      tr('approvalFinished');
    if(archived)heading=tr('historical');
    const detail=archived?tr('archiveHint'):statusValue==='consumed'
      ?(state.language==='fa'?'این مجوز یک‌بار مصرف شده و اجرای مجدد فقط با مجوز جدید ممکن است.':'This approval has already been consumed and cannot authorize a second execution.')
      :pending?tr('approvalSeparate'):tr('execBound');
    show('#ic-action-state','<div class="ic-decision-status"><strong>'+esc(heading)+'</strong><p>'+
      esc(detail)+'</p>'+
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
    renderKnowledge(r);renderOutcome(r);renderTimeline(r);renderDecision(r);renderReceivedSignals();
    renderAnalysisProgress();
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
      state.lastLiveCheck=Date.now();state.lifecyclePollError=false;
      if(prev!==report.snapshot_id||prevApproval!==lifecycle?.approval?.approval_id)state.reviewedSnapshot=null;
      if(!preserveHistory)state.historic=null;
      state.narrative=null;state.error=null;state.rejectionVisible=false;
      $('#ic-auth').hidden=true;$('#ic-loader').hidden=true;$('#ic-main').hidden=false;alert('');
      render();void loadNarrative();void loadReceivedSignals(token);
      void connectProgressStream();
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
    document.addEventListener('click',e=>{
      const button=e.target.closest('[data-copy-received]');
      if(!button)return;
      const index=Number(button.getAttribute('data-copy-received'));
      const item=arr(state.receivedSignals?.items)[index];
      if(!item)return;
      void navigator.clipboard.writeText(JSON.stringify(item.payload,null,2))
        .then(()=>notify(tr('copied'))).catch(()=>notify(tr('failure'),true));
    });
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
    document.addEventListener('visibilitychange',()=>{
      if(document.hidden){
        state.progressAbort?.abort();
        clearTimeout(progressRetryTimer);
      }else{
        void connectProgressStream();
        if(!state.progressConnected)void pollLifecycle();
      }
    });
    const lifecycleTimer=setInterval(()=>{void pollLifecycle();},6000);
    const durationTimer=setInterval(updateProgressClock,1000);
    if(typeof durationTimer?.unref==='function')durationTimer.unref();
    // Node-based browser regression harnesses should not be kept alive by polling.
    if(typeof lifecycleTimer?.unref==='function')lifecycleTimer.unref();
    setLang(state.language);
    void load();
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bind,{once:true});
  else bind();
})();
