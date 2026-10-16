/* Full-screen, evidence-first Incident Command Room. Operational writes use only existing governed APIs. */
(() => {
  'use strict';
  const match = location.pathname.match(/^\/dashboard\/incidents\/([0-9a-fA-F-]{36})\/?$/);
  const incidentId = match && match[1];
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  const $ = q => document.querySelector(q);
  const safe = x => String(x == null || x === '' ? '—' : x);
  const esc = x => safe(x).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'}[c]));
  const guardReasonFA = code => ({
    config_guard_sudo_nopasswd_required:'اجرای sudo بدون رمز ممکن نبود و احراز هویت با رمز کاربر SSH نیز تکمیل نشد. برای اجرای ویرایش موقتِ بدون Helper، مجوز sudo /bin/sh -s و احراز هویت همان کاربر باید بررسی شود.',
    config_guard_sudo_policy_denied:'سیاست sudoers اجرای اسکریپت موقت /bin/sh -s را برای کاربر SSH مجاز نمی‌داند. AIOps مجوزها را خودکار تغییر نمی‌دهد.',
    config_guard_sudo_or_invocation_failed:'اجرای اسکریپت موقت با sudo روی VM شکست خورد؛ علت دقیق از کد خروج به‌تنهایی مشخص نیست. مجوز sudo /bin/sh و لاگ مرحله اجرای SSH بررسی شود.',
    config_guard_helper_missing:'ابزار محافظ اصلاح کانفیگ روی VM در مسیر /usr/local/sbin/aiops-config-guard نصب نشده است. با کاربر SSH فعلی و دسترسی sudo، ابزار نسخه‌بندی‌شده پروژه باید به‌صورت جداگانه نصب و مالکیت root:root و مجوز 0750 آن راستی‌آزمایی شود؛ سپس اعتبارسنجی را تکرار کنید.',
    config_guard_helper_symlink_refused:'فایل Helper لینک نمادین است و برای جلوگیری از تغییر مسیر اجرای root رد شد. نسخه مورد اعتماد پروژه باید به‌صورت فایل معمولی نصب شود.',
    config_guard_helper_not_regular:'مسیر Helper فایل اجرایی معمولی نیست. پیش از اجرای sudo باید نوع فایل و فرایند استقرار اصلاح شود.',
    config_guard_helper_parent_missing:'پوشه /usr/local/sbin روی VM وجود ندارد یا در دسترس بررسی اولیه نیست؛ استقرار Helper باید توسط مدیر مجاز بررسی شود.',
    config_guard_helper_parent_inaccessible:'کاربر SSH اجازه عبور از یکی از پوشه‌های /usr ،/usr/local یا /usr/local/sbin را ندارد؛ نبودن فایل Helper هنوز اثبات نشده است.',
    config_guard_helper_unsafe_metadata:'مالکیت یا مجوز فایل Helper قابل قبول نیست. باید root:root و دقیقاً مجوز 0750 داشته باشد.',
    config_guard_preflight_unavailable:'بررسی مقدماتی وجود و مالکیت Helper با SSH انجام نشد؛ تا روشن شدن علت، اعتبارسنجی و اعمال کانفیگ مجاز نیست.',
    config_guard_helper_permission_denied:'دسترسی لازم برای اجرای Helper یا فایل هدف وجود ندارد.',
    config_guard_mount_namespace_unavailable:'ساخت فضای ایزوله Mount Namespace در این VM مجاز یا پشتیبانی‌شده نیست. اعتبارسنجی بدون ایزوله‌سازی مجاز نیست.',
    config_guard_isolated_mount_failed:'اتصال درخت کانفیگ در فضای ایزوله شکست خورد؛ مجوز mount یا تنظیمات Kernel بررسی شود.',
    config_guard_prerequisite_failed:'یکی از پیش‌نیازهای اسکریپت موقت، مسیر فایل یا ابزار مستقل اعتبارسنجی سرویس در VM در دسترس نیست.',
    config_guard_candidate_hash_mismatch:'هش نسخه پیشنهادی با درخواست تأیید مطابقت ندارد؛ تغییر باید دوباره بررسی شود.',
    config_guard_candidate_not_minimal:'Candidate ذخیره‌شده نسبت به فایل اصلی تغییرات غیرضروری یا گسترده دارد. اصلاح فقط باید ایراد نحوی نزدیک خط Validator را برطرف کند؛ یک پیشنهاد جدید با LLM تولید کنید.',
    config_guard_source_hash_changed:'فایل زنده از زمان پیشنهاد تغییر کرده؛ پیشنهاد و هش‌ها باید دوباره تولید شوند.',
    config_guard_vendor_syntax_failed:'Validator واقعی سرویس، نسخه اصلاحی را تأیید نکرده است؛ این تغییر نباید اعمال شود.',
    config_guard_staging_failed:'آماده‌سازی نسخه ایزوله کانفیگ ناموفق بود.',
    config_guard_ssh_timeout:'اتصال SSH یا عملیات Validator زمان‌بر و ناموفق بوده است.',
    config_guard_ssh_connection_failed:'ارتباط SSH با VM برای اعتبارسنجی برقرار نشد.',
    config_guard_request_rejected:'Helper درخواست را به‌دلیل ناسازگاری قرارداد امن رد کرده است.',
    config_guard_execution_failed:'Helper نتوانست نتیجه اعتبارسنجی قابل‌اعتماد تولید کند.',
  })[code] || 'اعتبارسنجی مستقل مسدود شده است؛ کد خطا را برای تشخیص بررسی کنید.';
  const arr = x => Array.isArray(x) ? x : [];
  const low = x => String(x || '').toLowerCase();
  const truncate = (x, limit = 340) => { const s = safe(x); return s.length > limit ? s.slice(0, limit) + '…' : s; };
  const vocabulary = {
    fa: {
      brandDetail:'فضای تصمیم‌گیری عملیاتی',dashboard:'داشبورد',incidents:'رخدادها',thisIncident:'این رخداد',
      refresh:'↻ تازه‌سازی',back:'بازگشت به رخدادها',loading:'در حال خواندن گزارش مستند از داده‌های ثبت‌شده رخداد…',
      heroKicker:'اتاق بررسی و تصمیم‌گیری',navOverview:'خلاصه تصمیم',navReceived:'آلارم دریافتی',navChat:'چت رخداد',navReview:'قبل از تأیید',
      navAnalysis:'تحلیل Agentها',navFix:'اصلاح کانفیگ',navEvidence:'شواهد و MCP',navKnowledge:'دانش و تجربه',navOutcome:'نتیجه اجرا',navHistory:'تاریخچه',
      receivedTitle:'آلارم دریافتی',receivedSubtitle:'آنچه واقعاً از سیستم مانیتورینگ دریافت شده',
      receivedNote:'متن و اطلاعات اصلی ثبت‌شده در زمان دریافت آلارم را می‌بینی. اطلاعات محرمانه پنهان شده‌اند. موارد قدیمی ممکن است قبل از ذخیره‌سازی نرمال شده باشند.',
      receivedLoading:'در حال دریافت آلارم ثبت‌شده…',receivedEmpty:'برای این رخداد، پیام اولیه‌ای از منابع ثبت‌شده پیدا نشد.',
      receivedOriginal:'ساختار پیام دریافتی، پس از پنهان‌سازی اطلاعات محرمانه',receivedNormalized:'نسخه ثبت‌شده و نرمال‌شده؛ بدنه دقیق اولیه در پایگاه داده موجود نیست',
      receivedWhen:'زمان دریافت',receivedEventTime:'زمان وقوع از دید منبع',receivedIdentifier:'شناسه در منبع',
      receivedMessage:'متن آلارم',receivedTags:'تگ‌های زبیکس',receivedLabels:'لیبل‌های Prometheus',
      receivedAnnotations:'توضیحات Alertmanager',receivedPayload:'نمایش تمام فیلدهای ثبت‌شده (JSON)',
      receivedCopy:'کپی اطلاعات آلارم',receivedCount:'تعداد سیگنال‌های ثبت‌شده',
      chatSubtitle:'گفت‌وگوی متصل به شواهد و مجوزهای همین رخداد',
      chatTitle:'دستیار تعاملی رخداد',
      chatNote:'بعد از تحلیل می‌توانی درباره خطا سؤال کنی، وضعیت زنده یا کانفیگ را بررسی کنی و برای عملیات درخواست تأیید ثبت کنی. هیچ دستور اجرایی صرفاً با پیام چت انجام نمی‌شود.',
      chatError:'علت خطا چیست؟',chatConfig:'کانفیگ را بررسی کن',chatStatus:'وضعیت سرویس را بررسی کن',
      chatReload:'ریلود سرویس را پیشنهاد بده',chatFiles:'بررسی فایل‌های Nginx',chatMessageLabel:'پیام شما برای این Incident',chatSend:'ارسال پیام',
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
      evidence:'شواهد ثبت‌شده',cause:'علت احتمالی',causeStatus:'میزان اطمینان به علت',why:'چرا این اقدام؟',
      criticalWarning:'پیش از تصمیم‌گیری به این هشدارها توجه کنید.',agents:'Agentهای اجراشده',
      mcp:'یافته‌های MCP',monitoring:'پایش زیرساخت',none:'اطلاعات قابل‌استنادی ثبت نشده است.',
      infoUnavailable:'اطلاعاتی برای این بخش ثبت نشده است؛ نتیجه‌گیری جدیدی ساخته نمی‌شود.',
      notUsed:'دانش مرتبط بازیابی شده است، اما هیچ Agent به آن استناد نکرده و اثر آن در تصمیم نهایی ثابت نشده است.',
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
      heroKicker:'Incident command room',navOverview:'Quick brief',navReceived:'Received alert',navChat:'Incident chat',navReview:'Before approval',navAnalysis:'Agent analysis',
      navFix:'Config correction',navEvidence:'Evidence & MCP',navKnowledge:'Knowledge & memory',navOutcome:'Execution result',navHistory:'History',
      receivedTitle:'Received alert',receivedSubtitle:'The notification actually sent by monitoring',
      receivedNote:'Original stored notification data with secrets removed. Older notifications may have been normalized before storage.',
      receivedLoading:'Loading recorded source notification…',receivedEmpty:'No stored ingress notification found for this Incident.',
      receivedOriginal:'Original received JSON structure (with credentials redacted)',
      receivedNormalized:'Normalized stored record; the precise original HTTP body is not retained',
      receivedWhen:'Received at',receivedEventTime:'Source event time',receivedIdentifier:'Source ID',
      receivedMessage:'Alert message',receivedTags:'Zabbix tags',receivedLabels:'Prometheus labels',
      receivedAnnotations:'Alertmanager annotations',receivedPayload:'All recorded fields (JSON)',
      receivedCopy:'Copy alert payload',receivedCount:'Stored signals',
      chatSubtitle:'Conversation grounded in this incident and its approvals',
      chatTitle:'Incident investigation copilot',
      chatNote:'Ask about root causes, request live read-only checks and initiate governed action approval. Chat messages never directly execute changes.',
      chatError:'What caused this error?',chatConfig:'Check configuration',chatStatus:'Check service status',
      chatReload:'Propose service reload',chatFiles:'Inspect Nginx files',chatMessageLabel:'Your message about this incident',chatSend:'Send message',receivedMore:'Results limited; query the API for more.',
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
      risk:'Risk',action:'Proposed action',tool:'Execution tool',freshness:'Evidence freshness',evidence:'Recorded evidence',
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
    configResponse: null, configResponseStatus: 'loading',
    chat: null, chatStatus: 'loading', chatBusy: false, chatLastResult: null,
    configPreviewPending: false, configPreviewLastResult: null,
    serviceStatus: null, serviceStatusLoading: false, serviceStatusBusy: false,
    serviceStatusToken: 0,
    serviceProfile: null, httpHealth: null, httpHealthBusy: false, profileBusy: false,
    liveDotnetSyntax: null, liveDotnetSyntaxStatus: 'not_checked',
    recoveryApproval: null, recoveryQueueAttempted: false,
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
    not_requested:'درخواست نشده',pending_validation:'در صف Approval، منتظر اعتبارسنجی فنی',not_executed:'اجرا نشده',not_recorded:'ثبت نشده',
    partial:'ناقص',inconclusive:'نامطمئن',queried:'پرس‌وجو انجام شده',not_queried:'جمع‌آوری نشده',
    investigated:'بررسی شده',queried_with_results:'استعلام شد؛ دارای نتیجه',
    queried_zero_results:'استعلام شد؛ بدون نتیجه',query_failed:'استعلام ناموفق',
    not_applicable:'قابل اعمال نیست',
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
    if(/active_state\s*=\s*active(?:[;, ]|$)/i.test(x)&&/sub_state\s*=\s*running/i.test(x)) facts.push('سرویس طبق systemd در زمان ثبت شواهد در حال اجراست');
    if(/active_state\s*=\s*(?:inactive|failed)|service (?:is |was )?(?:inactive|stopped)|inactive \(dead\)/i.test(x)) facts.push('سرویس طبق systemd در زمان ثبت شواهد متوقف بوده است');
    if(/running\s*=\s*false|process(?:es)? (?:are |is )?not running|process count (?:is )?0/i.test(x)) facts.push('پردازش سرویس اجرا نمی‌شود');
    if(/listening\s*=\s*false|not listening locally|port \d+ is not listening/i.test(x)) facts.push('پورت مورد انتظار باز نیست');
    if(/reachable\s*=\s*false|TCP connectivity check .*fails|TCP port .*unreachable/i.test(x)) facts.push('ارتباط با پورت برقرار نمی‌شود');
    if(!/invalid[_ ]json|invalid[_ ]syntax|syntax (?:error|failed|invalid)|valid\s*=\s*false|failed (?:config|json)|syntax check (?:failed|invalid)/i.test(x) &&
       /valid\s*=\s*true|syntax (?:is )?(?:valid|OK)|configuration validation passed/i.test(x))
      facts.push('در متن این شاهد، موفقیت تست ساختاری گزارش شده؛ نتیجه باید با Validator اختصاصی مقایسه شود');
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
    const explanation=r.operator_explanation||{};
    const config=r.configuration_diagnostic||{};
    const situation=r.state_correlation?.conclusion_kind==='source_discrepancy'?
      safe(r.state_correlation.conclusion_fa||r.state_correlation.headline_fa):
      low(config.status)==='invalid'?
      'بررسی معتبر کانفیگ خطای سینتکس را در '+safe(config.config_file||'فایل تنظیمات')+
      (Number.isInteger(config.error_line)?'، خط '+num(config.error_line):'')+
      ' ثبت کرده است. تا اصلاح و تست مجدد، Start پیشنهاد نمی‌شود.':
      explanation.headline_fa?
      explanation.headline_fa:
      facts.length?'بررسی ابزارها نشان می‌دهد: '+facts.join('؛ ')+'.' :
      'هنوز اطلاعات کافی برای توضیح دقیق وضعیت سرویس نداریم.';
    const stored=String(r.localized_narrative?.fa || '').trim();
    const storedNote=isFaText(stored) && stored.length <= 280 &&
      !/^رخداد سرویس|^شواهد ثبت شده|^برای این رخداد/.test(stored) ? stored+' ' : '';
    const next=low(config.status)==='invalid'?
      'Start سرویس با کانفیگ نامعتبر نباید اجرا شود؛ ابتدا اصلاح و تست دوباره لازم است.':
      x.action?'پیشنهاد سیستم '+humanAction(x.action)+' است.':'هنوز کاری برای اجرا پیشنهاد نشده است.';
    return 'برای '+subject+where+' رخداد ثبت شده. '+(low(config.status)==='invalid'?'':storedNote)+
      situation+' '+next+
      (low(config.status)==='invalid'?
        ' این خطا واقعی است؛ اما ارتباط قطعی آن با Timeout هنوز با لاگ شروع برنامه تأیید نشده است.':
        ' دلیل اصلی مشکل هنوز به‌طور قطعی روشن نشده است؛ تأیید و اجرای اقدام دو مرحله جدا هستند.');
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
      let detail='',code='',responseDetail=null;
      try {
        const body=await response.json();
        responseDetail=body?.detail&&typeof body.detail==='object'?body.detail:null;
        code=body?.detail?.code||body?.error?.code||'';
        detail=typeof body.detail==='string'?body.detail:JSON.stringify(body.detail||'');
      }catch(_){}
      const message=code==='DATABASE_MIGRATION_DRIFT'?
        (state.language==='fa'?
          'نسخه دیتابیس قدیمی است و عملیات به‌صورت ایمن متوقف شده. مدیر سیستم باید پس از بکاپ، Alembic migration را اجرا کند.':
          'Database schema is behind the application. Operations are safely blocked; a DBA must back up and apply Alembic migrations.') :
        response.status+' '+(detail||response.statusText);
      const e=new Error(message);e.status=response.status;e.code=code;
      e.detail=responseDetail;
      throw e;
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
    investigation:'تحقیق پویای مبتنی بر شواهد و استعلام تکمیلی دانش',
    evaluator:'ارزیابی شواهد و کیفیت نتیجه',
    decision:'تهیه پیشنهاد و تصمیم AIOps',
    approval:'در انتظار تصمیم اپراتور',
    pre_execution_check:'بررسی ایمنی و شواهد تازه پیش از اجرا',
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
    investigation:'Dynamic evidence investigation and focused knowledge search',
    evaluator:'Evaluating evidence and decision quality',
    decision:'Preparing the operational decision',
    approval:'Waiting for operator approval',
    pre_execution_check:'Fresh evidence and safety checks before execution',
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
    ? humanAgent(key.slice(6))+' ('+agentNameEN(key.slice(6))+')'
    : (state.language==='fa'?progressStageFa:progressStageEn)[key] || String(key||'');
  function updateProgressClock() {
    const element=$('#ic-flow-elapsed');
    if(!element || !state.progress?.started_at || state.historic)return;
    const p=state.progress,execution=p.approval_status==='consumed' && p.stages?.execution?.started_at;
    const start=execution?p.stages.execution.started_at:p.started_at;
    const finish=execution?(
      ['completed','failed'].includes(low(p.checkpoint_status))?p.stages?.end?.at||p.last_event_at:null
    ):['pending','approved'].includes(low(p.approval_status))?
      p.stages?.approval?.finished_at||p.stages?.approval?.at:
      ['completed','failed'].includes(low(p.checkpoint_status))?p.stages?.end?.at||p.last_event_at:
      p.failed_stage?p.stages?.[p.failed_stage]?.finished_at:null;
    const seconds=Math.max(0,Math.floor(((finish?new Date(finish).getTime():Date.now())-
      new Date(start).getTime())/1000));
    if(Number.isFinite(seconds))element.textContent=num(Math.floor(seconds/60))+
      (state.language==='fa'?' دقیقه ':'m ')+num(seconds%60)+(state.language==='fa'?' ثانیه':'s');
  }
  function renderAnalysisProgress() {
    const box=$('#ic-analysis-progress');
    if(!box)return;
    const l=state.lifecycle||{},r=state.report||{},p=state.progress||{};
    const approval=low(l.approval?.status||p.approval_status||r.approval_readiness?.approval_status);
    const statusValue=low(l.incident_status||p.incident_status||r.incident_summary?.status);
    const precheckStatus=p.stages?.pre_execution_check?.status;
    const precheckActive=precheckStatus==='started';
    const precheckFailed=precheckStatus==='failed';
    const running=precheckActive||l.analysis_in_progress===true ||
      (l.analysis_in_progress==null && statusValue==='analyzing' &&
       !['pending','approved','rejected'].includes(approval) &&
       !['paused','completed','failed'].includes(low(l.checkpoint_status)));
    const awaiting=!precheckActive&&!precheckFailed&&['pending','approved'].includes(approval);
    const terminal=['completed','failed'].includes(low(p.checkpoint_status));
    const expectedStages=Number(p.analysis_total)||6;
    const completedStages=Number(p.analysis_completed)||0;
    const missingProgressMilestones=terminal&&
      Number(p.analysis_percent)<100&&completedStages<expectedStages;
    const crashed=Boolean((precheckFailed||p.failed_stage&&!p.current_stage)&&!awaiting&&!terminal);
    const hasEvents=Boolean(p.last_event_at);
    if(state.historic || (!running && !awaiting && !hasEvents)){box.hidden=true;return;}
    box.hidden=false;
    const fa=state.language==='fa';
    const execution=(approval==='approved'||approval==='consumed') &&
      (p.current_stage==='pre_execution_check'||p.current_stage==='execution'||
       p.current_stage==='verification'||p.current_stage==='memory' ||
       (l.analysis_phase==='executing'&&!terminal));
    const currentStage=awaiting?'approval':
      (execution&&!['pre_execution_check','execution','verification','memory'].includes(p.current_stage))?
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
    if(spinner)spinner.hidden=awaiting||terminal||crashed||!running&&!(execution&&currentStage);
    const title=$('#ic-analysis-title'),detail=$('#ic-analysis-detail');
    if(title)title.textContent=crashed?
      (fa?'تحلیل با خطا در مرحلهٔ ':'Analysis failed during ')+phaseName(p.failed_stage):
      (activeAgent&&currentStage==='parallel_agents'&&activeLabel
      ?(fa?'در حال تحلیل: ':'Analyzing: ')+activeLabel
      :activeLabel)||
      (missingProgressMilestones?
        (fa?'پردازش پایان یافته؛ ثبت بعضی مراحل ناقص است':
          'Workflow ended; some milestones were not recorded'):
        terminal?(fa?'بررسی رخداد تکمیل شده است':'Incident analysis finished'):
        fa?'در حال دریافت وضعیت تحلیل…':'Loading analysis progress…');
    if(detail)detail.textContent=crashed?
      (fa?'این مرحله ناموفق بوده و ادامهٔ بررسی باید از گزارش خطا پیگیری شود.':'This step failed; check the error report.'):
      awaiting?
      (fa?'تحلیل متوقف است؛ منتظر تصمیم انسانی':'Analysis is paused for human approval'):
      missingProgressMilestones?
      (fa?'طبق Checkpoint پردازش پایان یافته، اما فقط '+completedStages+' مرحله از '+expectedStages+
        ' مرحلهٔ تحلیل به‌صورت موفق در ممیزی ثبت شده است؛ درصد را به ۱۰۰ تغییر نمی‌دهیم.':
        'The checkpoint is terminal, but only '+completedStages+' of '+expectedStages+
        ' analysis milestones were durably recorded; percent is not fabricated.'):
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
      'این درصد فقط از مراحل واقعاً تکمیل‌شده است و تخمین زمان باقی‌مانده نیست.':
      'Percentage is based on verified stage completion, not time remaining.';
    const timeline=[...Object.entries(p.stages||{}),...Object.entries(p.providers||{}),
      ...Object.entries(p.agents||{}).map(([key,v])=>['agent:'+key,v])]
      .filter(([_,v])=>v&&v.at)
      .sort((x,y)=>String(x[1].at).localeCompare(String(y[1].at))).slice(-8);
    show('#ic-flow-steps',timeline.map(([key,v])=>{
      const status=low(v.status),icon=status==='completed'?'✓':status==='failed'?'!':
        status==='skipped'?'–':'';
      const suffix=status==='completed'?(fa?' · بررسی انجام شد':' · checked'):
        status==='failed'?(fa?' · ناموفق':' · failed'):
        status==='skipped'?(fa?' · انجام نشده':' · skipped'):'';
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
    const checkpointChanged=Number.isInteger(snapshot.checkpoint_version) &&
      Number.isInteger(state.lifecycle?.checkpoint_version) &&
      snapshot.checkpoint_version!==state.lifecycle.checkpoint_version;
    if((statusChanged||checkpointChanged) && !state.busy && state.report && !state.historic &&
       (checkpointChanged || snapshot.last_event_at!==prior.last_event_at||
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


  function renderServiceStatus() {
    const node=$('#ic-service-status');
    if(!node)return;
    const ram=Boolean((state.historic||state.report)?.memory_investigation);
    node.hidden=ram;
    if(ram)return;
    const fa=state.language==='fa',o=state.serviceStatus||{};
    const busy=state.serviceStatusBusy,loading=state.serviceStatusLoading;
    const status=low(o.status);
    const authenticated=o.verified_systemd_only===true &&
      ['running','active','stopped','transitioning','unstable'].includes(status);
    const validTime=o.observed_at&&!Number.isNaN(new Date(o.observed_at).getTime());
    const old=validTime&&(Date.now()-new Date(o.observed_at).getTime()>120000);
    const label=busy?(fa?'در حال بررسی زنده…':'Checking live status…'):
      authenticated?({
        running:fa?'سرویس در حال اجراست · Running':'Service is running · Running',
        active:fa?'سرویس فعال است · Active':'Service is active · Active',
        stopped:fa?'سرویس متوقف است · Down':'Service is stopped · Down',
        transitioning:fa?'وضعیت سرویس در حال تغییر است':'Service state is transitioning',
        unstable:fa?'سرویس ناپایدار · چرخه Crash/Restart':'Unstable · Crash/restart loop',
      }[status]):loading?(fa?'در حال خواندن وضعیت…':'Loading recorded status…'):
      (fa?'وضعیت فعلی نامشخص است':'Current status unknown');
    const tone=!authenticated||old||busy?'warn':
      ['stopped','unstable'].includes(status)?'danger':
      status==='running'||status==='active'?'ok':'warn';
    const source=o.source==='vm_mcp_chat'?(fa?'پاسخ زندهٔ ثبت‌شده در چت':'Recorded live chat VM MCP'):
      o.source==='vm_mcp_recheck'?(fa?'بررسی زندهٔ مجدد VM MCP':'Fresh VM MCP recheck'):
      o.source==='vm_mcp_post_config'?(fa?'راستی‌آزمایی پس از اصلاح و شروع سرویس':'Verified after config repair and service start'):
      o.source==='vm_mcp_recorded'?(fa?'شواهد ثبت‌شدهٔ VM MCP':'Recorded VM MCP evidence'):
      o.source==='vm_mcp_recheck_failed'?(fa?'بررسی زنده ناموفق':'Failed live check'):
      (fa?'مشاهدهٔ قابل‌تأیید وجود ندارد':'No verifiable observation');
    const alertDown=/systemd service down|service down|inactive|failed/i.test(
      String(state.report?.incident_summary?.summary||'')+' '+
      String(state.report?.incident_summary?.title||''));
    const incidentResolved=!state.historic&&
      ['resolved','closed'].includes(low(state.lifecycle?.incident_status));
    const conflict=authenticated&&status==='running'&&alertDown&&!incidentResolved;
    const reason=!authenticated&&o.reason?
      '<p class="ic-service-health-conflict">'+esc(fa?
        'بررسی زنده یا شناسایی مقصد تأیید نشد: ':'Live check or target binding failed: ')+
        txt(o.reason)+'</p>':'';
    const stateExplanation=authenticated?
      (status==='unstable'?
        (fa?'شواهد اخیر systemd چرخهٔ راه‌اندازی مجدد یا افزایش تعداد Restart را نشان می‌دهند. مشاهدهٔ لحظه‌ای Active به معنی پایداری یا سلامت API نیست.':
          'Recent systemd evidence shows auto-restart or increasing restarts. A momentary Active state is not proof of stability or API health.'):
        (fa?'این نتیجه فقط وضعیت systemd را در زمان ثبت ثابت می‌کند؛ سلامت Endpoint و پاسخ واقعی API هنوز جداگانه باید بررسی شود.':
          'This observation verifies only systemd at the recorded time; API readiness and endpoint health remain unverified.')):
      (fa?'تا دریافت پاسخ معتبر از VM MCP، وضعیت سرویس را Running یا Down فرض نمی‌کنیم.':
        'No Running/Down claim is made without valid VM MCP evidence.');
    node.dataset.state=authenticated?status:'unknown';
    show('#ic-service-status',
      '<div class="ic-service-health-top"><strong>'+esc(fa?
        'آخرین وضعیت تأییدشدهٔ سرویس':'Last verified service state')+'</strong>'+
      '<span class="ic-service-health-state" data-tone="'+tone+'">'+esc(label)+'</span></div>'+
      '<div class="ic-service-health-detail"><span>'+esc(fa?'سرویس: ':'Service: ')+
        txt(o.service||state.report?.incident_summary?.service)+'</span><span>'+esc(fa?'میزبان: ':'Host: ')+
        txt(o.target)+'</span><span>'+esc(fa?'منبع: ':'Source: ')+esc(source)+'</span>'+
      '<span>'+esc(fa?'زمان مشاهده: ':'Observed at: ')+
        txt(validTime?date(o.observed_at):null)+'</span>'+
      (Number.isInteger(o.restart_count)?'<span>'+esc(fa?'تعداد Restart: ':'Restarts: ')+num(o.restart_count)+'</span>':'')+
      (Number.isInteger(o.main_pid)?'<span>MainPID: '+num(o.main_pid)+'</span>':'')+
      '</div>'+
      (old?'<p class="ic-service-health-conflict">'+esc(fa?
        'این مشاهده قدیمی است؛ برای اطلاع از وضعیت فعلی «بررسی مجدد» را بزنید.':
        'This observation is stale. Use Recheck for the current state.')+'</p>':'')+
      (incidentResolved&&authenticated&&status==='running'?
        '<p class="ic-service-health-note">'+esc(fa?
          'رخداد رفع‌شده ثبت شده است؛ وضعیت Running از شواهد VM تأیید شده و مستقل از پیام Recovery سامانه مانیتورینگ است.':
          'Incident resolved from independent VM evidence; monitor recovery is tracked separately.')+'</p>':'')+
      (conflict?'<p class="ic-service-health-conflict">'+esc(fa?
        'آلارم اولیه وضعیت Down را گزارش کرده، اما شواهد جدیدتر systemd وضعیت Running را نشان می‌دهند.':
        'The initial alert reports Down, while later systemd evidence reports Running.')+'</p>':'')+
      reason+'<p class="ic-service-health-note">'+esc(stateExplanation)+'</p>'+
      '<div class="ic-service-health-action"><button type="button" id="ic-service-recheck" class="ic-btn ic-btn-primary"'+
      (busy||state.historic||state.lifecycle?.analysis_in_progress?' disabled':'')+'>'+
      esc(busy?(fa?'در حال بررسی…':'Checking…'):(fa?'↻ بررسی مجدد وضعیت سرویس':'↻ Recheck service status'))+
      '</button><small class="ic-service-health-note">'+esc(fa?
        'این دکمه فقط استعلام Read-only انجام می‌دهد؛ هیچ Start یا Restart اجرا نمی‌کند.':
        'Read-only VM check; never starts or restarts a service.')+'</small></div>');
  }
  async function loadServiceStatus() {
    const token=++state.serviceStatusToken;
    state.serviceStatusLoading=true;renderServiceStatus();
    try {
      const result=await api(base+'/service-status');
      if(token!==state.serviceStatusToken)return;
      state.serviceStatus=result;
    }catch(e){
      if(token!==state.serviceStatusToken)return;
      state.serviceStatus={status:'unknown',source:'unavailable',
        reason:e.status===409?'incident_analysis_not_finished':e.message,
        verified_systemd_only:false};
    }finally{
      if(token===state.serviceStatusToken){
        state.serviceStatusLoading=false;renderServiceStatus();
      }
    }
  }
  async function recheckServiceStatus() {
    if(state.serviceStatusBusy||state.historic||state.lifecycle?.analysis_in_progress)return;
    const token=++state.serviceStatusToken;
    state.serviceStatusBusy=true;renderServiceStatus();
    try {
      const result=await api(base+'/service-status/recheck',{method:'POST'});
      if(token!==state.serviceStatusToken)return;
      state.serviceStatus=result;
      if(result.incident_status==='resolved' &&
         result.recovery_verification==='independent_vm_verified'){
        notify(state.language==='fa'?
          'بازیابی سرویس با دو بررسی زندهٔ VM تأیید و رخداد رفع شد. بازیابی Zabbix جداگانه ثبت می‌شود.':
          'Two live VM checks verified recovery and resolved the incident. Zabbix recovery remains separately tracked.');
        state.serviceStatusBusy=false;
        state.serviceStatusLoading=false;
        await load();
        return;
      }
      if(result.status==='running'&&result.recovery_verification&&
         result.recovery_verification!=='independent_vm_verified'){
        const restricted=result.recovery_verification==='recovery_authorization_required';
        const competing=result.recovery_verification==='other_correlated_signals';
        const failedVendor=result.recovery_verification==='nginx_live_config_not_verified';
        notify(state.language==='fa'?
          (restricted?
            'سرویس Running است؛ برای ثبت رفع رخداد، اختیار اپراتور یا SRE لازم است.':
           competing?
            'سرویس Running است؛ اما آلارم هم‌بستهٔ دیگری باقی است و رخداد بسته نمی‌شود.':
           failedVendor?
            'سرویس Running است؛ اعتبارسنجی کانفیگ nginx هنوز موفق نشده است.':
            'سرویس Running است؛ شرط اصلی آلارم هنوز به‌اندازهٔ کافی تأیید نشده است.') :
          (restricted?
            'Service running; operator or SRE permission is required to finalize recovery.':
           competing?
            'Service running; another correlated alert prevents incident resolution.':
           failedVendor?
            'Service running; nginx configuration validation has not passed.':
            'Service running; alert recovery is not sufficiently verified.'));
      }
      if(result.status==='unknown')notify(state.language==='fa'?
        'بررسی مجدد موفق نبود؛ نتیجهٔ قبلی به‌عنوان وضعیت فعلی نمایش داده نمی‌شود.':
        'Live check unavailable; previous status is not treated as current.',true);
    }catch(e){
      if(token!==state.serviceStatusToken)return;
      state.serviceStatus={status:'unknown',source:'vm_mcp_recheck_failed',
        reason:e.message,verified_systemd_only:false};
      notify((state.language==='fa'?'بررسی مجدد ناموفق: ':'Recheck failed: ')+e.message,true);
    }finally{
      if(token===state.serviceStatusToken){
        state.serviceStatusBusy=false;state.serviceStatusLoading=false;
        renderServiceStatus();renderOperationalSummary();
      }
    }
  }

  function knownServicePlatform(report) {
    const profile=state.serviceProfile?.profile||{};
    if(state.serviceProfile?.configured)return profile.platform;
    return report?.presentation_context?.platform||null;
  }
  function noProposedAction(report) {
    return !report?.remediation_recommendation?.action &&
      !report?.approval_readiness?.action;
  }
  function renderOperationalSummary(report=state.historic||state.report) {
    if(!report)return;
    const c=report.state_correlation||{};
    if(c.conclusion_kind==='source_discrepancy'){
      const fa=state.language==='fa',alert=c.alert||{},vm=c.last_vm_observation||{};
      const fresh=(!state.historic&&state.serviceStatus?.verified_systemd_only===true
        && Number.isFinite(Date.parse(state.serviceStatus.observed_at||''))
        && Date.now()-Date.parse(state.serviceStatus.observed_at)<120000);
      const live=fresh?(fa?'آخرین استعلام مجدد VM MCP: ':'Latest VM MCP recheck: ')+
        (state.serviceStatus.status==='running'?'Running':
         state.serviceStatus.status==='stopped'?'Stopped':'Unverified')+
        ' · '+date(state.serviceStatus.observed_at):'';
      const exactDate=value=>{
        const d=new Date(value);
        return !value||Number.isNaN(d.getTime())?
          (fa?'زمان نامعتبر':'Invalid timestamp'):
          new Intl.DateTimeFormat(fa?'fa-IR':'en-US',{
            dateStyle:'medium',timeStyle:'medium',hour12:false
          }).format(d);
      };
      const observation=(name,st,when,basis,ids)=>
        '<div class="ic-correlation-observation"><strong>'+esc(name)+'</strong>'+
        '<span>'+esc(st)+'</span><small>'+esc(
        when?exactDate(when)+(basis==='source_event_minute_only'?
          (fa?' · فقط دقت دقیقه':' · minute precision only'):
          basis==='evidence_persisted'?
          (fa?' · زمان ثبت Evidence، نه زمان قطعی مشاهده':' · Evidence persisted, not direct observation time'):''):
        (fa?'زمان وقوع از منبع ثبت نشده':'No source occurrence timestamp'))+
        '</small>'+refs(ids)+'</div>';
      const dateRelation=arr(c.contradictions).find(x=>
        x.contradiction_type==='zabbix_down_vs_vm_systemd_running')?.temporal_relation;
      const explanation=dateRelation==='alert_event_before_vm_observation'?
        (fa?'در زمان‌بندی ثبت‌شده، Event زبیکس مقدم بر مشاهدهٔ VM بوده است؛ این ترتیب به‌تنهایی بازیابی واقعی یا False Positive را اثبات نمی‌کند.':
        'Zabbix event precedes VM observation; this alone does not prove recovery or a false positive.'):
        (fa?'ترتیب زمانی واقعی وضعیت‌ها هنوز اثبات نشده است؛ زمان دریافت هشدار جای زمان وقوع Event نیست.':
        'The true state order is not established; receipt time is not source event time.');
      const steps=arr(c.next_steps_fa).slice(0,3);
      const hypothesisNames={
        temporary_stop_and_recovery:fa?'توقف موقت و بازیابی احتمالی':'Possible temporary stop/recovery',
        stale_or_incorrect_monitoring:fa?'تأخیر یا اشکال احتمالی در پایش':'Possible stale monitoring',
        systemd_running_but_http_unhealthy:fa?'بالابودن systemd همراه ناسالم‌بودن HTTP':'systemd up but HTTP unhealthy'
      };
      const hypotheses=arr(c.hypotheses).slice(0,3).map(x=>
        '<li>'+esc(hypothesisNames[x.kind]||x.kind||'')+
        ' — '+esc(fa?'هنوز تأیید نشده':'Not yet verified')+'</li>').join('');
      const sourceFindings=arr(c.cross_source_findings).slice(0,2).map(x=>
        '<div class="ic-correlation-source"><p>'+txt(x.statement_fa)+'</p>'+
        '<p class="ic-headline-meta">'+esc(fa?'نوع تطبیق: ':'Correlation: ')+
        txt(x.status)+' · '+esc(fa?'محدودهٔ Query: ':'Query scope: ')+
        txt(x.query_scope)+'</p>'+refs(x.evidence_refs)+'</div>').join('');
      const http=(!state.historic&&state.httpHealth?.checked_at)
        ?state.httpHealth:c.http_observation;
      const health=http?.status==='unhealthy'?
        (fa?'آخرین بررسی ثبت‌شدهٔ HTTP ناسالم بوده است.':'Last recorded HTTP check was unhealthy.'):
        http?.status==='healthy'?(fa?'آخرین بررسی HTTP پاسخ موفق ثبت کرده است؛ زمان آن باید با وضعیت سرویس مقایسه شود.':
          'Last HTTP check succeeded; compare its timestamp to service state.'):
        (fa?'سلامت HTTP برنامه هنوز تأیید نشده است.':'Application HTTP health has not been verified.');
      const approve=noProposedAction(report)?
        (fa?'هیچ اقدام اجرایی تأییدشده‌ای ثبت نشده است؛ Start/Restart بدون مجوز انجام نشود.':
          'No execution action is authorized; do not start or restart without governance.'):
        (fa?'اجرای هر اقدام همچنان مشروط به گیت تأیید و بررسی زنده است.':
          'Any action still requires authorization and live preflight.');
      show('#ic-operational-summary','<h3>'+esc(fa?
        'اختلاف وضعیت مانیتورینگ و systemd':'Monitoring / systemd state discrepancy')+'</h3>'+
        '<p><strong>'+txt(c.headline_fa)+'</strong></p>'+
        '<div class="ic-correlation-pair">'+
          observation('Zabbix','Down / inactive',alert.observed_at,alert.time_basis,alert.evidence_refs)+
          observation('VM MCP / systemd','Running',vm.observed_at,vm.time_basis,vm.evidence_refs)+
        '</div>'+
        (alert.received_at?'<p class="ic-headline-meta">'+esc(fa?
          'زمان دریافت هشدار در AIOps: ':'Alert received at AIOps: ')+
          txt(exactDate(alert.received_at))+' · '+esc(fa?
          'این زمان، زمان وقوع قطعی Event در زبیکس نیست.':
          'Receipt time is not the Zabbix event occurrence time.')+'</p>':'')+
        '<p>'+esc(explanation)+'</p>'+
        '<p class="ic-headline-caution">'+esc(health)+'</p>'+
        (sourceFindings?'<h4>'+esc(fa?
          'جمع‌بندی فنی Elasticsearch و Journal':'Elasticsearch / Journal evidence coverage')+
          '</h4>'+sourceFindings:'')+
        (hypotheses?'<h4>'+esc(fa?'توضیح‌های احتمالی؛ نه علت تأییدشده':
          'Possible explanations, not established causes')+'</h4>'+
          '<ul>'+hypotheses+'</ul>':'')+
        (live?'<p class="ic-headline-meta">'+esc(live)+'</p>':'')+
        '<h4>'+esc(fa?'سه بررسی بعدی برای تعیین علت':'Three discriminating checks')+'</h4>'+
        '<ol>'+steps.map(x=>'<li>'+txt(x)+'</li>').join('')+'</ol>'+
        '<p class="ic-headline-meta">'+esc(approve)+'</p>');
      return;
    }
    if(report.technical_investigation){
      show('#ic-operational-summary',''); // section 01 uses the detailed evidence-bound assessment
      return;
    }
    if(report.memory_investigation){
      const m=report.memory_investigation,fa=state.language==='fa';
      const pct=m.measurements?.memory_used_percent;
      show('#ic-operational-summary','<h3>'+esc(fa?
        'بررسی هشدار مصرف بالای RAM سرور':'Host high-memory investigation')+'</h3>'+
        '<p><strong>'+esc(fa?
          'Zabbix هشدار مصرف بالای RAM را ثبت کرده است.':'Zabbix reported high RAM utilization.')+'</strong></p>'+
        '<p>'+esc(m.alert?.recovery_received?
          (fa?'پیام رفع هشدار در Zabbix ثبت شده است؛ علت رشد RAM و اثر اقدام عملیاتی هنوز ثابت نشده است.':
            'Zabbix reported recovery, but root cause and any action effect are unproven.'):
          (fa?'بازگشت حافظه به حالت عادی هنوز با شاهد مستقل اثبات نشده است.':
            'Independent memory recovery is not yet demonstrated.'))+'</p>'+
        (pct!==null&&pct!==undefined?'<p>'+esc(fa?'آخرین مقدار ثبت‌شدهٔ مستقیم VM MCP: ':'Recorded VM MCP RAM usage: ')+
          '<strong>'+num(pct)+'%</strong></p>':'')+
        '<p class="ic-headline-caution">'+esc(fa?
          'هیچ پردازشی صرفاً با دیدن عنوان هشدار یا توافق Agentها به‌عنوان عامل رشد RAM معرفی نمی‌شود.':
          'An alert title or Agent agreement cannot identify the memory spike culprit.')+'</p>');
      return;
    }
    const fa=state.language==='fa',i=report.incident_summary||{};
    const p=report.presentation_context||{},st=state.historic?null:state.serviceStatus;
    const active=st?.verified_systemd_only===true;
    const old=st?.observed_at&&Date.now()-Date.parse(st.observed_at)>120000;
    const fresh=active&&!old;
    const statusSentence=fresh&&st.status==='running'?
      (fa?'آخرین استعلام مستقیم VM MCP نشان می‌دهد سرویس از دید systemd در حال اجراست.':
        'The latest VM MCP systemd observation shows the service is running.'):
      fresh&&st.status==='stopped'?
      (fa?'استعلام مستقیم VM MCP نشان می‌دهد سرویس متوقف است.':
        'VM MCP directly observed the service stopped.'):
      (fa?'وضعیت فعلی سرویس باید با VM MCP مجدداً بررسی شود؛ عنوان هشدار یا گزارش Agent جایگزین بررسی زنده نیست.':
        'Current state needs a new VM MCP check. Alert headlines and agent summaries are not live checks.');
    const action=noProposedAction(report);
    const reason=p.action_disposition==='blocked_by_evaluator'
      ?(fa?'Evaluator پیشنهاد تغییر را مجاز ندانسته است.':'The evaluator blocked an execution recommendation.')
      :(fa?'برای این رخداد اقدام اجرایی تأییدشده‌ای ثبت نشده است.':
        'No governed execution action has been registered for this incident.');
    const vm=p.observations||{};
    const checkedJson=arr(report.configuration_diagnostic?.files).filter(
      f=>f && low(f.status)==='valid_json_syntax');
    const dotnet=vm.dotnet_config_syntax?.values?.syntax_valid===true;
    const disk=vm.disk_status?.values||{};
    const full=Number(disk.used_percent)>=95;
    const paths=checkedJson.map(f=>f.path_verified && f.path?f.path:(f.file||'')).filter(Boolean);
    const config=dotnet&&paths.length?
      (fa?'سینتکس JSON فایل‌های ثبت‌شده ('+paths.join('، ')+') معتبر بوده؛ سلامت Runtime تأیید نشده است.':
        'JSON syntax passed for '+paths.join(', ')+'; runtime health is unverified.'):
      dotnet?
        (fa?'Validator موفقیت سینتکس JSON را ثبت کرده اما نام فایل بررسی‌شده در شواهد این نسخه مشخص نیست.':
          'JSON syntax success was recorded, but the checked filename is unavailable in this report.'):
      (fa?'صحت کانفیگ در همین جمع‌بندی به‌طور کامل تأیید نشده است.':
        'Complete configuration validation is not established here.');
    const health=state.httpHealth;
    const healthLabel=health?.status==='healthy'?
      (fa?'Endpoint سلامت HTTP در آخرین تست پاسخ موفق داده است.':'The configured HTTP health check last returned success.'):
      health?.status==='unhealthy'?
      (fa?'آخرین تست HTTP Health ناموفق بوده است.':'The latest HTTP health check was unhealthy.'):
      (fa?'سلامت HTTP برنامه هنوز تأیید نشده است.':'Application HTTP health remains unverified.');
    const observationTime=fresh&&st.observed_at?
      (fa?'مشاهدهٔ systemd: ':'Systemd observed: ')+date(st.observed_at):'';
    const rca=report.rca_assessment?.rca_confidence;
    const rcaLabel=rca==null?'':(fa?' · اطمینان به علت ریشه‌ای: ':' · Root-cause confidence: ')+numberPct(rca);
    const verifiedRefs=[...new Set([
      st?.evidence_ref,
      ...Object.values(vm).map(row=>row?.evidence_ref),
    ].filter(Boolean))].slice(0,8);
    show('#ic-operational-summary',
      '<h3>'+esc(fa?'نتیجهٔ عملیاتی این رخداد':'Operational incident assessment')+'</h3>'+
      '<p><strong>'+esc(statusSentence)+'</strong></p>'+
      '<p>'+esc(healthLabel+' '+config)+'</p>'+
      (full?'<p class="ic-headline-caution">'+esc(fa?
        'در زمان تحلیل فشار فضای دیسک مشاهده شد. این یک هشدار مستقل است و به‌تنهایی مانع Start مجاز سرویس نیست؛ وضعیت ظرفیت جداگانه بررسی شود.':
        'Disk pressure was observed during analysis. This is an independent warning, not a standalone blocker for an approved service Start; review storage separately.')+'</p>':'')+
      '<p>'+esc(action?reason:(fa?'اقدام پیشنهادی باید مطابق گیت مجوز بررسی شود.':
        'The proposed action requires governed authorization.'))+'</p>'+
      '<p class="ic-headline-meta">'+esc(observationTime+rcaLabel)+
      (p.block_reason?' · '+txt(p.block_reason):'')+'</p>'+
      refs(verifiedRefs));
  }
  function renderServiceProfile() {
    const node=$('#ic-service-profile');
    if(!node)return;
    const ram=Boolean((state.historic||state.report)?.memory_investigation);
    node.hidden=ram;
    if(ram)return;
    const fa=state.language==='fa';
    const row=state.serviceProfile||{},p=row.profile||{};
    const h=state.httpHealth||{};
    const known=row.configured===true;
    const label=(x)=>esc(x==null||x===''?(fa?'ثبت نشده':'Not configured'):String(x));
    const healthLabel={
      healthy:fa?'سالم در آخرین بررسی HTTP':'Healthy at last HTTP check',
      unhealthy:fa?'ناسالم در آخرین بررسی HTTP':'Unhealthy at last HTTP check',
      unavailable:fa?'بررسی HTTP ناموفق':'HTTP check unavailable',
      not_checked:fa?'HTTP هنوز بررسی نشده':'HTTP not checked',
      not_configured:fa?'پورت یا Health Endpoint ثبت نشده':'Health endpoint not configured'
    }[h.status]||(fa?'بررسی نشده':'Not checked');
    const ready=known&&p.expected_port&&p.health_path;
    const item=(id,title,v,type='text')=>
      '<label for="ic-profile-'+id+'">'+esc(title)+
      '<input id="ic-profile-'+id+'" name="'+id+'" type="'+type+'" value="'+esc(v??'')+
      '" maxlength="300"></label>';
    const form='<details id="ic-profile-edit"><summary>'+esc(fa?
      'ویرایش پروفایل سلامت (فقط SRE)':'Edit health profile (SRE only)')+'</summary>'+
      '<form class="ic-profile-form" id="ic-profile-form">'+
      '<label>'+esc(fa?'نوع سرویس':'Platform')+
      '<select name="platform"><option value="vm_systemd"'+(p.platform==='vm_systemd'||!p.platform?' selected':'')+'>VM / systemd</option>'+
      '<option value="windows_service"'+(p.platform==='windows_service'?' selected':'')+'>Windows Service</option>'+
      '<option value="kubernetes"'+(p.platform==='kubernetes'?' selected':'')+'>Kubernetes</option></select></label>'+
      item('owner',fa?'مالک سرویس':'Owner',p.owner)+
      item('expected_port',fa?'پورت HTTP':'HTTP port',p.expected_port,'number')+
      item('health_path',fa?'مسیر Health (مثل /health)':'Health path',p.health_path)+
      '<label>HTTP / HTTPS<select name="health_scheme"><option value="http"'+(p.health_scheme!=='https'?' selected':'')+'>HTTP</option>'+
      '<option value="https"'+(p.health_scheme==='https'?' selected':'')+'>HTTPS</option></select></label>'+
      item('dependencies',fa?'وابستگی‌ها (با کاما)':'Dependencies (comma separated)',arr(p.dependencies).join(','))+
      item('restart_runbook_id',fa?'شناسه Runbook (اطلاعاتی)':'Runbook ID (informational)',p.restart_runbook_id)+
      item('verification_notes',fa?'قواعد راستی‌آزمایی':'Verification notes',p.verification_notes)+
      '<button class="ic-btn ic-btn-primary" type="submit"'+(state.profileBusy?' disabled':'')+'>'+
      esc(state.profileBusy?(fa?'در حال ذخیره…':'Saving…'):(fa?'ذخیره پروفایل سرویس':'Save service profile'))+
      '</button></form></details>';
    show('#ic-service-profile','<div class="ic-profile-summary"><strong>'+
      esc(fa?'پروفایل و سلامت برنامه':'Service profile & application health')+'</strong>'+
      '<span class="ic-status" data-tone="'+(known?'ok':'warn')+'">'+esc(known?
      (fa?'ثبت‌شده توسط SRE':'SRE configured'):(fa?'نیازمند تکمیل':'Setup needed'))+'</span></div>'+
      '<div class="ic-profile-facts"><span>'+esc(fa?'محیط: ':'Platform: ')+
      label(p.platform||state.report?.presentation_context?.platform)+'</span>'+
      '<span>'+esc(fa?'مالک: ':'Owner: ')+label(p.owner)+'</span>'+
      '<span>'+esc(fa?'پورت: ':'Port: ')+label(p.expected_port)+'</span>'+
      '<span>'+esc(fa?'مسیر سلامت: ':'Health: ')+label(p.health_path)+'</span>'+
      '<span>'+esc(fa?'وابستگی‌ها: ':'Dependencies: ')+label(arr(p.dependencies).join(', '))+'</span></div>'+
      '<div class="ic-http-health"><span>'+esc(fa?'وضعیت HTTP: ':'HTTP status: ')+'</span>'+
      '<strong data-state="'+esc(h.status||'not_configured')+'">'+esc(healthLabel)+'</strong>'+
      (h.checked_at?'<small>'+txt(date(h.checked_at))+'</small>':'')+
      (h.http_code?'<small>HTTP '+txt(h.http_code)+'</small>':'')+
      (ready?'<button type="button" class="ic-btn ic-btn-muted" id="ic-http-recheck"'+
       (state.httpHealthBusy||state.historic?' disabled':'')+'>'+
       esc(state.httpHealthBusy?(fa?'در حال بررسی…':'Checking…'):(fa?'بررسی زنده HTTP':'Recheck HTTP'))+
       '</button>':'')+'</div>'+(!state.historic?form:''));
  }
  async function loadServiceProfile() {
    try{
      const values=await Promise.allSettled([
        api(base+'/service-profile'),api(base+'/health-status')
      ]);
      state.serviceProfile=values[0].status==='fulfilled'?values[0].value:
        {configured:false,reason:'catalog_unavailable'};
      state.httpHealth=values[1].status==='fulfilled'?values[1].value:
        {status:'unavailable'};
    }catch(_){state.serviceProfile={configured:false};state.httpHealth={status:'unavailable'};}
    renderServiceProfile();renderOperationalSummary();
  }
  async function recheckHttpHealth() {
    if(state.httpHealthBusy||state.historic)return;
    state.httpHealthBusy=true;renderServiceProfile();
    try {
      state.httpHealth=await api(base+'/health/recheck',{method:'POST'});
    }catch(e){
      state.httpHealth={status:'unavailable'};
      notify((state.language==='fa'?'بررسی HTTP ناموفق: ':'HTTP check failed: ')+e.message,true);
    }finally {
      state.httpHealthBusy=false;renderServiceProfile();renderOperationalSummary();
    }
  }
  async function saveServiceProfile(form) {
    if(state.profileBusy||state.historic)return;
    const field=name=>String(form.elements.namedItem(name)?.value||'').trim();
    const port=field('expected_port'),deps=field('dependencies');
    const payload={
      platform:field('platform')||'vm_systemd',owner:field('owner')||null,
      expected_port:port?Number(port):null,health_path:field('health_path')||null,
      health_scheme:field('health_scheme')||'http',
      dependencies:deps?deps.split(',').map(x=>x.trim()).filter(Boolean):[],
      restart_runbook_id:field('restart_runbook_id')||null,
      verification_notes:field('verification_notes')||null
    };
    state.profileBusy=true;
    try{
      state.serviceProfile=await api(base+'/service-profile',{
        method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)
      });
      state.httpHealth={status:'not_checked'};
      notify(state.language==='fa'?'پروفایل ذخیره شد؛ HTTP هنوز بررسی نشده است.':
        'Profile saved; HTTP health has not been tested.');
    }catch(e){notify((state.language==='fa'?'ذخیره پروفایل ناموفق: ':'Profile save failed: ')+e.message,true);}
    finally{state.profileBusy=false;renderServiceProfile();renderOperationalSummary();}
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
    // The Decision Brief is an immutable analysis snapshot. After an
    // approved Start the authoritative Incident row, not that old snapshot,
    // decides what appears in the page header.
    const currentIncidentStatus=state.historic?i.status:
      state.lifecycle?.incident_status||i.status;
    const resolved=['resolved','closed'].includes(low(currentIncidentStatus));
    show('#ic-hero-badges',pill(i.severity)+pill(currentIncidentStatus)+pill(a.approval_status));
    const authStatus=low(a.approval_status);
    const analyzing=state.lifecycle?.analysis_in_progress===true;
    const stateChangedActive=!state.historic&&
      state.recoveryApproval?.status==='state_changed_active';
    const recoveryApproved=!state.historic&&
      state.recoveryApproval?.status==='approved'&&
      UUID.test(String(state.recoveryApproval?.approval_id||''))&&
      ['start_service','restart_service'].includes(state.recoveryApproval?.action);
    const recoveryIsStart=state.recoveryApproval?.action==='start_service';
    const recoveryVerb=recoveryIsStart?'Start':'Restart';
    const pulseTitle=resolved?
      (state.language==='fa'?'رخداد رفع شده است':'Incident resolved')
      : recoveryApproved?
        (state.language==='fa'?'مجوز '+recoveryVerb+' تأیید شده؛ هنوز اجرا نشده است':
          recoveryVerb+' approved; execution pending')
      : analyzing
      ? (state.language==='fa'?'در حال بررسی و تحلیل':'Investigation in progress')
      : stateChangedActive?
        (state.language==='fa'?'سرویس از دید systemd فعال؛ Restart ثبت نشد':
          'Systemd active; restart approval not queued')
      : authStatus==='pending'?tr('approvalPending'):authStatus==='approved'?tr('approvalApproved'):tr('approvalFinished');
    const recoveryExplanation=state.language==='fa'
      ? 'علت توقف بازیابی: هنگام ثبت درخواست تأیید، بررسی زنده نشان داد سرویس از وضعیت خطا به active/running تغییر کرده است. بنابراین برای جلوگیری از Restart غیرضروری، درخواست Approval ثبت نشد.'
      : 'Why recovery was stopped: the fresh systemd check found the service active/running rather than failed. Restart approval was not queued to prevent an unnecessary operation.';
    show('#ic-decision-pulse',resolved?
        '<small>'+esc(state.language==='fa'?'آخرین وضعیت پایگاه داده':'Latest incident state')+
        '</small><strong>'+esc(pulseTitle)+'</strong><p>'+
        esc(state.language==='fa'?
          'وضعیت رفع رخداد در سامانه ثبت شده است. کارت وضعیت سرویس در بالا آخرین شواهد VM را جداگانه نمایش می‌دهد.':
          'Resolution was persisted. The service card separately shows the latest VM evidence.')+
        '</p>'
      : recoveryApproved
      ? '<small>'+esc(state.language==='fa'?'مجوز بازیابی آمادهٔ اجرا':'Approved recovery ready')+
          '</small><strong>'+esc(pulseTitle)+'</strong><p>'+
          esc(state.language==='fa'?
            'تأیید مجوز به‌تنهایی سرویس را راه‌اندازی نمی‌کند. برای اجرای واقعی روی سرور، دکمهٔ زیر را بزنید. پیش از اجرا وضعیت زنده و کانفیگ دوباره بررسی می‌شود.':
            'Approval alone does not start the service. Use the explicit action below; the server repeats live status and configuration checks.')+
          '</p><p><code>'+txt(state.recoveryApproval.approval_id)+'</code></p>'+
          '<button type="button" class="ic-btn ic-btn-danger" data-recovery-approval="execute"'+
          (state.busy?' disabled':'')+'>'+
          esc(state.language==='fa'?'اجرای واقعی '+recoveryVerb+' تأییدشده':
            'Execute approved '+recoveryVerb)+'</button>'
      : stateChangedActive
      ? '<div role="alert" aria-live="polite" style="border:2px solid #d97706;border-radius:12px;padding:18px 20px;background:rgba(217,119,6,.09);margin:8px 0;">'+
          '<strong style="display:block;font-size:1.35rem;line-height:1.6;font-weight:800;">'+
            esc(state.language==='fa'?'علت عدم اجرای بازیابی سرویس':'Why service recovery was stopped')+'</strong>'+
          '<p style="font-size:1.1rem;line-height:1.9;font-weight:650;margin:10px 0;">'+
            esc(recoveryExplanation)+'</p>'+
          '<p style="font-size:1rem;line-height:1.8;margin:0;">'+
            esc(recoveryApprovalSafetyNote(state.language==='fa'))+'</p></div>'
      : '<small>'+tr('decisionDesk')+'</small><strong>'+esc(pulseTitle)+'</strong><p>'+
          esc(analyzing
            ? (state.language==='fa'?'Agentها در حال گردآوری شواهد و بررسی رخداد هستند.':'Agents are analyzing the incident and gathering evidence.')
            : authStatus==='approved'?tr('approvalSeparate'):tr('backendGate'))+'</p>');
    const quick=[
      ['started',date(i.started_at)],['duration',i.elapsed_seconds==null?tr('unknown'):num(Math.max(0,Math.floor(i.elapsed_seconds/60)))+' '+(state.language==='fa'?'دقیقه':'min')],
      ['risk',noProposedAction(r)?(state.language==='fa'?'اقدام اجرایی پیشنهاد نشده':'No executable action'):status(action.risk_level)],
      ['evidence',num(i.total_evidence_count??r.source_references?.length??0)]
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
    if(arr(c.items).length>0 && arr(c.items).every(x=>x.use_status!=='cited_by_agent'))messages.push({text:tr('notUsed')});
    return messages;
  }
  function renderOperatorExplanation(r) {
    const op=r.operator_explanation||{},fa=state.language==='fa';
    if(!op.headline_fa){show('#ic-operator-explanation','');return;}
    const confirmed=arr(op.confirmed_findings);
    const unknown=arr(op.uncertainties_fa),next=arr(op.next_steps_fa);
    const rows=(items,withRefs)=>'<ul class="ic-explain-list">'+items.slice(0,6).map(x=>
      '<li>'+txt(withRefs?x.text_fa:x)+(withRefs?refs(x.evidence_refs):'')+'</li>'
    ).join('')+'</ul>';
    const heading=(title,body,label)=>'<section class="ic-explain-part"><h4>'+esc(title)+
      '</h4>'+body+'</section>';
    const faHeadline=op.headline_fa;
    const enHeadline=confirmed.length?
      'Evidence-backed diagnostic findings are available; see source details below.':
      'The recorded investigation does not yet establish the root cause.';
    const analysis=heading(fa?'چه چیزهایی واقعاً بررسی و تأیید شده؟':'Confirmed observations',
      confirmed.length?rows(confirmed,true):'<p>'+esc(fa?'شاهد قطعی کافی ثبت نشده است.':'No sufficient confirmed evidence.')+'</p>');
    const caution=heading(fa?'چه چیزهایی هنوز نامشخص است؟':'Open questions',
      rows(unknown,false));
    const nextSteps=heading(fa?'قدم بعدی پیشنهادی AIOps':'Suggested next steps',
      rows(next,false));
    const approval='<p class="ic-explain-gate">'+esc(fa?op.approval_explanation_fa:
      'This report is read-only and cannot approve or execute a configuration change.')+'</p>';
    const total=r.incident_summary?.total_evidence_count;
    const count=Number.isInteger(total)?
      '<p class="ic-explain-count">'+esc(fa?
        'شواهد ثبت‌شده: '+num(total)+' مورد · شواهد تازه و قابل اتکا برای تصمیم اجرایی: '+
          num(r.incident_summary.valid_evidence_count||0)+' مورد':
        'Recorded evidence: '+total+' · fresh execution-grade: '+
          (r.incident_summary.valid_evidence_count||0))+'</p>':'';
    show('#ic-operator-explanation','<details class="ic-diagnosis-drilldown"><summary>'+
      esc(fa?'دیدن گزارش تفصیلی یافته‌ها و شناسهٔ شواهد':'Detailed findings and evidence IDs')+
      '</summary><div class="ic-diagnosis-drilldown-body"><article class="ic-explain">'+
      '<h3>'+esc(fa?faHeadline:enHeadline)+'</h3>'+
      '<p class="ic-headline-caution">'+esc(fa?
        'یافته‌های زیر متعلق به زمان انجام تحلیل هستند و ممکن است با آخرین بررسی مجدد سرویس تفاوت داشته باشند.':
        'These findings describe the investigation time and may differ from the most recent live recheck.')+'</p>'+count+
      analysis+caution+nextSteps+approval+'</article></div></details>');
  }


  function renderMemoryForensics(r) {
    const node=$('#ic-memory-forensics');
    if(!node)return;
    const m=r.memory_investigation;
    node.hidden=!m;
    if(!m){show('#ic-memory-forensics','');return;}
    const fa=state.language==='fa',q=m.measurements||{},a=m.alert||{};
    const checked=arr(m.checks),next=arr(m.recommended_next_checks);
    const label=(code,faText,enText)=>fa?faText:enText;
    const number=x=>x===null||x===undefined?
      (fa?'اندازه‌گیری نشده':'Not measured'):num(x);
    const line=(key,v,unit)=>'<div class="ic-memory-measure"><small>'+
      esc(key)+'</small><strong>'+esc(number(v))+
      (v===null||v===undefined?'':esc(unit||''))+'</strong></div>';
    const metrics='<div class="ic-memory-metrics">'+
      line(label('ram','مصرف RAM از VM','VM RAM usage'),q.memory_used_percent,'%')+
      line(label('avail','RAM قابل استفاده','Available RAM'),q.available_mb,' MB')+
      line(label('cache','Cache قابل بازیابی','Reclaimable cache'),q.cache_reclaimable_mb,' MB')+
      line(label('swap','Swap مصرف‌شده','Used Swap'),q.swap_used_mb,' MB')+
      line(label('psi','فشار حافظه PSI','Memory PSI avg10'),q.psi_memory_some_avg10,'%')+
      '</div>';
    const processes=arr(q.top_processes).length?
      '<h4>'+esc(fa?'پردازش‌های پرمصرف در زمان ثبت Snapshot':'Top consumers at snapshot time')+'</h4>'+
      '<div class="ic-memory-processes">'+arr(q.top_processes).slice(0,8).map(p=>
        '<div><span>'+code(p.name)+' · PID '+txt(p.pid)+'</span>'+
        '<strong>'+num(p.percent)+'%'+(p.rss_mb!==null&&p.rss_mb!==undefined?
        ' · '+num(p.rss_mb)+' MB RSS':'')+'</strong></div>').join('')+'</div>'+
      '<p class="ic-memory-note">'+esc(fa?
        'این پردازش‌ها در یک لحظه حافظه مصرف کرده‌اند؛ الزاماً عامل رشد حافظه در زمان هشدار نیستند.':
        'Snapshot consumers are not automatically the historical root cause.')+'</p>':
      '<p class="ic-memory-note">'+esc(fa?
        'فهرست پردازش‌های پرمصرف در شواهد این رخداد ثبت نشده است.':
        'No attributable top-process snapshot was recorded.')+'</p>';
    const checks='<div class="ic-memory-checks">'+checked.map(x=>
      '<div class="ic-memory-check"><span>'+
      esc(x.status==='checked'?'✓ ':x.status==='failed'?'! ':'– ')+
      txt(fa?x.title_fa:x.code)+'</span><strong>'+esc(
        x.status==='checked'?(fa?'بررسی شده':'Checked'):
        x.status==='failed'?(fa?'ناموفق':'Failed'):(fa?'انجام نشده':'Not collected'))+
      '</strong>'+(x.observed_at?'<small>'+txt(date(x.observed_at))+'</small>':'')+
      refs(x.evidence_refs)+'</div>').join('')+'</div>';
    const steps='<ol class="ic-memory-steps">'+next.map(x=>
      '<li><strong>'+txt(x.title_fa)+'</strong><p>'+txt(x.detail_fa)+'</p>'+
      '<small>'+esc(x.type==='read_only'?(fa?'فقط خواندنی؛ بدون Restart':'Read-only'):
       (fa?'نیازمند تصمیم و مجوز مستقل':'Separate governed decision required'))+
      '</small></li>').join('')+'</ol>';
    show('#ic-memory-forensics',
      '<div class="ic-memory-header"><h3>'+esc(fa?'چرا RAM بالا رفت؟':'Why did RAM rise?')+'</h3>'+
      '<span class="ic-tag">'+esc(fa?'علت ریشه‌ای هنوز تأیید نشده':'Root cause not proven')+
      '</span></div>'+
      '<p>'+esc(fa?'میزبان: ':'Host: ')+txt(m.host||r.incident_summary?.host)+
      ' · '+esc(fa?'مقصد ثبت‌شده در آلارم: ':'Explicit alert target: ')+
      txt(m.alert_target_ip)+'</p>'+
      '<p>'+esc(fa?'هشدار اولیه: مصرف بالای ':'Initial threshold: above ')+
      number(a.threshold_percent)+'%'+(a.duration_minutes?
        ' · '+num(a.duration_minutes)+' '+esc(fa?'دقیقه':'minutes'):'')+'</p>'+
      '<p>'+esc(a.recovery_received?
        (fa?'✓ پیام Recovery از Zabbix دریافت شد؛ به معنی اجرای اصلاح توسط AIOps نیست.':
        '✓ Zabbix recovery received; no AIOps repair is thereby proven.'):
        (fa?'Recovery مستقل هنوز ثبت نشده است.':'Independent recovery not recorded.'))+
      '</p>'+metrics+processes+
      '<h4>'+esc(fa?'چه چیزهایی واقعاً بررسی شده؟':'What was actually checked?')+'</h4>'+
      checks+
      '<h4>'+esc(fa?'برای مشخص شدن علت چه شواهدی کم است؟':'What is still missing?')+'</h4>'+
      '<ul>'+arr(m.gaps).map(x=>'<li>'+txt(x)+'</li>').join('')+'</ul>'+
      '<h4>'+esc(fa?'اقدامات پیشنهادی به ترتیب اولویت':'Recommended investigation steps')+'</h4>'+
      steps+'<p class="ic-memory-note">'+esc(fa?
        'هیچ افزایش RAM، Kill، Restart یا پاک‌سازی Cache به‌صورت خودکار مجاز نیست.':
        'No automatic RAM increase, Kill, Restart or cache clearing is authorized.')+'</p>');
  }


  // Exact, allowlisted filenames from the persisted dotnet_config_syntax
  // observation. Never infer that appsettings.json exists or was validated.
  function renderCheckedJsonFiles(config) {
    const fa=state.language==='fa';
    const files=arr(config?.files);
    if(!files.length) {
      return '<p class="ic-diagnosis-caution">'+esc(fa?
        'نام فایل JSON بررسی‌شده در Evidence این رخداد ثبت نشده است؛ بنابراین مشخص نیست کدام فایل واقعاً تست شده است.':
        'No checked JSON filename was recorded in this incident evidence; the tested file cannot be identified.')+'</p>';
    }
    const labels={
      valid_json_syntax:fa?'سینتکس معتبر':'Syntax valid',
      invalid_json_syntax:fa?'خطای سینتکس':'Syntax invalid',
      unavailable:fa?'خواندن/بررسی ناموفق':'Not checked (unavailable)',
    };
    const items=files.map(file=>{
      const filename=file.path_verified===true && file.path ? file.path : file.file;
      const stateLabel=labels[low(file.status)]||(fa?'نتیجه نامشخص':'Unknown result');
      const line=Number.isInteger(file.line)?(' · '+(fa?'خط ':'line ')+num(file.line)):'';
      const column=Number.isInteger(file.column)?(' · '+(fa?'ستون ':'column ')+num(file.column)):'';
      return '<li><code dir="ltr">'+txt(filename||'unknown')+'</code>'+
        '<span class="ic-config-file-result">'+esc(stateLabel)+esc(line+column)+'</span>'+
        (!file.path_verified?'<small>'+esc(fa?'مسیر کامل از شواهد تأیید نشده است.':
          'Full absolute path is not verified in evidence.')+'</small>':'')+
        (file.evidence_ref?'<small>Evidence ID: '+txt(file.evidence_ref)+'</small>':'')+'</li>';
    }).join('');
    return '<div class="ic-config-verified-files"><strong>'+esc(fa?
      'فایل‌های JSON ثبت‌شده در نتیجهٔ Validator:':
      'Exact JSON files checked by the validator:')+'</strong>'+
      '<ul>'+items+'</ul><p>'+esc(fa?
      'این فقط آزمون سینتکس فایل‌های فهرست‌شده است؛ سایر فایل‌ها، مقادیر تنظیمات و سلامت Runtime تأیید نشده‌اند.':
      'Only listed files were syntax-checked; other files, configuration semantics and runtime health are not verified.')+'</p></div>';
  }


  function nginxCandidateReadiness(r) {
    const c=r?.dynamic_investigation?.config_proposal||{};
    if(low(r?.incident_summary?.service).replace(/\.service$/,'')!=='nginx' ||
       low(c.status)!=='candidate_proposed')return '';
    const fa=state.language==='fa';
    const status=low(c.validation_status);
    const codes={
      unexpected_open_brace_still_present:fa?'آکولاد باز اضافه همچنان در تست کاندید دیده شده است.':'Unexpected opening brace still present in staged test.',
      unexpected_closing_brace:fa?'آکولاد بستهٔ اضافه در تست کاندید گزارش شده است.':'Unexpected closing brace in staged test.',
      directive_context_invalid:fa?'دستور Nginx در بلوک نامعتبر قرار گرفته است.':'Nginx directive is in an invalid context.',
      directive_arguments_invalid:fa?'تعداد پارامترهای یکی از دستورها نامعتبر است.':'A directive has invalid arguments.',
      upstream_resolution_failed:fa?'Resolve یکی از Upstreamها در تست ناموفق بود.':'An upstream could not be resolved.',
      permission_denied:fa?'مجوز خواندن یکی از منابع برای تست کافی نبود.':'Permission denied while staging.',
      referenced_file_missing:fa?'یک فایل موردنیاز برای تست پیدا نشد.':'A referenced file was missing.',
      stage_timeout:fa?'تست کاندید از مهلت تعیین‌شده عبور کرد.':'Staged check timed out.',
      nginx_staging_unavailable:fa?'اجرای تست مرحله‌ای ممکن نشد.':'Staged validator unavailable.',
      nginx_binary_not_found:fa?'باینری Nginx برای تست در دسترس نبود.':'Nginx binary unavailable for testing.',
      nginx_staged_check_failed_unspecified:fa?'تست مرحله‌ای ناموفق بود؛ نوع خطا به‌صورت امن قابل استخراج نبود.':'Staged test failed; safe error category unavailable.',
      not_recorded:fa?'نوع دقیق شکست تست مرحله‌ای در شواهد ثبت نشده است.':'The reason for staged-test failure was not recorded.'
    };
    const explanation=status==='staged_failed'?
      (fa?'تغییر پیشنهادی ساخته شد، ولی nginx -t روی کپی موقت شکست خورد؛ این کاندید هنوز قابل‌اعمال نیست.':
        'A candidate was generated, but nginx -t on the staged copy failed. It is not deployable.'):
      status==='staged_pass_not_isolated'?
      (fa?'تست کپی موقت موفق بود، ولی Includeها/وابستگی‌های زنده خوانده شده‌اند و تست ایزوله نیست.':
        'The staged test passed but reads live dependencies/includes and is not isolated.'):
      (fa?'تست معتبر کاندید انجام نشده یا نتیجه قطعی ثبت نشده است.':
        'The candidate has no conclusive validated test.');
    const diff=c.redacted_diff||{};
    const change=Number.isInteger(diff.line)?
      '<pre class="ic-config-excerpt" dir="ltr">'+
      esc('@@ '+(c.config_file||'nginx config')+':'+diff.line+' @@\n- '+safe(diff.before)+'\n+ '+safe(diff.after))+
      '</pre>':'';
    const reason=status==='staged_failed'?
      '<p>'+esc(codes[low(c.stage_failure_reason)]||
        (fa?'دلیل جزئی شکست از نسخهٔ قبلی Validator ثبت نشده است.':'Older validator did not record a specific failure reason.'))+'</p>':'';
    return '<article class="ic-config-check ic-nginx-remediation-state" data-validation="'+esc(status)+'">'+
      '<h4>'+esc(fa?'چرا پیشنهاد اصلاح Nginx برای Approval اجرایی فعال نشد؟':
        'Why the Nginx correction did not reach executable approval')+'</h4>'+
      '<p><b>'+esc(fa?'فایل: ':'File: ')+'</b><code dir="ltr">'+txt(c.config_file||'not recorded')+'</code>'+
      (Number.isInteger(c.error_line)?' · '+esc(fa?'خط ':'line ')+num(c.error_line):'')+'</p>'+
      '<p>'+esc(fa?'وضعیت کاندید: ':'Candidate: ')+
      '<strong>'+esc(c.validation_status||'UNVERIFIED')+'</strong></p>'+
      change+'<p>'+esc(explanation)+'</p>'+reason+
      '<p class="ic-diagnosis-gate">'+esc(fa?
        'این مرحله فقط Preview است. دکمهٔ درخواست اعتبارسنجی، Approval اجرای تغییر نیست. بدون تست مستقل، قرارداد تغییر نسخه‌دار، تطبیق هش فایل اصلی و مجوز جداگانه، فایل سرور تغییر نمی‌کند.':
        'This is preview only. Requesting validation is not execution approval. Independent verification, a versioned change contract, source-hash matching and separate approval are prerequisites to any write.')+'</p>'+
      refs(c.source_evidence_refs)+'</article>';
  }

  function renderOperatorDiagnosis(r) {
    const node=$('#ic-diagnosis');
    if(!node)return;
    const fa=state.language==='fa',config=r.configuration_diagnostic||{},
      op=r.operator_explanation||{},summary=r.incident_summary||{},
      action=r.remediation_recommendation||{},agents=arr(r.agent_findings);
    const invalid=low(config.status)==='invalid';
    const validJson=low(config.status)==='json_syntax_valid';
    const kind=invalid?'invalid':validJson?'syntax_only':'unknown';
    const output=arr(op.confirmed_findings).filter(x=>x&&x.text_fa);
    const unresolved=arr(op.uncertainties_fa).filter(Boolean);
    const next=arr(op.next_steps_fa).filter(Boolean);
    if(!output.length && !invalid && !op.headline_fa){show('#ic-diagnosis','');return;}
    const service=safe(summary.service||'service');
    const path=safe(config.config_file||'');
    const loc=path+(Number.isInteger(config.error_line)?' · '+(fa?'خط ':'line ')+num(config.error_line):'')+
      (Number.isInteger(config.error_column)?' · '+(fa?'ستون ':'column ')+num(config.error_column):'');
    const jsonConfig=low(config.path_source)==='dotnet_config_syntax' ||
      /\.json$/i.test(path);
    const main=r.state_correlation?.conclusion_kind==='source_discrepancy'?
      safe(r.state_correlation.headline_fa):
      invalid?
      (jsonConfig?
        (fa?'خطای ساختار JSON در کانفیگ '+service+' تأیید شده است.':'Invalid JSON configuration was verified for '+service+'.'):
        (fa?'خطای سینتکس کانفیگ '+service+' تأیید شده است.':'Invalid configuration syntax was verified for '+service+'.')):
      op.headline_fa||'';
    const validatorNote=config.remote_python_required===false &&
      config.validator_location==='aiops_worker'?
      '<p class="ic-diagnosis-validator">'+esc(fa?
        'بررسی JSON روی سرور AIOps انجام شده است؛ نیازی به نصب Python روی VM برنامه نیست.':
        'JSON syntax was checked on the AIOps worker. No Python installation on the target VM is needed.')+'</p>':'';
    const diagnostic=invalid?
      '<p class="ic-diagnosis-location"><b>'+esc(fa?'محل خطای ثبت‌شده: ':'Recorded error: ')+
      '</b><span dir="auto">'+txt(loc)+'</span></p>'+
      (config.syntax_error?'<p><b>'+esc(fa?'نوع خطای JSON: ':'JSON syntax error: ')+
      '</b>'+txt(config.syntax_error)+'</p>':'')+
      '<p class="ic-diagnosis-caution">'+esc(fa?
        'این خطا در فایل بررسی‌شده ثبت شده است؛ ارتباط مستقیم آن با Timeout سرویس هنوز به بررسی لاگ راه‌اندازی برنامه نیاز دارد. علت نحوی فقط زمانی دقیق است که Validator کد/توضیح خطا را ثبت کرده باشد. هیچ تغییری در فایل انجام نشده است.':
        'The syntax issue is recorded by the validator; its precise causal link to the service timeout is not yet proven. No file was modified.')+'</p>'+
      (jsonConfig?renderCheckedJsonFiles(config):''):
      validJson?'<p class="ic-diagnosis-caution">'+esc(fa?
        'سینتکس فایل‌های JSON فهرست‌شده معتبر است؛ این نتیجه سلامت Runtime یا وابستگی‌های برنامه را ثابت نمی‌کند.':
        'Syntax passed for the listed JSON files; runtime and dependencies remain unverified.')+'</p>'+
        renderCheckedJsonFiles(config):'';
    const facts=output.slice(0,5).map(item=>'<li>'+txt(item.text_fa)+
      refs(item.evidence_refs)+'</li>').join('');
    const items=(rows,max)=>'<ul class="ic-diagnosis-bullets">'+rows.slice(0,max).map(x=>
      '<li>'+txt(x)+'</li>').join('')+'</ul>';
    // Old LLM interpretations can contradict a newer, real config validator.
    // Never elevate those interpretations above a verified syntax failure.
    const conflicting=invalid?agents.filter(agent=>{
      const texts=[agent.finding,...arr(agent.findings)].filter(x=>typeof x==='string');
      return texts.some(sentence=>
        /(?:configuration|config|JSON).{0,85}(?:fully valid|is valid|has passed|passed|successfully validated|healthy)|(?:all|the|application) (?:config(?:uration)?|JSON) (?:files? )?(?:is |are )?(?:valid|correct|passed)/i.test(sentence) &&
        !/invalid|not valid|failed|unverified|cannot|only.*runtimeconfig/i.test(sentence));
    }):[];
    const conflicts=conflicting.length?
      '<p class="ic-diagnosis-conflict"><strong>'+esc(fa?'تناقض در تحلیل ایجنت‌ها: ':'Agent analysis conflict: ')+
      '</strong>'+esc(fa?
        'بعضی ایجنت‌ها سالم‌بودن کانفیگ را مطرح کرده‌اند، ولی تست مستقیم JSON نامعتبر است. تشخیص معتبر ابزار بر تحلیل ایجنت اولویت دارد.':
        'Some agents claimed configuration success, but the direct JSON validation failed. Live validator evidence takes precedence.')+
      '</p>':'';
    const blocked=noProposedAction(r);
    const decision=invalid?
      (fa?'تا رفع خطای کانفیگ و موفقیت تست مجدد، Start ایمن تأیید نشده است؛ هر تغییر و اجرای بعدی نیازمند فرایند مجوز مستقل است.':
        'A safe Start is not validated until configuration is repaired and rechecked; separate authorization is required.'):
      blocked?
      (fa?'در حال حاضر عملیات اجرایی قابل تأییدی ثبت نشده است؛ ابتدا باید بررسی‌های باقی‌مانده کامل شوند.':
        'No executable action is currently available; outstanding checks are needed.'):
      (fa?'یک اقدام مشروط پیشنهاد شده است؛ برای اجرا همچنان کنترل‌های ایمنی و تأیید اپراتور ضروری است.':
        'A conditional action exists, subject to preflight and operator approval.');
    const existing=invalid ? [
      fa?'بررسی خط گزارش‌شده و خط قبل، بدون نمایش Secretها و مقادیر کانفیگ.':'Inspect the reported line and preceding structure without exposing secrets.',
      fa?'اصلاح کنترل‌شده، سپس تست دوبارهٔ JSON و بررسی لاگ Startup.':'Governed repair, JSON revalidation and startup log check.',
      fa?'بعد از تست موفق و بررسی پیش‌شرط‌ها، پیشنهاد Start سرویس با Approval جداگانه.':'Only after validation, consider separately approved Start.',
    ]:next;
    show('#ic-diagnosis','<article class="ic-diagnosis-report" data-state="'+esc(kind)+'">'+
      '<div class="ic-diagnosis-head"><span class="ic-diagnosis-mark" aria-hidden="true">'+
      (invalid?'!':'i')+'</span><div><small>'+esc(fa?'نتیجهٔ اصلی بررسی AIOps':'AIOps investigation result')+
      '</small><h3>'+txt(main)+'</h3></div></div>'+
      diagnostic+validatorNote+nginxCandidateReadiness(r)+
      '<section><h4>'+esc(fa?'چه چیزی واقعاً بررسی و تأیید شده؟':'Confirmed from actual checks')+'</h4>'+
      (facts?'<ul class="ic-diagnosis-bullets">'+facts+'</ul>':
        '<p>'+esc(fa?'یافتهٔ مستقل کافی در این گزارش ثبت نشده است.':'No sufficient independent evidence.')+'</p>')+'</section>'+
      conflicts+
      (unresolved.length?'<section><h4>'+esc(fa?'چه چیزی هنوز قطعی نیست؟':'What is still uncertain?')+
        '</h4>'+items(unresolved,3)+'</section>':'')+
      '<section><h4>'+esc(fa?'AIOps پیشنهاد می‌کند چه کار کنیم؟':'Recommended next checks')+
      '</h4>'+items(existing,4)+'</section>'+
      '<p class="ic-diagnosis-gate">'+esc(decision)+'</p>'+
      '<p class="ic-diagnosis-source">'+esc(fa?
        'این گزارش از شواهد ذخیره‌شدهٔ همین رخداد تهیه شده است؛ نمایش آن به معنی بررسی زندهٔ جدید یا اجرای تغییر نیست.':
        'This explanation uses recorded evidence, not a new live check or execution.')+
      '</p></article>');
  }

  // Evidence-first, operator-readable report. Never treats an MCP HTTP success as a
  // health assertion, a valid JSON file as working runtime, or coincidence as RCA.
  // Every dynamic field is escaped; actions stay behind the existing approval flow.
  function renderIntelligenceReport(r) {
    const node=$('#ic-intelligence-report');
    if(!node)return;
    const fa=state.language==='fa', i=r.incident_summary||{},
      t=r.technical_investigation||{},op=r.operator_explanation||{},
      domains=arr(t.domains),rca=t.rca||{}, config=r.configuration_diagnostic||{};
    const domain=key=>domains.find(x=>x.key===key)||{};
    const sys=domain('systemd'),disk=domain('disk');
    const statusEvidence=arr(sys.evidence).find(x=>x.tool==='service_status')||{};
    const facts=statusEvidence.facts||{};
    const stopped=['failed','inactive'].includes(low(facts.active_state));
    const running=low(facts.active_state)==='active';
    const sysFresh=statusEvidence.freshness==='fresh';
    const title=stopped&&sysFresh?
      (fa?'توقف سرویس از طریق Systemd تأیید شده است.':'Systemd confirmed the stopped service.'):
      running&&sysFresh?
      (fa?'سرویس هنگام بررسی Systemd فعال بوده است؛ سلامت HTTP هنوز مستقل است.':
        'Systemd was active at observation time; HTTP health is independent.'):
      (fa?'وضعیت فعلی سرویس باید دوباره با شواهد مستقیم بررسی شود.':
        'Current service state requires a fresh direct check.');
    const followup=r.followup_analysis||{};
    const followupMarkup=followup.status&&followup.status!=='not_requested'?
      '<div class="ic-ir-recovery"><h4>'+
      esc(fa?'نتیجهٔ بررسی‌های تکمیلی اپراتور':'Operator follow-up investigation')+
      '</h4><p>'+esc(fa?
        'این تحلیل پس از گفت‌وگوی رخداد با شواهد جدید به‌روزرسانی شده است؛ هیچ اقدام عملیاتی از این مسیر اجرا نمی‌شود.':
        'Analysis was updated from operator-requested evidence; this path never executes operations.')+
      '</p><p><strong>'+esc(fa?'وضعیت تحلیل: ':'Analysis: ')+
      '</strong>'+txt(followup.status)+' · '+
      esc(fa?'ایجنت‌های بازبینی‌کننده: ':'Specialists: ')+
      num(followup.agent_count||0)+'</p>'+
      '<p>'+txt(followup.decision_status||'')+'</p>'+
      (followup.knowledge_review_id?
        '<p>'+esc(fa?'دانش Cognia: پیش‌نویس در انتظار بررسی؛ هنوز منتشر نشده.':
        'Cognia: review draft, not published.')+
        ' <a href="/dashboard?view=knowledge&review='+
        encodeURIComponent(followup.knowledge_review_id)+'">'+
        esc(fa?'بازبینی دانش':'Review knowledge')+'</a></p>':
        '<p>'+esc(fa?'پیش‌نویس Cognia هنوز ایجاد نشده یا پیکربندی آن کامل نیست.':
        'Cognia review draft is not yet created or configured.')+'</p>')+
      refs([followup.evidence_ref].filter(Boolean))+'</div>':'';
    const stopOrigin=t.stop_origin||null;
    const stopExplanation=stopOrigin?
      '<div class="ic-ir-caution"><strong>'+esc(fa?
        'آیا سرویس دستی Stop شده است؟':'Was the service manually stopped?')+
      '</strong><p>'+txt(stopOrigin.note_fa)+'</p>'+
      (arr(stopOrigin.indicators).length?'<ul class="ic-ir-list">'+
        arr(stopOrigin.indicators).map(x=>'<li><code dir="auto">'+txt(x)+'</code></li>').join('')+
      '</ul>':'')+
      '<p><strong>'+esc(fa?'برای اثبات: ':'To verify: ')+
      '</strong>'+txt(stopOrigin.next_check_fa)+'</p>'+
      refs(stopOrigin.evidence_refs)+'</div>':'';
    const causeConfirmed=rca.cause_confirmed===true;
    const hasDirect=arr(sys.evidence).length>0;
    const snapshotNote=fa?
      'این گزارش از شواهد ذخیره‌شدهٔ اینسیدنت ساخته شده، نه بررسی زندهٔ جدید. HTTP 200 یک MCP به‌تنهایی اثبات سلامت برنامه یا وجود نتیجه نیست.':
      'This report uses persisted incident evidence, not a new live check. MCP HTTP 200 alone proves neither application health nor query results.';
    const list=(items,kind='')=>items.length?
      '<ul class="ic-ir-list '+esc(kind)+'">'+items.map(x=>'<li>'+x+'</li>').join('')+'</ul>':
      '<p class="ic-ir-empty">'+esc(fa?'شواهد قابل استنادی در این بخش ثبت نشده است.':'No attributable evidence was recorded for this section.')+'</p>';
    const unique=(rows,limit=6)=>{
      const found=new Set();
      return rows.filter(row=>{
        if(!row||!row.text)return false;
        const key=row.text.trim().toLowerCase();
        if(found.has(key))return false;
        found.add(key);return true;
      }).slice(0,limit);
    };
    const confirmed=unique([
      ...arr(op.confirmed_findings).filter(x=>x&&x.text_fa).map(x=>({text:x.text_fa,ids:x.evidence_refs})),
      ...arr(rca.confirmed_facts).filter(x=>x&&x.text).map(x=>({text:x.text,ids:x.evidence_refs}))
    ],6);
    const factsHtml=list(confirmed.map(x=>'<span>'+txt(x.text)+'</span>'+refs(x.ids)));
    const hypotheses=arr(rca.likely_hypotheses).slice(0,3).map(x=>
      '<strong>'+txt(x.title)+'</strong><p>'+
      txt(x.kind|| (fa?'فرضیه؛ تأیید نشده':'Unconfirmed hypothesis'))+'</p>'+
      (x.check?'<small>'+esc(fa?'آزمایش لازم: ':'Required check: ')+txt(x.check)+'</small>':'')+
      refs(x.supporting));
    const unknowns=unique([
      ...arr(op.uncertainties_fa).map(x=>({text:x})),
      ...arr(rca.remaining_unknowns).map(x=>({text:[x.domain,x.reason].filter(Boolean).join(' — ')}))
    ],5);
    const steps=unique([
      ...arr(op.next_steps_fa).map(x=>({text:x})),
      ...arr(t.actions?.read_only).map(x=>({text:x.expected||x.goal}))
    ],5);
    const domainLabels={systemd:fa?'Systemd و وضعیت سرویس':'Systemd service',
      disk:fa?'فضای ذخیره‌سازی':'Disk',journal:fa?'Journal و خطاهای سیستم':'System journal',
      elastic:'Elasticsearch',monitoring:fa?'Prometheus / Zabbix':'Prometheus / Zabbix',
      resources:'CPU / RAM',network:'Network / Port',config:fa?'فایل‌های تنظیمات':'Configuration'};
    const labels={
      investigated:fa?'بررسی‌شده':'Investigated',
      queried_with_results:fa?'نتیجه ثبت شده':'Results recorded',
      queried_zero_results:fa?'Query موفق؛ صفر نتیجه':'Query returned zero results',
      not_queried:fa?'بدون شاهد ثبت‌شده':'No recorded evidence',
      partial:fa?'بررسی ناقص':'Partial',query_failed:fa?'Query ناموفق':'Query failed',
      stale:fa?'شواهد قدیمی':'Stale',not_applicable:fa?'قابل اعمال نیست':'Not applicable'};
    const statuses=['systemd','disk','journal','elastic','monitoring','resources','network','config']
      .map(key=>domain(key)).filter(d=>d.key).map(d=>{
        const label=labels[d.status]||d.status||'not_recorded';
        const evidenceIds=arr(d.evidence).map(e=>e.id).filter(Boolean);
        const monitoringBreakdown=d.key==='monitoring'
          ?['prometheus','zabbix'].map(source=>{
            const subset=arr(d.evidence).filter(e=>low(e.source)===source);
            const queries=subset.filter(e=>e.facts?.status==='queried' &&
              Number.isFinite(Number(e.facts?.result_count)));
            const matched=queries.reduce((count,e)=>count+Number(e.facts.result_count),0);
            if(!subset.length)return '';
            const message=queries.length?
              (fa?num(queries.length)+' استعلام ثبت‌شده؛ '+num(matched)+' نتیجه. '+
                (matched===0?'صفر نتیجه نشانهٔ سلامت سرویس نیست.':'نتایج باید از نظر ارتباط با سرویس بررسی شوند.'):
                queries.length+' queries, '+matched+' results. Zero results do not prove health.'):
              (fa?num(subset.length)+' شاهد ثبت‌شده؛ نتیجهٔ Query به‌طور مستقل مشخص نیست.':
                subset.length+' records; query results not independently established.');
            return '<p class="ic-ir-provider"><strong>'+esc(source==='prometheus'?'Prometheus':'Zabbix')+
              ':</strong> '+esc(message)+'</p>';
          }).join('')
          :'';
        const bigFiles=d.key==='disk'
          ?arr(d.evidence).flatMap(e=>arr(e.facts?.largest_log_files)).slice(0,6)
          :[];
        const largest=bigFiles.length?
          '<div class="ic-ir-large-files"><strong>'+esc(fa?
          'بزرگ‌ترین فایل‌های ثبت‌شده (نه مجوز حذف):':'Largest recorded files (not safe-to-delete advice):')+
          '</strong><ul>'+bigFiles.map(x=>'<li><code dir="ltr">'+
          txt(x.path)+'</code> · '+num(x.size_bytes)+' bytes</li>').join('')+
          '</ul></div>':'';

        return '<article class="ic-ir-source"><header><strong>'+esc(domainLabels[d.key]||d.title)+
          '</strong><span class="ic-ir-source-state" data-result="'+esc(d.status||'unknown')+'">'+
          esc(label)+'</span></header><p>'+txt(d.technical_result||d.missing_reason)+'</p>'+
          (d.missing_reason?'<small>'+txt(d.missing_reason)+'</small>':'')+
          monitoringBreakdown+
          largest+
          (d.observed_at?'<small>'+esc(fa?'آخرین مشاهده: ':'Last observation: ')+esc(date(d.observed_at))+'</small>':'')+
          refs(evidenceIds)+'</article>';
      }).join('');
    const checked=arr(config.files).filter(x=>x&&x.file);
    const validated=checked.map(x=>{
      const path=x.path_verified && x.path?x.path:x.file;
      return '<li><code dir="ltr">'+esc(path)+'</code> — '+txt(x.status)+'</li>';
    });
    const diagnosis=low(config.status)==='invalid'?
      (fa?'در فایل تنظیمات خطای سینتکس ثبت شده؛ ارتباط علّی با توقف سرویس نیازمند لاگ Startup است.':
        'Configuration syntax error recorded; causality still requires startup logs.'):
      checked.length?
      (fa?'فقط ساختار JSON فایل‌های زیر بررسی شده؛ سلامت Runtime و صحت مقادیر کانفیگ تأیید نشده است.':
        'Only JSON syntax was tested for the files below; runtime health and config semantics remain unverified.'):
      '';
    const knowledge=r.cognia_knowledge||{},accepted=Number(knowledge.accepted_count),
      rejected=Number(knowledge.rejected_count);
    const knowledgeLine=Number.isFinite(accepted)&&Number.isFinite(rejected)?
      (fa?'اسناد مرتبط قابل استناد: '+num(accepted)+'؛ اسناد ردشده به‌دلیل نامرتبط بودن: '+num(rejected)+
        '. بازیابی نتیجهٔ خام به معنی استفاده از آن در RCA نیست.':
        'Relevant documents: '+accepted+'; rejected as unrelated: '+rejected+'. Retrieval does not prove RCA usage.'):
      (fa?'اثر دانش Cognia در این نتیجه بدون استناد مستقل تأیید نشده است.':
        'Cognia knowledge has no independently verified effect on this RCA.');
    const decision=rca.cause_confirmed===true?
      (fa?'علت ریشه‌ای در شواهد این گزارش تأیید شده است.':'The recorded report confirms a root cause.'):
      (fa?'علت ریشه‌ای هنوز تأیید نشده است. علائم و مشکلات هم‌زمان نباید بدون شاهد وابستگی علّی به هم نسبت داده شوند.':
        'Root cause remains unconfirmed. Coincident observations do not establish causality.');
    const recovery=r.recovery_advisory||{};
    const recoveryCandidate=recovery.suggested_action;
    const recoveryMarkup=recovery.status?
      '<div class="ic-ir-recovery"><h4>'+esc(fa?
        'پیشنهاد بازیابی سرویس (بدون مجوز اجرا)':'Service recovery options (not authorized)')+
        '</h4><p><strong>'+esc(fa?'اقدام پیشنهادی فعلی: ':'Current candidate: ')+
        '</strong>'+esc(recoveryCandidate==='restart_service'?'Restart':
          recoveryCandidate==='start_service'?'Start':
          fa?'ابتدا اصلاح مشکل کانفیگ':'Fix configuration first')+'</p>'+
        (arr(recovery.alternative_actions).length?
          '<ul class="ic-ir-list">'+arr(recovery.alternative_actions).slice(0,3).map(x=>
            '<li><strong>'+txt(x.action)+'</strong> — '+
            esc(x.status==='alternative_not_runbook_authorized_for_failed'?
              (fa?'گزینهٔ جایگزین؛ Runbook فعلی برای failed هنوز اجازهٔ Start نمی‌دهد.':
                'Alternative only: current runbook does not authorize Start for failed state.'):
              (fa?'مشروط به بررسی زنده و Approval جداگانه':'Requires fresh checks and separate approval'))+
            '</li>').join('')+'</ul>':'')+
        '<p>'+esc(fa?'کانفیگ: ':'Configuration: ')+txt(recovery.configuration_validation)+
        ' · '+esc(fa?'وضعیت مشاهده‌شده: ':'Observed: ')+txt(recovery.observed_state)+'</p>'+
        '<h4>'+esc(fa?'پیش‌شرط‌های بررسی و بازیابی':'Recovery preflight checklist')+'</h4>'+
        list(arr(recovery.prerequisite_checks).slice(0,8).map(txt))+
        '<p class="ic-ir-guard">'+esc(fa?
          'برای Start یا Restart ابتدا باید توقف عمدی/نگهداری، سلامت کانفیگ و تأثیر روی سرویس‌های وابسته بررسی شود. هیچ اقدامی اجرا نشده است.':
          'Confirm intent, configuration, dependencies and policy before restoring service. Nothing has been executed.')+
        '</p>'+refs(recovery.evidence_refs)+
        '<button type="button" class="ic-btn ic-btn-muted" data-incident-chat-prompt="plan">'+
        esc(fa?'با LLM برنامهٔ عیب‌یابی بساز':'Ask AI for a diagnostic plan')+
        '</button> <button type="button" class="ic-btn ic-btn-muted" data-incident-chat-prompt="start">'+
        esc(fa?'گزینه‌های Start/Restart را بررسی کن':'Discuss Start / Restart options')+
        '</button></div>':'';
    const enhanced=state.narrative, enhancedValid=!state.historic &&
      enhanced?.status==='available' && enhanced.snapshot_id===r.snapshot_id &&
      enhanced.language===state.language;
    const interpretation=enhancedValid?arr(enhanced.sections)
      .filter(x=>typeof x.text==='string'&&x.text.trim())
      .slice(0,11).map(x=>'<strong>'+txt(x.heading)+'</strong><p>'+
        txt(x.text)+'</p>'+refs(x.citations)):[];
    const legacyNote=fa?'متن تخصصی و گزارش کامل Agentها در جزئیات پایین قابل مشاهده است.':
      'Detailed findings and agent reports are available below.';
    const section=(title,body,extra='')=>'<section class="ic-ir-section '+extra+'"><h3>'+
      esc(title)+'</h3>'+body+'</section>';
    node.innerHTML='<article class="ic-ir" data-report-version="evidence-narrative-v1">'+
      '<header class="ic-ir-head"><span class="ic-ir-eyebrow">'+esc(fa?
        'گزارش هوشمندِ مبتنی بر شواهد':'Evidence-first incident intelligence')+
        '</span><h2>'+txt(title)+'</h2><p>'+esc(snapshotNote)+'</p>'+
        '<div class="ic-ir-meta"><span>'+esc(fa?'سرویس: ':'Service: ')+
        txt(i.service||t.service)+'</span><span>'+esc(fa?'میزبان: ':'Host: ')+
        txt(t.host||i.host||i.target)+'</span><span>'+esc(fa?'نسخه شواهد: ':'Snapshot: ')+
        '<code dir="ltr">'+txt(r.snapshot_id)+'</code></span></div></header>'+
      section(fa?'۱. چه اتفاقی افتاده است؟':'1. What happened',
        '<p>'+txt(op.headline_fa||i.summary||title)+'</p>'+
        (hasDirect?'<p>'+esc(fa?'Systemd ثبت کرده: ':'Systemd recorded: ')+
          '<code dir="ltr">'+esc('ActiveState='+String(facts.active_state??'?')+
          '; Result='+String(facts.result??'?')+'; MainPID='+String(facts.main_pid??'?'))+
          '</code>'+refs([statusEvidence.id].filter(Boolean))+'</p>':'')+
        (r.state_correlation?.conclusion_kind==='source_discrepancy'?
          '<p class="ic-ir-caution">'+txt(r.state_correlation.headline_fa)+'</p>':''))+
      section(fa?'۲. چه شواهدی واقعاً تأیید شده‌اند؟':'2. Confirmed observations',factsHtml)+
      section(fa?'۳. ابزارهای MCP دقیقاً چه نتیجه‌ای داده‌اند؟':'3. MCP result quality',
        '<div class="ic-ir-sources">'+statuses+'</div>')+
      (diagnosis?section(fa?'۴. دقیقاً کدام فایل تنظیمات بررسی شد؟':'4. Configuration check',
        '<p>'+esc(diagnosis)+'</p>'+list(validated)):'')+
      section(fa?'۵. علت قطعی است یا فرضیه؟':'5. RCA certainty',
        '<p class="ic-ir-caution">'+esc(decision)+'</p>'+
        followupMarkup+
        stopExplanation+
        (hypotheses.length?list(hypotheses):'<p>'+esc(fa?'فرضیهٔ مستند مستقلی ثبت نشده است.':'No supported independent hypothesis recorded.')+'</p>'))+
      section(fa?'۶. چه شواهدی کم داریم؟':'6. Missing evidence',
        list(unknowns.map(x=>txt(x.text))))+
      section(fa?'۷. اقدام بعدی اپراتور':'7. Next operator checks',
        recoveryMarkup+list(steps.map(x=>txt(x.text)))+
        '<p class="ic-ir-guard">'+esc(fa?
        'این گزارش Read-only است. هیچ Restart، حذف فایل یا تغییر کانفیگ بدون Approval و Verification مجاز نیست.':
        'Read-only: restart, file deletion and config changes require governed approval and verification.')+'</p>')+
      section(fa?'۸. دانش سازمانی و میزان اتکا':'8. Knowledge provenance',
        '<p>'+esc(knowledgeLine)+'</p>')+
      (interpretation.length?section(fa?'۹. تحلیل تکمیلی مدل با ارجاع':'9. Grounded AI explanation',
        '<p class="ic-ir-caution">'+esc(fa?
        'این بخش تفسیر مدل از شواهد است، نه تأیید مستقل علت؛ نتایج مستقیم MCP اولویت دارند.':
        'Model interpretation is not independent RCA confirmation; direct MCP evidence takes precedence.')+
        '</p>'+list(interpretation)):
        (state.narrative&&!state.historic?
          section(fa?'۹. وضعیت تحلیل مدل':'9. AI analysis status',
            '<p>'+esc(fa?
            'مدلِ تحلیل علت ریشه‌ای (RCA) در این Snapshot خروجی ساخت‌یافته و قابل‌استناد تولید نکرده است. این وضعیت به معنی شکست LLM در درخواست مستقل اصلاح فایل کانفیگ نیست؛ نتیجهٔ آن در بخش «اصلاح کانفیگ» نمایش داده می‌شود.':
            'The RCA analysis model did not return validated structured analysis in this snapshot. This does not mean the separate full-config repair LLM call failed; see the configuration repair section.')+
            ' · '+txt(state.narrative.reason||'model_unavailable')+'</p>'):'') )+
      '<footer class="ic-ir-footer">'+esc(legacyNote)+'</footer></article>';
  }

  function renderTechnicalInvestigation(r) {
    const investigation=r.technical_investigation;
    if(!investigation){show('#ic-technical-report','');return false;}
    const fa=state.language==='fa';
    const h=(fa?'نتیجهٔ بررسی‌های تخصصی':'Technical investigation results');
    const fmtFacts=facts=>Object.entries(facts||{}).map(([key,v])=>
      '<div class="ic-sre-fact"><b>'+esc(key)+'</b><code dir="auto">'+
      esc(typeof v==='object'?JSON.stringify(v):String(v))+'</code></div>').join('');
    const evidences=items=>arr(items).map(e=>
      '<article class="ic-sre-evidence"><div><strong>'+esc(e.tool||e.source)+'</strong> · '+
      esc(e.observed_at?date(e.observed_at):'Timestamp unavailable')+
      ' · '+esc(e.freshness||'unknown')+'</div>'+
      '<small>Evidence ID: '+esc(e.id||'not recorded')+'</small>'+
      '<div class="ic-sre-facts">'+fmtFacts(e.facts)+'</div></article>').join('');
    const rows=arr(investigation.domains).map(d=>
      '<tr><td><strong>'+esc(d.title)+'</strong><details class="ic-sre-drilldown"><summary>'+
      esc(fa?'شناسه شواهد و خروجی فنی':'Evidence and technical facts')+
      ' ('+num(arr(d.evidence).length)+')</summary>'+
      (arr(d.evidence).length?evidences(d.evidence):'<p>'+
      esc(d.missing_reason||d.collection_hint||'No recorded data')+'</p>')+
      '</details></td><td>'+pill(d.status)+'</td><td><p>'+esc(d.technical_result)+'</p>'+
      (d.missing_reason?'<small>'+esc(d.missing_reason)+'</small>':'')+
      '</td><td>'+esc(d.importance)+'</td><td>'+
      esc(d.observed_at?date(d.observed_at):'ثبت نشده')+'</td><td>'+
      esc(d.source)+'</td></tr>').join('');
    const rca=investigation.rca||{};
    const facts=arr(rca.confirmed_facts).map(x=>
      '<li>'+esc(x.text)+refs(x.evidence_refs)+'</li>').join('');
    const theories=arr(rca.likely_hypotheses).map(x=>
      '<article class="ic-sre-theory"><strong>'+esc(x.title)+'</strong>'+
      '<p>'+esc(x.kind||'')+'</p>'+
      '<p>'+esc(fa?'آزمایش تفکیکی: ':'Discriminating check: ')+esc(x.check)+'</p>'+
      (arr(x.supporting).length?refs(x.supporting):'')+
      '<small>'+esc(fa?'شواهد مخالف: ':'Opposing refs: ')+
      esc(arr(x.opposing).length?x.opposing.join(', '):'ثبت نشده')+'</small></article>').join('');
    const unknowns=arr(rca.remaining_unknowns).map(x=>
      '<li><strong>'+esc(x.domain)+'</strong> — '+esc(x.reason)+
      '<p>'+esc(x.next_check)+'</p></li>').join('');
    const acts=investigation.actions||{};
    const actionCards=items=>arr(items).map((a,index)=>
      '<article class="ic-sre-action"><strong>'+num(index+1)+'. '+esc(a.title)+'</strong>'+
      '<p>'+esc(a.goal)+'</p><p><b>Tool:</b> '+esc(a.tool)+
      ' · <b>Prerequisite:</b> '+esc(a.prerequisite)+'</p>'+
      '<p>'+esc(a.expected)+'</p><p>'+esc(a.if_positive)+
      ' / '+esc(a.if_negative)+'</p>'+
      '<small>'+esc(a.approval_required?'Approval REQUIRED':'Read-only — no execution')+
      ' · '+esc(a.status)+'</small></article>').join('');
    const lines=arr(investigation.executive_lines).slice(0,7).map(x=>'<li>'+esc(x)+'</li>').join('');
    show('#ic-technical-report','<details class="ic-diagnosis-drilldown"><summary>'+
      esc(fa?'گزارش کامل فنی و ممیزی (اختیاری)':'Full technical report and audit (optional)')+
      '</summary><div class="ic-diagnosis-drilldown-body">'+
      '<section class="ic-sre-assessment" aria-label="Executive Incident Assessment">'+
      '<h3>'+esc(fa?'جمع‌بندی تخصصی اولیه':'Executive Incident Assessment')+'</h3><ol>'+lines+'</ol>'+
      '<p class="ic-headline-caution">'+esc(fa?
      'این نتایج از Evidence ثبت‌شده استخراج شده‌اند؛ گزارش‌گیری به معنی بررسی زندهٔ مجدد نیست.':
      'This is persisted evidence, not a fresh live check.')+'</p></section>'+
      '<section class="ic-sre-audit"><h3>'+esc(h)+'</h3>'+
      '<div class="ic-sre-table-wrap"><table class="ic-sre-table"><thead><tr>'+
      ['حوزه','وضعیت بررسی','نتیجه فنی','اهمیت','زمان','منبع'].map(x=>'<th>'+esc(x)+'</th>').join('')+
      '</tr></thead><tbody>'+rows+'</tbody></table></div></section>'+
      '<section class="ic-sre-rca"><h3>Root Cause Analysis</h3>'+
      '<h4>Confirmed Facts</h4>'+(facts?'<ul>'+facts+'</ul>':empty(fa?'علت ریشه‌ای تأییدنشده است.':'No root cause confirmed.'))+
      '<h4>Likely Hypotheses &amp; Discriminating Checks</h4>'+
      (theories||empty(fa?'فرضیهٔ مستند برای علت اصلی ثبت نشده است.':'No supported hypothesis.'))+
      '<h4>Ruled-out Hypotheses</h4>'+
      (arr(rca.ruled_out).length?arr(rca.ruled_out).map(x=>'<p>'+esc(x)+'</p>').join(''):
      '<p>'+esc(fa?'فرضیه‌ای با شاهد مستقل رد نشده است.':'No hypothesis has been ruled out by independent evidence.')+'</p>')+
      '<h4>Remaining Unknowns</h4>'+
      (unknowns?'<ul>'+unknowns+'</ul>':empty(fa?'شکاف بررسی ثبت نشده است.':'No recorded gaps.'))+
      (arr(investigation.conflicts).length?
        '<h4>'+esc(fa?'تعارض بین منابع':'Source contradictions')+'</h4>'+
        arr(investigation.conflicts).map(x=>
          '<article class="ic-sre-theory"><strong>'+esc(x.description)+'</strong>'+
          '<p>'+esc(x.resolution)+'</p>'+refs(x.evidence_refs)+'</article>').join(''):'')+
      '<p class="ic-headline-caution">'+esc(rca.note)+'</p></section>'+
      '<section class="ic-sre-actions"><h3>'+esc(fa?'الان SRE چه کاری انجام دهد؟':'SRE next actions')+'</h3>'+
      '<h4>'+esc(fa?'فوری و Read-only':'Immediate read-only')+'</h4>'+
      (actionCards(acts.read_only)||empty(fa?'اقدام Read-only جدیدی پیشنهاد نشده است.':'No additional read-only checks.'))+
      '<h4>'+esc(fa?'مشروط و نیازمند Approval':'Conditional / Approval required')+'</h4>'+
      actionCards(acts.conditional)+
      '<h4>'+esc(fa?'ممنوع یا پرریسک':'Prohibited or high risk')+'</h4><ul>'+
      arr(acts.prohibited).map(x=>'<li>'+esc(x)+'</li>').join('')+'</ul></section>'+
      '</div></details>');
    return true;
  }

  function renderOverview(r) {
    const i=r.incident_summary||{},act=r.remediation_recommendation||{},a=r.approval_readiness||{};
    renderIntelligenceReport(r);
    renderOperationalSummary(r);
    renderOperatorDiagnosis(r);
    renderMemoryForensics(r);
    // Technical artifacts are supplementary. They must never hide the
    // plain-language verdict when a structured report is present.
    renderTechnicalInvestigation(r);
    if(r.memory_investigation){
      // Keep the RAM-specialized investigation, but retain the clear
      // operator explanation and the status/decision summary above it.
    }
    renderOperatorExplanation(r);
    const deterministic=plainLead(r);
    const n=state.narrative;
    const matched=n && n.snapshot_id===r.snapshot_id && n.language===state.language && !state.historic && n.status==='available';
    const narrative=matched?(
      '<div class="ic-grounded-narrative"><h3>'+esc(state.language==='fa'?
        'توضیح تکمیلی مبتنی بر شواهد (AI)':'Evidence-grounded AI explanation')+'</h3>'+
      arr(n.sections).filter(x=>['cause','evidence_gaps','advice'].includes(x.key)).map(x=>
        '<div class="ic-grounded-para"><strong>'+txt(x.heading)+'</strong><p>'+
          txt(x.text)+'</p>'+refs(x.citations)+'</div>').join('')+
      '<details class="ic-reveal"><summary>'+esc(state.language==='fa'?
        'مشاهدهٔ کل تحلیل و استنادها':'Full explanation and citations')+'</summary><div class="ic-reveal-content">'+
      arr(n.sections).filter(x=>!['cause','evidence_gaps','advice'].includes(x.key)).map(x=>
        '<article class="ic-detail-card"><h4>'+txt(x.heading)+'</h4><p>'+txt(x.text)+
        '</p>'+refs(x.citations)+'</article>').join('')+'</div></details></div>'
    ):'';
    show('#ic-brief-lead','<p>'+txt(deterministic)+'</p>'+original(i.likely_cause,'شرح علت احتمالی در گزارش اصلی')+narrative);
    show('#ic-key-answer',[
      fact('cause',humanCause(i.likely_cause)),fact('causeStatus',status(i.cause_status)),
      fact('serviceIdentity',status(i.service_identity?.status)),
      (i.service_identity?.suspected_service?fact('suspectedService',i.service_identity.suspected_service):''),
      fact('identityBasis',status(i.service_identity?.basis)),
      fact('action',noProposedAction(r)?(state.language==='fa'?'عملیاتی پیشنهاد نشده':'No proposed action'):humanAction(act.action)),
      fact('target',noProposedAction(r)?(i.target||state.serviceStatus?.target):act.target),
      ...(noProposedAction(r)?[]:[fact('tool',humanTool(act.tool))]),
      fact('freshness',status(r.data_freshness))
    ].join(''));
    const warnings=warningMessages(r);
    show('#ic-warning-list',warnings.length?warnings.map(x=>'<div class="ic-warning'+(x.critical?' critical':'')+'">'+esc(x.text)+'</div>').join('') :
      '<div class="ic-callout"><strong>'+esc(tr('evidenceRefs'))+'</strong><p>'+esc(tr('inspectSource'))+'</p></div>');
  }
  function renderReview(r) {
    const i=r.incident_summary||{},a=r.approval_readiness||{},x=r.remediation_recommendation||{};
    if(noProposedAction(r)){
      const fa=state.language==='fa';
      const disposition=r.presentation_context?.action_disposition;
      const reason=disposition==='blocked_by_evaluator'?
        (fa?'Evaluator به دلیل ناکافی‌بودن اطمینان یا شواهد، مجوز پیشنهاد اجرا صادر نکرده است.':
            'Evaluator blocked the operational action because its evidence or confidence gate did not pass.'):
        (fa?'در جریان تحلیل، اقدام اجرایی مشخصی پیشنهاد نشده است.':
            'The analysis did not produce an executable recommendation.');
      const isVm=knownServicePlatform(r)==='vm_systemd';
      show('#ic-proposal','<div class="ic-callout"><strong>'+esc(fa?
        'هیچ اقدام اجرایی تأیید نشده است':'No executable action authorized')+
        '</strong><p>'+esc(reason)+'</p></div><div class="ic-proposal">'+
        fact('host',i.target||state.serviceStatus?.target||i.host)+
        fact('risk',fa?'قابل ارزیابی نیست؛ اقدامی پیشنهاد نشده':'Not applicable; no action proposed')+
        fact('cluster',isVm?(fa?'قابل اعمال نیست؛ سرویس VM':'Not applicable to VM'):i.cluster)+
        fact('namespace',isVm?(fa?'قابل اعمال نیست؛ سرویس VM':'Not applicable to VM'):i.namespace)+
        fact('approval',state.lifecycle?.approval?.status==='pending_validation'
          ?(fa?'در صف Approval · منتظر اعتبارسنجی کانفیگ':'Queued for configuration validation')
          :(fa?'درخواستی ثبت نشده':'Not requested'))+'</div>');
      show('#ic-preconditions','<div class="ic-callout"><strong>'+esc(fa?'قدم بعدی':'Next step')+
        '</strong><p>'+esc(fa?
        'ابتدا وضعیت واقعی سرویس، HTTP Health و شواهد ناقص را بررسی کنید؛ اجرای تغییر نیازمند درخواست مجزا و Approval است.':
        'Review live service health and missing evidence; a change still requires a separate governed approval.')+
        '</p></div>');return;
    }
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
    // A confirmed "invalid_json_syntax" must never be translated into a
    // generic "configuration test passed" by signalFacts. Treat call success
    // and the actual JSON syntax result as entirely separate concepts.
    if(/invalid JSON syntax|JSON syntax (?:error|invalid)|invalid_json_syntax/i.test(x))
      return 'ایجنت وجود خطای ساختاری JSON در کانفیگ برنامه را گزارش کرده است؛ فایل، خط و نوع خطای قطعی در نتیجهٔ Validator آمده است.';
    // Contrary model statements are never shown as successful checks when a
    // dedicated .NET validator has explicitly failed on appsettings.json.
    if(low((state.historic||state.report)?.configuration_diagnostic?.status)==='invalid' &&
       !/invalid|not valid|failed|unverified|only.*runtimeconfig/i.test(x) &&
       (/\bvalid\s*=\s*true\b/i.test(x) ||
        /configuration (?:validation|check|syntax).*(?:passed|success|valid)/i.test(x) ||
        /(?:all|the|application) (?:config(?:uration)?|JSON) (?:files? )?(?:is |are )?(?:valid|correct|passed)/i.test(x)))
      return 'ادعای این ایجنت دربارهٔ سلامت کانفیگ با نتیجهٔ Validator معتبر مطابقت ندارد؛ آزمون فایل خطادار ناموفق بوده است.';
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
    if(/\bvalid\s*=\s*true\b/i.test(x) &&
       low((state.historic||state.report)?.configuration_diagnostic?.status)==='invalid')
      return 'ایجنت مقدار valid=true را ثبت کرده، اما این مقدار تأیید سلامت فایل خطادار نیست؛ آزمون اختصاصی کانفیگ نامعتبر گزارش شده است.';
    if(/(?:manual stop possible|manual(?:ly)? stop(?:ped)?(?: service)? is possible|A manual stop is possible but not proven)/i.test(x))
      return 'توقف دستی سرویس یک فرضیه است؛ عامل توقف و عمدی‌بودن آن هنوز تأیید نشده است.';
    if(/no confirmed domain fault yet/i.test(x))return 'با شواهد فعلی خرابی مستقلی در این حوزه تأیید نشده است.';
    if(/configuration (?:validation|check|syntax).*(?:success|passed|valid)/i.test(x) ||
       /(?:all|the|application) (?:config(?:uration)?|JSON) (?:files? )?(?:is |are )?(?:valid|correct|passed)/i.test(x)){
      if(state.report?.configuration_diagnostic?.status==='invalid')
        return 'این ایجنت سالم بودن کانفیگ را مطرح کرده، اما با خطای ثبت‌شدهٔ Validator تطابق ندارد؛ نتیجهٔ قطعی باید از ابزار بررسی کانفیگ گرفته شود.';
      return 'این ایجنت موفقیت تست کانفیگ را گزارش کرده است؛ نتیجه باید با خروجی مستقیم Validator مقایسه شود.';
    }
    if(/(?:agent|analysis|llm|model)\s+(?:response\s+)?(?:timed out|timeout|exceeded timeout)/i.test(x))
      return 'پاسخ این ایجنت یا مدل به علت Timeout کامل نشده است.';
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
        Number.isInteger(config.error_line)?(fa?'خط '+num(config.error_line):'line '+num(config.error_line)):null,
        Number.isInteger(config.error_column)?(fa?'ستون '+num(config.error_column):'column '+num(config.error_column)):null]
        .filter(Boolean).join(' — ');
      items.push('<article class="ic-config-check" data-config-status="invalid"><h3>'+
        esc(fa?'آخرین تست ثبت‌شده، خطای کانفیگ را نشان می‌دهد':'Recorded configuration syntax check failed')+'</h3>'+
        '<p><b>'+esc(fa?'محل خطا:':'Reported location:')+'</b> <span dir="auto">'+txt(location)+'</span></p>'+
        (config.syntax_error?'<p><b>'+esc(fa?'پیام ابزار بررسی سینتکس:':'Validator error:')+
          '</b> <span dir="auto">'+txt(config.syntax_error)+'</span></p>':'')+
        '<p>'+esc(fa?
          'در زمان ثبت این شواهد، تست سینتکس کانفیگ ناموفق بوده است. قبل از تغییر، وضعیت فایل و نسخه فعلی دوباره بررسی شود؛ سپس اصلاح کنترل‌شده و تست مجدد انجام شود. فقط بعد از موفقیت تست و گذر از گیت‌های ایمنی، Start سرویس برای تأیید اپراتور پیشنهاد می‌شود. علت توقف اولیه هنوز قطعی نیست.':
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
    } else if(kind==='json_syntax_valid') {
      items.push('<article class="ic-config-check" data-config-status="valid"><h3>'+
        esc(fa?'ساختار JSON فایل‌های دات‌نت بررسی شد':'Dotnet JSON syntax checked')+
        '</h3><p>'+esc(fa?'سینتکس فایل‌های فهرست‌شده معتبر است، اما صحت مقادیر تنظیمات، سلامت سرویس و امکان Start هنوز تأیید نشده است.':
          'Only listed JSON files passed syntax validation; runtime semantics and safe start remain unverified.')+
        '</p>'+renderCheckedJsonFiles(config)+refs(config.evidence_refs)+'</article>');
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
    const model=r?.dynamic_investigation?.config_llm_review||{};
    const fullRepair=r?.dynamic_investigation?.full_config_llm_repair||{};
    const hasNewerFullFileReview=fullRepair.status==='llm_candidate_proposed';
    if(model.status&&model.status!=='—'&&model.status!=='not_requested') {
      const observations=[
        [fa?'تشخیص اولیه مدل':'First model diagnosis',model.model_diagnosis],
        [fa?'بازبینی دوم مدل':'Second model review',model.model_second_review]
      ].filter(entry=>entry[1]?.error_kind&&entry[1].error_kind!=='—');
      const rows=observations.map(entry=>{
        const detail=entry[1];
        const pos=Number.isInteger(detail.line)?(fa?'، خط ':' , line ')+num(detail.line):'';
        return '<li><b>'+esc(entry[0])+'</b>: '+txt(detail.error_kind)+esc(pos)+
          '<div>'+txt(detail.reason||'')+'</div>'+
          (detail.suggestion?'<div>'+esc(fa?'پیشنهاد: ':'Suggestion: ')+
            txt(detail.suggestion)+'</div>':'')+'</li>';
      }).join('');
      items.push('<article class="ic-config-check" data-config-status="advisory">'+
        '<h3>'+esc(fa?'تحلیل و بازبینی کانفیگ با LLM':'LLM configuration syntax review')+
        '</h3><p>'+esc(fa?
          (hasNewerFullFileReview?
          'این نتیجهٔ قدیمی از نمای ساختاری محدود استخراج شده و مبنای اصلاح فایل کامل نیست؛ تشخیص‌هایی مانند تورفتگی ناهماهنگ در Nginx به‌تنهایی خطای نحوی را ثابت نمی‌کنند.':
          'این تحلیل فقط از نمای نحوی پالایش‌شده است، نه فایل کامل؛ فرضیه‌ها باید با خطای واقعی Validator سنجیده شوند و اجازهٔ اعمال نمی‌دهند.'):
        (hasNewerFullFileReview?
          'This is older, grammar-only advice and not the basis of the complete-file repair. Nginx indentation alone is not a syntax fault.':
          'The model analyzed only a value-free syntax projection. Its hypotheses require vendor validation and do not permit execution.'))+
        '</p>'+(rows?'<ul class="ic-agent-bullets">'+rows+'</ul>':
          '<p>'+txt(model.status)+'</p>')+'</article>');
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
      'این یافته‌ها مربوط به زمان تحلیل Incident هستند، نه لزوماً وضعیت فعلی سرویس. هر کارت نشان می‌دهد ایجنت چه داده‌ای دریافت کرده، چه نتیجه‌ای نوشته، چه فرضیه‌ای داشته و چه چیزی هنوز معلوم نیست. استناد به شواهد به معنی اجرای مستقیم ابزار توسط آن Agent نیست.':
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
        '<p class="ic-agent-peek">'+(directFindings.length?agentLine(directFindings[0]):
          a.finding?agentLine(a.finding):
          esc(fa?'یافتهٔ اختصاصی ثبت نشده است.':'No specific finding recorded.'))+'</p>'+
        '<details class="ic-agent-investigation"><summary>'+esc(fa?
          'نمایش بررسی‌ها، فرضیه‌ها و شواهد این ایجنت':'Show agent checks, hypotheses and evidence')+
        '</summary><div class="ic-agent-investigation-body">'+
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
        '</div></details></article>';
    });
    show('#ic-agents',cards.length?cards.join(''):empty(fa?'هنوز خروجی ایجنتی ثبت نشده است.':'No specialist result recorded.'));
  }
  function renderEvidence(r) {
    const sources=arr(r.monitoring_sources),mcp=arr(r.mcp_evidence),fa=state.language==='fa';
    show('#ic-sources',sources.length?sources.map(x=>'<article class="ic-source-card"><strong>'+txt(x.source)+'</strong>'+pill(x.status)+
      '<p>'+tr('freshness')+': '+txt(status(x.freshness))+'</p>'+
      (['error','unavailable'].includes(low(x.status))?'<p class="ic-warning">'+tr('sourceUnavailable')+'</p>':'')+'</article>').join(''):empty());
    const observations=mcp.map(x=>{
      const semantic=low(x.semantic_result);
      const label=semantic==='configuration_invalid'?(fa?'خطای کانفیگ تأیید شده':'Invalid configuration'):
        semantic==='configuration_valid_syntax_only'?(fa?'فقط سینتکس فایل معتبر است':'JSON syntax passed only'):null;
      return '<article class="ic-detail-card"><div class="ic-detail-head"><h4>'+
        txt(humanTool(x.server))+' / '+txt(humanTool(x.tool))+'</h4>'+
        (label?'<strong class="ic-semantic-diagnostic" data-invalid="'+(semantic==='configuration_invalid')+'">'+
          esc(label)+'</strong>':pill(x.status))+'</div>'+
        '<p>'+txt(semantic==='configuration_invalid'?
          (fa?'تست اختصاصی کانفیگ خطای سینتکس را تأیید کرده است؛ جزئیات فایل و خط در نتیجهٔ اصلی همین رخداد آمده است.':
            'The specialized configuration validator recorded a syntax failure.'):
          semantic==='configuration_valid_syntax_only'?
          (fa?'این تست فقط ساختار JSON فایل بررسی‌شده را معتبر دانسته، نه سلامت سرویس را.':
            'This validates only the checked JSON file syntax, not service health.'):
          plain(x.finding))+'</p>'+original(x.finding)+
        (label?'<p class="ic-agent-disclaimer">'+esc(fa?
          'موفق بودن فراخوانی MCP، سالم بودن تنظیمات سرویس را ثابت نمی‌کند.':
          'Tool call success is not evidence that application configuration is valid.')+'</p>':'')+
        '<div class="ic-meta">'+tr('sampleTime')+': '+txt(date(x.collected_at))+
        ' · '+tr('freshness')+': '+txt(status(x.freshness))+
        ' · '+tr('phase')+': '+txt(x.phase)+'</div>'+
        refs(x.evidence_ref?[x.evidence_ref]:[])+'</article>';
    });
    const important=[],remaining=[];
    mcp.forEach((x,i)=>{
      const priority=low(x.semantic_result)==='configuration_invalid' ||
        ['failed','error'].includes(low(x.status)) ||
        ['service_status','dotnet_config_syntax','config_validate','service_runtime_discovery'].includes(low(x.tool));
      (priority&&important.length<7?important:remaining).push(observations[i]);
    });
    const extra=remaining.length?'<details class="ic-evidence-rest"><summary>'+
      esc(fa?'مشاهدهٔ '+num(remaining.length)+' بررسی فنی دیگر':'Show '+remaining.length+' more technical results')+
      '</summary><div class="ic-evidence-rest-content">'+remaining.join('')+'</div></details>':'';
    show('#ic-mcp',mcp.length?important.join('')+extra:empty());
  }
  function renderKnowledge(r) {
    const k=r.cognia_knowledge||{},m=r.operational_memory||{},fa=state.language==='fa';
    const items=arr(k.items),accepted=items.length;
    const rejected=Number(k.rejected_count)||0;
    // Count admitted, attributable documents, not candidate chunks that
    // failed service/FQDN relevance checks.
    $('#ic-cognia-count').textContent=num(accepted)+(fa?' مرتبط':' matching');
    $('#ic-memory-count').textContent=num(m.retrieved_count||0);
    let note='';
    if(accepted){
      const experiences=items.filter(x=>x.document_kind==='historical_incident_experience').length;
      const cited=items.filter(x=>x.use_status==='cited_by_agent').length;
      note=(fa?
        'کاگنیا '+num(accepted)+' سند مرتبط برای این رخداد برگردانده است؛ '+num(experiences)+
        ' مورد صراحتاً سابقهٔ Incident مستند هستند. '+
        (cited?num(cited)+' سند در خروجی Agent مورد استناد قرار گرفته است. ':
          'هیچ‌یک در خروجی Agent مورد استناد قرار نگرفته‌اند. ')+
        'تأثیر این اسناد بر تصمیم نهایی بدون ردپای تصمیم‌گیری تأیید نیست.':
        'Cognia returned '+accepted+' admitted relevant documents, '+experiences+
        ' explicitly labeled historical incident records, and '+cited+
        ' cited by agents. Impact on the final decision is not verified.');
    }else if(low(k.status)==='filtered_empty'||rejected>0){
      note=fa?'هیچ سند مرتبط و قابل‌قبولی باقی نمانده است. '+num(rejected)+
        ' نتیجهٔ Cognia به دلیل عدم انطباق با سرویس یا محدودهٔ رخداد کنار گذاشته شده‌اند.':
        'No admitted matching documents. '+rejected+
        ' Cognia result(s) were excluded for service or incident scope mismatch.';
    }else if(['failed','error','unavailable','authentication_failed','forbidden'].includes(low(k.status))){
      note=fa?'جست‌وجوی Cognia ناموفق بوده است؛ این وضعیت به معنی نبود دانش مشابه نیست.':
        'Cognia lookup failed. This does not mean there is no matching knowledge.';
    }else if(low(k.status)==='not_queried'){
      note=fa?'برای این رخداد جست‌وجوی ثبت‌شده‌ای در Cognia وجود ندارد.':
        'No recorded Cognia search for this incident.';
    }else{
      note=fa?'جست‌وجوی Cognia نتیجهٔ مرتبط و قابل‌استنادی برای این رخداد ثبت نکرده است.':
        'Cognia has no admitted matching result for this incident.';
    }
    const counts=(rejected>0?'<p class="ic-meta">'+esc(fa?
      'اسناد ردشده در فیلتر ارتباط با رخداد: ':'Rejected by relevance gate: ')+num(rejected)+'</p>':'');
    const rejectedExamples=!accepted&&rejected?arr(k.rejected_examples).slice(0,6).map(x=>
      '<div class="ic-cognia-rejected"><strong>'+esc(fa?'سند کنارگذاشته‌شده':'Excluded result')+
      '</strong> '+code(x.source_id)+
      '<p>'+esc(fa?'علت: ':'Reason: ')+txt(x.reason)+
      (arr(x.declared_services).length?' · '+esc(fa?'سرویس سند: ':'Document service: ')+
        txt(arr(x.declared_services).join(', ')):'')+'</p></div>').join(''):'';
    const summary='<div class="ic-callout"><strong>'+txt(status(k.status||'not_queried'))+
      '</strong><p>'+esc(note)+'</p>'+counts+
      (!accepted&&k.error_code?'<p class="ic-meta">'+esc(fa?'کد خطا: ':'Error code: ')+
      code(k.error_code)+'</p>':'')+'</div>';
    const docs=items.map(x=>{
      const history=x.document_kind==='historical_incident_experience';
      const name=x.title||(history?
        (fa?'سابقهٔ رخداد '+(x.previous_incident_id||''):'Incident record '+(x.previous_incident_id||'')):
        (fa?'سند Cognia #'+(x.knowledge_id||x.source_id||'بدون عنوان'):
            'Cognia document #'+(x.knowledge_id||x.source_id||'untitled')));
      const facts=[
        [fa?'سرویس سند':'Document service',x.document_service],
        ...(history?[
          [fa?'رخداد قبلی':'Previous incident',x.previous_incident_id],
          [fa?'الگوی علامت':'Observed symptom',x.symptom_pattern],
          [fa?'وضعیت علت ریشه‌ای':'Historical RCA status',x.root_cause_status],
          [fa?'اقدام انجام‌شده در گذشته':'Historical action',x.historical_action],
          [fa?'راستی‌آزمایی گذشته':'Historical verification',x.verification_status],
          [fa?'نتیجهٔ گذشته':'Historical outcome',x.historical_outcome],
          [fa?'درس آموخته‌شده':'Reusable lesson',x.reusable_lesson],
        ]:[])
      ].filter(x=>x[1]!==null&&x[1]!==undefined&&x[1]!=='');
      const lesson=facts.length?'<dl class="ic-cognia-details">'+facts.map(([label,v])=>
        '<div><dt>'+esc(label)+'</dt><dd>'+txt(v)+'</dd></div>').join('')+'</dl>':'';
      return '<article class="ic-detail-card ic-cognia-match"><div class="ic-detail-head"><h4>'+
        txt(name)+'</h4><span class="ic-tag">'+esc(history?
          (fa?'سابقهٔ Incident مستند':'Recorded incident experience'):
          (fa?'مستند مرتبط':'Relevant knowledge document'))+'</span></div>'+
        '<p>'+esc(fa?'نوع ارتباط: ':'Relevance: ')+
        esc(history?(fa?'تجربهٔ قبلی منتشرشده؛ علت فعلی را ثابت نمی‌کند.':
          'Published incident experience, not proof of current cause.'):
          (fa?'سند دارای مالکیت یا محدودهٔ معتبر برای سرویس؛ لزوماً تجربهٔ حل مشکل نیست.':
          'Service-scoped document; not necessarily a previous recovery experience.'))+'</p>'+
        lesson+
        '<p class="ic-cognia-excerpt">'+txt(truncate(x.excerpt,500))+'</p>'+
        original(truncate(x.excerpt,1600),fa?'متن بازیابی‌شده از Cognia':'Original Cognia excerpt')+
        '<p class="ic-meta">'+esc(fa?'امتیاز تطبیق جست‌وجو: ':'Retrieval relevance score: ')+
        esc(numberPct(x.relevance))+
        ' · KB '+txt(x.knowledge_base_id)+
        ' · Knowledge '+txt(x.knowledge_id)+
        ' · Revision '+txt(x.revision_id)+
        ' · Chunk '+txt(x.chunk_id)+'</p>'+
        '<p class="ic-meta">'+esc(fa?'زمان بازیابی: ':'Retrieved at: ')+txt(date(x.retrieved_at))+
        ' · '+esc(x.use_status==='cited_by_agent'?
          (fa?'Agent به این سند استناد کرده':'Cited by an agent'):
          (fa?'استناد Agent ثبت نشده':'No agent citation recorded'))+
        ' · '+esc(fa?'اثر بر تصمیم نهایی: تأییدنشده':'Final decision impact: not traced')+'</p>'+
        refs(x.source_id?[x.source_id]:[])+'</article>';
    }).join('');
    show('#ic-cognia',summary+rejectedExamples+docs);
    show('#ic-memory','<div class="ic-callout"><strong>'+tr('knowledgeNotProof')+'</strong></div>'+
      (arr(m.items).length?arr(m.items).map(x=>'<article class="ic-detail-card"><div class="ic-detail-head"><h4>'+
        txt(state.language==='fa'?'تجربه رخداد قبلی':x.memory_id)+'</h4>'+pill(x.use_status)+'</div><p>'+txt(previousExperience(x,"memory"))+'</p>'+original(truncate(x.root_cause,1000))+
        '<div class="ic-meta">'+tr('action')+': '+txt(humanAction(x.action))+' · '+tr('verification')+': '+txt(status(x.verification))+
        ' · '+tr('result')+': '+txt(status(x.outcome))+' · '+tr('confidence')+': '+esc(numberPct(x.similarity))+'</div>'+
        refs(x.previous_incident_id?[x.previous_incident_id]:[])+'</article>').join(''):empty()));
  }
  // The source proposal is evidence-bound and review-only. A browser may
  // request an audit entry for separate validation; it cannot apply a patch.
  function renderConfigActionBanner(r) {
    const node=$('#ic-config-action-banner');
    if(!node)return;
    const fa=state.language==='fa';
    const service=low(r?.incident_summary?.service).replace(/\.service$/,'');
    const investigation=r?.dynamic_investigation||{};
    const config=investigation.config_proposal||{};
    const fullRepair=investigation.full_config_llm_repair||{};
    const repairAttention=investigation.config_repair_attention||{};
    const repairFailure=['llm_repair_timeout','llm_repair_unavailable',
      'llm_response_truncated','llm_complete_file_response_invalid',
      'candidate_storage_unavailable','llm_candidate_rejected'].includes(fullRepair.status);
    const discovery=investigation.config_discovery||{};
    const validator=r?.configuration_diagnostic||{};
    const response=state.configResponse||{};
    const approval=low(response.approval_status||response.status);
    const candidate=low(config.status)==='candidate_proposed';
    const hasDiff=configDiffRows(config,fullRepair).length>0;
    const originalFailed=low(validator.status)==='invalid'||
      low(response.repair_attention)==='confirmed_syntax_error_no_valid_candidate'||
      ['candidate_not_yet_valid','ready_for_prevalidation'].includes(
        low(repairAttention.status));
    const previouslyFailed=originalFailed||candidate||
      (Number.isInteger(config.error_line)&&!!config.config_file);
    const verified=arr(discovery.files).filter(item=>item.verified_exists===true);
    const path=config.config_file||response.config_file||validator.config_file||
      verified[0]?.path||discovery.unverified_candidates?.[0]?.path||'';
    const line=Number.isInteger(config.error_line)?config.error_line:
      Number.isInteger(validator.error_line)?validator.error_line:
      Number.isInteger(response.repair_error_line)?response.repair_error_line:null;
    const discoveryAvailable=Boolean(verified.length||discovery.unverified_candidates?.length);
    if(!service||(!previouslyFailed&&!path&&!discoveryAvailable)){
      node.hidden=true;node.innerHTML='';return;
    }

    const status=low(config.validation_status);
    const stageFailure=low(config.stage_failure_reason);
    const prerequisite=response.execution_prerequisites||{};
    const signingBlocked=approval==='approved'&&
      prerequisite.api_signing_key==='missing_or_weak_mcp_bearer_token';
    const oldEvent=approval==='consumed';
    const reportedError=String(validator.syntax_error||'').slice(0,180);
    const braceError=/unexpected\s*["']?\{["']?/i.test(reportedError);
    const symptom=braceError?
      (fa?'آکولاد باز «{» غیرمنتظره':'Unexpected opening brace {'):
      (fa?'خطای نحوی کانفیگ':'Configuration syntax error');
    const fullChanged=['llm_candidate_proposed','candidate_storage_unavailable'].includes(fullRepair.status)?
      arr(fullRepair.changed_line_numbers).filter(Number.isInteger).slice(0,12):[];
    const fullChangeActor=fullRepair.candidate_origin==='deterministic_json_syntax'?
      (fa?'، ابزار اعتبارسنج محلی تغییر خط ':'; worker syntax validator proposed line '):
      (fa?'، LLM تغییر خط ':'; LLM proposed line ');
    const filename=path?'<code dir="ltr">'+txt(path)+'</code>':
      esc(fa?'فایل کانفیگ سرویس':'the service configuration file');
    const location=path?
      (line!==null?
        esc(fa?'در خط ':'At line ')+
          '<strong>'+num(line)+'</strong> '+
          esc(fa?'فایل ':'of ')+filename:
        esc(fa?'در فایل ':'In ')+filename):
      esc(fa?'در کانفیگ سرویس ':'In the configuration of ')+txt(service);

    let title,summary,action;
    if(oldEvent){
      title=fa?'نتیجهٔ اصلاح کانفیگ '+service:'Configuration change result · '+service;
      summary=fa?'مجوز اجرای اصلاح مصرف شده است. نتیجهٔ اجرا و وضعیت فایل را بررسی کنید.':
        'The one-time approval has been consumed. Check the execution result and file status.';
      action='outcome';
    }else if(previouslyFailed){
      title=!candidate && approval!=='pending' && approval!=='pending_validation'
        ? (fa?'اقدام اصلاحی فوری لازم · '+service:'Action required: configuration repair · '+service)
        : (fa?'خطای کانفیگ '+service:'Configuration issue · '+service);
      summary=fullChanged.length?
        (esc(fa?'در فایل ':'In file ')+filename+
          esc(fullChangeActor)+
          fullChanged.map(num).join(', ')+
          esc(fa?' را پیشنهاد داده است؛ شمارهٔ خط ثبت‌شدهٔ Validator ممکن است مربوط به تشخیص قدیمی باشد. هنوز تست روی فایل اصلاحی انجام نشده است.':
            '. The recorded validator line may come from an older diagnostic. The revised file has not been tested.')):
        location+esc(fa?'، '+symptom+' گزارش شده است.':
          ': '+symptom+' was reported.');
      action=approval==='approved'?'approved':
        approval==='pending'?'pending':
        approval==='pending_validation'?'pending_validation':
        hasDiff?'diff':'review';
    }else{
      title=fa?'بررسی کانفیگ '+service:'Configuration review · '+service;
      summary=esc(fa?'برای این فایل هنوز خطای نحوی تأییدشده ثبت نشده است.':
        'No confirmed syntax issue has been recorded for this file.');
      action='review';
    }

    const instructions={
      approved:fa?'اصلاح بررسی و تأیید شده است؛ برای اعمال آن به بخش تأیید و اجرا بروید.':
        'The correction is approved; continue in the approval and execution section.',
      pending:fa?'نسخهٔ پیشنهادی اعتبارسنجی شده است؛ تفاوت‌ها را ببینید و در صورت موافقت تأیید کنید.':
        'The candidate passed validation; review the diff before approving.',
      pending_validation:fa?'پیشنهاد اصلاح ثبت شده است؛ پیش از تأیید، نسخهٔ موقت باید اعتبارسنجی شود.':
        'The request is recorded; validate the staged version before approval.',
      diff:fa?'اصلاح پیشنهادی را ببینید؛ پس از تأیید، برای اعمال آن اقدام کنید.':
        'Review the proposed correction; apply only after explicit approval.',
      review:fa?'برای دیدن اصلاح پیشنهادی و تفاوت فایل، بررسی را اجرا کنید.':
        'Run a review to see the suggested correction and file diff.',
      outcome:fa?'جزئیات اعمال، راستی‌آزمایی و بازگشت احتمالی را بررسی کنید.':
        'Inspect execution, verification and any rollback.',
    };
    // A failed full-file LLM attempt must not be silently presented as
    // "no fix exists". This is a generation/transport failure, not proof that
    // the configuration is unrepairable or that approval is already queued.
    if(repairFailure&&!hasDiff&&!oldEvent){
      summary=esc(fa?
        'تست کانفیگ خطا را نشان داده، اما تولید نسخه اصلاحی با LLM کامل نشده است؛ هنوز Diff معتبر یا درخواست Approval ایجاد نشده است.':
        'The configuration check found an error, but LLM repair did not complete. No verified diff or approval request exists yet.');
    }
    const stagedFailed=['staged_failed','staged_pass_not_isolated'].includes(status);
    const instruction=stagedFailed&&['diff','review'].includes(action)?
      (fa?'نسخهٔ پیشنهادی هنوز از اعتبارسنجی مستقل عبور نکرده است؛ آن را بررسی کنید، اما اعمال نکنید.':
        'The candidate has not passed independent validation; review it but do not apply.') :
      instructions[action];
    const previewKind=service==='nginx'?'nginx':verified.length?'review':'generic';
    const blocked=state.historic||state.busy||state.chatBusy||
      state.configPreviewPending||state.lifecycle?.analysis_in_progress;
    const disabled=blocked?' disabled':'';
    const previewButton='<button type="button" class="ic-btn ic-btn-primary" data-config-preview="'+
      previewKind+'" data-preview-open-diff="1"'+disabled+'>'+
      esc(fa?'بررسی و مشاهده اصلاح':'Review proposed fix')+'</button>';
    const diffLink='<a class="ic-btn ic-btn-primary" href="#ic-config-diff">'+
      esc(fa?'مشاهده اصلاح و Diff':'View fix and diff')+'</a>';
    const nextLink='<a class="ic-btn ic-btn-primary" href="#ic-action-controls">'+
      esc(fa?'مشاهده تأیید و اجرا':'View approval and execution')+'</a>';
    const resultLink='<a class="ic-btn ic-btn-primary" href="#ic-outcome-view">'+
      esc(fa?'مشاهده نتیجه اجرا':'View execution result')+'</a>';
    // A confirmed syntax failure without a candidate should offer the
    // deliberate COMPLETE-file repair as the primary action. The browser
    // always asks before sending any configuration secrets to the gateway.
    const needsCompleteRepair=originalFailed&&!candidate&&!hasDiff&&
      !['approved','pending','pending_validation','consumed'].includes(approval);
    const fullLLMButton=action==='outcome'?'':(
      '<button type="button" class="ic-btn '+
      (needsCompleteRepair?'ic-btn-primary':'ic-btn-muted')+
      '" data-config-preview="full-llm"'+disabled+'>'+
      esc(fa?'بررسی و اصلاح فایل کامل با LLM':'Review and repair COMPLETE config with LLM')+
      '</button>');
    const primary=action==='outcome'?resultLink:
      ['approved','pending','pending_validation'].includes(action)?nextLink:
      needsCompleteRepair?fullLLMButton:
      hasDiff?diffLink:previewButton;
    const secondary=needsCompleteRepair?
      '<button type="button" class="ic-btn ic-btn-muted" data-config-preview="'+
      previewKind+'"'+disabled+'>'+
      esc(fa?'بررسی امن بدون ارسال فایل به LLM':'Local review without sending the file to LLM')+
      '</button>':
      hasDiff&&!blocked&&action!=='outcome'?
      '<button type="button" class="ic-btn ic-btn-muted" data-config-preview="'+
      previewKind+'"'+disabled+'>'+esc(fa?'بررسی دوباره':'Recheck')+'</button>':'';
    const extraLLMButton=needsCompleteRepair?'':fullLLMButton;
    // Technical diagnostics are available on demand, not the lead sentence.
    // These may describe unavailable systemd/LLM capabilities without
    // contradicting a vendor-confirmed line number or a passed approval check.
    const diagnosticRows=[];
    if(reportedError)diagnosticRows.push(
      esc(fa?'پیام Validator: ':'Validator message: ')+txt(reportedError));
    if(discovery.status)diagnosticRows.push(
      esc(fa?'کشف فایل: ':'Discovery: ')+txt(discovery.status));
    if(discovery.llm_guidance_status)diagnosticRows.push(
      esc(fa?'مشورت LLM: ':'LLM consultation: ')+txt(discovery.llm_guidance_status));
    if(originalFailed) {
      diagnosticRows.push(
        esc(fa?'ارسال فایل کامل به مدل برای اصلاح: ':'Complete file sent to repair LLM: ')+
        (fullRepair.complete_file_in_prompt===true?
          esc(fa?'تأیید شد':'Confirmed')+
          (Number.isInteger(fullRepair.source_size_bytes)?
            ' ('+num(fullRepair.source_size_bytes)+' bytes)':''):
          esc(fa?'در این رخداد تأیید نشده؛ مشورت ساختاری LLM به معنی ارسال فایل کامل نیست':
            'Not verified for this incident; structural LLM advice does not send the complete file'))
      );
      if(['llm_bounded_edit_plan','llm_dotnet_jsonc_bounded_edits'].includes(fullRepair.candidate_generation_mode))diagnosticRows.push(
        esc(fa?'شیوه تولید اصلاح: پیشنهاد ویرایش کوچک روی متن کامل':
          'Repair mode: bounded edits against full original source')
      );
    }
    if(status&&status!=='—')diagnosticRows.push(
      esc(fa?'وضعیت پیشنهاد: ':'Candidate validation: ')+txt(status));
    if(stageFailure&&!['none','not_recorded','not_tested','—'].includes(stageFailure)){
      diagnosticRows.push(esc(fa?'مانع بررسی: ':'Check blocked: ')+txt(stageFailure));
    }
    if(response.validation_pipeline_status)diagnosticRows.push(
      esc(fa?'اعتبارسنجی مستقل: ':'Independent validation: ')+
      txt(response.validation_pipeline_status));
    const technical=diagnosticRows.length?
      '<details class="ic-config-banner-details"><summary>'+
      esc(fa?'جزئیات فنی':'Technical details')+'</summary><div>'+
      diagnosticRows.map(row=>'<p>'+row+'</p>').join('')+'</div></details>':'';
    const repairWarning=repairFailure&&!hasDiff?
      '<p class="ic-config-banner-warning" role="alert">'+
        esc(fa?
          (fullRepair.status==='llm_repair_timeout'?
            'علت توقف: ارتباط با مدل هنگام ساخت اصلاح زمان‌بر شد و به Timeout رسید. بازبینی زندهٔ دوباره و تلاش مجدد لازم است.':
            fullRepair.status==='llm_candidate_rejected'?
            'علت توقف: اصلاح LLM به خطای واقعی Validator مربوط نبود. این پچ برای حفاظت از فایل رد شد؛ باید اصلاح حداقلی معتبر تولید شود. هیچ درخواست Approval ثبت نشده است.':
            'علت توقف: مدل نسخه کامل قابل‌قبول تولید نکرد یا ذخیره امن Candidate انجام نشد؛ ارسال برای Approval ممکن نیست.'): 
          (fullRepair.status==='llm_repair_timeout'?
            'Reason: LLM repair timed out. Recheck live evidence and retry.':
            fullRepair.status==='llm_candidate_rejected'?
            'The model changed unrelated lines. Its patch was correctly rejected; rebuild and validate a minimal fix before queuing Approval.':
            'Reason: no complete acceptable candidate was produced or securely stored; approval cannot be queued.'))+
      '</p>':'';
    const warning=signingBlocked?
      '<p class="ic-config-banner-warning" role="status">'+
        esc(fa?'اعمال فعلاً متوقف است: توکن MCP در API برای امضای اجرا تنظیم نشده یا ضعیف است.':
          'Apply blocked: MCP bearer is missing or too weak for approval signing.')+
      '</p>':'';
    const liveStatus=state.configPreviewPending?
      '<p role="status" aria-live="polite">'+
      esc(fa?'در حال بررسی مجدد فایل کانفیگ…':'Rechecking the configuration…')+'</p>':
      state.configPreviewLastResult?
      '<p role="status" aria-live="polite">'+txt(state.configPreviewLastResult)+'</p>':'';
    node.hidden=false;
    const urgency=originalFailed&&!candidate&&!['pending','approved','pending_validation'].includes(approval);
    node.setAttribute('role',urgency?'alert':'region');
    const urgentExplanation=urgency?
      '<p role="alert" style="font-size:1.05rem;font-weight:700;line-height:1.8;">'+
      esc(fa?
        'خطای واقعی کانفیگ تأیید شده، اما هنوز اصلاح یکتا و قابل‌Parse ساخته نشده است؛ بنابراین هش معتبر و تیکت Approval وجود ندارد. فایل را دوباره با ابزار امن بررسی کنید. اجرای اصلاح همچنان به اعتبارسنجی مستقل و تأیید شما نیاز دارد.':
        'A measured configuration grammar error exists, but no unique parser-valid repair was generated. There is no hash-bound candidate or Approval ticket. Recheck the file; independent validation and your approval remain required.')+
      '</p>':'';
    node.innerHTML='<div class="ic-config-banner-copy"><strong style="font-size:1.2rem;">'+esc(title)+'</strong>'+urgentExplanation+
      '<p class="ic-config-banner-summary">'+summary+'</p>'+
      '<p>'+esc(instruction)+'</p>'+repairWarning+warning+liveStatus+technical+
      '</div><div class="ic-config-banner-actions">'+primary+secondary+extraLLMButton+'</div>';
  }

  // Only the bounded redacted representation from MCP may enter the DOM or
  // a client-generated download. Neither plaintext candidate nor live source
  // config is fetched from the remote VM or persisted in the incident report.
  function configDiffRows(config={},full={}) {
    const valid=rows=>arr(rows).filter(x=>
      x&&Number.isInteger(x.line)&&x.line>0&&x.line<=1000000
    ).slice(0,12);
    const llm=valid(full.redacted_changes);
    if(llm.length)return llm;
    const classic=valid(config.redacted_changes);
    if(classic.length)return classic;
    const fallback=config.redacted_diff||{};
    return Number.isInteger(fallback.line)?valid([fallback]):[];
  }

  function configDiffGlyph(value) {
    // Trusted worker enum values describe grammar edits without exposing
    // any property name, literal or secret. Unknown strings stay masked.
    const labels={
      remove_opening_brace:'حذف آکولاد باز اضافی {',
      remove_closing_brace:'حذف آکولاد بسته اضافی }',
      remove_opening_bracket:'حذف کروشه باز اضافی [',
      remove_closing_bracket:'حذف کروشه بسته اضافی ]',
      remove_comma:'حذف ویرگول اضافی ,',
      remove_colon:'حذف دونقطه اضافی :',
      insert_comma:'افزودن ویرگول لازم ,',
      insert_colon:'افزودن دونقطه لازم :',
      insert_closing_brace:'افزودن آکولاد بسته }',
      insert_closing_bracket:'افزودن کروشه بسته ]',
      quote_unquoted_key:'افزودن کوتیشن به نام ویژگی JSON',
      json_syntax_repaired:'ساختار JSON اصلاح شد',
      dotnet_jsonc_comments_or_trailing_commas:'بازنویسی کامنت‌ها و ویرگول‌های انتهایی مجاز در .NET برای اعتبارسنجی مستقل',
      strict_json_validator_compatible:'نسخه سازگار با JSON استاندارد و jq',
      json_invalid_punctuation:'ساختار نامعتبر JSON',
      json_punctuation_repaired:'ساختار JSON اصلاح شد',
    };
    const key=String(value||'');
    return Object.prototype.hasOwnProperty.call(labels,key)
      ?labels[key]:key.replace(/[^{};=,#()[\]\s]/g,'x').slice(0,180);
  }

  function configDiffText(config={},full={}) {
    const rows=configDiffRows(config,full);
    if(!rows.length)return '';
    const file=String(full.config_file||config.config_file||'configuration')
      .replace(/[\r\n]/g,'').replace(/^\/+/, '').slice(0,260);
    const source=String(full.source_sha256||config.original_sha256||'');
    const candidate=String(full.candidate_sha256||config.candidate_sha256||'');
    const header=[
      '# AIOps structural DIFF (values and secrets are redacted)',
      '# This is an advisory preview; apply requires independent validation and human approval',
      '# Source SHA-256: '+(/^[a-f0-9]{64}$/.test(source)?source:'not recorded'),
      '# Candidate SHA-256: '+(/^[a-f0-9]{64}$/.test(candidate)?candidate:'not recorded'),
      '--- a/'+file,'+++ b/'+file,
    ];
    return header.concat(rows.flatMap(row=>[
      '@@ -'+row.line+',1 +'+row.line+',1 @@',
      '-'+configDiffGlyph(row.before),
      '+'+configDiffGlyph(row.after),
    ])).join('\n')+'\n';
  }

  function renderConfigProposal(config,full={}) {
    const fa=state.language==='fa';
    const source=arr(config.current_excerpt),target=arr(config.proposed_excerpt);
    const diff=config.redacted_diff||{};
    const workerReplay=full.candidate_origin==='deterministic_json_syntax'&&
      full.proposed_change==='repair_json_bounded_syntax';
    const snippets=rows=>'<pre dir="ltr" class="ic-config-excerpt">'+
      rows.map(x=>esc(String(x.line).padStart(4,' ')+': '+safe(x.content))).join('\n')+'</pre>';
    const sourceHtml=source.length?snippets(source):'<p>'+esc(fa?
      'محتوای امن قابل نمایش هنوز دریافت نشده است.':'No safely displayable source excerpt is available.')+'</p>';
    const targetHtml=target.length?snippets(target):'<p>'+esc(fa?
      (['llm_candidate_proposed','candidate_storage_unavailable'].includes(full.status)?
        (full.candidate_stored?
          'نسخهٔ کامل اصلاحی به‌صورت رمزنگاری‌شده در VM MCP نگهداری شده؛ اعتبارسنجی مستقل قبل از Approval اجرا می‌شود.':
          (workerReplay?'اصلاح محدود JSON توسط اعتبارسنج محلی قابل‌بازسازی است؛ اعتبارسنجی ایزوله و Approval هنوز لازم است.':
            'LLM فایل کامل را برگردانده ولی ذخیره‌سازی امن آن تأیید نشده است.')) :
        'نسخه پیشنهادی قطعی تولید نشده است.'):
      (['llm_candidate_proposed','candidate_storage_unavailable'].includes(full.status)?
        (full.candidate_stored?
          'The full corrected file is encrypted in VM MCP; independent validation must pass before approval.':
          (workerReplay?'The bounded JSON syntax repair is independently reconstructible; isolated validation and approval are still required.':
            'The model returned a complete file, but durable secure storage is unverified.')) :
        'No deterministic patch candidate has been produced.'))+'</p>';
    let html='<div class="ic-fix-grid">'+
      '<article class="ic-detail-card"><h4>'+esc(fa?'کانفیگ موجود (بخش ساختاری، محرمانه‌زدایی شده)':'Existing config (redacted structural excerpt)')+'</h4>'+
      '<p>'+txt(config.config_file)+'</p>'+sourceHtml+
      '<p>'+esc(fa?'خط ثبت‌شده در بررسی قبلی Validator: ':'Previously recorded validator line: ')+txt(config.error_line)+'</p>'+
      '<p class="ic-meta">Source SHA-256: '+txt(config.original_sha256)+'</p></article>'+
      '<article class="ic-detail-card"><h4>'+esc(fa?'پیشنهاد اصلاح کانفیگ':'Proposed configuration correction')+'</h4>'+
      targetHtml+
      '<p class="ic-meta">Candidate SHA-256: '+txt(config.candidate_sha256)+'</p></article></div>';
    const safeDiffs=configDiffRows(config,full);
    if(safeDiffs.length){
      const maxInline=6;
      const inline=safeDiffs.slice(0,maxInline);
      html+='<article class="ic-detail-card" id="ic-config-diff">'+
        '<div class="ic-config-diff-header"><h4>'+esc(fa?
          'مقایسه تغییرات پیشنهادی (مقادیر محرمانه پوشانده شده‌اند)':
          'Proposed changes (sensitive values redacted)')+'</h4>'+
        '<button type="button" class="ic-btn ic-btn-muted" data-download-config-diff="1">'+
          esc(fa?'دانلود فایل Diff (.diff)':'Download diff (.diff)')+
        '</button></div>'+
        '<p class="ic-meta">'+esc(fa?
          'فقط خطوط تغییرکرده نمایش داده می‌شوند؛ حذف (−) و افزودن (+). خروجی دانلود نیز محرمانه‌زدایی شده است.':
          'Only changed lines are shown: removed (−) and added (+). The download is redacted too.')+'</p>'+
        '<pre dir="ltr" class="ic-config-excerpt ic-config-diff-preview">'+
          esc(inline.map(change=>'@@ line '+change.line+' @@\n- '+
            configDiffGlyph(change.before)+'\n+ '+configDiffGlyph(change.after)).join('\n'))+
        '</pre>'+
        (safeDiffs.length>maxInline?'<p>'+esc(fa?
          'نمایش '+num(maxInline)+' خط اول از '+num(safeDiffs.length)+
            ' تغییر؛ فایل Diff کامل را دانلود کنید.':
          'Showing '+maxInline+' of '+safeDiffs.length+
            ' changes. Download the complete redacted diff.')+'</p>':'')+
        '</article>';
    }
    html+='<article class="ic-detail-card"><h4>'+esc(fa?'وضعیت آزمایش نسخه پیشنهادی':'Proposed-version validation')+'</h4>'+
      '<p><strong>'+txt(config.validation_status||'UNVERIFIED')+'</strong></p>'+
      (config.format_validation_status?
        '<p>'+esc(fa?'بررسی ساختار فایل در AIOps: ':'AIOps file-format check: ')+
        txt(config.format_validation_status)+'</p>':'')+
      (config.vendor_validation_status?
        '<p>'+esc(fa?'وضعیت اعتبارسنج اختصاصی سرویس: ':'Vendor validator status: ')+
        txt(config.vendor_validation_status)+'</p>':'')+
      (low(config.validation_status)==='staged_failed'?'<p class="ic-diagnosis-caution">'+esc(fa?
        'nginx -t روی کپی موقت ناموفق بوده است. این پیشنهاد قابل اعمال نیست و تأیید بررسی، مجوز تغییر فایل نیست.':
        'Staged nginx -t failed. This candidate is not deployable, and acknowledging the review never authorizes a file write.')+'</p>':'')+
      (config.stage_failure_reason?'<p>'+esc(fa?'کد علت شکست/وضعیت تست: ':'Staging reason code: ')+
        txt(config.stage_failure_reason)+'</p>':'')+
      '<p>'+txt(config.test_scope||'not_tested')+'</p>'+
      '<p class="ic-agent-disclaimer">'+esc(
        config.test_scope==='worker_preview_unvalidated'?
          (fa?'پیشنهاد فقط در حافظهٔ AIOps ساخته شده است؛ هیچ فایل روی سرور تغییر نکرده و nginx -t برای نسخهٔ پیشنهادی اجرا نشده است. بدون اعتبارسنجی مستقل، اعمال مجاز نیست.':
          'Only an in-memory AIOps preview exists. No target file was changed and the candidate has not passed nginx -t. Independent validation is still required.'):
          (fa?'تست کپی موقت ممکن است Includeهای زنده را بخواند و اعتبارسنجی ایزوله نیست؛ مجوز اعمال صادر نمی‌شود.':
          'Temporary staging may access live includes. It is not isolated validation and does not authorize Apply.')
      )+'</p></article>';
    const candidate=config.status==='candidate_proposed'&&config.candidate_sha256&&config.original_sha256;
    if(candidate){
      const legacyIntent=state.configResponse?.status==='awaiting_isolated_validation' &&
        !state.configResponse?.approval_queue_registered;
      const answered=state.configResponse?.status&&state.configResponse.status!=='not_responded'&&!legacyIntent;
      const disabled=state.historic||state.busy||state.configResponseStatus!=='loaded';
      html+='<article class="ic-detail-card"><h4>'+esc(fa?
        'درخواست تأیید تغییر همین Diff':
        'Request approval for this exact diff')+'</h4>'+
        '<p>'+esc(fa?
          'درخواست در صف Approval ثبت می‌شود؛ دکمه تأیید تا موفقیت اعتبارسنجی مستقل غیرفعال است. هیچ فایلی تغییر نمی‌کند.':
          'This change enters the Approval queue; final approval stays disabled until independent validation. No file is changed.')+'</p>'+
        (answered?'<p><strong>'+txt(state.configResponse.status)+'</strong></p>':
        '<div class="ic-action-buttons">'+
        '<button type="button" class="ic-btn ic-btn-primary" data-config-intent="request_change_approval"'+(disabled?' disabled':'')+'>'+
        esc(fa?(legacyIntent?'انتقال درخواست قبلی به صف Approval':'ارسال درخواست به Approval'):
          (legacyIntent?'Queue previously recorded request':'Submit change for approval'))+'</button>'+
        '<button type="button" class="ic-btn ic-btn-muted" data-config-intent="reject"'+(disabled?' disabled':'')+'>'+
        esc(fa?'خیر، رد پیشنهاد':'No, reject proposal')+'</button></div>')+
        '<p class="ic-agent-disclaimer">'+esc(fa?
          'درخواست با وضعیت «در انتظار اعتبارسنجی» در صف Approval قرار می‌گیرد. تأیید نهایی تا تکمیل Validator و قرارداد اجرای کنترل‌شده مسدود است.':
          'The request queues as pending_validation. Final approval stays disabled until isolated validation and guarded execution exist.')+
        '</p></article>';
    }
    return html;
  }
  // 409 is an intentional execution guard, not a server outage. Only a
  // live, identity-matched systemd 'active' observation gets this label.
  // Never describe active systemd as proven application/HTTP recovery.
  function recoveryApprovalFailure(error) {
    const detail=error?.detail||{};
    const recognized=error?.status===409&&
      (error?.code||detail.code)==='recovery_live_binding_or_state_changed';
    if(recognized&&detail.reason_code==='service_active_before_approval'&&
       detail.observed_state==='active'){
      return {status:'state_changed_active',reason_code:detail.reason_code,
        observed_state:'active',expected_state:detail.expected_state||'failed',
        execution_authority:false,application_health_verified:false};
    }
    if(recognized)return {status:'blocked',reason_code:
      ['live_identity_unverified','service_state_changed'].includes(detail.reason_code)?
        detail.reason_code:'live_preflight_not_matching',
      execution_authority:false};
    if(error?.status===403)return {status:'permission_required',reason_code:'permission_required',
      execution_authority:false};
    return {status:'blocked',reason_code:error?.code||
      (error?.status===409?'recovery_approval_conflict':'recovery_queue_failed'),
      execution_authority:false};
  }
  function recoveryApprovalStatusLabel(approval,fa) {
    if(approval?.status==='state_changed_active')return fa?
      'سرویس اکنون از دید systemd فعال است؛ درخواست Restart به دلیل تغییر وضعیت ثبت نشد.':
      'The service is now active in systemd; Restart approval was not queued because its state changed.';
    if(approval?.status==='blocked')return fa?
      'ایجاد Approval مسدود شد؛ بررسی زنده با وضعیت یا هویت ثبت‌شده مطابقت ندارد.':
      'Approval was blocked: live target identity or service state did not match.';
    if(approval?.status==='permission_required')return fa?
      'دسترسی لازم برای ایجاد درخواست Approval وجود ندارد.':
      'You do not have permission to queue this Approval.';
    return '';
  }
  function recoveryApprovalSafetyNote(fa) {
    return fa?
      'فعال بودن systemd اثبات سلامت HTTP/API یا رفع آلارم Zabbix نیست. ابتدا وضعیت برنامه را به‌صورت Read-only بررسی کنید؛ Restart خودکار یا مجوز اجرا صادر نشده است.':
      'An active systemd unit does not prove API/HTTP health or Zabbix recovery. Recheck application health read-only; no restart or execution authority was issued.';
  }

  async function loadRecoveryApproval(token) {
    if(state.historic||!state.report?.recovery_advisory?.suggested_action)return;
    try{
      let approval=await api(base+'/recovery-approval');
      if(token!==state.loadingToken||state.historic)return;
      // A GET returning not_requested must not erase a prior, definitive
      // 409 status from this page load; otherwise the operator sees
      // "Loading Approval" forever while the queue attempt is suppressed.
      if(approval.status==='not_requested'&&state.recoveryQueueAttempted&&
         ['state_changed_active','blocked','permission_required'].includes(
           state.recoveryApproval?.status)){
        approval=state.recoveryApproval;
      }
      state.recoveryApproval=approval;
      // Queue a guarded high-risk human Approval when AIOps generated a
      // live-evidence-bound Restart/Start recommendation. Never approve or
      // execute automatically; the server repeats identity/target/state
      // checks and de-duplicates concurrent requests.
      if(approval.status==='not_requested'&&!state.recoveryQueueAttempted){
        state.recoveryQueueAttempted=true;
        try{
          approval=await api(base+'/recovery-approval/queue',{method:'POST'});
          if(token!==state.loadingToken||state.historic)return;
          state.recoveryApproval=approval;
        }catch(e){
          if(token!==state.loadingToken||state.historic)return;
          state.recoveryApproval=recoveryApprovalFailure(e);
        }
      }
    }catch(e){
      if(token!==state.loadingToken||state.historic)return;
      state.recoveryApproval={status:'unavailable',reason:String(e.message||'').slice(0,130)};
    }
    if(state.report){
      renderHero(state.report);
      renderInvestigation(state.report);
      renderDecision(state.report);
    }
  }

  async function handleRecoveryApproval(action) {
    const approval=state.recoveryApproval||{};
    const id=String(approval.approval_id||'');
    if(!UUID.test(id)||state.historic||state.busy)return;
    const fa=state.language==='fa';
    const combined=action==='approve-execute';
    const executionRequested=combined||action==='execute';
    if((action==='approve'||combined)&&approval.status!=='pending')return;
    if(action==='execute'&&approval.status!=='approved')return;
    if(action==='reject'&&approval.status!=='pending')return;
    if(!['approve','approve-execute','execute','reject'].includes(action))return;
    const verb=approval.action==='start_service'?'Start':'Restart';
    const message=combined?
      (fa?'آیا با تأیید این مجوز، اجرای واقعی '+verb+' روی '+approval.service+
        ' در سرور '+approval.target+' نیز انجام شود؟ ابتدا Approval ثبت و سپس بررسی زنده و تلاش برای '+verb+' اجرا می‌شود.':
        'Approve and execute '+verb+' of '+approval.service+' on '+approval.target+
        '? Approval is recorded first; live preflight and the actual action follow.'):
      action==='approve'?
      (fa?'مجوز '+verb+' سرویس فقط تأیید می‌شود؛ هنوز اجرا نخواهد شد. موافق هستید؟':
        'Authorize '+verb+'? No action executes yet.'):
      action==='execute'?
      (fa?'این عملیات واقعی '+verb+' سرویس '+approval.service+' روی سرور '+approval.target+
        ' است. Runbook پیش از اجرا مجدداً شرایط زنده و کانفیگ را بررسی می‌کند. ادامه می‌دهید؟':
        'This will actually '+verb+' '+approval.service+' on '+approval.target+
        ' if fresh runbook checks pass. Continue?'):
      (fa?'درخواست '+verb+' رد شود؟':'Reject this '+verb+' request?');
    if(!confirm(message))return;
    let reason='';
    if(action==='reject'){
      reason=prompt(fa?'دلیل رد (الزامی):':'Reason for rejection (required):','')||'';
      if(!reason.trim())return;
    }
    state.busy=true;renderInvestigation(state.report);renderHero(state.report);
    let attempted=false;
    try{
      const url='/api/v1/approvals/'+encodeURIComponent(id);
      if(combined){
        // One explicit operator confirmation, two distinct governed server
        // boundaries. No execution if approval fails, and the execution API
        // still checks independent execute permission, freshness and intent.
        const authorized=await api(url+'/approve',{method:'POST'});
        if(low(authorized.status)!=='approved'){
          throw new Error('recovery_approval_not_granted');
        }
        state.recoveryApproval={...approval,status:'approved'};
        attempted=true;
        const result=await api(url+'/execute',{method:'POST'});
        state.recoveryApproval={...approval,status:String(result.status||'consumed')};
        notify(result.success===true?
          (fa?'فرمان '+verb+' ارسال شد؛ نتیجهٔ راستی‌آزمایی سرویس در حال بازخوانی است.':
            verb+' executed; refreshing independently verified service state.'):
          (fa?'تلاش برای '+verb+' تأیید نشد؛ نتیجهٔ اجرای MCP و پیش‌شرط‌ها را بررسی کنید.':
            verb+' attempt was not confirmed; inspect MCP execution and preflight.'),
          result.success!==true);
      }else{
        const options=action==='reject'?
          {method:'POST',headers:{'Content-Type':'application/json'},
           body:JSON.stringify({reason:reason.trim().slice(0,1000)})}:
          {method:'POST'};
        attempted=executionRequested;
        const result=await api(url+'/'+action,options);
        state.recoveryApproval={...approval,status:String(result.status||'unknown')};
        notify(fa?(action==='approve'?'مجوز ثبت شد؛ هنوز '+verb+' اجرا نشده است.':
          action==='reject'?'درخواست '+verb+' رد شد.':
          'تلاش برای '+verb+' انجام شد؛ نتیجه و Verification را بررسی کنید.'):
          'The authorization state changed; check verification.');
      }
    }catch(e){
      notify(tr('failure')+' · '+e.message,true);
    }finally{
      state.busy=false;
      // Refresh even on 403/409 after approval. The approval can already be
      // durable while the independent execution is rejected by a live gate.
      await load();
      if(attempted)await recheckServiceStatus();
      void loadRecoveryApproval(state.loadingToken);
    }
  }

  function dotnetSyntaxLabel(item,fa) {
    const status=low(item?.status);
    if(status==='valid_json_syntax')return fa?'سینتکس صحیح':'Syntax valid';
    if(status==='invalid_json_syntax')return fa?'سینتکس نامعتبر':'Invalid syntax';
    if(status==='unavailable')return fa?'بررسی ناموفق':'Check unavailable';
    return fa?'بررسی نشده':'Not checked';
  }

  async function loadDotnetSyntax(token) {
    state.liveDotnetSyntax=null;state.liveDotnetSyntaxStatus='checking';
    if(state.report)renderInvestigation(state.report);
    try{
      const result=await api(base+'/dotnet-config-syntax');
      if(token!==state.loadingToken||state.historic)return;
      state.liveDotnetSyntax=result;
      state.liveDotnetSyntaxStatus=low(result.status)||'unavailable';
    }catch(e){
      if(token!==state.loadingToken||state.historic)return;
      state.liveDotnetSyntax={status:'unavailable',reason:e.status===409?
        'identity_or_analysis_unverified':'vm_mcp_syntax_check_failed',files:[]};
      state.liveDotnetSyntaxStatus='unavailable';
    }
    if(state.report)renderInvestigation(state.report);
  }

  function renderInvestigation(r) {
    if(r.memory_investigation){
      const m=r.memory_investigation;
      show('#ic-proposed-fix','<article class="ic-detail-card"><h3>'+
        esc(state.language==='fa'?'مسیر تخصصی عیب‌یابی RAM':'RAM diagnostic track')+
        '</h3><p>'+esc(state.language==='fa'?
        'پیشنهادهای تخصصی Read-only و دلایل انجام‌نشدن هر بررسی در بخش «چرا RAM بالا رفت؟» بالای گزارش مشخص شده‌اند. تا تأیید علت، هیچ پیشنهاد Restart، Kill یا افزایش RAM مجوز اجرا ندارد.':
        'Evidence-backed read-only investigation steps and gaps appear above. No restart, kill or RAM increase is authorized.')+
        '</p></article>');return;
    }
    const p=r.dynamic_investigation||{},kb=p.knowledge_followup||{};
    const config=p.config_proposal||{},fa=state.language==='fa';
    const historical=Boolean(state.historic);
    const syntaxLive=!historical&&state.liveDotnetSyntax?.runtime==='dotnet'?
      state.liveDotnetSyntax:null;
    const syntaxChecked=syntaxLive||null;
    const syntaxRows=arr(syntaxChecked?.files).filter(x=>x&&x.file);
    const syntaxByName=new Map(syntaxRows.map(x=>[String(x.file).toLowerCase(),x]));
    const recovery=r.recovery_advisory||{};
    // Recovery suggestion is NOT a pending approval. Never expose execution
    // controls here, even if the model calls an action "approved".
    const recoveryMarkup=recovery.status?
      '<article class="ic-detail-card ic-recovery-advice"><h3>'+
      esc(fa?'پیشنهاد بازیابی مشروط سرویس':'Conditional service recovery advice')+'</h3>'+
      '<p><strong>'+esc(fa?'اقدام پیشنهادی: ':'Suggested action: ')+
      '</strong>'+esc(recovery.suggested_action ?
        (recovery.suggested_action==='restart_service'?
          (fa?'Restart سرویس':'Restart service'):(fa?'Start سرویس':'Start service')) :
        (fa?'ابتدا اصلاح کانفیگ':'Repair configuration first'))+'</p>'+
      '<div class="ic-proposal">'+
        '<div>'+esc(fa?'سرویس':'Service')+': '+txt(recovery.service)+'</div>'+
        '<div>'+esc(fa?'مقصد':'Target')+': '+txt(recovery.target)+'</div>'+
        '<div>'+esc(fa?'وضعیت مشاهده‌شده':'Observed status')+': '+txt(recovery.observed_state)+'</div>'+
        '<div>'+esc(fa?'نتیجه systemd':'systemd result')+': '+txt(recovery.systemd_result)+'</div>'+
        '<div>'+esc(fa?'اعتبارسنجی کانفیگ':'Configuration check')+': '+txt(recovery.configuration_validation)+'</div>'+
      '</div>'+
      '<p>'+esc(fa?
        'این پیشنهاد صرفاً برای بررسی است. اختلاف نظر Agentها یا نبود Validator مانع نمایش راهکار نمی‌شود، اما اجرای عملی همچنان به پیش‌شرط‌های مستقل و Approval نیاز دارد.':
        'This is review-only advice. Agent disagreement or an unavailable validator does not suppress it, but execution still requires independent prechecks and approval.')+'</p>'+
      '<h4>'+esc(fa?'بررسی‌های لازم پیش از اجرا':'Required checks before execution')+'</h4>'+
      '<ul class="ic-agent-bullets">'+arr(recovery.prerequisite_checks).slice(0,6).map(check=>
        '<li>'+txt(check)+'</li>').join('')+'</ul>'+
      '<p>'+txt(recovery.operator_question)+'</p>'+
      (recovery.suggested_action?
        '<div class="ic-recovery-approval"><h4>'+
        esc(fa?'درخواست رسمی Approval برای بازیابی':'Recovery request in Approval queue')+'</h4>'+
        '<p>'+esc(fa?'وضعیت: ':'Status: ')+
        esc(state.recoveryApproval?.status==='pending'?(fa?'منتظر تأیید شما':'Awaiting your approval'):
          state.recoveryApproval?.status==='approved'?(fa?'تأیید شده؛ هنوز اجرا نشده':'Approved; not executed'):
          state.recoveryApproval?.status==='permission_required'?(fa?'برای ثبت درخواست نقش SRE لازم است':'SRE permission required'):
          ['blocked','state_changed_active'].includes(state.recoveryApproval?.status)?
            recoveryApprovalStatusLabel(state.recoveryApproval,fa):
          state.recoveryApproval?.status==='consumed'?(fa?'مجوز مصرف شده؛ نتیجه اجرا را بررسی کنید':'Authorization consumed'):
          fa?'در حال بررسی/ثبت درخواست Approval':'Loading or queuing approval')+'</p>'+
        (state.recoveryApproval?.approval_id?
          '<p class="ic-meta">Approval ID: <code dir="ltr">'+txt(state.recoveryApproval.approval_id)+'</code></p>':'')+
        (state.recoveryApproval?.status==='state_changed_active'?
          '<p class="ic-diagnosis-caution" role="status">'+
            esc(recoveryApprovalSafetyNote(fa))+'</p>':'')+
        (state.recoveryApproval?.reason_code&&state.recoveryApproval.status!=='state_changed_active'?
          '<p class="ic-meta"><code>'+txt(state.recoveryApproval.reason_code)+'</code></p>':'')+
        (state.recoveryApproval?.status==='pending'?
          '<button type="button" class="ic-btn ic-btn-primary" data-recovery-approval="approve-execute">'+
          esc(fa?'تأیید و اجرای واقعی '+(recovery.suggested_action==='start_service'?'Start':'Restart'):
            'Approve & execute '+(recovery.suggested_action==='start_service'?'Start':'Restart'))+'</button> '+
          '<button type="button" class="ic-btn ic-btn-muted" data-recovery-approval="approve">'+
          esc(fa?'فقط تأیید (بدون اجرا)':'Approve only (no execution)')+'</button> '+
          '<button type="button" class="ic-btn ic-btn-muted" data-recovery-approval="reject">'+
          esc(fa?'رد درخواست':'Reject request')+'</button>':'')+
        (state.recoveryApproval?.status==='approved'?
          '<button type="button" class="ic-btn ic-btn-danger" data-recovery-approval="execute">'+
          esc(fa?'اجرای واقعی '+(recovery.suggested_action==='start_service'?'Start':'Restart')+' پس از بررسی پیش‌شرط‌ها':
            'Execute '+(recovery.suggested_action==='start_service'?'start':'restart')+' after fresh preflight')+'</button>':'')+
        '<p class="ic-meta">'+esc(fa?
          'تأیید هیچ عملیاتی اجرا نمی‌کند. اجرای جداگانه همچنان به کنترل زنده Runbook و صحت کانفیگ وابسته است.':
          'Approval does not execute anything. Live runbook and config checks remain mandatory.')+'</p></div>':'')+
      refs(recovery.evidence_refs)+
      '<p class="ic-agent-disclaimer">'+esc(fa?
        'مجوز اجرای این پیشنهاد صادر نشده است؛ دکمهٔ تأیید اجرا تا ایجاد درخواست اجرایی معتبر فعال نمی‌شود.':
        'No execution authority has been granted. Only a separately generated, properly validated request may enter the approval workflow.')+
      '</p></article>':'';
    const full=p.full_config_llm_repair||{};
    const fullCandidate=['llm_candidate_proposed','candidate_storage_unavailable'].includes(full.status)&&
      /^[a-f0-9]{64}$/.test(String(full.candidate_sha256||''))&&
      full.llm_received_complete_file===true&&
      (full.llm_returned_complete_file===true||
        full.candidate_origin==='deterministic_json_syntax');
    const configRejectionReasons={
      candidate_excessive_changes:fa?
        'مدل بخش زیادی از کانفیگ را تغییر داده است؛ فقط اصلاح خطای کوچک مجاز است.':
        'The model rewrote too much of the configuration; only a small fix is allowed.',
      candidate_not_minimal_syntax_fix:fa?
        'بیش از ۳ کاراکتر نحوی تغییر کرده یا تغییر، اصلاح نحوی مؤثری نیست.':
        'More than 3 syntax characters changed, or no syntax correction was made.',
      candidate_changes_unrelated_bytes:fa?
        'تغییرات اضافی در فاصله‌گذاری، تورفتگی یا محتوای غیرمرتبط رد شد.':
        'Unrelated whitespace, indentation or configuration edits were rejected.',
      candidate_unrelated_to_validator_line:fa?
        'خطوط تغییریافته از محل خطای Validator فاصله دارند.':
        'The changes are unrelated to the vendor-reported error line.',
      candidate_changes_configuration_values:fa?
        'ویرایش مقدار تنظیمات مجاز نیست.':
        'Changing configuration values is not allowed.',
      candidate_changes_sensitive_line:fa?
        'تغییر روی خط حاوی مقادیر حساس مجاز نیست.':
        'Changes on sensitive lines are blocked.',
    };
    const fullRepairHtml=full.status&&full.status!=='—'?
      '<article class="ic-detail-card ic-complete-config-llm">'+
      '<h3>'+esc(fa?'نتیجهٔ بررسی فایل کامل توسط LLM':'Complete-file LLM repair result')+'</h3>'+
      '<p>'+esc(fullCandidate?
        (fa?'مدل تمام فایل انتخابی را دریافت و یک نسخهٔ کامل اصلاح‌شده برگردانده است. این نتیجه، مشاهدهٔ LLM است و اعتبارسنجی فایل اصلاحی نیست.':
          'The model received the complete selected file and returned a complete revised version. This is a model result, not independent validation.'):
        (fa?'نسخهٔ کامل اصلاح‌شدهٔ قابل‌قبول از LLM دریافت نشده است.':
          'An acceptable complete-file candidate was not returned by the model.'))+'</p>'+
      '<p><strong>'+esc(fa?'فایل: ':'File: ')+'</strong><code dir="ltr">'+txt(full.config_file||'')+'</code></p>'+
      '<p>'+esc(fa?'وضعیت: ':'Status: ')+txt(full.status)+'</p>'+
      (fullCandidate?
        '<p>'+esc(fa?'تعداد خطوط تغییرکرده: ':'Changed lines: ')+num(full.changed_line_count||0)+
        ' · '+esc(fa?'شماره خطوط: ':'Line numbers: ')+
        arr(full.changed_line_numbers).slice(0,12).map(num).join(', ')+'</p>'+
        '<p>Candidate SHA-256: <code dir="ltr">'+txt(full.candidate_sha256)+'</code></p>':'')+
      (full.source_sha256?'<p>Source SHA-256: <code dir="ltr">'+txt(full.source_sha256)+'</code></p>':'')+
      (full.rejection_reason?'<p>'+esc(fa?'دلیل رد: ':'Rejection reason: ')+
        esc(configRejectionReasons[String(full.rejection_reason)]||String(full.rejection_reason))+
        ' <code>'+txt(full.rejection_reason)+'</code></p>':'')+
      '<p class="ic-agent-disclaimer">'+esc(fa?
        (full.candidate_stored?
          'فایل اصلاح‌شده به‌شکل رمزنگاری‌شده نگهداری شده است؛ تا پایان موفق اعتبارسنجی مستقل و Approval، هیچ فایل Production تغییر نمی‌کند.':
          (full.candidate_origin==='deterministic_json_syntax'&&
           full.proposed_change==='repair_json_bounded_syntax'?
            'این اصلاح JSON از هش فایل اصلی قابل‌بازسازی است؛ پس از اعتبارسنجی مستقل می‌تواند به Approval برسد.':
            'فایل اصلاحی هنوز به‌شکل امن نگهداری نشده و امکان تأیید یا اعمال آن وجود ندارد.')):
        (full.candidate_stored?
          'The revised file is stored encrypted, but no production write occurs until independent validation and approval pass.':
          (full.candidate_origin==='deterministic_json_syntax'&&
           full.proposed_change==='repair_json_bounded_syntax'?
            'The worker can reconstruct this exact hash-bound JSON change without storing source bytes; independent validation and approval are still required.':
            'The revised file is not securely stored and cannot be approved or applied.')))+'</p>'+
      refs(full.source_evidence_refs)+'</article>':'';
    const hasPlan=p.status && p.status!=='not_available';
    if(!hasPlan) {
      show('#ic-proposed-fix',recoveryMarkup || empty(fa?
        'تحقیق پویای مرحله‌ای برای این رخداد ثبت نشده است. این قابلیت باید در Backend فعال و اجرا شود.':
        'No dynamic investigation was recorded for this incident. The backend capability must be enabled.'));
      return;
    }
    const questions=arr(p.questions);
    const checks=arr(p.checks);
    const disc=p.config_discovery||{};
    const guidance=p.llm_unknown_guidance||{};
    const found=arr(disc.files),hypotheses=arr(disc.unverified_candidates);
    const fileItems=found.length?found:hypotheses;
    const discoveryHtml=(fileItems.length||disc.runtime&&disc.runtime!=='—'||
      disc.status&&disc.status!=='—')?
      '<article class="ic-detail-card"><h3>'+
      esc(fa?'کشف فایل کانفیگ از systemd و MCP':'Config file discovery via systemd & MCP')+
      '</h3><p>'+esc(fa?'فناوری شناسایی‌شده: ':'Detected runtime: ')+txt(disc.runtime)+
      ' · '+esc(fa?'وضعیت کشف: ':'Discovery: ')+txt(disc.status)+'</p>'+
      (disc.systemd_unit&&disc.systemd_unit!=='—'?
        '<p>'+esc(fa?'فایل سرویس systemd: ':'Systemd unit: ')+
        '<code dir="ltr">'+txt(disc.systemd_unit)+'</code></p>':'')+
      (fileItems.length?'<ul class="ic-agent-bullets">'+fileItems.slice(0,10).map(file=>
        '<li><code dir="ltr">'+txt(file.path)+'</code> · '+
        esc(file.verified_exists===true?
          (file.source==='vendor_validator'?
            (fa?'فایل توسط Validator شناسایی شده':'File identified by vendor validator'):
            (fa?'وجود فایل تأیید شده':'File existence verified')):
          (fa?'وجود فایل تأیید نشده':'File existence unverified'))+
        (file.verified_exists===true&&low(disc.runtime)==='dotnet'&&/\.json$/i.test(String(file.path||''))?
          ' · <strong>'+esc(dotnetSyntaxLabel(
            syntaxByName.get(String(file.path).split('/').pop().toLowerCase()),fa))+'</strong>'+
          (syntaxByName.get(String(file.path).split('/').pop().toLowerCase())?.status==='invalid_json_syntax'?
            ' · '+esc(fa?'خط ':'Line ')+num(syntaxByName.get(String(file.path).split('/').pop().toLowerCase()).line)+
            '، '+esc(fa?'ستون ':'Column ')+num(syntaxByName.get(String(file.path).split('/').pop().toLowerCase()).column):''):
          '')+
        ' · '+txt(file.source)+'</li>').join('')+'</ul>':
        '<p>'+esc(fa?'فایل مشخصی هنوز تأیید نشده؛ سامانه باید از LLM و روش کشف معتبر کمک بگیرد.':
        'No verified file yet; consult LLM and vendor discovery guidance.')+'</p>')+
      '<p>'+esc(fa?'وضعیت مشورت LLM برای موارد نامشخص: ':'LLM advice for open questions: ')+
      esc(['unavailable','guidance_incomplete'].includes(
        String(disc.llm_guidance_status||guidance.status))?
        (fa?'مشورت این مرحله تکمیل نشده ('+
          String(guidance.failure_reason||'علت ثبت نشده')+
          ')؛ این به معنی قطع بودن LLM نیست.':
          'This advisory call was incomplete ('+
          String(guidance.failure_reason||'reason not recorded')+
          '); the shared LLM is not necessarily offline.'):
        String(disc.llm_guidance_status||guidance.status||'not_consulted'))+'</p>'+
      arr(guidance.items).slice(0,4).map(x=>
        '<p><strong>'+txt(x.subject)+'</strong> — '+txt(x.explanation)+
        ' · '+txt(x.validation_approach)+'</p>').join('')+
      '<p class="ic-agent-disclaimer">'+esc(fa?
        'پیشنهاد LLM و فایل حدسی مجوز خواندن مسیر دلخواه یا اجرای Validator نیستند؛ فقط مسیر تأییدشده و ابزار ثبت‌شده مجاز است.':
        'LLM suggestions never authorize arbitrary path reads, validation commands or changes.')+
      '</p>'+refs(disc.evidence_refs)+'</article>':'';
    const body='<div class="ic-callout"><strong>'+
      esc(fa?'وضعیت: صرفاً پیشنهاد تحقیق، بدون اجازه تغییر':'Status: investigation proposal, no change authority')+
      '</strong><p>'+esc(fa?
        'تا زمانی که کانفیگ فعلی و نسخه پیشنهادی از منبع معتبر جمع‌آوری و نسخه پیشنهادی واقعاً اعتبارسنجی نشده باشد، هیچ Patch یا تأیید اجرا وجود ندارد.':
        'No patch or executable approval exists until source material is collected and the proposed version passes a real validation.')+
      '</p></div>'+
      discoveryHtml+
      fullRepairHtml+
      ((config.status||configDiffRows(config,full).length)?renderConfigProposal(config,full):'')+
      (p.runtime_discovery?.runtime==='dotnet'?(()=>{
        const d=p.runtime_discovery,files=arr(d.files);
        return '<article class="ic-detail-card"><h4>'+esc(fa?'کشف ساختار برنامه و بررسی تنظیمات .NET':'Discovered .NET runtime & configuration checks')+'</h4>'+
          '<div class="ic-meta">'+
          esc(fa?'فناوری: .NET':'Technology: .NET')+
          '</div><p>'+esc(fa?'فایل اجرایی: ':'Entrypoint: ')+txt(d.entrypoint)+'</p>'+
          '<p>'+esc(fa?'مسیر Publish: ':'Publish directory: ')+txt(d.publish_directory)+'</p>'+
          '<p>'+esc(fa?'فایل systemd: ':'Systemd unit: ')+txt(d.unit_file)+'</p>'+
          '<p>'+esc(fa?'نوع سرویس: ':'Service Type: ')+txt(d.service_type)+
          ' · '+esc(fa?'مهلت Start (µs): ':'Start timeout (µs): ')+txt(d.timeout_start_usec)+'</p>'+
          '<p><strong>'+esc(fa?'نتیجهٔ بررسی Syntax JSON: ':'JSON syntax validation: ')+
        esc(syntaxChecked?.status==='syntax_valid'?(fa?'تمام فایل‌های بررسی‌شده صحیح؛ فقط از نظر Syntax':'All checked JSON files have valid syntax only'):
          syntaxChecked?.status==='invalid'?(fa?'حداقل یک فایل JSON سینتکس نامعتبر دارد':'One or more JSON files have invalid syntax'):
          syntaxChecked?.status==='partial'?(fa?'بررسی بخشی از فایل‌ها ناقص است':'Partial syntax check'):
          state.liveDotnetSyntaxStatus==='checking'?(fa?'در حال بررسی زنده از VM MCP…':'Checking live via VM MCP…'):
          state.liveDotnetSyntaxStatus==='unavailable'?(fa?'بررسی زنده ناموفق؛ جزئیات MCP را بررسی کنید':'Live check failed; inspect MCP evidence'):
          d.syntax_status==='syntax_valid'?(fa?'در زمان رخداد صحیح؛ فقط از نظر Syntax':'Syntax valid when collected'):
          d.syntax_status==='invalid'?(fa?'در زمان رخداد نامعتبر':'Invalid when collected'):
          fa?'تاکنون نتیجهٔ Syntax ثبت نشده است':'Syntax has not been checked')+
        '</strong></p>'+
      (syntaxRows.length?
        '<ul class="ic-agent-bullets">'+syntaxRows.map(row=>
          '<li><code dir="ltr">'+txt(row.file)+'</code>: '+
          esc(dotnetSyntaxLabel(row,fa))+
          (row.status==='invalid_json_syntax'&&row.line?
            ' · '+esc(fa?'خط ':'Line ')+num(row.line)+
            '، '+esc(fa?'ستون ':'Column ')+num(row.column):'')+
          (row.reason?' · <code>'+txt(row.reason)+'</code>':'')+
          '</li>').join('')+'</ul>':'')+
      (syntaxChecked?.checked_at?
        '<p class="ic-meta">'+esc(fa?'زمان بررسی زنده: ':'Live check: ')+date(syntaxChecked.checked_at)+'</p>':'')+
          (files.length?'<ul class="ic-agent-bullets">'+files.map(f=>
            '<li>'+txt(f.file)+' — '+txt(f.status)+
            (Number.isInteger(f.line)?' · '+esc(fa?'خط ':'line ')+num(f.line):'')+
            (Number.isInteger(f.column)?' · '+esc(fa?'ستون ':'column ')+num(f.column):'')+
            '</li>').join('')+'</ul>':'')+
          '<p class="ic-agent-disclaimer">'+esc(fa?
            'فقط Syntax JSON بررسی شده؛ محتوای تنظیمات و Secretها منتقل نشده‌اند. صحت راه‌اندازی برنامه و تنظیمات معنایی هنوز تأیید نشده است.':
            'JSON syntax only. No config contents or secrets were transferred. Startup readiness and semantic configuration are unverified.')+
          '</p>'+refs([d.runtime_evidence_ref,d.syntax_evidence_ref].filter(Boolean))+'</article>';
      })():'')+
      (kb.query?'<article class="ic-detail-card"><h4>'+esc(fa?'جست‌وجوی مجدد هدفمند در Cognia':'Focused Cognia re-query')+
        '</h4><p>'+txt(kb.query)+'</p><p>'+esc(fa?'وضعیت: ':'Status: ')+txt(kb.status||'unknown')+
        '</p><p>'+esc(fa?'منابع بازیابی‌شده:':'Retrieved sources:')+'</p>'+refs(kb.source_refs)+
        '<p>'+esc(fa?'منابعی که LLM صریحاً در برنامهٔ تحقیق استفاده کرده:':'Source refs explicitly used by LLM planning:')+
        '</p>'+(arr(p.used_knowledge_refs).length?refs(p.used_knowledge_refs):
          '<p>'+esc(fa?'استفادهٔ مستند ثبت نشده است.':'No evidenced use reported.')+'</p>')+
        '</article>':'')+
      (checks.length?'<article class="ic-detail-card"><h4>'+esc(fa?'بررسی‌های Read-only پیشنهادی':'Proposed read-only checks')+
        '</h4><p>'+checks.map(txt).join('، ')+'</p></article>':'')+
      (questions.length?'<article class="ic-detail-card"><h4>'+esc(fa?'سؤال یا اطلاعات موردنیاز از اپراتور':'Information requested from operator')+
        '</h4><ul class="ic-agent-bullets">'+questions.map(q=>
        '<li>'+txt(q.question)+'<p>'+txt(q.reason)+'</p>'+refs(q.evidence_refs)+'</li>').join('')+
        '</ul><p class="ic-agent-disclaimer">'+esc(fa?
          'این درخواست‌ها هنوز به گردش‌کار پاسخ تعاملی و Resume متصل نیستند. برای ثبت پاسخ، از فرایند مجاز رخداد استفاده کنید.':
          'Operator replies and resume are not yet wired to this proposal interface.')+
        '</p></article>':'')+
      '<p class="ic-empty">'+esc(fa?
        'تأیید اجرای تغییر غیرفعال است: Patch معتبر، Diff، تست ایزوله و قرارداد اجرایی هنوز موجود نیستند.':
        'Execution approval is unavailable: no verified patch, diff, isolated test or execution contract exists.')+'</p>';
    show('#ic-proposed-fix',recoveryMarkup+body);
  }

  function renderOutcome(r) {
    const o=r.execution_outcome||{},v=r.verification_result||{},learn=r.knowledge_learning_status||{},a=r.approval_readiness||{};
    const performed=o.status && !['not_executed','not_recorded','unknown'].includes(low(o.status));
    const consumed=low(a.approval_status)==='consumed';
    const running=consumed && state.lifecycle?.analysis_in_progress===true;
    if(!o.action&&!performed&&!running&&!consumed&&r.memory_investigation){
      const recovered=r.memory_investigation.alert?.recovery_received;
      show('#ic-outcome-view','<p class="ic-empty">'+esc(state.language==='fa'?
        'هیچ اقدامی توسط AIOps اجرا نشده است. '+(recovered?
        'پیام Recovery زبیکس دریافت شده، اما علت کاهش RAM یا موفقیت یک اصلاح عملیاتی ثابت نشده است.':
        'بازگشت مصرف RAM هنوز مستقل تأیید نشده است.'):
        'No AIOps action was executed. '+(recovered?
        'Zabbix recovery was received; root cause and operational repair remain unverified.':
        'Independent recovery is unverified.'))+'</p>');return;
    }
    if(!o.action&&!performed&&!running&&!consumed){
      show('#ic-outcome-view','<p class="ic-empty">'+esc(state.language==='fa'?
        'هیچ عملیاتی اجرا نشده است. بنابراین نتیجه اجرا، Verification و یادگیری پس از اجرا قابل اعمال نیستند.':
        'No operation was executed. Execution result, verification and post-execution learning are not applicable.')+'</p>');
      return;
    }
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
    const a=r.approval_readiness||{},x=r.remediation_recommendation||{};
    const durable=state.lifecycle?.approval||{};
    const statusValue=low(durable.status||a.approval_status);
    const archived=!!state.historic;
    const pending=statusValue==='pending', approved=statusValue==='approved';
    const completed=low(state.lifecycle?.checkpoint_status)==='completed';
    const durableBound=durable.metadata?.binding_complete===true||
      low(durable.metadata?.binding_complete)==='true';
    // A consumed approval is intentionally one-time. Snapshot changes from
    // actual execution/verification must never be shown as a NEW approval drift.
    const snapshotBad=(pending||approved)&&
      (a.evidence_snapshot_binding==='drift_detected'||a.status==='new_approval_required');
    const binding=Boolean(a.binding_complete)&&!snapshotBad;
    const executed=low(r.execution_outcome?.status)==='success';
    const verified=['success','verified','succeeded'].includes(low(r.verification_result?.status));
    const executing=statusValue==='consumed' && state.lifecycle?.analysis_in_progress===true;
    let heading=statusValue==='pending_validation'
      ?(state.language==='fa'?'درخواست تغییر در صف Approval، منتظر اعتبارسنجی مستقل':'Configuration change queued, awaiting independent validation'):
      pending?tr('approvalPending'):approved?tr('approvalApproved'):
      executing?(state.language==='fa'?'در حال اجرای عملیات تأییدشده':'Approved execution in progress'):
      statusValue==='consumed' && executed && verified
        ?(state.language==='fa'?'بازیابی سرویس تأیید شد':'Service recovery verified'):
      statusValue==='consumed'
        ?(state.language==='fa'?'مجوز مصرف شده؛ نتیجهٔ عملیات را بررسی کنید':'Approval consumed; review execution outcome'):
      tr('approvalFinished');
    if(archived)heading=tr('historical');
    const detail=archived?tr('archiveHint'):statusValue==='consumed'
      ?(state.language==='fa'?'این مجوز یک‌بار مصرف شده و اجرای مجدد فقط با مجوز جدید ممکن است.':'This approval has already been consumed and cannot authorize a second execution.')
      :statusValue==='pending_validation'
        ?(state.language==='fa'?'درخواست معتبر ثبت شده اما هنوز مجوز اجرا نیست؛ تأیید نهایی تا تکمیل اعتبارسنجی ایزوله مسدود است.':'Change is queued, not executable. Final approval requires isolated validation.')
      :pending?tr('approvalSeparate'):tr('execBound');
    show('#ic-action-state','<div class="ic-decision-status"><strong>'+esc(heading)+'</strong><p>'+
      esc(detail)+'</p>'+
      pill(statusValue)+'</div><div class="ic-mini-facts">'+
      mini('action',statusValue==='pending_validation'?(state.language==='fa'?'اصلاح کانفیگ':'Repair configuration'):humanAction(a.action||x.action))+mini('target',durable.metadata?.target||a.target||x.target)+mini('risk',status(x.risk_level))+
      mini('tool',humanTool(a.tool||x.tool))+mini('freshness',status(a.data_freshness))+
      mini('approvalId',durable.approval_id||a.approval_id)+'</div>');
    const recoveryApproval=state.recoveryApproval||{};
    const recoveryStatus=low(recoveryApproval.status);
    if(!archived&&UUID.test(String(recoveryApproval.approval_id||''))&&
       ['pending','approved','consumed','rejected'].includes(recoveryStatus)&&
       // A recovery approval has its OWN signed execution contract. Do not
       // bury it behind an unrelated paused E2E workflow approval: otherwise
       // the operator is directed to workflow/resume and receives 409
       // approval_not_granted even though Start itself is approved.
       (['pending','approved','consumed'].includes(recoveryStatus)||
         !['pending','approved','pending_validation'].includes(statusValue))){
      const fa=state.language==='fa';
      const recoveryLabel=recoveryApproval.action==='restart_service'?
        (fa?'ری‌استارت سرویس':'Restart service'):
        (fa?'شروع سرویس':'Start service');
      const message=recoveryStatus==='pending'?
        (fa?'درخواست بازیابی در صف Approval؛ منتظر تأیید شماست':
          'Recovery request is waiting for your approval'):
        recoveryStatus==='approved'?
        (fa?recoveryLabel+' تأیید شده؛ هنوز اجرا نشده است':
          recoveryLabel+' authorized; not yet executed'):
        recoveryStatus==='consumed'?
        (fa?'مجوز مصرف شده؛ نتیجه و راستی‌آزمایی را بررسی کنید':
          'Authorization consumed; inspect execution and verification'):
        (fa?'درخواست بازیابی رد شده است':'Recovery request rejected');
      show('#ic-action-state','<div class="ic-decision-status"><strong>'+
        esc(message)+'</strong><p>'+esc(fa?
          'این مجوز فقط به سرویس و سرور شناسایی‌شده متصل است. هر اجرا مجدداً از Runbook و بررسی زنده عبور می‌کند.':
          'The authorization is target- and service-bound; execution has fresh runbook gates.')+
        '</p>'+pill(recoveryStatus)+'</div><div class="ic-mini-facts">'+
        mini('action',recoveryLabel)+mini('target',recoveryApproval.target)+
        mini('risk',fa?'زیاد':'High')+
        mini('tool','VM MCP / SSH')+
        mini('approvalId',recoveryApproval.approval_id)+'</div>');
      const separateWorkflow=UUID.test(String(durable.approval_id||''))&&
        String(durable.approval_id)!==String(recoveryApproval.approval_id)&&
        ['pending','approved','pending_validation'].includes(statusValue);
      let controls=(separateWorkflow?
        '<p class="ic-warning" role="status">'+esc(fa?
          'دو مجوز متفاوت وجود دارد: Approval گردش‌کار تحلیل برای اجرای Start معتبر نیست. فقط مجوز بازیابی سرویسِ نمایش‌داده‌شده در این بخش می‌تواند Start/Restart را اجرا کند.':
          'Two different approvals exist: the analysis-workflow approval cannot authorize Start. Use the service recovery approval shown here.')+
        '</p>':'')+
        '<p class="ic-agent-disclaimer">'+esc(fa?
          'تأیید و اجرای Start/Restart دو مرحلهٔ مجزا هستند. هر دو مرحله فقط از مسیر مجوز متصل به همین سرویس/سرور انجام می‌شوند؛ قبل از Start وضعیت زنده و سینتکس کانفیگ بررسی می‌شود.':
          'Recovery approval and execution are separate governed operations. Live systemd state and config are checked before any Start/Restart.')+'</p>';
      if(recoveryStatus==='pending'){
        controls+='<button type="button" class="ic-btn ic-btn-primary" data-recovery-approval="approve-execute">'+
          esc(fa?'تأیید و اجرای واقعی '+recoveryLabel:'Approve & execute '+recoveryLabel)+'</button> '+
          '<button type="button" class="ic-btn ic-btn-muted" data-recovery-approval="approve">'+
          esc(fa?'فقط تأیید (بدون اجرا)':'Approve only (no execution)')+'</button> '+
          '<button type="button" class="ic-btn ic-btn-muted" data-recovery-approval="reject">'+
          esc(fa?'رد درخواست':'Reject request')+'</button>';
      }else if(recoveryStatus==='approved'){
        controls+='<button type="button" class="ic-btn ic-btn-danger" data-recovery-approval="execute">'+
          esc(fa?'اجرای '+recoveryLabel+' پس از بررسی زنده':'Execute '+recoveryLabel+' after live preflight')+'</button>';
      }
      show('#ic-action-checks','');
      show('#ic-action-controls',controls);
      return;
    }
    if(!archived&&recoveryStatus==='state_changed_active'&&
       !['pending','approved','pending_validation'].includes(statusValue)){
      const fa=state.language==='fa';
      show('#ic-action-state','<div class="ic-decision-status" role="status"><strong>'+
        esc(recoveryApprovalStatusLabel(recoveryApproval,fa))+'</strong><p>'+
        esc(recoveryApprovalSafetyNote(fa))+'</p>'+
        '<p class="ic-meta"><code>409 · recovery_live_binding_or_state_changed</code></p>'+
        '</div><div class="ic-mini-facts">'+
        mini('action',fa?'Restart لغو شد':'Restart not queued')+
        mini('target',r.recovery_advisory?.target)+
        mini('service',r.recovery_advisory?.service)+
        mini('approvalId',fa?'صادر نشده':'Not issued')+'</div>');
      show('#ic-action-checks','');
      show('#ic-action-controls','<p class="ic-agent-disclaimer">'+
        esc(fa?'برای تصمیم جدید، ابتدا «بررسی مجدد وضعیت سرویس» را اجرا و نتیجه HTTP Health و Zabbix را بررسی کنید.':
          'Run a new read-only service-status check, then verify HTTP health and the Zabbix recovery signal before making another decision.')+'</p>');
      return;
    }
    const configApproval=durable.metadata?.workflow==='config_change' &&
      ['pending_validation','pending','approved','consumed'].includes(statusValue);
    if(configApproval && !archived){
      const fa=state.language==='fa';
      const syntaxOnly=['generic_json_syntax_only_service_runtime_unverified',
        'generic_xml_syntax_only_service_runtime_unverified'].includes(durable.metadata?.validation_scope);
      const syntaxFormat=durable.metadata?.validation_scope==='generic_xml_syntax_only_service_runtime_unverified'?'XML':'JSON';
      let controls='<p class="ic-agent-disclaimer">'+esc(fa?
        'این تأیید صرفاً برای تغییر فایل مشخص با دو هش ثبت‌شده است. اعمال کانفیگ از مسیر ایمن VM MCP انجام می‌شود؛ Start یا Restart مجوز جداگانه می‌خواهد.':
        'This approval is bound to one config file and its hashes. Service start/restart requires a separate approval.')+'</p>';
      if(syntaxOnly){
        controls+='<p class="ic-warning">'+esc(fa?
          'تأیید فنی این فایل فقط صحت ساختار '+syntaxFormat+' است؛ سلامت منطق برنامه، وابستگی‌ها و Runtime سرویس ثابت نشده و Start/Restart جداگانه نیازمند تأیید است.':
          syntaxFormat+' grammar only: application semantics, dependencies and service runtime remain unverified. A separate approval is required for service recovery.')+'</p>';
      }
      if(statusValue==='pending_validation'){
        const failure=state.configResponse?.validation_reason||durable.metadata?.validation_last_reason;
        if(failure){
          const code=String(failure).slice(0,100);
          const exit=state.configResponse?.guard_exit_code??durable.metadata?.validation_last_exit_code;
          controls+='<p class="ic-warning" role="alert"><strong>'+esc(fa?'اعتبارسنجی مسدود شد':'Isolated validation blocked')+'</strong> '+
            esc(fa?guardReasonFA(code):code)+' <code>'+esc(code)+'</code>'+
            (Number.isInteger(exit)?' (exit '+esc(exit)+')':'')+'</p>';
        }
        controls+='<div class="ic-action-buttons"><button type="button" class="ic-btn ic-btn-primary" data-config-approval-action="validate"'+(state.busy?' disabled':'')+'>'+
          esc(fa?'اجرای اعتبارسنجی ایزوله و آماده‌سازی Approval':'Run isolated validation')+'</button>'+
          '<button type="button" class="ic-btn ic-btn-danger" data-config-approval-action="reject"'+(state.busy?' disabled':'')+'>'+
          esc(fa?'رد درخواست تغییر':'Reject config change')+'</button></div>';
      }else if(statusValue==='pending'){
        controls+='<p>'+esc(syntaxOnly?
          (fa?'نسخه پیشنهادی فقط از نظر سینتکس '+syntaxFormat+' بررسی شده است و منتظر تأیید صریح شماست.':'Staged '+syntaxFormat+' grammar check passed; application runtime is unverified.'):
          (fa?'نسخه پیشنهادی با Validator سرویس در فضای جداگانه بررسی شده و اکنون منتظر تأیید صریح شماست.':'Isolated vendor validation passed; human approval is required.'))+'</p>'+
          '<button type="button" class="ic-btn ic-btn-primary" data-config-approval-action="approve"'+(state.busy?' disabled':'')+'>'+
          esc(fa?(state.configResponse?.start_service_after_apply?
            'تأیید اصلاح و شروع خودکار سرویس پس از اعمال':'تأیید اصلاح کانفیگ — بدون اجرا'):
            (state.configResponse?.start_service_after_apply?
            'Approve config repair + automatic service start':'Approve configuration change'))+'</button>';
      }else if(statusValue==='approved'){
        controls+='<button type="button" class="ic-btn ic-btn-primary" data-config-approval-action="execute"'+(state.busy?' disabled':'')+'>'+
          esc(fa?(state.configResponse?.start_service_after_apply?
            'اعمال اصلاح، شروع سرویس و بررسی نتیجه':'اعمال اصلاح تأییدشده و بررسی نتیجه'):
            (state.configResponse?.start_service_after_apply?
            'Apply, start service and verify':'Apply approved config and verify'))+'</button>';
      }else{
        controls+='<p>'+esc(fa?'مجوز یک‌بارمصرف مصرف شده است. نتیجه و ممیزی عملیات را در تاریخچه بررسی کنید.':'One-time approval consumed; inspect the execution audit.')+'</p>';
        const failedAfterConfig=state.configResponse?.start_service_after_apply!==true &&
          state.serviceStatus?.verified_systemd_only===true &&
          ['failed','inactive'].includes(low(state.serviceStatus?.active_state)) &&
          low(state.serviceStatus?.service).replace(/\.service$/,'')===
            low(state.report?.incident_summary?.service).replace(/\.service$/,'');
        if(failedAfterConfig){
          controls+='<p class="ic-warning critical">'+esc(fa?
            'فایل اصلاح شده اما Approval قبلی فقط اجازه تغییر کانفیگ داشته است؛ Start/Restart صادر نشده و امکان افزودن مجوز به تیکت مصرف‌شده وجود ندارد. از چت همین رخداد درخواست «راه‌اندازی مجدد سرویس» بدهید تا درخواست Approval جداگانه با کنترل زنده ایجاد شود.':
            'The configuration Approval was config-only and has been consumed. Start/restart requires a NEW signed approval. Request service recovery from this incident chat; live preflight is required.')+'</p>';
        }
      }
      show('#ic-action-checks','');
      show('#ic-action-controls',controls);
      return;
    }
    if(archived) {
      show('#ic-action-checks','');
      show('#ic-action-controls','<p class="ic-warning critical">'+tr('archiveHint')+'</p>'+
        '<button type="button" class="ic-btn ic-btn-primary" id="ic-archive-action-return">'+tr('returnLive')+'</button>');
      return;
    }
    const liveSnapshot=state.report?.snapshot_id===r.snapshot_id;
    const acknowledged=state.reviewedSnapshot===r.snapshot_id;
    const canAct=Boolean(a.approval_id&&binding&&liveSnapshot);
    // A standalone approval on a completed incident is distinct from the
    // completed analysis snapshot. Execution remains bound to a durable
    // approved intent and undergoes fresh server-side safety checks.
    const canExecute=completed
      ?Boolean(approved&&UUID.test(String(durable.approval_id||''))&&durableBound&&!state.busy)
      :Boolean(canAct&&acknowledged&&!state.busy);
    show('#ic-action-checks',pending||(approved&&!completed)?'<label class="ic-checkbox-row"><input id="ic-check" type="checkbox"'+
      (acknowledged?' checked':'')+(state.busy?' disabled':'')+'><span>'+
      esc(pending?tr('reviewCheckbox'):tr('resumeCheckbox'))+'</span></label>':'');
    let controls='';
    if(snapshotBad)controls+='<p class="ic-action-error">'+tr('drift')+'</p>';
    else if(!binding&&(pending||approved))controls+='<p class="ic-action-error">'+tr('noBinding')+'</p>';
    if(statusValue==='pending_validation'){
      controls+='<p class="ic-warning">'+esc(state.language==='fa'
        ?'درخواست این تغییر ثبت شده است؛ تا اعتبارسنجی مستقل و قرارداد اجرای امن آماده نشود، امکان تأیید یا اعمال آن وجود ندارد.'
        :'This ticket is registered. Approve and Apply remain disabled until isolated validation and an execution contract are available.')+'</p>';
    }else if(pending){
      controls+='<div class="ic-action-buttons"><button type="button" id="ic-approve" class="ic-btn ic-btn-primary"'+
        (!canAct||!acknowledged||state.busy?' disabled':'')+'>'+esc(state.busy?tr('processing'):tr('approveOnly'))+'</button>'+
        '<button type="button" id="ic-toggle-reject" class="ic-btn ic-btn-danger"'+(state.busy?' disabled':'')+'>'+tr('reject')+'</button></div>'+
        (state.rejectionVisible?'<div class="ic-reject-box"><label for="ic-reject-reason">'+tr('rejectReason')+
        '</label><textarea id="ic-reject-reason" placeholder="'+esc(tr('rejectHint'))+'" maxlength="1000"></textarea>'+
        '<button type="button" id="ic-confirm-reject" class="ic-btn ic-btn-danger"'+(state.busy?' disabled':'')+'>'+tr('confirmReject')+'</button></div>':'');
    }else if(approved){
      // A chat/manual approval can be created after incident analysis is
      // completed. It must execute by approval ID, never resume that graph.
      const executeLabel=completed
        ?(state.language==='fa'?'اجرای واقعی '+humanAction(a.action||x.action)
          :'Execute approved '+humanAction(a.action||x.action))
        :tr('resume');
      controls+='<p class="ic-warning">'+esc(state.language==='fa'
        ?'مجوز تأیید شده اما هنوز هیچ فرمانی روی سرور اجرا نشده است. اجرای عملیات یک مرحلهٔ مستقل با بررسی زندهٔ مجدد است.'
        :'Approval was granted but no server command has run. Execution is a separate, freshly verified step.')+'</p>'+
        '<div class="ic-action-buttons"><button type="button" id="ic-resume" class="ic-btn ic-btn-primary"'+
      (!canExecute?' disabled':'')+'>'+esc(state.busy?tr('processing'):executeLabel)+'</button></div>';
    }else {
      controls+='<p class="ic-empty">'+tr('approvalNoRecord')+'</p>';
    }
    show('#ic-action-controls',controls);
  }
  function render() {
    if(!state.report)return;
    const r=state.historic||state.report;
    $('#ic-archive-banner').hidden=!state.historic;
    renderHero(r);renderServiceStatus();renderServiceProfile();renderConfigActionBanner(r);renderOverview(r);renderReview(r);renderAnalysis(r);renderEvidence(r);
    renderKnowledge(r);renderInvestigation(r);renderOutcome(r);renderTimeline(r);renderDecision(r);renderReceivedSignals();
    renderIncidentChat();
    renderAnalysisProgress();
    $('#ic-snapshot-label').textContent='Snapshot '+String(r.snapshot_id||'').slice(0,14);
  }
  function renderIncidentChat() {
    const fa=state.language==='fa';
    const zone=$('#ic-chat-thread'),form=$('#ic-chat-form'),statusNode=$('#ic-chat-status');
    if(!zone||!form||!statusNode)return;
    const archive=Boolean(state.historic),loading=state.chatBusy||state.chatStatus==='loading';
    const blocked=archive||state.lifecycle?.analysis_in_progress;
    $('#ic-chat-message').disabled=Boolean(blocked||state.chatBusy);
    $('#ic-chat-send').disabled=Boolean(blocked||state.chatBusy||state.chatStatus==='failed');
    form.setAttribute('aria-busy',String(loading));
    const items=arr(state.chat?.items),approvals=state.chat?.approvals||{};
    const head=state.chatStatus==='loading'?
      empty(fa?'در حال بارگذاری تاریخچه همین رخداد…':'Loading incident conversation…'):
      state.chatStatus==='failed'?
      empty(fa?'چت فعلاً در دسترس نیست یا تحلیل تمام نشده است.':'Incident chat is unavailable or analysis has not finished.'):
      items.length?'':empty(fa?'برای شروع، درباره شواهد همین رخداد سؤال کن.':'Ask about this incident to start a conversation.');
    const lines=items.map(m=>{
      const assistant=m.role==='assistant',prop=m.proposal||{},approval=approvals[m.id]||{};
      let control='';
      if(assistant&&prop.status==='requires_preflight_and_approval'){
        control='<div class="ic-chat-action">'+
          '<p><strong>'+esc(fa?'اقدام پیشنهادی':'Suggested action')+': </strong>'+
            txt(prop.action)+' · '+txt(prop.service)+' @ '+txt(prop.target)+'</p>'+
          '<p>'+esc(fa?
            'قبل از ایجاد درخواست Approval، وضعیت سرویس و کانفیگ به‌صورت زنده دوباره بررسی می‌شوند.':
            'Live service/configuration preflight is required before creating an approval.')+'</p>'+
          (!approval.approval_id?
            '<button class="ic-btn ic-btn-primary" type="button" data-chat-request="'+txt(m.id)+'"'+
            (blocked||state.chatBusy?' disabled':'')+'>'+
              esc(fa?'درخواست تأیید این اقدام':'Request approval for this action')+'</button>':
            '<p>'+esc(fa?'وضعیت مجوز: ':'Approval status: ')+txt(approval.status)+
            ' · '+txt(approval.approval_id)+'</p>'+
            (low(approval.status)==='pending'?
              '<button class="ic-btn ic-btn-primary" type="button" data-chat-approve="'+txt(approval.approval_id)+'"'+
              (blocked||state.chatBusy?' disabled':'')+'>'+esc(fa?'تأیید مجوز (بدون اجرا)':'Approve (no execution)')+'</button>':'')+
            (low(approval.status)==='approved'?
              '<button class="ic-btn ic-btn-danger" type="button" data-chat-execute="'+txt(approval.approval_id)+'"'+
              (blocked||state.chatBusy?' disabled':'')+'>'+esc(fa?'اجرای عملیات تأییدشده':'Execute approved operation')+'</button>':''))+
          '<p class="ic-agent-disclaimer">'+esc(fa?
            'دستور اجرا فقط با مجوز مستقل، احراز هویت و بررسی مجدد پیش‌شرط‌ها انجام می‌شود.':
            'Execution requires separate authentication, approval and fresh live preconditions.')+'</p>'+
          '</div>';
      }
      const modelLabel=m.model_status==='structured'?
        (fa?'LLM فعال':'LLM used'):
        m.model_status==='unavailable'?
        (fa?'پاسخ جایگزین؛ LLM ناموفق':'Fallback; LLM unavailable'):'';
      const sourceLabel=m.answer_basis==='stored_analysis'?
        (fa?'شواهد تحلیل ثبت‌شده':'Recorded incident evidence'):
        m.answer_basis==='stored_analysis_live_unavailable'?
        (fa?'بررسی زنده ناموفق؛ شواهد قبلی':'Live check unavailable; prior evidence'):
        m.answer_basis==='live_mcp'?
        (fa?'بررسی زنده VM MCP':'Live VM MCP'):
        m.answer_basis==='stored_analysis_guarded'?
        (fa?'ادعای بدون شاهد LLM کنار گذاشته شد':'Unsupported LLM claim rejected'):
        m.answer_basis==='stored_elasticsearch_evidence'?
        (fa?'گزارش ثبت‌شده Elasticsearch':'Saved Elasticsearch evidence'):
        m.answer_basis==='live_elasticsearch_mcp'?
        (fa?'استعلام واقعی Elasticsearch MCP':'Live Elasticsearch MCP'):
        m.answer_basis==='elastic_mcp_unavailable'?
        (fa?'Elasticsearch MCP ناموفق':'Elasticsearch MCP failed'):'';
      return '<article class="ic-chat-bubble '+(assistant?'ic-chat-assistant':'ic-chat-user')+'">'+
        '<div class="ic-chat-bubble-head"><strong>'+esc(assistant?(fa?'دستیار AIOps':'AIOps copilot'):(fa?'اپراتور':'Operator'))+
        '</strong><small>'+txt(date(m.created_at))+'</small></div>'+
        (assistant&&(modelLabel||sourceLabel)?
          '<small class="ic-chat-provenance">'+esc([modelLabel,sourceLabel].filter(Boolean).join(' · '))+'</small>':'')+
        '<p dir="auto">'+txt(m.message)+'</p>'+
        (arr(m.source_refs).length?refs(m.source_refs):'')+control+'</article>';
    }).join('');
    zone.innerHTML=head+lines;
    statusNode.textContent=archive?
      (fa?'نسخه تاریخی فقط قابل مشاهده است؛ برای چت به نسخه فعلی برگردید.':'Archived version: return to current to chat.'):
      state.lifecycle?.analysis_in_progress?
      (fa?'چت بعد از پایان تحلیل فعال می‌شود.':'Chat is enabled once analysis finishes.'):
      state.chatBusy?(fa?'در حال بررسی و ثبت پاسخ…':'Investigating and recording response…'):
      state.chatLastResult || (fa?'پاسخ‌ها در تاریخچه ممیزی همین رخداد ثبت می‌شوند.':
                                    'Conversation turns are retained in this incident audit.');
  }
  async function loadIncidentChat(token=state.loadingToken) {
    state.chatStatus='loading';renderIncidentChat();
    try{
      const data=await api(base+'/chat');
      if(token!==state.loadingToken)return;
      state.chat=data;state.chatStatus='ready';
    }catch(e){
      if(token!==state.loadingToken)return;
      state.chatStatus='failed';
    }
    renderIncidentChat();
  }
  async function submitIncidentChat(value) {
    const message=String(value||'').trim();
    if(!message||state.chatBusy||state.historic||state.lifecycle?.analysis_in_progress)return;
    state.chatBusy=true;state.chatLastResult=null;renderIncidentChat();
    try {
      const result=await api(base+'/chat',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({message})});
      $('#ic-chat-message').value='';
      await loadIncidentChat();
      if(result.followup_integration?.evidence_ref){
        state.chatLastResult=result.followup_integration.reassessed?
          'شاهد جدید ثبت شد؛ تحلیل ایجنت‌ها و ارزیابی به‌روز شدند.':
          'شاهد جدید ثبت شد؛ وضعیت تحلیل تکمیلی را در گزارش بررسی کنید.';
        // Refresh the Decision Brief and lifecycle instead of showing a stale
        // snapshot after new persisted Evidence changes the report digest.
        await load();
      }
    }catch(e){
      const message=String(e.message||'');
      const pending=/409|incident_analysis_not_finished/.test(message);
      state.chatLastResult=pending?
        (state.language==='fa'?
          'تحلیل رخداد هنوز تکمیل نشده است؛ پس از اتمام تحلیل، بررسی را دوباره اجرا کنید.':
          'Incident analysis is still running. Retry after it completes.'):
        message;
      notify(tr('failure')+' · '+state.chatLastResult,true);
    }
    finally{state.chatBusy=false;renderIncidentChat();}
  }
  async function incidentChatApproval(kind,id) {
    if(state.chatBusy||state.historic||!UUID.test(id))return;
    const fa=state.language==='fa';
    const caution=kind==='request'?
      (fa?'برای ایجاد درخواست Approval، بررسی زنده اجرا می‌شود؛ هنوز سرویس تغییر نمی‌کند. ادامه؟':
          'Fresh preflight precedes approval creation. No operation executes yet. Continue?'):
      kind==='approve'?
      (fa?'آیا مجوز این اقدام با ریسک بالا را تأیید می‌کنید؟ هنوز اجرا نمی‌شود.':
          'Approve this high-risk change authorization? Nothing executes yet.'):
      (fa?'این دکمه ممکن است سرویس Production را تغییر دهد. آیا اجرای اقدام تأییدشده را می‌پذیرید؟':
          'This may change a production service. Execute the approved action now?');
    if(!confirm(caution))return;
    state.chatBusy=true;renderIncidentChat();
    try{
      let response;
      if(kind==='request')response=await api(base+'/chat/request-approval',{
        method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({proposal_id:id})
      });
      else if(kind==='approve')response=await api('/api/v1/approvals/'+encodeURIComponent(id)+'/approve',{method:'POST'});
      else response=await api('/api/v1/approvals/'+encodeURIComponent(id)+'/execute',{method:'POST'});
      state.chatLastResult=kind==='execute'?
        (fa?'درخواست اجرای مجاز ارسال شد. نتیجه اجرا و راستی‌آزمایی را در بخش نتیجه اجرا بررسی کنید.':
            'Authorized execution submitted. Review the execution and verification results.'):
        kind==='approve'?
        (fa?'مجوز تأیید شد، ولی سرویس هنوز Restart نشده است؛ اکنون دکمهٔ «اجرای عملیات تأییدشده» را بزنید.':
            'Approval granted; the service has NOT restarted. Press Execute approved operation.'):
        (fa?'درخواست تأیید ثبت شد؛ سرویس هنوز تغییر نکرده است.':
            'Approval requested; no service change has occurred.');
      await load();
      await loadIncidentChat();
      if(kind==='execute'){
        // A governed Start/Restart may change the service after the cached
        // Decision Brief was produced. Recheck the live bound VM immediately.
        await recheckServiceStatus();
        notify(state.chatLastResult);
      }
    }catch(e){state.chatLastResult=e.message;notify(tr('failure')+' · '+e.message,true);}
    finally{state.chatBusy=false;renderIncidentChat();}
  }
  async function configApprovalAction(kind){
    const record=state.lifecycle?.approval||{};
    const id=record.approval_id,workflow=record.metadata?.workflow;
    const status=low(record.status),allowed={validate:'pending_validation',reject:'pending_validation',approve:'pending',execute:'approved'};
    if(state.busy||state.historic||!UUID.test(String(id||''))||workflow!=='config_change'||status!==allowed[kind])return;
    const fa=state.language==='fa';
    const scopedStart=record.metadata?.start_service_after_apply===true;
    const descriptions={
      validate:'اعتبارسنجی کپی کانفیگ در فضای جداگانه اجرا شود؟ هیچ تغییر Production انجام نمی‌شود.',
      reject:'درخواست تغییر کانفیگ را رد می‌کنید؟',
      approve:scopedStart?
        'آیا اصلاح کانفیگ و سپس یک بار Start خودکار سرویس در صورت موفقیت اصلاح را تأیید می‌کنید؟ هنوز عملیاتی اجرا نمی‌شود.':
        'این اصلاح دقیق کانفیگ را تأیید می‌کنید؟ تأیید به‌تنهایی هیچ فایلی تغییر نمی‌دهد.',
      execute:scopedStart?
        'این اجرا فایل کانفیگ را اصلاح می‌کند و پس از اعتبارسنجی موفق، در صورت توقف سرویس یک بار آن را Start می‌کند. درستی سرویس دوباره بررسی می‌شود. تأیید می‌کنید؟':
        'تأیید می‌کنید نسخه مشخص‌شده با هش ثابت روی سرور اعمال شود؟ در صورت شکست، بازگردانی انجام می‌شود. این عملیات پرریسک است.'
    };
    if(!confirm(fa?descriptions[kind]:{
      validate:'Validate the staged candidate without any production write?',
      reject:'Reject the config change request?',
      approve:scopedStart?'Approve both config repair and one post-apply systemd start?':
        'Approve this exact configuration change without applying yet?',
      execute:scopedStart?'Apply verified configuration and start the stopped service once?':
        'Apply the approved hash-bound config to production with verification and rollback?'
    }[kind]))return;
    if(kind==='execute'&&!confirm(fa?
      (scopedStart?'تأیید دوم: فایل Production تغییر می‌کند و در صورت موفقیت، یک بار Start سرویس انجام خواهد شد.':
        'تأیید دوم: این مرحله واقعاً فایل کانفیگ روی سرور را تغییر می‌دهد.') :
      (scopedStart?'Second confirmation: production config will change and the stopped service may start once.':
        'Second confirmation: this will modify the production configuration.')))return;
    state.busy=true;renderDecision(state.report);
    const route={validate:'validate-config',reject:'reject-config',approve:'approve',execute:'execute-config'}[kind];
    try{
      const value=await api('/api/v1/approvals/'+encodeURIComponent(id)+'/'+route,{method:'POST'});
      const incidentResolutionNote=kind==='execute'&&
        value.incident_resolved===true?
        (fa?'؛ رفع رخداد با راستی‌آزمایی مستقل VM ثبت شد.':
            '; incident resolved by independent VM verification.'):'';
      const recoveryNote=kind==='execute'&&scopedStart?
        (value.service_recovery_confirmed===true?
          (value.incident_resolved===true?
            (fa?'؛ سرویس Running و رخداد با دو بررسی مستقل رفع شد.':
                '; systemd running and incident independently resolved.') :
            (fa?'؛ سرویس Running است؛ شرایط رفع رخداد هنوز کامل نشده.':
                '; systemd running; incident resolution is still gated.')) :
          (fa?'؛ بازیابی سرویس تأیید نشد: ':'; service recovery not verified: ')+
            String(value.service_recovery_status||'نامشخص')):'';
      notify((fa?(kind==='validate'?'نتیجه اعتبارسنجی: ':'نتیجه درخواست: '):
                       'Configuration workflow: ')+
             (value.validation||value.status||'ثبت شد')+recoveryNote+incidentResolutionNote,
             kind==='execute'&&(value.success!==true||
               (scopedStart&&value.service_recovery_confirmed!==true)));
    }catch(e){notify(tr('failure')+' · '+e.message,true);}
    finally{state.busy=false;await load();}
  }

  async function loadConfigResponse(token) {
    state.configResponse=null;state.configResponseStatus='loading';
    try {
      const response=await api(base+'/configuration-review-response');
      if(token!==state.loadingToken)return;
      state.configResponse=response;state.configResponseStatus='loaded';
    } catch(_) {
      if(token!==state.loadingToken)return;
      state.configResponseStatus='failed';
    }
    if(state.report){renderInvestigation(state.historic||state.report);renderConfigActionBanner(state.historic||state.report);}
  }
  async function respondToConfigProposal(decision) {
    const c=state.report?.dynamic_investigation?.config_proposal||{};
    const previousAuditOnly=state.configResponse?.status==='awaiting_isolated_validation' &&
      !state.configResponse?.approval_queue_registered;
    if(state.historic||state.busy||state.configResponseStatus!=='loaded'||
       (state.configResponse?.status!=='not_responded'&&!previousAuditOnly)||
       c.status!=='candidate_proposed'||!c.candidate_sha256||!c.original_sha256)return;
    const fa=state.language==='fa';
    // Start permission is explicitly included in the approval being created,
    // only when a fresh verified systemd observation says the unit is down.
    const down=state.serviceStatus?.verified_systemd_only===true &&
      ['failed','inactive'].includes(low(state.serviceStatus?.active_state)) &&
      low(state.serviceStatus?.service).replace(/\.service$/,'')===
        low(state.report?.incident_summary?.service).replace(/\.service$/,'');
    const startAfterApply=decision==='request_change_approval' && down;
    if(!confirm(fa?
      (decision==='request_change_approval'?
        (startAfterApply?
          'تأیید این درخواست شامل دو اقدام است: ۱) اصلاح فایل پس از اعتبارسنجی ۲) شروع خودکار سرویسِ متوقف و بررسی systemd. شروع فقط بعد از Approval و اعمال موفق فایل انجام می‌شود. ادامه می‌دهید؟':
          'درخواست اصلاح فایل وارد صف Approval می‌شود؛ شروع سرویس مجاز نخواهد بود. ادامه می‌دهید؟'):
        'پیشنهاد اصلاح رد می‌شود؛ هیچ فایلی تغییر نمی‌کند. ادامه می‌دهید؟'):
      (decision==='request_change_approval'?
        (startAfterApply?
          'Approval covers both verified configuration repair and one automatic start of the stopped systemd service after successful apply. Continue?':
          'Queue configuration repair only? Service start is not authorized.'):
        'Reject this proposal without changing any file?')))return;
    state.busy=true;renderInvestigation(state.report);
    try {
      const fresh=await api(base+'/decision-brief');
      const v=fresh.dynamic_investigation?.config_proposal||{};
      if(v.original_sha256!==c.original_sha256||v.candidate_sha256!==c.candidate_sha256){
        notify(tr('rereview'),true);await load();return;
      }
      const response=await api(base+'/configuration-review-response',{
        method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({
          decision,expected_original_sha256:c.original_sha256,
          expected_candidate_sha256:c.candidate_sha256,
          start_service_after_apply:startAfterApply
        })
      });
      state.configResponse=response;state.configResponseStatus='loaded';
      notify(fa?
        (decision==='request_change_approval'?
          'درخواست در صف Approval ثبت شد؛ در انتظار اعتبارسنجی مستقل و بدون اجازه اعمال فایل.':
          'رد پیشنهاد ثبت شد؛ هیچ فایلی تغییر نکرد.'):
        (decision==='request_change_approval'?
          'Change queued for Approval; independent validation is still required. No file changed.':
          'Proposal rejected; no file changed.'));
    }catch(e){notify(tr('failure')+' · '+e.message,true);}
    finally{
      state.busy=false;
      if(state.report){renderInvestigation(state.report);renderConfigActionBanner(state.report);}
      // Immediately show the durable Approval in the incident decision desk.
      if(state.configResponse?.approval_queue_registered) await load();
    }
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
      render();
      // Detail endpoints require a terminal/paused workflow checkpoint.
      // Do not flood them with HTTP 409 while the graph is still analyzing.
      // The lifecycle/progress stream stays available and triggers reload on
      // checkpoint version change, so the controls appear once they are ready.
      const checkpointStatus=low(lifecycle.checkpoint_status);
      const detailReady=['completed','paused','failed'].includes(checkpointStatus);
      if(detailReady){
        if(!report.memory_investigation){void loadServiceStatus();void loadServiceProfile();}
        void loadConfigResponse(token);
        void loadIncidentChat(token);
        if(!report.memory_investigation&&report.recovery_advisory?.suggested_action){
          void loadRecoveryApproval(token);
        }
        if(!report.memory_investigation&&
            low(report.dynamic_investigation?.config_discovery?.runtime)==='dotnet'){
          void loadDotnetSyntax(token);
        }
      }else{
        state.serviceStatus={status:'unknown',source:'analysis_in_progress',
          reason:'incident_analysis_not_finished',verified_systemd_only:false};
        state.serviceProfile=null;
        state.chat={items:[],approvals:{}};
        state.chatStatus='loading';
        state.configResponse=null;
        state.configResponseStatus='loading';
        renderServiceStatus();renderServiceProfile();renderIncidentChat();
      }
      void loadNarrative();void loadReceivedSignals(token);
      void connectProgressStream();
    }catch(e){
      if(token!==state.loadingToken)return;
      $('#ic-loader').hidden=true;
      if(e.status===401||e.status===403){$('#ic-auth').hidden=false;$('#ic-main').hidden=true;alert(tr('authDenied'));}
      else {state.error=e.message;alert(tr('failure')+' · '+e.message);if(!state.report)$('#ic-main').hidden=true;}
    }
  }
  function returnLive(){
    state.historic=null;state.reviewedSnapshot=null;render();
    void connectProgressStream();
  }
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
      state.progressAbort?.abort();clearTimeout(progressRetryTimer);
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
    // Stale tabs, cached controls and overlapping workflow approvals must
    // never route a service-recovery Start through the E2E graph resume.
    // The separate approval ID is the only valid execution authority.
    const recovery=state.recoveryApproval||{};
    const independentRecovery=kind==='resume'&&
      low(recovery.status)==='approved'&&
      ['start_service','restart_service'].includes(recovery.action)&&
      // Recovery approval is an independent execution authority, even if a
      // future lifecycle snapshot happens to show that same approval ID.
      UUID.test(String(recovery.approval_id||''));
    if(independentRecovery){
      await handleRecoveryApproval('execute');
      return;
    }
    const completedRequest=kind==='resume'&&
      low(state.lifecycle?.checkpoint_status)==='completed';
    if(state.busy||state.historic||!state.report||
      (!completedRequest&&!approvalCurrent())) {
      notify(tr('rereview'),true);await load();return;
    }
    const approval=state.lifecycle.approval;
    const id=approval.approval_id,snapshot=state.report.snapshot_id;
    const pending=kind==='approve'||kind==='reject';
    const completedExecute=kind==='resume'&&low(state.lifecycle?.checkpoint_status)==='completed';
    if(low(approval.status)!==(pending?'pending':'approved')){
      notify(tr('rereview'),true);return;
    }
    if(!completedExecute&&kind!=='reject'&&state.reviewedSnapshot!==snapshot){
      notify(tr('needReview'),true);return;
    }
    const reason=kind==='reject'?String($('#ic-reject-reason')?.value||'').trim():'';
    if(kind==='reject'&&!reason){notify(tr('reasonMissing'),true);$('#ic-reject-reason')?.focus();return;}
    if(!confirm(tr(kind==='approve'?'firstApprove':kind==='resume'?'firstResume':'firstReject')))return;
    if(kind!=='reject'&&['high','critical'].includes(low(approval.risk_level))&&!confirm(tr('highConfirm')))return;
    state.busy=true;renderDecision(state.report);
    try{
      // Do not trust an old tab or long-lived approval card.
      // Compare exact persisted snapshot and durable approval ID before POST.
      const [latest,live]=await Promise.all([api(base+'/decision-brief'),api(base+'/lifecycle')]);
      const sameApproval=String(live.approval?.approval_id||'')===String(id)&&
        low(live.approval?.status)===(pending?'pending':'approved');
      const durableBinding=live.approval?.metadata?.binding_complete===true||
        low(live.approval?.metadata?.binding_complete)==='true';
      const sameIntent=live.approval?.action===approval.action&&
        String(live.approval?.metadata?.target||'')===
          String(approval.metadata?.target||'')&&
        String(live.approval?.metadata?.binding_digest||'')===
          String(approval.metadata?.binding_digest||'');
      if(!sameApproval||(completedExecute
          ?(!durableBinding||!sameIntent||low(live.checkpoint_status)!=='completed')
          :(latest.snapshot_id!==snapshot||
            latest.approval_readiness?.evidence_snapshot_binding==='drift_detected'))){
        state.busy=false;await load();notify(tr('rereview'),true);return;
      }
      if(kind==='approve'){
        await api('/api/v1/approvals/'+encodeURIComponent(id)+'/approve',{method:'POST'});
      }else if(kind==='reject'){
        await api('/api/v1/approvals/'+encodeURIComponent(id)+'/reject',{
          method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({reason})
        });
      }else{
        // Workflow resume only accepts paused checkpoints. Incident Chat
        // creates its own approval on an already completed analysis graph.
        // Use the independent governed execution route for that case.
        const checkpoint=low(live.checkpoint_status);
        if(checkpoint==='completed'){
          await api('/api/v1/approvals/'+encodeURIComponent(id)+'/execute',{method:'POST'});
        }else if(checkpoint==='paused'){
          await api('/api/v1/workflow/e2e/'+encodeURIComponent(incidentId)+'/resume',{method:'POST'});
        }else{
          throw new Error('checkpoint_not_executable: '+(checkpoint||'unknown'));
        }
      }
      notify(tr(kind==='approve'?'successApprove':kind==='reject'?'successReject':'successResume'));
    }catch(e){notify(tr('failure')+' · '+e.message,true);alert(e.message);}
    finally{
      state.busy=false;state.reviewedSnapshot=null;
      await load();
      if(kind==='resume')await recheckServiceStatus();
    }
  }
  function bind(){
    document.querySelectorAll('[data-lang]').forEach(el=>el.addEventListener('click',()=>setLang(el.dataset.lang)));
    $('#ic-theme').addEventListener('click',()=>{const theme=document.documentElement.dataset.theme==='light'?'dark':'light';document.documentElement.dataset.theme=theme;try{localStorage.setItem('aiops.chatbot.theme',theme);}catch(_){}});
    $('#ic-copy').addEventListener('click',async()=>{
      const r=state.historic||state.report;
      if(!r)return;
      const i=r.incident_summary||{},a=r.approval_readiness||{},x=r.remediation_recommendation||{};
      const readableReport=$('#ic-intelligence-report')?.innerText?.trim();
      const summary=[
        ...(readableReport?[readableReport,'---']:[]),
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
    $('#ic-service-status').addEventListener('click',e=>{
      if(e.target.closest('#ic-service-recheck'))void recheckServiceStatus();
    });
    $('#ic-service-profile').addEventListener('click',e=>{
      if(e.target.closest('#ic-http-recheck'))void recheckHttpHealth();
    });
    $('#ic-service-profile').addEventListener('submit',e=>{
      if(e.target.id==='ic-profile-form'){
        e.preventDefault();void saveServiceProfile(e.target);
      }
    });
    $('#ic-connect').addEventListener('click',()=>{state.key=$('#ic-key').value.trim();try{localStorage.setItem('aiops_api_key',state.key);}catch(_){}void load();});
    $('#ic-key').addEventListener('keydown',e=>{if(e.key==='Enter')$('#ic-connect').click();});
    $('#ic-return-live').addEventListener('click',returnLive);
    $('#ic-fetch-raw').addEventListener('click',()=>{void loadRaw();});
    $('#ic-chat-form').addEventListener('submit',e=>{
      e.preventDefault();void submitIncidentChat($('#ic-chat-message').value);
    });
    $('#ic-chat-message').addEventListener('keydown',e=>{
      if(e.key==='Enter'&&(e.ctrlKey||e.metaKey)){
        e.preventDefault();$('#ic-chat-form').requestSubmit();
      }
    });
    document.addEventListener('click',e=>{
      const prompt=e.target.closest('[data-incident-chat-prompt]');
      if(prompt){
        const suggestions={
          fa:{plan:'بر اساس شواهد همین رخداد، سه بررسی read-only بعدی را به ترتیب اولویت پیشنهاد بده؛ برای هرکدام توضیح بده چه چیزی را تأیید یا رد می‌کند و از کدام MCP باید استفاده شود. هیچ عملیاتی اجرا نکن.',start:'با توجه به وضعیت ثبت‌شده و احتمال Stop دستی، مقایسه کن Start یا Restart کدام منطقی‌تر است؛ پیش‌شرط‌ها، ناسازگاری با Runbook و Verification را بگو. فقط پیشنهاد بده، اجرا نکن.',error:'علت اصلی این رخداد از شواهد و تحلیل Agentها چیست؟',config:'کانفیگ همین سرویس را از VM MCP بررسی کن و خطا را بگو.',
              status:'وضعیت زنده سرویس این رخداد را بررسی کن.',files:'فایل‌های nginx.conf و sites-enabled همین سرویس را به صورت امن از VM MCP بخوان و خطای nginx -t و شماره خطوط را مشخص کن.',reload:'برای سرویس همین رخداد Reload پیشنهاد بده و پیش‌شرط‌های امنیتی را بگو.'},
          en:{plan:'Suggest the next three prioritized read-only MCP checks based on this incident evidence; for each explain what it would confirm or rule out. Do not execute anything.',start:'Compare a conditional Start and Restart in light of a possible manual stop, the current runbook, required preflight and verification; do not execute.',error:'What does the incident evidence establish about the root cause?',config:'Run a read-only configuration check for the incident service.',
              status:'Check the live service status for this incident.',files:'Inspect nginx.conf and sites-enabled configuration structure for this incident via VM MCP and report nginx -t errors.',reload:'Propose reloading the incident service and explain the safety gates.'}
        };
        $('#ic-chat-message').value=suggestions[state.language][prompt.dataset.incidentChatPrompt]||'';
        $('#ic-chat-message').focus();return;
      }
      const request=e.target.closest('[data-chat-request]');
      if(request){void incidentChatApproval('request',request.dataset.chatRequest);return;}
      const approve=e.target.closest('[data-chat-approve]');
      if(approve){void incidentChatApproval('approve',approve.dataset.chatApprove);return;}
      const execute=e.target.closest('[data-chat-execute]');
      if(execute){void incidentChatApproval('execute',execute.dataset.chatExecute);return;}
    });
    document.addEventListener('click',e=>{
      const button=e.target.closest('[data-recovery-approval]');
      if(button)void handleRecoveryApproval(button.dataset.recoveryApproval);
    });
    document.addEventListener('click',e=>{
      const button=e.target.closest('[data-download-config-diff]');
      if(!button)return;
      const report=state.historic||state.report||{};
      const investigation=report.dynamic_investigation||{};
      const content=configDiffText(investigation.config_proposal||{},
        investigation.full_config_llm_repair||{});
      if(!content){
        notify(state.language==='fa'?
          'هنوز Diff قابل دانلود ثبت نشده است.':'No diff is recorded yet.',true);
        return;
      }
      // No server-side download endpoint or plaintext file exposure.
      const id=String(report.incident_summary?.id||report.incident_summary?.incident_id||
        report.incident_id||'incident').replace(/[^a-zA-Z0-9_-]/g,'').slice(0,55);
      const blob=new Blob([content],{type:'text/plain;charset=utf-8'});
      const url=URL.createObjectURL(blob);
      const a=document.createElement('a');
      a.href=url;a.download='aiops-'+id+'-redacted.diff';
      document.body.appendChild(a);a.click();a.remove();
      setTimeout(()=>URL.revokeObjectURL(url),5000);
    });
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
      const preview=e.target.closest('[data-config-preview]');
      if(preview){
        if(state.historic||state.chatBusy||state.busy||state.configPreviewPending){
          notify(state.language==='fa'?
            'یک بررسی دیگر در حال اجراست یا نسخه تاریخی باز شده است.':
            'Another check is running or the historical snapshot is active.',true);
          return;
        }
        if(state.lifecycle?.analysis_in_progress){
          notify(state.language==='fa'?
            'تحلیل اولیه هنوز کامل نشده است؛ بعد از تکمیل دوباره بررسی کنید.':
            'Initial analysis is not yet complete; retry after it finishes.',true);
          return;
        }
        if(preview.dataset.configPreview==='full-llm'&&!window.confirm(
          state.language==='fa'?
          'متن کامل فایل تنظیمات ممکن است شامل گذرواژه یا توکن باشد و به LLM تعریف‌شده در تنظیمات VM MCP ارسال شود. هیچ تغییری روی سرور اعمال نمی‌شود. ادامه می‌دهید؟':
          'The full configuration may contain passwords or tokens and will be sent to the VM MCP configured LLM. Nothing will be applied. Continue?'
        ))return;
        const requested=preview.dataset.configPreview==='full-llm'?
          'service_config_llm_repair: درخواست صریح بازبینی فایل کانفیگ کامل همین سرویس با LLM و دریافت نسخه کامل اصلاح‌شده، فقط در حافظهٔ VM MCP و بدون Apply.':
          preview.dataset.configPreview==='nginx'?
          'nginx_config_review: فقط پیش‌نمایش امن اصلاح nginx را از VM MCP بگیر و به شواهد و تحلیل همین رخداد اضافه کن. هیچ فایلی را تغییر نده.':
          preview.dataset.configPreview==='review'?
          'service_config_review: فایل کانفیگی که systemd و MCP وجودش را برای همین سرویس تأیید کرده‌اند با ابزار امن بررسی کن و در صورت امکان پیشنهاد اصلاح ساختاری ارائه بده؛ از LLM برای ناشناخته‌ها کمک بگیر ولی هیچ تغییری اجرا نکن.':
          'service_config_discovery: مسیر فایل‌های تنظیمات همین سرویس را از systemd و VM MCP به‌صورت read-only کشف و تأیید کن؛ بعد با کمک LLM درباره روش اعتبارسنجی و رفع مشکل تحقیق کن. دستور اجرایی یا تغییر فایل انجام نده.';
        state.configPreviewPending=true;
        state.configPreviewLastResult=null;
        renderConfigActionBanner(state.report);
        void (async()=>{
          try{
            await submitIncidentChat(requested);
            if(preview.dataset.previewOpenDiff==='1'){
              document.querySelector('#ic-ai-proposed-fix')?.scrollIntoView({
                behavior:'smooth',block:'start'
              });
              if(!Number.isInteger(state.report?.dynamic_investigation?.config_proposal?.redacted_diff?.line)){
                notify(state.language==='fa'?
                  'هنوز Diff واقعی ثبت نشده است. وضعیت بازبینی MCP، دسترسی خواندن فایل و شواهد جدید را بررسی کنید.':
                  'No real diff is recorded yet. Check the MCP review result, file read permissions, and Evidence.',true);
              }
            }
            state.configPreviewLastResult=state.chatLastResult ||
              (state.language==='fa'?'بررسی ثبت شد؛ نتیجه را در چت و شواهد بخوانید.':
                'Review recorded; see chat and Evidence for the result.');
          }finally{
            state.configPreviewPending=false;
            if(state.report)renderConfigActionBanner(state.report);
          }
        })();
        return;
      }
      const cfg=e.target.closest('[data-config-approval-action]');
      if(cfg){void configApprovalAction(cfg.dataset.configApprovalAction);return;}
      const intent=e.target.closest('[data-config-intent]');
      if(intent){void respondToConfigProposal(intent.dataset.configIntent);return;}
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
    window.addEventListener('pagehide',()=>{state.progressAbort?.abort();clearTimeout(progressRetryTimer);});
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
    // Refresh age warnings locally; a previous Running observation must not
    // appear fresh indefinitely when the operator leaves the page open.
    const serviceAgeTimer=setInterval(()=>{
      if(state.report&&!state.historic){
        renderServiceStatus();renderOperationalSummary();
      }
    },30000);
    if(typeof serviceAgeTimer?.unref==='function')serviceAgeTimer.unref();
    if(typeof durationTimer?.unref==='function')durationTimer.unref();
    // Node-based browser regression harnesses should not be kept alive by polling.
    if(typeof lifecycleTimer?.unref==='function')lifecycleTimer.unref();
    setLang(state.language);
    void load();
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bind,{once:true});
  else bind();
})();
