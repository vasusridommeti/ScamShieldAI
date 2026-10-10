/* ScamShield AI - script.js
 * Rule-based scam-awareness engine + dashboard UI.
 * Everything runs locally in the browser. No network requests are made.
 * User text is only ever rendered with textContent / safe DOM construction.
 */
(function (root) {
  'use strict';

  /* ================================================================
   * 1. CONFIGURATION (edit weights / thresholds here)
   * ================================================================ */
  const CONFIG = {
    MAX_INPUT: 5000,
    MAX_HISTORY: 100,
    PREVIEW_LEN: 80,
    RECENT_DAYS: 7,
    THRESHOLDS: { moderate: 25, high: 50, critical: 75 },
    STORAGE_KEY: 'scamshield.history.v1',
    LANG_KEY: 'scamshield.lang.v1'
  };

  const SEVERITY_RANK = { low: 1, medium: 2, high: 3, critical: 4 };

  /* Sentences that give security ADVICE ("never share your OTP") must not be
   * treated as requests. Rules marked skipInSafe ignore matches inside them. */
  const SAFE_CONTEXT = new RegExp(
    '\\b(?:never|do not|don\'t|dont|should not|shouldn\'t|must not|will never|won\'t|never ever)\\s+(?:ever\\s+)?' +
      '(?:share|disclose|give|reveal|provide|send|click|download|install|enter|transfer|pay)\\b' +
      '[^.!?\\n]{0,60}\\b(?:otp|pin|password|cvv|code|card|link|links|app|apps|details|money|anyone|anybody|others?|strangers?|unknown)\\b' +
      '|\\b(?:will never|never|does not|doesn\'t|do not) ask (?:you )?for\\b',
    'i'
  );

  /* ================================================================
   * 2. DETECTION RULES
   * Each rule is counted at most once. weight = score contribution.
   * ================================================================ */
  const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'cutt.ly', 'is.gd', 'rb.gy', 'shorturl.at', 'ow.ly', 'tiny.cc', 'rebrand.ly'];
  const RISKY_TLDS = ['xyz', 'top', 'click', 'icu', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'loan', 'zip', 'link', 'vip', 'site', 'online', 'live'];
  const LOOKALIKE_WORDS = /(secure|verify|verification|login|update|kyc|alert|bank|account|support|refund|reward|claim|offer)/;
  const URL_REGEX = /\b(?:https?:\/\/|www\.)[^\s<>"')]+|\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:com|in|net|org|co|io|xyz|top|click|icu|tk|ml|ga|cf|gq|work|loan|zip|info|biz|site|online|link|live|vip|app|me|ly|gl|gy|gd|to)\b(?:\/[^\s<>"')]*)?/gi;

  function findUrls(text) {
    const out = [];
    const re = new RegExp(URL_REGEX.source, 'gi');
    let m;
    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) { re.lastIndex++; continue; }
      if (m.index > 0 && text[m.index - 1] === '@') continue; // part of an e-mail address
      let url = m[0].replace(/[.,;:!?]+$/, '');
      out.push({ start: m.index, end: m.index + url.length, url: url });
    }
    return out;
  }

  function urlReasons(url) {
    const reasons = [];
    const noProto = url.replace(/^https?:\/\//i, '');
    const authority = noProto.split(/[\/?#]/)[0];
    const host = authority.replace(/^.*@/, '').replace(/:\d+$/, '').toLowerCase();
    if (authority.indexOf('@') !== -1) reasons.push('contains an @ sign that can hide the real destination');
    if (SHORTENERS.indexOf(host) !== -1) reasons.push('uses a link shortener, so the real destination is hidden');
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) reasons.push('uses a raw IP address instead of a normal website name');
    const tld = host.split('.').pop();
    if (RISKY_TLDS.indexOf(tld) !== -1) reasons.push('ends in ".' + tld + '", an address ending often seen in throw-away scam sites');
    if (host.indexOf('xn--') !== -1) reasons.push('uses look-alike (punycode) characters');
    if (host.indexOf('-') !== -1 && LOOKALIKE_WORDS.test(host)) reasons.push('looks like a hyphenated imitation of a trusted brand or service');
    if (host.split('.').length >= 4) reasons.push('has many sub-domains, a common way to imitate a trusted name');
    return reasons;
  }

  function findAll(text, patterns, safeRanges, skipSafe, limit) {
    const ranges = [];
    for (const p of patterns) {
      const re = new RegExp(p.source, p.flags.indexOf('g') === -1 ? p.flags + 'g' : p.flags);
      let m;
      while ((m = re.exec(text)) !== null) {
        if (m[0].length === 0) { re.lastIndex++; continue; }
        if (skipSafe && inRanges(m.index, safeRanges)) continue;
        ranges.push({ start: m.index, end: m.index + m[0].length });
        if (ranges.length >= limit) return ranges;
      }
    }
    return ranges;
  }

  function inRanges(pos, ranges) {
    for (const r of ranges) if (pos >= r[0] && pos < r[1]) return true;
    return false;
  }

  const RULES = [
    {
      id: 'SS-001', category: 'Credential request', severity: 'critical', weight: 40, skipInSafe: true,
      title: 'Asks for an OTP, PIN or password',
      explanation: 'Genuine banks, payment apps and government services never ask you to share an OTP, PIN, CVV or password. Anyone who has them can move money or take over your account.',
      action: 'Never share OTPs, PINs, CVVs or passwords with anyone. Contact your bank through the number on your card or its official website.',
      patterns: [
        /\b(?:share|send|reply(?:\s+with)?|tell|give|provide|enter|submit|confirm|verify|forward|text|whatsapp|read out|type)\b[^.!?\n]{0,40}?\b(?:otp|one[- ]time (?:password|pin|code)|upi[- ]?pin|m[- ]?pin|pin(?!\s*code)|password|passcode|cvv|cvc|security code|verification code)\b/i,
        /\b(?:otp|pin(?!\s*code)|password|cvv)\b[^.!?\n]{0,20}\b(?:is required|required|needed|to verify|to confirm|to avoid|to proceed)\b/i
      ]
    },
    {
      id: 'SS-002', category: 'Advance payment', severity: 'high', weight: 30, skipInSafe: false,
      title: 'Asks for an upfront fee',
      explanation: 'Scammers often ask for a small "registration", "processing" or "clearance" fee before a prize, loan, parcel or job. Genuine winners, lenders and employers do not work this way, and the promised reward never arrives.',
      action: 'Do not pay any fee to receive a prize, loan, refund or job. Check the offer on the organisation\'s official website first.',
      patterns: [
        /\b(?:registration|processing|activation|joining|refundable|clearance|release|delivery|handling|admin(?:istration)?|training|verification|insurance|tax|gst|customs|security)\s+(?:fee|fees|charge|charges|deposit|amount)\b/i,
        /\bpay\b[^.!?\n]{0,30}\b(?:fee|fees|charges?|deposit)\b/i,
        /\b(?:small|nominal|one[- ]time)\s+(?:fee|amount|payment|charge)s?\b/i
      ]
    },
    {
      id: 'SS-003', category: 'Urgent threat', severity: 'high', weight: 20, skipInSafe: true,
      title: 'Threatens blocking, suspension or legal action',
      explanation: 'Fear is the scammer\'s main tool. Threats such as "your account will be blocked" are designed to make you act before you think or check.',
      action: 'Do not react to threats inside the message. Check your account status in the official app or by calling the bank on a number you trust.',
      patterns: [
        /\b(?:account|card|sim|number|service|services|kyc|wallet|connection|upi|policy|electricity)\b[^.!?\n]{0,35}\b(?:will be|is being|has been|been|shall be|may be|get)\s+(?:blocked|suspended|deactivated|frozen|terminated|closed|disconnected|cancelled|locked)\b/i,
        /\b(?:avoid|prevent|stop)\b[^.!?\n]{0,25}\b(?:suspension|blocking|closure|deactivation|disconnection|service interruption|penalty|legal action)\b/i,
        /\b(?:legal action|arrest warrant|arrested|police case|court notice|penalty will|fine will be)\b/i
      ]
    },
    {
      id: 'SS-004', category: 'Urgent threat', severity: 'medium', weight: 12, skipInSafe: false,
      title: 'Creates time pressure',
      explanation: 'Short deadlines ("in 10 minutes", "immediately") are used to stop you from verifying the message or asking someone you trust.',
      action: 'Slow down. A real organisation will still be there after you verify. Take time to check through an official channel.',
      patterns: [
        /\b(?:immediately|urgent(?:ly)?|right now|asap|at once|without delay|last chance|final (?:notice|warning|reminder)|act now|today only|expires? (?:today|soon|tonight)|hurry)\b/i,
        /\b(?:within|in|next)\s+\d+\s*(?:minutes?|mins?|hours?|hrs?)\b/i
      ]
    },
    {
      id: 'SS-005', category: 'Unrealistic reward', severity: 'medium', weight: 20, skipInSafe: false,
      title: 'Claims you won a prize or reward',
      explanation: 'You cannot win a contest you never entered. "Prize" messages are used to collect fees, personal details or to get you to click a harmful link.',
      action: 'Ignore prize and lottery claims you did not sign up for. Do not click, pay or reply.',
      patterns: [
        /\byou(?:'ve|\s+have)?\s+(?:been selected|won|are selected|are the winner)\b/i,
        /\b(?:lottery|lucky draw|jackpot|grand prize|free gift|gift voucher|cashback offer)\b/i,
        /\bcongratulations\b[^.!?\n]{0,60}\b(?:won|win|prize|reward|selected|winner)\b/i,
        /\bclaim\b[^.!?\n]{0,20}\b(?:prize|reward|gift|cash|bonus)\b/i,
        /\bprize\b/i
      ]
    },
    {
      id: 'SS-006', category: 'Unrealistic reward', severity: 'medium', weight: 20, skipInSafe: false,
      title: 'Promises guaranteed or very easy earnings',
      explanation: 'Offers of high daily income for little work, with no skills or investment needed, are a common lure in task, investment and fake job scams.',
      action: 'Treat guaranteed-income offers with suspicion. Research the company independently and never pay to start earning.',
      patterns: [
        /\b(?:earn|make|income|salary|get)\b[^.!?\n]{0,25}?(?:₹|\brs\.?|\binr|\$)\s?\d[\d,]*\s*(?:\/|per|a|each)?\s*(?:day|daily|week|weekly|hour|hourly|month|monthly)\b/i,
        /\bguaranteed\s+(?:income|returns?|profit|salary|job|placement)\b/i,
        /\bdouble your (?:money|investment)\b/i,
        /\b(?:work from home|part[- ]time)\b[^.!?\n]{0,40}\b(?:earn|income|salary)\b/i,
        /\bno (?:experience|skills?|investment) (?:needed|required|necessary)\b/i,
        /\bearn\b[^.!?\n]{0,20}\b(?:lakhs?|crores?)\b/i
      ]
    },
    {
      id: 'SS-007', category: 'Suspicious link', severity: 'high', weight: 25, skipInSafe: false,
      title: 'Contains a suspicious-looking link',
      explanation: 'Look-alike or disguised web addresses are used to steal logins, card details and OTPs on fake pages.',
      action: 'Do not open the link. Type the official website address yourself or use the official app.',
      detect: function (ctx) {
        const urls = findUrls(ctx.text);
        const flagged = [];
        let detail = '';
        for (const u of urls) {
          const reasons = urlReasons(u.url);
          if (reasons.length) {
            flagged.push({ start: u.start, end: u.end });
            if (!detail) detail = 'The link "' + u.url + '" ' + reasons.join('; ') + '.';
          }
        }
        return flagged.length ? { ranges: flagged.slice(0, 3), detail: detail } : null;
      }
    },
    {
      id: 'SS-008', category: 'Suspicious link', severity: 'low', weight: 6, skipInSafe: false,
      title: 'Contains a link you should verify',
      explanation: 'Links in unexpected messages are the most common way scams reach you. This link did not look unusual to the checker, but that is not proof it is safe.',
      action: 'Only open links from senders you know and expect. When unsure, go to the official website directly.',
      detect: function (ctx) {
        const urls = findUrls(ctx.text);
        if (!urls.length) return null;
        if (urls.some(function (u) { return urlReasons(u.url).length > 0; })) return null; // SS-007 already covers it
        return { ranges: urls.slice(0, 3).map(function (u) { return { start: u.start, end: u.end }; }) };
      }
    },
    {
      id: 'SS-009', category: 'Unknown app install', severity: 'high', weight: 28, skipInSafe: true,
      title: 'Asks you to install an app or remote-access tool',
      explanation: 'Fraudsters ask victims to install APK files or screen-sharing apps (such as AnyDesk or TeamViewer) so they can watch the screen, read OTPs and move money.',
      action: 'Install apps only from the official Play Store or App Store, and never install remote-access tools on a stranger\'s request.',
      patterns: [
        /\b(?:install|download)\b[^.!?\n]{0,40}\b(?:apk|app|application|software|anydesk|teamviewer|quicksupport|rustdesk|remote access|remote support)\b/i,
        /\b[\w-]+\.apk\b/i
      ]
    },
    {
      id: 'SS-010', category: 'Impersonation', severity: 'medium', weight: 12, skipInSafe: true,
      title: 'Appears to pose as a bank, agency or support team',
      explanation: 'Scammers copy the tone of banks, couriers, tax and police departments, or customer support to borrow their authority. A generic greeting such as "Dear customer" is another common sign.',
      action: 'Do not trust the sender\'s claim. Look up the organisation\'s official contact details yourself and ask them directly.',
      patterns: [
        /\b(?:this is|we are|i am|i'm|calling from|message from|msg from|sent by|official)\b[^.!?\n]{0,30}\b(?:bank|sbi|hdfc|icici|axis|paytm|phonepe|google ?pay|amazon|flipkart|income tax|rbi|customs|police|cbi|trai|uidai|aadhaar|courier|fedex|dhl|support|customer care|helpdesk|cyber ?cell|government|ministry|department|officer|manager)\b/i,
        /\bdear (?:customer|user|account holder|valued customer|sir\/madam|beneficiary)\b/i,
        /\b(?:kyc|pan|aadhaar)\b[^.!?\n]{0,30}\b(?:update|updated|expire|expired|expiry|pending|suspend|suspended|block|blocked|verification)\b/i,
        /\b(?:your|the)\s+(?:sbi|hdfc|icici|axis|paytm|phonepe|bank|amazon|flipkart)\b[^.!?\n]{0,25}\b(?:account|card|wallet|order|parcel|kyc)\b/i,
        /\b(?:customs|courier|parcel)\b[^.!?\n]{0,30}\b(?:held|seized|detained|pending|stuck)\b/i
      ]
    },
    {
      id: 'SS-011', category: 'Money transfer request', severity: 'high', weight: 30, skipInSafe: true,
      title: 'Asks you to send money to an unfamiliar account',
      explanation: 'Requests to move money to a new, "safe" or unknown account or UPI ID are central to impersonation and payment-redirect scams. Money sent this way is very hard to recover.',
      action: 'Never transfer money because of a message alone. Confirm the request with the person or company through a separate, trusted channel.',
      patterns: [
        /\b(?:transfer|send|deposit|remit|wire|pay)\b[^.!?\n]{0,30}\b(?:money|funds|amount|payment|cash|₹\s?\d[\d,]*|rs\.?\s?\d[\d,]*)\b[^.!?\n]{0,40}\b(?:to|into)\b[^.!?\n]{0,30}\b(?:account|upi|wallet|number|id|qr)\b/i,
        /\b(?:transfer|send|pay|deposit)\b[^.!?\n]{0,50}\b(?:new|different|another|unknown|personal|temporary|safe|secure)\s+(?:bank\s+)?(?:account|upi)\b/i,
        /\bscan\b[^.!?\n]{0,20}\bqr\b[^.!?\n]{0,40}\b(?:receive|refund|claim|get)\b/i
      ]
    },
    {
      id: 'SS-012', category: 'Job offer with payment', severity: 'high', weight: 25, skipInSafe: false,
      title: 'Job offer that requires you to pay',
      explanation: 'Genuine employers do not charge candidates for registration, training kits, uniforms or "security deposits". Paying for a job is the signature of a fake job scam.',
      action: 'Never pay to get a job. Verify the employer through its official website or careers page and walk away if money is requested.',
      detect: function (ctx) {
        const jobRe = /\b(?:job|jobs|offer letter|recruit\w*|hiring|vacanc\w+|placement|work from home|data entry|interview|appointment letter|employment|position)\b/i;
        if (!jobRe.test(ctx.text)) return null;
        const ranges = findAll(ctx.text, [
          /\b(?:pay|deposit|transfer|send|remit)\b[^.!?\n]{0,40}\b(?:fee|fees|charges?|deposit|amount|money|₹\s?\d|rs\.?\s?\d)\b/i,
          /\b(?:registration|security|training|kit|joining)\s+(?:fee|fees|deposit|charges?)\b/i
        ], ctx.safeRanges, false, 2);
        return ranges.length ? { ranges: ranges } : null;
      }
    },
    {
      id: 'SS-013', category: 'Sensitive information request', severity: 'high', weight: 25, skipInSafe: true,
      title: 'Asks for sensitive personal or banking details',
      explanation: 'Aadhaar, PAN, card details, bank logins and ID photos can be used for identity theft and fraud. Legitimate organisations do not collect them through random messages.',
      action: 'Do not share ID numbers, card details or login credentials in reply to a message. Use only the official app or website.',
      patterns: [
        /\b(?:send|share|submit|provide|upload|enter|confirm|verify|update|reply|fill|give)\b[^.!?\n]{0,40}?\b(?:aadhaar|aadhar|pan (?:card|number)|pan|bank account (?:number|details)|account number|card (?:number|details)|debit card|credit card|date of birth|dob|passport|selfie|photo id|mother'?s maiden name|login (?:id|details|credentials)|net ?banking (?:id|details)|address proof|id proof|expiry date)\b/i
      ]
    },
    {
      id: 'SS-014', category: 'Urgent threat', severity: 'medium', weight: 10, skipInSafe: false,
      title: 'Asks you to keep it secret',
      explanation: 'Scammers isolate victims by telling them not to discuss the matter with family, friends, the bank or the police. A genuine request can always be checked with others.',
      action: 'Talk to someone you trust before acting. Secrecy requests are a strong reason to stop and verify.',
      patterns: [
        /\b(?:do not|don't|dont|never)\s+(?:tell|inform|discuss|mention|call)\b[^.!?\n]{0,30}\b(?:anyone|anybody|family|friends|bank|police|others)\b/i,
        /\bkeep (?:this|it|the matter) (?:a )?(?:secret|confidential|private)\b/i,
        /\b(?:confidential|secret) (?:offer|matter|transaction|deal)\b/i
      ]
    }
  ];

  const RULE_INDEX = {};
  RULES.forEach(function (r) { RULE_INDEX[r.id] = r; });

  /* ================================================================
   * 3. ENGINE
   * ================================================================ */
  function splitSentences(text) {
    const out = [];
    const re = /[^.!?\n]+(?:[.!?]+|$)/g;
    let m;
    while ((m = re.exec(text)) !== null) out.push({ start: m.index, end: m.index + m[0].length, text: m[0] });
    return out;
  }

  function computeSafeRanges(text) {
    return splitSentences(text)
      .filter(function (s) { return SAFE_CONTEXT.test(s.text); })
      .map(function (s) { return [s.start, s.end]; });
  }

  function levelFor(score) {
    const t = CONFIG.THRESHOLDS;
    if (score >= t.critical) return 'critical';
    if (score >= t.high) return 'high';
    if (score >= t.moderate) return 'moderate';
    return 'low';
  }

  function mergeHighlights(findings) {
    const segs = [];
    findings.forEach(function (f) {
      f.ranges.forEach(function (r) {
        segs.push({ start: r.start, end: r.end, rank: SEVERITY_RANK[f.severity], severity: f.severity });
      });
    });
    segs.sort(function (a, b) { return a.start - b.start || b.end - a.end; });
    const out = [];
    segs.forEach(function (s) {
      const last = out[out.length - 1];
      if (last && s.start < last.end) {
        if (s.end > last.end) last.end = s.end;
        if (s.rank > last.rank) { last.rank = s.rank; last.severity = s.severity; }
      } else {
        out.push({ start: s.start, end: s.end, rank: s.rank, severity: s.severity });
      }
    });
    return out;
  }

  function analyzeMessage(input) {
    const text = String(input == null ? '' : input);
    const safeRanges = computeSafeRanges(text);
    const ctx = { text: text, safeRanges: safeRanges };
    const findings = [];

    RULES.forEach(function (rule) {
      let hit;
      if (rule.detect) {
        hit = rule.detect(ctx);
      } else {
        const ranges = findAll(text, rule.patterns, safeRanges, rule.skipInSafe, 3);
        hit = ranges.length ? { ranges: ranges } : null;
      }
      if (!hit || !hit.ranges.length) return;
      const first = hit.ranges[0];
      findings.push({
        id: rule.id,
        category: rule.category,
        severity: rule.severity,
        title: rule.title,
        explanation: rule.explanation,
        action: rule.action,
        weight: rule.weight,
        phrase: text.slice(first.start, first.end),
        detail: hit.detail || '',
        ranges: hit.ranges
      });
    });

    findings.sort(function (a, b) { return b.weight - a.weight; });
    const raw = findings.reduce(function (sum, f) { return sum + f.weight; }, 0);
    const score = Math.min(100, raw);
    return {
      score: score,
      level: levelFor(score),
      findings: findings,
      highlights: mergeHighlights(findings),
      safeAdviceDetected: safeRanges.length > 0,
      length: text.length
    };
  }

  function validateInput(text) {
    const trimmed = String(text == null ? '' : text).trim();
    if (!trimmed) return { ok: false, code: 'empty' };
    if (trimmed.length > CONFIG.MAX_INPUT) return { ok: false, code: 'long' };
    return { ok: true, text: trimmed };
  }

  /* Short, masked preview for history: hides long digit runs and e-mail addresses. */
  function makePreview(text) {
    const flat = text.replace(/\s+/g, ' ').trim()
      .replace(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g, '[email]')
      .replace(/\d{6,}/g, function (d) { return '•'.repeat(d.length); });
    return flat.length > CONFIG.PREVIEW_LEN ? flat.slice(0, CONFIG.PREVIEW_LEN - 1) + '…' : flat;
  }

  const SAMPLES = [
    { id: 'job', label: 'Fake job offer', text: 'Earn ₹5,000 daily from home. Pay a registration fee today to secure your job.' },
    { id: 'otp', label: 'OTP phishing', text: 'Your account will be blocked in 10 minutes. Reply with your OTP to avoid suspension.' },
    { id: 'prize', label: 'Prize scam', text: 'Congratulations! You have won a prize. Pay a processing fee to claim your reward.' },
    { id: 'pay', label: 'Payment request', text: 'Transfer money immediately to this new account to prevent service interruption.' },
    { id: 'info', label: 'Ordinary notice', text: 'Your college library will remain closed on Sunday. Regular hours resume on Monday.' },
    { id: 'tip', label: 'Security reminder', text: 'Never share your OTP or password with anyone. Contact your bank using its official website if you need assistance.' }
  ];

  const Engine = {
    CONFIG: CONFIG, RULES: RULES, SAMPLES: SAMPLES,
    analyzeMessage: analyzeMessage, validateInput: validateInput,
    makePreview: makePreview, levelFor: levelFor, findUrls: findUrls, urlReasons: urlReasons
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = Engine;
  root.ScamEngine = Engine;
  if (typeof document === 'undefined') return;

  /* ================================================================
   * 4. TRANSLATIONS (English is the default; Telugu is an unreviewed draft)
   * ================================================================ */
  const TE = {
    'nav.dashboard': 'డాష్‌బోర్డ్', 'nav.analyze': 'సందేశాన్ని విశ్లేషించండి', 'nav.history': 'స్కాన్ చరిత్ర',
    'nav.tips': 'భద్రతా చిట్కాలు', 'nav.about': 'ప్రాజెక్ట్ గురించి',
    'chip.privacy': 'స్థానికంగా మాత్రమే: ఏదీ అప్‌లోడ్ కాదు',
    'title.dashboard': 'డాష్‌బోర్డ్', 'sub.dashboard': 'మీ స్కామ్ తనిఖీ సారాంశం.',
    'title.analyze': 'సందేశాన్ని విశ్లేషించండి', 'sub.analyze': 'అనుమానాస్పద SMS, ఇమెయిల్ లేదా చాట్ సందేశాన్ని పేస్ట్ చేయండి.',
    'title.history': 'స్కాన్ చరిత్ర', 'sub.history': 'ఈ పరికరంలో మాత్రమే సేవ్ అవుతుంది.',
    'title.tips': 'భద్రతా చిట్కాలు', 'sub.tips': 'చాలా స్కామ్‌లను ఆపే అలవాట్లు.',
    'title.about': 'ScamShield AI గురించి', 'sub.about': 'వివరించగలిగేలా రూపొందించిన హ్యాకథాన్ ప్రాజెక్ట్.',
    'hero.title': 'నమ్మే ముందు ఆలోచించండి.',
    'hero.sub': 'క్లిక్ చేయడానికి, చెల్లించడానికి లేదా వ్యక్తిగత సమాచారం పంచుకోవడానికి ముందు అనుమానాస్పద సందేశాలను అర్థం చేసుకోండి.',
    'hero.analyze': 'సందేశాన్ని విశ్లేషించండి', 'hero.demo': 'డెమో ప్రయత్నించండి',
    'btn.analyze': 'సందేశాన్ని విశ్లేషించండి', 'btn.clear': 'తొలగించు',
    'stat.total': 'మొత్తం స్కాన్లు', 'stat.high': 'అధిక-ప్రమాద ఫలితాలు',
    'stat.top': 'తరచుగా కనిపించిన సంకేతం', 'stat.recent': 'ఇటీవలి స్కాన్లు (7 రోజులు)',
    'hist.clear': 'చరిత్రను తొలగించు', 'hist.reset': 'డెమో డేటాను రీసెట్ చేయి',
    'tip.otp.t': 'OTP, PIN, పాస్‌వర్డ్ రక్షణ', 'tip.otp.b': 'OTP, PIN లేదా పాస్‌వర్డ్‌ను ఎవరితోనూ పంచుకోవద్దు. నిజమైన బ్యాంకులు వీటిని అడగవు.',
    'tip.link.t': 'అనుమానాస్పద లింక్‌లు', 'tip.link.b': 'తెలియని లింక్‌లను క్లిక్ చేయవద్దు; అధికారిక వెబ్‌సైట్‌ను నేరుగా టైప్ చేయండి.',
    'tip.job.t': 'నకిలీ ఉద్యోగ ఆఫర్లు', 'tip.job.b': 'ఉద్యోగం కోసం రుసుము అడిగితే అది అనుమానాస్పదం. డబ్బు చెల్లించవద్దు.',
    'tip.fee.t': 'ముందస్తు రుసుము స్కామ్‌లు', 'tip.fee.b': 'బహుమతి, రుణం లేదా పార్శిల్ కోసం ముందస్తు రుసుము చెల్లించవద్దు.',
    'tip.prize.t': 'బహుమతి, లాటరీ స్కామ్‌లు', 'tip.prize.b': 'మీరు పాల్గొనని లాటరీ గెలిచారని చెప్పే సందేశాలను నమ్మవద్దు.',
    'tip.urgent.t': 'మోసపూరిత గుర్తింపు మరియు తొందర', 'tip.urgent.b': 'తొందర పెట్టడం స్కామర్ల సాధారణ పద్ధతి. ఆగి, స్వతంత్రంగా ధృవీకరించండి.',
    'tip.pay.t': 'చెల్లింపు అభ్యర్థనల ధృవీకరణ', 'tip.pay.b': 'కొత్త ఖాతాకు డబ్బు పంపే ముందు వేరే నమ్మకమైన మార్గంలో ధృవీకరించండి.',
    'tip.report.t': 'భారతదేశంలో ఫిర్యాదు', 'tip.report.b': 'ఇప్పటికే డబ్బు పంపితే వెంటనే మీ బ్యాంక్ లేదా చెల్లింపు సంస్థను సంప్రదించండి, తర్వాత cybercrime.gov.in లో ఫిర్యాదు చేయండి.',
    'tips.note': 'తెలుగు అనువాదం సమీక్షించబడలేదు (డ్రాఫ్ట్). ముఖ్యమైన సలహాకు ఇంగ్లీష్ వెర్షన్‌ను చూడండి.'
  };

  const DYN = {
    en: {
      'level.low': 'Low', 'level.moderate': 'Moderate', 'level.high': 'High', 'level.critical': 'Critical',
      'sum.low': 'No known warning signs matched. That does not make the message safe, so verify anything that asks you to act.',
      'sum.moderate': 'Some warning signs were found. Pause and verify the sender through an official channel.',
      'sum.high': 'Several strong warning signs were found. Do not click, pay or reply until you verify independently.',
      'sum.critical': 'Many serious warning signs were found. Do not respond, pay or share anything until you verify.',
      'disclaimer': 'This score is a heuristic estimate from a fixed set of rules. It is not a probability and cannot confirm whether a message is genuine or fraudulent.',
      'signs': 'warning signs', 'sign': 'warning sign'
    },
    te: {
      'level.low': 'తక్కువ', 'level.moderate': 'మధ్యస్థ', 'level.high': 'అధిక', 'level.critical': 'అత్యంత ప్రమాదం',
      'disclaimer': 'ఇది నిర్ణీత నియమాల ఆధారంగా చేసిన అంచనా మాత్రమే. సందేశం నిజమైనదా లేదా మోసమా అని ఇది హామీ ఇవ్వలేదు.',
      'signs': 'హెచ్చరిక సంకేతాలు', 'sign': 'హెచ్చరిక సంకేతం'
    }
  };

  let lang = 'en';
  function t(key) {
    return (DYN[lang] && DYN[lang][key]) || DYN.en[key] || key;
  }

  /* ================================================================
   * 5. DOM HELPERS (no innerHTML anywhere)
   * ================================================================ */
  const $ = function (sel, rootEl) { return (rootEl || document).querySelector(sel); };
  const $$ = function (sel, rootEl) { return Array.prototype.slice.call((rootEl || document).querySelectorAll(sel)); };

  function h(tag, attrs) {
    const el = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        const v = attrs[k];
        if (v == null || v === false) return;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = v;
        else if (k.indexOf('on') === 0 && typeof v === 'function') el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v === true ? '' : String(v));
      });
    }
    for (let i = 2; i < arguments.length; i++) appendKids(el, arguments[i]);
    return el;
  }
  function appendKids(el, kid) {
    if (kid == null || kid === false) return;
    if (Array.isArray(kid)) { kid.forEach(function (k) { appendKids(el, k); }); return; }
    el.appendChild(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }

  function highlightedText(text, highlights, className) {
    const p = h('p', { class: className || 'msg-text' });
    let pos = 0;
    highlights.forEach(function (hl, i) {
      if (hl.start > pos) p.appendChild(document.createTextNode(text.slice(pos, hl.start)));
      const mark = h('mark', { class: 'hl sev-' + hl.severity });
      mark.style.setProperty('--i', String(i));
      mark.textContent = text.slice(hl.start, hl.end);
      p.appendChild(mark);
      pos = hl.end;
    });
    if (pos < text.length) p.appendChild(document.createTextNode(text.slice(pos)));
    return p;
  }

  function buildRing(score, level) {
    const NS = 'http://www.w3.org/2000/svg';
    const C = 2 * Math.PI * 52;
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 120 120');
    svg.setAttribute('aria-hidden', 'true');
    const track = document.createElementNS(NS, 'circle');
    ['cx', 'cy'].forEach(function (a) { track.setAttribute(a, '60'); });
    track.setAttribute('r', '52');
    track.setAttribute('class', 'ring-track');
    const bar = document.createElementNS(NS, 'circle');
    ['cx', 'cy'].forEach(function (a) { bar.setAttribute(a, '60'); });
    bar.setAttribute('r', '52');
    bar.setAttribute('class', 'ring-bar');
    bar.style.strokeDasharray = String(C);
    bar.style.strokeDashoffset = String(C);
    svg.appendChild(track);
    svg.appendChild(bar);
    const wrap = h('div', {
      class: 'ring', 'data-level': level, role: 'img',
      'aria-label': 'Risk score ' + score + ' out of 100, ' + t('level.' + level)
    }, svg, h('div', { class: 'ring-num' }, h('strong', { text: String(score) }), h('span', { text: '/100' })));
    requestAnimationFrame(function () {
      requestAnimationFrame(function () { bar.style.strokeDashoffset = String(C * (1 - score / 100)); });
    });
    return wrap;
  }

  function levelBadge(level) {
    return h('span', { class: 'badge', 'data-level': level, text: t('level.' + level) });
  }

  /* ================================================================
   * 6. STORAGE (history in localStorage, with in-memory fallback)
   * ================================================================ */
  let memoryHistory = [];
  let storageOk = true;

  function loadHistory() {
    try {
      const raw = localStorage.getItem(CONFIG.STORAGE_KEY);
      if (!raw) return storageOk ? [] : memoryHistory;
      const data = JSON.parse(raw);
      if (!Array.isArray(data)) return [];
      return data.filter(function (e) {
        return e && typeof e.id === 'string' && typeof e.score === 'number' && Array.isArray(e.ruleIds);
      });
    } catch (err) {
      storageOk = false;
      return memoryHistory;
    }
  }

  function saveHistory(list) {
    const trimmed = list.slice(0, CONFIG.MAX_HISTORY);
    memoryHistory = trimmed;
    try {
      localStorage.setItem(CONFIG.STORAGE_KEY, JSON.stringify(trimmed));
    } catch (err) {
      if (storageOk) toast('Browser storage is unavailable, so history will be lost when you close this tab.');
      storageOk = false;
    }
  }

  function computeStats(list) {
    const counts = {};
    let high = 0, recent = 0;
    const cutoff = Date.now() - CONFIG.RECENT_DAYS * 86400000;
    list.forEach(function (e) {
      if (e.level === 'high' || e.level === 'critical') high++;
      if (e.ts >= cutoff) recent++;
      e.ruleIds.forEach(function (id) { counts[id] = (counts[id] || 0) + 1; });
    });
    let topId = null;
    Object.keys(counts).forEach(function (id) { if (topId === null || counts[id] > counts[topId]) topId = id; });
    return { total: list.length, high: high, recent: recent, top: topId ? RULE_INDEX[topId].title : null, topCount: topId ? counts[topId] : 0 };
  }

  /* ================================================================
   * 7. UI STATE + RENDERING
   * ================================================================ */
  const VIEWS = ['dashboard', 'analyze', 'history', 'tips', 'about'];
  let demoMode = false;
  let demoIndex = 0;
  let analyzing = false;

  function formatDate(ts) {
    try {
      return new Date(ts).toLocaleString(lang === 'te' ? 'te-IN' : 'en-IN', { dateStyle: 'medium', timeStyle: 'short' });
    } catch (e) { return new Date(ts).toString(); }
  }

  let toastTimer = null;
  function toast(msg) {
    const el = $('#toast');
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.classList.remove('show'); }, 3200);
  }

  /* ---------- dialog ---------- */
  function openDialog(title, bodyNode, actions) {
    const dlg = $('#dlg');
    $('#dlgTitle').textContent = title;
    const body = $('#dlgBody');
    body.replaceChildren(bodyNode);
    const bar = $('#dlgActions');
    bar.replaceChildren();
    actions.forEach(function (a) {
      bar.appendChild(h('button', {
        type: 'button', class: 'btn ' + (a.kind || 'ghost'), text: a.label,
        onclick: function () { closeDialog(); if (a.onClick) a.onClick(); }
      }));
    });
    if (typeof dlg.showModal === 'function') { if (!dlg.open) dlg.showModal(); }
    else dlg.setAttribute('open', '');
  }
  function closeDialog() {
    const dlg = $('#dlg');
    if (typeof dlg.close === 'function') dlg.close(); else dlg.removeAttribute('open');
  }

  /* ---------- findings ---------- */
  function findingCard(f, withPhrase) {
    return h('li', { class: 'finding sev-' + f.severity },
      h('div', { class: 'finding-head' },
        h('h4', { text: f.title }),
        h('span', { class: 'weight', text: '+' + f.weight })
      ),
      h('p', { class: 'finding-meta' }, f.category + ' • severity: ' + f.severity + ' • rule ' + f.id),
      withPhrase && f.phrase ? h('p', { class: 'finding-phrase' }, 'Matched: ', h('q', { text: f.phrase })) : null,
      f.detail ? h('p', { class: 'finding-detail', text: f.detail }) : null,
      h('p', { class: 'finding-why' }, h('strong', { text: 'Why it matters: ' }), f.explanation),
      h('p', { class: 'finding-do' }, h('strong', { text: 'What to do: ' }), f.action)
    );
  }

  function recommendedActions(findings) {
    const seen = {};
    const out = [];
    findings.forEach(function (f) { if (!seen[f.action]) { seen[f.action] = 1; out.push(f.action); } });
    const base = [
      'Verify the sender using an official website, app or phone number that you look up yourself.',
      'If you already paid or shared details, call your bank immediately and report at cybercrime.gov.in or helpline 1930.'
    ];
    return out.concat(base);
  }

  function renderResult(result, text, isDemo) {
    const panel = $('#resultPanel');
    panel.replaceChildren();
    const n = result.findings.length;
    const heading = h('h3', { id: 'resultHeading', tabindex: '-1', class: 'level-title' }, levelBadge(result.level), ' ' + (lang === 'te' ? '' : 'risk'));

    const summary = h('section', { class: 'summary', 'data-level': result.level, 'aria-labelledby': 'resultHeading' },
      buildRing(result.score, result.level),
      h('div', { class: 'summary-copy' },
        heading,
        h('p', { class: 'summary-line', text: t('sum.' + result.level) }),
        h('p', { class: 'summary-facts' },
          h('strong', { text: String(n) }), ' ' + (n === 1 ? t('sign') : t('signs')) + ' detected')
      )
    );
    panel.appendChild(summary);

    if (text !== null) {
      panel.appendChild(h('section', { class: 'block' },
        h('h3', { text: 'Your message, with suspicious phrases marked' }),
        highlightedText(text, result.highlights, 'msg-text boxed'),
        n === 0 ? h('p', { class: 'muted', text: 'Nothing in this message matched the known warning signs.' }) : null
      ));
    }

    if (result.safeAdviceDetected) {
      panel.appendChild(h('p', { class: 'notice info' },
        h('strong', { text: 'Security-advice wording found. ' }),
        'Parts of this message look like safety advice (for example "never share your OTP"), so those sentences were not treated as requests. Genuine alerts use this wording, and scammers can copy it, so still verify the sender.'));
    }

    if (n === 0) {
      panel.appendChild(h('p', { class: 'notice warn' },
        h('strong', { text: 'No warning signs matched, but this is not a safety guarantee. ' }),
        'Sophisticated scams avoid known keywords, and genuine messages can contain suspicious ones. If the message asks you to click, pay or share anything, verify it first.'));
    } else {
      panel.appendChild(h('section', { class: 'block' },
        h('h3', { text: 'Warning signs found' }),
        h('ul', { class: 'findings' }, result.findings.map(function (f) { return findingCard(f, text !== null); }))
      ));
    }

    panel.appendChild(h('section', { class: 'block' },
      h('h3', { text: 'Recommended actions' }),
      h('ul', { class: 'actions-list' }, recommendedActions(result.findings).map(function (a) { return h('li', { text: a }); }))
    ));

    panel.appendChild(h('p', { class: 'disclaimer', text: t('disclaimer') }));

    const buttons = h('div', { class: 'result-actions' },
      h('button', { type: 'button', class: 'btn primary', id: 'againBtn', text: 'Analyze Another Message', onclick: analyzeAnother })
    );
    if (isDemo) {
      buttons.appendChild(h('button', { type: 'button', class: 'btn ghost', id: 'nextDemoBtn', text: 'Next demo sample', onclick: nextDemo }));
    }
    panel.appendChild(buttons);

    $('#emptyState').hidden = true;
    panel.hidden = false;
  }

  function resetResults() {
    $('#resultPanel').hidden = true;
    $('#resultPanel').replaceChildren();
    $('#emptyState').hidden = false;
  }

  /* ---------- dashboard stats, history ---------- */
  function renderStats() {
    const list = loadHistory();
    const s = computeStats(list);
    $('#statTotal').textContent = String(s.total);
    $('#statHigh').textContent = String(s.high);
    $('#statRecent').textContent = String(s.recent);
    $('#statTop').textContent = s.top || 'None yet';
    $('#statTopNote').textContent = s.top ? 'Seen in ' + s.topCount + (s.topCount === 1 ? ' scan' : ' scans') : 'Run a scan to see this';
  }

  function historyItem(e, compact) {
    const kids = [
      h('span', { class: 'score-chip', 'data-level': e.level, text: String(e.score) }),
      h('div', { class: 'hist-main' },
        h('p', { class: 'hist-preview', text: e.preview || '[preview not saved]' }),
        h('p', { class: 'hist-meta' }, formatDate(e.ts) + ' • ', levelBadge(e.level), ' • ' + e.ruleIds.length + ' ' + (e.ruleIds.length === 1 ? t('sign') : t('signs')))
      )
    ];
    if (!compact) {
      kids.push(h('div', { class: 'hist-actions' },
        h('button', { type: 'button', class: 'btn small ghost', text: 'View summary', 'aria-label': 'View summary of scan from ' + formatDate(e.ts), onclick: function () { showSummary(e); } }),
        h('button', { type: 'button', class: 'btn small danger', text: 'Delete', 'aria-label': 'Delete scan from ' + formatDate(e.ts), onclick: function () { deleteEntry(e.id); } })
      ));
    }
    return h('li', { class: 'hist-item', 'data-level': e.level }, kids);
  }

  function renderHistory() {
    const list = loadHistory();
    const ul = $('#historyList');
    ul.replaceChildren();
    list.forEach(function (e) { ul.appendChild(historyItem(e, false)); });
    $('#historyEmpty').hidden = list.length > 0;
    $('#clearHistoryBtn').disabled = list.length === 0;
    $('#historyCount').textContent = list.length + ' of ' + CONFIG.MAX_HISTORY + ' saved';

    const recent = $('#recentList');
    recent.replaceChildren();
    list.slice(0, 3).forEach(function (e) { recent.appendChild(historyItem(e, true)); });
    $('#recentEmpty').hidden = list.length > 0;
  }

  function refreshAll() { renderStats(); renderHistory(); }

  function showSummary(e) {
    const findings = e.ruleIds.filter(function (id) { return RULE_INDEX[id]; }).map(function (id) {
      const r = RULE_INDEX[id];
      return { id: r.id, category: r.category, severity: r.severity, title: r.title, explanation: r.explanation, action: r.action, weight: r.weight, phrase: '', detail: '' };
    });
    const body = h('div', { class: 'summary-dlg' },
      h('p', { class: 'hist-meta' }, formatDate(e.ts) + ' • score ' + e.score + '/100 • ', levelBadge(e.level)),
      h('p', { class: 'boxed msg-text', text: e.preview || '[preview not saved]' }),
      findings.length
        ? h('ul', { class: 'findings' }, findings.map(function (f) { return findingCard(f, false); }))
        : h('p', { class: 'muted', text: 'No known warning signs matched. This is not a safety guarantee.' }),
      h('p', { class: 'disclaimer', text: t('disclaimer') })
    );
    openDialog('Scan summary', body, [{ label: 'Close', kind: 'primary' }]);
  }

  function deleteEntry(id) {
    saveHistory(loadHistory().filter(function (e) { return e.id !== id; }));
    refreshAll();
    toast('Scan deleted.');
  }

  function confirmClear() {
    openDialog('Clear all scan history?',
      h('p', { text: 'This removes every saved scan from this browser. It cannot be undone.' }),
      [{ label: 'Cancel', kind: 'ghost' }, { label: 'Clear history', kind: 'danger', onClick: function () { saveHistory([]); refreshAll(); toast('History cleared.'); } }]);
  }

  function confirmReset() {
    openDialog('Reset all demo data?',
      h('p', { text: 'This clears your scan history and saved settings (such as language) and empties the message box.' }),
      [{ label: 'Cancel', kind: 'ghost' }, { label: 'Reset everything', kind: 'danger', onClick: resetAll }]);
  }

  function resetAll() {
    try { localStorage.removeItem(CONFIG.STORAGE_KEY); localStorage.removeItem(CONFIG.LANG_KEY); } catch (e) { /* storage may be unavailable */ }
    memoryHistory = [];
    demoMode = false;
    $('#messageInput').value = '';
    updateCounter();
    setError('');
    resetResults();
    setLang('en', true);
    refreshAll();
    toast('Demo data reset.');
  }

  /* ---------- analyzer ---------- */
  function setError(msg) {
    const el = $('#inputError');
    el.textContent = msg;
    el.hidden = !msg;
    $('#messageInput').setAttribute('aria-invalid', msg ? 'true' : 'false');
  }

  function updateCounter() {
    const len = $('#messageInput').value.length;
    const el = $('#charCount');
    el.textContent = len.toLocaleString('en-IN') + ' / ' + CONFIG.MAX_INPUT.toLocaleString('en-IN');
    el.classList.toggle('near', len > CONFIG.MAX_INPUT * 0.9 && len <= CONFIG.MAX_INPUT);
    el.classList.toggle('over', len > CONFIG.MAX_INPUT);
  }

  function runAnalysis(opts) {
    if (analyzing) return;
    const v = validateInput($('#messageInput').value);
    if (!v.ok) {
      setError(v.code === 'empty'
        ? 'Paste a message first, or pick one of the samples below.'
        : 'This message is longer than ' + CONFIG.MAX_INPUT.toLocaleString('en-IN') + ' characters. Paste only the part that looks suspicious.');
      $('#messageInput').focus();
      return;
    }
    setError('');
    analyzing = true;
    const btn = $('#analyzeBtn');
    btn.classList.add('loading');
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');

    setTimeout(function () {
      try {
        const result = analyzeMessage(v.text);
        renderResult(result, v.text, demoMode);
        const store = $('#storePreview').checked;
        const entry = {
          id: Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
          ts: Date.now(), score: result.score, level: result.level,
          ruleIds: result.findings.map(function (f) { return f.id; }),
          preview: store ? makePreview(v.text) : ''
        };
        saveHistory([entry].concat(loadHistory()));
        refreshAll();
        const heading = $('#resultHeading');
        const box = $('#resultPanel .summary');
        if (heading && box) {
          box.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
          heading.focus({ preventScroll: true });
        }
      } catch (err) {
        setError('Something went wrong while analyzing this message. Please try again or clear the text.');
      } finally {
        analyzing = false;
        btn.classList.remove('loading');
        btn.disabled = false;
        btn.removeAttribute('aria-busy');
      }
    }, (opts && opts.instant) ? 0 : 350);
  }

  function loadSample(i) {
    $('#messageInput').value = SAMPLES[i].text;
    updateCounter();
    setError('');
  }

  function analyzeAnother() {
    demoMode = false;
    $('#messageInput').value = '';
    updateCounter();
    resetResults();
    setError('');
    $('#messageInput').focus();
    $('#messageInput').scrollIntoView({ block: 'center', behavior: 'auto' });
  }

  function startDemo() {
    demoMode = true;
    demoIndex = 0;
    navigate('analyze');
    loadSample(demoIndex);
    runAnalysis({ instant: true });
  }

  function nextDemo() {
    demoIndex = (demoIndex + 1) % SAMPLES.length;
    loadSample(demoIndex);
    runAnalysis({ instant: true });
  }

  /* ---------- hero example (computed by the real engine) ---------- */
  function renderHero() {
    const text = SAMPLES[1].text;
    const result = analyzeMessage(text);
    const box = $('#heroXray');
    box.replaceChildren(
      h('p', { class: 'xray-title', text: 'Example message, checked right here in your browser' }),
      highlightedText(text, result.highlights, 'msg-text xray-msg'),
      h('div', { class: 'xray-foot' },
        buildRing(result.score, result.level),
        h('ul', { class: 'xray-signs', 'aria-label': 'Warning signs found in the example' },
          result.findings.map(function (f) { return h('li', { class: 'sev-' + f.severity, text: f.title }); }))
      )
    );
  }

  /* ---------- navigation ---------- */
  let firstNav = true;
  function currentView() {
    const id = (location.hash || '').replace('#', '');
    return VIEWS.indexOf(id) !== -1 ? id : 'dashboard';
  }

  function navigate(view) {
    if (location.hash === '#' + view) showView(view); else location.hash = '#' + view;
  }

  function showView(view) {
    VIEWS.forEach(function (v) { $('#view-' + v).hidden = v !== view; });
    $$('.nav a').forEach(function (a) {
      if (a.getAttribute('data-nav') === view) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
    });
    applyTitle(view);
    closeNav();
    if (view === 'history' || view === 'dashboard') refreshAll();
    if (!firstNav) {
      window.scrollTo(0, 0);
      const hd = $('#view-' + view + ' .view-heading');
      if (hd) hd.focus({ preventScroll: true });
    }
    firstNav = false;
  }

  function applyTitle(view) {
    const titleEl = $('#viewTitle'), subEl = $('#viewSub');
    const tTitle = $('[data-i18n="title.' + view + '"]', $('#titleStore'));
    const tSub = $('[data-i18n="sub.' + view + '"]', $('#titleStore'));
    titleEl.textContent = lang === 'te' && TE['title.' + view] ? TE['title.' + view] : tTitle.textContent;
    subEl.textContent = lang === 'te' && TE['sub.' + view] ? TE['sub.' + view] : tSub.textContent;
    document.title = titleEl.textContent + ' | ScamShield AI';
  }

  function openNav() {
    document.body.classList.add('nav-open');
    $('#menuBtn').setAttribute('aria-expanded', 'true');
  }
  function closeNav() {
    document.body.classList.remove('nav-open');
    $('#menuBtn').setAttribute('aria-expanded', 'false');
  }

  /* ---------- language ---------- */
  function setLang(next, silent) {
    lang = next === 'te' ? 'te' : 'en';
    document.documentElement.lang = lang === 'te' ? 'te' : 'en';
    $$('[data-i18n]').forEach(function (el) {
      if (el.hasAttribute('data-en') === false) el.setAttribute('data-en', el.textContent);
      const key = el.getAttribute('data-i18n');
      el.textContent = lang === 'te' && TE[key] ? TE[key] : el.getAttribute('data-en');
    });
    $('#langEn').setAttribute('aria-pressed', String(lang === 'en'));
    $('#langTe').setAttribute('aria-pressed', String(lang === 'te'));
    $('#teNote').hidden = lang !== 'te';
    applyTitle(currentView());
    if (!silent) { try { localStorage.setItem(CONFIG.LANG_KEY, lang); } catch (e) { /* ignore */ } }
    renderHero();
    refreshAll();
  }

  /* ================================================================
   * 8. INIT
   * ================================================================ */
  function init() {
    // capture English text of every translatable node once
    $$('[data-i18n]').forEach(function (el) { el.setAttribute('data-en', el.textContent); });

    // sample chips
    const chips = $('#sampleChips');
    SAMPLES.forEach(function (s, i) {
      chips.appendChild(h('button', {
        type: 'button', class: 'chip', text: s.label,
        onclick: function () { demoMode = false; loadSample(i); $('#messageInput').focus(); }
      }));
    });

    $('#messageInput').addEventListener('input', function () { updateCounter(); if ($('#inputError').hidden === false) setError(''); });
    $('#messageInput').addEventListener('keydown', function (e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runAnalysis(); }
    });
    $('#analyzer').addEventListener('submit', function (e) { e.preventDefault(); demoMode = false; runAnalysis(); });
    $('#clearBtn').addEventListener('click', function () {
      demoMode = false;
      $('#messageInput').value = '';
      updateCounter(); setError(''); resetResults();
      $('#messageInput').focus();
    });

    $('#heroAnalyze').addEventListener('click', function () { navigate('analyze'); });
    $('#heroDemo').addEventListener('click', startDemo);
    $('#clearHistoryBtn').addEventListener('click', confirmClear);
    $('#resetBtn').addEventListener('click', confirmReset);
    $('#langEn').addEventListener('click', function () { setLang('en'); });
    $('#langTe').addEventListener('click', function () { setLang('te'); });
    $('#menuBtn').addEventListener('click', function () { document.body.classList.contains('nav-open') ? closeNav() : openNav(); });
    $('#overlay').addEventListener('click', closeNav);
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeNav(); });
    $('#dlg').addEventListener('click', function (e) { if (e.target === $('#dlg')) closeDialog(); });
    $$('[data-goto]').forEach(function (a) {
      a.addEventListener('click', function (e) { e.preventDefault(); navigate(a.getAttribute('data-goto')); });
    });

    window.addEventListener('hashchange', function () { showView(currentView()); });

    let saved = 'en';
    try { saved = localStorage.getItem(CONFIG.LANG_KEY) || 'en'; } catch (e) { /* ignore */ }
    updateCounter();
    setLang(saved, true);
    showView(currentView());
    refreshAll();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})(typeof window !== 'undefined' ? window : globalThis);
