# ScamShield AI: Test Cases

Status key: **Pass** = executed and matched the expected result during development. **Manual** = please repeat by hand before the demo (not automated).

How these were run: the detection engine was run in Node.js on each message; the interface was driven in headless Chromium (opened from `file://`) with screenshots reviewed. The optional Java engine class was compiled with `javac` and gave identical scores. The full Spring Boot project was **not** built (see `optional-backend/README.md`).

## 1. Sample messages

| # | Sample | Expected | Result |
|---|---|---|---|
| 1 | Fake job offer | Critical, rules SS-002, SS-006, SS-012, score 75 | Pass |
| 2 | OTP phishing | High, rules SS-001, SS-003, SS-004, score 72 | Pass |
| 3 | Prize scam | High, rules SS-002, SS-005, score 50 | Pass |
| 4 | Payment request | High, rules SS-003, SS-004, SS-011, score 62 | Pass |
| 5 | Ordinary notice | Low, score 0, "no warning signs, not a guarantee" notice | Pass |
| 6 | Security reminder | Low, score 0, security-advice notice shown | Pass |

Samples are illustrative: no sample is a promise that a real message is fraudulent or genuine.

## 2. Input validation

| Test | Steps | Expected | Result |
|---|---|---|---|
| Empty input | Click Analyze with an empty or spaces-only box | Friendly message: "Paste a message first, or pick one of the samples below." No result, nothing saved | Pass |
| Very long input | Paste 5,001 characters, click Analyze | Message says the limit is 5,000 characters; counter turns red; nothing analysed | Pass |
| Counter | Type text | Counter updates live; amber above 90 percent | Manual |

## 3. Special characters and HTML

| Test | Input | Expected | Result |
|---|---|---|---|
| HTML / script | `<img src=x onerror=window.__x=1><script>window.__x=2</script> Pay registration fee now for job` | Shown as plain text; no image element created; `window.__x` stays undefined; score 55 High (SS-002, SS-012) | Pass |
| Emoji and Indian rupee sign | `Earn ₹5,000 daily` | Analyzed normally | Pass |

## 4. Multiple and no warning signs

| Test | Input | Expected | Result |
|---|---|---|---|
| Many signs | "Dear customer, your SBI KYC is pending. Click http://sbi-kyc-update.xyz/login now or account will be blocked within 2 hours. Share Aadhaar and OTP. Do not tell anyone." | 7 signs, score capped at 100, Critical | Pass |
| No signs | "Hi, are we still meeting for lunch at 1 pm tomorrow?" | 0, Low, with "not a safety guarantee" notice | Pass |
| Advice wording | "Your OTP is 482913. Do not share it with anyone." | 0, Low (advice sentence recognised) | Pass |
| App install | "Install AnyDesk app and give me the code to receive refund" | 28 Moderate (SS-009) | Pass |

## 5. Scan history

| Test | Steps | Expected | Result |
|---|---|---|---|
| Persistence | Analyze several messages, reload the page, open Scan History | Entries still listed, newest first | Pass |
| View summary | Click View summary | Dialog shows score, category, warning signs | Pass |
| Delete one | Click Delete on an entry | Entry removed, count and dashboard stats update | Pass |
| Clear history | Click Clear history, confirm | All entries removed; confirmation dialog appears first | Pass |
| Preview masking | Analyze text containing a 13-digit number and an e-mail address | History shows bullets and `[email]` instead | Pass |
| No-preview option | Untick "Save a short preview", analyze | Stored entry has an empty preview | Pass |
| 100-entry limit | Add more than 100 scans | Only newest 100 kept | Manual |

## 6. Clear data

| Test | Steps | Expected | Result |
|---|---|---|---|
| Reset demo data | Switch to Telugu, click Reset demo data, confirm | History empty, language back to English, stored language removed | Pass |

## 7. Navigation, language and layout

| Test | Expected | Result |
|---|---|---|
| All five menu items open the right page; browser Back works | Pages switch with the URL hash | Pass |
| Try a Demo | Opens Analyze, runs sample 1; Next demo sample cycles through all six | Pass |
| Telugu toggle | Navigation, hero, stats, tips switch to Telugu; unreviewed-translation note shown on Tips | Pass |
| Mobile (390 px wide) | No horizontal scrolling; menu button opens the drawer; hero and buttons stack | Pass |
| Tablet and large desktop | Layout reflows without overlap | Manual |
| Keyboard | Tab reaches every control with a visible focus ring; Esc closes the mobile menu | Manual |
| Console | No JavaScript errors during all of the above | Pass |

## 8. Known limitations found during testing
- Rules are keyword and pattern based, so paraphrased scams can score 0.
- A genuine message that mentions a fee or a job together may be flagged.
- Security-advice detection could be imitated by a scammer, so the app still tells users to verify.
