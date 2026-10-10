# ScamShield AI

**Smart Digital Scam Detection Assistant.** Paste a suspicious SMS, email or chat message and ScamShield AI shows an illustrative risk score (0 to 100), marks the suspicious phrases, explains why each one matters, and suggests what to do next.

It is a **rule-based scam-awareness engine**, not a trained AI model. It runs 100% in your browser: no API key, no server, no message ever leaves your device.

---

## 1. Project overview

| | |
|---|---|
| Name | ScamShield AI |
| Type | Standalone web app (HTML, CSS, vanilla JavaScript) |
| Optional | Java Spring Boot REST API with the same rules (`optional-backend/`) |
| Languages | English, plus a draft Telugu interface (unreviewed) |
| Needs | Only a modern browser (Chrome, Edge, Firefox) |

## 2. The real-life problem

Phishing SMS, fake job offers, "you won a prize" messages and urgent payment requests reach people every day. They work by creating fear or excitement, and people rarely have a quick way to ask "what exactly is suspicious here?". Many victims in India lose money to fake job fees, OTP theft and payment-redirect scams.

## 3. Key features

- Analyzer with character counter, validation, clear button and six sample messages
- Risk meter (0 to 100) with Low, Moderate, High and Critical categories
- Suspicious phrases highlighted inside your message
- 14 explainable rules in 10 categories, each with a reason, severity, recommended action and score contribution
- Security-advice sentences ("never share your OTP") are not mistaken for scam requests
- Scan history (add, view summary, delete one, clear all with confirmation, reset demo data)
- Dashboard statistics calculated from your own saved history (nothing invented)
- Demo mode that steps through the samples for presentations
- Safety Tips page with India-specific reporting (cybercrime.gov.in, helpline 1930)
- English and Telugu interface toggle
- Responsive layout, keyboard focus, reduced-motion support

## 4. Technology stack

- HTML5, CSS3, vanilla JavaScript (no framework, no build step, no npm)
- `localStorage` for history
- System fonts only, so it works offline
- Optional: Java 17 and Spring Boot 3 for a REST API (see `optional-backend/README.md`)

## 5. Folder structure

```
ScamShield-AI/
├── index.html          Page structure (all five views)
├── style.css           Design system, layout, responsive rules
├── script.js           Detection engine + UI logic
├── assets/logo.svg     Logo and favicon
├── README.md           This file
├── USER_GUIDE.md       Step-by-step guide for users
├── TEST_CASES.md       Test plan and recorded results
├── .gitignore
└── optional-backend/   Optional Spring Boot API (not needed to run the app)
```

## 6. How the risk scoring works

1. The engine checks 14 rules (IDs `SS-001` to `SS-014`). Each rule has a **weight** (its score contribution) and a **severity**.
2. Every rule counts **at most once**, however many times it matches.
3. The weights of all matched rules are **added and capped at 100**.
4. The total is mapped to a category using configurable thresholds:

| Score | Category |
|---|---|
| 0 to 24 | Low |
| 25 to 49 | Moderate |
| 50 to 74 | High |
| 75 to 100 | Critical |

Rule weights and thresholds live at the top of `script.js` (`CONFIG` and `RULES`), so you can tune them.

**Important:** the score is a heuristic indicator, **not a probability** that a message is fraudulent. A score of 0 never means "safe": clever scams avoid known keywords, and genuine messages can contain suspicious ones.

The 10 categories: credential requests, advance payments, urgent threats, unrealistic rewards, suspicious links, app-install requests, impersonation, money-transfer requests, job offers that require payment, and requests for sensitive information.

## 7. How privacy is handled

- Analysis runs only in the browser. There are **no network requests** (the page's Content Security Policy blocks them).
- User text is shown with `textContent` / safe DOM building only. `innerHTML` and `eval()` are never used, so pasted HTML or JavaScript cannot run.
- History keeps only: time, score, category, matched rule IDs and an optional **masked preview** of up to 80 characters (long digit runs and e-mail addresses are masked). You can untick "Save a short preview" to store no text at all.
- Data stays in this browser's `localStorage`. Delete one scan, clear all history, or use **Reset demo data**.
- The app never asks for real OTPs, passwords or bank details.

## 8. Limitations

- Fixed rules, not a trained model. It cannot learn new scams.
- Keyword and pattern based: it can miss scams and can over-flag genuine messages.
- Tuned for English and common Indian scam patterns.
- The Telugu translation is an unreviewed draft and covers navigation, buttons, risk labels and tips only (not rule explanations).
- It cannot check whether a link, phone number or sender really exists.

## 9. How to run on Windows 10/11

**Easiest (no install):**

1. Unzip `ScamShield-AI.zip` (right-click, **Extract All**).
2. Open the `ScamShield-AI` folder and **double-click `index.html`**. It opens in your default browser.

That is all. It works offline.

**If double-click does not work, or you prefer a local server:**

- **VS Code Live Server:** install VS Code, add the "Live Server" extension, open the folder, right-click `index.html`, choose **Open with Live Server**.
- **Python (if installed):** open PowerShell in the folder and run `python -m http.server 8000`, then browse to `http://localhost:8000`.

No `npm install`, Java or API key is needed for the standalone app.

## 10. How to use the sample messages

1. Open **Analyze Message**.
2. Click a sample chip, for example "OTP phishing".
3. Press **Analyze Message** (or Ctrl + Enter).
4. Read the score, the highlighted phrases and the explanations.

The samples are illustrative only. They are not promises that a message is genuinely fraudulent or genuinely safe.

| Sample | Result with the current rules |
|---|---|
| Fake job offer | 75, Critical |
| OTP phishing | 72, High |
| Prize scam | 50, High |
| Payment request | 62, High |
| Ordinary notice | 0, Low (no known warning signs, not a guarantee) |
| Security reminder | 0, Low (security advice wording recognised) |

## 11. How to prepare a hackathon demonstration

- Open the app a few minutes early, press **Reset demo data** (Scan History) so statistics start clean.
- Use a full-screen browser at 100 to 125 percent zoom.
- Have the Dashboard open. Keep this README's demo sequence (below) handy.
- Test once on the venue network or offline. The app needs neither.
- Keep a backup: the ZIP on a USB stick and the folder on your desktop.

## 12. Troubleshooting

| Problem | Fix |
|---|---|
| Page is blank or unstyled | Make sure `index.html`, `style.css`, `script.js` and the `assets` folder stay together. |
| Buttons do nothing | Open the browser console (F12). Make sure JavaScript is enabled and `script.js` loaded. |
| History disappears | The browser is in private mode or blocks storage. Use a normal window. |
| Telugu shows as boxes | Windows needs the "Nirmala UI" font (installed by default on 10/11). |
| Old version showing | Hard refresh with Ctrl + F5. |

---

# Hackathon pitch

## Problem statement
People receive suspicious messages daily but have no quick, private way to understand *what* is suspicious about them. Existing tools either say only "scam / not scam" or send your message to a server.

## Target users
Students, first-time job seekers, parents and senior citizens, small shop owners, and anyone who receives SMS, e-mail or chat messages that ask them to click, pay or share details.

## Proposed solution
ScamShield AI explains suspicious messages. It highlights the matching phrases, explains why each matters in plain language, and suggests safe next steps, all inside the browser.

## Main features
Risk meter and categories, highlighted phrases, 14 explainable rules, scan history with delete and reset, dashboard stats from real local data, demo mode, safety tips with India reporting links, English and Telugu toggle.

## Architecture
```
Browser (index.html + style.css + script.js)
 ├─ Rule engine (14 rules, configurable weights and thresholds)
 ├─ UI renderer (safe DOM, no innerHTML)
 └─ localStorage (masked previews + rule IDs only)

Optional: Spring Boot API  POST /api/analyze  (same rules in Java, future AI integration point)
```

## What is innovative
- **Explainability first:** every point of the score traces to a named rule and a highlighted phrase.
- **Context awareness:** security-advice sentences are recognised, so a genuine "never share your OTP" reminder is not flagged.
- **Privacy by design:** zero network requests, enforced by a Content Security Policy.
- **Honest uncertainty:** it never says a message is "safe", and says so on screen.

## Limitations
Rule-based and keyword driven; English-focused; cannot verify senders or links; Telugu text unreviewed. Detection accuracy has **not** been measured on a real dataset, so no accuracy figure is claimed.

## Future improvements
Optional language-model explanations via the backend (with user consent), reviewed translations in more languages, link-reputation checks, a browser extension, and evaluation on a labelled dataset.

## 60-second presentation script
> "Every day, people get messages like 'your account will be blocked, reply with your OTP'. Most of us can sense something is wrong, but we can't say why, and scammers rely on that moment of doubt.
> ScamShield AI is a privacy-first scam-awareness assistant. You paste a message, and it highlights the exact phrases that match known scam patterns, gives an illustrative risk score from 0 to 100, explains each warning sign in plain language, and tells you what to do next.
> It runs entirely in your browser. No message is uploaded, and there is no API key. It's a rule-based engine, so every score is explainable, and it never claims a message is safe, only what it noticed.
> Our goal is not to replace judgment but to teach people to recognise the signs themselves. Thank you."

## Two-minute live-demo sequence
1. **(0:00)** Dashboard: read the headline, point to the example with highlighted phrases and the "Local only" badge.
2. **(0:20)** Click **Try a Demo**. Show the Fake job offer result: Critical, highlighted "registration fee", read one explanation.
3. **(0:50)** Click **Next demo sample** twice (OTP phishing, Prize scam). Show the score changing with the message.
4. **(1:10)** Paste your own message with an HTML tag (for example `<b>test</b>`) to show it is displayed as text, not executed.
5. **(1:25)** Load the **Security reminder** sample: Low, with the notice explaining why advice wording is not treated as a request.
6. **(1:40)** Open **Scan History**: view a summary, delete one entry, show the privacy note.
7. **(1:55)** Open **Safety Tips** (cybercrime.gov.in, 1930) and close with the limitations.

## Likely judges' questions and honest answers

**Is this real AI?**
No. It is a rule-based engine with explainable rules. We deliberately call it a scam-awareness engine. The Java backend is the place to plug in a language model later.

**How accurate is it?**
We have not measured accuracy on a real dataset, so we do not claim a number. We tested the rules against sample messages and edge cases (see `TEST_CASES.md`). It can miss scams and can over-flag genuine messages.

**Why not use a machine-learning model?**
We had limited time and wanted something that works offline, protects privacy, and can explain each result. A model would need labelled data and careful evaluation.

**What about privacy?**
Analysis is local. History is stored only in your browser, as a masked 80-character preview (optional) plus rule IDs. A Content Security Policy blocks network calls.

**Can scammers just avoid the keywords?**
Yes, and the app says so. That is why a score of 0 is never shown as "safe", and why the long-term plan includes AI-assisted analysis and link reputation.

**Who is it for and what is the impact?**
Students, job seekers and families. We have not run user research, so we make no impact claims. The stats on the dashboard come only from the user's own local history.

**What would you build next?**
Reviewed regional-language support, a browser extension, link checks against official lists, and evaluation on labelled data.
