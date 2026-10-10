package com.scamshield.service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;

/**
 * Rule-based scam-awareness engine. This is a Java port of the rules in the
 * browser app (script.js) so both give the same explainable result.
 * It is NOT a trained AI model and its score is a heuristic, not a probability.
 * Message text is analysed in memory only and is never logged or stored.
 */
@Service
public class ScamAnalysisService {

    public static final int MAX_INPUT = 5000;
    private static final int CI = Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE;
    private static final int MODERATE = 25;
    private static final int HIGH = 50;
    private static final int CRITICAL = 75;

    private static final Pattern SAFE_CONTEXT = Pattern.compile(
        "\\b(?:never|do not|don't|dont|should not|shouldn't|must not|will never|won't|never ever)\\s+(?:ever\\s+)?"
        + "(?:share|disclose|give|reveal|provide|send|click|download|install|enter|transfer|pay)\\b"
        + "[^.!?\\n]{0,60}\\b(?:otp|pin|password|cvv|code|card|link|links|app|apps|details|money|anyone|anybody|others?|strangers?|unknown)\\b"
        + "|\\b(?:will never|never|does not|doesn't|do not) ask (?:you )?for\\b", CI);

    private static final Pattern SENTENCE = Pattern.compile("[^.!?\\n]+(?:[.!?]+|$)");

    private static final Pattern URL_PATTERN = Pattern.compile(
        "\\b(?:https?://|www\\.)[^\\s<>\"')]+|\\b[a-z0-9][a-z0-9-]*(?:\\.[a-z0-9-]+)*\\."
        + "(?:com|in|net|org|co|io|xyz|top|click|icu|tk|ml|ga|cf|gq|work|loan|zip|info|biz|site|online|link|live|vip|app|me|ly|gl|gy|gd|to)"
        + "\\b(?:/[^\\s<>\"')]*)?", CI);

    private static final List<String> SHORTENERS = List.of("bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly",
        "is.gd", "rb.gy", "shorturl.at", "ow.ly", "tiny.cc", "rebrand.ly");
    private static final List<String> RISKY_TLDS = List.of("xyz", "top", "click", "icu", "tk", "ml", "ga", "cf",
        "gq", "work", "loan", "zip", "link", "vip", "site", "online", "live");
    private static final Pattern LOOKALIKE = Pattern.compile(
        "(secure|verify|verification|login|update|kyc|alert|bank|account|support|refund|reward|claim|offer)");
    private static final Pattern IP_HOST = Pattern.compile("^\\d{1,3}(?:\\.\\d{1,3}){3}$");
    private static final Pattern JOB_CONTEXT = Pattern.compile(
        "\\b(?:job|jobs|offer letter|recruit\\w*|hiring|vacanc\\w+|placement|work from home|data entry|interview|appointment letter|employment|position)\\b", CI);
    private static final List<Pattern> JOB_PAY = List.of(
        Pattern.compile("\\b(?:pay|deposit|transfer|send|remit)\\b[^.!?\\n]{0,40}\\b(?:fee|fees|charges?|deposit|amount|money|\\u20b9\\s?\\d|rs\\.?\\s?\\d)\\b", CI),
        Pattern.compile("\\b(?:registration|security|training|kit|joining)\\s+(?:fee|fees|deposit|charges?)\\b", CI));

    private enum Kind { PATTERNS, URL_SUSPICIOUS, URL_PLAIN, JOB_PAYMENT }

    private record Rule(String id, String category, String severity, int weight, boolean skipInSafe, Kind kind,
                        String title, String explanation, String action, List<Pattern> patterns) { }

    private record Range(int start, int end) { }

    private record Hit(List<Range> ranges, String detail) { }

    public record Finding(String id, String category, String severity, String title, String explanation,
                          String action, int weight, String phrase, String detail) { }

    public record Result(int score, String level, List<Finding> findings, boolean safeAdviceDetected,
                         int length, String disclaimer) { }

    private final List<Rule> rules = new ArrayList<>();

    public ScamAnalysisService() {
        rules.add(new Rule("SS-001", "Credential request", "critical", 40, true, Kind.PATTERNS,
            "Asks for an OTP, PIN or password",
            "Genuine banks, payment apps and government services never ask you to share an OTP, PIN, CVV or password. Anyone who has them can move money or take over your account.",
            "Never share OTPs, PINs, CVVs or passwords with anyone. Contact your bank through the number on your card or its official website.",
            List.of(
            Pattern.compile("\\b(?:share|send|reply(?:\\s+with)?|tell|give|provide|enter|submit|confirm|verify|forward|text|whatsapp|read out|type)\\b[^.!?\\n]{0,40}?\\b(?:otp|one[- ]time (?:password|pin|code)|upi[- ]?pin|m[- ]?pin|pin(?!\\s*code)|password|passcode|cvv|cvc|security code|verification code)\\b", CI),
            Pattern.compile("\\b(?:otp|pin(?!\\s*code)|password|cvv)\\b[^.!?\\n]{0,20}\\b(?:is required|required|needed|to verify|to confirm|to avoid|to proceed)\\b", CI)
        )));
        rules.add(new Rule("SS-002", "Advance payment", "high", 30, false, Kind.PATTERNS,
            "Asks for an upfront fee",
            "Scammers often ask for a small \"registration\", \"processing\" or \"clearance\" fee before a prize, loan, parcel or job. Genuine winners, lenders and employers do not work this way, and the promised reward never arrives.",
            "Do not pay any fee to receive a prize, loan, refund or job. Check the offer on the organisation's official website first.",
            List.of(
            Pattern.compile("\\b(?:registration|processing|activation|joining|refundable|clearance|release|delivery|handling|admin(?:istration)?|training|verification|insurance|tax|gst|customs|security)\\s+(?:fee|fees|charge|charges|deposit|amount)\\b", CI),
            Pattern.compile("\\bpay\\b[^.!?\\n]{0,30}\\b(?:fee|fees|charges?|deposit)\\b", CI),
            Pattern.compile("\\b(?:small|nominal|one[- ]time)\\s+(?:fee|amount|payment|charge)s?\\b", CI)
        )));
        rules.add(new Rule("SS-003", "Urgent threat", "high", 20, true, Kind.PATTERNS,
            "Threatens blocking, suspension or legal action",
            "Fear is the scammer's main tool. Threats such as \"your account will be blocked\" are designed to make you act before you think or check.",
            "Do not react to threats inside the message. Check your account status in the official app or by calling the bank on a number you trust.",
            List.of(
            Pattern.compile("\\b(?:account|card|sim|number|service|services|kyc|wallet|connection|upi|policy|electricity)\\b[^.!?\\n]{0,35}\\b(?:will be|is being|has been|been|shall be|may be|get)\\s+(?:blocked|suspended|deactivated|frozen|terminated|closed|disconnected|cancelled|locked)\\b", CI),
            Pattern.compile("\\b(?:avoid|prevent|stop)\\b[^.!?\\n]{0,25}\\b(?:suspension|blocking|closure|deactivation|disconnection|service interruption|penalty|legal action)\\b", CI),
            Pattern.compile("\\b(?:legal action|arrest warrant|arrested|police case|court notice|penalty will|fine will be)\\b", CI)
        )));
        rules.add(new Rule("SS-004", "Urgent threat", "medium", 12, false, Kind.PATTERNS,
            "Creates time pressure",
            "Short deadlines (\"in 10 minutes\", \"immediately\") are used to stop you from verifying the message or asking someone you trust.",
            "Slow down. A real organisation will still be there after you verify. Take time to check through an official channel.",
            List.of(
            Pattern.compile("\\b(?:immediately|urgent(?:ly)?|right now|asap|at once|without delay|last chance|final (?:notice|warning|reminder)|act now|today only|expires? (?:today|soon|tonight)|hurry)\\b", CI),
            Pattern.compile("\\b(?:within|in|next)\\s+\\d+\\s*(?:minutes?|mins?|hours?|hrs?)\\b", CI)
        )));
        rules.add(new Rule("SS-005", "Unrealistic reward", "medium", 20, false, Kind.PATTERNS,
            "Claims you won a prize or reward",
            "You cannot win a contest you never entered. \"Prize\" messages are used to collect fees, personal details or to get you to click a harmful link.",
            "Ignore prize and lottery claims you did not sign up for. Do not click, pay or reply.",
            List.of(
            Pattern.compile("\\byou(?:'ve|\\s+have)?\\s+(?:been selected|won|are selected|are the winner)\\b", CI),
            Pattern.compile("\\b(?:lottery|lucky draw|jackpot|grand prize|free gift|gift voucher|cashback offer)\\b", CI),
            Pattern.compile("\\bcongratulations\\b[^.!?\\n]{0,60}\\b(?:won|win|prize|reward|selected|winner)\\b", CI),
            Pattern.compile("\\bclaim\\b[^.!?\\n]{0,20}\\b(?:prize|reward|gift|cash|bonus)\\b", CI),
            Pattern.compile("\\bprize\\b", CI)
        )));
        rules.add(new Rule("SS-006", "Unrealistic reward", "medium", 20, false, Kind.PATTERNS,
            "Promises guaranteed or very easy earnings",
            "Offers of high daily income for little work, with no skills or investment needed, are a common lure in task, investment and fake job scams.",
            "Treat guaranteed-income offers with suspicion. Research the company independently and never pay to start earning.",
            List.of(
            Pattern.compile("\\b(?:earn|make|income|salary|get)\\b[^.!?\\n]{0,25}?(?:\u20b9|\\brs\\.?|\\binr|\\$)\\s?\\d[\\d,]*\\s*(?:\\/|per|a|each)?\\s*(?:day|daily|week|weekly|hour|hourly|month|monthly)\\b", CI),
            Pattern.compile("\\bguaranteed\\s+(?:income|returns?|profit|salary|job|placement)\\b", CI),
            Pattern.compile("\\bdouble your (?:money|investment)\\b", CI),
            Pattern.compile("\\b(?:work from home|part[- ]time)\\b[^.!?\\n]{0,40}\\b(?:earn|income|salary)\\b", CI),
            Pattern.compile("\\bno (?:experience|skills?|investment) (?:needed|required|necessary)\\b", CI),
            Pattern.compile("\\bearn\\b[^.!?\\n]{0,20}\\b(?:lakhs?|crores?)\\b", CI)
        )));
        rules.add(new Rule("SS-007", "Suspicious link", "high", 25, false, Kind.URL_SUSPICIOUS,
            "Contains a suspicious-looking link",
            "Look-alike or disguised web addresses are used to steal logins, card details and OTPs on fake pages.",
            "Do not open the link. Type the official website address yourself or use the official app.",
            List.of()));
        rules.add(new Rule("SS-008", "Suspicious link", "low", 6, false, Kind.URL_PLAIN,
            "Contains a link you should verify",
            "Links in unexpected messages are the most common way scams reach you. This link did not look unusual to the checker, but that is not proof it is safe.",
            "Only open links from senders you know and expect. When unsure, go to the official website directly.",
            List.of()));
        rules.add(new Rule("SS-009", "Unknown app install", "high", 28, true, Kind.PATTERNS,
            "Asks you to install an app or remote-access tool",
            "Fraudsters ask victims to install APK files or screen-sharing apps (such as AnyDesk or TeamViewer) so they can watch the screen, read OTPs and move money.",
            "Install apps only from the official Play Store or App Store, and never install remote-access tools on a stranger's request.",
            List.of(
            Pattern.compile("\\b(?:install|download)\\b[^.!?\\n]{0,40}\\b(?:apk|app|application|software|anydesk|teamviewer|quicksupport|rustdesk|remote access|remote support)\\b", CI),
            Pattern.compile("\\b[\\w-]+\\.apk\\b", CI)
        )));
        rules.add(new Rule("SS-010", "Impersonation", "medium", 12, true, Kind.PATTERNS,
            "Appears to pose as a bank, agency or support team",
            "Scammers copy the tone of banks, couriers, tax and police departments, or customer support to borrow their authority. A generic greeting such as \"Dear customer\" is another common sign.",
            "Do not trust the sender's claim. Look up the organisation's official contact details yourself and ask them directly.",
            List.of(
            Pattern.compile("\\b(?:this is|we are|i am|i'm|calling from|message from|msg from|sent by|official)\\b[^.!?\\n]{0,30}\\b(?:bank|sbi|hdfc|icici|axis|paytm|phonepe|google ?pay|amazon|flipkart|income tax|rbi|customs|police|cbi|trai|uidai|aadhaar|courier|fedex|dhl|support|customer care|helpdesk|cyber ?cell|government|ministry|department|officer|manager)\\b", CI),
            Pattern.compile("\\bdear (?:customer|user|account holder|valued customer|sir\\/madam|beneficiary)\\b", CI),
            Pattern.compile("\\b(?:kyc|pan|aadhaar)\\b[^.!?\\n]{0,30}\\b(?:update|updated|expire|expired|expiry|pending|suspend|suspended|block|blocked|verification)\\b", CI),
            Pattern.compile("\\b(?:your|the)\\s+(?:sbi|hdfc|icici|axis|paytm|phonepe|bank|amazon|flipkart)\\b[^.!?\\n]{0,25}\\b(?:account|card|wallet|order|parcel|kyc)\\b", CI),
            Pattern.compile("\\b(?:customs|courier|parcel)\\b[^.!?\\n]{0,30}\\b(?:held|seized|detained|pending|stuck)\\b", CI)
        )));
        rules.add(new Rule("SS-011", "Money transfer request", "high", 30, true, Kind.PATTERNS,
            "Asks you to send money to an unfamiliar account",
            "Requests to move money to a new, \"safe\" or unknown account or UPI ID are central to impersonation and payment-redirect scams. Money sent this way is very hard to recover.",
            "Never transfer money because of a message alone. Confirm the request with the person or company through a separate, trusted channel.",
            List.of(
            Pattern.compile("\\b(?:transfer|send|deposit|remit|wire|pay)\\b[^.!?\\n]{0,30}\\b(?:money|funds|amount|payment|cash|\u20b9\\s?\\d[\\d,]*|rs\\.?\\s?\\d[\\d,]*)\\b[^.!?\\n]{0,40}\\b(?:to|into)\\b[^.!?\\n]{0,30}\\b(?:account|upi|wallet|number|id|qr)\\b", CI),
            Pattern.compile("\\b(?:transfer|send|pay|deposit)\\b[^.!?\\n]{0,50}\\b(?:new|different|another|unknown|personal|temporary|safe|secure)\\s+(?:bank\\s+)?(?:account|upi)\\b", CI),
            Pattern.compile("\\bscan\\b[^.!?\\n]{0,20}\\bqr\\b[^.!?\\n]{0,40}\\b(?:receive|refund|claim|get)\\b", CI)
        )));
        rules.add(new Rule("SS-012", "Job offer with payment", "high", 25, false, Kind.JOB_PAYMENT,
            "Job offer that requires you to pay",
            "Genuine employers do not charge candidates for registration, training kits, uniforms or \"security deposits\". Paying for a job is the signature of a fake job scam.",
            "Never pay to get a job. Verify the employer through its official website or careers page and walk away if money is requested.",
            List.of()));
        rules.add(new Rule("SS-013", "Sensitive information request", "high", 25, true, Kind.PATTERNS,
            "Asks for sensitive personal or banking details",
            "Aadhaar, PAN, card details, bank logins and ID photos can be used for identity theft and fraud. Legitimate organisations do not collect them through random messages.",
            "Do not share ID numbers, card details or login credentials in reply to a message. Use only the official app or website.",
            List.of(
            Pattern.compile("\\b(?:send|share|submit|provide|upload|enter|confirm|verify|update|reply|fill|give)\\b[^.!?\\n]{0,40}?\\b(?:aadhaar|aadhar|pan (?:card|number)|pan|bank account (?:number|details)|account number|card (?:number|details)|debit card|credit card|date of birth|dob|passport|selfie|photo id|mother'?s maiden name|login (?:id|details|credentials)|net ?banking (?:id|details)|address proof|id proof|expiry date)\\b", CI)
        )));
        rules.add(new Rule("SS-014", "Urgent threat", "medium", 10, false, Kind.PATTERNS,
            "Asks you to keep it secret",
            "Scammers isolate victims by telling them not to discuss the matter with family, friends, the bank or the police. A genuine request can always be checked with others.",
            "Talk to someone you trust before acting. Secrecy requests are a strong reason to stop and verify.",
            List.of(
            Pattern.compile("\\b(?:do not|don't|dont|never)\\s+(?:tell|inform|discuss|mention|call)\\b[^.!?\\n]{0,30}\\b(?:anyone|anybody|family|friends|bank|police|others)\\b", CI),
            Pattern.compile("\\bkeep (?:this|it|the matter) (?:a )?(?:secret|confidential|private)\\b", CI),
            Pattern.compile("\\b(?:confidential|secret) (?:offer|matter|transaction|deal)\\b", CI)
        )));
    }

    /** Analyses one message. The caller must validate length first (see MAX_INPUT). */
    public Result analyze(String text) {
        List<int[]> safe = safeRanges(text);
        List<Finding> findings = new ArrayList<>();
        for (Rule rule : rules) {
            Hit hit = detect(rule, text, safe);
            if (hit == null || hit.ranges().isEmpty()) {
                continue;
            }
            Range first = hit.ranges().get(0);
            findings.add(new Finding(rule.id(), rule.category(), rule.severity(), rule.title(),
                rule.explanation(), rule.action(), rule.weight(),
                text.substring(first.start(), first.end()), hit.detail() == null ? "" : hit.detail()));
        }
        findings.sort(Comparator.comparingInt(Finding::weight).reversed());
        int score = Math.min(100, findings.stream().mapToInt(Finding::weight).sum());
        return new Result(score, levelFor(score), findings, !safe.isEmpty(), text.length(),
            "This score is a heuristic estimate from a fixed set of rules. It is not a probability and cannot "
            + "confirm whether a message is genuine or fraudulent.");
    }

    static String levelFor(int score) {
        if (score >= CRITICAL) {
            return "critical";
        }
        if (score >= HIGH) {
            return "high";
        }
        return score >= MODERATE ? "moderate" : "low";
    }

    private Hit detect(Rule rule, String text, List<int[]> safe) {
        switch (rule.kind()) {
            case URL_SUSPICIOUS: {
                List<Range> flagged = new ArrayList<>();
                String detail = "";
                for (Url u : findUrls(text)) {
                    List<String> reasons = urlReasons(u.url());
                    if (!reasons.isEmpty()) {
                        flagged.add(new Range(u.start(), u.end()));
                        if (detail.isEmpty()) {
                            detail = "The link \"" + u.url() + "\" " + String.join("; ", reasons) + ".";
                        }
                    }
                }
                return flagged.isEmpty() ? null : new Hit(flagged.subList(0, Math.min(3, flagged.size())), detail);
            }
            case URL_PLAIN: {
                List<Url> urls = findUrls(text);
                if (urls.isEmpty()) {
                    return null;
                }
                for (Url u : urls) {
                    if (!urlReasons(u.url()).isEmpty()) {
                        return null;
                    }
                }
                List<Range> ranges = new ArrayList<>();
                for (Url u : urls.subList(0, Math.min(3, urls.size()))) {
                    ranges.add(new Range(u.start(), u.end()));
                }
                return new Hit(ranges, "");
            }
            case JOB_PAYMENT: {
                if (!JOB_CONTEXT.matcher(text).find()) {
                    return null;
                }
                List<Range> ranges = findAll(text, JOB_PAY, safe, false, 2);
                return ranges.isEmpty() ? null : new Hit(ranges, "");
            }
            default: {
                List<Range> ranges = findAll(text, rule.patterns(), safe, rule.skipInSafe(), 3);
                return ranges.isEmpty() ? null : new Hit(ranges, "");
            }
        }
    }

    private static List<Range> findAll(String text, List<Pattern> patterns, List<int[]> safe,
                                       boolean skipSafe, int limit) {
        List<Range> out = new ArrayList<>();
        for (Pattern p : patterns) {
            Matcher m = p.matcher(text);
            while (m.find()) {
                if (m.end() == m.start()) {
                    continue;
                }
                if (skipSafe && inRanges(m.start(), safe)) {
                    continue;
                }
                out.add(new Range(m.start(), m.end()));
                if (out.size() >= limit) {
                    return out;
                }
            }
        }
        return out;
    }

    private static boolean inRanges(int pos, List<int[]> ranges) {
        for (int[] r : ranges) {
            if (pos >= r[0] && pos < r[1]) {
                return true;
            }
        }
        return false;
    }

    private static List<int[]> safeRanges(String text) {
        List<int[]> out = new ArrayList<>();
        Matcher m = SENTENCE.matcher(text);
        while (m.find()) {
            if (SAFE_CONTEXT.matcher(m.group()).find()) {
                out.add(new int[] {m.start(), m.end()});
            }
        }
        return out;
    }

    private record Url(int start, int end, String url) { }

    private static List<Url> findUrls(String text) {
        List<Url> out = new ArrayList<>();
        Matcher m = URL_PATTERN.matcher(text);
        while (m.find()) {
            if (m.start() > 0 && text.charAt(m.start() - 1) == '@') {
                continue;
            }
            String url = m.group().replaceAll("[.,;:!?]+$", "");
            out.add(new Url(m.start(), m.start() + url.length(), url));
        }
        return out;
    }

    private static List<String> urlReasons(String url) {
        List<String> reasons = new ArrayList<>();
        String noProto = url.replaceFirst("(?i)^https?://", "");
        String authority = noProto.split("[/?#]", 2)[0];
        String host = authority.replaceAll("^.*@", "").replaceAll(":\\d+$", "").toLowerCase();
        if (authority.contains("@")) {
            reasons.add("contains an @ sign that can hide the real destination");
        }
        if (SHORTENERS.contains(host)) {
            reasons.add("uses a link shortener, so the real destination is hidden");
        }
        if (IP_HOST.matcher(host).matches()) {
            reasons.add("uses a raw IP address instead of a normal website name");
        }
        String[] parts = host.split("\\.");
        String tld = parts[parts.length - 1];
        if (RISKY_TLDS.contains(tld)) {
            reasons.add("ends in \"." + tld + "\", an address ending often seen in throw-away scam sites");
        }
        if (host.contains("xn--")) {
            reasons.add("uses look-alike (punycode) characters");
        }
        if (host.contains("-") && LOOKALIKE.matcher(host).find()) {
            reasons.add("looks like a hyphenated imitation of a trusted brand or service");
        }
        if (parts.length >= 4) {
            reasons.add("has many sub-domains, a common way to imitate a trusted name");
        }
        return reasons;
    }
}
