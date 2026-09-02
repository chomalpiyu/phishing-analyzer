/* ---------------------------------------------------------------
   Phishing Email Analyzer — analysis engine
   All heuristics run locally in the browser. Nothing is sent
   anywhere. This is an educational tool: it flags *patterns*
   commonly seen in phishing email, it does not guarantee a
   message is safe or malicious.
   Author: Priyanka Chomal
--------------------------------------------------------------- */

(function () {
  "use strict";

  /* ---------------- reference data ---------------- */

  // Well-known brand -> its real registrable domain(s).
  // Used to catch display-name spoofing and lookalike domains.
  const KNOWN_BRANDS = {
    paypal: ["paypal.com"],
    amazon: ["amazon.com"],
    microsoft: ["microsoft.com", "live.com", "outlook.com"],
    apple: ["apple.com", "icloud.com"],
    google: ["google.com", "gmail.com"],
    facebook: ["facebook.com", "meta.com"],
    netflix: ["netflix.com"],
    "bank of america": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"],
    chase: ["chase.com"],
    irs: ["irs.gov"],
    dhl: ["dhl.com"],
    fedex: ["fedex.com"],
    ups: ["ups.com"],
    linkedin: ["linkedin.com"],
    instagram: ["instagram.com"],
    ebay: ["ebay.com"],
    "wells": ["wellsfargo.com"],
    dropbox: ["dropbox.com"],
    docusign: ["docusign.com"]
  };

  const URGENCY_PHRASES = [
    "act now", "act immediately", "urgent action", "immediate action required",
    "within 24 hours", "within 48 hours", "account will be suspended",
    "account has been limited", "account will be closed", "verify your account",
    "confirm your identity", "unusual activity", "unauthorized access",
    "your account has been", "failure to", "final notice", "permanently deleted",
    "permanently closed", "click here immediately", "expires today",
    "expires in", "time sensitive", "as soon as possible", "do not ignore this"
  ];

  const SENSITIVE_REQUESTS = [
    "social security number", "ssn", "credit card number", "cvv",
    "debit card", "bank account number", "routing number", "login credentials",
    "your password", "pin number", "date of birth and", "passport number",
    "security question", "one-time password", "verification code", "otp"
  ];

  const PRIZE_SCAM_PHRASES = [
    "you have won", "you've won", "congratulations", "lucky winner",
    "claim your prize", "lottery", "processing fee", "release your winnings",
    "selected as a winner", "free gift", "no purchase necessary", "cash prize"
  ];

  const GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear valued customer", "dear account holder",
    "dear sir/madam", "dear sir or madam", "dear winner", "dear beneficiary"
  ];

  const SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at"
  ];

  const RISKY_ATTACHMENT_EXT = [
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar", ".msi",
    ".docm", ".xlsm", ".pptm", ".iso", ".lnk"
  ];

  /* ---------------- small utilities ---------------- */

  function levenshtein(a, b) {
    const m = a.length, n = b.length;
    const d = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
    for (let j = 0; j <= n; j++) d[0][j] = j;
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      }
    }
    return d[m][n];
  }

  function deLeet(domain) {
    return domain
      .replace(/0/g, "o")
      .replace(/1/g, "l")
      .replace(/3/g, "e")
      .replace(/4/g, "a")
      .replace(/5/g, "s")
      .replace(/rn/g, "m")
      .replace(/vv/g, "w");
  }

  function registrableDomain(host) {
    const parts = host.toLowerCase().split(".");
    if (parts.length <= 2) return host.toLowerCase();
    return parts.slice(-2).join(".");
  }

  function extractHeader(text, name) {
    const re = new RegExp("^" + name + "\\s*:\\s*(.+)$", "im");
    const match = text.match(re);
    return match ? match[1].trim() : "";
  }

  function parseAddress(headerValue) {
    // "Display Name" <email@domain.com>  OR  email@domain.com
    const m = headerValue.match(/^\s*"?([^"<]*)"?\s*<([^>]+)>\s*$/);
    if (m) {
      return { display: m[1].trim(), email: m[2].trim() };
    }
    const emailOnly = headerValue.match(/[^\s<>]+@[^\s<>]+/);
    return { display: "", email: emailOnly ? emailOnly[0] : "" };
  }

  function domainOf(email) {
    const m = email.match(/@([^\s>]+)/);
    return m ? m[1].toLowerCase() : "";
  }

  function escapeHtml(str) {
    return str.replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
  }

  function countOccurrences(haystack, needle) {
    return haystack.split(needle).length - 1;
  }

  /* ---------------- the analyzer ---------------- */

  function analyze(raw) {
    const text = raw || "";
    const lower = text.toLowerCase();
    const findings = []; // { sev: 'high'|'medium'|'low', title, detail }

    // ---- headers ----
    const fromRaw = extractHeader(text, "from");
    const replyToRaw = extractHeader(text, "reply-to");
    const subject = extractHeader(text, "subject");
    const toRaw = extractHeader(text, "to");

    const from = parseAddress(fromRaw);
    const replyTo = parseAddress(replyToRaw);
    const fromDomain = domainOf(from.email);
    const replyToDomain = domainOf(replyTo.email);

    // ---- Reply-To mismatch ----
    if (replyToDomain && fromDomain && replyToDomain !== fromDomain) {
      findings.push({
        sev: "high",
        title: "Reply-To does not match From address",
        detail: `Replies would go to "${replyToDomain}" instead of "${fromDomain}" — a common trick to route your reply to an attacker while the From line still looks legitimate.`
      });
    }

    // ---- brand impersonation via display name ----
    const displayLower = from.display.toLowerCase();
    let matchedBrand = null;
    for (const brand in KNOWN_BRANDS) {
      if (displayLower.includes(brand)) { matchedBrand = brand; break; }
    }
    if (matchedBrand && fromDomain) {
      const officialDomains = KNOWN_BRANDS[matchedBrand];
      const regDomain = registrableDomain(fromDomain);
      const isOfficial = officialDomains.some((d) => regDomain === d);
      if (!isOfficial) {
        findings.push({
          sev: "high",
          title: `Sender name claims to be "${from.display}" but the domain isn't theirs`,
          detail: `The display name references ${matchedBrand}, but the message actually comes from "${fromDomain}", which does not belong to ${matchedBrand}. Legitimate companies send mail from their own domain.`
        });

        // lookalike / homoglyph check against the real domain
        for (const officialDomain of officialDomains) {
          const dist = levenshtein(deLeet(regDomain), officialDomain);
          if (dist > 0 && dist <= 2) {
            findings.push({
              sev: "high",
              title: `"${fromDomain}" looks like a lookalike of ${officialDomain}`,
              detail: `The sending domain is visually very close to the real one — a common typosquatting or character-substitution technique.`
            });
            break;
          }
        }
      }
    }

    // ---- generic greeting ----
    for (const phrase of GENERIC_GREETINGS) {
      if (lower.includes(phrase)) {
        findings.push({
          sev: "low",
          title: "Generic greeting instead of your name",
          detail: `Uses "${phrase}" rather than addressing you personally — common in mass phishing sends.`
        });
        break;
      }
    }

    // ---- urgency / pressure language ----
    const urgencyHits = URGENCY_PHRASES.filter((p) => lower.includes(p));
    if (urgencyHits.length) {
      findings.push({
        sev: urgencyHits.length >= 3 ? "high" : "medium",
        title: "Urgency or pressure language",
        detail: `Found ${urgencyHits.length} pressure phrase(s), e.g. "${urgencyHits[0]}". Creating time pressure is a classic tactic to stop you from thinking carefully.`
      });
    }

    // ---- sensitive info requests ----
    const sensitiveHits = SENSITIVE_REQUESTS.filter((p) => lower.includes(p));
    if (sensitiveHits.length) {
      findings.push({
        sev: "high",
        title: "Asks for sensitive personal or financial information",
        detail: `Mentions: ${sensitiveHits.slice(0, 4).join(", ")}. Legitimate organizations do not ask you to submit these details by email or by clicking a link in one.`
      });
    }

    // ---- prize / lottery scam language ----
    const prizeHits = PRIZE_SCAM_PHRASES.filter((p) => lower.includes(p));
    if (prizeHits.length >= 2) {
      findings.push({
        sev: "high",
        title: "Too-good-to-be-true prize or lottery language",
        detail: `Phrases like "${prizeHits[0]}" and "${prizeHits[1]}" are hallmarks of advance-fee and lottery scams — you can't win a contest you never entered.`
      });
    }

    // ---- attachments ----
    const attachmentLine = text.match(/attachment\s*:\s*(.+)/i);
    if (attachmentLine) {
      const filename = attachmentLine[1].trim();
      const risky = RISKY_ATTACHMENT_EXT.some((ext) => filename.toLowerCase().endsWith(ext));
      findings.push({
        sev: risky ? "high" : "medium",
        title: risky ? `Attachment "${filename}" has a high-risk file type` : `Message references an attachment: "${filename}"`,
        detail: risky
          ? "Executable, script, or macro-enabled file types are frequently used to install malware. Never run an attachment like this from an unsolicited email."
          : "Treat unexpected attachments with caution even if the extension looks harmless, especially from a sender you weren't expecting."
      });
    }

    // ---- shouting / excessive punctuation ----
    const shoutWords = (text.match(/\b[A-Z]{4,}\b/g) || []).length;
    const bangs = countOccurrences(text, "!!!");
    if (shoutWords >= 3 || bangs >= 1) {
      findings.push({
        sev: "low",
        title: "Heavy use of capital letters or exclamation marks",
        detail: "Excessive emphasis is a common, if weak, signal of low-effort mass phishing content."
      });
    }

    // ---- links ----
    const urlRegex = /\bhttps?:\/\/[^\s<>"')]+/gi;
    const urls = Array.from(new Set(text.match(urlRegex) || []));
    const linkFindings = urls.map((url) => {
      let host = "";
      try { host = new URL(url).hostname.toLowerCase(); } catch (e) { /* ignore */ }
      const reasons = [];

      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
        reasons.push("raw IP address instead of a domain name");
      }
      if (SHORTENER_DOMAINS.some((d) => host === d || host.endsWith("." + d))) {
        reasons.push("link shortener hides the real destination");
      }
      if (host.split(".").length >= 4) {
        reasons.push("unusually many subdomains");
      }
      if (url.startsWith("http://")) {
        reasons.push("not using HTTPS");
      }
      for (const brand in KNOWN_BRANDS) {
        if (host.includes(brand.replace(/\s/g, "")) &&
            !KNOWN_BRANDS[brand].some((d) => registrableDomain(host) === d)) {
          reasons.push(`contains "${brand}" but isn't ${brand}'s real domain`);
        }
      }
      return { url, host, reasons };
    });

    const suspiciousLinks = linkFindings.filter((l) => l.reasons.length > 0);
    if (suspiciousLinks.length) {
      findings.push({
        sev: "high",
        title: `${suspiciousLinks.length} suspicious link${suspiciousLinks.length > 1 ? "s" : ""} found`,
        detail: `For example "${suspiciousLinks[0].host || suspiciousLinks[0].url}" — ${suspiciousLinks[0].reasons[0]}.`
      });
    }

    // ---- score ----
    const weights = { high: 22, medium: 11, low: 5 };
    let score = findings.reduce((sum, f) => sum + weights[f.sev], 0);
    score = Math.min(100, score);

    let level = "clear";
    if (score >= 55) level = "danger";
    else if (score >= 22) level = "caution";

    return {
      score, level, findings,
      from, fromDomain, replyTo, replyToDomain, subject, toRaw,
      urls: linkFindings
    };
  }

  /* ---------------- rendering ---------------- */

  const STAMP_TEXT = { clear: "LOW RISK", caution: "USE CAUTION", danger: "LIKELY PHISHING" };
  const ADVICE_TEXT = {
    clear: "No strong phishing indicators were found, but no automated tool is a guarantee. If anything about this message still feels off, verify the sender through a channel you already trust — not a link or number in the email itself.",
    caution: "This message shows some patterns seen in phishing attempts. Don't click any links or open attachments. Verify the sender independently — go directly to the organization's known website or phone number rather than using contact details from the email.",
    danger: "This message shows strong signs of phishing. Do not click any links, download attachments, or reply with any personal information. Delete it, and report it to your email provider or IT/security team if this arrived at a work address."
  };

  function renderFact(dl, label, value, flagged) {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value || "(not found in message)";
    if (flagged) dd.classList.add("flag");
    dl.appendChild(dt);
    dl.appendChild(dd);
  }

  function render(result) {
    document.getElementById("report-empty").hidden = true;
    const body = document.getElementById("report-body");
    body.hidden = false;

    // gauge
    const fillPath = document.getElementById("gauge-fill");
    const len = fillPath.getTotalLength();
    fillPath.style.strokeDasharray = len;
    const offset = len * (1 - result.score / 100);
    requestAnimationFrame(() => { fillPath.style.strokeDashoffset = offset; });
    const gaugeColor = result.level === "danger" ? "var(--red)" : result.level === "caution" ? "var(--amber)" : "var(--green)";
    fillPath.style.stroke = gaugeColor;
    document.getElementById("gauge-score").textContent = result.score;

    // stamp
    const stamp = document.getElementById("stamp");
    stamp.textContent = STAMP_TEXT[result.level];
    stamp.dataset.level = result.level;

    document.getElementById("verdict-summary").textContent =
      result.findings.length
        ? `${result.findings.length} indicator${result.findings.length > 1 ? "s" : ""} flagged out of this analyzer's checklist. Details below.`
        : "No indicators from this analyzer's checklist were triggered.";

    // sender facts
    const dl = document.getElementById("sender-facts");
    dl.innerHTML = "";
    renderFact(dl, "From name", result.from.display);
    renderFact(dl, "From address", result.from.email);
    renderFact(dl, "Reply-To", result.replyTo.email,
      !!(result.replyToDomain && result.fromDomain && result.replyToDomain !== result.fromDomain));
    renderFact(dl, "Subject", result.subject);
    renderFact(dl, "To", result.toRaw);

    // indicators
    const list = document.getElementById("indicator-list");
    list.innerHTML = "";
    document.getElementById("flag-count").textContent = result.findings.length;
    if (!result.findings.length) {
      const li = document.createElement("li");
      li.className = "none";
      li.textContent = "No indicators triggered by this checklist.";
      list.appendChild(li);
    } else {
      const order = { high: 0, medium: 1, low: 2 };
      const sorted = [...result.findings].sort((a, b) => order[a.sev] - order[b.sev]);
      for (const f of sorted) {
        const li = document.createElement("li");
        li.dataset.sev = f.sev;
        li.innerHTML = `<span class="sev-tag">${f.sev.toUpperCase()}</span>
          <span class="ind-text"><strong>${escapeHtml(f.title)}</strong><span>${escapeHtml(f.detail)}</span></span>`;
        list.appendChild(li);
      }
    }

    // links
    const linkList = document.getElementById("link-list");
    linkList.innerHTML = "";
    if (!result.urls.length) {
      const li = document.createElement("li");
      li.className = "none";
      li.textContent = "No links found in the message.";
      linkList.appendChild(li);
    } else {
      for (const l of result.urls) {
        const li = document.createElement("li");
        const flagged = l.reasons.length > 0;
        li.innerHTML = `${flagged ? '<span class="link-flag">FLAGGED</span>' : ""}<span>${escapeHtml(l.url)}</span>`;
        if (flagged) li.title = l.reasons.join("; ");
        linkList.appendChild(li);
      }
    }

    document.getElementById("advice").textContent = ADVICE_TEXT[result.level];
  }

  /* ---------------- sample messages ----------------
     Mirrors the files in /samples/. Embedded directly because
     browsers block fetch() of local files opened via file://. */

  const SAMPLES = {
    phish1: `From: "PayPal Security Team" <security@paypa1-support.com>
Reply-To: verify-team@secure-paypal-alerts.com
To: customer@example.com
Subject: URGENT: Your Account Has Been Limited - Action Required Within 24 Hours

Dear Customer,

We have detected unusual activity on your PayPal account. Your account has been temporarily LIMITED for your protection.

To avoid permanent suspension, you must verify your identity immediately. Failure to confirm your information within 24 hours will result in permanent closure of your account.

Click here to verify your account now:
http://paypal-account-verify.security-check.info/login.php?id=8842910

Please have ready: full name, date of birth, credit card number and CVV, Social Security Number, and your online banking password.

PayPal Account Review Department

Attachment: Account_Verification_Form.exe`,

    phish2: `From: "Microsoft Rewards Team" <no-reply@micros0ft-rewards.net>
Reply-To: claims-dept@rewards-claim-center.biz
To: winner@example.com
Subject: CONGRATULATIONS!!! You Have Won $950,000 in the Microsoft Anniversary Draw

Dear Lucky Winner,

We are pleased to inform you that your email address was randomly selected as a winner of $950,000.00 USD in the Microsoft Anniversary Email Lottery.

This offer expires in 48 hours. Click below and complete the claim form:
http://bit.ly/ms-claim-2026win

You will need to provide your bank account number, routing number, and a processing fee of $250 to release your winnings.

Mrs. Angela Whitfield
Claims Coordinator`,

    clean: `From: "Amazon.com" <shipment-tracking@amazon.com>
To: priyanka@example.com
Subject: Your package has shipped - Order #112-4487213-9902241

Hi Priyanka,

Good news - your recent order has shipped and is on its way. Estimated delivery: Thursday, September 4.

Track your package from Your Orders:
https://www.amazon.com/gp/css/order-history

Item shipped: USB-C Charging Cable (2-Pack) - Qty 1

Thanks for being an Amazon customer.`
  };

  /* ---------------- wiring ---------------- */

  document.addEventListener("DOMContentLoaded", () => {
    const input = document.getElementById("email-input");

    document.getElementById("analyze-btn").addEventListener("click", () => {
      const result = analyze(input.value);
      render(result);
    });

    document.getElementById("clear-btn").addEventListener("click", () => {
      input.value = "";
      document.getElementById("report-body").hidden = true;
      document.getElementById("report-empty").hidden = false;
    });

    document.querySelectorAll(".sample-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        input.value = SAMPLES[btn.dataset.sample];
        render(analyze(input.value));
      });
    });

    document.getElementById("case-number").textContent =
      "NO. " + String(Math.floor(100000 + Math.random() * 899999));
  });
})();
