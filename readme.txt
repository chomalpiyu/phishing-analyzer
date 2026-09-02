PHISHING EMAIL ANALYZER
========================
Created by: Priyanka Chomal


WHAT THIS IS
------------
A browser-based tool that inspects a pasted email (headers + body)
and flags patterns commonly seen in phishing attempts:

  - Sender / Reply-To domain mismatches
  - Brand impersonation (display name claims a company, but the
    domain doesn't belong to that company)
  - Lookalike / typosquatted domains (e.g. paypa1.com, micros0ft.com)
  - Urgency and pressure language ("act now", "account suspended")
  - Requests for sensitive info (passwords, SSN, card numbers, OTPs)
  - Prize / lottery / advance-fee scam language
  - Risky attachment file types
  - Suspicious links: IP-address links, URL shorteners, non-HTTPS,
    domains that contain a brand name but aren't the real thing

It produces a risk score (0-100), a plain-language verdict, and a
breakdown of exactly which indicators were triggered and why.

This is an educational / awareness tool. It uses heuristics, not a
live threat-intelligence feed, so it can miss well-crafted phishing
and can occasionally flag a legitimate email. Always verify a
suspicious message through a channel you already trust.

Everything runs locally in your browser with plain HTML, CSS and
JavaScript. Nothing you paste is sent anywhere or stored.


PROJECT STRUCTURE
------------------
phishing-analyzer/
  index.html                          - page structure
  style.css                           - visual styling (case-file theme)
  script.js                           - analysis engine + UI logic
  readme.txt                          - this file
  samples/
    sample-email.txt                  - fake "account suspended" phish
    sample-email-2-lottery-scam.txt   - fake lottery / prize scam
    sample-email-3-legitimate.txt     - a normal, legitimate email


HOW TO RUN IT
-------------
1. Unzip / keep the folder structure above intact.
2. Double-click index.html to open it in any modern browser
   (Chrome, Firefox, Edge, Safari). No server, build step, or
   internet connection is required for the analyzer itself.
3. Paste an email into the text box on the left - ideally including
   header lines such as From, Reply-To, and Subject if you have
   them - and press "Examine message".
4. Or click one of the three "Try a sample" buttons to see the
   analyzer in action instantly. These buttons load built-in copies
   of the .txt files in /samples so they work even though browsers
   block a page from reading local files directly.

You're also welcome to open the files in /samples in a text editor,
copy the contents, and paste them into the analyzer by hand.


HOW SCORING WORKS
------------------
Each triggered indicator adds points based on severity:
  HIGH   = 22 points   (e.g. sensitive-info request, brand spoofing,
                          suspicious link, risky attachment)
  MEDIUM = 11 points   (e.g. urgency language, unexplained attachment)
  LOW    =  5 points   (e.g. generic greeting, heavy capitalization)

Total score (capped at 100) maps to a verdict:
  0-21   -> LOW RISK
  22-54  -> USE CAUTION
  55-100 -> LIKELY PHISHING


EXTENDING IT
------------
The brand list, phrase lists, and scoring weights all live near the
top of script.js and are plain arrays/objects, so they're easy to
extend with more brands, more phrases, or adjusted weights.


DISCLAIMER
----------
Built for learning and demonstration purposes. It is not a
substitute for a real email security product, and it should not be
the only thing you rely on to decide whether a message is safe.
