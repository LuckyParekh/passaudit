# PassAudit — Password Strength Calculator

A professional, portfolio-ready **password strength analyzer** built with vanilla HTML, CSS, and JavaScript. Analyzes passwords in real time using a multi-factor scoring engine — fully client-side, no frameworks, no backend.

---

## Overview

PassAudit evaluates the security of a password against a range of realistic criteria, provides an actionable feedback report, and estimates how long a modern brute-force attack would take to crack it. The tool is designed with a refined dark terminal aesthetic and smooth micro-animations to feel genuinely production-quality.

---

##  Features

### Core Analysis
- **Real-time scoring** — instant feedback as you type (0–100 composite score)
- **Strength tiers** — Very Weak / Weak / Fair / Good / Strong with color-coded UI
- **Animated progress bar** — segmented, color-transitioning meter
- **Crack time estimate** — rough offline brute-force approximation

### Security Checks
| Check | Description |
|---|---|
| Minimum length | Must be 8+ characters |
| Recommended length | 12+ characters preferred |
| Uppercase letters | A–Z present |
| Lowercase letters | a–z present |
| Numbers | 0–9 present |
| Special characters | `!@#$%^&*` etc. |
| No excessive repetition | No 4+ identical consecutive chars |
| Not a common password | Against a curated list of 100+ common passwords |
| No sequential patterns | Detects `1234`, `abcd`, `dcba` etc. |
| No keyboard patterns | Detects `qwerty`, `asdf`, `zxcvbn` etc. |

### UI/UX
- **Show/hide password toggle**
- **Generate strong password** button (18 chars, balanced character sets)
- **Visual checklist** with pass/fail icons
- **Detailed feedback panel** with positive, warning, and error messages
- **"How It Works"** section explaining the analysis methodology
- **Password tips section** with best practice advice
- **Fully responsive** — desktop, tablet, and mobile

---

##  Tech Stack

| Layer | Technology |
|---|---|
| Markup | HTML5 (semantic) |
| Styling | CSS3 (custom properties, grid, flexbox, animations) |
| Logic | Vanilla JavaScript (ES6+, strict mode) |
| Fonts | JetBrains Mono + Syne (Google Fonts) |

No frameworks. No dependencies. No build step.

---

##  Folder Structure

```
passaudit/
├── index.html      # Markup, layout, and content
├── style.css       # All styles, variables, and animations
├── script.js       # Analysis engine, generator, and UI renderer
└── README.md       # This file
```

---

##  How the Scoring Works

The score is a composite of:

| Component | Max Points |
|---|---|
| Length (4 tiers: 8 / 12 / 16 / 20+ chars) | 30 |
| Lowercase letters present | 10 |
| Uppercase letters present | 10 |
| Numbers present | 10 |
| Special characters present | 15 |
| 3+ character types bonus | 5 |
| All 4 character types bonus | 5 |
| **Total (before penalties)** | **85** |

**Penalties applied:**
| Condition | Deduction |
|---|---|
| Common password match | −50 |
| Keyboard pattern detected | −15 |
| Sequential pattern detected | −10 |
| Excessive character repetition | −10 |

Length caps are also enforced: passwords under 6, 8, or 10 characters have score ceilings regardless of character variety.

---

##  Possible Future Improvements

- **Pwned Passwords API** — check against real breach databases (Have I Been Pwned)
- **zxcvbn integration** — Dropbox's advanced entropy estimation library
- **Copy-to-clipboard** — one-click copy of the generated password
- **Password history** — show recent analyses in a session
- **Dark/light theme toggle** — system-preference aware
- **Custom word list** — let users add their own forbidden words (names, pets, etc.)
- **Passphrase mode** — evaluate and generate diceware-style passphrases
- **Localization** — multi-language feedback messages
- **Offline support** — PWA with service worker

---

##  Privacy

All analysis runs 100% in the browser. Your password is **never sent to any server**, never logged, and never stored. The app has no analytics, no tracking, and no external requests except Google Fonts.

