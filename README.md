# 🔍 WordPress External Auditor (WP SiteCheck)

A lightweight, zero-dependency Node.js external security & reconnaissance auditor for WordPress websites. Remotely audits third-party WordPress sites from the outside to detect WordPress Core version, active Theme, installed Plugins, and outdated software without requiring server access or administrative privileges.

---

## ✨ Features

- **Zero External Dependencies**: Runs entirely on native Node.js (v18+) without requiring any third-party npm packages.
- **Multi-Vector Fingerprinting**:
  - **REST API Enumeration**: Discovers active plugins via `/wp-json/` namespaces.
  - **Meta Generator & Comment Parsing**: Extracts exact plugin and core versions from HTML headers and comment signatures (e.g., Yoast SEO, Site Kit, WP Rocket).
  - **RSS / Atom Feed Extraction**: Probes `/feed/` to detect core version even if stripped from HTML.
  - **Asset Query String Parser**: Parses `?ver=` parameters on enqueued scripts and stylesheets.
  - **Theme Extraction**: Reads `/wp-content/themes/<slug>/style.css` to identify theme name and version.
  - **Security Headers & Server Tech**: Checks Server headers, HTTPS status, HSTS, and X-Frame-Options.
- **Real-Time Version Verification**: Automatically connects to the official `api.wordpress.org` repository to check the latest releases and highlights **🔴 Outdated** components in real time.
- **Dual Interface Modes**:
  - 🖥️ **CLI Mode**: Fast terminal reporting for automation and scripting.
  - 🌐 **Modern Web Dashboard**: Glassmorphic, dark-mode web interface (just like Sucuri SiteCheck).

---

## 🚀 Quick Start

### Prerequisites
- [Node.js](https://nodejs.org/) v18.0.0 or higher.

### 1. Terminal / CLI Mode
Scan any target website directly from your terminal:
```bash
node wp-audit.js https://wisdomtrading.com
```

### 2. Interactive Web Dashboard
Launch the built-in web dashboard:
```bash
npm run web
# Or: node wp-audit.js --web
```
Open your browser and navigate to:
```
http://localhost:3000
```
Enter any WordPress website URL and click **Scan Website** to view the live dashboard.

---

## 📊 Sample Output (CLI)

```text
====================================================
 WP SITECHECK REPORT FOR: https://wisdomtrading.com
====================================================
Site Title:           Wisdom Trading
WordPress Detected:   Yes
Server:               Apache
Core Detected:        v7.1.3 (Up to date)
Core Source:          <meta name="generator">
Active Theme:         Wisdom Trading V2 (v1.0.0)

--- DETECTED PLUGINS (5) ---

• [VERSION HIDDEN / PROTECTED] Redirection (redirection)
  Installed:  Hidden
  Latest:     v5.10.1
  Detection:  /wp-json/ namespace (redirection/v1)

• [VERSION HIDDEN / PROTECTED] Wordfence Security (wordfence)
  Installed:  Hidden
  Latest:     v9.0.2
  Detection:  /wp-json/ namespace (wordfence/v1)

• [OUTDATED] Yoast SEO (wordpress-seo)
  Installed:  v27.2
  Latest:     v28.7
  Detection:  HTML Comment Header

• [PREMIUM / COMMERCIAL PLUGIN] WP Rocket (wp-rocket)
  Installed:  v3.21.3
  Latest:     N/A (Private/Commercial)
  Detection:  <meta name="generator">

• [OUTDATED] Site Kit by Google (google-site-kit)
  Installed:  v1.179.0
  Latest:     v1.189.0
  Detection:  <meta name="generator">
====================================================
```

---

## 🛠️ Project Structure

```
├── wp-audit.js     # Core auditing engine, CLI runner, and web server with UI
├── package.json    # Project configuration and npm scripts
├── .gitignore      # Git ignore definitions
└── README.md       # Project documentation
```

---

## 🛡️ License
MIT License. Free for personal, educational, and authorized security auditing purposes.
