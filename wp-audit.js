/**
 * WordPress External Security & Version Auditor (Wordpress SiteCheck Alternative)
 * Remotely audits any WordPress website by combining:
 * 1. REST API (/wp-json/) namespaces
 * 2. RSS / Atom feed generator parsing (/feed/)
 * 3. HTML meta generator and comment parsing
 * 4. Enqueued CSS/JS asset query strings (?ver=)
 * 5. Theme metadata extraction (/wp-content/themes/<slug>/style.css)
 * 6. Security header checks & Server detection
 * 7. Real-time comparison with official WordPress.org APIs
 */

const http = require('http');

// Dictionary of known REST namespaces to official WordPress.org plugin slugs
const NAMESPACE_SLUG_MAP = {
  'yoast/v1': { name: 'Yoast SEO', slug: 'wordpress-seo', isOrg: true },
  'google-site-kit/v1': { name: 'Site Kit by Google', slug: 'google-site-kit', isOrg: true },
  'redirection/v1': { name: 'Redirection', slug: 'redirection', isOrg: true },
  'wordfence/v1': { name: 'Wordfence Security', slug: 'wordfence', isOrg: true },
  'wp-rocket/v1': { name: 'WP Rocket', slug: 'wp-rocket', isOrg: false, note: 'Premium / Commercial Plugin' },
  'contact-form-7/v1': { name: 'Contact Form 7', slug: 'contact-form-7', isOrg: true },
  'elementor/v1': { name: 'Elementor Website Builder', slug: 'elementor', isOrg: true },
  'woocommerce/v3': { name: 'WooCommerce', slug: 'woocommerce', isOrg: true },
  'wc/v3': { name: 'WooCommerce', slug: 'woocommerce', isOrg: true },
  'jetpack/v4': { name: 'Jetpack', slug: 'jetpack', isOrg: true },
  'rankmath/v1': { name: 'Rank Math SEO', slug: 'seo-by-rank-math', isOrg: true },
  'litespeed/v1': { name: 'LiteSpeed Cache', slug: 'litespeed-cache', isOrg: true },
  'wpforms/v1': { name: 'WPForms', slug: 'wpforms-lite', isOrg: true },
  'fluentform/v1': { name: 'Fluent Forms', slug: 'fluentform', isOrg: true },
  'aioseo/v1': { name: 'All in One SEO', slug: 'all-in-one-seo-pack', isOrg: true },
  'updraftplus/v1': { name: 'UpdraftPlus Backup', slug: 'updraftplus', isOrg: true },
  'acf/v3': { name: 'Advanced Custom Fields', slug: 'advanced-custom-fields', isOrg: true }
};

// Top popular WordPress plugins to actively check if not in wp-json
const POPULAR_PLUGINS_TO_PROBE = [
  { slug: 'contact-form-7', name: 'Contact Form 7' },
  { slug: 'elementor', name: 'Elementor Website Builder' },
  { slug: 'woocommerce', name: 'WooCommerce' },
  { slug: 'wordfence', name: 'Wordfence Security' },
  { slug: 'wordpress-seo', name: 'Yoast SEO' },
  { slug: 'google-site-kit', name: 'Site Kit by Google' },
  { slug: 'all-in-one-seo-pack', name: 'All in One SEO' },
  { slug: 'wpforms-lite', name: 'WPForms' }
];

function compareVersions(v1, v2) {
  if (!v1 || !v2) return 0;
  const clean = (v) => v.replace(/^v/i, '').split('.').map(num => parseInt(num, 10) || 0);
  const p1 = clean(v1);
  const p2 = clean(v2);
  const len = Math.max(p1.length, p2.length);
  for (let i = 0; i < len; i++) {
    const num1 = p1[i] || 0;
    const num2 = p2[i] || 0;
    if (num1 < num2) return -1;
    if (num1 > num2) return 1;
  }
  return 0;
}

async function fetchSafe(targetUrl, timeoutMs = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(targetUrl, {
      signal: controller.signal,
      headers: {
        'Accept': 'text/html,application/xhtml+xml,application/xml,application/json,*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
      }
    });
    clearTimeout(timer);
    return res;
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

async function auditWordPressSite(inputUrl) {
  let baseUrl = inputUrl.trim();
  if (!baseUrl.startsWith('http://') && !baseUrl.startsWith('https://')) {
    baseUrl = 'https://' + baseUrl;
  }
  baseUrl = baseUrl.replace(/\/+$/, '');

  const result = {
    target: baseUrl,
    scanTime: new Date().toISOString(),
    isWordPress: false,
    server: 'Unknown',
    securityHeaders: {
      https: baseUrl.startsWith('https://'),
      hsts: false,
      xFrameOptions: false,
      xContentTypeOptions: false
    },
    siteInfo: {},
    core: {
      detectedVersion: null,
      latestVersion: null,
      status: 'Unknown',
      disclosureSource: null
    },
    theme: {
      slug: null,
      name: null,
      version: null,
      author: null
    },
    plugins: [],
    logs: []
  };

  // 1. Fetch Homepage HTML & Headers
  let html = '';
  try {
    const res = await fetchSafe(baseUrl);
    if (res.headers.get('server')) {
      result.server = res.headers.get('server');
    }
    if (res.headers.get('strict-transport-security')) result.securityHeaders.hsts = true;
    if (res.headers.get('x-frame-options')) result.securityHeaders.xFrameOptions = true;
    if (res.headers.get('x-content-type-options')) result.securityHeaders.xContentTypeOptions = true;

    if (res.ok) {
      html = await res.text();
      if (html.includes('/wp-content/') || html.includes('/wp-includes/') || html.includes('wp-json')) {
        result.isWordPress = true;
      }
    }
  } catch (e) {
    result.logs.push(`Failed to fetch homepage: ${e.message}`);
  }

  // 2. Fetch /wp-json/
  let wpJsonData = null;
  try {
    const res = await fetchSafe(`${baseUrl}/wp-json/`);
    if (res.ok) {
      wpJsonData = await res.json();
      result.isWordPress = true;
      result.siteInfo = {
        name: wpJsonData.name || null,
        description: wpJsonData.description || null,
        url: wpJsonData.url || null,
        timezone: wpJsonData.timezone_string || null
      };
    }
  } catch (e) {
    result.logs.push(`Could not fetch wp-json: ${e.message}`);
  }

  // 3. WordPress Core Detection Strategy
  // Vector A: <meta name="generator" content="WordPress X.Y.Z">
  const metaGenerators = [...html.matchAll(/<meta\s+name=["']generator["']\s+content=["']([^"']+)["']/gi)].map(m => m[1]);
  for (const gen of metaGenerators) {
    const wpMatch = gen.match(/WordPress\s+([0-9\.]+)/i);
    if (wpMatch && !result.core.detectedVersion) {
      result.core.detectedVersion = wpMatch[1];
      result.core.disclosureSource = '<meta name="generator">';
      result.isWordPress = true;
    }
  }

  // Vector B: RSS Feed Generator (/feed/)
  if (!result.core.detectedVersion) {
    try {
      const feedRes = await fetchSafe(`${baseUrl}/feed/`);
      if (feedRes.ok) {
        const feedXml = await feedRes.text();
        const genMatch = feedXml.match(/<generator>https?:\/\/wordpress\.org\/\?v=([0-9\.]+)<\/generator>/i);
        if (genMatch) {
          result.core.detectedVersion = genMatch[1];
          result.core.disclosureSource = 'RSS Feed (/feed/) generator tag';
          result.isWordPress = true;
        }
      }
    } catch (e) {
      // feed probing failed
    }
  }

  // Vector C: Asset Query Strings (?ver=X.Y.Z in wp-includes)
  if (!result.core.detectedVersion) {
    const coreVerMatch = html.match(/\/wp-includes\/[^"' >]*\?ver=([0-9\.]+)/i);
    if (coreVerMatch) {
      result.core.detectedVersion = coreVerMatch[1];
      result.core.disclosureSource = 'wp-includes script ?ver= query param';
      result.isWordPress = true;
    }
  }

  // Fetch Latest Core Version from api.wordpress.org
  try {
    const coreApiRes = await fetchSafe('https://api.wordpress.org/core/version-check/1.7/');
    if (coreApiRes.ok) {
      const coreApiData = await coreApiRes.json();
      if (coreApiData.offers && coreApiData.offers[0]) {
        result.core.latestVersion = coreApiData.offers[0].current;
      }
    }
  } catch (e) {
    result.logs.push(`Could not fetch WordPress.org Core API: ${e.message}`);
  }

  if (result.core.detectedVersion && result.core.latestVersion) {
    const cmp = compareVersions(result.core.detectedVersion, result.core.latestVersion);
    result.core.status = cmp < 0 ? 'Outdated' : 'Up to date';
  } else if (!result.core.detectedVersion) {
    result.core.status = 'Version Hidden / Protected';
  }

  // 4. Theme Detection
  const themeMatch = html.match(/\/wp-content\/themes\/([a-zA-Z0-9_-]+)\//i);
  if (themeMatch) {
    const themeSlug = themeMatch[1];
    result.theme.slug = themeSlug;
    try {
      const styleRes = await fetchSafe(`${baseUrl}/wp-content/themes/${themeSlug}/style.css`);
      if (styleRes.ok) {
        const styleCss = await styleRes.text();
        const tName = styleCss.match(/Theme Name:\s*([^\r\n]+)/i);
        const tVer = styleCss.match(/Version:\s*([^\r\n]+)/i);
        const tAuth = styleCss.match(/Author:\s*([^\r\n]+)/i);
        result.theme.name = tName ? tName[1].trim() : themeSlug;
        result.theme.version = tVer ? tVer[1].trim() : 'Unknown';
        result.theme.author = tAuth ? tAuth[1].trim() : null;
      }
    } catch (e) {
      result.theme.name = themeSlug;
    }
  }

  // 5. Plugin Detection
  const pluginMap = new Map();

  // Source A: /wp-json/ namespaces
  if (wpJsonData && Array.isArray(wpJsonData.namespaces)) {
    for (const ns of wpJsonData.namespaces) {
      if (NAMESPACE_SLUG_MAP[ns]) {
        const item = NAMESPACE_SLUG_MAP[ns];
        pluginMap.set(item.slug, {
          name: item.name,
          slug: item.slug,
          isOrg: item.isOrg,
          note: item.note || null,
          installedVersion: null,
          source: `/wp-json/ namespace (${ns})`
        });
      }
    }
  }

  // Source B: <script> and <link> asset query parameters
  const assetRegex = /\/wp-content\/plugins\/([a-zA-Z0-9_-]+)\/[^"' >]*\?ver=([^"' &>]+)/gi;
  let aMatch;
  while ((aMatch = assetRegex.exec(html)) !== null) {
    const slug = aMatch[1];
    const ver = aMatch[2];
    if (!pluginMap.has(slug)) {
      pluginMap.set(slug, {
        name: slug.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
        slug: slug,
        isOrg: true,
        installedVersion: ver,
        source: 'Asset enqueued (?ver=)'
      });
    } else if (!pluginMap.get(slug).installedVersion) {
      pluginMap.get(slug).installedVersion = ver;
      pluginMap.get(slug).source = 'Asset enqueued (?ver=)';
    }
  }

  // Source C: Meta generators (Google Site Kit, WP Rocket, Elementor, WooCommerce)
  for (const gen of metaGenerators) {
    const siteKit = gen.match(/Site Kit by Google\s+([0-9\.]+)/i);
    if (siteKit) {
      if (!pluginMap.has('google-site-kit')) {
        pluginMap.set('google-site-kit', { name: 'Site Kit by Google', slug: 'google-site-kit', isOrg: true });
      }
      pluginMap.get('google-site-kit').installedVersion = siteKit[1];
      pluginMap.get('google-site-kit').source = '<meta name="generator">';
    }

    const rocket = gen.match(/WP Rocket\s+([0-9\.]+)/i);
    if (rocket) {
      if (!pluginMap.has('wp-rocket')) {
        pluginMap.set('wp-rocket', { name: 'WP Rocket', slug: 'wp-rocket', isOrg: false, note: 'Commercial Plugin' });
      }
      pluginMap.get('wp-rocket').installedVersion = rocket[1];
      pluginMap.get('wp-rocket').source = '<meta name="generator">';
    }

    const elem = gen.match(/Elementor\s+([0-9\.]+)/i);
    if (elem) {
      if (!pluginMap.has('elementor')) {
        pluginMap.set('elementor', { name: 'Elementor Website Builder', slug: 'elementor', isOrg: true });
      }
      pluginMap.get('elementor').installedVersion = elem[1];
      pluginMap.get('elementor').source = '<meta name="generator">';
    }
  }

  // Source D: HTML comments (e.g., Yoast SEO)
  const yoastComment = html.match(/Yoast SEO plugin v([0-9\.]+)/i);
  if (yoastComment) {
    if (!pluginMap.has('wordpress-seo')) {
      pluginMap.set('wordpress-seo', { name: 'Yoast SEO', slug: 'wordpress-seo', isOrg: true });
    }
    pluginMap.get('wordpress-seo').installedVersion = yoastComment[1];
    pluginMap.get('wordpress-seo').source = 'HTML Comment Header';
  }

  // 6. Cross-reference with WordPress.org API
  for (const [slug, item] of pluginMap.entries()) {
    let latestVersion = null;
    let lastUpdated = null;
    let wpOrgUrl = null;

    if (item.isOrg !== false) {
      try {
        const wpOrgRes = await fetchSafe(`https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=${slug}`);
        if (wpOrgRes.ok) {
          const orgData = await wpOrgRes.json();
          if (orgData && orgData.version) {
            latestVersion = orgData.version;
            lastUpdated = orgData.last_updated;
            wpOrgUrl = `https://wordpress.org/plugins/${slug}/`;
            if (orgData.name) item.name = orgData.name.replace(/&#8211;/g, '-').replace(/&amp;/g, '&');
          }
        }
      } catch (e) {
        // failed org fetch
      }
    }

    let status = 'Unknown';
    if (!item.installedVersion) {
      status = 'Version Hidden / Protected';
    } else if (!latestVersion) {
      status = item.note || 'Commercial / Private';
    } else {
      const cmp = compareVersions(item.installedVersion, latestVersion);
      status = cmp < 0 ? 'Outdated' : 'Up to date';
    }

    result.plugins.push({
      name: item.name,
      slug: slug,
      installedVersion: item.installedVersion,
      latestVersion: latestVersion,
      status: status,
      lastUpdated: lastUpdated,
      source: item.source,
      wpOrgUrl: wpOrgUrl,
      isCommercial: item.isOrg === false
    });
  }

  return result;
}

function startWebServer(port = 3000) {
  const server = http.createServer(async (req, res) => {
    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (parsedUrl.pathname === '/api/audit' && req.method === 'GET') {
      const targetUrl = parsedUrl.searchParams.get('url');
      if (!targetUrl) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Missing ?url= query parameter' }));
        return;
      }
      try {
        const auditResult = await auditWordPressSite(targetUrl);
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify(auditResult));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
      return;
    }

    if (parsedUrl.pathname === '/' || parsedUrl.pathname === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(getHtmlUI());
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  });

  server.listen(port, () => {
    console.log(`\n============================================================`);
    console.log(` WordPress SiteCheck Alternative running at: http://localhost:${port}`);
    console.log(`============================================================\n`);
  });
}

function getHtmlUI() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WP SiteCheck - External WordPress Security Scanner</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(19, 26, 42, 0.75);
      --card-border: rgba(255, 255, 255, 0.08);
      --accent: #4f46e5;
      --accent-glow: rgba(79, 70, 229, 0.35);
      --accent-hover: #4338ca;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --success: #10b981;
      --danger: #ef4444;
      --warning: #f59e0b;
      --font: 'Outfit', sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: radial-gradient(circle at 50% 0%, #1e1b4b 0%, var(--bg) 70%);
      color: var(--text);
      font-family: var(--font);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 40px 20px;
    }
    .container {
      width: 100%;
      max-width: 960px;
    }
    .header {
      text-align: center;
      margin-bottom: 35px;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 16px;
      background: rgba(79, 70, 229, 0.15);
      border: 1px solid rgba(79, 70, 229, 0.3);
      border-radius: 999px;
      color: #a5b4fc;
      font-size: 0.85rem;
      font-weight: 500;
      margin-bottom: 14px;
      letter-spacing: 0.5px;
    }
    h1 {
      font-size: 2.6rem;
      font-weight: 800;
      letter-spacing: -0.5px;
      background: linear-gradient(135deg, #ffffff 40%, #a5b4fc 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 10px;
    }
    p.subtitle {
      color: var(--text-muted);
      font-size: 1.05rem;
      max-width: 640px;
      margin: 0 auto;
    }
    .search-card {
      background: var(--card-bg);
      backdrop-filter: blur(16px);
      border: 1px solid var(--card-border);
      border-radius: 20px;
      padding: 24px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
      margin-bottom: 30px;
    }
    .input-group {
      display: flex;
      gap: 12px;
    }
    input[type="text"] {
      flex: 1;
      background: rgba(11, 15, 25, 0.85);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 12px;
      padding: 16px 20px;
      color: var(--text);
      font-size: 1rem;
      font-family: var(--font);
      outline: none;
      transition: all 0.2s ease;
    }
    input[type="text"]:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px var(--accent-glow);
    }
    button {
      background: var(--accent);
      color: #fff;
      border: none;
      border-radius: 12px;
      padding: 0 32px;
      font-size: 1rem;
      font-weight: 600;
      font-family: var(--font);
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    button:hover {
      background: var(--accent-hover);
      transform: translateY(-1px);
    }
    .quick-links {
      margin-top: 14px;
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 0.85rem;
      color: var(--text-muted);
    }
    .quick-link {
      color: #a5b4fc;
      text-decoration: underline;
      cursor: pointer;
    }
    .result-section {
      display: none;
      flex-direction: column;
      gap: 24px;
      animation: fadeIn 0.4s ease forwards;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(12px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .status-card {
      background: var(--card-bg);
      backdrop-filter: blur(16px);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      padding: 24px;
    }
    .card-title {
      font-size: 1.2rem;
      font-weight: 700;
      margin-bottom: 18px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 16px;
    }
    .metric {
      background: rgba(11, 15, 25, 0.5);
      border: 1px solid rgba(255, 255, 255, 0.05);
      border-radius: 12px;
      padding: 18px;
    }
    .metric-label {
      color: var(--text-muted);
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 6px;
    }
    .metric-value {
      font-size: 1.2rem;
      font-weight: 700;
      font-family: var(--font-mono);
    }
    .tag {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 0.8rem;
      font-weight: 600;
    }
    .tag-danger { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .tag-success { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .tag-warning { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
      text-align: left;
    }
    th {
      color: var(--text-muted);
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      padding: 12px 16px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    }
    td {
      padding: 16px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      font-size: 0.95rem;
    }
    .plugin-name {
      font-weight: 600;
      color: #fff;
    }
    .plugin-slug {
      font-size: 0.8rem;
      color: var(--text-muted);
      font-family: var(--font-mono);
    }
    .version-code {
      font-family: var(--font-mono);
      font-size: 0.9rem;
      background: rgba(0,0,0,0.3);
      padding: 3px 8px;
      border-radius: 4px;
    }
    .loader {
      display: none;
      text-align: center;
      padding: 40px;
    }
    .spinner {
      width: 44px;
      height: 44px;
      border: 3px solid rgba(79, 70, 229, 0.2);
      border-top-color: var(--accent);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      margin: 0 auto 16px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="badge">🛡️ WPSiteCheck Architecture</div>
      <h1>WP SiteCheck Scanner</h1>
      <p class="subtitle">External black-box reconnaissance for WordPress: Detects Core version, Theme, Active Plugins, and Outdated Software without server access.</p>
    </div>

    <div class="search-card">
      <div class="input-group">
        <input type="text" id="targetUrl" placeholder="e.g. https://wisdomtrading.com" value="https://wisdomtrading.com">
        <button id="scanBtn" onclick="runAudit()">
          <span>Scan Website</span>
        </button>
      </div>
      <div class="quick-links">
        <span>Quick Test:</span>
        <span class="quick-link" onclick="setAndRun('https://wisdomtrading.com')">wisdomtrading.com</span>
      </div>
    </div>

    <div class="loader" id="loader">
      <div class="spinner"></div>
      <p style="color: var(--text-muted)">Executing multi-vector reconnaissance: crawling HTML, /wp-json/, /feed/, and querying WordPress.org releases...</p>
    </div>

    <div class="result-section" id="results">
      <!-- Overview Card -->
      <div class="status-card">
        <div class="card-title">
          <span id="siteTitle">Site Security & Platform Overview</span>
          <span id="securityHeaderTag"></span>
        </div>
        <div class="summary-grid">
          <div class="metric">
            <div class="metric-label">WordPress Core</div>
            <div class="metric-value" id="coreVersion">-</div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 4px;" id="coreSource">-</div>
          </div>
          <div class="metric">
            <div class="metric-label">Latest Core Release</div>
            <div class="metric-value" id="latestCoreVersion" style="color: var(--success);">-</div>
            <div style="margin-top: 4px;" id="coreStatusTag">-</div>
          </div>
          <div class="metric">
            <div class="metric-label">Active Theme</div>
            <div class="metric-value" id="themeName" style="font-family: var(--font); font-size: 1.05rem;">-</div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 4px;" id="themeVer">-</div>
          </div>
          <div class="metric">
            <div class="metric-label">Server / Web Tech</div>
            <div class="metric-value" id="serverTech" style="font-size: 1.05rem;">-</div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 4px;" id="tlsStatus">HTTPS Active</div>
          </div>
        </div>
      </div>

      <!-- Plugins Table -->
      <div class="status-card">
        <div class="card-title">
          <span>Detected Plugins (<span id="pluginCount">0</span>)</span>
        </div>
        <table>
          <thead>
            <tr>
              <th>Plugin Name</th>
              <th>Installed Version</th>
              <th>Latest (WP.org)</th>
              <th>Update Status</th>
              <th>Detection Vector</th>
            </tr>
          </thead>
          <tbody id="pluginsTbody">
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    function setAndRun(url) {
      document.getElementById('targetUrl').value = url;
      runAudit();
    }

    async function runAudit() {
      const urlInput = document.getElementById('targetUrl').value.trim();
      if (!urlInput) return;

      const loader = document.getElementById('loader');
      const results = document.getElementById('results');
      loader.style.display = 'block';
      results.style.display = 'none';

      try {
        const res = await fetch('/api/audit?url=' + encodeURIComponent(urlInput));
        const data = await res.json();
        renderResults(data);
      } catch (err) {
        alert('Scan failed: ' + err.message);
      } finally {
        loader.style.display = 'none';
      }
    }

    function renderResults(data) {
      const results = document.getElementById('results');
      results.style.display = 'flex';

      document.getElementById('siteTitle').textContent = data.siteInfo?.name || data.target;
      document.getElementById('coreVersion').textContent = data.core?.detectedVersion ? 'v' + data.core.detectedVersion : 'Hidden / Protected';
      document.getElementById('coreSource').textContent = data.core?.disclosureSource || 'Protected against disclosure';
      document.getElementById('latestCoreVersion').textContent = data.core?.latestVersion ? 'v' + data.core.latestVersion : 'N/A';

      const coreTag = document.getElementById('coreStatusTag');
      if (data.core?.status === 'Up to date') {
        coreTag.innerHTML = '<span class="tag tag-success">Up to Date</span>';
      } else if (data.core?.status === 'Outdated') {
        coreTag.innerHTML = '<span class="tag tag-danger">Outdated Core</span>';
      } else {
        coreTag.innerHTML = '<span class="tag tag-warning">Protected</span>';
      }

      document.getElementById('themeName').textContent = data.theme?.name || 'Custom Theme';
      document.getElementById('themeVer').textContent = data.theme?.version ? 'Version ' + data.theme.version : 'Version hidden';
      document.getElementById('serverTech').textContent = data.server || 'Generic Web Server';
      document.getElementById('tlsStatus').textContent = data.securityHeaders?.https ? '🔒 HTTPS Secure' : '⚠️ Plain HTTP';

      const secTag = document.getElementById('securityHeaderTag');
      if (data.securityHeaders?.hsts) {
        secTag.innerHTML = '<span class="tag tag-success">HSTS Enabled</span>';
      } else {
        secTag.innerHTML = '<span class="tag tag-warning">Missing HSTS</span>';
      }

      const tbody = document.getElementById('pluginsTbody');
      tbody.innerHTML = '';
      document.getElementById('pluginCount').textContent = data.plugins?.length || 0;

      if (!data.plugins || data.plugins.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No active plugins exposed via public markers.</td></tr>';
        return;
      }

      data.plugins.forEach(p => {
        const tr = document.createElement('tr');
        
        let statusTag = '';
        if (p.status === 'Outdated') {
          statusTag = '<span class="tag tag-danger">🔴 Outdated</span>';
        } else if (p.status === 'Up to date') {
          statusTag = '<span class="tag tag-success">🟢 Up to Date</span>';
        } else {
          statusTag = '<span class="tag tag-warning">🟡 ' + p.status + '</span>';
        }

        tr.innerHTML = \`
          <td>
            <div class="plugin-name">\${p.name}</div>
            <div class="plugin-slug">\${p.slug}</div>
          </td>
          <td>\${p.installedVersion ? '<span class="version-code">v' + p.installedVersion + '</span>' : '<span style="color: var(--text-muted); font-size: 0.85rem;">Hidden</span>'}</td>
          <td>\${p.latestVersion ? '<span class="version-code" style="color: #34d399;">v' + p.latestVersion + '</span>' : '<span style="color: var(--text-muted); font-size: 0.85rem;">Private/Paid</span>'}</td>
          <td>\${statusTag}</td>
          <td style="font-size: 0.85rem; color: var(--text-muted);">\${p.source || 'Public marker'}</td>
        \`;
        tbody.appendChild(tr);
      });
    }
  </script>
</body>
</html>`;
}

// CLI Mode vs Server Mode
const args = process.argv.slice(2);
if (args.includes('--web') || args.includes('-w')) {
  startWebServer(3000);
} else if (args[0] && !args[0].startsWith('-')) {
  const target = args[0];
  console.log(`\n🔍 Scanning target: ${target}...\n`);
  auditWordPressSite(target).then(res => {
    console.log(`====================================================`);
    console.log(` WP SITECHECK REPORT FOR: ${res.target}`);
    console.log(`====================================================`);
    console.log(`Site Title:           ${res.siteInfo?.name || 'N/A'}`);
    console.log(`WordPress Detected:   ${res.isWordPress ? 'Yes' : 'No'}`);
    console.log(`Server:               ${res.server}`);
    console.log(`Core Detected:        ${res.core.detectedVersion ? 'v' + res.core.detectedVersion : 'Hidden'}`);
    console.log(`Core Latest:          ${res.core.latestVersion ? 'v' + res.core.latestVersion : 'N/A'}`);
    console.log(`Core Status:          ${res.core.status}`);
    console.log(`Core Source:          ${res.core.disclosureSource || 'Protected'}`);
    console.log(`Active Theme:         ${res.theme.name || 'Unknown'} (v${res.theme.version || '?'})`);
    console.log(`\n--- DETECTED PLUGINS (${res.plugins.length}) ---`);
    res.plugins.forEach(p => {
      console.log(`\n• [${p.status.toUpperCase()}] ${p.name} (${p.slug})`);
      console.log(`  Installed:  ${p.installedVersion ? 'v' + p.installedVersion : 'Hidden'}`);
      console.log(`  Latest:     ${p.latestVersion ? 'v' + p.latestVersion : 'N/A (Private/Commercial)'}`);
      console.log(`  Detection:  ${p.source}`);
    });
    console.log(`\n====================================================\n`);
  }).catch(err => {
    console.error('Scan failed:', err);
  });
} else {
  console.log(`Usage:`);
  console.log(`  CLI: node wp-audit.js <URL>`);
  console.log(`  Web: node wp-audit.js --web`);
}
