#!/usr/bin/env python3
"""
Laravel Security Scanner - Web Interface (Flask)
"""

import json
import threading
import uuid
from flask import Flask, render_template_string, request, jsonify, Response, stream_with_context
from scanner import LaravelScanner

app = Flask(__name__)
scan_results = {}  # Store results by scan_id

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Laravel Security Scanner</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Syne+Mono&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0a0c10;
    --surface: #111318;
    --surface2: #181b22;
    --border: #232733;
    --accent: #e8ff5a;
    --accent2: #5affa0;
    --red: #ff4d6a;
    --orange: #ff8c42;
    --yellow: #ffd166;
    --blue: #4da6ff;
    --text: #e2e8f0;
    --muted: #64748b;
    --mono: 'Syne Mono', monospace;
    --sans: 'Syne', sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }
  
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Grid background */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image: 
      linear-gradient(rgba(232,255,90,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(232,255,90,0.03) 1px, transparent 1px);
    background-size: 48px 48px;
    pointer-events: none;
    z-index: 0;
  }

  .container {
    position: relative;
    z-index: 1;
    max-width: 1100px;
    margin: 0 auto;
    padding: 0 24px;
  }

  /* ── Header ── */
  header {
    padding: 48px 0 40px;
    border-bottom: 1px solid var(--border);
  }

  .logo-line {
    display: flex;
    align-items: center;
    gap: 16px;
    margin-bottom: 8px;
  }

  .logo-badge {
    width: 44px; height: 44px;
    background: var(--accent);
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 22px;
  }

  h1 {
    font-family: var(--sans);
    font-size: 2rem;
    font-weight: 800;
    letter-spacing: -0.03em;
    color: #fff;
  }

  h1 span { color: var(--accent); }

  .tagline {
    font-family: var(--mono);
    font-size: 0.78rem;
    color: var(--muted);
    letter-spacing: 0.12em;
    text-transform: uppercase;
    margin-left: 60px;
  }

  /* ── Scanner form ── */
  .scan-section {
    padding: 40px 0 32px;
  }

  .scan-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 32px;
  }

  .scan-label {
    font-family: var(--mono);
    font-size: 0.72rem;
    color: var(--accent);
    letter-spacing: 0.15em;
    text-transform: uppercase;
    margin-bottom: 12px;
    display: block;
  }

  .scan-row {
    display: flex;
    gap: 12px;
    align-items: stretch;
  }

  .scan-input {
    flex: 1;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px 18px;
    font-family: var(--mono);
    font-size: 0.95rem;
    color: var(--text);
    outline: none;
    transition: border-color 0.2s;
  }

  .scan-input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(232,255,90,0.08);
  }

  .scan-input::placeholder { color: var(--muted); }

  .scan-btn {
    background: var(--accent);
    color: #0a0c10;
    border: none;
    border-radius: 10px;
    padding: 14px 28px;
    font-family: var(--sans);
    font-size: 0.9rem;
    font-weight: 700;
    cursor: pointer;
    letter-spacing: 0.05em;
    transition: all 0.2s;
    white-space: nowrap;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .scan-btn:hover { background: #f5ff80; transform: translateY(-1px); }
  .scan-btn:active { transform: translateY(0); }
  .scan-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }

  .scan-note {
    font-size: 0.78rem;
    color: var(--muted);
    margin-top: 12px;
  }

  /* ── Progress ── */
  #progress-section {
    display: none;
    margin-top: 24px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
  }

  .progress-header {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 16px;
    font-family: var(--mono);
    font-size: 0.82rem;
    color: var(--accent2);
  }

  .pulse-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--accent2);
    animation: pulse 1.2s ease-in-out infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.4; transform: scale(0.7); }
  }

  .progress-bar-wrap {
    background: var(--border);
    border-radius: 99px;
    height: 6px;
    overflow: hidden;
    margin-bottom: 12px;
  }

  .progress-bar {
    height: 100%;
    background: linear-gradient(90deg, var(--accent2), var(--accent));
    border-radius: 99px;
    transition: width 0.4s ease;
    width: 0%;
  }

  .log-output {
    font-family: var(--mono);
    font-size: 0.73rem;
    color: var(--muted);
    max-height: 120px;
    overflow-y: auto;
    line-height: 1.7;
  }

  .log-output .log-line { color: var(--muted); }
  .log-output .log-line::before { content: '› '; color: var(--accent); }

  /* ── Results ── */
  #results-section { display: none; padding-bottom: 60px; }

  .results-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 28px;
    padding-top: 32px;
  }

  .results-title {
    font-family: var(--sans);
    font-size: 1.4rem;
    font-weight: 800;
    color: #fff;
  }

  .results-url {
    font-family: var(--mono);
    font-size: 0.75rem;
    color: var(--muted);
  }

  /* Score Card */
  .score-grid {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 24px;
    margin-bottom: 32px;
  }

  .score-circle-wrap {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 28px 36px;
    min-width: 180px;
  }

  .score-number {
    font-family: var(--sans);
    font-size: 4rem;
    font-weight: 800;
    line-height: 1;
  }

  .score-label {
    font-family: var(--mono);
    font-size: 0.65rem;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: var(--muted);
    margin-top: 4px;
  }

  .score-grade {
    font-family: var(--mono);
    font-size: 0.75rem;
    padding: 4px 12px;
    border-radius: 6px;
    margin-top: 12px;
    font-weight: 600;
  }

  .severity-stats {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 24px;
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    align-content: center;
  }

  .stat-item { text-align: center; }

  .stat-count {
    font-family: var(--sans);
    font-size: 2.2rem;
    font-weight: 800;
    line-height: 1;
  }

  .stat-label {
    font-family: var(--mono);
    font-size: 0.65rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    margin-top: 4px;
  }

  .sev-critical { color: var(--red); }
  .sev-high { color: var(--orange); }
  .sev-medium { color: var(--yellow); }
  .sev-low { color: var(--blue); }
  .sev-info { color: var(--muted); }

  /* Filter tabs */
  .filter-tabs {
    display: flex;
    gap: 8px;
    margin-bottom: 20px;
    flex-wrap: wrap;
  }

  .filter-tab {
    font-family: var(--mono);
    font-size: 0.72rem;
    padding: 6px 14px;
    border-radius: 6px;
    border: 1px solid var(--border);
    background: transparent;
    color: var(--muted);
    cursor: pointer;
    letter-spacing: 0.08em;
    transition: all 0.15s;
  }

  .filter-tab.active, .filter-tab:hover {
    border-color: var(--accent);
    color: var(--accent);
    background: rgba(232,255,90,0.06);
  }

  /* Finding cards */
  .finding-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    margin-bottom: 14px;
    overflow: hidden;
    transition: border-color 0.2s;
  }

  .finding-card:hover { border-color: #2e3340; }

  .finding-header {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 18px 20px;
    cursor: pointer;
    user-select: none;
  }

  .sev-badge {
    font-family: var(--mono);
    font-size: 0.62rem;
    font-weight: 600;
    padding: 3px 10px;
    border-radius: 4px;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    flex-shrink: 0;
  }

  .badge-critical { background: rgba(255,77,106,0.15); color: var(--red); border: 1px solid rgba(255,77,106,0.3); }
  .badge-high { background: rgba(255,140,66,0.15); color: var(--orange); border: 1px solid rgba(255,140,66,0.3); }
  .badge-medium { background: rgba(255,209,102,0.15); color: var(--yellow); border: 1px solid rgba(255,209,102,0.3); }
  .badge-low { background: rgba(77,166,255,0.15); color: var(--blue); border: 1px solid rgba(77,166,255,0.3); }
  .badge-info { background: rgba(100,116,139,0.15); color: var(--muted); border: 1px solid rgba(100,116,139,0.3); }

  .finding-title {
    flex: 1;
    font-size: 0.95rem;
    font-weight: 600;
    color: #fff;
  }

  .finding-category {
    font-family: var(--mono);
    font-size: 0.68rem;
    color: var(--muted);
    flex-shrink: 0;
  }

  .chevron {
    color: var(--muted);
    transition: transform 0.2s;
    font-size: 1rem;
    flex-shrink: 0;
  }

  .finding-card.open .chevron { transform: rotate(180deg); }

  .finding-body {
    display: none;
    padding: 0 20px 20px;
    border-top: 1px solid var(--border);
  }

  .finding-card.open .finding-body { display: block; }

  .finding-section {
    margin-top: 16px;
  }

  .finding-section-label {
    font-family: var(--mono);
    font-size: 0.65rem;
    color: var(--accent);
    letter-spacing: 0.15em;
    text-transform: uppercase;
    margin-bottom: 8px;
  }

  .finding-section-text {
    font-size: 0.85rem;
    color: #a0aec0;
    line-height: 1.65;
  }

  .evidence-box, .fix-box {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 14px;
    font-family: var(--mono);
    font-size: 0.75rem;
    color: #94a3b8;
    line-height: 1.7;
    white-space: pre-wrap;
    word-break: break-all;
  }

  .fix-box { color: var(--accent2); }

  .refs {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    margin-top: 8px;
  }

  .ref-tag {
    font-family: var(--mono);
    font-size: 0.65rem;
    padding: 3px 8px;
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--muted);
  }

  /* Empty state */
  .empty-state {
    text-align: center;
    padding: 60px 20px;
    color: var(--muted);
  }

  .empty-state .big-icon { font-size: 4rem; margin-bottom: 16px; }
  .empty-state h3 { font-size: 1.1rem; color: var(--accent2); margin-bottom: 8px; }
  .empty-state p { font-size: 0.85rem; }

  /* Responsive */
  @media (max-width: 640px) {
    .score-grid { grid-template-columns: 1fr; }
    .severity-stats { grid-template-columns: repeat(2, 1fr); }
    .scan-row { flex-direction: column; }
  }
</style>
</head>
<body>
<div class="container">

  <header>
    <div class="logo-line">
      <div class="logo-badge">🛡</div>
      <h1>Laravel <span>Security</span> Scanner</h1>
    </div>
    <p class="tagline">// Vulnerability Assessment Tool for Laravel Applications</p>
  </header>

  <section class="scan-section">
    <div class="scan-card">
      <label class="scan-label" for="target-url">// Target URL</label>
      <div class="scan-row">
        <input
          id="target-url"
          class="scan-input"
          type="url"
          placeholder="https://your-laravel-app.com"
          autocomplete="off"
          spellcheck="false"
        />
        <button class="scan-btn" id="scan-btn" onclick="startScan()">
          <span id="btn-icon">▶</span>
          <span id="btn-text">Scan Now</span>
        </button>
      </div>
      <p class="scan-note">⚠ Only scan applications you own or have explicit permission to test.</p>

      <div id="progress-section">
        <div class="progress-header">
          <div class="pulse-dot"></div>
          <span id="progress-label">Initializing scan...</span>
          <span id="progress-pct" style="margin-left:auto; color:var(--muted)">0%</span>
        </div>
        <div class="progress-bar-wrap">
          <div class="progress-bar" id="progress-bar"></div>
        </div>
        <div class="log-output" id="log-output"></div>
      </div>
    </div>
  </section>

  <section id="results-section">
    <div class="results-header">
      <div>
        <div class="results-title">Scan Results</div>
        <div class="results-url" id="results-url"></div>
      </div>
      <button class="scan-btn" onclick="scrollTo(0,0)" style="background:var(--surface2);color:var(--text);border:1px solid var(--border);">
        ↑ New Scan
      </button>
    </div>

    <!-- Score -->
    <div class="score-grid">
      <div class="score-circle-wrap">
        <div class="score-number" id="score-num">-</div>
        <div class="score-label">Security Score</div>
        <div class="score-grade" id="score-grade"></div>
      </div>
      <div class="severity-stats">
        <div class="stat-item">
          <div class="stat-count sev-critical" id="count-critical">0</div>
          <div class="stat-label sev-critical">Critical</div>
        </div>
        <div class="stat-item">
          <div class="stat-count sev-high" id="count-high">0</div>
          <div class="stat-label sev-high">High</div>
        </div>
        <div class="stat-item">
          <div class="stat-count sev-medium" id="count-medium">0</div>
          <div class="stat-label sev-medium">Medium</div>
        </div>
        <div class="stat-item">
          <div class="stat-count sev-low" id="count-low">0</div>
          <div class="stat-label sev-low">Low</div>
        </div>
      </div>
    </div>

    <!-- Filters -->
    <div class="filter-tabs" id="filter-tabs">
      <button class="filter-tab active" onclick="filterFindings('all', this)">All</button>
      <button class="filter-tab" onclick="filterFindings('critical', this)">🔴 Critical</button>
      <button class="filter-tab" onclick="filterFindings('high', this)">🟠 High</button>
      <button class="filter-tab" onclick="filterFindings('medium', this)">🟡 Medium</button>
      <button class="filter-tab" onclick="filterFindings('low', this)">🔵 Low</button>
    </div>

    <!-- Findings list -->
    <div id="findings-list"></div>
  </section>

</div>

<script>
let allFindings = [];
let currentFilter = 'all';

async function startScan() {
  const url = document.getElementById('target-url').value.trim();
  if (!url) {
    alert('Please enter a target URL.');
    return;
  }
  try { new URL(url); } catch {
    alert('Please enter a valid URL (including https://)');
    return;
  }

  // Reset UI
  allFindings = [];
  document.getElementById('findings-list').innerHTML = '';
  document.getElementById('results-section').style.display = 'none';
  document.getElementById('progress-section').style.display = 'block';
  document.getElementById('log-output').innerHTML = '';
  document.getElementById('progress-bar').style.width = '0%';
  document.getElementById('progress-pct').textContent = '0%';
  document.getElementById('scan-btn').disabled = true;
  document.getElementById('btn-text').textContent = 'Scanning...';
  document.getElementById('btn-icon').textContent = '⟳';

  try {
    const resp = await fetch('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const lines = decoder.decode(value).split('\n');
      for (const line of lines) {
        if (!line.startsWith('data:')) continue;
        try {
          const data = JSON.parse(line.slice(5));
          handleEvent(data, url);
        } catch {}
      }
    }
  } catch (err) {
    alert('Scan failed: ' + err.message);
  } finally {
    document.getElementById('scan-btn').disabled = false;
    document.getElementById('btn-text').textContent = 'Scan Now';
    document.getElementById('btn-icon').textContent = '▶';
  }
}

function handleEvent(data, url) {
  if (data.type === 'progress') {
    const pct = data.pct;
    document.getElementById('progress-bar').style.width = pct + '%';
    document.getElementById('progress-pct').textContent = pct + '%';
    document.getElementById('progress-label').textContent = data.message || 'Scanning...';
    const log = document.getElementById('log-output');
    if (data.message) {
      const line = document.createElement('div');
      line.className = 'log-line';
      line.textContent = data.message;
      log.appendChild(line);
      log.scrollTop = log.scrollHeight;
    }
  }
  if (data.type === 'done') {
    renderResults(data.results, url);
    document.getElementById('progress-section').style.display = 'none';
  }
  if (data.type === 'error') {
    alert('Error: ' + data.message);
    document.getElementById('progress-section').style.display = 'none';
  }
}

function renderResults(results, url) {
  allFindings = results.findings || [];
  const counts = results.severity_counts || {};
  const score = results.security_score || 0;

  // Score
  document.getElementById('score-num').textContent = score;
  document.getElementById('results-url').textContent = url;

  const scoreEl = document.getElementById('score-num');
  const gradeEl = document.getElementById('score-grade');
  if (score >= 85) {
    scoreEl.style.color = 'var(--accent2)';
    gradeEl.textContent = 'GOOD';
    gradeEl.style.cssText = 'background:rgba(90,255,160,0.1);color:var(--accent2);border:1px solid rgba(90,255,160,0.3);';
  } else if (score >= 60) {
    scoreEl.style.color = 'var(--yellow)';
    gradeEl.textContent = 'FAIR';
    gradeEl.style.cssText = 'background:rgba(255,209,102,0.1);color:var(--yellow);border:1px solid rgba(255,209,102,0.3);';
  } else if (score >= 35) {
    scoreEl.style.color = 'var(--orange)';
    gradeEl.textContent = 'POOR';
    gradeEl.style.cssText = 'background:rgba(255,140,66,0.1);color:var(--orange);border:1px solid rgba(255,140,66,0.3);';
  } else {
    scoreEl.style.color = 'var(--red)';
    gradeEl.textContent = 'CRITICAL';
    gradeEl.style.cssText = 'background:rgba(255,77,106,0.1);color:var(--red);border:1px solid rgba(255,77,106,0.3);';
  }

  document.getElementById('count-critical').textContent = counts.critical || 0;
  document.getElementById('count-high').textContent = counts.high || 0;
  document.getElementById('count-medium').textContent = counts.medium || 0;
  document.getElementById('count-low').textContent = counts.low || 0;

  document.getElementById('results-section').style.display = 'block';
  filterFindings(currentFilter);
}

function filterFindings(filter, btn) {
  currentFilter = filter;
  document.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
  if (btn) btn.classList.add('active');

  const list = document.getElementById('findings-list');
  list.innerHTML = '';

  const filtered = filter === 'all'
    ? allFindings
    : allFindings.filter(f => f.severity === filter);

  // Sort by severity
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  filtered.sort((a, b) => (order[a.severity] || 9) - (order[b.severity] || 9));

  if (filtered.length === 0) {
    list.innerHTML = `
      <div class="empty-state">
        <div class="big-icon">${filter === 'all' ? '✅' : '🔍'}</div>
        <h3>${filter === 'all' ? 'No vulnerabilities detected!' : 'No ' + filter + ' severity findings'}</h3>
        <p>${filter === 'all' ? 'The scan completed with no issues found. Keep your dependencies updated.' : 'Try selecting a different severity filter.'}</p>
      </div>`;
    return;
  }

  filtered.forEach((f, i) => {
    const card = createFindingCard(f, i);
    list.appendChild(card);
  });
}

function createFindingCard(f, i) {
  const div = document.createElement('div');
  div.className = 'finding-card';
  div.innerHTML = `
    <div class="finding-header" onclick="toggleCard(this.parentElement)">
      <span class="sev-badge badge-${f.severity}">${f.severity}</span>
      <span class="finding-title">${escHtml(f.title)}</span>
      <span class="finding-category">${escHtml(f.category)}</span>
      <span class="chevron">▾</span>
    </div>
    <div class="finding-body">
      <div class="finding-section">
        <div class="finding-section-label">// Description</div>
        <div class="finding-section-text">${escHtml(f.description)}</div>
      </div>
      <div class="finding-section">
        <div class="finding-section-label">// Evidence</div>
        <div class="evidence-box">${escHtml(f.evidence)}</div>
      </div>
      <div class="finding-section">
        <div class="finding-section-label">// Recommended Fix</div>
        <div class="fix-box">${escHtml(f.fix)}</div>
      </div>
      ${f.references && f.references.length ? `
      <div class="finding-section">
        <div class="finding-section-label">// References</div>
        <div class="refs">
          ${f.references.map(r => `<span class="ref-tag">${escHtml(r)}</span>`).join('')}
        </div>
      </div>` : ''}
    </div>
  `;
  return div;
}

function toggleCard(card) {
  card.classList.toggle('open');
}

function escHtml(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Allow pressing Enter
document.getElementById('target-url').addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target_url = data.get("url", "").strip()

    if not target_url:
        return jsonify({"error": "No URL provided"}), 400

    def generate():
        def progress_cb(pct):
            pass  # handled inline

        try:
            scanner = LaravelScanner(target_url, timeout=8)
            checks = [
                (scanner.check_debug_mode, "Checking debug mode..."),
                (scanner.check_env_exposure, "Checking .env file exposure..."),
                (scanner.check_security_headers, "Checking security headers..."),
                (scanner.check_telescope_exposure, "Checking Telescope/Horizon exposure..."),
                (scanner.check_phpinfo, "Checking phpinfo() exposure..."),
                (scanner.check_sql_injection, "Testing for SQL injection..."),
                (scanner.check_csrf, "Checking CSRF protection..."),
                (scanner.check_directory_listing, "Checking directory listing..."),
                (scanner.check_sensitive_files, "Scanning for sensitive files..."),
                (scanner.check_ssl, "Checking SSL/TLS configuration..."),
                (scanner.check_open_redirect, "Testing for open redirect..."),
                (scanner.check_xss, "Testing for XSS vulnerabilities..."),
                (scanner.check_rate_limiting, "Checking rate limiting..."),
                (scanner.check_default_routes, "Checking default routes..."),
                (scanner.check_cookies, "Checking cookie security..."),
            ]

            total = len(checks)
            for i, (fn, msg) in enumerate(checks):
                pct = int((i / total) * 100)
                yield f"data:{json.dumps({'type':'progress','pct':pct,'message':msg})}\n\n"
                try:
                    fn()
                except Exception as e:
                    scanner._log(f"Check error: {e}")

            yield f"data:{json.dumps({'type':'progress','pct':100,'message':'Scan complete!'})}\n\n"
            summary = scanner.get_summary()
            yield f"data:{json.dumps({'type':'done','results':summary})}\n\n"

        except Exception as e:
            yield f"data:{json.dumps({'type':'error','message':str(e)})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


if __name__ == "__main__":
    print("🛡  Laravel Security Scanner")
    print("=" * 40)
    print("Starting server at http://localhost:5000")
    print("Open your browser and enter a Laravel URL to scan.")
    print("=" * 40)
    app.run(debug=False, port=5000, threaded=True)
