/**
 * PyAttackMap Frontend – app.js
 * Simulates the C++ native engine output in the browser.
 * Provides: code scanning, findings display, data-flow visualization, export.
 */

/* ═══════════════════════════════════════════════════════
   RULE DEFINITIONS (mirrors C++ rules registry)
   ═══════════════════════════════════════════════════════ */
const RULES = {
  PAM001: {
    id: 'PAM001',
    title: 'SQL Injection',
    cwe: 'CWE-89',
    severity: 'HIGH',
    confidence: 'HIGH',
    sources: ['input(', 'request.args', 'request.form', 'request.get(', 'sys.argv'],
    sinks: ['cursor.execute', 'cursor.executemany', 'connection.execute', 'db.execute'],
    taint_ops: ['f"', "f'", '+', '.format(', '% ('],
    remediation: 'Use parameterized queries with placeholders (?, %s) instead of string interpolation. Never concatenate user input into SQL strings.',
    desc: 'Untrusted user input flows into a SQL query string and is passed to a database execution sink, enabling SQL injection (CWE-89).'
  },
  PAM002: {
    id: 'PAM002',
    title: 'Command Injection',
    cwe: 'CWE-78',
    severity: 'HIGH',
    confidence: 'HIGH',
    sources: ['input(', 'request.args', 'request.form', 'sys.argv', 'os.environ'],
    sinks: ['os.system(', 'subprocess.run(', 'subprocess.call(', 'subprocess.Popen(', 'os.popen(', 'commands.getoutput('],
    taint_ops: ['+', 'f"', "f'", '.format(', '% ('],
    remediation: 'Use subprocess with a list of arguments (no shell=True) and validate/sanitize all inputs. Prefer shlex.quote() for shell escaping.',
    desc: 'Tainted user-controlled data reaches an OS command execution sink, enabling arbitrary command execution (CWE-78).'
  },
  PAM003: {
    id: 'PAM003',
    title: 'Unsafe Deserialization',
    cwe: 'CWE-502',
    severity: 'CRITICAL',
    confidence: 'MEDIUM',
    sources: ['input(', 'request.data', 'request.body', 'open(', 'socket.recv('],
    sinks: ['pickle.loads(', 'pickle.load(', 'marshal.loads(', 'yaml.load(', 'cPickle.loads('],
    taint_ops: ['.encode(', '.read(', '.decode('],
    remediation: 'Never deserialize data from untrusted sources with pickle/marshal. Use safe alternatives like json.loads(), or yaml.safe_load() for YAML.',
    desc: 'Untrusted data is passed to an unsafe deserialization function, enabling remote code execution via crafted payloads (CWE-502).'
  }
};

/* ═══════════════════════════════════════════════════════
   DEMO CODE SAMPLE (mirrors sample_project/vulnerable.py)
   ═══════════════════════════════════════════════════════ */
const DEMO_CODE = `"""Sample project: intentional vulnerabilities for demonstration."""

import os
import pickle
import sqlite3


def vulnerable_db_lookup(user_id: str) -> None:
    conn = sqlite3.connect("demo.db")
    cursor = conn.cursor()
    # PAM001: SQL injection via f-string
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)


def vulnerable_system_ping() -> None:
    host = input("Target IP: ")
    # PAM002: Command injection via tainted input to os.system
    os.system("ping -c 1 " + host)


def vulnerable_deserializer() -> None:
    token = input("Session token: ")
    # PAM003: Unsafe deserialization of untrusted input
    data = pickle.loads(token.encode("utf-8"))
    return data


def safe_db_lookup(user_id: str) -> None:
    conn = sqlite3.connect("demo.db")
    cursor = conn.cursor()
    # Safe: parameterized query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
`;

/* ═══════════════════════════════════════════════════════
   TAINT ANALYSIS ENGINE (browser simulation)
   ═══════════════════════════════════════════════════════ */
class TaintAnalyzer {
  constructor(code) {
    this.code = code;
    this.lines = code.split('\n');
    this.findings = [];
    this.findingId = 1;
  }

  analyze(ruleFilter = 'all', minSeverity = 'all') {
    const t0 = performance.now();

    const rulesToRun = ruleFilter === 'all'
      ? Object.values(RULES)
      : [RULES[ruleFilter]].filter(Boolean);

    for (const rule of rulesToRun) {
      this._runRule(rule);
    }

    // Filter by severity
    const order = { all: 0, low: 1, medium: 2, high: 3, critical: 4 };
    const minLevel = order[minSeverity] || 0;
    this.findings = this.findings.filter(f => {
      const sev = f.severity.toLowerCase();
      return (order[sev] || 0) >= minLevel;
    });

    const elapsed = (performance.now() - t0).toFixed(2);
    return { findings: this.findings, elapsed };
  }

  _runRule(rule) {
    // Find taint sources
    const sourceLocs = [];
    for (let i = 0; i < this.lines.length; i++) {
      const line = this.lines[i];
      for (const src of rule.sources) {
        if (line.includes(src) && !line.trimStart().startsWith('#')) {
          // Extract variable being assigned
          const varMatch = line.match(/^\s*(\w+)\s*=/);
          sourceLocs.push({
            line: i + 1,
            lineContent: line.trim(),
            variable: varMatch ? varMatch[1] : null,
            source: src
          });
        }
      }
    }

    if (sourceLocs.length === 0) return;

    // Find sinks and trace taint
    for (let i = 0; i < this.lines.length; i++) {
      const line = this.lines[i];
      if (line.trimStart().startsWith('#')) continue;

      for (const sink of rule.sinks) {
        if (!line.includes(sink)) continue;

        // Check if any tainted variable appears near this sink
        for (const srcLoc of sourceLocs) {
          if (i + 1 <= srcLoc.line) continue; // sink must come after source

          // Check direct taint or indirect via intermediate variables
          const isTainted = this._checkTaintFlow(srcLoc, i, sink, rule);
          if (isTainted) {
            const dataflow = this._buildDataflow(srcLoc, isTainted.intermediates, i, line.trim(), sink, rule);
            this.findings.push({
              id: `F${String(this.findingId++).padStart(3,'0')}`,
              rule_id: rule.id,
              title: rule.title,
              cwe: rule.cwe,
              severity: rule.severity,
              confidence: rule.confidence,
              line: i + 1,
              source_line: srcLoc.line,
              lineContent: line.trim(),
              desc: rule.desc,
              remediation: rule.remediation,
              dataflow
            });
            break; // one finding per sink occurrence
          }
        }
      }
    }
  }

  _checkTaintFlow(srcLoc, sinkLineIdx, sink, rule) {
    const intermediates = [];
    const sinkLine = this.lines[sinkLineIdx].trim();

    // Direct: source variable appears in sink line
    if (srcLoc.variable && sinkLine.includes(srcLoc.variable)) {
      return { intermediates };
    }

    // Look for intermediate variables between source and sink
    for (let j = srcLoc.line; j < sinkLineIdx; j++) {
      const mid = this.lines[j].trim();
      if (mid.startsWith('#')) continue;

      // Check if intermediate line uses source variable in a taint operation
      if (srcLoc.variable) {
        for (const op of rule.taint_ops) {
          if (mid.includes(srcLoc.variable) && mid.includes(op)) {
            const varMatch = mid.match(/^(\w+)\s*=/);
            if (varMatch) {
              intermediates.push({ line: j + 1, lineContent: mid, variable: varMatch[1] });
              // Check if this intermediate var appears in sink
              if (sinkLine.includes(varMatch[1])) {
                return { intermediates };
              }
            }
          }
        }
        // Also catch f-string or concatenation patterns that include the var
        if (mid.includes(srcLoc.variable)) {
          const varMatch = mid.match(/^(\w+)\s*=/);
          if (varMatch && sinkLine.includes(varMatch[1])) {
            intermediates.push({ line: j + 1, lineContent: mid, variable: varMatch[1] });
            return { intermediates };
          }
        }
      }
    }

    // Fallback: if sink line references any source pattern directly
    for (const src of rule.sources) {
      if (sinkLine.includes(src)) return { intermediates };
    }

    return null;
  }

  _buildDataflow(srcLoc, intermediates, sinkLineIdx, sinkContent, sinkName, rule) {
    const nodes = [];
    nodes.push({
      kind: 'SOURCE',
      line: srcLoc.line,
      label: srcLoc.source.replace('(','') + '()',
      content: srcLoc.lineContent
    });

    for (const im of intermediates) {
      nodes.push({
        kind: 'PROPAGATE',
        line: im.line,
        label: im.variable + ' = ...',
        content: im.lineContent
      });
    }

    nodes.push({
      kind: 'SINK',
      line: sinkLineIdx + 1,
      label: sinkName.replace('(','') + '()',
      content: sinkContent
    });

    return { nodes, rule_id: rule.id };
  }
}

/* ═══════════════════════════════════════════════════════
   MERMAID GRAPH GENERATOR
   ═══════════════════════════════════════════════════════ */
function toMermaid(dataflow) {
  const lines = ['flowchart LR'];
  const nodes = dataflow.nodes;
  for (let i = 0; i < nodes.length; i++) {
    const n = nodes[i];
    const id = `N${i}`;
    if (n.kind === 'SOURCE') {
      lines.push(`    ${id}["🔵 SOURCE\\nLine ${n.line}: ${escMermaid(n.label)}"]:::source`);
    } else if (n.kind === 'PROPAGATE') {
      lines.push(`    ${id}["🟡 TAINT\\nLine ${n.line}: ${escMermaid(n.label)}"]:::taint`);
    } else {
      lines.push(`    ${id}["🔴 SINK\\nLine ${n.line}: ${escMermaid(n.label)}"]:::sink`);
    }
    if (i > 0) lines.push(`    N${i-1} -->|taint| ${id}`);
  }
  lines.push('    classDef source fill:#1a4a5a,stroke:#26c6da,color:#26c6da');
  lines.push('    classDef taint fill:#4a3800,stroke:#ffa502,color:#ffa502');
  lines.push('    classDef sink fill:#4a1520,stroke:#ff4757,color:#ff4757');
  return lines.join('\n');
}

function escMermaid(s) {
  return s.replace(/"/g, "'").replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

/* ═══════════════════════════════════════════════════════
   UI CONTROLLER
   ═══════════════════════════════════════════════════════ */
let currentFindings = [];
let currentFindingIndex = 0;

// ── DOM refs ──
const codeEditor    = document.getElementById('code-editor');
const lineNumbers   = document.getElementById('line-numbers');
const lineCount     = document.getElementById('line-count');
const scanBtn       = document.getElementById('scan-btn');
const loadDemoBtn   = document.getElementById('load-demo-btn');
const clearBtn      = document.getElementById('clear-btn');
const fileInput     = document.getElementById('file-input');
const dropZone      = document.getElementById('drop-zone');
const currentFilename = document.getElementById('current-filename');

// Results refs
const emptyState      = document.getElementById('empty-state');
const scanLoader      = document.getElementById('scan-loader');
const cleanState      = document.getElementById('clean-state');
const findingsContainer = document.getElementById('findings-container');
const findingsList    = document.getElementById('findings-list');
const summaryCards    = document.getElementById('summary-cards');
const dataflowPanel   = document.getElementById('dataflow-panel');

// Stats
const totalFindings = document.getElementById('total-findings');
const highCount     = document.getElementById('high-count');
const mediumCount   = document.getElementById('medium-count');
const scanSpeed     = document.getElementById('scan-speed');

// ── Init ──
document.addEventListener('DOMContentLoaded', () => {
  initParticles();
  initEditor();
  initDropZone();
  initButtons();
  initNavScroll();
  updateLineNumbers();
});

/* ── Particles ── */
function initParticles() {
  const container = document.getElementById('particles-container');
  if (!container) return;
  for (let i = 0; i < 30; i++) {
    const p = document.createElement('div');
    p.className = 'particle';
    p.style.left = Math.random() * 100 + '%';
    p.style.animationDuration = (8 + Math.random() * 12) + 's';
    p.style.animationDelay = -(Math.random() * 15) + 's';
    p.style.width = p.style.height = (1 + Math.random() * 2) + 'px';
    p.style.opacity = (0.2 + Math.random() * 0.5).toString();
    container.appendChild(p);
  }
}

/* ── Code Editor line numbers ── */
function initEditor() {
  codeEditor.addEventListener('input', updateLineNumbers);
  codeEditor.addEventListener('scroll', () => {
    lineNumbers.scrollTop = codeEditor.scrollTop;
  });
}

function updateLineNumbers() {
  const lines = codeEditor.value.split('\n');
  lineCount.textContent = `${lines.length} lines`;
  lineNumbers.textContent = lines.map((_,i) => i+1).join('\n');
}

/* ── Drag & Drop ── */
function initDropZone() {
  dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) loadFile(file);
  });
  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) loadFile(fileInput.files[0]);
  });
}

function loadFile(file) {
  const reader = new FileReader();
  reader.onload = e => {
    codeEditor.value = e.target.result;
    currentFilename.textContent = file.name;
    updateLineNumbers();
  };
  reader.readAsText(file);
}

/* ── Buttons ── */
function initButtons() {
  loadDemoBtn.addEventListener('click', () => {
    codeEditor.value = DEMO_CODE;
    currentFilename.textContent = 'vulnerable.py';
    updateLineNumbers();
  });

  clearBtn.addEventListener('click', () => {
    codeEditor.value = '';
    currentFilename.textContent = 'untitled.py';
    updateLineNumbers();
    resetResults();
  });

  scanBtn.addEventListener('click', runScan);

  document.getElementById('export-json-btn').addEventListener('click', exportJSON);
  document.getElementById('copy-mermaid-btn').addEventListener('click', copyMermaid);

  document.getElementById('finding-select').addEventListener('change', e => {
    const idx = parseInt(e.target.value, 10);
    if (!isNaN(idx)) renderDataflow(currentFindings[idx]);
  });
}

/* ── Nav Active State on Scroll ── */
function initNavScroll() {
  const sections = ['scan-section', 'rules-section', 'about-section'];
  const navLinks = { 'scan-section': 'nav-scan', 'rules-section': 'nav-rules', 'about-section': 'nav-about' };

  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
        const link = document.getElementById(navLinks[entry.target.id]);
        if (link) link.classList.add('active');
      }
    });
  }, { threshold: 0.4 });

  sections.forEach(id => {
    const el = document.getElementById(id);
    if (el) observer.observe(el);
  });
}

/* ═══════════════════════════════════════════════════════
   SCAN LOGIC
   ═══════════════════════════════════════════════════════ */
async function runScan() {
  const code = codeEditor.value.trim();
  if (!code) {
    showToast('Please paste some Python code first!', 'warn');
    return;
  }

  const ruleFilter  = document.getElementById('rules-select').value;
  const minSeverity = document.getElementById('severity-select').value;

  // Show loader
  showState('loading');
  scanBtn.disabled = true;
  scanBtn.textContent = 'Scanning...';

  // Simulate async (for UX feel)
  await new Promise(r => setTimeout(r, 600 + Math.random() * 400));

  const analyzer = new TaintAnalyzer(code);
  const { findings, elapsed } = analyzer.analyze(ruleFilter, minSeverity);
  currentFindings = findings;

  scanBtn.disabled = false;
  scanBtn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Scan Code`;

  if (findings.length === 0) {
    showState('clean');
    summaryCards.style.display = 'none';
    dataflowPanel.style.display = 'none';
    return;
  }

  // Update summary
  const high = findings.filter(f => ['HIGH','CRITICAL'].includes(f.severity)).length;
  const medium = findings.filter(f => f.severity === 'MEDIUM').length;
  totalFindings.textContent = findings.length;
  highCount.textContent = high;
  mediumCount.textContent = medium;
  scanSpeed.textContent = elapsed + 'ms';

  summaryCards.style.display = 'grid';
  showState('findings');
  renderFindings(findings);
  renderDataflowPanel(findings);
  showToast(`Found ${findings.length} vulnerabilit${findings.length > 1 ? 'ies' : 'y'}!`, 'error');
}

/* ── Render Findings List ── */
function renderFindings(findings) {
  findingsList.innerHTML = '';
  findings.forEach((f, idx) => {
    const card = document.createElement('div');
    const sevClass = f.severity.toLowerCase();
    card.className = `finding-card sev-${sevClass}`;
    card.dataset.idx = idx;

    card.innerHTML = `
      <div class="finding-top">
        <span class="finding-rule">${f.rule_id}</span>
        <span class="finding-severity sev-badge-${sevClass}">${f.severity}</span>
      </div>
      <div class="finding-title">${f.title}</div>
      <div class="finding-meta">
        <span>📍 Line ${f.line}</span>
        <span>🔑 ${f.cwe}</span>
        <span>🎯 ${f.confidence} confidence</span>
      </div>
      <div class="finding-desc">${f.desc}</div>
      <div class="finding-remediation">💡 ${f.remediation}</div>
    `;

    card.addEventListener('click', () => {
      document.querySelectorAll('.finding-card').forEach(c => c.style.outline = '');
      card.style.outline = '1px solid var(--cyan)';
      renderDataflow(f);
      const sel = document.getElementById('finding-select');
      sel.value = idx;
      dataflowPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    });

    findingsList.appendChild(card);
  });
}

/* ── Data Flow Panel ── */
function renderDataflowPanel(findings) {
  dataflowPanel.style.display = 'block';

  const sel = document.getElementById('finding-select');
  sel.innerHTML = findings.map((f, i) =>
    `<option value="${i}">${f.id}: ${f.rule_id} – ${f.title} (L${f.line})</option>`
  ).join('');

  renderDataflow(findings[0]);
}

function renderDataflow(finding) {
  if (!finding || !finding.dataflow) return;
  const df = finding.dataflow;

  // Flow graph
  const graph = document.getElementById('flow-graph');
  let html = '<div class="flow-nodes">';
  df.nodes.forEach((node, i) => {
    const cls = node.kind === 'SOURCE' ? 'node-source' : node.kind === 'PROPAGATE' ? 'node-propagate' : 'node-sink';
    html += `
      <div class="flow-node">
        <div class="node-box ${cls}" title="${escHtml(node.content)}">${escHtml(node.label)}<br><small>L${node.line}</small></div>
        <div class="node-label">${node.kind}</div>
      </div>
    `;
    if (i < df.nodes.length - 1) {
      html += '<div class="flow-arrow">→</div>';
    }
  });
  html += '</div>';
  graph.innerHTML = html;

  // Mermaid
  document.getElementById('mermaid-output').textContent = toMermaid(df);
}

/* ── State Management ── */
function showState(state) {
  emptyState.style.display = 'none';
  scanLoader.style.display = 'none';
  cleanState.style.display = 'none';
  findingsContainer.style.display = 'none';

  if (state === 'empty') emptyState.style.display = 'flex';
  else if (state === 'loading') scanLoader.style.display = 'flex';
  else if (state === 'clean') cleanState.style.display = 'flex';
  else if (state === 'findings') findingsContainer.style.display = 'flex';
}

function resetResults() {
  currentFindings = [];
  summaryCards.style.display = 'none';
  dataflowPanel.style.display = 'none';
  showState('empty');
}

/* ── Export JSON ── */
function exportJSON() {
  if (!currentFindings.length) return;
  const report = {
    tool: 'PyAttackMap',
    version: '1.0.0',
    engine: 'Browser Simulation (C++20 Native Engine on CLI)',
    timestamp: new Date().toISOString(),
    summary: {
      total: currentFindings.length,
      high: currentFindings.filter(f => ['HIGH','CRITICAL'].includes(f.severity)).length,
      medium: currentFindings.filter(f => f.severity === 'MEDIUM').length
    },
    findings: currentFindings.map(f => ({
      id: f.id,
      rule_id: f.rule_id,
      title: f.title,
      cwe: f.cwe,
      severity: f.severity,
      confidence: f.confidence,
      location: { line: f.line },
      description: f.desc,
      remediation: f.remediation
    }))
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'pyattackmap_report.json';
  a.click();
  URL.revokeObjectURL(url);
  showToast('Report exported!', 'success');
}

/* ── Copy Mermaid ── */
function copyMermaid() {
  const pre = document.getElementById('mermaid-output');
  navigator.clipboard.writeText(pre.textContent).then(() => {
    showToast('Mermaid syntax copied!', 'success');
  });
}

/* ── Toast Notifications ── */
function showToast(msg, type = 'info') {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.className = 'toast';
  const colors = { success: '#00f5c4', error: '#ff4757', warn: '#ffa502', info: '#26c6da' };
  toast.style.cssText = `
    position: fixed; bottom: 24px; right: 24px; z-index: 9999;
    background: var(--bg-panel); color: ${colors[type] || colors.info};
    border: 1px solid ${colors[type] || colors.info};
    border-radius: 10px; padding: 12px 20px;
    font-size: 0.85rem; font-weight: 600; font-family: var(--font-body);
    box-shadow: 0 8px 30px rgba(0,0,0,0.5);
    animation: slideUp 0.3s ease;
    backdrop-filter: blur(10px);
  `;
  toast.textContent = msg;
  document.body.appendChild(toast);

  setTimeout(() => {
    toast.style.animation = 'fadeOut 0.3s ease forwards';
    setTimeout(() => toast.remove(), 300);
  }, 2800);
}

// Toast animations via style tag
const toastStyle = document.createElement('style');
toastStyle.textContent = `
  @keyframes slideUp { from { opacity:0; transform:translateY(10px); } to { opacity:1; transform:translateY(0); } }
  @keyframes fadeOut { from { opacity:1; } to { opacity:0; transform:translateY(5px); } }
`;
document.head.appendChild(toastStyle);

/* ── Helpers ── */
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
