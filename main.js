/**
 * TigerGRCi founder site — zero-trust client architecture.
 * Never trust the network, third parties, or client storage by default.
 * Explicit verify at every boundary; least privilege; assume breach.
 */
(function () {
  "use strict";

  /** Frame-busting (GitHub Pages cannot set frame-ancestors). */
  try {
    if (window.top && window.top !== window.self) {
      window.top.location = window.self.location;
    }
  } catch (_) {
    /* cross-origin frame */
  }

  /** @type {string} Only this Formspree form — no wildcard trust. */
  const FORMSPREE_ENDPOINT = "https://formspree.io/f/xqpkryrn";
  const FORMSPREE_ORIGIN = "https://formspree.io";

  const DRAFT_KEY = "tigergrci-community-draft-v2";
  const DRAFT_MAX_AGE_MS = 24 * 60 * 60 * 1000; /* 24h — assume breach on shared PCs */
  const SUBMIT_COOLDOWN_MS = 12000;
  let lastSubmitAt = 0;

  const SOCIAL_HOST_ALLOW = [
    "linkedin.com",
    "www.linkedin.com",
    "facebook.com",
    "www.facebook.com",
    "m.facebook.com",
    "fb.com",
    "www.fb.com",
  ];

  /** Trusted Types default policy: only escaped/sanitized HTML enters the DOM. */
  var ttPolicy = null;
  try {
    if (window.trustedTypes && typeof window.trustedTypes.createPolicy === "function") {
      ttPolicy = window.trustedTypes.createPolicy("tigergrci", {
        createHTML: function (s) {
          return String(s);
        },
        createScriptURL: function (s) {
          var u = String(s);
          if (/^https:\/\/formspree\.io\//i.test(u)) return u;
          if (/^[a-z0-9._\-\/]+\.(js|json|svg)(\?.*)?$/i.test(u)) return u;
          throw new Error("untrusted script URL");
        },
      });
    }
  } catch (_) {
    ttPolicy = null;
  }

  function setHtml(el, html) {
    if (!el) return;
    var payload = String(html);
    if (ttPolicy) {
      el.innerHTML = ttPolicy.createHTML(payload);
    } else {
      el.innerHTML = payload;
    }
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function clampInt(n, min, max, fallback) {
    const v = Number(n);
    if (!Number.isFinite(v)) return fallback;
    return Math.min(max, Math.max(min, Math.round(v)));
  }

  /** Marketing-safe copy: hide backend routes/stack formulas from public UI. */
  function publicSafeText(s) {
    const t = String(s || "");
    if (
      /\/api\/v?\d|postgres|keycloak|express\s*\d|next\.js\s*\d|scoring\s+formula|eval[\s_-]?id|BM25|RLS\b|docker-compose/i.test(
        t
      )
    ) {
      return "Product capability detail available under NDA.";
    }
    return t;
  }

  function isAllowedHttpsUrl(raw, hostAllowList) {
    if (!raw || typeof raw !== "string") return false;
    if (!hostAllowList || !hostAllowList.length) return false;
    let u;
    try {
      u = new URL(raw.trim());
    } catch (_) {
      return false;
    }
    if (u.protocol !== "https:") return false;
    if (u.username || u.password) return false;
    if (u.hash) return false;
    const host = u.hostname.toLowerCase();
    /* Exact host match only — no subdomain wildcard, no fail-open. */
    return hostAllowList.some(function (allowed) {
      return host === String(allowed).toLowerCase();
    });
  }

  /** Zero-trust images: same-origin assets only (no arbitrary https). */
  function isSafeImageUrl(raw) {
    if (!raw || typeof raw !== "string") return false;
    const t = raw.trim();
    if (t.indexOf("..") !== -1 || t.indexOf("\\") !== -1) return false;
    if (t.charAt(0) === "/" || /^https?:/i.test(t) || /^data:/i.test(t) || /^blob:/i.test(t)) {
      return false;
    }
    return /^assets\/[a-zA-Z0-9._\-\/]+$/i.test(t);
  }

  function isSameOriginRelative(path) {
    if (!path || typeof path !== "string") return false;
    const t = path.trim();
    if (t.indexOf("..") !== -1) return false;
    return /^[a-z0-9._\-\/]+\.(json|svg|js)(\?[#a-z0-9._\-=&]*)?$/i.test(t);
  }

  function sanitizeSvgMarkup(svgText) {
    return String(svgText || "")
      .replace(/<\?xml[^>]*>/gi, "")
      .replace(/<!DOCTYPE[^>]*>/gi, "")
      .replace(/<script[\s\S]*?<\/script>/gi, "")
      .replace(/<foreignObject[\s\S]*?<\/foreignObject>/gi, "")
      .replace(/\son[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, "")
      .replace(/(href|xlink:href)\s*=\s*("\s*javascript:[^"]*"|'\s*javascript:[^']*')/gi, '$1=""')
      .replace(/(href|xlink:href)="(iso\/[^"]+)"/g, '$1="assets/workflow-arch/$2"')
      .trim();
  }

  /** Fetch only same-origin relative JSON; verify Content-Type + shape. */
  function fetchTrustedJson(path, validate) {
    if (!isSameOriginRelative(path)) {
      return Promise.reject(new Error("untrusted path"));
    }
    return fetch(path, {
      cache: "no-store",
      credentials: "same-origin",
      mode: "same-origin",
      redirect: "error",
    }).then(function (res) {
      if (!res.ok) throw new Error("fetch failed");
      var ct = (res.headers.get("content-type") || "").toLowerCase();
      if (ct && ct.indexOf("json") === -1 && ct.indexOf("javascript") === -1 && ct.indexOf("text/plain") === -1) {
        throw new Error("unexpected content-type");
      }
      return res.json();
    }).then(function (data) {
      if (typeof validate === "function" && !validate(data)) {
        throw new Error("schema rejected");
      }
      return data;
    });
  }

  function canSubmitNow() {
    var now = Date.now();
    if (now - lastSubmitAt < SUBMIT_COOLDOWN_MS) return false;
    lastSubmitAt = now;
    return true;
  }

  function assertFormspreeEndpoint(url) {
    try {
      var u = new URL(url);
      return u.origin === FORMSPREE_ORIGIN && /^\/f\/[a-z0-9]+$/i.test(u.pathname);
    } catch (_) {
      return false;
    }
  }

  const WORKFLOW_STEPS = [
    {
      id: "collect",
      short: "Collect",
      sub: "Artefacts in",
      title: "Collect artefacts from every source",
      lead:
        "Policies, evidence packs, scan reports, vendor files, and profile photos land in one intake. Each upload belongs to a workspace so one organisation never bleeds into another.",
      checks: [
        "Policy PDFs, evidence files, and security scan reports enter through the same gate",
        "Workspace and business-unit scope travel with every artefact",
        "Owners and due dates attach early so nothing sits orphaned",
      ],
      mocks: [
        { label: "Intake", value: "12 files queued", tone: "" },
        { label: "Sources", value: "Policy, Evidence, Scans", tone: "" },
        { label: "Scope", value: "Workspace locked", tone: "is-ok" },
      ],
      scene: {
        title: "Artefact intake",
        rows: [
          { k: "ICT Security Policy.pdf", v: "Policy, queued", tone: "" },
          { k: "Access review Q3.zip", v: "Evidence, queued", tone: "" },
          { k: "External VAPT report.pdf", v: "Scan, queued", tone: "is-warn" },
          { k: "Vendor SOC 2 letter.pdf", v: "Third party, queued", tone: "" },
        ],
      },
    },
    {
      id: "process",
      short: "Process",
      sub: "Extract & register",
      title: "Process and register every file",
      lead:
        "File-type checks, content hashing, and allow-lists decide what may proceed. A receipt stays on the chain of custody before anything becomes proof an auditor can trust.",
      checks: [
        "File type and content profile must match what you claimed to upload",
        "Hash and receipt are stored so auditors can replay the gate later",
        "Rejected files never become attachable evidence",
      ],
      mocks: [
        { label: "Gate", value: "Allow, Deny, Quarantine", tone: "" },
        { label: "Receipts", value: "Hash recorded", tone: "is-ok" },
        { label: "Custody", value: "Provenance written", tone: "is-ok" },
      ],
      scene: {
        title: "Processing gate",
        rows: [
          { k: "Type check", v: "PDF matched claim", tone: "is-ok" },
          { k: "Integrity hash", v: "Recorded", tone: "is-ok" },
          { k: "Allow-list", v: "Profile permitted", tone: "is-ok" },
          { k: "Register", v: "Ready for Trust Center", tone: "" },
        ],
      },
    },
    {
      id: "trust",
      short: "Trust Center",
      sub: "Ransomware check",
      title: "Trust Center ransomware and trust check",
      lead:
        "Before a file can serve as proof, Trust Center scans for ransomware patterns, suspicious executables, and ransom-note language. Bad uploads are blocked, quarantined, and shown as detections. Identity, access, workload, and evidence trust stay continuous.",
      checks: [
        "Ransomware scan runs on policy, evidence, and profile upload paths",
        "Malicious or suspicious content is blocked and quarantined, not silently accepted",
        "Trust Report shows gates, decisions, and detections in one place",
      ],
      mocks: [
        { label: "RW scan", value: "Clean, proceed", tone: "is-ok" },
        { label: "Quarantine", value: "0 held", tone: "is-ok" },
        { label: "Decision", value: "Allow with provenance", tone: "" },
      ],
      scene: {
        title: "Trust Center",
        rows: [
          { k: "Ransomware patterns", v: "None found", tone: "is-ok" },
          { k: "Suspicious binary", v: "None found", tone: "is-ok" },
          { k: "Ransom-note language", v: "Clear", tone: "is-ok" },
          { k: "Trust decision", v: "Allow, attachable", tone: "is-ok" },
        ],
      },
    },
    {
      id: "map",
      short: "Map",
      sub: "Human review",
      title: "Map policies to controls with human review",
      lead:
        "Assistive matching suggests where a clause lands in your control library. A reviewer confirms or corrects. What applies is decided from organisation facts and dual approval. Nothing auto-passes.",
      checks: [
        "Suggested mappings enter a review queue, not a silent accept",
        "What applies is decided from verified facts, then dual-approved",
        "Clause search shows policy and framework coverage in one place",
      ],
      mocks: [
        { label: "Suggestions", value: "Assistive only", tone: "" },
        { label: "Review", value: "Queue open", tone: "is-warn" },
        { label: "Approval", value: "Maker and checker", tone: "is-ok" },
      ],
      scene: {
        title: "Mapping review",
        rows: [
          { k: "Clause 4.2 to A.5.1", v: "Suggested, pending", tone: "is-warn" },
          { k: "Clause 5.1 to A.8.2", v: "Confirmed", tone: "is-ok" },
          { k: "Applicability", v: "Facts verified", tone: "is-ok" },
          { k: "Dual approval", v: "Checker queued", tone: "" },
        ],
      },
    },
    {
      id: "score",
      short: "Score risk",
      sub: "Findings & scans",
      title: "Score risk and pull findings together",
      lead:
        "Operational, cyber, third-party, and compliance risk sit in one register. Scan findings join the same path as other issues so owners see priority, not siloed spreadsheets.",
      checks: [
        "Company risk register stays beside scan and vendor findings",
        "Severity and owners drive what to fix first",
        "Leadership sees posture without leaving the GRC workspace",
      ],
      mocks: [
        { label: "Register", value: "Risk scored", tone: "" },
        { label: "Scans", value: "Findings linked", tone: "is-warn" },
        { label: "Priority", value: "Owners assigned", tone: "is-ok" },
      ],
      scene: {
        title: "Risk scoring",
        rows: [
          { k: "Cyber: privilege creep", v: "High, owner set", tone: "is-warn" },
          { k: "Third party: vendor lag", v: "Medium", tone: "" },
          { k: "Scan finding: open port", v: "Linked to control", tone: "is-warn" },
          { k: "Board view", v: "Posture updated", tone: "is-ok" },
        ],
      },
    },
    {
      id: "remediate",
      short: "Remediate",
      sub: "Fix and prove",
      title: "Remediate with fix-and-prove",
      lead:
        "Gaps become findings with owners and due dates. Closing requires corrective action plus evidence. Dual approval keeps critical closes honest. Nothing closes itself in the background.",
      checks: [
        "Correct the issue, attach proof, then request close",
        "Evidence stays linked to the control and the finding",
        "Decision history stays readable for auditors",
      ],
      mocks: [
        { label: "Findings", value: "In progress", tone: "is-warn" },
        { label: "Proof", value: "Evidence attached", tone: "is-ok" },
        { label: "Close", value: "Dual approval", tone: "" },
      ],
      scene: {
        title: "Fix-and-prove",
        rows: [
          { k: "Finding F-184", v: "Corrective action done", tone: "is-ok" },
          { k: "Evidence pack", v: "Screenshot + config", tone: "is-ok" },
          { k: "Retest", v: "Passed", tone: "is-ok" },
          { k: "Close request", v: "Awaiting checker", tone: "is-warn" },
        ],
      },
    },
    {
      id: "monitor",
      short: "Monitor",
      sub: "Live in production",
      title: "Continuous compliance in production",
      lead:
        "Controls keep watching after go-live. Freshness bands flag stale evidence. Command center and Trust Report show what is green, what drifted, and what needs another fix-and-prove loop. The run does not end at audit week.",
      checks: [
        "Continuous checks watch operating controls after remediation",
        "Stale or missing evidence reopens the path to proof",
        "Production monitoring feeds the same risk and compliance story",
      ],
      mocks: [
        { label: "Controls", value: "Monitoring on", tone: "is-ok" },
        { label: "Evidence", value: "Freshness bands", tone: "" },
        { label: "Trust Report", value: "Live posture", tone: "is-ok" },
      ],
      scene: {
        title: "Production monitoring",
        rows: [
          { k: "Continuous checks", v: "119 watching", tone: "is-ok" },
          { k: "Evidence freshness", v: "2 approaching stale", tone: "is-warn" },
          { k: "Drift alerts", v: "1 reopen queued", tone: "is-warn" },
          { k: "Trust Report", v: "Live for leadership", tone: "is-ok" },
        ],
      },
    },
  ];

  /** Authentic operational architecture crops from NotebookLM mindmap SVG. */
  const WORKFLOW_ARCH = {
    "collect": {
      "title": "Collect: Master workflow architecture",
      "lead": "Six clear steps in a continuous loop - Collect → Gate → Link → Gap → Close → Re-check - laid out so the path never crosses itself.",
      "diagram": "assets/workflow-arch/collect.svg",
      "components": [
        "Human uploads",
        "Endpoint agents",
        "Cloud connectors / S3",
        "Compliance monitors / CCM",
        "VAPT scans",
        "Policies / mapping / PMCR",
        "CCF continuous checks"
      ],
      "stores": [
        "Zero-trust file gate",
        "Evidence artefacts fabric",
        "Freshness / TTL / stale alerts",
        "Continuous loop back to Collect"
      ]
    },
    "process": {
      "title": "Process: Gate and ledger architecture",
      "lead": "Intake sources feed the Gate and ledger chain, then Zero-Trust fabric hardening before proof can attach.",
      "diagram": "assets/workflow-arch/process.svg",
      "components": [
        "Zero-trust file gate",
        "Evidence artefacts fabric",
        "Freshness / TTL / stale alerts"
      ],
      "stores": [
        "File gate / quarantine",
        "Step-up decisions",
        "Four-phase hardening"
      ]
    },
    "trust": {
      "title": "Trust Center: Security and Trust architecture",
      "lead": "Trust Center over Zero-Trust fabric over IAM and tenancy, with Privacy hub alongside - live Security and Trust nodes.",
      "diagram": "assets/workflow-arch/trust.svg",
      "components": [
        "IAM & tenancy",
        "Zero-Trust fabric",
        "Trust Center",
        "Privacy hub"
      ],
      "stores": [
        "File gate / quarantine",
        "Step-up decisions",
        "Four-phase hardening"
      ]
    },
    "map": {
      "title": "Map: Mapping Fabric architecture",
      "lead": "Policy inputs through Mapping Fabric (crosswalk, STRM, review) into Link bindings for framework and control evidence.",
      "diagram": "assets/workflow-arch/map.svg",
      "components": [
        "Crosswalk ledger",
        "STRM hub-spoke",
        "Review queue + receipts",
        "Framework and control ID",
        "Assessment evidence",
        "Policy mappings / receipts",
        "Findings + case evidence"
      ],
      "stores": [
        "Crosswalk ledger",
        "Policy mappings and receipts",
        "Assessment evidence"
      ]
    },
    "score": {
      "title": "Score risk: Holistic scoring architecture",
      "lead": "Holistic scoring as parallel design and operate paths that merge into capstone blend, truthful display, and continuous re-score.",
      "diagram": "assets/workflow-arch/score.svg",
      "components": [
        "0. Inputs enter the scoring plane",
        "1. Scope before score",
        "2. Retrieve candidates (Hybrid RAG)",
        "3. Defensible rank & route (PMCR)",
        "4. Design-alignment report",
        "5. Parallel design path - assessment gauges",
        "6. Parallel OE path - CCF + monitors",
        "7. Evidence freshness scoring",
        "8. Risk plane scoring",
        "9. Capstone blend & display honesty",
        "10. Loop - re-score continuously"
      ],
      "stores": [
        "Score history with provenance",
        "Design and operate gauges",
        "Living scores, not audit-season snapshots"
      ]
    },
    "remediate": {
      "title": "Remediate: Gap becomes work and Close",
      "lead": "Live signals become Findings and CAPA work in My Work, then fix in environment and close.",
      "diagram": "assets/workflow-arch/remediate.svg",
      "components": [
        "Findings + CAPA",
        "Monitor remediation items",
        "CCF remediation items",
        "VAPT vuln remediation",
        "My Work / user tasks"
      ],
      "stores": [
        "Fix in environment",
        "CAPA closed / item resolved"
      ]
    },
    "monitor": {
      "title": "Monitor live: Re-check architecture",
      "lead": "Scheduler ticks fan out to live verification targets, then loop back into Collect intakes.",
      "diagram": "assets/workflow-arch/monitor.svg",
      "components": [
        "Scheduler ticks",
        "Monitors / CCM",
        "CCF",
        "Evidence fabric",
        "Freshness / stale"
      ],
      "stores": [
        "Human uploads",
        "Endpoint agents",
        "Cloud connectors / S3",
        "Compliance monitors / CCM",
        "VAPT scans",
        "Policies / mapping / PMCR",
        "CCF continuous checks"
      ]
    }
  };

  const DEPARTMENTS = [
    { name: "Finance", path: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm1 14.9V18h-2v-1.1A3 3 0 0 1 8 14h1.5a1.5 1.5 0 0 0 1.5 1.4h1a1.5 1.5 0 0 0 0-3h-2a3 3 0 0 1 0-6V6H13v1.1A3 3 0 0 1 16 10h-1.5a1.5 1.5 0 0 0-1.5-1.4h-1a1.5 1.5 0 0 0 0 3h2a3 3 0 0 1 0 6.3z" },
    { name: "HR", path: "M16 11c1.7 0 3-1.3 3-3s-1.3-3-3-3-3 1.3-3 3 1.3 3 3 3zM8 11c1.7 0 3-1.3 3-3S9.7 5 8 5 5 6.3 5 8s1.3 3 3 3zm0 2c-2.3 0-7 1.2-7 3.5V19h14v-2.5C15 14.2 10.3 13 8 13zm8 0c-.3 0-.6 0-1 .1 1.2.9 2 2 2 3.4V19h6v-2.5c0-2.3-4.7-3.5-7-3.5z" },
    { name: "Legal", path: "M12 3l7 4v2H5V7l7-4zm-6 8h2v7H6v-7zm5 0h2v7h-2v-7zm5 0h2v7h-2v-7zM4 20h16v2H4v-2z" },
    { name: "Operations", path: "M19.1 12.9l1.8-1.1-1.5-2.6-2.1.5a6.8 6.8 0 0 0-1.2-.7l-.3-2.1h-3l-.3 2.1c-.4.2-.8.4-1.2.7l-2.1-.5-1.5 2.6 1.8 1.1c0 .4-.1.7-.1 1.1s0 .7.1 1.1l-1.8 1.1 1.5 2.6 2.1-.5c.4.3.8.5 1.2.7l.3 2.1h3l.3-2.1c.4-.2.8-.4 1.2-.7l2.1.5 1.5-2.6-1.8-1.1c.1-.4.1-.7.1-1.1s0-.7-.1-1.1zM12 15.5A3.5 3.5 0 1 1 12 8.5a3.5 3.5 0 0 1 0 7z" },
    { name: "Facilities", path: "M3 21V7l8-4 8 4v14h-5v-6H8v6H3zm2-2h2v-6h10v6h2V8.3L11 5.1 5 8.3V19z" },
    { name: "Security", path: "M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5l8-3zm0 2.2L6 6.1v4.9c0 3.9 2.5 7.4 6 8.8 3.5-1.4 6-4.9 6-8.8V6.1l-6-1.9z" },
    { name: "IT", path: "M4 5h16v10H4V5zm2 2v6h12V7H6zm-2 10h16v2H4v-2zm6 0h4v2h-4v-2z" },
    { name: "Marketing", path: "M3 10v4h2l5 4V6L5 10H3zm10.5 4.5c.8-.8.8-2.2 0-3l1.4-1.4c1.6 1.6 1.6 4.1 0 5.7l-1.4-1.3zM15.7 17c1.9-1.9 1.9-5 0-7l1.4-1.4c2.7 2.7 2.7 7 0 9.7L15.7 17z" },
  ];

  const CAPABILITIES = [
    {
      id: "platform",
      title: "Platform and trust",
      filter: "Platform",
      items: [
        "Self-hostable GRC for compliance, risk, audit, and leadership teams",
        "Separate workspaces per organisation, with business unit and facility scoping",
        "Run it where your data needs to stay; optional local AI when you allow it",
        "Role-based access for admins, security leads, compliance, auditors, analysts, and viewers",
        "Guided journeys: what applies for Bangladesh Bank packs, audit to fix-and-prove, company risk register",
      ],
    },
    {
      id: "legal",
      title: "Bangladesh cyber law",
      filter: "BD law",
      items: [
        "Legal Center for Bangladesh cyber law, clause by clause",
        "Browse provisions and show penalties only as written in the source",
        "Decide what applies from organisation facts (applies, does not apply, or needs review)",
        "Dual approval with a clear decision history",
        "Legal gap to finding to fix-and-prove, closed only with evidence",
        "Clear trail from clause to control to evidence to decision",
      ],
    },
    {
      id: "frameworks",
      title: "Bank packs and frameworks",
      filter: "Frameworks",
      items: [
        "Bangladesh Bank packs: Cybersecurity Framework 2026, ICT Security 2023, Cloud Computing 2023",
        "Shared catalogue across major frameworks such as ISO 27001, NIST CSF, SOC 2, PCI DSS, and more",
        "Assess once and reuse across frameworks with a shared control library",
        "Enable standards and create policies only after you state what applies",
        "Standard export of bank packs for partners and regulators",
        "Crosswalks between Bangladesh cyber law and international frameworks",
      ],
    },
    {
      id: "policy",
      title: "Policies and mapping",
      filter: "Policies",
      items: [
        "Policy register with upload, versions, review cycles, signoffs, and exceptions",
        "Match policies to controls with a human review queue (assistive, not auto-pass)",
        "Search a clause and see policy and framework coverage",
        "Control applicability from verified organisation facts, approve first",
        "Attestation campaigns; design maturity kept separate from operating effectiveness",
      ],
    },
    {
      id: "assurance",
      title: "Evidence, audit, and fixes",
      filter: "Assurance",
      items: [
        "Evidence hub linked to controls, with due dates",
        "Audit projects: scope, plans, fieldwork, evidence requests",
        "Workpapers and checklists for engagements",
        "Issues and fix-and-prove: root cause, owner, due date, effectiveness, retest",
        "Read-only portals for external reviewers",
        "Export audit packages as PDF, ZIP, or spreadsheet",
      ],
    },
    {
      id: "ops",
      title: "Day-to-day compliance",
      filter: "Operations",
      items: [
        "Command center for ongoing control checks",
        "Dashboards that keep design posture and operating posture separate",
        "People and devices: workforce, training, access reviews, endpoint posture",
        "Workflow automation and a personal work inbox",
        "Live dashboards, notifications, and leadership insights",
      ],
    },
    {
      id: "risk",
      title: "Risk and scan findings",
      filter: "Risk",
      items: [
        "Company-wide risk register with treatments and linked findings",
        "Workspaces for cyber, operational, financial, strategic, reputational, and continuity risk",
        "Measured views and heat maps for leadership",
        "Scan findings synced to remediation, with control links and reports",
        "Third-party and vendor risk: inventory, questionnaires, assessments",
      ],
    },
    {
      id: "privacy",
      title: "Privacy and governance extras",
      filter: "Privacy",
      items: [
        "Privacy hub for records of processing, impact assessments, and request workflows",
        "Public trust report for stakeholders",
        "Board reporting and ethics (conduct, conflicts, gifts, training)",
        "Organisation and facility registry; AI and asset inventory modules",
        "Integrations for sign-in, cloud, messaging, and evidence connectors",
      ],
    },
  ];

  const state = {
    mode: "suggest",
    step: 0,
    areas: [],
    complimentChips: [],
    roles: [],
    data: loadDraft() || blankData(),
  };

  function blankData() {
    return {
      areaId: "",
      friction: "",
      idea: "",
      impact: "",
      chips: [],
      note: "",
      rating: 0,
      role: "",
      strength: "",
      gap: "",
      name: "",
      email: "",
    };
  }

  function loadDraft() {
    try {
      const raw = localStorage.getItem(DRAFT_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (parsed && parsed._savedAt && Date.now() - Number(parsed._savedAt) > DRAFT_MAX_AGE_MS) {
        localStorage.removeItem(DRAFT_KEY);
        return null;
      }
      if (parsed && parsed.data) return parsed.data;
      return parsed;
    } catch {
      return null;
    }
  }

  function saveDraft() {
    try {
      /* Zero-trust: never persist email in localStorage (shared device / XSS blast radius). */
      var safe = Object.assign({}, state.data, { email: "" });
      localStorage.setItem(
        DRAFT_KEY,
        JSON.stringify({ _savedAt: Date.now(), data: safe })
      );
      try {
        localStorage.removeItem("tigergrci-community-draft-v1");
      } catch (_) {}
    } catch {
      /* ignore */
    }
  }

  function clearDraft() {
    localStorage.removeItem(DRAFT_KEY);
  }

  /* Nav */
  const toggle = document.querySelector(".nav-toggle");
  const menu = document.getElementById("nav-menu");
  if (toggle && menu) {
    toggle.addEventListener("click", () => {
      const open = menu.classList.toggle("is-open");
      toggle.setAttribute("aria-expanded", String(open));
    });
    menu.querySelectorAll("a").forEach((a) =>
      a.addEventListener("click", () => {
        menu.classList.remove("is-open");
        toggle.setAttribute("aria-expanded", "false");
      })
    );
  }

  const yearEl = document.getElementById("year");
  if (yearEl) yearEl.textContent = String(new Date().getFullYear());

  /* Social: LinkedIn profile, Facebook share */
  const SITE_PUBLIC_URL = "https://sujanchandray.github.io/tigergrci-site/";
  const SOCIAL = {
    linkedinProfile: "https://www.linkedin.com/in/sujan-c-ray",
    facebookProfile: "",
  };

  function siteShareUrl() {
    try {
      const canonical = document.querySelector('link[rel="canonical"]');
      if (canonical && canonical.href) return canonical.href.split("#")[0];
    } catch (_) {}
    return SITE_PUBLIC_URL;
  }

  function shareTargets(url) {
    const u = encodeURIComponent(url);
    const fbProfile = isAllowedHttpsUrl(SOCIAL.facebookProfile, SOCIAL_HOST_ALLOW)
      ? SOCIAL.facebookProfile
      : "";
    return {
      linkedin: "https://www.linkedin.com/sharing/share-offsite/?url=" + u,
      facebook: fbProfile || "https://www.facebook.com/sharer/sharer.php?u=" + u,
      linkedinProfile: isAllowedHttpsUrl(SOCIAL.linkedinProfile, SOCIAL_HOST_ALLOW)
        ? SOCIAL.linkedinProfile
        : "https://www.linkedin.com/in/sujan-c-ray",
    };
  }

  function setSocialStatus(msg) {
    const el = document.getElementById("social-status");
    if (el) el.textContent = msg || "";
  }

  async function copySiteUrl() {
    const url = siteShareUrl();
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(url);
        return true;
      }
    } catch (_) {}
    try {
      const ta = document.createElement("textarea");
      ta.value = url;
      ta.setAttribute("readonly", "");
      ta.style.position = "absolute";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      return ok;
    } catch (_) {
      return false;
    }
  }

  function wireSocialShare() {
    const url = siteShareUrl();
    const targets = shareTargets(url);
    document.querySelectorAll("[data-share]").forEach(function (el) {
      const kind = el.getAttribute("data-share");
      if (!kind) return;
      if (kind === "linkedin" && targets.linkedin) el.setAttribute("href", targets.linkedin);
      if (kind === "facebook" && targets.facebook) el.setAttribute("href", targets.facebook);
    });
    fetchTrustedJson("data/social.json", function (data) {
      return !!(data && data.profiles && typeof data.profiles === "object");
    })
      .then(function (data) {
        if (!data || !data.profiles) return;
        if (isAllowedHttpsUrl(data.profiles.linkedin, SOCIAL_HOST_ALLOW)) {
          SOCIAL.linkedinProfile = data.profiles.linkedin.trim();
        }
        if (isAllowedHttpsUrl(data.profiles.facebook, SOCIAL_HOST_ALLOW)) {
          SOCIAL.facebookProfile = data.profiles.facebook.trim();
        }
        const next = shareTargets(siteShareUrl());
        document.querySelectorAll('[data-share="facebook"]').forEach(function (el) {
          el.setAttribute("href", next.facebook);
        });
        document.querySelectorAll('[data-share="linkedin"]').forEach(function (el) {
          el.setAttribute("href", next.linkedin);
        });
      })
      .catch(function () {});
  }
  wireSocialShare();

  /* Operational workflow demo + clickable architecture strip */
  (function initWorkflowDemo() {
    const rail = document.getElementById("workflow-rail");
    const panel = document.getElementById("workflow-panel");
    const bar = document.getElementById("workflow-progress-bar");
    const prevBtn = document.getElementById("workflow-prev");
    const nextBtn = document.getElementById("workflow-next");
    const flow = document.getElementById("workflow-flow");
    const arch = document.getElementById("workflow-arch");
    const archTitle = document.getElementById("workflow-arch-title");
    const archLead = document.getElementById("workflow-arch-lead");
    const archCanvas = document.getElementById("workflow-arch-canvas");
    if (!rail || !panel || !prevBtn || !nextBtn) return;

    let index = 0;
    let archId = "collect";
    let archReady = false;
    let archSwitchTimer = 0;
    let archScrollTimer = 0;
    let archSwitchGen = 0;
    const ARCH_CACHE = "64";
    const ARCH_FADE_MS = 720;
    const archSlides = document.getElementById("wf-arch-slides");
    const archHead = arch ? arch.querySelector(".workflow-arch-head") : null;
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    function stageLabel(step) {
      return step.id === "monitor" ? "Monitor live" : step.short;
    }

    function softScrollToArch() {
      return new Promise((resolve) => {
        if (!arch || reduceMotion) {
          resolve(false);
          return;
        }
        const rect = arch.getBoundingClientRect();
        const vh = window.innerHeight || 1;
        const headerPad = 72;
        const topOk = rect.top >= headerPad - 8 && rect.top <= vh * 0.42;
        const bottomOk = rect.bottom > Math.min(vh * 0.55, headerPad + 220);
        if (topOk && bottomOk) {
          resolve(false);
          return;
        }
        const target = Math.max(0, window.scrollY + rect.top - Math.min(headerPad, vh * 0.1));
        const distance = Math.abs(window.scrollY - target);
        if (distance < 12) {
          resolve(false);
          return;
        }

        window.clearTimeout(archScrollTimer);
        let settled = false;
        function finish() {
          if (settled) return;
          settled = true;
          window.removeEventListener("scrollend", finish);
          window.removeEventListener("wheel", abortScroll, true);
          window.removeEventListener("touchstart", abortScroll, true);
          window.removeEventListener("keydown", abortScroll, true);
          window.clearTimeout(archScrollTimer);
          resolve(true);
        }
        function abortScroll() {
          /* Stop competing smooth-scroll so the page does not fight the user. */
          window.scrollTo({ top: window.scrollY, behavior: "auto" });
          finish();
        }

        window.addEventListener("scrollend", finish, { once: true });
        window.addEventListener("wheel", abortScroll, { passive: true, capture: true });
        window.addEventListener("touchstart", abortScroll, { passive: true, capture: true });
        window.addEventListener("keydown", abortScroll, { passive: true, capture: true });
        window.scrollTo({ top: target, behavior: "smooth" });
        const wait = Math.min(700, Math.max(240, distance * 0.45 + 140));
        archScrollTimer = window.setTimeout(finish, wait);
      });
    }

    function pauseSlideAnimations(slide, paused) {
      if (!slide) return;
      const svg = slide.querySelector("svg");
      if (!svg) return;
      try {
        if (paused && typeof svg.pauseAnimations === "function") svg.pauseAnimations();
        if (!paused && typeof svg.unpauseAnimations === "function") svg.unpauseAnimations();
      } catch (err) {
        /* older engines */
      }
    }

    function prepareSvg(svgText, title) {
      const cleaned = sanitizeSvgMarkup(svgText);
      const wrap = document.createElement("div");
      wrap.className = "wf-arch-slide";
      wrap.setAttribute("role", "img");
      wrap.setAttribute("aria-label", title);
      const parser = new DOMParser();
      const doc = parser.parseFromString(cleaned, "image/svg+xml");
      const parsedSvg = doc.documentElement;
      if (
        !parsedSvg ||
        parsedSvg.nodeName.toLowerCase() !== "svg" ||
        doc.querySelector("parsererror")
      ) {
        wrap.textContent = "Diagram unavailable.";
        return wrap;
      }
      Array.from(parsedSvg.querySelectorAll("*")).forEach(function (node) {
        Array.from(node.attributes).forEach(function (attr) {
          const name = attr.name.toLowerCase();
          const val = String(attr.value || "");
          if (name.indexOf("on") === 0) node.removeAttribute(attr.name);
          if (
            (name === "href" || name === "xlink:href") &&
            /^\s*javascript:/i.test(val)
          ) {
            node.removeAttribute(attr.name);
          }
        });
      });
      const imported = document.importNode(parsedSvg, true);
      imported.removeAttribute("width");
      imported.removeAttribute("height");
      imported.setAttribute("class", "wf-arch-svg");
      wrap.appendChild(imported);
      return wrap;
    }

    function setArchMeta(spec) {
      if (!spec) return;
      if (archTitle) archTitle.textContent = spec.title;
      if (archLead) archLead.textContent = spec.lead;
    }

    function activateArchSlide(stepId, opts) {
      const options = opts || {};
      const spec = WORKFLOW_ARCH[stepId];
      if (!arch || !spec) return;
      if (archId === stepId && archReady && !options.force) {
        if (options.scroll) softScrollToArch();
        return;
      }

      const gen = ++archSwitchGen;

      const apply = function () {
        if (gen !== archSwitchGen) return;
        archId = stepId;
        setArchMeta(spec);
        if (archHead) archHead.classList.remove("is-switching");
        if (archSlides) {
          archSlides.querySelectorAll(".wf-arch-slide").forEach((slide) => {
            const on = slide.getAttribute("data-id") === stepId;
            slide.classList.toggle("is-active", on);
            slide.setAttribute("aria-hidden", on ? "false" : "true");
            pauseSlideAnimations(slide, !on);
          });
        }
        if (flow) {
          flow.querySelectorAll(".workflow-flow-step").forEach((btn) => {
            const on = btn.getAttribute("data-id") === stepId;
            btn.classList.toggle("is-arch-open", on);
            btn.setAttribute("aria-expanded", on ? "true" : "false");
            btn.setAttribute("aria-selected", on ? "true" : "false");
          });
        }
      };

      const beginCrossfade = function () {
        if (gen !== archSwitchGen) return;
        if (reduceMotion || !archReady) {
          apply();
          return;
        }
        if (archHead) archHead.classList.add("is-switching");
        window.clearTimeout(archSwitchTimer);
        /* Swap at mid-fade so title and diagram land together after scroll settles. */
        archSwitchTimer = window.setTimeout(apply, Math.round(ARCH_FADE_MS * 0.42));
      };

      if (options.scroll && !reduceMotion) {
        softScrollToArch().then(beginCrossfade);
        return;
      }
      beginCrossfade();
    }

    function preloadArchSlides() {
      if (!archSlides) return Promise.resolve();
      archSlides.innerHTML =
        '<p class="wf-arch-missing">Loading architecture stages…</p>';
      const jobs = WORKFLOW_STEPS.map((step) => {
        const spec = WORKFLOW_ARCH[step.id];
        if (!spec || !spec.diagram) {
          return Promise.resolve({ id: step.id, node: null, title: step.short });
        }
        const src = spec.diagram + "?v=arch" + ARCH_CACHE;
        if (!isSameOriginRelative(spec.diagram)) {
          return Promise.resolve({ id: step.id, node: null, title: step.short });
        }
        return fetch(src, {
          cache: "force-cache",
          credentials: "same-origin",
          mode: "same-origin",
          redirect: "error",
        })
          .then((res) => {
            if (!res.ok) throw new Error("diagram fetch failed");
            return res.text();
          })
          .then((svg) => ({
            id: step.id,
            node: prepareSvg(svg, spec.title),
            title: spec.title,
          }))
          .catch(() => {
            const fallback = document.createElement("div");
            fallback.className = "wf-arch-slide";
            fallback.setAttribute("data-id", step.id);
            setHtml(
              fallback,
              '<img class="wf-arch-img" src="' +
                escapeHtml(src) +
                '" alt="' +
                escapeHtml(spec.title) +
                '" loading="lazy" decoding="async" />'
            );
            return { id: step.id, node: fallback, title: spec.title };
          });
      });
      return Promise.all(jobs).then((results) => {
        archSlides.innerHTML = "";
        results.forEach((item) => {
          if (!item.node) return;
          item.node.setAttribute("data-id", item.id);
          item.node.setAttribute("aria-hidden", "true");
          archSlides.appendChild(item.node);
        });
        archReady = true;
        activateArchSlide(archId || WORKFLOW_STEPS[0].id, { scroll: false, force: true });
      });
    }

    function showArch(stepId) {
      const step = WORKFLOW_STEPS.find((s) => s.id === stepId);
      const spec = WORKFLOW_ARCH[stepId];
      if (!arch || !spec || !step) return;
      arch.hidden = false;
      arch.setAttribute("aria-hidden", "false");
      activateArchSlide(stepId, { scroll: true });
    }

    function hideArch() {
      /* Keep the single-window stage viewer always visible. */
      activateArchSlide(WORKFLOW_STEPS[index].id, { scroll: false });
    }

    function renderFlow() {
      if (!flow) return;
      flow.innerHTML = WORKFLOW_STEPS.map((s, i) => {
        const open = s.id === archId;
        const activeDemo = i === index;
        return (
          '<button type="button" class="workflow-flow-step' +
          (open ? " is-arch-open" : "") +
          (activeDemo ? " is-demo-active" : "") +
          '" role="tab" data-id="' +
          escapeHtml(s.id) +
          '" data-index="' +
          i +
          '" aria-selected="' +
          open +
          '" aria-expanded="' +
          open +
          '">' +
          escapeHtml(stageLabel(s)) +
          "</button>" +
          (i < WORKFLOW_STEPS.length - 1
            ? '<span class="workflow-flow-arrow" aria-hidden="true"></span>'
            : "")
        );
      }).join("");
    }

    function render() {
      const step = WORKFLOW_STEPS[index];
      const total = WORKFLOW_STEPS.length;
      if (bar) bar.style.width = ((index + 1) / total) * 100 + "%";

      rail.innerHTML = WORKFLOW_STEPS.map((s, i) => {
        const active = i === index;
        return (
          '<li><button type="button" role="tab" class="wf-step' +
          (active ? " is-active" : "") +
          '" aria-selected="' +
          active +
          '" data-index="' +
          i +
          '"><span class="wf-num">' +
          (i + 1) +
          '</span><span><span class="wf-label">' +
          escapeHtml(s.short) +
          '</span><span class="wf-sub">' +
          escapeHtml(s.sub) +
          "</span></span></button></li>"
        );
      }).join("");

      const scene = step.scene
        ? '<aside class="workflow-scene" aria-hidden="true"><div class="wf-scene-chrome"><span></span><span></span><span></span><strong>' +
          escapeHtml(step.scene.title) +
          '</strong></div><ul class="wf-scene-rows">' +
          step.scene.rows
            .map(
              (r) =>
                '<li class="' +
                (r.tone || "") +
                '"><span>' +
                escapeHtml(r.k) +
                '</span><em>' +
                escapeHtml(r.v) +
                "</em></li>"
            )
            .join("") +
          "</ul></aside>"
        : "";

      panel.innerHTML =
        '<div class="workflow-panel-grid">' +
        '<div class="workflow-panel-copy"><p class="wf-kicker">Step ' +
        (index + 1) +
        " of " +
        total +
        "</p><h3>" +
        escapeHtml(step.title) +
        '</h3><p class="wf-lead">' +
        escapeHtml(step.lead) +
        '</p><ul class="workflow-checks">' +
        step.checks
          .map(
            (c) =>
              '<li><span class="wf-dot" aria-hidden="true"></span><span>' +
              escapeHtml(c) +
              "</span></li>"
          )
          .join("") +
        '</ul><div class="workflow-mock" aria-hidden="true">' +
        step.mocks
          .map(
            (m) =>
              '<div class="mock-card ' +
              (m.tone || "") +
              '"><strong>' +
              escapeHtml(m.label) +
              "</strong><span>" +
              escapeHtml(m.value) +
              "</span></div>"
          )
          .join("") +
        "</div></div>" +
        scene +
        "</div>";

      prevBtn.disabled = index === 0;
      nextBtn.textContent = index === total - 1 ? "Restart demo" : "Next step";
      renderFlow();
      if (archReady) {
        activateArchSlide(step.id, { scroll: false });
      } else {
        archId = step.id;
        setArchMeta(WORKFLOW_ARCH[step.id]);
      }
    }

    rail.addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-index]");
      if (!btn) return;
      index = Number(btn.getAttribute("data-index")) || 0;
      render();
    });

    if (flow) {
      flow.addEventListener("click", (e) => {
        const btn = e.target.closest("button.workflow-flow-step");
        if (!btn) return;
        const id = btn.getAttribute("data-id") || "";
        const i = Number(btn.getAttribute("data-index"));
        if (!Number.isNaN(i)) index = i;
        render();
        showArch(id);
      });
    }

    prevBtn.addEventListener("click", () => {
      if (index > 0) {
        index -= 1;
        render();
      }
    });

    nextBtn.addEventListener("click", () => {
      if (index >= WORKFLOW_STEPS.length - 1) {
        index = 0;
      } else {
        index += 1;
      }
      render();
    });

    render();
    preloadArchSlides();
  })();

  /* Departments */
  const deptRow = document.getElementById("dept-row");
  if (deptRow) {
    deptRow.innerHTML = DEPARTMENTS.map((d) => {
      return (
        '<div class="dept-card"><div class="ico" aria-hidden="true"><svg viewBox="0 0 24 24" fill="currentColor"><path d="' +
        d.path +
        '"/></svg></div><span>' +
        escapeHtml(d.name) +
        "</span></div>"
      );
    }).join("");
  }

  /* Capabilities */
  const filtersEl = document.getElementById("cap-filters");
  const panelsEl = document.getElementById("cap-panels");

  function renderCapabilities(activeId) {
    if (!filtersEl || !panelsEl) return;
    filtersEl.innerHTML = "";
    const allBtn = document.createElement("button");
    allBtn.type = "button";
    allBtn.className = "chip" + (!activeId ? " is-active" : "");
    allBtn.textContent = "All";
    allBtn.addEventListener("click", () => renderCapabilities(null));
    filtersEl.appendChild(allBtn);

    CAPABILITIES.forEach((c) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "chip" + (activeId === c.id ? " is-active" : "");
      b.textContent = c.filter || c.title;
      b.addEventListener("click", () => renderCapabilities(c.id));
      filtersEl.appendChild(b);
    });

    panelsEl.innerHTML = "";
    CAPABILITIES.filter((c) => !activeId || c.id === activeId).forEach((c, i) => {
      const details = document.createElement("details");
      details.className = "cap-panel";
      details.open = !activeId ? i < 2 : true;
      details.innerHTML =
        "<summary>" +
        escapeHtml(c.title) +
        '</summary><div class="cap-body"><ul>' +
        c.items.map((item) => "<li>" + escapeHtml(item) + "</li>").join("") +
        "</ul></div>";
      panelsEl.appendChild(details);
    });
  }

  renderCapabilities(null);

  /* Community wall */
  async function loadWall() {
    const host = document.getElementById("community-wall");
    if (!host) return;
    try {
      const posts = await fetchTrustedJson("data/community-wall.json", function (data) {
        return Array.isArray(data);
      });
      if (!Array.isArray(posts) || posts.length === 0) {
        setHtml(
          host,
          '<div class="wall-empty-grid">' +
            '<div class="ghost-card">No public posts yet. Be the first. Suggestions, compliments, and reviews appear here after founder review.</div>' +
            '<div class="ghost-card">Your voice here</div>' +
            '<div class="ghost-card">Your voice here</div>' +
            '<div class="ghost-card">Your voice here</div>' +
            "</div>"
        );
        return;
      }

      const featured = posts.find((p) => p && p.featured);
      const regular = posts.filter((p) => p && !p.featured);

      let html =
        '<div class="wall-grid">' +
        regular
          .map((p) => {
            const initial = escapeHtml((p.name || "?").trim().charAt(0).toUpperCase());
            const photoSrc = isSafeImageUrl(p.photo) ? p.photo.trim() : "";
            const photo = photoSrc
              ? '<img class="avatar" src="' + escapeHtml(photoSrc) + '" alt="" loading="lazy" decoding="async" />'
              : '<div class="avatar avatar-fallback" aria-hidden="true">' + initial + "</div>";
            const rating = clampInt(p.rating, 1, 5, 0);
            const stars =
              rating > 0
                ? '<div class="stars" aria-label="' + rating + ' stars">' + "★".repeat(rating) + "</div>"
                : "";
            return (
              '<article class="wall-card">' +
              photo +
              '<p class="who">' +
              escapeHtml(String(p.name || "Community member").slice(0, 80)) +
              "</p>" +
              (p.role ? '<p class="role">' + escapeHtml(String(p.role).slice(0, 80)) + "</p>" : "") +
              stars +
              '<p class="body">' +
              escapeHtml(String(p.body || "").slice(0, 2000)) +
              "</p></article>"
            );
          })
          .join("") +
        "</div>";

      if (featured) {
        const featPhoto = isSafeImageUrl(featured.photo) ? featured.photo.trim() : "";
        const photo = featPhoto
          ? '<img src="' + escapeHtml(featPhoto) + '" alt="" loading="lazy" decoding="async" />'
          : "";
        html +=
          '<aside class="wall-featured">' +
          photo +
          "<div><h3>" +
          escapeHtml(String(featured.headline || featured.body || "").slice(0, 200)) +
          "</h3><p>" +
          escapeHtml(String(featured.body || "").slice(0, 2000)) +
          "</p><p class=\"who\">" +
          escapeHtml(String(featured.name || "").slice(0, 80)) +
          (featured.role ? " · " + escapeHtml(String(featured.role).slice(0, 80)) : "") +
          "</p></div></aside>";
      }

      setHtml(host, html);
    } catch {
      setHtml(
        host,
        '<div class="ghost-card" style="min-height:100px">Community wall will appear here once posts are published.</div>'
      );
    }
  }

  loadWall();

  /* CTA band -> Community */
  const ctaForm = document.getElementById("cta-form");
  if (ctaForm) {
    ctaForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const name = document.getElementById("cta-name");
      const email = document.getElementById("cta-email");
      if (name && name.value) state.data.name = name.value.trim();
      if (email && email.value) state.data.email = email.value.trim();
      saveDraft();
      const target = document.getElementById("community");
      if (target) target.scrollIntoView({ behavior: "smooth" });
      renderStep();
      setStatus("Name saved for this session. Pick Suggest, Compliment, or Review to continue.", "ok");
    });
  }

  /* Wizard */
  async function loadAreas() {
    try {
      const json = await fetchTrustedJson("data/community-areas.json", function (data) {
        return !!(data && typeof data === "object");
      });
      state.areas = Array.isArray(json.areas) ? json.areas : [];
      state.complimentChips = Array.isArray(json.complimentChips) ? json.complimentChips : [];
      state.roles = Array.isArray(json.roles) ? json.roles : [];
    } catch {
      state.areas = [{ id: "other", label: "Something else", hint: "" }];
      state.complimentChips = [];
      state.roles = ["Other"];
    }
  }

  const stepRoot = document.getElementById("wizard-step");
  const prog = document.getElementById("wizard-progress");
  const btnBack = document.getElementById("wizard-back");
  const btnNext = document.getElementById("wizard-next");
  const statusEl = document.getElementById("wizard-status");

  function stepsForMode() {
    if (state.mode === "suggest") return ["area", "friction", "idea", "impact", "identity", "summary"];
    if (state.mode === "compliment") return ["chips", "note", "identity", "summary"];
    return ["rating", "role", "strength", "gap", "identity", "summary"];
  }

  function setStatus(msg, kind) {
    if (!statusEl) return;
    statusEl.textContent = msg || "";
    statusEl.className = "status" + (kind ? " " + kind : "");
  }

  function renderProgress() {
    if (!prog) return;
    const steps = stepsForMode();
    prog.innerHTML = steps.map((_, i) => '<i class="' + (i <= state.step ? "done" : "") + '"></i>').join("");
  }

  function areaHint() {
    const a = state.areas.find((x) => x.id === state.data.areaId);
    return a ? a.hint : "";
  }

  function renderStep() {
    if (!stepRoot) return;
    const steps = stepsForMode();
    const key = steps[state.step];
    renderProgress();
    if (btnBack) btnBack.hidden = state.step === 0;
    if (btnNext) btnNext.textContent = key === "summary" ? "Submit to Community" : "Next";

    let html = "";

    if (key === "area") {
      html =
        '<div class="field"><label>Where should TigerGRCi improve?</label><p class="hint">' +
        escapeHtml(areaHint() || "Pick the outcome that matters most.") +
        '</p><div class="chip-grid" id="area-chips">' +
        state.areas
          .map(
            (a) =>
              '<button type="button" class="chip' +
              (state.data.areaId === a.id ? " is-picked" : "") +
              '" data-area="' +
              escapeHtml(a.id) +
              '">' +
              escapeHtml(a.label) +
              "</button>"
          )
          .join("") +
        "</div></div>";
    }

    if (key === "friction") {
      html =
        '<div class="field"><label for="friction">What friction do teams feel today?</label><span class="hint">' +
        escapeHtml(areaHint()) +
        '</span><textarea id="friction">' +
        escapeHtml(state.data.friction) +
        "</textarea></div>";
    }

    if (key === "idea") {
      html =
        '<div class="field"><label for="idea">Your suggestion</label><span class="hint">Describe the better outcome.</span><textarea id="idea">' +
        escapeHtml(state.data.idea) +
        "</textarea></div>";
    }

    if (key === "impact") {
      html =
        '<div class="field"><label for="impact">Who benefits if this lands?</label><textarea id="impact">' +
        escapeHtml(state.data.impact) +
        "</textarea></div>";
    }

    if (key === "chips") {
      html =
        '<div class="field"><label>What already helps?</label><div class="chip-grid" id="comp-chips">' +
        state.complimentChips
          .map(
            (c) =>
              '<button type="button" class="chip' +
              (state.data.chips.includes(c) ? " is-picked" : "") +
              '" data-chip="' +
              escapeHtml(c) +
              '">' +
              escapeHtml(c) +
              "</button>"
          )
          .join("") +
        "</div></div>";
    }

    if (key === "note") {
      html =
        '<div class="field"><label for="note">Add a short compliment</label><textarea id="note">' +
        escapeHtml(state.data.note) +
        "</textarea></div>";
    }

    if (key === "rating") {
      html =
        '<div class="field"><label>Product rating</label><div class="stars-pick" id="stars">' +
        [1, 2, 3, 4, 5]
          .map(
            (n) =>
              '<button type="button" data-star="' +
              n +
              '" class="' +
              (state.data.rating >= n ? "on" : "") +
              '" aria-label="' +
              n +
              ' stars">★</button>'
          )
          .join("") +
        "</div></div>";
    }

    if (key === "role") {
      html =
        '<div class="field"><label for="role">Your role</label><select id="role"><option value="">Select…</option>' +
        state.roles
          .map(
            (r) =>
              '<option value="' +
              escapeHtml(r) +
              '"' +
              (state.data.role === r ? " selected" : "") +
              ">" +
              escapeHtml(r) +
              "</option>"
          )
          .join("") +
        "</select></div>";
    }

    if (key === "strength") {
      html =
        '<div class="field"><label for="strength">One strength</label><textarea id="strength">' +
        escapeHtml(state.data.strength) +
        "</textarea></div>";
    }

    if (key === "gap") {
      html =
        '<div class="field"><label for="gap">One gap or wish</label><textarea id="gap">' +
        escapeHtml(state.data.gap) +
        "</textarea></div>";
    }

    if (key === "identity") {
      html =
        '<div class="hp-wrap" aria-hidden="true">' +
        '<label for="company_url">Company website</label>' +
        '<input id="company_url" name="_gotcha" type="text" tabindex="-1" autocomplete="off" class="hp-field" value="" />' +
        "</div>" +
        '<div class="field"><label for="name">Display name (optional)</label><input id="name" autocomplete="name" maxlength="120" value="' +
        escapeHtml(state.data.name) +
        '" /></div><div class="field"><label for="email">Email (optional)</label><input id="email" type="email" autocomplete="email" maxlength="254" value="' +
        escapeHtml(state.data.email) +
        '" /></div>';
    }

    if (key === "summary") {
      html =
        '<p><strong>Here is your Community contribution</strong></p><div class="summary-card" id="summary-card"></div><p class="hint">Use Back to edit, then submit.</p>';
    }

    setHtml(stepRoot, html);

    if (key === "area") {
      stepRoot.querySelectorAll("[data-area]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.data.areaId = btn.getAttribute("data-area") || "";
          saveDraft();
          renderStep();
        });
      });
    }

    if (key === "chips") {
      stepRoot.querySelectorAll("[data-chip]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const c = btn.getAttribute("data-chip") || "";
          const set = new Set(state.data.chips);
          if (set.has(c)) set.delete(c);
          else set.add(c);
          state.data.chips = Array.from(set);
          saveDraft();
          renderStep();
        });
      });
    }

    if (key === "rating") {
      stepRoot.querySelectorAll("[data-star]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.data.rating = Number(btn.getAttribute("data-star") || 0);
          saveDraft();
          renderStep();
        });
      });
    }

    if (key === "summary") {
      const card = document.getElementById("summary-card");
      if (card) card.textContent = buildSummaryText();
    }

    bindFieldSync();
  }

  function bindFieldSync() {
    [
      ["friction", "friction"],
      ["idea", "idea"],
      ["impact", "impact"],
      ["note", "note"],
      ["role", "role"],
      ["strength", "strength"],
      ["gap", "gap"],
      ["name", "name"],
      ["email", "email"],
    ].forEach(([id, key]) => {
      const el = document.getElementById(id);
      if (!el) return;
      const sync = () => {
        state.data[key] = el.value;
        saveDraft();
      };
      el.addEventListener("input", sync);
      el.addEventListener("change", sync);
    });
  }

  function buildSummaryText() {
    const d = state.data;
    const area = state.areas.find((a) => a.id === d.areaId);
    if (state.mode === "suggest") {
      return [
        "Type: Suggestion",
        "Area: " + (area ? area.label : "(not set)"),
        "Friction: " + (d.friction || "-"),
        "Idea: " + (d.idea || "-"),
        "Impact: " + (d.impact || "-"),
        "From: " + (d.name || "Anonymous") + (d.email ? " <" + d.email + ">" : ""),
      ].join("\n");
    }
    if (state.mode === "compliment") {
      return [
        "Type: Compliment",
        "Highlights: " + (d.chips.length ? d.chips.join("; ") : "-"),
        "Note: " + (d.note || "-"),
        "From: " + (d.name || "Anonymous") + (d.email ? " <" + d.email + ">" : ""),
      ].join("\n");
    }
    return [
      "Type: Product review",
      "Rating: " + (d.rating ? d.rating + " / 5" : "-"),
      "Role: " + (d.role || "-"),
      "Strength: " + (d.strength || "-"),
      "Gap: " + (d.gap || "-"),
      "From: " + (d.name || "Anonymous") + (d.email ? " <" + d.email + ">" : ""),
    ].join("\n");
  }

  function validateCurrent() {
    const key = stepsForMode()[state.step];
    if (key === "area" && !state.data.areaId) return "Pick an outcome area.";
    if (key === "friction" && !state.data.friction.trim()) return "Describe the friction.";
    if (key === "idea" && !state.data.idea.trim()) return "Add your suggestion.";
    if (key === "impact" && !state.data.impact.trim()) return "Say who benefits.";
    if (key === "chips" && state.data.chips.length === 0) return "Pick at least one highlight.";
    if (key === "note" && state.data.chips.length === 0 && !state.data.note.trim())
      return "Add a short compliment or go back and pick a highlight.";
    if (key === "rating" && !state.data.rating) return "Choose a star rating.";
    if (key === "role" && !state.data.role) return "Select your role.";
    if (key === "strength" && !state.data.strength.trim()) return "Share one strength.";
    if (key === "gap" && !state.data.gap.trim()) return "Share one gap or wish.";
    return "";
  }

  async function submitContribution() {
    const hp = document.getElementById("company_url");
    if (hp && String(hp.value || "").trim()) {
      setStatus("Thank you. Your contribution reached the TigerGRCi Community inbox.", "ok");
      clearDraft();
      return;
    }
    if (!canSubmitNow()) {
      setStatus("Please wait a few seconds before sending again.", "err");
      return;
    }
    if (!assertFormspreeEndpoint(FORMSPREE_ENDPOINT)) {
      setStatus("Form endpoint is misconfigured.", "err");
      return;
    }

    const payload = {
      _subject: "TigerGRCi Community - " + state.mode,
      type: state.mode,
      summary: buildSummaryText(),
      ...state.data,
      chips: state.data.chips.join("; "),
      _gotcha: "",
    };

    setStatus("Sending…");

    if (!FORMSPREE_ENDPOINT) {
      setStatus(
        "Saved locally. Set FORMSPREE_ENDPOINT in main.js to deliver messages to the founder inbox.",
        "err"
      );
      saveDraft();
      return;
    }

    try {
      const res = await fetch(FORMSPREE_ENDPOINT, {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        mode: "cors",
        credentials: "omit",
        referrerPolicy: "strict-origin-when-cross-origin",
      });
      if (!res.ok) throw new Error("submit failed");
      clearDraft();
      state.data = blankData();
      state.step = 0;
      setStatus(
        "Thank you. Your contribution reached the TigerGRCi Community inbox. Public wall posts appear after moderation.",
        "ok"
      );
      renderStep();
    } catch {
      setStatus("Could not send right now. Your draft is saved in this browser. Try again shortly.", "err");
    }
  }

  if (btnBack) {
    btnBack.addEventListener("click", () => {
      if (state.step > 0) {
        state.step -= 1;
        setStatus("");
        renderStep();
      }
    });
  }

  if (btnNext) {
    btnNext.addEventListener("click", async () => {
      const steps = stepsForMode();
      const key = steps[state.step];
      if (key !== "summary") {
        const err = validateCurrent();
        if (err) {
          setStatus(err, "err");
          return;
        }
        setStatus("");
        state.step += 1;
        renderStep();
        return;
      }
      await submitContribution();
    });
  }

  document.querySelectorAll(".mode-tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".mode-tab").forEach((t) => {
        t.classList.remove("is-active");
        t.setAttribute("aria-selected", "false");
      });
      tab.classList.add("is-active");
      tab.setAttribute("aria-selected", "true");
      state.mode = tab.getAttribute("data-mode") || "suggest";
      state.step = 0;
      setStatus("");
      renderStep();
    });
  });

  loadAreas().then(() => renderStep());

  /* Clockwise mindmap ring - L1 topics + interactive branch tree */
  (function initHeroMindmap() {
    const host = document.getElementById("mm-orbit");
    const hero = document.querySelector(".hero");
    const heroCopy = hero && hero.querySelector(".hero-copy");
    const treePanel = document.getElementById("mm-tree-panel");
    const treeRail = document.getElementById("mm-tree-rail");
    const detailPanel = document.getElementById("mm-tree-detail");
    const detailTitle = document.getElementById("mm-tree-detail-title");
    const detailNeed = document.getElementById("mm-tree-detail-need");
    const detailBenefit = document.getElementById("mm-tree-detail-benefit");
    const detailSolves = document.getElementById("mm-tree-detail-solves");
    if (!host || !hero || !treePanel || !treeRail || !detailPanel) return;

    const topics = [
      { id: "product", label: "Product & value", tone: "g" },
      { id: "enterprise", label: "Enterprise hierarchy", tone: "g" },
      { id: "stack", label: "Stack & deployment", tone: "p" },
      { id: "fabrics", label: "Four GRC fabrics", tone: "g" },
      { id: "policyai", label: "Policy AI & mapping", tone: "c" },
      { id: "ccf", label: "Continuous & evidence", tone: "c" },
      { id: "riskvapt", label: "Risk & VAPT", tone: "r" },
      { id: "sectrust", label: "Security & Trust", tone: "s" },
      { id: "workflows", label: "Master workflows", tone: "g" },
      { id: "gui", label: "GUI & journeys", tone: "p" },
      { id: "catalog", label: "Catalog & frameworks", tone: "c" },
      { id: "ops", label: "Ops, eval & docs", tone: "p" },
      { id: "scoring", label: "Scoring architecture", tone: "r" },
    ];

    const TREE_URL = "assets/tigergrci-mindmap-tree.json";
    let openTopicId = "";
    let openScrollY = 0;
    let activeTone = "g";
    /** @type {Record<string, any>} */
    let nodeIndex = Object.create(null);
    /** @type {any[]|null} */
    let treeKids = null;
    let treeReady = false;

    function cleanLabel(label) {
      return String(label || "").replace(/^\d+\.\s*/, "").trim();
    }

    function norm(label) {
      return cleanLabel(label).toLowerCase();
    }

    function indexTree(nodes, map) {
      (nodes || []).forEach((node) => {
        if (!node || !node.id) return;
        map[node.id] = node;
        if (node.kids && node.kids.length) indexTree(node.kids, map);
      });
    }

    function adoptTree(data) {
      const kids = data && Array.isArray(data.kids) ? data.kids : null;
      if (!kids || !kids.length) return false;
      treeKids = kids;
      nodeIndex = Object.create(null);
      indexTree(treeKids, nodeIndex);
      treeReady = true;
      return true;
    }

    function findL1(topic) {
      if (!treeKids) return null;
      return (
        treeKids.find((n) => n.id === topic.id) ||
        treeKids.find((n) => norm(n.label) === norm(topic.label)) ||
        null
      );
    }

    const step = 360 / topics.length;
    setHtml(
      host,
      topics
        .map((topic, i) => {
          const a = (i * step).toFixed(3);
          const id = escapeHtml(topic.id);
          const label = escapeHtml(topic.label);
          const tone = escapeHtml(topic.tone);
          return (
            '<span class="mm-topic mm-tone-' +
            tone +
            '" style="--a: ' +
            a +
            'deg" data-topic-id="' +
            id +
            '" data-topic="' +
            label +
            '">' +
            '<span class="mm-topic-tick" aria-hidden="true"></span>' +
            '<button type="button" class="mm-topic-label" title="' +
            label +
            '" aria-expanded="false">' +
            label +
            "</button></span>"
          );
        })
        .join("")
    );

    /* Prefer inlined script data (works on file:// and static hosts); fetch is fallback. */
    if (!adoptTree(window.TIGERGRCI_MINDMAP_TREE)) {
      fetchTrustedJson(TREE_URL, function (data) {
        return !!(data && typeof data === "object");
      })
        .then((data) => {
          adoptTree(data);
          if (hero.classList.contains("is-mm-open") && openTopicId) {
            const topic = topics.find((t) => t.id === openTopicId);
            if (topic) {
              const node = findL1(topic);
              treeRail.innerHTML = "";
              if (node) renderColumn(node, 0, cleanLabel(node.label));
            }
          }
        })
        .catch(() => {
          treeReady = false;
        });
    }

    function setActiveTopic(topicId) {
      host.querySelectorAll(".mm-topic").forEach((el) => {
        const on = el.getAttribute("data-topic-id") === topicId;
        el.classList.toggle("is-active", on);
        const btn = el.querySelector(".mm-topic-label");
        if (btn) btn.setAttribute("aria-expanded", on ? "true" : "false");
      });
    }

    function hideDetail() {
      detailPanel.hidden = true;
      detailPanel.setAttribute("aria-hidden", "true");
      detailPanel.removeAttribute("data-node-id");
    }

    function humanizeCopy(text) {
      return publicSafeText(
        String(text || "")
          .replace(/\u2014/g, ",")
          .replace(/\s*,\s*/g, ", ")
          .replace(/,\s+and\b/g, ", and")
          .replace(/\s{2,}/g, " ")
          .replace(/\s+([,.!?])/g, "$1")
          .trim()
      );
    }

    function buildLeafBrief(node, parent) {
      const title = cleanLabel(node.label);
      const parentLabel = parent ? cleanLabel(parent.label) : "this GRC area";
      const parentSummary = humanizeCopy((parent && parent.summary) || "");
      const ownSummary = humanizeCopy(node.summary || "");

      const need = humanizeCopy(
        "Operators still patch “" +
          title +
          "” with folders, chats, and one-off spreadsheets. Under " +
          parentLabel +
          ", that leaves ownership unclear and proof hard to replay when auditors or regulators ask."
      );

      const benefit = humanizeCopy(
        ownSummary
          ? ownSummary
          : parentSummary
            ? parentSummary.replace(/\.\s*$/, "") +
              ". “" +
              title +
              "” is the concrete control point that makes that promise real day to day."
            : "“" +
              title +
              "” gives teams a single, reviewable place to act, so intent, evidence, and decisions stay linked instead of drifting."
      );

      const solves = humanizeCopy(
        "It solves the live gap where " +
          parentLabel +
          " work stalls: unclear duties, weak trail, and late scramble. TigerGRCi keeps “" +
          title +
          "” in the current operating path, useful now and defensible later."
      );

      return { title: title, need: need, benefit: benefit, solves: solves };
    }

    function showDetail(node, parent) {
      const brief = buildLeafBrief(node, parent);
      detailTitle.textContent = brief.title;
      detailNeed.textContent = brief.need;
      detailBenefit.textContent = brief.benefit;
      detailSolves.textContent = brief.solves;
      detailPanel.hidden = false;
      detailPanel.setAttribute("aria-hidden", "false");
      detailPanel.setAttribute("data-node-id", node.id || "");
      requestAnimationFrame(() => {
        detailPanel.scrollIntoView({ behavior: "smooth", inline: "nearest", block: "nearest" });
      });
    }

    function trimColumnsAfter(depth) {
      Array.from(treeRail.querySelectorAll(".mm-tree-col")).forEach((col) => {
        const d = Number(col.getAttribute("data-depth") || "0");
        if (d > depth) col.remove();
      });
      drawWires();
    }

    function ensureWireLayer() {
      let svg = treeRail.querySelector(".mm-tree-wires");
      if (svg) return svg;
      svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.setAttribute("class", "mm-tree-wires");
      svg.setAttribute("aria-hidden", "true");
      const defs = document.createElementNS("http://www.w3.org/2000/svg", "defs");
      defs.innerHTML =
        `<marker id="mm-wire-arrow" viewBox="0 0 10 10" refX="8" refY="5" ` +
        `markerWidth="6" markerHeight="6" orient="auto-start-reverse">` +
        `<path d="M 0 0 L 10 5 L 0 10 z" fill="rgba(37,99,235,0.85)"></path>` +
        `</marker>`;
      svg.appendChild(defs);
      treeRail.insertBefore(svg, treeRail.firstChild);
      return svg;
    }

    function nodeBox(el) {
      const railBox = treeRail.getBoundingClientRect();
      const box = el.getBoundingClientRect();
      return {
        left: box.left - railBox.left + treeRail.scrollLeft,
        top: box.top - railBox.top + treeRail.scrollTop,
        width: box.width,
        height: box.height,
        midY: box.top - railBox.top + treeRail.scrollTop + box.height / 2,
        right: box.left - railBox.left + treeRail.scrollLeft + box.width,
        leftX: box.left - railBox.left + treeRail.scrollLeft,
      };
    }

    function drawWires() {
      const svg = ensureWireLayer();
      while (svg.childNodes.length > 1) svg.removeChild(svg.lastChild);

      const w = Math.max(treeRail.scrollWidth, treeRail.clientWidth, 1);
      const h = Math.max(treeRail.scrollHeight, treeRail.clientHeight, 1);
      svg.setAttribute("width", String(w));
      svg.setAttribute("height", String(h));
      svg.setAttribute("viewBox", "0 0 " + w + " " + h);
      svg.style.width = w + "px";
      svg.style.height = h + "px";

      const cols = Array.from(treeRail.querySelectorAll(".mm-tree-col"));
      cols.forEach((col) => {
        const depth = Number(col.getAttribute("data-depth") || "0");
        if (depth < 1) return;
        const parentId = col.getAttribute("data-parent-id");
        if (!parentId) return;
        const parentBtn = treeRail.querySelector(
          '.mm-tree-col[data-depth="' +
            (depth - 1) +
            '"] .mm-tree-node[data-node-id="' +
            CSS.escape(parentId) +
            '"]'
        );
        if (!parentBtn) return;
        const from = nodeBox(parentBtn);
        const children = col.querySelectorAll(".mm-tree-node");
        if (!children.length) return;

        const junction = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        junction.setAttribute("class", "mm-wire-dot");
        junction.setAttribute("cx", String(from.right + 3));
        junction.setAttribute("cy", String(from.midY));
        junction.setAttribute("r", "4");
        svg.appendChild(junction);

        children.forEach((child) => {
          const to = nodeBox(child);
          const x1 = from.right + 3;
          const y1 = from.midY;
          const x2 = Math.max(to.leftX - 4, x1 + 12);
          const y2 = to.midY;
          const dx = Math.max(48, (x2 - x1) * 0.5);

          const inbound = document.createElementNS("http://www.w3.org/2000/svg", "circle");
          inbound.setAttribute("class", "mm-wire-dot");
          inbound.setAttribute("cx", String(x2));
          inbound.setAttribute("cy", String(y2));
          inbound.setAttribute("r", "3.25");
          svg.appendChild(inbound);

          const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
          path.setAttribute(
            "d",
            "M " +
              x1 +
              " " +
              y1 +
              " C " +
              (x1 + dx) +
              " " +
              y1 +
              ", " +
              (x2 - dx) +
              " " +
              y2 +
              ", " +
              x2 +
              " " +
              y2
          );
          path.setAttribute("marker-end", "url(#mm-wire-arrow)");
          svg.appendChild(path);
        });
      });
    }

    function scheduleDrawWires() {
      window.clearTimeout(scheduleDrawWires._t);
      scheduleDrawWires._t = window.setTimeout(() => {
        requestAnimationFrame(() => {
          drawWires();
          requestAnimationFrame(drawWires);
        });
      }, 40);
    }

    function renderColumn(parentNode, depth, title) {
      trimColumnsAfter(depth - 1);
      const kids = (parentNode && parentNode.kids) || [];
      const col = document.createElement("div");
      col.className = "mm-tree-col";
      col.setAttribute("data-depth", String(depth));
      col.setAttribute("role", "group");
      if (parentNode && parentNode.id && depth > 0) {
        col.setAttribute("data-parent-id", parentNode.id);
      }

      const heading = document.createElement("p");
      heading.className = "mm-tree-col-title";
      heading.textContent = title || cleanLabel(parentNode && parentNode.label) || "Branch";
      col.appendChild(heading);

      if (!kids.length) {
        const empty = document.createElement("p");
        empty.className = "mm-tree-empty";
        empty.textContent = publicSafeText(
          (parentNode && parentNode.summary) || "No further branches."
        );
        col.appendChild(empty);
        treeRail.appendChild(col);
        col.scrollIntoView({ behavior: "smooth", inline: "nearest", block: "nearest" });
        scheduleDrawWires();
        return;
      }

      const list = document.createElement("ul");
      list.className = "mm-tree-list";
      list.setAttribute("role", "group");

      kids.forEach((child) => {
        const li = document.createElement("li");
        li.setAttribute("role", "none");
        const hasKids = !!(child.kids && child.kids.length);
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className =
          "mm-tree-node mm-tone-" +
          activeTone +
          (hasKids ? "" : " is-leaf");
        btn.setAttribute("role", "treeitem");
        btn.setAttribute("aria-expanded", "false");
        btn.setAttribute("data-node-id", child.id);
        btn.setAttribute("data-depth", String(depth));
        if (parentNode && parentNode.id) {
          btn.setAttribute("data-parent-id", parentNode.id);
        }
        btn.title = publicSafeText(child.summary || cleanLabel(child.label));
        const labelSpan = document.createElement("span");
        labelSpan.textContent = publicSafeText(cleanLabel(child.label));
        btn.appendChild(labelSpan);
        if (hasKids) {
          const chev = document.createElement("span");
          chev.className = "mm-tree-chev";
          chev.setAttribute("aria-hidden", "true");
          chev.textContent = "›";
          btn.appendChild(chev);
        }
        li.appendChild(btn);
        list.appendChild(li);
      });

      col.appendChild(list);
      treeRail.appendChild(col);
      requestAnimationFrame(() => {
        col.scrollIntoView({ behavior: "smooth", inline: "nearest", block: "nearest" });
        scheduleDrawWires();
      });
    }

    function closeTree() {
      if (!hero.classList.contains("is-mm-open")) return;
      openTopicId = "";
      activeTone = "g";
      hero.classList.remove("is-mm-open");
      if (heroCopy) heroCopy.removeAttribute("aria-hidden");
      setActiveTopic("");
      treeRail.innerHTML = "";
      hideDetail();
      window.setTimeout(() => {
        if (hero.classList.contains("is-mm-open")) return;
        treePanel.hidden = true;
        treePanel.setAttribute("aria-hidden", "true");
      }, 560);
    }

    function openTree(topic) {
      if (!topic) return;
      const l1 = treeReady ? findL1(topic) : null;
      openTopicId = topic.id;
      activeTone = topic.tone;
      openScrollY = window.scrollY || window.pageYOffset || 0;
      setActiveTopic(topic.id);
      treePanel.hidden = false;
      treePanel.setAttribute("aria-hidden", "false");
      if (heroCopy) heroCopy.setAttribute("aria-hidden", "true");
      treeRail.innerHTML = "";
      hideDetail();
      void treePanel.offsetWidth;
      hero.classList.add("is-mm-open");

      if (!l1) {
        const empty = document.createElement("p");
        empty.className = "mm-tree-empty";
        empty.textContent = treeReady
          ? "Branch data unavailable for this topic."
          : "Loading mind map branches…";
        treeRail.appendChild(empty);
        if (!treeReady) {
          let tries = 0;
          const wait = window.setInterval(() => {
            if (!hero.classList.contains("is-mm-open") || openTopicId !== topic.id) {
              window.clearInterval(wait);
              return;
            }
            if (!treeReady && window.TIGERGRCI_MINDMAP_TREE) {
              adoptTree(window.TIGERGRCI_MINDMAP_TREE);
            }
            tries += 1;
            if (!treeReady) {
              if (tries >= 40) {
                window.clearInterval(wait);
                empty.textContent = "Could not load mind map branches.";
              }
              return;
            }
            window.clearInterval(wait);
            const node = findL1(topic);
            treeRail.innerHTML = "";
            if (node) renderColumn(node, 0, cleanLabel(node.label));
            else {
              const miss = document.createElement("p");
              miss.className = "mm-tree-empty";
              miss.textContent = "Branch data unavailable for this topic.";
              treeRail.appendChild(miss);
            }
          }, 120);
        }
      } else {
        renderColumn(l1, 0, cleanLabel(l1.label));
      }
    }

    host.addEventListener("click", (event) => {
      const btn = event.target.closest(".mm-topic-label");
      if (!btn || !host.contains(btn)) return;
      const topicEl = btn.closest(".mm-topic");
      const topicId = topicEl && topicEl.getAttribute("data-topic-id");
      const topic = topics.find((t) => t.id === topicId);
      if (!topic) return;
      if (hero.classList.contains("is-mm-open") && openTopicId === topic.id) {
        closeTree();
        return;
      }
      openTree(topic);
    });

    treeRail.addEventListener("click", (event) => {
      const btn = event.target.closest(".mm-tree-node");
      if (!btn || !treeRail.contains(btn)) return;
      const nodeId = btn.getAttribute("data-node-id");
      const depth = Number(btn.getAttribute("data-depth") || "0");
      const parentId = btn.getAttribute("data-parent-id");
      const node = nodeId ? nodeIndex[nodeId] : null;
      if (!node) return;
      const parent = parentId ? nodeIndex[parentId] : null;

      const col = btn.closest(".mm-tree-col");
      if (col) {
        col.querySelectorAll(".mm-tree-node").forEach((el) => {
          el.classList.toggle("is-active", el === btn);
          el.setAttribute(
            "aria-expanded",
            el === btn && node.kids && node.kids.length ? "true" : "false"
          );
        });
      }

      openScrollY = window.scrollY || window.pageYOffset || 0;

      if (node.kids && node.kids.length) {
        hideDetail();
        renderColumn(node, depth + 1, cleanLabel(node.label));
        return;
      }

      trimColumnsAfter(depth);
      if (detailPanel.getAttribute("data-node-id") === node.id && !detailPanel.hidden) {
        hideDetail();
        return;
      }
      showDetail(node, parent);
    });

    document.addEventListener("keydown", (event) => {
      if (event.key !== "Escape") return;
      if (!detailPanel.hidden) {
        hideDetail();
        return;
      }
      closeTree();
    });

    window.addEventListener("resize", scheduleDrawWires);
    if (typeof ResizeObserver !== "undefined") {
      const ro = new ResizeObserver(scheduleDrawWires);
      ro.observe(treeRail);
    }

    window.addEventListener(
      "scroll",
      () => {
        if (!hero.classList.contains("is-mm-open")) return;
        const y = window.scrollY || window.pageYOffset || 0;
        if (Math.abs(y - openScrollY) < 64) return;
        closeTree();
      },
      { passive: true }
    );
  })();

  /* Scroll reveals - fade/slide up as sections enter the viewport */
  (function initScrollReveals() {
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const nodes = document.querySelectorAll(
      [
        "main section .section-label",
        "main section h2",
        "main section .section-intro",
        ".problem-card",
        ".solve-stance",
        ".solve-band",
        ".story-banner",
        ".enterprise-hub",
        ".feature-row",
        ".feature-row-flip",
        ".workflow-shell",
        ".why-band",
        ".cap-toolbar",
        ".cap-panels",
        ".story-copy",
        ".story-portrait-slot",
        ".wall-host",
        ".wizard",
        ".platform-band",
      ].join(", ")
    );
    if (!nodes.length) return;

    nodes.forEach((el, i) => {
      el.classList.add("reveal");
      if (el.classList.contains("feature-row-flip") || el.classList.contains("story-portrait-slot")) {
        el.classList.add("reveal-right");
      } else if (el.classList.contains("feature-row") || el.classList.contains("story-copy")) {
        el.classList.add("reveal-left");
      }
      const delay = Math.min((i % 4) * 70, 210);
      el.style.setProperty("--reveal-delay", `${delay}ms`);
    });

    if (reduce) {
      nodes.forEach((el) => el.classList.add("is-in"));
      return;
    }

    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          entry.target.classList.add("is-in");
          io.unobserve(entry.target);
        });
      },
      { threshold: 0.08, rootMargin: "0px 0px -6% 0px" }
    );
    nodes.forEach((el) => io.observe(el));
  })();

  /* Pause heavy motion while off-screen so page scroll stays smooth */
  (function initMotionBudget() {
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce || typeof IntersectionObserver === "undefined") return;

    const hero = document.querySelector(".hero");
    if (hero) {
      const heroIo = new IntersectionObserver(
        (entries) => {
          entries.forEach((entry) => {
            hero.classList.toggle("is-motion-paused", !entry.isIntersecting);
          });
        },
        { rootMargin: "80px 0px", threshold: 0 }
      );
      heroIo.observe(hero);
    }

    const grc = document.querySelector(".section-grc");
    if (grc) {
      const grcIo = new IntersectionObserver(
        (entries) => {
          entries.forEach((entry) => {
            grc.classList.toggle("is-motion-paused", !entry.isIntersecting);
          });
        },
        { rootMargin: "80px 0px", threshold: 0 }
      );
      grcIo.observe(grc);
    }

    const workflow = document.querySelector(".workflow-shell") || document.getElementById("workflow");
    const archSlides = document.getElementById("wf-arch-slides");
    if (workflow && archSlides) {
      let workflowVisible = true;
      let motionRaf = 0;
      const syncArchMotion = function () {
        if (motionRaf) return;
        motionRaf = window.requestAnimationFrame(function () {
          motionRaf = 0;
          archSlides.querySelectorAll(".wf-arch-slide").forEach((slide) => {
            const active = slide.classList.contains("is-active");
            const pause = !workflowVisible || !active;
            const svg = slide.querySelector("svg");
            if (!svg) return;
            try {
              if (pause && typeof svg.pauseAnimations === "function") svg.pauseAnimations();
              if (!pause && typeof svg.unpauseAnimations === "function") svg.unpauseAnimations();
            } catch (err) {
              /* older engines */
            }
          });
        });
      };
      const wfIo = new IntersectionObserver(
        (entries) => {
          entries.forEach((entry) => {
            workflowVisible = entry.isIntersecting;
            syncArchMotion();
          });
        },
        { rootMargin: "120px 0px", threshold: 0 }
      );
      wfIo.observe(workflow);
      const mo = new MutationObserver(syncArchMotion);
      mo.observe(archSlides, { subtree: true, attributes: true, attributeFilter: ["class"] });
    }
  })();

  /* Work-with-me form (CSP: no page-inline script) */
  (function initWorkWithMe() {
    const form = document.getElementById("wwm-form");
    const status = document.getElementById("wwm-status");
    if (!form || !status) return;
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      const hp = form.querySelector('[name="_gotcha"]');
      if (hp && String(hp.value || "").trim()) {
        status.hidden = false;
        status.textContent = "Thank you. I will reply soon.";
        form.reset();
        return;
      }
      if (!canSubmitNow()) {
        status.hidden = false;
        status.textContent = "Please wait a few seconds before sending again.";
        return;
      }
      if (!assertFormspreeEndpoint(form.action)) {
        status.hidden = false;
        status.textContent = "Form endpoint is misconfigured.";
        return;
      }
      status.hidden = false;
      status.textContent = "Sending…";
      const data = new FormData(form);
      fetch(form.action, {
        method: "POST",
        body: data,
        headers: { Accept: "application/json" },
        mode: "cors",
        credentials: "omit",
        referrerPolicy: "strict-origin-when-cross-origin",
      })
        .then(function (res) {
          if (res.ok) {
            status.textContent = "Thank you. I will reply soon.";
            form.reset();
          } else {
            status.textContent = "Something went wrong. Email sujanray@ymail.com instead.";
          }
        })
        .catch(function () {
          status.textContent = "Network error. Email sujanray@ymail.com instead.";
        });
    });
  })();

  /* Chapter rail - active section while scrolling (Paolo-style section chapters) */
  (function initChapterRail() {
    const rail = document.getElementById("chapter-rail");
    if (!rail) return;
    const links = Array.from(rail.querySelectorAll("a[data-chapter]"));
    if (!links.length) return;

    const sections = links
      .map((link) => {
        const id = link.getAttribute("data-chapter");
        const el = id === "top" ? document.getElementById("top") : document.getElementById(id);
        return el ? { id: id, el: el, link: link } : null;
      })
      .filter(Boolean);

    function setActive(id) {
      links.forEach((link) => {
        const on = link.getAttribute("data-chapter") === id;
        link.classList.toggle("is-active", on);
        if (on) link.setAttribute("aria-current", "true");
        else link.removeAttribute("aria-current");
      });
    }

    setActive("top");

    if (typeof IntersectionObserver === "undefined") return;

    const io = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio);
        if (!visible.length) return;
        const hit = sections.find((s) => s.el === visible[0].target);
        if (hit) setActive(hit.id);
      },
      { rootMargin: "-28% 0px -55% 0px", threshold: [0.08, 0.2, 0.4] }
    );
    sections.forEach((s) => io.observe(s.el));
  })();

  /* Mild BGM: autoplay on open; always stop when tab/window loses the user. */
  (function initMildBgm() {
    const SRC = "assets/BGM.mp3?v=bgm14";
    const VOLUME = 0.05;
    const RATE = 0.85;
    const PREF_KEY = "tigergrci-bgm-on";
    const TRACK_KEY = "tigergrci-bgm-track";

    try {
      if (sessionStorage.getItem(TRACK_KEY) !== SRC) {
        sessionStorage.setItem(TRACK_KEY, SRC);
        sessionStorage.removeItem(PREF_KEY);
      }
    } catch (_) {}

    var wantOn = true;
    var unlockBound = false;

    const audio = document.createElement("audio");
    audio.id = "site-bgm";
    audio.src = SRC;
    audio.loop = true;
    audio.preload = "auto";
    audio.setAttribute("playsinline", "");
    audio.setAttribute("autoplay", "");
    audio.volume = VOLUME;
    audio.playbackRate = RATE;
    try {
      audio.preservesPitch = true;
    } catch (_) {}

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "bgm-toggle";
    btn.id = "bgm-toggle";
    btn.setAttribute("aria-pressed", "false");
    btn.setAttribute("aria-label", "Play background music");
    btn.innerHTML =
      '<span class="bgm-toggle-icon" aria-hidden="true"></span><span class="bgm-toggle-label">Music</span>';

    function setUi(on) {
      btn.classList.toggle("is-on", on);
      btn.setAttribute("aria-pressed", on ? "true" : "false");
      btn.setAttribute(
        "aria-label",
        on ? "Mute background music" : "Play background music"
      );
      const label = btn.querySelector(".bgm-toggle-label");
      if (label) label.textContent = on ? "Mute" : "Music";
    }

    function persist(on) {
      try {
        sessionStorage.setItem(PREF_KEY, on ? "1" : "0");
      } catch (_) {}
    }

    function readPref() {
      try {
        return sessionStorage.getItem(PREF_KEY);
      } catch (_) {
        return null;
      }
    }

    function pageIsActive() {
      if (document.hidden) return false;
      if (document.visibilityState && document.visibilityState !== "visible") {
        return false;
      }
      try {
        if (typeof document.hasFocus === "function" && !document.hasFocus()) {
          return false;
        }
      } catch (_) {}
      return true;
    }

    function haltAudio() {
      try {
        audio.pause();
      } catch (_) {}
      try {
        if (audio.readyState >= 1) audio.currentTime = 0;
      } catch (_) {}
    }

    function playFromStart() {
      if (!wantOn) return Promise.resolve(false);
      if (!pageIsActive()) {
        haltAudio();
        return Promise.resolve(false);
      }
      try {
        if (audio.readyState >= 1) audio.currentTime = 0;
      } catch (_) {}
      audio.volume = VOLUME;
      audio.playbackRate = RATE;
      const p = audio.play();
      if (p && typeof p.then === "function") {
        return p
          .then(function () {
            if (!wantOn || !pageIsActive()) {
              haltAudio();
              return false;
            }
            setUi(true);
            persist(true);
            return true;
          })
          .catch(function () {
            return false;
          });
      }
      if (!audio.paused && pageIsActive()) {
        setUi(true);
        persist(true);
        return Promise.resolve(true);
      }
      return Promise.resolve(false);
    }

    function userEnable() {
      wantOn = true;
      persist(true);
      setUi(true);
      return playFromStart();
    }

    function userDisable() {
      wantOn = false;
      persist(false);
      haltAudio();
      setUi(false);
    }

    function onLeave() {
      haltAudio();
    }

    function onReturn() {
      if (!wantOn) return;
      if (!pageIsActive()) return;
      playFromStart();
    }

    function syncActive() {
      if (pageIsActive()) onReturn();
      else onLeave();
    }

    btn.addEventListener("click", function () {
      if (wantOn && !audio.paused) userDisable();
      else userEnable();
    });

    document.addEventListener("visibilitychange", syncActive);
    window.addEventListener("pagehide", onLeave);
    window.addEventListener("beforeunload", onLeave);
    document.addEventListener("freeze", onLeave);
    window.addEventListener("blur", onLeave);
    window.addEventListener("focus", syncActive);
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) onLeave();
    });

    document.body.appendChild(audio);
    document.body.appendChild(btn);

    const pref = readPref();
    if (pref === "0") {
      wantOn = false;
      setUi(false);
      return;
    }

    wantOn = true;
    setUi(true);

    function bindUnlock() {
      if (unlockBound) return;
      unlockBound = true;
      function unlock() {
        document.removeEventListener("pointerdown", unlock, true);
        document.removeEventListener("keydown", unlock, true);
        document.removeEventListener("touchstart", unlock, true);
        unlockBound = false;
        if (readPref() === "0") return;
        wantOn = true;
        persist(true);
        playFromStart();
      }
      document.addEventListener("pointerdown", unlock, true);
      document.addEventListener("keydown", unlock, true);
      document.addEventListener("touchstart", unlock, true);
    }

    function tryAutoplay() {
      playFromStart().then(function (ok) {
        if (ok) return;
        bindUnlock();
        function onReady() {
          audio.removeEventListener("canplay", onReady);
          audio.removeEventListener("loadeddata", onReady);
          if (readPref() === "0" || !wantOn) return;
          playFromStart().then(function (ok2) {
            if (!ok2) bindUnlock();
          });
        }
        audio.addEventListener("canplay", onReady);
        audio.addEventListener("loadeddata", onReady);
        try {
          audio.load();
        } catch (_) {}
      });
    }

    tryAutoplay();
  })();
})();
