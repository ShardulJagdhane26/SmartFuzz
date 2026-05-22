import React, { useState, useEffect, useRef } from "react";
import { Target, Zap, Settings, ArrowRight, Loader2, AlertCircle, Shield, Code, Database, Crosshair, Lock, ChevronDown, FileCode, Code2, ExternalLink } from "lucide-react";
import { AuthMode, ScanConfig, ScanType } from "../types";
import { startScan, StartScanPayload, VulnClass } from "../api";
import ConsentModal from "../components/ConsentModal";

const COOKIES_PLACEHOLDER = `[
  { "name": "session", "value": "abc123", "domain": "localhost", "path": "/" }
]`;

const HEADERS_PLACEHOLDER = `{
  "Authorization": "Bearer eyJhbGciOi...",
  "X-API-Key": "secret"
}`;

interface NewScanProps {
  onScanStarted: (scanId: string, config: ScanConfig) => void;
}

type PayloadFlags = {
  sql: boolean; xss: boolean; rce: boolean; ssrf: boolean; cmd: boolean;
  auth: boolean; idor: boolean; nosql: boolean; xxe: boolean; ssti: boolean; redirect: boolean;
};

function toVulnClasses(scanType: ScanType, payloads: PayloadFlags): VulnClass[] {
  if (scanType === "SQL Injection Test") return ["SQLi"];
  if (scanType === "XSS Test")           return ["XSS"];
  const classes: VulnClass[] = [];
  if (payloads.sql)      classes.push("SQLi");
  if (payloads.xss)      classes.push("XSS");
  if (payloads.rce)      classes.push("RCE");
  if (payloads.ssrf)     classes.push("SSRF");
  if (payloads.cmd)      classes.push("Command Injection");
  if (payloads.auth)     classes.push("Auth Bypass");
  if (payloads.idor)     classes.push("IDOR");
  if (payloads.nosql)    classes.push("NoSQL");
  if (payloads.xxe)      classes.push("XXE");
  if (payloads.ssti)     classes.push("SSTI");
  if (payloads.redirect) classes.push("Open Redirect");
  return classes.length > 0 ? classes : ["SQLi", "XSS"];
}


const SCAN_OPTIONS: { type: ScanType; icon: React.ReactNode; desc: string }[] = [
  { type: "Full Security Scan",  icon: <Shield   size={18} strokeWidth={2} />, desc: "All 11 vuln classes — SQLi, XSS, RCE, SSRF, CMDi, Auth, IDOR, NoSQL, XXE, SSTI, Open Redirect" },
  { type: "Basic Fuzzing",       icon: <Zap      size={18} strokeWidth={2} />, desc: "Custom selection — pick your own vulnerability classes" },
  { type: "SQL Injection Test",  icon: <Database size={18} strokeWidth={2} />, desc: "Targeted deep-dive into SQL injection vectors only" },
  { type: "XSS Test",            icon: <Code     size={18} strokeWidth={2} />, desc: "Cross-site scripting payload synthesis and detection" },
];

const glassPanel = {
  backdropFilter: 'blur(20px)',
  background: 'linear-gradient(160deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%)',
};

const NewScan: React.FC<NewScanProps> = ({ onScanStarted }) => {
  const [targetUrl, setTargetUrl] = useState("");
  const [scanType, setScanType]   = useState<ScanType>("Full Security Scan");
  const [payloads, setPayloads]   = useState<PayloadFlags>({
    sql: true, xss: true, rce: true, ssrf: true, cmd: true, auth: true, idor: true,
    nosql: true, xxe: true, ssti: true, redirect: true,
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError]         = useState<string | null>(null);

  // ── Authenticated Scan state ───────────────────────────────────────────────
  const [authExpanded, setAuthExpanded] = useState(false);
  const [authMode, setAuthMode]         = useState<AuthMode>("none");
  const [cookiesText, setCookiesText]   = useState("");
  const [headersText, setHeadersText]   = useState("");
  const [cookiesError, setCookiesError] = useState<string | null>(null);
  const [headersError, setHeadersError] = useState<string | null>(null);
  const [loginUrl, setLoginUrl]                   = useState("");
  const [loginUsername, setLoginUsername]         = useState("");
  const [loginPassword, setLoginPassword]         = useState("");
  const [loginUserField, setLoginUserField]       = useState("username");
  const [loginPassField, setLoginPassField]       = useState("password");

  // ── Consent gate state ─────────────────────────────────────────────────────
  const [showConsent, setShowConsent]     = useState(false);
  const [pendingSubmit, setPendingSubmit] = useState(false);
  const pendingPayloadRef = useRef<StartScanPayload | null>(null);

  useEffect(() => {
    if (scanType === "Full Security Scan") {
      setPayloads({ sql: true, xss: true, rce: true, ssrf: true, cmd: true, auth: true, idor: true,
                    nosql: true, xxe: true, ssti: true, redirect: true });
    } else if (scanType === "SQL Injection Test") {
      setPayloads({ sql: true, xss: false, rce: false, ssrf: false, cmd: false, auth: false, idor: false,
                    nosql: false, xxe: false, ssti: false, redirect: false });
    } else if (scanType === "XSS Test") {
      setPayloads({ sql: false, xss: true, rce: false, ssrf: false, cmd: false, auth: false, idor: false,
                    nosql: false, xxe: false, ssti: false, redirect: false });
    }
  }, [scanType]);

  type CookieEntry = { name: string; value: string; domain?: string; path?: string };

  const validateCookies = (raw: string): { ok: true; value: CookieEntry[] | undefined } | { ok: false; err: string } => {
    const trimmed = raw.trim();
    if (!trimmed) return { ok: true, value: undefined };
    try {
      const parsed = JSON.parse(trimmed);
      if (!Array.isArray(parsed)) return { ok: false, err: "Cookies must be a JSON array." };
      for (const c of parsed) {
        if (!c || typeof c !== "object" || typeof c.name !== "string" || typeof c.value !== "string") {
          return { ok: false, err: "Each cookie needs string `name` and `value`." };
        }
      }
      return { ok: true, value: parsed as CookieEntry[] };
    } catch (e) {
      return { ok: false, err: e instanceof Error ? e.message : "Invalid JSON." };
    }
  };

  const validateHeaders = (raw: string): { ok: true; value: Record<string, string> | undefined } | { ok: false; err: string } => {
    const trimmed = raw.trim();
    if (!trimmed) return { ok: true, value: undefined };
    try {
      const parsed = JSON.parse(trimmed);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return { ok: false, err: "Headers must be a JSON object." };
      }
      for (const k of Object.keys(parsed)) {
        if (typeof parsed[k] !== "string") return { ok: false, err: `Header "${k}" must have a string value.` };
      }
      return { ok: true, value: parsed as Record<string, string> };
    } catch (e) {
      return { ok: false, err: e instanceof Error ? e.message : "Invalid JSON." };
    }
  };

  /** Validate inputs and assemble the StartScanPayload. Returns null if validation fails (and sets inline errors). */
  const buildPayload = (): StartScanPayload | null => {
    let auth: StartScanPayload["auth"] | undefined;
    if (authMode !== "none") {
      auth = {};

      const cookieResult = validateCookies(cookiesText);
      if (!cookieResult.ok) {
        setCookiesError(cookieResult.err);
        return null;
      }
      setCookiesError(null);
      if (cookieResult.value && cookieResult.value.length > 0) {
        auth.cookies = cookieResult.value;
      }

      const headerResult = validateHeaders(headersText);
      if (!headerResult.ok) {
        setHeadersError(headerResult.err);
        return null;
      }
      setHeadersError(null);
      if (headerResult.value && Object.keys(headerResult.value).length > 0) {
        auth.headers = headerResult.value;
      }

      if (loginUrl.trim() && loginUsername.trim() && loginPassword.trim()) {
        auth.login = {
          url:      loginUrl.trim(),
          username: loginUsername.trim(),
          password: loginPassword,
          ...(loginUserField.trim() && loginUserField.trim() !== "username" ? { username_field: loginUserField.trim() } : {}),
          ...(loginPassField.trim() && loginPassField.trim() !== "password" ? { password_field: loginPassField.trim() } : {}),
        };
      }

      if (!auth.cookies && !auth.headers && !auth.login) {
        auth = undefined;
      }
    }

    const vulnClasses = toVulnClasses(scanType, payloads);
    return {
      target_url:   targetUrl,
      scan_type:    "POST",
      vuln_classes: vulnClasses,
      ...(auth ? { auth } : {}),
    };
  };

  /** Fire the validated scan request — used both directly and from the consent modal accept. */
  const launchScan = async (payload: StartScanPayload) => {
    setIsLoading(true);
    try {
      const scanId = await startScan(payload);
      onScanStarted(scanId, {
        targetUrl,
        scanType,
        depth: 3,
        payloads: payloads as any,
        auth: { mode: authMode, username: loginUsername || undefined },
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not reach the SmartFuzz backend.");
      setIsLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!targetUrl || isLoading) return;
    setError(null);

    const payload = buildPayload();
    if (!payload) return; // validation failed; inline errors are already set

    // Always gate behind the legal consent modal — re-confirm on every scan,
    // not just once per session.
    pendingPayloadRef.current = payload;
    setPendingSubmit(true);
    setShowConsent(true);
  };

  const handleConsentAccept = () => {
    setShowConsent(false);
    setPendingSubmit(false);
    const payload = pendingPayloadRef.current;
    pendingPayloadRef.current = null;
    if (payload) void launchScan(payload);
  };

  const handleConsentCancel = () => {
    setShowConsent(false);
    setPendingSubmit(false);
    pendingPayloadRef.current = null;
  };

  const inputStyle = {
    backdropFilter: 'blur(12px)',
    backgroundColor: 'rgba(255,255,255,0.05)',
  };

  return (
    <div className="animate-in slide-in-from-bottom-8 duration-700 space-y-8 pb-12">
      <ConsentModal
        open={showConsent}
        onAccept={handleConsentAccept}
        onCancel={handleConsentCancel}
        targetUrl={targetUrl}
      />

      <div className="flex items-end justify-between border-b border-white/[0.06] pb-8">
        <div>
          <h1 className="text-3xl sm:text-4xl font-black text-white tracking-tight">
            Mission{' '}
            <span style={{ background: 'linear-gradient(90deg, #34d399, #22d3ee)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              Config
            </span>
          </h1>
          <p className="text-slate-500 mt-2 text-sm">Define the security testing parameters for your audit.</p>
        </div>
      </div>

      {error && (
        <div className="flex items-start gap-3 bg-rose-500/[0.08] border border-rose-500/20 text-rose-400 rounded-xl px-5 py-4">
          <AlertCircle size={18} className="shrink-0 mt-0.5" strokeWidth={2} />
          <div>
            <p className="font-bold text-sm">Backend Error</p>
            <p className="text-sm mt-0.5 text-rose-300/80">{error}</p>
          </div>
        </div>
      )}

      <form onSubmit={handleSubmit} className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-5">

          {/* Target + Mode */}
          <div className="rounded-2xl p-8 border border-white/[0.08] space-y-8" style={glassPanel}>
            <div className="flex items-center gap-3 text-emerald-400">
              <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/15">
                <Target size={20} strokeWidth={2} />
              </div>
              <h2 className="font-bold text-white text-xs uppercase tracking-widest">Deployment Vector</h2>
            </div>

            <div className="space-y-6">
              <div>
                <label className="block text-[11px] font-bold text-slate-500 uppercase tracking-widest mb-3">
                  Target URI
                </label>
                <input
                  type="url"
                  placeholder="https://app.enterprise-security.com/api"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  className="w-full text-white px-5 py-3.5 rounded-xl border border-white/[0.1] focus:border-emerald-500/40 focus:outline-none transition-all placeholder:text-slate-600 font-mono text-sm"
                  style={inputStyle}
                  required
                  disabled={isLoading}
                />
              </div>

              <div>
                <label className="block text-[11px] font-bold text-slate-500 uppercase tracking-widest mb-3">
                  Audit Mode
                </label>
                <div className="grid grid-cols-2 gap-3 auto-rows-fr">
                  {SCAN_OPTIONS.map((opt) => {
                    const isActive = scanType === opt.type;
                    return (
                      <button
                        key={opt.type}
                        type="button"
                        disabled={isLoading}
                        onClick={() => setScanType(opt.type)}
                        className="h-full flex items-start gap-3.5 p-4 rounded-xl border text-left transition-all duration-200 disabled:opacity-50"
                        style={
                          isActive
                            ? {
                                background: 'linear-gradient(135deg, rgba(16,185,129,0.12) 0%, rgba(8,145,178,0.07) 100%)',
                                borderColor: 'rgba(52,211,153,0.35)',
                                boxShadow: '0 0 20px rgba(16,185,129,0.1), inset 0 1px 0 rgba(255,255,255,0.06)',
                              }
                            : {
                                background: 'rgba(255,255,255,0.03)',
                                borderColor: 'rgba(255,255,255,0.08)',
                              }
                        }
                      >
                        <div
                          className="shrink-0 w-9 h-9 rounded-lg flex items-center justify-center mt-0.5 transition-all"
                          style={
                            isActive
                              ? { background: 'rgba(16,185,129,0.2)', border: '1px solid rgba(52,211,153,0.3)', color: '#34d399' }
                              : { background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', color: 'rgb(100,116,139)' }
                          }
                        >
                          {opt.icon}
                        </div>
                        <div className="min-w-0">
                          <p className={`font-bold text-sm leading-tight ${isActive ? 'text-white' : 'text-slate-400'}`}>
                            {opt.type}
                          </p>
                          <p className="text-[11px] text-slate-600 mt-1 leading-snug">{opt.desc}</p>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>

          {/* Vuln classes */}
          <div className="rounded-2xl p-8 border border-white/[0.08] space-y-8" style={glassPanel}>
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/15">
                <Settings size={20} strokeWidth={2} className="text-emerald-400" />
              </div>
              <h2 className="font-bold text-white text-xs uppercase tracking-widest">AI Intelligence Tuning</h2>
              {scanType !== "Basic Fuzzing" && (
                <span className="ml-auto text-[10px] font-bold text-slate-500 bg-white/[0.04] px-3 py-1 rounded-full border border-white/[0.08]">
                  Auto-selected
                </span>
              )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {[
                { key: "sql",      label: "SQLi Deep Analysis",       icon: <Database size={14} strokeWidth={2} /> },
                { key: "xss",      label: "XSS Vector Synthesis",     icon: <Code     size={14} strokeWidth={2} /> },
                { key: "rce",      label: "RCE Simulation",           icon: <Zap      size={14} strokeWidth={2} /> },
                { key: "ssrf",     label: "SSRF Probe",               icon: <Crosshair size={14} strokeWidth={2} /> },
                { key: "cmd",      label: "Command Injection Probe",  icon: <Code     size={14} strokeWidth={2} /> },
                { key: "auth",     label: "Auth Bypass Vectors",      icon: <Lock     size={14} strokeWidth={2} /> },
                { key: "idor",     label: "IDOR Manipulation",        icon: <Shield   size={14} strokeWidth={2} /> },
                { key: "nosql",    label: "NoSQL Injection Probe",    icon: <Database size={14} strokeWidth={2} /> },
                { key: "xxe",      label: "XXE Entity Injection",     icon: <FileCode size={14} strokeWidth={2} /> },
                { key: "ssti",     label: "SSTI Template Probe",      icon: <Code2    size={14} strokeWidth={2} /> },
                { key: "redirect", label: "Open Redirect Probe",      icon: <ExternalLink size={14} strokeWidth={2} /> },
              ].map((p) => {
                const disabled = scanType !== "Basic Fuzzing";
                return (
                  <label
                    key={p.key}
                    className={`flex items-center gap-4 p-4 rounded-xl border transition-all ${
                      disabled || isLoading
                        ? "opacity-40 cursor-not-allowed border-white/[0.05]"
                        : payloads[p.key as keyof typeof payloads]
                          ? "cursor-pointer border-emerald-500/30 bg-emerald-500/[0.07]"
                          : "cursor-pointer border-white/[0.08] hover:border-white/[0.14] hover:bg-white/[0.03]"
                    }`}
                    style={{ backdropFilter: 'blur(8px)' }}
                  >
                    <input
                      type="checkbox"
                      checked={payloads[p.key as keyof typeof payloads]}
                      onChange={(e) => setPayloads((prev) => ({ ...prev, [p.key]: e.target.checked }))}
                      disabled={disabled || isLoading}
                      className="w-4 h-4 accent-emerald-500 rounded"
                    />
                    <span className="text-emerald-400/80 shrink-0">{p.icon}</span>
                    <span className="font-bold text-slate-300 text-sm">{p.label}</span>
                  </label>
                );
              })}
            </div>
          </div>

          {/* Authenticated Scan (Optional) */}
          <div className="rounded-2xl border border-white/[0.08]" style={glassPanel}>
            <button
              type="button"
              onClick={() => setAuthExpanded((v) => !v)}
              className="w-full flex items-center gap-3 p-8 text-left"
              aria-expanded={authExpanded}
            >
              <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/15">
                <Lock size={20} strokeWidth={2} className="text-emerald-400" />
              </div>
              <h2 className="font-bold text-white text-xs uppercase tracking-widest">
                Authenticated Scan <span className="text-slate-500 font-medium normal-case tracking-normal">(Optional)</span>
              </h2>
              {authMode !== "none" && (
                <span className="text-[10px] font-bold text-emerald-400 bg-emerald-500/10 px-3 py-1 rounded-full border border-emerald-500/20">
                  {authMode === "login" ? `Login: ${loginUsername || "—"}` : authMode[0].toUpperCase() + authMode.slice(1)}
                </span>
              )}
              <ChevronDown
                size={18}
                strokeWidth={2}
                className={`ml-auto text-slate-500 transition-transform ${authExpanded ? "rotate-180" : ""}`}
              />
            </button>

            {authExpanded && (
              <div className="px-8 pb-8 space-y-6 border-t border-white/[0.06] pt-6">
                {/* Mode tab strip */}
                <div className="grid grid-cols-4 gap-2 p-1 rounded-xl border border-white/[0.08]" style={{ background: 'rgba(255,255,255,0.02)' }}>
                  {([
                    { id: "none",    label: "None"    },
                    { id: "cookies", label: "Cookies" },
                    { id: "headers", label: "Headers" },
                    { id: "login",   label: "Form Login" },
                  ] as { id: AuthMode; label: string }[]).map((tab) => {
                    const active = authMode === tab.id;
                    return (
                      <button
                        key={tab.id}
                        type="button"
                        onClick={() => setAuthMode(tab.id)}
                        disabled={isLoading}
                        className={`px-3 py-2 rounded-lg text-xs font-bold transition-all disabled:opacity-50 ${
                          active ? "text-white" : "text-slate-500 hover:text-slate-300"
                        }`}
                        style={
                          active
                            ? {
                                background: 'linear-gradient(135deg, rgba(16,185,129,0.18) 0%, rgba(8,145,178,0.10) 100%)',
                                border: '1px solid rgba(52,211,153,0.35)',
                                boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.06)',
                              }
                            : { border: '1px solid transparent' }
                        }
                      >
                        {tab.label}
                      </button>
                    );
                  })}
                </div>

                {authMode === "cookies" && (
                  <div>
                    <label className="block text-[11px] font-bold text-slate-500 uppercase tracking-widest mb-3">
                      Cookies — JSON Array
                    </label>
                    <textarea
                      value={cookiesText}
                      onChange={(e) => { setCookiesText(e.target.value); if (cookiesError) setCookiesError(null); }}
                      onBlur={() => {
                        const r = validateCookies(cookiesText);
                        setCookiesError(r.ok ? null : r.err);
                      }}
                      placeholder={COOKIES_PLACEHOLDER}
                      rows={6}
                      disabled={isLoading}
                      className="w-full text-white px-5 py-3.5 rounded-xl border border-white/[0.1] focus:border-emerald-500/40 focus:outline-none transition-all placeholder:text-slate-600 font-mono text-xs resize-y"
                      style={inputStyle}
                    />
                    {cookiesError && (
                      <p className="text-xs text-rose-400 mt-2 flex items-center gap-1.5">
                        <AlertCircle size={13} strokeWidth={2} /> {cookiesError}
                      </p>
                    )}
                  </div>
                )}

                {authMode === "headers" && (
                  <div>
                    <label className="block text-[11px] font-bold text-slate-500 uppercase tracking-widest mb-3">
                      Custom Headers — JSON Object
                    </label>
                    <textarea
                      value={headersText}
                      onChange={(e) => { setHeadersText(e.target.value); if (headersError) setHeadersError(null); }}
                      onBlur={() => {
                        const r = validateHeaders(headersText);
                        setHeadersError(r.ok ? null : r.err);
                      }}
                      placeholder={HEADERS_PLACEHOLDER}
                      rows={6}
                      disabled={isLoading}
                      className="w-full text-white px-5 py-3.5 rounded-xl border border-white/[0.1] focus:border-emerald-500/40 focus:outline-none transition-all placeholder:text-slate-600 font-mono text-xs resize-y"
                      style={inputStyle}
                    />
                    {headersError && (
                      <p className="text-xs text-rose-400 mt-2 flex items-center gap-1.5">
                        <AlertCircle size={13} strokeWidth={2} /> {headersError}
                      </p>
                    )}
                  </div>
                )}

                {authMode === "login" && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="md:col-span-2">
                      <label className="block text-[11px] font-bold text-slate-500 uppercase tracking-widest mb-3">Login URL</label>
                      <input
                        type="url"
                        placeholder="http://localhost:8081/login"
                        value={loginUrl}
                        onChange={(e) => setLoginUrl(e.target.value)}
                        disabled={isLoading}
                        className="w-full text-white px-5 py-3.5 rounded-xl border border-white/[0.1] focus:border-emerald-500/40 focus:outline-none transition-all placeholder:text-slate-600 font-mono text-sm"
                        style={inputStyle}
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-bold text-slate-500 uppercase tracking-widest mb-3">Username</label>
                      <input
                        type="text"
                        placeholder="admin"
                        value={loginUsername}
                        onChange={(e) => setLoginUsername(e.target.value)}
                        disabled={isLoading}
                        className="w-full text-white px-5 py-3.5 rounded-xl border border-white/[0.1] focus:border-emerald-500/40 focus:outline-none transition-all placeholder:text-slate-600 font-mono text-sm"
                        style={inputStyle}
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-bold text-slate-500 uppercase tracking-widest mb-3">Password</label>
                      <input
                        type="password"
                        placeholder="••••••••"
                        value={loginPassword}
                        onChange={(e) => setLoginPassword(e.target.value)}
                        disabled={isLoading}
                        className="w-full text-white px-5 py-3.5 rounded-xl border border-white/[0.1] focus:border-emerald-500/40 focus:outline-none transition-all placeholder:text-slate-600 font-mono text-sm"
                        style={inputStyle}
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-bold text-slate-500 uppercase tracking-widest mb-3">Username Field Selector</label>
                      <input
                        type="text"
                        value={loginUserField}
                        onChange={(e) => setLoginUserField(e.target.value)}
                        disabled={isLoading}
                        className="w-full text-white px-5 py-3.5 rounded-xl border border-white/[0.1] focus:border-emerald-500/40 focus:outline-none transition-all placeholder:text-slate-600 font-mono text-sm"
                        style={inputStyle}
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-bold text-slate-500 uppercase tracking-widest mb-3">Password Field Selector</label>
                      <input
                        type="text"
                        value={loginPassField}
                        onChange={(e) => setLoginPassField(e.target.value)}
                        disabled={isLoading}
                        className="w-full text-white px-5 py-3.5 rounded-xl border border-white/[0.1] focus:border-emerald-500/40 focus:outline-none transition-all placeholder:text-slate-600 font-mono text-sm"
                        style={inputStyle}
                      />
                    </div>
                  </div>
                )}

                {authMode !== "none" && (
                  <p className="text-[11px] text-slate-500 leading-relaxed">
                    Fill any one section — or multiple, all filled sections are sent. Leave on <span className="text-slate-400 font-bold">None</span> to skip authentication.
                  </p>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Mission brief sidebar */}
        <div>
          <div className="rounded-2xl p-7 border border-white/[0.08] sticky top-8 space-y-7" style={glassPanel}>
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/15">
                <Zap size={18} strokeWidth={2} className="text-emerald-400" />
              </div>
              <h3 className="font-bold text-white text-xs uppercase tracking-widest">Mission Brief</h3>
            </div>

            <div className="space-y-3">
              {[
                { label: 'Mode',         value: scanType },
                { label: 'Method',       value: 'POST' },
                { label: 'Vuln Classes', value: `${toVulnClasses(scanType, payloads).length} selected` },
                { label: 'Auth',         value:
                    authMode === 'none'    ? 'None'
                  : authMode === 'cookies' ? 'Cookies'
                  : authMode === 'headers' ? 'Headers'
                  : `Login: ${loginUsername || '—'}`
                },
                { label: 'Target',       value: targetUrl || '—', mono: true },
              ].map((row) => (
                <div key={row.label} className="flex justify-between items-start gap-3 text-sm py-2 border-b border-white/[0.04] last:border-0">
                  <span className="text-slate-500 shrink-0">{row.label}</span>
                  <span className={`text-white font-bold text-right truncate max-w-[140px] ${row.mono ? 'font-mono text-emerald-400' : ''}`} title={row.value}>
                    {row.value}
                  </span>
                </div>
              ))}
            </div>

            <button
              type="submit"
              disabled={!targetUrl || isLoading}
              className="w-full flex items-center justify-center gap-2.5 px-6 py-3.5 text-white font-bold text-sm rounded-xl transition-all shadow-[0_0_25px_rgba(16,185,129,0.35)] disabled:opacity-40 disabled:cursor-not-allowed active:scale-95"
              style={{ background: 'linear-gradient(135deg, #10b981, #059669)' }}
            >
              {isLoading ? (
                <>
                  <Loader2 size={17} className="animate-spin" />
                  Queuing Scan…
                </>
              ) : (
                <>
                  Launch Fuzzer
                  <ArrowRight size={17} strokeWidth={2.5} />
                </>
              )}
            </button>

            {isLoading && (
              <p className="text-center text-xs text-slate-500">Connecting to Flask backend…</p>
            )}
          </div>
        </div>
      </form>
    </div>
  );
};

export default NewScan;
