"use client";

import { useEffect, useState, useRef } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { ScanResult, SQLiFinding, SEVERITY_COLORS, DETECTION_ICONS, CONFIDENCE_COLORS, ConfidenceLevel } from "@/lib/types";

function PocBlock({ poc }: { poc: string }) {
    const [copied, setCopied] = useState(false);
    if (!poc) return null;
    return (
        <div className="mt-2">
            <div className="flex items-center justify-between mb-1">
                <span className="text-xs text-gray-600">Proof of Concept Request</span>
                <button
                    onClick={() => { navigator.clipboard.writeText(poc); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
                    className="text-xs text-accent-blue hover:text-accent-blue/80 transition-colors"
                >
                    {copied ? "✅ Copied" : "📋 Copy"}
                </button>
            </div>
            <pre className="text-xs text-accent-orange bg-surface rounded p-2 overflow-x-auto max-h-36 font-mono leading-relaxed whitespace-pre-wrap">
                <code>{poc}</code>
            </pre>
        </div>
    );
}

function FindingCard({ finding, index }: { finding: SQLiFinding; index: number }) {
    const [expanded, setExpanded] = useState(false);
    const color = SEVERITY_COLORS[finding.severity] || "#6c757d";
    const icon = DETECTION_ICONS[finding.detectionMethod] || "💉";
    const confColor = CONFIDENCE_COLORS[(finding.confidenceLevel || "Tentative") as ConfidenceLevel] || "#6c757d";

    return (
        <div className="finding-card overflow-hidden">
            {/* Card Header */}
            <div
                className="flex items-center gap-2 p-3 border-b border-surface-border flex-wrap cursor-pointer hover:bg-surface-hover/30 transition-colors"
                onClick={() => setExpanded(!expanded)}
            >
                <span
                    className="text-xs font-bold px-2.5 py-1 rounded-full text-white uppercase tracking-wide"
                    style={{ background: color }}
                >
                    {finding.severity}
                </span>
                <span className="text-xs bg-surface-hover px-2 py-0.5 rounded-full text-gray-400">
                    {icon} {finding.detectionMethod?.replace(/_/g, " ") || "DETECTION"}
                </span>
                <span className="text-xs font-mono bg-surface px-2 py-0.5 rounded-full border border-surface-border text-gray-300">
                    CVSS {finding.cvssScore?.toFixed(1)}
                </span>
                <span
                    className="text-xs px-2 py-0.5 rounded-full font-medium"
                    style={{ background: `${confColor}18`, color: confColor }}
                >
                    {finding.confidenceLevel || "Tentative"} Confidence ({Math.round((finding.confidence || 0) * 100)}%)
                </span>
                <span className="text-xs text-gray-600 ml-auto">{expanded ? "▲ collapse" : "▼ expand"}</span>
            </div>

            {/* Card Body — always shown summary */}
            <div className="p-3 space-y-3">
                <div className="flex items-start gap-2">
                    <span className="text-gray-500 text-xs pt-0.5 shrink-0">#{index + 1}</span>
                    <div>
                        <p className="text-sm text-white">
                            Parameter: <code className="text-accent-orange">{finding.parameter}</code>{" "}
                            via <span className="text-gray-400 text-xs">{finding.vector}</span>{" "}
                            {finding.attackSurface && (
                                <span className="text-xs bg-surface-hover px-1.5 py-0.5 rounded text-gray-500">
                                    {finding.attackSurface}
                                </span>
                            )}
                        </p>
                        <p className="text-xs text-gray-500 mt-0.5 break-all">{finding.url}</p>
                    </div>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
                    <div>
                        <span className="text-gray-600 block mb-0.5">DB Type</span>
                        <code className="text-accent-blue">{finding.dbTypeHint || "unknown"}</code>
                    </div>
                    <div>
                        <span className="text-gray-600 block mb-0.5">CWE</span>
                        <a href={`https://cwe.mitre.org/data/definitions/89.html`} target="_blank" rel="noopener"
                            className="text-accent-purple hover:underline">
                            {finding.cweId || "CWE-89"}
                        </a>
                    </div>
                    <div>
                        <span className="text-gray-600 block mb-0.5">OWASP</span>
                        <span className="text-gray-400">{finding.owaspCategory || "A03:2021"}</span>
                    </div>
                    <div>
                        <span className="text-gray-600 block mb-0.5">Bypass</span>
                        <code className="text-gray-400">{finding.bypassTechnique || "NONE"}</code>
                    </div>
                    {finding.timeDelayDetected && (
                        <div>
                            <span className="text-gray-600 block mb-0.5">Time Delay</span>
                            <code className="text-accent-orange">
                                {finding.timeDelaySeconds?.toFixed(2)}s
                                {finding.timingZScore ? ` (Z=${finding.timingZScore.toFixed(1)})` : ""}
                            </code>
                        </div>
                    )}
                    {finding.responseDifferencePercent > 0 && (
                        <div>
                            <span className="text-gray-600 block mb-0.5">Content Diff</span>
                            <code>{finding.responseDifferencePercent.toFixed(1)}%</code>
                        </div>
                    )}
                    {finding.isBooleanPositive === true && (
                        <div>
                            <span className="text-gray-600 block mb-0.5">Boolean</span>
                            <code className="text-accent-green">TRUE≠FALSE ✓</code>
                        </div>
                    )}
                    {finding.oobInteractionId && (
                        <div>
                            <span className="text-gray-600 block mb-0.5">OOB</span>
                            <code className="text-accent-orange">Injected (verify callback)</code>
                        </div>
                    )}
                </div>

                {/* Error signatures */}
                {finding.errorSignatures && finding.errorSignatures.length > 0 && (
                    <div>
                        <span className="text-xs text-gray-600 block mb-1">Error Signatures Matched</span>
                        <div className="flex flex-wrap gap-1">
                            {finding.errorSignatures.slice(0, 5).map((s, si) => (
                                <span key={si} className="text-accent-red bg-accent-red/5 border border-accent-red/20 px-1.5 py-0.5 rounded text-xs font-mono">
                                    {s}
                                </span>
                            ))}
                            {finding.errorSignatures.length > 5 && (
                                <span className="text-xs text-gray-500 self-center">+{finding.errorSignatures.length - 5} more</span>
                            )}
                        </div>
                    </div>
                )}

                {/* Payload */}
                <div>
                    <span className="text-xs text-gray-600 block mb-0.5">Payload Used</span>
                    <pre className="text-xs text-accent-blue bg-surface rounded p-2 overflow-x-auto max-h-16 font-mono whitespace-pre-wrap">
                        <code>{finding.payloadUsed}</code>
                    </pre>
                </div>
            </div>

            {/* Expanded details */}
            {expanded && (
                <div className="px-3 pb-3 space-y-3 border-t border-surface-border pt-3">
                    {/* PoC */}
                    {finding.pocRequest && <PocBlock poc={finding.pocRequest} />}

                    {/* AI Explanation */}
                    {finding.aiExplanation && (
                        <div className="bg-surface rounded-lg p-3 border border-surface-border">
                            <p className="text-xs font-semibold text-accent-blue mb-2">📖 Technical Analysis</p>
                            <p className="text-xs text-gray-400 leading-relaxed">{finding.aiExplanation}</p>
                        </div>
                    )}

                    {/* Raw snippet */}
                    {finding.rawResponseSnippet && (
                        <div>
                            <span className="text-xs text-gray-600 block mb-1">Response Snippet (first 400 chars)</span>
                            <pre className="text-xs text-gray-500 bg-surface rounded p-2 overflow-x-auto max-h-24 font-mono whitespace-pre-wrap">
                                {finding.rawResponseSnippet}
                            </pre>
                        </div>
                    )}

                    {/* Remediation */}
                    {finding.remediationSteps && finding.remediationSteps.length > 0 && (
                        <div className="bg-accent-green/5 border border-accent-green/20 rounded-lg p-3">
                            <p className="text-xs font-semibold text-accent-green mb-2">🛡️ Remediation Steps</p>
                            <ol className="text-xs text-gray-400 space-y-1.5 list-none">
                                {finding.remediationSteps.map((step, si) => (
                                    <li key={si} className="leading-relaxed">{step}</li>
                                ))}
                            </ol>
                        </div>
                    )}

                    {/* References */}
                    {finding.references && finding.references.length > 0 && (
                        <div>
                            <span className="text-xs text-gray-600 block mb-1">References</span>
                            <ul className="text-xs space-y-0.5">
                                {finding.references.map((ref, ri) => (
                                    <li key={ri}>
                                        <a href={ref} target="_blank" rel="noopener noreferrer"
                                            className="text-accent-purple hover:text-accent-purple/80 hover:underline">
                                            {ref}
                                        </a>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

export default function ScanDetailPage() {
    const params = useParams();
    const id = params.id as string;
    const [scan, setScan] = useState<ScanResult | null>(null);
    const [loading, setLoading] = useState(true);
    const [pollError, setPollError] = useState<string | null>(null);
    const [isStalled, setIsStalled] = useState(false);
    const [stopping, setStopping] = useState(false);
    const retryCountRef = useRef(0);
    const lastProgressRef = useRef<{ progress: number; time: number } | null>(null);

    const handleStopScan = async () => {
        if (!id || stopping) return;
        setStopping(true);
        try {
            const resp = await fetch(`https://sqli-predator-api.onrender.com/api/scan/${id}/stop`, { method: "POST" });
            if (resp.ok) {
                setScan((prev) => prev ? { ...prev, status: "stopped", currentPhase: "Stopped by user" } : null);
            }
        } catch { }
        setStopping(false);
    };

    useEffect(() => {
        let isMounted = true;

        const saveToLocal = (data: ScanResult) => {
            try {
                localStorage.setItem(`sqli_scan_${id}`, JSON.stringify(data));
                const listRaw = localStorage.getItem("sqli_predator_scans");
                let list: ScanResult[] = listRaw ? JSON.parse(listRaw) : [];
                const idx = list.findIndex(s => s.id === id);
                if (idx >= 0) list[idx] = data;
                else list.unshift(data);
                localStorage.setItem("sqli_predator_scans", JSON.stringify(list));
            } catch { }
        };

        const loadFromLocal = (): ScanResult | null => {
            try {
                const item = localStorage.getItem(`sqli_scan_${id}`);
                if (item) return JSON.parse(item);
            } catch { }
            return null;
        };

        const poll = async () => {
            if (!isMounted) return;

            try {
                const resp = await fetch(`https://sqli-predator-api.onrender.com/api/scan/${id}/status`);
                if (!resp.ok) {
                    // On Render, the scan may take a moment to appear in the database after creation.
                    // Use exponential backoff up to 15 retries (covers ~60s of cold-start delay).
                    if (retryCountRef.current < 15) {
                        retryCountRef.current++;
                        const delay = Math.min(1000 * Math.pow(1.3, retryCountRef.current), 8000);
                        setTimeout(poll, delay);
                        return;
                    }
                    const local = loadFromLocal();
                    if (local && isMounted) {
                        setScan(local);
                    } else if (isMounted) {
                        setPollError(
                            "Unable to reach the scan server. The scan may have been lost due to a serverless timeout. " +
                            "Please try starting a new scan."
                        );
                    }
                    if (isMounted) setLoading(false);
                    return;
                }

                // Reset retry counter on successful response
                retryCountRef.current = 0;
                if (isMounted) setPollError(null);

                const data = await resp.json();

                // Stall detection: if progress hasn't changed in 90 seconds, warn
                if (data.status === "running") {
                    const now = Date.now();
                    const progress = data.progress || 0;
                    if (lastProgressRef.current) {
                        if (progress === lastProgressRef.current.progress) {
                            if (now - lastProgressRef.current.time > 90_000) {
                                if (isMounted) setIsStalled(true);
                            }
                        } else {
                            lastProgressRef.current = { progress, time: now };
                            if (isMounted) setIsStalled(false);
                        }
                    } else {
                        lastProgressRef.current = { progress, time: now };
                    }
                }

                if (data.status === "completed" || data.status === "failed" || data.status === "stopped") {
                    if (data.status === "completed") {
                        const reportResp = await fetch(`https://sqli-predator-api.onrender.com/api/scan/${id}/report`);
                        if (reportResp.ok) {
                            const report: ScanResult = await reportResp.json();
                            if (isMounted) { setScan(report); saveToLocal(report); }
                        } else {
                            if (isMounted) setScan(data as any);
                        }
                    } else {
                        // Failed or stopped scan — show state from backend
                        if (isMounted) setScan(data as any);
                    }
                    if (isMounted) setLoading(false);
                    return;
                }

                if (isMounted) setScan(data as any);
                if (data.status === "running") setTimeout(poll, 1500);
                else if (isMounted) setLoading(false);
            } catch (err: any) {
                if (retryCountRef.current < 15) {
                    retryCountRef.current++;
                    const delay = Math.min(1000 * Math.pow(1.3, retryCountRef.current), 8000);
                    setTimeout(poll, delay);
                    return;
                }
                const local = loadFromLocal();
                if (local && isMounted) {
                    setScan(local);
                } else if (isMounted) {
                    setPollError(
                        `Failed to connect to scan server: ${err.message || "Network error"}. ` +
                        "Please check your connection and try refreshing the page."
                    );
                }
                if (isMounted) setLoading(false);
            }
        };

        poll();
        return () => { isMounted = false; };
    }, [id]);

    if (loading && !scan) {
        return (
            <div className="flex flex-col items-center justify-center py-24">
                <svg className="animate-spin h-8 w-8 text-accent-blue mb-4" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                <p className="text-gray-500">Loading scan...</p>
            </div>
        );
    }

    if (pollError && !scan) {
        return (
            <div className="text-center py-24 max-w-lg mx-auto">
                <div className="text-3xl mb-3">⚠️</div>
                <p className="text-accent-red text-sm mb-4">{pollError}</p>
                <div className="flex gap-3 justify-center">
                    <button
                        onClick={() => window.location.reload()}
                        className="text-sm bg-surface-card border border-surface-border px-4 py-2 rounded-lg text-gray-400 hover:text-white hover:border-gray-600 transition-colors"
                    >
                        🔄 Retry
                    </button>
                    <Link href="/" className="text-sm bg-accent-blue/10 border border-accent-blue/30 px-4 py-2 rounded-lg text-accent-blue hover:bg-accent-blue/20 transition-colors">
                        Start New Scan
                    </Link>
                </div>
            </div>
        );
    }

    if (!scan) {
        return (
            <div className="text-center py-24">
                <p className="text-gray-500 mb-4">Scan not found</p>
                <Link href="/" className="text-accent-blue hover:underline text-sm">Start a new scan</Link>
            </div>
        );
    }

    const findings = scan.findings || [];
    const critCount = findings.filter(f => f.severity === "Critical").length;
    const highCount = findings.filter(f => f.severity === "High").length;

    return (
        <div className="space-y-6 max-w-4xl mx-auto">
            {/* Header */}
            <div className="flex items-start justify-between">
                <div>
                    <div className="flex items-center gap-2 mb-1">
                        <Link href="/scans" className="text-sm text-gray-500 hover:text-gray-400">← Back</Link>
                        <span className="text-gray-600">|</span>
                        <h1 className="text-xl font-bold text-white">Scan Report</h1>
                    </div>
                    <p className="text-sm text-gray-500">
                        Target: <code className="text-accent-blue">{scan.target}</code>
                    </p>
                    <p className="text-xs text-gray-600 mt-0.5">
                        {new Date(scan.timestamp).toLocaleString()} · ID: {scan.id}
                    </p>
                </div>

                <div className="flex items-center gap-3">
                    {scan.status === "running" && (
                        <>
                            <div className="flex items-center gap-2 text-accent-blue text-sm pulse-active px-3 py-1.5 rounded-lg border border-accent-blue/30">
                                <svg className="animate-spin h-3.5 w-3.5" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                                </svg>
                                Scanning...
                            </div>
                            <button
                                onClick={handleStopScan}
                                disabled={stopping}
                                className="text-xs bg-accent-red/10 text-accent-red hover:bg-accent-red/20 border border-accent-red/30 px-3 py-1.5 rounded-lg transition-colors font-medium flex items-center gap-1.5"
                            >
                                ⏹️ {stopping ? "Stopping..." : "Stop Scan"}
                            </button>
                        </>
                    )}
                    {scan.status === "completed" && (
                        <span className="text-xs bg-accent-green/10 text-accent-green px-3 py-1.5 rounded-lg font-medium">
                            ✅ Complete ({scan.duration?.toFixed(1)}s)
                        </span>
                    )}
                    {scan.status === "stopped" && (
                        <span className="text-xs bg-yellow-500/10 text-yellow-500 border border-yellow-500/30 px-3 py-1.5 rounded-lg font-medium">
                            🛑 Stopped
                        </span>
                    )}
                    {scan.status === "failed" && (
                        <span className="text-xs bg-accent-red/10 text-accent-red px-3 py-1.5 rounded-lg font-medium">❌ Failed</span>
                    )}
                </div>
            </div>

            {/* Progress bar */}
            {scan.status === "running" && (
                <div className="space-y-2">
                    <div className="flex justify-between text-xs text-gray-500">
                        <span>{scan.currentPhase}</span>
                        <span>{scan.progress?.toFixed(0)}%</span>
                    </div>
                    <div className="w-full bg-surface-border rounded-full h-1.5">
                        <div
                            className="bg-accent-blue h-1.5 rounded-full transition-all duration-1000"
                            style={{ width: `${scan.progress || 0}%` }}
                        />
                    </div>
                    {isStalled && (
                        <div className="bg-yellow-500/5 border border-yellow-500/30 rounded-lg p-2.5 mt-2">
                            <p className="text-xs text-yellow-500">
                                ⚠️ Scan progress has not changed for over 90 seconds. The serverless function may have timed out.
                                If this persists, try starting a new scan.
                            </p>
                        </div>
                    )}
                </div>
            )}

            {/* Error */}
            {scan.error && (
                <div className="bg-accent-red/5 border border-accent-red/20 rounded-lg p-3">
                    <p className="text-sm text-accent-red">{scan.error}</p>
                </div>
            )}

            {/* Enumeration Summary */}
            {scan.status === "completed" && scan.enumeration && (
                <div className="bg-surface-card border border-surface-border rounded-xl p-4">
                    <h2 className="text-sm font-semibold text-white mb-3">🔍 Enumeration Summary</h2>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        <div className="text-center">
                            <div className="text-xl font-bold text-accent-blue">{scan.enumeration.formsFound}</div>
                            <div className="text-xs text-gray-500 mt-0.5">Forms Found</div>
                        </div>
                        <div className="text-center">
                            <div className="text-xl font-bold text-accent-purple">{scan.enumeration.paramsFound}</div>
                            <div className="text-xs text-gray-500 mt-0.5">URL Parameters</div>
                        </div>
                        <div className="text-center">
                            <div className="text-xl font-bold text-accent-green">{scan.enumeration.pathsDiscovered}</div>
                            <div className="text-xs text-gray-500 mt-0.5">Paths Discovered</div>
                        </div>
                        <div className="text-center">
                            <div className="text-xl font-bold text-accent-orange">
                                {Object.values(scan.enumeration.techStack || {}).filter(Boolean).length}
                            </div>
                            <div className="text-xs text-gray-500 mt-0.5">Tech Detected</div>
                        </div>
                    </div>
                    {scan.enumeration.techStack && Object.keys(scan.enumeration.techStack).length > 0 && (
                        <div className="mt-3 flex flex-wrap gap-1.5">
                            {Object.entries(scan.enumeration.techStack).map(([k, v]) => v && (
                                <span key={k} className="text-xs bg-surface px-2 py-1 rounded-full border border-surface-border text-gray-400">
                                    {k}: <span className="text-white">{v as string}</span>
                                </span>
                            ))}
                        </div>
                    )}
                </div>
            )}

            {/* Severity Summary */}
            {scan.status === "completed" && (
                <>
                    <div className="grid grid-cols-5 gap-2">
                        {["Critical", "High", "Medium", "Low", "Info"].map((sev) => {
                            const count = findings.filter(f => f.severity === sev).length;
                            const color = SEVERITY_COLORS[sev] || "#888";
                            const isActive = count > 0;
                            return (
                                <div
                                    key={sev}
                                    className={`bg-surface-card border rounded-lg p-3 text-center transition-all ${isActive ? "border-current" : "border-surface-border"}`}
                                    style={isActive ? { borderColor: `${color}60` } : {}}
                                >
                                    <div className="text-2xl font-bold" style={{ color: isActive ? color : "#4b5563" }}>
                                        {count}
                                    </div>
                                    <div className="text-xs text-gray-500 mt-0.5">{sev}</div>
                                </div>
                            );
                        })}
                    </div>

                    {/* Risk banner */}
                    {(critCount > 0 || highCount > 0) && (
                        <div className="border border-accent-red/40 bg-accent-red/5 rounded-lg p-3 flex items-start gap-2">
                            <span className="text-lg">🚨</span>
                            <div>
                                <p className="text-sm font-semibold text-accent-red">
                                    {critCount > 0 ? `${critCount} Critical` : ""}{critCount > 0 && highCount > 0 ? " and " : ""}{highCount > 0 ? `${highCount} High` : ""} severity findings require immediate attention.
                                </p>
                                <p className="text-xs text-gray-400 mt-0.5">
                                    These findings represent confirmed SQL injection vulnerabilities with data exfiltration potential.
                                </p>
                            </div>
                        </div>
                    )}

                    {/* Findings */}
                    {findings.length === 0 ? (
                        <div className="text-center py-12 text-gray-500 border border-dashed border-surface-border rounded-xl">
                            <div className="text-3xl mb-2">✅</div>
                            <p>No SQL injection vulnerabilities detected.</p>
                            <p className="text-xs mt-1 text-gray-600">This does not guarantee the application is secure — consider a manual review.</p>
                        </div>
                    ) : (
                        <div className="space-y-4">
                            <div className="flex items-center justify-between">
                                <h2 className="text-lg font-semibold text-white">
                                    Findings ({findings.length})
                                </h2>
                                <span className="text-xs text-gray-500">Sorted by severity · Deduplicated</span>
                            </div>
                            {findings.map((finding, i) => (
                                <FindingCard key={finding.id || i} finding={finding} index={i} />
                            ))}
                        </div>
                    )}

                    {/* Scan Log */}
                    {scan.scanLog && scan.scanLog.length > 0 && (
                        <details className="mt-4">
                            <summary className="text-sm text-accent-purple cursor-pointer hover:text-accent-purple/80 font-medium">
                                📋 Scan Log ({scan.scanLog.length} entries) — Show full scan trace
                            </summary>
                            <div className="mt-2 bg-surface-card border border-surface-border rounded-lg p-3 max-h-96 overflow-y-auto">
                                <pre className="text-xs text-gray-400 whitespace-pre-wrap font-mono leading-relaxed">
                                    {scan.scanLog.map((entry, i) => {
                                        let cls = "text-gray-400";
                                        if (entry.includes("FINDING:")) cls = "text-accent-red font-semibold";
                                        else if (entry.includes("BOOLEAN CONFIRMED:")) cls = "text-accent-blue font-semibold";
                                        else if (entry.includes("[ERROR]")) cls = "text-yellow-500";
                                        else if (entry.includes("═══")) cls = "text-white font-semibold";
                                        else if (entry.includes("──")) cls = "text-gray-300";
                                        else if (entry.includes("Tech stack:")) cls = "text-accent-green";
                                        else if (entry.includes("robots.txt") || entry.includes("sitemap")) cls = "text-accent-purple";
                                        else if (entry.includes("Common path found")) cls = "text-accent-orange";
                                        return (
                                            <span key={i} className={cls}>{entry}{"\n"}</span>
                                        );
                                    })}
                                </pre>
                            </div>
                        </details>
                    )}

                    {/* Export */}
                    <div className="flex gap-3 pt-4">
                        <button
                            onClick={() => {
                                const blob = new Blob([JSON.stringify(scan, null, 2)], { type: "application/json" });
                                const url = URL.createObjectURL(blob);
                                const a = document.createElement("a");
                                a.href = url;
                                a.download = `sqli_predator_${scan.id}.json`;
                                a.click();
                                URL.revokeObjectURL(url);
                            }}
                            className="text-sm bg-surface-card border border-surface-border px-4 py-2 rounded-lg text-gray-400 hover:text-white hover:border-gray-600 transition-colors"
                        >
                            📥 Export JSON
                        </button>
                        <button
                            onClick={() => {
                                const lines = [
                                    `# SQLi-PREDATOR Report — ${scan.target}`,
                                    `Scan ID: ${scan.id}`,
                                    `Date: ${new Date(scan.timestamp).toLocaleString()}`,
                                    `Duration: ${scan.duration?.toFixed(1)}s`,
                                    ``,
                                    `## Summary`,
                                    `Critical: ${findings.filter(f => f.severity === "Critical").length}`,
                                    `High: ${findings.filter(f => f.severity === "High").length}`,
                                    `Medium: ${findings.filter(f => f.severity === "Medium").length}`,
                                    `Low: ${findings.filter(f => f.severity === "Low").length}`,
                                    ``,
                                    `## Findings`,
                                    ...findings.map((f, i) => [
                                        `### [${f.severity}] Finding ${i + 1}: ${f.detectionMethod} on ${f.parameter}`,
                                        `- URL: ${f.url}`,
                                        `- Parameter: ${f.parameter}`,
                                        `- CVSS: ${f.cvssScore?.toFixed(1)} (${f.severity})`,
                                        `- Confidence: ${f.confidenceLevel} (${(f.confidence * 100).toFixed(0)}%)`,
                                        `- Detection: ${f.detectionMethod}`,
                                        `- DB Type: ${f.dbTypeHint}`,
                                        `- CWE: ${f.cweId}`,
                                        `- OWASP: ${f.owaspCategory}`,
                                        `- Payload: ${f.payloadUsed}`,
                                        ``,
                                        `**Analysis:**`,
                                        f.aiExplanation,
                                        ``,
                                        `**Remediation:**`,
                                        ...f.remediationSteps,
                                        ``,
                                    ].join("\n")),
                                ].join("\n");
                                const blob = new Blob([lines], { type: "text/markdown" });
                                const url = URL.createObjectURL(blob);
                                const a = document.createElement("a");
                                a.href = url;
                                a.download = `sqli_predator_${scan.id}.md`;
                                a.click();
                                URL.revokeObjectURL(url);
                            }}
                            className="text-sm bg-surface-card border border-surface-border px-4 py-2 rounded-lg text-gray-400 hover:text-white hover:border-gray-600 transition-colors"
                        >
                            📄 Export Markdown
                        </button>
                    </div>
                </>
            )}
        </div>
    );
}