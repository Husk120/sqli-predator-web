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
        <div className={`finding-card overflow-hidden ${finding.likelyFalsePositive ? 'opacity-80' : ''}`}>
            {/* Card Header */}
            <div
                className={`flex items-center gap-2 p-3 flex-wrap cursor-pointer hover:bg-surface-hover/30 transition-colors border-b ${finding.likelyFalsePositive ? 'border-yellow-500/30 bg-yellow-500/5' : 'border-surface-border'}`}
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
                {finding.likelyFalsePositive && (
                    <span className="text-xs px-2 py-0.5 rounded-full font-medium bg-yellow-500/20 text-yellow-500 border border-yellow-500/30">
                        ⚠️ Likely False Positive
                    </span>
                )}
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
                    {/* False Positive Reason */}
                    {finding.likelyFalsePositive && finding.falsePositiveReason && (
                        <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-3">
                            <p className="text-xs font-semibold text-yellow-500 mb-1">⚠️ False Positive Warning</p>
                            <p className="text-xs text-gray-400 leading-relaxed">{finding.falsePositiveReason}</p>
                        </div>
                    )}

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

function normalizeFinding(f: any): SQLiFinding {
    return {
        ...f,
        payloadUsed: f.payloadUsed ?? f.payload_used ?? "",
        responseDifferencePercent: f.responseDifferencePercent ?? f.response_difference_pct ?? f.response_difference_percent ?? 0,
        dbTypeHint: f.dbTypeHint ?? f.db_type_hint ?? "unknown",
        hasSqlErrors: f.hasSqlErrors ?? f.has_sql_errors ?? false,
        errorSignatures: f.errorSignatures ?? f.error_signatures ?? [],
        cvssScore: f.cvssScore ?? f.cvss_score ?? 0,
        confidenceLevel: f.confidenceLevel ?? f.confidence_level ?? "Tentative",
        detectionMethod: f.detectionMethod ?? f.detection_method ?? "",
        timeDelayDetected: f.timeDelayDetected ?? f.time_delay_detected ?? false,
        timeDelaySeconds: f.timeDelaySeconds ?? f.time_delay_seconds ?? 0,
        timingZScore: f.timingZScore ?? f.timing_z_score ?? 0,
        timingPValue: f.timingPValue ?? f.timing_p_value ?? 0,
        isBooleanPositive: f.isBooleanPositive ?? f.is_boolean_positive ?? null,
        oobInteractionId: f.oobInteractionId ?? f.oob_interaction_id ?? "",
        baselineLength: f.baselineLength ?? f.baseline_length ?? 0,
        testLength: f.testLength ?? f.test_length ?? 0,
        baselineTime: f.baselineTime ?? f.baseline_time ?? 0,
        testTime: f.testTime ?? f.test_time ?? 0,
        aiExplanation: f.aiExplanation ?? f.ai_explanation ?? f.description ?? "",
        remediationSteps: f.remediationSteps ?? f.remediation_steps ?? f.remediation ?? [],
        vulnerabilityClass: f.vulnerabilityClass ?? f.vulnerability_class ?? "SQL Injection",
        rawResponseSnippet: f.rawResponseSnippet ?? f.raw_response_snippet ?? "",
        pocRequest: f.pocRequest ?? f.poc_request ?? "",
        cweId: f.cweId ?? f.cwe_id ?? "CWE-89",
        owaspCategory: f.owaspCategory ?? f.owasp_category ?? "A03:2021",
        bypassTechnique: f.bypassTechnique ?? f.bypass_technique ?? "NONE",
        likelyFalsePositive: f.likelyFalsePositive ?? f.likely_false_positive ?? false,
        falsePositiveReason: f.falsePositiveReason ?? f.false_positive_reason ?? "",
    };
}

function normalizeScanResult(data: any): ScanResult {
    if (!data) return data;
    let ts = data.timestamp ?? data.created_at ?? data.createdAt;
    if (!ts || isNaN(new Date(ts).getTime())) {
        ts = new Date().toISOString();
    } else {
        ts = new Date(ts).toISOString();
    }
    return {
        ...data,
        id: data.id ?? data.scan_id ?? data.scanId ?? "",
        target: data.target ?? data.target_url ?? data.targetUrl ?? "",
        timestamp: ts,
        status: data.status ?? "idle",
        progress: data.progress ?? 0,
        currentPhase: data.currentPhase ?? data.current_phase ?? "",
        duration: data.duration ?? data.duration_seconds ?? 0,
        scanLog: data.scanLog ?? data.scan_log ?? data.logs ?? [],
        findings: (data.findings || []).map(normalizeFinding),
    };
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

    useEffect(() => {
        console.log(`[SQLi-PREDATOR] ScanDetailPage mounted for ID: "${id}"`);
    }, [id]);

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
                if (item) return normalizeScanResult(JSON.parse(item));
            } catch { }

            try {
                const listRaw = localStorage.getItem("sqli_predator_scans");
                if (listRaw) {
                    const list: ScanResult[] = JSON.parse(listRaw);
                    const found = list.find((s) => s.id === id);
                    if (found) return normalizeScanResult(found);
                }
            } catch { }

            return null;
        };

        const fetchScanData = async (): Promise<{ statusResp: Response | null; data: any | null }> => {
            // 1. Try Render API backend
            try {
                const renderResp = await fetch(`https://sqli-predator-api.onrender.com/api/scan/${id}/status`);
                if (renderResp.ok) {
                    const data = await renderResp.json();
                    return { statusResp: renderResp, data };
                }
            } catch { }

            // 2. Fallback to local Vercel API route
            try {
                const localResp = await fetch(`/api/scan/status/${id}`);
                if (localResp.ok) {
                    const data = await localResp.json();
                    return { statusResp: localResp, data };
                }
            } catch { }

            return { statusResp: null, data: null };
        };

        const fetchReportData = async (): Promise<any | null> => {
            // 1. Try Render API report
            try {
                const renderReportResp = await fetch(`https://sqli-predator-api.onrender.com/api/scan/${id}/report`);
                if (renderReportResp.ok) {
                    return await renderReportResp.json();
                }
            } catch { }

            // 2. Fallback to local Vercel API report
            try {
                const localReportResp = await fetch(`/api/report/${id}`);
                if (localReportResp.ok) {
                    return await localReportResp.json();
                }
            } catch { }

            return null;
        };

        const poll = async () => {
            if (!isMounted) return;

            try {
                const { statusResp, data } = await fetchScanData();

                if (!statusResp || !data) {
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
                            "Unable to reach the scan server. The scan may have timed out or expired. " +
                            "Please try starting a new scan."
                        );
                    }
                    if (isMounted) setLoading(false);
                    return;
                }

                retryCountRef.current = 0;
                if (isMounted) setPollError(null);

                const normalizedData = normalizeScanResult(data);

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
                        const rawReport = await fetchReportData();
                        if (rawReport) {
                            const report: ScanResult = normalizeScanResult(rawReport);
                            if (isMounted) { setScan(report); saveToLocal(report); }
                        } else {
                            if (isMounted) setScan(normalizedData);
                        }
                    } else {
                        if (isMounted) setScan(normalizedData);
                    }
                    if (isMounted) setLoading(false);
                    return;
                }

                if (isMounted) setScan(normalizedData);
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
                        <Link href="/scans" className="text-sm text-[#6B7A78] hover:text-[#16231F]">← Back</Link>
                        <span className="text-[#8A9694]">|</span>
                        <h1 className="text-xl font-bold text-[#16231F]">Scan Report</h1>
                    </div>
                    <p className="text-sm text-[#6B7A78]">
                        Target: <code className="text-[#0F6E56] font-mono bg-[#E1F5EE] border-0">{scan.target}</code>
                    </p>
                    <p className="text-xs text-[#8A9694] mt-0.5">
                        {new Date(scan.timestamp).toLocaleString()} · ID: <code className="text-[#8A9694] font-mono bg-[#E9EDEC] border-0">{scan.id}</code>
                    </p>
                </div>

                <div className="flex items-center gap-3">
                    {scan.status === "running" && (
                        <>
                            <div className="flex items-center gap-2 text-[#085041] text-sm pulse-active px-3 py-1.5 rounded-full bg-[#E1F5EE] font-medium">
                                <svg className="animate-spin h-4 w-4 text-[#0F6E56]" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                                </svg>
                                Scanning Active...
                            </div>
                            <button
                                onClick={handleStopScan}
                                disabled={stopping}
                                className="text-xs bg-[#D9381E] text-white hover:bg-[#B92B14] px-4 py-2 rounded-full transition-all font-semibold flex items-center gap-2 shadow-sm disabled:opacity-50"
                            >
                                <span className="h-2 w-2 rounded-full bg-white animate-pulse" />
                                {stopping ? "Stopping..." : "Stop Scan"}
                            </button>
                        </>
                    )}
                    {scan.status === "completed" && (
                        <span className="text-xs bg-[#E1F5EE] text-[#085041] px-3.5 py-2 rounded-full font-semibold flex items-center gap-1.5">
                            ✅ Complete ({scan.duration?.toFixed(1)}s)
                        </span>
                    )}
                    {scan.status === "stopped" && (
                        <span className="text-xs bg-yellow-500/10 text-yellow-600 px-3.5 py-2 rounded-full font-semibold flex items-center gap-1.5">
                            🛑 Stopped
                        </span>
                    )}
                    {scan.status === "failed" && (
                        <span className="text-xs bg-[#FAECE7] text-[#993C1D] px-3.5 py-2 rounded-full font-semibold flex items-center gap-1.5">❌ Failed</span>
                    )}
                </div>
            </div>

            {/* Scan in Progress Redesign */}
            {scan.status === "running" && (
                <div className="space-y-4">
                    {/* Pipeline & Stepper Card */}
                    <div className="bg-white rounded-2xl p-5 space-y-4 relative overflow-hidden">
                        <div className="flex items-center justify-between">
                            <div>
                                <h2 className="text-sm font-bold text-[#16231F] flex items-center gap-2">
                                    <span className="relative flex h-2.5 w-2.5">
                                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#0F6E56] opacity-75"></span>
                                        <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-[#0F6E56]"></span>
                                    </span>
                                    Scan Pipeline Progress
                                </h2>
                                <p className="text-xs text-[#6B7A78] mt-0.5">{scan.currentPhase || "Executing security probes..."}</p>
                            </div>
                            <div className="text-right">
                                <span className="text-2xl font-extrabold text-[#0F6E56] font-mono">{scan.progress?.toFixed(0) || 0}%</span>
                            </div>
                        </div>

                        {/* Enhanced Animated Progress Bar */}
                        <div className="w-full bg-[#E9EDEC] rounded-full h-3.5 p-0.5 overflow-hidden">
                            <div
                                className="h-full rounded-full bg-[#0F6E56] transition-all duration-700 relative overflow-hidden"
                                style={{ width: `${Math.max(scan.progress || 0, 3)}%` }}
                            >
                                <div className="absolute inset-0 bg-white/20 animate-pulse" />
                            </div>
                        </div>

                        {/* Visual Phase Timeline Stepper */}
                        {(() => {
                            const steps = [
                                { label: "Discovery", sub: "Crawl & Tech Stack" },
                                { label: "Form Testing", sub: "Inputs & Payloads" },
                                { label: "URL Params", sub: "Query String" },
                                { label: "Headers", sub: "HTTP Headers" },
                                { label: "Finalize", sub: "Report Generation" },
                            ];
                            const p = (scan.currentPhase || "").toLowerCase();
                            const progress = scan.progress || 0;
                            let activeIdx = 0;
                            if (progress >= 100 || p.includes("complete") || p.includes("finalize")) activeIdx = 4;
                            else if (p.includes("header") || progress >= 80) activeIdx = 3;
                            else if (p.includes("param") || progress >= 65) activeIdx = 2;
                            else if (p.includes("form") || progress >= 20) activeIdx = 1;

                            return (
                                <div className="grid grid-cols-5 gap-2 pt-3 border-t border-[#E9EDEC]">
                                    {steps.map((step, idx) => {
                                        const isCompleted = idx < activeIdx;
                                        const isCurrent = idx === activeIdx;
                                        return (
                                            <div key={idx} className="flex flex-col items-center text-center group">
                                                <div
                                                    className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold transition-all ${
                                                        isCompleted
                                                            ? "bg-[#0F6E56] text-white font-extrabold"
                                                            : isCurrent
                                                            ? "bg-[#0F6E56] text-white ring-4 ring-[#0F6E56]/20 animate-pulse"
                                                            : "bg-[#E9EDEC] text-[#8A9694]"
                                                    }`}
                                                >
                                                    {isCompleted ? "✓" : idx + 1}
                                                </div>
                                                <span className={`text-xs mt-2 font-medium ${isCurrent ? "text-[#0F6E56]" : isCompleted ? "text-[#16231F]" : "text-[#8A9694]"}`}>
                                                    {step.label}
                                                </span>
                                                <span className="text-[10px] text-[#8A9694] hidden md:block mt-0.5">{step.sub}</span>
                                            </div>
                                        );
                                    })}
                                </div>
                            );
                        })()}

                        {isStalled && (
                            <div className="bg-yellow-500/10 rounded-xl p-3 mt-2">
                                <p className="text-xs text-yellow-700 leading-relaxed font-medium">
                                    ⚠️ Scan progress has not changed for over 90 seconds. Serverless processing may be delayed or cold-starting.
                                </p>
                            </div>
                        )}
                    </div>

                    {/* Live Activity Feed Area */}
                    <div className="bg-white rounded-2xl p-4 space-y-2.5">
                        <div className="flex items-center justify-between border-b border-[#E9EDEC] pb-2">
                            <h3 className="text-xs font-semibold text-[#16231F] flex items-center gap-2">
                                <span className="h-2 w-2 rounded-full bg-[#0F6E56] animate-ping" />
                                Live Activity Feed
                            </h3>
                            <span className="text-[11px] text-[#8A9694] font-mono">
                                {scan.scanLog?.length || 0} entries recorded
                            </span>
                        </div>

                        <div className="bg-[#F5F7F6] rounded-xl p-3 max-h-60 overflow-y-auto font-mono text-xs space-y-1 text-[#16231F]">
                            {scan.scanLog && scan.scanLog.length > 0 ? (
                                scan.scanLog.slice(-20).map((entry, i) => {
                                    let cls = "text-[#6B7A78]";
                                    if (entry.includes("FINDING:")) cls = "text-[#993C1D] font-semibold";
                                    else if (entry.includes("BOOLEAN CONFIRMED:")) cls = "text-[#0F6E56] font-semibold";
                                    else if (entry.includes("[ERROR]")) cls = "text-yellow-700";
                                    else if (entry.includes("═══")) cls = "text-[#16231F] font-semibold";
                                    else if (entry.includes("──")) cls = "text-[#8A9694]";
                                    else if (entry.includes("Tech stack:")) cls = "text-[#085041]";
                                    return (
                                        <div key={i} className={`leading-relaxed ${cls}`}>
                                            {entry}
                                        </div>
                                    );
                                })
                            ) : (
                                <div className="text-[#8A9694] text-center py-6 italic text-xs">
                                    Initializing scanner engine... Executing baseline checks and payload injections...
                                </div>
                            )}
                        </div>
                    </div>
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