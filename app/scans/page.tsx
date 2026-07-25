"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ScanResult, SEVERITY_COLORS } from "@/lib/types";

function normalizeFinding(f: any) {
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
        findings: (data.findings || []).map(normalizeFinding),
    };
}

export default function ScansPage() {
    const [scans, setScans] = useState<ScanResult[]>([]);
    const [loading, setLoading] = useState(true);
    const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
    const [confirmClearAll, setConfirmClearAll] = useState(false);

    useEffect(() => {
        const fetchScans = async () => {
            let combined: any[] = [];
            let deletedIds: string[] = [];

            try {
                const deletedRaw = localStorage.getItem("sqli_predator_deleted_scans");
                if (deletedRaw) deletedIds = JSON.parse(deletedRaw);
            } catch { }

            try {
                const resp = await fetch("/api/scans");
                if (resp.ok) {
                    const data = await resp.json();
                    if (Array.isArray(data)) combined.push(...data);
                }
            } catch { }

            try {
                const renderResp = await fetch("https://sqli-predator-api.onrender.com/api/scans");
                if (renderResp.ok) {
                    const renderData = await renderResp.json();
                    if (Array.isArray(renderData)) combined.push(...renderData);
                }
            } catch { }

            try {
                const localData = localStorage.getItem("sqli_predator_scans");
                if (localData) {
                    const parsed = JSON.parse(localData);
                    if (Array.isArray(parsed)) combined.push(...parsed);
                }
            } catch { }

            const map = new Map<string, any>();
            for (const item of combined) {
                if (item && item.id && !map.has(item.id) && !deletedIds.includes(item.id)) {
                    map.set(item.id, normalizeScanResult(item));
                }
            }

            const normalizedList = Array.from(map.values()).sort((a, b) => {
                const tA = new Date(a.timestamp || 0).getTime();
                const tB = new Date(b.timestamp || 0).getTime();
                return tB - tA;
            });

            setScans(normalizedList);
            try {
                localStorage.setItem("sqli_predator_scans", JSON.stringify(normalizedList));
            } catch { }
            setLoading(false);
        };

        fetchScans();
    }, []);

    const confirmDelete = (id: string, e: React.MouseEvent) => {
        e.preventDefault();
        e.stopPropagation();

        try {
            localStorage.removeItem(`sqli_scan_${id}`);
        } catch { }

        try {
            const deletedRaw = localStorage.getItem("sqli_predator_deleted_scans");
            const deleted: string[] = deletedRaw ? JSON.parse(deletedRaw) : [];
            if (!deleted.includes(id)) {
                deleted.push(id);
                localStorage.setItem("sqli_predator_deleted_scans", JSON.stringify(deleted));
            }
        } catch { }

        const updated = scans.filter((s) => s.id !== id);
        setScans(updated);
        try {
            localStorage.setItem("sqli_predator_scans", JSON.stringify(updated));
        } catch { }

        setConfirmDeleteId(null);
    };

    const clearAllHistory = () => {
        for (const scan of scans) {
            try {
                localStorage.removeItem(`sqli_scan_${scan.id}`);
            } catch { }
        }

        try {
            const deletedRaw = localStorage.getItem("sqli_predator_deleted_scans");
            const deleted: string[] = deletedRaw ? JSON.parse(deletedRaw) : [];
            for (const scan of scans) {
                if (scan.id && !deleted.includes(scan.id)) {
                    deleted.push(scan.id);
                }
            }
            localStorage.setItem("sqli_predator_deleted_scans", JSON.stringify(deleted));
        } catch { }

        try {
            localStorage.removeItem("sqli_predator_scans");
        } catch { }

        setScans([]);
        setConfirmClearAll(false);
    };

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between flex-wrap gap-3">
                <div>
                    <h1 className="text-2xl font-bold text-[#16231F]">Scan History</h1>
                    <p className="text-xs text-[#6B7A78] mt-0.5">Local scan traces and saved reports</p>
                </div>

                <div className="flex items-center gap-3">
                    {scans.length > 0 && (
                        <div>
                            {confirmClearAll ? (
                                <div className="flex items-center gap-2 bg-accent-red/10 border border-accent-red/30 px-3 py-1.5 rounded-lg">
                                    <span className="text-xs text-accent-red font-medium">Clear all local history?</span>
                                    <button
                                        onClick={clearAllHistory}
                                        className="text-xs bg-accent-red text-white px-2.5 py-1 rounded hover:bg-accent-red/80 transition-colors font-medium"
                                    >
                                        Yes, Clear All
                                    </button>
                                    <button
                                        onClick={() => setConfirmClearAll(false)}
                                        className="text-xs bg-surface text-gray-400 px-2.5 py-1 rounded hover:text-white transition-colors"
                                    >
                                        Cancel
                                    </button>
                                </div>
                            ) : (
                                <button
                                    onClick={() => setConfirmClearAll(true)}
                                    className="text-xs text-[#6B7A78] hover:text-accent-red border border-[#E9EDEC] hover:border-accent-red/40 px-3 py-1.5 rounded-full transition-colors font-medium flex items-center gap-1.5"
                                >
                                    🗑️ Clear All History
                                </button>
                            )}
                        </div>
                    )}

                    <Link
                        href="/"
                        className="text-sm bg-[#0F6E56] text-white px-4 py-2 rounded-full hover:bg-[#0F6E56]/90 transition-colors font-medium"
                    >
                        + New Scan
                    </Link>
                </div>
            </div>

            {loading ? (
                <div className="text-center py-12 text-[#6B7A78]">Loading scans...</div>
            ) : scans.length === 0 ? (
                <div className="text-center py-12 bg-white rounded-2xl">
                    <div className="text-4xl mb-3">🦅</div>
                    <p className="text-[#6B7A78]">No scans in history.</p>
                    <Link
                        href="/"
                        className="inline-block mt-3 text-sm text-[#0F6E56] hover:underline"
                    >
                        Start your first scan →
                    </Link>
                </div>
            ) : (
                <div className="space-y-3">
                    {scans.map((scan) => (
                        <Link
                            key={scan.id}
                            href={`/scans/${scan.id}`}
                            className="block bg-white rounded-2xl p-4 hover:shadow-sm transition-all relative group"
                        >
                            <div className="flex items-center justify-between">
                                <div>
                                    <p className="text-sm font-medium text-[#16231F]">{scan.target}</p>
                                    <p className="text-xs text-[#6B7A78] mt-1">
                                        {new Date(scan.timestamp).toLocaleString()} · {scan.findings?.length || 0} findings · ID: <code className="bg-[#E1F5EE] text-[#085041] px-1.5 py-0.5 rounded font-mono text-xs">{scan.id}</code>
                                    </p>
                                </div>
                                <div className="flex items-center gap-3">
                                    <span className={`text-xs px-2 py-1 rounded-full ${scan.status === "completed" ? "bg-accent-green/10 text-accent-green" :
                                            scan.status === "running" ? "bg-accent-blue/10 text-accent-blue pulse-active" :
                                                scan.status === "failed" ? "bg-accent-red/10 text-accent-red" :
                                                    "bg-gray-500/10 text-gray-400"
                                        }`}>
                                        {scan.status}
                                    </span>

                                    {/* Delete action */}
                                    {confirmDeleteId === scan.id ? (
                                        <div
                                            className="flex items-center gap-1.5 bg-accent-red/10 border border-accent-red/30 px-2 py-1 rounded-lg"
                                            onClick={(e) => { e.preventDefault(); e.stopPropagation(); }}
                                        >
                                            <span className="text-xs text-accent-red font-medium">Remove?</span>
                                            <button
                                                onClick={(e) => confirmDelete(scan.id, e)}
                                                className="text-xs bg-accent-red text-white px-2 py-0.5 rounded hover:bg-accent-red/80 transition-colors"
                                            >
                                                Yes
                                            </button>
                                            <button
                                                onClick={(e) => { e.preventDefault(); e.stopPropagation(); setConfirmDeleteId(null); }}
                                                className="text-xs bg-surface text-gray-400 px-2 py-0.5 rounded hover:text-white transition-colors"
                                            >
                                                No
                                            </button>
                                        </div>
                                    ) : (
                                        <button
                                            onClick={(e) => { e.preventDefault(); e.stopPropagation(); setConfirmDeleteId(scan.id); }}
                                            title="Remove scan from history"
                                            className="text-xs text-gray-500 hover:text-accent-red p-1 rounded hover:bg-surface-hover transition-colors opacity-70 group-hover:opacity-100"
                                        >
                                            🗑️
                                        </button>
                                    )}
                                </div>
                            </div>
                            {scan.status === "completed" && scan.findings && scan.findings.length > 0 && (
                                <div className="mt-3 flex gap-1.5 flex-wrap">
                                    {Object.entries(
                                        scan.findings.reduce((acc, f) => {
                                            acc[f.severity] = (acc[f.severity] || 0) + 1;
                                            return acc;
                                        }, {} as Record<string, number>)
                                    ).map(([sev, count]) => (
                                        <span
                                            key={sev}
                                            className="text-xs px-2 py-0.5 rounded-full"
                                            style={{
                                                background: `${SEVERITY_COLORS[sev] || '#888'}20`,
                                                color: SEVERITY_COLORS[sev] || '#888',
                                            }}
                                        >
                                            {sev}: {count}
                                        </span>
                                    ))}
                                </div>
                            )}
                        </Link>
                    ))}
                </div>
            )}
        </div>
    );
}