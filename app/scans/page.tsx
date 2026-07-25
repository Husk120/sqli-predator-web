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
    return {
        ...data,
        target: data.target ?? data.target_url ?? "",
        findings: (data.findings || []).map(normalizeFinding),
    };
}

export default function ScansPage() {
    const [scans, setScans] = useState<ScanResult[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchScans = async () => {
            let combined: any[] = [];

            try {
                const resp = await fetch("/api/scans");
                if (resp.ok) {
                    const data = await resp.json();
                    if (Array.isArray(data)) combined.push(...data);
                }
            } catch {}

            try {
                const renderResp = await fetch("https://sqli-predator-api.onrender.com/api/scans");
                if (renderResp.ok) {
                    const renderData = await renderResp.json();
                    if (Array.isArray(renderData)) combined.push(...renderData);
                }
            } catch {}

            try {
                const localData = localStorage.getItem("sqli_predator_scans");
                if (localData) {
                    const parsed = JSON.parse(localData);
                    if (Array.isArray(parsed)) combined.push(...parsed);
                }
            } catch {}

            const map = new Map<string, any>();
            for (const item of combined) {
                if (item && item.id && !map.has(item.id)) {
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
            } catch {}
            setLoading(false);
        };

        fetchScans();
    }, []);

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <h1 className="text-2xl font-bold text-white">Scan History</h1>
                <Link
                    href="/"
                    className="text-sm bg-accent-blue text-white px-4 py-2 rounded-lg hover:bg-accent-blue/80 transition-colors"
                >
                    + New Scan
                </Link>
            </div>

            {loading ? (
                <div className="text-center py-12 text-gray-500">Loading scans...</div>
            ) : scans.length === 0 ? (
                <div className="text-center py-12 border border-dashed border-surface-border rounded-xl">
                    <div className="text-4xl mb-3">🦅</div>
                    <p className="text-gray-500">No scans yet.</p>
                    <Link
                        href="/"
                        className="inline-block mt-3 text-sm text-accent-blue hover:underline"
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
                            className="block bg-surface-card border border-surface-border rounded-lg p-4 hover:border-gray-600 transition-colors"
                        >
                            <div className="flex items-center justify-between">
                                <div>
                                    <p className="text-sm font-medium text-white">{scan.target}</p>
                                    <p className="text-xs text-gray-500 mt-1">
                                        {new Date(scan.timestamp).toLocaleString()} · {scan.findings?.length || 0} findings
                                    </p>
                                </div>
                                <div className="flex items-center gap-2">
                                    <span className={`text-xs px-2 py-1 rounded-full ${
                                        scan.status === "completed" ? "bg-accent-green/10 text-accent-green" :
                                        scan.status === "running" ? "bg-accent-blue/10 text-accent-blue pulse-active" :
                                        scan.status === "failed" ? "bg-accent-red/10 text-accent-red" :
                                        "bg-gray-500/10 text-gray-400"
                                    }`}>
                                        {scan.status}
                                    </span>
                                </div>
                            </div>
                            {scan.status === "completed" && scan.findings && scan.findings.length > 0 && (
                                <div className="mt-3 flex gap-1.5">
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