"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { ScanResult, SEVERITY_COLORS, DETECTION_ICONS } from "@/lib/types";

export default function ScanDetailPage() {
    const params = useParams();
    const id = params.id as string;
    const [scan, setScan] = useState<ScanResult | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const poll = async () => {
            try {
                const resp = await fetch(`/api/scan/status/${id}`);
                if (!resp.ok) throw new Error("Not found");
                const data = await resp.json();

                if (data.status === "completed" || data.status === "failed") {
                    // Fetch full report
                    const reportResp = await fetch(`/api/report/${id}`);
                    if (reportResp.ok) {
                        const report = await reportResp.json();
                        setScan(report);
                    } else {
                        setScan(data as any);
                    }
                    setLoading(false);
                    return;
                }

                setScan(data as any);

                if (data.status === "running") {
                    setTimeout(poll, 2000);
                } else {
                    setLoading(false);
                }
            } catch {
                setLoading(false);
            }
        };

        poll();
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

    if (!scan) {
        return (
            <div className="text-center py-24">
                <p className="text-gray-500 mb-4">Scan not found</p>
                <Link href="/" className="text-accent-blue hover:underline text-sm">
                    Start a new scan
                </Link>
            </div>
        );
    }

    return (
        <div className="space-y-6 max-w-4xl mx-auto">
            {/* Header */}
            <div className="flex items-start justify-between">
                <div>
                    <div className="flex items-center gap-2 mb-1">
                        <Link href="/scans" className="text-sm text-gray-500 hover:text-gray-400">
                            ← Back
                        </Link>
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
                        <div className="flex items-center gap-2 text-accent-blue text-sm pulse-active px-3 py-1.5 rounded-lg border border-accent-blue/30">
                            <svg className="animate-spin h-3.5 w-3.5" viewBox="0 0 24 24">
                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                            </svg>
                            Scanning...
                        </div>
                    )}
                    {scan.status === "completed" && (
                        <span className="text-xs bg-accent-green/10 text-accent-green px-3 py-1.5 rounded-lg">
                            ✅ Complete ({scan.duration?.toFixed(1)}s)
                        </span>
                    )}
                    {scan.status === "failed" && (
                        <span className="text-xs bg-accent-red/10 text-accent-red px-3 py-1.5 rounded-lg">
                            ❌ Failed
                        </span>
                    )}
                </div>
            </div>

            {/* Progress bar (if running) */}
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
                </div>
            )}

            {/* Error */}
            {scan.error && (
                <div className="bg-accent-red/5 border border-accent-red/20 rounded-lg p-3">
                    <p className="text-sm text-accent-red">{scan.error}</p>
                </div>
            )}

            {/* Severity Summary */}
            {scan.status === "completed" && (
                <>
                    <div className="grid grid-cols-5 gap-2">
                        {["Critical", "High", "Medium", "Low", "Info"].map((sev) => {
                            const count = scan.findings.filter((f) => f.severity === sev).length;
                            const color = SEVERITY_COLORS[sev];
                            return (
                                <div
                                    key={sev}
                                    className="bg-surface-card border border-surface-border rounded-lg p-3 text-center"
                                >
                                    <div className="text-2xl font-bold" style={{ color }}>
                                        {count}
                                    </div>
                                    <div className="text-xs text-gray-500 mt-0.5">{sev}</div>
                                </div>
                            );
                        })}
                    </div>

                    {/* Findings */}
                    {scan.findings.length === 0 ? (
                        <div className="text-center py-12 text-gray-500 border border-dashed border-surface-border rounded-xl">
                            <div className="text-3xl mb-2">✅</div>
                            <p>No SQL injection vulnerabilities detected.</p>
                        </div>
                    ) : (
                        <div className="space-y-4">
                            <h2 className="text-lg font-semibold text-white">
                                Findings ({scan.findings.length})
                            </h2>
                            {scan.findings.map((finding, i) => {
                                const color = SEVERITY_COLORS[finding.severity] || "#6c757d";
                                const icon = DETECTION_ICONS[finding.detectionMethod] || "💉";
                                return (
                                    <div
                                        key={finding.id}
                                        className="finding-card overflow-hidden"
                                    >
                                        {/* Header */}
                                        <div className="flex items-center gap-2 p-3 border-b border-surface-border flex-wrap">
                                            <span
                                                className="text-xs font-semibold px-2 py-0.5 rounded-full text-white"
                                                style={{ background: color }}
                                            >
                                                {finding.severity}
                                            </span>
                                            <span className="text-xs bg-surface-hover px-2 py-0.5 rounded-full text-gray-400">
                                                {icon} {finding.detectionMethod.replace(/_/g, " ").trim()}
                                            </span>
                                            <span className="text-xs bg-surface-hover px-2 py-0.5 rounded-full text-gray-400">
                                                CVSS {finding.cvssScore?.toFixed(1)}
                                            </span>
                                            <span className="text-xs bg-surface-hover px-2 py-0.5 rounded-full text-gray-400">
                                                {Math.round(finding.confidence * 100)}% confidence
                                            </span>
                                        </div>

                                        {/* Body */}
                                        <div className="p-3 space-y-3">
                                            <p className="text-sm text-white">
                                                <span className="text-gray-500">#{i + 1}:</span>{" "}
                                                <code className="text-accent-orange">{finding.parameter}</code>{" "}
                                                on <span className="text-gray-400">{finding.url}</span>
                                            </p>

                                            <div className="grid grid-cols-2 md:grid-cols-3 gap-2 text-xs">
                                                <div>
                                                    <span className="text-gray-600 block">Vector</span>
                                                    <code>{finding.vector}</code>
                                                </div>
                                                <div>
                                                    <span className="text-gray-600 block">DB Type</span>
                                                    <code>{finding.dbTypeHint}</code>
                                                </div>
                                                <div>
                                                    <span className="text-gray-600 block">Bypass</span>
                                                    <code>{finding.bypassTechnique}</code>
                                                </div>
                                                {finding.timeDelayDetected && (
                                                    <div>
                                                        <span className="text-gray-600 block">Delay</span>
                                                        <code className="text-accent-orange">
                                                            {finding.timeDelaySeconds?.toFixed(2)}s
                                                            {finding.timingZScore ? ` (Z=${finding.timingZScore.toFixed(1)})` : ""}
                                                        </code>
                                                    </div>
                                                )}
                                                {finding.responseDifferencePercent > 0 && (
                                                    <div>
                                                        <span className="text-gray-600 block">Content Diff</span>
                                                        <code>{finding.responseDifferencePercent.toFixed(1)}%</code>
                                                    </div>
                                                )}
                                                {finding.errorSignatures?.length > 0 && (
                                                    <div className="col-span-2">
                                                        <span className="text-gray-600 block">Error Signatures</span>
                                                        <div className="flex flex-wrap gap-1 mt-0.5">
                                                            {finding.errorSignatures.slice(0, 3).map((s, si) => (
                                                                <span key={si} className="text-accent-red bg-accent-red/5 px-1.5 py-0.5 rounded text-xs">
                                                                    {s}
                                                                </span>
                                                            ))}
                                                        </div>
                                                    </div>
                                                )}
                                            </div>

                                            {/* Payload */}
                                            <div>
                                                <span className="text-xs text-gray-600 block mb-0.5">Payload</span>
                                                <pre className="text-xs max-h-20 overflow-y-auto">
                                                    <code>{finding.payloadUsed}</code>
                                                </pre>
                                            </div>

                                            {/* AI Explanation */}
                                            <details>
                                                <summary className="text-xs text-accent-blue cursor-pointer hover:text-accent-blue/80">
                                                    📖 Educational Explanation
                                                </summary>
                                                <p className="text-xs text-gray-400 mt-2 leading-relaxed">
                                                    {finding.aiExplanation}
                                                </p>
                                            </details>

                                            {/* Remediation */}
                                            <details>
                                                <summary className="text-xs text-accent-green cursor-pointer hover:text-accent-green/80">
                                                    🛡️ Remediation
                                                </summary>
                                                <ol className="text-xs text-gray-400 mt-2 space-y-1 list-decimal list-inside">
                                                    {finding.remediationSteps.map((step, si) => (
                                                        <li key={si}>{step}</li>
                                                    ))}
                                                </ol>
                                            </details>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}

                    {/* Export */}
                    <div className="flex gap-3 pt-4">
                        <button
                            onClick={() => {
                                const blob = new Blob([JSON.stringify(scan, null, 2)], { type: "application/json" });
                                const url = URL.createObjectURL(blob);
                                const a = document.createElement("a");
                                a.href = url;
                                a.download = `sqli_scan_${scan.id}.json`;
                                a.click();
                                URL.revokeObjectURL(url);
                            }}
                            className="text-sm bg-surface-card border border-surface-border px-4 py-2 rounded-lg text-gray-400 hover:text-white hover:border-gray-600 transition-colors"
                        >
                            📥 Export JSON
                        </button>
                    </div>
                </>
            )}
        </div>
    );
}