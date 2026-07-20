"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ScanResult, SEVERITY_COLORS } from "@/lib/types";

export default function ScansPage() {
    const [scans, setScans] = useState<ScanResult[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchScans = async () => {
            try {
                const resp = await fetch("/api/scans");
                if (resp.ok) {
                    const data: ScanResult[] = await resp.json();
                    if (data && data.length > 0) {
                        setScans(data);
                        // Save to localStorage as backup
                        try {
                            localStorage.setItem("sqli_predator_scans", JSON.stringify(data));
                        } catch {}
                        setLoading(false);
                        return;
                    }
                }
            } catch {}

            // Fallback to localStorage if API returned empty or failed
            try {
                const localData = localStorage.getItem("sqli_predator_scans");
                if (localData) {
                    setScans(JSON.parse(localData));
                }
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