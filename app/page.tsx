"use client";

import { useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { ScanForm } from "@/components/ScanForm";
import { ScanProfile } from "@/lib/types";

export default function HomePage() {
    const router = useRouter();
    const [scanning, setScanning] = useState(false);
    const [scanId, setScanId] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);

    const handleStartScan = useCallback(async (profile: ScanProfile) => {
        setScanning(true);
        setError(null);

        try {
            const scanRequest = {
                target_url: profile.targetUrl,
                crawl_depth: profile.crawlDepth,
                request_delay: profile.requestDelay,
                timeout: profile.timeout,
                test_all_headers: profile.testAllHeaders,
                test_second_order: profile.testSecondOrder,
                boolean_threshold: profile.booleanThreshold,
                auth_cookie: profile.authCookie,
                auth_creds: profile.authCreds,
            };

            const resp = await fetch("https://sqli-predator-api.onrender.com/api/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(scanRequest),
            });

            if (!resp.ok) {
                const data = await resp.json();
                throw new Error(data.error || "Failed to start scan");
            }

            const data = await resp.json();
            setScanId(data.id);

            try {
                const initialScan = {
                    id: data.id,
                    timestamp: new Date().toISOString(),
                    target: profile.targetUrl,
                    status: "running",
                    progress: 0,
                    currentPhase: "Starting...",
                    findings: [],
                    duration: 0,
                };
                localStorage.setItem(`sqli_scan_${data.id}`, JSON.stringify(initialScan));
                const listRaw = localStorage.getItem("sqli_predator_scans");
                let list = listRaw ? JSON.parse(listRaw) : [];
                list.unshift(initialScan);
                localStorage.setItem("sqli_predator_scans", JSON.stringify(list));
            } catch {}

            router.push(`/scans/${data.id}`);
        } catch (err: any) {
            setError(err.message);
            setScanning(false);
        }
    }, [router]);

    return (
        <div className="space-y-8 pt-4 md:pt-6">
            {/* Hero */}
            <div className="text-center py-6">
                <h1 className="text-4xl font-bold text-[var(--text-primary)] mb-3">
                    🦅 SQLi-<span className="text-[var(--accent-primary)]">PREDATOR</span>
                </h1>
                <p className="text-[var(--text-secondary)] max-w-2xl mx-auto text-sm md:text-base leading-relaxed">
                    Advanced SQL Injection Detection Engine — Multi-Vector, Polymorphic,
                    OOB & Statistical Analysis. <strong className="text-accent-orange">Authorized use only.</strong>
                </p>
                <div className="flex gap-2.5 justify-center mt-5 flex-wrap">
                    <span className="text-xs bg-[var(--bg-pill-muted)] text-[var(--text-primary)] px-3 py-1.5 rounded-full border border-[var(--border-subtle)] hover:border-[var(--accent-primary)]/40 hover:scale-105 transition-all shadow-sm">
                        ⚠️ Error-Based
                    </span>
                    <span className="text-xs bg-[var(--bg-pill-muted)] text-[var(--text-primary)] px-3 py-1.5 rounded-full border border-[var(--border-subtle)] hover:border-[var(--accent-primary)]/40 hover:scale-105 transition-all shadow-sm">
                        🔍 Boolean Blind
                    </span>
                    <span className="text-xs bg-[var(--bg-pill-muted)] text-[var(--text-primary)] px-3 py-1.5 rounded-full border border-[var(--border-subtle)] hover:border-[var(--accent-primary)]/40 hover:scale-105 transition-all shadow-sm">
                        ⏱️ Time-Based (Statistical)
                    </span>
                    <span className="text-xs bg-[var(--bg-pill-muted)] text-[var(--text-primary)] px-3 py-1.5 rounded-full border border-[var(--border-subtle)] hover:border-[var(--accent-primary)]/40 hover:scale-105 transition-all shadow-sm">
                        🔗 UNION Probe
                    </span>
                    <span className="text-xs bg-[var(--bg-pill-muted)] text-[var(--text-primary)] px-3 py-1.5 rounded-full border border-[var(--border-subtle)] hover:border-[var(--accent-primary)]/40 hover:scale-105 transition-all shadow-sm">
                        🌐 OOB DNS/HTTP
                    </span>
                    <span className="text-xs bg-[var(--bg-pill-muted)] text-[var(--text-primary)] px-3 py-1.5 rounded-full border border-[var(--border-subtle)] hover:border-[var(--accent-primary)]/40 hover:scale-105 transition-all shadow-sm">
                        🔄 Second-Order
                    </span>
                </div>
            </div>

            {/* Auth Warning */}
            <div className="border border-accent-orange/30 bg-accent-orange/5 rounded-2xl p-4 max-w-3xl mx-auto">
                <p className="text-sm text-accent-orange flex items-center gap-2">
                    <span>⚠️</span>
                    <span>
                        <strong>AUTHORIZED USE ONLY.</strong> This tool detects SQL injection vulnerabilities.
                        Use exclusively against systems you own or have explicit written permission to test.
                        Unauthorized use is illegal.
                    </span>
                </p>
            </div>

            {/* Scan Form */}
            <div className="max-w-2xl mx-auto">
                <ScanForm onStart={handleStartScan} scanning={scanning} />

                {error && (
                    <div className="mt-4 p-3 bg-accent-red/10 border border-accent-red/30 rounded-xl">
                        <p className="text-accent-red text-sm">{error}</p>
                    </div>
                )}
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-3xl mx-auto">
                <div className="bg-[var(--bg-card)] rounded-2xl p-4 text-center border border-[var(--border-subtle)] border-t-2 border-t-[var(--accent-primary)] transition-all hover:scale-[1.02] shadow-sm">
                    <div className="text-xl mb-1">💣</div>
                    <div className="text-2xl font-bold text-[var(--accent-primary)] font-mono">460+</div>
                    <div className="text-xs text-[var(--text-secondary)] mt-1 font-medium">Base Payloads</div>
                </div>
                <div className="bg-[var(--bg-card)] rounded-2xl p-4 text-center border border-[var(--border-subtle)] border-t-2 border-t-[var(--accent-primary)] transition-all hover:scale-[1.02] shadow-sm">
                    <div className="text-xl mb-1">🛡️</div>
                    <div className="text-2xl font-bold text-[var(--accent-primary)] font-mono">8</div>
                    <div className="text-xs text-[var(--text-secondary)] mt-1 font-medium">Detection Methods</div>
                </div>
                <div className="bg-[var(--bg-card)] rounded-2xl p-4 text-center border border-[var(--border-subtle)] border-t-2 border-t-[var(--accent-primary)] transition-all hover:scale-[1.02] shadow-sm">
                    <div className="text-xl mb-1">🎯</div>
                    <div className="text-2xl font-bold text-[var(--accent-primary)] font-mono">7</div>
                    <div className="text-xs text-[var(--text-secondary)] mt-1 font-medium">Injection Vectors</div>
                </div>
                <div className="bg-[var(--bg-card)] rounded-2xl p-4 text-center border border-[var(--border-subtle)] border-t-2 border-t-[var(--accent-primary)] transition-all hover:scale-[1.02] shadow-sm">
                    <div className="text-xl mb-1">🧬</div>
                    <div className="text-2xl font-bold text-[var(--accent-primary)] font-mono">∞</div>
                    <div className="text-xs text-[var(--text-secondary)] mt-1 font-medium">Polymorphic Variants</div>
                </div>
            </div>
        </div>
    );
}