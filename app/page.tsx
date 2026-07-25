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
        <div className="space-y-6 pt-2 md:pt-4 max-w-6xl mx-auto">
            {/* Hero Header */}
            <div className="text-center py-2">
                <h1 className="text-4xl font-bold text-[var(--text-primary)] mb-2">
                    🦅 SQLi-<span className="text-[var(--accent-primary)]">PREDATOR</span>
                </h1>
                <p className="text-[var(--text-secondary)] max-w-2xl mx-auto text-sm md:text-base leading-relaxed">
                    Advanced SQL Injection Detection Engine — Multi-Vector, Polymorphic,
                    OOB & Statistical Analysis.
                </p>
            </div>

            {/* Slim Auth Warning Strip */}
            <div className="border border-accent-orange/30 bg-accent-orange/5 rounded-xl px-4 py-2.5 max-w-4xl mx-auto">
                <p className="text-xs md:text-sm text-accent-orange flex items-center justify-center gap-2 text-center">
                    <span>⚠️</span>
                    <span>
                        <strong>AUTHORIZED USE ONLY:</strong> Use exclusively against systems you own or have explicit written permission to test.
                    </span>
                </p>
            </div>

            {/* Main Content Area: Target Radar (Left) + Scan Form (Right) */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 lg:gap-8 items-start pt-2">
                {/* Left Column: Radar Visual + Compact Stats + Badges */}
                <div className="lg:col-span-5 space-y-5">
                    {/* Radar Centerpiece */}
                    <div className="bg-[var(--bg-card)] rounded-2xl p-6 border border-[var(--border-subtle)] relative overflow-hidden shadow-sm flex flex-col items-center justify-center text-center">
                        <div className="text-xs font-mono font-semibold tracking-widest text-[var(--text-secondary)] uppercase mb-4 flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full bg-[var(--accent-primary)] animate-pulse inline-block"></span>
                            TARGET RADAR // ACTIVE
                        </div>

                        {/* Pure SVG Radar Graphic */}
                        <div className="relative w-48 h-48 my-2 flex items-center justify-center">
                            <svg className="w-full h-full" viewBox="0 0 200 200" fill="none" xmlns="http://www.w3.org/2000/svg">
                                {/* Outer border circle */}
                                <circle cx="100" cy="100" r="95" stroke="var(--border-subtle)" strokeWidth="1.5" />
                                {/* Concentric circles */}
                                <circle cx="100" cy="100" r="75" stroke="var(--accent-primary)" strokeWidth="1" strokeOpacity="0.25" strokeDasharray="4 4" />
                                <circle cx="100" cy="100" r="50" stroke="var(--accent-primary)" strokeWidth="1" strokeOpacity="0.35" />
                                <circle cx="100" cy="100" r="25" stroke="var(--accent-primary)" strokeWidth="1" strokeOpacity="0.45" strokeDasharray="2 2" />
                                <circle cx="100" cy="100" r="4" fill="var(--accent-primary)" />

                                {/* Crosshair lines */}
                                <line x1="100" y1="5" x2="100" y2="195" stroke="var(--accent-primary)" strokeWidth="1" strokeOpacity="0.3" />
                                <line x1="5" y1="100" x2="195" y2="100" stroke="var(--accent-primary)" strokeWidth="1" strokeOpacity="0.3" />
                                <line x1="30" y1="30" x2="170" y2="170" stroke="var(--accent-primary)" strokeWidth="0.5" strokeOpacity="0.15" />
                                <line x1="170" y1="30" x2="30" y2="170" stroke="var(--accent-primary)" strokeWidth="0.5" strokeOpacity="0.15" />

                                {/* Detected Indicators (Colored Dots) */}
                                <g className="animate-pulse">
                                    <circle cx="135" cy="65" r="5" fill="var(--accent-primary)" />
                                    <circle cx="135" cy="65" r="9" stroke="var(--accent-primary)" strokeWidth="1" strokeOpacity="0.5" />
                                </g>
                                <g className="animate-pulse" style={{ animationDelay: "700ms" }}>
                                    <circle cx="70" cy="140" r="4" fill="currentColor" className="text-accent-orange" />
                                    <circle cx="70" cy="140" r="8" stroke="currentColor" strokeWidth="1" strokeOpacity="0.5" className="text-accent-orange" />
                                </g>
                            </svg>
                        </div>

                        <div className="text-[11px] text-[var(--text-secondary)] font-mono mt-2">
                            VECTOR SCANNING: <span className="text-[var(--text-primary)] font-medium">READY</span>
                        </div>
                    </div>

                    {/* Compact Stats Grid */}
                    <div className="grid grid-cols-2 gap-3">
                        <div className="bg-[var(--bg-card)] rounded-xl p-3 text-center border border-[var(--border-subtle)] border-t-2 border-t-[var(--accent-primary)] transition-all hover:scale-[1.02] shadow-sm">
                            <div className="text-lg mb-0.5">💣</div>
                            <div className="text-xl font-bold text-[var(--accent-primary)] font-mono">460+</div>
                            <div className="text-[11px] text-[var(--text-secondary)] mt-0.5 font-medium">Base Payloads</div>
                        </div>
                        <div className="bg-[var(--bg-card)] rounded-xl p-3 text-center border border-[var(--border-subtle)] border-t-2 border-t-[var(--accent-primary)] transition-all hover:scale-[1.02] shadow-sm">
                            <div className="text-lg mb-0.5">🛡️</div>
                            <div className="text-xl font-bold text-[var(--accent-primary)] font-mono">8</div>
                            <div className="text-[11px] text-[var(--text-secondary)] mt-0.5 font-medium">Detection Methods</div>
                        </div>
                        <div className="bg-[var(--bg-card)] rounded-xl p-3 text-center border border-[var(--border-subtle)] border-t-2 border-t-[var(--accent-primary)] transition-all hover:scale-[1.02] shadow-sm">
                            <div className="text-lg mb-0.5">🎯</div>
                            <div className="text-xl font-bold text-[var(--accent-primary)] font-mono">7</div>
                            <div className="text-[11px] text-[var(--text-secondary)] mt-0.5 font-medium">Injection Vectors</div>
                        </div>
                        <div className="bg-[var(--bg-card)] rounded-xl p-3 text-center border border-[var(--border-subtle)] border-t-2 border-t-[var(--accent-primary)] transition-all hover:scale-[1.02] shadow-sm">
                            <div className="text-lg mb-0.5">🧬</div>
                            <div className="text-xl font-bold text-[var(--accent-primary)] font-mono">∞</div>
                            <div className="text-[11px] text-[var(--text-secondary)] mt-0.5 font-medium">Polymorphic Variants</div>
                        </div>
                    </div>

                    {/* Compact Badges Panel */}
                    <div className="bg-[var(--bg-card)] rounded-xl p-4 border border-[var(--border-subtle)] shadow-sm">
                        <div className="text-xs font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-2.5 font-mono">
                            Active Modules
                        </div>
                        <div className="flex flex-wrap gap-1.5">
                            <span className="text-[11px] bg-[var(--bg-pill-muted)] text-[var(--text-primary)] px-2.5 py-1 rounded-full border border-[var(--border-subtle)] hover:border-[var(--accent-primary)]/40 transition-all">
                                ⚠️ Error-Based
                            </span>
                            <span className="text-[11px] bg-[var(--bg-pill-muted)] text-[var(--text-primary)] px-2.5 py-1 rounded-full border border-[var(--border-subtle)] hover:border-[var(--accent-primary)]/40 transition-all">
                                🔍 Boolean Blind
                            </span>
                            <span className="text-[11px] bg-[var(--bg-pill-muted)] text-[var(--text-primary)] px-2.5 py-1 rounded-full border border-[var(--border-subtle)] hover:border-[var(--accent-primary)]/40 transition-all">
                                ⏱️ Time-Based
                            </span>
                            <span className="text-[11px] bg-[var(--bg-pill-muted)] text-[var(--text-primary)] px-2.5 py-1 rounded-full border border-[var(--border-subtle)] hover:border-[var(--accent-primary)]/40 transition-all">
                                🔗 UNION Probe
                            </span>
                            <span className="text-[11px] bg-[var(--bg-pill-muted)] text-[var(--text-primary)] px-2.5 py-1 rounded-full border border-[var(--border-subtle)] hover:border-[var(--accent-primary)]/40 transition-all">
                                🌐 OOB DNS/HTTP
                            </span>
                            <span className="text-[11px] bg-[var(--bg-pill-muted)] text-[var(--text-primary)] px-2.5 py-1 rounded-full border border-[var(--border-subtle)] hover:border-[var(--accent-primary)]/40 transition-all">
                                🔄 Second-Order
                            </span>
                        </div>
                    </div>
                </div>

                {/* Right Column: Existing Scan Form */}
                <div className="lg:col-span-7">
                    <ScanForm onStart={handleStartScan} scanning={scanning} />

                    {error && (
                        <div className="mt-4 p-3 bg-accent-red/10 border border-accent-red/30 rounded-xl">
                            <p className="text-accent-red text-sm">{error}</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}