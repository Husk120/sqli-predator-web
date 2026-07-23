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
            const resp = await fetch("https://sqli-predator-api.onrender.com/api/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(profile),
            });

            if (!resp.ok) {
                const data = await resp.json();
                throw new Error(data.error || "Failed to start scan");
            }

            const data = await resp.json();
            setScanId(data.id);

            // Store initial scan state in localStorage for fast client hydration
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
        <div className="space-y-8">
            {/* Hero */}
            <div className="text-center py-8">
                <h1 className="text-4xl font-bold text-white mb-3">
                    🦅 SQLi-<span className="text-accent-blue">PREDATOR</span>
                </h1>
                <p className="text-gray-400 max-w-2xl mx-auto">
                    Advanced SQL Injection Detection Engine — Multi-Vector, Polymorphic,
                    OOB & Statistical Analysis. <strong className="text-accent-orange">Authorized use only.</strong>
                </p>
                <div className="flex gap-2 justify-center mt-4 flex-wrap">
                    <span className="text-xs bg-surface-card border border-surface-border px-2 py-1 rounded-full text-gray-400">
                        ⚠️ Error-Based
                    </span>
                    <span className="text-xs bg-surface-card border border-surface-border px-2 py-1 rounded-full text-gray-400">
                        🔍 Boolean Blind
                    </span>
                    <span className="text-xs bg-surface-card border border-surface-border px-2 py-1 rounded-full text-gray-400">
                        ⏱️ Time-Based (Statistical)
                    </span>
                    <span className="text-xs bg-surface-card border border-surface-border px-2 py-1 rounded-full text-gray-400">
                        🔗 UNION Probe
                    </span>
                    <span className="text-xs bg-surface-card border border-surface-border px-2 py-1 rounded-full text-gray-400">
                        🌐 OOB DNS/HTTP
                    </span>
                    <span className="text-xs bg-surface-card border border-surface-border px-2 py-1 rounded-full text-gray-400">
                        🔄 Second-Order
                    </span>
                </div>
            </div>

            {/* Auth Warning */}
            <div className="border border-accent-orange/30 bg-accent-orange/5 rounded-lg p-4 max-w-3xl mx-auto">
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
                    <div className="mt-4 p-3 bg-accent-red/10 border border-accent-red/30 rounded-lg">
                        <p className="text-accent-red text-sm">{error}</p>
                    </div>
                )}
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-3xl mx-auto">
                <div className="bg-surface-card border border-surface-border rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-accent-blue">460+</div>
                    <div className="text-xs text-gray-500 mt-1">Base Payloads</div>
                </div>
                <div className="bg-surface-card border border-surface-border rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-accent-green">8</div>
                    <div className="text-xs text-gray-500 mt-1">Detection Methods</div>
                </div>
                <div className="bg-surface-card border border-surface-border rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-accent-purple">7</div>
                    <div className="text-xs text-gray-500 mt-1">Injection Vectors</div>
                </div>
                <div className="bg-surface-card border border-surface-border rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-accent-orange">∞</div>
                    <div className="text-xs text-gray-500 mt-1">Polymorphic Variants</div>
                </div>
            </div>
        </div>
    );
}