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
            // Convert camelCase profile to snake_case for backend API
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
                // Note: timeThreshold, timeSamples, and oobDomain from profile are not sent
                // as they are not part of the backend's ScanRequest model
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
                <h1 className="text-4xl font-bold text-[#16231F] mb-3">
                    🦅 SQLi-<span className="text-[#0F6E56]">PREDATOR</span>
                </h1>
                <p className="text-[#6B7A78] max-w-2xl mx-auto">
                    Advanced SQL Injection Detection Engine — Multi-Vector, Polymorphic,
                    OOB & Statistical Analysis. <strong className="text-accent-orange">Authorized use only.</strong>
                </p>
                <div className="flex gap-2 justify-center mt-4 flex-wrap">
                    <span className="text-xs bg-[#E9EDEC] text-[#6B7A78] px-2.5 py-1 rounded-full">
                        ⚠️ Error-Based
                    </span>
                    <span className="text-xs bg-[#E9EDEC] text-[#6B7A78] px-2.5 py-1 rounded-full">
                        🔍 Boolean Blind
                    </span>
                    <span className="text-xs bg-[#E9EDEC] text-[#6B7A78] px-2.5 py-1 rounded-full">
                        ⏱️ Time-Based (Statistical)
                    </span>
                    <span className="text-xs bg-[#E9EDEC] text-[#6B7A78] px-2.5 py-1 rounded-full">
                        🔗 UNION Probe
                    </span>
                    <span className="text-xs bg-[#E9EDEC] text-[#6B7A78] px-2.5 py-1 rounded-full">
                        🌐 OOB DNS/HTTP
                    </span>
                    <span className="text-xs bg-[#E9EDEC] text-[#6B7A78] px-2.5 py-1 rounded-full">
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
                <div className="bg-white rounded-2xl p-4 text-center">
                    <div className="text-2xl font-bold text-[#0F6E56]">460+</div>
                    <div className="text-xs text-[#6B7A78] mt-1">Base Payloads</div>
                </div>
                <div className="bg-white rounded-2xl p-4 text-center">
                    <div className="text-2xl font-bold text-[#0F6E56]">8</div>
                    <div className="text-xs text-[#6B7A78] mt-1">Detection Methods</div>
                </div>
                <div className="bg-white rounded-2xl p-4 text-center">
                    <div className="text-2xl font-bold text-[#0F6E56]">7</div>
                    <div className="text-xs text-[#6B7A78] mt-1">Injection Vectors</div>
                </div>
                <div className="bg-white rounded-2xl p-4 text-center">
                    <div className="text-2xl font-bold text-[#0F6E56]">∞</div>
                    <div className="text-xs text-[#6B7A78] mt-1">Polymorphic Variants</div>
                </div>
            </div>
        </div>
    );
}