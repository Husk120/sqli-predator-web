"use client";

import { useState } from "react";
import { ScanProfile } from "@/lib/types";

interface ScanFormProps {
    onStart: (profile: ScanProfile) => void;
    scanning: boolean;
}

export function ScanForm({ onStart, scanning }: ScanFormProps) {
    const [targetUrl, setTargetUrl] = useState("");
    const [crawlDepth, setCrawlDepth] = useState(1);
    const [timeSamples, setTimeSamples] = useState(3);
    const [testAllHeaders, setTestAllHeaders] = useState(false);
    const [testSecondOrder, setTestSecondOrder] = useState(false);
    const [oobDomain, setOobDomain] = useState("");
    const [requestDelay, setRequestDelay] = useState(0.5);
    const [authCookie, setAuthCookie] = useState("");
    const [authCreds, setAuthCreds] = useState("");

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (!targetUrl.trim()) return;

        onStart({
            targetUrl: targetUrl.trim(),
            crawlDepth,
            requestDelay,
            timeout: 30,
            timeSamples,
            testAllHeaders,
            testSecondOrder,
            oobDomain: oobDomain.trim(),
            authCookie: authCookie.trim(),
            authCreds: authCreds.trim(),
        });
    };

    return (
        <form onSubmit={handleSubmit} className="bg-surface-card border border-surface-border rounded-xl p-6 space-y-5">
            <h2 className="text-lg font-semibold text-white">New Scan</h2>

            {/* Target URL */}
            <div>
                <label className="block text-sm text-gray-400 mb-1.5">Target URL *</label>
                <input
                    type="url"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    placeholder="http://localhost/DVWA"
                    required
                    className="w-full bg-surface border border-surface-border rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-accent-blue transition-colors"
                />
            </div>

            {/* Two-column options */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <label className="block text-sm text-gray-400 mb-1.5">Crawl Depth</label>
                    <select
                        value={crawlDepth}
                        onChange={(e) => setCrawlDepth(Number(e.target.value))}
                        className="w-full bg-surface border border-surface-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-accent-blue"
                    >
                        <option value={1}>1 — Current page only</option>
                        <option value={2}>2 — One level deep</option>
                        <option value={3}>3 — Two levels deep</option>
                    </select>
                </div>

                <div>
                    <label className="block text-sm text-gray-400 mb-1.5">Time Samples (Statistical)</label>
                    <select
                        value={timeSamples}
                        onChange={(e) => setTimeSamples(Number(e.target.value))}
                        className="w-full bg-surface border border-surface-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-accent-blue"
                    >
                        <option value={1}>1 — Fast, less accurate</option>
                        <option value={3}>3 — Balanced</option>
                        <option value={5}>5 — More accurate time detection</option>
                        <option value={7}>7 — Maximum accuracy</option>
                    </select>
                </div>

                <div>
                    <label className="block text-sm text-gray-400 mb-1.5">Request Delay (seconds)</label>
                    <input
                        type="number"
                        min="0.1"
                        max="5"
                        step="0.1"
                        value={requestDelay}
                        onChange={(e) => setRequestDelay(Number(e.target.value))}
                        className="w-full bg-surface border border-surface-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-accent-blue"
                    />
                </div>

                <div>
                    <label className="block text-sm text-gray-400 mb-1.5">OOB Domain (optional)</label>
                    <input
                        type="text"
                        value={oobDomain}
                        onChange={(e) => setOobDomain(e.target.value)}
                        placeholder="interactsh.com"
                        className="w-full bg-surface border border-surface-border rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-accent-blue"
                    />
                </div>
            </div>

            {/* Auth section */}
            <details className="text-sm">
                <summary className="text-gray-400 cursor-pointer hover:text-white transition-colors">
                    Authentication (optional)
                </summary>
                <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label className="block text-sm text-gray-400 mb-1.5">Auth Cookie</label>
                        <input
                            type="text"
                            value={authCookie}
                            onChange={(e) => setAuthCookie(e.target.value)}
                            placeholder="PHPSESSID=abc123; security=low"
                            className="w-full bg-surface border border-surface-border rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-accent-blue"
                        />
                    </div>
                    <div>
                        <label className="block text-sm text-gray-400 mb-1.5">Basic Auth (user:pass)</label>
                        <input
                            type="text"
                            value={authCreds}
                            onChange={(e) => setAuthCreds(e.target.value)}
                            placeholder="admin:password"
                            className="w-full bg-surface border border-surface-border rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-accent-blue"
                        />
                    </div>
                </div>
            </details>

            {/* Feature toggles */}
            <div className="flex flex-wrap gap-4">
                <label className="flex items-center gap-2 cursor-pointer">
                    <input
                        type="checkbox"
                        checked={testAllHeaders}
                        onChange={(e) => setTestAllHeaders(e.target.checked)}
                        className="rounded bg-surface border-surface-border text-accent-blue focus:ring-accent-blue"
                    />
                    <span className="text-sm text-gray-400">Test HTTP Headers</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                    <input
                        type="checkbox"
                        checked={testSecondOrder}
                        onChange={(e) => setTestSecondOrder(e.target.checked)}
                        className="rounded bg-surface border-surface-border text-accent-blue focus:ring-accent-blue"
                    />
                    <span className="text-sm text-gray-400">Second-Order Detection</span>
                </label>
            </div>

            {/* Submit */}
            <button
                type="submit"
                disabled={scanning || !targetUrl.trim()}
                className="w-full py-2.5 rounded-lg font-medium text-sm transition-all
          bg-accent-blue text-white hover:bg-accent-blue/80 
          disabled:opacity-40 disabled:cursor-not-allowed"
            >
                {scanning ? (
                    <span className="flex items-center justify-center gap-2">
                        <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                        </svg>
                        Scan Running...
                    </span>
                ) : (
                    "🚀 Start Scan"
                )}
            </button>
        </form>
    );
}