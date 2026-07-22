import { NextRequest, NextResponse } from "next/server";
import { after } from "next/server";
import { runScan } from "@/lib/sqli-engine";
import { createScan, updateScan } from "@/lib/store";
import { ScanResult } from "@/lib/types";

export const maxDuration = 300; // 5 minutes (requires Vercel Pro)

export async function POST(request: NextRequest) {
    try {
        const body = await request.json();
        const {
            targetUrl, crawlDepth, requestDelay, timeSamples,
            testAllHeaders, testSecondOrder, oobDomain, authCookie, authCreds
        } = body;

        if (!targetUrl) {
            return NextResponse.json({ error: "Target URL is required" }, { status: 400 });
        }

        // Validate URL
        try {
            new URL(targetUrl);
        } catch {
            return NextResponse.json({ error: "Invalid URL format" }, { status: 400 });
        }

        // Reject obviously non-HTTP targets
        const parsed = new URL(targetUrl);
        if (!["http:", "https:"].includes(parsed.protocol)) {
            return NextResponse.json({ error: "Only HTTP/HTTPS targets are supported" }, { status: 400 });
        }

        const id = crypto.randomUUID().slice(0, 12);

        const scanResult: ScanResult = {
            id,
            timestamp: new Date().toISOString(),
            target: targetUrl,
            status: "running",
            progress: 0,
            currentPhase: "Initializing...",
            findings: [],
            scanLog: [],
            duration: 0,
        };

        // Persist to Redis BEFORE responding — the status endpoint can read it immediately
        await createScan(scanResult);

        // Use Next.js 15 `after()` to keep the Lambda alive after responding.
        // The scan runs in the background but the execution context stays warm.
        after(async () => {
            try {
                const result = await runScan(
                    {
                        targetUrl,
                        crawlDepth: Math.min(crawlDepth || 1, 3),
                        requestDelay: Math.max(requestDelay || 0.5, 0.1),
                        timeout: 30,
                        timeThreshold: 4.0,
                        timeSamples: Math.min(timeSamples || 3, 5),
                        testAllHeaders: testAllHeaders || false,
                        testSecondOrder: testSecondOrder || false,
                        oobDomain: oobDomain || "",
                        authCookie: authCookie || "",
                        authCreds: authCreds || "",
                    },
                    async (phase, progress) => {
                        // Write progress to Redis so the status endpoint can read it
                        await updateScan(id, { currentPhase: phase, progress });
                    }
                );

                const startTime = new Date(scanResult.timestamp).getTime();
                await updateScan(id, {
                    status: "completed",
                    progress: 100,
                    currentPhase: "Complete",
                    findings: result.findings,
                    scanLog: result.scanLog,
                    duration: (Date.now() - startTime) / 1000,
                    enumeration: result.enumeration,
                });
            } catch (err: any) {
                console.error("[PREDATOR] Scan failed:", err);
                await updateScan(id, {
                    status: "failed",
                    currentPhase: "Failed",
                    error: err.message || "Unknown scan error",
                });
            }
        });

        return NextResponse.json({ id, status: "running" });
    } catch (err: any) {
        return NextResponse.json({ error: err.message }, { status: 500 });
    }
}
