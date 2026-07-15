import { NextRequest, NextResponse } from "next/server";
import { runScan } from "@/lib/sqli-engine";
import { createScan, getScan, updateScan } from "@/lib/store";
import { ScanResult } from "@/lib/types";

export const maxDuration = 300; // 5 minutes

export async function POST(request: NextRequest) {
    try {
        const body = await request.json();
        const { targetUrl, crawlDepth, requestDelay, timeSamples, testAllHeaders, testSecondOrder, oobDomain, authCookie, authCreds } = body;

        if (!targetUrl) {
            return NextResponse.json({ error: "Target URL is required" }, { status: 400 });
        }

        // Validate URL
        try {
            new URL(targetUrl);
        } catch {
            return NextResponse.json({ error: "Invalid URL format" }, { status: 400 });
        }

        const id = crypto.randomUUID().slice(0, 12);

        const scanResult: ScanResult = {
            id,
            timestamp: new Date().toISOString(),
            target: targetUrl,
            status: "running",
            progress: 0,
            currentPhase: "Starting...",
            findings: [],
            duration: 0,
        };

        createScan(scanResult);

        // Start scan asynchronously (don't await — let it run in background)
        runScan(
            {
                targetUrl,
                crawlDepth: crawlDepth || 1,
                requestDelay: requestDelay || 0.5,
                timeout: 30,
                timeThreshold: 3,
                timeSamples: timeSamples || 3,
                testAllHeaders: testAllHeaders || false,
                testSecondOrder: testSecondOrder || false,
                oobDomain: oobDomain || "",
                authCookie: authCookie || "",
                authCreds: authCreds || "",
            },
            (phase, progress) => {
                updateScan(id, {
                    currentPhase: phase,
                    progress,
                });
            }
        )
            .then((findings) => {
                const startTime = new Date(scanResult.timestamp).getTime();
                updateScan(id, {
                    status: "completed",
                    progress: 100,
                    currentPhase: "Complete",
                    findings,
                    duration: (Date.now() - startTime) / 1000,
                });
            })
            .catch((err) => {
                updateScan(id, {
                    status: "failed",
                    currentPhase: "Failed",
                    error: err.message,
                });
            });

        return NextResponse.json({ id, status: "running" });
    } catch (err: any) {
        return NextResponse.json({ error: err.message }, { status: 500 });
    }
}
