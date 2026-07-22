import { NextRequest, NextResponse, after } from "next/server";
import { createScan, saveScanState } from "@/lib/store";
import { ScanResult, ScanChunkState } from "@/lib/types";

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

        const parsed = new URL(targetUrl);
        if (!["http:", "https:"].includes(parsed.protocol)) {
            return NextResponse.json({ error: "Only HTTP/HTTPS targets are supported" }, { status: 400 });
        }

        const id = crypto.randomUUID().slice(0, 12);

        const scanProfile = {
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
        };

        const scanResult: ScanResult = {
            id,
            timestamp: new Date().toISOString(),
            target: targetUrl,
            status: "running",
            progress: 0,
            currentPhase: "Initializing scan...",
            findings: [],
            scanLog: [`[${new Date().toISOString().slice(11, 19)}] Scan initialized`],
            duration: 0,
        };

        const chunkState: ScanChunkState = {
            scanId: id,
            config: scanProfile,
            step: { phase: "enumerate" },
            forms: [],
            params: [],
            techStack: {},
            discoveredPaths: [],
            baselines: {},
            findings: [],
            scanLog: scanResult.scanLog,
        };

        // Persist initial state to Firestore
        await createScan(scanResult);
        await saveScanState(id, chunkState);

        // Fire initial chunk continuation inside after() so Vercel keeps the runtime alive to dispatch the request
        const host = request.headers.get("host") || "localhost:3000";
        const protocol = request.headers.get("x-forwarded-proto") || "http";
        const continueUrl = `${protocol}://${host}/api/scan/continue/${id}`;

        after(async () => {
            try {
                await fetch(continueUrl, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                });
            } catch (err) {
                console.error(`[PREDATOR] Failed to kick off initial chunk for ${id}:`, err);
            }
        });

        return NextResponse.json({ id, status: "running" });
    } catch (err: any) {
        return NextResponse.json({ error: err.message || "Failed to start scan" }, { status: 500 });
    }
}
