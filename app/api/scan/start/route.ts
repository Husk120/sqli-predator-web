import { NextRequest, NextResponse, after } from "next/server";
import { createScan, saveScanState } from "@/lib/store";
import { ScanResult, ScanChunkState } from "@/lib/types";

export async function POST(request: NextRequest) {
    try {
        console.log("[PREDATOR-TRACE] 1. POST /api/scan/start received");
        const body = await request.json();
        const {
            targetUrl, crawlDepth, requestDelay, timeSamples,
            testAllHeaders, testSecondOrder, oobDomain, authCookie, authCreds,
            booleanThreshold
        } = body;

        if (!targetUrl) {
            console.log("[PREDATOR-TRACE] 1a. Missing targetUrl");
            return NextResponse.json({ error: "Target URL is required" }, { status: 400 });
        }

        // Validate URL
        try {
            new URL(targetUrl);
        } catch {
            console.log("[PREDATOR-TRACE] 1b. Invalid URL format:", targetUrl);
            return NextResponse.json({ error: "Invalid URL format" }, { status: 400 });
        }

        const parsed = new URL(targetUrl);
        if (!["http:", "https:"].includes(parsed.protocol)) {
            console.log("[PREDATOR-TRACE] 1c. Invalid protocol:", parsed.protocol);
            return NextResponse.json({ error: "Only HTTP/HTTPS targets are supported" }, { status: 400 });
        }

        const id = crypto.randomUUID().slice(0, 12);
        console.log(`[PREDATOR-TRACE] 2. Validation passed. Generated scan ID: ${id}`);

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
            booleanThreshold: booleanThreshold ?? 10
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
        console.log(`[PREDATOR-TRACE] 3. Writing scan and chunkState to Firestore for ${id}...`);
        await createScan(scanResult);
        await saveScanState(id, chunkState);
        console.log(`[PREDATOR-TRACE] 4. Firestore docs created successfully for ${id}`);

        // Fire initial chunk continuation inside after() so Vercel keeps the runtime alive to dispatch the request
        // Prioritize explicitly configured APP_URL, then request Host (production/preview alias), then VERCEL_URL fallback
        const appUrl = process.env.NEXT_PUBLIC_APP_URL || process.env.APP_URL;
        let continueUrl: string;

        if (appUrl) {
            const cleanAppUrl = appUrl.startsWith("http") ? appUrl : `https://${appUrl}`;
            continueUrl = `${cleanAppUrl.replace(/\/$/, "")}/api/scan/continue/${id}`;
        } else {
            const host = request.headers.get("host") || process.env.VERCEL_URL || "localhost:3000";
            const protocol = request.headers.get("x-forwarded-proto") || (host.includes("localhost") ? "http" : "https");
            continueUrl = `${protocol}://${host}/api/scan/continue/${id}`;
        }

        console.log(`[PREDATOR-TRACE] 5. Scheduling initial after() continuation fetch to: ${continueUrl}`);

        after(async () => {
            console.log(`[PREDATOR-TRACE] 6. [after()] Dispatching POST to ${continueUrl}...`);
            try {
                const headers: Record<string, string> = { "Content-Type": "application/json" };
                const bypassSecret = process.env.VERCEL_AUTOMATION_BYPASS_SECRET;
                if (bypassSecret) {
                    headers["x-vercel-protection-bypass"] = bypassSecret;
                }

                const res = await fetch(continueUrl, {
                    method: "POST",
                    headers,
                });
                console.log(`[PREDATOR-TRACE] 7. [after()] Dispatch response status: ${res.status}`);
            } catch (err: any) {
                console.error(`[PREDATOR-TRACE] 7a. [after()] Dispatch failed for ${id}:`, err?.message || err);
            }
        });

        return NextResponse.json({ id, status: "running" });
    } catch (err: any) {
        console.error("[PREDATOR-TRACE] ERROR in POST /api/scan/start:", err?.message || err);
        return NextResponse.json({ error: err.message || "Failed to start scan" }, { status: 500 });
    }
}
