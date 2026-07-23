import { NextRequest, NextResponse, after } from "next/server";
import { executeChunk } from "@/lib/scan-worker";
import { getScan } from "@/lib/store";

export async function POST(
    request: NextRequest,
    { params }: { params: Promise<{ id: string }> }
) {
    try {
        const { id } = await params;
        console.log(`[PREDATOR-TRACE] 8. POST /api/scan/continue/${id} received`);
        const result = await executeChunk(id);
        console.log(`[PREDATOR-TRACE] 9. executeChunk(${id}) returned: done=${result.done}`);

        if (!result.done) {
            // Check if scan was stopped via /api/scan/stop/[id]
            let shouldContinue = true;
            try {
                const scan = await getScan(id);
                if (scan && scan.status === "stopped") {
                    shouldContinue = false;
                    console.log(`[PREDATOR-TRACE] Scan ${id} is stopped, halting continuation`);
                }
            } catch (e) {
                // If we can't fetch the scan (e.g., Firestore temporarily unavailable),
                // assume it's still running (not stopped) to avoid halting the scan prematurely.
                console.warn(`[PREDATOR-TRACE] Could not fetch scan ${id} to check stop status:`, e);
            }

            if (shouldContinue) {
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

                console.log(`[PREDATOR-TRACE] 11. Scheduling next continuation fetch to: ${continueUrl}`);

                after(async () => {
                    console.log(`[PREDATOR-TRACE] 12. [after()] Dispatching next POST to ${continueUrl}...`);
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
                        console.log(`[PREDATOR-TRACE] 13. [after()] Dispatch response status: ${res.status}`);
                    } catch (err: any) {
                        console.error(`[PREDATOR-TRACE] 13a. [after()] Dispatch failed for ${id}:`, err?.message || err);
                    }
                });
            }
        }

        return NextResponse.json({ status: "ok", done: result.done });
    } catch (err: any) {
        console.error(`[PREDATOR-TRACE] ERROR in POST /api/scan/continue:`, err?.message || err);
        return NextResponse.json({ error: err.message || "Continuation failed" }, { status: 500 });
    }
}