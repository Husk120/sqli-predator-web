import { NextRequest, NextResponse, after } from "next/server";
import { executeChunk } from "@/lib/scan-worker";
import { getScan } from "@/lib/store";

export async function POST(
    request: NextRequest,
    { params }: { params: Promise<{ id: string }> }
) {
    try {
        const { id } = await params;
        const result = await executeChunk(id);

        if (!result.done) {
            // Check scan status before continuation
            const scan = await getScan(id);
            if (scan && scan.status === "running") {
                const vercelUrl = process.env.VERCEL_URL || process.env.NEXT_PUBLIC_VERCEL_URL;
                const host = vercelUrl ? vercelUrl : (request.headers.get("host") || "localhost:3000");
                const protocol = request.headers.get("x-forwarded-proto") || (vercelUrl ? "https" : "http");
                const continueUrl = `${protocol}://${host}/api/scan/continue/${id}`;

                after(async () => {
                    try {
                        await fetch(continueUrl, {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                        });
                    } catch (err) {
                        console.error(`[PREDATOR] Failed to fire continuation chunk for ${id}:`, err);
                    }
                });
            }
        }

        return NextResponse.json({ status: "ok", done: result.done });
    } catch (err: any) {
        console.error("[PREDATOR] Continuation route error:", err);
        return NextResponse.json({ error: err.message || "Continuation failed" }, { status: 500 });
    }
}
