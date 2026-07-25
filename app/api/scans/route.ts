import { NextResponse } from "next/server";
import { getAllScans } from "@/lib/store";

export async function GET() {
    const localScans = await getAllScans().catch(() => []);
    let remoteScans: any[] = [];

    try {
        const resp = await fetch("https://sqli-predator-api.onrender.com/api/scans", {
            headers: { "Cache-Control": "no-cache" },
            next: { revalidate: 0 },
        });
        if (resp.ok) {
            remoteScans = await resp.json();
        }
    } catch {}

    const scanMap = new Map<string, any>();
    for (const scan of [...remoteScans, ...localScans]) {
        if (scan && scan.id && !scanMap.has(scan.id)) {
            scanMap.set(scan.id, scan);
        }
    }

    const merged = Array.from(scanMap.values()).sort((a, b) => {
        const tA = new Date(a.timestamp || 0).getTime();
        const tB = new Date(b.timestamp || 0).getTime();
        return tB - tA;
    });

    return NextResponse.json(merged);
}
