import { NextRequest, NextResponse } from "next/server";
import { updateScan, deleteScanState } from "@/lib/store";

export async function POST(
    request: NextRequest,
    { params }: { params: Promise<{ id: string }> }
) {
    try {
        const { id } = await params;

        await updateScan(id, {
            status: "stopped",
            currentPhase: "Stopped by user",
        });

        await deleteScanState(id);

        return NextResponse.json({ status: "stopped", id });
    } catch (err: any) {
        return NextResponse.json(
            { error: err.message || "Failed to stop scan" },
            { status: 500 }
        );
    }
}
