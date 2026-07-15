import { NextRequest, NextResponse } from "next/server";
import { getScan } from "@/lib/store";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;

  const scan = getScan(id);

  if (!scan) {
    return NextResponse.json(
      { error: "Scan not found" },
      { status: 404 }
    );
  }

  return NextResponse.json({
    id: scan.id,
    status: scan.status,
    progress: scan.progress,
    currentPhase: scan.currentPhase,
    findingsCount: scan.findings.length,
    duration: scan.duration,
    error: scan.error,
  });
}
