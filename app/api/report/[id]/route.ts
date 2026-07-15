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

  if (scan.status !== "completed") {
    return NextResponse.json(
      { error: "Scan not yet completed" },
      { status: 400 }
    );
  }

  return NextResponse.json(scan);
}
