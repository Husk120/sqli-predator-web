import { NextResponse } from "next/server";
import { getAllScans } from "@/lib/store";

export async function GET() {
    const scans = getAllScans();
    return NextResponse.json(scans);
}
