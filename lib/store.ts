import { ScanResult } from "./types";

// In-memory store. For production, use a database.
// Vercel deploys are stateless, so this resets on each cold start.
// For persistence, add Vercel KV / Postgres / Supabase.

const scans = new Map<string, ScanResult>();

export function createScan(scan: ScanResult): void {
    scans.set(scan.id, scan);
}

export function getScan(id: string): ScanResult | undefined {
    return scans.get(id);
}

export function updateScan(id: string, updates: Partial<ScanResult>): void {
    const scan = scans.get(id);
    if (scan) {
        Object.assign(scan, updates);
    }
}

export function getAllScans(): ScanResult[] {
    return Array.from(scans.values()).sort(
        (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
}

export function deleteScan(id: string): void {
    scans.delete(id);
}