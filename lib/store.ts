import { ScanResult } from "./types";

// Persistent global store in Node environment across HMR / module re-evaluations.
declare global {
    var __scansStore: Map<string, ScanResult> | undefined;
}

const scans = globalThis.__scansStore || new Map<string, ScanResult>();
globalThis.__scansStore = scans;

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