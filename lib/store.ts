import { ScanResult, ScanChunkState } from "./types";
import { getFirestore, Firestore } from "firebase-admin/firestore";
import { getApps, initializeApp, cert } from "firebase-admin/app";

// ─── Firebase Admin Singleton ───

let _db: Firestore | null = null;

function getFirestoreDb(): Firestore | null {
    if (_db) return _db;

    const projectId = process.env.FIREBASE_PROJECT_ID;
    const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
    const privateKey = process.env.FIREBASE_PRIVATE_KEY;

    if (!projectId || !clientEmail || !privateKey) {
        return null; // Fall back to in-memory for local dev
    }

    // Initialize only once — guard against duplicate initialization in serverless
    if (getApps().length === 0) {
        console.log("[FIREBASE DEBUG] Raw privateKey length:", privateKey.length);
        console.log("[FIREBASE DEBUG] Raw start (first 30):", JSON.stringify(privateKey.slice(0, 30)));
        console.log("[FIREBASE DEBUG] Raw end (last 30):", JSON.stringify(privateKey.slice(-30)));

        // Strip surrounding quotes if present (e.g. from env file parsing)
        let cleanedKey = privateKey.trim();
        if ((cleanedKey.startsWith('"') && cleanedKey.endsWith('"')) || 
            (cleanedKey.startsWith("'") && cleanedKey.endsWith("'"))) {
            cleanedKey = cleanedKey.slice(1, -1);
        }

        cleanedKey = cleanedKey.replace(/\\n/g, "\n");

        console.log("[FIREBASE DEBUG] Cleaned start (first 30):", JSON.stringify(cleanedKey.slice(0, 30)));
        console.log("[FIREBASE DEBUG] Cleaned end (last 30):", JSON.stringify(cleanedKey.slice(-30)));

        initializeApp({
            credential: cert({
                projectId,
                clientEmail,
                privateKey: cleanedKey,
            }),
        });
    }

    _db = getFirestore();
    return _db;
}

// ─── Collection name ───

const COLLECTION = "scans";

// ─── In-Memory Fallback (local development only) ───

declare global {
    var __scansStore: Map<string, ScanResult> | undefined;
}

const localScans = globalThis.__scansStore || new Map<string, ScanResult>();
globalThis.__scansStore = localScans;

// ─── Store Functions ───

export async function createScan(scan: ScanResult): Promise<void> {
    const db = getFirestoreDb();
    if (!db) {
        localScans.set(scan.id, scan);
        return;
    }

    await db.collection(COLLECTION).doc(scan.id).set(JSON.parse(JSON.stringify(scan)));
}

export async function getScan(id: string): Promise<ScanResult | undefined> {
    const db = getFirestoreDb();
    if (!db) {
        return localScans.get(id);
    }

    const doc = await db.collection(COLLECTION).doc(id).get();
    if (!doc.exists) return undefined;
    return doc.data() as ScanResult;
}

export async function updateScan(
    id: string,
    updates: Partial<ScanResult>
): Promise<void> {
    const db = getFirestoreDb();
    if (!db) {
        const scan = localScans.get(id);
        if (scan) Object.assign(scan, updates);
        return;
    }

    // Firestore merge: true creates the doc if missing, updates fields otherwise
    const clean = JSON.parse(JSON.stringify(updates));
    await db.collection(COLLECTION).doc(id).set(clean, { merge: true });
}

export async function getAllScans(): Promise<ScanResult[]> {
    const db = getFirestoreDb();
    if (!db) {
        return Array.from(localScans.values()).sort(
            (a, b) =>
                new Date(b.timestamp).getTime() -
                new Date(a.timestamp).getTime()
        );
    }

    const snapshot = await db
        .collection(COLLECTION)
        .orderBy("timestamp", "desc")
        .limit(50)
        .get();

    return snapshot.docs.map((doc) => doc.data() as ScanResult);
}

export async function deleteScan(id: string): Promise<void> {
    const db = getFirestoreDb();
    if (!db) {
        localScans.delete(id);
        localScanStates.delete(id);
        return;
    }

    await db.collection(COLLECTION).doc(id).delete();
    await db.collection(STATES_COLLECTION).doc(id).delete();
}

// ─── Scan Chunk State Storage ───

const STATES_COLLECTION = "scan_states";

declare global {
    var __scanStatesStore: Map<string, ScanChunkState> | undefined;
}

const localScanStates = globalThis.__scanStatesStore || new Map<string, ScanChunkState>();
globalThis.__scanStatesStore = localScanStates;

export async function saveScanState(id: string, state: ScanChunkState): Promise<void> {
    const db = getFirestoreDb();
    if (!db) {
        localScanStates.set(id, state);
        return;
    }

    // Keep scanLog capped at last 200 entries and truncate response snippets to ensure doc fits in 1MB
    const cleanedState: ScanChunkState = {
        ...state,
        scanLog: state.scanLog.slice(-200),
        findings: state.findings.map(f => ({
            ...f,
            rawResponseSnippet: (f.rawResponseSnippet || "").slice(0, 200)
        }))
    };

    await db.collection(STATES_COLLECTION).doc(id).set(JSON.parse(JSON.stringify(cleanedState)));
}

export async function getScanState(id: string): Promise<ScanChunkState | undefined> {
    const db = getFirestoreDb();
    if (!db) {
        return localScanStates.get(id);
    }

    const doc = await db.collection(STATES_COLLECTION).doc(id).get();
    if (!doc.exists) return undefined;
    return doc.data() as ScanChunkState;
}

export async function deleteScanState(id: string): Promise<void> {
    const db = getFirestoreDb();
    if (!db) {
        localScanStates.delete(id);
        return;
    }

    await db.collection(STATES_COLLECTION).doc(id).delete();
}