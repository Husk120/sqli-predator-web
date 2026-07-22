import { ScanResult } from "./types";
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
        initializeApp({
            credential: cert({
                projectId,
                clientEmail,
                // Vercel stores the key with escaped \\n — convert to real newlines
                privateKey: privateKey.replace(/\\n/g, "\n"),
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
        return;
    }

    await db.collection(COLLECTION).doc(id).delete();
}