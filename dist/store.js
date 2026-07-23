"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createScan = createScan;
exports.getScan = getScan;
exports.updateScan = updateScan;
exports.getAllScans = getAllScans;
exports.deleteScan = deleteScan;
exports.saveScanState = saveScanState;
exports.getScanState = getScanState;
exports.deleteScanState = deleteScanState;
const firestore_1 = require("firebase-admin/firestore");
const app_1 = require("firebase-admin/app");
// ─── Firebase Admin Singleton ───
let _db = null;
function getFirestoreDb() {
    if (_db)
        return _db;
    const projectId = process.env.FIREBASE_PROJECT_ID;
    const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
    const privateKey = process.env.FIREBASE_PRIVATE_KEY;
    if (!projectId || !clientEmail || !privateKey) {
        return null; // Fall back to in-memory for local dev
    }
    // Initialize only once — guard against duplicate initialization in serverless
    if ((0, app_1.getApps)().length === 0) {
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
        (0, app_1.initializeApp)({
            credential: (0, app_1.cert)({
                projectId,
                clientEmail,
                privateKey: cleanedKey,
            }),
        });
    }
    _db = (0, firestore_1.getFirestore)();
    return _db;
}
// ─── Collection name ───
const COLLECTION = "scans";
const localScans = globalThis.__scansStore || new Map();
globalThis.__scansStore = localScans;
// ─── Store Functions ───
async function createScan(scan) {
    const db = getFirestoreDb();
    if (!db) {
        localScans.set(scan.id, scan);
        return;
    }
    await db.collection(COLLECTION).doc(scan.id).set(JSON.parse(JSON.stringify(scan)));
}
async function getScan(id) {
    const db = getFirestoreDb();
    if (!db) {
        return localScans.get(id);
    }
    const doc = await db.collection(COLLECTION).doc(id).get();
    if (!doc.exists)
        return undefined;
    return doc.data();
}
async function updateScan(id, updates) {
    const db = getFirestoreDb();
    if (!db) {
        const scan = localScans.get(id);
        if (scan)
            Object.assign(scan, updates);
        return;
    }
    // Firestore merge: true creates the doc if missing, updates fields otherwise
    const clean = JSON.parse(JSON.stringify(updates));
    await db.collection(COLLECTION).doc(id).set(clean, { merge: true });
}
async function getAllScans() {
    const db = getFirestoreDb();
    if (!db) {
        return Array.from(localScans.values()).sort((a, b) => new Date(b.timestamp).getTime() -
            new Date(a.timestamp).getTime());
    }
    const snapshot = await db
        .collection(COLLECTION)
        .orderBy("timestamp", "desc")
        .limit(50)
        .get();
    return snapshot.docs.map((doc) => doc.data());
}
async function deleteScan(id) {
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
const localScanStates = globalThis.__scanStatesStore || new Map();
globalThis.__scanStatesStore = localScanStates;
async function saveScanState(id, state) {
    const db = getFirestoreDb();
    if (!db) {
        localScanStates.set(id, state);
        return;
    }
    // Keep only the last 200 log entries
    const trimmedLog = state.scanLog.slice(-200);
    // Trim findings to a reasonable size and cut large payloads
    const trimmedFindings = state.findings.map(f => (Object.assign(Object.assign({}, f), { 
        // Keep the explanation short – it can be regenerated from the finding if needed
        aiExplanation: f.aiExplanation.slice(0, 500), 
        // Keep only a short snippet of the raw response (already done elsewhere, but be safe)
        rawResponseSnippet: (f.rawResponseSnippet || "").slice(0, 200), 
        // Optionally, drop very large fields that are not needed for continuation
        // e.g., we could remove pocRequest if it's huge, but we keep it trimmed.
        pocRequest: f.pocRequest.slice(0, 500) })));
    // Limit the number of stored findings to the most recent 500 (adjust as needed)
    const limitedFindings = trimmedFindings.slice(-500);
    const cleanedState = Object.assign(Object.assign({}, state), { scanLog: trimmedLog, findings: limitedFindings });
    await db.collection(STATES_COLLECTION).doc(id).set(JSON.parse(JSON.stringify(cleanedState)));
}
async function getScanState(id) {
    const db = getFirestoreDb();
    if (!db) {
        return localScanStates.get(id);
    }
    const doc = await db.collection(STATES_COLLECTION).doc(id).get();
    if (!doc.exists)
        return undefined;
    return doc.data();
}
async function deleteScanState(id) {
    const db = getFirestoreDb();
    if (!db) {
        localScanStates.delete(id);
        return;
    }
    await db.collection(STATES_COLLECTION).doc(id).delete();
}
