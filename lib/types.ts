export type ScanStatus = "idle" | "running" | "completed" | "failed";

export interface ScanProfile {
    targetUrl: string;
    crawlDepth: number;
    requestDelay: number;
    timeout: number;

    // Time-based SQLi detection settings
    timeThreshold: number;
    timeSamples: number;

    testAllHeaders: boolean;
    testSecondOrder: boolean;

    oobDomain: string;

    authCookie: string;
    authCreds: string;
}

export interface ScanResult {
    id: string;
    timestamp: string;
    target: string;
    status: ScanStatus;
    progress: number;
    currentPhase: string;
    findings: SQLiFinding[];
    error?: string;
    duration: number;
}

export interface SQLiFinding {
    id: string;
    timestamp: string;
    url: string;
    parameter: string;
    vector: string;
    detectionMethod: string;
    payloadUsed: string;
    bypassTechnique: string;
    dbTypeHint: string;
    confidence: number;
    severity: string;
    cvssScore: number;
    hasSqlErrors: boolean;
    errorSignatures: string[];
    timeDelayDetected: boolean;
    timeDelaySeconds: number;
    timingZScore: number;
    timingPValue: number;
    isBooleanPositive: boolean | null;
    oobInteractionId: string;
    responseDifferencePercent: number;
    baselineLength: number;
    testLength: number;
    baselineTime: number;
    testTime: number;
    aiExplanation: string;
    remediationSteps: string[];
    vulnerabilityClass: string;
    rawResponseSnippet: string;
}

export const SEVERITY_COLORS: Record<string, string> = {
    Critical: "#dc3545",
    High: "#fd7e14",
    Medium: "#ffc107",
    Low: "#28a745",
    Info: "#17a2b8",
};

export const DETECTION_ICONS: Record<string, string> = {
    ERROR_BASED: "⚠️",
    BOOLEAN_BASED: "🔍",
    TIME_BASED_STATISTICAL: "⏱️",
    UNION_PROBE: "🔗",
    OOB_DNS: "🌐",
    OOB_HTTP: "🌐",
    SECOND_ORDER: "🔄",
    STACKED_QUERY: "📚",
};
