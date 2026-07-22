export type ScanStatus = "idle" | "running" | "completed" | "failed" | "stopped";

export type ConfidenceLevel = "High" | "Medium" | "Low" | "Tentative";

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

export interface TechStackInfo {
    server?: string;
    language?: string;
    framework?: string;
    database?: string;
    waf?: string;
}

export interface DiscoveredEndpoint {
    url: string;
    method: string;
    params: string[];
    source: "crawl" | "robots" | "sitemap" | "js-extract" | "common-path" | "form";
    priority: "high" | "medium" | "low";
}

export interface EnumerationResult {
    forms: Array<{
        action: string;
        method: string;
        inputs: Array<{ name: string; type: string; value: string }>;
        priority: "high" | "medium" | "low";
    }>;
    urlParams: Array<{
        baseUrl: string;
        name: string;
        value: string;
        originalUrl?: string;
        allParams?: Record<string, string>;
        priority: "high" | "medium" | "low";
    }>;
    techStack: TechStackInfo;
    discoveredPaths: string[];
}

export interface ScanResult {
    id: string;
    timestamp: string;
    target: string;
    status: ScanStatus;
    progress: number;
    currentPhase: string;
    findings: SQLiFinding[];
    scanLog: string[];
    error?: string;
    duration: number;
    enumeration?: {
        formsFound: number;
        paramsFound: number;
        pathsDiscovered: number;
        techStack: TechStackInfo;
    };
}

export interface SQLiFinding {
    id: string;
    timestamp: string;
    url: string;
    parameter: string;
    vector: string;
    attackSurface: "form" | "url-param" | "header" | "second-order";
    detectionMethod: string;
    payloadUsed: string;
    bypassTechnique: string;
    dbTypeHint: string;

    // Severity & scoring
    confidence: number;
    confidenceLevel: ConfidenceLevel;
    severity: string;
    cvssScore: number;

    // Detection evidence
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

    // Report quality
    aiExplanation: string;
    remediationSteps: string[];
    vulnerabilityClass: string;
    rawResponseSnippet: string;
    pocRequest: string;

    // Classification
    cweId: string;
    owaspCategory: string;
    references: string[];
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
    STATUS_CODE_ANOMALY: "📊",
    CONTENT_DIFF: "📏",
};

export const CONFIDENCE_COLORS: Record<ConfidenceLevel, string> = {
    High: "#28a745",
    Medium: "#ffc107",
    Low: "#fd7e14",
    Tentative: "#6c757d",
};

export type ChunkPhase =
    | "enumerate"
    | "baseline"
    | "test_forms"
    | "test_params"
    | "test_headers"
    | "finalize";

export interface ChunkStep {
    phase: ChunkPhase;
    formIdx?: number;
    inputIdx?: number;
    paramIdx?: number;
    payloadIdx?: number;
    booleanIdx?: number;
    headerIdx?: number;
    headerPayloadIdx?: number;
}

export interface BaselineData {
    status: number;
    length: number;
    hash: string;
    mean: number;
    stddev: number;
}

export interface ScanChunkState {
    scanId: string;
    config: ScanProfile;
    step: ChunkStep;
    forms: Array<{
        action: string;
        method: string;
        inputs: Array<{ name: string; type: string; value: string }>;
        priority: "high" | "medium" | "low";
    }>;
    params: Array<{
        baseUrl: string;
        name: string;
        value: string;
        originalUrl?: string;
        allParams?: Record<string, string>;
        priority: "high" | "medium" | "low";
    }>;
    techStack: TechStackInfo;
    discoveredPaths: string[];
    baselines: Record<string, BaselineData>;
    findings: SQLiFinding[];
    scanLog: string[];
}

