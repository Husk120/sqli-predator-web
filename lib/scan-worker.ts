import { ScanChunkState, SQLiFinding } from "./types";
import { getScan, updateScan, getScanState, saveScanState, deleteScanState } from "./store";
import {
    Payload,
    crawlTarget,
    buildHeaders,
    measureBaslineTiming,
    computeZScore,
    simpleHash,
    BASE_PAYLOADS,
    buildOobPayloads,
    HEADER_INJECTION_PAYLOADS,
    INJECTABLE_HEADERS,
    generatePolymorphicVariants,
    checkErrorSignatures,
    scoreConfidence,
    calculateSeverity,
    getConfidenceLevel,
    generateExplanation,
    generateRemediation,
    buildPocRequest,
    deduplicateFindings,
    sleep,
    BypassTechnique,
} from "./sqli-engine";

export async function executeChunk(scanId: string): Promise<{ done: boolean }> {
    console.log(`[PREDATOR-TRACE-WORKER] Entering executeChunk for ${scanId}`);
    const scan = await getScan(scanId);
    if (!scan) {
        console.error(`[PREDATOR-TRACE-WORKER] Scan ${scanId} NOT FOUND in Firestore!`);
        return { done: true };
    }
    if (scan.status !== "running") {
        console.log(`[PREDATOR-TRACE-WORKER] Scan ${scanId} status is '${scan.status}' (not running). Halting.`);
        return { done: true };
    }

    const state = await getScanState(scanId);
    if (!state) {
        console.error(`[PREDATOR-TRACE-WORKER] ScanChunkState for ${scanId} NOT FOUND in Firestore!`);
        await updateScan(scanId, { status: "failed", currentPhase: "Failed", error: "Scan state lost" });
        return { done: true };
    }

    console.log(`[PREDATOR-TRACE-WORKER] executeChunk loaded state for ${scanId}. Current phase: '${state.step.phase}'`);

    const deadline = Date.now() + 7000; // 7-second time budget per serverless invocation
    const config = state.config;
    const authHeaders = buildHeaders(config);

    function log(msg: string) {
        const ts = new Date().toISOString().slice(11, 19);
        const line = `[${ts}] ${msg}`;
        if (state && state.scanLog) {
            state.scanLog.push(line);
        }
        console.log(line);
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
        const cvssScore = (opts.detectionMethod in {
            OOB_DNS: 1, OOB_HTTP: 1, UNION_PROBE: 1, STACKED_QUERY: 1,
            ERROR_BASED: 1, TIME_BASED_STATISTICAL: 1, BOOLEAN_BASED: 1,
            CONTENT_DIFF: 1, STATUS_CODE_ANOMALY: 1
        }) ? 8.5 : 4.5;

        const severity = calculateSeverity(cvssScore);
        const confidenceLevel = getConfidenceLevel(opts.confidence);

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
            aiExplanation: generateExplanation({ detectionMethod: opts.detectionMethod, payloadUsed: opts.payload.value, parameter: opts.parameter, url: opts.url, dbTypeHint: opts.dbHint }),
            remediationSteps: generateRemediation(opts.detectionMethod, opts.dbHint),
            vulnerabilityClass: "SQL Injection",
            rawResponseSnippet: opts.rawResponseSnippet,
            pocRequest,
            cweId: "CWE-89",
            owaspCategory: "A03:2021 – Injection",
            references: [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cwe.mitre.org/data/definitions/89.html"
            ],
        };
    }

    try {
        // Early deadline check
        if (Date.now() > deadline - 1000) {
            log("[WARN] Near deadline, skipping further work and forcing completion");
            await updateScan(scanId, { status: "failed", currentPhase: "Deadline exceeded", error: "Ran out of time" });
            return { done: true };
        }

        // Step Router
        if (state.step.phase === "enumerate") {
            log("── Phase 1: Enumerating Attack Surface ──");
            const crawlResults = await crawlTarget(config.targetUrl, config, authHeaders, log);
            state.forms = crawlResults.forms;
            state.params = crawlResults.params;
            state.techStack = crawlResults.techStack;
            state.discoveredPaths = crawlResults.discoveredPaths;
            state.step = { phase: "baseline", formIdx: 0, paramIdx: 0 };

            // Save state
            try {
                await saveScanState(scanId, state);
            } catch (saveErr) {
                console.error(`[PREDATOR-TRACE-WORKER] Failed to save state after enumerate:`, saveErr);
                // Continue anyway; we may lose some state but keep going
            }

            // Update scan progress
            try {
                await updateScan(scanId, {
                    currentPhase: "Phase 1: Enumeration complete",
                    progress: 15,
                    enumeration: {
                        formsFound: state.forms.length,
                        paramsFound: state.params.length,
                        pathsDiscovered: state.discoveredPaths.length,
                        techStack: state.techStack,
                    }
                });
            } catch (updErr) {
                console.error(`[PREDATOR-TRACE-WORKER] Failed to update scan after enumerate:`, updErr);
            }

            return { done: false };
        }

        if (state.step.phase === "baseline") {
            log("── Phase 2: Establishing Baselines ──");
            let formIdx = state.step.formIdx || 0;
            let paramIdx = state.step.paramIdx || 0;

            // Form baselines
            while (formIdx < state.forms.length && Date.now() < deadline) {
                const form = state.forms[formIdx];
                log(`[BASELINE] Processing form ${formIdx + 1}/${state.forms.length}: ${form.action}`);
                const key = `form:${form.action}:${form.method}`;
                if (!state.baselines[key]) {
                    try {
                        const formData: Record<string, string> = {};
                        for (const inp of form.inputs) formData[inp.name] = inp.value || "test";
                        const { mean, stddev } = await measureBaslineTiming(async () => {
                            const start = performance.now();
                            let resp: Response;
                            if (form.method === "GET") {
                                resp = await fetch(`${form.action}?${new URLSearchParams(formData).toString()}`, { headers: authHeaders, redirect: "follow", signal: AbortSignal.timeout(10000) });
                            } else {
                                resp = await fetch(form.action, { method: "POST", headers: { ...authHeaders, "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(formData), redirect: "follow", signal: AbortSignal.timeout(10000) });
                            }
                            const text = await resp.text();
                            return { elapsed: (performance.now() - start) / 1000, status: resp.status };
                        }, Math.min(config.timeSamples, 2), log);

                        let resp: Response;
                        if (form.method === "GET") {
                            resp = await fetch(`${form.action}?${new URLSearchParams(formData).toString()}`, { headers: authHeaders, redirect: "follow", signal: AbortSignal.timeout(10000) });
                        } else {
                            resp = await fetch(form.action, { method: "POST", headers: { ...authHeaders, "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(formData), redirect: "follow", signal: AbortSignal.timeout(10000) });
                        }
                        const text = await resp.text();
                        state.baselines[key] = { status: resp.status, length: text.length, hash: simpleHash(text), mean, stddev };
                    } catch (e) {
                        // ignore baseline errors
                        const msg = e instanceof Error ? e.message : String(e);
                        log(`[BASELINE] Error processing form ${formIdx}: ${msg}`);
                    }
                }
                formIdx++;
            }

            // Param baselines
            while (paramIdx < state.params.length && Date.now() < deadline) {
                const param = state.params[paramIdx];
                log(`[BASELINE] Processing param ${paramIdx + 1}/${state.params.length}: ${param.baseUrl}?${param.name}=${param.value}`);
                const key = `param:${param.baseUrl}:${param.name}`;
                if (!state.baselines[key]) {
                    try {
                        const { mean, stddev } = await measureBaslineTiming(async () => {
                            const start = performance.now();
                            const resp = await fetch(param.originalUrl || `${param.baseUrl}?${param.name}=${encodeURIComponent(param.value)}`, { headers: authHeaders, redirect: "follow", signal: AbortSignal.timeout(10000) });
                            await resp.text();
                            return { elapsed: (performance.now() - start) / 1000, status: resp.status };
                        }, Math.min(config.timeSamples, 2), log);

                        const resp = await fetch(param.originalUrl || `${param.baseUrl}?${param.name}=${encodeURIComponent(param.value)}`, { headers: authHeaders, redirect: "follow", signal: AbortSignal.timeout(10000) });
                        const text = await resp.text();
                        state.baselines[key] = { status: resp.status, length: text.length, hash: simpleHash(text), mean, stddev };
                    } catch (e) {
                        // ignore baseline errors
                        const msg = e instanceof Error ? e.message : String(e);
                        log(`[BASELINE] Error processing param ${paramIdx}: ${msg}`);
                    }
                }
                paramIdx++;
            }

            log(`[BASELINE] Completed form baseline up to index ${formIdx}/${state.forms.length}, param baseline up to index ${paramIdx}/${state.params.length}`);

            state.step = { formIdx, paramIdx, phase: (formIdx >= state.forms.length && paramIdx >= state.params.length) ? "test_forms" : "baseline" };
            if (state.step.phase === "test_forms") {
                state.step = { phase: "test_forms", formIdx: 0, inputIdx: 0, payloadIdx: 0, booleanIdx: 0 };
            }

            // Save state
            try {
                await saveScanState(scanId, state);
            } catch (saveErr) {
                console.error(`[PREDATOR-TRACE-WORKER] Failed to save state after baseline:`, saveErr);
            }

            // Update scan progress
            try {
                await updateScan(scanId, { currentPhase: "Phase 2: Baselines established", progress: 25 });
            } catch (updErr) {
                console.error(`[PREDATOR-TRACE-WORKER] Failed to update scan after baseline:`, updErr);
            }

            return { done: false };
        }

        if (state.step.phase === "test_forms") {
            log("── Phase 3: Testing Form Parameters ──");
            const oobPayloads = buildOobPayloads(config.oobDomain);
            const ALL_PAYLOADS = [...BASE_PAYLOADS, ...oobPayloads];
            const nonBooleanPayloads = ALL_PAYLOADS.filter(p => p.category !== "boolean_based_true" && p.category !== "boolean_based_false");
            const booleanTruePayloads = ALL_PAYLOADS.filter(p => p.category === "boolean_based_true");

            let formIdx = state.step.formIdx || 0;
            let inputIdx = state.step.inputIdx || 0;
            let payloadIdx = state.step.payloadIdx || 0;
            let booleanIdx = state.step.booleanIdx || 0;

            while (formIdx < state.forms.length && Date.now() < deadline) {
                const form = state.forms[formIdx];
                const baselineKey = `form:${form.action}:${form.method}`;
                const baseline = state.baselines[baselineKey];
                const formData: Record<string, string> = {};
                for (const inp of form.inputs) formData[inp.name] = inp.value || "test";

                while (inputIdx < form.inputs.length && Date.now() < deadline) {
                    const inputField = form.inputs[inputIdx];

                    // Test non-boolean payloads
                    while (payloadIdx < nonBooleanPayloads.length && Date.now() < deadline) {
                        const basePayload = nonBooleanPayloads[payloadIdx];
                        const variants = generatePolymorphicVariants(basePayload, basePayload.category === "time_based");

                        for (const { payload, bypass } of variants) {
                            try {
                                const data = { ...formData, [inputField.name]: payload.value };
                                const start = performance.now();
                                let resp: Response;
                                if (form.method === "GET") {
                                    resp = await fetch(`${form.action}?${new URLSearchParams(data).toString()}`, { headers: authHeaders, redirect: "follow", signal: AbortSignal.timeout(10000) });
                                } else {
                                    resp = await fetch(form.action, { method: "POST", headers: { ...authHeaders, "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(data), redirect: "follow", signal: AbortSignal.timeout(10000) });
                                }
                                const elapsed = (performance.now() - start) / 1000;
                                const text = await resp.text();

                                const { found: hasErrors, signatures, dbHint, totalWeight: errorWeight } = checkErrorSignatures(text);
                                const contentDiff = baseline ? (Math.abs(text.length - baseline.length) / (baseline.length || 1)) * 100 : 0;
                                const zScore = baseline ? computeZScore(elapsed, baseline.mean, baseline.stddev) : 0;
                                const isTimeBased = payload.category === "time_based" && elapsed > config.timeThreshold && zScore >= 2.5;

                                let detMethod = "";
                                if (hasErrors && errorWeight >= 2) detMethod = "ERROR_BASED";
                                else if (isTimeBased) detMethod = "TIME_BASED_STATISTICAL";
                                else if (payload.category === "union_probe" && contentDiff > 5) detMethod = "UNION_PROBE";
                                else if (payload.category === "stacked_query" && (isTimeBased || hasErrors)) detMethod = "STACKED_QUERY";
                                else if (payload.category === "oob_dns") detMethod = "OOB_DNS";
                                else if (payload.category === "oob_http") detMethod = "OOB_HTTP";
                                else if (contentDiff > 20) detMethod = "CONTENT_DIFF";

                                if (detMethod) {
                                    const confidence = scoreConfidence({
                                        hasErrors, errorWeight, timeDelay: isTimeBased, timingZScore: zScore,
                                        oobId: "", booleanConfirmed: false, contentDiff,
                                        testStatus: resp.status, baselineStatus: baseline?.status || 200, signatures, dbHint
                                    });

                                    if (confidence >= 0.25) {
                                        state.findings.push(createFinding({
                                            url: form.action, parameter: inputField.name, method: form.method,
                                            attackSurface: "form", detectionMethod: detMethod, payload, bypass, dbHint,
                                            confidence, hasSqlErrors: hasErrors, errorSignatures: signatures, errorWeight,
                                            timeDelayDetected: isTimeBased, timeDelaySeconds: elapsed, timingZScore: zScore, timingPValue: 0.05,
                                            isBooleanPositive: null, oobInteractionId: "", contentDiff, baselineLength: baseline?.length || 0,
                                            testLength: text.length, baselineTime: baseline?.mean || 0, testTime: elapsed,
                                            rawResponseSnippet: text, formData
                                        }));
                                    }
                                }
                            } catch (e) {
                                // ignore individual payload errors
                            }
                        }
                        payloadIdx++;
                    }

                    // Test boolean payloads
                    if (payloadIdx >= nonBooleanPayloads.length) {
                        while (booleanIdx < booleanTruePayloads.length && Date.now() < deadline) {
                            const truePayload = booleanTruePayloads[booleanIdx];
                            if (!truePayload.booleanPair) {
                                booleanIdx++;
                                continue;
                            }
                            const baseLen = baseline?.length || 0;
                            try {
                                const trueData = { ...formData, [inputField.name]: truePayload.value };
                                const falseData = { ...formData, [inputField.name]: truePayload.booleanPair };
                                const fetchF = async (d: Record<string, string>) => {
                                    const s = performance.now();
                                    const r = form.method === "GET"
                                        ? await fetch(`${form.action}?${new URLSearchParams(d).toString()}`, { headers: authHeaders, signal: AbortSignal.timeout(8000) })
                                        : await fetch(form.action, { method: "POST", headers: { ...authHeaders, "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(d), signal: AbortSignal.timeout(8000) });
                                    return { text: await r.text(), status: r.status, elapsed: (performance.now() - s) / 1000 };
                                };
                                const tResp = await fetchF(trueData);
                                const fResp = await fetchF(falseData);
                                const diff = baseLen > 0
                                    ? Math.abs(tResp.text.length - fResp.text.length) / baseLen * 100
                                    : Math.abs(tResp.text.length - fResp.text.length) / Math.max(tResp.text.length, fResp.text.length, 1) * 100;
                                // Boolean confirmed check - mirroring engine logic
                                const booleanConfirmed = diff > 5 && (
                                    (baseline && Math.abs(tResp.text.length - baseline.length) > 10) ||
                                    (baseline && Math.abs(fResp.text.length - baseline.length) > 10) ||
                                    diff > 50
                                );

                                if (booleanConfirmed) {
                                                                        const confidence = scoreConfidence({
                                        hasErrors: false, errorWeight: 0, timeDelay: false, timingZScore: 0,
                                        oobId: "", booleanConfirmed: true, contentDiff: diff,
                                        testStatus: tResp.status, baselineStatus: baseline?.status || 200, signatures: [], dbHint: "unknown"
                                    });
                                    if (confidence >= 0.25) {
                                        state.findings.push(createFinding({
                                            url: form.action, parameter: inputField.name, method: form.method,
                                            attackSurface: "form", detectionMethod: "BOOLEAN_BASED", payload: truePayload,
                                            bypass: BypassTechnique.NONE, dbHint: "unknown", confidence,
                                            hasSqlErrors: false, errorSignatures: [], errorWeight: 0, timeDelayDetected: false,
                                            timeDelaySeconds: 0, timingZScore: 0, timingPValue: 1, isBooleanPositive: true,
                                            oobInteractionId: "", contentDiff: diff, baselineLength: baseline?.length || 0,
                                            testLength: tResp.text.length, baselineTime: baseline?.mean || 0, testTime: tResp.elapsed,
                                            rawResponseSnippet: tResp.text.slice(0, 400), formData
                                        }));
                                    }
                                }
                            } catch (e) {
                                // ignore boolean test errors
                            }
                            booleanIdx++;
                        }
                    }

                    if (payloadIdx >= nonBooleanPayloads.length && booleanIdx >= booleanTruePayloads.length) {
                        inputIdx++;
                        payloadIdx = 0;
                        booleanIdx = 0;
                    }
                }

                if (inputIdx >= form.inputs.length) {
                    formIdx++;
                    inputIdx = 0;
                    payloadIdx = 0;
                    booleanIdx = 0;
                }
            }

            const isDone = formIdx >= state.forms.length;
            state.step = isDone
                ? { phase: "test_params", paramIdx: 0, payloadIdx: 0, booleanIdx: 0 }
                : { phase: "test_forms", formIdx, inputIdx, payloadIdx, booleanIdx };

            const formProgress = Math.min(28 + Math.floor((formIdx / (state.forms.length || 1)) * 32), 60);

            // Save state
            try {
                await saveScanState(scanId, state);
            } catch (saveErr) {
                console.error(`[PREDATOR-TRACE-WORKER] Failed to save state after test_forms:`, saveErr);
            }

            // Update scan progress
            try {
                await updateScan(scanId, { currentPhase: `Phase 3: Testing form parameters (${formIdx}/${state.forms.length})`, progress: formProgress });
            } catch (updErr) {
                console.error(`[PREDATOR-TRACE-WORKER] Failed to update scan after test_forms:`, updErr);
            }

            return { done: false };
        }

        if (state.step.phase === "test_params") {
            log("── Phase 4: Testing URL Parameters ──");
            const oobPayloads = buildOobPayloads(config.oobDomain);
            const ALL_PAYLOADS = [...BASE_PAYLOADS, ...oobPayloads];
            const nonBooleanPayloads = ALL_PAYLOADS.filter(p => p.category !== "boolean_based_true" && p.category !== "boolean_based_false");

            let paramIdx = state.step.paramIdx || 0;
            let payloadIdx = state.step.payloadIdx || 0;

            while (paramIdx < state.params.length && Date.now() < deadline) {
                const param = state.params[paramIdx];
                const baselineKey = `param:${param.baseUrl}:${param.name}`;
                const baseline = state.baselines[baselineKey];

                while (payloadIdx < nonBooleanPayloads.length && Date.now() < deadline) {
                    const basePayload = nonBooleanPayloads[payloadIdx];
                    const variants = generatePolymorphicVariants(basePayload, basePayload.category === "time_based");

                    for (const { payload, bypass } of variants) {
                        try {
                            const testUrl = new URL(param.baseUrl);
                            testUrl.searchParams.set(param.name, payload.value);
                            const start = performance.now();
                            const resp = await fetch(testUrl.toString(), { headers: authHeaders, redirect: "follow", signal: AbortSignal.timeout(10000) });
                            const elapsed = (performance.now() - start) / 1000;
                            const text = await resp.text();

                            const { found: hasErrors, signatures, dbHint, totalWeight: errorWeight } = checkErrorSignatures(text);
                            const contentDiff = baseline ? (Math.abs(text.length - baseline.length) / (baseline.length || 1)) * 100 : 0;
                            const zScore = baseline ? computeZScore(elapsed, baseline.mean, baseline.stddev) : 0;
                            const isTimeBased = payload.category === "time_based" && elapsed > config.timeThreshold && zScore >= 2.5;

                            let detMethod = "";
                            if (hasErrors && errorWeight >= 2) detMethod = "ERROR_BASED";
                            else if (isTimeBased) detMethod = "TIME_BASED_STATISTICAL";
                            else if (payload.category === "union_probe" && contentDiff > 5) detMethod = "UNION_PROBE";
                            else if (contentDiff > 20) detMethod = "CONTENT_DIFF";

                            if (detMethod) {
                                const confidence = scoreConfidence({
                                    hasErrors, errorWeight, timeDelay: isTimeBased, timingZScore: zScore,
                                    oobId: "", booleanConfirmed: false, contentDiff,
                                    testStatus: resp.status, baselineStatus: baseline?.status || 200, signatures, dbHint
                                });

                                if (confidence >= 0.25) {
                                    state.findings.push(createFinding({
                                        url: param.baseUrl, parameter: param.name, method: "GET",
                                        attackSurface: "url-param", detectionMethod: detMethod, payload, bypass, dbHint,
                                        confidence, hasSqlErrors: hasErrors, errorSignatures: signatures, errorWeight,
                                        timeDelayDetected: isTimeBased, timeDelaySeconds: elapsed, timingZScore: zScore, timingPValue: 0.05,
                                        isBooleanPositive: null, oobInteractionId: "", contentDiff, baselineLength: baseline?.length || 0,
                                        testLength: text.length, baselineTime: baseline?.mean || 0, testTime: elapsed,
                                        rawResponseSnippet: text
                                    }));
                                }
                            }
                        } catch (e) {
                            // ignore individual payload errors
                        }
                        payloadIdx++;
                    }

                    if (payloadIdx >= nonBooleanPayloads.length) {
                        paramIdx++;
                        payloadIdx = 0;
                    }
                }

                // No boolean testing for URL params in this worker (kept simple)
            }

            const isDone = paramIdx >= state.params.length;
            state.step = isDone
                ? { phase: "test_headers", headerIdx: 0, headerPayloadIdx: 0 }
                : { phase: "test_params", paramIdx, payloadIdx };

            const paramProgress = Math.min(62 + Math.floor((paramIdx / (state.params.length || 1)) * 25), 87);

            // Save state
            try {
                await saveScanState(scanId, state);
            } catch (saveErr) {
                console.error(`[PREDATOR-TRACE-WORKER] Failed to save state after test_params:`, saveErr);
            }

            // Update scan progress
            try {
                await updateScan(scanId, { currentPhase: `Phase 4: Testing URL parameters (${paramIdx}/${state.params.length})`, progress: paramProgress });
            } catch (updErr) {
                console.error(`[PREDATOR-TRACE-WORKER] Failed to update scan after test_params:`, updErr);
            }

            return { done: false };
        }

        if (state.step.phase === "test_headers") {
            log("── Phase 5: Testing Header Injection ──");
            if (config.testAllHeaders) {
                let headerIdx = state.step.headerIdx || 0;
                let headerPayloadIdx = state.step.headerPayloadIdx || 0;

                while (headerIdx < INJECTABLE_HEADERS.length && Date.now() < deadline) {
                    const headerName = INJECTABLE_HEADERS[headerIdx];
                    while (headerPayloadIdx < HEADER_INJECTION_PAYLOADS.length && Date.now() < deadline) {
                        const payload = HEADER_INJECTION_PAYLOADS[headerPayloadIdx];
                        try {
                            const testHeaders = { ...authHeaders, [headerName]: payload.value };
                            const start = performance.now();
                            const resp = await fetch(config.targetUrl, { headers: testHeaders, redirect: "follow", signal: AbortSignal.timeout(8000) });
                            const elapsed = (performance.now() - start) / 1000;
                            const text = await resp.text();
                            const { found: hasErrors, signatures, dbHint } = checkErrorSignatures(text);
                            if (hasErrors) {
                                state.findings.push(createFinding({
                                    url: config.targetUrl, parameter: headerName, method: "GET",
                                    attackSurface: "header", detectionMethod: "ERROR_BASED", payload, bypass: BypassTechnique.NONE,
                                    dbHint, confidence: 0.8, hasSqlErrors: true, errorSignatures: signatures, errorWeight: 3,
                                    timeDelayDetected: false, timeDelaySeconds: elapsed, timingZScore: 0, timingPValue: 0.05,
                                    isBooleanPositive: null, oobInteractionId: "", contentDiff: 0, baselineLength: 0,
                                    testLength: text.length, baselineTime: 0, testTime: elapsed, rawResponseSnippet: text
                                }));
                            }
                        } catch (e) {
                            // ignore header test errors
                        }
                        headerPayloadIdx++;
                    }

                    if (headerPayloadIdx >= HEADER_INJECTION_PAYLOADS.length) {
                        headerIdx++;
                        headerPayloadIdx = 0;
                    }
                }
            }

            state.step = { phase: "finalize" };

            // Save state
            try {
                await saveScanState(scanId, state);
            } catch (saveErr) {
                console.error(`[PREDATOR-TRACE-WORKER] Failed to save state after test_headers:`, saveErr);
            }

            // Update scan progress
            try {
                await updateScan(scanId, { currentPhase: "Phase 5: Header testing complete", progress: 92 });
            } catch (updErr) {
                console.error(`[PREDATOR-TRACE-WORKER] Failed to update scan after test_headers:`, updErr);
            }

            return { done: false };
        }

        if (state.step.phase === "finalize") {
            log("── Phase 6: Deduplicating and Scoring ──");
            const deduped = deduplicateFindings(state.findings);
            const startTime = new Date(scan.timestamp).getTime();
            const duration = (Date.now() - startTime) / 1000;

            // Update scan with final results
            try {
                await updateScan(scanId, {
                    status: "completed",
                    progress: 100,
                    currentPhase: "Complete",
                    findings: deduped,
                    scanLog: state.scanLog,
                    duration,
                    enumeration: {
                        formsFound: state.forms.length,
                        paramsFound: state.params.length,
                        pathsDiscovered: state.discoveredPaths.length,
                        techStack: state.techStack,
                    }
                });
            } catch (updErr) {
                console.error(`[PREDATOR-TRACE-WORKER] Failed to finalize scan:`, updErr);
                // Still consider done
            }

            // Clean up state
            try {
                await deleteScanState(scanId);
            } catch (delErr) {
                console.error(`[PREDATOR-TRACE-WORKER] Failed to delete scan state:`, delErr);
            }

            return { done: true };
        }
    } catch (err: any) {
        const msg = err?.message ?? String(err);
        log(`[ERROR] Chunk execution error: ${msg}`);
        console.error(`[PREDATOR-TRACE-WORKER] Unhandled error in executeChunk for ${scanId}:`, err);
        try {
            await updateScan(scanId, { status: "failed", currentPhase: "Failed", error: msg });
        } catch (updErr) {
            console.error(`[PREDATOR-TRACE-WORKER] Failed to set error on scan:`, updErr);
        }
        return { done: true };
    }

    // Fallback
    return { done: false };
}