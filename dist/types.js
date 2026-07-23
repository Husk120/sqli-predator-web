"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CONFIDENCE_COLORS = exports.DETECTION_ICONS = exports.SEVERITY_COLORS = void 0;
exports.SEVERITY_COLORS = {
    Critical: "#dc3545",
    High: "#fd7e14",
    Medium: "#ffc107",
    Low: "#28a745",
    Info: "#17a2b8",
};
exports.DETECTION_ICONS = {
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
exports.CONFIDENCE_COLORS = {
    High: "#28a745",
    Medium: "#ffc107",
    Low: "#fd7e14",
    Tentative: "#6c757d",
};
