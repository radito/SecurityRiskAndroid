package com.example.securitysample;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public class SecurityChecker {
    static {
        System.loadLibrary("securitysample");
    }

    public interface ThreatCallback {
        void onThreatDetected(String reason);
    }

    private Map<String, String> lastParsed = new LinkedHashMap<>();

    private native void setCallback(ThreatCallback callback);
    private native String runAllChecks();

    public native String getNativeLog();
    public native void clearNativeLog();

    public void setThreatCallback(ThreatCallback callback) {
        setCallback(callback);
    }

    public String runAllChecksRaw() {
        String raw = runAllChecks();
        lastParsed = parseResult(raw);
        return raw;
    }

    public Map<String, String> getParsedResults() {
        runAllChecksRaw();
        return Collections.unmodifiableMap(lastParsed);
    }

    public boolean isCompromised() {
        if (lastParsed == null || lastParsed.isEmpty()) {
            getParsedResults();
        }

        String verdict = lastParsed.get("VERDICT");
        if ("BLOCK".equals(verdict) || "WARN".equals(verdict)) {
            return true;
        }

        for (String status : lastParsed.values()) {
            if ("DETECTED".equals(status) || "TAMPERED".equals(status) || "HOOKED".equals(status)) {
                return true;
            }
        }
        return false;
    }

    private Map<String, String> parseResult(String raw) {
        LinkedHashMap<String, String> parsed = new LinkedHashMap<>();
        if (raw == null || raw.trim().isEmpty()) {
            parsed.put("ERROR", "EMPTY_NATIVE_RESULT");
            return parsed;
        }

        String[] parts = raw.split("\\|");
        for (String part : parts) {
            if (part == null || part.isEmpty()) continue;
            int idx = part.indexOf(':');
            if (idx <= 0 || idx >= part.length() - 1) continue;

            String key = part.substring(0, idx);
            String value = part.substring(idx + 1);
            parsed.put(key, value);
        }
        return parsed;
    }
}
