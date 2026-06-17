package com.example.securitysample;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.LinkedHashMap;
import java.util.Map;

public class MainActivity extends Activity {

    private SecurityChecker checker;
    private LinearLayout resultsLayout;
    private TextView bgStatus;
    private TextView isolatedStatus;
    private TextView nativeLogView;
    private Handler mainHandler;

    private Messenger isolatedServiceMessenger;
    private Messenger isolatedReplyMessenger;
    private boolean isolatedBound;

    private Map<String, String> lastMainResults = new LinkedHashMap<>();
    private Map<String, String> lastIsolatedResults = new LinkedHashMap<>();

    private final ServiceConnection isolatedConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            isolatedServiceMessenger = new Messenger(service);
            isolatedBound = true;
            updateIsolatedStatus("Isolated process: connected", false);
            requestIsolatedChecks();
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            isolatedServiceMessenger = null;
            isolatedBound = false;
            updateIsolatedStatus("Isolated process: disconnected", true);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mainHandler = new Handler(Looper.getMainLooper());
        isolatedReplyMessenger = new Messenger(new Handler(Looper.getMainLooper()) {
            @Override
            public void handleMessage(Message msg) {
                if (msg.what == SecurityIsolatedService.MSG_RESULT) {
                    handleIsolatedResult(msg.getData());
                    return;
                }
                super.handleMessage(msg);
            }
        });

        checker = new SecurityChecker();

        checker.setThreatCallback(reason -> {
            mainHandler.post(() -> {
                updateBgStatus("⚠ BG THREAD: " + reason);
                refreshNativeLog();
            });
        });

        setContentView(buildUI());
        bindIsolatedService();

        /*
         * Run immediately when app starts.
         */
        runChecks();

        /*
         * Wait 10 seconds,
         * run once more,
         * then stop.
         */
        mainHandler.postDelayed(() -> runChecks(), 10000);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();

        if (isolatedBound) {
            try {
                unbindService(isolatedConnection);
            } catch (IllegalArgumentException ignored) {
            }
            isolatedBound = false;
            isolatedServiceMessenger = null;
        }

        if (mainHandler != null) {
            mainHandler.removeCallbacksAndMessages(null);
        }
    }

    private View buildUI() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 48, 32, 32);
        root.setBackgroundColor(Color.parseColor("#121212"));

        TextView title = new TextView(this);
        title.setText("SecurityRiskAndroid");
        title.setTextSize(22f);
        title.setTextColor(Color.WHITE);
        title.setPadding(0, 0, 0, 24);
        root.addView(title);

        LinearLayout buttonRow = new LinearLayout(this);
        buttonRow.setOrientation(LinearLayout.HORIZONTAL);

        Button runBtn = new Button(this);
        runBtn.setText("Run All Checks");
        runBtn.setBackgroundColor(Color.parseColor("#1E88E5"));
        runBtn.setTextColor(Color.WHITE);
        buttonRow.addView(runBtn, new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        Button isolatedBtn = new Button(this);
        isolatedBtn.setText("Run Isolated");
        isolatedBtn.setTextColor(Color.WHITE);
        isolatedBtn.setBackgroundColor(Color.parseColor("#5E35B1"));
        buttonRow.addView(isolatedBtn, new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        Button clearLogBtn = new Button(this);
        clearLogBtn.setText("Clear Log");
        clearLogBtn.setTextColor(Color.WHITE);
        clearLogBtn.setBackgroundColor(Color.parseColor("#424242"));
        buttonRow.addView(clearLogBtn, new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        root.addView(buttonRow);

        bgStatus = new TextView(this);
        bgStatus.setText("Background thread: watching...");
        bgStatus.setTextColor(Color.parseColor("#90CAF9"));
        bgStatus.setTextSize(12f);
        bgStatus.setPadding(0, 16, 0, 8);
        root.addView(bgStatus);

        isolatedStatus = new TextView(this);
        isolatedStatus.setText("Isolated process: binding...");
        isolatedStatus.setTextColor(Color.parseColor("#B39DDB"));
        isolatedStatus.setTextSize(12f);
        isolatedStatus.setPadding(0, 0, 0, 8);
        root.addView(isolatedStatus);

        ScrollView resultScroll = new ScrollView(this);
        resultsLayout = new LinearLayout(this);
        resultsLayout.setOrientation(LinearLayout.VERTICAL);
        resultsLayout.setPadding(0, 8, 0, 8);
        resultScroll.addView(resultsLayout);
        root.addView(resultScroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        TextView logTitle = new TextView(this);
        logTitle.setText("Native log buffer");
        logTitle.setTextColor(Color.WHITE);
        logTitle.setTextSize(15f);
        logTitle.setPadding(0, 16, 0, 8);
        root.addView(logTitle);

        ScrollView logScroll = new ScrollView(this);
        nativeLogView = new TextView(this);
        nativeLogView.setTextColor(Color.parseColor("#C8E6C9"));
        nativeLogView.setTextSize(11f);
        nativeLogView.setTypeface(Typeface.MONOSPACE);
        nativeLogView.setTextIsSelectable(true);
        nativeLogView.setPadding(12, 12, 12, 12);
        nativeLogView.setBackgroundColor(Color.parseColor("#0B0B0B"));
        logScroll.addView(nativeLogView);
        root.addView(logScroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        runBtn.setOnClickListener(v -> runChecks());
        isolatedBtn.setOnClickListener(v -> requestIsolatedChecks());

        clearLogBtn.setOnClickListener(v -> {
            checker.clearNativeLog();
            refreshNativeLog();
        });

        return root;
    }

    private void bindIsolatedService() {
        Intent intent = new Intent(this, SecurityIsolatedService.class);
        boolean ok = bindService(intent, isolatedConnection, Context.BIND_AUTO_CREATE);
        if (!ok) {
            updateIsolatedStatus("Isolated process: bind failed", true);
        }
    }

    private void requestIsolatedChecks() {
        if (!isolatedBound || isolatedServiceMessenger == null) {
            updateIsolatedStatus("Isolated process: not connected yet", true);
            return;
        }

        updateIsolatedStatus("Isolated process: running checks...", false);

        Message msg = Message.obtain(null, SecurityIsolatedService.MSG_RUN_CHECKS);
        msg.replyTo = isolatedReplyMessenger;

        Bundle data = new Bundle();
        data.putBoolean(SecurityIsolatedService.REQ_WAIT_FOR_DEEP, true);
        data.putInt(SecurityIsolatedService.REQ_WAIT_MS, 1400);
        msg.setData(data);

        try {
            isolatedServiceMessenger.send(msg);
        } catch (RemoteException e) {
            updateIsolatedStatus("Isolated process: send failed: " + e.getMessage(), true);
        }
    }

    private void handleIsolatedResult(Bundle data) {
        if (data == null) {
            updateIsolatedStatus("Isolated process: empty reply", true);
            return;
        }

        String error = data.getString(SecurityIsolatedService.KEY_ERROR);
        if (error != null && !error.isEmpty()) {
            updateIsolatedStatus("Isolated process: error", true);
            addSectionTitle("Isolated process result");
            addResultRow("ISO_ERROR", error);
            return;
        }

        String rawInitial = data.getString(SecurityIsolatedService.KEY_RAW_INITIAL);
        String rawFinal = data.getString(SecurityIsolatedService.KEY_RAW_FINAL);
        String nativeLog = data.getString(SecurityIsolatedService.KEY_NATIVE_LOG);
        String processName = data.getString(SecurityIsolatedService.KEY_PROCESS_NAME);
        int pid = data.getInt(SecurityIsolatedService.KEY_PID, -1);
        int uid = data.getInt(SecurityIsolatedService.KEY_UID, -1);

        lastIsolatedResults = parseResult(rawFinal != null ? rawFinal : rawInitial);

        addSectionTitle("Isolated process result");
        addResultRow("ISO_PID", String.valueOf(pid));
        addResultRow("ISO_UID", String.valueOf(uid));
        // addResultRow("ISO_PROCESS", processName == null ? "<unknown>" : processName);

        for (Map.Entry<String, String> entry : lastIsolatedResults.entrySet()) {
            addResultRow("ISO_" + entry.getKey(), entry.getValue());
        }

        addIsolatedDeltas();

        if (nativeLog != null && !nativeLog.isEmpty()) {
            nativeLogView.setText(nativeLog);
        } else {
            refreshNativeLog();
        }

        updateIsolatedStatus("Isolated process: completed", false);
    }

    private void addIsolatedDeltas() {
        if (lastMainResults == null || lastMainResults.isEmpty() ||
                lastIsolatedResults == null || lastIsolatedResults.isEmpty()) {
            return;
        }

        boolean anyDelta = false;
        for (Map.Entry<String, String> entry : lastIsolatedResults.entrySet()) {
            String key = entry.getKey();
            String isoValue = entry.getValue();
            String mainValue = lastMainResults.get(key);

            if (mainValue != null && isoValue != null && !mainValue.equals(isoValue)) {
                if (!anyDelta) {
                    addSectionTitle("Main vs isolated deltas");
                    anyDelta = true;
                }
                addResultRow("DELTA_" + key, mainValue + " -> " + isoValue);
            }
        }

        if (!anyDelta) {
            addResultRow("ISOLATED_PROCESS_DELTA", "CLEAN");
        }
    }

    private void runChecks() {
        resultsLayout.removeAllViews();

        Map<String, String> results = checker.getParsedResults();
        lastMainResults = new LinkedHashMap<>(results);

        addSectionTitle("Main process result");
        for (Map.Entry<String, String> entry : results.entrySet()) {
            addResultRow(entry.getKey(), entry.getValue());
        }

        TextView summary = new TextView(this);
        boolean compromised = isCompromised(results);
        summary.setText(compromised
                ? "⚠  Environment compromised"
                : "✓  Environment looks clean");
        summary.setTextColor(compromised
                ? Color.parseColor("#FF5252")
                : Color.parseColor("#69F0AE"));
        summary.setTextSize(16f);
        summary.setPadding(16, 24, 16, 8);
        resultsLayout.addView(summary);

        refreshNativeLog();
        requestIsolatedChecks();
    }

    private void addSectionTitle(String title) {
        TextView section = new TextView(this);
        section.setText(title);
        section.setTextColor(Color.WHITE);
        section.setTextSize(15f);
        section.setTypeface(Typeface.DEFAULT_BOLD);
        section.setPadding(8, 20, 8, 8);
        resultsLayout.addView(section);
    }

    private void addResultRow(String check, String status) {
        if (status == null) status = "<null>";

        int state = statusState(status);

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setPadding(16, 12, 16, 12);
        row.setBackgroundColor(backgroundForState(state));

        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, 4, 0, 4);
        row.setLayoutParams(lp);

        TextView icon = new TextView(this);
        icon.setText(iconForState(state));
        icon.setTextColor(colorForState(state));
        icon.setTextSize(16f);
        row.addView(icon);

        TextView label = new TextView(this);
        label.setText(check);
        label.setTextColor(Color.WHITE);
        label.setTextSize(14f);
        label.setLayoutParams(new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        row.addView(label);

        TextView statusView = new TextView(this);
        statusView.setText(status);
        statusView.setTextColor(colorForState(state));
        statusView.setTextSize(13f);
        row.addView(statusView);

        resultsLayout.addView(row);
    }

    private int statusState(String status) {
        if (status == null) return 0;

        if (status.equals("DETECTED") ||
                status.equals("TAMPERED") ||
                status.equals("HOOKED") ||
                status.equals("WARNING") ||
                status.equals("WARN") ||
                status.equals("BLOCK") ||
                status.equals("ERROR") ||
                status.equals("DIFF") ||
                status.contains(" -> ")) {
            return 2;
        }

        if (status.equals("PENDING") ||
                status.equals("RUNNING") ||
                status.equals("CACHED") ||
                status.equals("RUNNING_CACHED") ||
                status.equals("SKIPPED") ||
                status.equals("UNREADABLE") ||
                status.equals("UNKNOWN") ||
                status.equals("TIMEOUT") ||
                status.equals("DENIED") ||
                status.equals("UNAVAILABLE")) {
            return 1;
        }

        return 0;
    }

    private int backgroundForState(int state) {
        if (state == 2) return Color.parseColor("#311212");
        if (state == 1) return Color.parseColor("#2B2610");
        return Color.parseColor("#0D2B0D");
    }

    private int colorForState(int state) {
        if (state == 2) return Color.parseColor("#EF5350");
        if (state == 1) return Color.parseColor("#FFD54F");
        return Color.parseColor("#66BB6A");
    }

    private String iconForState(int state) {
        if (state == 2) return "✗  ";
        if (state == 1) return "•  ";
        return "✓  ";
    }

    private boolean isCompromised(Map<String, String> results) {
        if (results == null || results.isEmpty()) return false;

        String verdict = results.get("VERDICT");
        if ("BLOCK".equals(verdict) || "WARN".equals(verdict)) {
            return true;
        }

        for (String status : results.values()) {
            if ("DETECTED".equals(status) ||
                    "TAMPERED".equals(status) ||
                    "HOOKED".equals(status)) {
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

    private void refreshNativeLog() {
        String log = checker.getNativeLog();
        nativeLogView.setText(log == null ? "<null>" : log);
    }

    private void updateBgStatus(String msg) {
        bgStatus.setText(msg);
        bgStatus.setTextColor(Color.parseColor("#FF5252"));
    }

    private void updateIsolatedStatus(String msg, boolean bad) {
        if (isolatedStatus == null) return;
        isolatedStatus.setText(msg);
        isolatedStatus.setTextColor(bad
                ? Color.parseColor("#FF5252")
                : Color.parseColor("#B39DDB"));
    }
}
