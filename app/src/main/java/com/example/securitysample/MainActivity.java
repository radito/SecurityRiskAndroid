package com.example.securitysample;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.graphics.Color;
import android.graphics.Typeface;
import android.view.View;

import java.util.Map;

public class MainActivity extends Activity {

    private SecurityChecker checker;
    private LinearLayout resultsLayout;
    private TextView bgStatus;
    private TextView nativeLogView;
    private Handler mainHandler;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mainHandler = new Handler(Looper.getMainLooper());
        checker = new SecurityChecker();

        checker.setThreatCallback(reason -> {
            mainHandler.post(() -> {
                updateBgStatus("⚠ BG THREAD: " + reason);
                refreshNativeLog();
            });
        });

        setContentView(buildUI());
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
        clearLogBtn.setOnClickListener(v -> {
            checker.clearNativeLog();
            refreshNativeLog();
        });

        runChecks();
        return root;
    }

    private void runChecks() {
        resultsLayout.removeAllViews();

        Map<String, String> results = checker.getParsedResults();

        for (Map.Entry<String, String> entry : results.entrySet()) {
            String check = entry.getKey();
            String status = entry.getValue();

            boolean bad = status.equals("DETECTED") ||
                    status.equals("TAMPERED") ||
                    status.equals("HOOKED") ||
                    status.equals("WARNING") ||
                    status.equals("BLOCK");

            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setPadding(16, 12, 16, 12);
            row.setBackgroundColor(bad
                    ? Color.parseColor("#311212")
                    : Color.parseColor("#0D2B0D"));

            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT);
            lp.setMargins(0, 4, 0, 4);
            row.setLayoutParams(lp);

            TextView icon = new TextView(this);
            icon.setText(bad ? "✗  " : "✓  ");
            icon.setTextColor(bad ? Color.parseColor("#EF5350") : Color.parseColor("#66BB6A"));
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
            statusView.setTextColor(bad
                    ? Color.parseColor("#EF5350")
                    : Color.parseColor("#66BB6A"));
            statusView.setTextSize(13f);
            row.addView(statusView);

            resultsLayout.addView(row);
        }

        TextView summary = new TextView(this);
        boolean compromised = checker.isCompromised();
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
    }

    private void refreshNativeLog() {
        String log = checker.getNativeLog();
        nativeLogView.setText(log == null ? "<null>" : log);
    }

    private void updateBgStatus(String msg) {
        bgStatus.setText(msg);
        bgStatus.setTextColor(Color.parseColor("#FF5252"));
    }
}
