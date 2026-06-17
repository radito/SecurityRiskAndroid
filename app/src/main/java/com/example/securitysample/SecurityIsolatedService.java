package com.example.securitysample;

import android.app.Service;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.Process;
import android.os.RemoteException;
import android.os.SystemClock;

import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;

public class SecurityIsolatedService extends Service {
    public static final int MSG_RUN_CHECKS = 1;
    public static final int MSG_RESULT = 2;

    public static final String KEY_RAW_INITIAL = "raw_initial";
    public static final String KEY_RAW_FINAL = "raw_final";
    public static final String KEY_NATIVE_LOG = "native_log";
    public static final String KEY_ERROR = "error";
    public static final String KEY_PID = "pid";
    public static final String KEY_UID = "uid";
    public static final String KEY_PROCESS_NAME = "process_name";

    public static final String REQ_WAIT_FOR_DEEP = "wait_for_deep";
    public static final String REQ_WAIT_MS = "wait_ms";

    private HandlerThread workerThread;
    private Messenger messenger;

    @Override
    public void onCreate() {
        super.onCreate();

        workerThread = new HandlerThread("SecurityIsolatedWorker");
        workerThread.start();

        messenger = new Messenger(new Handler(workerThread.getLooper()) {
            @Override
            public void handleMessage(Message msg) {
                if (msg.what == MSG_RUN_CHECKS) {
                    handleRunChecks(msg);
                    return;
                }

                super.handleMessage(msg);
            }
        });
    }

    @Override
    public IBinder onBind(Intent intent) {
        return messenger.getBinder();
    }

    @Override
    public void onDestroy() {
        if (workerThread != null) {
            workerThread.quitSafely();
            workerThread = null;
        }
        super.onDestroy();
    }

    private void handleRunChecks(Message request) {
        Messenger replyTo = request.replyTo;
        if (replyTo == null) {
            return;
        }

        Bundle req = request.getData();
        boolean waitForDeep = req == null || req.getBoolean(REQ_WAIT_FOR_DEEP, true);
        int waitMs = req != null ? req.getInt(REQ_WAIT_MS, 1300) : 1300;

        if (waitMs < 0) waitMs = 0;
        if (waitMs > 3000) waitMs = 3000;

        Bundle out = new Bundle();

        try {
            SecurityChecker checker = new SecurityChecker();

            String rawInitial = checker.runAllChecksRaw();
            String rawFinal = rawInitial;

            if (waitForDeep && waitMs > 0) {
                SystemClock.sleep(waitMs);
                rawFinal = checker.runAllChecksRaw();
            }

            out.putString(KEY_RAW_INITIAL, rawInitial);
            out.putString(KEY_RAW_FINAL, rawFinal);
            out.putString(KEY_NATIVE_LOG, checker.getNativeLog());
            out.putInt(KEY_PID, Process.myPid());
            out.putInt(KEY_UID, Process.myUid());
            out.putString(KEY_PROCESS_NAME, readProcessName());
        } catch (Throwable t) {
            out.putString(KEY_ERROR, t.getClass().getName() + ": " + t.getMessage());
        }

        Message response = Message.obtain(null, MSG_RESULT);
        response.setData(out);

        try {
            replyTo.send(response);
        } catch (RemoteException ignored) {
        }
    }

    private static String readProcessName() {
        try (FileInputStream fis = new FileInputStream("/proc/self/cmdline")) {
            byte[] buf = new byte[256];
            int n = fis.read(buf);
            if (n <= 0) return "<unknown>";

            int len = 0;
            while (len < n && buf[len] != 0) {
                len++;
            }

            return new String(buf, 0, len, StandardCharsets.UTF_8);
        } catch (Throwable t) {
            return "<unknown>";
        }
    }
}