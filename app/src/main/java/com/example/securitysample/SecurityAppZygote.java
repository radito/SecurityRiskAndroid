package com.example.securitysample;

import android.app.ZygotePreload;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Runs while this application's private app zygote still has the SELinux
 * permissions required to validate contexts. The result is inherited by the
 * isolated service when Android forks it from this process.
 *
 * The oracle is intentionally conservative: a known-valid context and a
 * deliberately invalid context must behave correctly in every round before a
 * KernelSU result is accepted.
 */
public final class SecurityAppZygote implements ZygotePreload {
    public static final String STATUS_DETECTED = "DETECTED";
    public static final String STATUS_CLEAN = "CLEAN";
    public static final String STATUS_INCONCLUSIVE = "INCONCLUSIVE";
    public static final String STATUS_UNSUPPORTED = "UNSUPPORTED";

    private static final int PROBE_ROUNDS = 3;
    private static final String SELINUX_CONTEXT = "/sys/fs/selinux/context";
    private static final String VALID_CONTROL = "u:r:untrusted_app:s0";
    private static final String INVALID_CONTROL = "u:r:security_probe_invalid:s0";
    private static final String KSU_DOMAIN = "u:r:ksu:s0";
    private static final String KSU_FILE_TYPE = "u:object_r:ksu_file:s0";

    private static String inheritedStatus = STATUS_INCONCLUSIVE;
    private static String inheritedDetail = "app zygote preload did not run";

    @Override
    public void doPreload(ApplicationInfo appInfo) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            setResult(STATUS_UNSUPPORTED, "app zygote requires Android 10+");
            return;
        }

        try {
            if (appInfo == null || Os.getuid() != appInfo.uid) {
                setResult(STATUS_INCONCLUSIVE, "app zygote UID validation failed");
                return;
            }

            String context = readTrimmed("/proc/self/task/" + Os.gettid() + "/attr/current");
            if (context == null || !context.startsWith("u:r:app_zygote:s0")) {
                setResult(STATUS_INCONCLUSIVE, "unexpected preload context=" + safe(context));
                return;
            }

            Boolean domainSeen = null;
            Boolean fileTypeSeen = null;

            for (int round = 0; round < PROBE_ROUNDS; round++) {
                ProbeResult valid = contextExists(VALID_CONTROL);
                ProbeResult invalid = contextExists(INVALID_CONTROL);
                if (valid != ProbeResult.EXISTS || invalid != ProbeResult.MISSING) {
                    setResult(STATUS_INCONCLUSIVE,
                            "SELinux oracle self-test failed valid=" + valid + " invalid=" + invalid);
                    return;
                }

                ProbeResult domain = contextExists(KSU_DOMAIN);
                ProbeResult fileType = contextExists(KSU_FILE_TYPE);
                if (domain == ProbeResult.ERROR || fileType == ProbeResult.ERROR) {
                    setResult(STATUS_INCONCLUSIVE,
                            "KernelSU context query failed domain=" + domain + " file=" + fileType);
                    return;
                }

                boolean currentDomainSeen = domain == ProbeResult.EXISTS;
                boolean currentFileTypeSeen = fileType == ProbeResult.EXISTS;
                if ((domainSeen != null && domainSeen != currentDomainSeen) ||
                        (fileTypeSeen != null && fileTypeSeen != currentFileTypeSeen)) {
                    setResult(STATUS_INCONCLUSIVE, "unstable KernelSU SELinux oracle result");
                    return;
                }

                domainSeen = currentDomainSeen;
                fileTypeSeen = currentFileTypeSeen;
            }

            boolean detected = Boolean.TRUE.equals(domainSeen) || Boolean.TRUE.equals(fileTypeSeen);
            setResult(detected ? STATUS_DETECTED : STATUS_CLEAN,
                    "context=" + context +
                            " ksu_domain=" + Boolean.TRUE.equals(domainSeen) +
                            " ksu_file=" + Boolean.TRUE.equals(fileTypeSeen));
        } catch (Throwable t) {
            setResult(STATUS_INCONCLUSIVE,
                    t.getClass().getSimpleName() + ": " + safe(t.getMessage()));
        }
    }

    public static String getInheritedStatus() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return STATUS_UNSUPPORTED;
        }
        return inheritedStatus;
    }

    public static String getInheritedDetail() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return "app zygote requires Android 10+";
        }
        return inheritedDetail;
    }

    private static void setResult(String status, String detail) {
        inheritedStatus = status;
        inheritedDetail = detail;
    }

    private static ProbeResult contextExists(String context) {
        byte[] data = context.getBytes(StandardCharsets.UTF_8);
        try (FileOutputStream stream = new FileOutputStream(SELINUX_CONTEXT)) {
            Os.write(stream.getFD(), data, 0, data.length);
            return ProbeResult.EXISTS;
        } catch (ErrnoException e) {
            if (e.errno == OsConstants.EINVAL) {
                return ProbeResult.MISSING;
            }
            return ProbeResult.ERROR;
        } catch (IOException e) {
            return ProbeResult.ERROR;
        }
    }

    private static String readTrimmed(String path) {
        try {
            return new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8).trim();
        } catch (IOException e) {
            return null;
        }
    }

    private static String safe(String value) {
        return value == null ? "<null>" : value.replace('|', '/');
    }

    private enum ProbeResult {
        EXISTS,
        MISSING,
        ERROR
    }
}
