#include <jni.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/utsname.h>
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <limits.h>
#include <android/log.h>

#define TAG "SecurityCheck"
#ifndef VERBOSE
#define VERBOSE 1   // Set to 0 to suppress detailed native log-buffer diagnostics.
#endif
#define NATIVE_LOG_BUFFER_MAX (256 * 1024)
#define MAX_SMALL_LINE 768

// JNI exported function declarations.
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved);
JNIEXPORT void JNICALL Java_com_example_securitysample_SecurityChecker_setCallback(JNIEnv *env, jobject thiz, jobject callback);
JNIEXPORT jstring JNICALL Java_com_example_securitysample_SecurityChecker_runAllChecks(JNIEnv *env, jobject thiz);
JNIEXPORT jstring JNICALL Java_com_example_securitysample_SecurityChecker_getNativeLog(JNIEnv *env, jobject thiz);
JNIEXPORT void JNICALL Java_com_example_securitysample_SecurityChecker_clearNativeLog(JNIEnv *env, jobject thiz);

// ─── Native log buffer ───────────────────────────────────────────────────────
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_log_buffer[NATIVE_LOG_BUFFER_MAX];
static size_t g_log_len = 0;

static long long wall_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ((long long)ts.tv_sec * 1000LL) + ((long long)ts.tv_nsec / 1000000LL);
}

static unsigned long current_tid(void) {
#ifdef __NR_gettid
    return (unsigned long)syscall(__NR_gettid);
#else
    return (unsigned long)pthread_self();
#endif
}

static void append_log_locked(const char *line) {
    if (!line) return;
    size_t n = strlen(line);
    if (n + 1 >= NATIVE_LOG_BUFFER_MAX) return;

    if (g_log_len + n + 1 >= NATIVE_LOG_BUFFER_MAX) {
        size_t keep = NATIVE_LOG_BUFFER_MAX / 2;
        if (g_log_len > keep) {
            memmove(g_log_buffer, g_log_buffer + (g_log_len - keep), keep);
            g_log_len = keep;
            g_log_buffer[g_log_len] = '\0';
        } else {
            g_log_len = 0;
            g_log_buffer[0] = '\0';
        }
    }

    memcpy(g_log_buffer + g_log_len, line, n);
    g_log_len += n;
    g_log_buffer[g_log_len++] = '\n';
    g_log_buffer[g_log_len] = '\0';
}

static void secLog(int prio, const char *level, const char *fmt, ...) {
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    __android_log_print(prio, TAG, "%s", msg);

    char line[1280];
    snprintf(line, sizeof(line), "%lld [%s] pid=%d tid=%lu %s",
             wall_time_ms(), level ? level : "I", getpid(), current_tid(), msg);

    pthread_mutex_lock(&g_log_lock);
    append_log_locked(line);
    pthread_mutex_unlock(&g_log_lock);
}

#define LOGI(...) secLog(ANDROID_LOG_INFO, "I", __VA_ARGS__)
#define LOGW(...) secLog(ANDROID_LOG_WARN, "W", __VA_ARGS__)
#define LOGE(...) secLog(ANDROID_LOG_ERROR, "E", __VA_ARGS__)
#if VERBOSE
#define VLOGI(...) LOGI(__VA_ARGS__)
#else
#define VLOGI(...) do { } while (0)
#endif

static JavaVM *g_vm = NULL;
static jobject g_callback = NULL;

// ─── Helpers ────────────────────────────────────────────────────────────────
static const char *safe_str(const char *s) {
    return (s && *s) ? s : "<none>";
}

static int contains_nocase(const char *haystack, const char *needle) {
    if (!haystack || !needle || !*needle) return 0;
    size_t nlen = strlen(needle);
    for (const char *p = haystack; *p; p++) {
        size_t i = 0;
        while (i < nlen && p[i] && tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) i++;
        if (i == nlen) return 1;
    }
    return 0;
}

static const char *basename_safe(const char *path) {
    if (!path) return "";
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static int basename_equals_nocase(const char *path, const char *name) {
    const char *base = basename_safe(path);
    if (!base || !name) return 0;
    if (strlen(base) != strlen(name)) return 0;
    for (size_t i = 0; base[i]; i++) {
        if (tolower((unsigned char)base[i]) != tolower((unsigned char)name[i])) return 0;
    }
    return 1;
}

static void strip_deleted_suffix(char *path) {
    if (!path) return;
    char *p = strstr(path, " (deleted)");
    if (p) *p = '\0';
}

static void appendf(char *dst, size_t cap, const char *fmt, ...) {
    if (!dst || cap == 0) return;
    size_t used = strlen(dst);
    if (used >= cap - 1) return;

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(dst + used, cap - used, fmt, ap);
    va_end(ap);
}

static char *read_file_raw_dynamic(const char *path, size_t *out_len) {
    if (out_len) *out_len = 0;
    int fd = (int)syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;

    size_t cap = 8192;
    size_t len = 0;
    char *buf = (char *)malloc(cap + 1);
    if (!buf) {
        syscall(__NR_close, fd);
        return NULL;
    }

    for (;;) {
        if (len + 4096 + 1 > cap) {
            size_t new_cap = cap * 2;
            char *new_buf = (char *)realloc(buf, new_cap + 1);
            if (!new_buf) break;
            buf = new_buf;
            cap = new_cap;
        }
        ssize_t n = syscall(__NR_read, fd, buf + len, cap - len);
        if (n <= 0) break;
        len += (size_t)n;
    }
    syscall(__NR_close, fd);

    buf[len] = '\0';
    if (out_len) *out_len = len;
    return buf;
}

static char *read_file_libc_dynamic(const char *path, size_t *out_len) {
    if (out_len) *out_len = 0;
    FILE *fp = fopen(path, "re");
    if (!fp) return NULL;

    size_t cap = 8192;
    size_t len = 0;
    char *buf = (char *)malloc(cap + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }

    for (;;) {
        if (len + 4096 + 1 > cap) {
            size_t new_cap = cap * 2;
            char *new_buf = (char *)realloc(buf, new_cap + 1);
            if (!new_buf) break;
            buf = new_buf;
            cap = new_cap;
        }
        size_t n = fread(buf + len, 1, cap - len, fp);
        len += n;
        if (n == 0) break;
    }
    fclose(fp);

    buf[len] = '\0';
    if (out_len) *out_len = len;
    return buf;
}

typedef struct MapEntry {
    uintptr_t start;
    uintptr_t end;
    unsigned long offset;
    char perms[5];
    char path[PATH_MAX];
} MapEntry;

static int parse_maps_line(const char *line, MapEntry *out) {
    if (!line || !out) return 0;
    memset(out, 0, sizeof(*out));
    unsigned long s = 0, e = 0, off = 0;
    char perms[5] = {0};
    int consumed = 0;
    int matched = sscanf(line, "%lx-%lx %4s %lx %*s %*s %n", &s, &e, perms, &off, &consumed);
    if (matched < 4) return 0;
    out->start = (uintptr_t)s;
    out->end = (uintptr_t)e;
    out->offset = off;
    snprintf(out->perms, sizeof(out->perms), "%s", perms);
    if (consumed > 0 && line[consumed]) {
        snprintf(out->path, sizeof(out->path), "%s", line + consumed);
    }
    return 1;
}

static void verboseLogMapEntry(const char *reason, const MapEntry *e) {
    if (!e) return;
    VLOGI("%s: range=0x%lx-0x%lx size=%lu perms=%s offset=0x%lx path=%s",
          reason ? reason : "map entry",
          (unsigned long)e->start,
          (unsigned long)e->end,
          (unsigned long)(e->end > e->start ? e->end - e->start : 0),
          e->perms,
          (unsigned long)e->offset,
          safe_str(e->path));
}

static void verboseLogRawLine(const char *reason, const char *line) {
    if (!line) return;
    char clipped[MAX_SMALL_LINE];
    snprintf(clipped, sizeof(clipped), "%s", line);
    VLOGI("%s: %s", reason ? reason : "line", clipped);
}

static int count_lines(const char *s) {
    if (!s) return 0;
    int n = 0;
    for (const char *p = s; *p; p++) if (*p == '\n') n++;
    return n;
}

// ─── Suspicious term matching with false-positive control ───────────────────
static int isKnownFalsePositivePath(const char *path) {
    if (!path) return 0;
    // Your live run showed this false positive: "ksu" inside libvndksupport.so.
    if (contains_nocase(path, "libvndksupport.so")) return 1;
    return 0;
}

static int isNormalArtJitPath(const char *path) {
    if (!path || !*path) return 0;
    return contains_nocase(path, "/memfd:jit-cache") ||
           contains_nocase(path, "/memfd:jit-zygote-cache") ||
           contains_nocase(path, "memfd:jit-cache") ||
           contains_nocase(path, "memfd:jit-zygote-cache") ||
           contains_nocase(path, "dalvik-jit-code-cache") ||
           contains_nocase(path, "jit-code-cache") ||
           contains_nocase(path, "dalvik-main space") ||
           contains_nocase(path, "dalvik-zygote space");
}

static int isSuspiciousPathPrecise(const char *path, const char **matched) {
    if (matched) *matched = NULL;
    if (!path || !*path) return 0;
    if (isKnownFalsePositivePath(path)) return 0;

    const char *strong_terms[] = {
        "frida", "gum-js-loop", "frida-agent", "linjector",
        "xposed", "lsposed", "lspd", "edxp", "riru",
        "zygisk", "magisk", "shamiko", "kernelsu", "ksud", "apatch",
        "substrate", "cydia", "dobby", "whale", "sandhook", "shadowhook", "epic", "pine",
        NULL
    };

    for (int i = 0; strong_terms[i]; i++) {
        if (contains_nocase(path, strong_terms[i])) {
            if (matched) *matched = strong_terms[i];
            return 1;
        }
    }

    // Avoid generic substring "ksu". Only treat it as KernelSU when token-like.
    if (basename_equals_nocase(path, "ksu") ||
        basename_equals_nocase(path, "su") ||
        contains_nocase(path, "/ksu/") ||
        contains_nocase(path, "/data/adb/ksu") ||
        contains_nocase(path, "/data/adb/ksud")) {
        if (matched) *matched = "ksu-token";
        return 1;
    }

    return 0;
}

static int has_suspicious_text_precise(const char *text) {
    if (!text) return 0;
    char *copy = strdup(text);
    if (!copy) return 0;

    int hit = 0;
    char *save = NULL;
    char *line = strtok_r(copy, "\n", &save);
    while (line) {
        if (isSuspiciousPathPrecise(line, NULL)) {
            hit = 1;
            break;
        }
        line = strtok_r(NULL, "\n", &save);
    }

    free(copy);
    return hit;
}

// ─── Hash / memory baseline ─────────────────────────────────────────────────
static uint64_t baseline_key1 = 0xCAFEBABEDEADBEEFULL;
static uint64_t baseline_key2 = 0x9E3779B97F4A7C15ULL;
static uint64_t baseline_xor = 0;
static uint64_t baseline_rot = 0;
static uintptr_t code_start = 0;
static uintptr_t code_end = 0;
static size_t code_len = 0;
static unsigned long code_file_offset = 0;
static char self_so_path[PATH_MAX];

static uint64_t fnv1a64_mem(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static uint64_t rotl64(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

static int resolveSelfCodeMapping(void) {
    size_t len = 0;
    char *maps = read_file_raw_dynamic("/proc/self/maps", &len);
    if (!maps) return 0;

    uintptr_t probe = (uintptr_t)&JNI_OnLoad;
    int found = 0;

    char *save = NULL;
    char *line = strtok_r(maps, "\n", &save);
    while (line) {
        MapEntry e;
        if (parse_maps_line(line, &e)) {
            int executable = e.perms[2] == 'x';
            if (probe >= e.start && probe < e.end && executable) {
                code_start = e.start;
                code_end = e.end;
                code_len = (size_t)(e.end - e.start);
                code_file_offset = e.offset;
                snprintf(self_so_path, sizeof(self_so_path), "%s", e.path);
                strip_deleted_suffix(self_so_path);
                verboseLogMapEntry("self code mapping resolved", &e);
                VLOGI("self_so_path=%s code_file_offset=0x%lx probe=%p",
                      safe_str(self_so_path), code_file_offset, (void *)probe);
                found = 1;
                break;
            }
        }
        line = strtok_r(NULL, "\n", &save);
    }

    free(maps);
    return found;
}

static void initMemoryBaseline(void) {
    if (!resolveSelfCodeMapping() || !code_start || !code_end || code_len == 0) {
        LOGW("Memory baseline skipped: self code mapping unresolved");
        return;
    }

    uint64_t live_hash = fnv1a64_mem((const void *)code_start, code_len);
    baseline_xor = live_hash ^ baseline_key1;
    baseline_rot = rotl64(live_hash ^ baseline_key2, 17);

    LOGI("Memory baseline initialized: range=0x%lx-0x%lx size=%lu path=%s file_offset=0x%lx live_hash=0x%016llx",
         (unsigned long)code_start, (unsigned long)code_end, (unsigned long)code_len,
         safe_str(self_so_path), code_file_offset, (unsigned long long)live_hash);
    VLOGI("Memory baseline encoded: key1=0x%016llx key2=0x%016llx xor=0x%016llx rot=0x%016llx",
          (unsigned long long)baseline_key1, (unsigned long long)baseline_key2,
          (unsigned long long)baseline_xor, (unsigned long long)baseline_rot);
}

static jboolean checkMemoryIntegrityLive(void) {
    if (!code_start || !code_end || !code_len) return JNI_FALSE;

    uint64_t decoded1 = baseline_xor ^ baseline_key1;
    uint64_t decoded2 = rotl64(baseline_rot, 64 - 17) ^ baseline_key2;
    if (decoded1 != decoded2) {
        LOGI("Baseline storage mismatch: decoded1=0x%016llx decoded2=0x%016llx range=0x%lx-0x%lx",
             (unsigned long long)decoded1, (unsigned long long)decoded2,
             (unsigned long)code_start, (unsigned long)code_end);
        return JNI_TRUE;
    }

    uint64_t current = fnv1a64_mem((const void *)code_start, code_len);
    if (current != decoded1) {
        LOGI("Live code hash mismatch: expected=0x%016llx current=0x%016llx range=0x%lx-0x%lx size=%lu path=%s",
             (unsigned long long)decoded1, (unsigned long long)current,
             (unsigned long)code_start, (unsigned long)code_end,
             (unsigned long)code_len, safe_str(self_so_path));
        return JNI_TRUE;
    }
    VLOGI("Live code hash OK: hash=0x%016llx range=0x%lx-0x%lx size=%lu",
          (unsigned long long)current, (unsigned long)code_start, (unsigned long)code_end,
          (unsigned long)code_len);
    return JNI_FALSE;
}

static int readDiskHashForMapping(uint64_t *out_hash) {
    if (!out_hash || !self_so_path[0] || !code_len) return 0;
    int fd = (int)syscall(__NR_openat, AT_FDCWD, self_so_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;

    uint8_t *buf = (uint8_t *)malloc(code_len);
    if (!buf) {
        syscall(__NR_close, fd);
        return 0;
    }

    size_t total = 0;
    while (total < code_len) {
        ssize_t n = pread(fd, buf + total, code_len - total, (off_t)(code_file_offset + total));
        if (n <= 0) break;
        total += (size_t)n;
    }
    syscall(__NR_close, fd);

    if (total != code_len) {
        free(buf);
        return 0;
    }

    *out_hash = fnv1a64_mem(buf, code_len);
    free(buf);
    return 1;
}

static jboolean checkMemoryIntegrityDisk(void) {
    if (!code_start || !code_len) return JNI_FALSE;

    uint64_t live_hash = fnv1a64_mem((const void *)code_start, code_len);
    uint64_t disk_hash = 0;
    if (!readDiskHashForMapping(&disk_hash)) {
        VLOGI("Disk-vs-memory hash skipped: unreadable path=%s offset=0x%lx size=%lu",
              safe_str(self_so_path), code_file_offset, (unsigned long)code_len);
        return JNI_FALSE;
    }

    if (disk_hash != live_hash) {
        LOGI("Disk-vs-memory code hash mismatch: path=%s offset=0x%lx size=%lu live=0x%016llx disk=0x%016llx",
             safe_str(self_so_path), code_file_offset, (unsigned long)code_len,
             (unsigned long long)live_hash, (unsigned long long)disk_hash);
        return JNI_TRUE;
    }

    VLOGI("Disk-vs-memory hash OK: path=%s offset=0x%lx size=%lu hash=0x%016llx",
          safe_str(self_so_path), code_file_offset, (unsigned long)code_len,
          (unsigned long long)live_hash);
    return JNI_FALSE;
}

// ─── Root / mount / maps checks ─────────────────────────────────────────────
static jboolean checkRootPaths(void) {
    const char *paths[] = {
        "/sbin/su", "/system/bin/su", "/system/xbin/su", "/data/local/xbin/su",
        "/data/local/bin/su", "/system/sd/xbin/su", "/data/local/su", "/su/bin/su",
        "/magisk/.core/bin/su", "/debug_ramdisk/.magisk", "/data/adb/magisk",
        "/data/adb/ksu", "/data/adb/ksud", "/data/adb/ap", "/data/adb/apatch",
        NULL
    };

    for (int i = 0; paths[i]; i++) {
        if (access(paths[i], F_OK) == 0) {
            LOGI("Root path artifact found: path=%s", paths[i]);
            return JNI_TRUE;
        }
    }
    return JNI_FALSE;
}

static jboolean checkRootMounts(void) {
    size_t len = 0;
    char *mountinfo = read_file_raw_dynamic("/proc/self/mountinfo", &len);
    if (!mountinfo) return JNI_FALSE;

    int hit = 0;
    char *save = NULL;
    char *line = strtok_r(mountinfo, "\n", &save);
    while (line) {
        if (isSuspiciousPathPrecise(line, NULL) || contains_nocase(line, "/debug_ramdisk")) {
            LOGI("Root/mount artifact found in mountinfo");
            verboseLogRawLine("mountinfo suspicious line", line);
            hit = 1;
            break;
        }
        line = strtok_r(NULL, "\n", &save);
    }

    free(mountinfo);
    return hit ? JNI_TRUE : JNI_FALSE;
}

static jboolean checkMapsArtifactsRaw(void) {
    size_t len = 0;
    char *maps = read_file_raw_dynamic("/proc/self/maps", &len);
    if (!maps) return JNI_FALSE;

    int hit = 0;
    char *save = NULL;
    char *line = strtok_r(maps, "\n", &save);
    while (line) {
        const char *matched = NULL;
        if (isSuspiciousPathPrecise(line, &matched)) {
            MapEntry e;
            LOGI("Hook/root artifact found in raw maps: term=%s", safe_str(matched));
            if (parse_maps_line(line, &e)) verboseLogMapEntry("maps artifact entry", &e);
            else verboseLogRawLine("maps artifact raw line", line);
            hit = 1;
            break;
        }
        line = strtok_r(NULL, "\n", &save);
    }

    free(maps);
    return hit ? JNI_TRUE : JNI_FALSE;
}

static jboolean checkMapsFilteringMismatch(void) {
    size_t raw_len = 0, libc_len = 0;
    char *raw = read_file_raw_dynamic("/proc/self/maps", &raw_len);
    char *libc = read_file_libc_dynamic("/proc/self/maps", &libc_len);
    if (!raw || !libc) {
        free(raw);
        free(libc);
        return JNI_FALSE;
    }

    int raw_lines = count_lines(raw);
    int libc_lines = count_lines(libc);
    int raw_has_artifact = has_suspicious_text_precise(raw);
    int libc_has_artifact = has_suspicious_text_precise(libc);

    free(raw);
    free(libc);

    if ((raw_lines - libc_lines) > 3 || (raw_has_artifact && !libc_has_artifact)) {
        LOGI("Possible /proc/self/maps filtering: libc_lines=%d raw_lines=%d libc_has_artifact=%d raw_has_artifact=%d raw_len=%lu libc_len=%lu",
             libc_lines, raw_lines, libc_has_artifact, raw_has_artifact,
             (unsigned long)raw_len, (unsigned long)libc_len);
        return JNI_TRUE;
    }
    VLOGI("Maps view comparison OK: libc_lines=%d raw_lines=%d raw_has_artifact=%d libc_has_artifact=%d",
          libc_lines, raw_lines, raw_has_artifact, libc_has_artifact);
    return JNI_FALSE;
}

static jboolean checkSuspiciousExecutableMaps(void) {
    size_t len = 0;
    char *maps = read_file_raw_dynamic("/proc/self/maps", &len);
    if (!maps) return JNI_FALSE;

    int suspicious = 0;
    char *save = NULL;
    char *line = strtok_r(maps, "\n", &save);
    while (line) {
        MapEntry e;
        if (!parse_maps_line(line, &e)) {
            line = strtok_r(NULL, "\n", &save);
            continue;
        }

        int r = e.perms[0] == 'r';
        int w = e.perms[1] == 'w';
        int x = e.perms[2] == 'x';
        size_t sz = e.end > e.start ? (size_t)(e.end - e.start) : 0;

        if (r && w && x) {
            LOGI("RWX memory mapping found");
            verboseLogMapEntry("suspicious RWX mapping", &e);
            suspicious = 1;
            break;
        }

        if (x) {
            const char *matched = NULL;
            if (isSuspiciousPathPrecise(e.path, &matched)) {
                LOGI("Suspicious executable mapping found: term=%s", safe_str(matched));
                verboseLogMapEntry("suspicious executable mapping", &e);
                suspicious = 1;
                break;
            }

            int is_memfd_or_deleted = contains_nocase(e.path, "/memfd:") ||
                                      contains_nocase(e.path, "memfd:") ||
                                      contains_nocase(e.path, "(deleted)") ||
                                      contains_nocase(e.path, "/dev/ashmem/");

            if (is_memfd_or_deleted && isNormalArtJitPath(e.path)) {
                VLOGI("Allowed ART/JIT executable mapping: path=%s", safe_str(e.path));
            } else if ((contains_nocase(e.path, "/memfd:") || contains_nocase(e.path, "memfd:")) && sz >= 4096) {
                LOGI("Unknown executable memfd mapping found");
                verboseLogMapEntry("unknown executable memfd", &e);
                suspicious = 1;
                break;
            } else if (!e.path[0] && sz >= (64 * 1024)) {
                LOGI("Large anonymous executable mapping found");
                verboseLogMapEntry("anonymous executable mapping", &e);
                suspicious = 1;
                break;
            }
        }

        line = strtok_r(NULL, "\n", &save);
    }

    free(maps);
    return suspicious ? JNI_TRUE : JNI_FALSE;
}

// ─── Debugger / thread / FD checks ──────────────────────────────────────────
static jboolean checkDebugger(void) {
    char *status = read_file_raw_dynamic("/proc/self/status", NULL);
    if (!status) return JNI_FALSE;

    int hit = 0;
    char *save = NULL;
    char *line = strtok_r(status, "\n", &save);
    while (line) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            if (pid != 0) {
                LOGI("Debugger detected: TracerPid=%d", pid);
                hit = 1;
            } else {
                VLOGI("Debugger status clean: TracerPid=0");
            }
            break;
        }
        line = strtok_r(NULL, "\n", &save);
    }

    free(status);
    return hit ? JNI_TRUE : JNI_FALSE;
}

static jboolean checkSuspiciousThreads(void) {
    DIR *dir = opendir("/proc/self/task");
    if (!dir) return JNI_FALSE;

    int hit = 0;
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", de->d_name);
        char *comm = read_file_raw_dynamic(path, NULL);
        if (!comm) continue;
        if (isSuspiciousPathPrecise(comm, NULL) ||
            contains_nocase(comm, "gum-js-loop") ||
            contains_nocase(comm, "gmain") ||
            contains_nocase(comm, "gdbus")) {
            char clipped[256];
            snprintf(clipped, sizeof(clipped), "%s", comm);
            LOGI("Suspicious thread name found: tid=%s comm=%s", de->d_name, clipped);
            hit = 1;
            free(comm);
            break;
        }
        free(comm);
    }

    closedir(dir);
    return hit ? JNI_TRUE : JNI_FALSE;
}

static jboolean checkSuspiciousFds(void) {
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) return JNI_FALSE;

    int hit = 0;
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char path[PATH_MAX];
        char target[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/self/fd/%s", de->d_name);
        ssize_t n = readlink(path, target, sizeof(target) - 1);
        if (n <= 0) continue;
        target[n] = '\0';

        if (isSuspiciousPathPrecise(target, NULL)) {
            LOGI("Suspicious fd target found: fd=%s target=%s", de->d_name, target);
            hit = 1;
            break;
        }
    }

    closedir(dir);
    return hit ? JNI_TRUE : JNI_FALSE;
}

// ─── Symbol / inline hook checks ────────────────────────────────────────────
static void *resolveSymbolAddress(const char *name) {
    if (!name) return NULL;
    void *addr = dlsym(RTLD_DEFAULT, name);
    if (!addr) addr = dlsym(RTLD_NEXT, name);
    return addr;
}

static jboolean checkSymbolOwner(const char *name, void *addr, const char *expected_owner) {
    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (!addr || !dladdr(addr, &info) || !info.dli_fname) {
        VLOGI("Symbol owner unresolved: name=%s addr=%p expected=%s", safe_str(name), addr, safe_str(expected_owner));
        return JNI_FALSE;
    }

    if (!contains_nocase(info.dli_fname, expected_owner)) {
        LOGI("Symbol owner mismatch: name=%s addr=%p owner=%s symbol=%s expected=%s",
             safe_str(name), addr, safe_str(info.dli_fname), safe_str(info.dli_sname), safe_str(expected_owner));
        return JNI_TRUE;
    }
    VLOGI("Symbol owner OK: name=%s addr=%p owner=%s symbol=%s expected=%s",
          safe_str(name), addr, safe_str(info.dli_fname), safe_str(info.dli_sname), safe_str(expected_owner));
    return JNI_FALSE;
}

static int looksLikeBranchOrJump(void *addr) {
    if (!addr) return 0;
#if defined(__aarch64__)
    uint32_t insn = 0;
    memcpy(&insn, addr, sizeof(insn));
    // B / BL immediate at function entry. This is heuristic only.
    return ((insn & 0xFC000000U) == 0x14000000U) ||
           ((insn & 0xFC000000U) == 0x94000000U);
#elif defined(__arm__)
    uint16_t half = 0;
    memcpy(&half, addr, sizeof(half));
    return (half & 0xF800U) == 0xE000U;
#elif defined(__i386__) || defined(__x86_64__)
    uint8_t b[2] = {0};
    memcpy(b, addr, sizeof(b));
    return b[0] == 0xE9 || b[0] == 0xEA || b[0] == 0xEB || (b[0] == 0xFF && (b[1] & 0xF0) == 0x20);
#else
    return 0;
#endif
}

static jboolean checkInlineHookHeuristic(const char *name, void *addr) {
    if (!addr) return JNI_FALSE;
    if (looksLikeBranchOrJump(addr)) {
#if defined(__aarch64__)
        uint32_t insn = 0;
        memcpy(&insn, addr, sizeof(insn));
        LOGI("Branch-like prologue seen: symbol=%s addr=%p insn=0x%08x", safe_str(name), addr, insn);
#elif defined(__arm__)
        uint16_t half = 0;
        memcpy(&half, addr, sizeof(half));
        LOGI("Branch-like Thumb prologue seen: symbol=%s addr=%p half=0x%04x", safe_str(name), addr, half);
#elif defined(__i386__) || defined(__x86_64__)
        uint8_t b[2] = {0};
        memcpy(b, addr, sizeof(b));
        LOGI("Jump-like prologue seen: symbol=%s addr=%p bytes=%02x %02x", safe_str(name), addr, b[0], b[1]);
#else
        LOGI("Branch-like prologue seen: symbol=%s addr=%p", safe_str(name), addr);
#endif
        return JNI_TRUE;
    }
    return JNI_FALSE;
}

static jboolean checkLinkerAndInlineHooks(void) {
    void *addr_fopen  = resolveSymbolAddress("fopen");
    void *addr_read   = resolveSymbolAddress("read");
    void *addr_open   = resolveSymbolAddress("open");
    void *addr_dlopen = resolveSymbolAddress("dlopen");
    void *addr_dlsym  = resolveSymbolAddress("dlsym");

    VLOGI("Resolved native symbols: fopen=%p read=%p open=%p dlopen=%p dlsym=%p",
          addr_fopen, addr_read, addr_open, addr_dlopen, addr_dlsym);

    int score = 0;
    score += checkSymbolOwner("fopen", addr_fopen, "libc.so") ? 4 : 0;
    score += checkSymbolOwner("read", addr_read, "libc.so") ? 4 : 0;
    score += checkSymbolOwner("open", addr_open, "libc.so") ? 4 : 0;
    score += checkSymbolOwner("dlopen", addr_dlopen, "libdl.so") ? 4 : 0;
    score += checkSymbolOwner("dlsym", addr_dlsym, "libdl.so") ? 4 : 0;

    score += checkInlineHookHeuristic("fopen", addr_fopen) ? 1 : 0;
    score += checkInlineHookHeuristic("read", addr_read) ? 1 : 0;
    score += checkInlineHookHeuristic("open", addr_open) ? 1 : 0;
    score += checkInlineHookHeuristic("dlopen", addr_dlopen) ? 1 : 0;
    score += checkInlineHookHeuristic("dlsym", addr_dlsym) ? 1 : 0;

    if (score >= 4) {
        LOGI("Linker/symbol integrity suspicious: score=%d", score);
        return JNI_TRUE;
    }
    return JNI_FALSE;
}

// ─── Props / device state checks ────────────────────────────────────────────
static int getProp(const char *name, char *out, size_t out_size) {
    if (!name || !out || out_size == 0) return 0;
    out[0] = '\0';
    char tmp[PROP_VALUE_MAX] = {0};
    int len = __system_property_get(name, tmp);
    if (len <= 0) return 0;
    snprintf(out, out_size, "%s", tmp);
    return 1;
}

static void verboseLogProp(const char *reason, const char *name) {
    char value[PROP_VALUE_MAX] = {0};
    if (getProp(name, value, sizeof(value))) VLOGI("%s: %s=%s", reason ? reason : "property", safe_str(name), value);
    else VLOGI("%s: %s=<unset>", reason ? reason : "property", safe_str(name));
}

static void logDetectedProp(const char *reason, const char *name) {
    char value[PROP_VALUE_MAX] = {0};
    if (getProp(name, value, sizeof(value))) LOGI("%s: %s=%s", reason ? reason : "property signal", safe_str(name), value);
    else LOGI("%s: %s=<unset>", reason ? reason : "property signal", safe_str(name));
}

static int propEquals(const char *name, const char *expected) {
    char value[PROP_VALUE_MAX] = {0};
    if (!getProp(name, value, sizeof(value))) return 0;
    return strcmp(value, expected) == 0;
}

static int propContains(const char *name, const char *needle) {
    char value[PROP_VALUE_MAX] = {0};
    if (!getProp(name, value, sizeof(value))) return 0;
    return contains_nocase(value, needle);
}

static jboolean checkUsbDebuggingProps(void) {
    int hit = 0;
    char value[PROP_VALUE_MAX] = {0};
    if (getProp("init.svc.adbd", value, sizeof(value)) &&
        (strcmp(value, "running") == 0 || strcmp(value, "restarting") == 0)) {
        logDetectedProp("USB debugging signal: adbd service active", "init.svc.adbd");
        hit = 1;
    }

    const char *usb_props[] = {"sys.usb.config", "sys.usb.state", "persist.sys.usb.config", NULL};
    for (int i = 0; usb_props[i]; i++) {
        if (propContains(usb_props[i], "adb")) {
            logDetectedProp("USB debugging signal: USB config contains adb", usb_props[i]);
            hit = 1;
        } else {
            verboseLogProp("USB debugging prop clean", usb_props[i]);
        }
    }
    return hit ? JNI_TRUE : JNI_FALSE;
}

static jboolean checkBootloaderUnlockedProps(void) {
    int hit = 0;
    VLOGI("Bootloader prop snapshot begin");
    verboseLogProp("bootloader prop", "ro.boot.flash.locked");
    verboseLogProp("bootloader prop", "ro.boot.vbmeta.device_state");
    verboseLogProp("bootloader prop", "ro.boot.verifiedbootstate");
    verboseLogProp("bootloader prop", "ro.boot.veritymode");
    verboseLogProp("bootloader prop", "ro.boot.warranty_bit");
    verboseLogProp("bootloader prop", "ro.warranty_bit");

    if (propEquals("ro.boot.flash.locked", "0")) { logDetectedProp("Bootloader signal: flash lock weak", "ro.boot.flash.locked"); hit = 1; }
    if (propContains("ro.boot.vbmeta.device_state", "unlocked")) { logDetectedProp("Bootloader signal: vbmeta device unlocked", "ro.boot.vbmeta.device_state"); hit = 1; }
    if (propContains("ro.boot.verifiedbootstate", "orange") || propContains("ro.boot.verifiedbootstate", "yellow") || propContains("ro.boot.verifiedbootstate", "red")) { logDetectedProp("Bootloader signal: verified boot not green", "ro.boot.verifiedbootstate"); hit = 1; }
    if (propContains("ro.boot.veritymode", "disabled") || propContains("ro.boot.veritymode", "eio")) { logDetectedProp("Bootloader signal: verity mode weak", "ro.boot.veritymode"); hit = 1; }
    if (propEquals("ro.boot.warranty_bit", "1") || propEquals("ro.warranty_bit", "1")) { LOGI("Bootloader signal: warranty bit set"); hit = 1; }

    return hit ? JNI_TRUE : JNI_FALSE;
}

static jboolean checkBuildProps(void) {
    int hit = 0;
    VLOGI("Build/security prop snapshot begin");
    verboseLogProp("build prop", "ro.secure");
    verboseLogProp("build prop", "ro.debuggable");
    verboseLogProp("build prop", "ro.adb.secure");
    verboseLogProp("build prop", "ro.build.tags");
    verboseLogProp("build prop", "ro.build.type");
    verboseLogProp("build prop", "ro.boot.selinux");

    if (propEquals("ro.secure", "0")) { logDetectedProp("Build prop signal", "ro.secure"); hit = 1; }
    if (propEquals("ro.debuggable", "1")) { logDetectedProp("Build prop signal", "ro.debuggable"); hit = 1; }
    if (propEquals("ro.adb.secure", "0")) { logDetectedProp("Build prop signal", "ro.adb.secure"); hit = 1; }
    if (propContains("ro.build.tags", "test-keys") || propContains("ro.build.tags", "dev-keys")) { logDetectedProp("Build prop signal: build tags not release", "ro.build.tags"); hit = 1; }
    if (propContains("ro.build.type", "userdebug") || propContains("ro.build.type", "eng")) { logDetectedProp("Build prop signal: build type debug", "ro.build.type"); hit = 1; }
    if (propContains("ro.boot.selinux", "permissive")) { logDetectedProp("Build prop signal: SELinux permissive", "ro.boot.selinux"); hit = 1; }

    const char *suspicious_props[] = {
        "init.svc.magisk", "init.svc.magiskd", "init.svc.kernelsu", "init.svc.ksud",
        "init.svc.apatchd", "persist.sys.lsposed", "persist.lsposed.manager", NULL
    };
    for (int i = 0; suspicious_props[i]; i++) {
        char v[PROP_VALUE_MAX] = {0};
        if (getProp(suspicious_props[i], v, sizeof(v)) && v[0]) {
            logDetectedProp("Build prop signal: suspicious framework/service property", suspicious_props[i]);
            hit = 1;
        }
    }
    return hit ? JNI_TRUE : JNI_FALSE;
}

static jboolean checkKernelIdentityConsistency(void) {
    struct utsname u;
    memset(&u, 0, sizeof(u));
    int libc_ok = uname(&u) == 0;

    size_t os_len = 0, ver_len = 0;
    char *osrelease = read_file_raw_dynamic("/proc/sys/kernel/osrelease", &os_len);
    char *kversion = read_file_raw_dynamic("/proc/sys/kernel/version", &ver_len);
    char *procver = read_file_raw_dynamic("/proc/version", NULL);

    int hit = 0;
    if (libc_ok) {
        VLOGI("uname snapshot: sysname=%s release=%s version=%s machine=%s",
              safe_str(u.sysname), safe_str(u.release), safe_str(u.version), safe_str(u.machine));
    }

    if (libc_ok && osrelease && osrelease[0] && !contains_nocase(osrelease, u.release)) {
        LOGI("Kernel identity mismatch: uname.release=%s osrelease=%s", safe_str(u.release), safe_str(osrelease));
        hit = 1;
    }
    if (libc_ok && procver && procver[0] && !contains_nocase(procver, u.release)) {
        LOGI("Kernel identity mismatch: uname.release=%s /proc/version does not contain it", safe_str(u.release));
        verboseLogRawLine("/proc/version", procver);
        hit = 1;
    }
    VLOGI("kernel osrelease=%s", osrelease ? osrelease : "<unreadable>");
    VLOGI("kernel version=%s", kversion ? kversion : "<unreadable>");

    free(osrelease);
    free(kversion);
    free(procver);
    return hit ? JNI_TRUE : JNI_FALSE;
}

// ─── Emulator ───────────────────────────────────────────────────────────────
static jboolean checkEmulatorFiles(void) {
    const char *emu[] = {
        "/dev/socket/qemud", "/dev/qemu_pipe", "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace", "/system/bin/qemu-props", NULL
    };
    for (int i = 0; emu[i]; i++) {
        if (access(emu[i], F_OK) == 0) {
            LOGI("Emulator artifact found: path=%s", emu[i]);
            return JNI_TRUE;
        }
    }
    return JNI_FALSE;
}

// ─── JNI table / JavaVM integrity ───────────────────────────────────────────
static int isTrustedRuntimeOwner(const char *path) {
    if (!path || !*path) return 0;
    return contains_nocase(path, "libart.so") ||
           contains_nocase(path, "libnativehelper.so") ||
           contains_nocase(path, "libandroid_runtime.so");
}

static int checkTrustedRuntimePointer(const char *label, void *addr) {
    if (!addr) return 0;
    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (!dladdr(addr, &info) || !info.dli_fname) {
        LOGI("Runtime pointer owner unresolved: label=%s addr=%p", safe_str(label), addr);
        return 1;
    }
    if (!isTrustedRuntimeOwner(info.dli_fname)) {
        LOGI("Runtime pointer owner mismatch: label=%s addr=%p owner=%s symbol=%s",
             safe_str(label), addr, safe_str(info.dli_fname), safe_str(info.dli_sname));
        return 1;
    }
    VLOGI("Runtime pointer OK: label=%s addr=%p owner=%s symbol=%s",
          safe_str(label), addr, safe_str(info.dli_fname), safe_str(info.dli_sname));
    return 0;
}

static jboolean checkJniTableIntegrity(JNIEnv *env) {
    if (!env || !*env) return JNI_FALSE;
    const struct JNINativeInterface *table = *env;
    int score = 0;
    VLOGI("JNI table address: env=%p table=%p", (void *)env, (void *)table);
    score += checkTrustedRuntimePointer("JNI.NewStringUTF", (void *)table->NewStringUTF) ? 3 : 0;
    score += checkTrustedRuntimePointer("JNI.GetMethodID", (void *)table->GetMethodID) ? 3 : 0;
    score += checkTrustedRuntimePointer("JNI.CallVoidMethod", (void *)table->CallVoidMethod) ? 3 : 0;
    score += checkTrustedRuntimePointer("JNI.GetObjectClass", (void *)table->GetObjectClass) ? 3 : 0;
    score += checkTrustedRuntimePointer("JNI.DeleteLocalRef", (void *)table->DeleteLocalRef) ? 2 : 0;
    score += checkTrustedRuntimePointer("JNI.GetStringUTFChars", (void *)table->GetStringUTFChars) ? 2 : 0;
    if (score >= 3) {
        LOGI("JNI function table integrity suspicious: score=%d", score);
        return JNI_TRUE;
    }
    return JNI_FALSE;
}

static jboolean checkJavaVmTableIntegrity(void) {
    if (!g_vm || !*g_vm) return JNI_FALSE;
    const struct JNIInvokeInterface *table = *g_vm;
    int score = 0;
    VLOGI("JavaVM table address: vm=%p table=%p", (void *)g_vm, (void *)table);
    score += checkTrustedRuntimePointer("JavaVM.GetEnv", (void *)table->GetEnv) ? 3 : 0;
    score += checkTrustedRuntimePointer("JavaVM.AttachCurrentThread", (void *)table->AttachCurrentThread) ? 3 : 0;
    score += checkTrustedRuntimePointer("JavaVM.DetachCurrentThread", (void *)table->DetachCurrentThread) ? 2 : 0;
    if (score >= 3) {
        LOGI("JavaVM function table integrity suspicious: score=%d", score);
        return JNI_TRUE;
    }
    return JNI_FALSE;
}

// ─── PHDR / linker module view ──────────────────────────────────────────────
static int mapsHasExecRange(const char *maps, uintptr_t addr) {
    if (!maps) return 0;
    char *copy = strdup(maps);
    if (!copy) return 0;
    int found = 0;
    char *save = NULL;
    char *line = strtok_r(copy, "\n", &save);
    while (line) {
        MapEntry e;
        if (parse_maps_line(line, &e) && addr >= e.start && addr < e.end && e.perms[2] == 'x') {
            found = 1;
            break;
        }
        line = strtok_r(NULL, "\n", &save);
    }
    free(copy);
    return found;
}

typedef struct PhdrCheckCtx {
    const char *maps;
    int suspicious;
    int hidden_exec_segment;
    int module_count;
    int logged_visible;
} PhdrCheckCtx;

#ifndef VERBOSE_MODULE_WALK
#define VERBOSE_MODULE_WALK 0
#endif

static int phdrCheckCallback(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    PhdrCheckCtx *ctx = (PhdrCheckCtx *)data;
    if (!info || !ctx) return 0;
    ctx->module_count++;

    const char *name = info->dlpi_name && info->dlpi_name[0] ? info->dlpi_name : "<main>";
    const char *matched = NULL;
    if (isSuspiciousPathPrecise(name, &matched)) {
        LOGI("Suspicious module visible through dl_iterate_phdr: term=%s name=%s base=%p phnum=%d",
             safe_str(matched), safe_str(name), (void *)(uintptr_t)info->dlpi_addr, (int)info->dlpi_phnum);
        ctx->suspicious = 1;
    }

    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_X) || ph->p_memsz == 0) continue;
        uintptr_t seg_start = (uintptr_t)(info->dlpi_addr + ph->p_vaddr);
        if (!mapsHasExecRange(ctx->maps, seg_start)) {
            LOGI("Executable module segment missing from maps view: module=%s base=%p seg_start=0x%lx memsz=0x%lx flags=0x%x",
                 basename_safe(name), (void *)(uintptr_t)info->dlpi_addr,
                 (unsigned long)seg_start, (unsigned long)ph->p_memsz, (unsigned int)ph->p_flags);
            ctx->hidden_exec_segment = 1;
            break;
        } else {
#if VERBOSE_MODULE_WALK
            if (ctx->logged_visible < 80) {
                VLOGI("PHDR executable segment visible: module=%s seg_start=0x%lx memsz=0x%lx flags=0x%x",
                      basename_safe(name), (unsigned long)seg_start, (unsigned long)ph->p_memsz, (unsigned int)ph->p_flags);
                ctx->logged_visible++;
            }
#endif
        }
    }
    return 0;
}

static jboolean checkLoadedModulesPhdr(void) {
    size_t len = 0;
    char *maps = read_file_raw_dynamic("/proc/self/maps", &len);
    if (!maps) return JNI_FALSE;

    PhdrCheckCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.maps = maps;
    dl_iterate_phdr(phdrCheckCallback, &ctx);
    free(maps);

    VLOGI("PHDR module scan summary: modules=%d suspicious=%d hidden_exec_segment=%d",
          ctx.module_count, ctx.suspicious, ctx.hidden_exec_segment);
    return (ctx.suspicious || ctx.hidden_exec_segment) ? JNI_TRUE : JNI_FALSE;
}

// ─── Self breakpoint checks ─────────────────────────────────────────────────
static int looksLikeBreakpointInstruction(void *addr) {
    if (!addr) return 0;
#if defined(__aarch64__)
    uint32_t insn = 0;
    memcpy(&insn, addr, sizeof(insn));
    return (insn & 0xFFE0001FU) == 0xD4200000U;
#elif defined(__arm__)
    uint16_t half = 0;
    memcpy(&half, addr, sizeof(half));
    return (half & 0xFF00U) == 0xBE00U;
#elif defined(__i386__) || defined(__x86_64__)
    uint8_t b = 0;
    memcpy(&b, addr, sizeof(b));
    return b == 0xCC;
#else
    return 0;
#endif
}

static jboolean checkSelfBreakpoints(void) {
    struct BreakpointTarget { const char *name; void *addr; } targets[] = {
        {"JNI_OnLoad", (void *)&JNI_OnLoad},
        {"checkMapsArtifactsRaw", (void *)&checkMapsArtifactsRaw},
        {"checkMemoryIntegrityLive", (void *)&checkMemoryIntegrityLive},
        {"checkLinkerAndInlineHooks", (void *)&checkLinkerAndInlineHooks},
        {"checkLoadedModulesPhdr", (void *)&checkLoadedModulesPhdr},
        {NULL, NULL}
    };

    for (int i = 0; targets[i].addr; i++) {
#if VERBOSE
#if defined(__aarch64__)
        uint32_t insn = 0;
        memcpy(&insn, targets[i].addr, sizeof(insn));
        VLOGI("Self entry probe: name=%s addr=%p first_insn=0x%08x", targets[i].name, targets[i].addr, insn);
#elif defined(__arm__)
        uint16_t half = 0;
        memcpy(&half, targets[i].addr, sizeof(half));
        VLOGI("Self entry probe: name=%s addr=%p first_half=0x%04x", targets[i].name, targets[i].addr, half);
#elif defined(__i386__) || defined(__x86_64__)
        uint8_t b = 0;
        memcpy(&b, targets[i].addr, sizeof(b));
        VLOGI("Self entry probe: name=%s addr=%p first_byte=0x%02x", targets[i].name, targets[i].addr, b);
#else
        VLOGI("Self entry probe: name=%s addr=%p", targets[i].name, targets[i].addr);
#endif
#endif
        if (looksLikeBreakpointInstruction(targets[i].addr)) {
            LOGI("Breakpoint-like instruction found at sensitive native entry: name=%s addr=%p", targets[i].name, targets[i].addr);
            return JNI_TRUE;
        }
    }
    return JNI_FALSE;
}



// ─── ART / ClassLoader / package / location side-effect checks ──────────────
#define APP_PACKAGE_NAME "com.example.securitysample"

static void clearJniException(JNIEnv *env, const char *where) {
    if (!env) return;
    if ((*env)->ExceptionCheck(env)) {
#if VERBOSE
        VLOGI("JNI reflective probe exception cleared: %s", where ? where : "<unknown>");
#endif
        (*env)->ExceptionClear(env);
    }
}

static int jstringToBuffer(JNIEnv *env, jstring js, char *out, size_t cap) {
    if (!env || !js || !out || cap == 0) return 0;
    const char *utf = (*env)->GetStringUTFChars(env, js, NULL);
    if (!utf) {
        clearJniException(env, "GetStringUTFChars");
        return 0;
    }
    snprintf(out, cap, "%s", utf);
    (*env)->ReleaseStringUTFChars(env, js, utf);
    return 1;
}

static int objectToString(JNIEnv *env, jobject obj, char *out, size_t cap) {
    if (!env || !obj || !out || cap == 0) return 0;
    out[0] = '\0';
    jclass objCls = (*env)->GetObjectClass(env, obj);
    if (!objCls) {
        clearJniException(env, "objectToString.GetObjectClass");
        return 0;
    }
    jmethodID toStringMid = (*env)->GetMethodID(env, objCls, "toString", "()Ljava/lang/String;");
    if (!toStringMid) {
        clearJniException(env, "objectToString.toString mid");
        (*env)->DeleteLocalRef(env, objCls);
        return 0;
    }
    jstring js = (jstring)(*env)->CallObjectMethod(env, obj, toStringMid);
    if ((*env)->ExceptionCheck(env) || !js) {
        clearJniException(env, "objectToString.CallObjectMethod");
        (*env)->DeleteLocalRef(env, objCls);
        return 0;
    }
    int ok = jstringToBuffer(env, js, out, cap);
    (*env)->DeleteLocalRef(env, js);
    (*env)->DeleteLocalRef(env, objCls);
    return ok;
}

static int objectClassName(JNIEnv *env, jobject obj, char *out, size_t cap) {
    if (!env || !obj || !out || cap == 0) return 0;
    out[0] = '\0';
    jclass clsObj = (*env)->GetObjectClass(env, obj);
    if (!clsObj) {
        clearJniException(env, "objectClassName.GetObjectClass");
        return 0;
    }
    jclass classCls = (*env)->FindClass(env, "java/lang/Class");
    if (!classCls) {
        clearJniException(env, "objectClassName.FindClass(Class)");
        (*env)->DeleteLocalRef(env, clsObj);
        return 0;
    }
    jmethodID getNameMid = (*env)->GetMethodID(env, classCls, "getName", "()Ljava/lang/String;");
    if (!getNameMid) {
        clearJniException(env, "objectClassName.getName mid");
        (*env)->DeleteLocalRef(env, classCls);
        (*env)->DeleteLocalRef(env, clsObj);
        return 0;
    }
    jstring name = (jstring)(*env)->CallObjectMethod(env, clsObj, getNameMid);
    if ((*env)->ExceptionCheck(env) || !name) {
        clearJniException(env, "objectClassName.getName call");
        (*env)->DeleteLocalRef(env, classCls);
        (*env)->DeleteLocalRef(env, clsObj);
        return 0;
    }
    int ok = jstringToBuffer(env, name, out, cap);
    (*env)->DeleteLocalRef(env, name);
    (*env)->DeleteLocalRef(env, classCls);
    (*env)->DeleteLocalRef(env, clsObj);
    return ok;
}

static int artSuspiciousText(const char *s) {
    if (!s || !*s) return 0;
    return contains_nocase(s, "xposed") ||
           contains_nocase(s, "lsposed") ||
           contains_nocase(s, "lsp") ||
           contains_nocase(s, "de.robv.android.xposed") ||
           contains_nocase(s, "io.github.libxposed") ||
           contains_nocase(s, "sandhook") ||
           contains_nocase(s, "yahfa") ||
           contains_nocase(s, "lsplant") ||
           contains_nocase(s, "edxp") ||
           contains_nocase(s, "riru") ||
           contains_nocase(s, "zygisk") ||
           contains_nocase(s, "frida") ||
           contains_nocase(s, "gum-js") ||
           contains_nocase(s, "substrate") ||
           contains_nocase(s, "cydia") ||
           contains_nocase(s, "dobby") ||
           contains_nocase(s, "shadowhook") ||
           contains_nocase(s, "hma_oss") ||
           contains_nocase(s, "hidemyapplist") ||
           contains_nocase(s, "fakegps") ||
           contains_nocase(s, "fake.gps") ||
           contains_nocase(s, "mocklocation") ||
           contains_nocase(s, "mock.location");
}

static int isForeignDataAppPath(const char *s) {
    if (!s || !*s) return 0;
    if (!contains_nocase(s, "/data/app/")) return 0;
    if (contains_nocase(s, APP_PACKAGE_NAME)) return 0;
    if (contains_nocase(s, "/data/resource-cache/")) return 0;
    return 1;
}

static jobject getCurrentApplication(JNIEnv *env) {
    if (!env) return NULL;
    jclass atCls = (*env)->FindClass(env, "android/app/ActivityThread");
    if (!atCls) {
        clearJniException(env, "ActivityThread class");
        return NULL;
    }
    jmethodID mid = (*env)->GetStaticMethodID(env, atCls, "currentApplication", "()Landroid/app/Application;");
    if (!mid) {
        clearJniException(env, "ActivityThread.currentApplication mid");
        (*env)->DeleteLocalRef(env, atCls);
        return NULL;
    }
    jobject app = (*env)->CallStaticObjectMethod(env, atCls, mid);
    if ((*env)->ExceptionCheck(env)) {
        clearJniException(env, "ActivityThread.currentApplication call");
        app = NULL;
    }
    (*env)->DeleteLocalRef(env, atCls);
    return app;
}

static jobject getApplicationClassLoader(JNIEnv *env) {
    if (!env) return NULL;
    jobject app = getCurrentApplication(env);
    if (!app) return NULL;

    jclass ctxCls = (*env)->FindClass(env, "android/content/Context");
    jmethodID getClMid = ctxCls ? (*env)->GetMethodID(env, ctxCls, "getClassLoader", "()Ljava/lang/ClassLoader;") : NULL;
    jobject loader = NULL;
    if (getClMid) loader = (*env)->CallObjectMethod(env, app, getClMid);
    if ((*env)->ExceptionCheck(env)) {
        clearJniException(env, "Context.getClassLoader fallback");
        loader = NULL;
    }
    if (ctxCls) (*env)->DeleteLocalRef(env, ctxCls);
    (*env)->DeleteLocalRef(env, app);
    return loader;
}

static jobject getCurrentThreadClassLoader(JNIEnv *env) {
    if (!env) return NULL;
    jclass threadCls = (*env)->FindClass(env, "java/lang/Thread");
    if (!threadCls) {
        clearJniException(env, "Thread class");
        return getApplicationClassLoader(env);
    }
    jmethodID currentThreadMid = (*env)->GetStaticMethodID(env, threadCls, "currentThread", "()Ljava/lang/Thread;");
    jmethodID getClMid = (*env)->GetMethodID(env, threadCls, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
    if (!currentThreadMid || !getClMid) {
        clearJniException(env, "Thread classloader mids");
        (*env)->DeleteLocalRef(env, threadCls);
        return getApplicationClassLoader(env);
    }
    jobject thread = (*env)->CallStaticObjectMethod(env, threadCls, currentThreadMid);
    if ((*env)->ExceptionCheck(env) || !thread) {
        clearJniException(env, "Thread.currentThread call");
        (*env)->DeleteLocalRef(env, threadCls);
        return getApplicationClassLoader(env);
    }
    jobject loader = (*env)->CallObjectMethod(env, thread, getClMid);
    if ((*env)->ExceptionCheck(env)) {
        clearJniException(env, "Thread.getContextClassLoader call");
        loader = NULL;
    }
    (*env)->DeleteLocalRef(env, thread);
    (*env)->DeleteLocalRef(env, threadCls);

    if (!loader) {
        VLOGI("Thread context ClassLoader is null; falling back to Application ClassLoader");
        loader = getApplicationClassLoader(env);
    }
    return loader;
}

static void setThreadContextClassLoaderFromApplication(JNIEnv *env) {
    if (!env) return;
    jobject appLoader = getApplicationClassLoader(env);
    if (!appLoader) return;

    jclass threadCls = (*env)->FindClass(env, "java/lang/Thread");
    jmethodID currentThreadMid = threadCls ? (*env)->GetStaticMethodID(env, threadCls, "currentThread", "()Ljava/lang/Thread;") : NULL;
    jmethodID setClMid = threadCls ? (*env)->GetMethodID(env, threadCls, "setContextClassLoader", "(Ljava/lang/ClassLoader;)V") : NULL;
    if (currentThreadMid && setClMid) {
        jobject thread = (*env)->CallStaticObjectMethod(env, threadCls, currentThreadMid);
        if ((*env)->ExceptionCheck(env)) clearJniException(env, "Thread.currentThread set CL");
        else if (thread) {
            (*env)->CallVoidMethod(env, thread, setClMid, appLoader);
            if ((*env)->ExceptionCheck(env)) clearJniException(env, "Thread.setContextClassLoader");
            else VLOGI("Deep worker context ClassLoader set to Application ClassLoader");
            (*env)->DeleteLocalRef(env, thread);
        }
    } else clearJniException(env, "Thread.setContextClassLoader mids");
    if (threadCls) (*env)->DeleteLocalRef(env, threadCls);
    (*env)->DeleteLocalRef(env, appLoader);
}

static int tryLoadClassWithLoader(JNIEnv *env, jobject loader, const char *dottedName) {
    if (!env || !loader || !dottedName) return 0;
    jclass clCls = (*env)->FindClass(env, "java/lang/ClassLoader");
    if (!clCls) {
        clearJniException(env, "ClassLoader class");
        return 0;
    }
    jmethodID loadMid = (*env)->GetMethodID(env, clCls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (!loadMid) {
        clearJniException(env, "ClassLoader.loadClass mid");
        (*env)->DeleteLocalRef(env, clCls);
        return 0;
    }
    jstring name = (*env)->NewStringUTF(env, dottedName);
    if (!name) {
        (*env)->DeleteLocalRef(env, clCls);
        return 0;
    }
    jobject cls = (*env)->CallObjectMethod(env, loader, loadMid, name);
    int found = 0;
    if ((*env)->ExceptionCheck(env)) {
        clearJniException(env, "ClassLoader.loadClass call");
    } else if (cls) {
        found = 1;
        (*env)->DeleteLocalRef(env, cls);
    }
    (*env)->DeleteLocalRef(env, name);
    (*env)->DeleteLocalRef(env, clCls);
    return found;
}

static jboolean checkArtBridgeClasses(JNIEnv *env) {
    if (!env) return JNI_FALSE;
    const char *classes[] = {
        "de.robv.android.xposed.XposedBridge",
        "de.robv.android.xposed.XC_MethodHook",
        "de.robv.android.xposed.XposedHelpers",
        "org.lsposed.lspd.core.Main",
        "org.lsposed.lspd.impl.LSPosedBridge",
        "org.lsposed.hiddenapibypass.HiddenApiBypass",
        "io.github.libxposed.api.XposedInterface",
        "com.saurik.substrate.MS",
        "com.swift.sandhook.SandHook",
        "de.robv.android.xposed.callbacks.XC_LoadPackage",
        NULL
    };

    jobject loader = getCurrentThreadClassLoader(env);
    int checked = 0;
    int suspicious = 0;
    for (int i = 0; classes[i]; i++) {
        checked++;
        if (loader && tryLoadClassWithLoader(env, loader, classes[i])) {
            LOGI("ART bridge class resolvable from app ClassLoader: %s", classes[i]);
            suspicious = 1;
        }

        char slashName[256];
        snprintf(slashName, sizeof(slashName), "%s", classes[i]);
        for (char *p = slashName; *p; p++) if (*p == '.') *p = '/';
        jclass cls = (*env)->FindClass(env, slashName);
        if ((*env)->ExceptionCheck(env)) {
            clearJniException(env, "FindClass bridge probe");
        } else if (cls) {
            LOGI("ART bridge class resolvable through FindClass: %s", classes[i]);
            suspicious = 1;
            (*env)->DeleteLocalRef(env, cls);
        }
    }
    if (loader) (*env)->DeleteLocalRef(env, loader);
    VLOGI("ART bridge class scan complete: checked=%d suspicious=%d", checked, suspicious);
    return suspicious ? JNI_TRUE : JNI_FALSE;
}

static int scanStackArray(JNIEnv *env, jobjectArray arr, const char *source) {
    if (!env || !arr) return 0;
    jsize n = (*env)->GetArrayLength(env, arr);
    int suspicious = 0;
    for (jsize i = 0; i < n; i++) {
        jobject frame = (*env)->GetObjectArrayElement(env, arr, i);
        if (!frame) continue;
        char text[768];
        if (objectToString(env, frame, text, sizeof(text))) {
            if (i < 10) VLOGI("ART stack frame sample: source=%s frame_index=%d frame=%s", safe_str(source), (int)i, text);
            if (artSuspiciousText(text)) {
                LOGI("Suspicious ART stack frame: source=%s frame_index=%d frame=%s", safe_str(source), (int)i, text);
                suspicious = 1;
            }
        }
        (*env)->DeleteLocalRef(env, frame);
    }
    VLOGI("ART stack scan complete: source=%s frames=%d suspicious=%d", safe_str(source), (int)n, suspicious);
    return suspicious;
}

static jboolean checkArtStack(JNIEnv *env) {
    if (!env) return JNI_FALSE;
    int suspicious = 0;

    jclass throwableCls = (*env)->FindClass(env, "java/lang/Throwable");
    if (throwableCls) {
        jmethodID ctor = (*env)->GetMethodID(env, throwableCls, "<init>", "()V");
        jmethodID getStackMid = (*env)->GetMethodID(env, throwableCls, "getStackTrace", "()[Ljava/lang/StackTraceElement;");
        if (ctor && getStackMid) {
            jobject thr = (*env)->NewObject(env, throwableCls, ctor);
            if ((*env)->ExceptionCheck(env)) {
                clearJniException(env, "Throwable ctor");
            } else if (thr) {
                jobjectArray arr = (jobjectArray)(*env)->CallObjectMethod(env, thr, getStackMid);
                if ((*env)->ExceptionCheck(env)) clearJniException(env, "Throwable.getStackTrace");
                else if (arr) {
                    suspicious |= scanStackArray(env, arr, "Throwable");
                    (*env)->DeleteLocalRef(env, arr);
                }
                (*env)->DeleteLocalRef(env, thr);
            }
        } else clearJniException(env, "Throwable mids");
        (*env)->DeleteLocalRef(env, throwableCls);
    } else clearJniException(env, "Throwable class");

    jclass threadCls = (*env)->FindClass(env, "java/lang/Thread");
    if (threadCls) {
        jmethodID currentThreadMid = (*env)->GetStaticMethodID(env, threadCls, "currentThread", "()Ljava/lang/Thread;");
        jmethodID getStackMid = (*env)->GetMethodID(env, threadCls, "getStackTrace", "()[Ljava/lang/StackTraceElement;");
        if (currentThreadMid && getStackMid) {
            jobject thread = (*env)->CallStaticObjectMethod(env, threadCls, currentThreadMid);
            if ((*env)->ExceptionCheck(env)) clearJniException(env, "Thread.currentThread stack");
            else if (thread) {
                jobjectArray arr = (jobjectArray)(*env)->CallObjectMethod(env, thread, getStackMid);
                if ((*env)->ExceptionCheck(env)) clearJniException(env, "Thread.getStackTrace");
                else if (arr) {
                    suspicious |= scanStackArray(env, arr, "Thread");
                    (*env)->DeleteLocalRef(env, arr);
                }
                (*env)->DeleteLocalRef(env, thread);
            }
        } else clearJniException(env, "Thread stack mids");
        (*env)->DeleteLocalRef(env, threadCls);
    } else clearJniException(env, "Thread class stack");

    return suspicious ? JNI_TRUE : JNI_FALSE;
}

static int inspectDexElements(JNIEnv *env, jobject pathList) {
    if (!env || !pathList) return 0;
    int suspicious = 0;
    jclass classCls = (*env)->FindClass(env, "java/lang/Class");
    jclass fieldCls = (*env)->FindClass(env, "java/lang/reflect/Field");
    if (!classCls || !fieldCls) {
        clearJniException(env, "inspectDexElements reflection classes");
        if (classCls) (*env)->DeleteLocalRef(env, classCls);
        if (fieldCls) (*env)->DeleteLocalRef(env, fieldCls);
        return 0;
    }
    jmethodID getDeclaredFieldMid = (*env)->GetMethodID(env, classCls, "getDeclaredField", "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
    jmethodID setAccessibleMid = (*env)->GetMethodID(env, fieldCls, "setAccessible", "(Z)V");
    jmethodID fieldGetMid = (*env)->GetMethodID(env, fieldCls, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
    if (!getDeclaredFieldMid || !setAccessibleMid || !fieldGetMid) {
        clearJniException(env, "inspectDexElements reflection mids");
        (*env)->DeleteLocalRef(env, classCls);
        (*env)->DeleteLocalRef(env, fieldCls);
        return 0;
    }

    jclass pathListCls = (*env)->GetObjectClass(env, pathList);
    jstring dexFieldName = (*env)->NewStringUTF(env, "dexElements");
    jobject field = NULL;
    if (pathListCls && dexFieldName) field = (*env)->CallObjectMethod(env, pathListCls, getDeclaredFieldMid, dexFieldName);
    if ((*env)->ExceptionCheck(env) || !field) {
        clearJniException(env, "DexPathList.dexElements field");
    } else {
        (*env)->CallVoidMethod(env, field, setAccessibleMid, JNI_TRUE);
        clearJniException(env, "dexElements.setAccessible");
        jobject arrObj = (*env)->CallObjectMethod(env, field, fieldGetMid, pathList);
        if ((*env)->ExceptionCheck(env) || !arrObj) {
            clearJniException(env, "dexElements.get");
        } else {
            jobjectArray arr = (jobjectArray)arrObj;
            jsize count = (*env)->GetArrayLength(env, arr);
            for (jsize i = 0; i < count && i < 64; i++) {
                jobject element = (*env)->GetObjectArrayElement(env, arr, i);
                if (!element) continue;
                char value[1024];
                if (objectToString(env, element, value, sizeof(value))) {
                    VLOGI("ART dex element sample: index=%d value=%s", (int)i, value);
                    if (artSuspiciousText(value) || isForeignDataAppPath(value) || contains_nocase(value, "/data/adb/") || contains_nocase(value, "/data/local/tmp/")) {
                        LOGI("Suspicious ART dex element: index=%d value=%s", (int)i, value);
                        suspicious = 1;
                    }
                }
                (*env)->DeleteLocalRef(env, element);
            }
            VLOGI("ART dex element scan complete: count=%d suspicious=%d", (int)count, suspicious);
            (*env)->DeleteLocalRef(env, arrObj);
        }
        (*env)->DeleteLocalRef(env, field);
    }
    if (dexFieldName) (*env)->DeleteLocalRef(env, dexFieldName);
    if (pathListCls) (*env)->DeleteLocalRef(env, pathListCls);
    (*env)->DeleteLocalRef(env, classCls);
    (*env)->DeleteLocalRef(env, fieldCls);
    return suspicious;
}

static jboolean checkArtClassLoader(JNIEnv *env) {
    if (!env) return JNI_FALSE;
    jobject loader = getCurrentThreadClassLoader(env);
    if (!loader) {
        VLOGI("ART ClassLoader check skipped: no context ClassLoader");
        return JNI_FALSE;
    }

    jclass classLoaderCls = (*env)->FindClass(env, "java/lang/ClassLoader");
    jmethodID getParentMid = classLoaderCls ? (*env)->GetMethodID(env, classLoaderCls, "getParent", "()Ljava/lang/ClassLoader;") : NULL;
    if (!classLoaderCls || !getParentMid) clearJniException(env, "ClassLoader.getParent mid");

    int suspicious = 0;
    jobject cur = loader;
    for (int depth = 0; cur && depth < 8; depth++) {
        char clsName[256], desc[1536];
        objectClassName(env, cur, clsName, sizeof(clsName));
        objectToString(env, cur, desc, sizeof(desc));
        VLOGI("ART ClassLoader chain: depth=%d class=%s desc=%s", depth, safe_str(clsName), safe_str(desc));
        if (artSuspiciousText(clsName) || artSuspiciousText(desc) ||
            contains_nocase(clsName, "InMemoryDexClassLoader") ||
            contains_nocase(clsName, "DelegateLastClassLoader") ||
            isForeignDataAppPath(desc) || contains_nocase(desc, "/data/adb/") || contains_nocase(desc, "/data/local/tmp/")) {
            LOGI("Suspicious ART ClassLoader: depth=%d class=%s desc=%s", depth, safe_str(clsName), safe_str(desc));
            suspicious = 1;
        }

        // Best-effort PathClassLoader pathList introspection. Failures are diagnostic only.
        jclass classCls = (*env)->FindClass(env, "java/lang/Class");
        jclass fieldCls = (*env)->FindClass(env, "java/lang/reflect/Field");
        if (classCls && fieldCls) {
            jmethodID getDeclaredFieldMid = (*env)->GetMethodID(env, classCls, "getDeclaredField", "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
            jmethodID setAccessibleMid = (*env)->GetMethodID(env, fieldCls, "setAccessible", "(Z)V");
            jmethodID fieldGetMid = (*env)->GetMethodID(env, fieldCls, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
            jclass curCls = (*env)->GetObjectClass(env, cur);
            jstring pathListName = (*env)->NewStringUTF(env, "pathList");
            jobject field = NULL;
            if (curCls && pathListName && getDeclaredFieldMid) field = (*env)->CallObjectMethod(env, curCls, getDeclaredFieldMid, pathListName);
            if ((*env)->ExceptionCheck(env) || !field) {
                clearJniException(env, "ClassLoader.pathList field");
            } else {
                if (setAccessibleMid) (*env)->CallVoidMethod(env, field, setAccessibleMid, JNI_TRUE);
                clearJniException(env, "pathList.setAccessible");
                jobject pathList = fieldGetMid ? (*env)->CallObjectMethod(env, field, fieldGetMid, cur) : NULL;
                if ((*env)->ExceptionCheck(env) || !pathList) {
                    clearJniException(env, "pathList.get");
                } else {
                    char pathDesc[1536];
                    if (objectToString(env, pathList, pathDesc, sizeof(pathDesc))) {
                        VLOGI("ART ClassLoader pathList=%s", pathDesc);
                        if (artSuspiciousText(pathDesc) || isForeignDataAppPath(pathDesc) || contains_nocase(pathDesc, "/data/adb/") || contains_nocase(pathDesc, "/data/local/tmp/")) {
                            LOGI("Suspicious ART ClassLoader pathList=%s", pathDesc);
                            suspicious = 1;
                        }
                    }
                    suspicious |= inspectDexElements(env, pathList);
                    (*env)->DeleteLocalRef(env, pathList);
                }
                (*env)->DeleteLocalRef(env, field);
            }
            if (pathListName) (*env)->DeleteLocalRef(env, pathListName);
            if (curCls) (*env)->DeleteLocalRef(env, curCls);
        } else clearJniException(env, "ClassLoader pathList reflection setup");
        if (classCls) (*env)->DeleteLocalRef(env, classCls);
        if (fieldCls) (*env)->DeleteLocalRef(env, fieldCls);

        jobject parent = NULL;
        if (getParentMid) parent = (*env)->CallObjectMethod(env, cur, getParentMid);
        if ((*env)->ExceptionCheck(env)) {
            clearJniException(env, "ClassLoader.getParent call");
            parent = NULL;
        }
        if (cur != loader) (*env)->DeleteLocalRef(env, cur);
        cur = parent;
    }
    (*env)->DeleteLocalRef(env, loader);
    if (classLoaderCls) (*env)->DeleteLocalRef(env, classLoaderCls);
    return suspicious ? JNI_TRUE : JNI_FALSE;
}

static jboolean checkArtDexMaps(void) {
    size_t len = 0;
    char *maps = read_file_raw_dynamic("/proc/self/maps", &len);
    if (!maps) return JNI_FALSE;
    int suspicious = 0;
    int dex_related = 0;
    char *save = NULL;
    char *line = strtok_r(maps, "\n", &save);
    while (line) {
        int dexish = contains_nocase(line, ".dex") || contains_nocase(line, ".jar") ||
                     contains_nocase(line, ".apk") || contains_nocase(line, ".vdex") ||
                     contains_nocase(line, ".oat") || contains_nocase(line, "InMemoryDex");
        if (dexish) {
            dex_related++;
            if (isSuspiciousPathPrecise(line, NULL) || artSuspiciousText(line) ||
                contains_nocase(line, "/data/adb/") || contains_nocase(line, "/data/local/tmp/") ||
                isForeignDataAppPath(line)) {
                LOGI("Suspicious ART dex/map line: %s", line);
                suspicious = 1;
            }
        }
        line = strtok_r(NULL, "\n", &save);
    }
    VLOGI("ART dex/map scan complete: dex_related_lines=%d suspicious=%d", dex_related, suspicious);
    free(maps);
    return suspicious ? JNI_TRUE : JNI_FALSE;
}

static int pmObjectExistsByString(JNIEnv *env, jobject pm, const char *methodName, const char *sig, const char *pkg) {
    if (!env || !pm || !methodName || !sig || !pkg) return 0;
    jclass pmCls = (*env)->GetObjectClass(env, pm);
    if (!pmCls) { clearJniException(env, "PM object class"); return 0; }
    jmethodID mid = (*env)->GetMethodID(env, pmCls, methodName, sig);
    if (!mid) { clearJniException(env, "PM method mid"); (*env)->DeleteLocalRef(env, pmCls); return 0; }
    jstring jpkg = (*env)->NewStringUTF(env, pkg);
    jobject obj = NULL;
    if (strcmp(sig, "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;") == 0 ||
        strcmp(sig, "(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;") == 0) {
        obj = (*env)->CallObjectMethod(env, pm, mid, jpkg, 0);
    } else if (strcmp(sig, "(Ljava/lang/String;)Landroid/content/Intent;") == 0) {
        obj = (*env)->CallObjectMethod(env, pm, mid, jpkg);
    }
    int exists = 0;
    if ((*env)->ExceptionCheck(env)) clearJniException(env, methodName);
    else if (obj) { exists = 1; (*env)->DeleteLocalRef(env, obj); }
    if (jpkg) (*env)->DeleteLocalRef(env, jpkg);
    (*env)->DeleteLocalRef(env, pmCls);
    return exists;
}

static int pmInstalledPackagesContains(JNIEnv *env, jobject pm, const char *pkg) {
    if (!env || !pm || !pkg) return 0;
    jclass pmCls = (*env)->GetObjectClass(env, pm);
    if (!pmCls) { clearJniException(env, "PM installed class"); return 0; }
    jmethodID getInstalledMid = (*env)->GetMethodID(env, pmCls, "getInstalledPackages", "(I)Ljava/util/List;");
    if (!getInstalledMid) { clearJniException(env, "getInstalledPackages mid"); (*env)->DeleteLocalRef(env, pmCls); return 0; }
    jobject list = (*env)->CallObjectMethod(env, pm, getInstalledMid, 0);
    if ((*env)->ExceptionCheck(env) || !list) {
        clearJniException(env, "getInstalledPackages call");
        (*env)->DeleteLocalRef(env, pmCls);
        return 0;
    }
    jclass listCls = (*env)->FindClass(env, "java/util/List");
    jmethodID sizeMid = listCls ? (*env)->GetMethodID(env, listCls, "size", "()I") : NULL;
    jmethodID getMid = listCls ? (*env)->GetMethodID(env, listCls, "get", "(I)Ljava/lang/Object;") : NULL;
    int found = 0;
    if (sizeMid && getMid) {
        jint size = (*env)->CallIntMethod(env, list, sizeMid);
        if ((*env)->ExceptionCheck(env)) { clearJniException(env, "installed list size"); size = 0; }
        for (jint i = 0; i < size && i < 300; i++) {
            jobject pi = (*env)->CallObjectMethod(env, list, getMid, i);
            if ((*env)->ExceptionCheck(env)) { clearJniException(env, "installed list get"); break; }
            if (!pi) continue;
            jclass piCls = (*env)->GetObjectClass(env, pi);
            jfieldID pkgField = piCls ? (*env)->GetFieldID(env, piCls, "packageName", "Ljava/lang/String;") : NULL;
            if ((*env)->ExceptionCheck(env)) clearJniException(env, "PackageInfo.packageName field");
            if (pkgField) {
                jstring name = (jstring)(*env)->GetObjectField(env, pi, pkgField);
                if ((*env)->ExceptionCheck(env)) clearJniException(env, "PackageInfo.packageName get");
                else if (name) {
                    char buf[256];
                    if (jstringToBuffer(env, name, buf, sizeof(buf)) && strcmp(buf, pkg) == 0) found = 1;
                    (*env)->DeleteLocalRef(env, name);
                }
            }
            if (piCls) (*env)->DeleteLocalRef(env, piCls);
            (*env)->DeleteLocalRef(env, pi);
            if (found) break;
        }
    } else clearJniException(env, "java.util.List mids");
    if (listCls) (*env)->DeleteLocalRef(env, listCls);
    (*env)->DeleteLocalRef(env, list);
    (*env)->DeleteLocalRef(env, pmCls);
    return found;
}

static jboolean checkPackageRiskAndInconsistency(JNIEnv *env, int *out_inconsistent) {
    if (out_inconsistent) *out_inconsistent = 0;
    if (!env) return JNI_FALSE;
    jobject app = getCurrentApplication(env);
    if (!app) {
        VLOGI("Package risk check skipped: currentApplication unavailable");
        return JNI_FALSE;
    }
    jclass ctxCls = (*env)->FindClass(env, "android/content/Context");
    jmethodID getPmMid = ctxCls ? (*env)->GetMethodID(env, ctxCls, "getPackageManager", "()Landroid/content/pm/PackageManager;") : NULL;
    jobject pm = NULL;
    if (getPmMid) pm = (*env)->CallObjectMethod(env, app, getPmMid);
    if ((*env)->ExceptionCheck(env) || !pm) {
        clearJniException(env, "Context.getPackageManager");
        if (ctxCls) (*env)->DeleteLocalRef(env, ctxCls);
        (*env)->DeleteLocalRef(env, app);
        return JNI_FALSE;
    }

    const char *riskyPkgs[] = {
        "org.lsposed.manager",
        "org.frknkrc44.hma_oss",
        "com.tsng.hidemyapplist",
        "com.topjohnwu.magisk",
        "io.github.huskydg.magisk",
        "com.lexa.fakegps",
        "com.blogspot.newapphorizons.fakegps",
        "com.incorporateapps.fakegps.fre",
        "com.theappninjas.fakegpsjoystick",
        "ru.gavrikov.mocklocations",
        "com.rosteam.gpsemulator",
        "io.github.auag0.fakelocation",
        NULL
    };

    int risk = 0;
    int inconsistent = 0;
    for (int i = 0; riskyPkgs[i]; i++) {
        const char *pkg = riskyPkgs[i];
        int pkgInfo = pmObjectExistsByString(env, pm, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;", pkg);
        int appInfo = pmObjectExistsByString(env, pm, "getApplicationInfo", "(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;", pkg);
        int launchIntent = pmObjectExistsByString(env, pm, "getLaunchIntentForPackage", "(Ljava/lang/String;)Landroid/content/Intent;", pkg);
        int installed = pmInstalledPackagesContains(env, pm, pkg);
        int seen = pkgInfo + appInfo + launchIntent + installed;
        if (seen > 0) {
            LOGI("Risky package visibility signal: pkg=%s getPackageInfo=%d getApplicationInfo=%d launchIntent=%d installedList=%d",
                 pkg, pkgInfo, appInfo, launchIntent, installed);
            risk = 1;
            if (seen > 0 && seen < 4) {
                LOGI("Package visibility inconsistency for risky pkg=%s seen_count=%d/4", pkg, seen);
                inconsistent = 1;
            }
        } else {
            VLOGI("Risky package not visible via checked PM views: pkg=%s", pkg);
        }
    }

    if (out_inconsistent) *out_inconsistent = inconsistent;
    (*env)->DeleteLocalRef(env, pm);
    if (ctxCls) (*env)->DeleteLocalRef(env, ctxCls);
    (*env)->DeleteLocalRef(env, app);
    return risk ? JNI_TRUE : JNI_FALSE;
}

static jstring settingsSecureGetString(JNIEnv *env, jobject resolver, const char *key) {
    if (!env || !resolver || !key) return NULL;
    jclass secureCls = (*env)->FindClass(env, "android/provider/Settings$Secure");
    if (!secureCls) { clearJniException(env, "Settings.Secure class"); return NULL; }
    jmethodID getStringMid = (*env)->GetStaticMethodID(env, secureCls, "getString", "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;");
    if (!getStringMid) { clearJniException(env, "Settings.Secure.getString mid"); (*env)->DeleteLocalRef(env, secureCls); return NULL; }
    jstring jkey = (*env)->NewStringUTF(env, key);
    jstring val = NULL;
    if (jkey) val = (jstring)(*env)->CallStaticObjectMethod(env, secureCls, getStringMid, resolver, jkey);
    if ((*env)->ExceptionCheck(env)) {
        clearJniException(env, "Settings.Secure.getString call");
        val = NULL;
    }
    if (jkey) (*env)->DeleteLocalRef(env, jkey);
    (*env)->DeleteLocalRef(env, secureCls);
    return val;
}

static jboolean checkLocationEnvironment(JNIEnv *env) {
    if (!env) return JNI_FALSE;
    jobject app = getCurrentApplication(env);
    if (!app) {
        VLOGI("Location environment check skipped: currentApplication unavailable");
        return JNI_FALSE;
    }
    int hit = 0;
    jclass ctxCls = (*env)->FindClass(env, "android/content/Context");
    if (!ctxCls) {
        clearJniException(env, "Context class for location");
        (*env)->DeleteLocalRef(env, app);
        return JNI_FALSE;
    }

    jmethodID getResolverMid = (*env)->GetMethodID(env, ctxCls, "getContentResolver", "()Landroid/content/ContentResolver;");
    jobject resolver = getResolverMid ? (*env)->CallObjectMethod(env, app, getResolverMid) : NULL;
    if ((*env)->ExceptionCheck(env)) { clearJniException(env, "Context.getContentResolver"); resolver = NULL; }
    if (resolver) {
        const char *keys[] = {"mock_location", "mock_location_app", "development_settings_enabled", NULL};
        for (int i = 0; keys[i]; i++) {
            jstring val = settingsSecureGetString(env, resolver, keys[i]);
            char buf[512] = {0};
            if (val && jstringToBuffer(env, val, buf, sizeof(buf))) {
                VLOGI("Settings.Secure signal: %s=%s", keys[i], safe_str(buf));
                if ((strcmp(keys[i], "mock_location") == 0 && strcmp(buf, "1") == 0) ||
                    (strcmp(keys[i], "mock_location_app") == 0 && buf[0] != '\0')) {
                    LOGI("Mock location setting signal: %s=%s", keys[i], safe_str(buf));
                    hit = 1;
                }
                if (strcmp(keys[i], "development_settings_enabled") == 0 && strcmp(buf, "1") == 0) {
                    VLOGI("Developer options enabled signal: %s=%s", keys[i], safe_str(buf));
                }
            }
            if (val) (*env)->DeleteLocalRef(env, val);
        }
        (*env)->DeleteLocalRef(env, resolver);
    }

    jmethodID getServiceMid = (*env)->GetMethodID(env, ctxCls, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;");
    jobject locMgr = NULL;
    if (getServiceMid) {
        jstring svc = (*env)->NewStringUTF(env, "location");
        if (svc) locMgr = (*env)->CallObjectMethod(env, app, getServiceMid, svc);
        if ((*env)->ExceptionCheck(env)) { clearJniException(env, "Context.getSystemService(location)"); locMgr = NULL; }
        if (svc) (*env)->DeleteLocalRef(env, svc);
    }
    if (locMgr) {
        jclass lmCls = (*env)->GetObjectClass(env, locMgr);
        jmethodID getProvidersMid = lmCls ? (*env)->GetMethodID(env, lmCls, "getProviders", "(Z)Ljava/util/List;") : NULL;
        if (getProvidersMid) {
            jobject providersAll = (*env)->CallObjectMethod(env, locMgr, getProvidersMid, JNI_FALSE);
            if ((*env)->ExceptionCheck(env)) clearJniException(env, "LocationManager.getProviders(false)");
            else if (providersAll) {
                char providers[1024];
                if (objectToString(env, providersAll, providers, sizeof(providers))) {
                    VLOGI("Location providers all=%s", providers);
                    if (contains_nocase(providers, "mock")) {
                        LOGI("Mock-like location provider listed: %s", providers);
                        hit = 1;
                    }
                }
                (*env)->DeleteLocalRef(env, providersAll);
            }
        } else clearJniException(env, "LocationManager.getProviders mid");

        // Best-effort last-known-location probe. On apps without location permission this should throw and be skipped.
        jmethodID getLastMid = lmCls ? (*env)->GetMethodID(env, lmCls, "getLastKnownLocation", "(Ljava/lang/String;)Landroid/location/Location;") : NULL;
        if (getLastMid) {
            const char *providers[] = {"gps", "network", "fused", NULL};
            for (int i = 0; providers[i]; i++) {
                jstring jp = (*env)->NewStringUTF(env, providers[i]);
                jobject loc = jp ? (*env)->CallObjectMethod(env, locMgr, getLastMid, jp) : NULL;
                if ((*env)->ExceptionCheck(env)) {
                    clearJniException(env, "LocationManager.getLastKnownLocation");
                } else if (loc) {
                    char locDesc[1024];
                    objectToString(env, loc, locDesc, sizeof(locDesc));
                    VLOGI("Last known location probe: provider=%s loc=%s", providers[i], safe_str(locDesc));
                    jclass locCls = (*env)->GetObjectClass(env, loc);
                    jmethodID isMockMid = locCls ? (*env)->GetMethodID(env, locCls, "isFromMockProvider", "()Z") : NULL;
                    if (isMockMid) {
                        jboolean mock = (*env)->CallBooleanMethod(env, loc, isMockMid);
                        if ((*env)->ExceptionCheck(env)) clearJniException(env, "Location.isFromMockProvider");
                        else if (mock) {
                            LOGI("Mock location object signal: provider=%s loc=%s", providers[i], safe_str(locDesc));
                            hit = 1;
                        }
                    } else clearJniException(env, "Location.isFromMockProvider mid");
                    if (locCls) (*env)->DeleteLocalRef(env, locCls);
                    (*env)->DeleteLocalRef(env, loc);
                }
                if (jp) (*env)->DeleteLocalRef(env, jp);
            }
        } else clearJniException(env, "LocationManager.getLastKnownLocation mid");

        if (lmCls) (*env)->DeleteLocalRef(env, lmCls);
        (*env)->DeleteLocalRef(env, locMgr);
    }

    (*env)->DeleteLocalRef(env, ctxCls);
    (*env)->DeleteLocalRef(env, app);
    VLOGI("Location environment scan complete: suspicious=%d", hit);
    return hit ? JNI_TRUE : JNI_FALSE;
}


// ─── Framework runtime / system framework side-effect checks ────────────────
static int isSuspiciousFrameworkMappingLine(const char *line) {
    if (!line || !*line) return 0;
    if (!(contains_nocase(line, ".jar") || contains_nocase(line, ".apk") ||
          contains_nocase(line, ".vdex") || contains_nocase(line, ".oat") ||
          contains_nocase(line, ".art"))) return 0;

    int framework_related =
        contains_nocase(line, "/system/framework/") ||
        contains_nocase(line, "/apex/com.android.") ||
        contains_nocase(line, "/data/misc/apexdata/com.android.art/") ||
        contains_nocase(line, "framework.jar") ||
        contains_nocase(line, "framework-res.apk") ||
        contains_nocase(line, "core-oj.jar") ||
        contains_nocase(line, "core-libart.jar") ||
        contains_nocase(line, "boot-framework") ||
        contains_nocase(line, "boot.vdex");

    if (!framework_related) return 0;

    if (contains_nocase(line, "/data/adb/") ||
        contains_nocase(line, "/data/local/tmp/") ||
        contains_nocase(line, "/sdcard/") ||
        contains_nocase(line, "/storage/emulated/")) {
        return 1;
    }

    if (contains_nocase(line, "/data/app/") && !contains_nocase(line, APP_PACKAGE_NAME)) {
        return 1;
    }

    // framework.jar and framework-res.apk should come from the system image in
    // normal app processes. APEX jars are allowed separately above.
    if ((contains_nocase(line, "framework.jar") || contains_nocase(line, "framework-res.apk")) &&
        !(contains_nocase(line, "/system/framework/") ||
          contains_nocase(line, "/apex/") ||
          contains_nocase(line, "/data/resource-cache/") ||
          contains_nocase(line, "/product/overlay/") ||
          contains_nocase(line, "/vendor/overlay/"))) {
        return 1;
    }

    return 0;
}

static int checkFrameworkMappingsOrigin(void) {
    size_t len = 0;
    char *maps = read_file_raw_dynamic("/proc/self/maps", &len);
    if (!maps) return 0;

    int framework_lines = 0;
    int suspicious = 0;
    char *saveptr = NULL;
    for (char *line = strtok_r(maps, "\n", &saveptr); line; line = strtok_r(NULL, "\n", &saveptr)) {
        int framework_related =
            contains_nocase(line, "/system/framework/") ||
            contains_nocase(line, "/apex/com.android.") ||
            contains_nocase(line, "/data/misc/apexdata/com.android.art/") ||
            contains_nocase(line, "framework.jar") ||
            contains_nocase(line, "framework-res.apk") ||
            contains_nocase(line, "core-oj.jar") ||
            contains_nocase(line, "core-libart.jar") ||
            contains_nocase(line, "boot-framework") ||
            contains_nocase(line, "boot.vdex");
        if (!framework_related) continue;
        framework_lines++;
        if (isSuspiciousFrameworkMappingLine(line) || artSuspiciousText(line)) {
            LOGI("Suspicious framework/runtime mapping: %s", line);
            suspicious = 1;
        } else if (framework_lines <= 8) {
            VLOGI("Framework/runtime mapping sample: %s", line);
        }
    }

    free(maps);
    VLOGI("Framework mapping origin scan complete: framework_lines=%d suspicious=%d", framework_lines, suspicious);
    return suspicious;
}

static int checkSingleFrameworkClassLoader(JNIEnv *env, const char *slash_name, const char *label) {
    if (!env || !slash_name) return 0;
    int suspicious = 0;

    jclass targetCls = (*env)->FindClass(env, slash_name);
    if ((*env)->ExceptionCheck(env) || !targetCls) {
        clearJniException(env, "framework class FindClass");
        return 0;
    }

    jclass classCls = (*env)->FindClass(env, "java/lang/Class");
    jmethodID getClMid = classCls ? (*env)->GetMethodID(env, classCls, "getClassLoader", "()Ljava/lang/ClassLoader;") : NULL;
    if (!classCls || !getClMid) {
        clearJniException(env, "Class.getClassLoader setup");
        if (classCls) (*env)->DeleteLocalRef(env, classCls);
        (*env)->DeleteLocalRef(env, targetCls);
        return 0;
    }

    jobject loader = (*env)->CallObjectMethod(env, targetCls, getClMid);
    if ((*env)->ExceptionCheck(env)) {
        clearJniException(env, "Class.getClassLoader call");
    } else if (!loader) {
        VLOGI("Framework class loader OK: class=%s loader=<bootstrap/null>", safe_str(label));
    } else {
        char loader_class[256];
        char loader_desc[1024];
        objectClassName(env, loader, loader_class, sizeof(loader_class));
        objectToString(env, loader, loader_desc, sizeof(loader_desc));
        VLOGI("Framework class loader: class=%s loader_class=%s desc=%s", safe_str(label), loader_class, loader_desc);

        if (artSuspiciousText(loader_class) || artSuspiciousText(loader_desc) ||
            contains_nocase(loader_class, "InMemoryDexClassLoader") ||
            contains_nocase(loader_class, "DelegateLastClassLoader") ||
            contains_nocase(loader_desc, "/data/adb/") ||
            contains_nocase(loader_desc, "/data/local/tmp/") ||
            isForeignDataAppPath(loader_desc)) {
            LOGI("Suspicious framework class loader: class=%s loader_class=%s desc=%s", safe_str(label), loader_class, loader_desc);
            suspicious = 1;
        }
        (*env)->DeleteLocalRef(env, loader);
    }

    (*env)->DeleteLocalRef(env, classCls);
    (*env)->DeleteLocalRef(env, targetCls);
    return suspicious;
}

static int isJavaProxyClass(JNIEnv *env, jobject obj) {
    if (!env || !obj) return 0;
    int is_proxy = 0;
    jclass objCls = (*env)->GetObjectClass(env, obj);
    jclass proxyCls = (*env)->FindClass(env, "java/lang/reflect/Proxy");
    jmethodID isProxyMid = proxyCls ? (*env)->GetStaticMethodID(env, proxyCls, "isProxyClass", "(Ljava/lang/Class;)Z") : NULL;
    if (objCls && proxyCls && isProxyMid) {
        is_proxy = (*env)->CallStaticBooleanMethod(env, proxyCls, isProxyMid, objCls) ? 1 : 0;
        if ((*env)->ExceptionCheck(env)) {
            clearJniException(env, "Proxy.isProxyClass");
            is_proxy = 0;
        }
    } else {
        clearJniException(env, "Proxy.isProxyClass setup");
    }
    if (proxyCls) (*env)->DeleteLocalRef(env, proxyCls);
    if (objCls) (*env)->DeleteLocalRef(env, objCls);
    return is_proxy;
}

static int inspectFrameworkServiceObject(JNIEnv *env, jobject obj, const char *label, const char *expected_hint) {
    if (!env || !obj) return 0;
    char cls_name[256];
    char desc[1024];
    objectClassName(env, obj, cls_name, sizeof(cls_name));
    objectToString(env, obj, desc, sizeof(desc));
    int proxy = isJavaProxyClass(env, obj);

    VLOGI("Framework service object: label=%s class=%s proxy=%d desc=%s",
          safe_str(label), cls_name, proxy, desc);

    int suspicious = 0;
    if (proxy || artSuspiciousText(cls_name) || artSuspiciousText(desc) ||
        contains_nocase(cls_name, "InMemory") ||
        contains_nocase(desc, "/data/adb/") ||
        contains_nocase(desc, "/data/local/tmp/") ||
        isForeignDataAppPath(desc)) {
        suspicious = 1;
    }

    // Treat unexpected service implementation class as weak suspicious signal.
    // This is intentionally conservative: OEM framework wrappers are possible.
    if (expected_hint && *expected_hint && !contains_nocase(cls_name, expected_hint)) {
        LOGI("Framework service implementation differs from expected hint: label=%s class=%s expected_hint=%s",
             safe_str(label), cls_name, expected_hint);
        // Do not mark suspicious by itself; log only to avoid OEM false positives.
    }

    if (suspicious) {
        LOGI("Suspicious framework service object: label=%s class=%s proxy=%d desc=%s",
             safe_str(label), cls_name, proxy, desc);
    }
    return suspicious;
}

static int checkFrameworkServiceObjects(JNIEnv *env) {
    if (!env) return 0;
    jobject app = getCurrentApplication(env);
    if (!app) return 0;

    int suspicious = 0;
    jclass ctxCls = (*env)->FindClass(env, "android/content/Context");
    if (!ctxCls) {
        clearJniException(env, "Context class framework service");
        (*env)->DeleteLocalRef(env, app);
        return 0;
    }

    jmethodID getPmMid = (*env)->GetMethodID(env, ctxCls, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    if (getPmMid) {
        jobject pm = (*env)->CallObjectMethod(env, app, getPmMid);
        if ((*env)->ExceptionCheck(env)) clearJniException(env, "Context.getPackageManager framework service");
        else if (pm) {
            suspicious |= inspectFrameworkServiceObject(env, pm, "PackageManager", "ApplicationPackageManager");
            (*env)->DeleteLocalRef(env, pm);
        }
    } else clearJniException(env, "Context.getPackageManager mid framework service");

    jmethodID getSystemServiceMid = (*env)->GetMethodID(env, ctxCls, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;");
    if (getSystemServiceMid) {
        const char *services[][3] = {
            {"location", "LocationManager", "LocationManager"},
            {"appops", "AppOpsManager", "AppOpsManager"},
            {"activity", "ActivityManager", "ActivityManager"},
            {NULL, NULL, NULL}
        };
        for (int i = 0; services[i][0]; i++) {
            jstring name = (*env)->NewStringUTF(env, services[i][0]);
            jobject svc = name ? (*env)->CallObjectMethod(env, app, getSystemServiceMid, name) : NULL;
            if ((*env)->ExceptionCheck(env)) clearJniException(env, "Context.getSystemService framework service");
            else if (svc) {
                suspicious |= inspectFrameworkServiceObject(env, svc, services[i][1], services[i][2]);
                (*env)->DeleteLocalRef(env, svc);
            }
            if (name) (*env)->DeleteLocalRef(env, name);
        }
    } else clearJniException(env, "Context.getSystemService mid framework service");

    (*env)->DeleteLocalRef(env, ctxCls);
    (*env)->DeleteLocalRef(env, app);
    return suspicious;
}

static jboolean checkFrameworkRuntime(JNIEnv *env) {
    int suspicious = 0;

    suspicious |= checkFrameworkMappingsOrigin();

    if (env) {
        const char *classes[][2] = {
            {"android/app/ActivityThread", "android.app.ActivityThread"},
            {"android/content/pm/PackageManager", "android.content.pm.PackageManager"},
            {"android/content/pm/ApplicationInfo", "android.content.pm.ApplicationInfo"},
            {"android/location/LocationManager", "android.location.LocationManager"},
            {"android/location/Location", "android.location.Location"},
            {"android/os/Binder", "android.os.Binder"},
            {"android/os/Build", "android.os.Build"},
            {"android/provider/Settings$Secure", "android.provider.Settings$Secure"},
            {NULL, NULL}
        };
        int checked = 0;
        for (int i = 0; classes[i][0]; i++) {
            checked++;
            suspicious |= checkSingleFrameworkClassLoader(env, classes[i][0], classes[i][1]);
        }
        suspicious |= checkFrameworkServiceObjects(env);
        VLOGI("Framework runtime class/service scan complete: classes_checked=%d suspicious=%d", checked, suspicious);
    }

    VLOGI("Framework runtime scan complete: suspicious=%d", suspicious);
    return suspicious ? JNI_TRUE : JNI_FALSE;
}

// ─── Disk artifact checks ───────────────────────────────────────────────────
typedef struct DiskArtifactReport {
    int public_artifacts;
    int root_artifacts;
    int zip_modules;
    int apk_risk;
    int files_seen;
    int dirs_seen;
    int zip_seen;
    int apk_seen;
} DiskArtifactReport;

#define DISK_SCAN_MAX_DEPTH 2
#define DISK_SCAN_MAX_ENTRIES_PER_DIR 128
#define DISK_SCAN_MAX_TOTAL_FILES 600
#define DISK_SCAN_MAX_FILE_BYTES (8 * 1024 * 1024)

static void lowercase_copy_limited(const char *src, char *dst, size_t cap) {
    if (!dst || cap == 0) return;
    dst[0] = '\0';
    if (!src) return;
    size_t i = 0;
    for (; src[i] && i + 1 < cap; i++) dst[i] = (char)tolower((unsigned char)src[i]);
    dst[i] = '\0';
}

static int ends_with_nocase(const char *s, const char *suffix) {
    if (!s || !suffix) return 0;
    size_t sl = strlen(s), fl = strlen(suffix);
    if (fl > sl) return 0;
    const char *tail = s + sl - fl;
    for (size_t i = 0; i < fl; i++) {
        if (tolower((unsigned char)tail[i]) != tolower((unsigned char)suffix[i])) return 0;
    }
    return 1;
}

static int disk_name_has_safe_token(const char *name, const char *token) {
    if (!name || !token || !*token) return 0;
    char lower[PATH_MAX];
    lowercase_copy_limited(name, lower, sizeof(lower));
    size_t tl = strlen(token);
    for (const char *p = lower; (p = strstr(p, token)) != NULL; p++) {
        char before = (p == lower) ? '\0' : p[-1];
        char after = p[tl];
        int left_ok = (p == lower) || before == '-' || before == '_' || before == '.' || before == ' ' || before == '/' || before == '(' || before == '[';
        int right_ok = after == '\0' || after == '-' || after == '_' || after == '.' || after == ' ' || after == ')' || after == ']' || after == '/';
        if (left_ok && right_ok) return 1;
    }
    return 0;
}

static int disk_filename_risky(const char *path, const char **matched) {
    const char *base = basename_safe(path);
    const char *tokens[] = {
        "magisk", "kitsune", "magiskdelta", "zygisk", "lsposed", "lspd", "riru",
        "shamiko", "kernelsu", "ksud", "apatch", "superuser", "supersu",
        "hide-my-applist", "hidemyapplist", "hma", "hmaoss",
        "fakegps", "fake-gps", "mocklocation", "mock-location", "gpsjoystick",
        "locationfaker", "lucky-patcher", "luckypatcher", "frida", "objection",
        NULL
    };
    for (int i = 0; tokens[i]; i++) {
        if (disk_name_has_safe_token(base, tokens[i]) || contains_nocase(base, tokens[i])) {
            if (matched) *matched = tokens[i];
            return 1;
        }
    }
    // Avoid generic "ksu" substring. Only flag basename-style KSU names.
    if (basename_equals_nocase(base, "ksu.apk") || basename_equals_nocase(base, "ksu.zip") ||
        basename_equals_nocase(base, "ksu") || disk_name_has_safe_token(base, "ksu")) {
        if (matched) *matched = "ksu-token";
        return 1;
    }
    return 0;
}

static int buffer_contains_nocase(const unsigned char *buf, size_t len, const char *needle) {
    if (!buf || !needle || !*needle) return 0;
    size_t nl = strlen(needle);
    if (nl == 0 || nl > len) return 0;
    for (size_t i = 0; i + nl <= len; i++) {
        size_t j = 0;
        while (j < nl && tolower((unsigned char)buf[i + j]) == tolower((unsigned char)needle[j])) j++;
        if (j == nl) return 1;
    }
    return 0;
}

static int scan_zip_for_module_markers(const char *path, const char **matched) {
    struct stat st;
    if (!path || lstat(path, &st) != 0 || !S_ISREG(st.st_mode)) return 0;
    if (st.st_size <= 0 || st.st_size > DISK_SCAN_MAX_FILE_BYTES) {
        VLOGI("Disk ZIP scan skipped: path=%s size=%lld", safe_str(path), (long long)st.st_size);
        return 0;
    }

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    size_t len = (size_t)st.st_size;
    unsigned char *buf = (unsigned char *)malloc(len);
    if (!buf) {
        close(fd);
        return 0;
    }
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n <= 0) break;
        off += (size_t)n;
    }
    close(fd);
    if (off < len) {
        free(buf);
        return 0;
    }

    const char *module_markers[] = {
        "module.prop", "customize.sh", "post-fs-data.sh", "service.sh",
        "system.prop", "sepolicy.rule", "zygisk/", "riru/",
        "META-INF/com/google/android/update-binary", NULL
    };
    int marker_count = 0;
    const char *first_marker = NULL;
    for (int i = 0; module_markers[i]; i++) {
        if (buffer_contains_nocase(buf, len, module_markers[i])) {
            marker_count++;
            if (!first_marker) first_marker = module_markers[i];
        }
    }

    const char *strong_terms[] = {
        "id=shamiko", "name=shamiko", "zygisk_lsposed", "lsposed", "riru",
        "kernelsu", "magisk", "zygisk", "apatch", "hide my applist", "hidemyapplist",
        "fake gps", "mock location", NULL
    };
    for (int i = 0; strong_terms[i]; i++) {
        if (buffer_contains_nocase(buf, len, strong_terms[i])) {
            if (matched) *matched = strong_terms[i];
            free(buf);
            return 1;
        }
    }

    free(buf);
    if (marker_count >= 2 || (marker_count >= 1 && disk_filename_risky(path, NULL))) {
        if (matched) *matched = first_marker ? first_marker : "zip-module-structure";
        return 1;
    }
    if (basename_equals_nocase(path, "module.zip") && marker_count >= 1) {
        if (matched) *matched = "module.zip+module-marker";
        return 1;
    }
    return 0;
}

static int scan_root_artifact_paths(DiskArtifactReport *out) {
    int hit = 0;
    const char *paths[] = {
        "/data/adb",
        "/data/adb/magisk",
        "/data/adb/magisk.db",
        "/data/adb/modules",
        "/data/adb/modules/shamiko",
        "/data/adb/modules/zygisk_lsposed",
        "/data/adb/modules/riru_lsposed",
        "/data/adb/modules/riru",
        "/data/adb/ksu",
        "/data/adb/ksud",
        "/data/adb/ap",
        "/data/adb/service.d",
        "/data/adb/post-fs-data.d",
        "/data/local/tmp/frida-server",
        "/data/local/tmp/re.frida.server",
        NULL
    };
    for (int i = 0; paths[i]; i++) {
        struct stat st;
        if (lstat(paths[i], &st) == 0) {
            LOGI("Root-only disk artifact visible: path=%s mode=0%o", paths[i], (unsigned)(st.st_mode & 07777));
            hit = 1;
        } else if (errno == EACCES || errno == EPERM) {
            VLOGI("Root-only disk path unreadable: path=%s errno=%d", paths[i], errno);
        }
    }

    const char *module_dirs[] = { "/data/adb/modules", "/data/adb/ksu/modules", "/data/adb/ap/modules", NULL };
    for (int i = 0; module_dirs[i]; i++) {
        DIR *d = opendir(module_dirs[i]);
        if (!d) {
            if (errno == EACCES || errno == EPERM) VLOGI("Root module dir unreadable: path=%s errno=%d", module_dirs[i], errno);
            continue;
        }
        struct dirent *de;
        int count = 0;
        while ((de = readdir(d)) != NULL && count++ < DISK_SCAN_MAX_ENTRIES_PER_DIR) {
            if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
            char child[PATH_MAX];
            snprintf(child, sizeof(child), "%s/%s", module_dirs[i], de->d_name);
            const char *matched = NULL;
            if (disk_filename_risky(child, &matched)) {
                LOGI("Risky root module directory name visible: path=%s term=%s", child, safe_str(matched));
                hit = 1;
            }
            char prop[PATH_MAX];
            snprintf(prop, sizeof(prop), "%s/module.prop", child);
            size_t len = 0;
            char *txt = read_file_raw_dynamic(prop, &len);
            if (txt) {
                const char *terms[] = { "shamiko", "lsposed", "zygisk", "riru", "magisk", "kernelsu", "apatch", "hide my applist", NULL };
                for (int t = 0; terms[t]; t++) {
                    if (contains_nocase(txt, terms[t])) {
                        LOGI("Risky root module.prop visible: path=%s term=%s", prop, terms[t]);
                        hit = 1;
                        if (out) out->zip_modules = 1;
                        break;
                    }
                }
                free(txt);
            }
        }
        closedir(d);
    }
    return hit;
}

static void scan_public_dir_recursive(const char *dir, int depth, DiskArtifactReport *out) {
    if (!dir || !out || depth > DISK_SCAN_MAX_DEPTH || out->files_seen > DISK_SCAN_MAX_TOTAL_FILES) return;
    DIR *d = opendir(dir);
    if (!d) {
        if (errno == EACCES || errno == EPERM) VLOGI("Public disk dir unreadable: path=%s errno=%d", safe_str(dir), errno);
        return;
    }
    out->dirs_seen++;
    struct dirent *de;
    int entries = 0;
    while ((de = readdir(d)) != NULL && entries++ < DISK_SCAN_MAX_ENTRIES_PER_DIR && out->files_seen <= DISK_SCAN_MAX_TOTAL_FILES) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        struct stat st;
        if (lstat(path, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            const char *matched = NULL;
            if (disk_filename_risky(path, &matched)) {
                LOGI("Suspicious public directory name: path=%s term=%s", path, safe_str(matched));
                out->public_artifacts = 1;
            }
            scan_public_dir_recursive(path, depth + 1, out);
            continue;
        }
        if (!S_ISREG(st.st_mode)) continue;
        out->files_seen++;
        const char *matched = NULL;
        if (disk_filename_risky(path, &matched)) {
            LOGI("Suspicious public file name: path=%s term=%s", path, safe_str(matched));
            out->public_artifacts = 1;
            if (ends_with_nocase(path, ".apk")) out->apk_risk = 1;
            if (ends_with_nocase(path, ".zip")) out->zip_modules = 1;
        }
        if (ends_with_nocase(path, ".apk")) {
            out->apk_seen++;
            if (disk_filename_risky(path, &matched)) {
                LOGI("Suspicious APK artifact: path=%s term=%s", path, safe_str(matched));
                out->apk_risk = 1;
            }
        } else if (ends_with_nocase(path, ".zip")) {
            out->zip_seen++;
            if (scan_zip_for_module_markers(path, &matched)) {
                LOGI("Suspicious ZIP/Magisk-module artifact: path=%s marker=%s", path, safe_str(matched));
                out->zip_modules = 1;
                out->public_artifacts = 1;
            }
        }
    }
    closedir(d);
}

static DiskArtifactReport checkDiskArtifacts(void) {
    long long t0 = wall_time_ms();
    DiskArtifactReport out;
    memset(&out, 0, sizeof(out));

    out.root_artifacts = scan_root_artifact_paths(&out);

    const char *public_dirs[] = {
        "/sdcard/Download",
        "/storage/emulated/0/Download",
        "/sdcard/Documents",
        "/storage/emulated/0/Documents",
        "/sdcard/Android/media",
        "/storage/emulated/0/Android/media",
        NULL
    };
    for (int i = 0; public_dirs[i]; i++) scan_public_dir_recursive(public_dirs[i], 0, &out);

    VLOGI("Disk artifact scan complete: elapsed_ms=%lld dirs=%d files=%d zip_seen=%d apk_seen=%d public=%d root=%d zip_modules=%d apk_risk=%d",
          wall_time_ms() - t0, out.dirs_seen, out.files_seen, out.zip_seen, out.apk_seen,
          out.public_artifacts, out.root_artifacts, out.zip_modules, out.apk_risk);
    return out;
}


// ─── Suspicious process scan ────────────────────────────────────────────────
typedef struct ProcessScanReport {
    int hit;
    int score;
    int strong;
    int medium;
    int weak;
    int scanned;
    int readable;
} ProcessScanReport;

#define PROCESS_SCAN_MAX_PIDS 512
#define PROCESS_TEXT_MAX 4096

static int is_decimal_pid_name(const char *s) {
    if (!s || !*s) return 0;
    for (const char *p = s; *p; p++) {
        if (!isdigit((unsigned char)*p)) return 0;
    }
    return 1;
}

static void read_proc_text_field(char *dst, size_t cap, const char *path, int nul_to_space) {
    if (!dst || cap == 0 || !path) return;
    size_t len = 0;
    char *buf = read_file_raw_dynamic(path, &len);
    if (!buf) return;
    size_t used = strlen(dst);
    if (used + 2 < cap) {
        dst[used++] = ' ';
        dst[used] = '\0';
    }
    size_t remaining = (used < cap) ? cap - used - 1 : 0;
    size_t n = len < remaining ? len : remaining;
    for (size_t i = 0; i < n; i++) {
        char c = buf[i];
        if (nul_to_space && c == '\0') c = ' ';
        if (c == '\n' || c == '\r' || c == '\t') c = ' ';
        dst[used + i] = c;
    }
    dst[used + n] = '\0';
    free(buf);
}

static void read_proc_link_field(char *dst, size_t cap, const char *path) {
    if (!dst || cap == 0 || !path) return;
    char linkbuf[PATH_MAX];
    ssize_t n = readlink(path, linkbuf, sizeof(linkbuf) - 1);
    if (n <= 0) return;
    linkbuf[n] = '\0';
    appendf(dst, cap, " %s", linkbuf);
}

static int process_text_has_any(const char *text, const char *const *terms, const char **matched) {
    if (matched) *matched = NULL;
    if (!text || !terms) return 0;
    for (int i = 0; terms[i]; i++) {
        if (contains_nocase(text, terms[i])) {
            if (matched) *matched = terms[i];
            return 1;
        }
    }
    return 0;
}

static ProcessScanReport checkSuspiciousProcesses(void) {
    long long t0 = wall_time_ms();
    ProcessScanReport out;
    memset(&out, 0, sizeof(out));

    static const char *const strong_terms[] = {
        "frida-server", "frida", "gum-js-loop", "gdbserver", "lldb-server",
        "objection", "re.frida.server", "/data/local/tmp/frida",
        "magiskd", "/data/adb/magisk", "ksud", "/data/adb/ksu",
        "apd", "/data/adb/ap", "zygisk", "riru", "lspd", "lsposed", "xposed",
        NULL
    };
    static const char *const medium_terms[] = {
        "sshd", "dropbear", "telnetd", "socat", "netcat", "nc -l",
        "termux-chroot", "proot", "tsu",
        "/data/data/com.termux/files/usr/bin/sshd",
        "/data/data/com.termux/files/usr/bin/dropbear",
        NULL
    };
    static const char *const weak_terms[] = {
        "com.termux", "/data/data/com.termux", "termux", "bash", "zsh", "python", "node",
        NULL
    };

    DIR *proc = opendir("/proc");
    if (!proc) {
        VLOGI("Suspicious process scan skipped: cannot open /proc errno=%d", errno);
        return out;
    }

    struct dirent *de;
    while ((de = readdir(proc)) != NULL && out.scanned < PROCESS_SCAN_MAX_PIDS) {
        if (!is_decimal_pid_name(de->d_name)) continue;
        out.scanned++;

        char base[64];
        snprintf(base, sizeof(base), "/proc/%s", de->d_name);

        char text[PROCESS_TEXT_MAX];
        text[0] = '\0';
        char path[PATH_MAX];

        snprintf(path, sizeof(path), "%s/comm", base);
        read_proc_text_field(text, sizeof(text), path, 0);
        snprintf(path, sizeof(path), "%s/cmdline", base);
        read_proc_text_field(text, sizeof(text), path, 1);
        snprintf(path, sizeof(path), "%s/status", base);
        read_proc_text_field(text, sizeof(text), path, 0);
        snprintf(path, sizeof(path), "%s/exe", base);
        read_proc_link_field(text, sizeof(text), path);
        snprintf(path, sizeof(path), "%s/cwd", base);
        read_proc_link_field(text, sizeof(text), path);

        if (!text[0]) continue;
        out.readable++;

        const char *matched = NULL;
        if (process_text_has_any(text, strong_terms, &matched)) {
            LOGI("Strong suspicious process signal: pid=%s term=%s text=%.512s", de->d_name, safe_str(matched), text);
            out.hit = 1;
            out.strong++;
            if (out.score < 6) out.score = 6;
            continue;
        }
        if (process_text_has_any(text, medium_terms, &matched)) {
            LOGI("Medium suspicious process signal: pid=%s term=%s text=%.512s", de->d_name, safe_str(matched), text);
            out.hit = 1;
            out.medium++;
            if (out.score < 3) out.score = 3;
            continue;
        }
        if (process_text_has_any(text, weak_terms, &matched)) {
            VLOGI("Weak process risk signal: pid=%s term=%s text=%.384s", de->d_name, safe_str(matched), text);
            out.hit = 1;
            out.weak++;
            if (out.score < 1) out.score = 1;
        }
    }

    closedir(proc);
    VLOGI("Suspicious process scan complete: elapsed_ms=%lld scanned=%d readable=%d strong=%d medium=%d weak=%d score=%d hit=%d",
          wall_time_ms() - t0, out.scanned, out.readable, out.strong, out.medium, out.weak, out.score, out.hit);
    return out;
}


// ─── Suspicious listening port scan ─────────────────────────────────────────
typedef struct PortScanReport {
    int hit;
    int score;
    int strong;
    int medium;
    int weak;
    int entries;
    int listening;
    int unix_hits;
} PortScanReport;

#define PORT_SCAN_MAX_LINES 2048

static const char *port_risk_label(int port, int *score_out) {
    if (score_out) *score_out = 0;
    switch (port) {
        case 27042: // Frida default
        case 27043: // Frida default
        case 5555:  // ADB-over-TCP is high-risk on a phone
            if (score_out) *score_out = 5;
            return "strong";
        case 22:    // SSH
        case 2222:  // common alternate SSH
        case 8022:  // common Termux SSH
        case 2022:  // common alternate dropbear/ssh
            if (score_out) *score_out = 3;
            return "medium";
        default:
            return NULL;
    }
}

static int parse_proc_net_tcp_line(const char *line, int *port_out, char *state_out, size_t state_cap) {
    if (!line || !port_out || !state_out || state_cap == 0) return 0;
    unsigned int sl = 0;
    char local[160] = {0};
    char remote[160] = {0};
    char st[16] = {0};
    if (sscanf(line, " %u: %159s %159s %15s", &sl, local, remote, st) < 4) return 0;
    char *colon = strrchr(local, ':');
    if (!colon || !colon[1]) return 0;
    unsigned int port = 0;
    if (sscanf(colon + 1, "%x", &port) != 1) return 0;
    *port_out = (int)port;
    snprintf(state_out, state_cap, "%s", st);
    return 1;
}

static void scan_proc_net_tcp_file(const char *path, PortScanReport *out) {
    if (!path || !out) return;
    FILE *fp = fopen(path, "re");
    if (!fp) {
        VLOGI("Suspicious port scan skipped file=%s errno=%d", path, errno);
        return;
    }

    char line[768];
    int line_no = 0;
    while (fgets(line, sizeof(line), fp) && line_no < PORT_SCAN_MAX_LINES) {
        line_no++;
        if (line_no == 1 && strstr(line, "local_address")) continue;
        out->entries++;

        int port = 0;
        char state[16] = {0};
        if (!parse_proc_net_tcp_line(line, &port, state, sizeof(state))) continue;
        if (strcmp(state, "0A") != 0) continue; // TCP_LISTEN
        out->listening++;

        int score = 0;
        const char *risk = port_risk_label(port, &score);
        if (!risk) continue;

        out->hit = 1;
        if (score > out->score) out->score = score;
        if (score >= 5) out->strong++;
        else if (score >= 3) out->medium++;
        else out->weak++;

        LOGI("Suspicious listening port signal: file=%s port=%d risk=%s state=%s line=%.384s",
             path, port, risk, state, line);
    }
    fclose(fp);
}

static void scan_proc_net_unix_sockets(PortScanReport *out) {
    if (!out) return;
    FILE *fp = fopen("/proc/net/unix", "re");
    if (!fp) {
        VLOGI("Suspicious unix socket scan skipped errno=%d", errno);
        return;
    }

    static const char *const strong_socket_terms[] = {
        "frida", "gum-js-loop", "objection", "lspd", "lsposed", "xposed",
        "magisk", "zygisk", "riru", "ksud", "apd", NULL
    };

    char line[768];
    int line_no = 0;
    while (fgets(line, sizeof(line), fp) && line_no < PORT_SCAN_MAX_LINES) {
        line_no++;
        if (line_no == 1 && strstr(line, "Num")) continue;
        const char *matched = NULL;
        if (process_text_has_any(line, strong_socket_terms, &matched)) {
            LOGI("Suspicious unix socket signal: term=%s line=%.384s", safe_str(matched), line);
            out->hit = 1;
            out->unix_hits++;
            out->strong++;
            if (out->score < 5) out->score = 5;
        }
    }
    fclose(fp);
}

static PortScanReport checkSuspiciousPorts(void) {
    long long t0 = wall_time_ms();
    PortScanReport out;
    memset(&out, 0, sizeof(out));

    scan_proc_net_tcp_file("/proc/net/tcp", &out);
    scan_proc_net_tcp_file("/proc/net/tcp6", &out);
    scan_proc_net_unix_sockets(&out);

    VLOGI("Suspicious port scan complete: elapsed_ms=%lld entries=%d listening=%d strong=%d medium=%d weak=%d unix_hits=%d score=%d hit=%d",
          wall_time_ms() - t0, out.entries, out.listening, out.strong, out.medium, out.weak,
          out.unix_hits, out.score, out.hit);
    return out;
}



// ─── Root-assisted async diagnostic scan ───────────────────────────────────
// Lab/diagnostic mode: request/use su from the async worker to compare the
// normal app-process view against a root helper view. This is intentionally
// separate from normal app-view checks.
typedef struct RootAssistReport {
    int status;
    int granted;
    int root_view;
    int modules;
    int process;
    int ports;
    int timeout;
    int output_bytes;
    int exit_code;
    int score;
} RootAssistReport;

enum {
    ROOT_ASSIST_NOT_RUN = 0,
    ROOT_ASSIST_GRANTED = 1,
    ROOT_ASSIST_DENIED = 2,
    ROOT_ASSIST_TIMEOUT = 3,
    ROOT_ASSIST_UNAVAILABLE = 4,
    ROOT_ASSIST_ERROR = 5
};

#define ROOT_ASSIST_TIMEOUT_MS 8000
#define ROOT_ASSIST_OUTPUT_MAX (96 * 1024)

static const char *rootAssistStatusText(int status) {
    switch (status) {
        case ROOT_ASSIST_GRANTED: return "GRANTED";
        case ROOT_ASSIST_DENIED: return "DENIED";
        case ROOT_ASSIST_TIMEOUT: return "TIMEOUT";
        case ROOT_ASSIST_UNAVAILABLE: return "UNAVAILABLE";
        case ROOT_ASSIST_ERROR: return "ERROR";
        case ROOT_ASSIST_NOT_RUN:
        default: return "NOT_RUN";
    }
}

static int run_su_command_timeout(const char *cmd, char *out, size_t out_cap, int timeout_ms, int *exit_code, int *timed_out) {
    if (out && out_cap) out[0] = '\0';
    if (exit_code) *exit_code = -1;
    if (timed_out) *timed_out = 0;
    if (!cmd || !out || out_cap < 2) return 0;

    int pipefd[2];
    if (pipe(pipefd) != 0) return 0;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return 0;
    }

    if (pid == 0) {
        setpgid(0, 0);
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execlp("su", "su", "-c", cmd, (char *)NULL);
        execl("/system/bin/su", "su", "-c", cmd, (char *)NULL);
        execl("/system/xbin/su", "su", "-c", cmd, (char *)NULL);
        _exit(127);
    }

    close(pipefd[1]);
    int flags = fcntl(pipefd[0], F_GETFL, 0);
    if (flags >= 0) fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    size_t used = 0;
    int status = 0;
    int child_done = 0;
    long long start = wall_time_ms();

    while (1) {
        char buf[1024];
        ssize_t n = read(pipefd[0], buf, sizeof(buf));
        if (n > 0) {
            size_t copy = (size_t)n;
            if (used + copy >= out_cap) copy = out_cap - used - 1;
            if (copy > 0) {
                memcpy(out + used, buf, copy);
                used += copy;
                out[used] = '\0';
            }
        }

        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) {
            child_done = 1;
            // Drain remaining buffered output once more.
            while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
                size_t copy = (size_t)n;
                if (used + copy >= out_cap) copy = out_cap - used - 1;
                if (copy > 0) {
                    memcpy(out + used, buf, copy);
                    used += copy;
                    out[used] = '\0';
                }
            }
            break;
        }

        if (timeout_ms > 0 && wall_time_ms() - start > timeout_ms) {
            if (timed_out) *timed_out = 1;
            kill(-pid, SIGKILL);
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            break;
        }
        usleep(20000);
    }

    close(pipefd[0]);
    if (exit_code) {
        if (child_done && WIFEXITED(status)) *exit_code = WEXITSTATUS(status);
        else if (WIFSIGNALED(status)) *exit_code = 128 + WTERMSIG(status);
        else *exit_code = -1;
    }
    return used > 0 || child_done;
}

static int root_assist_text_has_module_signal(const char *text) {
    if (!text) return 0;
    static const char *const module_terms[] = {
        "/data/adb/modules", "/data/adb/magisk", "/data/adb/magisk.db",
        "/data/adb/ksu", "/data/adb/ap", "module.prop", "zygisk_lsposed",
        "shamiko", "lsposed", "riru", "zygisk", "kernelsu", "apatch", "magisk",
        NULL
    };
    return process_text_has_any(text, module_terms, NULL);
}

static int root_assist_text_has_process_signal(const char *text, int *score_out) {
    if (score_out) *score_out = 0;
    if (!text) return 0;
    static const char *const strong_terms[] = {
        "frida-server", "frida", "gum-js-loop", "gdbserver", "lldb-server", "objection",
        "magiskd", "/data/adb/magisk", "ksud", "/data/adb/ksu", "apd", "/data/adb/ap",
        "zygisk", "riru", "lspd", "lsposed", "xposed", NULL
    };
    static const char *const medium_terms[] = {
        "sshd", "dropbear", "telnetd", "socat", "netcat", "nc -l",
        "/data/data/com.termux/files/usr/bin/sshd", "/data/data/com.termux/files/usr/bin/dropbear",
        "termux-chroot", "proot", "tsu", NULL
    };
    const char *matched = NULL;
    if (process_text_has_any(text, strong_terms, &matched)) {
        LOGI("Root-assisted process signal strong: term=%s", safe_str(matched));
        if (score_out) *score_out = 6;
        return 1;
    }
    if (process_text_has_any(text, medium_terms, &matched)) {
        LOGI("Root-assisted process signal medium: term=%s", safe_str(matched));
        if (score_out) *score_out = 3;
        return 1;
    }
    return 0;
}

static int root_assist_text_has_port_signal(const char *text, int *score_out) {
    if (score_out) *score_out = 0;
    if (!text) return 0;
    int hit = 0;
    int best = 0;

    char *copy = strdup(text);
    if (!copy) return 0;
    char *save = NULL;
    char *line = strtok_r(copy, "\n", &save);
    while (line) {
        int port = 0;
        char state[16] = {0};
        if (parse_proc_net_tcp_line(line, &port, state, sizeof(state)) && strcmp(state, "0A") == 0) {
            int ps = 0;
            const char *risk = port_risk_label(port, &ps);
            if (risk) {
                LOGI("Root-assisted suspicious listening port: port=%d risk=%s line=%.256s", port, risk, line);
                hit = 1;
                if (ps > best) best = ps;
            }
        }
        if (contains_nocase(line, "frida") || contains_nocase(line, "gum-js-loop") ||
            contains_nocase(line, "objection") || contains_nocase(line, "lspd") ||
            contains_nocase(line, "lsposed") || contains_nocase(line, "xposed") ||
            contains_nocase(line, "magisk") || contains_nocase(line, "zygisk") ||
            contains_nocase(line, "ksud") || contains_nocase(line, "apd")) {
            LOGI("Root-assisted suspicious unix/socket term: line=%.256s", line);
            hit = 1;
            if (best < 5) best = 5;
        }
        line = strtok_r(NULL, "\n", &save);
    }
    free(copy);
    if (score_out) *score_out = best;
    return hit;
}

static RootAssistReport checkRootAssistedAsyncView(void) {
    long long t0 = wall_time_ms();
    RootAssistReport out;
    memset(&out, 0, sizeof(out));
    out.status = ROOT_ASSIST_NOT_RUN;
    out.exit_code = -1;

    char *buf = (char *)calloc(1, ROOT_ASSIST_OUTPUT_MAX);
    if (!buf) {
        out.status = ROOT_ASSIST_ERROR;
        return out;
    }

    const char *cmd =
        "id; "
        "echo __ROOT_ASSIST_MODULES__; "
        "ls -ld /data/adb /data/adb/modules /data/adb/modules/* /data/adb/magisk.db /data/adb/ksu /data/adb/ap 2>/dev/null; "
        "for f in /data/adb/modules/*/module.prop; do echo __MODULE_PROP__:$f; cat \"$f\" 2>/dev/null; done; "
        "echo __ROOT_ASSIST_PROCESSES__; "
        "ps -A 2>/dev/null; "
        "echo __ROOT_ASSIST_PORTS__; "
        "cat /proc/net/tcp /proc/net/tcp6 /proc/net/unix 2>/dev/null; "
        "echo __ROOT_ASSIST_MOUNTS__; "
        "cat /proc/self/mountinfo /proc/mounts 2>/dev/null";

    int exit_code = -1;
    int timed_out = 0;
    int ran = run_su_command_timeout(cmd, buf, ROOT_ASSIST_OUTPUT_MAX, ROOT_ASSIST_TIMEOUT_MS, &exit_code, &timed_out);
    out.exit_code = exit_code;
    out.timeout = timed_out;
    out.output_bytes = (int)strlen(buf);

    if (timed_out) {
        out.status = ROOT_ASSIST_TIMEOUT;
        LOGW("Root-assisted scan timed out after %d ms", ROOT_ASSIST_TIMEOUT_MS);
        free(buf);
        return out;
    }
    if (!ran || exit_code == 127) {
        out.status = ROOT_ASSIST_UNAVAILABLE;
        VLOGI("Root-assisted scan unavailable: ran=%d exit=%d output_bytes=%d", ran, exit_code, out.output_bytes);
        free(buf);
        return out;
    }

    if (contains_nocase(buf, "uid=0") || contains_nocase(buf, "uid=0(root)")) {
        out.status = ROOT_ASSIST_GRANTED;
        out.granted = 1;
        out.root_view = 1;
        out.score = 8;
        LOGI("Root-assisted su granted: exit=%d output_bytes=%d", exit_code, out.output_bytes);
    } else {
        out.status = ROOT_ASSIST_DENIED;
        VLOGI("Root-assisted su not granted: exit=%d output=%.256s", exit_code, buf);
        free(buf);
        return out;
    }

    if (root_assist_text_has_module_signal(buf)) {
        out.modules = 1;
        if (out.score < 10) out.score = 10;
        LOGI("Root-assisted module/root artifact signal visible");
    }

    int pscore = 0;
    if (root_assist_text_has_process_signal(buf, &pscore)) {
        out.process = 1;
        if (out.score < 8 + pscore) out.score = 8 + pscore;
    }

    int port_score = 0;
    if (root_assist_text_has_port_signal(buf, &port_score)) {
        out.ports = 1;
        if (out.score < 8 + port_score) out.score = 8 + port_score;
    }

    VLOGI("Root-assisted scan complete: elapsed_ms=%lld status=%s granted=%d modules=%d process=%d ports=%d score=%d output_bytes=%d exit=%d",
          wall_time_ms() - t0, rootAssistStatusText(out.status), out.granted, out.modules,
          out.process, out.ports, out.score, out.output_bytes, out.exit_code);
    free(buf);
    return out;
}



// ─── Cross-view consistency checks: smaps, /data/app, namespaces/fdinfo ──────
static int mapsExecSummary(const char *text, int *out_count, unsigned long long *out_size) {
    if (out_count) *out_count = 0;
    if (out_size) *out_size = 0;
    if (!text) return 0;
    char *copy = strdup(text);
    if (!copy) return 0;
    int count = 0;
    unsigned long long size = 0;
    char *save = NULL;
    char *line = strtok_r(copy, "\n", &save);
    while (line) {
        MapEntry e;
        if (parse_maps_line(line, &e) && e.perms[2] == 'x') {
            count++;
            if (e.end > e.start) size += (unsigned long long)(e.end - e.start);
        }
        line = strtok_r(NULL, "\n", &save);
    }
    free(copy);
    if (out_count) *out_count = count;
    if (out_size) *out_size = size;
    return 1;
}

static jboolean checkSmapsConsistency(void) {
    size_t maps_len = 0, smaps_len = 0;
    char *maps = read_file_raw_dynamic("/proc/self/maps", &maps_len);
    char *smaps = read_file_raw_dynamic("/proc/self/smaps", &smaps_len);
    if (!maps || !smaps) {
        VLOGI("SMAPS consistency skipped: maps=%s smaps=%s", maps ? "readable" : "unreadable", smaps ? "readable" : "unreadable");
        free(maps);
        free(smaps);
        return JNI_FALSE;
    }

    int maps_exec = 0;
    unsigned long long maps_exec_size = 0;
    mapsExecSummary(maps, &maps_exec, &maps_exec_size);

    int smaps_exec = 0;
    unsigned long long smaps_exec_size = 0;
    unsigned long private_dirty_exec_kb = 0;
    int suspicious = 0;
    int current_exec = 0;
    char current_path[PATH_MAX];
    current_path[0] = '\0';

    char *save = NULL;
    char *line = strtok_r(smaps, "\n", &save);
    while (line) {
        MapEntry e;
        if (parse_maps_line(line, &e)) {
            current_exec = (e.perms[2] == 'x');
            snprintf(current_path, sizeof(current_path), "%s", e.path);
            if (current_exec) {
                smaps_exec++;
                if (e.end > e.start) smaps_exec_size += (unsigned long long)(e.end - e.start);

                const char *matched = NULL;
                if (isSuspiciousPathPrecise(e.path, &matched)) {
                    LOGI("SMAPS suspicious executable mapping: term=%s path=%s", safe_str(matched), safe_str(e.path));
                    suspicious = 1;
                }

                int memfd_or_deleted = contains_nocase(e.path, "memfd:") ||
                                       contains_nocase(e.path, "(deleted)") ||
                                       contains_nocase(e.path, "/dev/ashmem/");
                if (memfd_or_deleted && !isNormalArtJitPath(e.path) && !isKnownFalsePositivePath(e.path)) {
                    LOGI("SMAPS unknown executable memfd/deleted mapping: path=%s", safe_str(e.path));
                    suspicious = 1;
                }
            }
        } else if (current_exec && strncmp(line, "Private_Dirty:", 14) == 0) {
            unsigned long kb = 0;
            if (sscanf(line, "Private_Dirty: %lu kB", &kb) == 1) {
                private_dirty_exec_kb += kb;
                if (kb >= 8192 && current_path[0] &&
                    !contains_nocase(current_path, "/apex/") &&
                    !contains_nocase(current_path, "/system/") &&
                    !contains_nocase(current_path, APP_PACKAGE_NAME) &&
                    !isNormalArtJitPath(current_path)) {
                    LOGI("SMAPS executable private-dirty anomaly: private_dirty_kb=%lu path=%s", kb, safe_str(current_path));
                    suspicious = 1;
                }
            }
        }
        line = strtok_r(NULL, "\n", &save);
    }

    int delta = maps_exec - smaps_exec;
    if (delta < 0) delta = -delta;
    if (delta > 6) {
        LOGI("SMAPS/maps executable mapping count mismatch: maps_exec=%d smaps_exec=%d delta=%d", maps_exec, smaps_exec, delta);
        suspicious = 1;
    }

    VLOGI("SMAPS consistency summary: maps_exec=%d smaps_exec=%d maps_exec_size=%llu smaps_exec_size=%llu private_dirty_exec_kb=%lu suspicious=%d maps_len=%lu smaps_len=%lu",
          maps_exec, smaps_exec, maps_exec_size, smaps_exec_size,
          private_dirty_exec_kb, suspicious, (unsigned long)maps_len, (unsigned long)smaps_len);
    free(maps);
    free(smaps);
    return suspicious ? JNI_TRUE : JNI_FALSE;
}

static int scanDirForPackageToken(const char *dir_path, const char *pkg, int depth, int *entries) {
    if (!dir_path || !pkg || !entries || *entries > 700) return 0;
    DIR *dir = opendir(dir_path);
    if (!dir) return -1;

    int found = 0;
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') continue;
        if (++(*entries) > 700) break;
        if (contains_nocase(de->d_name, pkg)) {
            found = 1;
            break;
        }
        if (depth > 0 && de->d_type == DT_DIR) {
            char child[PATH_MAX];
            snprintf(child, sizeof(child), "%s/%s", dir_path, de->d_name);
            int sub = scanDirForPackageToken(child, pkg, depth - 1, entries);
            if (sub == 1) {
                found = 1;
                break;
            }
        }
    }
    closedir(dir);
    return found ? 1 : 0;
}

static int dataAppContainsPackageToken(const char *pkg, int *out_any_readable) {
    if (out_any_readable) *out_any_readable = 0;
    if (!pkg || !*pkg) return 0;
    const char *roots[] = {
        "/data/app",
        "/mnt/expand",
        NULL
    };
    int any_readable = 0;
    for (int i = 0; roots[i]; i++) {
        int entries = 0;
        int r = scanDirForPackageToken(roots[i], pkg, 3, &entries);
        if (r >= 0) any_readable = 1;
        if (r == 1) {
            if (out_any_readable) *out_any_readable = any_readable;
            return 1;
        }
    }
    if (out_any_readable) *out_any_readable = any_readable;
    return 0;
}

static jboolean checkDataAppInconsistency(JNIEnv *env) {
    if (!env) return JNI_FALSE;
    jobject app = getCurrentApplication(env);
    if (!app) {
        VLOGI("DATA_APP inconsistency skipped: currentApplication unavailable");
        return JNI_FALSE;
    }
    jclass ctxCls = (*env)->FindClass(env, "android/content/Context");
    jmethodID getPmMid = ctxCls ? (*env)->GetMethodID(env, ctxCls, "getPackageManager", "()Landroid/content/pm/PackageManager;") : NULL;
    jobject pm = NULL;
    if (getPmMid) pm = (*env)->CallObjectMethod(env, app, getPmMid);
    if ((*env)->ExceptionCheck(env) || !pm) {
        clearJniException(env, "DATA_APP getPackageManager");
        if (ctxCls) (*env)->DeleteLocalRef(env, ctxCls);
        (*env)->DeleteLocalRef(env, app);
        return JNI_FALSE;
    }

    const char *riskyPkgs[] = {
        "org.lsposed.manager",
        "org.frknkrc44.hma_oss",
        "com.tsng.hidemyapplist",
        "com.topjohnwu.magisk",
        "io.github.huskydg.magisk",
        "me.weishu.kernelsu",
        "me.bmax.apatch",
        "com.lexa.fakegps",
        "com.blogspot.newapphorizons.fakegps",
        "com.incorporateapps.fakegps.fre",
        "com.theappninjas.fakegpsjoystick",
        "ru.gavrikov.mocklocations",
        "com.rosteam.gpsemulator",
        "io.github.auag0.fakelocation",
        NULL
    };

    int inconsistent = 0;
    int any_readable = 0;
    for (int i = 0; riskyPkgs[i]; i++) {
        const char *pkg = riskyPkgs[i];
        int pkgInfo = pmObjectExistsByString(env, pm, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;", pkg);
        int appInfo = pmObjectExistsByString(env, pm, "getApplicationInfo", "(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;", pkg);
        int launchIntent = pmObjectExistsByString(env, pm, "getLaunchIntentForPackage", "(Ljava/lang/String;)Landroid/content/Intent;", pkg);
        int installed = pmInstalledPackagesContains(env, pm, pkg);
        int pm_seen = pkgInfo + appInfo + launchIntent + installed;
        int readable = 0;
        int fs_seen = dataAppContainsPackageToken(pkg, &readable);
        if (readable) any_readable = 1;
        if (fs_seen && pm_seen == 0) {
            LOGI("DATA_APP package visibility inconsistency: pkg=%s visible_in_data_app=1 pm_views=0", pkg);
            inconsistent = 1;
        } else if (fs_seen || pm_seen > 0) {
            VLOGI("DATA_APP package cross-view: pkg=%s fs_seen=%d pm_seen=%d getPackageInfo=%d getApplicationInfo=%d launchIntent=%d installedList=%d",
                  pkg, fs_seen, pm_seen, pkgInfo, appInfo, launchIntent, installed);
        }
    }

    if (!any_readable) VLOGI("DATA_APP inconsistency check: /data/app style roots unreadable; marking skipped/clean, not suspicious");
    VLOGI("DATA_APP inconsistency summary: any_readable=%d inconsistent=%d", any_readable, inconsistent);
    (*env)->DeleteLocalRef(env, pm);
    if (ctxCls) (*env)->DeleteLocalRef(env, ctxCls);
    (*env)->DeleteLocalRef(env, app);
    return inconsistent ? JNI_TRUE : JNI_FALSE;
}

static jboolean checkNamespaceFdinfo(void) {
    int suspicious = 0;
    const char *ns_paths[] = {
        "/proc/self/ns/mnt",
        "/proc/self/ns/pid",
        "/proc/self/ns/net",
        "/proc/self/ns/user",
        NULL
    };
    for (int i = 0; ns_paths[i]; i++) {
        char target[PATH_MAX];
        ssize_t n = readlink(ns_paths[i], target, sizeof(target) - 1);
        if (n > 0) {
            target[n] = '\0';
            VLOGI("Namespace snapshot: %s -> %s", ns_paths[i], target);
        } else {
            VLOGI("Namespace snapshot unreadable: %s errno=%d", ns_paths[i], errno);
        }
    }

    DIR *dir = opendir("/proc/self/fdinfo");
    if (!dir) {
        VLOGI("fdinfo scan skipped: /proc/self/fdinfo unreadable errno=%d", errno);
        return JNI_FALSE;
    }

    int scanned = 0;
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') continue;
        if (++scanned > 160) break;

        char fd_path[PATH_MAX];
        char fd_target[PATH_MAX];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%s", de->d_name);
        ssize_t n = readlink(fd_path, fd_target, sizeof(fd_target) - 1);
        if (n > 0) {
            fd_target[n] = '\0';
            if (isSuspiciousPathPrecise(fd_target, NULL) ||
                contains_nocase(fd_target, "/data/adb/") ||
                contains_nocase(fd_target, "/data/local/tmp/") ||
                contains_nocase(fd_target, "frida") ||
                contains_nocase(fd_target, "gum-js")) {
                LOGI("NAMESPACE_FDINFO suspicious fd target: fd=%s target=%s", de->d_name, fd_target);
                suspicious = 1;
            }
        }

        char info_path[PATH_MAX];
        snprintf(info_path, sizeof(info_path), "/proc/self/fdinfo/%s", de->d_name);
        char *info = read_file_raw_dynamic(info_path, NULL);
        if (info) {
            if (isSuspiciousPathPrecise(info, NULL) || contains_nocase(info, "/data/adb/") || contains_nocase(info, "frida")) {
                LOGI("NAMESPACE_FDINFO suspicious fdinfo text: fd=%s", de->d_name);
                suspicious = 1;
            }
            free(info);
        }
    }
    closedir(dir);
    VLOGI("NAMESPACE_FDINFO summary: scanned=%d suspicious=%d", scanned, suspicious);
    return suspicious ? JNI_TRUE : JNI_FALSE;
}

static void runTimingTelemetry(JNIEnv *env) {
    if (!env) return;
    jobject app = getCurrentApplication(env);
    if (!app) {
        VLOGI("Timing telemetry skipped: currentApplication unavailable");
        return;
    }
    jclass ctxCls = (*env)->FindClass(env, "android/content/Context");
    if (!ctxCls) {
        clearJniException(env, "TimingTelemetry Context class");
        (*env)->DeleteLocalRef(env, app);
        return;
    }

    jmethodID getPmMid = (*env)->GetMethodID(env, ctxCls, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject pm = getPmMid ? (*env)->CallObjectMethod(env, app, getPmMid) : NULL;
    if ((*env)->ExceptionCheck(env)) { clearJniException(env, "TimingTelemetry getPackageManager"); pm = NULL; }
    if (pm) {
        long long t = wall_time_ms();
        int seen = pmObjectExistsByString(env, pm, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;", APP_PACKAGE_NAME);
        long long dt = wall_time_ms() - t;
        VLOGI("Timing telemetry: PackageManager.getPackageInfo self elapsed_ms=%lld seen=%d", dt, seen);
        (*env)->DeleteLocalRef(env, pm);
    }

    jmethodID getResolverMid = (*env)->GetMethodID(env, ctxCls, "getContentResolver", "()Landroid/content/ContentResolver;");
    jobject resolver = getResolverMid ? (*env)->CallObjectMethod(env, app, getResolverMid) : NULL;
    if ((*env)->ExceptionCheck(env)) { clearJniException(env, "TimingTelemetry getContentResolver"); resolver = NULL; }
    if (resolver) {
        long long t = wall_time_ms();
        jstring val = settingsSecureGetString(env, resolver, "development_settings_enabled");
        long long dt = wall_time_ms() - t;
        char buf[64] = {0};
        if (val) {
            jstringToBuffer(env, val, buf, sizeof(buf));
            (*env)->DeleteLocalRef(env, val);
        }
        VLOGI("Timing telemetry: Settings.Secure.getString development_settings_enabled elapsed_ms=%lld value=%s", dt, buf[0] ? buf : "<none>");
        (*env)->DeleteLocalRef(env, resolver);
    }

    jmethodID getServiceMid = (*env)->GetMethodID(env, ctxCls, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;");
    if (getServiceMid) {
        jstring svc = (*env)->NewStringUTF(env, "location");
        long long t = wall_time_ms();
        jobject loc = svc ? (*env)->CallObjectMethod(env, app, getServiceMid, svc) : NULL;
        long long dt = wall_time_ms() - t;
        if ((*env)->ExceptionCheck(env)) { clearJniException(env, "TimingTelemetry getSystemService(location)"); loc = NULL; }
        VLOGI("Timing telemetry: Context.getSystemService(location) elapsed_ms=%lld object=%s", dt, loc ? "present" : "none");
        if (loc) (*env)->DeleteLocalRef(env, loc);
        if (svc) (*env)->DeleteLocalRef(env, svc);
    }

    (*env)->DeleteLocalRef(env, ctxCls);
    (*env)->DeleteLocalRef(env, app);
}


// ─── Aggregation ────────────────────────────────────────────────────────────
typedef struct ThreatReport {
    int root_paths;
    int root_mounts;
    int maps_artifacts;
    int maps_filtered;
    int smaps_consistency;
    int suspicious_maps;
    int debugger;
    int suspicious_threads;
    int suspicious_fds;
    int linker_hooks;
    int emulator;
    int usb_debugging;
    int bootloader_unlocked;
    int build_props;
    int kernel_identity;
    int jni_table;
    int jvm_table;
    int modules_phdr;
    int self_breakpoints;
    int memory_live;
    int memory_disk;
    int art_bridge_classes;
    int art_stack;
    int art_classloader;
    int art_dex_maps;
    int package_risk;
    int package_inconsistency;
    int data_app_inconsistency;
    int location_environment;
    int framework_runtime;
    int namespace_fdinfo;
    int disk_public_artifacts;
    int disk_root_artifacts;
    int disk_zip_modules;
    int disk_apk_risk;
    int suspicious_process;
    int suspicious_process_score;
    int suspicious_ports;
    int suspicious_ports_score;
    int root_assisted_status;
    int root_assisted_granted;
    int root_assisted_root_view;
    int root_assisted_modules;
    int root_assisted_process;
    int root_assisted_ports;
    int root_view_delta;
    int root_assisted_score;
    int score;
} ThreatReport;

static pthread_mutex_t g_deep_lock = PTHREAD_MUTEX_INITIALIZER;
static ThreatReport g_cached_deep_report;
static int g_deep_report_valid = 0;
static int g_deep_running = 0;
static long long g_deep_last_finished_ms = 0;
static long long g_deep_last_started_ms = 0;
#define DEEP_SCAN_MIN_INTERVAL_MS 15000LL
#define DEEP_SCAN_RANDOM_DELAY_MIN_MS 80U
#define DEEP_SCAN_RANDOM_DELAY_MAX_MS 900U

// Small per-run timing jitter for the existing async worker. This does not
// change scan logic or scheduling cadence; it only varies when the deep scan
// begins after the worker thread has been created.
static uint32_t deepScanRandom32(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    uint64_t x = ((uint64_t)ts.tv_sec << 32) ^ (uint64_t)ts.tv_nsec;
    x ^= ((uint64_t)getpid() << 17);
    x ^= ((uint64_t)current_tid() << 1);
    x ^= (uintptr_t)&ts;

    // xorshift64* style mixing; sufficient for non-security scheduling jitter.
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    x *= 2685821657736338717ULL;
    return (uint32_t)(x ^ (x >> 32));
}

static unsigned int deepScanRandomDelayMs(void) {
    const unsigned int min_ms = DEEP_SCAN_RANDOM_DELAY_MIN_MS;
    const unsigned int max_ms = DEEP_SCAN_RANDOM_DELAY_MAX_MS;
    const unsigned int span = (max_ms - min_ms) + 1U;
    return min_ms + (deepScanRandom32() % span);
}

static void sleepMilliseconds(unsigned int delay_ms) {
    struct timespec req;
    req.tv_sec = (time_t)(delay_ms / 1000U);
    req.tv_nsec = (long)((delay_ms % 1000U) * 1000000UL);
    while (nanosleep(&req, &req) != 0 && errno == EINTR) {
        // Resume the remaining sleep after a signal interruption.
    }
}

static const char *verdictFromScore(int score) {
    if (score >= 8) return "BLOCK";
    if (score >= 4) return "WARNING";
    return "CLEAN";
}

static int scoreThreatReport(const ThreatReport *r) {
    if (!r) return 0;
    int score = 0;
    score += r->root_paths ? 6 : 0;
    score += r->root_mounts ? 6 : 0;
    score += r->maps_artifacts ? 5 : 0;
    score += r->maps_filtered ? 5 : 0;
    score += r->smaps_consistency ? 4 : 0;
    score += r->suspicious_maps ? 5 : 0;
    score += r->debugger ? 5 : 0;
    score += r->suspicious_threads ? 4 : 0;
    score += r->suspicious_fds ? 4 : 0;
    score += r->linker_hooks ? 5 : 0;
    score += r->emulator ? 1 : 0;
    score += r->usb_debugging ? 1 : 0;
    score += r->bootloader_unlocked ? 3 : 0;
    score += r->build_props ? 3 : 0;
    score += r->kernel_identity ? 2 : 0;
    score += r->jni_table ? 8 : 0;
    score += r->jvm_table ? 8 : 0;
    score += r->modules_phdr ? 6 : 0;
    score += r->self_breakpoints ? 8 : 0;
    score += r->art_bridge_classes ? 6 : 0;
    score += r->art_stack ? 5 : 0;
    score += r->art_classloader ? 6 : 0;
    score += r->art_dex_maps ? 6 : 0;
    score += r->package_risk ? 4 : 0;
    score += r->package_inconsistency ? 5 : 0;
    score += r->data_app_inconsistency ? 5 : 0;
    score += r->location_environment ? 3 : 0;
    score += r->framework_runtime ? 5 : 0;
    score += r->namespace_fdinfo ? 2 : 0;
    score += r->disk_public_artifacts ? 2 : 0;
    score += r->disk_root_artifacts ? 5 : 0;
    score += r->disk_zip_modules ? 4 : 0;
    score += r->disk_apk_risk ? 3 : 0;
    score += r->suspicious_process_score;
    score += r->suspicious_ports_score;
    score += r->root_assisted_score;
    score += r->root_view_delta ? 6 : 0;
    score += r->memory_live ? 10 : 0;
    score += r->memory_disk ? 8 : 0;
    return score;
}

static ThreatReport runFastChecksInternal(JNIEnv *env) {
    long long t0 = wall_time_ms();
    ThreatReport r;
    memset(&r, 0, sizeof(r));
    VLOGI("runFastChecksInternal begin: env=%p", (void *)env);

    r.root_paths = checkRootPaths();
    r.root_mounts = checkRootMounts();
    r.maps_artifacts = checkMapsArtifactsRaw();
    r.suspicious_maps = checkSuspiciousExecutableMaps();
    r.debugger = checkDebugger();
    r.suspicious_threads = checkSuspiciousThreads();
    r.suspicious_fds = checkSuspiciousFds();
    r.linker_hooks = checkLinkerAndInlineHooks();
    r.emulator = checkEmulatorFiles();
    r.usb_debugging = checkUsbDebuggingProps();
    r.bootloader_unlocked = checkBootloaderUnlockedProps();
    r.build_props = checkBuildProps();
    r.kernel_identity = checkKernelIdentityConsistency();
    r.jni_table = checkJniTableIntegrity(env);
    r.jvm_table = checkJavaVmTableIntegrity();
    r.memory_live = checkMemoryIntegrityLive();

    r.score = scoreThreatReport(&r);
    VLOGI("runFastChecksInternal end: elapsed_ms=%lld score=%d verdict=%s",
          wall_time_ms() - t0, r.score, verdictFromScore(r.score));
    return r;
}

static ThreatReport runDeepChecksInternal(JNIEnv *env) {
    long long t0 = wall_time_ms();
    ThreatReport r;
    memset(&r, 0, sizeof(r));
    VLOGI("runDeepChecksInternal begin: env=%p", (void *)env);

    if (env) setThreadContextClassLoaderFromApplication(env);

    r.maps_filtered = checkMapsFilteringMismatch();
    r.smaps_consistency = checkSmapsConsistency();
    r.modules_phdr = checkLoadedModulesPhdr();
    r.self_breakpoints = checkSelfBreakpoints();
    r.art_bridge_classes = checkArtBridgeClasses(env);
    r.art_stack = checkArtStack(env);
    r.art_classloader = checkArtClassLoader(env);
    r.art_dex_maps = checkArtDexMaps();
    r.package_risk = checkPackageRiskAndInconsistency(env, &r.package_inconsistency);
    r.data_app_inconsistency = checkDataAppInconsistency(env);
    r.location_environment = checkLocationEnvironment(env);
    r.framework_runtime = checkFrameworkRuntime(env);
    r.namespace_fdinfo = checkNamespaceFdinfo();
    runTimingTelemetry(env);
    DiskArtifactReport disk = checkDiskArtifacts();
    r.disk_public_artifacts = disk.public_artifacts;
    r.disk_root_artifacts = disk.root_artifacts;
    r.disk_zip_modules = disk.zip_modules;
    r.disk_apk_risk = disk.apk_risk;
    ProcessScanReport proc = checkSuspiciousProcesses();
    r.suspicious_process = proc.hit;
    r.suspicious_process_score = proc.score;
    PortScanReport ports = checkSuspiciousPorts();
    r.suspicious_ports = ports.hit;
    r.suspicious_ports_score = ports.score;
    RootAssistReport root_assist = checkRootAssistedAsyncView();
    r.root_assisted_status = root_assist.status;
    r.root_assisted_granted = root_assist.granted;
    r.root_assisted_root_view = root_assist.root_view;
    r.root_assisted_modules = root_assist.modules;
    r.root_assisted_process = root_assist.process;
    r.root_assisted_ports = root_assist.ports;
    r.root_assisted_score = root_assist.score;
    r.memory_disk = checkMemoryIntegrityDisk();

    r.score = scoreThreatReport(&r);
    VLOGI("runDeepChecksInternal end: elapsed_ms=%lld deep_score=%d",
          wall_time_ms() - t0, r.score);
    return r;
}

static void mergeDeepReport(ThreatReport *dst, const ThreatReport *deep) {
    if (!dst || !deep) return;
    dst->maps_filtered = deep->maps_filtered;
    dst->smaps_consistency = deep->smaps_consistency;
    dst->modules_phdr = deep->modules_phdr;
    dst->self_breakpoints = deep->self_breakpoints;
    dst->art_bridge_classes = deep->art_bridge_classes;
    dst->art_stack = deep->art_stack;
    dst->art_classloader = deep->art_classloader;
    dst->art_dex_maps = deep->art_dex_maps;
    dst->package_risk = deep->package_risk;
    dst->package_inconsistency = deep->package_inconsistency;
    dst->data_app_inconsistency = deep->data_app_inconsistency;
    dst->location_environment = deep->location_environment;
    dst->framework_runtime = deep->framework_runtime;
    dst->namespace_fdinfo = deep->namespace_fdinfo;
    dst->disk_public_artifacts = deep->disk_public_artifacts;
    dst->disk_root_artifacts = deep->disk_root_artifacts;
    dst->disk_zip_modules = deep->disk_zip_modules;
    dst->disk_apk_risk = deep->disk_apk_risk;
    dst->suspicious_process = deep->suspicious_process;
    dst->suspicious_process_score = deep->suspicious_process_score;
    dst->suspicious_ports = deep->suspicious_ports;
    dst->suspicious_ports_score = deep->suspicious_ports_score;
    dst->root_assisted_status = deep->root_assisted_status;
    dst->root_assisted_granted = deep->root_assisted_granted;
    dst->root_assisted_root_view = deep->root_assisted_root_view;
    dst->root_assisted_modules = deep->root_assisted_modules;
    dst->root_assisted_process = deep->root_assisted_process;
    dst->root_assisted_ports = deep->root_assisted_ports;
    dst->root_assisted_score = deep->root_assisted_score;
    dst->root_view_delta = (deep->root_assisted_granted &&
                            !dst->root_paths && !dst->root_mounts && !dst->maps_artifacts && !dst->disk_root_artifacts &&
                            (deep->root_assisted_root_view || deep->root_assisted_modules ||
                             deep->root_assisted_process || deep->root_assisted_ports));
    dst->memory_disk = deep->memory_disk;
    dst->score = scoreThreatReport(dst);
}

static const char *cleanDetected(int value) { return value ? "DETECTED" : "CLEAN"; }
static const char *cleanTampered(int value) { return value ? "TAMPERED" : "CLEAN"; }
static const char *cleanHooked(int value) { return value ? "HOOKED" : "CLEAN"; }
static const char *pendingOrDetected(int pending, int value) { return pending ? "PENDING" : (value ? "DETECTED" : "CLEAN"); }
static const char *pendingOrTampered(int pending, int value) { return pending ? "PENDING" : (value ? "TAMPERED" : "CLEAN"); }

static void logThreatReport(const char *source, const ThreatReport *r) {
    if (!r) return;
    LOGI("[%s] SCORE=%d VERDICT=%s", source ? source : "unknown", r->score, verdictFromScore(r->score));
    LOGI("[%s] ROOT_PATHS=%s ROOT_MOUNTS=%s MAPS_ARTIFACTS=%s MAPS_FILTERED=%s SMAPS_CONSISTENCY=%s SUSPICIOUS_MAPS=%s",
         source ? source : "unknown", cleanDetected(r->root_paths), cleanDetected(r->root_mounts),
         cleanDetected(r->maps_artifacts), cleanDetected(r->maps_filtered), cleanDetected(r->smaps_consistency), cleanDetected(r->suspicious_maps));
    LOGI("[%s] DEBUGGER=%s THREADS=%s FDS=%s LINKER_INLINE=%s",
         source ? source : "unknown", cleanDetected(r->debugger), cleanDetected(r->suspicious_threads),
         cleanDetected(r->suspicious_fds), cleanDetected(r->linker_hooks));
    LOGI("[%s] USB_DEBUGGING=%s BOOTLOADER_UNLOCKED=%s BUILD_PROPS=%s KERNEL_IDENTITY=%s",
         source ? source : "unknown", cleanDetected(r->usb_debugging), cleanDetected(r->bootloader_unlocked),
         cleanDetected(r->build_props), cleanDetected(r->kernel_identity));
    LOGI("[%s] JNI_TABLE=%s JVM_TABLE=%s MODULES=%s SELF_BREAKPOINTS=%s",
         source ? source : "unknown", cleanHooked(r->jni_table), cleanHooked(r->jvm_table),
         cleanDetected(r->modules_phdr), cleanDetected(r->self_breakpoints));
    LOGI("[%s] ART_BRIDGE_CLASSES=%s ART_STACK=%s ART_CLASSLOADER=%s ART_DEX_MAPS=%s",
         source ? source : "unknown", cleanDetected(r->art_bridge_classes), cleanDetected(r->art_stack),
         cleanDetected(r->art_classloader), cleanDetected(r->art_dex_maps));
    LOGI("[%s] PACKAGE_RISK=%s PACKAGE_INCONSISTENCY=%s DATA_APP_INCONSISTENCY=%s LOCATION_ENVIRONMENT=%s FRAMEWORK_RUNTIME=%s NAMESPACE_FDINFO=%s",
         source ? source : "unknown", cleanDetected(r->package_risk), cleanDetected(r->package_inconsistency),
         cleanDetected(r->data_app_inconsistency), cleanDetected(r->location_environment), cleanDetected(r->framework_runtime),
         cleanDetected(r->namespace_fdinfo));
    LOGI("[%s] DISK_PUBLIC_ARTIFACTS=%s DISK_ROOT_ARTIFACTS=%s DISK_ZIP_MODULES=%s DISK_APK_RISK=%s",
         source ? source : "unknown", cleanDetected(r->disk_public_artifacts), cleanDetected(r->disk_root_artifacts),
         cleanDetected(r->disk_zip_modules), cleanDetected(r->disk_apk_risk));
    LOGI("[%s] SUSPICIOUS_PROCESS=%s PROCESS_SCORE=%d SUSPICIOUS_PORTS=%s PORT_SCORE=%d",
         source ? source : "unknown", cleanDetected(r->suspicious_process), r->suspicious_process_score,
         cleanDetected(r->suspicious_ports), r->suspicious_ports_score);
    LOGI("[%s] ROOT_ASSISTED_ASYNC=%s ROOT_ASSISTED_ROOT_VIEW=%s ROOT_ASSISTED_MODULES=%s ROOT_ASSISTED_PROCESS=%s ROOT_ASSISTED_PORTS=%s ROOT_VIEW_DELTA=%s ROOT_ASSIST_SCORE=%d",
         source ? source : "unknown", rootAssistStatusText(r->root_assisted_status),
         cleanDetected(r->root_assisted_root_view), cleanDetected(r->root_assisted_modules),
         cleanDetected(r->root_assisted_process), cleanDetected(r->root_assisted_ports),
         cleanDetected(r->root_view_delta), r->root_assisted_score);
    LOGI("[%s] APP_VIEW_ROOT_VISIBLE=%s ROOT_VIEW_DIRTY=%s ROOT_VIEW_DELTA=%s",
         source ? source : "unknown",
         cleanDetected(r->root_paths || r->root_mounts || r->maps_artifacts || r->disk_root_artifacts),
         cleanDetected(r->root_assisted_root_view || r->root_assisted_modules || r->root_assisted_process || r->root_assisted_ports),
         cleanDetected(r->root_view_delta));
    LOGI("[%s] EMULATOR=%s MEMORY_LIVE=%s MEMORY_DISK=%s",
         source ? source : "unknown", cleanDetected(r->emulator),
         cleanTampered(r->memory_live), cleanTampered(r->memory_disk));
}

// ─── Callback / async deep scan ─────────────────────────────────────────────
static void notifyJava(const char *reason) {
    if (!g_vm || !g_callback || !reason) return;
    JNIEnv *env = NULL;
    int attached = 0;
    if ((*g_vm)->GetEnv(g_vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        if ((*g_vm)->AttachCurrentThread(g_vm, (void **)&env, NULL) == JNI_OK) attached = 1;
        else return;
    }

    jclass cls = (*env)->GetObjectClass(env, g_callback);
    if (!cls) {
        if (attached) (*g_vm)->DetachCurrentThread(g_vm);
        return;
    }
    jmethodID mid = (*env)->GetMethodID(env, cls, "onThreatDetected", "(Ljava/lang/String;)V");
    if (mid) {
        jstring jreason = (*env)->NewStringUTF(env, reason);
        (*env)->CallVoidMethod(env, g_callback, mid, jreason);
        if ((*env)->ExceptionCheck(env)) clearJniException(env, "ThreatCallback.onThreatDetected");
        if (jreason) (*env)->DeleteLocalRef(env, jreason);
    }
    (*env)->DeleteLocalRef(env, cls);
    if (attached) (*g_vm)->DetachCurrentThread(g_vm);
}

static void notifyForReport(const ThreatReport *r) {
    if (!r) return;
    if (r->memory_live || r->memory_disk) notifyJava("MEMORY_TAMPERED");
    else if (r->jni_table || r->jvm_table) notifyJava("JNI_TABLE_HOOKED");
    else if (r->art_classloader || r->art_dex_maps || r->art_bridge_classes || r->art_stack) notifyJava("ART_RUNTIME_TAMPERED");
    else if (r->data_app_inconsistency) notifyJava("DATA_APP_VISIBILITY_INCONSISTENT");
    else if (r->package_inconsistency) notifyJava("PACKAGE_VISIBILITY_INCONSISTENT");
    else if (r->package_risk) notifyJava("RISKY_PACKAGE_VISIBLE");
    else if (r->location_environment) notifyJava("LOCATION_ENVIRONMENT_SUSPICIOUS");
    else if (r->framework_runtime) notifyJava("FRAMEWORK_RUNTIME_SUSPICIOUS");
    else if (r->disk_root_artifacts) notifyJava("DISK_ROOT_ARTIFACTS_VISIBLE");
    else if (r->disk_zip_modules) notifyJava("DISK_ZIP_MODULE_ARTIFACT");
    else if (r->disk_apk_risk) notifyJava("DISK_APK_RISK_ARTIFACT");
    else if (r->disk_public_artifacts) notifyJava("DISK_PUBLIC_ARTIFACTS_VISIBLE");
    else if (r->root_view_delta) notifyJava("ROOT_VIEW_DELTA_DETECTED");
    else if (r->root_assisted_modules) notifyJava("ROOT_ASSISTED_MODULES_VISIBLE");
    else if (r->root_assisted_process) notifyJava("ROOT_ASSISTED_PROCESS_VISIBLE");
    else if (r->root_assisted_ports) notifyJava("ROOT_ASSISTED_PORTS_VISIBLE");
    else if (r->root_assisted_granted) notifyJava("ROOT_ASSISTED_SU_GRANTED");
    else if (r->suspicious_process) notifyJava("SUSPICIOUS_PROCESS_VISIBLE");
    else if (r->suspicious_ports) notifyJava("SUSPICIOUS_PORTS_VISIBLE");
    else if (r->linker_hooks) notifyJava("LINKER_HOOKED");
    else if (r->debugger) notifyJava("DEBUGGER_ATTACHED");
    else if (r->smaps_consistency) notifyJava("SMAPS_CONSISTENCY_SUSPICIOUS");
    else if (r->namespace_fdinfo) notifyJava("NAMESPACE_FDINFO_SUSPICIOUS");
    else if (r->maps_filtered) notifyJava("MAPS_FILTERED");
    else if (r->maps_artifacts) notifyJava("MAPS_ARTIFACTS");
}

static void *deep_scan_worker(void *arg) {
    (void)arg;

    unsigned int delay_ms = deepScanRandomDelayMs();
    VLOGI("Deep async randomized start delay: %u ms", delay_ms);
    sleepMilliseconds(delay_ms);

    JNIEnv *env = NULL;
    int attached = 0;
    if (g_vm && (*g_vm)->GetEnv(g_vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        if ((*g_vm)->AttachCurrentThread(g_vm, (void **)&env, NULL) == JNI_OK) attached = 1;
        else env = NULL;
    }

    ThreatReport deep;
    memset(&deep, 0, sizeof(deep));
    if (env) {
        deep = runDeepChecksInternal(env);
        logThreatReport("deep_async", &deep);
    } else {
        LOGW("Deep async scan skipped: failed to attach native thread to JVM");
    }

    pthread_mutex_lock(&g_deep_lock);
    g_cached_deep_report = deep;
    g_deep_report_valid = env ? 1 : 0;
    g_deep_running = 0;
    g_deep_last_finished_ms = wall_time_ms();
    pthread_mutex_unlock(&g_deep_lock);

    if (env) notifyForReport(&deep);
    if (attached) (*g_vm)->DetachCurrentThread(g_vm);
    return NULL;
}

static int startDeepScanIfNeeded(void) {
    long long now = wall_time_ms();
    pthread_mutex_lock(&g_deep_lock);
    if (g_deep_running) {
        pthread_mutex_unlock(&g_deep_lock);
        return 0;
    }
    if (g_deep_report_valid && (now - g_deep_last_finished_ms) < DEEP_SCAN_MIN_INTERVAL_MS) {
        pthread_mutex_unlock(&g_deep_lock);
        return 0;
    }
    g_deep_running = 1;
    g_deep_last_started_ms = now;
    pthread_mutex_unlock(&g_deep_lock);

    pthread_t t;
    if (pthread_create(&t, NULL, deep_scan_worker, NULL) == 0) {
        pthread_detach(t);
        VLOGI("Deep async scan started");
        return 1;
    }

    pthread_mutex_lock(&g_deep_lock);
    g_deep_running = 0;
    pthread_mutex_unlock(&g_deep_lock);
    LOGW("Deep async scan failed to start");
    return 0;
}

static int getCachedDeepReport(ThreatReport *out, int *running, long long *age_ms) {
    int valid;
    long long now = wall_time_ms();
    pthread_mutex_lock(&g_deep_lock);
    valid = g_deep_report_valid;
    if (out && valid) *out = g_cached_deep_report;
    if (running) *running = g_deep_running;
    if (age_ms) *age_ms = valid ? (now - g_deep_last_finished_ms) : -1;
    pthread_mutex_unlock(&g_deep_lock);
    return valid;
}

static void buildResultString(char *result, size_t cap, const ThreatReport *r, int deep_valid, int deep_running, long long deep_age_ms) {
    if (!result || cap == 0 || !r) return;
    result[0] = '\0';
    int deep_pending = deep_valid ? 0 : 1;
    const char *deep_state = deep_valid ? (deep_running ? "RUNNING_CACHED" : "CACHED") : (deep_running ? "PENDING" : "NOT_STARTED");

    appendf(result, cap, "SCORE:%d|", r->score);
    appendf(result, cap, "VERDICT:%s|", verdictFromScore(r->score));
    appendf(result, cap, "DEEP_SCAN:%s|", deep_state);
    if (deep_valid && deep_age_ms >= 0) appendf(result, cap, "DEEP_AGE_MS:%lld|", deep_age_ms);

    appendf(result, cap, "ROOT_PATHS:%s|", r->root_paths ? "DETECTED" : "CLEAN");
    appendf(result, cap, "ROOT_MOUNTS:%s|", r->root_mounts ? "DETECTED" : "CLEAN");
    appendf(result, cap, "MAPS_ARTIFACTS:%s|", r->maps_artifacts ? "DETECTED" : "CLEAN");
    appendf(result, cap, "MAPS_FILTERED:%s|", pendingOrDetected(deep_pending, r->maps_filtered));
    appendf(result, cap, "SMAPS_CONSISTENCY:%s|", pendingOrDetected(deep_pending, r->smaps_consistency));
    appendf(result, cap, "SUSPICIOUS_MAPS:%s|", r->suspicious_maps ? "DETECTED" : "CLEAN");
    appendf(result, cap, "DEBUGGER:%s|", r->debugger ? "DETECTED" : "CLEAN");
    appendf(result, cap, "THREADS:%s|", r->suspicious_threads ? "DETECTED" : "CLEAN");
    appendf(result, cap, "FDS:%s|", r->suspicious_fds ? "DETECTED" : "CLEAN");
    appendf(result, cap, "LINKER_INLINE:%s|", r->linker_hooks ? "DETECTED" : "CLEAN");
    appendf(result, cap, "EMULATOR:%s|", r->emulator ? "DETECTED" : "CLEAN");
    appendf(result, cap, "USB_DEBUGGING:%s|", r->usb_debugging ? "DETECTED" : "CLEAN");
    appendf(result, cap, "BOOTLOADER_UNLOCKED:%s|", r->bootloader_unlocked ? "DETECTED" : "CLEAN");
    appendf(result, cap, "BUILD_PROPS:%s|", r->build_props ? "DETECTED" : "CLEAN");
    appendf(result, cap, "KERNEL_IDENTITY:%s|", r->kernel_identity ? "MISMATCH" : "CLEAN");
    appendf(result, cap, "JNI_TABLE:%s|", r->jni_table ? "HOOKED" : "CLEAN");
    appendf(result, cap, "JVM_TABLE:%s|", r->jvm_table ? "HOOKED" : "CLEAN");
    appendf(result, cap, "MODULES:%s|", pendingOrDetected(deep_pending, r->modules_phdr));
    appendf(result, cap, "SELF_BREAKPOINTS:%s|", pendingOrDetected(deep_pending, r->self_breakpoints));
    appendf(result, cap, "ART_BRIDGE_CLASSES:%s|", pendingOrDetected(deep_pending, r->art_bridge_classes));
    appendf(result, cap, "ART_STACK:%s|", pendingOrDetected(deep_pending, r->art_stack));
    appendf(result, cap, "ART_CLASSLOADER:%s|", pendingOrDetected(deep_pending, r->art_classloader));
    appendf(result, cap, "ART_DEX_MAPS:%s|", pendingOrDetected(deep_pending, r->art_dex_maps));
    appendf(result, cap, "PACKAGE_RISK:%s|", pendingOrDetected(deep_pending, r->package_risk));
    appendf(result, cap, "PACKAGE_INCONSISTENCY:%s|", pendingOrDetected(deep_pending, r->package_inconsistency));
    appendf(result, cap, "DATA_APP_INCONSISTENCY:%s|", pendingOrDetected(deep_pending, r->data_app_inconsistency));
    appendf(result, cap, "LOCATION_ENVIRONMENT:%s|", pendingOrDetected(deep_pending, r->location_environment));
    appendf(result, cap, "FRAMEWORK_RUNTIME:%s|", pendingOrDetected(deep_pending, r->framework_runtime));
    appendf(result, cap, "NAMESPACE_FDINFO:%s|", pendingOrDetected(deep_pending, r->namespace_fdinfo));
    appendf(result, cap, "DISK_PUBLIC_ARTIFACTS:%s|", pendingOrDetected(deep_pending, r->disk_public_artifacts));
    appendf(result, cap, "DISK_ROOT_ARTIFACTS:%s|", pendingOrDetected(deep_pending, r->disk_root_artifacts));
    appendf(result, cap, "DISK_ZIP_MODULES:%s|", pendingOrDetected(deep_pending, r->disk_zip_modules));
    appendf(result, cap, "DISK_APK_RISK:%s|", pendingOrDetected(deep_pending, r->disk_apk_risk));
    appendf(result, cap, "SUSPICIOUS_PROCESS:%s|", pendingOrDetected(deep_pending, r->suspicious_process));
    appendf(result, cap, "SUSPICIOUS_PORTS:%s|", pendingOrDetected(deep_pending, r->suspicious_ports));
    appendf(result, cap, "ROOT_ASSISTED_ASYNC:%s|", deep_pending ? "PENDING" : rootAssistStatusText(r->root_assisted_status));
    appendf(result, cap, "ROOT_ASSISTED_ROOT_VIEW:%s|", pendingOrDetected(deep_pending, r->root_assisted_root_view));
    appendf(result, cap, "ROOT_ASSISTED_MODULES:%s|", pendingOrDetected(deep_pending, r->root_assisted_modules));
    appendf(result, cap, "ROOT_ASSISTED_PROCESS:%s|", pendingOrDetected(deep_pending, r->root_assisted_process));
    appendf(result, cap, "ROOT_ASSISTED_PORTS:%s|", pendingOrDetected(deep_pending, r->root_assisted_ports));
    appendf(result, cap, "ROOT_VIEW_DELTA:%s|", pendingOrDetected(deep_pending, r->root_view_delta));
    appendf(result, cap, "MEMORY_LIVE:%s|", r->memory_live ? "TAMPERED" : "CLEAN");
    appendf(result, cap, "MEMORY_DISK:%s|", pendingOrTampered(deep_pending, r->memory_disk));
}

// ─── RegisterNatives ────────────────────────────────────────────────────────
static int registerSecurityCheckerNatives(JNIEnv *env) {
    if (!env) return 0;
    jclass cls = (*env)->FindClass(env, "com/example/securitysample/SecurityChecker");
    if (!cls) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        LOGI("RegisterNatives skipped: SecurityChecker class not found");
        return 0;
    }

    JNINativeMethod methods[] = {
        {"setCallback", "(Lcom/example/securitysample/SecurityChecker$ThreatCallback;)V", (void *)Java_com_example_securitysample_SecurityChecker_setCallback},
        {"runAllChecks", "()Ljava/lang/String;", (void *)Java_com_example_securitysample_SecurityChecker_runAllChecks},
        {"getNativeLog", "()Ljava/lang/String;", (void *)Java_com_example_securitysample_SecurityChecker_getNativeLog},
        {"clearNativeLog", "()V", (void *)Java_com_example_securitysample_SecurityChecker_clearNativeLog}
    };

    VLOGI("RegisterNatives target class=com/example/securitysample/SecurityChecker methods=%lu setCallback=%p runAllChecks=%p getNativeLog=%p clearNativeLog=%p",
          (unsigned long)(sizeof(methods) / sizeof(methods[0])),
          methods[0].fnPtr, methods[1].fnPtr, methods[2].fnPtr, methods[3].fnPtr);

    int rc = (*env)->RegisterNatives(env, cls, methods, (jint)(sizeof(methods) / sizeof(methods[0])));
    (*env)->DeleteLocalRef(env, cls);
    if (rc != JNI_OK) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        LOGI("RegisterNatives failed; exported JNI symbols remain as fallback");
        return 0;
    }
    LOGI("RegisterNatives completed for SecurityChecker");
    return 1;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    g_vm = vm;

    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK) {
        registerSecurityCheckerNatives(env);
    }

    initMemoryBaseline();

    LOGI("Security JNI loaded: async_deep_scan=on_demand root_assisted_async=enabled deep_min_interval_ms=%lld", (long long)DEEP_SCAN_MIN_INTERVAL_MS);

    LOGI("Security JNI loaded: VERBOSE=%d log_buffer=%lu bytes self_so=%s code=0x%lx-0x%lx",
         VERBOSE, (unsigned long)NATIVE_LOG_BUFFER_MAX, safe_str(self_so_path),
         (unsigned long)code_start, (unsigned long)code_end);
    return JNI_VERSION_1_6;
}

// ─── Public JNI methods ─────────────────────────────────────────────────────
JNIEXPORT void JNICALL
Java_com_example_securitysample_SecurityChecker_setCallback(JNIEnv *env, jobject thiz, jobject callback) {
    (void)thiz;
    if (g_callback) {
        (*env)->DeleteGlobalRef(env, g_callback);
        g_callback = NULL;
    }
    if (callback) {
        g_callback = (*env)->NewGlobalRef(env, callback);
    }
}

JNIEXPORT jstring JNICALL
Java_com_example_securitysample_SecurityChecker_runAllChecks(JNIEnv *env, jobject thiz) {
    (void)thiz;

    ThreatReport fast = runFastChecksInternal(env);
    ThreatReport combined = fast;
    ThreatReport cached_deep;
    memset(&cached_deep, 0, sizeof(cached_deep));

    int deep_running = 0;
    long long deep_age_ms = -1;
    int deep_valid = getCachedDeepReport(&cached_deep, &deep_running, &deep_age_ms);
    if (deep_valid) mergeDeepReport(&combined, &cached_deep);
    else combined.score = scoreThreatReport(&combined);

    int started = startDeepScanIfNeeded();
    if (started) deep_running = 1;
    else {
        // Refresh state after a possible no-op because another thread may already be running.
        ThreatReport tmp;
        memset(&tmp, 0, sizeof(tmp));
        int refreshed_running = 0;
        long long refreshed_age = deep_age_ms;
        int refreshed_valid = getCachedDeepReport(&tmp, &refreshed_running, &refreshed_age);
        deep_running = refreshed_running;
        if (refreshed_valid && !deep_valid) {
            cached_deep = tmp;
            combined = fast;
            mergeDeepReport(&combined, &cached_deep);
            deep_valid = 1;
            deep_age_ms = refreshed_age;
        }
    }

    logThreatReport(deep_valid ? "manual_fast_cached_deep" : "manual_fast_pending_deep", &combined);
    if (!deep_valid) {
        LOGI("[manual_fast_pending_deep] Deep fields are PENDING; async worker will update native log/callback when finished");
    } else if (deep_running) {
        LOGI("[manual_fast_cached_deep] Deep fields are cached while a new async deep scan is running age_ms=%lld", deep_age_ms);
    } else {
        LOGI("[manual_fast_cached_deep] Deep fields are cached age_ms=%lld", deep_age_ms);
    }

    char result[4096] = {0};
    buildResultString(result, sizeof(result), &combined, deep_valid, deep_running, deep_age_ms);
    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jstring JNICALL
Java_com_example_securitysample_SecurityChecker_getNativeLog(JNIEnv *env, jobject thiz) {
    (void)thiz;
    pthread_mutex_lock(&g_log_lock);
    jstring out = (*env)->NewStringUTF(env, g_log_buffer);
    pthread_mutex_unlock(&g_log_lock);
    return out;
}

JNIEXPORT void JNICALL
Java_com_example_securitysample_SecurityChecker_clearNativeLog(JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;
    pthread_mutex_lock(&g_log_lock);
    g_log_len = 0;
    g_log_buffer[0] = '\0';
    pthread_mutex_unlock(&g_log_lock);
    LOGI("Native log buffer cleared");
}
