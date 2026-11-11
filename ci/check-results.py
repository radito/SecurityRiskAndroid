#!/usr/bin/env python3
"""Check one emulator leg: app results (SecurityCheckCI logcat lines) vs expectations,
cross-checked against ground truth read as root from /proc/<pid>/maps.

usage: check-results.py <leg> <out_dir> <expectations.txt>

Expectation lines (comments with #):
    MAIN.<KEY> = VALUE[|VALUE...]    last main-process result
    ISO.<KEY>  = VALUE[|VALUE...]    last isolated-process result
    TRUTH.<fact> = yes|no            ground truth from the root-read maps
Writes <out_dir>/summary.json and appends Markdown to $GITHUB_STEP_SUMMARY.
"""
import json
import os
import re
import sys

REPORT_KEYS = ["SCORE", "VERDICT", "ANON_BSS_EXEC", "FAKE_JIT_MAPPING", "SUSPICIOUS_MAPS", "MAPS_ARTIFACTS",
               "ROOT_MOUNTS", "ROOT_PATHS", "MODULES", "SMAPS_CONSISTENCY", "EMULATOR"]
PKG = "com.example.securitysample"


def parse_raw(raw):
    out = {}
    for part in raw.strip().split("|"):
        if ":" in part:
            k, v = part.split(":", 1)
            if k and v:
                out[k] = v
    return out


def load_results(out_dir):
    main, iso = {}, {}
    path = os.path.join(out_dir, "results.txt")
    if os.path.exists(path):
        for line in open(path, errors="replace"):
            line = line.strip()
            if line.startswith("MAIN "):
                main = parse_raw(line[5:])
            elif line.startswith("ISO "):
                iso = parse_raw(line[4:])
    return main, iso


def maps_facts(path):
    # private_jit_exec: executable *private* mapping named like ART's JIT memfd. ART maps
    # jit-cache shared; Magisk loads Zygisk module libs from a memfd it names jit-cache.
    facts = {"exec_anon_bss": False, "private_jit_exec": False, "fixture_visible": False,
             "adb_module_path": False, "maps_captured": False}
    evidence = []
    if not os.path.exists(path):
        return facts, evidence
    facts["maps_captured"] = True
    for line in open(path, errors="replace"):
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        perms = parts[1]
        name = parts[5].strip() if len(parts) > 5 else ""
        if "x" in perms and name.startswith("[anon:.bss]"):
            facts["exec_anon_bss"] = True
            evidence.append(line.rstrip())
        if "x" in perms and perms.endswith("p") and ("memfd:jit-cache" in name or "memfd:jit-zygote-cache" in name):
            facts["private_jit_exec"] = True
            evidence.append(line.rstrip())
        if "ci_zygisk_fixture" in name:
            facts["fixture_visible"] = True
        if name.startswith("/data/adb/"):
            facts["adb_module_path"] = True
    return facts, evidence


def load_expectations(path):
    exp = []
    if not os.path.exists(path):
        return exp
    for n, line in enumerate(open(path), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^(MAIN|ISO|TRUTH)\.([A-Za-z0-9_]+)\s*=\s*(\S+)$", line)
        if not m:
            raise SystemExit(f"{path}:{n}: bad expectation: {line}")
        exp.append((m.group(1), m.group(2), m.group(3).split("|")))
    return exp


def main():
    leg, out_dir, exp_path = sys.argv[1:4]
    main_r, iso_r = load_results(out_dir)
    truth, evidence = maps_facts(os.path.join(out_dir, f"maps-{PKG}.txt"))
    truth_iso, _ = maps_facts(os.path.join(out_dir, f"maps-{PKG}_security_isolated.txt"))
    truth_txt = {k: ("yes" if v else "no") for k, v in truth.items()}

    failures, notes = [], []
    if not main_r:
        failures.append("no MAIN result line in logcat (app did not run or crashed; see logcat.txt)")

    # Setup problems: Magisk refusing a module's Zygisk libs means the hiding target
    # (or the hider) never loaded, so detector expectations are meaningless.
    setup_errors = []
    boot_log = os.path.join(out_dir, "logcat-boot.txt")
    if os.path.exists(boot_log):
        for line in open(boot_log, errors="replace"):
            if " E Magisk" in line and "zygisk/" in line:
                setup_errors.append(line.strip())
    for line in setup_errors[:5]:
        failures.append(f"SETUP: Magisk could not load a module's Zygisk library: {line}")

    for scope, key, allowed in load_expectations(exp_path):
        if scope == "TRUTH":
            got = truth_txt.get(key, "<unknown fact>")
        else:
            src = main_r if scope == "MAIN" else iso_r
            if scope == "ISO" and not iso_r:
                notes.append(f"ISO.{key}: isolated result missing, skipped")
                continue
            got = src.get(key, "<missing>")
        if got not in allowed:
            failures.append(f"{scope}.{key}: expected {'|'.join(allowed)}, got {got}")

    # Explain ANON_BSS_EXEC outcomes in terms of ground truth.
    app_says = main_r.get("ANON_BSS_EXEC")
    if truth["exec_anon_bss"] and app_says == "CLEAN":
        failures.append("DETECTOR MISS: exec [anon:.bss] present in /proc/<pid>/maps but app reported CLEAN")
    if not truth["exec_anon_bss"] and app_says == "DETECTED":
        failures.append("FALSE POSITIVE: app reported ANON_BSS_EXEC but root-read maps has no exec [anon:.bss]")
    jit_says = main_r.get("FAKE_JIT_MAPPING")
    if truth["private_jit_exec"] and jit_says == "CLEAN":
        failures.append("DETECTOR MISS: private exec jit-cache mapping present but app reported FAKE_JIT_MAPPING CLEAN")
    if not truth["private_jit_exec"] and jit_says == "DETECTED":
        failures.append("FALSE POSITIVE: app reported FAKE_JIT_MAPPING but root-read maps has no private exec jit-cache")
    if leg == "shamiko" and not truth["exec_anon_bss"] and not setup_errors:
        notes.append("Shamiko left no exec [anon:.bss] here. Expected with Magisk >= 31: module libs are "
                     "memfd-backed (jit-cache), so there is no /data/adb file mapping for Shamiko to remap.")
    if not truth["maps_captured"]:
        notes.append("app maps not captured (process not running at collection time?)")

    summary = {
        "leg": leg,
        "passed": not failures,
        "failures": failures,
        "notes": notes,
        "truth": truth_txt,
        "truth_isolated": {k: ("yes" if v else "no") for k, v in truth_iso.items()},
        "main": {k: main_r.get(k) for k in REPORT_KEYS},
        "iso": {k: iso_r.get(k) for k in REPORT_KEYS},
        "evidence": evidence[:10],
    }
    with open(os.path.join(out_dir, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2)

    md = [f"### Leg `{leg}`: {'✅ pass' if not failures else '❌ fail'}", "",
          "| key | main | isolated |", "| --- | --- | --- |"]
    for k in REPORT_KEYS:
        md.append(f"| {k} | {main_r.get(k, '–')} | {iso_r.get(k, '–')} |")
    md += ["", "Ground truth (root-read maps): " +
           ", ".join(f"`{k}={v}`" for k, v in truth_txt.items()), ""]
    for f in failures:
        md.append(f"- ❌ {f}")
    for n in notes:
        md.append(f"- ℹ️ {n}")
    if evidence:
        md += ["", "```", *evidence[:5], "```"]
    text = "\n".join(md) + "\n"
    print(text)
    step = os.environ.get("GITHUB_STEP_SUMMARY")
    if step:
        with open(step, "a") as fh:
            fh.write(text)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
