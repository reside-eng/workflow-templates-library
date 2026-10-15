#!/usr/bin/env python3
"""Deterministic security scans for CI (PLAT-12030).

One command per step of the security-scan composite action:
  context    resolve base/head, changed files and which scanners run
  secrets    gitleaks on the lines the PR adds
  deps       Trivy on the lockfile, head versus base
  sast       Semgrep, diff-aware against the base commit
  image      Trivy on a built image (OS packages only)
  workflows  zizmor on GitHub workflow files changed by the PR
  report     job summary, annotations, results bundle, exit code
  comment    upsert or clear the PR comment

Every command reads and writes JSON under $SCAN_WORKDIR. Standard library only
(runs on Python 3.10+ as shipped on GitHub-hosted and self-hosted runners).
"""
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

MODES = ("advisory", "blocking")
SOURCE_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
MANIFESTS = ("yarn.lock", "package.json", ".yarnrc.yml")
ALLOWLIST_FILES = (".gitleaks.toml", ".gitleaksignore", ".trivyignore.yaml", ".semgrepignore")
TEST_PATH_RE = re.compile(
    r"(^|/)(__tests__|__mocks__|__fixtures__|fixtures|mocks|cypress|e2e|test|tests|security-eval)(/|$)"
    r"|\.(test|spec|stories)\.[cm]?[jt]sx?$"
)
DOCKERFILE_RE = re.compile(r"(^|/)Dockerfile[^/]*$")
WORKFLOW_RE = re.compile(r"^\.github/(workflows/[^/]+\.ya?ml|actions/.+/action\.ya?ml)$")
SEMGREP_RULESETS = ("p/nodejs", "p/typescript", "p/react", "p/nextjs", "p/owasp-top-ten")
SEMGREP_EXCLUDES = (
    "node_modules", "dist", "build", ".next", "coverage", ".github", ".yarn",
    "__tests__", "__mocks__", "__fixtures__", "fixtures", "mocks", "cypress", "security-eval",
    "*.test.ts", "*.test.tsx", "*.test.js", "*.test.jsx", "*.spec.ts", "*.spec.tsx", "*.spec.js", "*.spec.jsx",
    "*.stories.tsx", "Dockerfile*", "*.md",
)
TRIVY_IGNORE_MAX_DAYS = 90
SCANNER_ORDER = ("secrets", "deps", "sast", "image", "workflows")
SCANNER_TITLES = {
    "secrets": "Secrets (gitleaks)",
    "deps": "Dependencies (Trivy, lockfile)",
    "sast": "SAST (Semgrep)",
    "image": "Image (Trivy, OS packages)",
    "workflows": "Workflows (zizmor)",
}


# ----------------------------------------------------------------------------- helpers
def env(name, default=""):
    return os.environ.get(name, default)


def workdir():
    d = Path(env("SCAN_WORKDIR") or (Path(env("RUNNER_TEMP", "/tmp")) / "security-scan"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def workspace():
    return Path(env("GITHUB_WORKSPACE") or os.getcwd())


def action_path():
    return Path(env("SCAN_ACTION_PATH") or Path(__file__).resolve().parent)


def mode_of(scanner):
    m = env("SCAN_MODE_" + scanner.upper(), "off").strip().lower()
    return m if m in MODES else "off"


def run(cmd, cwd=None, check=False, input_text=None, env_extra=None):
    e = dict(os.environ)
    if env_extra:
        e.update(env_extra)
    return subprocess.run(cmd, cwd=cwd or workspace(), text=True, capture_output=True,
                          input=input_text, check=check, env=e)


def git(*args, cwd=None):
    return run(["git", *args], cwd=cwd)


def log(msg):
    print(msg, flush=True)


def group(title):
    log(f"::group::{title}")


def endgroup():
    log("::endgroup::")


def load_json(path, default=None):
    if not path:
        return default
    p = Path(path)
    if not p.is_file():
        return default
    with p.open() as f:
        return json.load(f)


def save_json(path, data):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def set_output(name, value):
    out = env("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as f:
            f.write(f"{name}={value}\n")
    log(f"output {name}={value}")


def set_env(name, value):
    out = env("GITHUB_ENV")
    if out:
        with open(out, "a") as f:
            f.write(f"{name}={value}\n")


def read_event():
    return load_json(env("GITHUB_EVENT_PATH"), {}) or {}


def result(scanner, status, mode=None, **extra):
    data = {"scanner": scanner, "status": status, "mode": mode or mode_of(scanner), "findings": [],
            "gate_applies": True, "notes": []}
    data.update(extra)
    save_json(workdir() / f"{scanner}.json", data)
    return data


def comment_marker():
    """One PR comment per scan profile (code, image per app, workflows)."""
    tag = env("SCAN_PROFILE", "code")
    suffix = env("SCAN_SUFFIX", "")
    return f"<!-- security-scan:{tag}{':' + suffix if suffix else ''} -->"


def md_escape(text):
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def file_link(path, line=None):
    repo = env("GITHUB_REPOSITORY")
    sha = env("GITHUB_SHA")
    server = env("GITHUB_SERVER_URL", "https://github.com")
    loc = f"{path}:{line}" if line else path
    if not repo or not sha:
        return f"`{loc}`"
    anchor = f"#L{line}" if line else ""
    return f"[`{loc}`]({server}/{repo}/blob/{sha}/{path}{anchor})"


# ----------------------------------------------------------------------------- context
def parse_added_lines(base, head, files):
    """Map path -> set of line numbers added or modified by base..head (new side)."""
    added = {}
    if not files:
        return added
    r = git("diff", "--unified=0", "--no-color", "--no-ext-diff", "-M", base, head, "--", *files)
    current = None
    for line in r.stdout.splitlines():
        if line.startswith("+++ "):
            target = line[4:]
            current = target[2:] if target.startswith("b/") else None
            if current is not None:
                added.setdefault(current, set())
        elif line.startswith("@@ ") and current is not None:
            m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
            if not m:
                continue
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) is not None else 1
            for n in range(start, start + count):
                added[current].add(n)
    return added


def cmd_context():
    ws = workspace()
    head = env("GITHUB_SHA") or git("rev-parse", "HEAD").stdout.strip()
    base = env("SCAN_BASE_SHA").strip()
    if not base:
        r = git("rev-parse", "--verify", "--quiet", "HEAD^1")
        if r.returncode == 0:
            base = r.stdout.strip()
    event = read_event()
    pr = event.get("pull_request") or {}
    if not base and pr.get("base", {}).get("sha"):
        candidate = pr["base"]["sha"]
        git("fetch", "--no-tags", "--depth=1", "origin", candidate)
        if git("cat-file", "-e", f"{candidate}^{{commit}}").returncode == 0:
            base = candidate
    head_repo = (pr.get("head") or {}).get("repo") or {}
    is_fork = bool(head_repo) and head_repo.get("full_name") != env("GITHUB_REPOSITORY")
    pr_number = env("SCAN_PR_NUMBER") or str(pr.get("number") or "")

    changed = {}
    if base:
        r = git("diff", "--name-status", "-M", base, head)
        for line in r.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            status = parts[0]
            path = parts[-1]
            if status.startswith("D"):
                continue
            changed[path] = status[0]
    files = sorted(changed)
    added_lines = parse_added_lines(base, head, files) if base else {}

    def basename(p):
        return p.rsplit("/", 1)[-1]

    ctx = {
        "head": head,
        "base": base,
        "event": env("GITHUB_EVENT_NAME"),
        "pr_number": pr_number,
        "is_fork": is_fork,
        "changed": changed,
        "added_lines": {k: sorted(v) for k, v in added_lines.items()},
        "dockerfile_changed": any(DOCKERFILE_RE.search(p) for p in files),
        "manifests_changed": any(basename(p) in MANIFESTS and "node_modules" not in p.split("/") for p in files),
        "source_changed": any(p.endswith(SOURCE_EXTS) and not TEST_PATH_RE.search(p) for p in files),
        "workflows_changed": any(WORKFLOW_RE.match(p) for p in files),
        "allowlist_changed": any(basename(p) in ALLOWLIST_FILES for p in files),
        "modes": {s: mode_of(s) for s in ("secrets", "deps", "sast", "image", "workflows")},
    }
    ctx["run_secrets"] = ctx["modes"]["secrets"] != "off" and bool(base) and bool(files)
    ctx["run_deps"] = ctx["modes"]["deps"] != "off" and bool(base) and ctx["manifests_changed"]
    ctx["run_sast"] = ctx["modes"]["sast"] != "off" and bool(base) and ctx["source_changed"]
    ctx["run_workflows"] = ctx["modes"]["workflows"] != "off" and bool(base) and ctx["workflows_changed"]
    save_json(workdir() / "context.json", ctx)

    log(f"head={head} base={base or '(none)'} changed_files={len(files)} fork={is_fork}")
    for key in ("run_secrets", "run_deps", "run_sast", "run_workflows", "dockerfile_changed", "allowlist_changed"):
        set_output(key, "true" if ctx[key] else "false")
    set_output("base_sha", base)
    set_output("changed_files", str(len(files)))
    if not base:
        log("::warning title=security-scan::No base commit found; diff-aware scanners are skipped")


def load_ctx():
    ctx = load_json(workdir() / "context.json")
    if ctx is None:
        sys.exit("context.json missing: run `security-scan.py context` first")
    return ctx


# ----------------------------------------------------------------------------- secrets
def build_gitleaks_config(ws):
    """Repo .gitleaks.toml (must extend the defaults) + org allowlists, or defaults + org allowlists."""
    org = (action_path() / "gitleaks-allowlists.toml").read_text()
    repo_cfg = ws / ".gitleaks.toml"
    if repo_cfg.exists():
        text = repo_cfg.read_text()
        if re.search(r"^\s*path\s*=", text, re.M) and "[extend]" in text:
            return None, "`.gitleaks.toml` must use `[extend] useDefault = true`, not `extend.path`"
        if "[extend]" not in text:
            text = "[extend]\nuseDefault = true\n\n" + text
        effective = text.rstrip() + "\n\n# --- org allowlists (workflow-templates security-scan) ---\n" + org
    else:
        effective = 'title = "security-scan"\n\n[extend]\nuseDefault = true\n\n' + org
    path = workdir() / "gitleaks.toml"
    path.write_text(effective)
    return path, None


def to_sarif(tool_name, version, rules, results):
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool_name, "version": version,
                                "rules": [{"id": r, "name": r} for r in sorted(rules)]}},
            "results": results,
        }],
    }


def cmd_secrets():
    ctx = load_ctx()
    mode = ctx["modes"]["secrets"]
    if not ctx["run_secrets"]:
        reason = "no changed files" if ctx["base"] else "no base commit"
        result("secrets", "skipped", mode, reason=reason)
        return
    ws = workspace()
    cfg, err = build_gitleaks_config(ws)
    if err:
        result("secrets", "error", mode, error=err)
        return
    gitleaks = env("GITLEAKS_BIN", "gitleaks")
    raw = workdir() / "gitleaks-raw.json"
    cmd = [gitleaks, "dir", ".", "--config", str(cfg), "--no-banner", "--redact", "--exit-code", "0",
           "--max-target-megabytes", "10", "--report-format", "json", "--report-path", str(raw)]
    group("gitleaks")
    r = run(cmd)
    log(r.stderr[-4000:])
    endgroup()
    if r.returncode != 0:
        result("secrets", "error", mode, error=f"gitleaks exited {r.returncode}: {r.stderr[-800:]}")
        return
    findings_raw = load_json(raw, []) or []
    added = {k: set(v) for k, v in ctx["added_lines"].items()}
    findings = []
    for f in findings_raw:
        path = f.get("File", "")
        lines = added.get(path)
        if not lines:
            continue
        start, end = int(f.get("StartLine", 0)), int(f.get("EndLine", 0))
        if not any(n in lines for n in range(start, end + 1)):
            continue
        findings.append({
            "rule": f.get("RuleID"), "file": path, "line": start, "end_line": end,
            "description": f.get("Description"), "fingerprint": f.get("Fingerprint"),
            "entropy": round(float(f.get("Entropy") or 0), 2), "gate": True,
        })
    version = run([gitleaks, "version"]).stdout.strip()
    sarif = to_sarif("gitleaks", version, {f["rule"] for f in findings}, [{
        "ruleId": f["rule"], "level": "error",
        "message": {"text": f"{f['description']} (fingerprint {f['fingerprint']})"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]},
                                            "region": {"startLine": f["line"]}}}],
    } for f in findings])
    save_json(workdir() / "artifact" / "secrets.sarif", sarif)
    status = "findings" if findings else "clean"
    result("secrets", status, mode, findings=findings, scanned_files=len(ctx["changed"]),
           tree_findings=len(findings_raw), tool_version=version)


# ----------------------------------------------------------------------------- deps
def manifest_paths(sha):
    r = git("ls-tree", "-r", "--name-only", sha)
    paths = []
    for p in r.stdout.splitlines():
        parts = p.split("/")
        if parts[-1] in MANIFESTS and "node_modules" not in parts:
            paths.append(p)
    return paths


def export_tree(sha, paths, dest):
    dest.mkdir(parents=True, exist_ok=True)
    if not paths:
        return
    r = subprocess.run(["git", "archive", "--format=tar", sha, "--", *paths], cwd=workspace(), capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(f"git archive {sha[:8]} failed: {r.stderr.decode()[-400:]}")
    subprocess.run(["tar", "-x", "-C", str(dest)], input=r.stdout, check=True)


def validate_trivyignore(path):
    """Entries under `vulnerabilities` need an id, a statement and an expired_at within 90 days."""
    errors, notes = [], []
    yq = shutil.which("yq")
    if not yq:
        errors.append("`.trivyignore.yaml` present but yq is unavailable on this runner: entries cannot be validated")
        return errors, notes
    r = subprocess.run([yq, "-o=json", "-I=0", ".", str(path)], text=True, capture_output=True)
    if r.returncode != 0:
        errors.append(f"`.trivyignore.yaml` is not valid YAML: {r.stderr.strip()[:200]}")
        return errors, notes
    try:
        data = json.loads(r.stdout or "{}") or {}
    except json.JSONDecodeError as e:
        errors.append(f"`.trivyignore.yaml` could not be parsed: {e}")
        return errors, notes
    today = dt.date.today()
    for entry in data.get("vulnerabilities") or []:
        if not isinstance(entry, dict):
            errors.append(f"`.trivyignore.yaml` entry `{entry}` must be a mapping with id, statement and expired_at")
            continue
        vid = entry.get("id", "?")
        if not str(entry.get("statement") or "").strip():
            errors.append(f"`.trivyignore.yaml` entry {vid} has no `statement`")
        exp = entry.get("expired_at")
        if not exp:
            errors.append(f"`.trivyignore.yaml` entry {vid} has no `expired_at` (max {TRIVY_IGNORE_MAX_DAYS} days ahead)")
            continue
        try:
            exp_date = dt.date.fromisoformat(str(exp)[:10])
        except ValueError:
            errors.append(f"`.trivyignore.yaml` entry {vid} has an invalid `expired_at` ({exp}); use YYYY-MM-DD")
            continue
        if exp_date < today:
            notes.append(f"`.trivyignore.yaml` entry {vid} expired on {exp_date}: it no longer suppresses anything")
        elif (exp_date - today).days > TRIVY_IGNORE_MAX_DAYS:
            errors.append(f"`.trivyignore.yaml` entry {vid} expires on {exp_date}, more than "
                          f"{TRIVY_IGNORE_MAX_DAYS} days ahead")
    return errors, notes


def trivy_vulns(report):
    out = {}
    for res in (report or {}).get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            key = (v.get("VulnerabilityID"), v.get("PkgName"))
            out[key] = {
                "id": v.get("VulnerabilityID"), "pkg": v.get("PkgName"), "installed": v.get("InstalledVersion"),
                "fixed": v.get("FixedVersion") or "", "severity": v.get("Severity"), "title": v.get("Title") or "",
                "url": v.get("PrimaryURL") or "", "target": res.get("Target"),
            }
    return out


def classify_deps(head_v, base_v):
    """Head findings with new (absent from base), fixable and gate (new and fixable) flags."""
    findings = []
    for key in sorted(head_v, key=lambda k: (k[1], k[0])):
        v = dict(head_v[key])
        v["new"] = key not in base_v
        v["fixable"] = bool(v["fixed"])
        v["gate"] = v["new"] and v["fixable"]
        findings.append(v)
    return findings


def trivy_cmd(*args):
    return [env("TRIVY_BIN", "trivy"), *args, "--quiet", "--exit-code", "0", "--no-progress", "--format", "json"]


def cmd_deps():
    ctx = load_ctx()
    mode = ctx["modes"]["deps"]
    if not ctx["run_deps"]:
        reason = "lockfile and manifests unchanged" if ctx["base"] else "no base commit"
        result("deps", "skipped", mode, reason=reason)
        return
    ws = workspace()
    head_paths = manifest_paths(ctx["head"])
    if not any(p.rsplit("/", 1)[-1] == "yarn.lock" for p in head_paths):
        result("deps", "skipped", mode, reason="no yarn.lock in the repository")
        return
    d = workdir() / "deps"
    try:
        export_tree(ctx["head"], head_paths, d / "head")
        export_tree(ctx["base"], manifest_paths(ctx["base"]), d / "base")
    except RuntimeError as e:
        result("deps", "error", mode, error=str(e))
        return
    ignorefile = ws / ".trivyignore.yaml"
    policy_errors, notes = ([], [])
    extra = []
    if ignorefile.exists():
        policy_errors, notes = validate_trivyignore(ignorefile)
        extra = ["--ignorefile", str(ignorefile)]
    base_cmd = ["fs", "--scanners", "vuln", "--pkg-types", "library", "--severity", "HIGH,CRITICAL", *extra]
    reports = {}
    group("trivy fs")
    for side in ("head", "base"):
        out = d / f"{side}.json"
        r = run(trivy_cmd(*base_cmd, "--output", str(out), str(d / side)))
        log(r.stderr[-3000:])
        if r.returncode != 0:
            endgroup()
            result("deps", "error", mode, error=f"trivy fs ({side}) exited {r.returncode}: {r.stderr[-800:]}")
            return
        reports[side] = trivy_vulns(load_json(out, {}))
    endgroup()
    findings = classify_deps(reports["head"], reports["base"])
    conv = run([env("TRIVY_BIN", "trivy"), "convert", "--format", "sarif", "--output",
                str(workdir() / "artifact" / "deps.sarif"), str(d / "head.json")])
    if conv.returncode != 0:
        notes.append("SARIF conversion failed: " + conv.stderr.strip()[-200:])
    if policy_errors:
        status = "error"
    elif any(f["new"] for f in findings):
        status = "findings"
    else:
        status = "clean"
    version = run([env("TRIVY_BIN", "trivy"), "--version"]).stdout.split("\n")[0].strip()
    result("deps", status, mode, findings=findings, policy_errors=policy_errors, notes=notes,
           existing=sum(1 for f in findings if not f["new"]), tool_version=version,
           error="; ".join(policy_errors) if policy_errors else None)


# ----------------------------------------------------------------------------- sast
def semgrep_findings(report):
    findings = []
    for res in report.get("results") or []:
        path = res.get("path", "")
        path = path[5:] if path.startswith("/src/") else path
        extra = res.get("extra") or {}
        sev = extra.get("severity", "WARNING")
        meta = extra.get("metadata") or {}
        findings.append({
            "rule": res.get("check_id"), "severity": sev, "file": path, "line": (res.get("start") or {}).get("line"),
            "message": (extra.get("message") or "").strip(),
            "url": meta.get("shortlink") or meta.get("source") or "",
            "confidence": meta.get("confidence", ""), "gate": sev == "ERROR",
        })
    return findings


def sast_debug(ws, image, uid, gid, ctx):
    """Extra probes when SCAN_DEBUG=true: registry reachability, a local rule, the registry without baseline."""
    files = [p for p in ctx["changed"] if p.endswith(SOURCE_EXTS) and not TEST_PATH_RE.search(p)][:5]
    base = ["docker", "run", "--rm", "--user", f"{uid}:{gid}", "-e", "HOME=/tmp", "-v", f"{ws}:/src",
            "-v", f"{action_path()}:/action:ro", "-w", "/src"]
    group("sast debug")
    r = run(base + ["--entrypoint", "python3", image, "-c",
                    "import urllib.request,sys\n"
                    "try:\n  r=urllib.request.urlopen('https://semgrep.dev/c/p/nodejs',timeout=20); b=r.read(); print('registry', r.status, len(b), 'bytes')\n"
                    "except Exception as e: print('registry error', repr(e)[:300])"])
    log((r.stdout + r.stderr)[-600:])
    r = run(base + ["--entrypoint", "/bin/sh", image, "-c",
                    f"id; git --version; git -C /src log --oneline -3; git -C /src merge-base {ctx['base']} HEAD; "
                    "git -C /src status --porcelain | head -5; git -C /src rev-parse --is-shallow-repository"])
    log("git view: " + (r.stdout + r.stderr)[-800:])
    variants = (
        ("local-rule", base, ["--config", "/action/tests/debug-rule.yml"]),
        ("registry", base, ["--config", "p/nodejs"]),
        ("registry+baseline", base, ["--config", "p/nodejs", "--baseline-commit", ctx["base"], "--verbose"]),
        ("registry+baseline as root", [a for a in base if a not in (f"{uid}:{gid}", "--user")],
         ["--config", "p/nodejs", "--baseline-commit", ctx["base"], "--verbose"]),
    )
    for label, prefix, extra in variants:
        r = run(prefix + [image, "semgrep", "scan", *extra, "--metrics=off", "--json", "--disable-version-check",
                          *[f"/src/{p}" for p in files]])
        try:
            rep = json.loads(r.stdout or "{}")
            log(f"{label}: exit={r.returncode} results={len(rep.get('results') or [])} errors={len(rep.get('errors') or [])} "
                f"scanned={len((rep.get('paths') or {}).get('scanned') or [])} "
                f"first_error={json.dumps((rep.get('errors') or [{}])[0])[:300]}")
        except json.JSONDecodeError:
            log(f"{label}: exit={r.returncode} non-json output: {(r.stderr or r.stdout)[-500:]}")
        if "baseline" in label:
            lines = [l for l in r.stderr.splitlines() if re.search(r"(?i)baseline|stash|checkout|merge.base|worktree|fatal|error", l)]
            log(f"{label} stderr (baseline-related): " + " | ".join(lines)[-1500:])
    endgroup()


def cmd_sast():
    ctx = load_ctx()
    mode = ctx["modes"]["sast"]
    if not ctx["run_sast"]:
        reason = "no application source changed" if ctx["base"] else "no base commit"
        result("sast", "skipped", mode, reason=reason)
        return
    ws = workspace()
    out_dir = workdir() / "sast"
    out_dir.mkdir(parents=True, exist_ok=True)
    rules_file = action_path() / "semgrep-exclude-rules.txt"
    excluded_rules = [l.strip() for l in rules_file.read_text().splitlines()
                      if l.strip() and not l.startswith("#")] if rules_file.exists() else []
    image = env("SEMGREP_IMAGE", "semgrep/semgrep:latest")
    uid, gid = os.getuid(), os.getgid()
    cmd = ["docker", "run", "--rm", "--user", f"{uid}:{gid}", "-e", "HOME=/tmp",
           "-e", "GIT_CONFIG_COUNT=1", "-e", "GIT_CONFIG_KEY_0=safe.directory", "-e", "GIT_CONFIG_VALUE_0=*",
           "-v", f"{ws}:/src", "-v", f"{out_dir}:/out", "-w", "/src", image, "semgrep", "scan"]
    for rs in SEMGREP_RULESETS:
        cmd += ["--config", rs]
    cmd += ["--metrics=off", "--baseline-commit", ctx["base"], "--severity", "ERROR", "--severity", "WARNING",
            "--json-output=/out/semgrep.json", "--sarif-output=/out/semgrep.sarif",
            "--quiet", "--timeout", "30", "--timeout-threshold", "3", "--disable-version-check"]
    for pat in SEMGREP_EXCLUDES:
        cmd += ["--exclude", pat]
    for rule in excluded_rules:
        cmd += ["--exclude-rule", rule]
    # Relative target: Semgrep's baseline scan may chdir into a temporary worktree of the base commit
    # (when the working tree is not clean, e.g. gha-creds-*.json written by the Cloud auth step);
    # an absolute target would then point back at the head tree and cancel every finding.
    cmd.append(".")
    group("semgrep")
    log(" ".join(cmd))
    r = run(cmd)
    log(r.stdout[-2000:])
    log(r.stderr[-3000:])
    endgroup()
    report = load_json(out_dir / "semgrep.json")
    if r.returncode not in (0, 1) or report is None:
        result("sast", "error", mode, error=f"semgrep exited {r.returncode}: {(r.stderr or r.stdout)[-800:]}")
        return
    paths = report.get("paths") or {}
    scanned = paths.get("scanned") or []
    log(f"semgrep exit={r.returncode} scanned={len(scanned)} skipped={len(paths.get('skipped') or [])} "
        f"errors={len(report.get('errors') or [])} first={scanned[:5]}")
    if not scanned:
        probe = run(["docker", "run", "--rm", "--user", f"{uid}:{gid}", "-e", "HOME=/tmp", "-v", f"{ws}:/src", "-w", "/src",
                     "--entrypoint", "/bin/sh", image, "-c", "ls -a /src | head -20; git -C /src rev-parse HEAD 2>&1 | head -2"])
        log("::warning title=security-scan/sast::semgrep scanned no files; container view of the workspace:\n"
            + (probe.stdout + probe.stderr)[-1500:])
    if env("SCAN_DEBUG") == "true":
        sast_debug(ws, image, uid, gid, ctx)
    findings = semgrep_findings(report)
    errors = report.get("errors") or []
    if (out_dir / "semgrep.sarif").exists():
        shutil.copy(out_dir / "semgrep.sarif", workdir() / "artifact" / "sast.sarif")
    version = (report.get("version") or "").strip()
    notes = [f"{len(errors)} semgrep parse/timeout errors (non-fatal)"] if errors else []
    result("sast", "findings" if findings else "clean", mode, findings=findings, notes=notes,
           tool_version=version, rulesets=list(SEMGREP_RULESETS))


# ----------------------------------------------------------------------------- image
def cmd_image():
    ctx = load_ctx()
    mode = ctx["modes"]["image"]
    image = env("SCAN_IMAGE").strip()
    if mode == "off":
        result("image", "skipped", mode, reason="mode off")
        return
    if not image:
        result("image", "error", mode, error="SCAN_IMAGE is empty")
        return
    ws = workspace()
    ignorefile = ws / ".trivyignore.yaml"
    extra = ["--ignorefile", str(ignorefile)] if ignorefile.exists() else []
    out = workdir() / "image.json"
    cmd = trivy_cmd("image", "--scanners", "vuln", "--pkg-types", "os", "--ignore-unfixed",
                    "--severity", "HIGH,CRITICAL", "--image-src", "remote", *extra, "--output", str(out), image)
    group("trivy image")
    r = run(cmd)
    log(r.stderr[-3000:])
    endgroup()
    if r.returncode != 0:
        result("image", "error", mode, image=image, error=f"trivy image exited {r.returncode}: {r.stderr[-800:]}")
        return
    report = load_json(out, {})
    findings = []
    for v in trivy_vulns(report).values():
        v["gate"] = True
        findings.append(v)
    os_info = ((report or {}).get("Metadata") or {}).get("OS") or {}
    run([env("TRIVY_BIN", "trivy"), "convert", "--format", "sarif", "--output",
         str(workdir() / "artifact" / "image.sarif"), str(out)])
    gate_applies = bool(ctx.get("dockerfile_changed"))
    notes = [] if gate_applies else ["No Dockerfile changed in this PR: findings reported for information only"]
    version = run([env("TRIVY_BIN", "trivy"), "--version"]).stdout.split("\n")[0].strip()
    result("image", "findings" if findings else "clean", mode, image=image, findings=findings,
           gate_applies=gate_applies, notes=notes, os=f"{os_info.get('Family', '')} {os_info.get('Name', '')}".strip(),
           tool_version=version)


# ----------------------------------------------------------------------------- workflows
def zizmor_findings(raw, changed):
    """zizmor JSON findings restricted to the changed files; High/Critical gate."""
    findings = []
    for f in raw:
        locs = f.get("locations") or []
        loc = locs[0] if locs else {}
        key = ((loc.get("symbolic") or {}).get("key") or {}).get("Local") or {}
        path = key.get("verbatim_path") or key.get("path") or ""
        path = path[5:] if path.startswith("/src/") else path
        if path not in changed:
            continue
        line = (((loc.get("concrete") or {}).get("location") or {}).get("start_point") or {}).get("row")
        det = f.get("determinations") or {}
        findings.append({
            "rule": f.get("ident"), "severity": det.get("severity"), "confidence": det.get("confidence"),
            "file": path, "line": (line + 1) if isinstance(line, int) else None,
            "message": f.get("desc", ""), "url": f.get("url", ""),
            "gate": det.get("severity") in ("High", "Critical"),
        })
    return findings


def cmd_workflows():
    ctx = load_ctx()
    mode = ctx["modes"]["workflows"]
    if not ctx["run_workflows"]:
        reason = "no workflow or action files changed" if ctx["base"] else "no base commit"
        result("workflows", "skipped", mode, reason=reason)
        return
    ws = workspace()
    image = env("ZIZMOR_IMAGE", "ghcr.io/zizmorcore/zizmor:latest")
    cfg = ws / ".github" / "zizmor.yml"
    cmd = ["docker", "run", "--rm", "-v", f"{ws}:/src:ro", "-w", "/src", image,
           "--offline", "--format", "json", "--min-severity", "medium", "--min-confidence", "medium"]
    if cfg.exists():
        cmd += ["--config", "/src/.github/zizmor.yml"]
    cmd.append("/src")
    group("zizmor")
    r = run(cmd)
    log(r.stderr[-3000:])
    endgroup()
    try:
        raw = json.loads(r.stdout or "[]")
    except json.JSONDecodeError:
        result("workflows", "error", mode, error=f"zizmor exited {r.returncode}: {(r.stderr or r.stdout)[-800:]}")
        return
    findings = zizmor_findings(raw, set(ctx["changed"]))
    result("workflows", "findings" if findings else "clean", mode, findings=findings,
           total_in_repo=len(raw), tool_version=image.split("@")[0].rsplit(":", 1)[-1])


# ----------------------------------------------------------------------------- report
def allowlist_hint(scanner):
    return {
        "secrets": "Add the fingerprint to `.gitleaksignore` for a test fixture, or a path allowlist to "
                   "`.gitleaks.toml` (must keep `[extend] useDefault = true`). Rotate anything real first.",
        "deps": "Bump to the fixed version, or add an entry to `.trivyignore.yaml` with `id`, `statement` "
                f"and `expired_at` (at most {TRIVY_IGNORE_MAX_DAYS} days ahead).",
        "sast": "Fix the pattern, or add `// nosemgrep: <rule-id> -- reason` on the line.",
        "image": "Bump the base image in the Dockerfile; OS packages without a fix are already hidden.",
        "workflows": "Fix the workflow, or ignore a known case in `.github/zizmor.yml`.",
    }[scanner]


def scanner_table(scanner, r):
    f = r.get("findings") or []
    if scanner == "secrets":
        rows = ["| Rule | Location | Fingerprint |", "| --- | --- | --- |"]
        rows += [f"| `{x['rule']}` | {file_link(x['file'], x['line'])} | `{x['fingerprint']}` |" for x in f]
    elif scanner == "deps":
        rows = ["| Package | Installed | Fixed | Severity | Advisory | Status |", "| --- | --- | --- | --- | --- | --- |"]
        for x in sorted((v for v in f if v["new"]), key=lambda v: v["pkg"]):
            status = "new" if x["fixable"] else "new, no fix yet"
            adv = f"[{x['id']}]({x['url']})" if x["url"] else x["id"]
            rows.append(f"| `{x['pkg']}` | {x['installed']} | {x['fixed'] or '-'} | {x['severity']} | {adv} | {status} |")
        existing = sorted({x["pkg"] for x in f if not x["new"]})
        if existing:
            rows.append("")
            rows.append(f"{sum(1 for x in f if not x['new'])} pre-existing High/Critical findings on the base lockfile are not "
                        f"gated here (Dependabot alerts, weekly digest): {', '.join(f'`{p}`' for p in existing)}.")
    elif scanner == "image":
        rows = ["| Package | Installed | Fixed | Severity | Advisory |", "| --- | --- | --- | --- | --- |"]
        for x in f:
            adv = f"[{x['id']}]({x['url']})" if x["url"] else x["id"]
            rows.append(f"| `{x['pkg']}` | {x['installed']} | {x['fixed'] or '-'} | {x['severity']} | {adv} |")
    else:
        rows = ["| Severity | Rule | Location | Message |", "| --- | --- | --- | --- |"]
        for x in f:
            rule = x["rule"].rsplit(".", 1)[-1] if x["rule"] else ""
            rule = f"[`{rule}`]({x['url']})" if x.get("url") else f"`{rule}`"
            rows.append(f"| {x['severity']} | {rule} | {file_link(x['file'], x['line'])} | {md_escape(x['message'])[:200]} |")
    return "\n".join(rows)


def gate_count(r):
    if r.get("status") != "findings" or not r.get("gate_applies", True):
        return 0
    return sum(1 for x in r.get("findings") or [] if x.get("gate"))


def describe(scanner, r):
    status = r.get("status")
    if status == "skipped":
        return f"skipped ({r.get('reason', '')})"
    if status == "error":
        return "error"
    if status == "clean":
        return "clean"
    n = len(r.get("findings") or [])
    g = gate_count(r)
    if scanner == "deps":
        new = sum(1 for x in r["findings"] if x["new"])
        gate_word = "gating" if r.get("mode") == "blocking" else "would gate"
        return f"{new} new ({g} {gate_word}), {r.get('existing', 0)} pre-existing"
    if scanner == "sast":
        err = sum(1 for x in r["findings"] if x["severity"] == "ERROR")
        return f"{n} new ({err} ERROR, {n - err} WARNING)"
    if scanner == "image" and not r.get("gate_applies", True):
        return f"{n} fixable OS findings (not gating, Dockerfile unchanged)"
    return f"{n} finding{'s' if n != 1 else ''}"


def ordered(results):
    return [(s, results[s]) for s in SCANNER_ORDER if s in results]


def classify_results(results, title_suffix=""):
    """Blocking failures and advisory warnings for a set of scanner results."""
    failures, warnings_out = [], []
    for s, r in ordered(results):
        title = SCANNER_TITLES[s] + title_suffix
        mode, status = r.get("mode"), r.get("status")
        g = gate_count(r)
        if status == "error":
            (failures if mode == "blocking" else warnings_out).append(f"{title}: {r.get('error', 'scanner error')}")
        elif g and mode == "blocking":
            failures.append(f"{title}: {g} finding(s) introduced by this PR")
        elif r.get("findings") and status == "findings":
            warnings_out.append(f"{title}: {describe(s, r)}")
    return failures, warnings_out


def finding_sections(results, title_suffix=""):
    """Markdown sections (tables + allow-list hint) for every scanner with findings or an error."""
    lines = []
    for s, r in ordered(results):
        title = SCANNER_TITLES[s] + title_suffix
        if r.get("status") == "error":
            lines += [f"### {title}: error", "", md_escape(r.get("error", ""))[:800], ""]
        if r.get("findings") and (s != "deps" or any(x["new"] for x in r["findings"])):
            lines += [f"### {title}", "", scanner_table(s, r), "", allowlist_hint(s), ""]
        for n in r.get("notes") or []:
            lines.append(f"- {n}")
    return lines


def cmd_report():
    ctx = load_ctx()
    scanners = [s for s in ("secrets", "deps", "sast", "image", "workflows") if (workdir() / f"{s}.json").exists()]
    results = {s: load_json(workdir() / f"{s}.json") for s in scanners}
    failures, warnings_out = classify_results(results)
    lines = []
    for s in scanners:
        r = results[s]
        mode = r.get("mode")
        for x in r.get("findings") or []:
            if not x.get("file"):
                continue
            level = "error" if (mode == "blocking" and x.get("gate") and r.get("gate_applies", True)) else "warning"
            title = f"security-scan/{s}"
            text = x.get("description") or x.get("message") or x.get("title") or x.get("rule") or ""
            loc = f"file={x['file']}" + (f",line={x['line']}" if x.get("line") else "")
            log(f"::{level} {loc},title={title}::{md_escape(x.get('rule', ''))}: {md_escape(text)[:300]}")
    conclusion = "fail" if failures else ("advisory" if warnings_out else "pass")

    profile = env("SCAN_PROFILE", "code")
    suffix = env("SCAN_SUFFIX", "")
    label = {"code": "Security scan", "image": "Image scan", "workflows": "Workflow audit"}.get(profile, "Security scan")
    head = f"## {label}{' ' + suffix if suffix else ''}: {conclusion}"
    if ctx.get("event") == "merge_group":
        head += " (merge queue)"
    lines.append(head)
    lines.append("")
    lines.append("| Scanner | Mode | Result |")
    lines.append("| --- | --- | --- |")
    for s in scanners:
        lines.append(f"| {SCANNER_TITLES[s]} | {results[s].get('mode')} | {describe(s, results[s])} |")
    lines.append("")
    if failures:
        lines.append("**Blocking:** " + "; ".join(failures))
        lines.append("")
    lines += finding_sections(results)
    lines.append("")
    base = ctx.get("base") or ""
    lines.append(f"<sub>base `{base[:12]}` head `{ctx.get('head', '')[:12]}`, {len(ctx.get('changed') or {})} changed files. "
                 "Policies and allow-list formats: workflow-templates `docs/security-scanners.md`.</sub>")
    summary = "\n".join(lines)
    step_summary = env("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a") as f:
            f.write(summary + "\n")
    log(summary)

    total = sum(len(r.get("findings") or []) for r in results.values())
    bundle = {
        "schema": 1, "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "repository": env("GITHUB_REPOSITORY"), "run_id": env("GITHUB_RUN_ID"), "run_attempt": env("GITHUB_RUN_ATTEMPT"),
        "job": env("GITHUB_JOB"), "event": ctx.get("event"), "pr_number": ctx.get("pr_number"),
        "is_fork": bool(ctx.get("is_fork")), "profile": profile, "suffix": suffix,
        "head": ctx.get("head"), "base": base, "actor": env("GITHUB_ACTOR"), "conclusion": conclusion,
        "changed_files": len(ctx.get("changed") or {}), "scanners": results,
    }
    art = workdir() / "artifact"
    art.mkdir(parents=True, exist_ok=True)
    save_json(art / "results.json", bundle)
    comment = comment_marker() + "\n" + summary.replace(f"## {label}", f"## 🔎 {label}", 1)
    (workdir() / "comment.md").write_text(comment)
    set_output("conclusion", conclusion)
    set_output("findings_total", str(total))
    set_output("comment_needed", "true" if (total or failures or warnings_out) else "false")
    if failures:
        log("::error title=security-scan::" + "; ".join(failures))
        sys.exit(1)


# ----------------------------------------------------------------------------- comment
def gh_api(*args, input_text=None):
    return run(["gh", "api", *args], input_text=input_text)


def upsert_pr_comment(marker, body, has_content, pr, head):
    """Create or update the single comment starting with `marker`; rewrite it to pass when nothing is left."""
    repo = env("GITHUB_REPOSITORY")
    r = gh_api("--paginate", f"repos/{repo}/issues/{pr}/comments", "--jq",
               f'.[] | select(.body | startswith("{marker}")) | .id')
    existing = [i for i in r.stdout.split() if i.strip()]
    if has_content:
        payload = json.dumps({"body": body[:65000]})
        if existing:
            res = gh_api("-X", "PATCH", f"repos/{repo}/issues/comments/{existing[0]}", "--input", "-", input_text=payload)
        else:
            res = gh_api("-X", "POST", f"repos/{repo}/issues/{pr}/comments", "--input", "-", input_text=payload)
        log("comment upserted" if res.returncode == 0 else f"comment failed: {res.stderr[-300:]}")
    elif existing:
        clean = f"{marker}\n## 🔎 Security scan: pass\n\nNo findings on the latest push (`{head[:12]}`)."
        res = gh_api("-X", "PATCH", f"repos/{repo}/issues/comments/{existing[0]}", "--input", "-",
                     input_text=json.dumps({"body": clean}))
        log("comment cleared" if res.returncode == 0 else f"comment update failed: {res.stderr[-300:]}")
    else:
        log("nothing to comment")


def comment_allowed(event, pr, is_fork):
    if event == "merge_group" or not pr or is_fork:
        log("PR comment skipped (merge queue, fork or no PR number)")
        return False
    if not env("GH_TOKEN"):
        log("PR comment skipped (no GH_TOKEN)")
        return False
    return True


def cmd_comment():
    ctx = load_ctx()
    if not comment_allowed(ctx.get("event"), ctx.get("pr_number"), ctx.get("is_fork")):
        return
    body_path = workdir() / "comment.md"
    body = body_path.read_text() if body_path.exists() else ""
    bundle = load_json(workdir() / "artifact" / "results.json", {}) or {}
    upsert_pr_comment(comment_marker(), body, bundle.get("conclusion") in ("fail", "advisory"),
                      ctx.get("pr_number"), ctx.get("head", ""))


# ----------------------------------------------------------------------------- aggregate
def aggregate_bundles(bundles):
    """One report from the results.json of every scan job of a run: (conclusion, markdown, findings)."""
    code = [b for b in bundles if b.get("profile", "code") in ("code", "workflows")]
    images = sorted((b for b in bundles if b.get("profile") == "image"), key=lambda b: b.get("suffix") or "")
    conclusions = {b.get("conclusion") for b in bundles}
    conclusion = "fail" if "fail" in conclusions else ("advisory" if "advisory" in conclusions else "pass")
    failures, rows, sections, total = [], [], [], 0
    for b in code:
        results = b.get("scanners") or {}
        f, _ = classify_results(results)
        failures += f
        for s, r in ordered(results):
            rows.append(f"| {SCANNER_TITLES[s]} | {r.get('mode')} | {describe(s, r)} |")
            total += len(r.get("findings") or [])
        sections += finding_sections(results)
    for b in images:
        r = (b.get("scanners") or {}).get("image")
        if not r:
            continue
        name = b.get("suffix") or (b.get("job") or "image")
        suffix = f": {name}"
        f, _ = classify_results({"image": r}, suffix)
        failures += f
        os_name = f" ({r.get('os')})" if r.get("os") else ""
        rows.append(f"| {SCANNER_TITLES['image']}{suffix}{os_name} | {r.get('mode')} | {describe('image', r)} |")
        total += len(r.get("findings") or [])
        sections += finding_sections({"image": r}, suffix)
    first = code[0] if code else (images[0] if images else {})
    lines = [f"## 🔎 Security scan: {conclusion}"]
    if first.get("event") == "merge_group":
        lines[0] += " (merge queue)"
    lines += ["", "| Scanner | Mode | Result |", "| --- | --- | --- |", *rows, ""]
    if failures:
        lines += ["**Blocking:** " + "; ".join(failures), ""]
    lines += sections
    lines += ["", f"<sub>base `{(first.get('base') or '')[:12]}` head `{(first.get('head') or '')[:12]}`, "
                  f"{first.get('changed_files', 0)} changed files, {len(bundles)} scan job(s). "
                  "Policies and allow-list formats: workflow-templates `docs/security-scanners.md`.</sub>"]
    return conclusion, "\n".join(lines), total


def cmd_aggregate():
    root = Path(env("SCAN_AGGREGATE_DIR") or (workdir() / "aggregate"))
    bundles = [b for b in (load_json(f) for f in sorted(root.rglob("results.json"))) if b and b.get("schema") == 1]
    log(f"{len(bundles)} scan result bundle(s) under {root}")
    set_output("bundles", str(len(bundles)))
    if not bundles:
        return
    conclusion, body, total = aggregate_bundles(bundles)
    log(body)
    step_summary = env("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a") as f:
            f.write(body + "\n")
    (workdir() / "comment.md").write_text("<!-- security-scan -->\n" + body)
    set_output("conclusion", conclusion)
    set_output("findings_total", str(total))
    first = bundles[0]
    pr = env("SCAN_PR_NUMBER") or first.get("pr_number")
    if not comment_allowed(first.get("event"), pr, any(b.get("is_fork") for b in bundles)):
        return
    upsert_pr_comment("<!-- security-scan -->", "<!-- security-scan -->\n" + body, conclusion != "pass",
                      pr, first.get("head") or "")


COMMANDS = {
    "context": cmd_context, "secrets": cmd_secrets, "deps": cmd_deps, "sast": cmd_sast,
    "image": cmd_image, "workflows": cmd_workflows, "report": cmd_report, "comment": cmd_comment,
    "aggregate": cmd_aggregate,
}

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in COMMANDS:
        sys.exit(f"usage: security-scan.py <{'|'.join(COMMANDS)}>")
    (workdir() / "artifact").mkdir(parents=True, exist_ok=True)
    COMMANDS[sys.argv[1]]()
