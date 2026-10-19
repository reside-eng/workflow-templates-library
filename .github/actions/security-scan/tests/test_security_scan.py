"""Unit tests for security-scan.py (stdlib unittest; run: python3 -m unittest discover -s tests -v)."""
import importlib.util
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
import datetime as dt

HERE = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("security_scan", HERE / "security-scan.py")
ss = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ss)


def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *args], cwd=cwd, check=True,
                          text=True, capture_output=True).stdout.strip()


class TempWorkspace(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.ws = self.tmp / "ws"
        self.ws.mkdir()
        os.environ["GITHUB_WORKSPACE"] = str(self.ws)
        os.environ["SCAN_WORKDIR"] = str(self.tmp / "work")
        os.environ["SCAN_ACTION_PATH"] = str(HERE)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class ParseAddedLines(TempWorkspace):
    def test_added_and_modified_lines_only(self):
        git(self.ws, "init", "-q", "-b", "main")
        (self.ws / "a.txt").write_text("1\n2\n3\n4\n5\n")
        git(self.ws, "add", "-A")
        git(self.ws, "commit", "-qm", "base")
        base = git(self.ws, "rev-parse", "HEAD")
        (self.ws / "a.txt").write_text("1\n2\nthree\n4\n5\n6\n7\n")
        (self.ws / "b.txt").write_text("x\ny\n")
        git(self.ws, "add", "-A")
        git(self.ws, "commit", "-qm", "head")
        head = git(self.ws, "rev-parse", "HEAD")
        added = ss.parse_added_lines(base, head, ["a.txt", "b.txt"])
        self.assertEqual(added["a.txt"], {3, 6, 7})
        self.assertEqual(added["b.txt"], {1, 2})


class ClassifyDeps(unittest.TestCase):
    def test_new_fixable_gates(self):
        head = {
            ("CVE-1", "p1"): {"id": "CVE-1", "pkg": "p1", "fixed": "1.1"},
            ("CVE-2", "p2"): {"id": "CVE-2", "pkg": "p2", "fixed": ""},
            ("CVE-3", "p3"): {"id": "CVE-3", "pkg": "p3", "fixed": "2.0"},
        }
        base = {("CVE-3", "p3"): {"id": "CVE-3", "pkg": "p3", "fixed": "2.0"}}
        by_id = {f["id"]: f for f in ss.classify_deps(head, base)}
        self.assertTrue(by_id["CVE-1"]["new"] and by_id["CVE-1"]["gate"])
        self.assertTrue(by_id["CVE-2"]["new"] and not by_id["CVE-2"]["gate"])
        self.assertFalse(by_id["CVE-3"]["new"] or by_id["CVE-3"]["gate"])

    def test_trivy_vulns_extraction(self):
        report = {"Results": [{"Target": "yarn.lock", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-9", "PkgName": "lodash", "InstalledVersion": "4.17.20", "FixedVersion": "4.17.21",
             "Severity": "HIGH", "Title": "t", "PrimaryURL": "u"}]}]}
        v = ss.trivy_vulns(report)[("CVE-9", "lodash")]
        self.assertEqual((v["installed"], v["fixed"], v["severity"], v["target"]), ("4.17.20", "4.17.21", "HIGH", "yarn.lock"))


@unittest.skipUnless(shutil.which("yq"), "yq not installed")
class ValidateTrivyIgnore(TempWorkspace):
    def test_policy(self):
        today = dt.date.today()
        soon = (today + dt.timedelta(days=30)).isoformat()
        far = (today + dt.timedelta(days=200)).isoformat()
        past = (today - dt.timedelta(days=1)).isoformat()
        f = self.ws / ".trivyignore.yaml"
        f.write_text(
            "vulnerabilities:\n"
            f"  - id: CVE-OK\n    statement: fine\n    expired_at: {soon}\n"
            f"  - id: CVE-NOSTATEMENT\n    expired_at: {soon}\n"
            "  - id: CVE-NOEXPIRY\n    statement: s\n"
            f"  - id: CVE-FAR\n    statement: s\n    expired_at: {far}\n"
            f"  - id: CVE-PAST\n    statement: s\n    expired_at: {past}\n"
            "  - CVE-BARE\n")
        errors, notes = ss.validate_trivyignore(f)
        self.assertEqual(len(errors), 4, errors)
        self.assertTrue(any("CVE-PAST" in n for n in notes))
        self.assertFalse(any("CVE-OK" in e for e in errors))


class GitleaksConfig(TempWorkspace):
    def test_defaults_plus_org_allowlists(self):
        path, err = ss.build_gitleaks_config(self.ws)
        self.assertIsNone(err)
        text = path.read_text()
        self.assertIn("useDefault = true", text)
        self.assertIn("org: test fixtures", text)

    def test_repo_config_without_extend_gets_one(self):
        (self.ws / ".gitleaks.toml").write_text('[[allowlists]]\ndescription = "repo"\npaths = ["x"]\n')
        path, err = ss.build_gitleaks_config(self.ws)
        self.assertIsNone(err)
        self.assertTrue(path.read_text().startswith("[extend]\nuseDefault = true"))

    def test_extend_path_is_rejected(self):
        (self.ws / ".gitleaks.toml").write_text('[extend]\npath = "other.toml"\n')
        path, err = ss.build_gitleaks_config(self.ws)
        self.assertIsNone(path)
        self.assertIn("extend.path", err)


class ToolOutputParsing(unittest.TestCase):
    def test_semgrep_findings(self):
        report = {"results": [{"check_id": "r.eval", "path": "/src/src/a.ts", "start": {"line": 4},
                               "extra": {"severity": "ERROR", "message": "m", "metadata": {"shortlink": "https://sg.run/x"}}},
                              {"check_id": "r.warn", "path": "src/b.ts", "start": {"line": 9},
                               "extra": {"severity": "WARNING", "message": "w", "metadata": {}}}]}
        f = ss.semgrep_findings(report)
        self.assertEqual([(x["file"], x["gate"]) for x in f], [("src/a.ts", True), ("src/b.ts", False)])

    def test_zizmor_findings_restricted_to_changed_files(self):
        raw = [{"ident": "template-injection", "desc": "d", "url": "u",
                "determinations": {"severity": "High", "confidence": "High"},
                "locations": [{"symbolic": {"key": {"Local": {"verbatim_path": "/src/.github/workflows/x.yml"}}},
                               "concrete": {"location": {"start_point": {"row": 6, "column": 0}}}}]},
               {"ident": "excessive-permissions", "desc": "d", "url": "u",
                "determinations": {"severity": "Medium", "confidence": "High"},
                "locations": [{"symbolic": {"key": {"Local": {"verbatim_path": "/src/.github/workflows/other.yml"}}}}]}]
        f = ss.zizmor_findings(raw, {".github/workflows/x.yml"})
        self.assertEqual(len(f), 1)
        self.assertEqual((f[0]["file"], f[0]["line"], f[0]["gate"]), (".github/workflows/x.yml", 7, True))


class SastTargets(unittest.TestCase):
    def test_source_tests_and_workflows(self):
        self.assertTrue(ss.sast_target("src/app.ts"))
        self.assertFalse(ss.sast_target("src/__tests__/app.spec.ts"))
        self.assertTrue(ss.sast_target(".github/workflows/deploy.yml"))
        self.assertTrue(ss.sast_target(".github/actions/build/action.yml"))
        self.assertFalse(ss.sast_target("deploy-parameters/prod.yaml"))
        self.assertFalse(ss.sast_target("renovate.json"))


class BaseImageFindings(unittest.TestCase):
    def test_not_actionable_without_dockerfile_change(self):
        image = {"scanner": "image", "status": "findings", "mode": "advisory", "gate_applies": False, "notes": [],
                 "os": "alpine 3.24.1", "findings": [{"id": "CVE-1", "pkg": "libssl3", "installed": "1", "fixed": "2",
                                                      "severity": "HIGH", "url": "", "gate": True}]}
        self.assertEqual(ss.actionable("image", image), [])
        failures, warnings = ss.classify_results({"image": image})
        self.assertEqual((failures, warnings), ([], []))
        self.assertEqual([l for l in ss.finding_sections({"image": image}) if l.startswith("### ")], [])
        bundle = {"schema": 1, "profile": "image", "suffix": "", "conclusion": "pass", "event": "pull_request",
                  "pr_number": "7", "head": "h" * 40, "base": "b" * 40, "changed_files": 2, "scanners": {"image": image}}
        conclusion, body, total = ss.aggregate_bundles([bundle])
        self.assertEqual(conclusion, "pass")
        self.assertIn("not from this PR", body)
        self.assertNotIn("### Image", body)


class Reporting(unittest.TestCase):
    def test_comment_marker_per_profile(self):
        os.environ["SCAN_PROFILE"], os.environ["SCAN_SUFFIX"] = "image", "admin-ui"
        self.assertEqual(ss.comment_marker(), "<!-- security-scan:image:admin-ui -->")
        os.environ["SCAN_PROFILE"], os.environ["SCAN_SUFFIX"] = "code", ""
        self.assertEqual(ss.comment_marker(), "<!-- security-scan:code -->")

    def test_gate_count_respects_gate_applies(self):
        r = {"status": "findings", "mode": "blocking", "gate_applies": False, "findings": [{"gate": True}]}
        self.assertEqual(ss.gate_count(r), 0)
        r["gate_applies"] = True
        self.assertEqual(ss.gate_count(r), 1)
        self.assertEqual(ss.describe("secrets", r), "1 finding")



class Aggregate(unittest.TestCase):
    def test_single_report_from_code_and_image_bundles(self):
        secrets = {"scanner": "secrets", "status": "findings", "mode": "blocking", "gate_applies": True, "notes": [],
                   "findings": [{"rule": "slack-webhook-url", "file": "src/a.js", "line": 6, "description": "d",
                                 "fingerprint": "src/a.js:slack-webhook-url:6", "entropy": 4.1, "gate": True}]}
        sast = {"scanner": "sast", "status": "clean", "mode": "advisory", "gate_applies": True, "notes": [], "findings": []}
        image = {"scanner": "image", "status": "findings", "mode": "advisory", "gate_applies": True, "notes": [],
                 "os": "alpine 3.23.4",
                 "findings": [{"id": "CVE-1", "pkg": "libssl3", "installed": "1", "fixed": "2", "severity": "HIGH",
                               "url": "", "gate": True}]}
        code = {"schema": 1, "profile": "code", "suffix": "", "conclusion": "fail", "event": "pull_request",
                "pr_number": "7", "head": "h" * 40, "base": "b" * 40, "changed_files": 3,
                "scanners": {"secrets": secrets, "sast": sast}}
        img = {"schema": 1, "profile": "image", "suffix": "admin-ui", "conclusion": "advisory", "event": "pull_request",
               "pr_number": "7", "head": "h" * 40, "base": "b" * 40, "changed_files": 3, "scanners": {"image": image}}
        conclusion, body, total = ss.aggregate_bundles([img, code])
        self.assertEqual((conclusion, total), ("fail", 2))
        self.assertIn("| Secrets (gitleaks) | blocking | 1 finding |", body)
        self.assertIn("| Image (Trivy, OS packages): admin-ui (alpine 3.23.4) | advisory | 1 finding |", body)
        self.assertIn("**Blocking:** Secrets (gitleaks): 1 finding(s) introduced by this PR", body)
        self.assertIn("### Image (Trivy, OS packages): admin-ui", body)
        self.assertIn("2 scan job(s)", body)
if __name__ == "__main__":
    unittest.main()
