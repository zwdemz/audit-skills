import sys
import tempfile
import unittest
import json
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import run_component_vulnerability_scan as scan


class ComponentScanTests(unittest.TestCase):
    def rule(self, name="CVE-1", pattern=r"lodash[:_-]4\.17\.11", **kw):
        return scan.Rule("high", name, "", "", pattern, "node", **kw)

    def test_same_rule_is_deduplicated_across_sources(self):
        deps = [scan.Dependency("", "lodash", "4.17.11", "package.json", ".", "package-json", "", "node"),
                scan.Dependency("", "lodash", "4.17.11", "yarn.lock", ".", "yarn-lock", "", "node")]
        hits = scan.scan_hits(deps, [self.rule(), self.rule()])
        self.assertEqual(len(hits), 1)
        self.assertEqual(len(hits[0].rules), 1)
        self.assertEqual(len(hits[0].sources), 2)

    def test_ranges_are_not_exact_matches(self):
        for value in (">=2.31.0", "^4.17.11", "1.0.+", "~=2.31"):
            dep = scan.Dependency("", "lodash", value, "manifest", ".", "package-json", "", "node")
            self.assertEqual(scan.version_kind(value, dep.source_type), "range")
            self.assertFalse(scan.rule_matches_dependency(self.rule(), dep))

    def test_go_indirect_and_yarn_formats(self):
        dep = scan._parse_go_require_line("golang.org/x/text v0.3.7 // indirect", "go.mod", ".")
        self.assertEqual(dep.scope, "indirect")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "yarn.lock"
            path.write_text('"@babel/core@npm:^7.20.0":\n  version: "7.20.0"\n  resolution: "@babel/core@npm:7.20.0"\n\nlodash@^4.17.11:\n  version "4.17.11"\n', encoding="utf-8")
            deps = scan.parse_yarn_lock(path, [Path(tmp)])
            self.assertEqual({d.artifact_id for d in deps}, {"@babel/core", "lodash"})

    def test_maven_group_constraint(self):
        dep = scan.Dependency("org.other", "example-lib", "1.2.0", "pom.xml", ".", "pom", "", "java")
        rule = scan.Rule("high", "CVE", "", "", r"example-lib[:_-]1\.2\.0", "java", "org.example", "example-lib")
        self.assertFalse(scan.rule_matches_dependency(rule, dep))

    def test_maven_groups_are_not_merged(self):
        rule = self.rule(pattern=r"example-lib[:_-]1\.2\.0")
        deps = [scan.Dependency("org.a", "example-lib", "1.2.0", "a.pom", ".", "pom", "", "java"),
                scan.Dependency("org.b", "example-lib", "1.2.0", "b.pom", ".", "pom", "", "java")]
        self.assertEqual(len(scan.scan_hits(deps, [rule])), 2)
        self.assertEqual(len(scan.scan_hits(deps, [scan.Rule("high", "A", "", "", rule.pattern, "java", "org.a", "example-lib"),
                                                    scan.Rule("high", "B", "", "", rule.pattern, "java", "org.b", "example-lib")])), 2)

    def test_lockfile_wins_over_manifest_range(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"dependencies":{"lodash":"^4.17.11"}}')
            (root / "package-lock.json").write_text('{"packages":{"":{"name":"x"},"node_modules/lodash":{"version":"4.17.21"}}}')
            deps, _ = scan.collect_dependencies([root], False)
            lodash = next(d for d in deps if d.artifact_id == "lodash")
            self.assertEqual(lodash.version, "4.17.21")
            self.assertEqual(lodash.source_type, "package-lock")

    def test_gradle_requirements_and_scope_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "build.gradle").write_text("implementation 'org.example:example-lib:1.2.0'\ntestImplementation 'x:test-lib:1.0.0'")
            (root / "requirements.txt").write_text("requests>=2.31.0\nflask==2.3.0")
            deps, skipped = scan.collect_dependencies([root], False)
            self.assertEqual(skipped, 1)
            self.assertEqual({d.artifact_id for d in deps}, {"example-lib", "requests", "flask"})
            self.assertEqual(next(d for d in deps if d.artifact_id == "requests").version_kind, "range")

    def test_pipfile_and_pep621_keep_ranges(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pipfile = root / "Pipfile"
            pipfile.write_text('[packages]\nrequests = ">=2.31"\n[dev-packages]\npytest = "^8.0"')
            project = root / "pyproject.toml"
            project.write_text('[project]\ndependencies = ["requests>=2.31"]')
            deps, skipped = scan.collect_dependencies([root], True)
            self.assertEqual(skipped, 0)
            self.assertTrue(any(d.artifact_id == "requests" and d.version_kind == "range" for d in deps))
            self.assertTrue(any(d.artifact_id == "pytest" and d.version_kind == "range" for d in deps))

    def test_pipfile_lock_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Pipfile").write_text('[packages]\nrequests = ">=2.31"')
            (root / "Pipfile.lock").write_text('{"default":{"requests":{"version":"==2.31.0"}},"develop":{}}')
            deps, _ = scan.collect_dependencies([root], True)
            requests = next(d for d in deps if d.artifact_id == "requests")
            self.assertEqual((requests.version, requests.source_type), ("2.31.0", "pipfile-lock"))

    def test_go_multiline_replace_marks_local_as_unresolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "go.mod"
            path.write_text('module example.com/app\nrequire (\n example.com/foo v1.0.0\n)\nreplace (\n example.com/foo v1.0.0 => ../foo\n)\n')
            deps = scan.parse_go_mod(path, [Path(tmp)])
            self.assertEqual(deps[0].artifact_id, "../foo")
            self.assertEqual(scan.version_kind(deps[0].version, deps[0].source_type), "unresolved")

    def test_go_work_reads_used_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            module = root / "service"
            module.mkdir()
            (module / "go.mod").write_text('module example.com/service\nrequire example.com/foo v1.0.0\n')
            (root / "go.work").write_text('go 1.22\nuse (\n ./service\n)\n')
            deps, _ = scan.collect_dependencies([root / "go.work"], False)
            self.assertEqual(deps[0].artifact_id, "example.com/foo")

    def test_empty_and_invalid_inputs_are_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text("not-json")
            deps, skipped = scan.collect_dependencies([root], False)
            self.assertEqual((deps, skipped), ([], 0))

    def test_cli_writes_range_and_parse_error_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            workspace = root / "audit-workspace"
            source.mkdir()
            (source / "package.json").write_text('{"dependencies":{"lodash":"^4.17.11"}}')
            (source / "pom.xml").write_text("<project>")
            result = subprocess.run([sys.executable, str(Path(__file__).parents[1] / "scripts/run_component_vulnerability_scan.py"),
                                     "--workspace", str(workspace), "--source", str(source)],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0)
            output = workspace / "evidence" / "component-hits"
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(manifest["range_risk_count"], 1)
            self.assertEqual(manifest["parse_error_count"], 1)
            self.assertTrue((output / "range-risks.md").exists())


if __name__ == "__main__":
    unittest.main()
