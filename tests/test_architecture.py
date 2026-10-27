"""Architecture/compatibility invariants, without public DNS or network scans."""
import ast
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import main
from core_scanner import baseline, cli, config, models, network, reports, scheduler, targets


ROOT = Path(__file__).resolve().parents[1]
MODULES = ("core_scanner.config", "core_scanner.models", "core_scanner.targets",
           "core_scanner.network", "core_scanner.scheduler", "core_scanner.reports",
           "core_scanner.baseline", "core_scanner.cli")


class ImportStructureTests(unittest.TestCase):
    def test_each_module_imports_alone_in_fresh_process(self):
        for name in MODULES:
            with self.subTest(module=name):
                proc = subprocess.run(
                    [sys.executable, "-B", "-c", f"import {name}"],
                    cwd=str(ROOT), capture_output=True, text=True, timeout=10,
                    check=False, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(proc.stdout, "")

    def test_imports_do_not_scan_resolve_ask_or_write_files(self):
        # Use a fresh interpreter: previously-imported modules wouldn't test imports.
        code = '''
import builtins
import importlib
import socket
import tempfile
from unittest import mock
with mock.patch.object(socket, "socket", side_effect=AssertionError("socket opened")), \
     mock.patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS")), \
     mock.patch.object(builtins, "input", side_effect=AssertionError("prompt")), \
     mock.patch.object(tempfile, "NamedTemporaryFile", side_effect=AssertionError("write")):
    import main
    for name in ("core_scanner.config", "core_scanner.models", "core_scanner.targets", "core_scanner.network", "core_scanner.scheduler", "core_scanner.reports", "core_scanner.baseline", "core_scanner.cli"):
        importlib.import_module(name)
'''
        proc = subprocess.run(
            [sys.executable, "-B", "-c", code], cwd=str(ROOT),
            capture_output=True, text=True, timeout=10, check=False,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, "")

    def test_internal_dependency_graph_is_acyclic(self):
        nodes = {p.stem: p for p in (ROOT / "core_scanner").glob("*.py") if p.stem != "__init__"}
        graph = {}
        for name, path in nodes.items():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            deps = set()
            for entry in ast.walk(tree):
                if isinstance(entry, ast.ImportFrom) and entry.level == 1:
                    self.assertIn(entry.module, nodes, (name, entry.module))
                    deps.add(entry.module)
            graph[name] = deps
        visited = set()
        active = set()

        def visit(current):
            self.assertNotIn(current, active, f"circular dependency from {current}")
            if current in visited:
                return
            active.add(current)
            for child in graph[current]:
                visit(child)
            active.remove(current)
            visited.add(current)

        for name in nodes:
            visit(name)
        self.assertEqual(visited, set(nodes))

    def test_cli_help_from_other_directory_has_no_scan(self):
        with tempfile.TemporaryDirectory() as elsewhere:
            proc = subprocess.run(
                [sys.executable, "-B", str(ROOT / "main.py"), "--help"],
                cwd=elsewhere, capture_output=True, text=True, timeout=10,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for option in ("--target", "--input-file", "--ports", "--top-100",
                       "--top-1000", "--adaptive-timeout", "--gentle", "--shuffle",
                       "--banners", "--probe", "--diff", "--output", "--md", "--yes"):
            self.assertIn(option, proc.stdout)


class PublicContractTests(unittest.TestCase):
    def test_data_contracts_and_legacy_unpacking(self):
        self.assertIs(main.ScanResult, models.ScanResult)
        self.assertEqual(main.ScanResult._fields,
                         ("state", "rtt_ms", "banner", "tls_info", "advisory"))
        self.assertIs(main.DiffResult, models.DiffResult)
        change = main.DiffResult([(1, 80)], [], [], [])
        self.assertEqual(tuple(change), ([(1, 80)], []))

    def test_exports_point_to_implementing_modules(self):
        for name, component in (("parse_ports", targets),
                                ("resolve_address", targets),
                                ("scan_ports_bounded", scheduler),
                                ("AdaptiveTimeout", network),
                                ("save_results", reports),
                                ("save_markdown_report", reports),
                                ("diff_against_previous", baseline),
                                ("parse_args", cli)):
            with self.subTest(name=name):
                self.assertIs(getattr(main, name), getattr(component, name))

    def test_facade_forwards_local_tls_port_overrides(self):
        fake = main.ScanResult("open", 2.0, None, None, None)
        custom_ports = {65432}
        with mock.patch.object(main, "TLS_PORTS", custom_ports), \
             mock.patch.object(network, "scan_port", return_value=fake) as actual:
            observed = main.scan_port("127.0.0.1", 65432, grab_banner=True)
        self.assertIs(observed, fake)
        self.assertEqual(actual.call_args.kwargs["tls_ports"], custom_ports)
        self.assertEqual(actual.call_args.kwargs["cancel_event"], None)

    def test_facade_forwards_report_limits(self):
        with mock.patch.object(main, "MAX_REPORT_FILE_BYTES", 10), \
             mock.patch.object(main, "MAX_SCAN_COMBINATIONS", 2), \
             mock.patch.object(baseline, "load_previous_report", return_value={}) as actual:
            self.assertEqual(main.load_previous_report("baseline.json"), {})
        actual.assert_called_once_with("baseline.json", max_file_bytes=10, max_records=2)

    def test_facade_main_uses_patchable_dependencies(self):
        # This is the monkeypatch-binding pitfall: a re-export is not enough.
        args = mock.Mock(target="127.0.0.1", input_file=None, ports="80",
                         top_100=False, top_1000=False, timeout=1.0, workers=1,
                         gentle=False, shuffle=False, adaptive_timeout=False,
                         yes=True, banners=False, probe=False, output=None,
                         csv=False, md=None, diff=None)
        observation = main.ScanResult("closed", 1.0, None, None, None)
        with mock.patch.object(main, "parse_args", return_value=args), \
             mock.patch.object(main, "resolve_address", return_value="127.0.0.1"), \
             mock.patch.object(main, "scan_port", return_value=observation) as mocked, \
             contextlib.redirect_stdout(io.StringIO()):
            main.main()
        mocked.assert_called_once()

    def test_cross_module_report_json_and_baseline(self):
        scans = [{"target": "localhost", "ip": "127.0.0.1",
                  "ports": [443], "results": [models.ScanResult(
                      "open", 2.5, "HTTP/1.1 200 OK", None, None)]}]
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "report.json"
            reports.save_results(destination, False, "run123", scans)
            self.assertEqual(baseline.load_previous_report(destination),
                             {("localhost", 443): "open"})

    def test_cli_selection_and_parsing_reuses_shared_logic(self):
        options = mock.Mock(top_100=False, top_1000=False, ports="80,443",
                            target="2001:db8::1", input_file=None)
        self.assertEqual(cli.resolve_ports(options), [80, 443])
        self.assertEqual(cli.resolve_targets(options), ["2001:db8::1"])
        self.assertEqual(main.validate_scan_scope(["::1"], [80]), 1)

    def test_shuffle_still_saves_sorted_ports_via_facade(self):
        args = mock.Mock(target="127.0.0.1", input_file=None, ports="80,81",
                         top_100=False, top_1000=False, timeout=1.0, workers=1,
                         gentle=False, shuffle=True, adaptive_timeout=False,
                         yes=True, banners=False, probe=False, output="summary.json",
                         csv=False, md=None, diff=None)
        stored = []

        def fake_save(_path, _csv, _id, scans):
            stored.extend(scans)

        def reverse_in_place(ports):
            ports.reverse()

        with mock.patch.object(main, "parse_args", return_value=args), \
             mock.patch.object(main, "validate_report_paths"), \
             mock.patch.object(main, "resolve_address", return_value="127.0.0.1"), \
             mock.patch.object(main, "save_results", side_effect=fake_save), \
             mock.patch.object(main.random, "shuffle", side_effect=reverse_in_place), \
             mock.patch.object(main, "scan_port", side_effect=lambda _ip, port, *a, **kw:
                               main.ScanResult("closed", float(port), None, None, None)), \
             contextlib.redirect_stdout(io.StringIO()):
            main.main()
        self.assertEqual(stored[0]["ports"], [80, 81])
        self.assertEqual([r.rtt_ms for r in stored[0]["results"]], [80.0, 81.0])


    def test_gentle_mode_preserves_worker_cap_and_timeout_floor(self):
        args = mock.Mock(target="127.0.0.1", input_file=None, ports="80",
                         top_100=False, top_1000=False, timeout=0.5, workers=20,
                         gentle=True, shuffle=False, adaptive_timeout=False,
                         yes=True, banners=False, probe=False, output=None,
                         csv=False, md=None, diff=None)
        seen = []

        def bounded(_ports, worker, workers, event):
            seen.append(workers)
            return {80: worker(80)}

        with mock.patch.object(main, "parse_args", return_value=args), \
             mock.patch.object(main, "resolve_address", return_value="127.0.0.1"), \
             mock.patch.object(main, "scan_ports_bounded", side_effect=bounded), \
             mock.patch.object(main, "scan_port", return_value=main.ScanResult(
                 "closed", 1.0, None, None, None)) as scan, \
             contextlib.redirect_stdout(io.StringIO()):
            main.main()
        self.assertEqual(seen, [3])
        self.assertEqual(scan.call_args.args[2], 2.0)

    def test_adaptive_timeout_still_adjusts_between_ports(self):
        args = mock.Mock(target="127.0.0.1", input_file=None, ports="80,81",
                         top_100=False, top_1000=False, timeout=2.0, workers=1,
                         gentle=False, shuffle=False, adaptive_timeout=True,
                         yes=True, banners=False, probe=False, output=None,
                         csv=False, md=None, diff=None)
        used = []

        def fake_scan(_ip, _port, timeout, *_args, **_kwargs):
            used.append(timeout)
            return main.ScanResult("open", 10.0, None, None, None)

        with mock.patch.object(main, "parse_args", return_value=args), \
             mock.patch.object(main, "resolve_address", return_value="127.0.0.1"), \
             mock.patch.object(main, "scan_port", side_effect=fake_scan), \
             contextlib.redirect_stdout(io.StringIO()):
            main.main()
        self.assertEqual(used, [2.0, main.ADAPTIVE_TIMEOUT_FLOOR])


if __name__ == "__main__":
    unittest.main()
