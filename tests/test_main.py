"""Phase 1 regressions. No external connections or DNS requests are made."""
import argparse
import contextlib
import errno
import ssl
import threading
import time
import csv
import json
import os
import io
import socket
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

import main


class TargetParsingTests(unittest.TestCase):
    def test_ipv4_and_ipv6_literals(self):
        self.assertEqual(main.expand_target_entry("192.0.2.10"), ["192.0.2.10"])
        self.assertEqual(main.expand_target_entry("2001:db8::1"), ["2001:db8::1"])
        self.assertEqual(main.expand_target_entry("::1"), ["::1"])

    def test_bracketed_ipv6_with_explicit_port_warns(self):
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            actual = main.expand_target_entry("[2001:db8::1]:443")
        self.assertEqual(actual, ["2001:db8::1"])
        self.assertEqual(len(captured), 1)
        self.assertIn("--ports", str(captured[0].message))

    def test_url_hostname_and_idna(self):
        self.assertEqual(main.expand_target_entry("https://EXAMPLE.com:443/a?q=1"), ["example.com"])
        self.assertEqual(main.expand_target_entry("www.example.com"), ["www.example.com"])
        self.assertEqual(main.expand_target_entry("https://[::1]/"), ["::1"])
        self.assertEqual(main.expand_target_entry("bücher.example"), ["xn--bcher-kva.example"])

    def test_ipv4_and_ipv6_networks(self):
        self.assertEqual(main.expand_target_entry("192.0.2.0/30"), [
            "192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"
        ])
        self.assertEqual(main.expand_target_entry("2001:db8::/126"), [
            "2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"
        ])

    def test_cidr_per_entry_limit(self):
        with self.assertRaisesRegex(ValueError, "limit"):
            main.expand_target_entry("10.0.0.0/21")

    def test_blank_comments_and_inline_comments(self):
        self.assertEqual(main.expand_target_entry(" # blank"), [])
        self.assertEqual(main.expand_target_entry("example.com # comment"), ["example.com"])
        self.assertEqual(main.expand_target_entry("https://example.com/#heading"), ["example.com"])

    def test_invalid_and_ambiguous_targets_are_rejected(self):
        invalid = (
            "2001:db8::gg", "999.999.999.999", "127.1", "example.com/path",
            "example.com?x=y", "https://", "https://name:bad/",
            "https://user:secret@example.com/", "[::1", "example.com:0",
            "example.com:", "exa mple.com", "::1%eth0", "example..com",
            "http://[notanip]/", "http://[::1]garbage/",
            "http://[127.0.0.1]/",
            "a" * (main.MAX_TARGET_ENTRY_LENGTH + 1),
        )
        for target in invalid:
            with self.subTest(target=target[:40]):
                with self.assertRaises(ValueError):
                    main.expand_target_entry(target)

    def test_clean_target_preserves_legacy_empty_string_on_invalid(self):
        self.assertEqual(main.clean_target("example.com/path"), "")
        self.assertEqual(main.clean_target("https://EXAMPLE.com:443/a"), "example.com")
        self.assertEqual(main.clean_target("::1"), "::1")


class PortParsingTests(unittest.TestCase):
    def test_valid_ports_and_legacy_trailing_comma(self):
        self.assertEqual(main.parse_ports("80,22,80,443-444,"), [22, 80, 443, 444])
        self.assertEqual(main.parse_ports("10 - 12"), [10, 11, 12])

    def test_inverted_and_malformed_ranges_rejected(self):
        for spec in ("100-99,443", "0", "65536", "22-no", "1-65535",
                     "-1", "3-2", "1--2", "1-2-3", ",,", "999999999999"):
            with self.subTest(spec=spec):
                with self.assertRaises(ValueError):
                    main.parse_ports(spec)

    def test_distinct_port_cap(self):
        self.assertEqual(len(main.parse_ports("1-4096")), main.MAX_PORTS)
        with self.assertRaisesRegex(ValueError, "limit"):
            main.parse_ports("1-4097")


class FileAndScopeTests(unittest.TestCase):
    def test_targets_file_deduplicates_and_expands(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "targets.txt"
            path.write_text("192.0.2.1\n192.0.2.0/30\n192.0.2.1\n", encoding="utf-8")
            self.assertEqual(main.read_targets_file(path), [
                "192.0.2.1", "192.0.2.0", "192.0.2.2", "192.0.2.3"
            ])

    def test_targets_file_has_line_context_for_error(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "targets.txt"
            path.write_text("127.0.0.1\nexample.com/path\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "line 2"):
                main.read_targets_file(path)

    def test_global_unique_target_cap_in_input_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "targets.txt"
            path.write_text("\n".join(f"host-{n}.example" for n in range(1025)), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "too many unique targets"):
                main.read_targets_file(path)

    def test_target_file_byte_and_line_caps(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "targets.txt"
            path.write_text("x" * (main.MAX_TARGET_FILE_BYTES + 1), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "bytes"):
                main.read_targets_file(path)
            path.write_text("# comment\n" * (main.MAX_TARGET_FILE_LINES + 1), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "lines"):
                main.read_targets_file(path)

    def test_total_scan_cap_and_minimums(self):
        self.assertEqual(main.validate_scan_scope(["127.0.0.1"], [80]), 1)
        with self.assertRaisesRegex(ValueError, "combinations"):
            main.validate_scan_scope(["host"] * 1024, list(range(1, 1001)))
        with self.assertRaises(ValueError):
            main.validate_scan_scope([], [80])
        with self.assertRaises(ValueError):
            main.validate_scan_scope(["localhost"], [])

    def test_timeout_rejects_nonfinite_and_out_of_range(self):
        for timeout in (0, -1, 0.1, 30.1, float("nan"), float("inf"), float("-inf")):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError):
                    main.validate_timeout(timeout)
        self.assertEqual(main.validate_timeout(main.MIN_TIMEOUT), main.MIN_TIMEOUT)
        self.assertEqual(main.validate_timeout(main.MAX_TIMEOUT), main.MAX_TIMEOUT)


class AuthorizationAndSocketTests(unittest.TestCase):
    @staticmethod
    def args(**kwargs):
        values = dict(
            target="example.com", input_file=None, ports="80", top_100=False,
            top_1000=False, timeout=1.0, workers=1, gentle=False,
            shuffle=False, adaptive_timeout=False, yes=False,
            banners=False, probe=False, output=None, csv=False,
            md=None, diff=None,
        )
        values.update(kwargs)
        return argparse.Namespace(**values)

    def test_denied_permission_makes_no_dns_request(self):
        with mock.patch.object(main, "parse_args", return_value=self.args()), \
             mock.patch("builtins.input", return_value="n"), \
             mock.patch.object(main.socket, "getaddrinfo", side_effect=AssertionError("DNS before consent")), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                main.main()
        self.assertEqual(caught.exception.code, 0)

    def test_invalid_timeout_prevents_dns_request(self):
        with mock.patch.object(main, "parse_args", return_value=self.args(timeout=float("nan"), yes=True)), \
             mock.patch.object(main.socket, "getaddrinfo", side_effect=AssertionError("DNS before validation")), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                main.main()
        self.assertEqual(caught.exception.code, 1)

    def test_excessive_scope_prevents_dns_request(self):
        with mock.patch.object(main, "parse_args", return_value=self.args(ports="1-4096", yes=True)), \
             mock.patch.object(main, "resolve_targets", return_value=["example.com"] * 1024), \
             mock.patch.object(main.socket, "getaddrinfo", side_effect=AssertionError("DNS before cap")), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                main.main()
        self.assertEqual(caught.exception.code, 1)

    def test_authorization_precedes_dns_with_accepted_scope(self):
        events = []

        def authorize(_prompt):
            events.append("permission")
            return "y"

        def resolve(*_args, **_kwargs):
            events.append("dns")
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0))]

        fake_result = main.ScanResult("closed", 1.0, None, None, None)
        with mock.patch.object(main, "parse_args", return_value=self.args()), \
             mock.patch("builtins.input", side_effect=authorize), \
             mock.patch.object(main.socket, "getaddrinfo", side_effect=resolve), \
             mock.patch.object(main, "scan_port", return_value=fake_result), \
             contextlib.redirect_stdout(io.StringIO()):
            main.main()
        self.assertEqual(events, ["permission", "dns"])

    def test_hostname_resolution_prefers_ipv4(self):
        records = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
        ]
        with mock.patch.object(main.socket, "getaddrinfo", return_value=records) as resolver:
            self.assertEqual(main.resolve_address("localhost"), "127.0.0.1")
        resolver.assert_called_once()

    def test_ipv6_literal_does_not_trigger_dns(self):
        with mock.patch.object(main.socket, "getaddrinfo", side_effect=AssertionError("unexpected DNS")):
            self.assertEqual(main.resolve_address("::1"), "::1")

    def test_direct_scan_port_hostname_uses_legacy_ipv4_socket(self):
        fake_socket = mock.MagicMock()
        fake_socket.__enter__.return_value = fake_socket
        fake_socket.connect_ex.return_value = 111
        with mock.patch.object(main.socket, "socket", return_value=fake_socket) as factory:
            main.scan_port("localhost", 80)
        factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)

    def test_ipv6_socket_family_is_inet6(self):
        fake_socket = mock.MagicMock()
        fake_socket.__enter__.return_value = fake_socket
        fake_socket.connect_ex.return_value = 0
        with mock.patch.object(main.socket, "socket", return_value=fake_socket) as factory:
            result = main.scan_port("::1", 443)
        self.assertEqual(result.state, "open")
        factory.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM)
        fake_socket.connect_ex.assert_called_once_with(("::1", 443))


class ExistingRegressionsTests(unittest.TestCase):
    def test_adaptive_timeout_does_not_exceed_low_ceiling(self):
        adaptive = main.AdaptiveTimeout(0.1)
        adaptive.update(10)
        self.assertLessEqual(adaptive.get(), 0.1)

    def test_diff_no_response_is_not_closed(self):
        previous = {("localhost", 80): "open"}
        scans = [{"target": "localhost", "ports": [80], "results": [
            main.ScanResult("no_response", 20.0, None, None, None)
        ]}]
        new_open, newly_closed = main.diff_against_previous(previous, scans)
        self.assertEqual(new_open, [])
        self.assertEqual(newly_closed, [])

    def test_previous_report_missing_required_fields(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "previous.json"
            path.write_text('{"results": [{}]}', encoding="utf-8")
            with self.assertRaises(ValueError):
                main.load_previous_report(path)


class ReportSecurityTests(unittest.TestCase):
    @staticmethod
    def scans(banner="hello", port=443, state="open"):
        result = main.ScanResult(state, 1.25, banner, "TLSv1.3/EXAMPLE", None)
        return [{"target": "localhost", "ip": "127.0.0.1",
                 "ports": [port], "results": [result]}]

    def test_csv_formula_prefixes_are_neutralized(self):
        with tempfile.TemporaryDirectory() as folder:
            for index, formula in enumerate(("=1+2", "+SUM(1,2)", "-2+3", "@cmd", "   =7", "\u00a0=7")):
                with self.subTest(formula=formula):
                    path = Path(folder) / f"result{index}.csv"
                    main.save_results(path, True, "run123", self.scans(formula))
                    with path.open(newline="", encoding="utf-8") as stream:
                        record = list(csv.DictReader(stream))[0]
                    self.assertTrue(record["banner"].startswith("'"))
                    self.assertEqual(record["banner"][1:], formula)

    def test_csv_quotes_spaces_tabs_and_line_breaks(self):
        with tempfile.TemporaryDirectory() as folder:
            banner = '\t=HYPERLINK("bad","click")\r\nInjected,Row\n@SUM(1)'
            path = Path(folder) / "result.csv"
            main.save_results(path, True, "run", self.scans(banner))
            with path.open(encoding="utf-8", newline="") as stream:
                data = list(csv.DictReader(stream))
            self.assertEqual(len(data), 1)
            cell = data[0]["banner"]
            self.assertNotIn("\t", cell)
            self.assertNotIn("\r", cell)
            self.assertNotIn("\n", cell)
            self.assertIn(r"\t=HYPERLINK", cell)
            self.assertIn(r"\r\nInjected,Row", cell)
            self.assertIn('"bad"', cell)

    def test_ansi_bidi_and_other_controls_are_neutralized(self):
        banner = "hello\x1b[31mred\x1b[0m\x00\x07\u202e"
        displayed = main._safe_display_text(banner)
        for control in ("\x1b", "\x00", "\x07", "\u202e"):
            self.assertNotIn(control, displayed)
        self.assertIn(r"\x1b[31m", displayed)
        self.assertIn(r"\u202e", displayed)

    def test_markdown_escapes_html_pipe_backticks_and_link_syntax(self):
        banner = '<img src=x onerror=alert(1)> | `code` [link](javascript:evil)\n# INJECT'
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.md"
            main.save_markdown_report(path, "run", self.scans(banner), 2.0)
            content = path.read_text(encoding="utf-8")
            self.assertNotIn("<img", content)
            self.assertNotIn("[link](javascript:evil)", content)
            self.assertIn("&lt;img", content)
            self.assertIn(r"\|", content)
            self.assertIn(r"\`code\`", content)
            self.assertIn(r"\n", content)
            self.assertEqual(content.count("| localhost |"), 1)
            self.assertNotIn("\n# INJECT", content)

    def test_markdown_escapes_diff_target_and_states(self):
        result = main.DiffResult([], [], [("[test](javascript:evil)", 22, "unknown", "open")], [])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "result.md"
            main.save_markdown_report(path, "run", self.scans("hi"), 0.1, result)
            content = path.read_text(encoding="utf-8")
            self.assertNotIn("[test](javascript:evil)", content)
            self.assertIn("INCONCLUSIVE", content)

    def test_json_keeps_banner_raw_but_escapes_its_serialization(self):
        banner = "hello\x1b[31m\r\n=3"
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "scan.json"
            main.save_results(path, False, "run", self.scans(banner))
            serialized = path.read_text(encoding="utf-8")
            self.assertNotIn("\x1b", serialized)
            self.assertNotIn("\r", serialized)
            self.assertIn(r"\u001b", serialized)
            loaded = json.loads(serialized)
            self.assertEqual(loaded["results"][0]["banner"], banner)
            self.assertEqual(main.load_previous_report(path), {("localhost", 443): "open"})

    def test_unexpected_large_banner_or_field_is_rejected_before_write(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.json"
            with self.assertRaisesRegex(ValueError, "banner"):
                main.save_results(path, False, "run", self.scans("x" * (main.BANNER_MAX_LEN + 1)))
            self.assertFalse(path.exists())
            with self.assertRaisesRegex(ValueError, "RTT"):
                main.save_results(path, False, "run", [{"target": "localhost", "ip": "127.0.0.1",
                     "ports": [443], "results": [main.ScanResult("open", float("nan"), "ok", None, None)]}])
            self.assertFalse(path.exists())

    def test_csv_and_markdown_refuse_overwriting_existing_files(self):
        with tempfile.TemporaryDirectory() as folder:
            for suffix, callback in (
                ("csv", lambda path: main.save_results(path, True, "run", self.scans())),
                ("md", lambda path: main.save_markdown_report(path, "run", self.scans(), 1.0)),
            ):
                path = Path(folder) / f"report.{suffix}"
                path.write_text("ORIGINAL", encoding="utf-8")
                with self.assertRaises(FileExistsError):
                    callback(path)
                self.assertEqual(path.read_text(encoding="utf-8"), "ORIGINAL")

    def test_atomic_write_cleans_up_after_link_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "output.json"
            with mock.patch.object(main.os, "link", side_effect=OSError("simulated link failure")):
                with self.assertRaises(OSError):
                    main.save_results(path, False, "run", self.scans())
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_atomic_write_cleans_up_after_serialization_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "output.json"
            with mock.patch.object(main.json, "dump", side_effect=OSError("simulated disk failure")):
                with self.assertRaises(OSError):
                    main.save_results(path, False, "run", self.scans())
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_preflight_detects_collision_existing_file_and_missing_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            original = Path(folder) / "baseline.json"
            original.write_text("KEEP", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "already exists"):
                main.validate_report_paths(output=original)
            with self.assertRaisesRegex(ValueError, "collides"):
                main.validate_report_paths(output=original, baseline=original)
            with self.assertRaisesRegex(ValueError, "collides"):
                main.validate_report_paths(output=Path(folder) / "same.json",
                                           markdown=Path(folder) / "same.json")
            with self.assertRaisesRegex(ValueError, "directory"):
                main.validate_report_paths(output=Path(folder) / "missing" / "new.json")

    def test_preflight_blocks_dns_when_output_exists(self):
        with tempfile.TemporaryDirectory() as folder:
            report = Path(folder) / "out.json"
            report.write_text("existing", encoding="utf-8")
            args = AuthorizationAndSocketTests.args(output=str(report), yes=True)
            with mock.patch.object(main, "parse_args", return_value=args), \
                 mock.patch.object(main.socket, "getaddrinfo", side_effect=AssertionError("DNS before preflight")), \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as ctx:
                    main.main()
            self.assertEqual(ctx.exception.code, 1)
            self.assertEqual(report.read_text(encoding="utf-8"), "existing")

    def test_terminal_banner_does_not_emit_ansi(self):
        args = AuthorizationAndSocketTests.args(yes=True)
        result = main.ScanResult("open", 1.0, "hi\x1b[2J\x07", None, None)
        terminal = io.StringIO()
        with mock.patch.object(main, "parse_args", return_value=args), \
             mock.patch.object(main, "resolve_address", return_value="127.0.0.1"), \
             mock.patch.object(main, "scan_port", return_value=result), \
             contextlib.redirect_stdout(terminal):
            main.main()
        self.assertNotIn("\x1b", terminal.getvalue())
        self.assertIn(r"\x1b[2J", terminal.getvalue())


class PreviousReportValidationTests(unittest.TestCase):
    def load_data(self, data):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "baseline.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            return main.load_previous_report(path)

    def test_legacy_full_json_report_is_accepted(self):
        scans = ReportSecurityTests.scans("SSH-2.0-example", 22)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "old.json"
            legacy = {"run_id": "1a2b3c4d", "results": main.build_records("1a2b3c4d", scans)}
            path.write_text(json.dumps(legacy), encoding="utf-8")
            self.assertEqual(main.load_previous_report(path), {("localhost", 22): "open"})

    def test_legacy_minimal_baseline_is_accepted(self):
        self.assertEqual(self.load_data({"results": [
            {"target": "localhost", "port": 443, "state": "closed"}
        ]}), {("localhost", 443): "closed"})

    def test_unknown_and_error_states_are_accepted_as_indeterminate(self):
        data = {"results": [
            {"target": "localhost", "port": 1, "state": "unknown"},
            {"target": "localhost", "port": 2, "state": "error"},
            {"target": "localhost", "port": 3, "state": "no_response"},
        ]}
        previous = self.load_data(data)
        self.assertEqual(previous[("localhost", 1)], "unknown")
        self.assertEqual(previous[("localhost", 2)], "error")

    def test_missing_wrong_or_extra_fields_fail_with_valueerror(self):
        invalid_records = (
            {}, {"target": "x", "port": 1},
            {"target": [], "port": 2, "state": "open"},
            {"target": "x", "port": True, "state": "open"},
            {"target": "x", "port": 70000, "state": "open"},
            {"target": "x", "port": 1, "state": None},
            {"target": "x", "port": 1, "state": "not_a_state"},
            {"target": "x", "port": 1, "state": "open", "unexpected": "foo"},
            {"target": "x", "port": 1, "state": "open", "rtt_ms": float("inf")},
            {"target": "x", "port": 1, "state": "open", "banner": "x" * 201},
            {"target": "x", "port": 1, "state": "open", "ip": "not an ip"},
        )
        for record in invalid_records:
            with self.subTest(record=str(record)[:80]):
                with self.assertRaises(ValueError):
                    self.load_data({"results": [record]})

    def test_invalid_top_level_and_results_fields(self):
        for data in ([], None, {}, {"results": None}, {"results": {}},
                     {"results": [], "other": 1}, {"run_id": 123, "results": []}):
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    self.load_data(data)

    def test_duplicate_target_port_records_rejected(self):
        record = {"target": "localhost", "port": 443, "state": "open"}
        with self.assertRaisesRegex(ValueError, "duplicate target-port"):
            self.load_data({"results": [record, record]})

    def test_duplicate_json_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "old.json"
            path.write_text('{"results": [], "results": []}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid JSON"):
                main.load_previous_report(path)

    def test_nan_in_json_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "old.json"
            path.write_text('{"results": [], "run_id": NaN}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid JSON"):
                main.load_previous_report(path)

    def test_deep_json_is_rejected_before_deserialization(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "deep.json"
            path.write_text("[" * 20 + "0" + "]" * 20, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "nesting"):
                main.load_previous_report(path)

    def test_invalid_json_and_non_utf8_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "broken.json"
            for payload in (b"{broken}", b"\xff\xfe", b'{"results": ['):
                path.write_bytes(payload)
                with self.subTest(payload=payload):
                    with self.assertRaises(ValueError):
                        main.load_previous_report(path)

    def test_file_size_limit_is_enforced(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "big.json"
            path.write_bytes(b" " * 256)
            with mock.patch.object(main, "MAX_REPORT_FILE_BYTES", 128):
                with self.assertRaisesRegex(ValueError, "file size"):
                    main.load_previous_report(path)

    def test_record_count_limit_is_enforced(self):
        data = {"results": [
            {"target": "localhost", "port": n, "state": "closed"} for n in (1, 2, 3)
        ]}
        with mock.patch.object(main, "MAX_SCAN_COMBINATIONS", 2):
            with self.assertRaisesRegex(ValueError, "record count"):
                self.load_data(data)


class DiffTransitionTests(unittest.TestCase):
    @staticmethod
    def scan(states):
        ports = list(range(100, 100 + len(states)))
        return [{"target": "localhost", "ports": ports,
                 "results": [main.ScanResult(state, 1.0, None, None, None)
                             for state in states]}]

    def test_open_to_closed_is_confirmed(self):
        diff = main.diff_against_previous({("localhost", 100): "open"}, self.scan(["closed"]))
        self.assertEqual(diff.newly_closed, [("localhost", 100)])
        self.assertEqual(diff.inconclusive, [])

    def test_closed_to_open_is_confirmed(self):
        diff = main.diff_against_previous({("localhost", 100): "closed"}, self.scan(["open"]))
        self.assertEqual(diff.new_open, [("localhost", 100)])
        self.assertEqual(diff.newly_observed, [])

    def test_open_to_no_response_is_inconclusive(self):
        diff = main.diff_against_previous({("localhost", 100): "open"}, self.scan(["no_response"]))
        self.assertEqual(diff.newly_closed, [])
        self.assertEqual(diff.inconclusive, [("localhost", 100, "open", "no_response")])

    def test_unknown_to_open_is_not_claimed_new(self):
        diff = main.diff_against_previous({("localhost", 100): "unknown"}, self.scan(["open"]))
        self.assertEqual(diff.new_open, [])
        self.assertEqual(diff.inconclusive, [("localhost", 100, "unknown", "open")])

    def test_unseen_port_is_first_observation_not_transition(self):
        diff = main.diff_against_previous({}, self.scan(["open"]))
        self.assertEqual(diff.new_open, [])
        self.assertEqual(diff.newly_observed, [("localhost", 100)])

    def test_error_and_unknown_current_states_are_inconclusive(self):
        baseline = {("localhost", 100): "open", ("localhost", 101): "closed"}
        diff = main.diff_against_previous(baseline, self.scan(["error", "unknown"]))
        self.assertEqual(diff.newly_closed, [])
        self.assertEqual(len(diff.inconclusive), 2)

    def test_unchanged_and_untested_baseline_ports_ignored(self):
        baseline = {("localhost", 100): "open", ("localhost", 200): "open"}
        diff = main.diff_against_previous(baseline, self.scan(["open"]))
        self.assertEqual(diff.newly_closed, [])
        self.assertEqual(diff.inconclusive, [])

    def test_legacy_two_list_unpack_still_works(self):
        diff = main.diff_against_previous({("localhost", 100): "closed"}, self.scan(["open"]))
        open_ports, closed_ports = diff
        self.assertEqual(open_ports, [("localhost", 100)])
        self.assertEqual(closed_ports, [])

    def test_markdown_legacy_pair_is_still_accepted(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "legacy.md"
            main.save_markdown_report(path, "run", ReportSecurityTests.scans("hi"),
                                      1.2, ([("localhost", 443)], []))
            self.assertIn("CONFIRMED OPEN", path.read_text(encoding="utf-8"))



class ConcurrencyPhase3Tests(unittest.TestCase):
    """Deterministic bounded-scheduler exercises: no external network."""

    def test_in_flight_backpressure_and_concurrency_cap(self):
        started = threading.Event()
        release = threading.Event()
        window_full = threading.Event()
        state = {"generated": 0, "active": 0, "peak": 0}
        lock = threading.Lock()
        box = {}

        def source():
            for port in range(1, 201):
                with lock:
                    state["generated"] += 1
                    if state["generated"] == 4:
                        window_full.set()
                yield port

        def worker(port):
            with lock:
                state["active"] += 1
                state["peak"] = max(state["peak"], state["active"])
                started.set()
            try:
                if not release.wait(3):
                    raise RuntimeError("test timed out")
                return port * 10
            finally:
                with lock:
                    state["active"] -= 1

        def runner():
            try:
                box["results"] = main.scan_ports_bounded(source(), worker, 2)
            except BaseException as exc:
                box["error"] = exc

        thread = threading.Thread(target=runner)
        thread.start()
        try:
            self.assertTrue(started.wait(3))
            self.assertTrue(window_full.wait(3))
            self.assertEqual(state["generated"], 4)
        finally:
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive(), "bounded executor did not exit")
        self.assertNotIn("error", box)
        self.assertLessEqual(state["peak"], 2)
        self.assertEqual(box["results"], {n: n * 10 for n in range(1, 201)})

    def test_cancel_before_submission_does_not_iterate(self):
        cancel = threading.Event()
        cancel.set()
        source = mock.Mock()
        source.__iter__ = mock.Mock(side_effect=AssertionError("iterator touched"))
        with self.assertRaises(main.ScanCancelled):
            main.scan_ports_bounded(source, lambda port: port, 2, cancel)

    def test_cancel_during_run_discards_results_and_stops_submissions(self):
        stop = threading.Event()
        entered = threading.Event()
        release = threading.Event()
        counter = {"yielded": 0}
        lock = threading.Lock()
        box = {}

        def source():
            for port in range(1, 500):
                with lock:
                    counter["yielded"] += 1
                yield port

        def worker(port):
            entered.set()
            if not release.wait(3):
                raise AssertionError("worker not released")
            return port

        def runner():
            try:
                box["results"] = main.scan_ports_bounded(source(), worker, 1, stop)
            except BaseException as exc:
                box["error"] = exc

        t = threading.Thread(target=runner)
        t.start()
        try:
            self.assertTrue(entered.wait(3))
            stop.set()
        finally:
            release.set()
            t.join(5)
        self.assertFalse(t.is_alive())
        self.assertIsInstance(box.get("error"), main.ScanCancelled)
        self.assertNotIn("results", box)
        self.assertLessEqual(counter["yielded"], 2)

    def test_worker_exception_cancels_pending_and_joins_workers(self):
        visited = []
        threads = []

        def worker(port):
            threads.append(threading.current_thread())
            visited.append(port)
            raise RuntimeError("do not leak worker exception detail to user")

        with self.assertRaises(main.ScanExecutionError):
            main.scan_ports_bounded(range(1, 2000), worker, 2)
        self.assertLessEqual(len(visited), 4)
        self.assertTrue(all(not t.is_alive() for t in threads))

    def test_result_mapping_remains_correct_out_of_order(self):
        gate = threading.Barrier(2)
        def worker(port):
            if port in (11, 12):
                gate.wait(timeout=3)
            return main.ScanResult("closed", float(port), None, None, None)
        result = main.scan_ports_bounded([12, 11, 13, 10], worker, 2)
        self.assertEqual(set(result), {10, 11, 12, 13})
        self.assertEqual([result[p].rtt_ms for p in (10, 11, 12, 13)],
                         [10.0, 11.0, 12.0, 13.0])

    def test_bounded_scheduler_validation(self):
        for workers, limit in ((0, None), (101, None), (2, 1), (2, 5), (2, True)):
            with self.subTest(workers=workers, limit=limit):
                with self.assertRaises(ValueError):
                    main.scan_ports_bounded([], lambda port: port, workers, max_in_flight=limit)

    def test_keyboard_interrupt_propagates_and_joins_workers(self):
        thread_ref = []
        def worker(port):
            thread_ref.append(threading.current_thread())
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            main.scan_ports_bounded([443, 80], worker, 1)
        self.assertTrue(all(not t.is_alive() for t in thread_ref))

    def test_main_never_writes_partial_outputs_on_cancellation(self):
        args = AuthorizationAndSocketTests.args(yes=True, output="discard.json", ports="80")
        with mock.patch.object(main, "parse_args", return_value=args), \
             mock.patch.object(main, "validate_report_paths"), \
             mock.patch.object(main, "resolve_address", return_value="127.0.0.1"), \
             mock.patch.object(main, "scan_ports_bounded", side_effect=main.ScanCancelled), \
             mock.patch.object(main, "save_results") as save, \
             contextlib.redirect_stdout(io.StringIO()) as stdout:
            with self.assertRaises(SystemExit) as exit_ctx:
                main.main()
        self.assertEqual(exit_ctx.exception.code, 130)
        self.assertIn("partial results", stdout.getvalue())
        save.assert_not_called()

    def test_main_cancels_on_second_target_without_publishing_first(self):
        args = AuthorizationAndSocketTests.args(yes=True, output="discard.json")
        with mock.patch.object(main, "parse_args", return_value=args), \
             mock.patch.object(main, "validate_report_paths"), \
             mock.patch.object(main, "resolve_targets", return_value=["127.0.0.1", "127.0.0.2"]), \
             mock.patch.object(main, "resolve_address", side_effect=lambda host: host), \
             mock.patch.object(main, "scan_ports_bounded", side_effect=[
                 {80: main.ScanResult("closed", 1.0, None, None, None)},
                 main.ScanCancelled,
             ]), \
             mock.patch.object(main, "save_results") as save, \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as exit_ctx:
                main.main()
        self.assertEqual(exit_ctx.exception.code, 130)
        save.assert_not_called()

    def test_main_worker_exception_aborts_without_publishing(self):
        args = AuthorizationAndSocketTests.args(yes=True, output="discard.json")
        with mock.patch.object(main, "parse_args", return_value=args), \
             mock.patch.object(main, "validate_report_paths"), \
             mock.patch.object(main, "resolve_address", return_value="127.0.0.1"), \
             mock.patch.object(main, "scan_ports_bounded", side_effect=main.ScanExecutionError), \
             mock.patch.object(main, "save_results") as save, \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as exit_ctx:
                main.main()
        self.assertEqual(exit_ctx.exception.code, 1)
        save.assert_not_called()


class NetworkPhase3Tests(unittest.TestCase):
    def _socket(self, code):
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        sock.connect_ex.return_value = code
        return sock

    def test_posix_and_windows_connection_code_classification(self):
        expected = {errno.ECONNREFUSED: "closed", 10061: "closed",
                    errno.ETIMEDOUT: "no_response", 10060: "no_response",
                    10065: "no_response", 10051: "no_response",
                    errno.EADDRNOTAVAIL: "error", 10022: "error", 0: "open"}
        for code, state in expected.items():
            with self.subTest(code=code):
                self.assertEqual(main._connection_state(code), state)
                sock = self._socket(code)
                with mock.patch.object(main.socket, "socket", return_value=sock):
                    self.assertEqual(main.scan_port("127.0.0.1", 80).state, state)
                sock.__exit__.assert_called_once()

    def test_os_errors_from_connect_are_classified_and_socket_closed(self):
        for code, state in ((errno.ECONNREFUSED, "closed"),
                            (errno.ETIMEDOUT, "no_response"),
                            (errno.EINVAL, "error")):
            sock = self._socket(0)
            sock.connect_ex.side_effect = OSError(code, "mock failure")
            with mock.patch.object(main.socket, "socket", return_value=sock):
                self.assertEqual(main.scan_port("127.0.0.1", 80).state, state)
            sock.__exit__.assert_called_once()

    def test_timeout_exception_is_no_response(self):
        sock = self._socket(0)
        sock.connect_ex.side_effect = socket.timeout("test timeout")
        with mock.patch.object(main.socket, "socket", return_value=sock):
            self.assertEqual(main.scan_port("::1", 80).state, "no_response")

    def test_tcp_open_even_when_tls_handshake_times_out(self):
        sock = self._socket(0)
        wrapped = mock.MagicMock()
        wrapped.__enter__.return_value = wrapped
        wrapped.do_handshake.side_effect = socket.timeout("TLS never responded")
        ctx = mock.MagicMock()
        ctx.wrap_socket.return_value = wrapped
        with mock.patch.object(main.socket, "socket", return_value=sock), \
             mock.patch.object(main.ssl, "create_default_context", return_value=ctx):
            result = main.scan_port("127.0.0.1", 443, grab_banner=True)
        self.assertEqual(result.state, "open")
        self.assertIsNone(result.tls_info)
        self.assertIsNone(result.banner)
        wrapped.settimeout.assert_called_with(main.TLS_HANDSHAKE_TIMEOUT)
        ctx.wrap_socket.assert_called_once_with(
            sock, server_hostname=None, do_handshake_on_connect=False
        )
        wrapped.__exit__.assert_called_once()
        sock.__exit__.assert_called_once()

    def test_tls_disconnect_during_handshake_does_not_change_tcp(self):
        sock = self._socket(0)
        wrapped = mock.MagicMock()
        wrapped.__enter__.return_value = wrapped
        wrapped.do_handshake.side_effect = ssl.SSLError("peer dropped")
        ctx = mock.MagicMock()
        ctx.wrap_socket.return_value = wrapped
        with mock.patch.object(main.socket, "socket", return_value=sock), \
             mock.patch.object(main.ssl, "create_default_context", return_value=ctx):
            result = main.scan_port("127.0.0.1", 443, grab_banner=True)
        self.assertEqual(result.state, "open")
        self.assertIsNone(result.tls_info)
        sock.__exit__.assert_called_once()

    def test_banner_timeout_uses_independent_limit(self):
        sock = mock.MagicMock()
        sock.recv.side_effect = socket.timeout("no banner")
        self.assertIsNone(main._read_banner(sock))
        sock.settimeout.assert_called_once_with(main.BANNER_TIMEOUT)

    def test_active_probe_send_timeout_is_bounded(self):
        sock = mock.MagicMock()
        sock.sendall.side_effect = socket.timeout("blocked write")
        with mock.patch.object(main.time, "monotonic", side_effect=[10.0, 10.1]):
            self.assertIsNone(main._active_probe(sock, 80))
        sock.settimeout.assert_called_once()
        self.assertAlmostEqual(sock.settimeout.call_args.args[0], 0.65)
        sock.recv.assert_not_called()

    def test_active_probe_shares_deadline_across_send_and_recv(self):
        sock = mock.MagicMock()
        sock.recv.return_value = b"HTTP/1.1 200 OK\r\n"
        with mock.patch.object(main.time, "monotonic", side_effect=[100.0, 100.1, 100.3]):
            self.assertEqual(main._active_probe(sock, 80), "HTTP/1.1 200 OK")
        calls = sock.settimeout.call_args_list
        self.assertEqual(len(calls), 2)
        self.assertAlmostEqual(calls[0].args[0], 0.65)
        self.assertAlmostEqual(calls[1].args[0], 0.45)

    def test_active_probe_cancellation_skips_io(self):
        cancelled = threading.Event()
        cancelled.set()
        sock = mock.MagicMock()
        with self.assertRaises(main.ScanCancelled):
            main._active_probe(sock, 80, cancelled)
        sock.sendall.assert_not_called()

    def test_scan_port_cancelled_before_socket_creation(self):
        cancelled = threading.Event()
        cancelled.set()
        with mock.patch.object(main.socket, "socket", side_effect=AssertionError("created socket")):
            with self.assertRaises(main.ScanCancelled):
                main.scan_port("127.0.0.1", 80, cancel_event=cancelled)

    def test_tcp_rtt_uses_perf_counter(self):
        sock = self._socket(0)
        with mock.patch.object(main.socket, "socket", return_value=sock), \
             mock.patch.object(main.time, "perf_counter", side_effect=[50.0, 50.123]):
            result = main.scan_port("127.0.0.1", 80)
        self.assertEqual(result.state, "open")
        self.assertEqual(result.rtt_ms, 123.0)

    def test_main_duration_uses_monotonic_clock(self):
        args = AuthorizationAndSocketTests.args(yes=True)
        with mock.patch.object(main, "parse_args", return_value=args), \
             mock.patch.object(main, "resolve_address", return_value="127.0.0.1"), \
             mock.patch.object(main.time, "perf_counter", side_effect=[400.0, 401.75]), \
             mock.patch.object(main, "scan_port", return_value=main.ScanResult(
                 "closed", 10.0, None, None, None
             )), contextlib.redirect_stdout(io.StringIO()) as output:
            main.main()
        self.assertIn("1.75s", output.getvalue())


    def test_cancel_after_connect_closes_socket_before_banner_io(self):
        cancelled = threading.Event()
        sock = self._socket(0)

        def connect_and_cancel(_address):
            cancelled.set()
            return 0

        sock.connect_ex.side_effect = connect_and_cancel
        with mock.patch.object(main.socket, "socket", return_value=sock):
            with self.assertRaises(main.ScanCancelled):
                main.scan_port("127.0.0.1", 443, grab_banner=True,
                               cancel_event=cancelled)
        sock.__exit__.assert_called_once()
        sock.recv.assert_not_called()

    def test_windows_winerror_takes_precedence_when_present(self):
        exc = OSError(errno.EINVAL, "ignored errno")
        exc.winerror = 10061
        self.assertEqual(main._socket_error_code(exc), 10061)
        self.assertEqual(main._connection_state(main._socket_error_code(exc)), "closed")

    def test_silent_tls_server_on_local_loopback_only(self):
        """Real TLS timeout with local listener, no DNS or external endpoints."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
        except OSError as exc:
            listener.close()
            self.skipTest(f"loopback listener unavailable: {type(exc).__name__}")
        listener.settimeout(3)
        accepted = threading.Event()
        release = threading.Event()
        failures = []

        def server():
            try:
                with listener.accept()[0]:
                    accepted.set()
                    release.wait(3)
            except OSError as exc:
                failures.append(type(exc).__name__)

        server_thread = threading.Thread(target=server)
        server_thread.start()
        try:
            with mock.patch.object(main, "TLS_PORTS", {listener.getsockname()[1]}):
                start = time.perf_counter()
                result = main.scan_port("127.0.0.1", listener.getsockname()[1],
                                        timeout=0.5, grab_banner=True)
                elapsed = time.perf_counter() - start
            self.assertTrue(accepted.is_set())
            self.assertEqual(result.state, "open")
            self.assertIsNone(result.tls_info)
            self.assertLess(elapsed, main.TLS_HANDSHAKE_TIMEOUT + 1.5)
        finally:
            release.set()
            listener.close()
            server_thread.join(5)
        self.assertFalse(server_thread.is_alive())
        self.assertEqual(failures, [])

    def test_error_status_integrates_with_json_and_diff(self):
        result = main.ScanResult("error", 2.5, None, None, None)
        scans = [{"target": "localhost", "ip": "127.0.0.1", "ports": [80],
                  "results": [result]}]
        baseline = {("localhost", 80): "open"}
        diff = main.diff_against_previous(baseline, scans)
        self.assertEqual(diff.newly_closed, [])
        self.assertEqual(diff.inconclusive, [("localhost", 80, "open", "error")])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.json"
            main.save_results(path, False, "run", scans)
            self.assertEqual(main.load_previous_report(path), {("localhost", 80): "error"})



if __name__ == "__main__":
    unittest.main()
