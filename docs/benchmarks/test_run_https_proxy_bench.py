#!/usr/bin/env python3
"""Focused tests for the HTTPS proxy benchmark harness."""

from __future__ import annotations

import importlib.util
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("run_https_proxy_bench.py")
SPEC = importlib.util.spec_from_file_location("run_https_proxy_bench", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
bench = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bench
SPEC.loader.exec_module(bench)


class LocalTcpOrigin:
    def __init__(self, response_body: bytes) -> None:
        self.response_body = response_body
        self.stop_event = threading.Event()
        self.sock: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.port = 0

    def __enter__(self) -> "LocalTcpOrigin":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(8)
        sock.settimeout(0.2)
        self.sock = sock
        self.port = sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop_event.set()
        if self.sock is not None:
            self.sock.close()
        if self.thread is not None:
            self.thread.join(timeout=1.0)

    def _serve(self) -> None:
        assert self.sock is not None
        while not self.stop_event.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(2.0)
                data = bytearray()
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(65536)
                    if not chunk:
                        return
                    data.extend(chunk)
                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    + f"Content-Length: {len(self.response_body)}\r\n".encode("ascii")
                    + b"Connection: close\r\n\r\n"
                    + self.response_body
                )
                conn.sendall(response)


def recv_until(sock: ssl.SSLSocket, marker: bytes) -> bytes:
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


class HttpsProxyHarnessTest(unittest.TestCase):
    def test_connect_tunnel_forwards_bytes_to_origin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cert_file, key_file = bench.ensure_certificates(Path(tmp))
            with LocalTcpOrigin(b"origin-ok") as origin:
                with bench.LocalHttpsProxy(cert_file, key_file, b"proxy-body") as proxy:
                    context = ssl._create_unverified_context()
                    raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=2.0)
                    with context.wrap_socket(raw, server_hostname="127.0.0.1") as sock:
                        sock.settimeout(2.0)
                        target = f"127.0.0.1:{origin.port}"
                        sock.sendall(
                            f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode(
                                "ascii"
                            )
                        )
                        connect_response = recv_until(sock, b"\r\n\r\n")
                        self.assertIn(b"200 Connection Established", connect_response)

                        sock.sendall(
                            b"GET /bench HTTP/1.1\r\n"
                            b"Host: 127.0.0.1\r\n"
                            b"Connection: close\r\n\r\n"
                        )
                        response = recv_until(sock, b"origin-ok")
                        self.assertIn(b"origin-ok", response)

    def test_https_proxy_mtls_requires_client_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            certs = bench.ensure_benchmark_certificates(Path(tmp))
            with bench.LocalHttpsProxy(
                certs.proxy_cert_file,
                certs.proxy_key_file,
                b"proxy-body",
                client_ca_file=certs.ca_file,
            ) as proxy:
                without_cert = ssl.create_default_context(cafile=str(certs.ca_file))
                with self.assertRaises((ssl.SSLError, OSError, ConnectionResetError)):
                    raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=2.0)
                    with without_cert.wrap_socket(raw, server_hostname="127.0.0.1") as sock:
                        sock.settimeout(2.0)
                        sock.sendall(b"GET http://example.test/bench HTTP/1.1\r\n\r\n")
                        sock.recv(1)

                with_cert = ssl.create_default_context(cafile=str(certs.ca_file))
                with_cert.load_cert_chain(certs.client_cert_file, certs.client_key_file)
                raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=2.0)
                with with_cert.wrap_socket(raw, server_hostname="127.0.0.1") as sock:
                    sock.settimeout(2.0)
                    sock.sendall(
                        b"GET http://example.test/bench HTTP/1.1\r\n"
                        b"Host: example.test\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                    response = recv_until(sock, b"proxy-body")
                    self.assertIn(b"proxy-body", response)

    def test_verified_mtls_benchmark_env_uses_proxy_and_origin_tls_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            certs = bench.ensure_benchmark_certificates(Path(tmp))
            env, expected_clients = bench.build_benchmark_env(
                proxy_url="https://127.0.0.1:9443",
                target_url="https://127.0.0.1:9444/bench",
                curl=None,
                baseline="libcurl",
                requests=5,
                warmup=1,
                certs=certs,
                proxy_mtls=True,
                origin_tls=True,
                client="libcurl",
            )
            self.assertEqual(env["YLONG_BENCH_URL"], "https://127.0.0.1:9444/bench")
            self.assertEqual(env["YLONG_PROXY_CA_FILE"], str(certs.ca_file))
            self.assertEqual(env["YLONG_ORIGIN_CA_FILE"], str(certs.ca_file))
            self.assertEqual(env["YLONG_PROXY_CERT_FILE"], str(certs.client_cert_file))
            self.assertEqual(env["YLONG_PROXY_KEY_FILE"], str(certs.client_key_file))
            self.assertNotIn("YLONG_PROXY_INSECURE", env)
            self.assertEqual(env["YLONG_BENCH_CLIENTS"], "libcurl")
            self.assertEqual(expected_clients, {"libcurl"})

    def test_phase_timing_env_is_opt_in(self) -> None:
        env, _ = bench.build_benchmark_env(
            proxy_url="https://127.0.0.1:9443",
            target_url="http://127.0.0.1:9444/bench",
            curl=None,
            baseline="libcurl",
            requests=5,
            warmup=1,
            client="ylong_http_client",
        )
        self.assertNotIn("YLONG_BENCH_PHASES", env)

        env, _ = bench.build_benchmark_env(
            proxy_url="https://127.0.0.1:9443",
            target_url="http://127.0.0.1:9444/bench",
            curl=None,
            baseline="libcurl",
            requests=5,
            warmup=1,
            client="ylong_http_client",
            phase_timing=True,
        )
        self.assertEqual(env["YLONG_BENCH_PHASES"], "1")

    def test_concurrency_env_is_recorded_for_same_model_runs(self) -> None:
        env, _ = bench.build_benchmark_env(
            proxy_url="https://127.0.0.1:9443",
            target_url="http://127.0.0.1:9444/bench",
            curl=None,
            baseline="libcurl",
            requests=8,
            warmup=2,
            client="ylong_http_client",
            concurrency=4,
        )
        self.assertEqual(env["YLONG_BENCH_CONCURRENCY"], "4")

    def test_ylong_concurrency_model_is_explicit_result_dimension(self) -> None:
        env, _ = bench.build_benchmark_env(
            proxy_url="https://127.0.0.1:9443",
            target_url="http://127.0.0.1:9444/bench",
            curl=None,
            baseline="libcurl",
            requests=8,
            warmup=2,
            client="ylong_http_client",
            concurrency=4,
            ylong_concurrency_model="single-client",
        )
        self.assertEqual(env["YLONG_BENCH_YLONG_CONCURRENCY_MODEL"], "single-client")

    def test_body_stats_are_parsed_and_summarized(self) -> None:
        rows = bench.parse_output(
            "\n".join(
                [
                    "ylong_http_client: 1.5ms for 3 requests",
                    "ylong_http_client_stats: p50_us=100 p95_us=200 cpu_us=300 rss_peak_bytes=400 errors=0 for 3 requests",
                    "ylong_http_client_body_stats: chunks=6 bytes=12288 for 3 requests",
                    "libcurl: 1.0ms for 3 requests",
                    "libcurl_stats: p50_us=90 p95_us=180 cpu_us=240 rss_peak_bytes=360 errors=0 for 3 requests",
                    "libcurl_body_stats: chunks=3 bytes=12288 for 3 requests",
                ]
            ),
            "s",
            3,
            1,
            {"ylong_http_client", "libcurl"},
        )
        by_client = {row.client: row for row in rows}
        self.assertEqual(by_client["ylong_http_client"].body_chunks, 6)
        self.assertEqual(by_client["ylong_http_client"].body_bytes, 12288)
        self.assertEqual(by_client["libcurl"].body_chunks, 3)
        self.assertEqual(by_client["libcurl"].body_bytes, 12288)

        with tempfile.TemporaryDirectory() as tmp:
            summary = bench.summarize_results(
                bench.write_results(rows, result_dir=Path(tmp))
            )
            ylong = summary[summary["client"] == "ylong_http_client"].iloc[0]
            self.assertEqual(ylong["body_chunks_mean"], 6)
            self.assertEqual(ylong["body_bytes_mean"], 12288)

    def test_sync_candidate_client_is_explicitly_labeled(self) -> None:
        env, expected_clients = bench.build_benchmark_env(
            proxy_url="https://127.0.0.1:9443",
            target_url="http://127.0.0.1:9444/bench",
            curl=None,
            baseline="libcurl",
            requests=5,
            warmup=1,
            client="ylong_http_client_sync",
        )
        self.assertEqual(env["YLONG_BENCH_CLIENTS"], "ylong_http_client_sync")
        self.assertEqual(expected_clients, {"ylong_http_client_sync"})
        self.assertEqual(
            bench.benchmark_clients("libcurl", ylong_client="sync"),
            ["ylong_http_client_sync", "libcurl"],
        )

        rows = bench.parse_output(
            "\n".join(
                [
                    "ylong_http_client_sync: 1.5ms for 3 requests",
                    "ylong_http_client_sync_stats: p50_us=100 p95_us=200 cpu_us=300 rss_peak_bytes=400 errors=0 for 3 requests",
                ]
            ),
            "s",
            3,
            1,
            {"ylong_http_client_sync"},
        )
        self.assertEqual(rows[0].client, "ylong_http_client_sync")
        self.assertEqual(rows[0].p95_us, 200)

    def test_https_origin_is_reachable_through_https_proxy_tunnel(self) -> None:
        curl = shutil.which("curl")
        if curl is None:
            self.skipTest("curl is required for HTTPS-over-HTTPS-proxy fixture smoke")
        with tempfile.TemporaryDirectory() as tmp:
            certs = bench.ensure_benchmark_certificates(Path(tmp))
            with bench.LocalOriginServer(
                b"origin-tls-ok",
                cert_file=certs.origin_cert_file,
                key_file=certs.origin_key_file,
            ) as origin:
                with bench.LocalHttpsProxy(
                    certs.proxy_cert_file,
                    certs.proxy_key_file,
                    b"proxy-body",
                ) as proxy:
                    result = subprocess.run(
                        [
                            curl,
                            "-sS",
                            "--proxy",
                            proxy.url,
                            "--proxy-cacert",
                            str(certs.ca_file),
                            "--cacert",
                            str(certs.ca_file),
                            origin.url,
                        ],
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5.0,
                        check=True,
                    )
                    self.assertEqual(result.stdout.encode("utf-8"), b"origin-tls-ok")

    def test_summary_exposes_confidence_and_ratio_metrics(self) -> None:
        df = bench.pd.DataFrame(
            [
                {
                    "scenario": "s",
                    "requests": 10,
                    "repeat": 1,
                    "client": "ylong_http_client",
                    "elapsed_ms": 10.0,
                    "latency_ms": 1.0,
                    "throughput_rps": 1000.0,
                    "p50_us": 100,
                    "p95_us": 150,
                    "cpu_us_per_request": 20.0,
                    "rss_peak_bytes": 1000,
                    "errors": 0,
                },
                {
                    "scenario": "s",
                    "requests": 10,
                    "repeat": 2,
                    "client": "ylong_http_client",
                    "elapsed_ms": 12.0,
                    "latency_ms": 1.2,
                    "throughput_rps": 833.0,
                    "p50_us": 120,
                    "p95_us": 170,
                    "cpu_us_per_request": 22.0,
                    "rss_peak_bytes": 1000,
                    "errors": 0,
                },
                {
                    "scenario": "s",
                    "requests": 10,
                    "repeat": 1,
                    "client": "libcurl",
                    "elapsed_ms": 20.0,
                    "latency_ms": 2.0,
                    "throughput_rps": 500.0,
                    "p50_us": 200,
                    "p95_us": 300,
                    "cpu_us_per_request": 40.0,
                    "rss_peak_bytes": 1100,
                    "errors": 0,
                },
                {
                    "scenario": "s",
                    "requests": 10,
                    "repeat": 2,
                    "client": "libcurl",
                    "elapsed_ms": 24.0,
                    "latency_ms": 2.4,
                    "throughput_rps": 416.0,
                    "p50_us": 240,
                    "p95_us": 340,
                    "cpu_us_per_request": 44.0,
                    "rss_peak_bytes": 1100,
                    "errors": 0,
                },
            ]
        )
        summary = bench.summarize_results(df)
        self.assertIn("elapsed_ms_ci95_half_width", summary.columns)
        self.assertIn("latency_ms_ci95_half_width", summary.columns)
        comparisons = bench.compare_to_baseline(summary, baseline="libcurl")
        self.assertIn("elapsed_ms_ratio", comparisons.columns)
        ratio = comparisons.loc[
            (comparisons["scenario"] == "s")
            & (comparisons["requests"] == 10)
            & (comparisons["client"] == "ylong_http_client"),
            "elapsed_ms_ratio",
        ].iloc[0]
        self.assertAlmostEqual(ratio, 0.5)

    def test_client_order_policy_controls_fixed_order_bias(self) -> None:
        clients = ["ylong_http_client", "libcurl"]

        self.assertEqual(
            bench.build_client_run_order(clients, repeat=1, policy="interleaved", seed=7),
            ["ylong_http_client", "libcurl"],
        )
        self.assertEqual(
            bench.build_client_run_order(clients, repeat=2, policy="interleaved", seed=7),
            ["libcurl", "ylong_http_client"],
        )
        first_random = bench.build_client_run_order(
            clients, repeat=3, policy="random", seed=1234
        )
        second_random = bench.build_client_run_order(
            clients, repeat=3, policy="random", seed=1234
        )
        self.assertEqual(first_random, second_random)
        self.assertEqual(sorted(first_random), sorted(clients))

    def test_write_results_persists_client_order_metadata(self) -> None:
        rows = [
            bench.BenchResult(
                scenario="s",
                requests=3,
                repeat=1,
                client="ylong_http_client",
                elapsed_ms=1.5,
                client_order_policy="interleaved",
                client_order_seed=42,
                client_order_position=2,
            ),
            bench.BenchResult(
                scenario="s",
                requests=3,
                repeat=1,
                client="libcurl",
                elapsed_ms=1.2,
                client_order_policy="interleaved",
                client_order_seed=42,
                client_order_position=1,
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            df = bench.write_results(rows, result_dir=Path(tmp))
            self.assertIn("client_order_policy", df.columns)
            self.assertIn("client_order_seed", df.columns)
            self.assertIn("client_order_position", df.columns)
            ylong = df[df["client"] == "ylong_http_client"].iloc[0]
            self.assertEqual(ylong["client_order_policy"], "interleaved")
            self.assertEqual(int(ylong["client_order_seed"]), 42)
            self.assertEqual(int(ylong["client_order_position"]), 2)

    def test_paired_comparison_reports_ci_and_proxy_send_anomaly(self) -> None:
        df = bench.pd.DataFrame(
            [
                {
                    "scenario": "s",
                    "requests": 100,
                    "repeat": 1,
                    "client": "ylong_http_client",
                    "elapsed_ms": 100.0,
                    "latency_ms": 1.0,
                    "throughput_rps": 1000.0,
                    "p95_us": 1500,
                    "cpu_us_per_request": 20.0,
                    "rss_peak_bytes": 1000,
                    "errors": 0,
                    "proxy_response_send_us": 80_000,
                },
                {
                    "scenario": "s",
                    "requests": 100,
                    "repeat": 2,
                    "client": "ylong_http_client",
                    "elapsed_ms": 90.0,
                    "latency_ms": 0.9,
                    "throughput_rps": 1111.111,
                    "p95_us": 1400,
                    "cpu_us_per_request": 18.0,
                    "rss_peak_bytes": 1000,
                    "errors": 0,
                    "proxy_response_send_us": 70_000,
                },
                {
                    "scenario": "s",
                    "requests": 100,
                    "repeat": 1,
                    "client": "libcurl",
                    "elapsed_ms": 125.0,
                    "latency_ms": 1.25,
                    "throughput_rps": 800.0,
                    "p95_us": 1700,
                    "cpu_us_per_request": 30.0,
                    "rss_peak_bytes": 1100,
                    "errors": 0,
                    "proxy_response_send_us": 5_000,
                },
                {
                    "scenario": "s",
                    "requests": 100,
                    "repeat": 2,
                    "client": "libcurl",
                    "elapsed_ms": 120.0,
                    "latency_ms": 1.2,
                    "throughput_rps": 833.333,
                    "p95_us": 1650,
                    "cpu_us_per_request": 29.0,
                    "rss_peak_bytes": 1100,
                    "errors": 0,
                    "proxy_response_send_us": 4_000,
                },
            ]
        )

        paired = bench.paired_compare_to_baseline(df, baseline="libcurl")
        row = paired[paired["client"] == "ylong_http_client"].iloc[0]

        self.assertEqual(int(row["paired_sample_count"]), 2)
        self.assertIn("paired_throughput_rps_ratio_geomean", paired.columns)
        self.assertIn("paired_throughput_rps_ratio_ci95_low", paired.columns)
        self.assertIn("paired_throughput_rps_ratio_ci95_high", paired.columns)
        self.assertGreater(float(row["paired_throughput_rps_ratio_geomean"]), 1.2)
        self.assertTrue(bool(row["proxy_send_anomaly"]))
        self.assertEqual(row["sota_gate"], "reject_proxy_send_anomaly")

    def test_ratio_plot_data_keeps_all_scenarios_and_uses_throughput_ratio(self) -> None:
        df = bench.pd.DataFrame(
            [
                {
                    "scenario": "http-over-https-proxy",
                    "requests": 200,
                    "repeat": 1,
                    "client": "ylong_http_client_sync",
                    "elapsed_ms": 80.0,
                    "latency_ms": 0.4,
                    "throughput_rps": 2500.0,
                    "p50_us": 80,
                    "p95_us": 120,
                    "cpu_us_per_request": 20.0,
                    "rss_peak_bytes": 1200,
                    "errors": 0,
                },
                {
                    "scenario": "http-over-https-proxy",
                    "requests": 200,
                    "repeat": 1,
                    "client": "libcurl",
                    "elapsed_ms": 100.0,
                    "latency_ms": 0.5,
                    "throughput_rps": 2000.0,
                    "p50_us": 100,
                    "p95_us": 150,
                    "cpu_us_per_request": 40.0,
                    "rss_peak_bytes": 1100,
                    "errors": 0,
                },
                {
                    "scenario": "proxy-mtls-https-origin",
                    "requests": 1000,
                    "repeat": 1,
                    "client": "ylong_http_client_sync",
                    "elapsed_ms": 500.0,
                    "latency_ms": 0.5,
                    "throughput_rps": 2000.0,
                    "p50_us": 120,
                    "p95_us": 160,
                    "cpu_us_per_request": 30.0,
                    "rss_peak_bytes": 1300,
                    "errors": 0,
                },
                {
                    "scenario": "proxy-mtls-https-origin",
                    "requests": 1000,
                    "repeat": 1,
                    "client": "libcurl",
                    "elapsed_ms": 400.0,
                    "latency_ms": 0.4,
                    "throughput_rps": 2500.0,
                    "p50_us": 100,
                    "p95_us": 140,
                    "cpu_us_per_request": 45.0,
                    "rss_peak_bytes": 1250,
                    "errors": 0,
                },
            ]
        )

        plot_data = bench.benchmark_ratio_plot_data(df, baseline="libcurl")

        self.assertEqual(
            plot_data["scenarios"],
            ["http-over-https-proxy", "proxy-mtls-https-origin"],
        )
        self.assertEqual(plot_data["requests"], [200, 1000])
        self.assertEqual(plot_data["candidate"], "ylong_http_client_sync")
        self.assertEqual(plot_data["ratio_source"], "paired")
        throughput = plot_data["matrices"]["throughput_rps_ratio"]
        self.assertAlmostEqual(throughput.loc["http-over-https-proxy", 200], 1.25)
        self.assertAlmostEqual(throughput.loc["proxy-mtls-https-origin", 1000], 0.8)

    def test_summary_keeps_concurrency_as_comparison_dimension(self) -> None:
        df = bench.pd.DataFrame(
            [
                {
                    "scenario": "s",
                    "requests": 10,
                    "concurrency": 1,
                    "repeat": 1,
                    "client": "ylong_http_client",
                    "elapsed_ms": 10.0,
                    "latency_ms": 1.0,
                    "throughput_rps": 1000.0,
                    "p50_us": 100,
                    "p95_us": 150,
                    "cpu_us_per_request": 20.0,
                    "rss_peak_bytes": 1000,
                    "errors": 0,
                },
                {
                    "scenario": "s",
                    "requests": 10,
                    "concurrency": 4,
                    "repeat": 1,
                    "client": "ylong_http_client",
                    "elapsed_ms": 4.0,
                    "latency_ms": 0.4,
                    "throughput_rps": 2500.0,
                    "p50_us": 40,
                    "p95_us": 60,
                    "cpu_us_per_request": 12.0,
                    "rss_peak_bytes": 1200,
                    "errors": 0,
                },
                {
                    "scenario": "s",
                    "requests": 10,
                    "concurrency": 1,
                    "repeat": 1,
                    "client": "libcurl",
                    "elapsed_ms": 20.0,
                    "latency_ms": 2.0,
                    "throughput_rps": 500.0,
                    "p50_us": 200,
                    "p95_us": 300,
                    "cpu_us_per_request": 40.0,
                    "rss_peak_bytes": 1100,
                    "errors": 0,
                },
                {
                    "scenario": "s",
                    "requests": 10,
                    "concurrency": 4,
                    "repeat": 1,
                    "client": "libcurl",
                    "elapsed_ms": 8.0,
                    "latency_ms": 0.8,
                    "throughput_rps": 1250.0,
                    "p50_us": 80,
                    "p95_us": 120,
                    "cpu_us_per_request": 24.0,
                    "rss_peak_bytes": 1300,
                    "errors": 0,
                },
            ]
        )
        summary = bench.summarize_results(df)
        self.assertIn("concurrency", summary.columns)
        self.assertEqual(sorted(summary["concurrency"].unique()), [1, 4])

        comparisons = bench.compare_to_baseline(summary, baseline="libcurl")
        ylong_concurrency_4 = comparisons[
            (comparisons["client"] == "ylong_http_client")
            & (comparisons["concurrency"] == 4)
        ].iloc[0]
        self.assertAlmostEqual(ylong_concurrency_4["elapsed_ms_ratio"], 0.5)

    def test_trace_output_is_parsed_and_summarized(self) -> None:
        rows = bench.parse_trace_output(
            "\n".join(
                [
                    "proxy_trace: scenario=s client=ylong_http_client connections=1 forward_requests=3 connect_requests=0 tunnel_bytes_from_client=0 tunnel_bytes_from_origin=0 tls_client_auth_failures=0",
                    "origin_trace: scenario=s client=ylong_http_client connections=0 requests=0 tls_connections=0",
                    "proxy_trace: scenario=s client=libcurl connections=1 forward_requests=3 connect_requests=0 tunnel_bytes_from_client=0 tunnel_bytes_from_origin=0 tls_client_auth_failures=0 request_header_bytes=120 request_body_bytes=0 response_body_bytes=12288 response_send_us=700 response_send_events=3 tunnel_send_to_client_us=900 tunnel_send_to_client_events=4 tunnel_send_to_origin_us=120 tunnel_send_to_origin_events=2",
                    "origin_trace: scenario=s client=libcurl connections=0 requests=0 tls_connections=0 request_header_bytes=0 request_body_bytes=0 response_body_bytes=0 response_send_us=500 response_send_events=3",
                ]
            )
        )
        self.assertEqual(len(rows), 2)
        by_client = {row.client: row for row in rows}
        self.assertEqual(by_client["ylong_http_client"].proxy_connections, 1)
        self.assertEqual(by_client["ylong_http_client"].proxy_forward_requests, 3)
        self.assertEqual(by_client["libcurl"].proxy_request_header_bytes, 120)
        self.assertEqual(by_client["libcurl"].proxy_response_body_bytes, 12288)
        self.assertEqual(by_client["libcurl"].proxy_response_send_us, 700)
        self.assertEqual(by_client["libcurl"].proxy_tunnel_send_to_client_us, 900)
        self.assertEqual(by_client["libcurl"].proxy_tunnel_send_to_origin_events, 2)
        self.assertEqual(by_client["libcurl"].origin_response_send_us, 500)
        self.assertEqual(by_client["libcurl"].origin_response_send_events, 3)
        self.assertIn("libcurl", by_client)

        df = bench.pd.DataFrame(
            [
                {
                    "scenario": "s",
                    "requests": 3,
                    "repeat": 1,
                    "client": "ylong_http_client",
                    "elapsed_ms": 1.0,
                    "latency_ms": 0.333,
                    "throughput_rps": 3000.0,
                    "p50_us": 100,
                    "p95_us": 120,
                    "cpu_us_per_request": 10.0,
                    "rss_peak_bytes": 1000,
                    "errors": 0,
                    "proxy_connections": 1,
                    "proxy_forward_requests": 3,
                    "proxy_connect_requests": 0,
                    "proxy_request_header_bytes": 120,
                    "proxy_request_body_bytes": 0,
                    "proxy_response_body_bytes": 12288,
                    "proxy_response_send_us": 700,
                    "proxy_response_send_events": 3,
                    "proxy_tunnel_send_to_client_us": 900,
                    "proxy_tunnel_send_to_client_events": 4,
                    "proxy_tunnel_send_to_origin_us": 120,
                    "proxy_tunnel_send_to_origin_events": 2,
                    "origin_connections": 0,
                    "origin_requests": 0,
                    "origin_tls_connections": 0,
                    "origin_request_header_bytes": 0,
                    "origin_request_body_bytes": 0,
                    "origin_response_body_bytes": 0,
                    "origin_response_send_us": 500,
                    "origin_response_send_events": 3,
                }
            ]
        )
        summary = bench.summarize_results(df)
        self.assertIn("proxy_connections_mean", summary.columns)
        self.assertIn("proxy_request_header_bytes_mean", summary.columns)
        self.assertIn("origin_requests_mean", summary.columns)
        self.assertIn("origin_request_header_bytes_mean", summary.columns)
        self.assertIn("proxy_response_send_us_mean", summary.columns)
        self.assertIn("proxy_tunnel_send_to_client_us_mean", summary.columns)
        self.assertIn("origin_response_send_us_mean", summary.columns)

    def test_trace_output_records_tls_fingerprints(self) -> None:
        rows = bench.parse_trace_output(
            "\n".join(
                [
                    "proxy_trace: scenario=s client=ylong_http_client connections=2 forward_requests=0 connect_requests=2 tunnel_bytes_from_client=10 tunnel_bytes_from_origin=20 tls_client_auth_failures=0 request_header_bytes=120 request_body_bytes=0 response_body_bytes=0 tls_fingerprints=TLSv1.3:TLS_AES_256_GCM_SHA384:256=2",
                    "origin_trace: scenario=s client=ylong_http_client connections=2 requests=4 tls_connections=2 request_header_bytes=240 request_body_bytes=0 response_body_bytes=16384 tls_fingerprints=TLSv1.3:TLS_AES_256_GCM_SHA384:256=2",
                ]
            )
        )
        self.assertEqual(len(rows), 1)
        trace = rows[0]
        self.assertEqual(
            trace.proxy_tls_fingerprints,
            {"TLSv1.3:TLS_AES_256_GCM_SHA384:256": 2},
        )
        self.assertEqual(
            trace.origin_tls_fingerprints,
            {"TLSv1.3:TLS_AES_256_GCM_SHA384:256": 2},
        )

        bench_result = bench.BenchResult(
            scenario="s",
            requests=4,
            repeat=1,
            client="ylong_http_client",
            elapsed_ms=1.0,
        )
        bench.attach_trace([bench_result], trace)
        self.assertEqual(
            bench_result.proxy_tls_fingerprints,
            "TLSv1.3:TLS_AES_256_GCM_SHA384:256=2",
        )
        self.assertEqual(
            bench_result.origin_tls_fingerprints,
            "TLSv1.3:TLS_AES_256_GCM_SHA384:256=2",
        )

        with tempfile.TemporaryDirectory() as tmp:
            summary = bench.summarize_results(
                bench.write_results([bench_result], result_dir=Path(tmp))
            )
            self.assertIn("proxy_tls_fingerprints", summary.columns)
            self.assertIn("origin_tls_fingerprints", summary.columns)
            self.assertEqual(
                summary["proxy_tls_fingerprints"].iloc[0],
                "TLSv1.3:TLS_AES_256_GCM_SHA384:256=2",
            )

    def test_trace_delta_preserves_repeated_tls_fingerprint_counts(self) -> None:
        before = bench.TraceResult(
            "s",
            "ylong_http_client",
            proxy_tls_fingerprints={"TLSv1.3:TLS_AES_256_GCM_SHA384:256": 2},
            origin_tls_fingerprints={"TLSv1.3:TLS_AES_256_GCM_SHA384:256": 2},
        )
        after = bench.TraceResult(
            "s",
            "ylong_http_client",
            proxy_tls_fingerprints={"TLSv1.3:TLS_AES_256_GCM_SHA384:256": 4},
            origin_tls_fingerprints={"TLSv1.3:TLS_AES_256_GCM_SHA384:256": 5},
        )

        delta = after.delta(before)

        self.assertEqual(
            delta.proxy_tls_fingerprints,
            {"TLSv1.3:TLS_AES_256_GCM_SHA384:256": 2},
        )
        self.assertEqual(
            delta.origin_tls_fingerprints,
            {"TLSv1.3:TLS_AES_256_GCM_SHA384:256": 3},
        )

    def test_phase_output_is_parsed_and_summarized(self) -> None:
        rows = bench.parse_output(
            "\n".join(
                [
                    "ylong_http_client: 1.5ms for 3 requests",
                    "ylong_http_client_stats: p50_us=100 p95_us=200 cpu_us=300 rss_peak_bytes=400 errors=0 for 3 requests",
                    "ylong_http_client_phase_us: request_build=9 request_execute=300 body_drain=90 connect=12 dns=3 tcp=4 tls=5 transfer=0 request_format=11 pool_checkout=22 send_on_conn=33 http1_write=44 http1_encode=45 http1_write_io=46 response_head=55 response_read=66 response_read_polls=6 response_read_pending=3 response_pre_read_bytes=12288 response_pre_read_events=3 response_intercept=77 response_decode=88 libcurl_perform=0 for 3 requests",
                    "ylong_http_client_tls_io: ssl_read_calls=100 ssl_read_pending=20 ssl_write_calls=30 ssl_write_pending=4 underlying_read_calls=120 underlying_read_pending=21 underlying_write_calls=35 underlying_write_pending=5 for 3 requests",
                    "libcurl: 1.2ms for 3 requests",
                    "libcurl_stats: p50_us=80 p95_us=160 cpu_us=240 rss_peak_bytes=380 errors=0 for 3 requests",
                    "libcurl_phase_us: request_build=0 request_execute=0 body_drain=0 connect=0 dns=0 tcp=0 tls=0 transfer=0 request_format=0 pool_checkout=0 send_on_conn=0 http1_write=0 http1_encode=0 http1_write_io=0 response_head=0 response_read=0 response_read_polls=0 response_read_pending=0 response_pre_read_bytes=0 response_pre_read_events=0 response_intercept=0 response_decode=0 libcurl_perform=360 for 3 requests",
                ]
            ),
            "s",
            3,
            1,
            {"ylong_http_client", "libcurl"},
        )
        by_client = {row.client: row for row in rows}
        self.assertEqual(by_client["ylong_http_client"].phase_request_build_us, 9)
        self.assertEqual(by_client["ylong_http_client"].phase_tls_us, 5)
        self.assertEqual(by_client["ylong_http_client"].phase_request_format_us, 11)
        self.assertEqual(by_client["ylong_http_client"].phase_pool_checkout_us, 22)
        self.assertEqual(by_client["ylong_http_client"].phase_send_on_conn_us, 33)
        self.assertEqual(by_client["ylong_http_client"].phase_http1_write_us, 44)
        self.assertEqual(by_client["ylong_http_client"].phase_http1_encode_us, 45)
        self.assertEqual(by_client["ylong_http_client"].phase_http1_write_io_us, 46)
        self.assertEqual(by_client["ylong_http_client"].phase_response_head_us, 55)
        self.assertEqual(by_client["ylong_http_client"].phase_response_read_us, 66)
        self.assertEqual(by_client["ylong_http_client"].phase_response_read_polls, 6)
        self.assertEqual(by_client["ylong_http_client"].phase_response_read_pending, 3)
        self.assertEqual(by_client["ylong_http_client"].phase_response_pre_read_bytes, 12288)
        self.assertEqual(by_client["ylong_http_client"].phase_response_pre_read_events, 3)
        self.assertEqual(by_client["ylong_http_client"].phase_response_intercept_us, 77)
        self.assertEqual(by_client["ylong_http_client"].phase_response_decode_us, 88)
        self.assertEqual(by_client["ylong_http_client"].tls_ssl_read_calls, 100)
        self.assertEqual(by_client["ylong_http_client"].tls_ssl_read_pending, 20)
        self.assertEqual(by_client["ylong_http_client"].tls_ssl_write_calls, 30)
        self.assertEqual(by_client["ylong_http_client"].tls_ssl_write_pending, 4)
        self.assertEqual(by_client["ylong_http_client"].tls_underlying_read_calls, 120)
        self.assertEqual(by_client["ylong_http_client"].tls_underlying_read_pending, 21)
        self.assertEqual(by_client["ylong_http_client"].tls_underlying_write_calls, 35)
        self.assertEqual(by_client["ylong_http_client"].tls_underlying_write_pending, 5)
        self.assertEqual(by_client["libcurl"].phase_libcurl_perform_us, 360)

        df = bench.pd.DataFrame(
            [
                {
                    "scenario": "s",
                    "requests": 3,
                    "repeat": 1,
                    "client": "ylong_http_client",
                    "elapsed_ms": 1.5,
                    "latency_ms": 0.5,
                    "throughput_rps": 2000.0,
                    "p50_us": 100,
                    "p95_us": 200,
                    "cpu_us_per_request": 100.0,
                    "rss_peak_bytes": 400,
                    "errors": 0,
                    "phase_request_build_us": 9,
                    "phase_request_execute_us": 300,
                    "phase_body_drain_us": 90,
                    "phase_connect_us": 12,
                    "phase_dns_us": 3,
                    "phase_tcp_us": 4,
                    "phase_tls_us": 5,
                    "phase_transfer_us": 0,
                    "phase_request_format_us": 11,
                    "phase_pool_checkout_us": 22,
                    "phase_send_on_conn_us": 33,
                    "phase_http1_write_us": 44,
                    "phase_http1_encode_us": 45,
                    "phase_http1_write_io_us": 46,
                    "phase_response_head_us": 55,
                    "phase_response_read_us": 66,
                    "phase_response_read_polls": 6,
                    "phase_response_read_pending": 3,
                    "phase_response_pre_read_bytes": 12288,
                    "phase_response_pre_read_events": 3,
                    "phase_response_intercept_us": 77,
                    "phase_response_decode_us": 88,
                    "phase_libcurl_perform_us": 0,
                    "tls_ssl_read_calls": 100,
                    "tls_ssl_read_pending": 20,
                    "tls_ssl_write_calls": 30,
                    "tls_ssl_write_pending": 4,
                    "tls_underlying_read_calls": 120,
                    "tls_underlying_read_pending": 21,
                    "tls_underlying_write_calls": 35,
                    "tls_underlying_write_pending": 5,
                }
            ]
        )
        summary = bench.summarize_results(df)
        self.assertIn("phase_request_build_us_mean", summary.columns)
        self.assertIn("phase_request_format_us_mean", summary.columns)
        self.assertIn("phase_http1_encode_us_mean", summary.columns)
        self.assertIn("phase_http1_write_io_us_mean", summary.columns)
        self.assertIn("phase_response_head_us_mean", summary.columns)
        self.assertIn("phase_response_read_us_mean", summary.columns)
        self.assertIn("phase_response_read_polls_mean", summary.columns)
        self.assertIn("phase_response_read_pending_mean", summary.columns)
        self.assertIn("phase_response_pre_read_bytes_mean", summary.columns)
        self.assertIn("phase_response_pre_read_events_mean", summary.columns)
        self.assertIn("phase_response_intercept_us_mean", summary.columns)
        self.assertIn("phase_response_decode_us_mean", summary.columns)
        self.assertIn("phase_libcurl_perform_us_mean", summary.columns)
        self.assertIn("tls_ssl_read_calls_mean", summary.columns)
        self.assertIn("tls_underlying_read_pending_mean", summary.columns)

    def test_write_results_can_use_diagnostic_result_dir(self) -> None:
        rows = [
            bench.BenchResult(
                scenario="s",
                requests=3,
                repeat=1,
                client="ylong_http_client",
                elapsed_ms=1.5,
            ),
            bench.BenchResult(
                scenario="s",
                requests=3,
                repeat=1,
                client="libcurl",
                elapsed_ms=1.2,
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            result_dir = Path(tmp)
            bench.write_results(rows, result_dir=result_dir)
            self.assertTrue((result_dir / "https_proxy_bench_results.csv").exists())
            self.assertTrue((result_dir / "https_proxy_bench_summary.csv").exists())
            self.assertTrue((result_dir / "https_proxy_bench_comparison.csv").exists())

    def test_plot_can_use_diagnostic_figure_dir(self) -> None:
        df = bench.pd.DataFrame(
            [
                {
                    "scenario": "s",
                    "requests": 3,
                    "repeat": 1,
                    "client": "ylong_http_client",
                    "elapsed_ms": 1.5,
                    "latency_ms": 0.5,
                    "throughput_rps": 2000.0,
                },
                {
                    "scenario": "s",
                    "requests": 3,
                    "repeat": 1,
                    "client": "libcurl",
                    "elapsed_ms": 1.2,
                    "latency_ms": 0.4,
                    "throughput_rps": 2500.0,
                },
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            figure_dir = Path(tmp)
            bench.plot(df, figure_dir=figure_dir)
            self.assertTrue((figure_dir / "https_proxy_bench_performance.pdf").exists())
            self.assertTrue((figure_dir / "https_proxy_bench_performance.png").exists())


if __name__ == "__main__":
    unittest.main()
