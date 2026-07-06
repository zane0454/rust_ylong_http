#!/usr/bin/env python3
"""Run and plot the ylong_http_client HTTPS proxy benchmark.

The script is intentionally self-contained so the benchmark can be rerun from a
Conda Python environment after building `https_proxy_bench`.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import platform
import re
import select
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
FIG_DIR = ROOT / "docs" / "figures"
RESULT_DIR = ROOT / "docs" / "benchmarks" / "results"
BENCH_BIN = ROOT / "target" / "release" / (
    "https_proxy_bench.exe" if os.name == "nt" else "https_proxy_bench"
)
TARGET_URL = "http://127.0.0.1:18080/bench"
BODY = b"x" * 4096
SCENARIOS = (
    "http-over-https-proxy",
    "https-over-https-proxy",
    "proxy-mtls-https-origin",
)
DURATION_RE = re.compile(
    r"^(ylong_http_client|ylong_http_client_sync|curl|curl_cli|libcurl): "
    r"([0-9.]+)([a-zA-Zµ]+) for (\d+) requests$"
)
STATS_RE = re.compile(
    r"^(ylong_http_client|ylong_http_client_sync|curl_cli|libcurl)_stats: "
    r"p50_us=(\d+) p95_us=(\d+) cpu_us=(\d+) rss_peak_bytes=(\d+) errors=(\d+) "
    r"for (\d+) requests$"
)
PHASE_RE = re.compile(
    r"^(ylong_http_client|libcurl)_phase_us: "
    r"request_build=(\d+) request_execute=(\d+) body_drain=(\d+) "
    r"connect=(\d+) dns=(\d+) tcp=(\d+) tls=(\d+) transfer=(\d+) "
    r"request_format=(\d+) pool_checkout=(\d+) send_on_conn=(\d+) "
    r"http1_write=(\d+) http1_encode=(\d+) http1_write_io=(\d+) response_head=(\d+) "
    r"response_read=(\d+) response_read_polls=(\d+) response_read_pending=(\d+) "
    r"response_pre_read_bytes=(\d+) response_pre_read_events=(\d+) "
    r"response_intercept=(\d+) response_decode=(\d+) "
    r"libcurl_perform=(\d+) for (\d+) requests$"
)
TLS_IO_RE = re.compile(
    r"^(ylong_http_client)_tls_io: "
    r"ssl_read_calls=(\d+) ssl_read_pending=(\d+) "
    r"ssl_write_calls=(\d+) ssl_write_pending=(\d+) "
    r"underlying_read_calls=(\d+) underlying_read_pending=(\d+) "
    r"underlying_write_calls=(\d+) underlying_write_pending=(\d+) "
    r"for (\d+) requests$"
)
BODY_RE = re.compile(
    r"^(ylong_http_client|ylong_http_client_sync|curl_cli|libcurl)_body_stats: "
    r"chunks=(\d+) bytes=(\d+) for (\d+) requests$"
)
PROXY_TRACE_RE = re.compile(
    r"^proxy_trace: scenario=(\S+) client=(\S+) connections=(\d+) "
    r"forward_requests=(\d+) connect_requests=(\d+) "
    r"tunnel_bytes_from_client=(\d+) tunnel_bytes_from_origin=(\d+) "
    r"tls_client_auth_failures=(\d+)"
    r"(?: request_header_bytes=(\d+) request_body_bytes=(\d+) response_body_bytes=(\d+))?"
    r"(?: response_send_us=(\d+) response_send_events=(\d+) "
    r"tunnel_send_to_client_us=(\d+) tunnel_send_to_client_events=(\d+) "
    r"tunnel_send_to_origin_us=(\d+) tunnel_send_to_origin_events=(\d+))?"
    r"(?: tls_fingerprints=([^\s]+))?$"
)
ORIGIN_TRACE_RE = re.compile(
    r"^origin_trace: scenario=(\S+) client=(\S+) connections=(\d+) "
    r"requests=(\d+) tls_connections=(\d+)"
    r"(?: request_header_bytes=(\d+) request_body_bytes=(\d+) response_body_bytes=(\d+))?"
    r"(?: response_send_us=(\d+) response_send_events=(\d+))?"
    r"(?: tls_fingerprints=([^\s]+))?$"
)


def negotiated_tls_fingerprint(conn: ssl.SSLSocket) -> str:
    version = conn.version() or "unknown"
    cipher = conn.cipher()
    if cipher is None:
        return f"{version}:unknown:0"
    cipher_name, _, bits = cipher
    return f"{version}:{cipher_name}:{bits}"


def format_tls_fingerprints(fingerprints: dict[str, int]) -> str:
    parts = [f"{name}={count}" for name, count in sorted(fingerprints.items()) if count > 0]
    return "|".join(parts) if parts else "-"


def parse_tls_fingerprints(value: str | None) -> dict[str, int]:
    if value in (None, "", "-"):
        return {}
    fingerprints: dict[str, int] = {}
    for item in value.split("|"):
        name, sep, count = item.rpartition("=")
        if not sep:
            continue
        fingerprints[name] = int(count)
    return fingerprints


def subtract_tls_fingerprints(
    current: dict[str, int], earlier: dict[str, int]
) -> dict[str, int]:
    delta = Counter(current)
    delta.subtract(earlier)
    return {name: count for name, count in sorted(delta.items()) if count > 0}


def add_tls_fingerprints(target: dict[str, int], source: dict[str, int]) -> None:
    for name, count in source.items():
        target[name] = target.get(name, 0) + count


def unique_tls_fingerprint_values(values: Iterable[str]) -> str:
    unique: set[str] = set()
    for value in values:
        if not value or value == "-":
            continue
        unique.update(part for part in str(value).split("|") if part and part != "-")
    return "|".join(sorted(unique)) if unique else "-"


@dataclass
class BenchResult:
    scenario: str
    requests: int
    repeat: int
    client: str
    elapsed_ms: float
    concurrency: int = 1
    ylong_concurrency_model: str = "threaded"
    p50_us: int = 0
    p95_us: int = 0
    cpu_us: int = 0
    rss_peak_bytes: int = 0
    errors: int = 0
    proxy_connections: int = 0
    proxy_forward_requests: int = 0
    proxy_connect_requests: int = 0
    proxy_tunnel_bytes_from_client: int = 0
    proxy_tunnel_bytes_from_origin: int = 0
    proxy_tls_client_auth_failures: int = 0
    proxy_request_header_bytes: int = 0
    proxy_request_body_bytes: int = 0
    proxy_response_body_bytes: int = 0
    proxy_response_send_us: int = 0
    proxy_response_send_events: int = 0
    proxy_tunnel_send_to_client_us: int = 0
    proxy_tunnel_send_to_client_events: int = 0
    proxy_tunnel_send_to_origin_us: int = 0
    proxy_tunnel_send_to_origin_events: int = 0
    origin_connections: int = 0
    origin_requests: int = 0
    origin_tls_connections: int = 0
    origin_request_header_bytes: int = 0
    origin_request_body_bytes: int = 0
    origin_response_body_bytes: int = 0
    origin_response_send_us: int = 0
    origin_response_send_events: int = 0
    phase_request_build_us: int = 0
    phase_request_execute_us: int = 0
    phase_body_drain_us: int = 0
    phase_connect_us: int = 0
    phase_dns_us: int = 0
    phase_tcp_us: int = 0
    phase_tls_us: int = 0
    phase_transfer_us: int = 0
    phase_request_format_us: int = 0
    phase_pool_checkout_us: int = 0
    phase_send_on_conn_us: int = 0
    phase_http1_write_us: int = 0
    phase_http1_encode_us: int = 0
    phase_http1_write_io_us: int = 0
    phase_response_head_us: int = 0
    phase_response_read_us: int = 0
    phase_response_read_polls: int = 0
    phase_response_read_pending: int = 0
    phase_response_pre_read_bytes: int = 0
    phase_response_pre_read_events: int = 0
    phase_response_intercept_us: int = 0
    phase_response_decode_us: int = 0
    phase_libcurl_perform_us: int = 0
    tls_ssl_read_calls: int = 0
    tls_ssl_read_pending: int = 0
    tls_ssl_write_calls: int = 0
    tls_ssl_write_pending: int = 0
    tls_underlying_read_calls: int = 0
    tls_underlying_read_pending: int = 0
    tls_underlying_write_calls: int = 0
    tls_underlying_write_pending: int = 0
    body_chunks: int = 0
    body_bytes: int = 0
    proxy_tls_fingerprints: str = "-"
    origin_tls_fingerprints: str = "-"

    @property
    def latency_ms(self) -> float:
        return self.elapsed_ms / self.requests

    @property
    def throughput_rps(self) -> float:
        return self.requests / (self.elapsed_ms / 1000.0)


@dataclass(frozen=True)
class BenchmarkCertificates:
    ca_file: Path
    ca_key_file: Path
    proxy_cert_file: Path
    proxy_key_file: Path
    origin_cert_file: Path
    origin_key_file: Path
    client_cert_file: Path
    client_key_file: Path


@dataclass
class TraceResult:
    scenario: str
    client: str
    proxy_connections: int = 0
    proxy_forward_requests: int = 0
    proxy_connect_requests: int = 0
    proxy_tunnel_bytes_from_client: int = 0
    proxy_tunnel_bytes_from_origin: int = 0
    proxy_tls_client_auth_failures: int = 0
    proxy_request_header_bytes: int = 0
    proxy_request_body_bytes: int = 0
    proxy_response_body_bytes: int = 0
    proxy_response_send_us: int = 0
    proxy_response_send_events: int = 0
    proxy_tunnel_send_to_client_us: int = 0
    proxy_tunnel_send_to_client_events: int = 0
    proxy_tunnel_send_to_origin_us: int = 0
    proxy_tunnel_send_to_origin_events: int = 0
    origin_connections: int = 0
    origin_requests: int = 0
    origin_tls_connections: int = 0
    origin_request_header_bytes: int = 0
    origin_request_body_bytes: int = 0
    origin_response_body_bytes: int = 0
    origin_response_send_us: int = 0
    origin_response_send_events: int = 0
    proxy_tls_fingerprints: dict[str, int] = field(default_factory=dict)
    origin_tls_fingerprints: dict[str, int] = field(default_factory=dict)

    def delta(self, earlier: "TraceResult") -> "TraceResult":
        return TraceResult(
            scenario=self.scenario,
            client=self.client,
            proxy_connections=self.proxy_connections - earlier.proxy_connections,
            proxy_forward_requests=self.proxy_forward_requests - earlier.proxy_forward_requests,
            proxy_connect_requests=self.proxy_connect_requests - earlier.proxy_connect_requests,
            proxy_tunnel_bytes_from_client=(
                self.proxy_tunnel_bytes_from_client - earlier.proxy_tunnel_bytes_from_client
            ),
            proxy_tunnel_bytes_from_origin=(
                self.proxy_tunnel_bytes_from_origin - earlier.proxy_tunnel_bytes_from_origin
            ),
            proxy_tls_client_auth_failures=(
                self.proxy_tls_client_auth_failures - earlier.proxy_tls_client_auth_failures
            ),
            proxy_request_header_bytes=(
                self.proxy_request_header_bytes - earlier.proxy_request_header_bytes
            ),
            proxy_request_body_bytes=(
                self.proxy_request_body_bytes - earlier.proxy_request_body_bytes
            ),
            proxy_response_body_bytes=(
                self.proxy_response_body_bytes - earlier.proxy_response_body_bytes
            ),
            proxy_response_send_us=(
                self.proxy_response_send_us - earlier.proxy_response_send_us
            ),
            proxy_response_send_events=(
                self.proxy_response_send_events - earlier.proxy_response_send_events
            ),
            proxy_tunnel_send_to_client_us=(
                self.proxy_tunnel_send_to_client_us
                - earlier.proxy_tunnel_send_to_client_us
            ),
            proxy_tunnel_send_to_client_events=(
                self.proxy_tunnel_send_to_client_events
                - earlier.proxy_tunnel_send_to_client_events
            ),
            proxy_tunnel_send_to_origin_us=(
                self.proxy_tunnel_send_to_origin_us
                - earlier.proxy_tunnel_send_to_origin_us
            ),
            proxy_tunnel_send_to_origin_events=(
                self.proxy_tunnel_send_to_origin_events
                - earlier.proxy_tunnel_send_to_origin_events
            ),
            origin_connections=self.origin_connections - earlier.origin_connections,
            origin_requests=self.origin_requests - earlier.origin_requests,
            origin_tls_connections=self.origin_tls_connections - earlier.origin_tls_connections,
            origin_request_header_bytes=(
                self.origin_request_header_bytes - earlier.origin_request_header_bytes
            ),
            origin_request_body_bytes=(
                self.origin_request_body_bytes - earlier.origin_request_body_bytes
            ),
            origin_response_body_bytes=(
                self.origin_response_body_bytes - earlier.origin_response_body_bytes
            ),
            origin_response_send_us=(
                self.origin_response_send_us - earlier.origin_response_send_us
            ),
            origin_response_send_events=(
                self.origin_response_send_events - earlier.origin_response_send_events
            ),
            proxy_tls_fingerprints=subtract_tls_fingerprints(
                self.proxy_tls_fingerprints, earlier.proxy_tls_fingerprints
            ),
            origin_tls_fingerprints=subtract_tls_fingerprints(
                self.origin_tls_fingerprints, earlier.origin_tls_fingerprints
            ),
        )

    def add_proxy(self, other: "TraceResult") -> None:
        self.proxy_connections += other.proxy_connections
        self.proxy_forward_requests += other.proxy_forward_requests
        self.proxy_connect_requests += other.proxy_connect_requests
        self.proxy_tunnel_bytes_from_client += other.proxy_tunnel_bytes_from_client
        self.proxy_tunnel_bytes_from_origin += other.proxy_tunnel_bytes_from_origin
        self.proxy_tls_client_auth_failures += other.proxy_tls_client_auth_failures
        self.proxy_request_header_bytes += other.proxy_request_header_bytes
        self.proxy_request_body_bytes += other.proxy_request_body_bytes
        self.proxy_response_body_bytes += other.proxy_response_body_bytes
        self.proxy_response_send_us += other.proxy_response_send_us
        self.proxy_response_send_events += other.proxy_response_send_events
        self.proxy_tunnel_send_to_client_us += other.proxy_tunnel_send_to_client_us
        self.proxy_tunnel_send_to_client_events += other.proxy_tunnel_send_to_client_events
        self.proxy_tunnel_send_to_origin_us += other.proxy_tunnel_send_to_origin_us
        self.proxy_tunnel_send_to_origin_events += other.proxy_tunnel_send_to_origin_events
        add_tls_fingerprints(self.proxy_tls_fingerprints, other.proxy_tls_fingerprints)

    def add_origin(self, other: "TraceResult") -> None:
        self.origin_connections += other.origin_connections
        self.origin_requests += other.origin_requests
        self.origin_tls_connections += other.origin_tls_connections
        self.origin_request_header_bytes += other.origin_request_header_bytes
        self.origin_request_body_bytes += other.origin_request_body_bytes
        self.origin_response_body_bytes += other.origin_response_body_bytes
        self.origin_response_send_us += other.origin_response_send_us
        self.origin_response_send_events += other.origin_response_send_events
        add_tls_fingerprints(self.origin_tls_fingerprints, other.origin_tls_fingerprints)

    def proxy_line(self) -> str:
        return (
            f"proxy_trace: scenario={self.scenario} client={self.client} "
            f"connections={self.proxy_connections} "
            f"forward_requests={self.proxy_forward_requests} "
            f"connect_requests={self.proxy_connect_requests} "
            f"tunnel_bytes_from_client={self.proxy_tunnel_bytes_from_client} "
            f"tunnel_bytes_from_origin={self.proxy_tunnel_bytes_from_origin} "
            f"tls_client_auth_failures={self.proxy_tls_client_auth_failures} "
            f"request_header_bytes={self.proxy_request_header_bytes} "
            f"request_body_bytes={self.proxy_request_body_bytes} "
            f"response_body_bytes={self.proxy_response_body_bytes} "
            f"response_send_us={self.proxy_response_send_us} "
            f"response_send_events={self.proxy_response_send_events} "
            f"tunnel_send_to_client_us={self.proxy_tunnel_send_to_client_us} "
            f"tunnel_send_to_client_events={self.proxy_tunnel_send_to_client_events} "
            f"tunnel_send_to_origin_us={self.proxy_tunnel_send_to_origin_us} "
            f"tunnel_send_to_origin_events={self.proxy_tunnel_send_to_origin_events} "
            f"tls_fingerprints={format_tls_fingerprints(self.proxy_tls_fingerprints)}"
        )

    def origin_line(self) -> str:
        return (
            f"origin_trace: scenario={self.scenario} client={self.client} "
            f"connections={self.origin_connections} "
            f"requests={self.origin_requests} "
            f"tls_connections={self.origin_tls_connections} "
            f"request_header_bytes={self.origin_request_header_bytes} "
            f"request_body_bytes={self.origin_request_body_bytes} "
            f"response_body_bytes={self.origin_response_body_bytes} "
            f"response_send_us={self.origin_response_send_us} "
            f"response_send_events={self.origin_response_send_events} "
            f"tls_fingerprints={format_tls_fingerprints(self.origin_tls_fingerprints)}"
        )


def empty_trace(scenario: str, client: str) -> TraceResult:
    return TraceResult(scenario=scenario, client=client)


class LocalOriginServer:
    def __init__(
        self,
        body: bytes,
        *,
        cert_file: Path | None = None,
        key_file: Path | None = None,
    ) -> None:
        self.body = body
        self.cert_file = cert_file
        self.key_file = key_file
        self.stop_event = threading.Event()
        self.threads: list[threading.Thread] = []
        self.sock: socket.socket | None = None
        self.ctx: ssl.SSLContext | None = None
        self.port = 0
        self.trace = empty_trace("", "")
        self.trace_lock = threading.Lock()

    def __enter__(self) -> "LocalOriginServer":
        if self.cert_file is not None and self.key_file is not None:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.cert_file, self.key_file)
            self.ctx = ctx
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(128)
        sock.settimeout(0.2)
        self.sock = sock
        self.port = sock.getsockname()[1]
        thread = threading.Thread(target=self._serve, name="origin-server", daemon=True)
        thread.start()
        self.threads.append(thread)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop_event.set()
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        for thread in self.threads:
            thread.join(timeout=1.0)

    @property
    def url(self) -> str:
        scheme = "https" if self.ctx is not None else "http"
        return f"{scheme}://127.0.0.1:{self.port}/bench"

    def _serve(self) -> None:
        assert self.sock is not None
        while not self.stop_event.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            thread.start()
            self.threads.append(thread)

    def _handle(self, raw: socket.socket) -> None:
        try:
            if self.ctx is not None:
                conn = self.ctx.wrap_socket(raw, server_side=True)
                tls_fingerprint = negotiated_tls_fingerprint(conn)
                with self.trace_lock:
                    self.trace.origin_tls_connections += 1
                    self.trace.origin_tls_fingerprints[tls_fingerprint] = (
                        self.trace.origin_tls_fingerprints.get(tls_fingerprint, 0) + 1
                    )
            else:
                conn = raw
            with self.trace_lock:
                self.trace.origin_connections += 1
            with conn:
                conn.settimeout(5.0)
                data = bytearray()
                while not self.stop_event.is_set():
                    header_end = LocalHttpsProxy._read_headers(conn, data)
                    if header_end is None:
                        return
                    with self.trace_lock:
                        self.trace.origin_requests += 1
                    header = bytes(data[:header_end])
                    remaining = data[header_end + 4 :]
                    content_length = LocalHttpsProxy._content_length(header)
                    while len(remaining) < content_length:
                        chunk = conn.recv(65536)
                        if not chunk:
                            return
                        remaining.extend(chunk)
                    data = bytearray(remaining[content_length:])
                    should_close = b"connection: close" in header.lower()
                    response = (
                        b"HTTP/1.1 200 OK\r\n"
                        + f"Content-Length: {len(self.body)}\r\n".encode("ascii")
                        + (
                            b"Connection: close\r\n"
                            if should_close
                            else b"Connection: keep-alive\r\n"
                        )
                        + b"Content-Type: application/octet-stream\r\n\r\n"
                        + self.body
                    )
                    with self.trace_lock:
                        self.trace.origin_request_header_bytes += header_end + 4
                        self.trace.origin_request_body_bytes += content_length
                        self.trace.origin_response_body_bytes += len(self.body)
                    send_start = time.perf_counter_ns()
                    conn.sendall(response)
                    send_us = (time.perf_counter_ns() - send_start) // 1000
                    with self.trace_lock:
                        self.trace.origin_response_send_us += send_us
                        self.trace.origin_response_send_events += 1
                    if should_close:
                        return
        except (OSError, ssl.SSLError):
            return

    def snapshot(self, scenario: str, client: str) -> TraceResult:
        with self.trace_lock:
            trace = TraceResult(**self.trace.__dict__)
            trace.proxy_tls_fingerprints = dict(self.trace.proxy_tls_fingerprints)
            trace.origin_tls_fingerprints = dict(self.trace.origin_tls_fingerprints)
        trace.scenario = scenario
        trace.client = client
        return trace


class LocalHttpsProxy:
    def __init__(
        self,
        cert_file: Path,
        key_file: Path,
        body: bytes,
        *,
        client_ca_file: Path | None = None,
    ) -> None:
        self.cert_file = cert_file
        self.key_file = key_file
        self.body = body
        self.client_ca_file = client_ca_file
        self.stop_event = threading.Event()
        self.threads: list[threading.Thread] = []
        self.sock: socket.socket | None = None
        self.port = 0
        self.trace = empty_trace("", "")
        self.trace_lock = threading.Lock()

    def __enter__(self) -> "LocalHttpsProxy":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert_file, self.key_file)
        if self.client_ca_file is not None:
            ctx.load_verify_locations(cafile=str(self.client_ca_file))
            ctx.verify_mode = ssl.CERT_REQUIRED
        self.ctx = ctx
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(128)
        sock.settimeout(0.2)
        self.sock = sock
        self.port = sock.getsockname()[1]
        thread = threading.Thread(target=self._serve, name="https-proxy", daemon=True)
        thread.start()
        self.threads.append(thread)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop_event.set()
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        for thread in self.threads:
            thread.join(timeout=1.0)

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}"

    def _serve(self) -> None:
        assert self.sock is not None
        while not self.stop_event.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            thread.start()
            self.threads.append(thread)

    def _handle(self, raw: socket.socket) -> None:
        try:
            conn = self.ctx.wrap_socket(raw, server_side=True)
            tls_fingerprint = negotiated_tls_fingerprint(conn)
        except ssl.SSLError:
            with self.trace_lock:
                self.trace.proxy_tls_client_auth_failures += 1
            raw.close()
            return
        except OSError:
            raw.close()
            return

        try:
            with conn:
                with self.trace_lock:
                    self.trace.proxy_connections += 1
                    self.trace.proxy_tls_fingerprints[tls_fingerprint] = (
                        self.trace.proxy_tls_fingerprints.get(tls_fingerprint, 0) + 1
                    )
                conn.settimeout(5.0)
                data = bytearray()
                while not self.stop_event.is_set():
                    header_end = self._read_headers(conn, data)
                    if header_end is None:
                        return
                    header = bytes(data[:header_end])
                    remaining = data[header_end + 4 :]
                    content_length = self._content_length(header)
                    while len(remaining) < content_length:
                        chunk = conn.recv(65536)
                        if not chunk:
                            return
                        remaining.extend(chunk)
                    data = bytearray(remaining[content_length:])
                    first_line = header.split(b"\r\n", 1)[0]
                    with self.trace_lock:
                        self.trace.proxy_request_header_bytes += header_end + 4
                        self.trace.proxy_request_body_bytes += content_length
                    if first_line.startswith(b"CONNECT "):
                        with self.trace_lock:
                            self.trace.proxy_connect_requests += 1
                        host, port = self._connect_target(first_line)
                        with socket.create_connection((host, port), timeout=5.0) as upstream:
                            if remaining:
                                upstream.sendall(remaining)
                                remaining.clear()
                            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                            self._relay(conn, upstream)
                        return
                    response = (
                        b"HTTP/1.1 200 OK\r\n"
                        + f"Content-Length: {len(self.body)}\r\n".encode("ascii")
                        + b"Connection: keep-alive\r\n"
                        + b"Content-Type: application/octet-stream\r\n\r\n"
                        + self.body
                    )
                    with self.trace_lock:
                        self.trace.proxy_forward_requests += 1
                        self.trace.proxy_response_body_bytes += len(self.body)
                    send_start = time.perf_counter_ns()
                    conn.sendall(response)
                    send_us = (time.perf_counter_ns() - send_start) // 1000
                    with self.trace_lock:
                        self.trace.proxy_response_send_us += send_us
                        self.trace.proxy_response_send_events += 1
        except (OSError, ssl.SSLError):
            return

    def _relay(self, client: ssl.SSLSocket, upstream: socket.socket) -> None:
        sockets: list[socket.socket] = [client, upstream]
        while not self.stop_event.is_set():
            try:
                readable, _, _ = select.select(sockets, [], [], 5.0)
            except (OSError, ValueError):
                return
            if not readable:
                continue
            for source in readable:
                target = upstream if source is client else client
                try:
                    chunk = source.recv(65536)
                    if not chunk:
                        return
                    with self.trace_lock:
                        if source is client:
                            self.trace.proxy_tunnel_bytes_from_client += len(chunk)
                        else:
                            self.trace.proxy_tunnel_bytes_from_origin += len(chunk)
                    send_start = time.perf_counter_ns()
                    target.sendall(chunk)
                    send_us = (time.perf_counter_ns() - send_start) // 1000
                    with self.trace_lock:
                        if source is client:
                            self.trace.proxy_tunnel_send_to_origin_us += send_us
                            self.trace.proxy_tunnel_send_to_origin_events += 1
                        else:
                            self.trace.proxy_tunnel_send_to_client_us += send_us
                            self.trace.proxy_tunnel_send_to_client_events += 1
                except (OSError, ssl.SSLError):
                    return

    def snapshot(self, scenario: str, client: str) -> TraceResult:
        with self.trace_lock:
            trace = TraceResult(**self.trace.__dict__)
            trace.proxy_tls_fingerprints = dict(self.trace.proxy_tls_fingerprints)
            trace.origin_tls_fingerprints = dict(self.trace.origin_tls_fingerprints)
        trace.scenario = scenario
        trace.client = client
        return trace

    @staticmethod
    def _connect_target(first_line: bytes) -> tuple[str, int]:
        parts = first_line.split()
        if len(parts) < 2:
            raise OSError(f"malformed CONNECT line: {first_line!r}")
        authority = parts[1].decode("ascii")
        if authority.startswith("["):
            host, _, rest = authority[1:].partition("]")
            if not rest.startswith(":"):
                raise OSError(f"CONNECT target is missing port: {authority}")
            port = rest[1:]
        else:
            host, sep, port = authority.rpartition(":")
            if not sep:
                raise OSError(f"CONNECT target is missing port: {authority}")
        return host, int(port)

    @staticmethod
    def _read_headers(conn: ssl.SSLSocket, data: bytearray) -> int | None:
        while b"\r\n\r\n" not in data:
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                return None
            if not chunk:
                return None
            data.extend(chunk)
        return data.index(b"\r\n\r\n")

    @staticmethod
    def _content_length(header: bytes) -> int:
        for line in header.split(b"\r\n")[1:]:
            key, _, value = line.partition(b":")
            if key.strip().lower() == b"content-length":
                return int(value.strip() or b"0")
        return 0


def ensure_benchmark_certificates(work_dir: Path) -> BenchmarkCertificates:
    certs = BenchmarkCertificates(
        ca_file=work_dir / "https_proxy_bench_ca.crt",
        ca_key_file=work_dir / "https_proxy_bench_ca.key",
        proxy_cert_file=work_dir / "https_proxy_bench_proxy.crt",
        proxy_key_file=work_dir / "https_proxy_bench_proxy.key",
        origin_cert_file=work_dir / "https_proxy_bench_origin.crt",
        origin_key_file=work_dir / "https_proxy_bench_origin.key",
        client_cert_file=work_dir / "https_proxy_bench_client.crt",
        client_key_file=work_dir / "https_proxy_bench_client.key",
    )
    if all(path.exists() for path in certs.__dict__.values()):
        return certs

    preferred = Path("D:/msys64/mingw64/bin/openssl.exe")
    openssl = str(preferred) if preferred.exists() else shutil.which("openssl")
    if openssl is None:
        raise RuntimeError("openssl not found; source rust-env.ps1 before running this script")

    def run(cmd: list[str]) -> None:
        completed = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if completed.returncode != 0:
            raise RuntimeError(
                "openssl certificate generation failed:\n"
                + completed.stdout
                + completed.stderr
            )

    run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-keyout",
            str(certs.ca_key_file),
            "-out",
            str(certs.ca_file),
            "-subj",
            "/CN=ylong-http-benchmark-ca",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]
    )
    _sign_certificate(
        openssl,
        work_dir,
        certs.ca_file,
        certs.ca_key_file,
        "proxy",
        "/CN=127.0.0.1",
        "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n",
        certs.proxy_cert_file,
        certs.proxy_key_file,
    )
    _sign_certificate(
        openssl,
        work_dir,
        certs.ca_file,
        certs.ca_key_file,
        "origin",
        "/CN=127.0.0.1",
        "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n",
        certs.origin_cert_file,
        certs.origin_key_file,
    )
    _sign_certificate(
        openssl,
        work_dir,
        certs.ca_file,
        certs.ca_key_file,
        "client",
        "/CN=ylong-http-benchmark-client",
        "extendedKeyUsage=clientAuth\n",
        certs.client_cert_file,
        certs.client_key_file,
    )
    return certs


def ensure_certificates(work_dir: Path) -> tuple[Path, Path]:
    certs = ensure_benchmark_certificates(work_dir)
    return certs.proxy_cert_file, certs.proxy_key_file


def _sign_certificate(
    openssl: str,
    work_dir: Path,
    ca_file: Path,
    ca_key_file: Path,
    name: str,
    subject: str,
    extensions: str,
    cert_file: Path,
    key_file: Path,
) -> None:
    csr_file = work_dir / f"https_proxy_bench_{name}.csr"
    ext_file = work_dir / f"https_proxy_bench_{name}.ext"
    serial_file = work_dir / "https_proxy_bench_ca.srl"
    ext_file.write_text(extensions, encoding="utf-8")
    req_cmd = [
        openssl,
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key_file),
        "-out",
        str(csr_file),
        "-subj",
        subject,
    ]
    sign_cmd = [
        openssl,
        "x509",
        "-req",
        "-in",
        str(csr_file),
        "-CA",
        str(ca_file),
        "-CAkey",
        str(ca_key_file),
        "-CAserial",
        str(serial_file),
        "-CAcreateserial",
        "-out",
        str(cert_file),
        "-days",
        "2",
        "-sha256",
        "-extfile",
        str(ext_file),
    ]
    for cmd in (req_cmd, sign_cmd):
        completed = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if completed.returncode != 0:
            raise RuntimeError(
                "openssl certificate generation failed:\n"
                + completed.stdout
                + completed.stderr
            )


def duration_to_ms(value: str, unit: str) -> float:
    scalar = float(value)
    if unit == "s":
        return scalar * 1000.0
    if unit == "ms":
        return scalar
    if unit in {"us", "µs"}:
        return scalar / 1000.0
    if unit == "ns":
        return scalar / 1_000_000.0
    raise ValueError(f"unsupported duration unit: {unit}")


def client_label(client: str) -> str:
    if client == "curl":
        return "curl_cli"
    return client


def parse_output(
    stdout: str,
    scenario: str,
    requests: int,
    repeat: int,
    expected_clients: set[str],
    concurrency: int = 1,
    ylong_concurrency_model: str = "threaded",
) -> list[BenchResult]:
    rows: list[BenchResult] = []
    stats: dict[str, dict[str, int]] = {}
    phases: dict[str, dict[str, int]] = {}
    tls_io: dict[str, dict[str, int]] = {}
    body_stats: dict[str, dict[str, int]] = {}
    for line in stdout.splitlines():
        line = line.strip()
        stats_match = STATS_RE.match(line)
        if stats_match:
            client, p50, p95, cpu, rss, errors, count = stats_match.groups()
            if int(count) == requests:
                stats[client_label(client)] = {
                    "p50_us": int(p50),
                    "p95_us": int(p95),
                    "cpu_us": int(cpu),
                    "rss_peak_bytes": int(rss),
                    "errors": int(errors),
                }
            continue

        phase_match = PHASE_RE.match(line)
        if phase_match:
            (
                client,
                request_build,
                request_execute,
                body_drain,
                connect,
                dns,
                tcp,
                tls,
                transfer,
                request_format,
                pool_checkout,
                send_on_conn,
                http1_write,
                http1_encode,
                http1_write_io,
                response_head,
                response_read,
                response_read_polls,
                response_read_pending,
                response_pre_read_bytes,
                response_pre_read_events,
                response_intercept,
                response_decode,
                libcurl_perform,
                count,
            ) = phase_match.groups()
            if int(count) == requests:
                phases[client_label(client)] = {
                    "phase_request_build_us": int(request_build),
                    "phase_request_execute_us": int(request_execute),
                    "phase_body_drain_us": int(body_drain),
                    "phase_connect_us": int(connect),
                    "phase_dns_us": int(dns),
                    "phase_tcp_us": int(tcp),
                    "phase_tls_us": int(tls),
                    "phase_transfer_us": int(transfer),
                    "phase_request_format_us": int(request_format),
                    "phase_pool_checkout_us": int(pool_checkout),
                    "phase_send_on_conn_us": int(send_on_conn),
                    "phase_http1_write_us": int(http1_write),
                    "phase_http1_encode_us": int(http1_encode),
                    "phase_http1_write_io_us": int(http1_write_io),
                    "phase_response_head_us": int(response_head),
                    "phase_response_read_us": int(response_read),
                    "phase_response_read_polls": int(response_read_polls),
                    "phase_response_read_pending": int(response_read_pending),
                    "phase_response_pre_read_bytes": int(response_pre_read_bytes),
                    "phase_response_pre_read_events": int(response_pre_read_events),
                    "phase_response_intercept_us": int(response_intercept),
                    "phase_response_decode_us": int(response_decode),
                    "phase_libcurl_perform_us": int(libcurl_perform),
                }
            continue

        tls_io_match = TLS_IO_RE.match(line)
        if tls_io_match:
            (
                client,
                ssl_read_calls,
                ssl_read_pending,
                ssl_write_calls,
                ssl_write_pending,
                underlying_read_calls,
                underlying_read_pending,
                underlying_write_calls,
                underlying_write_pending,
                count,
            ) = tls_io_match.groups()
            if int(count) == requests:
                tls_io[client_label(client)] = {
                    "tls_ssl_read_calls": int(ssl_read_calls),
                    "tls_ssl_read_pending": int(ssl_read_pending),
                    "tls_ssl_write_calls": int(ssl_write_calls),
                    "tls_ssl_write_pending": int(ssl_write_pending),
                    "tls_underlying_read_calls": int(underlying_read_calls),
                    "tls_underlying_read_pending": int(underlying_read_pending),
                    "tls_underlying_write_calls": int(underlying_write_calls),
                    "tls_underlying_write_pending": int(underlying_write_pending),
                }
            continue

        body_match = BODY_RE.match(line)
        if body_match:
            client, chunks, body_bytes, count = body_match.groups()
            if int(count) == requests:
                body_stats[client_label(client)] = {
                    "body_chunks": int(chunks),
                    "body_bytes": int(body_bytes),
                }
            continue

        match = DURATION_RE.match(line)
        if not match:
            continue
        client, value, unit, count = match.groups()
        if int(count) != requests:
            continue
        client = client_label(client)
        rows.append(
            BenchResult(
                scenario=scenario,
                requests=requests,
                concurrency=concurrency,
                repeat=repeat,
                client=client,
                elapsed_ms=duration_to_ms(value, unit),
                ylong_concurrency_model=ylong_concurrency_model,
            )
        )
    for row in rows:
        client_stats = stats.get(row.client)
        if client_stats:
            row.p50_us = client_stats["p50_us"]
            row.p95_us = client_stats["p95_us"]
            row.cpu_us = client_stats["cpu_us"]
            row.rss_peak_bytes = client_stats["rss_peak_bytes"]
            row.errors = client_stats["errors"]
        client_phases = phases.get(row.client)
        if client_phases:
            row.phase_request_build_us = client_phases["phase_request_build_us"]
            row.phase_request_execute_us = client_phases["phase_request_execute_us"]
            row.phase_body_drain_us = client_phases["phase_body_drain_us"]
            row.phase_connect_us = client_phases["phase_connect_us"]
            row.phase_dns_us = client_phases["phase_dns_us"]
            row.phase_tcp_us = client_phases["phase_tcp_us"]
            row.phase_tls_us = client_phases["phase_tls_us"]
            row.phase_transfer_us = client_phases["phase_transfer_us"]
            row.phase_request_format_us = client_phases["phase_request_format_us"]
            row.phase_pool_checkout_us = client_phases["phase_pool_checkout_us"]
            row.phase_send_on_conn_us = client_phases["phase_send_on_conn_us"]
            row.phase_http1_write_us = client_phases["phase_http1_write_us"]
            row.phase_http1_encode_us = client_phases["phase_http1_encode_us"]
            row.phase_http1_write_io_us = client_phases["phase_http1_write_io_us"]
            row.phase_response_head_us = client_phases["phase_response_head_us"]
            row.phase_response_read_us = client_phases["phase_response_read_us"]
            row.phase_response_read_polls = client_phases["phase_response_read_polls"]
            row.phase_response_read_pending = client_phases["phase_response_read_pending"]
            row.phase_response_pre_read_bytes = client_phases[
                "phase_response_pre_read_bytes"
            ]
            row.phase_response_pre_read_events = client_phases[
                "phase_response_pre_read_events"
            ]
            row.phase_response_intercept_us = client_phases["phase_response_intercept_us"]
            row.phase_response_decode_us = client_phases["phase_response_decode_us"]
            row.phase_libcurl_perform_us = client_phases["phase_libcurl_perform_us"]
        client_tls_io = tls_io.get(row.client)
        if client_tls_io:
            row.tls_ssl_read_calls = client_tls_io["tls_ssl_read_calls"]
            row.tls_ssl_read_pending = client_tls_io["tls_ssl_read_pending"]
            row.tls_ssl_write_calls = client_tls_io["tls_ssl_write_calls"]
            row.tls_ssl_write_pending = client_tls_io["tls_ssl_write_pending"]
            row.tls_underlying_read_calls = client_tls_io["tls_underlying_read_calls"]
            row.tls_underlying_read_pending = client_tls_io["tls_underlying_read_pending"]
            row.tls_underlying_write_calls = client_tls_io["tls_underlying_write_calls"]
            row.tls_underlying_write_pending = client_tls_io["tls_underlying_write_pending"]
        client_body_stats = body_stats.get(row.client)
        if client_body_stats:
            row.body_chunks = client_body_stats["body_chunks"]
            row.body_bytes = client_body_stats["body_bytes"]
    clients = {row.client for row in rows}
    if clients != expected_clients:
        raise RuntimeError(f"failed to parse benchmark output:\n{stdout}")
    return rows


def parse_trace_output(stdout: str) -> list[TraceResult]:
    traces: dict[tuple[str, str], TraceResult] = {}
    for line in stdout.splitlines():
        line = line.strip()
        proxy_match = PROXY_TRACE_RE.match(line)
        if proxy_match:
            (
                scenario,
                client,
                connections,
                forward_requests,
                connect_requests,
                tunnel_from_client,
                tunnel_from_origin,
                tls_client_auth_failures,
                request_header_bytes,
                request_body_bytes,
                response_body_bytes,
                response_send_us,
                response_send_events,
                tunnel_send_to_client_us,
                tunnel_send_to_client_events,
                tunnel_send_to_origin_us,
                tunnel_send_to_origin_events,
                tls_fingerprints,
            ) = proxy_match.groups()
            key = (scenario, client_label(client))
            trace = traces.setdefault(key, TraceResult(scenario, client_label(client)))
            trace.proxy_connections = int(connections)
            trace.proxy_forward_requests = int(forward_requests)
            trace.proxy_connect_requests = int(connect_requests)
            trace.proxy_tunnel_bytes_from_client = int(tunnel_from_client)
            trace.proxy_tunnel_bytes_from_origin = int(tunnel_from_origin)
            trace.proxy_tls_client_auth_failures = int(tls_client_auth_failures)
            trace.proxy_request_header_bytes = int(request_header_bytes or 0)
            trace.proxy_request_body_bytes = int(request_body_bytes or 0)
            trace.proxy_response_body_bytes = int(response_body_bytes or 0)
            trace.proxy_response_send_us = int(response_send_us or 0)
            trace.proxy_response_send_events = int(response_send_events or 0)
            trace.proxy_tunnel_send_to_client_us = int(tunnel_send_to_client_us or 0)
            trace.proxy_tunnel_send_to_client_events = int(
                tunnel_send_to_client_events or 0
            )
            trace.proxy_tunnel_send_to_origin_us = int(tunnel_send_to_origin_us or 0)
            trace.proxy_tunnel_send_to_origin_events = int(
                tunnel_send_to_origin_events or 0
            )
            trace.proxy_tls_fingerprints = parse_tls_fingerprints(tls_fingerprints)
            continue
        origin_match = ORIGIN_TRACE_RE.match(line)
        if origin_match:
            (
                scenario,
                client,
                connections,
                requests,
                tls_connections,
                request_header_bytes,
                request_body_bytes,
                response_body_bytes,
                response_send_us,
                response_send_events,
                tls_fingerprints,
            ) = origin_match.groups()
            key = (scenario, client_label(client))
            trace = traces.setdefault(key, TraceResult(scenario, client_label(client)))
            trace.origin_connections = int(connections)
            trace.origin_requests = int(requests)
            trace.origin_tls_connections = int(tls_connections)
            trace.origin_request_header_bytes = int(request_header_bytes or 0)
            trace.origin_request_body_bytes = int(request_body_bytes or 0)
            trace.origin_response_body_bytes = int(response_body_bytes or 0)
            trace.origin_response_send_us = int(response_send_us or 0)
            trace.origin_response_send_events = int(response_send_events or 0)
            trace.origin_tls_fingerprints = parse_tls_fingerprints(tls_fingerprints)
    return [traces[key] for key in sorted(traces)]


def build_benchmark_env(
    *,
    proxy_url: str,
    target_url: str,
    curl: str | None,
    baseline: str,
    requests: int,
    warmup: int,
    certs: BenchmarkCertificates | None = None,
    proxy_mtls: bool = False,
    origin_tls: bool = False,
    proxy_insecure: bool = False,
    origin_insecure: bool = False,
    client: str | None = None,
    phase_timing: bool = False,
    concurrency: int = 1,
    ylong_concurrency_model: str = "threaded",
) -> tuple[dict[str, str], set[str]]:
    env = os.environ.copy()
    env.update(
        {
            "NO_PROXY": "",
            "no_proxy": "",
            "HTTP_PROXY": "",
            "HTTPS_PROXY": "",
            "http_proxy": "",
            "https_proxy": "",
            "YLONG_BENCH_URL": target_url,
            "YLONG_HTTPS_PROXY": proxy_url,
            "YLONG_BENCH_REQUESTS": str(requests),
            "YLONG_BENCH_WARMUP": str(warmup),
            "YLONG_BENCH_CONCURRENCY": str(concurrency),
            "YLONG_BENCH_YLONG_CONCURRENCY_MODEL": ylong_concurrency_model,
            "YLONG_CURL_OUTPUT": "NUL" if os.name == "nt" else "/dev/null",
        }
    )
    if client is not None:
        env["YLONG_BENCH_CLIENTS"] = client
    if phase_timing:
        env["YLONG_BENCH_PHASES"] = "1"

    if proxy_insecure:
        env["YLONG_PROXY_INSECURE"] = "1"
    elif certs is not None:
        env["YLONG_PROXY_CA_FILE"] = str(certs.ca_file)

    if origin_insecure:
        env["YLONG_ORIGIN_INSECURE"] = "1"
    elif origin_tls and certs is not None:
        env["YLONG_ORIGIN_CA_FILE"] = str(certs.ca_file)

    if proxy_mtls:
        if certs is None:
            raise RuntimeError("proxy_mtls requires benchmark certificates")
        env["YLONG_PROXY_CERT_FILE"] = str(certs.client_cert_file)
        env["YLONG_PROXY_KEY_FILE"] = str(certs.client_key_file)

    expected_clients = {client_label(client)} if client is not None else {"ylong_http_client"}
    needs_curl_cli = baseline in {"curl-cli", "both"} or client == "curl-cli"
    needs_libcurl = baseline in {"libcurl", "both"} or client == "libcurl"
    if needs_curl_cli:
        if curl is None:
            raise RuntimeError("curl CLI baseline requested, but curl was not found")
        env["YLONG_CURL"] = curl
        if client is None:
            expected_clients.add("curl_cli")
    if needs_libcurl:
        env["YLONG_LIBCURL"] = "1"
        if client is None:
            expected_clients.add("libcurl")
    return env, expected_clients


def run_benchmark(
    bench_bin: Path,
    scenario: str,
    proxy_url: str,
    target_url: str,
    curl: str | None,
    baseline: str,
    requests: int,
    warmup: int,
    repeat: int,
    certs: BenchmarkCertificates | None = None,
    proxy_mtls: bool = False,
    origin_tls: bool = False,
    client: str | None = None,
    phase_timing: bool = False,
    concurrency: int = 1,
    ylong_concurrency_model: str = "threaded",
) -> tuple[list[BenchResult], str]:
    env, expected_clients = build_benchmark_env(
        proxy_url=proxy_url,
        target_url=target_url,
        curl=curl,
        baseline=baseline,
        requests=requests,
        warmup=warmup,
        certs=certs,
        proxy_mtls=proxy_mtls,
        origin_tls=origin_tls,
        client=client,
        phase_timing=phase_timing,
        concurrency=concurrency,
        ylong_concurrency_model=ylong_concurrency_model,
    )
    try:
        completed = subprocess.run(
            [str(bench_bin)],
            cwd=ROOT,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=True,
        )
    except subprocess.CalledProcessError as err:
        raise RuntimeError(
            "https_proxy_bench failed "
            f"(requests={requests}, repeat={repeat}, exit={err.returncode}):\n"
            f"{err.stdout}"
        ) from err
    return (
        parse_output(
            completed.stdout,
            scenario,
            requests,
            repeat,
            expected_clients,
            concurrency=concurrency,
            ylong_concurrency_model=ylong_concurrency_model,
        ),
        completed.stdout,
    )


def benchmark_clients(baseline: str, *, ylong_client: str = "async") -> list[str]:
    clients: list[str] = []
    if ylong_client in {"async", "both"}:
        clients.append("ylong_http_client")
    if ylong_client in {"sync", "both"}:
        clients.append("ylong_http_client_sync")
    if baseline in {"curl-cli", "both"}:
        clients.append("curl-cli")
    if baseline in {"libcurl", "both"}:
        clients.append("libcurl")
    return clients


def attach_trace(rows: list[BenchResult], trace: TraceResult) -> None:
    for row in rows:
        row.proxy_connections = trace.proxy_connections
        row.proxy_forward_requests = trace.proxy_forward_requests
        row.proxy_connect_requests = trace.proxy_connect_requests
        row.proxy_tunnel_bytes_from_client = trace.proxy_tunnel_bytes_from_client
        row.proxy_tunnel_bytes_from_origin = trace.proxy_tunnel_bytes_from_origin
        row.proxy_tls_client_auth_failures = trace.proxy_tls_client_auth_failures
        row.proxy_request_header_bytes = trace.proxy_request_header_bytes
        row.proxy_request_body_bytes = trace.proxy_request_body_bytes
        row.proxy_response_body_bytes = trace.proxy_response_body_bytes
        row.proxy_response_send_us = trace.proxy_response_send_us
        row.proxy_response_send_events = trace.proxy_response_send_events
        row.proxy_tunnel_send_to_client_us = trace.proxy_tunnel_send_to_client_us
        row.proxy_tunnel_send_to_client_events = trace.proxy_tunnel_send_to_client_events
        row.proxy_tunnel_send_to_origin_us = trace.proxy_tunnel_send_to_origin_us
        row.proxy_tunnel_send_to_origin_events = trace.proxy_tunnel_send_to_origin_events
        row.origin_connections = trace.origin_connections
        row.origin_requests = trace.origin_requests
        row.origin_tls_connections = trace.origin_tls_connections
        row.origin_request_header_bytes = trace.origin_request_header_bytes
        row.origin_request_body_bytes = trace.origin_request_body_bytes
        row.origin_response_body_bytes = trace.origin_response_body_bytes
        row.origin_response_send_us = trace.origin_response_send_us
        row.origin_response_send_events = trace.origin_response_send_events
        row.proxy_tls_fingerprints = format_tls_fingerprints(trace.proxy_tls_fingerprints)
        row.origin_tls_fingerprints = format_tls_fingerprints(trace.origin_tls_fingerprints)


def write_results(
    rows: Iterable[BenchResult],
    *,
    result_dir: Path = RESULT_DIR,
) -> pd.DataFrame:
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    result_dir.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(
        {
            "requests": row.requests,
            "concurrency": row.concurrency,
            "ylong_concurrency_model": row.ylong_concurrency_model,
            "scenario": row.scenario,
            "repeat": row.repeat,
            "client": row.client,
            "elapsed_ms": row.elapsed_ms,
            "latency_ms": row.latency_ms,
            "throughput_rps": row.throughput_rps,
            "p50_us": row.p50_us,
            "p95_us": row.p95_us,
            "cpu_us": row.cpu_us,
            "cpu_us_per_request": row.cpu_us / row.requests,
            "rss_peak_bytes": row.rss_peak_bytes,
            "errors": row.errors,
            "proxy_connections": row.proxy_connections,
            "proxy_forward_requests": row.proxy_forward_requests,
            "proxy_connect_requests": row.proxy_connect_requests,
            "proxy_tunnel_bytes_from_client": row.proxy_tunnel_bytes_from_client,
            "proxy_tunnel_bytes_from_origin": row.proxy_tunnel_bytes_from_origin,
            "proxy_tls_client_auth_failures": row.proxy_tls_client_auth_failures,
            "proxy_request_header_bytes": row.proxy_request_header_bytes,
            "proxy_request_body_bytes": row.proxy_request_body_bytes,
            "proxy_response_body_bytes": row.proxy_response_body_bytes,
            "proxy_response_send_us": row.proxy_response_send_us,
            "proxy_response_send_events": row.proxy_response_send_events,
            "proxy_tunnel_send_to_client_us": row.proxy_tunnel_send_to_client_us,
            "proxy_tunnel_send_to_client_events": row.proxy_tunnel_send_to_client_events,
            "proxy_tunnel_send_to_origin_us": row.proxy_tunnel_send_to_origin_us,
            "proxy_tunnel_send_to_origin_events": row.proxy_tunnel_send_to_origin_events,
            "origin_connections": row.origin_connections,
            "origin_requests": row.origin_requests,
            "origin_tls_connections": row.origin_tls_connections,
            "origin_request_header_bytes": row.origin_request_header_bytes,
            "origin_request_body_bytes": row.origin_request_body_bytes,
            "origin_response_body_bytes": row.origin_response_body_bytes,
            "origin_response_send_us": row.origin_response_send_us,
            "origin_response_send_events": row.origin_response_send_events,
            "phase_request_build_us": row.phase_request_build_us,
            "phase_request_execute_us": row.phase_request_execute_us,
            "phase_body_drain_us": row.phase_body_drain_us,
            "phase_connect_us": row.phase_connect_us,
            "phase_dns_us": row.phase_dns_us,
            "phase_tcp_us": row.phase_tcp_us,
            "phase_tls_us": row.phase_tls_us,
            "phase_transfer_us": row.phase_transfer_us,
            "phase_request_format_us": row.phase_request_format_us,
            "phase_pool_checkout_us": row.phase_pool_checkout_us,
            "phase_send_on_conn_us": row.phase_send_on_conn_us,
            "phase_http1_write_us": row.phase_http1_write_us,
            "phase_http1_encode_us": row.phase_http1_encode_us,
            "phase_http1_write_io_us": row.phase_http1_write_io_us,
            "phase_response_head_us": row.phase_response_head_us,
            "phase_response_read_us": row.phase_response_read_us,
            "phase_response_read_polls": row.phase_response_read_polls,
            "phase_response_read_pending": row.phase_response_read_pending,
            "phase_response_pre_read_bytes": row.phase_response_pre_read_bytes,
            "phase_response_pre_read_events": row.phase_response_pre_read_events,
            "phase_response_intercept_us": row.phase_response_intercept_us,
            "phase_response_decode_us": row.phase_response_decode_us,
            "phase_libcurl_perform_us": row.phase_libcurl_perform_us,
            "tls_ssl_read_calls": row.tls_ssl_read_calls,
            "tls_ssl_read_pending": row.tls_ssl_read_pending,
            "tls_ssl_write_calls": row.tls_ssl_write_calls,
            "tls_ssl_write_pending": row.tls_ssl_write_pending,
            "tls_underlying_read_calls": row.tls_underlying_read_calls,
            "tls_underlying_read_pending": row.tls_underlying_read_pending,
            "tls_underlying_write_calls": row.tls_underlying_write_calls,
            "tls_underlying_write_pending": row.tls_underlying_write_pending,
            "body_chunks": row.body_chunks,
            "body_bytes": row.body_bytes,
            "proxy_tls_fingerprints": row.proxy_tls_fingerprints,
            "origin_tls_fingerprints": row.origin_tls_fingerprints,
        }
        for row in rows
    )
    df.to_csv(result_dir / "https_proxy_bench_results.csv", index=False)
    summary = summarize_results(df)
    summary.to_csv(result_dir / "https_proxy_bench_summary.csv", index=False)
    baseline = "libcurl" if "libcurl" in set(df["client"]) else "curl_cli"
    compare_to_baseline(summary, baseline=baseline).to_csv(
        result_dir / "https_proxy_bench_comparison.csv", index=False
    )
    return df


def summarize_results(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    if "concurrency" not in df:
        df["concurrency"] = 1
    if "ylong_concurrency_model" not in df:
        df["ylong_concurrency_model"] = "threaded"
    for column in ("proxy_tls_fingerprints", "origin_tls_fingerprints"):
        if column not in df:
            df[column] = "-"
    for column in (
        "proxy_connections",
        "proxy_forward_requests",
        "proxy_connect_requests",
        "proxy_tunnel_bytes_from_client",
        "proxy_tunnel_bytes_from_origin",
        "proxy_tls_client_auth_failures",
        "proxy_request_header_bytes",
        "proxy_request_body_bytes",
        "proxy_response_body_bytes",
        "proxy_response_send_us",
        "proxy_response_send_events",
        "proxy_tunnel_send_to_client_us",
        "proxy_tunnel_send_to_client_events",
        "proxy_tunnel_send_to_origin_us",
        "proxy_tunnel_send_to_origin_events",
        "origin_connections",
        "origin_requests",
        "origin_tls_connections",
        "origin_request_header_bytes",
        "origin_request_body_bytes",
        "origin_response_body_bytes",
        "origin_response_send_us",
        "origin_response_send_events",
        "phase_request_build_us",
        "phase_request_execute_us",
        "phase_body_drain_us",
        "phase_connect_us",
        "phase_dns_us",
        "phase_tcp_us",
        "phase_tls_us",
        "phase_transfer_us",
        "phase_request_format_us",
        "phase_pool_checkout_us",
        "phase_send_on_conn_us",
        "phase_http1_write_us",
        "phase_http1_encode_us",
        "phase_http1_write_io_us",
        "phase_response_head_us",
        "phase_response_read_us",
        "phase_response_read_polls",
        "phase_response_read_pending",
        "phase_response_pre_read_bytes",
        "phase_response_pre_read_events",
        "phase_response_intercept_us",
        "phase_response_decode_us",
        "phase_libcurl_perform_us",
        "tls_ssl_read_calls",
        "tls_ssl_read_pending",
        "tls_ssl_write_calls",
        "tls_ssl_write_pending",
        "tls_underlying_read_calls",
        "tls_underlying_read_pending",
        "tls_underlying_write_calls",
        "tls_underlying_write_pending",
        "body_chunks",
        "body_bytes",
    ):
        if column not in df:
            df[column] = 0
    summary = (
        df.groupby(
            [
                "scenario",
                "requests",
                "concurrency",
                "ylong_concurrency_model",
                "client",
            ],
            as_index=False,
        )
        .agg(
            repeat_count=("repeat", "count"),
            elapsed_ms_mean=("elapsed_ms", "mean"),
            elapsed_ms_std=("elapsed_ms", "std"),
            latency_ms_mean=("latency_ms", "mean"),
            latency_ms_std=("latency_ms", "std"),
            throughput_rps_mean=("throughput_rps", "mean"),
            throughput_rps_std=("throughput_rps", "std"),
            p50_us_mean=("p50_us", "mean"),
            p50_us_std=("p50_us", "std"),
            p95_us_mean=("p95_us", "mean"),
            p95_us_std=("p95_us", "std"),
            cpu_us_per_request_mean=("cpu_us_per_request", "mean"),
            cpu_us_per_request_std=("cpu_us_per_request", "std"),
            rss_peak_bytes_max=("rss_peak_bytes", "max"),
            errors_sum=("errors", "sum"),
            proxy_connections_mean=("proxy_connections", "mean"),
            proxy_forward_requests_mean=("proxy_forward_requests", "mean"),
            proxy_connect_requests_mean=("proxy_connect_requests", "mean"),
            proxy_tunnel_bytes_from_client_mean=("proxy_tunnel_bytes_from_client", "mean"),
            proxy_tunnel_bytes_from_origin_mean=("proxy_tunnel_bytes_from_origin", "mean"),
            proxy_tls_client_auth_failures_sum=("proxy_tls_client_auth_failures", "sum"),
            proxy_request_header_bytes_mean=("proxy_request_header_bytes", "mean"),
            proxy_request_body_bytes_mean=("proxy_request_body_bytes", "mean"),
            proxy_response_body_bytes_mean=("proxy_response_body_bytes", "mean"),
            proxy_response_send_us_mean=("proxy_response_send_us", "mean"),
            proxy_response_send_events_mean=("proxy_response_send_events", "mean"),
            proxy_tunnel_send_to_client_us_mean=("proxy_tunnel_send_to_client_us", "mean"),
            proxy_tunnel_send_to_client_events_mean=(
                "proxy_tunnel_send_to_client_events",
                "mean",
            ),
            proxy_tunnel_send_to_origin_us_mean=("proxy_tunnel_send_to_origin_us", "mean"),
            proxy_tunnel_send_to_origin_events_mean=(
                "proxy_tunnel_send_to_origin_events",
                "mean",
            ),
            origin_connections_mean=("origin_connections", "mean"),
            origin_requests_mean=("origin_requests", "mean"),
            origin_tls_connections_mean=("origin_tls_connections", "mean"),
            origin_request_header_bytes_mean=("origin_request_header_bytes", "mean"),
            origin_request_body_bytes_mean=("origin_request_body_bytes", "mean"),
            origin_response_body_bytes_mean=("origin_response_body_bytes", "mean"),
            origin_response_send_us_mean=("origin_response_send_us", "mean"),
            origin_response_send_events_mean=("origin_response_send_events", "mean"),
            phase_request_build_us_mean=("phase_request_build_us", "mean"),
            phase_request_execute_us_mean=("phase_request_execute_us", "mean"),
            phase_body_drain_us_mean=("phase_body_drain_us", "mean"),
            phase_connect_us_mean=("phase_connect_us", "mean"),
            phase_dns_us_mean=("phase_dns_us", "mean"),
            phase_tcp_us_mean=("phase_tcp_us", "mean"),
            phase_tls_us_mean=("phase_tls_us", "mean"),
            phase_transfer_us_mean=("phase_transfer_us", "mean"),
            phase_request_format_us_mean=("phase_request_format_us", "mean"),
            phase_pool_checkout_us_mean=("phase_pool_checkout_us", "mean"),
            phase_send_on_conn_us_mean=("phase_send_on_conn_us", "mean"),
            phase_http1_write_us_mean=("phase_http1_write_us", "mean"),
            phase_http1_encode_us_mean=("phase_http1_encode_us", "mean"),
            phase_http1_write_io_us_mean=("phase_http1_write_io_us", "mean"),
            phase_response_head_us_mean=("phase_response_head_us", "mean"),
            phase_response_read_us_mean=("phase_response_read_us", "mean"),
            phase_response_read_polls_mean=("phase_response_read_polls", "mean"),
            phase_response_read_pending_mean=("phase_response_read_pending", "mean"),
            phase_response_pre_read_bytes_mean=("phase_response_pre_read_bytes", "mean"),
            phase_response_pre_read_events_mean=("phase_response_pre_read_events", "mean"),
            phase_response_intercept_us_mean=("phase_response_intercept_us", "mean"),
            phase_response_decode_us_mean=("phase_response_decode_us", "mean"),
            phase_libcurl_perform_us_mean=("phase_libcurl_perform_us", "mean"),
            tls_ssl_read_calls_mean=("tls_ssl_read_calls", "mean"),
            tls_ssl_read_pending_mean=("tls_ssl_read_pending", "mean"),
            tls_ssl_write_calls_mean=("tls_ssl_write_calls", "mean"),
            tls_ssl_write_pending_mean=("tls_ssl_write_pending", "mean"),
            tls_underlying_read_calls_mean=("tls_underlying_read_calls", "mean"),
            tls_underlying_read_pending_mean=("tls_underlying_read_pending", "mean"),
            tls_underlying_write_calls_mean=("tls_underlying_write_calls", "mean"),
            tls_underlying_write_pending_mean=("tls_underlying_write_pending", "mean"),
            body_chunks_mean=("body_chunks", "mean"),
            body_bytes_mean=("body_bytes", "mean"),
            proxy_tls_fingerprints=(
                "proxy_tls_fingerprints",
                unique_tls_fingerprint_values,
            ),
            origin_tls_fingerprints=(
                "origin_tls_fingerprints",
                unique_tls_fingerprint_values,
            ),
        )
        .sort_values(
            [
                "scenario",
                "requests",
                "concurrency",
                "ylong_concurrency_model",
                "client",
            ]
        )
    )
    for metric in (
        "elapsed_ms",
        "latency_ms",
        "throughput_rps",
        "p50_us",
        "p95_us",
        "cpu_us_per_request",
    ):
        summary[f"{metric}_ci95_half_width"] = [
            ci95_half_width(std, count)
            for std, count in zip(summary[f"{metric}_std"], summary["repeat_count"])
        ]
    return summary


def compare_to_baseline(summary: pd.DataFrame, *, baseline: str) -> pd.DataFrame:
    baseline_rows = summary[summary["client"] == baseline][
        [
            "scenario",
            "requests",
            "concurrency",
            "ylong_concurrency_model",
            "elapsed_ms_mean",
            "latency_ms_mean",
            "throughput_rps_mean",
            "p50_us_mean",
            "p95_us_mean",
            "cpu_us_per_request_mean",
            "rss_peak_bytes_max",
        ]
    ]
    merged = summary.merge(
        baseline_rows,
        on=[
            "scenario",
            "requests",
            "concurrency",
            "ylong_concurrency_model",
        ],
        suffixes=("", "_baseline"),
    )
    for metric in ("elapsed_ms", "latency_ms", "p50_us", "p95_us", "cpu_us_per_request"):
        merged[f"{metric}_ratio"] = (
            merged[f"{metric}_mean"] / merged[f"{metric}_mean_baseline"]
        )
    merged["throughput_rps_ratio"] = (
        merged["throughput_rps_mean"] / merged["throughput_rps_mean_baseline"]
    )
    merged["rss_peak_bytes_ratio"] = (
        merged["rss_peak_bytes_max"] / merged["rss_peak_bytes_max_baseline"]
    )
    merged["baseline"] = baseline
    return merged.sort_values(
        [
            "scenario",
            "requests",
            "concurrency",
            "ylong_concurrency_model",
            "client",
        ]
    )


def ci95_half_width(std: float, count: int) -> float:
    if count <= 1 or pd.isna(std):
        return 0.0
    return float(t_critical_975(count - 1) * std / np.sqrt(count))


def t_critical_975(degrees_of_freedom: int) -> float:
    table = {
        1: 12.706,
        2: 4.303,
        3: 3.182,
        4: 2.776,
        5: 2.571,
        6: 2.447,
        7: 2.365,
        8: 2.306,
        9: 2.262,
        10: 2.228,
        11: 2.201,
        12: 2.179,
        13: 2.160,
        14: 2.145,
        15: 2.131,
        16: 2.120,
        17: 2.110,
        18: 2.101,
        19: 2.093,
        20: 2.086,
        24: 2.064,
        29: 2.045,
        39: 2.023,
        59: 2.001,
        119: 1.980,
    }
    for limit in sorted(table):
        if degrees_of_freedom <= limit:
            return table[limit]
    return 1.96


def plot(df: pd.DataFrame, *, figure_dir: Path = FIG_DIR) -> None:
    figure_dir.mkdir(parents=True, exist_ok=True)
    first_scenario = sorted(df["scenario"].unique())[0]
    df = df[df["scenario"] == first_scenario].copy()
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 9,
            "axes.labelsize": 9,
            "axes.titlesize": 9,
            "legend.fontsize": 8,
            "xtick.labelsize": 8,
            "ytick.labelsize": 8,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )
    colors = {
        "ylong_http_client": "#0072B2",
        "ylong_http_client_sync": "#CC79A7",
        "curl_cli": "#D55E00",
        "libcurl": "#009E73",
    }
    markers = {
        "ylong_http_client": "o",
        "ylong_http_client_sync": "D",
        "curl_cli": "s",
        "libcurl": "^",
    }
    labels = {
        "ylong_http_client": "ylong_http_client",
        "ylong_http_client_sync": "ylong_http_client sync",
        "curl_cli": "curl CLI",
        "libcurl": "libcurl library",
    }
    summary = (
        df.groupby(["requests", "client"], as_index=False)
        .agg(
            latency_mean=("latency_ms", "mean"),
            latency_std=("latency_ms", "std"),
            throughput_mean=("throughput_rps", "mean"),
            throughput_std=("throughput_rps", "std"),
            elapsed_mean=("elapsed_ms", "mean"),
        )
        .sort_values(["requests", "client"])
    )
    requests = sorted(df["requests"].unique())
    request_labels = [str(item) for item in requests]
    request_positions = {request: index for index, request in enumerate(requests)}
    baseline = "libcurl" if "libcurl" in set(df["client"]) else "curl_cli"
    ylong_candidate = (
        "ylong_http_client"
        if "ylong_http_client" in set(df["client"])
        else "ylong_http_client_sync"
    )
    paired = df.pivot(index=["requests", "repeat"], columns="client", values="elapsed_ms").reset_index()
    paired["improvement"] = (
        1.0 - paired[ylong_candidate] / paired[baseline]
    ) * 100.0
    improvement = (
        paired.groupby("requests", as_index=False)
        .agg(mean=("improvement", "mean"), std=("improvement", "std"))
        .sort_values("requests")
    )

    fig, axes = plt.subplots(1, 3, figsize=(8.2, 2.55), constrained_layout=True)
    for client in [
        item
        for item in ["ylong_http_client", "ylong_http_client_sync", "libcurl", "curl_cli"]
        if item in set(df["client"])
    ]:
        part = summary[summary["client"] == client]
        x = part["requests"].map(request_positions)
        axes[0].errorbar(
            x,
            part["latency_mean"] * 1000.0,
            yerr=part["latency_std"].fillna(0) * 1000.0,
            color=colors[client],
            marker=markers[client],
            linewidth=1.8,
            markersize=4.5,
            capsize=2.5,
            label=labels[client],
        )
        axes[1].errorbar(
            x,
            part["throughput_mean"] / 1000.0,
            yerr=part["throughput_std"].fillna(0) / 1000.0,
            color=colors[client],
            marker=markers[client],
            linewidth=1.8,
            markersize=4.5,
            capsize=2.5,
            label=labels[client],
        )

    axes[0].set_xticks(range(len(requests)), request_labels)
    axes[0].set_xlabel("Requests")
    axes[0].set_ylabel("Latency / request (us)")
    axes[0].grid(True, which="major", axis="both", color="#d9d9d9", linewidth=0.7)
    axes[0].legend(frameon=False, loc="best")

    axes[1].set_xticks(range(len(requests)), request_labels)
    axes[1].set_xlabel("Requests")
    axes[1].set_ylabel("Throughput (kreq/s)")
    axes[1].grid(True, which="major", axis="both", color="#d9d9d9", linewidth=0.7)

    x = np.arange(len(improvement))
    axes[2].bar(
        x,
        improvement["mean"],
        yerr=improvement["std"].fillna(0),
        color="#009E73",
        edgecolor="#222222",
        linewidth=0.6,
        capsize=2.5,
        width=0.62,
    )
    axes[2].axhline(0.0, color="#666666", linewidth=0.8)
    axes[2].axhline(20.0, color="#CC79A7", linestyle="--", linewidth=1.1)
    axes[2].set_xticks(x, [str(v) for v in improvement["requests"]])
    axes[2].set_xlabel("Requests")
    axes[2].set_ylabel(f"{labels[ylong_candidate]} vs {labels[baseline]} (%)")
    lower = min(-20.0, float((improvement["mean"] - improvement["std"].fillna(0)).min()) - 5.0)
    upper = max(25.0, float((improvement["mean"] + improvement["std"].fillna(0)).max()) + 5.0)
    axes[2].set_ylim(lower, upper)
    axes[2].grid(True, axis="y", color="#d9d9d9", linewidth=0.7)

    for idx, title in enumerate(["(a) Latency", "(b) Throughput", "(c) Speedup margin"]):
        axes[idx].set_title(title, loc="left", fontweight="bold")

    fig.savefig(figure_dir / "https_proxy_bench_performance.pdf")
    fig.savefig(figure_dir / "https_proxy_bench_performance.png", dpi=300)
    plt.close(fig)


def tool_version(cmd: list[str]) -> str:
    try:
        out = subprocess.run(
            cmd,
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=True,
        ).stdout
        return out.splitlines()[0]
    except Exception as exc:  # noqa: BLE001
        return f"unavailable: {exc}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", default="200,1000,3000")
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=50)
    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="Same-model client concurrency. Default 1 preserves the canonical sequential matrix.",
    )
    parser.add_argument(
        "--baseline",
        choices=["curl-cli", "libcurl", "both"],
        default="curl-cli",
        help="Baseline to run. curl-cli is a process baseline; libcurl is same-process library baseline.",
    )
    parser.add_argument(
        "--ylong-client",
        choices=["async", "sync", "both"],
        default="async",
        help="Which ylong_http_client public API path to benchmark. Default async preserves canonical matrices.",
    )
    parser.add_argument(
        "--ylong-concurrency-model",
        choices=["threaded", "single-client"],
        default="threaded",
        help=(
            "Async ylong concurrency model when --concurrency > 1. "
            "Default threaded preserves existing diagnostic behavior."
        ),
    )
    parser.add_argument(
        "--bench-bin",
        type=Path,
        default=BENCH_BIN,
        help="Path to the built https_proxy_bench binary.",
    )
    parser.add_argument(
        "--scenario",
        choices=[*SCENARIOS, "all"],
        default="http-over-https-proxy",
        help="Benchmark topology to run. Use all for the SOTA evidence matrix.",
    )
    parser.add_argument(
        "--phase-timing",
        action="store_true",
        help="Enable ylong/libcurl phase timing output. Keep off for SOTA threshold runs.",
    )
    parser.add_argument(
        "--result-dir",
        type=Path,
        default=RESULT_DIR,
        help="Directory for CSV, raw output, and environment JSON result files.",
    )
    parser.add_argument(
        "--figure-dir",
        type=Path,
        default=FIG_DIR,
        help="Directory for generated benchmark figures.",
    )
    args = parser.parse_args()

    if args.concurrency < 1:
        raise RuntimeError("--concurrency must be at least 1")
    if not args.bench_bin.exists():
        raise RuntimeError(f"benchmark binary not found: {args.bench_bin}")
    curl = str(Path("D:/msys64/mingw64/bin/curl.exe"))
    if not Path(curl).exists():
        found = shutil.which("curl")
        if found is None and args.baseline in {"curl-cli", "both"}:
            raise RuntimeError("curl not found")
        curl = found or ""
    curl_arg = curl if curl else None

    work_dir = Path(tempfile.gettempdir()) / "ylong_https_proxy_bench"
    work_dir.mkdir(parents=True, exist_ok=True)
    certs = ensure_benchmark_certificates(work_dir)
    request_counts = [int(item.strip()) for item in args.requests.split(",") if item.strip()]
    scenarios = list(SCENARIOS) if args.scenario == "all" else [args.scenario]

    all_rows: list[BenchResult] = []
    raw_lines: list[str] = []
    for scenario in scenarios:
        with contextlib.ExitStack() as stack:
            proxy_mtls = scenario == "proxy-mtls-https-origin"
            origin_tls = scenario in {"https-over-https-proxy", "proxy-mtls-https-origin"}
            if origin_tls:
                origin = stack.enter_context(
                    LocalOriginServer(
                        BODY,
                        cert_file=certs.origin_cert_file,
                        key_file=certs.origin_key_file,
                    )
                )
                target_url = origin.url
            else:
                target_url = TARGET_URL
            proxy = stack.enter_context(
                LocalHttpsProxy(
                    certs.proxy_cert_file,
                    certs.proxy_key_file,
                    BODY,
                    client_ca_file=certs.ca_file if proxy_mtls else None,
                )
            )
            time.sleep(0.2)
            for requests in request_counts:
                for repeat in range(1, args.repeats + 1):
                    for client in benchmark_clients(args.baseline, ylong_client=args.ylong_client):
                        before_proxy = proxy.snapshot(scenario, client_label(client))
                        before_origin = (
                            origin.snapshot(scenario, client_label(client))
                            if origin_tls
                            else empty_trace(scenario, client_label(client))
                        )
                        rows, stdout = run_benchmark(
                            args.bench_bin,
                            scenario,
                            proxy.url,
                            target_url,
                            curl_arg,
                            args.baseline,
                            requests,
                            args.warmup,
                            repeat,
                            certs=certs,
                            proxy_mtls=proxy_mtls,
                            origin_tls=origin_tls,
                            client=client,
                            phase_timing=args.phase_timing,
                            concurrency=args.concurrency,
                            ylong_concurrency_model=args.ylong_concurrency_model,
                        )
                        after_proxy = proxy.snapshot(scenario, client_label(client))
                        after_origin = (
                            origin.snapshot(scenario, client_label(client))
                            if origin_tls
                            else empty_trace(scenario, client_label(client))
                        )
                        trace = after_proxy.delta(before_proxy)
                        trace.add_origin(after_origin.delta(before_origin))
                        attach_trace(rows, trace)
                        all_rows.extend(rows)
                        raw_lines.append(
                            f"### scenario={scenario} requests={requests} "
                            f"concurrency={args.concurrency} repeat={repeat} "
                            f"ylong_concurrency_model={args.ylong_concurrency_model} "
                            f"client={client_label(client)}"
                        )
                        raw_lines.append(stdout.strip())
                        raw_lines.append(trace.proxy_line())
                        raw_lines.append(trace.origin_line())
                        print(
                            f"scenario={scenario} requests={requests} "
                            f"concurrency={args.concurrency} repeat={repeat} "
                            f"ylong_concurrency_model={args.ylong_concurrency_model} "
                            f"client={client_label(client)}: ok",
                            flush=True,
                        )

    df = write_results(all_rows, result_dir=args.result_dir)
    plot(df, figure_dir=args.figure_dir)
    (args.result_dir / "https_proxy_bench_raw.txt").write_text(
        "\n\n".join(raw_lines) + "\n", encoding="utf-8"
    )
    env = {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "conda_prefix": os.environ.get("CONDA_PREFIX", ""),
        "matplotlib": __import__("matplotlib").__version__,
        "pandas": pd.__version__,
        "numpy": np.__version__,
        "rustc": tool_version(["rustc", "--version"]),
        "cargo": tool_version(["cargo", "--version"]),
        "curl_cli": tool_version([curl, "--version"]) if curl else "not requested",
        "libcurl": tool_version(["curl-config", "--version"]),
        "bench_binary": str(args.bench_bin),
        "baseline": args.baseline,
        "scenario": args.scenario,
        "scenarios": scenarios,
        "proxy_tls": "verified-local-ca",
        "origin_tls": "verified-local-ca when scenario uses HTTPS origin",
        "request_body_bytes": 0,
        "response_body_bytes": len(BODY),
        "request_counts": request_counts,
        "concurrency": args.concurrency,
        "ylong_concurrency_model": args.ylong_concurrency_model,
        "repeats": args.repeats,
        "warmup": args.warmup,
        "phase_timing": args.phase_timing,
    }
    (args.result_dir / "https_proxy_bench_env.json").write_text(
        json.dumps(env, indent=2), encoding="utf-8"
    )


if __name__ == "__main__":
    main()
