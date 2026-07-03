#!/usr/bin/env python3
"""Run and plot the ylong_http_client HTTPS proxy benchmark.

The script is intentionally self-contained so the benchmark can be rerun from a
Conda Python environment after building `https_proxy_bench`.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
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
DURATION_RE = re.compile(r"^(ylong_http_client|curl): ([0-9.]+)([a-zA-Zµ]+) for (\d+) requests$")


@dataclass
class BenchResult:
    requests: int
    repeat: int
    client: str
    elapsed_ms: float

    @property
    def latency_ms(self) -> float:
        return self.elapsed_ms / self.requests

    @property
    def throughput_rps(self) -> float:
        return self.requests / (self.elapsed_ms / 1000.0)


class LocalHttpsProxy:
    def __init__(self, cert_file: Path, key_file: Path, body: bytes) -> None:
        self.cert_file = cert_file
        self.key_file = key_file
        self.body = body
        self.stop_event = threading.Event()
        self.threads: list[threading.Thread] = []
        self.sock: socket.socket | None = None
        self.port = 0

    def __enter__(self) -> "LocalHttpsProxy":
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
            with self.ctx.wrap_socket(raw, server_side=True) as conn:
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
                    if first_line.startswith(b"CONNECT "):
                        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        return
                    response = (
                        b"HTTP/1.1 200 OK\r\n"
                        + f"Content-Length: {len(self.body)}\r\n".encode("ascii")
                        + b"Connection: keep-alive\r\n"
                        + b"Content-Type: application/octet-stream\r\n\r\n"
                        + self.body
                    )
                    conn.sendall(response)
        except (OSError, ssl.SSLError):
            return

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


def ensure_certificates(work_dir: Path) -> tuple[Path, Path]:
    cert_file = work_dir / "https_proxy_bench_proxy.crt"
    key_file = work_dir / "https_proxy_bench_proxy.key"
    if cert_file.exists() and key_file.exists():
        return cert_file, key_file
    preferred = Path("D:/msys64/mingw64/bin/openssl.exe")
    openssl = str(preferred) if preferred.exists() else shutil.which("openssl")
    if openssl is None:
        raise RuntimeError("openssl not found; source rust-env.ps1 before running this script")
    cmd = [
        openssl,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "2",
        "-keyout",
        str(key_file),
        "-out",
        str(cert_file),
        "-subj",
        "/CN=127.0.0.1",
    ]
    completed = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if completed.returncode != 0:
        raise RuntimeError(
            "openssl certificate generation failed:\n"
            + completed.stdout
            + completed.stderr
        )
    return cert_file, key_file


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


def parse_output(stdout: str, requests: int, repeat: int) -> list[BenchResult]:
    rows: list[BenchResult] = []
    for line in stdout.splitlines():
        match = DURATION_RE.match(line.strip())
        if not match:
            continue
        client, value, unit, count = match.groups()
        if int(count) != requests:
            continue
        rows.append(
            BenchResult(
                requests=requests,
                repeat=repeat,
                client="ylong_http_client" if client == "ylong_http_client" else "curl",
                elapsed_ms=duration_to_ms(value, unit),
            )
        )
    clients = {row.client for row in rows}
    if clients != {"ylong_http_client", "curl"}:
        raise RuntimeError(f"failed to parse benchmark output:\n{stdout}")
    return rows


def run_benchmark(
    proxy_url: str,
    curl: str,
    requests: int,
    warmup: int,
    repeat: int,
) -> tuple[list[BenchResult], str]:
    env = os.environ.copy()
    env.update(
        {
            "NO_PROXY": "",
            "no_proxy": "",
            "HTTP_PROXY": "",
            "HTTPS_PROXY": "",
            "http_proxy": "",
            "https_proxy": "",
            "YLONG_BENCH_URL": TARGET_URL,
            "YLONG_HTTPS_PROXY": proxy_url,
            "YLONG_BENCH_REQUESTS": str(requests),
            "YLONG_BENCH_WARMUP": str(warmup),
            "YLONG_PROXY_INSECURE": "1",
            "YLONG_CURL": curl,
            "YLONG_CURL_OUTPUT": "NUL" if os.name == "nt" else "/dev/null",
        }
    )
    completed = subprocess.run(
        [str(BENCH_BIN)],
        cwd=ROOT,
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    )
    return parse_output(completed.stdout, requests, repeat), completed.stdout


def write_results(rows: Iterable[BenchResult]) -> pd.DataFrame:
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(
        {
            "requests": row.requests,
            "repeat": row.repeat,
            "client": row.client,
            "elapsed_ms": row.elapsed_ms,
            "latency_ms": row.latency_ms,
            "throughput_rps": row.throughput_rps,
        }
        for row in rows
    )
    df.to_csv(RESULT_DIR / "https_proxy_bench_results.csv", index=False)
    summary = (
        df.groupby(["requests", "client"], as_index=False)
        .agg(
            elapsed_ms_mean=("elapsed_ms", "mean"),
            elapsed_ms_std=("elapsed_ms", "std"),
            latency_ms_mean=("latency_ms", "mean"),
            latency_ms_std=("latency_ms", "std"),
            throughput_rps_mean=("throughput_rps", "mean"),
            throughput_rps_std=("throughput_rps", "std"),
        )
        .sort_values(["requests", "client"])
    )
    summary.to_csv(RESULT_DIR / "https_proxy_bench_summary.csv", index=False)
    return df


def plot(df: pd.DataFrame) -> None:
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
    colors = {"ylong_http_client": "#0072B2", "curl": "#D55E00"}
    markers = {"ylong_http_client": "o", "curl": "s"}
    labels = {"ylong_http_client": "ylong_http_client", "curl": "curl"}
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
    paired = df.pivot(index=["requests", "repeat"], columns="client", values="elapsed_ms").reset_index()
    paired["improvement"] = (
        1.0 - paired["ylong_http_client"] / paired["curl"]
    ) * 100.0
    improvement = (
        paired.groupby("requests", as_index=False)
        .agg(mean=("improvement", "mean"), std=("improvement", "std"))
        .sort_values("requests")
    )

    fig, axes = plt.subplots(1, 3, figsize=(8.2, 2.55), constrained_layout=True)
    for client in ["ylong_http_client", "curl"]:
        part = summary[summary["client"] == client]
        axes[0].errorbar(
            part["requests"],
            part["latency_mean"],
            yerr=part["latency_std"].fillna(0),
            color=colors[client],
            marker=markers[client],
            linewidth=1.8,
            markersize=4.5,
            capsize=2.5,
            label=labels[client],
        )
        axes[1].errorbar(
            part["requests"],
            part["throughput_mean"],
            yerr=part["throughput_std"].fillna(0),
            color=colors[client],
            marker=markers[client],
            linewidth=1.8,
            markersize=4.5,
            capsize=2.5,
            label=labels[client],
        )

    axes[0].set_xscale("log")
    axes[0].set_yscale("log")
    axes[0].set_xticks(requests)
    axes[0].get_xaxis().set_major_formatter(plt.ScalarFormatter())
    axes[0].set_xlabel("Requests")
    axes[0].set_ylabel("Latency / request (ms)")
    axes[0].grid(True, which="major", axis="both", color="#d9d9d9", linewidth=0.7)
    axes[0].legend(frameon=False, loc="best")

    axes[1].set_xscale("log")
    axes[1].set_xticks(requests)
    axes[1].get_xaxis().set_major_formatter(plt.ScalarFormatter())
    axes[1].set_xlabel("Requests")
    axes[1].set_ylabel("Throughput (req/s)")
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
    axes[2].axhline(20.0, color="#CC79A7", linestyle="--", linewidth=1.1)
    axes[2].set_xticks(x, [str(v) for v in improvement["requests"]])
    axes[2].set_xlabel("Requests")
    axes[2].set_ylabel("Improvement vs curl (%)")
    axes[2].set_ylim(0, max(100, float(improvement["mean"].max()) + 5))
    axes[2].grid(True, axis="y", color="#d9d9d9", linewidth=0.7)

    for idx, title in enumerate(["(a) Latency", "(b) Throughput", "(c) Speedup margin"]):
        axes[idx].set_title(title, loc="left", fontweight="bold")

    fig.savefig(FIG_DIR / "https_proxy_bench_performance.pdf")
    fig.savefig(FIG_DIR / "https_proxy_bench_performance.png", dpi=300)
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
    args = parser.parse_args()

    if not BENCH_BIN.exists():
        raise RuntimeError(f"benchmark binary not found: {BENCH_BIN}")
    curl = str(Path("D:/msys64/mingw64/bin/curl.exe"))
    if not Path(curl).exists():
        found = shutil.which("curl")
        if found is None:
            raise RuntimeError("curl not found")
        curl = found

    work_dir = Path(tempfile.gettempdir()) / "ylong_https_proxy_bench"
    work_dir.mkdir(parents=True, exist_ok=True)
    cert_file, key_file = ensure_certificates(work_dir)
    request_counts = [int(item.strip()) for item in args.requests.split(",") if item.strip()]

    all_rows: list[BenchResult] = []
    raw_lines: list[str] = []
    with LocalHttpsProxy(cert_file, key_file, BODY) as proxy:
        time.sleep(0.2)
        for requests in request_counts:
            for repeat in range(1, args.repeats + 1):
                rows, stdout = run_benchmark(proxy.url, curl, requests, args.warmup, repeat)
                all_rows.extend(rows)
                raw_lines.append(f"### requests={requests} repeat={repeat}")
                raw_lines.append(stdout.strip())
                print(f"requests={requests} repeat={repeat}: ok", flush=True)

    df = write_results(all_rows)
    plot(df)
    (RESULT_DIR / "https_proxy_bench_raw.txt").write_text(
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
        "curl": tool_version([curl, "--version"]),
        "bench_binary": str(BENCH_BIN),
        "target_url": TARGET_URL,
        "response_body_bytes": len(BODY),
        "request_counts": request_counts,
        "repeats": args.repeats,
        "warmup": args.warmup,
    }
    (RESULT_DIR / "https_proxy_bench_env.json").write_text(
        json.dumps(env, indent=2), encoding="utf-8"
    )


if __name__ == "__main__":
    main()
