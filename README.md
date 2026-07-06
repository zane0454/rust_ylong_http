# ylong_http

`ylong_http` provides HTTP protocol and client capabilities for OpenHarmony's
Rust networking stack. The workspace contains:

- `ylong_http`: protocol primitives for HTTP/1.1, HTTP/2, HTTP/3, request and
  response parsing, body types, HPACK/QPACK related components, and codecs.
- `ylong_http_client`: synchronous and asynchronous HTTP clients with
  connection management, TLS integration, redirect handling, proxy support, and
  shared utility modules.

The client is designed to work with both the `ylong_runtime` ecosystem and the
Rust async model while keeping synchronous and asynchronous public interfaces
close enough for users to switch between them with limited code changes.

## Architecture

The `ylong_http_client` module is split into three major layers:

- `async_impl`: asynchronous client, connector, connection, upload, and download
  implementations.
- `sync_impl`: blocking client and connection implementations for thread-based
  users.
- `util`: shared configuration, proxy, redirect, TLS, information, and
  connection-pool utilities.

Connection establishment is isolated in connector modules. Proxy selection and
proxy endpoint metadata are centralized in `util::proxy`, so synchronous and
asynchronous connectors use the same matching, authentication, `no_proxy`, and
tunnel parsing behavior.

## HTTPS Proxy Support

`ylong_http_client` supports both plaintext HTTP proxies and TLS-protected HTTPS
proxy endpoints. HTTPS proxy transport is implemented on top of the OpenSSL
adapter. HTTPS origin requests through a proxy use this sequence:

1. Connect to the proxy endpoint.
2. If the proxy URL uses `https://`, complete TLS with the proxy.
3. Send an HTTP/1.1 `CONNECT host:port` tunnel request.
4. Validate the proxy response.
5. Complete the origin TLS handshake over the established tunnel.

Key capabilities:

- HTTP proxy forwarding for HTTP origin requests.
- HTTPS-over-proxy tunnels via `CONNECT`.
- HTTPS proxy endpoint TLS verification with custom CA files.
- HTTPS proxy mutual TLS through client certificate and private key files.
- OpenSSL cipher-list configuration for the proxy TLS hop.
- Shared proxy module for sync and async clients.
- Explicit failure when HTTPS proxy is configured without TLS support.
- Explicit rejection for HTTP/3 over proxy.
- Strict tunnel response parsing with capped proxy header size.
- Hot-path proxy authentication reuse without allocating a fresh `String` per
  tunnel request.
- Single-pass `CONNECT` response boundary scanning with numeric status-code
  validation.

Example:

```rust
use ylong_http_client::async_impl::{Body, ClientBuilder, Request};
use ylong_http_client::{Proxy, TlsConfig, TlsFileType};

async fn request_via_https_proxy() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let proxy_tls = TlsConfig::builder()
        .ca_file("certs/proxy-ca.pem")
        .certificate_file("certs/client.pem", TlsFileType::PEM)
        .private_key_file("certs/client.key", TlsFileType::PEM)
        .cipher_list("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
        .build()?;

    let proxy = Proxy::all("https://proxy.example.com:8443")
        .tls_config(proxy_tls)
        .build()?;

    let client = ClientBuilder::new().proxy(proxy).build()?;
    let request = Request::builder()
        .url("https://target.example.com/data")
        .body(Body::empty())?;

    let _response = client.request(request).await?;
    Ok(())
}
```

## Benchmark

The `https_proxy_bench` binary measures `ylong_http_client` in a local HTTPS
proxy topology. It supports two separately named baselines:

- `curl_cli`: a curl executable process baseline, enabled with `YLONG_CURL`.
- `libcurl`: a same-process libcurl library baseline, enabled with
  `YLONG_LIBCURL=1` and the Cargo feature `libcurl_bench`.

Do not combine these labels in reports. A curl CLI batch includes process and
command-line mechanics; a libcurl batch is the required baseline for SOTA
performance claims.

```powershell
cargo build -p ylong_http_client --no-default-features `
  --features "async,http1_1,ylong_base,c_openssl_3_0,libcurl_bench" `
  --release --bin https_proxy_bench

conda run -n base python docs\benchmarks\run_https_proxy_bench.py `
  --baseline libcurl --ylong-client sync --scenario all `
  --requests "200,1000,3000" --repeats 5 --warmup 50 `
  --client-order interleaved --client-order-seed 20260707
```

![HTTPS proxy benchmark ratio matrix](docs/figures/https_proxy_bench_performance.png)

Checked-in repaired trust-gated matrix setup:

- response body: 4096 bytes
- request body: 0 bytes
- warmup: 50 requests
- repeats: 5 paired runs
- request counts: 200, 1000, 3000
- baseline: same-process libcurl
- candidate: `ylong_http_client_sync`
- client order: deterministic interleaving by repeat, seed `20260707`
- scenarios: HTTP over HTTPS proxy, HTTPS origin over HTTPS proxy, proxy mTLS
  with HTTPS origin
- proxy TLS: local CA verified
- origin TLS: local CA verified for HTTPS-origin scenarios
- connection reuse trace: ylong and libcurl both reuse one proxy connection per
  repeat; HTTPS-origin scenarios also use one CONNECT tunnel and one origin TLS
  connection per repeat
- raw output:
  `docs/benchmarks/results/gen006-benchmark-trust-repaired/https_proxy_bench_results.csv`
- summary output:
  `docs/benchmarks/results/gen006-benchmark-trust-repaired/https_proxy_bench_summary.csv`
- ratio output:
  `docs/benchmarks/results/gen006-benchmark-trust-repaired/https_proxy_bench_comparison.csv`
- old gen005 data recomputed with repaired gates:
  `docs/benchmarks/results/gen006-benchmark-trust-repaired/gen005_recomputed_with_repaired_gates.csv`

Latest repaired matrix results:

| Scenario | Requests | Paired throughput | 95% CI | p95 latency | CPU/request | RSS peak | Gate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| HTTP over HTTPS proxy | 200 | 1.111x | [0.512x, 2.413x] | 0.785x | 0.705x | 1.055x | reject_proxy_send_anomaly |
| HTTP over HTTPS proxy | 1000 | 1.299x | [1.021x, 1.654x] | 0.821x | 0.598x | 1.052x | reject_proxy_send_anomaly |
| HTTP over HTTPS proxy | 3000 | 1.064x | [0.852x, 1.329x] | 0.826x | 0.740x | 1.057x | reject_proxy_send_anomaly |
| HTTPS origin over HTTPS proxy | 200 | 1.171x | [0.913x, 1.502x] | 0.718x | 0.670x | 1.065x | fail_sota20 |
| HTTPS origin over HTTPS proxy | 1000 | 0.911x | [0.529x, 1.571x] | 0.938x | 0.808x | 1.058x | fail_sota20 |
| HTTPS origin over HTTPS proxy | 3000 | 1.016x | [0.802x, 1.289x] | 0.945x | 0.756x | 1.062x | fail_sota20 |
| proxy mTLS with HTTPS origin | 200 | 0.909x | [0.545x, 1.515x] | 1.033x | 0.781x | 1.054x | fail_sota20 |
| proxy mTLS with HTTPS origin | 1000 | 1.348x | [0.968x, 1.877x] | 0.727x | 0.577x | 1.056x | inconclusive_ci |
| proxy mTLS with HTTPS origin | 3000 | 1.196x | [0.748x, 1.913x] | 0.809x | 0.651x | 1.056x | fail_sota20 |

The repaired matrix verifies the same-process libcurl baseline path, verified
proxy TLS, HTTPS-origin tunneling, proxy mTLS, metric columns, scenario-ratio
output, connection-reuse trace, client order metadata, paired aggregation, and
proxy-send anomaly gates. Under the repaired gate, the SOTA claim is withdrawn:
the paired throughput geomean is 1.104x, which is below the 1.20x threshold, and
no cell reaches `pass_sota20`. All HTTP-over-HTTPS-proxy cells are rejected by
the proxy-send anomaly gate because Python TLS proxy send time is large enough
to pollute client-attribution. The old gen005 matrix remains historical
evidence only: its original ratio-of-means geomean was 1.228x, but recomputing
that data with repaired gates yields no `pass_sota20` cells.

Historical fair-matrix and counterexample runs remain under
`docs/benchmarks/results/`, including `tokio-full/`, but they are not the
canonical README figure source.

For a contest or production proxy environment, reuse the same release binary and
replace only the target/proxy variables.

```powershell
$env:NO_PROXY = ""
$env:no_proxy = ""
$env:YLONG_BENCH_URL = "https://target.example.com/path"
$env:YLONG_HTTPS_PROXY = "https://proxy.example.com:8443"
$env:YLONG_BENCH_REQUESTS = "1000"
$env:YLONG_BENCH_WARMUP = "50"
$env:YLONG_LIBCURL = "1"

# Optional proxy TLS verification and mutual TLS:
$env:YLONG_PROXY_CA_FILE = "D:\certs\proxy-ca.pem"
$env:YLONG_PROXY_CERT_FILE = "D:\certs\client.pem"
$env:YLONG_PROXY_KEY_FILE = "D:\certs\client.key"
$env:YLONG_PROXY_CIPHER_LIST = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"

.\target\release\https_proxy_bench.exe
```

Use `YLONG_PROXY_CA_FILE` for private proxy CAs. Reserve
`YLONG_PROXY_INSECURE=1` for local testing only.

## Validation

The HTTPS proxy path is covered by targeted unit and integration-style tests
across the OpenSSL, non-TLS, sync, and async code paths.

```powershell
cargo test -p ylong_http_client --no-default-features `
  --features "async,http1_1,tokio_base,c_openssl_3_0" `
  --test sdv_async_https_proxy_tls -- --test-threads=1

cargo test -p ylong_http_client --no-default-features `
  --features "sync,async,http1_1,tokio_base,c_openssl_3_0" `
  --test sdv_sync_https_proxy_tls -- --test-threads=1

cargo test -p ylong_http_client --no-default-features `
  --features "sync,async,http1_1,tokio_base" `
  --test sdv_https_proxy_no_tls -- --test-threads=1

cargo test -p ylong_http_client --no-default-features `
  --features "async,http1_1,tokio_base" `
  ut_tunnel_request_and_response
```

## Build

Cargo is supported:

```toml
[dependencies]
ylong_http_client = { path = "/example_path/ylong_http_client" }
```

GN is supported. Add the crate to the target `deps`:

```gn
deps += ["//example_path/ylong_http_client:ylong_http_client"]
```

## Directory

```text
ylong_http
|-- docs                         # User guide and benchmark assets
|-- docs/benchmarks              # HTTPS proxy benchmark driver and CSV results
|-- docs/figures                 # Generated benchmark figures
|-- figures                      # Architecture resources
|-- patches                      # CI patches
|-- ylong_http                   # HTTP protocol components
|   |-- examples                 # Examples of ylong_http
|   |-- src
|   |   |-- body                 # Body trait and body types
|   |   |-- h1                   # HTTP/1.1 components
|   |   |-- h2                   # HTTP/2 components
|   |   |-- h3                   # HTTP/3 components
|   |   |-- huffman              # Huffman codec
|   |   |-- request              # Request type
|   |   `-- response             # Response type
|   `-- tests                    # Tests of ylong_http
`-- ylong_http_client
    |-- examples                 # Examples of ylong_http_client
    |-- src
    |   |-- async_impl           # Asynchronous client implementation
    |   |-- bin                  # Utility binaries, including https_proxy_bench
    |   |-- sync_impl            # Synchronous client implementation
    |   `-- util                 # Shared client utilities
    |       |-- c_openssl        # OpenSSL adapter
    |       |-- config           # Client, proxy, and TLS configuration
    |       `-- proxy.rs         # Shared proxy selection and tunnel utilities
    `-- tests                    # Tests of ylong_http_client
```
