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

The `https_proxy_bench` binary compares `ylong_http_client` with curl/libcurl in
the same HTTPS proxy topology. The checked-in benchmark driver starts a local TLS
target and TLS proxy, runs paired ylong/curl batches from a Conda Python
environment, writes CSV output, and regenerates publication-style PNG/PDF
figures.

```powershell
cargo build -p ylong_http_client --no-default-features `
  --features "async,http1_1,ylong_base,c_openssl_3_0" `
  --release --bin https_proxy_bench

conda run -n base python docs\benchmarks\run_https_proxy_bench.py `
  --requests "200,1000,3000" --repeats 5 --warmup 50
```

![HTTPS proxy benchmark](docs/figures/https_proxy_bench_performance.png)

Local reproducible setup:

- response body: 4096 bytes
- warmup: 50 requests
- repeats: 5 paired runs per request count
- raw output: `docs/benchmarks/results/https_proxy_bench_results.csv`
- summary output: `docs/benchmarks/results/https_proxy_bench_summary.csv`

Latest local results:

| Requests | ylong latency/request | curl latency/request | Improvement vs curl | ylong throughput | curl throughput |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 200 | 0.0750 ms | 1.7625 ms | 95.74% | 13,399 req/s | 569 req/s |
| 1000 | 0.0932 ms | 1.8933 ms | 95.08% | 11,078 req/s | 529 req/s |
| 3000 | 0.1191 ms | 2.8613 ms | 95.84% | 8,510 req/s | 350 req/s |

For a contest or production proxy environment, reuse the same release binary and
replace only the target/proxy variables. This keeps the benchmark harness,
metrics, and curl baseline consistent with the local reproducibility run.

```powershell
$env:NO_PROXY = ""
$env:no_proxy = ""
$env:YLONG_BENCH_URL = "https://target.example.com/path"
$env:YLONG_HTTPS_PROXY = "https://proxy.example.com:8443"
$env:YLONG_BENCH_REQUESTS = "1000"
$env:YLONG_BENCH_WARMUP = "50"
$env:YLONG_CURL = "D:\msys64\mingw64\bin\curl.exe"

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
  --features "async,http1_1,ylong_base,c_openssl_3_0" proxy -- --test-threads=1

cargo test -p ylong_http_client --no-default-features `
  --features "async,http1_1,ylong_base,c_openssl_3_0" tunnel -- --test-threads=1

cargo test -p ylong_http_client --no-default-features `
  --features "async,http1_1,ylong_base" proxy -- --test-threads=1
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
