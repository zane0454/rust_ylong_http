// Copyright (c) 2023 Huawei Device Co., Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! HTTPS proxy performance harness.
//!
//! Environment variables:
//! - `YLONG_BENCH_URL`: target URL.
//! - `YLONG_HTTPS_PROXY`: HTTPS proxy URL.
//! - `YLONG_BENCH_REQUESTS`: request count, default `100`.
//! - `YLONG_BENCH_WARMUP`: warmup request count, default `10`.
//! - `YLONG_PROXY_CA_FILE`: PEM CA file for proxy certificate verification.
//! - `YLONG_PROXY_CERT_FILE`: client certificate file for proxy mutual TLS.
//! - `YLONG_PROXY_KEY_FILE`: client private key file for proxy mutual TLS.
//! - `YLONG_PROXY_CIPHER_LIST`: OpenSSL cipher list for proxy TLS.
//! - `YLONG_PROXY_INSECURE`: set to `1` to skip proxy cert and hostname checks.
//! - `YLONG_CURL`: curl executable path. When set, curl is run for comparison.
//! - `YLONG_CURL_OUTPUT`: curl output sink, default `NUL` on Windows and `/dev/null` elsewhere.

use std::env;
use std::error::Error;
use std::fs::{remove_file, File};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use ylong_http::body::async_impl::Body as _;
use ylong_http_client::async_impl::{Body, ClientBuilder, Request};
use ylong_http_client::{Proxy, TlsConfig, TlsFileType};

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    ylong_runtime::block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let url = env::var("YLONG_BENCH_URL").unwrap_or_else(|_| "https://example.com/".to_string());
    let proxy = env::var("YLONG_HTTPS_PROXY")?;
    let requests = env::var("YLONG_BENCH_REQUESTS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100);
    let warmup = env::var("YLONG_BENCH_WARMUP")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(10);

    let proxy_tls = proxy_tls_config()?;
    let client = ClientBuilder::new()
        .proxy(Proxy::all(&proxy).tls_config(proxy_tls).build()?)
        .build()?;

    run_ylong(&client, &url, warmup).await?;
    let ylong = run_ylong(&client, &url, requests).await?;
    println!("ylong_http_client: {:?} for {} requests", ylong, requests);

    if let Ok(curl) = env::var("YLONG_CURL") {
        run_curl(&curl, &proxy, &url, warmup)?;
        let curl_elapsed = run_curl(&curl, &proxy, &url, requests)?;
        let ratio = ylong.as_secs_f64() / curl_elapsed.as_secs_f64();
        let improvement = (1.0 - ratio) * 100.0;
        println!("curl: {:?} for {} requests", curl_elapsed, requests);
        println!("ylong/curl elapsed ratio: {ratio:.3}");
        println!("ylong improvement over curl: {improvement:.2}%");
    }

    Ok(())
}

fn proxy_tls_config() -> Result<TlsConfig, Box<dyn Error + Send + Sync>> {
    let mut builder = TlsConfig::builder();

    if env::var("YLONG_PROXY_INSECURE").ok().as_deref() == Some("1") {
        builder = builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
    }
    if let Ok(path) = env::var("YLONG_PROXY_CA_FILE") {
        builder = builder.ca_file(path);
    }
    if let Ok(path) = env::var("YLONG_PROXY_CERT_FILE") {
        builder = builder.certificate_file(path, TlsFileType::PEM);
    }
    if let Ok(path) = env::var("YLONG_PROXY_KEY_FILE") {
        builder = builder.private_key_file(path, TlsFileType::PEM);
    }
    if let Ok(list) = env::var("YLONG_PROXY_CIPHER_LIST") {
        builder = builder.cipher_list(&list);
    }

    Ok(builder.build()?)
}

async fn run_ylong(
    client: &ylong_http_client::async_impl::Client,
    url: &str,
    requests: usize,
) -> Result<Duration, Box<dyn Error + Send + Sync>> {
    let start = Instant::now();
    for _ in 0..requests {
        let request = Request::builder().url(url).body(Body::empty())?;
        let mut response = client.request(request).await?;
        let mut buf = [0; 16 * 1024];
        while response.body_mut().data(&mut buf).await? != 0 {}
    }
    Ok(start.elapsed())
}

fn run_curl(
    curl: &str,
    proxy: &str,
    url: &str,
    requests: usize,
) -> Result<Duration, Box<dyn Error + Send + Sync>> {
    if requests == 0 {
        return Ok(Duration::ZERO);
    }

    let mut command = Command::new(curl);
    let output = env::var("YLONG_CURL_OUTPUT").unwrap_or_else(|_| {
        if cfg!(windows) {
            "NUL".to_string()
        } else {
            "/dev/null".to_string()
        }
    });
    command.args(["-sS", "--proxy", proxy]);
    if env::var("YLONG_PROXY_INSECURE").ok().as_deref() == Some("1") {
        command.arg("--proxy-insecure");
    }
    if let Ok(path) = env::var("YLONG_PROXY_CA_FILE") {
        command.arg("--proxy-cacert").arg(path);
    }
    if let Ok(path) = env::var("YLONG_PROXY_CERT_FILE") {
        command.arg("--proxy-cert").arg(path);
    }
    if let Ok(path) = env::var("YLONG_PROXY_KEY_FILE") {
        command.arg("--proxy-key").arg(path);
    }
    if let Ok(list) = env::var("YLONG_PROXY_CIPHER_LIST") {
        command.arg("--proxy-ciphers").arg(list);
    }
    let curl_config = curl_url_config(&output, url, requests)?;
    command.arg("--config").arg(&curl_config);

    let start = Instant::now();
    let status = command.status()?;
    let _ = remove_file(&curl_config);
    if !status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("curl exited with status {status}"),
        )
        .into());
    }
    Ok(start.elapsed())
}

fn curl_url_config(
    output: &str,
    url: &str,
    requests: usize,
) -> Result<PathBuf, Box<dyn Error + Send + Sync>> {
    let path = env::temp_dir().join(format!(
        "ylong_http_client_curl_{}_{}.cfg",
        std::process::id(),
        requests
    ));
    let mut file = File::create(&path)?;
    let output = curl_config_escape(output);
    let url = curl_config_escape(url);
    for _ in 0..requests {
        writeln!(file, "output = \"{output}\"")?;
        writeln!(file, "url = \"{url}\"")?;
    }
    Ok(path)
}

fn curl_config_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
