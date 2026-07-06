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
//! - `YLONG_BENCH_PHASES`: set to `1` to print diagnostic phase timings.
//! - `YLONG_PROXY_CA_FILE`: PEM CA file for proxy certificate verification.
//! - `YLONG_PROXY_CERT_FILE`: client certificate file for proxy mutual TLS.
//! - `YLONG_PROXY_KEY_FILE`: client private key file for proxy mutual TLS.
//! - `YLONG_PROXY_CIPHER_LIST`: OpenSSL cipher list for proxy TLS.
//! - `YLONG_PROXY_INSECURE`: set to `1` to skip proxy cert and hostname checks.
//! - `YLONG_ORIGIN_CA_FILE`: PEM CA file for origin certificate verification.
//! - `YLONG_ORIGIN_CIPHER_LIST`: OpenSSL cipher list for origin TLS.
//! - `YLONG_ORIGIN_INSECURE`: set to `1` to skip origin cert and hostname checks.
//! - `YLONG_BENCH_CLIENTS`: `all`, `ylong_http_client`, `ylong_http_client_sync`, `curl-cli`, or `libcurl`.
//! - `YLONG_BENCH_YLONG_CONCURRENCY_MODEL`: `threaded` or `single-client`.
//! - `YLONG_CURL`: curl executable path. When set, curl is run for comparison.
//! - `YLONG_CURL_OUTPUT`: curl output sink, default `NUL` on Windows and `/dev/null` elsewhere.
//! - `YLONG_LIBCURL`: set to `1` to run the same-process libcurl library baseline.

use std::env;
use std::error::Error;
#[cfg(feature = "libcurl_bench")]
use std::ffi::{CStr, CString};
use std::fs::{remove_file, File};
use std::future::Future;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use ylong_http::body::async_impl::Body as _;
use ylong_http_client::async_impl::{Body, ClientBuilder, Request};
use ylong_http_client::{Proxy, TimeGroup, TlsConfig, TlsFileType};

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    #[cfg(feature = "ylong_base")]
    {
        return ylong_runtime::block_on(async_main());
    }

    #[cfg(all(not(feature = "ylong_base"), feature = "tokio_base"))]
    {
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async_main());
    }

    #[cfg(not(any(feature = "ylong_base", feature = "tokio_base")))]
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "https_proxy_bench requires either ylong_base or tokio_base",
        )
        .into());
    }
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
    let concurrency = env::var("YLONG_BENCH_CONCURRENCY")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1);
    let phase_timing = env::var("YLONG_BENCH_PHASES").ok().as_deref() == Some("1");
    if concurrency == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "YLONG_BENCH_CONCURRENCY must be at least 1",
        )
        .into());
    }
    let clients = BenchClients::from_env()?;
    let ylong_concurrency_model = YlongConcurrencyModel::from_env()?;
    let ylong_bench_config = YlongBenchConfig::for_concurrency(concurrency);

    let mut ylong_elapsed = None;
    if clients.ylong_async {
        let ylong = if concurrency == 1 {
            let client = build_ylong_client(&proxy, ylong_bench_config)?;
            run_ylong(&client, &url, warmup, phase_timing).await?;
            let measured = run_ylong(&client, &url, requests, phase_timing).await?;
            drop(client);
            measured
        } else {
            match ylong_concurrency_model {
                YlongConcurrencyModel::Threaded => run_ylong_concurrent(
                    &proxy,
                    &url,
                    warmup,
                    requests,
                    concurrency,
                    ylong_bench_config,
                    phase_timing,
                )?,
                YlongConcurrencyModel::SingleClient => {
                    run_ylong_concurrent_single_client(
                        &proxy,
                        &url,
                        warmup,
                        requests,
                        concurrency,
                        ylong_bench_config,
                        phase_timing,
                    )
                    .await?
                }
            }
        };
        println!(
            "ylong_http_client: {:?} for {} requests",
            ylong.elapsed, requests
        );
        ylong.print("ylong_http_client", requests);
        ylong_elapsed = Some(("ylong_http_client", ylong.elapsed));
    }

    if clients.ylong_sync {
        #[cfg(feature = "sync")]
        {
            let ylong = if concurrency == 1 {
                let client = build_ylong_sync_client(&proxy)?;
                run_ylong_sync(&client, &url, warmup)?;
                let measured = run_ylong_sync(&client, &url, requests)?;
                drop(client);
                measured
            } else {
                run_ylong_sync_concurrent(&proxy, &url, warmup, requests, concurrency)?
            };
            println!(
                "ylong_http_client_sync: {:?} for {} requests",
                ylong.elapsed, requests
            );
            ylong.print("ylong_http_client_sync", requests);
            ylong_elapsed = Some(("ylong_http_client_sync", ylong.elapsed));
        }
        #[cfg(not(feature = "sync"))]
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "YLONG_BENCH_CLIENTS=ylong_http_client_sync requires building with feature sync",
            )
            .into());
        }
    }

    if clients.curl_cli {
        let curl = env::var("YLONG_CURL")?;
        run_curl(&curl, &proxy, &url, warmup)?;
        let curl_elapsed = run_curl(&curl, &proxy, &url, requests)?;
        println!("curl_cli: {:?} for {} requests", curl_elapsed, requests);
        if let Some((ylong_label, ylong_elapsed)) = ylong_elapsed {
            let ratio = ylong_elapsed.as_secs_f64() / curl_elapsed.as_secs_f64();
            let improvement = (1.0 - ratio) * 100.0;
            println!("{ylong_label}/curl_cli elapsed ratio: {ratio:.3}");
            println!("{ylong_label} improvement over curl_cli: {improvement:.2}%");
        }
    }

    if clients.libcurl {
        #[cfg(feature = "libcurl_bench")]
        {
            let libcurl_elapsed = if concurrency == 1 {
                let mut libcurl = libcurl_baseline::Runner::new(&proxy, &url)?;
                libcurl.run(warmup, phase_timing)?;
                libcurl.run(requests, phase_timing)?
            } else {
                libcurl_baseline::run_concurrent(&proxy, &url, warmup, requests, concurrency)?
            };
            println!(
                "libcurl: {:?} for {} requests",
                libcurl_elapsed.elapsed, requests
            );
            libcurl_elapsed.print("libcurl", requests);
            if let Some((ylong_label, ylong_elapsed)) = ylong_elapsed {
                let ratio = ylong_elapsed.as_secs_f64() / libcurl_elapsed.elapsed.as_secs_f64();
                let improvement = (1.0 - ratio) * 100.0;
                println!("{ylong_label}/libcurl elapsed ratio: {ratio:.3}");
                println!("{ylong_label} improvement over libcurl: {improvement:.2}%");
            }
        }
        #[cfg(not(feature = "libcurl_bench"))]
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "YLONG_LIBCURL=1 requires building with feature libcurl_bench",
            )
            .into());
        }
    }

    Ok(())
}

struct BenchClients {
    ylong_async: bool,
    ylong_sync: bool,
    curl_cli: bool,
    libcurl: bool,
}

impl BenchClients {
    fn from_env() -> Result<Self, Box<dyn Error + Send + Sync>> {
        let value = env::var("YLONG_BENCH_CLIENTS").unwrap_or_else(|_| "all".to_string());
        Self::from_value(
            &value,
            env::var("YLONG_CURL").is_ok(),
            env::var("YLONG_LIBCURL").ok().as_deref() == Some("1"),
        )
    }

    fn from_value(
        value: &str,
        curl_cli_available: bool,
        libcurl_requested: bool,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        match value {
            "all" | "both" => Ok(Self {
                ylong_async: true,
                ylong_sync: false,
                curl_cli: curl_cli_available,
                libcurl: libcurl_requested,
            }),
            "ylong" | "ylong_http_client" => Ok(Self {
                ylong_async: true,
                ylong_sync: false,
                curl_cli: false,
                libcurl: false,
            }),
            "ylong_http_client_sync" | "ylong-sync" | "ylong_sync" => Ok(Self {
                ylong_async: false,
                ylong_sync: true,
                curl_cli: false,
                libcurl: false,
            }),
            "curl-cli" | "curl_cli" => Ok(Self {
                ylong_async: false,
                ylong_sync: false,
                curl_cli: true,
                libcurl: false,
            }),
            "libcurl" => Ok(Self {
                ylong_async: false,
                ylong_sync: false,
                curl_cli: false,
                libcurl: true,
            }),
            other => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsupported YLONG_BENCH_CLIENTS value: {other}"),
            )
            .into()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum YlongConcurrencyModel {
    Threaded,
    SingleClient,
}

impl YlongConcurrencyModel {
    fn from_env() -> Result<Self, Box<dyn Error + Send + Sync>> {
        let value =
            env::var("YLONG_BENCH_YLONG_CONCURRENCY_MODEL").unwrap_or_else(|_| "threaded".into());
        Self::from_value(&value)
    }

    fn from_value(value: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        match value {
            "" | "threaded" => Ok(Self::Threaded),
            "single-client" => Ok(Self::SingleClient),
            other => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsupported YLONG_BENCH_YLONG_CONCURRENCY_MODEL value: {other}"),
            )
            .into()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct YlongBenchConfig {
    max_h1_conn_number: Option<usize>,
}

impl YlongBenchConfig {
    fn for_concurrency(concurrency: usize) -> Self {
        Self {
            max_h1_conn_number: (concurrency > 1).then_some(concurrency),
        }
    }
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

fn origin_tls_config(
    mut builder: ClientBuilder,
) -> Result<ClientBuilder, Box<dyn Error + Send + Sync>> {
    if env::var("YLONG_ORIGIN_INSECURE").ok().as_deref() == Some("1") {
        builder = builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
    }
    if let Ok(path) = env::var("YLONG_ORIGIN_CA_FILE") {
        builder = builder.tls_ca_file(&path);
    }
    if let Ok(list) = env::var("YLONG_ORIGIN_CIPHER_LIST") {
        builder = builder.tls_cipher_list(&list);
    }
    Ok(builder)
}

fn build_ylong_client(
    proxy: &str,
    bench_config: YlongBenchConfig,
) -> Result<ylong_http_client::async_impl::Client, Box<dyn Error + Send + Sync>> {
    let proxy_tls = proxy_tls_config()?;
    let mut builder = ClientBuilder::new();
    if let Some(max_h1_conn_number) = bench_config.max_h1_conn_number {
        builder = builder.max_h1_conn_number(max_h1_conn_number);
    }
    Ok(origin_tls_config(builder)?
        .proxy(Proxy::all(proxy).tls_config(proxy_tls).build()?)
        .build()?)
}

#[cfg(feature = "sync")]
fn origin_tls_config_sync(
    mut builder: ylong_http_client::sync_impl::ClientBuilder,
) -> Result<ylong_http_client::sync_impl::ClientBuilder, Box<dyn Error + Send + Sync>> {
    if env::var("YLONG_ORIGIN_INSECURE").ok().as_deref() == Some("1") {
        builder = builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
    }
    if let Ok(path) = env::var("YLONG_ORIGIN_CA_FILE") {
        builder = builder.tls_ca_file(&path);
    }
    if let Ok(list) = env::var("YLONG_ORIGIN_CIPHER_LIST") {
        builder = builder.tls_cipher_list(&list);
    }
    Ok(builder)
}

#[cfg(feature = "sync")]
fn build_ylong_sync_client(
    proxy: &str,
) -> Result<
    ylong_http_client::sync_impl::Client<impl ylong_http_client::sync_impl::Connector>,
    Box<dyn Error + Send + Sync>,
> {
    let proxy_tls = proxy_tls_config()?;
    Ok(
        origin_tls_config_sync(ylong_http_client::sync_impl::ClientBuilder::new())?
            .proxy(Proxy::all(proxy).tls_config(proxy_tls).build()?)
            .build()?,
    )
}

async fn run_ylong(
    client: &ylong_http_client::async_impl::Client,
    url: &str,
    requests: usize,
    phase_timing: bool,
) -> Result<BenchRun, Box<dyn Error + Send + Sync>> {
    run_ylong_with_budget(
        client,
        url,
        Arc::new(SharedRequestBudget::new(requests)),
        phase_timing,
        true,
    )
    .await
}

async fn run_ylong_with_budget(
    client: &ylong_http_client::async_impl::Client,
    url: &str,
    budget: Arc<SharedRequestBudget>,
    phase_timing: bool,
    collect_tls_stats: bool,
) -> Result<BenchRun, Box<dyn Error + Send + Sync>> {
    if budget.is_empty() {
        return Ok(BenchRun::empty());
    }

    let _tls_stats_guard = collect_tls_stats.then(|| BenchTlsStatsGuard::new(phase_timing));
    let usage_start = Usage::snapshot();
    let tls_stats_start =
        (phase_timing && collect_tls_stats).then(ylong_http_client::tls_bench_stats_snapshot);
    let start = Instant::now();
    let mut latencies = Vec::new();
    let mut rss_peak = current_rss_bytes().unwrap_or(0);
    let mut phases = phase_timing.then(PhaseTotals::default);
    let mut body_stats = BodyStats::default();
    let mut buf = [0; 16 * 1024];
    while budget.next().is_some() {
        let request_start = Instant::now();
        let mut response = if let Some(phases) = phases.as_mut() {
            let build_start = Instant::now();
            let request = Request::builder().url(url).body(Body::empty())?;
            phases.request_build += build_start.elapsed();
            let execute_start = Instant::now();
            let response = client.request(request).await?;
            phases.request_execute += execute_start.elapsed();
            phases.add_time_group(response.time_group());
            response
        } else {
            let request = Request::builder().url(url).body(Body::empty())?;
            client.request(request).await?
        };
        let drain_start = Instant::now();
        loop {
            let size = response.body_mut().data(&mut buf).await?;
            if size == 0 {
                break;
            }
            body_stats.record(size);
        }
        if let Some(phases) = phases.as_mut() {
            phases.body_drain += drain_start.elapsed();
        }
        latencies.push(request_start.elapsed());
        if let Some(rss) = current_rss_bytes() {
            rss_peak = rss_peak.max(rss);
        }
    }
    if let (Some(phases), Some(tls_stats_start)) = (phases.as_mut(), tls_stats_start) {
        phases.add_tls_stats(
            ylong_http_client::tls_bench_stats_snapshot().saturating_sub(tls_stats_start),
        );
    }

    Ok(BenchRun::new(
        start.elapsed(),
        latencies,
        usage_start.elapsed_cpu_us(),
        rss_peak,
        body_stats,
        phases,
    ))
}

#[cfg(feature = "sync")]
fn run_ylong_sync<C>(
    client: &ylong_http_client::sync_impl::Client<C>,
    url: &str,
    requests: usize,
) -> Result<BenchRun, Box<dyn Error + Send + Sync>>
where
    C: ylong_http_client::sync_impl::Connector,
{
    if requests == 0 {
        return Ok(BenchRun::empty());
    }

    let usage_start = Usage::snapshot();
    let start = Instant::now();
    let mut latencies = Vec::with_capacity(requests);
    let mut rss_peak = current_rss_bytes().unwrap_or(0);
    let mut body_stats = BodyStats::default();
    for _ in 0..requests {
        let request_start = Instant::now();
        let request = ylong_http_client::sync_impl::Request::get(url)
            .body(ylong_http_client::sync_impl::EmptyBody)?;
        let mut response = client.request(request)?;
        let mut discard = SyncDiscard::default();
        ylong_http_client::sync_impl::BodyReader::new(&mut discard)
            .read_all(response.body_mut())?;
        body_stats.add(discard.body_stats);
        latencies.push(request_start.elapsed());
        if let Some(rss) = current_rss_bytes() {
            rss_peak = rss_peak.max(rss);
        }
    }

    Ok(BenchRun::new(
        start.elapsed(),
        latencies,
        usage_start.elapsed_cpu_us(),
        rss_peak,
        body_stats,
        None,
    ))
}

#[cfg(feature = "sync")]
#[derive(Default)]
struct SyncDiscard {
    body_stats: BodyStats,
}

#[cfg(feature = "sync")]
impl ylong_http_client::sync_impl::BodyProcessor for &mut SyncDiscard {
    fn write(&mut self, data: &[u8]) -> Result<(), ylong_http_client::sync_impl::BodyProcessError> {
        self.body_stats.record(data.len());
        Ok(())
    }

    fn progress(
        &mut self,
        _filled: usize,
    ) -> Result<(), ylong_http_client::sync_impl::BodyProcessError> {
        Ok(())
    }
}

fn run_ylong_concurrent(
    proxy: &str,
    url: &str,
    warmup: usize,
    requests: usize,
    concurrency: usize,
    bench_config: YlongBenchConfig,
    phase_timing: bool,
) -> Result<BenchRun, Box<dyn Error + Send + Sync>> {
    run_threaded(
        concurrency,
        warmup,
        requests,
        |warmup_count, request_count| {
            let proxy = proxy.to_string();
            let url = url.to_string();
            move |barrier| {
                let client = build_ylong_client(&proxy, bench_config)?;
                block_on_worker(run_ylong(&client, &url, warmup_count, false))?;
                barrier.wait();
                block_on_worker(run_ylong(&client, &url, request_count, phase_timing))
            }
        },
    )
}

async fn run_ylong_concurrent_single_client(
    proxy: &str,
    url: &str,
    warmup: usize,
    requests: usize,
    concurrency: usize,
    bench_config: YlongBenchConfig,
    phase_timing: bool,
) -> Result<BenchRun, Box<dyn Error + Send + Sync>> {
    let client = Arc::new(build_ylong_client(proxy, bench_config)?);
    run_ylong_single_client_workers(Arc::clone(&client), url, warmup, concurrency, false).await?;
    run_ylong_single_client_workers(client, url, requests, concurrency, phase_timing).await
}

async fn run_ylong_single_client_workers(
    client: Arc<ylong_http_client::async_impl::Client>,
    url: &str,
    requests: usize,
    concurrency: usize,
    phase_timing: bool,
) -> Result<BenchRun, Box<dyn Error + Send + Sync>> {
    if requests == 0 {
        return Ok(BenchRun::empty());
    }

    let workers = requests.min(concurrency.max(1));
    let budget = Arc::new(SharedRequestBudget::new(requests));
    let _tls_stats_guard = BenchTlsStatsGuard::new(phase_timing);
    let tls_stats_start = phase_timing.then(ylong_http_client::tls_bench_stats_snapshot);
    let usage_start = Usage::snapshot();
    let start = Instant::now();
    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let client = Arc::clone(&client);
        let budget = Arc::clone(&budget);
        let url = url.to_string();
        handles.push(spawn_bench_task(async move {
            run_ylong_with_budget(client.as_ref(), &url, budget, phase_timing, false).await
        }));
    }

    let mut runs = Vec::with_capacity(handles.len());
    for handle in handles {
        let run = join_bench_task(handle).await??;
        runs.push(run);
    }

    let mut run = BenchRun::from_concurrent(start.elapsed(), usage_start.elapsed_cpu_us(), runs);
    if let (Some(phases), Some(tls_stats_start)) = (run.phases.as_mut(), tls_stats_start) {
        phases.add_tls_stats(
            ylong_http_client::tls_bench_stats_snapshot().saturating_sub(tls_stats_start),
        );
    }
    Ok(run)
}

#[cfg(feature = "ylong_base")]
fn spawn_bench_task<F>(future: F) -> ylong_runtime::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    ylong_runtime::spawn(future)
}

#[cfg(all(not(feature = "ylong_base"), feature = "tokio_base"))]
fn spawn_bench_task<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(future)
}

#[cfg(feature = "ylong_base")]
async fn join_bench_task<T>(
    handle: ylong_runtime::task::JoinHandle<T>,
) -> Result<T, Box<dyn Error + Send + Sync>>
where
    T: Send + 'static,
{
    handle.await.map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("benchmark task failed: {err:?}"),
        )
        .into()
    })
}

#[cfg(all(not(feature = "ylong_base"), feature = "tokio_base"))]
async fn join_bench_task<T>(
    handle: tokio::task::JoinHandle<T>,
) -> Result<T, Box<dyn Error + Send + Sync>>
where
    T: Send + 'static,
{
    handle.await.map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("benchmark task failed: {err:?}"),
        )
        .into()
    })
}

#[cfg(feature = "sync")]
fn run_ylong_sync_concurrent(
    proxy: &str,
    url: &str,
    warmup: usize,
    requests: usize,
    concurrency: usize,
) -> Result<BenchRun, Box<dyn Error + Send + Sync>> {
    run_threaded(
        concurrency,
        warmup,
        requests,
        |warmup_count, request_count| {
            let proxy = proxy.to_string();
            let url = url.to_string();
            move |barrier| {
                let client = build_ylong_sync_client(&proxy)?;
                run_ylong_sync(&client, &url, warmup_count)?;
                barrier.wait();
                run_ylong_sync(&client, &url, request_count)
            }
        },
    )
}

fn run_threaded<F, G>(
    concurrency: usize,
    warmup: usize,
    requests: usize,
    worker: F,
) -> Result<BenchRun, Box<dyn Error + Send + Sync>>
where
    F: Fn(usize, usize) -> G,
    G: FnOnce(Arc<Barrier>) -> Result<BenchRun, Box<dyn Error + Send + Sync>> + Send + 'static,
{
    if requests == 0 {
        return Ok(BenchRun::empty());
    }
    let work = split_work(requests, concurrency);
    let warmup_work = split_work(warmup, work.len());
    let barrier = Arc::new(Barrier::new(work.len() + 1));
    let mut handles = Vec::with_capacity(work.len());
    for (idx, request_count) in work.into_iter().enumerate() {
        let barrier = barrier.clone();
        let warmup_count = warmup_work.get(idx).copied().unwrap_or(0);
        let worker = worker(warmup_count, request_count);
        handles.push(thread::spawn(move || worker(barrier)));
    }

    barrier.wait();
    let usage_start = Usage::snapshot();
    let start = Instant::now();
    let mut runs = Vec::with_capacity(handles.len());
    for handle in handles {
        let run = handle.join().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "benchmark worker panicked")
        })??;
        runs.push(run);
    }
    Ok(BenchRun::from_concurrent(
        start.elapsed(),
        usage_start.elapsed_cpu_us(),
        runs,
    ))
}

#[cfg(feature = "ylong_base")]
fn block_on_worker<F>(future: F) -> F::Output
where
    F: std::future::Future,
{
    ylong_runtime::block_on(future)
}

#[cfg(all(not(feature = "ylong_base"), feature = "tokio_base"))]
fn block_on_worker<F>(future: F) -> F::Output
where
    F: std::future::Future,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio benchmark worker runtime")
        .block_on(future)
}

struct BenchTlsStatsGuard;

impl BenchTlsStatsGuard {
    fn new(enabled: bool) -> Self {
        ylong_http_client::set_tls_bench_stats_enabled(enabled);
        Self
    }
}

impl Drop for BenchTlsStatsGuard {
    fn drop(&mut self) {
        ylong_http_client::set_tls_bench_stats_enabled(false);
    }
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
    if env::var("YLONG_ORIGIN_INSECURE").ok().as_deref() == Some("1") {
        command.arg("--insecure");
    }
    if let Ok(path) = env::var("YLONG_ORIGIN_CA_FILE") {
        command.arg("--cacert").arg(path);
    }
    if let Ok(path) = env::var("YLONG_ORIGIN_CERT_FILE") {
        command.arg("--cert").arg(path);
    }
    if let Ok(path) = env::var("YLONG_ORIGIN_KEY_FILE") {
        command.arg("--key").arg(path);
    }
    if let Ok(list) = env::var("YLONG_ORIGIN_CIPHER_LIST") {
        command.arg("--ciphers").arg(list);
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

struct BenchRun {
    elapsed: Duration,
    latencies: Vec<Duration>,
    cpu_us: u64,
    rss_peak_bytes: u64,
    body_stats: BodyStats,
    phases: Option<PhaseTotals>,
}

impl BenchRun {
    fn empty() -> Self {
        Self {
            elapsed: Duration::ZERO,
            latencies: Vec::new(),
            cpu_us: 0,
            rss_peak_bytes: 0,
            body_stats: BodyStats::default(),
            phases: None,
        }
    }

    fn new(
        elapsed: Duration,
        latencies: Vec<Duration>,
        cpu_us: u64,
        rss_peak_bytes: u64,
        body_stats: BodyStats,
        phases: Option<PhaseTotals>,
    ) -> Self {
        Self {
            elapsed,
            latencies,
            cpu_us,
            rss_peak_bytes,
            body_stats,
            phases,
        }
    }

    fn from_concurrent(elapsed: Duration, cpu_us: u64, runs: Vec<Self>) -> Self {
        let mut latencies = Vec::new();
        let mut rss_peak_bytes = 0;
        let mut body_stats = BodyStats::default();
        let mut phases = None;
        for mut run in runs {
            latencies.append(&mut run.latencies);
            rss_peak_bytes = rss_peak_bytes.max(run.rss_peak_bytes);
            body_stats.add(run.body_stats);
            if let Some(run_phases) = run.phases.take() {
                phases
                    .get_or_insert_with(PhaseTotals::default)
                    .add(run_phases);
            }
        }
        Self {
            elapsed,
            latencies,
            cpu_us,
            rss_peak_bytes,
            body_stats,
            phases,
        }
    }

    fn print(&self, client: &str, requests: usize) {
        println!(
            "{client}_stats: p50_us={} p95_us={} cpu_us={} rss_peak_bytes={} errors=0 for {} requests",
            percentile_us(&self.latencies, 0.50),
            percentile_us(&self.latencies, 0.95),
            self.cpu_us,
            self.rss_peak_bytes,
            requests
        );
        println!(
            "{client}_body_stats: chunks={} bytes={} for {} requests",
            self.body_stats.chunks, self.body_stats.bytes, requests
        );
        if let Some(phases) = &self.phases {
            phases.print(client, requests);
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct BodyStats {
    chunks: u64,
    bytes: u64,
}

impl BodyStats {
    fn record(&mut self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        self.chunks = self.chunks.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes as u64);
    }

    fn add(&mut self, other: Self) {
        self.chunks = self.chunks.saturating_add(other.chunks);
        self.bytes = self.bytes.saturating_add(other.bytes);
    }

    #[cfg(feature = "libcurl_bench")]
    fn saturating_sub(self, previous: Self) -> Self {
        Self {
            chunks: self.chunks.saturating_sub(previous.chunks),
            bytes: self.bytes.saturating_sub(previous.bytes),
        }
    }
}

#[derive(Default)]
struct PhaseTotals {
    request_build: Duration,
    request_execute: Duration,
    body_drain: Duration,
    connect: Duration,
    dns: Duration,
    tcp: Duration,
    tls: Duration,
    transfer: Duration,
    request_format: Duration,
    pool_checkout: Duration,
    send_on_conn: Duration,
    http1_write: Duration,
    http1_encode: Duration,
    http1_write_io: Duration,
    response_head: Duration,
    response_read: Duration,
    response_read_polls: u64,
    response_read_pending: u64,
    response_pre_read_bytes: u64,
    response_pre_read_events: u64,
    response_intercept: Duration,
    response_decode: Duration,
    libcurl_perform: Duration,
    tls_stats: ylong_http_client::BenchTlsStats,
}

impl PhaseTotals {
    fn add(&mut self, other: Self) {
        self.request_build += other.request_build;
        self.request_execute += other.request_execute;
        self.body_drain += other.body_drain;
        self.connect += other.connect;
        self.dns += other.dns;
        self.tcp += other.tcp;
        self.tls += other.tls;
        self.transfer += other.transfer;
        self.request_format += other.request_format;
        self.pool_checkout += other.pool_checkout;
        self.send_on_conn += other.send_on_conn;
        self.http1_write += other.http1_write;
        self.http1_encode += other.http1_encode;
        self.http1_write_io += other.http1_write_io;
        self.response_head += other.response_head;
        self.response_read += other.response_read;
        self.response_read_polls = self
            .response_read_polls
            .saturating_add(other.response_read_polls);
        self.response_read_pending = self
            .response_read_pending
            .saturating_add(other.response_read_pending);
        self.response_pre_read_bytes = self
            .response_pre_read_bytes
            .saturating_add(other.response_pre_read_bytes);
        self.response_pre_read_events = self
            .response_pre_read_events
            .saturating_add(other.response_pre_read_events);
        self.response_intercept += other.response_intercept;
        self.response_decode += other.response_decode;
        self.libcurl_perform += other.libcurl_perform;
        self.add_tls_stats(other.tls_stats);
    }

    fn add_tls_stats(&mut self, stats: ylong_http_client::BenchTlsStats) {
        self.tls_stats.ssl_read_calls = self
            .tls_stats
            .ssl_read_calls
            .saturating_add(stats.ssl_read_calls);
        self.tls_stats.ssl_read_pending = self
            .tls_stats
            .ssl_read_pending
            .saturating_add(stats.ssl_read_pending);
        self.tls_stats.ssl_write_calls = self
            .tls_stats
            .ssl_write_calls
            .saturating_add(stats.ssl_write_calls);
        self.tls_stats.ssl_write_pending = self
            .tls_stats
            .ssl_write_pending
            .saturating_add(stats.ssl_write_pending);
        self.tls_stats.underlying_read_calls = self
            .tls_stats
            .underlying_read_calls
            .saturating_add(stats.underlying_read_calls);
        self.tls_stats.underlying_read_pending = self
            .tls_stats
            .underlying_read_pending
            .saturating_add(stats.underlying_read_pending);
        self.tls_stats.underlying_write_calls = self
            .tls_stats
            .underlying_write_calls
            .saturating_add(stats.underlying_write_calls);
        self.tls_stats.underlying_write_pending = self
            .tls_stats
            .underlying_write_pending
            .saturating_add(stats.underlying_write_pending);
    }

    fn add_time_group(&mut self, time_group: &TimeGroup) {
        self.connect += duration_or_zero(time_group.connect_duration());
        self.dns += duration_or_zero(time_group.dns_duration());
        self.tcp += duration_or_zero(time_group.tcp_duration());
        #[cfg(feature = "__tls")]
        {
            self.tls += duration_or_zero(time_group.tls_duration());
        }
        self.transfer += duration_or_zero(time_group.transfer_duration());
        self.request_format += duration_or_zero(time_group.request_format_duration());
        self.pool_checkout += duration_or_zero(time_group.pool_checkout_duration());
        self.send_on_conn += duration_or_zero(time_group.send_on_conn_duration());
        self.http1_write += duration_or_zero(time_group.http1_write_duration());
        self.http1_encode += duration_or_zero(time_group.http1_encode_duration());
        self.http1_write_io += duration_or_zero(time_group.http1_write_io_duration());
        self.response_head += duration_or_zero(time_group.response_head_duration());
        self.response_read += duration_or_zero(time_group.response_read_duration());
        self.response_read_polls = self
            .response_read_polls
            .saturating_add(time_group.response_read_poll_count());
        self.response_read_pending = self
            .response_read_pending
            .saturating_add(time_group.response_read_pending_count());
        self.response_pre_read_bytes = self
            .response_pre_read_bytes
            .saturating_add(time_group.response_pre_read_bytes());
        self.response_pre_read_events = self
            .response_pre_read_events
            .saturating_add(time_group.response_pre_read_events());
        self.response_intercept += duration_or_zero(time_group.response_intercept_duration());
        self.response_decode += duration_or_zero(time_group.response_decode_duration());
    }

    fn print(&self, client: &str, requests: usize) {
        println!(
            "{client}_phase_us: request_build={} request_execute={} body_drain={} connect={} dns={} tcp={} tls={} transfer={} request_format={} pool_checkout={} send_on_conn={} http1_write={} http1_encode={} http1_write_io={} response_head={} response_read={} response_read_polls={} response_read_pending={} response_pre_read_bytes={} response_pre_read_events={} response_intercept={} response_decode={} libcurl_perform={} for {} requests",
            micros(self.request_build),
            micros(self.request_execute),
            micros(self.body_drain),
            micros(self.connect),
            micros(self.dns),
            micros(self.tcp),
            micros(self.tls),
            micros(self.transfer),
            micros(self.request_format),
            micros(self.pool_checkout),
            micros(self.send_on_conn),
            micros(self.http1_write),
            micros(self.http1_encode),
            micros(self.http1_write_io),
            micros(self.response_head),
            micros(self.response_read),
            self.response_read_polls,
            self.response_read_pending,
            self.response_pre_read_bytes,
            self.response_pre_read_events,
            micros(self.response_intercept),
            micros(self.response_decode),
            micros(self.libcurl_perform),
            requests
        );
        #[cfg(feature = "bench_tls_io")]
        if client == "ylong_http_client" {
            println!(
                "{client}_tls_io: ssl_read_calls={} ssl_read_pending={} ssl_write_calls={} ssl_write_pending={} underlying_read_calls={} underlying_read_pending={} underlying_write_calls={} underlying_write_pending={} for {} requests",
                self.tls_stats.ssl_read_calls,
                self.tls_stats.ssl_read_pending,
                self.tls_stats.ssl_write_calls,
                self.tls_stats.ssl_write_pending,
                self.tls_stats.underlying_read_calls,
                self.tls_stats.underlying_read_pending,
                self.tls_stats.underlying_write_calls,
                self.tls_stats.underlying_write_pending,
                requests
            );
        }
    }
}

fn duration_or_zero(value: Option<Duration>) -> Duration {
    value.unwrap_or(Duration::ZERO)
}

fn micros(value: Duration) -> u128 {
    value.as_micros()
}

fn percentile_us(values: &[Duration], percentile: f64) -> u128 {
    if values.is_empty() {
        return 0;
    }
    let mut micros = values.iter().map(Duration::as_micros).collect::<Vec<_>>();
    micros.sort_unstable();
    let rank = ((micros.len() as f64 * percentile).ceil() as usize).saturating_sub(1);
    micros[rank.min(micros.len() - 1)]
}

#[derive(Clone, Copy)]
struct Usage {
    cpu_us: u64,
}

impl Usage {
    fn snapshot() -> Self {
        Self {
            cpu_us: process_cpu_us(),
        }
    }

    fn elapsed_cpu_us(self) -> u64 {
        process_cpu_us().saturating_sub(self.cpu_us)
    }
}

#[cfg(unix)]
fn process_cpu_us() -> u64 {
    unsafe {
        let mut usage = std::mem::zeroed::<libc::rusage>();
        if libc::getrusage(libc::RUSAGE_SELF, &mut usage) != 0 {
            return 0;
        }
        timeval_us(usage.ru_utime).saturating_add(timeval_us(usage.ru_stime))
    }
}

#[cfg(unix)]
fn timeval_us(value: libc::timeval) -> u64 {
    (value.tv_sec as u64)
        .saturating_mul(1_000_000)
        .saturating_add(value.tv_usec as u64)
}

#[cfg(not(unix))]
fn process_cpu_us() -> u64 {
    0
}

#[cfg(target_os = "linux")]
fn current_rss_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages = statm.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    Some(pages.saturating_mul(page_size()))
}

#[cfg(target_os = "linux")]
fn page_size() -> u64 {
    unsafe {
        let size = libc::sysconf(libc::_SC_PAGESIZE);
        if size <= 0 {
            4096
        } else {
            size as u64
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn current_rss_bytes() -> Option<u64> {
    None
}

fn split_work(total: usize, concurrency: usize) -> Vec<usize> {
    if total == 0 || concurrency == 0 {
        return Vec::new();
    }
    let workers = total.min(concurrency);
    let base = total / workers;
    let remainder = total % workers;
    (0..workers)
        .map(|idx| base + usize::from(idx < remainder))
        .collect()
}

struct SharedRequestBudget {
    total: usize,
    next: AtomicUsize,
}

impl SharedRequestBudget {
    fn new(total: usize) -> Self {
        Self {
            total,
            next: AtomicUsize::new(0),
        }
    }

    fn is_empty(&self) -> bool {
        self.total == 0
    }

    fn next(&self) -> Option<usize> {
        let request = self.next.fetch_add(1, Ordering::Relaxed);
        (request < self.total).then_some(request)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ut_split_work_distributes_remainder_without_zero_workers() {
        assert_eq!(super::split_work(10, 4), vec![3, 3, 2, 2]);
        assert_eq!(super::split_work(3, 8), vec![1, 1, 1]);
        assert_eq!(super::split_work(0, 4), Vec::<usize>::new());
    }

    #[test]
    fn ut_shared_request_budget_issues_one_request_at_a_time_until_empty() {
        let budget = super::SharedRequestBudget::new(3);

        assert_eq!(budget.next(), Some(0));
        assert_eq!(budget.next(), Some(1));
        assert_eq!(budget.next(), Some(2));
        assert_eq!(budget.next(), None);
    }

    #[test]
    fn ut_bench_clients_selects_sync_candidate_only_when_explicit() {
        let default = super::BenchClients::from_value("all", true, true).unwrap();
        assert!(default.ylong_async);
        assert!(!default.ylong_sync);
        assert!(default.curl_cli);
        assert!(default.libcurl);

        let sync = super::BenchClients::from_value("ylong_http_client_sync", false, false).unwrap();
        assert!(!sync.ylong_async);
        assert!(sync.ylong_sync);
        assert!(!sync.curl_cli);
        assert!(!sync.libcurl);
    }

    #[test]
    fn ut_ylong_concurrency_model_defaults_to_threaded_and_requires_known_value() {
        assert_eq!(
            super::YlongConcurrencyModel::from_value("").unwrap(),
            super::YlongConcurrencyModel::Threaded
        );
        assert_eq!(
            super::YlongConcurrencyModel::from_value("threaded").unwrap(),
            super::YlongConcurrencyModel::Threaded
        );
        assert_eq!(
            super::YlongConcurrencyModel::from_value("single-client").unwrap(),
            super::YlongConcurrencyModel::SingleClient
        );
        assert!(super::YlongConcurrencyModel::from_value("pooled").is_err());
    }

    #[test]
    fn ut_ylong_bench_config_matches_h1_pool_to_requested_concurrency() {
        assert_eq!(
            super::YlongBenchConfig::for_concurrency(1).max_h1_conn_number,
            None
        );
        assert_eq!(
            super::YlongBenchConfig::for_concurrency(8).max_h1_conn_number,
            Some(8)
        );
    }

    #[test]
    fn ut_bench_run_aggregates_body_stats_from_concurrent_workers() {
        let run = super::BenchRun::from_concurrent(
            std::time::Duration::from_millis(10),
            99,
            vec![
                super::BenchRun::new(
                    std::time::Duration::from_millis(4),
                    Vec::new(),
                    40,
                    1024,
                    super::BodyStats {
                        chunks: 2,
                        bytes: 4096,
                    },
                    None,
                ),
                super::BenchRun::new(
                    std::time::Duration::from_millis(6),
                    Vec::new(),
                    59,
                    2048,
                    super::BodyStats {
                        chunks: 3,
                        bytes: 8192,
                    },
                    None,
                ),
            ],
        );

        assert_eq!(run.body_stats.chunks, 5);
        assert_eq!(run.body_stats.bytes, 12288);
        assert_eq!(run.rss_peak_bytes, 2048);
    }

    #[test]
    fn ut_bench_run_aggregates_phase_totals_from_concurrent_workers() {
        let mut first = super::PhaseTotals::default();
        first.request_execute = std::time::Duration::from_micros(10);
        first.response_read = std::time::Duration::from_micros(20);
        first.response_read_polls = 2;
        first.response_pre_read_bytes = 4096;
        first.response_pre_read_events = 1;

        let mut second = super::PhaseTotals::default();
        second.request_execute = std::time::Duration::from_micros(30);
        second.response_read = std::time::Duration::from_micros(40);
        second.response_read_polls = 3;
        second.response_pre_read_bytes = 8192;
        second.response_pre_read_events = 2;

        let run = super::BenchRun::from_concurrent(
            std::time::Duration::from_millis(10),
            99,
            vec![
                super::BenchRun::new(
                    std::time::Duration::from_millis(4),
                    Vec::new(),
                    40,
                    1024,
                    super::BodyStats::default(),
                    Some(first),
                ),
                super::BenchRun::new(
                    std::time::Duration::from_millis(6),
                    Vec::new(),
                    59,
                    2048,
                    super::BodyStats::default(),
                    Some(second),
                ),
            ],
        );

        let phases = run.phases.expect("concurrent phases should be aggregated");
        assert_eq!(phases.request_execute, std::time::Duration::from_micros(40));
        assert_eq!(phases.response_read, std::time::Duration::from_micros(60));
        assert_eq!(phases.response_read_polls, 5);
        assert_eq!(phases.response_pre_read_bytes, 12288);
        assert_eq!(phases.response_pre_read_events, 3);
    }
}

#[cfg(feature = "libcurl_bench")]
mod libcurl_baseline {
    use super::*;
    use libc::{c_char, c_int, c_long, c_uint, c_void, size_t};
    use std::ptr;

    enum Curl {}

    enum CurlMulti {}

    type CurlCode = c_int;
    type CurlOption = c_int;
    type CurlInfo = c_int;
    type CurlMultiCode = c_int;
    type CurlMultiOption = c_int;
    type WriteCallback = extern "C" fn(*mut c_char, size_t, size_t, *mut c_void) -> size_t;

    const CURLE_OK: CurlCode = 0;
    const CURLM_OK: CurlMultiCode = 0;
    const CURLMSG_DONE: c_int = 1;
    const CURL_GLOBAL_DEFAULT: c_long = 3;

    const CURLOPT_WRITEDATA: CurlOption = 10001;
    const CURLOPT_URL: CurlOption = 10002;
    const CURLOPT_PROXY: CurlOption = 10004;
    const CURLOPT_WRITEFUNCTION: CurlOption = 20011;
    const CURLOPT_SSL_VERIFYPEER: CurlOption = 64;
    const CURLOPT_CAINFO: CurlOption = 10065;
    const CURLOPT_SSL_VERIFYHOST: CurlOption = 81;
    const CURLOPT_SSL_CIPHER_LIST: CurlOption = 10083;
    const CURLOPT_SSLCERT: CurlOption = 10025;
    const CURLOPT_SSLKEY: CurlOption = 10087;
    const CURLOPT_NOSIGNAL: CurlOption = 99;
    const CURLOPT_PROXY_CAINFO: CurlOption = 10246;
    const CURLOPT_PROXY_SSL_VERIFYPEER: CurlOption = 248;
    const CURLOPT_PROXY_SSL_VERIFYHOST: CurlOption = 249;
    const CURLOPT_PROXY_SSLCERT: CurlOption = 10254;
    const CURLOPT_PROXY_SSLKEY: CurlOption = 10256;
    const CURLOPT_PROXY_SSL_CIPHER_LIST: CurlOption = 10259;

    const CURLINFO_RESPONSE_CODE: CurlInfo = 0x200000 + 2;

    const CURLMOPT_MAXCONNECTS: CurlMultiOption = 6;
    const CURLMOPT_MAX_HOST_CONNECTIONS: CurlMultiOption = 7;
    const CURLMOPT_MAX_TOTAL_CONNECTIONS: CurlMultiOption = 13;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CurlMsg {
        msg: c_int,
        easy_handle: *mut Curl,
        data: CurlMsgData,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    union CurlMsgData {
        whatever: *mut c_void,
        result: CurlCode,
    }

    extern "C" {
        fn curl_global_init(flags: c_long) -> CurlCode;
        fn curl_global_cleanup();
        fn curl_easy_init() -> *mut Curl;
        fn curl_easy_cleanup(curl: *mut Curl);
        fn curl_easy_perform(curl: *mut Curl) -> CurlCode;
        fn curl_easy_setopt(curl: *mut Curl, option: CurlOption, ...) -> CurlCode;
        fn curl_easy_getinfo(curl: *mut Curl, info: CurlInfo, ...) -> CurlCode;
        fn curl_easy_strerror(code: CurlCode) -> *const c_char;
        fn curl_multi_init() -> *mut CurlMulti;
        fn curl_multi_cleanup(multi: *mut CurlMulti) -> CurlMultiCode;
        fn curl_multi_add_handle(multi: *mut CurlMulti, easy: *mut Curl) -> CurlMultiCode;
        fn curl_multi_remove_handle(multi: *mut CurlMulti, easy: *mut Curl) -> CurlMultiCode;
        fn curl_multi_perform(multi: *mut CurlMulti, running: *mut c_int) -> CurlMultiCode;
        fn curl_multi_poll(
            multi: *mut CurlMulti,
            extra_fds: *mut c_void,
            extra_nfds: c_uint,
            timeout_ms: c_int,
            ret: *mut c_int,
        ) -> CurlMultiCode;
        fn curl_multi_info_read(multi: *mut CurlMulti, queued: *mut c_int) -> *mut CurlMsg;
        fn curl_multi_setopt(multi: *mut CurlMulti, option: CurlMultiOption, ...) -> CurlMultiCode;
        fn curl_multi_strerror(code: CurlMultiCode) -> *const c_char;
    }

    pub(crate) struct Runner {
        easy: Easy,
        _global: CurlGlobal,
    }

    pub(crate) fn run_concurrent(
        proxy: &str,
        url: &str,
        warmup: usize,
        requests: usize,
        concurrency: usize,
    ) -> Result<BenchRun, Box<dyn Error + Send + Sync>> {
        let mut runner = MultiRunner::new(proxy, url, concurrency)?;
        runner.run(warmup, false)?;
        runner.run(requests, true)
    }

    impl Runner {
        pub(crate) fn new(proxy: &str, url: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
            let global = CurlGlobal::new()?;
            let easy = configured_easy(proxy, url)?;
            Ok(Self {
                easy,
                _global: global,
            })
        }

        pub(crate) fn run(
            &mut self,
            requests: usize,
            phase_timing: bool,
        ) -> Result<BenchRun, Box<dyn Error + Send + Sync>> {
            if requests == 0 {
                return Ok(BenchRun::empty());
            }

            let usage_start = Usage::snapshot();
            let start = Instant::now();
            let mut latencies = Vec::with_capacity(requests);
            let mut rss_peak = current_rss_bytes().unwrap_or(0);
            let mut phases = phase_timing.then(PhaseTotals::default);
            let body_stats_start = self.easy.body_stats();
            for _ in 0..requests {
                let request_start = Instant::now();
                self.easy.perform()?;
                let perform_elapsed = request_start.elapsed();
                if let Some(phases) = phases.as_mut() {
                    phases.libcurl_perform += perform_elapsed;
                }
                latencies.push(perform_elapsed);
                if let Some(rss) = current_rss_bytes() {
                    rss_peak = rss_peak.max(rss);
                }
                let code = self.easy.response_code()?;
                if !(200..300).contains(&code) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("libcurl response status {code}"),
                    )
                    .into());
                }
            }
            let body_stats = self.easy.body_stats().saturating_sub(body_stats_start);
            Ok(BenchRun::new(
                start.elapsed(),
                latencies,
                usage_start.elapsed_cpu_us(),
                rss_peak,
                body_stats,
                phases,
            ))
        }
    }

    struct MultiRunner {
        multi: Multi,
        transfers: Vec<MultiTransfer>,
        _global: CurlGlobal,
    }

    struct MultiTransfer {
        easy: Easy,
        started_at: Option<Instant>,
    }

    impl MultiRunner {
        fn new(
            proxy: &str,
            url: &str,
            concurrency: usize,
        ) -> Result<Self, Box<dyn Error + Send + Sync>> {
            let global = CurlGlobal::new()?;
            let mut multi = Multi::new()?;
            let limit = concurrency.max(1) as c_long;
            multi.set_long(CURLMOPT_MAXCONNECTS, limit)?;
            multi.set_long(CURLMOPT_MAX_HOST_CONNECTIONS, limit)?;
            multi.set_long(CURLMOPT_MAX_TOTAL_CONNECTIONS, limit)?;
            let mut transfers = Vec::with_capacity(concurrency.max(1));
            for _ in 0..concurrency.max(1) {
                transfers.push(MultiTransfer {
                    easy: configured_easy(proxy, url)?,
                    started_at: None,
                });
            }
            Ok(Self {
                multi,
                transfers,
                _global: global,
            })
        }

        fn run(
            &mut self,
            requests: usize,
            collect_latencies: bool,
        ) -> Result<BenchRun, Box<dyn Error + Send + Sync>> {
            if requests == 0 {
                return Ok(BenchRun::empty());
            }

            let usage_start = Usage::snapshot();
            let start = Instant::now();
            let mut latencies = Vec::with_capacity(if collect_latencies { requests } else { 0 });
            let mut rss_peak = current_rss_bytes().unwrap_or(0);
            let body_stats_start: Vec<_> = self
                .transfers
                .iter()
                .map(|transfer| transfer.easy.body_stats())
                .collect();
            let mut next_request = 0;
            let mut completed = 0;
            let mut active = 0;
            let initial = requests.min(self.transfers.len());
            for idx in 0..initial {
                self.start_transfer(idx, &mut next_request)?;
                active += 1;
            }

            let mut running = 0;
            while completed < requests {
                self.multi.perform(&mut running)?;
                while let Some(message) = self.multi.info_read() {
                    if message.msg != CURLMSG_DONE {
                        continue;
                    }
                    let idx = self.transfer_index(message.easy_handle)?;
                    let started_at = self.transfers[idx].started_at.take().ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "libcurl completed transfer without start time",
                        )
                    })?;
                    self.multi.remove_handle(message.easy_handle)?;
                    active -= 1;
                    unsafe {
                        check(message.data.result, "curl_multi transfer")?;
                    }
                    let code = self.transfers[idx].easy.response_code()?;
                    if !(200..300).contains(&code) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("libcurl response status {code}"),
                        )
                        .into());
                    }
                    if collect_latencies {
                        latencies.push(started_at.elapsed());
                    }
                    completed += 1;
                    if let Some(rss) = current_rss_bytes() {
                        rss_peak = rss_peak.max(rss);
                    }
                    if next_request < requests {
                        self.start_transfer(idx, &mut next_request)?;
                        active += 1;
                    }
                }
                if completed < requests && active > 0 {
                    self.multi.poll(1000)?;
                }
            }

            let mut body_stats = BodyStats::default();
            for (transfer, previous) in self.transfers.iter().zip(body_stats_start) {
                body_stats.add(transfer.easy.body_stats().saturating_sub(previous));
            }
            Ok(BenchRun::new(
                start.elapsed(),
                latencies,
                usage_start.elapsed_cpu_us(),
                rss_peak,
                body_stats,
                None,
            ))
        }

        fn start_transfer(
            &mut self,
            idx: usize,
            next_request: &mut usize,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            let handle = self.transfers[idx].easy.handle();
            self.transfers[idx].started_at = Some(Instant::now());
            self.multi.add_handle(handle)?;
            *next_request += 1;
            Ok(())
        }

        fn transfer_index(&self, handle: *mut Curl) -> Result<usize, Box<dyn Error + Send + Sync>> {
            self.transfers
                .iter()
                .position(|transfer| transfer.easy.handle() == handle)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "libcurl completed unknown easy handle",
                    )
                    .into()
                })
        }
    }

    fn configured_easy(proxy: &str, url: &str) -> Result<Easy, Box<dyn Error + Send + Sync>> {
        let mut easy = Easy::new()?;
        easy.set_str(CURLOPT_URL, url)?;
        easy.set_str(CURLOPT_PROXY, proxy)?;
        easy.set_long(CURLOPT_NOSIGNAL, 1)?;
        easy.set_body_stats_callback()?;
        apply_tls_env(&mut easy)?;
        Ok(easy)
    }

    fn apply_tls_env(easy: &mut Easy) -> Result<(), Box<dyn Error + Send + Sync>> {
        if env::var("YLONG_PROXY_INSECURE").ok().as_deref() == Some("1") {
            easy.set_long(CURLOPT_PROXY_SSL_VERIFYPEER, 0)?;
            easy.set_long(CURLOPT_PROXY_SSL_VERIFYHOST, 0)?;
        }
        if env::var("YLONG_ORIGIN_INSECURE").ok().as_deref() == Some("1") {
            easy.set_long(CURLOPT_SSL_VERIFYPEER, 0)?;
            easy.set_long(CURLOPT_SSL_VERIFYHOST, 0)?;
        }
        if let Ok(path) = env::var("YLONG_PROXY_CA_FILE") {
            easy.set_str(CURLOPT_PROXY_CAINFO, &path)?;
        }
        if let Ok(path) = env::var("YLONG_PROXY_CERT_FILE") {
            easy.set_str(CURLOPT_PROXY_SSLCERT, &path)?;
        }
        if let Ok(path) = env::var("YLONG_PROXY_KEY_FILE") {
            easy.set_str(CURLOPT_PROXY_SSLKEY, &path)?;
        }
        if let Ok(list) = env::var("YLONG_PROXY_CIPHER_LIST") {
            easy.set_str(CURLOPT_PROXY_SSL_CIPHER_LIST, &list)?;
        }
        if let Ok(path) = env::var("YLONG_ORIGIN_CA_FILE") {
            easy.set_str(CURLOPT_CAINFO, &path)?;
        }
        if let Ok(path) = env::var("YLONG_ORIGIN_CERT_FILE") {
            easy.set_str(CURLOPT_SSLCERT, &path)?;
        }
        if let Ok(path) = env::var("YLONG_ORIGIN_KEY_FILE") {
            easy.set_str(CURLOPT_SSLKEY, &path)?;
        }
        if let Ok(list) = env::var("YLONG_ORIGIN_CIPHER_LIST") {
            easy.set_str(CURLOPT_SSL_CIPHER_LIST, &list)?;
        }
        Ok(())
    }

    extern "C" fn discard_body(
        _ptr: *mut c_char,
        size: size_t,
        nmemb: size_t,
        userdata: *mut c_void,
    ) -> size_t {
        let bytes = size.saturating_mul(nmemb);
        if !userdata.is_null() {
            unsafe {
                (*(userdata as *mut BodyStats)).record(bytes);
            }
        }
        bytes
    }

    struct CurlGlobal;

    impl CurlGlobal {
        fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
            check(
                unsafe { curl_global_init(CURL_GLOBAL_DEFAULT) },
                "curl_global_init",
            )?;
            Ok(Self)
        }
    }

    impl Drop for CurlGlobal {
        fn drop(&mut self) {
            unsafe { curl_global_cleanup() };
        }
    }

    struct Multi {
        handle: *mut CurlMulti,
    }

    impl Multi {
        fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
            let handle = unsafe { curl_multi_init() };
            if handle.is_null() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "curl_multi_init returned null",
                )
                .into());
            }
            Ok(Self { handle })
        }

        fn add_handle(&mut self, easy: *mut Curl) -> Result<(), Box<dyn Error + Send + Sync>> {
            check_multi(
                unsafe { curl_multi_add_handle(self.handle, easy) },
                "curl_multi_add_handle",
            )
        }

        fn remove_handle(&mut self, easy: *mut Curl) -> Result<(), Box<dyn Error + Send + Sync>> {
            check_multi(
                unsafe { curl_multi_remove_handle(self.handle, easy) },
                "curl_multi_remove_handle",
            )
        }

        fn perform(&mut self, running: &mut c_int) -> Result<(), Box<dyn Error + Send + Sync>> {
            check_multi(
                unsafe { curl_multi_perform(self.handle, running as *mut c_int) },
                "curl_multi_perform",
            )
        }

        fn poll(&mut self, timeout_ms: c_int) -> Result<(), Box<dyn Error + Send + Sync>> {
            let mut ret = 0;
            check_multi(
                unsafe {
                    curl_multi_poll(
                        self.handle,
                        ptr::null_mut(),
                        0,
                        timeout_ms,
                        &mut ret as *mut c_int,
                    )
                },
                "curl_multi_poll",
            )
        }

        fn info_read(&mut self) -> Option<CurlMsg> {
            let mut queued = 0;
            let message = unsafe { curl_multi_info_read(self.handle, &mut queued as *mut c_int) };
            if message.is_null() {
                None
            } else {
                Some(unsafe { *message })
            }
        }

        fn set_long(
            &mut self,
            option: CurlMultiOption,
            value: c_long,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            check_multi(
                unsafe { curl_multi_setopt(self.handle, option, value) },
                "curl_multi_setopt(long)",
            )
        }
    }

    impl Drop for Multi {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                unsafe {
                    curl_multi_cleanup(self.handle);
                }
                self.handle = ptr::null_mut();
            }
        }
    }

    struct Easy {
        handle: *mut Curl,
        strings: Vec<CString>,
        body_stats: Box<BodyStats>,
    }

    impl Easy {
        fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
            let handle = unsafe { curl_easy_init() };
            if handle.is_null() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "curl_easy_init returned null",
                )
                .into());
            }
            Ok(Self {
                handle,
                strings: Vec::new(),
                body_stats: Box::default(),
            })
        }

        fn handle(&self) -> *mut Curl {
            self.handle
        }

        fn set_long(
            &mut self,
            option: CurlOption,
            value: c_long,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            check(
                unsafe { curl_easy_setopt(self.handle, option, value) },
                "curl_easy_setopt(long)",
            )
        }

        fn set_str(
            &mut self,
            option: CurlOption,
            value: &str,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            let value = CString::new(value)?;
            check(
                unsafe { curl_easy_setopt(self.handle, option, value.as_ptr()) },
                "curl_easy_setopt(str)",
            )?;
            self.strings.push(value);
            Ok(())
        }

        fn set_ptr(
            &mut self,
            option: CurlOption,
            value: *mut c_void,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            check(
                unsafe { curl_easy_setopt(self.handle, option, value) },
                "curl_easy_setopt(ptr)",
            )
        }

        fn set_write_function(
            &mut self,
            callback: WriteCallback,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            check(
                unsafe { curl_easy_setopt(self.handle, CURLOPT_WRITEFUNCTION, callback) },
                "curl_easy_setopt(writefunction)",
            )
        }

        fn set_body_stats_callback(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
            let ptr = self.body_stats.as_mut() as *mut BodyStats as *mut c_void;
            self.set_ptr(CURLOPT_WRITEDATA, ptr)?;
            self.set_write_function(discard_body)
        }

        fn body_stats(&self) -> BodyStats {
            *self.body_stats
        }

        fn perform(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
            check(
                unsafe { curl_easy_perform(self.handle) },
                "curl_easy_perform",
            )
        }

        fn response_code(&mut self) -> Result<c_long, Box<dyn Error + Send + Sync>> {
            let mut code = 0 as c_long;
            check(
                unsafe { curl_easy_getinfo(self.handle, CURLINFO_RESPONSE_CODE, &mut code) },
                "curl_easy_getinfo(response_code)",
            )?;
            Ok(code)
        }
    }

    impl Drop for Easy {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                unsafe { curl_easy_cleanup(self.handle) };
                self.handle = ptr::null_mut();
            }
        }
    }

    fn check(code: CurlCode, action: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        if code == CURLE_OK {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("{action} failed: {}", curl_error(code)),
            )
            .into())
        }
    }

    fn check_multi(code: CurlMultiCode, action: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        if code == CURLM_OK {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("{action} failed: {}", curl_multi_error(code)),
            )
            .into())
        }
    }

    fn curl_error(code: CurlCode) -> String {
        unsafe {
            let ptr = curl_easy_strerror(code);
            if ptr.is_null() {
                format!("curl error {code}")
            } else {
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        }
    }

    fn curl_multi_error(code: CurlMultiCode) -> String {
        unsafe {
            let ptr = curl_multi_strerror(code);
            if ptr.is_null() {
                format!("curl multi error {code}")
            } else {
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        }
    }
}
