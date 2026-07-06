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

#![cfg(all(
    feature = "async",
    feature = "http1_1",
    feature = "__tls",
    feature = "tokio_base"
))]

use std::fs;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslVerifyMode};
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
use openssl::x509::{X509NameBuilder, X509};
use ylong_http_client::async_impl::{Body, Client, ClientBuilder, Request};
use ylong_http_client::{Proxy, TlsConfig, TlsFileType};

const PROXY_BODY: &str = "http over https proxy";
const ORIGIN_BODY: &str = "https over https proxy";

struct ProxyServer {
    port: u16,
    events: Receiver<String>,
    join: JoinHandle<()>,
}

impl ProxyServer {
    fn url(&self, host: &str) -> String {
        format!("https://{host}:{}", self.port)
    }

    fn join(self) {
        self.join.join().expect("proxy thread panicked");
    }
}

enum ProxyBehavior {
    HttpResponse(Vec<u8>),
    ConnectThenOrigin {
        status: &'static str,
        origin_acceptor: Arc<SslAcceptor>,
        body: Vec<u8>,
    },
}

fn manifest_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn proxy_cert() -> PathBuf {
    manifest_path("tests/file/cert_chain/chain.crt.pem")
}

fn proxy_key() -> PathBuf {
    manifest_path("tests/file/cert_chain/server.key.pem")
}

fn proxy_ca() -> PathBuf {
    manifest_path("tests/file/cert_chain/rootCA.crt.pem")
}

fn origin_cert() -> PathBuf {
    manifest_path("tests/file/cert.pem")
}

fn origin_key() -> PathBuf {
    manifest_path("tests/file/key.pem")
}

fn origin_ca() -> PathBuf {
    manifest_path("tests/file/root-ca.pem")
}

fn start_proxy(behavior: ProxyBehavior, client_ca: Option<&Path>) -> ProxyServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("proxy bind failed");
    let port = listener
        .local_addr()
        .expect("proxy local addr failed")
        .port();
    let acceptor = proxy_acceptor(client_ca);
    let (tx, rx) = channel();

    let join = thread::spawn(move || {
        let (tcp, _) = listener.accept().expect("proxy accept failed");
        tcp.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set proxy read timeout failed");
        tcp.set_write_timeout(Some(Duration::from_secs(5)))
            .expect("set proxy write timeout failed");

        let mut proxy_tls = match acceptor.accept(tcp) {
            Ok(stream) => stream,
            Err(err) => {
                let _ = tx.send(format!("proxy_tls_error:{err}"));
                return;
            }
        };

        let headers = read_headers(&mut proxy_tls).expect("read proxy request failed");
        let proxy_first_line = first_line(&headers);
        tx.send(proxy_first_line.clone())
            .expect("send proxy event failed");

        match behavior {
            ProxyBehavior::HttpResponse(body) => {
                write_response(&mut proxy_tls, &body).expect("write proxy response failed");
                let _ = proxy_tls.get_ref().shutdown(Shutdown::Both);
            }
            ProxyBehavior::ConnectThenOrigin {
                status,
                origin_acceptor,
                body,
            } => {
                assert!(proxy_first_line.starts_with("CONNECT "));
                proxy_tls
                    .write_all(format!("HTTP/1.1 {status}\r\n\r\n").as_bytes())
                    .expect("write CONNECT response failed");

                let mut origin_tls = match origin_acceptor.accept(proxy_tls) {
                    Ok(stream) => stream,
                    Err(err) => {
                        let _ = tx.send(format!("origin_tls_error:{err}"));
                        return;
                    }
                };
                let headers = read_headers(&mut origin_tls).expect("read origin request failed");
                tx.send(first_line(&headers))
                    .expect("send origin event failed");
                write_response(&mut origin_tls, &body).expect("write origin response failed");
            }
        }
    });

    ProxyServer {
        port,
        events: rx,
        join,
    }
}

fn proxy_acceptor(client_ca: Option<&Path>) -> SslAcceptor {
    let mut builder =
        SslAcceptor::mozilla_intermediate(SslMethod::tls()).expect("proxy acceptor build failed");
    builder
        .set_private_key_file(proxy_key(), SslFiletype::PEM)
        .expect("set proxy private key failed");
    builder
        .set_certificate_chain_file(proxy_cert())
        .expect("set proxy certificate failed");
    if let Some(ca) = client_ca {
        builder.set_ca_file(ca).expect("set proxy client CA failed");
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    }
    builder.build()
}

fn origin_acceptor() -> Arc<SslAcceptor> {
    let mut builder =
        SslAcceptor::mozilla_intermediate(SslMethod::tls()).expect("origin acceptor build failed");
    builder
        .set_private_key_file(origin_key(), SslFiletype::PEM)
        .expect("set origin private key failed");
    builder
        .set_certificate_chain_file(origin_cert())
        .expect("set origin certificate failed");
    Arc::new(builder.build())
}

fn read_headers<S: Read>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0; 1024];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(IoError::new(
                IoErrorKind::UnexpectedEof,
                "connection closed before headers",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > 8192 {
            return Err(IoError::new(IoErrorKind::InvalidData, "headers too long"));
        }
    }
}

fn first_line(headers: &[u8]) -> String {
    String::from_utf8_lossy(
        headers
            .split(|byte| *byte == b'\n')
            .next()
            .unwrap_or(headers),
    )
    .trim_end_matches('\r')
    .to_string()
}

fn write_response<S: Write>(stream: &mut S, body: &[u8]) -> std::io::Result<()> {
    stream.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )?;
    stream.write_all(body)?;
    stream.flush()
}

fn proxy_tls_config() -> TlsConfig {
    TlsConfig::builder()
        .ca_file(proxy_ca())
        .build()
        .expect("proxy tls config build failed")
}

fn proxy_tls_config_with_client_cert(certs: &ClientCertFiles) -> TlsConfig {
    TlsConfig::builder()
        .ca_file(proxy_ca())
        .certificate_file(&certs.client_cert, TlsFileType::PEM)
        .private_key_file(&certs.client_key, TlsFileType::PEM)
        .build()
        .expect("proxy mtls config build failed")
}

fn client_with_proxy(proxy_url: &str, proxy_tls: TlsConfig) -> Client {
    let proxy = Proxy::all(proxy_url)
        .tls_config(proxy_tls)
        .build()
        .expect("proxy config build failed");
    ClientBuilder::new()
        .proxy(proxy)
        .tls_ca_file(origin_ca().to_str().unwrap())
        .danger_accept_invalid_hostnames(true)
        .build()
        .expect("client build failed")
}

async fn get_text(
    client: &Client,
    url: &str,
) -> Result<String, ylong_http_client::HttpClientError> {
    let request = Request::builder().url(url).body(Body::empty())?;
    let response = tokio::time::timeout(Duration::from_secs(5), client.request(request))
        .await
        .expect("request timed out")?;
    response.text().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdv_async_http_target_over_https_proxy() {
    let proxy = start_proxy(
        ProxyBehavior::HttpResponse(PROXY_BODY.as_bytes().to_vec()),
        None,
    );
    let client = client_with_proxy(&proxy.url("127.0.0.1"), proxy_tls_config());

    let body = get_text(&client, "http://example.com/proxy-http")
        .await
        .expect("HTTP over HTTPS proxy request failed");

    assert_eq!(body, PROXY_BODY);
    assert_eq!(
        proxy.events.recv().expect("missing proxy request line"),
        "GET http://example.com:80/proxy-http HTTP/1.1"
    );
    proxy.join();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdv_async_https_target_over_https_proxy() {
    let proxy = start_proxy(
        ProxyBehavior::ConnectThenOrigin {
            status: "204 No Content",
            origin_acceptor: origin_acceptor(),
            body: ORIGIN_BODY.as_bytes().to_vec(),
        },
        None,
    );
    let client = client_with_proxy(&proxy.url("127.0.0.1"), proxy_tls_config());
    let target = format!("https://127.0.0.1:{}/proxy-https", proxy.port);

    let body = get_text(&client, &target)
        .await
        .expect("HTTPS over HTTPS proxy request failed");

    assert_eq!(body, ORIGIN_BODY);
    assert_eq!(
        proxy.events.recv().expect("missing CONNECT line"),
        format!("CONNECT 127.0.0.1:{} HTTP/1.1", proxy.port)
    );
    assert_eq!(
        proxy.events.recv().expect("missing tunneled request line"),
        "GET /proxy-https HTTP/1.1"
    );
    proxy.join();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdv_async_https_proxy_rejects_wrong_ca() {
    let proxy = start_proxy(
        ProxyBehavior::HttpResponse(PROXY_BODY.as_bytes().to_vec()),
        None,
    );
    let bad_proxy_tls = TlsConfig::builder()
        .ca_file(origin_ca())
        .build()
        .expect("bad proxy tls config build failed");
    let client = client_with_proxy(&proxy.url("127.0.0.1"), bad_proxy_tls);

    let err = get_text(&client, "http://example.com/wrong-ca")
        .await
        .expect_err("wrong proxy CA unexpectedly succeeded");

    assert!(err.is_tls_error(), "expected TLS error, got {err:?}");
    proxy.join();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdv_async_https_proxy_rejects_hostname_mismatch() {
    let proxy = start_proxy(
        ProxyBehavior::HttpResponse(PROXY_BODY.as_bytes().to_vec()),
        None,
    );
    let client = client_with_proxy(&proxy.url("localhost"), proxy_tls_config());

    let err = get_text(&client, "http://example.com/hostname-mismatch")
        .await
        .expect_err("proxy hostname mismatch unexpectedly succeeded");

    assert!(err.is_tls_error(), "expected TLS error, got {err:?}");
    proxy.join();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdv_async_https_proxy_mtls_requires_client_cert() {
    let certs = ClientCertFiles::new();

    let proxy_without_client = start_proxy(
        ProxyBehavior::HttpResponse(PROXY_BODY.as_bytes().to_vec()),
        Some(&certs.client_ca),
    );
    let client_without_cert =
        client_with_proxy(&proxy_without_client.url("127.0.0.1"), proxy_tls_config());
    let err = get_text(&client_without_cert, "http://example.com/mtls-missing")
        .await
        .expect_err("mTLS without client certificate unexpectedly succeeded");
    assert!(err.is_tls_error(), "expected TLS error, got {err:?}");
    proxy_without_client.join();

    let proxy_with_client = start_proxy(
        ProxyBehavior::HttpResponse(PROXY_BODY.as_bytes().to_vec()),
        Some(&certs.client_ca),
    );
    let client_with_cert = client_with_proxy(
        &proxy_with_client.url("127.0.0.1"),
        proxy_tls_config_with_client_cert(&certs),
    );
    let body = get_text(&client_with_cert, "http://example.com/mtls-present")
        .await
        .expect("mTLS with client certificate failed");

    assert_eq!(body, PROXY_BODY);
    assert_eq!(
        proxy_with_client
            .events
            .recv()
            .expect("missing mTLS proxy request line"),
        "GET http://example.com:80/mtls-present HTTP/1.1"
    );
    proxy_with_client.join();
}

struct ClientCertFiles {
    dir: PathBuf,
    client_ca: PathBuf,
    client_cert: PathBuf,
    client_key: PathBuf,
}

impl ClientCertFiles {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "ylong-http-proxy-mtls-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time before UNIX epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("create temp cert dir failed");

        let client_ca = dir.join("client-ca.pem");
        let client_cert = dir.join("client.pem");
        let client_key = dir.join("client.key");
        generate_client_cert_files(&client_ca, &client_cert, &client_key);

        Self {
            dir,
            client_ca,
            client_cert,
            client_key,
        }
    }
}

impl Drop for ClientCertFiles {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn generate_client_cert_files(ca_path: &Path, cert_path: &Path, key_path: &Path) {
    let ca_key = PKey::from_rsa(Rsa::generate(2048).expect("generate CA key failed"))
        .expect("create CA key failed");
    let ca_cert = build_ca_cert(&ca_key);
    let client_key = PKey::from_rsa(Rsa::generate(2048).expect("generate client key failed"))
        .expect("create client key failed");
    let client_cert = build_client_cert(&client_key, &ca_key, &ca_cert);

    fs::write(ca_path, ca_cert.to_pem().expect("encode CA cert failed"))
        .expect("write CA cert failed");
    fs::write(
        cert_path,
        client_cert.to_pem().expect("encode client cert failed"),
    )
    .expect("write client cert failed");
    fs::write(
        key_path,
        client_key
            .private_key_to_pem_pkcs8()
            .expect("encode client key failed"),
    )
    .expect("write client key failed");
}

fn build_ca_cert(ca_key: &PKey<Private>) -> X509 {
    let mut name = X509NameBuilder::new().expect("CA name builder failed");
    name.append_entry_by_nid(Nid::COMMONNAME, "ylong test proxy client CA")
        .expect("set CA CN failed");
    let name = name.build();

    let mut builder = X509::builder().expect("CA cert builder failed");
    builder.set_version(2).expect("set CA version failed");
    builder
        .set_serial_number(&serial().expect("create CA serial failed"))
        .expect("set CA serial failed");
    builder
        .set_subject_name(&name)
        .expect("set CA subject failed");
    builder
        .set_issuer_name(&name)
        .expect("set CA issuer failed");
    builder
        .set_pubkey(ca_key)
        .expect("set CA public key failed");
    builder
        .set_not_before(&Asn1Time::days_from_now(0).expect("set CA not_before failed"))
        .expect("apply CA not_before failed");
    builder
        .set_not_after(&Asn1Time::days_from_now(1).expect("set CA not_after failed"))
        .expect("apply CA not_after failed");
    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .build()
                .expect("build CA basic constraints failed"),
        )
        .expect("append CA basic constraints failed");
    builder
        .append_extension(
            KeyUsage::new()
                .key_cert_sign()
                .crl_sign()
                .build()
                .expect("build CA key usage failed"),
        )
        .expect("append CA key usage failed");
    builder
        .sign(ca_key, MessageDigest::sha256())
        .expect("sign CA cert failed");
    builder.build()
}

fn build_client_cert(client_key: &PKey<Private>, ca_key: &PKey<Private>, ca_cert: &X509) -> X509 {
    let mut name = X509NameBuilder::new().expect("client name builder failed");
    name.append_entry_by_nid(Nid::COMMONNAME, "ylong test proxy client")
        .expect("set client CN failed");
    let name = name.build();

    let mut builder = X509::builder().expect("client cert builder failed");
    builder.set_version(2).expect("set client version failed");
    builder
        .set_serial_number(&serial().expect("create client serial failed"))
        .expect("set client serial failed");
    builder
        .set_subject_name(&name)
        .expect("set client subject failed");
    builder
        .set_issuer_name(ca_cert.subject_name())
        .expect("set client issuer failed");
    builder
        .set_pubkey(client_key)
        .expect("set client public key failed");
    builder
        .set_not_before(&Asn1Time::days_from_now(0).expect("set client not_before failed"))
        .expect("apply client not_before failed");
    builder
        .set_not_after(&Asn1Time::days_from_now(1).expect("set client not_after failed"))
        .expect("apply client not_after failed");
    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .build()
                .expect("build client basic constraints failed"),
        )
        .expect("append client basic constraints failed");
    builder
        .append_extension(
            KeyUsage::new()
                .digital_signature()
                .key_encipherment()
                .build()
                .expect("build client key usage failed"),
        )
        .expect("append client key usage failed");
    builder
        .append_extension(
            ExtendedKeyUsage::new()
                .client_auth()
                .build()
                .expect("build client EKU failed"),
        )
        .expect("append client EKU failed");
    builder
        .sign(ca_key, MessageDigest::sha256())
        .expect("sign client cert failed");
    builder.build()
}

fn serial() -> Result<openssl::asn1::Asn1Integer, openssl::error::ErrorStack> {
    let mut serial = BigNum::new()?;
    serial.rand(64, MsbOption::MAYBE_ZERO, false)?;
    serial.to_asn1_integer()
}
