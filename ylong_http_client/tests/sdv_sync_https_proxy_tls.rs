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
    feature = "sync",
    feature = "http1_1",
    feature = "__tls",
    feature = "tokio_base"
))]

use std::io::{Error as IoError, ErrorKind as IoErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use ylong_http_client::sync_impl::{
    BodyProcessError, BodyProcessor, BodyReader, Client, ClientBuilder, Connector, EmptyBody,
    Request,
};
use ylong_http_client::{HttpClientError, Proxy, TlsConfig};

const PROXY_BODY: &str = "sync http over https proxy";
const ORIGIN_BODY: &str = "sync https over https proxy";

struct ProxyServer {
    port: u16,
    events: Receiver<String>,
    join: JoinHandle<()>,
}

impl ProxyServer {
    fn url(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
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

fn start_proxy(behavior: ProxyBehavior) -> ProxyServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("proxy bind failed");
    let port = listener
        .local_addr()
        .expect("proxy local addr failed")
        .port();
    let acceptor = proxy_acceptor();
    let (tx, rx) = channel();

    let join = thread::spawn(move || {
        let (tcp, _) = listener.accept().expect("proxy accept failed");
        tcp.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set proxy read timeout failed");
        tcp.set_write_timeout(Some(Duration::from_secs(5)))
            .expect("set proxy write timeout failed");

        let mut proxy_tls = acceptor.accept(tcp).expect("proxy TLS accept failed");
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

                let mut origin_tls = origin_acceptor
                    .accept(proxy_tls)
                    .expect("origin TLS accept failed");
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

fn proxy_acceptor() -> SslAcceptor {
    let mut builder =
        SslAcceptor::mozilla_intermediate(SslMethod::tls()).expect("proxy acceptor build failed");
    builder
        .set_private_key_file(proxy_key(), SslFiletype::PEM)
        .expect("set proxy private key failed");
    builder
        .set_certificate_chain_file(proxy_cert())
        .expect("set proxy certificate failed");
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

fn client_with_proxy(proxy_url: &str) -> Client<impl Connector> {
    let proxy = Proxy::all(proxy_url)
        .tls_config(proxy_tls_config())
        .build()
        .expect("proxy config build failed");
    ClientBuilder::new()
        .proxy(proxy)
        .tls_ca_file(origin_ca().to_str().unwrap())
        .danger_accept_invalid_hostnames(true)
        .build()
        .expect("client build failed")
}

fn get_text<C: Connector>(client: &Client<C>, url: &str) -> Result<String, HttpClientError> {
    let request = Request::get(url)
        .body(EmptyBody)
        .map_err(HttpClientError::other)?;
    let mut response = client.request(request)?;
    let mut collector = Collector(Vec::new());
    BodyReader::new(&mut collector).read_all(response.body_mut())?;
    String::from_utf8(collector.0).map_err(HttpClientError::other)
}

struct Collector(Vec<u8>);

impl BodyProcessor for &mut Collector {
    fn write(&mut self, data: &[u8]) -> Result<(), BodyProcessError> {
        self.0.extend_from_slice(data);
        Ok(())
    }

    fn progress(&mut self, _filled: usize) -> Result<(), BodyProcessError> {
        Ok(())
    }
}

#[test]
fn sdv_sync_http_target_over_https_proxy() {
    let proxy = start_proxy(ProxyBehavior::HttpResponse(PROXY_BODY.as_bytes().to_vec()));
    let client = client_with_proxy(&proxy.url());

    let body = get_text(&client, "http://example.com/sync-proxy-http")
        .expect("sync HTTP over HTTPS proxy request failed");

    assert_eq!(body, PROXY_BODY);
    assert_eq!(
        proxy.events.recv().expect("missing proxy request line"),
        "GET http://example.com:80/sync-proxy-http HTTP/1.1"
    );
    proxy.join();
}

#[test]
fn sdv_sync_https_target_over_https_proxy() {
    let proxy = start_proxy(ProxyBehavior::ConnectThenOrigin {
        status: "204 No Content",
        origin_acceptor: origin_acceptor(),
        body: ORIGIN_BODY.as_bytes().to_vec(),
    });
    let client = client_with_proxy(&proxy.url());
    let target = format!("https://127.0.0.1:{}/sync-proxy-https", proxy.port);

    let body = get_text(&client, &target).expect("sync HTTPS over HTTPS proxy request failed");

    assert_eq!(body, ORIGIN_BODY);
    assert_eq!(
        proxy.events.recv().expect("missing CONNECT line"),
        format!("CONNECT 127.0.0.1:{} HTTP/1.1", proxy.port)
    );
    assert_eq!(
        proxy.events.recv().expect("missing tunneled request line"),
        "GET /sync-proxy-https HTTP/1.1"
    );
    proxy.join();
}
