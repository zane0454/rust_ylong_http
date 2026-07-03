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

use std::io::{Read, Write};

use ylong_http::request::uri::Uri;

use crate::util::config::ConnectorConfig;

/// `Connector` trait used by `Client`. `Connector` provides synchronous
/// connection establishment interfaces.
pub trait Connector {
    /// The connection object established by `Connector::connect`.
    type Stream: Read + Write + 'static;
    /// Possible errors during connection establishment.
    type Error: Into<Box<dyn std::error::Error + Send + Sync>>;

    /// Attempts to establish a synchronous connection.
    fn connect(&self, uri: &Uri) -> Result<Self::Stream, Self::Error>;
}

/// Connector for creating HTTP connections synchronously.
///
/// `HttpConnector` implements `sync_impl::Connector` trait.
pub struct HttpConnector {
    config: ConnectorConfig,
}

impl HttpConnector {
    /// Creates a new `HttpConnector`.
    pub(crate) fn new(config: ConnectorConfig) -> HttpConnector {
        HttpConnector { config }
    }
}

impl Default for HttpConnector {
    fn default() -> Self {
        Self::new(ConnectorConfig::default())
    }
}

#[cfg(not(feature = "__tls"))]
pub mod no_tls {
    use std::io::Error;
    use std::net::TcpStream;

    use ylong_http::request::uri::Uri;

    use crate::sync_impl::Connector;

    impl Connector for super::HttpConnector {
        type Stream = TcpStream;
        type Error = Error;

        fn connect(&self, uri: &Uri) -> Result<Self::Stream, Self::Error> {
            let addr = if let Some(proxy) = self.config.proxies.match_proxy(uri) {
                let proxy_info = proxy.intercept.proxy_info();
                if proxy_info.is_secure() {
                    return Err(Error::new(
                        std::io::ErrorKind::Other,
                        "HTTPS proxy requires TLS feature",
                    ));
                }
                proxy_info.addr()
            } else {
                uri.authority().unwrap().to_string()
            };
            TcpStream::connect(addr)
        }
    }
}

#[cfg(feature = "__tls")]
pub mod tls_conn {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    use ylong_http::request::uri::{Scheme, Uri};

    use crate::sync_impl::ssl_stream::ProxyStream;
    use crate::sync_impl::{Connector, MixStream};
    use crate::util::proxy::{
        connect_request, parse_tunnel_response, tunnel_io_error, ProxyInfo, TunnelResponse,
        MAX_TUNNEL_RESPONSE_SIZE,
    };
    use crate::{ErrorKind, HttpClientError};

    impl Connector for super::HttpConnector {
        type Stream = MixStream<TcpStream>;
        type Error = HttpClientError;

        fn connect(&self, uri: &Uri) -> Result<Self::Stream, Self::Error> {
            // Make sure all parts of uri is accurate.
            let host = uri.host().unwrap().as_str().to_string();
            let port = uri.port().unwrap().as_u16().unwrap();
            let proxy_info = self
                .config
                .proxies
                .match_proxy(uri)
                .map(|proxy| proxy.intercept.proxy_info().clone());
            let addr = proxy_info
                .as_ref()
                .map(ProxyInfo::addr)
                .unwrap_or_else(|| uri.authority().unwrap().to_string());

            let host_name = match uri.host() {
                Some(host) => host.to_string(),
                None => "no host in uri".to_string(),
            };

            match *uri.scheme().unwrap() {
                Scheme::HTTP => {
                    let tcp_stream = TcpStream::connect(addr).map_err(|e| {
                        HttpClientError::from_error(ErrorKind::Connect, e)
                    })?;
                    if let Some(proxy_info) = proxy_info {
                        Ok(MixStream::Proxy(proxy_connect_stream(
                            tcp_stream,
                            &proxy_info,
                        )?))
                    } else {
                        Ok(MixStream::Http(tcp_stream))
                    }
                }
                Scheme::HTTPS => {
                    let tcp_stream = TcpStream::connect(addr)
                        .map_err(|e| HttpClientError::from_error(ErrorKind::Connect, e))?;

                    if let Some(proxy_info) = proxy_info {
                        let auth = proxy_info.basic_auth_value();
                        let proxy_stream = proxy_connect_stream(tcp_stream, &proxy_info)?;
                        let tunnel = tunnel(proxy_stream, host, port, auth)?;
                        let tls_ssl = self
                            .config
                            .tls
                            .ssl_new(&host_name)
                            .map_err(|e| HttpClientError::from_error(ErrorKind::Connect, e))?;

                        let stream = tls_ssl
                            .into_inner()
                            .connect(tunnel)
                            .map_err(|e| HttpClientError::from_error(ErrorKind::Connect, e))?;
                        Ok(MixStream::HttpsOverProxy(stream))
                    } else {
                        let tls_ssl = self
                            .config
                            .tls
                            .ssl_new(&host_name)
                            .map_err(|e| HttpClientError::from_error(ErrorKind::Connect, e))?;

                        let stream = tls_ssl
                            .into_inner()
                            .connect(tcp_stream)
                            .map_err(|e| HttpClientError::from_error(ErrorKind::Connect, e))?;
                        Ok(MixStream::Https(stream))
                    }
                }
            }
        }
    }

    fn proxy_connect_stream(
        tcp: TcpStream,
        proxy: &ProxyInfo,
    ) -> Result<ProxyStream<TcpStream>, HttpClientError> {
        if !proxy.is_secure() {
            return Ok(ProxyStream::Tcp(tcp));
        }

        let tls_ssl = proxy
            .tls_config()
            .ssl_new(proxy.host())
            .map_err(|e| HttpClientError::from_error(ErrorKind::Connect, e))?;
        let stream = tls_ssl
            .into_inner()
            .connect(tcp)
            .map_err(|e| HttpClientError::from_error(ErrorKind::Connect, e))?;
        Ok(ProxyStream::Tls(stream))
    }

    fn tunnel(
        mut conn: ProxyStream<TcpStream>,
        host: String,
        port: u16,
        auth: Option<String>,
    ) -> Result<ProxyStream<TcpStream>, HttpClientError> {
        let req = connect_request(&host, port, auth.as_deref())
            .map_err(|e| HttpClientError::from_error(ErrorKind::Connect, e))?;

        conn.write_all(&req)
            .map_err(|e| HttpClientError::from_error(ErrorKind::Connect, e))?;

        let mut buf = [0; MAX_TUNNEL_RESPONSE_SIZE];
        let mut pos = 0;

        loop {
            let n = conn
                .read(&mut buf[pos..])
                .map_err(|e| HttpClientError::from_error(ErrorKind::Connect, e))?;

            if n == 0 {
                return Err(HttpClientError::from_error(
                    ErrorKind::Connect,
                    tunnel_io_error(crate::util::proxy::CreateTunnelErr::Unsuccessful),
                ));
            }

            pos += n;
            match parse_tunnel_response(&buf[..pos]) {
                Ok(TunnelResponse::Complete) => return Ok(conn),
                Ok(TunnelResponse::Incomplete) => {}
                Err(e) => {
                    return Err(HttpClientError::from_error(
                        ErrorKind::Connect,
                        tunnel_io_error(e),
                    ));
                }
            }
            if pos == buf.len() {
                return Err(HttpClientError::from_error(
                    ErrorKind::Connect,
                    tunnel_io_error(crate::util::proxy::CreateTunnelErr::ProxyHeadersTooLong),
                ));
            }
        }
    }
}
