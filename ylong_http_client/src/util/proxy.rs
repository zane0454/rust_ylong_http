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

//! Proxy implementation.

use core::convert::TryFrom;
use std::error;
use std::fmt::{Debug, Display, Formatter};
use std::io::{Error, ErrorKind, Write};
use std::net::IpAddr;

use ylong_http::headers::HeaderValue;
use ylong_http::request::uri::{Authority, Scheme, Uri};

use crate::error::HttpClientError;
use crate::util::base64::encode;
use crate::util::normalizer::UriFormatter;
#[cfg(feature = "__tls")]
use crate::util::TlsConfig;

pub(crate) const MAX_TUNNEL_RESPONSE_SIZE: usize = 8192;

/// `Proxies` is responsible for managing a list of proxies.
#[derive(Clone, Default)]
pub(crate) struct Proxies {
    list: Vec<Proxy>,
}

impl Proxies {
    pub(crate) fn add_proxy(&mut self, proxy: Proxy) {
        self.list.push(proxy)
    }

    pub(crate) fn match_proxy(&self, uri: &Uri) -> Option<&Proxy> {
        self.list.iter().find(|proxy| proxy.is_intercepted(uri))
    }
}

/// Proxy is a configuration of client which should manage the destination
/// address of request.
///
/// A `Proxy` has below rules:
///
/// - Manage the uri of destination address.
/// - Manage the request content such as headers.
/// - Provide no proxy function which the request will not affected by proxy.
#[derive(Clone)]
pub(crate) struct Proxy {
    pub(crate) intercept: Intercept,
    pub(crate) no_proxy: Option<NoProxy>,
}

impl Proxy {
    pub(crate) fn new(intercept: Intercept) -> Self {
        Self {
            intercept,
            no_proxy: None,
        }
    }

    pub(crate) fn http(uri: &str) -> Result<Self, HttpClientError> {
        Ok(Proxy::new(Intercept::Http(ProxyInfo::new(uri)?)))
    }

    pub(crate) fn https(uri: &str) -> Result<Self, HttpClientError> {
        Ok(Proxy::new(Intercept::Https(ProxyInfo::new(uri)?)))
    }

    pub(crate) fn all(uri: &str) -> Result<Self, HttpClientError> {
        Ok(Proxy::new(Intercept::All(ProxyInfo::new(uri)?)))
    }

    pub(crate) fn basic_auth(&mut self, username: &str, password: &str) {
        let auth = encode(format!("{username}:{password}").as_bytes());

        // All characters in base64 format are valid characters, so we ignore the error.
        let mut auth = HeaderValue::from_bytes(auth.as_slice()).unwrap();
        auth.set_sensitive(true);

        match &mut self.intercept {
            Intercept::All(info) => info.basic_auth = Some(auth),
            Intercept::Http(info) => info.basic_auth = Some(auth),
            Intercept::Https(info) => info.basic_auth = Some(auth),
        }
    }

    #[cfg(feature = "__tls")]
    pub(crate) fn set_tls_config(&mut self, config: TlsConfig) {
        match &mut self.intercept {
            Intercept::All(info) => info.tls_config = Some(config),
            Intercept::Http(info) => info.tls_config = Some(config),
            Intercept::Https(info) => info.tls_config = Some(config),
        }
    }

    pub(crate) fn no_proxy(&mut self, no_proxy: &str) {
        self.no_proxy = NoProxy::from_str(no_proxy);
    }

    pub(crate) fn via_proxy(&self, uri: &Uri) -> Uri {
        let info = self.intercept.proxy_info();
        let mut builder = Uri::builder();
        builder = builder
            .scheme(info.scheme().clone())
            .authority(info.authority().clone());

        if let Some(path) = uri.path() {
            builder = builder.path(path.clone());
        }

        if let Some(query) = uri.query() {
            builder = builder.query(query.clone());
        }

        // Here all parts of builder is accurate.
        builder.build().unwrap()
    }

    pub(crate) fn is_intercepted(&self, uri: &Uri) -> bool {
        // uri is formatted uri, use unwrap directly
        let no_proxy = self
            .no_proxy
            .as_ref()
            .map(|no_proxy| no_proxy.contain(uri.host().unwrap().as_str()))
            .unwrap_or(false);

        match self.intercept {
            Intercept::All(_) => !no_proxy,
            Intercept::Http(_) => !no_proxy && *uri.scheme().unwrap() == Scheme::HTTP,
            Intercept::Https(_) => !no_proxy && *uri.scheme().unwrap() == Scheme::HTTPS,
        }
    }
}

#[derive(Clone)]
pub(crate) enum Intercept {
    All(ProxyInfo),
    Http(ProxyInfo),
    Https(ProxyInfo),
}

impl Intercept {
    pub(crate) fn proxy_info(&self) -> &ProxyInfo {
        match self {
            Self::All(info) => info,
            Self::Http(info) => info,
            Self::Https(info) => info,
        }
    }
}

/// ProxyInfo which contains authentication, scheme and host.
#[derive(Clone)]
pub(crate) struct ProxyInfo {
    pub(crate) scheme: Scheme,
    pub(crate) authority: Authority,
    pub(crate) basic_auth: Option<HeaderValue>,
    #[cfg(feature = "__tls")]
    pub(crate) tls_config: Option<TlsConfig>,
}

impl ProxyInfo {
    pub(crate) fn new(uri: &str) -> Result<Self, HttpClientError> {
        let mut uri = match Uri::try_from(uri) {
            Ok(u) => u,
            Err(e) => {
                return err_from_other!(Build, e);
            }
        };
        // Makes sure that all parts of uri exist.
        UriFormatter::new().format(&mut uri)?;
        let (scheme, authority, _, _) = uri.into_parts();
        // `scheme` and `authority` must have values after formatting.
        let scheme = scheme.unwrap();
        let authority = authority.unwrap();
        if scheme != Scheme::HTTP && scheme != Scheme::HTTPS {
            return err_from_msg!(Build, "Proxy only supports http and https schemes");
        }

        Ok(Self {
            basic_auth: None,
            scheme,
            authority,
            #[cfg(feature = "__tls")]
            tls_config: None,
        })
    }

    pub(crate) fn authority(&self) -> &Authority {
        &self.authority
    }

    pub(crate) fn scheme(&self) -> &Scheme {
        &self.scheme
    }

    pub(crate) fn addr(&self) -> String {
        self.authority.to_string()
    }

    pub(crate) fn host(&self) -> &str {
        self.authority.host().as_str()
    }

    pub(crate) fn port(&self) -> u16 {
        self.authority
            .port()
            .and_then(|port| port.as_u16().ok())
            .unwrap_or_else(|| self.scheme.default_port())
    }

    pub(crate) fn is_secure(&self) -> bool {
        self.scheme == Scheme::HTTPS
    }

    pub(crate) fn basic_auth_value(&self) -> Option<&HeaderValue> {
        self.basic_auth.as_ref()
    }

    #[cfg(feature = "__tls")]
    pub(crate) fn tls_config(&self) -> TlsConfig {
        self.tls_config.clone().unwrap_or_default()
    }
}

pub(crate) fn connect_request(
    host: &str,
    port: u16,
    auth: Option<&HeaderValue>,
) -> Result<Vec<u8>, Error> {
    let auth_len = auth.map(header_value_len).unwrap_or(0);
    let mut req = Vec::with_capacity(host.len() * 2 + auth_len + 64);

    write!(
        &mut req,
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
    )?;

    if let Some(value) = auth {
        req.extend_from_slice(b"Proxy-Authorization: Basic ");
        append_header_value(&mut req, value);
        req.extend_from_slice(b"\r\n");
    }

    req.extend_from_slice(b"\r\n");
    Ok(req)
}

fn header_value_len(value: &HeaderValue) -> usize {
    value
        .iter()
        .enumerate()
        .map(|(idx, bytes)| bytes.len() + usize::from(idx != 0) * 2)
        .sum()
}

fn append_header_value(buf: &mut Vec<u8>, value: &HeaderValue) {
    for (idx, bytes) in value.iter().enumerate() {
        if idx != 0 {
            buf.extend_from_slice(b", ");
        }
        buf.extend_from_slice(bytes.as_slice());
    }
}

pub(crate) enum TunnelResponse {
    Complete,
    Incomplete,
}

pub(crate) fn parse_tunnel_response(buf: &[u8]) -> Result<TunnelResponse, CreateTunnelErr> {
    let (line_end, header_end) = response_boundaries(buf);
    let Some(line_end) = line_end else {
        return if buf.len() >= MAX_TUNNEL_RESPONSE_SIZE {
            Err(CreateTunnelErr::ProxyHeadersTooLong)
        } else {
            Ok(TunnelResponse::Incomplete)
        };
    };

    let status = &buf[..line_end];
    let code = status_code(status)?;

    match code {
        [b'2', _, _] => {
            if header_end.is_some() {
                Ok(TunnelResponse::Complete)
            } else if buf.len() >= MAX_TUNNEL_RESPONSE_SIZE {
                Err(CreateTunnelErr::ProxyHeadersTooLong)
            } else {
                Ok(TunnelResponse::Incomplete)
            }
        }
        b"407" => Err(CreateTunnelErr::ProxyAuthenticationRequired),
        _ => Err(CreateTunnelErr::Unsuccessful),
    }
}

fn response_boundaries(buf: &[u8]) -> (Option<usize>, Option<usize>) {
    let mut line_end = None;
    let mut idx = 0;

    while idx + 1 < buf.len() {
        if buf[idx] == b'\r' && buf[idx + 1] == b'\n' {
            line_end.get_or_insert(idx);
            if idx + 3 < buf.len() && buf[idx + 2] == b'\r' && buf[idx + 3] == b'\n' {
                return (line_end, Some(idx + 4));
            }
            idx += 2;
        } else {
            idx += 1;
        }
    }

    (line_end, None)
}

fn status_code(status: &[u8]) -> Result<&[u8], CreateTunnelErr> {
    if status.len() < 12 || !(status.starts_with(b"HTTP/1.1 ") || status.starts_with(b"HTTP/1.0 "))
    {
        return Err(CreateTunnelErr::Unsuccessful);
    }

    if status.len() > 12 && status[12] != b' ' {
        return Err(CreateTunnelErr::Unsuccessful);
    }

    let code = &status[9..12];
    if !code.iter().all(u8::is_ascii_digit) {
        return Err(CreateTunnelErr::Unsuccessful);
    }

    Ok(code)
}

pub(crate) fn tunnel_io_error(err: CreateTunnelErr) -> Error {
    Error::new(ErrorKind::Other, err)
}

pub(crate) enum CreateTunnelErr {
    ProxyHeadersTooLong,
    ProxyAuthenticationRequired,
    Unsuccessful,
}

impl Debug for CreateTunnelErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProxyHeadersTooLong => f.write_str("Proxy headers too long for tunnel"),
            Self::ProxyAuthenticationRequired => f.write_str("Proxy authentication required"),
            Self::Unsuccessful => f.write_str("Unsuccessful tunnel"),
        }
    }
}

impl Display for CreateTunnelErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

impl error::Error for CreateTunnelErr {}

#[derive(Clone)]
enum Ip {
    Address(IpAddr),
}

#[derive(Clone, Default)]
pub(crate) struct NoProxy {
    ips: Vec<Ip>,
    domains: Vec<String>,
}

impl NoProxy {
    pub(crate) fn from_str(no_proxy: &str) -> Option<Self> {
        if no_proxy.is_empty() {
            return None;
        }

        let no_proxy_vec = no_proxy.split(',').map(|c| c.trim()).collect::<Vec<&str>>();
        let mut ip_list = Vec::new();
        let mut domains_list = Vec::new();

        for host in no_proxy_vec {
            let address = match Uri::from_bytes(host.as_bytes()) {
                Ok(uri) => uri,
                Err(_) => {
                    continue;
                }
            };
            // use unwrap directly, host has been checked before
            match address.host().unwrap().as_str().parse::<IpAddr>() {
                Ok(ip) => ip_list.push(Ip::Address(ip)),
                Err(_) => domains_list.push(host.to_string()),
            }
        }
        Some(NoProxy {
            ips: ip_list,
            domains: domains_list,
        })
    }

    pub(crate) fn contain(&self, proxy_host: &str) -> bool {
        match proxy_host.parse::<IpAddr>() {
            Ok(ip) => self.contains_ip(ip),
            Err(_) => self.contains_domain(proxy_host),
        }
    }

    fn contains_ip(&self, ip: IpAddr) -> bool {
        for Ip::Address(i) in self.ips.iter() {
            if &ip == i {
                return true;
            }
        }
        false
    }

    fn contains_domain(&self, domain: &str) -> bool {
        for block_domain in self.domains.iter() {
            let mut block_domain = block_domain.clone();
            // Changes *.example.com to .example.com
            if (block_domain.starts_with('*')) && (block_domain.len() > 1) {
                block_domain = block_domain.trim_matches('*').to_string();
            }

            if block_domain == "*"
                || block_domain.ends_with(domain)
                || block_domain == domain
                || block_domain.trim_matches('.') == domain
            {
                return true;
            } else if domain.ends_with(&block_domain) {
                // .example.com and www.
                if block_domain.starts_with('.')
                    || domain.as_bytes().get(domain.len() - block_domain.len() - 1) == Some(&b'.')
                {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod ut_proxy {
    use ylong_http::headers::HeaderValue;
    use ylong_http::request::uri::{Scheme, Uri};

    use crate::util::proxy::{
        connect_request, parse_tunnel_response, CreateTunnelErr, Proxies, Proxy, TunnelResponse,
    };

    /// UT test cases for `Proxy::via_proxy`.
    ///
    /// # Brief
    /// 1. Creates a `Proxy`.
    /// 2. Calls `Proxy::via_proxy` with some `Uri`to get the results.
    /// 4. Checks if the test result is correct.
    #[test]
    fn ut_via_proxy() {
        let proxy = Proxy::http("http://www.example.com").unwrap();
        let uri = Uri::from_bytes(b"http://www.example2.com").unwrap();
        let res = proxy.via_proxy(&uri);
        assert_eq!(res.to_string(), "http://www.example.com:80");
    }

    /// UT test cases for `Proxies`.
    ///
    /// # Brief
    /// 1. Creates a `Proxies`.
    /// 2. Adds some `Proxy` to `Proxies`
    /// 3. Calls `Proxies::match_proxy` with some `Uri`s and get the results.
    /// 4. Checks if the test result is correct.
    #[test]
    fn ut_proxies() {
        let mut proxies = Proxies::default();
        proxies.add_proxy(Proxy::http("http://www.aaa.com").unwrap());
        proxies.add_proxy(Proxy::https("http://www.bbb.com").unwrap());

        let uri = Uri::from_bytes(b"http://www.example.com").unwrap();
        let proxy = proxies.match_proxy(&uri).unwrap();
        assert!(proxy.no_proxy.is_none());
        let info = proxy.intercept.proxy_info();
        assert_eq!(info.scheme, Scheme::HTTP);
        assert_eq!(info.authority.to_string(), "www.aaa.com:80");

        let uri = Uri::from_bytes(b"https://www.example.com").unwrap();
        let matched = proxies.match_proxy(&uri).unwrap();
        assert!(matched.no_proxy.is_none());
        let info = matched.intercept.proxy_info();
        assert_eq!(info.scheme, Scheme::HTTP);
        assert_eq!(info.authority.to_string(), "www.bbb.com:80");

        // with no_proxy
        let mut proxies = Proxies::default();
        let mut proxy = Proxy::http("http://www.aaa.com").unwrap();
        proxy.no_proxy("http://no_proxy.aaa.com");
        proxies.add_proxy(proxy);

        let uri = Uri::from_bytes(b"http://www.bbb.com").unwrap();
        let matched = proxies.match_proxy(&uri).unwrap();
        let info = matched.intercept.proxy_info();
        assert_eq!(info.scheme, Scheme::HTTP);
        assert_eq!(info.authority.to_string(), "www.aaa.com:80");

        let uri = Uri::from_bytes(b"http://no_proxy.aaa.com").unwrap();
        assert!(proxies.match_proxy(&uri).is_none());

        let mut proxies = Proxies::default();
        let mut proxy = Proxy::http("http://www.aaa.com").unwrap();
        proxy.no_proxy(".aaa.com");
        proxies.add_proxy(proxy);

        let uri = Uri::from_bytes(b"http://no_proxy.aaa.com").unwrap();
        assert!(proxies.match_proxy(&uri).is_none());

        let mut proxies = Proxies::default();
        let mut proxy = Proxy::http("http://127.0.0.1:3000").unwrap();
        proxy.no_proxy("http://127.0.0.1:80");
        proxies.add_proxy(proxy);

        let uri = Uri::from_bytes(b"http://127.0.0.1:80").unwrap();
        assert!(proxies.match_proxy(&uri).is_none());
    }

    /// UT test cases for HTTPS proxy endpoint information.
    #[test]
    fn ut_https_proxy_info() {
        let proxy = Proxy::https("https://www.example.com").unwrap();
        let info = proxy.intercept.proxy_info();
        assert_eq!(info.scheme, Scheme::HTTPS);
        assert_eq!(info.addr(), "www.example.com:443");
        assert_eq!(info.host(), "www.example.com");
        assert_eq!(info.port(), 443);
        assert!(info.is_secure());
    }

    /// UT test cases for proxy endpoint validation.
    #[test]
    fn ut_proxy_endpoint_validation() {
        assert!(Proxy::http("ftp://www.example.com").is_err());
        assert!(Proxy::all("http://").is_err());
    }

    /// UT test cases for HTTPS proxy TLS config.
    #[cfg(feature = "__tls")]
    #[test]
    fn ut_https_proxy_tls_config() {
        let tls = crate::util::TlsConfig::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let mut proxy = Proxy::https("https://www.example.com").unwrap();
        proxy.set_tls_config(tls);
        assert!(proxy.intercept.proxy_info().tls_config.is_some());
    }

    /// UT test cases for tunnel request and response parsing.
    #[test]
    fn ut_tunnel_request_and_response() {
        let auth = HeaderValue::from_bytes(b"token").unwrap();
        let req = connect_request("www.example.com", 443, Some(&auth)).unwrap();
        assert_eq!(
            String::from_utf8(req).unwrap(),
            "CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\nProxy-Authorization: Basic token\r\n\r\n"
        );

        assert!(matches!(
            parse_tunnel_response(b"HTTP/1.1 200 Connection Established\r\n\r\n"),
            Ok(TunnelResponse::Complete)
        ));
        assert!(matches!(
            parse_tunnel_response(b"HTTP/1.1 201 Created\r\n\r\n"),
            Ok(TunnelResponse::Complete)
        ));
        assert!(matches!(
            parse_tunnel_response(b"HTTP/1.1 204 No Content\r\n\r\n"),
            Ok(TunnelResponse::Complete)
        ));
        assert!(matches!(
            parse_tunnel_response(b"HTTP/1.1 2000 Connection Established\r\n\r\n"),
            Err(CreateTunnelErr::Unsuccessful)
        ));
        assert!(matches!(
            parse_tunnel_response(b"HTTP/1.1 200Connection Established\r\n\r\n"),
            Err(CreateTunnelErr::Unsuccessful)
        ));
        assert!(matches!(
            parse_tunnel_response(b"HTTP/1.1 20A Connection Established\r\n\r\n"),
            Err(CreateTunnelErr::Unsuccessful)
        ));
        assert!(matches!(
            parse_tunnel_response(b"HTTP/1.1 200 Connection Established\r\n"),
            Ok(TunnelResponse::Incomplete)
        ));
        assert!(matches!(
            parse_tunnel_response(b"HTTP/1.1 200 Connection Established\r\nHeader: value\r\n"),
            Ok(TunnelResponse::Incomplete)
        ));
        assert!(matches!(
            parse_tunnel_response(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"),
            Err(CreateTunnelErr::ProxyAuthenticationRequired)
        ));
        assert!(matches!(
            parse_tunnel_response(b"HTTP/1.1 500 Internal Server Error\r\n\r\n"),
            Err(CreateTunnelErr::Unsuccessful)
        ));
    }
}
