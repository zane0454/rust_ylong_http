//! Native HTTPS proxy benchmark fixture.
//!
//! The Python benchmark harness treats this binary as the canonical fixture
//! because proxy/origin response timing should not be dominated by Python
//! `ssl.SSLSocket.sendall` scheduling.

use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslStream, SslVerifyMode};
use std::collections::VecDeque;
use std::env;
use std::error::Error;
use std::io::{self, BufRead, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

type AnyError = Box<dyn Error + Send + Sync>;
type SharedTrace = Arc<Mutex<TraceCounters>>;

#[derive(Debug)]
struct Args {
    scenario: String,
    body_bytes: usize,
    proxy_cert: PathBuf,
    proxy_key: PathBuf,
    origin_cert: PathBuf,
    origin_key: PathBuf,
    client_ca: Option<PathBuf>,
    origin_tls: bool,
}

#[derive(Clone, Default)]
struct TraceCounters {
    proxy_connections: u64,
    proxy_forward_requests: u64,
    proxy_connect_requests: u64,
    proxy_tunnel_bytes_from_client: u64,
    proxy_tunnel_bytes_from_origin: u64,
    proxy_tls_client_auth_failures: u64,
    proxy_request_header_bytes: u64,
    proxy_request_body_bytes: u64,
    proxy_response_body_bytes: u64,
    proxy_response_send_us: u64,
    proxy_response_send_events: u64,
    proxy_tunnel_send_to_client_us: u64,
    proxy_tunnel_send_to_client_events: u64,
    proxy_tunnel_send_to_origin_us: u64,
    proxy_tunnel_send_to_origin_events: u64,
    proxy_tunnel_poll_calls: u64,
    proxy_tunnel_poll_timeouts: u64,
    proxy_tunnel_client_read_would_block: u64,
    proxy_tunnel_origin_read_would_block: u64,
    proxy_tunnel_send_to_client_would_block: u64,
    proxy_tunnel_send_to_origin_would_block: u64,
    proxy_tunnel_client_to_origin_queue_bytes_max: u64,
    proxy_tunnel_origin_to_client_queue_bytes_max: u64,
    origin_connections: u64,
    origin_requests: u64,
    origin_tls_connections: u64,
    origin_request_header_bytes: u64,
    origin_request_body_bytes: u64,
    origin_response_body_bytes: u64,
    origin_response_send_us: u64,
    origin_response_send_events: u64,
}

fn main() -> Result<(), AnyError> {
    let args = parse_args(env::args().skip(1))?;
    let body = Arc::new(vec![b'x'; args.body_bytes]);
    let trace = Arc::new(Mutex::new(TraceCounters::default()));

    let proxy_listener = TcpListener::bind(("127.0.0.1", 0))?;
    let proxy_addr = proxy_listener.local_addr()?;
    let admin_listener = TcpListener::bind(("127.0.0.1", 0))?;
    let admin_addr = admin_listener.local_addr()?;

    let origin_listener = if args.origin_tls {
        Some(TcpListener::bind(("127.0.0.1", 0))?)
    } else {
        None
    };
    let target_url = if let Some(listener) = origin_listener.as_ref() {
        format!("https://127.0.0.1:{}/bench", listener.local_addr()?.port())
    } else {
        "http://127.0.0.1:18080/bench".to_string()
    };

    let proxy_acceptor = Arc::new(build_acceptor(
        &args.proxy_cert,
        &args.proxy_key,
        args.client_ca.as_ref(),
    )?);
    spawn_proxy(
        proxy_listener,
        proxy_acceptor,
        Arc::clone(&body),
        Arc::clone(&trace),
    );

    if let Some(listener) = origin_listener {
        let origin_acceptor = Arc::new(build_acceptor(&args.origin_cert, &args.origin_key, None)?);
        spawn_origin(
            listener,
            origin_acceptor,
            Arc::clone(&body),
            Arc::clone(&trace),
        );
    }
    spawn_admin(admin_listener, Arc::clone(&trace));

    let mut stdout = io::stdout();
    writeln!(
        stdout,
        "{{\"type\":\"ready\",\"proxy_url\":\"https://127.0.0.1:{}\",\"target_url\":\"{}\",\"admin_addr\":\"{}\"}}",
        proxy_addr.port(),
        target_url,
        admin_addr,
    )?;
    stdout.flush()?;

    let _ = args.scenario;
    loop {
        thread::park();
    }
}

fn parse_args<I>(args: I) -> Result<Args, AnyError>
where
    I: IntoIterator<Item = String>,
{
    let mut scenario = None;
    let mut body_bytes = None;
    let mut proxy_cert = None;
    let mut proxy_key = None;
    let mut origin_cert = None;
    let mut origin_key = None;
    let mut client_ca = None;
    let mut origin_tls = false;

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--scenario" => scenario = Some(take_value(&mut iter, "--scenario")?),
            "--body-bytes" => {
                body_bytes = Some(take_value(&mut iter, "--body-bytes")?.parse::<usize>()?)
            }
            "--proxy-cert" => {
                proxy_cert = Some(PathBuf::from(take_value(&mut iter, arg.as_str())?))
            }
            "--proxy-key" => proxy_key = Some(PathBuf::from(take_value(&mut iter, arg.as_str())?)),
            "--origin-cert" => {
                origin_cert = Some(PathBuf::from(take_value(&mut iter, arg.as_str())?))
            }
            "--origin-key" => {
                origin_key = Some(PathBuf::from(take_value(&mut iter, arg.as_str())?))
            }
            "--client-ca" => client_ca = Some(PathBuf::from(take_value(&mut iter, arg.as_str())?)),
            "--origin-tls" => origin_tls = true,
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    Ok(Args {
        scenario: scenario.ok_or("--scenario is required")?,
        body_bytes: body_bytes.ok_or("--body-bytes is required")?,
        proxy_cert: proxy_cert.ok_or("--proxy-cert is required")?,
        proxy_key: proxy_key.ok_or("--proxy-key is required")?,
        origin_cert: origin_cert.ok_or("--origin-cert is required")?,
        origin_key: origin_key.ok_or("--origin-key is required")?,
        client_ca,
        origin_tls,
    })
}

fn take_value<I>(iter: &mut I, name: &str) -> Result<String, AnyError>
where
    I: Iterator<Item = String>,
{
    iter.next()
        .ok_or_else(|| format!("{name} requires a value").into())
}

fn build_acceptor(
    cert: &PathBuf,
    key: &PathBuf,
    client_ca: Option<&PathBuf>,
) -> Result<SslAcceptor, AnyError> {
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    builder.set_certificate_chain_file(cert)?;
    builder.set_private_key_file(key, SslFiletype::PEM)?;
    if let Some(ca) = client_ca {
        builder.set_ca_file(ca)?;
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    }
    Ok(builder.build())
}

fn configure_latency_sensitive_tcp(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)
}

fn spawn_proxy(
    listener: TcpListener,
    acceptor: Arc<SslAcceptor>,
    body: Arc<Vec<u8>>,
    trace: SharedTrace,
) {
    thread::spawn(move || loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = configure_latency_sensitive_tcp(&stream);
                let acceptor = Arc::clone(&acceptor);
                let body = Arc::clone(&body);
                let trace = Arc::clone(&trace);
                thread::spawn(move || handle_proxy_conn(stream, acceptor, body, trace));
            }
            Err(_) => return,
        }
    });
}

fn spawn_origin(
    listener: TcpListener,
    acceptor: Arc<SslAcceptor>,
    body: Arc<Vec<u8>>,
    trace: SharedTrace,
) {
    thread::spawn(move || loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = configure_latency_sensitive_tcp(&stream);
                let acceptor = Arc::clone(&acceptor);
                let body = Arc::clone(&body);
                let trace = Arc::clone(&trace);
                thread::spawn(move || handle_origin_conn(stream, acceptor, body, trace));
            }
            Err(_) => return,
        }
    });
}

fn spawn_admin(listener: TcpListener, trace: SharedTrace) {
    thread::spawn(move || loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut line = String::new();
                let _ = io::BufReader::new(&mut stream).read_line(&mut line);
                let snapshot = snapshot_and_reset(&trace);
                let _ = stream.write_all(snapshot.to_json().as_bytes());
                let _ = stream.shutdown(Shutdown::Both);
            }
            Err(_) => return,
        }
    });
}

fn snapshot_and_reset(trace: &SharedTrace) -> TraceCounters {
    match trace.lock() {
        Ok(mut trace) => std::mem::take(&mut *trace),
        Err(_) => TraceCounters::default(),
    }
}

fn handle_proxy_conn(
    raw: TcpStream,
    acceptor: Arc<SslAcceptor>,
    body: Arc<Vec<u8>>,
    trace: SharedTrace,
) {
    let mut conn = match acceptor.accept(raw) {
        Ok(conn) => conn,
        Err(_) => {
            update_trace(&trace, |trace| trace.proxy_tls_client_auth_failures += 1);
            return;
        }
    };
    update_trace(&trace, |trace| trace.proxy_connections += 1);
    let mut data = Vec::new();

    loop {
        let header_end = match read_headers(&mut conn, &mut data) {
            Ok(Some(header_end)) => header_end,
            Ok(None) | Err(_) => return,
        };
        let header = data[..header_end].to_vec();
        let mut remaining = data.split_off(header_end + 4);
        let content_length = content_length(&header);
        while remaining.len() < content_length {
            let mut chunk = [0; 65536];
            match conn.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => remaining.extend_from_slice(&chunk[..n]),
            }
        }
        data = remaining[content_length..].to_vec();
        let first_line = first_header_line(&header);
        update_trace(&trace, |trace| {
            trace.proxy_request_header_bytes += (header_end + 4) as u64;
            trace.proxy_request_body_bytes += content_length as u64;
        });

        if first_line.starts_with(b"CONNECT ") {
            update_trace(&trace, |trace| trace.proxy_connect_requests += 1);
            let (host, port) = match parse_connect_target(first_line) {
                Ok(target) => target,
                Err(_) => return,
            };
            let upstream = match TcpStream::connect((host.as_str(), port)) {
                Ok(upstream) => upstream,
                Err(_) => return,
            };
            let _ = configure_latency_sensitive_tcp(&upstream);
            if conn
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .is_err()
            {
                return;
            }
            if !data.is_empty() {
                let _ = (&upstream).write_all(&data);
                data.clear();
            }
            let _ = relay_tunnel(conn, upstream, trace);
            return;
        }

        update_trace(&trace, |trace| {
            trace.proxy_forward_requests += 1;
            trace.proxy_response_body_bytes += body.len() as u64;
        });
        let response = fixed_response(&body, false);
        if write_all_timed(&mut conn, &response, &trace, TimedWrite::ProxyResponse).is_err() {
            return;
        }
    }
}

fn handle_origin_conn(
    raw: TcpStream,
    acceptor: Arc<SslAcceptor>,
    body: Arc<Vec<u8>>,
    trace: SharedTrace,
) {
    let mut conn = match acceptor.accept(raw) {
        Ok(conn) => conn,
        Err(_) => return,
    };
    update_trace(&trace, |trace| {
        trace.origin_connections += 1;
        trace.origin_tls_connections += 1;
    });
    let mut data = Vec::new();
    loop {
        let header_end = match read_headers(&mut conn, &mut data) {
            Ok(Some(header_end)) => header_end,
            Ok(None) | Err(_) => return,
        };
        let header = data[..header_end].to_vec();
        let mut remaining = data.split_off(header_end + 4);
        let content_length = content_length(&header);
        while remaining.len() < content_length {
            let mut chunk = [0; 65536];
            match conn.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => remaining.extend_from_slice(&chunk[..n]),
            }
        }
        data = remaining[content_length..].to_vec();
        let should_close = header
            .windows(b"connection: close".len())
            .any(|window| window.eq_ignore_ascii_case(b"connection: close"));
        update_trace(&trace, |trace| {
            trace.origin_requests += 1;
            trace.origin_request_header_bytes += (header_end + 4) as u64;
            trace.origin_request_body_bytes += content_length as u64;
            trace.origin_response_body_bytes += body.len() as u64;
        });
        let response = fixed_response(&body, should_close);
        if write_all_timed(&mut conn, &response, &trace, TimedWrite::OriginResponse).is_err() {
            return;
        }
        if should_close {
            return;
        }
    }
}

fn read_headers<R: Read>(reader: &mut R, data: &mut Vec<u8>) -> io::Result<Option<usize>> {
    while find_header_end(data).is_none() {
        let mut chunk = [0; 65536];
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            return Ok(None);
        }
        data.extend_from_slice(&chunk[..n]);
        if data.len() > 256 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "header too large",
            ));
        }
    }
    Ok(find_header_end(data))
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

fn first_header_line(header: &[u8]) -> &[u8] {
    match header.windows(2).position(|window| window == b"\r\n") {
        Some(end) => &header[..end],
        None => header,
    }
}

fn content_length(header: &[u8]) -> usize {
    for line in header.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some((name, value)) = split_once(line, b':') {
            if name.trim_ascii().eq_ignore_ascii_case(b"content-length") {
                return std::str::from_utf8(value.trim_ascii())
                    .ok()
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
            }
        }
    }
    0
}

fn split_once(data: &[u8], needle: u8) -> Option<(&[u8], &[u8])> {
    let index = data.iter().position(|byte| *byte == needle)?;
    Some((&data[..index], &data[index + 1..]))
}

fn parse_connect_target(line: &[u8]) -> Result<(String, u16), AnyError> {
    let mut parts = line.split(|byte| byte.is_ascii_whitespace());
    let method = parts.next().ok_or("missing CONNECT method")?;
    if method != b"CONNECT" {
        return Err("not a CONNECT request".into());
    }
    let authority = parts.next().ok_or("missing CONNECT authority")?;
    let authority = std::str::from_utf8(authority)?;
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, rest) = rest.split_once(']').ok_or("missing IPv6 closing bracket")?;
        let port = rest.strip_prefix(':').ok_or("missing CONNECT port")?;
        return Ok((host.to_string(), port.parse()?));
    }
    let (host, port) = authority.rsplit_once(':').ok_or("missing CONNECT port")?;
    Ok((host.to_string(), port.parse()?))
}

fn fixed_response(body: &[u8], close: bool) -> Vec<u8> {
    let mut response = Vec::with_capacity(128 + body.len());
    response.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: ");
    response.extend_from_slice(body.len().to_string().as_bytes());
    response.extend_from_slice(if close {
        b"\r\nConnection: close\r\nContent-Type: application/octet-stream\r\n\r\n"
    } else {
        b"\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\n\r\n"
    });
    response.extend_from_slice(body);
    response
}

enum TimedWrite {
    ProxyResponse,
    OriginResponse,
}

fn write_all_timed<W: Write>(
    writer: &mut W,
    bytes: &[u8],
    trace: &SharedTrace,
    kind: TimedWrite,
) -> io::Result<()> {
    let start = Instant::now();
    writer.write_all(bytes)?;
    let elapsed = start.elapsed().as_micros() as u64;
    update_trace(trace, |trace| match kind {
        TimedWrite::ProxyResponse => {
            trace.proxy_response_send_us += elapsed;
            trace.proxy_response_send_events += 1;
        }
        TimedWrite::OriginResponse => {
            trace.origin_response_send_us += elapsed;
            trace.origin_response_send_events += 1;
        }
    });
    Ok(())
}

#[cfg(unix)]
fn relay_tunnel(
    mut client: SslStream<TcpStream>,
    mut upstream: TcpStream,
    trace: SharedTrace,
) -> io::Result<()> {
    client.get_ref().set_nonblocking(true)?;
    upstream.set_nonblocking(true)?;
    let client_fd = client.get_ref().as_raw_fd();
    let upstream_fd = upstream.as_raw_fd();
    let mut client_to_upstream = VecDeque::new();
    let mut upstream_to_client = VecDeque::new();
    let mut buf = [0; 65536];

    loop {
        let mut pollfds = [
            libc::pollfd {
                fd: client_fd,
                events: libc::POLLIN
                    | if upstream_to_client.is_empty() {
                        0
                    } else {
                        libc::POLLOUT
                    },
                revents: 0,
            },
            libc::pollfd {
                fd: upstream_fd,
                events: libc::POLLIN
                    | if client_to_upstream.is_empty() {
                        0
                    } else {
                        libc::POLLOUT
                    },
                revents: 0,
            },
        ];
        let ready = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as _, 5000) };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        update_trace(&trace, |trace| {
            trace.proxy_tunnel_poll_calls += 1;
            if ready == 0 {
                trace.proxy_tunnel_poll_timeouts += 1;
            }
        });
        if ready == 0 {
            continue;
        }

        if pollfds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Ok(());
        }
        if pollfds[1].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Ok(());
        }

        if pollfds[0].revents & libc::POLLIN != 0 {
            match client.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    client_to_upstream.extend(&buf[..n]);
                    let queue_len = client_to_upstream.len() as u64;
                    update_trace(&trace, |trace| {
                        trace.proxy_tunnel_bytes_from_client += n as u64;
                        trace.proxy_tunnel_client_to_origin_queue_bytes_max = trace
                            .proxy_tunnel_client_to_origin_queue_bytes_max
                            .max(queue_len);
                    });
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    update_trace(&trace, |trace| {
                        trace.proxy_tunnel_client_read_would_block += 1;
                    });
                }
                Err(_) => return Ok(()),
            }
        }
        if pollfds[1].revents & libc::POLLIN != 0 {
            match upstream.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    upstream_to_client.extend(&buf[..n]);
                    let queue_len = upstream_to_client.len() as u64;
                    update_trace(&trace, |trace| {
                        trace.proxy_tunnel_bytes_from_origin += n as u64;
                        trace.proxy_tunnel_origin_to_client_queue_bytes_max = trace
                            .proxy_tunnel_origin_to_client_queue_bytes_max
                            .max(queue_len);
                    });
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    update_trace(&trace, |trace| {
                        trace.proxy_tunnel_origin_read_would_block += 1;
                    });
                }
                Err(_) => return Ok(()),
            }
        }
        if pollfds[1].revents & libc::POLLOUT != 0 && !client_to_upstream.is_empty() {
            let start = Instant::now();
            match write_from_queue(&mut upstream, &mut client_to_upstream) {
                Ok(0) => {}
                Ok(_) => {
                    let elapsed = start.elapsed().as_micros() as u64;
                    update_trace(&trace, |trace| {
                        trace.proxy_tunnel_send_to_origin_us += elapsed;
                        trace.proxy_tunnel_send_to_origin_events += 1;
                    });
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    update_trace(&trace, |trace| {
                        trace.proxy_tunnel_send_to_origin_would_block += 1;
                    });
                }
                Err(_) => return Ok(()),
            }
        }
        if pollfds[0].revents & libc::POLLOUT != 0 && !upstream_to_client.is_empty() {
            let start = Instant::now();
            match write_from_queue(&mut client, &mut upstream_to_client) {
                Ok(0) => {}
                Ok(_) => {
                    let elapsed = start.elapsed().as_micros() as u64;
                    update_trace(&trace, |trace| {
                        trace.proxy_tunnel_send_to_client_us += elapsed;
                        trace.proxy_tunnel_send_to_client_events += 1;
                    });
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    update_trace(&trace, |trace| {
                        trace.proxy_tunnel_send_to_client_would_block += 1;
                    });
                }
                Err(_) => return Ok(()),
            }
        }
    }
}

#[cfg(not(unix))]
fn relay_tunnel(
    _client: SslStream<TcpStream>,
    _upstream: TcpStream,
    _trace: SharedTrace,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native CONNECT relay is only implemented for Unix benchmark hosts",
    ))
}

fn write_from_queue<W: Write>(writer: &mut W, queue: &mut VecDeque<u8>) -> io::Result<usize> {
    let (front, _) = queue.as_slices();
    if front.is_empty() {
        return Ok(0);
    }
    let written = writer.write(front)?;
    for _ in 0..written {
        queue.pop_front();
    }
    Ok(written)
}

fn update_trace(trace: &SharedTrace, update: impl FnOnce(&mut TraceCounters)) {
    if let Ok(mut trace) = trace.lock() {
        update(&mut trace);
    }
}

impl TraceCounters {
    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"proxy_connections\":{},",
                "\"proxy_forward_requests\":{},",
                "\"proxy_connect_requests\":{},",
                "\"proxy_tunnel_bytes_from_client\":{},",
                "\"proxy_tunnel_bytes_from_origin\":{},",
                "\"proxy_tls_client_auth_failures\":{},",
                "\"proxy_request_header_bytes\":{},",
                "\"proxy_request_body_bytes\":{},",
                "\"proxy_response_body_bytes\":{},",
                "\"proxy_response_send_us\":{},",
                "\"proxy_response_send_events\":{},",
                "\"proxy_tunnel_send_to_client_us\":{},",
                "\"proxy_tunnel_send_to_client_events\":{},",
                "\"proxy_tunnel_send_to_origin_us\":{},",
                "\"proxy_tunnel_send_to_origin_events\":{},",
                "\"proxy_tunnel_poll_calls\":{},",
                "\"proxy_tunnel_poll_timeouts\":{},",
                "\"proxy_tunnel_client_read_would_block\":{},",
                "\"proxy_tunnel_origin_read_would_block\":{},",
                "\"proxy_tunnel_send_to_client_would_block\":{},",
                "\"proxy_tunnel_send_to_origin_would_block\":{},",
                "\"proxy_tunnel_client_to_origin_queue_bytes_max\":{},",
                "\"proxy_tunnel_origin_to_client_queue_bytes_max\":{},",
                "\"origin_connections\":{},",
                "\"origin_requests\":{},",
                "\"origin_tls_connections\":{},",
                "\"origin_request_header_bytes\":{},",
                "\"origin_request_body_bytes\":{},",
                "\"origin_response_body_bytes\":{},",
                "\"origin_response_send_us\":{},",
                "\"origin_response_send_events\":{}",
                "}}\n"
            ),
            self.proxy_connections,
            self.proxy_forward_requests,
            self.proxy_connect_requests,
            self.proxy_tunnel_bytes_from_client,
            self.proxy_tunnel_bytes_from_origin,
            self.proxy_tls_client_auth_failures,
            self.proxy_request_header_bytes,
            self.proxy_request_body_bytes,
            self.proxy_response_body_bytes,
            self.proxy_response_send_us,
            self.proxy_response_send_events,
            self.proxy_tunnel_send_to_client_us,
            self.proxy_tunnel_send_to_client_events,
            self.proxy_tunnel_send_to_origin_us,
            self.proxy_tunnel_send_to_origin_events,
            self.proxy_tunnel_poll_calls,
            self.proxy_tunnel_poll_timeouts,
            self.proxy_tunnel_client_read_would_block,
            self.proxy_tunnel_origin_read_would_block,
            self.proxy_tunnel_send_to_client_would_block,
            self.proxy_tunnel_send_to_origin_would_block,
            self.proxy_tunnel_client_to_origin_queue_bytes_max,
            self.proxy_tunnel_origin_to_client_queue_bytes_max,
            self.origin_connections,
            self.origin_requests,
            self.origin_tls_connections,
            self.origin_request_header_bytes,
            self.origin_request_body_bytes,
            self.origin_response_body_bytes,
            self.origin_response_send_us,
            self.origin_response_send_events,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        configure_latency_sensitive_tcp, content_length, parse_connect_target, snapshot_and_reset,
        TraceCounters,
    };
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn parses_connect_authority() {
        assert_eq!(
            parse_connect_target(b"CONNECT 127.0.0.1:443 HTTP/1.1").unwrap(),
            ("127.0.0.1".to_string(), 443)
        );
        assert_eq!(
            parse_connect_target(b"CONNECT [::1]:8443 HTTP/1.1").unwrap(),
            ("::1".to_string(), 8443)
        );
    }

    #[test]
    fn parses_content_length_case_insensitively() {
        assert_eq!(content_length(b"GET / HTTP/1.1\r\nContent-Length: 17"), 17);
        assert_eq!(content_length(b"GET / HTTP/1.1\r\ncontent-length: 5"), 5);
    }

    #[test]
    fn trace_snapshot_is_json_object() {
        let mut trace = TraceCounters::default();
        trace.proxy_connections = 2;
        trace.origin_requests = 3;
        trace.proxy_tunnel_poll_calls = 7;
        trace.proxy_tunnel_send_to_client_would_block = 11;
        trace.proxy_tunnel_origin_to_client_queue_bytes_max = 4096;
        let json = trace.to_json();
        assert!(json.starts_with('{'));
        assert!(json.contains("\"proxy_connections\":2"));
        assert!(json.contains("\"origin_requests\":3"));
        assert!(json.contains("\"proxy_tunnel_poll_calls\":7"));
        assert!(json.contains("\"proxy_tunnel_send_to_client_would_block\":11"));
        assert!(json.contains("\"proxy_tunnel_origin_to_client_queue_bytes_max\":4096"));
        assert!(json.ends_with('\n'));
    }

    #[test]
    fn snapshot_resets_trace_window() {
        let trace = Arc::new(Mutex::new(TraceCounters {
            proxy_connections: 2,
            proxy_tunnel_origin_to_client_queue_bytes_max: 4096,
            ..TraceCounters::default()
        }));

        let first = snapshot_and_reset(&trace);
        let second = snapshot_and_reset(&trace);

        assert_eq!(first.proxy_connections, 2);
        assert_eq!(first.proxy_tunnel_origin_to_client_queue_bytes_max, 4096);
        assert_eq!(second.proxy_connections, 0);
        assert_eq!(second.proxy_tunnel_origin_to_client_queue_bytes_max, 0);
    }

    #[test]
    fn latency_sensitive_tcp_stream_enables_nodelay() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || listener.accept().unwrap().0);
        let client = TcpStream::connect(addr).unwrap();
        let server = handle.join().unwrap();

        configure_latency_sensitive_tcp(&client).unwrap();
        configure_latency_sensitive_tcp(&server).unwrap();

        assert!(client.nodelay().unwrap());
        assert!(server.nodelay().unwrap());
    }
}
