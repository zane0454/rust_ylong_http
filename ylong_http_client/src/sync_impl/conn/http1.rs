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

use ylong_http::body::sync_impl::Body;
use ylong_http::h1::{RequestRefEncoder, ResponseDecoder};
use ylong_http::request::uri::Scheme;
use ylong_http::request::Request;
use ylong_http::response::Response;

use crate::error::{ErrorKind, HttpClientError};
use crate::sync_impl::conn::StreamData;
use crate::sync_impl::HttpBody;
use crate::util::dispatcher::http1::Http1Conn;

const TEMP_BUF_SIZE: usize = 16 * 1024;

fn request_part_encoder<T>(request: &Request<T>) -> RequestRefEncoder<'_> {
    RequestRefEncoder::new(request.part())
}

pub(crate) fn request<S, T>(
    mut conn: Http1Conn<S>,
    request: &mut Request<T>,
    is_proxy: bool,
) -> Result<Response<HttpBody>, HttpClientError>
where
    T: Body,
    S: Read + Write + 'static,
{
    let mut buf = vec![0u8; TEMP_BUF_SIZE];

    let mut write = 0;

    // Encodes request line and headers before borrowing the request body.
    {
        let mut part_encoder = request_part_encoder(request);
        if is_proxy && request.uri().scheme() == Some(&Scheme::HTTP) {
            part_encoder.absolute_uri(true);
        }

        loop {
            if write == buf.len() {
                conn.raw_mut()
                    .write_all(&buf[..write])
                    .map_err(|e| HttpClientError::from_error(ErrorKind::Request, e))?;
                write = 0;
            }

            let size = part_encoder
                .encode(&mut buf[write..])
                .map_err(|e| HttpClientError::from_error(ErrorKind::Request, e))?;
            write += size;
            if size == 0 {
                break;
            }
        }
    }

    let mut encode_body = Some(request.body_mut());
    while encode_body.is_some() {
        if write < buf.len() {
            if let Some(body) = encode_body.as_mut() {
                let size = body
                    .data(&mut buf[write..])
                    .map_err(|e| HttpClientError::from_error(ErrorKind::BodyTransfer, e))?;
                write += size;
                if size == 0 {
                    encode_body = None;
                }
            }
        }

        if write == buf.len() {
            conn.raw_mut()
                .write_all(&buf[..write])
                .map_err(|e| HttpClientError::from_error(ErrorKind::Request, e))?;
            write = 0;
        }
    }

    if write != 0 {
        conn.raw_mut()
            .write_all(&buf[..write])
            .map_err(|e| HttpClientError::from_error(ErrorKind::Request, e))?;
    }

    // Decodes response part.
    let (part, pre) = {
        let mut decoder = ResponseDecoder::new();
        loop {
            let size = conn
                .raw_mut()
                .read(buf.as_mut_slice())
                .map_err(|e| HttpClientError::from_error(ErrorKind::Request, e))?;
            match decoder.decode(&buf[..size]) {
                Ok(None) => {}
                Ok(Some((part, rem))) => break (part, rem),
                Err(e) => return err_from_other!(Request, e),
            }
        }
    };

    // Generates response body.
    let body = {
        let chunked = part
            .headers
            .get("Transfer-Encoding")
            .map(|v| v.to_string().unwrap_or(String::new()))
            .and_then(|s| s.find("chunked"))
            .is_some();
        let content_length = part
            .headers
            .get("Content-Length")
            .map(|v| v.to_string().unwrap_or(String::new()))
            .and_then(|s| s.parse::<u64>().ok());

        let is_trailer = part.headers.get("Trailer").is_some();

        match (chunked, content_length, pre.is_empty()) {
            (true, None, _) => HttpBody::chunk(pre, Box::new(conn), is_trailer),
            (false, Some(len), _) => HttpBody::text(len, pre, Box::new(conn)),
            (false, None, true) => HttpBody::empty(),
            _ => {
                return err_from_msg!(Request, "Invalid response format");
            }
        }
    };
    Ok(Response::from_raw_parts(part, body))
}

impl<S: Read> Read for Http1Conn<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.raw_mut().read(buf)
    }
}

impl<S: Read> StreamData for Http1Conn<S> {
    fn shutdown(&self) {
        Self::shutdown(self)
    }
}

#[cfg(test)]
mod ut_sync_http1 {
    use ylong_http::body::EmptyBody;
    use ylong_http::request::Request;

    use super::request_part_encoder;

    #[test]
    fn ut_request_part_encoder_borrows_request_part() {
        let request = Request::get("http://example.com/").body(EmptyBody).unwrap();
        let _encoder = request_part_encoder(&request);
        assert_eq!(request.uri().to_string(), "http://example.com/");
    }
}
