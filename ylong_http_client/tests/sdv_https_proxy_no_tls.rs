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

#![cfg(all(feature = "http1_1", not(feature = "__tls")))]

#[cfg(all(feature = "async", feature = "tokio_base"))]
mod async_no_tls {
    use ylong_http_client::async_impl::{Body, ClientBuilder, Request};
    use ylong_http_client::Proxy;

    #[tokio::test(flavor = "current_thread")]
    async fn sdv_async_https_proxy_requires_tls_feature() {
        let proxy = Proxy::all("https://127.0.0.1:9")
            .build()
            .expect("proxy config build failed");
        let client = ClientBuilder::new()
            .proxy(proxy)
            .build()
            .expect("client build failed");
        let request = Request::builder()
            .url("http://example.com/no-tls-async")
            .body(Body::empty())
            .expect("request build failed");

        let err = match client.request(request).await {
            Ok(_) => panic!("HTTPS proxy without TLS feature unexpectedly succeeded"),
            Err(err) => err,
        };

        assert!(
            format!("{err:?}").contains("HTTPS proxy requires TLS feature"),
            "unexpected error: {err:?}"
        );
    }
}

#[cfg(feature = "sync")]
mod sync_no_tls {
    use ylong_http_client::sync_impl::{ClientBuilder, EmptyBody, Request};
    use ylong_http_client::{HttpClientError, Proxy};

    #[test]
    fn sdv_sync_https_proxy_requires_tls_feature() {
        let proxy = Proxy::all("https://127.0.0.1:9")
            .build()
            .expect("proxy config build failed");
        let client = ClientBuilder::new()
            .proxy(proxy)
            .build()
            .expect("client build failed");
        let request = Request::get("http://example.com/no-tls-sync")
            .body(EmptyBody)
            .map_err(HttpClientError::other)
            .expect("request build failed");

        let err = match client.request(request) {
            Ok(_) => panic!("HTTPS proxy without TLS feature unexpectedly succeeded"),
            Err(err) => err,
        };

        assert!(
            format!("{err:?}").contains("HTTPS proxy requires TLS feature"),
            "unexpected error: {err:?}"
        );
    }
}
