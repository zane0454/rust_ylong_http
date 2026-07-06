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

#[cfg(feature = "__tls")]
mod c_ssl_stream;
mod wrapper;

#[cfg(feature = "__tls")]
pub use c_ssl_stream::AsyncSslStream;
pub(crate) use wrapper::{check_io_to_poll, Wrapper};

#[cfg(feature = "bench_tls_io")]
pub(crate) mod bench_tls_stats {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    static SSL_READ_CALLS: AtomicU64 = AtomicU64::new(0);
    static SSL_READ_PENDING: AtomicU64 = AtomicU64::new(0);
    static SSL_WRITE_CALLS: AtomicU64 = AtomicU64::new(0);
    static SSL_WRITE_PENDING: AtomicU64 = AtomicU64::new(0);
    static UNDERLYING_READ_CALLS: AtomicU64 = AtomicU64::new(0);
    static UNDERLYING_READ_PENDING: AtomicU64 = AtomicU64::new(0);
    static UNDERLYING_WRITE_CALLS: AtomicU64 = AtomicU64::new(0);
    static UNDERLYING_WRITE_PENDING: AtomicU64 = AtomicU64::new(0);
    static ENABLED: AtomicBool = AtomicBool::new(false);

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct BenchTlsStats {
        pub ssl_read_calls: u64,
        pub ssl_read_pending: u64,
        pub ssl_write_calls: u64,
        pub ssl_write_pending: u64,
        pub underlying_read_calls: u64,
        pub underlying_read_pending: u64,
        pub underlying_write_calls: u64,
        pub underlying_write_pending: u64,
    }

    impl BenchTlsStats {
        pub fn saturating_sub(self, earlier: Self) -> Self {
            Self {
                ssl_read_calls: self.ssl_read_calls.saturating_sub(earlier.ssl_read_calls),
                ssl_read_pending: self
                    .ssl_read_pending
                    .saturating_sub(earlier.ssl_read_pending),
                ssl_write_calls: self.ssl_write_calls.saturating_sub(earlier.ssl_write_calls),
                ssl_write_pending: self
                    .ssl_write_pending
                    .saturating_sub(earlier.ssl_write_pending),
                underlying_read_calls: self
                    .underlying_read_calls
                    .saturating_sub(earlier.underlying_read_calls),
                underlying_read_pending: self
                    .underlying_read_pending
                    .saturating_sub(earlier.underlying_read_pending),
                underlying_write_calls: self
                    .underlying_write_calls
                    .saturating_sub(earlier.underlying_write_calls),
                underlying_write_pending: self
                    .underlying_write_pending
                    .saturating_sub(earlier.underlying_write_pending),
            }
        }
    }

    pub fn snapshot() -> BenchTlsStats {
        BenchTlsStats {
            ssl_read_calls: SSL_READ_CALLS.load(Ordering::Relaxed),
            ssl_read_pending: SSL_READ_PENDING.load(Ordering::Relaxed),
            ssl_write_calls: SSL_WRITE_CALLS.load(Ordering::Relaxed),
            ssl_write_pending: SSL_WRITE_PENDING.load(Ordering::Relaxed),
            underlying_read_calls: UNDERLYING_READ_CALLS.load(Ordering::Relaxed),
            underlying_read_pending: UNDERLYING_READ_PENDING.load(Ordering::Relaxed),
            underlying_write_calls: UNDERLYING_WRITE_CALLS.load(Ordering::Relaxed),
            underlying_write_pending: UNDERLYING_WRITE_PENDING.load(Ordering::Relaxed),
        }
    }

    pub fn set_enabled(enabled: bool) {
        ENABLED.store(enabled, Ordering::Relaxed);
    }

    fn enabled() -> bool {
        ENABLED.load(Ordering::Relaxed)
    }

    pub(crate) fn record_ssl_read_call() {
        if enabled() {
            SSL_READ_CALLS.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_ssl_read_pending() {
        if enabled() {
            SSL_READ_PENDING.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_ssl_write_call() {
        if enabled() {
            SSL_WRITE_CALLS.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_ssl_write_pending() {
        if enabled() {
            SSL_WRITE_PENDING.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_underlying_read_call() {
        if enabled() {
            UNDERLYING_READ_CALLS.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_underlying_read_pending() {
        if enabled() {
            UNDERLYING_READ_PENDING.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_underlying_write_call() {
        if enabled() {
            UNDERLYING_WRITE_CALLS.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_underlying_write_pending() {
        if enabled() {
            UNDERLYING_WRITE_PENDING.fetch_add(1, Ordering::Relaxed);
        }
    }
}
