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

use std::time::{Duration, Instant};

/// Time statistics of a request in each stage.
#[derive(Default, Clone)]
pub struct TimeGroup {
    // TODO add total request time.
    dns_start: Option<Instant>,
    dns_end: Option<Instant>,
    dns_duration: Option<Duration>,
    tcp_start: Option<Instant>,
    tcp_end: Option<Instant>,
    tcp_duration: Option<Duration>,
    #[cfg(feature = "http3")]
    quic_start: Option<Instant>,
    #[cfg(feature = "http3")]
    quic_end: Option<Instant>,
    #[cfg(feature = "http3")]
    quic_duration: Option<Duration>,
    #[cfg(feature = "__tls")]
    tls_start: Option<Instant>,
    #[cfg(feature = "__tls")]
    tls_end: Option<Instant>,
    #[cfg(feature = "__tls")]
    tls_duration: Option<Duration>,
    conn_start: Option<Instant>,
    conn_end: Option<Instant>,
    conn_duration: Option<Duration>,
    // start send bytes to peer.
    transfer_start: Option<Instant>,
    // received first byte from peer.
    transfer_end: Option<Instant>,
    transfer_duration: Option<Duration>,
    #[cfg(feature = "libcurl_bench")]
    request_format_duration: Option<Duration>,
    #[cfg(feature = "libcurl_bench")]
    pool_checkout_duration: Option<Duration>,
    #[cfg(feature = "libcurl_bench")]
    send_on_conn_duration: Option<Duration>,
    #[cfg(feature = "libcurl_bench")]
    http1_write_duration: Option<Duration>,
    #[cfg(feature = "libcurl_bench")]
    http1_encode_duration: Option<Duration>,
    #[cfg(feature = "libcurl_bench")]
    http1_write_io_duration: Option<Duration>,
    #[cfg(feature = "libcurl_bench")]
    response_head_duration: Option<Duration>,
    #[cfg(feature = "libcurl_bench")]
    response_read_duration: Option<Duration>,
    #[cfg(feature = "libcurl_bench")]
    response_read_poll_count: u64,
    #[cfg(feature = "libcurl_bench")]
    response_read_pending_count: u64,
    #[cfg(feature = "libcurl_bench")]
    response_pre_read_bytes: u64,
    #[cfg(feature = "libcurl_bench")]
    response_pre_read_events: u64,
    #[cfg(feature = "libcurl_bench")]
    response_intercept_duration: Option<Duration>,
    #[cfg(feature = "libcurl_bench")]
    response_decode_duration: Option<Duration>,
}

impl TimeGroup {
    #[cfg(feature = "libcurl_bench")]
    pub(crate) fn bench_phase_enabled() -> bool {
        use std::sync::OnceLock;

        static ENABLED: OnceLock<bool> = OnceLock::new();
        *ENABLED.get_or_init(|| std::env::var("YLONG_BENCH_PHASES").ok().as_deref() == Some("1"))
    }

    #[cfg(not(feature = "libcurl_bench"))]
    pub(crate) fn bench_phase_enabled() -> bool {
        false
    }

    pub(crate) fn set_dns_start(&mut self, start: Instant) {
        self.dns_start = Some(start)
    }

    pub(crate) fn set_dns_end(&mut self, end: Instant) {
        if let Some(start) = self.dns_start {
            self.dns_duration = end.checked_duration_since(start);
        }
        self.dns_end = Some(end)
    }

    pub(crate) fn set_tcp_start(&mut self, start: Instant) {
        self.tcp_start = Some(start)
    }

    pub(crate) fn set_tcp_end(&mut self, end: Instant) {
        if let Some(start) = self.tcp_start {
            self.tcp_duration = end.checked_duration_since(start);
        }
        self.tcp_end = Some(end)
    }

    #[cfg(feature = "http3")]
    pub(crate) fn set_quic_start(&mut self, start: Instant) {
        self.quic_start = Some(start)
    }

    #[cfg(feature = "http3")]
    pub(crate) fn set_quic_end(&mut self, end: Instant) {
        if let Some(start) = self.quic_start {
            self.quic_duration = end.checked_duration_since(start);
        }
        self.quic_end = Some(end)
    }

    #[cfg(feature = "__tls")]
    pub(crate) fn set_tls_start(&mut self, start: Instant) {
        self.tls_start = Some(start)
    }

    #[cfg(feature = "__tls")]
    pub(crate) fn set_tls_end(&mut self, end: Instant) {
        if let Some(start) = self.tls_start {
            self.tls_duration = end.checked_duration_since(start)
        }
        self.tls_end = Some(end)
    }

    pub(crate) fn set_transfer_start(&mut self, start: Instant) {
        self.transfer_start = Some(start)
    }

    pub(crate) fn set_transfer_end(&mut self, end: Instant) {
        if let Some(start) = self.transfer_start {
            self.transfer_duration = end.checked_duration_since(start)
        }
        self.transfer_end = Some(end)
    }

    pub(crate) fn set_connect_start(&mut self, start: Instant) {
        self.conn_start = Some(start)
    }

    pub(crate) fn set_connect_end(&mut self, end: Instant) {
        if let Some(start) = self.conn_start {
            self.conn_duration = end.checked_duration_since(start)
        }
        self.conn_end = Some(end)
    }

    pub(crate) fn add_request_format_duration(&mut self, duration: Duration) {
        #[cfg(not(feature = "libcurl_bench"))]
        let _ = duration;
        #[cfg(feature = "libcurl_bench")]
        {
            self.request_format_duration = add_duration(self.request_format_duration, duration);
        }
    }

    pub(crate) fn add_pool_checkout_duration(&mut self, duration: Duration) {
        #[cfg(not(feature = "libcurl_bench"))]
        let _ = duration;
        #[cfg(feature = "libcurl_bench")]
        {
            self.pool_checkout_duration = add_duration(self.pool_checkout_duration, duration);
        }
    }

    pub(crate) fn add_send_on_conn_duration(&mut self, duration: Duration) {
        #[cfg(not(feature = "libcurl_bench"))]
        let _ = duration;
        #[cfg(feature = "libcurl_bench")]
        {
            self.send_on_conn_duration = add_duration(self.send_on_conn_duration, duration);
        }
    }

    pub(crate) fn add_http1_write_duration(&mut self, duration: Duration) {
        #[cfg(not(feature = "libcurl_bench"))]
        let _ = duration;
        #[cfg(feature = "libcurl_bench")]
        {
            self.http1_write_duration = add_duration(self.http1_write_duration, duration);
        }
    }

    pub(crate) fn add_http1_encode_duration(&mut self, duration: Duration) {
        #[cfg(not(feature = "libcurl_bench"))]
        let _ = duration;
        #[cfg(feature = "libcurl_bench")]
        {
            self.http1_encode_duration = add_duration(self.http1_encode_duration, duration);
        }
    }

    pub(crate) fn add_http1_write_io_duration(&mut self, duration: Duration) {
        #[cfg(not(feature = "libcurl_bench"))]
        let _ = duration;
        #[cfg(feature = "libcurl_bench")]
        {
            self.http1_write_io_duration = add_duration(self.http1_write_io_duration, duration);
        }
    }

    pub(crate) fn add_response_head_duration(&mut self, duration: Duration) {
        #[cfg(not(feature = "libcurl_bench"))]
        let _ = duration;
        #[cfg(feature = "libcurl_bench")]
        {
            self.response_head_duration = add_duration(self.response_head_duration, duration);
        }
    }

    pub(crate) fn add_response_read_duration(&mut self, duration: Duration) {
        #[cfg(not(feature = "libcurl_bench"))]
        let _ = duration;
        #[cfg(feature = "libcurl_bench")]
        {
            self.response_read_duration = add_duration(self.response_read_duration, duration);
        }
    }

    pub(crate) fn add_response_read_poll_counts(&mut self, polls: u64, pending: u64) {
        #[cfg(not(feature = "libcurl_bench"))]
        let _ = (polls, pending);
        #[cfg(feature = "libcurl_bench")]
        {
            self.response_read_poll_count = self.response_read_poll_count.saturating_add(polls);
            self.response_read_pending_count =
                self.response_read_pending_count.saturating_add(pending);
        }
    }

    pub(crate) fn add_response_pre_read(&mut self, bytes: usize) {
        #[cfg(not(feature = "libcurl_bench"))]
        let _ = bytes;
        #[cfg(feature = "libcurl_bench")]
        {
            if bytes == 0 {
                return;
            }
            self.response_pre_read_bytes =
                self.response_pre_read_bytes.saturating_add(bytes as u64);
            self.response_pre_read_events = self.response_pre_read_events.saturating_add(1);
        }
    }

    pub(crate) fn add_response_intercept_duration(&mut self, duration: Duration) {
        #[cfg(not(feature = "libcurl_bench"))]
        let _ = duration;
        #[cfg(feature = "libcurl_bench")]
        {
            self.response_intercept_duration =
                add_duration(self.response_intercept_duration, duration);
        }
    }

    pub(crate) fn add_response_decode_duration(&mut self, duration: Duration) {
        #[cfg(not(feature = "libcurl_bench"))]
        let _ = duration;
        #[cfg(feature = "libcurl_bench")]
        {
            self.response_decode_duration = add_duration(self.response_decode_duration, duration);
        }
    }

    #[cfg(feature = "http3")]
    pub(crate) fn update_quic_start(&mut self, start: Option<Instant>) {
        self.quic_start = start
    }

    #[cfg(feature = "http3")]
    pub(crate) fn update_quic_end(&mut self, end: Option<Instant>) {
        self.quic_end = end
    }

    #[cfg(feature = "http3")]
    pub(crate) fn update_quic_duration(&mut self, duration: Option<Duration>) {
        self.quic_duration = duration
    }

    pub(crate) fn update_tcp_start(&mut self, start: Option<Instant>) {
        self.tcp_start = start
    }

    pub(crate) fn update_tcp_end(&mut self, end: Option<Instant>) {
        self.tcp_end = end
    }

    pub(crate) fn update_tcp_duration(&mut self, duration: Option<Duration>) {
        self.tcp_duration = duration
    }

    #[cfg(feature = "__tls")]
    pub(crate) fn update_tls_start(&mut self, start: Option<Instant>) {
        self.tls_start = start
    }

    #[cfg(feature = "__tls")]
    pub(crate) fn update_tls_end(&mut self, end: Option<Instant>) {
        self.tls_end = end
    }

    #[cfg(feature = "__tls")]
    pub(crate) fn update_tls_duration(&mut self, duration: Option<Duration>) {
        self.tls_duration = duration
    }

    pub(crate) fn update_dns_start(&mut self, start: Option<Instant>) {
        self.dns_start = start
    }

    pub(crate) fn update_dns_end(&mut self, end: Option<Instant>) {
        self.dns_end = end
    }

    pub(crate) fn update_dns_duration(&mut self, duration: Option<Duration>) {
        self.dns_duration = duration
    }

    pub(crate) fn update_connection_start(&mut self, start: Option<Instant>) {
        self.conn_start = start
    }

    pub(crate) fn update_connection_end(&mut self, end: Option<Instant>) {
        self.conn_end = end
    }

    pub(crate) fn update_connection_duration(&mut self, duration: Option<Duration>) {
        self.conn_duration = duration
    }

    pub(crate) fn update_transport_conn_time(&mut self, time_group: &TimeGroup) {
        self.update_dns_start(time_group.dns_start_time());
        self.update_dns_end(time_group.dns_end_time());
        self.update_dns_duration(time_group.dns_duration());

        self.update_tcp_start(time_group.tcp_start_time());
        self.update_tcp_end(time_group.tcp_end_time());
        self.update_tcp_duration(time_group.tcp_duration());

        #[cfg(feature = "http3")]
        self.update_quic_start(time_group.quic_start_time());
        #[cfg(feature = "http3")]
        self.update_quic_end(time_group.quic_end_time());
        #[cfg(feature = "http3")]
        self.update_quic_duration(time_group.quic_duration());

        self.update_tcp_start(time_group.tcp_start_time());
        self.update_tcp_end(time_group.tcp_end_time());
        self.update_tcp_duration(time_group.tcp_duration());

        #[cfg(feature = "__tls")]
        self.update_tls_start(time_group.tls_start_time());
        #[cfg(feature = "__tls")]
        self.update_tls_end(time_group.tls_end_time());
        #[cfg(feature = "__tls")]
        self.update_tls_duration(time_group.tls_duration());

        self.update_connection_start(time_group.connect_start_time());
        self.update_connection_end(time_group.connect_end_time());
        self.update_connection_duration(time_group.connect_duration());
    }

    /// Gets the  point in time when the tcp connection starts to be
    /// established.
    pub fn tcp_start_time(&self) -> Option<Instant> {
        self.tcp_start
    }

    /// Gets the  point in time when the tcp connection was established.
    pub fn tcp_end_time(&self) -> Option<Instant> {
        self.tcp_end
    }

    /// Gets the total time taken to establish a tcp connection.
    pub fn tcp_duration(&self) -> Option<Duration> {
        self.tcp_duration
    }

    /// Gets the  point in time when the quic connection starts to be
    /// established.
    #[cfg(feature = "http3")]
    pub fn quic_start_time(&self) -> Option<Instant> {
        self.quic_start
    }

    /// Gets the  point in time when the quic connection was established.
    #[cfg(feature = "http3")]
    pub fn quic_end_time(&self) -> Option<Instant> {
        self.quic_end
    }

    /// Gets the total time taken to establish a quic connection.
    #[cfg(feature = "http3")]
    pub fn quic_duration(&self) -> Option<Duration> {
        self.quic_duration
    }

    /// Gets the start  point in time of the tls handshake.
    #[cfg(feature = "__tls")]
    pub fn tls_start_time(&self) -> Option<Instant> {
        self.tls_start
    }

    /// Gets the  point in time when the tls connection was established.
    #[cfg(feature = "__tls")]
    pub fn tls_end_time(&self) -> Option<Instant> {
        self.tls_end
    }

    /// Gets the time taken for the tls connection to be established.
    #[cfg(feature = "__tls")]
    pub fn tls_duration(&self) -> Option<Duration> {
        self.tls_duration
    }

    /// Gets the point in time when the dns query started (not currently
    /// recorded).
    pub fn dns_start_time(&self) -> Option<Instant> {
        self.dns_start
    }

    /// Gets the point in time when the dns query ended (not currently
    /// recorded).
    pub fn dns_end_time(&self) -> Option<Instant> {
        self.dns_end
    }

    /// Gets the time spent on dns queries (not currently recorded).
    pub fn dns_duration(&self) -> Option<Duration> {
        self.dns_duration
    }

    /// Gets the start point in time of data transmission.
    pub fn transfer_start_time(&self) -> Option<Instant> {
        self.transfer_start
    }

    /// Gets the point in time the data was received.
    pub fn transfer_end_time(&self) -> Option<Instant> {
        self.transfer_end
    }

    /// Gets the time it takes from the time the data is sent to the time it is
    /// received.
    pub fn transfer_duration(&self) -> Option<Duration> {
        self.transfer_duration
    }

    /// Gets the point in time to start establishing the request connection.
    pub fn connect_start_time(&self) -> Option<Instant> {
        self.conn_start
    }

    /// Gets the point in time when the request connection was established.
    pub fn connect_end_time(&self) -> Option<Instant> {
        self.conn_end
    }

    /// Gets the time it took to establish the requested connection.
    pub fn connect_duration(&self) -> Option<Duration> {
        self.conn_duration
    }

    pub fn request_format_duration(&self) -> Option<Duration> {
        #[cfg(feature = "libcurl_bench")]
        {
            return self.request_format_duration;
        }
        #[cfg(not(feature = "libcurl_bench"))]
        {
            None
        }
    }

    pub fn pool_checkout_duration(&self) -> Option<Duration> {
        #[cfg(feature = "libcurl_bench")]
        {
            return self.pool_checkout_duration;
        }
        #[cfg(not(feature = "libcurl_bench"))]
        {
            None
        }
    }

    pub fn send_on_conn_duration(&self) -> Option<Duration> {
        #[cfg(feature = "libcurl_bench")]
        {
            return self.send_on_conn_duration;
        }
        #[cfg(not(feature = "libcurl_bench"))]
        {
            None
        }
    }

    pub fn http1_write_duration(&self) -> Option<Duration> {
        #[cfg(feature = "libcurl_bench")]
        {
            return self.http1_write_duration;
        }
        #[cfg(not(feature = "libcurl_bench"))]
        {
            None
        }
    }

    pub fn http1_encode_duration(&self) -> Option<Duration> {
        #[cfg(feature = "libcurl_bench")]
        {
            return self.http1_encode_duration;
        }
        #[cfg(not(feature = "libcurl_bench"))]
        {
            None
        }
    }

    pub fn http1_write_io_duration(&self) -> Option<Duration> {
        #[cfg(feature = "libcurl_bench")]
        {
            return self.http1_write_io_duration;
        }
        #[cfg(not(feature = "libcurl_bench"))]
        {
            None
        }
    }

    pub fn response_head_duration(&self) -> Option<Duration> {
        #[cfg(feature = "libcurl_bench")]
        {
            return self.response_head_duration;
        }
        #[cfg(not(feature = "libcurl_bench"))]
        {
            None
        }
    }

    pub fn response_read_duration(&self) -> Option<Duration> {
        #[cfg(feature = "libcurl_bench")]
        {
            return self.response_read_duration;
        }
        #[cfg(not(feature = "libcurl_bench"))]
        {
            None
        }
    }

    pub fn response_read_poll_count(&self) -> u64 {
        #[cfg(feature = "libcurl_bench")]
        {
            return self.response_read_poll_count;
        }
        #[cfg(not(feature = "libcurl_bench"))]
        {
            0
        }
    }

    pub fn response_read_pending_count(&self) -> u64 {
        #[cfg(feature = "libcurl_bench")]
        {
            return self.response_read_pending_count;
        }
        #[cfg(not(feature = "libcurl_bench"))]
        {
            0
        }
    }

    pub fn response_pre_read_bytes(&self) -> u64 {
        #[cfg(feature = "libcurl_bench")]
        {
            return self.response_pre_read_bytes;
        }
        #[cfg(not(feature = "libcurl_bench"))]
        {
            0
        }
    }

    pub fn response_pre_read_events(&self) -> u64 {
        #[cfg(feature = "libcurl_bench")]
        {
            return self.response_pre_read_events;
        }
        #[cfg(not(feature = "libcurl_bench"))]
        {
            0
        }
    }

    pub fn response_intercept_duration(&self) -> Option<Duration> {
        #[cfg(feature = "libcurl_bench")]
        {
            return self.response_intercept_duration;
        }
        #[cfg(not(feature = "libcurl_bench"))]
        {
            None
        }
    }

    pub fn response_decode_duration(&self) -> Option<Duration> {
        #[cfg(feature = "libcurl_bench")]
        {
            return self.response_decode_duration;
        }
        #[cfg(not(feature = "libcurl_bench"))]
        {
            None
        }
    }
}

#[cfg(feature = "libcurl_bench")]
fn add_duration(current: Option<Duration>, duration: Duration) -> Option<Duration> {
    Some(current.unwrap_or(Duration::ZERO).saturating_add(duration))
}

#[cfg(all(test, feature = "libcurl_bench"))]
mod tests {
    use super::TimeGroup;

    #[test]
    fn ut_response_read_poll_counts_accumulate() {
        let mut group = TimeGroup::default();

        group.add_response_read_poll_counts(2, 1);
        group.add_response_read_poll_counts(3, 2);

        assert_eq!(group.response_read_poll_count(), 5);
        assert_eq!(group.response_read_pending_count(), 3);
    }

    #[test]
    fn ut_response_pre_read_bytes_accumulate() {
        let mut group = TimeGroup::default();

        group.add_response_pre_read(0);
        group.add_response_pre_read(17);
        group.add_response_pre_read(23);

        assert_eq!(group.response_pre_read_bytes(), 40);
        assert_eq!(group.response_pre_read_events(), 2);
    }
}
