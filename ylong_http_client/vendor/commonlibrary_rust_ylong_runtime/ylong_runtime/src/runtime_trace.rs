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

#[cfg(feature = "runtime_trace")]
use std::cell::Cell;
#[cfg(feature = "runtime_trace")]
use std::fs::{File, OpenOptions};
#[cfg(feature = "runtime_trace")]
use std::io::Write;
#[cfg(feature = "runtime_trace")]
use std::sync::{Mutex, OnceLock};
#[cfg(feature = "runtime_trace")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "runtime_trace")]
const TRACE_FILE_ENV: &str = "YLONG_RUNTIME_TRACE_FILE";

#[cfg(feature = "runtime_trace")]
thread_local! {
    static WAKE_ORIGIN: Cell<Option<&'static str>> = Cell::new(None);
}

#[cfg_attr(not(feature = "runtime_trace"), allow(dead_code))]
pub(crate) struct Event<'a> {
    pub(crate) name: &'a str,
    pub(crate) task_id: Option<usize>,
    pub(crate) worker_id: Option<usize>,
    pub(crate) target_worker_id: Option<usize>,
    pub(crate) wake_origin: Option<&'a str>,
    pub(crate) ready: Option<&'a str>,
    pub(crate) shutdown: Option<bool>,
    pub(crate) lifo: Option<bool>,
}

#[cfg(feature = "runtime_trace")]
pub(crate) fn record_lazy<'a, F>(make_event: F)
where
    F: FnOnce() -> Event<'a>,
{
    let Some(file) = trace_file() else {
        return;
    };

    record_to(Some(file), make_event(), |event| {
        format_event(
            now_ns(),
            &format!("{:?}", std::thread::current().id()),
            event,
        )
    });
}

#[cfg(not(feature = "runtime_trace"))]
#[inline(always)]
pub(crate) fn record_lazy<'a, F>(_make_event: F)
where
    F: FnOnce() -> Event<'a>,
{
}

#[cfg(feature = "runtime_trace")]
pub(crate) fn with_wake_origin<F>(origin: &'static str, f: F)
where
    F: FnOnce(),
{
    let previous = WAKE_ORIGIN.with(|cell| {
        let previous = cell.get();
        cell.set(Some(origin));
        previous
    });
    f();
    WAKE_ORIGIN.with(|cell| cell.set(previous));
}

#[cfg(not(feature = "runtime_trace"))]
#[inline(always)]
pub(crate) fn with_wake_origin<F>(_origin: &'static str, f: F)
where
    F: FnOnce(),
{
    f();
}

#[cfg(feature = "runtime_trace")]
pub(crate) fn current_wake_origin() -> Option<&'static str> {
    WAKE_ORIGIN.with(Cell::get)
}

#[cfg(not(feature = "runtime_trace"))]
#[inline(always)]
pub(crate) fn current_wake_origin() -> Option<&'static str> {
    None
}

#[cfg(feature = "runtime_trace")]
pub(crate) fn current_worker_id() -> Option<usize> {
    #[cfg(not(feature = "ffrt"))]
    {
        return crate::executor::worker::get_current_ctx().map(|ctx| ctx.worker.index);
    }

    #[cfg(feature = "ffrt")]
    {
        None
    }
}

#[cfg(not(feature = "runtime_trace"))]
#[inline(always)]
pub(crate) fn current_worker_id() -> Option<usize> {
    None
}

#[inline(always)]
pub(crate) fn task_id<T>(ptr: *const T) -> usize {
    ptr as usize
}

#[cfg(all(test, feature = "runtime_trace"))]
pub(crate) fn format_event_for_test(ts_ns: u128, thread: &str, event: Event<'_>) -> String {
    format_event(ts_ns, thread, event)
}

#[cfg(feature = "runtime_trace")]
fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

#[cfg(feature = "runtime_trace")]
fn trace_file() -> Option<&'static Mutex<File>> {
    static TRACE_FILE: OnceLock<Option<Mutex<File>>> = OnceLock::new();

    TRACE_FILE
        .get_or_init(|| {
            let path = std::env::var(TRACE_FILE_ENV).ok()?;
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .ok()?;
            Some(Mutex::new(file))
        })
        .as_ref()
}

#[cfg(feature = "runtime_trace")]
fn record_to<W, F>(file: Option<&Mutex<W>>, event: Event<'_>, formatter: F)
where
    W: Write,
    F: FnOnce(Event<'_>) -> String,
{
    let Some(file) = file else {
        return;
    };

    let line = formatter(event);
    if let Ok(mut file) = file.lock() {
        let _ = writeln!(file, "{line}");
    }
}

#[cfg(feature = "runtime_trace")]
fn format_event(ts_ns: u128, thread: &str, event: Event<'_>) -> String {
    let mut line = String::with_capacity(192);
    line.push('{');
    push_u128(&mut line, "ts_ns", ts_ns, true);
    push_str(&mut line, "event", event.name, false);
    push_str(&mut line, "thread", thread, false);
    if let Some(worker_id) = event.worker_id {
        push_usize(&mut line, "worker_id", worker_id, false);
    }
    if let Some(target_worker_id) = event.target_worker_id {
        push_usize(&mut line, "target_worker_id", target_worker_id, false);
    }
    if let Some(task_id) = event.task_id {
        push_usize(&mut line, "task_id", task_id, false);
    }
    if let Some(wake_origin) = event.wake_origin {
        push_str(&mut line, "wake_origin", wake_origin, false);
    }
    if let Some(ready) = event.ready {
        push_str(&mut line, "ready", ready, false);
    }
    if let Some(shutdown) = event.shutdown {
        push_bool(&mut line, "shutdown", shutdown, false);
    }
    if let Some(lifo) = event.lifo {
        push_bool(&mut line, "lifo", lifo, false);
    }
    line.push('}');
    line
}

#[cfg(feature = "runtime_trace")]
fn push_key(line: &mut String, key: &str, first: bool) {
    if !first {
        line.push(',');
    }
    line.push('"');
    line.push_str(key);
    line.push_str("\":");
}

#[cfg(feature = "runtime_trace")]
fn push_str(line: &mut String, key: &str, value: &str, first: bool) {
    push_key(line, key, first);
    line.push('"');
    push_escaped(line, value);
    line.push('"');
}

#[cfg(feature = "runtime_trace")]
fn push_usize(line: &mut String, key: &str, value: usize, first: bool) {
    push_key(line, key, first);
    line.push_str(&value.to_string());
}

#[cfg(feature = "runtime_trace")]
fn push_u128(line: &mut String, key: &str, value: u128, first: bool) {
    push_key(line, key, first);
    line.push_str(&value.to_string());
}

#[cfg(feature = "runtime_trace")]
fn push_bool(line: &mut String, key: &str, value: bool, first: bool) {
    push_key(line, key, first);
    line.push_str(if value { "true" } else { "false" });
}

#[cfg(feature = "runtime_trace")]
fn push_escaped(line: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '"' => line.push_str("\\\""),
            '\\' => line.push_str("\\\\"),
            '\n' => line.push_str("\\n"),
            '\r' => line.push_str("\\r"),
            '\t' => line.push_str("\\t"),
            ch if ch.is_control() => {
                line.push_str("\\u");
                line.push_str(&format!("{:04x}", ch as u32));
            }
            ch => line.push(ch),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    #[cfg(feature = "runtime_trace")]
    use std::sync::Mutex;

    use super::*;

    #[cfg(feature = "runtime_trace")]
    #[test]
    fn disabled_trace_does_not_format_event() {
        let formatted = Cell::new(false);
        let file: Option<&Mutex<Vec<u8>>> = None;
        let event = Event {
            name: "task_wake_by_ref",
            task_id: Some(0x1234),
            worker_id: Some(1),
            target_worker_id: Some(1),
            wake_origin: Some("io_readiness"),
            ready: Some("READABLE"),
            shutdown: None,
            lifo: Some(false),
        };

        record_to(file, event, |_| {
            formatted.set(true);
            String::new()
        });

        assert!(!formatted.get());
    }

    #[test]
    fn disabled_trace_does_not_build_lazy_event() {
        let built = Cell::new(false);

        record_lazy(|| {
            built.set(true);
            Event {
                name: "task_wake_by_ref",
                task_id: Some(0x1234),
                worker_id: Some(1),
                target_worker_id: Some(1),
                wake_origin: Some("io_readiness"),
                ready: Some("READABLE"),
                shutdown: None,
                lifo: Some(false),
            }
        });

        assert!(!built.get());
    }
}
