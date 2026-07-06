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

//! A FFI crate for FFRT runtime.

mod config;
mod sys_event;
mod task;

pub use config::*;
use libc::{c_int, c_void};
pub use sys_event::*;
pub use task::*;
pub use {ffrt_get_current_task, ffrt_submit_coroutine};

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
/// Qos levels.
pub enum Qos {
    /// Inherits parent's qos level
    Inherent = -1,
    /// Lowest qos
    Background,
    /// Utility qos
    Utility,
    /// Default qos
    Default,
    /// User initialiated qos
    UserInitiated,
    /// Deadline qos
    DeadlineRequest,
    /// Highest qos
    UserInteractive,
}

#[repr(C)]
/// Dependencies for the task.
pub struct FfrtDeps {
    len: u32,
    items: *const *const c_void,
}

#[repr(C)]
#[derive(Clone)]
/// Task attributes.
pub struct FfrtTaskAttr {
    storage: [u8; 128],
}

/// Result returned by the ffrt task.
pub type FfrtResult<T> = Result<T, c_int>;
