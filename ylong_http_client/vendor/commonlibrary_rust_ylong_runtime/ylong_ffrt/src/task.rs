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

use std::ffi::{CStr, CString};

use libc::{c_char, c_void};

use super::*;

type FfrtHook = extern "C" fn(*mut c_void);

type FfrtExecHook = extern "C" fn(*mut c_void) -> FfrtRet;

type RawTaskCtx = *mut c_void;

/// Return value.
#[repr(C)]
pub enum FfrtRet {
    /// Asynchronous task result pending.
    FfrtCoroutinePending,
    /// Asynchronous task result is ready.
    FfrtCoroutineReady,
}

impl Default for FfrtTaskAttr {
    fn default() -> Self {
        Self::new()
    }
}

impl FfrtTaskAttr {
    /// Creates a default task attribute.
    pub fn new() -> Self {
        Self { storage: [0; 128] }
    }

    /// Initializes the task attribute
    pub fn init(&mut self) {
        let attr = self as *mut FfrtTaskAttr;
        unsafe {
            ffrt_task_attr_init(attr);
        }
    }

    /// Sets the name for the task attribute.
    pub fn set_name(&mut self, name: &str) -> &mut Self {
        let attr_ptr = self as *mut FfrtTaskAttr;
        let c_name = CString::new(name).expect("FfrtTaskAttr::set_name failed");
        unsafe {
            ffrt_task_attr_set_name(attr_ptr, c_name.as_ptr());
        }
        self
    }

    /// Gets the name from the task attribtue.
    pub fn get_name(&self) -> String {
        let attr_ptr = self as *const FfrtTaskAttr;
        unsafe {
            let c_name = ffrt_task_attr_get_name(attr_ptr);
            CStr::from_ptr(c_name)
                .to_str()
                .expect("FfrtTaskAttr::get_name failed")
                .to_string()
        }
    }

    /// Sets qos level for the task attribute.
    pub fn set_qos(&mut self, qos: Qos) -> &mut Self {
        unsafe {
            let ptr = self as *mut FfrtTaskAttr;
            ffrt_task_attr_set_qos(ptr, qos);
        }
        self
    }

    /// Gets the qos level from the task attribute.
    pub fn get_qos(&self) -> Qos {
        unsafe { ffrt_task_attr_get_qos(self as _) }
    }
}

impl Drop for FfrtTaskAttr {
    fn drop(&mut self) {
        unsafe {
            ffrt_task_attr_destroy(self as _);
        }
    }
}

#[link(name = "ffrt")]
// task.h
extern "C" {
    #![allow(unused)]

    fn ffrt_task_attr_init(attr: *mut FfrtTaskAttr);
    fn ffrt_task_attr_set_name(attr: *mut FfrtTaskAttr, name: *const c_char);
    fn ffrt_task_attr_get_name(attr: *const FfrtTaskAttr) -> *const c_char;
    fn ffrt_task_attr_destroy(attr: *mut FfrtTaskAttr);
    fn ffrt_task_attr_set_qos(attr: *mut FfrtTaskAttr, qos: Qos);
    fn ffrt_task_attr_get_qos(attr: *const FfrtTaskAttr) -> Qos;

    // submit
    fn ffrt_alloc_auto_free_function_storage_base() -> *const c_void;

    /// Submits a task.
    pub fn ffrt_submit_coroutine(
        // void* callable
        data: *mut c_void,
        // ffrt_function_tdd exec
        fp: FfrtExecHook,
        // ffrt_function_t destroy
        destroy_fp: FfrtHook,
        // const ffrt_deps_t* out_deps,
        in_deps: *const FfrtDeps,
        // const ffrt_deps_t* out_deps,
        out_deps: *const FfrtDeps,
        // const ffrt_task_attr_t* att
        attr: *const FfrtTaskAttr,
    );

    /// Gets the current task context.
    pub fn ffrt_get_current_task() -> RawTaskCtx;

    /// Wakes the task
    pub fn ffrt_wake_coroutine(task: RawTaskCtx);
}
