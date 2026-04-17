//
// Copyright (c) 2026 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// Suppress the warnings
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(clippy::all)]
#![allow(unnecessary_transmutes)]

// Utilize the platform-specific bindings
#[cfg(not(target_os = "windows"))]
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/bindings.rs"));
#[cfg(target_os = "windows")]
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/bindings_windows.rs"));
