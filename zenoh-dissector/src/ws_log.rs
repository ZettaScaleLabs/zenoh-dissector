//! Wireshark-native logging.
//!
//! See [ws_log_defs.h] for a description of [`epan_sys::ws_log_level`].
//!
//! [ws_log_defs.h]:
//!     <https://github.com/wireshark/wireshark/blob/efbbb5b7f84f62fc4c45bb4c9169e6fefc360e26/include/ws_log_defs.h#L55-L70>

#![allow(unused_macros)]

/// Emits a log message with "error" severity. This macro always results in program termination with a coredump.
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::ws_log::__private::with_level(
            epan_sys::ws_log_level_LOG_LEVEL_ERROR,
            format!($($arg)*)
        )
    }
}

/// Emits a "critical" level message. Used for serious issues that do not terminate the program.
macro_rules! critical {
    ($($arg:tt)*) => {
        $crate::ws_log::__private::with_level(
            epan_sys::ws_log_level_LOG_LEVEL_CRITICAL,
            format!($($arg)*)
        )
    }
}
pub(crate) use critical;

/// Emits a log message with "warning" severity. Used to report recoverable issues or unexpected conditions.
macro_rules! warning {
    ($($arg:tt)*) => {
        $crate::ws_log::__private::with_level(
            epan_sys::ws_log_level_LOG_LEVEL_WARNING,
            format!($($arg)*)
        )
    }
}

/// Emits a log message with "message" severity, the default log level.
macro_rules! message {
    ($($arg:tt)*) => {
        $crate::ws_log::__private::with_level(
            epan_sys::ws_log_level_LOG_LEVEL_MESSAGE,
            format!($($arg)*)
        )
    }
}
pub(crate) use message;

/// Emits a log message with "info" severity, typically used for general informational output.
macro_rules! info {
    ($($arg:tt)*) => {
        $crate::ws_log::__private::with_level(
            epan_sys::ws_log_level_LOG_LEVEL_INFO,
            format!($($arg)*)
        )
    }
}

/// Emits a log message with "debug" severity.
macro_rules! debug {
    ($($arg:tt)*) => {
        $crate::ws_log::__private::with_level(
            epan_sys::ws_log_level_LOG_LEVEL_DEBUG,
            format!($($arg)*)
        )
    }
}

/// Emits a log message with "noisy" severity, typically used for verbose or low-level diagnostic output.
macro_rules! noisy {
    ($($arg:tt)*) => {
        $crate::ws_log::__private::with_level(
            epan_sys::ws_log_level_LOG_LEVEL_NOISY,
            format!($($arg)*)
        )
    }
}

pub(crate) mod __private {
    use std::{ffi::CString, panic::Location, ptr};

    #[track_caller]
    pub(crate) fn with_level(level: epan_sys::ws_log_level, s: String) {
        unsafe {
            let c_str = CString::new(s).unwrap();
            epan_sys::ws_log_full(
                c"Zenoh".as_ptr(),
                level,
                Location::caller().file_as_c_str().as_ptr(),
                Location::caller().line() as _,
                ptr::null(),
                c"%s".as_ptr(),
                c_str.as_ptr(),
            )
        };
    }
}
