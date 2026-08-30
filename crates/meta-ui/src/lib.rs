//! Shared UI assets and serve helpers for the Meta* family (no Axum in this crate).

mod assets;
mod banner;
mod net;
mod retain;
mod stats;

#[cfg(feature = "tui")]
pub mod tui;

pub use assets::{shell_css, shell_js, shell_css_mime, shell_js_mime};
pub use banner::{maybe_print_banner, Product};
pub use net::{
    is_headless_env, is_loopback_host, is_tty_stdio, remote_bind_requires_token, warn_remote_bind,
};
pub use retain::{RetainConfig, RetainStore, RetainedEntry};
pub use stats::{
    check_bearer_token, check_serve_token, query_token_param, ServeSnapshot, ServeStats, StatsLayer,
};
