/// True when stdout is an interactive terminal.
pub fn is_tty_stdio() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
}

pub fn is_headless_env() -> bool {
    if std::env::var("TERMUX_VERSION").is_ok() {
        return true;
    }
    if std::env::var("PREFIX")
        .map(|p| p.contains("com.termux"))
        .unwrap_or(false)
    {
        return true;
    }
    if std::env::var("CI").is_ok() || std::env::var("SSH_CONNECTION").is_ok() {
        return true;
    }
    #[cfg(unix)]
    {
        if std::env::var("DISPLAY").is_err() && std::env::var("WAYLAND_DISPLAY").is_err() {
            return true;
        }
    }
    false
}

pub fn is_loopback_host(host: &str) -> bool {
    let h = host.trim().to_ascii_lowercase();
    h == "127.0.0.1"
        || h == "localhost"
        || h == "::1"
        || h == "[::1]"
        || h.starts_with("127.")
}

pub fn remote_bind_requires_token(host: &str) -> bool {
    !is_loopback_host(host)
}

pub fn warn_remote_bind(host: &str) {
    if remote_bind_requires_token(host) {
        eprintln!(
            "WARNING: binding to {host} requires bearer token (META_SERVE_TOKEN or --token)."
        );
    }
}
