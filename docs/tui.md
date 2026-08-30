# TUI (terminal)

MetaDissect 0.11+ and Meta* consumer CLIs use the shared `meta-ui` ratatui layer.

## Analyze TUI

Runs automatically when stdout is a TTY and you did not pass `--no-tui` or a structured `-f json|csv|markdown`.

| Key | Action |
|-----|--------|
| `j` / `Down` | Next field |
| `k` / `Up` | Previous field |
| `/` | Filter fields |
| `c` | Copy selected field |
| `?` | Toggle help |
| `q` / `Esc` | Quit |

## Serve dashboard

`metadissect serve --api` (and consumer `serve` commands) show a live stats dashboard on TTY: RPS, latency percentiles, sparkline, last route/status. Press `q` to stop the server.

## MetaFake mutation confirm

`strip` / `set` with TUI enabled show a confirmation dialog before writing the `-o` copy. Declining cancels without overwrite.

## Headless / CI

Set `NO_COLOR=1` or use `--no-tui` / non-TTY stdout. Banners are skipped in CI.
