# Serve (HTTP)

## MetaDissect JSON API

```bash
metadissect serve --api                      # 127.0.0.1:8787
metadissect serve --api --host 0.0.0.0 --token "$META_SERVE_TOKEN"
metadissect serve --api --retain-dir ./tmp --retain-ttl 3600
```

Environment: `META_SERVE_TOKEN` (same as `--token`).

## Auth (remote bind)

Loopback (`127.0.0.1`, `localhost`, `::1`) skips auth. Any other `--host` requires a non-empty token:

- Header: `Authorization: Bearer YOUR_TOKEN`
- Query: `?token=YOUR_TOKEN` (useful for browser smoke tests; prefer Bearer in production)

## Retention

`--retain-dir` stores uploaded files temporarily; `GET /api/retained` lists them. TTL via `--retain-ttl` (seconds).

## TLS

Not implemented in 0.11.0. Use a reverse proxy (nginx, Caddy) for HTTPS until native rustls support lands.

## Consumer UIs

MetaInstructor (:5173), MetaTrace (:5174), and MetaFake (:5175) use the same token rules via `meta-ui`.
