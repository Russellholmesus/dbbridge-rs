**English** | [简体中文](README.zh-CN.md)

# DBBridge (Rust)

DBBridge (protocol 1.5) is a peer-to-peer proxy that carries raw
database TCP connections (MySQL, MariaDB, SQL Server) over WebSocket or HTTP POST + SSE, across
network boundaries that only allow HTTP(S).

## Features

| Area | Status |
|---|---|
| Forward mode | ingress (local TCP listeners) and egress (HTTP server + database dial); carriers `ws`, `http-sse`, `auto` |
| Session recovery | resume, epoch/generation fencing, recovery buffers, path failover including ws ↔ http-sse switch |
| Reverse mode | database side dials out and holds the tunnel; smux v2 multiplexing; tunnel carriers `ws`, `http-sse`, long-poll, `auto` |
| TLS / HTTP/2 | on by default (Cargo features `tls`, `h2`; rustls + hyper); ALPN h2 |
| Config / CLI | strict YAML schema with derived defaults and warnings; commands `run`, `check-config`, `gen-config`, `version` |
| Operations | `/healthz`, `/readyz`, `/metrics`; credential reload; systemd unit / install |

`cargo build --no-default-features` gives a build with no third-party crates at all (no TLS / HTTP/2).
MSRV is Rust 1.75.

## Build

```bash
cargo build --release                         # TLS + HTTP/2
cargo build --release --no-default-features   # zero-dependency build
bash scripts/build-release.sh                 # static musl release archives (x86_64, aarch64) + SHA256SUMS
```

## Quick start

```bash
./target/release/dbbridge gen-config -o ./pair
./target/release/dbbridge check-config -c ./pair/peer-a.yaml
./target/release/dbbridge run -c ./pair/peer-b.yaml &    # egress (database side)
./target/release/dbbridge run -c ./pair/peer-a.yaml &    # ingress (client side)
mysql -h 127.0.0.1 -P 13306 -u app -p
```

Sample configurations are in `testdata/configs/`; `testdata/examples.md` walks through common
deployments.

## Repository layout

```
src/        implementation (wire, session, transport, ingress, egress, mux, tunnel, net, config, cli, ...)
tests/      integration tests (optional real MySQL/MariaDB: set DBB_MYSQL_DSN / DBB_MARIADB_DSN)
scripts/    verify.sh, ci.sh, build-release.sh, config-check.py
testdata/   sample configs, examples, and the recorded check-config corpus
e2e/        end-to-end harness (Python): forward and reverse mode against a loopback echo backend
```

## Testing

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings
cargo test                         # default features
cargo test --no-default-features
bash scripts/verify.sh             # full local gate: builds, config-check, e2e
python3 e2e/e2e.py                 # forward mode, 3 carriers
python3 e2e/reverse_e2e.py         # reverse mode
```

## License

Apache-2.0
