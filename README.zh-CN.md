[English](README.md) | **简体中文**

# DBBridge（Rust）

DBBridge（协议 1.5）是点对点数据库代理，把 MySQL、MariaDB、SQL Server 的原始 TCP
连接承载在 WebSocket 或 HTTP POST + SSE 上，穿过只放行 HTTP(S) 的网络边界。

## 功能

| 范围 | 状态 |
|---|---|
| 正向模式 | ingress（本地 TCP 监听）与 egress（HTTP 服务 + 数据库拨号）；载体 `ws`、`http-sse`、`auto` |
| 会话恢复 | resume、epoch/generation 隔离、恢复缓冲、路径故障切换（含 ws ↔ http-sse 切换） |
| 反向模式 | 数据库侧主动建隧道；smux v2 多路复用；隧道载体 `ws`、`http-sse`、long-poll、`auto` |
| TLS / HTTP/2 | 默认启用（Cargo 特性 `tls`、`h2`，基于 rustls + hyper）；ALPN 协商 h2 |
| 配置 / CLI | 严格的 YAML 校验、派生默认值与 warning；命令 `run`、`check-config`、`gen-config`、`version` |
| 运维 | `/healthz`、`/readyz`、`/metrics`；凭据热加载；systemd unit / install |

`cargo build --no-default-features` 构建完全不依赖第三方 crate 的版本（不含 TLS / HTTP/2）。MSRV 为 Rust 1.75。

## 构建

```bash
cargo build --release                         # TLS + HTTP/2
cargo build --release --no-default-features   # 零依赖版本
bash scripts/build-release.sh                 # 静态 musl 发布包（x86_64、aarch64）+ SHA256SUMS
```

## 快速开始

```bash
./target/release/dbbridge gen-config -o ./pair
./target/release/dbbridge check-config -c ./pair/peer-a.yaml
./target/release/dbbridge run -c ./pair/peer-b.yaml &    # egress（数据库侧）
./target/release/dbbridge run -c ./pair/peer-a.yaml &    # ingress（客户端侧）
mysql -h 127.0.0.1 -P 13306 -u app -p
```

示例配置位于 `testdata/configs/`，常见部署方式见 `testdata/examples.md`。

## 目录结构

```
src/        实现（wire、session、transport、ingress、egress、mux、tunnel、net、config、cli 等）
tests/      集成测试（可选真实 MySQL/MariaDB：设置 DBB_MYSQL_DSN / DBB_MARIADB_DSN）
scripts/    verify.sh、ci.sh、build-release.sh、config-check.py
testdata/   示例配置、部署示例与 check-config 记录语料
e2e/        端到端测试脚本（Python）：正向与反向模式，对接本地 echo 后端
```

## 测试

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings
cargo test                         # 默认特性
cargo test --no-default-features
bash scripts/verify.sh             # 完整本地门禁：构建、config-check、e2e
python3 e2e/e2e.py                 # 正向模式，3 种载体
python3 e2e/reverse_e2e.py         # 反向模式
```

## 许可证

Apache-2.0
