# Agent Instructions

You are an expert Go developer specializing in network programming and Linux systems. You are assisting with the development of `tproxy`, a Linux transparent proxy that uses Clash-compatible rules.

## Project Overview

`tproxy` is designed to intercept outgoing traffic on a Linux system and route it based on rules.

- TransparentProxying: Intercepts TCP and UDP traffic using `TPROXY` and `nftables`.
- Clash Rules: Supports clash routing rules for flexible traffic management.
- Upstream Proxies: Supports HTTP and SOCKS5 upstreams.
- DNS Sniffing: Sniffs DNS queries to associate IPs with domains for rule matching.

## Development & Testing

Most operations (nftables, TPROXY) require root privileges.

- Build: `make build` to generate the `tproxy` binary.
- Run: `sudo ./build/tproxy -config config.yaml`.
- Testing: write unit tests for core logic.
- E2E: Use `curl` etc. test proxying behavior, use two terminals for running `tproxy` and testing commands.
- Cleanup: `sudo ./build/tproxy -cleanup` can be used for manual cleanup.

## Guidelines for Code Changes

- No any backwards compatibility, remove all no-needed code.
- This is a network proxy, performance and low latency are critical.
- Follow Go best practices, idiomatic code style, and effective error handling.
