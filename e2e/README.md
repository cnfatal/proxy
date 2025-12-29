# E2E Testing Framework

End-to-end tests for the transparent proxy using Linux network namespace isolation.

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Host Network                                   │
│  ┌──────────────────┐                          │
│  │ veth-host        │◄────── 10.200.1.1/24     │
│  └────────┬─────────┘                          │
│           │ veth pair                          │
│  ┌────────┴────────────────────────────────────┤
│  │ Network Namespace: tproxy_e2e               │
│  │                                             │
│  │  ┌──────────────────┐                       │
│  │  │ veth-ns          │◄──── 10.200.1.2/24    │
│  │  └──────────────────┘                       │
│  │                                             │
│  │  ┌──────────────────┐                       │
│  │  │ tproxy process   │◄──── :12345           │
│  │  │ + nftables rules │                       │
│  │  └──────────────────┘                       │
│  │                                             │
│  │  ✓ Isolated routing table                   │
│  │  ✓ Isolated nftables rules                  │
│  │  ✓ No impact on host network                │
│  └─────────────────────────────────────────────┘
└─────────────────────────────────────────────────┘
```

## Requirements

- Linux
- Root privileges
- Binary built: `make build`

## Running Tests

```bash
# Run E2E tests
make test-e2e

# Or manually
sudo go test -v -tags=e2e ./e2e/...
```

## Test Cases

| Test                          | Description                               |
| ----------------------------- | ----------------------------------------- |
| `TestNetworkNamespaceSetup`   | Verifies namespace and veth pair creation |
| `TestProxyStartupInNamespace` | Checks proxy starts in isolated namespace |
| `TestDirectConnection`        | Tests DIRECT policy routing               |
| `TestBypassMark`              | Validates SO_MARK prevents traffic loop   |
| `TestCleanupAfterExit`        | Confirms nftables cleanup on exit         |
| `TestNamespaceIsolation`      | Verifies rules only exist in namespace    |
| `TestUpstreamProxy`           | Tests tproxy with mock upstream HTTP proxy |
| `TestUpstreamProxyConnection` | Validates mock proxy connection handling  |

## Cleanup

If tests fail and leave resources behind:

```bash
sudo ip netns del tproxy_e2e
sudo ip link del veth-host
sudo nft delete table inet transparent_proxy
```
