# ming

A fast, async multi-ping network scanner with a live terminal UI.

```
ming 192.168.1.x tcp 80,443,8000-8080
```

---

## Features

- **Three scan modes** — ICMP ping, TCP connect, UDP probe
- **Flexible targets** — single IPs, CIDR ranges, wildcards, hostnames, and domains
- **Flexible port specs** — individual ports, ranges, comma-separated lists, or named presets
- **Live display** — results table builds in real time as hosts respond
- **Fast** — fully async with high concurrency (up to 500 simultaneous TCP connections)

---

## Installation

Requires Python 3.14+ and [uv](https://github.com/astral-sh/uv).

```sh
git clone https://github.com/yourname/ming
cd ming
uv pip install -e .
```

Then run with:

```sh
ming <destination> [method] [ports]
```

---

## Usage

```
ming DESTINATION [METHOD] [PORT_SPEC]
```

### Destinations

| Format | Example | Description |
|---|---|---|
| Single IP | `192.168.1.1` | One host |
| CIDR range | `192.168.1.0/24` | 256 hosts |
| Wildcard | `192.168.1.x` | Same as `/24` |
| Wider wildcard | `192.168.x.x` | `/16` — 65,536 hosts |
| Hostname | `localhost` | Resolved via DNS |
| Domain | `google.com` | Resolved via DNS |

Wildcard octets can be written as `x`, `xx`, or `xxx` — they all mean the same thing.

### Methods

| Method | Alias | Description |
|---|---|---|
| `icmp` | `ping` | ICMP echo request (default) |
| `tcp` | `syn` | TCP connect scan |
| `udp` | — | UDP probe |

### Port specs *(TCP and UDP only)*

| Spec | Example | Description |
|---|---|---|
| Single port | `80` | One port |
| Range | `8000-8080` | Inclusive range |
| List | `80,443,8000-8080` | Mix of ports and ranges |
| `top100` | `common100` | Top 100 most common ports |
| `top1000` | `common`, `common1000` | Top 1000 most common ports (default) |

If no port spec is given for TCP/UDP, the top 1000 most common ports are scanned.

---

## Examples

```sh
# ICMP ping a single host
ming 192.168.1.1

# ICMP ping a whole subnet
ming 192.168.1.x

# TCP scan a host on common ports
ming 192.168.1.1 tcp

# TCP scan specific ports
ming 192.168.1.1 tcp 22,80,443

# TCP scan a port range across a subnet
ming 10.0.0.x tcp 8000-8999

# UDP scan top 100 ports
ming 192.168.1.1 udp top100

# Scan a hostname
ming localhost tcp 80,443

# Scan a domain
ming google.com tcp 80,443
```

---

## Output

Results are displayed as a live table that updates in real time. Only hosts that respond are shown.

**ICMP mode**
```
 IP Address        RTT (ms)
 192.168.1.1            0.8
 192.168.1.42           1.2
 192.168.1.101          2.1
```

**TCP mode**
```
 IP Address        Open Ports
 192.168.1.1       22, 80, 443
 192.168.1.42      22, 3306, 8080
```

**UDP mode**
```
 IP Address        Reachable   Responded Ports
 192.168.1.1       ✓           53, 161
 192.168.1.42      ✓
```

> **UDP reachability** (`✓`) means an ICMP port-unreachable response was received — the host is up,
> but the port is closed. **Responded ports** are ports that sent actual UDP data back.

---

## Notes

- ICMP mode uses unprivileged sockets via [icmplib](https://github.com/ValentinBELYN/icmplib) — no root required on Linux/macOS. On Windows, ICMP requires Administrator privileges.
- TCP mode performs a full connect scan — no raw sockets, no root required.
- UDP mode uses `connect()` + `send()` and detects reachability from ICMP port-unreachable responses — no root required.
- Concurrency limits: ICMP 150 · TCP 500 · UDP 200 simultaneous probes.
