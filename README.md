# ming

A fast, async multi-ping network scanner with a live terminal UI.

```
ming 192.168.1.x tcp 80,443,8000-8080
```

---

## Features

- **Three scan modes** — ICMP ping, TCP connect, UDP probe
- **Flexible targets** — single IPs, CIDR ranges, wildcards, hostnames, domains, comma-separated lists
- **Flexible port specs** — individual ports, ranges, comma-separated lists, named ports, and group presets
- **Reverse DNS** — hostname lookup on responding IPs (on by default)
- **Live display** — results table builds in real time as hosts respond
- **Structured output** — `--output json` or `--output csv` for scripting
- **Watch mode** — re-scan on an interval, highlighting new hosts
- **Fast** — fully async with high concurrency; Ctrl+C exits immediately

---

## Installation

Requires Python 3.11+ and [uv](https://github.com/astral-sh/uv).

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
ming DESTINATION [METHOD] [PORT_SPEC] [OPTIONS]
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
| Comma-separated | `10.0.0.1,10.0.1.1` | Multiple targets |

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
| `top100` | — | Top 100 most common ports |
| `top1000` | — | Top 1000 most common ports (default) |
| Named port | `http`, `ssh`, `postgres` | Single named port |
| Group preset | `web`, `db`, `remote` | Multiple related ports |

**Named ports:** `http`, `https`, `http-alt`, `https-alt`, `ssh`, `telnet`, `rdp`, `vnc`, `ftp`, `ftps`, `tftp`, `rsync`, `nfs`, `smb`, `netbios`, `smtp`, `smtps`, `submission`, `pop3`, `pop3s`, `imap`, `imaps`, `dns`, `snmp`, `ntp`, `ldap`, `ldaps`, `kerberos`, `sip`, `rtsp`, `mysql`, `postgres`, `mssql`, `oracle`, `redis`, `mongodb`, `memcached`, `cassandra`, `elasticsearch`, `docker`, `kubernetes`, `kafka`, `rabbitmq`, `prometheus`, `grafana`, `kibana`, `jenkins`, and more.

**Group presets:**

| Group | Ports |
|---|---|
| `web` | 80, 443, 8080, 8443, 8000, 8888, 8008, 8081, 3000 |
| `db` | 3306, 5432, 1433, 6379, 27017, 5984, 9200, 9042, 11211, 1521 |
| `remote` | 22, 23, 3389, 5900, 5901 |
| `mail` | 25, 110, 143, 465, 587, 993, 995 |
| `file` | 20, 21, 69, 139, 445, 873, 990, 2049 |
| `devops` | 2375, 2376, 6443, 9200, 5601, 9090, 9092, 2181, 3000, 8086, 2379 |

### Options

| Option | Short | Description |
|---|---|---|
| `--resolve` / `--no-resolve` | `-r` / `-R` | Reverse DNS lookup on responding IPs (default: on) |
| `--quiet` | `-q` | No live display; print one line per responding host |
| `--output json\|csv` | `-o` | Structured output to stdout, disables live display |
| `--timeout SECS` | `-t` | Probe timeout in seconds (overrides per-protocol default) |
| `--concurrency N` | `-c` | Max concurrent probes (overrides per-protocol default) |
| `--watch` | `-w` | Re-scan repeatedly on `--interval` |
| `--interval SECS` | `-i` | Seconds between re-scans in watch mode (default: 30) |

---

## Examples

```sh
# ICMP ping a whole subnet
ming 192.168.1.x

# TCP scan a host on common ports
ming 192.168.1.1 tcp

# TCP scan specific ports
ming 192.168.1.1 tcp 22,80,443

# TCP scan web ports across a subnet
ming 10.0.0.x tcp web

# TCP scan a port range
ming 10.0.0.x tcp 8000-8999

# UDP scan top 100 ports
ming 192.168.1.1 udp top100

# Scan a hostname
ming localhost tcp ssh,http,https

# Scan a domain
ming google.com tcp 80,443

# Scan multiple targets
ming 10.0.0.1,10.0.1.1 tcp web

# Skip hostname resolution
ming 192.168.1.x --no-resolve

# Machine-readable output
ming 192.168.1.x tcp web --output json

# Watch mode — re-scan every 60 seconds
ming 192.168.1.x --watch --interval 60
```

---

## Output

Results are displayed as a live table that updates in real time. Only hosts that respond are shown. A summary line prints after the scan completes.

**ICMP mode**
```
 IP Address     Hostname         RTT (ms)
 192.168.1.1    router.local          0.8
 192.168.1.42   mypc.local            1.2
 192.168.1.101  nas.local             2.1

3/256 hosts responded (1%)  avg RTT 1.4ms — 3.2s
```

**TCP mode**
```
 IP Address     Hostname        Open Ports
 192.168.1.1    router.local    80, 443
 192.168.1.42   mypc.local      22, 3306, 8080

2 host(s) with open ports, 5 open port(s) total  256 hosts × 1000 ports — 8.1s
```

**UDP mode**
```
 IP Address     Hostname        Reachable   Responded Ports
 192.168.1.1    router.local    ✓           53, 161
 192.168.1.42   mypc.local      ✓

2 reachable host(s), 3 port(s) responded  256 hosts × 1000 ports — 12.4s
```

> **UDP reachability** (`✓`) means an ICMP port-unreachable response was received — the host is up,
> but the port is closed. **Responded ports** are ports that sent actual UDP data back.

---

## Notes

- ICMP mode uses unprivileged sockets via [icmplib](https://github.com/ValentinBELYN/icmplib) — no root required on Linux/macOS. On Windows, ICMP requires Administrator privileges.
- TCP mode performs a full connect scan — no raw sockets, no root required.
- UDP mode uses `connect()` + `send()` and detects reachability from ICMP port-unreachable responses — no root required.
- Default concurrency limits: ICMP 150 · TCP 500 · UDP 200 simultaneous probes.
- Ctrl+C stops the scan immediately and prints results found so far.
