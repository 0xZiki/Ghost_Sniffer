# 👻 GhostSniffer v2.0

**Advanced Network Reconnaissance Tool** — Zero Dependencies | Raw Sockets | Stealth Operations

```
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
  ██║  ███╗███████║██║   ██║███████╗   ██║
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
  ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗
  ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
  ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
  ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
  ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
  ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
```

---

## 🎯 Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | **Passive Host Discovery** | A silent spy — discovers hosts from passing traffic without sending anything |
| 2 | **Protocol Mimicry** | Wraps packets to look like legitimate DNS Queries to bypass DPI |
| 3 | **Dynamic Jitter** | Random timing between each packet to break IDS pattern detection |
| 4 | **Decoy Traffic** | IP Spoofing with fake addresses to distract the Blue Team |

---

## 📋 Requirements

- **Python 3.6+**
- **Administrator / root privileges** (required for Raw Sockets)
- **Zero external dependencies** — everything is Standard Library

---
## 🛡️ OPSEC & Configuration (The .env File)

To maintain strict Operational Security (OPSEC) and avoid leaking sensitive stealth configurations (like your custom decoy IPs or mimicry domains) to GitHub or Blue Teams, GhostSniffer utilizes environment variables.

### Setup Instructions:
1. Do **NOT** modify the core script to hardcode your secrets.
2. Copy the provided example file to create your local secret configuration:
   ```bash
   # On Linux/Mac
   cp .env.example .env

   # On Windows
   copy .env.example .env
   ```
   1. Edit the newly created `.env` file with your operational values.
   Available Environment Variables:

- `STEALTH_DOMAIN`: The domain used to mask your UDP payloads as DNS traffic (Default: example.com).

- `DECOY_IPS`: Comma-separated fake IPs to confuse Intrusion Detection Systems (e.g., 192.168.1.1,10.0.0.1).

- `DEFAULT_PORT`: The destination port for UDP probes (Default: 65212).

- `JITTER_MIN` / `JITTER_MAX`: Random delay bounds for packet crafting.

- `REPORT_INTERVAL`: Time in seconds between passive reports.

Note: The `.env` file is safely ignored by `.gitignore` to prevent accidental commits of your operational signatures.

---
## 🚀 Usage

> ⚠️ **Must be run as Administrator/root** for Raw Sockets to work.

### Quick Start

```bash
# Display all available commands
python ghost_sniffer.py --help
```

### Passive Discovery — The Silent Spy

```bash
# Monitor all traffic without filtering
python ghost_sniffer.py --mode passive

# Monitor a specific subnet with reports every 15 seconds
python ghost_sniffer.py --mode passive --subnet 192.168.1.0/24 --report-interval 15

# Monitor + save results to a JSON file
python ghost_sniffer.py --mode passive --subnet 10.0.0.0/24 --output passive_results.json
```

### Active Scan

```bash
# Simple scan
python ghost_sniffer.py --target 192.168.1.0/24

# Scan with DNS Mimicry
python ghost_sniffer.py --target 192.168.1.0/24 --mimicry dns

# Scan with DNS Mimicry + custom domain
python ghost_sniffer.py --target 192.168.1.0/24 --mimicry dns --dns-domain microsoft.com

# Scan with Jitter (random delay 0.5 - 2.0 seconds)
python ghost_sniffer.py --target 192.168.1.0/24 --jitter 0.5 2.0

# Scan with Decoys (distraction using fake addresses)
python ghost_sniffer.py --target 192.168.1.0/24 --decoys 192.168.1.1,192.168.1.254,10.0.0.1

# Scan with a specific port
python ghost_sniffer.py --target 192.168.1.0/24 --port 9999
```

### Stealth Mode — Full Ghost Mode

```bash
# --stealth = dns mimicry + jitter (0.5-2.0s) automatically
python ghost_sniffer.py --target 192.168.1.0/24 --stealth

# stealth + decoys = full power
python ghost_sniffer.py --target 192.168.1.0/24 --stealth \
  --decoys 192.168.1.1,192.168.1.254

# stealth + verbose + JSON export
python ghost_sniffer.py --target 192.168.1.0/24 --stealth \
  --decoys 10.0.0.1,10.0.0.254 -v --output full_scan.json
```

---

## 🔧 All Options

| Option | Default | Description |
|--------|---------|-------------|
| `--mode {scan,passive}` | `scan` | Operating mode |
| `--target, -t` | *required in scan* | Target Subnet (e.g. `192.168.1.0/24`) |
| `--port, -p` | `65212` | Target port |
| `--subnet` | `None` | Subnet filter in passive mode |
| `--mimicry {normal,dns}` | `normal` | Payload type |
| `--dns-domain` | `google.com` | Domain for dns mimicry mode |
| `--jitter MIN MAX` | `None` | Random delay range in seconds |
| `--decoys` | `None` | Comma-separated fake IP addresses |
| `--stealth` | `off` | Enable dns + jitter automatically |
| `--output, -o` | `None` | Save results as JSON |
| `--report-interval` | `30` | Seconds between passive reports |
| `--verbose, -v` | `off` | Print every captured packet |

---

## 🏗️ Architecture

```
GhostSniffer Engine
├── HostRegistry        ← Thread-safe host storage (threading.Lock)
├── SnifferEngine       ← Raw socket listener (passive + active)
│   ├── IP Parser       ← Network byte order (!), 20-byte header
│   └── ICMP Parser     ← Type/Code analysis
├── ScannerEngine       ← Active probe sender
│   ├── PacketBuilder   ← Raw IP/UDP/DNS construction
│   │   ├── IP Header   ← Manual checksum (RFC 1071)
│   │   ├── UDP Header  ← Manual checksum with pseudo-header
│   │   └── DNS Query   ← Legitimate A-record query builder
│   ├── Mimicry         ← normal / dns payload modes
│   ├── Jitter          ← random.uniform(min, max) delays
│   └── Decoys          ← Shuffled IP-spoofed packets
└── CLI (argparse)      ← Full argument parsing + --stealth shortcut
```

### Engineering Notes

- **Thread Safety**: The `HostRegistry` is protected with `threading.Lock()` since the Sniffer and Scanner write to it concurrently — no Race Conditions
- **UDP Checksum**: Manually computed with the Pseudo-header because some Windows versions don't compute it for Raw Sockets
- **IP Checksum**: Fully manually computed (RFC 1071) — not relying on the Kernel
- **Byte Order**: All Parsers use `!` (Network/Big-Endian) not `<` (Little-Endian)
- **Clean Shutdown**: Socket timeout + chunked sleep = fast response to Ctrl+C
- **Platform Aware**: The code automatically handles differences between Windows and Linux
- **Limitation**: On Linux, if the AF_PACKET socket cannot be opened (permissions), the sniffer falls back to ICMP‑only capture; passive discovery will then only see ICMP traffic.

---

## 📄 Output Example

### Console Output (Scan Mode)
```
[👻] Active Scan Mode — Engaging target network

[⚡] Target: 192.168.1.0/24 (254 hosts) -> Port 65212
[⚡] Mimicry: dns (domain: google.com)
[⚡] Jitter: 0.5s - 2.0s
[⚡] Decoys: 192.168.1.1, 192.168.1.254
[⚡] Local IP: 192.168.1.100

  [████████████████░░░░░░░░░░░░░░] 53% (135/254)

[👻] Host Up: 192.168.1.10 (ICMP Port Unreachable)
[👻] Host Up: 192.168.1.50 (ICMP Port Unreachable)
[👻] Host Up: 192.168.1.105 (ICMP Port Unreachable)
```

### JSON Output
```json
{
  "tool": "GhostSniffer v2.0",
  "timestamp": "2026-07-15T21:30:00",
  "mode": "scan",
  "statistics": {
    "packets_captured": 1547,
    "packets_sent": 254,
    "decoy_packets_sent": 508,
    "hosts_scanned": 254,
    "icmp_responses": 12
  },
  "hosts": {
    "192.168.1.10": {
      "ip": "192.168.1.10",
      "status": "up",
      "protocols": ["ICMP", "TCP"],
      "packet_count": 5
    }
  }
}
```

---

## ⚠️ Disclaimer

This tool is designed for **authorized penetration testing** and educational purposes only. Using it on networks without explicit permission is a legal violation. Full responsibility lies with the user.

---

## 📝 License

For educational and authorized penetration testing purposes only.
