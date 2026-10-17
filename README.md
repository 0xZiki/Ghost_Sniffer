#  GhostSniffer v2.1

**Hardened Modular Raw-Socket Network Reconnaissance Engine**  
*Zero External Dependencies | Raw Sockets | RFC-Compliant State Tracking | Stealth Operations*  
**Created by:** `0xZiki`  
**Language:** [English](README.md) | [العربية](README_AR.md)

---

##  Overview

**GhostSniffer v2.1** is an advanced, production-grade network reconnaissance and covert operations engine written in pure Python 3 using raw sockets. It provides deep visibility across Layer 2 (Data Link), Layer 3 (Network), Layer 4 (Transport), and Layer 7 (Application) without relying on third-party dependencies like Scapy, Nmap, or Pcap.

Originally a monolithic script, version 2.1 has been completely refactored into a high-performance modular package (`ghostsniffer/`) that resolves three critical protocol flaws:
1. **Strict RFC 793 SYN Response Correlation:** Guarantees zero false-positive port detections by verifying ephemeral source ports and 32-bit sequence number acknowledgments (`Ack == ISN + 1`).
2. **Hardened Port Knocking Daemon:** Replaces static sequence matching with per-source-IP session isolation, sliding expiration windows, cooldown replay mitigation, and constant-time HMAC-SHA256 payload verification.
3. **Multi-Vector Passive OS Fingerprinting:** Combines initial TTL reverse-engineering (hop decay), TCP Window Size signatures, and IPv4 Don't Fragment (DF) flags.

---

##  Core Features

| # | Feature | Layer | Description |
|---|---------|-------|-------------|
| 1 | **Passive Host Discovery** | L2 / L3 | Silent surveillance capturing ambient broadcasts, ARP replies, and transit IP packets without transmitting a single frame. |
| 2 | **Protocol Mimicry** | L7 | Disguises UDP probes as legitimate RFC 1035 DNS A-record queries to bypass Deep Packet Inspection (DPI) and egress filtering. |
| 3 | **Dynamic Temporal Jitter** | L4 | Randomizes inter-probe delays to defeat IDS/IPS pattern recognition and kernel rate-limiting (`icmp_ratelimit`). |
| 4 | **Decoy Traffic (Spoofing)** | L3 | Injects interleaved probes from spoofed IP addresses to overwhelm SIEMs and misdirect Blue Team incident responders. |
| 5 | **Hardened TCP SYN Half-Open Scan** | L4 | High-speed, stealthy port scanner enforcing strict RFC 793 correlation (`Ack == ISN + 1`, `DstPort == EphemeralSrcPort`). |
| 6 | **Layer-2 ARP Subnet Sweep** | L2 | Direct Ethernet broadcast discovery via `AF_PACKET`, revealing active hosts that block ICMP and TCP probes via local firewalls. |
| 7 | **Multi-Vector OS Fingerprinting** | L3 / L4 | Evaluates initial TTL hop decay, TCP Window Size patterns (Linux 64240 vs Windows 8192/65535), and IP DF flag presence. |
| 8 | **Secure Port Knocking Daemon** | L4 / L7 | Covert trigger engine with source IP binding, sliding timeout windows, replay protection, and optional HMAC-SHA256 authentication. |
| 9 | **Service Version Detection** | L7 | Seamlessly transitions to stream sockets to grab application banners (SSH, FTP, SMTP, HTTP, MySQL) with unverified TLS wrapping. |

---

##  System Requirements

- **Python 3.6+** (Standard Library only)
- **Root / Administrator privileges** (Mandatory for `SOCK_RAW` and `AF_PACKET` capabilities)
- **Linux:** Full support for all modes (including Layer-2 ARP scanning and IP spoofing).
- **Windows:** Supports UDP, TCP SYN, Passive capture (via `SIO_RCVALL`), and Service Detection. Layer-2 ARP is disabled due to OS limitations.

---

##  Installation & Quick Start

### 1. Standalone Execution (No Installation Required)
```bash
git clone https://github.com/0xZiki/ghost_sniffer.git
cd ghost_sniffer
chmod +x GhostSniffer.py

# Display help menu
sudo python3 GhostSniffer.py --help
```

### 2. Package Installation (Global CLI Command)
Install GhostSniffer as a system-wide or virtual environment package:
```bash
# Editable development install
sudo pip install -e .

# Or using setup.py
sudo python3 setup.py install

# Now run directly from anywhere:
ghostsniffer --help
```

---

##  OPSEC & Configuration (The `.env` File)

To prevent sensitive operational parameters (custom decoy IPs, covert domains, knock authentication secrets) from leaking in command-line arguments or process tables (`ps aux`), GhostSniffer implements a deterministic 4-tier configuration hierarchy:

1. `/etc/ghost_sniffer/.env` (System-wide — Linux production sensors, `chmod 600`)
2. `~/.config/ghost_sniffer/.env` (User configuration adhering to XDG standards)
3. `./.env` (Current working directory)
4. `<script_dir>/.env` (Repository root fallback)

### Configuration Template
Copy the template and configure your parameters:
```bash
cp .env.example .env
chmod 600 .env
```

| Environment Variable | CLI Equivalent | Description | Default |
|----------------------|----------------|-------------|---------|
| `STEALTH_DOMAIN` | `--dns-domain` | Domain disguised inside UDP payload | `google.com` |
| `DECOY_IPS` | `--decoys` | Comma-separated spoofed source IP addresses | `None` |
| `DEFAULT_PORT` | `--port` | Destination port for UDP sweeps | `65212` |
| `JITTER_MIN` / `JITTER_MAX` | `--jitter` | Random delay bounds between probes (seconds) | `None` |
| `REPORT_INTERVAL` | `--report-interval` | Interval between passive discovery reports | `30` |
| `KNOCK_SECRET` | `--knock-secret` | Shared secret key for HMAC/token knock verification | `None` |

---

##  Operational Modes & Usage Examples

### 1. Passive Host Discovery (The Silent Observer)
Listens passively to network traffic without transmitting any packets to the wire.
```bash
# Capture all traffic on the local interface
sudo ghostsniffer --mode passive

# Filter by target subnet with reports every 15 seconds
sudo ghostsniffer --mode passive --subnet 192.168.1.0/24 --report-interval 15

# Export discovered hosts to JSON
sudo ghostsniffer --mode passive --subnet 10.0.0.0/24 --output passive_hosts.json
```

---

### 2. Deterministic TCP SYN "Half-Open" Scan
High-speed port scanner using raw TCP packets with RFC 793 response correlation.
```bash
# Scan common web and management ports
sudo ghostsniffer --target 192.168.1.0/24 --scan-type tcp_syn -p 22,80,443

# Scan top 1024 ports with Service Version Detection (-sV)
sudo ghostsniffer --target 192.168.1.0/24 --scan-type tcp_syn -p 1-1024 -sV

# Full stealth mode with decoys and randomized jitter
sudo ghostsniffer --target 10.0.0.0/24 --scan-type tcp_syn -p 22,80,443,8080 \
  --stealth --decoys 10.0.0.1,10.0.0.254 --output scan_results.json
```

---

### 3. Layer-2 ARP Discovery Sweep (Linux Only)
Bypasses host-based personal firewalls (Windows Defender, iptables) by querying directly at Layer 2.
```bash
sudo ghostsniffer --target 192.168.1.0/24 --scan-type arp
```

---

### 4. Active UDP Probe Scan with DNS Mimicry
Sends crafted UDP packets disguised as DNS queries to elicit ICMP Port Unreachable responses.
```bash
# Standard UDP sweep
sudo ghostsniffer --target 192.168.1.0/24 --scan-type udp

# Disguise UDP payloads as Microsoft DNS queries
sudo ghostsniffer --target 192.168.1.0/24 --mimicry dns --dns-domain microsoft.com
```

---

### 5. Secure Port Knocking Listener
Monitors incoming packets for an authorized sequence with source IP binding and cryptographic replay protection.

**On the Listener (Server):**
```bash
sudo ghostsniffer --mode listen \
  --knock-seq 1000,2000,3000 \
  --knock-proto udp \
  --knock-timeout 5.0 \
  --knock-secret "S3cr3tKn0ckK3y" \
  --action "iptables -I INPUT -s {src_ip} -p tcp --dport 22 -j ACCEPT"
```

**From the Client:**
```bash
# Send authorized knocks with HMAC or shared secret payload
echo "S3cr3tKn0ckK3y" | nc -u -w1 <SERVER_IP> 1000
echo "S3cr3tKn0ckK3y" | nc -u -w1 <SERVER_IP> 2000
echo "S3cr3tKn0ckK3y" | nc -u -w1 <SERVER_IP> 3000
```

---

## 🔧 Comprehensive CLI Options

```
usage: ghost_sniffer [-h] [--mode {scan,passive,listen}] [--target TARGET]
                     [--subnet SUBNET] [--scan-type {udp,tcp_syn,arp}]
                     [--ports PORTS] [--port PORT] [--mimicry {normal,dns}]
                     [--dns-domain DNS_DOMAIN] [--jitter MIN MAX]
                     [--decoys DECOYS] [--stealth] [--service-detection]
                     [--service-timeout SERVICE_TIMEOUT]
                     [--knock-seq KNOCK_SEQ] [--knock-proto {udp,icmp}]
                     [--knock-timeout KNOCK_TIMEOUT]
                     [--knock-secret KNOCK_SECRET] [--action ACTION]
                     [--output OUTPUT] [--report-interval REPORT_INTERVAL]
                     [--verbose]
```

| Parameter | Type / Choices | Default | Description |
|-----------|----------------|---------|-------------|
| `--mode` | `scan`, `passive`, `listen` | `scan` | Primary operational engine mode. |
| `--target`, `-t` | CIDR String | `None` | Target network subnet for scanning (e.g. `192.168.1.0/24`). |
| `--subnet` | CIDR String | `None` | Subnet filter for passive sniffer or listen mode. |
| `--scan-type` | `udp`, `tcp_syn`, `arp` | `udp` | Probe mechanism for active scan mode. |
| `--ports`, `-p` | Port Spec | `1-1024` | Target TCP ports (`22,80,443` or ranges `1-1024`). |
| `--port` | Integer | `65212` | Destination port for UDP sweeps. |
| `--mimicry` | `normal`, `dns` | `normal` | Payload obfuscation type. |
| `--dns-domain` | String | `google.com` | Camouflage domain for DNS query mimicry. |
| `--jitter` | Float Float | `None` | Random delay bounds `MIN MAX` in seconds between probes. |
| `--decoys` | String | `None` | Comma-separated spoofed source IP addresses. |
| `--stealth` | Flag | `False` | Shortcut enabling DNS mimicry + jitter (0.5s - 2.0s). |
| `--service-detection`, `-sV` | Flag | `False` | Connects to open ports to extract application banners. |
| `--service-timeout` | Float | `5.0` | Timeout per service probe in seconds. |
| `--knock-seq` | String | `None` | Port knock sequence (e.g. `1000,2000,3000`). |
| `--knock-proto` | `udp`, `icmp` | `udp` | Protocol monitored for port knocks. |
| `--knock-timeout` | Float | `5.0` | Maximum sliding window delay between sequential knocks. |
| `--knock-secret` | String | `None` | Shared secret key for HMAC/token payload authentication. |
| `--action` | String | `None` | Shell command executed upon valid knock sequence. |
| `--output`, `-o` | File Path | `None` | Export full telemetry report to JSON format. |
| `--report-interval` | Integer | `30` | Interval in seconds between periodic passive reports. |
| `--verbose`, `-v` | Flag | `False` | Display detailed per-packet capture diagnostics. |

---

##  Architecture

```
ghost_sniffer/
├── ghostsniffer/
│   ├── __init__.py            # Package root exports and version metadata
│   ├── config.py              # Constants, defaults, protocols, timing, dotenv loader
│   ├── registry.py            # HostRegistry (thread-safe host/port tracking)
│   ├── network/
│   │   ├── __init__.py        # Network subpackage exports
│   │   ├── checksum.py        # Manual RFC 1071 Internet Checksum calculation
│   │   ├── packet_builder.py  # Raw IP, UDP, TCP SYN, DNS, and ARP builders
│   │   └── parsers.py         # Binary unpackers (! Network Byte Order: IP, TCP, ICMP, ARP)
│   ├── scanners/
│   │   ├── __init__.py        # Scanner subpackage exports
│   │   ├── tcp_syn.py         # Hardened SYN Half-Open Scanner with RFC 793 correlation
│   │   ├── udp_scanner.py     # UDP probe scanner with DNS mimicry
│   │   └── arp_scanner.py     # Layer-2 AF_PACKET discovery (Linux only)
│   ├── detection/
│   │   ├── __init__.py        # Detection subpackage exports
│   │   ├── os_fingerprint.py  # Advanced OS detection (TTL heuristic + TCP Window + DF flag)
│   │   └── service_detect.py  # Banner grabbing & protocol fingerprinting
│   ├── knock/
│   │   ├── __init__.py        # Knock subpackage exports
│   │   └── listener.py        # Secure Port Knocking daemon with replay mitigation & IP binding
│   └── cli.py                 # Argparse orchestration, SnifferEngine, GhostSniffer orchestrator
├── GhostSniffer.py            # Executable standalone runner
├── setup.py                   # Package setup with 'ghostsniffer' console_scripts
├── .gitignore                 # Standard clean ignore file
└── README.md                  # Comprehensive documentation
```

---

##  Sample Output

### Console Report
```
================================================================================
  GHOSTSNIFFER — FINAL REPORT
================================================================================

  Statistics:
  ------------------------------------------
  Packets Captured:     1842
  Packets Sent:         762
  Decoy Packets Sent:   1524
  Hosts Scanned:        254
  ICMP Responses:       18
  Unique Hosts Found:   14
  Hosts Confirmed Up:   9

  Discovered Hosts:
  ----------------------------------------------------------------------------
  IP Address         Status     Protocols    OS Guess             Open Ports
  ----------------------------------------------------------------------------
  192.168.1.1        up         ICMP,ARP     Network Device       -
  192.168.1.10       up         TCP,ARP      Linux (kernel 3.x)   22(SSH-2.0-OpenSSH...),80(HTTP/1.1 200)
  192.168.1.25       up         TCP          Windows 10/11        445,3389(RDP)
  192.168.1.50       up         TCP          macOS/iOS or BSD     443(HTTPS)
  ----------------------------------------------------------------------------

================================================================================
[+] Completed at 14:35:10
```

### JSON Export (`--output scan.json`)
```json
{
  "tool": "GhostSniffer v2.0 (Hardened Modular Engine)",
  "timestamp": "2026-10-17T14:35:10.123456",
  "mode": "scan",
  "config": {
    "target": "192.168.1.0/24",
    "scan_type": "tcp_syn",
    "ports": [22, 80, 443, 3389],
    "mimicry": "dns",
    "jitter": [0.5, 2.0],
    "decoys": "192.168.1.1,192.168.1.254"
  },
  "statistics": {
    "packets_captured": 1842,
    "packets_sent": 762,
    "decoy_packets_sent": 1524,
    "hosts_scanned": 254,
    "icmp_responses": 18
  },
  "hosts": {
    "192.168.1.10": {
      "ip": "192.168.1.10",
      "first_seen": "2026-10-17T14:34:02.001122",
      "last_seen": "2026-10-17T14:35:08.554433",
      "packet_count": 14,
      "protocols": ["ARP", "TCP"],
      "status": "up",
      "open_ports": [22, 80],
      "os_guess": "Linux (kernel 3.x-6.x, hops: 0)",
      "ttl": 64,
      "services": {
        "22": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        "80": "HTTP/1.1 200 OK"
      }
    }
  }
}
```

---

##  Automated Testing

GhostSniffer includes an automated unit and integration test suite covering RFC 793 correlation, 32-bit sequence wraparounds, Port Knocking session tracking and replay protection, OS fingerprinting heuristics, and RFC 1071 checksums:

```bash
# Execute the test suite
python3 -m unittest -v scratch/test_suite.py
```

---

##  Legal & Security Disclaimer

GhostSniffer is developed solely for authorized penetration testing, security auditing, and educational protocol research. Performing unauthorized port scanning, packet injection, or network reconnaissance against systems without explicit, documented permission is strictly prohibited by law. The author and contributors assume no liability for misuse.

---

## 📝 License

Distributed under the [MIT License](https://opensource.org/licenses/MIT).
