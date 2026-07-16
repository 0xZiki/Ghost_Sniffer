#!/usr/bin/env python3
"""
   ██████╗ ██╗  ██╗ ██████╗ ███████╗███████╗███████╗███████╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔═══██╗██╔════╝╚══██╔══╝╚══██╔══╝
  ██║  ███╗███████║██║   ██║██║   ██║█████╗     ██║      ██║
  ██║   ██║██╔══██║██║   ██║██║   ██║██╔══╝     ██║      ██║
  ╚██████╔╝██║  ██║╚██████╔╝╚██████╔╝███████╗   ██║      ██║
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚══════╝   ╚═╝      ╚═╝
██████╗ ██╗   ██╗██████╗ ██████╗ ███████╗██████╗ ██████╗ ██████╗ 
██╔════╝██║   ██║╚════██╗██╔══██╗██╔════╝██╔══██╗╚════██╗██╔══██╗
██║     ██║   ██║ █████╔╝██████╔╝█████╗  ██████╔╝ █████╔╝██████╔╝
██║     ██║   ██║ ╚═══██╗██╔══██╗██╔══╝  ██╔══██╗ ╚═══██╗██╔══██╗
╚██████╗╚██████╔╝██████╔╝██║  ██║███████╗██║  ██║██████╔╝██║  ██║
 ╚═════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝

GhostSniffer v2.0 — Advanced Network Reconnaissance Tool
Zero Dependencies | Raw Sockets | Stealth Operations

Features:
  [1] Passive Host Discovery — Silent network monitoring
  [2] Protocol Mimicry      — DNS payload camouflage
  [3] Dynamic Jitter         — Random timing to evade IDS
  [4] Decoy Traffic          — IP Spoofing with fake sources
"""

import socket
import struct
import ipaddress
import os
import sys
import time
import random
import threading
import argparse
import json
from datetime import datetime

# ----------------------------------------------------------------------------
#  Load .env file if present
# ----------------------------------------------------------------------------

def load_dotenv():
    """Load environment variables from .env file if it exists."""
    try:
        with open('.env') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if '=' in line:
                        key, val = line.split('=', 1)
                        os.environ[key.strip()] = val.strip()
    except FileNotFoundError:
        pass

# ----------------------------------------------------------------------------
#  ANSI Terminal Colors
# ----------------------------------------------------------------------------

class C:
    """ANSI color codes — auto-enables VT100 on Windows."""

    if os.name == 'nt':
        os.system('')

    RST  = '\033[0m'
    BOLD = '\033[1m'
    DIM  = '\033[2m'

    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    BLUE   = '\033[94m'
    PURPLE = '\033[95m'
    CYAN   = '\033[96m'
    WHITE  = '\033[97m'
    GRAY   = '\033[90m'

    @staticmethod
    def ok(msg):    return f"{C.GREEN}[+]{C.RST} {msg}"
    @staticmethod
    def info(msg):  return f"{C.CYAN}[*]{C.RST} {msg}"
    @staticmethod
    def warn(msg):  return f"{C.YELLOW}[!]{C.RST} {msg}"
    @staticmethod
    def err(msg):   return f"{C.RED}[✗]{C.RST} {msg}"
    @staticmethod
    def ghost(msg): return f"{C.PURPLE}[👻]{C.RST} {msg}"
    @staticmethod
    def scan(msg):  return f"{C.BLUE}[⚡]{C.RST} {msg}"

# ----------------------------------------------------------------------------
#  Banner
# ----------------------------------------------------------------------------

BANNER = f"""
{C.PURPLE}{C.BOLD}   ██████╗ ██╗  ██╗ ██████╗ ███████╗███████╗███████╗███████╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔═══██╗██╔════╝╚══██╔══╝╚══██╔══╝
  ██║  ███╗███████║██║   ██║██║   ██║█████╗     ██║      ██║
  ██║   ██║██╔══██║██║   ██║██║   ██║██╔══╝     ██║      ██║
  ╚██████╔╝██║  ██║╚██████╔╝╚██████╔╝███████╗   ██║      ██║
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚══════╝   ╚═╝      ╚═╝
{C.CYAN}  ██████╗ ██╗   ██╗██████╗ ██████╗ ███████╗██████╗ ██████╗ ██████╗ 
  ██╔════╝██║   ██║╚════██╗██╔══██╗██╔════╝██╔══██╗╚════██╗██╔══██╗
  ██║     ██║   ██║ █████╔╝██████╔╝█████╗  ██████╔╝ █████╔╝██████╔╝
  ██║     ██║   ██║ ╚═══██╗██╔══██╗██╔══╝  ██╔══██╗ ╚═══██╗██╔══██╗
  ╚██████╗╚██████╔╝██████╔╝██║  ██║███████╗██║  ██║██████╔╝██║  ██║
   ╚═════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝{C.RST}
  {C.GRAY}──────────────────────────────────────────────────────────────────────
  {C.DIM}v2.0 │ Advanced Network Recon │ Zero Dependencies
  Raw Sockets │ Stealth Ops │ Protocol Mimicry{C.RST}
  {C.GRAY}──────────────────────────────────────────────────────────────────────{C.RST}
"""

# ----------------------------------------------------------------------------
#  Checksum Utilities  (RFC 1071)
# ----------------------------------------------------------------------------

def inet_checksum(data: bytes) -> int:
    """Calculate the Internet Checksum per RFC 1071."""
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) | data[i + 1]
        total += word
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF

def compute_udp_checksum(src_ip: str, dst_ip: str, udp_packet: bytes) -> int:
    """Calculate UDP checksum including the IPv4 pseudo-header."""
    pseudo_header = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack('!BBH', 0, socket.IPPROTO_UDP, len(udp_packet))
    )
    return inet_checksum(pseudo_header + udp_packet)

# ----------------------------------------------------------------------------
#  Protocol Parsers
# ----------------------------------------------------------------------------

class IP:
    """Parse a raw IPv4 header (supports options)."""

    PROTO_MAP = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

    def __init__(self, raw: bytes):
        if len(raw) < 1:
            raise ValueError("Truncated IP header")
        ver_ihl = raw[0]
        ihl = ver_ihl & 0xF
        header_len = ihl * 4
        if len(raw) < header_len:
            raise ValueError("Truncated IP header with options")

        fmt = f'!BBHHHBBH{4}s{4}s'
        unpacked = struct.unpack(fmt, raw[:header_len])
        self.ver        = unpacked[0] >> 4
        self.ihl        = ihl
        self.tos        = unpacked[1]
        self.total_len  = unpacked[2]
        self.ident      = unpacked[3]
        self.flags_frag = unpacked[4]
        self.ttl        = unpacked[5]
        self.proto_num  = unpacked[6]
        self.checksum   = unpacked[7]
        self.src_raw    = unpacked[8]
        self.dst_raw    = unpacked[9]

        self.src_address = ipaddress.ip_address(self.src_raw)
        self.dst_address = ipaddress.ip_address(self.dst_raw)
        self.protocol    = self.PROTO_MAP.get(self.proto_num, str(self.proto_num))
        self.header_len  = header_len

    def __str__(self):
        return (f"IP [{self.protocol}] {self.src_address} -> "
                f"{self.dst_address} "
                f"(TTL:{self.ttl} Len:{self.total_len})")

class ICMP:
    """Parse a raw ICMP header (type, code, checksum)."""

    TYPE_MAP = {
        0: 'Echo Reply',
        3: 'Dest Unreachable',
        8: 'Echo Request',
        11: 'Time Exceeded',
    }

    def __init__(self, raw: bytes):
        if len(raw) < 4:
            raise ValueError("Truncated ICMP header")
        header = struct.unpack('!BBH', raw[:4])
        self.type     = header[0]
        self.code     = header[1]
        self.checksum = header[2]
        self.type_str = self.TYPE_MAP.get(self.type, f'Type-{self.type}')

    def __str__(self):
        return (f"ICMP {self.type_str} "
                f"(Type:{self.type} Code:{self.code})")

# ----------------------------------------------------------------------------
#  Packet Builders
# ----------------------------------------------------------------------------

class PacketBuilder:
    """Construct raw network packets for scanning operations."""

    @staticmethod
    def build_dns_query(domain: str = "google.com") -> bytes:
        txn_id = struct.pack('!H', random.randint(0, 0xFFFF))
        flags  = struct.pack('!H', 0x0100)
        counts = struct.pack('!HHHH', 1, 0, 0, 0)

        qname = b''
        for label in domain.split('.'):
            qname += struct.pack('B', len(label)) + label.encode('ascii')
        qname += b'\x00'

        qtype_class = struct.pack('!HH', 1, 1)
        return txn_id + flags + counts + qname + qtype_class

    @staticmethod
    def build_normal_payload() -> bytes:
        return os.urandom(random.randint(32, 128))

    @staticmethod
    def build_udp_header(src_port: int, dst_port: int,
                         payload: bytes,
                         src_ip: str, dst_ip: str) -> bytes:
        length = 8 + len(payload)
        header_zero = struct.pack('!HHHH', src_port, dst_port, length, 0)
        csum = compute_udp_checksum(src_ip, dst_ip, header_zero + payload)
        if csum == 0:
            csum = 0xFFFF
        return struct.pack('!HHHH', src_port, dst_port, length, csum)

    @staticmethod
    def build_ip_header(src_ip: str, dst_ip: str,
                        payload_len: int) -> bytes:
        ver_ihl   = 0x45
        tos       = 0
        total_len = 20 + payload_len
        ident     = random.randint(1, 0xFFFF)
        frag      = 0
        ttl       = random.randint(60, 128)
        proto     = socket.IPPROTO_UDP
        src       = socket.inet_aton(src_ip)
        dst       = socket.inet_aton(dst_ip)

        header = struct.pack('!BBHHHBBH4s4s',
                             ver_ihl, tos, total_len, ident,
                             frag, ttl, proto, 0, src, dst)
        csum = inet_checksum(header)
        header = struct.pack('!BBHHHBBH4s4s',
                             ver_ihl, tos, total_len, ident,
                             frag, ttl, proto, csum, src, dst)
        return header

    @staticmethod
    def build_full_packet(src_ip: str, dst_ip: str,
                          src_port: int, dst_port: int,
                          payload: bytes) -> bytes:
        udp_hdr = PacketBuilder.build_udp_header(
            src_port, dst_port, payload, src_ip, dst_ip)
        udp_segment = udp_hdr + payload
        ip_hdr = PacketBuilder.build_ip_header(
            src_ip, dst_ip, len(udp_segment))
        return ip_hdr + udp_segment

# ----------------------------------------------------------------------------
#  Thread-Safe Host Registry
# ----------------------------------------------------------------------------

class HostRegistry:
    """Central, thread-safe store for all discovered hosts and scan times."""

    def __init__(self):
        self._lock = threading.Lock()
        self._hosts: dict = {}
        self._responsive: set = set()
        self._last_scan: dict = {}   # ip -> timestamp (float)

    def register(self, ip: str, protocol: str) -> bool:
        now = datetime.now().isoformat()
        with self._lock:
            if ip not in self._hosts:
                self._hosts[ip] = {
                    'ip': ip,
                    'first_seen': now,
                    'last_seen': now,
                    'packet_count': 1,
                    'protocols': {protocol},
                    'status': 'discovered',
                }
                return True
            else:
                entry = self._hosts[ip]
                entry['last_seen'] = now
                entry['packet_count'] += 1
                entry['protocols'].add(protocol)
                return False

    def mark_responsive(self, ip: str, icmp_type: int, icmp_code: int) -> None:
        now = datetime.now().isoformat()
        with self._lock:
            self._responsive.add(ip)
            if ip in self._hosts:
                self._hosts[ip]['status'] = 'up'
                self._hosts[ip]['icmp_response'] = f"Type:{icmp_type} Code:{icmp_code}"
            else:
                self._hosts[ip] = {
                    'ip': ip,
                    'first_seen': now,
                    'last_seen': now,
                    'packet_count': 1,
                    'protocols': {'ICMP'},
                    'status': 'up',
                    'icmp_response': f"Type:{icmp_type} Code:{icmp_code}",
                }

    def mark_scanned(self, ip: str) -> None:
        """Record that we just scanned this IP (for ICMP matching)."""
        with self._lock:
            self._last_scan[ip] = time.time()

    def was_scanned_recently(self, ip: str, seconds: float = 15.0) -> bool:
        """Check if this IP was scanned within the last `seconds`."""
        with self._lock:
            ts = self._last_scan.get(ip, 0.0)
            return (time.time() - ts) <= seconds

    def get_all(self) -> dict:
        with self._lock:
            out = {}
            for ip, info in self._hosts.items():
                copy = dict(info)
                copy['protocols'] = sorted(info['protocols'])
                out[ip] = copy
            return out

    def get_responsive(self) -> set:
        with self._lock:
            return set(self._responsive)

    def count(self) -> int:
        with self._lock:
            return len(self._hosts)

    def responsive_count(self) -> int:
        with self._lock:
            return len(self._responsive)

# ----------------------------------------------------------------------------
#  Sniffer Engine
# ----------------------------------------------------------------------------

class SnifferEngine:
    """Raw-socket listener that captures and analyses network traffic."""

    @staticmethod
    def _detect_local_ip() -> str:
        """Discover the primary outbound IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '0.0.0.0'  # fallback

    def __init__(self, registry: HostRegistry,
                 subnet_filter=None,
                 verbose: bool = False,
                 scan_mode: bool = False):
        self.registry      = registry
        self.subnet_filter = subnet_filter
        self.verbose       = verbose
        self.scan_mode     = scan_mode
        self._running      = False
        self._socket       = None
        self._thread       = None
        self._stats        = {'packets_captured': 0, 'icmp_responses': 0}
        self.packet_offset = 0
        self.is_af_packet  = False
        self._local_ip     = self._detect_local_ip()   # <-- التعديل

    def start(self) -> None:
        """Create the raw socket and launch the sniffer thread."""
        if os.name == 'nt':
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((self._local_ip, 0))   # <-- استخدام IP المحلي
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            except OSError:
                if self.verbose:
                    print(C.warn("IP_HDRINCL not supported; capture may be limited"))
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            except Exception:
                if self.verbose:
                    print(C.warn("RCVALL not supported; capture may be limited"))
            self.packet_offset = 0
            self.is_af_packet = False
        else:
            # Try AF_PACKET for full capture, fallback to ICMP
            try:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
                self.packet_offset = 14
                self.is_af_packet = True
                if self.verbose:
                    print(C.info("Using AF_PACKET for full packet capture"))
            except (AttributeError, PermissionError) as e:
                if self.verbose:
                    print(C.warn(f"AF_PACKET failed ({e}), falling back to ICMP-only"))
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    sock.bind((self._local_ip, 0))   # <-- استخدام IP المحلي هنا أيضاً
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                except PermissionError:
                    raise PermissionError("Need root privileges for raw socket")
                self.packet_offset = 0
                self.is_af_packet = False

        self._socket = sock
        self._socket.settimeout(1.0)

        self._running = True
        self._thread = threading.Thread(
            target=self._sniff_loop, daemon=True, name='Sniffer')
        self._thread.start()
        print(C.ok("Sniffer engine started"))

    def _sniff_loop(self) -> None:
        while self._running:
            try:
                if self.is_af_packet:
                    raw_buffer, _ = self._socket.recvfrom(65565)
                    raw_buffer = raw_buffer[self.packet_offset:]  # strip Ethernet header
                else:
                    raw_buffer, _ = self._socket.recvfrom(65565)
            except socket.timeout:
                continue
            except OSError:
                break

            if len(raw_buffer) < 20:
                continue

            try:
                ip_hdr = IP(raw_buffer[:60])
            except Exception:
                continue

            self._stats['packets_captured'] += 1
            src_ip = str(ip_hdr.src_address)

            if self.subnet_filter:
                if ip_hdr.src_address in self.subnet_filter:
                    is_new = self.registry.register(src_ip, ip_hdr.protocol)
                    if is_new and not self.scan_mode:
                        print(C.ghost(
                            f"New host: {C.GREEN}{C.BOLD}{src_ip}"
                            f"{C.RST} {C.GRAY}[{ip_hdr.protocol}]{C.RST}"))
            else:
                is_new = self.registry.register(src_ip, ip_hdr.protocol)
                if is_new and not self.scan_mode:
                    print(C.ghost(
                        f"New host: {C.GREEN}{C.BOLD}{src_ip}"
                        f"{C.RST} {C.GRAY}[{ip_hdr.protocol}]{C.RST}"))

            if self.scan_mode and ip_hdr.protocol == 'ICMP':
                offset = ip_hdr.header_len
                if len(raw_buffer) >= offset + 4:
                    try:
                        icmp_hdr = ICMP(raw_buffer[offset:offset + 4])
                    except Exception:
                        continue

                    if self.verbose:
                        print(C.info(f"{ip_hdr} | {icmp_hdr}"))

                    # Port Unreachable → possible host up
                    if icmp_hdr.type == 3 and icmp_hdr.code == 3:
                        # Only consider it if we scanned this host recently
                        if self.registry.was_scanned_recently(src_ip):
                            self._stats['icmp_responses'] += 1
                            self.registry.mark_responsive(
                                src_ip, icmp_hdr.type, icmp_hdr.code)
                            print(C.ghost(
                                f"Host Up: {C.GREEN}{C.BOLD}{src_ip}"
                                f"{C.RST} {C.GRAY}(ICMP Port Unreachable){C.RST}"))
                        elif self.verbose:
                            print(C.warn(
                                f"Ignored ICMP Port Unreachable from {src_ip} "
                                f"(not recently scanned)"))

            elif self.verbose and not self.scan_mode:
                print(C.info(f"{ip_hdr}"))

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        if self._socket:
            if os.name == 'nt':
                try:
                    self._socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except Exception:
                    pass
            self._socket.close()
        print(C.ok("Sniffer engine stopped"))

    @property
    def stats(self) -> dict:
        return dict(self._stats)

# ----------------------------------------------------------------------------
#  Scanner Engine
# ----------------------------------------------------------------------------

class ScannerEngine:
    """Active network scanner with stealth capabilities."""

    def __init__(self, registry: HostRegistry, target_subnet: str, port: int,
                 mimicry: str = 'normal',
                 dns_domain: str = 'google.com',
                 jitter: tuple = None,
                 decoys: list = None,
                 verbose: bool = False):
        self.registry = registry
        self.target_subnet = ipaddress.ip_network(target_subnet, strict=False)
        self.port       = port
        self.mimicry    = mimicry
        self.dns_domain = dns_domain
        self.jitter     = jitter
        self.decoys     = decoys or []
        self.verbose    = verbose

        self._running   = False
        self._thread    = None
        self._socket    = None
        self._stats     = {
            'packets_sent': 0,
            'decoy_packets_sent': 0,
            'hosts_scanned': 0,
        }
        self._local_ip  = self._detect_local_ip()

    @staticmethod
    def _detect_local_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '0.0.0.0'

    def _build_payload(self) -> bytes:
        if self.mimicry == 'dns':
            return PacketBuilder.build_dns_query(self.dns_domain)
        return PacketBuilder.build_normal_payload()

    def _send_packet(self, src_ip: str, dst_ip: str, payload: bytes) -> bool:
        src_port = random.randint(1024, 65535)
        packet = PacketBuilder.build_full_packet(
            src_ip, dst_ip, src_port, self.port, payload)
        try:
            self._socket.sendto(packet, (dst_ip, 0))
            return True
        except PermissionError:
            print(C.err("Permission denied — run as Administrator/root"))
            self._running = False
            return False
        except Exception as e:
            if self.verbose:
                print(C.err(f"Send to {dst_ip} failed: {e}"))
            return False

    def _scan_host(self, target_ip: str, payload: bytes) -> None:
        dst = str(target_ip)
        self.registry.mark_scanned(dst)

        if self.decoys:
            senders = [(self._local_ip, False)]
            for decoy_ip in self.decoys:
                senders.append((decoy_ip, True))
            random.shuffle(senders)

            for src_ip, is_decoy in senders:
                if not self._running:
                    return
                pld = self._build_payload() if is_decoy else payload
                if self._send_packet(src_ip, dst, pld):
                    if is_decoy:
                        self._stats['decoy_packets_sent'] += 1
                    else:
                        self._stats['packets_sent'] += 1
                time.sleep(random.uniform(0.005, 0.03))
        else:
            if self._send_packet(self._local_ip, dst, payload):
                self._stats['packets_sent'] += 1

    def _scan_loop(self) -> None:
        hosts = list(self.target_subnet.hosts())
        total = len(hosts)

        for i, host in enumerate(hosts, 1):
            if not self._running:
                break

            payload = self._build_payload()
            self._scan_host(str(host), payload)
            self._stats['hosts_scanned'] += 1
            # Record that we scanned this host (for ICMP matching)
            # self.registry.mark_scanned(str(host))

            if i % 10 == 0 or i == total:
                pct = int(i / total * 100)
                filled = int(30 * i / total)
                bar = '\u2588' * filled + '\u2591' * (30 - filled)
                sys.stdout.write(
                    f"\r  {C.GRAY}[{bar}] "
                    f"{pct}% ({i}/{total}){C.RST}")
                sys.stdout.flush()

            if self.jitter and self._running:
                delay = random.uniform(self.jitter[0], self.jitter[1])
                if self.verbose:
                    print(f"  {C.DIM}jitter: {delay:.2f}s{C.RST}")
                elapsed = 0.0
                while elapsed < delay and self._running:
                    chunk = min(0.1, delay - elapsed)
                    time.sleep(chunk)
                    elapsed += chunk

        sys.stdout.write('\n')
        print(C.ok('Scan sweep complete'))
        self._running = False

    def start(self) -> None:
        if os.name == 'nt':
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except OSError as e:
            if self.verbose:
                print(C.warn(f"IP_HDRINCL not supported: {e}"))

        self._socket = sock
        self._running = True
        self._thread = threading.Thread(
            target=self._scan_loop, daemon=True, name='Scanner')
        self._thread.start()

        host_count = sum(1 for _ in self.target_subnet.hosts())
        print(C.scan(
            f"Target: {C.BOLD}{self.target_subnet}{C.RST} "
            f"({host_count} hosts) -> Port {self.port}"))
        print(C.scan(
            f"Mimicry: {C.YELLOW}{self.mimicry}{C.RST}"
            + (f' (domain: {self.dns_domain})'
               if self.mimicry == 'dns' else '')))
        if self.jitter:
            print(C.scan(
                f"Jitter: {C.YELLOW}"
                f"{self.jitter[0]}s - {self.jitter[1]}s{C.RST}"))
        if self.decoys:
            print(C.scan(
                f"Decoys: {C.YELLOW}"
                f"{', '.join(self.decoys)}{C.RST}"))
        print(C.scan(
            f"Local IP: {C.CYAN}{self._local_ip}{C.RST}"))
        print()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        if self._socket:
            self._socket.close()

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def stats(self) -> dict:
        return dict(self._stats)

# ----------------------------------------------------------------------------
#  GhostSniffer — Main Orchestrator
# ----------------------------------------------------------------------------

class GhostSniffer:
    """Top-level controller that wires Sniffer + Scanner + Registry."""

    def __init__(self, args: argparse.Namespace):
        self.args     = args
        self.registry = HostRegistry()
        self.sniffer  = None
        self.scanner  = None

    def run(self) -> None:
        print(BANNER)
        self._print_config()

        if self.args.mode == 'passive':
            self._run_passive()
        else:
            self._run_scan()

    def _print_config(self) -> None:
        print(f"  {C.GRAY}{'─' * 50}{C.RST}")
        print(f"  {C.BOLD}Mode:{C.RST}    "
              f"{C.CYAN}{self.args.mode.upper()}{C.RST}")
        print(f"  {C.BOLD}Time:{C.RST}    "
              f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  {C.BOLD}OS:{C.RST}      {os.name}")
        print(f"  {C.GRAY}{'─' * 50}{C.RST}\n")

    def _run_passive(self) -> None:
        print(C.ghost(
            f"{C.BOLD}Passive Discovery Mode{C.RST}"
            " — Silent reconnaissance active"))

        subnet = None
        if self.args.subnet:
            subnet = ipaddress.ip_network(self.args.subnet, strict=False)
            print(C.info(f"Filtering: {subnet}"))
        else:
            print(C.info("No subnet filter — capturing all traffic"))
        print(C.info(
            f"Report interval: {self.args.report_interval}s"))
        print()

        self.sniffer = SnifferEngine(
            self.registry, subnet_filter=subnet,
            verbose=self.args.verbose, scan_mode=False)
        self.sniffer.start()

        stop_event = threading.Event()

        def _reporter():
            while not stop_event.is_set():
                stop_event.wait(timeout=self.args.report_interval)
                if not stop_event.is_set():
                    self._print_passive_report()

        report_thread = threading.Thread(
            target=_reporter, daemon=True, name='Reporter')
        report_thread.start()

        try:
            print(C.warn(
                "Press Ctrl+C to stop and generate final report\n"))
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            stop_event.set()
            self.sniffer.stop()
            print()
            self._print_final_report()
            self._export_results()

    def _run_scan(self) -> None:
        if not self.args.target:
            print(C.err("--target is required in scan mode"))
            sys.exit(1)

        print(C.ghost(
            f"{C.BOLD}Active Scan Mode{C.RST}"
            " — Engaging target network"))
        print()

        jitter = None
        if self.args.jitter:
            jitter = (self.args.jitter[0], self.args.jitter[1])

        decoys = None
        if self.args.decoys:
            decoys = [d.strip() for d in self.args.decoys.split(',')]

        target_net = ipaddress.ip_network(self.args.target, strict=False)

        # Start sniffer first
        self.sniffer = SnifferEngine(
            self.registry, subnet_filter=target_net,
            verbose=self.args.verbose, scan_mode=True)
        self.sniffer.start()

        # Start scanner, pass registry so it can mark scan times
        self.scanner = ScannerEngine(
            registry=self.registry,
            target_subnet=self.args.target,
            port=self.args.port,
            mimicry=self.args.mimicry,
            dns_domain=self.args.dns_domain,
            jitter=jitter,
            decoys=decoys,
            verbose=self.args.verbose)
        self.scanner.start()

        try:
            while self.scanner.is_running:
                time.sleep(0.5)
            print(C.info("Waiting 3s for late ICMP responses..."))
            time.sleep(3)

        except KeyboardInterrupt:
            print(f"\n{C.warn('Scan interrupted by user')}")

        finally:
            if self.scanner:
                self.scanner.stop()
            self.sniffer.stop()
            print()
            self._print_final_report()
            self._export_results()

    def _print_passive_report(self) -> None:
        count = self.registry.count()
        stats = self.sniffer.stats if self.sniffer else {}

        print(f"\n  {C.CYAN}{'=' * 48}{C.RST}")
        print(
            f"  {C.BOLD}  PERIODIC REPORT{C.RST}  "
            f"{datetime.now().strftime('%H:%M:%S')}")
        print(f"  {C.CYAN}{'=' * 48}{C.RST}")
        print(f"  Hosts discovered:  "
              f"{C.GREEN}{C.BOLD}{count}{C.RST}")
        print(f"  Packets captured:  "
              f"{stats.get('packets_captured', 0)}")

        hosts = self.registry.get_all()
        if hosts:
            recent = sorted(
                hosts.values(),
                key=lambda h: h['last_seen'], reverse=True)
            print(f"  {C.DIM}Last 5 seen:{C.RST}")
            for h in recent[:5]:
                protos = ', '.join(h['protocols'])
                print(
                    f"    {C.GREEN}*{C.RST} "
                    f"{h['ip']:16s} "
                    f"{C.GRAY}[{protos}] "
                    f"pkts:{h['packet_count']}{C.RST}")
        print(f"  {C.CYAN}{'=' * 48}{C.RST}\n")

    def _print_final_report(self) -> None:
        hosts      = self.registry.get_all()
        responsive = self.registry.get_responsive()
        s_stats    = self.sniffer.stats  if self.sniffer  else {}
        c_stats    = self.scanner.stats  if self.scanner  else {}

        width = 55
        print(f"\n{C.PURPLE}{'=' * width}{C.RST}")
        print(f"{C.BOLD}{C.PURPLE}"
              f"  GHOSTSNIFFER  —  FINAL REPORT{C.RST}")
        print(f"{C.PURPLE}{'=' * width}{C.RST}")

        print(f"\n  {C.BOLD}Statistics:{C.RST}")
        print(f"  {'─' * 42}")
        print(f"  Packets Captured:     "
              f"{s_stats.get('packets_captured', 0)}")
        if c_stats:
            print(f"  Packets Sent:         "
                  f"{c_stats.get('packets_sent', 0)}")
            print(f"  Decoy Packets Sent:   "
                  f"{c_stats.get('decoy_packets_sent', 0)}")
            print(f"  Hosts Scanned:        "
                  f"{c_stats.get('hosts_scanned', 0)}")
            print(f"  ICMP Responses:       "
                  f"{s_stats.get('icmp_responses', 0)}")
        print(f"  Unique Hosts Found:   "
              f"{C.GREEN}{C.BOLD}{len(hosts)}{C.RST}")
        if responsive:
            print(f"  Hosts Confirmed Up:   "
                  f"{C.GREEN}{C.BOLD}{len(responsive)}{C.RST}")

        if hosts:
            print(f"\n  {C.BOLD}Discovered Hosts:{C.RST}")
            print(f"  {'─' * 52}")
            print(f"  {'IP Address':<18} {'Status':<12} "
                  f"{'Protocols':<15} {'Pkts'}")
            print(f"  {'─' * 52}")

            sorted_hosts = sorted(
                hosts.values(),
                key=lambda h: ipaddress.ip_address(h['ip']))
            for h in sorted_hosts:
                st = h.get('status', 'discovered')
                sc = C.GREEN if st == 'up' else C.YELLOW
                pr = ', '.join(h['protocols'])
                print(f"  {h['ip']:<18} "
                      f"{sc}{st:<12}{C.RST} "
                      f"{pr:<15} {h['packet_count']}")
            print(f"  {'─' * 52}")
        else:
            print(f"\n  {C.YELLOW}No hosts discovered.{C.RST}")

        print(f"\n{C.PURPLE}{'=' * width}{C.RST}")
        print(C.ok(
            f"Completed at "
            f"{datetime.now().strftime('%H:%M:%S')}"))
        print(C.ghost("Engineering site secured.\n"))

    def _export_results(self) -> None:
        if not self.args.output:
            return

        hosts    = self.registry.get_all()
        s_stats  = self.sniffer.stats  if self.sniffer  else {}
        c_stats  = self.scanner.stats  if self.scanner  else {}

        report = {
            'tool': 'GhostSniffer v2.0',
            'timestamp': datetime.now().isoformat(),
            'mode': self.args.mode,
            'config': {
                'target': self.args.target,
                'port': self.args.port,
                'mimicry': self.args.mimicry,
                'jitter': self.args.jitter,
                'decoys': self.args.decoys,
            },
            'statistics': {**s_stats, **c_stats},
            'hosts': hosts,
        }

        try:
            with open(self.args.output, 'w', encoding='utf-8') as fh:
                json.dump(report, fh, indent=2, ensure_ascii=False)
            print(C.ok(
                f"Results exported to: "
                f"{C.BOLD}{self.args.output}{C.RST}"))
        except Exception as exc:
            print(C.err(f"Export failed: {exc}"))

# ----------------------------------------------------------------------------
#  CLI Argument Parser
# ----------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='ghost_sniffer',
        description='GhostSniffer v2.0 — Advanced Network Reconnaissance Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:

  # Passive host discovery on local subnet
  python ghost_sniffer.py --mode passive --subnet 192.168.1.0/24

  # Active scan with DNS mimicry
  python ghost_sniffer.py --target 192.168.1.0/24 --mimicry dns

  # Full stealth scan with all features
  python ghost_sniffer.py --target 10.0.0.0/24 --stealth \\
    --decoys 10.0.0.1,10.0.0.254

  # Scan with custom jitter and JSON output
  python ghost_sniffer.py --target 192.168.1.0/24 \\
    --jitter 0.5 2.0 --output results.json

  # Verbose scan for debugging
  python ghost_sniffer.py --target 192.168.1.0/24 -v
""")

    p.add_argument(
        '--mode', choices=['scan', 'passive'], default='scan',
        help='Operation mode (default: scan)')

    p.add_argument(
        '--target', '-t', type=str, default=None,
        help='Target subnet for scan (e.g. 192.168.1.0/24)')
    p.add_argument(
        '--port', '-p', type=int,
        default=int(os.environ.get('DEFAULT_PORT', 65212)),
        help='Destination port (default: 65212)')
    p.add_argument(
        '--subnet', type=str, default=None,
        help='Subnet filter for passive mode')

    p.add_argument(
        '--mimicry', choices=['normal', 'dns'], default='normal',
        help='Payload disguise: normal or dns (default: normal)')
    p.add_argument(
        '--dns-domain', type=str,
        default=os.environ.get('STEALTH_DOMAIN', 'google.com'),
        help='Domain for dns mimicry (default: google.com)')
    p.add_argument(
        '--jitter', nargs=2, type=float,
        metavar=('MIN', 'MAX'),
        help='Random delay range in seconds (e.g. 0.5 2.0)')
    p.add_argument(
        '--decoys', type=str, default=None,
        help='Comma-separated decoy IPs (e.g. 10.0.0.1,10.0.0.254)')
    p.add_argument(
        '--stealth', action='store_true',
        help='Shortcut: enable dns mimicry + jitter 0.5-2.0')

    p.add_argument(
        '--output', '-o', type=str, default=None,
        help='Export results to JSON file')
    p.add_argument(
        '--report-interval', type=int,
        default=int(os.environ.get('REPORT_INTERVAL', 30)),
        help='Seconds between passive reports (default: 30)')
    p.add_argument(
        '--verbose', '-v', action='store_true',
        help='Show every captured packet')

    return p

# ----------------------------------------------------------------------------
#  Main
# ----------------------------------------------------------------------------

def main() -> None:
    # 1. Load .env first so environment variables are available
    load_dotenv()

    # 2. Check privileges before doing anything
    if os.name == 'nt':
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                print(C.err("This tool requires Administrator privileges on Windows."))
                print(C.info("Please run as Administrator (right-click -> Run as administrator)."))
                sys.exit(1)
        except Exception:
            # If we can't check, assume not admin and warn
            print(C.warn("Could not verify admin privileges. Raw sockets may fail."))
    else:
        if os.geteuid() != 0:
            print(C.err("This tool requires root privileges on Linux."))
            print(C.info("Please run with sudo: sudo python ghost_sniffer.py ..."))
            sys.exit(1)

    parser = build_parser()
    args = parser.parse_args()

    # Apply environment defaults for jitter and decoys if not provided
    if not args.jitter:
        try:
            min_j = float(os.environ.get('JITTER_MIN', ''))
            max_j = float(os.environ.get('JITTER_MAX', ''))
            args.jitter = [min_j, max_j] if min_j < max_j else None
        except (ValueError, TypeError):
            pass

    if not args.decoys and os.environ.get('DECOY_IPS'):
        args.decoys = os.environ.get('DECOY_IPS')

    # Validate decoys
    if args.decoys:
        decoys = [d.strip() for d in args.decoys.split(',')]
        for ip in decoys:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                parser.error(f"Invalid decoy IP: {ip}")
        args.decoys = ','.join(decoys)

    # --stealth shortcut
    if args.stealth:
        args.mimicry = 'dns'
        if not args.jitter:
            args.jitter = [0.5, 2.0]

    if args.mode == 'scan' and not args.target:
        parser.error("--target is required in scan mode")

    if args.jitter and args.jitter[0] >= args.jitter[1]:
        parser.error("Jitter MIN must be less than MAX")

    ghost = GhostSniffer(args)
    ghost.run()

if __name__ == '__main__':
    main()