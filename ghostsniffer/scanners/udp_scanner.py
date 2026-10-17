"""
UDP Probe Scanner with DNS Mimicry and ICMP Response Correlation.
Sends crafted UDP probes to discover responsive network endpoints.
"""

import ipaddress
import os
import random
import socket
import sys
import threading
import time
from typing import List, Optional, Tuple, Dict

from ghostsniffer.network.packet_builder import PacketBuilder
from ghostsniffer.network.parsers import IP, ICMP
from ghostsniffer.registry import HostRegistry


class UDPScanner:
    """Active UDP probe scanner with protocol mimicry (DNS masking)."""

    def __init__(
        self,
        registry: HostRegistry,
        target_subnet: str,
        port: int = 65212,
        mimicry: str = 'normal',
        dns_domain: str = 'google.com',
        jitter: Optional[Tuple[float, float]] = None,
        decoys: Optional[List[str]] = None,
        verbose: bool = False,
    ) -> None:
        self.registry = registry
        self.target_subnet = ipaddress.ip_network(target_subnet, strict=False)
        self.port = port
        self.mimicry = mimicry
        self.dns_domain = dns_domain
        self.jitter = jitter
        self.decoys = decoys or []
        self.verbose = verbose

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._socket: Optional[socket.socket] = None
        self._stats: Dict[str, int] = {
            'packets_sent': 0,
            'decoy_packets_sent': 0,
            'hosts_scanned': 0,
        }
        self._local_ip = self._detect_local_ip()

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
    def _progress(current: int, total: int) -> None:
        if total == 0:
            return
        pct = int(current / total * 100)
        filled = int(30 * current / total)
        bar = '\u2588' * filled + '\u2591' * (30 - filled)
        sys.stdout.write(f"\r  [{bar}] {pct}% ({current}/{total})")
        sys.stdout.flush()

    def _build_payload(self) -> bytes:
        if self.mimicry == 'dns':
            return PacketBuilder.build_dns_query(self.dns_domain)
        return PacketBuilder.build_normal_payload()

    def _send_packet(self, src_ip: str, dst_ip: str, payload: bytes) -> bool:
        src_port = random.randint(1024, 65535)
        packet = PacketBuilder.build_full_packet(
            src_ip, dst_ip, src_port, self.port, payload
        )
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

    def handle_icmp_packet(self, ip_hdr: IP, icmp_hdr: ICMP) -> bool:
        """Handle ICMP Port Unreachable responses to confirm host presence."""
        src_ip = str(ip_hdr.src_address)
        if icmp_hdr.type == 3 and icmp_hdr.code == 3:
            if self.registry.was_scanned_recently(src_ip):
                self.registry.mark_responsive(src_ip, icmp_hdr.type, icmp_hdr.code)
                print(f"[+] Host Up: {src_ip} (ICMP Port Unreachable)")
                return True
            elif self.verbose:
                print(f"[!] Ignored ICMP from {src_ip} (not recently scanned)")
        return False

    def _scan_loop(self) -> None:
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
                        key = 'decoy_packets_sent' if is_decoy else 'packets_sent'
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

        sys.stdout.write('\n')
        print('[+] UDP scan sweep complete')
        self._running = False

    def start(self) -> None:
        """Create socket and start probe thread."""
        if os.name == 'nt':
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except OSError as e:
            if self.verbose:
                print(f"[!] IP_HDRINCL not supported: {e}")

        self._socket = sock
        self._running = True
        self._thread = threading.Thread(target=self._scan_loop, daemon=True, name='UDPScanner')
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)
