"""
Hardened TCP SYN Half-Open Scanner.
Implements RFC 793 State Correlation (ACK = ISN + 1, DstPort = SrcPort)
to eliminate false positives from stray network packets.
"""

import ipaddress
import os
import random
import socket
import sys
import threading
import time
from typing import List, Optional, Tuple, Dict, Any

from ghostsniffer.network.packet_builder import PacketBuilder
from ghostsniffer.network.parsers import IP, TCP
from ghostsniffer.registry import HostRegistry


class TCPSYNScanner:
    """Hardened TCP SYN Half-Open Scanner.

    RFC 793 Correlation:
    Strictly tracks each probe's ephemeral source port and initial sequence number (ISN).
    Incoming SYN-ACK / RST responses are only accepted if:
    1. Response dest_port == probe src_port
    2. Response ack_num == (probe isn + 1) mod 2^32
    """

    def __init__(
        self,
        registry: HostRegistry,
        target_subnet: str,
        ports: Optional[List[int]] = None,
        jitter: Optional[Tuple[float, float]] = None,
        decoys: Optional[List[str]] = None,
        verbose: bool = False,
    ) -> None:
        self.registry = registry
        self.target_subnet = ipaddress.ip_network(target_subnet, strict=False)
        self.ports = ports if ports else list(range(1, 1025))
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

        # Probe correlation tracking:
        # (target_ip, target_port, local_src_port) -> (original_isn, timestamp)
        self._pending_probes: Dict[Tuple[str, int, int], Tuple[int, float]] = {}
        self._probe_lock = threading.Lock()

    @staticmethod
    def _detect_local_ip() -> str:
        """Discover outbound IP address."""
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

    def _record_probe(
        self,
        target_ip: str,
        target_port: int,
        src_port: int,
        isn: int,
    ) -> None:
        """Record an active TCP SYN probe for strict RFC 793 correlation."""
        now = time.time()
        with self._probe_lock:
            # Clean up stale probes older than 30 seconds
            stale_keys = [
                k for k, (_, ts) in self._pending_probes.items()
                if (now - ts) > 30.0
            ]
            for k in stale_keys:
                del self._pending_probes[k]

            self._pending_probes[(target_ip, target_port, src_port)] = (isn, now)

    def handle_tcp_packet(self, ip_hdr: IP, tcp_hdr: TCP) -> bool:
        """Correlate an incoming TCP packet against active SYN probes.

        RFC 793 Enforcement:
        - Response ip_hdr.src_address must match target_ip
        - Response tcp_hdr.src_port must match target_port
        - Response tcp_hdr.dest_port must match original ephemeral src_port
        - Response tcp_hdr.ack_num must match (original_isn + 1) mod 2^32

        Returns True if packet is a correlated response; False if discarded as stray.
        """
        src_ip = str(ip_hdr.src_address)
        target_port = tcp_hdr.src_port
        local_src_port = tcp_hdr.dest_port
        key = (src_ip, target_port, local_src_port)

        with self._probe_lock:
            probe = self._pending_probes.pop(key, None)

        if not probe:
            # No matching active probe for this tuple; stray packet discarded
            return False

        original_isn, _ = probe

        # Strict RFC 793 correlation check
        if not tcp_hdr.correlates_with(local_src_port, original_isn):
            # Sequence/acknowledgment mismatch; stray packet discarded
            if self.verbose:
                expected_ack = (original_isn + 1) & 0xFFFFFFFF
                print(
                    f"[!] Discarded TCP response from {src_ip}:{target_port} "
                    f"— failed RFC 793 correlation (ack:{tcp_hdr.ack_num} != exp:{expected_ack})"
                )
            return False

        # Correlated response validated
        if tcp_hdr.is_syn_ack:
            self.registry.add_open_port(src_ip, target_port)
            self.registry.mark_responsive(src_ip, 0, 0)
            print(f"[+] Open port: {src_ip}:{target_port}")
            return True
        elif tcp_hdr.is_rst:
            if self.verbose:
                print(f"[*] Closed port: {src_ip}:{target_port}")
            return True

        return False

    def _scan_loop(self) -> None:
        hosts = list(self.target_subnet.hosts())
        ports = self.ports
        total = len(hosts) * len(ports)
        count = 0
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
                        seq = random.randint(0, 0xFFFFFFFF)

                        if not is_decoy:
                            self._record_probe(host_ip, port, src_port, seq)

                        pkt = PacketBuilder.build_tcp_syn(
                            src_ip, host_ip, src_port, port, seq=seq
                        )
                        try:
                            self._socket.sendto(pkt, (host_ip, 0))
                            key = 'decoy_packets_sent' if is_decoy else 'packets_sent'
                            self._stats[key] += 1
                        except Exception as e:
                            if self.verbose:
                                print(f"[!] SYN to {host_ip}:{port} failed: {e}")
                        time.sleep(random.uniform(0.005, 0.03))
                else:
                    src_port = random.randint(1024, 65535)
                    seq = random.randint(0, 0xFFFFFFFF)
                    self._record_probe(host_ip, port, src_port, seq)

                    pkt = PacketBuilder.build_tcp_syn(
                        self._local_ip, host_ip, src_port, port, seq=seq
                    )
                    try:
                        self._socket.sendto(pkt, (host_ip, 0))
                        self._stats['packets_sent'] += 1
                    except Exception as e:
                        if self.verbose:
                            print(f"[!] SYN to {host_ip}:{port} failed: {e}")

                self._stats['hosts_scanned'] = len(scanned_hosts)

                if count % 10 == 0 or count == total:
                    self._progress(count, total)

                # Inter-probe jitter delay
                if self.jitter and self._running:
                    delay = random.uniform(self.jitter[0], self.jitter[1])
                    elapsed = 0.0
                    while elapsed < delay and self._running:
                        chunk = min(0.1, delay - elapsed)
                        time.sleep(chunk)
                        elapsed += chunk
                else:
                    time.sleep(random.uniform(0.001, 0.01))

        sys.stdout.write('\n')
        print('[+] TCP SYN scan sweep complete')
        self._running = False

    def start(self) -> None:
        """Create raw socket and start scanning thread."""
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
        self._thread = threading.Thread(target=self._scan_loop, daemon=True, name='TCPSYNScanner')
        self._thread.start()

    def stop(self) -> None:
        """Stop scanner thread and clean up socket."""
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
