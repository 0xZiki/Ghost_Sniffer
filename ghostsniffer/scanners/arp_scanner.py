"""
Layer-2 ARP Host Discovery Scanner (Linux AF_PACKET).
Discovers local network endpoints at the data-link layer.
"""

import ipaddress
import os
import random
import socket
import sys
import threading
import time
from typing import Optional, Dict

from ghostsniffer.network.packet_builder import PacketBuilder
from ghostsniffer.network.parsers import ARP
from ghostsniffer.registry import HostRegistry


class ARPScanner:
    """Layer-2 ARP scanner utilizing AF_PACKET raw sockets."""

    def __init__(
        self,
        registry: HostRegistry,
        target_subnet: str,
        verbose: bool = False,
    ) -> None:
        self.registry = registry
        self.target_subnet = ipaddress.ip_network(target_subnet, strict=False)
        self.verbose = verbose

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._socket: Optional[socket.socket] = None
        self._stats: Dict[str, int] = {
            'packets_sent': 0,
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
    def _get_local_interface() -> str:
        """Return the primary network interface name (Linux only)."""
        try:
            with open('/proc/net/route', 'r', encoding='utf-8') as f:
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
                iface = ARPScanner._get_local_interface()
                path = f'/sys/class/net/{iface}/address'
                if os.path.exists(path):
                    with open(path, 'r', encoding='utf-8') as f:
                        mac_str = f.read().strip()
                        return bytes.fromhex(mac_str.replace(':', ''))
        except Exception:
            pass
        import uuid
        mac = uuid.getnode()
        return bytes([(mac >> (8 * (5 - i))) & 0xFF for i in range(6)])

    @staticmethod
    def _progress(current: int, total: int) -> None:
        if total == 0:
            return
        pct = int(current / total * 100)
        filled = int(30 * current / total)
        bar = '\u2588' * filled + '\u2591' * (30 - filled)
        sys.stdout.write(f"\r  [{bar}] {pct}% ({current}/{total})")
        sys.stdout.flush()

    def handle_arp_packet(self, arp_pkt: ARP) -> bool:
        """Process an incoming ARP reply and register host."""
        if not arp_pkt.is_reply:
            return False

        sender_ip = arp_pkt.sender_ip
        try:
            if ipaddress.ip_address(sender_ip) not in self.target_subnet:
                return False
        except ValueError:
            return False

        is_new = self.registry.register(sender_ip, 'ARP')
        self.registry.mark_responsive(sender_ip, 0, 0)
        if is_new:
            print(f"[+] Host Up: {sender_ip} (ARP Reply: {arp_pkt.sender_mac_str})")
        return True

    def _scan_loop(self) -> None:
        if os.name == 'nt':
            print("[!] ARP scan is not supported on Windows")
            self._running = False
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
                host_ip, local_mac, self._local_ip
            )
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

        sys.stdout.write('\n')
        print('[+] ARP scan sweep complete')
        self._running = False

    def start(self) -> None:
        """Create AF_PACKET raw socket and start scan thread."""
        if os.name == 'nt':
            print("[!] ARP scan is not supported on Windows")
            return

        try:
            interface = self._get_local_interface()
            sock = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(0x0003),
            )
            sock.bind((interface, 0))
            self._socket = sock
            self._running = True
            self._thread = threading.Thread(target=self._scan_loop, daemon=True, name='ARPScanner')
            self._thread.start()
        except (AttributeError, PermissionError, OSError) as e:
            print(f"[!] Cannot create ARP socket: {e}")
            print("[*] ARP scan requires root privileges and AF_PACKET support")

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
