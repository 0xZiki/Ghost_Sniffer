"""
GhostSniffer Host Registry.
Thread-safe centralized storage for discovered hosts, scan states, and network telemetry.
"""

import threading
import time
from datetime import datetime
from typing import Dict, Set, Any


class HostRegistry:
    """Central, thread-safe store for all discovered hosts and scan data."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hosts: Dict[str, Dict[str, Any]] = {}
        self._responsive: Set[str] = set()
        self._last_scan: Dict[str, float] = {}  # ip -> timestamp

    # -- Registration --------------------------------------------------------

    def register(self, ip: str, protocol: str) -> bool:
        """Register a host. Returns True if the host is newly discovered."""
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

    def mark_responsive(self, ip: str, icmp_type: int = 0, icmp_code: int = 0) -> None:
        """Flag a host as confirmed up (e.g. via ICMP/ARP/TCP)."""
        now = datetime.now().isoformat()
        with self._lock:
            self._responsive.add(ip)
            if ip in self._hosts:
                self._hosts[ip]['status'] = 'up'
                if icmp_type or icmp_code:
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
                    'open_ports': set(),
                    'os_guess': '',
                    'ttl': 0,
                    'services': {},
                }

    # -- Scan Tracking -------------------------------------------------------

    def mark_scanned(self, ip: str) -> None:
        """Record that we just scanned this IP."""
        with self._lock:
            self._last_scan[ip] = time.time()

    def was_scanned_recently(self, ip: str, seconds: float = 15.0) -> bool:
        """Check if this IP was scanned within the last *seconds*."""
        with self._lock:
            ts = self._last_scan.get(ip, 0.0)
            return (time.time() - ts) <= seconds

    # -- Feature-Specific Setters -------------------------------------------

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

    def get_all(self) -> Dict[str, Dict[str, Any]]:
        """Return a deep copy of all hosts (sets converted to sorted lists)."""
        with self._lock:
            out = {}
            for ip, info in self._hosts.items():
                copy = dict(info)
                copy['protocols'] = sorted(info['protocols'])
                copy['open_ports'] = sorted(info.get('open_ports', set()))
                copy['services'] = dict(info.get('services', {}))
                out[ip] = copy
            return out

    def get_responsive(self) -> Set[str]:
        """Return a copy of the responsive hosts set."""
        with self._lock:
            return set(self._responsive)

    def count(self) -> int:
        """Return the count of discovered hosts."""
        with self._lock:
            return len(self._hosts)

    def responsive_count(self) -> int:
        """Return the count of confirmed up hosts."""
        with self._lock:
            return len(self._responsive)
