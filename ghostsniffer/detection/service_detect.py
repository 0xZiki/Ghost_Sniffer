"""
Application-Layer Service and Banner Detection.
Extracts banners and service signatures from identified open TCP ports.
"""

import socket
import ssl
from typing import Optional, Dict, Tuple, Any

from ghostsniffer.registry import HostRegistry


class ServiceDetector:
    """Connect to open ports and grab service banners / version strings."""

    # port -> (service_name, probe_bytes | None, wait_for_banner_first)
    PROBES: Dict[int, Tuple[str, Optional[bytes], bool]] = {
        21: ('FTP', b'', True),
        22: ('SSH', b'', True),
        23: ('Telnet', b'', True),
        25: ('SMTP', b'', True),
        80: ('HTTP', None, False),
        110: ('POP3', b'', True),
        143: ('IMAP', b'', True),
        443: ('HTTPS', None, False),
        445: ('SMB', b'', True),
        3306: ('MySQL', b'', True),
        3389: ('RDP', b'', True),
        5432: ('PostgreSQL', b'', True),
        6379: ('Redis', b'', True),
        8080: ('HTTP', None, False),
        8443: ('HTTPS', None, False),
        27017: ('MongoDB', b'', True),
    }

    def __init__(
        self,
        registry: HostRegistry,
        timeout: float = 5.0,
        verbose: bool = False,
    ) -> None:
        self.registry = registry
        self.timeout = timeout
        self.verbose = verbose

    def detect_all(self) -> None:
        """Run banner grabs for every open port across all discovered hosts."""
        hosts = self.registry.get_all()
        for ip, info in hosts.items():
            open_ports = info.get('open_ports', [])
            for port in open_ports:
                version = self._grab_banner(ip, port)
                if version:
                    self.registry.add_service(ip, port, version)
                    print(f"[+] Service: {ip}:{port} -> {version}")

    def _grab_banner(self, ip: str, port: int) -> Optional[str]:
        """Attempt a TCP connect and grab the service banner on ip:port."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            probe_info = self.PROBES.get(port, ('Unknown', b'', True))
            service_name, probe_data, wait_first = probe_info

            banner = b''

            # Services that send banner immediately on connection
            if wait_first:
                try:
                    banner = sock.recv(1024)
                except socket.timeout:
                    pass

            # HTTP(S) requires a client request
            if not wait_first:
                if port in (443, 8443):
                    try:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        sock = ctx.wrap_socket(sock, server_hostname=ip)
                    except Exception:
                        pass
                http_req = (
                    b'HEAD / HTTP/1.0\r\n'
                    b'Host: ' + ip.encode() + b'\r\n\r\n'
                )
                try:
                    sock.send(http_req)
                    banner = sock.recv(1024)
                except socket.timeout:
                    pass

            if banner:
                first_line = banner.split(b'\r\n')[0].split(b'\n')[0]
                decoded = first_line.decode('utf-8', errors='replace').strip()
                return decoded if decoded else service_name
            return service_name

        except Exception as e:
            if self.verbose:
                print(f"[*] Banner grab {ip}:{port} failed: {e}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
