"""
GhostSniffer CLI Orchestration Engine.
Handles argument parsing, sniffer loop dispatching, scan coordination, and telemetry reporting.
"""

import argparse
import ipaddress
import json
import os
import random
import socket
import struct
import sys
import threading
import time
from datetime import datetime
from typing import Optional, List, Dict, Any

from ghostsniffer.config import (
    load_dotenv,
    DEFAULT_PORT,
    DEFAULT_REPORT_INTERVAL,
    DEFAULT_STEALTH_DOMAIN,
    DEFAULT_SERVICE_TIMEOUT,
    DEFAULT_KNOCK_TIMEOUT,
)
from ghostsniffer.detection.os_fingerprint import OSFingerprinter
from ghostsniffer.detection.service_detect import ServiceDetector
from ghostsniffer.knock.listener import KnockListener
from ghostsniffer.network.parsers import IP, TCP, ICMP, ARP
from ghostsniffer.registry import HostRegistry
from ghostsniffer.scanners.arp_scanner import ARPScanner
from ghostsniffer.scanners.tcp_syn import TCPSYNScanner
from ghostsniffer.scanners.udp_scanner import UDPScanner


# ============================================================================
#  Sniffer Engine
# ============================================================================

class SnifferEngine:
    """Raw-socket packet capture listener and event dispatcher."""

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

    def __init__(
        self,
        registry: HostRegistry,
        subnet_filter: Optional[Any] = None,
        verbose: bool = False,
        scan_mode: bool = False,
        knock_listener: Optional[KnockListener] = None,
        tcp_scanner: Optional[TCPSYNScanner] = None,
        udp_scanner: Optional[UDPScanner] = None,
        arp_scanner: Optional[ARPScanner] = None,
    ) -> None:
        self.registry = registry
        self.subnet_filter = subnet_filter
        self.verbose = verbose
        self.scan_mode = scan_mode
        self.knock_listener = knock_listener
        self.tcp_scanner = tcp_scanner
        self.udp_scanner = udp_scanner
        self.arp_scanner = arp_scanner

        self._running = False
        self._socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stats: Dict[str, int] = {'packets_captured': 0, 'icmp_responses': 0}
        self.packet_offset = 0
        self.is_af_packet = False
        self._local_ip = self._detect_local_ip()

    def _handle_arp_raw(self, raw_arp: bytes) -> None:
        """Handle raw ARP bytes from AF_PACKET."""
        try:
            arp_pkt = ARP(raw_arp)
        except Exception:
            return

        if self.arp_scanner:
            self.arp_scanner.handle_arp_packet(arp_pkt)
        else:
            if not arp_pkt.is_reply:
                return
            sender_ip = arp_pkt.sender_ip
            should_reg = True
            if self.subnet_filter:
                try:
                    should_reg = ipaddress.ip_address(sender_ip) in self.subnet_filter
                except ValueError:
                    should_reg = False
            if should_reg:
                is_new = self.registry.register(sender_ip, 'ARP')
                self.registry.mark_responsive(sender_ip, 0, 0)
                if is_new:
                    print(f"[+] Host Up: {sender_ip} (ARP Reply: {arp_pkt.sender_mac_str})")

    def start(self) -> None:
        """Initialize the raw socket and launch capture thread."""
        if os.name == 'nt':
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((self._local_ip, 0))
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            except OSError:
                if self.verbose:
                    print("[!] IP_HDRINCL not supported; capture may be limited")
            try:
                sock.ioctl(socket.SIIO_RCVALL, socket.RCVALL_ON)
            except Exception:
                if self.verbose:
                    print("[!] RCVALL not supported; capture may be limited")
            self.packet_offset = 0
            self.is_af_packet = False
        else:
            try:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
                self.packet_offset = 14
                self.is_af_packet = True
                if self.verbose:
                    print("[*] Using AF_PACKET for full packet capture")
            except (AttributeError, PermissionError) as e:
                if self.verbose:
                    print(f"[!] AF_PACKET failed ({e}), falling back to ICMP-only")
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    sock.bind((self._local_ip, 0))
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                except PermissionError:
                    raise PermissionError("Need root privileges for raw socket")
                self.packet_offset = 0
                self.is_af_packet = False

        self._socket = sock
        self._socket.settimeout(1.0)
        self._running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True, name='SnifferEngine')
        self._thread.start()
        print("[+] Sniffer engine started")

    def _sniff_loop(self) -> None:
        """Main packet capture and dispatch loop."""
        while self._running:
            try:
                if self.is_af_packet:
                    raw_buffer, _ = self._socket.recvfrom(65565)
                    if len(raw_buffer) < 14:
                        continue
                    eth_proto = struct.unpack('!H', raw_buffer[12:14])[0]
                    if eth_proto == 0x0806:  # ARP
                        self._handle_arp_raw(raw_buffer[14:])
                        continue
                    elif eth_proto != 0x0800:  # Not IPv4
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
            tcp_hdr: Optional[TCP] = None

            # Parse TCP header if present (for fingerprinting & SYN correlation)
            if ip_hdr.protocol == 'TCP':
                offset = ip_hdr.header_len
                if len(raw_buffer) >= offset + 20:
                    try:
                        tcp_hdr = TCP(raw_buffer[offset:offset + 20])
                    except Exception:
                        tcp_hdr = None

            # Passive OS Fingerprinting (Protocol Fix 3)
            os_guess = OSFingerprinter.fingerprint(ip_hdr, tcp_hdr)

            # Host registration
            should_register = True
            if self.subnet_filter:
                try:
                    should_register = ip_hdr.src_address in self.subnet_filter
                except ValueError:
                    should_register = False

            if should_register:
                is_new = self.registry.register(src_ip, ip_hdr.protocol)
                self.registry.update_os(src_ip, os_guess, ip_hdr.ttl)
                if is_new and not self.scan_mode:
                    print(f"[+] New host: {src_ip} [{ip_hdr.protocol}] ({os_guess})")

            # ---- ICMP Handling (Scan Mode) ----
            if self.scan_mode and ip_hdr.protocol == 'ICMP':
                offset = ip_hdr.header_len
                if len(raw_buffer) >= offset + 4:
                    try:
                        icmp_hdr = ICMP(raw_buffer[offset:offset + 4])
                    except Exception:
                        continue

                    if self.verbose:
                        print(f"[*] {ip_hdr} | {icmp_hdr}")

                    if self.udp_scanner:
                        if self.udp_scanner.handle_icmp_packet(ip_hdr, icmp_hdr):
                            self._stats['icmp_responses'] += 1
                    else:
                        if icmp_hdr.type == 3 and icmp_hdr.code == 3:
                            if self.registry.was_scanned_recently(src_ip):
                                self._stats['icmp_responses'] += 1
                                self.registry.mark_responsive(src_ip, icmp_hdr.type, icmp_hdr.code)
                                print(f"[+] Host Up: {src_ip} (ICMP Port Unreachable)")

            # ---- TCP SYN Response Correlation (Protocol Fix 1) ----
            if self.scan_mode and ip_hdr.protocol == 'TCP' and tcp_hdr:
                if self.tcp_scanner:
                    self.tcp_scanner.handle_tcp_packet(ip_hdr, tcp_hdr)
                else:
                    # Legacy fallback
                    if self.registry.was_scanned_recently(src_ip):
                        if tcp_hdr.is_syn_ack:
                            self.registry.add_open_port(src_ip, tcp_hdr.src_port)
                            self.registry.mark_responsive(src_ip, 0, 0)
                            print(f"[+] Open port: {src_ip}:{tcp_hdr.src_port}")
                        elif tcp_hdr.is_rst and self.verbose:
                            print(f"[*] Closed port: {src_ip}:{tcp_hdr.src_port}")

            # ---- Secure Port Knocking (Protocol Fix 2) ----
            if self.knock_listener:
                if ip_hdr.protocol == 'UDP':
                    offset = ip_hdr.header_len
                    if len(raw_buffer) >= offset + 8:
                        dst_port = struct.unpack('!H', raw_buffer[offset + 2:offset + 4])[0]
                        udp_payload = raw_buffer[offset + 8:]
                        if self.knock_listener.check_packet(src_ip, 'UDP', dst_port, udp_payload):
                            print(f"[+] Knock sequence completed by {src_ip}! Executing action...")
                            self.knock_listener.execute_action(src_ip)

                elif ip_hdr.protocol == 'ICMP':
                    offset = ip_hdr.header_len
                    if len(raw_buffer) >= offset + 4:
                        icmp_type = raw_buffer[offset]
                        icmp_payload = raw_buffer[offset + 4:]
                        if self.knock_listener.check_packet(src_ip, 'ICMP', icmp_type, icmp_payload):
                            print(f"[+] Knock sequence completed by {src_ip}! Executing action...")
                            self.knock_listener.execute_action(src_ip)

            # Verbose packet dump for passive mode
            if self.verbose and not self.scan_mode and not self.knock_listener:
                print(f"[*] {ip_hdr}")

    def stop(self) -> None:
        """Stop packet capture thread and close socket."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        if self._socket:
            if os.name == 'nt':
                try:
                    self._socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except Exception:
                    pass
            try:
                self._socket.close()
            except Exception:
                pass
        print("[+] Sniffer engine stopped")

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)


# ============================================================================
#  GhostSniffer Main Orchestrator
# ============================================================================

class GhostSniffer:
    """Top-level controller wiring Sniffer + Scanners + HostRegistry."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.registry = HostRegistry()
        self.sniffer: Optional[SnifferEngine] = None
        self.scanner: Optional[Any] = None

    def run(self) -> None:
        print("GhostSniffer v2.0 - Advanced Network Recon")
        self._print_config()

        if self.args.mode == 'passive':
            self._run_passive()
        elif self.args.mode == 'listen':
            self._run_listen()
        else:
            self._run_scan()

    def _print_config(self) -> None:
        print(f"  {'-' * 50}")
        print(f"  Mode:    {self.args.mode.upper()}")
        print(f"  Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  OS:      {os.name}")
        print(f"  {'-' * 50}")
        print()

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
            self.registry,
            subnet_filter=subnet,
            verbose=self.args.verbose,
            scan_mode=False,
        )
        self.sniffer.start()

        stop_event = threading.Event()

        def _reporter():
            while not stop_event.is_set():
                stop_event.wait(timeout=self.args.report_interval)
                if not stop_event.is_set():
                    self._print_passive_report()

        report_thread = threading.Thread(target=_reporter, daemon=True, name='Reporter')
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

    def _run_scan(self) -> None:
        if not self.args.target:
            print("[!] --target is required in scan mode")
            sys.exit(1)

        print("[+] Active Scan Mode — Engaging target network")
        print()

        jitter = (self.args.jitter[0], self.args.jitter[1]) if self.args.jitter else None
        decoys = [d.strip() for d in self.args.decoys.split(',')] if self.args.decoys else None
        target_net = ipaddress.ip_network(self.args.target, strict=False)
        scan_type = getattr(self.args, 'scan_type', 'udp')
        ports = getattr(self.args, 'ports', None)

        tcp_scanner = None
        udp_scanner = None
        arp_scanner = None

        if scan_type == 'tcp_syn':
            tcp_scanner = TCPSYNScanner(
                registry=self.registry,
                target_subnet=self.args.target,
                ports=ports,
                jitter=jitter,
                decoys=decoys,
                verbose=self.args.verbose,
            )
            self.scanner = tcp_scanner
        elif scan_type == 'arp':
            arp_scanner = ARPScanner(
                registry=self.registry,
                target_subnet=self.args.target,
                verbose=self.args.verbose,
            )
            self.scanner = arp_scanner
        else:
            udp_scanner = UDPScanner(
                registry=self.registry,
                target_subnet=self.args.target,
                port=self.args.port,
                mimicry=self.args.mimicry,
                dns_domain=self.args.dns_domain,
                jitter=jitter,
                decoys=decoys,
                verbose=self.args.verbose,
            )
            self.scanner = udp_scanner

        # Start sniffer first
        self.sniffer = SnifferEngine(
            self.registry,
            subnet_filter=target_net,
            verbose=self.args.verbose,
            scan_mode=True,
            tcp_scanner=tcp_scanner,
            udp_scanner=udp_scanner,
            arp_scanner=arp_scanner,
        )
        self.sniffer.start()

        # Print scan header
        host_count = sum(1 for _ in target_net.hosts())
        print(f"[>] Target: {target_net} ({host_count} hosts)")
        print(f"[>] Scan Type: {scan_type}")
        if scan_type == 'tcp_syn':
            port_list = ports if ports else list(range(1, 1025))
            print(f"[>] Ports: {len(port_list)} ports")
        elif scan_type == 'udp':
            print(f"[>] Port: {self.args.port}")
            print(f"[>] Mimicry: {self.args.mimicry}" + (f' (domain: {self.args.dns_domain})' if self.args.mimicry == 'dns' else ''))
        if jitter:
            print(f"[>] Jitter: {jitter[0]}s - {jitter[1]}s")
        if decoys:
            print(f"[>] Decoys: {', '.join(decoys)}")
        print()

        # Start active scanner
        self.scanner.start()

        try:
            while self.scanner.is_running:
                time.sleep(0.5)
            print("[*] Waiting 3s for late responses...")
            time.sleep(3)

            # Service Version Detection
            if getattr(self.args, 'service_detection', False) and scan_type == 'tcp_syn':
                print("[*] Starting service version detection...")
                detector = ServiceDetector(
                    self.registry,
                    timeout=getattr(self.args, 'service_timeout', DEFAULT_SERVICE_TIMEOUT),
                    verbose=self.args.verbose,
                )
                detector.detect_all()
                print("[+] Service detection complete")

        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
        finally:
            if self.scanner:
                self.scanner.stop()
            if self.sniffer:
                self.sniffer.stop()
            print()
            self._print_final_report()
            self._export_results()

    def _run_listen(self) -> None:
        knock_seq = self.args.knock_seq
        action = self.args.action

        if not knock_seq:
            print("[!] --knock-seq is required in listen mode")
            sys.exit(1)
        if not action:
            print("[!] --action is required in listen mode")
            sys.exit(1)

        sequence = [int(p.strip()) for p in knock_seq.split(',')]
        protocol = getattr(self.args, 'knock_proto', 'udp') or 'udp'
        timeout = getattr(self.args, 'knock_timeout', DEFAULT_KNOCK_TIMEOUT) or DEFAULT_KNOCK_TIMEOUT
        secret = getattr(self.args, 'knock_secret', None)

        knock = KnockListener(
            sequence=sequence,
            protocol=protocol,
            timeout=timeout,
            action=action,
            secret=secret,
        )

        print("[+] Secure Port Knocking Listener Active")
        print(f"[*] Sequence: {sequence}")
        print(f"[*] Protocol: {protocol}")
        print(f"[*] Timeout:  {timeout}s")
        if secret:
            print("[*] Payload Auth: HMAC / Token verification enabled")
        print(f"[*] Action:   {action}")
        print()

        subnet = ipaddress.ip_network(self.args.subnet, strict=False) if self.args.subnet else None

        self.sniffer = SnifferEngine(
            self.registry,
            subnet_filter=subnet,
            verbose=self.args.verbose,
            scan_mode=False,
            knock_listener=knock,
        )
        self.sniffer.start()

        try:
            print("[!] Press Ctrl+C to stop\n")
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            if self.sniffer:
                self.sniffer.stop()
            print("\n[+] Listener stopped")

    def _print_passive_report(self) -> None:
        count = self.registry.count()
        stats = self.sniffer.stats if self.sniffer else {}

        print(f"\n  {'=' * 48}")
        print(f"    PERIODIC REPORT  {datetime.now().strftime('%H:%M:%S')}")
        print(f"  {'=' * 48}")
        print(f"  Hosts discovered:  {count}")
        print(f"  Packets captured:  {stats.get('packets_captured', 0)}")

        hosts = self.registry.get_all()
        if hosts:
            recent = sorted(hosts.values(), key=lambda h: h['last_seen'], reverse=True)
            print("  Last 5 seen:")
            for h in recent[:5]:
                protos = ', '.join(h['protocols'])
                os_g = h.get('os_guess', '')
                os_str = f" ({os_g})" if os_g else ""
                print(f"    * {h['ip']:<16} [{protos}] pkts:{h['packet_count']}{os_str}")
        print(f"  {'=' * 48}\n")

    def _print_final_report(self) -> None:
        hosts = self.registry.get_all()
        responsive = self.registry.get_responsive()
        s_stats = self.sniffer.stats if self.sniffer else {}
        c_stats = self.scanner.stats if self.scanner else {}

        width = 80
        print(f"\n{'=' * width}")
        print("  GHOSTSNIFFER — FINAL REPORT")
        print(f"{'=' * width}")

        print(f"\n  Statistics:")
        print(f"  {'-' * 42}")
        print(f"  Packets Captured:     {s_stats.get('packets_captured', 0)}")
        if c_stats:
            print(f"  Packets Sent:         {c_stats.get('packets_sent', 0)}")
            print(f"  Decoy Packets Sent:   {c_stats.get('decoy_packets_sent', 0)}")
            print(f"  Hosts Scanned:        {c_stats.get('hosts_scanned', 0)}")
            print(f"  ICMP Responses:       {s_stats.get('icmp_responses', 0)}")
        print(f"  Unique Hosts Found:   {len(hosts)}")
        if responsive:
            print(f"  Hosts Confirmed Up:   {len(responsive)}")

        if hosts:
            print(f"\n  Discovered Hosts:")
            print(f"  {'-' * (width - 4)}")
            print(f"  {'IP Address':<18} {'Status':<10} {'Protocols':<12} {'OS Guess':<20} {'Open Ports'}")
            print(f"  {'-' * (width - 4)}")

            sorted_hosts = sorted(hosts.values(), key=lambda h: ipaddress.ip_address(h['ip']))

            for h in sorted_hosts:
                st = h.get('status', 'discovered')
                pr = ', '.join(h['protocols'])
                os_g = h.get('os_guess', '-') or '-'

                open_ports = h.get('open_ports', [])
                services = h.get('services', {})
                if open_ports:
                    parts = []
                    for p in sorted(open_ports):
                        svc = services.get(p, services.get(str(p), ''))
                        if svc:
                            short = svc[:25] + '...' if len(svc) > 25 else svc
                            parts.append(f"{p}({short})")
                        else:
                            parts.append(str(p))
                    ports_str = ', '.join(parts)
                else:
                    ports_str = '-'

                print(f"  {h['ip']:<18} {st:<10} {pr:<12} {os_g:<20} {ports_str}")

            print(f"  {'-' * (width - 4)}")
        else:
            print("\n  No hosts discovered.")

        print(f"\n{'=' * width}")
        print(f"[+] Completed at {datetime.now().strftime('%H:%M:%S')}\n")

    def _export_results(self) -> None:
        if not self.args.output:
            return

        hosts = self.registry.get_all()
        s_stats = self.sniffer.stats if self.sniffer else {}
        c_stats = self.scanner.stats if self.scanner else {}

        report = {
            'tool': 'GhostSniffer v2.0 (Hardened Modular Engine)',
            'timestamp': datetime.now().isoformat(),
            'mode': self.args.mode,
            'config': {
                'target': getattr(self.args, 'target', None),
                'scan_type': getattr(self.args, 'scan_type', 'udp'),
                'port': getattr(self.args, 'port', None),
                'ports': getattr(self.args, 'ports', None),
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
            print(f"[+] Results exported to: {self.args.output}")
        except Exception as exc:
            print(f"[!] Export failed: {exc}")


# ============================================================================
#  CLI Parser & Helpers
# ============================================================================

def parse_ports(port_str: str) -> List[int]:
    """Parse port specification string into a sorted list of integers."""
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
                raise argparse.ArgumentTypeError(f"Invalid port range: {part}")
        else:
            try:
                p = int(part)
                if not 1 <= p <= 65535:
                    raise argparse.ArgumentTypeError(f"Port out of range: {p}")
                ports.add(p)
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid port number: {part}")
    return sorted(ports)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='ghost_sniffer',
        description='GhostSniffer v2.0 — Hardened Modular Network Reconnaissance Engine',
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

  # Secure Port knocking listener
  ghost_sniffer --mode listen --knock-seq 1000,2000,3000 \\
    --knock-proto udp --action "echo Knock completed"

  # Scan with custom jitter and JSON output
  ghost_sniffer --target 192.168.1.0/24 \\
    --jitter 0.5 2.0 --output results.json

  # Verbose scan for debugging
  ghost_sniffer --target 192.168.1.0/24 -v
""",
    )

    # ---- Mode ----
    p.add_argument(
        '--mode', choices=['scan', 'passive', 'listen'], default='scan',
        help='Operation mode (default: scan)',
    )

    # ---- Targeting ----
    p.add_argument(
        '--target', '-t', type=str, default=None,
        help='Target subnet for scan (e.g. 192.168.1.0/24)',
    )
    p.add_argument(
        '--subnet', type=str, default=None,
        help='Subnet filter for passive/listen mode',
    )

    # ---- Scan type ----
    p.add_argument(
        '--scan-type', choices=['udp', 'tcp_syn', 'arp'], default='udp',
        help='Scan type: udp, tcp_syn, or arp (default: udp)',
    )
    p.add_argument(
        '--ports', '-p', type=str, default=None,
        help='Target ports for TCP SYN scan (e.g. 22,80,443 or 1-1024)',
    )
    p.add_argument(
        '--port', type=int,
        default=int(os.environ.get('DEFAULT_PORT', DEFAULT_PORT)),
        help=f'Destination port for UDP scan (default: {DEFAULT_PORT})',
    )

    # ---- Mimicry / Stealth ----
    p.add_argument(
        '--mimicry', choices=['normal', 'dns'], default='normal',
        help='Payload disguise: normal or dns (default: normal)',
    )
    p.add_argument(
        '--dns-domain', type=str,
        default=os.environ.get('STEALTH_DOMAIN', DEFAULT_STEALTH_DOMAIN),
        help=f'Domain for dns mimicry (default: {DEFAULT_STEALTH_DOMAIN})',
    )
    p.add_argument(
        '--jitter', nargs=2, type=float, metavar=('MIN', 'MAX'),
        help='Random delay range in seconds (e.g. 0.5 2.0)',
    )
    p.add_argument(
        '--decoys', type=str, default=None,
        help='Comma-separated decoy IPs (e.g. 10.0.0.1,10.0.0.254)',
    )
    p.add_argument(
        '--stealth', action='store_true',
        help='Shortcut: enable dns mimicry + jitter 0.5-2.0',
    )

    # ---- Service Detection ----
    p.add_argument(
        '--service-detection', '-sV', action='store_true',
        help='Detect service versions on open ports (requires --scan-type tcp_syn)',
    )
    p.add_argument(
        '--service-timeout', type=float, default=DEFAULT_SERVICE_TIMEOUT,
        help=f'Timeout per service probe in seconds (default: {DEFAULT_SERVICE_TIMEOUT})',
    )

    # ---- Port Knocking ----
    p.add_argument(
        '--knock-seq', type=str, default=None,
        help='Port knock sequence (e.g. 1000,2000,3000)',
    )
    p.add_argument(
        '--knock-proto', choices=['udp', 'icmp'], default='udp',
        help='Protocol for port knocking (default: udp)',
    )
    p.add_argument(
        '--knock-timeout', type=float, default=DEFAULT_KNOCK_TIMEOUT,
        help=f'Timeout between knocks in seconds (default: {DEFAULT_KNOCK_TIMEOUT})',
    )
    p.add_argument(
        '--knock-secret', type=str, default=None,
        help='Secret key or token for HMAC/token payload verification',
    )
    p.add_argument(
        '--action', type=str, default=None,
        help='Command to execute when knock sequence completes',
    )

    # ---- Output ----
    p.add_argument(
        '--output', '-o', type=str, default=None,
        help='Export results to JSON file',
    )
    p.add_argument(
        '--report-interval', type=int,
        default=int(os.environ.get('REPORT_INTERVAL', DEFAULT_REPORT_INTERVAL)),
        help=f'Seconds between passive reports (default: {DEFAULT_REPORT_INTERVAL})',
    )
    p.add_argument(
        '--verbose', '-v', action='store_true',
        help='Show every captured packet',
    )

    return p


def main() -> None:
    # 1. Load .env first
    load_dotenv()

    # 2. Parse arguments FIRST so --help works without privileges
    parser = build_parser()
    args = parser.parse_args()

    # 3. Check privileges (after argparse so --help always works)
    if os.name == 'nt':
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                print("[!] This tool requires Administrator privileges on Windows.")
                print("[*] Please run as Administrator (right-click -> Run as administrator).")
                sys.exit(1)
        except Exception:
            print("[!] Could not verify admin privileges. Raw sockets may fail.")
    else:
        if os.geteuid() != 0:
            print("[!] This tool requires root privileges on Linux.")
            print("[*] Please run with sudo: sudo ghost_sniffer ...")
            sys.exit(1)

    # 4. Parse port list for TCP SYN scan
    if args.ports:
        args.ports = parse_ports(args.ports)
    elif args.scan_type == 'tcp_syn' and not args.ports:
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
