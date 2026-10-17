"""
GhostSniffer v2.1 — Hardened Modular Network Reconnaissance Engine.
Zero Dependencies | Raw Sockets | Stealth Ops | Protocol Mimicry
"""

__version__ = "2.1.0"
__author__ = "0xZiki"

from ghostsniffer.registry import HostRegistry
from ghostsniffer.network.packet_builder import PacketBuilder
from ghostsniffer.detection.os_fingerprint import OSFingerprinter
from ghostsniffer.detection.service_detect import ServiceDetector
from ghostsniffer.knock.listener import KnockListener
from ghostsniffer.scanners.tcp_syn import TCPSYNScanner
from ghostsniffer.scanners.udp_scanner import UDPScanner
from ghostsniffer.scanners.arp_scanner import ARPScanner


def main():
    """Main CLI entrypoint."""
    from ghostsniffer.cli import main as _main
    return _main()


def build_parser():
    """Build CLI argument parser."""
    from ghostsniffer.cli import build_parser as _build_parser
    return _build_parser()


__all__ = [
    '__version__',
    '__author__',
    'HostRegistry',
    'PacketBuilder',
    'OSFingerprinter',
    'ServiceDetector',
    'KnockListener',
    'TCPSYNScanner',
    'UDPScanner',
    'ARPScanner',
    'build_parser',
    'main',
]
