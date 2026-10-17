"""
Manual RFC 1071 Internet Checksum Calculation.
Handles one's complement addition for IPv4, UDP, and TCP pseudo-headers.
"""

import socket
import struct


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
