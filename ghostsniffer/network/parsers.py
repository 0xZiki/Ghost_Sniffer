"""
Binary Protocol Unpackers (Network Byte Order).
Parses IPv4, TCP, ICMP, and ARP packets with RFC state validation helpers.
"""

import ipaddress
import socket
import struct
from typing import Optional

from ghostsniffer.config import PROTO_MAP, ICMP_TYPE_MAP


class IP:
    """Parse a raw IPv4 header (supports options and DF flag extraction)."""

    def __init__(self, raw: bytes):
        if len(raw) < 20:
            raise ValueError("Truncated IP header (less than 20 bytes)")
        ver_ihl = raw[0]
        ihl = ver_ihl & 0xF
        header_len = ihl * 4
        if len(raw) < header_len:
            raise ValueError("Truncated IP header with options")

        fmt = f'!BBHHHBBH{4}s{4}s'
        unpacked = struct.unpack(fmt, raw[:20])
        self.ver = unpacked[0] >> 4
        self.ihl = ihl
        self.tos = unpacked[1]
        self.total_len = unpacked[2]
        self.ident = unpacked[3]
        self.flags_frag = unpacked[4]
        self.ttl = unpacked[5]
        self.proto_num = unpacked[6]
        self.checksum = unpacked[7]
        self.src_raw = unpacked[8]
        self.dst_raw = unpacked[9]

        # Flags & Fragment Offset
        self.df = bool(self.flags_frag & 0x4000)
        self.mf = bool(self.flags_frag & 0x2000)
        self.frag_offset = (self.flags_frag & 0x1FFF) * 8

        self.src_address = ipaddress.ip_address(self.src_raw)
        self.dst_address = ipaddress.ip_address(self.dst_raw)
        self.protocol = PROTO_MAP.get(self.proto_num, str(self.proto_num))
        self.header_len = header_len

    def __str__(self) -> str:
        df_str = " DF" if self.df else ""
        return (
            f"IP [{self.protocol}] {self.src_address} -> {self.dst_address} "
            f"(TTL:{self.ttl}{df_str} Len:{self.total_len})"
        )


class ICMP:
    """Parse a raw ICMP header (type, code, checksum)."""

    def __init__(self, raw: bytes):
        if len(raw) < 4:
            raise ValueError("Truncated ICMP header")
        header = struct.unpack('!BBH', raw[:4])
        self.type = header[0]
        self.code = header[1]
        self.checksum = header[2]
        self.type_str = ICMP_TYPE_MAP.get(self.type, f'Type-{self.type}')

    def __str__(self) -> str:
        return f"ICMP {self.type_str} (Type:{self.type} Code:{self.code})"


class TCP:
    """Parse a raw TCP header (20 bytes minimum) with RFC 793 correlation helpers."""

    def __init__(self, raw: bytes):
        if len(raw) < 20:
            raise ValueError("Truncated TCP header")
        fields = struct.unpack('!HHIIBBHHH', raw[:20])
        self.src_port = fields[0]
        self.dst_port = fields[1]
        self.seq = fields[2]
        self.ack_num = fields[3]
        self.data_offset = (fields[4] >> 4) * 4
        self.flags = fields[5]
        self.window = fields[6]
        self.checksum = fields[7]
        self.urg_ptr = fields[8]

        # Individual flags
        self.flag_fin = bool(self.flags & 0x01)
        self.flag_syn = bool(self.flags & 0x02)
        self.flag_rst = bool(self.flags & 0x04)
        self.flag_psh = bool(self.flags & 0x08)
        self.flag_ack = bool(self.flags & 0x10)
        self.flag_urg = bool(self.flags & 0x20)

    @property
    def dest_port(self) -> int:
        """Alias for dst_port."""
        return self.dst_port

    @property
    def is_syn_ack(self) -> bool:
        """Check if packet is a TCP SYN-ACK."""
        return self.flag_syn and self.flag_ack and not self.flag_rst

    @property
    def is_rst(self) -> bool:
        """Check if packet is a TCP RST."""
        return self.flag_rst

    def correlates_with(self, original_src_port: int, original_isn: int) -> bool:
        """Verify strict RFC 793 correlation.

        Checks:
        1. dest_port matches the ephemeral source port of the original probe.
        2. ack_num matches original_isn + 1 (with 32-bit modulo wrap).
        """
        expected_ack = (original_isn + 1) & 0xFFFFFFFF
        return self.dst_port == original_src_port and self.ack_num == expected_ack

    def __str__(self) -> str:
        flag_strs = []
        if self.flag_syn:
            flag_strs.append('SYN')
        if self.flag_ack:
            flag_strs.append('ACK')
        if self.flag_rst:
            flag_strs.append('RST')
        if self.flag_fin:
            flag_strs.append('FIN')
        if self.flag_psh:
            flag_strs.append('PSH')
        if self.flag_urg:
            flag_strs.append('URG')
        return (
            f"TCP {self.src_port} -> {self.dst_port} "
            f"[{','.join(flag_strs)}] Seq:{self.seq} Ack:{self.ack_num} Win:{self.window}"
        )


class ARP:
    """Parse a raw ARP packet (28 bytes)."""

    def __init__(self, raw: bytes):
        if len(raw) < 28:
            raise ValueError("Truncated ARP packet (less than 28 bytes)")
        fields = struct.unpack('!HHBBH6s4s6s4s', raw[:28])
        self.htype = fields[0]
        self.ptype = fields[1]
        self.hlen = fields[2]
        self.plen = fields[3]
        self.op = fields[4]  # 1 = Request, 2 = Reply
        self.sender_mac = fields[5]
        self.sender_ip_bytes = fields[6]
        self.target_mac = fields[7]
        self.target_ip_bytes = fields[8]

        self.sender_ip = socket.inet_ntoa(self.sender_ip_bytes)
        self.target_ip = socket.inet_ntoa(self.target_ip_bytes)
        self.sender_mac_str = ':'.join(f'{b:02x}' for b in self.sender_mac)
        self.target_mac_str = ':'.join(f'{b:02x}' for b in self.target_mac)

    @property
    def is_reply(self) -> bool:
        """Check if packet is an ARP reply."""
        return self.op == 2

    def __str__(self) -> str:
        op_str = 'Reply' if self.op == 2 else 'Request' if self.op == 1 else f'Op:{self.op}'
        return f"ARP {op_str}: {self.sender_ip} ({self.sender_mac_str}) -> {self.target_ip}"
