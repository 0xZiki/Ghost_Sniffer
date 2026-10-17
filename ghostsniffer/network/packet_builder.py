"""
Raw Network Packet Builders.
Constructs IPv4, UDP, TCP SYN, DNS query, and ARP frames.
"""

import os
import random
import socket
import struct
from typing import Optional

from ghostsniffer.network.checksum import (
    inet_checksum,
    compute_udp_checksum,
    compute_tcp_checksum,
)


class PacketBuilder:
    """Construct raw network packets for scanning and discovery operations."""

    @staticmethod
    def build_dns_query(domain: str = "google.com") -> bytes:
        """Build a DNS query payload for protocol mimicry."""
        txn_id = struct.pack('!H', random.randint(0, 0xFFFF))
        flags = struct.pack('!H', 0x0100)  # Standard query with recursion desired
        counts = struct.pack('!HHHH', 1, 0, 0, 0)

        qname = b''
        for label in domain.split('.'):
            if label:
                qname += struct.pack('B', len(label)) + label.encode('ascii')
        qname += b'\x00'

        qtype_class = struct.pack('!HH', 1, 1)  # Type A, Class IN
        return txn_id + flags + counts + qname + qtype_class

    @staticmethod
    def build_normal_payload() -> bytes:
        """Build a pseudo-random payload of 32-128 bytes."""
        return os.urandom(random.randint(32, 128))

    @staticmethod
    def build_udp_header(
        src_port: int,
        dst_port: int,
        payload: bytes,
        src_ip: str,
        dst_ip: str,
    ) -> bytes:
        """Build a UDP header with RFC-compliant checksum."""
        length = 8 + len(payload)
        header_zero = struct.pack('!HHHH', src_port, dst_port, length, 0)
        csum = compute_udp_checksum(src_ip, dst_ip, header_zero + payload)
        if csum == 0:
            csum = 0xFFFF
        return struct.pack('!HHHH', src_port, dst_port, length, csum)

    @staticmethod
    def build_ip_header(
        src_ip: str,
        dst_ip: str,
        payload_len: int,
        proto: int = socket.IPPROTO_UDP,
        df: bool = False,
        ttl: Optional[int] = None,
        ident: Optional[int] = None,
    ) -> bytes:
        """Build an IPv4 header."""
        ver_ihl = 0x45  # IPv4, IHL = 5 (20 bytes)
        tos = 0
        total_len = 20 + payload_len
        pkt_ident = ident if ident is not None else random.randint(1, 0xFFFF)
        frag = 0x4000 if df else 0  # DF (Don't Fragment) bit
        pkt_ttl = ttl if ttl is not None else random.randint(60, 128)
        src = socket.inet_aton(src_ip)
        dst = socket.inet_aton(dst_ip)

        header = struct.pack(
            '!BBHHHBBH4s4s',
            ver_ihl, tos, total_len, pkt_ident,
            frag, pkt_ttl, proto, 0, src, dst
        )
        csum = inet_checksum(header)
        header = struct.pack(
            '!BBHHHBBH4s4s',
            ver_ihl, tos, total_len, pkt_ident,
            frag, pkt_ttl, proto, csum, src, dst
        )
        return header

    @staticmethod
    def build_full_packet(
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        payload: bytes,
    ) -> bytes:
        """Build a complete IP + UDP packet."""
        udp_hdr = PacketBuilder.build_udp_header(
            src_port, dst_port, payload, src_ip, dst_ip
        )
        udp_segment = udp_hdr + payload
        ip_hdr = PacketBuilder.build_ip_header(
            src_ip, dst_ip, len(udp_segment), proto=socket.IPPROTO_UDP
        )
        return ip_hdr + udp_segment

    @staticmethod
    def build_tcp_syn(
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        seq: Optional[int] = None,
        window: int = 65535,
    ) -> bytes:
        """Build a TCP SYN packet (IP + TCP header, no payload).

        Half-open probe: SYN flag set, ACK=0, data-offset=5 (20 bytes, no options).
        """
        if seq is None:
            seq = random.randint(0, 0xFFFFFFFF)

        data_offset_reserved = 0x50  # data offset = 5 words (20 bytes)
        flags = 0x02                 # SYN
        urg_ptr = 0

        # TCP header with zero checksum
        tcp_header = struct.pack(
            '!HHIIBBHHH',
            src_port, dst_port,
            seq, 0,
            data_offset_reserved, flags,
            window, 0, urg_ptr
        )

        csum = compute_tcp_checksum(src_ip, dst_ip, tcp_header)
        tcp_header = struct.pack(
            '!HHIIBBHHH',
            src_port, dst_port,
            seq, 0,
            data_offset_reserved, flags,
            window, csum, urg_ptr
        )

        # IP header with DF bit set (standard for TCP SYN)
        ip_header = PacketBuilder.build_ip_header(
            src_ip, dst_ip, len(tcp_header), proto=socket.IPPROTO_TCP, df=True
        )

        return ip_header + tcp_header

    @staticmethod
    def build_arp_request(
        target_ip: str,
        local_mac: bytes,
        local_ip: str,
    ) -> bytes:
        """Build an ARP Request frame (Ethernet + ARP)."""
        eth_dst = b'\xff\xff\xff\xff\xff\xff'
        eth_type = struct.pack('!H', 0x0806)
        eth_header = eth_dst + local_mac + eth_type

        arp_header = struct.pack(
            '!HHBBH',
            1,       # hardware type: Ethernet
            0x0800,  # protocol type: IPv4
            6,       # hardware addr len
            4,       # protocol addr len
            1        # operation: request
        )
        sender_mac = local_mac
        sender_ip = socket.inet_aton(local_ip)
        target_mac = b'\x00\x00\x00\x00\x00\x00'
        target_ip_b = socket.inet_aton(target_ip)

        arp_payload = sender_mac + sender_ip + target_mac + target_ip_b
        return eth_header + arp_header + arp_payload
