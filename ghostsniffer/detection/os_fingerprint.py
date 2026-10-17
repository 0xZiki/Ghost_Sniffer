"""
Advanced Passive OS Fingerprinting Engine.
Combines Initial TTL Heuristics (Hop Decay), TCP Window Size Patterns, and IP DF Flags.
"""

from typing import Optional, Tuple
from ghostsniffer.network.parsers import IP, TCP


class OSFingerprinter:
    """Multi-feature passive OS fingerprint classifier."""

    @staticmethod
    def estimate_initial_ttl(observed_ttl: int) -> Tuple[int, int]:
        """Estimate the initial TTL and network hop count.

        Returns (initial_ttl, estimated_hops).
        Standard initial TTLs:
        - 64:  Linux, macOS, iOS, Android, modern BSDs
        - 128: Windows (XP, 7, 8, 10, 11, Server 2003-2022)
        - 255: Cisco IOS, Solaris, network appliances
        - 32:  Legacy Windows 95/98/NT or specialized embedded stacks
        """
        if observed_ttl <= 0:
            return (64, 0)

        if observed_ttl <= 32:
            return (32, 32 - observed_ttl)
        elif observed_ttl <= 64:
            return (64, 64 - observed_ttl)
        elif observed_ttl <= 128:
            return (128, 128 - observed_ttl)
        else:
            return (255, 255 - observed_ttl)

    @classmethod
    def fingerprint(cls, ip_hdr: IP, tcp_hdr: Optional[TCP] = None) -> str:
        """Evaluate packet primitives to determine the operating system.

        Correlates:
        - Initial TTL heuristic & hop decay.
        - TCP Window size signatures (e.g. Linux 64240 vs Windows 65535/8192).
        - IPv4 Don't Fragment (DF) flag.
        """
        initial_ttl, hops = cls.estimate_initial_ttl(ip_hdr.ttl)
        df_flag = getattr(ip_hdr, 'df', False)

        if tcp_hdr is not None:
            win = tcp_hdr.window

            # ---- Initial TTL = 64 (Linux / BSD / macOS / Android) ----
            if initial_ttl == 64:
                # Linux common window sizes: 64240 (standard MSS 1460 * 44), 5840, 14600, 29200, 5720
                if win in (64240, 5840, 14600, 29200, 5720):
                    return f"Linux (kernel 3.x-6.x, hops: {hops})"
                # macOS / iOS frequently advertise window 65535 with initial TTL 64
                elif win == 65535 and df_flag:
                    return f"macOS/iOS or FreeBSD (hops: {hops})"
                elif win in (16384, 32768) and df_flag:
                    return f"FreeBSD/OpenBSD (hops: {hops})"
                elif win == 65535 and not df_flag:
                    return f"Unix/Legacy BSD (hops: {hops})"
                else:
                    return f"Linux/Unix (hops: {hops}, win: {win})"

            # ---- Initial TTL = 128 (Windows family) ----
            elif initial_ttl == 128:
                # Windows 7/8/10 commonly uses window 8192 initially before scaling
                if win == 8192:
                    return f"Windows 7/8/10 (hops: {hops})"
                # Windows XP/10/Server frequently uses 65535
                elif win == 65535:
                    return f"Windows (XP/10/Server, hops: {hops})"
                elif win in (16384, 64512):
                    return f"Windows Server (hops: {hops})"
                else:
                    return f"Windows (hops: {hops}, win: {win})"

            # ---- Initial TTL = 255 (Network Appliances / Cisco / Solaris) ----
            elif initial_ttl == 255:
                return f"Network Device / Cisco (hops: {hops})"

            # ---- Initial TTL = 32 (Legacy / Embedded) ----
            elif initial_ttl == 32:
                return f"Legacy Windows / Embedded (hops: {hops})"

            return f"Unknown (TTL: {ip_hdr.ttl}, Win: {win})"

        # ---- Fallback for non-TCP packets (UDP / ICMP) ----
        if initial_ttl == 64:
            return f"Linux/Unix (est. hops: {hops})"
        elif initial_ttl == 128:
            return f"Windows (est. hops: {hops})"
        elif initial_ttl == 255:
            return f"Network Device / Cisco (est. hops: {hops})"
        elif initial_ttl == 32:
            return f"Legacy Windows / Embedded (est. hops: {hops})"

        return f"Unknown (TTL: {ip_hdr.ttl})"

    @classmethod
    def guess_os(cls, ttl: int) -> str:
        """Legacy helper for simple classification based solely on TTL."""
        initial_ttl, hops = cls.estimate_initial_ttl(ttl)
        if initial_ttl == 64:
            return f"Linux/Unix (est. hops: {hops})"
        elif initial_ttl == 128:
            return f"Windows (est. hops: {hops})"
        elif initial_ttl == 255:
            return f"Network Device (est. hops: {hops})"
        return f"Unknown (TTL: {ttl})"
