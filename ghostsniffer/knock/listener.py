"""
Hardened Port Knocking Daemon.
Enforces per-source-IP state tracking, strict sliding expiration windows,
replay mitigation cooldowns, and optional HMAC/token payload verification.
"""

import hmac
import hashlib
import os
import subprocess
import threading
import time
from typing import List, Optional, Dict, Any


class KnockListener:
    """Monitor incoming packets for a hardened port-knock sequence.

    Security Mitigations:
    1. Source IP Binding: State tracked independently per sender IP.
    2. Sliding Expiration Window: Strict timeout between knocks and max overall window.
    3. Replay Attack Mitigation: Prevents replayed sequences within cooldown periods.
    4. Optional Payload Verification: Validates HMAC or secret token within packet payloads.
    """

    def __init__(
        self,
        sequence: List[int],
        protocol: str = 'udp',
        timeout: float = 5.0,
        action: Optional[str] = None,
        secret: Optional[str] = None,
        cooldown: float = 10.0,
    ) -> None:
        self.sequence = sequence  # e.g. [1000, 2000, 3000]
        self.protocol = protocol.upper()
        self.timeout = timeout
        self.action = action
        self.secret = secret or os.environ.get('KNOCK_SECRET')
        self.cooldown = cooldown

        # Source IP -> {'current_index': int, 'last_knock_time': float, 'start_time': float}
        self._sessions: Dict[str, Dict[str, Any]] = {}
        # Source IP -> completion timestamp (for cooldown / replay protection)
        self._completed_cache: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _verify_payload(self, payload: bytes, src_ip: str, value: int) -> bool:
        """Verify HMAC or secret token if configured."""
        if not self.secret:
            return True  # No secret required

        secret_bytes = self.secret.encode('utf-8')

        # Check 1: Direct token substring or exact match
        if secret_bytes in payload:
            return True

        # Check 2: Hex-encoded HMAC-SHA256 signature
        try:
            expected_hmac = hmac.new(
                secret_bytes,
                f"{src_ip}:{value}".encode('utf-8'),
                hashlib.sha256
            ).hexdigest().encode('ascii')
            if hmac.compare_digest(payload.strip(), expected_hmac):
                return True
        except Exception:
            pass

        return False

    def _prune_expired(self, now: float) -> None:
        """Clean up expired sessions and completed cache entries."""
        expired_ips = [
            ip for ip, sess in self._sessions.items()
            if (now - sess['last_knock_time']) > (self.timeout * 3)
        ]
        for ip in expired_ips:
            del self._sessions[ip]

        stale_completed = [
            ip for ip, ts in self._completed_cache.items()
            if (now - ts) > (self.cooldown * 5)
        ]
        for ip in stale_completed:
            del self._completed_cache[ip]

    def check_packet(
        self,
        src_ip: str,
        proto: str,
        value: int,
        payload: bytes = b'',
    ) -> bool:
        """Check whether *value* matches the expected knock for *src_ip*.

        Returns True when the full sequence is successfully verified.
        """
        with self._lock:
            now = time.time()
            self._prune_expired(now)

            if proto.upper() != self.protocol:
                return False

            # Replay mitigation check: enforce cooldown for recent completed knock
            if src_ip in self._completed_cache:
                if (now - self._completed_cache[src_ip]) < self.cooldown:
                    # Sequence was completed recently; reject replayed knocks
                    return False

            # Initialize session for source IP if not present
            if src_ip not in self._sessions:
                self._sessions[src_ip] = {
                    'current_index': 0,
                    'last_knock_time': now,
                    'start_time': now,
                }

            session = self._sessions[src_ip]
            current_idx = session['current_index']

            # Sliding expiration window check
            if current_idx > 0:
                # Step timeout exceeded
                if (now - session['last_knock_time']) > self.timeout:
                    session['current_index'] = 0
                    current_idx = 0

                # Max total sequence window exceeded
                max_total_window = self.timeout * len(self.sequence)
                if (now - session['start_time']) > max_total_window:
                    session['current_index'] = 0
                    current_idx = 0

            # Match next expected knock in sequence
            expected_val = self.sequence[current_idx]
            if value == expected_val:
                # Payload verification if secret/token configured
                if self.secret and not self._verify_payload(payload, src_ip, value):
                    session['current_index'] = 0
                    return False

                if current_idx == 0:
                    session['start_time'] = now

                session['current_index'] += 1
                session['last_knock_time'] = now

                print(
                    f"[*] Knock {session['current_index']}/{len(self.sequence)} "
                    f"from {src_ip}: {proto} {value}"
                )

                # Check sequence completion
                if session['current_index'] >= len(self.sequence):
                    session['current_index'] = 0
                    self._completed_cache[src_ip] = now
                    return True
            else:
                # Value mismatch; reset sequence for this source IP
                if session['current_index'] > 0:
                    session['current_index'] = 0

            return False

    def execute_action(self, src_ip: Optional[str] = None) -> None:
        """Run the configured shell command."""
        if not self.action:
            return
        cmd = self.action
        if src_ip:
            cmd = cmd.replace('{src_ip}', src_ip)
        try:
            subprocess.Popen(cmd, shell=True)
            print(f"[+] Action executed: {cmd}")
        except Exception as e:
            print(f"[!] Action execution failed: {e}")
