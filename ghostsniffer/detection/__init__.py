"""
GhostSniffer Detection Subpackage.
Exports OS fingerprinter and service banner grabber.
"""

from ghostsniffer.detection.os_fingerprint import OSFingerprinter
from ghostsniffer.detection.service_detect import ServiceDetector

__all__ = [
    'OSFingerprinter',
    'ServiceDetector',
]
