"""
GhostSniffer Configuration & Constants.
Handles environment configuration, protocol mappings, and operational defaults.
"""

import os

# ============================================================================
#  Protocol Mappings
# ============================================================================

PROTO_MAP = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
}

ICMP_TYPE_MAP = {
    0: 'Echo Reply',
    3: 'Dest Unreachable',
    8: 'Echo Request',
    11: 'Time Exceeded',
}

# ============================================================================
#  Operational Defaults
# ============================================================================

DEFAULT_PORT = 65212
DEFAULT_REPORT_INTERVAL = 30
DEFAULT_STEALTH_DOMAIN = 'google.com'
DEFAULT_SERVICE_TIMEOUT = 5.0
DEFAULT_KNOCK_TIMEOUT = 5.0

# ============================================================================
#  Environment Loader
# ============================================================================

def load_dotenv() -> None:
    """Load environment variables from .env file.

    Search order (first found wins per key):
    1. /etc/ghost_sniffer/.env      (system-wide — Linux)
    2. ~/.config/ghost_sniffer/.env (user config)
    3. Current working directory .env
    4. Script directory .env
    """
    search_paths = []

    if os.name != 'nt':
        search_paths.append('/etc/ghost_sniffer/.env')

    home = os.path.expanduser('~')
    search_paths.append(os.path.join(home, '.config', 'ghost_sniffer', '.env'))
    search_paths.append(os.path.join(os.getcwd(), '.env'))

    base_dir = os.path.dirname(os.path.abspath(__file__))
    search_paths.append(os.path.join(base_dir, '..', '.env'))

    for env_path in search_paths:
        try:
            with open(env_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '=' in line:
                            key, val = line.split('=', 1)
                            os.environ.setdefault(key.strip(), val.strip())
        except (FileNotFoundError, PermissionError):
            continue
