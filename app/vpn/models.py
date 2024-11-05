"""Data models for VPN management."""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional


class VPNStatus(Enum):
    """VPN connection status"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"


@dataclass
class VPNInterface:
    """Network interface information"""
    name: str
    log_file: Path
    status: VPNStatus = VPNStatus.DISCONNECTED
    ip_address: Optional[str] = None