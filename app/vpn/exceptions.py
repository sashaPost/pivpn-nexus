"""Custom exceptions for VPN management."""


class VPNError(Exception):
    """Base exception for VPN-related errors."""
    pass


class ConfigurationError(VPNError):
    """Raised when there's an issue with VPN configuration"""
    pass


class InterfaceError(VPNError):
    """Raised when there's an issue with network interfaces"""
    pass


class ConnectionError(VPNError):
    """Raised when VPN connection fails"""
    pass
