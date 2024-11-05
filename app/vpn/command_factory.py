"""Factory for creating VPN-related commands."""

from pathlib import Path
from typing import Optional
from .commands import (
    OPENVPN_START,
    IP_ADDR,
    IP_LINK,
    IP_ROUTE,
    CHECK_IP,
    KILLALL,
    CAT,
    BASH,
    IP_RULE_DEL,
    IP_RULE_FLUSH,
)


class VPNCommandFactory:
    """Factory for creating VPN management commands."""

    @staticmethod
    def start_vpn(
            config_path: Path,
            credentials_path: Path,
            log_path: Path,
            interface: Optional[str] = None,
    ) -> list[str]:
        """Create OpenVPN start command."""
        cmd = OPENVPN_START.with_options(
            config=str(config_path),
            auth_user_pass=str(credentials_path),
            log=str(log_path),
        )

        if interface:
            # cmd = cmd.with_option("dev", interface)
            cmd = cmd.with_options(dev=interface)  # Changed to with_options to match option name

        return cmd.as_sudo().build()

    @staticmethod
    def check_interface(interface: str) -> list[str]:
        """Create interface check command."""
        return IP_ADDR.with_args("show", interface).as_sudo().build()

    @staticmethod
    def check_ip(interface: str) -> list[str]:
        """Create IP check command."""
        return (
            CHECK_IP
            .with_option("interface", interface)
            .as_sudo()
            .build()
        )

    @staticmethod
    def kill_vpn() -> list[str]:
        """Create VPN kill command."""
        return KILLALL.with_arg("openvpn").as_sudo().build()

    @staticmethod
    def show_routes() -> list[str]:
        """Create route show command."""
        return IP_ROUTE.with_arg("show").as_sudo().build()

    @staticmethod
    def show_interfaces() -> list[str]:
        """Create interface show command."""
        return IP_ADDR.as_sudo().build()

    @staticmethod
    def check_links() -> list[str]:
        """Create command to check network links."""
        return IP_LINK.as_sudo().build()

    @staticmethod
    def read_routing_tables() -> list[str]:
        """Command to read routing tables."""
        return CAT.with_arg("/etc/iproute2/rt_tables").as_sudo().build()

    @staticmethod
    def write_routing_tables(content: str) -> list[str]:
        """Command to write to routing tables."""
        return BASH.with_option("c", f"echo '{content}' >> /etc/iproute2/rt_tables").as_sudo().build()

    @staticmethod
    def delete_routing_rule(table: str) -> list[str]:
        """Command to delete routing rule."""
        return IP_RULE_DEL.with_options(table=table).as_sudo().build()

    @staticmethod
    def flush_routing_table(table: str) -> list[str]:
        """Command to flush routing table."""
        return IP_RULE_FLUSH.with_options(table=table).as_sudo().build()