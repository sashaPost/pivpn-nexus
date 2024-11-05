"""VPN chain management implementation."""

import configparser
from pathlib import Path
import os
from typing import Dict, Optional

from .command_factory import VPNCommandFactory
from .commands import CommandError
from .exceptions import ConfigurationError, VPNError, InterfaceError
from .models import VPNInterface, VPNStatus
from .utils import wait_for_interface, log_vpn_output, run_command
from ..logging_utility import logger


class AdvancedVPNNexusManager:
    def __init__(self, config_file: str):
        self.config = self._load_config(config_file)
        self.base_path = Path(__file__).parent.parent.parent
        self.socks_ports = {}
        self.vpn1_table = 11
        self.vpn2_table = 12
        self.interfaces: Dict[str, VPNInterface] = {}

    def _create_interface(self, name: str, log_file: Path) -> VPNInterface:
        """
        Create and track a new VPN interface.

        Args:
            name: Interface name (e.g., 'tun0')
            log_file: Path to log file

        Returns:
            VPNInterface object
        """
        interface = VPNInterface(
            name=name,
            log_file=Path(log_file),
            status=VPNStatus.CONNECTING
        )
        self.interfaces[name] = interface
        return interface

    def get_interface_status(self, name: str) -> VPNStatus:
        """
        Get current status of an interface.

        Args:
            name: Interface name (e.g., 'tun0')

        Returns:
            VPNStatus enum value
        """
        return self.interfaces.get(name, VPNInterface(name=name, log_file=Path(""))).status

    @staticmethod
    def _load_config(config_file: str) -> configparser.ConfigParser:
        config = configparser.ConfigParser()
        config.read(config_file)
        return config

    def _setup_routing_rules(self) -> bool:
        """Set up routing tables and rules"""
        try:
            # Check if tables already exist
            tables_exist = False
            try:
                stdout, _ = run_command(VPNCommandFactory.read_routing_tables())
                if str(self.vpn1_table) in stdout and str(self.vpn2_table) in stdout:
                    tables_exist = True
            except Exception as e:
                logger.warning(f"Could not read routing tables: {e}")

            # Add tables if they don't exist
            if not tables_exist:
                logger.info("Adding routing tables")
                tables_content = f"\n{self.vpn1_table} vpn1\n{self.vpn2_table} vpn2\n"
                run_command(VPNCommandFactory.write_routing_tables(tables_content))

            # Flush existing rules and routes
            logger.info("Cleaning up existing routes and rules")
            for table in [str(self.vpn1_table), str(self.vpn2_table)]:
                run_command(VPNCommandFactory.delete_routing_rule(table), check=False)
                run_command(VPNCommandFactory.flush_routing_table(table), check=False)

            logger.info("Routing tables and rules initialized")
            return True
        except Exception as e:
            logger.error(f"Failed to set up routing rules: {str(e)}")
            return False

    def setup_vpn_chain(self, num_hops: int = 2) -> bool:
        """Set up VPN + SOCKS proxy chain"""
        try:
            # Clean up any existing configuration
            self.cleanup_vpn_chain()

            # Get first VPN
            try:
                first_vpn = list(self.config.sections())[0]
                vpn_config = self.config[first_vpn]['config_path']
            except (IndexError, KeyError) as e:
                raise ConfigurationError(f"Invalid VPN configuration: {str(e)}")

            if not vpn_config.startswith('/'):
                vpn_config = str(self.base_path / vpn_config)

            # Start first VPN with logging
            first_vpn_log = self.base_path / "logs" / "first_vpn.log"
            credentials = Path("/home/anyone/.prjcts/pivpn-nexus/config/test/vpn-credentials.txt")

            logger.info(f"Starting first VPN using config: {vpn_config}")

            # Create interface tracking
            first_interface = self._create_interface(name="tun0", log_file=first_vpn_log)

            try:
                run_command(
                    VPNCommandFactory.start_vpn(
                        config_path=Path(vpn_config),
                        credentials_path=credentials,
                        log_path=first_vpn_log,
                        interface=first_interface.name
                    )
                )
            except CommandError as e:
                first_interface.status = VPNStatus.ERROR
                raise ConnectionError(f"Failed to start first VPN: {str(e)}")

            # Wait for first VPN interface
            if not wait_for_interface("tun0"):
                first_interface.status = VPNStatus.ERROR
                log_vpn_output(str(first_vpn_log))
                raise InterfaceError("First VPN interface (tun0) failed to initialize")

            first_interface.status = VPNStatus.CONNECTED
            logger.info("First VPN connection established")

            # Log network configuration
            logger.info("Final network configuration:")

            route_stdout, _ = run_command(VPNCommandFactory.show_routes())
            logger.info(f"Routing table:\n{route_stdout}")

            ifaces_stdout, _ = run_command(VPNCommandFactory.show_interfaces())
            logger.info(f"Network interfaces:\n{ifaces_stdout}")

            # Test connections
            first_ip_stdout, _ = run_command(
                VPNCommandFactory.check_ip("tun0"))
            logger.info(f"First VPN IP: {first_ip_stdout.strip()}")

            # Set up second hop if needed
            if num_hops > 1:
                try:
                    second_vpn = list(self.config.sections())[1]
                    logger.info(f"Setting up second hop through {second_vpn}")
                    config_path = self.config[second_vpn]['config_path']
                except (IndexError, KeyError) as e:
                    raise ConfigurationError(f"Invalid VPN configuration: {str(e)}")

                # Start second VPN
                second_vpn_log = self.base_path / "logs" / "second_vpn.log"

                # Create second interface tracking
                second_interface = self._create_interface(name="tun1", log_file=second_vpn_log)
                try:
                    run_command(
                        VPNCommandFactory.start_vpn(
                            config_path=Path(vpn_config),
                            credentials_path=credentials,
                            log_path=second_vpn_log,
                            interface=second_interface.name
                        )
                    )
                except VPNError as e:
                    second_interface.status = VPNStatus.ERROR
                    raise ConnectionError(f"Failed to start first VPN: {str(e)}")

                # Wait for second VPN interface
                if not wait_for_interface("tun1"):
                    second_interface.status = VPNStatus.ERROR
                    log_vpn_output(str(second_vpn_log))
                    raise Exception("Second VPN interface (tun1) failed to initialize")

                second_interface.status = VPNStatus.CONNECTED
                logger.info("Second VPN connection established")

            # Log network configuration
            logger.info("Final network configuration:")

            # route_stdout, _ = run_command(["ip", "route", "show"], use_sudo=True)
            route_stdout, _ = run_command(VPNCommandFactory.show_routes())
            logger.info(f"Routing table:\n{route_stdout}")

            # ifaces_stdout, _ = run_command(["ip", "addr"], use_sudo=True)
            ifaces_stdout, _ = run_command(VPNCommandFactory.show_interfaces())
            logger.info(f"Network interfaces:\n{ifaces_stdout}")

            first_ip_stdout, _ = run_command(VPNCommandFactory.check_ip("tun0"))
            logger.info(f"First VPN IP: {first_ip_stdout.strip()}")

            if num_hops > 1:
                second_ip_stdout, _ = run_command(VPNCommandFactory.check_ip("tun1"))
                logger.info(f"Second VPN IP: {second_ip_stdout.strip()}")

            return True

        except Exception as e:
            for interface in self.interfaces.values():
                interface.status = VPNStatus.ERROR
            logger.error(f"Failed to set up chain: {str(e)}")
            self.cleanup_vpn_chain()
            return False

    def cleanup_vpn_chain(self) -> None:
        """Clean up processes"""
        try:
            run_command(VPNCommandFactory.kill_vpn(), check=False)

            for interface in self.interfaces.values():
                interface.status = VPNStatus.DISCONNECTED

            # Remove log files
            for log_file in ["first_vpn.log", "second_vpn.log"]:
                log_path = os.path.join(self.base_path, "logs", log_file)
                if os.path.exists(log_path):
                    os.remove(log_path)

            # Clear interface tracking
            self.interfaces.clear()

            logger.info("VPN chain cleaned up")
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")

    def get_current_ip(self) -> Optional[str]:
        """Test the chain by checking current IP"""
        try:
            # Check IP through second VPN if available
            link_stdout, _ = run_command(VPNCommandFactory.check_links())
            if "tun1" in link_stdout:
                logger.info("Checking IP through second VPN (tun1)")
                ip_stdout, _ = run_command(VPNCommandFactory.check_ip("tun1"))
            else:
                # Check IP through first VPN
                logger.info("Checking IP through first VPN (tun0)")
                ip_stdout, _ = run_command(VPNCommandFactory.check_ip("tun0"))

            current_ip = ip_stdout.strip()
            logger.info(f"Current IP: {current_ip}")
            return current_ip
        except Exception as e:
            logger.error(f"Failed to get current IP: {str(e)}")
            return None