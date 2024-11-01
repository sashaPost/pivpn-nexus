import configparser
import subprocess
import time
from pathlib import Path
import os
from .logging_utility import logger



class AdvancedVPNNexusManager:
    def __init__(self, config_file: str):
        self.config = self._load_config(config_file)
        self.base_path = Path(__file__).parent.parent
        self.socks_ports = {}
        self.vpn1_table = 11
        self.vpn2_table = 12

    @staticmethod
    def _load_config(config_file: str) -> configparser.ConfigParser:
        config = configparser.ConfigParser()
        config.read(config_file)
        return config

    def _setup_routing_rules(self):
        """Set up routing tables and rules"""
        try:
            # Check if tables already exist
            tables_exist = False
            try:
                result = subprocess.run(["sudo", "cat", "/etc/iproute2/rt_tables"], capture_output=True, text=True, check=True)
                if str(self.vpn1_table) in result.stdout and str(self.vpn2_table) in result.stdout:
                    tables_exist = True
            except subprocess.CalledProcessError as e:
                logger.warning(f"Could not read routing tables: {e}")

            # Add tables if they don't exist
            if not tables_exist:
                logger.info("Adding routing tables")
                tables_content = f"\n{self.vpn1_table} vpn1\n{self.vpn2_table} vpn2\n"
                subprocess.run(
                    ["sudo", "bash", "-c", f"echo '{tables_content}' >> /etc/iproute2/rt_tables"],
                    check=True
                )

            # Flush existing rules and routes
            logger.info("Cleaning up existing routes and rules")
            subprocess.run(["sudo", "ip", "rule", "del", "table", str(self.vpn1_table)], check=False)
            subprocess.run(["sudo", "ip", "rule", "del", "table", str(self.vpn2_table)], check=False)
            # subprocess.run(["sudo", "ip", "rule", "flush"], check=True)
            subprocess.run(["sudo", "ip", "route", "flush", "table", str(self.vpn1_table)], check=False)
            subprocess.run(["sudo", "ip", "route", "flush", "table", str(self.vpn2_table)], check=False)

            # # Restore default rule
            # subprocess.run(["sudo", "ip", "rule", "add", "from", "all", "lookup", "main"], check=True)

            logger.info("Routing tables and rules initialized")
            return True
        except Exception as e:
            logger.error(f"Failed to set up routing rules: {str(e)}")
            return False

    def setup_vpn_chain(self, num_hops=2):
        """Set up VPN + SOCKS proxy chain"""
        try:
            # Clean up any existing configuration
            self.cleanup_vpn_chain()

            # Get first VPN
            first_vpn = list(self.config.sections())[0]
            vpn_config = self.config[first_vpn]['config_path']
            if not vpn_config.startswith('/'):
                vpn_config = str(self.base_path / vpn_config)

            # Start first VPN with logging
            first_vpn_log = os.path.join(self.base_path, "logs",
                                         "first_vpn.log")
            logger.info(f"Starting first VPN using config: {vpn_config}")
            subprocess.run([
                "sudo",
                "openvpn",
                "--config", vpn_config,
                "--auth-user-pass",
                "/home/anyone/.prjcts/pivpn-nexus/config/test/vpn-credentials.txt",
                "--daemon",
                "--verb", "4",
                "--log", first_vpn_log
            ], check=True)

            # Wait for first VPN interface
            if not self._wait_for_interface("tun0"):
                # Read and log the OpenVPN output
                if os.path.exists(first_vpn_log):
                    with open(first_vpn_log, 'r') as f:
                        vpn_output = f.read()
                        logger.error(f"OpenVPN output:\n{vpn_output}")
                raise Exception(
                    "First VPN interface (tun0) failed to initialize")

            logger.info("First VPN connection established")

            # Set up second hop if needed
            if num_hops > 1:
                second_vpn = list(self.config.sections())[1]
                logger.info(f"Setting up second hop through {second_vpn}")
                config_path = self.config[second_vpn]['config_path']

                # Start second VPN
                second_vpn_log = os.path.join(self.base_path, "logs",
                                              "second_vpn.log")
                subprocess.run([
                    "sudo",
                    "openvpn",
                    "--config", config_path,
                    "--auth-user-pass",
                    "/home/anyone/.prjcts/pivpn-nexus/config/test/vpn-credentials.txt",
                    "--daemon",
                    "--verb", "4",
                    "--log", second_vpn_log,
                ], check=True)

                # Wait for second VPN interface
                if not self._wait_for_interface("tun1"):
                    # Read and log the OpenVPN output
                    if os.path.exists(second_vpn_log):
                        with open(second_vpn_log, 'r') as f:
                            vpn_output = f.read()
                            logger.error(f"Second VPN output:\n{vpn_output}")
                    raise Exception(
                        "Second VPN interface (tun1) failed to initialize")

                logger.info("Second VPN connection established")

            # Log network configuration
            logger.info("Final network configuration:")

            route_result = subprocess.run(["ip", "route", "show"],
                                          capture_output=True, text=True)
            logger.info(f"Routing table:\n{route_result.stdout}")

            ifaces = subprocess.run(["ip", "addr"], capture_output=True,
                                    text=True)
            logger.info(f"Network interfaces:\n{ifaces.stdout}")

            # Test connections
            first_ip = subprocess.run(
                ["curl", "--interface", "tun0", "--silent", "ifconfig.me"],
                capture_output=True, text=True
            )
            logger.info(f"First VPN IP: {first_ip.stdout.strip()}")

            if num_hops > 1:
                second_ip = subprocess.run(
                    ["curl", "--interface", "tun1", "--silent", "ifconfig.me"],
                    capture_output=True, text=True
                )
                logger.info(f"Second VPN IP: {second_ip.stdout.strip()}")

            return True

        except Exception as e:
            logger.error(f"Failed to set up chain: {str(e)}")
            self.cleanup_vpn_chain()
            return False

    def _wait_for_interface(self, interface, max_attempts=30):
        """Wait for network interface to be available"""
        logger.info(f"Waiting for {interface} to be ready...")
        for i in range(max_attempts):
            try:
                result = subprocess.run(
                    ["ip", "addr", "show", interface],
                    capture_output=True,
                    text=True,
                    check=True
                )
                if "inet" in result.stdout:
                    logger.info(f"{interface} is ready with IP configuration")
                    return True
            except subprocess.CalledProcessError:
                pass
            time.sleep(1)
            logger.info(f"Waiting for {interface}... ({i + 1}/{max_attempts})")
        return False

    def cleanup_vpn_chain(self):
        """Clean up processes"""
        try:
            # Stop OpenVPN processes
            subprocess.run(["sudo", "killall", "openvpn"], check=False)

            # Remove log files
            for log_file in ["first_vpn.log", "second_vpn.log"]:
                log_path = os.path.join(self.base_path, "logs", log_file)
                if os.path.exists(log_path):
                    os.remove(log_path)

            logger.info("VPN chain cleaned up")
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")

    def get_current_ip(self):
        """Test the chain by checking current IP"""
        try:
            # Check IP through second VPN if available
            if "tun1" in subprocess.run(["ip", "link"], capture_output=True,
                                        text=True).stdout:
                logger.info("Checking IP through second VPN (tun1)")
                result = subprocess.run([
                    "curl",
                    "--interface", "tun1",
                    "--silent",
                    "--max-time", "10",
                    "ifconfig.me"
                ], capture_output=True, text=True)
            else:
                # Check IP through first VPN
                logger.info("Checking IP through first VPN (tun0)")
                result = subprocess.run([
                    "curl",
                    "--interface", "tun0",
                    "--silent",
                    "--max-time", "10",
                    "ifconfig.me"
                ], capture_output=True, text=True)

            logger.info(f"Current IP: {result.stdout.strip()}")
            return result.stdout.strip()
        except Exception as e:
            logger.error(f"Failed to get current IP: {str(e)}")
            return None

