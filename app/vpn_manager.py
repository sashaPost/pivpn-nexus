import configparser
import subprocess
import time
from pathlib import Path
from .logging_utility import logger



class AdvancedVPNNexusManager:
    def __init__(self, config_file: str):
        self.config = self._load_config(config_file)
        # self.vpn_chain = []
        # self.traffic_log = {}
        # self.dns_leak_status = True
        # self.pfs_enabled = False
        self.base_path = Path(__file__).parent.parent
        # self.active_tunnels = {}
        self.socks_ports = {}

    @staticmethod
    def _load_config(config_file: str) -> configparser.ConfigParser:
        config = configparser.ConfigParser()
        config.read(config_file)
        return config

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

            # Start first VPN
            logger.info(f"Starting first VPN using config: {vpn_config}")
            subprocess.run([
                "sudo",
                "openvpn",
                "--config", vpn_config,
                "--auth-user-pass", "/home/anyone/.prjcts/pivpn-nexus/config/test/vpn-credentials.txt",
                "--daemon",
            ], check=True)

            time.sleep(10)

            # For each additional hop
            base_port = 1080
            for i, vpn in enumerate(list(self.config.sections())[1:num_hops], 1):
                config_path = self.config[vpn]['config_path']

                # Extract server and port from config
                with open(config_path) as f:
                    config_text = f.read()
                    for line in config_text.split('\n'):
                        if line.startswith('remote '):
                            _, host, port = line.split()
                            break

                # Start SOCKS proxy to this server
                socks_port = base_port + i
                logger.info(f"Starting SOCKS proxy on port {socks_port} to {host}:{port}")

                # Using socat to create SOCKS proxy
                subprocess.Popen([
                    "socat",
                    f"TCP-LISTEN:{socks_port},fork",
                    f"SOCKS4:{host}:{port}"
                ])

                self.socks_ports[vpn] = socks_port
                time.sleep(2)

            logger.info("Proxy chain established")
            logger.info(f"SOCKS ports: {self.socks_ports}")
            return True
        except Exception as e:
            logger.error(f"Failed to set up chain: {str(e)}")
            self.cleanup_vpn_chain()
            return False

    def cleanup_vpn_chain(self):
        """Clean up processes"""
        subprocess.run(["sudo", "killall", "openvpn"], check=False)
        subprocess.run(["killall", "socat"], check=False)
        self.socks_ports.clear()

    def get_current_ip(self):
        """Test the chain by checking IP through last proxy"""
        try:
            if not self.socks_ports:
                # Just VPN
                result = subprocess.run([
                    "curl",
                    "ifconfig.me"
                ], capture_output=True, text=True)
            else:
                # Through last proxy in chain
                last_port = max(self.socks_ports.values())
                result = subprocess.run([
                    "curl",
                    "--socks4", f"127.0.0.1:{last_port}",
                    "ifconfig.me"
                ], capture_output=True, text=True)
            return result.stdout.strip()
        except Exception as e:
            logger.error(f"Failed to get current IP: {str(e)}")
            return None