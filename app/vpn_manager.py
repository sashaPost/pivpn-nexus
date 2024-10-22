import configparser
import datetime
import os.path
import random
import subprocess
import time
import re
import dns.resolver
import threading
import requests
import psutil
import schedule
from .logging_utility import logger
from pathlib import Path


class AdvancedVPNNexusManager:
    def __init__(self, config_file: str):
        self.config = self._load_config(config_file)
        self.vpn_chain = []
        self.traffic_log = {}
        self.dns_leak_status = True
        self.pfs_enabled = False
        self.base_path = Path(__file__).parent.parent

    @staticmethod
    def _load_config(config_file: str) -> configparser.ConfigParser:
        config = configparser.ConfigParser()
        config.read(config_file)
        return config

    def setup_enhanced_encryption(self):
        for vpn in self.config.sections():
            config_path = self.config[vpn]['config_path']
            self._update_openvpn_config(config_path)
        logger.info("Enhanced encryption setup completed")

    def _update_openvpn_config(self, config_path: str):
        with open(config_path, 'a') as config_file:
            config_file.write("\ncipher AES-256-GCM")
            config_file.write("\nauth SHA256")
            config_file.write("\ntls-version-min 1.2")
            config_file.write("\ntls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384")
            config_file.write("\nncp-ciphers AES-256-GCM:AES-256-CBC")
        logger.info(f"Updated OpenVPN config: {config_path}")

    def setup_vpn_chain(self, num_hops=2):
        available_vpns = self.config.sections()
        if len(available_vpns) < num_hops:
            logger.error(f"Not enough VPN configs for {num_hops} hops")
            return False

        self.vpn_chain = random.sample(available_vpns, num_hops)
        for i, vpn in enumerate(self.vpn_chain):
            config_path = self.config[vpn]['config_path']
            if not os.path.isabs(config_path):
                config_path = os.path.join(self.base_path, config_path)

            try:
                subprocess.run(["which", "openvpn"], check=True, capture_output=True)

                if not os.path.isfile(config_path):
                    logger.error(f"Config file not found: {config_path}")
                    return False

                creds_file = os.path.join(os.path.dirname(config_path), "vpn-credentials.txt")
                logger.info(f"Using credentials file: {creds_file}")
                if os.path.isfile(creds_file):
                    auth_cmd = ["--auth-user-pass", creds_file]
                else:
                    auth_cmd = []

                cmd = [
                    "sudo", "openvpn",
                    "--config", config_path,
                    "--daemon",
                    f"--log", os.path.join(self.base_path, "logs", f"openvpn-{vpn}.log"),
                    "--status", os.path.join(self.base_path, "logs", f"openvpn-status-{vpn}.log"), "1"
                ] + auth_cmd

                logger.info(f"Starting OpenVPN with command: {cmd}")
                process = subprocess.run(
                    cmd,
                    check=True,
                    capture_output=True,
                    text=True
                )

                if i < num_hops - 1:
                    time.sleep(10)

                logger.info(f"Successfully started VPN: {vpn}")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to start OpenVPN for {vpn}: {e.stderr}")
                # Clean up any running VPN instances
                self.cleanup_vpn_chain()
                return False
            except Exception as e:
                logger.error(f"Unexpected error setting up VPN chain: {str(e)}")                # Clean up any running VPN instances
                self.cleanup_vpn_chain()
                return False

        logger.info(f"VPN chain established: {' -> '.join(self.vpn_chain)}")
        return True

    def cleanup_vpn_chain(self):
        """Clean up any running OpenVPN instances"""
        try:
            subprocess.run(["sudo", "killall", "openvpn"], check=False)
            logger.info(f"Cleaned up OpenVPN processes")
        except Exception as e:
            logger.error(f"Failed to clean up OpenVPN processes: {str(e)}")

    def optimize_vpn_chain(self):
        best_chain = None
        best_latency = float('inf')

        for _ in range(5):  # Try 5 different combinations
            self.setup_vpn_chain()
            latency = self.measure_latency()
            if latency < best_latency:
                best_chain = self.vpn_chain.copy()
                best_latency = latency

        self.vpn_chain = best_chain
        # self.logger.info(f"Optimized VPN chain: {' -> '.join(self.vpn_chain)}")
        logger.info(f"Optimized VPN chain: {' -> '.join(self.vpn_chain)}")

    def measure_latency(self):
        try:
            start = time.time()
            requests.get('https://www.google.com')
            end = time.time()
            return end - start
        except Exception as e:
            # self.logger.error(f"Failed to measure latency: {e}")
            logger.error(f"Failed to measure latency: {e}")
            return float('inf')

    def setup_dns_over_https(self):
        try:
            subprocess.run(["sudo", "apt", "install", "-y", "dnscrypt-proxy"], check=True)
            config = """
            server_names = ['cloudflare', 'google']
            listen_addresses = ['127.0.0.1:53']
            """
            with open('/etc/dnscrypt-proxy/dnscrypt-proxy.toml', 'w') as f:
                f.write(config)
            subprocess.run(["sudo", "systemctl", "enable", "dnscrypt-proxy"], check=True)
            subprocess.run(["sudo", "systemctl", "start", "dnscrypt-proxy"], check=True)
            with open("/etc/resolv.conf", "w") as f:
                f.write("nameserver 127.0.0.1\n")
            # self.logger.info("DNS over HTTPS setup completed")
            logger.info("DNS over HTTPS setup completed")
            return True
        except subprocess.CalledProcessError as e:
            # self.logger.error(f"Failed to setup DNS over HTTPS: {str(e)}")
            logger.error(f"Failed to setup DNS over HTTPS: {str(e)}")
            return False

    def check_dns_leak(self):
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8']
            answers = resolver.resolve('whoami.akamai.net', 'A')
            ip = answers[0].to_text()

            if ip == self.get_current_ip():
                self.dns_leak_status = False
                # self.logger.warning("DNS leak detected")
                logger.warning("DNS leak detected")
            else:
                self.dns_leak_status = True
                # self.logger.info("No DNS leak detected")
                logger.info("No DNS leak detected")
        except Exception as e:
            # self.logger.error(f"Error checking DNS leaks: {str(e)}")
            logger.error(f"Error checking DNS leaks: {str(e)}")

    def enable_pfs(self):
        """
        Enable Perfect Forward Secrecy if not already enabled.
        This involves:
        1. Generating a static key if needed
        2. Adding appropriate TLS configuration
        3. Ensuring proper cipher suites
        """
        try:
            for vpn in self.config.sections():
                config_path = self.config[vpn]['config_path']
                config_dir = os.path.dirname(config_path)

                # Read current config
                with open(config_path, 'r') as f:
                    config_content = f.read()

                # Skip if PFS is already enabled via embedded key
                if '<tls-crypt>' in config_content or '<tls-auth>' in config_content:
                    logger.info(f"PFS already enabled in {vpn} via embedded key")
                    continue

                # If no embedded key, need to set up PFS
                ta_key_path = os.path.join(config_dir, f"{vpn}-ta.key")

                # Generate static key if it doesn't exist
                if not os.path.exists(ta_key_path):
                    logger.info(f"Generating static key for {vpn}")
                    try:
                        subprocess.run(
                            ["openvpn", "--genkey", "secret", ta_key_path],
                            check=True,
                            capture_output=True,
                            text=True
                        )
                        os.chmod(ta_key_path, 0o600)    # Secure permissions
                    except subprocess.CalledProcessError as e:
                        logger.error(f"Failed to generate static key for {vpn}: {str(e)}")
                        return False

                # Read current config lines
                with open(config_path, 'r') as f:
                    lines = f.readlines()

                # Prepare PFS configuration
                pfs_config = [
                    "\n# Perfect Forward Secrecy Configuration\n",
                    "tls-version-min 1.2\n",
                    f"tls-crypt {ta_key_path}\n",
                    "cipher AES-256-GCM\n",
                    "auth SHA256\n",
                    "key-direction 1\n",
                    "tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384\n"
                ]

                # Check if these settings already exist
                existing_settings = ''.join(lines)
                new_settings = []
                for setting in pfs_config:
                    setting_name = setting.split()[0]
                    if setting_name not in existing_settings:
                        new_settings.append(setting)

                # Backup original config
                backup_path = f"{config_path}.backup"
                if not os.path.exists(backup_path):
                    with open(backup_path, 'w') as f:
                        f.write(existing_settings)

                # Add new PFS settings if needed
                if new_settings:
                    with open(config_path, 'a') as f:
                        f.writelines(new_settings)
                    logger.info(f"Added PFS configuration to {vpn}")

                self.pfs_enabled = True
                logger.info("Perfect Forward Secrecy enabled for all configurations")
                return True
        except Exception as e:
            logger.error(f"Failed to enable PFS: {str(e)}")
            return False

    def check_pfs_status(self):
        """
        Check PFS status for all VPN configurations
        Returns detailed status including cipher suites and key configurations
        """
        try:
            status = {}
            for vpn in self.config.sections():
                config_path = self.config[vpn]['config_path']
                with open(config_path, 'r') as f:
                    content = f.read()

                # Check for various PFS indicators
                status[vpn] = {
                    'embedded_key': '<tls-crypt>' in content or '<tls-auth>' in content,
                    'external_key': bool(re.search(r'tls-crypt\s+\S+\.key', content)),
                    'tls_version': re.search(r'tls-version-min\s+([\d.]+)', content),
                    'cipher': re.search(r'cipher\s+(\S+)', content),
                    'tls_cipher': 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384' in content,
                    'config_path': config_path,
                    'pfs_enabled': any([
                        '<tls-crypt>' in content,
                        '<tls-auth>' in content,
                        'tls-crypt' in content and '.key' in content
                    ])
                }

                # Extract actual values where found
                if status[vpn]['tls_version']:
                    status[vpn]['tls_version'] = status[vpn]['tls_version'].group(1)

                if status[vpn]['cipher']:
                    status[vpn]['cipher'] = status[vpn]['cipher'].group(1)

            return status
        except Exception as e:
            logger.error(f"Failed to check PFS status: {str(e)}")
            return None

    def disable_pfs(self):
        """
        Disable PFS by restoring original configurations
        """
        try:
            for vpn in self.config.sections():
                config_path = self.config[vpn]['config_path']
                backup_path = f"{config_path}.backup"

                if os.path.exists(backup_path):
                    with open(backup_path, 'r') as f:
                        original_config = f.read()

                with open(config_path, 'w') as f:
                    f.write(original_config)

                logger.info(f"Restored original configuration for {vpn}")

            self.pfs_enabled = False
            logger.info("PFS disabled and original configurations restored")
            return True
        except Exception as e:
            logger.error(f"Error disabling PFS: {str(e)}")
            return False


    def monitor_traffic(self):
        net_io = psutil.net_io_counters()
        timestamp = datetime.datetime.now()
        self.traffic_log[timestamp] = {
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv
        }

    def get_traffic_stats(self):
        if len(self.traffic_log) < 2:
            return {"error": "Not enough data"}

        times = sorted(self.traffic_log.keys())
        start, end = times[0], times[-1]
        duration = (datetime.datetime.fromisoformat(end) - datetime.datetime.fromisoformat(start)).total_seconds()

        bytes_sent = self.traffic_log[end]['bytes_sent'] - self.traffic_log[start]['bytes_sent']
        bytes_recv = self.traffic_log[end]['bytes_recv'] - self.traffic_log[start]['bytes_recv']

        return {
            "duration": duration,
            "bytes_sent": bytes_sent,
            "bytes_recv": bytes_recv,
            "send_rate": bytes_sent / duration,
            "recv_rate": bytes_recv / duration
        }

    def start_monitoring(self):
        schedule.every(1).minutes.do(self.monitor_traffic)
        schedule.every(5).minutes.do(self.check_dns_leak)
        schedule.every(30).minutes.do(self.optimize_vpn_chain)
        threading.Thread(target=self._run_schedule, daemon=True).start()

    def _run_schedule(self):
        while True:
            schedule.run_pending()
            time.sleep(1)

    def get_status(self):
        return {
            "vpn_chain": self.vpn_chain,
            "dns_leak_status": self.dns_leak_status,
            "pfs_enabled": self.pfs_enabled,
            "traffic_stats": self.get_traffic_stats()
        }

    def list_providers(self):
        providers = []
        for section in self.config.sections():
            provider = {
                'name': section,
                'config_path': self.config[section]['config_path']
            }
            providers.append(provider)
            logger.info(f"Provider: {provider['name']}, Config Path: {provider['config_path']}")
        return providers

    def add_provider(self, name: str, config_path: str):
        if name not in self.config:
            self.config[name] = {"config_path": config_path}
            with open("/etc/vpn_nexus_manager.conf", "w") as configfile:
                self.config.write(configfile)
            return True
        return False

    def delete_provider(self, name: str):
        if name in self.config:
            self.config.remove_section(name)
            with open("/etc/vpn_nexus_manager.conf", "w") as configfile:
                self.config.write(configfile)
            return True
        return False

    def get_current_ip(self):
        try:
            response = requests.get('https://api.ipify.org')
            return response.text
        except Exception as e:
            # self.logger.error(f"Failed to get current IP: {str(e)}")
            logger.error(f"Failed to get current IP: {str(e)}")
            return None

    def __del__(self):
        """Ensure VPN processes are cleaned up when the object is destroyed"""
        self.cleanup_vpn_chain()
