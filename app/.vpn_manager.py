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
import socket


class AdvancedVPNNexusManager:
    def __init__(self, config_file: str):
        self.config = self._load_config(config_file)
        self.vpn_chain = []
        self.traffic_log = {}
        self.dns_leak_status = True
        self.pfs_enabled = False
        self.base_path = Path(__file__).parent.parent
        self.virtual_interfaces = []
        self.namespace_prefix = "vpnns"

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

    def _create_network_namespace(self, namespace):
        """Create a new network namespace with proper routing"""
        try:
            # Create namespace
            subprocess.run(["sudo", "ip", "netns", "add", namespace], check=True)

            # Create veth pair
            veth0 = f"veth0_{namespace}"
            veth1 = f"veth1_{namespace}"
            subprocess.run(["sudo", "ip", "link", "add", veth0, "type", "veth", "peer", "name", veth1], check=True)

            # Move veth1 to namespace
            subprocess.run(["sudo", "ip", "link", "set", veth1, "netns", namespace], check=True)

            # Configure interfaces with different IPs
            subprocess.run(["sudo", "ip", "addr", "add", "10.200.1.1/24", "dev", veth0], check=True)
            subprocess.run(["sudo", "ip", "netns", "exec", namespace, "ip", "addr", "add", "10.200.1.2/24", "dev", veth1], check=True)

            # Enable interfaces
            subprocess.run(["sudo", "ip", "link", "set", veth0, "up"], check=True)
            subprocess.run(["sudo", "ip", "netns", "exec", namespace, "ip", "link", "set", "dev", veth1, "up"], check=True)
            subprocess.run(["sudo", "ip", "netns", "exec", namespace, "ip", "link", "set", "dev", "lo", "up"], check=True)

            # Set up routing in namespace
            subprocess.run(["sudo", "ip", "netns", "exec", namespace, "ip", "route", "add", "default", "via", "10.200.1.1"], check=True)

            # Enable IP forwarding on host
            subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)

            # Set up NAT on host
            subprocess.run([
                "sudo", "iptables", "-t", "nat", "-A", "POSTROUTING",
                "-s", "10.200.1.0/24", "-o", self._get_default_interface(),
                "-j", "MASQUERADE"
            ], check=True)

            # Allow forwarding between interfaces
            subprocess.run([
                "sudo", "iptables", "-A", "FORWARD",
                "-i", veth0, "-o", self._get_default_interface(),
                "-j", "ACCEPT"
            ], check=True)
            subprocess.run([
                "sudo", "iptables", "-A", "FORWARD",
                "-i", self._get_default_interface(), "-o", veth0,
                "-j", "ACCEPT"
            ], check=True)

            # Set up DNS in namespace
            ns_resolv_conf = f"/etc/netns/{namespace}/resolv.conf"
            os.makedirs(os.path.dirname(ns_resolv_conf), exist_ok=True)
            with open(ns_resolv_conf, 'w') as f:
                f.write("nameserver 8.8.8.8\n")
                f.write("nameserver 8.8.4.4\n")

            logger.info(
                f"Created network namespace {namespace} with veth pair {veth0} and {veth1}")

            # Debug: verify network setup
            self._debug_namespace(namespace)
            return True

        except subprocess.CalledProcessError as e:
            logger.error(
                f"Failed to create network namespace {namespace}: {str(e)}")
            return False

    def _get_default_interface(self):
        """Get the name of the default network interface"""
        try:
            result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, check=True)
            return result.stdout.split()[4]
        except (subprocess.CalledProcessError, IndexError) as e:
            return "eth0"  # fallback to common default

    def setup_vpn_chain(self, num_hops=2):
        """Set up a VPN chain using network namespaces"""
        try:
            # Clean up any existing configuration
            self.cleanup_vpn_chain()

            available_vpns = list(self.config.sections())
            if len(available_vpns) < num_hops:
                logger.error(f"Not enough VPN configs for {num_hops} hops")
                return False

            self.vpn_chain = random.sample(available_vpns, num_hops)

            # Create and configure network namespaces for each hop
            for i, vpn in enumerate(self.vpn_chain):
                namespace = f"{self.namespace_prefix}{i}"
                if not self._create_network_namespace(namespace):
                    self.cleanup_vpn_chain()
                    return False

                # Start OpenVPN in the namespace
                config_path = self.config[vpn]['config_path']
                if not os.path.isabs(config_path):
                    config_path = os.path.join(self.base_path, config_path)

                if not self._start_vpn_in_namespace(namespace, config_path, i):
                    self.cleanup_vpn_chain()
                    return False

                # Set up routing between namespaces
                if i > 0:
                    prev_namespace = f"{self.namespace_prefix}{i - 1}"
                    if not self._connect_namespaces(prev_namespace, namespace):
                        self.cleanup_vpn_chain()
                        return False

                # Debug information
                self._debug_namespace(namespace)

            # Set up final routing to direct traffic through the chain
            self._setup_chain_routing()
            logger.info(
                f"Successfully established VPN chain: {' -> '.join(self.vpn_chain)}")
            return True

        except Exception as e:
            logger.error(f"Error setting up VPN chain: {str(e)}")
            self.cleanup_vpn_chain()
            return False

    def _start_vpn_in_namespace(self, namespace, config_path, hop_index):
        """Start OpenVPN process in the specified namespace"""
        try:
            # Prepare OpenVPN configuration
            temp_config = self._prepare_vpn_config(config_path, hop_index)
            temp_dir = os.path.dirname(temp_config)

            # Set up namespace DNS
            self._setup_namespace_dns(namespace)

            # Create TUN device
            try:
                subprocess.run([
                    "sudo", "ip", "netns", "exec", namespace,
                    "ip", "tuntap", "add", "dev", "tun0", "mode", "tun"
                ], check=True)
                subprocess.run([
                    "sudo", "ip", "netns", "exec", namespace,
                    "ip", "link", "set", "dev", "tun0", "up"
                ], check=True)
            except subprocess.CalledProcessError:
                logger.warning("TUN device might already exist, continuing...")

            # Start OpenVPN with minimal options
            cmd = [
                "sudo", "ip", "netns", "exec", namespace,
                "openvpn",
                "--config", temp_config,
                "--dev", "tun0",
                "--daemon",
                "--log", os.path.join(self.base_path, "logs", f"openvpn-{namespace}.log"),
                "--status", os.path.join(self.base_path, "logs", f"openvpn-status-{namespace}.log"),
                "--writepid", os.path.join(self.base_path, "logs", f"openvpn-{namespace}.pid"),
                "--verb", "4"
            ]

            # Add auth if credentials exist
            creds_file = os.path.join(temp_dir, "vpn-credentials.txt")
            if os.path.exists(creds_file):
                cmd.extend(["--auth-user-pass", creds_file])

            logger.info(f"Starting OpenVPN with command: {' '.join(cmd)}")
            subprocess.run(cmd, check=True)

            # Wait for VPN to initialize
            max_attempts = 12
            for attempt in range(max_attempts):
                if self._verify_vpn_interface(namespace):
                    logger.info(f"VPN connection established in namespace {namespace}")
                    return True
                logger.info(f"Waiting for OpenVPN initialization (attempt {attempt + 1}/{max_attempts})")
                time.sleep(5)

            logger.error(f"OpenVPN failed to initialize in namespace {namespace}")
            return False

        except Exception as e:
            logger.error(f"Error starting VPN in namespace {namespace}: {str(e)}")
            return False

    def _prepare_vpn_config(self, config_path, hop_index):
        """Prepare OpenVPN configuration for chaining"""
        try:
            # Create temp directory
            temp_dir = os.path.join(self.base_path, 'config', 'temp', f'hop{hop_index}')
            os.makedirs(temp_dir, exist_ok=True)

            # Read original config
            with open(config_path, 'r') as f:
                config_lines = []
                for line in f:
                    # Skip routing commands we'll handle ourselves
                    if any(line.strip().startswith(x) for x in [
                        'route ',
                        'redirect-gateway',
                        'dhcp-option',
                        'pull-filter',
                        'route-nopull'
                    ]):
                        continue
                    config_lines.append(line.strip())

            # Add our configuration
            config_lines.extend([
                '',
                '# Added by VPN Chain Manager',
                'script-security 2',
                'route-nopull',
                'persist-tun',
                'auth-nocache'
            ])

            if hop_index == 0:
                config_lines.extend([
                    'route 0.0.0.0 0.0.0.0 10.200.1.1'
                ])

            # Write modified config
            temp_config = os.path.join(temp_dir, "config.ovpn")
            with open(temp_config, 'w') as f:
                f.write('\n'.join(config_lines))

            # Copy credentials file
            creds_file = os.path.join(os.path.dirname(config_path), "vpn-credentials.txt")
            if os.path.exists(creds_file):
                new_creds = os.path.join(temp_dir, "vpn-credentials.txt")
                with open(creds_file, 'r') as src, open(new_creds, 'w') as dst:
                    dst.write(src.read())
                os.chmod(new_creds, 0o600)

            # Set proper permissions
            os.chmod(temp_config, 0o600)
            return temp_config

        except Exception as e:
            logger.error(f"Failed to prepare VPN config: {str(e)}")
            raise

    def _setup_namespace_dns(self, namespace, dns_servers=None):
        """Set up DNS in the network namespace"""
        if dns_servers is None:
            dns_servers = ['8.8.8.8', '8.8.4.4']

        try:
            # Create resolv.conf directory for namespace if it doesn't exist
            resolv_dir = f"/etc/netns/{namespace}"
            os.makedirs(resolv_dir, exist_ok=True)

            # Write resolv.conf for namespace
            with open(f"{resolv_dir}/resolv.conf", 'w') as f:
                for server in dns_servers:
                    f.write(f"nameserver {server}\n")

            logger.info(f"Set up DNS in namespace {namespace}")
            return True
        except Exception as e:
            logger.error(
                f"Failed to set up DNS in namespace {namespace}: {str(e)}")
            return False

    def _connect_namespaces(self, ns1, ns2):
        """Connect two network namespaces for traffic forwarding"""
        try:
            # Create veth pair between namespaces
            veth1 = f"veth_{ns1}_{ns2}"
            veth2 = f"veth_{ns2}_{ns1}"

            subprocess.run(["sudo", "ip", "link", "add", veth1, "type", "veth", "peer", "name", veth2], check=True)
            subprocess.run(["sudo", "ip", "link", "set", veth1, "netns", ns1], check=True)
            subprocess.run(["sudo", "ip", "link", "set", veth2, "netns", ns2], check=True)

            # Configure IP addresses
            ip_prefix = f"10.{len(self.virtual_interfaces) + 1}"
            subprocess.run(["sudo", "ip", "netns", "exec", ns1, "ip", "addr", "add", f"{ip_prefix}.1.1/24", "dev", veth1], check=True)
            subprocess.run(["sudo", "ip", "netns", "exec", ns2, "ip", "addr", "add", f"{ip_prefix}.2.1/24", "dev", veth2], check=True)

            # Enable interfaces
            subprocess.run(["sudo", "ip", "netns", "exec", ns1, "ip", "link", "set", veth1, "up"], check=True)
            subprocess.run(["sudo", "ip", "netns", "exec", ns2, "ip", "link", "set", veth2, "up"], check=True)

            # Add routing
            subprocess.run(["sudo", "ip", "netns", "exec", ns1, "ip", "route", "add", "default", "via", f"{ip_prefix}.1.2"], check=True)

            self.virtual_interfaces.append((veth1, veth2))
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to connect namespaces {ns1} and {ns2}: {str(e)}")
            return False

    def _setup_chain_routing(self):
        """Set up final routing to direct traffic through the VPN chain"""
        try:
            # Enable IP forwarding
            subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)

            # Set up NAT for the first namespace
            # first_ns = f"{self.namespace_prefix}0"
            subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.200.1.0/24", "-j", "MASQUERADE"], check=True)

            # Add default route to the VPN chain
            subprocess.run(["sudo", "ip", "route", "add", "default", "via", "10.200.1.2"], check=True)

            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to set up chain routing: {e}")
            return False

    def cleanup_vpn_chain(self):
        """Clean up any running OpenVPN instances"""
        try:
            # Kill OpenVPN processes
            subprocess.run(["sudo", "killall", "openvpn"], check=False)

            # Remove virtual interfaces
            for veth1, veth2 in self.virtual_interfaces:
                subprocess.run(["sudo", "ip", "link", "delete", veth1], check=False)

            # Remove network namespaces
            for i in range(len(self.vpn_chain)):
                namespace = f"{self.namespace_prefix}{i}"
                subprocess.run(["sudo", "ip", "netns", "delete", namespace], check=False)

            # Clean up routing rules
            subprocess.run(["sudo", "iptables", "-t", "nat", "-F"], check=False)

            self.virtual_interfaces = []
            self.vpn_chain = []
            logger.info("VPN chain cleaned up")

        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")

    def _verify_vpn_interface(self, namespace):
        """Verify VPN interface is up and working"""
        try:
            # Check tun0 exists and is UP
            result = subprocess.run([
                "sudo", "ip", "netns", "exec", namespace,
                "ip", "link", "show", "tun0"
            ], capture_output=True, text=True, check=True)

            if "state UP" not in result.stdout:
                return False

            # Check if we can ping through tun0
            result = subprocess.run([
                "sudo", "ip", "netns", "exec", namespace,
                "ping", "-c", "1", "-W", "3", "-I", "tun0", "8.8.8.8"
            ], capture_output=True)

            return result.returncode == 0
        except Exception as e:
            logger.error(f"Failed to verify VPN interface: {e}")
            return False

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

    def _debug_namespace(self, namespace):
        """Debug network namespace configuration"""
        debug_commands = [
            ["ip", "link", "show"],  # Show interfaces
            ["ip", "addr", "show"],  # Show addresses
            ["ip", "route", "show"],  # Show routes
            ["cat", "/etc/resolv.conf"],  # Show DNS config
            ["ping", "-c1", "-W2", "8.8.8.8"],  # Test connectivity
            ["ss", "-tupln"],  # Show listening ports
        ]

        logger.info(f"=== Debug information for namespace {namespace} ===")
        for cmd in debug_commands:
            try:
                full_cmd = ["sudo", "ip", "netns", "exec", namespace] + cmd
                result = subprocess.run(full_cmd, capture_output=True,
                                        text=True)
                logger.info(f"Command: {' '.join(cmd)}")
                logger.info(f"Output:\n{result.stdout}")
                if result.stderr:
                    logger.info(f"Errors:\n{result.stderr}")
            except Exception as e:
                logger.error(f"Failed to run debug command {cmd}: {str(e)}")
        logger.info("=== End debug information ===")