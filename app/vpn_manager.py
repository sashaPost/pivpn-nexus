import configparser
import datetime
import logging
import random
import subprocess
import time
import dns.resolver
import threading

import requests
import psutil
import schedule


class AdvancedVPNNexusManager:
    def __init__(self, config_file: str):
        self.config = self._load_config(config_file)
        self.logger = self._setup_logger()
        self.vpn_chain = []
        self.traffic_log = {}
        self.dns_leak_status = True
        self.pfs_enabled = False

    @staticmethod
    def _load_config(config_file: str) -> configparser.ConfigParser:
        config = configparser.ConfigParser()
        config.read(config_file)
        return config

    @staticmethod
    def _setup_logger() -> logging.Logger:
        logger = logging.getLogger('VPNNexusManager')
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler('/var/log/vpn_nexus_manager.log')
        # formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s:%(lineno)d - %(pathname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def setup_enhanced_encryption(self):
        for vpn in self.config.sections():
            config_path = self.config[vpn]['config_path']
            self._update_openvpn_config(config_path)
        self.logger.info("Enhanced encryption setup completed")

    def _update_openvpn_config(self, config_path: str):
        with open(config_path, 'a') as config_file:
            config_file.write("\ncipher AES-256-GCM")
            config_file.write("\nauth SHA256")
            config_file.write("\ntls-version-min 1.2")
            config_file.write("\ntls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384")
            config_file.write("\nncp-ciphers AES-256-GCM:AES-256-CBC")
        self.logger.info(f"Updated OpenVPN config: {config_path}")

    def setup_vpn_chain(self, num_hops=2):
        available_vpns = self.config.sections()
        if len(available_vpns) < num_hops:
            self.logger.error(f"Not enough VPN configs for {num_hops} hops")
            return False

        self.vpn_chain = random.sample(available_vpns, num_hops)
        for i, vpn in enumerate(self.vpn_chain):
            config_path = self.config[vpn]['config_path']
            if i==0:
                subprocess.run(["sudo", "openvpn", "--config", config_path, "--daemon"], check=True)
            else:
                time.sleep(10)
                subprocess.run(["sudo", "openvpn", "--config", config_path, "--daemon"], check=True)

        self.logger.info(f"VPN chain established: {' -> '.join(self.vpn_chain)}")
        return True

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
        self.logger.info(f"Optimized VPN chain: {' -> '.join(self.vpn_chain)}")

    def measure_latency(self):
        try:
            start = time.time()
            requests.get('https://www.google.com')
            end = time.time()
            return end - start
        except Exception as e:
            self.logger.error(f"Failed to measure latency: {e}")
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
            self.logger.info("DNS over HTTPS setup completed")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to setup DNS over HTTPS: {str(e)}")
            return False

    def check_dns_leak(self):
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8']
            answers = resolver.resolve('whoami.akamai.net', 'A')
            ip = answers[0].to_text()

            if ip == self.get_current_ip():
                self.dns_leak_status = False
                self.logger.warning("DNS leak detected")
            else:
                self.dns_leak_status = True
                self.logger.info("No DNS leak detected")
        except Exception as e:
            self.logger.error(f"Error checking DNS leaks: {str(e)}")

    def enable_pfs(self):
        for vpn in self.config.sections():
            config_path = self.config[vpn]['config_path']
            with open(config_path, 'a') as f:
                f.write("\ntls-crypt ta.key")
        self.pfs_enabled = True
        self.logger.info("Perfect Forward Secrecy enabled")

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
        return list(self.config.sections())

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
            self.logger.error(f"Failed to get current IP: {str(e)}")
            return None