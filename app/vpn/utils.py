"""Utility functions for VPN management."""

from pathlib import Path
import subprocess
from typing import Optional, Tuple
import time

from .exceptions import VPNError
from ..logging_utility import logger


def run_command(cmd: list[str], check: bool = True, use_sudo: bool = False) -> Tuple[str, str]:
    """
    Run shell command and return output.

    Args:
        cmd: Command as list of strings
        check: Whether to raise exception on error
        use_sudo: Whether to prepend sudo to the command

    Returns:
        Tuple of (stdout, stderr)
    """
    try:
        if use_sudo and cmd[0] != "sudo":
            cmd = ["sudo"] + cmd

        result = subprocess.run(cmd, capture_output=True, text=True, check=check)
        return result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        if check:
            raise VPNError(f"Command failed: {' '.join(cmd)}\n{e.stderr}")
        return e.stdout, e.stderr


def wait_for_interface(interface: str, max_attempts: int = 30) -> bool:
    """
    Wait for network interface to become available.

    Args:
        interface: Interface name
        max_attempts: Maximum number of attempts

    Returns:
        bool: True if interface is ready
    """
    logger.info(f"Waiting for {interface} to be ready...")
    for i in range(max_attempts):
        try:
            stdout, _ = run_command(
                ["sudo", "ip", "addr", "show", interface],
                check=False,
                use_sudo=True
            )
            if "inet" in stdout:
                logger.info(f"{interface} is ready with IP configuration")
                return True
        except subprocess.CalledProcessError:
            pass
        time.sleep(1)
        logger.info(f"Waiting for {interface}... ({i + 1}/{max_attempts})")
    return False


# def get_interface_ip(interface: str) -> Optional[str]:
#     """
#     Get IP address for interface.
#
#     Args:
#         interface: Interface name
#
#     Returns:
#         str: IP address or None if failed
#     """
#     try:
#         result = subprocess.run(
#             ["sudo", "curl", "--interface", interface, "--silent", "--max-time", "10", "ifconfig.me"],
#             capture_output=True,
#             text=True,
#             check=True
#         )
#         return result.stdout.strip()
#     except subprocess.CalledProcessError:
#         return None


def log_vpn_output(log_file: str) -> None:
    """
    Log OpenVPN output from log file.

    Args:
        log_file: Path to log file
    """
    log_path = Path(log_file)
    # if os.path.exists(log_file):
    if log_path.exists():
        with open(log_file, "r") as f:
            vpn_output = f.read()
            logger.error(f"OpenVPN output:\n{vpn_output}")