#!/usr/bin/env python3

from app.vpn.manager import AdvancedVPNNexusManager
import time
import sys
import subprocess


def test_vpn_chain():
    """Test VPN chain setup and verification"""
    initial_ip = subprocess.run(["curl", "ifconfig.me"], capture_output=True, text=True)
    print(f"Initial IP: {initial_ip.stdout.strip()}")

    # Initialize manager
    vpn_manager = AdvancedVPNNexusManager('config/vpn_nexus_manager.conf')
    print("VPN Manager initialized")

    try:
        # Set up VPN chain
        print("\nSetting up VPN chain...")
        success = vpn_manager.setup_vpn_chain(num_hops=2)

        if not success:
            print("Failed to set up VPN chain")
            return False

        print("VPN chain setup successful")

        # Test IP
        print("\nChecking current IP...")
        current_ip = vpn_manager.get_current_ip()
        if current_ip:
            print(f"Current IP: {current_ip}")
        else:
            print("Failed to get current IP")
            return False

        # Wait a bit to check stability
        print("\nWaiting 10 seconds to verify stability...")
        time.sleep(10)

        # Check IP again
        print("Checking IP again...")
        new_ip = vpn_manager.get_current_ip()
        if new_ip != current_ip:
            print(f"IP changed: {current_ip} -> {new_ip}")
            return False

        print("Connection stable")
        return True

    except Exception as e:
        print(f"Error during test: {str(e)}")
        return False

    finally:
        print("\nCleaning up...")
        vpn_manager.cleanup_vpn_chain()


if __name__ == '__main__':
    print("Starting VPN chain test\n")

    success = test_vpn_chain()

    print("\nTest result:", "SUCCESS" if success else "FAILURE")
    sys.exit(0 if success else 1)