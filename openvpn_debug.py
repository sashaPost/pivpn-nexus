import os
import subprocess
import sys


def check_openvpn_config(config_file):
    required_files = []
    with open(config_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('ca '):
                required_files.append(line.split()[1])
            elif line.startswith('cert '):
                required_files.append(line.split()[1])
            elif line.startswith('key '):
                required_files.append(line.split()[1])
            elif line.startswith('tls-auth '):
                required_files.append(line.split()[1])
            elif line.startswith('tls-crypt '):
                required_files.append(line.split()[1])

    print(f"\nChecking OpenVPN configuration: {config_file}")
    print("-" * 50)

    # Check for auth-user-pass directive
    with open(config_file, 'r') as f:
        config_content = f.read()
        if 'auth-user-pass' in config_content:
            print("Auth-user-pass directive found - credentials file required")
            if os.path.exists('/home/anyone/.prjcts/pivpn-nexus/config/test/vpn-credentials.txt'):
                print("✓ Credentials file found")
                # Check credentials file format
                with open('/home/anyone/.prjcts/pivpn-nexus/config/test/vpn-credentials.txt', 'r') as cred_file:
                    lines = cred_file.readlines()
                    if len(lines) == 2:
                        print("✓ Credentials file format appears correct")
                    else:
                        print(
                            "✗ Credentials file should contain exactly 2 lines")
            else:
                print("✗ Missing vpn-credentials.txt file")

    # Check for required files
    print("\nChecking required certificate/key files:")
    config_dir = os.path.dirname(config_file)
    for file in required_files:
        file_path = os.path.join(config_dir, file)
        if os.path.exists(file_path):
            print(f"✓ Found: {file}")
        else:
            print(f"✗ Missing: {file}")

    # Check file permissions
    print("\nChecking file permissions:")
    for file in [config_file] + [os.path.join(config_dir, f) for f in
                                 required_files]:
        if os.path.exists(file):
            perms = oct(os.stat(file).st_mode)[-3:]
            print(f"{file}: {perms}")

    # Test network connectivity
    print("\nTesting network connectivity to VPN server:")
    with open(config_file, 'r') as f:
        for line in f:
            if line.startswith('remote '):
                _, host, port = line.split()
                try:
                    subprocess.run(['ping', '-c', '1', host], check=True,
                                   capture_output=True)
                    print(f"✓ Can reach {host}")
                except subprocess.CalledProcessError:
                    print(f"✗ Cannot reach {host}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python openvpn_debug.py <config_file>")
        sys.exit(1)
    check_openvpn_config(sys.argv[1])