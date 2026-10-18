import os
import random

out_dir = os.path.join(r"c:\Users\pravi\OneDrive\文档\adl2\adl\media", "sample_test_files")
os.makedirs(out_dir, exist_ok=True)

# 1. PE executable test sample (using whoami.exe with simulated IOC overlay strings)
src_exe = r"C:\Windows\System32\whoami.exe"
dst_exe = os.path.join(out_dir, "sample_windows_beacon.exe")
if os.path.exists(src_exe):
    with open(src_exe, "rb") as f:
        content = f.read()
    # Harmless simulated overlay for IOC extractor testing
    overlay = (
        b"\n\x00--- SIMULATED THREAT LAB IOCS ---\x00\n"
        b"C2_HOST: 185.220.101.5\x00\n"
        b"C2_DOMAIN: command-control-beacon.com\x00\n"
        b"DROP_URL: https://payload-delivery-network.org/stage2.bin\x00\n"
        b"REG_KEY: HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\TelemetryService\x00\n"
    )
    with open(dst_exe, "wb") as f:
        f.write(content + overlay)
    print("Created sample_windows_beacon.exe successfully")

# 2. PowerShell Dropper Script
ps1_path = os.path.join(out_dir, "sample_obfuscated_dropper.ps1")
ps1_content = """# [SIMULATED DEFENSIVE TEST SAMPLE - HARMFUL CODE DISABLED]
# CyberTrace Forensics Test Artifact
$C2_Server = "198.51.100.42"
$DropUrl = "https://dark-nexus-c2.net/endpoint"
$FallbackHost = "threat-intel-lab.org"

Write-Output "Simulated dropper payload executing triage check..."
Write-Output "Connecting to $C2_Server via port 443"
"""
with open(ps1_path, "w", encoding="utf-8") as f:
    f.write(ps1_content)
print("Created sample_obfuscated_dropper.ps1 successfully")

# 3. High Entropy Packed / Encrypted Artifact (.bin)
bin_path = os.path.join(out_dir, "sample_high_entropy_packed.bin")
random.seed(42)
rand_data = bytes([random.randint(0, 255) for _ in range(16384)])
header = b"MZ\x90\x00UPX0_ENCRYPTED_HEADER_TEST\x00C2_IP: 203.0.113.88\x00"
with open(bin_path, "wb") as f:
    f.write(header + rand_data)
print("Created sample_high_entropy_packed.bin successfully")
