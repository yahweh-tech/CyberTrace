import hashlib
import math
import os
import re
from datetime import datetime, timezone

from .models import BinaryAnalysis


class BinaryAnalysisError(Exception):
    """Raised when binary analysis fails."""


# Heuristic rule definitions for suspicious Windows API calls
SUSPICIOUS_API_RULES = [
    {
        "category": "Process Injection & Memory Tampering",
        "severity": "CRITICAL",
        "mitre_id": "T1055",
        "mitre_name": "Process Injection",
        "description": "Allocates or writes to memory of remote processes, typical of shellcode injection or process hollowing.",
        "apis": {
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "QueueUserAPC",
            "SetThreadContext", "ResumeThread", "RtlCreateUserThread"
        },
    },
    {
        "category": "Anti-Analysis & Evasion",
        "severity": "HIGH",
        "mitre_id": "T1497 / T1622",
        "mitre_name": "Virtualization/Sandbox Evasion & Debugger Evasion",
        "description": "Checks for debugger, hypervisor, or analyst monitoring environments to alter behavior.",
        "apis": {
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "OutputDebugStringA", "OutputDebugStringW", "FindWindowA", "FindWindowW",
            "GetTickCount", "QueryPerformanceCounter", "ZwSetInformationThread"
        },
    },
    {
        "category": "Keylogging & Input Capture",
        "severity": "HIGH",
        "mitre_id": "T1056.001",
        "mitre_name": "Keylogging",
        "description": "Installs global hooks or polls keyboard states to intercept keystrokes and credentials.",
        "apis": {
            "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
            "GetKeyState", "RegisterRawInputDevices", "GetKeyboardState"
        },
    },
    {
        "category": "Command & Control / Network Exfiltration",
        "severity": "HIGH",
        "mitre_id": "T1071 / T1105",
        "mitre_name": "Application Layer Protocol & Ingress Tool Transfer",
        "description": "Establishes socket connections, downloads payloads, or communicates with external servers.",
        "apis": {
            "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
            "HttpSendRequestA", "HttpSendRequestW", "URLDownloadToFileA", "URLDownloadToFileW",
            "WSAStartup", "socket", "connect", "send", "recv", "WinHttpOpen", "WinHttpConnect"
        },
    },
    {
        "category": "Cryptographic Primitives / Ransomware Indicator",
        "severity": "HIGH",
        "mitre_id": "T1486",
        "mitre_name": "Data Encrypted for Impact",
        "description": "Uses Windows CryptoAPI/CNG to encrypt or decrypt files and memory blocks.",
        "apis": {
            "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA", "CryptAcquireContextW",
            "BCryptEncrypt", "BCryptDecrypt", "CryptGenKey", "CryptDeriveKey"
        },
    },
    {
        "category": "Persistence & Service Installation",
        "severity": "MEDIUM",
        "mitre_id": "T1547 / T1543",
        "mitre_name": "Boot or Logon Autostart Execution & Create Service",
        "description": "Creates system services or writes to auto-run registry keys to survive reboots.",
        "apis": {
            "RegSetValueExA", "RegSetValueExW", "CreateServiceA", "CreateServiceW",
            "RegCreateKeyExA", "RegCreateKeyExW", "OpenSCManagerA", "OpenSCManagerW"
        },
    },
    {
        "category": "Privilege Escalation & Token Manipulation",
        "severity": "HIGH",
        "mitre_id": "T1134",
        "mitre_name": "Access Token Manipulation",
        "description": "Inspects or alters security access tokens to impersonate SYSTEM or administrator rights.",
        "apis": {
            "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA",
            "LookupPrivilegeValueW", "DuplicateTokenEx", "ImpersonateLoggedOnUser"
        },
    },
    {
        "category": "Dynamic API Resolving (Evasion)",
        "severity": "MEDIUM",
        "mitre_id": "T1027.007",
        "mitre_name": "Dynamic API Resolution",
        "description": "Dynamically looks up API functions at runtime to hide intentions from static IAT analysis.",
        "apis": {
            "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress"
        },
    },
]

KNOWN_PACKER_SECTIONS = {
    "upx0", "upx1", "upx2", ".aspack", ".mpress1", ".mpress2",
    ".themida", ".vmp0", ".vmp1", ".nsp0", ".nsp1", ".petite",
    ".fsg", ".meow", ".pecrypt", "pec2"
}

IP_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
URL_REGEX = re.compile(r"https?://[a-zA-Z0-9\.\-_]+(?::\d+)?(?:/[a-zA-Z0-9_\-\./\?%&=]*)?", re.IGNORECASE)
DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|xyz|cc|top|info|biz|co|cn|me|tk|ml|ga|cf)\b", re.IGNORECASE)


class ReverseEngineeringService:

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of a byte stream (0.0 to 8.0)."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        for count in counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    @staticmethod
    def extract_strings(data: bytes, min_len: int = 4, max_count: int = 200) -> list[str]:
        """Extract ASCII and UTF-16LE printable strings from binary data."""
        results = set()
        # ASCII printable strings
        ascii_matches = re.finditer(b"[\x20-\x7e]{" + str(min_len).encode() + b",}", data)
        for m in ascii_matches:
            results.add(m.group(0).decode("ascii", errors="ignore"))
            if len(results) >= max_count:
                break

        # UTF-16LE strings
        if len(results) < max_count:
            wide_pattern = re.compile(b"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + b",}")
            for m in wide_pattern.finditer(data):
                try:
                    results.add(m.group(0).decode("utf-16le", errors="ignore"))
                except Exception:
                    pass
                if len(results) >= max_count:
                    break

        return sorted(list(results))

    @staticmethod
    def extract_iocs(strings: list[str]) -> dict:
        """Filter extracted strings for actionable network IOCs (IPs, URLs, Domains)."""
        ips = set()
        urls = set()
        domains = set()

        for s in strings:
            for ip in IP_REGEX.findall(s):
                if not ip.startswith(("0.", "127.", "255.", "224.")):
                    ips.add(ip)
            for url in URL_REGEX.findall(s):
                urls.add(url)
            for dom in DOMAIN_REGEX.findall(s):
                if not dom.endswith((".dll", ".exe", ".png", ".jpg", ".txt")):
                    domains.add(dom.lower())

        return {
            "ips": sorted(list(ips))[:25],
            "urls": sorted(list(urls))[:25],
            "domains": sorted(list(domains))[:25],
        }

    @classmethod
    def disassemble_pe_entrypoint(cls, pe, raw_bytes: bytes, is_64bit: bool) -> list[dict]:
        """Disassemble entry point instructions using Capstone engine."""
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
        except ImportError:
            return []

        try:
            entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            image_base = pe.OPTIONAL_HEADER.ImageBase
            entry_offset = pe.get_offset_from_rva(entry_rva)
            code_slice = raw_bytes[entry_offset:entry_offset + 128]
            if not code_slice:
                return []

            mode = CS_MODE_64 if is_64bit else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)
            instructions = []
            for instr in md.disasm(code_slice, image_base + entry_rva):
                instructions.append({
                    "address": f"0x{instr.address:08X}",
                    "mnemonic": instr.mnemonic,
                    "op_str": instr.op_str,
                    "bytes": instr.bytes.hex(),
                })
                if len(instructions) >= 25:
                    break
            return instructions
        except Exception:
            return []

    @classmethod
    def analyze_bytes(cls, raw_bytes: bytes, file_name: str) -> dict:
        """Run deep static triage and reverse engineering heuristics on binary data."""
        file_size = len(raw_bytes)
        if file_size == 0:
            raise BinaryAnalysisError("Uploaded sample is empty (0 bytes).")

        md5 = hashlib.md5(raw_bytes).hexdigest()
        sha1 = hashlib.sha1(raw_bytes).hexdigest()
        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        overall_entropy = cls.calculate_entropy(raw_bytes)

        # Basic Format Sniffing
        is_pe = raw_bytes.startswith(b"MZ")
        is_elf = raw_bytes.startswith(b"\x7fELF")
        is_script = raw_bytes.startswith((b"#!", b"rem ", b"@echo off", b"param(", b"powershell"))

        file_type = "Binary / Data File"
        architecture = "Unknown"
        subsystem = "N/A"
        entry_point = "N/A"
        image_base = "N/A"
        imphash = ""
        compile_time = "N/A"
        is_packed = False
        packer_name = ""
        sections_data = []
        imports_data = []
        exports_data = []
        disassembly_data = []

        all_imported_apis = set()

        if is_pe:
            try:
                import pefile
                pe = pefile.PE(data=raw_bytes, fast_load=False)

                is_64bit = pe.FILE_HEADER.Machine == 0x8664  # IMAGE_FILE_MACHINE_AMD64
                if is_64bit:
                    architecture = "x86-64 (AMD64)"
                    file_type = "Windows PE32+ (64-bit)"
                elif pe.FILE_HEADER.Machine == 0x014c:  # IMAGE_FILE_MACHINE_I386
                    architecture = "x86 (32-bit)"
                    file_type = "Windows PE32 (32-bit)"
                elif pe.FILE_HEADER.Machine == 0xAA64:
                    architecture = "ARM64"
                    file_type = "Windows PE (ARM64)"
                else:
                    architecture = f"Machine 0x{pe.FILE_HEADER.Machine:X}"
                    file_type = "Windows PE Binary"

                # Subsystem
                sub_val = getattr(pe.OPTIONAL_HEADER, "Subsystem", None)
                if sub_val == 2:
                    subsystem = "Windows GUI"
                elif sub_val == 3:
                    subsystem = "Windows CUI (Console)"
                elif sub_val == 1:
                    subsystem = "Native / Driver"
                elif sub_val:
                    subsystem = f"Subsystem {sub_val}"

                entry_point = f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}"
                image_base = f"0x{pe.OPTIONAL_HEADER.ImageBase:08X}"

                # Timestamp
                try:
                    ts = pe.FILE_HEADER.TimeDateStamp
                    compile_time = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                except Exception:
                    compile_time = "Invalid / Obfuscated Timestamp"

                # Imphash
                try:
                    imphash = pe.get_imphash() or ""
                except Exception:
                    imphash = ""

                # Sections analysis & Entropy
                for sec in pe.sections:
                    try:
                        sec_name = sec.Name.decode("utf-8", errors="ignore").strip("\x00")
                    except Exception:
                        sec_name = str(sec.Name)
                    sec_data = sec.get_data()
                    sec_entropy = cls.calculate_entropy(sec_data)

                    is_suspicious_sec = False
                    low_name = sec_name.lower()
                    if sec_entropy > 7.1 or low_name in KNOWN_PACKER_SECTIONS:
                        is_suspicious_sec = True
                        is_packed = True
                        if low_name in KNOWN_PACKER_SECTIONS:
                            packer_name = f"Detected signature: {sec_name}"

                    sections_data.append({
                        "name": sec_name or "[anonymous]",
                        "virtual_address": f"0x{sec.VirtualAddress:08X}",
                        "virtual_size": sec.Misc_VirtualSize,
                        "raw_size": sec.SizeOfRawData,
                        "entropy": sec_entropy,
                        "is_high_entropy": sec_entropy > 7.1,
                        "is_suspicious": is_suspicious_sec,
                    })

                # Imports parsing
                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode("utf-8", errors="ignore") if entry.dll else "unknown.dll"
                        functions = []
                        for imp in entry.imports:
                            if imp.name:
                                func_name = imp.name.decode("utf-8", errors="ignore")
                                functions.append(func_name)
                                all_imported_apis.add(func_name)
                            elif imp.ordinal:
                                functions.append(f"Ordinal#{imp.ordinal}")
                        imports_data.append({
                            "dll": dll_name,
                            "count": len(functions),
                            "functions": functions[:40],
                        })

                # Exports parsing
                if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if exp.name:
                            exports_data.append(exp.name.decode("utf-8", errors="ignore"))
                        elif exp.ordinal:
                            exports_data.append(f"Ordinal#{exp.ordinal}")

                # Disassemble Entry Point
                disassembly_data = cls.disassemble_pe_entrypoint(pe, raw_bytes, is_64bit)

            except Exception as pe_err:
                file_type = "Corrupted or Protected PE Header"
                packer_details = str(pe_err)
        elif is_elf:
            file_type = "Linux ELF Executable"
            if len(raw_bytes) > 4:
                architecture = "64-bit" if raw_bytes[4] == 2 else "32-bit"
        elif is_script:
            file_type = "Script / Macro / Text Artifact"

        # Heuristic Capability & ATT&CK Matrix Mapping
        matched_capabilities = []
        threat_score = 0

        for rule in SUSPICIOUS_API_RULES:
            found_apis = sorted(list(all_imported_apis.intersection(rule["apis"])))
            if found_apis:
                matched_capabilities.append({
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "mitre_id": rule["mitre_id"],
                    "mitre_name": rule["mitre_name"],
                    "description": rule["description"],
                    "detected_apis": found_apis,
                })
                if rule["severity"] == "CRITICAL":
                    threat_score += 30
                elif rule["severity"] == "HIGH":
                    threat_score += 20
                else:
                    threat_score += 10

        # Factor in Packing & Entropy
        if is_packed:
            threat_score += 25
            if not packer_name:
                packer_name = "Heuristic High-Entropy / Section Packing"
        elif overall_entropy > 7.2:
            threat_score += 15

        # Strings & IOC extraction
        extracted_strings = cls.extract_strings(raw_bytes)
        iocs = cls.extract_iocs(extracted_strings)

        if iocs["ips"] or iocs["urls"]:
            threat_score += 10

        threat_score = min(threat_score, 100)

        # Determine Threat Level
        if threat_score >= 70:
            threat_level = "CRITICAL"
        elif threat_score >= 45:
            threat_level = "HIGH"
        elif threat_score >= 20:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        return {
            "file_name": file_name,
            "file_size": file_size,
            "file_type": file_type,
            "architecture": architecture,
            "subsystem": subsystem,
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "imphash": imphash,
            "entropy": overall_entropy,
            "is_packed": is_packed,
            "packer_name": packer_name,
            "entry_point": entry_point,
            "image_base": image_base,
            "compile_time": compile_time,
            "threat_level": threat_level,
            "threat_score": threat_score,
            "sections_data": sections_data,
            "imports_data": imports_data,
            "exports_data": exports_data,
            "suspicious_capabilities": matched_capabilities,
            "extracted_iocs": iocs,
            "disassembly_data": disassembly_data,
            "top_strings": extracted_strings[:60],
        }

    @classmethod
    def save_analysis(cls, investigation, sample_file, source_label="", user=None) -> BinaryAnalysis:
        """Analyze uploaded file and persist BinaryAnalysis model + timeline log."""
        raw_bytes = sample_file.read()
        file_name = source_label.strip() or os.path.basename(sample_file.name)

        parsed = cls.analyze_bytes(raw_bytes, file_name)

        analysis = BinaryAnalysis.objects.create(
            investigation=investigation,
            sample_file=sample_file,
            file_name=parsed["file_name"],
            file_size=parsed["file_size"],
            file_type=parsed["file_type"],
            architecture=parsed["architecture"],
            subsystem=parsed["subsystem"],
            md5=parsed["md5"],
            sha1=parsed["sha1"],
            sha256=parsed["sha256"],
            imphash=parsed["imphash"],
            entropy=parsed["entropy"],
            is_packed=parsed["is_packed"],
            packer_name=parsed["packer_name"],
            entry_point=parsed["entry_point"],
            image_base=parsed["image_base"],
            compile_time=parsed["compile_time"],
            threat_level=parsed["threat_level"],
            threat_score=parsed["threat_score"],
            sections_data=parsed["sections_data"],
            imports_data=parsed["imports_data"],
            exports_data=parsed["exports_data"],
            suspicious_capabilities=parsed["suspicious_capabilities"],
            extracted_iocs=parsed["extracted_iocs"],
            disassembly_data=parsed["disassembly_data"],
            top_strings=parsed["top_strings"],
        )

        if user:
            from timeline.services import TimelineService
            TimelineService.log(
                investigation,
                user,
                "Reverse Engineering / Binary Triage Completed",
                f"Analyzed {analysis.file_name} [{analysis.threat_level} - Risk {analysis.threat_score}/100]. "
                f"SHA256: {analysis.sha256[:16]}... Found {len(analysis.suspicious_capabilities)} suspicious capability profiles.",
            )

        return analysis
