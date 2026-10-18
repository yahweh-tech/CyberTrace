import re
from collections import Counter

from .models import PacketAnalysis


class PacketAnalysisError(Exception):
    """Raised when a capture file cannot be read or parsed."""


# --- SIP header extraction (applied to any UDP/TCP payload seen on SIP ports) ---

HEADER_PATTERNS = {
    "sip_method": re.compile(r"^(INVITE|REGISTER|BYE|ACK|OPTIONS|CANCEL)\s", re.MULTILINE | re.IGNORECASE),
    "call_id": re.compile(r"^Call-ID:\s*(.+)$", re.MULTILINE | re.IGNORECASE),
    "from_uri": re.compile(r"^From:\s*(.+)$", re.MULTILINE | re.IGNORECASE),
    "to_uri": re.compile(r"^To:\s*(.+)$", re.MULTILINE | re.IGNORECASE),
    "user_agent": re.compile(r"^User-Agent:\s*(.+)$", re.MULTILINE | re.IGNORECASE),
    "via_header": re.compile(r"^Via:\s*(.+)$", re.MULTILINE | re.IGNORECASE),
    "contact": re.compile(r"^Contact:\s*(.+)$", re.MULTILINE | re.IGNORECASE),
}

SIP_PORTS = {5060, 5061}

# Ports considered "normal" for their common protocols; anything a service
# is running on outside this set gets flagged as a heads-up, not a verdict.
COMMON_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 137, 138, 139,
    143, 161, 389, 443, 445, 465, 514, 587, 636, 993, 995,
    3306, 3389, 5060, 5061, 8080, 8443,
}

CREDENTIAL_PATTERN = re.compile(
    r"(password|passwd|pwd|authorization:\s*basic)\s*[:=]",
    re.IGNORECASE,
)


class PacketAnalysisService:

    @staticmethod
    def parse_sip_headers(raw_text):
        if not raw_text:
            return {}

        result = {}
        for key, pattern in HEADER_PATTERNS.items():
            match = pattern.search(raw_text)
            if match:
                result[key] = match.group(1).strip() if match.lastindex else match.group(0).strip()

        return result

    @staticmethod
    def _decode_payload(pkt):
        try:
            from scapy.packet import Raw
        except ImportError:
            return ""

        if pkt.haslayer(Raw):
            try:
                return bytes(pkt[Raw].load).decode("utf-8", errors="ignore")
            except Exception:
                return ""
        return ""

    @staticmethod
    def parse_pcap(file_path):
        """
        Parse a real .pcap/.pcapng file with scapy and extract genuine
        packet-level intelligence: protocol breakdown, top talkers, ports
        in use, and any SIP/VoIP signalling payloads.
        """
        try:
            from scapy.all import rdpcap
            from scapy.layers.inet import ICMP, IP, TCP, UDP
        except ImportError as exc:
            raise PacketAnalysisError(
                "scapy is not installed. Run: pip install scapy"
            ) from exc

        try:
            packets = rdpcap(file_path)
        except Exception as exc:
            raise PacketAnalysisError(f"Could not parse capture file: {exc}") from exc

        if len(packets) == 0:
            raise PacketAnalysisError("The capture file contains no packets.")

        protocol_counter = Counter()
        ip_counter = Counter()
        port_counter = Counter()
        unusual_ports = set()
        sip_payloads = []
        credential_hits = 0

        for pkt in packets:
            if pkt.haslayer(IP):
                ip_layer = pkt[IP]
                ip_counter[ip_layer.src] += 1
                ip_counter[ip_layer.dst] += 1

                if pkt.haslayer(TCP):
                    protocol_counter["TCP"] += 1
                    sport, dport = pkt[TCP].sport, pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    protocol_counter["UDP"] += 1
                    sport, dport = pkt[UDP].sport, pkt[UDP].dport
                elif pkt.haslayer(ICMP):
                    protocol_counter["ICMP"] += 1
                    sport = dport = None
                else:
                    protocol_counter["Other IP"] += 1
                    sport = dport = None

                for port in (sport, dport):
                    if port is None:
                        continue
                    port_counter[port] += 1

                # The lower of the two ports is almost always the "service"
                # side of the connection (the higher one is usually a
                # short-lived client port) — flag only that one as unusual,
                # so normal ephemeral client ports don't create noise.
                if sport is not None and dport is not None:
                    service_port = min(sport, dport)
                    if service_port not in COMMON_PORTS and service_port > 0:
                        unusual_ports.add(service_port)

                if sport in SIP_PORTS or dport in SIP_PORTS:
                    payload = PacketAnalysisService._decode_payload(pkt)
                    if payload:
                        sip_payloads.append(payload)
                        if CREDENTIAL_PATTERN.search(payload):
                            credential_hits += 1

            elif pkt.haslayer("ARP"):
                protocol_counter["ARP"] += 1
            else:
                protocol_counter["Other"] += 1

        combined_sip_text = "\n".join(sip_payloads)
        parsed_sip = PacketAnalysisService.parse_sip_headers(combined_sip_text)

        suspicious = []
        if credential_hits:
            suspicious.append(
                f"Possible cleartext credentials found in {credential_hits} SIP payload(s)"
            )
        if unusual_ports:
            shown = ", ".join(str(p) for p in sorted(unusual_ports)[:15])
            suspicious.append(f"Traffic seen on non-standard ports: {shown}")
        if sip_payloads:
            suspicious.append(f"{len(sip_payloads)} VoIP/SIP signalling packet(s) detected")

        top_ips = ", ".join(f"{ip} ({count})" for ip, count in ip_counter.most_common(10))
        protocol_summary = ", ".join(f"{proto}: {count}" for proto, count in protocol_counter.most_common())
        top_ports = ", ".join(str(p) for p, _ in port_counter.most_common(20))

        return {
            "packet_count": len(packets),
            "protocol_summary": protocol_summary or "No IP traffic recognized",
            "unique_ips": top_ips or "N/A",
            "open_ports": top_ports or "N/A",
            "suspicious_flags": "; ".join(suspicious) if suspicious else "None detected",
            "sip_method": parsed_sip.get("sip_method", ""),
            "call_id": parsed_sip.get("call_id", ""),
            "from_uri": parsed_sip.get("from_uri", ""),
            "to_uri": parsed_sip.get("to_uri", ""),
            "user_agent": parsed_sip.get("user_agent", ""),
            "via_header": parsed_sip.get("via_header", ""),
            "contact": parsed_sip.get("contact", ""),
            "raw_headers": combined_sip_text[:5000],
        }

    @staticmethod
    def save_analysis(investigation, pcap_file, source_label="", user=None):
        analysis = PacketAnalysis.objects.create(
            investigation=investigation,
            pcap_file=pcap_file,
            source_label=source_label or getattr(pcap_file, "name", ""),
        )

        try:
            parsed = PacketAnalysisService.parse_pcap(analysis.pcap_file.path)
        except PacketAnalysisError:
            analysis.delete()
            raise

        analysis.packet_count = parsed["packet_count"]
        analysis.protocol_summary = parsed["protocol_summary"]
        analysis.unique_ips = parsed["unique_ips"]
        analysis.open_ports = parsed["open_ports"]
        analysis.suspicious_flags = parsed["suspicious_flags"]
        analysis.sip_method = parsed["sip_method"]
        analysis.call_id = parsed["call_id"]
        analysis.from_uri = parsed["from_uri"]
        analysis.to_uri = parsed["to_uri"]
        analysis.user_agent = parsed["user_agent"]
        analysis.via_header = parsed["via_header"]
        analysis.contact = parsed["contact"]
        analysis.raw_headers = parsed["raw_headers"]
        analysis.save()

        if user:
            from timeline.services import TimelineService

            TimelineService.log(
                investigation,
                user,
                "Packet Analysis Completed",
                f"Parsed {analysis.packet_count} packets from {analysis.source_label} "
                f"({analysis.protocol_summary}).",
            )

        return analysis
