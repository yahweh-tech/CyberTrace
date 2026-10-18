import re
from typing import Dict, List, Tuple
from .fixtures_data import ATLAS_TACTICS, ATLAS_TECHNIQUES
from .models import AtlasTactic, AtlasTechnique, AtlasAssessment, AtlasAssessmentTechnique


class AtlasService:
    @staticmethod
    def seed_atlas_data() -> Tuple[int, int]:
        """
        Seeds the MITRE ATLAS Tactics and Techniques into the database if not present.
        Returns (tactics_count, techniques_count).
        """
        tactics_created = 0
        techniques_created = 0

        for tactic_data in ATLAS_TACTICS:
            tactic_obj, created = AtlasTactic.objects.update_or_create(
                code=tactic_data["code"],
                defaults={
                    "name": tactic_data["name"],
                    "order": tactic_data["order"],
                    "icon": tactic_data["icon"],
                    "description": tactic_data["description"],
                },
            )
            if created:
                tactics_created += 1

        for tech_data in ATLAS_TECHNIQUES:
            try:
                tactic = AtlasTactic.objects.get(code=tech_data["tactic_code"])
                tech_obj, created = AtlasTechnique.objects.update_or_create(
                    code=tech_data["code"],
                    defaults={
                        "tactic": tactic,
                        "name": tech_data["name"],
                        "attack_surface": tech_data["attack_surface"],
                        "severity": tech_data["severity"],
                        "description": tech_data["description"],
                        "detection_guidance": tech_data["detection_guidance"],
                        "mitigation_guidance": tech_data["mitigation_guidance"],
                        "real_world_example": tech_data["real_world_example"],
                    },
                )
                if created:
                    techniques_created += 1
            except AtlasTactic.DoesNotExist:
                continue

        return tactics_created, techniques_created

    @staticmethod
    def calculate_risk(techniques: List[AtlasTechnique]) -> Tuple[int, str]:
        """
        Calculates composite AI Risk Score (0-100) and qualitative risk level.
        """
        if not techniques:
            return 0, "LOW"

        weights = {
            "CRITICAL": 35,
            "HIGH": 20,
            "MEDIUM": 10,
            "LOW": 5,
        }

        total_points = sum(weights.get(t.severity, 10) for t in techniques)
        # Cap at 100
        score = min(100, total_points)

        # Has any critical technique?
        has_critical = any(t.severity == "CRITICAL" for t in techniques)
        has_high = any(t.severity == "HIGH" for t in techniques)

        if score >= 70 or (has_critical and score >= 50):
            level = "CRITICAL"
        elif score >= 45 or has_critical or (has_high and len(techniques) >= 2):
            level = "HIGH"
        elif score >= 20 or has_high:
            level = "MEDIUM"
        else:
            level = "LOW"

        return score, level

    @staticmethod
    def analyze_payload(payload: str) -> List[Dict]:
        """
        Heuristic AI Threat Triage Engine:
        Scans incident payload or prompt text for known MITRE ATLAS attack indicators.
        Returns a list of suggested techniques with reasoning and match confidence.
        """
        if not payload or not payload.strip():
            return []

        text = payload.lower()
        findings = []

        patterns = [
            {
                "code": "AML.T0051.000",
                "regexes": [
                    r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|directives)",
                    r"disregard\s+(the\s+)?(rules|safety|guidelines)",
                    r"you\s+are\s+now\s+(unconstrained|jailbroken|free)",
                    r"system\s*override",
                    r"developer\s+mode\s+enabled",
                ],
                "confidence": "HIGH",
                "reason": "Direct Prompt Injection indicator detected (instruction override / developer mode command).",
            },
            {
                "code": "AML.T0054",
                "regexes": [
                    r"\bdan\b|do\s+anything\s+now",
                    r"pretend\s+you\s+have\s+no\s+(rules|limits|ethics)",
                    r"hypothetical\s+scenario\s+where\s+it\s+is\s+legal",
                    r"roleplay\s+as\s+an\s+evil|unfiltered",
                    r"bypass\s+(filter|moderation|guardrail)",
                    r"base64|rot13|hex-encoded",
                ],
                "confidence": "HIGH",
                "reason": "LLM Jailbreak pattern identified (DAN persona, hypothetical evasion, or obfuscation cues).",
            },
            {
                "code": "AML.T0056",
                "regexes": [
                    r"repeat\s+(the\s+)?(words|text|instructions)\s+above",
                    r"what\s+is\s+your\s+system\s+prompt",
                    r"print\s+your\s+initial\s+prompt",
                    r"output\s+verbatim\s+all\s+text\s+before",
                    r"reveal\s+(hidden|internal)\s+(rules|instructions)",
                ],
                "confidence": "HIGH",
                "reason": "System Prompt Extraction probe detected.",
            },
            {
                "code": "AML.T0012",
                "regexes": [
                    r"pickle",
                    r"__reduce__",
                    r"torch\.load",
                    r"joblib",
                    r"subprocess\.popen",
                    r"os\.system",
                    r"\.pkl|\.bin|\.pt",
                ],
                "confidence": "HIGH",
                "reason": "Unsafe ML Model Deserialization indicator (pickle execution hook or unsafe binary model loader).",
            },
            {
                "code": "AML.T0051.001",
                "regexes": [
                    r"hidden\s+instruction",
                    r"markdown\s+injection",
                    r"invisible\s+text",
                    r"search_results\s*\[",
                    r"rag_context",
                    r"retrieved\s+document\s+override",
                ],
                "confidence": "MEDIUM",
                "reason": "Indirect Prompt Injection / Context Tampering cue detected.",
            },
            {
                "code": "AML.T0029",
                "regexes": [
                    r"sponge\s+attack",
                    r"context\s+exhaustion",
                    r"quadratic\s+attention",
                    r"token\s+flood",
                    r"repeat\s+the\s+word\s+forever",
                ],
                "confidence": "MEDIUM",
                "reason": "Denial of ML Service / Sponge Attack pattern detected.",
            },
            {
                "code": "AML.T0024",
                "regexes": [
                    r"training\s+data\s+leak",
                    r"membership\s+inference",
                    r"extract\s+private\s+records",
                    r"memorization\s+probe",
                ],
                "confidence": "MEDIUM",
                "reason": "Training Data Leakage / Model Inversion probe detected.",
            },
        ]

        for p in patterns:
            matched = False
            for rgx in p["regexes"]:
                if re.search(rgx, text):
                    matched = True
                    break
            if matched:
                try:
                    tech = AtlasTechnique.objects.get(code=p["code"])
                    findings.append({
                        "technique": tech,
                        "confidence": p["confidence"],
                        "reason": p["reason"],
                    })
                except AtlasTechnique.DoesNotExist:
                    pass

        return findings

    @staticmethod
    def correlate_investigation_evidence(investigation) -> Dict:
        """
        Cross-correlates IP Intelligence, Domain Intelligence, and Packet Analysis
        artifacts from this investigation to recommend MITRE ATLAS techniques.
        """
        correlated_techniques = {}
        ip_evidence = []
        domain_evidence = []
        packet_evidence = []

        # 1. Correlate IP Intelligence
        for ip in investigation.ip_lookups.all():
            if ip.is_proxy:
                for code, conf, reason in [
                    ("AML.T0002", "HIGH", f"Anonymized proxy/VPN origin at {ip.ip_address} ({ip.isp}) used to conduct automated ML endpoint scans."),
                    ("AML.T0025", "MEDIUM", f"Proxy IP rotation from {ip.ip_address} matches distributed query patterns used for model extraction."),
                ]:
                    try:
                        tech = AtlasTechnique.objects.get(code=code)
                        if tech.id not in correlated_techniques:
                            correlated_techniques[tech.id] = {
                                "technique": tech,
                                "source": "IP Intelligence",
                                "confidence": conf,
                                "evidence": reason,
                            }
                    except AtlasTechnique.DoesNotExist:
                        pass
            else:
                try:
                    tech = AtlasTechnique.objects.get(code="AML.T0002")
                    if tech.id not in correlated_techniques:
                        correlated_techniques[tech.id] = {
                            "technique": tech,
                            "source": "IP Intelligence",
                            "confidence": "LOW",
                            "evidence": f"Origin IP {ip.ip_address} ({ip.country}, {ip.isp}) targeting ML infrastructure.",
                        }
                except AtlasTechnique.DoesNotExist:
                    pass

            ip_evidence.append({
                "ip": ip.ip_address,
                "location": f"{ip.city or 'Unknown'}, {ip.country or 'Unknown'}",
                "isp": ip.isp or "Unknown ISP",
                "is_proxy": ip.is_proxy,
            })

        # 2. Correlate Domain Intelligence
        for dom in investigation.domain_lookups.all():
            domain_evidence.append({
                "domain": dom.domain,
                "registrar": dom.registrar or "Unknown Registrar",
                "creation_date": str(dom.creation_date) if dom.creation_date else "Unknown",
            })
            for code, conf, reason in [
                ("AML.T0024", "HIGH", f"Target domain {dom.domain} (Registrar: {dom.registrar or 'N/A'}) identified as exfiltration C2 drop for stolen model context or PII."),
                ("AML.T0010", "MEDIUM", f"Domain {dom.domain} flagged as external repository/staging host for untrusted model weights or poisoned RAG corpus."),
            ]:
                try:
                    tech = AtlasTechnique.objects.get(code=code)
                    if tech.id not in correlated_techniques:
                        correlated_techniques[tech.id] = {
                            "technique": tech,
                            "source": "Domain Intelligence",
                            "confidence": conf,
                            "evidence": reason,
                        }
                except AtlasTechnique.DoesNotExist:
                    pass

        # 3. Correlate Packet Analysis
        for pa in investigation.packet_analyses.all():
            packet_evidence.append({
                "source_label": pa.source_label or f"PCAP #{pa.pk}",
                "packet_count": pa.packet_count,
                "open_ports": pa.open_ports or "N/A",
                "user_agent": pa.user_agent or "N/A",
                "sip_method": pa.sip_method or "N/A",
            })

            text_to_scan = f"{pa.raw_headers or ''} {pa.suspicious_flags or ''} {pa.user_agent or ''}"
            if text_to_scan.strip():
                sub_matches = AtlasService.analyze_payload(text_to_scan)
                for sm in sub_matches:
                    tech = sm["technique"]
                    correlated_techniques[tech.id] = {
                        "technique": tech,
                        "source": "Packet Analysis",
                        "confidence": sm["confidence"],
                        "evidence": f"Captured packet payload in {pa.source_label or 'PCAP'}: {sm['reason']}",
                    }

            if pa.packet_count > 50:
                try:
                    tech = AtlasTechnique.objects.get(code="AML.T0029")
                    if tech.id not in correlated_techniques:
                        correlated_techniques[tech.id] = {
                            "technique": tech,
                            "source": "Packet Analysis",
                            "confidence": "MEDIUM",
                            "evidence": f"Volumetric burst of {pa.packet_count} packets on ports {pa.open_ports or 'N/A'} correlates with ML Denial of Service / Sponge Attack.",
                        }
                except AtlasTechnique.DoesNotExist:
                    pass

            # SIP VoIP specific AI attacks
            if pa.sip_method:
                for code, conf, reason in [
                    ("AML.T0051.000", "MEDIUM", f"SIP {pa.sip_method} traffic (Call-ID: {pa.call_id or 'N/A'}, UA: {pa.user_agent or 'Unknown'}) directed at Conversational Voice AI bot / IVR system."),
                    ("AML.T0043", "HIGH", f"VoIP SIP signalling with audio stream potentially carrying adversarial acoustic perturbations targeting Speech-to-Text (ASR)."),
                ]:
                    try:
                        tech = AtlasTechnique.objects.get(code=code)
                        if tech.id not in correlated_techniques:
                            correlated_techniques[tech.id] = {
                                "technique": tech,
                                "source": "VoIP SIP Analysis",
                                "confidence": conf,
                                "evidence": reason,
                            }
                    except AtlasTechnique.DoesNotExist:
                        pass

        # 4. Correlate Phone & Virtual VoIP Intelligence
        phone_evidence = []
        for num in investigation.number_lookups.all():
            is_voip = num.is_virtual or "voip" in (num.line_type or "").lower()
            phone_evidence.append({
                "phone_number": num.phone_number,
                "carrier": num.carrier or num.provider or "Unknown Carrier",
                "line_type": num.line_type or ("Virtual VoIP" if num.is_virtual else "Standard"),
                "is_virtual": num.is_virtual,
            })
            if is_voip:
                for code, conf, reason in [
                    ("AML.T0002", "HIGH", f"Virtual VoIP caller {num.phone_number} ({num.carrier or 'VoIP'}) identified as automated caller targeting Voice AI / IVR endpoints."),
                    ("AML.T0043", "MEDIUM", f"VoIP line {num.phone_number} associated with synthetic voice generation or adversarial voice prompts."),
                ]:
                    try:
                        tech = AtlasTechnique.objects.get(code=code)
                        if tech.id not in correlated_techniques:
                            correlated_techniques[tech.id] = {
                                "technique": tech,
                                "source": "VoIP / Phone Intel",
                                "confidence": conf,
                                "evidence": reason,
                            }
                    except AtlasTechnique.DoesNotExist:
                        pass

        return {
            "correlated_techniques": list(correlated_techniques.values()),
            "ip_evidence": ip_evidence,
            "domain_evidence": domain_evidence,
            "packet_evidence": packet_evidence,
            "phone_evidence": phone_evidence,
            "has_evidence": bool(ip_evidence or domain_evidence or packet_evidence or phone_evidence),
        }
