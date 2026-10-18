import csv
from io import StringIO

from django.http import HttpResponse
from django.utils import timezone


class ReportService:

    @staticmethod
    def build_csv(investigation):
        output = StringIO()
        writer = csv.writer(output)

        writer.writerow(["CyberTrace: VoIP & AI Threat Forensic Attribution Report"])
        writer.writerow(["Focus: AI Voice Deepfakes, Conversational Vishing & Infrastructure Attribution"])
        writer.writerow(["Investigation", investigation.title])
        writer.writerow(["Status", investigation.get_status_display()])
        writer.writerow(["Generated", timezone.now().strftime("%Y-%m-%d %H:%M UTC")])
        writer.writerow([])

        writer.writerow(["--- 1. VoIP & Phone Intelligence (Virtual DID & Burner Origins) ---"])
        writer.writerow(["Phone", "Country", "Carrier", "Line Type", "Provider", "Virtual"])
        for lookup in investigation.number_lookups.all():
            writer.writerow([
                lookup.phone_number,
                lookup.country,
                lookup.carrier,
                lookup.line_type,
                lookup.provider,
                lookup.is_virtual,
            ])
        writer.writerow([])

        writer.writerow(["--- 2. Infrastructure: IP Intelligence (Proxy / VPN Origin) ---"])
        writer.writerow(["IP", "Country", "City", "ISP", "Org", "Proxy/VPN"])
        for lookup in investigation.ip_lookups.all():
            writer.writerow([
                lookup.ip_address,
                lookup.country,
                lookup.city,
                lookup.isp,
                lookup.org,
                lookup.is_proxy,
            ])
        writer.writerow([])

        writer.writerow(["--- 3. Infrastructure: Domain Intelligence (C2 & Exfiltration Hosts) ---"])
        writer.writerow(["Domain", "Registrar", "Created", "Expires", "Name Servers"])
        for lookup in investigation.domain_lookups.all():
            writer.writerow([
                lookup.domain,
                lookup.registrar,
                lookup.creation_date,
                lookup.expiry_date,
                lookup.name_servers,
            ])
        writer.writerow([])

        writer.writerow(["--- 4. SIP Packet & Media Forensics (Signaling & Injected Streams) ---"])
        writer.writerow(["Method", "Call-ID", "From", "To", "User-Agent", "Ports"])
        for analysis in investigation.packet_analyses.all():
            writer.writerow([
                analysis.sip_method,
                analysis.call_id,
                analysis.from_uri,
                analysis.to_uri,
                analysis.user_agent,
                analysis.open_ports,
            ])
        writer.writerow([])

        writer.writerow(["--- 5. MITRE ATLAS AI Security Assessments (Voice Threat Matrix) ---"])
        writer.writerow(["System Name", "Architecture", "Risk Level", "Risk Score", "Mapped Techniques", "Date"])
        for assess in investigation.atlas_assessments.all():
            tech_codes = ", ".join(mt.technique.code for mt in assess.mapped_techniques.all())
            writer.writerow([
                assess.system_name,
                assess.get_system_type_display(),
                assess.get_risk_level_display(),
                f"{assess.risk_score}/100",
                tech_codes,
                assess.created_at.strftime("%Y-%m-%d %H:%M"),
            ])
        writer.writerow([])

        writer.writerow(["--- 6. Reverse Engineering & Binary Forensics (Malware Triage) ---"])
        writer.writerow(["File Name", "Format", "Threat Level", "Threat Score", "SHA256", "Imphash", "Packed", "Capabilities Count", "Extracted IPs/Domains", "Date"])
        for binary in investigation.binary_analyses.all():
            iocs_summary = f"IPs: {len(binary.extracted_iocs.get('ips', []))}, Domains: {len(binary.extracted_iocs.get('domains', []))}"
            writer.writerow([
                binary.file_name,
                binary.file_type,
                binary.threat_level,
                f"{binary.threat_score}/100",
                binary.sha256,
                binary.imphash,
                "Yes" if binary.is_packed else "No",
                len(binary.suspicious_capabilities),
                iocs_summary,
                binary.created_at.strftime("%Y-%m-%d %H:%M"),
            ])

        return output.getvalue()

    @staticmethod
    def csv_response(investigation):
        content = ReportService.build_csv(investigation)
        response = HttpResponse(content, content_type="text/csv")
        filename = f"cybertrace_report_{investigation.id}.csv"
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

    @staticmethod
    def has_data(investigation):
        return any([
            investigation.number_lookups.exists(),
            investigation.ip_lookups.exists(),
            investigation.domain_lookups.exists(),
            investigation.packet_analyses.exists(),
            investigation.atlas_assessments.exists(),
            investigation.binary_analyses.exists(),
        ])
