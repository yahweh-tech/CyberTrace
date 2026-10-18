from django.db import models

from investigations.models import Investigation


class PacketAnalysis(models.Model):

    investigation = models.ForeignKey(
        Investigation,
        on_delete=models.CASCADE,
        related_name="packet_analyses",
    )

    pcap_file = models.FileField(
        upload_to="packet_captures/",
        blank=True,
        null=True,
        help_text="Uploaded .pcap / .pcapng capture file.",
    )

    source_label = models.CharField(
        max_length=200,
        blank=True,
        help_text="Filename or label for the capture source.",
    )

    packet_count = models.PositiveIntegerField(default=0)

    protocol_summary = models.TextField(
        blank=True,
        help_text="Protocol -> packet count breakdown, e.g. 'TCP: 120, UDP: 45'.",
    )

    unique_ips = models.TextField(
        blank=True,
        help_text="Most frequent source/destination IPs seen in the capture.",
    )

    open_ports = models.CharField(max_length=255, blank=True)

    suspicious_flags = models.TextField(
        blank=True,
        help_text="Heuristic findings, e.g. cleartext credentials, unusual ports.",
    )

    # Populated only when SIP/VoIP signalling traffic (port 5060/5061) is found.
    sip_method = models.CharField(max_length=20, blank=True)
    call_id = models.CharField(max_length=255, blank=True)
    from_uri = models.CharField(max_length=255, blank=True)
    to_uri = models.CharField(max_length=255, blank=True)
    user_agent = models.CharField(max_length=255, blank=True)
    via_header = models.CharField(max_length=255, blank=True)
    contact = models.CharField(max_length=255, blank=True)

    raw_headers = models.TextField(
        blank=True,
        help_text="Extracted SIP payload text, if any VoIP signalling was found.",
    )

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.source_label or self.call_id or f"Analysis #{self.pk}"
