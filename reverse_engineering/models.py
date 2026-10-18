from django.db import models
from investigations.models import Investigation


class BinaryAnalysis(models.Model):
    investigation = models.ForeignKey(
        Investigation,
        on_delete=models.CASCADE,
        related_name="binary_analyses",
    )
    sample_file = models.FileField(
        upload_to="malware_samples/",
        blank=True,
        null=True,
        help_text="Uploaded binary/executable for static reverse engineering triage.",
    )
    file_name = models.CharField(max_length=255)
    file_size = models.PositiveBigIntegerField(default=0)
    file_type = models.CharField(max_length=150, default="Unknown Binary / Data")
    architecture = models.CharField(max_length=50, blank=True, default="Unknown")
    subsystem = models.CharField(max_length=50, blank=True, default="N/A")

    # Hashes & Fingerprints
    md5 = models.CharField(max_length=32, blank=True)
    sha1 = models.CharField(max_length=40, blank=True)
    sha256 = models.CharField(max_length=64, blank=True)
    imphash = models.CharField(max_length=32, blank=True, help_text="Import Hash")
    entropy = models.FloatField(default=0.0, help_text="Overall Shannon entropy (0.0 to 8.0)")

    # Packing / Obfuscation
    is_packed = models.BooleanField(default=False)
    packer_name = models.CharField(max_length=100, blank=True, default="")

    # Headers & Execution
    entry_point = models.CharField(max_length=50, blank=True, default="N/A")
    image_base = models.CharField(max_length=50, blank=True, default="N/A")
    compile_time = models.CharField(max_length=100, blank=True, default="N/A")

    # Threat Scoring
    threat_level = models.CharField(
        max_length=20,
        choices=[
            ("CLEAN", "Clean / Normal"),
            ("LOW", "Low Suspicion"),
            ("MEDIUM", "Medium Suspicion"),
            ("HIGH", "High Risk / Likely Malicious"),
            ("CRITICAL", "Critical Threat / Malicious"),
        ],
        default="LOW",
    )
    threat_score = models.PositiveIntegerField(default=0, help_text="Score from 0 to 100")

    # Structured Data
    sections_data = models.JSONField(default=list, blank=True)
    imports_data = models.JSONField(default=list, blank=True)
    exports_data = models.JSONField(default=list, blank=True)
    suspicious_capabilities = models.JSONField(default=list, blank=True)
    extracted_iocs = models.JSONField(default=dict, blank=True)
    disassembly_data = models.JSONField(default=list, blank=True)
    top_strings = models.JSONField(default=list, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Binary Analysis"
        verbose_name_plural = "Binary Analyses"

    def __str__(self):
        return f"{self.file_name} [{self.threat_level}] ({self.sha256[:8]}...)"
