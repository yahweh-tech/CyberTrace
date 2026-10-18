from django.db import models
from investigations.models import Investigation


class AtlasTactic(models.Model):
    code = models.CharField(max_length=20, unique=True, help_text="e.g. AML.TA0004")
    name = models.CharField(max_length=100)
    description = models.TextField()
    order = models.PositiveSmallIntegerField(default=0)
    icon = models.CharField(max_length=50, default="bi-shield-shaded")

    class Meta:
        ordering = ["order", "code"]
        verbose_name = "ATLAS Tactic"
        verbose_name_plural = "ATLAS Tactics"

    def __str__(self):
        return f"{self.code} - {self.name}"


class AtlasTechnique(models.Model):
    SEVERITY_CHOICES = [
        ("LOW", "Low"),
        ("MEDIUM", "Medium"),
        ("HIGH", "High"),
        ("CRITICAL", "Critical"),
    ]

    tactic = models.ForeignKey(
        AtlasTactic,
        on_delete=models.CASCADE,
        related_name="techniques",
    )
    code = models.CharField(max_length=20, unique=True, help_text="e.g. AML.T0051")
    name = models.CharField(max_length=150)
    description = models.TextField()
    attack_surface = models.CharField(max_length=120, default="API / Prompt Interface")
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default="HIGH")
    detection_guidance = models.TextField(blank=True)
    mitigation_guidance = models.TextField(blank=True)
    real_world_example = models.TextField(blank=True)

    class Meta:
        ordering = ["tactic__order", "code"]
        verbose_name = "ATLAS Technique"
        verbose_name_plural = "ATLAS Techniques"

    def __str__(self):
        return f"{self.code}: {self.name}"


class AtlasAssessment(models.Model):
    SYSTEM_TYPE_CHOICES = [
        ("VOIP_AI_AGENT", "VoIP / Conversational Voice AI Bot"),
        ("LLM_AGENT", "LLM / Autonomous Agent"),
        ("RAG_PIPELINE", "RAG / Vector Database System"),
        ("VISION_MODEL", "Computer Vision Model"),
        ("PREDICTIVE_ML", "Predictive / Tabular ML Model"),
        ("EMBEDDED_EDGE", "Edge / IoT AI Hardware"),
        ("OTHER", "Other AI System"),
    ]

    RISK_LEVEL_CHOICES = [
        ("LOW", "Low Risk"),
        ("MEDIUM", "Medium Risk"),
        ("HIGH", "High Risk"),
        ("CRITICAL", "Critical Risk"),
    ]

    investigation = models.ForeignKey(
        Investigation,
        on_delete=models.CASCADE,
        related_name="atlas_assessments",
    )
    system_name = models.CharField(
        max_length=150,
        help_text="Name of the AI/ML application or model under investigation",
    )
    system_type = models.CharField(
        max_length=40,
        choices=SYSTEM_TYPE_CHOICES,
        default="LLM_AGENT",
    )
    risk_score = models.PositiveIntegerField(
        default=0,
        help_text="Calculated AI risk score (0-100)",
    )
    risk_level = models.CharField(
        max_length=20,
        choices=RISK_LEVEL_CHOICES,
        default="LOW",
    )
    incident_payload = models.TextField(
        blank=True,
        help_text="Observed attack prompt, adversarial sample metadata, or suspicious logs",
    )
    notes = models.TextField(
        blank=True,
        help_text="Analyst findings and operational context",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "ATLAS AI Assessment"
        verbose_name_plural = "ATLAS AI Assessments"

    def __str__(self):
        return f"{self.system_name} ({self.get_risk_level_display()})"


class AtlasAssessmentTechnique(models.Model):
    STATUS_CHOICES = [
        ("EXPLOITED", "Confirmed Exploited"),
        ("SUSPECTED", "Suspected / Observed"),
        ("POTENTIAL", "Potential Vulnerability"),
        ("MITIGATED", "Mitigated / Hardened"),
    ]

    assessment = models.ForeignKey(
        AtlasAssessment,
        on_delete=models.CASCADE,
        related_name="mapped_techniques",
    )
    technique = models.ForeignKey(
        AtlasTechnique,
        on_delete=models.CASCADE,
        related_name="assessment_instances",
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="SUSPECTED",
    )
    evidence_notes = models.TextField(
        blank=True,
        help_text="Specific indicators, prompt text, or attack artifacts",
    )

    class Meta:
        unique_together = ("assessment", "technique")
        verbose_name = "Assessment Mapped Technique"
        verbose_name_plural = "Assessment Mapped Techniques"

    def __str__(self):
        return f"{self.assessment.system_name} -> {self.technique.code}"
