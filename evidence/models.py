from django.db import models

from investigations.models import Investigation


class Evidence(models.Model):

    FILE_TYPES = (
        ("IMAGE", "Image"),
        ("PDF", "PDF"),
        ("VIDEO", "Video"),
        ("AUDIO", "Audio"),
        ("PCAP", "PCAP"),
        ("OTHER", "Other"),
    )

    investigation = models.ForeignKey(
        Investigation,
        on_delete=models.CASCADE,
        related_name="evidence",
    )

    title = models.CharField(
        max_length=200,
    )

    description = models.TextField(
        blank=True,
    )

    file = models.FileField(
        upload_to="evidence/",
    )

    file_type = models.CharField(
        max_length=20,
        choices=FILE_TYPES,
    )

    uploaded_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.CASCADE,
    )

    uploaded_at = models.DateTimeField(
        auto_now_add=True,
    )

    def __str__(self):
        return self.title