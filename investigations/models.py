from django.conf import settings
from django.db import models
from core.choices import InvestigationStatus

class Investigation(models.Model):

    

    title = models.CharField(max_length=200)

    description = models.TextField(blank=True)

    investigator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="investigations",
    )

    status = models.CharField(
    max_length=20,
    choices=InvestigationStatus.choices,
    default=InvestigationStatus.PENDING,
)

    created_at = models.DateTimeField(auto_now_add=True)

    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title