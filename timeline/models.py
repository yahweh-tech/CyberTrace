from django.db import models

from investigations.models import Investigation
from accounts.models import User


class TimelineEvent(models.Model):

    investigation = models.ForeignKey(
        Investigation,
        on_delete=models.CASCADE,
        related_name="timeline",
    )

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )

    event = models.CharField(
        max_length=200,
    )

    description = models.TextField(
        blank=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.event